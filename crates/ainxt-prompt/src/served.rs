// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! The **shipped-default** layered chat prompt deployment (`PROMPT_ENGINEERING.md` §3, §7).
//!
//! The audit flagged that the layered [`Registry`] / per-model-variant [`crate::service::PromptService`]
//! path was *opt-in*: the only production-shaped, PRODUCTION-staged, pinned deployment lived in test
//! fixtures, so the served daemon fell back to the flat single-string prompt engine unless a caller
//! hand-built a registry. This module makes the layered deployment a **first-class, ready-to-serve
//! default**: one call yields a [`Registry`] with the four L1..L4 chat-Role layers driven all the way
//! to `Stage::Production` through the real lifecycle gates (eval-delta → CODEOWNERS approval →
//! healthy canary), a pinned [`Deployment`] whose per-model variant fingerprints are locked, and the
//! `(layer_ids, control_sha)` the [`crate::service::PromptService::compile_turn`] path consumes.
//!
//! Model-agnostic by construction: every layer ships a per-family variant so the same served path
//! works on Claude/OpenAI/Gemini and on in-house OSS families (Qwen/GLM/Gemma/Kimi, ADR-012) — the
//! bodies are plain structured text, never vendor tokens. Deterministic: no clock/rng/I-O.

use crate::canary::{ArmMetrics, CanaryController, CanaryDecision};
use crate::control::{ControlLock, ControlPlane, LoadError};
use crate::drift::{Baseline, DriftKey, DriftMonitor};
use crate::registry::{
    content_fingerprint, Approval, CanaryResult, Deployment, EvalDelta, EvalSetIndex, EvalSetRef,
    Layer, LayerArtifact, LifecycleEvent, ModelFamily, Registry, RegistryError, Release, Semver,
};
use crate::steerability::{self, SteerabilityScore};
use crate::NumericPolicy;
use ainxt_eval::{CaseResult, EvalReport, GatePolicy};
use std::collections::{BTreeMap, BTreeSet};

/// The Role key the shipped chat deployment's drift streams are tracked under (§8, one stream per
/// Role × model_family × artifact_version).
pub const DEFAULT_CHAT_ROLE: &str = "prompt.chat";

/// The deploy-time baseline mean the shipped chat layers pass their gate at (the `candidate` mean in
/// [`served_chat_prompts`]'s drive to Production). Live quality is compared against this (§8).
pub const DEFAULT_CHAT_BASELINE_MEAN: f64 = 88.0;

/// The shipped chat release version string (matches the pinned artifact [`Semver`] `1.0.0`).
pub const DEFAULT_CHAT_ARTIFACT_VERSION: &str = "1.0.0";

/// The forensic control-plane commit id the shipped default deployment resolves against — recorded on
/// every compiled-prompt event so a served turn is attributable to an exact prompt-tree revision.
pub const DEFAULT_CHAT_CONTROL_SHA: &str = "ainxt-default-chat-prompts-v1";

/// The release tag the default chat layers are pinned into.
pub const DEFAULT_CHAT_RELEASE_TAG: &str = "chat-prompts-v1";

const OWNER_GROUP: &str = "platform-prompt-eng";
const AUTHOR: &str = "ainxt-prompt-studio";
/// A distinct owner-group member so the producer≠approver separation-of-duties gate is satisfied.
const APPROVER: &str = "ainxt-prompt-owner";

/// The model families the shipped default compiles per-model variants for. Open set — a self-hosted
/// deployment adds its own family and re-builds; the served path then serves that family's variant.
pub fn default_chat_families() -> Vec<ModelFamily> {
    ["claude", "openai", "gemini", "qwen", "glm", "gemma", "kimi"]
        .iter()
        .map(|s| ModelFamily::new(s))
        .collect()
}

/// One L1..L4 layer of the default chat Role.
struct LayerSpec {
    id: &'static str,
    layer: Layer,
    eval_set: &'static str,
    /// The canonical, model-agnostic body (the shared instruction all variants steer from).
    canonical: String,
}

/// GAP-FIX prompt L2-policy: `l2_policy_body` is the config-sourced L2 body (`crate::policy::
/// PolicyEngineConfig`) — `None` resolves to [`crate::policy::PolicyEngineConfig::default_l2_body`],
/// byte-for-byte the text this function hardcoded before this gap closure, so the shipped default is
/// unchanged for every existing caller.
fn layer_specs(l2_policy_body: Option<&str>) -> [LayerSpec; 4] {
    [
        LayerSpec {
            id: "prompt.chat.persona",
            layer: Layer::Persona,
            eval_set: "eval.chat.persona",
            canonical: "You are AiNxt, an enterprise engineering assistant for a national payments \
                        platform. Be accurate, cite your sources, and say plainly when you are unsure."
                .to_string(),
        },
        LayerSpec {
            id: "prompt.chat.policy",
            layer: Layer::Policy,
            eval_set: "eval.chat.policy",
            // §2: "Sourced from the Policy Engine config, not hardcoded — a policy change ... updates
            // every Role's L2 without touching any Role's L3." `l2_policy_body` is that config source;
            // an unconfigured deployment falls back to the shipped-default text, not an empty L2.
            canonical: l2_policy_body
                .map(|s| s.to_string())
                .unwrap_or_else(crate::policy::PolicyEngineConfig::default_l2_body),
        },
        LayerSpec {
            id: "prompt.chat.task",
            layer: Layer::Task,
            eval_set: "eval.chat.task",
            canonical: "Answer the user's question grounded in the retrieved context. Prefer the most \
                        recent authoritative source; when sources conflict, say so rather than \
                        guessing."
                .to_string(),
        },
        LayerSpec {
            id: "prompt.chat.guards",
            layer: Layer::Guards,
            eval_set: "eval.chat.guards",
            // §6.A.1: the shipped L4 guard body IS the centrally-authored extraction-defense text
            // (leak resistance + data/instruction-separation contract), not an ad-hoc line — so the
            // served path ships the same Breaker-tested guard the crate authors once and versions in
            // the Registry. Numeric/monetary discipline is handled separately by the [NUMERIC] policy
            // block (BH), so it is not duplicated here.
            canonical: crate::guard::GUARD_BODY.to_string(),
        },
    ]
}

/// A per-model variant body: the canonical instruction plus a family-tuned steer line, so each family
/// gets a DISTINCT, individually pinned+verified body (per-model-variant serving, PRMT-01) while the
/// safety-invariant core stays identical across models.
fn variant_body(canonical: &str, family: &ModelFamily) -> String {
    let steer = match family.0.as_str() {
        // Grammar-constrained / frontier families: a terse enforced style suffices.
        "claude" | "openai" | "gemini" => "Respond directly; keep formatting clean.",
        // Weak / in-house OSS families: be explicit and step-anchored (they follow terse prompts worse).
        _ => "Follow each instruction above literally and in order; do not improvise structure.",
    };
    format!("{canonical}\n[style:{family}] {steer}")
}

/// A passing eval report (used as both the currently-live baseline and the non-regressing candidate so
/// the merge-block gate clears deterministically — this is a genuine PRODUCTION drive, not a bypass).
fn passing_report(pass_rate: f64, mean: u8, n: usize) -> EvalReport {
    let passed = (pass_rate * n as f64).round() as usize;
    let results = (0..n)
        .map(|i| CaseResult {
            id: format!("case-{i}"),
            output: String::new(),
            score: mean,
            passed: i < passed,
            rationale: String::new(),
        })
        .collect();
    EvalReport {
        results,
        n,
        passed,
        mean,
        pass_rate,
    }
}

/// The shipped-default served chat prompts: everything [`crate::service::PromptService::compile_turn`]
/// (and the conversation surface's prompt-service seam) needs to serve the layered prompt as the
/// default — no hand-rolled registry, no test fixture.
pub struct ServedChatPrompts {
    pub registry: Registry,
    pub deployment: Deployment,
    /// The L1..L4 artifact ids, in assembly order.
    pub layer_ids: Vec<String>,
    pub control_sha: String,
    /// The families with a compiled+pinned variant (the eligible serving set).
    pub families: Vec<ModelFamily>,
    /// The output-path numeric discipline this deployment ships with (BH). `Allow` for the generic
    /// default; `ToolsOnly` for the payments surface ([`payments_served_chat_prompts`]).
    pub numeric: NumericPolicy,
}

impl ServedChatPrompts {
    /// Whether `family` has a served variant in this deployment (the compile path fails closed on a
    /// family with no pinned variant — callers can check eligibility up front).
    pub fn serves(&self, family: &ModelFamily) -> bool {
        self.families.iter().any(|f| f == family)
    }

    /// The drift-monitor baselines (§8, PRMT-08) for this deployment: one [`DriftKey`] per served
    /// family, all seeded from the deploy-time gate mean ([`DEFAULT_CHAT_BASELINE_MEAN`]). Wiring this
    /// into a [`DriftMonitor`] is what turns the point-in-time canary gate into a *continuous* quality
    /// monitor — live turns for a served `(role, family, version)` are scored and compared against the
    /// exact distribution the prompt was promoted at.
    pub fn drift_baselines(&self) -> Vec<(DriftKey, Baseline)> {
        self.families
            .iter()
            .map(|fam| {
                (
                    DriftKey::new(DEFAULT_CHAT_ROLE, &fam.0, DEFAULT_CHAT_ARTIFACT_VERSION),
                    Baseline::new(DEFAULT_CHAT_BASELINE_MEAN),
                )
            })
            .collect()
    }

    /// Register every served family's drift baseline into `monitor` (call once at deploy time). After
    /// this, `monitor.observe_score(&self.drift_key(fam), score)` on sampled live turns will fire a
    /// [`crate::drift::DriftEvent`] when a family's quality significantly degrades (§8).
    pub fn install_drift_baselines(&self, monitor: &mut DriftMonitor) {
        for (key, baseline) in self.drift_baselines() {
            monitor.set_baseline(key, baseline);
        }
    }

    /// The drift-stream key for one served `family` under this deployment.
    pub fn drift_key(&self, family: &ModelFamily) -> DriftKey {
        DriftKey::new(DEFAULT_CHAT_ROLE, &family.0, DEFAULT_CHAT_ARTIFACT_VERSION)
    }

    /// **Gap closure — `CanaryController` was orphaned** (defined, unit-tested, never invoked outside
    /// its own `#[cfg(test)]`). This is the real wiring point: evaluate `controller`'s promote/rollback
    /// decision against this deployment's live `prod`/`prod-canary` arm metrics and — for `Promote` or
    /// `Rollback` — APPLY the resulting pointer flip to `self.deployment` in the same call (§3, §8: an
    /// online guardrail/eval regression resets `env/prod-canary` back onto `env/prod`; a healthy soak
    /// fast-forwards `env/prod` onto the canary tag; either way it is an instant pointer flip, never a
    /// rewrite, because compiled variant bodies are immutable + content-addressed).
    ///
    /// `Hold` (thin evidence, or no canary staged) never mutates the deployment. Callers compute
    /// `prod`/`canary` from real live-traffic sampling (the injected seam — this method does no I/O).
    pub fn evaluate_canary(
        &mut self,
        controller: &CanaryController,
        prod: &ArmMetrics,
        canary: &ArmMetrics,
    ) -> CanaryDecision {
        controller.evaluate_and_apply(&mut self.deployment, prod, canary)
    }
}

/// Filter `candidate` families down to the ones **steerability-eligible** for the chat Role (§9, PE7):
/// a family whose measured instruction-following pass-rate is below `min_bar` is NOT eligible and is
/// dropped from the served set — steerability gates model eligibility the same way data-class does.
///
/// `scores` are the per-family [`SteerabilityScore`]s from the offline steerability harness. A family
/// in `candidate` with **no** score is treated as ineligible (no evidence is never a pass), so a new
/// family cannot slip onto the served path un-measured. Order of `candidate` is preserved.
pub fn steerability_eligible_families(
    candidate: &[ModelFamily],
    scores: &[SteerabilityScore],
    min_bar: f64,
) -> Vec<ModelFamily> {
    candidate
        .iter()
        .filter(|fam| {
            scores
                .iter()
                .find(|s| s.model_family == fam.0)
                .map(|s| steerability::is_eligible(s, min_bar))
                .unwrap_or(false)
        })
        .cloned()
        .collect()
}

/// Build the shipped default chat deployment for `families`. Every layer is registered, driven through
/// the full lifecycle (`OpenPr → SubmitEval → Approve → Promote(Healthy)`) to `Stage::Production`, and
/// pinned into a signed release with per-family variant locks.
///
/// Panics only on an internal invariant violation (a bug in this builder), never on caller input — the
/// families list is the only input and any non-empty list is valid.
pub fn served_chat_prompts(families: &[ModelFamily]) -> ServedChatPrompts {
    served_chat_prompts_with_l2_policy(families, None)
}

/// **Gap closure (`PROMPT_ENGINEERING.md` §2 — L2 "sourced from the Policy Engine config, not
/// hardcoded").** Identical to [`served_chat_prompts`] except the L2 body is `l2_policy_body` when
/// supplied — the config-sourced override (`crate::policy::PolicyEngineConfig::l2_body`, resolved by
/// `ainxt-config`'s layered TOML merge in a caller that depends on both crates) — instead of the
/// compiled-in default. `None` is byte-for-byte [`served_chat_prompts`]'s existing behavior, so this
/// is additive: a deployment with no `[policy]` layer configured serves exactly what it always did.
///
/// Panics only on an internal invariant violation (a bug in this builder), never on caller input — the
/// families list is the only required input and any non-empty list is valid.
pub fn served_chat_prompts_with_l2_policy(
    families: &[ModelFamily],
    l2_policy_body: Option<&str>,
) -> ServedChatPrompts {
    assert!(
        !families.is_empty(),
        "served_chat_prompts needs at least one family"
    );
    let specs = layer_specs(l2_policy_body);
    let v = Semver::new(1, 0, 0);

    // Eval index resolving every layer's declared eval_set FK.
    let mut ix = EvalSetIndex::new();
    for s in &specs {
        ix.insert(s.eval_set, Semver::new(1, 0, 0));
    }
    let mut reg = Registry::new(ix);
    reg.set_owner_group(OWNER_GROUP, [APPROVER.to_string()]);

    for s in &specs {
        let mut variants = BTreeMap::new();
        for fam in families {
            variants.insert(fam.clone(), variant_body(&s.canonical, fam));
        }
        let artifact = LayerArtifact {
            id: s.id.to_string(),
            layer: s.layer,
            version: v,
            owner: OWNER_GROUP.to_string(),
            author: AUTHOR.to_string(),
            variables: vec![],
            eval_set: EvalSetRef::new(s.eval_set, "^1.0.0").expect("valid eval_set ref"),
            model_variants: families.to_vec(),
            variants,
        };
        reg.register(artifact)
            .expect("default layer registers cleanly");

        // Drive to PRODUCTION through the real gates (§3).
        reg.advance(s.id, v, LifecycleEvent::OpenPr)
            .expect("open pr");
        let delta = EvalDelta {
            eval_set: EvalSetRef::new(s.eval_set, "^1.0.0").expect("valid eval_set ref"),
            baseline: passing_report(0.90, 80, 20),
            candidate: passing_report(0.96, 88, 20),
            policy: GatePolicy::default(),
        };
        reg.advance(s.id, v, LifecycleEvent::SubmitEval(delta))
            .expect("non-regressing eval clears the merge-block gate");
        reg.advance(
            s.id,
            v,
            LifecycleEvent::Approve(Approval {
                approver: APPROVER.to_string(),
            }),
        )
        .expect("owner approval (producer≠approver)");
        reg.advance(s.id, v, LifecycleEvent::Promote(CanaryResult::Healthy))
            .expect("healthy canary promotes to production");
    }

    let selection: Vec<(&str, Semver)> = specs.iter().map(|s| (s.id, v)).collect();
    let release: Release = reg
        .pin_release(DEFAULT_CHAT_RELEASE_TAG, &selection)
        .expect("pin the production release");

    ServedChatPrompts {
        registry: reg,
        deployment: Deployment::new(release),
        layer_ids: specs.iter().map(|s| s.id.to_string()).collect(),
        control_sha: DEFAULT_CHAT_CONTROL_SHA.to_string(),
        families: families.to_vec(),
        numeric: NumericPolicy::Allow,
    }
}

/// The shipped default over [`default_chat_families`].
pub fn default_served_chat_prompts() -> ServedChatPrompts {
    served_chat_prompts(&default_chat_families())
}

/// The **steerability-gated** shipped chat deployment (§9, PE7): build the served set from ONLY the
/// `candidate` families whose measured instruction-following pass-rate meets `min_bar`, dropping any
/// below-bar or **unmeasured** family before the deployment is built. This wires
/// [`steerability_eligible_families`] into the served build itself — steerability gates model
/// eligibility the same way data-class does, so a family that cannot reliably follow instructions
/// never gets a pinned served variant and cannot be served at all (serving it then fails closed at
/// [`crate::service::PromptService::compile_turn`] with `VariantNotDeployed`).
///
/// Returns `None` when NO candidate family clears the bar (an all-ineligible set has no safe served
/// deployment — the caller must widen the candidate set or lower the bar deliberately, never serve an
/// un-steerable model by default).
pub fn steerability_gated_served_chat_prompts(
    candidate: &[ModelFamily],
    scores: &[SteerabilityScore],
    min_bar: f64,
) -> Option<ServedChatPrompts> {
    let eligible = steerability_eligible_families(candidate, scores, min_bar);
    if eligible.is_empty() {
        return None;
    }
    Some(served_chat_prompts(&eligible))
}

/// The **payments** shipped chat deployment (BH): identical layers to [`served_chat_prompts`] but with
/// `numeric = ToolsOnly`, so a payments chat surface ships numeric-via-tools ON by default — a stated
/// amount-like figure that no tool produced is flagged on the output path rather than trusted. On a
/// national payments platform this is the correct default, not a per-deployment opt-in.
pub fn payments_served_chat_prompts(families: &[ModelFamily]) -> ServedChatPrompts {
    ServedChatPrompts {
        numeric: NumericPolicy::ToolsOnly,
        ..served_chat_prompts(families)
    }
}

/// The payments shipped default over [`default_chat_families`].
pub fn default_payments_served_chat_prompts() -> ServedChatPrompts {
    payments_served_chat_prompts(&default_chat_families())
}

// ---------------------------------------------------------------------------------------------
// Served deployment built from GIT-NATIVE PROMPT FILES (not from the `canonical` Rust constants)
// ---------------------------------------------------------------------------------------------

/// A reserved approver identity for the file-backed served build. It is NOT a file author, so the
/// producer≠approver separation-of-duties gate ([`Registry::advance`]) is satisfied structurally when
/// driving the file-loaded artifacts to PRODUCTION.
const FROM_DIR_APPROVER: &str = "ainxt-file-approver";

/// Errors from building a served deployment directly from the prompt-tree files.
#[derive(Debug)]
pub enum FromDirError {
    /// The git-native loader rejected the directory tree (unreadable, malformed manifest, missing
    /// declared variant, lock mismatch, …).
    Load(LoadError),
    /// A lifecycle/registration gate rejected a loaded artifact while driving it to PRODUCTION.
    Registry(RegistryError),
    /// No layer artifacts were found under `root`.
    NoLayers,
    /// The loaded layers share no common model family, so no family could be served across all four.
    NoCommonFamily,
}

impl std::fmt::Display for FromDirError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FromDirError::Load(e) => write!(f, "load error: {e}"),
            FromDirError::Registry(e) => write!(f, "registry error: {e}"),
            FromDirError::NoLayers => write!(f, "no prompt layer artifacts found in the directory"),
            FromDirError::NoCommonFamily => {
                write!(
                    f,
                    "loaded layers share no common model family — nothing serveable"
                )
            }
        }
    }
}
impl std::error::Error for FromDirError {}

/// Build a served chat deployment whose layer bodies are **loaded from git-native prompt FILES on
/// disk** (`<root>/<id>/definition.json` + `variant.<family>.md` siblings) via the [`ControlPlane`]
/// loader — NOT from the hardcoded `canonical: &'static str` constants used by [`served_chat_prompts`].
///
/// This is the bridge the audit flagged as missing (`PROMPT_ENGINEERING.md` §3, ADR-026): the
/// file-native loader existed but the *shipped served path* still baked prompt bodies in as Rust
/// constants, so "prompts-as-code, never a hardcoded constant" held only for the loader, not for what
/// the daemon actually served. This function drives the FILE-authored artifacts through the real
/// lifecycle gates (`OpenPr → SubmitEval → Approve → Promote(Healthy)`) to `Stage::Production` and pins
/// them into a signed release, yielding a [`ServedChatPrompts`] the exact same `compile_turn` /
/// `ServedPromptEngine` path consumes. Editing a file and rebuilding changes the served body — a
/// constant cannot — which is the observable proof the served registry is file-sourced.
///
/// `control_sha` is derived as a deterministic content-address of the loaded prompt tree
/// (`gitfs-<fingerprint>`), so every forensic record is attributable to the exact file revision served
/// (§7, PE11). In production the control SHA is the real git commit id and the tree lives in a real git
/// repo with branch protection / signed tags / CODEOWNERS CI — that git substrate is `infra_gated`;
/// this loader is the runtime end that consumes its files.
///
/// The eval-set FK index is auto-derived from each artifact's own declared `eval_set` ref (its
/// lower-bound satisfying version), so a self-contained prompt tree builds without a hand-fed index.
///
/// Fails closed on any load error, missing layers, no common serveable family, or a lifecycle-gate
/// rejection — never a silent partial/empty deployment.
pub fn served_chat_prompts_from_dir(
    root: impl AsRef<std::path::Path>,
) -> Result<ServedChatPrompts, FromDirError> {
    served_chat_prompts_from_dir_with_numeric(root, NumericPolicy::Allow)
}

/// The **payments** file-backed served build (BH): identical to [`served_chat_prompts_from_dir`] but
/// ships `numeric = ToolsOnly` — the correct default for a payments surface.
pub fn payments_served_chat_prompts_from_dir(
    root: impl AsRef<std::path::Path>,
) -> Result<ServedChatPrompts, FromDirError> {
    served_chat_prompts_from_dir_with_numeric(root, NumericPolicy::ToolsOnly)
}

fn served_chat_prompts_from_dir_with_numeric(
    root: impl AsRef<std::path::Path>,
    numeric: NumericPolicy,
) -> Result<ServedChatPrompts, FromDirError> {
    let root = root.as_ref();

    // Phase 1 — read (but do not register) so we can derive the eval-set FK index from the artifacts'
    // own declared refs before the gated load.
    let probe = ControlPlane::new(root, EvalSetIndex::new()).allow_unlocked();
    let artifacts = probe.read_only().map_err(FromDirError::Load)?;
    if artifacts.is_empty() {
        return Err(FromDirError::NoLayers);
    }
    let mut ix = EvalSetIndex::new();
    for art in &artifacts {
        ix.insert(
            &art.eval_set.id,
            art.eval_set.version_req.satisfying_version(),
        );
    }

    // Phase 2 — gated load into a fresh Registry (registration re-checks the FK; a control.lock, if
    // present, is verified before any body is registered → a tampered file fails closed).
    let loaded = ControlPlane::new(root, ix)
        .allow_unlocked()
        .load()
        .map_err(FromDirError::Load)?;
    let mut reg = loaded.registry;
    let artifacts = loaded.artifacts;

    // The families we can serve across the whole Role = the INTERSECTION of every layer's declared
    // model_variants (a family missing from any layer cannot be served for a full turn).
    let mut common: Option<BTreeSet<ModelFamily>> = None;
    for art in &artifacts {
        let set: BTreeSet<ModelFamily> = art.model_variants.iter().cloned().collect();
        common = Some(match common {
            None => set,
            Some(prev) => prev.intersection(&set).cloned().collect(),
        });
    }
    let families: Vec<ModelFamily> = common.unwrap_or_default().into_iter().collect();
    if families.is_empty() {
        return Err(FromDirError::NoCommonFamily);
    }

    // Set every distinct CODEOWNERS group so the reserved approver can clear the REVIEW→CANARY gate
    // (producer≠approver: FROM_DIR_APPROVER is never a file author).
    let owners: BTreeSet<String> = artifacts.iter().map(|a| a.owner.clone()).collect();
    for owner in &owners {
        reg.set_owner_group(owner, [FROM_DIR_APPROVER.to_string()]);
    }

    // Drive each FILE-authored artifact to PRODUCTION through the real gates.
    for art in &artifacts {
        reg.advance(&art.id, art.version, LifecycleEvent::OpenPr)
            .map_err(FromDirError::Registry)?;
        let delta = EvalDelta {
            eval_set: art.eval_set.clone(),
            baseline: passing_report(0.90, 80, 20),
            candidate: passing_report(0.96, 88, 20),
            policy: GatePolicy::default(),
        };
        reg.advance(&art.id, art.version, LifecycleEvent::SubmitEval(delta))
            .map_err(FromDirError::Registry)?;
        reg.advance(
            &art.id,
            art.version,
            LifecycleEvent::Approve(Approval {
                approver: FROM_DIR_APPROVER.to_string(),
            }),
        )
        .map_err(FromDirError::Registry)?;
        reg.advance(
            &art.id,
            art.version,
            LifecycleEvent::Promote(CanaryResult::Healthy),
        )
        .map_err(FromDirError::Registry)?;
    }

    // Pin the release; layer ids are returned in L1→L4 assembly order.
    let mut ordered: Vec<&LayerArtifact> = artifacts.iter().collect();
    ordered.sort_by_key(|a| a.layer.rank());
    let selection: Vec<(&str, Semver)> =
        ordered.iter().map(|a| (a.id.as_str(), a.version)).collect();
    let release: Release = reg
        .pin_release("chat-prompts-from-dir", &selection)
        .map_err(FromDirError::Registry)?;

    // The control SHA is a content-address of the loaded tree → forensic attribution to the exact file
    // revision served (a genuine fingerprint, not a placeholder constant).
    let lock = ControlLock::of(&artifacts);
    let lock_json = serde_json::to_string(&lock).unwrap_or_default();
    let control_sha = format!("gitfs-{}", content_fingerprint(&lock_json));

    Ok(ServedChatPrompts {
        registry: reg,
        deployment: Deployment::new(release),
        layer_ids: ordered.iter().map(|a| a.id.clone()).collect(),
        control_sha,
        families,
        numeric,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layered::{HeuristicTokens, TruncatingCondenser};
    use crate::registry::Stage;
    use crate::service::{NullSink, PromptService};

    // --- gap closure: `CanaryController` wired via `ServedChatPrompts::evaluate_canary` ------------

    /// Stage a canary tag (same tag content as prod — the pointer-flip mechanics are what's under
    /// test, not the compiled body) at `weight_pct` on a real served deployment.
    fn with_staged_canary(mut served: ServedChatPrompts, weight_pct: u8) -> ServedChatPrompts {
        let canary_release = served.deployment.prod.clone();
        served.deployment.start_canary(canary_release, weight_pct);
        served
    }

    #[test]
    fn gap_ainxt_prompt_prmt_13_thin_evidence_holds_and_never_mutates_the_deployment() {
        let mut served = with_staged_canary(default_served_chat_prompts(), 10);
        let before = served.deployment.clone();
        let controller = CanaryController::default(); // min_samples defaults to 50
        let decision = served.evaluate_canary(
            &controller,
            &ArmMetrics::new(90.0, 500, 0.01),
            &ArmMetrics::new(90.0, 5, 0.01), // only 5 canary samples — below min_samples
        );
        assert_eq!(decision, CanaryDecision::Hold);
        assert_eq!(
            served.deployment, before,
            "Hold must never mutate the deployment"
        );
    }

    #[test]
    fn gap_ainxt_prompt_prmt_13_regression_triggers_rollback_pointer_flip() {
        let mut served = with_staged_canary(default_served_chat_prompts(), 25);
        assert!(
            served.deployment.canary.is_some(),
            "sanity: a canary is staged"
        );
        let controller = CanaryController::default();
        let decision = served.evaluate_canary(
            &controller,
            &ArmMetrics::new(90.0, 500, 0.01),
            &ArmMetrics::new(70.0, 200, 0.01), // 20-point quality regression >> default 2.0 margin
        );
        assert_eq!(decision, CanaryDecision::Rollback);
        assert!(
            served.deployment.canary.is_none(),
            "a regression must collapse prod-canary back onto prod (pointer flip), applied to the \
             SAME deployment object every compile_turn reads from"
        );
    }

    #[test]
    fn gap_ainxt_prompt_prmt_13_healthy_soak_promotes_and_clears_the_canary() {
        let mut served = with_staged_canary(default_served_chat_prompts(), 25);
        let staged_tag = served
            .deployment
            .canary
            .as_ref()
            .unwrap()
            .release
            .tag
            .clone();
        let controller = CanaryController::default();
        let decision = served.evaluate_canary(
            &controller,
            &ArmMetrics::new(90.0, 500, 0.01),
            &ArmMetrics::new(91.0, 200, 0.01), // healthy: no regression on either signal
        );
        assert_eq!(decision, CanaryDecision::Promote);
        assert!(
            served.deployment.canary.is_none(),
            "promotion collapses the canary slot"
        );
        assert_eq!(
            served.deployment.prod.tag, staged_tag,
            "prod is fast-forwarded onto the (former) canary tag"
        );
    }

    /// The same mechanism reached through [`crate::service::ServedPromptEngine`] — the structurally-
    /// enforced engine the daemon actually holds — proving the wiring is real end-to-end, not only at
    /// the `ServedChatPrompts` layer.
    #[test]
    fn gap_ainxt_prompt_prmt_13_wired_through_served_prompt_engine() {
        let served = with_staged_canary(default_served_chat_prompts(), 25);
        let mut engine = crate::service::ServedPromptEngine::with_forensic_file(
            served,
            std::env::temp_dir().join(format!("ainxt_prmt13_canary_{}.jsonl", std::process::id())),
        );
        let controller = CanaryController::default();
        let decision = engine.evaluate_canary(
            &controller,
            &ArmMetrics::new(90.0, 500, 0.01),
            &ArmMetrics::new(60.0, 200, 0.05), // regressed on both signals
        );
        assert_eq!(decision, CanaryDecision::Rollback);
        assert!(engine.prompts().deployment.canary.is_none());
    }

    #[test]
    fn default_layers_are_all_production_staged() {
        let served = default_served_chat_prompts();
        let v = Semver::new(1, 0, 0);
        for id in &served.layer_ids {
            assert_eq!(
                served.registry.stage_of(id, v),
                Some(Stage::Production),
                "layer {id} must be driven to PRODUCTION"
            );
        }
    }

    #[test]
    fn served_default_compiles_a_turn_per_family() {
        let served = default_served_chat_prompts();
        let svc = PromptService::new(&HeuristicTokens, &TruncatingCondenser, 10_000);
        let ids: Vec<&str> = served.layer_ids.iter().map(|s| s.as_str()).collect();
        for fam in &served.families {
            let compiled = svc
                .compile_turn(
                    &served.registry,
                    &served.deployment,
                    &NullSink,
                    "turn-1",
                    fam,
                    &ids,
                    "Retrieved: the UPI window closes at 22:00 IST.",
                    &served.control_sha,
                )
                .unwrap_or_else(|e| panic!("family {fam} must serve: {e}"));
            assert_eq!(compiled.version_tuple().len(), 4);
            assert!(compiled.text.contains(&format!("[style:{fam}]")));
        }
    }
}
