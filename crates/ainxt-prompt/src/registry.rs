// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Prompt Registry — prompts-as-code, versioned artifacts (`PROMPT_ENGINEERING.md` §3, ADR-026).
//!
//! A prompt is not a string an engineer edited and shipped. It is a **versioned, per-model-tuned
//! artifact** with a lifecycle identical to code: authored (DRAFT), evaluated (EVAL), reviewed
//! (REVIEW), canaried (CANARY), promoted (PRODUCTION), retired (DEPRECATED). This module is the
//! runtime side of that discipline — the pure, deterministic core the git-native control plane loads:
//!
//! * **Five ordered layers** (§2) — L1 persona / L2 policy / L3 task / L4 guards are *definitions*
//!   ([`Layer`]); L5 context is the per-turn data-plane slice and is never an artifact.
//! * **Per-layer semver versioning** ([`Semver`]) and **per-model variants** ([`LayerArtifact`]):
//!   `variant.<family>.md` is first-class, selected *at serve time* — a Role switched from Claude to
//!   a self-hosted Qwen deployment picks up the Qwen-tuned body, never the Claude prose run as-is.
//! * **The eval_set "FK" + eval-delta merge-block gate** ([`Registry::advance`], [`EvalDelta`]):
//!   EVAL→REVIEW is *structurally* impossible without a resolvable eval_set and a **non-regressing**
//!   eval delta — reusing [`ainxt_eval::evaluate_gate`] so the two subsystems can never drift apart.
//! * **Producer≠approver SoD** at REVIEW→CANARY (a forged self-approval is rejected).
//! * **Rollback-by-pointer** ([`Deployment`]): env refs `prod` / `prod-canary`; a canary regression
//!   is an *instant* pointer flip back to the last-known-good release, and every served body is
//!   verified byte-for-byte against the pinned content fingerprint (the `control.lock` check) — a
//!   tampered/drifted body fails closed rather than reaching a model.
//!
//! Deterministic: no clock/rng — the routing key, approvals, and eval reports are all passed in.

use ainxt_eval::{evaluate_gate_statistical_dropin, EvalReport, GatePolicy};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;

// ---------------------------------------------------------------------------------------------
// Content fingerprint — the in-runtime lock check (NOT the cryptographic content-address).
// ---------------------------------------------------------------------------------------------

/// A deterministic 128-bit content fingerprint (two FNV-1a lanes, hex).
///
/// This is the **in-runtime lock check** that a served variant body still matches the pinned
/// artifact (rollback identity / tamper detection). It is deliberately *not* the cryptographic
/// content-address — git's signed content-addressing and tag signing are the cryptographic layer
/// (ADR-026 §9); this fingerprint is what the runtime compares on every serve so a drifted or
/// swapped body fails closed. Same bytes → same fingerprint, forever.
pub fn content_fingerprint(s: &str) -> String {
    const OFF1: u64 = 0xcbf2_9ce4_8422_2325;
    const OFF2: u64 = 0x8422_2325_cbf2_9ce4;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h1 = OFF1;
    let mut h2 = OFF2;
    for b in s.bytes() {
        h1 = (h1 ^ b as u64).wrapping_mul(PRIME);
        h2 = (h2 ^ (b as u64).rotate_left(5)).wrapping_mul(PRIME);
    }
    format!("{h1:016x}{h2:016x}")
}

// ---------------------------------------------------------------------------------------------
// Layers + semver + model family
// ---------------------------------------------------------------------------------------------

/// A definition layer. L5 (context) is intentionally absent — it is the Context Fabric's per-turn
/// data-plane slice, never a versioned definition (`PROMPT_ENGINEERING.md` §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Layer {
    /// L1 — identity / persona.
    Persona,
    /// L2 — org / config policy.
    Policy,
    /// L3 — task instructions (the layer Studio authors + the optimizer tunes).
    Task,
    /// L4 — guard prompts (refuse/never; leak + injection defense).
    Guards,
}

impl Layer {
    /// The fixed assembly rank (L1→L4). Lower composes earlier so guards (L4) sit immediately above
    /// the untrusted L5 context (`PROMPT_ENGINEERING.md` §2).
    pub fn rank(self) -> u8 {
        match self {
            Layer::Persona => 1,
            Layer::Policy => 2,
            Layer::Task => 3,
            Layer::Guards => 4,
        }
    }
    /// The `L1..L4` code used in the recorded version tuple.
    pub fn code(self) -> &'static str {
        match self {
            Layer::Persona => "L1",
            Layer::Policy => "L2",
            Layer::Task => "L3",
            Layer::Guards => "L4",
        }
    }
}

/// A model family the Registry compiles per-model variants for (`variant.<family>.md`). A newtype so
/// the set is open (self-hosted deployments add their own) yet type-distinct from a plain string.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ModelFamily(pub String);

impl ModelFamily {
    pub fn new(s: &str) -> Self {
        ModelFamily(s.to_string())
    }
}

impl fmt::Display for ModelFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A semantic version (`major.minor.patch`). Ordering is field order (major, then minor, then patch).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Semver {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl Semver {
    pub fn new(major: u16, minor: u16, patch: u16) -> Self {
        Semver {
            major,
            minor,
            patch,
        }
    }
}

impl fmt::Display for Semver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl FromStr for Semver {
    type Err = RegistryError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut it = s.trim().split('.');
        let mut next = || -> Result<u16, RegistryError> {
            it.next()
                .ok_or_else(|| RegistryError::BadVersion(s.to_string()))?
                .parse::<u16>()
                .map_err(|_| RegistryError::BadVersion(s.to_string()))
        };
        let major = next()?;
        let minor = next()?;
        let patch = next()?;
        if it.next().is_some() {
            return Err(RegistryError::BadVersion(s.to_string()));
        }
        Ok(Semver {
            major,
            minor,
            patch,
        })
    }
}

/// A semver requirement on an eval_set (the "FK" target). Supports `*` (any), `^a.b.c` (caret:
/// `>=a.b.c` and `<(a+1).0.0`), and an exact `a.b.c`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VersionReq {
    Any,
    Caret(Semver),
    Exact(Semver),
}

impl VersionReq {
    pub fn matches(&self, v: Semver) -> bool {
        match self {
            VersionReq::Any => true,
            VersionReq::Exact(e) => *e == v,
            VersionReq::Caret(base) => v >= *base && v.major == base.major,
        }
    }

    /// A concrete version that satisfies this requirement (its lower bound). Used to auto-derive an
    /// eval-set FK index from the artifacts' *own* declared refs when no external eval control plane is
    /// supplied — i.e. when the served deployment is built straight from the git-native prompt files
    /// (`served_chat_prompts_from_dir`) rather than a hand-built index.
    pub fn satisfying_version(&self) -> Semver {
        match self {
            VersionReq::Any => Semver::new(0, 0, 0),
            VersionReq::Caret(base) => *base,
            VersionReq::Exact(e) => *e,
        }
    }
}

impl FromStr for VersionReq {
    type Err = RegistryError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s == "*" {
            Ok(VersionReq::Any)
        } else if let Some(rest) = s.strip_prefix('^') {
            Ok(VersionReq::Caret(rest.parse()?))
        } else {
            Ok(VersionReq::Exact(s.parse()?))
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The eval_set reference (FK) + its index
// ---------------------------------------------------------------------------------------------

/// A reference from a prompt artifact to the eval set it is gated against (`eval_set:` front-matter).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvalSetRef {
    pub id: String,
    pub version_req: VersionReq,
}

impl EvalSetRef {
    pub fn new(id: &str, req: &str) -> Result<Self, RegistryError> {
        Ok(EvalSetRef {
            id: id.to_string(),
            version_req: req.parse()?,
        })
    }
}

/// The set of eval sets that actually exist in the control plane — the "FK target table". A prompt
/// whose `eval_set` ref does not resolve here is a **dangling FK** and cannot pass EVAL.
#[derive(Debug, Clone, Default)]
pub struct EvalSetIndex {
    available: BTreeMap<String, BTreeSet<Semver>>,
}

impl EvalSetIndex {
    pub fn new() -> Self {
        EvalSetIndex::default()
    }
    /// Register an eval set version as existing.
    pub fn insert(&mut self, id: &str, version: Semver) {
        self.available
            .entry(id.to_string())
            .or_default()
            .insert(version);
    }
    /// Does this ref resolve to a concrete existing eval-set version?
    pub fn resolves(&self, r: &EvalSetRef) -> bool {
        self.available
            .get(&r.id)
            .map(|vs| vs.iter().any(|v| r.version_req.matches(*v)))
            .unwrap_or(false)
    }
}

// ---------------------------------------------------------------------------------------------
// The layer artifact (prompt-as-code) + its manifest front-matter
// ---------------------------------------------------------------------------------------------

/// One versioned layer artifact — the runtime shape of a `prompts/<id>/` directory.
///
/// `model_variants` is the *declaration* (which `variant.<family>.md` siblings MUST exist);
/// `variants` is the compiled content. [`LayerArtifact::validate`] rejects a declared-but-missing
/// variant — the same rejection the git loader performs (`PROMPT_ENGINEERING.md` §3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayerArtifact {
    /// Immutable slug — the `L{n}@name.vN` name is this id.
    pub id: String,
    pub layer: Layer,
    pub version: Semver,
    /// The CODEOWNERS group that owns this artifact (approvals must come from its members).
    pub owner: String,
    /// The principal who authored this version (used for producer≠approver SoD).
    pub author: String,
    pub variables: Vec<String>,
    pub eval_set: EvalSetRef,
    /// The declared model families — each MUST have a compiled variant body.
    pub model_variants: Vec<ModelFamily>,
    /// Compiled per-model bodies. Key = family; value = the variant body sent for that family.
    pub variants: BTreeMap<ModelFamily, String>,
}

impl LayerArtifact {
    /// Validate structural integrity: non-empty id, no missing declared variant, no undeclared extra
    /// variant. Returns every problem at once (fail-closed authoring feedback).
    pub fn validate(&self) -> Result<(), RegistryError> {
        let mut problems = Vec::new();
        if self.id.trim().is_empty() {
            problems.push("empty id".to_string());
        }
        if self.model_variants.is_empty() {
            problems.push("no model_variants declared".to_string());
        }
        for fam in &self.model_variants {
            match self.variants.get(fam) {
                None => problems.push(format!(
                    "declared model_variant '{fam}' has no variant body"
                )),
                Some(body) if body.trim().is_empty() => {
                    problems.push(format!("variant '{fam}' is empty"))
                }
                Some(_) => {}
            }
        }
        for fam in self.variants.keys() {
            if !self.model_variants.contains(fam) {
                problems.push(format!(
                    "variant '{fam}' present but not declared in model_variants"
                ));
            }
        }
        if problems.is_empty() {
            Ok(())
        } else {
            Err(RegistryError::InvalidArtifact(problems))
        }
    }

    /// The compiled body for a family, or `None` if that family is not compiled.
    pub fn variant(&self, family: &ModelFamily) -> Option<&str> {
        self.variants.get(family).map(|s| s.as_str())
    }

    /// The content fingerprint of a family's variant body (what the deployment pins).
    pub fn variant_fingerprint(&self, family: &ModelFamily) -> Option<String> {
        self.variant(family).map(content_fingerprint)
    }
}

/// The manifest front-matter (`definition.md`), parsed as-authored (`version`/`eval_set.version` are
/// strings in the file). [`Manifest::into_artifact`] binds it to compiled variant bodies.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub kind: String,
    pub id: String,
    pub layer: Layer,
    pub version: String,
    pub owner: String,
    pub author: String,
    #[serde(default)]
    pub variables: Vec<String>,
    pub model_variants: Vec<String>,
    pub eval_set: ManifestEvalSet,
}

/// The `eval_set:` front-matter block.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestEvalSet {
    pub id: String,
    pub version: String,
}

impl Manifest {
    /// Bind this manifest to its compiled variant bodies, producing a runtime [`LayerArtifact`].
    /// The caller supplies `(family, body)` pairs loaded from the sibling `variant.<family>.md`
    /// files; [`LayerArtifact::validate`] then enforces the declared-vs-present invariant.
    pub fn into_artifact(
        self,
        bodies: BTreeMap<String, String>,
    ) -> Result<LayerArtifact, RegistryError> {
        if self.kind != "prompt" {
            return Err(RegistryError::InvalidArtifact(vec![format!(
                "kind must be 'prompt', got '{}'",
                self.kind
            )]));
        }
        let version: Semver = self.version.parse()?;
        let eval_set = EvalSetRef {
            id: self.eval_set.id,
            version_req: self.eval_set.version.parse()?,
        };
        let model_variants: Vec<ModelFamily> = self
            .model_variants
            .iter()
            .map(|s| ModelFamily::new(s))
            .collect();
        let variants: BTreeMap<ModelFamily, String> = bodies
            .into_iter()
            .map(|(k, v)| (ModelFamily::new(&k), v))
            .collect();
        let art = LayerArtifact {
            id: self.id,
            layer: self.layer,
            version,
            owner: self.owner,
            author: self.author,
            variables: self.variables,
            eval_set,
            model_variants,
            variants,
        };
        art.validate()?;
        Ok(art)
    }
}

// ---------------------------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------------------------

/// The artifact lifecycle stage (`PROMPT_ENGINEERING.md` §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage {
    Draft,
    Eval,
    Review,
    Canary,
    Production,
    Deprecated,
}

/// A non-regressing eval delta — the merge-blocking gate's evidence (`PROMPT_ENGINEERING.md` §3, §8).
/// `baseline` is the currently-live PRODUCTION report for this id; `candidate` is the new version's
/// report on the same eval set. The gate reuses [`ainxt_eval::evaluate_gate_statistical_dropin`] —
/// the statistically-valid drop-in that pairs candidate/baseline by case id and blocks only a
/// *significant* per-case regression, rather than the aggregate pass-rate arithmetic that flaps on
/// coin-flips (or misses a real within-pass-rate quality drop).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvalDelta {
    pub eval_set: EvalSetRef,
    pub baseline: EvalReport,
    pub candidate: EvalReport,
    pub policy: GatePolicy,
}

impl EvalDelta {
    /// The blocking reasons, if any — empty means the delta is non-regressing and may merge.
    pub fn blocking_reasons(&self) -> Vec<String> {
        match evaluate_gate_statistical_dropin(&self.candidate, &self.policy, Some(&self.baseline))
        {
            ainxt_eval::GateOutcome::Pass => Vec::new(),
            ainxt_eval::GateOutcome::Fail(rs) => rs,
        }
    }
    pub fn is_non_regressing(&self) -> bool {
        self.blocking_reasons().is_empty()
    }
}

/// An approval at REVIEW (CODEOWNERS). SoD: the approver must be an owner-group member AND must not
/// be the artifact's author.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Approval {
    pub approver: String,
}

/// The outcome of a canary soak (`PROMPT_ENGINEERING.md` §8). A regressed canary can never promote.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CanaryResult {
    Healthy,
    Regressed,
}

/// A lifecycle transition request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum LifecycleEvent {
    /// DRAFT → EVAL (open the PR / start CI).
    OpenPr,
    /// EVAL → REVIEW — gated on a resolvable eval_set FK + a non-regressing eval delta.
    SubmitEval(EvalDelta),
    /// REVIEW → CANARY — gated on CODEOWNERS approval + producer≠approver SoD.
    Approve(Approval),
    /// CANARY → PRODUCTION — gated on a healthy canary soak.
    Promote(CanaryResult),
    /// any non-terminal → DEPRECATED.
    Deprecate,
}

// ---------------------------------------------------------------------------------------------
// The registry
// ---------------------------------------------------------------------------------------------

/// The prompt registry: artifacts keyed by `(id, version)` + their lifecycle stage, plus the
/// eval-set FK index and the CODEOWNERS membership needed to gate transitions.
#[derive(Debug, Clone, Default)]
pub struct Registry {
    artifacts: BTreeMap<(String, Semver), LayerArtifact>,
    stages: BTreeMap<(String, Semver), Stage>,
    eval_index: EvalSetIndex,
    owners: BTreeMap<String, BTreeSet<String>>,
}

impl Registry {
    pub fn new(eval_index: EvalSetIndex) -> Self {
        Registry {
            artifacts: BTreeMap::new(),
            stages: BTreeMap::new(),
            eval_index,
            owners: BTreeMap::new(),
        }
    }

    /// Define a CODEOWNERS group's membership.
    pub fn set_owner_group(&mut self, group: &str, members: impl IntoIterator<Item = String>) {
        self.owners
            .insert(group.to_string(), members.into_iter().collect());
    }

    /// Register a new artifact version at DRAFT. Rejects an invalid artifact, a dangling eval_set FK,
    /// or a duplicate `(id, version)` (a merged/tagged version is immutable — a new behavior needs a
    /// new version, never a re-register).
    pub fn register(&mut self, artifact: LayerArtifact) -> Result<(), RegistryError> {
        artifact.validate()?;
        if !self.eval_index.resolves(&artifact.eval_set) {
            return Err(RegistryError::DanglingEvalSet {
                id: artifact.eval_set.id.clone(),
            });
        }
        let key = (artifact.id.clone(), artifact.version);
        if self.artifacts.contains_key(&key) {
            return Err(RegistryError::ImmutableVersion {
                id: key.0,
                version: key.1,
            });
        }
        self.stages.insert(key.clone(), Stage::Draft);
        self.artifacts.insert(key, artifact);
        Ok(())
    }

    pub fn get(&self, id: &str, version: Semver) -> Option<&LayerArtifact> {
        self.artifacts.get(&(id.to_string(), version))
    }

    pub fn stage_of(&self, id: &str, version: Semver) -> Option<Stage> {
        self.stages.get(&(id.to_string(), version)).copied()
    }

    /// Advance an artifact through its lifecycle, enforcing every gate. Returns the new stage.
    pub fn advance(
        &mut self,
        id: &str,
        version: Semver,
        event: LifecycleEvent,
    ) -> Result<Stage, RegistryError> {
        let key = (id.to_string(), version);
        let stage = *self
            .stages
            .get(&key)
            .ok_or_else(|| RegistryError::Unknown {
                id: id.to_string(),
                version,
            })?;
        let artifact = self
            .artifacts
            .get(&key)
            .ok_or_else(|| RegistryError::Unknown {
                id: id.to_string(),
                version,
            })?;

        let next = match (stage, &event) {
            (Stage::Draft, LifecycleEvent::OpenPr) => Stage::Eval,

            (Stage::Eval, LifecycleEvent::SubmitEval(delta)) => {
                // The eval_set FK: the delta must target the artifact's declared eval_set id AND
                // resolve to an eval set that exists.
                if delta.eval_set.id != artifact.eval_set.id {
                    return Err(RegistryError::EvalSetMismatch {
                        declared: artifact.eval_set.id.clone(),
                        submitted: delta.eval_set.id.clone(),
                    });
                }
                if !self.eval_index.resolves(&delta.eval_set) {
                    return Err(RegistryError::DanglingEvalSet {
                        id: delta.eval_set.id.clone(),
                    });
                }
                // The merge-block gate: a regressing (or empty) candidate cannot proceed.
                let reasons = delta.blocking_reasons();
                if !reasons.is_empty() {
                    return Err(RegistryError::EvalRegression(reasons));
                }
                Stage::Review
            }

            (Stage::Review, LifecycleEvent::Approve(app)) => {
                let members = self.owners.get(&artifact.owner);
                let is_owner = members.map(|m| m.contains(&app.approver)).unwrap_or(false);
                if !is_owner {
                    return Err(RegistryError::NotAnOwner {
                        approver: app.approver.clone(),
                        group: artifact.owner.clone(),
                    });
                }
                // Producer≠approver separation of duties.
                if app.approver == artifact.author {
                    return Err(RegistryError::SelfApproval {
                        who: app.approver.clone(),
                    });
                }
                Stage::Canary
            }

            (Stage::Canary, LifecycleEvent::Promote(result)) => match result {
                CanaryResult::Healthy => Stage::Production,
                CanaryResult::Regressed => {
                    return Err(RegistryError::CanaryRegressed);
                }
            },

            (s, LifecycleEvent::Deprecate) if s != Stage::Deprecated => Stage::Deprecated,

            (s, ev) => {
                return Err(RegistryError::IllegalTransition {
                    from: s,
                    event: ev.kind(),
                })
            }
        };

        self.stages.insert(key, next);
        Ok(next)
    }

    /// Build a signed-release pin from a selection of `(id, version)` artifacts — the release job's
    /// job. Each pin records the per-family variant fingerprints (the lock). Every selected artifact
    /// must exist.
    pub fn pin_release(
        &self,
        tag: &str,
        selection: &[(&str, Semver)],
    ) -> Result<Release, RegistryError> {
        let mut layers = BTreeMap::new();
        for (id, version) in selection {
            let art = self
                .get(id, *version)
                .ok_or_else(|| RegistryError::Unknown {
                    id: id.to_string(),
                    version: *version,
                })?;
            let variant_hashes: BTreeMap<ModelFamily, String> = art
                .variants
                .keys()
                .map(|fam| (fam.clone(), content_fingerprint(&art.variants[fam])))
                .collect();
            layers.insert(
                art.id.clone(),
                PinnedLayer {
                    id: art.id.clone(),
                    layer: art.layer,
                    version: art.version,
                    variant_hashes,
                },
            );
        }
        Ok(Release {
            tag: tag.to_string(),
            layers,
        })
    }

    /// Serve-time resolution: pick the release (prod vs canary by weight), then for each requested
    /// layer bind `(layer, id@version, family)` → the variant body, **verifying** it against the
    /// pinned fingerprint (`control.lock`). A drifted/tampered/undeployed variant fails closed.
    ///
    /// Returns the resolved layers in fixed L1→L4 order. `routing_key` (e.g. the turn id) makes the
    /// canary split deterministic — no rng.
    pub fn serve(
        &self,
        deployment: &Deployment,
        routing_key: &str,
        family: &ModelFamily,
        layer_ids: &[&str],
    ) -> Result<Vec<ResolvedLayer>, ServeError> {
        let (release, is_canary) = deployment.select_release(routing_key);
        let mut out = Vec::with_capacity(layer_ids.len());
        for id in layer_ids {
            let pin = release
                .layers
                .get(*id)
                .ok_or_else(|| ServeError::LayerNotInRelease {
                    id: id.to_string(),
                    tag: release.tag.clone(),
                })?;
            let pinned_hash =
                pin.variant_hashes
                    .get(family)
                    .ok_or_else(|| ServeError::VariantNotDeployed {
                        id: id.to_string(),
                        family: family.clone(),
                    })?;
            let art = self
                .get(id, pin.version)
                .ok_or_else(|| ServeError::MissingArtifact {
                    id: id.to_string(),
                    version: pin.version,
                })?;
            let body = art
                .variant(family)
                .ok_or_else(|| ServeError::VariantNotDeployed {
                    id: id.to_string(),
                    family: family.clone(),
                })?;
            let actual = content_fingerprint(body);
            if &actual != pinned_hash {
                return Err(ServeError::LockMismatch {
                    id: id.to_string(),
                    expected: pinned_hash.clone(),
                    actual,
                });
            }
            out.push(ResolvedLayer {
                layer: pin.layer,
                id: pin.id.clone(),
                version: pin.version,
                family: family.clone(),
                body: body.to_string(),
                content_hash: actual,
                from_canary: is_canary,
            });
        }
        out.sort_by_key(|r| r.layer.rank());
        Ok(out)
    }
}

/// One layer bound at serve time, verified against the deployment lock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedLayer {
    pub layer: Layer,
    pub id: String,
    pub version: Semver,
    pub family: ModelFamily,
    pub body: String,
    pub content_hash: String,
    /// True when this layer was served from the canary release (for telemetry / A/B attribution).
    pub from_canary: bool,
}

// ---------------------------------------------------------------------------------------------
// Deployment — env refs + rollback-by-pointer
// ---------------------------------------------------------------------------------------------

/// A layer pinned into a release: its version + per-family content fingerprints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedLayer {
    pub id: String,
    pub layer: Layer,
    pub version: Semver,
    pub variant_hashes: BTreeMap<ModelFamily, String>,
}

/// A signed release (a git tag): the exact set of layer versions + their locks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Release {
    pub tag: String,
    pub layers: BTreeMap<String, PinnedLayer>,
}

/// A canary release riding a % of traffic behind the `prod-canary` ref.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanaryRelease {
    pub release: Release,
    /// 0–100. The Prompt Engine routes this fraction of turns to the canary tree.
    pub weight_pct: u8,
}

/// The deployment: env refs `prod` / `prod-canary`. Rollback is a pointer flip, not a rewrite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Deployment {
    pub prod: Release,
    pub canary: Option<CanaryRelease>,
}

impl Deployment {
    pub fn new(prod: Release) -> Self {
        Deployment { prod, canary: None }
    }

    /// Stage a canary release at `weight_pct` of traffic (clamped to 0–100).
    pub fn start_canary(&mut self, release: Release, weight_pct: u8) {
        self.canary = Some(CanaryRelease {
            release,
            weight_pct: weight_pct.min(100),
        });
    }

    /// **Rollback-by-pointer:** collapse `prod-canary` back onto `prod` (weight → 0), instantly.
    /// Because bodies are immutable + content-addressed, this is byte-for-byte the last-known-good.
    pub fn rollback_canary(&mut self) {
        self.canary = None;
    }

    /// Promote the canary to `prod` at 100% (fast-forward the `prod` ref onto the canary tag),
    /// collapsing the canary. No-op if there is no canary.
    pub fn promote_canary(&mut self) {
        if let Some(c) = self.canary.take() {
            self.prod = c.release;
        }
    }

    /// **Rollback-by-pointer for prod:** repoint `prod` to a prior known-good release. Instant.
    pub fn rollback_prod_to(&mut self, previous: Release) {
        self.prod = previous;
        self.canary = None;
    }

    /// Deterministically pick which release serves this `routing_key`. Returns `(release, is_canary)`.
    /// The split is a stable hash bucket of the key — same key always routes the same way (no rng),
    /// so a turn's release choice is reproducible in replay.
    pub fn select_release(&self, routing_key: &str) -> (&Release, bool) {
        if let Some(c) = &self.canary {
            if c.weight_pct > 0 && bucket_of(routing_key) < c.weight_pct {
                return (&c.release, true);
            }
        }
        (&self.prod, false)
    }
}

/// Map a routing key to a stable bucket in `0..100`.
fn bucket_of(key: &str) -> u8 {
    let fp = content_fingerprint(key);
    // Use the first 8 hex chars as a u32, mod 100 → a stable 0..99 bucket.
    let n = u32::from_str_radix(&fp[..8], 16).unwrap_or(0);
    (n % 100) as u8
}

// ---------------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------------

/// Errors from registry construction / lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryError {
    BadVersion(String),
    InvalidArtifact(Vec<String>),
    DanglingEvalSet { id: String },
    EvalSetMismatch { declared: String, submitted: String },
    EvalRegression(Vec<String>),
    NotAnOwner { approver: String, group: String },
    SelfApproval { who: String },
    CanaryRegressed,
    ImmutableVersion { id: String, version: Semver },
    Unknown { id: String, version: Semver },
    IllegalTransition { from: Stage, event: &'static str },
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegistryError::BadVersion(s) => write!(f, "invalid version '{s}'"),
            RegistryError::InvalidArtifact(ps) => write!(f, "invalid artifact: {}", ps.join("; ")),
            RegistryError::DanglingEvalSet { id } => {
                write!(f, "eval_set '{id}' does not resolve (dangling FK)")
            }
            RegistryError::EvalSetMismatch {
                declared,
                submitted,
            } => write!(
                f,
                "eval delta targets '{submitted}' but the artifact declares '{declared}'"
            ),
            RegistryError::EvalRegression(rs) => {
                write!(f, "eval delta is a blocking regression: {}", rs.join("; "))
            }
            RegistryError::NotAnOwner { approver, group } => {
                write!(f, "'{approver}' is not a member of owner group '{group}'")
            }
            RegistryError::SelfApproval { who } => {
                write!(
                    f,
                    "producer≠approver violated: '{who}' cannot approve their own version"
                )
            }
            RegistryError::CanaryRegressed => {
                write!(f, "canary regressed — cannot promote to production")
            }
            RegistryError::ImmutableVersion { id, version } => {
                write!(
                    f,
                    "{id}@{version} already exists — a tagged version is immutable"
                )
            }
            RegistryError::Unknown { id, version } => write!(f, "unknown artifact {id}@{version}"),
            RegistryError::IllegalTransition { from, event } => {
                write!(f, "illegal transition from {from:?} on {event}")
            }
        }
    }
}

impl std::error::Error for RegistryError {}

/// Errors from serve-time resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServeError {
    LayerNotInRelease {
        id: String,
        tag: String,
    },
    VariantNotDeployed {
        id: String,
        family: ModelFamily,
    },
    MissingArtifact {
        id: String,
        version: Semver,
    },
    LockMismatch {
        id: String,
        expected: String,
        actual: String,
    },
}

impl fmt::Display for ServeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServeError::LayerNotInRelease { id, tag } => {
                write!(f, "layer '{id}' is not pinned in release '{tag}'")
            }
            ServeError::VariantNotDeployed { id, family } => {
                write!(
                    f,
                    "layer '{id}' has no deployed variant for model family '{family}'"
                )
            }
            ServeError::MissingArtifact { id, version } => {
                write!(
                    f,
                    "artifact {id}@{version} referenced by the release is missing"
                )
            }
            ServeError::LockMismatch {
                id,
                expected,
                actual,
            } => write!(
                f,
                "lock mismatch for '{id}': served body hashes {actual}, deployment pins {expected}"
            ),
        }
    }
}

impl std::error::Error for ServeError {}

impl LifecycleEvent {
    fn kind(&self) -> &'static str {
        match self {
            LifecycleEvent::OpenPr => "OpenPr",
            LifecycleEvent::SubmitEval(_) => "SubmitEval",
            LifecycleEvent::Approve(_) => "Approve",
            LifecycleEvent::Promote(_) => "Promote",
            LifecycleEvent::Deprecate => "Deprecate",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ainxt_eval::{CaseResult, EvalReport};

    fn report(pass_rate: f64, mean: u8, n: usize) -> EvalReport {
        // A minimal report whose aggregate fields drive the gate; results are consistent with n.
        let passed = (pass_rate * n as f64).round() as usize;
        let results = (0..n)
            .map(|i| CaseResult {
                id: format!("c{i}"),
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

    fn fam(s: &str) -> ModelFamily {
        ModelFamily::new(s)
    }

    fn artifact(id: &str, layer: Layer, v: Semver, author: &str) -> LayerArtifact {
        let mut variants = BTreeMap::new();
        variants.insert(fam("claude"), format!("[{id}] claude body v{v}"));
        variants.insert(
            fam("qwen"),
            format!("[{id}] qwen body v{v} — restate format, few-shot"),
        );
        LayerArtifact {
            id: id.to_string(),
            layer,
            version: v,
            owner: "platform-prompt-eng".to_string(),
            author: author.to_string(),
            variables: vec!["role_name".to_string()],
            eval_set: EvalSetRef::new("eval.role.l1_support", "^2.0.0").unwrap(),
            model_variants: vec![fam("claude"), fam("qwen")],
            variants,
        }
    }

    fn index() -> EvalSetIndex {
        let mut ix = EvalSetIndex::new();
        ix.insert("eval.role.l1_support", Semver::new(2, 1, 0));
        ix
    }

    // --- semver + version-req -------------------------------------------------------------------

    #[test]
    fn semver_parses_orders_and_rejects_garbage() {
        assert_eq!("3.1.0".parse::<Semver>().unwrap(), Semver::new(3, 1, 0));
        assert!(Semver::new(3, 2, 0) > Semver::new(3, 1, 9));
        assert!(Semver::new(4, 0, 0) > Semver::new(3, 9, 9));
        assert!("3.1".parse::<Semver>().is_err());
        assert!("3.1.0.0".parse::<Semver>().is_err());
        assert!("x.1.0".parse::<Semver>().is_err());
    }

    #[test]
    fn caret_req_matches_same_major_at_or_above_and_rejects_next_major() {
        let req: VersionReq = "^2.0.0".parse().unwrap();
        assert!(req.matches(Semver::new(2, 0, 0)));
        assert!(req.matches(Semver::new(2, 9, 9)));
        assert!(!req.matches(Semver::new(1, 9, 9)));
        assert!(!req.matches(Semver::new(3, 0, 0)));
        let exact: VersionReq = "2.1.0".parse().unwrap();
        assert!(exact.matches(Semver::new(2, 1, 0)));
        assert!(!exact.matches(Semver::new(2, 1, 1)));
        assert!("*"
            .parse::<VersionReq>()
            .unwrap()
            .matches(Semver::new(9, 9, 9)));
    }

    // --- artifact validation --------------------------------------------------------------------

    #[test]
    fn declared_but_missing_variant_is_rejected() {
        let mut art = artifact(
            "prompt.persona",
            Layer::Persona,
            Semver::new(1, 0, 0),
            "alice",
        );
        // Declare a third family but do NOT compile its body.
        art.model_variants.push(fam("gemma"));
        let err = art.validate().unwrap_err();
        match err {
            RegistryError::InvalidArtifact(ps) => {
                assert!(ps
                    .iter()
                    .any(|p| p.contains("gemma") && p.contains("no variant body")));
            }
            other => panic!("expected InvalidArtifact, got {other:?}"),
        }
    }

    #[test]
    fn undeclared_extra_variant_is_rejected() {
        let mut art = artifact(
            "prompt.persona",
            Layer::Persona,
            Semver::new(1, 0, 0),
            "alice",
        );
        art.variants.insert(fam("kimi"), "sneaky".to_string());
        let err = art.validate().unwrap_err();
        assert!(matches!(err, RegistryError::InvalidArtifact(_)));
    }

    // --- registration: FK + immutability --------------------------------------------------------

    #[test]
    fn register_rejects_dangling_eval_set_fk() {
        let mut reg = Registry::new(EvalSetIndex::new()); // empty index → nothing resolves
        let art = artifact("prompt.task", Layer::Task, Semver::new(1, 0, 0), "alice");
        let err = reg.register(art).unwrap_err();
        assert!(matches!(err, RegistryError::DanglingEvalSet { .. }));
    }

    #[test]
    fn a_tagged_version_is_immutable() {
        let mut reg = Registry::new(index());
        let art = artifact("prompt.task", Layer::Task, Semver::new(1, 0, 0), "alice");
        reg.register(art.clone()).unwrap();
        let err = reg.register(art).unwrap_err();
        assert!(matches!(err, RegistryError::ImmutableVersion { .. }));
    }

    // --- the lifecycle happy path + every gate --------------------------------------------------

    #[test]
    fn full_lifecycle_draft_to_production() {
        let mut reg = Registry::new(index());
        let art = artifact("prompt.task", Layer::Task, Semver::new(2, 0, 0), "alice");
        reg.register(art).unwrap();
        reg.set_owner_group(
            "platform-prompt-eng",
            ["bob".to_string(), "carol".to_string()],
        );
        let v = Semver::new(2, 0, 0);

        assert_eq!(reg.stage_of("prompt.task", v), Some(Stage::Draft));
        assert_eq!(
            reg.advance("prompt.task", v, LifecycleEvent::OpenPr)
                .unwrap(),
            Stage::Eval
        );

        let delta = EvalDelta {
            eval_set: EvalSetRef::new("eval.role.l1_support", "^2.0.0").unwrap(),
            baseline: report(0.90, 80, 20),
            candidate: report(0.95, 85, 20), // improvement
            policy: GatePolicy::default(),
        };
        assert_eq!(
            reg.advance("prompt.task", v, LifecycleEvent::SubmitEval(delta))
                .unwrap(),
            Stage::Review
        );

        // A non-owner cannot approve.
        let err = reg
            .advance(
                "prompt.task",
                v,
                LifecycleEvent::Approve(Approval {
                    approver: "mallory".into(),
                }),
            )
            .unwrap_err();
        assert!(matches!(err, RegistryError::NotAnOwner { .. }));

        let bob = LifecycleEvent::Approve(Approval {
            approver: "bob".into(),
        });
        assert_eq!(reg.advance("prompt.task", v, bob).unwrap(), Stage::Canary);

        assert_eq!(
            reg.advance(
                "prompt.task",
                v,
                LifecycleEvent::Promote(CanaryResult::Healthy)
            )
            .unwrap(),
            Stage::Production
        );
    }

    #[test]
    fn eval_delta_regression_blocks_merge() {
        let mut reg = Registry::new(index());
        let art = artifact("prompt.task", Layer::Task, Semver::new(2, 0, 0), "alice");
        reg.register(art).unwrap();
        let v = Semver::new(2, 0, 0);
        reg.advance("prompt.task", v, LifecycleEvent::OpenPr)
            .unwrap();

        // Candidate regresses pass-rate well beyond the non-inferiority margin.
        let delta = EvalDelta {
            eval_set: EvalSetRef::new("eval.role.l1_support", "^2.0.0").unwrap(),
            baseline: report(0.95, 85, 20),
            candidate: report(0.70, 60, 20),
            policy: GatePolicy::default(),
        };
        let err = reg
            .advance("prompt.task", v, LifecycleEvent::SubmitEval(delta))
            .unwrap_err();
        assert!(matches!(err, RegistryError::EvalRegression(_)));
        // Still stuck at EVAL — the gate is merge-blocking, not advisory.
        assert_eq!(reg.stage_of("prompt.task", v), Some(Stage::Eval));
    }

    #[test]
    fn r4_stat_gate_blocks_within_noise_regression() {
        // A real per-case quality regression that leaves the AGGREGATE pass-rate untouched: every
        // case still passes (pass-rate 1.0 on both runs, mean above the floor), yet every case's
        // score drops ~12 points. The naive aggregate gate — which compares only pass-rates — sees no
        // regression and lets it merge (fail-before). The statistically-valid drop-in pairs the runs
        // by case id and blocks the significant per-case regression (pass-after). Exercised on the
        // REAL merge gate of `Registry::advance`, not a mock.
        fn per_case(scores: &[u8]) -> EvalReport {
            let results: Vec<CaseResult> = scores
                .iter()
                .enumerate()
                .map(|(i, &s)| CaseResult {
                    id: format!("c{i}"),
                    output: String::new(),
                    score: s,
                    passed: true,
                    rationale: String::new(),
                })
                .collect();
            let n = results.len();
            let sum: u32 = results.iter().map(|r| r.score as u32).sum();
            EvalReport {
                mean: (sum / n as u32) as u8,
                pass_rate: 1.0,
                passed: n,
                n,
                results,
            }
        }
        // 30 paired cases. Baseline ~86, candidate ~73 — both clear the 70 mean floor, both 100% pass.
        let base_scores: Vec<u8> = (0..30).map(|i| 85 + (i % 3) as u8).collect();
        let cand_scores: Vec<u8> = (0..30)
            .map(|i| 85 + (i % 3) as u8 - 12 - (i % 2) as u8)
            .collect();
        let baseline = per_case(&base_scores);
        let candidate = per_case(&cand_scores);

        // The aggregate signals the naive gate watches are unchanged / within floor.
        assert!((baseline.pass_rate - candidate.pass_rate).abs() < 1e-9);
        assert!(candidate.mean >= GatePolicy::default().min_mean);

        let delta = EvalDelta {
            eval_set: EvalSetRef::new("eval.role.l1_support", "^2.0.0").unwrap(),
            baseline,
            candidate,
            policy: GatePolicy::default(),
        };
        // The drop-in blocks the within-noise regression that the naive pass-rate gate passed.
        assert!(
            !delta.blocking_reasons().is_empty(),
            "statistical drop-in must block a significant per-case regression the naive gate misses"
        );

        // And it is merge-blocking on the REAL Registry, not advisory.
        let mut reg = Registry::new(index());
        reg.register(artifact(
            "prompt.task",
            Layer::Task,
            Semver::new(2, 0, 0),
            "alice",
        ))
        .unwrap();
        let v = Semver::new(2, 0, 0);
        reg.advance("prompt.task", v, LifecycleEvent::OpenPr)
            .unwrap();
        let err = reg
            .advance("prompt.task", v, LifecycleEvent::SubmitEval(delta))
            .unwrap_err();
        assert!(matches!(err, RegistryError::EvalRegression(_)));
        assert_eq!(reg.stage_of("prompt.task", v), Some(Stage::Eval));
    }

    #[test]
    fn empty_eval_run_cannot_certify() {
        let mut reg = Registry::new(index());
        let art = artifact("prompt.task", Layer::Task, Semver::new(2, 0, 0), "alice");
        reg.register(art).unwrap();
        let v = Semver::new(2, 0, 0);
        reg.advance("prompt.task", v, LifecycleEvent::OpenPr)
            .unwrap();
        let delta = EvalDelta {
            eval_set: EvalSetRef::new("eval.role.l1_support", "^2.0.0").unwrap(),
            baseline: report(0.95, 85, 20),
            candidate: report(0.0, 0, 0), // no cases run
            policy: GatePolicy::default(),
        };
        let err = reg
            .advance("prompt.task", v, LifecycleEvent::SubmitEval(delta))
            .unwrap_err();
        assert!(matches!(err, RegistryError::EvalRegression(_)));
    }

    #[test]
    fn eval_delta_targeting_the_wrong_eval_set_is_rejected() {
        let mut reg = Registry::new(index());
        let art = artifact("prompt.task", Layer::Task, Semver::new(2, 0, 0), "alice");
        reg.register(art).unwrap();
        let v = Semver::new(2, 0, 0);
        reg.advance("prompt.task", v, LifecycleEvent::OpenPr)
            .unwrap();
        let delta = EvalDelta {
            eval_set: EvalSetRef::new("eval.some.other", "*").unwrap(),
            baseline: report(0.90, 80, 20),
            candidate: report(0.95, 85, 20),
            policy: GatePolicy::default(),
        };
        let err = reg
            .advance("prompt.task", v, LifecycleEvent::SubmitEval(delta))
            .unwrap_err();
        assert!(matches!(err, RegistryError::EvalSetMismatch { .. }));
    }

    #[test]
    fn producer_cannot_approve_their_own_version() {
        let mut reg = Registry::new(index());
        let art = artifact("prompt.task", Layer::Task, Semver::new(2, 0, 0), "alice");
        reg.register(art).unwrap();
        reg.set_owner_group("platform-prompt-eng", ["alice".to_string()]);
        let v = Semver::new(2, 0, 0);
        reg.advance("prompt.task", v, LifecycleEvent::OpenPr)
            .unwrap();
        let delta = EvalDelta {
            eval_set: EvalSetRef::new("eval.role.l1_support", "^2.0.0").unwrap(),
            baseline: report(0.90, 80, 20),
            candidate: report(0.95, 85, 20),
            policy: GatePolicy::default(),
        };
        reg.advance("prompt.task", v, LifecycleEvent::SubmitEval(delta))
            .unwrap();
        // Alice is an owner-group member AND the author → self-approval blocked.
        let err = reg
            .advance(
                "prompt.task",
                v,
                LifecycleEvent::Approve(Approval {
                    approver: "alice".into(),
                }),
            )
            .unwrap_err();
        assert!(matches!(err, RegistryError::SelfApproval { .. }));
    }

    #[test]
    fn regressed_canary_cannot_promote() {
        let mut reg = Registry::new(index());
        let art = artifact("prompt.task", Layer::Task, Semver::new(2, 0, 0), "alice");
        reg.register(art).unwrap();
        reg.set_owner_group("platform-prompt-eng", ["bob".to_string()]);
        let v = Semver::new(2, 0, 0);
        reg.advance("prompt.task", v, LifecycleEvent::OpenPr)
            .unwrap();
        let delta = EvalDelta {
            eval_set: EvalSetRef::new("eval.role.l1_support", "^2.0.0").unwrap(),
            baseline: report(0.90, 80, 20),
            candidate: report(0.95, 85, 20),
            policy: GatePolicy::default(),
        };
        reg.advance("prompt.task", v, LifecycleEvent::SubmitEval(delta))
            .unwrap();
        reg.advance(
            "prompt.task",
            v,
            LifecycleEvent::Approve(Approval {
                approver: "bob".into(),
            }),
        )
        .unwrap();
        let err = reg
            .advance(
                "prompt.task",
                v,
                LifecycleEvent::Promote(CanaryResult::Regressed),
            )
            .unwrap_err();
        assert!(matches!(err, RegistryError::CanaryRegressed));
        assert_eq!(reg.stage_of("prompt.task", v), Some(Stage::Canary));
    }

    #[test]
    fn illegal_transition_is_rejected() {
        let mut reg = Registry::new(index());
        let art = artifact("prompt.task", Layer::Task, Semver::new(2, 0, 0), "alice");
        reg.register(art).unwrap();
        let v = Semver::new(2, 0, 0);
        // Cannot approve straight from DRAFT.
        let err = reg
            .advance(
                "prompt.task",
                v,
                LifecycleEvent::Approve(Approval {
                    approver: "bob".into(),
                }),
            )
            .unwrap_err();
        assert!(matches!(err, RegistryError::IllegalTransition { .. }));
    }

    // --- serve-time per-model variant selection + lock verification -----------------------------

    #[test]
    fn serve_selects_the_per_model_variant_and_verifies_the_lock() {
        let mut reg = Registry::new(index());
        for (id, layer) in [
            ("prompt.persona", Layer::Persona),
            ("prompt.guards", Layer::Guards),
        ] {
            reg.register(artifact(id, layer, Semver::new(1, 0, 0), "alice"))
                .unwrap();
        }
        let release = reg
            .pin_release(
                "prompt-v1",
                &[
                    ("prompt.persona", Semver::new(1, 0, 0)),
                    ("prompt.guards", Semver::new(1, 0, 0)),
                ],
            )
            .unwrap();
        let dep = Deployment::new(release);

        let ids = ["prompt.persona", "prompt.guards"];
        let claude = reg.serve(&dep, "turn-1", &fam("claude"), &ids).unwrap();
        let qwen = reg.serve(&dep, "turn-1", &fam("qwen"), &ids).unwrap();

        // Different families get DIFFERENT bodies (PE2), and layers come back in L1→L4 order.
        assert_eq!(claude[0].layer, Layer::Persona);
        assert_eq!(claude[1].layer, Layer::Guards);
        assert!(claude[0].body.contains("claude body"));
        assert!(qwen[0].body.contains("qwen body"));
        assert_ne!(claude[0].body, qwen[0].body);
        assert!(claude.iter().all(|r| !r.from_canary));
    }

    #[test]
    fn serve_fails_closed_on_a_tampered_body() {
        // Pin a release, then mutate the underlying artifact body so the lock no longer matches.
        let mut reg = Registry::new(index());
        reg.register(artifact(
            "prompt.persona",
            Layer::Persona,
            Semver::new(1, 0, 0),
            "alice",
        ))
        .unwrap();
        let release = reg
            .pin_release("prompt-v1", &[("prompt.persona", Semver::new(1, 0, 0))])
            .unwrap();
        let dep = Deployment::new(release);

        // Tamper: build a second registry whose body differs but claims the same version.
        let mut tampered = artifact(
            "prompt.persona",
            Layer::Persona,
            Semver::new(1, 0, 0),
            "alice",
        );
        tampered
            .variants
            .insert(fam("claude"), "SWAPPED malicious body".to_string());
        let mut reg2 = Registry::new(index());
        reg2.register(tampered).unwrap();

        let err = reg2
            .serve(&dep, "turn-1", &fam("claude"), &["prompt.persona"])
            .unwrap_err();
        assert!(matches!(err, ServeError::LockMismatch { .. }));
    }

    #[test]
    fn serve_rejects_a_family_with_no_deployed_variant() {
        let mut reg = Registry::new(index());
        reg.register(artifact(
            "prompt.persona",
            Layer::Persona,
            Semver::new(1, 0, 0),
            "alice",
        ))
        .unwrap();
        let release = reg
            .pin_release("prompt-v1", &[("prompt.persona", Semver::new(1, 0, 0))])
            .unwrap();
        let dep = Deployment::new(release);
        let err = reg
            .serve(&dep, "t", &fam("gemma"), &["prompt.persona"])
            .unwrap_err();
        assert!(matches!(err, ServeError::VariantNotDeployed { .. }));
    }

    // --- rollback-by-pointer + canary split -----------------------------------------------------

    #[test]
    fn canary_split_is_deterministic_and_weight_respecting() {
        let mut reg = Registry::new(index());
        reg.register(artifact(
            "prompt.persona",
            Layer::Persona,
            Semver::new(1, 0, 0),
            "alice",
        ))
        .unwrap();
        reg.register(artifact(
            "prompt.persona",
            Layer::Persona,
            Semver::new(1, 1, 0),
            "alice",
        ))
        .unwrap();
        let prod = reg
            .pin_release("v1", &[("prompt.persona", Semver::new(1, 0, 0))])
            .unwrap();
        let canary = reg
            .pin_release("v1.1", &[("prompt.persona", Semver::new(1, 1, 0))])
            .unwrap();
        let mut dep = Deployment::new(prod);
        dep.start_canary(canary, 30);

        // Deterministic: the same key always routes the same way.
        let a = dep.select_release("turn-42").1;
        let b = dep.select_release("turn-42").1;
        assert_eq!(a, b);

        // Roughly weight_pct of a spread of keys land on canary; never wildly off.
        let n = 1000;
        let hits = (0..n)
            .filter(|i| dep.select_release(&format!("turn-{i}")).1)
            .count();
        assert!(
            (200..400).contains(&hits),
            "≈30% of 1000 keys should hit canary, got {hits}"
        );
    }

    #[test]
    fn rollback_canary_is_an_instant_pointer_flip() {
        let mut reg = Registry::new(index());
        reg.register(artifact(
            "prompt.persona",
            Layer::Persona,
            Semver::new(1, 0, 0),
            "alice",
        ))
        .unwrap();
        reg.register(artifact(
            "prompt.persona",
            Layer::Persona,
            Semver::new(2, 0, 0),
            "alice",
        ))
        .unwrap();
        let good = reg
            .pin_release("good", &[("prompt.persona", Semver::new(1, 0, 0))])
            .unwrap();
        let bad = reg
            .pin_release("bad", &[("prompt.persona", Semver::new(2, 0, 0))])
            .unwrap();
        let mut dep = Deployment::new(good);
        dep.start_canary(bad, 100); // 100% canary

        // With 100% weight the bad v2 body serves.
        let served = reg
            .serve(&dep, "t", &fam("claude"), &["prompt.persona"])
            .unwrap();
        assert!(served[0].body.contains("v2.0.0"));
        assert!(served[0].from_canary);

        // Rollback: instant pointer flip back to the last-known-good v1 — byte-for-byte.
        dep.rollback_canary();
        let served = reg
            .serve(&dep, "t", &fam("claude"), &["prompt.persona"])
            .unwrap();
        assert!(served[0].body.contains("v1.0.0"));
        assert!(!served[0].from_canary);
    }

    #[test]
    fn promote_canary_fast_forwards_prod() {
        let mut reg = Registry::new(index());
        reg.register(artifact(
            "prompt.persona",
            Layer::Persona,
            Semver::new(1, 0, 0),
            "alice",
        ))
        .unwrap();
        reg.register(artifact(
            "prompt.persona",
            Layer::Persona,
            Semver::new(2, 0, 0),
            "alice",
        ))
        .unwrap();
        let v1 = reg
            .pin_release("v1", &[("prompt.persona", Semver::new(1, 0, 0))])
            .unwrap();
        let v2 = reg
            .pin_release("v2", &[("prompt.persona", Semver::new(2, 0, 0))])
            .unwrap();
        let mut dep = Deployment::new(v1);
        dep.start_canary(v2, 10);
        dep.promote_canary();
        assert!(dep.canary.is_none());
        // Now 100% of traffic serves the promoted v2.
        let served = reg
            .serve(&dep, "any", &fam("claude"), &["prompt.persona"])
            .unwrap();
        assert!(served[0].body.contains("v2.0.0"));
    }

    // --- manifest front-matter parsing ----------------------------------------------------------

    #[test]
    fn manifest_front_matter_parses_and_binds_to_variant_bodies() {
        let json = r#"{
            "kind": "prompt",
            "id": "prompt.persona-enterprise-core",
            "layer": "persona",
            "version": "3.1.0",
            "owner": "platform-prompt-eng",
            "author": "alice",
            "variables": ["role_name", "ticket_tier"],
            "model_variants": ["claude", "qwen"],
            "eval_set": { "id": "eval.role.l1_support", "version": "^2.0.0" }
        }"#;
        let m: Manifest = serde_json::from_str(json).unwrap();
        assert_eq!(m.layer, Layer::Persona);
        let mut bodies = BTreeMap::new();
        bodies.insert("claude".to_string(), "claude body".to_string());
        bodies.insert("qwen".to_string(), "qwen body".to_string());
        let art = m.into_artifact(bodies).unwrap();
        assert_eq!(art.version, Semver::new(3, 1, 0));
        assert_eq!(
            art.eval_set.version_req,
            VersionReq::Caret(Semver::new(2, 0, 0))
        );
        assert_eq!(art.model_variants.len(), 2);
        assert!(art.variant(&fam("qwen")).is_some());
    }

    #[test]
    fn manifest_missing_declared_variant_body_is_rejected() {
        let json = r#"{
            "kind": "prompt", "id": "x", "layer": "task", "version": "1.0.0",
            "owner": "g", "author": "a", "model_variants": ["claude", "qwen"],
            "eval_set": { "id": "e", "version": "*" }
        }"#;
        let m: Manifest = serde_json::from_str(json).unwrap();
        let mut bodies = BTreeMap::new();
        bodies.insert("claude".to_string(), "only claude".to_string());
        assert!(m.into_artifact(bodies).is_err());
    }
}
