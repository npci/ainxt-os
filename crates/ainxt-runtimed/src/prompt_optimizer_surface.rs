// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! **Gap closure — `ainxt-promptopt` had zero live driver.** `optimize`/`optimize_all`/`ab_promote`
//! (`PROMPT_ENGINEERING.md` §5) and the optimizer → Registry bridge (`ainxt_promptopt::bridge`, §5.5)
//! were fully implemented and exhaustively unit-tested, but nothing outside the crate's own tests ever
//! called them — the search-and-rank engine and the DRAFT-landing bridge were both real, wired to each
//! other, and reachable from nowhere.
//!
//! [`run_prompt_optimizer_sweep_tick`] is the composition-root entrypoint a daemon cadence calls: it
//! drives ONE pass of the optimizer over every supplied model, and bridges each model's certified
//! winner into a per-model-family **DRAFT** artifact in the live [`Registry`] — never further. This
//! mirrors [`crate::workforce_surface::run_workforce_nightly_tick`]'s pattern exactly: a single pure
//! pass per call, drivable by a real cron/timer, previously reachable only from library tests.
//!
//! **`needs_hot_wiring` / INFRA** (honestly unimplemented on the air-gapped default, exactly as
//! `run_workforce_nightly_tick` documents for its own two seams):
//! 1. a live [`ModelSeam`] per model family backed by the real Provider Gateway (today the caller
//!    supplies deterministic/test seams — there is no network call here); and
//! 2. a real cron/timer that invokes this tick on a schedule (today it is a single pass per call, not
//!    a spawned loop) — the same honest gap `run_workforce_nightly_tick` flags for its own cadence, for
//!    the same reason: a fabricated timer with no live gold-set/model source would just call this with
//!    empty inputs forever, which is worse than being explicit that the scheduling loop itself is the
//!    remaining infra wire.

use ainxt_eval::{EvalCase, QualityJudge};
use ainxt_prompt::constrained::{ConstrainedDecoder, DecodeError};
use ainxt_prompt::registry::{
    EvalSetIndex, EvalSetRef, Layer, ModelFamily, Registry, Semver, Stage,
};
use ainxt_promptopt::bridge::{register_draft, winner_to_draft, BridgeError, DraftSpec};
use ainxt_promptopt::budget::{optimize_budgeted, CostModel, OptBudget};
use ainxt_promptopt::constrained_judge::ConstrainedLlmJudge;
use ainxt_promptopt::propose::{Exemplar, ProposeCatalog, ProposeConfig};
use ainxt_promptopt::{
    ab_promote, optimize_all, optimize_with_holdout, ModelSeam, Promotion, PromptVariant,
};
use ainxt_protocol::Event;
use ainxt_runtime::provider::Provider;
use std::sync::Arc;

/// The non-body metadata needed to mint this sweep's DRAFT artifacts — one per model family, all at the
/// same target `next_version` (a real scheduler bumps this between sweeps; see
/// [`run_prompt_optimizer_sweep_tick`]'s infra note — version-bumping policy is a caller decision, not
/// hardcoded here).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromptSweepSpec {
    /// The layer artifact id to author a new version of (typically an L3 task layer).
    pub id: String,
    pub layer: Layer,
    pub next_version: Semver,
    pub owner: String,
    pub variables: Vec<String>,
    pub eval_set: EvalSetRef,
}

/// One model's sweep outcome. The sweep never silently drops a model — every entry in
/// [`run_prompt_optimizer_sweep_tick`]'s result corresponds 1:1 to an input model, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromptSweepOutcome {
    /// The optimizer certified a winner for this model and it landed as a new DRAFT (never further —
    /// the optimizer never auto-promotes, `PROMPT_ENGINEERING.md` §5.5).
    Drafted {
        model_id: String,
        family: ModelFamily,
        version: Semver,
    },
    /// No DRAFT landed for this model: no winner was certified (empty gold/variants), or the Registry
    /// refused the artifact (dangling eval_set FK, duplicate version, invalid composition).
    Skipped { model_id: String, reason: String },
}

/// **The composition-root entrypoint a daemon cadence calls.** Runs [`optimize_all`] once (per-model,
/// always — `PROMPT_ENGINEERING.md` §5.4, so the winner for one family is never assumed valid for
/// another) over `variants`/`gold`/`judge`.
///
/// The Registry's [`LayerArtifact`](ainxt_prompt::registry::LayerArtifact) declares ALL its compiled
/// model families together at ONE `(id, version)` — a tagged version is immutable, so two separate
/// single-family artifacts can never share a version. This tick therefore builds each model's winner
/// via [`winner_to_draft`] (the SAME per-family bridge every `ainxt-promptopt` unit test exercises),
/// then MERGES every model that certified a winner into one multi-family artifact before the single
/// [`register_draft`] call — never one `register` per model, which would collide on the second call.
///
/// `models` pairs each [`ModelSeam`] with the [`ModelFamily`] its winning template compiles for in the
/// Registry (the optimizer's `ModelSeam::id()` is a free-form seam identity; `ModelFamily` is the
/// Registry's own per-model-variant key — the caller supplies the mapping because only the caller knows
/// which served deployment a given seam represents). The sweep never silently drops a model: a model
/// with no certified winner, or whose merge would violate [`LayerArtifact::validate`], is reported
/// [`PromptSweepOutcome::Skipped`] with the precise reason, and does not block the other models' drafts.
pub fn run_prompt_optimizer_sweep_tick(
    registry: &mut Registry,
    variants: &[PromptVariant],
    gold: &[EvalCase],
    judge: &dyn QualityJudge,
    models: &[(&dyn ModelSeam, ModelFamily)],
    spec: &PromptSweepSpec,
) -> Vec<PromptSweepOutcome> {
    let seams: Vec<&dyn ModelSeam> = models.iter().map(|(m, _)| *m).collect();
    let optimizations = optimize_all(variants, gold, judge, &seams);

    let mut merged: Option<ainxt_prompt::registry::LayerArtifact> = None;
    // (model_id, family, per-family bridge result) — resolved into final outcomes once we know
    // whether the merged artifact (if any) actually registered.
    let mut prepared: Vec<(String, ModelFamily, Result<(), BridgeError>)> = Vec::new();

    for (opt, (_, family)) in optimizations.iter().zip(models.iter()) {
        let draft_spec = ainxt_promptopt::bridge::DraftSpec {
            id: spec.id.clone(),
            layer: spec.layer,
            version: spec.next_version,
            owner: spec.owner.clone(),
            author: "prompt-optimizer".into(),
            variables: spec.variables.clone(),
            eval_set: spec.eval_set.clone(),
        };
        match winner_to_draft(&draft_spec, family, variants, opt) {
            Ok(single_family) => {
                match &mut merged {
                    None => merged = Some(single_family),
                    Some(existing) => {
                        existing.model_variants.extend(single_family.model_variants);
                        existing.variants.extend(single_family.variants);
                    }
                }
                prepared.push((opt.model_id.clone(), family.clone(), Ok(())));
            }
            Err(e) => prepared.push((opt.model_id.clone(), family.clone(), Err(e))),
        }
    }

    let registered: Option<Result<Stage, BridgeError>> =
        merged.map(|artifact| register_draft(registry, artifact));

    prepared
        .into_iter()
        .map(|(model_id, family, per_family)| match per_family {
            Err(e) => PromptSweepOutcome::Skipped {
                model_id,
                reason: e.to_string(),
            },
            Ok(()) => match &registered {
                Some(Ok(_stage)) => PromptSweepOutcome::Drafted {
                    model_id,
                    family,
                    version: spec.next_version,
                },
                Some(Err(e)) => PromptSweepOutcome::Skipped {
                    model_id,
                    reason: e.to_string(),
                },
                None => unreachable!("a model with Ok(()) implies `merged` was populated"),
            },
        })
        .collect()
}

// ============================ gap6-promptopt-completeness: the fuller pipeline ============================
//
// **Gap closure — three named `ainxt-promptopt` capabilities had zero live driver.** The crate's own
// doc (`lib.rs`) names three disciplines beyond the search-and-rank core [`optimize`]/[`optimize_all`]
// that [`run_prompt_optimizer_sweep_tick`] above never used:
//
// 1. [`ab_promote`] — A/B **non-inferiority** promotion: a challenger only displaces the live champion
//    if it clears a margin, never on a bare "best of the candidates I happened to score" basis.
// 2. [`optimize_with_holdout`] — the **overfit guard**: a winner is confirmed on a disjoint holdout
//    split before it is trusted, catching a candidate that memorized the visible set.
// 3. [`propose`](ainxt_promptopt::propose::propose) + [`optimize_budgeted`] — genuine **candidate
//    generation** under a **cost budget**, instead of scoring a caller-supplied fixed variant list.
//
// [`optimize_all`] (used by the tick above) is the simpler subset: it ranks a FIXED variant list with
// no proposal step, no spend cap, no holdout confirmation, and no comparison against what is actually
// live. [`run_prompt_optimizer_sweep_tick_v2`] is the fuller, more rigorous pipeline these three items
// together describe: **propose → optimize_budgeted → optimize_with_holdout → ab_promote**, and only a
// challenger that clears BOTH the holdout overfit guard AND the A/B non-inferiority check against its
// model's champion is bridged into a DRAFT (never further than DRAFT — the optimizer still never
// auto-promotes to production, exactly as [`winner_to_draft`]'s own doc requires).
//
// This is added as a SIBLING to [`run_prompt_optimizer_sweep_tick`], not a replacement: fully replacing
// `optimize_all`'s simpler behavior risked a regression this change could not fully verify in one pass,
// so both ticks run side by side from [`spawn_prompt_optimizer_tick`], sharing the SAME `Registry`,
// `ModelSeam`, and `QualityJudge` handles that tick already builds each cycle — never a second,
// disconnected optimizer state.

/// One model's outcome under the fuller propose→budget→holdout→A/B pipeline. Every entry in
/// [`run_prompt_optimizer_sweep_tick_v2`]'s result corresponds 1:1 to an input model, in order — the
/// sweep never silently drops a model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromptSweepOutcomeV2 {
    /// The budgeted challenger cleared the holdout overfit guard AND the A/B non-inferiority check
    /// against its champion — it landed as a new per-family DRAFT (never further than DRAFT).
    PromotedDraft {
        model_id: String,
        family: ModelFamily,
        version: Semver,
        challenger_id: String,
    },
    /// The challenger did not clear the A/B margin against the live champion — the champion holds, and
    /// no draft was even created for it (the A/B check gates whether a draft is worth registering).
    KeptChampion {
        model_id: String,
        champion_id: String,
    },
    /// No draft landed for this model: no budgeted winner was found (empty gold / budget exhausted
    /// before any candidate), the winner was flagged overfit on the holdout, or the Registry refused
    /// the artifact.
    Skipped { model_id: String, reason: String },
}

/// **The fuller, more rigorous composition-root pipeline** — propose candidates from `seed`, optimize
/// them under `budget` (real spend accounting, [`optimize_budgeted`]), confirm the round's winner on a
/// disjoint `holdout_gold` (real overfit guard, [`optimize_with_holdout`]), and only bridge it into a
/// DRAFT if it ALSO clears a genuine A/B non-inferiority check against its model's live `champion`
/// ([`ab_promote`]) — reusing the SAME per-family merge-then-register-once discipline
/// [`run_prompt_optimizer_sweep_tick`] uses, so two families' drafts can never collide on one version.
///
/// `models` pairs each [`ModelSeam`] with the [`ModelFamily`] its winning template compiles for AND the
/// `champion` variant currently considered live for that family (the caller supplies the champion for
/// the same reason [`run_prompt_optimizer_sweep_tick`]'s caller supplies `variants`/`gold`: only the
/// caller knows which template is actually the incumbent — see [`spawn_prompt_optimizer_tick`]'s doc for
/// the shipped-default's honest stand-in). The A/B check is scored on `holdout_gold` — genuinely
/// out-of-sample for both champion and challenger, not the set either was tuned against.
///
/// Per model: a budgeted run with no certified winner, or an overfit-flagged winner, is `Skipped` with
/// the precise reason; a winner that fails the A/B margin is `KeptChampion`; only a winner that clears
/// both gates is bridged and, on a successful (possibly merged, multi-family) registration, reported
/// [`PromptSweepOutcomeV2::PromotedDraft`].
#[allow(clippy::too_many_arguments)]
pub fn run_prompt_optimizer_sweep_tick_v2(
    registry: &mut Registry,
    seed: &PromptVariant,
    catalog: &ProposeCatalog,
    exemplars: &[Exemplar],
    propose_cfg: ProposeConfig,
    train_gold: &[EvalCase],
    holdout_gold: &[EvalCase],
    judge: &dyn QualityJudge,
    cost: CostModel,
    budget: OptBudget,
    improve_margin: f64,
    holdout_margin: f64,
    ab_margin: f64,
    models: &[(&dyn ModelSeam, ModelFamily, PromptVariant)],
    spec: &PromptSweepSpec,
) -> Vec<PromptSweepOutcomeV2> {
    // Deferred per-model results: whether/what to bridge is decided before we know if the eventual
    // MERGED multi-family artifact will actually register (mirrors `run_prompt_optimizer_sweep_tick`'s
    // own two-phase prepare-then-register shape, so families never collide on one `register_draft` call).
    enum Prep {
        Pending {
            model_id: String,
            family: ModelFamily,
            challenger_id: String,
        },
        KeptChampion {
            model_id: String,
            champion_id: String,
        },
        Skipped {
            model_id: String,
            reason: String,
        },
    }

    let mut merged: Option<ainxt_prompt::registry::LayerArtifact> = None;
    let mut prepared: Vec<Prep> = Vec::new();

    for (seam, family, champion) in models {
        let seam: &dyn ModelSeam = *seam;
        let model_id = seam.id().to_string();

        // 1) Propose + optimize under a hard spend budget (the SAME `propose` step every round uses).
        let budgeted = optimize_budgeted(
            seed,
            catalog,
            exemplars,
            propose_cfg,
            train_gold,
            judge,
            seam,
            cost,
            budget,
            improve_margin,
        );
        let (Some(best), Some(best_template)) =
            (budgeted.best.clone(), budgeted.best_template.clone())
        else {
            prepared.push(Prep::Skipped {
                model_id,
                reason: format!(
                    "no budgeted winner (stop_reason={:?})",
                    budgeted.stop_reason
                ),
            });
            continue;
        };
        let challenger = PromptVariant::new(&best.variant_id, &best_template);

        // 2) Overfit guard: confirm the challenger on a DISJOINT holdout split before trusting it.
        let holdout_outcome = optimize_with_holdout(
            std::slice::from_ref(&challenger),
            train_gold,
            holdout_gold,
            judge,
            seam,
            holdout_margin,
        );
        if holdout_outcome.overfit {
            prepared.push(Prep::Skipped {
                model_id,
                reason: format!(
                    "challenger '{}' regressed on the holdout beyond margin {holdout_margin} — \
                     refusing promotion (overfit guard)",
                    challenger.id
                ),
            });
            continue;
        }

        // 3) A/B non-inferiority: the challenger must beat the LIVE champion beyond `ab_margin` on the
        // out-of-sample holdout — a marginal or worse challenger keeps the incumbent.
        let ab = ab_promote(champion, &challenger, holdout_gold, judge, seam, ab_margin);
        if ab.decision == Promotion::KeepChampion {
            prepared.push(Prep::KeptChampion {
                model_id,
                champion_id: champion.id.clone(),
            });
            continue;
        }

        // 4) Promoted: bridge into a per-family DRAFT (never further than DRAFT — the optimizer still
        // never auto-promotes; the gated lifecycle owns everything past this point).
        let draft_spec = DraftSpec {
            id: spec.id.clone(),
            layer: spec.layer,
            version: spec.next_version,
            owner: spec.owner.clone(),
            author: "prompt-optimizer-v2".into(),
            variables: spec.variables.clone(),
            eval_set: spec.eval_set.clone(),
        };
        match winner_to_draft(
            &draft_spec,
            family,
            std::slice::from_ref(&challenger),
            &holdout_outcome.train,
        ) {
            Ok(single_family) => {
                match &mut merged {
                    None => merged = Some(single_family),
                    Some(existing) => {
                        existing.model_variants.extend(single_family.model_variants);
                        existing.variants.extend(single_family.variants);
                    }
                }
                prepared.push(Prep::Pending {
                    model_id,
                    family: family.clone(),
                    challenger_id: challenger.id.clone(),
                });
            }
            Err(e) => prepared.push(Prep::Skipped {
                model_id,
                reason: e.to_string(),
            }),
        }
    }

    let registered: Option<Result<Stage, BridgeError>> =
        merged.map(|artifact| register_draft(registry, artifact));

    prepared
        .into_iter()
        .map(|entry| match entry {
            Prep::KeptChampion {
                model_id,
                champion_id,
            } => PromptSweepOutcomeV2::KeptChampion {
                model_id,
                champion_id,
            },
            Prep::Skipped { model_id, reason } => {
                PromptSweepOutcomeV2::Skipped { model_id, reason }
            }
            Prep::Pending {
                model_id,
                family,
                challenger_id,
            } => match &registered {
                Some(Ok(_stage)) => PromptSweepOutcomeV2::PromotedDraft {
                    model_id,
                    family,
                    version: spec.next_version,
                    challenger_id,
                },
                Some(Err(e)) => PromptSweepOutcomeV2::Skipped {
                    model_id,
                    reason: e.to_string(),
                },
                None => unreachable!("a Pending entry implies `merged` was populated"),
            },
        })
        .collect()
}

// ============================ prompt-governance #1: a real served constrained-decoding caller ============================

/// Drain a [`Provider::stream`] receiver into its concatenated text reply — the SAME discipline
/// `ainxt_eval::live::LiveProviderJudge`'s private `drain_reply` uses (that helper is crate-private to
/// `ainxt-eval`, so this is a standalone twin over the identical [`Event`] contract): text deltas
/// concatenate, an [`Event::Error`] fails closed, tool/usage/reasoning/artifact events are ignored (not
/// the scored/completed text), and a tool-approval request refuses rather than guessing.
async fn drain_provider_reply(provider: &dyn Provider, prompt: &str) -> Result<String, String> {
    let mut rx = provider.stream(prompt);
    let mut out = String::new();
    while let Some(ev) = rx.recv().await {
        match ev {
            Event::TextDelta(s) => out.push_str(&s),
            Event::Error(e) => return Err(e),
            Event::Done => break,
            Event::ReasoningDelta(_)
            | Event::ToolCallStart { .. }
            | Event::ToolResult { .. }
            | Event::Artifact { .. }
            | Event::Usage { .. } => {}
            Event::ApprovalRequest { .. } => {
                return Err("model requested tool approval — refusing to score/complete".into());
            }
        }
    }
    Ok(out)
}

/// Bridge the sync [`ConstrainedDecoder`]/[`ModelSeam`] seams into the async [`Provider::stream`].
/// UNLIKE `ainxt_eval::live::LiveProviderJudge::score_blocking` (whose real caller is a plain, no-
/// runtime CI-gate process), every caller here — [`run_prompt_optimizer_sweep_tick`]'s sync `judge`/
/// `models` parameters — is invoked from WITHIN an already-running multi-threaded Tokio runtime (the
/// daemon's own `#[tokio::main(flavor = "multi_thread")]`, via [`spawn_prompt_optimizer_tick`]'s
/// spawned task). Spinning up a SECOND runtime and calling its own `block_on` from inside that context
/// panics ("Cannot start a runtime from within a runtime"). [`tokio::task::block_in_place`] is the
/// correct bridge for exactly this shape: it moves the current task onto a blocking-pool thread so
/// `Handle::current().block_on` can drive the SAME runtime's async work without nesting. Requires a
/// multi-threaded runtime on the calling thread (true for both the daemon and every test here).
fn blocking_provider_call(provider: &dyn Provider, prompt: &str) -> Result<String, String> {
    let prompt = prompt.to_string();
    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current()
            .block_on(async move { drain_provider_reply(provider, &prompt).await })
    })
}

/// **Gap closure (prompt-governance #1) — `ainxt_prompt::constrained::StructuredOutputEngine`'s only
/// cross-crate caller was `ainxt_promptopt::constrained_judge::ConstrainedLlmJudge`, which itself had
/// zero callers in `ainxt-runtimed`/`ainxt-server` — the grammar-attach + validate + bounded-repair
/// guarantee (PE3, §4) had no real served path, only its own crate's unit tests.**
///
/// This is that real caller: a [`ConstrainedDecoder`] backed by ANY real [`Provider`] adapter
/// (Anthropic / OpenAI-schema / Gemini / local — the SAME seam every other model call in the runtime
/// goes through, ADR-006), so [`ConstrainedLlmJudge`] is genuinely reachable from the served daemon
/// (via [`spawn_prompt_optimizer_tick`]) instead of only from `ainxt-promptopt`'s own tests.
///
/// `grammar_native() == false`: no `Provider` adapter exposes a native GBNF-attach hook at this layer
/// today, so every call goes through `StructuredOutputEngine`'s bounded prompted-JSON repair loop — the
/// honest backstop path, never a fabricated "native" claim.
pub struct ProviderConstrainedDecoder {
    provider: Arc<dyn Provider>,
}

impl ProviderConstrainedDecoder {
    pub fn new(provider: Arc<dyn Provider>) -> Self {
        ProviderConstrainedDecoder { provider }
    }
}

impl ConstrainedDecoder for ProviderConstrainedDecoder {
    fn grammar_native(&self) -> bool {
        false
    }
    fn decode(&self, prompt: &str, _grammar: Option<&str>) -> Result<String, DecodeError> {
        blocking_provider_call(self.provider.as_ref(), prompt).map_err(DecodeError)
    }
}

/// A [`ModelSeam`] over any real [`Provider`] — the live half of `run_prompt_optimizer_sweep_tick`'s
/// own documented gap ("a live ModelSeam per model family backed by the real Provider Gateway ...
/// there is no network call here"). A transport failure completes as an empty string (fail-soft:
/// the optimizer's own judge then scores the empty completion on its merits — never a panic, never a
/// silently fabricated answer).
pub struct ProviderModelSeam {
    provider: Arc<dyn Provider>,
}

impl ProviderModelSeam {
    pub fn new(provider: Arc<dyn Provider>) -> Self {
        ProviderModelSeam { provider }
    }
}

impl ModelSeam for ProviderModelSeam {
    fn id(&self) -> &str {
        self.provider.id()
    }
    fn tier(&self) -> ainxt_types::Tier {
        self.provider.tier().unwrap_or(ainxt_types::Tier::Medium)
    }
    fn complete(&self, prompt: &str) -> String {
        blocking_provider_call(self.provider.as_ref(), prompt).unwrap_or_default()
    }
}

// ============================ prompt-governance #6: the missing cadence ============================

/// The eval_set this sweep's shipped-default target references — registered into the tick's own
/// private [`Registry`] at spawn time so `register_draft` never dangling-FK-rejects the first sweep.
const PROMPT_SWEEP_EVAL_SET: &str = "eval.chat.task.optimizer-sweep";

/// The shipped-default illustrative gold-set for [`spawn_prompt_optimizer_tick`]'s sweep target —
/// mirrors `ainxt_prompt::served`'s own precedent of a shipped canonical constant (a real deployment's
/// Role/gold-set is a further config wire, exactly as `run_prompt_optimizer_sweep_tick`'s own doc
/// flags for its `variants`/`gold` inputs).
fn default_prompt_sweep_gold() -> Vec<EvalCase> {
    vec![EvalCase::new(
        "prompt-optimizer-g1",
        "how did UPI settlement volume grow last quarter?",
        "must mention UPI",
        60,
    )]
}

/// The shipped-default candidate templates for the sweep target's L3 Task layer.
fn default_prompt_sweep_variants() -> Vec<PromptVariant> {
    vec![
        PromptVariant::new("plain", "{input}"),
        PromptVariant::new(
            "grounded",
            "Answer the user's question grounded in the retrieved context, citing UPI figures \
             where relevant: {input}",
        ),
    ]
}

fn default_prompt_sweep_spec(next_version: Semver) -> PromptSweepSpec {
    PromptSweepSpec {
        id: "prompt.chat.task.optimizer-sweep".into(),
        layer: Layer::Task,
        next_version,
        owner: "platform-prompt-eng".into(),
        variables: vec![],
        eval_set: EvalSetRef::new(PROMPT_SWEEP_EVAL_SET, "^1.0.0").expect("valid eval_set ref"),
    }
}

/// The shipped-default illustrative HOLDOUT gold-set for [`run_prompt_optimizer_sweep_tick_v2`]'s sweep
/// target — disjoint case id AND topic from [`default_prompt_sweep_gold`] (train), so the shipped
/// cadence's overfit guard has a genuinely out-of-sample split to confirm against, not a degenerate
/// train==holdout stand-in. A real deployment's own disjoint holdout is a further config wire, exactly
/// as the train gold-set/variants above are already flagged.
fn default_prompt_sweep_holdout_gold() -> Vec<EvalCase> {
    vec![EvalCase::new(
        "prompt-optimizer-h1",
        "how did NEFT clearing volume trend last quarter?",
        "must mention NEFT",
        60,
    )]
}

/// The DraftSpec for [`run_prompt_optimizer_sweep_tick_v2`]'s shipped-default sweep target — a
/// DISTINCT artifact id from [`default_prompt_sweep_spec`] (v1) so the two ticks, sharing the SAME
/// [`Registry`] each cycle, never collide registering at the same `(id, version)`.
fn default_prompt_sweep_spec_v2(next_version: Semver) -> PromptSweepSpec {
    PromptSweepSpec {
        id: "prompt.chat.task.optimizer-sweep-v2".into(),
        layer: Layer::Task,
        next_version,
        owner: "platform-prompt-eng".into(),
        variables: vec![],
        eval_set: EvalSetRef::new(PROMPT_SWEEP_EVAL_SET, "^1.0.0").expect("valid eval_set ref"),
    }
}

/// **Gap closure (prompt-governance #6) — `run_prompt_optimizer_sweep_tick` was reachable only from
/// this module's own unit tests: nothing on the daemon ever called it on a cadence, and its
/// `judge`/`models` parameters had no real (non-test) construction anywhere in `ainxt-runtimed`.**
///
/// Resolves a real [`Provider`] from `loaded.runtime.models` through the SAME seam
/// [`build_chat_classifier_model`](crate::build_chat_classifier_model) already uses for the Stage-2
/// classifier (an OpenAI-schema/local provider with both an endpoint and, for cloud, an API key).
/// **`None`** on the air-gapped default (no such provider configured) — no cadence spawned, matching
/// every other conditionally-live cadence in this crate (`spawn_health_sweep`, `spawn_autoscale_tick`,
/// `spawn_attestation_refresh`). `Some` spawns a REAL recurring tick that drives
/// [`run_prompt_optimizer_sweep_tick`] with [`ConstrainedLlmJudge`]`<`[`ProviderConstrainedDecoder`]`>`
/// (prompt-governance #1) as the judge and [`ProviderModelSeam`] as the model, both over the SAME real
/// provider — a genuinely live model is asked, through the real Provider Gateway, to complete real
/// candidate templates, and the real `StructuredOutputEngine` bounded-repair loop scores the verdict.
///
/// **`needs_hot_wiring` / INFRA, honestly**: (1) the illustrative gold-set/variants above are a SHIPPED
/// DEFAULT sweep target, not a real deployment's own Role/gold-set (a further config wire, exactly as
/// `run_prompt_optimizer_sweep_tick`'s own doc already flags); (2) the tick operates on a FRESH,
/// private [`Registry`] held by this spawned task, not the SAME live registry `build_served_chat_prompt`
/// owns for `/v1/chat` — landing a certified DRAFT onto the actually-served registry is a separate wire
/// (the same shared-mutable-deployment problem prompt-governance #4's canary handle solves for the
/// pointer-flip case, not yet solved here for the optimizer's registry). What IS real: the constrained-
/// decoding judge, the model seam, and the recurring cadence itself.
///
/// **gap6-promptopt-completeness**: every cycle, AFTER the v1 [`run_prompt_optimizer_sweep_tick`] call,
/// this loop ALSO drives [`run_prompt_optimizer_sweep_tick_v2`] — the fuller propose→budget→holdout→A/B
/// pipeline — over the SAME `registry`, `judge`, and `seam` this cycle already built for v1 (never a
/// second, disconnected optimizer state). The v2 call is additive: it registers under its OWN artifact
/// id ([`default_prompt_sweep_spec_v2`]), so it can never collide with v1's draft in the shared registry.
/// `needs_hot_wiring` for v2 specifically: the shipped-default `champion` is the same `plain` seed used
/// to propose from (no live Registry-sourced production champion lookup wired yet — a further config
/// wire, the same honest shape as every other shipped-default noted above).
pub fn spawn_prompt_optimizer_tick(
    loaded: &crate::LoadedConfig,
    period: std::time::Duration,
) -> Option<tokio::task::JoinHandle<()>> {
    let (provider, _caps) = crate::build_chat_classifier_model(&loaded.runtime.models)?;
    let provider: Arc<dyn Provider> = Arc::new(provider);
    Some(tokio::spawn(async move {
        let mut iv = tokio::time::interval(period);
        let mut ix = EvalSetIndex::new();
        ix.insert(PROMPT_SWEEP_EVAL_SET, Semver::new(1, 0, 0));
        let mut registry = Registry::new(ix);
        let gold = default_prompt_sweep_gold();
        let holdout_gold = default_prompt_sweep_holdout_gold();
        let variants = default_prompt_sweep_variants();
        let seed = variants[0].clone();
        let mut minor: u16 = 0;
        loop {
            iv.tick().await;
            minor += 1;
            let judge = ConstrainedLlmJudge::new(ProviderConstrainedDecoder::new(provider.clone()));
            let seam = ProviderModelSeam::new(provider.clone());
            let family = ModelFamily::new(provider.id());
            let models: Vec<(&dyn ModelSeam, ModelFamily)> = vec![(&seam, family.clone())];
            let _outcomes = run_prompt_optimizer_sweep_tick(
                &mut registry,
                &variants,
                &gold,
                &judge,
                &models,
                &default_prompt_sweep_spec(Semver::new(1, minor, 0)),
            );
            // Outcome telemetry/logging, and landing the DRAFT onto the actually-served registry, are
            // further wires (see this function's doc) — the mechanism itself is now live and reachable
            // on a real recurring cadence, which is what this gap closure adds.

            // gap6-promptopt-completeness: the fuller pipeline, sharing the SAME registry/judge/seam
            // built above for v1 — never a second, disconnected optimizer state.
            let models_v2: Vec<(&dyn ModelSeam, ModelFamily, PromptVariant)> =
                vec![(&seam, family, seed.clone())];
            let _outcomes_v2 = run_prompt_optimizer_sweep_tick_v2(
                &mut registry,
                &seed,
                &ProposeCatalog::default(),
                &[],
                ProposeConfig::default(),
                &gold,
                &holdout_gold,
                &judge,
                CostModel::default(),
                OptBudget::default(),
                0.01,
                0.05,
                0.05,
                &models_v2,
                &default_prompt_sweep_spec_v2(Semver::new(1, minor, 0)),
            );
            // Same further wires as v1 (telemetry + landing onto the actually-served registry) apply
            // here too — see this function's doc.
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ainxt_eval::{EvalCriteria, QualityScore};
    use ainxt_prompt::registry::{EvalSetIndex, LifecycleEvent, Stage};
    use ainxt_types::Tier;

    struct TermJudge;
    impl QualityJudge for TermJudge {
        fn score(&self, _i: &str, output: &str, c: &EvalCriteria) -> QualityScore {
            let needle = c.rubric.split_whitespace().last().unwrap_or("");
            let s = if !needle.is_empty() && output.contains(needle) {
                90
            } else {
                10
            };
            QualityScore {
                score: s,
                rationale: String::new(),
            }
        }
    }

    struct SbsModel {
        id: &'static str,
    }
    impl ModelSeam for SbsModel {
        fn id(&self) -> &str {
            self.id
        }
        fn tier(&self) -> Tier {
            Tier::Medium
        }
        fn complete(&self, prompt: &str) -> String {
            let mut out = prompt.to_string();
            if prompt.contains("step by step") && prompt.contains("instant transfer") {
                out.push_str(" UPI");
            }
            out
        }
    }

    fn variants() -> Vec<PromptVariant> {
        vec![
            PromptVariant::new("plain", "{input}"),
            PromptVariant::new("guided", "Explain step by step about {input}"),
        ]
    }
    fn gold() -> Vec<EvalCase> {
        vec![EvalCase::new(
            "g",
            "instant transfer",
            "must mention UPI",
            60,
        )]
    }
    fn registry() -> Registry {
        let mut ix = EvalSetIndex::new();
        ix.insert("eval.role.l1_support", Semver::new(2, 1, 0));
        Registry::new(ix)
    }
    fn spec() -> PromptSweepSpec {
        PromptSweepSpec {
            id: "prompt.task".into(),
            layer: Layer::Task,
            next_version: Semver::new(2, 0, 0),
            owner: "platform-prompt-eng".into(),
            variables: vec![],
            eval_set: EvalSetRef::new("eval.role.l1_support", "^2.0.0").unwrap(),
        }
    }

    /// The load-bearing proof: a real, non-test caller (this tick) drives `optimize_all` +
    /// `winner_to_draft` + `register_draft` end-to-end across TWO models, landing two independent
    /// per-family DRAFTs in one live Registry — the optimizer's search engine and its Registry bridge,
    /// now genuinely reachable from a composition-root entrypoint.
    #[test]
    fn gap_ainxt_runtimed_prmt_12_sweep_tick_lands_a_draft_per_model() {
        let mut reg = registry();
        let vs = variants();
        let g = gold();
        let model_a = SbsModel { id: "sbs-a" };
        let model_b = SbsModel { id: "sbs-b" };
        let models: Vec<(&dyn ModelSeam, ModelFamily)> = vec![
            (&model_a, ModelFamily::new("sbs-a")),
            (&model_b, ModelFamily::new("sbs-b")),
        ];
        let outcomes =
            run_prompt_optimizer_sweep_tick(&mut reg, &vs, &g, &TermJudge, &models, &spec());

        assert_eq!(outcomes.len(), 2, "one outcome per input model, in order");
        for outcome in &outcomes {
            match outcome {
                PromptSweepOutcome::Drafted { version, .. } => {
                    assert_eq!(*version, Semver::new(2, 0, 0));
                }
                PromptSweepOutcome::Skipped { reason, .. } => {
                    panic!("expected a draft, got skipped: {reason}")
                }
            }
        }
        // Both families' DRAFTs are live in the SAME registry under the same id/version — a
        // per-model-family artifact, not two competing single-family drafts overwriting each other.
        assert_eq!(
            reg.stage_of("prompt.task", Semver::new(2, 0, 0)),
            Some(Stage::Draft)
        );
        // Never auto-promoted: the only forward move is the real gate (OpenPr → Eval).
        assert_eq!(
            reg.advance("prompt.task", Semver::new(2, 0, 0), LifecycleEvent::OpenPr)
                .unwrap(),
            Stage::Eval
        );
    }

    /// A model with no certified winner (empty gold) is reported `Skipped`, never silently dropped from
    /// the result — and it does not poison the other model's outcome.
    #[test]
    fn gap_ainxt_runtimed_prmt_12_no_winner_is_skipped_not_silently_dropped() {
        let mut reg = registry();
        let vs = variants();
        let model_a = SbsModel { id: "sbs-a" };
        let models: Vec<(&dyn ModelSeam, ModelFamily)> =
            vec![(&model_a, ModelFamily::new("sbs-a"))];
        let outcomes =
            run_prompt_optimizer_sweep_tick(&mut reg, &vs, &[], &TermJudge, &models, &spec());
        assert_eq!(outcomes.len(), 1);
        assert!(matches!(
            &outcomes[0],
            PromptSweepOutcome::Skipped { reason, .. } if reason.contains("no winner")
        ));
    }

    /// A registry that does not carry the referenced eval_set rejects the draft (dangling FK) — the
    /// sweep surfaces the Registry's own refusal instead of masking it as success.
    #[test]
    fn gap_ainxt_runtimed_prmt_12_registry_rejection_is_reported_as_skipped() {
        let mut empty_reg = Registry::new(EvalSetIndex::new());
        let vs = variants();
        let g = gold();
        let model_a = SbsModel { id: "sbs-a" };
        let models: Vec<(&dyn ModelSeam, ModelFamily)> =
            vec![(&model_a, ModelFamily::new("sbs-a"))];
        let outcomes =
            run_prompt_optimizer_sweep_tick(&mut empty_reg, &vs, &g, &TermJudge, &models, &spec());
        assert!(matches!(
            &outcomes[0],
            PromptSweepOutcome::Skipped { reason, .. } if reason.contains("registry rejected")
        ));
    }

    // ======================= gap6-promptopt-completeness: the fuller pipeline =======================
    //
    // These tests drive `run_prompt_optimizer_sweep_tick_v2` directly — the SAME function
    // `spawn_prompt_optimizer_tick` calls every cycle from the real composition root — proving the
    // full propose→optimize_budgeted→optimize_with_holdout→ab_promote chain discriminates for real:
    // a memorized (overfit) challenger and a legitimately-worse challenger are BOTH refused, and a
    // legitimately-better challenger is accepted and actually lands as a DRAFT.

    /// An "echo" model: it returns the rendered prompt verbatim. Combined with few-shot exemplars whose
    /// bootstrapped text literally contains the expected answer term, this is exactly how a real
    /// optimizer's propose step can accidentally memorize the visible (train) set — the exemplar
    /// answers leak into every candidate's rendered template regardless of the actual per-case input.
    struct RegurgitateModel;
    impl ModelSeam for RegurgitateModel {
        fn id(&self) -> &str {
            "regurgitate"
        }
        fn tier(&self) -> Tier {
            Tier::Medium
        }
        fn complete(&self, prompt: &str) -> String {
            prompt.to_string()
        }
    }

    /// A model that reveals an ordinary "OK" marker for the catalog-reachable "step by step" lead, but
    /// only reveals its "BONUS" reward term for a phrase ("gold-standard-marker") that lives ONLY in a
    /// hand-tuned champion — no combination of `ProposeCatalog::default()`'s leads/decomposition can
    /// ever produce it. This is what makes the A/B refusal test real: the automated search is genuinely
    /// unable to reach the champion's quality, not merely handicapped by a rigged judge.
    struct MarkerModel;
    impl ModelSeam for MarkerModel {
        fn id(&self) -> &str {
            "marker"
        }
        fn tier(&self) -> Tier {
            Tier::Medium
        }
        fn complete(&self, prompt: &str) -> String {
            let mut out = prompt.to_string();
            if prompt.contains("step by step") {
                out.push_str(" OK");
            }
            if prompt.contains("gold-standard-marker") {
                out.push_str(" BONUS");
            }
            out
        }
    }

    fn v2_registry() -> Registry {
        let mut ix = EvalSetIndex::new();
        ix.insert("eval.role.l1_support", Semver::new(2, 1, 0));
        Registry::new(ix)
    }
    fn v2_spec(id: &str, next_version: Semver) -> PromptSweepSpec {
        PromptSweepSpec {
            id: id.into(),
            layer: Layer::Task,
            next_version,
            owner: "platform-prompt-eng".into(),
            variables: vec![],
            eval_set: EvalSetRef::new("eval.role.l1_support", "^2.0.0").unwrap(),
        }
    }

    /// **Overfit guard refuses a promotion.** Few-shot exemplars whose outputs mirror the train
    /// answers ("instant transfer" → "UPI", "bulk clearing" → "NACH") are legitimately proposed by
    /// `propose`'s few-shot axis; against `RegurgitateModel`, the resulting candidate "passes" train by
    /// literally echoing the baked exemplar text, not by generalizing. `optimize_with_holdout` must
    /// catch this BEFORE `ab_promote` is even consulted: the challenger is refused as `Skipped`, never
    /// bridged, and never even reaches the A/B step.
    #[test]
    fn gap6_promptopt_v2_overfit_challenger_is_refused_before_ab_check() {
        let seed = PromptVariant::new("seed", "{input}");
        let catalog = ProposeCatalog::default();
        let exemplars = [
            Exemplar::new("instant transfer", "UPI"),
            Exemplar::new("bulk clearing", "NACH"),
        ];
        let train = vec![
            EvalCase::new("t_upi", "instant transfer", "must mention UPI", 60),
            EvalCase::new("t_nach", "bulk clearing", "must mention NACH", 60),
        ];
        let holdout = vec![
            EvalCase::new("h_rtgs", "high value", "must mention RTGS", 60),
            EvalCase::new("h_neft", "deferred net", "must mention NEFT", 60),
        ];
        // The champion is irrelevant here — the overfit guard must refuse BEFORE the A/B step runs.
        let champion = PromptVariant::new("champion", "{input}");
        let model = RegurgitateModel;
        let mut reg = v2_registry();
        let models: Vec<(&dyn ModelSeam, ModelFamily, PromptVariant)> =
            vec![(&model, ModelFamily::new("regurgitate"), champion)];

        let outcomes = run_prompt_optimizer_sweep_tick_v2(
            &mut reg,
            &seed,
            &catalog,
            &exemplars,
            ProposeConfig::default(),
            &train,
            &holdout,
            &TermJudge,
            CostModel::default(),
            OptBudget::default(),
            0.001,
            0.05,
            0.05,
            &models,
            &v2_spec("prompt.v2.overfit", Semver::new(3, 0, 0)),
        );

        assert_eq!(outcomes.len(), 1);
        match &outcomes[0] {
            PromptSweepOutcomeV2::Skipped { reason, .. } => {
                assert!(
                    reason.contains("overfit"),
                    "expected an overfit-guard refusal, got: {reason}"
                );
            }
            other => panic!("expected the overfit guard to refuse this challenger, got: {other:?}"),
        }
        // Nothing was drafted — the guard fired before any registration.
        assert_eq!(
            reg.stage_of("prompt.v2.overfit", Semver::new(3, 0, 0)),
            None
        );
    }

    /// **A/B non-inferiority refuses a deliberately-worse challenger.** The champion is hand-tuned with
    /// a marker phrase (`"gold-standard-marker"`) that `ProposeCatalog::default()` can never generate;
    /// the automated propose→budget search genuinely cannot reach the champion's quality. The
    /// challenger it finds is NOT overfit (it scores identically — badly — on train and holdout), so it
    /// clears the holdout guard, but `ab_promote` must still refuse it: it is simply worse than what is
    /// already live. No draft is created.
    #[test]
    fn gap6_promptopt_v2_worse_challenger_is_refused_by_ab_promote() {
        let seed = PromptVariant::new("seed", "{input}");
        let catalog = ProposeCatalog::default();
        let train = vec![EvalCase::new(
            "t1",
            "instant transfer",
            "must mention BONUS",
            60,
        )];
        let holdout = vec![EvalCase::new("h1", "high value", "must mention BONUS", 60)];
        let champion = PromptVariant::new(
            "champion",
            "gold-standard-marker Explain step by step about {input}",
        );
        let model = MarkerModel;
        let mut reg = v2_registry();
        let models: Vec<(&dyn ModelSeam, ModelFamily, PromptVariant)> =
            vec![(&model, ModelFamily::new("marker"), champion.clone())];

        let outcomes = run_prompt_optimizer_sweep_tick_v2(
            &mut reg,
            &seed,
            &catalog,
            &[],
            ProposeConfig::default(),
            &train,
            &holdout,
            &TermJudge,
            CostModel::default(),
            OptBudget::default(),
            0.001,
            0.05,
            0.05,
            &models,
            &v2_spec("prompt.v2.worse", Semver::new(3, 0, 0)),
        );

        assert_eq!(outcomes.len(), 1);
        match &outcomes[0] {
            PromptSweepOutcomeV2::KeptChampion { champion_id, .. } => {
                assert_eq!(champion_id, &champion.id);
            }
            other => panic!("expected ab_promote to keep the champion, got: {other:?}"),
        }
        // No draft was registered — the champion's own artifact id never even entered the registry.
        assert_eq!(reg.stage_of("prompt.v2.worse", Semver::new(3, 0, 0)), None);
    }

    /// **A/B non-inferiority accepts a genuinely-better challenger.** The champion here is the weak
    /// plain baseline; the automated propose→budget search finds the catalog's "step by step" lead,
    /// which the model rewards, clears the holdout confirmation (same reveal condition holds
    /// out-of-sample), and beats the champion beyond the margin — `ab_promote` must accept it, and the
    /// challenger must actually land as a DRAFT in the shared registry (never further than DRAFT).
    #[test]
    fn gap6_promptopt_v2_better_challenger_is_promoted_and_actually_drafted() {
        let seed = PromptVariant::new("seed", "{input}");
        let catalog = ProposeCatalog::default();
        let train = vec![EvalCase::new(
            "t1",
            "instant transfer",
            "must mention UPI",
            60,
        )];
        let holdout = vec![EvalCase::new(
            "h1",
            "instant transfer",
            "must mention UPI",
            60,
        )];
        let champion = PromptVariant::new("champion", "{input}");
        let model = SbsModel { id: "sbs-v2" };
        let mut reg = v2_registry();
        let models: Vec<(&dyn ModelSeam, ModelFamily, PromptVariant)> =
            vec![(&model, ModelFamily::new("sbs-v2"), champion)];
        let spec = v2_spec("prompt.v2.better", Semver::new(3, 0, 0));

        let outcomes = run_prompt_optimizer_sweep_tick_v2(
            &mut reg,
            &seed,
            &catalog,
            &[],
            ProposeConfig::default(),
            &train,
            &holdout,
            &TermJudge,
            CostModel::default(),
            OptBudget::default(),
            0.001,
            0.05,
            0.05,
            &models,
            &spec,
        );

        assert_eq!(outcomes.len(), 1);
        match &outcomes[0] {
            PromptSweepOutcomeV2::PromotedDraft {
                version,
                challenger_id,
                ..
            } => {
                assert_eq!(*version, Semver::new(3, 0, 0));
                assert!(
                    challenger_id.contains("cand"),
                    "challenger came from propose, got: {challenger_id}"
                );
            }
            other => panic!("expected the better challenger to be promoted, got: {other:?}"),
        }
        // The draft genuinely landed at DRAFT — never further (the optimizer never auto-promotes).
        assert_eq!(
            reg.stage_of("prompt.v2.better", Semver::new(3, 0, 0)),
            Some(Stage::Draft)
        );
        assert_eq!(
            reg.advance(
                "prompt.v2.better",
                Semver::new(3, 0, 0),
                LifecycleEvent::OpenPr
            )
            .unwrap(),
            Stage::Eval
        );
    }
}
