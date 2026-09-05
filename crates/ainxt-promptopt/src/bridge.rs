// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! The **optimizer → Registry bridge** (`PROMPT_ENGINEERING.md` §5.5). The optimizer's best candidate
//! does not ship — it becomes a new **DRAFT** artifact version in the Prompt [`Registry`], entering the
//! normal DRAFT → EVAL → REVIEW → CANARY → PRODUCTION pipeline. **The optimizer never auto-promotes.**
//!
//! This closes the gap that `ainxt-promptopt` produced a [`ModelOptimization`]/[`HoldoutOutcome`] with
//! no path into the Registry: [`winner_to_draft`] turns the winning [`PromptVariant`] into a
//! per-model-family [`LayerArtifact`] and [`register_draft`] lands it at [`Stage::Draft`] — and only
//! Draft. A promotion still requires the full gated lifecycle (eval delta + SoD + canary), so a bug or
//! an overfit candidate cannot reach production by the optimizer's own hand.
//!
//! The overfit guard is honored at the boundary: [`holdout_winner_to_draft`] **refuses** to bridge a
//! candidate the holdout flagged overfit (gap AQ / PE10) — a memorized winner never even becomes a
//! DRAFT for a reviewer to rubber-stamp.

use crate::{HoldoutOutcome, ModelOptimization, PromptVariant};
use ainxt_prompt::registry::{
    EvalSetRef, Layer, LayerArtifact, ModelFamily, Registry, RegistryError, Semver, Stage,
};
use std::collections::BTreeMap;

/// The non-body metadata needed to mint a DRAFT artifact from an optimizer winner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DraftSpec {
    /// The layer artifact id to author a new version of (typically an L3 task layer).
    pub id: String,
    pub layer: Layer,
    /// The new DRAFT version (the caller bumps from the current PRODUCTION version).
    pub version: Semver,
    /// The CODEOWNERS group that owns the artifact.
    pub owner: String,
    /// Recorded author — e.g. `"prompt-optimizer"` (SoD: an optimizer author can never self-approve).
    pub author: String,
    pub variables: Vec<String>,
    pub eval_set: EvalSetRef,
}

/// Errors bridging an optimizer result into the Registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeError {
    /// The optimization certified no winner (no variants / empty gold set) — nothing to draft.
    NoWinner,
    /// The winning id is not among the supplied variants (caller passed a mismatched set).
    WinnerNotFound { id: String },
    /// The holdout flagged the winner as overfit — refuse to draft it (gap AQ / PE10).
    Overfit { id: String },
    /// The Registry rejected the DRAFT (invalid artifact / dangling eval_set FK / duplicate version).
    Registry(RegistryError),
}

impl std::fmt::Display for BridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BridgeError::NoWinner => {
                write!(f, "optimization certified no winner — nothing to draft")
            }
            BridgeError::WinnerNotFound { id } => {
                write!(f, "winner '{id}' is not among the supplied variants")
            }
            BridgeError::Overfit { id } => write!(
                f,
                "winner '{id}' was flagged overfit on the holdout — refusing to draft it"
            ),
            BridgeError::Registry(e) => write!(f, "registry rejected the draft: {e}"),
        }
    }
}
impl std::error::Error for BridgeError {}

/// Turn an optimizer winner into a **per-model-family** DRAFT [`LayerArtifact`]. The winning variant's
/// template becomes the compiled body for `family`; the artifact declares exactly that one family (a
/// per-model DRAFT, §4/§5.4 — other families are optimized + drafted separately).
pub fn winner_to_draft(
    spec: &DraftSpec,
    family: &ModelFamily,
    variants: &[PromptVariant],
    opt: &ModelOptimization,
) -> Result<LayerArtifact, BridgeError> {
    let winner_id = opt.winner.as_ref().ok_or(BridgeError::NoWinner)?;
    let winner = variants
        .iter()
        .find(|v| &v.id == winner_id)
        .ok_or_else(|| BridgeError::WinnerNotFound {
            id: winner_id.clone(),
        })?;

    let mut body_map = BTreeMap::new();
    body_map.insert(family.clone(), winner.template.clone());

    let art = LayerArtifact {
        id: spec.id.clone(),
        layer: spec.layer,
        version: spec.version,
        owner: spec.owner.clone(),
        author: spec.author.clone(),
        variables: spec.variables.clone(),
        eval_set: spec.eval_set.clone(),
        model_variants: vec![family.clone()],
        variants: body_map,
    };
    art.validate().map_err(BridgeError::Registry)?;
    Ok(art)
}

/// Bridge a holdout-confirmed winner into a DRAFT, **refusing an overfit candidate** (gap AQ / PE10).
pub fn holdout_winner_to_draft(
    spec: &DraftSpec,
    family: &ModelFamily,
    variants: &[PromptVariant],
    outcome: &HoldoutOutcome,
) -> Result<LayerArtifact, BridgeError> {
    let winner_id = outcome.winner.as_ref().ok_or(BridgeError::NoWinner)?;
    if outcome.overfit {
        return Err(BridgeError::Overfit {
            id: winner_id.clone(),
        });
    }
    winner_to_draft(spec, family, variants, &outcome.train)
}

/// Register a DRAFT artifact into the Registry. Lands at [`Stage::Draft`] and returns it — this
/// function performs **no** lifecycle advancement: promotion is the gated pipeline's job, never the
/// optimizer's.
pub fn register_draft(
    registry: &mut Registry,
    artifact: LayerArtifact,
) -> Result<Stage, BridgeError> {
    let id = artifact.id.clone();
    let version = artifact.version;
    registry.register(artifact).map_err(BridgeError::Registry)?;
    Ok(registry
        .stage_of(&id, version)
        .expect("just-registered artifact must have a stage"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{optimize, optimize_with_holdout, ModelSeam};
    use ainxt_eval::{EvalCase, EvalCriteria, QualityJudge, QualityScore};
    use ainxt_prompt::registry::{EvalSetIndex, LifecycleEvent};
    use ainxt_types::Tier;

    // A model that only "knows" the answer when the prompt shows work step by step.
    struct SbsModel;
    impl ModelSeam for SbsModel {
        fn id(&self) -> &str {
            "sbs"
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

    fn fam() -> ModelFamily {
        ModelFamily::new("sbs")
    }
    fn spec() -> DraftSpec {
        DraftSpec {
            id: "prompt.task".into(),
            layer: Layer::Task,
            version: Semver::new(2, 0, 0),
            owner: "platform-prompt-eng".into(),
            author: "prompt-optimizer".into(),
            variables: vec![],
            eval_set: EvalSetRef::new("eval.role.l1_support", "^2.0.0").unwrap(),
        }
    }
    fn registry() -> Registry {
        let mut ix = EvalSetIndex::new();
        ix.insert("eval.role.l1_support", Semver::new(2, 1, 0));
        Registry::new(ix)
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

    // --- PRMT-07: winner lands as DRAFT and never auto-promotes ------------------------------

    #[test]
    fn gap_ainxt_promptopt_prmt_07_optimizer_winner_lands_as_draft_only() {
        let vs = variants();
        let opt = optimize(&vs, &gold(), &TermJudge, &SbsModel);
        assert_eq!(opt.winner.as_deref(), Some("guided"));

        let draft = winner_to_draft(&spec(), &fam(), &vs, &opt).unwrap();
        // The DRAFT body is the winning template compiled for this family.
        assert!(draft.variant(&fam()).unwrap().contains("step by step"));

        let mut reg = registry();
        let stage = register_draft(&mut reg, draft).unwrap();
        // It enters the pipeline at DRAFT — NOT production. The optimizer never auto-promotes.
        assert_eq!(stage, Stage::Draft);
        assert_eq!(
            reg.stage_of("prompt.task", Semver::new(2, 0, 0)),
            Some(Stage::Draft)
        );

        // Proof it is not live: it can only advance to EVAL (a real gate) — never straight to prod.
        assert_eq!(
            reg.advance("prompt.task", Semver::new(2, 0, 0), LifecycleEvent::OpenPr)
                .unwrap(),
            ainxt_prompt::registry::Stage::Eval
        );
    }

    #[test]
    fn gap_ainxt_promptopt_prmt_07_no_winner_cannot_be_drafted() {
        // Empty gold set → no certified winner → nothing to draft.
        let vs = variants();
        let opt = optimize(&vs, &[], &TermJudge, &SbsModel);
        assert!(matches!(
            winner_to_draft(&spec(), &fam(), &vs, &opt),
            Err(BridgeError::NoWinner)
        ));
    }

    #[test]
    fn gap_ainxt_promptopt_prmt_07_overfit_winner_is_refused_at_the_bridge() {
        // A variant that BAKES the train answer and collapses on the holdout is flagged overfit and
        // must never become a DRAFT.
        let over = PromptVariant::new("overfit", "The answer is UPI regardless of {input}");
        let train = vec![EvalCase::new(
            "t",
            "instant transfer",
            "must mention UPI",
            60,
        )];
        let holdout = vec![EvalCase::new("h", "high value", "must mention RTGS", 60)];
        let outcome = optimize_with_holdout(
            std::slice::from_ref(&over),
            &train,
            &holdout,
            &TermJudge,
            &SbsModel,
            0.05,
        );
        assert!(outcome.overfit, "sanity: this variant is overfit");
        let vs = vec![over];
        assert!(matches!(
            holdout_winner_to_draft(&spec(), &fam(), &vs, &outcome),
            Err(BridgeError::Overfit { .. })
        ));
    }

    #[test]
    fn gap_ainxt_promptopt_prmt_07_dangling_eval_set_fk_is_rejected_by_the_registry() {
        let vs = variants();
        let opt = optimize(&vs, &gold(), &TermJudge, &SbsModel);
        let draft = winner_to_draft(&spec(), &fam(), &vs, &opt).unwrap();
        // A registry whose eval index does NOT contain the referenced set → FK rejection.
        let mut empty_reg = Registry::new(EvalSetIndex::new());
        assert!(matches!(
            register_draft(&mut empty_reg, draft),
            Err(BridgeError::Registry(RegistryError::DanglingEvalSet { .. }))
        ));
    }
}
