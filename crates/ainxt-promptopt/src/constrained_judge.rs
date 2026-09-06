// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! **Gap closure — constrained-decoding unwired (`ainxt_prompt::constrained::StructuredOutputEngine`).**
//!
//! `StructuredOutputEngine::generate` (`PROMPT_ENGINEERING.md` §4, PE3) guarantees a schema-valid
//! object from ANY model family — including self-hosted models with no native JSON reliability — via
//! grammar attachment (native decoders) or a bounded prompted-JSON repair loop (everyone else). Its own
//! module doc names **eval-judge verdicts** as one of the four generalized call sites
//! (`ainxt_prompt::constrained`'s `StructuredOutputKind::JudgeVerdict`), but before this module nothing
//! in the workspace actually called `generate` outside its own unit tests.
//!
//! [`ConstrainedLlmJudge`] is that real caller: a [`QualityJudge`] backend that decodes the judge
//! model's raw reply through the engine instead of hoping the model free-formats a parseable verdict.
//! It plugs directly into this crate's real API — [`crate::optimize`], [`crate::optimize_all`],
//! [`crate::ab_promote`], [`crate::optimize_with_holdout`] all take `judge: &dyn QualityJudge` — so the
//! optimizer's per-model-family judging (`PROMPT_ENGINEERING.md` §5.4: "per-model, always", the exact
//! scenario where a self-hosted family needs the repair-loop backstop a frontier model rarely does) goes
//! through the engine for real, not through a bespoke ad hoc parse.
//!
//! `ainxt-eval`'s own `LiveProviderJudge` (`ainxt-eval/src/live.rs`) cannot depend on
//! `ainxt_prompt::constrained` directly — `ainxt-prompt` already depends on `ainxt-eval` (its Registry's
//! eval-delta gate reuses `evaluate_gate`), so the reverse edge would be a cycle. `ainxt-promptopt`
//! already legally depends on BOTH crates, which is why the constrained-decoding-backed judge lives
//! here rather than in `ainxt-eval` itself.
//!
//! Fail-closed, exactly as `StructuredOutputEngine` and `LiveProviderJudge` both are: a decode failure
//! never fabricates a passing score — it returns `score: 0` with the structured error recorded in the
//! rationale, so a judge outage is visible in the eval report, never silently treated as "the candidate
//! failed the rubric."

use ainxt_eval::{EvalCriteria, QualityJudge, QualityScore};
use ainxt_prompt::constrained::{
    ConstrainedDecoder, NeverCancel, StructuredOutputEngine, StructuredOutputKind,
};

/// A [`QualityJudge`] backend that decodes the judge model's verdict via
/// [`StructuredOutputEngine::generate`] against [`StructuredOutputKind::JudgeVerdict`]'s schema
/// (`{score, passed, rationale}`) instead of a bespoke text scan. `decoder` is the injected serving
/// seam (§4) — production wiring passes a decoder whose `grammar_native()` reflects the actual serving
/// stack (`true` for vLLM/Outlines/lm-format-enforcer-backed deployments, `false` for a plain
/// prompted-completion endpoint); tests inject fakes exactly as `ainxt_prompt::constrained`'s own tests
/// do.
pub struct ConstrainedLlmJudge<D: ConstrainedDecoder> {
    decoder: D,
    engine: StructuredOutputEngine,
}

impl<D: ConstrainedDecoder> ConstrainedLlmJudge<D> {
    /// Default bounded-repair budget (3 repairs, mirroring `StructuredOutputEngine::default()`).
    pub fn new(decoder: D) -> Self {
        ConstrainedLlmJudge {
            decoder,
            engine: StructuredOutputEngine::default(),
        }
    }

    /// Explicit repair budget — a hard cap so a pathological model cannot spin unbounded spend even
    /// inside an optimizer sweep that already runs many candidates × many gold cases.
    pub fn with_max_repairs(decoder: D, max_repairs: usize) -> Self {
        ConstrainedLlmJudge {
            decoder,
            engine: StructuredOutputEngine::new(max_repairs),
        }
    }

    /// The exact base prompt sent before schema/repair instructions are layered on by the engine
    /// (`prompted_json`/`repair_prompt` inside `ainxt_prompt::constrained` do that layering). Kept as a
    /// free method so the wire text is independently inspectable/testable.
    fn base_prompt(input: &str, output: &str, criteria: &EvalCriteria) -> String {
        format!(
            "You are a calibrated evaluation judge. Score the ANSWER against the RUBRIC on a 0-100 \
             integer scale (0 = fails the rubric entirely, 100 = fully satisfies it). `passed` must be \
             true iff score >= {}.\n\nRUBRIC: {}\n\nQUESTION: {input}\n\nANSWER: {output}\n",
            criteria.threshold, criteria.rubric
        )
    }
}

impl<D: ConstrainedDecoder> QualityJudge for ConstrainedLlmJudge<D> {
    fn score(&self, input: &str, output: &str, criteria: &EvalCriteria) -> QualityScore {
        let schema = StructuredOutputKind::JudgeVerdict.schema();
        let prompt = Self::base_prompt(input, output, criteria);
        match self
            .engine
            .generate(&self.decoder, &schema, &prompt, &NeverCancel)
        {
            Ok(structured) => {
                // The engine already validated the object against the JudgeVerdict schema (score:
                // Integer, passed: Boolean, rationale: String, all required) — these reads cannot
                // fail, but `unwrap_or` defaults keep this path panic-free even under a future schema
                // change.
                let score = structured
                    .value
                    .get("score")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0)
                    .clamp(0, 100) as u8;
                let passed = structured
                    .value
                    .get("passed")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let rationale = structured
                    .value
                    .get("rationale")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                // Never silently trust the model's OWN pass/fail claim over the actual threshold
                // comparison (the same "don't trust the model's claim" discipline `constrained.rs`
                // applies to grammar-native decoders) — surface the disagreement instead of masking it.
                let threshold_says_pass = score >= criteria.threshold;
                if passed != threshold_says_pass {
                    QualityScore {
                        score,
                        rationale: format!(
                            "{rationale} [judge's passed={passed} disagrees with score {score} vs \
                             threshold {}; scoring stands on the numeric score]",
                            criteria.threshold
                        ),
                    }
                } else {
                    QualityScore { score, rationale }
                }
            }
            Err(e) => QualityScore {
                score: 0,
                rationale: format!(
                    "constrained-decoding judge failed — failing closed, never a fabricated pass: {e}"
                ),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ainxt_prompt::constrained::DecodeError;

    fn criteria() -> EvalCriteria {
        EvalCriteria {
            rubric: "must mention UPI".into(),
            threshold: 60,
        }
    }

    /// A grammar-native decoder: "enforces" the grammar, so it always returns a valid object on the
    /// first attempt.
    struct NativeDecoder(&'static str);
    impl ConstrainedDecoder for NativeDecoder {
        fn grammar_native(&self) -> bool {
            true
        }
        fn decode(&self, _p: &str, grammar: Option<&str>) -> Result<String, DecodeError> {
            assert!(grammar.is_some(), "native decoder must receive the grammar");
            Ok(self.0.to_string())
        }
    }

    /// A weak self-hosted-style model: emits prose on the first attempt (no repair-error context yet),
    /// then a valid `JudgeVerdict` object once the repair prompt carries the exact validation error —
    /// the same shape as `ainxt_prompt::constrained`'s own `WeakModel` test fixture, proving the SAME
    /// bounded-repair mechanism now backs a real judge, not just the module's internal tests.
    struct WeakJudgeModel;
    impl ConstrainedDecoder for WeakJudgeModel {
        fn grammar_native(&self) -> bool {
            false
        }
        fn decode(&self, prompt: &str, _g: Option<&str>) -> Result<String, DecodeError> {
            if prompt.contains("was invalid") {
                Ok(r#"{"score":85,"passed":true,"rationale":"mentions UPI clearly"}"#.to_string())
            } else {
                Ok("Sure! score=85, looks great".to_string())
            }
        }
    }

    struct HopelessJudgeModel;
    impl ConstrainedDecoder for HopelessJudgeModel {
        fn grammar_native(&self) -> bool {
            false
        }
        fn decode(&self, _p: &str, _g: Option<&str>) -> Result<String, DecodeError> {
            Ok("I refuse to output JSON.".to_string())
        }
    }

    #[test]
    fn gap_ainxt_promptopt_prmt_11_native_decoder_path_is_used() {
        let judge = ConstrainedLlmJudge::new(NativeDecoder(
            r#"{"score":90,"passed":true,"rationale":"solid answer"}"#,
        ));
        let out = judge.score("q", "a mentions UPI", &criteria());
        assert_eq!(out.score, 90);
        assert_eq!(out.rationale, "solid answer");
    }

    /// The load-bearing proof this gap closure exists for: a WEAK model that cannot format valid JSON
    /// on the first try still yields a schema-valid, correctly-scored verdict via the SAME bounded
    /// repair loop `StructuredOutputEngine` was built to provide — through the real `QualityJudge` seam
    /// this crate's `optimize`/`optimize_all`/`ab_promote` consume.
    #[test]
    fn gap_ainxt_promptopt_prmt_11_weak_model_verdict_repairs_through_the_engine() {
        let judge = ConstrainedLlmJudge::new(WeakJudgeModel);
        let out = judge.score("q", "a mentions UPI", &criteria());
        assert_eq!(out.score, 85);
        assert_eq!(out.rationale, "mentions UPI clearly");
    }

    #[test]
    fn gap_ainxt_promptopt_prmt_11_unrepairable_model_fails_closed_never_fabricates_a_pass() {
        let judge = ConstrainedLlmJudge::with_max_repairs(HopelessJudgeModel, 2);
        let out = judge.score("q", "a", &criteria());
        assert_eq!(
            out.score, 0,
            "a judge that never emits valid JSON must fail closed at 0"
        );
        assert!(out.rationale.contains("failing closed"));
    }

    #[test]
    fn gap_ainxt_promptopt_prmt_11_disagreeing_passed_claim_is_surfaced_not_masked() {
        // The model claims passed=true but its own score is below threshold — never silently trust the
        // claim; the discrepancy must be visible in the rationale.
        let judge = ConstrainedLlmJudge::new(NativeDecoder(
            r#"{"score":10,"passed":true,"rationale":"barely mentions it"}"#,
        ));
        let out = judge.score("q", "a", &criteria());
        assert_eq!(out.score, 10);
        assert!(out.rationale.contains("disagrees"));
    }

    /// End-to-end: the constrained-decoding judge plugs into this crate's real optimizer entrypoint
    /// unchanged — proving `StructuredOutputEngine::generate` now has a real caller reachable from
    /// `crate::optimize`, not merely from this module's own unit tests.
    #[test]
    fn gap_ainxt_promptopt_prmt_11_plugs_into_optimize_unchanged() {
        use crate::{optimize, ModelSeam, PromptVariant};
        use ainxt_types::Tier;

        struct EchoModel;
        impl ModelSeam for EchoModel {
            fn id(&self) -> &str {
                "self-hosted-weak"
            }
            fn tier(&self) -> Tier {
                Tier::Medium
            }
            fn complete(&self, prompt: &str) -> String {
                format!("answer for: {prompt}")
            }
        }

        let judge = ConstrainedLlmJudge::new(WeakJudgeModel);
        let variants = vec![PromptVariant::new("v1", "{input}")];
        let gold = vec![ainxt_eval::EvalCase::new("g1", "q", "must mention UPI", 60)];
        let opt = optimize(&variants, &gold, &judge, &EchoModel);
        assert_eq!(opt.winner.as_deref(), Some("v1"));
        assert_eq!(opt.ranked[0].report.results[0].score, 85);
    }
}
