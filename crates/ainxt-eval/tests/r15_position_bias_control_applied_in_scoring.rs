// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-15 gap-closing integration test (eval-tester-scenarios, MEDIUM):
//! **"Structural position-bias control applied in scoring."**
//!
//! Before this round, [`ainxt_eval::judge::position_bias_flip_rate`] was a bare statistic: a caller
//! who had *already* run a Judge under both presentation orders and collected the two winner lists
//! could measure how often it flipped. Nothing in the crate ever MADE the swapped-order call itself —
//! so no comparison a real pipeline ran was ever actually bias-checked; the control was measurable, not
//! applied.
//!
//! [`ainxt_eval::judge::CalibratedPairwiseJudge::compare_governed`] closes that: every governed
//! comparison it makes calls [`ainxt_eval::judge::bias_controlled_compare`], which drives the SAME
//! head-to-head comparison under BOTH presentation orders and reconciles them itself, as part of
//! scoring — never leaving the double-order call as an opt-in the caller might skip.
//!
//! Fail-before: `CalibratedPairwiseJudge` / `PairwiseJudge` / `bias_controlled_compare` did not exist —
//! a pairwise Judge had no way to be scored at all, let alone bias-controlled. Pass-after: an
//! order-biased Judge (favors whichever candidate is presented first) is caught and REFUSED
//! (`ScoreRefusal::PositionBiasDetected`) rather than silently returning a biased pick, while a
//! genuinely content-based (order-independent) Judge's verdict passes through unchanged — proving the
//! control is applied at the moment of scoring, not as a separate audit step.

use ainxt_eval::judge::{
    bias_controlled_compare, CalibratedPairwiseJudge, CalibrationFloors, JudgeSpec, PairwiseJudge,
    PairwiseVerdict, ScoreRefusal,
};
use ainxt_eval::EvalCriteria;

fn criteria() -> EvalCriteria {
    EvalCriteria {
        rubric: "must be the better answer".into(),
        threshold: 60,
    }
}

fn spec(family: &str) -> JudgeSpec {
    JudgeSpec {
        judge_id: "pairwise-correctness-v1".into(),
        base_model: format!("{family}-model"),
        model_version: format!("{family}-2026-05"),
        family: family.into(),
        temperature: 0.0,
        seed: 11,
        rubric: "pick the better answer".into(),
        scoring_scale: "A/B/tie".into(),
        dimension: "correctness".into(),
        in_house_only: true,
    }
}

/// A Judge that always favors whichever content is presented FIRST — a pure position-bias artifact,
/// blind to actual content. This is exactly the failure mode the control must catch.
struct OrderBiasedJudge;
impl PairwiseJudge for OrderBiasedJudge {
    fn compare(&self, _input: &str, _a: &str, _b: &str, _c: &EvalCriteria) -> PairwiseVerdict {
        PairwiseVerdict::A // "whichever argument came first" — always wins
    }
}

/// A Judge that decides purely on CONTENT (whichever side contains "GOOD"), independent of which
/// argument position it's passed in — a genuinely unbiased judge.
struct ContentBasedJudge;
impl PairwiseJudge for ContentBasedJudge {
    fn compare(&self, _input: &str, x: &str, y: &str, _c: &EvalCriteria) -> PairwiseVerdict {
        let x_good = x.contains("GOOD");
        let y_good = y.contains("GOOD");
        if x_good && !y_good {
            PairwiseVerdict::A
        } else if y_good && !x_good {
            PairwiseVerdict::B
        } else {
            PairwiseVerdict::Tie
        }
    }
}

fn good_labels() -> (Vec<String>, Vec<String>) {
    let mut gold = vec!["A".to_string(); 8];
    gold.extend(vec!["B".to_string(); 8]);
    let mut judge = gold.clone();
    judge[0] = "B".into(); // one mistake — still clears the admission floors
    (gold, judge)
}

#[test]
fn r15_bias_controlled_compare_catches_an_order_biased_judge() {
    let a = "answer alpha, mediocre";
    let b = "answer beta, also mediocre";
    let v = bias_controlled_compare(&OrderBiasedJudge, "q", a, b, &criteria());
    assert!(
        v.is_biased(),
        "a judge that always favors position 1 must be caught as position-biased: {v:?}"
    );
    assert!(
        v.resolved().is_none(),
        "a biased verdict is never silently resolved"
    );
}

#[test]
fn r15_bias_controlled_compare_passes_through_a_content_based_judge() {
    let a = "this is the GOOD answer";
    let b = "this answer is fine but not great";
    let v = bias_controlled_compare(&ContentBasedJudge, "q", a, b, &criteria());
    assert_eq!(
        v.resolved(),
        Some(PairwiseVerdict::A),
        "an order-independent judge's verdict must survive the order-swap check: {v:?}"
    );
}

#[test]
fn r15_calibrated_pairwise_judge_refuses_on_detected_position_bias() {
    let (gold, labels) = good_labels();
    let cpj = CalibratedPairwiseJudge::admit(
        spec("glm"),
        Box::new(OrderBiasedJudge),
        &gold,
        &labels,
        &CalibrationFloors::default(),
    )
    .expect("the calibration math admits this judge regardless of its scoring backend's bias");

    let result = cpj.compare_governed(
        "q",
        "answer alpha",
        "answer beta",
        &criteria(),
        "claude", // producer family — distinct from the judge's "glm" family
        "gpt",
        false, // not cloud-eligible data
    );
    assert!(
        matches!(result, Err(ScoreRefusal::PositionBiasDetected { .. })),
        "the governed instrument must refuse a position-biased comparison at scoring time: {result:?}"
    );
}

#[test]
fn r15_calibrated_pairwise_judge_admits_a_consistent_comparison() {
    let (gold, labels) = good_labels();
    let cpj = CalibratedPairwiseJudge::admit(
        spec("glm"),
        Box::new(ContentBasedJudge),
        &gold,
        &labels,
        &CalibrationFloors::default(),
    )
    .expect("admitted");

    let result = cpj.compare_governed(
        "q",
        "this is the GOOD answer",
        "this answer is fine but not great",
        &criteria(),
        "claude",
        "gpt",
        false,
    );
    assert_eq!(
        result,
        Ok(PairwiseVerdict::A),
        "an order-independent comparison scores through unchanged: {result:?}"
    );
}

#[test]
fn r15_calibrated_pairwise_judge_still_enforces_self_preference_and_in_house_only() {
    let (gold, labels) = good_labels();
    let cpj = CalibratedPairwiseJudge::admit(
        spec("glm"),
        Box::new(ContentBasedJudge),
        &gold,
        &labels,
        &CalibrationFloors::default(),
    )
    .expect("admitted");

    // Self-preference: one producer shares the judge's own family ("glm").
    let self_pref = cpj.compare_governed(
        "q",
        "the GOOD answer",
        "a mediocre answer",
        &criteria(),
        "glm",
        "gpt",
        false,
    );
    assert!(
        matches!(self_pref, Err(ScoreRefusal::SelfPreference { .. })),
        "self-preference must refuse BEFORE the bias-control comparison runs: {self_pref:?}"
    );

    // in_house_only judge scoring cloud-eligible data.
    let cloud_violation = cpj.compare_governed(
        "q",
        "the GOOD answer",
        "a mediocre answer",
        &criteria(),
        "claude",
        "gpt",
        true, // data IS cloud-eligible
    );
    assert!(
        matches!(
            cloud_violation,
            Err(ScoreRefusal::InHouseOnlyViolation { .. })
        ),
        "an in-house-only judge must refuse cloud-eligible data: {cloud_violation:?}"
    );
}

/// The offline reference [`ainxt_eval::semantic::SemanticOverlapPairwiseJudge`] is, by construction, a
/// pure function of `(input, a, b, criteria)` — proving the production-shaped offline stand-in is
/// itself bias-free under the exact same control the biased test double above fails.
#[test]
fn r15_semantic_overlap_pairwise_judge_is_order_independent() {
    use ainxt_eval::semantic::SemanticOverlapPairwiseJudge;
    let judge = SemanticOverlapPairwiseJudge::default();
    let rubric = "settlement batches reconcile against the ledger before payout";
    let c = EvalCriteria {
        rubric: rubric.into(),
        threshold: 60,
    };
    let grounded = "the settlement batches reconcile against the ledger before any payout";
    let hallucinated = "the weather today is sunny with a light breeze";
    let v = bias_controlled_compare(
        &judge,
        "when does settlement run",
        grounded,
        hallucinated,
        &c,
    );
    assert_eq!(
        v.resolved(),
        Some(PairwiseVerdict::A),
        "the grounded answer wins consistently regardless of presentation order: {v:?}"
    );
}
