// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-12 gap-closing integration test (eval-tester-scenarios, HIGH):
//! **"Calibrated/pinned LLM Judge (the semantic instrument itself)."**
//!
//! Before this round the crate had the calibration MATH (`judge::admit_judge`, κ/balanced-accuracy
//! floors, bias controls) and an offline scoring backend (`semantic::SemanticOverlapJudge`) as
//! SEPARATE pieces — nothing bound a pinned+admitted `JudgeSpec` to the scoring seam into "the Judge"
//! the design means: an instrument that (a) cannot exist un-calibrated and (b) enforces its own
//! self-preference + in-house-only governance at *scoring* time.
//!
//! `judge::CalibratedJudge` is that instrument. This test drives it end-to-end over the offline
//! `SemanticOverlapJudge` backend (the exact slot the pinned LLM judge fills in production — a live
//! model call, infra-gated). Fail-before: `CalibratedJudge` did not exist. Pass-after: an
//! un-calibrated candidate cannot be built, an admitted one refuses self-preference + cloud-routing
//! violations, and it scores grounded > hallucinated behind the `QualityJudge` seam.

use ainxt_eval::judge::{
    CalibratedJudge, CalibrationFloors, JudgeAdmission, JudgeSpec, ScoreRefusal,
};
use ainxt_eval::semantic::SemanticOverlapJudge;
use ainxt_eval::{run_eval, EvalCase, EvalCriteria, QualityJudge};

fn spec(family: &str, in_house_only: bool) -> JudgeSpec {
    JudgeSpec {
        judge_id: "groundedness-v1".into(),
        base_model: format!("{family}-4"),
        model_version: format!("{family}-4-2026-05"),
        family: family.into(),
        temperature: 0.0,
        seed: 42,
        rubric: "Score 0-100 how supported the answer is by the sources.".into(),
        scoring_scale: "0-100".into(),
        dimension: "groundedness".into(),
        in_house_only,
    }
}

/// A near-perfect, balanced calibration slice (8 good / 8 bad, one mistake) → clears both floors.
fn admitted_labels() -> (Vec<String>, Vec<String>) {
    let mut gold = vec!["good".to_string(); 8];
    gold.extend(vec!["bad".to_string(); 8]);
    let mut judge = gold.clone();
    judge[0] = "bad".into(); // a single miss — still high κ + balanced accuracy
    (gold, judge)
}

#[test]
fn r12_calibrated_judge_instrument() {
    let floors = CalibrationFloors::default();

    // --- 1. An un-calibrated (class-blind) candidate CANNOT become an instrument. -----------------
    let mut gold = vec!["good".to_string(); 8];
    gold.extend(vec!["bad".to_string(); 8]);
    let class_blind = vec!["good".to_string(); 16];
    let rejected = CalibratedJudge::admit(
        spec("glm", true),
        Box::new(SemanticOverlapJudge::new()),
        &gold,
        &class_blind,
        &floors,
    );
    assert!(
        matches!(rejected, Err(JudgeAdmission::Rejected { .. })),
        "a candidate that fails the balanced-accuracy floor must not build an instrument"
    );

    // --- 2. A calibrated candidate is admitted and carries a pinned, reproducible version. --------
    let (gold, judge_labels) = admitted_labels();
    let inst = CalibratedJudge::admit(
        spec("glm", true),
        Box::new(SemanticOverlapJudge::new()),
        &gold,
        &judge_labels,
        &floors,
    )
    .expect("a near-perfect balanced judge is admitted");
    assert!(inst.admission().is_admitted());
    assert_eq!(inst.version().len(), 64, "pinned SHA-256 version");
    assert_eq!(
        inst.version(),
        spec("glm", true).version(),
        "version == spec content SHA"
    );

    let crit = EvalCriteria {
        rubric: "settlement batches reconcile against the ledger before payout".into(),
        threshold: 60,
    };

    // --- 3. Governance at SCORING time: self-preference is refused (not silently mis-scored). ------
    let self_pref = inst.score_governed(
        "q",
        "the settlement batches reconcile against the ledger before payout",
        &crit,
        "glm", // producer is the SAME family as the judge
        false,
    );
    assert!(
        matches!(self_pref, Err(ScoreRefusal::SelfPreference { .. })),
        "a judge must never score its own family's output: {self_pref:?}"
    );

    // --- 4. In-house-only judge refuses cloud-eligible data (regulated routing, ADR-012). ---------
    let leak = inst.score_governed(
        "q",
        "the settlement batches reconcile against the ledger before payout",
        &crit,
        "qwen",
        true, // data may leave the in-house boundary
    );
    assert!(
        matches!(leak, Err(ScoreRefusal::InHouseOnlyViolation { .. })),
        "an in-house-only judge must refuse cloud-eligible data: {leak:?}"
    );

    // --- 5. A clean, in-boundary, cross-family score DELEGATES to the calibrated backend and -------
    //         separates a grounded answer from a hallucinated one, stamped with the pinned version.
    let grounded = inst
        .score_governed(
            "q",
            "the settlement batches reconcile against the ledger before payout",
            &crit,
            "qwen",
            false,
        )
        .expect("clean, in-boundary, cross-family → scores");
    let hallucinated = inst
        .score_governed(
            "q",
            "the weather in mumbai is pleasant",
            &crit,
            "qwen",
            false,
        )
        .expect("scores");
    assert!(
        grounded.score >= crit.threshold,
        "grounded clears threshold: {}",
        grounded.score
    );
    assert!(
        hallucinated.score < crit.threshold,
        "off-topic falls below: {}",
        hallucinated.score
    );
    assert!(
        grounded.rationale.contains(&inst.version()),
        "every verdict is stamped with the pinned judge version"
    );

    // --- 6. The instrument plugs into run_eval behind the QualityJudge seam unchanged. ------------
    let judge: Box<dyn QualityJudge> = Box::new(
        CalibratedJudge::admit(
            spec("glm", true),
            Box::new(SemanticOverlapJudge::new()),
            &gold,
            &judge_labels,
            &floors,
        )
        .unwrap(),
    );
    let cases = vec![EvalCase::new(
        "c1",
        "settlement",
        "settlement batches reconcile against the ledger before payout",
        60,
    )];
    struct Sys;
    impl ainxt_eval::EvalSystem for Sys {
        fn respond(&self, _input: &str) -> String {
            "settlement batches reconcile against the ledger before payout".into()
        }
    }
    let report = run_eval(&cases, &Sys, judge.as_ref());
    assert_eq!(report.n, 1);
    assert!(
        report.results[0].rationale.contains("[judge "),
        "seam stamps the version"
    );
}
