// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-12 (loop-teams-longhorizon gap 1): the served three-way verification is no longer
//! deterministic-only with a fabricated-green adversarial gate + a fixed-score Judge. The offline
//! [`AdversarialBreaker`] and [`RubricJudge`] genuinely inspect the produced artifact and return a
//! *computed* verdict, so a bad module (empty / stubbed / off-goal / a card-number-shaped literal)
//! blocks the three-way gate even when the deterministic gate is green — and a real artifact passes.
//!
//! Fail-before: `AdversarialVerdict::green()` + `JudgeVerdict::pass(95, …)` never looked at the
//! artifact, so the two proofs could not catch anything. Pass-after: content-driven verdicts block a
//! bad module and admit a good one. (A live cross-model LLM judge / attack loop remains the
//! `needs_hot_wiring` deployment substitution behind the same shape.)

use ainxt_planner::assurance::{AdversarialBreaker, ModuleArtifact, RubricJudge};
use ainxt_planner::program::EditRung;
use ainxt_planner::verify::{three_way_gate, DeterministicVerdict, GateOutcome};

fn good() -> ModuleArtifact {
    ModuleArtifact::new(
        "validate the settlement amount and reject negative values",
        "fn validate(amount: i64) -> Result<(), Error> { if amount < 0 { return Err(Error::Negative); } Ok(()) }\n#[test] fn rejects_negative_and_zero_boundary() { assert!(validate(-1).is_err()); assert!(validate(0).is_ok()); }",
        "qwen-coder",
    )
    .with_edit_rung(EditRung::Ast)
    .claiming_input_handling()
    .claiming_tests()
}

#[test]
fn r12_assurance_nonsynthetic_proofs() {
    let breaker = AdversarialBreaker::new();
    let judge = RubricJudge::default();

    // ---- a real, substantive artifact passes both content proofs and the whole gate --------------
    let g = good();
    let adv = breaker.attack(&g);
    assert!(
        adv.counterexamples.is_empty(),
        "unexpected {:?}",
        adv.counterexamples
    );
    let jv = judge.judge(&g);
    assert!(jv.score >= jv.threshold);
    assert_ne!(jv.producer_model, jv.judge_model, "cross-model (§10)");
    assert_eq!(
        three_way_gate(&DeterministicVerdict::green(), &adv, &jv),
        GateOutcome::Complete
    );

    // ---- an empty artifact is blocked by the breaker (not a fabricated green) ---------------------
    let empty = ModuleArtifact::new("do the thing", "   ", "qwen-coder");
    let adv = breaker.attack(&empty);
    assert!(adv
        .counterexamples
        .iter()
        .any(|c| c.contains("empty-output")));
    assert!(matches!(
        three_way_gate(&DeterministicVerdict::green(), &adv, &judge.judge(&empty)),
        GateOutcome::Blocked { .. }
    ));

    // ---- a stub artifact scores below the judge threshold AND trips the breaker -------------------
    let stub = ModuleArtifact::new(
        "validate the settlement amount and reject negatives",
        "fn validate() { todo!() }",
        "qwen-coder",
    );
    let jv = judge.judge(&stub);
    assert!(jv.score < jv.threshold, "stub scored {}", jv.score);
    let adv = breaker.attack(&stub);
    assert!(adv
        .counterexamples
        .iter()
        .any(|c| c.contains("unfinished-stub")));
    assert!(matches!(
        three_way_gate(&DeterministicVerdict::green(), &adv, &jv),
        GateOutcome::Blocked { .. }
    ));

    // ---- a card-number-shaped literal baked into code is a hard adversarial counterexample --------
    let pan = ModuleArtifact::new(
        "store the token",
        "let card = \"4111 1111 1111 1111\"; save(card);",
        "qwen-coder",
    );
    let adv = breaker.attack(&pan);
    assert!(adv.counterexamples.iter().any(|c| c.contains("pci-leak")));
    assert!(judge.judge(&pan).score < judge.judge(&good()).score);

    // ---- an off-goal artifact scores lower on goal-relevance than an on-goal one -----------------
    let off_goal = ModuleArtifact::new(
        "validate the settlement amount and reject negative values",
        "fn unrelated_helper() -> u32 { let x = 1 + 2 + 3 + 4; x * 10 }",
        "qwen-coder",
    );
    assert!(
        judge.judge(&off_goal).score < judge.judge(&good()).score,
        "off-goal must score lower on goal-relevance"
    );
}
