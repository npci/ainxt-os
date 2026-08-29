// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R8 — the composed release gate, dogfooded against the REAL runtime as system-under-eval.
//!
//! Before this round the composed gate ([`ainxt_eval::pipeline::run_release_gate`]) and its enforcer
//! seam ([`ainxt_eval::dogfood::run_merge_check`]) were only ever exercised against in-crate fakes:
//! nothing ran the *actual assembled runtime* through the gate, so the keystone claim ("a change can't
//! ship if it made quality/safety worse") was never proven end-to-end on the real engine.
//!
//! [`ainxt_conformance::dogfood::dogfood_merge_check`] closes that: it runs the conformance corpus
//! through the real [`ainxt_runtime::Engine`] (compliance output gate + RBAC + provider-failover + tool
//! ledger + injection gate) and scores the outputs with the composed statistical gate. This test
//! proves the gate genuinely bites against the real runtime — a null change SHIPS, and a runtime whose
//! output compliance gate leaks is BLOCKED (fail-before/pass-after: the negative control fails RED
//! against the leaky runtime while the positive control ships).

use ainxt_conformance::dogfood::{
    dogfood_merge_check, dogfood_merge_check_with_regression, Regression, DOGFOOD_CORPUS_SIZE,
};
use ainxt_eval::ci::{EXIT_BLOCK, EXIT_SHIP};

/// The dogfood entrypoint runs the real runtime through the composed gate and the intact runtime
/// SHIPS (mergeable, exit 0). This is the positive control: the same assembled engine the conformance
/// matrix and shipped daemon use produces safe (redacted) outputs, the in-house Judge scores them
/// safe, and the composed statistical gate passes.
#[test]
fn dogfood_ships_the_intact_runtime() {
    let check = dogfood_merge_check();
    assert!(
        check.is_mergeable() && !check.merge_blocked(),
        "an intact runtime (real Engine, StrongRedactor output gate) must SHIP: {}",
        check.summary()
    );
    assert_eq!(check.exit_code(), EXIT_SHIP, "ship maps to exit 0");

    // The composed gate actually RAN over the real corpus (not a fail-closed short-circuit).
    let outcome = check
        .outcome()
        .expect("a shipped merge-check must carry the full gate outcome");
    assert!(outcome.report.is_ship());
    assert_eq!(
        outcome.report.scored, DOGFOOD_CORPUS_SIZE,
        "every corpus case must have been scored through the real runtime"
    );
    assert!(
        outcome.report.statistical.is_some(),
        "the statistical gate must have run"
    );
    // A reproduce-from-SHA verdict was minted for the run.
    assert_eq!(outcome.report.verdict.outcome, "pass");
    assert_eq!(
        outcome.report.verdict.candidate_sha,
        "dogfood-candidate-sha"
    );
}

/// NEGATIVE CONTROL (the fail-before): a runtime whose output compliance gate no longer redacts leaks
/// a PAN on every case. Run through the SAME composed gate, the in-house Judge scores every candidate
/// output 0 while the intact baseline scores 100, so the paired statistical gate detects a genuine,
/// significant regression and BLOCKS the merge. This proves the dogfood gate is not vacuously green —
/// it bites against the real engine.
#[test]
fn dogfood_blocks_a_runtime_whose_output_gate_leaks() {
    let check = dogfood_merge_check_with_regression(Regression::LeakyOutputGate);
    assert!(
        check.merge_blocked() && !check.is_mergeable(),
        "a runtime that leaks PANs must be BLOCKED by the composed gate: {}",
        check.summary()
    );
    assert_eq!(
        check.exit_code(),
        EXIT_BLOCK,
        "a real statistical regression maps to exit 1 (block)"
    );

    let outcome = check
        .outcome()
        .expect("a blocked (not fail-closed) merge-check carries the gate outcome");
    // The block is specifically a statistical regression the paired gate found on the real outputs.
    match &outcome.report.decision {
        ainxt_eval::pipeline::ReleaseDecision::Block(reasons) => assert!(
            reasons.iter().any(|r| r.contains("statistical regression")),
            "the block must be a statistical regression, got: {reasons:?}"
        ),
        other => panic!("a leaky runtime must Block, got {other:?}"),
    }
    assert_eq!(outcome.report.verdict.outcome, "block");
}

/// The two runs are driven by the identical corpus + gate; the ONLY difference is the injected
/// regression. So the ship/block split is attributable to the runtime's behavior, not to two
/// different eval setups — the dogfood is a controlled A/B against the real engine.
#[test]
fn ship_vs_block_differ_only_by_the_injected_regression() {
    let intact = dogfood_merge_check();
    let leaky = dogfood_merge_check_with_regression(Regression::LeakyOutputGate);
    assert!(intact.is_mergeable(), "intact must ship");
    assert!(leaky.merge_blocked(), "leaky must block");
    // Same corpus size scored on the intact ship path.
    assert_eq!(intact.outcome().unwrap().report.scored, DOGFOOD_CORPUS_SIZE);
}
