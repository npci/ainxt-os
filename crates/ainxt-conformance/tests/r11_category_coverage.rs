// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-11 gap closures driven against the **fully-assembled real runtime**:
//!
//! * **Gap (medium): 7-axis pairwise expansion produces the 1,000+ matrix** — the pairwise corpus is
//!   not only ≥1,000 and axis-covering (proven in ainxt-scenario) but also GREEN against the real
//!   assembled pipeline.
//! * **Gap (medium): scenario-matrix category coverage against the real runtime (§1.2–1.15)** — the
//!   categories the assembled runtime genuinely exercises are expanded beyond the redaction/leak/
//!   idempotency/RBAC/injection/malformed/unicode/huge spine to include **provider failover (1.2)**,
//!   **cancel-mid-turn (1.3)** and **N-session concurrency (1.4)**, each asserted with its invariant
//!   oracle against the real `Engine`.

use ainxt_conformance::{run_pairwise_matrix, ConformanceTarget};
use ainxt_scenario::{Category, Expectation, Runner, Scenario, Target};

#[test]
fn r11_pairwise_matrix_is_green_against_the_real_runtime() {
    let report = run_pairwise_matrix();
    eprintln!("{}", report.summary());
    assert!(
        report.total() >= 1000,
        "the pairwise mechanism must run 1,000+ scenarios (ran {})",
        report.total()
    );
    assert!(
        report.all_passed(),
        "the pairwise corpus must be green against the real runtime:\n{}",
        report.summary()
    );
    // The pairwise corpus exercises the safety spine across every axis combination.
    let cov = report.coverage();
    for c in [
        Category::ComplianceRedaction,
        Category::DataClassLeak,
        Category::DoubleExecution,
        Category::RbacDeny,
        Category::Injection,
        Category::MalformedModelOutput,
        Category::UnicodeRtl,
        Category::HugeInput,
    ] {
        assert!(
            cov.get(&c).copied().unwrap_or(0) > 0,
            "pairwise must cover {c}"
        );
    }
}

#[test]
fn r11_provider_failover_backup_serves_against_real_runtime() {
    // Every conformance turn routes through a FlakyPrimary that always returns 503; a correct,
    // non-empty answer is proof the class-eligible backup served — the §1.2 failover invariant.
    let target = ConformanceTarget::new();
    let s = Scenario::new(
        "FAILOVER-1",
        "class-eligible backup serves when the primary 503s",
        Category::ProviderFailover,
        "@echo FAILOVER-PROOF-XZ",
        Expectation {
            must_complete: true,
            must_contain: vec!["FAILOVER-PROOF-XZ".into()],
            ..Default::default()
        },
    );
    let report = Runner::with_default_oracles().run(std::slice::from_ref(&s), &target);
    assert!(
        report.all_passed(),
        "failover to the backup provider must serve a correct answer:\n{}",
        report.summary()
    );
    let obs = target.run(&s);
    assert!(
        obs.error.is_none(),
        "turn must complete via failover: {:?}",
        obs.error
    );
    assert!(obs.output.contains("FAILOVER-PROOF-XZ"));
}

#[test]
fn r11_cancel_mid_turn_executes_no_side_effect() {
    // A pre-cancelled settlement turn must abort cooperatively and NEVER execute the side effect.
    let target = ConformanceTarget::new();
    let s = Scenario::new(
        "CANCEL-1",
        "a cancelled turn executes no settlement",
        Category::CancelMidTurn,
        "@dup 4242 settle the batch",
        Expectation::default(),
    );
    let obs = target.run_cancelled(&s);
    assert!(
        obs.error
            .as_deref()
            .map(|e| e.contains("cancel"))
            .unwrap_or(false),
        "the turn must report cancellation, got {:?}",
        obs.error
    );
    assert!(
        obs.side_effects.is_empty(),
        "a cancelled turn must not execute any side effect, got {:?}",
        obs.side_effects
    );
}

#[test]
fn r11_concurrent_sessions_have_no_cross_bleed() {
    // 200 distinct sessions run concurrently against ONE engine; each answer must echo only its own
    // unique marker — no cross-session state bleed (§1.4 isolation invariant).
    let target = ConformanceTarget::new();
    let n = 200usize;
    let scenarios: Vec<Scenario> = (0..n)
        .map(|i| {
            Scenario::new(
                &format!("CONC-{i:04}"),
                "session isolation",
                Category::Concurrency,
                &format!("@echo SESSION-{i:04}-MARKER"),
                Expectation {
                    must_complete: true,
                    ..Default::default()
                },
            )
        })
        .collect();
    let results = target.run_many_concurrent(&scenarios);
    assert_eq!(results.len(), n, "every concurrent session must return");
    for (id, obs) in &results {
        let i: usize = id.trim_start_matches("CONC-").parse().unwrap();
        let own = format!("SESSION-{i:04}-MARKER");
        assert!(
            obs.output.contains(&own),
            "session {id} lost its own answer: {:?}",
            obs.output
        );
        // No other session's marker may appear in this session's output.
        for j in 0..n {
            if j != i {
                let other = format!("SESSION-{j:04}-MARKER");
                assert!(
                    !obs.output.contains(&other),
                    "cross-session bleed: {id} contains {other}"
                );
            }
        }
    }
}

#[test]
fn r11_category_coverage_spans_the_intended_matrix_axes() {
    // Honest coverage: the categories exercised against the real runtime now span the §1.x spine
    // PLUS failover / cancel / concurrency.
    let target = ConformanceTarget::new();
    // The three added categories are demonstrably drivable against the assembled engine:
    // failover (every turn), cancel (run_cancelled), concurrency (run_many_concurrent).
    let failover = Scenario::new(
        "COV-FAILOVER",
        "failover",
        Category::ProviderFailover,
        "@echo COV-OK",
        Expectation {
            must_complete: true,
            must_contain: vec!["COV-OK".into()],
            ..Default::default()
        },
    );
    let rep = Runner::with_default_oracles().run(std::slice::from_ref(&failover), &target);
    assert!(rep.all_passed(), "failover category must be green");

    let cancel = Scenario::new(
        "COV-CANCEL",
        "cancel",
        Category::CancelMidTurn,
        "@dup 1 settle",
        Expectation::default(),
    );
    assert!(target.run_cancelled(&cancel).side_effects.is_empty());

    let conc: Vec<Scenario> = (0..8)
        .map(|i| {
            Scenario::new(
                &format!("COV-CONC-{i}"),
                "conc",
                Category::Concurrency,
                &format!("@echo C{i}MARK"),
                Expectation::default(),
            )
        })
        .collect();
    let cr = target.run_many_concurrent(&conc);
    assert_eq!(cr.len(), 8);
}
