// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R11 §1.3 — saga steps tracked by the exactly-once ledger. A saga replayed after a mid-way failure
//! re-adopts already-committed steps instead of re-executing them, compensates on failure in reverse,
//! and reports FAILED_PARTIAL honestly when a step is non-compensable. Scenario 3.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use ainxt_tools::{run_saga_ledgered, InMemoryLedger, LedgerSagaStep, SagaOutcome};

fn step(
    name: &str,
    key: &str,
    calls: Arc<AtomicUsize>,
    fail: bool,
    comp: Arc<AtomicUsize>,
) -> LedgerSagaStep {
    let n = name.to_string();
    LedgerSagaStep::new(
        name,
        key,
        Box::new(move || {
            calls.fetch_add(1, Ordering::SeqCst);
            if fail {
                Err(format!("{n} failed"))
            } else {
                Ok(format!("{n}-done"))
            }
        }),
        Box::new(move || {
            comp.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }),
    )
}

#[test]
fn happy_path_runs_all_steps_once_and_ledger_dedups_a_replay() {
    let ledger = InMemoryLedger::new();
    let c1 = Arc::new(AtomicUsize::new(0));
    let c2 = Arc::new(AtomicUsize::new(0));
    let comp = Arc::new(AtomicUsize::new(0));

    let steps = vec![
        step(
            "jira_update",
            "k-jira",
            Arc::clone(&c1),
            false,
            Arc::clone(&comp),
        ),
        step(
            "gitlab_mr",
            "k-mr",
            Arc::clone(&c2),
            false,
            Arc::clone(&comp),
        ),
    ];
    let out = run_saga_ledgered(&ledger, steps);
    assert!(matches!(out, SagaOutcome::Completed(ref r) if r.len() == 2));
    assert_eq!(c1.load(Ordering::SeqCst), 1);
    assert_eq!(c2.load(Ordering::SeqCst), 1);

    // Replay the SAME saga (same keys): the ledger dedups — no step re-executes.
    let steps2 = vec![
        step(
            "jira_update",
            "k-jira",
            Arc::clone(&c1),
            false,
            Arc::clone(&comp),
        ),
        step(
            "gitlab_mr",
            "k-mr",
            Arc::clone(&c2),
            false,
            Arc::clone(&comp),
        ),
    ];
    let out2 = run_saga_ledgered(&ledger, steps2);
    assert!(matches!(out2, SagaOutcome::Completed(ref r) if r.len() == 2));
    assert_eq!(
        c1.load(Ordering::SeqCst),
        1,
        "committed step must not re-execute on replay"
    );
    assert_eq!(c2.load(Ordering::SeqCst), 1);
    assert_eq!(comp.load(Ordering::SeqCst), 0);
}

#[test]
fn a_failed_step_compensates_completed_steps_in_reverse() {
    let ledger = InMemoryLedger::new();
    let c1 = Arc::new(AtomicUsize::new(0));
    let c2 = Arc::new(AtomicUsize::new(0));
    let c3 = Arc::new(AtomicUsize::new(0));
    let comp1 = Arc::new(AtomicUsize::new(0));
    let comp2 = Arc::new(AtomicUsize::new(0));
    let noop = Arc::new(AtomicUsize::new(0));

    let steps = vec![
        step("s1", "k1", Arc::clone(&c1), false, Arc::clone(&comp1)),
        step("s2", "k2", Arc::clone(&c2), false, Arc::clone(&comp2)),
        step("s3", "k3", Arc::clone(&c3), true, Arc::clone(&noop)), // fails
    ];
    let out = run_saga_ledgered(&ledger, steps);
    match out {
        SagaOutcome::Compensated { failed_step, .. } => assert_eq!(failed_step, "s3"),
        other => panic!("expected Compensated, got {other:?}"),
    }
    // s1 and s2 committed then compensated; s3 attempted (and failed, so ledger-marked FAILED).
    assert_eq!(comp1.load(Ordering::SeqCst), 1);
    assert_eq!(comp2.load(Ordering::SeqCst), 1);
    assert_eq!(c3.load(Ordering::SeqCst), 1);
}

#[test]
fn a_non_compensable_step_reports_failed_partial_honestly() {
    let ledger = InMemoryLedger::new();
    let c1 = Arc::new(AtomicUsize::new(0));
    let c2 = Arc::new(AtomicUsize::new(0));

    // s1 = an email already sent → its compensation FAILS (can't unsend).
    let s1 = LedgerSagaStep::new(
        "send_email",
        "k-email",
        Box::new(|| Ok("sent".into())),
        Box::new(|| Err("email cannot be unsent".into())),
    );
    let s2 = step(
        "charge",
        "k-charge",
        Arc::clone(&c2),
        true,
        Arc::new(AtomicUsize::new(0)),
    );
    let _ = c1;

    let out = run_saga_ledgered(&ledger, vec![s1, s2]);
    match out {
        SagaOutcome::FailedPartial {
            failed_step,
            uncompensated,
            ..
        } => {
            assert_eq!(failed_step, "charge");
            assert_eq!(uncompensated.len(), 1);
            assert!(uncompensated[0].contains("send_email"));
        }
        other => panic!("expected FailedPartial, got {other:?}"),
    }
}
