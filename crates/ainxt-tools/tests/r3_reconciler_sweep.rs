// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! r3_reconciler_sweep — active background sweep of lost-ack PENDING rows (§1.8, scenario 23).
//!
//! Fail-before: the reconciler fired ONLY inline when a new dispatch happened to hit an InDoubt
//! claim — there was no sweep loop, no timeout scan, no lease, no escalation/paging (the scan/lease
//! API did not exist). Pass-after: a real `ReconcilerSweeper` on the real `InMemoryLedger` finds
//! timed-out PENDING rows, leases each, probes the downstream, and resolves to COMMITTED / FAILED
//! or escalates to MANUAL_RECONCILIATION with an incident + page — and an active background thread
//! does the same on an interval.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ainxt_tools::{
    Claim, InMemoryLedger, Ledger, Reconciler, ReconcilerSweeper, RecordingEscalationSink,
    Resolution,
};

/// A downstream probe scripted per key: A committed, D not-found (fail), everything else ambiguous.
struct ScriptedReconciler {
    probes: Arc<AtomicUsize>,
}
impl Reconciler for ScriptedReconciler {
    fn reconcile(&self, key: &str, _tool: &str, _args: &str) -> Resolution {
        self.probes.fetch_add(1, Ordering::SeqCst);
        match key {
            "key-A" => Resolution::Committed("downstream-confirmed-A".into()),
            "key-D" => Resolution::Failed("downstream has no record".into()),
            _ => Resolution::Manual, // Ambiguous / no probe → escalate, never guess
        }
    }
}

/// A probe that always confirms — for the background-thread scenario.
struct AlwaysCommit;
impl Reconciler for AlwaysCommit {
    fn reconcile(&self, _k: &str, _t: &str, _a: &str) -> Resolution {
        Resolution::Committed("bg-confirmed".into())
    }
}

/// Simulate a lost ack: claim the slot (PENDING) and record the probe metadata, but — as if the
/// process died — never commit/fail it.
fn lost_ack(ledger: &InMemoryLedger, key: &str, tool: &str, args: &str) {
    assert_eq!(
        ledger.claim(key),
        Claim::Fresh,
        "first claim should be Fresh"
    );
    ledger.record_pending_meta(key, tool, args);
}

#[test]
fn r3_reconciler_sweep() {
    // ---- Scenario 1: resolve (commit + fail) and escalate, gated by the timeout ----
    let ledger = Arc::new(InMemoryLedger::new());
    lost_ack(&ledger, "key-A", "settle_tool", r#"{"batch":1}"#);
    lost_ack(&ledger, "key-D", "mr_tool", r#"{"branch":"x"}"#);
    lost_ack(&ledger, "key-B", "email_tool", r#"{"to":"ops@example"}"#);

    let probes = Arc::new(AtomicUsize::new(0));
    let escalation = Arc::new(RecordingEscalationSink::new());
    let sweeper = ReconcilerSweeper::new(
        ledger.clone(),
        Arc::new(ScriptedReconciler {
            probes: probes.clone(),
        }),
        escalation.clone(),
        "node-1",
        /*min_age*/ 5,
        /*lease_ttl*/ 10,
    );

    // Timeout gate: rows are age 0 (< min_age 5) → the sweep must touch NOTHING.
    let pre = sweeper.sweep_once();
    assert_eq!(pre.resolved(), 0, "no row is old enough yet");
    assert_eq!(probes.load(Ordering::SeqCst), 0, "no probe before timeout");
    assert_eq!(ledger.pending_beyond(0).len(), 3, "all three still PENDING");

    // Age the rows past the timeout, then sweep.
    ledger.advance(5);
    let rep = sweeper.sweep_once();

    assert!(
        rep.committed.contains(&"key-A".to_string()),
        "A probed → COMMITTED"
    );
    assert!(
        rep.failed.contains(&"key-D".to_string()),
        "D probed → FAILED"
    );
    assert!(
        rep.escalated.contains(&"key-B".to_string()),
        "B ambiguous → escalated"
    );
    assert_eq!(rep.resolved(), 3);
    assert_eq!(
        probes.load(Ordering::SeqCst),
        3,
        "each row probed exactly once"
    );

    // Every row has left PENDING (resolved or escalated) — none left indefinitely ambiguous.
    assert!(
        ledger.pending_beyond(0).is_empty(),
        "no PENDING rows remain"
    );

    // A: adopted the downstream result, no re-execution.
    assert_eq!(
        ledger.claim("key-A"),
        Claim::Committed("downstream-confirmed-A".to_string())
    );
    // B: MANUAL_RECONCILIATION — a re-claim is InDoubt (never silently re-run).
    assert_eq!(ledger.claim("key-B"), Claim::InDoubt);

    // The escalation filed exactly one incident carrying the request identity + receipt.
    let incidents = escalation.incidents();
    assert_eq!(incidents.len(), 1);
    assert_eq!(incidents[0].key, "key-B");
    assert_eq!(incidents[0].tool, "email_tool");
    assert_eq!(incidents[0].args, r#"{"to":"ops@example"}"#);

    // Idempotent: a second pass does nothing and files no duplicate incident.
    // (key-A re-claimed above is Committed/non-mutating; key-B is Manual; key-D was FAILED.)
    let again = sweeper.sweep_once();
    assert_eq!(again.resolved(), 0);
    assert!(again.skipped_leased.is_empty());
    assert_eq!(escalation.len(), 1, "no duplicate incident");

    // ---- Scenario 2: a live lease on another node makes the sweep skip the row (no double-probe) ----
    let l2 = Arc::new(InMemoryLedger::new());
    lost_ack(&l2, "key-C", "settle_tool", r#"{"batch":9}"#);
    l2.advance(5);
    // Node-A takes the lease (as if mid-reconcile); Node-B's sweep must skip it.
    assert!(
        l2.try_lease("key-C", "node-A", 100),
        "node-A leases the row"
    );
    let node_b = ReconcilerSweeper::new(
        l2.clone(),
        Arc::new(AlwaysCommit),
        Arc::new(RecordingEscalationSink::new()),
        "node-B",
        5,
        10,
    );
    let rb = node_b.sweep_once();
    assert!(
        rb.skipped_leased.contains(&"key-C".to_string()),
        "leased row skipped"
    );
    assert_eq!(rb.resolved(), 0);
    assert_eq!(
        l2.claim("key-C"),
        Claim::InDoubt,
        "row untouched, still in-doubt"
    );

    // ---- Scenario 3: the ACTIVE background sweep loop reconciles a lost-ack row on its own ----
    let l3 = Arc::new(InMemoryLedger::new());
    lost_ack(&l3, "bg", "settle_tool", r#"{"batch":42}"#);
    l3.advance(2);
    let bg = Arc::new(ReconcilerSweeper::new(
        l3.clone(),
        Arc::new(AlwaysCommit),
        Arc::new(RecordingEscalationSink::new()),
        "node-bg",
        /*min_age*/ 1,
        /*lease_ttl*/ 1000,
    ));
    let handle = bg.spawn(Duration::from_millis(5));

    // Poll (bounded) until the background loop commits the row.
    let mut confirmed = false;
    for _ in 0..200 {
        if matches!(l3.claim("bg"), Claim::Committed(_)) {
            confirmed = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    handle.stop();
    assert!(
        confirmed,
        "the active background sweep should reconcile the lost-ack row"
    );
}
