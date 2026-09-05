// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! r6_sql_ledger_reconciler_sweep — active lost-ack reconciliation over the DURABLE SQL ledger, and
//! across processes (§1.8, gap R+S).
//!
//! Fail-before: the §1.8 sweep only ran against the ephemeral in-process `InMemoryLedger`; there was
//! no durable, cross-process ledger for it to run over, so a row a *crashed* daemon left `PENDING`
//! was invisible to the surviving daemon's sweeper. (No `SqlLedger`/`InMemorySqlStore` existed.)
//!
//! Pass-after: a lost-ack `PENDING` row written by process A's dispatch handle is found, leased, and
//! resolved by process B's `ReconcilerSweeper` running over the SAME durable store — committed /
//! failed / escalated exactly as the ledger core prescribes, and a live lease on one node makes the
//! other node skip the row (no double-probe of a settlement record).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use ainxt_tools::{
    Claim, InMemorySqlStore, Ledger, Reconciler, ReconcilerSweeper, RecordingEscalationSink,
    Resolution, SqlLedger,
};

/// Scripted downstream probe: A committed, D not-found, everything else ambiguous → escalate.
struct ScriptedReconciler {
    probes: Arc<AtomicUsize>,
}
impl Reconciler for ScriptedReconciler {
    fn reconcile(&self, key: &str, _tool: &str, _args: &str) -> Resolution {
        self.probes.fetch_add(1, Ordering::SeqCst);
        match key {
            "key-A" => Resolution::Committed("downstream-confirmed-A".into()),
            "key-D" => Resolution::Failed("downstream has no record".into()),
            _ => Resolution::Manual,
        }
    }
}

/// Simulate a lost ack on a given process handle: claim (Fresh) + record probe metadata, then — as
/// if that daemon died — never commit/fail.
fn lost_ack(dispatch: &SqlLedger<InMemorySqlStore>, key: &str, tool: &str, args: &str) {
    assert_eq!(
        dispatch.claim(key),
        Claim::Fresh,
        "first claim should be Fresh"
    );
    dispatch.record_pending_meta(key, tool, args);
}

#[test]
fn r6_sql_ledger_reconciler_sweep() {
    // One durable store; process A dispatches, process B sweeps — the cross-process recovery path.
    let store = InMemorySqlStore::new();
    let proc_a = SqlLedger::new(store.clone());
    // Process B's sweeper needs an Arc<dyn Ledger> over the SAME store.
    let proc_b: Arc<dyn Ledger> = Arc::new(SqlLedger::new(store.clone()));

    // Process A leaves three lost-ack rows and then "crashes".
    lost_ack(&proc_a, "key-A", "settle_tool", r#"{"batch":1}"#);
    lost_ack(&proc_a, "key-D", "mr_tool", r#"{"branch":"x"}"#);
    lost_ack(&proc_a, "key-B", "email_tool", r#"{"to":"ops@example"}"#);

    let probes = Arc::new(AtomicUsize::new(0));
    let escalation = Arc::new(RecordingEscalationSink::new());
    let sweeper = ReconcilerSweeper::new(
        proc_b.clone(),
        Arc::new(ScriptedReconciler {
            probes: probes.clone(),
        }),
        escalation.clone(),
        "node-B",
        /*min_age*/ 5,
        /*lease_ttl*/ 10,
    );

    // Timeout gate: rows are age 0 → the sweep touches nothing.
    let pre = sweeper.sweep_once();
    assert_eq!(pre.resolved(), 0, "no row old enough yet");
    assert_eq!(probes.load(Ordering::SeqCst), 0);
    assert_eq!(
        store.len(),
        3,
        "three durable PENDING rows persist across the crash"
    );

    // Age the durable rows past the lost-ack timeout, then sweep from the SURVIVING process.
    store.advance(5);
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

    // No row is left indefinitely ambiguous.
    assert!(store_pending_empty(&proc_b), "no PENDING rows remain");

    // A adopted the downstream result — visible to the ORIGINAL process too (one durable store).
    assert_eq!(
        proc_a.claim("key-A"),
        Claim::Committed("downstream-confirmed-A".to_string()),
        "recovery by node-B is durable and visible to node-A"
    );
    // B escalated to MANUAL — a re-claim is InDoubt, never silently re-run.
    assert_eq!(proc_a.claim("key-B"), Claim::InDoubt);

    // Exactly one incident carrying the request identity + receipt.
    let incidents = escalation.incidents();
    assert_eq!(incidents.len(), 1);
    assert_eq!(incidents[0].key, "key-B");
    assert_eq!(incidents[0].tool, "email_tool");
    assert_eq!(incidents[0].args, r#"{"to":"ops@example"}"#);

    // Idempotent: a second pass resolves nothing and files no duplicate incident.
    let again = sweeper.sweep_once();
    assert_eq!(again.resolved(), 0);
    assert_eq!(escalation.len(), 1, "no duplicate incident");

    // ---- Lease exclusivity across two processes: a live lease makes the peer sweep skip ----
    let store2 = InMemorySqlStore::new();
    let dispatch2 = SqlLedger::new(store2.clone());
    lost_ack(&dispatch2, "key-C", "settle_tool", r#"{"batch":9}"#);
    store2.advance(5);

    // Node-A takes the lease (as if mid-reconcile) directly on its handle.
    let node_a: Arc<dyn Ledger> = Arc::new(SqlLedger::new(store2.clone()));
    assert!(
        node_a.try_lease("key-C", "node-A", 100),
        "node-A leases the durable row"
    );

    let node_b: Arc<dyn Ledger> = Arc::new(SqlLedger::new(store2.clone()));
    let peer_sweeper = ReconcilerSweeper::new(
        node_b,
        Arc::new(ScriptedReconciler {
            probes: Arc::new(AtomicUsize::new(0)),
        }),
        Arc::new(RecordingEscalationSink::new()),
        "node-B",
        5,
        10,
    );
    let rb = peer_sweeper.sweep_once();
    assert!(
        rb.skipped_leased.contains(&"key-C".to_string()),
        "leased row skipped by peer"
    );
    assert_eq!(rb.resolved(), 0);
    assert_eq!(
        dispatch2.claim("key-C"),
        Claim::InDoubt,
        "row untouched, still in-doubt"
    );
}

fn store_pending_empty(ledger: &Arc<dyn Ledger>) -> bool {
    ledger.pending_beyond(0).is_empty()
}
