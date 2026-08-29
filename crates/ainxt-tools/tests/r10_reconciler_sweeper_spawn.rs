// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! r10_reconciler_sweeper_spawn — the daemon-facing spawn/handle entrypoint of the active lost-ack
//! reconciler sweep (§1.8) is clean: responsive shutdown + observable liveness.
//!
//! The sweep logic itself is covered by `r3_reconciler_sweep`; THIS test pins the qualities a
//! daemon supervisor needs from `ReconcilerSweeper::spawn` / `SweepHandle` — the piece that will be
//! hot-wired into the daemon lifecycle (runtimed→needs_hot_wiring), so the entrypoint it hands off
//! must already be correct at the crate level.
//!
//! Fail-before: the loop slept `std::thread::sleep(interval)` between passes, so `stop()` could not
//! return until the current interval elapsed — a daemon with a realistic (minutes-long) sweep
//! interval would hang for that long on shutdown — and there was no way to observe how many passes
//! had run (`SweepHandle::passes_completed` did not exist, so this test would not even compile).
//! Pass-after: one pass always runs before the first wait (so a lost-ack row present at spawn is
//! reconciled promptly regardless of `interval`), `stop()` interrupts a sleeping loop immediately
//! (a condvar timed-wait, not an interval sleep), and completed passes are observable.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ainxt_tools::{
    Claim, InMemoryLedger, Ledger, Reconciler, ReconcilerSweeper, RecordingEscalationSink,
    Resolution,
};

/// A downstream probe that always confirms the effect happened — the row must be adopted, not
/// re-executed. Counts how many times it was asked, to prove the loop is actually sweeping.
struct AlwaysCommit {
    probes: Arc<AtomicUsize>,
}
impl Reconciler for AlwaysCommit {
    fn reconcile(&self, _key: &str, _tool: &str, _args: &str) -> Resolution {
        self.probes.fetch_add(1, Ordering::SeqCst);
        Resolution::Committed("bg-confirmed".into())
    }
}

/// Seed a lost-ack row: claim the slot (PENDING) + record probe metadata, then never commit — as if
/// the process died between firing the downstream effect and recording the outcome.
fn lost_ack(ledger: &InMemoryLedger, key: &str) {
    assert_eq!(
        ledger.claim(key),
        Claim::Fresh,
        "first claim should be Fresh"
    );
    ledger.record_pending_meta(key, "settle_tool", r#"{"batch":1}"#);
}

#[test]
fn r10_reconciler_sweeper_spawn() {
    // ---- One pass runs before the first wait, regardless of a huge interval ----
    // A ONE-HOUR interval: if the loop slept the interval before its first sweep (or if `stop()`
    // waited the interval out), this test would take an hour. It does not — proving the first pass
    // is eager and shutdown is condvar-responsive.
    let huge_interval = Duration::from_secs(3600);

    let ledger = Arc::new(InMemoryLedger::new());
    lost_ack(&ledger, "bg");
    // Age the row past the sweep timeout so the first pass is eligible to reconcile it.
    ledger.advance(2);

    let probes = Arc::new(AtomicUsize::new(0));
    let sweeper = Arc::new(ReconcilerSweeper::new(
        ledger.clone(),
        Arc::new(AlwaysCommit {
            probes: probes.clone(),
        }),
        Arc::new(RecordingEscalationSink::new()),
        "node-daemon",
        /*min_age*/ 1,
        /*lease_ttl*/ 1000,
    ));

    let handle = sweeper.spawn(huge_interval);

    // The eager first pass must reconcile the lost-ack row well within a bounded poll — NOT after
    // the hour-long interval. Poll briefly; the pass is immediate.
    let mut committed = false;
    for _ in 0..200 {
        if matches!(ledger.claim("bg"), Claim::Committed(_)) {
            committed = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(
        committed,
        "the eager first sweep pass must reconcile the lost-ack row regardless of interval"
    );
    assert!(
        probes.load(Ordering::SeqCst) >= 1,
        "the downstream was actually probed by the background loop"
    );

    // Liveness observability: at least one full pass has been recorded.
    assert!(
        handle.passes_completed() >= 1,
        "completed passes are observable for a supervisor"
    );

    // ---- Shutdown is responsive: stop() returns promptly despite the hour-long interval ----
    // With the old `thread::sleep(interval)` the loop would be parked for up to an hour and stop()
    // could not join until it woke; the condvar timed-wait wakes it at once.
    let t0 = Instant::now();
    handle.stop();
    let shutdown = t0.elapsed();
    assert!(
        shutdown < Duration::from_secs(5),
        "stop() must interrupt the inter-pass wait immediately, not wait out the interval \
         (took {shutdown:?}, interval was {huge_interval:?})"
    );

    // The row was adopted from the downstream, never re-executed; it is out of PENDING for good.
    assert_eq!(
        ledger.claim("bg"),
        Claim::Committed("bg-confirmed".to_string())
    );
    assert!(
        ledger.pending_beyond(0).is_empty(),
        "no PENDING row remains"
    );

    // ---- A short interval drives repeated passes, and Drop also stops cleanly (no explicit stop) ----
    let l2 = Arc::new(InMemoryLedger::new());
    let sweeper2 = Arc::new(ReconcilerSweeper::new(
        l2.clone(),
        Arc::new(AlwaysCommit {
            probes: Arc::new(AtomicUsize::new(0)),
        }),
        Arc::new(RecordingEscalationSink::new()),
        "node-daemon-2",
        1,
        1000,
    ));
    let h2 = sweeper2.spawn(Duration::from_millis(2));
    // Wait (bounded) until the loop has clearly cycled more than once.
    let mut multi_pass = false;
    for _ in 0..200 {
        if h2.passes_completed() >= 3 {
            multi_pass = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(multi_pass, "a short interval drives repeated sweep passes");
    // Drop (no explicit stop) must signal + join without hanging — the test simply returning proves
    // it, since a leaked non-stopping thread on a 2ms interval would keep the process from a clean
    // join only if Drop failed to signal. Explicitly drop here to make the intent local.
    drop(h2);
}
