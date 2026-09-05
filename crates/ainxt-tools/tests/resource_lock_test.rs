// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! TOOL-01 — per-resource locking (design §1.5, scenario 8).
//!
//! Before the fix, `ToolRuntime::dispatch` resolved a call's `resource_key` only for authorization;
//! nothing serialized two concurrent calls that touch the SAME resource, so their side effects could
//! interleave (a lost update / double write on the same ledger account or file). These tests pin the
//! two halves of the design property:
//!   * calls sharing a `resource_key` **serialize** (peak concurrency == 1), and
//!   * calls on **disjoint** resources still run **in parallel** (we did not over-serialize globally).

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ainxt_tools::{
    DispatchResult, EffectClass, InMemoryLedger, ManualReconciler, Tool, ToolError, ToolRuntime,
};

/// A side-effecting "update this account" tool. `resource()` is the account id (the part of `args`
/// before `|`), while `idempotency_key()` is the FULL args — so two calls on the same account with
/// different operations are distinct ledger entries (both genuinely execute) yet share a resource
/// and therefore must not run concurrently. `peak` records the maximum number of overlapping
/// `execute` bodies observed; with correct per-resource locking it can never exceed 1.
struct AccountUpdate {
    in_flight: Arc<AtomicU32>,
    peak: Arc<AtomicU32>,
    runs: Arc<AtomicU32>,
}

impl Tool for AccountUpdate {
    fn name(&self) -> &str {
        "account_update"
    }
    fn effect_class(&self) -> EffectClass {
        EffectClass::SideEffecting
    }
    fn idempotency_key(&self, args: &str) -> Option<String> {
        Some(args.to_string()) // unique per call → every call really executes
    }
    fn resource(&self, args: &str) -> Option<String> {
        Some(args.split('|').next().unwrap_or(args).to_string())
    }
    fn execute(&self, _args: &str) -> Result<String, ToolError> {
        self.runs.fetch_add(1, Ordering::SeqCst);
        let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(now, Ordering::SeqCst);
        // A real external call takes time; this window is where an interleave would show up.
        std::thread::sleep(Duration::from_millis(40));
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
        Ok("updated".into())
    }
}

#[test]
fn gap_tool_01_concurrent_calls_on_same_resource_serialize() {
    let in_flight = Arc::new(AtomicU32::new(0));
    let peak = Arc::new(AtomicU32::new(0));
    let runs = Arc::new(AtomicU32::new(0));

    let mut rt = ToolRuntime::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler));
    rt.register(Box::new(AccountUpdate {
        in_flight: in_flight.clone(),
        peak: peak.clone(),
        runs: runs.clone(),
    }));
    let rt = Arc::new(rt);

    // 8 concurrent turns, all touching account "acct-1" but each a distinct operation (distinct
    // idempotency key) so all 8 execute for real.
    let mut handles = Vec::new();
    for i in 0..8u32 {
        let rt = rt.clone();
        handles.push(std::thread::spawn(move || {
            rt.dispatch("account_update", &format!("acct-1|op{i}"))
        }));
    }
    for h in handles {
        assert!(matches!(h.join().unwrap(), DispatchResult::Ok(_)));
    }

    assert_eq!(
        runs.load(Ordering::SeqCst),
        8,
        "all 8 distinct operations must actually execute (the ledger dedups nothing here)"
    );
    // The load-bearing assertion: BEFORE per-resource locking this reaches up to 8 (all threads in
    // execute at once); AFTER, same-resource calls serialize so it is exactly 1.
    assert_eq!(
        peak.load(Ordering::SeqCst),
        1,
        "concurrent calls on the SAME resource_key must serialize — no interleaved writes"
    );
}

/// A probe whose `execute` waits (bounded) for a *peer* to also enter, then records the peak overlap.
/// If two calls are serialized, the second can never enter while the first waits, so the first times
/// out and peak stays 1. If they run in parallel, both enter and peak reaches 2.
struct ConcurrencyProbe {
    entered: Arc<AtomicU32>,
    peak: Arc<AtomicU32>,
}

impl Tool for ConcurrencyProbe {
    fn name(&self) -> &str {
        "probe"
    }
    fn effect_class(&self) -> EffectClass {
        EffectClass::Pure // resource locking must apply regardless of effect class
    }
    fn resource(&self, args: &str) -> Option<String> {
        Some(args.to_string()) // the whole arg IS the resource id here
    }
    fn execute(&self, _args: &str) -> Result<String, ToolError> {
        let n = self.entered.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(n, Ordering::SeqCst);
        let deadline = Instant::now() + Duration::from_secs(3);
        while self.entered.load(Ordering::SeqCst) < 2 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(2));
        }
        self.entered.fetch_sub(1, Ordering::SeqCst);
        Ok("done".into())
    }
}

#[test]
fn gap_tool_01_disjoint_resources_run_in_parallel() {
    let entered = Arc::new(AtomicU32::new(0));
    let peak = Arc::new(AtomicU32::new(0));

    let mut rt = ToolRuntime::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler));
    rt.register(Box::new(ConcurrencyProbe {
        entered: entered.clone(),
        peak: peak.clone(),
    }));
    let rt = Arc::new(rt);

    // Two turns on DIFFERENT resources ("acct-a" vs "acct-b"). They must be able to overlap; if a
    // global (rather than per-resource) lock were used they'd serialize and this would time out at
    // peak == 1. This is the guard that per-resource locking does not over-serialize.
    let mut handles = Vec::new();
    for r in ["acct-a", "acct-b"] {
        let rt = rt.clone();
        handles.push(std::thread::spawn(move || rt.dispatch("probe", r)));
    }
    for h in handles {
        assert!(matches!(h.join().unwrap(), DispatchResult::Ok(_)));
    }

    assert_eq!(
        peak.load(Ordering::SeqCst),
        2,
        "calls on disjoint resources must run in parallel — per-resource locking, not a global lock"
    );
}
