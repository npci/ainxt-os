// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Side-Effect Ledger tests — the no-double-payment guarantee, in-doubt reconciliation,
//! saga compensation, and durable exactly-once across a restart.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ainxt_eventlog::JsonlEventLog;
use ainxt_tools::{
    run_saga, Claim, DispatchResult, EffectClass, EventLogLedger, InMemoryLedger, Ledger,
    ManualReconciler, Reconciler, Resolution, SagaOutcome, SagaStep, Tool, ToolError, ToolRuntime,
};

/// A side-effecting settlement tool; `counter` proves how many times it actually ran.
struct SettleTool {
    counter: Arc<AtomicU32>,
}
impl Tool for SettleTool {
    fn name(&self) -> &str {
        "settle"
    }
    fn effect_class(&self) -> EffectClass {
        EffectClass::SideEffecting
    }
    fn idempotency_key(&self, args: &str) -> Option<String> {
        Some(args.to_string()) // purely semantic — no timestamp/random
    }
    fn execute(&self, args: &str) -> Result<String, ToolError> {
        self.counter.fetch_add(1, Ordering::SeqCst);
        Ok(format!("settled:{args}"))
    }
}

/// A side-effecting tool that (wrongly) supplies no key — must be blocked.
struct NoKeyTool;
impl Tool for NoKeyTool {
    fn name(&self) -> &str {
        "nokey"
    }
    fn effect_class(&self) -> EffectClass {
        EffectClass::SideEffecting
    }
    fn execute(&self, _args: &str) -> Result<String, ToolError> {
        Ok("should never run".into())
    }
}

/// A pure tool — runs every time, never ledgered.
struct EchoTool {
    counter: Arc<AtomicU32>,
}
impl Tool for EchoTool {
    fn name(&self) -> &str {
        "echo"
    }
    fn effect_class(&self) -> EffectClass {
        EffectClass::Pure
    }
    fn execute(&self, args: &str) -> Result<String, ToolError> {
        self.counter.fetch_add(1, Ordering::SeqCst);
        Ok(args.to_string())
    }
}

fn temp_dir(tag: &str) -> PathBuf {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("ainxt-tools-{tag}-{}-{n}", std::process::id()))
}

#[test]
fn retried_side_effect_executes_exactly_once() {
    let counter = Arc::new(AtomicU32::new(0));
    let mut rt = ToolRuntime::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler));
    rt.register(Box::new(SettleTool {
        counter: counter.clone(),
    }));

    let r1 = rt.dispatch("settle", "NEFT-2026-07-18");
    let r2 = rt.dispatch("settle", "NEFT-2026-07-18"); // retry, same key

    assert_eq!(r1, DispatchResult::Ok("settled:NEFT-2026-07-18".into()));
    assert_eq!(
        r2,
        DispatchResult::Deduped("settled:NEFT-2026-07-18".into())
    );
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "the settlement must run EXACTLY ONCE"
    );
}

#[test]
fn different_keys_execute_separately() {
    let counter = Arc::new(AtomicU32::new(0));
    let mut rt = ToolRuntime::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler));
    rt.register(Box::new(SettleTool {
        counter: counter.clone(),
    }));
    rt.dispatch("settle", "batch-A");
    rt.dispatch("settle", "batch-B");
    assert_eq!(counter.load(Ordering::SeqCst), 2);
}

#[test]
fn side_effecting_tool_without_a_key_is_blocked() {
    let mut rt = ToolRuntime::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler));
    rt.register(Box::new(NoKeyTool));
    assert!(matches!(
        rt.dispatch("nokey", "x"),
        DispatchResult::Blocked(_)
    ));
}

#[test]
fn pure_tool_runs_every_time() {
    let counter = Arc::new(AtomicU32::new(0));
    let mut rt = ToolRuntime::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler));
    rt.register(Box::new(EchoTool {
        counter: counter.clone(),
    }));
    rt.dispatch("echo", "hi");
    rt.dispatch("echo", "hi");
    assert_eq!(
        counter.load(Ordering::SeqCst),
        2,
        "pure tools are not deduped"
    );
}

#[test]
fn in_doubt_claim_escalates_by_default() {
    let ledger = InMemoryLedger::new();
    ledger.claim("NEFT-X"); // reserve PENDING, then "crash" before commit
    let mut rt = ToolRuntime::new(Box::new(ledger), Box::new(ManualReconciler));
    rt.register(Box::new(SettleTool {
        counter: Arc::new(AtomicU32::new(0)),
    }));
    assert_eq!(
        rt.dispatch("settle", "NEFT-X"),
        DispatchResult::NeedsReconciliation
    );
}

#[test]
fn in_doubt_claim_can_be_resolved_by_a_reconciler() {
    struct Recon;
    impl Reconciler for Recon {
        fn reconcile(&self, _k: &str, _t: &str, _a: &str) -> Resolution {
            Resolution::Committed("recovered-downstream".into())
        }
    }
    let counter = Arc::new(AtomicU32::new(0));
    let ledger = InMemoryLedger::new();
    ledger.claim("NEFT-Y");
    let mut rt = ToolRuntime::new(Box::new(ledger), Box::new(Recon));
    rt.register(Box::new(SettleTool {
        counter: counter.clone(),
    }));
    assert_eq!(
        rt.dispatch("settle", "NEFT-Y"),
        DispatchResult::Deduped("recovered-downstream".into())
    );
    assert_eq!(
        counter.load(Ordering::SeqCst),
        0,
        "in-doubt must not blind-re-execute"
    );
}

#[test]
fn saga_compensates_completed_steps_on_failure() {
    let comp1 = Arc::new(AtomicU32::new(0));
    let c1 = comp1.clone();
    let out = run_saga(vec![
        SagaStep::new(
            "open-branch",
            Box::new(|| Ok("branch".into())),
            Box::new(move || {
                c1.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }),
        ),
        SagaStep::new(
            "commit-change",
            Box::new(|| Err("compile failed".into())),
            Box::new(|| Ok(())),
        ),
    ]);
    assert_eq!(
        out,
        SagaOutcome::Compensated {
            failed_step: "commit-change".into(),
            reason: "compile failed".into()
        }
    );
    assert_eq!(
        comp1.load(Ordering::SeqCst),
        1,
        "the completed step must be compensated"
    );
}

#[test]
fn saga_reports_failed_partial_when_compensation_also_fails() {
    let out = run_saga(vec![
        SagaStep::new(
            "s1",
            Box::new(|| Ok("ok".into())),
            Box::new(|| Err("cannot undo".into())),
        ),
        SagaStep::new("s2", Box::new(|| Err("boom".into())), Box::new(|| Ok(()))),
    ]);
    match out {
        SagaOutcome::FailedPartial {
            failed_step,
            uncompensated,
            ..
        } => {
            assert_eq!(failed_step, "s2");
            assert_eq!(uncompensated.len(), 1);
        }
        other => panic!("expected FailedPartial, got {other:?}"),
    }
}

#[test]
fn durable_exactly_once_survives_a_restart() {
    let dir = temp_dir("durable");
    let counter = Arc::new(AtomicU32::new(0)); // shared across both "process" instances

    {
        let log = JsonlEventLog::open(&dir).unwrap();
        let mut rt = ToolRuntime::new(
            Box::new(EventLogLedger::new(log)),
            Box::new(ManualReconciler),
        );
        rt.register(Box::new(SettleTool {
            counter: counter.clone(),
        }));
        assert_eq!(
            rt.dispatch("settle", "NEFT-1"),
            DispatchResult::Ok("settled:NEFT-1".into())
        );
    } // restart
    assert_eq!(counter.load(Ordering::SeqCst), 1);

    let log2 = JsonlEventLog::open(&dir).unwrap();
    let mut rt2 = ToolRuntime::new(
        Box::new(EventLogLedger::new(log2)),
        Box::new(ManualReconciler),
    );
    rt2.register(Box::new(SettleTool {
        counter: counter.clone(),
    }));
    let r = rt2.dispatch("settle", "NEFT-1"); // same key, after restart

    assert_eq!(r, DispatchResult::Deduped("settled:NEFT-1".into()));
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "must NOT re-execute after a restart"
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn durable_ledger_claim_is_atomic_under_concurrency() {
    // 16 threads race to claim the SAME key. Exactly ONE may win `Fresh`; the rest must see
    // InDoubt/Committed. Without the claim lock, several threads read "not present" and all append
    // "pending", each returning Fresh → the same side effect executes multiple times (double debit).
    let dir = temp_dir("durable-concurrent");
    let log = JsonlEventLog::open(&dir).unwrap();
    let ledger = Arc::new(EventLogLedger::new(log));

    let fresh = Arc::new(AtomicU32::new(0));
    let mut handles = Vec::new();
    for _ in 0..16 {
        let l = ledger.clone();
        let f = fresh.clone();
        handles.push(std::thread::spawn(move || {
            if matches!(l.claim("NEFT-RACE"), Claim::Fresh) {
                f.fetch_add(1, Ordering::SeqCst);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(
        fresh.load(Ordering::SeqCst),
        1,
        "exactly one claim may win the race — more than one means the exactly-once ledger double-executes"
    );
    std::fs::remove_dir_all(&dir).ok();
}
