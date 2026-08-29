// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! r3_two_phase_commit — two-phase commit (dry_run/commit) for HighRisk actions (§1.4).
//!
//! Fail-before: `RiskTier::HighRisk` and `ToolRuntime::dry_run`/`commit` did not exist, and a
//! `HighRisk` tool would execute on a bare `dispatch`. Pass-after: `dispatch` REFUSES a HighRisk
//! capability, and the ONLY path that fires it is `dry_run` (preview, no side effect) → `commit`
//! (requires the exact key from a prior, unexpired dry_run). Exercised on the real `ToolRuntime`.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use ainxt_tools::{
    DispatchResult, EffectClass, InMemoryLedger, ManualReconciler, RiskTier, Tool, ToolError,
    ToolRuntime,
};

/// A HighRisk, side-effecting bulk-write. `execute` bumps `calls`; `dry_run_preview` bumps
/// `previews` and MUST NOT touch `calls` (the preview has no side effect). The name is deliberately
/// NOT a payment-initiation signature, so registration is admitted.
struct BulkLedgerWrite {
    calls: Arc<AtomicUsize>,
    previews: Arc<AtomicUsize>,
}

impl Tool for BulkLedgerWrite {
    fn name(&self) -> &str {
        "bulk_record_write"
    }
    fn effect_class(&self) -> EffectClass {
        EffectClass::SideEffecting
    }
    fn risk_tier(&self) -> RiskTier {
        RiskTier::HighRisk
    }
    fn idempotency_key(&self, args: &str) -> Option<String> {
        Some(format!("bulk_record_write:{args}"))
    }
    fn dry_run_preview(&self, args: &str) -> Result<String, ToolError> {
        self.previews.fetch_add(1, Ordering::SeqCst);
        Ok(format!("would write records for {args}"))
    }
    fn execute(&self, args: &str) -> Result<String, ToolError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(format!("wrote {args}"))
    }
}

/// A plain Low-risk side-effecting tool — proves single-phase dispatch is unaffected by the gate.
struct LowNote {
    calls: Arc<AtomicUsize>,
}
impl Tool for LowNote {
    fn name(&self) -> &str {
        "note"
    }
    fn effect_class(&self) -> EffectClass {
        EffectClass::SideEffecting
    }
    fn idempotency_key(&self, args: &str) -> Option<String> {
        Some(format!("note:{args}"))
    }
    fn execute(&self, _args: &str) -> Result<String, ToolError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok("noted".into())
    }
}

fn runtime() -> ToolRuntime {
    ToolRuntime::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler))
}

#[test]
fn r3_two_phase_commit() {
    let calls = Arc::new(AtomicUsize::new(0));
    let previews = Arc::new(AtomicUsize::new(0));

    let mut rt = runtime();
    rt.register(Box::new(BulkLedgerWrite {
        calls: calls.clone(),
        previews: previews.clone(),
    }));
    rt.register(Box::new(LowNote {
        calls: Arc::new(AtomicUsize::new(0)),
    }));

    let args = r#"{"batch":"B-100","amount":500}"#;

    // (1) Direct dispatch of a HighRisk capability is REFUSED — the agent cannot skip the preview.
    //     No side effect occurred.
    match rt.dispatch("bulk_record_write", args) {
        DispatchResult::Blocked(msg) => assert!(
            msg.contains("two-phase"),
            "HighRisk direct dispatch must be blocked with a two-phase message, got: {msg}"
        ),
        other => panic!("expected Blocked, got {other:?}"),
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "no side effect on refused dispatch"
    );

    // (2) Phase one: dry_run previews + computes the key, still NO side effect.
    let outcome = rt
        .dry_run("bulk_record_write", args, /*now*/ 0, /*ttl*/ 10)
        .expect("dry_run should succeed");
    assert!(outcome.preview.contains("would write"));
    assert_eq!(
        outcome.commit_key,
        "bulk_record_write:{\"batch\":\"B-100\",\"amount\":500}"
    );
    assert_eq!(previews.load(Ordering::SeqCst), 1);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "dry_run performs no side effect"
    );

    // (3) Phase two: commit with the exact key within TTL → executes exactly once.
    match rt.commit(
        "bulk_record_write",
        args,
        &outcome.commit_key,
        /*now*/ 1,
    ) {
        DispatchResult::Ok(r) => assert_eq!(r, "wrote {\"batch\":\"B-100\",\"amount\":500}"),
        other => panic!("expected Ok, got {other:?}"),
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // (3b) A fresh preview + commit of the SAME action dedups via the shared ledger — never a
    //      second write (exactly-once holds across the two-phase path too).
    let o2 = rt.dry_run("bulk_record_write", args, 2, 10).unwrap();
    match rt.commit("bulk_record_write", args, &o2.commit_key, 3) {
        DispatchResult::Deduped(r) => assert_eq!(r, "wrote {\"batch\":\"B-100\",\"amount\":500}"),
        other => panic!("expected Deduped, got {other:?}"),
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "commit must not double-execute"
    );

    // (4) A commit with NO matching prior dry_run is refused (fresh runtime, fresh tool).
    let calls2 = Arc::new(AtomicUsize::new(0));
    let mut rt2 = runtime();
    rt2.register(Box::new(BulkLedgerWrite {
        calls: calls2.clone(),
        previews: Arc::new(AtomicUsize::new(0)),
    }));
    // The presented key matches the args (so it passes the arg-binding check) but no dry_run was
    // ever issued for it — the commit must still be refused.
    let matching_key = format!("bulk_record_write:{args}");
    match rt2.commit("bulk_record_write", args, &matching_key, 0) {
        DispatchResult::Blocked(msg) => {
            assert!(msg.contains("no matching prior dry_run"), "got: {msg}")
        }
        other => panic!("expected Blocked (no prior dry_run), got {other:?}"),
    }
    assert_eq!(calls2.load(Ordering::SeqCst), 0);

    // (5) An EXPIRED dry_run preview is refused at commit time.
    let o3 = rt2
        .dry_run("bulk_record_write", args, /*now*/ 0, /*ttl*/ 5)
        .unwrap();
    match rt2.commit("bulk_record_write", args, &o3.commit_key, /*now*/ 100) {
        DispatchResult::Blocked(msg) => assert!(msg.contains("expired"), "got: {msg}"),
        other => panic!("expected Blocked (expired), got {other:?}"),
    }
    assert_eq!(calls2.load(Ordering::SeqCst), 0);

    // (6) A commit whose args differ from the previewed key is refused (can't preview benign, commit
    //     something else under the same token).
    let o4 = rt2.dry_run("bulk_record_write", args, 0, 10).unwrap();
    match rt2.commit(
        "bulk_record_write",
        r#"{"batch":"EVIL"}"#,
        &o4.commit_key,
        1,
    ) {
        DispatchResult::Blocked(msg) => assert!(msg.contains("do not match"), "got: {msg}"),
        other => panic!("expected Blocked (arg mismatch), got {other:?}"),
    }

    // (7) Regression: a Low-risk side-effecting tool still dispatches single-phase, unchanged.
    match rt.dispatch("note", r#"{"x":1}"#) {
        DispatchResult::Ok(r) => assert_eq!(r, "noted"),
        other => panic!("expected Ok for Low tool, got {other:?}"),
    }
}
