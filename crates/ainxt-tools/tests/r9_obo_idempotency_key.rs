// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R9 — the exactly-once idempotency key must be `f(user_id, capability, resource_key,
//! semantic-args)` (§1.2). Before the fix the key omitted the acting principal, so two DIFFERENT
//! users issuing the byte-identical side-effecting call collided on ONE ledger row: the second
//! user's call was silently `Deduped` against the first user's committed result and never executed
//! (a cross-user leak / dropped side effect). This proves (a) two different users → two distinct
//! rows, both execute; (b) the SAME user's retry still dedups to one row.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use ainxt_tools::{
    DispatchResult, EffectClass, InMemoryLedger, ManualReconciler, Tool, ToolError, ToolRuntime,
};

/// A side-effecting settlement tool. Its idempotency key is purely the semantic args — the
/// per-user separation is the *runtime's* job (§1.2), NOT the tool's, which is exactly what this
/// test pins: an unchanged tool + identical args, differing only by acting principal.
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
        Some(args.to_string()) // purely semantic — no user_id here; the runtime folds it in
    }
    fn execute(&self, args: &str) -> Result<String, ToolError> {
        self.counter.fetch_add(1, Ordering::SeqCst);
        Ok(format!("settled:{args}"))
    }
}

fn runtime(counter: &Arc<AtomicU32>) -> ToolRuntime {
    let mut rt = ToolRuntime::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler));
    rt.register(Box::new(SettleTool {
        counter: counter.clone(),
    }));
    rt
}

/// Two different users, identical call → two DISTINCT ledger rows; BOTH execute. No cross-user
/// dedup. (Pre-fix this failed: user B's call returned `Deduped` and `counter == 1`.)
#[test]
fn r9_obo_idempotency_key_two_users_no_cross_dedup() {
    let counter = Arc::new(AtomicU32::new(0));
    let rt = runtime(&counter);

    let args = r#"{"account":"A-100","amount":250}"#;

    let alice = rt.dispatch_for("user:alice", "settle", args);
    let bob = rt.dispatch_for("user:bob", "settle", args);

    // Both are first-time executions — neither is deduped against the other.
    assert_eq!(
        alice,
        DispatchResult::Ok(format!("settled:{args}")),
        "alice's call must execute"
    );
    assert_eq!(
        bob,
        DispatchResult::Ok(format!("settled:{args}")),
        "bob's identical call must ALSO execute — it is a distinct principal, distinct ledger row"
    );
    assert_eq!(
        counter.load(Ordering::SeqCst),
        2,
        "two different users issuing the same call must produce two side effects (two ledger rows)"
    );
}

/// The SAME user retrying the SAME call → deduped to ONE ledger row, executed exactly once
/// (lost-ack safety preserved — the user_id scoping must not break within-user dedup).
#[test]
fn r9_obo_idempotency_key_same_user_retry_dedups() {
    let counter = Arc::new(AtomicU32::new(0));
    let rt = runtime(&counter);

    let args = r#"{"account":"A-100","amount":250}"#;

    let first = rt.dispatch_for("user:alice", "settle", args);
    let retry = rt.dispatch_for("user:alice", "settle", args);

    assert_eq!(first, DispatchResult::Ok(format!("settled:{args}")));
    assert_eq!(
        retry,
        DispatchResult::Deduped(format!("settled:{args}")),
        "same user + same call must dedup, not re-execute"
    );
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "the same user's retry must run the settlement EXACTLY ONCE"
    );
}

/// Interleaving proof: alice → bob → alice(retry) → bob(retry). Exactly two executions total; each
/// user's retry dedups against ITS OWN row, never the other's.
#[test]
fn r9_obo_idempotency_key_interleaved_users_isolated_rows() {
    let counter = Arc::new(AtomicU32::new(0));
    let rt = runtime(&counter);
    let args = r#"{"txn":"NEFT-9931"}"#;

    assert!(matches!(
        rt.dispatch_for("alice", "settle", args),
        DispatchResult::Ok(_)
    ));
    assert!(matches!(
        rt.dispatch_for("bob", "settle", args),
        DispatchResult::Ok(_)
    ));
    assert!(matches!(
        rt.dispatch_for("alice", "settle", args),
        DispatchResult::Deduped(_)
    ));
    assert!(matches!(
        rt.dispatch_for("bob", "settle", args),
        DispatchResult::Deduped(_)
    ));

    assert_eq!(
        counter.load(Ordering::SeqCst),
        2,
        "two principals, one call each (+ retries) => exactly two side effects"
    );
}
