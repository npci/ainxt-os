// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R12 §1.6 — the OBO authorization decision (GRANTED **or** DENIED) is written to the audit sink
//! beside the tool call, on the same clean entrypoint the served daemon hot-wires
//! ([`ToolRuntime::dispatch_obo_audited`]). Design §1.6: "Every OBO decision (granted or denied) is
//! written to the Event Log beside the tool call, reconstructable for audit two years later."
//! Fail-before: `dispatch_obo` enforced the three layers but recorded nothing — the confused-deputy
//! DENIAL left no audit trail. Pass-after: every decision, including a sub-agent hop at depth>0,
//! lands in the sink with its verdict, and a denial still hard-blocks with zero execution.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use ainxt_tools::obo::{Grant, MapAbac, OboContext, OboDenial, ThreeLayerPolicy, VecOboAudit};
use ainxt_tools::{
    DispatchResult, EffectClass, InMemoryLedger, ManualReconciler, Tool, ToolError, ToolRuntime,
};
use ainxt_types::DataClass;

struct PgQuery {
    calls: Arc<AtomicUsize>,
}
impl Tool for PgQuery {
    fn name(&self) -> &str {
        "connector.postgres.query"
    }
    fn effect_class(&self) -> EffectClass {
        EffectClass::Pure
    }
    fn resource(&self, args: &str) -> Option<String> {
        Some(args.trim().to_string())
    }
    fn execute(&self, args: &str) -> Result<String, ToolError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(format!("rows-from-{}", args.trim()))
    }
}

fn runtime(calls: Arc<AtomicUsize>) -> ToolRuntime {
    let mut rt = ToolRuntime::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler));
    rt.register(Box::new(PgQuery { calls }));
    rt
}

fn abac() -> MapAbac {
    MapAbac::new()
        .with("settlement_batches", DataClass::Confidential)
        .with("ledger_accounts", DataClass::RegulatedPayment)
}

#[test]
fn granted_and_denied_obo_decisions_are_both_audited() {
    let calls = Arc::new(AtomicUsize::new(0));
    let rt = runtime(Arc::clone(&calls));
    let policy = ThreeLayerPolicy::new(abac());
    let audit = VecOboAudit::new();

    let ctx = OboContext::new(
        "alice",
        vec![Grant::new(
            "connector.postgres.query",
            "settlement_batches",
            "read",
        )],
        ["connector.postgres.query".to_string()],
        DataClass::Confidential,
    );

    // Granted call: dispatched AND recorded.
    let ok = rt.dispatch_obo_audited(
        &ctx,
        &policy,
        &audit,
        "connector.postgres.query",
        "settlement_batches",
        "read",
    );
    assert!(matches!(ok, DispatchResult::Ok(_)));

    // Denied call (out-of-scope resource): hard-blocked, never executed, but STILL recorded.
    let denied = rt.dispatch_obo_audited(
        &ctx,
        &policy,
        &audit,
        "connector.postgres.query",
        "ledger_accounts",
        "read",
    );
    assert!(matches!(denied, DispatchResult::Blocked(_)));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "only the granted call executed"
    );

    // Both decisions are in the audit trail — this is the fail-before/pass-after core.
    let recs = audit.decisions();
    assert_eq!(recs.len(), 2, "granted AND denied must both be audited");

    let g = &recs[0];
    assert!(g.granted());
    assert_eq!(g.user_id, "alice");
    assert_eq!(g.resource.as_deref(), Some("settlement_batches"));
    assert_eq!(g.depth, 0);

    let d = &recs[1];
    assert!(
        !d.granted(),
        "the denied decision must be recorded as a denial"
    );
    assert_eq!(d.resource.as_deref(), Some("ledger_accounts"));
    assert!(matches!(d.verdict, Err(OboDenial::NoGrant { .. })));
}

#[test]
fn sub_agent_denial_is_audited_at_delegation_depth() {
    let calls = Arc::new(AtomicUsize::new(0));
    let rt = runtime(Arc::clone(&calls));
    let policy = ThreeLayerPolicy::new(abac());
    let audit = VecOboAudit::new();

    let parent = OboContext::new(
        "alice",
        vec![Grant::new(
            "connector.postgres.query",
            "settlement_batches",
            "read",
        )],
        ["connector.postgres.query".to_string()],
        DataClass::Confidential,
    );
    // A sub-agent inherits the parent's context (depth+1) but cannot exceed it.
    let sub = parent.inherit();
    assert_eq!(sub.depth, 1);

    // The sub-agent reaches beyond the parent's grant → denied, and the DENIED hop is audited at
    // depth 1 so a reviewer can see exactly which delegation tried to over-reach.
    let denied = rt.dispatch_obo_audited(
        &sub,
        &policy,
        &audit,
        "connector.postgres.query",
        "ledger_accounts",
        "read",
    );
    assert!(matches!(denied, DispatchResult::Blocked(_)));
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let recs = audit.decisions();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].depth, 1, "the sub-agent hop is recorded at depth 1");
    assert!(!recs[0].granted());
}

#[test]
fn plain_dispatch_obo_still_works_unaudited() {
    // The un-audited entrypoint keeps its exact prior behavior (no sink, same enforcement).
    let calls = Arc::new(AtomicUsize::new(0));
    let rt = runtime(Arc::clone(&calls));
    let policy = ThreeLayerPolicy::new(abac());
    let ctx = OboContext::new(
        "bob",
        vec![],
        ["connector.postgres.query".to_string()],
        DataClass::RegulatedPayment,
    );
    // No grant → confused-deputy denial, ambient credential never substituted.
    let res = rt.dispatch_obo(
        &ctx,
        &policy,
        "connector.postgres.query",
        "ledger_accounts",
        "read",
    );
    assert!(matches!(res, DispatchResult::Blocked(_)));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
