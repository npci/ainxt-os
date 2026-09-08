// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R11 §1.6 — on-behalf-of authorization: three-layer policy (declared grant ∧ issued scope ∧
//! resource ABAC) wired onto the live tool dispatch, with sub-agent delegation that can only narrow.
//! Scenarios 4 (confused-deputy denial), 5 (scoped grant boundary), 6 (sub-agent inheritance).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use ainxt_tools::obo::{Grant, MapAbac, OboContext, ThreeLayerPolicy};
use ainxt_tools::{
    DispatchResult, EffectClass, InMemoryLedger, ManualReconciler, Tool, ToolError, ToolRuntime,
};
use ainxt_types::DataClass;

/// A read-only connector query tool: its `resource` is the table named in the (bare) args, so the OBO
/// policy authorizes against exactly the resource dispatch would touch. Pure (no ledger).
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
        Some(args.trim().to_string()) // args == the table name
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
fn scenario4_confused_deputy_is_denied_and_ambient_credential_never_substituted() {
    let calls = Arc::new(AtomicUsize::new(0));
    let rt = runtime(Arc::clone(&calls));
    let policy = ThreeLayerPolicy::new(abac());

    // The user has NO grant for the query capability (the agent itself holds a broad service cred,
    // but that is never substituted).
    let ctx = OboContext::new(
        "alice",
        vec![],                                   // no declared grant
        ["connector.postgres.query".to_string()], // even a full issued scope must not save it
        DataClass::RegulatedPayment,
    );
    let res = rt.dispatch_obo(
        &ctx,
        &policy,
        "connector.postgres.query",
        "ledger_accounts",
        "read",
    );
    assert!(
        matches!(res, DispatchResult::Blocked(_)),
        "must be a hard denial, got {res:?}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "a denied call must never execute"
    );
}

#[test]
fn scenario5_scoped_grant_allows_only_the_named_resource() {
    let calls = Arc::new(AtomicUsize::new(0));
    let rt = runtime(Arc::clone(&calls));
    let policy = ThreeLayerPolicy::new(abac());

    // Granted read-only on settlement_batches ONLY; clearance covers Confidential.
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

    // In-scope resource: allowed and executed.
    let ok = rt.dispatch_obo(
        &ctx,
        &policy,
        "connector.postgres.query",
        "settlement_batches",
        "read",
    );
    assert!(
        matches!(ok, DispatchResult::Ok(_)),
        "granted resource must succeed, got {ok:?}"
    );
    // Out-of-scope resource in the same turn: denied (grant is resource-scoped, not blanket).
    let denied = rt.dispatch_obo(
        &ctx,
        &policy,
        "connector.postgres.query",
        "ledger_accounts",
        "read",
    );
    assert!(matches!(denied, DispatchResult::Blocked(_)));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "only the in-scope call executed"
    );
}

#[test]
fn layer2_issued_scope_and_layer3_clearance_each_deny_independently() {
    let calls = Arc::new(AtomicUsize::new(0));
    let rt = runtime(Arc::clone(&calls));
    let policy = ThreeLayerPolicy::new(abac());

    // Layer 2: has the grant but the user's OWN credential does not cover the capability.
    let no_issued = OboContext::new(
        "alice",
        vec![Grant::new("connector.postgres.query", "*", "read")],
        Vec::<String>::new(), // empty issued scope
        DataClass::RegulatedPayment,
    );
    assert!(matches!(
        rt.dispatch_obo(
            &no_issued,
            &policy,
            "connector.postgres.query",
            "settlement_batches",
            "read"
        ),
        DispatchResult::Blocked(_)
    ));

    // Layer 3: grant + issued scope OK, but the resource's class exceeds the user's clearance.
    let low_clearance = OboContext::new(
        "alice",
        vec![Grant::new("connector.postgres.query", "*", "read")],
        ["connector.postgres.query".to_string()],
        DataClass::Internal, // below ledger_accounts' RegulatedPayment
    );
    let res = rt.dispatch_obo(
        &low_clearance,
        &policy,
        "connector.postgres.query",
        "ledger_accounts",
        "read",
    );
    assert!(matches!(res, DispatchResult::Blocked(_)));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn scenario6_sub_agent_cannot_exceed_the_parents_grant() {
    let calls = Arc::new(AtomicUsize::new(0));
    let rt = runtime(Arc::clone(&calls));
    let policy = ThreeLayerPolicy::new(abac());

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

    // A sub-agent inherits the SAME context: still bounded to settlement_batches.
    let sub = parent.inherit();
    assert_eq!(sub.depth, 1);
    assert!(matches!(
        rt.dispatch_obo(
            &sub,
            &policy,
            "connector.postgres.query",
            "settlement_batches",
            "read"
        ),
        DispatchResult::Ok(_)
    ));
    assert!(matches!(
        rt.dispatch_obo(
            &sub,
            &policy,
            "connector.postgres.query",
            "ledger_accounts",
            "read"
        ),
        DispatchResult::Blocked(_)
    ));

    // A narrowing delegation that drops the capability entirely → the child can do NOTHING.
    let narrowed = parent.delegate(&[], DataClass::Confidential);
    assert!(narrowed.grants.is_empty());
    assert!(matches!(
        rt.dispatch_obo(
            &narrowed,
            &policy,
            "connector.postgres.query",
            "settlement_batches",
            "read"
        ),
        DispatchResult::Blocked(_)
    ));

    // Delegation clamps clearance DOWN even when the child "requests" more.
    let clamped = parent.delegate(&["connector.postgres.query"], DataClass::RegulatedPayment);
    assert_eq!(
        clamped.clearance,
        DataClass::Confidential,
        "clearance clamps to the parent, never up"
    );
}
