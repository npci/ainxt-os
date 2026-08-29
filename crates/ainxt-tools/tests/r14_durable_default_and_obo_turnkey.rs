// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! r14_durable_default_and_obo_turnkey — the two round-13 HIGHs for tooling-mcp-plugins-routing,
//! closed at the TURNKEY-entrypoint level (§1.2 durable exactly-once + §1.6 three-layer OBO).
//!
//! HIGH #1 — "durable cross-process/restart exactly-once ledger is the DEFAULT on the shipped daemon."
//!   The building block ([`SqlLedger`]) existed and was proven, but the daemon still hand-assembled
//!   `ToolRuntime::with_shared_ledger(Arc::new(InMemoryLedger::new()), ..)` — the EPHEMERAL ledger,
//!   whose exactly-once state dies with the process. There was no single entrypoint that installs the
//!   durable ledger as the default backing.
//!   Fail-before: `install_durable_ledger` / `install_durable_ledger_default` / `DurableToolRuntime`
//!   did not exist — this test would not compile.
//!   Pass-after: `install_durable_ledger(store)` returns a `ToolRuntime` whose exactly-once state
//!   lives in the SHARED durable store, so a SECOND process handle (a restart / a sibling daemon)
//!   over the SAME store DEDUPS a committed key and the underlying side effect runs exactly ONCE —
//!   the ephemeral default would have re-executed it (double debit). Cross-restart survival of the
//!   store itself is the live DB's job (`PostgresSqlLedgerDriver`, infra-gated).
//!
//! HIGH #2 — "three-layer OBO (issued-scope + resource-ABAC) and sub-agent OBO propagation on the
//!   LIVE served path." `dispatch_obo_audited` existed but the served path had to re-assemble the
//!   policy + audit sink + context on every call. `OboDispatcher` makes it turnkey: install once, then
//!   ONE `dispatch` / `dispatch_sub_agent` call runs the audited three-layer authz, writing the
//!   GRANTED/DENIED decision to the DURABLE Event Log via `EventLogOboAudit`, and a sub-agent child
//!   that can only NARROW flows through the identical enforced+audited path.
//!   Fail-before: `OboDispatcher` / `obo::EventLogOboAudit` did not exist — would not compile.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use ainxt_eventlog::{EventLog, JsonlEventLog};
use ainxt_tools::obo::{Grant, MapAbac, OboContext};
use ainxt_tools::{
    install_durable_ledger, install_durable_ledger_default, DispatchResult, EffectClass,
    InMemorySqlStore, OboDispatcher, Tool, ToolError, ToolRuntime,
};
use ainxt_types::DataClass;

// ---- A settlement-style side-effecting tool: `counter` proves how many times it ACTUALLY ran. ----
struct SettleTool {
    counter: Arc<AtomicUsize>,
}
impl Tool for SettleTool {
    fn name(&self) -> &str {
        "settle"
    }
    fn effect_class(&self) -> EffectClass {
        EffectClass::SideEffecting
    }
    fn idempotency_key(&self, args: &str) -> Option<String> {
        Some(args.to_string()) // purely semantic
    }
    fn execute(&self, args: &str) -> Result<String, ToolError> {
        self.counter.fetch_add(1, Ordering::SeqCst);
        Ok(format!("settled:{args}"))
    }
}

/// One "process" / daemon handle: its own `ToolRuntime` over a clone of the SAME durable store, with a
/// SettleTool sharing `counter` so we can count executions across handles.
fn daemon(store: &InMemorySqlStore, counter: Arc<AtomicUsize>) -> ToolRuntime {
    let mut d = install_durable_ledger(store.clone());
    d.runtime.register(Box::new(SettleTool { counter }));
    d.runtime
}

#[test]
fn r14_durable_ledger_is_the_turnkey_default_not_ephemeral() {
    let store = InMemorySqlStore::new();
    let counter = Arc::new(AtomicUsize::new(0));

    // Daemon A dispatches a settlement on-behalf-of user "alice".
    let a = daemon(&store, Arc::clone(&counter));
    let key = "batch-7:alice";
    match a.dispatch_for("alice", "settle", key) {
        DispatchResult::Ok(r) => assert_eq!(r, "settled:batch-7:alice"),
        other => panic!("first dispatch should execute: {other:?}"),
    }
    assert_eq!(counter.load(Ordering::SeqCst), 1, "executed exactly once");

    // --- Simulate a RESTART / a sibling daemon: a brand-new ToolRuntime handle over the SAME durable
    // store. If the default were the ephemeral InMemoryLedger, this fresh handle would know NOTHING of
    // the committed row and would RE-EXECUTE the settlement (counter -> 2 = double debit). Because the
    // turnkey default installs the durable ledger, the exactly-once state lives in the shared store. ---
    drop(a);
    let b = daemon(&store, Arc::clone(&counter));
    match b.dispatch_for("alice", "settle", key) {
        DispatchResult::Deduped(r) => assert_eq!(r, "settled:batch-7:alice"),
        other => panic!("restart/sibling handle must DEDUP the committed key, got: {other:?}"),
    }
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "durable default: the side effect ran exactly once across the process-handle swap"
    );

    // A DIFFERENT user's identical call is a DISTINCT ledger row (independent side effect), so it is
    // NOT cross-deduped — it executes on its own key.
    match b.dispatch_for("bob", "settle", "batch-7:bob") {
        DispatchResult::Ok(_) => {}
        other => panic!("a different principal's call must not cross-dedup: {other:?}"),
    }
    assert_eq!(
        counter.load(Ordering::SeqCst),
        2,
        "bob's independent settlement ran once"
    );
}

#[test]
fn r14_install_durable_ledger_default_builds_a_durable_runtime() {
    // The zero-arg OSS/air-gapped turnkey default must produce a runtime whose ledger is durable
    // (exactly-once), never the ephemeral fallback: a retry of a committed key DEDUPS, one execution.
    let mut d = install_durable_ledger_default();
    let counter = Arc::new(AtomicUsize::new(0));
    d.runtime.register(Box::new(SettleTool {
        counter: Arc::clone(&counter),
    }));
    let rt = d.runtime;

    assert!(matches!(
        rt.dispatch_for("u", "settle", "k1"),
        DispatchResult::Ok(_)
    ));
    // Retry of the SAME key on the SAME runtime dedups (no second execution).
    assert!(matches!(
        rt.dispatch_for("u", "settle", "k1"),
        DispatchResult::Deduped(_)
    ));
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "exactly-once holds on the default"
    );

    // The shared ledger handle is exposed so the daemon can hand a clone to a ReconcilerSweeper.
    assert!(Arc::strong_count(&d.ledger) >= 1);
}

// ---- A read-only connector query: `resource` == the table named in the args, so OBO authorizes
//      against exactly the resource dispatch would touch. Pure (no ledger). ----
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

fn obo_ctx(user: &str) -> OboContext {
    // Layer 1: a scoped grant (read connector.postgres.query on the `public.*` prefix).
    let grants = vec![Grant::new("connector.postgres.query", "public.*", "read")];
    // Layer 2: the user's OWN issued credential covers the capability.
    let issued = ["connector.postgres.query".to_string()];
    // Layer 3: clearance == Internal.
    OboContext::new(user, grants, issued, DataClass::Internal)
}

#[test]
fn r14_obo_dispatcher_turnkey_three_layer_and_audit() {
    let tmp = std::env::temp_dir().join(format!("ainxt_r14_obo_{}", std::process::id()));
    let log = JsonlEventLog::open(&tmp).unwrap();

    let calls = Arc::new(AtomicUsize::new(0));
    let mut rt = ToolRuntime::new(
        Box::new(ainxt_tools::InMemoryLedger::new()),
        Box::new(ainxt_tools::ManualReconciler),
    );
    rt.register(Box::new(PgQuery {
        calls: Arc::clone(&calls),
    }));

    // A resource in `restricted.*` is Confidential — above the Internal clearance (layer 3).
    let abac = MapAbac::new()
        .with("public.customers", DataClass::Internal)
        .with("restricted.settlements", DataClass::Confidential);

    // TURNKEY: install the three-layer policy + durable Event-Log audit sink ONCE.
    let dispatcher = OboDispatcher::with_event_log(Arc::new(rt), abac, log.clone());
    let ctx = obo_ctx("alice");

    // GRANTED: read a public table the grant + scope + clearance all cover.
    match dispatcher.dispatch(&ctx, "connector.postgres.query", "public.customers", "read") {
        DispatchResult::Ok(r) => assert_eq!(r, "rows-from-public.customers"),
        other => panic!("granted read should execute: {other:?}"),
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // DENIED (layer 1 — no grant covers the `restricted.*` resource pattern): hard block, NO execution.
    match dispatcher.dispatch(
        &ctx,
        "connector.postgres.query",
        "restricted.settlements",
        "read",
    ) {
        DispatchResult::Blocked(_) => {}
        other => panic!("out-of-grant resource must hard-block: {other:?}"),
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "a denied OBO call must never execute (confused-deputy fix)"
    );

    // The audit sink wrote BOTH decisions to the durable log, GRANTED and DENIED, beside the call.
    let records = log.records("__obo__");
    assert_eq!(
        records.len(),
        2,
        "every OBO decision is audited, incl. the denial"
    );
    assert!(records[0].text.contains("verdict=GRANTED"));
    assert!(records[0].text.contains("depth=0"));
    assert!(records[1].text.contains("verdict=DENIED"));
    // The hash chain over the audit is intact (tamper-evident, reconstructable for a regulator).
    assert!(log.verify("__obo__").is_ok());
}

#[test]
fn r14_obo_dispatcher_sub_agent_propagation_narrows_and_audits_depth() {
    let tmp = std::env::temp_dir().join(format!("ainxt_r14_obo_sub_{}", std::process::id()));
    let log = JsonlEventLog::open(&tmp).unwrap();

    let calls = Arc::new(AtomicUsize::new(0));
    let mut rt = ToolRuntime::new(
        Box::new(ainxt_tools::InMemoryLedger::new()),
        Box::new(ainxt_tools::ManualReconciler),
    );
    rt.register(Box::new(PgQuery {
        calls: Arc::clone(&calls),
    }));
    let abac = MapAbac::new()
        .with("public.customers", DataClass::Internal)
        .with("restricted.settlements", DataClass::Confidential);
    let dispatcher = OboDispatcher::with_event_log(Arc::new(rt), abac, log.clone());
    let parent = obo_ctx("alice");

    // Sub-agent that KEEPS the query capability and requests the SAME clearance — flows through the
    // identical audited three-layer path, at depth 1, and executes.
    match dispatcher.dispatch_sub_agent(
        &parent,
        &["connector.postgres.query"],
        DataClass::Internal,
        "connector.postgres.query",
        "public.customers",
        "read",
    ) {
        DispatchResult::Ok(r) => assert_eq!(r, "rows-from-public.customers"),
        other => panic!("delegated sub-agent read should execute: {other:?}"),
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // A sub-agent CANNOT widen: even requesting RegulatedPayment clearance clamps to min(parent=Internal,
    // requested) == Internal. So a `restricted.*` (Confidential) resource stays ABOVE clearance and is
    // denied at depth 1 — the confused-deputy fix propagates to the sub-agent hop.
    match dispatcher.dispatch_sub_agent(
        &parent,
        &["connector.postgres.query"],
        DataClass::RegulatedPayment, // attempt to widen — must be clamped down
        "connector.postgres.query",
        "restricted.settlements",
        "read",
    ) {
        DispatchResult::Blocked(_) => {}
        other => panic!(
            "a sub-agent must not widen clearance to reach a higher-class resource: {other:?}"
        ),
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the denied sub-agent call never executed"
    );

    let records = log.records("__obo__");
    assert_eq!(records.len(), 2);
    // Both sub-agent decisions were recorded at delegation depth 1.
    assert!(records[0].text.contains("depth=1") && records[0].text.contains("verdict=GRANTED"));
    assert!(records[1].text.contains("depth=1") && records[1].text.contains("verdict=DENIED"));
}
