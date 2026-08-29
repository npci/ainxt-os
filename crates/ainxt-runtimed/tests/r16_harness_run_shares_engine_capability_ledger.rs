// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R16 (§0/§1.2, CRITICAL) — closes: "served harness `/run` mounts a SECOND capability registry over a
//! DISJOINT exactly-once ledger" from the served chat/engine tool-dispatch path. On a payments platform
//! this is a double-execution path: the SAME caller-supplied idempotency key ("retry settlement
//! initiation") could commit once via `/v1/chat` and AGAIN via `/v1/harness/{id}/run`, because each
//! surface dispatched through its OWN, independently-built `ToolRuntime` (= Capability registry) over
//! its OWN, independently-built exactly-once ledger.
//!
//! THE FIX (this round):
//! * `ainxt_runtime::Engine::with_shared_tools` installs a PRE-BUILT `Arc<ToolRuntime>` instead of
//!   taking ownership of a fresh one (the served engine's own tool loop dispatches through it exactly
//!   as before — `with_tools` is unchanged and still wraps a fresh one for single-dispatcher callers).
//! * `build_engine_ext` / `build_chat_engine_with_authz` now return that shared handle, threaded out
//!   through `Assembled::capability_tools`.
//! * `assemble_full` hands the SAME handle to `mounts::build_harness_mounts`, which now dispatches the
//!   harness `/run` bridge (`ainxt_server::ToolPathInvoker`) over the IDENTICAL registry + ledger the
//!   served engine's own tool loop uses — never a second, disjoint instance (falling back to its own
//!   fresh registry only on the AiNxt-OS workforce surface, which has no real Engine to share with).
//! * `ToolPathInvoker` additionally now dispatches via the audited `dispatch_obo_audited` (folding the
//!   caller's `user_id` into the idempotency key, exactly as the engine's own tool loop does) instead of
//!   the legacy unattributed `ToolRuntime::dispatch` — without this, even a SHARED ledger would compute
//!   a DIFFERENT (unscoped) key for what the caller intends as the identical retried action, and the
//!   dispatch would run with no on-behalf-of authorization at all.
//!
//! Both tests below drive the SAME semantic idempotency key ("batch-42") through (1) the served
//! `Engine`'s real tool-dispatch loop (the "chat path" — a scripted `Provider` requests the tool exactly
//! as a model would) and (2) the harness `/run` bridge (`ToolPathInvoker`, the real dispatch code mounted
//! at `/v1/harness/{id}/run`), and assert the underlying side effect (`SettlementInitiate::applied`, a
//! counter shared across both dispatch attempts) increments EXACTLY ONCE.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use ainxt_admission::{HarnessStep, StepKind};
use ainxt_client::CapabilityInvoker;
use ainxt_protocol::{Event, Request};
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_runtime::{engine_with_defaults, Engine};
use ainxt_runtimed::mounts;
use ainxt_server::ToolPathInvoker;
use ainxt_tools::obo::{MapAbac, OboDecisionSink, OboPolicy, ThreeLayerPolicy, VecOboAudit};
use ainxt_tools::{DispatchResult, EffectClass, Tool, ToolError, ToolRuntime};
use ainxt_types::{DataClass, Principal};

/// The exact scenario the CRITICAL describes: "retry settlement initiation" becoming a double payment.
/// `applied` proves how many times the underlying settlement action actually ran end-to-end — the
/// number that must never be 2 for one caller's retried idempotency key. `EffectClass::SideEffecting` +
/// a purely-semantic `idempotency_key` (derived only from `args`, §1.2) is what routes every dispatch
/// through the exactly-once ledger path (`ToolRuntime::execute_dispatch`), exactly like a real
/// settlement-adjacent capability a deployment would register into the unified registry.
struct SettlementInitiate {
    applied: Arc<AtomicU32>,
}
impl Tool for SettlementInitiate {
    fn name(&self) -> &str {
        "settlement.initiate"
    }
    fn effect_class(&self) -> EffectClass {
        EffectClass::SideEffecting
    }
    fn idempotency_key(&self, args: &str) -> Option<String> {
        Some(args.to_string())
    }
    fn execute(&self, args: &str) -> Result<String, ToolError> {
        self.applied.fetch_add(1, Ordering::SeqCst);
        Ok(format!("settled:{args}"))
    }
}

/// Round 1: the model requests `settlement.initiate` with the semantic batch id. Round 2 (the tool
/// result is now folded into the prompt): answer. Mirrors the exact pattern
/// `ainxt-runtimed/tests/r14_served_obo_dispatch.rs::ToolThenAnswer` uses to drive a real tool call
/// through the served engine's turn loop.
struct RetrySettlementProvider;
impl Provider for RetrySettlementProvider {
    fn id(&self) -> &str {
        "retryprov"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, prompt: &str) -> tokio::sync::mpsc::Receiver<Event> {
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        let done = prompt.contains("[tool ");
        tokio::spawn(async move {
            if done {
                let _ = tx.send(Event::TextDelta("settled".to_string())).await;
            } else {
                let _ = tx
                    .send(Event::ToolCallStart {
                        id: "t0".to_string(),
                        name: "settlement.initiate".to_string(),
                        args: "batch-42".to_string(),
                    })
                    .await;
            }
            let _ = tx.send(Event::Done).await;
        });
        rx
    }
}

/// The caller's principal — used IDENTICALLY for the chat-path turn and the harness-path invoke: same
/// human, same retried batch, two different surfaces. Holds both the OBO capability
/// (`settlement.initiate`) and the engine's pre-dispatch tool cap (`tool.settlement.initiate`), exactly
/// the combination `r14_served_obo_dispatch.rs`'s cleared-caller test uses.
fn caller() -> Principal {
    Principal::user(
        "alice",
        &[
            "chat.send",
            "settlement.initiate",
            "tool.settlement.initiate",
        ],
    )
    .with_clearance(DataClass::Confidential)
}

/// A fresh three-layer OBO policy + audit sink pair (the offline reference config every composition
/// site in this crate uses: `ThreeLayerPolicy::new(MapAbac::new())` + `VecOboAudit`).
fn obo_pair() -> (Box<dyn OboPolicy>, Arc<dyn OboDecisionSink>) {
    (
        Box::new(ThreeLayerPolicy::new(MapAbac::new())),
        Arc::new(VecOboAudit::new()),
    )
}

/// Drive `settlement.initiate` once through a REAL served-style `Engine`'s tool-dispatch loop (the
/// "chat path"): `Engine::with_shared_tools` installs `tools`, a scripted provider requests the tool
/// exactly as a model would, and the engine's own OBO-audited dispatch (R14) executes it.
async fn dispatch_via_chat_path(tools: Arc<ToolRuntime>) {
    let mut router = ModelRouter::new();
    router.register(Box::new(RetrySettlementProvider));
    let (obo_policy, obo_sink) = obo_pair();
    let engine: Engine = engine_with_defaults(router)
        .with_shared_tools(tools)
        .with_obo(obo_policy, obo_sink);
    let out = engine
        .run_turn_collect(
            &caller(),
            &Request::chat(
                "s",
                "t",
                "retry settlement batch-42",
                DataClass::Confidential,
            ),
        )
        .await
        .expect("chat-path turn must complete");
    assert!(
        out.events.iter().any(
            |e| matches!(e, Event::ToolResult { output, .. } if output.contains("settled:batch-42"))
        ),
        "the chat-path turn must have actually dispatched settlement.initiate: {:?}",
        out.events
    );
}

/// FAIL-BEFORE (needs no revert to demonstrate — see the module doc): reproduces the EXACT pre-fix
/// topology. `ainxt_runtimed::build_unified_capability_registry_shared` is the SAME function
/// `build_engine_ext` calls for the served engine's registry, and is exactly what pre-fix
/// `mounts::build_harness_mounts` called a SECOND, independent time (via its own
/// `build_unified_capability_registry(report) == build_unified_capability_registry_shared(report).0`) —
/// each call installs a fresh `InMemorySqlStore`-backed ledger. Calling it twice here and registering
/// the SAME side-effecting capability into EACH stands in for exactly what happens today for every
/// NATIVE capability that function seeds (e.g. `query_ledger`): pre-fix, a side-effecting native/
/// deployment capability really WOULD be present, independently, in both the engine's registry and the
/// harness bridge's registry. Dispatching the SAME idempotency key ("batch-42") for the SAME user
/// through each independent ledger — the engine's via a bare `dispatch_for` (its dedup-key derivation is
/// identical to `dispatch_obo_audited`'s), the harness bridge's via the REAL `ToolPathInvoker` dispatch
/// code — commits TWICE.
#[tokio::test(flavor = "multi_thread")]
async fn r16_disjoint_registry_double_executes_same_key() {
    let applied = Arc::new(AtomicU32::new(0));
    let mut report = Vec::new();

    // Stand-in for `build_engine_ext`'s call building the served engine's OWN registry.
    let (mut engine_tools, _engine_ledger, _engine_reconciler) =
        ainxt_runtimed::build_unified_capability_registry_shared(&mut report);
    engine_tools.register(Box::new(SettlementInitiate {
        applied: applied.clone(),
    }));
    let engine_tools = Arc::new(engine_tools);

    // Stand-in for pre-fix `mounts::build_harness_mounts`'s OWN, INDEPENDENT call — a disjoint
    // registry over a disjoint ledger, registering the identical capability.
    let (mut harness_tools, _harness_ledger, _harness_reconciler) =
        ainxt_runtimed::build_unified_capability_registry_shared(&mut report);
    harness_tools.register(Box::new(SettlementInitiate {
        applied: applied.clone(),
    }));
    let harness_tools = Arc::new(harness_tools);
    let (obo_policy, obo_sink) = obo_pair();
    let invoker = ToolPathInvoker::new(harness_tools, Arc::from(obo_policy), obo_sink);

    // Chat path: dispatch #1 — folds `user_id` into the key exactly as `dispatch_obo_audited` does.
    let r1 = engine_tools.dispatch_for("alice", "settlement.initiate", "batch-42");
    assert!(
        matches!(r1, DispatchResult::Ok(_)),
        "first dispatch (chat path) must execute: {r1:?}"
    );
    assert_eq!(applied.load(Ordering::SeqCst), 1);

    // Harness path: the SAME idempotency key, the SAME user, via the REAL `ToolPathInvoker` dispatch
    // code — but over the INDEPENDENT (disjoint) registry + ledger.
    let step = HarnessStep {
        id: "s1".into(),
        kind: StepKind::Tool,
        capability: "settlement.initiate".into(),
        estimated_tokens: 1,
        input: Some("batch-42".into()),
    };
    let harness_result = invoker
        .invoke(&step, &caller(), DataClass::Confidential)
        .await;
    assert!(
        harness_result.is_ok(),
        "the capability IS registered on this (disjoint) registry, so the harness dispatch itself must \
         succeed: {harness_result:?}"
    );

    // THE BUG: two independent ledgers each believe this is the first time they have seen the key — the
    // settlement runs TWICE for what the caller intends as one retried action. This is the exact failure
    // the R16 CRITICAL closes ("the same idempotency key can be applied TWICE, once through each
    // ledger").
    assert_eq!(
        applied.load(Ordering::SeqCst),
        2,
        "double-execution: the SAME idempotency key committed once on EACH of two disjoint ledgers"
    );
}

/// PASS-AFTER: exercises the ACTUAL shipped, fixed `mounts::build_harness_mounts` directly. Builds ONE
/// unified registry (the exact function `build_engine_ext` uses), registers the SAME side-effecting
/// capability into it ONCE, installs it on a real `Engine` via `with_shared_tools` (the chat path), and
/// hands the SAME `Arc<ToolRuntime>` to the REAL `mounts::build_harness_mounts` (the harness path).
/// Driving the SAME idempotency key through both applies the underlying settlement EXACTLY ONCE.
///
/// FAIL-BEFORE was captured by temporarily reverting `mounts::build_harness_mounts`'s body to IGNORE its
/// `served_tools` parameter and unconditionally rebuild via
/// `Arc::new(crate::build_unified_capability_registry(report))` — the literal pre-fix behavior (the
/// function took no `served_tools` parameter at all before this round). See the sibling test
/// `r16_disjoint_registry_double_executes_same_key` for the numeric double-execution failure mode this
/// produces when the SAME capability is independently registered into both sides (exactly what happens
/// today for every NATIVE capability `build_unified_capability_registry_shared_over` seeds); THIS test's
/// synthetic `SettlementInitiate` is registered only into the shared handle, so under that same revert
/// the freshly-rebuilt harness registry does not contain it at all and the harness dispatch below fails
/// closed instead — see this file's accompanying report for the exact captured panic message.
#[tokio::test(flavor = "multi_thread")]
async fn r16_harness_run_shares_engine_capability_ledger() {
    let applied = Arc::new(AtomicU32::new(0));
    let mut report = Vec::new();

    let (mut tools, _ledger, _reconciler) =
        ainxt_runtimed::build_unified_capability_registry_shared(&mut report);
    tools.register(Box::new(SettlementInitiate {
        applied: applied.clone(),
    }));
    let tools = Arc::new(tools);

    // (1) Chat path: a real served-style Engine turn dispatches `settlement.initiate` — applied == 1.
    dispatch_via_chat_path(tools.clone()).await;
    assert_eq!(
        applied.load(Ordering::SeqCst),
        1,
        "chat-path dispatch must execute the settlement once"
    );

    // (2) Harness path: the REAL shipped `mounts::build_harness_mounts`, over the SAME `tools` handle —
    // the R16 fix under test.
    let harness = mounts::build_harness_mounts(
        &mut report,
        Some(tools.clone()),
        &ainxt_config::GatesConfig::default(),
        &ainxt_runtimed::HarnessConfig::default(),
    )
    .expect("build_harness_mounts over the default in-memory OBO sink");
    let step = HarnessStep {
        id: "s1".into(),
        kind: StepKind::Tool,
        capability: "settlement.initiate".into(),
        estimated_tokens: 1,
        input: Some("batch-42".into()),
    };
    let harness_result = harness
        .invoker
        .invoke(&step, &caller(), DataClass::Confidential)
        .await;
    assert!(
        harness_result.is_ok(),
        "harness dispatch must succeed and dedupe against the engine's already-committed key: \
         {harness_result:?}"
    );

    // THE FIX: one shared ledger — the retried key from the harness path deduped, never re-executed.
    assert_eq!(
        applied.load(Ordering::SeqCst),
        1,
        "exactly-once: the SAME idempotency key retried via the harness /run bridge must NOT re-execute \
         the settlement — it must dedupe against the served engine's already-committed row"
    );
}
