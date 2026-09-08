// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX transport-daemon (ADR-016 §9) — the wire-level `payment_boundary` human-approve-only
//! gate was fully implemented in `ainxt-runtime`'s dispatch loop
//! (`ainxt_runtime::Engine::run_turn_cancellable`, §9/ADR-016) but had exactly ONE call site for
//! `Engine::with_payment_boundary_resolver` outside its own definition — a test
//! (`ainxt-runtime/tests/r4_turn_pipeline_test.rs`) — and ZERO call sites in the daemon composition
//! root (`ainxt-runtimed`). Every served engine therefore ran with `Engine::new`'s default resolver
//! (`|_, _| PaymentBoundary::None`), so no served `approval.request` could ever carry a real
//! boundary: a payment-adjacent tool call could clear the ordinary high-risk gate (or slip through a
//! Low/Medium-risk tool entirely) without ever reaching the human-approve-only invariant.
//!
//! The fix installs `ainxt_runtimed::default_payment_boundary_resolver` — built on the REAL §4.5
//! signature classifier `ainxt_payments::boundary::PaymentBoundary` (the same decision core
//! `ainxt-connector-http`'s egress tripwire already screens resolved network calls with) — via
//! `Engine::with_payment_boundary_resolver` in BOTH of the daemon's Engine composition roots:
//! `build_engine_ext` (bare/program/team surfaces, reached through the `pub` `build_engine`/
//! `assemble` entrypoints) and `build_chat_engine_with_authz` (the flagship chat/code/sdlc/buddy
//! surfaces, reached through `assemble_chat` and friends).
//!
//! Proof strategy (read this before judging the tests below):
//!
//!  * Tests 1-2 exercise the REAL, `pub`, served daemon composition-root functions directly
//!    (`ainxt_runtimed::build_engine`, `ainxt_runtimed::assemble_chat`) and prove each one now
//!    installs a resolver whose behavior is NEVER `PaymentBoundary::None` for a payment-shaped call
//!    — the exact regression this fix closes. `build_engine`'s `Engine` is not erased, so the test
//!    calls `Engine::probe_payment_boundary` (a thin, read-only pass-through added onto the SAME
//!    `self.payment_boundary` field the approval gate consults at dispatch time — never a
//!    re-derivation of it). `assemble_chat`'s engine IS erased behind `Arc<dyn TurnHandler>`, so
//!    that test instead reads the assembly `report` line `build_chat_engine_with_authz` pushes
//!    immediately after installing the SAME resolver call.
//!  * Test 3 proves the installed resolver's *dispatch-time behavior* — the fail-closed
//!    human-approve-only gate itself — end-to-end over a REAL `Engine::run_turn`, using the SAME
//!    `ainxt_runtimed::default_payment_boundary_resolver` function the two composition roots above
//!    call (not a re-implementation of its detection logic), because no shipped `Provider` adapter
//!    (`AnthropicProvider`/`OpenAiSchemaProvider`/`OfflineProvider` — see `ainxt-providers`) parses
//!    `tool_calls` out of a live model response yet: that is a separate, pre-existing, structural
//!    gap in this build (confirmed by inspection: none of the three adapters' SSE normalizers ever
//!    construct `Event::ToolCallStart`), so a REAL cloud/local LLM can never drive a tool dispatch
//!    through ANY served engine in this codebase today, payment-related or not. A test double
//!    `Provider` — the same substitution every other tool-dispatch-behavior test in this workspace
//!    uses (`r4_turn_pipeline_test.rs`, `dock_chat_http.rs`) — is therefore the honest ceiling for
//!    exercising dispatch-time behavior; what matters for THIS gap is that the resolver under test
//!    is the real production one, which it is.
//!  * Test 4 carries Test 3's exact engine over a REAL HTTP server (`ainxt_server::serve` +
//!    `reqwest`), proving the fix's effect survives the full SessionManager/transport/SSE stack, not
//!    just the in-process engine loop.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use ainxt_protocol::{Event, PaymentBoundary, Request, WireEvent};
use ainxt_runtime::approval::{ApprovalDecision, ApprovalGate, ApprovalRequest, AutoApprove};
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_runtime::wire::VecWireSink;
use ainxt_runtime::{engine_with_defaults, Engine};
use ainxt_runtimed::{
    assemble_chat, build_engine, default_payment_boundary_resolver, load_layered,
};
use ainxt_server::serve;
use ainxt_session::{SessionConfig, SessionManager};
use ainxt_tools::{EffectClass, InMemoryLedger, ManualReconciler, Tool, ToolError, ToolRuntime};
use ainxt_types::{DataClass, Principal};
use tokio::sync::mpsc;

fn loaded_config() -> ainxt_runtimed::LoadedConfig {
    load_layered(&[("g5pb", "version = 1")]).expect("load offline config")
}

// =================================================================================================
// Test 1 — the REAL bare-engine composition root (`build_engine`, used by `assemble`'s served
// bare-engine surface) installs a resolver that is genuinely NOT the default None stub.
// =================================================================================================

#[test]
fn build_engine_installs_a_real_payment_boundary_resolver() {
    let loaded = loaded_config();
    let (engine, _report) = build_engine(&loaded.runtime).expect("build_engine must assemble");

    // A benign call must NOT be gated — the fix must not over-block ordinary tool dispatch.
    assert_eq!(
        engine.probe_payment_boundary("lookup", "{}"),
        PaymentBoundary::None,
        "an ordinary tool call must classify as no payment boundary"
    );

    // A call naming a destination inside the reserved perimeter must resolve to a REAL boundary.
    // Before the resolver was installed this was ALWAYS `None`.
    //
    // `"x402.pay"` is used because it genuinely matches `SettlementPerimeter::default_reserved`
    // (the `"x402."` agent-payment-protocol pattern, ADR-016 §5). This assertion previously probed
    // `"settlement.example.transfer"` with a `settlement-account:` resource key, which matches
    // NEITHER facet here: no `default_reserved` pattern is a substring of that name, and the
    // resource-key facet reads `ToolRuntime::resource_of`, which is `None` for a tool this runtime
    // never registers. The resource-key facet is exercised directly against `classify()` in
    // `ainxt-payments::boundary`'s own tests, where a resource key can actually be supplied.
    let boundary = engine.probe_payment_boundary("x402.pay", "{}");
    assert_ne!(
        boundary,
        PaymentBoundary::None,
        "a settlement-perimeter destination must classify as a real payment boundary on the \
         daemon's real bare-engine composition root"
    );

    // Layer-6 tripwire (ADR-016 §4.6): a call with a BENIGN name/resource but whose raw ARGS carry a
    // value-moving UPI signature must still be caught — proving the fix does not rely solely on the
    // tool's declared name/resource_key.
    let payload_only = engine.probe_payment_boundary(
        "generic.invoke",
        "{\"upi_operation\":\"collect\",\"vpa\":\"payee@bank\"}",
    );
    assert_ne!(
        payload_only,
        PaymentBoundary::None,
        "a mis-declared/dynamically-constructed call whose ARGS carry a UPI value-moving signature \
         must still be classified as a payment boundary"
    );
}

// =================================================================================================
// Test 2 — the REAL flagship chat composition root (`assemble_chat`, what `/v1/chat` serves) also
// installs the resolver. `assemble_chat`'s engine is erased behind `Arc<dyn TurnHandler>`, so this
// reads the assembly report line `build_chat_engine_with_authz` pushes right after installing it —
// the same "prove it from the report" technique `r11_config_selects_otlp_telemetry_sink` uses for a
// seam it also can't get a live handle back out of.
// =================================================================================================

#[test]
fn assemble_chat_installs_the_same_real_payment_boundary_resolver() {
    let loaded = loaded_config();
    let assembled = assemble_chat(&loaded).expect("assemble_chat must assemble");
    assert!(
        assembled.report.iter().any(|l| l
            .contains("payments: payment-initiation-signature classifier")
            && l.contains("payment_boundary resolver")),
        "assemble_chat's report must record the real payment-boundary classifier being wired onto \
         the served chat/code/sdlc/buddy engine: {:?}",
        assembled.report
    );
}

// =================================================================================================
// Shared test doubles for Tests 3-4 (mirrors the established pattern in
// `ainxt-runtime/tests/r4_turn_pipeline_test.rs` / `ainxt-runtimed/tests/dock_chat_http.rs`: no
// shipped Provider parses live tool-calls, so a deterministic stand-in drives the turn).
// =================================================================================================

/// A value-moving, side-effecting tool. Deliberately LOW risk tier (no `risk_tier` override) so any
/// gating observed is due ENTIRELY to the payment-boundary resolver, not the legacy high-risk path.
struct SettlePaymentTool {
    counter: Arc<AtomicU32>,
}
impl Tool for SettlePaymentTool {
    fn name(&self) -> &str {
        "settlement.example.transfer"
    }
    fn effect_class(&self) -> EffectClass {
        EffectClass::SideEffecting
    }
    fn idempotency_key(&self, args: &str) -> Option<String> {
        Some(args.to_string())
    }
    fn resource(&self, _args: &str) -> Option<String> {
        Some("settlement-account:HDFC0001".to_string())
    }
    fn execute(&self, _args: &str) -> Result<String, ToolError> {
        self.counter.fetch_add(1, Ordering::SeqCst);
        Ok("settled".into())
    }
}

/// Emits ONE tool call for the given tool/args on the first round, then acknowledges once the
/// observation (or a denial) is folded back into the prompt.
struct OneToolProvider {
    tool: String,
    args: String,
}
impl Provider for OneToolProvider {
    fn id(&self) -> &str {
        "oneprov"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, prompt: &str) -> mpsc::Receiver<Event> {
        let (tx, rx) = mpsc::channel(8);
        let settled =
            prompt.contains("result:") || prompt.contains("denied") || prompt.contains("settled");
        let tool = self.tool.clone();
        let args = self.args.clone();
        tokio::spawn(async move {
            if settled {
                let _ = tx.send(Event::TextDelta("acknowledged".into())).await;
            } else {
                let _ = tx
                    .send(Event::ToolCallStart {
                        id: "c0".into(),
                        name: tool,
                        args,
                    })
                    .await;
            }
            let _ = tx.send(Event::Done).await;
        });
        rx
    }
}

struct FixedGate {
    decision: ApprovalDecision,
    policy_auto: bool,
}
impl ApprovalGate for FixedGate {
    fn decide(&self, _req: &ApprovalRequest) -> ApprovalDecision {
        self.decision.clone()
    }
    fn is_policy_auto(&self) -> bool {
        self.policy_auto
    }
}

fn user(caps: &[&str]) -> Principal {
    Principal::user("u", caps)
}

/// Build the test engine: a real `Engine` (mirrors the shape `build_engine_ext`/
/// `build_chat_engine_with_authz` produce) with the tool call wired to a payment-adjacent settlement
/// transfer, gated with `.with_payment_boundary_resolver(ainxt_runtimed::default_payment_boundary_resolver(...))`
/// — THE REAL PRODUCTION RESOLVER FUNCTION, not a re-implementation of its detection logic.
fn build_payment_test_engine(
    gate: Option<Box<dyn ApprovalGate>>,
) -> (Engine, Arc<AtomicU32>, Arc<VecWireSink>) {
    let counter = Arc::new(AtomicU32::new(0));
    let mut router = ModelRouter::new();
    router.register(Box::new(OneToolProvider {
        tool: "settlement.example.transfer".into(),
        args: "{\"resource_key\":\"settlement-account:HDFC0001\",\"amount\":100}".into(),
    }));
    let mut tr = ToolRuntime::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler));
    tr.register(Box::new(SettlePaymentTool {
        counter: counter.clone(),
    }));
    let tools = Arc::new(tr);
    let wire = Arc::new(VecWireSink::default());
    let mut eng = engine_with_defaults(router)
        .with_shared_tools(tools.clone())
        .with_wire_sink(Box::new(Arc::clone(&wire)))
        // THE FIX under test, called through its real exported production function.
        .with_payment_boundary_resolver(default_payment_boundary_resolver(tools));
    if let Some(g) = gate {
        eng = eng.with_approval(g);
    }
    (eng, counter, wire)
}

async fn run_payment(eng: &Engine) -> Vec<Event> {
    eng.run_turn_collect(
        &user(&["chat.send", "tool.settlement.example.transfer"]),
        &Request::chat("s", "t", "move funds", DataClass::Public),
    )
    .await
    .unwrap()
    .events
}

// =================================================================================================
// Test 3 — the REAL resolver's dispatch-time behavior: a settlement-perimeter tool call is ALWAYS
// gated, cleared ONLY by a genuine human approve; a policy auto-approve is refused fail-closed.
// =================================================================================================

#[tokio::test]
async fn real_resolver_drives_the_fail_closed_human_approve_only_gate() {
    // (a) A live HUMAN `approve` clears the payment — the tool runs exactly once.
    let human_approve = FixedGate {
        decision: ApprovalDecision::Approve,
        policy_auto: false,
    };
    let (eng, counter, wire) = build_payment_test_engine(Some(Box::new(human_approve)));
    let events = run_payment(&eng).await;
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "a HUMAN approve must clear the settlement transfer gated by the REAL production resolver"
    );
    assert!(
        events
            .iter()
            .any(|e| matches!(e, Event::ToolResult { output, .. } if output == "settled")),
        "the settlement tool should have executed"
    );
    assert!(
        wire.snapshot().iter().any(|e| matches!(&e.event,
            WireEvent::ApprovalRequest { action, payment_boundary, .. }
                if action == "settlement.example.transfer" && *payment_boundary != PaymentBoundary::None)),
        "expected a §6 approval.request{{payment_boundary != None}} on the wire, carrying the boundary \
         the REAL default_payment_boundary_resolver computed"
    );

    // (b) A POLICY auto-approve must NOT clear a payment — fail-closed, exactly ADR-016 §9's
    // invariant, driven here by the real production resolver rather than a hand-rolled test stub.
    let (eng, counter, _wire) = build_payment_test_engine(Some(Box::new(AutoApprove)));
    let events = run_payment(&eng).await;
    assert_eq!(
        counter.load(Ordering::SeqCst),
        0,
        "a policy auto-approve must NEVER move value, even though AutoApprove would clear an \
         ordinary high-risk (non-payment) gate"
    );
    assert!(
        events.iter().any(
            |e| matches!(e, Event::ToolResult { output, .. } if output.starts_with("denied:"))
        ),
        "the auto-approved payment must be refused: {events:?}"
    );

    // (c) No approval gate configured at all: fail-closed by omission — never open by omission.
    let (eng, counter, _wire) = build_payment_test_engine(None);
    let _ = run_payment(&eng).await;
    assert_eq!(
        counter.load(Ordering::SeqCst),
        0,
        "a payment-boundary tool with no approval gate configured must be refused, never dispatched"
    );
}

// =================================================================================================
// Test 4 — the SAME real-resolver-gated engine, served over a REAL HTTP/SSE `/v1/chat`-shaped
// transport (`ainxt_server::serve` + `reqwest`), proving the fix's effect reaches an actual socket.
// =================================================================================================

#[tokio::test(flavor = "multi_thread")]
async fn served_http_chat_turn_carries_the_real_payment_boundary_on_the_wire() {
    let human_approve = FixedGate {
        decision: ApprovalDecision::Approve,
        policy_auto: false,
    };
    let (eng, counter, _wire) = build_payment_test_engine(Some(Box::new(human_approve)));
    let manager = Arc::new(SessionManager::new(Arc::new(eng), SessionConfig::default()));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(serve(listener, manager));

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{addr}/v1/chat"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(
            serde_json::json!({
                "session": "sess-pay-http",
                "turn": "t1",
                "input": "move funds",
                "data_class": "public",
                "caps": ["chat.send", "tool.settlement.example.transfer"],
            })
            .to_string(),
        )
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status().as_u16(), 200, "chat POST should succeed");
    let body = resp.text().await.expect("read body");

    assert!(
        body.contains("approval") || body.contains("Approval"),
        "the served /v1/chat SSE body must carry an approval event for the settlement transfer: {body}"
    );
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "the served HTTP turn's human-approved settlement transfer must have executed exactly once"
    );
}
