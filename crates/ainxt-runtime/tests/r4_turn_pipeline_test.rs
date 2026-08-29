// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-4 gap-closing integration tests, driven end-to-end on the REAL `Engine`
//! (`run_turn` / `run_turn_collect`) — never a mock of a gate. Covers the three turn-pipeline gaps
//! closed this round:
//!
//!  * `r4_tool_args_redacted_before_wire` — tool-call ARGS are compliance-redacted (Direction::
//!    ToolArgs) BEFORE the legacy `tool.call.start` event and the §6 wire `tool.call.start`/
//!    `tool.call.stop` envelopes are emitted, so a PAN the model copied into a call never reaches
//!    the transport ahead of the 7a seam. Fails-before: raw args reached the transport.
//!  * `r4_wire_vocabulary_tool_result_usage` — the live pipeline emits the fuller §6 vocabulary on
//!    the wire sink: `tool.result` (structured, redacted blocks) and `usage` (actually-routed model,
//!    priced tokens). Fails-before: neither was emitted on the wire.
//!  * `r4_payment_boundary_requires_human_approve` — an action with `payment_boundary != none` is
//!    always routed through the approval gate and cleared ONLY by an explicit HUMAN `approve`; a
//!    policy auto-approve and a human `approve_for_session` are BOTH refused (fail-closed), mirroring
//!    `ApprovalRespond::is_valid`. The wire carries `approval.request{payment_boundary}`.
//!    Fails-before: a low-risk value-moving tool was dispatched with no human gate.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use ainxt_protocol::{Event, PaymentBoundary, Request, ResultBlock, WireEvent};
use ainxt_runtime::approval::{ApprovalDecision, ApprovalGate, ApprovalRequest, AutoApprove};
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_runtime::wire::VecWireSink;
use ainxt_runtime::{engine_with_defaults, Engine};
use ainxt_tools::{EffectClass, InMemoryLedger, ManualReconciler, Tool, ToolError, ToolRuntime};
use ainxt_types::{DataClass, Principal};
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------------------------
// Shared test doubles
// ---------------------------------------------------------------------------------------------

/// A pure lookup tool (no side effect) — the dispatch produces an observation for the wire test.
struct LookupTool;
impl Tool for LookupTool {
    fn name(&self) -> &str {
        "lookup"
    }
    fn effect_class(&self) -> EffectClass {
        EffectClass::Pure
    }
    fn execute(&self, _args: &str) -> Result<String, ToolError> {
        Ok("record-42".into())
    }
}

/// Emits ONE tool call carrying the given raw args on the first round, then acknowledges once the
/// observation (or a denial) is folded back into the prompt.
struct OneToolProvider {
    tool: String,
    args: String,
    /// Whether to emit a Usage event on each round (for the accounting-wire test).
    usage: bool,
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
        let settled = prompt.contains("result:") || prompt.contains("denied");
        let tool = self.tool.clone();
        let args = self.args.clone();
        let usage = self.usage;
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
            if usage {
                let _ = tx
                    .send(Event::Usage {
                        input_tokens: 11,
                        output_tokens: 7,
                    })
                    .await;
            }
            let _ = tx.send(Event::Done).await;
        });
        rx
    }
}

/// A value-moving, side-effecting tool. Low risk tier — it is NOT gated by the legacy high-risk
/// path; it is gated ONLY because the engine's payment-boundary resolver marks it `MovesValue`.
struct ValueOpTool {
    counter: Arc<AtomicU32>,
}
impl Tool for ValueOpTool {
    fn name(&self) -> &str {
        "value_op"
    }
    fn effect_class(&self) -> EffectClass {
        EffectClass::SideEffecting
    }
    fn idempotency_key(&self, args: &str) -> Option<String> {
        Some(args.to_string())
    }
    fn execute(&self, _args: &str) -> Result<String, ToolError> {
        self.counter.fetch_add(1, Ordering::SeqCst);
        Ok("moved".into())
    }
}

/// A gate that returns a fixed decision and declares whether it is a live-human gate.
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

async fn run_collect(eng: &Engine, principal: &Principal, req: &Request) -> Vec<Event> {
    eng.run_turn_collect(principal, req).await.unwrap().events
}

// ---------------------------------------------------------------------------------------------
// Gap 1 — tool-call args redacted BEFORE they hit the transport (wire + legacy)
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn r4_tool_args_redacted_before_wire() {
    // A PAN-like 16-digit run the model copied into the tool call's args.
    const PAN: &str = "4111111111111111";
    let raw_args = format!("{{\"pan\":\"{PAN}\"}}");

    let mut router = ModelRouter::new();
    router.register(Box::new(OneToolProvider {
        tool: "lookup".into(),
        args: raw_args.clone(),
        usage: false,
    }));
    let mut tr = ToolRuntime::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler));
    tr.register(Box::new(LookupTool));

    let wire = Arc::new(VecWireSink::default());
    let eng = engine_with_defaults(router)
        .with_tools(tr)
        .with_wire_sink(Box::new(Arc::clone(&wire)));

    let events = run_collect(
        &eng,
        &user(&["chat.send", "tool.lookup"]),
        &Request::chat("s", "t", "look it up", DataClass::Public),
    )
    .await;

    // Legacy tool.call.start: args must be redacted — the raw PAN never reaches the transport.
    let legacy_start = events
        .iter()
        .find_map(|e| match e {
            Event::ToolCallStart { args, .. } => Some(args.clone()),
            _ => None,
        })
        .expect("a tool.call.start event");
    assert!(
        !legacy_start.contains(PAN),
        "raw PAN leaked to the legacy tool.call.start args: {legacy_start}"
    );
    assert!(
        legacy_start.contains("[REDACTED-PAN]"),
        "tool.call.start args were not compliance-redacted: {legacy_start}"
    );

    // §6 wire tool.call.start / tool.call.stop: the stop carries args — also redacted.
    let envs = wire.snapshot();
    let stop_args = envs
        .iter()
        .find_map(|e| match &e.event {
            WireEvent::ToolCallStop { args, .. } => Some(args.clone()),
            _ => None,
        })
        .expect("a wire tool.call.stop envelope");
    assert!(
        !stop_args.contains(PAN) && stop_args.contains("[REDACTED-PAN]"),
        "raw PAN leaked to the wire tool.call.stop args: {stop_args}"
    );
    // The redaction was announced on the wire as a compliance.notice for the tool-args category.
    assert!(
        envs.iter().any(|e| matches!(&e.event,
            WireEvent::ComplianceNotice { categories, .. } if categories.iter().any(|c| c == "tool-args"))),
        "expected a compliance.notice{{tool-args}} on the wire"
    );
}

// ---------------------------------------------------------------------------------------------
// Gap 2 — fuller §6 wire vocabulary: tool.result + usage
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn r4_wire_vocabulary_tool_result_usage() {
    let mut router = ModelRouter::new();
    router.register(Box::new(OneToolProvider {
        tool: "lookup".into(),
        args: "{\"q\":\"x\"}".into(),
        usage: true,
    }));
    let mut tr = ToolRuntime::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler));
    tr.register(Box::new(LookupTool));

    let wire = Arc::new(VecWireSink::default());
    let eng = engine_with_defaults(router)
        .with_tools(tr)
        .with_wire_sink(Box::new(Arc::clone(&wire)));

    let _ = run_collect(
        &eng,
        &user(&["chat.send", "tool.lookup"]),
        &Request::chat("s", "t", "go", DataClass::Public),
    )
    .await;

    let envs = wire.snapshot();

    // tool.result on the wire, carrying the (redacted) observation as a structured text block.
    let tr_ok = envs.iter().any(|e| matches!(&e.event,
        WireEvent::ToolResult { call_id, blocks, is_error }
            if call_id == "c0"
            && !*is_error
            && blocks.iter().any(|b| matches!(b, ResultBlock::Text { text } if text == "record-42"))));
    assert!(
        tr_ok,
        "expected a §6 tool.result envelope with the observation block"
    );

    // usage on the wire, attributed to the ACTUALLY-routed model with priced tokens.
    let usage_ok = envs.iter().any(|e| {
        matches!(&e.event,
        WireEvent::Usage { model, input_tokens, output_tokens, .. }
            if model == "oneprov" && *input_tokens == 11 && *output_tokens == 7)
    });
    assert!(
        usage_ok,
        "expected a §6 usage envelope for the routed provider"
    );
}

// ---------------------------------------------------------------------------------------------
// Gap 3 — payment_boundary != none requires an explicit HUMAN approve (never auto)
// ---------------------------------------------------------------------------------------------

/// Build an engine whose `value_op` tool crosses a payment boundary (`MovesValue`), with the given
/// approval gate. Returns the engine, the execution counter, and the shared wire sink.
fn build_payment_engine(
    gate: Option<Box<dyn ApprovalGate>>,
) -> (Engine, Arc<AtomicU32>, Arc<VecWireSink>) {
    let counter = Arc::new(AtomicU32::new(0));
    let mut router = ModelRouter::new();
    router.register(Box::new(OneToolProvider {
        tool: "value_op".into(),
        args: "{\"amount\":100}".into(),
        usage: false,
    }));
    let mut tr = ToolRuntime::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler));
    tr.register(Box::new(ValueOpTool {
        counter: counter.clone(),
    }));
    let wire = Arc::new(VecWireSink::default());
    let mut eng = engine_with_defaults(router)
        .with_tools(tr)
        .with_wire_sink(Box::new(Arc::clone(&wire)))
        // The runtime's payment-boundary resolver: value_op moves value; everything else is None.
        .with_payment_boundary_resolver(Box::new(|name, _args| {
            if name == "value_op" {
                PaymentBoundary::MovesValue
            } else {
                PaymentBoundary::None
            }
        }));
    if let Some(g) = gate {
        eng = eng.with_approval(g);
    }
    (eng, counter, wire)
}

async fn run_payment(eng: &Engine) -> Vec<Event> {
    run_collect(
        eng,
        &user(&["chat.send", "tool.value_op"]),
        &Request::chat("s", "t", "move funds", DataClass::Public),
    )
    .await
}

#[tokio::test]
async fn r4_payment_boundary_requires_human_approve() {
    // (a) A live HUMAN `approve` clears the payment — the tool runs exactly once.
    let human_approve = FixedGate {
        decision: ApprovalDecision::Approve,
        policy_auto: false,
    };
    let (eng, counter, wire) = build_payment_engine(Some(Box::new(human_approve)));
    let events = run_payment(&eng).await;
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "a HUMAN approve must clear the payment-boundary action"
    );
    assert!(
        events
            .iter()
            .any(|e| matches!(e, Event::ToolResult { output, .. } if output == "moved")),
        "the value-moving tool should have executed"
    );
    // The wire announced the approval request WITH the payment_boundary so a renderer knows a human
    // approve is mandatory.
    assert!(
        wire.snapshot().iter().any(|e| matches!(&e.event,
            WireEvent::ApprovalRequest { action, payment_boundary, .. }
                if action == "value_op" && *payment_boundary == PaymentBoundary::MovesValue)),
        "expected a §6 approval.request{{payment_boundary=MovesValue}} on the wire"
    );

    // (b) A POLICY auto-approve (AutoApprove) must NOT clear a payment — fail-closed.
    let (eng, counter, _wire) = build_payment_engine(Some(Box::new(AutoApprove)));
    let events = run_payment(&eng).await;
    assert_eq!(
        counter.load(Ordering::SeqCst),
        0,
        "a policy auto-approve must NEVER move value"
    );
    assert!(
        events.iter().any(
            |e| matches!(e, Event::ToolResult { output, .. } if output.starts_with("denied:"))
        ),
        "the payment should have been denied, not dispatched"
    );

    // (c) Even a HUMAN `approve_for_session` is refused for a payment boundary — each payment needs a
    //     fresh, explicit human approve (§9, ADR-016).
    let human_afs = FixedGate {
        decision: ApprovalDecision::ApproveForSession,
        policy_auto: false,
    };
    let (eng, counter, _wire) = build_payment_engine(Some(Box::new(human_afs)));
    let _ = run_payment(&eng).await;
    assert_eq!(
        counter.load(Ordering::SeqCst),
        0,
        "approve_for_session must NOT clear a payment-boundary action"
    );

    // (d) No gate at all → fail-closed (never auto-dispatched).
    let (eng, counter, _wire) = build_payment_engine(None);
    let _ = run_payment(&eng).await;
    assert_eq!(
        counter.load(Ordering::SeqCst),
        0,
        "no approval gate ⇒ a payment-boundary action must be refused"
    );
}
