// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-5 turn-pipeline + tooling/routing wiring tests. Each drives the REAL `Engine`
//! end-to-end (no mock of the gate under test) and is fail-before / pass-after:
//!
//! * `r5_wire_projection_channel` — the engine emits the TRUTHFUL §6 outcome (`turn.completed{Capped}`)
//!   and `compliance.notice` onto a `ChannelWireSink` a served transport drains, instead of the
//!   transport re-deriving them from the lossy legacy `Event` stream (which carries neither).
//! * `r5_two_phase_commit_agent_loop` — a `HighRisk` capability fires on the live agent loop ONLY via
//!   §1.4 two-phase commit (dry_run → commit), and is refused when no approval gate can clear it.
//! * `r5_tri_signal_data_class_routing` — a request that under-declares its class but smuggles a PAN
//!   is escalated (§4.2 tri-signal) to a regulated class BEFORE ranking, so a cloud-only provider is
//!   excluded from the route and the in-house provider serves it (ADR-012).

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use ainxt_protocol::{ComplianceAction, Event, Request, TurnOutcome as WireOutcome, WireEvent};
use ainxt_runtime::approval::AutoApprove;
use ainxt_runtime::compliance::RedactAndProceed;
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_runtime::wire::ChannelWireSink;
use ainxt_runtime::{engine_with_defaults, Engine};
use ainxt_tools::{
    EffectClass, InMemoryLedger, ManualReconciler, RiskTier, Tool, ToolError, ToolRuntime,
};
use ainxt_types::{DataClass, Principal};
use tokio::sync::mpsc;

// ============================================================================
// Shared test doubles
// ============================================================================

/// A `Pure` no-op tool the "always calls a tool" provider can invoke each round.
struct NoopTool;
impl Tool for NoopTool {
    fn name(&self) -> &str {
        "noop"
    }
    fn effect_class(&self) -> EffectClass {
        EffectClass::Pure
    }
    fn execute(&self, _args: &str) -> Result<String, ToolError> {
        Ok("noop-ok".to_string())
    }
}

/// Provider that requests the SAME tool call every round and never answers — so the agent loop
/// terminates by the stuck-detector: a TRUTHFUL `Capped`, never a natural `Complete`.
struct NeverDoneProvider;
impl Provider for NeverDoneProvider {
    fn id(&self) -> &str {
        "never-done"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, _prompt: &str) -> mpsc::Receiver<Event> {
        let (tx, rx) = mpsc::channel(8);
        tokio::spawn(async move {
            let _ = tx
                .send(Event::ToolCallStart {
                    id: "t0".into(),
                    name: "noop".into(),
                    args: "x".into(),
                })
                .await;
            let _ = tx.send(Event::Done).await;
        });
        rx
    }
}

/// A `HighRisk` settlement tool (§1.4): SideEffecting, keyed, apex risk tier. `counter` proves how
/// many times it actually executed.
struct HighRiskSettle {
    counter: Arc<AtomicU32>,
}
impl Tool for HighRiskSettle {
    fn name(&self) -> &str {
        "settle"
    }
    fn effect_class(&self) -> EffectClass {
        EffectClass::SideEffecting
    }
    fn risk_tier(&self) -> RiskTier {
        RiskTier::HighRisk
    }
    fn idempotency_key(&self, args: &str) -> Option<String> {
        Some(args.to_string())
    }
    fn execute(&self, args: &str) -> Result<String, ToolError> {
        self.counter.fetch_add(1, Ordering::SeqCst);
        Ok(format!("settled:{args}"))
    }
}

/// Round 1: request `settle`. Round 2 (once its result is in the prompt): answer.
struct SettleThenAnswer;
impl Provider for SettleThenAnswer {
    fn id(&self) -> &str {
        "settleprov"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, prompt: &str) -> mpsc::Receiver<Event> {
        let (tx, rx) = mpsc::channel(8);
        let done = prompt.contains("[tool settle result:");
        tokio::spawn(async move {
            if done {
                let _ = tx
                    .send(Event::TextDelta("settlement complete".into()))
                    .await;
            } else {
                let _ = tx
                    .send(Event::ToolCallStart {
                        id: "s0".into(),
                        name: "settle".into(),
                        args: "NEFT-1".into(),
                    })
                    .await;
            }
            let _ = tx.send(Event::Done).await;
        });
        rx
    }
}

/// Emits a single text answer and stops naturally — for the routing test (no tool calls needed).
struct AnswerProvider {
    id: &'static str,
    eligible: Vec<DataClass>,
}
impl Provider for AnswerProvider {
    fn id(&self) -> &str {
        self.id
    }
    fn eligible(&self, dc: DataClass) -> bool {
        self.eligible.contains(&dc)
    }
    fn stream(&self, _prompt: &str) -> mpsc::Receiver<Event> {
        let (tx, rx) = mpsc::channel(8);
        tokio::spawn(async move {
            let _ = tx.send(Event::TextDelta("ok".into())).await;
            let _ = tx.send(Event::Done).await;
        });
        rx
    }
}

fn user() -> Principal {
    Principal::user("u", &["chat.send", "tool.settle", "tool.noop"])
}

// ============================================================================
// (1) Default wire projection: capped + compliance.notice reach the transport
// ============================================================================

#[tokio::test]
async fn r5_wire_projection_channel() {
    // The engine emits its typed §4/§6 envelope stream onto the ChannelWireSink; a server drains it.
    let (sink, mut rx) = ChannelWireSink::new();

    let mut router = ModelRouter::new();
    router.register(Box::new(NeverDoneProvider));
    let mut tr = ToolRuntime::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler));
    tr.register(Box::new(NoopTool));
    let eng: Engine = engine_with_defaults(router)
        .with_tools(tr)
        .with_wire_sink(Box::new(sink));

    // Input smuggles a PAN → the mandatory compliance gate redacts it (redact-and-proceed).
    let out = eng
        .run_turn_collect(
            &user(),
            &Request::chat(
                "s",
                "t",
                "settle card 4111111111111111 now",
                DataClass::Public,
            ),
        )
        .await
        .expect("turn runs to completion (redact-and-proceed, never blocked)");

    // The engine emits synchronously during the turn; by now every envelope is queued. Drain it.
    let mut wire = Vec::new();
    while let Ok(env) = rx.try_recv() {
        wire.push(env);
    }
    assert!(
        !wire.is_empty(),
        "the wire projection must carry the turn's typed events"
    );

    // (a) The truthful terminal outcome is `Capped` — NEVER `Complete`. This is the exact bug in a
    //     transport that re-derives the outcome from the legacy `Event::Done` (which is always mapped
    //     to `Complete`): the honest "judge could not confirm done" is only on this stream.
    let completed: Vec<&WireEvent> = wire
        .iter()
        .map(|e| &e.event)
        .filter(|e| matches!(e, WireEvent::TurnCompleted { .. }))
        .collect();
    assert_eq!(completed.len(), 1, "exactly one terminal turn.completed");
    assert!(
        matches!(
            completed[0],
            WireEvent::TurnCompleted {
                outcome: WireOutcome::Capped,
                ..
            }
        ),
        "a stuck/iteration-capped turn is Capped on the wire, not Complete: {:?}",
        completed[0]
    );

    // (b) A `compliance.notice{redacted}` for the input class is on the wire — the legacy `Event`
    //     stream has no such event at all, so a re-deriving transport can never surface it.
    let notice = wire.iter().map(|e| &e.event).find_map(|e| match e {
        WireEvent::ComplianceNotice { categories, action } => Some((categories.clone(), *action)),
        _ => None,
    });
    let (cats, action) = notice.expect("input redaction must emit a compliance.notice on the wire");
    assert!(
        cats.iter().any(|c| c == "input"),
        "notice names the redacted class: {cats:?}"
    );
    assert_eq!(action, ComplianceAction::Redacted);

    // (c) The legacy in-proc stream that a naive transport re-derives from carries NEITHER: only a
    //     bare `Event::Done` (→ Complete) and no compliance event. This is the divergence the wire
    //     projection fixes.
    assert!(
        out.events.contains(&Event::Done),
        "legacy stream ends with Done"
    );
    assert!(
        !out.events.iter().any(|e| matches!(e, Event::Error(_))),
        "the turn was not an error — it was capped"
    );

    // Envelope hygiene: strictly-monotonic per-session seq.
    for w in wire.windows(2) {
        assert!(w[1].seq > w[0].seq, "seq must be strictly monotonic");
    }
}

// ============================================================================
// (2) §1.4 two-phase commit wired into the live agent loop
// ============================================================================

fn settle_engine(
    gate: Option<Box<dyn ainxt_runtime::approval::ApprovalGate>>,
    counter: Arc<AtomicU32>,
) -> Engine {
    let mut router = ModelRouter::new();
    router.register(Box::new(SettleThenAnswer));
    let mut tr = ToolRuntime::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler));
    tr.register(Box::new(HighRiskSettle { counter }));
    let mut eng = Engine::new(
        Box::new(RedactAndProceed),
        Box::new(ainxt_runtime::authz::RbacAuthorizer),
        Box::new(ainxt_runtime::audit::InMemoryAudit::default()),
        router,
    )
    .with_tools(tr);
    if let Some(g) = gate {
        eng = eng.with_approval(g);
    }
    eng
}

#[tokio::test]
async fn r5_two_phase_commit_agent_loop() {
    // --- Positive: an approval gate clears the HighRisk action → it fires via dry_run → commit,
    //     exactly once, and the loop then completes. Before the wiring, direct dispatch of a HighRisk
    //     tool is refused (Blocked) and the tool NEVER runs. ---
    let counter = Arc::new(AtomicU32::new(0));
    let eng = settle_engine(Some(Box::new(AutoApprove)), counter.clone());
    let out = eng
        .run_turn_collect(
            &user(),
            &Request::chat("s", "t", "please settle NEFT-1", DataClass::Public),
        )
        .await
        .unwrap();

    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "the HighRisk tool must execute exactly once — via two-phase commit"
    );
    assert!(
        out.events
            .iter()
            .any(|e| matches!(e, Event::ToolResult { output, .. } if output == "settled:NEFT-1")),
        "the committed result is fed back: {:?}",
        out.events
    );
    assert_eq!(
        out.final_text, "settlement complete",
        "the loop completes after the commit"
    );

    // --- Enforcement: with NO approval gate, a HighRisk action is fail-closed (refused) and the tool
    //     never executes — the two-phase path does not weaken the gate. ---
    let counter2 = Arc::new(AtomicU32::new(0));
    let eng2 = settle_engine(None, counter2.clone());
    let _ = eng2
        .run_turn_collect(
            &user(),
            &Request::chat("s", "t", "please settle NEFT-1", DataClass::Public),
        )
        .await
        .unwrap();
    assert_eq!(
        counter2.load(Ordering::SeqCst),
        0,
        "a HighRisk action with no approval gate must be refused, never committed"
    );
}

// ============================================================================
// (3) §4.2 tri-signal data-class classification feeding the router before ranking
// ============================================================================

fn routing_engine() -> Engine {
    // `cloud` handles up to Confidential but is EXCLUDED from regulated classes; `inhouse` handles
    // everything. `cloud` is registered first, so it wins any route it is eligible for.
    let mut router = ModelRouter::new();
    router.register(Box::new(AnswerProvider {
        id: "cloud",
        eligible: vec![
            DataClass::Public,
            DataClass::Internal,
            DataClass::Confidential,
        ],
    }));
    router.register(Box::new(AnswerProvider {
        id: "inhouse",
        eligible: vec![
            DataClass::Public,
            DataClass::Internal,
            DataClass::Confidential,
            DataClass::RegulatedPayment,
            DataClass::Pii,
        ],
    }));
    engine_with_defaults(router)
}

#[tokio::test]
async fn r5_tri_signal_data_class_routing() {
    // Control: a benign `Public` turn routes to the first eligible provider (`cloud`) — proving the
    // test does not just always pick `inhouse`.
    let benign = routing_engine()
        .run_turn_collect(
            &user(),
            &Request::chat("s", "t", "hello there", DataClass::Public),
        )
        .await
        .unwrap();
    assert_eq!(
        benign.provider, "cloud",
        "a genuinely Public turn may route to cloud"
    );

    // The same declared `Public` class, but the input smuggles a Luhn-valid PAN. §4.2 escalates the
    // effective class to RegulatedPayment BEFORE ranking, excluding `cloud` from the eligible set, so
    // the in-house provider serves it (ADR-012). Before the wiring, this under-declared turn would
    // have routed to `cloud` and leaked a regulated payload to a cloud model.
    let escalated = routing_engine()
        .run_turn_collect(
            &user(),
            &Request::chat(
                "s",
                "t",
                "pay from 4111111111111111 today",
                DataClass::Public,
            ),
        )
        .await
        .unwrap();
    assert_eq!(
        escalated.provider, "inhouse",
        "a PAN-bearing under-declared turn must be escalated to a regulated class and kept in-house"
    );
}
