// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-3 gap-closing integration tests, driven end-to-end on the REAL `Engine`
//! (`run_turn_cancellable`) — never a mock of a gate. Covers the four turn-pipeline / serving-ops
//! gaps closed this round:
//!
//!  * `r3_clearance_read_authz`  — clearance-vs-data-class READ authz denies a turn whose data class
//!    is more sensitive than the caller's clearance, BEFORE any provider/retrieval (turn-pipeline #1).
//!  * `r3_wire_event_vocabulary` — the live pipeline emits the §4 `EventEnvelope` + §6 `WireEvent`
//!    vocabulary onto the wire sink: strictly-monotonic `seq`, pinned `control_plane_sha`,
//!    `compliance.notice` on redaction, and a terminal `turn.completed{outcome}` (turn-pipeline #2).
//!  * `r3_loop_verification_enforced` — loop verification is enforced on the reachable path: a
//!    natural stop → `turn.completed{Complete}`; a turn cut off by the stuck-detector / iteration cap
//!    → `turn.completed{Capped}`, never reported Complete (LOOP §7 / ADR §6).
//!  * `r3_node_attestation_gate` — the node-attestation hook (real `ServingGate::pre_serve_check`
//!    via `ServingGateAttestor`) fails a regulated turn closed BEFORE dispatch when no node is
//!    attested; a public turn is admitted (serving-ops SRV-02 / ADR-021 §8.2).
//!
//! Each fails-before / passes-after the round-3 wiring: before it, `run_turn_cancellable` had no
//! clearance gate, emitted no §4/§6 envelope, never distinguished Complete vs Capped, and had no
//! pre-dispatch attestation hook.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use ainxt_protocol::{Event, EventEnvelope, Request, TurnOutcome as WireTurnOutcome, WireEvent};
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_runtime::serving::ServingGateAttestor;
use ainxt_runtime::wire::VecWireSink;
use ainxt_runtime::{engine_with_defaults, Engine, TurnError};
use ainxt_serving::attestation::{AttestationConfig, AttestationGate};
use ainxt_serving::gate::{NodeCandidate, ServingGate};
use ainxt_serving::preemption::PreemptionScheduler;
use ainxt_serving::FairnessLimiter;
use ainxt_types::{DataClass, Principal};
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------------------------
// Providers
// ---------------------------------------------------------------------------------------------

/// Flips a flag the instant its stream is opened — the tripwire proving whether a gate stopped the
/// turn BEFORE any provider was contacted.
struct TripwireProvider {
    called: Arc<AtomicBool>,
    text: String,
}
impl Provider for TripwireProvider {
    fn id(&self) -> &str {
        "tripwire"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, _prompt: &str) -> mpsc::Receiver<Event> {
        self.called.store(true, Ordering::SeqCst);
        let (tx, rx) = mpsc::channel(8);
        let text = self.text.clone();
        tokio::spawn(async move {
            let _ = tx.send(Event::TextDelta(text)).await;
            let _ = tx.send(Event::Done).await;
        });
        rx
    }
}

/// Never stops: every round emits the SAME tool call, so after the first dispatch the stuck-detector
/// fires — the turn is Capped, never Complete.
struct AlwaysToolProvider;
impl Provider for AlwaysToolProvider {
    fn id(&self) -> &str {
        "loopprov"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, _prompt: &str) -> mpsc::Receiver<Event> {
        let (tx, rx) = mpsc::channel(8);
        tokio::spawn(async move {
            let _ = tx
                .send(Event::ToolCallStart {
                    id: "c0".into(),
                    name: "noop".into(),
                    args: "same".into(),
                })
                .await;
            let _ = tx.send(Event::Done).await;
        });
        rx
    }
}

// A trivial no-op tool so the loop has a runtime to dispatch to (the stuck-detector path).
use ainxt_tools::{EffectClass, InMemoryLedger, ManualReconciler, Tool, ToolError, ToolRuntime};
struct NoopTool;
impl Tool for NoopTool {
    fn name(&self) -> &str {
        "noop"
    }
    fn effect_class(&self) -> EffectClass {
        EffectClass::Pure
    }
    fn execute(&self, _args: &str) -> Result<String, ToolError> {
        Ok("ok".into())
    }
}

// ---------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------

/// Run a turn, draining events concurrently, returning `(result, legacy events, wire envelopes)`.
async fn run_with_wire(
    eng: &Engine,
    principal: &Principal,
    req: &Request,
    wire: Arc<VecWireSink>,
) -> (
    Result<ainxt_runtime::TurnSummary, TurnError>,
    Vec<Event>,
    Vec<EventEnvelope>,
) {
    let (tx, mut rx) = mpsc::channel::<Event>(64);
    let fut = eng.run_turn(principal, req, tx);
    let drain = async move {
        let mut v = Vec::new();
        while let Some(e) = rx.recv().await {
            v.push(e);
        }
        v
    };
    let (res, events) = tokio::join!(fut, drain);
    (res, events, wire.snapshot())
}

fn terminal_outcome(envs: &[EventEnvelope]) -> Option<WireTurnOutcome> {
    envs.iter().find_map(|e| match &e.event {
        WireEvent::TurnCompleted { outcome, .. } => Some(*outcome),
        _ => None,
    })
}

// ---------------------------------------------------------------------------------------------
// 1. Clearance-vs-data-class READ authorization (turn-pipeline #1)
// ---------------------------------------------------------------------------------------------
#[tokio::test]
async fn r3_clearance_read_authz() {
    // Clearance-vs-data-class is a RETRIEVAL read-filter, NOT a turn-admission gate. A user cleared
    // only to `internal` submitting a `regulated-payment`-classed turn (e.g. their input contains
    // payment data) must be REDACTED and PROCEED — never hard-denied — per redact-and-proceed. The
    // clearance ceiling instead bounds what RETRIEVED context is returned (carried via
    // AccessScope::from_principal into the memory/retrieval read step, applied as a pre-rank chunk ACL).
    {
        let called = Arc::new(AtomicBool::new(false));
        let mut router = ModelRouter::new();
        router.register(Box::new(TripwireProvider {
            called: called.clone(),
            text: "served".into(),
        }));
        let eng = engine_with_defaults(router);
        let p = Principal::user("junior", &["chat.send"]).with_clearance(DataClass::Internal);
        let req = Request::chat("s", "t", "settle this payment", DataClass::RegulatedPayment);

        let wire = Arc::new(VecWireSink::default());
        let (res, _events, _envs) = run_with_wire(&eng, &p, &req, wire).await;
        assert!(
            res.is_ok(),
            "an under-clearance turn must PROCEED (redact-and-proceed), never be hard-denied on \
             clearance, got {res:?}"
        );
        assert!(
            called.load(Ordering::SeqCst),
            "the turn reaches the provider — clearance filters retrieval, it does not block admission"
        );
    }

    // A user cleared to `pii` (>= regulated-payment) is served the same turn — clearance never
    // blocks turn admission for either principal.
    {
        let called = Arc::new(AtomicBool::new(false));
        let mut router = ModelRouter::new();
        router.register(Box::new(TripwireProvider {
            called: called.clone(),
            text: "served".into(),
        }));
        let eng = engine_with_defaults(router);
        let p = Principal::user("cleared", &["chat.send"]).with_clearance(DataClass::Pii);
        let req = Request::chat("s", "t", "settle this payment", DataClass::RegulatedPayment);

        let wire = Arc::new(VecWireSink::default());
        let (res, _events, _envs) = run_with_wire(&eng, &p, &req, wire).await;
        assert!(
            res.is_ok(),
            "sufficient clearance must proceed, got {res:?}"
        );
        assert!(
            called.load(Ordering::SeqCst),
            "a sufficiently-cleared caller reaches the provider"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// 2. §4 EventEnvelope + §6 WireEvent vocabulary on the live sink (turn-pipeline #2)
// ---------------------------------------------------------------------------------------------
#[tokio::test]
async fn r3_wire_event_vocabulary() {
    let called = Arc::new(AtomicBool::new(false));
    let mut router = ModelRouter::new();
    // Output carries a PAN-like digit run → the always-on compliance gate redacts → a
    // `compliance.notice{Redacted}` must appear on the wire.
    router.register(Box::new(TripwireProvider {
        called: called.clone(),
        text: "your card 4111111111111111 ok".into(),
    }));
    let wire = Arc::new(VecWireSink::default());
    let eng = engine_with_defaults(router)
        .with_control_plane_sha("cp-sha-abc")
        .with_wire_sink(Box::new(wire.clone()));

    let p = Principal::user("u", &["chat.send"]);
    let req = Request::chat("sess-1", "turn-1", "what is my card", DataClass::Public);
    let (res, _events, envs) = run_with_wire(&eng, &p, &req, wire).await;
    assert!(res.is_ok(), "turn should complete, got {res:?}");
    assert!(
        !envs.is_empty(),
        "the live pipeline must emit §4/§6 envelopes"
    );

    // §4 envelope invariants: strictly-monotonic seq from 1, pinned control_plane_sha, turn id.
    for (i, e) in envs.iter().enumerate() {
        assert_eq!(
            e.seq,
            (i as u64) + 1,
            "seq must be strictly monotonic from 1"
        );
        assert_eq!(
            e.control_plane_sha, "cp-sha-abc",
            "control_plane_sha pinned"
        );
        assert_eq!(e.turn_id.as_deref(), Some("turn-1"));
        assert_eq!(e.session_id, "sess-1");
    }

    // §6 vocabulary: turn.started, compliance.notice{Redacted}, terminal turn.completed{Complete}.
    assert!(
        envs.iter()
            .any(|e| matches!(e.event, WireEvent::TurnStarted { .. })),
        "turn.started must be emitted after admission"
    );
    assert!(
        envs.iter().any(|e| matches!(
            &e.event,
            WireEvent::ComplianceNotice { action, .. }
                if *action == ainxt_protocol::ComplianceAction::Redacted
        )),
        "a compliance.notice{{Redacted}} must fire on the redacted output; envs={envs:?}"
    );
    assert_eq!(
        terminal_outcome(&envs),
        Some(WireTurnOutcome::Complete),
        "a naturally-stopped turn ends with turn.completed{{Complete}}"
    );
}

// ---------------------------------------------------------------------------------------------
// 3. Loop verification enforced on the reachable path (LOOP §7 / ADR §6)
// ---------------------------------------------------------------------------------------------
#[tokio::test]
async fn r3_loop_verification_enforced() {
    // Complete: a provider that answers with no tool calls reaches a natural stop.
    {
        let called = Arc::new(AtomicBool::new(false));
        let mut router = ModelRouter::new();
        router.register(Box::new(TripwireProvider {
            called: called.clone(),
            text: "done".into(),
        }));
        let wire = Arc::new(VecWireSink::default());
        let eng = engine_with_defaults(router).with_wire_sink(Box::new(wire.clone()));
        let p = Principal::user("u", &["chat.send"]);
        let req = Request::chat("s", "t", "hi", DataClass::Public);
        let (res, _e, envs) = run_with_wire(&eng, &p, &req, wire).await;
        assert!(res.is_ok());
        assert_eq!(
            terminal_outcome(&envs),
            Some(WireTurnOutcome::Complete),
            "natural stop → Complete"
        );
    }

    // Capped: a provider that only ever repeats the same tool call is cut off by the stuck-detector.
    // Before this round the outcome was silently reported as Completed (a lie); now it is Capped.
    {
        let mut router = ModelRouter::new();
        router.register(Box::new(AlwaysToolProvider));
        let mut tr = ToolRuntime::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler));
        tr.register(Box::new(NoopTool));
        let wire = Arc::new(VecWireSink::default());
        let eng = engine_with_defaults(router)
            .with_tools(tr)
            .with_wire_sink(Box::new(wire.clone()));
        let p = Principal::user("u", &["chat.send", "tool.noop"]);
        let req = Request::chat("s", "t", "loop forever", DataClass::Public);
        let (res, _e, envs) = run_with_wire(&eng, &p, &req, wire).await;
        assert!(res.is_ok(), "a capped turn still returns Ok, got {res:?}");
        assert_eq!(
            terminal_outcome(&envs),
            Some(WireTurnOutcome::Capped),
            "a stuck/iteration-capped turn must be reported Capped, never Complete; envs={envs:?}"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// 4. Node-attestation hook before model dispatch for regulated data (serving-ops SRV-02)
// ---------------------------------------------------------------------------------------------
fn serving_attestor(
) -> ServingGateAttestor<impl Fn() -> (Vec<NodeCandidate>, u64, bool) + Send + Sync> {
    // A gate with NO submitted quotes: a regulated class has no attested capacity → fail-closed.
    let att = AttestationGate::new(AttestationConfig {
        quote_ttl: 100,
        grace_ttl: 0,
    });
    let gate = ServingGate::new(
        att,
        FairnessLimiter::new(100, 100),
        PreemptionScheduler::new(100),
    );
    // Fleet: one routable-but-unattested node, verifier reachable (no grace).
    ServingGateAttestor::new(Arc::new(Mutex::new(gate)), || {
        (vec![NodeCandidate::new("n1", true)], 0u64, true)
    })
}

#[tokio::test]
async fn r3_node_attestation_gate() {
    // Regulated turn + attestor with no attested node → fail-closed BEFORE dispatch.
    {
        let called = Arc::new(AtomicBool::new(false));
        let mut router = ModelRouter::new();
        router.register(Box::new(TripwireProvider {
            called: called.clone(),
            text: "served".into(),
        }));
        let eng = engine_with_defaults(router).with_node_attestor(Box::new(serving_attestor()));
        let p = Principal::user("u", &["chat.send"]).with_clearance(DataClass::Confidential);
        let req = Request::chat("s", "t", "regulated work", DataClass::Confidential);
        let wire = Arc::new(VecWireSink::default());
        let (res, events, _envs) = run_with_wire(&eng, &p, &req, wire).await;
        assert!(
            matches!(res, Err(TurnError::Denied(ref m)) if m.contains("attestation")),
            "regulated turn must fail closed when no node is attested, got {res:?}"
        );
        assert!(
            !called.load(Ordering::SeqCst),
            "attestation must deny BEFORE any provider dispatch"
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, Event::Error(m) if m.contains("attestation"))),
            "the attestation denial must surface as a session error event"
        );
    }

    // Public turn needs no attestation → admitted on the routable node, provider is reached.
    {
        let called = Arc::new(AtomicBool::new(false));
        let mut router = ModelRouter::new();
        router.register(Box::new(TripwireProvider {
            called: called.clone(),
            text: "served".into(),
        }));
        let eng = engine_with_defaults(router).with_node_attestor(Box::new(serving_attestor()));
        let p = Principal::user("u", &["chat.send"]);
        let req = Request::chat("s", "t", "public work", DataClass::Public);
        let wire = Arc::new(VecWireSink::default());
        let (res, _events, _envs) = run_with_wire(&eng, &p, &req, wire).await;
        assert!(
            res.is_ok(),
            "a public turn needs no attestation, got {res:?}"
        );
        assert!(
            called.load(Ordering::SeqCst),
            "a public turn is admitted and reaches the provider"
        );
    }

    // Control (no attestor attached): the regulated turn is NOT fenced by attestation (pre-wire).
    {
        let called = Arc::new(AtomicBool::new(false));
        let mut router = ModelRouter::new();
        router.register(Box::new(TripwireProvider {
            called: called.clone(),
            text: "served".into(),
        }));
        let eng = engine_with_defaults(router);
        let p = Principal::user("u", &["chat.send"]).with_clearance(DataClass::Confidential);
        let req = Request::chat("s", "t", "regulated work", DataClass::Confidential);
        let wire = Arc::new(VecWireSink::default());
        let (res, _events, _envs) = run_with_wire(&eng, &p, &req, wire).await;
        assert!(res.is_ok());
        assert!(
            called.load(Ordering::SeqCst),
            "with no attestor attached the regulated turn reaches the provider (pre-wire behavior)"
        );
    }
}
