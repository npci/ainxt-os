// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-11 turn-pipeline gaps:
//!
//! HIGH — §6 wire `text.delta` was DROPPED when output guardrails buffer. With output rails active
//! the engine buffers the whole answer and releases it only via the LEGACY `Event` sink; it never
//! emitted `WireEvent::TextDelta` on the §6 wire, so a wire-only consumer received a turn with a
//! `turn.completed` but NO assistant text. `r11_wire_text_delta_arrives_with_guardrails_on` attaches
//! a wire sink WITH guardrails on and asserts the buffered final answer arrives as `text.delta`.
//! FAIL-BEFORE: the release arms sent only `sink.send(Event::TextDelta ..)`; PASS-AFTER: they also
//! `wire.emit(WireEvent::TextDelta ..)`.
//!
//! MEDIUM — a bounded-inflight backpressure ADMISSION seam producing `ErrorCategory::Capacity`
//! (`r11_capacity_admission_typed_503`). Additive; the engine's own gates are untouched.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use ainxt_protocol::{ErrorCategory, Event, Request, WireEvent};
use ainxt_runtime::capacity::{CapacityGate, InflightGate};
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_runtime::wire::VecWireSink;
use ainxt_runtime::{engine_with_defaults, GuardrailsConfig, RailMode};
use ainxt_types::{DataClass, Principal};
use tokio::sync::mpsc;

struct FixedAnswer {
    answer: String,
    called: Arc<AtomicBool>,
}
impl Provider for FixedAnswer {
    fn id(&self) -> &str {
        "prov"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, _prompt: &str) -> mpsc::Receiver<Event> {
        self.called.store(true, Ordering::SeqCst);
        let (tx, rx) = mpsc::channel(8);
        let answer = self.answer.clone();
        tokio::spawn(async move {
            let _ = tx.send(Event::TextDelta(answer)).await;
            let _ = tx.send(Event::Done).await;
        });
        rx
    }
}

fn principal() -> Principal {
    Principal::user("u", &["chat.send"])
}

// ---------------------------------------------------------------------------
// HIGH — wire text.delta must arrive even when output guardrails buffer the answer.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn r11_wire_text_delta_arrives_with_guardrails_on() {
    const ANSWER: &str = "the weekly UPI settlement report is ready for review";

    // Output rail active (toxicity=Enforce) => buffer_output is TRUE. The answer is benign so it is
    // Allowed and released via the buffered path — exactly the path that previously dropped the wire
    // text.delta.
    let cfg = GuardrailsConfig {
        toxicity: RailMode::Enforce,
        ..Default::default()
    };

    let called = Arc::new(AtomicBool::new(false));
    let mut router = ModelRouter::new();
    router.register(Box::new(FixedAnswer {
        answer: ANSWER.into(),
        called: called.clone(),
    }));

    // Attach a wire sink WITH guardrails on.
    let wire = Arc::new(VecWireSink::default());
    let eng = engine_with_defaults(router)
        .with_guardrails(&cfg)
        .with_wire_sink(Box::new(Arc::clone(&wire)));

    let (tx, mut rx) = mpsc::channel(64);
    let summary = eng
        .run_turn(
            &principal(),
            &Request::chat("s", "t", "status?", DataClass::Public),
            tx,
        )
        .await
        .expect("turn completes");

    // Drain the legacy stream so the turn task finishes.
    let mut legacy_text = String::new();
    while let Some(ev) = rx.recv().await {
        if let Event::TextDelta(t) = ev {
            legacy_text.push_str(&t);
        }
    }

    assert!(called.load(Ordering::SeqCst), "the provider must have run");
    assert_eq!(
        summary.provider, "prov",
        "benign answer must not be blocked"
    );
    assert_eq!(legacy_text, ANSWER, "legacy sink still gets the answer");

    // THE FIX: the buffered final answer must ALSO have been emitted on the §6 wire as text.delta.
    let envs = wire.snapshot();
    let wire_text: String = envs
        .iter()
        .filter_map(|e| match &e.event {
            WireEvent::TextDelta { text } => Some(text.clone()),
            _ => None,
        })
        .collect();
    assert!(
        !wire_text.is_empty(),
        "REGRESSION: wire text.delta was DROPPED when output guardrails buffered the answer; \
         a wire-only consumer got no assistant text. envelopes={:?}",
        envs.iter().map(|e| &e.event).collect::<Vec<_>>()
    );
    assert!(
        wire_text.contains(ANSWER),
        "the wire text.delta must carry the full buffered answer; got {wire_text:?}"
    );
    // And the turn still terminates on the wire.
    assert!(
        envs.iter()
            .any(|e| matches!(e.event, WireEvent::TurnCompleted { .. })),
        "the turn must still complete on the wire"
    );
}

// Control: with guardrails OFF (no buffering) the wire text.delta must still arrive — proves the fix
// did not regress the streaming path.
#[tokio::test]
async fn r11_wire_text_delta_arrives_without_guardrails() {
    const ANSWER: &str = "hello from the streaming path";
    let called = Arc::new(AtomicBool::new(false));
    let mut router = ModelRouter::new();
    router.register(Box::new(FixedAnswer {
        answer: ANSWER.into(),
        called: called.clone(),
    }));
    let wire = Arc::new(VecWireSink::default());
    let eng = engine_with_defaults(router).with_wire_sink(Box::new(Arc::clone(&wire)));

    let (tx, mut rx) = mpsc::channel(64);
    eng.run_turn(
        &principal(),
        &Request::chat("s", "t", "hi", DataClass::Public),
        tx,
    )
    .await
    .expect("turn completes");
    while rx.recv().await.is_some() {}

    let wire_text: String = wire
        .snapshot()
        .iter()
        .filter_map(|e| match &e.event {
            WireEvent::TextDelta { text } => Some(text.clone()),
            _ => None,
        })
        .collect();
    assert!(wire_text.contains(ANSWER), "streaming wire path unchanged");
}

// ---------------------------------------------------------------------------
// MEDIUM — bounded-inflight capacity admission seam → typed ErrorCategory::Capacity.
// ---------------------------------------------------------------------------
#[test]
fn r11_capacity_admission_typed_503() {
    let gate = InflightGate::new(2);
    assert_eq!(gate.capacity(), 2);
    assert_eq!(gate.inflight(), 0);

    // Admit up to the ceiling.
    let p1 = gate.try_admit().expect("1st admits");
    let p2 = gate.try_admit().expect("2nd admits");
    assert_eq!(gate.inflight(), 2);

    // The 3rd is refused with a TYPED Capacity (retryable 503) error.
    let err = gate
        .try_admit()
        .expect_err("3rd must be refused at capacity");
    assert_eq!(
        err.category,
        ErrorCategory::Capacity,
        "backpressure refusal must carry the typed Capacity category"
    );
    assert!(
        err.category.retryable_default(),
        "a Capacity refusal must be retryable"
    );
    // A rejected admission must NOT consume a slot.
    assert_eq!(gate.inflight(), 2, "a refused admit must not leak a slot");

    // Releasing a permit (RAII on drop) frees a slot for the next turn.
    drop(p1);
    assert_eq!(gate.inflight(), 1);
    let p3 = gate.try_admit().expect("slot freed => admits again");
    assert_eq!(gate.inflight(), 2);

    drop(p2);
    drop(p3);
    assert_eq!(gate.inflight(), 0, "all permits released => fully drained");
}

// A clone of the gate shares ONE global ceiling (the session layer hands clones to N tasks).
#[test]
fn r11_capacity_gate_shared_across_clones() {
    let gate = InflightGate::new(1);
    let clone = gate.clone();
    let _p = gate.try_admit().expect("admits on original");
    let err = clone
        .try_admit()
        .expect_err("clone shares the same counter => at capacity");
    assert_eq!(err.category, ErrorCategory::Capacity);
    assert_eq!(clone.inflight(), 1, "one global inflight across clones");
}

// max == 0 => unbounded (the explicit "no ceiling" configuration; pre-wire behavior).
#[test]
fn r11_capacity_unbounded_when_zero() {
    let gate = InflightGate::new(0);
    let mut permits = Vec::new();
    for _ in 0..1000 {
        permits.push(gate.try_admit().expect("unbounded never refuses"));
    }
    assert_eq!(gate.inflight(), 1000);
}
