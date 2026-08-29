// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-12 turn-pipeline gap closure (runtime engine, `Engine::run_turn_cancellable`).
//!
//! Three additive fixes, each proven fail-before / pass-after. All existing mandatory gates
//! (compliance / authz / audit) and the shipped-chat guard are untouched.
//!
//!  (1) MEDIUM — an authorization DENY at step 2 is now written to the MANDATORY audit sink (it was
//!      only fed to `emit_metrics`). A refused turn is a governance/forensic event; it must appear
//!      in the tamper-evident trail. `r12_authz_deny_is_audited`.
//!
//!  (2) LOW — a provider-supplied `Event::Error` string is routed through compliance-OUT
//!      (`scan_outbound_event`) before re-emit, so an error that echoes a PAN/secret can never
//!      become an exfiltration channel. `r12_provider_error_is_scanned_out` (terminal path) and
//!      `r12_all_providers_failed_error_is_scanned_out` (failover-exhausted path).
//!
//!  (3) MEDIUM — the bounded-inflight backpressure ADMISSION seam is now invoked FIRST inside the
//!      turn engine: an over-capacity turn is refused up front with the typed
//!      `ErrorCategory::Capacity` (surfaced as `TurnError::Capacity`) and NO provider is contacted.
//!      `r12_over_capacity_turn_is_refused_typed`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use ainxt_protocol::{Event, Request, WireEvent};
use ainxt_runtime::audit::{AuditRecord, AuditSink};
use ainxt_runtime::authz::RbacAuthorizer;
use ainxt_runtime::capacity::{CapacityGate, InflightGate};
use ainxt_runtime::compliance::RedactAndProceed;
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_runtime::wire::VecWireSink;
use ainxt_runtime::{Engine, TurnError};
use ainxt_types::{DataClass, Principal};
use std::sync::Arc as StdArc;
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// Records whether it was ever asked to stream (so a test can prove a turn was refused BEFORE any
/// provider dispatch). Emits an optional scripted prefix then a scripted error, else a plain answer.
struct ScriptProvider {
    called: Arc<AtomicBool>,
    prefix: Option<String>,
    error: Option<String>,
    answer: String,
}

impl ScriptProvider {
    fn answering(answer: &str, called: Arc<AtomicBool>) -> Self {
        Self {
            called,
            prefix: None,
            error: None,
            answer: answer.into(),
        }
    }
}

impl Provider for ScriptProvider {
    fn id(&self) -> &str {
        "prov"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, _prompt: &str) -> mpsc::Receiver<Event> {
        self.called.store(true, Ordering::SeqCst);
        let (tx, rx) = mpsc::channel(8);
        let prefix = self.prefix.clone();
        let error = self.error.clone();
        let answer = self.answer.clone();
        tokio::spawn(async move {
            if let Some(p) = prefix {
                let _ = tx.send(Event::TextDelta(p)).await;
            }
            if let Some(e) = error {
                let _ = tx.send(Event::Error(e)).await;
            } else {
                let _ = tx.send(Event::TextDelta(answer)).await;
            }
            let _ = tx.send(Event::Done).await;
        });
        rx
    }
}

#[derive(Clone, Default)]
struct SharedAudit(Arc<Mutex<Vec<String>>>);
impl AuditSink for SharedAudit {
    fn record(&self, rec: AuditRecord) {
        self.0.lock().unwrap().push(rec.summary);
    }
}

fn router_with(prov: ScriptProvider) -> ModelRouter {
    let mut r = ModelRouter::new();
    r.register(Box::new(prov));
    r
}

fn engine_with(prov: ScriptProvider, audit: SharedAudit) -> Engine {
    Engine::new(
        Box::new(RedactAndProceed),
        Box::new(RbacAuthorizer),
        Box::new(audit),
        router_with(prov),
    )
}

fn req() -> Request {
    Request::chat("s", "t", "hello", DataClass::Public)
}

/// Run a turn and return (result, streamed events) WITHOUT collapsing an Err (unlike
/// `run_turn_collect`, which drops events on `Err`). Drains concurrently so the sink never blocks.
async fn run(engine: &Engine, p: &Principal) -> (Result<(), TurnError>, Vec<Event>) {
    let (tx, mut rx) = mpsc::channel::<Event>(64);
    let request = req();
    let run = engine.run_turn(p, &request, tx);
    let collect = async move {
        let mut v = Vec::new();
        while let Some(e) = rx.recv().await {
            v.push(e);
        }
        v
    };
    let (res, events) = tokio::join!(run, collect);
    (res.map(|_| ()), events)
}

// ---------------------------------------------------------------------------
// (1) authz DENY is written to the mandatory audit sink
// ---------------------------------------------------------------------------
#[tokio::test]
async fn r12_authz_deny_is_audited() {
    let called = Arc::new(AtomicBool::new(false));
    let audit = SharedAudit::default();
    let engine = engine_with(
        ScriptProvider::answering("ok", called.clone()),
        audit.clone(),
    );

    // A user WITHOUT `chat.send` (has an unrelated cap) is denied turn admission at step 2.
    let denied = Principal::user("mallory", &["tool.lookup"]);
    let (res, _events) = run(&engine, &denied).await;

    assert!(
        matches!(res, Err(TurnError::Denied(_))),
        "a principal lacking chat.send must be denied: {res:?}"
    );
    assert!(
        !called.load(Ordering::SeqCst),
        "a denied turn must never reach a provider"
    );

    let records = audit.0.lock().unwrap().clone();
    // THE FIX: the denial is in the mandatory audit trail (fail-before: only emit_metrics ran).
    assert!(
        records
            .iter()
            .any(|s| s.contains("authz denied turn at step 2")),
        "an authz DENY must be written to the audit sink; got {records:?}"
    );

    // Control: an authorized user is NOT audited as denied and DOES reach the provider.
    let called2 = Arc::new(AtomicBool::new(false));
    let audit2 = SharedAudit::default();
    let engine2 = engine_with(
        ScriptProvider::answering("ok", called2.clone()),
        audit2.clone(),
    );
    let ok = Principal::user("alice", &["chat.send"]);
    let (res2, _e2) = run(&engine2, &ok).await;
    assert!(res2.is_ok(), "authorized turn completes: {res2:?}");
    assert!(called2.load(Ordering::SeqCst), "authorized turn runs");
    assert!(
        !audit2
            .0
            .lock()
            .unwrap()
            .iter()
            .any(|s| s.contains("authz denied")),
        "an authorized turn must NOT record an authz denial"
    );
}

// ---------------------------------------------------------------------------
// (2) provider Error string is passed through compliance-OUT before re-emit
// ---------------------------------------------------------------------------
#[tokio::test]
async fn r12_provider_error_is_scanned_out() {
    // Partial output THEN a terminal error whose text echoes a 16-digit PAN — the terminal_error
    // re-emit path. Partial output makes it non-failoverable (produced == true).
    let pan = "4111111111111111";
    let called = Arc::new(AtomicBool::new(false));
    let audit = SharedAudit::default();
    let mut prov = ScriptProvider::answering("", called.clone());
    prov.prefix = Some("working... ".into());
    prov.error = Some(format!("upstream rejected card {pan} — declined"));
    let engine = engine_with(prov, audit);

    let (res, events) = run(&engine, &Principal::user("u", &["chat.send"])).await;
    assert!(
        res.is_ok(),
        "redact-and-proceed: the turn ends cleanly: {res:?}"
    );

    let err_text: String = events
        .iter()
        .filter_map(|e| match e {
            Event::Error(m) => Some(m.clone()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join(" | ");
    assert!(!err_text.is_empty(), "an error event must be surfaced");
    // THE FIX: the raw PAN must NOT leak in the error; it is redacted by compliance-OUT.
    assert!(
        !err_text.contains(pan),
        "provider error text reached the sink with a RAW PAN (compliance-OUT bypassed): {err_text:?}"
    );
    assert!(
        err_text.contains("[REDACTED-PAN]"),
        "the PAN in the provider error must be redacted: {err_text:?}"
    );
}

#[tokio::test]
async fn r12_all_providers_failed_error_is_scanned_out() {
    // No partial output → the error is not terminal-on-produce; the single provider is a
    // non-retryable failure → the "all eligible providers failed: {msg}" path, which also carries
    // provider-supplied text and must be scanned.
    let pan = "4111111111111111";
    let called = Arc::new(AtomicBool::new(false));
    let audit = SharedAudit::default();
    let mut prov = ScriptProvider::answering("", called.clone());
    prov.error = Some(format!("fatal: token {pan} invalid"));
    let engine = engine_with(prov, audit);

    let (_res, events) = run(&engine, &Principal::user("u", &["chat.send"])).await;
    let err_text: String = events
        .iter()
        .filter_map(|e| match e {
            Event::Error(m) => Some(m.clone()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join(" | ");
    assert!(
        err_text.contains("all eligible providers failed"),
        "the aggregate error must be the one surfaced: {err_text:?}"
    );
    assert!(
        !err_text.contains(pan),
        "the aggregate error leaked a RAW PAN (compliance-OUT bypassed): {err_text:?}"
    );
    assert!(
        err_text.contains("[REDACTED-PAN]"),
        "the PAN in the aggregate error must be redacted: {err_text:?}"
    );
}

// ---------------------------------------------------------------------------
// (bonus/low) §6 turn.rationale is now emitted on the wire (was defined but never emitted)
// ---------------------------------------------------------------------------
#[tokio::test]
async fn r12_turn_rationale_emitted_on_wire() {
    let called = Arc::new(AtomicBool::new(false));
    let wire = StdArc::new(VecWireSink::default());
    let engine = Engine::new(
        Box::new(RedactAndProceed),
        Box::new(RbacAuthorizer),
        Box::new(SharedAudit::default()),
        router_with(ScriptProvider::answering("the answer", called.clone())),
    )
    .with_wire_sink(Box::new(StdArc::clone(&wire)));

    let (tx, mut rx) = mpsc::channel::<Event>(64);
    let request = req();
    let p = Principal::user("u", &["chat.send"]);
    let run = engine.run_turn(&p, &request, tx);
    let drain = async move { while rx.recv().await.is_some() {} };
    let (res, _) = tokio::join!(run, drain);
    res.expect("turn completes");

    let envs = wire.snapshot();
    // THE FIX: a turn.rationale envelope is emitted, naming the routed model (audit-grade "why this").
    let rationale = envs.iter().find_map(|e| match &e.event {
        WireEvent::TurnRationale {
            model, model_tier, ..
        } => Some((model.clone(), model_tier.clone())),
        _ => None,
    });
    let (model, tier) = rationale.expect("a turn.rationale must be emitted on the wire");
    assert_eq!(model, "prov", "rationale names the ACTUALLY-routed model");
    assert!(!tier.is_empty(), "rationale carries a model tier");
    // It must precede turn.completed (the panel describes the turn that just completed).
    let idx_rat = envs
        .iter()
        .position(|e| matches!(e.event, WireEvent::TurnRationale { .. }));
    let idx_done = envs
        .iter()
        .position(|e| matches!(e.event, WireEvent::TurnCompleted { .. }));
    assert!(
        idx_rat < idx_done,
        "turn.rationale must be emitted before turn.completed"
    );
}

// ---------------------------------------------------------------------------
// (3) over-capacity turn is refused up front with the typed Capacity error
// ---------------------------------------------------------------------------
#[tokio::test]
async fn r12_over_capacity_turn_is_refused_typed() {
    // A gate bounded at 1. Occupy the only slot with a held permit (a clone shares the counter),
    // then hand the SAME gate to the engine. The turn must be refused BEFORE any provider runs.
    let gate = InflightGate::new(1);
    let _held = gate.try_admit().expect("occupy the single slot");
    assert_eq!(gate.inflight(), 1);

    let called = Arc::new(AtomicBool::new(false));
    let audit = SharedAudit::default();
    let engine = engine_with(
        ScriptProvider::answering("ok", called.clone()),
        audit.clone(),
    )
    .with_capacity_gate(Box::new(gate.clone()));

    let (res, events) = run(&engine, &Principal::user("u", &["chat.send"])).await;

    assert!(
        matches!(res, Err(TurnError::Capacity(_))),
        "an over-capacity turn must return the typed Capacity error: {res:?}"
    );
    assert!(
        !called.load(Ordering::SeqCst),
        "a capacity-refused turn must NEVER contact a provider"
    );
    assert!(
        events.iter().any(|e| matches!(e, Event::Error(_))),
        "the refusal must be surfaced as an error event"
    );
    assert!(
        audit
            .0
            .lock()
            .unwrap()
            .iter()
            .any(|s| s.contains("backpressure admission refused")),
        "the capacity refusal must be audited"
    );

    // The refused turn must not have consumed a slot (only the held permit occupies it).
    assert_eq!(gate.inflight(), 1, "a refused admit must not leak a slot");

    // Releasing the held permit frees the slot → the next turn admits and runs.
    drop(_held);
    assert_eq!(gate.inflight(), 0);
    let called2 = Arc::new(AtomicBool::new(false));
    let engine2 = engine_with(
        ScriptProvider::answering("ok", called2.clone()),
        SharedAudit::default(),
    )
    .with_capacity_gate(Box::new(gate.clone()));
    let (res2, _e2) = run(&engine2, &Principal::user("u", &["chat.send"])).await;
    assert!(res2.is_ok(), "slot freed => turn admits: {res2:?}");
    assert!(
        called2.load(Ordering::SeqCst),
        "admitted turn runs the provider"
    );
    assert_eq!(
        gate.inflight(),
        0,
        "admitted turn released its slot on completion"
    );
}
