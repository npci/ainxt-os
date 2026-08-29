// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R16 CRITICAL — compliance-OUT on the served chat SHORT-CIRCUIT (`turn-pipeline`).
//!
//! `run_turn_streaming` answers some turns without ever calling `Engine::run_turn_cancellable`:
//! a Stage-3 clarification, a doc-generation echo, and a content-consuming action all resolve to a
//! terminal string and return early. Before this round that early return sent the text straight to
//! the sink and appended it to session history, so the whole §1 tail — compliance-OUT (step 8) and
//! the mandatory audit record (step 10) — was skipped for those turns.
//!
//! That is not a theoretical hole. The terminal text is resolved from the user's OWN prior turn
//! (`ContentSource::Explicit`/`Referent`), so "the model did not write it" is no defence: paste a
//! PAN, ask for it as a document, and the PAN reached the wire verbatim AND was written into
//! history, where every later context read re-served it.
//!
//! FAIL-BEFORE: against the previous code `streamed` is the raw input, so the digits survive and
//! `summary.redactions` is the hardcoded `0` — both assertions below fail.
//! PASS-AFTER: the short-circuit runs the engine's mandatory gate, redacts, and proceeds.

use ainxt_convo::{ConversationManager, HeuristicClassifier};
use ainxt_protocol::{Event, Request};
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_runtime::{engine_with_defaults, CancelToken};
use ainxt_types::{DataClass, Principal};
use tokio::sync::mpsc;

/// A provider that must NEVER be reached on a short-circuited turn.
struct UnusedProvider;
impl Provider for UnusedProvider {
    fn id(&self) -> &str {
        "unused"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, _prompt: &str) -> mpsc::Receiver<Event> {
        let (tx, rx) = mpsc::channel(8);
        tokio::spawn(async move {
            let _ = tx
                .send(Event::TextDelta("PROVIDER-WAS-CALLED".into()))
                .await;
            let _ = tx.send(Event::Done).await;
        });
        rx
    }
}

fn user() -> Principal {
    Principal::user("analyst", &["chat.send"]).with_clearance(DataClass::Public)
}

fn manager() -> ConversationManager<HeuristicClassifier> {
    let mut router = ModelRouter::new();
    router.register(Box::new(UnusedProvider));
    ConversationManager::new(engine_with_defaults(router), HeuristicClassifier)
}

/// Drive one streaming turn on an existing manager; return (streamed_text, summary).
async fn stream_on(
    m: &ConversationManager<HeuristicClassifier>,
    session: &str,
    turn: &str,
    input: &str,
) -> (String, ainxt_runtime::TurnSummary) {
    let (tx, mut rx) = mpsc::channel::<Event>(32);
    let cancel = CancelToken::new();
    let req = Request::chat(session, turn, input, DataClass::Public);
    let summary = m
        .run_turn_streaming(&user(), &req, tx, &cancel)
        .await
        .expect("streaming turn");
    let mut streamed = String::new();
    while let Some(ev) = rx.recv().await {
        if let Event::TextDelta(t) = ev {
            streamed.push_str(&t);
        }
    }
    (streamed, summary)
}

/// A PAN-like digit run the placeholder compliance gate collapses. Kept as a synthetic,
/// never-issued test number.
const PAN: &str = "4111111111111111";

#[tokio::test]
async fn r16_doc_generation_short_circuit_runs_compliance_out() {
    let m = manager();
    // The user pastes card data and asks for it back as a document — the doc-generation
    // short-circuit echoes the resolved content without ever reaching a provider. No anaphora in
    // the phrasing, so `resolve_content` takes the explicit "…: <content>" branch rather than
    // looking for a referent.
    let input = format!("generate a pdf: cardholder record {PAN}");
    let (streamed, summary) = stream_on(&m, "s-doc", "t1", &input).await;

    assert!(
        !streamed.contains(PAN),
        "the short-circuit put an un-redacted PAN on the wire: {streamed:?}"
    );
    assert!(
        summary.redactions > 0,
        "compliance-OUT did not run on the short-circuit (redactions reported as {})",
        summary.redactions
    );
    // Redact and PROCEED: the user still gets an answer, not a refusal.
    assert!(
        !streamed.trim().is_empty(),
        "compliance must redact and proceed, never blank the turn"
    );
    assert_ne!(
        streamed, "PROVIDER-WAS-CALLED",
        "this turn must still short-circuit (the test would otherwise prove nothing)"
    );
}

#[tokio::test]
async fn r16_short_circuit_writes_redacted_text_to_history_not_the_raw_span() {
    let m = manager();
    let input = format!("generate a pdf: cardholder record {PAN}");
    let (_, _) = stream_on(&m, "s-hist", "t1", &input).await;

    // History is re-read as context on every later turn. An unsafe span stored here would be
    // re-served past the gate on each one — a leak that repeats forever rather than once.
    let history = m.history("s-hist");
    let assistant: Vec<&str> = history
        .iter()
        .filter(|m| matches!(m.role, ainxt_convo::Role::Assistant))
        .map(|m| m.text.as_str())
        .collect();
    assert!(
        !assistant.is_empty(),
        "the short-circuit answer must still be recorded in history"
    );
    assert!(
        assistant.iter().all(|t| !t.contains(PAN)),
        "an un-redacted PAN was written into session history: {assistant:?}"
    );
}

#[tokio::test]
async fn r16_clarify_short_circuit_is_also_gated() {
    let m = manager();
    // An ambiguous doc-gen request with no resolvable referent yields the Stage-3 clarification
    // branch — a different early return, which must be gated too.
    let (streamed, _) = stream_on(&m, "s-clar", "t1", "make it a pdf").await;
    assert!(
        !streamed.trim().is_empty(),
        "a clarification must still be produced"
    );
    assert!(
        !streamed.contains(PAN),
        "clarification leaked card data: {streamed:?}"
    );
}

#[tokio::test]
async fn r16_benign_short_circuit_is_untouched_and_reports_zero_redactions() {
    let m = manager();
    // Nothing unsafe in this turn: the gate must be a no-op, not a mangler. Proves the redaction
    // above comes from the detector firing, not from the short-circuit garbling every answer.
    let (streamed, summary) =
        stream_on(&m, "s-ok", "t1", "generate a pdf: quarterly summary text").await;
    assert_eq!(
        summary.redactions, 0,
        "a benign short-circuit must not report redactions"
    );
    assert!(
        streamed.contains("quarterly summary"),
        "benign content was altered by the gate: {streamed:?}"
    );
}
