// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R3 — streaming-path parity with `handle()` for OUTPUT-side safety gates (gap CONV-01).
//!
//! `run_turn_streaming` is the impl backing the `TurnHandler` seam the daemon docks (`ChatSurface` →
//! `SessionManager`). Before this round it forwarded model tokens straight to the client with NO
//! call to the answer-path verifier / groundedness rail — so an unverified figure that `handle()`
//! would BLOCK could stream to the wire. These tests drive the REAL `ConversationManager` streaming
//! path and prove the fail-closed verifier now runs there too (fail-before / pass-after).

use ainxt_context::{Chunk, Corpus, LexicalRetriever};
use ainxt_convo::{AnswerVerifier, ConversationManager, HeuristicClassifier};
use ainxt_protocol::{Event, Request};
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_runtime::{engine_with_defaults, CancelToken};
use ainxt_types::{DataClass, Principal};
use tokio::sync::mpsc;

/// A provider that always emits one fixed answer (so we control exactly what the model "says").
struct FixedProvider(&'static str);
impl Provider for FixedProvider {
    fn id(&self) -> &str {
        "fixed"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, _prompt: &str) -> mpsc::Receiver<Event> {
        let (tx, rx) = mpsc::channel(8);
        let msg = self.0.to_string();
        tokio::spawn(async move {
            let _ = tx.send(Event::TextDelta(msg)).await;
            let _ = tx.send(Event::Done).await;
        });
        rx
    }
}

fn user() -> Principal {
    Principal::user("analyst", &["chat.send"]).with_clearance(DataClass::Public)
}

fn engine_with(p: impl Provider + 'static) -> ainxt_runtime::Engine {
    let mut router = ModelRouter::new();
    router.register(Box::new(p));
    engine_with_defaults(router)
}

fn upi_corpus() -> Corpus {
    Corpus::new().with(Chunk::new(
        "upi",
        "kb",
        "UPI settlement runs in nightly deferred-net cycles across member banks via the payment switch.",
        DataClass::Public,
    ))
}

/// Drive one streaming turn; return (streamed_text, summary_final_text).
async fn stream_turn(
    m: &ConversationManager<HeuristicClassifier>,
    input: &str,
) -> (String, String) {
    let (tx, mut rx) = mpsc::channel::<Event>(32);
    let cancel = CancelToken::new();
    let req = Request::chat("s", "t", input, DataClass::Public);
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
    (streamed, summary.final_text)
}

#[tokio::test]
async fn r3_streaming_output_gate_blocks_unverified_number() {
    let q = "how does UPI settlement run?";
    // An invented amount unsupported by any retrieved source → the numeric gate must BLOCK it.
    let bad = "The settlement total is 987654.";

    // WITH the verifier on the STREAMING path: the bad figure must NEVER reach the wire; the client
    // sees the escalation message instead. This is the parity the gap flagged as missing.
    let gated = ConversationManager::with_retriever(
        engine_with(FixedProvider(bad)),
        HeuristicClassifier,
        Box::new(LexicalRetriever::new(upi_corpus())),
    )
    .with_verifier(AnswerVerifier::new());
    let (streamed, final_text) = stream_turn(&gated, q).await;
    // The client receives the ESCALATION, not the model's answer. (The audit reason quotes the
    // offending claim, so the figure legitimately appears inside the escalation text — what matters
    // is that the model's answer was blocked and never presented AS an answer.)
    assert_ne!(
        streamed, bad,
        "the raw model answer must NOT be shipped verbatim"
    );
    assert!(
        streamed.contains("can't share")
            && (streamed.to_lowercase().contains("verification")
                || streamed.to_lowercase().contains("escalated")),
        "the streamed text must be the fail-closed escalation message: {streamed:?}"
    );
    assert_eq!(
        streamed, final_text,
        "the summary must match what was streamed"
    );

    // WITHOUT the verifier (the pre-wire behavior) the SAME bad figure streams straight through —
    // proving the gate is what blocks it, not some incidental difference.
    let ungated = ConversationManager::with_retriever(
        engine_with(FixedProvider(bad)),
        HeuristicClassifier,
        Box::new(LexicalRetriever::new(upi_corpus())),
    );
    let (streamed_ungated, _) = stream_turn(&ungated, q).await;
    assert!(
        streamed_ungated.contains("987654"),
        "without the verifier the unverified figure reaches the wire: {streamed_ungated:?}"
    );
}

#[tokio::test]
async fn r3_streaming_output_gate_passes_clean_grounded_answer() {
    let q = "how does UPI settlement run?";
    // A clean, grounded, number-free answer must still ship on the gated streaming path.
    let good = "UPI settlement runs in nightly cycles across member banks.";
    let gated = ConversationManager::with_retriever(
        engine_with(FixedProvider(good)),
        HeuristicClassifier,
        Box::new(LexicalRetriever::new(upi_corpus())),
    )
    .with_verifier(AnswerVerifier::new());
    let (streamed, _) = stream_turn(&gated, q).await;
    assert!(
        streamed.to_lowercase().contains("nightly cycles"),
        "a grounded, number-free answer must ship on the gated streaming path: {streamed:?}"
    );
    assert!(
        !streamed.to_lowercase().contains("verification"),
        "a clean answer must NOT be escalated: {streamed:?}"
    );
}
