// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX conversation-intelligence "conflict-arbitration discarded".
//!
//! `ainxt_synthesis::AnswerVerification::resolutions` carries EVERY detected cross-source
//! conflict plus its arbitration outcome (winner/loser/basis), computed regardless of
//! `VerificationPolicy::block_on_unresolved_conflict` — the served surface uses
//! `AnswerVerifier::numeric_gate_only()`, which never hard-blocks on a conflict. Before this fix,
//! `ConversationManager::handle`/`run_turn_streaming` only ever read `verification.blocked` (for
//! the ship/no-ship decision); `resolutions` was computed and then silently discarded, so a real
//! contradiction between two retrieved sources shipped with ZERO indication to the user that the
//! sources disagreed. These tests drive the REAL streaming path (the same one `ChatSurface` docks)
//! with a corpus containing a genuine numeric contradiction and prove the answer now carries a
//! disclosure caveat instead of shipping silently.

use ainxt_context::{Chunk, Corpus, LexicalRetriever};
use ainxt_convo::{AnswerVerifier, ConversationManager, HeuristicClassifier};
use ainxt_protocol::{Event, Request};
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_runtime::{engine_with_defaults, CancelToken};
use ainxt_types::{DataClass, Principal};
use tokio::sync::mpsc;

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

/// Two sources on the SAME subject (UPI transaction fee) asserting DIFFERENT numbers — the exact
/// shape `ainxt_synthesis::detect_conflicts`'s own unit test (`numeric_conflict_flagged_with_subject`)
/// proves is a genuine `ConflictKind::Numeric` contradiction.
fn conflicting_fee_corpus() -> Corpus {
    Corpus::new()
        .with(Chunk::new(
            "fee-a",
            "kb",
            "The UPI transaction fee is 5 rupees.",
            DataClass::Public,
        ))
        .with(Chunk::new(
            "fee-b",
            "kb",
            "The UPI transaction fee is 10 rupees.",
            DataClass::Public,
        ))
}

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
async fn r_conflict_arbitration_caveat_surfaces_on_streaming_path_instead_of_discarded() {
    // A clean, number-free model answer — the numeric gate has nothing of its own to fail on, so
    // whatever ships (or is caveated) is entirely down to the CROSS-SOURCE conflict, isolating the
    // exact mechanism this gap is about.
    let good = "UPI transactions are settled across member banks.";
    let m = ConversationManager::with_retriever(
        engine_with(FixedProvider(good)),
        HeuristicClassifier,
        Box::new(LexicalRetriever::new(conflicting_fee_corpus())),
    )
    // The served surface's actual policy (`build_chat_surface_wired_authz` /
    // `AnswerVerifier::numeric_gate_only`): does NOT hard-block on an unresolved conflict, so the
    // answer SHIPS — this is exactly the case where the discard bug fired.
    .with_verifier(AnswerVerifier::numeric_gate_only());

    let (streamed, final_text) = stream_turn(&m, "what is the UPI transaction fee?").await;

    assert!(
        streamed.contains(good),
        "a non-blocking policy must still ship the clean answer: {streamed:?}"
    );
    assert_eq!(streamed, final_text);
    assert!(
        !streamed.to_lowercase().contains("can't share"),
        "numeric_gate_only must not hard-block on a conflict: {streamed:?}"
    );
    // THE FIX: the arbitration outcome must be disclosed, not silently thrown away.
    assert!(
        streamed.to_lowercase().contains("disagree") || streamed.to_lowercase().contains("fee"),
        "the cross-source conflict arbitration must be surfaced as a caveat, not discarded: {streamed:?}"
    );
}

#[tokio::test]
async fn r_conflict_arbitration_no_caveat_when_sources_agree() {
    // Control: agreeing sources must never manufacture a spurious caveat.
    let corpus = Corpus::new().with(Chunk::new(
        "fee-a",
        "kb",
        "The UPI transaction fee is 5 rupees.",
        DataClass::Public,
    ));
    let good = "UPI transactions are settled across member banks.";
    let m = ConversationManager::with_retriever(
        engine_with(FixedProvider(good)),
        HeuristicClassifier,
        Box::new(LexicalRetriever::new(corpus)),
    )
    .with_verifier(AnswerVerifier::numeric_gate_only());

    let (streamed, _) = stream_turn(&m, "what is the UPI transaction fee?").await;
    assert!(streamed.contains(good));
    assert!(
        !streamed.to_lowercase().contains("disagree"),
        "a single, uncontested source must never trigger a conflict caveat: {streamed:?}"
    );
}
