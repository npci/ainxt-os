// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-12 Conversation-Intelligence gap-closure tests (subsystem `conversation-intelligence`).
//!
//! Each test is named `r12_<slug>` and is written to FAIL before the round-12 change and PASS after:
//!
//! * `r12_deterministic_rewrite_is_clean_standalone` — gap [low] the deterministic follow-up rewrite
//!   emitted a debug-formatted enrichment wrapper (`prior question: {:?}; prior answer: …) follow-up:`)
//!   that buried the request. It now LEADS with the user's request and appends the resolved prior
//!   subject as a genuine standalone query (no `{:?}` dump, no trailing `follow-up:` scaffold).
//! * `r12_resolve_content_no_overcapture_on_action_turn` — gap [low] the explicit-subject heuristics
//!   (" about "/":") ran before referent resolution and over-captured the delivery/manner qualifier
//!   of an action turn ("email the above … about Q3") as the artifact body. They now defer to any
//!   referent signal (anaphora / ordinal / id).
//! * `r12_streaming_grounds_on_classify_source` — gap [low] the streaming QA path rewrote+grounded
//!   retrieval on the COMPOSED `req.input` (persona/guard/context) instead of the de-contaminated
//!   `req.classify_source()`. Retrieval now grounds on the user's own words.
//! * `r12_model_rewrite_reaches_served_streaming_path` — gap [medium] offline evidence that the
//!   model-backed follow-up rewrite seam (`with_rewriter`) drives the served STREAMING (SessionManager
//!   `TurnHandler`) path — the daemon-consumable path — not only `handle()`. The live rewrite MODEL is
//!   an injected provider (= infra); the seam + wiring are exercised here with a scripted double.
//!
//! Everything runs offline against deterministic doubles (no provider/network).

use ainxt_convo::{
    rewrite_query, ContentSource, ConversationManager, HeuristicClassifier, Message, RewriteError,
    RewriteModel, Role,
};
use ainxt_protocol::{Event, Request};
use ainxt_runtime::engine_with_defaults;
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_runtime::CancelToken;
use ainxt_types::{DataClass, Principal};
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------------------------
// Doubles
// ---------------------------------------------------------------------------------------------

/// Echoes the exact prompt it is handed back as the answer. With an empty retrieval context the
/// manager's prompt IS the (possibly rewritten) grounding query, so echoing it lets a test observe
/// which text grounded the served turn.
struct EchoProvider;
impl Provider for EchoProvider {
    fn id(&self) -> &str {
        "echo"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, prompt: &str) -> mpsc::Receiver<Event> {
        let (tx, rx) = mpsc::channel(8);
        let p = prompt.to_string();
        tokio::spawn(async move {
            let _ = tx.send(Event::TextDelta(p)).await;
            let _ = tx.send(Event::Done).await;
        });
        rx
    }
}

fn engine_with(p: impl Provider + 'static) -> ainxt_runtime::Engine {
    let mut router = ModelRouter::new();
    router.register(Box::new(p));
    engine_with_defaults(router)
}

fn user() -> Principal {
    Principal::user("analyst", &["chat.send"]).with_clearance(DataClass::Public)
}

/// A rewriter returning a distinctive self-contained standalone request (never the raw follow-up).
struct SentinelRewriter;
impl RewriteModel for SentinelRewriter {
    fn rewrite(&self, _prompt: &str) -> Result<String, RewriteError> {
        Ok(
            "R12_STANDALONE what was NEFT settlement growth relative to the prior UPI discussion"
                .to_string(),
        )
    }
}

// ---------------------------------------------------------------------------------------------
// gap [low] — deterministic rewrite is a clean standalone (not a debug-formatted wrapper)
// ---------------------------------------------------------------------------------------------

#[test]
fn r12_deterministic_rewrite_is_clean_standalone() {
    let history = vec![
        Message::new(Role::User, "What is UPI growth?"),
        Message::new(
            Role::Assistant,
            "UPI transaction volume grew ~45% YoY across 2024.",
        ),
    ];
    let out = rewrite_query("and NEFT?", &history);

    // Leads with the user's own request (not a `(context — prior question: …` dump).
    assert!(
        out.starts_with("and NEFT?"),
        "rewrite must lead with the request, got {out:?}"
    );
    // Carries the resolved prior subject (interrogative lead stripped: "What is UPI growth?" → "UPI
    // growth"), so retrieval grounds on the concrete topic.
    assert!(
        out.contains("UPI growth"),
        "must resolve the prior subject, got {out:?}"
    );
    // The debug-formatted scaffold is gone: no prior-answer dump, no `follow-up:` tail, no `{:?}`
    // quoting of the prior question.
    assert!(
        !out.contains("prior answer"),
        "no prior-answer dump: {out:?}"
    );
    assert!(
        !out.contains("follow-up:"),
        "no trailing follow-up scaffold: {out:?}"
    );
    assert!(
        !out.contains("prior question"),
        "no debug-formatted prior-question dump: {out:?}"
    );

    // A standalone (non-follow-up) turn is still left untouched.
    assert_eq!(rewrite_query("What is NEFT?", &[]), "What is NEFT?");
}

// ---------------------------------------------------------------------------------------------
// gap [low] — resolve_content does not over-capture the qualifier of an action turn
// ---------------------------------------------------------------------------------------------

#[test]
fn r12_resolve_content_no_overcapture_on_action_turn() {
    let history = vec![
        Message::new(Role::User, "How did UPI grow?"),
        Message::new(Role::Assistant, "UPI grew 45% YoY across 2024."),
    ];

    // An action turn carrying BOTH an anaphora ("the above") AND an " about …" qualifier. The content
    // is the referent (the prior answer); " about the quarterly report" is a delivery qualifier and
    // must NOT be captured as the artifact body.
    match ainxt_convo::resolve_content(
        "email the above to bob about the quarterly report",
        &history,
    ) {
        ContentSource::Referent(t) => {
            assert!(
                t.contains("45% YoY"),
                "content = resolved referent, got {t:?}"
            );
            assert!(
                !t.contains("quarterly report"),
                "the ' about …' qualifier must not be over-captured as content: {t:?}"
            );
        }
        other => {
            panic!("an action turn with an anaphora must resolve to the referent, got {other:?}")
        }
    }

    // Regression: a genuine explicit subject with NO referent signal still resolves as Explicit.
    match ainxt_convo::resolve_content("make a pdf about NEFT limits", &history) {
        ContentSource::Explicit(t) => {
            assert!(t.contains("NEFT"), "explicit subject kept, got {t:?}")
        }
        other => panic!("an explicit subject with no referent must be Explicit, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------------------------
// gap [low] — streaming QA grounds on classify_source, not the composed input
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn r12_streaming_grounds_on_classify_source() {
    let m = ConversationManager::new(engine_with(EchoProvider), HeuristicClassifier);
    let p = user();
    let cancel = CancelToken::new();

    // `input` is a COMPOSED prompt (a Surface profile prepended persona/guard prose); `user_turn` is
    // the raw user question. Retrieval must ground on the user turn, never the composed blob.
    let composed = "PERSONA_CONTAMINATION_MARKER: system persona and guard text. \
                    USER: what is UPI settlement timing";
    let req = Request::chat("s1", "t1", composed, DataClass::Public)
        .with_user_turn("what is UPI settlement timing");

    let (tx, mut rx) = mpsc::channel::<Event>(16);
    let summary = m.run_turn_streaming(&p, &req, tx, &cancel).await.unwrap();

    let mut streamed = String::new();
    while let Some(ev) = rx.recv().await {
        if let Event::TextDelta(t) = ev {
            streamed.push_str(&t);
        }
    }

    // The echoed grounding prompt reflects the user turn, NOT the composed persona blob.
    assert!(
        streamed.contains("UPI settlement timing")
            && summary.final_text.contains("UPI settlement timing"),
        "retrieval must ground on the user turn, got stream={streamed:?}"
    );
    assert!(
        !streamed.contains("PERSONA_CONTAMINATION_MARKER"),
        "the composed persona/guard prose must not steer retrieval: {streamed:?}"
    );
}

// ---------------------------------------------------------------------------------------------
// gap [medium] (infra_gated live model) — model rewrite reaches the served STREAMING path
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn r12_model_rewrite_reaches_served_streaming_path() {
    // EchoProvider makes the served answer equal the assembled prompt; with an empty retrieval
    // context that prompt IS the grounding query. So if the injected rewriter drove the served
    // STREAMING turn (the daemon SessionManager `TurnHandler` path), the stream contains the
    // standalone rewrite — proving `with_rewriter` reaches run_turn_streaming, not only handle().
    let m = ConversationManager::new(engine_with(EchoProvider), HeuristicClassifier)
        .with_rewriter(Box::new(SentinelRewriter));
    let p = user();
    let cancel = CancelToken::new();

    // Turn 1 seeds an assistant message so turn 2 reads as a follow-up.
    let _ = m
        .handle("s1", &p, "what is UPI growth", DataClass::Public)
        .await
        .unwrap();

    // Turn 2 is a follow-up streamed through the served path → rewritten to the standalone form.
    let req = Request::chat("s1", "t2", "and NEFT settlement?", DataClass::Public);
    let (tx, mut rx) = mpsc::channel::<Event>(16);
    let summary = m.run_turn_streaming(&p, &req, tx, &cancel).await.unwrap();

    let mut streamed = String::new();
    while let Some(ev) = rx.recv().await {
        if let Event::TextDelta(t) = ev {
            streamed.push_str(&t);
        }
    }
    assert!(
        streamed.contains("R12_STANDALONE") && summary.final_text.contains("R12_STANDALONE"),
        "the model-backed rewrite must ground the served STREAMING turn, got {streamed:?}"
    );
    assert!(
        !streamed.trim().eq_ignore_ascii_case("and NEFT settlement?"),
        "the raw follow-up must not be what grounded retrieval: {streamed:?}"
    );
}
