// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX conversation-intelligence "doc-gen artifact IR + content-action delivery dead on the
//! streaming path": `ManagerOutcome::Document`/`ManagerOutcome::Action` were only ever produced by
//! `ConversationManager::handle()`/`ChatSurface::turn()`, which have ZERO callers anywhere in
//! `ainxt-server`/`ainxt-runtimed` — the served `TurnHandler::handle_turn` (the function
//! `SessionManager` actually drives) uses `run_turn_streaming` instead, which dropped the format/
//! action signal entirely and streamed only the resolved plain text. This drives the REAL
//! `ChatSurface::handle_turn` seam (the same one `served_turnhandler.rs`/`r6_served_intelligence.rs`
//! use) and proves:
//!
//! * `gap5_doc_generation_reaches_the_streaming_path_as_a_real_artifact` — a `/pdf` turn's
//!   `TurnSummary.format`/`document_json` are populated with the REAL `ainxt_artifact::Document` IR
//!   (deserializable, right title/body), and an `Event::Artifact` (the SAME wire vocabulary a model-
//!   invoked `artifact.*` tool call already uses) reaches the sink — not just an undifferentiated
//!   `TextDelta`.
//! * `gap5_content_action_reaches_the_streaming_path_with_its_kind` — "summarize the above and email
//!   it", after a real prior substantive answer, populates `TurnSummary.action == Some("email")` — a
//!   served client can now tell WHAT to do with `final_text`, not just receive undifferentiated text.
//! * `gap5_ordinary_qa_leaves_the_new_fields_none` — negative control: an ordinary Q&A turn (which
//!   goes through the DIFFERENT model-turn path entirely, not the short-circuit terminal) leaves all
//!   three new fields `None` — the fix does not misfire on ordinary chat.

use ainxt_artifact::Document;
use ainxt_cache::{CacheConfig, FixedClock};
use ainxt_chat::ChatSurface;
use ainxt_compliance::StrongRedactor;
use ainxt_context::Corpus;
use ainxt_protocol::{Event, Request};
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_runtime::{CancelToken, Engine, InMemoryAudit, RbacAuthorizer, TurnHandler, TurnSummary};
use ainxt_types::{DataClass, Principal};
use tokio::sync::mpsc;

/// A provider that answers every QA turn with a fixed, substantive sentence — used ONLY to seed a
/// real prior assistant answer for the content-action test's referent resolution ("the above").
struct AnswerProvider;
impl Provider for AnswerProvider {
    fn id(&self) -> &str {
        "mock-answer"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, _prompt: &str) -> mpsc::Receiver<Event> {
        let (tx, rx) = mpsc::channel(8);
        let _ = tx.try_send(Event::TextDelta(
            "UPI settlement finality happens within seconds.".into(),
        ));
        let _ = tx.try_send(Event::Done);
        rx
    }
}

fn surface() -> ChatSurface {
    let mut router = ModelRouter::new();
    router.register(Box::new(AnswerProvider));
    let engine = Engine::new(
        Box::new(StrongRedactor::new()),
        Box::new(RbacAuthorizer),
        Box::new(InMemoryAudit::default()),
        router,
    );
    ChatSurface::from_engine(
        engine,
        Corpus::new(),
        CacheConfig {
            capacity: 128,
            ttl_ticks: 100,
            semantic_threshold: 0.99,
        },
        Box::new(FixedClock(0)),
    )
}

fn user() -> Principal {
    Principal::user("analyst", &["chat.send"])
}

/// Drive one turn through the REAL `TurnHandler` seam; return the summary + every event the sink saw.
async fn serve(
    s: &ChatSurface,
    session: &str,
    turn: &str,
    input: &str,
) -> (TurnSummary, Vec<Event>) {
    let (tx, mut rx) = mpsc::channel::<Event>(64);
    let cancel = CancelToken::new();
    let req = Request::chat(session, turn, input, DataClass::Public);
    let summary = s
        .handle_turn(&user(), &req, tx, &cancel)
        .await
        .expect("served turn");
    let mut events = Vec::new();
    while let Some(ev) = rx.recv().await {
        events.push(ev);
    }
    (summary, events)
}

#[tokio::test]
async fn gap5_doc_generation_reaches_the_streaming_path_as_a_real_artifact() {
    let s = surface();
    let (summary, events) = serve(&s, "s-doc", "t1", "/pdf about UPI settlement finality").await;

    assert_eq!(
        summary.provider, "chat",
        "a doc-generation terminal short-circuits before any provider call: {summary:?}"
    );
    assert_eq!(
        summary.format.as_deref(),
        Some("pdf"),
        "TurnSummary.format must carry the resolved output format on the served streaming path: \
         {summary:?}"
    );
    let doc_json = summary
        .document_json
        .as_ref()
        .expect("TurnSummary.document_json must be populated for a doc-generation terminal");
    let document: Document = serde_json::from_str(doc_json)
        .expect("document_json must deserialize to a real Document IR");
    assert!(
        document.text_segments().iter().any(|t| t.contains("UPI settlement finality")),
        "the Document IR must be built from the REAL resolved content, not a placeholder: {document:?}"
    );

    // The SAME artifact must ALSO reach the live event stream — a served streaming client sees it in
    // real time, not only after the turn completes via the summary.
    let artifact_event = events.iter().find_map(|ev| match ev {
        Event::Artifact {
            id,
            capability,
            output,
        } => Some((id.clone(), capability.clone(), output.clone())),
        _ => None,
    });
    let (id, capability, output) = artifact_event
        .expect("an Event::Artifact must reach the sink for a doc-generation terminal");
    assert_eq!(id, "t1");
    assert_eq!(capability, "artifact.generate");
    assert_eq!(
        output,
        doc_json.clone(),
        "the streamed artifact payload must be the exact same JSON as TurnSummary.document_json"
    );

    // The plain-text delta is STILL sent too (backward compatibility for a client that only
    // understands TextDelta).
    assert!(
        events
            .iter()
            .any(|ev| matches!(ev, Event::TextDelta(t) if t.contains("UPI settlement finality"))),
        "the resolved content must still stream as plain text for older clients: {events:?}"
    );
}

#[tokio::test]
async fn gap5_content_action_reaches_the_streaming_path_with_its_kind() {
    let s = surface();

    // Turn 1: an ordinary QA turn, seeding a real substantive prior assistant answer.
    let (qa_summary, _) = serve(&s, "s-action", "t1", "How does UPI settlement work?").await;
    assert_eq!(
        qa_summary.provider, "mock-answer",
        "sanity: the seeding QA turn must reach the model"
    );
    assert_eq!(
        qa_summary.action, None,
        "an ordinary QA turn must not carry an action signal"
    );

    // Turn 2: the content-consuming action, referring back to "the above".
    let (summary, events) = serve(
        &s,
        "s-action",
        "t2",
        "summarize the above and email it to the ops team",
    )
    .await;
    assert_eq!(
        summary.provider, "chat",
        "a content-action terminal short-circuits before any provider call: {summary:?}"
    );
    assert_eq!(
        summary.action.as_deref(),
        Some("email"),
        "TurnSummary.action must carry the resolved action kind on the served streaming path: \
         {summary:?}"
    );
    assert_eq!(
        summary.format, None,
        "an action terminal is not a doc-generation terminal"
    );
    assert!(
        summary.final_text.contains("UPI settlement finality"),
        "final_text must be the REFERENT content (the prior answer), never the instruction verb \
         phrase: {}",
        summary.final_text
    );
    assert!(
        !events.iter().any(|ev| matches!(ev, Event::Artifact { .. })),
        "a content-action terminal is not a document — no Event::Artifact should fire: {events:?}"
    );
}

#[tokio::test]
async fn gap5_ordinary_qa_leaves_the_new_fields_none() {
    let s = surface();
    let (summary, events) = serve(&s, "s-qa", "t1", "How does UPI settlement work?").await;
    assert_eq!(summary.provider, "mock-answer");
    assert_eq!(summary.format, None);
    assert_eq!(summary.document_json, None);
    assert_eq!(summary.action, None);
    assert!(!events.iter().any(|ev| matches!(ev, Event::Artifact { .. })));
}
