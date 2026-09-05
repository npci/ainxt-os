// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Conversation-intelligence tests — the "Chat-done-right" behaviors, incl. the exact
//! UPI→PDF regression, driven through the REAL engine.

use ainxt_convo::{ConversationManager, HeuristicClassifier, ManagerOutcome, Message, Role};
use ainxt_protocol::Event;
use ainxt_runtime::engine_with_defaults;
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_types::{DataClass, Principal};
use tokio::sync::mpsc;

/// A provider that answers any prompt with a UPI-growth answer (so the QA turn produces a
/// substantive assistant message the referent resolver can point at).
struct UpiProvider;
impl Provider for UpiProvider {
    fn id(&self) -> &str {
        "mock"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, _prompt: &str) -> mpsc::Receiver<Event> {
        let (tx, rx) = mpsc::channel(8);
        tokio::spawn(async move {
            let _ = tx
                .send(Event::TextDelta(
                    "UPI transaction volume grew ~45% YoY.".to_string(),
                ))
                .await;
            let _ = tx.send(Event::Done).await;
        });
        rx
    }
}

fn manager() -> ConversationManager<HeuristicClassifier> {
    let mut router = ModelRouter::new();
    router.register(Box::new(UpiProvider));
    ConversationManager::new(engine_with_defaults(router), HeuristicClassifier)
}

fn user() -> Principal {
    Principal::user("analyst", &["chat.send"])
}

#[tokio::test]
async fn generate_this_as_pdf_resolves_to_the_prior_answer_not_the_instruction() {
    let m = manager();
    // Turn 1: a real QA turn through the engine.
    let a1 = m
        .handle("s1", &user(), "UPI growth?", DataClass::Public)
        .await
        .unwrap();
    assert!(
        matches!(a1, ManagerOutcome::Answer { .. }),
        "turn 1 should be an answer"
    );

    // Turn 2: the bug scenario.
    let a2 = m
        .handle("s1", &user(), "generate this as pdf", DataClass::Public)
        .await
        .unwrap();
    match a2 {
        ManagerOutcome::Document { content, .. } => {
            assert!(
                content.contains("UPI"),
                "PDF content must be the UPI answer: {content:?}"
            );
            assert!(
                !content.contains("generate this as pdf"),
                "PDF content must NOT be the instruction: {content:?}"
            );
        }
        other => panic!("expected a Document, got {other:?}"),
    }
}

#[tokio::test]
async fn over_trigger_guard_does_not_generate_a_doc_when_deferred() {
    let m = manager();
    let out = m
        .handle(
            "s2",
            &user(),
            "can you summarize this, I'll make a doc later",
            DataClass::Public,
        )
        .await
        .unwrap();
    assert!(
        matches!(out, ManagerOutcome::Answer { .. }),
        "deferred 'make a doc later' must NOT trigger doc-gen: {out:?}"
    );
}

#[tokio::test]
async fn explicit_content_in_the_message_is_used_over_history() {
    let m = manager();
    let out = m
        .handle(
            "s3",
            &user(),
            "create a pdf about NEFT limits: max 1 lakh",
            DataClass::Public,
        )
        .await
        .unwrap();
    match out {
        ManagerOutcome::Document { content, .. } => {
            assert!(
                content.contains("NEFT"),
                "explicit content should carry the subject: {content:?}"
            );
            assert!(
                !content.contains("create a pdf"),
                "must not include the instruction verb"
            );
        }
        other => panic!("expected a Document, got {other:?}"),
    }
}

#[tokio::test]
async fn ambiguous_referent_with_no_prior_answer_asks_for_clarification() {
    let m = manager();
    let out = m
        .handle("s4", &user(), "generate this as a pdf", DataClass::Public)
        .await
        .unwrap();
    assert!(
        matches!(out, ManagerOutcome::Clarify { .. }),
        "a bare referent with no prior answer must ask, not guess: {out:?}"
    );
}

#[test]
fn followup_query_is_rewritten_with_prior_context() {
    let history = vec![
        Message {
            id: None,
            role: Role::User,
            text: "UPI growth?".into(),
        },
        Message {
            id: None,
            role: Role::Assistant,
            text: "UPI transaction volume grew ~45% YoY.".into(),
        },
    ];
    let rewritten = ainxt_convo::rewrite_query("and NEFT?", &history);
    assert_ne!(rewritten, "and NEFT?", "a follow-up must be rewritten");
    assert!(
        rewritten.contains("UPI"),
        "rewrite must enrich with prior context: {rewritten}"
    );
    // A standalone question is left as-is.
    assert_eq!(
        ainxt_convo::rewrite_query("What is UPI?", &[]),
        "What is UPI?"
    );
}
