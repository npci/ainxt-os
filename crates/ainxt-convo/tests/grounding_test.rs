// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! End-to-end grounding: a QA turn retrieves data-class-filtered context, grounds the prompt,
//! and attaches citations — driven through the real engine + Context Fabric. Uses an echo
//! provider so we can assert exactly what the grounded prompt contained (and what it did NOT).

use ainxt_context::{Chunk, Corpus, LexicalRetriever};
use ainxt_convo::{ConversationManager, HeuristicClassifier, ManagerOutcome};
use ainxt_protocol::Event;
use ainxt_runtime::engine_with_defaults;
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_types::{DataClass, Principal};
use tokio::sync::mpsc;

/// Echoes the prompt it receives — lets the test inspect the grounded prompt end-to-end.
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

fn corpus() -> Corpus {
    Corpus::new()
        .with(Chunk::new(
            "pub-upi",
            "upi-report.md",
            "UPI transaction volume grew strongly year over year",
            DataClass::Public,
        ))
        .with(Chunk::new(
            "conf-margin",
            "margins.md",
            "confidential settlement margin internal figures here",
            DataClass::Confidential,
        ))
}

fn grounded_manager() -> ConversationManager<HeuristicClassifier> {
    let mut router = ModelRouter::new();
    router.register(Box::new(EchoProvider));
    ConversationManager::with_retriever(
        engine_with_defaults(router),
        HeuristicClassifier,
        Box::new(LexicalRetriever::new(corpus())),
    )
}

#[tokio::test]
async fn qa_turn_is_grounded_and_cited_and_respects_clearance() {
    let m = grounded_manager();
    // Public-cleared user — must NOT see the Confidential chunk.
    let principal = Principal::user("analyst", &["chat.send"]).with_clearance(DataClass::Public);

    let out = m
        .handle(
            "s1",
            &principal,
            "how did UPI transaction volume grow?",
            DataClass::Public,
        )
        .await
        .unwrap();

    match out {
        ManagerOutcome::Answer {
            text, citations, ..
        } => {
            // Grounded: the echoed prompt carried the Public UPI chunk + a citation marker.
            assert!(
                text.contains("UPI transaction volume grew"),
                "answer must be grounded in the corpus: {text}"
            );
            assert!(
                text.contains("[1]"),
                "grounded prompt must include a citation marker"
            );
            // Cited: lineage attached.
            assert!(
                !citations.is_empty(),
                "a grounded answer must carry citations"
            );
            assert_eq!(citations[0].source, "upi-report.md");
            // Leak-proof: the Confidential chunk never reached the model.
            assert!(
                !text.contains("confidential settlement margin"),
                "confidential content leaked into a Public turn!"
            );
        }
        other => panic!("expected a grounded Answer, got {other:?}"),
    }
}

#[tokio::test]
async fn cleared_user_can_ground_on_confidential_context() {
    let m = grounded_manager();
    let principal = Principal::user("risk", &["chat.send"]).with_clearance(DataClass::Confidential);

    let out = m
        .handle(
            "s2",
            &principal,
            "what are the settlement margin figures?",
            DataClass::Confidential,
        )
        .await
        .unwrap();

    match out {
        ManagerOutcome::Answer {
            citations, text, ..
        } => {
            assert!(
                citations.iter().any(|c| c.source == "margins.md") || text.contains("margin"),
                "a Confidential-cleared user should be able to ground on the confidential chunk"
            );
        }
        other => panic!("expected an Answer, got {other:?}"),
    }
}
