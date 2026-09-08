// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Prompt Engine wired into the ConversationManager: the assembled, model-agnostic prompt
//! (system + reasoning + numeric + grounded context + task) is what the model actually receives.

use ainxt_context::{Chunk, Corpus, LexicalRetriever};
use ainxt_convo::{ConversationManager, HeuristicClassifier, ManagerOutcome};
use ainxt_prompt::{NumericPolicy, PromptConfig};
use ainxt_protocol::Event;
use ainxt_runtime::engine_with_defaults;
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_types::{DataClass, Principal};
use tokio::sync::mpsc;

/// Echoes the prompt it receives so the test can assert exactly what the model saw.
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
    Corpus::new().with(Chunk::new(
        "upi",
        "upi.md",
        "UPI settlement runs in cycles across member banks",
        DataClass::Public,
    ))
}

fn manager(cfg: PromptConfig) -> ConversationManager<HeuristicClassifier> {
    let mut router = ModelRouter::new();
    router.register(Box::new(EchoProvider));
    ConversationManager::with_retriever(
        engine_with_defaults(router),
        HeuristicClassifier,
        Box::new(LexicalRetriever::new(corpus())),
    )
    .with_prompt(cfg)
}

fn user() -> Principal {
    Principal::user("u", &["chat.send"]).with_clearance(DataClass::Public)
}

#[tokio::test]
async fn the_assembled_prompt_is_what_the_model_receives() {
    let cfg = PromptConfig {
        numeric: NumericPolicy::ToolsOnly,
        ..Default::default()
    };
    let m = manager(cfg);

    let out = m
        .handle(
            "s",
            &user(),
            "analyze how UPI settlement works and compare cycles",
            DataClass::Public,
        )
        .await
        .unwrap();

    match out {
        ManagerOutcome::Answer { text, .. } => {
            // The echoed prompt carries every engine section, in order.
            assert!(text.contains("[SYSTEM]"), "system directives present");
            assert!(
                text.contains("take precedence"),
                "instruction precedence (BG)"
            );
            assert!(
                text.contains("[NUMERIC]"),
                "numeric discipline injected (BH, tools-only)"
            );
            assert!(
                text.contains("step by step"),
                "an 'analyze/compare' query gets deep reasoning (BE)"
            );
            // The grounded context still flows through, fenced as untrusted (ADR-009).
            assert!(
                text.contains("UPI settlement runs in cycles"),
                "retrieved context is included"
            );
            assert!(
                text.contains("<untrusted"),
                "retrieved context stays fenced"
            );
        }
        other => panic!("expected an Answer, got {other:?}"),
    }
}

#[tokio::test]
async fn a_trivial_followup_is_not_over_classified_as_deep() {
    // Depth must come from the RAW user message, not the rewritten (prior-Q+A-padded) query —
    // otherwise a one-line follow-up after a substantive answer would mis-route to deep/Complex.
    // NOTE: the first turn is a simple question (not "explain in detail") so its response does not
    // contain a "step by step" deep-reasoning directive that would later appear in the second turn's
    // injected history block (the EchoProvider echoes the full prompt including history).
    let m = manager(PromptConfig::default());
    let _ = m
        .handle("s", &user(), "what is UPI settlement?", DataClass::Public)
        .await
        .unwrap();
    let out = m
        .handle("s", &user(), "and the fees?", DataClass::Public)
        .await
        .unwrap();
    match out {
        ManagerOutcome::Answer { text, .. } => {
            assert!(
                !text.contains("step by step"),
                "a trivial follow-up must NOT inherit deep reasoning from the padded rewrite: {text}"
            );
        }
        other => panic!("expected an Answer, got {other:?}"),
    }
}

#[tokio::test]
async fn without_the_prompt_engine_the_body_passes_through_unchanged() {
    let mut router = ModelRouter::new();
    router.register(Box::new(EchoProvider));
    let m = ConversationManager::with_retriever(
        engine_with_defaults(router),
        HeuristicClassifier,
        Box::new(LexicalRetriever::new(corpus())),
    ); // no .with_prompt

    let out = m
        .handle(
            "s",
            &user(),
            "how does UPI settlement work?",
            DataClass::Public,
        )
        .await
        .unwrap();
    match out {
        ManagerOutcome::Answer { text, .. } => {
            assert!(
                !text.contains("[SYSTEM]"),
                "prompt engine off → no engine sections"
            );
            assert!(
                text.contains("Question:"),
                "the plain grounded body is used"
            );
        }
        other => panic!("expected an Answer, got {other:?}"),
    }
}
