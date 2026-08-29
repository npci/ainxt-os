// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-11 Conversation-Intelligence gap-closure tests (subsystem `conversation-intelligence`).
//!
//! Each test is named `r11_<slug>` and is written to FAIL before the round-11 change and PASS after:
//!
//! * `r11_output_format_text_answers_in_chat`  — gap [low] output_format `text` (answer in chat, not
//!   a document): a `text` format reading (lexical "plain text" OR the constrained format model's
//!   `text` label) keeps the turn on the Q&A/chat path instead of forcing a downloadable PDF.
//! * `r11_t7_over_trigger_guard_on_model_classifier` — gap [low] T7 over-trigger guard on the MODEL
//!   classifier path: a deferred "…I'll make a deck later" doc_generation reading is downgraded to Qa.
//! * `r11_t5_action_on_served_handle_path` — gap [medium] T5 content-consuming actions
//!   (summarize/email/translate/save) surfaced as a first-class outcome on the served `handle()` path,
//!   with content resolved from the referent (instruction ≠ content).
//! * `r11_t5_action_on_served_streaming_path` — the same T5 dispatch on the served STREAMING path
//!   (`run_turn_streaming`), so the daemon's SessionManager turn does not mis-ground the instruction.
//! * `r11_model_rewrite_grounds_served_turn` — offline evidence for the model-backed follow-up rewrite
//!   seam (`with_rewriter`) driving the served `handle()` grounding query (the live rewrite MODEL is
//!   an injected provider = infra; the seam + wiring are exercised here with a scripted double).
//!
//! Everything runs offline against deterministic doubles (no provider/network).

use std::sync::Mutex;

use ainxt_convo::{
    resolve_action, ActionKind, ContentSource, ConversationManager, HeuristicClassifier, Intent,
    IntentClassifier, LabelModel, ManagerOutcome, ModelCaps, ModelError, ModelIntentClassifier,
    OutputFormat, RewriteError, RewriteModel,
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

/// A scripted [`LabelModel`]: returns each output in turn (repeating the last once exhausted).
struct ScriptedLabelModel {
    outputs: Vec<Result<String, ModelError>>,
    calls: Mutex<usize>,
}
impl ScriptedLabelModel {
    fn ok(outputs: &[&str]) -> Self {
        ScriptedLabelModel {
            outputs: outputs.iter().map(|s| Ok(s.to_string())).collect(),
            calls: Mutex::new(0),
        }
    }
}
impl LabelModel for ScriptedLabelModel {
    fn classify(&self, _prompt: &str) -> Result<String, ModelError> {
        let mut c = self.calls.lock().unwrap();
        let idx = (*c).min(self.outputs.len() - 1);
        *c += 1;
        self.outputs[idx].clone()
    }
}

/// A provider that echoes the exact prompt it is handed back as the answer. With an empty retrieval
/// context the manager's prompt IS the (possibly rewritten) query, so echoing it lets a test observe
/// which query grounded the served turn.
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

/// A provider that returns a fixed substantive UPI answer (so a first QA turn seeds a real referent).
struct UpiProvider;
impl Provider for UpiProvider {
    fn id(&self) -> &str {
        "upi"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, _prompt: &str) -> mpsc::Receiver<Event> {
        let (tx, rx) = mpsc::channel(8);
        tokio::spawn(async move {
            let _ = tx
                .send(Event::TextDelta(
                    "UPI transaction volume grew ~45% YoY across 2024.".to_string(),
                ))
                .await;
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

/// A rewriter that returns a distinctive self-contained standalone request (never the raw follow-up).
struct SentinelRewriter;
impl RewriteModel for SentinelRewriter {
    fn rewrite(&self, _prompt: &str) -> Result<String, RewriteError> {
        Ok(
            "STANDALONE_REWRITE what was NEFT settlement growth in the prior UPI discussion"
                .to_string(),
        )
    }
}

// ---------------------------------------------------------------------------------------------
// gap [low] — output_format `text` (answer in chat, not a document)
// ---------------------------------------------------------------------------------------------

#[test]
fn r11_output_format_text_answers_in_chat() {
    // (a) The constrained FORMAT model resolves `text` for a doc_generation turn. Before r11 this
    //     collapsed to OutputFormat::Pdf (a document); now it is an in-chat Qa answer.
    //     Script: intent call -> "doc_generation", format call -> "text".
    let clf = ModelIntentClassifier::new(
        ScriptedLabelModel::ok(&["doc_generation", "text"]),
        ModelCaps::frontier(),
    );
    // No lexical format word and no "plain text" phrase, so the format model call is what decides.
    let r = clf.classify("turn that into something I can read", &[]);
    assert_eq!(
        r.intent,
        Intent::Qa,
        "output_format=text must answer in chat, not produce a document: {:?}",
        r.intent
    );

    // (b) An explicit "as plain text" phrasing keeps the turn in chat even if the model would say docx.
    let clf2 = ModelIntentClassifier::new(
        ScriptedLabelModel::ok(&["doc_generation", "docx"]),
        ModelCaps::frontier(),
    );
    let r2 = clf2.classify("give me that as plain text", &[]);
    assert_eq!(
        r2.intent,
        Intent::Qa,
        "explicit 'plain text' → in-chat answer"
    );

    // (c) Regression: a genuine PDF request still resolves to a document.
    let clf3 = ModelIntentClassifier::new(
        ScriptedLabelModel::ok(&["doc_generation"]),
        ModelCaps::frontier(),
    );
    assert_eq!(
        clf3.classify("make a pdf of that", &[]).intent,
        Intent::DocGeneration(OutputFormat::Pdf)
    );
}

// ---------------------------------------------------------------------------------------------
// gap [low] — T7 over-trigger guard on the MODEL classifier path
// ---------------------------------------------------------------------------------------------

#[test]
fn r11_t7_over_trigger_guard_on_model_classifier() {
    // The model says doc_generation, but the turn is DEFERRED ("…I'll make a deck later"). Before r11
    // the model path acted on doc_generation and produced DocGeneration(Pptx); now it downgrades to Qa.
    let clf = ModelIntentClassifier::new(
        ScriptedLabelModel::ok(&["doc_generation"]),
        ModelCaps::frontier(),
    );
    let r = clf.classify("great — I'll make a deck later from this", &[]);
    assert_eq!(
        r.intent,
        Intent::Qa,
        "a deferred doc mention must NOT fire doc-generation on the model path: {:?}",
        r.intent
    );

    // Regression: a NON-deferred doc request on the model path still fires.
    let clf2 = ModelIntentClassifier::new(
        ScriptedLabelModel::ok(&["doc_generation"]),
        ModelCaps::frontier(),
    );
    assert_eq!(
        clf2.classify("make a deck from this now", &[]).intent,
        Intent::DocGeneration(OutputFormat::Pptx)
    );
}

// ---------------------------------------------------------------------------------------------
// gap [medium] — T5 content-consuming actions on the served handle() path
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn r11_t5_action_on_served_handle_path() {
    let m = ConversationManager::new(engine_with(UpiProvider), HeuristicClassifier);
    let p = user();

    // Turn 1: a QA that seeds a substantive assistant answer (the referent).
    let _ = m
        .handle(
            "s1",
            &p,
            "how did UPI transaction volume grow?",
            DataClass::Public,
        )
        .await
        .unwrap();

    // Turn 2: the T5 multi-action. The served path must surface a first-class Action whose content is
    // the resolved referent (instruction verb phrase EXCLUDED), not a Q&A answer grounded on the verb.
    let out = m
        .handle(
            "s1",
            &p,
            "summarize the above and email it",
            DataClass::Public,
        )
        .await
        .unwrap();
    match out {
        ManagerOutcome::Action { action, content } => {
            assert_eq!(
                action,
                ActionKind::Email,
                "terminal delivery wins in a multi-action turn"
            );
            assert!(
                content.contains("45% YoY"),
                "content = resolved referent, got {content:?}"
            );
            assert!(
                !content.to_lowercase().contains("summarize"),
                "the instruction verb phrase must be EXCLUDED from the content: {content:?}"
            );
        }
        other => panic!("expected a T5 Action outcome on the served path, got {other:?}"),
    }

    // Guard against over-trigger: an action word inside a FRESH question (no referent) is NOT an
    // action — it falls through to the normal Q&A path.
    let fresh = m
        .handle("s2", &p, "how do I send money via UPI?", DataClass::Public)
        .await
        .unwrap();
    assert!(
        matches!(fresh, ManagerOutcome::Answer { .. }),
        "a fresh question containing an action word must answer, not fire an action: {fresh:?}"
    );
}

// ---------------------------------------------------------------------------------------------
// gap [medium] — T5 on the served STREAMING path (run_turn_streaming)
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn r11_t5_action_on_served_streaming_path() {
    let m = ConversationManager::new(engine_with(UpiProvider), HeuristicClassifier);
    let p = user();
    let cancel = CancelToken::new();

    // Seed a substantive answer.
    let _ = m
        .handle(
            "s1",
            &p,
            "how did UPI transaction volume grow?",
            DataClass::Public,
        )
        .await
        .unwrap();

    // Stream a T5 action turn. The terminal must emit the resolved referent (instruction excluded),
    // NOT ground the model on the instruction "summarize the above and email it".
    let req = Request::chat(
        "s1",
        "t2",
        "summarize the above and email it",
        DataClass::Public,
    );
    let (tx, mut rx) = mpsc::channel::<Event>(16);
    let summary = m.run_turn_streaming(&p, &req, tx, &cancel).await.unwrap();

    let mut streamed = String::new();
    while let Some(ev) = rx.recv().await {
        if let Event::TextDelta(t) = ev {
            streamed.push_str(&t);
        }
    }
    assert!(
        streamed.contains("45% YoY") && summary.final_text.contains("45% YoY"),
        "streaming T5 must emit the resolved referent, got stream={streamed:?} summary={:?}",
        summary.final_text
    );
    assert!(
        !streamed.to_lowercase().contains("email it"),
        "the instruction must not be echoed as the action content: {streamed:?}"
    );
}

// ---------------------------------------------------------------------------------------------
// gap [medium] (infra_gated live model) — model-backed follow-up rewrite grounds the served turn
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn r11_model_rewrite_grounds_served_turn() {
    // An EchoProvider makes the served answer equal the assembled prompt; with an empty retrieval
    // context that prompt IS the grounding query. So if the injected rewriter drove the served turn,
    // the answer contains the standalone rewrite — proving `with_rewriter` reaches the served path.
    let m = ConversationManager::new(engine_with(EchoProvider), HeuristicClassifier)
        .with_rewriter(Box::new(SentinelRewriter));
    let p = user();

    // Turn 1 seeds an assistant message so turn 2 reads as a follow-up.
    let _ = m
        .handle("s1", &p, "what is UPI growth", DataClass::Public)
        .await
        .unwrap();

    // Turn 2 is a follow-up ("and …") → rewritten to the standalone form → grounds the served turn.
    let out = m
        .handle("s1", &p, "and NEFT?", DataClass::Public)
        .await
        .unwrap();
    match out {
        ManagerOutcome::Answer { text, .. } => {
            assert!(
                text.contains("STANDALONE_REWRITE"),
                "the model-backed rewrite must ground the served turn, got {text:?}"
            );
            assert_ne!(
                text.trim(),
                "and NEFT?",
                "the raw follow-up must not be what grounded retrieval"
            );
        }
        other => panic!("expected an answer, got {other:?}"),
    }

    // Also directly assert the seam is present on the manager (documented entrypoint for the daemon).
    let action = resolve_action("save this", &m.history("s1"));
    assert!(
        matches!(action, Some(a) if a.action == ActionKind::Save && matches!(a.content, ContentSource::Referent(_))),
        "the resolved-action seam remains available for the served path"
    );
}
