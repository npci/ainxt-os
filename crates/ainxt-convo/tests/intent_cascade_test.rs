// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Gap-closure tests for the Conversation-Intelligence subsystem (gap_tracker CONV-01..CONV-10).
//!
//! Each test is named after the gap id it closes and is written to FAIL before the corresponding
//! change (either a behavioral assertion that the old code violated, or an API that did not exist)
//! and PASS after. The model-backed cascade is exercised through a deterministic scripted
//! `LabelModel` double so the whole thing stays offline + reproducible (no provider/network).

use std::sync::{Arc, Mutex};

use ainxt_context::Citation;
use ainxt_convo::{
    compose_chat_answer, compose_chat_answer_typed, last_substantive_assistant, resolve_action,
    rewrite_query_with_model, stage1_signal, ActionKind, ContentSource, ConversationManager,
    HeuristicClassifier, Intent, IntentClassifier, LabelModel, ManagerOutcome, Message, ModelCaps,
    ModelError, ModelIntentClassifier, OutputFormat, RewriteError, RewriteModel, Role,
};
use ainxt_protocol::Event;
use ainxt_runtime::engine_with_defaults;
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_types::{DataClass, Principal, Tier};
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------------------------
// Doubles
// ---------------------------------------------------------------------------------------------

/// A deterministic [`LabelModel`] double: returns each scripted output in turn (repeating the last
/// once exhausted) and records every prompt it was handed, so a test can prove the constrained
/// prompt actually reached the model (Stage-2 wiring) and inspect the capability-selected strategy.
struct ScriptedLabelModel {
    outputs: Vec<Result<String, ModelError>>,
    calls: Mutex<usize>,
    prompts: Arc<Mutex<Vec<String>>>,
}

impl ScriptedLabelModel {
    fn ok(outputs: &[&str]) -> Self {
        ScriptedLabelModel {
            outputs: outputs.iter().map(|s| Ok(s.to_string())).collect(),
            calls: Mutex::new(0),
            prompts: Arc::new(Mutex::new(Vec::new())),
        }
    }
    fn logged(outputs: &[&str], log: Arc<Mutex<Vec<String>>>) -> Self {
        ScriptedLabelModel {
            outputs: outputs.iter().map(|s| Ok(s.to_string())).collect(),
            calls: Mutex::new(0),
            prompts: log,
        }
    }
}

impl LabelModel for ScriptedLabelModel {
    fn classify(&self, prompt: &str) -> Result<String, ModelError> {
        self.prompts.lock().unwrap().push(prompt.to_string());
        let mut c = self.calls.lock().unwrap();
        let idx = (*c).min(self.outputs.len() - 1);
        *c += 1;
        self.outputs[idx].clone()
    }
}

/// A provider that answers any prompt with a UPI-growth answer, so a QA turn produces a substantive
/// assistant message for the live-pipeline tests.
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

fn engine() -> ainxt_runtime::Engine {
    let mut router = ModelRouter::new();
    router.register(Box::new(UpiProvider));
    engine_with_defaults(router)
}

fn user() -> Principal {
    Principal::user("analyst", &["chat.send"])
}

// ---------------------------------------------------------------------------------------------
// CONV-01 — Stage-2 model-backed constrained classifier wired into the cascade
// ---------------------------------------------------------------------------------------------

#[test]
fn gap_ainxt_convo_conv_01_model_backed_classifier_drives_intent() {
    // "hello there" is Chitchat to the deterministic heuristic; the MODEL says code. If the result
    // is Code, the Stage-2 constrained model call actually drove the classification (not a bypass).
    let clf = ModelIntentClassifier::new(ScriptedLabelModel::ok(&["code"]), ModelCaps::frontier());
    let r = clf.classify("hello there", &[]);
    assert_eq!(
        r.intent,
        Intent::Code,
        "the model's label must drive the intent"
    );
    assert!(!r.should_clarify());
    assert!(r.confidence >= 0.9);
}

#[test]
fn gap_ainxt_convo_conv_01_model_classifier_receives_constraint_prompt() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let clf = ModelIntentClassifier::new(
        ScriptedLabelModel::logged(&["qa"], log.clone()),
        ModelCaps::frontier(),
    );
    let _ = clf.classify("what is the settlement window?", &[]);
    let prompts = log.lock().unwrap();
    assert_eq!(prompts.len(), 1, "exactly one cheap Stage-2 call");
    // The constrained vocabulary + the user turn both reached the model (real wiring, not a stub).
    assert!(prompts[0].contains("EXACTLY one of"));
    assert!(prompts[0].contains("doc_generation"));
    assert!(prompts[0].contains("settlement window"));
}

#[tokio::test]
async fn gap_ainxt_convo_conv_01_model_classifier_runs_in_live_pipeline() {
    // The model classifier plugged into ConversationManager decides the live turn's control-flow.
    let m = ConversationManager::new(
        engine(),
        ModelIntentClassifier::new(ScriptedLabelModel::ok(&["qa"]), ModelCaps::weak_oss()),
    );
    let out = m
        .handle(
            "s1",
            &user(),
            "tell me about UPI settlement",
            DataClass::Public,
        )
        .await
        .unwrap();
    assert!(
        matches!(out, ManagerOutcome::Answer { .. }),
        "a model-classified qa turn must answer: {out:?}"
    );
}

// ---------------------------------------------------------------------------------------------
// CONV-02 — Stage-3 clarify-on-low-confidence in the LIVE conversation path
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn gap_ainxt_convo_conv_02_ambiguous_read_clarifies_in_live_path() {
    // Two distinct labels → ambiguous; the live handle() must ASK, not silently answer.
    let m = ConversationManager::new(
        engine(),
        ModelIntentClassifier::new(
            ScriptedLabelModel::ok(&["maybe qa or code"]),
            ModelCaps::frontier(),
        ),
    );
    let out = m
        .handle("s1", &user(), "do the thing with that", DataClass::Public)
        .await
        .unwrap();
    match out {
        ManagerOutcome::Clarify { question } => assert!(!question.trim().is_empty()),
        other => panic!("low-confidence turn must clarify, got {other:?}"),
    }
}

#[tokio::test]
async fn gap_ainxt_convo_conv_02_low_confidence_streaming_path_clarifies() {
    // The streaming path honors Stage-3 too: an embedded-alias read (0.6 < floor 0.7) → clarify.
    let m = ConversationManager::new(
        engine(),
        ModelIntentClassifier::new(
            ScriptedLabelModel::ok(&["it is probably a document i think"]),
            ModelCaps::frontier(),
        ),
    );
    let (tx, mut rx) = mpsc::channel(16);
    let cancel = ainxt_runtime::CancelToken::new();
    let req = ainxt_protocol::Request::chat("s1", "t1", "please handle this", DataClass::Public);
    let summary = m
        .run_turn_streaming(&user(), &req, tx, &cancel)
        .await
        .unwrap();
    // The clarifying question is emitted as the streamed text — no silent guess/answer.
    let mut streamed = String::new();
    while let Some(ev) = rx.recv().await {
        if let Event::TextDelta(t) = ev {
            streamed.push_str(&t);
        }
    }
    assert!(!summary.final_text.trim().is_empty());
    assert_eq!(streamed, summary.final_text);
    assert!(
        streamed.to_lowercase().contains("clarify")
            || streamed.contains('?')
            || streamed.to_lowercase().contains("rephrase"),
        "streaming clarify must ask a question: {streamed:?}"
    );
}

// ---------------------------------------------------------------------------------------------
// CONV-03 — model-agnostic / capability-aware extraction (grammar flag drives the strategy)
// ---------------------------------------------------------------------------------------------

#[test]
fn gap_ainxt_convo_conv_03_capability_flags_select_extraction_strategy() {
    // Weak (non-grammar) model → few-shot steering is added to the prompt.
    let weak_log = Arc::new(Mutex::new(Vec::new()));
    let weak = ModelIntentClassifier::new(
        ScriptedLabelModel::logged(&["qa"], weak_log.clone()),
        ModelCaps::weak_oss(),
    );
    let _ = weak.classify("some ambiguous request", &[]);
    let wp = weak_log.lock().unwrap()[0].clone();
    assert!(
        wp.contains("Examples:"),
        "weak models get few-shot steering"
    );
    assert!(
        wp.contains("EXACTLY one of"),
        "grammar mirror still present"
    );

    // Grammar-constrained frontier model → terse instruction, the grammar does the enforcing.
    let front_log = Arc::new(Mutex::new(Vec::new()));
    let front = ModelIntentClassifier::new(
        ScriptedLabelModel::logged(&["qa"], front_log.clone()),
        ModelCaps::frontier(),
    );
    let _ = front.classify("some ambiguous request", &[]);
    let fp = front_log.lock().unwrap()[0].clone();
    assert!(
        !fp.contains("Examples:"),
        "grammar-constrained model needs no few-shot"
    );
}

#[test]
fn gap_ainxt_convo_conv_03_weak_model_gets_larger_repair_budget() {
    // Two garbled streams then a clean label. A weak model's raised repair budget (>=3) recovers;
    // the frontier default budget (2) exhausts and clarifies — same cascade, capability-aware.
    let weak = ModelIntentClassifier::new(
        ScriptedLabelModel::ok(&["nonsense", "nonsense", "qa"]),
        ModelCaps::weak_oss(),
    );
    assert_eq!(weak.classify("x y z", &[]).intent, Intent::Qa);

    let front = ModelIntentClassifier::new(
        ScriptedLabelModel::ok(&["nonsense", "nonsense", "qa"]),
        ModelCaps::frontier(),
    );
    assert!(
        front.classify("x y z", &[]).should_clarify(),
        "frontier default budget exhausts before the 3rd stream → clarify"
    );
}

// ---------------------------------------------------------------------------------------------
// CONV-04 — intent taxonomy completeness (task + code reachable and distinct)
// ---------------------------------------------------------------------------------------------

#[test]
fn gap_ainxt_convo_conv_04_taxonomy_covers_code_and_task() {
    // The model can produce every label; Code/Task are representable and returned.
    let code = ModelIntentClassifier::new(ScriptedLabelModel::ok(&["code"]), ModelCaps::frontier())
        .classify("hello", &[]);
    assert_eq!(code.intent, Intent::Code);
    let task = ModelIntentClassifier::new(ScriptedLabelModel::ok(&["task"]), ModelCaps::frontier())
        .classify("hello", &[]);
    assert_eq!(task.intent, Intent::Task);

    // The deterministic tier now reaches Code and Task lexically too (before: both → Qa).
    assert_eq!(
        HeuristicClassifier
            .classify("write a function to reverse a list", &[])
            .intent,
        Intent::Code
    );
    assert_eq!(
        HeuristicClassifier
            .classify("schedule a meeting for friday", &[])
            .intent,
        Intent::Task
    );
}

// ---------------------------------------------------------------------------------------------
// CONV-05 — follow-up rewrite to a self-contained standalone query
// ---------------------------------------------------------------------------------------------

struct StandaloneRewriter;
impl RewriteModel for StandaloneRewriter {
    fn rewrite(&self, _prompt: &str) -> Result<String, RewriteError> {
        Ok(
            "Generate a PDF of the UPI growth analysis provided in the previous answer."
                .to_string(),
        )
    }
}

struct FailingRewriter;
impl RewriteModel for FailingRewriter {
    fn rewrite(&self, _prompt: &str) -> Result<String, RewriteError> {
        Err(RewriteError("provider timeout".into()))
    }
}

#[test]
fn gap_ainxt_convo_conv_05_model_rewrite_is_clean_standalone() {
    let history = vec![
        Message::new(Role::User, "UPI growth?"),
        Message::new(
            Role::Assistant,
            "UPI transaction volume grew ~45% YoY across 2024.",
        ),
    ];
    let out = rewrite_query_with_model("generate this as pdf", &history, Some(&StandaloneRewriter));
    assert_eq!(
        out,
        "Generate a PDF of the UPI growth analysis provided in the previous answer."
    );
    // NOT the deterministic context-prefix scaffold.
    assert!(!out.contains("(context —"));

    // On a model failure it falls back to the deterministic enrichment (never worse than before).
    let fb = rewrite_query_with_model("generate this as pdf", &history, Some(&FailingRewriter));
    assert!(fb.contains("(context —"));

    // A standalone (non-follow-up) turn is left untouched even with a model present.
    assert_eq!(
        rewrite_query_with_model("What is UPI?", &[], Some(&StandaloneRewriter)),
        "What is UPI?"
    );
}

// ---------------------------------------------------------------------------------------------
// CONV-06 — content resolution order 3: a specific earlier answer by ordinal / id
// ---------------------------------------------------------------------------------------------

#[test]
fn gap_ainxt_convo_conv_06_resolve_specific_answer_by_ordinal_and_id() {
    let history = vec![
        Message::with_id("m1", Role::User, "UPI?"),
        Message::with_id("m2", Role::Assistant, "ANSWER-ONE: UPI grew 45% YoY."),
        Message::with_id("m3", Role::User, "NEFT?"),
        Message::with_id(
            "m4",
            Role::Assistant,
            "ANSWER-TWO: NEFT settles half-hourly.",
        ),
    ];
    // Ordinal → the FIRST substantive answer, not the most recent one.
    match ainxt_convo::resolve_content("make a pdf of answer 1", &history) {
        ContentSource::Referent(t) => assert!(t.contains("ANSWER-ONE"), "got {t:?}"),
        other => panic!("ordinal reference must resolve, got {other:?}"),
    }
    // Explicit id token.
    match ainxt_convo::resolve_content("put m4 into a pdf", &history) {
        ContentSource::Referent(t) => assert!(t.contains("ANSWER-TWO"), "got {t:?}"),
        other => panic!("id reference must resolve, got {other:?}"),
    }
    // An out-of-range pointer is NOT silently coerced to some other turn.
    assert_eq!(
        ainxt_convo::resolve_content("export answer 9", &history),
        ContentSource::Ambiguous
    );
}

// ---------------------------------------------------------------------------------------------
// CONV-07 — "substantive answer" skips acknowledgements & clarifying questions
// ---------------------------------------------------------------------------------------------

#[test]
fn gap_ainxt_convo_conv_07_substantive_skips_ack_and_clarifying_question() {
    let history = vec![
        Message::new(
            Role::Assistant,
            "UPI transaction volume grew ~45% YoY across 2024.",
        ),
        Message::new(Role::User, "make a pdf"),
        Message::new(Role::Assistant, "Which content should I put in the PDF?"),
    ];
    let ans = last_substantive_assistant(&history).expect("a substantive answer exists");
    assert!(
        ans.contains("45% YoY"),
        "the clarifying question must be skipped, got {ans:?}"
    );

    let h2 = vec![
        Message::new(Role::Assistant, "NEFT settles in half-hourly batches."),
        Message::new(Role::Assistant, "Sure!"),
    ];
    assert!(
        last_substantive_assistant(&h2).unwrap().contains("NEFT"),
        "a bare acknowledgement must be skipped"
    );
}

// ---------------------------------------------------------------------------------------------
// CONV-08 — T5 multi-action "summarize the above and email it"
// ---------------------------------------------------------------------------------------------

#[test]
fn gap_ainxt_convo_conv_08_summarize_and_email_content_is_referent_not_instruction() {
    let history = vec![
        Message::new(Role::User, "UPI growth?"),
        Message::new(Role::Assistant, "UPI transaction volume grew ~45% YoY."),
    ];
    let action = resolve_action("summarize the above and email it", &history).expect("an action");
    // The terminal delivery action wins over "summarize".
    assert_eq!(action.action, ActionKind::Email);
    match action.content {
        ContentSource::Referent(t) => {
            assert!(t.contains("45% YoY"), "content = resolved referent");
            assert!(
                !t.to_lowercase().contains("summarize"),
                "the instruction verb phrase must be EXCLUDED from the content"
            );
        }
        other => panic!("content must resolve to the referent, got {other:?}"),
    }
    // A plain question is not an action.
    assert!(resolve_action("what is UPI?", &history).is_none());
}

// ---------------------------------------------------------------------------------------------
// CONV-09 — Stage-1 explicit UI affordance / slash commands
// ---------------------------------------------------------------------------------------------

#[test]
fn gap_ainxt_convo_conv_09_slash_commands_and_affordance_are_stage1() {
    assert_eq!(
        stage1_signal("/pdf the quarterly numbers").unwrap().intent,
        Intent::DocGeneration(OutputFormat::Pdf)
    );
    assert_eq!(
        stage1_signal("/ppt").unwrap().intent,
        Intent::DocGeneration(OutputFormat::Pptx)
    );
    // Full confidence — the model tier is skipped when the affordance is explicit.
    assert_eq!(stage1_signal("/doc").unwrap().confidence, 1.0);
    // A slash mentioned mid-sentence is NOT a command.
    assert!(stage1_signal("please make a pdf /pdf").is_none());
    // Explicit "Generate document" action sentinel.
    assert_eq!(
        stage1_signal("[[generate_document:xlsx]] the revenue table")
            .unwrap()
            .intent,
        Intent::DocGeneration(OutputFormat::Xlsx)
    );
    // The heuristic classifier routes slash commands through Stage-1 too.
    assert_eq!(
        HeuristicClassifier.classify("/xlsx", &[]).intent,
        Intent::DocGeneration(OutputFormat::Xlsx)
    );
}

// ---------------------------------------------------------------------------------------------
// CONV-10 — ainxt-answer composition/formatting integrated into the conversation surface
// ---------------------------------------------------------------------------------------------

#[test]
fn gap_ainxt_convo_conv_10_answer_composition_wired_into_convo() {
    let cites = vec![Citation {
        marker: "[1]".into(),
        source: "Payment System Report 2024".into(),
        chunk_id: "c1".into(),
        data_class: DataClass::Public,
    }];
    let body = "UPI grew 45% YoY.\n\nDrivers included merchant adoption.";

    // A Complex turn keeps the structure and renders a deterministic References list (BK/BN).
    let md = compose_chat_answer(body, &cites, Tier::Complex);
    assert!(md.contains("UPI grew 45% YoY"));
    assert!(md.contains("Drivers included merchant adoption"));
    assert!(md.contains("## References"));
    assert!(md.contains("Payment System Report 2024"));

    // BM right-sizing: a Terse (Simple) tier bounds the answer and records the truncation — never
    // silently. This proves ainxt-answer's verbosity calibration is actually exercised from convo.
    let composed = compose_chat_answer_typed(body, &cites, Tier::Simple);
    assert!(
        composed.has_warnings(),
        "Terse verbosity must record the bound it enforced"
    );
}

#[tokio::test]
async fn gap_ainxt_convo_conv_10_manager_answer_format_renders_references() {
    // With a retriever that yields a citation and answer-formatting enabled, the live answer text is
    // composed through ainxt-answer (a References section appears) rather than the raw model string.
    use ainxt_context::{Chunk, Corpus, LexicalRetriever};
    let corpus = Corpus::new().with(Chunk::new(
        "pub-upi",
        "Payment System Report 2024",
        "UPI transaction volume grew strongly year over year",
        DataClass::Public,
    ));
    let m = ConversationManager::with_retriever(
        engine(),
        HeuristicClassifier,
        Box::new(LexicalRetriever::new(corpus)),
    )
    .with_answer_format();
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
        ManagerOutcome::Answer { text, .. } => {
            assert!(
                text.contains("## References"),
                "answer_format must compose via ainxt-answer: {text:?}"
            );
        }
        other => panic!("expected an answer, got {other:?}"),
    }
}
