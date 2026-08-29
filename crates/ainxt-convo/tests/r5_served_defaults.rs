// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R5 gap closure — the RICH conversation defaults are what a served ConversationManager uses.
//!
//! Two round-5 gaps converge on one daemon-consumable constructor
//! ([`ConversationManager::served`]):
//!
//! * conversation-intelligence — the **Stage-2 model-backed constrained classifier** must be the
//!   selected classifier on the served path (not the deterministic heuristic).
//! * Prompt Engineering — the **layered per-model-variant Prompt Service** must be the DEFAULT
//!   prompt assembly on the served path (not the flat single-string engine).
//!
//! Both are proven behaviorally through offline doubles (a scripted `LabelModel`, a recording prompt
//! sink) — no provider/network/infra. The test is written to FAIL before the change (`served` and
//! `PromptDeployment::served_default` did not exist) and PASS after.

use std::sync::{Arc, Mutex};

use ainxt_context::{Chunk, Corpus, LexicalRetriever};
use ainxt_convo::{
    ConversationManager, LabelModel, ManagerOutcome, ModelCaps, ModelError, PromptDeployment,
};
use ainxt_prompt::layered::PromptEventRecord;
use ainxt_prompt::registry::ModelFamily;
use ainxt_prompt::served::DEFAULT_CHAT_CONTROL_SHA;
use ainxt_prompt::service::EventSink;
use ainxt_protocol::Event;
use ainxt_runtime::engine_with_defaults;
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_types::{DataClass, Principal};
use tokio::sync::mpsc;

/// A [`LabelModel`] double that records every prompt it is handed — a recorded prompt PROVES the
/// model-backed Stage-2 classifier ran (the heuristic classifier never calls a `LabelModel`).
struct LoggingLabelModel {
    label: String,
    prompts: Arc<Mutex<Vec<String>>>,
}
impl LabelModel for LoggingLabelModel {
    fn classify(&self, prompt: &str) -> Result<String, ModelError> {
        self.prompts.lock().unwrap().push(prompt.to_string());
        Ok(self.label.clone())
    }
}

/// A [`EventSink`] that records every forensic prompt record — a recorded layered record PROVES the
/// layered Prompt Service produced the turn's system prompt (the flat engine records nothing here).
struct RecordingSink {
    records: Arc<Mutex<Vec<PromptEventRecord>>>,
}
impl EventSink for RecordingSink {
    fn record_prompt(&self, record: &PromptEventRecord) {
        self.records.lock().unwrap().push(record.clone());
    }
}

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
                    "The UPI settlement window closes at 22:00 IST.".to_string(),
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

fn corpus() -> Corpus {
    Corpus::new().with(Chunk::new(
        "kb-1",
        "ops-handbook",
        "The UPI settlement window closes at 22:00 IST each day.",
        DataClass::Public,
    ))
}

fn user() -> Principal {
    Principal::user("analyst", &["chat.send"])
}

#[tokio::test]
async fn r5_served_conversation_uses_model_classifier_and_layered_prompt_default() {
    let label_prompts = Arc::new(Mutex::new(Vec::new()));
    let prompt_records = Arc::new(Mutex::new(Vec::new()));

    let model = LoggingLabelModel {
        label: "qa".to_string(),
        prompts: label_prompts.clone(),
    };
    let sink = RecordingSink {
        records: prompt_records.clone(),
    };

    // The ONE daemon-consumable constructor: rich defaults in a single call.
    let manager = ConversationManager::served(
        engine(),
        model,
        ModelCaps::frontier(),
        Box::new(LexicalRetriever::new(corpus())),
        ModelFamily::new("claude"),
        Box::new(sink),
    );

    let out = manager
        .handle(
            "s1",
            &user(),
            "when does the settlement window close?",
            DataClass::Public,
        )
        .await
        .unwrap();
    assert!(
        matches!(out, ManagerOutcome::Answer { .. }),
        "a QA turn produces an answer"
    );

    // conversation-intelligence gap: the Stage-2 MODEL classifier was the selected classifier — it
    // received a constrained-decoding prompt (the heuristic path never calls a LabelModel at all).
    let lp = label_prompts.lock().unwrap();
    assert_eq!(
        lp.len(),
        1,
        "exactly one cheap Stage-2 constrained call ran"
    );
    assert!(
        lp[0].contains("EXACTLY one of"),
        "the constrained vocabulary reached the model"
    );
    assert!(
        lp[0].contains("settlement window"),
        "the real user turn reached the model"
    );

    // Prompt Engineering gap: the LAYERED Prompt Service produced the system prompt by default — the
    // forensic record was emitted against the shipped default control-plane revision with all four
    // L1..L4 layers (the flat engine records nothing to a prompt sink).
    let pr = prompt_records.lock().unwrap();
    assert_eq!(
        pr.len(),
        1,
        "exactly one layered prompt was compiled + recorded before the call"
    );
    assert_eq!(
        pr[0].control_sha, DEFAULT_CHAT_CONTROL_SHA,
        "served against the default prompt tree"
    );
    assert_eq!(
        pr[0].layers.len(),
        4,
        "all four L1..L4 layers were assembled"
    );
}

#[test]
fn r5_served_default_prompt_deployment_serves_every_default_family_and_a_self_hosted_one() {
    // A built-in family and a self-hosted family not in the default set both get a served deployment
    // (the constructor adds the active family so it never fails closed on its own configured model).
    for fam in [
        "claude",
        "openai",
        "gemini",
        "qwen",
        "glm",
        "gemma",
        "kimi",
        "inhouse-llm",
    ] {
        let sink: Box<dyn EventSink> = Box::new(RecordingSink {
            records: Arc::new(Mutex::new(Vec::new())),
        });
        // Construction drives the four layers to PRODUCTION and pins them; a panic here would mean the
        // default deployment is not actually serveable for this family.
        let _dep = PromptDeployment::served_default(ModelFamily::new(fam), sink);
    }
}
