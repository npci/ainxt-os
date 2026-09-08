// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! CONV-03 wiring test — the model-agnostic / capability-aware extraction path runs on
//! the REAL assembled object.
//!
//! Assembles `ainxt_convo::ModelIntentClassifier` over this crate's production
//! `ProviderLabelModel`, driven by a deterministic offline `ConstrainedProvider` double
//! (no network, no API key). The double records the grammar it receives, so the test
//! proves the capability flag actually selects the extraction technique end-to-end:
//! a grammar-capable model gets a real grammar derived from the classifier's own
//! constraint line; a weak model gets prompt-steering only. Both flow through the same
//! cascade to a real `Intent`.

use std::sync::{Arc, Mutex};

use ainxt_convo::{Intent, IntentClassifier, ModelCaps, ModelIntentClassifier};
use ainxt_protocol::Event;
use ainxt_providers::{ConstrainedProvider, LabelGrammar, ProviderLabelModel};
use ainxt_types::DataClass;
use tokio::sync::mpsc;

/// A deterministic, offline [`ConstrainedProvider`]: emits one scripted completion and
/// records the grammar handed to each call, so the test can assert the capability-aware
/// selection without any network or credentials.
struct ScriptedTransport {
    reply: String,
    seen_grammar: Arc<Mutex<Vec<Option<Vec<String>>>>>,
}

impl ScriptedTransport {
    fn new(reply: &str, seen: Arc<Mutex<Vec<Option<Vec<String>>>>>) -> Self {
        ScriptedTransport {
            reply: reply.to_string(),
            seen_grammar: seen,
        }
    }
}

impl ConstrainedProvider for ScriptedTransport {
    fn stream_constrained(
        &self,
        _prompt: &str,
        grammar: Option<&LabelGrammar>,
    ) -> mpsc::Receiver<Event> {
        self.seen_grammar
            .lock()
            .unwrap()
            .push(grammar.map(|g| g.alternatives().to_vec()));
        let (tx, rx) = mpsc::channel(8);
        let reply = self.reply.clone();
        tokio::spawn(async move {
            let _ = tx.send(Event::TextDelta(reply)).await;
            let _ = tx.send(Event::Done).await;
        });
        rx
    }
}

#[test]
fn wire2_conv_03() {
    // -- Grammar-capable (frontier) model: the adapter derives a REAL grammar from the
    //    Stage-2 constraint line and pins the transport to the intent vocabulary. --
    let seen = Arc::new(Mutex::new(Vec::new()));
    let transport = ScriptedTransport::new("code", seen.clone());
    let model = ProviderLabelModel::new(transport, /* grammar_constrained */ true);
    assert!(model.grammar_constrained());
    let clf = ModelIntentClassifier::new(model, ModelCaps::frontier());

    // The heuristic would call "hello there" chitchat; the model says code, so if the
    // result is Code the model-backed extraction actually drove the live classification.
    let r = clf.classify("hello there", &[]);
    assert_eq!(r.intent, Intent::Code, "model label must drive the intent");
    assert!(!r.should_clarify());

    let g = seen.lock().unwrap();
    assert_eq!(g.len(), 1, "exactly one cheap Stage-2 call");
    let alts = g[0]
        .as_ref()
        .expect("a grammar-constrained model must receive a grammar");
    // The grammar is the real intent taxonomy, not a stub.
    assert!(
        alts.iter().any(|a| a == "code"),
        "grammar carries intents: {alts:?}"
    );
    assert!(
        alts.iter().any(|a| a == "doc_generation"),
        "grammar carries the full vocabulary: {alts:?}"
    );

    // -- Weak (non-grammar) OSS model: SAME assembled stack, but no grammar is emitted;
    //    the model prompt-steers instead. Capability flag drives the technique. --
    let seen_weak = Arc::new(Mutex::new(Vec::new()));
    let weak_transport = ScriptedTransport::new("qa", seen_weak.clone());
    let weak_model = ProviderLabelModel::new(weak_transport, /* grammar_constrained */ false);
    assert!(!weak_model.grammar_constrained());
    let weak_clf = ModelIntentClassifier::new(weak_model, ModelCaps::weak_oss());
    let rw = weak_clf.classify("some ambiguous request", &[]);
    assert_eq!(rw.intent, Intent::Qa);
    let gw = seen_weak.lock().unwrap();
    assert_eq!(gw.len(), 1);
    assert!(
        gw[0].is_none(),
        "a non-grammar model must NOT be handed a grammar: {:?}",
        gw[0]
    );
}

#[test]
fn wire2_conv_03_transport_error_surfaces_as_model_error() {
    // A transport-level failure must reach the cascade as unavailability (→ clarify),
    // never a silent wrong guess (§0.3). Proves the real error path is wired.
    struct FailingTransport;
    impl ConstrainedProvider for FailingTransport {
        fn stream_constrained(
            &self,
            _prompt: &str,
            _grammar: Option<&LabelGrammar>,
        ) -> mpsc::Receiver<Event> {
            let (tx, rx) = mpsc::channel(4);
            tokio::spawn(async move {
                let _ = tx.send(Event::Error("upstream 503".into())).await;
            });
            rx
        }
    }
    let model = ProviderLabelModel::new(FailingTransport, true);
    let clf = ModelIntentClassifier::new(model, ModelCaps::frontier());
    let r = clf.classify("do the thing", &[]);
    assert!(
        r.should_clarify(),
        "a provider error must clarify, never dispatch a guess"
    );
}

#[test]
fn wire2_conv_03_real_openai_provider_wires_as_label_model() {
    // Compile-time + construction evidence that the REAL OpenAI-schema provider (which
    // natively implements ConstrainedProvider) assembles as a LabelModel behind the
    // classifier. No classify() call → no network, no key required.
    use ainxt_providers::OpenAiSchemaProvider;
    let provider = OpenAiSchemaProvider::new(
        "http://127.0.0.1:1",
        "",
        "test-model",
        vec![DataClass::Public],
    );
    let model = ProviderLabelModel::new(provider, true);
    let _clf = ModelIntentClassifier::new(model, ModelCaps::frontier());
}
