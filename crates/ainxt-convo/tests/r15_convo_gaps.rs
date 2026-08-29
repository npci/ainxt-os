// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-15 gap-closure tests for Conversation Intelligence (`CONVERSATION_INTELLIGENCE.md`).
//! Each test targets exactly one round-14 audit finding and is written to FAIL on the pre-fix
//! behavior and PASS after. No network, no ML runtime, no live provider — every double here is a
//! deterministic offline seam, matching the "shipped air-gapped default" the findings are about.

use std::sync::{Arc, Mutex};

use ainxt_convo::{
    ConversationManager, HeuristicClassifier, Intent, IntentClassifier, LabelModel, ManagerOutcome,
    Message, ModelCaps, ModelError, ModelIntentClassifier, OutputFormat, Role,
};
use ainxt_protocol::Event;
use ainxt_runtime::engine_with_defaults;
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_types::{DataClass, Principal};
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------------------------
// gap [medium] — "Stage-2 model classifier consumes conversation history"
// ---------------------------------------------------------------------------------------------

/// A [`LabelModel`] double whose answer depends on whether the PRIOR turn's content made it into
/// the prompt it was handed — the only way to prove Stage-2 actually consumed `history` rather
/// than classifying the bare current message in isolation (the pre-fix `classify` signature took
/// `_history: &[Message]`, unused).
struct ContextSensitiveModel {
    prompts: Arc<Mutex<Vec<String>>>,
}

impl LabelModel for ContextSensitiveModel {
    fn classify(&self, prompt: &str) -> Result<String, ModelError> {
        self.prompts.lock().unwrap().push(prompt.to_string());
        // Only a prompt that actually carries the prior turn's subject matter lets this "model"
        // recognize the bare follow-up as a doc-generation request; with no history in the prompt
        // it has nothing to go on and answers the safe default.
        if prompt.contains("UPI growth") || prompt.contains("grew ~45%") {
            Ok("doc_generation".to_string())
        } else {
            Ok("qa".to_string())
        }
    }
}

#[test]
fn r15_stage2_classifier_consumes_conversation_history() {
    let history = vec![
        Message::new(Role::User, "UPI growth?"),
        Message::new(Role::Assistant, "UPI transaction volume grew ~45% YoY."),
    ];
    let prompts = Arc::new(Mutex::new(Vec::new()));
    let clf = ModelIntentClassifier::new(
        ContextSensitiveModel {
            prompts: prompts.clone(),
        },
        ModelCaps::frontier(),
    );

    // "make it a deck" is a follow-up (anaphora "it") with no standalone subject of its own — the
    // prior turn's content is the ONLY way to resolve what "it" refers to.
    let r = clf.classify("make it a deck", &history);

    let sent = prompts.lock().unwrap();
    assert_eq!(sent.len(), 1, "exactly one Stage-2 call");
    assert!(
        sent[0].contains("UPI growth") && sent[0].contains("grew ~45%"),
        "the Stage-2 prompt must carry the prior user turn AND the prior substantive answer, \
         got: {:?}",
        sent[0]
    );
    assert!(
        !r.should_clarify(),
        "context resolved the follow-up confidently: {r:?}"
    );
    assert_eq!(
        r.intent,
        Intent::DocGeneration(OutputFormat::Pptx),
        "history-aware Stage-2 must read the deck follow-up as doc_generation/pptx: {r:?}"
    );
}

#[test]
fn r15_stage2_standalone_turn_gets_no_history_padding() {
    // A standalone (non-follow-up) message needs no history — the common-case prompt stays small
    // and byte-identical to the no-history call.
    let prompts = Arc::new(Mutex::new(Vec::new()));
    let clf = ModelIntentClassifier::new(
        ContextSensitiveModel {
            prompts: prompts.clone(),
        },
        ModelCaps::frontier(),
    );
    let history = vec![
        Message::new(Role::User, "UPI growth?"),
        Message::new(Role::Assistant, "UPI transaction volume grew ~45% YoY."),
    ];
    let _ = clf.classify("what is the settlement window for NEFT?", &history);
    let sent = prompts.lock().unwrap();
    assert_eq!(sent.len(), 1);
    assert!(
        !sent[0].contains("UPI growth"),
        "a standalone question needs no prior-turn padding: {:?}",
        sent[0]
    );
}

// ---------------------------------------------------------------------------------------------
// gap [low] — "Stage-3 'ask third' active on the shipped air-gapped default"
// ---------------------------------------------------------------------------------------------

#[test]
fn r15_offline_classifier_clarifies_on_genuine_lexical_ambiguity() {
    // `ModelIntentClassifier::offline()` needs zero infra (no network, no local inference server,
    // no ML runtime) — exactly the shipped air-gapped default's constraint. "compare this code"
    // carries BOTH a comparison cue ("compare") and a code cue ("code"): a real ambiguity the
    // bare HeuristicClassifier would silently resolve by priority order (comparison wins) and
    // NEVER ask about, because its own contract is "never sets a clarify decision — its signals
    // are known" (`ainxt_convo::HeuristicClassifier` doc comment). Stage-3 must ask here instead.
    let clf = ModelIntentClassifier::offline();
    let r = clf.classify("compare this code", &[]);
    assert!(
        r.should_clarify(),
        "two distinct lexical signals colliding must ask, not silently pick one: {r:?}"
    );

    // Contrast: the deterministic HeuristicClassifier tier NEVER clarifies on this same input —
    // proving the offline model genuinely adds Stage-3 capability the shipped default otherwise
    // lacks, rather than just duplicating existing behavior.
    let heuristic = HeuristicClassifier.classify("compare this code", &[]);
    assert!(
        !heuristic.should_clarify(),
        "the deterministic tier is documented to never clarify (sanity check on the contrast)"
    );
}

#[test]
fn r15_offline_classifier_acts_confidently_on_a_single_decisive_signal() {
    // A message with exactly one lexical signal must NOT be over-clarified — Stage-3 exists to
    // catch genuine ambiguity, not to add friction to every turn.
    let clf = ModelIntentClassifier::offline();
    let r = clf.classify("make a pdf report", &[]);
    assert!(
        !r.should_clarify(),
        "one decisive signal should act, not ask: {r:?}"
    );
    assert_eq!(r.intent, Intent::DocGeneration(OutputFormat::Pdf));
}

#[test]
fn r15_offline_classifier_defaults_open_questions_to_qa_without_asking() {
    // A plain open-ended question with no lexical signal at all must still answer normally — a
    // keyword miss is not the kind of ambiguity worth interrupting the user over (parity with
    // `HeuristicClassifier`'s own safe default, no UX regression from adding Stage-3 capability).
    let clf = ModelIntentClassifier::offline();
    let r = clf.classify("what is UPI?", &[]);
    assert!(
        !r.should_clarify(),
        "an ordinary question must not be blocked by Stage-3: {r:?}"
    );
    assert_eq!(r.intent, Intent::Qa);
}

// ---------------------------------------------------------------------------------------------
// gap [low] — "T4 exact 'export this' (verb, no format word) → clarify which content"
// ---------------------------------------------------------------------------------------------

/// Answers any prompt with a substantive (non-acknowledgement) turn, so a prior Q&A turn leaves a
/// real referent behind for the content resolver to point at.
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
async fn r15_t4_bare_export_this_with_no_prior_answer_asks_which_content() {
    let m = manager();
    let out = m
        .handle("s-r15-t4", &user(), "export this", DataClass::Public)
        .await
        .unwrap();
    assert!(
        matches!(out, ManagerOutcome::Clarify { .. }),
        "T4: a bare 'export this' (verb, no format word) with no prior substantive answer must \
         ask which content, not silently answer a Q&A: {out:?}"
    );
}

#[test]
fn r15_t4_heuristic_classifies_bare_export_verb_as_doc_generation() {
    // Unit-level pin on the classifier itself: "export this" has no explicit format word, so the
    // OLD code's `if let Some(fmt) = detect_format(&l) { if gen_verb {...} }` never fired and the
    // message fell all the way through to the generic `Qa` catch-all — it never even reached the
    // doc-generation outcome branch, so `resolve_content`'s ambiguity clarify was never consulted.
    let r = HeuristicClassifier.classify("export this", &[]);
    assert_eq!(r.intent, Intent::DocGeneration(OutputFormat::Pdf));
    assert!(!r.should_clarify());
}

#[tokio::test]
async fn r15_t4_bare_download_this_with_no_prior_answer_also_asks() {
    // "download" is grouped with "export" (§7 T4) — same bare-verb, no-format-word, no-prior-
    // content shape must ask too.
    let m = manager();
    let out = m
        .handle("s-r15-t4b", &user(), "download this", DataClass::Public)
        .await
        .unwrap();
    assert!(
        matches!(out, ManagerOutcome::Clarify { .. }),
        "bare 'download this' with no prior answer must ask which content: {out:?}"
    );
}

#[tokio::test]
async fn r15_t4_export_this_with_prior_answer_resolves_the_referent_not_the_instruction() {
    // Sanity check that the fix does not turn "export this" into an unconditional clarify — with
    // a real prior substantive answer, the referent resolves and the export proceeds (T1's
    // instruction-vs-content invariant, applied to the export verb).
    let m = manager();
    let _ = m
        .handle("s-r15-t4c", &user(), "how did UPI grow?", DataClass::Public)
        .await
        .unwrap();
    let out = m
        .handle("s-r15-t4c", &user(), "export this", DataClass::Public)
        .await
        .unwrap();
    match out {
        ManagerOutcome::Document { content, .. } => {
            assert!(
                !content.contains("export this"),
                "must not include the instruction verb phrase: {content:?}"
            );
        }
        other => panic!("expected a Document once a prior substantive answer exists: {other:?}"),
    }
}
