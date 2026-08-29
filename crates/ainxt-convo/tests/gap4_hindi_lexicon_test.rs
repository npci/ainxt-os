// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX conversation-intelligence "lexicon English-only" — proving tests.
//!
//! Every deterministic Stage-1/2 keyword set in `ainxt-convo` (`gen_verb`, format words, action
//! verbs, anaphora, ack/clarify detection) used to be hardcoded English strings, so the
//! deterministic tier never fired for Hindi input and a Hindi-speaking user always fell through to
//! the model-backed tier (slower/costlier), or was misclassified when no model tier was
//! configured. This file drives the SAME public API the existing English-only regression tests use
//! (`HeuristicClassifier`, `resolve_content`, `resolve_action`, `is_followup`,
//! `last_substantive_assistant`), but with Hindi (Devanagari) input, and is written to FAIL on the
//! pre-fix English-only lexicon (every assertion below would previously resolve to the generic
//! `Qa`/`Ambiguous`/`false` fallback instead of the correct classification) and PASS after.
//!
//! No network, no ML runtime, no live provider — purely the deterministic tier, matching the
//! "shipped air-gapped default" scope of the rest of this crate's gap-closure tests.

use ainxt_convo::{
    is_followup, last_substantive_assistant, resolve_action, resolve_content, ActionKind,
    ContentSource, HeuristicClassifier, Intent, IntentClassifier, Message, Role,
};

fn classify(msg: &str) -> Intent {
    HeuristicClassifier.classify(msg, &[]).intent
}

// ---------------------------------------------------------------------------------------------
// gen_verb + format words: "इसे पीडीएफ बनाओ" ("make this into a pdf") must deterministically
// resolve to DocGeneration(Pdf), exactly the way "make this into a pdf" already does in English.
// ---------------------------------------------------------------------------------------------
#[test]
fn hindi_gen_verb_and_format_word_trigger_doc_generation_deterministically() {
    assert_eq!(
        classify("इसे पीडीएफ बनाओ"),
        Intent::DocGeneration(ainxt_convo::OutputFormat::Pdf)
    );
    assert_eq!(
        classify("रिपोर्ट वर्ड में लिखो"),
        Intent::DocGeneration(ainxt_convo::OutputFormat::Docx)
    );
    assert_eq!(
        classify("डेटा एक्सेल में बनाओ"),
        Intent::DocGeneration(ainxt_convo::OutputFormat::Xlsx)
    );
}

// ---------------------------------------------------------------------------------------------
// T4 analog: a bare Hindi export verb with no format word still names a downloadable-artifact
// intent (defaults to Pdf) instead of falling through to plain Q&A.
// ---------------------------------------------------------------------------------------------
#[test]
fn hindi_bare_export_verb_without_format_still_names_doc_generation() {
    assert_eq!(
        classify("इसे निर्यात करो"),
        Intent::DocGeneration(ainxt_convo::OutputFormat::Pdf)
    );
}

// ---------------------------------------------------------------------------------------------
// The T7 "deferred" over-trigger guard must ALSO recognize Hindi future-tense phrasing — a stated
// future intention ("बाद में" = "later") must not fire doc-generation now.
// ---------------------------------------------------------------------------------------------
#[test]
fn hindi_deferred_doc_verb_does_not_trigger_generation_now() {
    let intent = classify("बाद में इसे पीडीएफ बनाओ");
    assert_ne!(
        intent,
        Intent::DocGeneration(ainxt_convo::OutputFormat::Pdf),
        "a deferred ('later') Hindi doc-gen phrasing must not fire now, got {intent:?}"
    );
}

// ---------------------------------------------------------------------------------------------
// Multi-format guard (mirrors `r_multi_format_not_dropped.rs`): a Hindi turn naming TWO
// mutually-exclusive formats must not be confidently mis-named as either one.
// ---------------------------------------------------------------------------------------------
#[test]
fn hindi_multi_format_turn_is_not_confidently_mis_named() {
    let intent = classify("इसे पीडीएफ और वर्ड दोनों में बनाओ");
    assert_ne!(
        intent,
        Intent::DocGeneration(ainxt_convo::OutputFormat::Pdf),
        "a turn naming two Hindi formats must not silently collapse to Pdf, got {intent:?}"
    );
    assert_ne!(
        intent,
        Intent::DocGeneration(ainxt_convo::OutputFormat::Docx),
        "a turn naming two Hindi formats must not silently collapse to Docx, got {intent:?}"
    );
}

// ---------------------------------------------------------------------------------------------
// Action verbs: comparison (बनाम/तुलना), code (कोड), task (टिकट खोलो) — each in the SAME priority
// order as the English lexicon (code before task).
// ---------------------------------------------------------------------------------------------
#[test]
fn hindi_comparison_request_is_recognized() {
    assert_eq!(classify("UPI बनाम NEFT"), Intent::Comparison);
    assert_eq!(classify("दोनों की तुलना करो"), Intent::Comparison);
}

#[test]
fn hindi_code_request_is_recognized() {
    assert_eq!(classify("यह कोड ठीक करो"), Intent::Code);
}

#[test]
fn hindi_task_request_is_recognized() {
    assert_eq!(classify("टिकट खोलो"), Intent::Task);
}

// ---------------------------------------------------------------------------------------------
// resolve_action: the content-consuming action verbs (email/translate/summarize/save) in Hindi,
// with the content still resolved from context (instruction != content), never the instruction.
// ---------------------------------------------------------------------------------------------
#[test]
fn hindi_resolve_action_recognizes_email_translate_summarize_save() {
    let history = vec![
        Message::new(Role::User, "UPI वृद्धि क्या है?"),
        Message::new(Role::Assistant, "UPI लेनदेन में ~45% वार्षिक वृद्धि हुई।"),
    ];

    let email = resolve_action("इसे भेजो", &history).expect("email action recognized");
    assert_eq!(email.action, ActionKind::Email);
    assert!(matches!(email.content, ContentSource::Referent(_)));

    let translate =
        resolve_action("इसका अनुवाद करो", &history).expect("translate action recognized");
    assert_eq!(translate.action, ActionKind::Translate);

    let summarize = resolve_action("इसका सारांश दो", &history).expect("summarize action recognized");
    assert_eq!(summarize.action, ActionKind::Summarize);

    let save = resolve_action("इसे सहेजो", &history).expect("save action recognized");
    assert_eq!(save.action, ActionKind::Save);
}

// ---------------------------------------------------------------------------------------------
// Anaphora: a Hindi "it"/"this" pronoun resolves the referent to the prior substantive assistant
// answer, exactly the way the English "generate this as pdf" bug fix works — the instruction
// (bare Hindi pronoun) must never be mistaken for the content.
// ---------------------------------------------------------------------------------------------
#[test]
fn hindi_anaphora_resolves_to_prior_substantive_answer() {
    let history = vec![
        Message::new(Role::User, "UPI वृद्धि क्या है?"),
        Message::new(Role::Assistant, "UPI लेनदेन में ~45% वार्षिक वृद्धि हुई।"),
    ];
    match resolve_content("इसे पीडीएफ में बनाओ", &history) {
        ContentSource::Referent(text) => {
            assert!(
                text.contains("45%"),
                "expected the prior answer, got {text:?}"
            )
        }
        other => panic!("expected a Referent resolved via Hindi anaphora, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------------------------
// Follow-up detection: Hindi conjunction लीड + the reversed-order "X के बारे में क्या" phrasing +
// the postpositional "भी" particle must ALL mark a longer (>6-word) Hindi turn as a follow-up,
// exactly the way "and NEFT?"/"what about NEFT?"/"also tell me about NEFT" do in English — with a
// same-length, non-triggering Hindi control proving this is not just the generic short-turn
// fallback.
// ---------------------------------------------------------------------------------------------
#[test]
fn hindi_followup_conjunction_and_trailing_about_phrase_are_recognized() {
    let history = vec![Message::new(Role::Assistant, "UPI लेनदेन में वृद्धि हुई है।")];

    assert!(
        is_followup("और NEFT ट्रांजैक्शन की सीमा कितनी है अभी", &history),
        "a Hindi turn opening with 'और' (and) must be recognized as a follow-up"
    );
    assert!(
        is_followup("NEFT के बारे में क्या जानकारी चाहिए अभी विस्तार से", &history),
        "the Hindi 'X के बारे में क्या' (what about X) trailing phrasing must be recognized"
    );
    assert!(
        is_followup("मुझे इसकी जानकारी भी चाहिए अभी विस्तार से बताओ", &history),
        "the Hindi postpositional 'भी' (also) particle must be recognized as a whole word"
    );
    // Control: a same-length Hindi turn with none of the follow-up signals must NOT be flagged —
    // proves the assertions above are driven by the new Hindi keywords, not just Hindi text in
    // general or the generic <=6-word short-turn fallback.
    assert!(
        !is_followup("NEFT ट्रांजैक्शन की सीमा कितनी है अभी विस्तार से बताओ", &history),
        "a Hindi turn with no anaphora/conjunction/'about' signal must not be a false positive"
    );
}

// ---------------------------------------------------------------------------------------------
// Ack/clarify detection: a bare Hindi acknowledgement ("ठीक है") and a Hindi clarifying question
// must both be skipped when resolving the last SUBSTANTIVE assistant answer — exactly the
// English-language "skip acknowledgements"/"skip clarifying questions" contract
// (`CONVERSATION_INTELLIGENCE.md` §4), now honored for Hindi too.
// ---------------------------------------------------------------------------------------------
#[test]
fn hindi_ack_phrase_is_skipped_when_resolving_last_substantive_answer() {
    let history = vec![
        Message::new(Role::User, "UPI वृद्धि क्या है?"),
        Message::new(Role::Assistant, "UPI लेनदेन में ~45% वार्षिक वृद्धि हुई।"),
        Message::new(Role::User, "धन्यवाद"),
        // A bare Hindi acknowledgement the model might emit — carries no content.
        Message::new(Role::Assistant, "ठीक है"),
    ];
    let answer = last_substantive_assistant(&history).expect("a substantive answer exists");
    assert!(
        answer.contains("45%"),
        "the bare Hindi ack 'ठीक है' must be skipped, got {answer:?}"
    );
}

#[test]
fn hindi_clarifying_question_is_skipped_when_resolving_last_substantive_answer() {
    let history = vec![
        Message::new(Role::User, "UPI वृद्धि क्या है?"),
        Message::new(Role::Assistant, "UPI लेनदेन में ~45% वार्षिक वृद्धि हुई।"),
        Message::new(Role::User, "इसे डॉक्यूमेंट बनाओ"),
        // A Hindi clarifying question the model might ask back — must not be treated as the
        // referenceable content.
        Message::new(Role::Assistant, "आप कौन सा प्रारूप चाहते हैं?"),
    ];
    let answer = last_substantive_assistant(&history).expect("a substantive answer exists");
    assert!(
        answer.contains("45%"),
        "the Hindi clarifying question must be skipped, got {answer:?}"
    );
}
