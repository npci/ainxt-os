// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX conversation-intelligence "multi-action format dropped".
//!
//! `HeuristicClassifier::detect_format` used a hardcoded if/else-if priority (Pdf checked first,
//! then Pptx, Xlsx, Docx) — a turn naming MORE THAN ONE mutually-exclusive output format
//! ("generate this as pdf and docx") silently collapsed to whichever format happened to be
//! checked first (always Pdf), throwing away the other named format with zero signal. This is
//! exactly the confident silent-wrong-guess `CONVERSATION_INTELLIGENCE.md` §0.3 forbids ("never a
//! silent wrong guess"), and — unlike `resolve_action`'s T5 multi-action priority, which is a
//! DESIGNED, tested, documented behavior (`CONV-08`) — nothing anywhere named or tested this
//! format-collision case.
//!
//! These tests drive the real, public `IntentClassifier::classify` entrypoint (not the private
//! `detect_format` directly) and prove: a genuinely multi-format turn no longer confidently
//! mis-names one format, a SINGLE named format still works exactly as before (no regression), and
//! the bare export/download-verb fallback (T4) does not re-commit the same bug.

use ainxt_convo::{HeuristicClassifier, Intent, IntentClassifier, OutputFormat};

fn classify(msg: &str) -> ainxt_convo::IntentResult {
    HeuristicClassifier.classify(msg, &[])
}

#[test]
fn r_multi_format_turn_is_not_confidently_mis_named_as_a_single_format() {
    let r = classify("please generate this as pdf and docx");
    // Before the fix this returned Intent::DocGeneration(OutputFormat::Pdf) at confidence 0.9,
    // silently dropping the docx request. It must NOT do that now.
    assert_ne!(
        r.intent,
        Intent::DocGeneration(OutputFormat::Pdf),
        "must not silently collapse a two-format request to Pdf: {r:?}"
    );
    assert_ne!(
        r.intent,
        Intent::DocGeneration(OutputFormat::Docx),
        "must not silently collapse a two-format request to Docx either: {r:?}"
    );
}

#[test]
fn r_multi_format_export_verb_fallback_also_does_not_default_to_pdf() {
    // T4's bare export/download fallback defaults to Pdf ONLY when no format is named at all;
    // it must not re-commit the same silent-drop when two formats ARE named.
    let r = classify("export this as pdf and docx please");
    assert_ne!(
        r.intent,
        Intent::DocGeneration(OutputFormat::Pdf),
        "the export-verb fallback must not default to Pdf when two formats were named: {r:?}"
    );
}

#[test]
fn r_single_format_still_classifies_confidently_no_regression() {
    let r = classify("please generate this as a pdf");
    assert_eq!(r.intent, Intent::DocGeneration(OutputFormat::Pdf));
    assert!((r.confidence - 0.9).abs() < f32::EPSILON);

    let r = classify("turn this into a deck");
    assert_eq!(r.intent, Intent::DocGeneration(OutputFormat::Pptx));
}

#[test]
fn r_bare_export_with_no_format_still_defaults_to_pdf_t4_unaffected() {
    // T4 (`CONVERSATION_INTELLIGENCE.md` §7): a bare "export this" with NO format word at all must
    // still default to Pdf — this fix must not regress that acceptance case.
    let r = classify("please export this");
    assert_eq!(r.intent, Intent::DocGeneration(OutputFormat::Pdf));
}
