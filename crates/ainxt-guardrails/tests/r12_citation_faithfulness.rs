// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R12 gap closure (design AA — citation faithfulness rail): verify that each inline `[n]` citation
//! is supported by the SPECIFICALLY CITED source, not merely by some source in the corpus. This is
//! the failure ordinary groundedness passes: a true claim attributed to the wrong / a fabricated
//! source. Fail-before: `CitationRail` / `GuardrailsConfig::citation` did not exist.

use ainxt_guardrails::{
    CitationRail, FaithfulnessJudge, GuardrailOutcome, GuardrailsConfig, Rail, RailChain, RailMode,
    RailVerdict,
};

fn sources() -> Vec<String> {
    vec![
        "The settlement window closes at midnight for all member banks.".to_string(),
        "Refunds are processed within seven working days.".to_string(),
    ]
}

#[test]
fn r12_citation_flags_wrong_source_where_groundedness_passes() {
    let src = sources();
    // Claim IS supported by source [1], but the answer cites [2] (the refunds source).
    let wrong_cite = "The settlement window closes at midnight [2].";

    // Groundedness (support-by-ANY-source, numeric check off to isolate the lexical dimension from
    // the citation-marker digit) PASSES — the fact really is in the corpus.
    let mut grounded = ainxt_guardrails::GroundednessRail::default();
    grounded.check_numbers = false;
    assert!(
        matches!(grounded.check(wrong_cite, &src), RailVerdict::Pass),
        "groundedness should pass: the claim is supported by SOME source"
    );

    // Citation faithfulness FLAGS — the cited source [2] does not support the claim.
    let cite = CitationRail::default();
    match cite.check(wrong_cite, &src) {
        RailVerdict::Flag(r) => {
            assert!(
                r.contains("[2]"),
                "reason should name the unfaithful citation: {r}"
            );
        }
        other => panic!("expected Flag for a wrong citation, got {other:?}"),
    }
}

#[test]
fn r12_citation_passes_faithful_and_flags_fabricated_index() {
    let src = sources();
    let cite = CitationRail::default();

    // Faithful: the cited source actually supports the sentence.
    assert!(matches!(
        cite.check("The settlement window closes at midnight [1].", &src),
        RailVerdict::Pass
    ));

    // Fabricated: [5] points past the end of the retrieved list.
    match cite.check("The settlement window closes at midnight [5].", &src) {
        RailVerdict::Flag(r) => assert!(r.contains("non-existent"), "{r}"),
        other => panic!("expected Flag for a fabricated citation, got {other:?}"),
    }

    // No sources at all → nothing to attribute against → Pass (advisory, never spurious).
    assert!(matches!(
        cite.check("The settlement window closes at midnight [1].", &[]),
        RailVerdict::Pass
    ));
}

#[test]
fn r12_citation_is_in_the_output_chain_and_flags() {
    let cfg = GuardrailsConfig {
        citation: RailMode::Audit,
        ..Default::default()
    };
    // Present on the OUTPUT chain, absent on the INPUT chain (it is output-only).
    let out = RailChain::for_output(&cfg, None);
    assert_eq!(out.len(), 1, "output chain must carry the citation rail");
    assert!(RailChain::for_input(&cfg).is_empty());

    match out.evaluate("The settlement window closes at midnight [2].", &sources()) {
        GuardrailOutcome::Flagged(flags) => {
            assert!(flags.iter().any(|f| f.contains("citation")), "{flags:?}");
        }
        other => panic!("expected Flagged, got {other:?}"),
    }
}

/// An NLI/entailment judge (offline stand-in) drives per-citation support when attached.
struct FakeJudge(f32);
impl FaithfulnessJudge for FakeJudge {
    fn support(&self, _answer: &str, _cited: &[String]) -> f32 {
        self.0
    }
}

#[test]
fn r12_citation_uses_the_nli_judge_seam() {
    let src = sources();
    // A judge that says "unentailed" flags even a lexically-overlapping citation.
    let rail = CitationRail::default().with_judge(Box::new(FakeJudge(0.05)));
    assert!(matches!(
        rail.check("The settlement window closes at midnight [1].", &src),
        RailVerdict::Flag(_)
    ));
    // A judge that says "entailed" passes.
    let rail_ok = CitationRail::default().with_judge(Box::new(FakeJudge(0.95)));
    assert!(matches!(
        rail_ok.check("The settlement window closes at midnight [2].", &src),
        RailVerdict::Pass
    ));
}
