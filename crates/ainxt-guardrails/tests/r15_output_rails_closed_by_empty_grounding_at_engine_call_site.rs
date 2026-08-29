// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R15 gap closure (needs_hot_wiring pin — subsystem guardrails-injection, item "Groundedness +
//! citation-faithfulness (AA) as OUTPUT rails on the engine path"): mirrors the RESERVED
//! `ainxt-runtime` engine's exact output-rail call site (§9) on both sides of the fix:
//!
//! ```ignore
//! // current call site
//! let output_rails = self.guardrails.as_ref().map(|cfg| RailChain::for_output(cfg, ...));
//! ...
//! match rails.evaluate(&final_text, &[]) { ... }   // <-- always an EMPTY grounding slice
//! ```
//!
//! The engine already builds the correct OUTPUT chain (groundedness + citation are members when
//! configured — see `r11_groundedness_output_enforced` / `r12_citation_faithfulness`) and calls the
//! exact `evaluate(text, context)` entrypoint. The one thing missing on the served path is that the
//! turn's actually-retrieved grounding corpus is never threaded into `context` — the call site always
//! passes `&[]`, so groundedness/citation can never fire no matter how the rails are configured. This
//! test proves that with the SHIPPED_DEFAULTS posture (`groundedness = audit`, `citation = audit`,
//! closed in Round 8), a fabricated-and-miscited answer:
//!   - is silently ALLOWED at today's exact call-site shape (`evaluate(text, &[])`) — fail-before;
//!   - is FLAGGED once the same call is given the turn's real grounding context — pass-after on our
//!     side of the seam.
//!
//! Threading the retrieved corpus into `context` at the reserved call site (the turn loop already
//! collects `rationale_sources` / memory `hits` — see `ainxt-runtime::turn`) is the needs_hot_wiring
//! step; nothing in `ainxt-runtime` is touched by this test.

use ainxt_guardrails::{GuardrailOutcome, GuardrailsConfig, RailChain, RailMode};

/// The SHIPPED_DEFAULTS posture (Round 8, `ainxt-runtimed::SHIPPED_DEFAULTS`): audit-on groundedness
/// + citation, mirrored here so this test tracks the actual shipped config shape.
fn shipped_defaults_guardrails() -> GuardrailsConfig {
    GuardrailsConfig {
        jailbreak: RailMode::Audit,
        groundedness: RailMode::Audit,
        toxicity: RailMode::Audit,
        system_prompt_leak: RailMode::Audit,
        citation: RailMode::Audit,
        ..Default::default()
    }
}

/// The turn's real grounding corpus — what the engine's retrieval already has in hand (memory hits /
/// hybrid-retriever chunks) but does not thread through today.
fn turn_grounding_corpus() -> Vec<String> {
    vec![
        "UPI processed 12 billion transactions in the reported month.".to_string(),
        "Settlement completes at midnight for all member banks.".to_string(),
    ]
}

/// Mirrors the RESERVED call site exactly: builds the output chain from config, then calls
/// `evaluate(text, context)` with whatever `context` the engine passes today (`&[]`).
fn engine_call_site(
    cfg: &GuardrailsConfig,
    final_text: &str,
    context: &[String],
) -> GuardrailOutcome {
    let chain = RailChain::for_output(cfg, None);
    chain.evaluate(final_text, context)
}

#[test]
fn r15_todays_empty_grounding_call_site_allows_a_fabricated_miscited_answer() {
    let cfg = shipped_defaults_guardrails();
    // A fabricated figure AND a citation pointing at a source that would not support it — exactly the
    // dual failure groundedness+citation exist to catch.
    let final_text = "UPI processed 47 billion transactions [2].";

    // FAIL-BEFORE: today's exact call-site shape (`&[]`) can never catch this — there is nothing to
    // check the claim or the citation against.
    let outcome = engine_call_site(&cfg, final_text, &[]);
    assert_eq!(
        outcome,
        GuardrailOutcome::Allowed,
        "with the engine's current empty-grounding call site, a fabricated/miscited answer is \
         silently allowed: {outcome:?}"
    );
}

#[test]
fn r15_same_call_site_with_real_grounding_flags_the_same_fabricated_miscited_answer() {
    let cfg = shipped_defaults_guardrails();
    let final_text = "UPI processed 47 billion transactions [2].";
    let context = turn_grounding_corpus();

    // PASS-AFTER on our side of the seam: the SAME call, given the turn's real grounding corpus,
    // flags the fabrication (audit mode: flag-and-proceed, never a hard block, per the redact-don't-
    // block spirit already baked into SHIPPED_DEFAULTS).
    let outcome = engine_call_site(&cfg, final_text, &context);
    match outcome {
        GuardrailOutcome::Flagged(flags) => {
            assert!(
                flags.iter().any(|f| f.contains("groundedness")),
                "expected a groundedness flag for the fabricated figure: {flags:?}"
            );
        }
        other => panic!("expected the fabricated/miscited answer to be flagged, got {other:?}"),
    }
}

#[test]
fn r15_same_call_site_with_real_grounding_still_allows_a_faithful_answer() {
    // Non-regression: threading real grounding context must not start flagging correct answers —
    // the fix only ADDS the ability to catch fabrications, it never tightens false positives.
    let cfg = shipped_defaults_guardrails();
    let context = turn_grounding_corpus();
    let outcome = engine_call_site(&cfg, "UPI processed 12 billion transactions.", &context);
    assert_eq!(outcome, GuardrailOutcome::Allowed);
}
