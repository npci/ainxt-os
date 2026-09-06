// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R11 gap closure (entrypoint proof): the groundedness rail is enforcement-ready on the OUTPUT
//! path. `RailChain::for_output` carries the groundedness rail, and when the rail is given the
//! turn's grounding context it BLOCKS (Enforce) / FLAGS (Audit) a fabricated answer and passes a
//! supported one.
//!
//! NOTE (needs_hot_wiring): the runtime engine (RESERVED crate `ainxt-runtime`) already builds this
//! output chain and runs it on the complete answer, but currently evaluates it with an EMPTY
//! grounding slice, so the groundedness rail cannot fire on the served path. Closing that requires
//! the engine to thread the turn's retrieved grounding corpus into the `evaluate(text, grounding)`
//! call — a reserved-crate wiring change. This test pins the clean entrypoint the engine must feed.

use ainxt_guardrails::{
    FaithfulnessJudge, GroundednessRail, GuardrailOutcome, GuardrailsConfig, Rail, RailChain,
    RailMode, RailVerdict,
};

/// A fake NLI/entailment judge (stands in for a real model offline).
struct FakeJudge(f32);
impl FaithfulnessJudge for FakeJudge {
    fn support(&self, _answer: &str, _context: &[String]) -> f32 {
        self.0
    }
}

#[test]
fn r11_groundedness_is_in_the_output_chain() {
    let cfg = GuardrailsConfig {
        groundedness: RailMode::Enforce,
        ..Default::default()
    };
    let out = RailChain::for_output(&cfg, None);
    assert_eq!(
        out.len(),
        1,
        "output chain must carry the groundedness rail"
    );
    // And it is NOT on the input chain (groundedness is output-only).
    assert!(RailChain::for_input(&cfg).is_empty());
}

#[test]
fn r11_groundedness_output_flags_fabricated_figure_with_context() {
    // Groundedness is advisory by design (redact-don't-block spirit): it FLAGS a hallucination and
    // proceeds, it never hard-blocks a turn. What the gap requires is that it actually FIRES on the
    // output path when given grounding context — which it does not today because the engine passes
    // an empty slice.
    let cfg = GuardrailsConfig {
        groundedness: RailMode::Enforce,
        ..Default::default()
    };
    let out = RailChain::for_output(&cfg, None);
    let context = vec!["UPI processed 12 billion transactions in the reported month.".to_string()];

    // A fabricated figure absent from the grounding context → flagged.
    match out.evaluate("UPI processed 47 billion transactions.", &context) {
        GuardrailOutcome::Flagged(flags) => {
            assert!(
                flags.iter().any(|f| f.contains("groundedness")),
                "{flags:?}"
            );
        }
        other => panic!("expected Flagged for an unsupported figure, got {other:?}"),
    }
    // A supported answer → allowed.
    assert_eq!(
        out.evaluate("UPI processed 12 billion transactions.", &context),
        GuardrailOutcome::Allowed
    );
    // With an EMPTY grounding slice (the current served-path call), the rail cannot judge and
    // passes — this is exactly the needs_hot_wiring gap: the engine must supply the context.
    assert_eq!(
        out.evaluate("UPI processed 47 billion transactions.", &[]),
        GuardrailOutcome::Allowed
    );
}

// GAP-FIX guardrails-injection — `GuardrailsConfig::groundedness_strict` was never read by
// `RailChain::from_config`/`for_output`, which always built a bare `GroundednessRail::default()` —
// a deployment's `groundedness_strict = true` silently did nothing on the served Engine output-rail
// path (only ainxt-convo's separate, hand-rolled `check_grounding` honored it).
#[test]
fn r11_for_output_honors_groundedness_strict_flag_unverifiable() {
    let strict_cfg = GuardrailsConfig {
        groundedness: RailMode::Enforce,
        groundedness_strict: true,
        ..Default::default()
    };
    let out = RailChain::for_output(&strict_cfg, None);
    // Zero sources at all, but the answer makes a substantive factual claim — strict mode must flag
    // it unverifiable rather than silently passing.
    match out.evaluate("Settlement volumes doubled to 500 million last year.", &[]) {
        GuardrailOutcome::Flagged(flags) => {
            assert!(
                flags.iter().any(|f| f.contains("unverifiable")),
                "{flags:?}"
            )
        }
        other => panic!("strict mode must flag a zero-source substantive claim, got {other:?}"),
    }

    // Control: WITHOUT strict mode (the default), the identical zero-source claim is NOT flagged —
    // proving the flag genuinely changes behavior rather than being a no-op either way.
    let default_cfg = GuardrailsConfig {
        groundedness: RailMode::Enforce,
        ..Default::default()
    };
    let out = RailChain::for_output(&default_cfg, None);
    assert_eq!(
        out.evaluate("Settlement volumes doubled to 500 million last year.", &[]),
        GuardrailOutcome::Allowed,
        "without strict, a zero-source claim is NOT flagged (this is the control)"
    );
}

#[test]
fn r11_groundedness_output_nli_judge_flags_unentailed_in_audit() {
    // Audit mode: a fabricated (unentailed) answer is FLAGGED-and-proceeds (redact-don't-block
    // spirit), driven by the pluggable NLI judge seam.
    let mut rail = GroundednessRail::default().with_judge(Box::new(FakeJudge(0.05)));
    rail.check_numbers = false;
    let context = vec!["settlement completes at midnight".to_string()];
    assert!(matches!(
        rail.check("settlement completes at noon", &context),
        RailVerdict::Flag(_)
    ));
}
