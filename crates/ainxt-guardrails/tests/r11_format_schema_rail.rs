// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R11 gap closure: Format / schema validation rail (ADR-008, PE3 companion to constrained
//! decoding). The rail verifies the MODEL ANSWER actually conforms to the structured shape the
//! turn requested — valid JSON with required keys, a closed-vocabulary label, non-empty, or a
//! length bound — before the malformed answer reaches a downstream parser.
//!
//! Written to FAIL before the change (no `FormatRail` / `FormatSpec` / `format` config field) and
//! PASS after. No live model needed — the rail is deterministic.

use ainxt_guardrails::{
    FormatRail, FormatSpec, GuardrailOutcome, GuardrailsConfig, Rail, RailChain, RailMode,
    RailVerdict,
};

#[test]
fn r11_format_json_required_keys() {
    let rail = FormatRail::new(FormatSpec::Json {
        required_keys: vec!["decision".to_string(), "amount".to_string()],
    });
    // Malformed JSON → Block.
    assert!(matches!(
        rail.check("{not json at all", &[]),
        RailVerdict::Block(_)
    ));
    // Valid JSON but missing a required key → Block.
    assert!(matches!(
        rail.check(r#"{"decision":"approve"}"#, &[]),
        RailVerdict::Block(_)
    ));
    // Valid JSON with all required keys → Pass (leading/trailing whitespace tolerated).
    assert_eq!(
        rail.check("  {\"decision\":\"approve\",\"amount\":100}  ", &[]),
        RailVerdict::Pass
    );
}

#[test]
fn r11_format_one_of_closed_vocabulary() {
    let rail = FormatRail::new(FormatSpec::OneOf {
        values: vec!["simple".into(), "medium".into(), "complex".into()],
        ignore_case: true,
    });
    assert_eq!(rail.check("COMPLEX", &[]), RailVerdict::Pass);
    assert!(matches!(
        rail.check("extremely-complex", &[]),
        RailVerdict::Block(_)
    ));
}

#[test]
fn r11_format_nonempty_and_maxchars() {
    assert!(matches!(
        FormatRail::new(FormatSpec::NonEmpty).check("   \n ", &[]),
        RailVerdict::Block(_)
    ));
    assert_eq!(
        FormatRail::new(FormatSpec::NonEmpty).check("ok", &[]),
        RailVerdict::Pass
    );
    let short = FormatRail::new(FormatSpec::MaxChars { limit: 5 });
    assert_eq!(short.check("hello", &[]), RailVerdict::Pass);
    assert!(matches!(
        short.check("hello world", &[]),
        RailVerdict::Block(_)
    ));
}

#[test]
fn r11_format_any_is_a_noop() {
    // Enabling the rail without a spec (default Any) must never block anything.
    assert_eq!(
        FormatRail::new(FormatSpec::Any).check("", &[]),
        RailVerdict::Pass
    );
    assert_eq!(
        FormatRail::new(FormatSpec::Any).check("literally anything {[", &[]),
        RailVerdict::Pass
    );
}

#[test]
fn r11_format_rail_wired_into_output_chain_and_enforces() {
    // The format rail is an OUTPUT rail: it must appear in for_output and hard-block malformed JSON
    // under Enforce, and it must NOT appear on the input chain.
    let cfg = GuardrailsConfig {
        format: RailMode::Enforce,
        format_spec: FormatSpec::Json {
            required_keys: vec!["label".to_string()],
        },
        ..Default::default()
    };
    assert!(!cfg.is_off(), "format rail must count toward is_off()");

    let out = RailChain::for_output(&cfg, None);
    assert!(!out.is_empty(), "output chain must carry the format rail");
    assert!(matches!(
        out.evaluate("this is prose, not the requested JSON", &[]),
        GuardrailOutcome::Blocked(_)
    ));
    assert_eq!(
        out.evaluate(r#"{"label":"fraud"}"#, &[]),
        GuardrailOutcome::Allowed
    );

    // Input chain is output-only for format: it should not carry the rail.
    assert!(RailChain::for_input(&cfg).is_empty());
}

#[test]
fn r11_format_config_roundtrips_via_serde() {
    let cfg: GuardrailsConfig = serde_json::from_str(
        r#"{"format":"audit","format_spec":{"kind":"one_of","values":["yes","no"]}}"#,
    )
    .unwrap();
    assert_eq!(cfg.format, RailMode::Audit);
    match cfg.format_spec {
        FormatSpec::OneOf { values, .. } => assert_eq!(values, vec!["yes", "no"]),
        other => panic!("unexpected spec: {other:?}"),
    }
}
