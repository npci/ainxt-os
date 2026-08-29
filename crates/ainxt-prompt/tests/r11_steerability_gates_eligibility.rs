// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R11 (Prompt Engineering, §9 / PE7) — STEERABILITY gates model eligibility on the served path. A
//! family whose measured instruction-following pass-rate is below the Role's bar is dropped from the
//! served set; a family with no measurement is never eligible (no evidence is not a pass). Serving a
//! gated-out family then fails closed at serve time.
//!
//! FAIL-BEFORE: `steerability_eligible_families` did not exist (won't compile). PASS-AFTER: green.

use ainxt_prompt::layered::{HeuristicTokens, TruncatingCondenser};
use ainxt_prompt::registry::{ModelFamily, ServeError};
use ainxt_prompt::served::{served_chat_prompts, steerability_eligible_families};
use ainxt_prompt::service::{NullSink, PromptService};
use ainxt_prompt::steerability::{grade_case, score, Constraint, SteerabilityScore};

/// A steerability score at an exact pass-rate: `passes` all-good cases + `fails` broken cases.
fn score_at(family: &str, passes: usize, fails: usize) -> SteerabilityScore {
    let c = [Constraint::ExactBullets { n: 2 }];
    let mut verdicts = Vec::new();
    for i in 0..passes {
        verdicts.push(grade_case(&format!("p{i}"), "- a\n- b", &c));
    }
    for i in 0..fails {
        verdicts.push(grade_case(&format!("f{i}"), "- only one", &c));
    }
    score(family, "1.0.0", verdicts)
}

#[test]
fn r11_below_bar_and_unmeasured_families_are_dropped_from_the_served_set() {
    let candidate = [
        ModelFamily::new("claude"),
        ModelFamily::new("qwen"),
        ModelFamily::new("gemma"),
    ];
    let scores = [
        score_at("claude", 10, 0), // 1.00 — eligible
        score_at("qwen", 4, 6),    // 0.40 — below bar
                                   // gemma: NO score → never eligible.
    ];

    let eligible = steerability_eligible_families(&candidate, &scores, 0.9);
    assert_eq!(eligible, vec![ModelFamily::new("claude")]);
}

#[test]
fn r11_serving_a_gated_out_family_fails_closed() {
    let candidate = [ModelFamily::new("claude"), ModelFamily::new("qwen")];
    let scores = [score_at("claude", 10, 0), score_at("qwen", 3, 7)];
    let eligible = steerability_eligible_families(&candidate, &scores, 0.9);
    assert_eq!(eligible, vec![ModelFamily::new("claude")]);

    // Build the served deployment over ONLY the eligible families.
    let served = served_chat_prompts(&eligible);
    assert!(served.serves(&ModelFamily::new("claude")));
    assert!(!served.serves(&ModelFamily::new("qwen")));

    // Attempting to serve the gated-out family fails closed (never a silent empty prompt).
    let est = HeuristicTokens;
    let cond = TruncatingCondenser;
    let svc = PromptService::new(&est, &cond, 10_000);
    let ids: Vec<&str> = served.layer_ids.iter().map(|s| s.as_str()).collect();
    let err = svc
        .compile_turn(
            &served.registry,
            &served.deployment,
            &NullSink,
            "t",
            &ModelFamily::new("qwen"),
            &ids,
            "ctx",
            &served.control_sha,
        )
        .unwrap_err();
    assert!(matches!(err, ServeError::VariantNotDeployed { .. }));
}
