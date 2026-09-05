// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R12 (Prompt Engineering, §9 / PE7) — STEERABILITY gates model eligibility ON THE SERVED BUILD.
//! `steerability_gated_served_chat_prompts` constructs the served deployment from ONLY the families
//! whose measured instruction-following pass-rate clears the Role's bar; a below-bar or UNMEASURED
//! family never gets a pinned served variant (and serving it then fails closed).
//!
//! FAIL-BEFORE: `steerability_gated_served_chat_prompts` did not exist (won't compile). PASS-AFTER:
//! green. Offline + deterministic.

use ainxt_prompt::layered::{HeuristicTokens, TruncatingCondenser};
use ainxt_prompt::registry::{ModelFamily, ServeError};
use ainxt_prompt::served::steerability_gated_served_chat_prompts;
use ainxt_prompt::service::{NullSink, PromptService};
use ainxt_prompt::steerability::{grade_case, score, Constraint, SteerabilityScore};

fn score_at(family: &str, passes: usize, fails: usize) -> SteerabilityScore {
    let c = vec![Constraint::ExactBullets { n: 2 }];
    let mut verdicts = Vec::new();
    for i in 0..passes {
        verdicts.push(grade_case(&format!("{family}-p{i}"), "- a\n- b", &c));
    }
    for i in 0..fails {
        verdicts.push(grade_case(&format!("{family}-f{i}"), "- a\n- b\n- c", &c));
    }
    score(family, "v1", verdicts)
}

#[test]
fn r12_served_build_drops_below_bar_and_unmeasured_families() {
    let candidate = [
        ModelFamily::new("claude"),
        ModelFamily::new("qwen"),
        ModelFamily::new("gemma"),
    ];
    // claude strong (100%), qwen weak (20%), gemma UNMEASURED (no score at all).
    let scores = vec![score_at("claude", 10, 0), score_at("qwen", 2, 8)];

    let served = steerability_gated_served_chat_prompts(&candidate, &scores, 0.9)
        .expect("at least one family clears the bar");
    assert!(served.serves(&ModelFamily::new("claude")));
    assert!(
        !served.serves(&ModelFamily::new("qwen")),
        "below-bar family dropped"
    );
    assert!(
        !served.serves(&ModelFamily::new("gemma")),
        "unmeasured family dropped"
    );
    assert_eq!(served.families, vec![ModelFamily::new("claude")]);

    // Serving a gated-out family fails closed (no pinned variant).
    let svc = PromptService::new(&HeuristicTokens, &TruncatingCondenser, 10_000);
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

#[test]
fn r12_all_ineligible_candidate_set_has_no_served_deployment() {
    let candidate = [ModelFamily::new("qwen")];
    let scores = vec![score_at("qwen", 1, 9)]; // 10% — below 0.9
    assert!(
        steerability_gated_served_chat_prompts(&candidate, &scores, 0.9).is_none(),
        "an all-ineligible set must not silently serve an un-steerable model"
    );
}
