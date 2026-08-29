// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R12 (Prompt Engineering, §BE) — on the SERVED (layered) path, adaptive reasoning depth ROUTES BY
//! TIER: `PromptService::compile_turn_adaptive` classifies the raw user message, injects a depth
//! directive at high recency (before L5), AND returns the depth so the caller routes by `depth.tier()`
//! instead of a fixed tier. This is the crate-side proof; the served convo/chat call site must call the
//! adaptive entrypoint (needs_hot_wiring — it currently calls the fixed `compile_turn`).
//!
//! FAIL-BEFORE: exercises `compile_turn_adaptive` + `depth.tier()` from outside the crate. PASS-AFTER:
//! green. Offline + deterministic.

use ainxt_prompt::layered::{HeuristicTokens, TruncatingCondenser};
use ainxt_prompt::registry::ModelFamily;
use ainxt_prompt::served::default_served_chat_prompts;
use ainxt_prompt::service::{NullSink, PromptService};
use ainxt_prompt::{HeuristicComplexity, ReasoningDepth};
use ainxt_types::Tier;

#[test]
fn r12_served_adaptive_compile_routes_by_depth_tier() {
    let served = default_served_chat_prompts();
    let svc = PromptService::new(&HeuristicTokens, &TruncatingCondenser, 10_000);
    let ids: Vec<&str> = served.layer_ids.iter().map(|s| s.as_str()).collect();
    let clf = HeuristicComplexity;
    let fam = ModelFamily::new("claude");

    let (_shallow_prompt, d_shallow) = svc
        .compile_turn_adaptive(
            &served.registry,
            &served.deployment,
            &NullSink,
            "t1",
            &fam,
            &ids,
            "ctx",
            &served.control_sha,
            "hi",
            &clf,
        )
        .unwrap();

    let (deep_prompt, d_deep) = svc
        .compile_turn_adaptive(
            &served.registry,
            &served.deployment,
            &NullSink,
            "t2",
            &fam,
            &ids,
            "ctx",
            &served.control_sha,
            "why does the settlement reconciliation fail — analyze the root cause",
            &clf,
        )
        .unwrap();

    // Route BY depth, not a fixed tier: a greeting → Simple, a deep analytical ask → Complex.
    assert_eq!(d_shallow.tier(), Tier::Simple);
    assert_eq!(d_deep.tier(), Tier::Complex);
    assert_ne!(d_shallow, d_deep);

    // The depth directive is injected at high recency (a [REASONING] block before the L5 context).
    assert!(deep_prompt.text.contains("[REASONING]"));
    assert!(deep_prompt.text.contains(ReasoningDepth::Deep.directive()));
    let reasoning_at = deep_prompt.text.find("[REASONING]").unwrap();
    let l5_at = deep_prompt.text.find("[L5-CONTEXT]").unwrap();
    assert!(
        reasoning_at < l5_at,
        "reasoning directive must sit above the untrusted L5 context"
    );
}
