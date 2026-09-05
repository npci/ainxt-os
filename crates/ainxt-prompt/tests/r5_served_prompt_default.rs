// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R5 gap closure (Prompt Engineering) — the layered Registry / per-model-variant PromptService is a
//! first-class, PRODUCTION-staged, ready-to-serve DEFAULT, not a test-only / hand-rolled fixture.
//!
//! Written to FAIL before the change (`ainxt_prompt::served` did not exist) and PASS after. Offline +
//! deterministic (no infra).

use ainxt_prompt::layered::{HeuristicTokens, TruncatingCondenser};
use ainxt_prompt::registry::{ModelFamily, Semver, ServeError, Stage};
use ainxt_prompt::served::{
    default_served_chat_prompts, served_chat_prompts, DEFAULT_CHAT_CONTROL_SHA,
};
use ainxt_prompt::service::{NullSink, PromptService};

#[test]
fn r5_default_chat_prompts_are_production_staged_and_pinned() {
    let served = default_served_chat_prompts();
    assert_eq!(
        served.layer_ids.len(),
        4,
        "the four L1..L4 chat-Role layers"
    );
    let v = Semver::new(1, 0, 0);
    for id in &served.layer_ids {
        assert_eq!(
            served.registry.stage_of(id, v),
            Some(Stage::Production),
            "layer {id} must be driven all the way to PRODUCTION through the real gates"
        );
    }
    assert_eq!(served.control_sha, DEFAULT_CHAT_CONTROL_SHA);
}

#[test]
fn r5_default_serves_distinct_per_model_variants() {
    let served = default_served_chat_prompts();
    let svc = PromptService::new(&HeuristicTokens, &TruncatingCondenser, 10_000);
    let ids: Vec<&str> = served.layer_ids.iter().map(|s| s.as_str()).collect();

    let claude = svc
        .compile_turn(
            &served.registry,
            &served.deployment,
            &NullSink,
            "turn-1",
            &ModelFamily::new("claude"),
            &ids,
            "ctx",
            &served.control_sha,
        )
        .unwrap();
    let qwen = svc
        .compile_turn(
            &served.registry,
            &served.deployment,
            &NullSink,
            "turn-1",
            &ModelFamily::new("qwen"),
            &ids,
            "ctx",
            &served.control_sha,
        )
        .unwrap();

    // Per-model-variant serving (PRMT-01): the two families get DISTINCT pinned+verified bodies.
    assert_ne!(claude.text, qwen.text);
    assert!(claude.text.contains("[style:claude]"));
    assert!(qwen.text.contains("[style:qwen]"));
    assert_eq!(claude.version_tuple().len(), 4);
}

#[test]
fn r5_default_fails_closed_on_an_undeployed_family() {
    // A family with no pinned variant must fail closed at serve time (never a silent empty prompt).
    let served = served_chat_prompts(&[ModelFamily::new("claude")]);
    let svc = PromptService::new(&HeuristicTokens, &TruncatingCondenser, 10_000);
    let ids: Vec<&str> = served.layer_ids.iter().map(|s| s.as_str()).collect();
    let err = svc
        .compile_turn(
            &served.registry,
            &served.deployment,
            &NullSink,
            "t",
            &ModelFamily::new("gemma"),
            &ids,
            "ctx",
            &served.control_sha,
        )
        .unwrap_err();
    assert!(matches!(err, ServeError::VariantNotDeployed { .. }));
}
