// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-11 closure: the Skill Runtime is ACTIVE in production wiring (registered handlers + profile
//! skill refs), not an empty registry that fails closed on every reference (SURF medium).
//!
//! Fails before `SkillRuntime::with_builtins` existed (the daemon's `SkillRuntime::new(empty, …)`
//! returned `SkillError::NotFound` for any profile skill ref); passes after — a profile referencing a
//! built-in behavioral skill injects into the system prompt and an execution skill runs its native
//! handler into `## Context`.

use ainxt_skill::{builtin, SkillRuntime};

#[test]
fn r11_builtin_skill_runtime_resolves_behavioral_and_execution_refs() {
    let rt = SkillRuntime::with_builtins();

    // A profile that references BOTH a built-in behavioral SOP and a built-in execution skill — the
    // exact shape a canonical surface profile carries.
    let refs = vec![
        builtin::CITATION_DISCIPLINE.to_string(),
        builtin::TURN_HEADER.to_string(),
    ];
    let prepared = rt
        .prepare(&refs, "why did the settlement batch fail?")
        .expect("built-in refs resolve (not NotFound)");

    // Behavioral → system prompt.
    let sp = SkillRuntime::system_prompt("You are ops.", &prepared, &[]);
    assert!(sp.contains("You are ops."));
    assert!(
        sp.contains("Cite every factual claim"),
        "the citation-discipline SOP must inject into the system prompt: {sp}"
    );

    // Execution → ## Context, with the native handler REALLY run on the user's turn.
    let ctx = prepared.context_block();
    assert!(ctx.starts_with("## Context"));
    assert!(ctx.contains("### turn-header"));
    assert!(
        ctx.contains("Request under consideration: why did the settlement batch fail?"),
        "the turn-header native handler must run on the user input: {ctx}"
    );
}

#[test]
fn r11_empty_runtime_still_fails_closed_on_unknown_ref() {
    // The safety property the built-ins do NOT weaken: an unregistered ref is still a hard error.
    let rt = SkillRuntime::with_builtins();
    let err = rt
        .prepare(&["not-a-real-skill".to_string()], "x")
        .unwrap_err();
    assert!(matches!(err, ainxt_skill::SkillError::NotFound(_)));
}
