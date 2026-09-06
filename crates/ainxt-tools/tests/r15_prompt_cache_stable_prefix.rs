// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R15 §4.5 — structural prompt caching: stable-prefix cache key, invalidation on prompt change
//! (scenario 19), and the KV session-affinity hint for self-hosted models. Fail-before: nothing in
//! the tooling/routing crates modeled the stable-prefix cache as a stateful, invalidation-aware
//! decision — a hot-updated skill mid-session had no mechanism proving the NEXT call would reflect
//! the new prefix rather than a stale cached one. Pass-after: `PromptCache` is a real, deterministic
//! state machine: same prefix -> warm (with a growing streak); changed prefix -> explicit
//! `Invalidated` (never silently served stale) and the KV affinity pin is cleared with it.

use ainxt_tools::prompt_cache::{CacheOutcome, PromptCache};
use ainxt_types::DataClass;

const PERSONA_V1: &str = "You are AiNxt Chat. Skills: [kb.search, jira.create]. Guard: PCI/DSS.";
const PERSONA_V2: &str =
    "You are AiNxt Chat. Skills: [kb.search, jira.create, NEW_SKILL]. Guard: PCI/DSS.";

#[test]
fn first_turn_is_cold_by_construction() {
    let mut cache = PromptCache::new();
    let outcome = cache.observe("session-1", PERSONA_V1);
    assert_eq!(outcome, CacheOutcome::FirstUse);
    assert!(
        !cache.is_warm("session-1", PERSONA_V1),
        "not warm until a SECOND matching observe"
    );
}

#[test]
fn same_prefix_across_turns_stays_warm_with_a_growing_streak() {
    let mut cache = PromptCache::new();
    assert_eq!(cache.observe("s", PERSONA_V1), CacheOutcome::FirstUse);
    assert_eq!(
        cache.observe("s", PERSONA_V1),
        CacheOutcome::Warm { warm_streak: 2 }
    );
    assert_eq!(
        cache.observe("s", PERSONA_V1),
        CacheOutcome::Warm { warm_streak: 3 }
    );
    assert!(cache.is_warm("s", PERSONA_V1));
}

#[test]
fn scenario_19_prompt_change_mid_session_invalidates_the_cache() {
    // A harness's system prompt changes mid-session (a skill is hot-updated) — the design's exact
    // scenario 19: "The next turn's model call reflects the NEW stable prefix; no response is served
    // against a stale cached prefix."
    let mut cache = PromptCache::new();
    cache.observe("s", PERSONA_V1);
    cache.observe("s", PERSONA_V1); // warm

    let outcome = cache.observe("s", PERSONA_V2); // skill hot-updated
    assert_eq!(outcome, CacheOutcome::Invalidated);

    // The OLD prefix is no longer considered warm for this session — proves the cache does not keep
    // treating stale content as cached.
    assert!(!cache.is_warm("s", PERSONA_V1));
    // The NEW prefix is also not yet "warm" (this IS its first observation) — invalidation resets the
    // streak rather than fast-forwarding to warm.
    assert!(!cache.is_warm("s", PERSONA_V2));

    // But it settles correctly on subsequent turns with the new prefix.
    let next = cache.observe("s", PERSONA_V2);
    assert_eq!(next, CacheOutcome::Warm { warm_streak: 2 });
    assert!(cache.is_warm("s", PERSONA_V2));
}

#[test]
fn kv_session_affinity_hint_can_only_be_set_while_warm_and_is_cleared_on_invalidation() {
    let mut cache = PromptCache::new();
    cache.observe("s", PERSONA_V1);

    // Attempting to pin affinity against a prefix that was just observed for the FIRST time (cold,
    // not yet warm by this module's `is_warm` definition) is refused.
    assert!(!cache.set_affinity("s", PERSONA_V1, "gpu-node-7"));
    assert_eq!(cache.affinity_hint("s"), None);

    // Warm now (second observation of the SAME prefix) — the pin takes effect.
    cache.observe("s", PERSONA_V1);
    assert!(cache.set_affinity("s", PERSONA_V1, "gpu-node-7"));
    assert_eq!(cache.affinity_hint("s"), Some("gpu-node-7"));

    // A prompt change (mid-session skill update) invalidates the cache AND clears the affinity pin —
    // the old KV state is stale too, so the hint must never be carried forward blindly.
    cache.observe("s", PERSONA_V2);
    assert_eq!(cache.affinity_hint("s"), None);
}

#[test]
fn sessions_are_independent() {
    let mut cache = PromptCache::new();
    cache.observe("alice", PERSONA_V1);
    cache.observe("alice", PERSONA_V1);
    cache.observe("bob", PERSONA_V2);

    assert!(cache.is_warm("alice", PERSONA_V1));
    assert!(!cache.is_warm("bob", PERSONA_V1));
    assert!(!cache.is_warm("alice", PERSONA_V2));
    assert!(
        !cache.is_warm("bob", PERSONA_V2),
        "bob's first observation is cold, not yet warm"
    );
}

#[test]
fn warm_preference_bonus_feeds_router_ranking_and_is_zero_when_cold() {
    let mut cache = PromptCache::new();
    // Cold: no session yet.
    assert_eq!(cache.warm_preference_bonus("s", PERSONA_V1), 0.0);

    cache.observe("s", PERSONA_V1);
    // Still cold by this module's convention: only a SECOND matching observation is warm.
    assert_eq!(cache.warm_preference_bonus("s", PERSONA_V1), 0.0);

    cache.observe("s", PERSONA_V1);
    let bonus = cache.warm_preference_bonus("s", PERSONA_V1);
    assert!(
        bonus > 0.0,
        "a warm session must carry a positive ranking bonus, got {bonus}"
    );

    // A DIFFERENT (cold) prefix on the same session scores no bonus even though the session exists.
    assert_eq!(cache.warm_preference_bonus("s", PERSONA_V2), 0.0);
}

#[test]
fn data_class_import_is_reachable_for_downstream_composition() {
    // Sanity: `ainxt_types::DataClass` (the §4.2 classifier's type) is the one the router's ranking
    // step would carry alongside a warm-preference bonus — not a duplicate/local enum.
    let _ = DataClass::Internal;
}
