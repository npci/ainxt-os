// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX tooling-mcp-plugins-routing (round 2) — "PromptCache has zero callers".
//!
//! `ainxt_tools::prompt_cache::PromptCache` (the stable-prefix structural cache; see
//! `ainxt-tools/tests/r15_prompt_cache_stable_prefix.rs`, its own unit-spec) previously existed ONLY
//! in `ainxt-tools/src/lib.rs` with zero callers anywhere else in the workspace, including its own
//! crate's production code — `grep -rln "PromptCache" crates/` found only the struct's own definition
//! and its unit test. Nothing in the served turn pipeline ever observed a session's stable prefix
//! through it, so a served turn could never actually produce a cache hit/miss/affinity signal, no
//! matter how correct the cache's own state machine was in isolation.
//!
//! `ainxt_runtime::Engine` now carries an optional `PromptCache` (`Engine::with_prompt_cache`),
//! observed exactly ONCE per turn (never per provider-retry) right before the agent loop, with the
//! outcome recorded to the audit trail, and a successful provider dispatch sets the session's
//! warm-affinity hint. `ainxt_runtimed::build_engine_ext` — the REAL composition-root function that
//! builds the daemon's bare/program/team engine — mounts a cache and threads the SAME shared handle
//! out (mirroring how `DispatchProbe` is already threaded out for the identical reason: the engine
//! exposes no getter for it once built).
//!
//! This test drives the REAL composed `Engine` (via `build_engine_ext`, never a bespoke hand-built
//! one) through TWO genuine turns and reads the SAME shared `PromptCache` handle back:
//!   1. Turn 1 (a session's first turn) leaves the cache cold — not yet warm.
//!   2. Turn 2 on the SAME session makes the cache warm (`warm_streak` reaches the >=2 threshold
//!      `PromptCache::is_warm` requires) AND sets a session-affinity hint to the provider that served
//!      it (the air-gapped default `"offline"` provider) — proving the cache is genuinely OBSERVED
//!      and USED on the real served turn pipeline, not merely constructible in isolation.
//!   3. A DIFFERENT, never-turned session has no warm state — proving cache state is scoped per
//!      session, never leaked across sessions sharing the same engine.

use ainxt_protocol::Request;
use ainxt_runtime::CancelToken;
use ainxt_runtimed::{build_engine_ext, load_layered};
use ainxt_types::{DataClass, Principal};

fn offline() -> ainxt_runtimed::LoadedConfig {
    load_layered(&[("x", "version = 1")]).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_prompt_cache_wired_engine_goes_cold_then_warm_across_two_real_turns_on_the_same_session()
{
    let loaded = offline();
    let (
        engine,
        _report,
        _ledger,
        _reconciler,
        _dispatch_probe,
        _tools,
        _outsourcing,
        _mandate_registry,
        _mcp_admin,
        prompt_cache,
        _serving,
    ) = build_engine_ext(&loaded.runtime)
        .expect("bare engine assembles through the REAL composition root");

    let principal = Principal::user("alice", &["chat.send"]);
    let cancel = CancelToken::new();
    let session = "gap5-prompt-cache-session";
    // `build_engine_ext` never calls `Engine::with_system_prompt`, so the engine's stable prefix for
    // this composition is the empty string — still a valid, deterministic key the cache tracks
    // per-session; what this test proves is the WIRING (observe/affinity called on a real turn),
    // not the cache's own hashing correctness (already proven in `r15_prompt_cache_stable_prefix.rs`).
    let stable_prefix = "";

    // Turn 1: this session's first-ever turn.
    let req1 = Request::chat(session, "t1", "hello there", DataClass::Public);
    let (tx1, rx1) = tokio::sync::mpsc::channel(16);
    let outcome1 = engine
        .run_turn_cancellable(&principal, &req1, tx1, &cancel)
        .await;
    drop(rx1);
    assert!(
        outcome1.is_ok(),
        "turn 1 must complete over the air-gapped offline provider: {outcome1:?}"
    );
    assert!(
        !prompt_cache
            .lock()
            .expect("prompt cache lock")
            .is_warm(session, stable_prefix),
        "a session's very first turn must not already read as cache-warm"
    );
    assert!(
        prompt_cache
            .lock()
            .expect("prompt cache lock")
            .affinity_hint(session)
            .is_none(),
        "PromptCache::set_affinity only takes effect once warm_streak >= 2 — after just turn 1 (streak \
         1) no affinity hint must be set yet"
    );

    // Turn 2: the SAME session, same stable prefix (unchanged engine composition) — the cache's own
    // warm-streak rule (`warm_streak >= 2`) means THIS is the first turn that reads as warm.
    let req2 = Request::chat(session, "t2", "hello again", DataClass::Public);
    let (tx2, rx2) = tokio::sync::mpsc::channel(16);
    let outcome2 = engine
        .run_turn_cancellable(&principal, &req2, tx2, &cancel)
        .await;
    drop(rx2);
    assert!(
        outcome2.is_ok(),
        "turn 2 must complete over the air-gapped offline provider: {outcome2:?}"
    );
    assert!(
        prompt_cache
            .lock()
            .expect("prompt cache lock")
            .is_warm(session, stable_prefix),
        "the SAME session's second turn must register as a cache hit through the REAL composed \
         engine returned by build_engine_ext — proving PromptCache::observe is genuinely called on \
         the served turn pipeline, not just unit-testable in isolation"
    );
    assert_eq!(
        prompt_cache
            .lock()
            .expect("prompt cache lock")
            .affinity_hint(session),
        Some("offline"),
        "once warm, a successful provider dispatch must set this session's KV-affinity hint to the \
         provider that actually served it — proving the cache is genuinely USED (Engine::set_affinity \
         called at the real dispatch success call site), not merely observed and discarded"
    );

    // A different, never-turned session must have completely independent (cold) state.
    assert!(
        !prompt_cache
            .lock()
            .expect("prompt cache lock")
            .is_warm("some-other-never-seen-session", stable_prefix),
        "cache state must be scoped per session — a session that never had a turn must never read as \
         warm just because ANOTHER session on the SAME engine did"
    );
}
