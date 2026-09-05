// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-AUDIT gap6-composition-root (Item 3) — `assemble_chat` is NOT the live default `/v1/chat`
//! composition, despite at least 8 doc comments across `ainxt-runtimed` (and one in `ainxt-chat`)
//! asserting exactly that ("the default `/v1/chat` surface"). `assemble_selected`'s dispatch table —
//! reached from `main.rs` via `assemble_selected_fabric_grounded` → `assemble_selected_governed` →
//! `assemble_selected` — has NO `"chat"` arm at all: every profile id, INCLUDING the default `"chat"`,
//! falls through to `assemble_surface`, which composes the SAME family of retrieval/cache/redaction
//! logic via `build_chat_surface_wired_authz` wrapped in a profile-enforced `ProfiledSurface` (RBAC
//! floor, department-scoped row isolation, `SurfaceScopedAuthorizer` capability bounding). Confirmed
//! via `grep -rn "assemble_chat(" crates/ainxt-runtimed/src/*.rs crates/ainxt-server/src/lib.rs`:
//! zero callers outside `assemble_chat`'s own definition and this crate's tests.
//!
//! DECISION (see `assemble_chat`'s own doc comment for the full reasoning): `assemble_chat` is kept,
//! not deleted, and not turned into a delegate `assemble_surface` calls into. It is a genuinely
//! different, un-profiled composition (`build_chat_surface_wired`, i.e. `build_chat_surface_wired_authz`
//! with no authz override, no provider allow-list, row isolation forced `false`) that ~30 call sites
//! across this crate's OWN test suite (kill-switch, canary, memory, mandate, wire-replay, sink-guard,
//! harness-renderer, compose-wiring, ...) depend on as a working chat-surface fixture that does NOT
//! carry the `"chat"` profile's mandatory `chat.send` RBAC capability or department-scoped row
//! isolation — swapping those onto `assemble_surface` would inject unrelated auth requirements into
//! every one of them for no gap-closing benefit. Every doc comment that falsely called it "the default"
//! is corrected instead (`lib.rs`, `fabric_chat.rs`, `ainxt-chat/src/lib.rs`).
//!
//! This file is the proof, not just an assertion: `Assembled::skill_runtime` is `Some` ONLY on the
//! profile-enforced `assemble_surface` path and `None` everywhere else (including `assemble_chat`) —
//! see both functions' own doc comments — so it is a clean, code-level discriminator between the two
//! compositions that a future regression (accidentally routing the daemon's `"chat"` default back
//! through `assemble_chat`) would trip.

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use ainxt_identity::control::ControlPlane;
use ainxt_runtimed::{
    assemble_chat, assemble_selected_fabric_grounded, load_layered, LoadedConfig,
};

fn unique_log_dir(tag: &str) -> String {
    // R16 critical: the daemon refuses the header-trusting default authenticator unless the
    // deployment states the assumption (same pattern as every other composition-root test).
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir()
        .join(format!("ainxt-gap6-assemble-chat-{tag}-{nanos}"))
        .to_string_lossy()
        .into_owned()
}

fn default_config(tag: &str) -> LoadedConfig {
    let dir = unique_log_dir(tag);
    let src = format!("version = 1\n[server]\nevent_log_dir = {dir:?}\n");
    load_layered(&[("gap6-assemble-chat", &src)]).expect("load default config")
}

#[test]
fn gap6_real_default_v1_chat_path_is_profile_enforced_assemble_surface_not_assemble_chat() {
    let loaded = default_config("real-default");
    let control = Arc::new(Mutex::new(ControlPlane::new()));

    // The EXACT dispatch chain `main.rs` drives for the shipped daemon's default surface (`"chat"`,
    // the value `main.rs` defaults `surface` to when `--surface` is not passed at all).
    let real_default = assemble_selected_fabric_grounded(&loaded, "chat", control)
        .expect("assemble the real default chat surface via the real main.rs dispatch chain");
    assert!(
        real_default.skill_runtime.is_some(),
        "the REAL default /v1/chat path is profile-enforced (assemble_surface -> ProfiledSurface, \
         which always carries a Some(SkillRuntime)) -- Some here proves \"chat\" resolved through \
         assemble_surface, NOT assemble_chat (which always sets skill_runtime: None)"
    );

    // `assemble_chat` itself: a real, still-useful, but materially DIFFERENT composition (un-profiled,
    // no SkillRuntime, no department row isolation, no capability-bounded authorizer) — never reached
    // by the daemon's own dispatch table, only ever called directly (this crate's test fixtures, and
    // this test).
    let un_profiled =
        assemble_chat(&loaded).expect("assemble_chat still compiles and assembles standalone");
    assert!(
        un_profiled.skill_runtime.is_none(),
        "assemble_chat's own contract: no profile/SkillRuntime layer -- confirms it is a genuinely \
         different, weaker composition than the real default this test just proved \"chat\" resolves \
         to, not a byte-identical alias for it"
    );
}
