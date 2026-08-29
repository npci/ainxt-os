// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX identity-payments (ADR-022 §15/§17/§19 "per-turn granularity",
//! `docs/architecture/AGENT_IDENTITY_AND_PAYMENT_BOUNDARY.md`).
//!
//! `GovernedChatSurface` (`ainxt-runtimed/src/chat_identity.rs`) — the fused §15 short-TTL JIT
//! renew-and-re-attest + §17/§19 in-flight admission gate driven on EVERY chat turn — was fully built
//! and unit-tested, and its own module doc even claims it is "additive and config-selectable". But
//! `assemble_selected` (the ONE dispatch table `main.rs`'s served daemon actually drives — every other
//! id, including the default `"chat"`, falls through to the ungoverned `assemble_surface`/
//! `assemble_chat`) had NO arm that could ever produce `assemble_chat_governed`'s surface, and
//! `assemble_full` always minted its OWN fresh `ControlPlane` with no way to share the one a
//! pre-assembled governed surface was built against. So the claimed "config-selectable" mechanism was
//! actually unreachable from the shipped daemon: an operator could never select it, and even if they
//! called `assemble_chat_governed` directly, the daemon's kill-switch/revocation endpoints (exposed on
//! `AssembledFull`, GAP-FIX `e759a5a`) would consult a DIFFERENT, disconnected plane.
//!
//! Net effect before this fix: the served `/v1/chat` surface ran chat identity lifecycle at NO
//! granularity whatsoever — not per-turn, not per-session, not per-run, simply never checked — while
//! the already-wired Program/Team executors call `ControlPlane::admit` on every turn (coarser would be
//! per-run; this was coarser still: absent).
//!
//! This test proves the fix: `assemble_selected_governed` adds the missing `"chat_governed"` id, and
//! `assemble_full_with_control_plane` lets the daemon thread ONE shared plane through both the
//! selected surface and its own kill-switch wiring, exactly as Program/Team already do.
//!
//! FAIL-BEFORE / PASS-AFTER: before this fix, `assemble_selected_governed` and
//! `assemble_full_with_control_plane` did not exist, so this test could not compile against the old
//! API; a kill-switch pulled on any `AssembledFull` could never influence a served chat turn under any
//! surface id.

use std::sync::{Arc, Mutex};

use ainxt_client::{Client, ClientConfig};
use ainxt_identity::authority::KillScope;
use ainxt_identity::control::ControlPlane;
use ainxt_identity::LogicalTime;
use ainxt_runtimed::{
    assemble_full, assemble_full_with_control_plane, assemble_selected, assemble_selected_governed,
    load_layered,
};
use ainxt_types::Principal;

fn governed_full(control: Arc<Mutex<ControlPlane>>) -> ainxt_runtimed::AssembledFull {
    // R16 critical: state the trusted-gateway assumption (see r10_breach_clock_unit.rs) — every other
    // served test in this crate does the same.
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let loaded = load_layered(&[("base", "version = 1")]).unwrap();
    let assembled = assemble_selected_governed(&loaded, "chat_governed", control.clone()).expect(
        "the new 'chat_governed' surface id must be selectable from the daemon's dispatch table",
    );
    assemble_full_with_control_plane(&loaded, assembled, control)
        .expect("assemble_full_with_control_plane must accept the caller-supplied shared plane")
}

/// The new opt-in surface actually serves an ordinary turn — the fix is not merely "compiles", it
/// produces a live, working chat surface.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chat_governed_is_selectable_and_serves_an_ordinary_turn() {
    let control = Arc::new(Mutex::new(ControlPlane::new()));
    let full = governed_full(control);
    let client = Client::in_process(
        full.manager.clone(),
        Principal::user("u-alice", &["chat.send"]),
        ClientConfig::default(),
    );
    let out = client
        .chat("gap-idp-s1", "t1", "hello")
        .unwrap()
        .collect()
        .await;
    assert!(
        out.completed && out.error.is_none(),
        "an ordinary turn on the new chat_governed surface must succeed: {out:?}"
    );
}

/// The load-bearing proof: a kill-switch pulled on the SAME shared `ControlPlane` the daemon exposes
/// via `AssembledFull::pull_kill_switch` (the served admin passthrough, GAP-FIX `e759a5a`) denies the
/// VERY NEXT turn of an in-flight chat_governed session — real per-turn reachability, not merely a
/// per-Run mint that is never re-checked.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kill_switch_pulled_on_the_shared_plane_denies_the_next_chat_governed_turn() {
    let control = Arc::new(Mutex::new(ControlPlane::new()));
    let full = governed_full(control);
    let client = Client::in_process(
        full.manager.clone(),
        Principal::user("u-bob", &["chat.send"]),
        ClientConfig::default(),
    );

    // First turn of the run: healthy plane, admitted.
    let out1 = client
        .chat("gap-idp-s2", "t1", "hi")
        .unwrap()
        .collect()
        .await;
    assert!(
        out1.completed && out1.error.is_none(),
        "the first turn must be admitted before any control action: {out1:?}"
    );

    // A senior, approving operator pulls the workforce-wide kill-switch on the SAME plane
    // `full.manager`'s governed surface consults every turn.
    full.pull_kill_switch(KillScope::Workforce, "u-exec", 1, true, LogicalTime(100))
        .expect("a senior approver with can_approve may pull the workforce kill-switch");

    // The NEXT turn of the SAME already-in-flight session must be denied fail-closed — this is the
    // per-turn granularity the design requires and the old (unreachable) mechanism could never deliver
    // because nothing on the served path ever consulted the shared plane for chat.
    let out2 = client
        .chat("gap-idp-s2", "t2", "are you still there")
        .unwrap()
        .collect()
        .await;
    assert!(
        out2.error.is_some(),
        "a workforce kill-switch pulled on the shared plane must deny the chat_governed surface's \
         very next turn: {out2:?}"
    );
}

/// Additivity / non-regression guard: the plain `"chat"` id must remain byte-identical to before —
/// ungoverned — even when the SAME `ControlPlane` instance handed to `assemble_selected_governed` has
/// its kill-switch pulled. `chat_identity.rs`'s own module doc requires this: the fix must not
/// silently change the shipped default `/v1/chat` surface.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn default_chat_id_stays_ungoverned_even_when_sharing_the_governed_control_plane() {
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let loaded = load_layered(&[("base", "version = 1")]).unwrap();
    let control = Arc::new(Mutex::new(ControlPlane::new()));

    // Sanity: `assemble_selected_governed` on the plain id is a byte-identical delegation to
    // `assemble_selected` (both must succeed the same way).
    assemble_selected(&loaded, "chat").expect("assemble_selected('chat') must still work");
    let assembled = assemble_selected_governed(&loaded, "chat", control.clone())
        .expect("assemble_selected_governed must fall through to assemble_selected for 'chat'");
    let full = assemble_full_with_control_plane(&loaded, assembled, control.clone())
        .expect("assemble_full_with_control_plane must still assemble the plain chat surface");

    // The builtin "chat" profile is department-scoped (orthogonal, pre-existing RBAC gate unrelated to
    // this fix — `ainxt_surface`'s admission refuses an unscoped principal), so the proving principal
    // needs a department, exactly like every other served-"chat"-surface test in this crate.
    let client = Client::in_process(
        full.manager.clone(),
        Principal::user("u-carol", &["chat.send"]).with_department("payments-eng"),
        ClientConfig::default(),
    );

    // Pull the kill-switch on the very plane threaded through the plain "chat" build.
    full.pull_kill_switch(KillScope::Workforce, "u-exec", 1, true, LogicalTime(1))
        .expect("a senior approver may pull the workforce kill-switch");

    // The plain "chat" surface never wraps with GovernedChatSurface, so it must remain unaffected —
    // proving the fix is additive, not a silent behavior change to the shipped default.
    let out = client
        .chat("gap-idp-s3", "t1", "hi")
        .unwrap()
        .collect()
        .await;
    assert!(
        out.completed && out.error.is_none(),
        "the plain 'chat' id must stay ungoverned (unaffected by a kill-switch on a plane it never \
         consults), exactly as before this fix: {out:?}"
    );

    // And the vanilla `assemble_full` (no control plane argument at all) still behaves exactly as
    // every pre-existing caller in this crate relies on.
    let assembled2 = assemble_selected(&loaded, "chat").unwrap();
    let full2 = assemble_full(&loaded, assembled2).unwrap();
    let client2 = Client::in_process(
        full2.manager.clone(),
        Principal::user("u-dave", &["chat.send"]).with_department("payments-eng"),
        ClientConfig::default(),
    );
    let out2 = client2
        .chat("gap-idp-s4", "t1", "hi")
        .unwrap()
        .collect()
        .await;
    assert!(
        out2.completed && out2.error.is_none(),
        "assemble_full (unchanged signature) must remain fully functional: {out2:?}"
    );
}
