// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R15 (data-surfaces-artifacts): the two remaining `ainxt-replay` served-path entrypoints —
//! **re-execution replay** (medium) and the **shareable, credential-free replay bundle export**
//! (low) — over the SAME durable `SessionStore` the shipped daemon's `/v1/replay/step` reads and the
//! served turn path writes.
//!
//! Both entrypoints (`AssembledFull::re_execute_replay` / `AssembledFull::export_replay_bundle`) are
//! CLEAN, DRIVABLE, and exercised end-to-end offline here (fork/persist and content-commit/sign are
//! pure logic; the only genuinely infra-gated piece — a LIVE model call — sits behind the
//! `ReExecutor` seam, satisfied here by the offline `DeterministicReplayExecutor`, and a real
//! asymmetric bundle signature — satisfied here by the offline `ContentCommitmentSigner`).
//! `ainxt-server`/`ainxt-runtimed` are the daemon's RESERVED composition crates (round-15 policy):
//! mounting `POST /v1/replay/reexecute` and `GET /v1/replay/bundle` is the transport hookup
//! (`needs_hot_wiring`, documented on both entrypoints), tracked separately from this offline proof.

use ainxt_replay::{
    ContentCommitmentSigner, DeterministicReplayExecutor, EventKind, FrozenTurnInputs,
    ReplayOptions, SessionRecording, TurnRole,
};
use ainxt_runtimed::{assemble_full, assemble_surface, load_layered, LoadedConfig};
use ainxt_types::{DataClass, Principal};

fn offline() -> LoadedConfig {
    load_layered(&[("x", "version = 1")]).unwrap()
}

fn full() -> ainxt_runtimed::AssembledFull {
    // R16 critical: the daemon now refuses the header-trusting default authenticator unless the
    // deployment states the assumption (see r10_breach_clock_unit.rs) — state it here.
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let assembled = assemble_surface(&offline(), "chat").expect("assemble chat surface");
    assemble_full(&offline(), assembled).expect("assemble fully-wired surface")
}

fn seed(full: &ainxt_runtimed::AssembledFull, session: &str, participants: &[&str]) {
    let mut rec = SessionRecording::new(session, participants);
    rec.append_root_turn("t1", TurnRole::User, participants[0], 0)
        .expect("seed root turn");
    rec.set_frozen(
        "t1",
        FrozenTurnInputs {
            prompt: "what is the settlement window for UPI?".into(),
            model: "offline-default".into(),
            params: "temp=0".into(),
            seed: 7,
        },
    )
    .expect("attach frozen inputs");
    rec.record_event(
        "t1",
        EventKind::TextDelta,
        DataClass::Internal,
        "UPI settles T+0.",
        1,
    )
    .expect("seed one event");
    full.replay_store()
        .save(&rec.to_durable())
        .expect("seed durable session");
}

#[test]
fn r15_re_execute_replay_entrypoint_forks_new_branch_offline() {
    let full = full();
    seed(&full, "s-reexec", &["alice"]);
    let principal = Principal::user("alice", &[]).with_clearance(DataClass::Internal);
    let executor = DeterministicReplayExecutor::new(DataClass::Internal);

    let new_head = full
        .re_execute_replay(
            "s-reexec", "t1", "t1-fork", "alice", &principal, &executor, 100,
        )
        .expect("re-execution entrypoint succeeds offline");
    assert_eq!(
        new_head, "t1-fork",
        "the fork lands at the newly minted turn id"
    );

    // Reload from the SAME durable store `/v1/replay/step` would read — proving the fork is durable,
    // not merely an in-memory side effect of this one call.
    let durable = full
        .replay_store()
        .load("s-reexec")
        .expect("load ok")
        .expect("session persisted");
    assert!(
        durable.tree.turn("t1-fork").is_some(),
        "the forked branch must be persisted onto the SAME store"
    );
    assert!(
        durable.tree.turn("t1").is_some(),
        "re-execution must NEVER overwrite the original turn — it forks a sibling"
    );
    // The fork carries TWO events: the `Branch` marker (text = the target turn id, "t1") pushed by
    // `re_execute` itself, then the executor's own event(s) — find the latter specifically.
    let forked_event = durable
        .events
        .iter()
        .find(|e| e.turn_id == "t1-fork" && e.kind == EventKind::TextDelta)
        .expect("the offline executor's TextDelta event landed on the fork");
    assert!(
        forked_event.text.contains("offline re-execution"),
        "the offline DeterministicReplayExecutor's output must be persisted: {}",
        forked_event.text
    );
    // "t1" also carries its own `TurnStart` marker (empty text) ahead of the seeded content event —
    // find the TextDelta specifically, proving the ORIGINAL turn's content survives untouched.
    let original_event = durable
        .events
        .iter()
        .find(|e| e.turn_id == "t1" && e.kind == EventKind::TextDelta)
        .expect("the original turn's TextDelta event survives untouched");
    assert_eq!(original_event.text, "UPI settles T+0.");
}

#[test]
fn r15_export_replay_bundle_entrypoint_is_credential_free_and_verifiable_offline() {
    let full = full();
    seed(&full, "s-bundle", &["alice", "bob"]);
    let principal = Principal::user("alice", &[]).with_clearance(DataClass::Internal);
    let signer = ContentCommitmentSigner::new("test-signing-key");

    let bundle = full
        .export_replay_bundle(
            "s-bundle",
            &principal,
            &ReplayOptions::default(),
            "rt-1.0",
            &signer,
        )
        .expect("export entrypoint succeeds offline");

    assert_eq!(bundle.manifest.sid, "s-bundle");
    assert_eq!(bundle.manifest.event_count, bundle.events.len());
    assert!(
        bundle
            .events
            .iter()
            .any(|e| e.text.contains("UPI settles T+0.")),
        "the bundle carries the recorded (redacted) event content"
    );
    // Credential-free by construction: `BundleManifest` structurally carries no credential/roster
    // field — round-tripping through JSON proves no such field sneaks in via a stray `Serialize` impl.
    let json = serde_json::to_string(&bundle.manifest).expect("manifest serializes");
    assert!(
        !json.contains("participant"),
        "a bundle manifest must carry NO participant roster: {json}"
    );
    assert!(
        !json.contains("token") && !json.contains("secret"),
        "a bundle manifest must carry NO credentials: {json}"
    );

    // Integrity: the bundle verifies against the SAME signer (content-commitment + signature match)
    // and is rejected once tampered — proving `export_replay_bundle` produces a genuinely checkable
    // artifact, not just an opaque blob.
    assert!(
        bundle.verify(&signer),
        "a freshly exported bundle must verify"
    );
    let mut tampered = bundle.clone();
    if let Some(first) = tampered.events.first_mut() {
        first.text.push_str(" (tampered)");
    }
    assert!(
        !tampered.verify(&signer),
        "a tampered bundle must fail verification"
    );
}
