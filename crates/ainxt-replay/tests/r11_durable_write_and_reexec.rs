// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R11 DATA — the turn-tree as a first-class DURABLE object (gap: "turn-tree as a first-class
//! durable object for branch/edit/stop/steer — the WRITE path") and durable RE-EXECUTION replay
//! (gap: "re-execution replay — re-run frozen inputs against a live model, forked to a new branch").
//!
//! The tree ops and the store seam existed and the READ path (`step_replay_session`) was covered by
//! r6, but nothing exercised the store-backed WRITE entrypoints end-to-end: that a branch/edit/stop/
//! steer applied through `apply_interaction_persisted` in one "request" is visible to the NEXT
//! request (it durably round-trips through the `SessionStore`), and that `re_execute_persisted` forks
//! a NEW branch off a frozen turn (against the offline default behind the live-model seam) WITHOUT
//! mutating the original, persisting the fork.
//!
//! Fail-before/pass-after: `DeterministicReplayExecutor` did not exist (so this crate would not
//! compile), and no test proved the persisted write/re-exec entrypoints round-trip across store
//! loads. Live model: the re-run itself is INFRA-gated behind the `ReExecutor` seam; this proves the
//! entire fork/authz/persistence envelope with the shipped offline executor.

use ainxt_replay::{
    apply_interaction_persisted, re_execute_persisted, replay_session, DataClass,
    DeterministicReplayExecutor, FrozenTurnInputs, InMemorySessionStore, Interaction,
    InteractionOutcome, PersistedError, Principal, ReplayOptions, SessionRecording, SessionStore,
    TurnRole,
};

fn priya() -> Principal {
    Principal::user("priya", &[]).with_clearance(DataClass::Internal)
}

/// Seed a store with session `s1` owned by `priya`: user `u1` -> active assistant `a1` (frozen).
fn seeded_store() -> InMemorySessionStore {
    let mut r = SessionRecording::new("s1", &["priya"]);
    r.append_root_turn("u1", TurnRole::User, "priya", 100)
        .unwrap();
    r.append_turn("a1", "u1", TurnRole::Assistant, "assistant", 110)
        .unwrap();
    r.set_frozen(
        "a1",
        FrozenTurnInputs {
            prompt: "compute settlement".into(),
            model: "claude-sonnet-4-6".into(),
            params: "temp=0".into(),
            seed: 7,
        },
    )
    .unwrap();
    let store = InMemorySessionStore::new();
    store.save(&r.to_durable()).unwrap();
    store
}

#[test]
fn r11_durable_branch_edit_stop_steer_round_trip_across_requests() {
    let store = seeded_store();

    // Request 1: branch off a1. The mutation must be persisted (not thrown away like the old
    // ephemeral rebuild-per-request path).
    let out = apply_interaction_persisted(
        &store,
        "s1",
        &Interaction::Branch {
            from_turn: "a1".to_string(),
            new_id: "b1".to_string(),
            label: Some("what-if".to_string()),
        },
        &priya(),
        200,
    )
    .unwrap();
    assert!(matches!(out, InteractionOutcome::HeadMoved { .. }));

    // Request 2 (fresh load from the store): the branch survived — 3 turns now, head at b1.
    let after1 = store.load("s1").unwrap().unwrap();
    let rec1 = SessionRecording::from_durable(after1);
    assert_eq!(rec1.tree().turn_count(), 3);
    assert_eq!(rec1.tree().active_head(), Some("b1"));

    // Request 3: edit the user turn u1 — forks a sibling, NEVER mutating history.
    apply_interaction_persisted(
        &store,
        "s1",
        &Interaction::Edit {
            turn: "u1".to_string(),
            new_id: "u1e".to_string(),
            label: None,
        },
        &priya(),
        300,
    )
    .unwrap();

    // Request 4: steer a1 (still active) — accepted, persisted.
    apply_interaction_persisted(
        &store,
        "s1",
        &Interaction::Steer {
            turn: "a1".to_string(),
            text: "also include UPI".to_string(),
            data_class: DataClass::Internal,
        },
        &priya(),
        310,
    )
    .unwrap();

    // Request 5: stop a1.
    apply_interaction_persisted(
        &store,
        "s1",
        &Interaction::Stop {
            turn: "a1".to_string(),
        },
        &priya(),
        320,
    )
    .unwrap();

    // Final load: original turns still present (history preserved), edit added a sibling.
    let final_rec = SessionRecording::from_durable(store.load("s1").unwrap().unwrap());
    assert!(final_rec.tree().turn("u1").is_some());
    assert!(final_rec.tree().turn("a1").is_some());
    assert!(final_rec.tree().turn("b1").is_some());
    assert!(final_rec.tree().turn("u1e").is_some());
    assert!(final_rec.tree().turn_count() >= 4);

    // The persisted session is still replayable (READ path) by the participant.
    let replay = replay_session(&store, "s1", &priya(), &ReplayOptions::default()).unwrap();
    assert!(replay.cursor().remaining() > 0);
}

#[test]
fn r11_durable_write_refuses_non_participant() {
    let store = seeded_store();
    let stranger = Principal::user("mallory", &[]);
    let err = apply_interaction_persisted(
        &store,
        "s1",
        &Interaction::Stop {
            turn: "a1".to_string(),
        },
        &stranger,
        200,
    )
    .unwrap_err();
    assert!(matches!(err, PersistedError::Interaction(_)));
    // And nothing was persisted by the refused mutation.
    let rec = SessionRecording::from_durable(store.load("s1").unwrap().unwrap());
    assert_eq!(rec.tree().turn_count(), 2);
}

#[test]
fn r11_durable_re_execution_forks_new_branch_and_persists_without_mutating_original() {
    let store = seeded_store();
    let before = SessionRecording::from_durable(store.load("s1").unwrap().unwrap());
    let a1_events_before = before.events().iter().filter(|e| e.turn_id == "a1").count();

    // Re-execute a1's frozen inputs against the OFFLINE default (live model is INFRA-gated behind
    // the ReExecutor seam). It must fork a NEW branch and persist it.
    let new_head = re_execute_persisted(
        &store,
        "s1",
        "a1",
        "a1re",
        "priya",
        &priya(),
        &DeterministicReplayExecutor::new(DataClass::Internal),
        400,
    )
    .unwrap();
    assert_eq!(new_head, "a1re");

    let after = SessionRecording::from_durable(store.load("s1").unwrap().unwrap());
    // Original turn a1 still exists with its ORIGINAL events untouched.
    assert!(after.tree().turn("a1").is_some());
    let a1_events_after = after.events().iter().filter(|e| e.turn_id == "a1").count();
    assert_eq!(
        a1_events_before, a1_events_after,
        "re-execution must never mutate the original turn's events"
    );
    // The new sibling branch exists, is the active head, and carries the offline re-run's output.
    assert!(after.tree().turn("a1re").is_some());
    assert_eq!(after.tree().active_head(), Some("a1re"));
    let has_reexec_text = after
        .events()
        .iter()
        .any(|e| e.turn_id == "a1re" && e.text.contains("[offline re-execution]"));
    assert!(
        has_reexec_text,
        "forked branch carries the re-executed output"
    );
}
