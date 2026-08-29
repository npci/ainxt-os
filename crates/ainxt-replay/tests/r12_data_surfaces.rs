// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R12 DATA — the remaining data-surfaces-artifacts gaps for the interaction/replay spine:
//!
//! * **Durable turn-tree WRITE over transport** (medium): a branch/edit/stop/steer arriving as a wire
//!   JSON body deserializes into the `Interaction` vocabulary, drives the store-backed durable write
//!   (`apply_interaction_persisted`), and durably round-trips across independent store loads — the
//!   transport contract, RBAC-scoped (participant-only) and JSON-serializable end to end.
//! * **Re-execution replay over transport + drift/differential oracle** (low): a `ReExecRequest`
//!   deserializes from the wire, `re_execute_persisted_req` forks a drift branch (never overwriting the
//!   original), and `drift_report_persisted` is the read-side differential oracle a canary/auto-rollback
//!   gate consumes — RBAC-scoped and redaction-preserving.
//! * **Collaborative presence events** (low): `participant.joined/left/typing/viewing` are produced by
//!   a first-class, RBAC-scoped, self-asserted presence roster on the live session (advisory, ephemeral).
//!
//! Fail-before/pass-after: `ReExecRequest`, `re_execute_persisted_req`, `DriftReport` /
//! `drift_report_persisted`, and `PresenceKind`/`PresenceEvent`/`SessionRecording::mark_presence` did
//! not exist, so this test crate would not compile. Live model: the re-run itself is INFRA-gated behind
//! the `ReExecutor` seam — proven end-to-end here with the shipped offline `DeterministicReplayExecutor`.

use ainxt_replay::{
    apply_interaction_persisted, drift_report_persisted, re_execute_persisted_req, replay_session,
    DataClass, DeterministicReplayExecutor, EventKind, FrozenTurnInputs, InMemorySessionStore,
    Interaction, InteractionOutcome, PersistedError, PresenceKind, Principal, ReExecRequest,
    ReplayOptions, SessionRecording, SessionStore, TurnRole,
};

fn priya() -> Principal {
    Principal::user("priya", &[]).with_clearance(DataClass::Confidential)
}
fn stranger() -> Principal {
    Principal::user("mallory", &[]).with_clearance(DataClass::Pii)
}

/// Seed a durable store with session `s1` (participants priya+arun): user `u1` -> assistant `a1`
/// (frozen + a recorded original answer).
fn seeded_store() -> InMemorySessionStore {
    let mut r = SessionRecording::new("s1", &["priya", "arun"]);
    r.append_root_turn("u1", TurnRole::User, "priya", 100)
        .unwrap();
    r.record_event(
        "u1",
        EventKind::TextDelta,
        DataClass::Internal,
        "compute settlement",
        101,
    )
    .unwrap();
    r.append_turn("a1", "u1", TurnRole::Assistant, "assistant", 110)
        .unwrap();
    r.record_event(
        "a1",
        EventKind::TextDelta,
        DataClass::Internal,
        "the answer is 42",
        120,
    )
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

// ---------------------------------------------------------------------------
// Gap 2 — durable turn-tree WRITE over transport (branch/edit/stop/steer).
// ---------------------------------------------------------------------------

#[test]
fn r12_durable_write_over_transport_json_roundtrip_and_persists() {
    let store = seeded_store();

    // The transport receives a JSON body; it deserializes into the `Interaction` wire vocabulary.
    let wire = r#"{"op":"branch","from_turn":"a1","new_id":"b1","label":"what-if: no discount"}"#;
    let interaction: Interaction = serde_json::from_str(wire).expect("wire body deserializes");

    // Drive the DURABLE store-backed write (not an ephemeral client-projection rebuild).
    let outcome = apply_interaction_persisted(&store, "s1", &interaction, &priya(), 200).unwrap();
    assert_eq!(
        outcome,
        InteractionOutcome::HeadMoved {
            new_head: "b1".into()
        }
    );
    // The outcome itself serializes back to the wire.
    let out_json = serde_json::to_string(&outcome).unwrap();
    assert!(out_json.contains("head_moved") && out_json.contains("b1"));

    // A completely independent load sees the branch — it durably round-tripped through the store.
    let reloaded = SessionRecording::from_durable(store.load("s1").unwrap().unwrap());
    let b1 = reloaded
        .tree()
        .turn("b1")
        .expect("branch durably persisted");
    assert_eq!(b1.parent.as_deref(), Some("a1"));
    assert_eq!(reloaded.tree().active_head(), Some("b1"));

    // A SECOND wire op (edit) sees the first (proves non-ephemeral): fork a sibling off u1.
    let edit: Interaction =
        serde_json::from_str(r#"{"op":"edit","turn":"u1","new_id":"u1e"}"#).unwrap();
    apply_interaction_persisted(&store, "s1", &edit, &priya(), 300).unwrap();
    let final_rec = SessionRecording::from_durable(store.load("s1").unwrap().unwrap());
    assert!(
        final_rec.tree().turn("u1").is_some(),
        "history preserved (edit never mutates)"
    );
    assert!(final_rec.tree().turn("u1e").is_some());
    assert!(final_rec.tree().turn("b1").is_some());
}

#[test]
fn r12_durable_write_over_transport_is_rbac_scoped_and_persists_nothing_on_refusal() {
    let store = seeded_store();
    let stop: Interaction = serde_json::from_str(r#"{"op":"stop","turn":"a1"}"#).unwrap();
    // A non-participant is refused BEFORE any tree lookup, and nothing is persisted.
    let err = apply_interaction_persisted(&store, "s1", &stop, &stranger(), 200).unwrap_err();
    assert!(matches!(err, PersistedError::Interaction(_)));
    let rec = SessionRecording::from_durable(store.load("s1").unwrap().unwrap());
    assert_eq!(
        rec.tree().turn_count(),
        2,
        "refused write left the tree unchanged"
    );
    // A missing session is a clean NotFound over transport.
    assert!(matches!(
        apply_interaction_persisted(&store, "nope", &stop, &priya(), 200).unwrap_err(),
        PersistedError::SessionNotFound(_)
    ));
}

// ---------------------------------------------------------------------------
// Gap 3 — re-execution over transport + the drift/differential oracle.
// ---------------------------------------------------------------------------

#[test]
fn r12_reexecution_over_transport_forks_drift_branch_and_oracle_detects_drift() {
    let store = seeded_store();

    // Transport JSON body -> ReExecRequest (no model named on the wire; runtime injects the executor).
    let wire = r#"{"target_turn":"a1","new_id":"a1re"}"#;
    let req: ReExecRequest = serde_json::from_str(wire).expect("re-exec request deserializes");

    // Re-execute against the shipped OFFLINE executor (the live model is INFRA-gated behind ReExecutor).
    let new_head = re_execute_persisted_req(
        &store,
        "s1",
        &req,
        &priya(),
        &DeterministicReplayExecutor::new(DataClass::Internal),
        400,
    )
    .unwrap();
    assert_eq!(new_head, "a1re");

    // The original turn a1 is untouched; the fork is a sibling that persisted.
    let after = SessionRecording::from_durable(store.load("s1").unwrap().unwrap());
    assert!(after.tree().turn("a1").is_some(), "original intact");
    assert_eq!(
        after.tree().turn("a1re").unwrap().parent.as_deref(),
        Some("u1")
    );

    // The differential oracle: original "the answer is 42" vs the offline re-run output => DRIFTED.
    let report = drift_report_persisted(&store, "s1", "a1", "a1re", &priya()).unwrap();
    assert_eq!(report.original_turn, "a1");
    assert_eq!(report.reexec_turn, "a1re");
    assert_eq!(report.original_text, "the answer is 42");
    assert!(report.reexec_text.contains("[offline re-execution]"));
    assert!(
        report.drifted,
        "the re-run output differs from the original => drift"
    );
    // The report serializes to the wire for a canary/auto-rollback consumer.
    assert!(serde_json::to_string(&report)
        .unwrap()
        .contains("\"drifted\":true"));
}

#[test]
fn r12_drift_oracle_is_rbac_scoped_and_reports_no_drift_when_text_matches() {
    let store = seeded_store();
    // Comparing a1 against itself: identical text => no drift (the oracle's stable baseline).
    let same = drift_report_persisted(&store, "s1", "a1", "a1", &priya()).unwrap();
    assert!(!same.drifted);
    assert_eq!(same.original_text, same.reexec_text);

    // An outsider cannot run the oracle (RBAC-scoped exactly as replay).
    assert!(matches!(
        drift_report_persisted(&store, "s1", "a1", "a1", &stranger()).unwrap_err(),
        PersistedError::Replay(_)
    ));
    // An unknown turn is a clean typed error, not a panic.
    assert!(matches!(
        drift_report_persisted(&store, "s1", "ghost", "a1", &priya()).unwrap_err(),
        PersistedError::Replay(_)
    ));
    // Sanity: the persisted session is still replayable after re-exec/oracle reads (read-only).
    assert!(replay_session(&store, "s1", &priya(), &ReplayOptions::default()).is_ok());
}

// ---------------------------------------------------------------------------
// Gap 5 — collaborative presence events (participant.joined/left/typing/viewing).
// ---------------------------------------------------------------------------

#[test]
fn r12_presence_roster_tracks_join_leave_and_emits_advisory_events() {
    let mut rec = SessionRecording::new("s1", &["priya", "arun"]);
    assert!(rec.present_participants().is_empty());

    // priya joins -> roster + a serializable participant.joined event.
    let ev = rec
        .mark_presence(&priya(), "priya", PresenceKind::Joined, None, 10)
        .unwrap();
    assert_eq!(ev.kind, PresenceKind::Joined);
    assert!(rec.is_present("priya"));
    let json = serde_json::to_string(&ev).unwrap();
    assert!(json.contains("\"kind\":\"joined\"") && json.contains("priya"));

    // typing/viewing are allowed once joined and can scope to a turn.
    let typing = rec
        .mark_presence(&priya(), "priya", PresenceKind::Typing, Some("u1"), 11)
        .unwrap();
    assert_eq!(typing.turn_id.as_deref(), Some("u1"));
    rec.mark_presence(&priya(), "priya", PresenceKind::Viewing, Some("a1"), 12)
        .unwrap();

    // priya leaves -> removed from the roster.
    rec.mark_presence(&priya(), "priya", PresenceKind::Left, None, 13)
        .unwrap();
    assert!(!rec.is_present("priya"));
}

#[test]
fn r12_presence_is_rbac_scoped_self_asserted_and_requires_join_for_typing() {
    let mut rec = SessionRecording::new("s1", &["priya", "arun"]);
    let arun = Principal::user("arun", &[]).with_clearance(DataClass::Internal);

    // A non-participant cannot signal presence at all.
    assert!(rec
        .mark_presence(&stranger(), "mallory", PresenceKind::Joined, None, 1)
        .is_err());

    // Presence is self-asserted: priya cannot forge arun's presence.
    assert!(rec
        .mark_presence(&priya(), "arun", PresenceKind::Joined, None, 2)
        .is_err());

    // Typing before joining is refused (advisory but coherent).
    assert!(rec
        .mark_presence(&arun, "arun", PresenceKind::Typing, None, 3)
        .is_err());

    // After a real self-join, typing is accepted.
    rec.mark_presence(&arun, "arun", PresenceKind::Joined, None, 4)
        .unwrap();
    assert!(rec
        .mark_presence(&arun, "arun", PresenceKind::Typing, None, 5)
        .is_ok());
    assert_eq!(rec.present_participants(), vec!["arun"]);
}
