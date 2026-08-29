// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R3 DATA — integration coverage for the mount-ready `apply_interaction` entrypoint.
//!
//! Gap: "Branch/edit/steer + Execution Replay not exposed on the live protocol." The tree
//! operations existed, but the unified, RBAC-scoped WRITE dispatch that a transport route mounts
//! lived outside this crate. `apply_interaction` + `Interaction`/`InteractionOutcome`/
//! `InteractionError` provide that single entrypoint over the durable `SessionRecording`.
//!
//! Fail-before/pass-after: these symbols did not exist, so this test crate would not compile.

use ainxt_replay::{
    apply_interaction, DataClass, Interaction, InteractionError, InteractionOutcome, Principal,
    SessionRecording, SteerDelivery, TurnRole, CAP_COMPLIANCE_REPLAY,
};

/// A recording owned by participant `priya`, with a user turn `u1` and an active assistant turn `a1`.
fn recording() -> SessionRecording {
    let mut r = SessionRecording::new("s1", &["priya"]);
    r.append_root_turn("u1", TurnRole::User, "priya", 100)
        .unwrap();
    r.append_turn("a1", "u1", TurnRole::Assistant, "assistant", 110)
        .unwrap();
    r
}

fn priya() -> Principal {
    Principal::user("priya", &[]).with_clearance(DataClass::Internal)
}

#[test]
fn r3_apply_interaction_refuses_non_participant_before_tree_lookup() {
    let mut r = recording();

    // A read-only compliance role may REPLAY the session but must never mutate it.
    let dpo = Principal::user("dpo", &[CAP_COMPLIANCE_REPLAY]).with_clearance(DataClass::Pii);
    let branch = Interaction::Branch {
        from_turn: "a1".to_string(),
        new_id: "b1".to_string(),
        label: Some("explore".to_string()),
    };
    assert_eq!(
        apply_interaction(&mut r, &branch, &dpo, 200),
        Err(InteractionError::NotAuthorized),
        "compliance-replay is a READ role — it cannot branch/edit/steer"
    );

    // Authorization precedes tree lookup: a non-participant targeting a NON-existent turn still gets
    // NotAuthorized (never UnknownTurn), so the error shape is no existence oracle.
    let stranger = Principal::user("mallory", &[]);
    let stop_ghost = Interaction::Stop {
        turn: "does_not_exist".to_string(),
    };
    assert_eq!(
        apply_interaction(&mut r, &stop_ghost, &stranger, 200),
        Err(InteractionError::NotAuthorized)
    );

    // Nothing was mutated by the refused calls.
    assert_eq!(r.tree().turn_count(), 2);
}

#[test]
fn r3_apply_interaction_branch_and_edit_fork_without_mutating_history() {
    let mut r = recording();

    // Branch off the assistant turn → new active head, original turns preserved.
    let branch = Interaction::Branch {
        from_turn: "a1".to_string(),
        new_id: "b1".to_string(),
        label: Some("alt".to_string()),
    };
    match apply_interaction(&mut r, &branch, &priya(), 200).unwrap() {
        InteractionOutcome::HeadMoved { new_head } => assert_eq!(new_head, "b1"),
        other => panic!("expected HeadMoved, got {other:?}"),
    }
    assert_eq!(r.tree().active_head(), Some("b1"));

    // Edit the USER turn u1 → forks a NEW sibling; u1 and a1 remain replayable (history intact).
    let edit = Interaction::Edit {
        turn: "u1".to_string(),
        new_id: "u1b".to_string(),
        label: None,
    };
    match apply_interaction(&mut r, &edit, &priya(), 210).unwrap() {
        InteractionOutcome::HeadMoved { new_head } => assert_eq!(new_head, "u1b"),
        other => panic!("expected HeadMoved, got {other:?}"),
    }
    // All four turns coexist — editing forked, it did not overwrite.
    assert!(r.tree().turn("u1").is_some());
    assert!(r.tree().turn("a1").is_some());
    assert!(r.tree().turn("b1").is_some());
    assert!(r.tree().turn("u1b").is_some());
    assert_eq!(r.tree().turn_count(), 4);

    // Editing an ASSISTANT turn is refused (only user turns are editable).
    let bad_edit = Interaction::Edit {
        turn: "a1".to_string(),
        new_id: "a1b".to_string(),
        label: None,
    };
    assert_eq!(
        apply_interaction(&mut r, &bad_edit, &priya(), 220),
        Err(InteractionError::NotEditable("a1".to_string()))
    );
}

#[test]
fn r3_apply_interaction_stop_and_steer_and_serialize() {
    let mut r = recording();

    // Steer the active assistant turn → accepted, lands immediately (no tool in flight).
    let steer = Interaction::Steer {
        turn: "a1".to_string(),
        text: "also cover refunds".to_string(),
        data_class: DataClass::Internal,
    };
    match apply_interaction(&mut r, &steer, &priya(), 200).unwrap() {
        InteractionOutcome::Steered { turn, delivery } => {
            assert_eq!(turn, "a1");
            assert_eq!(delivery, SteerDelivery::Immediate);
        }
        other => panic!("expected Steered, got {other:?}"),
    }

    // Stop the active turn → durable terminal record.
    let stop = Interaction::Stop {
        turn: "a1".to_string(),
    };
    assert_eq!(
        apply_interaction(&mut r, &stop, &priya(), 210).unwrap(),
        InteractionOutcome::Stopped {
            turn: "a1".to_string()
        }
    );
    // Steering a now-stopped (non-active) turn is refused.
    assert_eq!(
        apply_interaction(&mut r, &steer, &priya(), 220),
        Err(InteractionError::NotActive("a1".to_string()))
    );

    // Mount-readiness: the command deserializes from the wire and the outcome serializes back.
    let parsed: Interaction = serde_json::from_value(serde_json::json!({
        "op": "branch", "from_turn": "u1", "new_id": "z1", "label": "wire"
    }))
    .unwrap();
    let outcome = apply_interaction(&mut r, &parsed, &priya(), 230).unwrap();
    let json = serde_json::to_value(&outcome).unwrap();
    assert_eq!(
        json,
        serde_json::json!({"kind": "head_moved", "new_head": "z1"})
    );
}
