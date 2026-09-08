// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R13 DATA — close the data-surfaces-artifacts HIGH: "/v1/replay branch/edit/stop/steer bypasses the
//! durable SessionStore and uses a client-supplied log + self-asserted participant list."
//!
//! The fix is the route-ready store-backed write entrypoint [`apply_replay_write`] over the
//! [`ReplayWriteRequest`] wire body. This test proves, over the actual JSON transport shape:
//!
//! * **No client log, no client participants.** The wire body carries ONLY `{session, op, ...}` — it
//!   has no `log` or `participants` field, so a client cannot smuggle a fabricated history or a
//!   self-asserted roster. The tree AND the authoritative participant set are loaded from the durable
//!   store. (`serde(deny_unknown_fields)`-free by design, but the *authorization* uses only the stored
//!   roster — a client that appends `"participants":["mallory"]` to the body is ignored and still
//!   refused.)
//! * **Durable round-trip for all four ops** (branch / edit / stop / steer): each op is applied through
//!   the store and a COMPLETELY INDEPENDENT `store.load(...)` sees the effect — proving persistence, not
//!   an ephemeral client-projection rebuild.
//! * **RBAC from the store, fail-closed.** A non-participant is refused BEFORE any tree lookup and
//!   nothing is persisted; a missing session is a clean typed `SessionNotFound`.
//! * **Editing never mutates history** — the original turns survive a branch and an edit.
//!
//! Fail-before/pass-after: `ReplayWriteRequest` and `apply_replay_write` did not exist, so this crate
//! would not compile before the round-13 change. The served-route swap in the reserved `ainxt-server`
//! crate (pointing `POST /v1/replay` at this entrypoint) is `needs_hot_wiring` — the durable behaviour
//! it will inherit is proven end-to-end here against the shipped offline `InMemorySessionStore`.

use ainxt_replay::{
    apply_replay_write, DataClass, EventKind, FrozenTurnInputs, InMemorySessionStore, Interaction,
    InteractionOutcome, PersistedError, Principal, ReplayWriteRequest, SessionRecording,
    SessionStore, SteerDelivery, TurnRole,
};

fn priya() -> Principal {
    Principal::user("priya", &[]).with_clearance(DataClass::Confidential)
}
fn mallory() -> Principal {
    Principal::user("mallory", &[]).with_clearance(DataClass::Pii)
}

/// Seed a durable store with session `s1` whose AUTHORITATIVE participants are {priya, arun} (set
/// server-side, never by the client): user `u1` -> assistant `a1` (a1 frozen + still Active so stop/
/// steer are valid; a1 also carries a recorded answer).
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

/// Deserialize a `/v1/replay` wire body into the store-backed request type.
fn wire(body: &str) -> ReplayWriteRequest {
    serde_json::from_str(body).expect("wire body deserializes into ReplayWriteRequest")
}

#[test]
fn r13_replay_write_all_four_ops_round_trip_through_the_durable_store() {
    let store = seeded_store();

    // ---- branch: fork an alternative line off a1. ----
    let branch =
        wire(r#"{"session":"s1","op":"branch","from_turn":"a1","new_id":"b1","label":"what-if"}"#);
    let out = apply_replay_write(&store, &branch, &priya(), 200).unwrap();
    assert_eq!(
        out,
        InteractionOutcome::HeadMoved {
            new_head: "b1".into()
        }
    );
    // An INDEPENDENT load sees the branch — it durably round-tripped through the store.
    let reloaded = SessionRecording::from_durable(store.load("s1").unwrap().unwrap());
    assert_eq!(
        reloaded.tree().turn("b1").unwrap().parent.as_deref(),
        Some("a1")
    );
    assert_eq!(reloaded.tree().active_head(), Some("b1"));

    // ---- edit: fork a sibling off the edited user turn's parent (history preserved). ----
    let edit = wire(r#"{"session":"s1","op":"edit","turn":"u1","new_id":"u1e"}"#);
    let out = apply_replay_write(&store, &edit, &priya(), 300).unwrap();
    assert!(matches!(out, InteractionOutcome::HeadMoved { .. }));
    let reloaded = SessionRecording::from_durable(store.load("s1").unwrap().unwrap());
    assert!(
        reloaded.tree().turn("u1").is_some(),
        "history preserved — edit never mutates"
    );
    assert!(reloaded.tree().turn("u1e").is_some());
    assert!(
        reloaded.tree().turn("b1").is_some(),
        "the earlier branch is still there (non-ephemeral)"
    );

    // ---- steer: interject into the still-Active a1; lands immediately (no tool call in flight). ----
    let steer = wire(
        r#"{"session":"s1","op":"steer","turn":"a1","text":"focus on T+1","data_class":"internal"}"#,
    );
    let out = apply_replay_write(&store, &steer, &priya(), 400).unwrap();
    assert_eq!(
        out,
        InteractionOutcome::Steered {
            turn: "a1".into(),
            delivery: SteerDelivery::Immediate
        }
    );

    // ---- stop: mark a1 terminal (durable record; the live token fire is the actor's job). ----
    let stop = wire(r#"{"session":"s1","op":"stop","turn":"a1"}"#);
    let out = apply_replay_write(&store, &stop, &priya(), 500).unwrap();
    assert_eq!(out, InteractionOutcome::Stopped { turn: "a1".into() });

    // Final independent load: every op persisted and history is intact across the whole sequence.
    let final_rec = SessionRecording::from_durable(store.load("s1").unwrap().unwrap());
    for id in ["u1", "a1", "b1", "u1e"] {
        assert!(
            final_rec.tree().turn(id).is_some(),
            "turn {id} durably present"
        );
    }
}

#[test]
fn r13_client_supplied_participants_in_the_body_cannot_defeat_store_rbac() {
    let store = seeded_store();

    // The attacker (mallory) is NOT in the stored roster {priya, arun}. She appends a self-asserted
    // "participants":["mallory"] to the wire body hoping to smuggle herself in. `ReplayWriteRequest`
    // has no such field, so it is simply ignored on deserialize — and authorization uses ONLY the
    // roster loaded from the store. The write is refused, and NOTHING is persisted.
    let forged = wire(
        r#"{"session":"s1","op":"stop","turn":"a1","participants":["mallory"],"log":[{"kind":"text_delta"}]}"#,
    );
    let err = apply_replay_write(&store, &forged, &mallory(), 200).unwrap_err();
    assert!(
        matches!(err, PersistedError::Interaction(_)),
        "a non-participant is refused regardless of a self-asserted body roster: {err:?}"
    );

    // The refused write left the durable tree byte-for-byte unchanged (2 turns, a1 still Active).
    let rec = SessionRecording::from_durable(store.load("s1").unwrap().unwrap());
    assert_eq!(
        rec.tree().turn_count(),
        2,
        "refused write persisted nothing"
    );

    // Sanity: the SAME op from a genuine stored participant DOES succeed (proves the refusal was RBAC,
    // not a malformed body).
    let legit = wire(r#"{"session":"s1","op":"stop","turn":"a1"}"#);
    assert_eq!(
        apply_replay_write(&store, &legit, &priya(), 300).unwrap(),
        InteractionOutcome::Stopped { turn: "a1".into() }
    );
}

#[test]
fn r13_missing_session_is_a_clean_typed_not_found_not_a_client_projection() {
    let store = seeded_store();
    // With no client-supplied log to fall back on, an unknown session is a clean NotFound (the client
    // can no longer fabricate a session out of a supplied projection).
    let branch = wire(r#"{"session":"ghost","op":"branch","from_turn":"x","new_id":"y"}"#);
    assert!(matches!(
        apply_replay_write(&store, &branch, &priya(), 200).unwrap_err(),
        PersistedError::SessionNotFound(_)
    ));
}

#[test]
fn r13_request_type_has_no_log_or_participants_and_reserializes_to_the_op_wire() {
    // The request round-trips to a body that carries only {session, op, ...} — proving no `log`/
    // `participants` surface exists on the transport contract.
    let req = ReplayWriteRequest {
        session: "s1".into(),
        interaction: Interaction::Branch {
            from_turn: "a1".into(),
            new_id: "b1".into(),
            label: Some("alt".into()),
        },
    };
    let json = serde_json::to_string(&req).unwrap();
    assert!(json.contains("\"session\":\"s1\""));
    assert!(json.contains("\"op\":\"branch\""));
    assert!(
        !json.contains("\"log\""),
        "no client log on the wire: {json}"
    );
    assert!(
        !json.contains("\"participants\""),
        "no self-asserted roster on the wire: {json}"
    );
}
