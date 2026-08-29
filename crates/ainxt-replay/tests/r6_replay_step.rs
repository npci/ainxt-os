// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R6 DATA — integration coverage for the mount-ready, store-backed STEP entrypoint.
//!
//! Gap: the `generate/replay/step/bundle` route quartet the server mounts had a `replay` entrypoint
//! ([`replay_session`]) and a signed `bundle` entrypoint ([`export_session_bundle`]), but *stepping*
//! was only an in-process [`StepCursor`] over a live `&Replay` — there was no **stateless**,
//! store-backed step call a REST route could mount (each request holds only an integer cursor).
//! [`step_replay_session`] + [`ReplayPage`] close that: plan the persisted session's replay, return
//! the run of steps up to the next boundary, and hand back a `next_index` the client resumes from.
//!
//! Fail-before/pass-after: `step_replay_session`/`ReplayPage` did not exist, so this test crate would
//! not compile before the change; the paging/RBAC/clearance assertions hold only after it.

use ainxt_replay::{
    step_replay_session, DataClass, EventKind, InMemorySessionStore, PersistedError, Principal,
    ReplayError, ReplayEvent, ReplayOptions, ReplayPage, SessionRecording, SessionStore, TurnRole,
    CAP_COMPLIANCE_REPLAY,
};

fn internal() -> DataClass {
    DataClass::Internal
}

fn participant() -> Principal {
    Principal::user("priya", &[]).with_clearance(DataClass::Confidential)
}

fn outsider() -> Principal {
    Principal::user("mallory", &[]).with_clearance(DataClass::Pii)
}

/// A recording with two step-boundaries on the active branch: a ModelCall and a ToolCall.
fn recording() -> SessionRecording {
    let mut r = SessionRecording::new("s1", &["priya"]);
    r.append_root_turn("u1", TurnRole::User, "priya", 1000)
        .unwrap();
    r.record_event(
        "u1",
        EventKind::TextDelta,
        internal(),
        "compute settlement",
        1001,
    )
    .unwrap();
    r.append_turn("a1", "u1", TurnRole::Assistant, "assistant", 1100)
        .unwrap();
    r.record_event("a1", EventKind::ModelCall, internal(), "call", 1101)
        .unwrap();
    r.record_event("a1", EventKind::ToolCall, internal(), "sql.query", 1200)
        .unwrap();
    r.record_event("a1", EventKind::ToolResult, internal(), "42 rows", 1500)
        .unwrap();
    r.record_event(
        "a1",
        EventKind::TextDelta,
        internal(),
        "the answer is 42",
        1600,
    )
    .unwrap();
    r.record_event("a1", EventKind::TurnEnd, internal(), "", 1700)
        .unwrap();
    r
}

fn seeded_store() -> InMemorySessionStore {
    let store = InMemorySessionStore::new();
    store.save(&recording().to_durable()).unwrap();
    store
}

#[test]
fn r6_step_pages_pause_before_each_boundary_and_reassemble_the_full_replay() {
    let store = seeded_store();

    // Page through the whole persisted session, following `next_index` each time, and reassemble.
    let mut reassembled: Vec<ReplayEvent> = Vec::new();
    let mut cursor = 0usize;
    let mut pages = 0usize;
    let total;
    loop {
        let page: ReplayPage = step_replay_session(
            &store,
            "s1",
            &participant(),
            &ReplayOptions::default(),
            cursor,
        )
        .unwrap();
        pages += 1;
        assert_eq!(page.sid, "s1");
        assert!(
            !page.steps.is_empty(),
            "a non-exhausted page must carry >=1 step"
        );

        // If we paused, the FIRST step of the NEXT page must be the boundary we paused before.
        if page.paused_at_boundary {
            let next = page.next_index.expect("paused pages carry a resume index");
            assert!(next > cursor);
        } else {
            assert_eq!(page.next_index, None, "the final page has no resume index");
        }

        reassembled.extend(page.steps.iter().map(|s| s.event.clone()));
        match page.next_index {
            Some(n) => cursor = n,
            None => {
                total = page.total_steps;
                break;
            }
        }
    }

    // Paging split the replay at its two boundaries → three pages, and the concatenation is exactly
    // the full replay with no gaps or duplicates.
    assert_eq!(
        pages, 3,
        "two boundaries (ModelCall, ToolCall) => three pages"
    );
    assert_eq!(reassembled.len(), total);
    let kinds: Vec<EventKind> = reassembled.iter().map(|e| e.kind).collect();
    assert_eq!(
        kinds,
        vec![
            EventKind::TurnStart,  // u1
            EventKind::TextDelta,  // u1
            EventKind::TurnStart,  // a1
            EventKind::ModelCall,  // boundary
            EventKind::ToolCall,   // boundary
            EventKind::ToolResult, // a1
            EventKind::TextDelta,  // a1
            EventKind::TurnEnd,    // a1
        ]
    );
    // The two middle pages each begin exactly on a boundary event (the pause landed there).
    assert!(reassembled.iter().any(|e| e.text == "the answer is 42"));
}

#[test]
fn r6_step_is_rbac_scoped_and_maps_missing_session() {
    let store = seeded_store();

    // A participant may step; an outsider is refused (mapped through PersistedError::Replay).
    assert!(
        step_replay_session(&store, "s1", &participant(), &ReplayOptions::default(), 0).is_ok()
    );
    assert_eq!(
        step_replay_session(&store, "s1", &outsider(), &ReplayOptions::default(), 0).unwrap_err(),
        PersistedError::Replay(ReplayError::NotAuthorized)
    );
    // A compliance auditor (read role) may step too — stepping is a READ, like replay/view.
    let auditor = Principal::user("dpo", &[CAP_COMPLIANCE_REPLAY]).with_clearance(DataClass::Pii);
    assert!(step_replay_session(&store, "s1", &auditor, &ReplayOptions::default(), 0).is_ok());

    // A missing session is a clean NotFound (→ 404), never a panic.
    assert_eq!(
        step_replay_session(&store, "nope", &participant(), &ReplayOptions::default(), 0)
            .unwrap_err(),
        PersistedError::SessionNotFound("nope".into())
    );
}

#[test]
fn r6_step_pages_are_clearance_filtered_like_a_full_replay() {
    // A PII event on the branch must never appear in an under-cleared caller's page.
    let store = InMemorySessionStore::new();
    let mut rec = SessionRecording::new("s2", &["priya"]);
    rec.append_root_turn("u1", TurnRole::User, "priya", 10)
        .unwrap();
    rec.record_event(
        "u1",
        EventKind::TextDelta,
        DataClass::Internal,
        "public",
        11,
    )
    .unwrap();
    rec.record_event(
        "u1",
        EventKind::TextDelta,
        DataClass::Pii,
        "acct 4111111111111111",
        12,
    )
    .unwrap();
    store.save(&rec.to_durable()).unwrap();

    // Confidential-cleared participant: the PII event is omitted from every page (redaction-preserving).
    let mut cursor = 0usize;
    loop {
        let page = step_replay_session(
            &store,
            "s2",
            &participant(),
            &ReplayOptions::default(),
            cursor,
        )
        .unwrap();
        assert!(
            page.steps
                .iter()
                .all(|s| s.event.data_class != DataClass::Pii),
            "an above-clearance event must never appear in a step page"
        );
        assert!(page.steps.iter().all(|s| !s.event.text.contains("4111")));
        match page.next_index {
            Some(n) => cursor = n,
            None => break,
        }
    }

    // A PII-cleared viewer stepping the same session DOES see it.
    let hi = Principal::user("priya", &[]).with_clearance(DataClass::Pii);
    let page = step_replay_session(&store, "s2", &hi, &ReplayOptions::default(), 0).unwrap();
    assert!(page.steps.iter().any(|s| s.event.text.contains("4111")));
}

#[test]
fn r6_step_past_the_end_is_an_empty_final_page_and_page_round_trips() {
    let store = seeded_store();
    // A cursor past the end is a clean empty final page (no panic, no error).
    let end =
        step_replay_session(&store, "s1", &participant(), &ReplayOptions::default(), 999).unwrap();
    assert!(end.steps.is_empty());
    assert_eq!(end.next_index, None);
    assert!(!end.paused_at_boundary);
    assert!(
        end.total_steps > 0,
        "the plan still reports its total length"
    );

    // The page is a serializable wire type (the route returns it as the response body).
    let first =
        step_replay_session(&store, "s1", &participant(), &ReplayOptions::default(), 0).unwrap();
    let json = serde_json::to_string(&first).unwrap();
    let back: ReplayPage = serde_json::from_str(&json).unwrap();
    assert_eq!(back, first);
}
