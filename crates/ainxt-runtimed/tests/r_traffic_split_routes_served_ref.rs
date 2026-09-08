// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX eval-tester-scenarios — `ainxt_canary::experiment::TrafficSplit` (the git-ref-pinned
//! request router `ainxt_quality::feed`'s own doc names as *the* source of `served_ref`: "the git-ref
//! that actually served the turn, from the upstream traffic split") had zero callers anywhere in the
//! workspace outside its own crate's tests, even though the online release controller it should feed
//! (`AssembledFull::ingest_served_turn`, closed in an earlier round) is already live on the served
//! surface. Nothing on the served composition root ever computed a `served_ref` from an actual request
//! — [`AssembledFull::route_served_ref`] is that missing wire.
//!
//! Fail-before: `AssembledFull` had no `traffic_split` field and no `route_served_ref` method;
//! `ainxt_canary::experiment::TrafficSplit` was reachable only from its own crate's unit tests.
//! Pass-after: the assembled daemon resolves a deterministic, weighted served-ref per request key from
//! the SAME candidate/champion refs `release_controller` canaries, and that resolved ref can be fed
//! straight into `ingest_served_turn` end-to-end.

use ainxt_canary::experiment::{Notifier, PointerController};
use ainxt_quality::monitor::DriftResponder;
use ainxt_runtimed::{assemble_chat, assemble_full, load_layered};

struct MemPointer(String);
impl PointerController for MemPointer {
    fn current(&self) -> String {
        self.0.clone()
    }
    fn flip(&mut self, to: &str) -> String {
        std::mem::replace(&mut self.0, to.to_string())
    }
}
#[derive(Default)]
struct Notes;
impl Notifier for Notes {
    fn notify(&mut self, _m: &str) {}
}
#[derive(Default)]
struct Resp;
impl DriftResponder for Resp {
    fn open_ticket(&mut self, _s: &str) {}
    fn rollback_last_good(&mut self) -> bool {
        true
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r_traffic_split_routes_a_deterministic_served_ref() {
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let loaded = load_layered(&[("base", "version = 1")]).unwrap();
    let assembled = assemble_chat(&loaded).unwrap();
    let full = assemble_full(&loaded, assembled).unwrap();

    // Every request key must route to one of the two refs the release controller itself canaries.
    let mut saw_champion = false;
    let mut saw_candidate = false;
    for i in 0..2000 {
        let key = format!("session-{i}");
        let served_ref = full
            .route_served_ref(&key)
            .expect("a non-empty traffic split must always resolve a ref");
        assert!(
            served_ref == "env/prod" || served_ref == "env/candidate",
            "unexpected served ref: {served_ref}"
        );
        if served_ref == "env/prod" {
            saw_champion = true;
        } else {
            saw_candidate = true;
        }

        // Deterministic: routing the SAME key twice must yield the SAME ref (no RNG, stable hash).
        let served_ref_again = full.route_served_ref(&key).unwrap();
        assert_eq!(
            served_ref, served_ref_again,
            "the same request key must always route to the same served ref"
        );
    }
    assert!(
        saw_champion,
        "the 95% champion arm must be reachable over 2000 distinct keys"
    );
    assert!(
        saw_candidate,
        "the 5% candidate arm must be reachable over 2000 distinct keys"
    );

    // End-to-end: the ref this seam resolves must be usable directly as `ingest_served_turn`'s
    // `served_ref` argument, feeding the SAME release controller `route_served_ref`'s refs came from.
    let served_ref = full.route_served_ref("session-e2e").unwrap();
    let mut ptr = MemPointer("env/prod".into());
    let mut notes = Notes;
    let mut resp = Resp;
    let step = full.ingest_served_turn(&served_ref, 92.0, &mut ptr, &mut notes, &mut resp);
    // No assertion on the controller's verdict itself (a single turn never establishes anything) —
    // this proves the plumbing end-to-end: a route_served_ref() output is accepted by
    // ingest_served_turn() without panicking or type mismatch, which is the whole point of the wire.
    let _ = step;
}
