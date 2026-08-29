// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-11 (gap AS, EVAL_PLATFORM.md §7): the online canary + auto-rollback is driven through the
//! **clean served-path entrypoint** [`AssembledFull::ingest_served_turn`] — the seam the live-traffic
//! turn-completion hook targets (needs_hot_wiring for the real git-ref pointer / ticketing backends;
//! the live-production-traffic hour itself is infra-gated). Here it is exercised offline against
//! in-memory pointer/notifier/responder doubles to prove the entrypoint really drives the controller
//! to a pointer flip.

use ainxt_canary::experiment::{Notifier, PointerController};
use ainxt_quality::monitor::DriftResponder;
use ainxt_runtimed::{assemble_chat, assemble_full, load_layered};

struct MemPointer(String, Vec<String>);
impl PointerController for MemPointer {
    fn current(&self) -> String {
        self.0.clone()
    }
    fn flip(&mut self, to: &str) -> String {
        self.1.push(to.to_string());
        std::mem::replace(&mut self.0, to.to_string())
    }
}
#[derive(Default)]
struct Notes(Vec<String>);
impl Notifier for Notes {
    fn notify(&mut self, m: &str) {
        self.0.push(m.to_string());
    }
}
#[derive(Default)]
struct Resp {
    tickets: usize,
    rollbacks: usize,
}
impl DriftResponder for Resp {
    fn open_ticket(&mut self, _s: &str) {
        self.tickets += 1;
    }
    fn rollback_last_good(&mut self) -> bool {
        self.rollbacks += 1;
        true
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r11_served_canary_entrypoint_rolls_back_a_regression() {
    // R16 critical: the daemon now refuses the header-trusting default authenticator unless the
    // deployment states the assumption (see r10_breach_clock_unit.rs) — state it here.
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let loaded = load_layered(&[("base", "version = 1")]).unwrap();
    let assembled = assemble_chat(&loaded).unwrap();
    let full = assemble_full(&loaded, assembled).unwrap();

    let mut ptr = MemPointer("env/prod".into(), Vec::new());
    let mut notes = Notes::default();
    let mut resp = Resp::default();

    // Feed a clearly-worse candidate stream through the CLEAN entrypoint (not the raw lock): the
    // anytime-valid canary must establish the regression and the entrypoint must flip the pointer back.
    let mut rolled_back = false;
    for _ in 0..600 {
        let step = full.ingest_served_turn("env/candidate", 5.0, &mut ptr, &mut notes, &mut resp);
        if step.rolled_back() {
            rolled_back = true;
            break;
        }
    }
    assert!(
        rolled_back,
        "the served-path entrypoint must auto-roll-back an established regression"
    );
    assert_eq!(
        ptr.current(),
        "env/prod",
        "the deploy pointer returns to the champion ref"
    );
    assert!(
        !notes.0.is_empty(),
        "a human is notified on rollback (never paged)"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r11_served_canary_entrypoint_holds_pointer_on_champion_traffic() {
    // R16 critical: the daemon now refuses the header-trusting default authenticator unless the
    // deployment states the assumption (see r10_breach_clock_unit.rs) — state it here.
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let loaded = load_layered(&[("base", "version = 1")]).unwrap();
    let assembled = assemble_chat(&loaded).unwrap();
    let full = assemble_full(&loaded, assembled).unwrap();

    let mut ptr = MemPointer("env/prod".into(), Vec::new());
    let mut notes = Notes::default();
    let mut resp = Resp::default();
    // Champion turns must not move the candidate's decision — the pointer holds, nothing flips.
    for _ in 0..1000 {
        let step = full.ingest_served_turn("env/prod", 95.0, &mut ptr, &mut notes, &mut resp);
        assert!(!step.rolled_back());
    }
    assert_eq!(ptr.current(), "env/prod");
    assert!(ptr.1.is_empty(), "no pointer flip on champion-only traffic");
}

// GAP-FIX eval-tester-scenarios — `OnlineReleaseController::phase`/`candidate_samples` were fully
// implemented and unit-tested but had zero callers outside their own crate. Proves the new read-only
// `AssembledFull::release_controller_status` reflects the SAME controller `ingest_served_turn` drives.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r_release_controller_status_reflects_the_same_controller_ingest_drives() {
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let loaded = load_layered(&[("base", "version = 1")]).unwrap();
    let assembled = assemble_chat(&loaded).unwrap();
    let full = assemble_full(&loaded, assembled).unwrap();

    let (phase0, samples0) = full.release_controller_status();
    assert_eq!(
        phase0,
        ainxt_quality::controller::Phase::Canarying,
        "a fresh rollout starts Canarying"
    );
    assert_eq!(samples0, 0, "no candidate samples accrued yet");

    let mut ptr = MemPointer("env/prod".into(), Vec::new());
    let mut notes = Notes::default();
    let mut resp = Resp::default();
    for _ in 0..10 {
        full.ingest_served_turn("env/candidate", 95.0, &mut ptr, &mut notes, &mut resp);
    }

    let (_phase1, samples1) = full.release_controller_status();
    assert_eq!(
        samples1, 10,
        "the status read reflects the SAME controller ingest_served_turn drove"
    );
}

// GAP-FIX eval-tester-scenarios — `OnlineReleaseController::drive_from_feed` (the batch/loop form,
// vs. the per-turn `ingest_served_turn`) had zero callers outside its own crate. Proves the served
// wrapper drains a feed to a terminal rollback on the SAME controller `ingest_served_turn` drives.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r_drive_release_controller_from_feed_drains_a_feed_to_terminal_rollback() {
    use ainxt_quality::feed::{ObservedTurn, ReplayFeed};

    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let loaded = load_layered(&[("base", "version = 1")]).unwrap();
    let assembled = assemble_chat(&loaded).unwrap();
    let full = assemble_full(&loaded, assembled).unwrap();

    // A clearly-worse candidate stream, long enough to establish a regression and roll back.
    let turns: Vec<ObservedTurn> = (0..600)
        .map(|_| ObservedTurn {
            served_ref: "env/candidate".into(),
            quality: 5.0,
        })
        .collect();
    let mut feed = ReplayFeed::new(turns);
    let mut ptr = MemPointer("env/prod".into(), Vec::new());
    let mut notes = Notes::default();
    let mut resp = Resp::default();

    let steps = full.drive_release_controller_from_feed(&mut feed, &mut ptr, &mut notes, &mut resp);
    assert!(
        !steps.is_empty(),
        "the feed must actually be drained through the controller"
    );
    assert!(
        steps.last().unwrap().rolled_back(),
        "a sustained regression fed through the batch entrypoint must still auto-roll-back"
    );
    assert_eq!(
        ptr.current(),
        "env/prod",
        "the pointer returns to the champion ref"
    );

    // The batch entrypoint drove the SAME controller the per-turn entrypoint uses — its samples are
    // visible through the shared status read.
    let (phase, _samples) = full.release_controller_status();
    assert_eq!(phase, ainxt_quality::controller::Phase::RolledBack);
}
