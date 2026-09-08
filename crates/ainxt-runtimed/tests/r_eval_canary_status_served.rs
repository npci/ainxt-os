// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX eval-tester-scenarios — `AssembledFull::release_controller_status` (the online canary →
//! auto-rollback → drift-monitor controller's read-only rollout phase + accrued candidate-sample
//! count) was fully implemented and unit-tested — its own doc comment names the exact reason it
//! exists ("a status route/telemetry consumer needs to read the controller's current rollout phase
//! and accrued sample count without driving it") — but no route anywhere in the served daemon ever
//! called it: `FullAppExt` had no `release_controller` field at all, so `to_full_app_ext` could never
//! hand the live controller to the transport. An operator/dashboard had no way to observe the LIVE
//! release controller's state on the shipped daemon (only `ainxt-runtimed`'s own tests could).
//!
//! This proves the missing wire end-to-end through the REAL served HTTP surface (not just the
//! `AssembledFull` method): `GET /v1/eval/canary/status` reports the SAME controller instance
//! `AssembledFull::ingest_served_turn` drives.

use ainxt_canary::experiment::{Notifier, PointerController};
use ainxt_quality::monitor::DriftResponder;
use ainxt_runtimed::{assemble_full, assemble_surface, load_layered};

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

#[tokio::test(flavor = "multi_thread")]
async fn r_eval_canary_status_route_reflects_the_same_controller_ingest_drives() {
    // R16 critical: the daemon refuses the header-trusting default authenticator unless the
    // deployment states the assumption (see r10_breach_clock_unit.rs).
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let loaded = load_layered(&[("base", "version = 1")]).unwrap();
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat surface");
    let full = assemble_full(&loaded, assembled).expect("assemble fully-wired surface");

    // Serve the REAL fully-wired daemon (the composition root's own `to_full_app`/`to_full_app_ext`,
    // exactly as `ainxt-runtimed`'s `main.rs` does) — not a hand-rolled router.
    let app = full.to_full_app();
    let ext = full.to_full_app_ext();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(ainxt_server::serve_full_ext(listener, app, ext));
    let client = reqwest::Client::new();

    // Fail-before shape: a fresh rollout starts Canarying with zero candidate samples.
    let before: serde_json::Value = client
        .get(format!("http://{addr}/v1/eval/canary/status"))
        .header("x-ainxt-user", "operator")
        .send()
        .await
        .expect("status request send")
        .json()
        .await
        .expect("status response is JSON");
    assert_eq!(
        before["phase"], "Canarying",
        "a fresh rollout starts Canarying: {before}"
    );
    assert_eq!(
        before["candidate_samples"], 0,
        "no candidate samples accrued yet: {before}"
    );

    // Drive the SAME controller `AssembledFull::ingest_served_turn` drives, exactly as the live-traffic
    // turn-completion hook would (offline pointer/notifier/responder doubles — the real backends stay
    // needs_hot_wiring/infra-gated; only the READ route this test proves is in scope here).
    let mut ptr = MemPointer("env/prod".into());
    let mut notes = Notes;
    let mut resp = Resp;
    for _ in 0..7 {
        full.ingest_served_turn("env/candidate", 95.0, &mut ptr, &mut notes, &mut resp);
    }

    // The served HTTP route reflects the SAME live controller state the direct method call mutated —
    // this is the actual "built but not wired" gap: before this fix there was no HTTP path to observe
    // it at all (404), regardless of what `ingest_served_turn` had driven.
    let after: serde_json::Value = client
        .get(format!("http://{addr}/v1/eval/canary/status"))
        .header("x-ainxt-user", "operator")
        .send()
        .await
        .expect("status request send")
        .json()
        .await
        .expect("status response is JSON");
    assert_eq!(
        after["candidate_samples"], 7,
        "the served status route must reflect the SAME controller ingest_served_turn drove: {after}"
    );

    // Auth-gated like every other governed surface: no identity header → 401, not an open read.
    let unauthenticated = client
        .get(format!("http://{addr}/v1/eval/canary/status"))
        .send()
        .await
        .expect("unauthenticated request send")
        .status();
    assert_eq!(
        unauthenticated,
        reqwest::StatusCode::UNAUTHORIZED,
        "the canary status route must be identity-gated like every other governed surface"
    );
}
