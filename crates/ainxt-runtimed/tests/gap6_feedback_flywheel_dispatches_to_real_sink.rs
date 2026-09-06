// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX memory (gap6, item 2) — closes the audited finding that the memory flywheel's
//! curation/dispatch half is captured-but-never-read: `ImprovementEngine::propose` (design §4),
//! `Curator::triage`, `ImprovementEngine::dispatch`/`dispatch_gated`, `DestinationGates`,
//! `MemoryStoreSink`, and `PoisonScanner`/`CandidateSink` were fully implemented and unit-tested, and
//! production (`ainxt-runtimed`/`ainxt-server`) constructs a REAL, LIVE `ImprovementEngine` and wires
//! `POST /feedback` to capture into it — but before this fix, nothing on any served or
//! composition-root path ever called `.propose(`, `.triage(`, `.dispatch(`/`.dispatch_gated(`. The
//! daemon captured feedback forever but never read it back out.
//!
//! This test drives the EXACT shipped composition (`assemble_chat` -> `assemble_full` ->
//! `serve_full_ext`), same harness as `r16_regfi_erasure_guards_mirrored_turn.rs`, and proves:
//!
//! 1. Two REAL `POST /feedback` corrections (different turn ids, the SAME `error_signature`) are
//!    captured into the daemon's one LIVE `ImprovementEngine` — the SAME instance `/feedback` writes
//!    into (`AssembledFull::feedback_engine`).
//! 2. `AssembledFull::run_feedback_flywheel_tick` — the new composition-root cadence method the
//!    background `spawn_feedback_flywheel_sweep` loop also calls — runs propose -> triage ->
//!    dispatch_gated over that SAME engine instance (never a second, disconnected one).
//! 3. The resulting `CommonFix` org-knowledge candidate reaches a REAL destination: the SAME MEM-10
//!    memory backing `POST /memory/*` reads/writes (`AssembledFull::memory_consent`). This is verified
//!    by READING THE DESTINATION BACK (`ConsentBacking::with_store` + `MemoryStore::get`) — not merely
//!    asserting the dispatch call returned an accepted count.
//! 4. The written item is `Draft` (never auto-authoritative) — the design's human-gate survives the
//!    automated cadence untouched.
//!
//! Fail-before/pass-after: reverting the `.with_org_knowledge(&mut org_sink)` wire in
//! `ainxt_runtimed::feedback_flywheel_tick` (back to no gates at all) makes the read-back assertion
//! fail — the tick still reports the candidate as `unrouted` instead of `accepted`, and nothing is
//! ever written to the memory store.

use std::time::{SystemTime, UNIX_EPOCH};

use ainxt_runtimed::{assemble_chat, assemble_full, AssembledFull};

fn loaded_with_unique_log() -> ainxt_runtimed::LoadedConfig {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("ainxt-gap6-flywheel-{nanos}"));
    let src = format!(
        "version = 1\n[server]\nevent_log_dir = {:?}\n",
        dir.to_string_lossy()
    );
    ainxt_runtimed::load_layered(&[("gap6-flywheel", &src)]).expect("load offline config")
}

/// Serve the EXACT fully-wired app `main` ships and return the bound address.
async fn serve_shipped(full: &AssembledFull) -> std::net::SocketAddr {
    let app = full.to_full_app();
    let ext = full.to_full_app_ext();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(ainxt_server::serve_full_ext(listener, app, ext));
    addr
}

#[tokio::test(flavor = "multi_thread")]
async fn feedback_flywheel_dispatch_reaches_a_real_memory_sink() {
    use ainxt_memory::flywheel::CandidateDest;
    use ainxt_memory::GovernanceState;

    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let loaded = loaded_with_unique_log();
    let assembled = assemble_chat(&loaded).expect("assemble chat");
    let full = assemble_full(&loaded, assembled).expect("assemble full");
    assert!(
        full.memory_consent.is_some(),
        "sanity: assemble_chat must give this surface a real memory backing to dispatch into"
    );

    let addr = serve_shipped(&full).await;
    let client = reqwest::Client::new();

    // Two REAL served /feedback corrections, different turns, the SAME recurring error signature —
    // exactly the shape `ImprovementEngine::propose` needs to surface a CommonFix candidate
    // (recurrence threshold >= 2).
    let post_feedback = |turn_id: &'static str| {
        let client = client.clone();
        let addr = addr;
        async move {
            let body = serde_json::json!({
                "turn_id": turn_id,
                "signal": {
                    "kind": "correction",
                    "original": "retry immediately on timeout",
                    "corrected": "retry with exponential backoff on timeout",
                },
                "error_signature": "sig-timeout-retry",
                "confidence": 1.0,
            });
            let resp = client
                .post(format!("http://{addr}/feedback"))
                .header("content-type", "application/json")
                .header("x-ainxt-user", "alice")
                .body(body.to_string())
                .send()
                .await
                .expect("feedback send");
            assert_eq!(resp.status().as_u16(), 200, "feedback capture must succeed");
            let json: serde_json::Value = resp.json().await.expect("feedback json");
            assert_eq!(
                json["accepted"], true,
                "a fresh correction must be accepted: {json}"
            );
        }
    };
    post_feedback("t-1").await;
    post_feedback("t-2").await;

    // A bad-trajectory signal too, so the SAME tick also produces an `EvalCase` candidate — proving
    // the second real destination this fix wires (`AssembledFull::eval_staging`), not just OrgKnowledge.
    let traj_body = serde_json::json!({
        "turn_id": "t-3",
        "signal": {"kind": "trajectory", "step_id": "s1", "good": false, "note": "picked the wrong tool"},
    });
    let traj_resp = client
        .post(format!("http://{addr}/feedback"))
        .header("content-type", "application/json")
        .header("x-ainxt-user", "alice")
        .body(traj_body.to_string())
        .send()
        .await
        .expect("trajectory feedback send");
    assert_eq!(traj_resp.status().as_u16(), 200);

    // Sanity: captured into the SAME LIVE engine `AssembledFull::feedback_engine` holds (not a private
    // per-request copy) — the served route and the composition-root cadence must share ONE engine.
    assert_eq!(
        full.feedback_engine.lock().unwrap().rejected_quoted(),
        0,
        "real UserExplicit corrections must never be counted as rejected quoted-content"
    );

    // Drive ONE flywheel cadence tick — the SAME method `spawn_feedback_flywheel_sweep`'s background
    // loop calls — over that exact engine instance.
    let now = 1_000u64;
    let report = full.run_feedback_flywheel_tick(now);

    // The recurring-fix candidate must be ACCEPTED into the OrgKnowledge gate, not left unrouted.
    assert!(
        !report.unrouted.contains(&CandidateDest::OrgKnowledge),
        "OrgKnowledge must have a real gate wired, never unrouted: {report:?}"
    );
    assert_eq!(
        report.per_dest.get(&CandidateDest::OrgKnowledge),
        Some(&(1, 0)),
        "exactly one CommonFix candidate must be accepted, none rejected: {report:?}"
    );
    assert!(
        !report.unrouted.contains(&CandidateDest::EvalCase),
        "EvalCase must also have a real gate wired (the staging set), never unrouted: {report:?}"
    );
    assert_eq!(
        report.per_dest.get(&CandidateDest::EvalCase),
        Some(&(1, 0)),
        "the bad-trajectory candidate must be staged: {report:?}"
    );

    // Read the SECOND real destination back too: the flywheel staging set actually holds the staged
    // case (not just a dispatch-call accounting claim).
    {
        let staging = full.eval_staging.lock().unwrap();
        let staged = staging.staged();
        assert_eq!(
            staged.len(),
            1,
            "the staging set must durably hold the dispatched candidate"
        );
        assert_eq!(
            staged[0].provenance,
            ainxt_eval::integrity::CaseProvenance::Flywheel
        );
        assert!(
            !staged[0].human_approved,
            "the flywheel can never self-approve a staged case"
        );
        assert!(
            !staging.is_live(&staged[0].id),
            "a staged case is never auto-promoted to live"
        );
    }

    // THE PROVING STEP: read the destination BACK — the SAME MEM-10 memory backing `POST /memory/*`
    // serves — rather than trusting the dispatch call's own accounting.
    let expected_id = format!("flywheel-{now}-fix-0");
    let written = full
        .memory_consent
        .as_ref()
        .expect("memory backing")
        .with_store(|store| Ok(store.get_unchecked(&expected_id).cloned()))
        .expect("with_store must not error")
        .unwrap_or_else(|| panic!("the dispatched CommonFix OKI '{expected_id}' must actually be readable back from the SAME memory store POST /memory/* serves"));

    assert_eq!(
        written.governance,
        GovernanceState::Draft,
        "a flywheel-authored OKI must land Draft — the human-gate to authority must survive the \
         automated dispatch cadence untouched"
    );
    match &written.payload {
        Some(ainxt_memory::OrgPayload::CommonFix {
            error_pattern,
            verified_count,
            ..
        }) => {
            assert_eq!(error_pattern, "sig-timeout-retry");
            assert_eq!(
                *verified_count, 2,
                "both supporting turns must be reflected"
            );
        }
        other => panic!("expected a CommonFix payload, got {other:?}"),
    }
}
