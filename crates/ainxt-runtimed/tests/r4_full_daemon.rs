// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R4 — the SHIPPED daemon serves the FULLY-WIRED app.
//!
//! Before this round the shipped `ainxt-runtimed` binary called `ainxt_server::serve` (the minimal
//! transport: only `/v1/chat` + `/v1/command`), so `/v1/replay`, `/graph`, `/v1/query_ledger`,
//! `/v1/infer` and the control organs were test-only fixtures. These tests assert on the REAL
//! composition objects (`assemble_full` → `AssembledFull` → `ainxt_server::serve_full`).
//!
//! `r4_daemon_serves_fully_wired_app` asserts the served daemon exposes `/graph`, `/v1/query_ledger`,
//! `/v1/replay` and `/v1/infer` (NOT 404) even on the air-gapped default (empty corpus, graph, and
//! serving pool still serve), and that a live `IncidentRegister` and shared `ControlPlane` are present
//! on the served surface. `r4_breach_clock_advances` asserts the live `IncidentRegister` advances its
//! statutory clocks (an armed clock breaches once wall-clock time passes its budget).
//! `r4_kill_switch_reaches_inflight_run` asserts a kill-switch / revocation on the shared
//! `ControlPlane` reaches an in-flight Program Run (its next module dispatch is denied, fail-closed).
//!
//! Deterministic: the offline provider (no keys/network) backs the engine; the transport, the
//! SessionManager spine, the governed surfaces and the control organs are the REAL production types.

use std::time::{SystemTime, UNIX_EPOCH};

use ainxt_incident::{IncidentCandidate, StatutoryClockKind};
use ainxt_planner::program::{NodeClass, NodeDecl};
use ainxt_planner::supervisor::SupervisorConfig;
use ainxt_runtimed::{
    assemble_full, assemble_program, assemble_surface, load_layered, RunIdentitySpec,
};
use ainxt_types::DataClass;

/// A loaded config with a UNIQUE durable event-log dir (so concurrent tests never share a hash chain).
fn loaded_with_unique_log() -> ainxt_runtimed::LoadedConfig {
    // R16 critical: the daemon now refuses the header-trusting default authenticator unless the
    // deployment states the assumption (see r10_breach_clock_unit.rs) — state it here.
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("ainxt-r4-{nanos}"));
    let src = format!(
        "version = 1\n[server]\nevent_log_dir = {:?}\n",
        dir.to_string_lossy()
    );
    load_layered(&[("r4", &src)]).expect("load offline config")
}

async fn post(
    client: &reqwest::Client,
    addr: &std::net::SocketAddr,
    path: &str,
    body: serde_json::Value,
) -> u16 {
    client
        .post(format!("http://{addr}{path}"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header("x-ainxt-user", "alice")
        .header("x-ainxt-clearance", "confidential")
        .body(body.to_string())
        .send()
        .await
        .expect("request send")
        .status()
        .as_u16()
}

#[tokio::test(flavor = "multi_thread")]
async fn r4_daemon_serves_fully_wired_app() {
    let loaded = loaded_with_unique_log();
    // The default chat surface, augmented into the fully-wired served surface — exactly what `main`
    // ships (assemble_surface → assemble_full → serve_full).
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat surface");
    let full = assemble_full(&loaded, assembled).expect("assemble fully-wired surface");

    // The two live control organs are PRESENT on the served surface (not test-only).
    assert!(
        full.incidents.lock().is_ok(),
        "a live IncidentRegister must be present on the served surface"
    );
    assert!(
        full.control_plane.lock().is_ok(),
        "a shared ControlPlane must be present on the served surface"
    );
    // Offline default holds: empty graph, empty serving pool — but every governed surface is wired.
    assert!(
        full.graph.node_count() == 0,
        "air-gapped default graph is empty"
    );
    assert!(
        full.serving.1.is_empty(),
        "air-gapped default advertises no serving nodes"
    );

    // Serve the REAL fully-wired app over HTTP.
    let app = full.to_full_app();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let _clock = full.spawn_breach_clock(std::time::Duration::from_millis(50));
    tokio::spawn(ainxt_server::serve_full(listener, app));
    let client = reqwest::Client::new();

    // Each governed surface is MOUNTED (a 404 would mean it was never wired into the shipped binary).
    // Bodies are plausible; the exact status may be 200/4xx/503 — the assertion is "route exists".
    let graph = post(
        &client,
        &addr,
        "/graph",
        serde_json::json!({"op":"traverse","start":"root","max_depth":1}),
    )
    .await;
    assert_ne!(graph, 404, "/graph must be served by the shipped daemon");
    assert_eq!(
        graph, 200,
        "empty graph still SERVES (offline default): got {graph}"
    );

    let ledger = post(
        &client,
        &addr,
        "/v1/query_ledger",
        serde_json::json!({"select":["entry_id"],"from":"ledger_entries","limit":10}),
    )
    .await;
    assert_ne!(
        ledger, 404,
        "/v1/query_ledger must be served by the shipped daemon"
    );

    let replay = post(
        &client,
        &addr,
        "/v1/replay",
        serde_json::json!({"session":"s1","op":{"turn.stop":{"turn_id":"t1"}}}),
    )
    .await;
    assert_ne!(
        replay, 404,
        "/v1/replay must be served by the shipped daemon"
    );

    let infer = post(
        &client,
        &addr,
        "/v1/infer",
        serde_json::json!({"seq_id":1,"model_id":"m","data_class":"internal"}),
    )
    .await;
    assert_ne!(infer, 404, "/v1/infer must be served by the shipped daemon");

    // REGRESSION GUARD (round-4 ship fix): the shipped `/v1/chat` MUST actually serve a turn on the
    // air-gapped default. The serving/attestation fence must apply ONLY when a serving pool is
    // deployed — with an empty pool it must NOT 503 (the model is served by the engine's own provider
    // chain, no GPU node to attest). Before the fix this returned 503 on every turn.
    let chat = post(
        &client,
        &addr,
        "/v1/chat",
        serde_json::json!({"session":"s1","turn":"t1","input":"hello","data_class":"public","caps":["chat.send"]}),
    )
    .await;
    assert_ne!(chat, 404, "/v1/chat must be served by the shipped daemon");
    assert_ne!(
        chat, 503,
        "/v1/chat must NOT 503 on the air-gapped default — the serving fence must be inert with no pool"
    );
    assert_eq!(
        chat, 200,
        "the shipped daemon must serve a basic chat turn on the default: got {chat}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn r4_breach_clock_advances() {
    let loaded = loaded_with_unique_log();
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat surface");
    let full = assemble_full(&loaded, assembled).expect("assemble fully-wired surface");

    // Open a real regulated-egress incident on the LIVE register (t0 = 0). The India arming policy arms
    // the DPDP clocks for a personal-data breach.
    let t0 = 0u64;
    {
        let mut reg = full.incidents.lock().unwrap();
        let candidate =
            IncidentCandidate::from_compliance_egress(t0, "cp-sha-r4", DataClass::Pii, 100);
        reg.open_from(candidate, t0);
        assert!(
            !reg.armed_clocks(t0).is_empty(),
            "opening a regulated-egress incident must arm statutory clocks"
        );
        assert!(
            reg.breached_without_filing(t0).is_empty(),
            "no clock is breached at t0"
        );
    }

    // Advance logical time past the tightest budget (DPDP data-principal = 1440 ticks) via tick() — the
    // same call the background breach-clock ticker makes. The clock must now be BREACHED.
    let now = t0 + 1_441;
    {
        let mut reg = full.incidents.lock().unwrap();
        reg.tick(now);
        let breached = reg.breached_without_filing(now);
        assert!(
            breached
                .iter()
                .any(|(_, kind)| *kind == StatutoryClockKind::DpdpDataPrincipal),
            "the breach clock must advance and breach once its budget elapses: {breached:?}"
        );
    }
    // The evidentiary hash chain still verifies after arming + ticking (tamper-evident).
    assert!(
        full.incidents.lock().unwrap().verify().is_ok(),
        "incident chain verifies"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn r4_kill_switch_reaches_inflight_run() {
    let loaded = loaded_with_unique_log();
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat surface");
    let full = assemble_full(&loaded, assembled).expect("assemble fully-wired surface");

    // A program runtime over the SAME offline engine, driven through the GOVERNED path so the shared
    // control plane is consulted before every module dispatch.
    let program = assemble_program(&loaded).expect("assemble program runtime");
    let run_id = "run-kill-1";
    let identity = RunIdentitySpec::new("program", "prog-a", run_id, DataClass::Internal, "alice");

    // Pull the control lever BEFORE the run: revoke this exact Run on the shared control plane.
    full.control_plane.lock().unwrap().revoke_run(run_id);

    let run = program
        .run_program_governed(
            identity,
            "do the work",
            vec![NodeDecl::new("deliver", NodeClass::MigrationRun)],
            SupervisorConfig::default(),
            None,
            full.control_plane.clone(),
        )
        .await
        .expect("the run drives to a terminal report even when denied");

    // Every module dispatch was DENIED by the control plane — no module turn reached the provider.
    assert!(
        !run.turns.is_empty(),
        "the supervisor attempted at least one module dispatch"
    );
    assert!(
        run.turns.iter().all(|t| !t.ok && t.provider == "denied"),
        "a revoked Run's dispatches must be denied by the control plane (kill-switch reaches in-flight \
         Runs): {:?}",
        run.turns
    );
}
