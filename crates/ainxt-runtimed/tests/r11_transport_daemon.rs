// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R11 transport-daemon — the SHIPPED daemon exercises the newly-wired transport seams:
//!
//! * `r11_served_daemon_approval_roundtrip` — the wire-level HITL approve-to-proceed round-trip runs
//!   end-to-end over the REAL shipped daemon (`assemble_full` → `serve_full_ext`): the engine-side
//!   [`WireApprovalGate`](ainxt_server::WireApprovalGate) built from `AssembledFull::wire_approval_gate`
//!   blocks on the SAME coordinator the transport was handed, and a client's `approval.respond` on the
//!   served `/v1/command` resolves it. Proves the coordinator is genuinely shared (engine ↔ transport).
//! * `r11_served_daemon_observer_tail` — the read-only observer tail (`GET /v1/observe`) is MOUNTED on
//!   the shipped daemon and RBAC-gated (participant/admin only).
//! * `r11_config_selects_otlp_telemetry_sink` — `[telemetry] sink = "otlp"` config-selects the OTLP
//!   exporter on the shipped assembly (the report records the selection; the network POST is the infra
//!   transport swap).
//!
//! Deterministic + offline: the air-gapped provider backs the engine; the transport, spine and organs
//! are the REAL shipped composition types.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ainxt_runtime::approval::{ApprovalDecision, ApprovalGate, ApprovalRequest};
use ainxt_runtimed::{assemble_full, assemble_surface, load_layered};

fn loaded_with(extra: &str) -> ainxt_runtimed::LoadedConfig {
    // R16 critical: the daemon now refuses the header-trusting default authenticator unless the
    // deployment states the assumption (see r10_breach_clock_unit.rs) — state it here.
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("ainxt-r11td-{nanos}"));
    let src = format!(
        "version = 1\n[server]\nevent_log_dir = {:?}\n{extra}",
        dir.to_string_lossy()
    );
    load_layered(&[("r11td", &src)]).expect("load offline config")
}

#[tokio::test(flavor = "multi_thread")]
async fn r11_served_daemon_approval_roundtrip() {
    let loaded = loaded_with("");
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat");
    let full = assemble_full(&loaded, assembled).expect("assemble full");

    // The engine-side gate built from the surface's shared coordinator — the exact object a
    // composition feeds into the engine's `.with_approval(..)` seam.
    let gate = full.wire_approval_gate(Duration::from_secs(5));

    // Serve the REAL shipped daemon (base FullApp + additive FullAppExt, which carries the coordinator).
    let app = full.to_full_app();
    let ext = full.to_full_app_ext();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(ainxt_server::serve_full_ext(listener, app, ext));

    // Block a gated decision on the engine side.
    let decider = tokio::task::spawn_blocking(move || {
        gate.decide(&ApprovalRequest {
            session: "sess-pay".into(),
            actor: "alice".into(),
            tool: "settle.payment".into(),
            args: "amount=1".into(),
        })
    });

    // Deliver the human approval over the SERVED `/v1/command`.
    let client = reqwest::Client::new();
    let mut delivered = false;
    for _ in 0..100 {
        let txt = client
            .post(format!("http://{addr}/v1/command"))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(
                serde_json::json!({
                    "session": "sess-pay", "type": "approval.respond",
                    "approval_id": "ap-1", "decision": "approve"
                })
                .to_string(),
            )
            .send()
            .await
            .expect("send")
            .text()
            .await
            .expect("body");
        let body: serde_json::Value = serde_json::from_str(&txt).expect("json");
        if body["delivered"] == serde_json::Value::Bool(true) {
            delivered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        delivered,
        "the served daemon must deliver approval.respond to the blocked engine gate"
    );
    assert_eq!(
        decider.await.expect("joined"),
        ApprovalDecision::Approve,
        "the wire approve resumes the gated turn (approve-to-proceed) on the shipped daemon"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn r11_served_daemon_observer_tail() {
    let loaded = loaded_with("");
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat");
    let full = assemble_full(&loaded, assembled).expect("assemble full");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(ainxt_server::serve_full_ext(
        listener,
        full.to_full_app(),
        full.to_full_app_ext(),
    ));
    let client = reqwest::Client::new();

    // A non-participant is refused 403 — the observer tail is RBAC-gated on the shipped daemon.
    let stranger = client
        .get(format!("http://{addr}/v1/observe?session=nope"))
        .header("x-ainxt-user", "mallory")
        .send()
        .await
        .expect("send");
    assert_eq!(
        stranger.status().as_u16(),
        403,
        "observer tail must refuse a non-participant"
    );

    // An un-attributed request is 401 (identity seam mandatory).
    let anon = client
        .get(format!("http://{addr}/v1/observe?session=nope"))
        .send()
        .await
        .expect("send");
    assert_eq!(
        anon.status().as_u16(),
        401,
        "observer tail requires an authenticated principal"
    );
}

#[test]
fn r11_config_selects_otlp_telemetry_sink() {
    // Default config: the OSS in-memory sink (no OTLP selection line).
    let default_loaded = loaded_with("");
    let default_assembled = assemble_surface(&default_loaded, "chat").expect("assemble");
    let default_full = assemble_full(&default_loaded, default_assembled).expect("full");
    assert!(
        !default_full
            .report
            .iter()
            .any(|l| l.contains("OTLP/OpenTelemetry exporter SELECTED")),
        "the default config must NOT select the OTLP exporter"
    );

    // `sink = "otlp"` config-selects the OTLP exporter on the shipped assembly.
    let otlp_loaded =
        loaded_with("[telemetry]\nsink = \"otlp\"\notlp_endpoint = \"http://collector:4318\"\n");
    let otlp_assembled = assemble_surface(&otlp_loaded, "chat").expect("assemble");
    let otlp_full = assemble_full(&otlp_loaded, otlp_assembled).expect("full");
    assert!(
        otlp_full
            .report
            .iter()
            .any(|l| l.contains("OTLP/OpenTelemetry exporter SELECTED")
                && l.contains("collector:4318")),
        "sink=otlp must config-select the OTLP exporter (report): {:?}",
        otlp_full.report
    );
}
