// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R9 — the SHIPPED daemon serves three things END-TO-END over REAL HTTP that were previously either
//! held-but-unrouted or served through the lossy legacy projection. Each test drives the EXACT
//! composition `main` ships (`assemble_surface` → `assemble_full` →
//! `serve_full_ext(to_full_app(), to_full_app_ext())`) over a real socket + a real `reqwest` client.
//!
//!   * `r9_served_chat_emits_typed_wire_by_default` (gap 1) — the served `/v1/chat` SSE body carries the
//!     engine's REAL typed §6 [`WireEvent`] envelopes BY DEFAULT: a `turn.started` frame (which the lossy
//!     legacy `Event` projection can NEVER emit — there is no `Event` for turn-start) proves the engine
//!     wire sink is attached and serialized, not re-derived. Fail-before: `to_full_app_ext` set
//!     `wire_events: None`, so the body was the legacy projection (no `turn.started`).
//!   * `r9_served_turn_round_trips_through_replay_store` (gap 2) — a served chat turn is WRITTEN into the
//!     SAME durable session store `/v1/replay/step` reads: the step route 404s for the session BEFORE the
//!     turn and 200s (with ≥1 step) AFTER it. Fail-before: nothing on the served path ever persisted a
//!     turn tree, so a served run could never be paged back.
//!   * `r9_regfi_routes_mounted_and_fail_closed` (gap 3) — the regulated-FI supervisory routes are MOUNTED
//!     over the LIVE organs and fail-closed: `/v1/regfi/erasure` refuses without `CAP_RETENTION_ADMIN`
//!     (403) and hard-erases a free record with it; `/v1/regfi/auditor` + `/v1/regfi/evidence` refuse
//!     without the EXPLICIT `AUDITOR_CAP` (403, admin NOT implied), an unknown incident is existence-
//!     hidden (404), and an in-scope §63 export succeeds (200). Fail-before: the routes did not exist.
//!
//! Deterministic + offline: the air-gapped default (offline provider, no keys/network) backs the engine;
//! the transport, the SessionManager spine, and the regulated-FI organs are the REAL production types.

use std::time::{SystemTime, UNIX_EPOCH};

use ainxt_runtimed::{assemble_chat, assemble_full, assemble_surface, load_layered};

fn loaded_with_unique_log() -> ainxt_runtimed::LoadedConfig {
    // R16 critical: the daemon now refuses the header-trusting default authenticator unless the
    // deployment states the assumption (see r10_breach_clock_unit.rs) — state it here.
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("ainxt-r9w-{nanos}"));
    // These assertions are about the India statutory-clock machinery (CERT-In/DPDP/RBI). The OSS
    // default arming policy is `Generic` (no pre-armed clocks), so state the profile explicitly —
    // exactly as an India-regulated deployment does in its private overlay.
    let src = format!(
        "version = 1\n[server]\nevent_log_dir = {:?}\n[incident]\narming_policy = \"india-regulatory\"\n",
        dir.to_string_lossy()
    );
    load_layered(&[("r9w", &src)]).expect("load offline config")
}

/// Serve the EXACT fully-wired app `main` ships and return the bound address.
async fn serve_shipped(full: &ainxt_runtimed::AssembledFull) -> std::net::SocketAddr {
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
async fn r9_served_chat_emits_typed_wire_by_default() {
    let loaded = loaded_with_unique_log();
    // The grounded ChatSurface (the shipped-default wire path) — `assemble_chat` uses the SAME
    // `build_chat_surface_wired` seam `assemble_surface` does, so the engine wire sink is attached and
    // its receiver flows to the transport. (The profile-scoped `assemble_surface` "chat" additionally
    // enforces a department floor the trusted-gateway DTO principal cannot carry, which would refuse the
    // turn IN-BAND before the engine runs — that RBAC is out of scope for this wire-serialization proof.)
    let assembled = assemble_chat(&loaded).expect("assemble chat");
    let full = assemble_full(&loaded, assembled).expect("assemble full");
    let addr = serve_shipped(&full).await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{addr}/v1/chat"))
        .header("content-type", "application/json")
        .header("x-ainxt-user", "alice")
        .header("x-ainxt-clearance", "internal")
        .header("x-ainxt-department", "payments")
        // R16 critical #13: once an X-AInxt-User header is forwarded, capabilities are resolved from
        // the trusted X-AInxt-Caps header (identity_from_headers), never the request-body `caps` field
        // — a client can no longer self-grant capabilities by simply listing them in the JSON body.
        .header("x-ainxt-caps", "chat.send")
        .body(
            serde_json::json!({
                "session":"s1","turn":"t1","input":"What is the settlement runbook?",
                "data_class":"public","caps":["chat.send"]
            })
            .to_string(),
        )
        .send()
        .await
        .expect("chat send");
    assert_eq!(
        resp.status().as_u16(),
        200,
        "the shipped daemon serves the chat turn"
    );
    let body = resp.text().await.expect("read SSE body");

    // The typed §6 wire stream emits a `turn.started` frame — the lossy legacy `Event` projection has no
    // Event for turn-start, so its presence proves the engine wire sink is attached + serialized by
    // default (not re-derived). This is the exact frame that was ABSENT before the R9 default flip.
    assert!(
        body.contains("\"type\":\"turn.started\""),
        "served /v1/chat must emit the typed §6 WireEvent stream by default (a turn.started frame the \
         legacy projection cannot produce); body was:\n{body}"
    );
    // And the terminal outcome frame is the typed `turn.completed` (truthful capped-vs-complete lives
    // only on this stream) — the SSE stream is envelope-framed, not bare legacy `Event`.
    assert!(
        body.contains("\"type\":\"turn.completed\""),
        "served /v1/chat must emit a typed turn.completed terminal frame; body was:\n{body}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn r9_served_turn_round_trips_through_replay_store() {
    let loaded = loaded_with_unique_log();
    let assembled = assemble_chat(&loaded).expect("assemble chat");
    let full = assemble_full(&loaded, assembled).expect("assemble full");
    let addr = serve_shipped(&full).await;
    let client = reqwest::Client::new();

    // NOTE: under the trusted-gateway header auth, `principal_for_chat` resolves the served turn's
    // actor (the recording participant) from the forwarded `X-AInxt-User` header — "alice" below, not
    // the session id — so the replay caller, who is authorized only if a participant, must
    // authenticate AS "alice" (R16 critical #13: chat no longer falls back to session-as-actor once an
    // identity header is present).
    let step = |session: &str| {
        let client = client.clone();
        let session = session.to_string();
        async move {
            client
                .post(format!("http://{addr}/v1/replay/step"))
                .header("content-type", "application/json")
                .header("x-ainxt-user", "alice")
                .header("x-ainxt-clearance", "internal")
                .header("x-ainxt-caps", "chat.send")
                .body(serde_json::json!({"session": session, "from_index": 0}).to_string())
                .send()
                .await
                .expect("replay/step send")
        }
    };

    // FAIL-BEFORE: no served turn has persisted this session yet → the step route 404s.
    let before = step("conv-1").await.status().as_u16();
    assert_eq!(
        before, 404,
        "before the served turn, /v1/replay/step has no session: got {before}"
    );

    // Drive a served chat turn to completion (read the body fully so the write-path task has run).
    let chat = client
        .post(format!("http://{addr}/v1/chat"))
        .header("content-type", "application/json")
        .header("x-ainxt-user", "alice")
        .header("x-ainxt-clearance", "internal")
        .header("x-ainxt-department", "payments")
        .header("x-ainxt-caps", "chat.send")
        .body(
            serde_json::json!({
                "session":"conv-1","turn":"u1","input":"How did UPI grow?",
                "data_class":"public","caps":["chat.send"]
            })
            .to_string(),
        )
        .send()
        .await
        .expect("chat send");
    assert_eq!(chat.status().as_u16(), 200);
    let _ = chat.text().await.expect("drain chat body");

    // PASS-AFTER: the SAME served session now pages through the ONE durable store.
    let resp = step("conv-1").await;
    assert_eq!(
        resp.status().as_u16(),
        200,
        "after the served turn, /v1/replay/step must page the recorded session"
    );
    let page: serde_json::Value = resp.json().await.expect("replay page json");
    let steps = page
        .get("steps")
        .and_then(|s| s.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    assert!(
        steps > 0,
        "the served-recorded session must page ≥1 replay step: {page}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn r9_regfi_routes_mounted_and_fail_closed() {
    use ainxt_lifecycle::Record;
    use ainxt_types::DataClass;

    let loaded = loaded_with_unique_log();
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat");
    let full = assemble_full(&loaded, assembled).expect("assemble full");

    // Seed the LIVE retention store with one FREE record for the subject, and open one personal-data
    // breach incident on the LIVE register — the SAME organs the routes drive.
    full.retention.lock().unwrap().put(Record::new(
        "free-rec",
        "subject-9",
        DataClass::Internal,
        0,
    ));
    let incident_id = full.arm_compliance_egress_incident(100, DataClass::Pii, 5);

    let addr = serve_shipped(&full).await;
    let client = reqwest::Client::new();

    // ---- /v1/regfi/erasure — fail-closed on CAP_RETENTION_ADMIN ----
    let post = |path: &str, caps: &str, body: serde_json::Value| {
        let client = client.clone();
        let (path, caps, body) = (path.to_string(), caps.to_string(), body);
        async move {
            client
                .post(format!("http://{addr}{path}"))
                .header("content-type", "application/json")
                .header("x-ainxt-user", "dpo")
                .header("x-ainxt-caps", caps)
                .body(body.to_string())
                .send()
                .await
                .expect("regfi send")
        }
    };

    let refused = post(
        "/v1/regfi/erasure",
        "chat.send",
        serde_json::json!({"subject_id":"subject-9"}),
    )
    .await;
    assert_eq!(
        refused.status().as_u16(),
        403,
        "erasure without CAP_RETENTION_ADMIN must be 403"
    );
    assert!(
        full.retention.lock().unwrap().get("free-rec").is_some(),
        "nothing erased on the refusal"
    );

    let ok = post(
        "/v1/regfi/erasure",
        "retention.admin",
        serde_json::json!({"subject_id":"subject-9","now":1000}),
    )
    .await;
    assert_eq!(
        ok.status().as_u16(),
        200,
        "erasure with CAP_RETENTION_ADMIN must be 200"
    );
    let att: serde_json::Value = ok.json().await.expect("attestation json");
    assert!(
        att.get("resolution")
            .and_then(|r| r.get("erased"))
            .and_then(|v| v.as_array())
            .map(|a| a.iter().any(|v| v.as_str() == Some("free-rec")))
            .unwrap_or(false),
        "the free record must be hard-erased in the attestation: {att}"
    );
    assert!(
        full.retention.lock().unwrap().get("free-rec").is_none(),
        "the free record is gone from the store"
    );

    // ---- /v1/regfi/auditor — fail-closed on the EXPLICIT AUDITOR_CAP (admin NOT implied) ----
    let auditor_body = serde_json::json!({"scope":{"kind":"all"},"now":300});
    let refused_auditor = client
        .post(format!("http://{addr}/v1/regfi/auditor"))
        .header("content-type", "application/json")
        .header("x-ainxt-user", "root")
        .header("x-ainxt-role", "admin") // admin is NOT implied — must still be refused
        .body(auditor_body.to_string())
        .send()
        .await
        .expect("auditor send");
    assert_eq!(
        refused_auditor.status().as_u16(),
        403,
        "auditor listing without AUDITOR_CAP must be 403 (admin not implied)"
    );

    let ok_auditor = post(
        "/v1/regfi/auditor",
        "incident:supervisory-auditor",
        serde_json::json!({"scope":{"kind":"all"},"now":300}),
    )
    .await;
    assert_eq!(
        ok_auditor.status().as_u16(),
        200,
        "auditor listing with AUDITOR_CAP must be 200"
    );
    let listing: serde_json::Value = ok_auditor.json().await.expect("listing json");
    let ids = listing
        .get("incident_ids")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    assert!(
        ids.iter().any(|v| v.as_str() == Some(incident_id.as_str())),
        "the auditor listing must include the live incident: {listing}"
    );

    // ---- /v1/regfi/evidence — existence-hiding + explicit-cap §63 export ----
    let export_req = |incident: &str| {
        serde_json::json!({
            "scope": {"kind":"classes","classes":["personal-data-breach"]},
            "request": {
                "incident_id": incident,
                "runtime_version": "ainxt-runtime/9.0.0",
                "production_method": "append-only SHA-256 hash-chained Event Log",
                "ntp": {"source":"nic-ntp-pool","last_sync_offset_ms":8,"within_threshold":true},
                "export_tick": 500
            }
        })
    };

    // Unknown incident id → existence-hidden 404 (with AUDITOR_CAP).
    let unknown = post(
        "/v1/regfi/evidence",
        "incident:supervisory-auditor",
        export_req("no-such-incident"),
    )
    .await;
    assert_eq!(
        unknown.status().as_u16(),
        404,
        "an unknown incident must be existence-hidden (404)"
    );

    // In-scope real incident → 200 §63 export.
    let export = post(
        "/v1/regfi/evidence",
        "incident:supervisory-auditor",
        export_req(&incident_id),
    )
    .await;
    assert_eq!(
        export.status().as_u16(),
        200,
        "an in-scope §63 export with AUDITOR_CAP must be 200"
    );
    let ev: serde_json::Value = export.json().await.expect("export json");
    assert_eq!(
        ev.get("certificate")
            .and_then(|c| c.get("record_set_id"))
            .and_then(|v| v.as_str()),
        Some(incident_id.as_str()),
        "the §63 certificate must be for the exported incident: {ev}"
    );

    // ---- GAP-AUDIT regulated-fi #6 — /v1/regfi/downgrade, fail-closed on DOWNGRADE_CAP ----
    // `arm_compliance_egress_incident` opens a `PersonalDataBreach` incident, which the India default
    // arming policy (`ArmingPolicy::india_default`) arms with `DpdpDataPrincipal` + `DpdpBoard` — not
    // `CertIn` (that clock is reserved for `CyberSecurityIncident`/`AgentSettlementAction`).
    let downgrade_body = serde_json::json!({
        "incident_id": incident_id,
        "clock": "dpdp-data-principal",
        "reason": "confirmed a false positive on manual review",
        "now": 400
    });
    let refused_downgrade = post(
        "/v1/regfi/downgrade",
        "incident:supervisory-auditor",
        downgrade_body.clone(),
    )
    .await;
    assert_eq!(
        refused_downgrade.status().as_u16(),
        403,
        "downgrade without DOWNGRADE_CAP must be 403"
    );

    let ok_downgrade = post(
        "/v1/regfi/downgrade",
        "compliance:downgrade-clock",
        downgrade_body,
    )
    .await;
    assert_eq!(
        ok_downgrade.status().as_u16(),
        200,
        "downgrade with DOWNGRADE_CAP must be 200"
    );

    // The clock is genuinely stopped on the LIVE served register — visible to the SAME auditor listing
    // used above (the incident itself still exists; only its clock state changed).
    let still_visible = post(
        "/v1/regfi/auditor",
        "incident:supervisory-auditor",
        serde_json::json!({"scope":{"kind":"all"},"now":500}),
    )
    .await;
    assert_eq!(still_visible.status().as_u16(), 200);
    let listing2: serde_json::Value = still_visible.json().await.expect("listing json");
    let ids2 = listing2
        .get("incident_ids")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    assert!(
        ids2.iter().any(|v| v.as_str() == Some(incident_id.as_str())),
        "the incident itself must still exist after a clock downgrade (downgrade stops a clock, not the incident): {listing2}"
    );
}

/// GAP-AUDIT regulated-fi #13 — the §6.5 break-glass Program was fully implemented and tested in
/// `ainxt-lifecycle` but had zero callers outside its own crate: no served route ever opened or
/// stepped one. Proves `/v1/regfi/breakglass/{open,step,progress}` over the SHIPPED daemon: fail-closed
/// on the EXPLICIT BREAK_GLASS_CAP (admin NOT implied, matching the AUDITOR_CAP/CAP_RETENTION_ADMIN
/// least-privilege pattern the sibling regfi routes already use), a two-target campaign steps to
/// completion one checkpoint at a time, and re-opening an existing program id is refused rather than
/// silently replacing the in-flight campaign.
#[tokio::test(flavor = "multi_thread")]
async fn r13_served_breakglass_program_open_step_progress() {
    let loaded = loaded_with_unique_log();
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat surface");
    let full = assemble_full(&loaded, assembled).expect("assemble fully-wired surface");
    let addr = serve_shipped(&full).await;
    let client = reqwest::Client::new();

    let post = |path: &str, caps: &str, body: serde_json::Value| {
        let client = client.clone();
        let (path, caps, body) = (path.to_string(), caps.to_string(), body);
        async move {
            client
                .post(format!("http://{addr}{path}"))
                .header("content-type", "application/json")
                .header("x-ainxt-user", "dpo")
                .header("x-ainxt-caps", caps)
                .body(body.to_string())
                .send()
                .await
                .expect("breakglass send")
        }
    };

    let open_body = serde_json::json!({
        "program_id": "bg-campaign-1",
        "reason_code": "detector-miss-pii-in-held-record",
        "targets": [
            {"record_id": "rec-a", "original_evidence_hash": "hash-a", "note": "email leaked into a PMLA-floored log"},
            {"record_id": "rec-b", "original_evidence_hash": "hash-b", "note": "phone leaked into the same log"}
        ]
    });

    // Fail-closed: a caller WITHOUT the explicit BREAK_GLASS_CAP is refused (admin not implied, but
    // there's no admin role in play here at all — just the wrong/no capability).
    let refused = post("/v1/regfi/breakglass/open", "chat.send", open_body.clone()).await;
    assert_eq!(
        refused.status().as_u16(),
        403,
        "open without BREAK_GLASS_CAP must be 403"
    );

    let opened = post(
        "/v1/regfi/breakglass/open",
        "lifecycle:break-glass-remediate",
        open_body.clone(),
    )
    .await;
    assert_eq!(
        opened.status().as_u16(),
        200,
        "open with BREAK_GLASS_CAP must be 200"
    );
    let opened_json: serde_json::Value = opened.json().await.expect("open json");
    assert_eq!(opened_json.get("total").and_then(|v| v.as_u64()), Some(2));

    // Re-opening the SAME program id is refused, not silently replaced.
    let reopen = post(
        "/v1/regfi/breakglass/open",
        "lifecycle:break-glass-remediate",
        open_body,
    )
    .await;
    assert_eq!(
        reopen.status().as_u16(),
        409,
        "re-opening an existing program id must be refused"
    );

    // Stepping without the capability is refused too (re-checked per call, not just at open).
    let step_body = serde_json::json!({"program_id": "bg-campaign-1", "now": 100});
    let step_refused = post("/v1/regfi/breakglass/step", "chat.send", step_body.clone()).await;
    assert_eq!(
        step_refused.status().as_u16(),
        403,
        "step without BREAK_GLASS_CAP must be 403"
    );

    // Two steps process both targets and reach completion.
    let step1 = post(
        "/v1/regfi/breakglass/step",
        "lifecycle:break-glass-remediate",
        step_body.clone(),
    )
    .await;
    assert_eq!(step1.status().as_u16(), 200);
    let step1_json: serde_json::Value = step1.json().await.expect("step1 json");
    assert_eq!(step1_json.get("done").and_then(|v| v.as_u64()), Some(1));
    assert!(
        step1_json
            .get("attestation")
            .map(|a| !a.is_null())
            .unwrap_or(false),
        "the first step must return a real attestation: {step1_json}"
    );

    let step2 = post(
        "/v1/regfi/breakglass/step",
        "lifecycle:break-glass-remediate",
        step_body,
    )
    .await;
    let step2_json: serde_json::Value = step2.json().await.expect("step2 json");
    assert_eq!(step2_json.get("done").and_then(|v| v.as_u64()), Some(2));

    let progress = post(
        "/v1/regfi/breakglass/progress",
        "lifecycle:break-glass-remediate",
        serde_json::json!({"program_id": "bg-campaign-1"}),
    )
    .await;
    let progress_json: serde_json::Value = progress.json().await.expect("progress json");
    assert_eq!(
        progress_json.get("complete").and_then(|v| v.as_bool()),
        Some(true)
    );
    assert_eq!(progress_json.get("total").and_then(|v| v.as_u64()), Some(2));
}

/// GAP-AUDIT regulated-fi #7/#9 — the §4.4 DSAR workflow and the §6 retention/legal-hold precedence
/// command set were both fully implemented and route-ready (`DsarWorkflow`/`RetentionService` in
/// `ainxt-lifecycle`) but had NO served entrypoint at all before this fix — the only DPDP path that
/// existed on the shipped daemon was the narrower `/v1/regfi/erasure`. Proves `/v1/regfi/dsar`
/// (open → authenticate → erase, dispatching through the SAME shared retention store
/// `/v1/regfi/erasure` uses) and `/v1/regfi/hold` (request-erasure / purge) are both reachable and
/// fail-closed on their respective capabilities.
#[tokio::test(flavor = "multi_thread")]
async fn r7_r9_served_dsar_and_hold_routes() {
    use ainxt_lifecycle::Record;
    use ainxt_types::DataClass;

    let loaded = loaded_with_unique_log();
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat surface");
    let full = assemble_full(&loaded, assembled).expect("assemble fully-wired surface");

    // Seed the SAME shared retention store `/v1/regfi/erasure` drives with a free record for the DSAR
    // subject, so the DSAR's `Erase` command has something real to hard-erase.
    full.retention.lock().unwrap().put(Record::new(
        "dsar-rec",
        "subject-dsar",
        DataClass::Internal,
        0,
    ));

    let addr = serve_shipped(&full).await;
    let client = reqwest::Client::new();
    let post = |path: &str, caps: &str, body: serde_json::Value| {
        let client = client.clone();
        let (path, caps, body) = (path.to_string(), caps.to_string(), body);
        async move {
            client
                .post(format!("http://{addr}{path}"))
                .header("content-type", "application/json")
                .header("x-ainxt-user", "dpo")
                .header("x-ainxt-caps", caps)
                .body(body.to_string())
                .send()
                .await
                .expect("regfi send")
        }
    };

    // ---- /v1/regfi/dsar — fail-closed on CAP_DSAR_OPERATE ----
    let open_body = serde_json::json!({
        "command": {"op":"open","id":"dsar-1","subject_id":"subject-dsar","kind":"erasure","sla_ticks":1000},
        "now": 0
    });
    let refused = post("/v1/regfi/dsar", "chat.send", open_body.clone()).await;
    assert_eq!(
        refused.status().as_u16(),
        403,
        "DSAR open without CAP_DSAR_OPERATE must be 403"
    );

    let opened = post("/v1/regfi/dsar", "dsar.operate", open_body).await;
    assert_eq!(
        opened.status().as_u16(),
        200,
        "DSAR open with CAP_DSAR_OPERATE must be 200"
    );

    let authed = post(
        "/v1/regfi/dsar",
        "dsar.operate",
        serde_json::json!({"command": {"op":"authenticate","id":"dsar-1","proof_ok":true}, "now": 1}),
    )
    .await;
    assert_eq!(
        authed.status().as_u16(),
        200,
        "DSAR authenticate must be 200"
    );

    // The erasure DISPATCHES THROUGH the SAME shared retention store `/v1/regfi/erasure` uses.
    let erased = post(
        "/v1/regfi/dsar",
        "dsar.operate",
        serde_json::json!({"command": {"op":"erase","id":"dsar-1"}, "now": 2}),
    )
    .await;
    assert_eq!(erased.status().as_u16(), 200, "DSAR erase must be 200");
    assert!(
        full.retention.lock().unwrap().get("dsar-rec").is_none(),
        "the DSAR erasure must hard-erase the free record on the SAME shared retention store"
    );

    // ---- /v1/regfi/hold — fail-closed on CAP_RETENTION_ADMIN ----
    let purge_body = serde_json::json!({"command": {"op":"purge"}, "now": 3});
    let hold_refused = post("/v1/regfi/hold", "chat.send", purge_body.clone()).await;
    assert_eq!(
        hold_refused.status().as_u16(),
        403,
        "hold command without CAP_RETENTION_ADMIN must be 403"
    );

    let purge_ok = post("/v1/regfi/hold", "retention.admin", purge_body).await;
    assert_eq!(
        purge_ok.status().as_u16(),
        200,
        "purge with CAP_RETENTION_ADMIN must be 200"
    );
}

/// GAP-AUDIT regulated-fi #5 — the §2.4 pre-templated breach-report drafting mechanism was fully
/// implemented and tested in `ainxt-incident::report` but had zero callers outside its own crate.
/// Proves `/v1/regfi/report` is reachable, fail-closed on the SAME explicit AUDITOR_CAP the sibling
/// evidence/auditor routes use, and drafts a real CERT-In form from the LIVE incident register's
/// structured facts (not a stub/placeholder body).
#[tokio::test(flavor = "multi_thread")]
async fn r5_served_report_drafting_route() {
    use ainxt_types::DataClass;

    let loaded = loaded_with_unique_log();
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat surface");
    let full = assemble_full(&loaded, assembled).expect("assemble fully-wired surface");

    let incident_id = full.arm_compliance_egress_incident(100, DataClass::Pii, 7);

    let addr = serve_shipped(&full).await;
    let client = reqwest::Client::new();
    let post = |caps: &str, body: serde_json::Value| {
        let client = client.clone();
        let (caps, body) = (caps.to_string(), body);
        async move {
            client
                .post(format!("http://{addr}/v1/regfi/report"))
                .header("content-type", "application/json")
                .header("x-ainxt-user", "dpo")
                .header("x-ainxt-caps", caps)
                .body(body.to_string())
                .send()
                .await
                .expect("report send")
        }
    };

    let body = serde_json::json!({"incident_id": incident_id, "kind": "cert-in"});
    let refused = post("chat.send", body.clone()).await;
    assert_eq!(
        refused.status().as_u16(),
        403,
        "report drafting without AUDITOR_CAP must be 403"
    );

    let ok = post("incident:supervisory-auditor", body).await;
    assert_eq!(
        ok.status().as_u16(),
        200,
        "report drafting with AUDITOR_CAP must be 200"
    );
    let draft: serde_json::Value = ok.json().await.expect("draft json");
    let rendered = draft
        .get("body")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert!(
        rendered.contains(&incident_id),
        "the drafted report must be filled with the REAL incident id, not a stub: {rendered}"
    );
    assert!(
        rendered.contains("Pii") || rendered.contains("pii"),
        "the drafted report must reflect the incident's real data class: {rendered}"
    );
}
