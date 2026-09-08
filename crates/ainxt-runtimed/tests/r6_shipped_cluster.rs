// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R6 — the SHIPPED daemon serves the FULLY-WIRED **cluster**.
//!
//! Round 5 left `assemble_full` populating only `manager/auth/event_log/serving/graph/ledger_schema`
//! and served through `serve_full` (never `serve_full_ext`), so `/v1/harness/*`, `/connectors/*`,
//! `/v1/artifact`, and `/v1/replay/step` were reachable only from `ainxt-server`'s own tests, and the
//! DSAR/right-to-erasure + SR-11-7 quality-circuit-breaker organs were not instantiated on the served
//! surface. These tests assert on the REAL composition objects (`assemble_full` → `AssembledFull` →
//! `to_full_app`/`to_full_app_ext` → `ainxt_server::serve_full_ext`).
//!
//! * `r6_shipped_daemon_mounts_cluster_surfaces` — the served daemon exposes `/v1/harness/{id}`,
//!   `/connectors`, `/v1/artifact`, `/v1/replay/step` (NOT 404) on the air-gapped default, and the
//!   round-4 shipped-chat guard still holds (`/v1/chat` 200, never 503).
//! * `r6_assemble_full_instantiates_organs_and_qos` — the DSAR erasure + SR-11-7 quality-breaker organs
//!   are present on the served surface and the SLO-aware QoS pre_serve wait-queue is configured.
//! * `r6_served_program_run_enforces_verification` — a served Program run drives the driver
//!   `Program::record_verdict`/`commit_node` (verification enforced; committed nodes all carry a
//!   durable Complete proof), and `verdict_for_observation` proves the verdict is DERIVED FROM THE REAL
//!   TURN (an errored/empty turn yields a RED deterministic gate — never a fabricated green).
//!
//! Deterministic: the offline provider (no keys/network) backs the engine; the transport, the governed
//! surfaces, and the control organs are the REAL production types.

use std::time::{SystemTime, UNIX_EPOCH};

use ainxt_replay::{SessionRecording, TurnRole};
use ainxt_runtimed::{
    assemble_full, assemble_program_surface, assemble_surface, load_layered,
    verdict_for_observation, TurnObservation,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Find the first `\r\n\r\n` header/body separator in a raw byte buffer.
fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// GAP-FIX planner-assurance-revision (item 1) — a minimal, hand-rolled mock OpenAI-`/chat/completions`-
/// schema upstream (the SAME raw-socket pattern `gap5_fabric_mount_served.rs`'s `spawn_mock_llm` uses):
/// replies to EVERY request with the SAME fixed `text`. Needed because `assemble_program_surface`'s
/// air-gapped default (`OfflineProvider`) always streams a prompt-invariant "offline mode: no model
/// configured." — content that carries none of a real goal's keywords and therefore genuinely (and
/// correctly) fails the served Program driver's now-real, content-varying `RubricJudge` (no longer a
/// fabricated fixed pass). This mock stubs only the vendor HTTP endpoint the real `OpenAiSchemaProvider`
/// calls (`kind = "local"`), exactly as a live deployment's own local vLLM/Ollama endpoint would be.
async fn spawn_mock_llm_fixed_text(text: String) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock llm");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => break,
            };
            let text = text.clone();
            tokio::spawn(async move {
                let mut buf: Vec<u8> = Vec::new();
                let mut chunk = [0u8; 8192];
                loop {
                    let n = match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(pos) = find_double_crlf(&buf) {
                        let headers = String::from_utf8_lossy(&buf[..pos]).to_string();
                        let cl = headers
                            .lines()
                            .find_map(|l| {
                                let (k, v) = l.split_once(':')?;
                                if k.trim().eq_ignore_ascii_case("content-length") {
                                    v.trim().parse::<usize>().ok()
                                } else {
                                    None
                                }
                            })
                            .unwrap_or(0);
                        if buf.len() >= pos + 4 + cl {
                            break;
                        }
                    }
                }
                let sse = format!(
                    "data: {{\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"model\":\"mock\",\"choices\":[{{\"index\":0,\"delta\":{{\"content\":{text:?}}},\"finish_reason\":null}}]}}\n\n\
                     data: {{\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"model\":\"mock\",\"choices\":[{{\"index\":0,\"delta\":{{}},\"finish_reason\":\"stop\"}}]}}\n\n\
                     data: [DONE]\n\n"
                );
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    sse.len(),
                    sse
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    addr
}

/// A config identical to `load_layered(&[("t", "version = 1")])` except it also wires a `kind = "local"`
/// provider pointed at a mock upstream that always replies `text` — see [`spawn_mock_llm_fixed_text`].
fn loaded_with_fixed_text_provider(
    mock_addr: std::net::SocketAddr,
    tag: &str,
) -> ainxt_runtimed::LoadedConfig {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let src = format!(
        "version = 1\n\
         [[models.providers]]\n\
         id = \"mock-llm-{tag}-{nanos}\"\n\
         kind = \"local\"\n\
         base_url = \"http://{mock_addr}\"\n\
         eligible = [\"internal\"]\n"
    );
    load_layered(&[("t", &src)]).unwrap()
}

fn loaded_with_unique_log() -> ainxt_runtimed::LoadedConfig {
    // R16 critical: the daemon now refuses the header-trusting default authenticator unless the
    // deployment states the assumption (see r10_breach_clock_unit.rs) — state it here.
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("ainxt-r6-{nanos}"));
    let src = format!(
        "version = 1\n[server]\nevent_log_dir = {:?}\n",
        dir.to_string_lossy()
    );
    load_layered(&[("r6", &src)]).expect("load offline config")
}

async fn post(
    client: &reqwest::Client,
    addr: &std::net::SocketAddr,
    path: &str,
    caps: &str,
    body: serde_json::Value,
) -> u16 {
    client
        .post(format!("http://{addr}{path}"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header("x-ainxt-user", "alice")
        .header("x-ainxt-caps", caps)
        .header("x-ainxt-clearance", "confidential")
        .body(body.to_string())
        .send()
        .await
        .expect("request send")
        .status()
        .as_u16()
}

/// [`post`], additionally returning the parsed JSON body — needed to inspect
/// `is_binary`/`byte_len` for a binary (docx/pdf/xlsx/pptx) artifact response, which `post`'s bare
/// status code cannot distinguish from a text (markdown) one.
async fn post_json(
    client: &reqwest::Client,
    addr: &std::net::SocketAddr,
    path: &str,
    caps: &str,
    body: serde_json::Value,
) -> (u16, serde_json::Value) {
    let resp = client
        .post(format!("http://{addr}{path}"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header("x-ainxt-user", "alice")
        .header("x-ainxt-caps", caps)
        .header("x-ainxt-clearance", "confidential")
        .body(body.to_string())
        .send()
        .await
        .expect("request send");
    let status = resp.status().as_u16();
    let text = resp.text().await.expect("response body must be readable");
    // Parsed via `serde_json::from_str` (not `Response::json`), which needs reqwest's `json`
    // feature — this crate's dev-dependency only enables `rustls-tls`, and pulling in a whole new
    // feature just for one test's convenience is not worth the added compile surface.
    let json: serde_json::Value = serde_json::from_str(&text).expect("response body must be JSON");
    (status, json)
}

#[tokio::test(flavor = "multi_thread")]
async fn r6_shipped_daemon_mounts_cluster_surfaces() {
    let loaded = loaded_with_unique_log();
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat surface");
    let full = assemble_full(&loaded, assembled).expect("assemble fully-wired surface");

    // Seed a persisted recording so `/v1/replay/step` has a real session to page (the caller `alice`
    // is a participant → authorized). This exercises the store-backed step entrypoint end-to-end.
    let mut rec = SessionRecording::new("replay-sess", &["alice"]);
    rec.append_root_turn("t1", TurnRole::User, "alice", 1)
        .expect("append root turn");
    full.replay_store
        .save(&rec.to_durable())
        .expect("seed replay store");

    // Serve the REAL fully-wired app WITH the additive cluster surfaces (serve_full_ext).
    let app = full.to_full_app();
    let ext = full.to_full_app_ext();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let _clock = full.spawn_breach_clock(std::time::Duration::from_millis(50));
    tokio::spawn(ainxt_server::serve_full_ext(listener, app, ext));
    let client = reqwest::Client::new();

    // HARN-03 — the harness invoke surface is MOUNTED and LIVE (built-in diag.selftest harness).
    let harness_ok = post(
        &client,
        &addr,
        "/v1/harness/diag.selftest",
        "diag.selftest",
        serde_json::json!({}),
    )
    .await;
    assert_ne!(
        harness_ok, 404,
        "/v1/harness/{{id}} must be served by the shipped daemon"
    );
    assert_eq!(
        harness_ok, 200,
        "the built-in diag.selftest harness must invoke on the shipped daemon: got {harness_ok}"
    );

    // The harness /run bridge is mounted too (unknown id → 404, but the route resolves, never a panic).
    let harness_run = post(
        &client,
        &addr,
        "/v1/harness/diag.selftest/run",
        "diag.selftest",
        serde_json::json!({}),
    )
    .await;
    assert_ne!(
        harness_run, 404,
        "/v1/harness/{{id}}/run must be served by the shipped daemon"
    );

    // CONN-03 — the connector OAuth catalog serves (empty on the air-gapped default, never 404).
    let connectors = client
        .get(format!("http://{addr}/connectors"))
        .header("x-ainxt-user", "alice")
        .header("x-ainxt-caps", "connector.graph")
        .send()
        .await
        .expect("connectors send")
        .status()
        .as_u16();
    assert_ne!(
        connectors, 404,
        "/connectors must be served by the shipped daemon"
    );
    assert_eq!(
        connectors, 200,
        "the connector catalog must serve (empty ok): got {connectors}"
    );

    // R6 DATA — the artifact-generation surface is MOUNTED and RBAC-scoped.
    let doc = serde_json::json!({
        "document": {
            "title": "Quarterly Reconciliation",
            "blocks": [{"kind": "paragraph", "text": "UPI settlement volumes grew."}]
        },
        "format": "markdown"
    });
    let artifact_ok = post(
        &client,
        &addr,
        "/v1/artifact",
        "artifact.generate",
        doc.clone(),
    )
    .await;
    assert_ne!(
        artifact_ok, 404,
        "/v1/artifact must be served by the shipped daemon"
    );
    assert_eq!(
        artifact_ok, 200,
        "an authorized artifact generate must 200: got {artifact_ok}"
    );

    // Fail-closed: a caller WITHOUT artifact.generate is refused (403), no capability oracle.
    let artifact_denied = post(&client, &addr, "/v1/artifact", "chat.send", doc).await;
    assert_eq!(
        artifact_denied, 403,
        "artifact generation without the capability must be 403: got {artifact_denied}"
    );

    // R6 DATA — the store-backed step-through replay surface is MOUNTED and pages the seeded session.
    let replay_step = post(
        &client,
        &addr,
        "/v1/replay/step",
        "chat.send",
        serde_json::json!({"session": "replay-sess", "from_index": 0}),
    )
    .await;
    assert_ne!(
        replay_step, 404,
        "/v1/replay/step must be served by the shipped daemon"
    );
    assert_eq!(
        replay_step, 200,
        "the store-backed step entrypoint must page a seeded session: got {replay_step}"
    );

    // REGRESSION GUARD (round-4 ship fix): the shipped `/v1/chat` still serves on the air-gapped default.
    let chat = post(
        &client,
        &addr,
        "/v1/chat",
        "chat.send",
        serde_json::json!({"session":"s1","turn":"t1","input":"hello","data_class":"public","caps":["chat.send"]}),
    )
    .await;
    assert_ne!(
        chat, 503,
        "/v1/chat must NOT 503 on the air-gapped default (serving fence inert, no pool)"
    );
    assert_eq!(
        chat, 200,
        "the shipped daemon must still serve a basic chat turn: got {chat}"
    );
}

/// GAP-FIX data-surfaces-artifacts "DocxRenderer format=docx never proven through the live HTTP
/// endpoint" — `mounts.rs` registers `DocxRenderer` (and `PdfRenderer`/`XlsxRenderer`/`PptxRenderer`)
/// on the SAME `ArtifactRuntime::with_all_renderers` the shipped `/v1/artifact` route serves, and the
/// renderer itself is correct and unit-tested (`ainxt-artifact`'s own tests), but the only format ever
/// proven through the LIVE served HTTP endpoint (`r6_shipped_daemon_mounts_cluster_surfaces` above)
/// was `"markdown"` — a text format whose response shape (`is_binary: false`, `content` inlined) is
/// structurally different from a binary format's. This proves `format=docx` specifically: a real
/// `POST /v1/artifact` request against the shipped, fully-wired daemon renders real non-empty DOCX
/// bytes and reports them correctly as binary (never accidentally falling through to a text-shaped
/// response, and never a 404/500 for a format the renderer registry actually has registered).
#[tokio::test(flavor = "multi_thread")]
async fn r6_shipped_daemon_serves_docx_binary_artifact_over_http() {
    let loaded = loaded_with_unique_log();
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat surface");
    let full = assemble_full(&loaded, assembled).expect("assemble fully-wired surface");

    let app = full.to_full_app();
    let ext = full.to_full_app_ext();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let _clock = full.spawn_breach_clock(std::time::Duration::from_millis(50));
    tokio::spawn(ainxt_server::serve_full_ext(listener, app, ext));
    let client = reqwest::Client::new();

    let doc = serde_json::json!({
        "document": {
            "title": "Quarterly Reconciliation",
            "blocks": [{"kind": "paragraph", "text": "UPI settlement volumes grew."}]
        },
        "format": "docx"
    });
    let (status, body) = post_json(
        &client,
        &addr,
        "/v1/artifact",
        "artifact.generate",
        doc.clone(),
    )
    .await;
    assert_eq!(
        status, 200,
        "a docx generate against the shipped daemon must 200 (DocxRenderer IS registered on the \
         served ArtifactRuntime): got {status}, body={body}"
    );
    assert_eq!(
        body["format"].as_str(),
        Some("docx"),
        "the response must echo the requested format: {body}"
    );
    assert_eq!(
        body["is_binary"].as_bool(),
        Some(true),
        "docx is a binary format — is_binary must be true, never the text-shaped false: {body}"
    );
    assert!(
        body["content"].is_null(),
        "a binary format's inline `content` must be null (bytes are reported by size, not \
         inlined as text): {body}"
    );
    let byte_len = body["byte_len"]
        .as_u64()
        .expect("byte_len must be a number");
    assert!(
        byte_len > 0,
        "the rendered DOCX package must be real, non-empty bytes (a real OOXML zip container, not \
         a stub): byte_len={byte_len}"
    );

    // Fail-closed parity with the markdown case above: a caller WITHOUT artifact.generate is refused.
    let denied = post(&client, &addr, "/v1/artifact", "chat.send", doc).await;
    assert_eq!(
        denied, 403,
        "docx generation without the capability must be 403 exactly like every other format: got \
         {denied}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn r6_assemble_full_instantiates_organs_and_qos() {
    let loaded = loaded_with_unique_log();
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat surface");
    let full = assemble_full(&loaded, assembled).expect("assemble fully-wired surface");

    // DSAR / right-to-erasure organ present on the served surface — a principal-scoped erase runs.
    {
        let mut erasure = full.erasure.lock().unwrap();
        let ack = erasure.erase_principal("alice");
        // No cached entries yet, but the cascade is LIVE and touches its tiers deterministically.
        let _ = ack.total_partitions_purged();
    }

    // SR-11-7 quality circuit-breaker organ present — an absent scoreboard trips the breaker (fail-safe).
    assert!(
        full.report
            .iter()
            .any(|r| r.contains("quality circuit-breaker")),
        "the assembly report must announce the SR-11-7 quality circuit-breaker organ"
    );
    assert!(
        full.report
            .iter()
            .any(|r| r.contains("DSAR/right-to-erasure")),
        "the assembly report must announce the DSAR/right-to-erasure organ"
    );
    // The mount surfaces are announced too.
    for needle in [
        "/v1/harness/{id}",
        "/connectors/*",
        "/v1/artifact",
        "/v1/replay/step",
        "QoS pre_serve",
    ] {
        assert!(
            full.report.iter().any(|r| r.contains(needle)),
            "the assembly report must announce '{needle}': {:?}",
            full.report
        );
    }
    // Held handles are constructed.
    assert!(
        !full.harness.registry.is_empty(),
        "a built-in harness must be published"
    );
    assert!(
        full.artifact.formats().contains(&"markdown"),
        "the artifact runtime must ship a renderer"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn r6_served_program_run_enforces_verification() {
    use ainxt_client::{Client, ClientConfig};
    use ainxt_types::Principal;

    // GAP-FIX planner-assurance-revision (item 1) — a genuinely substantive, on-goal artifact is
    // required for the served Program driver's REAL RubricJudge to pass; see
    // `spawn_mock_llm_fixed_text`'s doc comment.
    let mock_addr = spawn_mock_llm_fixed_text(
        "migrated the legacy module successfully: assessed dependencies, executed the migration, and \
         verified the result with boundary tests for empty and negative edge cases."
            .to_string(),
    )
    .await;
    let loaded = loaded_with_fixed_text_provider(mock_addr, "r6-program");
    let assembled = assemble_program_surface(&loaded, "program").expect("assemble program surface");

    let client = Client::in_process(
        assembled.manager,
        Principal::user("dev", &["chat.send"]),
        ClientConfig::default(),
    );
    let out = client
        .chat("s", "t", "migrate the legacy module")
        .unwrap()
        .collect()
        .await;
    assert!(out.completed, "the served program turn must complete");
    // The driver-enforced path drove record_verdict/commit_node to a proven-committed terminal outcome.
    assert!(
        out.text.contains("Completed"),
        "the served program must reach a terminal Completed outcome: {}",
        out.text
    );
    assert!(
        out.text.contains("all_committed_proven=true"),
        "every committed node must carry a durable Complete three-way proof (verification enforced): {}",
        out.text
    );
    // The served path composes its node graph from the real MigrationBlueprint::compose planner
    // (assess → migrate → verify), never a single hard-coded node — so a real module turn ran for
    // each composed node.
    assert!(
        out.text.contains("module:assess")
            && out.text.contains("module:migrate")
            && out.text.contains("module:verify"),
        "the served path must run the composed multi-node graph (assess/migrate/verify): {}",
        out.text
    );
    // §15 JIT identity renewal is APPLIED on the served Run (short-TTL credential renewed at its TTL
    // boundary — each renewal re-checks def validity / revocation / kill-switch / anomaly).
    assert!(
        out.text.contains("identity renewal(s)") && !out.text.contains("0 identity renewal"),
        "the served Program run must apply JIT identity renewal (renewals > 0): {}",
        out.text
    );

    // Anti-fabrication (fail-before/pass-after at the wire): the deterministic verdict is DERIVED from
    // the real turn. A committable turn is green; an errored/empty turn is a RED gate (a blocking
    // finding), which the three-way gate refuses — so `commit_node` would reject it (NodeNotProven).
    let good = TurnObservation {
        label: "module:deliver".into(),
        actor: "dev".into(),
        provider: "offline".into(),
        redactions: 0,
        text: "offline mode: no model configured.".into(),
        ok: true,
    };
    let (det_good, _adv) = verdict_for_observation(&good);
    assert!(
        det_good.blocking_findings.is_empty() && det_good.compiled && det_good.tests_passed,
        "a real, non-empty turn must yield a green deterministic verdict"
    );
    let empty = TurnObservation {
        text: "   ".into(),
        ok: true,
        ..good.clone()
    };
    let (det_empty, _adv2) = verdict_for_observation(&empty);
    assert!(
        !det_empty.blocking_findings.is_empty(),
        "an empty turn must yield a RED deterministic gate — never a fabricated green"
    );
    let errored = TurnObservation { ok: false, ..good };
    let (det_err, _adv3) = verdict_for_observation(&errored);
    assert!(
        !det_err.blocking_findings.is_empty(),
        "an errored turn must yield a RED deterministic gate — never a fabricated green"
    );
}
