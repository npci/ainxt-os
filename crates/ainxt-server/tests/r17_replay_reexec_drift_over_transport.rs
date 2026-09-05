// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! GAP6 replay-reexec-presence — `POST /v1/replay/reexecute` + `POST /v1/replay/drift` over the REAL
//! served daemon transport, through the SAME durable `SessionStore` `/v1/replay/step` reads.
//!
//! `ainxt-replay`'s own `tests/r12_data_surfaces.rs` proved `ReExecRequest`/`re_execute_persisted_req`/
//! `drift_report_persisted` at the crate level, but nothing in the composition root
//! (`ainxt-runtimed`) or the served transport (`ainxt-server`) ever called them — a canary/
//! auto-rollback gate could never actually ask the SHIPPED DAEMON "did this turn's output drift since
//! it was recorded?" via HTTP. This test proves the real served route, and — per the gap's own
//! requirement — that the drift oracle reflects a REAL difference driven by a LIVE CONFIG CHANGE since
//! the original recording (a swapped system prompt), not merely "any re-execution looks different by
//! construction":
//!
//!   1. Turn `a1` was recorded under system prompt `SP-v1`. The live daemon's injected `ReExecutor`
//!      (the deployment-swappable seam behind `POST /v1/replay/reexecute`) now runs under `SP-v2` (the
//!      prompt changed since recording). Re-executing `a1` forks `a1re`, durably, off the SAME store;
//!      the drift oracle reports `drifted: true` because the two texts differ ONLY in the system-prompt
//!      component — proving the drift signal tracks the live config change, not just re-exec-vs-original
//!      text formatting.
//!   2. Turn `a2` was recorded under `SP-v2` (i.e. no config change happened for it) — re-executing it
//!      against the SAME live `SP-v2` executor produces byte-identical text, so the oracle reports
//!      `drifted: false`. This rules out "the oracle always says drifted" as an explanation for (1).
//!   3. A non-participant is refused (403) on both routes, and refusal persists nothing.
//!
//! FAIL-BEFORE: `/v1/replay/reexecute` and `/v1/replay/drift` did not exist as routes (404 on any
//! daemon build). PASS-AFTER: both are live on `app_full_ext`, backed by the SAME `SessionStore`
//! `/v1/replay/step` reads, with a deployment-injectable `ReExecutor` (this test injects a
//! config-aware fake standing in for "the live model", instead of the shipped offline
//! `DeterministicReplayExecutor` default — proving the seam is genuinely swappable end-to-end).

use std::sync::Arc;

use ainxt_eventlog::{EventLog, JsonlEventLog};
use ainxt_protocol::Event;
use ainxt_replay::{
    DataClass, EventKind, FrozenTurnInputs, InMemorySessionStore, ReExecEvent, ReExecutor,
    SessionRecording, SessionStore, TurnRole,
};
use ainxt_runtime::engine_with_defaults;
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_server::{app_full_ext, FullApp, FullAppExt, TrustedGatewayAuth};
use ainxt_session::{SessionConfig, SessionManager};
use tokio::sync::mpsc;

struct MockProvider;
impl Provider for MockProvider {
    fn id(&self) -> &str {
        "mock"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, _prompt: &str) -> mpsc::Receiver<Event> {
        let (tx, rx) = mpsc::channel(8);
        tokio::spawn(async move {
            let _ = tx.send(Event::TextDelta("hi".to_string())).await;
            let _ = tx.send(Event::Done).await;
        });
        rx
    }
}

fn manager() -> Arc<SessionManager> {
    let mut router = ModelRouter::new();
    router.register(Box::new(MockProvider));
    Arc::new(SessionManager::new(
        Arc::new(engine_with_defaults(router)),
        SessionConfig::default(),
    ))
}

fn temp_log_dir(tag: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("ainxt-r17-reexec-{tag}-{nanos}"))
}

/// A fake "live model" `ReExecutor`: its output is a function of the CURRENT (live) system prompt this
/// executor was built with PLUS the turn's frozen prompt — standing in for a real provider-backed
/// executor whose answer depends on whatever system prompt the deployment currently has configured.
/// Deterministic and offline (no I/O), so the test is not flaky, while still modeling "the live config
/// can differ from what was frozen at recording time".
struct ConfigAwareExecutor {
    live_system_prompt: &'static str,
}

impl ReExecutor for ConfigAwareExecutor {
    fn re_execute(&self, frozen: &FrozenTurnInputs) -> Vec<ReExecEvent> {
        vec![ReExecEvent {
            kind: EventKind::TextDelta,
            data_class: DataClass::Internal,
            text: format!(
                "[answer under system_prompt={}] {}",
                self.live_system_prompt, frozen.prompt
            ),
        }]
    }
}

/// Seed a durable session (participants priya/arun) with TWO already-answered assistant turns:
/// * `a1` (child of `u1`) was recorded under system prompt `SP-v1`.
/// * `a2` (child of `u2`) was recorded under system prompt `SP-v2`.
/// Both carry frozen inputs (required for re-execution) whose `prompt` distinguishes them so the
/// re-executor's output for each is independently verifiable.
fn seed_store() -> Arc<InMemorySessionStore> {
    let store = Arc::new(InMemorySessionStore::new());
    let mut rec = SessionRecording::new("s1", &["priya", "arun"]);

    rec.append_root_turn("u1", TurnRole::User, "priya", 100)
        .unwrap();
    rec.record_event(
        "u1",
        EventKind::TextDelta,
        DataClass::Internal,
        "compute settlement",
        101,
    )
    .unwrap();
    rec.append_turn("a1", "u1", TurnRole::Assistant, "assistant", 110)
        .unwrap();
    rec.record_event(
        "a1",
        EventKind::TextDelta,
        DataClass::Internal,
        "[answer under system_prompt=SP-v1] compute settlement",
        120,
    )
    .unwrap();
    rec.set_frozen(
        "a1",
        FrozenTurnInputs {
            prompt: "compute settlement".into(),
            model: "claude-sonnet-4-6".into(),
            params: "temp=0".into(),
            seed: 7,
        },
    )
    .unwrap();

    rec.append_root_turn("u2", TurnRole::User, "arun", 200)
        .unwrap();
    rec.record_event(
        "u2",
        EventKind::TextDelta,
        DataClass::Internal,
        "compute payout",
        201,
    )
    .unwrap();
    rec.append_turn("a2", "u2", TurnRole::Assistant, "assistant", 210)
        .unwrap();
    rec.record_event(
        "a2",
        EventKind::TextDelta,
        DataClass::Internal,
        "[answer under system_prompt=SP-v2] compute payout",
        220,
    )
    .unwrap();
    rec.set_frozen(
        "a2",
        FrozenTurnInputs {
            prompt: "compute payout".into(),
            model: "claude-sonnet-4-6".into(),
            params: "temp=0".into(),
            seed: 8,
        },
    )
    .unwrap();

    store.save(&rec.to_durable()).unwrap();
    store
}

async fn serve(store: Arc<InMemorySessionStore>, live_system_prompt: &'static str) -> String {
    let dir = temp_log_dir("evt");
    let event_log: Arc<dyn EventLog> = Arc::new(JsonlEventLog::open(&dir).expect("open log"));
    let cfg = FullApp {
        manager: manager(),
        auth: Arc::new(TrustedGatewayAuth),
        event_log,
        control_plane_sha: "sha-r17".to_string(),
        serving: None,
        graph: None,
        ledger_schema: None,
        harness: None,
    };
    let ext = FullAppExt {
        replay_store: Some(store as Arc<dyn SessionStore>),
        // The daemon's live-model seam: the deployment's CURRENT config, which may have drifted from
        // whatever was frozen into any given turn at recording time (exactly what a canary/
        // auto-rollback gate needs to detect).
        reexec_executor: Some(Arc::new(ConfigAwareExecutor { live_system_prompt })),
        ..FullAppExt::default()
    };
    let router = app_full_ext(cfg, ext);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    format!("http://{addr}")
}

#[tokio::test(flavor = "multi_thread")]
async fn r17_reexec_over_transport_forks_durable_branch_and_drift_tracks_live_config_change() {
    let store = seed_store();
    // The live daemon now runs under SP-v2 — `a1` was recorded under SP-v1 (config changed since
    // recording); `a2` was recorded under SP-v2 (no config change for it).
    let base = serve(store.clone(), "SP-v2").await;
    let client = reqwest::Client::new();

    // --- (1) Re-execute `a1` (config CHANGED since recording) --------------------------------------
    let resp = client
        .post(format!("{base}/v1/replay/reexecute"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header("x-ainxt-user", "priya")
        .body(
            serde_json::json!({"session": "s1", "target_turn": "a1", "new_id": "a1re"}).to_string(),
        )
        .send()
        .await
        .expect("send");
    assert!(resp.status().is_success(), "reexec a1: {}", resp.status());
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["applied"], true);
    assert_eq!(body["new_turn_id"], "a1re");

    // Durable: an independent load sees the fork as a SIBLING of `a1` (never overwriting it).
    let after = SessionRecording::from_durable(store.load("s1").unwrap().unwrap());
    assert!(after.tree().turn("a1").is_some(), "original a1 untouched");
    assert_eq!(
        after.tree().turn("a1re").unwrap().parent.as_deref(),
        Some("u1")
    );

    // The drift oracle over transport: original vs re-exec for a1.
    let resp = client
        .post(format!("{base}/v1/replay/drift"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header("x-ainxt-user", "priya")
        .body(
            serde_json::json!({"session": "s1", "original_turn": "a1", "reexec_turn": "a1re"})
                .to_string(),
        )
        .send()
        .await
        .expect("send");
    assert!(
        resp.status().is_success(),
        "drift a1/a1re: {}",
        resp.status()
    );
    let report: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(
        report["original_text"],
        "[answer under system_prompt=SP-v1] compute settlement"
    );
    assert_eq!(
        report["reexec_text"],
        "[answer under system_prompt=SP-v2] compute settlement"
    );
    assert_eq!(
        report["drifted"], true,
        "the live system prompt changed since a1 was recorded"
    );

    // --- (2) Re-execute `a2` (config UNCHANGED since recording) — the drift oracle must say NO drift,
    // proving the true positive above is a real signal, not "any re-exec always drifts". -------------
    let resp = client
        .post(format!("{base}/v1/replay/reexecute"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header("x-ainxt-user", "arun")
        .body(
            serde_json::json!({"session": "s1", "target_turn": "a2", "new_id": "a2re"}).to_string(),
        )
        .send()
        .await
        .expect("send");
    assert!(resp.status().is_success(), "reexec a2: {}", resp.status());

    let resp = client
        .post(format!("{base}/v1/replay/drift"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header("x-ainxt-user", "arun")
        .body(
            serde_json::json!({"session": "s1", "original_turn": "a2", "reexec_turn": "a2re"})
                .to_string(),
        )
        .send()
        .await
        .expect("send");
    assert!(
        resp.status().is_success(),
        "drift a2/a2re: {}",
        resp.status()
    );
    let report: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(report["original_text"], report["reexec_text"]);
    assert_eq!(
        report["drifted"], false,
        "no live config change happened for a2 since recording"
    );

    // --- (3) RBAC: a non-participant is refused on both routes, and refusal persists nothing. -------
    let resp = client
        .post(format!("{base}/v1/replay/reexecute"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header("x-ainxt-user", "mallory")
        .body(
            serde_json::json!({"session": "s1", "target_turn": "a1", "new_id": "a1-evil"})
                .to_string(),
        )
        .send()
        .await
        .expect("send");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::FORBIDDEN,
        "non-participant reexec refused"
    );
    let after = SessionRecording::from_durable(store.load("s1").unwrap().unwrap());
    assert!(
        after.tree().turn("a1-evil").is_none(),
        "refused reexec persisted nothing"
    );

    let resp = client
        .post(format!("{base}/v1/replay/drift"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header("x-ainxt-user", "mallory")
        .body(
            serde_json::json!({"session": "s1", "original_turn": "a1", "reexec_turn": "a1re"})
                .to_string(),
        )
        .send()
        .await
        .expect("send");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::FORBIDDEN,
        "non-participant drift-read refused"
    );
}
