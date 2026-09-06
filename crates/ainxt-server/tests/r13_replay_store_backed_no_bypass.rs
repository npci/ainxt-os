// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R13 (data-surfaces-artifacts, HIGH) — `POST /v1/replay` no longer bypasses the durable SessionStore
//! with a client-supplied log + self-asserted participant list.
//!
//! The audit found the served `/v1/replay` handler applied the branch/edit/stop/steer op over the
//! renderer's OWN `log` projection and OWN `participants` roster — so a caller could (a) fabricate a
//! history to apply the op against and (b) self-assert themselves into the participant list to defeat
//! RBAC. This test wires a real `InMemorySessionStore` into the fully-wired daemon and proves:
//!
//!   1. the turn TREE is loaded from the durable store, not the client `log` (a branch lands off a turn
//!      that exists ONLY in the store while the client sends a garbage/empty log), and
//!   2. the authoritative participant set is loaded from the store, not the request: a real participant
//!      is authorized *despite* sending a bogus roster, while a non-participant who SELF-ASSERTS herself
//!      into `participants` is still refused 403 (the roster cannot defeat RBAC), and
//!   3. the branch is DURABLE (a fresh load through the store sees it).
//!
//! FAIL-BEFORE: the handler used the client roster, so the self-asserting non-participant would be
//! authorized (200). PASS-AFTER: 403 for her, 200 for the real participant, durable branch. Offline,
//! deterministic, no live DB (the `InMemorySessionStore` round-trips the exact `DurableSession` the
//! production Postgres store does — that binding is the infra_gated seam).

use std::sync::Arc;

use ainxt_eventlog::{EventLog, JsonlEventLog};
use ainxt_protocol::Event;
use ainxt_replay::{EventKind, InMemorySessionStore, SessionRecording, SessionStore, TurnRole};
use ainxt_runtime::engine_with_defaults;
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_server::{app_full_ext, FullApp, FullAppExt, TrustedGatewayAuth};
use ainxt_session::{SessionConfig, SessionManager};
use ainxt_types::DataClass;
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
    std::env::temp_dir().join(format!("ainxt-r13-replay-{tag}-{nanos}"))
}

/// Seed a durable session whose authoritative participants are `priya`/`arun` and whose tree carries a
/// user turn `u1` + assistant turn `a1` — the branch target lives ONLY here, never in a client log.
fn seed_store() -> Arc<InMemorySessionStore> {
    let store = Arc::new(InMemorySessionStore::new());
    let mut rec = SessionRecording::new("s1", &["priya", "arun"]);
    rec.append_root_turn("u1", TurnRole::User, "priya", 1000)
        .unwrap();
    rec.record_event(
        "u1",
        EventKind::TextDelta,
        DataClass::Internal,
        "compute settlement",
        1001,
    )
    .unwrap();
    rec.append_turn("a1", "u1", TurnRole::Assistant, "assistant", 1100)
        .unwrap();
    rec.record_event(
        "a1",
        EventKind::TextDelta,
        DataClass::Internal,
        "the answer is 42",
        1200,
    )
    .unwrap();
    store.save(&rec.to_durable()).unwrap();
    store
}

async fn serve(store: Arc<InMemorySessionStore>) -> String {
    let dir = temp_log_dir("evt");
    let event_log: Arc<dyn EventLog> = Arc::new(JsonlEventLog::open(&dir).expect("open log"));
    let cfg = FullApp {
        manager: manager(),
        auth: Arc::new(TrustedGatewayAuth),
        event_log,
        control_plane_sha: "sha-r13".to_string(),
        serving: None,
        graph: None,
        ledger_schema: None,
        harness: None,
    };
    let ext = FullAppExt {
        replay_store: Some(store as Arc<dyn SessionStore>),
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
async fn r13_replay_uses_durable_store_tree_and_participants_not_client_supplied() {
    let store = seed_store();
    let base = serve(store.clone()).await;
    let client = reqwest::Client::new();

    // (1)+(2) A REAL participant (`priya`) branches off `a1` — a turn that exists ONLY in the durable
    // store. She sends a GARBAGE client log (empty) and a BOGUS participant roster (["nobody"]). If the
    // handler still trusted the client inputs, the branch would fail (a1 not in the empty log). It
    // succeeds because the tree + roster come from the store.
    let resp = client
        .post(format!("{base}/v1/replay"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header("x-ainxt-user", "priya")
        .body(
            serde_json::json!({
                "session": "s1",
                "type": "turn.branch",
                "from_turn_id": "a1",
                "new_turn_id": "b1",
                "label": "what-if",
                "participants": ["nobody"],
                "log": []
            })
            .to_string(),
        )
        .send()
        .await
        .expect("send");
    assert!(
        resp.status().is_success(),
        "a real store participant branches off a store-only turn despite a bogus client log+roster: {}",
        resp.status()
    );

    // (3) The branch is DURABLE: a fresh load through the store sees `b1` parented on `a1`.
    let reloaded = SessionRecording::from_durable(store.load("s1").unwrap().unwrap());
    let b1 = reloaded
        .tree()
        .turn("b1")
        .expect("branch durably persisted to the store");
    assert_eq!(
        b1.parent.as_deref(),
        Some("a1"),
        "branch parented on the store's turn"
    );

    // (2, sharp) A NON-participant (`mallory`) SELF-ASSERTS herself into `participants` — the exact
    // bypass the audit flagged. The store's authoritative roster (priya/arun) governs, so she is refused
    // 403 and never mutates the session.
    let resp = client
        .post(format!("{base}/v1/replay"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header("x-ainxt-user", "mallory")
        .body(
            serde_json::json!({
                "session": "s1",
                "type": "turn.stop",
                "turn_id": "a1",
                "participants": ["mallory"],
                "log": []
            })
            .to_string(),
        )
        .send()
        .await
        .expect("send");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::FORBIDDEN,
        "a self-asserted participant roster cannot defeat RBAC — the store's roster governs"
    );

    // The refused op left NO durable mutation: `a1` is not stopped.
    let after = SessionRecording::from_durable(store.load("s1").unwrap().unwrap());
    assert_ne!(
        after.tree().turn("a1").unwrap().status,
        ainxt_replay::TurnStatus::Stopped,
        "the refused non-participant stop never mutated the durable tree"
    );
}
