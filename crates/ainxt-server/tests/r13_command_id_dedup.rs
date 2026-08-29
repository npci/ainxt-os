// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! r13_command_id_dedup — GAP-AUDIT transport-daemon #1/#2 (second half): `command_id`
//! (`ainxt_protocol::CommandEnvelope`'s own exactly-once dedup key, ADR-013) was defined but never
//! read anywhere in `command_handler` — a client retry after a dropped ack (e.g. a `session.fork` or
//! `approval.respond`) would re-apply the command a second time. `ainxt_serving::idempotency::IdempotencyLedger`
//! already existed for inference-call exactly-once billing; it's now reused to dedup on `command_id`.
//!
//! This drives `POST /v1/command` twice with the SAME `command_id` and asserts the second call is an
//! idempotent replay (never re-dispatched), while a THIRD call with a different `command_id` still
//! dispatches normally — proving dedup is scoped to the key, not a global "second call ever" latch.

use ainxt_protocol::Event;
use ainxt_runtime::engine_with_defaults;
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_server::{serve_with_auth, TrustedGatewayAuth};
use ainxt_session::{SessionConfig, SessionManager};
use ainxt_types::DataClass;
use std::sync::Arc;
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

async fn spawn() -> String {
    let mut router = ModelRouter::new();
    router.register(Box::new(MockProvider));
    let manager = Arc::new(SessionManager::new(
        Arc::new(engine_with_defaults(router)),
        SessionConfig::default(),
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(serve_with_auth(
        listener,
        manager,
        Arc::new(TrustedGatewayAuth),
    ));
    format!("http://{addr}")
}

async fn open(base: &str, body: serde_json::Value) -> serde_json::Value {
    let client = reqwest::Client::new();
    let text = client
        .post(format!("{base}/v1/command"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body.to_string())
        .send()
        .await
        .expect("send")
        .text()
        .await
        .expect("body");
    serde_json::from_str(&text).unwrap_or(serde_json::Value::Null)
}

#[tokio::test(flavor = "multi_thread")]
async fn r13_repeated_command_id_short_circuits_to_an_idempotent_replay() {
    let base = spawn().await;

    let first = open(
        &base,
        serde_json::json!({
            "session": "s1", "type": "session.open", "profile_id": "chat",
            "command_id": "cmd-abc",
        }),
    )
    .await;
    assert_eq!(first["accepted"], true);
    assert!(
        first.get("idempotent_replay").is_none(),
        "the FIRST call with a command_id must dispatch normally: {first}"
    );

    let second = open(
        &base,
        serde_json::json!({
            "session": "s1", "type": "session.open", "profile_id": "chat",
            "command_id": "cmd-abc",
        }),
    )
    .await;
    assert_eq!(
        second["idempotent_replay"], true,
        "a REPEATED command_id must short-circuit to an idempotent replay, not re-dispatch: {second}"
    );

    // A different command_id is unaffected — dedup is scoped to the key, not a global latch.
    let third = open(
        &base,
        serde_json::json!({
            "session": "s1", "type": "session.open", "profile_id": "chat",
            "command_id": "cmd-xyz",
        }),
    )
    .await;
    assert_eq!(third["accepted"], true);
    assert!(
        third.get("idempotent_replay").is_none(),
        "a DIFFERENT command_id must dispatch normally: {third}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn r13_omitted_command_id_is_unaffected_every_call_dispatches() {
    let base = spawn().await;
    // No command_id at all: pre-existing behavior, every call dispatches (no dedup applied).
    for _ in 0..3 {
        let resp = open(
            &base,
            serde_json::json!({"session": "s2", "type": "session.open", "profile_id": "chat"}),
        )
        .await;
        assert_eq!(resp["accepted"], true);
        assert!(resp.get("idempotent_replay").is_none());
    }
}
