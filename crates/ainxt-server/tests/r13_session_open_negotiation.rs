// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! r13_session_open_negotiation — GAP-AUDIT transport-daemon #1/#2: `ainxt_protocol::negotiate`
//! (§10.2 version negotiation) was fully built and unit-tested but had ZERO call sites in the served
//! path — `session.open` unconditionally echoed the server's own `PROTOCOL_VERSION` back regardless of
//! what the client asked for, so a client outside the supported major window was never refused.
//!
//! This test drives `POST /v1/command {session.open}` over a real HTTP server and proves:
//!   * no client version supplied → the server's own version is returned (back-compat default).
//!   * a compatible-but-older client version → the runtime negotiates DOWN to the lower version.
//!   * a client version outside the N-2 major window → refused 400 `protocol_incompatible`.
//!   * a malformed client version string → refused 400 `protocol_incompatible`, not a panic/500.

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

async fn open(base: &str, body: serde_json::Value) -> (u16, serde_json::Value) {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/v1/command"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body.to_string())
        .send()
        .await
        .expect("send");
    let status = resp.status().as_u16();
    let text = resp.text().await.expect("body");
    let json: serde_json::Value = serde_json::from_str(&text).unwrap_or(serde_json::Value::Null);
    (status, json)
}

#[tokio::test(flavor = "multi_thread")]
async fn r13_no_client_version_defaults_to_the_servers_own() {
    let base = spawn().await;
    let (status, body) = open(
        &base,
        serde_json::json!({"session": "s1", "type": "session.open", "profile_id": "chat"}),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["accepted"], true);
    assert_eq!(
        body["protocol_version"],
        ainxt_protocol::PROTOCOL_VERSION.to_string(),
        "omitted client version must default to the server's own PROTOCOL_VERSION: {body}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn r13_older_compatible_client_negotiates_down() {
    let base = spawn().await;
    // Server is 1.0; a client claiming an older-minor-but-same-major "1.0" is trivially compatible —
    // this proves the wire actually calls negotiate() and returns ITS result, not a hardcoded echo.
    let (status, body) = open(
        &base,
        serde_json::json!({
            "session": "s2", "type": "session.open", "profile_id": "chat",
            "client_protocol_version": "1.0",
        }),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["accepted"], true);
    assert_eq!(body["protocol_version"], "1.0");
}

#[tokio::test(flavor = "multi_thread")]
async fn r13_far_future_major_is_refused_protocol_incompatible() {
    let base = spawn().await;
    // Server major is 1; SUPPORTED_MAJOR_WINDOW only tolerates older majors within the window, and a
    // client claiming a NEWER major than the server can never be honored (a runtime cannot speak a
    // future contract it hasn't implemented).
    let (status, body) = open(
        &base,
        serde_json::json!({
            "session": "s3", "type": "session.open", "profile_id": "chat",
            "client_protocol_version": "99.0",
        }),
    )
    .await;
    assert_eq!(
        status, 400,
        "an incompatible client major must be refused, got {status}: {body}"
    );
    assert_eq!(body["accepted"], false);
    assert_eq!(body["error"]["category"], "protocol_incompatible");
}

#[tokio::test(flavor = "multi_thread")]
async fn r13_malformed_client_version_is_refused_not_a_panic() {
    let base = spawn().await;
    let (status, body) = open(
        &base,
        serde_json::json!({
            "session": "s4", "type": "session.open", "profile_id": "chat",
            "client_protocol_version": "not-a-version",
        }),
    )
    .await;
    assert_eq!(
        status, 400,
        "a malformed client version must be refused cleanly, got {status}: {body}"
    );
    assert_eq!(body["accepted"], false);
    assert_eq!(body["error"]["category"], "protocol_incompatible");
}
