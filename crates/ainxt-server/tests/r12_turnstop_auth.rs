// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! r12_turnstop_auth — the offline conformance test for the gap
//! "turn.stop cancellation is accepted without authentication".
//!
//! `POST /v1/command {turn.stop}` fires the live cancel token. Before the fix it did so with NO
//! authentication at all: a caller who merely guessed a `(session, turn)` pair could cancel another
//! user's live turn. The fix routes `turn.stop` through the SAME mandatory [`Authenticator`] seam every
//! other command/turn uses (`authenticate_command`), so a credential-checking policy refuses the
//! un-credentialed caller — while the trusted-gateway DEFAULT is unchanged (owner-deferred).
//!
//! This test FAILS before the fix (an un-credentialed `turn.stop` is accepted 200/202 under a real
//! authenticator) and PASSES after (401 without a bearer; accepted with the right bearer). It also
//! pins the default's TURN-04 behaviour: under the trusted-gateway default a bare `turn.stop` still
//! cancels (the cancel path stays "always available").

use ainxt_protocol::Event;
use ainxt_runtime::engine_with_defaults;
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_server::{app_with_auth, serve_with_auth, BearerSecretAuth, TrustedGatewayAuth};
use ainxt_session::{SessionConfig, SessionManager};
use ainxt_types::DataClass;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Minimal offline provider — eligible for every class; emits one delta then closes.
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

async fn spawn(auth: Arc<dyn ainxt_server::Authenticator>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(serve_with_auth(listener, manager(), auth));
    format!("http://{addr}")
}

/// Post a `turn.stop` command with an optional bearer token; return the HTTP status.
async fn post_stop(base: &str, bearer: Option<&str>) -> u16 {
    let client = reqwest::Client::new();
    let mut req = client
        .post(format!("{base}/v1/command"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(
            serde_json::json!({"session": "victim", "type": "turn.stop", "turn_id": "t1"})
                .to_string(),
        );
    if let Some(tok) = bearer {
        req = req.header(reqwest::header::AUTHORIZATION, format!("Bearer {tok}"));
    }
    req.send().await.expect("send").status().as_u16()
}

#[tokio::test(flavor = "multi_thread")]
async fn r12_turnstop_refused_without_credentials_under_a_real_authenticator() {
    // A real credential-checking authenticator (pre-shared bearer secret).
    let base = spawn(Arc::new(BearerSecretAuth::new("s3cr3t"))).await;

    // No bearer → the cancel is REFUSED before it can fire (the gap: previously accepted 200/202).
    let unauth = post_stop(&base, None).await;
    assert_eq!(
        unauth, 401,
        "un-credentialed turn.stop must be refused 401 under a real authenticator, got {unauth}"
    );

    // Wrong bearer → still refused.
    let wrong = post_stop(&base, Some("nope")).await;
    assert_eq!(
        wrong, 401,
        "a wrong bearer must be refused 401, got {wrong}"
    );

    // Correct bearer → the command is authenticated and accepted (no live turn ⇒ 200 OK, cancelled=false).
    let ok = post_stop(&base, Some("s3cr3t")).await;
    assert_eq!(
        ok, 200,
        "an authenticated turn.stop with no live turn is accepted 200 (idempotent), got {ok}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn r12_turnstop_default_trusted_gateway_still_cancels_without_headers() {
    // The DEFAULT (trusted-gateway sidecar, owner-deferred) is UNCHANGED: a bare turn.stop with no
    // headers is still accepted (TURN-04 — the cancel path is always available behind the trusted
    // front gateway). With no live turn it acks 200 (cancelled=false).
    let base = spawn(Arc::new(TrustedGatewayAuth)).await;
    let status = post_stop(&base, None).await;
    assert_eq!(
        status, 200,
        "the trusted-gateway default must keep accepting a bare turn.stop (200, no live turn), got {status}"
    );

    // And app_with_auth builds the same default route surface (smoke: the route is mounted, not 404).
    let _app = app_with_auth(manager(), Arc::new(TrustedGatewayAuth));
}
