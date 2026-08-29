// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! r17_deprecation_notice_on_chat_response — GAP-AUDIT protocol #2: `ainxt_protocol::deprecation_notice`
//! (the deprecated-surface registry, seeded with `"ainxt_protocol::Event"` and
//! `"ainxt_protocol::Request"`) had zero callers outside `ainxt-protocol`'s own `#[cfg(test)]` block —
//! the registry existed and was seeded, but nothing in the served daemon ever surfaced a notice to a
//! real caller, so a client depending on the deprecated legacy in-proc pair had no way to learn it was
//! on a deprecated shape short of reading Rust doc comments in a crate it may not even depend on.
//!
//! `POST /v1/chat` unconditionally builds an `ainxt_protocol::Request` (see `chat_handler`'s doc
//! comment) and always creates its transport sink as an `ainxt_protocol::Event` channel, regardless of
//! whether a wire hub is configured — i.e. EVERY real `/v1/chat` call touches both seeded surfaces.
//! This test drives a real HTTP server (via `app_full_ext`, the same composition-root entrypoint the
//! shipped daemon uses) and asserts the response actually carries both notices with real
//! `since`/`reason` values matching the registry — not just that the registry function exists.

use ainxt_eventlog::{EventLog, JsonlEventLog};
use ainxt_protocol::Event;
use ainxt_runtime::engine_with_defaults;
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_server::{app_full_ext, FullApp, FullAppExt, TrustedGatewayAuth};
use ainxt_session::{SessionConfig, SessionManager};
use ainxt_types::DataClass;
use std::sync::Arc;
use tokio::sync::mpsc;

struct Fixed;
impl Provider for Fixed {
    fn id(&self) -> &str {
        "fixed"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, _prompt: &str) -> mpsc::Receiver<Event> {
        let (tx, rx) = mpsc::channel(8);
        tokio::spawn(async move {
            let _ = tx.send(Event::TextDelta("hi".into())).await;
            let _ = tx.send(Event::Done).await;
        });
        rx
    }
}

fn manager() -> Arc<SessionManager> {
    let mut router = ModelRouter::new();
    router.register(Box::new(Fixed));
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
    std::env::temp_dir().join(format!("ainxt-r17-deprecation-{tag}-{nanos}"))
}

/// Serve the REAL composition-root app (`app_full_ext`, no wire hub — the legacy `Event` SSE
/// projection path) so this proves the shipped daemon's default transport, not a synthetic harness.
async fn spawn_app(tag: &str) -> String {
    let event_log: Arc<dyn EventLog> =
        Arc::new(JsonlEventLog::open(&temp_log_dir(tag)).expect("open log"));
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
    let router = app_full_ext(cfg, FullAppExt::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    addr
}

#[tokio::test(flavor = "multi_thread")]
async fn r17_chat_response_surfaces_the_deprecation_notice_for_both_seeded_legacy_surfaces() {
    let addr = spawn_app("legacy-pair").await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{addr}/v1/chat"))
        .header("content-type", "application/json")
        .header("x-ainxt-user", "alice")
        .body(
            serde_json::json!({
                "session": "s1", "turn": "t1", "input": "hello",
                "data_class": "internal", "caps": ["chat.send"]
            })
            .to_string(),
        )
        .send()
        .await
        .expect("send");

    assert_eq!(
        resp.status().as_u16(),
        200,
        "the chat call itself must succeed"
    );
    let header = resp
        .headers()
        .get("x-ainxt-deprecation-notice")
        .expect("a request that touches ainxt_protocol::Request/Event must carry a deprecation notice header")
        .to_str()
        .expect("header value must be plain visible ASCII (transliterated), never rejected by a client's to_str()")
        .to_string();

    // Drain the SSE body so the turn completes cleanly (not required for the header assertion, but
    // keeps this test symmetric with the other /v1/chat integration tests in this crate).
    let _ = resp.text().await;

    let notices: serde_json::Value =
        serde_json::from_str(&header).expect("header must be a JSON array");
    let notices = notices.as_array().expect("notices must be a JSON array");

    let by_surface = |surface: &str| -> &serde_json::Value {
        notices
            .iter()
            .find(|n| n["surface"] == surface)
            .unwrap_or_else(|| panic!("no notice for {surface} in {notices:?}"))
    };

    // Header values are transliterated to plain ASCII (the reason text uses `§`, which most HTTP
    // client `to_str()` implementations reject) — replicate the same transform here so this asserts
    // real equivalence, not a coincidental substring match.
    fn ascii_safe(s: &str) -> String {
        s.chars()
            .map(|c| {
                if c.is_ascii() && c != '\u{7f}' {
                    c
                } else {
                    '?'
                }
            })
            .collect()
    }

    // Cross-check against the registry directly so this test breaks if the registry's content ever
    // changes without the wiring being updated to match — never hardcode a copy that can drift silent.
    let expect_request = ainxt_protocol::deprecation_notice("ainxt_protocol::Request")
        .expect("ainxt_protocol::Request must be a seeded deprecation");
    let expect_event = ainxt_protocol::deprecation_notice("ainxt_protocol::Event")
        .expect("ainxt_protocol::Event must be a seeded deprecation");

    let got_request = by_surface("ainxt_protocol::Request");
    assert_eq!(got_request["since"], ascii_safe(expect_request.since));
    assert_eq!(got_request["reason"], ascii_safe(expect_request.reason));

    let got_event = by_surface("ainxt_protocol::Event");
    assert_eq!(got_event["since"], ascii_safe(expect_event.since));
    assert_eq!(got_event["reason"], ascii_safe(expect_event.reason));
}

#[tokio::test(flavor = "multi_thread")]
async fn r17_a_surface_with_no_registered_deprecation_never_appears() {
    let addr = spawn_app("no-spurious-entries").await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{addr}/v1/chat"))
        .header("content-type", "application/json")
        .header("x-ainxt-user", "bob")
        .body(
            serde_json::json!({
                "session": "s2", "turn": "t1", "input": "hello",
                "data_class": "internal", "caps": ["chat.send"]
            })
            .to_string(),
        )
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status().as_u16(), 200);
    let header = resp
        .headers()
        .get("x-ainxt-deprecation-notice")
        .expect("header present")
        .to_str()
        .unwrap()
        .to_string();
    let _ = resp.text().await;
    let notices: serde_json::Value = serde_json::from_str(&header).unwrap();
    let notices = notices.as_array().unwrap();
    // Exactly the two real surfaces this route touches — never a phantom/unregistered entry, and
    // never silently missing one of the two.
    assert_eq!(notices.len(), 2, "unexpected notice set: {notices:?}");
    assert!(ainxt_protocol::deprecation_notice("turn.steer").is_none());
}
