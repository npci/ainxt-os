// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R16 CRITICAL — cross-principal transcript leak via SELF-ENROLLMENT (`transport-daemon`).
//!
//! `/v1/events` (resume) and `/v1/observe` both authorize on "is this principal an actor recorded on
//! this session". That check is real and fail-closed. The defect is that its INPUT was forgeable:
//! `/v1/chat` never checked the caller-supplied `dto.session` against the caller, and serving a turn
//! is exactly what RECORDS an actor on a session.
//!
//! So the attack needed no vulnerability in the tails at all:
//!
//!   1. victim chats in session `s-victim`            → victim recorded as an actor
//!   2. intruder POSTs one throwaway turn to `s-victim` → INTRUDER now recorded as an actor
//!   3. intruder calls `/v1/events?session=s-victim`   → passes the participant check, reads all
//!
//! The fix puts an ownership gate where the participant set is WRITTEN: an unclaimed session's first
//! caller becomes its owner; a claimed session admits only its existing actors (or an admin).
//!
//! FAIL-BEFORE: step 2 returns 200 and the intruder is enrolled.
//! PASS-AFTER: step 2 returns 403 and the intruder never enters the actor set.

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
            let _ = tx
                .send(Event::TextDelta("settlement figures for Q3".into()))
                .await;
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
    std::env::temp_dir().join(format!("ainxt-r16-ownership-{tag}-{nanos}"))
}

/// Serve the app with a hash-chained event log installed — the participant set lives there.
async fn spawn_app(tag: &str) -> String {
    let event_log: Arc<dyn EventLog> =
        Arc::new(JsonlEventLog::open(&temp_log_dir(tag)).expect("open log"));
    let cfg = FullApp {
        manager: manager(),
        auth: Arc::new(TrustedGatewayAuth),
        event_log,
        control_plane_sha: "sha-r16".to_string(),
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

async fn chat_as(addr: &str, user: &str, session: &str) -> u16 {
    let client = reqwest::Client::new();
    let r = client
        .post(format!("http://{addr}/v1/chat"))
        .header("content-type", "application/json")
        .header("x-ainxt-user", user)
        .body(
            serde_json::json!({
                "session": session, "turn": "t1", "input": "hello",
                "data_class": "internal", "caps": ["chat.send"]
            })
            .to_string(),
        )
        .send()
        .await
        .expect("chat send");
    let code = r.status().as_u16();
    let _ = r.text().await; // drain so the turn completes and the actor is recorded
    code
}

#[tokio::test(flavor = "multi_thread")]
async fn r16_intruder_cannot_self_enroll_into_another_principals_session() {
    let addr = spawn_app("attack").await;

    // 1. The victim opens and uses their session — they become its owner.
    assert_eq!(chat_as(&addr, "victim", "s-victim").await, 200);

    // 2. THE ATTACK: the intruder posts a throwaway turn into the victim's session id. Before the
    //    fix this returned 200 and silently added "intruder" to the victim's participant set, which
    //    is what made the resume/observe tails hand over the transcript.
    let code = chat_as(&addr, "intruder", "s-victim").await;
    assert_eq!(
        code, 403,
        "an intruder was allowed to write into another principal's session (self-enrollment)"
    );

    // 3. The intruder must not have been enrolled, so the tail refuses them too.
    let client = reqwest::Client::new();
    let tail = client
        .get(format!("http://{addr}/v1/events?session=s-victim"))
        .header("x-ainxt-user", "intruder")
        .send()
        .await
        .expect("events");
    assert_eq!(
        tail.status().as_u16(),
        403,
        "the intruder reached the victim's transcript tail"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn r16_owner_keeps_full_access_and_new_sessions_are_claimable() {
    let addr = spawn_app("owner").await;

    // A fresh session is unclaimed: the first caller becomes its owner.
    assert_eq!(chat_as(&addr, "alice", "s-alice").await, 200);
    // ...and may keep using it across turns (the gate must not lock a user out of their own session).
    assert_eq!(chat_as(&addr, "alice", "s-alice").await, 200);

    // A different, unrelated session is still freely claimable by someone else.
    assert_eq!(chat_as(&addr, "bob", "s-bob").await, 200);

    // And the owner still reaches their own tail.
    let client = reqwest::Client::new();
    let tail = client
        .get(format!("http://{addr}/v1/events?session=s-alice"))
        .header("x-ainxt-user", "alice")
        .send()
        .await
        .expect("events");
    assert_ne!(
        tail.status().as_u16(),
        403,
        "the session owner was locked out of their own transcript"
    );
}
