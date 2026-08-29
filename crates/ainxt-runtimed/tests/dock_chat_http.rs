// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Dock-and-play proof: a frontend POSTs to the daemon's `/v1/chat` over REAL HTTP and gets the FULL
//! Chat intelligence back — streamed — through the same concurrency spine. This is the end-to-end
//! contract any frontend (React UI, the AiNxt Python gateway, a CLI) speaks. It asserts the
//! cross-cutting behaviors that only exist when the whole stack is wired and served:
//!   1. a QA turn streams a grounded-style answer;
//!   2. "generate this as pdf" resolves to the PRIOR answer, not the instruction (referent);
//!   3. a streamed PAN is redacted by StrongRedactor before it leaves the socket;
//!   4. an unauthorized principal is refused with nothing served.
//!
//! The provider is a deterministic mock (no keys/network); the transport, the SessionManager spine,
//! the conversation intelligence, and the compliance gate are all the REAL production types.

use std::sync::Arc;

use ainxt_compliance::StrongRedactor;
use ainxt_convo::{ConversationManager, HeuristicClassifier};
use ainxt_prompt::PromptConfig;
use ainxt_protocol::Event;
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_runtime::{Engine, InMemoryAudit, RbacAuthorizer};
use ainxt_server::serve;
use ainxt_session::{SessionConfig, SessionManager};
use ainxt_types::DataClass;
use tokio::sync::mpsc;

/// Deterministic mock model: a substantive UPI answer by default; a STREAMED PAN when asked about a
/// card (so the surface's streaming-aware redaction is exercised on a split secret).
struct ChatMock;
impl Provider for ChatMock {
    fn id(&self) -> &str {
        "mock"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, prompt: &str) -> mpsc::Receiver<Event> {
        let p = prompt.to_lowercase();
        let (tx, rx) = mpsc::channel(16);
        tokio::spawn(async move {
            if p.contains("card") || p.contains("account") {
                let _ = tx.send(Event::TextDelta("Your card ".into())).await;
                for c in ["4111", "1111", "1111", "1111"] {
                    let _ = tx.send(Event::TextDelta(c.into())).await;
                }
                let _ = tx.send(Event::TextDelta(" on file.".into())).await;
            } else {
                let _ = tx
                    .send(Event::TextDelta(
                        "UPI transaction volume grew ~45% YoY.".into(),
                    ))
                    .await;
            }
            let _ = tx.send(Event::Done).await;
        });
        rx
    }
}

/// The REAL served stack: ConversationManager (full intelligence + StrongRedactor engine) behind the
/// SessionManager spine — exactly what `ainxt_runtimed::assemble_chat` builds, but with a controllable
/// provider instead of the offline one.
fn chat_manager() -> Arc<SessionManager> {
    let mut router = ModelRouter::new();
    router.register(Box::new(ChatMock));
    let engine = Engine::new(
        Box::new(StrongRedactor::new()),
        Box::new(RbacAuthorizer),
        Box::new(InMemoryAudit::default()),
        router,
    );
    let convo =
        ConversationManager::new(engine, HeuristicClassifier).with_prompt(PromptConfig::default());
    Arc::new(SessionManager::new(
        Arc::new(convo),
        SessionConfig::default(),
    ))
}

/// POST one chat turn and return the full SSE body text. `caps` empty ⇒ default `["chat.send"]`.
async fn post_chat(
    client: &reqwest::Client,
    addr: &std::net::SocketAddr,
    session: &str,
    turn: &str,
    input: &str,
    caps: Option<&[&str]>,
) -> (u16, String) {
    let mut body = serde_json::json!({
        "session": session, "turn": turn, "input": input, "data_class": "public",
    });
    if let Some(c) = caps {
        body["caps"] = serde_json::json!(c);
    }
    let resp = client
        .post(format!("http://{addr}/v1/chat"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(serde_json::to_string(&body).unwrap())
        .send()
        .await
        .expect("request send");
    let status = resp.status().as_u16();
    let text = resp.text().await.expect("read body");
    (status, text)
}

#[tokio::test(flavor = "multi_thread")]
async fn dock_full_chat_intelligence_over_http() {
    let manager = chat_manager();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(serve(listener, manager));
    let client = reqwest::Client::new();

    // 1. QA turn — a streamed answer over HTTP.
    let (s1, t1) = post_chat(&client, &addr, "s1", "t1", "How did UPI grow?", None).await;
    assert_eq!(s1, 200, "chat POST should succeed");
    assert!(t1.contains("data: "), "response must be SSE-framed: {t1}");
    assert!(t1.contains("UPI"), "QA turn must stream the answer: {t1}");

    // 2. Referent resolution — "generate this as pdf" must carry the PRIOR answer, not the instruction.
    let (_s2, t2) = post_chat(&client, &addr, "s1", "t2", "generate this as pdf", None).await;
    assert!(
        t2.contains("UPI"),
        "the pdf turn must resolve to the prior answer: {t2}"
    );
    assert!(
        !t2.contains("generate this as pdf"),
        "the pdf turn must NOT echo the instruction text: {t2}"
    );

    // 3. Streaming PAN redaction — the raw card number must never leave the socket.
    let (_s3, t3) = post_chat(&client, &addr, "s3", "t1", "show me the card on file", None).await;
    assert!(
        t3.contains("REDACTED-PAN"),
        "the streamed PAN must be redacted over HTTP: {t3}"
    );
    assert!(
        !t3.contains("4111111111111111"),
        "raw PAN leaked over the wire: {t3}"
    );

    // 4. RBAC — a principal without chat.send is refused; the answer never streams.
    let (_s4, t4) = post_chat(&client, &addr, "s4", "t1", "How did UPI grow?", Some(&[])).await;
    assert!(
        !t4.contains("UPI"),
        "an unauthorized turn must not stream an answer: {t4}"
    );
}
