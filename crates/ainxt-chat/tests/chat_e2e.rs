// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! End-to-end Chat surface tests: a real multi-turn conversation through the ASSEMBLED stack
//! (cache → conversation intelligence → grounded retrieval → prompt engine → Engine with
//! StrongRedactor + RBAC + failover). These assert the cross-cutting behaviors that only appear when
//! the crates are wired together.

use ainxt_cache::{CacheConfig, FixedClock};
use ainxt_chat::{ChatReply, ChatSurface};
use ainxt_context::{Chunk, Corpus};
use ainxt_protocol::Event;
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_types::{DataClass, Principal};
use tokio::sync::mpsc;

/// A deterministic mock model: a substantive UPI answer by default; a STREAMED PAN when asked about
/// a card/account (so the surface's compliance-out redaction is exercised on a split secret).
struct ChatProvider;
impl Provider for ChatProvider {
    fn id(&self) -> &str {
        "mock-chat"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, prompt: &str) -> mpsc::Receiver<Event> {
        let p = prompt.to_lowercase();
        let (tx, rx) = mpsc::channel(16);
        tokio::spawn(async move {
            // Key off the USER's request phrase ("card on file"), not a bare "card" — the served
            // layered guard prompt legitimately contains "card data", which a bare-word sniff would
            // (spuriously) trip. The test's intent is "the USER asked about a card" and is unchanged.
            if p.contains("card on file") || p.contains("account number") {
                let _ = tx.send(Event::TextDelta("Your card ".into())).await;
                for c in ["4111", "1111", "1111", "1111"] {
                    let _ = tx.send(Event::TextDelta(c.into())).await;
                }
                let _ = tx.send(Event::TextDelta(" on file.".into())).await;
            } else {
                let _ = tx
                    .send(Event::TextDelta(
                        "UPI transaction volume grew ~45% YoY. See [1].".into(),
                    ))
                    .await;
            }
            let _ = tx.send(Event::Done).await;
        });
        rx
    }
}

fn surface() -> ChatSurface {
    let mut router = ModelRouter::new();
    router.register(Box::new(ChatProvider));
    let corpus = Corpus::new().with(Chunk::new(
        "upi",
        "kb",
        "UPI is a real-time payments system and its transaction volume grew rapidly year over year",
        DataClass::Public,
    ));
    let cfg = CacheConfig {
        capacity: 128,
        ttl_ticks: 100,
        semantic_threshold: 0.99,
    };
    ChatSurface::new(router, corpus, cfg, Box::new(FixedClock(0)))
}

fn user() -> Principal {
    Principal::user("analyst", &["chat.send"])
}

#[tokio::test]
async fn grounded_answer_then_cache_hit() {
    let s = surface();
    let r1 = s
        .turn("s1", &user(), "How did UPI grow?", DataClass::Public)
        .await
        .unwrap();
    match &r1 {
        ChatReply::Answer {
            text, from_cache, ..
        } => {
            assert!(text.contains("UPI"), "answer should mention UPI: {text}");
            assert!(!from_cache, "first turn must be a cache miss");
        }
        o => panic!("expected Answer, got {o:?}"),
    }
    let r2 = s
        .turn("s1", &user(), "How did UPI grow?", DataClass::Public)
        .await
        .unwrap();
    match r2 {
        ChatReply::Answer {
            from_cache, text, ..
        } => {
            assert!(from_cache, "an identical turn must hit the cache");
            assert!(text.contains("UPI"));
        }
        o => panic!("expected a cached Answer, got {o:?}"),
    }
}

#[tokio::test]
async fn generate_as_pdf_resolves_referent_not_instruction() {
    let s = surface();
    let _ = s
        .turn("s2", &user(), "How did UPI grow?", DataClass::Public)
        .await
        .unwrap();
    let r = s
        .turn("s2", &user(), "generate this as pdf", DataClass::Public)
        .await
        .unwrap();
    match r {
        ChatReply::Document { content, .. } => {
            assert!(
                content.contains("UPI"),
                "the pdf content must be the PRIOR answer: {content}"
            );
            assert!(
                !content.contains("generate this as pdf"),
                "the pdf content must NOT be the instruction text: {content}"
            );
        }
        o => panic!("expected a Document, got {o:?}"),
    }
}

/// R16 fix (gap "doc_generation dead-ends"): `ChatReply::Document` now carries a REAL
/// `ainxt_artifact::Document` IR, not just the naked content string — and that IR is not a
/// parallel/inert type: it renders through the actual `ainxt_artifact::ArtifactRuntime` a
/// `POST /v1/artifact` handler would use, end to end from a real chat turn.
#[tokio::test]
async fn generate_as_pdf_builds_a_real_renderable_artifact_document() {
    let s = surface();
    let _ = s
        .turn("s4", &user(), "How did UPI grow?", DataClass::Public)
        .await
        .unwrap();
    let r = s
        .turn("s4", &user(), "generate this as pdf", DataClass::Public)
        .await
        .unwrap();
    match r {
        ChatReply::Document {
            content, document, ..
        } => {
            // The IR is built FROM the same resolved content this reply already carried.
            assert!(
                !document.blocks.is_empty(),
                "the built Document must have real blocks"
            );
            assert!(
                document.text_segments().iter().any(|s| s.contains("UPI")),
                "the artifact IR's text must carry the resolved UPI content: {document:?}"
            );
            // It is a genuine construction into the existing artifact runtime, not a dead-end type:
            // it renders through the SAME `ArtifactRuntime` a `POST /v1/artifact` handler would use.
            let rt = ainxt_artifact::ArtifactRuntime::with_builtin_renderers(Box::new(
                ainxt_artifact::MarkerScanner,
            ));
            let out = rt
                .generate(&document, "markdown")
                .expect("the built IR must render");
            assert!(
                out.text_lossy().contains("UPI"),
                "the rendered artifact must contain the resolved content: {}",
                out.text_lossy()
            );
            assert!(
                !out.text_lossy().contains("generate this as pdf"),
                "the rendered artifact must NOT contain the instruction text"
            );
            assert!(content.contains("UPI"));
        }
        o => panic!("expected a Document, got {o:?}"),
    }
}

#[tokio::test]
async fn streamed_pan_is_redacted_in_the_chat_path() {
    let s = surface();
    let r = s
        .turn("s3", &user(), "show me the card on file", DataClass::Public)
        .await
        .unwrap();
    match r {
        ChatReply::Answer { text, .. } => {
            assert!(
                text.contains("[REDACTED-PAN]"),
                "the streamed PAN must be redacted: {text}"
            );
            assert!(
                !text.contains("4111111111111111"),
                "raw PAN leaked through the chat surface: {text}"
            );
        }
        o => panic!("expected Answer, got {o:?}"),
    }
}

#[tokio::test]
async fn unauthorized_principal_is_denied() {
    let s = surface();
    let blocked = Principal::user("intruder", &[]); // no chat.send
    let r = s
        .turn("s4", &blocked, "How did UPI grow?", DataClass::Public)
        .await;
    assert!(
        r.is_err(),
        "a principal without chat.send must be denied, not served"
    );
}

#[tokio::test]
async fn confidential_class_answers_are_never_cached() {
    let s = surface();
    // Cleared to READ Confidential (the turn pipeline now enforces the clearance-vs-data-class read
    // seam, ADR-012): this test asserts the cache decision for a sensitive class, not the read gate,
    // so the caller must legitimately satisfy the gate — we do not bypass it.
    let u = user().with_clearance(DataClass::Confidential);
    let r1 = s
        .turn("s5", &u, "How did UPI grow?", DataClass::Confidential)
        .await
        .unwrap();
    let r2 = s
        .turn("s5", &u, "How did UPI grow?", DataClass::Confidential)
        .await
        .unwrap();
    for r in [r1, r2] {
        match r {
            ChatReply::Answer { from_cache, .. } => {
                assert!(
                    !from_cache,
                    "an above-Internal (Confidential) answer must never be cached"
                )
            }
            o => panic!("expected Answer, got {o:?}"),
        }
    }
}

#[tokio::test]
async fn cache_is_scoped_by_clearance() {
    let s = surface();
    // First caller (default Internal clearance) caches a Public answer.
    let _ = s
        .turn("s6", &user(), "How did UPI grow?", DataClass::Public)
        .await
        .unwrap();
    // A caller with a DIFFERENT clearance must NOT read the first caller's cached answer.
    let higher = Principal::user("exec", &["chat.send"]).with_clearance(DataClass::Confidential);
    let r = s
        .turn("s6", &higher, "How did UPI grow?", DataClass::Public)
        .await
        .unwrap();
    match r {
        ChatReply::Answer { from_cache, .. } => {
            assert!(
                !from_cache,
                "a different clearance must not share another clearance's cache slot"
            )
        }
        o => panic!("expected Answer, got {o:?}"),
    }
}
