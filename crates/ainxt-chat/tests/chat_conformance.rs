// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Chat-level conformance: the INTELLIGENCE-category invariants proven at scale through the
//! assembled Chat surface (the engine-level `ainxt-conformance` matrix covers redaction/leak/rbac/
//! idempotency/injection; this adds referent-resolution + chat-path redaction + cache across many
//! genuinely-distinct cases). Each iteration varies a real axis (a distinct topic, a distinct PAN),
//! so this is coverage, not a cloned assertion.

use ainxt_cache::{CacheConfig, FixedClock};
use ainxt_chat::{ChatReply, ChatSurface};
use ainxt_context::Corpus;
use ainxt_protocol::Event;
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_types::{DataClass, Principal};
use tokio::sync::mpsc;

/// A distinct 16-digit PAN per seed (contiguous ⇒ StrongRedactor redacts it). Shared by the mock
/// model (which emits it) and the assertions (which check it is gone) — so a green run reflects real
/// redaction, never a rigged test. The seed (not the PAN) is what travels in the input, so
/// compliance-IN cannot pre-redact it: the value originates in the model output, as with a real LLM.
fn pan_for(seed: u64) -> String {
    format!("{:016}", 4_000_000_000_000_000u64 + seed)
}

fn extract_after(hay: &str, marker: &str) -> Option<String> {
    let i = hay.find(marker)? + marker.len();
    let tok: String = hay[i..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric())
        .collect();
    if tok.is_empty() {
        None
    } else {
        Some(tok)
    }
}

/// Deterministic mock model: echoes the distinct `widget-N` topic (so each conversation's prior
/// answer is unique for the referent test), and streams a distinct seed-derived PAN, split across
/// deltas, when asked about `card#N`.
struct EchoProvider;
impl Provider for EchoProvider {
    fn id(&self) -> &str {
        "echo"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, prompt: &str) -> mpsc::Receiver<Event> {
        let p = prompt.to_string();
        let (tx, rx) = mpsc::channel(16);
        tokio::spawn(async move {
            if let Some(seed) = extract_after(&p, "card#").and_then(|s| s.parse::<u64>().ok()) {
                let pan = pan_for(seed);
                let parts: Vec<String> = pan
                    .chars()
                    .collect::<Vec<_>>()
                    .chunks(4)
                    .map(|c| c.iter().collect())
                    .collect();
                let _ = tx.send(Event::TextDelta("card: ".into())).await;
                for part in parts {
                    let _ = tx.send(Event::TextDelta(part)).await;
                }
                let _ = tx.send(Event::TextDelta(" end".into())).await;
            } else if let Some(w) = extract_after(&p, "widget-") {
                let _ = tx
                    .send(Event::TextDelta(format!("Details on widget-{w} follow.")))
                    .await;
            } else {
                let _ = tx.send(Event::TextDelta("ok".into())).await;
            }
            let _ = tx.send(Event::Done).await;
        });
        rx
    }
}

fn surface() -> ChatSurface {
    let mut router = ModelRouter::new();
    router.register(Box::new(EchoProvider));
    let cfg = CacheConfig {
        capacity: 4096,
        ttl_ticks: 1000,
        semantic_threshold: 0.99,
    };
    ChatSurface::new(router, Corpus::new(), cfg, Box::new(FixedClock(0)))
}

fn user() -> Principal {
    Principal::user("analyst", &["chat.send"])
}

#[tokio::test]
async fn referent_resolution_holds_across_100_distinct_conversations() {
    let s = surface();
    for i in 0..100u64 {
        let sess = format!("r{i}");
        let a = s
            .turn(
                &sess,
                &user(),
                &format!("tell me about widget-{i}"),
                DataClass::Public,
            )
            .await
            .unwrap();
        assert!(
            matches!(a, ChatReply::Answer { .. }),
            "scenario {i}: turn 1 should answer"
        );
        let d = s
            .turn(&sess, &user(), "generate this as pdf", DataClass::Public)
            .await
            .unwrap();
        match d {
            ChatReply::Document { content, .. } => {
                assert!(
                    content.contains(&format!("widget-{i}")),
                    "scenario {i}: the pdf must carry the PRIOR answer: {content}"
                );
                assert!(
                    !content.contains("generate this as pdf"),
                    "scenario {i}: the pdf must NOT echo the instruction: {content}"
                );
            }
            o => panic!("scenario {i}: expected Document, got {o:?}"),
        }
    }
}

#[tokio::test]
async fn streamed_pan_redaction_holds_across_100_distinct_pans() {
    let s = surface();
    for seed in 0..100u64 {
        let sess = format!("p{seed}");
        let r = s
            .turn(
                &sess,
                &user(),
                &format!("show card#{seed} on file"),
                DataClass::Public,
            )
            .await
            .unwrap();
        match r {
            ChatReply::Answer { text, .. } => {
                assert!(
                    !text.contains(&pan_for(seed)),
                    "seed {seed}: raw PAN leaked in chat: {text}"
                );
                assert!(
                    text.contains("[REDACTED-PAN]"),
                    "seed {seed}: no redaction: {text}"
                );
            }
            o => panic!("seed {seed}: expected Answer, got {o:?}"),
        }
    }
}

#[tokio::test]
async fn cache_serves_every_repeated_query() {
    let s = surface();
    let mut hits = 0u32;
    for i in 0..60u64 {
        let q = format!("tell me about widget-{i}");
        let _ = s.turn("c", &user(), &q, DataClass::Public).await.unwrap(); // miss + store
        if let ChatReply::Answer { from_cache, .. } =
            s.turn("c", &user(), &q, DataClass::Public).await.unwrap()
        {
            if from_cache {
                hits += 1;
            }
        }
    }
    assert_eq!(
        hits, 60,
        "every distinct query's repeat must be served from cache"
    );
}
