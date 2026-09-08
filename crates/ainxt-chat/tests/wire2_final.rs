// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! FINAL integration-pass tests (`wire2_*`): the capabilities the earlier pass unit-tested are now
//! exercised on the REAL assembled [`ChatSurface`] object, on the LIVE turn path.
//!
//! * `wire2_conv_01` — the provider-backed [`ainxt_convo::ModelIntentClassifier`] actually drives the
//!   live surface's control-flow when a model is configured (and the surface falls back to the
//!   heuristic when one is not).
//! * `wire2_conv_08` — a referent action ("summarize the above and email it") is surfaced as a
//!   [`ChatReply::Action`] whose content is the PRIOR answer, instruction verb phrase excluded.
//! * `wire2_conv_10` — the live QA answer is composed through `ainxt-answer` (a `## References`
//!   section appears) rather than returned as the raw model string.
//! * `wire2_srv_06` — the response cache is partition-isolated by `{data_class, principal_scope,
//!   harness_id}` and never crosses clearance: two departments at the same clearance do NOT share an
//!   internal-class entry, and the same user at a higher clearance does not read the lower one's.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use ainxt_cache::{CacheConfig, FixedClock};
use ainxt_chat::{ChatReply, ChatSurface};
use ainxt_compliance::StrongRedactor;
use ainxt_context::{Chunk, Corpus};
use ainxt_convo::{ActionKind, ModelCaps};
use ainxt_protocol::Event;
use ainxt_providers::{ConstrainedProvider, LabelGrammar};
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_runtime::{Engine, InMemoryAudit, RbacAuthorizer};
use ainxt_types::{DataClass, Principal};
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------------------------

/// A deterministic model provider for the ENGINE (answers QA turns). Not the classifier transport.
struct AnswerProvider;
impl Provider for AnswerProvider {
    fn id(&self) -> &str {
        "mock-answer"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, _prompt: &str) -> mpsc::Receiver<Event> {
        let (tx, rx) = mpsc::channel(8);
        // Pre-buffered, no runtime needed for the sends.
        let _ = tx.try_send(Event::TextDelta(
            "UPI transaction volume grew ~45% YoY. See [1].".into(),
        ));
        let _ = tx.try_send(Event::Done);
        rx
    }
}

/// A scripted [`ConstrainedProvider`] — the CLASSIFIER transport behind `ProviderLabelModel`.
/// Emits a fixed label and records that it was invoked, so a test can prove the model-backed
/// classifier ran on the live surface (a heuristic surface would never touch it).
struct ScriptedConstrainedProvider {
    label: String,
    calls: Arc<AtomicUsize>,
}
impl ConstrainedProvider for ScriptedConstrainedProvider {
    fn stream_constrained(
        &self,
        _prompt: &str,
        _grammar: Option<&LabelGrammar>,
    ) -> mpsc::Receiver<Event> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = mpsc::channel(4);
        let _ = tx.try_send(Event::TextDelta(self.label.clone()));
        let _ = tx.try_send(Event::Done);
        rx
    }
}

fn engine() -> Engine {
    let mut router = ModelRouter::new();
    router.register(Box::new(AnswerProvider));
    Engine::new(
        Box::new(StrongRedactor::new()),
        Box::new(RbacAuthorizer),
        Box::new(InMemoryAudit::default()),
        router,
    )
}

fn upi_corpus() -> Corpus {
    Corpus::new().with(Chunk::new(
        "upi",
        "Payment System Report 2024",
        "UPI is a real-time payments system and its transaction volume grew rapidly year over year",
        DataClass::Public,
    ))
}

fn cfg() -> CacheConfig {
    CacheConfig {
        capacity: 128,
        ttl_ticks: 100,
        semantic_threshold: 0.99,
    }
}

fn user() -> Principal {
    Principal::user("analyst", &["chat.send"]).with_clearance(DataClass::Public)
}

// ---------------------------------------------------------------------------------------------
// CONV-01 — the provider-backed ModelIntentClassifier drives the live surface
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn wire2_conv_01() {
    // A message the HEURISTIC would route to doc-generation ("make a pdf …") — proving the model,
    // not the heuristic, owns the branch when a live model is configured.
    let input = "make a pdf about the quarterly numbers";

    // Model surface: scripted classifier overrides the intent to `qa`.
    let calls = Arc::new(AtomicUsize::new(0));
    let provider = ScriptedConstrainedProvider {
        label: "qa".into(),
        calls: calls.clone(),
    };
    let model_surface = ChatSurface::from_engine_classified(
        engine(),
        upi_corpus(),
        cfg(),
        Box::new(FixedClock(0)),
        Some((provider, ModelCaps::weak_oss())),
    );
    let out = model_surface
        .turn("s1", &user(), input, DataClass::Public)
        .await
        .unwrap();
    assert!(
        calls.load(Ordering::SeqCst) >= 1,
        "the provider-backed LabelModel must actually be invoked on the live ChatSurface path"
    );
    assert!(
        matches!(out, ChatReply::Answer { .. }),
        "the MODEL's `qa` label must drive control-flow (Answer), not the heuristic's doc-gen: {out:?}"
    );

    // Heuristic surface (no live model): the SAME input is read as doc-generation instead — a
    // different outcome, confirming the two classifiers are genuinely distinct and the wiring chose
    // the model above.
    let heuristic_surface = ChatSurface::new(
        {
            let mut r = ModelRouter::new();
            r.register(Box::new(AnswerProvider));
            r
        },
        upi_corpus(),
        cfg(),
        Box::new(FixedClock(0)),
    );
    let h = heuristic_surface
        .turn("s1", &user(), input, DataClass::Public)
        .await
        .unwrap();
    assert!(
        matches!(h, ChatReply::Document { .. } | ChatReply::Clarify { .. }),
        "the heuristic must read '{input}' as doc-generation, not qa: {h:?}"
    );
}

// ---------------------------------------------------------------------------------------------
// CONV-08 — a referent action ("summarize the above and email it") is surfaced as an outcome
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn wire2_conv_08() {
    let s = ChatSurface::from_engine(engine(), upi_corpus(), cfg(), Box::new(FixedClock(0)));
    let p = user();

    // Turn 1: a real answer, stored as history for referent resolution.
    let a1 = s
        .turn(
            "sess",
            &p,
            "How did UPI transaction volume grow?",
            DataClass::Public,
        )
        .await
        .unwrap();
    assert!(
        matches!(a1, ChatReply::Answer { .. }),
        "first turn is an answer"
    );

    // Turn 2: a multi-action turn. Email (terminal delivery) wins; content = the resolved referent.
    let a2 = s
        .turn(
            "sess",
            &p,
            "summarize the above and email it",
            DataClass::Public,
        )
        .await
        .unwrap();
    match a2 {
        ChatReply::Action { action, content } => {
            assert_eq!(action, ActionKind::Email, "terminal delivery action wins");
            assert!(
                content.contains("45%") || content.to_uppercase().contains("UPI"),
                "content must be the PRIOR answer (referent): {content:?}"
            );
            let lc = content.to_lowercase();
            assert!(
                !lc.contains("summarize") && !lc.contains("email it"),
                "the instruction verb phrase must be EXCLUDED from the content: {content:?}"
            );
        }
        other => panic!("a referent action must surface as ChatReply::Action, got {other:?}"),
    }

    // A plain question is NOT an action — it still answers normally.
    let a3 = s
        .turn("sess", &p, "what is NEFT?", DataClass::Public)
        .await
        .unwrap();
    assert!(
        matches!(a3, ChatReply::Answer { .. }),
        "a plain question must not be hijacked as an action: {a3:?}"
    );
}

// ---------------------------------------------------------------------------------------------
// CONV-10 — the live QA answer is composed through ainxt-answer (References rendered)
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn wire2_conv_10() {
    let s = ChatSurface::from_engine(engine(), upi_corpus(), cfg(), Box::new(FixedClock(0)));
    let out = s
        .turn(
            "s1",
            &user(),
            "How did UPI transaction volume grow?",
            DataClass::Public,
        )
        .await
        .unwrap();
    match out {
        ChatReply::Answer {
            text, citations, ..
        } => {
            assert!(
                !citations.is_empty(),
                "the grounded turn must carry a citation to compose"
            );
            assert!(
                text.contains("## References"),
                "answer_format must compose the live answer via ainxt-answer (BK/BN): {text:?}"
            );
            assert!(
                text.contains("Payment System Report 2024"),
                "the source must be rendered: {text:?}"
            );
        }
        other => panic!("expected a composed answer, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------------------------
// SRV-06 — partition-isolated cache: never cross department, never cross clearance
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn wire2_srv_06() {
    let s = ChatSurface::from_engine(engine(), upi_corpus(), cfg(), Box::new(FixedClock(0)));
    let q = "How did UPI transaction volume grow?";

    // Internal data-class → per-DEPARTMENT scope. alice ∈ payments, bob ∈ cards, same clearance.
    // Both cleared for Internal: the read seam (ADR-012 clearance-vs-data-class) requires clearance
    // ≥ the turn class, and this test's subject is the department cache partition, not the read gate.
    let alice = Principal::user("alice", &["chat.send"])
        .with_clearance(DataClass::Internal)
        .with_department("payments");
    let bob = Principal::user("bob", &["chat.send"])
        .with_clearance(DataClass::Internal)
        .with_department("cards");

    // alice: first turn is a miss and is cached in her department partition.
    let a1 = s.turn("a", &alice, q, DataClass::Internal).await.unwrap();
    assert!(
        matches!(
            a1,
            ChatReply::Answer {
                from_cache: false,
                ..
            }
        ),
        "alice's first turn must be a cache miss: {a1:?}"
    );

    // bob (different department, same clearance, same question): MUST still be a miss — the audit
    // bug was that both departments shared one internal-class entry.
    let b1 = s.turn("b", &bob, q, DataClass::Internal).await.unwrap();
    assert!(
        matches!(
            b1,
            ChatReply::Answer {
                from_cache: false,
                ..
            }
        ),
        "a different department MUST NOT read alice's cached entry: {b1:?}"
    );

    // alice again (same partition): now a hit.
    let a2 = s.turn("a", &alice, q, DataClass::Internal).await.unwrap();
    assert!(
        matches!(
            a2,
            ChatReply::Answer {
                from_cache: true,
                ..
            }
        ),
        "the same department+clearance must hit its own partition: {a2:?}"
    );

    // Never cross clearance: alice, same department + same partition, but a HIGHER clearance reads a
    // different within-partition key, so she does NOT see the lower-clearance entry.
    let alice_conf = Principal::user("alice", &["chat.send"])
        .with_clearance(DataClass::Confidential)
        .with_department("payments");
    let a3 = s
        .turn("a", &alice_conf, q, DataClass::Internal)
        .await
        .unwrap();
    assert!(
        matches!(
            a3,
            ChatReply::Answer {
                from_cache: false,
                ..
            }
        ),
        "a higher clearance must never read the lower-clearance cache entry: {a3:?}"
    );
}
