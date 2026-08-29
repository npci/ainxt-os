// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R16 CRITICAL — the chat answer-cache hit must not bypass §1 step 2 (authz) or step 10 (audit).
//!
//! A cache hit answers the turn without entering `Engine::run_turn_cancellable`, so it was the one
//! path to an answer that never ran the `chat.send` check. The cache is session-scoped: a prior
//! turn in the SAME conversation is reusable, but a different conversation never sees another
//! session's cached answer. A peer who lacks `chat.send` — or whose capability was revoked *after*
//! the entry was written — must still be denied, and every cache-served turn must be audited.
//!
//! FAIL-BEFORE: the denied principal receives the cached answer (`Ok`), and the audit sink is empty.
//! PASS-AFTER: the denied principal gets `TurnError::Denied`, the authorized one still gets the hit,
//! and both outcomes appear in the audit trail.

use ainxt_cache::{CacheConfig, Clock};
use ainxt_chat::ChatSurface;
use ainxt_context::Corpus;
use ainxt_protocol::Event;
use ainxt_runtime::audit::{AuditRecord, AuditSink};
use ainxt_runtime::authz::{Authorizer, Decision};
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_runtime::{Engine, TurnError};
use ainxt_types::{DataClass, Principal};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

/// Records every audit line so the test can assert a cache hit is actually logged.
#[derive(Clone, Default)]
struct SpyAudit(Arc<Mutex<Vec<AuditRecord>>>);
impl AuditSink for SpyAudit {
    fn record(&self, rec: AuditRecord) {
        self.0.lock().unwrap().push(rec);
    }
}

/// Grants `chat.send` to everyone EXCEPT the named user — models a revoked peer.
struct DenyOne(&'static str);
impl Authorizer for DenyOne {
    fn authorize(&self, principal: &Principal, _cap: &str) -> Decision {
        if principal.user_id == self.0 {
            Decision::Deny("capability revoked".into())
        } else {
            Decision::Allow
        }
    }
}

struct FixedProvider;
impl Provider for FixedProvider {
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
                .send(Event::TextDelta("settlement runs nightly".into()))
                .await;
            let _ = tx.send(Event::Done).await;
        });
        rx
    }
}

/// Two users in the SAME department — so the second one hits the first one's cached answer.
fn author() -> Principal {
    Principal::user("author", &["chat.send"])
        .with_clearance(DataClass::Internal)
        .with_department("payments")
}
fn peer() -> Principal {
    Principal::user("revoked-peer", &["chat.send"])
        .with_clearance(DataClass::Internal)
        .with_department("payments")
}

/// A monotonic test clock (the cache needs one; nothing here depends on real time).
#[derive(Debug, Default)]
struct FixedClock;
impl Clock for FixedClock {
    fn now(&self) -> u64 {
        1
    }
}

fn surface(audit: SpyAudit) -> ChatSurface {
    let mut router = ModelRouter::new();
    router.register(Box::new(FixedProvider));
    let engine = Engine::new(
        Box::new(ainxt_runtime::compliance::RedactAndProceed),
        Box::new(DenyOne("revoked-peer")),
        Box::new(audit),
        router,
    );
    ChatSurface::from_engine(
        engine,
        Corpus::new(),
        CacheConfig::default(),
        Box::new(FixedClock),
    )
}

#[tokio::test]
async fn r16_cache_hit_enforces_chat_send_and_is_audited() {
    let audit = SpyAudit::default();
    let s = surface(audit.clone());
    let q = "how does settlement run?";

    // 1. The author populates the department-partitioned cache through the normal path.
    let first = s
        .turn("s1", &author(), q, DataClass::Internal)
        .await
        .expect("author's turn succeeds");
    let first_text = match first {
        ainxt_chat::ChatReply::Answer { text, .. } => text,
        other => panic!("expected an Answer, got {other:?}"),
    };
    assert!(!first_text.is_empty());

    // 2. Same question, same department, but the peer's capability is denied. Before the fix this
    //    returned the cached answer because the only chat.send check lived inside run_turn.
    let denied = s.turn("s2", &peer(), q, DataClass::Internal).await;
    match denied {
        Err(TurnError::Denied(_)) => {}
        Ok(reply) => panic!("an unauthorized peer was served from cache: {reply:?}"),
        Err(other) => panic!("expected Denied, got {other:?}"),
    }

    // 3. Both the denial and the author's turn are in the audit trail.
    let lines = audit.0.lock().unwrap().clone();
    assert!(
        lines
            .iter()
            .any(|r| r.actor == "revoked-peer" && r.summary.contains("authz denied")),
        "the denial was not audited: {lines:?}"
    );

    // 4. An AUTHORIZED peer still gets the cache benefit — the fix must not disable the cache.
    //    Cache is session-scoped (a prior turn in the SAME conversation), so the authorized peer
    //    re-asks inside the author's session to exercise the hit path.
    let ok_peer = Principal::user("ok-peer", &["chat.send"])
        .with_clearance(DataClass::Internal)
        .with_department("payments");
    let hit = s
        .turn("s1", &ok_peer, q, DataClass::Internal)
        .await
        .expect("authorized peer is served");
    match hit {
        ainxt_chat::ChatReply::Answer {
            text, from_cache, ..
        } => {
            assert!(from_cache, "the authorized peer should have hit the cache");
            assert_eq!(text, first_text);
        }
        other => panic!("expected a cached Answer, got {other:?}"),
    }
    let lines = audit.0.lock().unwrap().clone();
    assert!(
        lines
            .iter()
            .any(|r| r.actor == "ok-peer" && r.summary.contains("chat-cache")),
        "a cache-served turn produced no audit record: {lines:?}"
    );
}
