// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R16 CRITICAL (serving-ops) — "DPDP erasure ack is vacuous": the daemon's DSAR/right-to-erasure
//! organ (`ainxt_serving::erasure::TieredCacheErasure`) used to own its OWN private answer cache
//! (built fresh by `TieredCacheErasure::new`), completely disconnected from the LIVE
//! `PartitionedCache` a served [`ChatSurface`] actually reads/writes on every turn
//! (`ChatSurface`'s own `cache: Arc<Mutex<PartitionedCache>>` field). A right-to-erasure request
//! therefore drained an organ no served turn had ever populated: the platform told a data subject
//! their data was erased while their cached answer kept being served, byte-for-byte, forever.
//!
//! The fix: [`ChatSurface::answer_cache_handle`] hands out a clone of the SAME `Arc` the surface
//! caches into, and [`TieredCacheErasure::with_shared_answer_cache`] builds the erasure organ
//! directly over that handle — so the organ IS the live cache, not a second one. The daemon
//! composition root (`ainxt-runtimed::assemble_chat` / `assemble_chat_governed` / `assemble_surface`
//! + `assemble_full` / `mounts::build_erasure`) wires this once at assembly time, before the
//! `ChatSurface` is erased behind `Arc<dyn TurnHandler>`.
//!
//! This test drives the actual served path end-to-end at the lowest level that proves the fix:
//! [`ChatSurface::turn`] (exactly what `/v1/chat` and `TurnHandler::handle_turn` call) populates the
//! cache, and [`TieredCacheErasure::erase_principal`] (exactly what `POST /v1/erasure` calls) purges
//! it — over ONE shared instance, wired exactly like the composition root wires it.
//!
//! FAIL-BEFORE: `ChatSurface::answer_cache_handle` and
//! `TieredCacheErasure::with_shared_answer_cache` did not exist before this fix — this file would not
//! compile against the prior code (see the task report for the exact `cargo build` error captured by
//! temporarily reverting the wiring). PASS-AFTER: the erased subject's cached answer is gone from the
//! SAME instance the served chat path reads, and a repeat turn is no longer served from cache.

use ainxt_cache::{CacheConfig, Clock};
use ainxt_chat::{ChatReply, ChatSurface};
use ainxt_context::Corpus;
use ainxt_protocol::Event;
use ainxt_runtime::audit::InMemoryAudit;
use ainxt_runtime::authz::RbacAuthorizer;
use ainxt_runtime::compliance::RedactAndProceed;
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_runtime::Engine;
use ainxt_serving::erasure::TieredCacheErasure;
use ainxt_types::{DataClass, Principal};
use tokio::sync::mpsc;

/// A fixed, deterministic model response — nothing here depends on a live provider.
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
                .send(Event::TextDelta("your UPI limit is 1 lakh".into()))
                .await;
            let _ = tx.send(Event::Done).await;
        });
        rx
    }
}

#[derive(Debug, Default)]
struct FixedClock;
impl Clock for FixedClock {
    fn now(&self) -> u64 {
        1
    }
}

/// A REAL `ChatSurface` over a real `Engine` — same shape as the composition root's
/// `build_chat_surface_wired_authz` (offline provider swapped in for determinism).
fn surface() -> ChatSurface {
    let mut router = ModelRouter::new();
    router.register(Box::new(FixedProvider));
    let engine = Engine::new(
        Box::new(RedactAndProceed),
        Box::new(RbacAuthorizer),
        Box::new(InMemoryAudit::default()),
        router,
    );
    ChatSurface::from_engine(
        engine,
        Corpus::new(),
        CacheConfig::default(),
        Box::new(FixedClock),
    )
}

/// `alice` has NO department: for `DataClass::Internal` (the cacheable-by-default class) an unknown
/// department falls back to PER-USER partition scope (`ainxt_serving::cache_isolation::
/// principal_scope`: "a missing department must never widen the sharing boundary, only narrow it") —
/// exactly the scope `TieredCacheErasure::erase_principal("alice")` targets. This is deliberately the
/// realistic "erase one data subject's own cached answer" case the DPDP finding is about.
fn alice() -> Principal {
    Principal::user("alice", &["chat.send"]).with_clearance(DataClass::Internal)
}

#[tokio::test]
async fn r16_right_to_erasure_purges_the_cache_the_served_chat_path_actually_reads() {
    let chat = surface();

    // ---- THE FIX, exactly as the composition root wires it -----------------------------------
    // 1. Take a handle to the surface's OWN live cache (the one `ChatSurface::turn` reads/writes).
    let handle = chat.answer_cache_handle();
    // 2. Build the daemon's DSAR/right-to-erasure organ directly OVER that handle — not a second,
    //    private `PartitionedCache` (which is what `TieredCacheErasure::new` would give it).
    let mut erasure = TieredCacheErasure::with_shared_answer_cache(handle, CacheConfig::default());

    let q = "what is my UPI limit?";

    // Precondition: the shared organ starts empty — nothing has been served yet.
    assert_eq!(
        erasure.live_answer_entries(),
        0,
        "precondition: the erasure organ's answer tier starts unpopulated"
    );

    // ---- (1) SEED: a real served turn populates the LIVE cache -------------------------------
    let first = chat
        .turn("s1", &alice(), q, DataClass::Internal)
        .await
        .expect("alice's turn succeeds");
    let text = match first {
        ChatReply::Answer {
            text, from_cache, ..
        } => {
            assert!(
                !from_cache,
                "first turn must be a fresh model answer, not a cache hit"
            );
            text
        }
        other => panic!("expected an Answer, got {other:?}"),
    };
    assert!(!text.is_empty());

    // THE REACHABILITY PROOF: the erasure organ's answer-tier count moved as a pure side effect of
    // the SERVED CHAT TURN — the two are the SAME instance, not two disconnected caches.
    assert_eq!(
        erasure.live_answer_entries(),
        1,
        "the served turn's cache write must be visible from the erasure organ — same instance"
    );

    // Sanity/regression: caching still works normally — a repeat turn in the SAME session is
    // served from cache. (Cache is session-scoped: a hit requires the same session id.)
    let second = chat
        .turn("s1", &alice(), q, DataClass::Internal)
        .await
        .expect("alice's second turn succeeds");
    match second {
        ChatReply::Answer {
            text: t2,
            from_cache,
            ..
        } => {
            assert!(from_cache, "a repeat prompt must hit the cache");
            assert_eq!(t2, text);
        }
        other => panic!("expected a cached Answer, got {other:?}"),
    }
    assert_eq!(
        erasure.live_answer_entries(),
        1,
        "a cache HIT must not create a second entry"
    );

    // ---- (2) RUN THE ERASURE -------------------------------------------------------------------
    let ack = erasure.erase_principal("alice");
    assert!(
        ack.answer_partitions_purged >= 1,
        "the erasure cascade must report at least one purged answer-cache partition, got {ack:?}"
    );
    assert!(ack.touched_any_tier());

    // ---- (3) THE PROOF: the cached entry is GONE -----------------------------------------------
    // (a) Gone from the organ's own count.
    assert_eq!(
        erasure.live_answer_entries(),
        0,
        "alice's cached answer must be gone from the erasure organ after erase_principal"
    );

    // (b) Gone from the perspective of the SERVED CHAT PATH ITSELF — the strongest possible
    //     assertion: a repeat of the exact same turn (same session) is no longer served from
    //     cache, because the entry the served path would have hit was actually deleted (not
    //     merely uncounted).
    let third = chat
        .turn("s1", &alice(), q, DataClass::Internal)
        .await
        .expect("alice's post-erasure turn succeeds");
    match third {
        ChatReply::Answer { from_cache, .. } => {
            assert!(
                !from_cache,
                "a DPDP-erased subject's prior answer must never be served from cache again"
            );
        }
        other => panic!("expected a fresh (non-cached) Answer, got {other:?}"),
    }
    // And this fresh turn repopulated the (still-shared, still-live) organ — the cache and the
    // served surface are, after erasure too, still provably the same instance.
    assert_eq!(erasure.live_answer_entries(), 1);
}

#[tokio::test]
async fn r16_erasure_never_widens_to_a_different_subject() {
    // The fix must not turn "reach the live cache" into "reach every principal's cache" — erasing
    // alice must leave bob's cached answer intact (SERVING_OPS.md §6 narrowing-only guarantee),
    // proven over the SAME shared instance used above.
    let chat = surface();
    let handle = chat.answer_cache_handle();
    let mut erasure = TieredCacheErasure::with_shared_answer_cache(handle, CacheConfig::default());

    let bob = Principal::user("bob", &["chat.send"]).with_clearance(DataClass::Internal);
    let q = "what is my UPI limit?";

    chat.turn("s1", &alice(), q, DataClass::Internal)
        .await
        .unwrap();
    chat.turn("s2", &bob, q, DataClass::Internal).await.unwrap();
    assert_eq!(
        erasure.live_answer_entries(),
        2,
        "alice and bob each cached their own answer"
    );

    erasure.erase_principal("alice");
    assert_eq!(
        erasure.live_answer_entries(),
        1,
        "only alice's entry is purged"
    );

    // Bob's repeat turn (same session s2) still hits the cache — his data was never touched.
    let bob_again = chat.turn("s2", &bob, q, DataClass::Internal).await.unwrap();
    match bob_again {
        ChatReply::Answer { from_cache, .. } => {
            assert!(from_cache, "bob's cache entry must survive alice's erasure")
        }
        other => panic!("expected a cached Answer, got {other:?}"),
    }
}
