// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R15 (data-surfaces-artifacts, low): the SEMANTIC (paraphrase) cache tier — built and unit-tested
//! in `ainxt-cache` (`ResponseCache::get_tiered` / `Embedder` / `HashEmbedder`) — is wired onto the
//! CHAT LIVE PATH: [`ChatSurface::with_embedder`] plumbs it into both the non-streaming `turn()` API
//! and the served [`TurnHandler::handle_turn`] the daemon's `SessionManager` actually drives.
//!
//! Before this round `ChatSurface` only ever called `get_exact` — a re-worded repeat of a cached
//! prompt ("upi daily volume" vs "volume daily upi") always re-ran the full grounded pipeline (a
//! fresh provider call), even though the pure paraphrase-matching tier already existed one crate
//! away. `HashEmbedder` (the dependency-free bag-of-tokens embedder, the OFFLINE default behind the
//! `Embedder` seam) makes two token-identical-but-reordered queries land at cosine similarity 1.0, so
//! this is fully exercisable with zero infra.
//!
//! FAIL-BEFORE / contrast: `r15_semantic_cache_tier_inert_without_embedder` shows the pre-wiring
//! default (`ChatSurface::from_engine`, no embedder) still re-invokes the provider on the reordered
//! query — proving the tier is genuinely OFF unless a surface opts in (no behavior change for every
//! existing constructor / test).
//!
//! PASS-AFTER: `r15_semantic_cache_tier_hits_on_paraphrase_when_embedder_wired` shows the SAME
//! surface, wired with `.with_embedder(Arc::new(HashEmbedder::default()))`, serves the reordered query
//! straight from the cache (provider invoked exactly once across both turns) on the served
//! `TurnHandler` path — the same seam `ainxt-runtimed` wires for the daemon.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use ainxt_cache::{CacheConfig, FixedClock, HashEmbedder};
use ainxt_chat::ChatSurface;
use ainxt_compliance::StrongRedactor;
use ainxt_context::Corpus;
use ainxt_protocol::{Event, Request};
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_runtime::{CancelToken, Engine, InMemoryAudit, RbacAuthorizer, TurnHandler};
use ainxt_types::{DataClass, Principal};
use tokio::sync::mpsc;

/// A provider that counts every invocation (so a test can assert whether the grounded pipeline was
/// re-run) and always answers the same canned text — the exact text served is irrelevant; what the
/// test proves is whether the SECOND turn ever reaches this provider at all.
struct CountingProvider(Arc<AtomicUsize>);
impl Provider for CountingProvider {
    fn id(&self) -> &str {
        "counting"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, _prompt: &str) -> mpsc::Receiver<Event> {
        self.0.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = mpsc::channel(8);
        tokio::spawn(async move {
            let _ = tx
                .send(Event::TextDelta("upi transaction volume: 14B/mo".into()))
                .await;
            let _ = tx.send(Event::Done).await;
        });
        rx
    }
}

fn cache_cfg() -> CacheConfig {
    // A permissive-but-real threshold (below HashEmbedder's exact-permutation cosine of 1.0, above
    // noise) — the tier only fires because the two queries share the identical token multiset.
    CacheConfig {
        capacity: 128,
        ttl_ticks: 1_000,
        semantic_threshold: 0.9,
    }
}

fn build_surface(calls: Arc<AtomicUsize>, with_semantic_tier: bool) -> ChatSurface {
    let mut router = ModelRouter::new();
    router.register(Box::new(CountingProvider(calls)));
    let engine = Engine::new(
        Box::new(StrongRedactor::new()),
        Box::new(RbacAuthorizer),
        Box::new(InMemoryAudit::default()),
        router,
    );
    let surface =
        ChatSurface::from_engine(engine, Corpus::new(), cache_cfg(), Box::new(FixedClock(0)));
    if with_semantic_tier {
        surface.with_embedder(Arc::new(HashEmbedder::default()))
    } else {
        surface
    }
}

fn user() -> Principal {
    Principal::user("analyst", &["chat.send"]).with_clearance(DataClass::Public)
}

/// Drive one served turn through the EXACT `TurnHandler` seam the daemon's `SessionManager` uses,
/// draining the sink and returning the final answer text.
async fn drive(surface: &ChatSurface, turn_id: &str, input: &str) -> String {
    let principal = user();
    let req = Request::chat("s-sem", turn_id, input, DataClass::Public);
    let cancel = CancelToken::new();
    let (tx, mut rx) = mpsc::channel::<Event>(16);
    let summary = surface
        .handle_turn(&principal, &req, tx, &cancel)
        .await
        .expect("turn completes");
    while rx.recv().await.is_some() {}
    summary.final_text
}

#[tokio::test(flavor = "multi_thread")]
async fn r15_semantic_cache_tier_hits_on_paraphrase_when_embedder_wired() {
    let calls = Arc::new(AtomicUsize::new(0));
    let surface = build_surface(calls.clone(), true);

    let first = drive(&surface, "t1", "what is upi daily volume").await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "first turn is a genuine cache miss"
    );

    // A token-identical REORDERING — not equal after case/whitespace normalization, so the
    // exact/normalized tier misses; the SEMANTIC tier (HashEmbedder cosine == 1.0 on a permutation)
    // is what serves this without a second provider call.
    let second = drive(&surface, "t2", "volume daily upi what is").await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "a re-worded (token-permuted) repeat must hit the SEMANTIC cache tier on the served \
         TurnHandler path, not re-invoke the provider"
    );
    assert_eq!(
        second, first,
        "the semantic hit must serve the SAME cached answer as the original turn"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn r15_semantic_cache_tier_inert_without_embedder() {
    // Contrast / fail-before: the pre-wiring default (no embedder) — every existing constructor —
    // must NOT change behavior. The reordered query is a genuine miss and re-invokes the provider.
    let calls = Arc::new(AtomicUsize::new(0));
    let surface = build_surface(calls.clone(), false);

    let _first = drive(&surface, "t1", "what is upi daily volume").await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let _second = drive(&surface, "t2", "volume daily upi what is").await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "without an embedder wired the surface must degrade to exact/normalized-only — no behavior \
         change for a surface that never opts in"
    );
}
