// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R11 (gap I) — the SEMANTIC / prompt cache paraphrase-matching tier, made drivable on the LIVE
//! path. The `get_semantic` primitive existed, but the served path only ever called `get_exact`
//! (passing `None` for the embedding), so a paraphrase of a cached prompt always missed and paid for
//! a fresh model call. This test proves the live-path wiring: an [`Embedder`] seam produces the query
//! embedding and [`ResponseCache::get_tiered`] / [`PartitionedCache::get_tiered`] consult exact→then
//! →semantic in one call, so a paraphrase HITS above the configured cosine threshold.
//!
//! Fail-before/pass-after: `Embedder` / `HashEmbedder` / `get_tiered` / `CacheHit` did not exist, so
//! this crate would not compile. INFRA note: producing a real semantic embedding on the live path is
//! the embed-service seam (this test injects the deterministic [`HashEmbedder`]).

use ainxt_cache::{
    CacheConfig, Embedder, HashEmbedder, HitTier, Partition, PartitionedCache, ResponseCache,
};

fn cfg(threshold: f64) -> CacheConfig {
    CacheConfig {
        capacity: 128,
        ttl_ticks: 10_000,
        semantic_threshold: threshold,
    }
}

#[test]
fn r11_semantic_paraphrase_hits_where_exact_misses() {
    let embedder = HashEmbedder::default();
    // Threshold tuned to the offline bag-of-tokens embedder: a real reset-PIN paraphrase shares ~5
    // of ~7 tokens (cosine ≈ 0.67), well above an unrelated query (≈ 0), so 0.60 separates them.
    let mut c = ResponseCache::new(cfg(0.60));

    let canonical = "how do i reset my UPI PIN";
    let answer = "Open the app, go to settings, and reset the UPI PIN.";
    c.put(canonical, answer, embedder.embed(canonical), 0);

    // A paraphrase: different word order + filler, same tokens mostly. Exact tier misses.
    let paraphrase = "how can i reset the UPI PIN please";
    assert_eq!(
        c.get_exact(paraphrase, 1),
        None,
        "the paraphrase is not a verbatim key — exact tier must miss"
    );

    // The tiered lookup consults the semantic tier with the embed-service embedding → HIT.
    let hit = c
        .get_tiered(paraphrase, embedder.embed(paraphrase).as_deref(), 2)
        .expect("paraphrase must hit the semantic tier");
    assert_eq!(hit.tier, HitTier::Semantic);
    assert_eq!(hit.value, answer);
    assert!(hit.similarity.unwrap() >= 0.60);
    assert_eq!(c.stats().semantic_hits, 1);
}

#[test]
fn r11_tiered_prefers_exact_and_degrades_without_embedding() {
    let embedder = HashEmbedder::default();
    let mut c = ResponseCache::new(cfg(0.80));
    let key = "what is imps";
    c.put(
        key,
        "IMPS is an instant interbank transfer.",
        embedder.embed(key),
        0,
    );

    // Exact wins (cheapest tier), similarity absent.
    let hit = c
        .get_tiered(key, embedder.embed(key).as_deref(), 1)
        .unwrap();
    assert_eq!(hit.tier, HitTier::Exact);
    assert!(hit.similarity.is_none());

    // With NO embedding (embed service unavailable / semantic disabled) a non-exact query degrades
    // safely to a miss — never a fresh model call masquerading as a hit, never a cross-scope read.
    assert!(c
        .get_tiered("tell me about imps transfers", None, 2)
        .is_none());
}

#[test]
fn r11_unrelated_query_does_not_falsely_hit() {
    let embedder = HashEmbedder::default();
    let mut c = ResponseCache::new(cfg(0.80));
    let key = "how do i reset my UPI PIN";
    c.put(key, "reset instructions", embedder.embed(key), 0);

    // A totally unrelated query must fall below the threshold → miss (no false paraphrase hit).
    let unrelated = "what were the settlement volumes last quarter";
    assert!(c
        .get_tiered(unrelated, embedder.embed(unrelated).as_deref(), 1)
        .is_none());
    assert_eq!(c.stats().semantic_misses, 1);
}

#[test]
fn r11_partitioned_tiered_never_crosses_scope() {
    let embedder = HashEmbedder::default();
    let mut c = PartitionedCache::new(cfg(0.70));
    let a = Partition::new("tenant-a|internal");
    let b = Partition::new("tenant-b|internal");

    let key = "quarterly settlement summary";
    c.put(&a, key, "TENANT-A ANSWER", embedder.embed(key), 0);

    // Same paraphrase, but a DIFFERENT partition must never reach tenant-a's entry.
    let paraphrase = "summary of quarterly settlement";
    assert!(
        c.get_tiered(&b, paraphrase, embedder.embed(paraphrase).as_deref(), 1)
            .is_none(),
        "semantic tier must not cross partitions"
    );

    // In its own partition the paraphrase hits.
    let hit = c
        .get_tiered(&a, paraphrase, embedder.embed(paraphrase).as_deref(), 2)
        .expect("same-partition paraphrase hit");
    assert_eq!(hit.tier, HitTier::Semantic);
    assert_eq!(hit.value, "TENANT-A ANSWER");
}
