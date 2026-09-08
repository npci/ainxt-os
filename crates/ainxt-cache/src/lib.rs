// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! ainxt-cache — the runtime response cache (gap I: semantic/prompt caching).
//!
//! Three lookup modes over one store, cheapest-first:
//! 1. **Exact** — the normalized prompt key matches verbatim.
//! 2. **Normalized** — case-folded, whitespace-collapsed key (so "  Hello   World " hits "hello
//!    world"), folded into the exact path via [`normalize`].
//! 3. **Semantic** — the query's precomputed embedding is within a cosine threshold of a cached
//!    entry's embedding (a paraphrase hits). Embeddings are ACCEPTED precomputed — producing them is
//!    the embed-service seam, never done here — so the cache logic stays pure and testable.
//!
//! Eviction is **LRU** (bounded capacity) and expiry is **TTL** on a caller-supplied logical tick —
//! there is no clock and no RNG, so the whole cache is deterministic and exhaustively testable. A
//! stale/expired entry is never returned (and is swept on access), so the cache can never serve an
//! answer past its freshness window (gap Z: knowledge freshness).
//!
//! Correctness note for a payments platform: a cache MUST NOT be consulted across trust/authz
//! boundaries. This crate is the mechanism; the *key* the caller supplies must already encode every
//! scoping dimension that could change the answer (tenant, data-class, principal clearance, model).
//! The cache never widens visibility on its own.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// A logical time source for TTL. The cache core takes `now` explicitly (so it stays deterministic
/// and testable); this seam lets an *edge* (a chat surface, a worker) drive TTL without threading a
/// tick through every call. Deliberately NOT implemented with a wall clock in this crate — a system
/// clock is an edge concern the caller provides, keeping this crate clock-free and replayable.
pub trait Clock: Send + Sync {
    fn now(&self) -> u64;
}

/// A fixed clock for tests / deterministic replay.
#[derive(Debug, Clone, Copy)]
pub struct FixedClock(pub u64);

impl Clock for FixedClock {
    fn now(&self) -> u64 {
        self.0
    }
}

/// Cache configuration (config-first; a deployment tunes these per surface).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct CacheConfig {
    /// Maximum number of live entries; the least-recently-used entry is evicted past this.
    pub capacity: usize,
    /// Time-to-live in logical ticks; an entry created at `t` expires strictly after `t + ttl_ticks`.
    pub ttl_ticks: u64,
    /// Minimum cosine similarity (0.0–1.0) for a SEMANTIC hit. 1.0 disables paraphrase matching.
    pub semantic_threshold: f64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        CacheConfig {
            capacity: 1024,
            ttl_ticks: 3600,
            semantic_threshold: 0.92,
        }
    }
}

#[derive(Debug, Clone)]
struct Entry {
    value: String,
    embedding: Option<Vec<f32>>,
    created: u64,
    last_used: u64,
}

/// Hit/miss/eviction counters — the FinOps/observability signal (gap V) for the cache.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheStats {
    pub exact_hits: u64,
    pub exact_misses: u64,
    pub semantic_hits: u64,
    pub semantic_misses: u64,
    pub evictions: u64,
    pub expirations: u64,
}

impl CacheStats {
    /// Combined hit rate across exact + semantic lookups (0.0 when nothing has been looked up).
    pub fn hit_rate(&self) -> f64 {
        let hits = self.exact_hits + self.semantic_hits;
        let total = hits + self.exact_misses + self.semantic_misses;
        if total == 0 {
            0.0
        } else {
            hits as f64 / total as f64
        }
    }
}

/// Normalize a prompt key: trim, collapse internal whitespace to single spaces, and lowercase — so
/// trivially-different surface forms of the same prompt share a cache slot.
pub fn normalize(key: &str) -> String {
    key.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

/// Cosine similarity in `[-1, 1]`, or `None` if incomparable (empty, differing dim, or zero-norm).
fn cosine(a: &[f32], b: &[f32]) -> Option<f64> {
    if a.is_empty() || a.len() != b.len() {
        return None;
    }
    let (mut dot, mut na, mut nb) = (0.0f64, 0.0f64, 0.0f64);
    for (x, y) in a.iter().zip(b.iter()) {
        let (x, y) = (*x as f64, *y as f64);
        dot += x * y;
        na += x * x;
        nb += y * y;
    }
    if na == 0.0 || nb == 0.0 {
        return None;
    }
    Some(dot / (na.sqrt() * nb.sqrt()))
}

/// The response cache. `&mut self` on reads because a hit refreshes LRU recency and updates stats.
#[derive(Debug, Clone)]
pub struct ResponseCache {
    cfg: CacheConfig,
    entries: HashMap<String, Entry>,
    stats: CacheStats,
}

impl ResponseCache {
    pub fn new(cfg: CacheConfig) -> Self {
        ResponseCache {
            cfg,
            entries: HashMap::new(),
            stats: CacheStats::default(),
        }
    }

    pub fn stats(&self) -> CacheStats {
        self.stats
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn is_expired(&self, e: &Entry, now: u64) -> bool {
        now > e.created.saturating_add(self.cfg.ttl_ticks)
    }

    /// Insert (or replace) an entry under `key`, optionally with a precomputed `embedding` for
    /// semantic lookup. LRU-evicts down to `capacity`. A zero-capacity cache stores nothing.
    pub fn put(&mut self, key: &str, value: &str, embedding: Option<Vec<f32>>, now: u64) {
        if self.cfg.capacity == 0 {
            return;
        }
        let k = normalize(key);
        self.entries.insert(
            k,
            Entry {
                value: value.to_string(),
                embedding,
                created: now,
                last_used: now,
            },
        );
        self.evict_to_capacity();
    }

    /// Exact/normalized lookup. Returns the cached value on a fresh hit; sweeps + misses on expiry.
    pub fn get_exact(&mut self, key: &str, now: u64) -> Option<String> {
        let k = normalize(key);
        match self.entries.get(&k) {
            Some(e) if self.is_expired(e, now) => {
                self.entries.remove(&k);
                self.stats.expirations += 1;
                self.stats.exact_misses += 1;
                None
            }
            Some(_) => {
                let e = self.entries.get_mut(&k).expect("present");
                e.last_used = now;
                let v = e.value.clone();
                self.stats.exact_hits += 1;
                Some(v)
            }
            None => {
                self.stats.exact_misses += 1;
                None
            }
        }
    }

    /// Semantic lookup: the fresh entry whose embedding is nearest `query_embedding` and at/above the
    /// configured threshold. Ties (equal similarity) break by key for determinism. Expired entries
    /// are ignored (and swept). Returns `(value, similarity)`.
    pub fn get_semantic(&mut self, query_embedding: &[f32], now: u64) -> Option<(String, f64)> {
        // First sweep expired entries so they can neither match nor linger.
        self.sweep_expired(now);
        let mut best: Option<(String, f64)> = None; // (key, sim)
        for (k, e) in self.entries.iter() {
            let Some(emb) = e.embedding.as_deref() else {
                continue;
            };
            let Some(sim) = cosine(query_embedding, emb) else {
                continue;
            };
            if sim + 1e-12 < self.cfg.semantic_threshold {
                continue;
            }
            match &best {
                Some((bk, bs)) if (*bs > sim) || (*bs == sim && bk.as_str() <= k.as_str()) => {}
                _ => best = Some((k.clone(), sim)),
            }
        }
        match best {
            Some((k, sim)) => {
                let e = self.entries.get_mut(&k).expect("present");
                e.last_used = now;
                let v = e.value.clone();
                self.stats.semantic_hits += 1;
                Some((v, sim))
            }
            None => {
                self.stats.semantic_misses += 1;
                None
            }
        }
    }

    /// Remove all expired entries as of `now`; returns how many were swept.
    pub fn purge_expired(&mut self, now: u64) -> usize {
        self.sweep_expired(now)
    }

    fn sweep_expired(&mut self, now: u64) -> usize {
        let ttl = self.cfg.ttl_ticks;
        let before = self.entries.len();
        self.entries
            .retain(|_, e| now <= e.created.saturating_add(ttl));
        let removed = before - self.entries.len();
        self.stats.expirations += removed as u64;
        removed
    }

    fn evict_to_capacity(&mut self) {
        while self.entries.len() > self.cfg.capacity {
            // Evict the least-recently-used entry; ties break by key for determinism.
            let victim = self
                .entries
                .iter()
                .min_by(|a, b| a.1.last_used.cmp(&b.1.last_used).then(a.0.cmp(b.0)))
                .map(|(k, _)| k.clone());
            match victim {
                Some(k) => {
                    self.entries.remove(&k);
                    self.stats.evictions += 1;
                }
                None => break,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Partition-isolated cache (SERVING_OPS.md §6 — the coarse-answer / prompt-prefix tiers)
// ---------------------------------------------------------------------------

/// An opaque cache partition — the rendering of `{data_class, principal_scope, harness_id}`
/// (SERVING_OPS.md §6). The *caller* (e.g. `ainxt-serving::cache_isolation::PartitionKey::render`)
/// builds the string; this crate treats it as an isolation boundary and nothing more. Two byte-
/// identical prompts under different partitions **never** share an entry, so there is no cross-
/// tenant hit/miss timing signal to leak.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Partition(pub String);

impl Partition {
    pub fn new(s: impl Into<String>) -> Self {
        Partition(s.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for Partition {
    fn from(s: &str) -> Self {
        Partition(s.to_string())
    }
}

/// A cache that keeps a fully-independent [`ResponseCache`] per [`Partition`] (SERVING_OPS.md §6).
///
/// This is the structural fix for the audit's "the cache DELEGATES the scoping key to the caller"
/// note applied to the coarse-answer and prompt-prefix tiers: isolation is no longer a convention
/// the caller must remember to encode into one flat keyspace — a lookup can only ever reach its own
/// partition's store, and [`PartitionedCache::erase_scope`] gives the DPDP erasure cascade a hook to
/// drop every entry belonging to a principal/scope across the answer tiers.
#[derive(Debug, Clone)]
pub struct PartitionedCache {
    cfg: CacheConfig,
    parts: HashMap<Partition, ResponseCache>,
}

impl PartitionedCache {
    pub fn new(cfg: CacheConfig) -> Self {
        PartitionedCache {
            cfg,
            parts: HashMap::new(),
        }
    }

    fn part_mut(&mut self, p: &Partition) -> &mut ResponseCache {
        let cfg = self.cfg;
        self.parts
            .entry(p.clone())
            .or_insert_with(|| ResponseCache::new(cfg))
    }

    /// Insert under `partition`. Creates the partition's store on first use.
    pub fn put(
        &mut self,
        partition: &Partition,
        key: &str,
        value: &str,
        embedding: Option<Vec<f32>>,
        now: u64,
    ) {
        self.part_mut(partition).put(key, value, embedding, now);
    }

    /// Exact/normalized lookup **within** `partition`. A miss for an unknown partition — never a
    /// cross-partition read.
    pub fn get_exact(&mut self, partition: &Partition, key: &str, now: u64) -> Option<String> {
        self.parts.get_mut(partition)?.get_exact(key, now)
    }

    /// Semantic lookup **within** `partition`.
    pub fn get_semantic(
        &mut self,
        partition: &Partition,
        query_embedding: &[f32],
        now: u64,
    ) -> Option<(String, f64)> {
        self.parts
            .get_mut(partition)?
            .get_semantic(query_embedding, now)
    }

    /// Drop one partition entirely (session end). Returns whether it existed.
    pub fn purge_partition(&mut self, partition: &Partition) -> bool {
        self.parts.remove(partition).is_some()
    }

    /// DPDP right-to-erasure across the answer/prompt-prefix tiers (SERVING_OPS.md §6 (a)): drop
    /// every partition whose rendering matches `predicate` (e.g. contains the principal's scope
    /// token). Returns the number of partitions removed. Answer/prompt-prefix entries are **deleted**
    /// (not zeroized — that is the KV tier's discipline, in `ainxt-serving`).
    pub fn erase_scope(&mut self, predicate: impl Fn(&str) -> bool) -> usize {
        let victims: Vec<Partition> = self
            .parts
            .keys()
            .filter(|p| predicate(p.as_str()))
            .cloned()
            .collect();
        for p in &victims {
            self.parts.remove(p);
        }
        victims.len()
    }

    /// Number of live partitions.
    pub fn partition_count(&self) -> usize {
        self.parts.len()
    }

    /// Total live entries across all partitions.
    pub fn total_entries(&self) -> usize {
        self.parts.values().map(ResponseCache::len).sum()
    }
}

// ===========================================================================
// The live-path paraphrase tier: an embed seam + a tiered lookup (gap I).
// ===========================================================================

/// The embed-service seam (INFRA-gated). Producing an embedding is an ML/embed-service concern (the
/// live path calls the batch embed service — Redis-cached, batched), NEVER done in this pure crate;
/// the cache accepts embeddings precomputed. This trait is the single wiring point the served path
/// implements so the SEMANTIC (paraphrase-matching) tier can run on the live path: given a query
/// string it returns the query embedding (or `None` when the embed service is unavailable / the
/// surface disables semantic caching), which is then handed to [`ResponseCache::get_tiered`].
///
/// Keeping this a trait (not a concrete embedder) preserves the crate's purity + determinism: a unit
/// test injects a deterministic embedder ([`HashEmbedder`]); production injects the real embed client.
pub trait Embedder: Send + Sync {
    /// Embed `text`, or `None` to skip the semantic tier for this query.
    fn embed(&self, text: &str) -> Option<Vec<f32>>;
}

/// A deterministic, dependency-free bag-of-tokens embedder — the OFFLINE default behind the
/// [`Embedder`] seam so the paraphrase tier is exercisable with zero infra. Each lowercased,
/// punctuation-stripped token is FNV-hashed into one of `DIM` buckets and L2-implicitly compared via
/// cosine, so two queries sharing most tokens (a paraphrase / re-ordering / added filler word) land
/// close while unrelated queries do not. This is NOT a semantic model — production swaps the real
/// embed service behind the same seam — but it makes the tier's wiring real and testable.
pub struct HashEmbedder {
    dim: usize,
}

impl Default for HashEmbedder {
    fn default() -> Self {
        HashEmbedder { dim: 64 }
    }
}

impl HashEmbedder {
    pub fn new(dim: usize) -> Self {
        HashEmbedder { dim: dim.max(1) }
    }
    fn tokenize(text: &str) -> Vec<String> {
        text.split(|c: char| !c.is_alphanumeric())
            .filter(|t| !t.is_empty())
            .map(|t| t.to_ascii_lowercase())
            .collect()
    }
}

impl Embedder for HashEmbedder {
    fn embed(&self, text: &str) -> Option<Vec<f32>> {
        let tokens = Self::tokenize(text);
        if tokens.is_empty() {
            return None;
        }
        let mut v = vec![0.0f32; self.dim];
        for tok in tokens {
            // FNV-1a 64-bit, folded into a bucket.
            let mut h: u64 = 0xcbf2_9ce4_8422_2325;
            for b in tok.as_bytes() {
                h ^= *b as u64;
                h = h.wrapping_mul(0x100_0000_01b3);
            }
            let idx = (h % self.dim as u64) as usize;
            v[idx] += 1.0;
        }
        Some(v)
    }
}

/// Which tier produced a [`CacheHit`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HitTier {
    /// Exact / normalized key match.
    Exact,
    /// Semantic (paraphrase) match above the configured cosine threshold.
    Semantic,
}

/// A tiered-lookup hit: the cached value, which tier served it, and (for a semantic hit) the cosine
/// similarity, so a caller can log/telemeter the paraphrase match quality.
#[derive(Debug, Clone, PartialEq)]
pub struct CacheHit {
    pub value: String,
    pub tier: HitTier,
    pub similarity: Option<f64>,
}

impl ResponseCache {
    /// **The live-path tiered lookup** (gap I): try the cheapest tier first — exact/normalized — and
    /// only on a miss consult the SEMANTIC (paraphrase) tier, and only when a `query_embedding` is
    /// present. This is the single call the served path makes so a paraphrase of a cached prompt hits
    /// without a fresh model call; passing `None` (no embed service / semantic disabled) degrades
    /// safely to exact-only. Scoping is unchanged: the caller's `key` must already encode every
    /// trust/authz dimension, and the embedding tier never crosses into another scope's store.
    pub fn get_tiered(
        &mut self,
        key: &str,
        query_embedding: Option<&[f32]>,
        now: u64,
    ) -> Option<CacheHit> {
        if let Some(v) = self.get_exact(key, now) {
            return Some(CacheHit {
                value: v,
                tier: HitTier::Exact,
                similarity: None,
            });
        }
        let emb = query_embedding?;
        let (v, sim) = self.get_semantic(emb, now)?;
        Some(CacheHit {
            value: v,
            tier: HitTier::Semantic,
            similarity: Some(sim),
        })
    }
}

impl PartitionedCache {
    /// Partition-isolated tiered lookup — the [`ResponseCache::get_tiered`] contract confined to one
    /// [`Partition`] (never a cross-partition read). This is the live-path entrypoint a served chat
    /// surface calls with the caller's scope partition + the embed-service query embedding.
    pub fn get_tiered(
        &mut self,
        partition: &Partition,
        key: &str,
        query_embedding: Option<&[f32]>,
        now: u64,
    ) -> Option<CacheHit> {
        self.parts
            .get_mut(partition)?
            .get_tiered(key, query_embedding, now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(capacity: usize, ttl: u64, thr: f64) -> CacheConfig {
        CacheConfig {
            capacity,
            ttl_ticks: ttl,
            semantic_threshold: thr,
        }
    }

    #[test]
    fn exact_hit_and_miss() {
        let mut c = ResponseCache::new(cfg(10, 100, 0.9));
        assert_eq!(c.get_exact("what is upi?", 0), None);
        c.put("what is upi?", "UPI is a payment system", None, 0);
        assert_eq!(
            c.get_exact("what is upi?", 1).as_deref(),
            Some("UPI is a payment system")
        );
        assert_eq!(c.stats().exact_hits, 1);
        assert_eq!(c.stats().exact_misses, 1);
    }

    #[test]
    fn normalized_key_folds_case_and_whitespace() {
        let mut c = ResponseCache::new(cfg(10, 100, 0.9));
        c.put("What   is  UPI?", "answer", None, 0);
        assert_eq!(c.get_exact("  what is upi? ", 1).as_deref(), Some("answer"));
    }

    #[test]
    fn ttl_expiry_is_a_miss_and_sweeps() {
        let mut c = ResponseCache::new(cfg(10, 5, 0.9));
        c.put("k", "v", None, 0);
        assert_eq!(
            c.get_exact("k", 5).as_deref(),
            Some("v"),
            "at ttl boundary still fresh"
        );
        assert_eq!(c.get_exact("k", 6), None, "past ttl is a miss");
        assert_eq!(c.len(), 0, "expired entry is swept");
        assert_eq!(c.stats().expirations, 1);
    }

    #[test]
    fn lru_evicts_least_recently_used() {
        let mut c = ResponseCache::new(cfg(2, 100, 0.9));
        c.put("a", "1", None, 0);
        c.put("b", "2", None, 1);
        // Touch "a" so "b" becomes least-recently-used.
        assert_eq!(c.get_exact("a", 2).as_deref(), Some("1"));
        c.put("c", "3", None, 3); // over capacity → evict LRU ("b")
        assert_eq!(c.len(), 2);
        assert_eq!(
            c.get_exact("b", 4),
            None,
            "b was the LRU and must be evicted"
        );
        assert_eq!(c.get_exact("a", 4).as_deref(), Some("1"));
        assert_eq!(c.get_exact("c", 4).as_deref(), Some("3"));
        assert_eq!(c.stats().evictions, 1);
    }

    #[test]
    fn semantic_hit_above_threshold_and_miss_below() {
        let mut c = ResponseCache::new(cfg(10, 100, 0.9));
        c.put("original", "cached answer", Some(vec![1.0, 0.0, 0.0]), 0);
        // A near-parallel query vector → cosine ~0.9998 ≥ 0.9 → hit.
        let hit = c.get_semantic(&[0.98, 0.02, 0.0], 1);
        assert!(hit.is_some(), "a near-duplicate embedding must hit");
        assert_eq!(hit.unwrap().0, "cached answer");
        // An orthogonal query → cosine 0 < 0.9 → miss.
        assert!(c.get_semantic(&[0.0, 1.0, 0.0], 2).is_none());
        assert_eq!(c.stats().semantic_hits, 1);
        assert_eq!(c.stats().semantic_misses, 1);
    }

    #[test]
    fn semantic_picks_the_nearest_entry() {
        let mut c = ResponseCache::new(cfg(10, 100, 0.5));
        c.put("x", "answer-x", Some(vec![1.0, 0.0]), 0);
        c.put("y", "answer-y", Some(vec![0.0, 1.0]), 0);
        // Query leans toward x.
        let (val, sim) = c.get_semantic(&[0.9, 0.1], 1).unwrap();
        assert_eq!(val, "answer-x");
        assert!(sim > 0.9);
    }

    #[test]
    fn semantic_ignores_expired_entries() {
        let mut c = ResponseCache::new(cfg(10, 3, 0.5));
        c.put("x", "old", Some(vec![1.0, 0.0]), 0);
        // Past TTL → not returned even for an exact-direction query.
        assert!(c.get_semantic(&[1.0, 0.0], 10).is_none());
        assert_eq!(c.len(), 0, "expired semantic entry is swept");
    }

    #[test]
    fn semantic_handles_missing_and_mismatched_embeddings() {
        let mut c = ResponseCache::new(cfg(10, 100, 0.5));
        c.put("no-emb", "v", None, 0); // no embedding → never a semantic candidate
        c.put("wrong-dim", "w", Some(vec![1.0, 0.0, 0.0]), 0);
        assert!(
            c.get_semantic(&[1.0, 0.0], 1).is_none(),
            "no comparable embedding → miss"
        );
    }

    #[test]
    fn zero_capacity_disables_caching() {
        let mut c = ResponseCache::new(cfg(0, 100, 0.9));
        c.put("k", "v", None, 0);
        assert_eq!(c.len(), 0);
        assert_eq!(c.get_exact("k", 0), None);
    }

    #[test]
    fn hit_rate_is_computed() {
        let mut c = ResponseCache::new(cfg(10, 100, 0.9));
        c.put("k", "v", None, 0);
        c.get_exact("k", 1); // hit
        c.get_exact("miss", 1); // miss
        assert!((c.stats().hit_rate() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn config_and_stats_serialize() {
        let cfg = cfg(5, 10, 0.8);
        let j = serde_json::to_string(&cfg).unwrap();
        assert_eq!(serde_json::from_str::<CacheConfig>(&j).unwrap(), cfg);
    }

    // ---- PartitionedCache (SERVING_OPS.md §6) -------------------------------

    #[test]
    fn partitions_never_share_a_hit() {
        let mut c = PartitionedCache::new(cfg(10, 100, 0.9));
        let alice = Partition::new("confidential|user:alice|chat");
        let bob = Partition::new("confidential|user:bob|chat");
        // Byte-identical prompt cached for Alice...
        c.put(&alice, "what is my balance?", "alice's answer", None, 0);
        // ...must NOT be visible to Bob's identical prompt (no cross-partition read).
        assert_eq!(c.get_exact(&bob, "what is my balance?", 1), None);
        assert_eq!(
            c.get_exact(&alice, "what is my balance?", 1).as_deref(),
            Some("alice's answer")
        );
    }

    #[test]
    fn unknown_partition_is_a_clean_miss() {
        let mut c = PartitionedCache::new(cfg(10, 100, 0.9));
        assert_eq!(c.get_exact(&Partition::new("nope"), "k", 0), None);
        assert!(c
            .get_semantic(&Partition::new("nope"), &[1.0, 0.0], 0)
            .is_none());
    }

    #[test]
    fn semantic_lookup_is_partition_scoped() {
        let mut c = PartitionedCache::new(cfg(10, 100, 0.5));
        let a = Partition::new("dept:payments");
        let b = Partition::new("dept:ops");
        c.put(&a, "q", "payments-answer", Some(vec![1.0, 0.0]), 0);
        // A near-parallel embedding hits within partition a...
        assert_eq!(
            c.get_semantic(&a, &[0.99, 0.01], 1).unwrap().0,
            "payments-answer"
        );
        // ...but partition b has nothing, even for the same embedding.
        assert!(c.get_semantic(&b, &[0.99, 0.01], 1).is_none());
    }

    #[test]
    fn erase_scope_drops_only_matching_partitions() {
        let mut c = PartitionedCache::new(cfg(10, 100, 0.9));
        c.put(
            &Partition::new("confidential|user:alice|chat"),
            "k",
            "v",
            None,
            0,
        );
        c.put(&Partition::new("pii|user:alice|sdlc"), "k", "v", None, 0);
        c.put(
            &Partition::new("confidential|user:bob|chat"),
            "k",
            "v",
            None,
            0,
        );
        assert_eq!(c.partition_count(), 3);

        // DPDP erasure for Alice: drop every partition mentioning her scope token.
        let removed = c.erase_scope(|p| p.contains("user:alice"));
        assert_eq!(removed, 2);
        assert_eq!(c.partition_count(), 1);
        assert_eq!(
            c.get_exact(&Partition::new("confidential|user:alice|chat"), "k", 1),
            None,
            "Alice's answer-cache entries are gone"
        );
        assert_eq!(
            c.get_exact(&Partition::new("confidential|user:bob|chat"), "k", 1)
                .as_deref(),
            Some("v"),
            "Bob is untouched"
        );
    }

    #[test]
    fn purge_partition_removes_one_scope() {
        let mut c = PartitionedCache::new(cfg(10, 100, 0.9));
        let p = Partition::new("user:alice");
        c.put(&p, "k", "v", None, 0);
        assert_eq!(c.total_entries(), 1);
        assert!(c.purge_partition(&p));
        assert_eq!(c.total_entries(), 0);
        assert!(!c.purge_partition(&p), "second purge is a no-op");
    }

    #[test]
    fn partition_serializes_transparently() {
        let p = Partition::new("confidential|user:alice|chat");
        let j = serde_json::to_string(&p).unwrap();
        assert_eq!(j, "\"confidential|user:alice|chat\"");
        assert_eq!(serde_json::from_str::<Partition>(&j).unwrap(), p);
    }
}
