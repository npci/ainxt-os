// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! The GPU-residue purge hook — the tiered cache erasure cascade (SERVING_OPS.md §6, scenario 16;
//! ADR-021 §8.4; ADR-015 erasure cascade).
//!
//! The audit found the two erasure mechanisms — [`KvCacheIsolation::erase_principal`] /
//! [`KvPage::zeroize`] in this crate and [`PartitionedCache::erase_scope`] in `ainxt-cache` — fully
//! implemented and tested but with **no caller composing them**: a DPDP right-to-erasure that
//! reached the answer tier would silently miss KV pages still resident in GPU memory, and the
//! zeroization discipline had no live invoker. This module is that composer.
//!
//! [`TieredCacheErasure`] owns all three cache tiers SERVING_OPS.md §6 partitions by the *same*
//! `{data_class, principal_scope, harness_id}` key —
//!
//! 1. the **coarse-answer** cache ([`PartitionedCache`]),
//! 2. the **prompt-prefix** cache ([`PartitionedCache`]),
//! 3. the **KV** cache ([`KvCacheIsolation`], zeroize-before-free) —
//!
//! and drives them together on the two erasure paths the design names:
//!
//! * **erase-on-logout / right-to-erasure** ([`TieredCacheErasure::erase_principal`]): every entry
//!   keyed to a principal is deleted from tiers 1–2, and every resident KV page in a partition
//!   *owned by* that principal is **zeroized before its slot returns to the free pool**. The
//!   returned [`CascadeAck`] *is* the "erasure is not reported complete until Serving-Ops acks the
//!   purge" contract — a DB-only sweep is structurally blind to data that only ever lived in GPU
//!   memory, so the cascade is not complete until this ack exists.
//! * **erase-on-evict / session end** ([`TieredCacheErasure::evict_session`]): one partition's
//!   entries are dropped from all three tiers, zeroizing its KV pages, bounding page lifetime even
//!   outside a formal erasure event (ADR-021 §8.4 defense-in-depth against a future CC-stack bug).
//!
//! Reclaimed KV pages are held in a **free pool** so the residue is *provably* zero before reuse —
//! a unit test can assert every freed page satisfies [`KvPage::is_zeroized`], byte for byte.
//! Deterministic and pure: no clock, no GPU, no RNG.

use std::sync::{Arc, Mutex};

use ainxt_cache::{CacheConfig, CacheHit, PartitionedCache};

use crate::cache_isolation::{ErasureAck, KvCacheIsolation, KvPage, PartitionKey, PrincipalScope};

/// The combined acknowledgement of a tiered erasure across all three cache tiers (SERVING_OPS.md
/// §6, scenario 16). Its existence is the "Serving-Ops acked the purge" signal the platform
/// erasure cascade (ADR-015) waits on before reporting erasure complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CascadeAck {
    /// Coarse-answer-cache partitions removed.
    pub answer_partitions_purged: usize,
    /// Prompt-prefix-cache partitions removed.
    pub prompt_prefix_partitions_purged: usize,
    /// The KV-tier ack — partitions purged + **pages zeroized before free** (the GPU-residue part).
    pub kv: ErasureAck,
}

impl CascadeAck {
    /// Total partitions removed across every tier.
    pub fn total_partitions_purged(&self) -> u64 {
        self.answer_partitions_purged as u64
            + self.prompt_prefix_partitions_purged as u64
            + self.kv.partitions_purged
    }

    /// KV pages explicitly zeroized before their slots returned to the free pool.
    pub fn kv_pages_zeroized(&self) -> u64 {
        self.kv.pages_zeroized
    }

    /// True when the cascade reached at least one tier (something was actually purged) — an honest
    /// signal for the erasure log; a fully-empty cascade is a clean no-op ack, still valid.
    pub fn touched_any_tier(&self) -> bool {
        self.total_partitions_purged() > 0
    }
}

/// The tiered cache erasure cascade — the single caller that ties the KV tier's zeroize-before-free
/// discipline to the answer/prompt-prefix tiers' partition deletion (SERVING_OPS.md §6).
///
/// Populated by the live serving path (answer/prefix entries as turns are cached; KV pages as
/// sequences run) and drained by the platform erasure cascade / session-end hook. All tiers key on
/// the **same** [`PartitionKey`] contract, rendered via [`PartitionKey::render`], so the three tiers
/// never disagree about which entries belong to a principal.
#[derive(Debug, Clone)]
pub struct TieredCacheErasure {
    // R16 CRITICAL (serving-ops): `Arc<Mutex<..>>`, not an owned `PartitionedCache` — see
    // `with_shared_answer_cache`. The audit found this organ built its OWN private answer cache
    // (via `new`) while the served `ChatSurface` read/wrote a SECOND, unrelated `PartitionedCache`
    // instance: a DPDP erasure drained an organ no served turn had ever populated, so the ack was
    // vacuous — the subject's cached answer was untouched. Sharing the Arc is what makes
    // `erase_principal` reach the entries the served path actually created.
    answer: Arc<Mutex<PartitionedCache>>,
    prompt_prefix: PartitionedCache,
    kv: KvCacheIsolation,
    free_pool: Vec<KvPage>,
}

impl TieredCacheErasure {
    /// Build a cascade whose answer + prompt-prefix tiers share `cfg`, each owning a **private**
    /// `PartitionedCache` (the pre-R16 behavior — still correct for a standalone/offline organ, e.g.
    /// these unit tests). A served daemon composition must instead call
    /// [`TieredCacheErasure::with_shared_answer_cache`] so the answer tier is the SAME instance the
    /// served surface reads, or right-to-erasure never reaches live served content.
    pub fn new(cfg: CacheConfig) -> Self {
        TieredCacheErasure {
            answer: Arc::new(Mutex::new(PartitionedCache::new(cfg))),
            prompt_prefix: PartitionedCache::new(cfg),
            kv: KvCacheIsolation::new(),
            free_pool: Vec::new(),
        }
    }

    /// **R16 CRITICAL fix**: build a cascade whose **answer tier is `answer`** — a handle a served
    /// surface (e.g. `ainxt_chat::ChatSurface::answer_cache_handle`) already owns and populates on
    /// every cacheable turn. This is the composition-root constructor: the daemon builds the served
    /// `ChatSurface` first, takes its cache handle, and hands the SAME `Arc` here, so
    /// [`TieredCacheErasure::erase_principal`] purges exactly the entries the live served path wrote
    /// — never a second, disconnected cache. The prompt-prefix tier is unaffected by this fix (the
    /// served chat path does not populate it today) and stays privately owned under `cfg`.
    pub fn with_shared_answer_cache(
        answer: Arc<Mutex<PartitionedCache>>,
        cfg: CacheConfig,
    ) -> Self {
        TieredCacheErasure {
            answer,
            prompt_prefix: PartitionedCache::new(cfg),
            kv: KvCacheIsolation::new(),
            free_pool: Vec::new(),
        }
    }

    // --- tier access (the live serving path populates/looks up through these) ----------------

    /// The coarse-answer cache tier (locks the shared handle — see [`Self::with_shared_answer_cache`]).
    pub fn answer(&mut self) -> std::sync::MutexGuard<'_, PartitionedCache> {
        self.answer.lock().expect("answer-cache mutex poisoned")
    }

    /// The prompt-prefix cache tier.
    pub fn prompt_prefix(&mut self) -> &mut PartitionedCache {
        &mut self.prompt_prefix
    }

    /// The KV cache tier (zeroize-before-free).
    pub fn kv(&mut self) -> &mut KvCacheIsolation {
        &mut self.kv
    }

    // --- live-path answer cache (the served turn path populates + reads through these) -----------
    //
    // The audit's HIGH finding was that the daemon held a `TieredCacheErasure` that no served turn
    // ever WROTE to — so a DPDP erasure reached an empty organ and the GPU-residue cascade was inert
    // in production. These two calls make this organ the *same instance* that serves cache hits: the
    // served path REMEMBERS an answer under the caller's `{data_class, principal_scope, harness_id}`
    // partition and LOOKS IT UP through the identical key, so a subsequent right-to-erasure for that
    // principal provably drops entries the live path actually created (proven in
    // `tests/r12_erasure_reaches_live_cache.rs`). Populating this from `/v1/chat` is a one-line call
    // in the (reserved) `ainxt-server` turn handler — the clean entrypoint is here; that call-site is
    // reported needs_hot_wiring.

    /// **Live-path REMEMBER** (SERVING_OPS.md §6): cache a served `answer` for `prompt` under the
    /// caller's partition `key`, optionally with a precomputed paraphrase `embedding`. Scoping is the
    /// partition key itself — two principals' byte-identical prompts never share an entry — and this
    /// is the SAME store [`TieredCacheErasure::erase_principal`] drains, so nothing cached here can
    /// escape a later erasure.
    pub fn remember_answer(
        &mut self,
        key: &PartitionKey,
        prompt: &str,
        answer: &str,
        embedding: Option<Vec<f32>>,
        now: u64,
    ) {
        let partition = key.render().as_str().into();
        self.answer
            .lock()
            .expect("answer-cache mutex poisoned")
            .put(&partition, prompt, answer, embedding, now);
    }

    /// **Live-path LOOKUP** (gap I tiered exact→paraphrase, SERVING_OPS.md §6): the cheapest-tier hit
    /// for `prompt` **within** the caller's partition `key` (never a cross-partition read), consulting
    /// the semantic tier only when a `query_embedding` is supplied. This is the single call the served
    /// turn path makes before a fresh model call; a hit here is an answer that IS subject to erasure.
    pub fn lookup_answer(
        &mut self,
        key: &PartitionKey,
        prompt: &str,
        query_embedding: Option<&[f32]>,
        now: u64,
    ) -> Option<CacheHit> {
        let partition = key.render().as_str().into();
        self.answer
            .lock()
            .expect("answer-cache mutex poisoned")
            .get_tiered(&partition, prompt, query_embedding, now)
    }

    /// Total live answer-cache entries across all partitions — the "is this organ actually populated?"
    /// signal the audit found stuck at 0 on the served surface.
    pub fn live_answer_entries(&self) -> usize {
        self.answer
            .lock()
            .expect("answer-cache mutex poisoned")
            .total_entries()
    }

    /// The free pool of KV pages returned after zeroization — every page here satisfies
    /// [`KvPage::is_zeroized`]. This models the fleet's free page pool; a test asserts the residue
    /// is zero before the memory is ever handed back out.
    pub fn free_pool(&self) -> &[KvPage] {
        &self.free_pool
    }

    /// The bounded partition-scope token a per-user principal's entries render under across all
    /// three tiers (`|user:{id}|`), delimited so `alice` never matches `alice2`. This is exactly the
    /// middle segment of [`PartitionKey::render`], so the answer/prefix predicate and the KV owner
    /// check target the identical boundary.
    fn user_scope_token(user_id: &str) -> String {
        format!("|{}|", PrincipalScope::User(user_id.to_string()).render())
    }

    /// **Right-to-erasure / erase-on-logout** (SERVING_OPS.md §6 (a)+(b), scenario 16). Deletes every
    /// answer + prompt-prefix entry keyed to `user_id` and **zeroizes every resident KV page** in a
    /// partition owned by that principal before returning it to the free pool. Department-scoped
    /// aggregate partitions are *not* one principal's and are left intact (§6 (b)). Returns the
    /// [`CascadeAck`] the ADR-015 cascade waits on — erasure is not complete until this exists.
    pub fn erase_principal(&mut self, user_id: &str) -> CascadeAck {
        // Tier 3 (KV): zeroize-before-free, reclaiming the (now-zero) pages into the free pool so the
        // residue is provably gone before the slot is reused. This is the real caller for
        // KvCacheIsolation::erase_principal / KvPage::zeroize.
        let (kv_ack, mut reclaimed) = self.kv.erase_principal_reclaim(user_id);
        self.free_pool.append(&mut reclaimed);

        // Tiers 1 + 2 (answer / prompt-prefix): drop every partition rendering under this principal's
        // per-user scope token. Deleted (not zeroized) — zeroization is the KV tier's discipline.
        let token = Self::user_scope_token(user_id);
        let answer_partitions_purged = self
            .answer
            .lock()
            .expect("answer-cache mutex poisoned")
            .erase_scope(|p| p.contains(&token));
        let prompt_prefix_partitions_purged =
            self.prompt_prefix.erase_scope(|p| p.contains(&token));

        CascadeAck {
            answer_partitions_purged,
            prompt_prefix_partitions_purged,
            kv: kv_ack,
        }
    }

    /// **Erase-on-evict / session end** for a single partition (SERVING_OPS.md §6, ADR-021 §8.4).
    /// Drops that partition's entries from all three tiers, zeroizing its KV pages into the free pool.
    /// Used when a session ends (bound page lifetime even outside a formal erasure event).
    pub fn evict_session(&mut self, key: &PartitionKey) -> CascadeAck {
        let render = key.render();
        let partition = render.as_str().into();

        // Tier 3 (KV): zeroize + reclaim this partition's pages.
        let (kv_pages_zeroized, mut reclaimed) = self.kv.purge_partition_reclaim(key);
        self.free_pool.append(&mut reclaimed);

        // Tiers 1 + 2: drop the exact partition.
        let answer_removed = self
            .answer
            .lock()
            .expect("answer-cache mutex poisoned")
            .purge_partition(&partition);
        let prefix_removed = self.prompt_prefix.purge_partition(&partition);

        CascadeAck {
            answer_partitions_purged: usize::from(answer_removed),
            prompt_prefix_partitions_purged: usize::from(prefix_removed),
            kv: ErasureAck {
                partitions_purged: u64::from(kv_pages_zeroized > 0),
                pages_zeroized: kv_pages_zeroized,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// The DPDP erase-scope seam (SERVING_OPS.md §6, ADR-015 / ADR-021 §8.4)
// ---------------------------------------------------------------------------

/// Why an erasure is being driven — the DPDP/lifecycle event that reached Serving-Ops
/// (ADR-015 erasure cascade). Informational for the ack/audit; every reason drives the *same*
/// zeroize-before-free discipline on the KV tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErasureReason {
    /// A data subject exercised their DPDP right-to-erasure (erase-on-logout / SAR).
    RightToErasure,
    /// A session ended — bound page lifetime even outside a formal erasure event (§8.4).
    SessionEnd,
    /// A retention floor/TTL elapsed for the scope (lifecycle-driven purge).
    RetentionExpiry,
}

/// What an erasure event targets. This is the DPDP "erase-scope" the platform cascade (ADR-015 —
/// e.g. `ainxt-memory`'s `erase_subject`) resolves and forwards to every downstream tier so a
/// sweep that only touched the DB is not blind to data that lived only in GPU/KV memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EraseScope {
    /// Every per-user-scoped partition owned by this data subject (department aggregates untouched).
    Subject(String),
    /// One exact partition (a single ended session).
    Session(PartitionKey),
}

/// A resolved DPDP erasure request handed to a downstream tier (SERVING_OPS.md §6, ADR-015).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErasureRequest {
    pub scope: EraseScope,
    pub reason: ErasureReason,
}

impl ErasureRequest {
    /// A DPDP right-to-erasure for an individual data subject.
    pub fn right_to_erasure(subject: impl Into<String>) -> Self {
        ErasureRequest {
            scope: EraseScope::Subject(subject.into()),
            reason: ErasureReason::RightToErasure,
        }
    }

    /// A session-end eviction of one partition.
    pub fn session_end(key: PartitionKey) -> Self {
        ErasureRequest {
            scope: EraseScope::Session(key),
            reason: ErasureReason::SessionEnd,
        }
    }
}

/// A downstream tier that participates in the platform DPDP erasure cascade (ADR-015). Serving-Ops
/// exposes [`TieredCacheErasure`] as one such participant so the cascade can drive the GPU/KV
/// residue purge through a **stable, versioned trait object** — the clean entrypoint the platform
/// erasure driver (`ainxt-memory::erase_subject` and the lifecycle sweeper) calls to reach the KV
/// tier. The returned [`CascadeAck`] is the "not complete until Serving-Ops acks the purge" signal.
///
/// Wiring note: the cascade owner holds a `Box<dyn ErasureParticipant>` (or a slice of them) and
/// calls [`ErasureParticipant::erase`] for every subject/session it erases. The dependency edge
/// (cascade crate → `ainxt-serving`) is acyclic — `ainxt-serving` depends only on `ainxt-types` and
/// `ainxt-cache`.
pub trait ErasureParticipant {
    /// Erase everything in `req`'s scope from this tier, zeroizing any GPU/KV residue before free,
    /// and return the ack. Idempotent: erasing an already-empty scope is a clean no-op ack.
    fn erase(&mut self, req: &ErasureRequest) -> CascadeAck;
}

impl TieredCacheErasure {
    /// Drive a resolved DPDP [`ErasureRequest`] across all three cache tiers (SERVING_OPS.md §6).
    /// This is the single erase-scope entrypoint the platform cascade calls; it dispatches to the
    /// right-to-erasure or session-end path and, on either, **zeroizes every resident KV page
    /// before its slot returns to the free pool** — so a DPDP erasure reaches the GPU tier, not
    /// only the DB. Returns the [`CascadeAck`] the ADR-015 cascade waits on.
    pub fn erase_scope(&mut self, req: &ErasureRequest) -> CascadeAck {
        match &req.scope {
            EraseScope::Subject(subject) => self.erase_principal(subject),
            EraseScope::Session(key) => self.evict_session(key),
        }
    }
}

impl ErasureParticipant for TieredCacheErasure {
    fn erase(&mut self, req: &ErasureRequest) -> CascadeAck {
        self.erase_scope(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ainxt_types::DataClass;

    fn cfg() -> CacheConfig {
        CacheConfig {
            capacity: 64,
            ttl_ticks: 1000,
            semantic_threshold: 0.9,
        }
    }

    fn conf_key(user: &str, harness: &str) -> PartitionKey {
        // Confidential ⇒ per-user scope — the erasure-relevant case.
        PartitionKey::resolve(DataClass::Confidential, user, Some("payments"), harness)
    }

    #[test]
    fn r3_serving_ops_kv_residue_zeroized_on_erasure_cascade() {
        // ROUND-3 (critical): give KvCacheIsolation::erase_principal / KvPage::zeroize a REAL caller
        // via a PartitionedCache erase-on-logout + erase-on-evict path, and PROVE the GPU residue is
        // zeroized before the slot returns to the free pool (SERVING_OPS.md §6 / ADR-021 §8.4).
        //
        // Fail-before: nothing composed the KV zeroization with the answer/prompt-prefix tiers, so a
        // right-to-erasure left KV pages resident (and zeroize() had no live caller). Pass-after: one
        // cascade call erases all three tiers for the principal and the reclaimed pages are all-zero.
        let mut casc = TieredCacheErasure::new(cfg());

        let alice = conf_key("alice", "chat");
        let bob = conf_key("bob", "chat");

        // Seed all three tiers for Alice (with NON-ZERO KV residue) and Bob.
        casc.kv()
            .insert_page(alice.clone(), KvPage::new(vec![0xAB, 0xCD, 0xEF]));
        casc.kv()
            .insert_page(alice.clone(), KvPage::new(vec![1, 2, 3, 4]));
        casc.kv().insert_page(bob.clone(), KvPage::new(vec![9, 9]));
        casc.answer().put(
            &alice.render().as_str().into(),
            "q",
            "alice-answer",
            None,
            0,
        );
        casc.prompt_prefix().put(
            &alice.render().as_str().into(),
            "sys",
            "alice-prefix",
            None,
            0,
        );
        casc.answer()
            .put(&bob.render().as_str().into(), "q", "bob-answer", None, 0);

        // Sanity: Alice's KV residue is genuinely non-zero before erasure.
        assert!(
            casc.kv().pages_for(&alice).iter().any(|p| !p.is_zeroized()),
            "precondition: Alice's KV pages carry non-zero residue"
        );

        // ---- erase-on-logout / right-to-erasure -------------------------------------------------
        let ack = casc.erase_principal("alice");

        // KV: both of Alice's pages zeroized-before-free; Bob's untouched.
        assert_eq!(ack.kv.partitions_purged, 1);
        assert_eq!(
            ack.kv_pages_zeroized(),
            2,
            "both of Alice's KV pages zeroized"
        );
        assert!(
            casc.kv().pages_for(&alice).is_empty(),
            "Alice's KV partition is gone"
        );
        assert_eq!(casc.kv().pages_for(&bob).len(), 1, "Bob's KV is untouched");

        // Answer + prompt-prefix: Alice's entries deleted from BOTH tiers, Bob's answer remains.
        assert_eq!(ack.answer_partitions_purged, 1);
        assert_eq!(ack.prompt_prefix_partitions_purged, 1);
        assert_eq!(
            casc.answer()
                .get_exact(&alice.render().as_str().into(), "q", 1),
            None,
            "Alice's coarse-answer entry is gone"
        );
        assert_eq!(
            casc.prompt_prefix()
                .get_exact(&alice.render().as_str().into(), "sys", 1),
            None,
            "Alice's prompt-prefix entry is gone"
        );
        assert_eq!(
            casc.answer()
                .get_exact(&bob.render().as_str().into(), "q", 1)
                .as_deref(),
            Some("bob-answer"),
            "Bob's answer cache is untouched by Alice's erasure"
        );

        // THE PROOF: every page returned to the free pool is byte-for-byte zero — no residue can be
        // read back out of reused GPU memory.
        assert_eq!(
            casc.free_pool().len(),
            2,
            "both zeroized pages returned to the free pool"
        );
        for page in casc.free_pool() {
            assert!(
                page.is_zeroized(),
                "a reclaimed KV page still carries residue"
            );
            assert!(
                page.bytes().iter().all(|b| *b == 0),
                "residue bytes are not all zero"
            );
        }
        // The reclaimed pages preserved their original sizes (3 and 4) but wiped their contents.
        let mut sizes: Vec<usize> = casc.free_pool().iter().map(KvPage::len).collect();
        sizes.sort_unstable();
        assert_eq!(sizes, vec![3, 4]);

        assert!(ack.touched_any_tier());
        assert_eq!(ack.total_partitions_purged(), 3);
    }

    #[test]
    fn r3_serving_ops_erase_on_evict_zeroizes_single_session_partition() {
        // The second erasure path: session end evicts ONE partition from all three tiers, zeroizing
        // its KV pages. (Same cascade object; proves the erase-on-evict caller, not only on-logout.)
        let mut casc = TieredCacheErasure::new(cfg());
        let sess = conf_key("carol", "sdlc");
        casc.kv()
            .insert_page(sess.clone(), KvPage::new(vec![7, 7, 7, 7]));
        casc.answer()
            .put(&sess.render().as_str().into(), "q", "carol-answer", None, 0);

        let ack = casc.evict_session(&sess);
        assert_eq!(ack.kv_pages_zeroized(), 1);
        assert_eq!(ack.answer_partitions_purged, 1);
        assert!(casc.kv().pages_for(&sess).is_empty());
        assert_eq!(casc.free_pool().len(), 1);
        assert!(
            casc.free_pool()[0].is_zeroized(),
            "evicted session's KV residue zeroized"
        );

        // A second evict of the same (now empty) partition is a clean no-op ack.
        let ack2 = casc.evict_session(&sess);
        assert_eq!(ack2.kv_pages_zeroized(), 0);
        assert!(!ack2.touched_any_tier());
    }

    #[test]
    fn r3_serving_ops_erasure_never_widens_across_similar_user_ids() {
        // The bounded scope token must not let `alice`'s erasure hit `alice2` (a prefix-collision
        // safety property — narrowing isolation, never widening it).
        let mut casc = TieredCacheErasure::new(cfg());
        let alice = conf_key("alice", "chat");
        let alice2 = conf_key("alice2", "chat");
        casc.kv().insert_page(alice.clone(), KvPage::new(vec![1]));
        casc.kv().insert_page(alice2.clone(), KvPage::new(vec![2]));
        casc.answer()
            .put(&alice.render().as_str().into(), "q", "a", None, 0);
        casc.answer()
            .put(&alice2.render().as_str().into(), "q", "a2", None, 0);

        let ack = casc.erase_principal("alice");
        assert_eq!(
            ack.kv_pages_zeroized(),
            1,
            "only alice's page, never alice2's"
        );
        assert_eq!(ack.answer_partitions_purged, 1);
        assert_eq!(
            casc.kv().pages_for(&alice2).len(),
            1,
            "alice2 is a different principal"
        );
        assert_eq!(
            casc.answer()
                .get_exact(&alice2.render().as_str().into(), "q", 1)
                .as_deref(),
            Some("a2"),
        );
    }
}
