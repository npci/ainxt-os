// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Inference-cache isolation + GPU-residue zeroization (SERVING_OPS.md §6, ADR-021 §8.4).
//!
//! Three cache tiers sit under/around inference — the coarse answer cache, the prompt-prefix
//! cache, and the **KV cache** (raw attention key/value tensors for in-flight / recently
//! completed sequences on self-hosted models). SERVING_OPS.md §6 requires all three be
//! partitioned by the **same** key: `{data_class, principal_scope, harness_id}` — *never a
//! content-hash alone*. Two byte-identical prompts from different principals or data classes
//! must never share a cache entry, so there is no entry to leak via a hit/miss timing signal in
//! the first place.
//!
//! This module owns two things the audit found entirely missing from `ainxt-serving`:
//!
//! 1. **The partition key and its granularity rule.** [`principal_scope`] resolves the scope
//!    granularity from the data class: `confidential`/`regulated-payment`/`pii` partition
//!    **per-user** (nothing about one user's cache is observable by another, even a same-department
//!    colleague); `internal`/`public` partition **per-department** (an accepted, same-trust-boundary
//!    warmth signal). When a department is unknown the scope **falls back to per-user** — isolation
//!    is only ever *narrowed*, never widened, on missing metadata.
//!
//! 2. **The KV-cache with erasure-time zeroization.** [`KvCacheIsolation`] stores paged KV blocks
//!    strictly under their [`PartitionKey`]; a lookup can only ever see its own partition
//!    ([`KvCacheIsolation::pages_for`]). On a DPDP right-to-erasure event
//!    ([`KvCacheIsolation::erase_principal`]) every KV page belonging to that principal is
//!    **explicitly zeroized** ([`KvPage::zeroize`]) *before* the slot is returned to the free pool
//!    — defense-in-depth under ADR-021's confidential-computing guarantee (attestation makes the
//!    data unreadable by the operator *during* residency; zeroization bounds its *lifetime* even
//!    against a future bug in the CC stack). Erasure returns an [`ErasureAck`] — the design's
//!    "erasure is not reported complete until Serving-Ops acks the purge" contract.
//!
//! Deterministic and pure: no clock, no RNG, no GPU. The tensors are modeled as opaque bytes so
//! the zeroization discipline is a property a unit test can assert byte-for-byte.

use std::collections::BTreeMap;

use ainxt_types::DataClass;

// ---------------------------------------------------------------------------
// Principal scope — the granularity rule (SERVING_OPS.md §6)
// ---------------------------------------------------------------------------

/// The scope a cache entry is partitioned under. Granularity is **data-class dependent**, not a
/// single global rule (SERVING_OPS.md §6): sensitive classes are isolated per individual
/// principal; low-sensitivity classes may share within a department.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum PrincipalScope {
    /// Per-individual-principal isolation — `confidential`/`regulated-payment`/`pii`.
    User(String),
    /// Per-department isolation — `internal`/`public` (a same-trust-boundary warmth signal).
    Department(String),
}

impl PrincipalScope {
    /// A stable string rendering for use as an opaque partition prefix in the coarse-answer /
    /// prompt-prefix tiers (e.g. `ainxt-cache`), so all three tiers agree on the boundary.
    pub fn render(&self) -> String {
        match self {
            PrincipalScope::User(u) => format!("user:{u}"),
            PrincipalScope::Department(d) => format!("dept:{d}"),
        }
    }
}

/// The data-class threshold at/above which a partition is isolated **per-user**. `Confidential`
/// and everything more sensitive (`RegulatedPayment`, `Pii`) is per-user; below it is
/// per-department. Encoded once here so retrieval, routing, and caching never disagree.
pub fn requires_per_user_isolation(data_class: DataClass) -> bool {
    data_class.sensitivity() >= DataClass::Confidential.sensitivity()
}

/// Resolve the [`PrincipalScope`] for a `(data_class, user, department)` triple (SERVING_OPS.md §6).
///
/// * `confidential`+ → [`PrincipalScope::User`].
/// * `internal`/`public` with a known department → [`PrincipalScope::Department`].
/// * `internal`/`public` with **no** department → falls back to [`PrincipalScope::User`]: a missing
///   department must never *widen* the sharing boundary, only narrow it.
pub fn principal_scope(
    data_class: DataClass,
    user_id: &str,
    department: Option<&str>,
) -> PrincipalScope {
    if requires_per_user_isolation(data_class) {
        return PrincipalScope::User(user_id.to_string());
    }
    match department {
        Some(dept) if !dept.is_empty() => PrincipalScope::Department(dept.to_string()),
        _ => PrincipalScope::User(user_id.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Partition key — {data_class, principal_scope, harness_id}
// ---------------------------------------------------------------------------

/// The uniform cache partition key (SERVING_OPS.md §6). `Ord`, so it is a `BTreeMap` key across
/// all three cache tiers. Two entries with any differing field are structurally distinct — there
/// is no cross-partition read path, so no timing side-channel to exploit.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PartitionKey {
    pub data_class: DataClass,
    pub scope: PrincipalScope,
    pub harness_id: String,
}

impl PartitionKey {
    /// Build a key, resolving the scope granularity from the data class.
    pub fn resolve(
        data_class: DataClass,
        user_id: &str,
        department: Option<&str>,
        harness_id: &str,
    ) -> Self {
        PartitionKey {
            data_class,
            scope: principal_scope(data_class, user_id, department),
            harness_id: harness_id.to_string(),
        }
    }

    /// True when this partition belongs to `user_id` as an *individual* principal (per-user
    /// scope). Department-scoped partitions are aggregate and are **not** owned by any one user, so
    /// they are not matched by a single principal's erasure (SERVING_OPS.md §6 (b) — "pages tagged
    /// with that principal's partition key").
    pub fn is_owned_by_user(&self, user_id: &str) -> bool {
        matches!(&self.scope, PrincipalScope::User(u) if u == user_id)
    }

    /// Opaque string rendering for the answer/prompt-prefix tiers so they partition identically.
    pub fn render(&self) -> String {
        format!(
            "{}|{}|{}",
            self.data_class.as_str(),
            self.scope.render(),
            self.harness_id
        )
    }
}

// ---------------------------------------------------------------------------
// KV page + zeroization
// ---------------------------------------------------------------------------

/// One paged KV block (SERVING_OPS.md §1 — KV is produced as fixed-size pages so a page can be
/// relocated, spilled, or dropped independently). The tensor bytes are modeled opaquely; what
/// matters here is that erasure can **zeroize** them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KvPage {
    bytes: Vec<u8>,
}

impl KvPage {
    pub fn new(bytes: Vec<u8>) -> Self {
        KvPage { bytes }
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Overwrite every byte with zero (ADR-021 §8.4 defense-in-depth). Idempotent.
    pub fn zeroize(&mut self) {
        for b in self.bytes.iter_mut() {
            *b = 0;
        }
    }

    /// True when every byte is zero — i.e. the page carries no residue.
    pub fn is_zeroized(&self) -> bool {
        self.bytes.iter().all(|b| *b == 0)
    }

    /// Read-only view of the residual bytes (for tests / spill transport).
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// The acknowledgement returned by an erasure sweep. SERVING_OPS.md §6: "erasure is not reported
/// complete until Serving-Ops acks the purge" — the presence of this value *is* that ack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErasureAck {
    /// Partitions whose entries were removed.
    pub partitions_purged: u64,
    /// Individual KV pages that were zeroized before being freed.
    pub pages_zeroized: u64,
}

// ---------------------------------------------------------------------------
// KV cache with partition isolation + zeroization-on-erasure
// ---------------------------------------------------------------------------

/// Partition-isolated KV-cache residency with erasure-time zeroization (SERVING_OPS.md §6).
///
/// Pages live strictly under a [`PartitionKey`]; there is no API that reads across partitions, so
/// isolation is structural, not advisory. Deterministic (no clock/GPU) — the "GPU memory" is a
/// `BTreeMap` of pages so the zeroize-before-free ordering is unit-assertable.
#[derive(Debug, Clone, Default)]
pub struct KvCacheIsolation {
    pages: BTreeMap<PartitionKey, Vec<KvPage>>,
}

impl KvCacheIsolation {
    pub fn new() -> Self {
        KvCacheIsolation {
            pages: BTreeMap::new(),
        }
    }

    /// Admit a KV page into `key`'s partition.
    pub fn insert_page(&mut self, key: PartitionKey, page: KvPage) {
        self.pages.entry(key).or_default().push(page);
    }

    /// The pages resident for exactly this partition — never any other's.
    pub fn pages_for(&self, key: &PartitionKey) -> &[KvPage] {
        self.pages.get(key).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Number of distinct partitions currently resident.
    pub fn partition_count(&self) -> usize {
        self.pages.len()
    }

    /// Total pages resident across all partitions.
    pub fn page_count(&self) -> usize {
        self.pages.values().map(Vec::len).sum()
    }

    /// DPDP right-to-erasure for one principal (SERVING_OPS.md §6 (b)). Every KV page in a
    /// partition **owned by** `user_id` (per-user scope) is zeroized *before* its slot is freed;
    /// department-scoped aggregate partitions are not a single principal's and are left intact.
    /// Returns the [`ErasureAck`] the erasure cascade waits on.
    pub fn erase_principal(&mut self, user_id: &str) -> ErasureAck {
        // Delegate to the reclaiming variant and let the (already-zeroized) pages drop here — the
        // free returns clean memory. Callers that hand pages back to a free pool use `_reclaim`.
        let (ack, _zeroized) = self.erase_principal_reclaim(user_id);
        ack
    }

    /// Like [`KvCacheIsolation::erase_principal`] but **returns the zeroized pages** to the caller so
    /// they can be handed back to the fleet's free pool with the residue *provably* zero before reuse
    /// (SERVING_OPS.md §6 — "returned to the free pool" — and ADR-021 §8.4). Every returned page
    /// satisfies [`KvPage::is_zeroized`]. This is the caller seam the tiered erasure cascade uses so
    /// that [`KvPage::zeroize`] runs on a real erasure path, not only in a unit test.
    pub fn erase_principal_reclaim(&mut self, user_id: &str) -> (ErasureAck, Vec<KvPage>) {
        let victims: Vec<PartitionKey> = self
            .pages
            .keys()
            .filter(|k| k.is_owned_by_user(user_id))
            .cloned()
            .collect();

        let mut reclaimed: Vec<KvPage> = Vec::new();
        let mut pages_zeroized = 0u64;
        for key in &victims {
            if let Some(mut pages) = self.pages.remove(key) {
                for page in pages.iter_mut() {
                    page.zeroize();
                    pages_zeroized += 1;
                }
                reclaimed.append(&mut pages);
            }
        }

        (
            ErasureAck {
                partitions_purged: victims.len() as u64,
                pages_zeroized,
            },
            reclaimed,
        )
    }

    /// Zeroize + drop a single partition on session end (SERVING_OPS.md §6 — bound page lifetime
    /// even outside an erasure event). Returns pages zeroized, or 0 if the partition was empty.
    pub fn purge_partition(&mut self, key: &PartitionKey) -> u64 {
        let (n, _zeroized) = self.purge_partition_reclaim(key);
        n
    }

    /// Like [`KvCacheIsolation::purge_partition`] but returns the zeroized pages for the free pool
    /// (the erase-on-evict path). Every returned page satisfies [`KvPage::is_zeroized`].
    pub fn purge_partition_reclaim(&mut self, key: &PartitionKey) -> (u64, Vec<KvPage>) {
        match self.pages.remove(key) {
            Some(mut pages) => {
                let mut n = 0u64;
                for page in pages.iter_mut() {
                    page.zeroize();
                    n += 1;
                }
                (n, pages)
            }
            None => (0, Vec::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conf_key(user: &str, harness: &str) -> PartitionKey {
        PartitionKey::resolve(DataClass::Confidential, user, Some("payments"), harness)
    }

    // ---- scope granularity --------------------------------------------------

    #[test]
    fn confidential_and_above_isolate_per_user() {
        for dc in [
            DataClass::Confidential,
            DataClass::RegulatedPayment,
            DataClass::Pii,
        ] {
            let s = principal_scope(dc, "alice", Some("payments"));
            assert_eq!(
                s,
                PrincipalScope::User("alice".into()),
                "{dc:?} must isolate per-user regardless of department"
            );
        }
    }

    #[test]
    fn internal_and_public_share_within_a_department() {
        let alice = principal_scope(DataClass::Internal, "alice", Some("payments"));
        let bob = principal_scope(DataClass::Internal, "bob", Some("payments"));
        assert_eq!(
            alice, bob,
            "same-dept internal traffic may share a partition"
        );
        assert_eq!(alice, PrincipalScope::Department("payments".into()));

        let pub_a = principal_scope(DataClass::Public, "alice", Some("ops"));
        assert_eq!(pub_a, PrincipalScope::Department("ops".into()));
    }

    #[test]
    fn missing_department_falls_back_to_per_user_never_widens() {
        // internal/public with no department must NOT collapse everyone into one shared bucket.
        let a = principal_scope(DataClass::Internal, "alice", None);
        let b = principal_scope(DataClass::Internal, "bob", None);
        assert_eq!(a, PrincipalScope::User("alice".into()));
        assert_ne!(
            a, b,
            "missing dept narrows to per-user, never widens sharing"
        );

        let empty = principal_scope(DataClass::Public, "carol", Some(""));
        assert_eq!(
            empty,
            PrincipalScope::User("carol".into()),
            "empty department string is treated as unknown → per-user"
        );
    }

    // ---- partition-key isolation --------------------------------------------

    #[test]
    fn identical_confidential_prompts_from_two_users_never_collide() {
        // The cross-tenant cache-leak attempt (SERVING_OPS.md §6 scenario 15): byte-identical
        // prompt, same data class + harness, different principals → distinct partitions.
        let a = conf_key("alice", "chat");
        let b = conf_key("bob", "chat");
        assert_ne!(a, b);

        let mut kv = KvCacheIsolation::new();
        kv.insert_page(a.clone(), KvPage::new(vec![7, 7, 7]));
        // Bob's identical prompt sees NOTHING of Alice's cache — no entry, no timing signal.
        assert!(kv.pages_for(&b).is_empty());
        assert_eq!(kv.pages_for(&a).len(), 1);
    }

    #[test]
    fn harness_id_and_data_class_are_part_of_the_boundary() {
        let base = conf_key("alice", "chat");
        // Same user + class, different harness → different partition.
        let other_harness = conf_key("alice", "sdlc");
        assert_ne!(base, other_harness);
        // Same user + harness, different data class → different partition.
        let other_class = PartitionKey::resolve(DataClass::Pii, "alice", Some("payments"), "chat");
        assert_ne!(base, other_class);
    }

    #[test]
    fn gap_ainxt_serving_srv_06_internal_class_separates_by_department_and_harness() {
        // The audit's exact leak (SRV-06): the live chat cache keys only on
        // `clearance|data_class|input`, so "two different users in different departments at the same
        // clearance share an internal-class entry". The designed partition key fixes this — an
        // Internal-class turn is scoped per-DEPARTMENT (and per-harness), so:
        //   * two users in DIFFERENT departments never collide;
        //   * the same department may share (the intended, same-trust-boundary warmth signal);
        //   * a different harness is a different partition.
        let alice_payments =
            PartitionKey::resolve(DataClass::Internal, "alice", Some("payments"), "chat");
        let bob_risk = PartitionKey::resolve(DataClass::Internal, "bob", Some("risk"), "chat");
        assert_ne!(
            alice_payments, bob_risk,
            "different departments must NOT share an internal-class entry (the SRV-06 leak)"
        );

        let carol_payments =
            PartitionKey::resolve(DataClass::Internal, "carol", Some("payments"), "chat");
        assert_eq!(
            alice_payments, carol_payments,
            "same department at the same clearance MAY share (intended warmth signal)"
        );

        let alice_payments_sdlc =
            PartitionKey::resolve(DataClass::Internal, "alice", Some("payments"), "sdlc");
        assert_ne!(
            alice_payments, alice_payments_sdlc,
            "harness_id is part of the boundary — chat and sdlc never share"
        );

        // And the rendered token is exactly what the answer/prompt-prefix tiers (ainxt-cache
        // Partition) must key on, so all three tiers agree on the boundary.
        assert_eq!(alice_payments.render(), "internal|dept:payments|chat");
        assert_ne!(alice_payments.render(), bob_risk.render());
    }

    #[test]
    fn render_is_stable_and_distinguishing() {
        let k = conf_key("alice", "chat");
        assert_eq!(k.render(), "confidential|user:alice|chat");
        let dept = PartitionKey::resolve(DataClass::Internal, "alice", Some("payments"), "chat");
        assert_eq!(dept.render(), "internal|dept:payments|chat");
    }

    // ---- zeroization --------------------------------------------------------

    #[test]
    fn kv_page_zeroize_wipes_every_byte() {
        let mut p = KvPage::new(vec![1, 2, 3, 255, 128]);
        assert!(!p.is_zeroized());
        p.zeroize();
        assert!(p.is_zeroized());
        assert_eq!(p.bytes(), &[0, 0, 0, 0, 0]);
        // Idempotent.
        p.zeroize();
        assert!(p.is_zeroized());
    }

    #[test]
    fn erase_principal_zeroizes_and_purges_only_that_users_partitions() {
        let mut kv = KvCacheIsolation::new();
        let alice = conf_key("alice", "chat");
        let bob = conf_key("bob", "chat");
        kv.insert_page(alice.clone(), KvPage::new(vec![9, 9]));
        kv.insert_page(alice.clone(), KvPage::new(vec![8, 8, 8]));
        kv.insert_page(bob.clone(), KvPage::new(vec![1, 1]));
        assert_eq!(kv.partition_count(), 2);
        assert_eq!(kv.page_count(), 3);

        let ack = kv.erase_principal("alice");
        assert_eq!(ack.partitions_purged, 1);
        assert_eq!(ack.pages_zeroized, 2, "both of Alice's pages zeroized");

        // Alice is gone entirely; Bob is untouched.
        assert!(kv.pages_for(&alice).is_empty());
        assert_eq!(kv.pages_for(&bob).len(), 1);
        assert_eq!(kv.partition_count(), 1);
    }

    #[test]
    fn erase_does_not_touch_department_scoped_aggregate_partitions() {
        // An internal/public partition is per-department — not "that principal's" — so a single
        // user's erasure must not wipe the shared department cache (SERVING_OPS.md §6 (b)).
        let mut kv = KvCacheIsolation::new();
        let dept = PartitionKey::resolve(DataClass::Internal, "alice", Some("payments"), "chat");
        kv.insert_page(dept.clone(), KvPage::new(vec![5, 5]));
        let ack = kv.erase_principal("alice");
        assert_eq!(ack.partitions_purged, 0);
        assert_eq!(ack.pages_zeroized, 0);
        assert_eq!(kv.pages_for(&dept).len(), 1);
    }

    #[test]
    fn erase_of_unknown_principal_is_a_clean_noop_ack() {
        let mut kv = KvCacheIsolation::new();
        kv.insert_page(conf_key("alice", "chat"), KvPage::new(vec![1]));
        let ack = kv.erase_principal("nobody");
        assert_eq!(ack.partitions_purged, 0);
        assert_eq!(ack.pages_zeroized, 0);
        assert_eq!(kv.page_count(), 1);
    }

    #[test]
    fn purge_partition_zeroizes_on_session_end() {
        let mut kv = KvCacheIsolation::new();
        let k = conf_key("alice", "chat");
        kv.insert_page(k.clone(), KvPage::new(vec![3, 3, 3]));
        assert_eq!(kv.purge_partition(&k), 1);
        assert!(kv.pages_for(&k).is_empty());
        assert_eq!(kv.purge_partition(&k), 0, "second purge is a no-op");
    }
}
