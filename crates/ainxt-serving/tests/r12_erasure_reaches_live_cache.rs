// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-12 Serving-Ops gap-1 (HIGH) — the DPDP right-to-erasure cascade reaches **live serving
//! state**: the daemon's [`TieredCacheErasure`] is now the SAME instance the served turn path caches
//! answers into, so an erasure drops entries the live path actually created (and zeroizes their KV
//! residue) instead of draining a standalone, never-populated organ.
//!
//! The audit found the served daemon built a `TieredCacheErasure` that no `/v1/chat` turn ever wrote
//! to — a `remember`/`lookup` seam did not exist — so a right-to-erasure reached an empty organ and
//! the GPU-residue purge was inert in production. This test drives the newly-exposed live-path
//! entrypoints ([`TieredCacheErasure::remember_answer`] / [`lookup_answer`]) to prove the composition:
//! a served answer is REMEMBERED, is SERVED back as a cache hit (exact AND paraphrase), and is then
//! provably GONE — across all three tiers, with KV residue zeroized — after the principal's erasure.
//!
//! Fail-before: `remember_answer`/`lookup_answer`/`live_answer_entries` did not exist — this file
//! would not compile, and the only way to populate the organ was the internal `answer()` accessor no
//! served turn called. Pass-after: the live path populates the organ, hits are served from it, and
//! `erase_principal` reaches exactly those live entries. (The one-line `/v1/chat` call that invokes
//! `remember_answer` lives in the reserved `ainxt-server` handler — reported needs_hot_wiring.)

use ainxt_cache::HitTier;
use ainxt_serving::cache_isolation::{KvPage, PartitionKey};
use ainxt_serving::erasure::TieredCacheErasure;
use ainxt_types::DataClass;

fn organ() -> TieredCacheErasure {
    TieredCacheErasure::new(ainxt_cache::CacheConfig {
        capacity: 64,
        ttl_ticks: 10_000,
        semantic_threshold: 0.9,
    })
}

/// A per-user (Confidential ⇒ per-principal scope) partition key — the erasure-relevant case.
fn key(user: &str) -> PartitionKey {
    PartitionKey::resolve(DataClass::Confidential, user, Some("payments"), "chat")
}

#[test]
fn r12_erasure_reaches_the_live_served_answer_cache() {
    let mut organ = organ();
    assert_eq!(
        organ.live_answer_entries(),
        0,
        "precondition: the organ starts unpopulated (the bug)"
    );

    let alice = key("alice");
    let bob = key("bob");

    // (1) The LIVE served path remembers an answer for Alice (with a paraphrase embedding) and one for
    //     Bob — the population the audit found never happened on the served surface.
    organ.remember_answer(
        &alice,
        "what is my UPI limit?",
        "your UPI limit is 1 lakh",
        Some(vec![1.0, 0.0, 0.0]),
        0,
    );
    organ.remember_answer(
        &bob,
        "what is my UPI limit?",
        "bob's limit is 2 lakh",
        None,
        0,
    );
    // KV residue for Alice's sequence (the GPU-tier data an SQL-only erasure would miss).
    organ
        .kv()
        .insert_page(alice.clone(), KvPage::new(vec![0xAB, 0xCD, 0xEF]));
    assert_eq!(
        organ.live_answer_entries(),
        2,
        "the organ is now populated by the live path"
    );

    // (2) The organ SERVES the cache — an exact hit within Alice's partition, and a PARAPHRASE hit via
    //     the semantic tier — proving it is the real live cache, not a write-only sink.
    let exact = organ
        .lookup_answer(&alice, "what is my UPI limit?", None, 1)
        .expect("exact hit");
    assert_eq!(exact.tier, HitTier::Exact);
    assert_eq!(exact.value, "your UPI limit is 1 lakh");
    let para = organ
        .lookup_answer(
            &alice,
            "some unrelated key text",
            Some(&[0.98, 0.02, 0.0]),
            1,
        )
        .expect("paraphrase hit via the semantic tier");
    assert_eq!(para.tier, HitTier::Semantic);
    assert_eq!(para.value, "your UPI limit is 1 lakh");
    // Partition isolation: Bob's identical prompt never reads Alice's answer.
    assert_eq!(
        organ
            .lookup_answer(&bob, "what is my UPI limit?", None, 1)
            .unwrap()
            .value,
        "bob's limit is 2 lakh"
    );

    // (3) THE PROOF: a DPDP right-to-erasure for Alice reaches the LIVE entries — the answer tier drops
    //     her partition AND the KV residue is zeroized before free — while Bob is untouched.
    let ack = organ.erase_principal("alice");
    assert_eq!(
        ack.answer_partitions_purged, 1,
        "Alice's live answer-cache partition is erased"
    );
    assert_eq!(
        ack.kv_pages_zeroized(),
        1,
        "Alice's GPU/KV residue is zeroized before free"
    );
    assert!(ack.touched_any_tier());

    // Alice's live answer is GONE from both the exact and semantic tiers...
    assert!(organ
        .lookup_answer(&alice, "what is my UPI limit?", None, 2)
        .is_none());
    assert!(organ
        .lookup_answer(&alice, "x", Some(&[0.98, 0.02, 0.0]), 2)
        .is_none());
    // ...Bob's remains (erasure did not widen)...
    assert_eq!(
        organ
            .lookup_answer(&bob, "what is my UPI limit?", None, 2)
            .unwrap()
            .value,
        "bob's limit is 2 lakh"
    );
    // ...and the reclaimed KV page is byte-for-byte zero (no residue readable from reused GPU memory).
    assert_eq!(organ.free_pool().len(), 1);
    assert!(organ.free_pool()[0].bytes().iter().all(|b| *b == 0));
}
