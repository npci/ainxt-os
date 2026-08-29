// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-5 Serving-Ops integration tests — the two gaps closed against the crate's public API:
//!
//! * `r5_slo_qos_main_admission_path` — the SLO-aware QoS main admission path (SERVING_OPS.md §2):
//!   priority classes carried on the request + chunk/step preemption + bounded-queue backpressure,
//!   composed into one pre-node decision. Fail-before: no `slo::SloAdmissionController` existed —
//!   the request path was priority-blind and never invoked the scheduler.
//!
//! * `r5_kv_residue_zeroized_via_erase_scope_seam` — the GPU-residue purge driven through the DPDP
//!   `ErasureParticipant` erase-scope seam (SERVING_OPS.md §6, ADR-015/§8.4), proving KV residue is
//!   zeroized before the slot returns to the free pool. Fail-before: no erase-scope trait/request
//!   existed, so the KV zeroization had no cascade-callable entrypoint.

use ainxt_cache::CacheConfig;
use ainxt_serving::cache_isolation::{KvPage, PartitionKey};
use ainxt_serving::erasure::{
    ErasureParticipant, ErasureReason, ErasureRequest, TieredCacheErasure,
};
use ainxt_serving::preemption::{KvDisposition, PreemptionScheduler};
use ainxt_serving::slo::{QosRequest, SloAdmissionController, SloDecision};
use ainxt_serving::{DataClass, FairnessLimiter, PriorityClass, ShedReason, TenantId};

#[test]
fn r5_slo_qos_main_admission_path() {
    // A pool of concurrency 2, generous per-tenant quota, a wait queue bounded at 1.
    let mut c = SloAdmissionController::new(
        FairnessLimiter::new(1000, 1000),
        PreemptionScheduler::new(2),
        1,
    );

    // (1) A P2 batch program run and a P1 SDLC turn fill the pool — each carrying its PriorityClass
    //     (the field the audit found missing on the live path).
    let batch = QosRequest::new(1, PriorityClass::Batch, "prog").with_work(100_000, 8);
    let sdlc = QosRequest::new(2, PriorityClass::Standard, "eng").with_work(5_000, 4);
    assert_eq!(c.admit(&batch), SloDecision::Admitted { preempted: None });
    assert_eq!(c.admit(&sdlc), SloDecision::Admitted { preempted: None });
    assert_eq!(c.running_count(), 2);

    // (2) A P0 incident arrives into the full pool. It must preempt the LOWEST-priority incumbent
    //     (the P2 batch) at its chunk/step boundary and be admitted immediately — never queued
    //     behind the 20-min batch. The P1 SDLC turn is untouched.
    let incident = QosRequest::new(3, PriorityClass::Interactive, "ops");
    match c.admit(&incident) {
        SloDecision::Admitted { preempted: Some(p) } => {
            assert_eq!(p.victim, 1, "the P2 batch is the victim, not the P1 turn");
            assert_eq!(p.victim_priority, PriorityClass::Batch);
            // A P2 victim checkpoints to PENDING for idempotent resume (ADR-027).
            assert_eq!(
                p.disposition,
                KvDisposition::CheckpointedToPending { resume_from: 0 }
            );
        }
        other => panic!("expected the incident to preempt the batch, got {other:?}"),
    }
    assert_eq!(
        c.running_count(),
        2,
        "pool still holds two (batch swapped for incident)"
    );
    assert_eq!(c.preempted_count(), 1);

    // (3) A second P0 arrives. The pool now holds [P1 sdlc, P0 incident]; the P1 is strictly lower,
    //     so it too is preempted (with its committed KV kept recoverable) — a P0 never waits behind
    //     a P1 either.
    match c.admit(&QosRequest::new(4, PriorityClass::Interactive, "ops")) {
        SloDecision::Admitted { preempted: Some(p) } => {
            assert_eq!(p.victim, 2);
            assert_eq!(p.victim_priority, PriorityClass::Standard);
            assert_eq!(
                p.disposition,
                KvDisposition::EvictedRecoverable {
                    pages: 4,
                    resume_from: 0
                }
            );
        }
        other => panic!("expected the P1 to be preempted, got {other:?}"),
    }

    // (4) Now the pool is full of P0s. A third P0 can preempt nobody → it waits in the bounded queue.
    assert_eq!(
        c.admit(&QosRequest::new(5, PriorityClass::Interactive, "ops")),
        SloDecision::Enqueued { depth: 1 }
    );

    // (5) The queue ceiling is now hit → the next arrival is shed with honest backpressure.
    assert_eq!(
        c.admit(&QosRequest::new(6, PriorityClass::Interactive, "ops")),
        SloDecision::Shed(ShedReason::QueueFull { max_queue_depth: 1 })
    );

    // (6) The incident finishes → a slot frees and the controller signals the queued P0 may now be
    //     promoted (the caller re-drives admit for the queue head).
    let out = c.complete(&incident).unwrap();
    assert!(out.slot_freed);
    assert!(out.dequeue_head);
    assert_eq!(c.queue_depth(), 0);

    // (6) Fairness still protects a sibling: a tenant capped at quota 1 is refused its 2nd
    //     concurrent turn with the honest over-quota reason, taking no slot.
    let mut fair = SloAdmissionController::new(
        FairnessLimiter::new(10, 1),
        PreemptionScheduler::new(10),
        10,
    );
    assert!(fair
        .admit(&QosRequest::new(1, PriorityClass::Standard, "greedy"))
        .is_admitted());
    assert_eq!(
        fair.admit(&QosRequest::new(2, PriorityClass::Standard, "greedy")),
        SloDecision::RejectedOverQuota { quota: 1 }
    );
    assert_eq!(fair.tenant_usage(&TenantId::new("greedy")), 1);
}

#[test]
fn r5_kv_residue_zeroized_via_erase_scope_seam() {
    let cfg = CacheConfig {
        capacity: 64,
        ttl_ticks: 1000,
        semantic_threshold: 0.9,
    };
    let mut casc = TieredCacheErasure::new(cfg);

    // Confidential ⇒ per-user KV partitions. Seed Alice's KV with NON-ZERO residue + answer/prefix
    // entries, and an unrelated Bob partition that must survive.
    let alice = PartitionKey::resolve(DataClass::Confidential, "alice", Some("payments"), "chat");
    let bob = PartitionKey::resolve(DataClass::Confidential, "bob", Some("payments"), "chat");
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

    // Precondition: Alice's KV residue is genuinely non-zero.
    assert!(casc.kv().pages_for(&alice).iter().any(|p| !p.is_zeroized()));

    // Drive the DPDP right-to-erasure THROUGH the cascade seam (a trait object, exactly how the
    // platform erasure driver in ainxt-memory would hold and call it).
    let req = ErasureRequest::right_to_erasure("alice");
    assert_eq!(req.reason, ErasureReason::RightToErasure);
    let participant: &mut dyn ErasureParticipant = &mut casc;
    let ack = participant.erase(&req);

    // KV tier: both of Alice's pages zeroized-before-free; the ack carries the GPU-residue count.
    assert_eq!(ack.kv_pages_zeroized(), 2);
    assert_eq!(ack.answer_partitions_purged, 1);
    assert_eq!(ack.prompt_prefix_partitions_purged, 1);
    assert_eq!(ack.total_partitions_purged(), 3);
    assert!(ack.touched_any_tier());

    // Alice is gone from every tier; Bob is untouched.
    assert!(casc.kv().pages_for(&alice).is_empty());
    assert_eq!(casc.kv().pages_for(&bob).len(), 1);
    assert_eq!(
        casc.answer()
            .get_exact(&alice.render().as_str().into(), "q", 1),
        None
    );

    // THE PROOF: every page returned to the fleet free pool is byte-for-byte zero — no residue can
    // be read back out of reused GPU memory.
    assert_eq!(casc.free_pool().len(), 2);
    for page in casc.free_pool() {
        assert!(
            page.is_zeroized(),
            "reclaimed KV page still carries residue"
        );
        assert!(page.bytes().iter().all(|b| *b == 0));
    }

    // The session-end scope variant reaches the same zeroize-before-free discipline via the seam.
    let carol = PartitionKey::resolve(DataClass::Confidential, "carol", Some("risk"), "sdlc");
    casc.kv()
        .insert_page(carol.clone(), KvPage::new(vec![7, 7, 7, 7]));
    let sess_ack = (&mut casc as &mut dyn ErasureParticipant)
        .erase(&ErasureRequest::session_end(carol.clone()));
    assert_eq!(sess_ack.kv_pages_zeroized(), 1);
    assert!(casc.kv().pages_for(&carol).is_empty());
    assert!(casc.free_pool().last().unwrap().is_zeroized());
}
