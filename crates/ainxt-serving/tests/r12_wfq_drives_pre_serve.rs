// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-12 Serving-Ops gap-2 (MEDIUM) — the §2 WFQ minimum-service ordering now **drives the live
//! wait queue** of the served admission path ([`ServingGate::pre_serve`]), not a blind FIFO counter.
//!
//! The audit found `with_wfq` *configured* a [`WfqScheduler`] the served `pre_serve` path never
//! enqueued into: over-capacity turns bumped a first-come-first-served `qos_queued` counter, so a
//! greedy tenant that flooded the queue first sat ahead of a low-weight sibling's turn indefinitely —
//! exactly the starvation §2's minimum-service guarantee exists to prevent. The `wfq_enqueue`/
//! `wfq_round` methods existed but were a parallel, manually-driven API disconnected from the live
//! admission decision (`ainxt-server`'s `/v1/chat` calls `pre_serve`).
//!
//! Fail-before: with WFQ configured, `pre_serve`'s Enqueued path used the blind FIFO counter, so a
//! drain round would clear the greedy tenant's turns in arrival order and the light tenant would wait
//! behind the whole flood — `pre_serve_drain_round` did not exist. Pass-after: an over-capacity turn
//! from `pre_serve` lands on the WFQ scheduler, and ONE drain round dispatches the light tenant's
//! turn in weight-proportional order the same round as a 40-deep greedy backlog — never starved.

use ainxt_serving::attestation::{AttestationConfig, AttestationGate};
use ainxt_serving::gate::ServingGate;
use ainxt_serving::preemption::PreemptionScheduler;
use ainxt_serving::slo::{QosRequest, SloDecision};
use ainxt_serving::{FairnessLimiter, PriorityClass, TenantId};

/// A gate whose single running slot is full (so every further arrival must queue), opted into a §2
/// WFQ wait queue with heavy:light = 4:1 relative shares and a deep ceiling.
fn saturated_gate_with_wfq() -> ServingGate {
    ServingGate::new(
        AttestationGate::new(AttestationConfig {
            quote_ttl: 300,
            grace_ttl: 30,
        }),
        // Ample fairness capacity + per-tenant quota so fairness is NOT the thing that queues — the
        // pool concurrency (scheduler capacity 1) is, which is what exercises the WFQ wait queue.
        FairnessLimiter::new(1000, 1000),
        PreemptionScheduler::new(1),
    )
    .with_qos_queue_depth(128)
    .with_wfq(1, &[("dept-heavy", 4), ("dept-light", 1)])
}

fn qos(seq: u64, tenant: &str) -> QosRequest {
    // All the same priority so preemption never fires — the ONLY reason an arrival queues is the full
    // pool, so the queue backend (FIFO vs WFQ) is what the test isolates.
    QosRequest::new(seq, PriorityClass::Standard, tenant)
}

#[test]
fn r12_wfq_drives_pre_serve_wait_queue_min_service() {
    let mut gate = saturated_gate_with_wfq();
    assert!(gate.has_wfq());

    // (1) Fill the single pool slot with a heavy-tenant turn (admitted, running).
    assert_eq!(
        gate.pre_serve(&qos(0, "dept-heavy")),
        SloDecision::Admitted { preempted: None }
    );

    // (2) The heavy tenant FLOODS the over-capacity wait queue via the LIVE `pre_serve` path (40 turns
    //     that can neither run nor preempt). Each must land on the WFQ scheduler, not a FIFO counter.
    for seq in 1..=40u64 {
        assert!(
            matches!(
                gate.pre_serve(&qos(seq, "dept-heavy")),
                SloDecision::Enqueued { .. }
            ),
            "over-capacity heavy turn {seq} must enqueue"
        );
    }
    // (3) ONE light-tenant turn arrives AFTER the flood — dead last in arrival order.
    assert!(matches!(
        gate.pre_serve(&qos(9_000, "dept-light")),
        SloDecision::Enqueued { .. }
    ));

    let light = TenantId::new("dept-light");
    let heavy = TenantId::new("dept-heavy");
    assert_eq!(
        gate.wfq_backlog(&light),
        1,
        "the light turn is queued behind the 40-deep flood"
    );
    assert_eq!(gate.wfq_backlog(&heavy), 40);
    assert_eq!(
        gate.qos_queue_depth(),
        41,
        "live wait-queue depth is the WFQ backlog, not a FIFO count"
    );

    // (4) THE PROOF: one WFQ drain round off the LIVE queue dispatches the light tenant's single turn
    //     THIS round — the §2 minimum-service guarantee — despite it arriving last behind a 40-deep
    //     greedy backlog. A blind FIFO would not have surfaced it until all 40 heavy turns cleared.
    let round = gate.pre_serve_drain_round();
    let light_n = round.iter().filter(|(t, _)| t == &light).count();
    let heavy_n = round.iter().filter(|(t, _)| t == &heavy).count();
    assert_eq!(
        light_n, 1,
        "light tenant GUARANTEED service in round 1, never starved: {round:?}"
    );
    assert_eq!(
        heavy_n, 4,
        "heavy tenant served proportional to its 4x weight, not unboundedly"
    );
    assert_eq!(
        gate.wfq_backlog(&light),
        0,
        "the light tenant is fully served this drain round"
    );
    assert_eq!(
        gate.wfq_backlog(&heavy),
        36,
        "the greedy tenant still has its remaining backlog"
    );
}

#[test]
fn r12_wfq_pre_serve_still_sheds_honestly_at_the_ceiling() {
    // The WFQ queue is still BOUNDED — once the ceiling is hit the arrival is shed (503-equivalent),
    // never an unbounded queue. Ceiling of 2 with a full single-slot pool.
    let mut gate = ServingGate::new(
        AttestationGate::new(AttestationConfig {
            quote_ttl: 300,
            grace_ttl: 30,
        }),
        FairnessLimiter::new(1000, 1000),
        PreemptionScheduler::new(1),
    )
    .with_qos_queue_depth(2)
    .with_wfq(1, &[("t", 1)]);

    assert!(gate.pre_serve(&qos(0, "t")).is_admitted()); // fills the slot
    assert!(matches!(
        gate.pre_serve(&qos(1, "t")),
        SloDecision::Enqueued { depth: 1 }
    ));
    assert!(matches!(
        gate.pre_serve(&qos(2, "t")),
        SloDecision::Enqueued { depth: 2 }
    ));
    // Ceiling hit → honest shed, nothing enqueued past the bound.
    assert!(
        gate.pre_serve(&qos(3, "t")).is_shed(),
        "bounded WFQ queue sheds at its ceiling"
    );
    assert_eq!(
        gate.wfq_total_backlog(),
        2,
        "the queue never grew past its bound"
    );
}

#[test]
fn r12_no_wfq_pre_serve_is_unchanged_fifo_counter() {
    // Regression guard: with NO WFQ configured, `pre_serve` is the unchanged bounded-FIFO path — the
    // shipped-default behaviour (and the r6 pre_serve tests) must not shift.
    let mut gate = ServingGate::new(
        AttestationGate::new(AttestationConfig {
            quote_ttl: 300,
            grace_ttl: 30,
        }),
        FairnessLimiter::new(1000, 1000),
        PreemptionScheduler::new(1),
    )
    .with_qos_queue_depth(2);
    assert!(!gate.has_wfq());
    assert!(gate.pre_serve(&qos(0, "t")).is_admitted());
    assert!(matches!(
        gate.pre_serve(&qos(1, "t")),
        SloDecision::Enqueued { depth: 1 }
    ));
    assert_eq!(
        gate.qos_queue_depth(),
        1,
        "FIFO counter drives the queue depth when WFQ is off"
    );
    // A drain round is empty (no WFQ scheduler) — the cap-only path never used one.
    assert!(gate.pre_serve_drain_round().is_empty());
}
