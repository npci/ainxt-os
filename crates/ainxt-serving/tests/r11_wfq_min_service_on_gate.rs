// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-11 Serving-Ops gap-6 (SRV-07) — the served [`ServingGate`]'s per-tenant fairness is now the
//! §2 **WFQ minimum-service guarantee**, not merely a concurrency cap.
//!
//! The audit found the served fairness path was [`FairnessLimiter`] alone — a per-tenant concurrency
//! *ceiling*. A ceiling caps a greedy tenant, but under a saturated pool it does NOT guarantee a
//! low-weight tenant *forward progress*: a sibling's burst can sit ahead of it in the admission order
//! indefinitely. SERVING_OPS.md §2 promises a **minimum service rate** per tenant, which needs
//! deficit-round-robin queue ordering — the mechanism [`crate::wfq::WfqScheduler`] implements but which
//! was not reachable from the gate the daemon serves.
//!
//! Fail-before: `ServingGate::{with_wfq, wfq_enqueue, wfq_round, wfq_backlog, has_wfq}` did not exist —
//! this file would not compile. Pass-after: a gate opted into WFQ dispatches a light tenant's queued
//! turn in the SAME round as a 50-deep heavy backlog (never starved), and the per-round dispatch is
//! weight-proportional.

use ainxt_serving::attestation::{AttestationConfig, AttestationGate};
use ainxt_serving::gate::ServingGate;
use ainxt_serving::preemption::PreemptionScheduler;
use ainxt_serving::{FairnessLimiter, TenantId};

fn gate_with_wfq() -> ServingGate {
    ServingGate::new(
        AttestationGate::new(AttestationConfig {
            quote_ttl: 300,
            grace_ttl: 30,
        }),
        FairnessLimiter::new(8, 1),
        PreemptionScheduler::new(4),
    )
    .with_qos_queue_depth(64)
    // Heavy department weighted 4×; light department weighted 1× — the §2 relative shares.
    .with_wfq(1, &[("dept-heavy", 4), ("dept-light", 1)])
}

#[test]
fn r11_wfq_min_service_on_served_gate_protects_light_tenant() {
    let mut gate = gate_with_wfq();
    assert!(
        gate.has_wfq(),
        "the served gate now orders its wait queue by §2 WFQ"
    );

    // The heavy tenant FLOODS the over-capacity wait queue (50 turns); the light tenant has ONE queued
    // turn arriving after the flood. A plain concurrency cap would admit the flood ahead of it.
    for i in 0..50 {
        assert!(gate.wfq_enqueue("dept-heavy", i, 1));
    }
    assert!(gate.wfq_enqueue("dept-light", 9_000, 1));

    let light = TenantId::new("dept-light");
    assert_eq!(
        gate.wfq_backlog(&light),
        1,
        "light tenant has one queued turn behind the flood"
    );

    // ONE WFQ round: the light tenant's turn is dispatched THIS round — the minimum-service guarantee
    // §2 promises, which a concurrency cap does not give (its turn would wait behind the 50-deep burst).
    let round = gate.wfq_round();
    let light_n = round
        .iter()
        .filter(|(t, _)| t.as_str() == "dept-light")
        .count();
    let heavy_n = round
        .iter()
        .filter(|(t, _)| t.as_str() == "dept-heavy")
        .count();
    assert_eq!(
        light_n, 1,
        "light tenant GUARANTEED service in round 1, never starved: {round:?}"
    );
    // Weight-proportional dispatch: heavy (weight 4) clears 4× the light tenant's share in the round.
    assert_eq!(
        heavy_n, 4,
        "heavy tenant served proportional to its weight, not unboundedly: {round:?}"
    );
    assert_eq!(
        gate.wfq_backlog(&light),
        0,
        "the light tenant is fully served this round"
    );

    // Idempotency of drain: subsequent rounds continue clearing the heavy backlog deterministically,
    // and the (now-empty) light tenant never blocks progress.
    let r2 = gate.wfq_round();
    assert!(
        r2.iter().all(|(t, _)| t.as_str() == "dept-heavy"),
        "only the still-backlogged tenant: {r2:?}"
    );
    assert_eq!(
        r2.len(),
        4,
        "steady weight-4 service rate for the backlogged heavy tenant"
    );
}

#[test]
fn r11_wfq_disabled_by_default_is_a_pure_no_op() {
    // A gate WITHOUT `.with_wfq(...)` is unchanged: WFQ is absent, enqueue is refused (caller falls back
    // to the plain bounded queue), and a round dispatches nothing. Preserves the cap-only behaviour for
    // deployments that do not opt in.
    let mut gate = ServingGate::new(
        AttestationGate::new(AttestationConfig {
            quote_ttl: 300,
            grace_ttl: 30,
        }),
        FairnessLimiter::new(8, 1),
        PreemptionScheduler::new(4),
    );
    assert!(!gate.has_wfq());
    assert!(
        !gate.wfq_enqueue("dept-x", 1, 1),
        "enqueue is a no-op when WFQ is not enabled"
    );
    assert!(gate.wfq_round().is_empty());
    assert_eq!(gate.wfq_backlog(&TenantId::new("dept-x")), 0);
}
