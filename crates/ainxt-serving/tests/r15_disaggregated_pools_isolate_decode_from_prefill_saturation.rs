// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-15 serving-ops (MEDIUM) — SERVING_OPS.md §1 (gap 7) names the required fix as a **physical
//! pool split**: "a request's decode never waits on another request's prefill, because they
//! physically execute on different GPUs... not by scheduling around it... but by removing the shared
//! resource." The audit found the crate had the KV relay fabric ([`ainxt_serving::kv_relay`]) and the
//! chunked-prefill *scheduling* mitigation ([`ainxt_serving::wfq`]), but nothing composed two
//! independent admission gates so "decode never waits on prefill" was a checkable *structural*
//! property rather than a scheduling-fairness outcome that still shares the same pool underneath.
//!
//! Fail-before: `ainxt_serving::disagg::DisaggregatedPools` did not exist — this file would not
//! compile. Pass-after: saturating the Prefill Pool completely has ZERO effect on Decode Pool
//! admission, because they are two independent `ServingGate`s joined only by the KV relay.

use ainxt_serving::attestation::{AttestationConfig, AttestationGate};
use ainxt_serving::disagg::DisaggregatedPools;
use ainxt_serving::gate::{
    InferAdmission, InferExecutor, InferRequest, NodeCandidate, ServingGate, StreamHandle,
};
use ainxt_serving::preemption::PreemptionScheduler;
use ainxt_serving::{DataClass, FairnessLimiter, PriorityClass, TenantId};

struct FakeExecutor;
impl InferExecutor for FakeExecutor {
    fn execute(&self, req: &InferRequest, node_id: &str) -> StreamHandle {
        StreamHandle(format!("stream:{}@{}", req.seq_id, node_id))
    }
}

fn one_slot_gate() -> ServingGate {
    ServingGate::new(
        AttestationGate::new(AttestationConfig {
            quote_ttl: 1000,
            grace_ttl: 0,
        }),
        FairnessLimiter::new(1000, 1000),
        PreemptionScheduler::new(1),
    )
}

fn req(seq: u64, tenant: &str, priority: PriorityClass) -> InferRequest {
    InferRequest {
        seq_id: seq,
        model_id: "qwen-32b".into(),
        priority,
        tenant: TenantId::new(tenant),
        data_class: DataClass::Internal,
        total_units: 100,
        kv_pages: 4,
    }
}

#[test]
fn r15_decode_admission_is_structurally_independent_of_prefill_pool_saturation() {
    let mut pools = DisaggregatedPools::new(one_slot_gate(), one_slot_gate());
    let candidates = vec![NodeCandidate::new("n1", true)];

    // Saturate the Prefill Pool: one admitted, a second same-priority arrival sheds (nothing lower
    // priority to preempt) — this is a genuinely full pool, not a synthetic assertion.
    let p1 = req(1, "sdlc", PriorityClass::Standard);
    assert!(pools
        .admit_prefill(&p1, &candidates, 0, true, &FakeExecutor)
        .is_admitted());
    let p2 = req(2, "sdlc", PriorityClass::Standard);
    assert_eq!(
        pools.admit_prefill(&p2, &candidates, 0, true, &FakeExecutor),
        InferAdmission::Shed,
        "precondition: the Prefill Pool is genuinely full"
    );

    // A batch of decode admissions for unrelated interactive turns must ALL succeed — the Decode
    // Pool never even observes the Prefill Pool's saturated state.
    for seq in 10..20u64 {
        let d = req(seq, "chat", PriorityClass::Interactive);
        assert!(
            pools
                .admit_decode(&d, &candidates, 0, true, &FakeExecutor)
                .is_admitted(),
            "decode seq {seq} must admit regardless of prefill saturation"
        );
        pools.complete_decode(&d);
    }

    // And the shed above was honest backpressure, not permanent: freeing the prefill slot lets the
    // second prefill in, on the SAME pool that was full — proving the two pools' state never mixed.
    pools.complete_prefill(&p1);
    assert!(pools
        .admit_prefill(&p2, &candidates, 0, true, &FakeExecutor)
        .is_admitted());
}

#[test]
fn r15_kv_relay_is_the_only_channel_between_the_two_pools() {
    use ainxt_serving::kv_relay::{
        DecodeNodeId, FabricRelation, InMemoryKvTransport, TransferOutcome,
    };

    let mut pools = DisaggregatedPools::new(one_slot_gate(), one_slot_gate());
    let node = DecodeNodeId::new("decode-0");
    pools.relay_mut().grant_credits(&node, 8);
    let mut transport = InMemoryKvTransport::new();

    // A prefill burst that exceeds the decode node's landing credits is held, not pushed — the
    // structural boundary between the pools is credit-gated, never a silent overflow.
    let held = pools.handoff(
        &mut transport,
        "burst",
        &node,
        20,
        FabricRelation::SameDomain,
    );
    assert!(matches!(
        held,
        TransferOutcome::Throttled {
            requested: 20,
            available: 8
        }
    ));
    assert_eq!(
        transport.delivered_count(),
        0,
        "throttled push never touches the fabric"
    );

    // A push within credit is delivered exactly once, even under a retried submission.
    let out = pools.handoff(
        &mut transport,
        "req-1",
        &node,
        8,
        FabricRelation::SameDomain,
    );
    assert!(out.is_delivered());
    assert_eq!(
        pools.handoff(
            &mut transport,
            "req-1",
            &node,
            8,
            FabricRelation::SameDomain
        ),
        TransferOutcome::AlreadyDelivered
    );
    assert_eq!(transport.delivered_count(), 1);
}
