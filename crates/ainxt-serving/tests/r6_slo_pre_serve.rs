// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-6 Serving-Ops — the SLO-aware QoS admission (P0/P1/P2 priority classes + chunk/step
//! preemption) exposed as a clean `pre_serve` entrypoint **the composition applies on the main
//! path** (SERVING_OPS.md §2).
//!
//! R5 built [`ainxt_serving::slo::SloAdmissionController`] as the standalone §2 primitive, but it had
//! **no caller** — the object the served composition actually holds is the node-level
//! [`ainxt_serving::gate::ServingGate`], which admitted priority-blind on the main path (it exposed
//! only `model_infer`, the node-level capability, and `pre_serve_check`, the attestation fence — no
//! priority-aware admission entrypoint). This round exposes `ServingGate::pre_serve`: the SLO-aware
//! QoS decision the request path makes first, running the SAME `qos_admit` policy the controller
//! documents but over the gate's OWN pool state, so the main chat path and the node-level
//! `model.infer` capability compete for ONE pool-concurrency view.
//!
//! Fail-before: `ServingGate::pre_serve` / `pre_serve_complete` / `with_qos_queue_depth` did not
//! exist — this test would not compile. Pass-after: the entrypoint composes priority + preemption +
//! fairness + bounded-queue backpressure, and shares pool state with `model_infer`.

use ainxt_serving::attestation::{AttestationConfig, AttestationGate};
use ainxt_serving::gate::{InferExecutor, InferRequest, NodeCandidate, ServingGate, StreamHandle};
use ainxt_serving::preemption::{KvDisposition, PreemptionScheduler};
use ainxt_serving::slo::{QosPreemption, QosRequest, SloDecision};
use ainxt_serving::{DataClass, FairnessLimiter, PriorityClass, ShedReason, TenantId};

/// A fake executor for the node-level `model_infer` path (records dispatch, returns a handle).
struct FakeExecutor;
impl InferExecutor for FakeExecutor {
    fn execute(&self, req: &InferRequest, node_id: &str) -> StreamHandle {
        StreamHandle(format!("stream:{}@{}", req.seq_id, node_id))
    }
}

fn gate(pool: usize, quota: u32) -> ServingGate {
    ServingGate::new(
        AttestationGate::new(AttestationConfig {
            quote_ttl: 100,
            grace_ttl: 15,
        }),
        FairnessLimiter::new(1000, quota),
        PreemptionScheduler::new(pool),
    )
}

#[test]
fn r6_slo_pre_serve_priority_preemption_on_main_path() {
    // A single-slot pool. The main path carries a PriorityClass and admits through `pre_serve`.
    let mut g = gate(1, 1000);

    // A P2 batch program run (a 20-min-scale generation) is admitted on the main path.
    let batch = QosRequest::new(1, PriorityClass::Batch, "prog").with_work(100_000, 8);
    assert_eq!(
        g.pre_serve(&batch),
        SloDecision::Admitted { preempted: None }
    );
    assert_eq!(g.qos_queue_depth(), 0);

    // A P0 incident arrives into the full pool. It must NOT queue behind the 20-minute batch — it
    // preempts the lowest-priority incumbent at its next chunk/step boundary and is admitted now.
    let p0 = QosRequest::new(2, PriorityClass::Interactive, "ops");
    match g.pre_serve(&p0) {
        SloDecision::Admitted {
            preempted:
                Some(QosPreemption {
                    victim,
                    victim_priority,
                    disposition,
                }),
        } => {
            assert_eq!(victim, 1, "the P2 batch is the preempted victim");
            assert_eq!(victim_priority, PriorityClass::Batch);
            // A P2 victim checkpoints to PENDING and re-queues at the Program Supervisor level.
            assert_eq!(
                disposition,
                KvDisposition::CheckpointedToPending { resume_from: 0 }
            );
        }
        other => panic!("expected the P0 to preempt the P2 on the main path, got {other:?}"),
    }

    // Completing the P0 frees the slot on the same shared pool state.
    let out = g
        .pre_serve_complete(&p0)
        .expect("complete an admitted turn");
    assert!(out.slot_freed);
}

#[test]
fn r6_pre_serve_shares_one_pool_view_with_model_infer() {
    // THE cross-path property: `pre_serve` (main chat path) and `model_infer` (node-level capability)
    // admit into the SAME scheduler/fairness — one physical pool, not two divergent copies. A batch
    // admitted through the node-level `model_infer` is preemptible by a P0 arriving on the main path.
    let mut g = gate(1, 1000);
    let candidates = vec![NodeCandidate::new("n1", true)];

    // A P2 batch enters through the node-level `model_infer` capability and occupies the single slot.
    let infer_batch = InferRequest {
        seq_id: 10,
        model_id: "qwen-32b".into(),
        priority: PriorityClass::Batch,
        tenant: TenantId::new("prog"),
        data_class: DataClass::Internal,
        total_units: 100_000,
        kv_pages: 8,
    };
    assert!(
        g.model_infer(&infer_batch, &candidates, 0, true, &FakeExecutor)
            .is_admitted(),
        "the node-level batch is admitted onto the shared pool"
    );

    // A P0 incident arrives on the MAIN path. If the two paths held separate pools this would find an
    // empty pool and admit without preemption; because they share ONE pool it preempts the batch.
    let p0 = QosRequest::new(11, PriorityClass::Interactive, "ops");
    match g.pre_serve(&p0) {
        SloDecision::Admitted { preempted: Some(p) } => {
            assert_eq!(
                p.victim, 10,
                "the main-path P0 preempts the node-level batch — one shared pool"
            );
            assert_eq!(p.victim_priority, PriorityClass::Batch);
        }
        other => panic!("expected cross-path preemption over one shared pool, got {other:?}"),
    }
}

#[test]
fn r6_pre_serve_rejects_over_quota_tenant_without_taking_a_slot() {
    // Per-tenant WFQ fairness on the main path: a greedy tenant is capped at its quota and never eats
    // a sibling's reserved share — refused for quota (not shed), and no pool slot is consumed.
    let mut g = gate(10, 1);
    let first = QosRequest::new(1, PriorityClass::Standard, "greedy");
    assert!(g.pre_serve(&first).is_admitted());
    assert_eq!(
        g.pre_serve(&QosRequest::new(2, PriorityClass::Standard, "greedy")),
        SloDecision::RejectedOverQuota { quota: 1 },
    );
}

#[test]
fn r6_pre_serve_default_gate_sheds_when_full_and_nothing_lower() {
    // The shipped default gate has NO wait queue (depth 0): a peer arrival into a full pool with
    // nothing lower to preempt is shed as honest backpressure, never enqueued unboundedly.
    let mut g = gate(1, 1000);
    assert!(g
        .pre_serve(&QosRequest::new(1, PriorityClass::Interactive, "a"))
        .is_admitted());
    assert_eq!(
        g.pre_serve(&QosRequest::new(2, PriorityClass::Interactive, "b")),
        SloDecision::Shed(ShedReason::QueueFull { max_queue_depth: 0 }),
    );
    assert_eq!(g.qos_queue_depth(), 0);
}

#[test]
fn r6_pre_serve_bounded_queue_enqueues_then_sheds_when_opted_in() {
    // A deployment that opts a surface into a bounded wait queue: a peer that cannot preempt waits in
    // the queue up to the ceiling, then is shed. The queue is a HARD cap — never unbounded.
    let mut g = gate(1, 1000).with_qos_queue_depth(1);
    assert!(g
        .pre_serve(&QosRequest::new(1, PriorityClass::Interactive, "a"))
        .is_admitted());
    assert_eq!(
        g.pre_serve(&QosRequest::new(2, PriorityClass::Interactive, "b")),
        SloDecision::Enqueued { depth: 1 },
    );
    assert_eq!(
        g.pre_serve(&QosRequest::new(3, PriorityClass::Interactive, "c")),
        SloDecision::Shed(ShedReason::QueueFull { max_queue_depth: 1 }),
    );

    // Completing the running turn signals a queued turn may now be promoted (the caller re-drives).
    let out = g
        .pre_serve_complete(&QosRequest::new(1, PriorityClass::Interactive, "a"))
        .expect("complete the running turn");
    assert!(out.slot_freed);
    assert!(out.dequeue_head, "a queued turn may now be promoted");
    assert_eq!(g.qos_queue_depth(), 0);
}
