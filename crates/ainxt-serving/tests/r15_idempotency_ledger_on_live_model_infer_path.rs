// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-15 serving-ops (LOW) — ADR-013's inference idempotency ledger
//! (`ainxt_serving::idempotency::IdempotencyLedger`) was fully implemented and unit-tested since
//! round-3, but the audit found it had **no caller anywhere on the live `model_infer` admission
//! path** — `ServingGate::model_infer` dispatched to the executor and `ServingGate::complete` freed
//! pool slots without ever touching a ledger, so a gateway retry after a dropped call had no defence
//! against double-billing tokens, and two divergent answers for the same logical request could both
//! be reported as final with nothing to catch it.
//!
//! Fail-before: `ServingGate::complete_billed` / `infer_is_committed` / `infer_attempt` /
//! `infer_total_billed` did not exist — this file would not compile, and `model_infer` never opened a
//! ledger attempt. Pass-after: `model_infer` opens a ledger attempt on every dispatch, and
//! `complete_billed` enforces exactly-once billing + the divergence guard on the SAME gate instance
//! the live admission path serves through.

use ainxt_serving::attestation::{AttestationConfig, AttestationGate};
use ainxt_serving::gate::{InferExecutor, InferRequest, NodeCandidate, ServingGate, StreamHandle};
use ainxt_serving::idempotency::CommitError;
use ainxt_serving::preemption::PreemptionScheduler;
use ainxt_serving::{DataClass, FairnessLimiter, PriorityClass, TenantId};

struct FakeExecutor;
impl InferExecutor for FakeExecutor {
    fn execute(&self, req: &InferRequest, node_id: &str) -> StreamHandle {
        StreamHandle(format!("stream:{}@{}", req.seq_id, node_id))
    }
}

fn gate() -> ServingGate {
    ServingGate::new(
        AttestationGate::new(AttestationConfig {
            quote_ttl: 1000,
            grace_ttl: 0,
        }),
        FairnessLimiter::new(1000, 1000),
        PreemptionScheduler::new(4),
    )
}

fn req(seq: u64, tenant: &str) -> InferRequest {
    InferRequest {
        seq_id: seq,
        model_id: "qwen-32b".into(),
        priority: PriorityClass::Standard,
        tenant: TenantId::new(tenant),
        data_class: DataClass::Internal,
        total_units: 100,
        kv_pages: 4,
    }
}

#[test]
fn r15_model_infer_opens_a_ledger_attempt_and_complete_billed_bills_exactly_once() {
    let mut g = gate();
    let candidates = vec![NodeCandidate::new("n1", true)];
    let r = req(1, "dept-a");

    // Nothing has been dispatched yet — no attempt on record.
    assert_eq!(g.infer_attempt(&r), None);
    assert!(!g.infer_is_committed(&r));

    // Admit: `model_infer` is the live path, and it now opens a ledger attempt as part of dispatch.
    let admission = g.model_infer(&r, &candidates, 0, true, &FakeExecutor);
    assert!(admission.is_admitted());
    assert_eq!(
        g.infer_attempt(&r),
        Some(1),
        "model_infer opened attempt 1 on the live path"
    );
    assert!(
        !g.infer_is_committed(&r),
        "not committed until complete_billed"
    );

    // Complete + bill: the FIRST commit for this logical request bills exactly the reported tokens.
    let outcome = g
        .complete_billed(&r, 512, 0xAAAA)
        .expect("first commit succeeds");
    assert_eq!(outcome.billed_now, 512);
    assert_eq!(g.infer_total_billed(), 512);
    assert!(g.infer_is_committed(&r));
    assert_eq!(
        g.infer_attempt(&r),
        None,
        "no in-flight attempt once committed"
    );

    // A duplicate commit of the SAME answer (e.g. a caller that double-reports completion) bills
    // NOTHING further — exactly-once billing holds even under a duplicate call on the live gate.
    let dup = g
        .complete_billed(&r, 512, 0xAAAA)
        .expect("idempotent replay is a safe no-op");
    assert_eq!(dup.billed_now, 0);
    assert_eq!(g.infer_total_billed(), 512, "still billed exactly once");
}

#[test]
fn r15_divergent_completion_for_the_same_request_is_rejected_on_the_live_gate() {
    let mut g = gate();
    let candidates = vec![NodeCandidate::new("n1", true)];
    let r = req(2, "dept-b");

    assert!(g
        .model_infer(&r, &candidates, 0, true, &FakeExecutor)
        .is_admitted());
    g.complete_billed(&r, 100, 0x1111).unwrap();

    // A second, DIFFERENT answer for the identical logical request (tenant + seq_id) is the concrete
    // "two divergent answers to one logical request" failure ADR-013 exists to catch — it is
    // rejected, not silently accepted as a second bill.
    let err = g.complete_billed(&r, 100, 0x2222);
    assert_eq!(
        err,
        Err(CommitError::DivergentResult {
            existing_hash: 0x1111,
            attempted_hash: 0x2222
        })
    );
    // Billing stayed at exactly the first, valid commit — the rejected divergent call billed nothing.
    assert_eq!(g.infer_total_billed(), 100);
}

#[test]
fn r15_retry_after_drop_resumes_under_the_same_key_without_double_billing() {
    // A drop before `complete_billed` (e.g. the node was drained mid-generation, SERVING_OPS.md §4
    // step 2) never committed — the SAME (tenant, seq_id) retried through `model_infer` a second time
    // resumes as attempt 2 under the identical ledger key, and only the attempt that actually reaches
    // `complete_billed` bills.
    let mut g = gate();
    let candidates = vec![NodeCandidate::new("n1", true)];
    let r = req(3, "dept-c");

    assert!(g
        .model_infer(&r, &candidates, 0, true, &FakeExecutor)
        .is_admitted());
    assert_eq!(g.infer_attempt(&r), Some(1));
    // Simulate the drop: free the pool slot WITHOUT billing (plain `complete`, not `complete_billed`).
    g.complete(&r);

    // The gateway retries the identical logical request.
    let retry = g.model_infer(&r, &candidates, 0, true, &FakeExecutor);
    assert!(
        retry.is_admitted(),
        "the pool slot was freed by the drop, so the retry is admitted"
    );
    assert_eq!(
        g.infer_attempt(&r),
        Some(2),
        "the retry resumed as attempt 2 under the same key"
    );

    let outcome = g.complete_billed(&r, 200, 0xBEEF).unwrap();
    assert_eq!(
        outcome.billed_now, 200,
        "billed exactly once, on the attempt that actually finished"
    );
    assert_eq!(g.infer_total_billed(), 200);
}

#[test]
fn r15_different_logical_requests_never_share_a_ledger_key() {
    // Two different tenants at two different seq_ids (the scheduler's `seq_id` namespace is global
    // per pool, per `PreemptionScheduler` — the ledger key additionally folds in the tenant so a
    // future scheduler that DID scope seq_id per-tenant still could not collide two tenants'
    // ledger entries) must never collide in the ledger — each is billed independently.
    let mut g = gate();
    let candidates = vec![NodeCandidate::new("n1", true)];
    let a = req(100, "dept-a");
    let b = req(101, "dept-b");

    assert!(g
        .model_infer(&a, &candidates, 0, true, &FakeExecutor)
        .is_admitted());
    assert!(g
        .model_infer(&b, &candidates, 0, true, &FakeExecutor)
        .is_admitted());
    g.complete_billed(&a, 10, 1).unwrap();
    g.complete_billed(&b, 20, 2).unwrap();
    assert_eq!(
        g.infer_total_billed(),
        30,
        "distinct tenants bill independently"
    );

    let mut g2 = gate();
    let c = req(1, "dept-a");
    let d = req(2, "dept-a"); // same tenant, DIFFERENT seq_id
    assert!(g2
        .model_infer(&c, &candidates, 0, true, &FakeExecutor)
        .is_admitted());
    assert!(g2
        .model_infer(&d, &candidates, 0, true, &FakeExecutor)
        .is_admitted());
    g2.complete_billed(&c, 5, 1).unwrap();
    g2.complete_billed(&d, 7, 2).unwrap();
    assert_eq!(g2.infer_total_billed(), 12);
}
