// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! The disaggregated prefill/decode pool split — the **structural interference-elimination
//! mechanism** SERVING_OPS.md §1 (gap 7) requires.
//!
//! §1 names the interference problem precisely: prefill (compute-bound, parallel over prompt tokens)
//! and decode (memory-bandwidth-bound, one token at a time) have opposite hardware profiles, so
//! co-locating them on one GPU means a long prefill (an SDLC turn's large repo-context prompt) blocks
//! the decode step of every other in-flight sequence on that GPU for the prefill's whole duration.
//! [`crate::wfq`]'s chunked-prefill interleaving mitigates this *within* one pool by carving a long
//! prefill into steps a decode step can be scheduled between — but that is scheduling AROUND a shared
//! resource, not removing it. The design is explicit that gap 7 is closed only by **physical pool
//! separation**: "a request's decode never waits on another request's prefill, because they physically
//! execute on different GPUs. This structurally eliminates the interference class gap 7 names — not
//! by scheduling around it... but by removing the shared resource."
//!
//! [`crate::kv_relay`] already builds the fabric connecting the two pools (credit-based flow control +
//! idempotency-ledger-backed retry). What the audit found still missing is the composition that makes
//! the *separation itself* a checkable property rather than an operational convention: nothing in the
//! crate proved that admitting decode work is structurally independent of how saturated the prefill
//! pool is. [`DisaggregatedPools`] is that composition: it holds **two independent [`ServingGate`]s**
//! — independent attestation state, independent per-tenant fairness quotas, independent preemption
//! schedulers, one pool's [`crate::idempotency::IdempotencyLedger`] separate from the other's — joined
//! *only* by the [`KvRelay`] fabric. A decode admission touches only the decode gate's own state, so a
//! fully-saturated prefill pool can never delay, shed, or preempt a decode admission — the hardware
//! separation the design calls for, made a property [`admit_decode_is_never_gated_by_prefill_saturation`]
//! (see the test module) can assert without a GPU.
//!
//! [`admit_decode_is_never_gated_by_prefill_saturation`]: tests::admit_decode_is_never_gated_by_prefill_saturation

use crate::gate::{InferAdmission, InferExecutor, InferRequest, NodeCandidate, ServingGate};
use crate::idempotency::IdempotencyLedger;
use crate::kv_relay::{
    prefill_to_decode_handoff, DecodeNodeId, FabricRelation, KvRelay, KvTransport, TransferOutcome,
};

/// The two **physically separate** serving pools (SERVING_OPS.md §1, gap 7): `prefill` and `decode`
/// are independent [`ServingGate`]s, joined only by the [`KvRelay`] fabric that hands finished
/// prefill's KV blocks to a decode node under credit-based admission. Nothing in this type lets a
/// prefill admission touch the decode pool's fairness/scheduler/attestation state or vice versa — the
/// separation is structural, not a convention the caller has to honour.
#[derive(Debug)]
pub struct DisaggregatedPools {
    prefill: ServingGate,
    decode: ServingGate,
    relay: KvRelay,
    /// The idempotency ledger for the KV **handoff** itself (distinct from either pool's own
    /// inference-billing ledger) — retry-safety for the physical block transfer, per SERVING_OPS.md §1.
    handoff_ledger: IdempotencyLedger,
}

impl DisaggregatedPools {
    /// Build the split from two independently-configured pools. A deployment typically sizes the
    /// decode pool's fairness/scheduler capacity differently from the prefill pool's (decode holds many
    /// more concurrent low-compute sequences; prefill holds fewer, heavier bursts) — this constructor
    /// takes them exactly as configured, imposing no shared state between them.
    pub fn new(prefill: ServingGate, decode: ServingGate) -> Self {
        DisaggregatedPools {
            prefill,
            decode,
            relay: KvRelay::new(),
            handoff_ledger: IdempotencyLedger::new(),
        }
    }

    /// Mutable access to the Prefill Pool's own gate (e.g. to submit its attestation quotes).
    pub fn prefill_mut(&mut self) -> &mut ServingGate {
        &mut self.prefill
    }

    /// Mutable access to the Decode Pool's own gate.
    pub fn decode_mut(&mut self) -> &mut ServingGate {
        &mut self.decode
    }

    /// Mutable access to the KV relay fabric joining the two pools.
    pub fn relay_mut(&mut self) -> &mut KvRelay {
        &mut self.relay
    }

    /// Admit a **prefill-phase** request. Touches only the Prefill Pool's own attestation, fairness,
    /// and preemption state.
    pub fn admit_prefill(
        &mut self,
        req: &InferRequest,
        candidates: &[NodeCandidate],
        now: u64,
        verifier_reachable: bool,
        executor: &dyn InferExecutor,
    ) -> InferAdmission {
        self.prefill
            .model_infer(req, candidates, now, verifier_reachable, executor)
    }

    /// Admit a **decode-phase** request. Touches only the Decode Pool's own attestation, fairness, and
    /// preemption state — **structurally independent of the Prefill Pool's saturation**: this call can
    /// never observe, wait on, or be shed because of prefill-pool load, since it is a different
    /// [`ServingGate`] instance with its own capacity ceilings (SERVING_OPS.md §1, gap 7 — the
    /// interference is eliminated by removing the shared resource, not by scheduling around it).
    pub fn admit_decode(
        &mut self,
        req: &InferRequest,
        candidates: &[NodeCandidate],
        now: u64,
        verifier_reachable: bool,
        executor: &dyn InferExecutor,
    ) -> InferAdmission {
        self.decode
            .model_infer(req, candidates, now, verifier_reachable, executor)
    }

    /// Hand a finished prefill's KV blocks to a decode node over the credit-based relay — the ONLY
    /// channel connecting the two pools (SERVING_OPS.md §1). Credit-bounded (never OOMs the decode
    /// pool) and idempotency-ledger-backed (a link drop refunds credits and is safely retryable).
    pub fn handoff(
        &mut self,
        transport: &mut dyn KvTransport,
        req_key: &str,
        node: &DecodeNodeId,
        pages: u32,
        relation: FabricRelation,
    ) -> TransferOutcome {
        prefill_to_decode_handoff(
            &mut self.relay,
            transport,
            &mut self.handoff_ledger,
            req_key,
            node,
            pages,
            relation,
        )
    }

    /// Free the Prefill Pool's slot for a completed prefill generation.
    pub fn complete_prefill(&mut self, req: &InferRequest) {
        self.prefill.complete(req);
    }

    /// Free the Decode Pool's slot for a completed decode generation.
    pub fn complete_decode(&mut self, req: &InferRequest) {
        self.decode.complete(req);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::{AttestationConfig, AttestationGate};
    use crate::kv_relay::InMemoryKvTransport;
    use crate::preemption::PreemptionScheduler;
    use crate::{DataClass, FairnessLimiter, PriorityClass, TenantId};

    struct FakeExecutor;
    impl InferExecutor for FakeExecutor {
        fn execute(&self, req: &InferRequest, node_id: &str) -> crate::gate::StreamHandle {
            crate::gate::StreamHandle(format!("stream:{}@{}", req.seq_id, node_id))
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

    fn req(seq: u64, tenant: &str) -> InferRequest {
        InferRequest {
            seq_id: seq,
            model_id: "qwen-32b".into(),
            priority: PriorityClass::Batch,
            tenant: TenantId::new(tenant),
            data_class: DataClass::Internal,
            total_units: 100,
            kv_pages: 4,
        }
    }

    #[test]
    fn admit_decode_is_never_gated_by_prefill_saturation() {
        // THE PROOF (SERVING_OPS.md §1, gap 7): saturate the Prefill Pool completely, then show the
        // Decode Pool admits normally — because they are two independent `ServingGate`s, not one
        // undifferentiated pool a scheduler is merely trying to be fair over.
        //
        // Fail-before: `DisaggregatedPools` did not exist — this file would not compile, and the only
        // available composition (one `ServingGate` per candidate set) gave no way to make "decode never
        // waits on prefill" a checkable property distinct from ordinary priority scheduling.
        let mut pools = DisaggregatedPools::new(one_slot_gate(), one_slot_gate());
        let candidates = vec![NodeCandidate::new("n1", true)];

        // Fill the Prefill Pool's single slot.
        let p1 = req(1, "sdlc");
        assert!(
            pools
                .admit_prefill(&p1, &candidates, 0, true, &FakeExecutor)
                .is_admitted(),
            "first prefill fills the pool's only slot"
        );
        // A SECOND same-priority prefill arrival finds the pool full with nothing lower to preempt →
        // honest backpressure. This is the "20-minute SDLC prefill saturates its own pool" scenario.
        let p2 = req(2, "sdlc");
        assert_eq!(
            pools.admit_prefill(&p2, &candidates, 0, true, &FakeExecutor),
            InferAdmission::Shed,
            "the Prefill Pool is genuinely saturated"
        );

        // THE STRUCTURAL PROPERTY: a decode request for an UNRELATED interactive turn is admitted
        // immediately on the Decode Pool — it never observes, waits on, or is shed by the Prefill
        // Pool's saturation, because it is a completely separate gate with its own capacity.
        let d1 = InferRequest {
            priority: PriorityClass::Interactive,
            ..req(10, "chat")
        };
        assert!(
            pools
                .admit_decode(&d1, &candidates, 0, true, &FakeExecutor)
                .is_admitted(),
            "decode admission is structurally independent of prefill-pool saturation"
        );

        // Freeing the Prefill Pool's slot lets the second prefill in — proving the shed above was
        // genuine backpressure, not a permanent failure, and that `complete_prefill` only touches the
        // Prefill Pool's own state (the Decode Pool's admitted turn above is untouched by it).
        pools.complete_prefill(&p1);
        assert!(pools
            .admit_prefill(&p2, &candidates, 0, true, &FakeExecutor)
            .is_admitted());
    }

    #[test]
    fn handoff_moves_kv_blocks_between_the_two_pools_under_credit() {
        // The ONLY channel between the two structurally-separate pools is the KV relay — proven here
        // with the same credit-bounded, idempotent semantics `kv_relay` tests standalone, now reachable
        // through the composed `DisaggregatedPools` entrypoint.
        let mut pools = DisaggregatedPools::new(one_slot_gate(), one_slot_gate());
        let node = DecodeNodeId::new("decode-0");
        pools.relay_mut().grant_credits(&node, 4);
        let mut transport = InMemoryKvTransport::new();

        let outcome = pools.handoff(
            &mut transport,
            "req-1",
            &node,
            4,
            FabricRelation::SameDomain,
        );
        assert!(outcome.is_delivered());
        assert_eq!(transport.delivered_count(), 1);
        assert_eq!(
            pools.relay_mut().credits(&node),
            0,
            "credits debited by the handoff"
        );

        // A duplicate handoff of the same request key is refused (already delivered), never
        // double-moving blocks over the fabric.
        assert_eq!(
            pools.handoff(
                &mut transport,
                "req-1",
                &node,
                4,
                FabricRelation::SameDomain
            ),
            TransferOutcome::AlreadyDelivered
        );
        assert_eq!(transport.delivered_count(), 1, "no duplicate physical move");
    }
}
