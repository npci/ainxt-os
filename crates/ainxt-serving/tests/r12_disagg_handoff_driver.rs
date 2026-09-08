// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-12 Serving-Ops gap-6 (MEDIUM) — the §1 disaggregated prefill/decode handoff now has an
//! explicit physical-transport SEAM + a DRIVER sequencing a prefill-pool → decode-pool handoff through
//! it under credit-based flow control + the idempotency ledger.
//!
//! The audit found the two physical pools + the KV-block transport were unmodeled seams with no driver
//! composing them. This closes the orchestration ([`KvTransport`] seam + [`prefill_to_decode_handoff`]);
//! the live NVLink/RDMA fabric and the two physical GPU pools remain infra. The driver physically moves
//! blocks ONLY when credit-admitted + not already delivered, and a link drop refunds credits + keeps
//! the request retryable — no decode-pool OOM, no double-bill.
//!
//! Fail-before: `KvTransport`/`InMemoryKvTransport`/`prefill_to_decode_handoff` did not exist.
//! Pass-after: a same-domain handoff moves blocks zero-copy, a throttled handoff never touches the
//! fabric, and a link-dropped handoff refunds credits + is safely retried without a double-bill.

use ainxt_serving::idempotency::IdempotencyLedger;
use ainxt_serving::kv_relay::{
    prefill_to_decode_handoff, DecodeNodeId, FabricRelation, InMemoryKvTransport, KvRelay,
    TransferOutcome, Transport,
};

fn node(s: &str) -> DecodeNodeId {
    DecodeNodeId::new(s)
}

#[test]
fn r12_handoff_moves_blocks_only_when_credit_admitted() {
    let mut relay = KvRelay::new();
    let mut ledger = IdempotencyLedger::new();
    let mut fabric = InMemoryKvTransport::new();
    let d = node("decode-0");
    relay.grant_credits(&d, 4); // decode node can land 4 pages

    // A 6-page handoff exceeds the credit → HELD, and the physical fabric is NEVER touched (no OOM).
    assert_eq!(
        prefill_to_decode_handoff(
            &mut relay,
            &mut fabric,
            &mut ledger,
            "r1",
            &d,
            6,
            FabricRelation::SameDomain
        ),
        TransferOutcome::Throttled {
            requested: 6,
            available: 4
        }
    );
    assert_eq!(
        fabric.delivered_count(),
        0,
        "a throttled handoff never moves blocks over the fabric"
    );
    assert_eq!(relay.credits(&d), 4, "throttled handoff debits nothing");

    // A 4-page handoff fits → physically moved zero-copy (same fabric domain), credits debited.
    assert_eq!(
        prefill_to_decode_handoff(
            &mut relay,
            &mut fabric,
            &mut ledger,
            "r1",
            &d,
            4,
            FabricRelation::SameDomain
        ),
        TransferOutcome::Delivered {
            transport: Transport::GpuToGpu,
            pages: 4
        }
    );
    assert_eq!(
        fabric.delivered_count(),
        1,
        "admitted handoff moved one block set over the fabric"
    );
    assert_eq!(relay.credits(&d), 0);
}

#[test]
fn r12_handoff_link_drop_refunds_credits_and_retry_is_safe() {
    let mut relay = KvRelay::new();
    let mut ledger = IdempotencyLedger::new();
    // The physical fabric drops the FIRST send (a link/node drop mid-transfer).
    let mut fabric = InMemoryKvTransport::new().failing_next(1);
    let d = node("decode-0");
    relay.grant_credits(&d, 4);

    // First handoff attempt: the physical move fails → credits refunded, request retryable.
    let out = prefill_to_decode_handoff(
        &mut relay,
        &mut fabric,
        &mut ledger,
        "req",
        &d,
        4,
        FabricRelation::CrossDomain,
    );
    assert_eq!(
        out,
        TransferOutcome::Failed {
            transport: Transport::HostBuffer,
            retryable: true
        }
    );
    assert_eq!(
        relay.credits(&d),
        4,
        "a transient link drop must not permanently shrink decode capacity"
    );
    assert!(
        !ledger.is_committed("req"),
        "the request stays open so a retry is safe"
    );

    // Retry (fabric healthy now): delivered, and billed EXACTLY ONCE across the failed + retried attempt.
    assert!(prefill_to_decode_handoff(
        &mut relay,
        &mut fabric,
        &mut ledger,
        "req",
        &d,
        4,
        FabricRelation::CrossDomain
    )
    .is_delivered());
    assert_eq!(
        ledger.total_billed(),
        4,
        "billed once despite the earlier drop"
    );
    assert_eq!(
        fabric.delivered_count(),
        1,
        "only the successful retry moved blocks"
    );

    // A duplicate submission is refused without re-moving blocks (belt-and-suspenders).
    assert_eq!(
        prefill_to_decode_handoff(
            &mut relay,
            &mut fabric,
            &mut ledger,
            "req",
            &d,
            4,
            FabricRelation::CrossDomain
        ),
        TransferOutcome::AlreadyDelivered
    );
    assert_eq!(
        fabric.delivered_count(),
        1,
        "the duplicate never touched the fabric again"
    );
}
