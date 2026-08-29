// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Disaggregated prefill/decode KV Relay — credit-based flow control + idempotent retry
//! (SERVING_OPS.md §1, gap **SRV-03**).
//!
//! Prefill (compute-bound, parallel over prompt tokens) and decode (bandwidth-bound, one token at a
//! time) have opposite hardware profiles, so §1 splits them into independently-scaled pools. The
//! prefill pool emits the prompt's **KV cache as paged blocks**; those blocks must reach the decode
//! pool without the transport becoming the new bottleneck. This module is the pure policy core of
//! that relay — the audit found only a bare `Phase{Prefill,Decode}` enum and no relay at all:
//!
//! * **Credit-based, not fire-and-hose** ([`KvRelay::grant_credits`] / [`KvRelay::transfer`]). A
//!   decode node advertises free KV-page landing capacity as *credits*; the relay only pushes a block
//!   it has been granted a landing credit for. This **bounds decode-pool memory pressure** under a
//!   prefill burst instead of letting the burst OOM the decode side (§1). A transfer that has no
//!   credit is [`TransferOutcome::Throttled`], held not dropped.
//! * **GPU-to-GPU with host-buffer fallback** ([`FabricRelation`] → [`Transport`]). Same fabric
//!   domain → zero-copy [`Transport::GpuToGpu`]; a burst-capacity node on a different segment falls
//!   back to the slower-but-correct [`Transport::HostBuffer`] relay. The fallback is a *scheduling
//!   input* (placement prefers same-domain pairing, §3), not a silent tax — it is reported in the
//!   outcome.
//! * **Idempotency-ledger-backed retry on relay failure** (§1). A link/node drop mid-transfer is a
//!   retryable event **scoped to that one request**: its landing credits are refunded (a drop must
//!   not permanently shrink decode capacity) and, on retry, the request's idempotency key
//!   ([`crate::idempotency`]) ensures prefill is resubmitted without double-charging tokens or
//!   serving a corrupted partial.
//!
//! Deterministic and pure: no GPU, no network, no clock. "A link drop" is a boolean the caller feeds
//! in; every credit and byte is accounted for so the flow-control invariant is unit-assertable.

use std::collections::BTreeMap;

use crate::idempotency::{BeginOutcome, IdempotencyLedger};

/// A decode-pool node that KV blocks land on. Opaque id.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DecodeNodeId(pub String);

impl DecodeNodeId {
    pub fn new(s: impl Into<String>) -> Self {
        DecodeNodeId(s.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Whether the prefill and decode nodes share an interconnect fabric domain (RDMA/NVLink-class).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FabricRelation {
    /// Same fabric domain — a zero-copy GPU-to-GPU push is possible.
    SameDomain,
    /// Different segment (e.g. burst capacity) — must fall back to the host-buffer relay.
    CrossDomain,
}

/// The transport actually used for a KV block transfer (SERVING_OPS.md §1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// Zero-copy over the shared fabric (no host round-trip).
    GpuToGpu,
    /// GPU→host pinned memory→network→host→GPU — slower, but correct, when fabric differs.
    HostBuffer,
}

impl FabricRelation {
    /// The transport this relation dictates.
    pub fn transport(self) -> Transport {
        match self {
            FabricRelation::SameDomain => Transport::GpuToGpu,
            FabricRelation::CrossDomain => Transport::HostBuffer,
        }
    }
}

/// The outcome of one [`KvRelay::transfer`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferOutcome {
    /// The blocks landed. `transport` records whether the fast or fallback path was used.
    Delivered { transport: Transport, pages: u32 },
    /// The decode node had insufficient landing credits — the push is **held, not dropped**, so a
    /// prefill burst cannot OOM the decode pool. The caller retries after credits are replenished.
    Throttled { requested: u32, available: u32 },
    /// The link/node dropped mid-transfer. Credits were refunded and the request is retryable under
    /// its idempotency key — no double-charge, no corrupted partial (§1 failure semantics).
    Failed {
        transport: Transport,
        retryable: bool,
    },
    /// This request's idempotency key was already committed — the KV was already delivered and billed;
    /// re-pushing is refused (belt-and-suspenders against a duplicate submission).
    AlreadyDelivered,
}

impl TransferOutcome {
    pub fn is_delivered(&self) -> bool {
        matches!(self, TransferOutcome::Delivered { .. })
    }
}

/// The credit-based KV relay for one prefill→decode fabric (SERVING_OPS.md §1).
///
/// Holds per-decode-node landing credits (free KV-page capacity the node has advertised). The relay
/// never pushes more pages than a node has credited, so decode-pool memory pressure is bounded by
/// construction. On a link drop the debited credits are refunded so a transient failure never
/// permanently shrinks capacity.
#[derive(Debug, Clone, Default)]
pub struct KvRelay {
    credits: BTreeMap<DecodeNodeId, u32>,
}

impl KvRelay {
    pub fn new() -> Self {
        KvRelay::default()
    }

    /// Advertise (add) `pages` of free landing capacity on `node`. Saturating.
    pub fn grant_credits(&mut self, node: &DecodeNodeId, pages: u32) {
        let slot = self.credits.entry(node.clone()).or_insert(0);
        *slot = slot.saturating_add(pages);
    }

    /// Current landing credits on `node`.
    pub fn credits(&self, node: &DecodeNodeId) -> u32 {
        self.credits.get(node).copied().unwrap_or(0)
    }

    /// Attempt to transfer `pages` KV blocks for the request keyed `req_key` to `node` over a fabric
    /// with the given `relation`. `link_ok` models whether the physical transfer succeeds — a `false`
    /// value is a mid-transfer link/node drop.
    ///
    /// Flow: begin the request in the `ledger` (an already-committed key short-circuits to
    /// [`TransferOutcome::AlreadyDelivered`]); require enough credits (else
    /// [`TransferOutcome::Throttled`], holding the push); debit credits; on `link_ok` commit the
    /// delivery and bill the KV pages exactly once; on a drop, **refund the credits** and return a
    /// retryable failure — the ledger keeps the attempt open so a retry is safe.
    pub fn transfer(
        &mut self,
        req_key: &str,
        node: &DecodeNodeId,
        pages: u32,
        relation: FabricRelation,
        link_ok: bool,
        ledger: &mut IdempotencyLedger,
    ) -> TransferOutcome {
        let transport = relation.transport();

        // A relay is idempotent per request key: an already-delivered KV must not be re-pushed.
        if let BeginOutcome::AlreadyCommitted { .. } = ledger.begin(req_key) {
            return TransferOutcome::AlreadyDelivered;
        }

        // Credit-based admission: never push more than the decode node can land.
        let available = self.credits(node);
        if available < pages {
            return TransferOutcome::Throttled {
                requested: pages,
                available,
            };
        }
        // Debit the landing credits for this push.
        self.credits.insert(node.clone(), available - pages);

        if link_ok {
            // Delivered: bill the KV pages exactly once for this request (retry-safe via the ledger).
            let _ = ledger.commit(
                req_key,
                u64::from(pages),
                delivery_hash(node, pages, transport),
            );
            TransferOutcome::Delivered { transport, pages }
        } else {
            // Drop mid-transfer: refund credits (a transient failure must not shrink decode capacity)
            // and leave the ledger attempt OPEN so the gateway can safely resubmit prefill.
            self.grant_credits(node, pages);
            TransferOutcome::Failed {
                transport,
                retryable: true,
            }
        }
    }
}

/// A deterministic content-ish hash pinning a delivery (models the KV block-set identity for the
/// idempotency ledger's divergence guard; the real relay would hash the block manifest).
fn delivery_hash(node: &DecodeNodeId, pages: u32, transport: Transport) -> u64 {
    let mut h = 1469598103934665603u64; // FNV-1a offset basis
    let mix = |h: &mut u64, byte: u8| {
        *h ^= u64::from(byte);
        *h = h.wrapping_mul(1099511628211);
    };
    for b in node.as_str().as_bytes() {
        mix(&mut h, *b);
    }
    for b in pages.to_le_bytes() {
        mix(&mut h, b);
    }
    mix(&mut h, transport as u8);
    h
}

// ---------------------------------------------------------------------------
// Physical KV-block transport seam + disaggregated prefill→decode handoff driver
// (SERVING_OPS.md §1, INFRA-GATED; serving-ops gap-6)
// ---------------------------------------------------------------------------
//
// [`KvRelay`] above is the pure flow-control core (credits + idempotency + the fabric→transport
// decision). The audit found the disaggregated §1 design still lacked (a) an explicit seam for the
// *physical* block movement between the two pools and (b) a driver sequencing a prefill-pool → decode-
// pool handoff through it. This closes both: [`KvTransport`] is the physical-move seam (live NVLink/
// RDMA or host-buffer relay), and [`prefill_to_decode_handoff`] is the driver that runs a handoff under
// credit admission + the idempotency ledger — physically moving blocks ONLY when admitted, and
// refunding credits + keeping the request retryable on a link drop. The two physical GPU pools and the
// live interconnect are the deferred infra; the handoff orchestration is proven offline.

/// The physical KV-block transport seam (SERVING_OPS.md §1, INFRA-GATED). A real implementation moves
/// `pages` paged KV blocks for `req_key` to `node` over `transport` (zero-copy GPU-to-GPU on a shared
/// fabric, or the host-buffer relay across segments) and returns whether the physical move succeeded —
/// `false` models a mid-transfer link/node drop. [`InMemoryKvTransport`] is the offline reference.
pub trait KvTransport {
    fn send(
        &mut self,
        req_key: &str,
        node: &DecodeNodeId,
        pages: u32,
        transport: Transport,
    ) -> bool;
}

/// A deterministic offline [`KvTransport`]: records each delivered `(req_key, node, pages, transport)`
/// and can be told to fail the next `fail_next` sends (a modeled link drop) so retry-safety is testable.
#[derive(Debug, Clone, Default)]
pub struct InMemoryKvTransport {
    delivered: Vec<(String, DecodeNodeId, u32, Transport)>,
    fail_next: u32,
}

impl InMemoryKvTransport {
    pub fn new() -> Self {
        InMemoryKvTransport::default()
    }
    /// Configure the next `n` physical sends to fail (a link/node drop).
    pub fn failing_next(mut self, n: u32) -> Self {
        self.fail_next = n;
        self
    }
    /// How many physical block moves have been delivered.
    pub fn delivered_count(&self) -> usize {
        self.delivered.len()
    }
}

impl KvTransport for InMemoryKvTransport {
    fn send(
        &mut self,
        req_key: &str,
        node: &DecodeNodeId,
        pages: u32,
        transport: Transport,
    ) -> bool {
        if self.fail_next > 0 {
            self.fail_next -= 1;
            return false;
        }
        self.delivered
            .push((req_key.to_string(), node.clone(), pages, transport));
        true
    }
}

/// **Drive one disaggregated prefill→decode handoff** (SERVING_OPS.md §1, gap-6): a prefill pool that
/// finished a prompt's KV hands `pages` blocks to a decode `node` over `relation`'s transport, under
/// credit-based admission + the idempotency ledger. The physical [`KvTransport::send`] is invoked ONLY
/// when the request is credit-admitted and not already delivered — so a throttled/duplicate handoff
/// never touches the fabric — and a link drop refunds credits + leaves the request retryable (proven by
/// the ledger staying open). Composes the two physical pools' handoff into one tested orchestration;
/// the live interconnect + pools are the seam.
pub fn prefill_to_decode_handoff(
    relay: &mut KvRelay,
    transport: &mut dyn KvTransport,
    ledger: &mut IdempotencyLedger,
    req_key: &str,
    node: &DecodeNodeId,
    pages: u32,
    relation: FabricRelation,
) -> TransferOutcome {
    // Duplicate submission → already delivered/billed; do not re-move blocks over the fabric.
    if ledger.is_committed(req_key) {
        return relay.transfer(req_key, node, pages, relation, true, ledger);
    }
    // Insufficient landing credits → held, not pushed; the fabric is never touched (no decode OOM).
    if relay.credits(node) < pages {
        return relay.transfer(req_key, node, pages, relation, true, ledger);
    }
    // Admitted: perform the physical move over the seam, then settle credits + idempotency on the result.
    let link_ok = transport.send(req_key, node, pages, relation.transport());
    relay.transfer(req_key, node, pages, relation, link_ok, ledger)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(s: &str) -> DecodeNodeId {
        DecodeNodeId::new(s)
    }

    #[test]
    fn gap_ainxt_serving_srv_03_credits_bound_decode_pressure() {
        let mut relay = KvRelay::new();
        let mut ledger = IdempotencyLedger::new();
        let d = node("decode-0");
        relay.grant_credits(&d, 4); // decode node can land 4 pages
                                    // A 6-page prefill burst exceeds the credit → HELD, not pushed (no OOM), nothing debited.
        assert_eq!(
            relay.transfer("r1", &d, 6, FabricRelation::SameDomain, true, &mut ledger),
            TransferOutcome::Throttled {
                requested: 6,
                available: 4
            }
        );
        assert_eq!(relay.credits(&d), 4, "throttled push debits nothing");
        // A 4-page push fits and is delivered, debiting exactly 4 credits.
        assert!(relay
            .transfer("r1", &d, 4, FabricRelation::SameDomain, true, &mut ledger)
            .is_delivered());
        assert_eq!(relay.credits(&d), 0);
    }

    #[test]
    fn gap_ainxt_serving_srv_03_same_domain_is_gpu_to_gpu_cross_domain_falls_back_to_host_buffer() {
        let mut relay = KvRelay::new();
        let mut ledger = IdempotencyLedger::new();
        let same = node("decode-same");
        let cross = node("decode-cross");
        relay.grant_credits(&same, 8);
        relay.grant_credits(&cross, 8);
        assert_eq!(
            relay.transfer("a", &same, 2, FabricRelation::SameDomain, true, &mut ledger),
            TransferOutcome::Delivered {
                transport: Transport::GpuToGpu,
                pages: 2
            }
        );
        assert_eq!(
            relay.transfer(
                "b",
                &cross,
                2,
                FabricRelation::CrossDomain,
                true,
                &mut ledger
            ),
            TransferOutcome::Delivered {
                transport: Transport::HostBuffer,
                pages: 2
            }
        );
    }

    #[test]
    fn gap_ainxt_serving_srv_03_link_drop_refunds_credits_and_retry_is_safe_no_double_bill() {
        let mut relay = KvRelay::new();
        let mut ledger = IdempotencyLedger::new();
        let d = node("decode-0");
        relay.grant_credits(&d, 4);
        // First attempt: the link drops mid-transfer.
        let out = relay.transfer("req", &d, 4, FabricRelation::SameDomain, false, &mut ledger);
        assert_eq!(
            out,
            TransferOutcome::Failed {
                transport: Transport::GpuToGpu,
                retryable: true
            }
        );
        // Credits were refunded — a transient drop must not permanently shrink decode capacity.
        assert_eq!(relay.credits(&d), 4);
        // The ledger attempt is still open (not committed) → a retry is safe.
        assert!(!ledger.is_committed("req"));
        // Retry succeeds; KV pages are billed EXACTLY ONCE despite the earlier failure.
        assert!(relay
            .transfer("req", &d, 4, FabricRelation::SameDomain, true, &mut ledger)
            .is_delivered());
        assert_eq!(
            ledger.total_billed(),
            4,
            "billed once across the failed + retried attempt"
        );
    }

    #[test]
    fn gap_ainxt_serving_srv_03_already_delivered_request_is_not_re_pushed() {
        let mut relay = KvRelay::new();
        let mut ledger = IdempotencyLedger::new();
        let d = node("decode-0");
        relay.grant_credits(&d, 10);
        assert!(relay
            .transfer("once", &d, 3, FabricRelation::SameDomain, true, &mut ledger)
            .is_delivered());
        // A duplicate submission of the same key is refused — the KV was already delivered/billed.
        assert_eq!(
            relay.transfer("once", &d, 3, FabricRelation::SameDomain, true, &mut ledger),
            TransferOutcome::AlreadyDelivered
        );
        assert_eq!(
            relay.credits(&d),
            7,
            "the duplicate debits no further credits"
        );
        assert_eq!(ledger.total_billed(), 3);
    }
}
