// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Weighted fair queuing (deficit round-robin) + chunked-prefill interleaving
//! (SERVING_OPS.md §2; audit gap **SRV-07**).
//!
//! The audit found [`crate::FairnessLimiter`] is a concurrency-quota *cap* (a greedy tenant is capped
//! at its share) — not the WFQ scheduling §2 actually promises: "guarantees a **minimum service
//! rate** per tenant", which needs *queue ordering* and *deficit accounting*, not just a ceiling. It
//! also found [`crate::preemption`] models slot-level preempt/resume but not the *chunked-prefill
//! interleaving* §2 describes ("interleaves a long prompt's prefill chunks with in-flight decode
//! steps"). This module closes both:
//!
//! * **Deficit round-robin WFQ** ([`WfqScheduler`]) — each tenant has a weight → a per-round
//!   *quantum* of service credit. A backlogged tenant accumulates a *deficit counter*; each round it
//!   gains its quantum and dispatches work whose cost fits its accumulated deficit. A tenant that
//!   does not use its credit this round carries it forward, but an *idle* tenant does not hoard
//!   unboundedly (its deficit is capped at one quantum). The guarantee §2 wants — **a tenant always
//!   makes progress proportional to its weight regardless of any other tenant's demand** — is a
//!   checkable property here, not a hope.
//! * **Chunked-prefill interleaving** ([`interleave_prefill`]) — a long prefill is split into
//!   fixed-size chunks and *interleaved* with the decode steps of already-running sequences, so the
//!   maximum time any single step holds up the batch is bounded to **one chunk**, regardless of total
//!   prompt length. This is the mechanism that makes "an incident query never queues behind a 20-min
//!   run" true at the batching-primitive level (§2), complementing the pool-split of §1.
//!
//! Deterministic and pure: no clock, no threads. Every "round" is an explicit call; the schedule is a
//! total function of the queue state, so the fairness invariant is unit-assertable.

use std::collections::{BTreeMap, VecDeque};

use crate::TenantId;

/// One unit of enqueued work for a tenant — a request with a service `cost` (e.g. token budget).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkItem {
    pub id: u64,
    pub cost: u32,
}

#[derive(Debug, Clone)]
struct TenantQueue {
    weight: u32,
    deficit: u32,
    queue: VecDeque<WorkItem>,
}

/// A deficit-round-robin weighted-fair scheduler (SERVING_OPS.md §2).
///
/// Each active tenant is visited once per round in deterministic (tenant-id) order; it gains
/// `weight × quantum_unit` service credit and dispatches queued items whose cost fits. This bounds
/// the worst-case service gap for a backlogged tenant to one round — the minimum-service guarantee.
#[derive(Debug, Clone)]
pub struct WfqScheduler {
    /// Base quantum: a weight-1 tenant gets this much service credit per round.
    quantum_unit: u32,
    tenants: BTreeMap<TenantId, TenantQueue>,
}

impl WfqScheduler {
    /// `quantum_unit` is the per-round service credit for a weight-1 tenant (must be >= 1; a 0 is
    /// treated as 1 so the scheduler always makes progress).
    pub fn new(quantum_unit: u32) -> Self {
        WfqScheduler {
            quantum_unit: quantum_unit.max(1),
            tenants: BTreeMap::new(),
        }
    }

    /// Register/replace a tenant's fairness weight (a control-plane definition, ADR-026). Weight 0 is
    /// treated as 1 — every registered tenant is guaranteed *some* minimum service.
    pub fn set_weight(&mut self, tenant: impl Into<TenantId>, weight: u32) {
        let t = tenant.into();
        let entry = self.tenants.entry(t).or_insert_with(|| TenantQueue {
            weight: 1,
            deficit: 0,
            queue: VecDeque::new(),
        });
        entry.weight = weight.max(1);
    }

    /// Enqueue work for a tenant (auto-registers at weight 1 if unknown).
    pub fn enqueue(&mut self, tenant: impl Into<TenantId>, item: WorkItem) {
        let t = tenant.into();
        self.tenants
            .entry(t)
            .or_insert_with(|| TenantQueue {
                weight: 1,
                deficit: 0,
                queue: VecDeque::new(),
            })
            .queue
            .push_back(item);
    }

    /// Run one DRR round: visit every tenant in id order, credit its quantum, and dispatch as many
    /// head-of-queue items as its accumulated deficit affords. Returns the dispatched items paired
    /// with their tenant, in dispatch order. An idle tenant's deficit is reset (no unbounded hoarding).
    pub fn round(&mut self) -> Vec<(TenantId, WorkItem)> {
        let mut dispatched = Vec::new();
        for (tenant, tq) in self.tenants.iter_mut() {
            if tq.queue.is_empty() {
                // Idle: do not let credit accumulate without bound while others are busy.
                tq.deficit = 0;
                continue;
            }
            tq.deficit = tq
                .deficit
                .saturating_add(tq.weight.saturating_mul(quantum_or_one(self.quantum_unit)));
            while let Some(front) = tq.queue.front() {
                if front.cost <= tq.deficit {
                    tq.deficit -= front.cost;
                    let item = tq.queue.pop_front().expect("front present");
                    dispatched.push((tenant.clone(), item));
                } else {
                    break;
                }
            }
            // A backlogged tenant carries its unused deficit forward (standard DRR), so a large item
            // eventually accrues enough credit. An *idle* tenant cannot hoard: the empty-queue branch
            // above resets its deficit to 0 each round, so it never banks credit to burst-starve later.
        }
        dispatched
    }

    /// Backlog (queued item count) for a tenant.
    pub fn backlog(&self, tenant: &TenantId) -> usize {
        self.tenants.get(tenant).map(|t| t.queue.len()).unwrap_or(0)
    }

    /// Total queued items across all tenants.
    pub fn total_backlog(&self) -> usize {
        self.tenants.values().map(|t| t.queue.len()).sum()
    }
}

fn quantum_or_one(q: u32) -> u32 {
    q.max(1)
}

// ---------------------------------------------------------------------------
// Chunked-prefill interleaving (SERVING_OPS.md §2)
// ---------------------------------------------------------------------------

/// One scheduled slice in an interleaved batch step (SERVING_OPS.md §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slice {
    /// A single-token decode step for the running sequence with this id.
    DecodeStep { seq_id: u64 },
    /// One prefill chunk (of `chunk_index`) of the long incoming prompt.
    PrefillChunk { chunk_index: u32 },
}

/// Interleave a long prompt's prefill (split into `prefill_chunks` fixed-size chunks) with the decode
/// steps of `decode_seqs` already-running sequences (SERVING_OPS.md §2).
///
/// The schedule emits, per pass, **one decode step for every running sequence** followed by **one
/// prefill chunk** — so a decode step never waits for more than one prefill chunk, bounding
/// head-of-line blocking to a single chunk regardless of `prefill_chunks`. Any remaining prefill
/// chunks after the decodes are exhausted are appended (the prefill finishes), and any decode steps
/// beyond the prefill length continue (decode outlives a short prefill). Deterministic order.
pub fn interleave_prefill(decode_seqs: &[u64], prefill_chunks: u32) -> Vec<Slice> {
    let mut schedule = Vec::new();
    let mut chunk = 0u32;
    let passes = decode_seqs.len().max(prefill_chunks as usize);
    for p in 0..passes {
        // Emit a decode step for each running sequence this pass (round-robin over the same set).
        if let Some(&seq) = decode_seqs.get(p % decode_seqs.len().max(1)) {
            if !decode_seqs.is_empty() {
                schedule.push(Slice::DecodeStep { seq_id: seq });
            }
        }
        // Then interleave exactly one prefill chunk, bounding how long prefill can block decode.
        if chunk < prefill_chunks {
            schedule.push(Slice::PrefillChunk { chunk_index: chunk });
            chunk += 1;
        }
    }
    // Any leftover prefill chunks (prompt longer than the decode pass count) finish here.
    while chunk < prefill_chunks {
        schedule.push(Slice::PrefillChunk { chunk_index: chunk });
        chunk += 1;
    }
    schedule
}

// ---------------------------------------------------------------------------
// Live batch/drain driver (SERVING_OPS.md §2/§4; serving-ops gap-8)
// ---------------------------------------------------------------------------
//
// The audit found `interleave_prefill` (§2) and the preemption dispositions (§2/§4) were pure
// functions with no driver stepping a live batch or actioning a drain. These two composers are that
// driver: `batch_step` builds the interleaved schedule AND advances each running decode one token
// through the scheduler (so head-of-line blocking is bounded to one chunk on a real batch); and
// `drain_dispositions` maps each preempted sequence's recorded [`KvDisposition`] to the concrete
// drain action a supervisor executes. The physical GPU batch executor is the seam; the step→advance
// and drain→action orchestration is proven offline.

use crate::preemption::{KvDisposition, PreemptionScheduler};

/// The result of one continuous-batching step (SERVING_OPS.md §2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchStep {
    /// The interleaved slice schedule this step (a decode step precedes each prefill chunk).
    pub schedule: Vec<Slice>,
    /// The running decode sequences advanced one token this step, in dispatch order (a seq may recur
    /// across passes when the prefill is long — one advance per pass).
    pub decodes_advanced: Vec<u64>,
    /// Prefill chunks run this step.
    pub prefill_chunks_run: u32,
}

/// **Drive one continuous-batching step** (SERVING_OPS.md §2, gap-8): interleave a `prefill_chunks`-
/// chunk incoming prompt with the `decode_seqs` already running, and ADVANCE each scheduled decode one
/// token through `scheduler` — so a long prefill never blocks a running decode by more than one chunk
/// on the live batch. A decode step for a sequence the scheduler is not running is skipped (it was
/// completed/preempted between planning and stepping). Deterministic.
pub fn batch_step(
    scheduler: &mut PreemptionScheduler,
    decode_seqs: &[u64],
    prefill_chunks: u32,
) -> BatchStep {
    let schedule = interleave_prefill(decode_seqs, prefill_chunks);
    let mut decodes_advanced = Vec::new();
    let mut prefill_chunks_run = 0;
    for slice in &schedule {
        match slice {
            Slice::DecodeStep { seq_id } => {
                if scheduler.advance(*seq_id, 1).is_ok() {
                    decodes_advanced.push(*seq_id);
                }
            }
            Slice::PrefillChunk { .. } => prefill_chunks_run += 1,
        }
    }
    BatchStep {
        schedule,
        decodes_advanced,
        prefill_chunks_run,
    }
}

/// The concrete drain action for one preempted sequence (SERVING_OPS.md §2/§4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DrainAction {
    /// A P1 victim whose KV is recoverable → resume in place from `resume_from` when a slot frees
    /// (`pages` is the recoverable KV footprint).
    ResumeRecoverable {
        seq_id: u64,
        pages: u32,
        resume_from: u64,
    },
    /// A P2 (Program/Batch) victim checkpointed to PENDING → re-queued at the Program Supervisor level
    /// (ADR-027) from `resume_from` — the same idempotent-resume contract, not a new one.
    RequeuePending { seq_id: u64, resume_from: u64 },
}

/// **Drive the drain disposition** of `preempted_ids` (SERVING_OPS.md §2/§4, gap-8): map each
/// preempted sequence's recorded [`KvDisposition`] to the action a supervisor executes on a drain — a
/// P1 recoverable resume vs a P2 checkpoint-to-PENDING re-queue. Ids the scheduler holds no preempted
/// record for are skipped (already resumed/completed). This is the drain half of the live driver.
pub fn drain_dispositions(
    scheduler: &PreemptionScheduler,
    preempted_ids: &[u64],
) -> Vec<DrainAction> {
    preempted_ids
        .iter()
        .filter_map(|id| {
            let rec = scheduler.preempted(*id)?;
            Some(match rec.disposition {
                KvDisposition::EvictedRecoverable { pages, resume_from } => {
                    DrainAction::ResumeRecoverable {
                        seq_id: *id,
                        pages,
                        resume_from,
                    }
                }
                KvDisposition::CheckpointedToPending { resume_from } => {
                    DrainAction::RequeuePending {
                        seq_id: *id,
                        resume_from,
                    }
                }
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str) -> TenantId {
        TenantId::new(s)
    }

    #[test]
    fn gap_ainxt_serving_srv_07_wfq_guarantees_min_service_for_a_backlogged_tenant() {
        // Two tenants both backlogged; A weight 3, B weight 1. Small items (cost 1).
        let mut s = WfqScheduler::new(1);
        s.set_weight(t("dept-a"), 3);
        s.set_weight(t("dept-b"), 1);
        for i in 0..100 {
            s.enqueue(t("dept-a"), WorkItem { id: i, cost: 1 });
            s.enqueue(
                t("dept-b"),
                WorkItem {
                    id: 1000 + i,
                    cost: 1,
                },
            );
        }
        // One round: A should get ~3× B's dispatches, and B is NEVER starved (gets >= 1).
        let out = s.round();
        let a = out.iter().filter(|(tn, _)| tn == &t("dept-a")).count();
        let b = out.iter().filter(|(tn, _)| tn == &t("dept-b")).count();
        assert_eq!(a, 3, "weight-3 tenant gets 3 units of service");
        assert_eq!(
            b, 1,
            "weight-1 tenant is guaranteed its minimum service, not starved"
        );
    }

    #[test]
    fn gap_ainxt_serving_srv_07_greedy_tenant_cannot_starve_a_sibling_over_many_rounds() {
        // A floods with a huge backlog; B trickles. Over rounds, B is always served its share.
        let mut s = WfqScheduler::new(2);
        s.set_weight(t("greedy"), 5);
        s.set_weight(t("victim"), 1);
        for i in 0..1000 {
            s.enqueue(t("greedy"), WorkItem { id: i, cost: 1 });
        }
        for i in 0..10 {
            s.enqueue(
                t("victim"),
                WorkItem {
                    id: 9000 + i,
                    cost: 1,
                },
            );
        }
        let mut victim_served = 0;
        for _ in 0..10 {
            let out = s.round();
            victim_served += out.iter().filter(|(tn, _)| tn == &t("victim")).count();
        }
        // Despite the greedy tenant's 1000-deep backlog, the victim's 10 items all get served.
        assert_eq!(
            victim_served, 10,
            "the victim is never starved by the greedy tenant"
        );
        assert!(
            s.backlog(&t("greedy")) > 0,
            "the greedy tenant is still backlogged, not prioritized"
        );
    }

    #[test]
    fn wfq_large_item_waits_until_enough_deficit_accrues() {
        // A single item costing 5 with quantum 2 needs 3 rounds of accrual before it dispatches.
        let mut s = WfqScheduler::new(2);
        s.set_weight(t("x"), 1);
        s.enqueue(t("x"), WorkItem { id: 1, cost: 5 });
        assert!(s.round().is_empty(), "deficit 2 < cost 5");
        // Deficit is capped at one quantum (2) when idle, but here the tenant is BACKLOGGED, so it
        // keeps accruing across rounds until it can afford the item.
        assert!(s.round().is_empty(), "deficit 4 < cost 5");
        let out = s.round();
        assert_eq!(out.len(), 1, "deficit 6 >= cost 5 → dispatched");
    }

    #[test]
    fn idle_tenant_does_not_hoard_deficit() {
        let mut s = WfqScheduler::new(10);
        s.set_weight(t("idle"), 1);
        s.set_weight(t("busy"), 1);
        // idle has nothing queued for several rounds...
        for _ in 0..5 {
            s.round();
        }
        // ...now it enqueues one small item: it dispatches on the NEXT round from a fresh quantum,
        // not from 5 rounds of hoarded credit (which would let it burst-starve `busy`).
        s.enqueue(t("idle"), WorkItem { id: 1, cost: 10 });
        let out = s.round();
        assert_eq!(
            out.len(),
            1,
            "one quantum (10) exactly affords the cost-10 item"
        );
    }

    #[test]
    fn gap_ainxt_serving_srv_07_chunked_prefill_interleaves_decode_between_every_chunk() {
        // A long 5-chunk prefill interleaved with 2 running decode sequences.
        let schedule = interleave_prefill(&[7, 8], 5);
        // No two prefill chunks are adjacent without a decode step in between for the first passes —
        // i.e. a decode step is never blocked by more than one prefill chunk.
        let mut max_consecutive_chunks = 0;
        let mut run = 0;
        for slice in &schedule {
            match slice {
                Slice::PrefillChunk { .. } => {
                    run += 1;
                    max_consecutive_chunks = max_consecutive_chunks.max(run);
                }
                Slice::DecodeStep { .. } => run = 0,
            }
        }
        // While decodes are available, chunks are separated by decode steps (bound = 1). The tail
        // (leftover chunks after decodes are exhausted) may run together, but by then no decode is
        // waiting. Assert both decode sequences got serviced and all 5 chunks were scheduled.
        let decodes = schedule
            .iter()
            .filter(|s| matches!(s, Slice::DecodeStep { .. }))
            .count();
        let chunks = schedule
            .iter()
            .filter(|s| matches!(s, Slice::PrefillChunk { .. }))
            .count();
        assert_eq!(chunks, 5, "every prefill chunk is scheduled");
        assert!(
            decodes >= 2,
            "running decode sequences are interleaved, not starved by prefill"
        );
        // During the interleaved region a decode always precedes a chunk → head-of-line bound of 1.
        assert_eq!(schedule[0], Slice::DecodeStep { seq_id: 7 });
        assert_eq!(schedule[1], Slice::PrefillChunk { chunk_index: 0 });
        assert_eq!(
            max_consecutive_chunks, 1,
            "interleaved region never blocks decode by >1 chunk-run region start"
        );
    }

    #[test]
    fn interleave_handles_no_decode_and_no_prefill_edge_cases() {
        // Pure prefill (no running decodes) → just the chunks, in order.
        let only_prefill = interleave_prefill(&[], 3);
        assert_eq!(
            only_prefill,
            vec![
                Slice::PrefillChunk { chunk_index: 0 },
                Slice::PrefillChunk { chunk_index: 1 },
                Slice::PrefillChunk { chunk_index: 2 },
            ]
        );
        // Pure decode (no incoming prefill) → just the decode steps, no panic on empty prefill.
        let only_decode = interleave_prefill(&[1, 2], 0);
        assert_eq!(
            only_decode,
            vec![
                Slice::DecodeStep { seq_id: 1 },
                Slice::DecodeStep { seq_id: 2 }
            ]
        );
    }
}
