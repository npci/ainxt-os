// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! The SLO-aware QoS **main admission path** (SERVING_OPS.md §2 — the core brief).
//!
//! The audit found the §2 mechanisms — per-tenant [`FairnessLimiter`], the chunk/step-granular
//! [`PreemptionScheduler`], and the bounded-queue backpressure of [`AdmissionController`] — each
//! implemented and tested, but the *main request path* (the daemon's chat/agent submit) carried
//! **no priority class and never invoked the scheduler**: an incident P0 could queue behind a
//! 20-minute P2 program run because admission was priority-blind. [`crate::gate::ServingGate`] composes
//! fairness + preemption too, but only *after* node selection (§7, the node-level gate); it has no
//! notion of a bounded wait queue and is not the pre-node admission decision the request path makes
//! first.
//!
//! [`SloAdmissionController`] is that missing pre-node, priority-aware main-path decision. Given an
//! arriving [`QosRequest`] carrying its [`PriorityClass`] and tenant it decides, deterministically:
//!
//! 1. **Per-tenant fairness** — the tenant must be within its WFQ quota ([`FairnessLimiter`]) or it
//!    is [`SloDecision::RejectedOverQuota`] (a sibling department's reserved share is never eaten).
//! 2. **QoS admission with chunk/step preemption** — the [`PreemptionScheduler`] admits into a free
//!    slot, or **preempts a strictly-lower-priority incumbent at its next chunk/step boundary** so a
//!    P0 never waits for a long P2/P1 generation to finish (committed work is preserved per
//!    [`KvDisposition`]).
//! 3. **Bounded-queue backpressure** — when the pool is full and nothing lower is preemptible the
//!    arrival waits in a **bounded** queue ([`SloDecision::Enqueued`]); once that ceiling is hit the
//!    request is shed with an honest [`ShedReason`] rather than growing an unbounded queue.
//!
//! Pure and deterministic: no clock, no async, no GPU. The physical model stream, the node choice,
//! and the async wait/wakeups are seams owned elsewhere (the node-level [`crate::gate::ServingGate`] runs
//! *after* this decision admits a turn). The queue here is a **counted ceiling**, not a container:
//! this crate owns the *policy* (may this request run now, preempt, wait, or shed) — the request
//! objects and the actual dequeue live in the caller, which re-drives [`SloAdmissionController::admit`]
//! for a request this controller reports as promotable on [`SloAdmissionController::complete`].

use crate::preemption::{
    AdmitOutcome, KvDisposition, Phase, PreemptionScheduler, SchedError, SeqSpec,
};
use crate::{FairnessDecision, FairnessLimiter, PriorityClass, ShedReason, TenantId};

// ---------------------------------------------------------------------------
// The SLO-aware QoS admission core as reusable free functions (SERVING_OPS.md §2).
//
// The exact fairness → preemptive-QoS → bounded-queue policy, extracted so it has **one**
// implementation shared by every composition point: the standalone [`SloAdmissionController`]
// (the §2 pre-node primitive) AND [`crate::gate::ServingGate::pre_serve`] (the same policy over
// the gate's own pool state, so the main chat path and the node-level `model.infer` capability
// admit against ONE scheduler/fairness view rather than two divergent copies). No duplicated
// admission logic can drift between the two callers.
// ---------------------------------------------------------------------------

/// Run one SLO-aware QoS admission against the supplied pool state (SERVING_OPS.md §2): per-tenant
/// fairness, then chunk/step-granular preemption, then bounded-queue backpressure — in that order.
///
/// The three pieces of pool state are passed by mutable reference so a caller that already owns a
/// [`FairnessLimiter`] + [`PreemptionScheduler`] for other reasons (the node-level
/// [`crate::gate::ServingGate`]) reuses them directly, keeping a single source of truth for pool
/// occupancy. `queued`/`max_queue_depth` are the caller's bounded wait-queue counter and ceiling.
pub fn qos_admit(
    fairness: &mut FairnessLimiter,
    scheduler: &mut PreemptionScheduler,
    queued: &mut u32,
    max_queue_depth: u32,
    req: &QosRequest,
) -> SloDecision {
    // Step 1: per-tenant fairness. Over-quota is refused with its honest reason and takes no slot;
    // a greedy tenant never consumes a sibling's reserved share.
    match fairness.try_admit(&req.tenant) {
        FairnessDecision::Admit => {}
        FairnessDecision::RejectOverQuota { quota } => {
            return SloDecision::RejectedOverQuota { quota }
        }
        FairnessDecision::RejectAtCapacity => {
            // Global fairness capacity exhausted (only reachable with oversubscribed quotas) —
            // treat as backpressure, never an unbounded wait.
            return SloDecision::Shed(ShedReason::QueueFull { max_queue_depth });
        }
    }

    // Step 2: QoS admission with chunk/step-granular preemption.
    let spec = SeqSpec {
        id: req.seq_id,
        priority: req.priority,
        tenant: req.tenant.clone(),
        phase: Phase::Prefill,
        total_units: req.total_units,
        kv_pages: req.kv_pages,
        run_id: req.run_id.clone(),
    };
    match scheduler.admit(spec) {
        Ok(AdmitOutcome::Started) => SloDecision::Admitted { preempted: None },
        Ok(AdmitOutcome::Preempted {
            victim,
            victim_priority,
            disposition,
        }) => {
            // A slot was reused by preemption — net running count unchanged, fairness slot kept.
            SloDecision::Admitted {
                preempted: Some(QosPreemption {
                    victim,
                    victim_priority,
                    disposition,
                }),
            }
        }
        Ok(AdmitOutcome::Rejected) => {
            // Cannot run now and nothing lower to preempt (equal/higher incumbents fill the pool).
            // Release the fairness slot — the request is not running — and try the bounded queue.
            fairness.release(&req.tenant);
            if *queued < max_queue_depth {
                *queued += 1;
                SloDecision::Enqueued { depth: *queued }
            } else {
                SloDecision::Shed(ShedReason::QueueFull { max_queue_depth })
            }
        }
        Err(_) => {
            // Duplicate seq_id (an upstream accounting bug): undo the fairness slot, refuse.
            fairness.release(&req.tenant);
            SloDecision::Shed(ShedReason::QueueFull { max_queue_depth })
        }
    }
}

/// Complete an admitted generation against the supplied pool state: free its scheduler slot and
/// fairness quota, and report whether a queued request may now be promoted. Mirrors [`qos_admit`]'s
/// state so the two never drift.
pub fn qos_complete(
    fairness: &mut FairnessLimiter,
    scheduler: &mut PreemptionScheduler,
    queued: &mut u32,
    req: &QosRequest,
) -> Result<CompleteOutcome, SchedError> {
    scheduler.complete(req.seq_id)?;
    fairness.release(&req.tenant);
    let dequeue_head = *queued > 0;
    if dequeue_head {
        *queued -= 1;
    }
    Ok(CompleteOutcome {
        slot_freed: true,
        dequeue_head,
    })
}

/// One arrival on the SLO-aware main admission path (SERVING_OPS.md §2). Unlike
/// [`crate::gate::InferRequest`] this pre-node decision needs no `model_id`/`data_class`/candidate node —
/// only what §2 admission turns on: the priority class, the fairness tenant, and the generation's
/// chunk/step + KV accounting that drives preemption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QosRequest {
    /// Unique sequence id for the preemption scheduler (caller-assigned, e.g. a request counter).
    pub seq_id: u64,
    /// The SLO priority class carried on the request — the field the audit found missing on the
    /// live path (`chat_handler` submitted with none).
    pub priority: PriorityClass,
    /// The fairness tenant (the JWT `department` claim, §2).
    pub tenant: TenantId,
    /// Total chunks/steps this generation will take (drives preemption progress accounting).
    pub total_units: u64,
    /// KV pages this sequence holds (for the preemption evicted-recoverable disposition).
    pub kv_pages: u32,
    /// GAP-FIX identity-payments (gap6 audit item 2) — the identity-plane `run_id` this arrival
    /// serves, when the caller has one (see [`crate::preemption::SeqSpec::run_id`]'s doc for the
    /// full ownership chain: for a served `/v1/chat` turn this is `req.session`, the SAME string
    /// `chat_identity.rs` mints an `AgentWorkloadCredential` under). `None` (the default via
    /// [`QosRequest::new`]) is the pre-existing, unchanged shape.
    pub run_id: Option<String>,
}

impl QosRequest {
    pub fn new(seq_id: u64, priority: PriorityClass, tenant: impl Into<TenantId>) -> Self {
        QosRequest {
            seq_id,
            priority,
            tenant: tenant.into(),
            total_units: 1,
            kv_pages: 0,
            run_id: None,
        }
    }

    /// Set the chunk/step total and KV-page count (preemption accounting).
    pub fn with_work(mut self, total_units: u64, kv_pages: u32) -> Self {
        self.total_units = total_units;
        self.kv_pages = kv_pages;
        self
    }

    /// GAP-FIX identity-payments (gap6 audit item 2) — correlate this arrival with an identity-plane
    /// `run_id` so a kill-switch's [`ainxt_identity::authority::PreemptDirective`] (keyed on the SAME
    /// `run_id`) can find and force-preempt it in the real scheduler (see
    /// [`crate::preemption::PreemptionScheduler::force_preempt_by_run_id`]).
    pub fn with_run_id(mut self, run_id: impl Into<String>) -> Self {
        self.run_id = Some(run_id.into());
        self
    }
}

/// Details of a preemption performed to admit a higher-priority request on the main path — the same
/// shape as the node-level [`crate::gate::Preemption`], carried up to the main-path caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QosPreemption {
    pub victim: u64,
    pub victim_priority: PriorityClass,
    pub disposition: KvDisposition,
}

/// The verdict of one [`SloAdmissionController::admit`] (SERVING_OPS.md §2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SloDecision {
    /// Admitted into the pool. `preempted` names a strictly-lower-priority victim if this arrival
    /// displaced one (its committed work is preserved per [`KvDisposition`]).
    Admitted { preempted: Option<QosPreemption> },
    /// The pool is full and nothing lower was preemptible, but the bounded queue had room — the
    /// request waits. `depth` is the resulting queue depth (always `<= max_queue_depth`).
    Enqueued { depth: u32 },
    /// The tenant is over its WFQ quota — a sibling's reserved share is protected. No slot taken.
    RejectedOverQuota { quota: u32 },
    /// Backpressure: the pool is full, nothing lower is preemptible, and the bounded queue is full
    /// too (or the fairness global capacity is exhausted). Honest shed, never an unbounded queue.
    Shed(ShedReason),
}

impl SloDecision {
    pub fn is_admitted(&self) -> bool {
        matches!(self, SloDecision::Admitted { .. })
    }
    pub fn is_enqueued(&self) -> bool {
        matches!(self, SloDecision::Enqueued { .. })
    }
    pub fn is_shed(&self) -> bool {
        matches!(self, SloDecision::Shed(_))
    }
}

/// The result of completing an admitted generation on the main path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompleteOutcome {
    /// A running slot was freed.
    pub slot_freed: bool,
    /// A queued request may now be promoted — the caller should re-drive [`SloAdmissionController::admit`]
    /// for the head of its wait queue. `false` when the queue was empty.
    pub dequeue_head: bool,
}

/// The SLO-aware QoS main admission controller (SERVING_OPS.md §2).
///
/// Composes per-tenant fairness, the chunk/step preemptive scheduler, and a bounded wait queue into
/// the single pre-node admission decision the daemon's request path makes first. The parent runtime
/// constructs one per serving pool and calls [`SloAdmissionController::admit`] on every arriving
/// turn *before* handing an admitted turn to the node-level [`crate::gate::ServingGate`].
#[derive(Debug, Clone)]
pub struct SloAdmissionController {
    fairness: FairnessLimiter,
    scheduler: PreemptionScheduler,
    max_queue_depth: u32,
    queued: u32,
}

impl SloAdmissionController {
    /// Build a controller. `fairness` enforces per-tenant quotas; `scheduler` owns the running set
    /// and preemption (its capacity is the pool concurrency); `max_queue_depth` bounds the wait
    /// queue for requests that can neither run nor preempt.
    pub fn new(
        fairness: FairnessLimiter,
        scheduler: PreemptionScheduler,
        max_queue_depth: u32,
    ) -> Self {
        SloAdmissionController {
            fairness,
            scheduler,
            max_queue_depth,
            queued: 0,
        }
    }

    /// Decide admission for one arriving request (SERVING_OPS.md §2). Fairness → preemptive QoS →
    /// bounded-queue backpressure, in that order. On [`SloDecision::Admitted`] the request now
    /// occupies a pool slot (and any victim has been preempted at its boundary).
    ///
    /// This is the same policy [`crate::gate::ServingGate::pre_serve`] runs over the node-level
    /// gate's own pool state — both delegate to the shared [`qos_admit`], so the standalone
    /// controller and the wired gate can never diverge.
    pub fn admit(&mut self, req: &QosRequest) -> SloDecision {
        qos_admit(
            &mut self.fairness,
            &mut self.scheduler,
            &mut self.queued,
            self.max_queue_depth,
            req,
        )
    }

    /// The composition-facing name for [`Self::admit`]: the single SLO-aware QoS **pre-serve**
    /// decision the request path makes first, before the node-level [`crate::gate::ServingGate`].
    /// Alias kept deliberately thin — the served surface reads better calling `pre_serve` than
    /// `admit`, and the two are guaranteed identical.
    pub fn pre_serve(&mut self, req: &QosRequest) -> SloDecision {
        self.admit(req)
    }

    /// An admitted generation finished. Frees its scheduler slot and fairness quota, and reports
    /// whether a queued request may now be promoted (the caller re-drives [`Self::admit`] for the
    /// head of its wait queue — the queue holds request objects, this crate holds only the policy).
    pub fn complete(&mut self, req: &QosRequest) -> Result<CompleteOutcome, SchedError> {
        qos_complete(
            &mut self.fairness,
            &mut self.scheduler,
            &mut self.queued,
            req,
        )
    }

    /// Resume a previously-preempted sequence if a slot is free (passthrough to the scheduler).
    pub fn resume(&mut self, seq_id: u64) -> Result<bool, SchedError> {
        self.scheduler.resume(seq_id)
    }

    /// Current bounded-queue depth.
    pub fn queue_depth(&self) -> u32 {
        self.queued
    }
    /// Configured wait-queue ceiling.
    pub fn max_queue_depth(&self) -> u32 {
        self.max_queue_depth
    }
    /// Running sequences in the pool right now.
    pub fn running_count(&self) -> usize {
        self.scheduler.running_count()
    }
    /// Sequences currently preempted (awaiting resume).
    pub fn preempted_count(&self) -> usize {
        self.scheduler.preempted_count()
    }
    /// In-use fairness slots for a tenant.
    pub fn tenant_usage(&self, tenant: &TenantId) -> u32 {
        self.fairness.usage_of(tenant)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctrl(capacity: usize, quota: u32, queue: u32) -> SloAdmissionController {
        SloAdmissionController::new(
            FairnessLimiter::new(1000, quota),
            PreemptionScheduler::new(capacity),
            queue,
        )
    }

    #[test]
    fn priority_carried_p0_preempts_a_running_batch_on_the_main_path() {
        let mut c = ctrl(1, 1000, 4);
        // A P2 batch (a 20-min-scale program run) is admitted and running.
        let batch = QosRequest::new(1, PriorityClass::Batch, "prog").with_work(100_000, 8);
        assert_eq!(c.admit(&batch), SloDecision::Admitted { preempted: None });
        // A P0 incident arrives into the full pool → the batch is preempted at its boundary and the
        // incident is admitted immediately (never queued behind the batch).
        let p0 = QosRequest::new(2, PriorityClass::Interactive, "ops");
        match c.admit(&p0) {
            SloDecision::Admitted { preempted: Some(p) } => {
                assert_eq!(p.victim, 1);
                assert_eq!(p.victim_priority, PriorityClass::Batch);
            }
            other => panic!("expected preemption on the main path, got {other:?}"),
        }
    }

    #[test]
    fn full_pool_of_peers_enqueues_then_sheds_with_bounded_backpressure() {
        let mut c = ctrl(1, 1000, 1);
        assert!(c
            .admit(&QosRequest::new(1, PriorityClass::Interactive, "a"))
            .is_admitted());
        // Another P0 cannot preempt a P0 → waits in the bounded queue.
        assert_eq!(
            c.admit(&QosRequest::new(2, PriorityClass::Interactive, "b")),
            SloDecision::Enqueued { depth: 1 }
        );
        // Queue ceiling hit → honest shed, never an unbounded queue.
        assert_eq!(
            c.admit(&QosRequest::new(3, PriorityClass::Interactive, "c")),
            SloDecision::Shed(ShedReason::QueueFull { max_queue_depth: 1 })
        );
    }

    #[test]
    fn over_quota_tenant_rejected_without_consuming_a_slot() {
        let mut c = ctrl(10, 1, 10);
        assert!(c
            .admit(&QosRequest::new(1, PriorityClass::Standard, "greedy"))
            .is_admitted());
        assert_eq!(
            c.admit(&QosRequest::new(2, PriorityClass::Standard, "greedy")),
            SloDecision::RejectedOverQuota { quota: 1 }
        );
        assert_eq!(
            c.running_count(),
            1,
            "the over-quota arrival never entered the pool"
        );
    }

    #[test]
    fn complete_frees_slot_and_signals_dequeue() {
        let mut c = ctrl(1, 1000, 2);
        let r1 = QosRequest::new(1, PriorityClass::Interactive, "a");
        assert!(c.admit(&r1).is_admitted());
        assert!(c
            .admit(&QosRequest::new(2, PriorityClass::Interactive, "b"))
            .is_enqueued());
        let out = c.complete(&r1).unwrap();
        assert!(out.slot_freed);
        assert!(out.dequeue_head, "a queued request may now be promoted");
        assert_eq!(c.queue_depth(), 0);
    }
}
