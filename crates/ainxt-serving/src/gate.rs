// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! The `model.infer` upward capability — the node-level admission gate that ties Serving-Ops together
//! (SERVING_OPS.md §7 / ADR-020; audit gaps **SRV-01** + **SRV-02**).
//!
//! The audit found the crate's mechanisms — [`crate::attestation::AttestationGate`],
//! [`crate::FairnessLimiter`], [`crate::preemption::PreemptionScheduler`] — each had tests but **no
//! caller**: nothing composed them into the single capability §7/ADR-020 says Serving-Ops exposes
//! upward, and in particular the attestation gate (`SRV-02`) was inert dead code — no request was
//! actually fenced off an unattested node. This module is that caller.
//!
//! [`ServingGate::model_infer`] is the "second, node-level admission gate underneath the Model
//! Router" (§7). Given a request the Router has *already* deemed model-eligible (ADR-012), it decides
//! *whether the fleet can physically take the call right now, on a node trusted enough to see this
//! data*, in one deterministic pipeline:
//!
//! 1. **Node trust filter (ADR-021 §8.2, `SRV-02`)** — for a regulated (`confidential`+) class, only
//!    nodes the [`AttestationGate`] currently admits are candidates; if none, the request **fails
//!    closed** ([`InferAdmission::FailedClosedNoAttestedCapacity`]) and is *never* routed to an
//!    untrusted node, even one sitting idle.
//! 2. **Per-tenant fairness** — the tenant must be within its WFQ quota
//!    ([`FairnessLimiter`]) or it is [`InferAdmission::RejectedOverQuota`] (a sibling's reserved share
//!    is never consumed).
//! 3. **QoS admission with preemption** — the [`PreemptionScheduler`] admits immediately, preempts a
//!    strictly-lower-priority incumbent for a higher-priority arrival, or sheds
//!    ([`InferAdmission::Shed`]) when nothing lower is preemptible.
//! 4. **Execute** — only on a clean pass is the injected [`InferExecutor`] seam (the actual model
//!    stream, owned by the deployment) invoked.
//!
//! This is the exact `model.infer(model_id, priority_class, tenant, data_class, payload) → stream`
//! shape ADR-020 specifies, minus the physical stream (the seam). The parent runtime registers it as
//! the `model.infer` capability in its `CapabilityRegistry` — see the crate wiring note.
//!
//! Deterministic and pure: no clock, no GPU. `now`/`verifier_reachable` are inputs; the executor is a
//! seam. Every rejection path is typed and honest — nothing is silently dropped.

use ainxt_types::DataClass;

use crate::attestation::AttestationGate;
use crate::idempotency::{CommitError, CommitOutcome, IdempotencyLedger};
use crate::preemption::{AdmitOutcome, KvDisposition, Phase, PreemptionScheduler, SeqSpec};
use crate::slo::{qos_admit, qos_complete, CompleteOutcome, QosRequest, SloDecision};
use crate::wfq::{WfqScheduler, WorkItem};
use crate::{FairnessDecision, FairnessLimiter, PriorityClass, TenantId};

/// The single capability name Serving-Ops exposes upward through the platform `CapabilityRegistry`
/// (SERVING_OPS.md §7 / ADR-020 — "Serving-Ops exposes exactly one capability upward"). The parent
/// runtime registers [`ServingGate::model_infer`] under this name; nothing above the gate needs to
/// know which of the §1–§6 mechanisms fired to serve a given call.
pub const MODEL_INFER_CAPABILITY: &str = "model.infer";

/// A candidate node the request could physically run on, as offered by placement/health (§3/§4).
/// `routable` is the health verdict ([`crate::health::HealthState::is_routable`]); attestation is
/// applied here by the gate for regulated classes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeCandidate {
    pub node_id: String,
    pub routable: bool,
}

impl NodeCandidate {
    pub fn new(node_id: impl Into<String>, routable: bool) -> Self {
        NodeCandidate {
            node_id: node_id.into(),
            routable,
        }
    }
}

/// One `model.infer` call (SERVING_OPS.md §7 / ADR-020: `model.infer(model_id, priority_class,
/// tenant, data_class, payload)`). The payload/stream is the [`InferExecutor`] seam.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InferRequest {
    /// Unique sequence id for the preemption scheduler (caller-assigned, e.g. a request counter).
    pub seq_id: u64,
    pub model_id: String,
    pub priority: PriorityClass,
    pub tenant: TenantId,
    pub data_class: DataClass,
    /// Total chunks/steps this generation will take (drives preemption progress accounting).
    pub total_units: u64,
    /// KV pages this sequence will hold (for the preemption evicted-recoverable disposition).
    pub kv_pages: u32,
}

/// The physical inference-stream seam (SERVING_OPS.md §7). Real implementations dispatch to the
/// prefill/decode pools on `node_id`; this pure crate only records that the call was dispatched.
pub trait InferExecutor {
    /// Begin executing `req` on `node_id`, returning an opaque stream handle.
    fn execute(&self, req: &InferRequest, node_id: &str) -> StreamHandle;
}

/// An opaque handle to an in-flight inference stream (the real stream is the deployment's).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamHandle(pub String);

/// The verdict of one [`ServingGate::model_infer`] (SERVING_OPS.md §7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InferAdmission {
    /// Admitted and dispatched. `node_id` is the chosen node; `preempted` names a lower-priority
    /// victim if this arrival displaced one (its work is preserved per [`KvDisposition`]).
    Admitted {
        node_id: String,
        stream: StreamHandle,
        preempted: Option<Preemption>,
    },
    /// A regulated-class request with **no currently-attested node** — fails closed (ADR-021 §8.2).
    /// It is never routed to an untrusted node under any load condition.
    FailedClosedNoAttestedCapacity,
    /// No health-routable node was offered at all (the whole candidate set is drained/degraded).
    NoRoutableNode,
    /// The tenant is over its WFQ quota — its sibling's reserved share is protected.
    RejectedOverQuota { quota: u32 },
    /// The pool is full and nothing of lower priority was preemptible — honest backpressure.
    Shed,
}

impl InferAdmission {
    pub fn is_admitted(&self) -> bool {
        matches!(self, InferAdmission::Admitted { .. })
    }
}

/// Details of a preemption that occurred to admit a higher-priority request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Preemption {
    pub victim: u64,
    pub victim_priority: PriorityClass,
    pub disposition: KvDisposition,
}

/// The Serving-Ops node-level admission gate — the concrete `model.infer` capability (ADR-020).
///
/// Owns the attestation gate, the per-tenant fairness limiter, and the preemptive scheduler for one
/// serving pool. The parent runtime constructs one per pool and registers `model_infer` as the
/// `model.infer` capability.
#[derive(Debug, Clone)]
pub struct ServingGate {
    attestation: AttestationGate,
    fairness: FairnessLimiter,
    scheduler: PreemptionScheduler,
    /// Bounded main-path wait-queue ceiling for [`ServingGate::pre_serve`] (SERVING_OPS.md §2).
    /// `0` (the default) means no wait queue — a request that can neither run nor preempt is shed
    /// immediately, the same honest backpressure `model_infer` gives. A deployment opts a surface
    /// into a wait queue with [`ServingGate::with_qos_queue_depth`].
    qos_max_queue_depth: u32,
    /// Live depth of the main-path wait queue (a counted ceiling; the request objects live in the
    /// caller, this holds only the policy count — see [`ServingGate::pre_serve`]).
    qos_queued: u32,
    /// The §2 **weighted-fair-queuing** scheduler (deficit round-robin) that orders the over-capacity
    /// wait queue with a per-tenant *minimum service rate* guarantee — NOT merely the concurrency cap
    /// the [`FairnessLimiter`] provides (the audit's SRV-07 / gap-6 finding: "served per-tenant fairness
    /// is a concurrency cap, not the §2 WFQ minimum-service guarantee"). `None` (the default) leaves the
    /// gate on the plain fairness cap (unchanged behaviour); a deployment opts a pool into WFQ ordering
    /// via [`ServingGate::with_wfq`], after which a backlogged low-weight tenant is guaranteed forward
    /// progress every round proportional to its weight, regardless of a greedy sibling's demand.
    wfq: Option<WfqScheduler>,
    /// The ADR-013 inference-call idempotency ledger (`crate::idempotency`, gap `SRV-08`, round-15) —
    /// exactly-once billing + the divergence guard for THIS pool's `model_infer` dispatches. The audit
    /// found the ledger fully implemented (round-3) but with no caller on the live admission path: a
    /// gateway retry of a dropped call had no defence against double-billing tokens or a promoted node
    /// returning two different answers to the same logical request. [`ServingGate::model_infer`] now
    /// opens a ledger attempt for every dispatch it makes; [`ServingGate::complete_billed`] is the
    /// commit call the caller makes when the generation finishes, closing the loop.
    ledger: IdempotencyLedger,
    /// GAP-FIX serving-ops (SERVING_OPS.md §2, gap 6) — chunked-prefill interleaving tuning: the
    /// number of prefill chunks [`ServingGate::batch_step_tick`] schedules per tick when enabled.
    /// `None` (the default) leaves the mechanism off — unchanged behaviour, matching `wfq`'s
    /// absent-is-off shape. A deployment opts a pool in via [`ServingGate::with_chunked_prefill`].
    chunked_prefill: Option<u32>,
}

impl ServingGate {
    pub fn new(
        attestation: AttestationGate,
        fairness: FairnessLimiter,
        scheduler: PreemptionScheduler,
    ) -> Self {
        ServingGate {
            attestation,
            fairness,
            scheduler,
            qos_max_queue_depth: 0,
            qos_queued: 0,
            wfq: None,
            ledger: IdempotencyLedger::new(),
            chunked_prefill: None,
        }
    }

    /// Opt this gate into **chunked-prefill interleaving** (SERVING_OPS.md §2, gap 6): every
    /// [`ServingGate::batch_step_tick`] call schedules `prefill_chunks_per_tick` fresh prefill chunks
    /// interleaved with a decode step for every sequence CURRENTLY running on this gate's own
    /// [`PreemptionScheduler`] — so a long incoming prefill never blocks an in-flight decode by more
    /// than one chunk, on the SAME pool state `model_infer` admits into. Builder-style so existing
    /// [`ServingGate::new`] callers are unchanged; default (unset) keeps the mechanism off.
    pub fn with_chunked_prefill(mut self, prefill_chunks_per_tick: u32) -> Self {
        self.chunked_prefill = Some(prefill_chunks_per_tick.max(1));
        self
    }

    /// Whether this gate has chunked-prefill interleaving enabled.
    pub fn has_chunked_prefill(&self) -> bool {
        self.chunked_prefill.is_some()
    }

    /// **Drive one chunked-prefill interleaving step** (SERVING_OPS.md §2, gap 6) over this gate's own
    /// live [`PreemptionScheduler`] — the SAME scheduler instance [`ServingGate::model_infer`] admits
    /// every `/v1/infer` call into. Gathers every currently-running sequence id
    /// ([`crate::preemption::PreemptionScheduler::running_ids`]) and interleaves this tick's declared
    /// prefill-chunk budget between a decode step for each of them via [`crate::wfq::batch_step`] —
    /// which ALSO advances each interleaved decode sequence one step through the SAME scheduler, a
    /// real mutation of the live pool state, not a read-only projection. Returns `None` when chunked
    /// prefill is not enabled on this gate (matching the `wfq`/`attestation_manifest` absent-is-off
    /// shape); otherwise the [`crate::wfq::BatchStep`] that ran.
    pub fn batch_step_tick(&mut self) -> Option<crate::wfq::BatchStep> {
        let chunks = self.chunked_prefill?;
        let decode_seqs = self.scheduler.running_ids();
        Some(crate::wfq::batch_step(
            &mut self.scheduler,
            &decode_seqs,
            chunks,
        ))
    }

    /// GAP-FIX gap6-composition-root (Item 2 test support) — the cumulative decode progress
    /// ([`crate::preemption::PreemptionScheduler::completed_units`]) for a currently-running sequence:
    /// a pure read exposing the SAME scheduler [`ServingGate::batch_step_tick`] advances. Purely for
    /// external observability (e.g. proving a background sweep loop over this gate is making real
    /// decode progress from OUTSIDE the loop, not merely returning a handle that never actually runs)
    /// — mirrors the already-established `has_chunked_prefill`/`infer_total_billed`/`qos_queue_depth`
    /// shape of exposing gate-internal state read-only. `None` if `seq_id` is not currently running.
    pub fn running_decode_progress(&self, seq_id: u64) -> Option<u64> {
        self.scheduler.completed_units(seq_id)
    }

    /// The ADR-013 idempotency key for one `model.infer` call (gap `SRV-08`): the tenant + the
    /// caller-assigned `seq_id` identify one *logical* request across retries. A gateway retrying the
    /// same logical call after a drop resubmits the SAME `seq_id` for the SAME tenant — that contract
    /// is what makes this key stable across attempts without widening [`InferRequest`]'s field set
    /// (which would break the reserved served-path caller's exhaustive struct literal).
    fn infer_key(req: &InferRequest) -> String {
        format!("{}#{}", req.tenant.as_str(), req.seq_id)
    }

    /// Whether this pool's ledger already holds a **final, billed** answer for `req`'s logical
    /// request — a retry of this exact `(tenant, seq_id)` must not be re-billed at
    /// [`Self::complete_billed`] time (it is a safe, zero-charge no-op there instead).
    pub fn infer_is_committed(&self, req: &InferRequest) -> bool {
        self.ledger.is_committed(&Self::infer_key(req))
    }

    /// The current ledger attempt number for `req`'s logical request (`None` once committed, or if
    /// `model_infer` was never dispatched for it) — surfaces a retry-after-drop as attempt >= 2.
    pub fn infer_attempt(&self, req: &InferRequest) -> Option<u32> {
        self.ledger.attempt(&Self::infer_key(req))
    }

    /// Total tokens this pool's ledger has billed across every committed `model_infer` call — the
    /// FinOps accounting signal (ADR-013), summed exactly once per logical request regardless of how
    /// many admission attempts it took.
    pub fn infer_total_billed(&self) -> u64 {
        self.ledger.total_billed()
    }

    /// Opt this gate's main-path [`ServingGate::pre_serve`] into a **bounded** wait queue of at most
    /// `depth` requests (SERVING_OPS.md §2): a turn that can neither run nor preempt waits rather
    /// than being shed, until the ceiling is hit (then honest [`SloDecision::Shed`], never an
    /// unbounded queue). Builder-style so the existing 3-arg [`ServingGate::new`] callers are
    /// unchanged; default (unset) is `0` = no queue.
    pub fn with_qos_queue_depth(mut self, depth: u32) -> Self {
        self.qos_max_queue_depth = depth;
        self
    }

    /// Opt this gate's over-capacity wait queue into **weighted-fair-queuing minimum-service** ordering
    /// (SERVING_OPS.md §2; audit gap SRV-07 / serving-ops gap-6). `quantum_unit` is the per-round
    /// service credit a weight-1 tenant receives; `weights` sets each tenant's relative share. Unlike
    /// the plain [`FairnessLimiter`] concurrency cap (which under a saturated pool can let a burst from
    /// one tenant indefinitely delay a sibling's queued turn), the WFQ scheduler visits every backlogged
    /// tenant each round and dispatches work up to its accumulated deficit — so a low-weight tenant is
    /// *guaranteed* progress proportional to its weight regardless of any other tenant's demand. Builder
    /// style so existing [`ServingGate::new`] callers are unchanged; default (unset) keeps the cap-only
    /// behaviour.
    pub fn with_wfq(mut self, quantum_unit: u32, weights: &[(&str, u32)]) -> Self {
        let mut sched = WfqScheduler::new(quantum_unit);
        for (tenant, weight) in weights {
            sched.set_weight(*tenant, *weight);
        }
        self.wfq = Some(sched);
        self
    }

    /// Whether this gate orders its wait queue by the §2 WFQ minimum-service discipline.
    pub fn has_wfq(&self) -> bool {
        self.wfq.is_some()
    }

    /// Enqueue an over-capacity turn onto the §2 WFQ wait queue under its tenant (the JWT `department`
    /// claim). No-op returning `false` when WFQ is not enabled on this gate (the caller falls back to
    /// the plain bounded queue). The `cost` is the turn's service weight (e.g. token budget).
    pub fn wfq_enqueue(&mut self, tenant: impl Into<TenantId>, id: u64, cost: u32) -> bool {
        match self.wfq.as_mut() {
            Some(sched) => {
                sched.enqueue(tenant, WorkItem { id, cost });
                true
            }
            None => false,
        }
    }

    /// Dispatch one WFQ round: the deterministic, weight-proportional set of queued turns cleared to run
    /// this round (SERVING_OPS.md §2 minimum-service). Empty when WFQ is disabled or nothing is queued.
    /// This is the ordering the served daemon's wait-queue drain consults (the per-round tick binding on
    /// the async HTTP path is the daemon's concern — needs_hot_wiring).
    pub fn wfq_round(&mut self) -> Vec<(TenantId, WorkItem)> {
        match self.wfq.as_mut() {
            Some(sched) => sched.round(),
            None => Vec::new(),
        }
    }

    /// Current WFQ backlog for a tenant (0 when WFQ is disabled).
    pub fn wfq_backlog(&self, tenant: &TenantId) -> usize {
        self.wfq.as_ref().map(|s| s.backlog(tenant)).unwrap_or(0)
    }

    /// Mutable access to the attestation gate so the deployment can submit quotes / clear quarantines.
    pub fn attestation_mut(&mut self) -> &mut AttestationGate {
        &mut self.attestation
    }

    /// GAP-FIX identity-payments (gap6 audit item 2) — unconditionally preempt, on THIS gate's own
    /// live [`PreemptionScheduler`], the running sequence carrying identity-plane `run_id` (see
    /// [`crate::preemption::SeqSpec::run_id`]'s doc). This is the real mechanism
    /// [`ainxt_identity::authority::KillSwitch::signal_preemption`]'s
    /// [`ainxt_identity::authority::PreemptionSink`] seam drives (see the `impl PreemptionSink for
    /// ServingGate` below) — a scoped/workforce kill-switch pull reaches a Run already admitted into
    /// this pool, not merely its next issuance/renewal. `None` if no running sequence on this gate
    /// carries that `run_id` (idempotent-friendly, mirroring `PreemptionSink::preempt`'s own doc).
    pub fn force_preempt_run(
        &mut self,
        run_id: &str,
    ) -> Option<crate::preemption::PreemptedRecord> {
        self.scheduler.force_preempt_by_run_id(run_id)
    }

    /// Read-only access to this gate's own live [`PreemptionScheduler`] — lets a caller/test observe
    /// `is_running`/`preempted`/`running_count` state after a [`Self::force_preempt_run`] or an
    /// ordinary `admit`, without this gate needing a bespoke passthrough for every scheduler query.
    pub fn scheduler(&self) -> &PreemptionScheduler {
        &self.scheduler
    }

    /// Mutable access to this gate's own live [`PreemptionScheduler`] (mirrors [`Self::scheduler`]) —
    /// lets a caller drive `advance`/`complete`/`resume` directly against the SAME pool state
    /// [`Self::pre_serve`]/`model_infer` admit into, for callers that need the lower-level scheduler
    /// API `ServingGate` does not otherwise wrap (e.g. progress accounting in a test/harness).
    pub fn scheduler_mut(&mut self) -> &mut PreemptionScheduler {
        &mut self.scheduler
    }

    /// The **SLO-aware QoS pre-serve entrypoint** the composition applies on the main request path
    /// (SERVING_OPS.md §2 — P0/P1/P2 priority classes + chunk/step-granular preemption + per-tenant
    /// fairness + bounded-queue backpressure), the pre-node decision `/v1/chat` makes first.
    ///
    /// This runs the identical [`qos_admit`] policy the standalone [`crate::slo::SloAdmissionController`]
    /// documents, but over **this gate's own** [`FairnessLimiter`] + [`PreemptionScheduler`] — the
    /// same pool state [`ServingGate::model_infer`] admits into. So the main chat path and the
    /// node-level `model.infer` capability compete for ONE pool-concurrency view (a P0 chat turn can
    /// preempt a running P2 batch, and vice-versa) rather than two divergent copies. On
    /// [`SloDecision::Admitted`] the request now holds a scheduler slot + a fairness quota slot; the
    /// caller MUST later call [`ServingGate::pre_serve_complete`] (a release-on-drop guard on the
    /// served path) so the slot is never leaked.
    ///
    /// Unlike [`ServingGate::pre_serve_check`] this carries no `data_class`/candidate node: the
    /// attestation node fence is a *separate* seam (§8.2) the composition applies alongside this —
    /// this is purely the §2 priority-aware admission the audit found the live path was missing.
    pub fn pre_serve(&mut self, req: &QosRequest) -> SloDecision {
        // Cap-only default (no WFQ configured): the plain bounded-FIFO counter, unchanged.
        if self.wfq.is_none() {
            return qos_admit(
                &mut self.fairness,
                &mut self.scheduler,
                &mut self.qos_queued,
                self.qos_max_queue_depth,
                req,
            );
        }
        // WFQ-ordered wait queue (SERVING_OPS.md §2, gap-2): the over-capacity wait queue is the
        // §2 deficit-round-robin [`WfqScheduler`], not a blind FIFO counter — so a low-weight tenant's
        // queued turn is GUARANTEED weight-proportional forward progress on the next drain
        // ([`ServingGate::pre_serve_drain_round`]) regardless of a greedy sibling's backlog. This is the
        // caller the audit found missing: `with_wfq` configured a scheduler the live `pre_serve` path
        // never actually enqueued into. Fairness + preemption are identical to [`qos_admit`]; only the
        // *queue backend* for the Rejected branch changes.
        match self.fairness.try_admit(&req.tenant) {
            FairnessDecision::Admit => {}
            FairnessDecision::RejectOverQuota { quota } => {
                return SloDecision::RejectedOverQuota { quota }
            }
            FairnessDecision::RejectAtCapacity => {
                return SloDecision::Shed(crate::ShedReason::QueueFull {
                    max_queue_depth: self.qos_max_queue_depth,
                })
            }
        }
        let spec = SeqSpec {
            id: req.seq_id,
            priority: req.priority,
            tenant: req.tenant.clone(),
            phase: Phase::Prefill,
            total_units: req.total_units,
            kv_pages: req.kv_pages,
            run_id: req.run_id.clone(),
        };
        match self.scheduler.admit(spec) {
            Ok(AdmitOutcome::Started) => SloDecision::Admitted { preempted: None },
            Ok(AdmitOutcome::Preempted {
                victim,
                victim_priority,
                disposition,
            }) => SloDecision::Admitted {
                preempted: Some(crate::slo::QosPreemption {
                    victim,
                    victim_priority,
                    disposition,
                }),
            },
            Ok(AdmitOutcome::Rejected) => {
                // Cannot run now and nothing lower to preempt: release the fairness slot (the turn is
                // NOT running) and enqueue into the WFQ scheduler, bounded by the same queue ceiling.
                self.fairness.release(&req.tenant);
                let backlog = self.wfq_total_backlog();
                if backlog < self.qos_max_queue_depth {
                    // Service weight of the turn (token budget proxy); at least 1 so every turn accrues.
                    let cost = req.total_units.min(u64::from(u32::MAX)) as u32;
                    let cost = cost.max(1);
                    self.wfq
                        .as_mut()
                        .expect("wfq present in this branch")
                        .enqueue(
                            req.tenant.clone(),
                            WorkItem {
                                id: req.seq_id,
                                cost,
                            },
                        );
                    SloDecision::Enqueued {
                        depth: self.wfq_total_backlog(),
                    }
                } else {
                    SloDecision::Shed(crate::ShedReason::QueueFull {
                        max_queue_depth: self.qos_max_queue_depth,
                    })
                }
            }
            Err(_) => {
                self.fairness.release(&req.tenant);
                SloDecision::Shed(crate::ShedReason::QueueFull {
                    max_queue_depth: self.qos_max_queue_depth,
                })
            }
        }
    }

    /// Total queued turns across all tenants on the §2 WFQ wait queue (0 when WFQ is disabled).
    pub fn wfq_total_backlog(&self) -> u32 {
        self.wfq
            .as_ref()
            .map(|s| s.total_backlog().min(u32::MAX as usize) as u32)
            .unwrap_or(0)
    }

    /// Drain one **WFQ round** off the live wait queue (SERVING_OPS.md §2, gap-2): the deterministic,
    /// weight-proportional set of queued turns cleared to run this round, with a per-tenant
    /// *minimum-service* guarantee (a backlogged low-weight tenant is never starved by a greedy
    /// sibling). Returns the dequeued turns in dispatch order; the caller re-drives
    /// [`ServingGate::pre_serve`] for each as a running slot frees. Empty when WFQ is disabled or the
    /// queue is empty. (The async timer that ticks this drain on the served HTTP path is the daemon's
    /// concern — needs_hot_wiring; the ORDERING it drains by is now the live queue, not a blind FIFO.)
    pub fn pre_serve_drain_round(&mut self) -> Vec<(TenantId, WorkItem)> {
        self.wfq_round()
    }

    /// Release the pool slot a [`ServingGate::pre_serve`]-admitted turn held, and report whether a
    /// queued turn may now be promoted. The served path calls this from a release-on-drop guard tied
    /// to the response stream so a slot is freed on normal end AND on client disconnect.
    pub fn pre_serve_complete(
        &mut self,
        req: &QosRequest,
    ) -> Result<CompleteOutcome, crate::preemption::SchedError> {
        if self.wfq.is_some() {
            // WFQ-ordered queue: free the scheduler + fairness slots, then report whether any tenant
            // still has a WFQ backlog the caller should drain a round for (the queue itself is the WFQ
            // scheduler, so `qos_queued` is not the depth signal here).
            self.scheduler.complete(req.seq_id)?;
            self.fairness.release(&req.tenant);
            return Ok(CompleteOutcome {
                slot_freed: true,
                dequeue_head: self.wfq_total_backlog() > 0,
            });
        }
        qos_complete(
            &mut self.fairness,
            &mut self.scheduler,
            &mut self.qos_queued,
            req,
        )
    }

    /// Current main-path wait-queue depth (SERVING_OPS.md §2). When WFQ ordering is enabled this is
    /// the total WFQ backlog (the live queue is the WFQ scheduler); otherwise the plain FIFO counter.
    pub fn qos_queue_depth(&self) -> u32 {
        if self.wfq.is_some() {
            self.wfq_total_backlog()
        } else {
            self.qos_queued
        }
    }

    /// The **node-level attestation pre-serve check** (SERVING_OPS.md §8.2 / ADR-021, gap `SRV-02`),
    /// exposed as a standalone callable so the live serving path (and any surface fronting this pool)
    /// can fence a turn off an untrusted node *before* committing fleet capacity — the cheap first
    /// hop [`ServingGate::model_infer`] itself runs internally.
    ///
    /// For a regulated (`confidential`+) class only nodes the [`AttestationGate`] currently admits are
    /// eligible; if a routable node exists but none carry a valid, unexpired quote the check
    /// **fails closed** ([`PreServeVerdict::FailClosedNoAttestedCapacity`]) — the request is *never*
    /// handed to an untrusted node under any load, even one sitting idle. It is fail-closed, not
    /// fail-open: the safe default when trust cannot be established is refusal.
    pub fn pre_serve_check(
        &self,
        data_class: DataClass,
        candidates: &[NodeCandidate],
        now: u64,
        verifier_reachable: bool,
    ) -> PreServeVerdict {
        match self.select_node(data_class, candidates, now, verifier_reachable) {
            NodeSelection::Selected(id) => PreServeVerdict::Admit { node_id: id },
            NodeSelection::NoRoutable => PreServeVerdict::NoRoutableNode,
            NodeSelection::NoAttested => PreServeVerdict::FailClosedNoAttestedCapacity,
        }
    }

    /// The `model.infer` capability entrypoint (SERVING_OPS.md §7 / ADR-020).
    ///
    /// `candidates` are the nodes placement/health currently offers for this model; `now` and
    /// `verifier_reachable` drive the attestation freshness/grace decision (ADR-021 §8.3). Returns a
    /// typed [`InferAdmission`] — on `Admitted` the injected executor has been invoked.
    pub fn model_infer(
        &mut self,
        req: &InferRequest,
        candidates: &[NodeCandidate],
        now: u64,
        verifier_reachable: bool,
        executor: &dyn InferExecutor,
    ) -> InferAdmission {
        // Step 1: pick a health-routable, trust-eligible node (SRV-02 — the attestation gate CALLER).
        // The same standalone pre-serve check the live path calls, so admission and the cheap
        // pre-flight can never disagree about which nodes are trusted for this data class.
        let node = match self.pre_serve_check(req.data_class, candidates, now, verifier_reachable) {
            PreServeVerdict::Admit { node_id } => node_id,
            PreServeVerdict::NoRoutableNode => return InferAdmission::NoRoutableNode,
            PreServeVerdict::FailClosedNoAttestedCapacity => {
                return InferAdmission::FailedClosedNoAttestedCapacity
            }
        };

        // Step 2: per-tenant fairness (a greedy tenant never eats a sibling's reserved share).
        match self.fairness.try_admit(&req.tenant) {
            FairnessDecision::Admit => {}
            FairnessDecision::RejectOverQuota { quota } => {
                return InferAdmission::RejectedOverQuota { quota }
            }
            // At-capacity within the fairness limiter is also backpressure — treat as a shed.
            FairnessDecision::RejectAtCapacity => return InferAdmission::Shed,
        }

        // Step 3: QoS admission with chunk/step-granular preemption.
        let spec = SeqSpec {
            id: req.seq_id,
            priority: req.priority,
            tenant: req.tenant.clone(),
            phase: Phase::Prefill,
            total_units: req.total_units,
            kv_pages: req.kv_pages,
            // The node-level `model.infer` capability carries no identity-plane `run_id` correlation
            // today (unlike the main `/v1/chat` path's `QosRequest::with_run_id`, gap6 audit item 2) —
            // `None` is the pre-existing, unchanged shape; a kill-switch cannot force-preempt a
            // sequence admitted through this path by `run_id` (it can still be swept by the ordinary
            // priority-based `admit` eviction).
            run_id: None,
        };
        let admit = match self.scheduler.admit(spec) {
            Ok(o) => o,
            Err(_) => {
                // Duplicate seq_id (an accounting bug upstream): release the fairness slot, refuse.
                self.fairness.release(&req.tenant);
                return InferAdmission::Shed;
            }
        };
        let preempted = match admit {
            AdmitOutcome::Started => None,
            AdmitOutcome::Preempted {
                victim,
                victim_priority,
                disposition,
            } => Some(Preemption {
                victim,
                victim_priority,
                disposition,
            }),
            AdmitOutcome::Rejected => {
                // Nothing lower-priority to preempt → honest backpressure; undo the fairness slot.
                self.fairness.release(&req.tenant);
                return InferAdmission::Shed;
            }
        };

        // Step 4: open the ADR-013 ledger attempt for this logical request (gap `SRV-08`) — BEFORE
        // touching the physical stream seam, so a call that never reaches `complete_billed` (the
        // process dies mid-generation) is still recorded as an open attempt a retry can safely resume
        // under the SAME key, rather than the ledger's exactly-once/divergence machinery having no
        // record of the call at all.
        self.ledger.begin(&Self::infer_key(req));

        // Step 5: dispatch to the physical stream seam.
        let stream = executor.execute(req, &node);
        InferAdmission::Admitted {
            node_id: node,
            stream,
            preempted,
        }
    }

    /// Free the fairness + scheduler slots when an admitted generation completes. Does **not** touch
    /// the idempotency ledger — a caller that only tracks completion, not billing, keeps today's
    /// behaviour unchanged. Prefer [`ServingGate::complete_billed`] on any path that bills tokens.
    pub fn complete(&mut self, req: &InferRequest) {
        let _ = self.scheduler.complete(req.seq_id);
        self.fairness.release(&req.tenant);
    }

    /// **Complete + bill** an admitted `model_infer` generation (SERVING_OPS.md §1/§4 step 2, ADR-013,
    /// gap `SRV-08`, round-15): frees the fairness + scheduler slots (identical to
    /// [`ServingGate::complete`]) and commits `tokens` against this logical request's ledger entry
    /// under `result_hash`.
    ///
    /// * A **first** commit for this `(tenant, seq_id)` bills `tokens` exactly once
    ///   ([`CommitOutcome::billed_now`] == `tokens`).
    /// * A **duplicate** commit with the SAME `result_hash` (e.g. the caller commits twice for the
    ///   same generation by mistake, or a retried-then-succeeded attempt reports the same answer) bills
    ///   **nothing further** (`billed_now == 0`) — exactly-once billing survives a duplicate call.
    /// * A commit with a **different** `result_hash` than what is already committed is rejected
    ///   ([`CommitError::DivergentResult`]) — the concrete guard against a promoted/retried node
    ///   returning two different answers to one logical request being both billed. The fairness +
    ///   scheduler slots are still freed even on this error path (the generation DID finish; only the
    ///   ledger call is rejected), so a divergence never leaks a pool slot.
    pub fn complete_billed(
        &mut self,
        req: &InferRequest,
        tokens: u64,
        result_hash: u64,
    ) -> Result<CommitOutcome, CommitError> {
        let outcome = self
            .ledger
            .commit(&Self::infer_key(req), tokens, result_hash);
        let _ = self.scheduler.complete(req.seq_id);
        self.fairness.release(&req.tenant);
        outcome
    }

    /// Select a node: health-routable, and (for regulated classes) currently attestation-admitted.
    fn select_node(
        &self,
        data_class: DataClass,
        candidates: &[NodeCandidate],
        now: u64,
        verifier_reachable: bool,
    ) -> NodeSelection {
        let mut saw_routable = false;
        for c in candidates {
            if !c.routable {
                continue;
            }
            saw_routable = true;
            let verdict =
                self.attestation
                    .evaluate(&c.node_id, data_class, now, verifier_reachable);
            if verdict.is_admitted() {
                return NodeSelection::Selected(c.node_id.clone());
            }
        }
        if !saw_routable {
            NodeSelection::NoRoutable
        } else {
            // There were routable nodes, but none passed the trust gate for this data class →
            // fail closed for regulated traffic (ADR-021 §8.2). For non-regulated classes the
            // attestation gate admits any node, so this branch is only reached when regulated.
            NodeSelection::NoAttested
        }
    }
}

enum NodeSelection {
    Selected(String),
    NoRoutable,
    NoAttested,
}

/// The verdict of the standalone node-level attestation [`ServingGate::pre_serve_check`]
/// (SERVING_OPS.md §8.2 / ADR-021). A `FailClosedNoAttestedCapacity` is a hard refusal for
/// regulated data — the request must never be served on an untrusted node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreServeVerdict {
    /// A trust-eligible, health-routable node was found — `node_id` may serve this data class.
    Admit { node_id: String },
    /// No health-routable node was offered at all (the whole candidate set is drained/degraded).
    NoRoutableNode,
    /// Routable nodes exist but none currently carry a valid attestation quote for this regulated
    /// class — **fail closed** (ADR-021 §8.2): never route to an untrusted node, even an idle one.
    FailClosedNoAttestedCapacity,
}

impl PreServeVerdict {
    /// True only when a node was admitted; a fail-closed / no-node verdict is `false`.
    pub fn is_admitted(&self) -> bool {
        matches!(self, PreServeVerdict::Admit { .. })
    }
}

// ===========================================================================
// GAP-FIX identity-payments (gap6 audit item 2) — the REAL `PreemptionSink` implementor.
// ===========================================================================

/// `ServingGate` is the REAL, production scheduler type the served daemon holds
/// (`ainxt_runtimed::AssembledFull::serving` / `ainxt_server`'s `ServingAdmission::gate`) — not a
/// test double. Before this `impl`, `ainxt-serving` had ZERO implementors of
/// [`ainxt_identity::authority::PreemptionSink`] anywhere in the workspace outside
/// `ainxt-identity`'s own tests' hand-rolled `RecordingScheduler`, even though
/// `KillSwitch::signal_preemption`'s own doc explicitly claims "the real deployment wires
/// `ainxt-serving`'s preemptor in behind it." `preempt` delegates to
/// [`ServingGate::force_preempt_run`] — idempotent by `run_id` (a directive for a `run_id` this gate
/// never admitted, or already preempted/completed, is a silent no-op, matching the trait's own
/// idempotency contract), and deliberately ignores [`PreemptDirective::checkpoint_to_pending`]: this
/// gate's own [`crate::preemption::PreemptionScheduler::force_preempt_by_run_id`] already derives the
/// correct [`crate::preemption::KvDisposition`] (checkpoint-to-PENDING vs evicted-recoverable) from
/// the sequence's OWN [`PriorityClass`], the SAME rule [`crate::preemption::PreemptionScheduler::admit`]'s
/// own eviction uses — never a second, divergent disposition decision.
impl ainxt_identity::authority::PreemptionSink for ServingGate {
    fn preempt(&mut self, directive: &ainxt_identity::authority::PreemptDirective) {
        let _ = self.force_preempt_run(&directive.run_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::{
        AllowListVerifier, AttestationConfig, AttestationQuote, Measurements, ReferenceValues,
        TrustTier,
    };

    /// A fake executor that records dispatch and returns a deterministic handle.
    struct FakeExecutor;
    impl InferExecutor for FakeExecutor {
        fn execute(&self, req: &InferRequest, node_id: &str) -> StreamHandle {
            StreamHandle(format!("stream:{}@{}", req.seq_id, node_id))
        }
    }

    fn gate() -> ServingGate {
        ServingGate::new(
            AttestationGate::new(AttestationConfig {
                quote_ttl: 100,
                grace_ttl: 15,
            }),
            FairnessLimiter::new(4, 2),
            PreemptionScheduler::new(2),
        )
    }

    fn attest(gate: &mut ServingGate, node: &str) {
        let refs = ReferenceValues::new()
            .allow_firmware("fw-1")
            .allow_driver("drv-1")
            .allow_binary("bin-1");
        let verifier = AllowListVerifier::new().accept("sig-good");
        let quote = AttestationQuote {
            node_id: node.into(),
            tier: TrustTier::CcEnclave,
            measurements: Measurements {
                firmware_hash: "fw-1".into(),
                driver_version: "drv-1".into(),
                binary_hash: "bin-1".into(),
            },
            signature: "sig-good".into(),
        };
        gate.attestation_mut()
            .submit_quote(&quote, 0, &verifier, &refs)
            .unwrap();
    }

    fn req(seq: u64, p: PriorityClass, dc: DataClass, tenant: &str) -> InferRequest {
        InferRequest {
            seq_id: seq,
            model_id: "qwen-32b".into(),
            priority: p,
            tenant: TenantId::new(tenant),
            data_class: dc,
            total_units: 100,
            kv_pages: 4,
        }
    }

    #[test]
    fn r3_serving_ops_pre_serve_attestation_gate_callable_fails_closed() {
        // ROUND-3 (critical): the node-level attestation gate must be a CALLABLE pre-serve check that
        // fails closed for regulated data — the property the live serving path enforces before it
        // commits fleet capacity. Fail-before: no such standalone entrypoint existed (only the full
        // model_infer pipeline). Pass-after: `pre_serve_check` fences a regulated turn off an
        // unattested-but-routable node, and admits it once (and only once) a node is attested.
        let mut g = gate();
        let routable_unattested = vec![NodeCandidate::new("n1", true)];

        // (a) Regulated class, routable node with NO quote → fail closed (never served untrusted).
        assert_eq!(
            g.pre_serve_check(DataClass::RegulatedPayment, &routable_unattested, 10, true),
            PreServeVerdict::FailClosedNoAttestedCapacity,
        );
        // PII is regulated too — same fail-closed verdict.
        assert_eq!(
            g.pre_serve_check(DataClass::Pii, &routable_unattested, 10, true),
            PreServeVerdict::FailClosedNoAttestedCapacity,
        );

        // (b) A non-regulated class is admitted on the same node (the gate does not over-block).
        assert!(g
            .pre_serve_check(DataClass::Internal, &routable_unattested, 10, true)
            .is_admitted());

        // (c) Attest the node → the regulated turn is now admitted onto exactly that node.
        attest(&mut g, "n1");
        assert_eq!(
            g.pre_serve_check(DataClass::RegulatedPayment, &routable_unattested, 10, true),
            PreServeVerdict::Admit {
                node_id: "n1".into()
            },
        );

        // (d) The quote goes stale (now beyond ttl) → the callable fails closed again, even though the
        // node is still health-routable. Trust is time-bounded, not a one-time flag.
        assert_eq!(
            g.pre_serve_check(DataClass::RegulatedPayment, &routable_unattested, 500, true),
            PreServeVerdict::FailClosedNoAttestedCapacity,
        );

        // (e) The standalone check and the full model_infer pipeline agree on the trust decision.
        let r = req(
            1,
            PriorityClass::Interactive,
            DataClass::RegulatedPayment,
            "dept-a",
        );
        assert_eq!(
            g.model_infer(&r, &routable_unattested, 500, true, &FakeExecutor),
            InferAdmission::FailedClosedNoAttestedCapacity,
        );

        // The single upward capability is named for the CapabilityRegistry.
        assert_eq!(super::MODEL_INFER_CAPABILITY, "model.infer");
    }

    #[test]
    fn gap_ainxt_serving_srv_01_model_infer_admits_and_dispatches_end_to_end() {
        // The whole pipeline: node selection + fairness + admission + executor dispatch.
        let mut g = gate();
        let candidates = vec![NodeCandidate::new("n1", true)];
        let r = req(1, PriorityClass::Interactive, DataClass::Internal, "dept-a");
        let out = g.model_infer(&r, &candidates, 10, true, &FakeExecutor);
        match out {
            InferAdmission::Admitted {
                node_id,
                stream,
                preempted,
            } => {
                assert_eq!(node_id, "n1");
                assert_eq!(stream, StreamHandle("stream:1@n1".into()));
                assert!(preempted.is_none());
            }
            other => panic!("expected admission, got {other:?}"),
        }
    }

    #[test]
    fn gap_ainxt_serving_srv_02_regulated_request_fails_closed_on_unattested_node() {
        // A routable node exists but has NO attestation quote → a regulated request must fail closed,
        // never run on it. This is the caller the audit said was missing for AttestationGate.
        let mut g = gate();
        let candidates = vec![NodeCandidate::new("unattested", true)];
        let r = req(
            1,
            PriorityClass::Interactive,
            DataClass::RegulatedPayment,
            "dept-a",
        );
        assert_eq!(
            g.model_infer(&r, &candidates, 10, true, &FakeExecutor),
            InferAdmission::FailedClosedNoAttestedCapacity
        );
    }

    #[test]
    fn gap_ainxt_serving_srv_02_regulated_request_runs_only_on_attested_node() {
        let mut g = gate();
        // Two routable nodes; only n2 is attested. The regulated request must land on n2.
        attest(&mut g, "n2");
        let candidates = vec![
            NodeCandidate::new("n1", true),
            NodeCandidate::new("n2", true),
        ];
        let r = req(1, PriorityClass::Interactive, DataClass::Pii, "dept-a");
        match g.model_infer(&r, &candidates, 10, true, &FakeExecutor) {
            InferAdmission::Admitted { node_id, .. } => assert_eq!(node_id, "n2"),
            other => panic!("expected admission on the attested node, got {other:?}"),
        }
    }

    #[test]
    fn gap_ainxt_serving_srv_02_stale_attestation_fails_closed_even_with_routable_node() {
        let mut g = gate();
        attest(&mut g, "n1"); // quote fresh at t=0, ttl=100
        let candidates = vec![NodeCandidate::new("n1", true)];
        let r = req(
            1,
            PriorityClass::Interactive,
            DataClass::RegulatedPayment,
            "dept-a",
        );
        // now=200 > ttl, verifier reachable → the quote is stale → fail closed, do NOT serve.
        assert_eq!(
            g.model_infer(&r, &candidates, 200, true, &FakeExecutor),
            InferAdmission::FailedClosedNoAttestedCapacity
        );
    }

    #[test]
    fn no_routable_node_is_distinct_from_no_attested_capacity() {
        let mut g = gate();
        let candidates = vec![NodeCandidate::new("n1", false)]; // health-drained
        let r = req(1, PriorityClass::Interactive, DataClass::Internal, "dept-a");
        assert_eq!(
            g.model_infer(&r, &candidates, 10, true, &FakeExecutor),
            InferAdmission::NoRoutableNode
        );
    }

    #[test]
    fn incident_p0_preempts_a_batch_incumbent_through_the_gate() {
        let mut g = ServingGate::new(
            AttestationGate::new(AttestationConfig {
                quote_ttl: 100,
                grace_ttl: 15,
            }),
            FairnessLimiter::new(10, 10),
            PreemptionScheduler::new(1),
        );
        let candidates = vec![NodeCandidate::new("n1", true)];
        // A P2 batch job is admitted and running...
        assert!(g
            .model_infer(
                &req(1, PriorityClass::Batch, DataClass::Internal, "batch"),
                &candidates,
                0,
                true,
                &FakeExecutor
            )
            .is_admitted());
        // ...a P0 incident arrives into the full pool → the batch is preempted, incident dispatched.
        let out = g.model_infer(
            &req(2, PriorityClass::Interactive, DataClass::Internal, "ops"),
            &candidates,
            0,
            true,
            &FakeExecutor,
        );
        match out {
            InferAdmission::Admitted {
                preempted: Some(p), ..
            } => {
                assert_eq!(p.victim, 1);
                assert_eq!(p.victim_priority, PriorityClass::Batch);
            }
            other => panic!("expected preemption, got {other:?}"),
        }
    }

    #[test]
    fn over_quota_tenant_is_rejected_without_touching_the_scheduler() {
        // Fairness quota 1 per tenant; the second concurrent request from the same tenant is refused
        // for quota (not admitted, not shed) — and the scheduler slot is NOT consumed.
        let mut g = ServingGate::new(
            AttestationGate::new(AttestationConfig {
                quote_ttl: 100,
                grace_ttl: 15,
            }),
            FairnessLimiter::new(10, 1),
            PreemptionScheduler::new(4),
        );
        let candidates = vec![NodeCandidate::new("n1", true)];
        assert!(g
            .model_infer(
                &req(1, PriorityClass::Standard, DataClass::Internal, "dept-a"),
                &candidates,
                0,
                true,
                &FakeExecutor
            )
            .is_admitted());
        assert_eq!(
            g.model_infer(
                &req(2, PriorityClass::Standard, DataClass::Internal, "dept-a"),
                &candidates,
                0,
                true,
                &FakeExecutor
            ),
            InferAdmission::RejectedOverQuota { quota: 1 }
        );
        assert_eq!(
            g.scheduler.running_count(),
            1,
            "the rejected request never entered the scheduler"
        );
    }

    #[test]
    fn shed_when_pool_full_and_nothing_preemptible_releases_fairness_slot() {
        let mut g = ServingGate::new(
            AttestationGate::new(AttestationConfig {
                quote_ttl: 100,
                grace_ttl: 15,
            }),
            FairnessLimiter::new(10, 10),
            PreemptionScheduler::new(1),
        );
        let candidates = vec![NodeCandidate::new("n1", true)];
        // A P0 fills the single slot.
        assert!(g
            .model_infer(
                &req(1, PriorityClass::Interactive, DataClass::Internal, "a"),
                &candidates,
                0,
                true,
                &FakeExecutor
            )
            .is_admitted());
        // Another P0 can preempt nobody → Shed, and the fairness slot for tenant "b" is released.
        assert_eq!(
            g.model_infer(
                &req(2, PriorityClass::Interactive, DataClass::Internal, "b"),
                &candidates,
                0,
                true,
                &FakeExecutor
            ),
            InferAdmission::Shed
        );
        assert_eq!(
            g.fairness.usage_of(&TenantId::new("b")),
            0,
            "shed request holds no fairness slot"
        );
    }
}
