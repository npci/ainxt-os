// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Chunk/step-granular preemption of already-running work (SERVING_OPS.md §2 — the core brief).
//!
//! Priority-ordered *admission* alone is not sufficient: once a P1 SDLC request is already inside a
//! running decode batch generating a large diff, a naive scheduler cannot inject a new P0 incident
//! query without waiting for that generation to finish — which can be the full 20 minutes the brief
//! explicitly rules out. This module models the mechanism that actually satisfies "an incident
//! query never queues behind a 20-minute SDLC run":
//!
//! * **Chunked work** — a sequence advances one *chunk* (prefill) / *token step* (decode) at a
//!   time via [`PreemptionScheduler::advance`]. The maximum time any single step can hold up the
//!   batch is bounded to one chunk, regardless of total prompt/generation length.
//! * **Preemption at boundaries** — when a higher-priority request arrives and the pool is full
//!   ([`PreemptionScheduler::admit`]), the scheduler evaluates preemption *now*, at the next
//!   boundary, and admits the arrival **immediately** by evicting the lowest-priority preemptible
//!   incumbent. It never waits for the victim to complete.
//! * **P0 is never a victim** — [`crate::PriorityClass::Interactive`] work is only ever preempted
//!   by nothing; it can only preempt.
//! * **Committed work is preserved** — a preempted sequence keeps its `resume_from` = the units it
//!   had already completed, so it resumes from its last completed step, not from scratch. A **P2**
//!   (Batch/Program) victim checkpoints to `PENDING` and re-queues at the Program Supervisor level
//!   (ADR-027 contract); a **P1** victim's KV pages are marked evicted-but-recoverable and it
//!   resumes locally. The disposition differs by class ([`KvDisposition`]).
//!
//! Pure and deterministic — no clock, no GPU. "One step of delay" is the granularity of an
//! [`PreemptionScheduler::advance`] call; the scheduling decision itself is synchronous.

use std::collections::BTreeMap;

use crate::{PriorityClass, TenantId};

/// The phase a sequence is in — prefill (chunked prompt processing) or decode (per-token
/// generation). Preemption is evaluated at either boundary (SERVING_OPS.md §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Phase {
    Prefill,
    Decode,
}

/// A request to run a sequence on the pool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeqSpec {
    pub id: u64,
    pub priority: PriorityClass,
    pub tenant: TenantId,
    pub phase: Phase,
    /// Total chunks/steps this sequence must complete (informational; drives progress accounting).
    pub total_units: u64,
    /// KV pages this sequence holds (for the evicted-recoverable disposition, §2).
    pub kv_pages: u32,
    /// GAP-FIX identity-payments (gap6 audit item 2) — the identity-plane `run_id` this sequence
    /// serves, when the caller has one (ADR-022 §12's per-Run `AgentWorkloadCredential.run_id`; for a
    /// served `/v1/chat` turn this is the SAME string `chat_identity.rs` mints a credential under —
    /// `req.session`). `None` for a caller with no correlated identity-plane Run (the pre-existing,
    /// unchanged default). This is what lets a kill-switch's [`PreemptDirective`] (keyed on that SAME
    /// `run_id`) find and preempt THIS sequence in the real scheduler — see
    /// [`PreemptionScheduler::force_preempt_by_run_id`].
    pub run_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Running {
    spec: SeqSpec,
    completed_units: u64,
}

/// What happens to a preempted sequence's KV state (SERVING_OPS.md §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KvDisposition {
    /// A P1 victim: KV pages kept evicted-but-recoverable (resident if capacity allows, else
    /// spilled to a fast host tier); resumes from `resume_from`.
    EvictedRecoverable { pages: u32, resume_from: u64 },
    /// A P2 (Program/Batch) victim: checkpointed to `PENDING` and re-queued at the Program
    /// Supervisor level (ADR-027) — the same idempotent-resume contract, not a new one.
    CheckpointedToPending { resume_from: u64 },
}

/// The outcome of an [`PreemptionScheduler::admit`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmitOutcome {
    /// A slot was free; the sequence started with no preemption.
    Started,
    /// The pool was full; a strictly-lower-priority incumbent was preempted at its boundary and the
    /// arrival started in its place — immediately, without waiting for the victim to finish.
    Preempted {
        victim: u64,
        victim_priority: PriorityClass,
        disposition: KvDisposition,
    },
    /// The pool was full and nothing of *lower* priority was preemptible — admitting the arrival
    /// would harm an equal-or-higher-priority incumbent, so the arrival is refused (a P2 arriving
    /// into a pool of P0s, for instance).
    Rejected,
}

/// A misuse of the scheduler state machine, returned rather than panicked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedError {
    /// No running sequence with this id.
    NotRunning,
    /// No preempted sequence with this id to resume.
    NotPreempted,
    /// The id is already live (running or preempted) — ids must be unique.
    DuplicateId,
}

/// A record of a preempted sequence, awaiting resume (SERVING_OPS.md §2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreemptedRecord {
    pub spec: SeqSpec,
    pub resume_from: u64,
    pub disposition: KvDisposition,
}

/// Chunk/step-granular preemptive scheduler for one pool (SERVING_OPS.md §2).
///
/// Holds up to `capacity` concurrently-running sequences plus a set of preempted sequences that can
/// be resumed. Deterministic victim selection: lowest priority first, ties broken by largest id.
#[derive(Debug, Clone)]
pub struct PreemptionScheduler {
    capacity: usize,
    running: BTreeMap<u64, Running>,
    preempted: BTreeMap<u64, PreemptedRecord>,
}

impl PreemptionScheduler {
    pub fn new(capacity: usize) -> Self {
        PreemptionScheduler {
            capacity,
            running: BTreeMap::new(),
            preempted: BTreeMap::new(),
        }
    }

    /// Admit `spec`, preempting a lower-priority incumbent if the pool is full (SERVING_OPS.md §2).
    pub fn admit(&mut self, spec: SeqSpec) -> Result<AdmitOutcome, SchedError> {
        if self.running.contains_key(&spec.id) || self.preempted.contains_key(&spec.id) {
            return Err(SchedError::DuplicateId);
        }
        if self.running.len() < self.capacity {
            self.running.insert(
                spec.id,
                Running {
                    spec,
                    completed_units: 0,
                },
            );
            return Ok(AdmitOutcome::Started);
        }
        // Full: find the lowest-priority incumbent strictly below the arrival (P0 is never a
        // victim because nothing is strictly below it). Ties → largest id, for determinism.
        let victim = self
            .running
            .values()
            .filter(|r| r.spec.priority < spec.priority)
            .min_by(|a, b| {
                a.spec
                    .priority
                    .cmp(&b.spec.priority)
                    .then(b.spec.id.cmp(&a.spec.id))
            })
            .map(|r| r.spec.id);

        let Some(victim_id) = victim else {
            return Ok(AdmitOutcome::Rejected);
        };

        let victim = self.running.remove(&victim_id).expect("victim present");
        let resume_from = victim.completed_units;
        let disposition = match victim.spec.priority {
            PriorityClass::Batch => KvDisposition::CheckpointedToPending { resume_from },
            // Standard (and defensively any non-Batch preemptible class) keeps recoverable KV.
            _ => KvDisposition::EvictedRecoverable {
                pages: victim.spec.kv_pages,
                resume_from,
            },
        };
        self.preempted.insert(
            victim_id,
            PreemptedRecord {
                spec: victim.spec.clone(),
                resume_from,
                disposition,
            },
        );
        self.running.insert(
            spec.id,
            Running {
                spec,
                completed_units: 0,
            },
        );
        Ok(AdmitOutcome::Preempted {
            victim: victim_id,
            victim_priority: victim.spec.priority,
            disposition,
        })
    }

    /// Advance a running sequence by `units` chunks/steps (bounded by its `total_units`). This is
    /// the "one step at a time" granularity that bounds head-of-line blocking. Returns the new
    /// completed count.
    pub fn advance(&mut self, id: u64, units: u64) -> Result<u64, SchedError> {
        let r = self.running.get_mut(&id).ok_or(SchedError::NotRunning)?;
        r.completed_units = r
            .completed_units
            .saturating_add(units)
            .min(r.spec.total_units);
        Ok(r.completed_units)
    }

    /// GAP-FIX identity-payments (gap6 audit item 2) — unconditionally preempt the running sequence
    /// whose [`SeqSpec::run_id`] equals `run_id`, regardless of its [`PriorityClass`] (an authority-
    /// scoped kill-switch halt OUTRANKS admission-priority protection — unlike [`Self::admit`]'s
    /// eviction, which never selects a P0/[`crate::PriorityClass::Interactive`] victim, THIS preempts
    /// one if that is the Run being halted; §19's "big red button" stops in-flight work, full stop).
    /// Same disposition rule as `admit`'s eviction: a [`crate::PriorityClass::Batch`] victim
    /// checkpoints to `PENDING` (ADR-027 §7 resumable-Program contract); anything else keeps
    /// recoverable KV. Idempotent-friendly: `None` if no running sequence carries this `run_id` (already
    /// completed, never admitted, or admitted with no `run_id` at all) — a caller matching
    /// [`PreemptionSink::preempt`]'s doc ("idempotent by `run_id` on the sink side") does not need to
    /// re-check first.
    pub fn force_preempt_by_run_id(&mut self, run_id: &str) -> Option<PreemptedRecord> {
        let victim_id = self
            .running
            .values()
            .find(|r| r.spec.run_id.as_deref() == Some(run_id))
            .map(|r| r.spec.id)?;
        let victim = self.running.remove(&victim_id).expect("victim present");
        let resume_from = victim.completed_units;
        let disposition = match victim.spec.priority {
            PriorityClass::Batch => KvDisposition::CheckpointedToPending { resume_from },
            _ => KvDisposition::EvictedRecoverable {
                pages: victim.spec.kv_pages,
                resume_from,
            },
        };
        let record = PreemptedRecord {
            spec: victim.spec,
            resume_from,
            disposition,
        };
        self.preempted.insert(victim_id, record.clone());
        Some(record)
    }

    /// A running sequence finished normally; free its slot. Returns its final completed count.
    pub fn complete(&mut self, id: u64) -> Result<u64, SchedError> {
        self.running
            .remove(&id)
            .map(|r| r.completed_units)
            .ok_or(SchedError::NotRunning)
    }

    /// Resume a preempted sequence if a slot is free, continuing from its checkpoint. Returns
    /// `Ok(true)` if it resumed, `Ok(false)` if the pool is still full (it stays preempted).
    pub fn resume(&mut self, id: u64) -> Result<bool, SchedError> {
        if !self.preempted.contains_key(&id) {
            return Err(SchedError::NotPreempted);
        }
        if self.running.len() >= self.capacity {
            return Ok(false);
        }
        let rec = self.preempted.remove(&id).expect("preempted present");
        self.running.insert(
            id,
            Running {
                spec: rec.spec,
                completed_units: rec.resume_from,
            },
        );
        Ok(true)
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }
    pub fn running_count(&self) -> usize {
        self.running.len()
    }
    pub fn preempted_count(&self) -> usize {
        self.preempted.len()
    }
    pub fn is_running(&self, id: u64) -> bool {
        self.running.contains_key(&id)
    }
    /// GAP-FIX serving-ops (SERVING_OPS.md §2, gap 6) — every currently-running sequence's id, in
    /// deterministic (id) order. This is the "already in-flight decode work" [`crate::wfq::batch_step`]
    /// needs to interleave a NEW long prefill's chunks against — before this accessor, a caller of
    /// `batch_step` had no way to source that list from the SAME scheduler instance `model_infer`
    /// admits into, so the live continuous-batching step had nothing real to interleave with.
    pub fn running_ids(&self) -> Vec<u64> {
        self.running.keys().copied().collect()
    }
    pub fn preempted(&self, id: u64) -> Option<&PreemptedRecord> {
        self.preempted.get(&id)
    }
    /// Completed units for a running sequence, if present.
    pub fn completed_units(&self, id: u64) -> Option<u64> {
        self.running.get(&id).map(|r| r.completed_units)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(id: u64, p: PriorityClass, total: u64) -> SeqSpec {
        SeqSpec {
            id,
            priority: p,
            tenant: TenantId::new("dept"),
            phase: Phase::Decode,
            total_units: total,
            kv_pages: 4,
            run_id: None,
        }
    }

    fn spec_with_run(id: u64, p: PriorityClass, total: u64, run_id: &str) -> SeqSpec {
        SeqSpec {
            run_id: Some(run_id.to_string()),
            ..spec(id, p, total)
        }
    }

    #[test]
    fn admits_to_capacity_then_preempts_lowest_priority() {
        let mut s = PreemptionScheduler::new(2);
        assert_eq!(
            s.admit(spec(1, PriorityClass::Batch, 100)).unwrap(),
            AdmitOutcome::Started
        );
        assert_eq!(
            s.admit(spec(2, PriorityClass::Standard, 100)).unwrap(),
            AdmitOutcome::Started
        );
        assert_eq!(s.running_count(), 2);
        // A P0 incident arrives into a full pool → the P2 batch (lowest) is preempted, not the P1.
        let out = s.admit(spec(3, PriorityClass::Interactive, 10)).unwrap();
        assert_eq!(
            out,
            AdmitOutcome::Preempted {
                victim: 1,
                victim_priority: PriorityClass::Batch,
                disposition: KvDisposition::CheckpointedToPending { resume_from: 0 },
            }
        );
        assert!(s.is_running(3));
        assert!(!s.is_running(1));
        assert_eq!(s.preempted_count(), 1);
    }

    #[test]
    fn incident_preempts_a_long_running_generation_immediately_preserving_committed_work() {
        // The core brief: a P0 must not wait behind a huge P1 generation.
        let mut s = PreemptionScheduler::new(1);
        s.admit(spec(1, PriorityClass::Standard, 100_000)).unwrap(); // a 20-min-scale SDLC decode
                                                                     // It has generated 37 tokens so far.
        assert_eq!(s.advance(1, 37).unwrap(), 37);
        // Incident arrives. Admitted RIGHT NOW — no waiting for the 99,963 remaining steps.
        let out = s.admit(spec(2, PriorityClass::Interactive, 20)).unwrap();
        match out {
            AdmitOutcome::Preempted {
                victim,
                disposition,
                ..
            } => {
                assert_eq!(victim, 1);
                // P1 victim keeps recoverable KV and resumes from step 37, not from scratch.
                assert_eq!(
                    disposition,
                    KvDisposition::EvictedRecoverable {
                        pages: 4,
                        resume_from: 37
                    }
                );
            }
            other => panic!("expected preemption, got {other:?}"),
        }
        assert!(s.is_running(2));
        assert_eq!(s.preempted(1).unwrap().resume_from, 37);
    }

    #[test]
    fn p0_is_never_a_victim() {
        let mut s = PreemptionScheduler::new(1);
        s.admit(spec(1, PriorityClass::Interactive, 10)).unwrap();
        // Another P0 arrives into a pool holding a P0 → nothing strictly lower → Rejected.
        assert_eq!(
            s.admit(spec(2, PriorityClass::Interactive, 10)).unwrap(),
            AdmitOutcome::Rejected
        );
        assert!(s.is_running(1));
        assert!(!s.is_running(2));
    }

    #[test]
    fn batch_arrival_into_full_higher_priority_pool_is_rejected_not_admitted() {
        let mut s = PreemptionScheduler::new(2);
        s.admit(spec(1, PriorityClass::Interactive, 10)).unwrap();
        s.admit(spec(2, PriorityClass::Standard, 10)).unwrap();
        // A P2 batch job can preempt nobody here → refused, protecting the P0/P1 incumbents.
        assert_eq!(
            s.admit(spec(3, PriorityClass::Batch, 10)).unwrap(),
            AdmitOutcome::Rejected
        );
    }

    #[test]
    fn preempts_lowest_priority_first_when_multiple_lower_present() {
        let mut s = PreemptionScheduler::new(2);
        s.admit(spec(1, PriorityClass::Standard, 10)).unwrap();
        s.admit(spec(2, PriorityClass::Batch, 10)).unwrap();
        // P0 arrives → must evict the P2 batch (id 2), never the P1.
        let out = s.admit(spec(3, PriorityClass::Interactive, 10)).unwrap();
        match out {
            AdmitOutcome::Preempted {
                victim,
                victim_priority,
                ..
            } => {
                assert_eq!(victim, 2);
                assert_eq!(victim_priority, PriorityClass::Batch);
            }
            other => panic!("expected batch preemption, got {other:?}"),
        }
        assert!(s.is_running(1), "the P1 keeps running");
    }

    #[test]
    fn victim_tie_breaks_deterministically_by_largest_id() {
        let mut s = PreemptionScheduler::new(2);
        s.admit(spec(5, PriorityClass::Batch, 10)).unwrap();
        s.admit(spec(9, PriorityClass::Batch, 10)).unwrap();
        // Two equal-lowest incumbents → deterministic: evict the larger id (9).
        let out = s.admit(spec(1, PriorityClass::Standard, 10)).unwrap();
        match out {
            AdmitOutcome::Preempted { victim, .. } => assert_eq!(victim, 9),
            other => panic!("expected preemption, got {other:?}"),
        }
    }

    #[test]
    fn resume_continues_from_checkpoint_when_a_slot_frees() {
        let mut s = PreemptionScheduler::new(1);
        s.admit(spec(1, PriorityClass::Standard, 100)).unwrap();
        s.advance(1, 40).unwrap();
        s.admit(spec(2, PriorityClass::Interactive, 10)).unwrap(); // preempts 1 at 40
        assert!(!s.is_running(1));
        // While the P0 runs, resume is refused (pool full).
        assert!(!s.resume(1).unwrap());
        // P0 finishes → a slot frees → the P1 resumes from step 40, not 0.
        s.complete(2).unwrap();
        assert!(s.resume(1).unwrap());
        assert_eq!(s.completed_units(1), Some(40));
        // And it can make further progress.
        assert_eq!(s.advance(1, 5).unwrap(), 45);
    }

    #[test]
    fn advance_is_bounded_by_total_units() {
        let mut s = PreemptionScheduler::new(1);
        s.admit(spec(1, PriorityClass::Batch, 3)).unwrap();
        assert_eq!(s.advance(1, 100).unwrap(), 3, "cannot exceed total_units");
    }

    #[test]
    fn duplicate_id_is_rejected() {
        let mut s = PreemptionScheduler::new(4);
        s.admit(spec(1, PriorityClass::Standard, 10)).unwrap();
        assert_eq!(
            s.admit(spec(1, PriorityClass::Standard, 10)),
            Err(SchedError::DuplicateId)
        );
    }

    #[test]
    fn state_errors_are_returned_not_panicked() {
        let mut s = PreemptionScheduler::new(1);
        assert_eq!(s.advance(99, 1), Err(SchedError::NotRunning));
        assert_eq!(s.complete(99), Err(SchedError::NotRunning));
        assert_eq!(s.resume(99), Err(SchedError::NotPreempted));
    }

    // ---- GAP-FIX identity-payments (gap6 audit item 2): kill-switch-driven forced preemption -------

    #[test]
    fn force_preempt_by_run_id_evicts_regardless_of_priority() {
        let mut s = PreemptionScheduler::new(2);
        // A P0/Interactive Run — `admit`'s own eviction would NEVER select this as a victim, but an
        // authority-scoped kill-switch halt must still be able to stop it.
        s.admit(spec_with_run(
            1,
            PriorityClass::Interactive,
            100,
            "run-halt-me",
        ))
        .unwrap();
        s.admit(spec(2, PriorityClass::Standard, 100)).unwrap();
        s.advance(1, 7).unwrap();

        let rec = s
            .force_preempt_by_run_id("run-halt-me")
            .expect("the matching running sequence is force-preempted");
        assert_eq!(
            rec.resume_from, 7,
            "committed progress is preserved, not lost"
        );
        assert_eq!(
            rec.disposition,
            KvDisposition::EvictedRecoverable {
                pages: 4,
                resume_from: 7
            }
        );
        assert!(
            !s.is_running(1),
            "the halted Run's sequence must no longer be running"
        );
        assert!(s.is_running(2), "an unrelated sequence must be unaffected");
        assert_eq!(s.preempted(1).unwrap().resume_from, 7);
    }

    #[test]
    fn force_preempt_by_run_id_checkpoints_a_batch_program_to_pending() {
        let mut s = PreemptionScheduler::new(1);
        s.admit(spec_with_run(
            1,
            PriorityClass::Batch,
            100,
            "run-program-halt",
        ))
        .unwrap();
        s.advance(1, 30).unwrap();
        let rec = s.force_preempt_by_run_id("run-program-halt").unwrap();
        assert_eq!(
            rec.disposition,
            KvDisposition::CheckpointedToPending { resume_from: 30 },
            "a resumable Program Run checkpoints to PENDING (ADR-027 §7), never merely evicted-KV"
        );
    }

    #[test]
    fn force_preempt_by_run_id_is_none_when_no_match() {
        let mut s = PreemptionScheduler::new(2);
        // No run_id at all (the pre-existing, unchanged default shape).
        s.admit(spec(1, PriorityClass::Standard, 10)).unwrap();
        assert_eq!(s.force_preempt_by_run_id("run-does-not-exist"), None);
        assert!(
            s.is_running(1),
            "an unmatched preempt call must not disturb unrelated sequences"
        );
    }
}
