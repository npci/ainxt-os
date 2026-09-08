// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-12 Serving-Ops gap-8 (LOW) — the §2 chunked-prefill interleaving and §2/§4 drain-disposition
//! pure functions now have a LIVE batch/drain DRIVER: one steps the batch (interleave + advance each
//! decode a token through the scheduler), the other maps a preempted sequence's KV disposition to the
//! concrete drain action a supervisor executes.
//!
//! The audit found `interleave_prefill` and the preemption dispositions were pure functions nothing
//! stepped on a real batch or actioned on a drain. This closes the orchestration
//! ([`batch_step`] / [`drain_dispositions`]); the physical GPU batch executor is the infra seam.
//!
//! Fail-before: `batch_step`/`drain_dispositions`/`BatchStep`/`DrainAction` did not exist. Pass-after:
//! a batch step interleaves a long prefill with running decodes and advances each decoded sequence,
//! and a preemption's disposition drives the correct drain action (P1 recoverable resume vs P2
//! checkpoint-to-PENDING).

use ainxt_serving::preemption::{AdmitOutcome, Phase, PreemptionScheduler, SeqSpec};
use ainxt_serving::wfq::{batch_step, drain_dispositions, DrainAction, Slice};
use ainxt_serving::{PriorityClass, TenantId};

fn spec(id: u64, priority: PriorityClass, kv_pages: u32) -> SeqSpec {
    SeqSpec {
        id,
        priority,
        tenant: TenantId::new("dept"),
        phase: Phase::Prefill,
        total_units: 1_000,
        kv_pages,
        run_id: None,
    }
}

#[test]
fn r12_batch_step_interleaves_prefill_and_advances_running_decodes() {
    // Two running decode sequences on a 4-slot pool.
    let mut sched = PreemptionScheduler::new(4);
    assert_eq!(
        sched.admit(spec(7, PriorityClass::Standard, 2)).unwrap(),
        AdmitOutcome::Started
    );
    assert_eq!(
        sched.admit(spec(8, PriorityClass::Standard, 2)).unwrap(),
        AdmitOutcome::Started
    );

    // One batch step interleaving a 5-chunk incoming prefill with the two running decodes.
    let step = batch_step(&mut sched, &[7, 8], 5);

    // Every prefill chunk was scheduled, and the interleave bounds head-of-line blocking: the first
    // slice is a decode step, the second a prefill chunk (a decode always precedes a chunk while
    // decodes remain).
    assert_eq!(
        step.prefill_chunks_run, 5,
        "all prefill chunks run this step"
    );
    assert_eq!(step.schedule[0], Slice::DecodeStep { seq_id: 7 });
    assert_eq!(step.schedule[1], Slice::PrefillChunk { chunk_index: 0 });

    // Each running decode was ADVANCED through the scheduler (progress is real, not just planned).
    assert!(step.decodes_advanced.contains(&7) && step.decodes_advanced.contains(&8));
    assert!(
        sched.completed_units(7).unwrap() >= 1,
        "seq 7 advanced at least one token"
    );
    assert!(
        sched.completed_units(8).unwrap() >= 1,
        "seq 8 advanced at least one token"
    );
}

#[test]
fn r12_drain_disposition_driver_maps_p1_recoverable_and_p2_checkpoint() {
    // Capacity 1 so an arrival must preempt to run — exercising both disposition classes.
    // (a) A P1 (Standard) incumbent preempted by a P0 → EvictedRecoverable disposition.
    let mut s1 = PreemptionScheduler::new(1);
    s1.admit(spec(1, PriorityClass::Standard, 6)).unwrap();
    match s1.admit(spec(2, PriorityClass::Interactive, 0)).unwrap() {
        AdmitOutcome::Preempted { victim, .. } => assert_eq!(victim, 1),
        other => panic!("expected preemption, got {other:?}"),
    }
    let actions = drain_dispositions(&s1, &[1]);
    assert_eq!(
        actions,
        vec![DrainAction::ResumeRecoverable {
            seq_id: 1,
            pages: 6,
            resume_from: 0
        }],
        "P1 victim's recoverable KV drives a resume-in-place action"
    );

    // (b) A P2 (Batch) incumbent preempted by a P0 → CheckpointedToPending disposition.
    let mut s2 = PreemptionScheduler::new(1);
    s2.admit(spec(10, PriorityClass::Batch, 8)).unwrap();
    assert!(matches!(
        s2.admit(spec(11, PriorityClass::Interactive, 0)).unwrap(),
        AdmitOutcome::Preempted { victim: 10, .. }
    ));
    let actions = drain_dispositions(&s2, &[10]);
    assert_eq!(
        actions,
        vec![DrainAction::RequeuePending {
            seq_id: 10,
            resume_from: 0
        }],
        "P2 victim is checkpointed to PENDING for supervisor re-queue"
    );

    // An id with no preempted record is skipped (already resumed / never preempted) — no panic.
    assert!(drain_dispositions(&s2, &[9999]).is_empty());
}
