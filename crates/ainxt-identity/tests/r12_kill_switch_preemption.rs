// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-12 closure of the §19 (c) (LOW) gap — **the workforce-wide kill-switch signals Serving-Ops
//! (ADR-020) to preempt/drain running Program Runs, checkpointing them to `PENDING` (ADR-027 §7).**
//!
//! Before, the kill-switch only denied the *next* issuance/renewal (drain-by-expiry). This adds the
//! "big red button" arm: the AIA kill-switch emits [`PreemptDirective`]s for the Runs already in
//! flight, so a halt reaches them immediately, and a resumable Program Run checkpoints to `PENDING`
//! (loses nothing) rather than being hard-killed. The scheduler that consumes the directives is the
//! injected [`PreemptionSink`] seam (ainxt-serving wires its preemptor behind it — kept acyclic).
//!
//! Fail-before/pass-after: `preemption_directives` / `signal_preemption` / `RunningProgramRun` /
//! `PreemptDirective` / `PreemptionSink` are new this round.

use ainxt_identity::authority::{
    KillScope, KillSwitch, PreemptDirective, PreemptionSink, RunningProgramRun,
};
use ainxt_types::DataClass;

/// A test scheduler standing in for Serving-Ops: records the directives it was signalled.
#[derive(Default)]
struct RecordingScheduler {
    preempted: Vec<PreemptDirective>,
}
impl PreemptionSink for RecordingScheduler {
    fn preempt(&mut self, directive: &PreemptDirective) {
        self.preempted.push(directive.clone());
    }
}

fn running() -> Vec<RunningProgramRun> {
    vec![
        RunningProgramRun {
            run_id: "prog-1".into(),
            def_ref: "def:role/migrator@v1".into(),
            department: Some("payments-eng".into()),
            data_class: DataClass::RegulatedPayment,
            is_program: true, // resumable Program Run -> checkpoints to PENDING
        },
        RunningProgramRun {
            run_id: "chat-9".into(),
            def_ref: "def:role/coder@v3".into(),
            department: Some("platform".into()),
            data_class: DataClass::Internal,
            is_program: false, // transient run -> drains, no checkpoint
        },
    ]
}

#[test]
fn r12_workforce_kill_switch_preempts_all_running_and_checkpoints_programs() {
    let mut ks = KillSwitch::new();
    ks.pull(KillScope::Workforce);
    let mut sched = RecordingScheduler::default();
    let runs = running();
    let directives = ks.signal_preemption(&runs, &mut sched);

    // Every in-flight Run is preempted (the halt reaches them, not only new work).
    assert_eq!(directives.len(), 2);
    assert_eq!(sched.preempted.len(), 2);

    // The resumable Program Run checkpoints to PENDING (loses nothing); the transient run does not.
    let prog = directives.iter().find(|d| d.run_id == "prog-1").unwrap();
    assert!(
        prog.checkpoint_to_pending,
        "a Program Run checkpoints to PENDING"
    );
    assert_eq!(prog.reason, KillScope::Workforce);
    let chat = directives.iter().find(|d| d.run_id == "chat-9").unwrap();
    assert!(!chat.checkpoint_to_pending, "a transient run just drains");
}

#[test]
fn r12_scoped_kill_switch_preempts_only_matching_runs() {
    // Halt only regulated-payment data-class Runs: only prog-1 is preempted; chat-9 keeps running.
    let mut ks = KillSwitch::new();
    ks.pull(KillScope::DataClass(DataClass::RegulatedPayment));
    let directives = ks.preemption_directives(&running());
    assert_eq!(directives.len(), 1);
    assert_eq!(directives[0].run_id, "prog-1");
    assert!(directives[0].checkpoint_to_pending);
    assert_eq!(
        directives[0].reason,
        KillScope::DataClass(DataClass::RegulatedPayment)
    );
}

#[test]
fn r12_no_active_scope_preempts_nothing() {
    let ks = KillSwitch::new();
    assert!(
        ks.preemption_directives(&running()).is_empty(),
        "no halt, no preemption"
    );
}
