// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-9 — the served driver LOOP over the [`Program`] enforcement API
//! (`ainxt_planner::driver::drive_program_verified`).
//!
//! Proves the three round-9 requirements on the DRIVER the served path hot-wires:
//!  1. three-way verification uses a REAL (injected) semantic-Judge seam — a stubbed-fail proof
//!     BLOCKS the commit (the node never advances to Committed, the program never `Completed`);
//!  2. program-scale verification (per-edge integration + regression sweep + program Judge) runs
//!     BEFORE a program is declared `Completed` — a red edge/sweep/program-judge blocks completion
//!     even when every module committed;
//!  3. a user-stop cancellation signal propagates into the executing loop and halts an in-flight run
//!     promptly — the run stops mid-flight without committing a half-verified node.

use ainxt_planner::driver::{
    drive_program_verified, DriverModuleContext, ModuleAttempt, ModuleExecutor, ModuleJudge,
    StopSignal,
};
use ainxt_planner::program::{NodeClass, NodeDecl, NodeId, ProgramId, ProgramOutcome};
use ainxt_planner::supervisor::ProgramVerifier;
use ainxt_planner::verify::{AdversarialVerdict, DeterministicVerdict, GateOutcome, JudgeVerdict};

// ---- fakes ---------------------------------------------------------------

/// An executor that produces a clean, engine-derived module artifact every time.
struct GreenExecutor {
    calls: u32,
}
impl ModuleExecutor for GreenExecutor {
    fn execute(&mut self, ctx: &DriverModuleContext, _stop: &StopSignal) -> ModuleAttempt {
        self.calls += 1;
        ModuleAttempt::Ran {
            det: DeterministicVerdict::green(),
            adv: AdversarialVerdict::green(10),
            commit_shas: vec![format!("sha-{}", ctx.node)],
            ledger_key: format!("k-{}-{}", ctx.node, ctx.attempt),
            by_model: "producer-model".into(),
        }
    }
}

/// A model-backed Judge stub that ALWAYS returns a below-threshold verdict — a stubbed-fail proof.
struct FailJudge;
impl ModuleJudge for FailJudge {
    fn judge(&mut self, _ctx: &DriverModuleContext, _a: &ModuleAttempt) -> JudgeVerdict {
        // Cross-model (so the failure is the SCORE, not the structural cross-model rule) but below
        // threshold — the semantic proof is red.
        JudgeVerdict::pass(40, 80, "producer-model", "judge-model")
    }
}

/// A model-backed Judge stub that passes cross-model at/above threshold.
struct GreenJudge;
impl ModuleJudge for GreenJudge {
    fn judge(&mut self, _ctx: &DriverModuleContext, _a: &ModuleAttempt) -> JudgeVerdict {
        JudgeVerdict::pass(92, 80, "producer-model", "judge-model")
    }
}

/// A program-scale verifier whose edges + sweep are green and whose program Judge passes cross-model.
struct GreenVerifier;
impl ProgramVerifier for GreenVerifier {
    fn verify_edge(&mut self, _c: &NodeId, _n: &NodeId) -> GateOutcome {
        GateOutcome::Complete
    }
    fn regression_sweep(&mut self, _c: &[NodeId]) -> GateOutcome {
        GateOutcome::Complete
    }
    fn program_judge(&mut self) -> JudgeVerdict {
        JudgeVerdict::pass(95, 80, "producer-model", "judge-model")
    }
}

/// A program-scale verifier whose per-edge integration is always RED.
struct RedEdgeVerifier;
impl ProgramVerifier for RedEdgeVerifier {
    fn verify_edge(&mut self, _c: &NodeId, _n: &NodeId) -> GateOutcome {
        GateOutcome::Blocked {
            reasons: vec!["integration contract broken across the seam".into()],
        }
    }
    fn regression_sweep(&mut self, _c: &[NodeId]) -> GateOutcome {
        GateOutcome::Complete
    }
    fn program_judge(&mut self) -> JudgeVerdict {
        JudgeVerdict::pass(95, 80, "producer-model", "judge-model")
    }
}

fn chain2() -> Vec<NodeDecl> {
    vec![
        NodeDecl::new("a", NodeClass::MigrationRun),
        NodeDecl::new("b", NodeClass::MigrationRun).depends_on("a"),
    ]
}

fn nid(s: &str) -> NodeId {
    NodeId::new(s)
}

// ---- req 1: a stubbed-fail proof blocks the commit -----------------------

#[test]
fn r9_stubbed_fail_proof_blocks_commit() {
    let mut exec = GreenExecutor { calls: 0 };
    let mut judge = FailJudge; // the semantic proof is red
    let mut ver = GreenVerifier;
    let stop = StopSignal::new();

    let report = drive_program_verified(
        ProgramId::new("prog-fail"),
        "migrate the switch",
        chain2(),
        &mut exec,
        &mut judge,
        &mut ver,
        &stop,
        2, // attempt cap
    )
    .unwrap();

    // The engine produced clean artifacts, but the Judge proof failed -> NOTHING committed.
    assert!(
        report.committed.is_empty(),
        "a failing three-way proof must block every commit; committed={:?}",
        report.committed
    );
    // The node never reached a durable Complete proof.
    assert!(!report.program.is_proven(&nid("a")));
    // The program is an honest CappedPartial, never a fabricated Completed.
    assert_eq!(report.outcome, ProgramOutcome::CappedPartial);
    assert!(!report.gate.is_complete());
    // The node WAS attempted up to the cap (proof recomputed each time), never silently advanced.
    assert!(exec.calls >= 1);
}

// ---- baseline: with a real green judge the same program DOES complete ----

#[test]
fn r9_green_judge_completes_when_all_proofs_pass() {
    let mut exec = GreenExecutor { calls: 0 };
    let mut judge = GreenJudge;
    let mut ver = GreenVerifier;
    let stop = StopSignal::new();

    let report = drive_program_verified(
        ProgramId::new("prog-ok"),
        "migrate the switch",
        chain2(),
        &mut exec,
        &mut judge,
        &mut ver,
        &stop,
        2,
    )
    .unwrap();

    assert_eq!(report.outcome, ProgramOutcome::Completed);
    assert!(report.gate.is_complete());
    assert_eq!(report.committed, vec![nid("a"), nid("b")]);
    assert!(report.program.state().committed_nodes_are_all_proven());
}

// ---- req 2: program-scale verification runs before Completed -------------

#[test]
fn r9_program_scale_red_edge_blocks_completion_though_every_module_committed() {
    let mut exec = GreenExecutor { calls: 0 };
    let mut judge = GreenJudge; // every per-module gate is green -> every node commits
    let mut ver = RedEdgeVerifier; // but the integration seam is red
    let stop = StopSignal::new();

    let report = drive_program_verified(
        ProgramId::new("prog-rededge"),
        "migrate the switch",
        chain2(),
        &mut exec,
        &mut judge,
        &mut ver,
        &stop,
        2,
    )
    .unwrap();

    // Every module committed (the per-module three-way gate was green)...
    assert_eq!(report.committed, vec![nid("a"), nid("b")]);
    // ...yet the PROGRAM is not Completed: the program-scale per-edge integration proof is red.
    assert_eq!(report.outcome, ProgramOutcome::CappedPartial);
    assert!(!report.gate.is_complete());
    match &report.gate {
        GateOutcome::Blocked { reasons } => {
            assert!(
                reasons.iter().any(|r| r.contains("edge-not-complete")),
                "expected an edge-not-complete reason, got {reasons:?}"
            );
        }
        other => panic!("expected Blocked program-scale gate, got {other:?}"),
    }
}

// ---- req 3: a user-stop halts an in-flight run promptly ------------------

/// An executor that trips the user-stop signal DURING its first module turn (an in-flight stop) and
/// records how many module turns it was asked to drive.
struct StopMidRunExecutor {
    stop: StopSignal,
    calls: u32,
}
impl ModuleExecutor for StopMidRunExecutor {
    fn execute(&mut self, ctx: &DriverModuleContext, stop: &StopSignal) -> ModuleAttempt {
        self.calls += 1;
        // Simulate the user pressing stop while this module turn is in flight.
        self.stop.stop();
        assert!(
            stop.is_stopped(),
            "the stop signal propagated into the executor"
        );
        ModuleAttempt::Ran {
            det: DeterministicVerdict::green(),
            adv: AdversarialVerdict::green(10),
            commit_shas: vec![format!("sha-{}", ctx.node)],
            ledger_key: format!("k-{}", ctx.node),
            by_model: "producer-model".into(),
        }
    }
}

#[test]
fn r9_mid_run_stop_halts_promptly() {
    let stop = StopSignal::new();
    let mut exec = StopMidRunExecutor {
        stop: stop.clone(),
        calls: 0,
    };
    let mut judge = GreenJudge;
    let mut ver = GreenVerifier;

    // A 3-node chain — without a stop all three would commit and the program would Complete.
    let nodes = vec![
        NodeDecl::new("a", NodeClass::MigrationRun),
        NodeDecl::new("b", NodeClass::MigrationRun).depends_on("a"),
        NodeDecl::new("c", NodeClass::MigrationRun).depends_on("b"),
    ];

    let report = drive_program_verified(
        ProgramId::new("prog-stop"),
        "migrate the switch",
        nodes,
        &mut exec,
        &mut judge,
        &mut ver,
        &stop,
        2,
    )
    .unwrap();

    // The in-flight stop halted the run BEFORE the half-verified node was committed.
    assert!(report.stopped, "the run must report a user-stop halt");
    assert!(
        report.committed.is_empty(),
        "an in-flight stop must not commit a half-verified node; committed={:?}",
        report.committed
    );
    // Only ONE module turn was driven — the loop did not schedule the remaining nodes after the stop.
    assert_eq!(exec.calls, 1, "no further modules run after a user-stop");
    // A stopped run is an honest CappedPartial, never a fabricated Completed.
    assert_eq!(report.outcome, ProgramOutcome::CappedPartial);
    assert!(!report.gate.is_complete());
}
