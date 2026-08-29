// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-11 — the long-horizon **verified Program path**: durability+resume, the COMPLETED gate on the
//! durable path, the independent cross-model semantic Judge, and parallel fan-out of independent nodes.
//!
//! Closes (LONG_HORIZON §4/§6/§7, LOOP §3/§5):
//!  * **Durability + resume on the verified path** — a run stopped mid-flight leaves a NON-terminal
//!    durable log; [`resume_program_verified`] rebuilds from that log and continues WITHOUT re-executing
//!    any already-committed module (its durable three-way proof survives).
//!  * **The durable path actually verifies** — a resumed run reaches `Completed` only through the
//!    program-scale `COMPLETED` gate, and every committed node carries a durable `Complete` proof.
//!  * **Independent cross-model Judge** — a SAME-model producer/judge pairing structurally BLOCKS the
//!    commit even at a perfect (100) score; nothing commits, the program is an honest `CappedPartial`.
//!  * **Parallel fan-out** — independent `Ready` nodes are admitted together in one wave, and the
//!    fan-out driver completes a diamond graph.
//!
//! Each is fail-before/pass-after: the entrypoints (`drive_program_verified_resumable`,
//! `resume_program_verified`, `drive_program_verified_fanout`, `Program::actionable_wave`) did not exist
//! before round-11, so these tests could not compile — they exercise the new, real capability.

use ainxt_planner::driver::{
    drive_program_verified, drive_program_verified_fanout, drive_program_verified_resumable,
    resume_program_verified, DriverModuleContext, ModuleAttempt, ModuleExecutor, ModuleJudge,
    Program, StopSignal,
};
use ainxt_planner::program::{NodeClass, NodeDecl, NodeId, ProgramId, ProgramOutcome};
use ainxt_planner::supervisor::ProgramVerifier;
use ainxt_planner::verify::{AdversarialVerdict, DeterministicVerdict, GateOutcome, JudgeVerdict};

// ---- shared fakes --------------------------------------------------------

/// Produces a clean engine-derived artifact for every module, counting the module turns it drove.
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

/// Runs green EXCEPT it trips the shared user-stop while executing node `b` (an in-flight stop) so the
/// run halts after `a` has committed but before `b` is verified/committed.
struct StopOnNodeExecutor {
    stop: StopSignal,
    stop_at: NodeId,
    calls: u32,
}
impl ModuleExecutor for StopOnNodeExecutor {
    fn execute(&mut self, ctx: &DriverModuleContext, _stop: &StopSignal) -> ModuleAttempt {
        self.calls += 1;
        if ctx.node == self.stop_at {
            self.stop.stop();
            return ModuleAttempt::Failed {
                reason: "user-stop tripped mid-turn".into(),
            };
        }
        ModuleAttempt::Ran {
            det: DeterministicVerdict::green(),
            adv: AdversarialVerdict::green(10),
            commit_shas: vec![format!("sha-{}", ctx.node)],
            ledger_key: format!("k-{}", ctx.node),
            by_model: "producer-model".into(),
        }
    }
}

struct GreenJudge;
impl ModuleJudge for GreenJudge {
    fn judge(&mut self, _c: &DriverModuleContext, _a: &ModuleAttempt) -> JudgeVerdict {
        JudgeVerdict::pass(92, 80, "producer-model", "judge-model")
    }
}

/// A SAME-model judge: producer == judge, at a PERFECT score. The three-way gate must reject it on the
/// structural cross-model rule (§10), not the score.
struct SameModelJudge;
impl ModuleJudge for SameModelJudge {
    fn judge(&mut self, _c: &DriverModuleContext, _a: &ModuleAttempt) -> JudgeVerdict {
        JudgeVerdict::pass(100, 80, "producer-model", "producer-model")
    }
}

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

fn nid(s: &str) -> NodeId {
    NodeId::new(s)
}

fn chain3() -> Vec<NodeDecl> {
    vec![
        NodeDecl::new("a", NodeClass::MigrationRun),
        NodeDecl::new("b", NodeClass::MigrationRun).depends_on("a"),
        NodeDecl::new("c", NodeClass::MigrationRun).depends_on("b"),
    ]
}

fn diamond() -> Vec<NodeDecl> {
    vec![
        NodeDecl::new("a", NodeClass::MigrationRun),
        NodeDecl::new("b", NodeClass::MigrationRun).depends_on("a"),
        NodeDecl::new("c", NodeClass::MigrationRun).depends_on("a"),
        NodeDecl::new("d", NodeClass::MigrationRun)
            .depends_on("b")
            .depends_on("c"),
    ]
}

// ---- gaps 1+2: durability + resume on the verified path, which actually verifies ----

#[test]
fn r11_verified_resume_continues_without_reexecuting_committed_work() {
    let stop = StopSignal::new();
    let mut exec = StopOnNodeExecutor {
        stop: stop.clone(),
        stop_at: nid("b"),
        calls: 0,
    };
    let mut judge = GreenJudge;
    let mut ver = GreenVerifier;

    // First run: resumable drive halts mid-flight at b. a commits; the log is left NON-terminal.
    let first = drive_program_verified_resumable(
        ProgramId::new("prog-resume"),
        "migrate the settlement switch",
        chain3(),
        &mut exec,
        &mut judge,
        &mut ver,
        &stop,
        3,
    )
    .unwrap();

    assert!(first.stopped, "the run halted on the in-flight user-stop");
    assert_eq!(
        first.committed,
        vec![nid("a")],
        "only a committed before the stop"
    );
    // Resumable: the durable log was NOT sealed with a terminal Outcome, so it can be continued.
    assert!(
        !first.program.state().phase.is_terminal(),
        "a stopped resumable run leaves the program non-terminal"
    );

    // Persist → resume purely from the durable log with a FRESH executor + a fresh (un-tripped) stop.
    let log = first.program.log().to_vec();
    let fresh_stop = StopSignal::new();
    let mut exec2 = GreenExecutor { calls: 0 };
    let mut judge2 = GreenJudge;
    let mut ver2 = GreenVerifier;
    let resumed =
        resume_program_verified(&log, &mut exec2, &mut judge2, &mut ver2, &fresh_stop, 3).unwrap();

    // The durable path actually verifies to completion — only through the program-scale gate.
    assert_eq!(resumed.outcome, ProgramOutcome::Completed);
    assert!(
        resumed.gate.is_complete(),
        "COMPLETED gate must be green on the durable path"
    );
    assert_eq!(resumed.committed, vec![nid("a"), nid("b"), nid("c")]);
    assert!(
        resumed.program.state().committed_nodes_are_all_proven(),
        "every committed node carries a durable Complete three-way proof after resume"
    );
    // a was committed in the FIRST run and is NOT re-executed on resume: only b and c drive a turn.
    assert_eq!(
        exec2.calls, 2,
        "resume must not re-execute committed work; only b and c ran"
    );
    // a's single durable commit is preserved (idempotent resume — no double commit).
    let a_commits = log_committed_count(resumed.program.log(), &nid("a"));
    assert_eq!(a_commits, 1);
}

fn log_committed_count(log: &[ainxt_planner::program::ProgramEvent], node: &NodeId) -> usize {
    use ainxt_planner::program::ProgramEvent;
    log.iter()
        .filter(|e| matches!(e, ProgramEvent::NodeCommitted { node: n, .. } if n == node))
        .count()
}

// ---- gap 3: independent cross-model semantic Judge on the served path ----

#[test]
fn r11_same_model_judge_blocks_commit_even_at_a_perfect_score() {
    let mut exec = GreenExecutor { calls: 0 };
    let mut judge = SameModelJudge; // producer == judge, score 100
    let mut ver = GreenVerifier;
    let stop = StopSignal::new();

    let report = drive_program_verified(
        ProgramId::new("prog-samemodel"),
        "migrate the switch",
        vec![
            NodeDecl::new("a", NodeClass::MigrationRun),
            NodeDecl::new("b", NodeClass::MigrationRun).depends_on("a"),
        ],
        &mut exec,
        &mut judge,
        &mut ver,
        &stop,
        2,
    )
    .unwrap();

    // A same-model judge is a STRUCTURAL blind spot (§10) — the perfect score cannot rescue it.
    assert!(
        report.committed.is_empty(),
        "a same-model producer/judge pairing must block every commit; committed={:?}",
        report.committed
    );
    assert!(!report.program.is_proven(&nid("a")));
    assert_eq!(report.outcome, ProgramOutcome::CappedPartial);
    assert!(!report.gate.is_complete());
}

// ---- gap 4: parallel fan-out of independent nodes/branches ----

#[test]
fn r11_independent_nodes_are_admitted_together_in_one_wave() {
    // Manually drive `a` to Committed through the enforcement API, then the two independent branches
    // b and c must BOTH become schedulable in a single wave (LONG_HORIZON §7 fan-out).
    let mut program = Program::start(ProgramId::new("prog-wave"), "migrate").unwrap();
    program.decompose(diamond()).unwrap();
    program.approve("driver").unwrap();

    // Only `a` is schedulable at the start.
    assert_eq!(program.actionable_wave(8), vec![nid("a")]);

    program.begin_node(&nid("a")).unwrap();
    let gate = program
        .record_verdict(
            &nid("a"),
            DeterministicVerdict::green(),
            AdversarialVerdict::green(10),
            JudgeVerdict::pass(90, 80, "producer-model", "judge-model"),
        )
        .unwrap();
    assert!(gate.is_complete());
    program
        .commit_node(&nid("a"), vec!["sha-a".into()], "k-a", "producer-model")
        .unwrap();

    // After a commits, b and c are BOTH admissible in one wave — independent branches, real parallelism.
    assert_eq!(program.actionable_wave(8), vec![nid("b"), nid("c")]);
    // A ceiling of 1 still narrows the wave to one node (bounded fan-out).
    assert_eq!(program.actionable_wave(1), vec![nid("b")]);
    // d is NOT yet admissible (it depends on both b and c).
    assert!(!program.actionable_wave(8).contains(&nid("d")));
}

#[test]
fn r11_fanout_driver_completes_a_diamond_graph() {
    let mut exec = GreenExecutor { calls: 0 };
    let mut judge = GreenJudge;
    let mut ver = GreenVerifier;
    let stop = StopSignal::new();

    let report = drive_program_verified_fanout(
        ProgramId::new("prog-diamond"),
        "migrate the settlement switch",
        diamond(),
        &mut exec,
        &mut judge,
        &mut ver,
        &stop,
        2,
        8, // fan-out ceiling admits both branches at once
    )
    .unwrap();

    assert_eq!(report.outcome, ProgramOutcome::Completed);
    assert!(report.gate.is_complete());
    assert_eq!(
        report.committed,
        vec![nid("a"), nid("b"), nid("c"), nid("d")]
    );
    assert_eq!(exec.calls, 4, "every module drove exactly one turn");
    assert!(report.program.state().committed_is_dependency_closed());
}
