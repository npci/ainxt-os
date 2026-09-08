// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-15 (`loop-teams-longhorizon` gap: "Durable single-module rollback + dependent cascade and
//! poison-node quarantine + route-around", ADR-027 §9) — the served/live [`driver`] path.
//!
//! Before this round, `ainxt_planner::supervisor::run_program` (the batch driver) already had §9
//! (durable quarantine + rollback-on-red), but `ainxt_planner::driver` — the LIVE, resumable API the
//! served daemon actually hot-wires (`drive_program_verified`/`drive_program_verified_reopening`) —
//! did not: a poison node was only skipped via an in-memory `BTreeSet`, never durably quarantined
//! (`ProgramEvent::Quarantined` never emitted, dependents never gated to `BlockedOnHuman`), and a
//! just-committed node whose integration edge went red was simply left `Committed` with the red edge
//! only surfacing at the very final program-scale gate — no rollback, no re-attempt.
//!
//! Fail-before: [`Program::quarantine_node`]/[`Program::rollback_node`] and
//! [`drive_program_verified_reopening`] did not exist before this round, so a poison node's state
//! never advanced past `Pending` and a red-edge commit was never reverted. Pass-after: both are real,
//! durable, Event-Log-recorded transitions this test observes directly on [`Program::log`].

use ainxt_planner::driver::{
    drive_program_verified, drive_program_verified_reopening, DriverModuleContext, ModuleAttempt,
    ModuleExecutor, ModuleJudge, StopSignal,
};
use ainxt_planner::program::{
    NodeClass, NodeDecl, NodeId, NodeState, ProgramEvent, ProgramOutcome,
};
use ainxt_planner::supervisor::ProgramVerifier;
use ainxt_planner::verify::{AdversarialVerdict, DeterministicVerdict, GateOutcome, JudgeVerdict};

fn nid(s: &str) -> NodeId {
    NodeId::new(s)
}

struct GreenJudge;
impl ModuleJudge for GreenJudge {
    fn judge(&mut self, _c: &DriverModuleContext, _a: &ModuleAttempt) -> JudgeVerdict {
        JudgeVerdict::pass(92, 80, "producer-model", "judge-model")
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

// ---- gap 1: poison-node quarantine + route-around is DURABLE, not an in-memory skip -------------

/// Node `a` always fails; `b` depends on `a` (never runnable); independent `d` is unrelated and
/// green. `a` must exhaust the attempt cap and be DURABLY quarantined (`FailedIsolated` on the
/// projected state + a `Quarantined` event on the log), `b` durably gated to `BlockedOnHuman`, and
/// `d` — an independent branch — must complete despite `a`'s poisoning (route-around).
struct PoisonExceptExecutor;
impl ModuleExecutor for PoisonExceptExecutor {
    fn execute(&mut self, ctx: &DriverModuleContext, _stop: &StopSignal) -> ModuleAttempt {
        if ctx.node == nid("a") {
            return ModuleAttempt::Failed {
                reason: "a always fails".into(),
            };
        }
        ModuleAttempt::Ran {
            det: DeterministicVerdict::green(),
            adv: AdversarialVerdict::green(5),
            commit_shas: vec![format!("sha-{}", ctx.node)],
            ledger_key: format!("k-{}-{}", ctx.node, ctx.attempt),
            by_model: "producer-model".into(),
        }
    }
}

#[test]
fn r15_poison_node_durably_quarantined_and_dependents_route_around() {
    let mut exec = PoisonExceptExecutor;
    let mut judge = GreenJudge;
    let mut ver = GreenVerifier;
    let stop = StopSignal::new();

    let nodes = vec![
        NodeDecl::new("a", NodeClass::MigrationRun),
        NodeDecl::new("b", NodeClass::MigrationRun).depends_on("a"),
        NodeDecl::new("d", NodeClass::MigrationRun), // independent
    ];

    let report = drive_program_verified(
        ainxt_planner::program::ProgramId::new("prog-poison"),
        "migrate the switch",
        nodes,
        &mut exec,
        &mut judge,
        &mut ver,
        &stop,
        2, // attempt cap
    )
    .unwrap();

    // The program is an honest CappedPartial (a never committed) — never a fabricated Completed.
    assert_eq!(report.outcome, ProgramOutcome::CappedPartial);

    // Gap 1a: `a` is DURABLY quarantined — a real `FailedIsolated` projected state, not merely
    // skipped in an in-memory set that leaves the durable state at `Pending` forever.
    assert_eq!(
        report.program.state().nodes.get(&nid("a")).map(|n| n.state),
        Some(NodeState::FailedIsolated)
    );
    assert!(
        report
            .program
            .log()
            .iter()
            .any(|e| matches!(e, ProgramEvent::Quarantined { node } if *node == nid("a"))),
        "a Quarantined event must be durably appended to the log"
    );

    // Gap 1b: `b` (a`'s dependent) is durably gated, not merely never-scheduled.
    assert_eq!(
        report.program.state().nodes.get(&nid("b")).map(|n| n.state),
        Some(NodeState::BlockedOnHuman)
    );

    // Gap 1c: route-around — the independent branch `d` completes despite `a`'s poisoning.
    assert!(report.committed.contains(&nid("d")));
    assert!(report.program.is_proven(&nid("d")));
}

// ---- gap 2: durable single-module rollback + dependent cascade on a red integration edge --------

/// `verify_edge` is red exactly once (b's first integration check against already-committed `a`),
/// then green forever after — modeling "the first attempt broke the contract; the retry fixes it".
struct RedOnceThenGreenVerifier {
    edge_calls: u32,
}
impl ProgramVerifier for RedOnceThenGreenVerifier {
    fn verify_edge(&mut self, _c: &NodeId, _n: &NodeId) -> GateOutcome {
        self.edge_calls += 1;
        if self.edge_calls == 1 {
            GateOutcome::Blocked {
                reasons: vec!["contract broken on first attempt".into()],
            }
        } else {
            GateOutcome::Complete
        }
    }
    fn regression_sweep(&mut self, _c: &[NodeId]) -> GateOutcome {
        GateOutcome::Complete
    }
    fn program_judge(&mut self) -> JudgeVerdict {
        JudgeVerdict::pass(95, 80, "producer-model", "judge-model")
    }
}

struct CountingGreenExecutor {
    calls_per_node: std::collections::BTreeMap<NodeId, u32>,
}
impl ModuleExecutor for CountingGreenExecutor {
    fn execute(&mut self, ctx: &DriverModuleContext, _stop: &StopSignal) -> ModuleAttempt {
        *self.calls_per_node.entry(ctx.node.clone()).or_insert(0) += 1;
        ModuleAttempt::Ran {
            det: DeterministicVerdict::green(),
            adv: AdversarialVerdict::green(5),
            commit_shas: vec![format!("sha-{}-{}", ctx.node, ctx.attempt)],
            ledger_key: format!("k-{}-{}", ctx.node, ctx.attempt),
            by_model: "producer-model".into(),
        }
    }
}

#[test]
fn r15_reopening_rolls_back_the_committing_node_and_recovers() {
    let mut exec = CountingGreenExecutor {
        calls_per_node: Default::default(),
    };
    let mut judge = GreenJudge;
    let mut ver = RedOnceThenGreenVerifier { edge_calls: 0 };
    let stop = StopSignal::new();

    let nodes = vec![
        NodeDecl::new("a", NodeClass::MigrationRun),
        NodeDecl::new("b", NodeClass::MigrationRun).depends_on("a"),
    ];

    let report = drive_program_verified_reopening(
        ainxt_planner::program::ProgramId::new("prog-reopen"),
        "migrate the switch",
        nodes,
        &mut exec,
        &mut judge,
        &mut ver,
        &stop,
        3, // attempt cap — enough room for the rollback + one successful retry
    )
    .unwrap();

    // The program recovers and completes: the rollback + retry fixed the red edge.
    assert_eq!(report.outcome, ProgramOutcome::Completed);
    assert!(report.gate.is_complete());
    assert_eq!(report.committed, vec![nid("a"), nid("b")]);

    // `b` was executed at least twice — once that landed the red edge, once that recovered. Without
    // the rollback wiring, the loop would have capped after the first red edge and never retried.
    assert!(
        *exec.calls_per_node.get(&nid("b")).unwrap_or(&0) >= 2,
        "b must have been re-attempted after its rollback: {:?}",
        exec.calls_per_node
    );

    // `a` — the OLDER, still-good neighbor — was NEVER rolled back; only `b` (the node that just
    // committed and broke the contract) was.
    assert!(
        !report
            .program
            .log()
            .iter()
            .any(|e| matches!(e, ProgramEvent::RolledBack { node } if *node == nid("a"))),
        "the older, still-good neighbor must never be rolled back"
    );
    assert!(
        report
            .program
            .log()
            .iter()
            .any(|e| matches!(e, ProgramEvent::RolledBack { node } if *node == nid("b"))),
        "the node that broke the contract on commit must be durably rolled back"
    );
}

// ---- gap loop-teams-longhorizon item 4: rollback's real compensation side effect -----------------

/// Same red-once-then-green edge behavior as [`RedOnceThenGreenVerifier`], but also RECORDS every
/// `compensate` call (node + commit shas) and lets the test control whether compensation succeeds.
struct CompensationTrackingVerifier {
    edge_calls: u32,
    compensate_calls: std::cell::RefCell<Vec<(NodeId, Vec<String>)>>,
    compensate_result: Result<(), String>,
}
impl ProgramVerifier for CompensationTrackingVerifier {
    fn verify_edge(&mut self, _c: &NodeId, _n: &NodeId) -> GateOutcome {
        self.edge_calls += 1;
        if self.edge_calls == 1 {
            GateOutcome::Blocked {
                reasons: vec!["contract broken on first attempt".into()],
            }
        } else {
            GateOutcome::Complete
        }
    }
    fn regression_sweep(&mut self, _c: &[NodeId]) -> GateOutcome {
        GateOutcome::Complete
    }
    fn program_judge(&mut self) -> JudgeVerdict {
        JudgeVerdict::pass(95, 80, "producer-model", "judge-model")
    }
    fn compensate(&mut self, node: &NodeId, commit_shas: &[String]) -> Result<(), String> {
        self.compensate_calls
            .borrow_mut()
            .push((node.clone(), commit_shas.to_vec()));
        self.compensate_result.clone()
    }
}

/// Before this gap closed, NOTHING in the codebase ever called a rollback's real compensation side
/// effect — `Program::rollback_node` performed only the durable STATE transition. This proves the
/// real wire: `drive_program_verified_reopening`'s rollback branch calls `ProgramVerifier::compensate`
/// with the EXACT node and commit SHAs that are being undone, before the state-level rollback.
#[test]
fn r15_rollback_invokes_the_real_compensator_with_the_committed_shas() {
    let mut exec = CountingGreenExecutor {
        calls_per_node: Default::default(),
    };
    let mut judge = GreenJudge;
    let mut ver = CompensationTrackingVerifier {
        edge_calls: 0,
        compensate_calls: std::cell::RefCell::new(Vec::new()),
        compensate_result: Ok(()),
    };
    let stop = StopSignal::new();

    let nodes = vec![
        NodeDecl::new("a", NodeClass::MigrationRun),
        NodeDecl::new("b", NodeClass::MigrationRun).depends_on("a"),
    ];

    let report = drive_program_verified_reopening(
        ainxt_planner::program::ProgramId::new("prog-compensate"),
        "migrate the switch",
        nodes,
        &mut exec,
        &mut judge,
        &mut ver,
        &stop,
        3,
    )
    .unwrap();

    assert_eq!(report.outcome, ProgramOutcome::Completed);
    // Compensation ran exactly once, for `b` (the node that broke the contract), with its FIRST
    // commit's real SHA — never a placeholder, never the older neighbor `a`.
    let calls = ver.compensate_calls.borrow();
    assert_eq!(
        calls.len(),
        1,
        "compensate must run exactly once: {calls:?}"
    );
    assert_eq!(calls[0].0, nid("b"));
    assert_eq!(calls[0].1, vec!["sha-b-0".to_string()]);
    // A successful compensation reports no honest FAILED_PARTIAL trail.
    assert!(report.non_compensable_rollbacks.is_empty());
}

/// When compensation genuinely cannot undo the real-world side effect (e.g. the MR was already
/// merged), that must be surfaced honestly (§9 `FAILED_PARTIAL`) on the `DriveReport` — never
/// silently swallowed — while the STATE-level rollback still proceeds so the node stays schedulable.
#[test]
fn r15_non_compensable_rollback_is_surfaced_never_swallowed() {
    let mut exec = CountingGreenExecutor {
        calls_per_node: Default::default(),
    };
    let mut judge = GreenJudge;
    let mut ver = CompensationTrackingVerifier {
        edge_calls: 0,
        compensate_calls: std::cell::RefCell::new(Vec::new()),
        compensate_result: Err("MR already merged upstream; cannot un-create".to_string()),
    };
    let stop = StopSignal::new();

    let nodes = vec![
        NodeDecl::new("a", NodeClass::MigrationRun),
        NodeDecl::new("b", NodeClass::MigrationRun).depends_on("a"),
    ];

    let report = drive_program_verified_reopening(
        ainxt_planner::program::ProgramId::new("prog-noncompensable"),
        "migrate the switch",
        nodes,
        &mut exec,
        &mut judge,
        &mut ver,
        &stop,
        3,
    )
    .unwrap();

    // The state machine still recovers and completes (the rollback + retry fixed the red edge)...
    assert_eq!(report.outcome, ProgramOutcome::Completed);
    // ...but the report HONESTLY records that the real-world compensation for `b`'s first (bad)
    // commit could not complete — this is exactly the FAILED_PARTIAL trail §9 requires and the
    // pre-fix code had no mechanism to ever produce.
    assert_eq!(report.non_compensable_rollbacks.len(), 1);
    assert_eq!(report.non_compensable_rollbacks[0].0, nid("b"));
    assert!(report.non_compensable_rollbacks[0]
        .1
        .contains("already merged"));
}

// ---- baseline: the ORIGINAL round-9 entrypoint keeps its unchanged contract ----------------------

/// [`drive_program_verified`] (rollback OFF) must still behave exactly as round-9 specified: a red
/// edge is retained and blocks only the FINAL program-scale gate — every module that individually
/// committed stays `Committed` (this is `r9_program_scale_red_edge_blocks_completion_though_every_module_committed`'s
/// contract; this test guards that the round-15 rollback wiring did not silently change it for the
/// entrypoint that must not opt in).
struct AlwaysRedEdgeVerifier;
impl ProgramVerifier for AlwaysRedEdgeVerifier {
    fn verify_edge(&mut self, _c: &NodeId, _n: &NodeId) -> GateOutcome {
        GateOutcome::Blocked {
            reasons: vec!["integration contract broken".into()],
        }
    }
    fn regression_sweep(&mut self, _c: &[NodeId]) -> GateOutcome {
        GateOutcome::Complete
    }
    fn program_judge(&mut self) -> JudgeVerdict {
        JudgeVerdict::pass(95, 80, "producer-model", "judge-model")
    }
}

#[test]
fn r15_drive_program_verified_without_reopening_keeps_round9_contract() {
    let mut exec = CountingGreenExecutor {
        calls_per_node: Default::default(),
    };
    let mut judge = GreenJudge;
    let mut ver = AlwaysRedEdgeVerifier;
    let stop = StopSignal::new();

    let nodes = vec![
        NodeDecl::new("a", NodeClass::MigrationRun),
        NodeDecl::new("b", NodeClass::MigrationRun).depends_on("a"),
    ];

    let report = drive_program_verified(
        ainxt_planner::program::ProgramId::new("prog-noreopen"),
        "migrate the switch",
        nodes,
        &mut exec,
        &mut judge,
        &mut ver,
        &stop,
        2,
    )
    .unwrap();

    // Every module still committed (unchanged round-9 contract) even though the edge is red.
    assert_eq!(report.committed, vec![nid("a"), nid("b")]);
    assert_eq!(report.outcome, ProgramOutcome::CappedPartial);
    assert!(!report.gate.is_complete());
    // No rollback ever happened on this entrypoint.
    assert!(!report
        .program
        .log()
        .iter()
        .any(|e| matches!(e, ProgramEvent::RolledBack { .. })));
}
