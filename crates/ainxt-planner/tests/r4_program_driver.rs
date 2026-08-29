// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-4 gap-closing integration tests on the REAL live-drivable `Program` object
//! (`ainxt_planner::driver::Program`).
//!
//! Two loop-highs proven end-to-end against the public API:
//!  * `r4_enforced_verification` — three-way verification is ENFORCED, not self-reported: a node
//!    cannot commit without a durable `Complete` proof, and a red/same-model verdict never verifies.
//!  * `r4_checkpoint_resume` — a Program resumes from a checkpoint by replaying the durable log,
//!    WITHOUT re-executing already-committed nodes.

use ainxt_planner::driver::{Program, ProgramCheckpoint};
use ainxt_planner::program::{NodeClass, NodeDecl, NodeId, NodeState, ProgramId, ProgramOutcome};
use ainxt_planner::verify::{AdversarialVerdict, DeterministicVerdict, GateOutcome, JudgeVerdict};

fn nid(s: &str) -> NodeId {
    NodeId::new(s)
}

/// A chain a -> b -> c, each depending on the previous.
fn chain() -> Vec<NodeDecl> {
    vec![
        NodeDecl::new("a", NodeClass::MigrationRun),
        NodeDecl::new("b", NodeClass::MigrationRun).depends_on("a"),
        NodeDecl::new("c", NodeClass::MigrationRun).depends_on("b"),
    ]
}

/// Stand up an approved, decomposed program ready to schedule `a`.
fn approved_chain() -> Program {
    let mut p = Program::start(ProgramId::new("prog"), "migrate settlement").unwrap();
    p.decompose(chain()).unwrap();
    p.approve("boss").unwrap();
    p
}

/// A fully green, cross-model per-module proof.
fn green_proofs() -> (DeterministicVerdict, AdversarialVerdict, JudgeVerdict) {
    (
        DeterministicVerdict::green(),
        AdversarialVerdict::green(25),
        JudgeVerdict::pass(90, 80, "qwen-coder", "glm-judge"),
    )
}

// ---------------------------------------------------------------------------
// GAP 1 — three-way verification enforced (never done until proven)
// ---------------------------------------------------------------------------

#[test]
fn r4_enforced_verification() {
    let mut p = approved_chain();
    let a = nid("a");

    // `a` is schedulable; begin it.
    assert_eq!(p.actionable(), vec![a.clone()]);
    p.begin_node(&a).unwrap();

    // ENFORCEMENT 1: committing an unproven in-progress node is refused — you cannot self-report
    // "done". (Before this object existed the only gate was inside the batch supervisor; a caller
    // driving the state machine directly could reach Committed with no verification at all.)
    let err = p
        .commit_node(&a, vec!["sha-a".into()], "k-a", "qwen-coder")
        .unwrap_err();
    assert_eq!(
        format!("{err}"),
        "node a has no Complete three-way verification proof"
    );
    assert!(!p.is_proven(&a));

    // ENFORCEMENT 2: a red proof (Judge below threshold) does NOT verify — it is a failed attempt,
    // and the node returns to the schedulable pool. Commit is still refused.
    let (det, adv, _) = green_proofs();
    let red_judge = JudgeVerdict::pass(60, 80, "qwen-coder", "glm-judge");
    let outcome = p.record_verdict(&a, det, adv, red_judge).unwrap();
    assert!(matches!(outcome, GateOutcome::Blocked { .. }));
    // Not verified: the failed attempt returns `a` to the schedulable pool (dep-free -> re-derived
    // Ready), never Verified.
    assert_ne!(p.state().nodes[&a].state, NodeState::Verified);
    assert_eq!(p.state().nodes[&a].state, NodeState::Ready);
    assert!(!p.is_proven(&a));
    assert!(p
        .commit_node(&a, vec!["sha-a".into()], "k-a2", "qwen-coder")
        .is_err());

    // ENFORCEMENT 3: a same-model producer/judge pairing is a structural blind spot — rejected by
    // the cross-model rule even with a perfect score, so it cannot verify either.
    p.begin_node(&a).unwrap();
    let (det, adv, _) = green_proofs();
    let same_model = JudgeVerdict::pass(100, 80, "qwen-coder", "qwen-coder");
    let outcome = p.record_verdict(&a, det, adv, same_model).unwrap();
    assert!(matches!(outcome, GateOutcome::Blocked { .. }));
    assert!(!p.is_proven(&a));

    // Now a genuine, green, cross-model three-way proof verifies the node.
    p.begin_node(&a).unwrap();
    let (det, adv, judge) = green_proofs();
    let outcome = p.record_verdict(&a, det, adv, judge).unwrap();
    assert_eq!(outcome, GateOutcome::Complete);
    assert_eq!(p.state().nodes[&a].state, NodeState::Verified);
    assert!(p.is_proven(&a));

    // Only now does commit succeed.
    p.commit_node(&a, vec!["sha-a".into()], "k-a-final", "qwen-coder")
        .unwrap();
    assert_eq!(p.state().nodes[&a].state, NodeState::Committed);

    // The durable, replayable invariant: EVERY committed node carries a Complete proof — this holds
    // on a fresh projection of the log too, so the enforcement is a property of the log, not RAM.
    assert!(p.state().committed_nodes_are_all_proven());
    let replayed = Program::resume(p.log()).unwrap();
    assert!(replayed.state().committed_nodes_are_all_proven());
    assert!(replayed.state().is_node_proven(&a));
}

// ---------------------------------------------------------------------------
// GAP 2 — checkpoint -> resume replays the durable log, no committed re-execution
// ---------------------------------------------------------------------------

/// Drive one schedulable node all the way to committed through the enforced gate, recording every
/// node the "executor" actually ran into `executed`.
fn run_one_module(p: &mut Program, executed: &mut Vec<NodeId>) {
    let node = p
        .actionable()
        .into_iter()
        .next()
        .expect("a schedulable node");
    executed.push(node.clone()); // <- the ONLY place a module's work is "executed"
    p.begin_node(&node).unwrap();
    let (det, adv, judge) = green_proofs();
    assert_eq!(
        p.record_verdict(&node, det, adv, judge).unwrap(),
        GateOutcome::Complete
    );
    p.commit_node(
        &node,
        vec![format!("sha-{node}")],
        format!("k-{node}"),
        "qwen-coder",
    )
    .unwrap();
}

#[test]
fn r4_checkpoint_resume() {
    // Phase 1: run to the first commit, then take a durable checkpoint (simulating end-of-day).
    let mut executed_before: Vec<NodeId> = Vec::new();
    let mut p = approved_chain();
    run_one_module(&mut p, &mut executed_before); // commits `a`
    assert_eq!(executed_before, vec![nid("a")]);
    assert_eq!(p.state().committed_node_ids(), vec![nid("a")]);

    let checkpoint: ProgramCheckpoint = p.checkpoint();
    let durable_log = p.log().to_vec(); // this is all that survives the "crash"
    drop(p); // process dies

    // Two independent resume paths reconstruct byte-identical state (§4):
    //  (i) full replay of the durable log;
    let resumed = Program::resume(&durable_log).unwrap();
    //  (ii) checkpoint snapshot + only the tail after the checkpoint offset.
    let tail = &durable_log[checkpoint.offset as usize..];
    let resumed_from_cp = Program::resume_from_checkpoint(&checkpoint, tail).unwrap();
    assert_eq!(resumed.state(), resumed_from_cp.state());
    assert_eq!(
        resumed.state().head_hash,
        resumed_from_cp.state().head_hash,
        "checkpoint resume == full replay (hash-chained)"
    );

    // The resumed program remembers `a` is committed AND proven — no re-verification needed.
    assert_eq!(resumed.state().committed_node_ids(), vec![nid("a")]);
    assert!(resumed.state().is_node_proven(&nid("a")));
    assert!(resumed.state().committed_nodes_are_all_proven());

    // Phase 2: continue driving on the resumed object to completion. Crucially, `a` (committed) is
    // never actionable again, so the executor is never invoked for it — committed work is not redone.
    let mut executed_after: Vec<NodeId> = Vec::new();
    let mut p = resumed;
    assert_eq!(p.actionable(), vec![nid("b")]); // `a` is NOT here
    run_one_module(&mut p, &mut executed_after); // commits `b`
    run_one_module(&mut p, &mut executed_after); // commits `c`
    p.record_outcome(ProgramOutcome::Completed).unwrap();

    // The committed node `a` was executed exactly once — in phase 1, never after resume.
    assert_eq!(executed_after, vec![nid("b"), nid("c")]);
    assert!(!executed_after.contains(&nid("a")));

    // Whole-program invariants hold on the final durable log.
    assert_eq!(
        p.state().committed_node_ids(),
        vec![nid("a"), nid("b"), nid("c")]
    );
    assert!(p.state().committed_is_dependency_closed());
    assert!(p.state().committed_nodes_are_all_proven());

    // `a` was committed exactly once across the whole crash/resume history (idempotent, §4).
    // `p` was resumed from the full durable log, so its log carries the entire history.
    let a_commits = p
        .log()
        .iter()
        .filter(|e| {
            matches!(e,
                ainxt_planner::program::ProgramEvent::NodeCommitted { node, .. } if node == &nid("a"))
        })
        .count();
    assert_eq!(a_commits, 1);
    // The phase-1 checkpoint really was mid-flight (its prefix log is shorter than the finished one).
    assert!((checkpoint.offset as usize) < p.log().len());
    let _ = durable_log;
}
