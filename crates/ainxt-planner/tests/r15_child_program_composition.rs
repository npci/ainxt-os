// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-15 (`loop-teams-longhorizon` gap: "Child-program composition / nested Programs for
//! recursive migrations", ADR-027 §4).
//!
//! `ainxt_planner::program`'s pure event fold already supported `child-program`-class nodes
//! (`ChildProgramSpawned`/`ChildProgramOutcomeMapped`, `BlockedOnChildProgram`) and
//! `ainxt_planner::supervisor` (the BATCH driver) already exercised them. The LIVE, resumable
//! [`driver::Program`] object — the one the served daemon actually hot-wires
//! (`drive_program_verified` et al.) — had no command surface for it at all: no way to spawn a
//! child, no way to resolve one, so a `child-program`-class node on the live path was permanently
//! stuck `InProgress` with no legal way forward.
//!
//! Fail-before: [`Program::spawn_child_program`]/[`Program::resolve_child_program`] did not exist —
//! this test would not compile before this round. Pass-after: both are real, durable, event-logged
//! commands with the exact §4 semantics (spawn only from `InProgress` on a `ChildProgram`-class
//! node; `Completed` re-opens to `Ready`; `CappedPartial`/`Abandoned` raise to `BlockedOnHuman`; a
//! blocked node is never schedulable; the resolved node can then commit normally).

use ainxt_planner::driver::Program;
use ainxt_planner::program::{
    ChildOutcome, NodeClass, NodeDecl, NodeId, ProgramId, ProgramOutcome,
};
use ainxt_planner::verify::{AdversarialVerdict, DeterministicVerdict, JudgeVerdict};

fn nid(s: &str) -> NodeId {
    NodeId::new(s)
}

#[test]
fn r15_child_program_completed_reopens_the_parent_node_to_ready() {
    let mut program = Program::start(ProgramId::new("parent"), "decouple the monolith").unwrap();
    program
        .decompose(vec![NodeDecl::new("m", NodeClass::ChildProgram)])
        .unwrap();
    program.approve("driver").unwrap();

    // Before spawn: the node is Ready/actionable, ordinarily.
    assert_eq!(program.actionable(), vec![nid("m")]);

    program.begin_node(&nid("m")).unwrap();
    // Fail-before contract: no proof, no commit, and (before this round) no way to spawn a child.
    assert!(!program.is_proven(&nid("m")));

    program
        .spawn_child_program(&nid("m"), ProgramId::new("child-decouple-refactor"))
        .unwrap();

    // While blocked on the child, the parent node is NOT schedulable — the parent Program does not
    // advance past it (§4).
    assert!(
        program.actionable().is_empty(),
        "a node awaiting its child's terminal outcome must not be schedulable"
    );

    // The child's terminal outcome maps back deterministically: `Completed` -> `Ready` again.
    program
        .resolve_child_program(&nid("m"), ChildOutcome::Completed)
        .unwrap();
    assert_eq!(
        program.actionable(),
        vec![nid("m")],
        "Completed must re-open the parent node to Ready, schedulable again"
    );

    // The re-opened node now completes through the ORDINARY three-way-verified path — child-program
    // composition does not bypass §6 verification.
    program.begin_node(&nid("m")).unwrap();
    let gate = program
        .record_verdict(
            &nid("m"),
            DeterministicVerdict::green(),
            AdversarialVerdict::green(5),
            JudgeVerdict::pass(90, 80, "producer-model", "judge-model"),
        )
        .unwrap();
    assert!(gate.is_complete());
    program
        .commit_node(&nid("m"), vec!["sha-m".into()], "k-m", "producer-model")
        .unwrap();
    assert_eq!(program.state().committed_node_ids(), vec![nid("m")]);
}

#[test]
fn r15_child_program_capped_partial_raises_the_parent_to_blocked_on_human() {
    let mut program = Program::start(ProgramId::new("parent2"), "decouple the monolith").unwrap();
    program
        .decompose(vec![NodeDecl::new("m", NodeClass::ChildProgram)])
        .unwrap();
    program.approve("driver").unwrap();
    program.begin_node(&nid("m")).unwrap();
    program
        .spawn_child_program(&nid("m"), ProgramId::new("child-cant-finish"))
        .unwrap();

    program
        .resolve_child_program(&nid("m"), ChildOutcome::CappedPartial)
        .unwrap();

    // A CappedPartial/Abandoned child NEVER silently re-opens the parent to Ready — it is raised to
    // a human gate, never inferred as success (§4 "never claimed, only proven" discipline).
    assert!(
        program.actionable().is_empty(),
        "a CappedPartial child must not make the parent node schedulable again"
    );
    assert!(!program.is_proven(&nid("m")));
}

#[test]
fn r15_spawn_child_program_is_refused_on_a_non_child_program_class_node() {
    // The §4 guard: spawning a child is refused unless the node is DECLARED `child-program` class —
    // an ordinary migration-run node can never be silently redirected into a nested Program.
    let mut program = Program::start(ProgramId::new("parent3"), "migrate").unwrap();
    program
        .decompose(vec![NodeDecl::new("a", NodeClass::MigrationRun)])
        .unwrap();
    program.approve("driver").unwrap();
    program.begin_node(&nid("a")).unwrap();

    assert!(program
        .spawn_child_program(&nid("a"), ProgramId::new("should-not-exist"))
        .is_err());
}

#[test]
fn r15_spawn_child_program_is_refused_before_the_node_is_in_progress() {
    // The §4 guard: a child can only be spawned from a node the parent has actually STARTED — never
    // from a merely-Ready node (which would let a child spawn without the parent ever recording it
    // began the work).
    let mut program = Program::start(ProgramId::new("parent4"), "decouple").unwrap();
    program
        .decompose(vec![NodeDecl::new("m", NodeClass::ChildProgram)])
        .unwrap();
    program.approve("driver").unwrap();
    // Still Ready, never begun.
    assert!(program
        .spawn_child_program(&nid("m"), ProgramId::new("too-early"))
        .is_err());
}

/// End-to-end: a program with an independent `MigrationRun` node alongside a `ChildProgram` node —
/// the independent branch is never blocked by the other's child-program wait (route-around-like
/// independence, mirroring §9's "independent branches keep progressing").
#[test]
fn r15_independent_branch_progresses_while_a_sibling_awaits_its_child() {
    let mut program = Program::start(ProgramId::new("parent5"), "migrate + decouple").unwrap();
    program
        .decompose(vec![
            NodeDecl::new("m", NodeClass::ChildProgram),
            NodeDecl::new("independent", NodeClass::MigrationRun),
        ])
        .unwrap();
    program.approve("driver").unwrap();

    program.begin_node(&nid("m")).unwrap();
    program
        .spawn_child_program(&nid("m"), ProgramId::new("child-x"))
        .unwrap();

    // `m` is blocked, but `independent` is untouched and still actionable.
    assert_eq!(program.actionable(), vec![nid("independent")]);

    program.begin_node(&nid("independent")).unwrap();
    let gate = program
        .record_verdict(
            &nid("independent"),
            DeterministicVerdict::green(),
            AdversarialVerdict::green(5),
            JudgeVerdict::pass(90, 80, "producer-model", "judge-model"),
        )
        .unwrap();
    assert!(gate.is_complete());
    program
        .commit_node(
            &nid("independent"),
            vec!["sha-i".into()],
            "k-i",
            "producer-model",
        )
        .unwrap();
    assert!(program
        .state()
        .committed_node_ids()
        .contains(&nid("independent")));

    // Resolve the child; `m` completes too, and the whole program can now be sealed as Completed.
    program
        .resolve_child_program(&nid("m"), ChildOutcome::Completed)
        .unwrap();
    program.begin_node(&nid("m")).unwrap();
    program
        .record_verdict(
            &nid("m"),
            DeterministicVerdict::green(),
            AdversarialVerdict::green(5),
            JudgeVerdict::pass(90, 80, "producer-model", "judge-model"),
        )
        .unwrap();
    program
        .commit_node(&nid("m"), vec!["sha-m".into()], "k-m", "producer-model")
        .unwrap();

    program.record_outcome(ProgramOutcome::Completed).unwrap();
    assert!(program.state().phase.is_terminal());
}
