// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-12 (loop-teams-longhorizon gap 4): the node contract's `edit_ladder_floor` is **enforced at
//! the commit gate** (§10), not merely stored. A node whose artifact was authored with a Semantic-
//! Editing rung BELOW its floor — e.g. a raw `TextPatch` on a critical-path module whose floor is
//! `Ast` — is refused at commit even with a fully-green three-way verification proof; a node authored
//! at (or above) its floor commits normally.
//!
//! Fail-before: prior to this round the floor was recorded on the node but never checked, so a
//! below-floor artifact committed silently. Pass-after: [`ProgramError::EditFloorViolation`].

use ainxt_planner::driver::Program;
use ainxt_planner::program::{EditRung, NodeClass, NodeDecl, NodeId, ProgramError, ProgramId};
use ainxt_planner::verify::{AdversarialVerdict, DeterministicVerdict, GateOutcome, JudgeVerdict};

fn nid(s: &str) -> NodeId {
    NodeId::new(s)
}

fn green() -> (DeterministicVerdict, AdversarialVerdict, JudgeVerdict) {
    (
        DeterministicVerdict::green(),
        AdversarialVerdict::green(25),
        JudgeVerdict::pass(95, 80, "qwen-coder", "glm-judge"),
    )
}

/// A one-node program whose single node carries `floor` as its edit-ladder floor.
fn program_with_floor(node: &str, floor: EditRung) -> Program {
    let mut p = Program::start(ProgramId::new("prog"), "migrate settlement").unwrap();
    p.decompose(vec![
        NodeDecl::new(node, NodeClass::MigrationRun).with_edit_floor(floor)
    ])
    .unwrap();
    p.approve("test").unwrap();
    p
}

#[test]
fn r12_edit_floor_commit_gate() {
    // ---- below-floor artifact is REFUSED at the commit gate despite a green three-way proof -------
    let a = nid("settlement");
    let mut p = program_with_floor("settlement", EditRung::Ast);
    p.begin_node(&a).unwrap();
    let (det, adv, judge) = green();
    // A raw TextPatch (below the Ast floor) still earns a green three-way gate (compile/tests/judge
    // are all fine) — the node advances to Verified...
    assert_eq!(
        p.record_verdict_with_rung(&a, det, adv, judge, EditRung::TextPatch)
            .unwrap(),
        GateOutcome::Complete
    );
    assert!(p.is_proven(&a), "the three-way proof is green");
    // ...but the commit gate REFUSES it: the rung is below the node's floor (§10).
    let err = p
        .commit_node(&a, vec!["sha".into()], "k-a", "qwen-coder")
        .unwrap_err();
    match err {
        ProgramError::EditFloorViolation { node, used, floor } => {
            assert_eq!(node, a);
            assert_eq!(used, EditRung::TextPatch);
            assert_eq!(floor, EditRung::Ast);
        }
        other => panic!("expected EditFloorViolation, got {other:?}"),
    }
    // The node never reached Committed.
    assert!(p.state().committed_node_ids().is_empty());

    // ---- an at-floor artifact commits normally ---------------------------------------------------
    let b = nid("fees");
    let mut p2 = program_with_floor("fees", EditRung::Ast);
    p2.begin_node(&b).unwrap();
    let (det, adv, judge) = green();
    p2.record_verdict_with_rung(&b, det, adv, judge, EditRung::Ast)
        .unwrap();
    p2.commit_node(&b, vec!["sha".into()], "k-b", "qwen-coder")
        .unwrap();
    assert_eq!(p2.state().committed_node_ids(), vec![b.clone()]);

    // ---- an above-floor (safer) artifact also commits --------------------------------------------
    let c = nid("rounding");
    let mut p3 = program_with_floor("rounding", EditRung::StructuredPatch);
    p3.begin_node(&c).unwrap();
    let (det, adv, judge) = green();
    p3.record_verdict_with_rung(&c, det, adv, judge, EditRung::Lsp)
        .unwrap();
    p3.commit_node(&c, vec!["sha".into()], "k-c", "qwen-coder")
        .unwrap();
    assert_eq!(p3.state().committed_node_ids(), vec![c]);

    // ---- backward-compat: the rung-less `record_verdict` defaults to the floor and commits --------
    let d = nid("legacy");
    let mut p4 = program_with_floor("legacy", EditRung::Ast);
    p4.begin_node(&d).unwrap();
    let (det, adv, judge) = green();
    p4.record_verdict(&d, det, adv, judge).unwrap();
    p4.commit_node(&d, vec!["sha".into()], "k-d", "qwen-coder")
        .unwrap();
    assert_eq!(p4.state().committed_node_ids(), vec![d]);
}
