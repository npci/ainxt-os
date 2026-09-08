// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-5 gap-closing integration test: MTG window-sizing / SCC / strangler-shim planning are
//! reachable from the live path through **one clean entrypoint**
//! (`ainxt_planner::compose::MigrationBlueprint::compose`), and the node graph it produces feeds the
//! REAL live-drivable, durable `Program` (`ainxt_planner::driver::Program`) — where the three-way
//! verification gate is ENFORCED (never self-reported) and a checkpoint→resume replays the durable
//! log without re-executing committed nodes.
//!
//! Before this test's entrypoint existed the served path hard-coded a single `NodeDecl`, so a real
//! multi-module repository never reached window-sizing, cycle handling or shim planning at all. Here a
//! realistic repository — an oversized module that must split, a mutual-import cycle, a critical-path
//! module, and a reverse-order dependency — is composed into the real node graph and driven to a
//! COMPLETED program end-to-end.

use ainxt_planner::compose::MigrationBlueprint;
use ainxt_planner::driver::{Program, ProgramCheckpoint};
use ainxt_planner::mtg::{MtgNode, WindowBudget};
use ainxt_planner::program::{CheckpointClass, NodeClass, NodeId, ProgramId, ProgramOutcome};
use ainxt_planner::scc::DepGraph;
use ainxt_planner::verify::{AdversarialVerdict, DeterministicVerdict, GateOutcome, JudgeVerdict};

fn nid(s: &str) -> NodeId {
    NodeId::new(s)
}

fn green() -> (DeterministicVerdict, AdversarialVerdict, JudgeVerdict) {
    (
        DeterministicVerdict::green(),
        AdversarialVerdict::green(25),
        JudgeVerdict::pass(90, 80, "qwen-coder", "glm-judge"),
    )
}

/// A realistic 1M-LOC-shaped repository blueprint exercising all three subsystems at once.
fn repo_blueprint() -> MigrationBlueprint {
    let window = WindowBudget::new(10_000); // ceiling 5_000

    let roots = vec![
        // (1) window-sizing: 'big' is over budget and splits into three admissible sub-packages.
        MtgNode::new("big", 12_000)
            .with_child(MtgNode::new("big::a", 4_000))
            .with_child(MtgNode::new("big::b", 3_000))
            .with_child(MtgNode::new("big::c", 4_500)),
        // (2) SCC: x <-> y is a mutual-import cycle that fits the window -> one super-node.
        MtgNode::new("x", 1_000),
        MtgNode::new("y", 1_000),
        // (3) critical-path module.
        MtgNode::new("settlement", 1_000),
        // (4) strangler: ui must migrate before the api it depends on.
        MtgNode::new("ui", 1_000),
        MtgNode::new("api", 1_000),
    ];

    let mut g = DepGraph::new();
    g.add_edge("big::b", "big::a"); // b depends on a
    g.add_edge("big::c", "big::b"); // c depends on b
    g.add_edge("x", "y"); // mutual import cycle
    g.add_edge("y", "x");
    g.add_edge("settlement", "x"); // depends on the cycle cluster
    g.add_edge("ui", "api"); // reverse-order edge (declared below)

    MigrationBlueprint::new(roots, g, window)
        .with_reverse_edge("ui", "api")
        .with_critical_path("settlement")
}

/// Drive the single node the enforced gate makes schedulable, recording every node the executor
/// actually ran into `executed`.
fn run_one(p: &mut Program, executed: &mut Vec<NodeId>) {
    let node = p
        .actionable()
        .into_iter()
        .next()
        .expect("a schedulable node");
    executed.push(node.clone());
    p.begin_node(&node).unwrap();
    let (det, adv, judge) = green();
    assert_eq!(
        p.record_verdict(&node, det, adv, judge).unwrap(),
        GateOutcome::Complete,
        "genuine cross-model green proof verifies node {node}"
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
fn r5_compose_to_program() {
    // ---- ENTRYPOINT: one call composes the whole repo into the real node graph ----------------
    let bp = repo_blueprint();
    let nodes = bp.compose().expect("blueprint composes");

    // The served path used to hard-code exactly ONE node; the entrypoint yields the full graph.
    assert!(
        nodes.len() > 1,
        "a multi-module repo must decompose into many nodes, got {}",
        nodes.len()
    );

    // Each subsystem is visible in the composed graph:
    let has = |id: &str| nodes.iter().any(|n| n.id.as_str() == id);
    // (1) window-sizing produced admissible leaves for the oversized module.
    assert!(has("big::a") && has("big::b") && has("big::c"));
    assert!(
        nodes.iter().all(|n| n.working_set_estimate <= 5_000),
        "no composed node exceeds the window ceiling"
    );
    // (2) the mutual-import cycle collapsed into one migration super-node (never linearized).
    assert!(has("x+y"));
    // (3) the critical-path module carries a human commit gate.
    let settlement = nodes
        .iter()
        .find(|n| n.id.as_str() == "settlement")
        .unwrap();
    assert_eq!(settlement.checkpoint_class, CheckpointClass::CriticalPath);
    // (4) the reverse-order edge produced a shim + shim-cleanup, and rewired the consumer.
    assert!(has("shim::ui->api") && has("shim-cleanup::ui->api"));
    let ui = nodes.iter().find(|n| n.id.as_str() == "ui").unwrap();
    assert!(ui.deps.contains(&nid("shim::ui->api")));
    assert!(!ui.deps.contains(&nid("api")));
    assert_eq!(
        nodes
            .iter()
            .find(|n| n.id.as_str() == "shim::ui->api")
            .unwrap()
            .node_class,
        NodeClass::Shim
    );

    // ---- LIVE PROGRAM: the composed graph is accepted and schedulable --------------------------
    // Program::decompose validates the graph (no cycle / dangling / self / duplicate). That it is
    // accepted proves the composition — with a super-node collapse and a shim rewiring — is a
    // schedulable graph, not just a bag of decls.
    let mut p = Program::start(ProgramId::new("mig-1"), "migrate the monolith").unwrap();
    p.decompose(nodes.clone())
        .expect("composed graph is a valid decomposition");
    p.approve("release-manager").unwrap();

    // Multiple dependency-free nodes are actionable at once — a real parallel graph off the entrypoint.
    let initial = p.actionable();
    assert!(
        initial.len() > 1,
        "composed graph exposes parallel work: {initial:?}"
    );
    assert!(
        initial.contains(&nid("x+y")),
        "the super-node is schedulable"
    );
    assert!(
        !initial.contains(&nid("settlement")),
        "settlement waits on x+y"
    );

    // ---- GAP 1: three-way verification is ENFORCED on this composed graph ----------------------
    let first = initial[0].clone();
    p.begin_node(&first).unwrap();
    // You cannot self-report done: committing without a durable proof is refused.
    assert!(
        p.commit_node(&first, vec!["sha".into()], "k", "qwen-coder")
            .is_err(),
        "commit refused without a Complete three-way proof"
    );
    // A red proof (judge below threshold) does not verify — failed attempt, not Verified.
    let red = JudgeVerdict::pass(50, 80, "qwen-coder", "glm-judge");
    assert!(matches!(
        p.record_verdict(
            &first,
            DeterministicVerdict::green(),
            AdversarialVerdict::green(25),
            red
        )
        .unwrap(),
        GateOutcome::Blocked { .. }
    ));
    assert!(!p.is_proven(&first));

    // ---- Drive to the first commit, then checkpoint (end-of-day) -------------------------------
    let mut executed: Vec<NodeId> = Vec::new();
    run_one(&mut p, &mut executed); // commits the first schedulable node through the genuine gate
    let committed_first = executed[0].clone();
    assert!(p.state().committed_node_ids().contains(&committed_first));

    let checkpoint: ProgramCheckpoint = p.checkpoint();
    let durable_log = p.log().to_vec();
    drop(p); // process dies

    // ---- GAP 2: resume replays the durable log; committed work is NOT re-executed --------------
    let resumed = Program::resume(&durable_log).unwrap();
    let tail = &durable_log[checkpoint.offset as usize..];
    let from_cp = Program::resume_from_checkpoint(&checkpoint, tail).unwrap();
    assert_eq!(resumed.state().head_hash, from_cp.state().head_hash);
    assert!(resumed.state().is_node_proven(&committed_first));
    assert!(
        !resumed.actionable().contains(&committed_first),
        "a committed node is never handed back to the executor after resume"
    );

    // ---- Continue to a COMPLETED program on the resumed object ---------------------------------
    let mut p = resumed;
    let mut after: Vec<NodeId> = Vec::new();
    while !p.actionable().is_empty() {
        run_one(&mut p, &mut after);
    }
    // The committed-before node was never re-run after resume.
    assert!(!after.contains(&committed_first));

    // Every composed node committed exactly once, and the committed set is dependency-closed + proven.
    assert_eq!(p.state().committed_node_ids().len(), nodes.len());
    assert!(p.state().committed_is_dependency_closed());
    assert!(p.state().committed_nodes_are_all_proven());
    p.record_outcome(ProgramOutcome::Completed).unwrap();
}
