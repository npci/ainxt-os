// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-11 — adaptive planning, the anti-thrash detector DRIVEN by an executing loop, decomposition
//! from a Context-Fabric-derived module graph, and tamper-evident Event-Log hash chaining.
//!
//! Closes (LOOP §2/§9, LONG_HORIZON §3.1/§4, gap AR/AK):
//!  * **Adaptive planning depth + structure probe + graph materialization** — `plan_adaptively` chains
//!    depth classification → decompose → (only on the complex tier) structure-probe + materialize, so a
//!    genuinely-independent multi-service goal earns parallel tracks while a simple goal stays a cheap
//!    sequential list.
//!  * **Plan-stability / anti-thrash wired into an executing loop** — `drive_revisable` runs a
//!    `RevisablePlan` and re-plans failures THROUGH `revise`, so excessive churn freezes the plan
//!    mid-execution instead of emitting a stream of micro-edits; a single-failure run still completes.
//!  * **Decomposition from real Context-Fabric structure** — `MigrationBlueprint::from_module_graph`
//!    composes a MULTI-node, dependency-carrying program from a Fabric-derived `(module, edges)`
//!    structure (the live Fabric population is `needs_hot_wiring`).
//!  * **Tamper-evident hash chaining** — `verify_hash_chain` detects a mutated / reordered / truncated
//!    durable log; an intact log verifies.
//!
//! Fail-before/pass-after: `plan_adaptively`, `drive_revisable`, `from_module_graph`, and
//! `verify_hash_chain`/`recompute_head_hash` are new in round-11 — these tests would not compile before.

use ainxt_planner::compose::MigrationBlueprint;
use ainxt_planner::mtg::{ModuleRef, WindowBudget};
use ainxt_planner::program::{
    recompute_head_hash, verify_hash_chain, ChainVerdict, NodeClass, NodeDecl, ProgramId,
};
use ainxt_planner::revision::{
    drive_revisable, RevisableExecutor, RevisablePlan, StepExecution, ThrashConfig,
};
use ainxt_planner::{
    plan_adaptively, Alternative, Goal, HeuristicDepthClassifier, Plan, PlanConfig, PlanningDepth,
    Step, StepId, StepTemplate, StructureProbe, TemplateDecomposer,
};
use std::collections::BTreeMap;

fn sid(s: &str) -> StepId {
    StepId::new(s)
}

// ---- gap 7: adaptive planning depth + structure probe + materialization ----

/// A probe that reports EVERY step as genuinely independent and judges parallelism worth it — the
/// live runtime backs this with the Context-Fabric dependency graph + a short LLM judgment.
struct AllIndependentProbe;
impl StructureProbe for AllIndependentProbe {
    fn true_dependencies(&self, steps: &[Step]) -> BTreeMap<StepId, Vec<StepId>> {
        steps.iter().map(|s| (s.id.clone(), Vec::new())).collect()
    }
    fn worth_parallelizing(&self, _s: &[Step]) -> bool {
        true
    }
}

fn sequential_decomposer() -> TemplateDecomposer {
    TemplateDecomposer::new(vec![
        StepTemplate::new("t1", "first", vec![]),
        StepTemplate::new("t2", "second", vec![sid("t1")]),
        StepTemplate::new("t3", "third", vec![sid("t2")]),
    ])
}

#[test]
fn r11_plan_adaptively_promotes_a_complex_goal_and_leaves_a_simple_goal_flat() {
    let dec = sequential_decomposer();
    let classifier = HeuristicDepthClassifier;
    let probe = AllIndependentProbe;

    // A multi-service / compare goal → Complex tier → structure probe runs → parallel tracks.
    let complex_goal = Goal::new(
        "g1",
        "migrate the auth service and the billing service and compare behaviour",
    );
    let complex = plan_adaptively(
        complex_goal,
        &dec,
        &classifier,
        &probe,
        PlanConfig::default(),
    )
    .unwrap();
    assert_eq!(complex.depth, PlanningDepth::Complex);
    assert!(
        complex.materialized,
        "a genuinely-independent complex goal must materialize parallel tracks"
    );
    // After materialization all three tasks are independently ready — real fan-out, not a chain.
    assert_eq!(complex.plan.ready_steps().len(), 3);

    // A simple goal → simple tier → NO structure probe, stays the decomposer's cheap sequential list.
    let simple_goal = Goal::new("g2", "rename a local variable");
    let simple = plan_adaptively(
        simple_goal,
        &dec,
        &classifier,
        &probe,
        PlanConfig::default(),
    )
    .unwrap();
    assert_eq!(simple.depth, PlanningDepth::Simple);
    assert!(!simple.materialized);
    // Sequential: only the head task is ready.
    assert_eq!(simple.plan.ready_steps().len(), 1);
}

// ---- gap 6: anti-thrash detector driven by an executing loop ----

/// Fails the FIRST time it sees each of `fail_once` (asking the loop to re-plan it), then succeeds on
/// the retry — so plan churn accumulates across the failing steps.
struct FailOnceExecutor {
    fail_once: std::collections::BTreeSet<String>,
    seen: std::collections::BTreeSet<String>,
}
impl RevisableExecutor for FailOnceExecutor {
    fn execute(&mut self, step: &Step) -> StepExecution {
        let id = step.id.to_string();
        if self.fail_once.contains(&id) && self.seen.insert(id.clone()) {
            StepExecution::FailedReplan {
                signal: format!("critic: {id} deficient"),
                alternative: Alternative::replace(format!("{id} v2"), step.deps.clone()),
            }
        } else {
            StepExecution::Succeeded
        }
    }
}

fn flat_plan(n: usize) -> Plan {
    let steps: Vec<Step> = (0..n)
        .map(|i| Step::new(format!("s{i}"), format!("s{i}"), vec![]))
        .collect();
    Plan::new(Goal::new("g", "goal"), steps, PlanConfig::default()).unwrap()
}

#[test]
fn r11_executing_loop_freezes_the_plan_on_excessive_churn() {
    // Four independent steps; re-planning several of them in quick succession crosses the 40% churn
    // threshold, so the executing loop must FREEZE (§9) instead of continuing to micro-edit.
    let mut rp = RevisablePlan::new(flat_plan(4), ThrashConfig::default());
    let mut exec = FailOnceExecutor {
        fail_once: ["s0", "s1", "s2", "s3"]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        seen: Default::default(),
    };
    let report = drive_revisable(&mut rp, &mut exec, 100);

    assert!(
        report.froze,
        "excessive plan churn must freeze the plan mid-execution"
    );
    assert!(rp.is_frozen());
    assert!(
        !report.completed,
        "a frozen run is an honest partial, not silently completed"
    );
    // The revision history is append-only and did NOT record the thrashing micro-edit that froze it.
    assert!(
        rp.revisions().len() >= 2,
        "the applied re-plans are recorded before the freeze"
    );
}

#[test]
fn r11_executing_loop_completes_when_churn_stays_below_threshold() {
    // Only one step needs a re-plan → churn stays well under the threshold → the loop completes and
    // never freezes (the detector does not over-fire).
    let mut rp = RevisablePlan::new(flat_plan(4), ThrashConfig::default());
    let mut exec = FailOnceExecutor {
        fail_once: ["s0"].iter().map(|s| s.to_string()).collect(),
        seen: Default::default(),
    };
    let report = drive_revisable(&mut rp, &mut exec, 100);

    assert!(!report.froze);
    assert!(
        report.completed,
        "a single bounded re-plan completes without freezing"
    );
    assert_eq!(report.revisions, 1);
    assert!(!rp.is_frozen());
}

// ---- gap 5: decomposition from a Context-Fabric-derived module graph ----

#[test]
fn r11_compose_a_multi_node_program_from_a_fabric_module_graph() {
    // A synthetic Context-Fabric dependency structure: three modules with a real import chain
    // (c -> b -> a). The seam composes a MULTI-node, dependency-carrying program — never one node.
    let modules = vec![
        (ModuleRef::new("switch::a"), 400u64),
        (ModuleRef::new("switch::b"), 500u64),
        (ModuleRef::new("switch::c"), 300u64),
    ];
    let edges = vec![
        (ModuleRef::new("switch::b"), ModuleRef::new("switch::a")), // b depends on a
        (ModuleRef::new("switch::c"), ModuleRef::new("switch::b")), // c depends on b
    ];
    let window = WindowBudget::new(100_000);
    let decls = MigrationBlueprint::from_module_graph(modules, edges, window)
        .compose()
        .unwrap();

    // Three real migration nodes (window-sizing/SCC/shim planning all ran over the graph).
    assert_eq!(
        decls.len(),
        3,
        "a Fabric graph composes a multi-node program"
    );
    let find = |id: &str| decls.iter().find(|d| d.id.as_str() == id).unwrap();
    assert!(find("switch::b")
        .deps
        .contains(&ModuleRef::new("switch::a")));
    assert!(find("switch::c")
        .deps
        .contains(&ModuleRef::new("switch::b")));
    assert!(find("switch::a").deps.is_empty());

    // The composed decls are a schedulable program: decompose accepts them and only the root is ready.
    use ainxt_planner::driver::Program;
    let mut program = Program::start(ProgramId::new("prog-fabric"), "migrate the switch").unwrap();
    program.decompose(decls).unwrap();
    program.approve("driver").unwrap();
    assert_eq!(program.actionable(), vec![ModuleRef::new("switch::a")]);
}

// ---- gap 9: tamper-evident / WORM-grade hash chaining ----

fn valid_log() -> (Vec<ainxt_planner::program::ProgramEvent>, String) {
    use ainxt_planner::driver::{
        DriverModuleContext, ModuleAttempt, ModuleExecutor, ModuleJudge, StopSignal,
    };
    use ainxt_planner::supervisor::ProgramVerifier;
    use ainxt_planner::verify::{
        AdversarialVerdict, DeterministicVerdict, GateOutcome, JudgeVerdict,
    };
    use ainxt_planner::{driver::drive_program_verified, program::NodeId};

    struct E;
    impl ModuleExecutor for E {
        fn execute(&mut self, ctx: &DriverModuleContext, _s: &StopSignal) -> ModuleAttempt {
            ModuleAttempt::Ran {
                det: DeterministicVerdict::green(),
                adv: AdversarialVerdict::green(10),
                commit_shas: vec![format!("sha-{}", ctx.node)],
                ledger_key: format!("k-{}", ctx.node),
                by_model: "producer".into(),
            }
        }
    }
    struct J;
    impl ModuleJudge for J {
        fn judge(&mut self, _c: &DriverModuleContext, _a: &ModuleAttempt) -> JudgeVerdict {
            JudgeVerdict::pass(90, 80, "producer", "judge")
        }
    }
    struct V;
    impl ProgramVerifier for V {
        fn verify_edge(&mut self, _c: &NodeId, _n: &NodeId) -> GateOutcome {
            GateOutcome::Complete
        }
        fn regression_sweep(&mut self, _c: &[NodeId]) -> GateOutcome {
            GateOutcome::Complete
        }
        fn program_judge(&mut self) -> JudgeVerdict {
            JudgeVerdict::pass(95, 80, "producer", "judge")
        }
    }

    let report = drive_program_verified(
        ProgramId::new("prog-chain"),
        "migrate",
        vec![
            NodeDecl::new("a", NodeClass::MigrationRun),
            NodeDecl::new("b", NodeClass::MigrationRun).depends_on("a"),
        ],
        &mut E,
        &mut J,
        &mut V,
        &StopSignal::new(),
        2,
    )
    .unwrap();
    let head = report.program.state().head_hash.clone();
    (report.program.log().to_vec(), head)
}

#[test]
fn r11_hash_chain_detects_tamper_and_verifies_an_intact_log() {
    let (log, head) = valid_log();

    // The projected head equals the pure recomputed chain, and an intact log verifies.
    assert_eq!(recompute_head_hash(&log), head);
    assert!(verify_hash_chain(&log, &head).is_intact());

    // Reordering two events breaks the chain (tamper detected).
    let mut reordered = log.clone();
    reordered.swap(2, 3);
    assert!(matches!(
        verify_hash_chain(&reordered, &head),
        ChainVerdict::Tampered { .. }
    ));

    // Truncating the log (dropping the sealing Outcome) breaks the chain.
    let truncated = &log[..log.len() - 1];
    assert!(matches!(
        verify_hash_chain(truncated, &head),
        ChainVerdict::Tampered { .. }
    ));

    // A genuinely intact copy still verifies (no false positive).
    let intact = log.clone();
    assert!(verify_hash_chain(&intact, &head).is_intact());
}
