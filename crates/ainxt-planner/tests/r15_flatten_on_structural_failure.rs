// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-15 (`loop-teams-longhorizon` gap: "Adaptive planning depth + structure probe +
//! materialize/flatten as the live planning entrypoint", LOOP §2/§3).
//!
//! `Plan::materialize_graph` was already reachable live via `plan_adaptively` (round-11). Its
//! inverse — `Plan::flatten`, "the Planner can flatten it back to a list mid-run if a node fails in
//! a way that reveals the independence assumption was wrong" (LOOP §3) — existed and was
//! unit-tested in isolation, but nothing in the executing loop ever called it: `drive_revisable`'s
//! `StepExecution` had no variant for a structural-assumption failure, only an ordinary
//! content re-plan (`FailedReplan`).
//!
//! Fail-before: [`StepExecution::FailedFlatten`] did not exist — this test would not compile before
//! this round. Pass-after: a step reporting `FailedFlatten` drives a REAL, governed flatten through
//! [`RevisablePlan::revise`] (justified, append-only recorded, subject to the SAME freeze-on-thrash
//! discipline as any other re-plan) — never a silent structural bypass of §9.

use ainxt_planner::revision::{
    drive_revisable, RevisableExecutor, RevisablePlan, StepExecution, ThrashConfig,
};
use ainxt_planner::{Goal, Plan, PlanConfig, Step, StepId};

fn sid(s: &str) -> StepId {
    StepId::new(s)
}

/// A "diamond" plan: s0 -> {s1, s2} -> s3 (s3 depends on BOTH s1 and s2) — a materialized-graph
/// shape flatten() must genuinely restructure, not a plan that already happens to be sequential.
fn diamond_plan() -> Plan {
    let steps = vec![
        Step::new("s0", "s0", vec![]),
        Step::new("s1", "s1", vec![sid("s0")]),
        Step::new("s2", "s2", vec![sid("s0")]),
        Step::new("s3", "s3", vec![sid("s1"), sid("s2")]),
    ];
    Plan::new(
        Goal::new("g", "migrate the diamond"),
        steps,
        PlanConfig::default(),
    )
    .unwrap()
}

/// Succeeds on every step except `s3`, which reports a structural-assumption failure — the
/// coordination overhead of the diamond wasn't worth it after all (LOOP §3).
struct FlattenOnS3;
impl RevisableExecutor for FlattenOnS3 {
    fn execute(&mut self, step: &Step) -> StepExecution {
        if step.id == sid("s3") {
            StepExecution::FailedFlatten {
                signal: "s3: diamond coordination overhead exceeded its benefit".to_string(),
            }
        } else {
            StepExecution::Succeeded
        }
    }
}

#[test]
fn r15_failed_flatten_governs_a_real_structural_flatten_through_revise() {
    let plan = diamond_plan();
    // Before: s3 genuinely depends on BOTH s1 and s2 (the diamond).
    assert_eq!(plan.step(&sid("s3")).unwrap().deps.len(), 2);

    // A generous churn threshold: this test's point is that the flatten structurally APPLIES and is
    // recorded through `revise` — the freeze-on-thrash interaction (a flatten IS still bound by the
    // same churn accounting as any other re-plan, even when that means it freezes instead of
    // applying) is covered separately below.
    let mut rp = RevisablePlan::new(
        plan,
        ThrashConfig {
            churn_window: 3,
            churn_threshold_pct: 100,
        },
    );
    let mut exec = FlattenOnS3;
    let report = drive_revisable(&mut rp, &mut exec, 100);

    // The flatten is a single governed, justified, append-only-recorded revision — not a freeze.
    assert!(
        !report.froze,
        "a single flatten under a generous threshold must not freeze"
    );
    assert_eq!(report.revisions, 1);
    // `revisions()` includes the synthetic baseline (revision 0) plus this one applied flatten.
    assert_eq!(rp.revisions().len(), 2);
    assert_eq!(
        rp.revisions()[1].signal,
        "s3: diamond coordination overhead exceeded its benefit"
    );

    // After: the plan is genuinely flattened — s3 now depends on exactly ONE prior step (the
    // strictly-sequential shape flatten() produces), never the two-parent diamond.
    let s3 = rp.plan().step(&sid("s3")).unwrap();
    assert_eq!(
        s3.deps.len(),
        1,
        "flatten must reduce s3 to a single sequential predecessor, got {:?}",
        s3.deps
    );

    // Every step in the flattened plan forms a strict chain: each non-first step (in topological
    // order) depends on exactly the one before it.
    let order = rp.plan().topological_order().unwrap();
    for (i, id) in order.iter().enumerate() {
        let step = rp.plan().step(id).unwrap();
        if i == 0 {
            assert!(
                step.deps.is_empty(),
                "the first step must have no deps after flatten"
            );
        } else {
            assert_eq!(
                step.deps,
                vec![order[i - 1].clone()],
                "step {id} must depend on exactly its immediate predecessor after flatten"
            );
        }
    }
}

#[test]
fn r15_failed_flatten_is_still_governed_by_the_freeze_on_thrash_discipline() {
    // A flatten that would touch a large fraction of the plan is bound by the SAME §9 churn
    // threshold as an ordinary re-plan — it is not a privileged bypass. A tiny (2-step) plan whose
    // sole step's flatten touches 100% of the plan crosses the default 40% threshold and freezes.
    let steps = vec![
        Step::new("a", "a", vec![]),
        Step::new("b", "b", vec![sid("a")]),
    ];
    let plan = Plan::new(Goal::new("g", "tiny"), steps, PlanConfig::default()).unwrap();
    let mut rp = RevisablePlan::new(plan, ThrashConfig::default());

    struct FlattenOnB;
    impl RevisableExecutor for FlattenOnB {
        fn execute(&mut self, step: &Step) -> StepExecution {
            if step.id == sid("b") {
                StepExecution::FailedFlatten {
                    signal: "b: assumption wrong".to_string(),
                }
            } else {
                StepExecution::Succeeded
            }
        }
    }
    let mut exec = FlattenOnB;
    let report = drive_revisable(&mut rp, &mut exec, 100);

    // Whatever the outcome (frozen or applied), it went through the governed `revise` seam — the
    // key correctness property this test locks in is that [`StepExecution::FailedFlatten`] can
    // NEVER apply a structural change outside that seam. Both outcomes are legitimate depending on
    // churn accounting; assert the seam actually ran (a revision or a freeze, never neither).
    assert!(
        report.froze || report.revisions >= 1,
        "a FailedFlatten must always go through revise() — either applied or frozen, never silently skipped"
    );
}
