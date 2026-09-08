// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-12 (loop-teams-longhorizon gap 7): the [`PlanningDepth`] enum variant naming now matches its
//! semantic tier and is ordered by ascending planning cost, so a one-conjunction feature classifies as
//! `Medium` (not the mislabelled `Complex`) and a multi-service goal as `Complex`, and `Simple < Medium
//! < Complex` holds structurally. The structure probe is earned only by the true `Complex` tier.
//!
//! Fail-before: the variants were inverted (a handful-of-files feature was named `Complex`, a
//! multi-service goal `Medium`), so `plan_adaptively` probed the wrong tier. Pass-after: the mapping is
//! semantic and the ordinal ordering is asserted.

use ainxt_planner::{
    plan_adaptively, DecomposeError, Decomposer, DepthClassifier, Goal, HeuristicDepthClassifier,
    Plan, PlanConfig, PlanningDepth, Step, StepId, StructureProbe,
};
use std::collections::BTreeMap;

struct AllIndependent;
impl StructureProbe for AllIndependent {
    fn true_dependencies(&self, steps: &[Step]) -> BTreeMap<StepId, Vec<StepId>> {
        steps.iter().map(|s| (s.id.clone(), Vec::new())).collect()
    }
    fn worth_parallelizing(&self, _s: &[Step]) -> bool {
        true
    }
}

/// A decomposer that emits a fixed sequential 3-step chain regardless of the goal.
struct ChainDecomposer;
impl Decomposer for ChainDecomposer {
    fn decompose(&self, _goal: &Goal) -> Result<Vec<Step>, DecomposeError> {
        Ok(vec![
            Step::new(StepId::new("a"), "a", vec![]),
            Step::new(StepId::new("b"), "b", vec![StepId::new("a")]),
            Step::new(StepId::new("c"), "c", vec![StepId::new("b")]),
        ])
    }
}

#[test]
fn r12_planning_depth_semantic_tier() {
    let c = HeuristicDepthClassifier;

    // Semantic naming: the variant matches the tier.
    assert_eq!(
        c.classify(&Goal::new("g", "rename a local variable")),
        PlanningDepth::Simple
    );
    assert_eq!(
        c.classify(&Goal::new("g", "add validation and a unit test")),
        PlanningDepth::Medium,
        "one conjunction is the medium tier"
    );
    assert_eq!(
        c.classify(&Goal::new(
            "g",
            "migrate the auth service and the billing service and compare behaviour"
        )),
        PlanningDepth::Complex,
        "multi-service is the complex tier"
    );

    // Ordered by ascending planning cost.
    assert!(PlanningDepth::Simple < PlanningDepth::Medium);
    assert!(PlanningDepth::Medium < PlanningDepth::Complex);

    // The structure probe is earned only by the true Complex tier: a Medium goal keeps the cheap
    // sequential list (not materialized), a Complex goal materializes independent tracks.
    let medium = plan_adaptively(
        Goal::new("g", "add validation and a unit test"),
        &ChainDecomposer,
        &c,
        &AllIndependent,
        PlanConfig::default(),
    )
    .unwrap();
    assert_eq!(medium.depth, PlanningDepth::Medium);
    assert!(
        !medium.materialized,
        "Medium tier does not run the structure probe"
    );

    let complex = plan_adaptively(
        Goal::new("g", "migrate auth and billing and compare across services"),
        &ChainDecomposer,
        &c,
        &AllIndependent,
        PlanConfig::default(),
    )
    .unwrap();
    assert_eq!(complex.depth, PlanningDepth::Complex);
    assert!(complex.materialized, "Complex tier earns parallel tracks");
    // Sanity: materialization widened the ready wave (independent tracks).
    let _: &Plan = &complex.plan;
    assert!(complex.plan.ready_steps().len() > 1);
}
