// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-12 (loop-teams-longhorizon gap 6): the learning flywheel now has **downstream consumers**.
//! Terminal-run [`LearningRecord`]s are curated into (a) regression eval cases, (b) per-task
//! plan-template priors, and (c) per-role tuning recommendations — the improvement signal the design
//! (LOOP §10) names but nothing previously consumed.
//!
//! This drives the real 3-tier team loop to produce Learning Records, then feeds a batch of records
//! (including a persistently-failing role) through the three curators and asserts the emitted signal.

use ainxt_teams::flywheel::{
    generate_eval_cases, plan_template_priors, role_spec_tuning, FailureMode,
};
use ainxt_teams::{Cost, LearningRecord, ModelTier, RoleId, TaskId};
use std::collections::BTreeMap;

fn tid(s: &str) -> TaskId {
    TaskId::from(s)
}
fn rid(s: &str) -> RoleId {
    RoleId(s.to_string())
}

/// A learning record with explicit succeeded/failed task sets and a note per failed task.
fn record(succeeded: &[&str], failed: &[&str], note: &str) -> LearningRecord {
    LearningRecord {
        succeeded: succeeded.iter().map(|s| tid(s)).collect(),
        failed: failed.iter().map(|s| tid(s)).collect(),
        blocked: Vec::new(),
        refused: Vec::new(),
        skipped: Vec::new(),
        cancelled: Vec::new(),
        notes: failed.iter().map(|s| (tid(s), note.to_string())).collect(),
        total_cost: Cost::ZERO,
        all_succeeded: failed.is_empty(),
        budget_exhausted: false,
        was_cancelled: false,
    }
}

#[test]
fn r12_learning_flywheel_consumers() {
    // A batch of terminal runs: the `impl` task (coder) fails twice then succeeds; `review` (reviewer)
    // always succeeds.
    let records = vec![
        record(&["review"], &["impl"], "compile error: missing import"),
        record(&["review"], &["impl"], "test failure: negative amount"),
        record(&["impl", "review"], &[], ""),
    ];

    // (a) Eval-set generation: every failure becomes a regression case carrying its verbatim note.
    let cases = generate_eval_cases(&records);
    assert_eq!(
        cases.len(),
        2,
        "two failed-task observations -> two eval cases"
    );
    assert!(cases.iter().all(|c| c.task == tid("impl")));
    assert!(cases.iter().all(|c| c.failure_mode == FailureMode::Failed));
    assert!(cases.iter().any(|c| c.observed.contains("missing import")));
    assert!(cases.iter().any(|c| c.observed.contains("negative amount")));

    // (b) Plan-template priors: `impl` is risky (2/3 runs failed), `review` is not.
    let priors = plan_template_priors(&records);
    let impl_p = &priors[&tid("impl")];
    assert_eq!((impl_p.runs, impl_p.successes, impl_p.failures), (3, 1, 2));
    assert!(
        impl_p.is_risky(),
        "majority-failure task earns extra scrutiny"
    );
    assert_eq!(impl_p.failure_rate_bps(), 6666);
    assert!(!priors[&tid("review")].is_risky());

    // (c) Role-spec tuning: the coder (ran the failing `impl`) earns a tier bump; the reviewer does not.
    let mut task_roles = BTreeMap::new();
    task_roles.insert(tid("impl"), rid("coder"));
    task_roles.insert(tid("review"), rid("reviewer"));
    let mut role_tiers = BTreeMap::new();
    role_tiers.insert(rid("coder"), ModelTier::Medium);
    role_tiers.insert(rid("reviewer"), ModelTier::Simple);

    let tuning = role_spec_tuning(&records, &task_roles, &role_tiers);
    let coder = &tuning[&rid("coder")];
    assert!(coder.recommends_change());
    assert_eq!(coder.current_tier, ModelTier::Medium);
    assert_eq!(coder.suggested_tier, ModelTier::Complex);
    let reviewer = &tuning[&rid("reviewer")];
    assert!(!reviewer.recommends_change());

    // A clean run contributes no eval cases and no risky priors.
    let clean = vec![record(&["a", "b"], &[], "")];
    assert!(generate_eval_cases(&clean).is_empty());
    assert!(plan_template_priors(&clean).values().all(|p| !p.is_risky()));
}
