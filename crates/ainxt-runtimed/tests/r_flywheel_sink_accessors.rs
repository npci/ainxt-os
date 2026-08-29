// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX loop-teams-longhorizon (LOOP §10) — `ainxt_teams::flywheel::generate_eval_cases`,
//! `plan_template_priors`, AND `role_spec_tuning` were fully implemented and unit-tested but had zero
//! callers outside their own crate, even though `InMemoryLearningSink` (the LOOP-13 sink already wired
//! into every served team run) accumulates exactly the `Vec<LearningRecord>` all three functions
//! consume. `role_spec_tuning` was overlooked when the other two were wired in an earlier round (it
//! alone needs the caller's static task→role / role→tier maps) — this is the completing GAP-AUDIT
//! pass. Proves the new `InMemoryLearningSink::flywheel_eval_cases`/`flywheel_template_priors`/
//! `flywheel_role_tuning` passthroughs curate the SAME records the sink already holds.

use std::collections::BTreeMap;

use ainxt_runtimed::{InMemoryLearningSink, LearningSink};
use ainxt_teams::flywheel::FailureMode;
use ainxt_teams::{LearningRecord, ModelTier, RoleId, TaskId};

fn record(succeeded: &[&str], failed: &[&str], note: Option<(&str, &str)>) -> LearningRecord {
    let mut notes = BTreeMap::new();
    if let Some((task, msg)) = note {
        notes.insert(TaskId::from(task), msg.to_string());
    }
    LearningRecord {
        succeeded: succeeded.iter().map(|t| TaskId::from(*t)).collect(),
        failed: failed.iter().map(|t| TaskId::from(*t)).collect(),
        blocked: Vec::new(),
        refused: Vec::new(),
        skipped: Vec::new(),
        cancelled: Vec::new(),
        notes,
        total_cost: ainxt_teams::Cost::ZERO,
        all_succeeded: failed.is_empty(),
        budget_exhausted: false,
        was_cancelled: false,
    }
}

#[test]
fn r_flywheel_eval_cases_and_priors_curate_the_sinks_own_records() {
    let sink = InMemoryLearningSink::new();
    sink.record(&record(&["impl", "review"], &[], None));
    sink.record(&record(
        &["impl"],
        &["review"],
        Some(("review", "reviewer timed out")),
    ));

    // generate_eval_cases: only the failed/blocked/refused task across BOTH records becomes a case.
    let cases = sink.flywheel_eval_cases();
    assert_eq!(
        cases.len(),
        1,
        "only the failing run's failed task becomes an eval case: {cases:?}"
    );
    assert_eq!(cases[0].task, TaskId::from("review"));
    assert_eq!(cases[0].failure_mode, FailureMode::Failed);
    assert_eq!(cases[0].observed, "reviewer timed out");

    // plan_template_priors: `impl` succeeded twice (100%); `review` succeeded once, failed once (50%).
    let priors = sink.flywheel_template_priors();
    let impl_prior = &priors[&TaskId::from("impl")];
    assert_eq!(
        (impl_prior.runs, impl_prior.successes, impl_prior.failures),
        (2, 2, 0)
    );
    assert!(!impl_prior.is_risky());

    let review_prior = &priors[&TaskId::from("review")];
    assert_eq!(
        (
            review_prior.runs,
            review_prior.successes,
            review_prior.failures
        ),
        (2, 1, 1)
    );
    assert_eq!(review_prior.failure_rate_bps(), 5_000);
}

#[test]
fn r_flywheel_role_tuning_curates_the_sinks_own_records() {
    let sink = InMemoryLearningSink::new();
    // impl (coder) always succeeds; review (reviewer) fails a MAJORITY of the time (2 of 3).
    sink.record(&record(&["impl", "review"], &[], None));
    sink.record(&record(&["impl"], &["review"], Some(("review", "flaky"))));
    sink.record(&record(
        &["impl"],
        &["review"],
        Some(("review", "flaky again")),
    ));

    let mut task_roles = BTreeMap::new();
    task_roles.insert(TaskId::from("impl"), RoleId::from("coder"));
    task_roles.insert(TaskId::from("review"), RoleId::from("reviewer"));
    let mut role_tiers = BTreeMap::new();
    role_tiers.insert(RoleId::from("coder"), ModelTier::Medium);
    role_tiers.insert(RoleId::from("reviewer"), ModelTier::Simple);

    let tuning = sink.flywheel_role_tuning(&task_roles, &role_tiers);

    let coder = &tuning[&RoleId::from("coder")];
    assert_eq!((coder.runs, coder.successes), (3, 3));
    assert!(
        !coder.recommends_change(),
        "an all-succeeding role earns no tier bump: {coder:?}"
    );

    let reviewer = &tuning[&RoleId::from("reviewer")];
    assert_eq!((reviewer.runs, reviewer.successes), (3, 1));
    assert!(
        reviewer.recommends_change(),
        "a majority-failing role (2 of 3) must earn a one-rung tier-bump recommendation: {reviewer:?}"
    );
    assert_eq!(
        reviewer.suggested_tier,
        ModelTier::Medium,
        "Simple bumps one rung to Medium"
    );
}
