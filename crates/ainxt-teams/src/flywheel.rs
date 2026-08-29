// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! The learning-flywheel **downstream consumers** (LOOP §10 / ADR-027 §13): the three curators that
//! turn accumulated [`LearningRecord`]s into durable improvement signal.
//!
//! Design: `docs/architecture/LOOP_AND_AGENT_TEAMS.md` §10 and `GAP_ANALYSIS_VS_AI_PLATFORMS.md`
//! gap (E) data-flywheel / feedback-loop.
//!
//! # The gap this closes
//!
//! [`LearningRecord`] (emitted on every terminal Run) and the [`LearningSink`] that collects them were
//! the *producer* side of the flywheel — but nothing *consumed* the accumulated records. A flywheel
//! with no downstream is just a log. This module is the consumer side: three deterministic curators
//! that read a batch of records and emit the improvement artifacts the design names —
//!
//! * [`generate_eval_cases`] — **eval-set generation**: every failed / blocked / refused task with its
//!   verbatim note becomes a regression eval case, so the *same* failure is caught automatically next
//!   time (the flywheel's core: turn a production failure into a permanent test).
//! * [`plan_template_priors`] — **plan-template priors**: per-task success/failure counts across all
//!   runs, yielding a failure-rate prior that biases future decomposition (a task that fails 70% of
//!   the time earns extra scrutiny / a checkpoint next time it is planned).
//! * [`role_spec_tuning`] — **role-spec tuning**: per-role success rates, yielding a suggested
//!   model-tier bump for roles whose Runs fail too often (the role spec is *tuned by outcomes*, not
//!   guessed once).
//!
//! Pure and deterministic — no clock/rng/I/O — so every rule is a unit-test property. The gating /
//! curation of *which* signal to act on lives downstream in Enterprise-Memory; this crate produces the
//! structured candidates it curates.

use crate::{LearningRecord, ModelTier, RoleId, TaskId};
use std::collections::BTreeMap;

// ===========================================================================
// Eval-set generation
// ===========================================================================

/// A candidate regression eval case distilled from a real failure (LOOP §10). It names the task that
/// failed, the failure mode it fell into, and the verbatim observed note — enough to re-run the
/// scenario and assert the failure does not recur.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvalCase {
    pub task: TaskId,
    /// The terminal state the task landed in (why it became an eval candidate).
    pub failure_mode: FailureMode,
    /// The verbatim run note (the error / refusal / blocker reason), never swallowed.
    pub observed: String,
}

/// The class of terminal failure a task hit — the eval case's category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureMode {
    /// The task executed and failed (a bug / unmet acceptance criterion) — the highest-value eval.
    Failed,
    /// The task was blocked by an upstream failure (bulkhead isolation) — a dependency eval.
    Blocked,
    /// The task was refused (policy / compliance / capability) — a guardrail eval.
    Refused,
}

/// Generate regression eval cases from a batch of terminal Learning Records (LOOP §10 eval-set
/// generation). Every failed / blocked / refused task becomes a case, tagged with its failure mode and
/// the verbatim note. Deterministic order: records in input order, then tasks in the record's stored
/// order. A run where everything succeeded contributes no cases.
pub fn generate_eval_cases(records: &[LearningRecord]) -> Vec<EvalCase> {
    let mut cases = Vec::new();
    for rec in records {
        for (tasks, mode) in [
            (&rec.failed, FailureMode::Failed),
            (&rec.blocked, FailureMode::Blocked),
            (&rec.refused, FailureMode::Refused),
        ] {
            for task in tasks {
                let observed = rec
                    .notes
                    .get(task)
                    .cloned()
                    .unwrap_or_else(|| format!("{mode:?} with no recorded note"));
                cases.push(EvalCase {
                    task: task.clone(),
                    failure_mode: mode,
                    observed,
                });
            }
        }
    }
    cases
}

// ===========================================================================
// Plan-template priors
// ===========================================================================

/// The accumulated outcome prior for one task across many Runs (LOOP §10). Biases future
/// decomposition: a high `failure_rate` task earns extra scrutiny (a checkpoint / a smaller window)
/// the next time the planner emits it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskPrior {
    pub task: TaskId,
    /// Total Runs that included this task (success + failure observations).
    pub runs: u32,
    /// Runs in which the task succeeded.
    pub successes: u32,
    /// Runs in which the task did NOT succeed (failed / blocked / refused / skipped / cancelled).
    pub failures: u32,
}

impl TaskPrior {
    /// Failure rate in basis points (0..=10000) — integer so the prior is deterministic (no float).
    /// `runs == 0` reads as 0 (no evidence).
    pub fn failure_rate_bps(&self) -> u32 {
        self.failures
            .saturating_mul(10_000)
            .checked_div(self.runs)
            .unwrap_or(0)
    }
    /// Whether this task should earn extra scrutiny next time it is planned (majority-failure prior).
    pub fn is_risky(&self) -> bool {
        self.failure_rate_bps() > 5_000
    }
}

/// Aggregate per-task success/failure priors across a batch of Learning Records (LOOP §10 plan-template
/// priors). Returns priors keyed by task, sorted by task id (deterministic). A task counts one
/// observation per record it appears in, as a success iff it is in that record's `succeeded` set.
pub fn plan_template_priors(records: &[LearningRecord]) -> BTreeMap<TaskId, TaskPrior> {
    let mut priors: BTreeMap<TaskId, TaskPrior> = BTreeMap::new();
    for rec in records {
        // Success observations.
        for task in &rec.succeeded {
            let p = priors.entry(task.clone()).or_insert_with(|| TaskPrior {
                task: task.clone(),
                runs: 0,
                successes: 0,
                failures: 0,
            });
            p.runs += 1;
            p.successes += 1;
        }
        // Non-success observations (any terminal non-succeeded state).
        for task in rec
            .failed
            .iter()
            .chain(&rec.blocked)
            .chain(&rec.refused)
            .chain(&rec.skipped)
            .chain(&rec.cancelled)
        {
            let p = priors.entry(task.clone()).or_insert_with(|| TaskPrior {
                task: task.clone(),
                runs: 0,
                successes: 0,
                failures: 0,
            });
            p.runs += 1;
            p.failures += 1;
        }
    }
    priors
}

// ===========================================================================
// Role-spec tuning
// ===========================================================================

/// A tuning recommendation for one role, derived from the outcomes of the tasks it ran (LOOP §10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleTuning {
    pub role: RoleId,
    pub runs: u32,
    pub successes: u32,
    /// The role's current model tier (as configured), for the recommendation delta.
    pub current_tier: ModelTier,
    /// The suggested tier after tuning — bumped one rung when the role fails too often, unchanged
    /// otherwise. A deployment reviews this before applying (never auto-mutates the role spec here).
    pub suggested_tier: ModelTier,
}

impl RoleTuning {
    /// Whether tuning recommends a change (the suggested tier differs from the current one).
    pub fn recommends_change(&self) -> bool {
        self.suggested_tier != self.current_tier
    }
}

/// Bump a model tier one rung (`Complex` is the ceiling) — the escalation a failing role earns.
fn bump(t: ModelTier) -> ModelTier {
    match t {
        ModelTier::Simple => ModelTier::Medium,
        ModelTier::Medium => ModelTier::Complex,
        ModelTier::Complex => ModelTier::Complex,
    }
}

/// Tune role specs from accumulated outcomes (LOOP §10 role-spec tuning). `task_roles` maps each task
/// to the role that ran it; `role_tiers` gives each role's current model tier. A role whose tasks fail
/// in the majority of observations earns a one-rung tier-bump recommendation. Returns tunings keyed by
/// role, sorted by role id (deterministic). Roles with no observations are omitted.
pub fn role_spec_tuning(
    records: &[LearningRecord],
    task_roles: &BTreeMap<TaskId, RoleId>,
    role_tiers: &BTreeMap<RoleId, ModelTier>,
) -> BTreeMap<RoleId, RoleTuning> {
    // Roll task outcomes up to the role that ran each task.
    let mut runs: BTreeMap<RoleId, u32> = BTreeMap::new();
    let mut successes: BTreeMap<RoleId, u32> = BTreeMap::new();

    let mut observe = |task: &TaskId, ok: bool| {
        if let Some(role) = task_roles.get(task) {
            *runs.entry(role.clone()).or_insert(0) += 1;
            if ok {
                *successes.entry(role.clone()).or_insert(0) += 1;
            }
        }
    };
    for rec in records {
        for t in &rec.succeeded {
            observe(t, true);
        }
        for t in rec
            .failed
            .iter()
            .chain(&rec.blocked)
            .chain(&rec.refused)
            .chain(&rec.skipped)
            .chain(&rec.cancelled)
        {
            observe(t, false);
        }
    }

    let mut out: BTreeMap<RoleId, RoleTuning> = BTreeMap::new();
    for (role, &n) in &runs {
        let ok = successes.get(role).copied().unwrap_or(0);
        let failures = n.saturating_sub(ok);
        let current = role_tiers.get(role).copied().unwrap_or(ModelTier::Medium);
        // Majority-failure roles earn a one-rung bump.
        let suggested = if n > 0 && failures * 2 > n {
            bump(current)
        } else {
            current
        };
        out.insert(
            role.clone(),
            RoleTuning {
                role: role.clone(),
                runs: n,
                successes: ok,
                current_tier: current,
                suggested_tier: suggested,
            },
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Cost, TaskId};

    fn tid(s: &str) -> TaskId {
        TaskId::from(s)
    }
    fn rid(s: &str) -> RoleId {
        RoleId(s.to_string())
    }

    /// A learning record with the given succeeded / failed tasks and a note per failed task.
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
    fn eval_cases_are_generated_from_failures_with_notes() {
        let recs = vec![record(&["a"], &["b"], "compile error in b")];
        let cases = generate_eval_cases(&recs);
        assert_eq!(cases.len(), 1);
        assert_eq!(cases[0].task, tid("b"));
        assert_eq!(cases[0].failure_mode, FailureMode::Failed);
        assert_eq!(cases[0].observed, "compile error in b");
    }

    #[test]
    fn eval_cases_empty_when_everything_succeeded() {
        let recs = vec![record(&["a", "b"], &[], "")];
        assert!(generate_eval_cases(&recs).is_empty());
    }

    #[test]
    fn plan_priors_accumulate_success_and_failure_rates() {
        // Task `b` failed twice, succeeded once → 3 runs, 2 failures = 6666 bps > 5000 → risky.
        let recs = vec![
            record(&["a"], &["b"], "x"),
            record(&["a"], &["b"], "x"),
            record(&["a", "b"], &[], ""),
        ];
        let priors = plan_template_priors(&recs);
        let a = &priors[&tid("a")];
        assert_eq!((a.runs, a.successes, a.failures), (3, 3, 0));
        assert!(!a.is_risky());
        let b = &priors[&tid("b")];
        assert_eq!((b.runs, b.successes, b.failures), (3, 1, 2));
        assert_eq!(b.failure_rate_bps(), 6666);
        assert!(b.is_risky());
    }

    #[test]
    fn role_tuning_bumps_a_majority_failing_role() {
        // coder ran `impl` (failed twice, ok once) → majority failure → bump Medium→Complex.
        // reviewer ran `review` (ok twice) → no change.
        let recs = vec![
            record(&["review"], &["impl"], "x"),
            record(&["review"], &["impl"], "x"),
            record(&["impl"], &[], ""),
        ];
        let mut task_roles = BTreeMap::new();
        task_roles.insert(tid("impl"), rid("coder"));
        task_roles.insert(tid("review"), rid("reviewer"));
        let mut role_tiers = BTreeMap::new();
        role_tiers.insert(rid("coder"), ModelTier::Medium);
        role_tiers.insert(rid("reviewer"), ModelTier::Simple);

        let tuning = role_spec_tuning(&recs, &task_roles, &role_tiers);
        let coder = &tuning[&rid("coder")];
        assert_eq!((coder.runs, coder.successes), (3, 1));
        assert_eq!(coder.suggested_tier, ModelTier::Complex);
        assert!(coder.recommends_change());
        let reviewer = &tuning[&rid("reviewer")];
        assert!(!reviewer.recommends_change());
        assert_eq!(reviewer.suggested_tier, ModelTier::Simple);
    }
}
