// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-9 req 3 (team loop): a user-stop cancellation signal propagates into the executing 3-tier
//! team loop so an in-flight run halts promptly — `ainxt_teams::tiers::run_team_3tier_cancellable`.
//!
//! Proves: once the stop is tripped mid-run, no further task drives a real model turn (the remaining
//! tasks fail fast), and the Run terminates as an honest `Capped("user-stop: run halted")` — never a
//! fabricated `Complete`. A baseline with no stop (same graph/seams) completes, so the halt is causal.

use ainxt_teams::tiers::{
    run_team_3tier, run_team_3tier_cancellable, AcceptingCritic, Deliverable, EscalatingHealer,
    GoalJudge, JudgeOutcome, StepAttempt, StepContext, StepResult, StopSignal, TaskExecutor,
    TeamOutcome, ThreeTierConfig,
};
use ainxt_teams::{AgentInvocation, Cost, Role, Task, TaskGraph, TaskId, TaskState, Team};
use ainxt_types::Tier as ModelTier;
use std::collections::BTreeSet;

fn team() -> Team {
    let mut t = Team::new();
    t.add_role(Role::new("coder", ModelTier::Medium, ["edit_code"]));
    t.add_role(Role::new("reviewer", ModelTier::Simple, ["review"]));
    t
}

/// A 3-task chain: impl -> review -> signoff. Without a stop all three complete.
fn chain_graph() -> TaskGraph {
    let mut g = TaskGraph::new();
    g.add_task(
        Task::new("impl", "coder")
            .produces("diff")
            .accepts("compiles"),
    )
    .unwrap();
    g.add_task(
        Task::new("review", "reviewer")
            .depends_on("impl")
            .accepts("reviewed"),
    )
    .unwrap();
    g.add_task(
        Task::new("signoff", "reviewer")
            .depends_on("review")
            .accepts("approved"),
    )
    .unwrap();
    g
}

struct ConfirmingJudge;
impl GoalJudge for ConfirmingJudge {
    fn audit(&mut self, _d: &Deliverable) -> JudgeOutcome {
        JudgeOutcome::Confirmed
    }
}

/// Succeeds every task at a fixed cost.
struct HappyExecutor {
    calls: u32,
}
impl TaskExecutor for HappyExecutor {
    fn run_task(&mut self, task: &Task, _ctx: &StepContext) -> StepAttempt {
        self.calls += 1;
        StepAttempt {
            invocation: AgentInvocation::leaf(task.role.clone(), Cost::new(10, 1, 0, 0)),
            result: StepResult::Produced {
                output_ref: format!("artifact://{}", task.id),
            },
        }
    }
}

/// Trips the user-stop signal during its FIRST in-flight task turn (simulating the user pressing stop
/// mid-run), then succeeds that task. Every later task must be halted BEFORE it drives a turn.
struct StopOnFirstExecutor {
    stop: StopSignal,
    calls: u32,
}
impl TaskExecutor for StopOnFirstExecutor {
    fn run_task(&mut self, task: &Task, _ctx: &StepContext) -> StepAttempt {
        self.calls += 1;
        self.stop.stop();
        StepAttempt {
            invocation: AgentInvocation::leaf(task.role.clone(), Cost::new(10, 1, 0, 0)),
            result: StepResult::Produced {
                output_ref: format!("artifact://{}", task.id),
            },
        }
    }
}

fn no_seed() -> BTreeSet<String> {
    BTreeSet::new()
}

#[test]
fn r9_team_no_stop_baseline_completes() {
    let g = chain_graph();
    let t = team();
    let mut exec = HappyExecutor { calls: 0 };
    let report = run_team_3tier(
        &g,
        &t,
        "ship the feature",
        &no_seed(),
        &mut exec,
        &mut AcceptingCritic,
        &mut EscalatingHealer,
        &mut ConfirmingJudge,
        ThreeTierConfig::default(),
    )
    .unwrap();

    assert_eq!(report.outcome, TeamOutcome::Complete);
    assert_eq!(
        exec.calls, 3,
        "all three tasks drove a turn on the happy path"
    );
}

#[test]
fn r9_team_mid_run_stop_halts_promptly() {
    let g = chain_graph();
    let t = team();
    let stop = StopSignal::new();
    let mut exec = StopOnFirstExecutor {
        stop: stop.clone(),
        calls: 0,
    };

    let report = run_team_3tier_cancellable(
        &g,
        &t,
        "ship the feature",
        &no_seed(),
        &mut exec,
        &mut AcceptingCritic,
        &mut EscalatingHealer,
        &mut ConfirmingJudge,
        ThreeTierConfig::default(),
        &stop,
    )
    .unwrap();

    // The Run terminated as an honest user-stop Capped, never a fabricated Complete.
    match &report.outcome {
        TeamOutcome::Capped { reason } => {
            assert!(
                reason.contains("user-stop"),
                "expected a user-stop reason, got {reason:?}"
            );
        }
        other => panic!("expected Capped(user-stop), got {other:?}"),
    }
    // Only the FIRST task drove a real model turn; the in-flight stop halted the rest before any turn.
    assert_eq!(
        exec.calls, 1,
        "no further task drives a model turn after a user-stop"
    );
    // It halted inside the first round — never looped for another judge round.
    assert_eq!(report.rounds, 1);
}

/// gap loop-teams-longhorizon (item 2, cancellation partial): the scheduler ITSELF must learn about a
/// mid-run stop, not just the per-task self-heal wrapper. Before the fix, `run_team_3tier_impl` drove
/// the graph through the plain (non-cancellable) `run_team_fanout`, whose `cancel()` predicate is
/// hard-coded to never fire — the stop was only ever observed inside `execute_task_with_self_heal`'s
/// own manual check, which returns a plain task-level `StepReport::failure(..)`. That made a stopped
/// run indistinguishable from a real failure at the scheduler level: `review` landed in
/// `TaskState::Failed` (never `Cancelled`), `signoff` was cascaded to `TaskState::Blocked` by the
/// bulkhead logic (the wrong reason — it was never "blocked by a bad dependency", the whole team was
/// stopped), and `RunReport::cancelled` stayed permanently `false` even on a genuine user-stop.
///
/// This test asserts the scheduler-level truth on `report.last_run` (not just the outer
/// `TeamOutcome`, which `r9_team_mid_run_stop_halts_promptly` already covers): every task the stop
/// reached is honestly `TaskState::Cancelled`, and `last_run.cancelled` is `true`.
#[test]
fn r9_team_mid_run_stop_marks_remaining_tasks_cancelled_not_failed_or_blocked() {
    let g = chain_graph();
    let t = team();
    let stop = StopSignal::new();
    let mut exec = StopOnFirstExecutor {
        stop: stop.clone(),
        calls: 0,
    };

    let report = run_team_3tier_cancellable(
        &g,
        &t,
        "ship the feature",
        &no_seed(),
        &mut exec,
        &mut AcceptingCritic,
        &mut EscalatingHealer,
        &mut ConfirmingJudge,
        ThreeTierConfig::default(),
        &stop,
    )
    .unwrap();

    // The scheduler's own cancellation flag fired — this is dead/always-false without the fix.
    assert!(
        report.last_run.cancelled,
        "the scheduler itself must observe the mid-run stop, not just the self-heal wrapper"
    );
    // `impl` already succeeded before the stop tripped.
    assert_eq!(
        report.last_run.state_of(&TaskId::new("impl")),
        Some(TaskState::Succeeded)
    );
    // `review` and `signoff` were never reached after the stop — both honestly Cancelled, never a
    // fabricated Failed/Blocked that would look like a real defect to a human reading the report or
    // to a downstream stuck/thrash detector.
    assert_eq!(
        report.last_run.state_of(&TaskId::new("review")),
        Some(TaskState::Cancelled),
        "a stopped task must be Cancelled, not misreported as Failed"
    );
    assert_eq!(
        report.last_run.state_of(&TaskId::new("signoff")),
        Some(TaskState::Cancelled),
        "a dependent of a cancelled (not failed) task must itself be Cancelled, not Blocked"
    );
}
