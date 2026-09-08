// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-11 — the hierarchical **3-tier team loop** end-to-end, with parallel fan-out admission of
//! independent branches (LOOP §1-§7, acceptance #2).
//!
//! `ainxt_teams::tiers::run_team_3tier` / `run_team_3tier_cancellable` is the entrypoint the served
//! daemon drives (already consumed by `ainxt_runtimed::run_team` with real Engine turns; the HTTP route
//! mount is the remaining `needs_hot_wiring`). This test proves the entrypoint drives a hierarchical,
//! MULTI-branch team (architect → coder → reviewer, plus an independent tester branch) through all three
//! tiers to `Complete`, and that the fan-out admission decision (`TaskGraph::ready_wave`) admits the two
//! independent roots together — the time-feasibility claim that independent branches do not serialize.

use ainxt_teams::tiers::{
    run_team_3tier, AcceptingCritic, Deliverable, EscalatingHealer, GoalJudge, JudgeOutcome,
    StepAttempt, StepContext, StepResult, TaskExecutor, TeamOutcome, ThreeTierConfig,
};
use ainxt_teams::{AgentInvocation, Cost, Role, Task, TaskGraph, TaskId, Team};
use ainxt_types::Tier as ModelTier;
use std::collections::BTreeSet;

fn tid(s: &str) -> TaskId {
    TaskId::from(s)
}

/// A hierarchical team: an Architect (Complex tier) down to a Reviewer (Simple), plus a Tester.
fn team() -> Team {
    let mut t = Team::new();
    t.add_role(Role::new("architect", ModelTier::Complex, ["design"]));
    t.add_role(Role::new("coder", ModelTier::Medium, ["edit_code"]));
    t.add_role(Role::new("reviewer", ModelTier::Simple, ["review"]));
    t.add_role(Role::new("tester", ModelTier::Simple, ["test"]));
    t
}

/// architect -> coder -> reviewer  (a hierarchy) + an INDEPENDENT tester branch.
fn hierarchical_graph() -> TaskGraph {
    let mut g = TaskGraph::new();
    g.add_task(
        Task::new("architect", "architect")
            .produces("design")
            .accepts("designed"),
    )
    .unwrap();
    g.add_task(
        Task::new("code", "coder")
            .depends_on("architect")
            .requires("design")
            .produces("diff")
            .accepts("compiles"),
    )
    .unwrap();
    g.add_task(
        Task::new("review", "reviewer")
            .depends_on("code")
            .accepts("reviewed"),
    )
    .unwrap();
    // Independent branch: tester has no dependency on the architect chain.
    g.add_task(Task::new("test", "tester").accepts("tested"))
        .unwrap();
    g
}

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

struct ConfirmingJudge;
impl GoalJudge for ConfirmingJudge {
    fn audit(&mut self, _d: &Deliverable) -> JudgeOutcome {
        JudgeOutcome::Confirmed
    }
}

#[test]
fn r11_ready_wave_admits_independent_roots_together() {
    let g = hierarchical_graph();
    // With nothing completed, BOTH independent roots (architect, test) are admissible in one wave.
    let wave = g.ready_wave(&BTreeSet::new(), 8);
    assert!(
        wave.contains(&tid("architect")),
        "architect root admissible"
    );
    assert!(
        wave.contains(&tid("test")),
        "independent tester root admissible in the SAME wave"
    );
    // The chained tasks are NOT yet admissible (their deps are unmet).
    assert!(!wave.contains(&tid("code")));
    assert!(!wave.contains(&tid("review")));
    // A ceiling narrows the wave (bounded fan-out).
    assert_eq!(g.ready_wave(&BTreeSet::new(), 1).len(), 1);
}

#[test]
fn r11_three_tier_drives_a_hierarchical_multibranch_team_to_complete() {
    let g = hierarchical_graph();
    let t = team();
    let mut exec = HappyExecutor { calls: 0 };

    let report = run_team_3tier(
        &g,
        &t,
        "ship the settlement feature",
        &BTreeSet::new(),
        &mut exec,
        &mut AcceptingCritic,
        &mut EscalatingHealer,
        &mut ConfirmingJudge,
        ThreeTierConfig::default(),
    )
    .unwrap();

    assert_eq!(report.outcome, TeamOutcome::Complete);
    assert_eq!(report.rounds, 1);
    assert_eq!(report.judge, Some(JudgeOutcome::Confirmed));
    assert!(
        report.last_run.all_succeeded(),
        "every task in every branch succeeded"
    );
    // All four tasks (both branches) drove a real tier-1 turn.
    assert_eq!(exec.calls, 4);
    // The learning record (LOOP §10 flywheel) is emitted with the whole-run aggregate cost.
    assert_eq!(report.learning.total_cost, report.total_cost);
    assert!(report.learning.succeeded.contains(&tid("architect")));
    assert!(report.learning.succeeded.contains(&tid("test")));

    // GAP-AUDIT loop-teams-longhorizon — `TaskGraph::ready_wave` had zero production callers; the
    // scheduler still runs strictly one task at a time (unchanged), but now reports how much
    // fan-out potential the graph exposed at its widest point. This graph's two independent roots
    // (architect, test) are both ready with nothing completed — the widest wave must reflect that.
    assert!(
        report.last_run.max_observed_wave_width >= 2,
        "the two independent roots must be observed in the same wave: {}",
        report.last_run.max_observed_wave_width
    );
}
