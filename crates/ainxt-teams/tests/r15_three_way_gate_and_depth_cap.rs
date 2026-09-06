// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-15 (`loop-teams-longhorizon` gaps):
//!
//! 1. **HIGH — three non-substitutable proofs / anti-sycophancy independent Judge** (LOOP §5/§7,
//!    ADR-027 §6). Before this round, [`run_team_3tier`]'s `Complete` decision rested on the
//!    tier-3 [`GoalJudge`] ALONE — a judge talked into confirming a stubbed/off-goal deliverable
//!    (the textbook sycophancy failure) could single-handedly complete the Run. Fail-before:
//!    [`run_team_3tier_verified`], [`DeterministicGate`], [`AdversarialGate`] did not exist; the
//!    only entrypoint ([`run_team_3tier`]) completes on the Judge's word alone (demonstrated below
//!    as the honest baseline, not a bug in that entrypoint — it never claimed more). Pass-after:
//!    [`run_team_3tier_verified`] requires the deterministic + adversarial proofs ALSO be green,
//!    reusing `ainxt_planner`'s real (non-fabricated) offline analysers.
//!
//! 2. **LOW — tier-2 per-step critic and hierarchy depth-cap enforcement** (LOOP §4 depth cap, §5
//!    tier-2). [`AgentInvocation::validate_depth`] existed as a pure check but nothing called it —
//!    the kernel boundary never enforced the cap. Fail-before: an executor could return an
//!    arbitrarily deep sub-agent call tree and the 3-tier loop accepted it silently. Pass-after: the
//!    depth cap is checked on every task attempt in [`run_team_3tier`]/[`run_team_3tier_verified`]
//!    and a violation is a structured, surfaced failure, not silently accepted.

use ainxt_teams::tiers::{
    run_team_3tier, run_team_3tier_verified, AcceptingCritic, BreakerAdversarialGate,
    ContentDeterministicGate, Deliverable, DeterministicGate, EscalatingHealer, GoalJudge,
    JudgeOutcome, StepAttempt, StepContext, StepResult, TaskExecutor, TeamOutcome, ThreeTierConfig,
};
use ainxt_teams::{AgentInvocation, Cost, Role, Task, TaskGraph, TaskId, Team};
use ainxt_types::Tier as ModelTier;

fn tid(s: &str) -> TaskId {
    TaskId::from(s)
}

fn team() -> Team {
    let mut t = Team::new();
    t.add_role(Role::new("coder", ModelTier::Medium, ["edit_code"]));
    t
}

fn one_task_graph() -> TaskGraph {
    let mut g = TaskGraph::new();
    g.add_task(
        Task::new("impl", "coder")
            .describe("validate the settlement amount and reject negative values")
            .accepts("compiles"),
    )
    .unwrap();
    g
}

fn no_seed() -> std::collections::BTreeSet<String> {
    std::collections::BTreeSet::new()
}

/// A judge that ALWAYS confirms, regardless of content — models a judge talked into agreement
/// (the sycophancy failure the three-way gate exists to catch).
struct AlwaysConfirmJudge;
impl GoalJudge for AlwaysConfirmJudge {
    fn audit(&mut self, _d: &Deliverable) -> JudgeOutcome {
        JudgeOutcome::Confirmed
    }
}

/// An executor whose task output is a bare, unfinished stub — the kind of deliverable a real
/// deterministic/adversarial check must catch even when the Judge confirms it.
struct StubExecutor;
impl TaskExecutor for StubExecutor {
    fn run_task(&mut self, task: &Task, _ctx: &StepContext) -> StepAttempt {
        StepAttempt {
            invocation: AgentInvocation::leaf(task.role.clone(), Cost::new(1, 1, 0, 0)),
            result: StepResult::Produced {
                output_ref: "fn validate() { todo!() }".to_string(),
            },
        }
    }
}

/// An executor whose task output is real, substantive, on-goal, and safe — must pass both the new
/// gates AND the judge.
struct SubstantiveExecutor;
impl TaskExecutor for SubstantiveExecutor {
    fn run_task(&mut self, task: &Task, _ctx: &StepContext) -> StepAttempt {
        StepAttempt {
            invocation: AgentInvocation::leaf(task.role.clone(), Cost::new(1, 1, 0, 0)),
            result: StepResult::Produced {
                output_ref: "fn validate(amount: i64) -> Result<(), Error> { if amount < 0 { return Err(Error::Negative); } Ok(()) }".to_string(),
            },
        }
    }
}

// ---- gap 1: anti-sycophancy three-way gate ---------------------------------------------------

#[test]
fn r15_baseline_judge_alone_completes_on_a_stub_the_new_gates_would_catch() {
    // The pre-round-15 entrypoint never claimed more than "the fresh-context judge confirmed it" —
    // this documents that honest, narrower contract as the baseline the new entrypoint improves on.
    let g = one_task_graph();
    let t = team();
    let mut exec = StubExecutor;
    let report = run_team_3tier(
        &g,
        &t,
        "validate the settlement amount and reject negative values",
        &no_seed(),
        &mut exec,
        &mut AcceptingCritic,
        &mut EscalatingHealer,
        &mut AlwaysConfirmJudge,
        ThreeTierConfig::default(),
    )
    .unwrap();
    assert_eq!(report.outcome, TeamOutcome::Complete);
}

#[test]
fn r15_verified_gate_blocks_a_confidently_wrong_confirm_on_a_stub() {
    // Same stub, same always-confirming judge — but through the NEW three-way-gated entrypoint the
    // deterministic content check (an unfinished-stub marker) refuses to let the judge's confirm
    // stand alone, so the Run does NOT complete.
    let g = one_task_graph();
    let t = team();
    let mut exec = StubExecutor;
    let mut det_gate = ContentDeterministicGate;
    let mut adv_gate = BreakerAdversarialGate;
    let report = run_team_3tier_verified(
        &g,
        &t,
        "validate the settlement amount and reject negative values",
        &no_seed(),
        &mut exec,
        &mut AcceptingCritic,
        &mut EscalatingHealer,
        &mut AlwaysConfirmJudge,
        &mut det_gate,
        &mut adv_gate,
        ThreeTierConfig {
            max_judge_rounds: 1,
            ..ThreeTierConfig::default()
        },
    )
    .unwrap();
    assert!(
        matches!(report.outcome, TeamOutcome::Capped { .. }),
        "expected Capped, got {:?}",
        report.outcome
    );
}

#[test]
fn r15_verified_gate_admits_a_real_substantive_deliverable() {
    // The new gates must not become a false-positive machine: real, on-goal, safe work with a
    // confirming judge still completes.
    let g = one_task_graph();
    let t = team();
    let mut exec = SubstantiveExecutor;
    let mut det_gate = ContentDeterministicGate;
    let mut adv_gate = BreakerAdversarialGate;
    let report = run_team_3tier_verified(
        &g,
        &t,
        "validate the settlement amount and reject negative values",
        &no_seed(),
        &mut exec,
        &mut AcceptingCritic,
        &mut EscalatingHealer,
        &mut AlwaysConfirmJudge,
        &mut det_gate,
        &mut adv_gate,
        ThreeTierConfig::default(),
    )
    .unwrap();
    assert_eq!(report.outcome, TeamOutcome::Complete);
}

#[test]
fn r15_deterministic_gate_alone_is_a_real_content_check_not_fabricated() {
    let d_good = Deliverable {
        goal: "do the thing".into(),
        acceptance_criteria: Default::default(),
        outputs: [(
            tid("t"),
            "a real, non-empty, finished implementation".to_string(),
        )]
        .into_iter()
        .collect(),
    };
    let d_bad = Deliverable {
        goal: "do the thing".into(),
        acceptance_criteria: Default::default(),
        outputs: [(tid("t"), "todo!()".to_string())].into_iter().collect(),
    };
    let mut gate = ContentDeterministicGate;
    assert!(gate.check(&d_good).compiled);
    assert!(!gate.check(&d_bad).compiled);
    assert!(!gate.check(&d_bad).blocking_findings.is_empty());
}

// ---- gap 2: hierarchy depth-cap enforcement at the kernel boundary ----------------------------

/// An executor that returns a sub-agent invocation tree deeper than the configured cap — models an
/// agent-spawns-agent recursion runaway.
struct RunawayDepthExecutor;
impl TaskExecutor for RunawayDepthExecutor {
    fn run_task(&mut self, task: &Task, _ctx: &StepContext) -> StepAttempt {
        // depth 3 sub-tree (sub1 -> sub2 -> sub3); root wraps it as a child -> root depth = 1 + 3 =
        // 4, exceeding the default cap (3).
        let deep = AgentInvocation::leaf("sub1", Cost::ZERO).with_child(
            AgentInvocation::leaf("sub2", Cost::ZERO)
                .with_child(AgentInvocation::leaf("sub3", Cost::ZERO)),
        );
        StepAttempt {
            invocation: deep,
            result: StepResult::Produced {
                output_ref: format!("artifact://{}", task.id),
            },
        }
    }
}

#[test]
fn r15_hierarchy_depth_cap_enforced_at_kernel_boundary() {
    let g = one_task_graph();
    let t = team();
    let mut exec = RunawayDepthExecutor;
    let report = run_team_3tier(
        &g,
        &t,
        "ship it",
        &no_seed(),
        &mut exec,
        &mut AcceptingCritic,
        &mut EscalatingHealer,
        &mut AlwaysConfirmJudge,
        ThreeTierConfig {
            max_attempts_per_task: 1,
            max_judge_rounds: 1,
            ..ThreeTierConfig::default()
        },
    )
    .unwrap();

    // The runaway-depth attempt is refused, not silently accepted — the task fails and the Run is
    // an honest Capped, never a fabricated Complete built on an unenforced depth cap.
    assert!(matches!(report.outcome, TeamOutcome::Capped { .. }));
    assert!(
        report.last_run.state_of(&tid("impl")).is_some(),
        "the task must have been scheduled and attempted"
    );
}

#[test]
fn r15_within_cap_invocation_tree_is_accepted() {
    // A depth-2 sub-tree (root wraps a depth-1 leaf -> root depth 2) is comfortably within the
    // default cap of 3 and must NOT be refused.
    struct ShallowExecutor;
    impl TaskExecutor for ShallowExecutor {
        fn run_task(&mut self, task: &Task, _ctx: &StepContext) -> StepAttempt {
            StepAttempt {
                invocation: AgentInvocation::leaf(task.role.clone(), Cost::ZERO)
                    .with_child(AgentInvocation::leaf("helper", Cost::ZERO)),
                result: StepResult::Produced {
                    output_ref: format!("artifact://{}", task.id),
                },
            }
        }
    }
    let g = one_task_graph();
    let t = team();
    let mut exec = ShallowExecutor;
    let report = run_team_3tier(
        &g,
        &t,
        "ship it",
        &no_seed(),
        &mut exec,
        &mut AcceptingCritic,
        &mut EscalatingHealer,
        &mut AlwaysConfirmJudge,
        ThreeTierConfig::default(),
    )
    .unwrap();
    assert_eq!(report.outcome, TeamOutcome::Complete);
}
