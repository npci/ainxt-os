// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Plan anti-thrash — change-justification, append-only revision history, freeze-on-thrash cooldown.
//!
//! Design: `docs/architecture/LOOP_AND_AGENT_TEAMS.md` §9 (plan stability / anti-thrash) and §6
//! (the *thrash* detector — structural churn, distinct from the tier-1 *stuck* detector).
//!
//! [`crate::Plan::replan_failed`] is the low-level replan primitive: bounded, cycle-safe, but it
//! carries **no** triggering signal and has **no** plan-level churn detector — the gap this module
//! closes (`gap_tracker` LOOP-10). [`RevisablePlan`] wraps a [`Plan`] and adds the three §9
//! stability disciplines the design mandates, all pure and deterministic:
//!
//! * **Change-justification** — every mutation must carry a triggering signal (which critic finding /
//!   judge gap / new context caused it); a signal-less mutation is **rejected at the API boundary**
//!   ([`RevisionError::MissingSignal`]) — the Planner cannot silently reshuffle "because it changed
//!   its mind".
//! * **Append-only revision history** — every accepted mutation appends a [`PlanRevision`] (never an
//!   in-place overwrite), so a Run's full planning history is replayable.
//! * **Freeze on thrash** — when churn across the last `churn_window` revisions exceeds
//!   `churn_threshold_pct` (§9's ">40% of tasks touched across 3 re-plans"), plan mutation is
//!   **frozen** until [`checkpoint_reached`](RevisablePlan::checkpoint_reached): the runtime must
//!   execute the current plan to its next natural checkpoint before one deliberate, consolidated
//!   re-plan is allowed — replacing a stream of micro-edits with a single considered one.
//!
//! # GAP-AUDIT gap6-planner-assurance-revision (item 2) — re-audited, no real caller to wire into
//!
//! [`RevisablePlan`]/[`drive_revisable`] wrap [`Plan`] (the LOOP-era `Step`/`Alternative`/
//! `replan_failed` structure), not the LONG_HORIZON-era [`crate::program::Program`]/
//! [`crate::program::NodeDecl`] graph the served daemon actually drives (`ainxt-runtimed`'s
//! `drive_served_program_governed`/`run_program_durable`, both reached from `ainxt-runtimed`'s
//! `assemble_*` composition roots). A workspace-wide search confirms `crate::Plan` (and therefore
//! `RevisablePlan`, which only wraps it) has **zero** references anywhere outside this crate: not in
//! `ainxt-teams` (whose `TaskGraph`/`Task` — the team loop's own graph — never restructures itself
//! mid-run; a tier-3 `JudgeOutcome::Gap` re-runs the SAME task set for another round, it never adds or
//! removes a `Task`) and not in `ainxt-workforce` (no `Plan`/`replan`/`thrash`/`churn` concept exists
//! there at all). The Program graph's OWN retry/quarantine mechanism (`VERIFY_ATTEMPT_CAP` + durable
//! poison-node quarantine, ADR-027 §9) is real and served, but it is a structurally different type —
//! bounded attempts on a FIXED node, never a `Plan`-shaped structural edit (add/remove/reorder steps)
//! — so `RevisablePlan` cannot be wired around it without inventing a new bridge from scratch, which is
//! exactly the fabrication this round is chartered to avoid. The ONE non-test, non-`revision.rs` caller
//! of `Plan::replan_failed` anywhere in the codebase is `driver.rs`'s
//! `confirm_node_escalation_via_plan_lifecycle` — a narrow, synthetic helper that builds a throwaway
//! single-step `Plan` purely to reuse the escalation state machine's `Escalated` outcome for a
//! `Program` node's poison-quarantine decision; it is discarded immediately after and never becomes a
//! `RevisablePlan`, never calls `revise()`, and carries no anti-thrash concept.
//!
//! Conclusion: this module was built ahead of a caller that does not exist yet. No code change is the
//! honest fix here — wiring a fabricated caller into `RevisablePlan` merely to close this out would be
//! the same "declared reachable, not actually reachable" gap this audit series exists to catch, just
//! moved one level up. The day a real Plan-shaped (add/remove/reorder-step) replanning loop is built on
//! the served path, this module is exactly what should gate it.

use crate::{Alternative, Plan, PlanError, Step, StepId};
use std::collections::BTreeSet;

/// Default churn window: the number of consecutive revisions the thrash detector looks back over.
pub const DEFAULT_CHURN_WINDOW: usize = 3;
/// Default churn threshold: >40% of tasks touched across the window freezes the plan (§9).
pub const DEFAULT_CHURN_THRESHOLD_PCT: u32 = 40;

/// Tunable thrash-detector config (§9). Illustrative defaults; ADR notes real workloads differ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThrashConfig {
    pub churn_window: usize,
    pub churn_threshold_pct: u32,
}

impl Default for ThrashConfig {
    fn default() -> Self {
        ThrashConfig {
            churn_window: DEFAULT_CHURN_WINDOW,
            churn_threshold_pct: DEFAULT_CHURN_THRESHOLD_PCT,
        }
    }
}

/// One append-only plan revision (§9 plan persistence — never overwritten in place).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanRevision {
    /// 0-based revision number (0 = the baseline snapshot).
    pub revision: u32,
    /// The triggering signal that justified this change (§9 change-justification). The baseline's is
    /// a synthetic `"baseline"`.
    pub signal: String,
    /// The step ids this revision added/removed/changed relative to the prior revision.
    pub touched: BTreeSet<StepId>,
    /// Snapshot of the plan's step ids at this revision (for replay / churn accounting).
    pub step_ids: Vec<StepId>,
}

/// The outcome of a [`RevisablePlan::revise`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReviseOutcome {
    /// The mutation was applied and recorded as a new revision.
    Applied { revision: u32 },
    /// The mutation would push churn over the threshold: it was **not applied**, and the plan is now
    /// frozen until a checkpoint (§9). The Planner must execute the current plan, then consolidate.
    FrozenOnThrash { touched_pct: u32, window: usize },
}

/// Why a revision was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevisionError {
    /// No triggering signal was supplied (§9 change-justification — rejected at the API boundary).
    MissingSignal,
    /// The plan is frozen for a thrash cooldown; a checkpoint must be reached first (§9).
    Frozen,
    /// The underlying plan mutation failed (cycle / dangling dep / budget / …). Plan left unchanged.
    Plan(PlanError),
}

impl std::fmt::Display for RevisionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RevisionError::MissingSignal => {
                f.write_str("plan mutation rejected: no triggering signal (change-justification)")
            }
            RevisionError::Frozen => {
                f.write_str("plan mutation frozen for thrash cooldown; reach a checkpoint first")
            }
            RevisionError::Plan(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for RevisionError {}

/// A [`Plan`] with the §9 anti-thrash disciplines layered on. Wraps rather than replaces the plan so
/// the low-level primitives stay available; every *mutation* goes through [`revise`](Self::revise).
#[derive(Debug, Clone)]
pub struct RevisablePlan {
    plan: Plan,
    revisions: Vec<PlanRevision>,
    frozen: bool,
    config: ThrashConfig,
}

impl RevisablePlan {
    /// Wrap a plan, recording its current shape as the baseline revision 0.
    pub fn new(plan: Plan, config: ThrashConfig) -> Self {
        let step_ids: Vec<StepId> = plan.steps().iter().map(|s| s.id.clone()).collect();
        let baseline = PlanRevision {
            revision: 0,
            signal: "baseline".to_string(),
            touched: BTreeSet::new(),
            step_ids,
        };
        RevisablePlan {
            plan,
            revisions: vec![baseline],
            frozen: false,
            config,
        }
    }

    /// The wrapped plan (read-only).
    pub fn plan(&self) -> &Plan {
        &self.plan
    }

    /// Execution-state transitions are **not** plan mutations and carry no change-justification (§9
    /// distinguishes *structural churn* from ordinary progress): a step starting, finishing, or
    /// failing is progress, not a re-plan. These delegate straight to the wrapped plan; only
    /// structural re-planning goes through [`revise`](Self::revise).
    pub fn mark_running(&mut self, id: &StepId) -> Result<(), PlanError> {
        self.plan.mark_running(id)
    }
    pub fn mark_done(&mut self, id: &StepId) -> Result<(), PlanError> {
        self.plan.mark_done(id)
    }
    pub fn mark_failed(&mut self, id: &StepId) -> Result<(), PlanError> {
        self.plan.mark_failed(id)
    }

    /// The append-only revision history (§9).
    pub fn revisions(&self) -> &[PlanRevision] {
        &self.revisions
    }

    /// True iff the plan is currently frozen for a thrash cooldown (§9).
    pub fn is_frozen(&self) -> bool {
        self.frozen
    }

    /// Signal that the current plan reached its next natural checkpoint (a task completion or hard
    /// failure), lifting a thrash freeze so one deliberate, consolidated re-plan is allowed (§9).
    pub fn checkpoint_reached(&mut self) {
        self.frozen = false;
    }

    /// Apply a plan mutation under the §9 disciplines.
    ///
    /// * `signal` is the **required** triggering justification; `None` ⇒ [`RevisionError::MissingSignal`].
    /// * If the plan is frozen ⇒ [`RevisionError::Frozen`] until [`checkpoint_reached`](Self::checkpoint_reached).
    /// * `mutate` runs against a **clone**, so a failing mutation leaves the plan untouched.
    /// * On success the churn over the last `churn_window` revisions is computed; if it would exceed
    ///   `churn_threshold_pct` the mutation is **rolled back**, the plan is frozen, and
    ///   [`ReviseOutcome::FrozenOnThrash`] is returned. Otherwise the mutation is committed and an
    ///   append-only [`PlanRevision`] recorded.
    pub fn revise<F>(
        &mut self,
        signal: Option<&str>,
        mutate: F,
    ) -> Result<ReviseOutcome, RevisionError>
    where
        F: FnOnce(&mut Plan) -> Result<(), PlanError>,
    {
        let signal = signal.ok_or(RevisionError::MissingSignal)?;
        if self.frozen {
            return Err(RevisionError::Frozen);
        }

        let before: Vec<(StepId, String, Vec<StepId>)> = self
            .plan
            .steps()
            .iter()
            .map(|s| (s.id.clone(), s.description.clone(), s.deps.clone()))
            .collect();

        // Apply against a clone so a failed mutation is a no-op.
        let mut candidate = self.plan.clone();
        mutate(&mut candidate).map_err(RevisionError::Plan)?;

        let touched = diff_touched(&before, &candidate);

        // Churn accounting across the last `window` revisions PLUS this proposed one.
        let window = self.config.churn_window.max(1);
        let mut union: BTreeSet<StepId> = touched.clone();
        for rev in self.revisions.iter().rev().take(window.saturating_sub(1)) {
            union.extend(rev.touched.iter().cloned());
        }
        let total = candidate.steps().len().max(before.len()).max(1);
        let touched_pct = ((union.len() as u128 * 100) / total as u128) as u32;

        if touched_pct > self.config.churn_threshold_pct {
            // Freeze WITHOUT applying — force execution then one consolidated re-plan (§9).
            self.frozen = true;
            return Ok(ReviseOutcome::FrozenOnThrash {
                touched_pct,
                window,
            });
        }

        // Commit.
        self.plan = candidate;
        let revision = self.revisions.len() as u32;
        let step_ids: Vec<StepId> = self.plan.steps().iter().map(|s| s.id.clone()).collect();
        self.revisions.push(PlanRevision {
            revision,
            signal: signal.to_string(),
            touched,
            step_ids,
        });
        Ok(ReviseOutcome::Applied { revision })
    }
}

// ---------------------------------------------------------------------------
// The executing loop that DRIVES the anti-thrash detector (§9 / LOOP §6)
// ---------------------------------------------------------------------------

/// What the executing loop's step seam reports for one attempt (§9 / LOOP §6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepExecution {
    /// The step's work succeeded.
    Succeeded,
    /// The step failed; the loop must re-plan it with `alternative`, justified by `signal` (the
    /// critic finding / judge gap that triggered the change — §9 change-justification).
    FailedReplan {
        signal: String,
        alternative: Alternative,
    },
    /// The failure revealed that a materialized graph's independence assumption was WRONG (LOOP §3:
    /// "the Planner can flatten it back to a list mid-run if a node fails in a way that reveals the
    /// independence assumption was wrong"). The loop flattens the plan back to a strictly sequential
    /// list ([`Plan::flatten`]) through the SAME [`RevisablePlan::revise`] disciplines — the flatten
    /// is itself a governed, justified, append-only-recorded mutation, never a silent bypass of §9.
    FailedFlatten { signal: String },
}

/// The executing-loop step seam. The parent backs this with a real base-loop Run; the loop wraps every
/// re-plan in the [`RevisablePlan`] anti-thrash disciplines so plan churn is governed *as it executes*.
pub trait RevisableExecutor {
    fn execute(&mut self, step: &Step) -> StepExecution;
}

/// The terminal report of [`drive_revisable`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevisableDriveReport {
    /// Every step reached `Done`.
    pub completed: bool,
    /// The thrash detector froze the plan mid-execution (§9): churn crossed the threshold and the loop
    /// stopped re-planning until a checkpoint, rather than emitting a stream of micro-edits.
    pub froze: bool,
    /// How many re-plans were applied (each an append-only [`PlanRevision`]) before termination.
    pub revisions: usize,
}

/// Drive a [`RevisablePlan`] through an **executing loop** with the §9 anti-thrash detector wired in
/// (the gap: [`RevisablePlan`] existed but nothing *drove* it — the detector was callable, never
/// exercised by a running plan). Each ready step is executed via the `exec` seam; a success is an
/// ordinary execution transition (and a natural checkpoint that lifts any freeze), while a failure is
/// re-planned **through [`RevisablePlan::revise`]** so the change-justification, append-only history,
/// and freeze-on-thrash cooldown all bind live. When churn crosses the threshold the loop observes
/// [`ReviseOutcome::FrozenOnThrash`] and stops churning (honest partial), never looping forever.
/// Deterministic given the seam and the config — a test property, not a hope.
pub fn drive_revisable<E: RevisableExecutor>(
    rp: &mut RevisablePlan,
    exec: &mut E,
    max_iters: usize,
) -> RevisableDriveReport {
    let mut revisions = 0usize;
    let mut froze = false;
    for _ in 0..max_iters {
        let Some(id) = rp.plan().ready_step_ids().into_iter().next() else {
            break;
        };
        // Execution transitions are progress, not re-plans — they bypass revise() (§9).
        let _ = rp.mark_running(&id);
        let step = rp.plan().step(&id).expect("ready step present").clone();
        match exec.execute(&step) {
            StepExecution::Succeeded => {
                let _ = rp.mark_done(&id);
                // A task completion is the natural checkpoint that lifts a thrash freeze (§9).
                rp.checkpoint_reached();
            }
            StepExecution::FailedReplan {
                signal,
                alternative,
            } => {
                let _ = rp.mark_failed(&id);
                if rp.is_frozen() {
                    froze = true;
                    break; // frozen: no more re-plans until a checkpoint — stop churning.
                }
                let rid = id.clone();
                match rp.revise(Some(&signal), move |p| {
                    p.replan_failed(&rid, alternative).map(|_| ())
                }) {
                    Ok(ReviseOutcome::Applied { .. }) => revisions += 1,
                    Ok(ReviseOutcome::FrozenOnThrash { .. }) => {
                        froze = true;
                        break;
                    }
                    Err(_) => break,
                }
            }
            StepExecution::FailedFlatten { signal } => {
                let _ = rp.mark_failed(&id);
                if rp.is_frozen() {
                    froze = true;
                    break; // frozen: no more re-plans until a checkpoint — stop churning.
                }
                // LOOP §3: flatten the (over-)materialized graph back to a sequential list — through
                // the SAME governed `revise` seam as an ordinary re-plan, so the flatten is justified
                // and append-only recorded, never a silent structural bypass of §9.
                match rp.revise(Some(&signal), |p| {
                    *p = p.flatten()?;
                    Ok(())
                }) {
                    Ok(ReviseOutcome::Applied { .. }) => revisions += 1,
                    Ok(ReviseOutcome::FrozenOnThrash { .. }) => {
                        froze = true;
                        break;
                    }
                    Err(_) => break,
                }
            }
        }
    }
    RevisableDriveReport {
        completed: rp.plan().is_complete(),
        froze,
        revisions,
    }
}

/// Steps that were added, removed, or had their description/deps changed between `before` and the
/// candidate plan — the §9 churn unit.
fn diff_touched(before: &[(StepId, String, Vec<StepId>)], after: &Plan) -> BTreeSet<StepId> {
    let mut touched = BTreeSet::new();
    let after_ids: BTreeSet<&StepId> = after.steps().iter().map(|s| &s.id).collect();
    let before_ids: BTreeSet<&StepId> = before.iter().map(|(id, _, _)| id).collect();

    // Added steps.
    for s in after.steps() {
        if !before_ids.contains(&s.id) {
            touched.insert(s.id.clone());
        }
    }
    // Removed steps.
    for (id, _, _) in before {
        if !after_ids.contains(id) {
            touched.insert(id.clone());
        }
    }
    // Changed steps (description or deps differ).
    for (id, desc, deps) in before {
        if let Some(a) = after.step(id) {
            if &a.description != desc || &a.deps != deps {
                touched.insert(id.clone());
            }
        }
    }
    touched
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Goal, PlanConfig, Step, StepStatus};

    fn sid(s: &str) -> StepId {
        StepId::new(s)
    }
    fn step(id: &str, deps: &[&str]) -> Step {
        Step::new(id, id, deps.iter().map(|d| sid(d)).collect())
    }
    fn base_plan(n: usize) -> Plan {
        // A flat list of n independent steps.
        let steps: Vec<Step> = (0..n).map(|i| step(&format!("s{i}"), &[])).collect();
        Plan::new(Goal::new("g", "goal"), steps, PlanConfig::default()).unwrap()
    }

    // ---- change-justification --------------------------------------------

    #[test]
    fn gap_loop_10_mutation_without_a_signal_is_rejected() {
        let mut rp = RevisablePlan::new(base_plan(4), ThrashConfig::default());
        let err = rp
            .revise(None, |p| {
                p.mark_running(&sid("s0"))?;
                Ok(())
            })
            .unwrap_err();
        assert_eq!(err, RevisionError::MissingSignal);
        // A signal-less mutation never touched the plan.
        assert_eq!(rp.plan().status(&sid("s0")), Some(StepStatus::Pending));
        assert_eq!(rp.revisions().len(), 1); // baseline only
    }

    #[test]
    fn gap_loop_10_revisions_are_append_only_with_their_signal() {
        use crate::Alternative;
        let mut rp = RevisablePlan::new(base_plan(10), ThrashConfig::default());
        // A structural re-plan of s0 (new description) — execution transitions happen outside revise.
        rp.mark_failed(&sid("s0")).unwrap();
        rp.revise(Some("critic: s0 needs a prereq"), |p| {
            p.replan_failed(
                &sid("s0"),
                Alternative::replace("s0 alternate route", vec![]),
            )
            .map(|_| ())
        })
        .unwrap();
        rp.mark_failed(&sid("s1")).unwrap();
        rp.revise(Some("judge gap: s1 incomplete"), |p| {
            p.replan_failed(&sid("s1"), Alternative::replace("s1 alternate", vec![]))
                .map(|_| ())
        })
        .unwrap();

        assert_eq!(rp.revisions().len(), 3); // baseline + 2
        assert_eq!(rp.revisions()[1].signal, "critic: s0 needs a prereq");
        assert_eq!(rp.revisions()[2].signal, "judge gap: s1 incomplete");
        // Each revision recorded the structurally-touched step.
        assert!(rp.revisions()[1].touched.contains(&sid("s0")));
        assert!(rp.revisions()[2].touched.contains(&sid("s1")));
    }

    // ---- freeze on thrash -------------------------------------------------

    #[test]
    fn gap_loop_10_excessive_churn_freezes_the_plan_until_a_checkpoint() {
        use crate::Alternative;
        // 4 steps; structurally re-planning 3 of them in one revision is 75% churn > 40% -> freeze.
        let mut rp = RevisablePlan::new(base_plan(4), ThrashConfig::default());
        rp.mark_failed(&sid("s0")).unwrap();
        rp.mark_failed(&sid("s1")).unwrap();
        rp.mark_failed(&sid("s2")).unwrap();
        let out = rp
            .revise(Some("planner reshuffle"), |p| {
                p.replan_failed(&sid("s0"), Alternative::replace("s0 v2", vec![]))?;
                p.replan_failed(&sid("s1"), Alternative::replace("s1 v2", vec![]))?;
                p.replan_failed(&sid("s2"), Alternative::replace("s2 v2", vec![]))?;
                Ok(())
            })
            .unwrap();
        match out {
            ReviseOutcome::FrozenOnThrash { touched_pct, .. } => assert!(touched_pct > 40),
            other => panic!("expected FrozenOnThrash, got {other:?}"),
        }
        assert!(rp.is_frozen());
        // The thrashing mutation was NOT applied (description unchanged, still failed).
        assert_eq!(rp.plan().step(&sid("s0")).unwrap().description, "s0");
        assert_eq!(rp.plan().status(&sid("s0")), Some(StepStatus::Failed));
        // Revisions unchanged (baseline only) — no micro-edit recorded.
        assert_eq!(rp.revisions().len(), 1);

        // While frozen, further mutations are rejected — must reach a checkpoint first.
        let err = rp
            .revise(Some("another edit"), |p| {
                p.replan_failed(&sid("s3"), Alternative::replace("x", vec![]))
                    .map(|_| ())
            })
            .unwrap_err();
        assert_eq!(err, RevisionError::Frozen);

        // After the checkpoint, one deliberate, consolidated re-plan is allowed again.
        rp.checkpoint_reached();
        assert!(!rp.is_frozen());
        let out = rp
            .revise(Some("consolidated re-plan after checkpoint"), |p| {
                p.replan_failed(&sid("s0"), Alternative::replace("s0 consolidated", vec![]))
                    .map(|_| ())
            })
            .unwrap();
        assert!(matches!(out, ReviseOutcome::Applied { .. }));
    }

    #[test]
    fn gap_loop_10_a_failing_mutation_is_a_noop_and_records_no_revision() {
        let mut rp = RevisablePlan::new(base_plan(3), ThrashConfig::default());
        // Marking an unknown step fails; the revision must not be recorded.
        let err = rp
            .revise(Some("bad edit"), |p| p.mark_running(&sid("ghost")))
            .unwrap_err();
        assert!(matches!(err, RevisionError::Plan(_)));
        assert_eq!(rp.revisions().len(), 1);
        assert!(!rp.is_frozen());
    }
}
