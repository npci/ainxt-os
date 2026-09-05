// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! RBI outsourcing **exit plan as a rehearsable, tested Long-Horizon shadow Program** (FI-03 §3.4;
//! Q1 / ADR-027).
//!
//! # Why this exists
//!
//! [`OutsourcingRegister`](crate::outsourcing::OutsourcingRegister) already *fences* a regulated
//! request away from any route whose exit plan is untested
//! ([`Eligibility::ExitUntested`](crate::outsourcing::Eligibility::ExitUntested)). But "tested" was
//! only a **date** an operator asserted: [`ExitRehearsal::At`](crate::outsourcing::ExitRehearsal). A
//! date is not a test — a stale runbook that has silently rotted still reads "fresh" until its cadence
//! lapses, and nothing ever *ran* it. RBI's exit-plan expectation (§3.4) is that the exit is
//! **rehearsable and rehearsed**: you can actually stand up the fallback, drain to it, repatriate the
//! data, verify deletion, and revoke the provider — end to end, without touching production.
//!
//! This module makes the exit plan an **executable program** rather than a wiki page:
//!
//! - [`ExitPlan`] is an *ordered* program of [`ExitStep`]s — a Long-Horizon runbook whose stages have a
//!   real prerequisite order (you cannot verify fallback health before you activate the fallback).
//! - [`ExitPlan::rehearse`] drives the program **in shadow** through an injected [`ShadowProbe`]: the
//!   probe exercises each stage against a standby/shadow environment and returns pass/fail. Execution
//!   is **fail-stop** — the first failed stage halts the program and every later stage is recorded as
//!   [`StepStatus::NotReached`], so a rehearsal that limps to step 3 and dies is *not* a pass. The
//!   `ShadowProbe` is the seam a deployment binds to real shadow-env execution (that live standby
//!   infra is `infra_gated`); the program, its ordering, its fail-stop semantics, and the freshness it
//!   produces are all pure and deterministic here.
//! - A rehearsal yields an [`ExitRehearsalReport`]; only an **all-pass** report freshens the route
//!   ([`OutsourcingRegister::record_exit_rehearsal`](crate::outsourcing::OutsourcingRegister::record_exit_rehearsal)).
//!   A failed rehearsal leaves the route [`ExitUntested`](crate::outsourcing::Eligibility::ExitUntested)
//!   — fail-safe: a broken exit cannot dress itself up as tested.
//!
//! No clock/rng/I/O — logical `now` is injected; the probe is the caller's.

use serde::{Deserialize, Serialize};

use crate::outsourcing::ExitRehearsal;

/// One rehearsable stage of a vendor-exit runbook (§3.4). Each is exercised against a **shadow**
/// (standby) environment during a rehearsal — never production.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExitStepKind {
    /// Stand up / confirm the fallback route (in-house model or alternate provider) is reachable.
    ActivateFallback,
    /// Drain live traffic off the provider onto the fallback (shadow: mirrored, not cut over).
    DrainTraffic,
    /// Validate the fallback meets the SLO/quality bar under the drained load.
    ValidateFallbackHealth,
    /// Repatriate data held by the provider back in-country (§8.1 residency).
    RepatriateData,
    /// Verify the provider has deleted the repatriated data (right-to-erasure / contract exit).
    VerifyProviderDeletion,
    /// Revoke the provider's credentials / access.
    RevokeCredentials,
}

impl ExitStepKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ExitStepKind::ActivateFallback => "activate-fallback",
            ExitStepKind::DrainTraffic => "drain-traffic",
            ExitStepKind::ValidateFallbackHealth => "validate-fallback-health",
            ExitStepKind::RepatriateData => "repatriate-data",
            ExitStepKind::VerifyProviderDeletion => "verify-provider-deletion",
            ExitStepKind::RevokeCredentials => "revoke-credentials",
        }
    }
}

/// One step of an [`ExitPlan`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitStep {
    pub id: String,
    pub kind: ExitStepKind,
    pub description: String,
}

impl ExitStep {
    pub fn new(id: &str, kind: ExitStepKind, description: &str) -> Self {
        Self {
            id: id.to_string(),
            kind,
            description: description.to_string(),
        }
    }
}

/// A route's exit plan — an *ordered* Long-Horizon program of rehearsable stages (§3.4 / ADR-027).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitPlan {
    /// The outsourcing route id this plan exits (`outsourcing.cloud.<provider>.<route>`).
    pub route_id: String,
    /// The ordered stages. Order is prerequisite order — the rehearsal runs them front-to-back and
    /// fail-stops on the first failure.
    pub steps: Vec<ExitStep>,
}

impl ExitPlan {
    /// An empty plan for `route_id` (add steps with [`with_step`](Self::with_step)).
    pub fn new(route_id: &str) -> Self {
        Self {
            route_id: route_id.to_string(),
            steps: Vec::new(),
        }
    }

    /// Append a stage (chainable). Insertion order is the program's execution/prerequisite order.
    pub fn with_step(mut self, step: ExitStep) -> Self {
        self.steps.push(step);
        self
    }

    /// The canonical 6-stage RBI exit runbook for `route_id`: activate fallback → drain → validate →
    /// repatriate → verify deletion → revoke. A deployment may author a bespoke plan; this is the
    /// sensible default a route inherits.
    pub fn standard(route_id: &str) -> Self {
        Self::new(route_id)
            .with_step(ExitStep::new(
                "activate",
                ExitStepKind::ActivateFallback,
                "stand up the in-house/alternate fallback route",
            ))
            .with_step(ExitStep::new(
                "drain",
                ExitStepKind::DrainTraffic,
                "mirror live traffic onto the fallback (shadow)",
            ))
            .with_step(ExitStep::new(
                "validate",
                ExitStepKind::ValidateFallbackHealth,
                "confirm the fallback meets the SLO/quality bar under load",
            ))
            .with_step(ExitStep::new(
                "repatriate",
                ExitStepKind::RepatriateData,
                "repatriate provider-held data in-country",
            ))
            .with_step(ExitStep::new(
                "verify-deletion",
                ExitStepKind::VerifyProviderDeletion,
                "verify the provider deleted the repatriated data",
            ))
            .with_step(ExitStep::new(
                "revoke",
                ExitStepKind::RevokeCredentials,
                "revoke the provider's credentials / access",
            ))
    }

    /// Rehearse the whole program **in shadow** at logical time `now`, driving each stage through
    /// `probe`. Fail-stop: the first failed stage halts execution and every later stage is
    /// [`StepStatus::NotReached`]. Returns an [`ExitRehearsalReport`] whose `passed` is true iff **every**
    /// stage passed — a partial rehearsal is not a tested exit.
    ///
    /// `needs_hot_wiring` (GAP-FIX gap6-responsibleai-cleanup, item 3 — investigated, not wired):
    /// this method itself has zero served callers, and — unlike the other two items in that round —
    /// there is genuinely no real trigger point to wire it into yet, on either composition-root crate:
    ///
    /// * No admin route or cadence tick anywhere in `ainxt-runtimed`/`ainxt-server` mentions
    ///   `exit_cadence`, `exit_rehearsal`, `ExitPlan`, or `ShadowProbe`. `main.rs`'s boot sequence
    ///   spawns several OTHER periodic sweeps (canary, tripwire re-score, retention, memory
    ///   condensation, …) but none for exit rehearsal.
    /// * [`crate::outsourcing::OutsourcingRegister::record_exit_rehearsal`] (the ONLY consumer of this
    ///   method's [`ExitRehearsalReport`] output) and [`crate::outsourcing::OutsourcingRegister::
    ///   exit_untested`] (which would name the routes due for one) are BOTH also zero-served-caller —
    ///   confirmed by the same grep this doc note is based on.
    /// * The one outsourcing-related served route, `POST /admin/outsourcing/register`
    ///   (`ainxt-server::outsourcing_register_admin_handler`), only lets an operator directly ASSERT a
    ///   `last_exit_rehearsal: ExitRehearsal` timestamp on (re-)registration — this is exactly the
    ///   "a date is not a test" gap this whole module's doc comment says `ExitPlan`/`rehearse` exists to
    ///   close, so that route is NOT a rehearsal-execution trigger point and wiring `rehearse` behind it
    ///   would misrepresent an operator's assertion as an executed rehearsal.
    ///
    /// Wiring this for real needs BOTH a genuine trigger (an admin "run the exit rehearsal for route
    /// X now" route, or a periodic cadence loop over `exit_untested`) AND a real [`ShadowProbe`] bound
    /// to live standby infra — the latter is `infra_gated` by this module's own design (see the module
    /// doc): no such standby-environment execution surface exists anywhere in this monorepo to bind to,
    /// so inventing one here would be forced wiring, not a real closure. Left as a follow-up.
    pub fn rehearse(&self, probe: &dyn ShadowProbe, now: u64) -> ExitRehearsalReport {
        let mut steps = Vec::with_capacity(self.steps.len());
        let mut halted = false;
        for step in &self.steps {
            let status = if halted {
                StepStatus::NotReached
            } else {
                match probe.rehearse_step(&self.route_id, step) {
                    Ok(()) => StepStatus::Passed,
                    Err(detail) => {
                        halted = true;
                        StepStatus::Failed(detail)
                    }
                }
            };
            steps.push(StepResult {
                step_id: step.id.clone(),
                kind: step.kind,
                status,
            });
        }
        let passed =
            !self.steps.is_empty() && steps.iter().all(|s| matches!(s.status, StepStatus::Passed));
        ExitRehearsalReport {
            route_id: self.route_id.clone(),
            at_tick: now,
            steps,
            passed,
        }
    }
}

/// The shadow-execution seam (§3.4): given a route and a stage, exercise it against the standby/shadow
/// environment and return `Ok(())` on success or `Err(detail)` on failure. A deployment binds this to
/// real shadow-env execution (that live standby infra is `infra_gated`); tests inject a deterministic
/// probe. The runtime never *runs* the exit against production — a rehearsal is always shadow.
pub trait ShadowProbe {
    /// Rehearse one stage in shadow. `Ok(())` = the stage succeeded; `Err(detail)` = it failed (PII-free
    /// detail recorded on the report).
    fn rehearse_step(&self, route_id: &str, step: &ExitStep) -> Result<(), String>;
}

/// The outcome of one rehearsed stage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "status", content = "detail")]
pub enum StepStatus {
    /// The stage succeeded in shadow.
    Passed,
    /// The stage failed (carries a PII-free failure detail).
    Failed(String),
    /// A prior stage failed, so this stage was never reached (fail-stop).
    NotReached,
}

/// The result of one rehearsed stage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepResult {
    pub step_id: String,
    pub kind: ExitStepKind,
    pub status: StepStatus,
}

/// The report of a full rehearsal (the auditable artifact §3.4 asks for — proof the exit was actually
/// exercised end-to-end, with the outcome of every stage).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitRehearsalReport {
    pub route_id: String,
    /// Logical tick the rehearsal ran at (the freshness stamp a passing rehearsal produces).
    pub at_tick: u64,
    pub steps: Vec<StepResult>,
    /// True iff every stage passed — only then is the exit "tested".
    pub passed: bool,
}

impl ExitRehearsalReport {
    /// The [`ExitRehearsal`] freshness stamp this report justifies: `At { at_tick }` on an all-pass
    /// rehearsal, `None` otherwise. A failed/partial rehearsal produces **no** freshness — the route
    /// stays fail-safe [`ExitUntested`](crate::outsourcing::Eligibility::ExitUntested).
    pub fn as_rehearsal(&self) -> Option<ExitRehearsal> {
        self.passed
            .then_some(ExitRehearsal::At { tick: self.at_tick })
    }

    /// The id of the first failed stage, if any (for the audit trail / operator drill-down).
    pub fn first_failure(&self) -> Option<&StepResult> {
        self.steps
            .iter()
            .find(|s| matches!(s.status, StepStatus::Failed(_)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A probe that fails exactly the named step kind (deterministic; stands in for shadow execution).
    struct FailAt(Option<ExitStepKind>);
    impl ShadowProbe for FailAt {
        fn rehearse_step(&self, _route: &str, step: &ExitStep) -> Result<(), String> {
            match self.0 {
                Some(k) if k == step.kind => Err(format!("shadow {} failed", step.kind.as_str())),
                _ => Ok(()),
            }
        }
    }

    #[test]
    fn all_pass_rehearsal_produces_freshness() {
        let plan = ExitPlan::standard("outsourcing.cloud.acme.chat");
        let report = plan.rehearse(&FailAt(None), 500);
        assert!(report.passed);
        assert_eq!(report.steps.len(), 6);
        assert_eq!(report.as_rehearsal(), Some(ExitRehearsal::At { tick: 500 }));
        assert!(report.first_failure().is_none());
    }

    #[test]
    fn fail_stop_marks_later_steps_not_reached_and_yields_no_freshness() {
        let plan = ExitPlan::standard("r");
        // Fail at "validate" (step 3): activate+drain pass, validate fails, the rest are NotReached.
        let report = plan.rehearse(&FailAt(Some(ExitStepKind::ValidateFallbackHealth)), 10);
        assert!(!report.passed);
        assert_eq!(
            report.as_rehearsal(),
            None,
            "a failed rehearsal produces no freshness"
        );
        assert!(matches!(report.steps[0].status, StepStatus::Passed));
        assert!(matches!(report.steps[1].status, StepStatus::Passed));
        assert!(matches!(report.steps[2].status, StepStatus::Failed(_)));
        assert!(matches!(report.steps[3].status, StepStatus::NotReached));
        assert!(matches!(report.steps[5].status, StepStatus::NotReached));
        assert_eq!(report.first_failure().unwrap().step_id, "validate");
    }

    #[test]
    fn empty_plan_never_passes() {
        // An exit plan with no stages is not a tested exit (a vacuous pass would be a fail-safe hole).
        let report = ExitPlan::new("r").rehearse(&FailAt(None), 1);
        assert!(!report.passed);
        assert_eq!(report.as_rehearsal(), None);
    }
}
