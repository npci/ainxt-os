// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R11 — two regulated-FI gap closures, fail-before / pass-after:
//!
//! 1. `r11_rehearsed_exit_plan_flips_route_eligibility` (§3.4 / ADR-027) — a route's exit plan is a
//!    rehearsable Long-Horizon shadow Program, not a date. A regulated request is fenced away from a
//!    route whose exit is untested; running the exit plan's rehearsal in shadow (all stages pass)
//!    records freshness on the register and FLIPS eligibility to Eligible. A rehearsal that fail-stops
//!    mid-program produces NO freshness — the route stays ExitUntested (fail-safe).
//!    Fail-before: `ExitPlan` / `rehearse` / `OutsourcingRegister::record_exit_rehearsal` did not exist;
//!    exit freshness could only be asserted as a bare date.
//!
//! 2. `r11_dpia_ci_gate_blocks_prod_allows_dev` (§4.1) — the DPIA-per-feature gate as a CI promotion
//!    gate: a personal-data feature promotes freely to dev, but the promotion JOB to env/prod is
//!    blocked until an approved, current DPIA is on record; a material data-processing change
//!    re-blocks it. An un-inventoried feature fails closed for env/prod.
//!    Fail-before: `DpiaCiGate` / `PromotionTarget` did not exist — DPIA was a free function no
//!    promotion job gated on.

use ainxt_responsibleai::dpia::{
    Dpia, DpiaCiGate, DpiaGateRefusal, FeatureProfile, PromotionTarget,
};
use ainxt_responsibleai::exit_plan::{ExitPlan, ExitStep, ExitStepKind, ShadowProbe};
use ainxt_responsibleai::outsourcing::{
    Eligibility, ExitRehearsal, OutsourcingArrangement, OutsourcingRegister,
};
use ainxt_types::DataClass;

// ============================================================================
// (1) §3.4 — rehearsed exit plan flips a route's eligibility
// ============================================================================

/// A deterministic shadow probe that fails exactly one named stage (or none).
struct ShadowStub(Option<ExitStepKind>);
impl ShadowProbe for ShadowStub {
    fn rehearse_step(&self, _route: &str, step: &ExitStep) -> Result<(), String> {
        match self.0 {
            Some(k) if k == step.kind => Err("shadow stage failed".into()),
            _ => Ok(()),
        }
    }
}

fn regulated_route(route_id: &str) -> OutsourcingArrangement {
    OutsourcingArrangement::new(
        route_id,
        "Acme Cloud Pvt Ltd",        // provider legal entity
        DataClass::RegulatedPayment, // permitted ceiling
        "in",                        // residency
        Vec::new(),                  // sub-processors
        "exit-plan-ref",
        "acme",               // concentration tag
        ExitRehearsal::Never, // exit NOT YET rehearsed
    )
}

#[test]
fn r11_rehearsed_exit_plan_flips_route_eligibility() {
    let route_id = "outsourcing.cloud.acme.chat";
    let mut reg = OutsourcingRegister::new(10_000); // generous cadence
    reg.upsert(regulated_route(route_id));

    // A regulated request is fenced away from the route: its exit plan is untested.
    assert_eq!(
        reg.eligibility(route_id, DataClass::RegulatedPayment, "in", 500),
        Eligibility::ExitUntested,
        "an unrehearsed exit plan is a fail-safe exclusion for a regulated request"
    );

    // A FAILED shadow rehearsal (fail-stops at 'validate') does NOT freshen — still ExitUntested.
    let plan = ExitPlan::standard(route_id);
    let failed = plan.rehearse(&ShadowStub(Some(ExitStepKind::ValidateFallbackHealth)), 400);
    assert!(!failed.passed);
    assert!(
        !reg.record_exit_rehearsal(&failed),
        "a failed rehearsal must not freshen the route"
    );
    assert_eq!(
        reg.eligibility(route_id, DataClass::RegulatedPayment, "in", 500),
        Eligibility::ExitUntested
    );

    // An ALL-PASS shadow rehearsal records freshness → eligibility flips to Eligible.
    let passed = plan.rehearse(&ShadowStub(None), 450);
    assert!(passed.passed);
    assert_eq!(passed.steps.len(), 6);
    assert!(
        reg.record_exit_rehearsal(&passed),
        "an all-pass rehearsal freshens the route"
    );
    assert_eq!(
        reg.eligibility(route_id, DataClass::RegulatedPayment, "in", 500),
        Eligibility::Eligible,
        "a rehearsed exit plan makes the route eligible for a regulated request"
    );

    // The freshness decays with the cadence: far past the rehearsal, the route is untested again —
    // the rehearsal is a living test, not a permanent tick.
    let mut tight = OutsourcingRegister::new(100);
    tight.upsert(regulated_route(route_id));
    let r = ExitPlan::standard(route_id).rehearse(&ShadowStub(None), 1_000);
    assert!(tight.record_exit_rehearsal(&r));
    assert!(tight
        .eligibility(route_id, DataClass::RegulatedPayment, "in", 1_050)
        .is_eligible());
    assert_eq!(
        tight.eligibility(route_id, DataClass::RegulatedPayment, "in", 1_200),
        Eligibility::ExitUntested,
        "a stale rehearsal lapses back to untested"
    );
}

// ============================================================================
// (2) §4.1 — DPIA-per-feature as a CI promotion gate
// ============================================================================

#[test]
fn r11_dpia_ci_gate_blocks_prod_allows_dev() {
    let mut gate = DpiaCiGate::new(&["outlook", "graph"]);
    let profile = FeatureProfile::new("inbox-summarizer", DataClass::Internal, "summarize inbox")
        .with_capability("connector.outlook.read");
    gate.register_feature(profile.clone());

    // Dev promotion is free even with no DPIA (iterate in a sandbox with no real data principals).
    assert!(gate
        .check("inbox-summarizer", PromotionTarget::Dev)
        .is_allowed());

    // The promotion JOB to prod is BLOCKED — a personal-data feature with no approved DPIA.
    assert_eq!(
        gate.check("inbox-summarizer", PromotionTarget::Prod),
        ainxt_responsibleai::dpia::DpiaGateDecision::Blocked(DpiaGateRefusal::MissingDpia {
            feature_id: "inbox-summarizer".into()
        })
    );

    // Record an approved, current DPIA → the prod promotion job passes.
    let mut dpia = Dpia::draft("inbox-summarizer", "risks + mitigations");
    dpia.approve_for(&profile, "dpo-anita");
    gate.record_dpia(dpia);
    assert!(gate
        .check("inbox-summarizer", PromotionTarget::Prod)
        .is_allowed());
    assert!(gate
        .check("inbox-summarizer", PromotionTarget::Env)
        .is_allowed());

    // A material data-processing change (ceiling expands) invalidates the approval → re-blocked for
    // env/prod until re-assessed, while dev stays free.
    let expanded = FeatureProfile::new(
        "inbox-summarizer",
        DataClass::RegulatedPayment,
        "summarize inbox",
    )
    .with_capability("connector.outlook.read");
    gate.register_feature(expanded);
    assert_eq!(
        gate.check("inbox-summarizer", PromotionTarget::Prod),
        ainxt_responsibleai::dpia::DpiaGateDecision::Blocked(DpiaGateRefusal::Stale {
            feature_id: "inbox-summarizer".into()
        })
    );
    assert!(gate
        .check("inbox-summarizer", PromotionTarget::Dev)
        .is_allowed());

    // An un-inventoried feature fails closed for env/prod (cannot assess → cannot promote).
    assert_eq!(
        gate.check("ghost-feature", PromotionTarget::Prod),
        ainxt_responsibleai::dpia::DpiaGateDecision::Blocked(DpiaGateRefusal::UnknownFeature {
            feature_id: "ghost-feature".into()
        })
    );

    // A non-personal-data feature promotes to prod with no DPIA at all.
    gate.register_feature(FeatureProfile::new(
        "public-docs-search",
        DataClass::Public,
        "search public docs",
    ));
    assert!(gate
        .check("public-docs-search", PromotionTarget::Prod)
        .is_allowed());
}
