// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-CLOSE os-workforce (gap6-workforce-governance-gate) — PROVES the closed gap: before this,
//! `WorkforceSurface::publish_role` drove ONLY `RoleSpec::validate` -> `Breaker::gate` ->
//! `breaker::publish` (Steps 2/7/9), silently skipping the `RoleStudio`'s own Steps 3 (grant & govern),
//! 4 (autonomy coherence), 5 (knowledge retrieval-quality), 6 (KPI/eval), and 8 (shadow-run evidence) —
//! even though every one of those steps already had a real, independently-tested implementation, and
//! even though the crate's own `studio.rs` documents ALL of Steps 0-10 as non-bypassable gates of the
//! SAME publish pipeline. A role could reach the Marketplace at PRODUCTION having cleared ONLY
//! spec-validation and the Breaker.
//!
//! This test proves, against the REAL `WorkforceSurface::publish_role` (the actual composition-root
//! method, not a bespoke standalone instance):
//!   (a) a role missing ANY of the newly-enforced gates is REFUSED — including a knowledge-quality
//!       case that the OLD code's Breaker static battery would have let through (it only checked a
//!       namespace's score was *set*, never that it cleared a floor);
//!   (b) a role that legitimately clears every gate IS published (positive control).
//!
//! Part (c) — a real HTTP request against the new `POST /v1/workforce/roles` route reaching this SAME
//! enforcement — is the sibling `r_gap6_workforce_governance_gate_http.rs`.

use ainxt_governance::AuthoringContext;
use ainxt_runtimed::{assemble_workforce_surface, ShadowCase, WorkforceError};
use ainxt_types::DataClass;
use ainxt_workforce::autonomy::{AutonomyLevel, AutonomyModel, TaskAutonomy};
use ainxt_workforce::breaker::{GovernedPublishRequest, ResponseAction};
use ainxt_workforce::ladder::{AgentRung, Capability, ModelPolicy, SkillRef};
use ainxt_workforce::role::{
    Charter, ConnectorRef, Governance, KnowledgeScope, Kpi, ModelRiskClass, PaymentBoundary,
    Residency, RoleSpec, Visibility,
};
use ainxt_workforce::studio::StudioError;

/// A role with an SRE-style sensitive capability (`service.restart`, `.requiring_approval()` —
/// mirrors `ainxt-workforce::author`'s own `Template::Ops` blueprint) so Step 3's real gate has
/// something to actually check. `knowledge_quality` and `kpis` are parameterized so each test can
/// isolate exactly one gate.
fn spec_with_sensitive_capability(
    id: &str,
    knowledge_quality: Option<f64>,
    kpis: Vec<Kpi>,
) -> RoleSpec {
    RoleSpec {
        id: id.to_string(),
        charter: Charter {
            title: "SRE Ops Worker".into(),
            responsibilities: vec!["remediate incidents".into()],
            inputs: vec!["alert".into()],
            outputs: vec!["remediation".into()],
            escalation_rules: vec!["escalate anything unrecognized".into()],
        },
        agents: vec![AgentRung::new(
            "agent-1",
            "an SRE persona",
            ModelPolicy::new(&["openai"], DataClass::Internal),
        )
        .with_skill(SkillRef::behavioral("runbook-sop"))
        .with_capability(Capability::new("monitoring.read", DataClass::Internal))
        .with_capability(
            Capability::new("service.restart", DataClass::Internal).requiring_approval(),
        )],
        skills: vec![SkillRef::behavioral("runbook-sop")],
        connectors: vec![ConnectorRef::new(
            "connector.monitoring",
            DataClass::Internal,
        )],
        knowledge: vec![{
            let mut k = KnowledgeScope::new("kb:runbooks", DataClass::Internal);
            k.retrieval_quality = knowledge_quality;
            k
        }],
        governance: Governance {
            owner: "alice".into(),
            codeowners_group: "sre-leads".into(),
            rbac_visibility: Visibility::Private,
            obo_authority: true,
            model_risk_class: ModelRiskClass::Low,
            residency: Residency::InHouse,
            retention_days: 365,
        },
        kpis,
        autonomy: AutonomyModel::new(AutonomyLevel::Assisted, 0.6)
            .with_task(TaskAutonomy::new(
                "restart-service",
                AutonomyLevel::Assisted,
            ))
            .with_task(TaskAutonomy::new("unknown", AutonomyLevel::Escalate)),
        payment_boundary: PaymentBoundary::Adjacent,
    }
}

/// A fully-compliant version of the above: knowledge scored above the floor, KPIs present. The ONLY
/// remaining variables each test controls are `approved_capabilities` and `shadow_cases`.
fn compliant_spec(id: &str) -> RoleSpec {
    spec_with_sensitive_capability(
        id,
        Some(0.9),
        vec![
            Kpi::new("mttr-minutes", 30.0),
            Kpi::new("false-remediation-rate", 0.02),
        ],
    )
}

fn gov_for(id: &str) -> GovernedPublishRequest {
    GovernedPublishRequest::release_signed(
        id,
        "sre-leads",
        "release-key",
        AuthoringContext {
            payments_council_approved: true,
            commit_signed: true,
            author_can_approve: true,
            author_ad_level: 3,
        },
    )
}

/// `n` cases, ALL `Answered` — matches the offline `CompliantExecutor`'s `MustAnswerWithQuality` arm
/// (always `Answered` regardless of input content), so an `n`-case, 100%-agreement observation is
/// real, non-fabricated evidence.
fn agreeing_shadow_cases(n: u32) -> Vec<ShadowCase> {
    (0..n)
        .map(|i| ShadowCase {
            id: format!("shadow-{i}"),
            input: "A normal in-scope remediation request.".into(),
            human_action: ResponseAction::Answered,
        })
        .collect()
}

/// `n` cases where only `agreeing` of them record the human decision as `Answered` (matching what
/// `CompliantExecutor` will actually return) — the rest record `Refused`, a real, deliberate
/// disagreement, so the resulting `ShadowResult::agreement()` is genuinely below 1.0.
fn partially_agreeing_shadow_cases(n: u32, agreeing: u32) -> Vec<ShadowCase> {
    (0..n)
        .map(|i| ShadowCase {
            id: format!("shadow-{i}"),
            input: "A normal in-scope remediation request.".into(),
            human_action: if i < agreeing {
                ResponseAction::Answered
            } else {
                ResponseAction::Refused
            },
        })
        .collect()
}

const APPROVED: &str = "service.restart";

// ---------------------------------------------------------------------------------------------
// (a) Each newly-enforced gate REFUSES a role that would have cleared the OLD code's checks.
// ---------------------------------------------------------------------------------------------

/// Step 3 — a sensitive capability with NO approval is refused, even though the old code never
/// looked at approvals at all (it would have published this role).
#[test]
fn sensitive_capability_without_approval_is_refused() {
    let surface = assemble_workforce_surface();
    let spec = compliant_spec("gap6-no-approval");
    let result = surface.publish_role(
        spec,
        &[],
        &agreeing_shadow_cases(20),
        &gov_for("gap6-no-approval"),
    );
    match result {
        Err(WorkforceError::Studio(StudioError::SensitiveCapabilityNeedsApproval(caps))) => {
            assert!(caps.iter().any(|c| c == APPROVED), "got {caps:?}");
        }
        other => panic!("expected SensitiveCapabilityNeedsApproval (fail-closed), got {other:?}"),
    }
}

/// Step 5 — a knowledge namespace scored BELOW the floor (but NOT `None`) is refused. This is the
/// genuinely NEW tightening: the OLD code's Breaker static battery only checked a namespace's
/// `retrieval_quality` was *set* (`is_none()`), never that the value cleared a quality bar — a score
/// of `Some(0.3)` sailed straight through the old `publish_role`. It does not here.
#[test]
fn knowledge_below_quality_floor_is_refused_even_though_old_breaker_would_have_passed_it() {
    let surface = assemble_workforce_surface();
    let spec = spec_with_sensitive_capability(
        "gap6-low-knowledge-quality",
        Some(0.3), // set (not None) — the old code's ONLY check — but below the 0.75 floor.
        vec![Kpi::new("mttr-minutes", 30.0)],
    );
    let result = surface.publish_role(
        spec,
        &[APPROVED.to_string()],
        &agreeing_shadow_cases(20),
        &gov_for("gap6-low-knowledge-quality"),
    );
    match result {
        Err(WorkforceError::Studio(StudioError::RetrievalQualityGap {
            namespace,
            score,
            floor,
        })) => {
            assert_eq!(namespace, "kb:runbooks");
            assert!(score < floor, "score {score} should be below floor {floor}");
        }
        other => panic!("expected RetrievalQualityGap (fail-closed), got {other:?}"),
    }
}

/// A knowledge namespace never measured at all (`None`) is ALSO refused (treated as `0.0`, fail
/// closed) — the OLD code's Breaker static battery refused this case too, so this one preserves
/// existing behaviour rather than closing a new gap; included for completeness of Step 5's coverage.
#[test]
fn unmeasured_knowledge_is_treated_as_zero_and_refused() {
    let surface = assemble_workforce_surface();
    let spec = spec_with_sensitive_capability(
        "gap6-unmeasured-knowledge",
        None,
        vec![Kpi::new("mttr-minutes", 30.0)],
    );
    let result = surface.publish_role(
        spec,
        &[APPROVED.to_string()],
        &agreeing_shadow_cases(20),
        &gov_for("gap6-unmeasured-knowledge"),
    );
    assert!(
        matches!(
            result,
            Err(WorkforceError::Studio(StudioError::RetrievalQualityGap { score, .. })) if score == 0.0
        ),
        "expected a zero-score RetrievalQualityGap, got {result:?}"
    );
}

/// Step 6 — no KPIs at all is refused. The OLD code's Breaker static battery already caught this
/// case too (a "quality-measurable" probe failure), so this preserves existing behaviour (reached one
/// step earlier, via the Studio, rather than closing a brand-new gap) — included because the task's
/// own gate list names it explicitly.
#[test]
fn no_kpis_is_refused() {
    let surface = assemble_workforce_surface();
    let spec = spec_with_sensitive_capability("gap6-no-kpis", Some(0.9), vec![]);
    let result = surface.publish_role(
        spec,
        &[APPROVED.to_string()],
        &agreeing_shadow_cases(20),
        &gov_for("gap6-no-kpis"),
    );
    match result {
        Err(WorkforceError::Studio(StudioError::Invalid(errs))) => {
            assert!(
                errs.iter().any(|e| e.contains("no KPIs defined")),
                "got {errs:?}"
            );
        }
        other => panic!("expected Studio(Invalid) no-KPIs refusal, got {other:?}"),
    }
}

/// Step 8 — too FEW shadow observations (below `MIN_SHADOW_OBSERVATIONS`) is refused. Genuinely NEW:
/// the old code never ran a shadow observation at all — a role could publish with ZERO shadow
/// evidence. Not here.
#[test]
fn too_few_shadow_observations_is_refused() {
    let surface = assemble_workforce_surface();
    let spec = compliant_spec("gap6-too-few-shadow");
    let result = surface.publish_role(
        spec,
        &[APPROVED.to_string()],
        &agreeing_shadow_cases(5), // below MIN_SHADOW_OBSERVATIONS (20)
        &gov_for("gap6-too-few-shadow"),
    );
    match result {
        Err(WorkforceError::Studio(StudioError::InsufficientShadowEvidence {
            observed,
            required_observed,
            ..
        })) => {
            assert_eq!(observed, 5);
            assert_eq!(
                required_observed,
                ainxt_workforce::studio::MIN_SHADOW_OBSERVATIONS
            );
        }
        other => panic!("expected InsufficientShadowEvidence (fail-closed), got {other:?}"),
    }
}

/// Step 8 — enough OBSERVATIONS but a real, low AGREEMENT rate (below `MIN_SHADOW_AGREEMENT`) is
/// refused. Also genuinely new: the old code never compared the role's actual behaviour to any human
/// ground truth before publish.
#[test]
fn low_shadow_agreement_is_refused() {
    let surface = assemble_workforce_surface();
    let spec = compliant_spec("gap6-low-agreement");
    // 20 observations (clears the count floor), but only 5 genuinely match what CompliantExecutor
    // will actually answer -> agreement 0.25, well below the 0.85 floor.
    let result = surface.publish_role(
        spec,
        &[APPROVED.to_string()],
        &partially_agreeing_shadow_cases(20, 5),
        &gov_for("gap6-low-agreement"),
    );
    match result {
        Err(WorkforceError::Studio(StudioError::InsufficientShadowEvidence {
            observed,
            agreement,
            required_agreement,
            ..
        })) => {
            assert_eq!(observed, 20);
            assert!(
                agreement < required_agreement,
                "agreement {agreement} should be below floor {required_agreement}"
            );
        }
        other => panic!("expected InsufficientShadowEvidence (fail-closed), got {other:?}"),
    }
}

/// No shadow cases supplied at all (the fail-closed wire default) is refused exactly like too-few.
#[test]
fn zero_shadow_cases_is_refused() {
    let surface = assemble_workforce_surface();
    let spec = compliant_spec("gap6-zero-shadow");
    let result = surface.publish_role(
        spec,
        &[APPROVED.to_string()],
        &[],
        &gov_for("gap6-zero-shadow"),
    );
    assert!(
        matches!(
            result,
            Err(WorkforceError::Studio(
                StudioError::InsufficientShadowEvidence { observed: 0, .. }
            ))
        ),
        "expected InsufficientShadowEvidence{{observed: 0, ..}}, got {result:?}"
    );
}

// ---------------------------------------------------------------------------------------------
// (b) Positive control — a role that legitimately clears EVERY gate IS published.
// ---------------------------------------------------------------------------------------------

#[test]
fn a_role_clearing_every_gate_is_published() {
    let surface = assemble_workforce_surface();
    let spec = compliant_spec("gap6-fully-compliant");
    let published = surface
        .publish_role(
            spec,
            &[APPROVED.to_string()],
            &agreeing_shadow_cases(20),
            &gov_for("gap6-fully-compliant"),
        )
        .expect("a role clearing Steps 3-9 must publish");
    assert_eq!(published.id(), "gap6-fully-compliant");
    assert_eq!(
        published.state(),
        ainxt_governance::GovernanceState::Production
    );
}

// Part (c) — a REAL HTTP request against POST /v1/workforce/roles reaching this SAME enforcement —
// lives in the sibling `r_gap6_workforce_governance_gate_http.rs` (kept separate so this crate's
// commit history stays bisectable between the gate-logic change and the HTTP-route-mounting change).
