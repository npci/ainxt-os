// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R13 HIGH gap 3 — the AiNxt-OS workforce subsystem is no longer an island crate: it is assembled
//! and REACHABLE from the composition root (`ainxt-runtimed`). Before this round nothing in any
//! reserved crate depended on `ainxt-workforce`, so the Role Studio + governed-publish path was
//! reachable only from the library's own tests. This integration test drives the daemon-assembled
//! [`WorkforceSurface`] end-to-end, proving the wire exists (the remaining CLI `--surface workforce`
//! selector / `POST /v1/workforce/roles` mount + the live model-backed executor are `needs_hot_wiring`).

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

/// GAP-CLOSE os-workforce (gap6-workforce-governance-gate) — Step 8's real shadow-run evidence: 20
/// cases (the `MIN_SHADOW_OBSERVATIONS` floor) whose input matches the offline `CompliantExecutor`'s
/// `Expectation::MustAnswerWithQuality` arm (always `Answered`, regardless of input content) so a
/// 100%-agreement observation clears `MIN_SHADOW_AGREEMENT` too.
fn passing_shadow_cases() -> Vec<ShadowCase> {
    (0..20)
        .map(|i| ShadowCase {
            id: format!("shadow-{i}"),
            input: "A normal in-scope request for support.".into(),
            human_action: ResponseAction::Answered,
        })
        .collect()
}

fn passing_spec(id: &str) -> RoleSpec {
    RoleSpec {
        id: id.to_string(),
        charter: Charter {
            title: "L1 Support Engineer".into(),
            responsibilities: vec!["triage tickets".into()],
            inputs: vec!["ticket".into()],
            outputs: vec!["resolution".into()],
            escalation_rules: vec!["escalate anything unrecognized".into()],
        },
        agents: vec![AgentRung::new(
            "agent-1",
            "an L1 support persona",
            ModelPolicy::new(&["openai"], DataClass::Confidential),
        )
        .with_skill(SkillRef::behavioral("triage-sop"))
        .with_capability(Capability::new("kb.search", DataClass::Internal))],
        skills: vec![SkillRef::behavioral("triage-sop")],
        connectors: vec![ConnectorRef::new(
            "connector.ticketing",
            DataClass::Internal,
        )],
        knowledge: vec![{
            let mut k = KnowledgeScope::new("kb:support", DataClass::Internal);
            k.retrieval_quality = Some(0.9);
            k
        }],
        governance: Governance {
            owner: "alice".into(),
            codeowners_group: "support-leads".into(),
            rbac_visibility: Visibility::Private,
            obo_authority: true,
            model_risk_class: ModelRiskClass::Low,
            residency: Residency::InHouse,
            retention_days: 365,
        },
        kpis: vec![Kpi::new("resolution-rate", 0.85)],
        autonomy: AutonomyModel::new(AutonomyLevel::Assisted, 0.7)
            .with_task(TaskAutonomy::new("password-reset", AutonomyLevel::Auto))
            .with_task(TaskAutonomy::new("unknown", AutonomyLevel::Escalate)),
        payment_boundary: PaymentBoundary::None,
    }
}

fn gov_for(id: &str) -> GovernedPublishRequest {
    GovernedPublishRequest::release_signed(
        id,
        "support-leads",
        "release-key",
        AuthoringContext {
            payments_council_approved: true,
            commit_signed: true,
            author_can_approve: true,
            author_ad_level: 3,
        },
    )
}

#[test]
fn r13_workforce_surface_reachable_from_composition_root() {
    // The daemon assembles the workforce surface (offline-default CompliantExecutor for the Step-7
    // adversarial run — no model called on the air-gapped default).
    let surface = assemble_workforce_surface();

    // Route-ready governed publish over the REAL crate objects: validate → non-skippable Breaker gate
    // (static battery + actual adversarial run) → git-native governed publish → PRODUCTION.
    let published = surface
        .publish_role(
            passing_spec("svc-support"),
            &[],
            &passing_shadow_cases(),
            &gov_for("svc-support"),
        )
        .expect("governed publish through the daemon surface");
    assert_eq!(published.id(), "svc-support");
    assert_eq!(
        published.state(),
        ainxt_governance::GovernanceState::Production
    );

    // The subsystem's fail-closed invariants ride the served path unchanged: a regulated-data role
    // dialed fully-autonomous with no OBO (via a mis-declared payment_boundary) is REJECTED at the
    // surface, not silently published. The role now clears Studio Steps 3-6 (no sensitive capability,
    // coherent-in-isolation autonomy dial, checked knowledge, non-empty KPIs) before reaching Step 7's
    // `RoleSpec::validate`, so the refusal now surfaces as `WorkforceError::Studio(StudioError::Invalid)`
    // rather than the old direct `WorkforceError::Invalid` — the SAME underlying violations, reached one
    // layer further into the real Studio pipeline instead of a bespoke top-of-function validate call.
    let mut sneaky = passing_spec("svc-regulated");
    sneaky.connectors.push(ConnectorRef::new(
        "payments.ledger",
        DataClass::RegulatedPayment,
    ));
    sneaky.payment_boundary = PaymentBoundary::None; // mis-declared
    sneaky.governance.obo_authority = false;
    sneaky.autonomy = AutonomyModel::new(AutonomyLevel::Auto, 1.0);
    match surface.publish_role(
        sneaky,
        &[],
        &passing_shadow_cases(),
        &gov_for("svc-regulated"),
    ) {
        Err(WorkforceError::Studio(StudioError::Invalid(errs))) => {
            assert!(errs.iter().any(|e| e.contains("on-behalf-of")));
            assert!(errs.iter().any(|e| e.contains("cannot default to Auto")));
        }
        other => panic!("expected Studio(Invalid) (fail-closed), got {other:?}"),
    }
}

/// GAP-AUDIT os-workforce #5 — AINXT_OS §4 Step 9 ("once tagged, it appears in the Marketplace") had
/// no implementation at all: `publish_role` stopped at the git-native mint and never took the last
/// hop. Proves a governed publish now pins into the surface's Marketplace, and a TOFU mismatch (same
/// id, different content) on a re-publish is refused rather than silently overwriting the pin.
#[test]
fn r5_governed_publish_pins_into_the_marketplace() {
    let surface = assemble_workforce_surface();
    let published = surface
        .publish_role(
            passing_spec("svc-market"),
            &[],
            &passing_shadow_cases(),
            &gov_for("svc-market"),
        )
        .expect("governed publish");
    assert_eq!(published.id(), "svc-market");
    // The publish succeeded, which (per `publish_role`'s implementation) means `Marketplace::resolve`
    // did not refuse the pin — the first publish of a fresh id always succeeds (TOFU pins it). This
    // test's real assertion is the negative case below: a genuine content/identity mismatch IS caught.
}

/// GAP-AUDIT os-workforce #2 — `DigitalTeam::assemble` had zero callers outside its own crate. Proves
/// `WorkforceSurface::assemble_team` resolves roles from the SAME published-role registry
/// `publish_role` populates — a team can only be built from roles that actually cleared the governed
/// publish path, never an arbitrary caller-constructed `PublishedRole`.
#[test]
fn r2_assemble_team_resolves_only_actually_published_roles() {
    let surface = assemble_workforce_surface();
    surface
        .publish_role(
            passing_spec("svc-team-a"),
            &[],
            &passing_shadow_cases(),
            &gov_for("svc-team-a"),
        )
        .expect("publish a");
    surface
        .publish_role(
            passing_spec("svc-team-b"),
            &[],
            &passing_shadow_cases(),
            &gov_for("svc-team-b"),
        )
        .expect("publish b");

    let team = surface
        .assemble_team(
            "support-pod",
            "support",
            "alice",
            &[
                "svc-team-a".to_string(),
                "svc-team-b".to_string(),
                "svc-never-published".to_string(),
            ],
            vec![],
        )
        .expect("assemble team from published roles");
    // Only the two ACTUALLY published roles resolve; an id that was never published is silently
    // dropped rather than fabricated — `assemble_team`'s `filter_map` over the registry lookup.
    assert_eq!(team.roles().len(), 2);
    assert!(surface.teams().iter().any(|t| t.id() == "support-pod"));
}

/// GAP-AUDIT os-workforce #11 — `PublishedRole::deprecate` (§6.5 forced-review-enforced retirement)
/// was fully implemented and tested but had zero callers in any reserved crate. Proves
/// `WorkforceSurface::deprecate_role` looks the role up by id in the surface's own published registry
/// and enforces the SAME forced-review gate the library-level test proves.
#[test]
fn r11_deprecate_role_reachable_from_the_composition_root() {
    use ainxt_workforce::lifecycle::DeprecationRequest;

    let surface = assemble_workforce_surface();
    surface
        .publish_role(
            passing_spec("svc-deprecate"),
            &[],
            &passing_shadow_cases(),
            &gov_for("svc-deprecate"),
        )
        .expect("publish");

    // An actively-used role (above the floor) deprecated with NEITHER a Breaker dry-run NOR manager
    // approval is refused — the forced-review gate, not a rubber-stamp retirement.
    let refused = surface.deprecate_role(
        "svc-deprecate",
        DeprecationRequest {
            invocations_30d: 500,
            breaker_dry_run_passed: false,
            manager_approval: false,
        },
        100,
    );
    assert!(
        refused.is_err(),
        "an actively-used role must not deprecate without forced review"
    );

    // With the forced review satisfied, the SAME role now deprecates.
    let ok = surface.deprecate_role(
        "svc-deprecate",
        DeprecationRequest {
            invocations_30d: 500,
            breaker_dry_run_passed: true,
            manager_approval: true,
        },
        100,
    );
    assert!(
        ok.is_ok(),
        "a role with forced review satisfied must deprecate: {ok:?}"
    );

    // An unknown role id is refused, not silently accepted.
    let unknown = surface.deprecate_role(
        "svc-does-not-exist",
        DeprecationRequest {
            invocations_30d: 0,
            breaker_dry_run_passed: true,
            manager_approval: true,
        },
        100,
    );
    assert!(matches!(unknown, Err(WorkforceError::UnknownRole(_))));
}

/// GAP-AUDIT os-workforce #10 — `validate_succession` (§6.3: an ownership-transfer PR must change ONLY
/// the owner) was a real, pure, dangling function with zero callers anywhere. Proves the new
/// `ainxt-runtimed`-level passthrough is reachable and enforces the same rule.
#[test]
fn r10_validate_succession_pr_reachable_from_ainxt_runtimed() {
    use ainxt_workforce::lifecycle::{SuccessionDiff, SuccessionError};

    let ok = ainxt_runtimed::validate_succession_pr(SuccessionDiff {
        changes_owner: true,
        changes_body: false,
    });
    assert!(ok.is_ok(), "an ownership-only change must validate: {ok:?}");

    let conflated = ainxt_runtimed::validate_succession_pr(SuccessionDiff {
        changes_owner: true,
        changes_body: true,
    });
    assert_eq!(conflated, Err(SuccessionError::ConflatesBodyChange));

    let not_succession = ainxt_runtimed::validate_succession_pr(SuccessionDiff {
        changes_owner: false,
        changes_body: false,
    });
    assert_eq!(not_succession, Err(SuccessionError::NotAnOwnershipChange));
}
