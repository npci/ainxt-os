// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-15 ALL-SEVERITIES closure for the AiNxt-OS workforce ladder + Role Studio (ainxt-workforce).
//! Each `r15_*` test closes one round-14 gap, fail-before / pass-after, exercising the crate exactly
//! as a downstream consumer would.

use ainxt_governance::AuthoringContext;
use ainxt_types::DataClass;
use ainxt_workforce::autonomy::{AutonomyLevel, AutonomyModel, TaskAutonomy};
use ainxt_workforce::breaker::{
    self, Breaker, CompliantExecutor, GovernedPublishRequest, PublishError,
};
use ainxt_workforce::controls::{
    InMemoryDataPlane, InMemoryEventLog, NightlyControls, RecordingNotifier,
};
use ainxt_workforce::ladder::{AgentRung, Capability, ModelPolicy, SkillRef};
use ainxt_workforce::lifecycle::{DefinitionTelemetry, DeprecationRequest};
use ainxt_workforce::oversight;
use ainxt_workforce::role::{
    Charter, ConnectorRef, DeprecateError, Governance, KnowledgeScope, Kpi, ModelRiskClass,
    PaymentBoundary, Residency, RoleSpec, Visibility,
};
use ainxt_workforce::studio::{
    MonitorDecision, RoleStudio, ShadowResult, StudioError, StudioStage, Template,
};

// ------------------------------------------------------------------ helpers (mirrors r11/r13's)

fn good_agent(id: &str) -> AgentRung {
    AgentRung::new(
        id,
        "an L1 support persona",
        ModelPolicy::new(&["openai"], DataClass::Confidential),
    )
    .with_skill(SkillRef::behavioral("triage-sop"))
    .with_capability(Capability::new("kb.search", DataClass::Internal))
}

fn good_governance(owner: &str) -> Governance {
    Governance {
        owner: owner.to_string(),
        codeowners_group: "support-leads".into(),
        rbac_visibility: Visibility::Private,
        obo_authority: true,
        model_risk_class: ModelRiskClass::Low,
        residency: Residency::InHouse,
        retention_days: 365,
    }
}

fn good_autonomy() -> AutonomyModel {
    AutonomyModel::new(AutonomyLevel::Assisted, 0.7)
        .with_task(TaskAutonomy::new("password-reset", AutonomyLevel::Auto))
        .with_task(TaskAutonomy::new("unknown", AutonomyLevel::Escalate))
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
        agents: vec![good_agent("agent-1")],
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
        governance: good_governance("alice"),
        kpis: vec![Kpi::new("resolution-rate", 0.85)],
        autonomy: good_autonomy(),
        payment_boundary: PaymentBoundary::None,
    }
}

fn full_authoring() -> AuthoringContext {
    AuthoringContext {
        payments_council_approved: true,
        commit_signed: true,
        author_can_approve: true,
        author_ad_level: 3,
    }
}

fn gov_for(id: &str, group: &str) -> GovernedPublishRequest {
    GovernedPublishRequest::release_signed(id, group, "release-key", full_authoring())
}

// ================================================================== HIGH + MEDIUM
// Step 3 grant & govern: a capability marked `requires_approval` MUST be explicitly signed off, or
// the step is refused — sensitive capabilities need human approval, not a rubber-stamp `govern()`.

#[test]
fn r15_govern_requires_sensitive_capability_approval() {
    let mut spec = passing_spec("needs-approval");
    spec.agents[0] = spec.agents[0].clone().with_capability(
        Capability::new("service.restart", DataClass::Internal).requiring_approval(),
    );

    let mut studio = RoleStudio::start(Template::Ops);
    studio.describe_and_draft(spec.clone()).unwrap();
    // Plain govern() refuses: a sensitive capability was never approved.
    match studio.govern() {
        Err(StudioError::SensitiveCapabilityNeedsApproval(caps)) => {
            assert!(caps.iter().any(|c| c == "service.restart"));
        }
        other => panic!("expected SensitiveCapabilityNeedsApproval, got {other:?}"),
    }
    assert_eq!(
        studio.stage(),
        StudioStage::Drafted,
        "must NOT advance past Step 3 unapproved"
    );

    // Approving the WRONG capability still refuses.
    let mut studio2 = RoleStudio::start(Template::Ops);
    studio2.describe_and_draft(spec.clone()).unwrap();
    assert!(studio2
        .govern_with_approvals(&["kb.search".to_string()])
        .is_err());

    // Approving the actual sensitive capability advances Step 3.
    let mut studio3 = RoleStudio::start(Template::Ops);
    studio3.describe_and_draft(spec).unwrap();
    studio3
        .govern_with_approvals(&["service.restart".to_string()])
        .expect("explicit sign-off on the sensitive capability advances Step 3");
    assert_eq!(studio3.stage(), StudioStage::Governed);

    // Control: a draft with NO sensitive capability still passes plain govern() (back-compat).
    let mut studio4 = RoleStudio::start(Template::Support);
    studio4
        .describe_and_draft(passing_spec("no-sensitive-caps"))
        .unwrap();
    studio4
        .govern()
        .expect("no sensitive capability -> plain govern() still succeeds");
}

// ================================================================== LOW (Step 4 real substance)
// set_autonomy is no longer a no-op stage flip: it runs the dial's own coherence validation NOW.

#[test]
fn r15_set_autonomy_validates_dial_not_a_rubber_stamp() {
    let mut spec = passing_spec("bad-dial");
    // An incoherent dial: a regulated per-task Auto, caught by AutonomyModel::validate.
    spec.autonomy = AutonomyModel::new(AutonomyLevel::Assisted, 0.7)
        .with_task(TaskAutonomy::new("settle", AutonomyLevel::Auto).regulated());

    let mut studio = RoleStudio::start(Template::Support);
    studio.describe_and_draft(spec).unwrap();
    studio.govern().unwrap();
    match studio.set_autonomy() {
        Err(StudioError::Invalid(errs)) => {
            assert!(errs
                .iter()
                .any(|e| e.contains("settle") && e.contains("cannot be dialed to Auto")));
        }
        other => panic!("expected Invalid from set_autonomy's real coherence check, got {other:?}"),
    }
    assert_eq!(
        studio.stage(),
        StudioStage::Governed,
        "must not advance past Step 4 on an incoherent dial"
    );

    // Control: a coherent dial still advances (back-compat with r11/r12's plain call).
    let mut ok_studio = RoleStudio::start(Template::Support);
    ok_studio
        .describe_and_draft(passing_spec("good-dial"))
        .unwrap();
    ok_studio.govern().unwrap();
    ok_studio
        .set_autonomy()
        .expect("coherent dial advances Step 4");
}

// ================================================================== HIGH + MEDIUM
// Step 8 shadow run: trust must be EARNED WITH EVIDENCE before publish — too few observations, or an
// agreement rate below the floor, refuses the step (machine stays at BreakerPassed).

#[test]
fn r15_shadow_run_requires_evidence_before_publish() {
    let role = passing_spec("shadow-thin").validate().unwrap();
    let pass = Breaker::gate(&role, &CompliantExecutor).unwrap();
    let mut studio = RoleStudio::start(Template::Support);
    studio
        .describe_and_draft(passing_spec("shadow-thin"))
        .unwrap();
    studio.govern().unwrap();
    studio.set_autonomy().unwrap();
    studio.check_knowledge(&[("kb:support", 0.9)], 0.6).unwrap();
    studio.define_kpis().unwrap();
    studio.run_breaker(&CompliantExecutor).unwrap();
    let _ = &pass; // (pass computed above just to show the role is otherwise publishable)

    // Too few observations (below MIN_SHADOW_OBSERVATIONS).
    match studio.shadow_run(ShadowResult::new(5, 5)) {
        Err(StudioError::InsufficientShadowEvidence { observed, .. }) => assert_eq!(observed, 5),
        other => {
            panic!("expected InsufficientShadowEvidence (too few observations), got {other:?}")
        }
    }
    assert_eq!(
        studio.stage(),
        StudioStage::BreakerPassed,
        "must stay at BreakerPassed on thin evidence"
    );

    // Enough volume but a bad agreement rate (below MIN_SHADOW_AGREEMENT).
    match studio.shadow_run(ShadowResult::new(100, 40)) {
        Err(StudioError::InsufficientShadowEvidence { agreement, .. }) => assert!(agreement < 0.85),
        other => panic!("expected InsufficientShadowEvidence (low agreement), got {other:?}"),
    }
    assert_eq!(studio.stage(), StudioStage::BreakerPassed);

    // Good evidence advances to Shadow (and publish is then reachable).
    studio
        .shadow_run(ShadowResult::new(50, 46))
        .expect("sufficient evidence advances Step 8");
    assert_eq!(studio.stage(), StudioStage::Shadow);
    studio
        .publish(&gov_for("shadow-thin", "support-leads"))
        .expect("publish reachable after real evidence");
}

// ================================================================== MEDIUM
// §7.2 attention-check decoys must be BREAKER-GENERATED — real adversarial-corpus content, not a
// caller-invented label.

#[test]
fn r15_decoy_is_breaker_generated_not_hand_authored() {
    let role = passing_spec("decoy-role").validate().unwrap();
    let generated =
        oversight::generate_decoy(&role).expect("role ingests connectors/knowledge -> has probes");
    // The decoy id IS one of the role's own generated adversarial-corpus case ids.
    let corpus = Breaker::adversarial_corpus(&role);
    assert!(
        corpus.iter().any(|c| c.id == generated.check.decoy_id),
        "decoy content must come from the Breaker's own corpus, got {:?}",
        generated.check.decoy_id
    );
    assert_eq!(generated.case.id, generated.check.decoy_id);
    assert_eq!(generated.check.role, "decoy-role");

    // A role with nothing adversarial to decoy with (no external ingest, no PII, no capabilities)
    // yields no decoy — honestly `None`, not a fabricated one.
    let mut bare = passing_spec("bare-role");
    bare.connectors.clear();
    bare.knowledge.clear();
    bare.agents[0].capabilities.clear();
    // still needs at least one skill/capability to validate as "does something"; keep the skill.
    let bare = bare.validate().unwrap();
    assert!(oversight::generate_decoy(&bare).is_none());
}

// ================================================================== MEDIUM
// §6.5 forced review before deprecation is now enforced AT THE DEPRECATE CALL SITE, not left as
// unwired pure logic.

#[test]
fn r15_deprecate_enforces_forced_review_at_the_call_site() {
    let role = passing_spec("deprecate-me").validate().unwrap();
    let pass = Breaker::gate(&role, &CompliantExecutor).unwrap();
    let mut published =
        breaker::publish(role, &pass, &gov_for("deprecate-me", "support-leads")).unwrap();

    // High-volume, un-reviewed deprecation is BLOCKED (needs Breaker dry-run + manager approval).
    let floor = 10;
    let req = DeprecationRequest {
        invocations_30d: 5000,
        breaker_dry_run_passed: false,
        manager_approval: false,
    };
    match published.deprecate(req, floor) {
        Err(DeprecateError::ForcedReviewRequired(blocks)) => assert_eq!(blocks.len(), 2),
        other => panic!("expected ForcedReviewRequired for a high-volume un-reviewed deprecation, got {other:?}"),
    }
    assert_eq!(
        published.state(),
        ainxt_governance::GovernanceState::Production,
        "a blocked deprecation must not touch the git lifecycle state"
    );

    // With the forced review satisfied, deprecation proceeds through the git-native lifecycle.
    let req_ok = DeprecationRequest {
        invocations_30d: 5000,
        breaker_dry_run_passed: true,
        manager_approval: true,
    };
    published
        .deprecate(req_ok, floor)
        .expect("forced review satisfied -> deprecation proceeds");
    assert_eq!(
        published.state(),
        ainxt_governance::GovernanceState::Deprecated
    );

    // Control: a low-volume role deprecates on ordinary approval alone (no forced review needed).
    let role2 = passing_spec("low-volume").validate().unwrap();
    let pass2 = Breaker::gate(&role2, &CompliantExecutor).unwrap();
    let mut published2 =
        breaker::publish(role2, &pass2, &gov_for("low-volume", "support-leads")).unwrap();
    let low_req = DeprecationRequest {
        invocations_30d: 1,
        breaker_dry_run_passed: false,
        manager_approval: false,
    };
    published2
        .deprecate(low_req, floor)
        .expect("below-floor deprecation needs no forced review");
}

// ================================================================== LOW
// §6.2 re-certification nudge is now WIRED into the continuous nightly sweep, not just pure logic
// nobody calls.

#[test]
fn r15_recert_nudge_wired_into_nightly_sweep() {
    let defs = vec![
        DefinitionTelemetry {
            definition_id: "stale-def".into(),
            owner: "alice".into(),
            kpi_trend_90d: 0.1,
            invocation_trend: 0.1,
            days_since_last_commit: 400, // over the 365-day default cadence
            invocations_30d: 50,
        },
        DefinitionTelemetry {
            definition_id: "fresh-def".into(),
            owner: "bob".into(),
            kpi_trend_90d: 0.1,
            invocation_trend: 0.1,
            days_since_last_commit: 10,
            invocations_30d: 50,
        },
    ];
    let codeowners: std::collections::BTreeSet<String> = ["alice".to_string(), "bob".to_string()]
        .into_iter()
        .collect();
    let mut org = ainxt_workforce::lifecycle::OrgTree::default();
    org.active.insert("alice".into(), true);
    org.active.insert("bob".into(), true);

    let mut store = InMemoryDataPlane::default();
    let mut notifier = RecordingNotifier::default();
    let mut log = InMemoryEventLog::default();
    let summary = {
        let mut ctrl = NightlyControls::new(&mut store, &mut notifier, &mut log);
        ctrl.run_nightly(
            &defs,
            &ainxt_workforce::lifecycle::DecayThresholds::default(),
            &codeowners,
            &org,
            &[],
            20,
        )
    };

    assert_eq!(
        summary.recert_nudged, 1,
        "only the stale definition is nudged"
    );
    assert_eq!(store.recert_nudges.len(), 1);
    assert_eq!(store.recert_nudges[0].definition_id, "stale-def");
    assert_eq!(
        notifier.count_for("alice"),
        1,
        "alice gets exactly one aggregated recert digest"
    );
    assert_eq!(
        notifier.count_for("bob"),
        0,
        "bob's fresh definition is not nudged"
    );

    // Explicit-cadence variant closes the same gap with a tighter threshold.
    let mut store2 = InMemoryDataPlane::default();
    let mut notifier2 = RecordingNotifier::default();
    let mut log2 = InMemoryEventLog::default();
    let summary2 = {
        let mut ctrl = NightlyControls::new(&mut store2, &mut notifier2, &mut log2);
        ctrl.run_nightly_with_recert(
            &defs,
            &ainxt_workforce::lifecycle::DecayThresholds::default(),
            &codeowners,
            &org,
            &[],
            20,
            5, // both are now over cadence
        )
    };
    assert_eq!(summary2.recert_nudged, 2);
}

// ================================================================== MEDIUM
// Step 10 monitor: real KPI/quality-drift + cost pause/rollback decision logic (not a no-op flag).

#[test]
fn r15_monitor_evaluates_kpi_drift_and_cost_for_pause_rollback() {
    let spec = passing_spec("monitored-role");

    // Healthy: KPI at target, cost within budget.
    let ok = RoleStudio::evaluate_monitoring(&spec, &[("resolution-rate", 0.9)], 80.0, 100.0);
    assert_eq!(ok, MonitorDecision::Continue);

    // Soft drift: KPI below target but not collapsed -> pause for review.
    let soft = RoleStudio::evaluate_monitoring(&spec, &[("resolution-rate", 0.7)], 80.0, 100.0);
    match soft {
        MonitorDecision::PauseForReview(reasons) => {
            assert!(reasons.iter().any(|r| r.contains("resolution-rate")))
        }
        other => panic!("expected PauseForReview on KPI drift, got {other:?}"),
    }

    // Hard collapse: KPI at/below half target -> rollback.
    let hard = RoleStudio::evaluate_monitoring(&spec, &[("resolution-rate", 0.1)], 80.0, 100.0);
    match hard {
        MonitorDecision::Rollback(reasons) => {
            assert!(reasons.iter().any(|r| r.contains("collapsed")))
        }
        other => panic!("expected Rollback on KPI collapse, got {other:?}"),
    }

    // Cost blew past 2x budget -> rollback, even with healthy KPIs.
    let cost_hard =
        RoleStudio::evaluate_monitoring(&spec, &[("resolution-rate", 0.9)], 250.0, 100.0);
    match cost_hard {
        MonitorDecision::Rollback(reasons) => assert!(reasons.iter().any(|r| r.contains("cost"))),
        other => panic!("expected Rollback on cost blowout, got {other:?}"),
    }
}
