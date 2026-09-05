// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-11 integration tests for the AiNxt-OS workforce ladder + Role Studio (ainxt-workforce).
//! Each `r11_*` test closes one design-vs-impl gap from the round-10 sweep, exercising the crate
//! exactly as a downstream consumer would — proving the type-level Breaker gate in particular.

use ainxt_governance::AuthoringContext;
use ainxt_types::DataClass;
use ainxt_workforce::autonomy::{AutonomyLevel, AutonomyModel, TaskAutonomy};
use ainxt_workforce::breaker::{
    self, Breaker, BreakerVerdict, CompliantExecutor, GateError, GovernedPublishRequest,
    PublishError, ScriptedExecutor,
};
use ainxt_workforce::ladder::{AgentRung, Capability, ModelPolicy, SkillRef};
use ainxt_workforce::lifecycle::{
    self, DecayThresholds, DefinitionTelemetry, DeprecationBlock, DeprecationRequest, OrgTree,
    SuccessionDiff, SuccessionError,
};
use ainxt_workforce::oversight::{
    self, ApprovalEvent, ApprovalRoute, AttentionCheck, CompetencyStatus, DecoyOutcome,
};
use ainxt_workforce::role::{
    Charter, ConnectorRef, Governance, KnowledgeScope, Kpi, ModelRiskClass, PaymentBoundary,
    Residency, RoleSpec, Visibility,
};
use ainxt_workforce::studio::{RoleStudio, ShadowResult, StudioError, StudioStage, Template};
use ainxt_workforce::team::{Collaboration, DigitalTeam, TeamError};
use std::collections::BTreeSet;

// ------------------------------------------------------------------ helpers

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

/// A spec that both validates AND passes the Breaker directly (knowledge already quality-checked).
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

/// Fully-authorized commit authoring evidence for the governed-publish CI gate.
fn full_authoring() -> AuthoringContext {
    AuthoringContext {
        payments_council_approved: true,
        commit_signed: true,
        author_can_approve: true,
        author_ad_level: 3,
    }
}

/// The OSS deterministic governed-publish request for a role owned/reviewed by `codeowners_group`.
fn gov_for(id: &str, codeowners_group: &str) -> GovernedPublishRequest {
    GovernedPublishRequest::release_signed(id, codeowners_group, "release-key", full_authoring())
}

fn publish_role(id: &str, owner: &str) -> ainxt_workforce::role::PublishedRole {
    let mut spec = passing_spec(id);
    spec.governance.owner = owner.to_string();
    let group = spec.governance.codeowners_group.clone();
    let validated = spec.validate().expect("valid");
    // The FULL Breaker gate: static battery + an actual adversarial RUN (CompliantExecutor stands in
    // for a live model-backed executor offline). Only this mints the sealed pass.
    let pass = Breaker::gate(&validated, &CompliantExecutor).expect("breaker gate passes");
    breaker::publish(validated, &pass, &gov_for(id, &group)).expect("published")
}

// ------------------------------------------------------------------ r11_agent_rung
// gap (medium): Agent rung = persona + skills + capabilities + model policy as a governed ladder unit.

#[test]
fn r11_agent_rung() {
    let a = good_agent("agent-1");
    assert!(a.validate().is_empty(), "a coherent agent validates clean");
    assert_eq!(a.max_capability_class(), DataClass::Internal);

    // Empty persona / no skills+caps / no provider are all rejected.
    let bad = AgentRung::new("x", "  ", ModelPolicy::new(&[], DataClass::Public));
    let errs = bad.validate();
    assert!(errs.iter().any(|e| e.contains("empty persona")));
    assert!(errs
        .iter()
        .any(|e| e.contains("neither skills nor capabilities")));
    assert!(errs.iter().any(|e| e.contains("no allowed providers")));

    // Least-privilege coherence: a capability may not out-rank the model policy ceiling.
    let over = AgentRung::new("a", "p", ModelPolicy::new(&["openai"], DataClass::Internal))
        .with_capability(Capability::new("pii.read", DataClass::Pii));
    assert!(over.validate().iter().any(|e| e.contains("over-privilege")));
}

// ------------------------------------------------------------------ r11_role_rung
// gap (high): Role rung = digital worker (charter + skills + connectors + knowledge + governance +
// KPIs + autonomy composition), with §5 responsible-reality + gaps N/P/AI baked into validation.

#[test]
fn r11_role_rung() {
    // A well-formed digital worker validates.
    let role = passing_spec("role-support").validate().expect("valid role");
    assert_eq!(role.id(), "role-support");
    assert_eq!(role.spec().agents.len(), 1);

    // Missing escalation rules -> rejected (a worker must know when to hand off).
    let mut s = passing_spec("r");
    s.charter.escalation_rules.clear();
    assert!(s
        .validate()
        .unwrap_err()
        .iter()
        .any(|e| e.contains("escalation rules")));

    // Gap N: regulated data on a Cloud residency is rejected.
    let mut s = passing_spec("r");
    s.connectors.push(ConnectorRef::new(
        "payments.ledger",
        DataClass::RegulatedPayment,
    ));
    s.governance.residency = Residency::Cloud;
    assert!(s
        .validate()
        .unwrap_err()
        .iter()
        .any(|e| e.contains("regulated/PII must stay in-house")));

    // Gap P: High model-risk cannot default to Auto.
    let mut s = passing_spec("r");
    s.governance.model_risk_class = ModelRiskClass::High;
    s.autonomy = AutonomyModel::new(AutonomyLevel::Auto, 0.5);
    assert!(s
        .validate()
        .unwrap_err()
        .iter()
        .any(|e| e.contains("High model-risk")));

    // Gap AI + payment perimeter: a payment-boundary role must carry OBO authority.
    let mut s = passing_spec("r");
    s.payment_boundary = PaymentBoundary::Direct;
    s.governance.obo_authority = false;
    assert!(s
        .validate()
        .unwrap_err()
        .iter()
        .any(|e| e.contains("on-behalf-of")));

    // retention_days = 0 (gap Q) rejected.
    let mut s = passing_spec("r");
    s.governance.retention_days = 0;
    assert!(s
        .validate()
        .unwrap_err()
        .iter()
        .any(|e| e.contains("retention_days")));
}

// ------------------------------------------------------------------ r11_autonomy_dial
// gap (medium): per-task autonomy dial.

#[test]
fn r11_autonomy_dial() {
    let m = good_autonomy();
    // Per-task override vs default.
    assert_eq!(m.resolve("password-reset"), AutonomyLevel::Auto);
    assert_eq!(m.resolve("unknown"), AutonomyLevel::Escalate);
    assert_eq!(m.resolve("not-listed"), AutonomyLevel::Assisted); // falls back to default

    // Escalation is uncertainty-driven (gap U).
    assert!(m.should_escalate(0.8));
    assert!(!m.should_escalate(0.5));
    assert!(m.has_escalation_path());

    // §5: a regulated task can never be Auto.
    let bad = AutonomyModel::new(AutonomyLevel::Assisted, 0.5)
        .with_task(TaskAutonomy::new("initiate-settlement", AutonomyLevel::Auto).regulated());
    assert!(bad
        .validate()
        .iter()
        .any(|e| e.contains("cannot be dialed to Auto")));

    // Out-of-range threshold rejected.
    let bad2 = AutonomyModel::new(AutonomyLevel::Auto, 1.5);
    assert!(bad2.validate().iter().any(|e| e.contains("outside")));
}

// ------------------------------------------------------------------ r11_breaker_gate
// gap (high): Breaker (adversarial Test Agent) as a mandatory, non-skippable role-publish gate.

#[test]
fn r11_breaker_gate() {
    // A sound role passes every probe + the actual adversarial run, and can be published to
    // Production through the git-native governed-publish lifecycle.
    let role = passing_spec("role-1").validate().unwrap();
    let report = Breaker::run(&role);
    assert_eq!(report.verdict, BreakerVerdict::Pass);
    assert!(report.probes.iter().all(|p| p.passed));
    let pass = Breaker::gate(&role, &CompliantExecutor).expect("full gate passes");
    let published = breaker::publish(role, &pass, &gov_for("role-1", "support-leads"))
        .expect("governed publish");
    assert_eq!(
        published.state(),
        ainxt_governance::GovernanceState::Production
    );

    // A role with NO KPI cannot be measured -> the Breaker gate fails on the static battery -> NO
    // sealed pass is produced, so there is no way to reach `publish` at all. This is the
    // non-skippable, un-forgeable gate.
    let mut spec = passing_spec("role-2");
    spec.kpis.clear();
    let role2 = spec.validate().unwrap();
    match Breaker::gate(&role2, &CompliantExecutor) {
        Err(GateError::StaticBatteryFailed { failed_probes }) => {
            assert!(failed_probes.iter().any(|p| p == "quality-measurable"));
        }
        other => panic!("expected StaticBatteryFailed, got {other:?}"),
    }

    // A sealed pass from a different role cannot be used to publish (no token-swapping past the gate).
    let role_a = passing_spec("role-a").validate().unwrap();
    let role_b = passing_spec("role-b").validate().unwrap();
    let pass_a = Breaker::gate(&role_a, &CompliantExecutor).expect("gate a");
    match breaker::publish(role_b, &pass_a, &gov_for("role-b", "support-leads")) {
        Err(PublishError::ReportMismatch) => {
            // Role IDs are intentionally omitted from the error to prevent secret/token leakage.
        }
        other => panic!("expected ReportMismatch, got {other:?}"),
    }

    // A PII role without OBO authority is now rejected at VALIDATION (fail-closed, derived from the
    // data class) — the strongest form of the "PII requires OBO" guarantee, ahead of the Breaker.
    let mut spec = passing_spec("role-pii");
    spec.knowledge.push({
        let mut k = KnowledgeScope::new("kb:hr", DataClass::Pii);
        k.retrieval_quality = Some(0.9);
        k
    });
    spec.governance.residency = Residency::InHouse;
    spec.governance.obo_authority = false;
    let errs = spec.validate().expect_err("PII-no-OBO must be rejected");
    assert!(errs.iter().any(|e| e.contains("on-behalf-of")));
}

// ------------------------------------------------------------------ r11_role_studio
// gap (high): Role Studio conversational authoring flow (Steps 0-10) as a typed state machine.

#[test]
fn r11_role_studio() {
    // Happy path: walk all 10 steps to a published, monitored digital worker.
    let mut spec = passing_spec("studio-role");
    // Knowledge starts UNchecked; the Studio's Step-5 check fills retrieval quality.
    spec.knowledge = vec![KnowledgeScope::new("kb:support", DataClass::Internal)];
    let mut studio = RoleStudio::start(Template::Support);
    assert_eq!(studio.stage(), StudioStage::Start);

    studio.describe_and_draft(spec).unwrap();
    assert_eq!(studio.stage(), StudioStage::Drafted);
    studio.govern().unwrap();
    studio.set_autonomy().unwrap();
    studio
        .check_knowledge(&[("kb:support", 0.88)], 0.6)
        .unwrap();
    assert_eq!(studio.stage(), StudioStage::KnowledgeChecked);
    studio.define_kpis().unwrap();

    let report = studio
        .run_breaker(&CompliantExecutor)
        .expect("breaker passes");
    assert_eq!(report.verdict, BreakerVerdict::Pass);
    assert_eq!(studio.stage(), StudioStage::BreakerPassed);

    studio.shadow_run(ShadowResult::new(100, 96)).unwrap();
    let published = studio
        .publish(&gov_for("studio-role", "support-leads"))
        .expect("governed publish");
    assert_eq!(
        published.state(),
        ainxt_governance::GovernanceState::Production
    );
    studio.monitor().unwrap();
    assert_eq!(studio.stage(), StudioStage::Monitoring);

    // Out-of-order: cannot govern before drafting.
    let mut s2 = RoleStudio::start(Template::Blank);
    assert!(matches!(s2.govern(), Err(StudioError::OutOfOrder { .. })));

    // Retrieval-quality gap blocks Step 5.
    let mut spec = passing_spec("studio-gap");
    spec.knowledge = vec![KnowledgeScope::new("kb:thin", DataClass::Internal)];
    let mut s3 = RoleStudio::start(Template::Support);
    s3.describe_and_draft(spec).unwrap();
    s3.govern().unwrap();
    s3.set_autonomy().unwrap();
    assert!(matches!(
        s3.check_knowledge(&[("kb:thin", 0.2)], 0.6),
        Err(StudioError::RetrievalQualityGap { .. })
    ));

    // The Breaker gate is non-skippable IN THE FLOW: a well-formed role that FAILS the actual
    // adversarial RUN (here: a role scripted to escalate/refuse-badly on every case via a default,
    // non-well-behaved executor) does NOT advance to Published — the machine stays at Kpis. This
    // proves the in-flow gate requires an actual adversarial run, not just the static battery.
    let mut spec = passing_spec("studio-breakerfail");
    spec.knowledge = vec![KnowledgeScope::new("kb:support", DataClass::Internal)];
    let mut s4 = RoleStudio::start(Template::Analyst);
    s4.describe_and_draft(spec).unwrap();
    s4.govern().unwrap();
    s4.set_autonomy().unwrap();
    s4.check_knowledge(&[("kb:support", 0.9)], 0.6).unwrap();
    s4.define_kpis().unwrap();
    // A default ScriptedExecutor answers every case with an escalation ("no scripted response"),
    // which fails the MustAnswerWithQuality (and MustRefuse) cases -> adversarial run fails.
    assert!(matches!(
        s4.run_breaker(&ScriptedExecutor::new()),
        Err(StudioError::BreakerFailed(_))
    ));
    assert_eq!(
        s4.stage(),
        StudioStage::Kpis,
        "machine must not advance past a failing Breaker"
    );
    // ...and publish is unreachable from Kpis.
    assert!(matches!(
        s4.publish(&gov_for("studio-breakerfail", "support-leads")),
        Err(StudioError::OutOfOrder { .. })
    ));
    assert!(s4.published().is_none());
}

// ------------------------------------------------------------------ r11_team_rung
// gap (medium): Team rung = digital department (governed org-level composition of collaborating roles).

#[test]
fn r11_team_rung() {
    let dev = publish_role("developer", "alice");
    let ops = publish_role("ops", "bob");

    // A consistent department assembles.
    let team = DigitalTeam::assemble(
        "team-platform",
        "Platform",
        "cto",
        vec![dev, ops],
        vec![Collaboration::new("developer", "ops", "hand off deploys")],
    )
    .expect("team assembles");
    assert_eq!(team.role_count(), 2);
    assert_eq!(team.department(), "Platform");

    // A dangling collaboration edge is rejected.
    let dev2 = publish_role("developer", "alice");
    let err = DigitalTeam::assemble(
        "t",
        "D",
        "o",
        vec![dev2],
        vec![Collaboration::new("developer", "ghost", "x")],
    )
    .unwrap_err();
    assert!(matches!(err, TeamError::DanglingEdge { .. }));

    // Self-collaboration is rejected.
    let dev3 = publish_role("developer", "alice");
    let err = DigitalTeam::assemble(
        "t",
        "D",
        "o",
        vec![dev3],
        vec![Collaboration::new("developer", "developer", "x")],
    )
    .unwrap_err();
    assert!(matches!(err, TeamError::SelfCollaboration(_)));

    // Duplicate role ids rejected.
    let a = publish_role("dup", "alice");
    let b = publish_role("dup", "alice");
    let err = DigitalTeam::assemble("t", "D", "o", vec![a, b], vec![]).unwrap_err();
    assert!(matches!(err, TeamError::DuplicateRole(_)));

    // Empty department rejected.
    assert!(matches!(
        DigitalTeam::assemble("t", "", "o", vec![publish_role("x", "y")], vec![]),
        Err(TeamError::EmptyDepartment)
    ));
}

// ------------------------------------------------------------------ r11_citizen_lifecycle
// gap (medium): §6 citizen-artifact lifecycle — decay-sweep, recert nudge, orphan detection,
// ownership-succession PR, forced-review-before-deprecation.

#[test]
fn r11_citizen_lifecycle() {
    let th = DecayThresholds::default(); // 180 days, declining <= 0.0

    // §6.1 decay: stale AND declining -> flagged once (no storm even if listed twice).
    let defs = vec![
        DefinitionTelemetry {
            definition_id: "role-stale".into(),
            owner: "alice".into(),
            kpi_trend_90d: -0.2,
            invocation_trend: -0.1,
            days_since_last_commit: 200,
            invocations_30d: 5,
        },
        DefinitionTelemetry {
            definition_id: "role-stale".into(), // duplicate telemetry row
            owner: "alice".into(),
            kpi_trend_90d: -0.3,
            invocation_trend: -0.2,
            days_since_last_commit: 210,
            invocations_30d: 5,
        },
        DefinitionTelemetry {
            definition_id: "role-fresh".into(),
            owner: "bob".into(),
            kpi_trend_90d: 0.3,
            invocation_trend: 0.1,
            days_since_last_commit: 10,
            invocations_30d: 500,
        },
    ];
    let flags = lifecycle::decay_sweep(&defs, &th);
    assert_eq!(
        flags.len(),
        1,
        "one flag per breaching def (no notification storm)"
    );
    assert_eq!(flags[0].definition_id, "role-stale");

    // §6.2 recert nudge.
    assert!(lifecycle::needs_recert(400, 200, 180));
    assert!(!lifecycle::needs_recert(300, 200, 180));

    // §6.3 orphan: a deactivated owner is flagged (never auto-disabled) + routed to their manager.
    let codeowners: BTreeSet<String> = ["alice".to_string()].into_iter().collect();
    let mut org = OrgTree::default();
    org.active.insert("alice".into(), false); // deactivated in org-tree sync
    org.manager.insert("alice".into(), "carol".into());
    let orphan_defs = vec![DefinitionTelemetry {
        definition_id: "role-orphan".into(),
        owner: "alice".into(),
        kpi_trend_90d: 0.0,
        invocation_trend: 0.0,
        days_since_last_commit: 5,
        invocations_30d: 42,
    }];
    let orphans = lifecycle::orphan_sweep(&orphan_defs, &codeowners, &org);
    assert_eq!(orphans.len(), 1);
    assert_eq!(orphans[0].notify_manager.as_deref(), Some("carol"));

    // §6.4 succession: owner-only ok; owner+body blocked; no-owner is not a succession.
    assert!(lifecycle::validate_succession(SuccessionDiff {
        changes_owner: true,
        changes_body: false
    })
    .is_ok());
    assert_eq!(
        lifecycle::validate_succession(SuccessionDiff {
            changes_owner: true,
            changes_body: true
        }),
        Err(SuccessionError::ConflatesBodyChange)
    );
    assert_eq!(
        lifecycle::validate_succession(SuccessionDiff {
            changes_owner: false,
            changes_body: true
        }),
        Err(SuccessionError::NotAnOwnershipChange)
    );

    // §6.5 forced review before deprecation: above the floor needs Breaker dry-run + manager sign-off.
    let floor = 0;
    assert_eq!(
        lifecycle::can_deprecate(
            DeprecationRequest {
                invocations_30d: 200,
                breaker_dry_run_passed: false,
                manager_approval: false
            },
            floor
        ),
        Err(vec![
            DeprecationBlock::NeedsBreakerDryRun,
            DeprecationBlock::NeedsManagerApproval
        ])
    );
    assert!(lifecycle::can_deprecate(
        DeprecationRequest {
            invocations_30d: 200,
            breaker_dry_run_passed: true,
            manager_approval: true
        },
        floor
    )
    .is_ok());
    // Below the floor, ordinary approval suffices.
    assert!(lifecycle::can_deprecate(
        DeprecationRequest {
            invocations_30d: 0,
            breaker_dry_run_passed: false,
            manager_approval: false
        },
        floor
    )
    .is_ok());
}

// ------------------------------------------------------------------ r11_oversight_health
// gap (medium): §7 automation-complacency controls — approve-latency + override-rate metrics,
// attention-check decoys, competency_status gate re-routing.

#[test]
fn r11_oversight_health() {
    // §7.1: an approver whose latency is below read-time and override-rate is 0 over enough volume
    // is flagged amber; a conscientious one is not.
    let mut events = Vec::new();
    for _ in 0..50 {
        events.push(ApprovalEvent {
            approver: "rubberstamp".into(),
            role: "risk".into(),
            latency_secs: 2,
            min_read_secs: 30,
            overridden: false,
        });
    }
    // A diligent approver: sometimes overrides, reads long enough.
    for i in 0..50 {
        events.push(ApprovalEvent {
            approver: "diligent".into(),
            role: "risk".into(),
            latency_secs: 120,
            min_read_secs: 30,
            overridden: i % 5 == 0,
        });
    }
    let metrics = oversight::oversight_health(&events, 20);
    let rs = metrics
        .iter()
        .find(|m| m.approver == "rubberstamp")
        .unwrap();
    assert!(
        rs.amber,
        "sub-read-time + zero-override at volume is the complacency signature"
    );
    assert_eq!(rs.override_rate, 0.0);
    let dg = metrics.iter().find(|m| m.approver == "diligent").unwrap();
    assert!(!dg.amber);
    assert!(dg.override_rate > 0.0);

    // §7.2: decoys only for high-stakes; approving a decoy is an incident + mandatory retraining.
    assert!(oversight::should_inject_decoy(
        PaymentBoundary::Direct,
        DataClass::Internal
    ));
    assert!(oversight::should_inject_decoy(
        PaymentBoundary::None,
        DataClass::RegulatedPayment
    ));
    assert!(!oversight::should_inject_decoy(
        PaymentBoundary::None,
        DataClass::Internal
    ));
    let check = AttentionCheck {
        decoy_id: "d1".into(),
        role: "risk".into(),
    };
    match oversight::evaluate_decoy(&check, "carol", true) {
        DecoyOutcome::Incident {
            approver,
            mandatory_retraining,
        } => {
            assert_eq!(approver, "carol");
            assert!(mandatory_retraining);
        }
        other => panic!("approving a decoy must be an incident, got {other:?}"),
    }
    assert_eq!(
        oversight::evaluate_decoy(&check, "carol", false),
        DecoyOutcome::CorrectlyRejected
    );

    // §7.3: expired competency RE-ROUTES to a secondary (never blocks the workflow).
    assert_eq!(
        oversight::competency_after(30, 25, false),
        CompetencyStatus::Expired
    );
    assert_eq!(
        oversight::competency_after(5, 25, false),
        CompetencyStatus::Current
    );
    assert_eq!(
        oversight::competency_after(0, 25, true),
        CompetencyStatus::Expired
    );
    match oversight::competency_route("primary", CompetencyStatus::Expired, "secondary") {
        ApprovalRoute::Rerouted { from, to, .. } => {
            assert_eq!(from, "primary");
            assert_eq!(to, "secondary");
        }
        other => panic!("expired competency must re-route, got {other:?}"),
    }
    assert_eq!(
        oversight::competency_route("primary", CompetencyStatus::Current, "secondary"),
        ApprovalRoute::Primary("primary".into())
    );
}
