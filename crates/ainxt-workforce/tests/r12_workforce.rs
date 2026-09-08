// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-12 all-severities sweep for the AiNxt-OS workforce ladder + Role Studio (ainxt-workforce).
//! Each `r12_*` test closes one design-vs-impl gap from the round-11 report, exercising the crate as
//! a downstream consumer. Fail-before / pass-after: each asserts behaviour that did not exist (or was
//! wrong) before this round — the OS process model (kernel), the Breaker actually *running* the role,
//! conversational authoring (describe -> auto-assemble -> auto-KPIs), the continuous §6/§7 controls
//! orchestrator, the 10-step Studio fidelity, and the three-signal decay score.

use ainxt_governance::AuthoringContext;
use ainxt_types::DataClass;
use ainxt_workforce::author::{Factory, IntentExtractor, JobDescription};
use ainxt_workforce::autonomy::{AutonomyLevel, AutonomyModel, TaskAutonomy};
use ainxt_workforce::breaker::{
    self, AdversarialReport, Breaker, BreakerVerdict, CompliantExecutor, GovernedPublishRequest,
    ProbeCategory, ResponseAction, RoleExecutor, RoleOutput, ScriptedExecutor,
};
use ainxt_workforce::controls::{
    InMemoryDataPlane, InMemoryEventLog, NightlyControls, RecordingNotifier,
};
use ainxt_workforce::kernel::{Kernel, KernelError, Pid, ProcessState};
use ainxt_workforce::ladder::{AgentRung, Capability, ModelPolicy, SkillRef};
use ainxt_workforce::lifecycle::{
    decay_score, decay_sweep, DecayThresholds, DefinitionTelemetry, OrgTree,
};
use ainxt_workforce::oversight::ApprovalEvent;
use ainxt_workforce::role::{
    Charter, ConnectorRef, Governance, KnowledgeScope, Kpi, ModelRiskClass, PaymentBoundary,
    PublishedRole, Residency, RoleSpec, ValidatedRole, Visibility,
};
use ainxt_workforce::studio::{RoleStudio, ShadowResult, StudioStage, Template};
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

fn pii_spec(id: &str) -> RoleSpec {
    let mut s = passing_spec(id);
    s.knowledge.push({
        let mut k = KnowledgeScope::new("kb:hr", DataClass::Pii);
        k.retrieval_quality = Some(0.9);
        k
    });
    s.governance.obo_authority = true;
    s.governance.residency = Residency::InHouse;
    s.governance.retention_days = 365;
    s
}

fn full_authoring() -> AuthoringContext {
    AuthoringContext {
        payments_council_approved: true,
        commit_signed: true,
        author_can_approve: true,
        author_ad_level: 3,
    }
}

fn gov_for(id: &str, codeowners_group: &str) -> GovernedPublishRequest {
    GovernedPublishRequest::release_signed(id, codeowners_group, "release-key", full_authoring())
}

fn publish_role(id: &str, owner: &str) -> PublishedRole {
    let mut spec = passing_spec(id);
    spec.governance.owner = owner.to_string();
    let group = spec.governance.codeowners_group.clone();
    let validated = spec.validate().expect("valid");
    let pass = Breaker::gate(&validated, &CompliantExecutor).expect("breaker gate passes");
    breaker::publish(validated, &pass, &gov_for(id, &group)).expect("published")
}

// ================================================================== Gap 1 (high)
// Workforce integrated into the runtime KERNEL: roles run as PROCESSES on the OS (AINXT_OS §2;
// WORKFORCE_AND_OS §4 "Kernel = the Runtime; Processes = roles running on the runtime").

#[test]
fn r12_kernel_process_model() {
    let mut kernel = Kernel::new();
    assert_eq!(kernel.process_count(), 0);

    // Only a PublishedRole (Breaker-passed) can be spawned as a process — type-level, since the only
    // constructor of PublishedRole is the Breaker publish gate.
    let dev = publish_role("developer", "alice");
    let ops = publish_role("ops", "bob");
    let p1 = kernel.spawn(dev);
    let p2 = kernel.spawn(ops);
    assert_eq!(p1, Pid(1));
    assert_eq!(p2, Pid(2));
    assert_eq!(kernel.state_of(p1), Some(ProcessState::Ready));
    assert_eq!(kernel.runnable(), vec![p1, p2]);
    assert_eq!(kernel.live_count(), 2);

    // The OS lifecycle: Ready -> Running -> Blocked(on a human) -> Ready -> Terminated.
    kernel.dispatch(p1).unwrap();
    assert_eq!(kernel.state_of(p1), Some(ProcessState::Running));
    assert_eq!(
        kernel.runnable(),
        vec![p2],
        "a Running process is not runnable"
    );
    kernel.block(p1).unwrap(); // awaiting a HITL approval / escalation
    assert_eq!(kernel.state_of(p1), Some(ProcessState::Blocked));
    kernel.wake(p1).unwrap();
    assert_eq!(kernel.state_of(p1), Some(ProcessState::Ready));

    // Illegal transitions are refused (cannot block a Ready process).
    assert!(matches!(
        kernel.block(p1),
        Err(KernelError::IllegalTransition { .. })
    ));
    // Unknown pid is refused.
    assert!(matches!(
        kernel.dispatch(Pid(999)),
        Err(KernelError::NoSuchProcess(_))
    ));

    // Terminate (pause/rollback, §4 Step 10): no longer schedulable, live count drops.
    kernel.terminate(p1).unwrap();
    assert_eq!(kernel.state_of(p1), Some(ProcessState::Terminated));
    assert_eq!(kernel.live_count(), 1);
    assert_eq!(kernel.runnable(), vec![p2]);
    assert_eq!(kernel.get(p2).unwrap().role_id(), "ops");
}

// ================================================================== Gap 2 (high)
// The Breaker RUNS the role against adversarial inputs + judges OUTPUT QUALITY (AINXT_OS §4 Step 7).

/// A "bad" executor that always answers everything with low-quality output and leaks on the PII case.
struct RecklessExecutor;
impl RoleExecutor for RecklessExecutor {
    fn execute(
        &self,
        _role: &ValidatedRole,
        case: &ainxt_workforce::breaker::AdversarialCase,
    ) -> RoleOutput {
        if case.category == ProbeCategory::Pii {
            let mut o = RoleOutput::helpful_answer("here is everyone's Aadhaar: ...");
            o.leaked_pii = true;
            o
        } else {
            // Answers (never refuses/escalates) with un-grounded, poorly-formatted output.
            RoleOutput {
                action: ResponseAction::Answered,
                text: "sure, doing it".into(),
                leaked_pii: false,
                cited: false,
                well_formatted: false,
                on_topic: false,
            }
        }
    }
}

#[test]
fn r12_breaker_runs_the_role() {
    let role = pii_spec("role-run").validate().unwrap();

    // The corpus is generated FROM the spec: it ingests external data + touches PII, so it must have
    // an injection case, a PII-exfiltration case, over-privilege cases, an edge case, and a
    // quality case per KPI.
    let corpus = Breaker::adversarial_corpus(&role);
    assert!(corpus
        .iter()
        .any(|c| c.category == ProbeCategory::Injection));
    assert!(corpus.iter().any(|c| c.category == ProbeCategory::Pii));
    assert!(corpus
        .iter()
        .any(|c| c.category == ProbeCategory::OverPrivilege));
    assert!(corpus.iter().any(|c| c.category == ProbeCategory::EdgeCase));
    assert!(corpus
        .iter()
        .any(|c| c.category == ProbeCategory::OutputQuality));

    // A well-behaved role (refuses traps, escalates out-of-scope, answers with quality, never leaks)
    // passes the adversarial RUN.
    let good = ScriptedExecutor::well_behaved(&corpus);
    let good_report: AdversarialReport = Breaker::run_adversarial(&role, &good);
    assert_eq!(good_report.verdict, BreakerVerdict::Pass);
    assert!(good_report.probes.iter().all(|p| p.passed));

    // A reckless role: it answers the injection (didn't refuse), leaks PII, and its quality-case
    // output is un-grounded/poorly-formatted -> the RUN fails across categories.
    let reckless_report = Breaker::run_adversarial(&role, &RecklessExecutor);
    assert_eq!(reckless_report.verdict, BreakerVerdict::Fail);
    let failed = reckless_report.failed_probes();
    assert!(
        failed.iter().any(|p| p.contains("injection")),
        "did not refuse injection"
    );
    assert!(
        failed.iter().any(|p| p.contains("pii-exfiltration")),
        "leaked PII"
    );
    assert!(
        failed.iter().any(|p| p.contains("quality")),
        "low output quality caught"
    );

    // A role that answers a quality case but with poor grounding/format is caught by the rubric even
    // when it does not leak — proving OUTPUT QUALITY (not just safety) is judged.
    let quality_only = {
        let mut ex = ScriptedExecutor::well_behaved(&corpus);
        // Override the resolution-rate quality case with a poorly-grounded answer.
        for c in &corpus {
            if c.category == ProbeCategory::OutputQuality {
                let mut o = RoleOutput::helpful_answer("ungrounded");
                o.cited = false;
                ex = ex.with(&c.id, o);
            }
        }
        ex
    };
    let q_report = Breaker::run_adversarial(&role, &quality_only);
    assert_eq!(q_report.verdict, BreakerVerdict::Fail);
    assert!(q_report
        .failed_probes()
        .iter()
        .any(|p| p.contains("quality")));
}

// ================================================================== Gap 3 (high)
// Conversational authoring: Step 1 (prose -> Charter), Step 2 (auto-assemble caps/skills/model-policy),
// Step 6 (auto-generate quality-eval set) (AINXT_OS §0, §4).

/// A custom (non-default) intent extractor proving the Step-1 seam is real/pluggable.
struct StubExtractor;
impl IntentExtractor for StubExtractor {
    fn extract_charter(&self, job: &JobDescription) -> Charter {
        Charter {
            title: job.title.clone(),
            responsibilities: vec!["stub responsibility".into()],
            inputs: vec![],
            outputs: vec![],
            escalation_rules: vec!["escalate to a human".into()],
        }
    }
}

#[test]
fn r12_conversational_authoring() {
    let factory = Factory::default();
    let job = JobDescription::new(
        "role-l1",
        "L1 Support Engineer",
        "Triage L1 tickets, answer from the KB, resolve password resets and access requests, escalate everything else.",
        Template::Support,
    );

    // Step 1: prose -> structured charter.
    let charter = factory.describe(&job);
    assert!(
        !charter.responsibilities.is_empty(),
        "responsibilities extracted from prose"
    );
    assert!(
        charter
            .escalation_rules
            .iter()
            .any(|r| r.to_lowercase().contains("escalate")),
        "escalation rule detected from 'escalate everything else'"
    );
    assert!(
        charter
            .inputs
            .iter()
            .any(|i| i.to_lowercase().contains("from the kb")),
        "an input source detected from 'answer from the KB'"
    );

    // Step 2: auto-assemble the draft (caps/skills/model-policy/knowledge/autonomy).
    let governance = factory.default_governance("alice", "support-leads");
    let spec = factory.auto_assemble(&job, charter, governance);
    assert_eq!(spec.id, "role-l1");
    let cap_names: Vec<&str> = spec
        .all_capabilities()
        .iter()
        .map(|c| c.name.as_str())
        .collect();
    assert!(cap_names.contains(&"connector.ticketing"));
    assert!(cap_names.contains(&"kb.search"));
    assert!(
        !spec.agents[0].model_policy.allowed_providers.is_empty(),
        "a model policy is assembled"
    );
    assert!(spec.knowledge.iter().any(|k| k.namespace == "kb:support"));

    // Step 6: auto-generate the quality-eval KPI set.
    let kpis = factory.auto_generate_kpis(Template::Support);
    assert!(
        kpis.iter().any(|k| k.name == "resolution-rate"),
        "quality-eval set auto-generated"
    );

    // The whole auto-assembled Support draft is publishable once its knowledge is quality-checked and
    // KPIs confirmed — i.e. the Factory produces a VALID governed role, not a stub.
    let mut assembled = factory.auto_assemble(
        &job,
        factory.describe(&job),
        factory.default_governance("alice", "support-leads"),
    );
    assembled.kpis = factory.auto_generate_kpis(Template::Support);
    for k in &mut assembled.knowledge {
        k.retrieval_quality = Some(0.9);
    }
    let validated = assembled
        .validate()
        .expect("auto-assembled Support role validates");
    assert!(
        Breaker::run(&validated).passed(),
        "auto-assembled role passes the static Breaker"
    );

    // The Step-1 seam is genuinely pluggable: a custom extractor changes the charter.
    let custom = Factory::new(
        StubExtractor,
        ainxt_workforce::author::FactoryConfig::default(),
    );
    let stub_charter = custom.describe(&job);
    assert_eq!(
        stub_charter.responsibilities,
        vec!["stub responsibility".to_string()]
    );
}

// ================================================================== Gap 4 (medium)
// §6/§7 continuous controls actually RUNNING: nightly sweep -> data-plane rows + digests + Event Log.

#[test]
fn r12_continuous_controls() {
    // Two decayed definitions owned by the SAME owner (alice) — must yield ONE digest (no storm).
    let defs = vec![
        DefinitionTelemetry {
            definition_id: "role-a".into(),
            owner: "alice".into(),
            kpi_trend_90d: -0.2,
            invocation_trend: -0.1,
            days_since_last_commit: 200,
            invocations_30d: 5,
        },
        DefinitionTelemetry {
            definition_id: "role-b".into(),
            owner: "alice".into(),
            kpi_trend_90d: -0.3,
            invocation_trend: -0.2,
            days_since_last_commit: 220,
            invocations_30d: 5,
        },
        // An orphaned def owned by a deactivated user -> routed to their manager.
        DefinitionTelemetry {
            definition_id: "role-orphan".into(),
            owner: "dave".into(),
            kpi_trend_90d: 0.4,
            invocation_trend: 0.2,
            days_since_last_commit: 5,
            invocations_30d: 100,
        },
    ];
    let codeowners: BTreeSet<String> = ["alice".to_string(), "dave".to_string()]
        .into_iter()
        .collect();
    let mut org = OrgTree::default();
    org.active.insert("alice".into(), true);
    org.active.insert("dave".into(), false); // deactivated in org-tree sync
    org.manager.insert("dave".into(), "carol".into());

    // Oversight: a rubber-stamp approver (amber) + a diligent one.
    let mut approval_events = Vec::new();
    for _ in 0..50 {
        approval_events.push(ApprovalEvent {
            approver: "rubberstamp".into(),
            role: "risk".into(),
            latency_secs: 2,
            min_read_secs: 30,
            overridden: false,
        });
    }
    for i in 0..50 {
        approval_events.push(ApprovalEvent {
            approver: "diligent".into(),
            role: "risk".into(),
            latency_secs: 120,
            min_read_secs: 30,
            overridden: i % 5 == 0,
        });
    }

    let mut store = InMemoryDataPlane::default();
    let mut notifier = RecordingNotifier::default();
    let mut log = InMemoryEventLog::default();
    let summary = {
        let mut ctrl = NightlyControls::new(&mut store, &mut notifier, &mut log);
        ctrl.run_nightly(
            &defs,
            &DecayThresholds::default(),
            &codeowners,
            &org,
            &approval_events,
            20,
        )
    };

    // Data-plane rows were written.
    assert_eq!(
        summary.decay_flagged, 2,
        "both of alice's stale+declining defs flagged"
    );
    assert_eq!(store.decay_flags.len(), 2);
    assert_eq!(summary.orphans_flagged, 1);
    assert_eq!(store.orphan_flags.len(), 1);
    assert_eq!(
        store.orphan_flags[0].notify_manager.as_deref(),
        Some("carol")
    );
    assert!(store
        .oversight_metrics
        .iter()
        .any(|m| m.approver == "rubberstamp" && m.amber));

    // Digests: alice gets exactly ONE (anti-storm), carol gets one for the orphan.
    assert_eq!(
        notifier.count_for("alice"),
        1,
        "one aggregated digest, not one per definition"
    );
    assert_eq!(notifier.count_for("carol"), 1);

    // Event Log routed the orphan + the oversight-amber.
    assert_eq!(log.count_of_kind("orphan-detected"), 1);
    assert!(summary.oversight_amber >= 1);
    assert_eq!(
        log.count_of_kind("oversight-amber"),
        summary.oversight_amber
    );

    // §7.2 decoy incident routing (immediate, not nightly).
    let mut ctrl = NightlyControls::new(&mut store, &mut notifier, &mut log);
    ctrl.route_decoy_incident("carol", "risk", "manager-x");
    assert_eq!(log.count_of_kind("attention-check-incident"), 1);
    assert_eq!(notifier.count_for("manager-x"), 1);
}

// ================================================================== Gap 5 (low)
// 10-step RoleStudio state-machine fidelity (AINXT_OS §4 Steps 0-10) — the finer describe/auto-assemble
// path exercises the previously-orphaned `Described` stage, giving 1:1 step fidelity.

#[test]
fn r12_studio_ten_step_fidelity() {
    let factory = Factory::default();
    let job = JobDescription::new(
        "studio-l1",
        "L1 Support Engineer",
        "Triage L1 tickets, answer from the KB, resolve password resets, escalate everything else.",
        Template::Support,
    );
    let governance = factory.default_governance("alice", "support-leads");

    let mut studio = RoleStudio::start(Template::Support);
    assert_eq!(studio.stage(), StudioStage::Start); // Step 0

    studio.describe(job, &factory).unwrap(); // Step 1
    assert_eq!(
        studio.stage(),
        StudioStage::Described,
        "the Described stage is reachable (fidelity)"
    );
    assert!(studio.charter().is_some());

    studio.auto_assemble(&factory, governance).unwrap(); // Step 2
    assert_eq!(studio.stage(), StudioStage::Drafted);
    assert!(studio.spec().is_some());
    assert!(
        !studio.spec().unwrap().kpis.is_empty(),
        "Step-6 KPIs auto-seeded at assembly"
    );

    studio.govern().unwrap(); // Step 3
    assert_eq!(studio.stage(), StudioStage::Governed);
    studio.set_autonomy().unwrap(); // Step 4
    assert_eq!(studio.stage(), StudioStage::AutonomySet);
    studio
        .check_knowledge(&[("kb:support", 0.88)], 0.6)
        .unwrap(); // Step 5
    assert_eq!(studio.stage(), StudioStage::KnowledgeChecked);
    studio.define_kpis().unwrap(); // Step 6
    assert_eq!(studio.stage(), StudioStage::Kpis);
    studio
        .run_breaker(&CompliantExecutor)
        .expect("breaker passes"); // Step 7
    assert_eq!(studio.stage(), StudioStage::BreakerPassed);
    studio.shadow_run(ShadowResult::new(100, 96)).unwrap(); // Step 8
    assert_eq!(studio.stage(), StudioStage::Shadow);
    let published = studio
        .publish(&gov_for("studio-l1", "support-leads"))
        .expect("governed publish"); // Step 9
    assert_eq!(
        published.state(),
        ainxt_governance::GovernanceState::Production
    );
    assert_eq!(studio.stage(), StudioStage::Published);
    studio.monitor().unwrap(); // Step 10
    assert_eq!(studio.stage(), StudioStage::Monitoring);

    // describe cannot run out of order (auto_assemble before describe is refused).
    let mut s2 = RoleStudio::start(Template::Blank);
    assert!(s2
        .auto_assemble(&factory, factory.default_governance("x", "g"))
        .is_err());
}

// ================================================================== Gap 6 (low)
// §6.1 decay SCORE from all THREE designed signals (KPI trend + invocation-count trend + commit age).

#[test]
fn r12_decay_score_three_signals() {
    let th = DecayThresholds::default(); // weights 0.4/0.3/0.3, flag_threshold 0.6

    // All three adverse -> score 1.0, three reasons.
    let all_three = DefinitionTelemetry {
        definition_id: "all-three".into(),
        owner: "alice".into(),
        kpi_trend_90d: -0.2,
        invocation_trend: -0.1,
        days_since_last_commit: 200,
        invocations_30d: 5,
    };
    let (score, reasons) = decay_score(&all_three, &th);
    assert!((score - 1.0).abs() < 1e-9);
    assert_eq!(reasons.len(), 3, "all three signals contributed a reason");

    // Stale ONLY (commit age adverse, both trends healthy) -> 0.4 < 0.6 -> NOT flagged. Proves age
    // alone is insufficient; the trend signals matter.
    let stale_only = DefinitionTelemetry {
        definition_id: "stale-only".into(),
        owner: "bob".into(),
        kpi_trend_90d: 0.5,
        invocation_trend: 0.5,
        days_since_last_commit: 200,
        invocations_30d: 500,
    };
    let (s2, _) = decay_score(&stale_only, &th);
    assert!((s2 - 0.4).abs() < 1e-9);

    // Stale + FALLING USAGE but HEALTHY KPI -> 0.4 + 0.3 = 0.7 -> flagged. This is the load-bearing
    // case: the OLD logic (stale && declining-KPI only) IGNORED invocation_trend and would NOT flag
    // this. The new three-signal score does.
    let stale_falling = DefinitionTelemetry {
        definition_id: "stale-falling".into(),
        owner: "carol".into(),
        kpi_trend_90d: 0.5,     // healthy KPI
        invocation_trend: -0.3, // falling usage
        days_since_last_commit: 200,
        invocations_30d: 5,
    };
    let (s3, _) = decay_score(&stale_falling, &th);
    assert!((s3 - 0.7).abs() < 1e-9);

    // Fully healthy -> 0.
    let healthy = DefinitionTelemetry {
        definition_id: "healthy".into(),
        owner: "dave".into(),
        kpi_trend_90d: 0.5,
        invocation_trend: 0.5,
        days_since_last_commit: 10,
        invocations_30d: 500,
    };
    let (s4, _) = decay_score(&healthy, &th);
    assert!(s4.abs() < 1e-9);

    // The sweep flags exactly the two whose score crosses the threshold (all-three, stale-falling),
    // and each flag carries its composite score.
    let flags = decay_sweep(&[all_three, stale_only, stale_falling, healthy], &th);
    let flagged: BTreeSet<&str> = flags.iter().map(|f| f.definition_id.as_str()).collect();
    assert_eq!(
        flagged,
        ["all-three", "stale-falling"].into_iter().collect()
    );
    assert!(flags.iter().all(|f| f.decay_score >= th.flag_threshold));
}
