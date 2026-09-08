// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX os-workforce — the kernel's `Ready → Running → {Blocked → Ready} → Terminated`
//! process-transition primitives (`dispatch`/`block`/`wake`/`terminate`/`runnable`) were fully
//! implemented and unit-tested inside `ainxt-workforce`, but nothing past the initial `Ready`
//! admission (`spawn_process`) was reachable from the composition root. Proves
//! `WorkforceSurface::dispatch_process`/`block_process`/`wake_process`/`terminate_process`/
//! `runnable_processes` are reachable and enforce the SAME legal-transition rules as the kernel
//! itself, and that `ainxt_runtimed::evaluate_role_monitoring` (Step 10 continuous KPI/cost
//! monitoring) is reachable and returns the right decision tier.

use ainxt_governance::AuthoringContext;
use ainxt_runtimed::{assemble_workforce_surface, evaluate_role_monitoring, ShadowCase};
use ainxt_types::DataClass;
use ainxt_workforce::autonomy::{AutonomyLevel, AutonomyModel, TaskAutonomy};
use ainxt_workforce::breaker::{GovernedPublishRequest, ResponseAction};
use ainxt_workforce::kernel::{KernelError, ProcessState};
use ainxt_workforce::ladder::{AgentRung, Capability, ModelPolicy, SkillRef};
use ainxt_workforce::role::{
    Charter, ConnectorRef, Governance, KnowledgeScope, Kpi, ModelRiskClass, PaymentBoundary,
    Residency, RoleSpec, Visibility,
};
use ainxt_workforce::studio::MonitorDecision;

/// GAP-CLOSE os-workforce (gap6-workforce-governance-gate) — see the identical helper's doc in
/// `r13_workforce_surface_reachable.rs`.
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
fn r13_kernel_transitions_reachable_from_the_composition_root() {
    let surface = assemble_workforce_surface();
    let published = surface
        .publish_role(
            passing_spec("svc-kernel"),
            &[],
            &passing_shadow_cases(),
            &gov_for("svc-kernel"),
        )
        .expect("governed publish");
    // `publish_role` already admitted this role once (Step 9→10 continuity); spawn a second,
    // independent process for this role so this test owns its own pid to drive transitions on.
    let pid = surface.spawn_process(published);
    assert_eq!(surface.process_state(pid), Some(ProcessState::Ready));
    assert!(surface.runnable_processes().contains(&pid));

    // Ready -> Running.
    surface
        .dispatch_process(pid)
        .expect("dispatch a Ready process");
    assert_eq!(surface.process_state(pid), Some(ProcessState::Running));
    assert!(
        !surface.runnable_processes().contains(&pid),
        "a Running process is not runnable"
    );

    // Running -> Blocked (a HITL escalation).
    surface.block_process(pid).expect("block a Running process");
    assert_eq!(surface.process_state(pid), Some(ProcessState::Blocked));

    // Illegal: cannot dispatch a Blocked process directly.
    let illegal = surface.dispatch_process(pid);
    assert!(
        matches!(illegal, Err(KernelError::IllegalTransition { .. })),
        "dispatching a Blocked process must be refused, got {illegal:?}"
    );

    // Blocked -> Ready (the human responded), then dispatch again -> Running.
    surface.wake_process(pid).expect("wake a Blocked process");
    assert_eq!(surface.process_state(pid), Some(ProcessState::Ready));
    surface.dispatch_process(pid).expect("dispatch after wake");

    // GAP-FIX os-workforce — Running -> Ready (a cooperative yield), the one transition the original
    // dispatch/block/wake/terminate sweep skipped.
    surface.yield_process(pid).expect("yield a Running process");
    assert_eq!(surface.process_state(pid), Some(ProcessState::Ready));
    assert!(
        surface.runnable_processes().contains(&pid),
        "a yielded process is runnable again"
    );

    surface.dispatch_process(pid).expect("dispatch after yield");
    surface
        .terminate_process(pid)
        .expect("terminate a Running process");
    assert_eq!(surface.process_state(pid), Some(ProcessState::Terminated));
    assert!(!surface.runnable_processes().contains(&pid));

    // An unknown pid is refused, not silently accepted.
    let unknown = surface.dispatch_process(ainxt_workforce::kernel::Pid(999_999));
    assert!(matches!(unknown, Err(KernelError::NoSuchProcess(_))));
}

#[test]
fn r13_evaluate_role_monitoring_reachable_from_ainxt_runtimed() {
    let spec = passing_spec("svc-monitor");

    // Within bounds -> Continue.
    let ok = evaluate_role_monitoring(&spec, &[("resolution-rate", 0.9)], 100.0, 100.0);
    assert_eq!(ok, MonitorDecision::Continue);

    // Drifting below target but not collapsed, and within cost -> PauseForReview.
    let soft = evaluate_role_monitoring(&spec, &[("resolution-rate", 0.7)], 100.0, 100.0);
    assert!(
        matches!(soft, MonitorDecision::PauseForReview(_)),
        "got {soft:?}"
    );

    // KPI collapsed (<= 50% of target) -> Rollback.
    let hard = evaluate_role_monitoring(&spec, &[("resolution-rate", 0.2)], 100.0, 100.0);
    assert!(matches!(hard, MonitorDecision::Rollback(_)), "got {hard:?}");
}
