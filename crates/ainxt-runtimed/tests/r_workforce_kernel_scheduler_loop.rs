// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX os-workforce (HIGH) — `WorkforceSurface::dispatch_process`/`runnable_processes` were
//! reachable primitives with zero automatic driver: a role admitted `Ready` stayed `Ready` forever
//! unless some caller manually polled and dispatched it by hand. Proves
//! `WorkforceSurface::spawn_kernel_scheduler` is a REAL background loop that automatically moves
//! `Ready` processes to `Running` on a live `tokio::time::interval` tick, with no caller manually
//! calling `dispatch_process` — the scheduler drives it, not the test.

use std::sync::Arc;
use std::time::Duration;

use ainxt_governance::AuthoringContext;
use ainxt_runtimed::{assemble_workforce_surface, ShadowCase};
use ainxt_types::DataClass;
use ainxt_workforce::autonomy::{AutonomyLevel, AutonomyModel, TaskAutonomy};
use ainxt_workforce::breaker::{GovernedPublishRequest, ResponseAction};
use ainxt_workforce::kernel::ProcessState;
use ainxt_workforce::ladder::{AgentRung, Capability, ModelPolicy, SkillRef};
use ainxt_workforce::role::{
    Charter, ConnectorRef, Governance, KnowledgeScope, Kpi, ModelRiskClass, PaymentBoundary,
    Residency, RoleSpec, Visibility,
};

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

#[tokio::test]
async fn r_kernel_scheduler_loop_auto_dispatches_ready_processes() {
    let surface = Arc::new(assemble_workforce_surface());
    let published = surface
        .publish_role(
            passing_spec("svc-scheduled"),
            &[],
            &passing_shadow_cases(),
            &gov_for("svc-scheduled"),
        )
        .expect("governed publish");
    // A second, independent process this test owns (publish_role already admitted one on its own).
    let pid = surface.spawn_process(published);
    assert_eq!(surface.process_state(pid), Some(ProcessState::Ready));
    assert!(surface.runnable_processes().contains(&pid));

    // Start the real scheduler loop. Nothing in this test ever calls `dispatch_process` itself.
    let _handle = surface.spawn_kernel_scheduler(Duration::from_millis(5));

    // Give the interval loop a few ticks to observe and act on the Ready pid.
    let mut moved = false;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(5)).await;
        if surface.process_state(pid) == Some(ProcessState::Running) {
            moved = true;
            break;
        }
    }
    assert!(
        moved,
        "scheduler loop did not auto-dispatch a Ready process to Running in time"
    );
    assert!(
        !surface.runnable_processes().contains(&pid),
        "a Running process is not runnable"
    );
}

#[tokio::test]
async fn r_kernel_scheduler_loop_ignores_non_ready_processes() {
    let surface = Arc::new(assemble_workforce_surface());
    let published = surface
        .publish_role(
            passing_spec("svc-blocked"),
            &[],
            &passing_shadow_cases(),
            &gov_for("svc-blocked"),
        )
        .expect("governed publish");
    let pid = surface.spawn_process(published);

    // Drive it to Blocked by hand BEFORE starting the loop.
    surface.dispatch_process(pid).expect("dispatch");
    surface.block_process(pid).expect("block");
    assert_eq!(surface.process_state(pid), Some(ProcessState::Blocked));

    let _handle = surface.spawn_kernel_scheduler(Duration::from_millis(5));
    tokio::time::sleep(Duration::from_millis(60)).await;

    // The scheduler only auto-dispatches Ready pids; a Blocked one is untouched by construction
    // (Kernel::dispatch on a non-Ready pid is refused and silently skipped by the loop).
    assert_eq!(surface.process_state(pid), Some(ProcessState::Blocked));
}
