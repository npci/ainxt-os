// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-CLOSE os-workforce-exec #3 (HIGH) — `WorkforceSurface::spawn_kernel_scheduler` had a real,
//! unit-tested background loop (`r_workforce_kernel_scheduler_loop.rs`, which builds a bespoke
//! `WorkforceSurface` by hand and starts the loop on it itself), but ZERO non-test callers anywhere:
//! `assemble_workforce_surface_served` — the EXACT function the daemon's `--surface workforce`
//! dispatch (`assemble_selected`) calls in production — never started it. A role a served `publish_role`
//! admits onto the kernel as `Ready` would therefore have stayed `Ready` forever; the daemon's kernel
//! never actually ran anything.
//!
//! This test drives `assemble_selected(&loaded, "workforce")` — the served composition root — and
//! reads `Assembled::workforce_kernel`: a clone of the SAME `Kernel` `Arc` the scheduler this exact
//! function started is ticking over. It admits a genuinely Breaker-passed, governed-published role (the
//! same type-level invariant `Kernel::spawn` enforces: only a `PublishedRole` — mintable ONLY via
//! `RoleSpec::validate` -> the full `Breaker::gate` -> `breaker::publish` — can ever become a process)
//! directly onto that live table, then proves the `Ready -> Running` transition happens on its own — no
//! test code ever calls `dispatch`/`dispatch_process`. This is the one piece of the three-item round
//! that is NOT provable purely through a chat turn (the served `POST /v1/chat` handler
//! (`WorkforceTurnSurface::handle_turn`) only ever drives the validate+gate path, never
//! `publish_role`/kernel admission — that is a separate, larger gap tracked elsewhere, not one of
//! this round's three items), so the admission step below goes directly through the library's own
//! governed-publish functions rather than a chat turn; the SCHEDULER itself — the mechanism this item
//! closes — is proven live over the composition root's own kernel handle, not a disconnected copy.

use ainxt_governance::AuthoringContext;
use ainxt_runtimed::{assemble_selected, load_layered, LoadedConfig};
use ainxt_types::DataClass;
use ainxt_workforce::autonomy::{AutonomyLevel, AutonomyModel, TaskAutonomy};
use ainxt_workforce::breaker::{Breaker, CompliantExecutor, GovernedPublishRequest};
use ainxt_workforce::kernel::ProcessState;
use ainxt_workforce::ladder::{AgentRung, Capability, ModelPolicy, SkillRef};
use ainxt_workforce::role::{
    Charter, ConnectorRef, Governance, KnowledgeScope, Kpi, ModelRiskClass, PaymentBoundary,
    Residency, RoleSpec, Visibility,
};

fn offline() -> LoadedConfig {
    load_layered(&[("gap5-os-workforce-exec", "version = 1")]).unwrap()
}

fn passing_spec(id: &str) -> RoleSpec {
    RoleSpec {
        id: id.to_string(),
        charter: Charter {
            title: "Gap5 Kernel-Scheduler Worker".into(),
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
            obo_authority: false,
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

#[tokio::test(flavor = "multi_thread")]
async fn gap5_served_workforce_scheduler_auto_dispatches_a_ready_process_with_no_manual_dispatch() {
    let loaded = offline();

    // The REAL composition root — the exact function `main.rs`'s `--surface workforce` dispatch calls.
    // `assemble_workforce_surface_served` starts the kernel scheduler loop as a side effect of THIS
    // call, over the SAME kernel handle it hands back below.
    let assembled =
        assemble_selected(&loaded, "workforce").expect("--surface workforce must assemble");
    let kernel = assembled
        .workforce_kernel
        .clone()
        .expect("the served workforce surface must expose its real, live kernel handle");

    // Mint a genuinely governed PublishedRole via the library's own gate (spec.validate -> the FULL
    // Breaker::gate, static battery + an actual adversarial run through the deterministic well-behaved
    // CompliantExecutor -> breaker::publish). This is the SAME type-level invariant Kernel::spawn
    // enforces (only a Breaker-passed role can ever become a process) — not a shortcut around it.
    let spec = passing_spec("gap5-kernel-scheduled");
    let validated = spec.validate().expect("valid spec");
    let pass = Breaker::gate(&validated, &CompliantExecutor)
        .expect("the well-behaved role clears the real Breaker gate");
    let gov = GovernedPublishRequest::release_signed(
        "gap5-kernel-scheduled",
        "support-leads",
        "release-key",
        AuthoringContext {
            payments_council_approved: true,
            commit_signed: true,
            author_can_approve: true,
            author_ad_level: 3,
        },
    );
    let published = ainxt_workforce::breaker::publish(validated, &pass, &gov)
        .expect("the sealed pass clears the real git-native governed publish");

    // Admit it directly onto the served composition's OWN live kernel table — the exact table
    // `assemble_workforce_surface_served`'s scheduler loop is already ticking over.
    let pid = kernel.lock().unwrap().spawn(published);
    assert_eq!(
        kernel.lock().unwrap().state_of(pid),
        Some(ProcessState::Ready),
        "a freshly admitted process starts Ready"
    );

    // Wait for the REAL scheduler (started by the composition root, not by this test) to drive the
    // Ready -> Running transition on its own. No call to `dispatch`/`dispatch_process` anywhere in
    // this test.
    let mut moved_to_running = false;
    for _ in 0..50 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        if kernel.lock().unwrap().state_of(pid) == Some(ProcessState::Running) {
            moved_to_running = true;
            break;
        }
    }
    assert!(
        moved_to_running,
        "the served composition root's own kernel scheduler must auto-dispatch a Ready process to \
         Running without any manual dispatch call"
    );
}
