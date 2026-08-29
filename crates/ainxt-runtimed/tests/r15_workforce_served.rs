// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R15 — the served workforce turn handler now INGESTS a citizen-authored `RoleSpec`, not only the
//! fixed canonical golden-path role. Before this, `WorkforceTurnSurface::handle_turn` called
//! `gate_canonical()` unconditionally, so the served `POST /v1/chat` workforce turn could never gate
//! anything an actual caller authored — every turn, no matter its input, exercised the same fixed
//! role. Fail-before / pass-after: an authored-RoleSpec JSON turn now gates THAT role (and is
//! correctly refused when it is invalid), while a plain-text turn falls back to the canonical role
//! byte-identically (existing callers see no change).

use ainxt_governance::AuthoringContext;
use ainxt_protocol::{Event, Request};
use ainxt_runtime::{CancelToken, TurnHandler};
use ainxt_runtimed::{
    assemble_workforce_surface, run_workforce_nightly_tick, ShadowCase, WorkforceTurnSurface,
};
use ainxt_types::{DataClass, Principal};
use ainxt_workforce::autonomy::{AutonomyLevel, AutonomyModel, TaskAutonomy};
use ainxt_workforce::breaker::{GovernedPublishRequest, ResponseAction};
use ainxt_workforce::controls::{InMemoryDataPlane, InMemoryEventLog, RecordingNotifier};
use ainxt_workforce::ladder::{AgentRung, Capability, ModelPolicy, SkillRef};
use ainxt_workforce::lifecycle::{DecayThresholds, DefinitionTelemetry, OrgTree};
use ainxt_workforce::oversight::ApprovalEvent;
use ainxt_workforce::role::{
    Charter, ConnectorRef, Governance, KnowledgeScope, Kpi, ModelRiskClass, PaymentBoundary,
    Residency, RoleSpec, Visibility,
};
use tokio::sync::mpsc;

fn authored_role_spec(id: &str) -> RoleSpec {
    RoleSpec {
        id: id.to_string(),
        charter: Charter {
            title: "Citizen-Authored Ops Worker".into(),
            responsibilities: vec!["run runbooks".into()],
            inputs: vec!["alert".into()],
            outputs: vec!["remediation".into()],
            escalation_rules: vec!["escalate anything unrecognized".into()],
        },
        agents: vec![AgentRung::new(
            "agent-1",
            "an ops persona",
            ModelPolicy::new(&["openai"], DataClass::Confidential),
        )
        .with_skill(SkillRef::behavioral("ops-sop"))
        .with_capability(Capability::new("kb.search", DataClass::Internal))],
        skills: vec![SkillRef::behavioral("ops-sop")],
        connectors: vec![ConnectorRef::new(
            "connector.monitoring",
            DataClass::Internal,
        )],
        knowledge: vec![{
            let mut k = KnowledgeScope::new("kb:ops", DataClass::Internal);
            k.retrieval_quality = Some(0.9);
            k
        }],
        governance: Governance {
            owner: "alice".into(),
            codeowners_group: "ops-leads".into(),
            rbac_visibility: Visibility::Private,
            obo_authority: true,
            model_risk_class: ModelRiskClass::Low,
            residency: Residency::InHouse,
            retention_days: 365,
        },
        kpis: vec![Kpi::new("mttr", 0.85)],
        autonomy: AutonomyModel::new(AutonomyLevel::Assisted, 0.7)
            .with_task(TaskAutonomy::new("unknown", AutonomyLevel::Escalate)),
        payment_boundary: PaymentBoundary::None,
    }
}

async fn drive(handler: &dyn TurnHandler, principal: &Principal, req: &Request) -> Vec<Event> {
    let (tx, mut rx) = mpsc::channel::<Event>(64);
    let cancel = CancelToken::new();
    let _ = handler.handle_turn(principal, req, tx, &cancel).await;
    let mut events = Vec::new();
    while let Some(ev) = rx.recv().await {
        events.push(ev);
    }
    events
}

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

fn streamed_text(events: &[Event]) -> String {
    events
        .iter()
        .filter_map(|e| match e {
            Event::TextDelta(t) => Some(t.as_str()),
            _ => None,
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn r15_served_workforce_turn_ingests_authored_role_spec() {
    let surface = WorkforceTurnSurface::new(std::sync::Arc::new(assemble_workforce_surface()));
    let principal = Principal::user("alice", &[]);

    // A turn whose input IS an authored RoleSpec (JSON) — the served path must gate THAT role, not
    // the fixed canonical "l1-support" probe.
    let spec = authored_role_spec("cn-ops-authored");
    let body = serde_json::to_string(&spec).unwrap();
    let req = Request::chat("s1", "t1", &body, DataClass::Internal);
    let events = drive(&surface, &principal, &req).await;
    let text = streamed_text(&events);
    assert!(
        text.contains("authored role 'cn-ops-authored'"),
        "served turn must gate the AUTHORED spec, got: {text}"
    );
    assert!(
        !text.contains("canonical role"),
        "must not silently fall back when a valid spec is given"
    );

    // An INVALID authored spec (no KPIs -> fails validation) is refused, fail-closed — proving the
    // ingestion is real (not just echoed), the same non-skippable invariants apply to it.
    let mut invalid = authored_role_spec("cn-ops-invalid");
    invalid.kpis.clear();
    let bad_body = serde_json::to_string(&invalid).unwrap();
    let bad_req = Request::chat("s1", "t2", &bad_body, DataClass::Internal);
    let bad_events = drive(&surface, &principal, &bad_req).await;
    assert!(
        bad_events.iter().any(|e| matches!(e, Event::Error(_))),
        "an invalid authored spec must be refused fail-closed, got {bad_events:?}"
    );

    // A plain-text turn (not JSON) falls back to the canonical golden-path role — byte-identical
    // behavior for every existing (pre-R15) caller.
    let plain_req = Request::chat("s1", "t3", "hello, build me a worker", DataClass::Internal);
    let plain_events = drive(&surface, &principal, &plain_req).await;
    let plain_text = streamed_text(&plain_events);
    assert!(
        plain_text.contains("canonical role 'l1-support'"),
        "a non-JSON turn must still fall back to the canonical role, got: {plain_text}"
    );
}

/// R15 — the governed-publish first two steps (validate + full Breaker gate) are reachable for an
/// authored spec directly off the daemon-assembled surface too, mirroring the served-turn path.
#[test]
fn r15_workforce_surface_gates_authored_spec_directly() {
    let surface = assemble_workforce_surface();
    let pass = surface
        .gate_role_spec(authored_role_spec("direct-gate"))
        .expect("a valid authored spec clears validate + the full Breaker gate");
    assert_eq!(pass.role_id(), "direct-gate");

    // Publishing through the SAME pass over the governed publish path still works end-to-end.
    let gov = GovernedPublishRequest::release_signed(
        "direct-gate",
        "ops-leads",
        "release-key",
        AuthoringContext {
            payments_council_approved: true,
            commit_signed: true,
            author_can_approve: true,
            author_ad_level: 3,
        },
    );
    let published = surface
        .publish_role(
            authored_role_spec("direct-gate"),
            &[],
            &passing_shadow_cases(),
            &gov,
        )
        .expect("governed publish over the authored spec");
    assert_eq!(
        published.state(),
        ainxt_governance::GovernanceState::Production
    );
}

/// R15 (§6/§7 "controls run continuously in production") — the nightly-sweep entrypoint is now
/// reachable from the composition root (`ainxt-runtimed`), not only from `ainxt-workforce`'s own
/// tests. Drives one real pass through `run_workforce_nightly_tick` over the offline in-memory seams.
#[test]
fn r15_workforce_nightly_tick_reachable_from_composition_root() {
    let defs = vec![DefinitionTelemetry {
        definition_id: "svc-a".into(),
        owner: "alice".into(),
        kpi_trend_90d: -0.5,
        invocation_trend: -0.5,
        days_since_last_commit: 999,
        invocations_30d: 1,
    }];
    let codeowners: std::collections::BTreeSet<String> =
        ["alice".to_string()].into_iter().collect();
    let mut org = OrgTree::default();
    org.active.insert("alice".into(), true);

    let mut store = InMemoryDataPlane::default();
    let mut notifier = RecordingNotifier::default();
    let mut log = InMemoryEventLog::default();
    let approvals: Vec<ApprovalEvent> = Vec::new();

    let summary = run_workforce_nightly_tick(
        &mut store,
        &mut notifier,
        &mut log,
        &defs,
        &DecayThresholds::default(),
        &codeowners,
        &org,
        &approvals,
        20,
        30, // recert cadence -> the 999-day-stale def is nudged too
    );

    assert_eq!(
        summary.decay_flagged, 1,
        "the stale, declining definition is flagged"
    );
    assert_eq!(summary.recert_nudged, 1, "and nudged for re-certification");
    assert!(!store.decay_flags.is_empty());
    assert!(!store.recert_nudges.is_empty());
}

/// R15 (LOW: "AiNxt-OS kernel process model wired to a live scheduler/event-bus") — the kernel
/// process table is now reachable from THIS composition root: a governed publish through
/// `WorkforceSurface::publish_role` admits the role onto the surface's kernel automatically, and the
/// process is observable via `process_state`/`live_process_count`. The live async scheduler loop /
/// event bus that would drive `dispatch`/`block`/`wake`/`terminate` off real work remains
/// `needs_hot_wiring` — honestly documented, not faked.
#[test]
fn r15_kernel_process_model_reachable_from_composition_root() {
    let surface = assemble_workforce_surface();
    assert_eq!(surface.live_process_count(), 0);

    let gov = GovernedPublishRequest::release_signed(
        "kernel-reachable",
        "ops-leads",
        "release-key",
        AuthoringContext {
            payments_council_approved: true,
            commit_signed: true,
            author_can_approve: true,
            author_ad_level: 3,
        },
    );
    surface
        .publish_role(
            authored_role_spec("kernel-reachable"),
            &[],
            &passing_shadow_cases(),
            &gov,
        )
        .expect("governed publish");

    // The published role was admitted onto the kernel as a live, Ready process.
    assert_eq!(
        surface.live_process_count(),
        1,
        "publish_role must admit the role onto the kernel"
    );
}
