// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-CLOSE os-workforce (gap5-os-workforce-authoring) items #1/#2/#3 — the Role Studio's
//! conversational authoring flow (`WorkforceSurface::draft_role_from_job`, itself driving the real
//! `RoleStudio` state machine), the governed-publish step (`WorkforceSurface::publish_role`), and the
//! Digital Team ladder rung (`WorkforceSurface::assemble_team`) each had NO route from the served turn
//! path: `WorkforceTurnSurface::handle_turn`'s JSON-body dispatch special-cased exactly one shape (an
//! already-fully-formed authored `RoleSpec`), so a creator's plain-language job description, a
//! governed publish, and a team assembly had zero callers from anything a real `POST /v1/chat` turn
//! could send.
//!
//! `handle_turn` now recognizes a `"studio_action"` tag and routes it through the REAL `RoleStudio`-
//! backed `WorkforceSurface` methods (`workforce_surface.rs`'s `StudioTurn`/`handle_studio_turn`). This
//! proves all three end-to-end through the actual served composition root:
//!   * the DRAFT step needs no live model (offline `Factory`/`KeywordIntentExtractor`), so it is driven
//!     through the FULLEST real path: `assemble_selected("workforce")` (the exact daemon `--surface`
//!     dispatch `main` calls) -> `Client::in_process` -> `client.chat(...)`.
//!   * the PUBLISH + TEAM steps need an ACTUAL PASSING adversarial run to reach (the Breaker is
//!     un-forgeable by construction), which needs a live model call; a CI test has no live API keys.
//!     This drives the SAME `TurnHandler::handle_turn` `assemble_selected("workforce")` ultimately
//!     wraps, constructed with a live-router-backed surface exactly as `assemble_workforce_surface_served`
//!     builds it from config — mirroring `r_workforce_live_role_executor.rs`'s own established
//!     GAP-CLOSE precedent for proving this same executor's reachability without live network access.
//!   * a served turn that ISN'T Studio-shaped (a plain authored `RoleSpec`, or plain prose) is proven
//!     byte-identical, unchanged.

use std::sync::Arc;

use ainxt_client::{Client, ClientConfig};
use ainxt_protocol::{Event, Request};
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_runtime::{CancelToken, TurnHandler};
use ainxt_runtimed::{
    assemble_selected, assemble_workforce_surface, load_layered, LoadedConfig, WorkforceTurnSurface,
};
use ainxt_types::{DataClass, Principal};
use ainxt_workforce::autonomy::{AutonomyLevel, AutonomyModel, TaskAutonomy};
use ainxt_workforce::ladder::{AgentRung, Capability, ModelPolicy, SkillRef};
use ainxt_workforce::role::{
    Charter, ConnectorRef, Governance, KnowledgeScope, Kpi, ModelRiskClass, PaymentBoundary,
    Residency, RoleSpec, Visibility,
};
use tokio::sync::mpsc;

fn offline() -> LoadedConfig {
    load_layered(&[("x", "version = 1")]).unwrap()
}

/// A fake `Provider` that answers in character for the Studio's own generated adversarial corpus —
/// the same pattern `r_workforce_live_role_executor.rs`'s `ScenarioProvider` already established as a
/// legitimate live-executor double.
struct ScenarioProvider;
impl Provider for ScenarioProvider {
    fn id(&self) -> &str {
        "openai"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, prompt: &str) -> mpsc::Receiver<Event> {
        let (tx, rx) = mpsc::channel(8);
        let response = if prompt.contains("far outside your charter") {
            "I'll be escalating this to a human right away."
        } else if prompt.contains("A normal in-scope request") {
            "Here is the grounded answer to your in-scope request [source]."
        } else {
            "I can't help with that request."
        };
        let _ = tx.try_send(Event::TextDelta(response.to_string()));
        let _ = tx.try_send(Event::Done);
        rx
    }
}

fn spec_with_agent(id: &str) -> RoleSpec {
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
            ModelPolicy::new(&["openai"], DataClass::Internal),
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

fn streamed_text(events: &[Event]) -> String {
    events
        .iter()
        .filter_map(|e| match e {
            Event::TextDelta(t) => Some(t.as_str()),
            _ => None,
        })
        .collect()
}

/// `handle_studio_turn`'s result is streamed as `"workforce {turn}: {json}\n"` — strip that envelope
/// and parse the JSON payload.
fn studio_payload(text: &str) -> serde_json::Value {
    let json_start = text
        .find('{')
        .unwrap_or_else(|| panic!("no JSON payload in: {text}"));
    serde_json::from_str(text[json_start..].trim())
        .unwrap_or_else(|e| panic!("invalid JSON studio result ({e}) in: {text}"))
}

/// GAP-CLOSE os-workforce #1 — `WorkforceSurface::open_studio`/`draft_role_from_job` (AINXT_OS §4
/// Steps 0-2) reachable from the REAL served turn path for the first time, via the fullest real
/// composition root: `assemble_selected("workforce")` (the exact function the daemon's `--surface`
/// dispatch calls) -> a real client -> a real chat turn.
#[tokio::test(flavor = "multi_thread")]
async fn studio_draft_role_from_job_reachable_from_the_real_served_dispatch() {
    let assembled =
        assemble_selected(&offline(), "workforce").expect("--surface workforce must assemble");
    let client = Client::in_process(
        assembled.manager,
        Principal::user("u", &["chat.send"]).with_department("support"),
        ClientConfig::default(),
    );
    let body = serde_json::json!({
        "studio_action": "draft_role_from_job",
        "id": "l1-support-drafted",
        "title": "L1 Support Engineer",
        "text": "Triage L1 tickets from the ticketing queue, answer from the KB, and escalate \
                  anything unrecognized to a human.",
        "template": "support",
        "owner": "alice",
        "codeowners_group": "support-leads",
    })
    .to_string();
    let out = client.chat("s1", "t1", &body).unwrap().collect().await;
    assert!(
        out.completed,
        "the served studio draft turn must complete: {:?}",
        out.error
    );

    let payload = studio_payload(&out.text);
    assert_eq!(payload["studio_result"], "drafted");
    assert_eq!(payload["role_id"], "l1-support-drafted");

    // Step 1 (Factory::describe / KeywordIntentExtractor) actually parsed the free-form prose — not a
    // stub — and Step 2 (Factory::auto_assemble) + Step 6 (auto_generate_kpis) proposed a real draft.
    let spec = &payload["spec"];
    assert!(
        spec["charter"]["escalation_rules"]
            .as_array()
            .expect("escalation_rules array")
            .iter()
            .any(|r| r
                .as_str()
                .unwrap_or_default()
                .to_lowercase()
                .contains("escalate")),
        "the escalation clause must be detected: {spec}"
    );
    assert!(
        !spec["kpis"].as_array().expect("kpis array").is_empty(),
        "Step-6 KPIs must be pre-seeded on the draft: {spec}"
    );
    assert_eq!(spec["agents"].as_array().expect("agents array").len(), 1);
}

/// The Studio dispatch fails CLOSED on a malformed turn (unknown Step-0 template) rather than
/// silently falling through to the canonical gate — proves `handle_studio_turn`'s own error path is
/// real, reached through the same served entrypoint.
#[tokio::test(flavor = "multi_thread")]
async fn studio_draft_rejects_an_unknown_template_fail_closed() {
    let assembled =
        assemble_selected(&offline(), "workforce").expect("--surface workforce must assemble");
    let client = Client::in_process(
        assembled.manager,
        Principal::user("u", &["chat.send"]).with_department("support"),
        ClientConfig::default(),
    );
    let body = serde_json::json!({
        "studio_action": "draft_role_from_job",
        "id": "x",
        "title": "X",
        "text": "does something",
        "template": "not-a-real-template",
        "owner": "alice",
        "codeowners_group": "leads",
    })
    .to_string();
    let out = client.chat("s1", "t1", &body).unwrap().collect().await;
    let err = out.error.as_deref().unwrap_or_default();
    assert!(
        err.contains("workforce studio turn refused") && err.contains("unknown Step-0 template"),
        "expected a fail-closed unknown-template refusal, got: {err}"
    );
}

/// A body that is NOT Studio-shaped (a plain authored `RoleSpec`) is unaffected by the new dispatch —
/// it still falls through to the pre-existing gate path, byte-identical.
#[tokio::test(flavor = "multi_thread")]
async fn non_studio_authored_role_spec_turn_is_unaffected() {
    let assembled =
        assemble_selected(&offline(), "workforce").expect("--surface workforce must assemble");
    let client = Client::in_process(
        assembled.manager,
        Principal::user("u", &["chat.send"]).with_department("support"),
        ClientConfig::default(),
    );
    let spec = spec_with_agent("cn-plain-authored");
    let body = serde_json::to_string(&spec).unwrap();
    let out = client.chat("s1", "t1", &body).unwrap().collect().await;
    // No live model on the offline default -> the Breaker's adversarial run fails closed exactly as
    // `r14_surface_selectors.rs` documents; the key proof here is that it took the "authored" branch
    // (not the Studio dispatch, and not silently misrouted).
    let err = out.error.as_deref().unwrap_or_default();
    assert!(
        err.contains("workforce gate refused (fail-closed)"),
        "a plain authored RoleSpec turn must still take the pre-existing gate path: {err}"
    );
}

/// GAP-CLOSE os-workforce #2/#3 — `WorkforceSurface::publish_role` (Step 7 Breaker -> Step 9 governed
/// publish -> kernel admission + Marketplace TOFU pin) and `WorkforceSurface::assemble_team` (the
/// Digital Team ladder rung), both reached through the REAL `TurnHandler::handle_turn` the daemon
/// serves `POST /v1/chat` through — constructed with a live-router-backed surface (the composition
/// `assemble_workforce_surface_served` itself builds from config) since reaching an ACTUAL Breaker
/// PASS needs a real adversarial run, and a CI test has no live API keys.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn studio_publish_and_assemble_team_reachable_from_the_real_turn_handler() {
    let mut router = ModelRouter::new();
    router.register(Box::new(ScenarioProvider));
    let surface = WorkforceTurnSurface::new(Arc::new(
        assemble_workforce_surface().with_model_router(Arc::new(router)),
    ));
    let principal = Principal::user("alice", &[]);

    // 1) "studio_action": "publish" — GAP-CLOSE os-workforce (gap6-workforce-governance-gate) Steps
    // 3-9: `approved_capabilities` (empty — `spec_with_agent`'s only capability, `kb.search`, does not
    // require approval) and `shadow_cases` (20 cases whose input matches `ScenarioProvider`'s own "A
    // normal in-scope request" branch -> `Answered`, so a 100%-agreement real observation clears
    // Step 8) alongside the pre-existing Step 7 Breaker + Step 9 governed publish.
    let spec = spec_with_agent("svc-studio-publish");
    let shadow_cases: Vec<serde_json::Value> = (0..20)
        .map(|i| {
            serde_json::json!({
                "id": format!("shadow-{i}"),
                "input": "A normal in-scope request for support.",
                "human_action": "answered",
            })
        })
        .collect();
    let publish_body = serde_json::json!({
        "studio_action": "publish",
        "spec": spec,
        "codeowners_group": "support-leads",
        "release_key": "release-key",
        "authoring": {
            "payments_council_approved": true,
            "commit_signed": true,
            "author_can_approve": true,
            "author_ad_level": 3,
        },
        "approved_capabilities": [],
        "shadow_cases": shadow_cases,
    })
    .to_string();
    let req1 = Request::chat("s1", "t1", &publish_body, DataClass::Internal);
    let events1 = drive(&surface, &principal, &req1).await;
    let payload1 = studio_payload(&streamed_text(&events1));
    assert_eq!(payload1["studio_result"], "published");
    assert_eq!(payload1["role_id"], "svc-studio-publish");
    assert_eq!(payload1["state"], "Production");

    // 2) "studio_action": "assemble_team" referencing the role THIS surface just published — proves
    // the team rung resolves from the surface's own published-role registry, not an arbitrary input.
    let team_body = serde_json::json!({
        "studio_action": "assemble_team",
        "id": "support-team",
        "department": "support",
        "owner": "alice",
        "role_ids": ["svc-studio-publish"],
        "collaborations": [],
    })
    .to_string();
    let req2 = Request::chat("s1", "t2", &team_body, DataClass::Internal);
    let events2 = drive(&surface, &principal, &req2).await;
    let payload2 = studio_payload(&streamed_text(&events2));
    assert_eq!(payload2["studio_result"], "team_assembled");
    assert_eq!(payload2["team_id"], "support-team");
    assert_eq!(payload2["department"], "support");
    assert_eq!(payload2["role_count"], 1);

    // 3) a team referencing a role NEVER published on this surface is refused, not fabricated.
    let bad_team_body = serde_json::json!({
        "studio_action": "assemble_team",
        "id": "bad-team",
        "department": "support",
        "owner": "alice",
        "role_ids": ["never-published"],
        "collaborations": [],
    })
    .to_string();
    let req3 = Request::chat("s1", "t3", &bad_team_body, DataClass::Internal);
    let events3 = drive(&surface, &principal, &req3).await;
    assert!(
        events3.iter().any(|e| matches!(e, Event::Error(_))),
        "a team over an unpublished role id must be refused fail-closed, got {events3:?}"
    );
}
