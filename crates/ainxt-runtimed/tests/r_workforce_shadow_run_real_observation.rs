// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-CLOSE os-workforce #4 — shadow-run REAL observation (AINXT_OS §4 Step 8), unblocked now that
//! #1 (`ModelRoutedExecutor`) is closed. `RoleStudio::shadow_run` has always been a real, tested gate
//! over `ShadowResult` — but `ShadowResult` itself was 100% caller-fabricated: every caller (every
//! existing test, e.g. `ShadowResult::new(100, 96)` in `r12_workforce.rs`) hand-invented the observed/
//! agreed numbers. `run_shadow_observation` closes this: it actually runs the role through the SAME
//! live model-routed executor as the Breaker, against real (input, human-decision) pairs, and counts
//! genuine agreement.
//!
//! This proves:
//!  1. the computed `ShadowResult` reflects REAL comparisons (mixed agree/disagree), not an invented
//!     number — a driver that always reported 100% agreement regardless of input would be exactly the
//!     fabrication this gap-close must avoid;
//!  2. genuinely-earned high agreement clears `RoleStudio::shadow_run`'s trust bar end-to-end, driving
//!     the studio to `StudioStage::Shadow`;
//!  3. genuinely-earned LOW agreement (computed from the same real driver, not a fabricated low
//!     number) is correctly refused by the trust-before-publish gate.

use std::sync::Arc;

use ainxt_protocol::Event;
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_runtimed::{run_shadow_observation, ModelRoutedExecutor, ShadowCase};
use ainxt_types::DataClass;
use ainxt_workforce::autonomy::{AutonomyLevel, AutonomyModel, TaskAutonomy};
use ainxt_workforce::breaker::{CompliantExecutor, ResponseAction};
use ainxt_workforce::ladder::{AgentRung, Capability, ModelPolicy, SkillRef};
use ainxt_workforce::role::{
    Charter, ConnectorRef, Governance, KnowledgeScope, Kpi, ModelRiskClass, PaymentBoundary,
    Residency, RoleSpec, Visibility,
};
use ainxt_workforce::studio::{RoleStudio, StudioError, StudioStage, Template};

/// Answers "escalate:*" inputs by actually escalating, everything else with a plain in-scope answer —
/// a deterministic stand-in for "what the model really decided," driven by the prompt content
/// `ModelRoutedExecutor::prompt_for` embeds (`case.input`), exactly like `ScenarioProvider` elsewhere.
struct DecidingProvider;
impl Provider for DecidingProvider {
    fn id(&self) -> &str {
        "openai"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, prompt: &str) -> tokio::sync::mpsc::Receiver<Event> {
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        let text = if prompt.contains("escalate:") {
            "I'll be escalating this to a human right away."
        } else {
            "Here is the grounded answer [source]."
        };
        let _ = tx.try_send(Event::TextDelta(text.to_string()));
        let _ = tx.try_send(Event::Done);
        rx
    }
}

fn spec_for(id: &str) -> RoleSpec {
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
            .with_task(TaskAutonomy::new("password-reset", AutonomyLevel::Auto))
            .with_task(TaskAutonomy::new("unknown", AutonomyLevel::Escalate)),
        payment_boundary: PaymentBoundary::None,
    }
}

/// `n` real cases: the first `escalate_count` are ones the human escalated (and the model, seeing
/// "escalate:" in the input, also escalates — agreement); the rest are ones the human ANSWERED
/// (and the model answers too — agreement). `mismatches` of the trailing "answered" cases are
/// deliberately mislabeled with `Escalated` as the human's decision, so the driver counts a REAL
/// disagreement instead of reporting 100% agreement no matter what.
fn cases(n: usize, mismatches: usize) -> Vec<ShadowCase> {
    let mut answered_seen = 0usize;
    (0..n)
        .map(|i| {
            let escalate_input = i % 2 == 0;
            let input = if escalate_input {
                format!("escalate: case {i} far outside charter")
            } else {
                format!("a normal in-scope request {i}")
            };
            let human_action = if escalate_input {
                ResponseAction::Escalated
            } else {
                let mislabel = answered_seen < mismatches;
                answered_seen += 1;
                if mislabel {
                    ResponseAction::Escalated // deliberately wrong vs. what the model will actually do
                } else {
                    ResponseAction::Answered
                }
            };
            ShadowCase {
                id: format!("shadow-{i}"),
                input,
                human_action,
            }
        })
        .collect()
}

#[test]
fn shadow_observation_reflects_real_comparisons_not_a_fabricated_number() {
    let mut router = ModelRouter::new();
    router.register(Box::new(DecidingProvider));
    let executor = ModelRoutedExecutor::new(Arc::new(router));
    let spec = spec_for("svc-shadow-unit").validate().expect("valid spec");

    // 10 cases, 2 deliberately mislabeled -> 8/10 real agreement, never 100%.
    let result = run_shadow_observation(&executor, &spec, &cases(10, 2));
    assert_eq!(result.observed, 10);
    assert_eq!(
        result.agreed_with_human, 8,
        "must reflect the REAL count of matching decisions"
    );
    assert!((result.agreement() - 0.8).abs() < 1e-9);
}

fn studio_at_breaker_passed(id: &str) -> RoleStudio {
    let mut studio = RoleStudio::start(Template::Support);
    studio.describe_and_draft(spec_for(id)).unwrap();
    studio.govern().unwrap();
    studio.set_autonomy().unwrap();
    studio.check_knowledge(&[("kb:support", 0.9)], 0.6).unwrap();
    studio.define_kpis().unwrap();
    studio
        .run_breaker(&CompliantExecutor)
        .expect("breaker passes on the offline stand-in");
    assert_eq!(studio.stage(), StudioStage::BreakerPassed);
    studio
}

#[test]
fn genuinely_earned_high_agreement_clears_the_real_studio_gate() {
    let mut router = ModelRouter::new();
    router.register(Box::new(DecidingProvider));
    let executor = ModelRoutedExecutor::new(Arc::new(router));
    let spec = spec_for("svc-shadow-pass").validate().expect("valid spec");

    // 20 cases (meets MIN_SHADOW_OBSERVATIONS), 2 mismatches -> 18/20 = 90% >= MIN_SHADOW_AGREEMENT.
    let result = run_shadow_observation(&executor, &spec, &cases(20, 2));
    assert_eq!(result.observed, 20);
    assert!(
        result.agreement() >= 0.85,
        "fixture must genuinely clear the bar: {result:?}"
    );

    let mut studio = studio_at_breaker_passed("svc-shadow-pass");
    studio
        .shadow_run(result)
        .expect("genuinely-earned evidence must clear the trust gate");
    assert_eq!(studio.stage(), StudioStage::Shadow);
}

#[test]
fn genuinely_earned_low_agreement_is_refused_by_the_real_studio_gate() {
    let mut router = ModelRouter::new();
    router.register(Box::new(DecidingProvider));
    let executor = ModelRoutedExecutor::new(Arc::new(router));
    let spec = spec_for("svc-shadow-fail").validate().expect("valid spec");

    // 20 cases, 10 mismatches -> 10/20 = 50% < MIN_SHADOW_AGREEMENT — a REAL low-trust outcome.
    let result = run_shadow_observation(&executor, &spec, &cases(20, 10));
    assert_eq!(result.observed, 20);
    assert!(
        result.agreement() < 0.85,
        "fixture must genuinely miss the bar: {result:?}"
    );

    let mut studio = studio_at_breaker_passed("svc-shadow-fail");
    match studio.shadow_run(result) {
        Err(StudioError::InsufficientShadowEvidence { .. }) => {}
        other => panic!(
            "expected InsufficientShadowEvidence from genuinely low real agreement, got {other:?}"
        ),
    }
    assert_eq!(
        studio.stage(),
        StudioStage::BreakerPassed,
        "machine must not advance on real, but weak, evidence"
    );
}
