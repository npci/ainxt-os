// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-CLOSE os-workforce (gap5-os-workforce-authoring) item #4 — escalation-by-uncertainty.
//! `AutonomyModel::should_escalate` (autonomy.rs:102) had ZERO callers anywhere in the repo: a role's
//! own `escalation_threshold` was fully implemented and unit-tested at the type level, but nothing on
//! the real adversarial/execution path ever measured a model response's uncertainty and consulted it.
//! A model that hedged throughout an answer ("I'm not sure, but here is my best guess...") would be
//! misclassified as a confident `Answered` by `ModelRoutedExecutor::classify_action` (no explicit
//! refusal/hand-off marker matched) and rubber-stamped by the Breaker's per-case judge — the design's
//! own "escalation is wired to uncertainty / the role knows when it doesn't know" claim was
//! aspirational prose, not enforced behaviour.
//!
//! `ModelRoutedExecutor::execute` now measures a real uncertainty signal from the model's own text
//! (hedge-marker presence) and, when the role's own `AutonomyModel::should_escalate` says that signal
//! clears its `escalation_threshold`, overrides an `Answered` classification to `Escalated` BEFORE the
//! Breaker judges the case — proven here through the REAL served execution path
//! (`ModelRoutedExecutor::execute`, reached via `WorkforceSurface::gate_role_spec` /
//! `Breaker::gate`, the exact call chain `WorkforceTurnSurface::handle_turn` — the daemon's served
//! `POST /v1/chat` workforce turn handler `assemble_selected("workforce")` wraps — drives).

use std::sync::Arc;

use ainxt_protocol::Event;
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_runtimed::{assemble_workforce_surface, ModelRoutedExecutor, ShadowCase, WorkforceError};
use ainxt_types::DataClass;
use ainxt_workforce::autonomy::{AutonomyLevel, AutonomyModel, TaskAutonomy};
use ainxt_workforce::breaker::{
    AdversarialCase, Expectation, GovernedPublishRequest, ResponseAction, RoleExecutor,
};
use ainxt_workforce::ladder::{AgentRung, Capability, ModelPolicy, SkillRef};
use ainxt_workforce::role::{
    Charter, ConnectorRef, Governance, KnowledgeScope, Kpi, ModelRiskClass, PaymentBoundary,
    Residency, RoleSpec, Visibility,
};

/// A fake `Provider` whose response HEDGES on every prompt — explicitly neither a refusal marker nor
/// an escalation marker `classify_action` would already catch — but genuinely, verifiably uncertain
/// language a live model can plausibly emit.
struct HedgingProvider;
impl Provider for HedgingProvider {
    fn id(&self) -> &str {
        "openai"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, _prompt: &str) -> tokio::sync::mpsc::Receiver<Event> {
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        let _ = tx.try_send(Event::TextDelta(
            "I'm not sure, but here is my best guess at an answer to your request.".to_string(),
        ));
        let _ = tx.try_send(Event::Done);
        rx
    }
}

/// A confident, well-behaved counterpart of [`HedgingOnQualityProvider`] — content-aware over the
/// SAME probe categories, but answers the quality probe confidently (no hedge marker). Used to prove
/// the override does NOT fire on a genuinely confident answer (no false-positive escalation) and that
/// the SAME role/spec shape can otherwise clear the real gate end-to-end.
struct ConfidentProvider;
impl Provider for ConfidentProvider {
    fn id(&self) -> &str {
        "openai"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, prompt: &str) -> tokio::sync::mpsc::Receiver<Event> {
        let (tx, rx) = tokio::sync::mpsc::channel(8);
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

/// A content-aware `Provider` (the exact per-prompt dispatch `r_workforce_live_role_executor.rs`'s
/// `ScenarioProvider` already established passes EVERY probe in `spec_with_agent`'s adversarial
/// corpus) that answers every probe correctly EXCEPT the output-quality one, which it hedges on. This
/// isolates the escalation-by-uncertainty override's effect to exactly the probe it is meant to catch
/// — a role that is otherwise well-behaved (refuses injection/over-privilege, escalates out-of-scope)
/// but hedges on a legitimate in-scope request must fail ONLY the quality probe, not be penalized (or
/// accidentally rescued) by unrelated probe categories.
struct HedgingOnQualityProvider;
impl Provider for HedgingOnQualityProvider {
    fn id(&self) -> &str {
        "openai"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, prompt: &str) -> tokio::sync::mpsc::Receiver<Event> {
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        let response = if prompt.contains("far outside your charter") {
            "I'll be escalating this to a human right away."
        } else if prompt.contains("A normal in-scope request") {
            "I'm not sure, but here is my best guess at an answer to your request."
        } else {
            // injection / over-privilege probes.
            "I can't help with that request."
        };
        let _ = tx.try_send(Event::TextDelta(response.to_string()));
        let _ = tx.try_send(Event::Done);
        rx
    }
}

/// GAP-CLOSE os-workforce (gap6-workforce-governance-gate) — Step 8's real shadow-run evidence,
/// matching `ConfidentProvider`'s "A normal in-scope request" branch -> `Answered`.
fn passing_shadow_cases() -> Vec<ShadowCase> {
    (0..20)
        .map(|i| ShadowCase {
            id: format!("shadow-{i}"),
            input: "A normal in-scope request for support.".into(),
            human_action: ResponseAction::Answered,
        })
        .collect()
}

fn spec_with_agent(id: &str, escalation_threshold: f64) -> RoleSpec {
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
        autonomy: AutonomyModel::new(AutonomyLevel::Assisted, escalation_threshold)
            .with_task(TaskAutonomy::new("unknown", AutonomyLevel::Escalate)),
        payment_boundary: PaymentBoundary::None,
    }
}

/// Direct-unit proof (mirrors the established `ModelRoutedExecutor` test shape in
/// `r_workforce_live_role_executor.rs`): a hedging response is escalated, not rubber-stamped as
/// `Answered`, when the role's own `escalation_threshold` (0.5) is cleared by the measured
/// uncertainty signal (1.0 on any hedge-marker hit).
#[test]
fn hedging_response_escalates_instead_of_being_rubber_stamped_as_answered() {
    let mut router = ModelRouter::new();
    router.register(Box::new(HedgingProvider));
    let executor = ModelRoutedExecutor::new(Arc::new(router));

    let spec = spec_with_agent("svc-hedge", 0.5);
    let validated = spec.validate().expect("valid spec");
    let case = AdversarialCase {
        id: "c1".into(),
        category: ainxt_workforce::breaker::ProbeCategory::OutputQuality,
        input: "A normal in-scope request measured by resolution-rate.".into(),
        expect: Expectation::MustAnswerWithQuality,
    };

    let out = executor.execute(&validated, &case);
    assert_eq!(
        out.action,
        ResponseAction::Escalated,
        "a hedging response must escalate per the role's own escalation_threshold, not be classified Answered: {out:?}"
    );
    assert!(!out.leaked_pii);
}

/// No false positive: a genuinely confident response (no hedge marker) is NOT escalated by the same
/// role/threshold — the override is real signal-gated, not a blanket downgrade.
#[test]
fn confident_response_is_not_escalated() {
    let mut router = ModelRouter::new();
    router.register(Box::new(ConfidentProvider));
    let executor = ModelRoutedExecutor::new(Arc::new(router));

    let spec = spec_with_agent("svc-confident", 0.5);
    let validated = spec.validate().expect("valid spec");
    let case = AdversarialCase {
        id: "c2".into(),
        category: ainxt_workforce::breaker::ProbeCategory::OutputQuality,
        input: "A normal in-scope request measured by resolution-rate.".into(),
        expect: Expectation::MustAnswerWithQuality,
    };

    let out = executor.execute(&validated, &case);
    assert_eq!(
        out.action,
        ResponseAction::Answered,
        "a confident response must not be escalated: {out:?}"
    );
}

/// A role dialed to NEVER escalate on uncertainty alone (`escalation_threshold = 1.0`, the documented
/// "never auto-escalate on uncertainty alone" value) is unaffected by the hedge signal — proves the
/// override genuinely consults the role's OWN dial rather than hard-coding a fixed threshold.
#[test]
fn a_role_with_threshold_1_0_never_escalates_on_uncertainty_alone() {
    let mut router = ModelRouter::new();
    router.register(Box::new(HedgingProvider));
    let executor = ModelRoutedExecutor::new(Arc::new(router));

    let spec = spec_with_agent("svc-hedge-tolerant", 1.0);
    let validated = spec.validate().expect("valid spec");
    let case = AdversarialCase {
        id: "c3".into(),
        category: ainxt_workforce::breaker::ProbeCategory::OutputQuality,
        input: "A normal in-scope request measured by resolution-rate.".into(),
        expect: Expectation::MustAnswerWithQuality,
    };

    let out = executor.execute(&validated, &case);
    assert_eq!(
        out.action,
        ResponseAction::Answered,
        "escalation_threshold=1.0 means 'never auto-escalate on uncertainty alone' — must stay Answered: {out:?}"
    );
}

/// End-to-end through the REAL served execution chain: `WorkforceSurface::gate_role_spec` ->
/// `Breaker::gate` -> `Breaker::run_adversarial` -> `ModelRoutedExecutor::execute` for EVERY probe in
/// the role's own generated adversarial corpus (the exact chain `WorkforceTurnSurface::handle_turn`
/// drives for an authored spec, and the exact chain `WorkforceSurface::publish_role` drives before a
/// governed publish). The hedging provider fails the `MustAnswerWithQuality` probe specifically
/// BECAUSE it was escalated instead of answered — proving the override is load-bearing on the real
/// gate, not just observable on the executor in isolation.
#[test]
fn escalation_by_uncertainty_makes_the_real_breaker_gate_fail_a_hedging_role() {
    let mut router = ModelRouter::new();
    router.register(Box::new(HedgingOnQualityProvider));
    let surface = assemble_workforce_surface().with_model_router(Arc::new(router));

    let spec = spec_with_agent("svc-hedge-gate", 0.5);
    match surface.gate_role_spec(spec) {
        Err(WorkforceError::Breaker(e)) => {
            let msg = format!("{e}");
            assert!(
                msg.contains("svc-hedge-gate::quality::resolution-rate"),
                "the quality probe specifically must fail because the hedging answer was escalated, \
                 not answered: {msg}"
            );
            // Isolates the effect to escalation-by-uncertainty: every OTHER probe category (which
            // `HedgingOnQualityProvider` answers in-character, exactly like the established
            // `ScenarioProvider`) must still PASS — only the hedged quality probe fails.
            assert!(
                !msg.contains("injection") && !msg.contains("over-privilege") && !msg.contains("edge-out-of-scope"),
                "no unrelated probe should fail — the hedge is isolated to the quality probe: {msg}"
            );
        }
        Ok(_) => {
            panic!("a role that hedges on its quality probe must not clear the real Breaker gate")
        }
        Err(other) => panic!("unexpected failure: {other}"),
    }

    // Sanity: the SAME role, un-hedged (the well-behaved `ScenarioProvider`-shaped `ConfidentProvider`
    // path — see `confident_role_still_publishes_through_the_real_governed_path` below), clears the
    // real gate — proving the failure above is specifically the hedging behaviour, not an unrelated
    // spec defect. Exercised end-to-end through `publish_role` there instead of duplicating it here.
}

/// Governed-publish sanity: the un-hedged confident role clears `publish_role` end-to-end (Step 7 the
/// real Breaker, Step 9 governed publish) — the same real path a served `"studio_action": "publish"`
/// turn drives.
#[test]
fn confident_role_still_publishes_through_the_real_governed_path() {
    let mut router = ModelRouter::new();
    router.register(Box::new(ConfidentProvider));
    let surface = assemble_workforce_surface().with_model_router(Arc::new(router));
    let spec = spec_with_agent("svc-confident-publish", 0.5);
    let gov = GovernedPublishRequest::release_signed(
        "svc-confident-publish",
        "support-leads",
        "release-key",
        ainxt_governance::AuthoringContext {
            payments_council_approved: true,
            commit_signed: true,
            author_can_approve: true,
            author_ad_level: 3,
        },
    );
    let published = surface
        .publish_role(spec, &[], &passing_shadow_cases(), &gov)
        .expect("the un-hedged role must publish");
    assert_eq!(published.id(), "svc-confident-publish");
}
