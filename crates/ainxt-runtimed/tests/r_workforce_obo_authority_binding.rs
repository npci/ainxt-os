// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-CLOSE os-workforce #3 — `ainxt_workforce::role::Governance::obo_authority` was a purely
//! static, self-declared spec field: `RoleSpec::validate` requires it be `true` for a regulated-data
//! role, but nothing ever checked it against a REAL credential/policy at execution time — a role
//! could claim the authority and nothing downstream would ever refuse it even if that authority
//! didn't actually exist. `ModelRoutedExecutor::with_obo_gate` wires it to the SAME
//! `ainxt_tools::obo::OboPolicy` / `OboDecisionSink` seam the general chat-engine agent loop installs
//! (`ainxt_runtime::EngineBuilder::with_obo` / `ToolRuntime::dispatch_obo_audited`).
//!
//! This proves:
//!  1. a DENIED OBO decision fails the role's case CLOSED to an escalation, the model is never
//!     called, and the denial is recorded to the audit sink (granted-or-denied, before acting — same
//!     invariant `dispatch_obo_audited` enforces for tool calls);
//!  2. a GRANTED decision lets the model actually run, and is itself recorded to the sink (auditing
//!     the grant, not just the denial);
//!  3. a role that does NOT claim `obo_authority` skips the check entirely, even with a gate that
//!     would deny everything — the field still gates WHEN the check applies, exactly as designed.

use std::sync::{Arc, Mutex};

use ainxt_protocol::Event;
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_runtimed::ModelRoutedExecutor;
use ainxt_tools::obo::{OboContext, OboDecision, OboDenial, OboPolicy};
use ainxt_types::DataClass;
use ainxt_workforce::autonomy::{AutonomyLevel, AutonomyModel, TaskAutonomy};
use ainxt_workforce::breaker::{
    AdversarialCase, Expectation, ProbeCategory, ResponseAction, RoleExecutor,
};
use ainxt_workforce::ladder::{AgentRung, Capability, ModelPolicy, SkillRef};
use ainxt_workforce::role::{
    Charter, ConnectorRef, Governance, KnowledgeScope, Kpi, ModelRiskClass, PaymentBoundary,
    Residency, RoleSpec, Visibility,
};

struct EchoProvider;
impl Provider for EchoProvider {
    fn id(&self) -> &str {
        "openai"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, _prompt: &str) -> tokio::sync::mpsc::Receiver<Event> {
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        let _ = tx.try_send(Event::TextDelta(
            "Here is the grounded answer [source].".into(),
        ));
        let _ = tx.try_send(Event::Done);
        rx
    }
}

/// A policy that always denies, or always grants, so the test controls the verdict deterministically
/// rather than depending on a real credential store.
struct FixedPolicy {
    grant: bool,
}
impl OboPolicy for FixedPolicy {
    fn authorize(
        &self,
        _ctx: &OboContext,
        capability: &str,
        _resource: Option<&str>,
        _action: &str,
    ) -> Result<(), OboDenial> {
        if self.grant {
            Ok(())
        } else {
            Err(OboDenial::NoGrant {
                capability: capability.to_string(),
                resource: None,
                action: "invoke".into(),
            })
        }
    }
}

#[derive(Default)]
struct RecordingSink {
    decisions: Mutex<Vec<OboDecision>>,
}
impl ainxt_tools::obo::OboDecisionSink for RecordingSink {
    fn record(&self, decision: &OboDecision) {
        self.decisions.lock().unwrap().push(decision.clone());
    }
}

fn spec_with_obo(id: &str, obo_authority: bool) -> RoleSpec {
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
            obo_authority,
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

fn a_case() -> AdversarialCase {
    AdversarialCase {
        id: "c1".into(),
        category: ProbeCategory::EdgeCase,
        input: "a normal in-scope request".into(),
        expect: Expectation::MustAnswerWithQuality,
    }
}

#[test]
fn obo_denial_fails_closed_and_is_audited_before_any_model_call() {
    let mut router = ModelRouter::new();
    router.register(Box::new(EchoProvider));
    let sink = Arc::new(RecordingSink::default());
    let executor = ModelRoutedExecutor::new(Arc::new(router))
        .with_obo_gate(Box::new(FixedPolicy { grant: false }), sink.clone());

    let spec = spec_with_obo("svc-obo-denied", true);
    let validated = spec.validate().expect("valid spec");
    let out = executor.execute(&validated, &a_case());

    assert_eq!(
        out.action,
        ResponseAction::Escalated,
        "a denied OBO check must fail closed to escalation"
    );
    assert!(
        !out.text.contains("grounded answer"),
        "the model must never be called after a denial"
    );

    let decisions = sink.decisions.lock().unwrap();
    assert_eq!(
        decisions.len(),
        1,
        "the decision must be recorded even though it was denied"
    );
    assert!(!decisions[0].granted());
    assert_eq!(decisions[0].user_id, "alice");
}

#[test]
fn obo_grant_lets_the_model_run_and_is_itself_audited() {
    let mut router = ModelRouter::new();
    router.register(Box::new(EchoProvider));
    let sink = Arc::new(RecordingSink::default());
    let executor = ModelRoutedExecutor::new(Arc::new(router))
        .with_obo_gate(Box::new(FixedPolicy { grant: true }), sink.clone());

    let spec = spec_with_obo("svc-obo-granted", true);
    let validated = spec.validate().expect("valid spec");
    let out = executor.execute(&validated, &a_case());

    assert_eq!(out.action, ResponseAction::Answered);
    assert!(
        out.text.contains("grounded answer"),
        "a granted OBO check must let the model actually run"
    );

    let decisions = sink.decisions.lock().unwrap();
    assert_eq!(
        decisions.len(),
        1,
        "the GRANTED decision must also be recorded, not just denials"
    );
    assert!(decisions[0].granted());
}

#[test]
fn a_role_without_obo_authority_skips_the_check_entirely() {
    let mut router = ModelRouter::new();
    router.register(Box::new(EchoProvider));
    let sink = Arc::new(RecordingSink::default());
    // A policy that denies EVERYTHING — proving the field still gates WHEN the check runs: a role
    // that never claimed the authority is not subject to it at all.
    let executor = ModelRoutedExecutor::new(Arc::new(router))
        .with_obo_gate(Box::new(FixedPolicy { grant: false }), sink.clone());

    let spec = spec_with_obo("svc-no-obo-claim", false);
    let validated = spec.validate().expect("valid spec");
    let out = executor.execute(&validated, &a_case());

    assert_eq!(
        out.action,
        ResponseAction::Answered,
        "no OBO claim ⇒ the deny-everything policy must never run"
    );
    assert!(
        sink.decisions.lock().unwrap().is_empty(),
        "no decision should be recorded when obo_authority is false"
    );
}
