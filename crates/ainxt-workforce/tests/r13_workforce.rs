// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-13 HIGH-severity closure for the AiNxt-OS workforce ladder + Role Studio (ainxt-workforce).
//! Each `r13_*` test closes one round-12 HIGH gap, fail-before / pass-after, exercising the crate as
//! a downstream consumer:
//!
//!  * H1 — a regulated-data role can no longer be dialed fully-autonomous with no OBO / no oversight
//!    via a mis-declared `payment_boundary`; the invariant now keys off the DERIVED data class.
//!  * H4 — the "cannot-skip Breaker" gate is un-forgeable: `PublishedRole` is reachable ONLY via a
//!    sealed `BreakerPass` with no public constructor, produced ONLY by an actual Breaker run.
//!  * H5 — the publish gate requires an ACTUAL adversarial RUN of the role, not just the presence of
//!    the static spec battery.
//!  * H2 — governed publish walks the git-native ADR-026 lifecycle (PR → CI/pre-receive → CODEOWNERS
//!    signed merge → signed prod tag) via `ainxt-governance`, minting only at PRODUCTION.

use ainxt_governance::{
    AuthoringContext, CiGateError, CodeownersApproval, FrontMatterError, GovError,
    MarkerPrereceiveGate, Signature, SingleOwnerPolicy, TrustedKeyVerifier,
};
use ainxt_types::DataClass;
use ainxt_workforce::autonomy::{AutonomyLevel, AutonomyModel, TaskAutonomy};
use ainxt_workforce::breaker::{
    self, Breaker, BreakerVerdict, CompliantExecutor, GateError, GovernedPublishRequest,
    PublishError, ResponseAction, RoleExecutor, RoleOutput,
};
use ainxt_workforce::ladder::{AgentRung, Capability, ModelPolicy, SkillRef};
use ainxt_workforce::role::{
    Charter, ConnectorRef, Governance, KnowledgeScope, Kpi, ModelRiskClass, PaymentBoundary,
    Residency, RoleSpec, ValidatedRole, Visibility,
};

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

fn full_authoring() -> AuthoringContext {
    AuthoringContext {
        payments_council_approved: true,
        commit_signed: true,
        author_can_approve: true,
        author_ad_level: 3,
    }
}

fn gov_for(id: &str, group: &str) -> GovernedPublishRequest {
    GovernedPublishRequest::release_signed(id, group, "release-key", full_authoring())
}

// ================================================================== H1
// A regulated-data role cannot be dialed fully-autonomous with no OBO / no human oversight, EVEN IF
// its `payment_boundary` is mis-declared as `None`. The invariant keys off the DERIVED data class
// (max over connectors + knowledge + agent caps), not the author-supplied label.

#[test]
fn r13_regulated_role_cannot_be_dialed_fully_autonomous() {
    // A role that TOUCHES regulated-payment data (via a connector) but understates its boundary as
    // `None`, drops OBO, and dials the default to fully-autonomous. Before R13 this validated clean
    // (payment_boundary=None short-circuited the OBO/autonomy checks). Now it is REJECTED.
    let mut s = passing_spec("regulated-sneaky");
    s.connectors.push(ConnectorRef::new(
        "payments.ledger",
        DataClass::RegulatedPayment,
    ));
    s.payment_boundary = PaymentBoundary::None; // mis-declared
    s.governance.obo_authority = false;
    s.governance.residency = Residency::InHouse; // isolate: not the residency error
    s.autonomy = AutonomyModel::new(AutonomyLevel::Auto, 1.0); // fully autonomous, no escalation
    let errs = s
        .validate()
        .expect_err("regulated + no-OBO + Auto must be rejected");
    assert!(
        errs.iter().any(|e| e.contains("on-behalf-of")),
        "must require OBO derived from data class, got {errs:?}"
    );
    assert!(
        errs.iter().any(|e| e.contains("cannot default to Auto")),
        "must forbid Auto default for regulated data, got {errs:?}"
    );
    assert!(
        errs.iter().any(|e| e.contains("human-escalation path")),
        "must require an escalation path for regulated data, got {errs:?}"
    );

    // The same via PII in a knowledge scope (regulated-by-PII), still mis-declared None.
    let mut p = passing_spec("pii-sneaky");
    p.knowledge.push({
        let mut k = KnowledgeScope::new("kb:hr", DataClass::Pii);
        k.retrieval_quality = Some(0.9);
        k
    });
    p.payment_boundary = PaymentBoundary::None;
    p.governance.obo_authority = false;
    p.autonomy = AutonomyModel::new(AutonomyLevel::Auto, 1.0);
    let errs = p
        .validate()
        .expect_err("PII + no-OBO + Auto must be rejected");
    assert!(errs.iter().any(|e| e.contains("on-behalf-of")));
    assert!(errs.iter().any(|e| e.contains("cannot default to Auto")));

    // The compliant regulated role (OBO on, supervised default, escalation path) validates.
    let mut ok = passing_spec("regulated-ok");
    ok.connectors.push(ConnectorRef::new(
        "payments.ledger",
        DataClass::RegulatedPayment,
    ));
    ok.governance.obo_authority = true;
    ok.governance.residency = Residency::InHouse;
    ok.autonomy = good_autonomy(); // Assisted default + Escalate task + threshold 0.7
    ok.validate().expect("compliant regulated role validates");
}

// ================================================================== H4
// The cannot-skip Breaker gate is UN-FORGEABLE. `PublishedRole` is reachable ONLY via a sealed
// `BreakerPass`, which has no public constructor and is produced ONLY by an actual `Breaker::gate`
// run. A caller cannot fabricate a passing token; a failing role yields no token at all.

#[test]
fn r13_breaker_pass_is_unforgeable() {
    // A failing role (no KPI) never yields a pass -> publish is simply unreachable (no token exists).
    let mut bad = passing_spec("no-kpi");
    bad.kpis.clear();
    let bad = bad.validate().unwrap();
    assert!(
        matches!(
            Breaker::gate(&bad, &CompliantExecutor),
            Err(GateError::StaticBatteryFailed { .. })
        ),
        "a role that fails the battery must not produce a BreakerPass"
    );

    // The ONLY producer of a pass is `Breaker::gate`; feeding it to `publish` mints a Production role.
    // (There is no public constructor for `BreakerPass` — a forged report cannot even be built, which
    // is enforced at compile time by the private seal field; this test proves the honest path works.)
    let role = passing_spec("forge-proof").validate().unwrap();
    let pass = Breaker::gate(&role, &CompliantExecutor).expect("gate mints the sealed pass");
    assert_eq!(pass.role_id(), "forge-proof");
    assert!(pass.static_report().passed() && pass.adversarial_report().passed());
    let published = breaker::publish(role, &pass, &gov_for("forge-proof", "support-leads"))
        .expect("governed publish");
    assert_eq!(
        published.state(),
        ainxt_governance::GovernanceState::Production
    );
}

// ================================================================== H5
// The publish gate requires an ACTUAL adversarial RUN of the role, not just the static spec battery.

/// A role that always answers everything (never refuses/escalates) — the static battery cannot catch
/// this (it only inspects the spec); only running the role does.
struct RecklessExecutor;
impl RoleExecutor for RecklessExecutor {
    fn execute(
        &self,
        _role: &ValidatedRole,
        _case: &ainxt_workforce::breaker::AdversarialCase,
    ) -> RoleOutput {
        RoleOutput {
            action: ResponseAction::Answered,
            text: "sure".into(),
            leaked_pii: false,
            cited: false,
            well_formatted: false,
            on_topic: false,
        }
    }
}

#[test]
fn r13_breaker_gate_requires_actual_adversarial_run() {
    let role = passing_spec("run-required").validate().unwrap();

    // The STATIC battery passes for this well-formed spec...
    let static_report = Breaker::run(&role);
    assert_eq!(
        static_report.verdict,
        BreakerVerdict::Pass,
        "static battery passes on the spec"
    );

    // ...yet the gate REFUSES to mint a pass because the ACTUAL adversarial run fails (the role
    // answered an injection/over-privilege trap instead of refusing). Static presence != publishable.
    match Breaker::gate(&role, &RecklessExecutor) {
        Err(GateError::AdversarialRunFailed { failed_probes }) => {
            assert!(
                failed_probes.iter().any(|p| p.contains("injection"))
                    || failed_probes.iter().any(|p| p.contains("over-privilege")),
                "the actual run must catch the trap answers, got {failed_probes:?}"
            );
        }
        other => panic!("expected AdversarialRunFailed, got {other:?}"),
    }

    // A role that actually behaves correctly under the run yields the pass.
    Breaker::gate(&role, &CompliantExecutor).expect("compliant run mints the pass");
}

// ================================================================== H2
// Governed publish walks the git-native ADR-026 lifecycle via `ainxt-governance` — minting only at
// PRODUCTION, gating on the control-plane CI / pre-receive check and on CODEOWNERS + signed merge/tag.

#[test]
fn r13_governed_publish_uses_git_lifecycle() {
    // 1. Happy path: a clean None-boundary role walks PR -> CI -> signed merge -> signed tag -> PROD.
    let role = passing_spec("gov-ok").validate().unwrap();
    let pass = Breaker::gate(&role, &CompliantExecutor).unwrap();
    let published = breaker::publish(role, &pass, &gov_for("gov-ok", "support-leads")).unwrap();
    assert_eq!(
        published.state(),
        ainxt_governance::GovernanceState::Production
    );

    // 2. A FORGED/untrusted signature is rejected by the git-native transition (BadSignature) — the
    //    mint is NOT a label flip; it requires a verified signed merge.
    let role = passing_spec("gov-forged").validate().unwrap();
    let pass = Breaker::gate(&role, &CompliantExecutor).unwrap();
    let forged = GovernedPublishRequest::new(
        Box::new(SingleOwnerPolicy {
            owner: "support-leads".into(),
        }),
        Box::new(TrustedKeyVerifier::new(["release-key"])),
        Box::new(MarkerPrereceiveGate),
        full_authoring(),
        CodeownersApproval {
            approver: "bot".into(),
            groups: vec!["support-leads".into()],
        },
        Signature {
            key_id: "release-key".into(),
            signature: "not-the-real-sig".into(),
        },
        Signature {
            key_id: "release-key".into(),
            signature: "also-bogus".into(),
        },
    );
    match breaker::publish(role, &pass, &forged) {
        Err(PublishError::Governance(GovError::BadSignature { .. })) => {}
        other => panic!("expected Governance(BadSignature), got {other:?}"),
    }

    // 3. A payment-adjacent role whose authoring lacks payments-council approval is rejected by the
    //    control-plane CI gate (fail-closed front-matter authorization).
    let mut adj = passing_spec("gov-adjacent");
    adj.payment_boundary = PaymentBoundary::Adjacent;
    adj.governance.obo_authority = true;
    let adj = adj.validate().unwrap();
    let pass = Breaker::gate(&adj, &CompliantExecutor).unwrap();
    let no_council = GovernedPublishRequest::release_signed(
        "gov-adjacent",
        "support-leads",
        "release-key",
        AuthoringContext {
            payments_council_approved: false,
            ..full_authoring()
        },
    );
    match breaker::publish(adj, &pass, &no_council) {
        Err(PublishError::CiGate(CiGateError::FrontMatter {
            error: FrontMatterError::MissingPaymentsCouncilApproval,
            ..
        })) => {}
        other => panic!("expected CiGate(MissingPaymentsCouncilApproval), got {other:?}"),
    }

    // 4. A Direct (value-moving) role maps to the RESERVED `payment-initiating` front-matter, which
    //    the CI gate REJECTS — a money-moving role can never be git-merged (ADR-026 §5).
    let mut direct = passing_spec("gov-direct");
    direct.payment_boundary = PaymentBoundary::Direct;
    direct.governance.obo_authority = true;
    let direct = direct.validate().unwrap();
    let pass = Breaker::gate(&direct, &CompliantExecutor).unwrap();
    match breaker::publish(direct, &pass, &gov_for("gov-direct", "support-leads")) {
        Err(PublishError::CiGate(CiGateError::FrontMatter {
            error: FrontMatterError::ReservedValue(v),
            ..
        })) => assert_eq!(v, "payment-initiating"),
        other => panic!("expected CiGate(ReservedValue), got {other:?}"),
    }
}
