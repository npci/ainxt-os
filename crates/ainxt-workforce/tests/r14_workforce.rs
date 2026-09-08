// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-14 HIGH-severity closure for the AiNxt-OS workforce ladder (ainxt-workforce).
//!
//! H (R13 residual): **Per-task Auto autonomy is now cross-checked against the role's DERIVED data
//! class, not only the self-declared per-task `regulated` bool.** Previously a per-task `Auto`
//! override was gated solely by `TaskAutonomy::regulated` (in `AutonomyModel::validate`); an author
//! could dial a regulated-data task to fully-autonomous simply by leaving that bool `false`. The fix:
//!   * `TaskAutonomy` gains an optional attested `data_class`, folded into
//!     `RoleSpec::max_data_class` (so a task that touches regulated data raises the role's DERIVED
//!     class and cannot understate it), and
//!   * `RoleSpec::validate` — inside the `max.is_regulated()` block, keyed off the DERIVED class —
//!     rejects any per-task `Auto` on a task that touches regulated data (effective signal), exactly
//!     like the top-level default rule. Benign non-regulated per-task Auto (WORKFORCE §5 task-by-task
//!     automation, e.g. credential-reset) stays valid — the check is discriminating, not blanket.

use ainxt_types::DataClass;
use ainxt_workforce::autonomy::{AutonomyLevel, AutonomyModel, TaskAutonomy};
use ainxt_workforce::ladder::{AgentRung, Capability, ModelPolicy, SkillRef};
use ainxt_workforce::role::{
    Charter, ConnectorRef, Governance, KnowledgeScope, Kpi, ModelRiskClass, PaymentBoundary,
    Residency, RoleSpec, Visibility,
};

// ------------------------------------------------------------------ helpers

fn agent() -> AgentRung {
    AgentRung::new(
        "agent-1",
        "an L1 ops persona",
        ModelPolicy::new(&["openai"], DataClass::Confidential),
    )
    .with_skill(SkillRef::behavioral("ops-sop"))
    .with_capability(Capability::new("kb.search", DataClass::Internal))
}

fn governance() -> Governance {
    Governance {
        owner: "alice".into(),
        codeowners_group: "ops-leads".into(),
        rbac_visibility: Visibility::Private,
        obo_authority: true, // compliant so we isolate the per-task-Auto rejection
        model_risk_class: ModelRiskClass::Low,
        residency: Residency::InHouse, // compliant residency (regulated stays in-house)
        retention_days: 365,
    }
}

/// A base spec that, on its own, touches only non-regulated (Internal) data — so the ONLY regulated
/// signal in the treatment case comes from the per-task attestation. `autonomy` is filled per-case.
fn base_spec(id: &str, autonomy: AutonomyModel) -> RoleSpec {
    RoleSpec {
        id: id.to_string(),
        charter: Charter {
            title: "Ops Engineer".into(),
            responsibilities: vec!["run runbooks".into()],
            inputs: vec!["alert".into()],
            outputs: vec!["remediation".into()],
            escalation_rules: vec!["escalate anything unrecognized".into()],
        },
        agents: vec![agent()],
        skills: vec![SkillRef::behavioral("ops-sop")],
        connectors: vec![ConnectorRef::new(
            "connector.ticketing",
            DataClass::Internal,
        )],
        knowledge: vec![{
            let mut k = KnowledgeScope::new("kb:ops", DataClass::Internal);
            k.retrieval_quality = Some(0.9);
            k
        }],
        governance: governance(),
        kpis: vec![Kpi::new("mttr", 0.85)],
        autonomy,
        payment_boundary: PaymentBoundary::None, // deliberately understated — the point of the fix
    }
}

// ==================================================================================================
// Proves: a per-task Auto on a task that touches regulated data is REFUSED by RoleSpec::validate,
// via the DERIVED data class — even though the self-declared `regulated` bool is false and the
// payment_boundary is understated as None. Control vs. treatment shows fail-before / pass-after in
// one run: the identical Auto task WITHOUT the regulated attestation validates clean (the old
// behaviour), and WITH it the role is rejected.

#[test]
fn r14_regulated_per_task_auto_refused() {
    // ---- CONTROL (the pre-fix behaviour, still correct): a benign per-task Auto in a role that
    // touches only non-regulated data validates clean. No task attests regulated data.
    let control = AutonomyModel::new(AutonomyLevel::Assisted, 0.7)
        .with_task(TaskAutonomy::new("restart-service", AutonomyLevel::Auto)) // Auto, non-regulated
        .with_task(TaskAutonomy::new("unknown", AutonomyLevel::Escalate));
    let control_spec = base_spec("ops-control", control);
    assert!(
        !control_spec.max_data_class().is_regulated(),
        "control role must derive a NON-regulated class"
    );
    control_spec
        .validate()
        .expect("a non-regulated per-task Auto is allowed (WORKFORCE §5)");

    // ---- TREATMENT: the SAME role, but the Auto task now attests it touches RegulatedPayment data
    // while the self-declared `regulated` bool stays FALSE (the under-declaration the fix targets).
    let treat = AutonomyModel::new(AutonomyLevel::Assisted, 0.7)
        .with_task(
            // regulated=false (default) BUT attests a regulated data_class -> effective regulated.
            TaskAutonomy::new("initiate-settlement", AutonomyLevel::Auto)
                .touching(DataClass::RegulatedPayment),
        )
        .with_task(TaskAutonomy::new("restart-service", AutonomyLevel::Auto)) // benign, must stay OK
        .with_task(TaskAutonomy::new("unknown", AutonomyLevel::Escalate));
    let treat_spec = base_spec("ops-treatment", treat);

    // The attestation folds into the DERIVED class -> the role is now regulated.
    assert_eq!(
        treat_spec.max_data_class(),
        DataClass::RegulatedPayment,
        "the per-task attestation must raise the role's DERIVED data class (no under-statement)"
    );

    let errs = treat_spec
        .clone()
        .validate()
        .expect_err("a regulated per-task Auto must be refused by RoleSpec::validate");

    // The rejection names the offending task and cites the derived-data-class basis.
    assert!(
        errs.iter().any(|e| e.contains("initiate-settlement")
            && e.contains("cannot be dialed to Auto")
            && e.contains("derived from data class")),
        "must refuse the regulated per-task Auto on a DERIVED basis, got {errs:?}"
    );

    // The benign non-regulated Auto task (restart-service) must NOT be in the rejection — the check
    // is discriminating, not a blanket ban on per-task Auto inside a regulated role.
    assert!(
        !errs
            .iter()
            .any(|e| e.contains("restart-service") && e.contains("cannot be dialed to Auto")),
        "benign non-regulated per-task Auto must remain allowed, got {errs:?}"
    );
}

// ==================================================================================================
// Proves the second, purely-self-declared path is also refused via the DERIVED cross-check (not
// just the pre-existing AutonomyModel::validate bool check): a task self-declared `regulated` at
// Auto, in a role otherwise regulated by a connector, is refused with the DERIVED-basis message.

#[test]
fn r14_self_declared_regulated_auto_still_refused_via_derived_check() {
    let autonomy = AutonomyModel::new(AutonomyLevel::Assisted, 0.7)
        .with_task(TaskAutonomy::new("authorize-payout", AutonomyLevel::Auto).regulated())
        .with_task(TaskAutonomy::new("unknown", AutonomyLevel::Escalate));
    let mut spec = base_spec("ops-selfdecl", autonomy);
    // Make the role regulated at the role level via a connector (independent of the task attestation).
    spec.connectors.push(ConnectorRef::new(
        "payments.ledger",
        DataClass::RegulatedPayment,
    ));

    let errs = spec
        .validate()
        .expect_err("self-declared regulated Auto must be refused");
    assert!(
        errs.iter().any(|e| e.contains("authorize-payout")
            && e.contains("cannot be dialed to Auto")
            && e.contains("derived from data class")),
        "RoleSpec::validate must refuse it on the derived basis, got {errs:?}"
    );
}
