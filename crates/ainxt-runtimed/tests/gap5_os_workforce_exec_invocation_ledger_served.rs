// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-CLOSE os-workforce-exec #2 — `ModelRoutedExecutor::with_invocation_ledger` existed and was
//! proven at the crate-unit level (`r_workforce_invocation_telemetry.rs`, which builds a bespoke
//! `ModelRoutedExecutor` by hand), but `assemble_workforce_surface_served` — the EXACT function the
//! daemon's `--surface workforce` dispatch (`assemble_selected`) calls in production — never called
//! `with_invocation_ledger` at all, so every genuine served role invocation was silently discarded
//! rather than recorded.
//!
//! This test drives a REAL turn through `assemble_selected(&loaded, "workforce")` — the served
//! composition root, not a hand-built `WorkforceSurface`/`ModelRoutedExecutor` — with an authored
//! RoleSpec, then reads `Assembled::workforce_invocation_ledger` (the SAME ledger handle the served
//! executor records to) and proves it holds a genuine, non-fabricated invocation count for that role.
//! A second, never-turned role proves the ledger is per-role (no invocation bleeds onto an unrelated
//! id), and the `"chat"` selector proves the field is honestly `None` on a surface with no
//! role-invocation concept at all.

use ainxt_client::{Client, ClientConfig};
use ainxt_runtimed::{assemble_selected, load_layered, LoadedConfig};
use ainxt_types::{DataClass, Principal};
use ainxt_workforce::autonomy::{AutonomyLevel, AutonomyModel, TaskAutonomy};
use ainxt_workforce::breaker::Breaker;
use ainxt_workforce::ladder::{AgentRung, Capability, ModelPolicy, SkillRef};
use ainxt_workforce::role::{
    Charter, ConnectorRef, Governance, KnowledgeScope, Kpi, ModelRiskClass, PaymentBoundary,
    Residency, RoleSpec, Visibility,
};

fn offline() -> LoadedConfig {
    load_layered(&[("gap5-os-workforce-exec", "version = 1")]).unwrap()
}

/// `obo_authority: false` — deliberately keeps this test's concern isolated from item #1's OBO gate
/// (every case's execution still records to the ledger regardless of the OBO outcome, but a role that
/// never claims the authority makes the "why did this fail" story simpler to read).
fn authored_role(id: &str) -> RoleSpec {
    RoleSpec {
        id: id.to_string(),
        charter: Charter {
            title: "Gap5 Invocation-Ledger Worker".into(),
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
            obo_authority: false,
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

fn today_day_number() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / 86_400
}

#[tokio::test(flavor = "multi_thread")]
async fn gap5_served_workforce_turn_records_a_real_invocation_per_adversarial_case() {
    let loaded = offline();

    // The REAL composition root — the exact function `main.rs`'s `--surface workforce` dispatch calls.
    let assembled =
        assemble_selected(&loaded, "workforce").expect("--surface workforce must assemble");
    let ledger = assembled
        .workforce_invocation_ledger
        .clone()
        .expect("the workforce surface must expose its real invocation ledger");

    let role_id = "gap5-ledger-role";
    let spec = authored_role(role_id);
    // The exact same corpus size `Breaker::run_adversarial` will drive through the executor — computed
    // independently, from the library's own corpus generator, so this assertion is not a fabricated
    // "at least one" but the genuine expected count.
    let validated = spec.clone().validate().expect("valid spec");
    let expected_invocations = Breaker::adversarial_corpus(&validated).len() as u64;
    assert!(
        expected_invocations > 0,
        "the canonical corpus must be non-empty for this role shape"
    );

    let client = Client::in_process(
        assembled.manager,
        Principal::user("u", &["chat.send"]).with_department("ops"),
        ClientConfig::default(),
    );
    let body = serde_json::to_string(&spec).unwrap();
    let _ = client.chat("s", "t", &body).unwrap().collect().await;

    let today = today_day_number();
    let recorded = ledger.invocations_30d(role_id, today);
    assert_eq!(
        recorded, expected_invocations,
        "the served turn must record exactly one REAL ledger hit per adversarial case actually \
         executed by the live composition root, not a fabricated or partial count"
    );

    // A role that was never turned through this surface has no invocations at all — the ledger is
    // genuinely per-role, not a global counter that would make the assertion above trivially true.
    assert_eq!(
        ledger.invocations_30d("gap5-ledger-role-never-turned", today),
        0,
        "an unrelated role id must show zero invocations on the SAME ledger"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn gap5_non_workforce_surfaces_honestly_expose_no_invocation_ledger() {
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let chat = assemble_selected(&offline(), "chat").expect("chat must assemble");
    assert!(
        chat.workforce_invocation_ledger.is_none(),
        "a surface with no role-invocation concept must not fabricate a ledger handle"
    );
}
