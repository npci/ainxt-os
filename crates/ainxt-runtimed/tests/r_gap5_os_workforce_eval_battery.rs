// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-CLOSE os-workforce (gap5-os-workforce-authoring) item #5 — a REAL Step-6 quality-eval battery.
//! `RoleStudio::define_kpis` (`ainxt-workforce`, `studio.rs:338`) only checked the drafted spec's
//! `Vec<Kpi>` was non-empty — a name + a business-metric target, never a concrete, RUNNABLE gold-set
//! case. `generate_eval_battery` (in `ainxt-runtimed`, the composition root — `ainxt-eval` is
//! deliberately NOT a dependency of the dependency-free `ainxt-workforce` crate) derives one genuine
//! `ainxt_eval::EvalCase` per KPI from the role's own charter + KPI name, and is wired into the served
//! `"studio_action": "draft_role_from_job"` turn's response — proven here through the REAL served
//! composition root: `assemble_selected("workforce")` -> `Client::in_process` -> `client.chat(...)`.

use ainxt_client::{Client, ClientConfig};
use ainxt_eval::{CaseResult, EvalCriteria, EvalSystem, QualityJudge, QualityScore};
use ainxt_runtimed::{assemble_selected, generate_eval_battery, load_layered, LoadedConfig};
use ainxt_types::Principal;
use ainxt_workforce::autonomy::{AutonomyLevel, AutonomyModel};
use ainxt_workforce::role::{
    Charter, Governance, Kpi, ModelRiskClass, PaymentBoundary, Residency, RoleSpec, Visibility,
};

fn offline() -> LoadedConfig {
    load_layered(&[("x", "version = 1")]).unwrap()
}

fn minimal_spec(id: &str, kpis: Vec<Kpi>) -> RoleSpec {
    RoleSpec {
        id: id.to_string(),
        charter: Charter {
            title: "L1 Support Engineer".into(),
            responsibilities: vec!["triage tickets from the queue".into()],
            inputs: vec![],
            outputs: vec![],
            escalation_rules: vec!["escalate anything unrecognized to a human".into()],
        },
        agents: vec![],
        skills: vec![],
        connectors: vec![],
        knowledge: vec![],
        governance: Governance {
            owner: "alice".into(),
            codeowners_group: "support-leads".into(),
            rbac_visibility: Visibility::Private,
            obo_authority: false,
            model_risk_class: ModelRiskClass::Low,
            residency: Residency::InHouse,
            retention_days: 365,
        },
        kpis,
        autonomy: AutonomyModel::new(AutonomyLevel::Assisted, 0.7),
        payment_boundary: PaymentBoundary::None,
    }
}

/// GAP-CLOSE os-workforce #5, unit-level: the generated battery has one real case per KPI, each
/// derived from the role's OWN charter/KPI data (not fabricated constants) and runnable through
/// `ainxt_eval::run_eval`.
#[test]
fn generate_eval_battery_derives_one_real_case_per_kpi_from_the_spec_itself() {
    let spec = minimal_spec(
        "l1-support-eval",
        vec![Kpi::new("resolution-rate", 0.85), Kpi::new("csat", 0.8)],
    );
    let battery = generate_eval_battery(&spec);
    assert_eq!(battery.len(), 2, "one eval case per KPI: {battery:?}");

    let by_kpi: std::collections::HashMap<&str, _> =
        battery.iter().map(|c| (c.id.as_str(), c)).collect();
    let res = by_kpi
        .values()
        .find(|c| c.id.contains("resolution-rate"))
        .expect("a case for resolution-rate");
    assert!(
        res.id.starts_with("l1-support-eval::eval::"),
        "case id: {}",
        res.id
    );
    assert!(
        res.input.contains("triage tickets from the queue"),
        "the case input must be derived from the role's OWN charter, not invented: {}",
        res.input
    );
    assert!(
        res.criteria.rubric.contains("resolution-rate") && res.criteria.rubric.contains("0.85"),
        "the rubric must name the SAME KPI + target: {}",
        res.criteria.rubric
    );
    assert!(
        res.criteria
            .rubric
            .contains("escalate anything unrecognized"),
        "the rubric must carry the role's own escalation rule: {}",
        res.criteria.rubric
    );

    // Actually runnable: `ainxt_eval::run_eval` accepts the battery with a real system + judge.
    struct EchoSystem;
    impl EvalSystem for EchoSystem {
        fn respond(&self, input: &str) -> String {
            format!("handled: {input}")
        }
    }
    struct AlwaysPassJudge;
    impl QualityJudge for AlwaysPassJudge {
        fn score(&self, _input: &str, _output: &str, _criteria: &EvalCriteria) -> QualityScore {
            QualityScore {
                score: 90,
                rationale: "looks fine".into(),
            }
        }
    }
    let report = ainxt_eval::run_eval(&battery, &EchoSystem, &AlwaysPassJudge);
    assert_eq!(report.n, 2);
    assert_eq!(report.passed, 2);
    let _: &[CaseResult] = &report.results;
}

/// GAP-CLOSE os-workforce #5, served end-to-end: the `"studio_action": "draft_role_from_job"` turn's
/// response now carries a real `eval_battery` alongside the drafted `spec`, reached through the exact
/// same real served composition root proven for items #1/#2/#3
/// (`r_gap5_os_workforce_studio_served.rs`).
#[tokio::test(flavor = "multi_thread")]
async fn studio_draft_response_carries_a_real_eval_battery_from_the_served_dispatch() {
    let assembled =
        assemble_selected(&offline(), "workforce").expect("--surface workforce must assemble");
    let client = Client::in_process(
        assembled.manager,
        Principal::user("u", &["chat.send"]).with_department("support"),
        ClientConfig::default(),
    );
    let body = serde_json::json!({
        "studio_action": "draft_role_from_job",
        "id": "l1-support-eval-served",
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

    let json_start = out.text.find('{').expect("a JSON payload");
    let payload: serde_json::Value =
        serde_json::from_str(out.text[json_start..].trim()).expect("valid JSON studio result");

    let spec_kpis = payload["spec"]["kpis"].as_array().expect("kpis array");
    let battery = payload["eval_battery"]
        .as_array()
        .expect("eval_battery array");
    assert_eq!(
        battery.len(),
        spec_kpis.len(),
        "one real eval case per drafted KPI: kpis={spec_kpis:?} battery={battery:?}"
    );
    assert!(
        !battery.is_empty(),
        "the Support template always seeds KPIs, so the battery must be non-empty"
    );
    for case in battery {
        assert!(case["id"]
            .as_str()
            .unwrap()
            .starts_with("l1-support-eval-served::eval::"));
        assert!(!case["input"].as_str().unwrap().is_empty());
        assert!(!case["criteria"]["rubric"].as_str().unwrap().is_empty());
        assert_eq!(case["criteria"]["threshold"], 70);
    }
}
