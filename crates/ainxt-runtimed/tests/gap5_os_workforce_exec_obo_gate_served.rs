// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-CLOSE os-workforce-exec #1 (CRITICAL) — `ModelRoutedExecutor::with_obo_gate` existed and was
//! proven at the crate-unit level (`r_workforce_obo_authority_binding.rs`, which builds a bespoke
//! `ModelRoutedExecutor` by hand), but `assemble_workforce_surface_served` — the EXACT function the
//! daemon's `--surface workforce` dispatch (`assemble_selected`, the same table
//! `r14_surface_workforce_assembles_the_role_factory` drives) calls in production — never called
//! `with_obo_gate` at all. `check_obo` short-circuits to `Ok(())` when no gate is installed, so every
//! served role's `obo_authority: true` claim was accepted at face value and NEVER actually checked.
//!
//! This test drives a REAL turn through `assemble_selected(&loaded, "workforce")` — the served
//! composition root, not a hand-built `WorkforceSurface` — with an AUTHORED RoleSpec that claims
//! `obo_authority: true` but declares no capability literally named `"role.execute"` (the fixed
//! capability `ModelRoutedExecutor::check_obo` asks the policy to authorize). Under the installed
//! `ThreeLayerPolicy`, this is a genuine Layer-1 `NoGrant` denial — proving the policy is REACHED and
//! EVALUATED for real, not bypassed. The served turn must fail closed, and — the part that was
//! impossible before this fix — the denial must be durably AUDITED, verified here by reopening the
//! SAME `[gates] audit = "event-log"` directory this exact composition root wrote to (mirrors
//! `gap_fix_tooling_build_obo_sink_durably_persists_when_event_log_selected`'s own verification shape).
//!
//! A second turn with `obo_authority: false` proves the gate still only applies WHEN the role claims
//! the authority — no OBO record is written for that role at all, through the same served surface.

use ainxt_client::{Client, ClientConfig};
use ainxt_runtimed::{assemble_selected, load_layered, LoadedConfig};
use ainxt_types::{DataClass, Principal};
use ainxt_workforce::autonomy::{AutonomyLevel, AutonomyModel, TaskAutonomy};
use ainxt_workforce::ladder::{AgentRung, Capability, ModelPolicy, SkillRef};
use ainxt_workforce::role::{
    Charter, ConnectorRef, Governance, KnowledgeScope, Kpi, ModelRiskClass, PaymentBoundary,
    Residency, RoleSpec, Visibility,
};

/// A durable, unique event-log directory per test invocation (never shared across test runs).
fn durable_gates_dir(tag: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir()
        .join(format!("ainxt-gap5-obo-served-{tag}-{nanos}"))
        .to_string_lossy()
        .into_owned()
}

fn loaded_with_durable_obo_audit(dir: &str) -> LoadedConfig {
    let toml =
        format!("version = 1\n[gates]\naudit = \"event-log\"\naudit_event_log_dir = \"{dir}\"\n");
    load_layered(&[("gap5-os-workforce-exec", &toml)]).expect("config with durable OBO audit loads")
}

fn authored_role(id: &str, obo_authority: bool) -> RoleSpec {
    RoleSpec {
        id: id.to_string(),
        charter: Charter {
            title: "Gap5 Ops Worker".into(),
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
        // Deliberately NOT named "role.execute" — the fixed capability `check_obo` authorizes. A
        // ThreeLayerPolicy grant is built from the role's OWN capability names, so this role's grants
        // can never cover "role.execute": the denial below is a genuine Layer-1 NoGrant, not a scripted
        // stand-in.
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
            obo_authority,
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

#[tokio::test(flavor = "multi_thread")]
async fn gap5_served_workforce_obo_denial_is_reached_and_durably_audited() {
    let dir = durable_gates_dir("denied");
    let loaded = loaded_with_durable_obo_audit(&dir);

    // The REAL composition root — the exact function `main.rs`'s `--surface workforce` dispatch calls.
    let assembled =
        assemble_selected(&loaded, "workforce").expect("--surface workforce must assemble");
    let client = Client::in_process(
        assembled.manager,
        Principal::user("u", &["chat.send"]).with_department("ops"),
        ClientConfig::default(),
    );

    let spec = authored_role("gap5-obo-denied", true);
    let body = serde_json::to_string(&spec).unwrap();
    let out = client.chat("s", "t", &body).unwrap().collect().await;

    // The stream always reaches `Done` (both the pass and fail-closed paths send it) — `completed`
    // alone does not distinguish them; the terminal `Event::Error` is what proves fail-closed.
    assert!(
        out.completed,
        "the served workforce turn must still reach a terminal Done"
    );
    let err = out.error.as_deref().unwrap_or_default();
    assert!(
        err.contains("workforce gate refused (fail-closed)"),
        "an OBO-denied role must fail closed through the real gate, not clear it or surface an \
         unrelated error: {err}"
    );

    // The genuinely new part: the OBO decision was DURABLY AUDITED by the exact served composition
    // root, over the [gates] audit=event-log directory THIS config declared — reopened fresh, exactly
    // like `gap_fix_tooling_build_obo_sink_durably_persists_when_event_log_selected` verifies for the
    // chat-engine's OBO gate.
    let reopened =
        ainxt_eventlog::JsonlEventLog::open(&dir).expect("reopen the durable OBO audit dir");
    let records = ainxt_eventlog::EventLog::records(&reopened, "__obo__");
    assert!(
        !records.is_empty(),
        "the served workforce surface's OBO gate must have recorded at least one decision"
    );
    assert!(
        records.iter().all(|r| r.kind == "obo_decision"),
        "every record in the OBO session must be a genuine OBO decision: {records:?}"
    );
    assert!(
        records.iter().all(|r| r.actor == "alice"),
        "the audited decision is authorized AS the role's declared owner, never the ambient caller: \
         {records:?}"
    );
    assert!(
        records.iter().all(|r| r.text.contains("DENIED") && r.text.contains("cap=role.execute")),
        "the audited decision must reflect a genuine Layer-1 NoGrant denial on 'role.execute', not a \
         fabricated verdict: {records:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn gap5_served_workforce_skips_the_obo_check_when_the_role_does_not_claim_it() {
    let dir = durable_gates_dir("skipped");
    let loaded = loaded_with_durable_obo_audit(&dir);

    let assembled =
        assemble_selected(&loaded, "workforce").expect("--surface workforce must assemble");
    let client = Client::in_process(
        assembled.manager,
        Principal::user("u", &["chat.send"]).with_department("ops"),
        ClientConfig::default(),
    );

    let spec = authored_role("gap5-no-obo-claim", false);
    let body = serde_json::to_string(&spec).unwrap();
    let _ = client.chat("s", "t", &body).unwrap().collect().await;

    // No OBO session was ever created for this surface: the field still gates WHEN the check runs, not
    // just what it decides, proven through the SAME served composition root as the denial case above.
    let reopened =
        ainxt_eventlog::JsonlEventLog::open(&dir).expect("reopen the durable OBO audit dir");
    let records = ainxt_eventlog::EventLog::records(&reopened, "__obo__");
    assert!(
        records.is_empty(),
        "a role that never claims obo_authority must never reach the OBO policy at all: {records:?}"
    );
}
