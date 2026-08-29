// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-CLOSE os-workforce (gap6-workforce-governance-gate) — part (c) of the required proof: a REAL
//! HTTP request against the dedicated `POST /v1/workforce/roles` route (`ainxt-server`'s
//! `workforce_router`, mounted by `assemble_full_with_control_plane`/`to_full_app_ext` on a
//! `--surface workforce` daemon — the EXACT composition functions `main.rs` calls) reaches the SAME
//! `WorkforceSurface::publish_role` enforcement `r_gap6_workforce_governance_gate.rs` proves directly:
//! refusing a non-admin caller, refusing a role with no shadow-run evidence, and publishing a role that
//! legitimately clears every Studio gate. Split into its own file (rather than folded into the sibling
//! direct-call test file) purely to keep this crate's incremental commit history bisectable — the HTTP
//! route (`ainxt-server`'s side) and the underlying gate logic (`ainxt-workforce`/`ainxt-runtimed`'s
//! side) are two independently-compilable changes.
//!
//! `--surface workforce`'s served composition ([`assemble_workforce_surface_served`]) drives Step 7's
//! Breaker AND Step 8's shadow-run through a LIVE, `ModelRouter`-backed [`ModelRoutedExecutor`], not the
//! offline `CompliantExecutor` the direct-call sibling test uses — so proving the POSITIVE control (a
//! role that clears every gate actually publishes) over this real HTTP path needs an actual model
//! response, not a fixed offline string. This configures a `kind = "local"` (in-house, keyless) provider
//! pointed at a tiny hand-rolled mock `/chat/completions` upstream that answers in-character for the
//! Breaker's own generated adversarial corpus and the shadow-run's own probes — mirroring the exact
//! "stub only the vendor HTTP endpoint, never the mechanism under test" pattern
//! `gap5_fabric_mount_served.rs` already established in this crate. `governance.obo_authority` is left
//! `false` here (the role's own data classes are all `Internal`, so `RoleSpec::validate` does not
//! require it) — this surface's `ModelRoutedExecutor::with_obo_gate` installs a real, otherwise-empty
//! `ThreeLayerPolicy` whose grants are keyed by the role's OWN capability names, never the
//! `"role.execute"` capability `check_obo` actually asks it to authorize, so an `obo_authority: true`
//! role would always be denied on this composition — a pre-existing, orthogonal OBO-binding
//! characteristic, not a Studio governance gate this test is about.
//!
//! FAIL-BEFORE / PASS-AFTER: before this fix, `POST /v1/workforce/roles` did not exist on the served
//! router at all (every request here would 404); `publish_role` itself only drove Steps 2/7/9 and
//! would have accepted a role missing Steps 3-6/8's evidence.

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use ainxt_identity::control::ControlPlane;
use ainxt_runtimed::{assemble_full_with_control_plane, assemble_selected, load_layered};
use ainxt_types::DataClass;
use ainxt_workforce::autonomy::{AutonomyLevel, AutonomyModel, TaskAutonomy};
use ainxt_workforce::breaker::ResponseAction;
use ainxt_workforce::ladder::{AgentRung, Capability, ModelPolicy, SkillRef};
use ainxt_workforce::role::{
    Charter, ConnectorRef, Governance, KnowledgeScope, Kpi, ModelRiskClass, PaymentBoundary,
    Residency, RoleSpec, Visibility,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const APPROVED: &str = "service.restart";

/// A fully-compliant role (matches `r_gap6_workforce_governance_gate.rs`'s `compliant_spec` shape):
/// a sensitive `service.restart` capability (needs Step 3 approval), knowledge scored above the
/// floor, and non-empty KPIs. The caller still supplies `approved_capabilities`/`shadow_cases` over
/// the wire per test. `obo_authority: false` — see the module doc for why.
fn compliant_spec(id: &str) -> RoleSpec {
    RoleSpec {
        id: id.to_string(),
        charter: Charter {
            title: "SRE Ops Worker".into(),
            responsibilities: vec!["remediate incidents".into()],
            inputs: vec!["alert".into()],
            outputs: vec!["remediation".into()],
            escalation_rules: vec!["escalate anything unrecognized".into()],
        },
        agents: vec![AgentRung::new(
            "agent-1",
            "an SRE persona",
            ModelPolicy::new(&["openai"], DataClass::Internal),
        )
        .with_skill(SkillRef::behavioral("runbook-sop"))
        .with_capability(Capability::new("monitoring.read", DataClass::Internal))
        .with_capability(
            Capability::new("service.restart", DataClass::Internal).requiring_approval(),
        )],
        skills: vec![SkillRef::behavioral("runbook-sop")],
        connectors: vec![ConnectorRef::new(
            "connector.monitoring",
            DataClass::Internal,
        )],
        knowledge: vec![{
            let mut k = KnowledgeScope::new("kb:runbooks", DataClass::Internal);
            k.retrieval_quality = Some(0.9);
            k
        }],
        governance: Governance {
            owner: "alice".into(),
            codeowners_group: "sre-leads".into(),
            rbac_visibility: Visibility::Private,
            obo_authority: false,
            model_risk_class: ModelRiskClass::Low,
            residency: Residency::InHouse,
            retention_days: 365,
        },
        kpis: vec![
            Kpi::new("mttr-minutes", 30.0),
            Kpi::new("false-remediation-rate", 0.02),
        ],
        autonomy: AutonomyModel::new(AutonomyLevel::Assisted, 0.6)
            .with_task(TaskAutonomy::new(
                "restart-service",
                AutonomyLevel::Assisted,
            ))
            .with_task(TaskAutonomy::new("unknown", AutonomyLevel::Escalate)),
        payment_boundary: PaymentBoundary::None,
    }
}

/// Find the first `\r\n\r\n` header/body separator in a raw byte buffer.
fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// A raw, hand-rolled mock OpenAI-`/chat/completions`-schema upstream (mirrors
/// `gap5_fabric_mount_served.rs`'s `spawn_mock_llm` exactly — no axum/hyper dependency needed): reads
/// each request's `messages[0].content` (the exact outbound prompt `ModelRoutedExecutor::prompt_for`
/// sends, which embeds the Breaker's own generated `AdversarialCase.input` / this test's own shadow-case
/// input after `"Request: "`) and answers IN CHARACTER for that specific probe — the SAME content-aware
/// dispatch `r_workforce_live_role_executor.rs`'s `ScenarioProvider` / `r_gap5_os_workforce_studio_served.rs`'s
/// `ScenarioProvider` already establish as a legitimate live-executor double, just speaking real HTTP:
/// * a prompt embedding the Breaker's own `"...request far outside your charter."` edge-case probe ->
///   an escalation ("hand this to a human");
/// * a prompt embedding `"normal in-scope"` (the Breaker's own quality-probe phrasing, and this test's
///   own shadow-case phrasing) -> a grounded, cited answer (`[source]`);
/// * anything else (the injection / over-privilege probes) -> a refusal.
async fn spawn_mock_llm() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock llm");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let mut buf: Vec<u8> = Vec::new();
                let mut chunk = [0u8; 8192];
                let (headers_end, content_length) = loop {
                    let n = match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(pos) = find_double_crlf(&buf) {
                        let headers = String::from_utf8_lossy(&buf[..pos]).to_string();
                        let cl = headers
                            .lines()
                            .find_map(|l| {
                                let (k, v) = l.split_once(':')?;
                                if k.trim().eq_ignore_ascii_case("content-length") {
                                    v.trim().parse::<usize>().ok()
                                } else {
                                    None
                                }
                            })
                            .unwrap_or(0);
                        if buf.len() >= pos + 4 + cl {
                            break (pos, cl);
                        }
                    }
                };
                let body_start = headers_end + 4;
                let body = &buf[body_start..body_start + content_length];
                let body_str = String::from_utf8_lossy(body);
                let value: serde_json::Value = serde_json::from_str(&body_str).unwrap_or_default();
                let prompt = value["messages"][0]["content"]
                    .as_str()
                    .unwrap_or("")
                    .to_string();

                let reply = if prompt.contains("far outside your charter") {
                    "I'll be escalating this to a human right away."
                } else if prompt.contains("normal in-scope") {
                    "Here is the grounded answer to your in-scope request [source]."
                } else {
                    "I can't help with that request."
                };
                let sse = format!(
                    "data: {{\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"model\":\"mock\",\"choices\":[{{\"index\":0,\"delta\":{{\"content\":{reply:?}}},\"finish_reason\":null}}]}}\n\n\
                     data: {{\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"model\":\"mock\",\"choices\":[{{\"index\":0,\"delta\":{{}},\"finish_reason\":\"stop\"}}]}}\n\n\
                     data: [DONE]\n\n"
                );
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    sse.len(),
                    sse
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    addr
}

fn loaded_with_mock_llm(
    mock_addr: std::net::SocketAddr,
    tag: &str,
) -> ainxt_runtimed::LoadedConfig {
    // R16 critical: state the trusted-gateway assumption (every served daemon test in this crate does).
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("ainxt-r-gap6-workforce-http-{tag}-{nanos}"));
    let src = format!(
        "version = 1\n\
         [server]\n\
         event_log_dir = {:?}\n\
         [[models.providers]]\n\
         id = \"openai\"\n\
         kind = \"local\"\n\
         base_url = \"http://{mock_addr}\"\n\
         eligible = [\"internal\"]\n",
        dir.to_string_lossy()
    );
    load_layered(&[("r-gap6-workforce-http", &src)]).expect("load offline config")
}

fn publish_request_body(
    spec: &RoleSpec,
    approved_capabilities: &[String],
    shadow_cases: &[(String, ResponseAction)],
) -> String {
    let cases: Vec<serde_json::Value> = shadow_cases
        .iter()
        .enumerate()
        .map(|(i, (input, action))| {
            let action_str = match action {
                ResponseAction::Answered => "answered",
                ResponseAction::Refused => "refused",
                ResponseAction::Escalated => "escalated",
            };
            serde_json::json!({ "id": format!("shadow-{i}"), "input": input, "human_action": action_str })
        })
        .collect();
    serde_json::json!({
        "spec": spec,
        "codeowners_group": "sre-leads",
        "release_key": "release-key",
        "authoring": {
            "payments_council_approved": true,
            "commit_signed": true,
            "author_can_approve": true,
            "author_ad_level": 3,
        },
        "approved_capabilities": approved_capabilities,
        "shadow_cases": cases,
    })
    .to_string()
}

/// 20 cases (the `MIN_SHADOW_OBSERVATIONS` floor) whose input contains `"normal in-scope"` — the mock
/// LLM's own trigger phrase for a grounded, cited answer — so a REAL, live-model-driven observation
/// (never a caller-fabricated `ShadowResult`) reports 100% agreement with the declared human decision
/// `Answered`, clearing `MIN_SHADOW_AGREEMENT`.
fn twenty_agreeing_cases() -> Vec<(String, ResponseAction)> {
    (0..20)
        .map(|i| {
            (
                format!("A normal in-scope remediation request {i}."),
                ResponseAction::Answered,
            )
        })
        .collect()
}

/// **The composition-root proof required by the process spec**: a REAL HTTP `POST` against the
/// daemon-mounted `/v1/workforce/roles` route reaches the SAME `WorkforceSurface::publish_role`
/// enforcement — refusing a non-admin caller, refusing a role with no shadow evidence, and publishing
/// a role that legitimately clears every gate (over a REAL live-model-backed Breaker + shadow-run, via
/// the mock upstream — not a stub of the enforcement itself).
#[tokio::test(flavor = "multi_thread")]
async fn http_post_workforce_roles_reaches_the_real_publish_role_enforcement() {
    let mock_addr = spawn_mock_llm().await;
    let control = Arc::new(Mutex::new(ControlPlane::new()));
    let loaded = loaded_with_mock_llm(mock_addr, "main");
    let assembled = assemble_selected(&loaded, "workforce")
        .expect("--surface workforce must assemble from the real composition-root dispatch");
    let full = assemble_full_with_control_plane(&loaded, assembled, control)
        .expect("assemble_full_with_control_plane must assemble the workforce surface");

    let app = full.to_full_app();
    let ext = full.to_full_app_ext();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(ainxt_server::serve_full_ext(listener, app, ext));

    let client = reqwest::Client::new();
    let base = format!("http://{addr}");

    // ---- 1. A non-admin caller is refused (403) — never reaches publish_role at all. ----
    let spec = compliant_spec("http-nonadmin");
    let body = publish_request_body(&spec, &[APPROVED.to_string()], &twenty_agreeing_cases());
    let denied = client
        .post(format!("{base}/v1/workforce/roles"))
        .header("x-ainxt-user", "u-junior")
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body)
        .send()
        .await
        .expect("request must complete");
    assert_eq!(
        denied.status(),
        reqwest::StatusCode::FORBIDDEN,
        "a non-admin must be refused"
    );

    // ---- 2. An admin caller with NO shadow evidence is refused — the REAL Step-8 gate, not a stub. ----
    // (Role id deliberately avoids the substring "shadow" so the assertion below can only pass because
    // the REAL refusal reason names the gate, never a naming coincidence.)
    let spec_no_evidence = compliant_spec("http-no-evidence");
    let body_no_evidence = publish_request_body(&spec_no_evidence, &[APPROVED.to_string()], &[]);
    let refused = client
        .post(format!("{base}/v1/workforce/roles"))
        .header("x-ainxt-user", "root")
        .header("x-ainxt-role", "admin")
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body_no_evidence)
        .send()
        .await
        .expect("request must complete");
    assert_eq!(
        refused.status(),
        reqwest::StatusCode::FORBIDDEN,
        "an admin publishing a role with zero shadow-run evidence must still be refused"
    );
    let refused_text = refused.text().await.expect("body");
    assert!(
        refused_text.contains("shadow"),
        "the refusal reason must name the real Step-8 shadow-evidence gate: {refused_text}"
    );

    // ---- 3. An admin caller with a role that clears EVERY gate is published (positive control). ----
    let spec_ok = compliant_spec("http-published");
    let body_ok = publish_request_body(&spec_ok, &[APPROVED.to_string()], &twenty_agreeing_cases());
    let ok = client
        .post(format!("{base}/v1/workforce/roles"))
        .header("x-ainxt-user", "root")
        .header("x-ainxt-role", "admin")
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body_ok)
        .send()
        .await
        .expect("request must complete");
    let ok_status = ok.status();
    let ok_text = ok.text().await.expect("body");
    assert_eq!(
        ok_status,
        reqwest::StatusCode::OK,
        "a role clearing every gate must publish: {ok_text}"
    );
    let published_json: serde_json::Value =
        serde_json::from_str(&ok_text).expect("valid JSON body");
    assert_eq!(published_json["role_id"], "http-published");
    assert_eq!(published_json["state"], "Production");
}
