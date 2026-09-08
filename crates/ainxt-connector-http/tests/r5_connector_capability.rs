// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! r5_connector_capability — the ConnectorInvoker call pipeline, exposed as a first-class capability
//! the ONE tool registry (`ainxt_tools::CapabilityRegistry`) dispatches.
//!
//! Round-5 gap: `ConnectorInvoker` (admission → egress DLP → payment boundary → token → dispatch) was
//! fully implemented but reachable ONLY from tests — no capability/surface dispatched it live. These
//! tests drive a connector call THROUGH the real `ToolRuntime`/`CapabilityRegistry` via the new
//! [`ConnectorCapability`] adapter, proving:
//!   1. a connector op dispatches by name through the registry, end-to-end (token injected → wire);
//!   2. a side-effecting connector write is exactly-once through the shared ledger (lost-ack retry is
//!      deduped, never double-executed — ADR-013);
//!   3. every safety seam still runs — an admission denial fails closed with no bytes on the wire.
//!
//! Fail-before/pass-after: before this round `ConnectorCapability` did not exist, so a connector call
//! could not be registered as a `Box<dyn Tool>` at all; this file would not compile.

use std::sync::Arc;

use ainxt_connector::{
    AllowAllPolicy, AuthKind, CapabilityConnectorAuthorizer, ConnectorDef, ConnectorRegistry,
    ConnectorRuntime, InMemoryConnectorAudit, MarkerEgressGuard,
};
use ainxt_connector_http::{
    ConnectorCapability, ConnectorInvoker, GitLab, HttpResponse, StaticTokenSource, StubTransport,
};
use ainxt_tools::{DispatchResult, EffectClass, InMemoryLedger, ManualReconciler, ToolRuntime};
use ainxt_types::{DataClass, Principal};

const NOW: u64 = 1_000_000;

fn runtime() -> Arc<ConnectorRuntime> {
    let mut reg = ConnectorRegistry::new();
    reg.register(
        ConnectorDef::new("gitlab", "GitLab", AuthKind::ApiToken)
            .with_max_egress_class(DataClass::Internal),
    );
    Arc::new(ConnectorRuntime::new(
        reg,
        Box::new(AllowAllPolicy),
        Box::new(CapabilityConnectorAuthorizer),
        Box::new(MarkerEgressGuard),
        Box::new(InMemoryConnectorAudit::new()),
    ))
}

fn invoker(rt: Arc<ConnectorRuntime>, stub: StubTransport) -> Arc<ConnectorInvoker> {
    Arc::new(ConnectorInvoker::new(
        rt,
        Box::new(stub),
        Box::new(StaticTokenSource("AT-TEST".into())),
    ))
}

fn tool_runtime() -> ToolRuntime {
    ToolRuntime::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler))
}

/// A read connector op registered as a capability dispatches through the registry end-to-end: the
/// pipeline admits it, injects the token, hits the (stub) wire, and the untrusted body comes back.
#[test]
fn r5_connector_capability_dispatches_through_registry() {
    let stub = StubTransport::new();
    stub.push_response(HttpResponse::new(
        200,
        br#"{"id":42,"name":"repo"}"#.to_vec(),
    ));
    let inv = invoker(runtime(), stub.clone());

    let gl = GitLab::new("https://gl.example.invalid");
    let cap = ConnectorCapability::new(
        "gitlab.get_project",
        inv,
        Arc::new(|uid: &str| (uid == "u1").then(|| Principal::user("u1", &["connector.gitlab"]))),
        "tenant-a",
        DataClass::Internal,
        Arc::new(move |args: &str| {
            let v: serde_json::Value = serde_json::from_str(args).map_err(|e| e.to_string())?;
            let project = v
                .get("project")
                .and_then(|p| p.as_str())
                .ok_or("missing 'project'")?;
            Ok(gl.get_project(project))
        }),
    )
    // A read is idempotent — no exactly-once ledger record required.
    .with_effect(EffectClass::Idempotent)
    .with_clock(Arc::new(|| NOW));

    let mut tr = tool_runtime();
    tr.register(Box::new(cap));

    match tr.dispatch_for("u1", "gitlab.get_project", r#"{"project":"grp/repo"}"#) {
        DispatchResult::Ok(body) => {
            assert!(
                body.contains("\"id\":42"),
                "untrusted connector body surfaced: {body}"
            );
        }
        other => panic!("expected Ok, got {other:?}"),
    }

    // The pipeline actually reached the wire with the bearer token injected AFTER egress control.
    let sent = stub.sent();
    assert_eq!(
        sent.len(),
        1,
        "exactly one request should have been dispatched"
    );
    assert!(
        sent[0]
            .headers
            .iter()
            .any(|(k, v)| k == "Authorization" && v == "Bearer AT-TEST"),
        "the invoker must inject the resolved bearer token"
    );
    assert!(
        sent[0].url.contains("/api/v4/projects/"),
        "adapter built the GitLab URL"
    );
}

/// A side-effecting connector write is exactly-once through the shared ledger: a retry with the same
/// semantic args is DEDUPED (the stored result is returned), never sent to the wire twice.
#[test]
fn r5_connector_capability_write_is_exactly_once() {
    let stub = StubTransport::new();
    stub.push_response(HttpResponse::new(201, br#"{"note_id":7}"#.to_vec()));
    // If the dedup failed and a second request were sent, the stub would fall back to 200-empty; we
    // assert on the sent-count below, which is the unambiguous signal.
    let inv = invoker(runtime(), stub.clone());

    let gl = GitLab::new("https://gl.example.invalid");
    let cap = ConnectorCapability::new(
        "gitlab.post_mr_note",
        inv,
        Arc::new(|uid: &str| (uid == "u1").then(|| Principal::user("u1", &["connector.gitlab"]))),
        "tenant-a",
        DataClass::Internal,
        Arc::new(move |args: &str| {
            let v: serde_json::Value = serde_json::from_str(args).map_err(|e| e.to_string())?;
            let project = v
                .get("project")
                .and_then(|p| p.as_str())
                .ok_or("missing 'project'")?;
            let mr = v.get("mr").and_then(|m| m.as_u64()).ok_or("missing 'mr'")?;
            let body = v
                .get("body")
                .and_then(|b| b.as_str())
                .ok_or("missing 'body'")?;
            Ok(gl.post_mr_note(project, mr, body))
        }),
    )
    // Default effect is SideEffecting → the ledger enforces exactly-once.
    .with_clock(Arc::new(|| NOW));

    let mut tr = tool_runtime();
    tr.register(Box::new(cap));

    let args = r#"{"project":"grp/repo","mr":3,"body":"LGTM"}"#;
    match tr.dispatch_for("u1", "gitlab.post_mr_note", args) {
        DispatchResult::Ok(body) => assert!(body.contains("note_id")),
        other => panic!("first write should execute, got {other:?}"),
    }
    // Same semantic args again — a lost-ack retry must be deduped, not double-posted.
    match tr.dispatch_for("u1", "gitlab.post_mr_note", args) {
        DispatchResult::Deduped(body) => assert!(body.contains("note_id")),
        other => panic!("retry should be deduped, got {other:?}"),
    }
    assert_eq!(
        stub.sent_count(),
        1,
        "exactly-once: the write must reach the wire only once across the retry"
    );
}

/// Every safety seam still runs on the registry path: a principal lacking the connector capability is
/// refused at admission — the call fails closed and NOTHING reaches the network.
#[test]
fn r5_connector_capability_admission_denial_fails_closed() {
    let stub = StubTransport::new();
    let inv = invoker(runtime(), stub.clone());

    let gl = GitLab::new("https://gl.example.invalid");
    let cap = ConnectorCapability::new(
        "gitlab.get_project",
        inv,
        // No `connector.gitlab` capability → admission must deny.
        Arc::new(|uid: &str| {
            (uid == "intruder").then(|| Principal::user("intruder", &["connector.jira"]))
        }),
        "tenant-a",
        DataClass::Internal,
        Arc::new(move |args: &str| {
            let v: serde_json::Value = serde_json::from_str(args).map_err(|e| e.to_string())?;
            let project = v
                .get("project")
                .and_then(|p| p.as_str())
                .ok_or("missing 'project'")?;
            Ok(gl.get_project(project))
        }),
    )
    .with_effect(EffectClass::Idempotent)
    .with_clock(Arc::new(|| NOW));

    let mut tr = tool_runtime();
    tr.register(Box::new(cap));

    match tr.dispatch_for(
        "intruder",
        "gitlab.get_project",
        r#"{"project":"grp/repo"}"#,
    ) {
        DispatchResult::Failed(msg) => {
            assert!(
                msg.contains("admission denied"),
                "denial must be an admission refusal, got: {msg}"
            );
        }
        other => panic!("expected Failed (admission), got {other:?}"),
    }
    assert_eq!(stub.sent_count(), 0, "fail-closed: no bytes on the wire");
}
