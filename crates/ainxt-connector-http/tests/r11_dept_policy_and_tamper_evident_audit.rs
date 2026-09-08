// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! r11_dept_policy_and_tamper_evident_audit — org/dept allow-deny AND a tamper-evident audit chain
//! are active on the actual connector USE call-site (`ConnectorInvoker::invoke_in`).
//!
//! Round-11 Connectors gap (MEDIUM): "Org/dept allow-deny policy + tamper-evident audit active on the
//! served path." The primitives existed — `DeptRuleTable` (least-privilege org/dept policy) and
//! `HashChainedConnectorAudit` (SHA-256 hash-chain, gap AK) — but the only invoke-path coverage
//! (`dod_p2_matrix`) wired `InMemoryConnectorAudit`, which is NOT tamper-evident. So the design's
//! tamper-evident audit had never been proven active on the path a served connector call actually
//! takes. This test composes BOTH onto the real `ConnectorInvoker` and proves, on that single path:
//!
//!   1. a department the policy does not permit is refused at admission — BEFORE any bytes leave —
//!      and the refusal is recorded in the hash chain;
//!   2. a permitted department dispatches, and every admission/egress outcome is chained;
//!   3. the chain VERIFIES intact, and any silent mutation of a recorded outcome is DETECTED at the
//!      first altered link (tamper-evidence) — the regulator-grade property the design names.
//!
//! `invoke_in` is the exact entrypoint a served `ConnectorCapability` dispatches through (see
//! `r7_connector_use_entrypoint`), so proving enforcement here proves it on the served USE path; the
//! daemon composition root selects `DeptRuleTable` + `HashChainedConnectorAudit` as the production
//! `ConnectorPolicy`/`ConnectorAudit` behind `ConnectorRuntime::new`.
//!
//! Fail-before/pass-after: before this test, no invoke-path test bound the tamper-evident audit, so
//! the "tamper-evident audit active on the served path" half of the gap was unproven; the tamper
//! assertion fails against a non-chained sink and passes only because the chain binds each link to
//! the full prior history.

use std::sync::Arc;

use ainxt_connector::{
    AuthKind, CapabilityConnectorAuthorizer, ConnectorDef, ConnectorRegistry, ConnectorRuntime,
    DeptRuleTable, HashChainedConnectorAudit, MarkerEgressGuard,
};
use ainxt_connector_http::{
    ConnectorCallError, ConnectorInvoker, GitLab, HttpResponse, StaticTokenSource, StubTransport,
};
use ainxt_types::{DataClass, Principal};

/// A principal in `dept` authorized (OBO capability) for gitlab.
fn user_in_dept(user: &str, dept: &str) -> Principal {
    Principal::user(user, &["connector.gitlab"]).with_department(dept)
}

/// Build the invoker with a dept allow-list policy (`payments-eng` may use gitlab; default-deny) and
/// a shared tamper-evident hash-chained audit sink (returned so the test can inspect + verify it).
fn invoker_with(audit: HashChainedConnectorAudit, wire: StubTransport) -> Arc<ConnectorInvoker> {
    let mut reg = ConnectorRegistry::new();
    reg.register(
        ConnectorDef::new("gitlab", "GitLab", AuthKind::ApiToken)
            .with_max_egress_class(DataClass::Confidential),
    );
    let policy = DeptRuleTable::new().allow_dept("gitlab", "payments-eng"); // least-privilege default
    let runtime = Arc::new(ConnectorRuntime::new(
        reg,
        Box::new(policy),
        Box::new(CapabilityConnectorAuthorizer),
        Box::new(MarkerEgressGuard),
        Box::new(audit),
    ));
    Arc::new(ConnectorInvoker::new(
        runtime,
        Box::new(wire),
        Box::new(StaticTokenSource("glpat-static".into())),
    ))
}

/// A denied department is refused at admission before any network I/O; a permitted one dispatches;
/// every outcome is written to the tamper-evident chain, which verifies intact.
#[test]
fn r11_dept_policy_enforced_and_every_outcome_chained_on_use_path() {
    let audit = HashChainedConnectorAudit::new();
    let wire = StubTransport::new();
    wire.push_response(HttpResponse::new(200, br#"{"id":1}"#.to_vec()));
    let inv = invoker_with(audit.clone(), wire.clone());

    // 1. Disallowed department → admission denial, nothing on the wire.
    let denied = inv
        .invoke(
            &user_in_dept("mallory", "retail-ops"),
            0,
            DataClass::Internal,
            GitLab::new("https://gl").get_project("g/r"),
        )
        .expect_err("a department the policy does not permit must be refused");
    assert!(
        matches!(denied, ConnectorCallError::Admission(_)),
        "expected an admission (policy) denial, got {denied:?}"
    );
    assert_eq!(
        wire.sent_count(),
        0,
        "a policy-denied call must never reach the network"
    );

    // 2. Permitted department → dispatches.
    let ok = inv
        .invoke(
            &user_in_dept("alice", "payments-eng"),
            0,
            DataClass::Internal,
            GitLab::new("https://gl").get_project("g/r"),
        )
        .expect("permitted department dispatches");
    assert!(ok.response.is_success());
    assert_eq!(wire.sent_count(), 1);

    // 3. The tamper-evident chain recorded both flows and verifies intact.
    let snapshot = audit.snapshot();
    assert!(
        snapshot.len() >= 3,
        "expected chained links for the denial + the authorized admission + egress, got {}",
        snapshot.len()
    );
    assert!(audit.verify().is_ok(), "an untampered chain must verify");
    let outcomes: Vec<&str> = snapshot.iter().map(|e| e.event.outcome.as_str()).collect();
    assert!(
        outcomes.contains(&"policy-denied"),
        "the org/dept denial must be audited, got {outcomes:?}"
    );
    assert!(
        outcomes.contains(&"authorized"),
        "the permitted admission must be audited, got {outcomes:?}"
    );
    // Non-secret: the admission link records only that a resource was PRESENT (a bool), never the
    // "g/r" value itself — the audit trail cannot leak a sensitive id.
    assert!(
        snapshot
            .iter()
            .any(|e| e.event.outcome == "authorized" && e.event.resource_present),
        "the authorized admission over get_project must record resource_present=true (value never stored)"
    );
}

/// Tamper-evidence: silently mutating a recorded outcome breaks the hash chain at that link, and
/// `verify_chain` reports the first altered index. (A non-chained sink would accept the mutation
/// silently — this is exactly what the tamper-evident audit buys on the served path.)
#[test]
fn r11_tamper_evident_audit_detects_silent_mutation() {
    let audit = HashChainedConnectorAudit::new();
    let wire = StubTransport::new();
    wire.push_response(HttpResponse::new(200, br#"{"id":1}"#.to_vec()));
    let inv = invoker_with(audit.clone(), wire);

    // Produce a denial then a success so there are multiple links to tamper within.
    let _ = inv.invoke(
        &user_in_dept("mallory", "retail-ops"),
        0,
        DataClass::Internal,
        GitLab::new("https://gl").get_project("g/r"),
    );
    let _ = inv.invoke(
        &user_in_dept("alice", "payments-eng"),
        0,
        DataClass::Internal,
        GitLab::new("https://gl").get_project("g/r"),
    );

    let mut snapshot = audit.snapshot();
    assert!(audit.verify().is_ok(), "baseline chain verifies");
    assert!(snapshot.len() >= 2);

    // An auditor/attacker flips a recorded "policy-denied" into "authorized" to hide the refusal.
    let victim = snapshot
        .iter()
        .position(|e| e.event.outcome == "policy-denied")
        .expect("a policy-denied link exists");
    snapshot[victim].event.outcome = "authorized".into();

    match HashChainedConnectorAudit::verify_chain(&snapshot) {
        Err(bad) => assert_eq!(
            bad, victim,
            "tamper detection must point at the first altered link"
        ),
        Ok(()) => panic!("a mutated audit chain must NOT verify — tamper went undetected"),
    }
}
