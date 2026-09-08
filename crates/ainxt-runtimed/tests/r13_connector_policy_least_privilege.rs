// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! r13_connector_policy_least_privilege — GAP-AUDIT connectors #6.
//!
//! `ainxt_connector::dept_policy_from_env` is a genuinely least-privilege, zero-required-config
//! `ConnectorPolicy`: an unset/empty env var default-DENIES every connector to every principal,
//! only an explicit `connector:dept` rule widens access. `mounts::build_connector_gateway` and
//! `mounts::build_connector_invoker` previously constructed their `ConnectorRuntime` with
//! `Box::new(AllowAllPolicy)` — permit-everyone, no org/dept scoping at all — despite this real,
//! zero-config-required least-privilege policy already existing in-tree.
//!
//! This test mirrors the EXACT composition pattern `mounts.rs` now uses (a `ConnectorRuntime` built
//! with `dept_policy_from_env(var)` as its policy seam) and proves, end-to-end through
//! `ConnectorRuntime::authorize_use`: (1) with no rule for the connector, admission is refused
//! specifically by POLICY (not "unknown connector" or authz) and (2) an explicit env-var rule
//! granting the principal's department admits it through policy (a later seam may still refuse for
//! an unrelated reason, but policy itself no longer blocks it).

use ainxt_connector::{
    dept_policy_from_env, CapabilityConnectorAuthorizer, ConnectorDef, ConnectorError,
    ConnectorRegistry, ConnectorRuntime, InMemoryConnectorAudit, MarkerEgressGuard,
};
use ainxt_types::{DataClass, Principal};

fn runtime_with(env_var: &str) -> ConnectorRuntime {
    let mut reg = ConnectorRegistry::new();
    reg.register(
        ConnectorDef::new(
            "graph",
            "Microsoft Graph",
            ainxt_connector::AuthKind::OAuth2AuthCode,
        )
        .with_max_egress_class(DataClass::Confidential),
    );
    ConnectorRuntime::new(
        reg,
        // Mirrors mounts.rs's own construction: `Box::new(dept_policy_from_env(...))`.
        Box::new(dept_policy_from_env(env_var)),
        Box::new(CapabilityConnectorAuthorizer),
        Box::new(MarkerEgressGuard),
        Box::new(InMemoryConnectorAudit::new()),
    )
}

#[test]
fn r13_no_env_rule_denies_by_policy_not_by_unknown_connector_or_authz() {
    // A genuinely unique env var name so no other test running in parallel can collide with it.
    let var = "AINXT_CONNECTOR_DEPT_RULES_TEST_R13_NO_RULE";
    std::env::remove_var(var);
    let rt = runtime_with(var);
    let principal = Principal::user("alice", &["connector.graph"]).with_department("payments-eng");

    let err = rt
        .authorize_use(&principal, &"graph".into(), "read", None)
        .expect_err("with no dept rule configured, admission must be refused");
    assert!(
        matches!(err, ConnectorError::PolicyDenied(_)),
        "the refusal must come from the POLICY seam (least-privilege default), not unknown-connector \
         or authz: {err:?}"
    );
}

#[test]
fn r13_explicit_env_rule_admits_the_matching_department_through_policy() {
    let var = "AINXT_CONNECTOR_DEPT_RULES_TEST_R13_WITH_RULE";
    std::env::set_var(var, "graph:payments-eng");
    let rt = runtime_with(var);
    let principal = Principal::user("alice", &["connector.graph"]).with_department("payments-eng");

    let result = rt.authorize_use(&principal, &"graph".into(), "read", None);
    assert!(
        result.is_ok(),
        "an explicit env-var rule granting the principal's department must admit through policy: \
         {result:?}"
    );
    std::env::remove_var(var);
}
