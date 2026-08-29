// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! OBO three-layer authz (ADR-003 §1.6, design doc §1.6): a declared capability grant (layer 1)
//! is necessary but never sufficient — issued connector scope (layer 2) and resource-clearance
//! ABAC (layer 3) are INDEPENDENT gates that must ALSO pass. Regression for the collapse where
//! `Authorizer::authorize_tool`'s default implementation only ever evaluated layer 1, so a broad
//! `tool.*` grant silently satisfied the whole OBO contract on its own.

use ainxt_runtime::authz::{Authorizer, Decision};
use ainxt_types::{DataClass, Principal};

/// An authorizer that grants `connector.postgres.query` broadly at layer 1, but requires a
/// specific issued connector scope (layer 2) and classifies two resources for ABAC (layer 3).
struct ThreeLayerAuthorizer;

impl Authorizer for ThreeLayerAuthorizer {
    fn authorize(&self, principal: &Principal, capability: &str) -> Decision {
        if capability == "tool.connector.postgres.query" || principal.has_cap(capability) {
            Decision::Allow
        } else {
            Decision::Deny(format!("no grant for {capability}"))
        }
    }

    fn required_connector_scope(&self, tool: &str) -> Option<&str> {
        if tool == "connector.postgres.query" {
            Some("postgres:read")
        } else {
            None
        }
    }

    fn resource_data_class(&self, _tool: &str, resource: &str) -> Option<DataClass> {
        match resource {
            "ledger_accounts" => Some(DataClass::RegulatedPayment),
            "settlement_batches" => Some(DataClass::Confidential),
            _ => None,
        }
    }
}

#[test]
fn layer1_grant_alone_is_not_sufficient_without_connector_scope() {
    let az = ThreeLayerAuthorizer;
    // Layer 1 always passes for this tool (see `authorize` above), but the principal's own
    // issued credential (`connector_scopes`) carries no postgres scope at all.
    let p = Principal::user("u", &[]).with_clearance(DataClass::Pii);
    let d = az.authorize_tool(&p, "connector.postgres.query", Some("settlement_batches"));
    assert!(
        matches!(d, Decision::Deny(_)),
        "a capability grant must not substitute for a connector scope the user's own \
         credential doesn't cover: {d:?}"
    );
}

#[test]
fn layer2_scope_present_but_layer3_clearance_insufficient_still_denies() {
    let az = ThreeLayerAuthorizer;
    let p = Principal::user("u", &[])
        .with_clearance(DataClass::Internal)
        .with_connector_scopes(&["postgres:read"]);
    // `ledger_accounts` is classified RegulatedPayment, above the principal's Internal clearance.
    let d = az.authorize_tool(&p, "connector.postgres.query", Some("ledger_accounts"));
    assert!(
        matches!(d, Decision::Deny(_)),
        "clearance below the resource's data-class must deny even with grant + scope satisfied: {d:?}"
    );
}

#[test]
fn all_three_layers_passing_allows() {
    let az = ThreeLayerAuthorizer;
    let p = Principal::user("u", &[])
        .with_clearance(DataClass::Confidential)
        .with_connector_scopes(&["postgres:read"]);
    let d = az.authorize_tool(&p, "connector.postgres.query", Some("settlement_batches"));
    assert_eq!(d, Decision::Allow);
}

#[test]
fn wrong_connector_scope_literal_is_rejected_not_just_presence_of_any_scope() {
    let az = ThreeLayerAuthorizer;
    let p = Principal::user("u", &[])
        .with_clearance(DataClass::Pii)
        .with_connector_scopes(&["postgres:write"]); // wrong scope, not the required read scope
    let d = az.authorize_tool(&p, "connector.postgres.query", Some("settlement_batches"));
    assert!(matches!(d, Decision::Deny(_)));
}

#[test]
fn authorizers_that_dont_override_new_layers_are_unaffected_backcompat() {
    // A plain, pre-existing authorizer that only ever implemented `authorize` (layer 1) keeps
    // behaving exactly as before -- the new layers default to "no opinion" so nothing regresses
    // for authorizers that never modeled connector scopes or resource ABAC.
    struct Layer1Only;
    impl Authorizer for Layer1Only {
        fn authorize(&self, principal: &Principal, capability: &str) -> Decision {
            if principal.has_cap(capability) {
                Decision::Allow
            } else {
                Decision::Deny("no grant".into())
            }
        }
    }
    let az = Layer1Only;
    let p = Principal::user("u", &["tool.transfer"]);
    assert_eq!(
        az.authorize_tool(&p, "transfer", Some("acct-1")),
        Decision::Allow
    );
}
