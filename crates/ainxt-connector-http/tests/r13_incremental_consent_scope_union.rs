// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! r13_incremental_consent_scope_union — GAP-AUDIT connectors #5.
//!
//! `ConnectorGateway::step_up_consent_if_needed` deliberately begins a fresh authorize flow for only
//! the MISSING scopes (true incremental consent — the user re-prompts for the delta, not the whole
//! set). The IdP token response for that flow then legitimately echoes back only the delta scope
//! (`scope=Mail.Read`), not the full cumulative grant. `complete_callback` sealed whatever scope set
//! came back from THIS exchange directly into the vault via `save_in`, which **overwrites** any
//! existing record for `(tenant, user, connector)` — so a user who first granted `User.Read`, then
//! stepped up to `Mail.Read`, ended up with a vault entry that only remembered `Mail.Read`.
//! `missing_scopes` computed against that record would then treat `User.Read` as ungranted again,
//! even though the user never revoked it and the (still-valid, still-refreshable) token can serve it.
//!
//! This test drives exactly that two-step flow (initial grant → step-up) and asserts the vault's
//! metadata after the SECOND callback is the UNION of both grants, not just the second one.

use std::sync::Arc;

use ainxt_connector::{
    AllowAllPolicy, AuthKind, CapabilityConnectorAuthorizer, ConnectorDef, ConnectorRegistry,
    ConnectorRuntime, InMemoryConnectorAudit, MarkerEgressGuard,
};
use ainxt_connector_http::{ConnectorGateway, HttpResponse, StubTransport};
use ainxt_oauth::{missing_scopes, InMemoryPendingAuthStore, OAuthProvider};
use ainxt_token::{AeadCodec, InMemoryTokenStore, KeyRing, TokenVault};
use ainxt_types::{DataClass, Principal};

const NOW: u64 = 1_000_000;
const TENANT: &str = "tenant-a";
const USER: &str = "alice";
const KEY: [u8; 32] = [0x5a; 32];

fn provider() -> OAuthProvider {
    OAuthProvider {
        authorize_endpoint: "https://login.example.invalid/authorize".into(),
        token_endpoint: "https://login.example.invalid/token".into(),
        client_id: "client-1".into(),
        redirect_uri: "https://app.example.invalid/connectors/callback".into(),
        scopes: vec!["User.Read".into()],
    }
}

fn runtime() -> Arc<ConnectorRuntime> {
    let mut reg = ConnectorRegistry::new();
    reg.register(
        ConnectorDef::new("graph", "Microsoft Graph", AuthKind::OAuth2AuthCode)
            .with_max_egress_class(DataClass::Confidential),
    );
    Arc::new(ConnectorRuntime::new(
        reg,
        Box::new(AllowAllPolicy),
        Box::new(CapabilityConnectorAuthorizer),
        Box::new(MarkerEgressGuard),
        Box::new(InMemoryConnectorAudit::new()),
    ))
}

#[test]
fn r13_step_up_consent_unions_scopes_instead_of_overwriting() {
    let store = InMemoryTokenStore::new();
    // A second, independent vault HANDLE over the same (cloned, shared-internals) store — used only
    // to inspect metadata after each callback, exactly as `r11_callback_to_use_roundtrip.rs` shares
    // one durable vault between the callback handler and a turn worker.
    let inspect_vault = TokenVault::new(
        Box::new(AeadCodec::new(KeyRing::new(1, KEY))),
        Box::new(store.clone()),
    );
    let vault = TokenVault::new(
        Box::new(AeadCodec::new(KeyRing::new(1, KEY))),
        Box::new(store),
    );
    let idp = StubTransport::new();
    let gateway = ConnectorGateway::new(
        runtime(),
        vault,
        Box::new(InMemoryPendingAuthStore::new()),
        Box::new(idp.clone()),
        Box::new(InMemoryConnectorAudit::new()),
    )
    .with_provider("graph", provider());
    let principal = Principal::user(USER, &["connector.graph"]);

    // --- Step 1: initial grant of User.Read only. ---
    idp.push_response(HttpResponse::new(
        200,
        br#"{"access_token":"AT-1","refresh_token":"RT-1","expires_in":3600,"scope":"User.Read","token_type":"Bearer"}"#.to_vec(),
    ));
    let start1 = gateway
        .begin_authorization(TENANT, &principal, "graph", &["User.Read".into()], NOW)
        .expect("begin first authorization");
    let done1 = gateway
        .complete_callback(&start1.state, "code-1", NOW + 1)
        .expect("first callback");
    assert_eq!(done1.granted_scopes, vec!["User.Read".to_string()]);

    // --- Step 2: incremental (step-up) consent for the DELTA only — Mail.Read. The runtime
    // deliberately requests just the missing scope, and this stub IdP (like several real ones on an
    // incremental grant) echoes back only that delta, not the cumulative set. ---
    let required = vec!["User.Read".to_string(), "Mail.Read".to_string()];
    let step_up = gateway
        .step_up_consent_if_needed(TENANT, &principal, "graph", &required, NOW + 2)
        .expect("step-up check")
        .expect("Mail.Read is missing so a step-up flow must be started");

    idp.push_response(HttpResponse::new(
        200,
        br#"{"access_token":"AT-2","refresh_token":"RT-2","expires_in":3600,"scope":"Mail.Read","token_type":"Bearer"}"#.to_vec(),
    ));
    let done2 = gateway
        .complete_callback(&step_up.state, "code-2", NOW + 3)
        .expect("step-up callback");
    // The API-level "what did THIS exchange grant" answer is correctly just the delta.
    assert_eq!(done2.granted_scopes, vec!["Mail.Read".to_string()]);

    // --- The vault's cumulative record must be the UNION of both grants, not just the second. ---
    let meta = inspect_vault
        .metadata_in(TENANT, USER, "graph")
        .expect("read vault metadata")
        .expect("a token must be sealed");
    assert!(
        meta.scopes.contains(&"User.Read".to_string()),
        "the FIRST grant's scope must survive the step-up: {:?}",
        meta.scopes
    );
    assert!(
        meta.scopes.contains(&"Mail.Read".to_string()),
        "the step-up's newly-granted scope must be present: {:?}",
        meta.scopes
    );

    // And a fresh `missing_scopes` check against the union must find nothing missing anymore — the
    // regression this bug caused (User.Read wrongly re-appearing as "missing" after the step-up).
    assert!(
        missing_scopes(&meta.scopes, &required).is_empty(),
        "after the step-up both required scopes must be satisfied: missing={:?}",
        missing_scopes(&meta.scopes, &required)
    );
}
