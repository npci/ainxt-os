// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! r11_step_up_consent — incremental (step-up) consent is TRIGGERED when a capability needs a scope
//! the user has not yet granted.
//!
//! Round-11 Connectors gap (LOW): "Incremental (step-up) consent triggered when a capability needs an
//! unconsented scope." The OAuth engine had the pure helpers (`missing_scopes` / `step_up_consent`)
//! and `dod_p2_matrix` exercised them as a stand-alone computation, but nothing on the Connector
//! Runtime surface actually READ the user's stored grant and TRIGGERED a step-up flow. Without that,
//! a capability that needs a newly-added scope would fail opaquely at the provider mid-turn
//! (`403 insufficient_scope`). This test drives the new
//! [`ConnectorGateway::step_up_consent_if_needed`] entrypoint end-to-end:
//!
//!   1. when the stored grant already covers the required scopes → `Ok(None)` (proceed, no re-prompt);
//!   2. when a required scope is NOT in the stored grant → `Ok(Some(start))` whose authorize URL
//!      requests ONLY the missing scope (true incremental consent — not the whole set);
//!   3. a first-time user with NO stored token → every required scope is missing → a consent flow is
//!      begun; and after completing that flow the same check returns `Ok(None)`.
//!
//! Everything is offline: `StubTransport` stands in for the IdP token endpoint; the vault holds the
//! (encrypted) grant. Fail-before/pass-after: `step_up_consent_if_needed` did not exist before this
//! round, so there was no served entrypoint that turned a stored-grant scope gap into a consent flow.

use std::sync::Arc;

use ainxt_connector::{
    AllowAllPolicy, AuthKind, CapabilityConnectorAuthorizer, ConnectorDef, ConnectorRegistry,
    ConnectorRuntime, InMemoryConnectorAudit, MarkerEgressGuard,
};
use ainxt_connector_http::{ConnectorGateway, HttpResponse, StubTransport};
use ainxt_oauth::{InMemoryPendingAuthStore, OAuthProvider};
use ainxt_token::{AeadCodec, InMemoryTokenStore, KeyRing, TokenVault};
use ainxt_types::{DataClass, Principal};

const NOW: u64 = 1_000_000;
const TENANT: &str = "tenant-a";

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

/// A gateway whose IdP stub grants exactly `granted_scope` on a code exchange (used to seal an
/// initial grant), returned alongside the shared vault store so scope state is inspectable.
fn gateway(store: &InMemoryTokenStore, granted_scope: &str) -> ConnectorGateway {
    let idp = StubTransport::new();
    idp.push_response(HttpResponse::new(
        200,
        format!(
            r#"{{"access_token":"AT","refresh_token":"RT","expires_in":3600,"scope":"{granted_scope}","token_type":"Bearer"}}"#
        )
        .into_bytes(),
    ));
    ConnectorGateway::new(
        runtime(),
        TokenVault::new(
            Box::new(AeadCodec::new(KeyRing::new(1, [0x33; 32]))),
            Box::new(store.clone()),
        ),
        Box::new(InMemoryPendingAuthStore::new()),
        Box::new(idp),
        Box::new(InMemoryConnectorAudit::new()),
    )
    .with_provider("graph", provider())
}

/// Seal an initial grant for `user` covering `granted_scope` by driving a full begin→callback.
fn seed_grant(gw: &ConnectorGateway, user: &Principal, granted_scope: &str) {
    let start = gw
        .begin_authorization(TENANT, user, "graph", &[granted_scope.into()], NOW)
        .expect("begin");
    gw.complete_callback(&start.state, "code", NOW + 1)
        .expect("callback seals the grant");
}

/// A stored grant that already covers the required scopes → no re-prompt; a required scope outside
/// the grant → a step-up flow requesting ONLY the missing scope.
#[test]
fn r11_step_up_triggers_only_when_a_required_scope_is_unconsented() {
    let store = InMemoryTokenStore::new();
    let gw = gateway(&store, "User.Read");
    let alice = Principal::user("alice", &["connector.graph"]);
    seed_grant(&gw, &alice, "User.Read");

    // 1. Required ⊆ granted → Ok(None): the USE path may proceed with the stored token.
    let none = gw
        .step_up_consent_if_needed(TENANT, &alice, "graph", &["User.Read".into()], NOW + 2)
        .expect("consent check must not error");
    assert!(
        none.is_none(),
        "an already-granted scope must NOT trigger a re-prompt"
    );

    // 2. A capability needs Mail.Send, which was never granted → a step-up flow for JUST Mail.Send.
    let start = gw
        .step_up_consent_if_needed(
            TENANT,
            &alice,
            "graph",
            &["User.Read".into(), "Mail.Send".into()],
            NOW + 3,
        )
        .expect("consent check")
        .expect("a missing scope must trigger a step-up authorize flow");
    assert!(
        start.authorize_url.contains("Mail.Send"),
        "the step-up flow must request the missing scope, url={}",
        start.authorize_url
    );
    assert!(
        !start.authorize_url.contains("User.Read"),
        "incremental consent must request ONLY the delta, not the already-granted scope: {}",
        start.authorize_url
    );
    assert!(
        start.authorize_url.contains("code_challenge_method=S256"),
        "the step-up flow is a real PKCE authorize URL"
    );
    assert!(
        !start.state.is_empty(),
        "a fresh CSRF state is minted for the step-up flow"
    );
}

/// A first-time user (no stored token) needs consent for every required scope; after completing the
/// step-up flow the same check returns Ok(None).
#[test]
fn r11_step_up_for_first_time_user_then_satisfied_after_consent() {
    let store = InMemoryTokenStore::new();
    // IdP will grant User.Read when the step-up callback completes.
    let gw = gateway(&store, "User.Read");
    let bob = Principal::user("bob", &["connector.graph"]);

    // No token yet → nothing granted → the required scope is missing → a consent flow is begun.
    let start = gw
        .step_up_consent_if_needed(TENANT, &bob, "graph", &["User.Read".into()], NOW)
        .expect("consent check")
        .expect("a first-time user must be sent through consent");
    assert!(start.authorize_url.contains("User.Read"));

    // Complete the step-up flow (seals the grant).
    gw.complete_callback(&start.state, "code", NOW + 1)
        .expect("step-up callback seals the grant");

    // Now the same required scope is satisfied → no further prompt.
    let none = gw
        .step_up_consent_if_needed(TENANT, &bob, "graph", &["User.Read".into()], NOW + 2)
        .expect("consent check");
    assert!(
        none.is_none(),
        "after consenting, the same required scope must not re-prompt"
    );
}
