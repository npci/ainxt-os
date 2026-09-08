// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! r11_callback_to_use_roundtrip — the OAuth callback WRITE path and the connector USE path close
//! the loop over ONE vault.
//!
//! Round-11 Connectors gap (HIGH): "USE-path token resolution wired to the vault the OAuth callback
//! seals into." The two halves each had coverage in isolation — `gap_conn_03` proves the gateway
//! begin→callback SEALS a token, and `r7_connector_use_entrypoint` proves a *manually seeded* token
//! resolves→refreshes→dispatches. Nothing chained them: no test proved that the exact token the
//! `ConnectorGateway::complete_callback` write path seals is the exact token the
//! `ConnectorInvoker::invoke_in` USE path later resolves, on the design's `(tenant, jwt.sub,
//! connector)` key, over a SINGLE shared vault (as the daemon composes it).
//!
//! This test builds that end-to-end chain from the owned crates:
//!
//!   gateway.begin_authorization → complete_callback (seals CALLBACK-AT into the vault, tenant-scoped)
//!     → CoordinatorTokenSource over the SAME vault → ConnectorInvoker.invoke_in → the FRESH bearer
//!       on the connector wire is exactly the callback-sealed token.
//!
//! The gateway and the USE path hold two `TokenVault` handles over ONE shared store + the SAME codec
//! key — faithfully modelling the daemon's single durable vault reached by the callback HTTP handler
//! and by a worker running the turn. Everything is offline: `StubTransport` stands in for the IdP
//! token endpoint and the connector wire; the live Postgres store + live IdP are the infra_gated
//! seams these fakes model.
//!
//! Fail-before/pass-after: before this round nothing resolved a callback-SEALED token through the USE
//! entrypoint, so the "wired to the vault the callback seals into" contract was unproven. The
//! `before_callback_use_fails_closed` assertion pins the negative — the USE path finds NOTHING until
//! the callback seals — so the positive is meaningful, not vacuous.

use std::sync::Arc;

use ainxt_connector::{
    AllowAllPolicy, AuthKind, CapabilityConnectorAuthorizer, ConnectorDef, ConnectorRegistry,
    ConnectorRuntime, InMemoryConnectorAudit, MarkerEgressGuard,
};
use ainxt_connector_http::{
    ConnectorGateway, ConnectorInvoker, CoordinatorTokenSource, Graph, HttpRefreshExecutor,
    HttpResponse, StubTransport,
};
use ainxt_oauth::{InMemoryPendingAuthStore, OAuthProvider};
use ainxt_refresh::{InMemoryRefreshLock, RefreshCoordinator};
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

/// A `ConnectorRuntime` that admits (policy pass-through) with the graph connector registered.
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

/// A vault over a (cloned) shared store with a fixed codec key — two handles model the daemon's ONE
/// durable vault reached by both the callback handler and a turn worker.
fn vault_over(store: &InMemoryTokenStore) -> TokenVault {
    TokenVault::new(
        Box::new(AeadCodec::new(KeyRing::new(1, KEY))),
        Box::new(store.clone()),
    )
}

/// Build the USE-path invoker (coordinator-backed token source) over `use_vault`, with its own
/// connector-wire stub (200 OK) and an unused refresh executor.
fn use_invoker(use_vault: TokenVault) -> (Arc<ConnectorInvoker>, StubTransport) {
    // The refresh executor should NOT be hit — the callback-sealed token is fresh — but must exist.
    let refresh_stub = StubTransport::new();
    refresh_stub.push_response(HttpResponse::new(
        200,
        br#"{"access_token":"SHOULD-NOT-BE-USED","expires_in":3600,"token_type":"Bearer"}"#
            .to_vec(),
    ));
    let coordinator = RefreshCoordinator::new(
        "graph",
        provider(),
        use_vault,
        Box::new(InMemoryRefreshLock::new()),
        Box::new(HttpRefreshExecutor::new(Box::new(refresh_stub))),
    );
    let connector_stub = StubTransport::new();
    connector_stub.push_response(HttpResponse::new(
        200,
        br#"{"id":"me","displayName":"Alice"}"#.to_vec(),
    ));
    let invoker = Arc::new(ConnectorInvoker::new(
        runtime(),
        Box::new(connector_stub.clone()),
        Box::new(CoordinatorTokenSource::new(coordinator)),
    ));
    (invoker, connector_stub)
}

fn bearer_of(stub: &StubTransport) -> Option<String> {
    stub.sent().first().and_then(|r| {
        r.headers
            .iter()
            .find(|(k, _)| k == "Authorization")
            .map(|(_, v)| v.clone())
    })
}

/// End-to-end: the token sealed by the OAuth callback is the exact token the USE path resolves and
/// injects on the connector wire — on the design's (tenant, user, connector) key, over one vault.
#[test]
fn r11_callback_sealed_token_is_what_the_use_path_dispatches() {
    let store = InMemoryTokenStore::new();

    // --- fail-before: with nothing sealed yet, the USE path finds no token and fails closed. ---
    {
        let (invoker, wire) = use_invoker(vault_over(&store));
        let err = invoker
            .invoke_in(
                TENANT,
                &Principal::user(USER, &["connector.graph"]),
                NOW,
                DataClass::Confidential,
                Graph::new().get_me(),
            )
            .expect_err("USE path must fail closed before any token is sealed");
        assert!(
            err.to_string().contains("token error") || err.to_string().contains("no token"),
            "expected a token-resolution failure, got: {err}"
        );
        assert_eq!(
            wire.sent_count(),
            0,
            "fail-closed: nothing on the wire before the callback seals a token"
        );
    }

    // --- WRITE path: gateway begin → callback seals CALLBACK-AT into the shared vault. ---
    let idp_stub = StubTransport::new();
    idp_stub.push_response(HttpResponse::new(
        200,
        br#"{"access_token":"CALLBACK-AT","refresh_token":"RT-1","expires_in":3600,"scope":"User.Read","token_type":"Bearer"}"#.to_vec(),
    ));
    let gateway = ConnectorGateway::new(
        runtime(),
        vault_over(&store),
        Box::new(InMemoryPendingAuthStore::new()),
        Box::new(idp_stub),
        Box::new(InMemoryConnectorAudit::new()),
    )
    .with_provider("graph", provider());

    let principal = Principal::user(USER, &["connector.graph"]);
    let start = gateway
        .begin_authorization(TENANT, &principal, "graph", &["User.Read".into()], NOW)
        .expect("begin authorization");
    let done = gateway
        .complete_callback(&start.state, "auth-code-xyz", NOW + 5)
        .expect("callback exchange + seal");
    assert_eq!(done.connector, "graph");
    assert_eq!(done.granted_scopes, vec!["User.Read".to_string()]);

    // --- pass-after: the USE path resolves the callback-sealed token over the SAME vault. ---
    let (invoker, wire) = use_invoker(vault_over(&store));
    let outcome = invoker
        .invoke_in(
            TENANT,
            &principal,
            NOW + 10, // still far from the 1h expiry → no refresh
            DataClass::Confidential,
            Graph::new().get_me(),
        )
        .expect("USE path resolves the callback-sealed token");
    assert!(outcome.response.is_success());
    assert_eq!(wire.sent_count(), 1, "the connector call dispatched once");
    assert_eq!(
        bearer_of(&wire).as_deref(),
        Some("Bearer CALLBACK-AT"),
        "the USE path must inject exactly the token the OAuth callback sealed into the vault"
    );
}

/// Tenant isolation of the callback→USE wiring: a token sealed for TENANT is unreachable when the
/// USE path resolves under a different tenant — it fails closed with nothing on the wire.
#[test]
fn r11_callback_sealed_token_is_tenant_isolated_on_the_use_path() {
    let store = InMemoryTokenStore::new();
    let idp_stub = StubTransport::new();
    idp_stub.push_response(HttpResponse::new(
        200,
        br#"{"access_token":"CALLBACK-AT","refresh_token":"RT-1","expires_in":3600,"scope":"User.Read","token_type":"Bearer"}"#.to_vec(),
    ));
    let gateway = ConnectorGateway::new(
        runtime(),
        vault_over(&store),
        Box::new(InMemoryPendingAuthStore::new()),
        Box::new(idp_stub),
        Box::new(InMemoryConnectorAudit::new()),
    )
    .with_provider("graph", provider());
    let principal = Principal::user(USER, &["connector.graph"]);
    let start = gateway
        .begin_authorization(TENANT, &principal, "graph", &["User.Read".into()], NOW)
        .unwrap();
    gateway
        .complete_callback(&start.state, "code", NOW + 5)
        .unwrap();

    // The USE path resolving under a DIFFERENT tenant must not reach tenant-a's sealed token.
    let (invoker, wire) = use_invoker(vault_over(&store));
    let err = invoker
        .invoke_in(
            "tenant-b",
            &principal,
            NOW + 10,
            DataClass::Confidential,
            Graph::new().get_me(),
        )
        .expect_err("a different tenant must not resolve tenant-a's callback-sealed token");
    assert!(
        err.to_string().contains("token error") || err.to_string().contains("no token"),
        "cross-tenant resolution must fail as a token error, got: {err}"
    );
    assert_eq!(
        wire.sent_count(),
        0,
        "fail-closed across tenants: nothing on the wire"
    );
}
