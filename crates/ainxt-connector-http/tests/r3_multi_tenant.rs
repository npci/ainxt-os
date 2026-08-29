// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R3 gap (Connectors, "diverged"): multi-tenant token resolution on the USE/refresh path, proven
//! end-to-end through the REAL connector call pipeline (`ConnectorInvoker`) with the real
//! `CoordinatorTokenSource` → `RefreshCoordinator` → `TokenVault` stack.
//!
//! The OAuth callback sealed the token tenant-scoped (`vault.save_in(&owner.tenant, ..)`); the USE
//! path (`invoke`) historically resolved the token unscoped (DEFAULT_TENANT), so in a multi-tenant
//! deployment the connector call could never find the token the callback wrote. `invoke_in` closes
//! that: the token is resolved on the design's `(tenant, jwt.sub, connector)` key. Admission, egress
//! DLP, the payment boundary, and audit seams still run on every call — this only fixes the key the
//! token is looked up under.

use std::sync::Arc;

use ainxt_connector::{
    AllowAllPolicy, AuthKind, CapabilityConnectorAuthorizer, ConnectorDef, ConnectorPolicy,
    ConnectorRegistry, ConnectorRuntime, InMemoryConnectorAudit, MarkerEgressGuard,
};
use ainxt_connector_http::{
    ConnectorCallError, ConnectorInvoker, CoordinatorTokenSource, Graph, HttpResponse,
    StubTransport,
};
use ainxt_oauth::{OAuthProvider, TokenSet};
use ainxt_refresh::{InMemoryRefreshLock, RefreshCoordinator};
use ainxt_token::{AeadCodec, InMemoryTokenStore, KeyRing, TokenVault};
use ainxt_types::{DataClass, Principal};

const NOW: u64 = 1_000_000;

fn provider() -> OAuthProvider {
    OAuthProvider {
        authorize_endpoint: "https://idp.example.invalid/authorize".into(),
        token_endpoint: "https://idp.example.invalid/token".into(),
        client_id: "client-1".into(),
        redirect_uri: "https://app.example.invalid/cb".into(),
        scopes: vec![],
    }
}

fn registry() -> ConnectorRegistry {
    let mut r = ConnectorRegistry::new();
    r.register(
        ConnectorDef::new("graph", "Graph", AuthKind::OAuth2AuthCode)
            .with_max_egress_class(DataClass::Confidential),
    );
    r
}

fn runtime(policy: Box<dyn ConnectorPolicy>) -> Arc<ConnectorRuntime> {
    Arc::new(ConnectorRuntime::new(
        registry(),
        policy,
        Box::new(CapabilityConnectorAuthorizer),
        Box::new(MarkerEgressGuard),
        Box::new(InMemoryConnectorAudit::new()),
    ))
}

/// Seal a token tenant-scoped, exactly as the OAuth callback write path does.
fn seal_tenant_scoped(v: &TokenVault, tenant: &str, user: &str, access: &str) {
    let ts = TokenSet {
        access_token: access.into(),
        refresh_token: Some("R".into()),
        expires_in: Some(10_000), // far from expiry → the USE path returns it without a refresh
        scope: vec!["api".into()],
        token_type: "Bearer".into(),
    };
    let blob = serde_json::to_vec(&ts).unwrap();
    v.save_in(tenant, user, "graph", &blob, Some(NOW + 10_000), &ts.scope)
        .unwrap();
}

/// End-to-end: a connector call resolves the access token on the `(tenant, user, connector)` key.
/// The token the callback sealed for tenant-a is injected as the Bearer for a tenant-a call, is NOT
/// reachable for a tenant-b call, and is NOT reachable via the unscoped (DEFAULT_TENANT) `invoke`.
#[test]
fn r3_multi_tenant_token_use_path() {
    // The vault holds ONLY a tenant-a-scoped token (as the callback would have written it).
    let v = TokenVault::new(
        Box::new(AeadCodec::new(KeyRing::new(1, [7u8; 32]))),
        Box::new(InMemoryTokenStore::new()),
    );
    seal_tenant_scoped(&v, "tenant-a", "u", "TENANT-A-ACCESS");

    let coord = RefreshCoordinator::new(
        "graph",
        provider(),
        v,
        Box::new(InMemoryRefreshLock::new()),
        // No network stub is needed for token resolution: the token is not due, so the coordinator
        // returns the stored access token without calling the token endpoint.
        Box::new(NoRefreshExecutor),
    );

    let stub = StubTransport::new();
    stub.push_response(HttpResponse::new(200, br#"{"id":1}"#.to_vec()));
    let inv = ConnectorInvoker::new(
        runtime(Box::new(AllowAllPolicy)),
        Box::new(stub.clone()),
        Box::new(CoordinatorTokenSource::new(coord)),
    );
    let p = Principal::user("u", &["connector.graph"]);

    // 1. Tenant-a USE path: the call succeeds and the tenant-a token is the injected Bearer.
    let out = inv
        .invoke_in(
            "tenant-a",
            &p,
            NOW,
            DataClass::Internal,
            Graph::new().get_me(),
        )
        .expect("tenant-a call must succeed");
    assert!(out.response.is_success());
    let sent = stub.sent();
    assert_eq!(sent.len(), 1);
    assert!(
        sent[0]
            .headers
            .iter()
            .any(|(k, v)| k == "Authorization" && v == "Bearer TENANT-A-ACCESS"),
        "the tenant-a-scoped token must be the injected Bearer, got {:?}",
        sent[0].headers
    );

    // 2. A different tenant reusing the same (user, connector) resolves NO token → fail-closed at
    //    the token step, before any bytes leave (no extra request is sent).
    let err = inv
        .invoke_in(
            "tenant-b",
            &p,
            NOW,
            DataClass::Internal,
            Graph::new().get_me(),
        )
        .expect_err("tenant-b has no token for this (user, connector)");
    assert!(matches!(err, ConnectorCallError::Token(_)), "got {err:?}");

    // 3. The legacy unscoped invoke (DEFAULT_TENANT) — the OLD divergent behavior — also resolves
    //    nothing, since the write path sealed under tenant-a. This is the gap being closed.
    let err = inv
        .invoke(&p, NOW, DataClass::Internal, Graph::new().get_me())
        .expect_err("DEFAULT_TENANT resolution must not see the tenant-a token");
    assert!(matches!(err, ConnectorCallError::Token(_)), "got {err:?}");

    // Only the single successful tenant-a dispatch ever hit the network.
    assert_eq!(stub.sent_count(), 1, "token failures must never dispatch");
}

/// A refresh executor that must never be called in this test (the token is not due).
struct NoRefreshExecutor;
impl ainxt_refresh::RefreshExecutor for NoRefreshExecutor {
    fn execute(&self, _r: &ainxt_oauth::TokenRequest) -> Result<TokenSet, String> {
        Err("refresh must not be called for a non-due token".into())
    }
}
