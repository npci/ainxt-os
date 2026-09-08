// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! r7_connector_use_entrypoint — the clean turn-time connector USE entrypoint, end-to-end.
//!
//! Round-7 gap: the pieces of the connector USE path each had unit coverage, but the *entrypoint the
//! tool registry actually dispatches* had never been wired together as one chain. The r5 capability
//! test dispatched a connector op through the ONE [`ToolRuntime`]/`CapabilityRegistry`, but with a
//! [`StaticTokenSource`] — it proved dispatch, NOT the "resolve token → expiry check → refresh → call"
//! contract the design names. Nothing exercised [`CoordinatorTokenSource`] (it had zero test callers),
//! so the real turn-time chain
//!
//!   durable encrypted vault  →  metadata expiry check  →  double-checked refresh under a
//!   Redis-contract distributed lock  →  fresh bearer injected  →  connector dispatch  →  the ONE
//!   tool registry
//!
//! was unproven. These tests build exactly that chain from the owned crates and dispatch a Microsoft
//! Graph call by name through `ToolRuntime`, proving:
//!   1. a stale stored token is resolved, refreshed EXACTLY ONCE under the distributed lock, and the
//!      FRESH bearer (not the stale one) is what reaches the wire — then re-sealed durably;
//!   2. a still-fresh token is resolved with ZERO network refresh (the cheap lock-free expiry check);
//!   3. tenant isolation holds on the USE entrypoint — a token sealed for tenant-a is unreachable when
//!      the capability binds tenant-b, and the call fails closed with no bytes on the wire.
//!
//! Everything is offline: an in-memory SQL backend stands in for the durable Postgres
//! `user_connector_tokens` table, a `RedisCommands` fake models the exact Redis lock command contract,
//! and `StubTransport` stands in for both the token endpoint and the connector wire. The live Postgres
//! store and the live Redis lock are the infra_gated seams these fakes model faithfully.
//!
//! Fail-before/pass-after: before this round `CoordinatorTokenSource` was never composed into a
//! `ConnectorCapability`, so the refresh-on-use contract of the dispatchable entrypoint was untested.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use ainxt_connector::{
    AllowAllPolicy, AuthKind, CapabilityConnectorAuthorizer, ConnectorDef, ConnectorRegistry,
    ConnectorRuntime, InMemoryConnectorAudit, MarkerEgressGuard,
};
use ainxt_connector_http::{
    ConnectorCapability, ConnectorInvoker, CoordinatorTokenSource, Graph, HttpRefreshExecutor,
    HttpResponse, StubTransport,
};
use ainxt_oauth::{OAuthProvider, TokenSet};
use ainxt_refresh::{
    DistributedRefreshLock, LockError, RedisCommands, RedisLockKv, RefreshCoordinator,
    SystemMonoClock,
};
use ainxt_token::{
    AeadCodec, InMemorySqlTokenBackend, KeyRing, SqlTokenBackend, SqlTokenStore, TokenVault,
};
use ainxt_tools::{DispatchResult, EffectClass, InMemoryLedger, ManualReconciler, ToolRuntime};
use ainxt_types::{DataClass, Principal};

const NOW: u64 = 1_000_000;
const TENANT: &str = "tenant-a";
const USER: &str = "alice";

// ---------------------------------------------------------------------------------------------
// A minimal offline `RedisCommands` fake: models INCR + SET NX PX + fenced compare-and-delete,
// so the distributed refresh lock runs its real Redis command contract with no live Redis. TTL is
// not exercised here (the lock is held only for the duration of one refresh), so a simple absent/held
// keyspace is sufficient and faithful.
// ---------------------------------------------------------------------------------------------
#[derive(Default)]
struct FakeRedis {
    strings: Mutex<BTreeMap<String, String>>,
    fence: AtomicU64,
}
impl RedisCommands for FakeRedis {
    fn incr(&self, _key: &str) -> Result<u64, LockError> {
        Ok(self.fence.fetch_add(1, Ordering::SeqCst) + 1)
    }
    fn set_nx_px(&self, key: &str, val: &str, _ttl_ms: u64) -> Result<bool, LockError> {
        let mut m = self
            .strings
            .lock()
            .map_err(|_| LockError("poisoned".into()))?;
        if m.contains_key(key) {
            return Ok(false);
        }
        m.insert(key.to_string(), val.to_string());
        Ok(true)
    }
    fn compare_del(&self, key: &str, val: &str) -> Result<bool, LockError> {
        let mut m = self
            .strings
            .lock()
            .map_err(|_| LockError("poisoned".into()))?;
        if m.get(key).map(String::as_str) == Some(val) {
            m.remove(key);
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

fn provider() -> OAuthProvider {
    OAuthProvider {
        authorize_endpoint: "https://login.example.invalid/authorize".into(),
        token_endpoint: "https://login.example.invalid/token".into(),
        client_id: "client-1".into(),
        redirect_uri: "https://app.example.invalid/connectors/callback".into(),
        scopes: vec!["User.Read".into()],
    }
}

/// A durable-modeled encrypted vault over the SQL token store (in-memory SQL backend stands in for
/// the Postgres `user_connector_tokens` table). Returns the vault plus the shared backend handle so a
/// test can inspect the persisted row.
fn durable_vault(backend: InMemorySqlTokenBackend) -> TokenVault {
    TokenVault::new(
        Box::new(AeadCodec::new(KeyRing::new(1, [9u8; 32]))),
        Box::new(SqlTokenStore::new(backend)),
    )
}

/// Seed an OAuth token for (TENANT, USER, "graph") with a given absolute expiry.
fn seed(vault: &TokenVault, access: &str, expires_at: Option<u64>) {
    let ts = TokenSet {
        access_token: access.into(),
        refresh_token: Some("REFRESH-1".into()),
        expires_in: expires_at.map(|e| e.saturating_sub(NOW)),
        scope: vec!["User.Read".into()],
        token_type: "Bearer".into(),
    };
    let blob = serde_json::to_vec(&ts).unwrap();
    vault
        .save_in(TENANT, USER, "graph", &blob, expires_at, &ts.scope)
        .unwrap();
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

/// Assemble the full turn-time USE entrypoint as a dispatchable capability, returning the capability,
/// the connector-wire stub, and the token-endpoint stub (to assert refresh calls) plus the SQL backend
/// (to assert the re-seal). `refresh_calls` counts token-endpoint hits.
struct Wired {
    cap: ConnectorCapability,
    connector_stub: StubTransport,
    refresh_calls: Arc<AtomicU32>,
    backend: InMemorySqlTokenBackend,
}

fn wire(bind_tenant: &str, seed_access: &str, seed_expires_at: Option<u64>) -> Wired {
    // Durable encrypted vault over the SQL (Postgres-modeled) store.
    let backend = InMemorySqlTokenBackend::new();
    let vault = durable_vault(backend.clone());
    seed(&vault, seed_access, seed_expires_at);

    // Refresh executor over its own stub token endpoint that mints a fresh access token; a call-count
    // handle proves exactly-once refresh.
    let token_stub = StubTransport::new();
    token_stub.push_response(HttpResponse::new(
        200,
        br#"{"access_token":"NEW-AT","refresh_token":"REFRESH-2","expires_in":3600,"scope":"User.Read","token_type":"Bearer"}"#.to_vec(),
    ));
    let refresh_calls = Arc::new(AtomicU32::new(0));
    let counted = CountingTransport {
        inner: token_stub,
        calls: refresh_calls.clone(),
    };
    let executor = HttpRefreshExecutor::new(Box::new(counted));

    // Double-checked refresh coordinator under a Redis-contract distributed lock.
    let lock = DistributedRefreshLock::new(
        Box::new(RedisLockKv::new(FakeRedis::default())),
        Box::new(SystemMonoClock::new()),
    );
    let coordinator = RefreshCoordinator::new(
        "graph",
        provider(),
        vault,
        Box::new(lock),
        Box::new(executor),
    );

    // The connector invoker over the coordinator-backed token source (the USE entrypoint).
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

    let graph = Graph::new();
    let cap = ConnectorCapability::new(
        "graph.get_me",
        invoker,
        Arc::new(|uid: &str| (uid == USER).then(|| Principal::user(USER, &["connector.graph"]))),
        bind_tenant,
        DataClass::Confidential,
        Arc::new(move |_args: &str| Ok(graph.get_me())),
    )
    .with_effect(EffectClass::Idempotent) // a read
    .with_clock(Arc::new(|| NOW));

    Wired {
        cap,
        connector_stub,
        refresh_calls,
        backend,
    }
}

/// Wraps a transport to count how many requests were sent through it.
struct CountingTransport {
    inner: StubTransport,
    calls: Arc<AtomicU32>,
}
impl ainxt_connector_http::HttpTransport for CountingTransport {
    fn send(
        &self,
        request: &ainxt_connector_http::HttpRequest,
    ) -> Result<ainxt_connector_http::HttpResponse, ainxt_connector_http::TransportError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.send(request)
    }
}

fn tool_runtime() -> ToolRuntime {
    ToolRuntime::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler))
}

fn bearer_of(stub: &StubTransport) -> Option<String> {
    stub.sent().first().and_then(|r| {
        r.headers
            .iter()
            .find(|(k, _)| k == "Authorization")
            .map(|(_, v)| v.clone())
    })
}

/// (1) A stale stored token is resolved, refreshed EXACTLY ONCE under the distributed lock, the FRESH
/// bearer reaches the wire, and the refreshed token is re-sealed durably — dispatched through the ONE
/// tool registry.
#[test]
fn r7_use_entrypoint_refreshes_stale_token_under_lock_and_dispatches_fresh() {
    let w = wire(TENANT, "OLD-AT", Some(NOW)); // due now
    let mut tr = tool_runtime();
    tr.register(Box::new(w.cap));

    match tr.dispatch_for(USER, "graph.get_me", "{}") {
        DispatchResult::Ok(body) => {
            assert!(
                body.contains("displayName"),
                "untrusted connector body surfaced: {body}"
            );
        }
        other => panic!("expected Ok, got {other:?}"),
    }

    // Exactly ONE refresh happened (the double-checked lock collapses to one token-endpoint call).
    assert_eq!(
        w.refresh_calls.load(Ordering::SeqCst),
        1,
        "a stale token must be refreshed exactly once"
    );
    // The FRESH bearer — not the stale OLD-AT — reached the connector wire.
    assert_eq!(
        w.connector_stub.sent_count(),
        1,
        "the connector call must dispatch once"
    );
    assert_eq!(
        bearer_of(&w.connector_stub).as_deref(),
        Some("Bearer NEW-AT"),
        "the resolved+refreshed token must be what is injected on the wire"
    );
    // The refreshed token was re-sealed durably (expiry advanced ~1h; ciphertext, never plaintext).
    let row = w.backend.fetch(TENANT, USER, "graph").unwrap().unwrap();
    assert_eq!(
        row.expires_at,
        Some(NOW + 3600),
        "refreshed expiry re-sealed durably"
    );
    assert!(
        !row.ciphertext.windows(6).any(|c| c == b"NEW-AT"),
        "the durable row must hold only ciphertext"
    );
}

/// (2) A still-fresh token is resolved with ZERO network refresh — the cheap lock-free expiry check —
/// and the ORIGINAL bearer reaches the wire.
#[test]
fn r7_use_entrypoint_fresh_token_skips_refresh() {
    let w = wire(TENANT, "FRESH-AT", Some(NOW + 10_000)); // far from expiry
    let mut tr = tool_runtime();
    tr.register(Box::new(w.cap));

    match tr.dispatch_for(USER, "graph.get_me", "{}") {
        DispatchResult::Ok(_) => {}
        other => panic!("expected Ok, got {other:?}"),
    }
    assert_eq!(
        w.refresh_calls.load(Ordering::SeqCst),
        0,
        "a fresh token must NOT hit the token endpoint"
    );
    assert_eq!(
        bearer_of(&w.connector_stub).as_deref(),
        Some("Bearer FRESH-AT"),
        "the stored fresh token must be injected without a refresh"
    );
}

/// (3) Tenant isolation holds on the USE entrypoint: a token sealed for tenant-a is unreachable when
/// the capability binds tenant-b — resolution fails closed (NoToken) and NOTHING reaches the wire.
#[test]
fn r7_use_entrypoint_tenant_isolation_fails_closed() {
    // Seed for tenant-a but bind the capability to tenant-b.
    let w = wire("tenant-b", "OLD-AT", Some(NOW));
    let mut tr = tool_runtime();
    tr.register(Box::new(w.cap));

    match tr.dispatch_for(USER, "graph.get_me", "{}") {
        DispatchResult::Failed(msg) => {
            assert!(
                msg.contains("token error") || msg.contains("no token"),
                "a cross-tenant resolution must fail as a token error, got: {msg}"
            );
        }
        other => panic!("expected Failed (token resolution), got {other:?}"),
    }
    assert_eq!(
        w.refresh_calls.load(Ordering::SeqCst),
        0,
        "no refresh for a missing token"
    );
    assert_eq!(
        w.connector_stub.sent_count(),
        0,
        "fail-closed: a tenant with no token must never reach the connector wire"
    );
}
