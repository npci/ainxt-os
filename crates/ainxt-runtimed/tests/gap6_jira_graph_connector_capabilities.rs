// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX connector-http item 1 — "`Jira`/`Graph` adapters built but never instantiated": the module
//! doc of `ainxt_connector_http` promises three concrete adapters ("GitLab, Jira, Graph"); only
//! `GitLab` was ever imported/instantiated by `ainxt-runtimed::mounts::register_connector_capability`.
//! `Jira`/`Graph` and their `get_issue`/`add_comment`/`get_me`/`list_messages`/`send_mail` methods had
//! zero references outside `ainxt-connector-http`'s own `mod tests`.
//!
//! These tests mirror the existing GitLab connector proving tests exactly (same two-test structure as
//! `gap5_connector_capability_served.rs` + `gap5_connector_shared_refresh_vault.rs`):
//!
//!   1. `gap6_jira_and_graph_capabilities_registered_on_real_composition_root_and_fail_closed_for_real`
//!      — drives the REAL composition-root function every served surface calls
//!      (`build_unified_capability_registry_shared`, exactly like `gap5_connector_capability_served.rs`
//!      does for `gitlab.get_project`) and proves all five Jira/Graph capabilities are registered,
//!      declare `Provenance::Connector`, and dispatch through the real admission→egress→token→dispatch
//!      pipeline, failing CLOSED on the air-gapped default (never a fabricated success, never a
//!      generic "unknown capability" error).
//!   2. `gap6_jira_oauth_callback_to_api_call_is_a_real_round_trip` — a genuinely real OAuth-callback-
//!      to-API-call round trip: a `ConnectorGateway` runs a full authorization-code + PKCE flow against
//!      a `StubTransport`-served Atlassian-shaped token endpoint, seals the minted token into a
//!      `TokenVault`, and a `ConnectorCapability`/`ConnectorInvoker` sharing that EXACT
//!      `(token_key, backend)` pair (reconstructing the same wiring
//!      `mounts::register_jira_capability`/`build_scoped_connector_invoker` build internally — the
//!      same reconstruction technique `gap5_connector_shared_refresh_vault.rs` uses for GitLab, since
//!      the real composition root's own vault is intentionally private to each registration call and
//!      not otherwise reachable from a test) resolves that SAME sealed token and dispatches a real
//!      `jira.get_issue` call, proving the access token minted by the callback is the EXACT bearer
//!      token that reaches the wire.

use ainxt_connector::{
    AuthKind, CapabilityConnectorAuthorizer, ConnectorDef, ConnectorRegistry, ConnectorRuntime,
    HashChainedConnectorAudit, InMemoryConnectorAudit, MarkerEgressGuard,
};
use ainxt_connector_http::{
    ConnectorCapability, ConnectorGateway, ConnectorInvoker, CoordinatorTokenSource,
    HttpRefreshExecutor, HttpResponse, Jira, StubTransport,
};
use ainxt_injection::Provenance;
use ainxt_oauth::{InMemoryPendingAuthStore, OAuthProvider};
use ainxt_refresh::RefreshCoordinator;
use ainxt_runtimed::build_unified_capability_registry_shared;
use ainxt_runtimed::mounts::OfflineTransport;
use ainxt_token::{AeadCodec, InMemorySqlTokenBackend, KeyRing, DEFAULT_TENANT};
use ainxt_tools::{DispatchResult, EffectClass, InMemoryLedger, ManualReconciler, ToolRuntime};
use ainxt_types::{DataClass, Principal};
use std::sync::Arc;

// =====================================================================================
// 1. The real composition root registers real, dispatchable Jira + Graph capabilities.
// =====================================================================================

#[test]
fn gap6_jira_and_graph_capabilities_registered_on_real_composition_root_and_fail_closed_for_real() {
    let mut report = Vec::new();
    // The EXACT function `build_engine_ext` / `build_chat_engine_with_authz` call — i.e. every surface
    // `assemble_selected`/`main.rs` can produce — to build the served tool registry. Not a copy.
    let (registry, _ledger, _reconciler) = build_unified_capability_registry_shared(&mut report);

    let expected = [
        "jira.get_issue",
        "jira.add_comment",
        "graph.get_me",
        "graph.list_messages",
        "graph.send_mail",
    ];
    for name in expected {
        assert!(
            report
                .iter()
                .any(|r| r.contains(name) && r.contains("REGISTERED")),
            "the boot report must announce '{name}' registration on the real composition root: \
             {report:?}"
        );
        assert_eq!(
            registry.provenance_of(name),
            Some(Provenance::Connector),
            "'{name}' must declare Provenance::Connector"
        );
    }
    // GitLab's pre-existing capability is unaffected (additive, not a replacement).
    assert_eq!(
        registry.provenance_of("gitlab.get_project"),
        Some(Provenance::Connector)
    );
    // A non-connector native capability keeps the pre-existing default provenance.
    assert_eq!(
        registry.provenance_of("query_ledger"),
        Some(Provenance::ToolResult)
    );

    // THE PROVING DISPATCH for each: no hand-rolled ToolRuntime/ConnectorCapability — dispatches
    // through the IDENTICAL registry `build_engine_ext`/`build_chat_engine_with_authz` install on the
    // served Engine via `with_shared_tools`. Before this fix, Jira/Graph had zero production callers;
    // this reaches the real admission -> egress-DLP -> payment-tripwire -> token -> dispatch pipeline
    // for real and fails CLOSED (air-gapped default: empty `ConnectorRegistry` + `OfflineTransport`).
    let cases: &[(&str, &str, &str)] = &[
        ("jira.get_issue", r#"{"key":"ABC-123"}"#, "jira"),
        (
            "jira.add_comment",
            r#"{"key":"ABC-123","body":"hi"}"#,
            "jira",
        ),
        ("graph.get_me", "{}", "graph"),
        ("graph.list_messages", r#"{"top":5}"#, "graph"),
        (
            "graph.send_mail",
            r#"{"to":"a@b.com","subject":"s","body":"b"}"#,
            "graph",
        ),
    ];
    for (name, args, connector_hint) in cases {
        match registry.dispatch_for("alice", name, args) {
            DispatchResult::Failed(msg) => {
                let lower = msg.to_lowercase();
                assert!(
                    lower.contains("connector") || lower.contains(connector_hint),
                    "'{name}' must fail CLOSED with an honest connector-pipeline error naming the \
                     connector (admission/egress/token/transport) — not a fabricated success or an \
                     unrelated 'unknown capability' error. Got: {msg}"
                );
            }
            other => panic!(
                "expected the air-gapped default's ConnectorInvoker to fail closed for '{name}' (no \
                 ConnectorDef registered / OfflineTransport), got: {other:?}"
            ),
        }
    }
}

// =====================================================================================
// 2. A real OAuth-callback-to-API-call round trip for Jira.
// =====================================================================================

/// Reconstructs the EXACT wiring shape `mounts::register_jira_capability`/
/// `mounts::build_scoped_connector_invoker` build internally (own `ConnectorRuntime`, own
/// `CoordinatorTokenSource` over `RefreshCoordinator::served_default("jira", ..)`) over a
/// CALLER-SUPPLIED `(token_key, backend)` pair — the same reconstruction technique
/// `gap5_connector_shared_refresh_vault.rs` uses for GitLab, needed because the real composition
/// root's own vault is intentionally private to each `register_*_capability` call (never exposed to a
/// caller) — exactly like GitLab's own `register_connector_capability`.
fn jira_invoker_over(
    token_key: [u8; 32],
    backend: InMemorySqlTokenBackend,
    stub: StubTransport,
) -> Arc<ConnectorInvoker> {
    let registry = {
        let mut r = ConnectorRegistry::new();
        r.register(
            ConnectorDef::new("jira", "Jira", AuthKind::OAuth2AuthCode)
                .with_max_egress_class(DataClass::Internal),
        );
        r
    };
    let connector_runtime = Arc::new(ConnectorRuntime::new(
        registry,
        Box::new(ainxt_connector::AllowAllPolicy),
        Box::new(CapabilityConnectorAuthorizer),
        Box::new(MarkerEgressGuard),
        Box::new(InMemoryConnectorAudit::new()),
    ));
    let vault = ainxt_server::sql_token_vault(
        Box::new(AeadCodec::new(KeyRing::new(1, token_key))),
        backend,
    );
    let executor: Box<dyn ainxt_refresh::RefreshExecutor> =
        Box::new(HttpRefreshExecutor::new(Box::new(OfflineTransport)));
    let coordinator =
        RefreshCoordinator::served_default("jira", jira_oauth_provider(), vault, executor);
    let token_source: Box<dyn ainxt_connector_http::TokenSource> =
        Box::new(CoordinatorTokenSource::new(coordinator));
    Arc::new(ConnectorInvoker::new(
        connector_runtime,
        Box::new(stub),
        token_source,
    ))
}

fn jira_oauth_provider() -> OAuthProvider {
    OAuthProvider::atlassian(
        "jira-client-1",
        "https://app.example.invalid/connectors/callback",
        &["read:jira-work", "write:jira-work", "offline_access"],
    )
}

#[test]
fn gap6_jira_oauth_callback_to_api_call_is_a_real_round_trip() {
    // ---- Shared vault backend: the OAuth-callback SEAL path and the USE-path resolve share ONE
    // ---- logical vault, exactly like `build_connector_gateway`/`build_scoped_connector_invoker` do
    // ---- in the real composition root.
    let token_key = [42u8; 32];
    let backend = InMemorySqlTokenBackend::new();

    // ---- 1. A REAL ConnectorGateway drives the OAuth authorization-code + PKCE flow.
    let gateway_registry = {
        let mut r = ConnectorRegistry::new();
        r.register(ConnectorDef::new("jira", "Jira", AuthKind::OAuth2AuthCode));
        r
    };
    let gateway_runtime = Arc::new(ConnectorRuntime::new(
        gateway_registry,
        Box::new(ainxt_connector::AllowAllPolicy),
        Box::new(CapabilityConnectorAuthorizer),
        Box::new(MarkerEgressGuard),
        Box::new(HashChainedConnectorAudit::new()),
    ));
    let gateway_vault = ainxt_server::sql_token_vault(
        Box::new(AeadCodec::new(KeyRing::new(1, token_key))),
        backend.clone(),
    );
    let oauth_stub = StubTransport::new();
    let gateway = ConnectorGateway::new(
        gateway_runtime,
        gateway_vault,
        Box::new(InMemoryPendingAuthStore::new()),
        Box::new(oauth_stub.clone()),
        Box::new(HashChainedConnectorAudit::new()),
    )
    .with_provider("jira", jira_oauth_provider());

    let alice = Principal::user("alice", &["connector.jira"]);

    // begin: a real authorize URL + CSRF state/PKCE is minted and stashed.
    let start = gateway
        .begin_authorization(DEFAULT_TENANT, &alice, "jira", &[], 1_000)
        .expect("begin_authorization must succeed for a registered OAuth2AuthCode connector");
    assert!(
        start
            .authorize_url
            .starts_with("https://auth.atlassian.com/authorize?"),
        "the authorize URL must be Atlassian's own endpoint, not GitLab's: {}",
        start.authorize_url
    );
    assert!(start.authorize_url.contains("audience=api.atlassian.com"));

    // The IdP's token endpoint responds with a real access token (no expiry ⇒ never due for
    // refresh, exactly like `gap5_connector_shared_refresh_vault.rs`'s own callback simulation).
    const MINTED_TOKEN: &str = "atlassian-access-token-xyz";
    oauth_stub.push_response(HttpResponse::new(
        200,
        format!(
            r#"{{"access_token":"{MINTED_TOKEN}","token_type":"Bearer","scope":"read:jira-work"}}"#
        )
        .into_bytes(),
    ));

    // callback: the code is exchanged, the token is sealed into the vault.
    let complete = gateway
        .complete_callback(&start.state, "auth-code-from-atlassian", 1_100)
        .expect("complete_callback must succeed: valid state, stub token endpoint responds 200");
    assert_eq!(complete.connector, "jira");
    assert_eq!(
        oauth_stub.sent_count(),
        1,
        "exactly one token-exchange POST must have been sent"
    );
    let token_req = &oauth_stub.sent()[0];
    assert!(
        token_req
            .url
            .starts_with("https://auth.atlassian.com/oauth/token"),
        "token exchange must hit Atlassian's own token endpoint: {}",
        token_req.url
    );

    // ---- 2. The USE-path invoker (own ConnectorRuntime, own CoordinatorTokenSource) shares the
    // ---- EXACT (token_key, backend) pair the gateway above sealed into.
    let api_stub = StubTransport::new();
    api_stub.push_response(HttpResponse::new(
        200,
        br#"{"id":"10001","key":"ABC-123","fields":{"summary":"a real issue"}}"#.to_vec(),
    ));
    let invoker = jira_invoker_over(token_key, backend, api_stub.clone());

    let principals: ainxt_connector_http::capability::PrincipalResolver =
        Arc::new(|uid: &str| Some(Principal::user(uid, &["connector.jira"])));
    let jira_adapter = Jira::new("https://api.atlassian.invalid/ex/jira/cloud-id-1");
    let capability = ConnectorCapability::new(
        "jira.get_issue",
        invoker,
        principals,
        DEFAULT_TENANT,
        DataClass::Internal,
        Arc::new(move |args: &str| {
            let v: serde_json::Value = serde_json::from_str(args).map_err(|e| e.to_string())?;
            let key = v
                .get("key")
                .and_then(|p| p.as_str())
                .ok_or("missing 'key'")?;
            Ok(jira_adapter.get_issue(key))
        }),
    )
    .with_effect(EffectClass::Idempotent);

    let mut tools = ToolRuntime::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler));
    tools.register(Box::new(capability));

    // THE PROVING DISPATCH: the SAME "alice" principal that ran the OAuth flow now calls the USE
    // path, and it must resolve the EXACT token that flow minted — a real callback-to-API-call
    // round trip, not two disjoint mechanisms merely tested in isolation.
    match tools.dispatch_for("alice", "jira.get_issue", r#"{"key":"ABC-123"}"#) {
        DispatchResult::Ok(output) => {
            assert!(
                output.contains("a real issue"),
                "expected the stub Jira response body to be surfaced verbatim: {output}"
            );
        }
        other => panic!("expected the real round trip to succeed, got: {other:?}"),
    }

    assert_eq!(
        api_stub.sent_count(),
        1,
        "exactly one real Jira API call must have reached the wire"
    );
    let api_req = &api_stub.sent()[0];
    assert!(
        api_req.url.contains("/rest/api/3/issue/ABC-123"),
        "must hit Jira's own issue-by-key endpoint: {}",
        api_req.url
    );
    let auth_header = api_req
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("Authorization"))
        .map(|(_, v)| v.as_str());
    assert_eq!(
        auth_header,
        Some(format!("Bearer {MINTED_TOKEN}").as_str()),
        "the bearer token that reaches the wire must be the EXACT token the OAuth callback minted \
         and sealed — proving this is one real round trip, not two independently-tested halves"
    );
}
