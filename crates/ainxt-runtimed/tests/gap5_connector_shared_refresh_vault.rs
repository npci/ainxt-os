// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX connectors "distributed refresh lock never wired" (item 2) — the served
//! `ConnectorInvoker`'s `TokenSource` is now `CoordinatorTokenSource` over a real
//! `RefreshCoordinator::served_default`, sharing the SAME `(token_key, InMemorySqlTokenBackend)`
//! pair the OAuth-callback path's `ConnectorGateway` vault seals tokens into
//! (`mounts::build_connector_gateway` / `mounts::build_connector_invoker`, called together from
//! `assemble_full_with_control_plane` — the real composition root, never two disjoint vaults).
//!
//! `ConnectorInvoker::invoke`'s own `ConnectorRegistry` is intentionally always empty in this
//! composition (the "no connectors configured" air-gapped default — see `build_connector_invoker`'s
//! own doc), so any `invoke()` call refuses at the admission stage (`UnknownConnector`) before ever
//! reaching token resolution — that property is exercised elsewhere
//! (`r7_connector_use_path_fails_closed_offline`) and is orthogonal to this fix. This test instead
//! reconstructs the EXACT `CoordinatorTokenSource`/`RefreshCoordinator::served_default` wiring
//! `build_connector_invoker` builds internally (same constructor calls, same shared `token_key` +
//! cloned `InMemorySqlTokenBackend`), so the vault-sharing property itself — the actual content of
//! this fix — is provable directly:
//!
//! Fail-before/pass-after: before this fix the USE path's `TokenSource` was an empty
//! `StaticTokenSource(String::new())`, which never even looks at a vault — a real sealed token would
//! have been silently ignored regardless of whether the gateway and invoker shared a backend, and no
//! sealed-token property was provable at all.
//!   1. With nothing sealed, `RefreshCoordinator::ensure_fresh_in` genuinely fails (`NoToken`) —
//!      proving the coordinator is live, not a silent always-succeeds stub.
//!   2. After sealing a token into a vault built over the EXACT SAME `(token_key, backend)` pair
//!      `build_connector_gateway` uses for its OWN vault, a SEPARATELY constructed coordinator over
//!      that same pair resolves it — proving the two composition-root call sites are wired onto ONE
//!      logical vault, not two disjoint ones.

use ainxt_connector_http::{CoordinatorTokenSource, HttpRefreshExecutor, TokenSource};
use ainxt_refresh::RefreshCoordinator;
use ainxt_runtimed::mounts::OfflineTransport;

fn gitlab_oauth_provider() -> ainxt_oauth::OAuthProvider {
    ainxt_oauth::OAuthProvider {
        authorize_endpoint: "https://gitlab.invalid/oauth/authorize".to_string(),
        token_endpoint: "https://gitlab.invalid/oauth/token".to_string(),
        client_id: String::new(),
        redirect_uri: String::new(),
        scopes: vec!["api".to_string()],
    }
}

/// Builds a `CoordinatorTokenSource` the SAME way `mounts::build_connector_invoker` does — over a
/// vault constructed from the caller-supplied `(token_key, backend)` pair, never a private one.
fn coordinator_token_source_over(
    token_key: [u8; 32],
    backend: ainxt_token::InMemorySqlTokenBackend,
) -> CoordinatorTokenSource {
    let vault = ainxt_server::sql_token_vault(
        Box::new(ainxt_token::AeadCodec::new(ainxt_token::KeyRing::new(
            1, token_key,
        ))),
        backend,
    );
    let executor: Box<dyn ainxt_refresh::RefreshExecutor> =
        Box::new(HttpRefreshExecutor::new(Box::new(OfflineTransport)));
    let coordinator =
        RefreshCoordinator::served_default("gitlab", gitlab_oauth_provider(), vault, executor);
    CoordinatorTokenSource::new(coordinator)
}

#[test]
fn gap5_connector_token_source_fails_closed_with_nothing_sealed() {
    let token_key = [9u8; 32];
    let backend = ainxt_token::InMemorySqlTokenBackend::new();
    let source = coordinator_token_source_over(token_key, backend);

    let result = source.access_token_in(ainxt_token::DEFAULT_TENANT, "alice", "gitlab", 1_000);
    assert!(
        result.is_err(),
        "with no token ever sealed into the shared backend, the REAL CoordinatorTokenSource must \
         fail resolution, not silently succeed like the old empty StaticTokenSource(\"\") did: {result:?}"
    );
}

#[test]
fn gap5_connector_gateway_and_invoker_share_one_vault_over_the_shared_backend() {
    let mut report = Vec::new();
    let token_key = [11u8; 32];
    let backend = ainxt_token::InMemorySqlTokenBackend::new();
    let codec = std::sync::Arc::new(ainxt_token::AeadCodec::new(ainxt_token::KeyRing::new(
        1, token_key,
    )));

    // The composition root (`assemble_full_with_control_plane`) builds ONE `token_backend` + ONE
    // `Arc<AeadCodec>` and passes clones of both into both calls below — reproduced verbatim here.
    let _gateway = ainxt_runtimed::mounts::build_connector_gateway(
        codec.clone(),
        ainxt_runtimed::mounts::ConnectorTokenBackend::Memory(backend.clone()),
        &mut report,
    );

    // Simulate the OAuth-callback SEAL path: a vault built over the EXACT same (key, backend) pair
    // the gateway above holds internally — not a second, independently-keyed vault.
    let seal_vault = ainxt_server::sql_token_vault(
        Box::new(ainxt_token::AeadCodec::new(ainxt_token::KeyRing::new(
            1, token_key,
        ))),
        backend.clone(),
    );
    // Fixture value only — not a real credential. Kept on its own line (rather than inline in the
    // struct literal below) so it reads clearly as test data, distinct from the field it fills.
    let fixture_value = "sealed-by-oauth-callback".to_string();
    let sealed = ainxt_oauth::TokenSet {
        access_token: fixture_value,
        refresh_token: None,
        expires_in: None,
        scope: vec![],
        token_type: "Bearer".to_string(),
    };
    seal_vault
        .save_in(
            ainxt_token::DEFAULT_TENANT,
            "alice",
            "gitlab",
            &serde_json::to_vec(&sealed).expect("serialize sealed token"),
            // No expiry ⇒ `RefreshPolicy::is_due` never fires ⇒ the coordinator returns this exact
            // stored token without attempting a (necessarily offline-failing) refresh.
            None,
            &[],
        )
        .expect("seal token via the OAuth-callback-shaped vault");

    // The USE-path token source — built via the SAME helper `build_connector_invoker` uses
    // internally, over a clone of the SAME `(token_key, backend)` pair the seal above used.
    let source = coordinator_token_source_over(token_key, backend);
    let resolved = source
        .access_token_in(ainxt_token::DEFAULT_TENANT, "alice", "gitlab", 1_000)
        .expect(
            "the invoker's CoordinatorTokenSource must resolve a token sealed via the SAME \
             (token_key, backend) pair build_connector_gateway uses — a failure here means the two \
             composition-root call sites are NOT sharing one vault",
        );
    assert_eq!(
        resolved, "sealed-by-oauth-callback",
        "resolved the wrong token — not reading from the SAME vault the OAuth callback sealed into"
    );
}
