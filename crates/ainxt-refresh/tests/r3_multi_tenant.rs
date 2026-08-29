// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R3 gap (Connectors, "diverged"): multi-tenant token resolution on the USE/refresh path.
//!
//! The OAuth callback WRITE path seals a token tenant-scoped (`vault.save_in(&owner.tenant, ..)`),
//! but the USE/refresh path historically resolved through the unscoped vault API, which routes to
//! `DEFAULT_TENANT`. In a multi-tenant deployment that is a hard divergence: the refresh coordinator
//! reads a *different* key than the one the callback sealed, so it never finds the token (or, worse,
//! two tenants reusing the same `(user, connector)` collide).
//!
//! These tests run against the REAL `RefreshCoordinator` and prove the USE/refresh path now resolves
//! the design's `(tenant, jwt.sub, connector)` key end-to-end, with tenant isolation.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use ainxt_oauth::{OAuthProvider, TokenRequest, TokenSet};
use ainxt_refresh::{InMemoryRefreshLock, RefreshCoordinator, RefreshError, RefreshExecutor};
use ainxt_token::{AeadCodec, InMemoryTokenStore, KeyRing, TokenVault, DEFAULT_TENANT};

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

fn vault() -> TokenVault {
    TokenVault::new(
        Box::new(AeadCodec::new(KeyRing::new(1, [7u8; 32]))),
        Box::new(InMemoryTokenStore::new()),
    )
}

/// Seal a token tenant-scoped, exactly as the OAuth callback write path does (`save_in`).
fn seal_tenant_scoped(
    v: &TokenVault,
    tenant: &str,
    user: &str,
    connector: &str,
    access: &str,
    refresh: Option<&str>,
    expires_at: Option<u64>,
) {
    let ts = TokenSet {
        access_token: access.into(),
        refresh_token: refresh.map(str::to_string),
        expires_in: expires_at.map(|e| e.saturating_sub(NOW)),
        scope: vec!["api".into()],
        token_type: "Bearer".into(),
    };
    let blob = serde_json::to_vec(&ts).unwrap();
    v.save_in(tenant, user, connector, &blob, expires_at, &ts.scope)
        .unwrap();
}

/// Executor that stamps a per-invocation fresh access token so we can see WHICH tenant refreshed.
struct TaggedExecutor {
    tag: String,
    calls: Arc<AtomicU32>,
}
impl RefreshExecutor for TaggedExecutor {
    fn execute(&self, _r: &TokenRequest) -> Result<TokenSet, String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(TokenSet {
            access_token: format!("FRESH-{}", self.tag),
            refresh_token: Some("R2".into()),
            expires_in: Some(3600),
            scope: vec!["api".into()],
            token_type: "Bearer".into(),
        })
    }
}

fn coordinator(v: TokenVault, tag: &str, calls: Arc<AtomicU32>) -> RefreshCoordinator {
    RefreshCoordinator::new(
        "graph",
        provider(),
        v,
        Box::new(InMemoryRefreshLock::new()),
        Box::new(TaggedExecutor {
            tag: tag.to_string(),
            calls,
        }),
    )
}

/// THE gap test: a token sealed tenant-scoped (as the callback does) is resolvable on the USE path
/// ONLY under its own tenant. The unscoped/DEFAULT_TENANT resolution (the old divergent behavior)
/// finds nothing — which is exactly why single-tenant resolution was a bug in a multi-tenant world.
#[test]
fn r3_multi_tenant_token_use_path() {
    let v = vault();
    // The callback sealed this token for tenant-a ONLY (never DEFAULT_TENANT). Not due for refresh.
    seal_tenant_scoped(
        &v,
        "tenant-a",
        "u",
        "graph",
        "TENANT-A-ACCESS",
        Some("R"),
        Some(NOW + 10_000),
    );
    let calls = Arc::new(AtomicU32::new(0));
    let c = coordinator(v, "A", calls.clone());

    // Tenant-scoped USE path resolves the token the callback sealed — fresh, no network needed.
    assert_eq!(
        c.ensure_fresh_in("tenant-a", "u", NOW).unwrap(),
        "TENANT-A-ACCESS"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "not due → no network refresh"
    );

    // A DIFFERENT tenant reusing the same (user, connector) sees nothing — structural isolation.
    assert_eq!(
        c.ensure_fresh_in("tenant-b", "u", NOW),
        Err(RefreshError::NoToken)
    );

    // The unscoped path (DEFAULT_TENANT) — the OLD divergent USE-path behavior — resolves NOTHING,
    // because the write path sealed under tenant-a, not DEFAULT_TENANT. This is the closed gap.
    assert_eq!(c.ensure_fresh("u", NOW), Err(RefreshError::NoToken));
    assert_eq!(
        c.ensure_fresh_in(DEFAULT_TENANT, "u", NOW),
        Err(RefreshError::NoToken)
    );
}

/// Isolation under refresh: two tenants reuse the same (user, connector), both due. Each refreshes
/// its OWN token; refreshing one never mints/overwrites the other, and the re-seal stays tenant-
/// scoped so a follow-up read returns the SAME tenant's fresh token.
#[test]
fn r3_multi_tenant_refresh_isolation() {
    let v = vault();
    seal_tenant_scoped(&v, "tenant-a", "u", "graph", "OLD-A", Some("RA"), Some(NOW)); // due
    seal_tenant_scoped(&v, "tenant-b", "u", "graph", "OLD-B", Some("RB"), Some(NOW)); // due
    let calls = Arc::new(AtomicU32::new(0));
    let c = coordinator(v, "T", calls.clone());

    // Refresh tenant-a. Exactly one network call; tenant-a now holds a fresh token.
    assert_eq!(c.ensure_fresh_in("tenant-a", "u", NOW).unwrap(), "FRESH-T");
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // Tenant-b is untouched by tenant-a's refresh — it is still due and refreshes independently
    // (a SECOND network call), proving the two tenants never shared a slot or a lock outcome.
    assert_eq!(c.ensure_fresh_in("tenant-b", "u", NOW).unwrap(), "FRESH-T");
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    // The re-seal was tenant-scoped: reading tenant-a again returns its fresh token with no further
    // network call (now expires at NOW+3600, not due).
    assert_eq!(c.ensure_fresh_in("tenant-a", "u", NOW).unwrap(), "FRESH-T");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "no extra refresh — token is fresh"
    );
}
