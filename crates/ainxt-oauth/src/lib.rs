// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! ainxt-oauth — OAuth2 authorization-code + PKCE engine (Phase 2, increment #3).
//!
//! This is the **pure, transport-agnostic** core of the connector OAuth flow. It does no network
//! I/O: it *constructs* the artifacts an OAuth handshake needs (a PKCE pair, a CSRF `state`, an
//! authorize URL, a token-exchange/refresh request descriptor) and *parses* the provider's token
//! response. The actual HTTP is executed by the connector transport (#5), which POSTs the request
//! descriptor and hands the response body back here to parse. Keeping I/O out means every rule in
//! the protocol — PKCE S256, the exact form fields, error classification, incremental consent — is
//! deterministic and exhaustively unit-testable, which is exactly what an auth boundary needs.
//!
//! ## Why PKCE, always
//! Authorization-code **with PKCE** (RFC 7636) is used for every provider, confidential or not: the
//! `code_verifier` binds the token exchange to the same client that began the flow, so a stolen
//! authorization code is useless without it. `state` is an unguessable CSRF token that must be
//! echoed back on the callback.
//!
//! ## Incremental consent
//! Providers may grant fewer scopes than requested. [`missing_scopes`] / [`needs_consent`] compare
//! what was granted against what an operation needs, so the caller can trigger a fresh authorize
//! flow for *just* the missing scopes rather than failing the user's action opaquely. Provider
//! error responses that demand re-interaction are surfaced as [`OAuthError::ConsentRequired`].
//!
//! Clean-room: all terminology and the request/response shapes are original to AiNxt.

use std::collections::BTreeMap;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ============================ base64url (no padding) ============================

/// URL-safe base64 without padding (RFC 4648 §5), as required for PKCE (RFC 7636).
fn base64url_nopad(input: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(A[((n >> 18) & 63) as usize] as char);
        out.push(A[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(A[((n >> 6) & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(A[(n & 63) as usize] as char);
        }
    }
    out
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// Fill `n` bytes from the OS CSPRNG and base64url-encode them (verifier / state).
fn random_token(n: usize) -> String {
    let mut b = vec![0u8; n];
    getrandom::getrandom(&mut b).expect("OS CSPRNG unavailable");
    base64url_nopad(&b)
}

// ============================ PKCE ============================

/// A PKCE pair. `verifier` is kept server-side (never sent on the authorize request); `challenge`
/// is what goes in the authorize URL. The method is always `S256`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pkce {
    pub verifier: String,
    pub challenge: String,
}

impl Pkce {
    /// Generate a fresh pair: a 43-char base64url verifier (32 random bytes) and its S256 challenge.
    pub fn generate() -> Pkce {
        let verifier = random_token(32); // 32 bytes → 43 base64url chars, within RFC 7636's 43..=128
        let challenge = base64url_nopad(&sha256(verifier.as_bytes()));
        Pkce {
            verifier,
            challenge,
        }
    }

    /// The challenge method — always `S256` (plain is never used).
    pub fn method(&self) -> &'static str {
        "S256"
    }
}

// ============================ Provider config (declarative) ============================

/// Declarative OAuth2 provider configuration. Loadable from config; carries no secrets beyond the
/// (public) `client_id` — the client *secret*, if any, lives in the secret store, not here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OAuthProvider {
    pub authorize_endpoint: String,
    pub token_endpoint: String,
    pub client_id: String,
    pub redirect_uri: String,
    /// Default scopes when a `begin` call doesn't specify its own.
    #[serde(default)]
    pub scopes: Vec<String>,
}

impl OAuthProvider {
    /// Microsoft Entra ID (v2.0) endpoints for a given tenant — used by the Graph connector.
    pub fn entra(tenant: &str, client_id: &str, redirect_uri: &str, scopes: &[&str]) -> Self {
        OAuthProvider {
            authorize_endpoint: format!(
                "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize"
            ),
            token_endpoint: format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"),
            client_id: client_id.to_string(),
            redirect_uri: redirect_uri.to_string(),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// Atlassian Cloud OAuth 2.0 (3LO) endpoints — used by the Jira connector. DIFFERENT from
    /// GitLab's self-hosted OAuth app endpoints and from [`entra`](Self::entra)'s per-tenant Microsoft
    /// endpoints: Atlassian is a single fixed authorization server (`auth.atlassian.com`), and its
    /// `/authorize` step REQUIRES a fixed `audience=api.atlassian.com` query parameter (without it the
    /// exchanged token is not valid against any Atlassian API) plus `prompt=consent` (Atlassian does
    /// not silently re-prompt on a scope change without it, which would otherwise break incremental
    /// consent). This generic OAuth core has no per-provider extra-authorize-params hook, so those two
    /// fixed params are baked directly into `authorize_endpoint` here; [`begin`] joins its own
    /// query params onto an endpoint that already carries a `?query` with `&`, never a second `?`.
    ///
    /// Note: a refresh token is only issued by Atlassian when `offline_access` is among the granted
    /// scopes — callers that need longer-lived Jira access without re-prompting must include it.
    /// Also note: Jira Cloud's REST API is reached through `https://api.atlassian.com/ex/jira/{cloudId}`
    /// once OAuth-authorized (the `cloudId` is resolved via a separate `accessible-resources` call),
    /// not through the customer's own `*.atlassian.net` site URL — the connector's `base_url`
    /// (`AINXT_JIRA_BASE_URL`) must be set to that resolved URL in a real deployment; this crate does
    /// not perform the `accessible-resources` lookup itself.
    pub fn atlassian(client_id: &str, redirect_uri: &str, scopes: &[&str]) -> Self {
        OAuthProvider {
            authorize_endpoint:
                "https://auth.atlassian.com/authorize?audience=api.atlassian.com&prompt=consent"
                    .to_string(),
            token_endpoint: "https://auth.atlassian.com/oauth/token".to_string(),
            client_id: client_id.to_string(),
            redirect_uri: redirect_uri.to_string(),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
        }
    }
}

// ============================ Begin (authorize URL) ============================

/// The output of starting a flow: the URL to send the user to, plus the `state` and PKCE the caller
/// must persist (server-side, keyed by `state`) until the callback arrives. `requested_scopes` is
/// retained so the callback can compute incremental consent against what was actually granted.
#[derive(Debug, Clone)]
pub struct AuthStart {
    pub url: String,
    pub state: String,
    pub pkce: Pkce,
    pub requested_scopes: Vec<String>,
}

/// RFC 3986 unreserved characters stay unencoded; everything else in a query value is percent-encoded.
const QUERY_VALUE: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

fn enc(v: &str) -> String {
    percent_encoding::utf8_percent_encode(v, QUERY_VALUE).to_string()
}

/// Begin an authorization-code + PKCE flow. If `scopes` is empty the provider's default scopes are
/// used. Returns the authorize URL and the `state`/`pkce` to stash for the callback.
pub fn begin(provider: &OAuthProvider, scopes: &[String]) -> AuthStart {
    let pkce = Pkce::generate();
    let state = random_token(24);
    let requested: Vec<String> = if scopes.is_empty() {
        provider.scopes.clone()
    } else {
        scopes.to_vec()
    };
    let scope = requested.join(" ");
    // Most providers' `authorize_endpoint` is a bare URL (join with `?`); Atlassian's
    // (`OAuthProvider::atlassian`) already carries its own fixed `?audience=...&prompt=consent` — join
    // with `&` instead so the result is one valid query string, never a second (malformed) `?`.
    let sep = if provider.authorize_endpoint.contains('?') {
        '&'
    } else {
        '?'
    };
    let url = format!(
        "{}{}response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method=S256",
        provider.authorize_endpoint,
        sep,
        enc(&provider.client_id),
        enc(&provider.redirect_uri),
        enc(&scope),
        enc(&state),
        enc(&pkce.challenge),
    );
    AuthStart {
        url,
        state,
        pkce,
        requested_scopes: requested,
    }
}

// ============================ Token exchange / refresh ============================

/// A ready-to-send token-endpoint request: POST `form` (application/x-www-form-urlencoded) to
/// `token_endpoint`. The transport (#5) executes it; the fields are raw (unencoded) — the HTTP
/// client encodes the form body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenRequest {
    pub token_endpoint: String,
    pub form: Vec<(String, String)>,
}

/// Exchange an authorization `code` for tokens, proving possession of the PKCE verifier.
pub fn exchange_code(provider: &OAuthProvider, code: &str, pkce: &Pkce) -> TokenRequest {
    TokenRequest {
        token_endpoint: provider.token_endpoint.clone(),
        form: vec![
            ("grant_type".into(), "authorization_code".into()),
            ("code".into(), code.into()),
            ("redirect_uri".into(), provider.redirect_uri.clone()),
            ("client_id".into(), provider.client_id.clone()),
            ("code_verifier".into(), pkce.verifier.clone()),
        ],
    }
}

/// Build a refresh request. `scopes` narrows/repeats the grant if non-empty (some providers require
/// it, some ignore it); leave empty to refresh the existing grant unchanged.
pub fn refresh(provider: &OAuthProvider, refresh_token: &str, scopes: &[String]) -> TokenRequest {
    let mut form = vec![
        ("grant_type".into(), "refresh_token".into()),
        ("refresh_token".into(), refresh_token.into()),
        ("client_id".into(), provider.client_id.clone()),
    ];
    if !scopes.is_empty() {
        form.push(("scope".into(), scopes.join(" ")));
    }
    TokenRequest {
        token_endpoint: provider.token_endpoint.clone(),
        form,
    }
}

// ============================ Token response ============================

/// A parsed successful token response. Serializable so the refresh coordinator (#4) can persist it
/// as the encrypted vault blob (the access + refresh tokens are the sensitive part).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenSet {
    pub access_token: String,
    pub refresh_token: Option<String>,
    /// Lifetime in seconds, if the provider reported one.
    pub expires_in: Option<u64>,
    /// The scopes actually GRANTED (may be fewer than requested → incremental consent).
    pub scope: Vec<String>,
    pub token_type: String,
}

impl std::fmt::Debug for TokenSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the real tokens — a Debug-logged TokenSet would leak usable OAuth
        // credentials into logs/error messages (same pattern as `HmacSha256AuditHasher`).
        f.debug_struct("TokenSet")
            .field("access_token", &"<redacted>")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .field("expires_in", &self.expires_in)
            .field("scope", &self.scope)
            .field("token_type", &self.token_type)
            .finish()
    }
}

impl TokenSet {
    /// Absolute expiry (unix seconds) given the current time, if a lifetime was reported.
    pub fn expires_at(&self, now_unix: u64) -> Option<u64> {
        self.expires_in.map(|s| now_unix.saturating_add(s))
    }

    /// Parse a token-endpoint response body. A well-formed OAuth **error** response is mapped to the
    /// matching [`OAuthError`]; anything else unparseable is [`OAuthError::MalformedResponse`].
    pub fn parse(body: &str) -> Result<TokenSet, OAuthError> {
        let raw: RawToken = serde_json::from_str(body)
            .map_err(|e| OAuthError::MalformedResponse(format!("invalid JSON: {e}")))?;

        if let Some(error) = raw.error {
            let error_description = raw.error_description;
            // Codes that mean "the user must (re-)interact/consent" → trigger a fresh authorize.
            const CONSENT: &[&str] = &[
                "consent_required",
                "interaction_required",
                "login_required",
                "invalid_grant",
            ];
            return Err(if CONSENT.contains(&error.as_str()) {
                OAuthError::ConsentRequired { error, error_description }
            } else {
                OAuthError::Provider { error, error_description }
            });
        }

        let access_token = raw
            .access_token
            .ok_or(OAuthError::MalformedResponse(
                "no access_token and no error".into(),
            ))?;
        let scope = raw
            .scope
            .map(|s| s.split_whitespace().map(str::to_string).collect())
            .unwrap_or_default();
        Ok(TokenSet {
            access_token,
            refresh_token: raw.refresh_token,
            expires_in: raw.expires_in,
            scope,
            token_type: raw.token_type.unwrap_or_else(|| "Bearer".to_string()),
        })
    }
}

#[derive(Deserialize)]
struct RawToken {
    access_token: Option<String>,
    refresh_token: Option<String>,
    expires_in: Option<u64>,
    scope: Option<String>,
    token_type: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

/// A token-flow error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OAuthError {
    /// A generic provider error (`{error, error_description}`).
    Provider {
        error: String,
        error_description: Option<String>,
    },
    /// The provider requires (re-)interaction/consent — start a fresh authorize flow.
    ConsentRequired {
        error: String,
        error_description: Option<String>,
    },
    /// The response was neither a valid token nor a valid error object.
    MalformedResponse(String),
}

impl std::fmt::Display for OAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OAuthError::Provider { error, error_description } => {
                write!(f, "oauth provider error '{error}'")?;
                if let Some(d) = error_description {
                    write!(f, ": {d}")?;
                }
                Ok(())
            }
            OAuthError::ConsentRequired { error, .. } => {
                write!(f, "oauth consent/interaction required ('{error}')")
            }
            OAuthError::MalformedResponse(m) => write!(f, "malformed oauth response: {m}"),
        }
    }
}

impl std::error::Error for OAuthError {}

// ============================ Incremental consent ============================

/// The required scopes that were NOT granted (case-sensitive, per OAuth). Empty ⇒ fully consented.
pub fn missing_scopes(granted: &[String], required: &[String]) -> Vec<String> {
    required
        .iter()
        .filter(|r| !granted.iter().any(|g| g == *r))
        .cloned()
        .collect()
}

/// Whether a fresh consent flow is needed to satisfy `required`.
pub fn needs_consent(granted: &[String], required: &[String]) -> bool {
    !missing_scopes(granted, required).is_empty()
}

/// Step-up (incremental) consent: if the operation needs scopes the user has not granted, return a
/// **fresh authorize flow for just the missing scopes** so the user re-consents to the delta rather
/// than the whole set (Entra/Google support incremental consent). Returns `None` when the granted
/// set already covers `required` — no re-prompt needed. The returned [`AuthStart`] carries a NEW
/// `state`/PKCE that the caller must persist (e.g. via [`begin_and_store`]) before redirecting.
///
/// GAP-AUDIT misc-decisions: this is the BARE, single-provider convenience (no tenant/user/vault
/// concept) — only this crate's own tests call it directly. The production step-up-consent path is
/// [`ainxt_connector_http::ConnectorGateway::step_up_consent_if_needed`], which is NOT a reimplemented
/// copy of this function: it already delegates the scope-diff to [`missing_scopes`] (this crate stays
/// the single source of truth for that check), then composes its OWN richer "begin" —
/// [`ConnectorGateway::begin_authorization`] — because the production flow needs things this bare
/// function structurally cannot do: `Principal`/tenant-scoped admission, reading already-granted
/// scopes from the vault's metadata (without decrypting the secret), and persisting the new
/// state/PKCE + owner mapping atomically with beginning the flow. Confirmed non-gap: not
/// duplicated-and-drifting logic, just two different altitudes over the same `missing_scopes` core.
pub fn step_up_consent(
    provider: &OAuthProvider,
    granted: &[String],
    required: &[String],
) -> Option<AuthStart> {
    let missing = missing_scopes(granted, required);
    if missing.is_empty() {
        return None;
    }
    Some(begin(provider, &missing))
}

// ============================ Callback CSRF-state validation ============================
//
// The authorize redirect returns `?code=...&state=...` to our callback. `state` is the CSRF
// defense: it is an unguessable token WE minted in `begin`, stashed server-side, and must be echoed
// back. An attacker who forges a callback (login-CSRF / code-injection) cannot know a live `state`,
// so a callback whose `state` has no matching stashed entry is rejected. The stash is **single-use**
// (a matched `state` is consumed, so a captured callback cannot be replayed) and **TTL-bounded** (a
// stale flow cannot be completed hours later). The PKCE `verifier` is retrieved *by* the `state`, so
// the token exchange is bound to the same client that began the flow.

/// Constant-time string equality — no early return on the first differing byte, so comparing an
/// attacker-supplied `state` against the stored one leaks no timing signal about the matched prefix.
pub fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// What we stash server-side, keyed by `state`, between `begin` and the callback. Holds the PKCE
/// verifier (never sent on the authorize request), the scopes requested (for incremental-consent
/// checks against what is granted), the `state` itself (for the explicit constant-time compare), and
/// the mint time (for TTL expiry).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingAuth {
    pub state: String,
    pub pkce: Pkce,
    pub requested_scopes: Vec<String>,
    pub created_at_unix: u64,
}

/// A callback-validation failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallbackError {
    /// No live flow matches the returned `state` — a forged, replayed, or already-consumed callback.
    /// This is the CSRF rejection arm; treat it as an attack, not a user error.
    UnknownState,
    /// The `state` matched a flow that is older than the allowed TTL — expired, do not exchange.
    Expired,
    /// The stash backend failed.
    Store(String),
}

impl std::fmt::Display for CallbackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallbackError::UnknownState => {
                f.write_str("oauth callback rejected: unknown/forged/replayed state (CSRF)")
            }
            CallbackError::Expired => {
                f.write_str("oauth callback rejected: authorization flow expired")
            }
            CallbackError::Store(m) => write!(f, "oauth pending-auth store error: {m}"),
        }
    }
}

impl std::error::Error for CallbackError {}

/// Server-side stash for in-flight authorize flows, keyed by `state`. Production uses Redis (short
/// TTL); the default [`InMemoryPendingAuthStore`] is for tests/dev. `take` MUST be atomic and
/// single-use — a `state` may be consumed at most once, or a captured callback becomes replayable.
pub trait PendingAuthStore: Send + Sync {
    /// Stash a pending flow under its `state`.
    fn put(&self, pending: PendingAuth) -> Result<(), CallbackError>;
    /// Atomically remove and return the pending flow for `state` (single-use). `None` if absent.
    fn take(&self, state: &str) -> Result<Option<PendingAuth>, CallbackError>;
}

/// In-memory single-process stash (tests/dev). Cheap to clone; clones share the backing map.
#[derive(Clone, Default)]
pub struct InMemoryPendingAuthStore {
    map: std::sync::Arc<Mutex<BTreeMap<String, PendingAuth>>>,
}

impl InMemoryPendingAuthStore {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn len(&self) -> usize {
        self.map.lock().expect("pending-auth lock").len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl PendingAuthStore for InMemoryPendingAuthStore {
    fn put(&self, pending: PendingAuth) -> Result<(), CallbackError> {
        self.map
            .lock()
            .map_err(|_| CallbackError::Store("poisoned".into()))?
            .insert(pending.state.clone(), pending);
        Ok(())
    }
    fn take(&self, state: &str) -> Result<Option<PendingAuth>, CallbackError> {
        Ok(self
            .map
            .lock()
            .map_err(|_| CallbackError::Store("poisoned".into()))?
            .remove(state))
    }
}

/// Begin an authorize flow AND stash it in `store` keyed by its `state`, so the later callback can be
/// validated. `now_unix` stamps the flow for TTL expiry. Returns the [`AuthStart`] (its `url` is
/// where the user is sent; its `state` is what the IdP will echo back).
pub fn begin_and_store(
    store: &dyn PendingAuthStore,
    provider: &OAuthProvider,
    scopes: &[String],
    now_unix: u64,
) -> Result<AuthStart, CallbackError> {
    let start = begin(provider, scopes);
    store.put(PendingAuth {
        state: start.state.clone(),
        pkce: start.pkce.clone(),
        requested_scopes: start.requested_scopes.clone(),
        created_at_unix: now_unix,
    })?;
    Ok(start)
}

/// A validated callback: the token-exchange request to send to the IdP, plus the scopes the flow
/// originally requested (so incremental consent can be checked once the token comes back).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallbackValidated {
    pub token_request: TokenRequest,
    pub requested_scopes: Vec<String>,
}

/// Validate an OAuth callback and produce the token-exchange request. `returned_state` is the
/// (attacker-controllable) `state` echoed by the IdP; `code` is the authorization code.
///
/// Fail-closed, in order:
/// 1. **Consume** the stashed flow for `returned_state` — single-use (removed whether or not the
///    rest succeeds), so a captured callback can never be replayed. Absent ⇒ [`CallbackError::UnknownState`]
///    (CSRF/forgery/replay).
/// 2. **Constant-time compare** the returned `state` against the stored one (defense in depth against
///    a store that might do loose matching). Mismatch ⇒ `UnknownState`.
/// 3. **TTL**: if the flow is older than `ttl_secs`, reject as [`CallbackError::Expired`].
///
/// Only then is the PKCE-bound [`exchange_code`] request returned.
pub fn validate_callback(
    store: &dyn PendingAuthStore,
    provider: &OAuthProvider,
    returned_state: &str,
    code: &str,
    ttl_secs: u64,
    now_unix: u64,
) -> Result<CallbackValidated, CallbackError> {
    // 1. Single-use consume — a matched state is burned even if validation below fails.
    let pending = store
        .take(returned_state)?
        .ok_or(CallbackError::UnknownState)?;
    // 2. Explicit constant-time state comparison.
    if !ct_eq(returned_state, &pending.state) {
        return Err(CallbackError::UnknownState);
    }
    // 3. TTL bound (saturating so a clock quirk cannot underflow into "not expired").
    if now_unix.saturating_sub(pending.created_at_unix) > ttl_secs {
        return Err(CallbackError::Expired);
    }
    Ok(CallbackValidated {
        token_request: exchange_code(provider, code, &pending.pkce),
        requested_scopes: pending.requested_scopes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider() -> OAuthProvider {
        OAuthProvider {
            authorize_endpoint: "https://idp.example.invalid/authorize".into(),
            token_endpoint: "https://idp.example.invalid/token".into(),
            client_id: "client-123".into(),
            redirect_uri: "https://app.example.invalid/callback?x=1".into(),
            scopes: vec!["openid".into(), "offline_access".into()],
        }
    }

    #[test]
    fn base64url_matches_known_vectors() {
        assert_eq!(base64url_nopad(b""), "");
        assert_eq!(base64url_nopad(b"f"), "Zg");
        assert_eq!(base64url_nopad(b"fo"), "Zm8");
        assert_eq!(base64url_nopad(b"foo"), "Zm9v");
        assert_eq!(base64url_nopad(b"foobar"), "Zm9vYmFy");
        // A byte that exercises the url-safe alphabet (0xff 0xff 0xff -> "____").
        assert_eq!(base64url_nopad(&[0xff, 0xff, 0xff]), "____");
    }

    #[test]
    fn pkce_challenge_matches_rfc7636_test_vector() {
        // RFC 7636 Appendix B: verifier → S256 challenge.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = base64url_nopad(&sha256(verifier.as_bytes()));
        assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn pkce_generate_is_well_formed_and_unique() {
        let a = Pkce::generate();
        let b = Pkce::generate();
        assert_eq!(a.verifier.len(), 43, "32 bytes → 43 base64url chars");
        assert_eq!(a.method(), "S256");
        assert_ne!(a.verifier, b.verifier, "verifiers must be random");
        // The challenge must be the S256 of the verifier.
        assert_eq!(a.challenge, base64url_nopad(&sha256(a.verifier.as_bytes())));
    }

    #[test]
    fn authorize_url_has_all_params_and_encodes_values() {
        let start = begin(&provider(), &["User.Read".into()]);
        let u = &start.url;
        assert!(u.starts_with("https://idp.example.invalid/authorize?"));
        assert!(u.contains("response_type=code"));
        assert!(u.contains("client_id=client-123"));
        assert!(u.contains("code_challenge_method=S256"));
        assert!(u.contains(&format!("code_challenge={}", start.pkce.challenge)));
        assert!(u.contains(&format!("state={}", start.state)));
        // redirect_uri contains reserved chars → must be percent-encoded (no raw "://" or "?").
        assert!(u.contains("redirect_uri=https%3A%2F%2Fapp.example.invalid%2Fcallback%3Fx%3D1"));
        // explicit scope overrides provider defaults.
        assert!(u.contains("scope=User.Read"));
        assert_eq!(start.requested_scopes, vec!["User.Read".to_string()]);
    }

    #[test]
    fn begin_uses_provider_default_scopes_when_unspecified() {
        let start = begin(&provider(), &[]);
        assert!(
            start.url.contains("scope=openid%20offline_access"),
            "url: {}",
            start.url
        );
        assert_eq!(
            start.requested_scopes,
            vec!["openid".to_string(), "offline_access".to_string()]
        );
    }

    #[test]
    fn exchange_code_form_is_correct() {
        let pkce = Pkce::generate();
        let req = exchange_code(&provider(), "auth-code-xyz", &pkce);
        assert_eq!(req.token_endpoint, "https://idp.example.invalid/token");
        let f = |k: &str| {
            req.form
                .iter()
                .find(|(kk, _)| kk == k)
                .map(|(_, v)| v.clone())
        };
        assert_eq!(f("grant_type").as_deref(), Some("authorization_code"));
        assert_eq!(f("code").as_deref(), Some("auth-code-xyz"));
        assert_eq!(f("client_id").as_deref(), Some("client-123"));
        assert_eq!(f("code_verifier").as_deref(), Some(pkce.verifier.as_str()));
        assert_eq!(
            f("redirect_uri").as_deref(),
            Some("https://app.example.invalid/callback?x=1")
        );
    }

    #[test]
    fn refresh_form_includes_scope_only_when_present() {
        let with = refresh(&provider(), "rt-1", &["Mail.Read".into()]);
        assert!(with
            .form
            .iter()
            .any(|(k, v)| k == "grant_type" && v == "refresh_token"));
        assert!(with
            .form
            .iter()
            .any(|(k, v)| k == "refresh_token" && v == "rt-1"));
        assert!(with
            .form
            .iter()
            .any(|(k, v)| k == "scope" && v == "Mail.Read"));
        let without = refresh(&provider(), "rt-1", &[]);
        assert!(!without.form.iter().any(|(k, _)| k == "scope"));
    }

    #[test]
    fn parse_success_response() {
        let body = r#"{"access_token":"at-1","refresh_token":"rt-1","expires_in":3600,"scope":"openid User.Read","token_type":"Bearer"}"#;
        let ts = TokenSet::parse(body).unwrap();
        assert_eq!(ts.access_token, "at-1");
        assert_eq!(ts.refresh_token.as_deref(), Some("rt-1"));
        assert_eq!(ts.expires_in, Some(3600));
        assert_eq!(
            ts.scope,
            vec!["openid".to_string(), "User.Read".to_string()]
        );
        assert_eq!(ts.expires_at(1_000), Some(4_600));
    }

    #[test]
    fn parse_defaults_token_type_and_empty_scope() {
        let ts = TokenSet::parse(r#"{"access_token":"at"}"#).unwrap();
        assert_eq!(ts.token_type, "Bearer");
        assert!(ts.scope.is_empty());
        assert_eq!(ts.refresh_token, None);
        assert_eq!(ts.expires_at(1_000), None);
    }

    #[test]
    fn parse_generic_provider_error() {
        let body = r#"{"error":"invalid_client","error_description":"bad secret"}"#;
        match TokenSet::parse(body) {
            Err(OAuthError::Provider { error, error_description }) => {
                assert_eq!(error, "invalid_client");
                assert_eq!(error_description.as_deref(), Some("bad secret"));
            }
            other => panic!("expected Provider error, got {other:?}"),
        }
    }

    #[test]
    fn parse_consent_required_errors() {
        for code in [
            "consent_required",
            "interaction_required",
            "login_required",
            "invalid_grant",
        ] {
            let body = format!(r#"{{"error":"{code}"}}"#);
            assert!(
                matches!(
                    TokenSet::parse(&body),
                    Err(OAuthError::ConsentRequired { .. })
                ),
                "{code} should map to ConsentRequired"
            );
        }
    }

    #[test]
    fn parse_malformed_response() {
        assert!(matches!(
            TokenSet::parse("not json"),
            Err(OAuthError::MalformedResponse(_))
        ));
        // Valid JSON but neither a token nor an error.
        assert!(matches!(
            TokenSet::parse("{}"),
            Err(OAuthError::MalformedResponse(_))
        ));
    }

    #[test]
    fn incremental_consent_detects_missing_scopes() {
        let granted = vec!["openid".to_string(), "User.Read".to_string()];
        let required = vec!["User.Read".to_string(), "Mail.Send".to_string()];
        assert_eq!(
            missing_scopes(&granted, &required),
            vec!["Mail.Send".to_string()]
        );
        assert!(needs_consent(&granted, &required));
        assert!(!needs_consent(&granted, &["openid".to_string()]));
    }

    #[test]
    fn step_up_consent_only_requests_the_missing_scopes() {
        let p = provider();
        let granted = vec!["openid".to_string()];
        let required = vec![
            "openid".to_string(),
            "Mail.Send".to_string(),
            "Files.Read".to_string(),
        ];
        let start = step_up_consent(&p, &granted, &required).expect("step-up needed");
        // Only the delta is re-requested, not the already-granted "openid".
        assert_eq!(
            start.requested_scopes,
            vec!["Mail.Send".to_string(), "Files.Read".to_string()]
        );
        assert!(
            start.url.contains("scope=Mail.Send%20Files.Read"),
            "url: {}",
            start.url
        );
        // Fresh CSRF state + PKCE for the step-up flow.
        assert!(!start.state.is_empty());
        assert_eq!(start.pkce.method(), "S256");
        // No step-up when everything required is already granted.
        assert!(step_up_consent(&p, &required, &required).is_none());
    }

    #[test]
    fn ct_eq_matches_and_rejects() {
        assert!(ct_eq("abc123", "abc123"));
        assert!(!ct_eq("abc123", "abc124"));
        assert!(!ct_eq("abc", "abcd")); // length mismatch
        assert!(ct_eq("", ""));
    }

    #[test]
    fn callback_happy_path_binds_pkce_verifier() {
        let store = InMemoryPendingAuthStore::new();
        let p = provider();
        let start = begin_and_store(&store, &p, &["openid".into()], 1_000).unwrap();
        assert_eq!(store.len(), 1);
        let verifier = start.pkce.verifier.clone();

        let out = validate_callback(&store, &p, &start.state, "the-code", 600, 1_100).unwrap();
        // The exchange must carry THIS flow's verifier and the code (PKCE binding).
        let form = out.token_request.form;
        let get = |k: &str| form.iter().find(|(kk, _)| kk == k).map(|(_, v)| v.clone());
        assert_eq!(get("code").as_deref(), Some("the-code"));
        assert_eq!(get("code_verifier").as_deref(), Some(verifier.as_str()));
        assert_eq!(out.requested_scopes, vec!["openid".to_string()]);
        // Single-use: the flow is consumed.
        assert!(store.is_empty(), "state must be consumed on success");
    }

    #[test]
    fn callback_rejects_forged_state_as_csrf() {
        let store = InMemoryPendingAuthStore::new();
        let p = provider();
        // A flow exists, but the attacker echoes a state they invented.
        begin_and_store(&store, &p, &["openid".into()], 1_000).unwrap();
        let err =
            validate_callback(&store, &p, "attacker-picked-state", "code", 600, 1_100).unwrap_err();
        assert_eq!(err, CallbackError::UnknownState);
        // The legitimate flow is untouched (a forged callback must not consume a real state).
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn callback_is_single_use_replay_is_rejected() {
        let store = InMemoryPendingAuthStore::new();
        let p = provider();
        let start = begin_and_store(&store, &p, &["openid".into()], 1_000).unwrap();
        // First use succeeds.
        assert!(validate_callback(&store, &p, &start.state, "c", 600, 1_050).is_ok());
        // A replay of the SAME captured callback must fail (state already consumed).
        let replay = validate_callback(&store, &p, &start.state, "c", 600, 1_060).unwrap_err();
        assert_eq!(replay, CallbackError::UnknownState);
    }

    #[test]
    fn callback_rejects_expired_flow_and_consumes_it() {
        let store = InMemoryPendingAuthStore::new();
        let p = provider();
        let start = begin_and_store(&store, &p, &["openid".into()], 1_000).unwrap();
        // ttl = 600s; callback arrives at 1_000 + 601 → expired.
        let err = validate_callback(&store, &p, &start.state, "c", 600, 1_601).unwrap_err();
        assert_eq!(err, CallbackError::Expired);
        // Even on expiry the state is burned (no lingering replayable entry).
        assert!(store.is_empty(), "expired state must still be consumed");
    }

    #[test]
    fn callback_within_ttl_boundary_is_accepted() {
        let store = InMemoryPendingAuthStore::new();
        let p = provider();
        let start = begin_and_store(&store, &p, &["openid".into()], 1_000).unwrap();
        // Exactly at the TTL boundary (age == ttl) is still valid; age > ttl is expired.
        assert!(validate_callback(&store, &p, &start.state, "c", 600, 1_600).is_ok());
    }

    #[test]
    fn provider_serde_round_trips_and_entra_helper() {
        let p = OAuthProvider::entra(
            "tenant-abc",
            "client-9",
            "https://app/cb",
            &["User.Read", "Mail.Read"],
        );
        assert!(p
            .authorize_endpoint
            .contains("login.microsoftonline.com/tenant-abc/oauth2/v2.0/authorize"));
        assert!(p.token_endpoint.ends_with("/tenant-abc/oauth2/v2.0/token"));
        let json = serde_json::to_string(&p).unwrap();
        let back: OAuthProvider = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn atlassian_helper_endpoints_and_fixed_audience_prompt_params() {
        let p = OAuthProvider::atlassian(
            "jira-client-1",
            "https://app/cb",
            &["read:jira-work", "write:jira-work", "offline_access"],
        );
        assert_eq!(p.token_endpoint, "https://auth.atlassian.com/oauth/token");
        assert!(p
            .authorize_endpoint
            .starts_with("https://auth.atlassian.com/authorize?"));
        assert!(p.authorize_endpoint.contains("audience=api.atlassian.com"));
        assert!(p.authorize_endpoint.contains("prompt=consent"));
        // Round-trips through serde like any other provider config.
        let json = serde_json::to_string(&p).unwrap();
        let back: OAuthProvider = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn begin_joins_a_provider_endpoint_that_already_has_a_query_with_ampersand_not_a_second_question_mark(
    ) {
        // Atlassian's endpoint already carries `?audience=...&prompt=consent`; `begin`'s own params
        // must be appended with `&`, producing exactly one `?` in the whole URL.
        let p = OAuthProvider::atlassian("client", "https://app/cb", &["offline_access"]);
        let start = begin(&p, &[]);
        assert_eq!(
            start.url.matches('?').count(),
            1,
            "exactly one '?' — the provider's own query params and begin()'s must be joined with \
             '&', not a second '?': {}",
            start.url
        );
        assert!(start.url.contains("audience=api.atlassian.com"));
        assert!(start.url.contains("prompt=consent"));
        assert!(start.url.contains("response_type=code"));
        assert!(start.url.contains("scope=offline_access"));
    }
}
