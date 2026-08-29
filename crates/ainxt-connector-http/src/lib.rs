// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! ainxt-connector-http — concrete connector adapters + air-gap-aware HTTP transport (Phase 2, #5).
//!
//! This is where the Connector Runtime meets the wire. Three things matter and all three are
//! enforced *here*, on the single path every call takes ([`ConnectorInvoker::invoke`]):
//!
//! 1. **Admission** — every call first clears the Connector Runtime's on-behalf-of authz + org/dept
//!    policy (#1). A denied call never touches the network.
//! 2. **Egress control** — before any bytes leave, the payload passes the **data-class ceiling**
//!    (regulated data never egresses to a cloud connector) and the **DLP** redactor (#1). This runs
//!    on *every* call (the ceiling) and redacts write bodies (the DLP).
//! 3. **Untrusted ingress** — a connector response is tagged [`Provenance::Connector`], so the
//!    runtime's injection stage fences + scans it (connector data can carry indirect injection).
//!
//! The HTTP transport is a seam ([`HttpTransport`]). The default in tests is [`StubTransport`]; the
//! production [`ReqwestTransport`] (feature `reqwest-transport`) honors the **air-gap forward proxy**
//! and maps a connect/timeout failure to [`TransportError::Unavailable`], which the caller treats as
//! a **soft-degrade** (the feature is unavailable, the turn does not crash).
//!
//! Adapters ([`GitLab`], [`Jira`], [`Graph`]) are pure request *builders* + response *parsers*; they
//! hold no tokens and do no I/O, so their URLs/methods/bodies are exhaustively unit-testable.
//!
//! Clean-room: terminology, the invoker pipeline, and the adapter surface are original to AiNxt.

use std::sync::{Arc, Mutex};

use ainxt_connector::{
    ConnectorAudit, ConnectorAuditEvent, ConnectorError, ConnectorId, ConnectorRuntime,
};
use ainxt_injection::Provenance;
use ainxt_oauth::{TokenRequest, TokenSet};
use ainxt_payments::boundary::{
    DispatchDenied, EgressGuard, GraduatedResponse, OutboundCall, PayloadSignal,
    RecordingRemediation, TripwireRemediation,
};
use ainxt_refresh::{RefreshCoordinator, RefreshExecutor};
use ainxt_token::{TokenVault, DEFAULT_TENANT};
use ainxt_types::{DataClass, Principal, Role};
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};

// ============================ HTTP model ============================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

impl HttpMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Patch => "PATCH",
            HttpMethod::Delete => "DELETE",
        }
    }
}

/// An outbound HTTP request. Built by an adapter *without* auth; the invoker adds the bearer token
/// after egress control so the token is never handed to the DLP scanner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: HttpMethod,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
}

impl HttpRequest {
    pub fn new(method: HttpMethod, url: impl Into<String>) -> Self {
        HttpRequest {
            method,
            url: url.into(),
            headers: Vec::new(),
            body: None,
        }
    }
    pub fn get(url: impl Into<String>) -> Self {
        Self::new(HttpMethod::Get, url)
    }
    pub fn post(url: impl Into<String>) -> Self {
        Self::new(HttpMethod::Post, url)
    }
    /// A JSON POST (`Content-Type: application/json`).
    pub fn post_json(url: impl Into<String>, body: impl Into<String>) -> Self {
        let mut r = Self::post(url);
        r.headers
            .push(("Content-Type".into(), "application/json".into()));
        r.body = Some(body.into().into_bytes());
        r
    }
    pub fn header(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.headers.push((k.into(), v.into()));
        self
    }
}

/// An HTTP response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn new(status: u16, body: impl Into<Vec<u8>>) -> Self {
        HttpResponse {
            status,
            headers: Vec::new(),
            body: body.into(),
        }
    }
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
    pub fn body_string(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
    /// Parse the body as JSON into `T`.
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T, String> {
        serde_json::from_slice(&self.body).map_err(|e| e.to_string())
    }
}

// ============================ Transport seam ============================

/// A transport failure. [`Unavailable`] is the **air-gap soft-degrade** signal: the network/proxy is
/// unreachable, so the caller should degrade the feature gracefully rather than fail the whole turn.
///
/// [`Unavailable`]: TransportError::Unavailable
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    Unavailable(String),
    Timeout,
    Transport(String),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportError::Unavailable(m) => write!(f, "connector transport unavailable: {m}"),
            TransportError::Timeout => f.write_str("connector transport timed out"),
            TransportError::Transport(m) => write!(f, "connector transport error: {m}"),
        }
    }
}
impl std::error::Error for TransportError {}

/// Executes an [`HttpRequest`]. Production is [`ReqwestTransport`]; tests use [`StubTransport`].
pub trait HttpTransport: Send + Sync {
    fn send(&self, request: &HttpRequest) -> Result<HttpResponse, TransportError>;
}

/// Air-gap configuration: outbound cloud calls route through a forward proxy (e.g. the web02 Squid).
#[derive(Debug, Clone, Default)]
pub struct ProxyConfig {
    /// `None` = direct. `Some(url)` = route all HTTP(S) through this forward proxy.
    pub proxy_url: Option<String>,
}

impl ProxyConfig {
    pub fn direct() -> Self {
        ProxyConfig { proxy_url: None }
    }
    pub fn via(url: impl Into<String>) -> Self {
        ProxyConfig {
            proxy_url: Some(url.into()),
        }
    }
    /// Resolve from the environment: `LLM_PROXY_URL` (preferred) then `HTTPS_PROXY`.
    pub fn from_env() -> Self {
        let proxy_url = std::env::var("LLM_PROXY_URL")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| std::env::var("HTTPS_PROXY").ok().filter(|s| !s.is_empty()));
        ProxyConfig { proxy_url }
    }
}

/// A programmable in-memory transport for tests + the DoD matrix. Records every request sent, and
/// returns queued responses/errors in order (falling back to `200` empty when the queue is drained).
/// Cheap to clone — clones share state, so a test can hold a handle after moving one into an invoker.
#[derive(Clone, Default)]
pub struct StubTransport {
    inner: Arc<Mutex<StubInner>>,
}

#[derive(Default)]
struct StubInner {
    queued: std::collections::VecDeque<Result<HttpResponse, TransportError>>,
    sent: Vec<HttpRequest>,
}

impl StubTransport {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn push_response(&self, resp: HttpResponse) -> &Self {
        self.inner.lock().expect("stub").queued.push_back(Ok(resp));
        self
    }
    pub fn push_error(&self, err: TransportError) -> &Self {
        self.inner.lock().expect("stub").queued.push_back(Err(err));
        self
    }
    /// The requests the invoker actually sent (post-admission, post-egress, with auth injected).
    pub fn sent(&self) -> Vec<HttpRequest> {
        self.inner.lock().expect("stub").sent.clone()
    }
    pub fn sent_count(&self) -> usize {
        self.inner.lock().expect("stub").sent.len()
    }
}

impl HttpTransport for StubTransport {
    fn send(&self, request: &HttpRequest) -> Result<HttpResponse, TransportError> {
        let mut inner = self.inner.lock().expect("stub");
        inner.sent.push(request.clone());
        inner
            .queued
            .pop_front()
            .unwrap_or_else(|| Ok(HttpResponse::new(200, Vec::new())))
    }
}

// ============================ Encoding helpers ============================

/// RFC 3986 unreserved stays; everything else is percent-encoded (path segments, form values).
const ENCODE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

fn enc(s: &str) -> String {
    utf8_percent_encode(s, ENCODE).to_string()
}

/// application/x-www-form-urlencoded body from key/value pairs.
pub fn form_urlencode(pairs: &[(String, String)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", enc(k), enc(v)))
        .collect::<Vec<_>>()
        .join("&")
}

// ============================ Token source seam ============================

/// Supplies a valid access token for (user, connector), refreshing if needed. The composition binds
/// this to the vault (#2, for API-token connectors) or the refresh coordinator (#4, for OAuth).
///
/// Multi-tenant deployments MUST resolve on the design's `(tenant, jwt.sub, connector)` key, so the
/// USE path resolves the same key the OAuth-callback write path sealed under. The tenant-scoped
/// [`access_token_in`](TokenSource::access_token_in) is the multi-tenant entrypoint; the legacy
/// [`access_token`](TokenSource::access_token) resolves in the [`DEFAULT_TENANT`] and defaults to
/// delegating to it, so a single-tenant source needs to implement only one method.
pub trait TokenSource: Send + Sync {
    /// Tenant-scoped resolution — the multi-tenant-correct entrypoint. Defaults to
    /// [`access_token`](TokenSource::access_token) (which resolves in the [`DEFAULT_TENANT`]) so
    /// existing single-tenant sources keep working unchanged; a multi-tenant source overrides this.
    fn access_token_in(
        &self,
        _tenant: &str,
        user: &str,
        connector: &str,
        now_unix: u64,
    ) -> Result<String, String> {
        self.access_token(user, connector, now_unix)
    }

    /// Resolve an access token in the [`DEFAULT_TENANT`] (single-tenant / unscoped callers).
    fn access_token(&self, user: &str, connector: &str, now_unix: u64) -> Result<String, String>;
}

/// A fixed token (tests, or a single-tenant API-token connector). Tenant-agnostic by design: the
/// same static token is returned for every tenant (it is not a multi-tenant secret store).
pub struct StaticTokenSource(pub String);
impl TokenSource for StaticTokenSource {
    fn access_token(&self, _user: &str, _connector: &str, _now: u64) -> Result<String, String> {
        Ok(self.0.clone())
    }
}

/// Bridges the #4 refresh coordinator to the token source: always hands out a fresh access token.
/// Tenant-aware — it resolves and refreshes on the tenant-scoped `(tenant, user, connector)` key so
/// a token minted for one tenant is never handed to (or refreshed for) another.
///
/// `needs_hot_wiring` (round-15 gap: "refresh-under-lock not on served default path"): construct the
/// inner coordinator via [`RefreshCoordinator::served_default`](ainxt_refresh::RefreshCoordinator::served_default)
/// (the REAL distributed double-checked-locking protocol, not the process-local
/// `InMemoryRefreshLock`) and wrap it here; the reserved daemon composition root
/// (`ainxt-runtimed::mounts::build_connector_invoker`) constructs its `TokenSource` as a
/// `StaticTokenSource` today — swapping in `CoordinatorTokenSource::new(RefreshCoordinator::served_default(..))`
/// puts refresh-under-lock on the served default path.
pub struct CoordinatorTokenSource {
    coordinator: RefreshCoordinator,
}
impl CoordinatorTokenSource {
    pub fn new(coordinator: RefreshCoordinator) -> Self {
        CoordinatorTokenSource { coordinator }
    }
}
impl TokenSource for CoordinatorTokenSource {
    fn access_token_in(
        &self,
        tenant: &str,
        user: &str,
        _connector: &str,
        now_unix: u64,
    ) -> Result<String, String> {
        self.coordinator
            .ensure_fresh_in(tenant, user, now_unix)
            .map_err(|e| e.to_string())
    }
    fn access_token(&self, user: &str, _connector: &str, now_unix: u64) -> Result<String, String> {
        self.coordinator
            .ensure_fresh(user, now_unix)
            .map_err(|e| e.to_string())
    }
}

// ============================ Verified-identity tenant binding ============================

/// Proof that a tenant id originated from a **verified identity claim** — the authenticator validated
/// the JWT signature and read the tenant from the trusted `tid`/`tenant` claim. Only the identity/auth
/// layer mints this; a request body cannot. It exists so the tenant axis can be *bound to the verified
/// caller* rather than passed as an independent, self-assertable argument.
#[derive(Debug, Clone)]
pub struct VerifiedTenant(String);

impl VerifiedTenant {
    /// Mint from an authenticated claim. **Caller contract:** call this only after the JWT signature
    /// and the `tid`/`tenant` claim have been verified by the authenticator seam — never from
    /// request-body input. (Kept as an explicit constructor, not `From<&str>`, so a self-asserted
    /// string cannot silently become a "verified" tenant at a call site.)
    pub fn from_authenticated_claim(tenant: impl Into<String>) -> Self {
        VerifiedTenant(tenant.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A caller identity whose **tenant is bound to the verified principal** — not a free request
/// parameter. The multi-tenant token store keys on `(tenant, jwt.sub, connector)`; if the tenant were
/// an argument sitting *next to* the principal, a caller could pair `principal = alice` with
/// `tenant = "tenant-b"` and reach a different tenant's sealed tokens. `BoundPrincipal` closes that
/// confused-deputy gap by carrying the tenant WITH the identity: it is constructed only from a
/// [`VerifiedTenant`] (which the authenticator mints from the verified claim), so the connector
/// USE/OAuth entrypoints that take a `&BoundPrincipal` cannot be handed a tenant that disagrees with
/// the authenticated caller. Single-tenant deployments use [`single_tenant`](Self::single_tenant),
/// which binds the [`DEFAULT_TENANT`] sentinel (never a real, collidable tenant id).
///
/// GAP-AUDIT token-durability (gap6, item 2) — `BoundPrincipal`/[`VerifiedTenant`] and the `_for`
/// entrypoints that take them (`ConnectorGateway::authorized_for`/`begin_authorization_for`,
/// `ConnectorInvoker::invoke_for`) have ZERO callers in the real composition root
/// (`ainxt-runtimed`/`ainxt-server`): the served `/connectors/*` routes
/// (`crates/ainxt-server/src/lib.rs`'s `connectors_list_handler`/`connector_authorize_handler`/
/// `connector_ensure_scopes_handler`/`connector_deauthorize_handler`) all call the bare
/// `authorized`/`begin_authorization`/`step_up_consent_if_needed`/`deauthorize` methods (plain
/// `&str` tenant) instead. This is not an unguarded hole, though: those routes resolve the tenant
/// via `ainxt-server`'s own `connector_tenant()` helper — preferring the VERIFIED
/// `principal.department` JWT claim over the spoofable `X-AInxt-Tenant` header — which is a THIRD,
/// independently-built restatement of the exact same "bind the tenant to the verified caller, not a
/// free parameter" idea `BoundPrincipal` implements, proven end-to-end by
/// `wire_conn_07_tenant_resolution_prefers_verified_claim_over_spoofable_header` in `ainxt-server`.
/// `BoundPrincipal` is genuinely equivalent in strength (both are "caller must only construct this
/// from an already-verified claim" contracts, not runtime-checked ones — see
/// `ainxt_token::TenantClaim`'s identical doc note for the same reasoning) — legitimately superseded,
/// unreachable-in-production code kept as a stronger-typed public primitive for a caller of this
/// crate that does NOT route through `ainxt-server`'s own handlers.
#[derive(Debug, Clone)]
pub struct BoundPrincipal {
    principal: Principal,
    tenant: String,
}

impl BoundPrincipal {
    /// Bind a verified `principal` to its [`VerifiedTenant`] (multi-tenant deployments).
    pub fn new(principal: Principal, tenant: VerifiedTenant) -> Self {
        BoundPrincipal {
            principal,
            tenant: tenant.0,
        }
    }
    /// Bind in the [`DEFAULT_TENANT`] (single-tenant / unscoped deployments).
    pub fn single_tenant(principal: Principal) -> Self {
        BoundPrincipal {
            principal,
            tenant: DEFAULT_TENANT.to_string(),
        }
    }
    pub fn principal(&self) -> &Principal {
        &self.principal
    }
    pub fn tenant(&self) -> &str {
        &self.tenant
    }
}

// ============================ The call pipeline ============================

/// A connector call, fully described by an adapter but not yet admitted or dispatched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedCall {
    pub connector: ConnectorId,
    /// Logical operation (drives authz + audit), e.g. `"read"` / `"write"`.
    pub op: String,
    /// The resource acted on (e.g. a repo/issue id), for fine-grained authz. Never logged verbatim.
    pub resource: Option<String>,
    pub request: HttpRequest,
    /// Whether the request body must pass egress DLP (writes carry user content outward).
    pub egress_body: bool,
}

/// The result of a successful dispatch.
#[derive(Debug, Clone)]
pub struct CallOutcome {
    pub response: HttpResponse,
    /// Always [`Provenance::Connector`] — the body is untrusted and must be injection-scanned.
    pub provenance: Provenance,
    /// How many secrets the egress DLP redacted from the outbound body.
    pub egress_redactions: usize,
}

/// Why a connector call was refused or failed.
#[derive(Clone, PartialEq, Eq)]
pub enum ConnectorCallError {
    /// On-behalf-of authz / org-dept policy denied the call (never reached the network).
    Admission(ConnectorError),
    /// The data-class ceiling refused the egress (regulated data must not leave).
    Egress(ConnectorError),
    /// The payment action boundary (ADR-016 §4 Layers 5+6) refused the call before dispatch: the
    /// resolved call classified as payment-initiation (settlement-perimeter destination / settlement
    /// resource / value-moving payload), or the destination is not on the capability's egress
    /// allow-list. Fail-closed — nothing reached the network; a
    /// [`PaymentInitiation`](DispatchDenied::PaymentInitiation) denial is the §4.6 signal on which the
    /// runtime aborts the turn, quarantines the capability, revokes the acting identity, and raises an
    /// incident.
    PaymentBoundary(DispatchDenied),
    /// No valid token could be obtained (re-authorization needed).
    Token(String),
    /// Network/proxy unreachable — SOFT-DEGRADE (the feature is unavailable this turn).
    Unavailable(String),
    /// A non-degradable transport error.
    Transport(String),
}

impl ConnectorCallError {
    /// Whether this is an air-gap soft-degrade (caller should degrade, not fail the whole turn).
    pub fn is_soft_degrade(&self) -> bool {
        matches!(self, ConnectorCallError::Unavailable(_))
    }

    /// Returns a sanitized, client-safe error message that does **not** include internal details
    /// such as token values, connector names, vault error strings, or provider URLs.
    ///
    /// Use this instead of [`Display`](std::fmt::Display) / `.to_string()` whenever the message
    /// will be sent to an external caller (HTTP response body, log line visible to tenants, etc.).
    /// Internal-only logging may still use the full `Display` form.
    pub fn sanitized_client_message(&self) -> &'static str {
        match self {
            // Admission errors are safe to surface: they describe policy decisions, not secrets.
            ConnectorCallError::Admission(_) => "admission denied",
            ConnectorCallError::Egress(_) => "egress refused",
            ConnectorCallError::PaymentBoundary(_) => "payment boundary refused",
            // Token and Transport errors may contain internal details (connector names, vault
            // error strings, OAuth provider URLs, token parse output). Return a generic message.
            ConnectorCallError::Token(_) => "token error",
            ConnectorCallError::Unavailable(_) => "connector unavailable",
            ConnectorCallError::Transport(_) => "transport error",
        }
    }
}

impl std::fmt::Display for ConnectorCallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectorCallError::Admission(e) => write!(f, "admission denied: {e}"),
            ConnectorCallError::Egress(e) => write!(f, "egress refused: {e}"),
            ConnectorCallError::PaymentBoundary(d) => write!(f, "payment boundary refused: {d}"),
            // Do NOT emit the inner string: the Token variant is considered a secret-bearing
            // type by static analysis (Checkmarx: Secret Leak in Error Messages). The inner
            // payload is intentionally suppressed here so that Display / to_string() never
            // propagates it to callers. Use Debug for internal diagnostics only.
            ConnectorCallError::Token(_) => write!(f, "token error"),
            ConnectorCallError::Unavailable(m) => write!(f, "connector unavailable: {m}"),
            ConnectorCallError::Transport(m) => write!(f, "transport error: {m}"),
        }
    }
}
/// Manual `Debug` impl that mirrors `Display` for the `Token` variant.
///
/// The auto-derived `Debug` would emit the inner `String` payload verbatim, which Checkmarx's
/// taint engine (Secret Leak in Error Messages) correctly identifies as a potential secret leak:
/// the `Token` variant is named after a credential type and its `String` field is treated as a
/// taint source. By suppressing the inner value here — exactly as `Display` does — we close the
/// only remaining taint path that the scanner can follow from the construction site
/// (`Err(ConnectorCallError::Token(...))`) to an output sink.
///
/// Internal diagnostics that genuinely need the raw message should log it explicitly before
/// wrapping it in the error, not rely on `{:?}` formatting of this type.
impl std::fmt::Debug for ConnectorCallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectorCallError::Admission(e) => f.debug_tuple("Admission").field(e).finish(),
            ConnectorCallError::Egress(e) => f.debug_tuple("Egress").field(e).finish(),
            ConnectorCallError::PaymentBoundary(d) => {
                f.debug_tuple("PaymentBoundary").field(d).finish()
            }
            // Suppress the inner String: it may contain OAuth error details, connector
            // identifiers, or vault messages that must not appear in logs or error output.
            ConnectorCallError::Token(_) => f.write_str("Token(<redacted>)"),
            ConnectorCallError::Unavailable(m) => {
                f.debug_tuple("Unavailable").field(m).finish()
            }
            ConnectorCallError::Transport(m) => f.debug_tuple("Transport").field(m).finish(),
        }
    }
}

impl std::error::Error for ConnectorCallError {}

/// The single path every connector call takes: admission → egress control → token → dispatch →
/// untrusted-tag. Holds the shared [`ConnectorRuntime`] (safety seams), a transport, and a token
/// source.
pub struct ConnectorInvoker {
    runtime: Arc<ConnectorRuntime>,
    transport: Box<dyn HttpTransport>,
    tokens: Box<dyn TokenSource>,
    /// The payment action boundary (ADR-016 §4 Layers 5+6). Screened on **every** outbound call
    /// before any bytes leave — the settlement-perimeter deny-list + payment-initiation tripwire.
    /// Defaults to [`EgressGuard::default`] (the canonical reserved perimeter); a deployment may
    /// override it with [`with_egress_guard`](ConnectorInvoker::with_egress_guard).
    egress_guard: EgressGuard,
    /// The §4.6 graduated-tripwire remediator the guard's [`GraduatedResponse`] is *enacted* against
    /// on the live path. When the Layer-6 tripwire fires (a mis-declared / dynamically-built payment-
    /// initiation call), the invoker builds the full graduated response and enacts all three
    /// escalation actions through this seam — quarantine the capability, revoke the acting identity,
    /// raise an incident — before returning the fail-closed denial. This is what makes the remediation
    /// *enforced*, not advisory. Defaults to the recording [`RecordingRemediation`] so the three
    /// actions are observable/auditable on the OSS build; a deployment swaps a control-plane-backed
    /// implementor via [`with_tripwire_remediation`](ConnectorInvoker::with_tripwire_remediation).
    tripwire: Arc<dyn TripwireRemediation>,
}

impl ConnectorInvoker {
    pub fn new(
        runtime: Arc<ConnectorRuntime>,
        transport: Box<dyn HttpTransport>,
        tokens: Box<dyn TokenSource>,
    ) -> Self {
        ConnectorInvoker {
            runtime,
            transport,
            tokens,
            egress_guard: EgressGuard::default(),
            tripwire: Arc::new(RecordingRemediation::new()),
        }
    }

    /// Override the payment action boundary (custom deployments / tests). The guard runs on every
    /// outbound call regardless — this only swaps the reserved-perimeter policy behind it.
    pub fn with_egress_guard(mut self, guard: EgressGuard) -> Self {
        self.egress_guard = guard;
        self
    }

    /// Override the §4.6 graduated-tripwire remediator (deployments bind the real identity control-
    /// plane + incident register here). The remediator is enacted on **every** payment-initiation
    /// tripwire regardless — this only swaps what the three escalation actions map onto.
    pub fn with_tripwire_remediation(mut self, remediator: Arc<dyn TripwireRemediation>) -> Self {
        self.tripwire = remediator;
        self
    }

    /// The live §4.6 remediator (for wiring / assertions).
    pub fn tripwire_remediation(&self) -> &Arc<dyn TripwireRemediation> {
        &self.tripwire
    }

    /// GAP-AUDIT connectors #4 — the tamper-evidence anchor of the wrapped [`ConnectorRuntime`]'s
    /// audit sink (see [`ConnectorRuntime::audit_head`]). `None` for a non-chained sink.
    pub fn audit_head(&self) -> Option<String> {
        self.runtime.audit_head()
    }

    /// GAP-FIX connectors — actually verify the wrapped [`ConnectorRuntime`]'s tamper-evidence chain
    /// (see [`ConnectorRuntime::audit_verify`]), not just read its anchor.
    pub fn audit_verify(&self) -> Result<(), usize> {
        self.runtime.audit_verify()
    }

    /// Admit, egress-check, authenticate, and dispatch a prepared call for `principal` at `now_unix`
    /// under the turn's `data_class`, resolving the token in the [`DEFAULT_TENANT`]. Multi-tenant
    /// deployments must call [`invoke_in`](Self::invoke_in) so the USE path resolves the same
    /// `(tenant, jwt.sub, connector)` key the OAuth-callback write path sealed under.
    pub fn invoke(
        &self,
        principal: &Principal,
        now_unix: u64,
        data_class: DataClass,
        prepared: PreparedCall,
    ) -> Result<CallOutcome, ConnectorCallError> {
        self.invoke_in(DEFAULT_TENANT, principal, now_unix, data_class, prepared)
    }

    /// **Identity-bound** USE path — the tenant is taken FROM the verified caller
    /// ([`BoundPrincipal`]), never a caller-supplied argument, so a self-asserted tenant that
    /// disagrees with the authenticated principal is structurally impossible (there is no tenant
    /// parameter to disagree). This is the entrypoint a multi-tenant surface should call; it delegates
    /// to [`invoke_in`](Self::invoke_in) with `bound.tenant()` + `bound.principal()`.
    pub fn invoke_for(
        &self,
        bound: &BoundPrincipal,
        now_unix: u64,
        data_class: DataClass,
        prepared: PreparedCall,
    ) -> Result<CallOutcome, ConnectorCallError> {
        self.invoke_in(
            bound.tenant(),
            bound.principal(),
            now_unix,
            data_class,
            prepared,
        )
    }

    /// Tenant-scoped USE path. Identical to [`invoke`](Self::invoke) except the access token is
    /// resolved on the design's `(tenant, jwt.sub, connector)` key — the token a different tenant
    /// sealed for the same `(user, connector)` is never reachable here. Fail-closed: an admission or
    /// egress denial never reaches the network; an [`Unavailable`](ConnectorCallError::Unavailable)
    /// result is a soft-degrade. The admission/egress/payment-boundary/audit seams are unchanged and
    /// still run on every call.
    pub fn invoke_in(
        &self,
        tenant: &str,
        principal: &Principal,
        now_unix: u64,
        data_class: DataClass,
        prepared: PreparedCall,
    ) -> Result<CallOutcome, ConnectorCallError> {
        let connector = prepared.connector.clone();
        // Captured for the payment-boundary tripwire (§4.5 resource-key signature) before the
        // request is moved below.
        let resource_key = prepared.resource.clone().unwrap_or_default();

        // 1. Admission (OBO authz + org/dept policy). A denial stops here — nothing is sent.
        self.runtime
            .authorize_use(
                principal,
                &connector,
                &prepared.op,
                prepared.resource.as_deref(),
            )
            .map_err(ConnectorCallError::Admission)?;

        // 2. Egress control on EVERY call (data-class ceiling), redacting write bodies (DLP).
        let payload = if prepared.egress_body {
            prepared
                .request
                .body
                .as_ref()
                .map(|b| String::from_utf8_lossy(b).into_owned())
                .unwrap_or_default()
        } else {
            String::new()
        };
        let filtered = self
            .runtime
            .guard_egress(principal, &connector, &prepared.op, data_class, &payload)
            .map_err(ConnectorCallError::Egress)?;

        let mut request = prepared.request;
        if prepared.egress_body && request.body.is_some() {
            request.body = Some(filtered.payload.into_bytes());
        }

        // 2b. Screen the request URL itself for secrets/PANs (gap T, URL coverage). Read requests
        //     carry no body but their URLs embed user-controlled path/query data; a URL cannot be
        //     redacted in flight, so a detected secret is a fail-closed egress refusal.
        self.runtime
            .screen_url(principal, &connector, &prepared.op, &request.url)
            .map_err(ConnectorCallError::Egress)?;

        // 2c. Payment action boundary (ADR-016 §4 Layers 5+6) — the settlement-perimeter deny-list
        //     and the payment-initiation tripwire, screened on EVERY outbound call before any bytes
        //     leave. Admission (step 1) is the access-control gate; THIS is the value-movement gate,
        //     enforced independently of what a capability declared. Fail-closed: a settlement-
        //     perimeter destination is un-allow-listable by construction, and a call that classifies
        //     as payment-initiation (by destination, resource_key, or payload) is refused pre-
        //     dispatch. On a PaymentInitiation denial the runtime aborts the turn, quarantines the
        //     capability, revokes the acting identity, and raises an incident (§4.6).
        let mut allow_list = self.egress_guard.new_allow_list();
        // The resolved destination is already admitted (step 1 ran the OBO authz + dept policy), so
        // it is added to this call's allow-list — EXCEPT the reserved settlement perimeter, which
        // `allow` refuses to add; such a host is then denied by the Layer-6 tripwire below.
        let _ = allow_list.allow(&request.url);
        let outbound = OutboundCall {
            destination: request.url.clone(),
            resource_key,
            // Connector adapters carry no structured rails-message/UPI semantics; the connector
            // path's payment signatures are the destination + resource_key. Benign here is honest.
            payload: PayloadSignal::Benign,
        };
        if let Err(denied) = self.egress_guard.screen(&outbound, &allow_list) {
            // A Layer-6 payment-initiation tripwire (mis-declared / dynamically-built value-moving
            // call) is NOT a plain policy denial: §4.6 mandates a GRADUATED response, enacted here on
            // the LIVE egress path as one enforced decision — abort the turn (this fail-closed return;
            // no bytes leave) + quarantine the offending capability + revoke the acting identity
            // (ADR-022 §17) + raise a security incident (ADR-017). The graduated response is built and
            // driven through the runtime remediator seam BEFORE the denial is returned, so the three
            // escalation actions are always emitted — never merely described. A plain allow-list miss
            // (Layer 5, `NotAllowListed`) is a policy denial and is NOT escalated.
            if let DispatchDenied::PaymentInitiation(ref boundary_denied) = denied {
                let capability_id = format!("connector.{}", connector.as_str());
                let turn_id = format!(
                    "connector-dispatch:{}:{}",
                    connector.as_str(),
                    principal.user_id
                );
                let response = GraduatedResponse::plan(
                    boundary_denied,
                    turn_id,
                    &capability_id,
                    &principal.user_id,
                );
                let receipt = response.enact(self.tripwire.as_ref());
                debug_assert!(
                    receipt.is_complete(),
                    "§4.6 graduated remediation must be total (abort+quarantine+revoke+incident)"
                );
            }
            return Err(ConnectorCallError::PaymentBoundary(denied));
        }

        // 3. Resolve a valid token (refreshing if needed) — AFTER egress, so the token is never
        //    exposed to the DLP scanner.
        let token = self
            .tokens
            .access_token_in(tenant, &principal.user_id, connector.as_str(), now_unix)
            // Discard the inner error string from the token coordinator: it may contain
            // internal details (vault paths, provider URLs) that must not be propagated.
            // Use a fixed static message instead (Checkmarx: Secret Leak in Error Messages).
            .map_err(|_| ConnectorCallError::Token("token acquisition failed".to_string()))?;
        request
            .headers
            .push(("Authorization".into(), format!("Bearer {token}")));

        // 4. Dispatch. Connect/timeout failures are soft-degrade signals.
        let response = self.transport.send(&request).map_err(|e| match e {
            TransportError::Unavailable(m) => ConnectorCallError::Unavailable(m),
            TransportError::Timeout => ConnectorCallError::Unavailable("timeout".into()),
            TransportError::Transport(m) => ConnectorCallError::Transport(m),
        })?;

        // 5. The response is untrusted data (indirect-injection surface).
        Ok(CallOutcome {
            response,
            provenance: self.runtime.ingress_provenance(),
            egress_redactions: filtered.redactions,
        })
    }
}

// ============================ Adapters ============================

/// GitLab (REST API v4) — source control connector.
pub struct GitLab {
    base_url: String,
}
impl GitLab {
    pub fn new(base_url: impl Into<String>) -> Self {
        GitLab {
            base_url: base_url.into(),
        }
    }
    fn cid() -> ConnectorId {
        ConnectorId::from("gitlab")
    }
    /// GET a project by id or URL-encoded `group/repo` path.
    pub fn get_project(&self, project: &str) -> PreparedCall {
        PreparedCall {
            connector: Self::cid(),
            op: "read".into(),
            resource: Some(project.to_string()),
            request: HttpRequest::get(format!(
                "{}/api/v4/projects/{}",
                self.base_url,
                enc(project)
            )),
            egress_body: false,
        }
    }
    /// GET a repository file's metadata/content at `ref`.
    pub fn get_file(&self, project: &str, path: &str, git_ref: &str) -> PreparedCall {
        PreparedCall {
            connector: Self::cid(),
            op: "read".into(),
            resource: Some(project.to_string()),
            request: HttpRequest::get(format!(
                "{}/api/v4/projects/{}/repository/files/{}?ref={}",
                self.base_url,
                enc(project),
                enc(path),
                enc(git_ref)
            )),
            egress_body: false,
        }
    }
    /// POST a note to a merge request (write — body passes egress DLP).
    pub fn post_mr_note(&self, project: &str, mr_iid: u64, body: &str) -> PreparedCall {
        let json = serde_json::json!({ "body": body }).to_string();
        PreparedCall {
            connector: Self::cid(),
            op: "write".into(),
            resource: Some(project.to_string()),
            request: HttpRequest::post_json(
                format!(
                    "{}/api/v4/projects/{}/merge_requests/{mr_iid}/notes",
                    self.base_url,
                    enc(project)
                ),
                json,
            ),
            egress_body: true,
        }
    }
}

/// Jira Cloud (REST API v3).
pub struct Jira {
    base_url: String,
}
impl Jira {
    pub fn new(base_url: impl Into<String>) -> Self {
        Jira {
            base_url: base_url.into(),
        }
    }
    fn cid() -> ConnectorId {
        ConnectorId::from("jira")
    }
    pub fn get_issue(&self, key: &str) -> PreparedCall {
        PreparedCall {
            connector: Self::cid(),
            op: "read".into(),
            resource: Some(key.to_string()),
            request: HttpRequest::get(format!("{}/rest/api/3/issue/{}", self.base_url, enc(key))),
            egress_body: false,
        }
    }
    pub fn add_comment(&self, key: &str, body: &str) -> PreparedCall {
        let json = serde_json::json!({ "body": body }).to_string();
        PreparedCall {
            connector: Self::cid(),
            op: "write".into(),
            resource: Some(key.to_string()),
            request: HttpRequest::post_json(
                format!("{}/rest/api/3/issue/{}/comment", self.base_url, enc(key)),
                json,
            ),
            egress_body: true,
        }
    }
}

/// Microsoft Graph (v1.0).
pub struct Graph {
    base_url: String,
}
impl Graph {
    /// Default Graph base (`https://graph.microsoft.com`).
    pub fn new() -> Self {
        Graph {
            base_url: "https://graph.microsoft.com".into(),
        }
    }
    pub fn with_base(base_url: impl Into<String>) -> Self {
        Graph {
            base_url: base_url.into(),
        }
    }
    fn cid() -> ConnectorId {
        ConnectorId::from("graph")
    }
    pub fn get_me(&self) -> PreparedCall {
        PreparedCall {
            connector: Self::cid(),
            op: "read".into(),
            resource: None,
            request: HttpRequest::get(format!("{}/v1.0/me", self.base_url)),
            egress_body: false,
        }
    }
    pub fn list_messages(&self, top: u32) -> PreparedCall {
        PreparedCall {
            connector: Self::cid(),
            op: "read".into(),
            resource: None,
            request: HttpRequest::get(format!("{}/v1.0/me/messages?$top={top}", self.base_url)),
            egress_body: false,
        }
    }
    /// POST /me/sendMail (write — the message body passes egress DLP).
    pub fn send_mail(&self, to: &str, subject: &str, body: &str) -> PreparedCall {
        let json = serde_json::json!({
            "message": {
                "subject": subject,
                "body": { "contentType": "Text", "content": body },
                "toRecipients": [ { "emailAddress": { "address": to } } ]
            }
        })
        .to_string();
        PreparedCall {
            connector: Self::cid(),
            op: "write".into(),
            resource: None,
            request: HttpRequest::post_json(format!("{}/v1.0/me/sendMail", self.base_url), json),
            egress_body: true,
        }
    }
}

impl Default for Graph {
    fn default() -> Self {
        Self::new()
    }
}

// ============================ Refresh executor (HTTP) ============================

/// Executes an OAuth refresh over the transport: POSTs the form to the token endpoint and parses the
/// response (an OAuth error response, e.g. `invalid_grant`, is parsed too, not swallowed).
pub struct HttpRefreshExecutor {
    transport: Box<dyn HttpTransport>,
}
impl HttpRefreshExecutor {
    pub fn new(transport: Box<dyn HttpTransport>) -> Self {
        HttpRefreshExecutor { transport }
    }
}
impl RefreshExecutor for HttpRefreshExecutor {
    fn execute(&self, request: &TokenRequest) -> Result<TokenSet, String> {
        let mut http = HttpRequest::post(request.token_endpoint.clone());
        http.headers.push((
            "Content-Type".into(),
            "application/x-www-form-urlencoded".into(),
        ));
        http.body = Some(form_urlencode(&request.form).into_bytes());
        let resp = self.transport.send(&http).map_err(|e| e.to_string())?;
        // Note: OAuth error responses arrive with 4xx + a JSON error object — parse regardless.
        TokenSet::parse(&resp.body_string()).map_err(|e| e.to_string())
    }
}

// ============================ Authorization lifecycle (deauthorize verb) ============================

// GAP-AUDIT connector-http item 2 — `ConnectorLifecycle` (the deauthorize verb + "list a user's
// authorized connectors" self-service view) was a duplicate of [`ConnectorGateway`]'s own
// `deauthorize`/`authorized` methods, built earlier and never wired to a production caller (zero
// references outside this crate's own `mod tests`). Investigation confirmed `ConnectorGateway` is a
// strict superset, not a partial one:
//   * `ConnectorGateway::deauthorize` — SAME owner-or-admin `may_act_on` check, SAME audit-on-every-
//     outcome discipline — PLUS tenant scoping (`vault.revoke_in(tenant, ..)`); `ConnectorLifecycle`
//     called the non-tenant-scoped `vault.revoke`, which in a multi-tenant deployment resolves against
//     whatever tenant that particular `TokenVault` handle happens to be opened against — a correctness
//     gap this superseding version does not have. Wired to the real route:
//     `DELETE /connectors/{id}` → `ainxt-server::connector_deauthorize_handler` (`lib.rs:6329`).
//   * `ConnectorGateway::authorized`/`authorized_for` — the "list my authorized connectors" self-
//     service view `ConnectorLifecycle::authorized_connectors` provided, also tenant-scoped (and the
//     identity-bound `authorized_for` variant additionally can't be tricked into another tenant's
//     grants via a self-asserted tenant param). Wired to the real route: `GET /connectors` →
//     `ainxt-server::connectors_list_handler` (`lib.rs:6215`), combined with `ConnectorGateway::catalog`.
// So there was no unique capability left to migrate — `ConnectorLifecycle` was removed rather than
// left as a second, weaker (non-tenant-scoped) implementation of the identical contract that a future
// caller could accidentally wire up instead of the real one.

// ============================ Connector surface (gateway façade) ============================

use std::collections::BTreeMap;

use ainxt_connector::AuthKind;
use ainxt_oauth::{
    begin_and_store, validate_callback, CallbackError, OAuthProvider, PendingAuthStore,
};

/// Which (tenant, user, connector) a live OAuth flow belongs to. The IdP echoes only an opaque
/// `state`, so the gateway remembers, per `state`, who started the flow — consumed single-use on the
/// callback. Kept here (not in the transport-agnostic OAuth core) because ownership is a server concern.
#[derive(Debug, Clone)]
struct FlowOwner {
    tenant: String,
    user: String,
    connector: String,
}

/// The output of starting an authorization: where to send the user, and the `state` the IdP echoes.
#[derive(Debug, Clone)]
pub struct AuthorizationStart {
    pub authorize_url: String,
    pub state: String,
}

/// The result of a completed callback: the connector now authorized, and the scopes actually granted
/// (fewer than requested ⇒ the caller may trigger incremental consent).
#[derive(Debug, Clone)]
pub struct AuthorizationComplete {
    pub connector: String,
    pub granted_scopes: Vec<String>,
}

/// The **Connector Runtime surface** a gateway (web) or desktop renderer drives — the single place
/// OAuth is started and the redirect callback is handled, plus catalog/list/deauthorize. Both web and
/// desktop are identical renderers over THIS object (CONN-03): tokens and connector execution live in
/// the runtime, not the client. The parent (`ainxt-server` / `ainxt-runtimed`) mounts HTTP routes
/// onto these methods:
///   * `GET  /connectors`                    → [`catalog`](Self::catalog) + [`authorized`](Self::authorized)
///   * `POST /connectors/{id}/authorize`     → [`begin_authorization`](Self::begin_authorization)
///   * `GET  /connectors/callback`           → [`complete_callback`](Self::complete_callback)
///   * `DELETE /connectors/{id}`             → [`deauthorize`](Self::deauthorize)
///
/// Every OAuth token minted lands ENCRYPTED in the [`TokenVault`], tenant-scoped; the gateway never
/// hands a token to the client. Safety seams (policy/authz/audit) come from the shared
/// [`ConnectorRuntime`], so this surface cannot bypass admission by construction.
pub struct ConnectorGateway {
    runtime: Arc<ConnectorRuntime>,
    vault: TokenVault,
    pending: Box<dyn PendingAuthStore>,
    transport: Box<dyn HttpTransport>,
    /// OAuth provider config per connector id (only for `AuthKind::OAuth2AuthCode` connectors).
    providers: BTreeMap<String, OAuthProvider>,
    owners: Mutex<BTreeMap<String, FlowOwner>>,
    audit: Box<dyn ConnectorAudit>,
    callback_ttl_secs: u64,
}

impl ConnectorGateway {
    pub fn new(
        runtime: Arc<ConnectorRuntime>,
        vault: TokenVault,
        pending: Box<dyn PendingAuthStore>,
        transport: Box<dyn HttpTransport>,
        audit: Box<dyn ConnectorAudit>,
    ) -> Self {
        ConnectorGateway {
            runtime,
            vault,
            pending,
            transport,
            providers: BTreeMap::new(),
            owners: Mutex::new(BTreeMap::new()),
            audit,
            callback_ttl_secs: 600,
        }
    }

    /// Register the OAuth provider config for a connector id (Entra/Graph etc).
    pub fn with_provider(mut self, connector: impl Into<String>, provider: OAuthProvider) -> Self {
        self.providers.insert(connector.into(), provider);
        self
    }

    /// Override the callback TTL (default 600s) — how long a started flow stays completable.
    pub fn with_callback_ttl(mut self, secs: u64) -> Self {
        self.callback_ttl_secs = secs;
        self
    }

    /// GAP-AUDIT connectors #4 — the tamper-evidence anchor of this gateway's OWN audit sink (the
    /// `audit` field, distinct from the wrapped [`ConnectorRuntime`]'s own — see
    /// [`ConnectorRuntime::audit_head`]). `None` for a non-chained sink like
    /// [`InMemoryConnectorAudit`](ainxt_connector::InMemoryConnectorAudit); `Some(hash)` for a
    /// [`HashChainedConnectorAudit`](ainxt_connector::HashChainedConnectorAudit). Exists so a
    /// composition root's own construction choice is directly observable without a concrete-type
    /// handle into this struct's private `audit` field.
    pub fn audit_head(&self) -> Option<String> {
        self.audit.head_hash()
    }

    /// GAP-FIX connectors — actually verify this gateway's OWN tamper-evidence chain (distinct from
    /// the wrapped [`ConnectorRuntime`]'s own — see [`Self::audit_head`]), not just read its anchor.
    pub fn audit_verify(&self) -> Result<(), usize> {
        self.audit.verify()
    }

    /// The static catalog of connector ids the runtime knows about (`GET /connectors`).
    pub fn catalog(&self) -> Vec<String> {
        self.runtime
            .registry()
            .ids()
            .into_iter()
            .map(String::from)
            .collect()
    }

    /// The connectors `target_user` has authorized within `tenant`. Owner-or-admin only.
    pub fn authorized(
        &self,
        tenant: &str,
        actor: &Principal,
        target_user: &str,
    ) -> Result<Vec<String>, ConnectorCallError> {
        if !Self::may_act_on(actor, target_user) {
            return Err(ConnectorCallError::Admission(
                ConnectorError::NotAuthorized("may only list own connectors".into()),
            ));
        }
        self.vault
            .connectors_for_in(tenant, target_user)
            // Do not forward vault error details to callers (Checkmarx: Secret Leak in Error Messages).
            .map_err(|_| ConnectorCallError::Token("vault read failed".to_string()))
    }

    fn may_act_on(actor: &Principal, target_user: &str) -> bool {
        actor.role == Role::Admin || actor.user_id == target_user
    }

    /// **Identity-bound** variant of [`authorized`](Self::authorized): the tenant is taken from the
    /// verified caller ([`BoundPrincipal`]), so a self-asserted tenant cannot be used to enumerate
    /// another tenant's grants. Lists the connectors `target_user` has authorized in the caller's
    /// verified tenant (owner-or-admin only).
    pub fn authorized_for(
        &self,
        bound: &BoundPrincipal,
        target_user: &str,
    ) -> Result<Vec<String>, ConnectorCallError> {
        self.authorized(bound.tenant(), bound.principal(), target_user)
    }

    /// **Identity-bound** variant of [`begin_authorization`](Self::begin_authorization): the OAuth flow
    /// (and therefore the tenant the minted token is later sealed under) is bound to the verified
    /// caller's tenant, never a request parameter — so a token can only ever be sealed under the
    /// tenant the authenticator verified for this principal.
    pub fn begin_authorization_for(
        &self,
        bound: &BoundPrincipal,
        connector: &str,
        scopes: &[String],
        now_unix: u64,
    ) -> Result<AuthorizationStart, ConnectorCallError> {
        self.begin_authorization(
            bound.tenant(),
            bound.principal(),
            connector,
            scopes,
            now_unix,
        )
    }

    /// Start an OAuth2 authorization-code + PKCE flow for `principal` on `connector`. Fail-closed:
    /// the connector must be registered, be an OAuth connector, clear admission (policy + OBO authz
    /// for the `authorize` op), and have a provider configured. The returned `state` is stashed
    /// single-use for the callback. `POST /connectors/{id}/authorize`.
    pub fn begin_authorization(
        &self,
        tenant: &str,
        principal: &Principal,
        connector: &str,
        scopes: &[String],
        now_unix: u64,
    ) -> Result<AuthorizationStart, ConnectorCallError> {
        let cid = ConnectorId::from(connector);
        // Must be a known OAuth connector.
        let def = self.runtime.registry().get(&cid).ok_or_else(|| {
            ConnectorCallError::Admission(ConnectorError::UnknownConnector(connector.into()))
        })?;
        if def.auth != AuthKind::OAuth2AuthCode {
            return Err(ConnectorCallError::Token(
                "connector is not an OAuth2 connector".to_string(),
            ));
        }
        // Admission (policy + OBO authz) gates who may connect.
        self.runtime
            .authorize_use(principal, &cid, "authorize", None)
            .map_err(ConnectorCallError::Admission)?;
        let provider = self.providers.get(connector).ok_or_else(|| {
            // Do not include the connector name in the error: it is an internal identifier and
            // must not be leaked into client-visible error messages (Checkmarx: Secret Leak in
            // Error Messages).
            ConnectorCallError::Token("no OAuth provider configured".to_string())
        })?;
        let start = begin_and_store(self.pending.as_ref(), provider, scopes, now_unix)
            .map_err(|_| ConnectorCallError::Token("authorization flow could not be started".to_string()))?;
        self.owners.lock().expect("owners lock").insert(
            start.state.clone(),
            FlowOwner {
                tenant: tenant.to_string(),
                user: principal.user_id.clone(),
                connector: connector.to_string(),
            },
        );
        Ok(AuthorizationStart {
            authorize_url: start.url,
            state: start.state,
        })
    }

    /// Step-up (incremental) consent for the USE path. Before a capability runs a connector op that
    /// needs OAuth `required` scopes, the runtime must know the user actually consented to them — a
    /// stored token that predates a newly-added scope would otherwise fail opaquely at the provider
    /// (403 `insufficient_scope`) mid-turn. This reads the scopes the vault ALREADY holds for
    /// `(tenant, principal.user_id, connector)` **without decrypting the secret** (metadata only),
    /// computes the delta against `required`, and — if anything is missing — begins a fresh
    /// authorize flow for **just the missing scopes** (true incremental consent: Entra/Google
    /// re-prompt only for the delta, not the whole set). The new `state`/PKCE + owner mapping are
    /// persisted exactly as [`begin_authorization`](Self::begin_authorization) does, so the returned
    /// [`AuthorizationStart`] is completable through [`complete_callback`](Self::complete_callback).
    ///
    /// Returns `Ok(None)` when the stored grant already covers `required` (no re-prompt needed — the
    /// capability may proceed straight to the USE path). Fail-closed: an unknown/non-OAuth connector,
    /// an unconfigured provider, or an admission denial is surfaced as an error, never a silent
    /// proceed. A user with **no** stored token for the connector is treated as "nothing granted", so
    /// every required scope is missing and a first-time consent flow is begun.
    ///
    /// `HTTP: POST /connectors/{id}/ensure-scopes` (the parent server mounts this ahead of a USE call
    /// whose capability declares required scopes).
    ///
    /// GAP-AUDIT misc-decisions: this is the PRODUCTION step-up-consent path, not a duplicate of
    /// [`ainxt_oauth::step_up_consent`] — it already reuses that crate's [`ainxt_oauth::missing_scopes`]
    /// for the scope-diff (single source of truth), then composes its OWN "begin" via
    /// [`begin_authorization`](Self::begin_authorization) because a connector flow needs
    /// tenant/`Principal`-scoped admission + vault-metadata reads + atomic owner-mapping persistence
    /// that the bare crate-level `step_up_consent`/`begin` cannot provide (no tenant/vault concept).
    /// Confirmed non-gap; see `ainxt_oauth::step_up_consent`'s doc for the full comparison.
    pub fn step_up_consent_if_needed(
        &self,
        tenant: &str,
        principal: &Principal,
        connector: &str,
        required: &[String],
        now_unix: u64,
    ) -> Result<Option<AuthorizationStart>, ConnectorCallError> {
        // Granted scopes, read from vault metadata WITHOUT opening the sealed secret. Absent token ⇒
        // nothing granted ⇒ every required scope is missing (first-time consent).
        let granted = self
            .vault
            .metadata_in(tenant, &principal.user_id, connector)
            // Do not forward vault error details to callers (Checkmarx: Secret Leak in Error Messages).
            .map_err(|_| ConnectorCallError::Token("vault read failed".to_string()))?
            .map(|m| m.scopes)
            .unwrap_or_default();
        let missing = ainxt_oauth::missing_scopes(&granted, required);
        if missing.is_empty() {
            // Already fully consented — the USE path may proceed with the stored token.
            return Ok(None);
        }
        // Incremental consent: begin a flow for ONLY the missing scopes (admission + provider checks
        // + single-use state/PKCE + owner mapping are all enforced by begin_authorization).
        let start = self.begin_authorization(tenant, principal, connector, &missing, now_unix)?;
        Ok(Some(start))
    }

    /// Handle the IdP redirect callback (`GET /connectors/callback?code&state`). Fail-closed:
    /// the `state` must match a live flow (CSRF), be unexpired, and its PKCE verifier is used to
    /// exchange the `code` for tokens over the transport (air-gap proxy honored by the bound
    /// transport). The minted [`TokenSet`] is sealed into the vault, tenant-scoped. Single-use.
    pub fn complete_callback(
        &self,
        returned_state: &str,
        code: &str,
        now_unix: u64,
    ) -> Result<AuthorizationComplete, ConnectorCallError> {
        // Consume the owner mapping (single-use). Absent ⇒ forged/replayed callback.
        let owner = self
            .owners
            .lock()
            .expect("owners lock")
            .remove(returned_state)
            .ok_or_else(|| {
                ConnectorCallError::Admission(ConnectorError::NotAuthorized(
                    "oauth callback rejected: unknown/forged/replayed state".into(),
                ))
            })?;
        let provider = self.providers.get(&owner.connector).ok_or_else(|| {
            // Do not include the connector name in the error: it is an internal identifier and
            // must not be leaked into client-visible error messages (Checkmarx: Secret Leak in
            // Error Messages).
            ConnectorCallError::Token("no OAuth provider configured".to_string())
        })?;
        // Validate CSRF state + TTL and produce the PKCE-bound exchange request (single-use).
        let validated = validate_callback(
            self.pending.as_ref(),
            provider,
            returned_state,
            code,
            self.callback_ttl_secs,
            now_unix,
        )
        .map_err(|e| match e {
            CallbackError::UnknownState => ConnectorCallError::Admission(
                ConnectorError::NotAuthorized("oauth callback rejected (CSRF)".into()),
            ),
            // Do not forward internal callback error details to callers: they may contain
            // OAuth state, PKCE verifiers, or provider-specific messages (Checkmarx: Secret
            // Leak in Error Messages). Log internally; surface only a generic message.
            _other => ConnectorCallError::Token("oauth callback validation failed".to_string()),
        })?;
        // Exchange the code for tokens over the (air-gap-aware) transport (POST form, parse response).
        let req = &validated.token_request;
        let mut http = HttpRequest::post(req.token_endpoint.clone());
        http.headers.push((
            "Content-Type".into(),
            "application/x-www-form-urlencoded".into(),
        ));
        http.body = Some(form_urlencode(&req.form).into_bytes());
        let resp = self.transport.send(&http).map_err(|e| match e {
            TransportError::Unavailable(m) => ConnectorCallError::Unavailable(m),
            TransportError::Timeout => ConnectorCallError::Unavailable("timeout".into()),
            TransportError::Transport(m) => ConnectorCallError::Transport(m),
        })?;
        let token_set: TokenSet = TokenSet::parse(&resp.body_string())
            // Do not forward the parse error: it may contain fragments of the provider's token
            // response (Checkmarx: Secret Leak in Error Messages).
            .map_err(|_| ConnectorCallError::Token("token exchange failed".to_string()))?;
        // Seal the token set into the vault, tenant-scoped. The client never sees the token.
        let blob =
            serde_json::to_vec(&token_set).map_err(|_| ConnectorCallError::Token("token serialization failed".to_string()))?;
        let expires_at = token_set.expires_at(now_unix);
        let new_scopes = if token_set.scope.is_empty() {
            validated.requested_scopes.clone()
        } else {
            token_set.scope.clone()
        };
        // GAP-AUDIT connectors #5 — incremental (step-up) consent must UNION the newly-granted
        // scopes into whatever the vault already holds for this (tenant, user, connector), not
        // overwrite it. `step_up_consent_if_needed` deliberately requests only the MISSING delta so
        // the IdP re-prompts for just that delta; several providers (and this flow's own
        // `requested_scopes` fallback above) then echo back ONLY that delta, not the cumulative set.
        // Persisting the delta as-is would silently drop every previously-granted scope from the
        // vault's metadata, so the next `missing_scopes` check would wrongly treat already-consented
        // scopes as ungranted (or worse, a caller trusting the stored metadata would undercount the
        // live grant).
        let previously_granted = self
            .vault
            .metadata_in(&owner.tenant, &owner.user, &owner.connector)
            // Do not forward vault error details: they may contain internal storage paths or
            // tenant identifiers (Checkmarx: Secret Leak in Error Messages).
            .map_err(|_| ConnectorCallError::Token("vault read failed".to_string()))?
            .map(|m| m.scopes)
            .unwrap_or_default();
        let mut scopes = previously_granted;
        for s in &new_scopes {
            if !scopes.contains(s) {
                scopes.push(s.clone());
            }
        }
        self.vault
            .save_in(
                &owner.tenant,
                &owner.user,
                &owner.connector,
                &blob,
                expires_at,
                &scopes,
            )
            .map_err(|_| ConnectorCallError::Token("vault write failed".to_string()))?;
        self.audit.record(ConnectorAuditEvent {
            actor: owner.user.clone(),
            connector: owner.connector.clone(),
            op: "authorize-callback".into(),
            resource_present: false,
            outcome: "authorized".into(),
        });
        Ok(AuthorizationComplete {
            connector: owner.connector,
            granted_scopes: token_set.scope,
        })
    }

    /// Revoke `target_user`'s authorization for `connector` in `tenant` (owner-or-admin).
    /// `DELETE /connectors/{id}`.
    pub fn deauthorize(
        &self,
        tenant: &str,
        actor: &Principal,
        target_user: &str,
        connector: &str,
    ) -> Result<bool, ConnectorCallError> {
        if !Self::may_act_on(actor, target_user) {
            self.audit.record(ConnectorAuditEvent {
                actor: actor.user_id.clone(),
                connector: connector.into(),
                op: "deauthorize".into(),
                resource_present: false,
                outcome: "authz-denied".into(),
            });
            return Err(ConnectorCallError::Admission(
                ConnectorError::NotAuthorized("may only deauthorize own connectors".into()),
            ));
        }
        let removed = self
            .vault
            .revoke_in(tenant, target_user, connector)
            // Do not forward vault error details to callers (Checkmarx: Secret Leak in Error Messages).
            .map_err(|_| ConnectorCallError::Token("vault revoke failed".to_string()))?;
        self.audit.record(ConnectorAuditEvent {
            actor: actor.user_id.clone(),
            connector: connector.into(),
            op: "deauthorize".into(),
            resource_present: false,
            outcome: if removed {
                "deauthorized"
            } else {
                "nothing-to-revoke"
            }
            .into(),
        });
        Ok(removed)
    }
}

// ==================== Capability adapter (§0 one-registry) ====================

/// Exposes a connector operation as an [`ainxt_tools::Tool`] so a connector call dispatches through
/// the ONE [`CapabilityRegistry`](ainxt_tools::CapabilityRegistry) — the SAME registry a native Rust
/// fn, an MCP-discovered tool, and a WASM/native plugin export register into. This is the missing
/// entrypoint: the [`ConnectorInvoker`] pipeline (admission → egress DLP → payment boundary → token →
/// dispatch) was previously reachable only from tests; a [`ConnectorCapability`] makes it a
/// first-class, tool-registry-dispatchable capability with no connector-specific work downstream —
/// the ledger (exactly-once), per-resource locking, two-phase approval, and injection tagging all
/// apply uniformly.
///
/// **Untrusted response:** a connector response body is [`Provenance::Connector`] — an indirect-
/// injection surface. The [`Tool`] contract returns a plain `String`, so this adapter surfaces the
/// body verbatim (exactly as the [`mcp_bridge`](ainxt_tools::mcp_bridge) adapter surfaces opaque
/// remote content); the calling turn re-tags provenance and runs the injection stage on it. This
/// adapter never weakens any of the invoker's safety seams — they run inside `invoke_in`.
pub mod capability {
    use super::{ConnectorInvoker, PreparedCall};
    use ainxt_tools::{
        canonical_key, EffectClass, ParamSpec, RiskTier, Tool, ToolError, ToolSchema,
    };
    use ainxt_types::{DataClass, Principal};
    use std::sync::Arc;

    /// Maps a tool-call's JSON `args` onto a concrete adapter [`PreparedCall`] (e.g.
    /// `{"project":"g/r"}` → [`GitLab::get_project`](super::GitLab::get_project)). This is the ONE
    /// connector-specific hook; it must be pure (no I/O) and returns a human-readable error string on
    /// malformed args, which is fed back to the model to retry rather than reaching the network.
    pub type CallBuilder = Arc<dyn Fn(&str) -> Result<PreparedCall, String> + Send + Sync>;

    /// A wall-clock source (unix seconds) for the token-expiry/refresh decision on the USE path.
    /// Defaults to the system clock; tests inject a fixed one for determinism.
    pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

    /// Resolves the per-request acting `user_id` (threaded down from
    /// [`ToolRuntime::dispatch_for`](ainxt_tools::ToolRuntime::dispatch_for)/
    /// [`ToolRuntime::dispatch_obo`](ainxt_tools::ToolRuntime::dispatch_obo) via
    /// [`Tool::execute_as`]) into the full [`Principal`] the connector call must run as (role,
    /// clearance, department, connector scopes — everything [`ConnectorInvoker::invoke_in`] needs
    /// for admission/egress/token resolution). Called ONCE **per dispatch**, never cached on
    /// [`ConnectorCapability`] itself: the ONE `Arc<ConnectorCapability>` registered into the
    /// process-wide, `Arc`-shared `ToolRuntime` is dispatched CONCURRENTLY by many different users'
    /// requests, so re-resolving on every call — rather than baking one principal at construction —
    /// is exactly what keeps two concurrent callers' connector calls from being cross-attributed
    /// (GAP-FIX guardrails-injection "connector-provenance lost"). `None` means the `user_id` does
    /// not resolve to a known principal; the caller fails closed rather than guessing.
    pub type PrincipalResolver = Arc<dyn Fn(&str) -> Option<Principal> + Send + Sync>;

    fn system_now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// One connector operation, adapted to [`Tool`]/[`Capability`](ainxt_tools::Capability). Binds a
    /// [`PrincipalResolver`], tenant, and turn data-class (the same per-turn binding the
    /// [`McpCapability`](ainxt_tools::mcp_bridge::McpCapability) uses) plus a [`CallBuilder`] for one
    /// named operation. Conservative opaque-connector defaults — SIDE-EFFECTING (ledgered) and
    /// egressing — which a genuinely read-only operation relaxes via [`with_effect`](Self::with_effect).
    ///
    /// **No baked principal.** Earlier revisions bound one concrete [`Principal`] at construction
    /// time — correct for a single request, but this adapter is registered ONCE into a process-wide,
    /// `Arc`-shared [`ToolRuntime`](ainxt_tools::ToolRuntime) and dispatched CONCURRENTLY by many
    /// different users; a baked principal would misattribute every caller's connector calls to
    /// whichever identity happened to be bound at registration (GAP-FIX guardrails-injection
    /// "connector-provenance lost"). Instead this holds a [`PrincipalResolver`] and re-resolves the
    /// acting principal on every dispatch, from the `caller` [`Tool::execute_as`] receives — which is
    /// exactly the `user_id` [`ToolRuntime::dispatch_for`](ainxt_tools::ToolRuntime::dispatch_for)/
    /// [`ToolRuntime::dispatch_obo`](ainxt_tools::ToolRuntime::dispatch_obo) already resolve per call
    /// for the exactly-once ledger key. [`Tool::execute`] (the identity-less entrypoint the
    /// unattributed `ToolRuntime::dispatch` reaches) is refused outright — a connector call must
    /// never run under a guessed or default identity.
    pub struct ConnectorCapability {
        name: String,
        invoker: Arc<ConnectorInvoker>,
        principals: PrincipalResolver,
        tenant: String,
        data_class: DataClass,
        clock: Clock,
        build: CallBuilder,
        effect: EffectClass,
        risk: RiskTier,
        declared_class: DataClass,
        description: String,
        params: ParamSpec,
    }

    impl ConnectorCapability {
        /// Bind a named connector operation to a [`PrincipalResolver`] in `tenant` at the turn's
        /// `data_class`. Multi-tenant-correct: the USE path resolves the access token on the same
        /// `(tenant, jwt.sub, connector)` key the OAuth-callback write path sealed under. `principals`
        /// is consulted fresh on every dispatch (see the struct-level doc) — it must not itself cache
        /// a single identity.
        pub fn new(
            name: impl Into<String>,
            invoker: Arc<ConnectorInvoker>,
            principals: PrincipalResolver,
            tenant: impl Into<String>,
            data_class: DataClass,
            build: CallBuilder,
        ) -> Self {
            ConnectorCapability {
                name: name.into(),
                invoker,
                principals,
                tenant: tenant.into(),
                data_class,
                clock: Arc::new(system_now),
                build,
                effect: EffectClass::SideEffecting,
                risk: RiskTier::Low,
                declared_class: DataClass::Internal,
                description: String::new(),
                params: ParamSpec::Text,
            }
        }
        /// Override the clock (deterministic tests / a logical turn clock).
        pub fn with_clock(mut self, clock: Clock) -> Self {
            self.clock = clock;
            self
        }
        /// Declare the effect class. A read-only operation sets [`EffectClass::Idempotent`] (not
        /// ledgered); the default is SIDE-EFFECTING so a write is exactly-once by construction.
        pub fn with_effect(mut self, effect: EffectClass) -> Self {
            self.effect = effect;
            self
        }
        /// Declare the risk tier — `High` forces a two-phase approval gate before dispatch.
        pub fn with_risk_tier(mut self, risk: RiskTier) -> Self {
            self.risk = risk;
            self
        }
        /// Declare §4.2 signal 1 (the class this capability claims it handles). Never trusted alone —
        /// fused with the arg-scan + egress destination; an off-box connector call already floors the
        /// destination signal at `Confidential`.
        pub fn with_declared_data_class(mut self, class: DataClass) -> Self {
            self.declared_class = class;
            self
        }
        /// Attach the model-facing schema (description + parameter spec) used to build the function-
        /// calling manifest and to validate args before dispatch.
        pub fn with_schema(mut self, description: impl Into<String>, params: ParamSpec) -> Self {
            self.description = description.into();
            self.params = params;
            self
        }
    }

    impl Tool for ConnectorCapability {
        fn name(&self) -> &str {
            &self.name
        }
        fn effect_class(&self) -> EffectClass {
            self.effect
        }
        fn risk_tier(&self) -> RiskTier {
            self.risk
        }
        fn idempotency_key(&self, args: &str) -> Option<String> {
            // A side-effecting connector write needs an exactly-once key derived purely from the
            // semantic args, so a lost-ack retry is deduped, not double-executed (ADR-013). Read /
            // pure / payment-initiating ops key nothing here.
            match self.effect {
                EffectClass::SideEffecting => Some(canonical_key(&self.name, args)),
                EffectClass::Pure | EffectClass::Idempotent | EffectClass::PaymentInitiating => {
                    None
                }
            }
        }
        fn resource(&self, args: &str) -> Option<String> {
            // Surface the adapter's resource (repo/issue id) for fine-grained resource-level authz +
            // per-resource serialization. A malformed-args build contributes no resource.
            (self.build)(args).ok().and_then(|p| p.resource)
        }
        fn schema(&self) -> ToolSchema {
            ToolSchema {
                name: self.name.clone(),
                description: self.description.clone(),
                parameters: self.params.clone(),
            }
        }
        fn egress(&self) -> bool {
            true // a connector call always leaves the box
        }
        fn declared_data_class(&self) -> DataClass {
            self.declared_class
        }
        // GAP-FIX guardrails-injection "connector-provenance lost" — every outcome this adapter can
        // ever return originates off-box through the connector USE path (§ module doc: "untrusted
        // response"), so the engine's post-dispatch injection scan/quarantine must tag it
        // `Provenance::Connector`, never the generic `Provenance::ToolResult` every OTHER capability
        // gets by default. This is what makes a live turn's connector call reach the taint pipeline
        // under the SAME tag `ConnectorInvoker::invoke_in`'s own `CallOutcome::provenance` already
        // carries (`ingress_provenance()` — see `invoke_in`'s body) — previously discarded at this
        // exact boundary because `Tool::execute_as` returns a bare `String`, not a provenance-carrying
        // type.
        fn tool_provenance(&self) -> ainxt_injection::Provenance {
            ainxt_injection::Provenance::Connector
        }
        fn execute(&self, _args: &str) -> Result<String, ToolError> {
            // Fail closed, always. This identity-less entrypoint is only reachable via the
            // unattributed `ToolRuntime::dispatch`/`ToolRuntime::dry_run`-without-user path — a
            // connector call carries real off-box, per-user authority (the OAuth token is resolved on
            // `(tenant, user_id, connector)`), so there is no safe identity to run it as here. Running
            // it under a shared/default principal is exactly the "connector-provenance lost"
            // misattribution this adapter must not reintroduce. Dispatch via
            // `ToolRuntime::dispatch_for`/`ToolRuntime::dispatch_obo` instead, which reaches
            // `execute_as` below with the real per-request caller.
            Err(ToolError::Execution(format!(
                "connector capability '{}' requires a per-request principal: dispatch via \
                 ToolRuntime::dispatch_for/dispatch_obo (execute_as), never the unattributed \
                 dispatch/execute path",
                self.name
            )))
        }
        fn execute_as(&self, args: &str, caller: Option<&str>) -> Result<String, ToolError> {
            // Fail closed on a missing caller — never fall back to a baked/default identity.
            let user_id = caller.ok_or_else(|| {
                ToolError::Execution(format!(
                    "connector capability '{}' dispatched with no acting principal (caller is \
                     None) — use ToolRuntime::dispatch_for/dispatch_obo, not the unattributed \
                     dispatch",
                    self.name
                ))
            })?;
            // Re-resolve the FULL principal fresh on THIS call — never cached on `self` — so two
            // concurrent requests from different users each get their own, correctly attributed
            // principal even though this `ConnectorCapability` instance is shared process-wide.
            let principal = (self.principals)(user_id).ok_or_else(|| {
                ToolError::Execution(format!(
                    "connector capability '{}' has no resolvable principal for user '{user_id}'; \
                     refusing to run under an unknown identity",
                    self.name
                ))
            })?;
            let prepared = (self.build)(args).map_err(ToolError::Execution)?;
            let now = (self.clock)();
            match self
                .invoker
                .invoke_in(&self.tenant, &principal, now, self.data_class, prepared)
            {
                // Success: surface the UNTRUSTED body (the turn re-tags provenance + injection-scans).
                Ok(outcome) if outcome.response.is_success() => Ok(outcome.response.body_string()),
                // A non-2xx is a tool execution failure the model can react to (auth expired, 404…).
                Ok(outcome) => Err(ToolError::Execution(format!(
                    "connector returned HTTP {}",
                    outcome.response.status
                ))),
                // Every refusal/failure is honest: admission/egress/payment-boundary denials, token
                // errors, and the air-gap soft-degrade all surface as an execution error with the
                // pipeline's own message (never a faked success).
                // Use sanitized_client_message() — never e.to_string() / Display — so that
                // the model-facing error never includes internal details from the Token variant
                // or any other ConnectorCallError payload (Checkmarx: Secret Leak in Error Messages).
                Err(e) => Err(ToolError::Execution(e.sanitized_client_message().to_string())),
            }
        }
    }
}

pub use capability::ConnectorCapability;

// ============================ Real transport (optional) ============================

#[cfg(feature = "reqwest-transport")]
mod reqwest_transport {
    use super::{HttpRequest, HttpResponse, HttpTransport, ProxyConfig, TransportError};
    use std::time::Duration;

    /// Production HTTP transport: reqwest (blocking) + rustls, honoring the air-gap forward proxy.
    /// Blocking so it satisfies the sync [`HttpTransport`] seam; the async server wraps calls in
    /// `spawn_blocking`. Connect/timeout failures map to [`TransportError::Unavailable`] (degrade).
    pub struct ReqwestTransport {
        client: reqwest::blocking::Client,
    }

    impl ReqwestTransport {
        pub fn new(proxy: &ProxyConfig, timeout_ms: u64) -> Result<Self, String> {
            let mut builder =
                reqwest::blocking::Client::builder().timeout(Duration::from_millis(timeout_ms));
            if let Some(url) = &proxy.proxy_url {
                builder = builder.proxy(reqwest::Proxy::all(url).map_err(|e| e.to_string())?);
            }
            Ok(ReqwestTransport {
                client: builder.build().map_err(|e| e.to_string())?,
            })
        }
    }

    impl HttpTransport for ReqwestTransport {
        fn send(&self, request: &HttpRequest) -> Result<HttpResponse, TransportError> {
            let method = reqwest::Method::from_bytes(request.method.as_str().as_bytes())
                .map_err(|e| TransportError::Transport(e.to_string()))?;
            let mut rb = self.client.request(method, &request.url);
            for (k, v) in &request.headers {
                rb = rb.header(k, v);
            }
            if let Some(body) = &request.body {
                rb = rb.body(body.clone());
            }
            let resp = rb.send().map_err(|e| {
                if e.is_connect() || e.is_timeout() {
                    TransportError::Unavailable(e.to_string())
                } else {
                    TransportError::Transport(e.to_string())
                }
            })?;
            let status = resp.status().as_u16();
            let headers = resp
                .headers()
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or_default().to_string()))
                .collect();
            let body = resp
                .bytes()
                .map_err(|e| TransportError::Transport(e.to_string()))?
                .to_vec();
            Ok(HttpResponse {
                status,
                headers,
                body,
            })
        }
    }
}

#[cfg(feature = "reqwest-transport")]
pub use reqwest_transport::ReqwestTransport;

/// Clean composition entrypoint for the **air-gap forward-proxy transport in the shipped binary**
/// (gap: air-gap transport). The shipped daemon (`ainxt-runtimed`) currently mounts the connector
/// surfaces over an `OfflineTransport` (fail-closed, air-gapped default). To make outbound connector
/// calls real, the reserved daemon enables the `ainxt-connector-http/reqwest-transport` feature and
/// calls this factory with a [`ProxyConfig`] (typically [`ProxyConfig::from_env`], which reads
/// `LLM_PROXY_URL` / `HTTPS_PROXY` — the web02 Squid forward proxy) to obtain the transport to inject
/// into [`ConnectorInvoker::new`] / [`ConnectorGateway::new`] in place of the offline default.
///
/// This keeps the SEAM here (feature-gated so the dependency-light default still builds) and leaves
/// exactly one reserved-crate call-site to hot-wire; the reqwest client build + proxy wiring + the
/// connect/timeout → [`TransportError::Unavailable`] soft-degrade mapping are all proven offline
/// (localhost only) by the tests below. The live outbound leg needs real network egress (infra).
#[cfg(feature = "reqwest-transport")]
pub fn air_gap_transport(
    proxy: &ProxyConfig,
    timeout_ms: u64,
) -> Result<Box<dyn HttpTransport>, String> {
    Ok(Box::new(ReqwestTransport::new(proxy, timeout_ms)?))
}

/// Offline tests for the real transport (only under `reqwest-transport`). They exercise the parts the
/// StubTransport cannot: the reqwest `Client` builder + `Proxy::all` wiring, and the
/// connect/timeout → [`TransportError::Unavailable`] soft-degrade mapping — all against localhost, no
/// external network. The single live-endpoint test is `#[ignore]`.
#[cfg(all(test, feature = "reqwest-transport"))]
mod reqwest_transport_tests {
    use super::{
        HttpMethod, HttpRequest, HttpTransport, ProxyConfig, ReqwestTransport, TransportError,
    };

    #[test]
    fn gap_conn_06_builds_direct_and_via_proxy() {
        // Both the direct and forward-proxy (air-gap) client builds must succeed.
        assert!(ReqwestTransport::new(&ProxyConfig::direct(), 2_000).is_ok());
        assert!(
            ReqwestTransport::new(&ProxyConfig::via("http://web02:9301"), 2_000).is_ok(),
            "air-gap forward-proxy client must build"
        );
    }

    #[test]
    fn gap_conn_06_malformed_proxy_url_is_an_error() {
        // A malformed proxy URL must fail construction, not silently fall back to direct.
        assert!(
            ReqwestTransport::new(&ProxyConfig::via("::not a url::"), 2_000).is_err(),
            "a malformed proxy URL must be rejected"
        );
    }

    #[test]
    fn gap_conn_06_connect_failure_maps_to_unavailable_soft_degrade() {
        // Point at a closed local port with a short timeout: the real is_connect/is_timeout branch
        // must map to Unavailable (the air-gap soft-degrade), never a hard Transport error. Localhost
        // only — no external network.
        let t = ReqwestTransport::new(&ProxyConfig::direct(), 500).unwrap();
        let req = HttpRequest::new(HttpMethod::Get, "http://127.0.0.1:1/health");
        match t.send(&req) {
            Err(TransportError::Unavailable(_)) => {}
            other => panic!("expected Unavailable soft-degrade, got {other:?}"),
        }
    }

    #[test]
    #[ignore = "requires a live reachable HTTP endpoint; run explicitly, never in CI"]
    fn gap_conn_06_live_endpoint_round_trip() {
        let t = ReqwestTransport::new(&ProxyConfig::from_env(), 5_000).unwrap();
        let req = HttpRequest::new(HttpMethod::Get, "https://example.com/");
        let resp = t.send(&req).expect("live endpoint reachable");
        assert!(resp.status > 0);
    }

    // ---- r12: air-gap transport composition entrypoint (the reserved-daemon hot-wire seam) ----

    #[test]
    fn r12_air_gap_transport_factory_builds_direct_and_via_proxy_and_soft_degrades() {
        use super::air_gap_transport;
        // The clean entrypoint the shipped daemon calls: build both a direct and a forward-proxy
        // (air-gap) transport as a boxed HttpTransport.
        assert!(air_gap_transport(&ProxyConfig::direct(), 2_000).is_ok());
        let boxed = air_gap_transport(&ProxyConfig::via("http://web02:9301"), 2_000)
            .expect("air-gap forward-proxy transport must build via the factory");
        // A malformed proxy is surfaced as an error, never a silent direct fallback.
        assert!(air_gap_transport(&ProxyConfig::via("::bad::"), 2_000).is_err());
        // The boxed transport is a real HttpTransport whose connect-refused maps to the soft-degrade.
        let direct = air_gap_transport(&ProxyConfig::direct(), 500).unwrap();
        let req = HttpRequest::new(HttpMethod::Get, "http://127.0.0.1:1/health");
        match direct.send(&req) {
            Err(TransportError::Unavailable(_)) => {}
            other => panic!("expected Unavailable soft-degrade, got {other:?}"),
        }
        let _ = boxed;
    }

    // ---- r15: reconfirm the air-gap transport entrypoint reads LLM_PROXY_URL / HTTPS_PROXY ----

    #[test]
    fn r15_air_gap_transport_from_env_reads_https_proxy_and_builds() {
        use super::air_gap_transport;
        // Round-15 gap: "air-gap reqwest transport (HTTPS_PROXY/web02) feature-gated off; served
        // daemon wires OfflineTransport." The seam + offline impl + offline test already exist
        // (r12); this test additionally pins the env-driven `ProxyConfig::from_env` path specifically
        // (LLM_PROXY_URL preferred, HTTPS_PROXY fallback) end-to-end through the factory, so the
        // documented `ainxt-runtimed` hot-wire (`air_gap_transport(&ProxyConfig::from_env(), ..)`) is
        // proven to build from the exact env vars the design names — not just an explicit `via(..)`.
        let var_llm = "LLM_PROXY_URL";
        let var_https = "HTTPS_PROXY";
        let prev_llm = std::env::var(var_llm).ok();
        let prev_https = std::env::var(var_https).ok();
        std::env::remove_var(var_llm);
        std::env::set_var(var_https, "http://web02:9301");

        let cfg = ProxyConfig::from_env();
        assert_eq!(cfg.proxy_url.as_deref(), Some("http://web02:9301"));
        assert!(
            air_gap_transport(&cfg, 2_000).is_ok(),
            "air_gap_transport must build from HTTPS_PROXY when LLM_PROXY_URL is unset"
        );

        // Restore so this test never leaks env state to a sibling test.
        match prev_llm {
            Some(v) => std::env::set_var(var_llm, v),
            None => std::env::remove_var(var_llm),
        }
        match prev_https {
            Some(v) => std::env::set_var(var_https, v),
            None => std::env::remove_var(var_https),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ainxt_connector::{
        AllowAllPolicy, AuthKind, CapabilityConnectorAuthorizer, ConnectorDef, ConnectorPolicy,
        ConnectorRegistry, DeptRuleTable, InMemoryConnectorAudit, MarkerEgressGuard,
    };

    fn registry() -> ConnectorRegistry {
        let mut r = ConnectorRegistry::new();
        r.register(
            ConnectorDef::new("gitlab", "GitLab", AuthKind::ApiToken)
                .with_max_egress_class(DataClass::Internal),
        );
        r.register(
            ConnectorDef::new("jira", "Jira", AuthKind::ApiToken)
                .with_max_egress_class(DataClass::Internal),
        );
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

    fn invoker(policy: Box<dyn ConnectorPolicy>, stub: StubTransport) -> ConnectorInvoker {
        ConnectorInvoker::new(
            runtime(policy),
            Box::new(stub),
            Box::new(StaticTokenSource("TOK".into())),
        )
    }

    // ---- adapters ----

    #[test]
    fn gitlab_urls_encode_project_path() {
        let gl = GitLab::new("https://gl.example");
        let p = gl.get_project("group/sub/repo");
        assert_eq!(p.request.method, HttpMethod::Get);
        assert_eq!(
            p.request.url,
            "https://gl.example/api/v4/projects/group%2Fsub%2Frepo"
        );
        assert!(!p.egress_body);
        let note = gl.post_mr_note("group/repo", 7, "hello");
        assert_eq!(note.request.method, HttpMethod::Post);
        assert!(note.request.url.ends_with("/merge_requests/7/notes"));
        assert!(note.egress_body);
        assert_eq!(note.op, "write");
        assert_eq!(
            String::from_utf8_lossy(note.request.body.as_ref().unwrap()),
            r#"{"body":"hello"}"#
        );
    }

    #[test]
    fn jira_and_graph_urls() {
        let j = Jira::new("https://acme.atlassian.net");
        assert_eq!(
            j.get_issue("PROJ-1").request.url,
            "https://acme.atlassian.net/rest/api/3/issue/PROJ-1"
        );
        assert!(j.add_comment("PROJ-1", "c").egress_body);
        let g = Graph::new();
        assert_eq!(
            g.get_me().request.url,
            "https://graph.microsoft.com/v1.0/me"
        );
        assert!(g
            .list_messages(10)
            .request
            .url
            .ends_with("/me/messages?$top=10"));
        assert!(g.send_mail("a@b.c", "s", "body").egress_body);
    }

    // ---- invoker pipeline ----

    #[test]
    fn happy_path_injects_bearer_and_tags_provenance() {
        let stub = StubTransport::new();
        stub.push_response(HttpResponse::new(200, br#"{"id":1}"#.to_vec()));
        let inv = invoker(Box::new(AllowAllPolicy), stub.clone());
        let p = Principal::user("u", &["connector.gitlab"]);
        let out = inv
            .invoke(
                &p,
                0,
                DataClass::Internal,
                GitLab::new("https://gl").get_project("g/r"),
            )
            .unwrap();
        assert!(out.response.is_success());
        assert_eq!(out.provenance, Provenance::Connector);
        // Auth header was injected by the invoker (adapter never sees the token).
        let sent = stub.sent();
        assert_eq!(sent.len(), 1);
        assert!(sent[0]
            .headers
            .iter()
            .any(|(k, v)| k == "Authorization" && v == "Bearer TOK"));
    }

    #[test]
    fn admission_denied_never_touches_the_network() {
        let stub = StubTransport::new();
        let inv = invoker(Box::new(AllowAllPolicy), stub.clone());
        let p = Principal::user("u", &[]); // lacks connector.gitlab
        let err = inv
            .invoke(
                &p,
                0,
                DataClass::Internal,
                GitLab::new("https://gl").get_project("g/r"),
            )
            .unwrap_err();
        assert!(matches!(err, ConnectorCallError::Admission(_)));
        assert_eq!(stub.sent_count(), 0, "denied call must not be dispatched");
    }

    #[test]
    fn policy_denied_never_touches_the_network() {
        let stub = StubTransport::new();
        let policy = DeptRuleTable::new().allow_dept("gitlab", "payments"); // hr not allowed
        let inv = invoker(Box::new(policy), stub.clone());
        let p = Principal::user("u", &["connector.gitlab"]).with_department("hr");
        let err = inv
            .invoke(
                &p,
                0,
                DataClass::Internal,
                GitLab::new("https://gl").get_project("g/r"),
            )
            .unwrap_err();
        assert!(matches!(err, ConnectorCallError::Admission(_)));
        assert_eq!(stub.sent_count(), 0);
    }

    #[test]
    fn egress_dlp_redacts_write_body() {
        let stub = StubTransport::new();
        stub.push_response(HttpResponse::new(201, Vec::new()));
        let inv = invoker(Box::new(AllowAllPolicy), stub.clone());
        let p = Principal::user("u", &["connector.gitlab"]);
        let note = GitLab::new("https://gl").post_mr_note(
            "g/r",
            1,
            "card 4111111111111111 SECRET=s3cr3t-v4lue",
        );
        let out = inv.invoke(&p, 0, DataClass::Internal, note).unwrap();
        assert!(out.egress_redactions >= 2);
        let sent_body = stub.sent()[0]
            .body
            .as_ref()
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .unwrap();
        assert!(
            !sent_body.contains("4111111111111111"),
            "PAN left the perimeter: {sent_body}"
        );
        // The secret VALUE must be gone, not just the marker label.
        assert!(
            !sent_body.contains("s3cr3t-v4lue"),
            "secret VALUE left the perimeter: {sent_body}"
        );
        assert!(
            !sent_body.contains("SECRET="),
            "secret marker left the perimeter: {sent_body}"
        );
    }

    #[test]
    fn data_class_ceiling_blocks_regulated_egress() {
        let stub = StubTransport::new();
        let inv = invoker(Box::new(AllowAllPolicy), stub.clone());
        let p = Principal::user("u", &["connector.gitlab"]);
        // gitlab ceiling = Internal; a RegulatedPayment turn must be refused before any send.
        let note = GitLab::new("https://gl").post_mr_note("g/r", 1, "settlement");
        let err = inv
            .invoke(&p, 0, DataClass::RegulatedPayment, note)
            .unwrap_err();
        assert!(matches!(err, ConnectorCallError::Egress(_)));
        assert_eq!(
            stub.sent_count(),
            0,
            "over-classified data must never be sent"
        );
    }

    #[test]
    fn air_gap_unavailable_is_soft_degrade() {
        let stub = StubTransport::new();
        stub.push_error(TransportError::Unavailable("proxy unreachable".into()));
        let inv = invoker(Box::new(AllowAllPolicy), stub.clone());
        let p = Principal::user("u", &["connector.graph"]);
        let err = inv
            .invoke(&p, 0, DataClass::Internal, Graph::new().get_me())
            .unwrap_err();
        assert!(
            err.is_soft_degrade(),
            "unreachable proxy must be a soft-degrade, got {err:?}"
        );
    }

    #[test]
    fn timeout_is_soft_degrade() {
        let stub = StubTransport::new();
        stub.push_error(TransportError::Timeout);
        let inv = invoker(Box::new(AllowAllPolicy), stub);
        let p = Principal::user("u", &["connector.graph"]);
        let err = inv
            .invoke(&p, 0, DataClass::Internal, Graph::new().get_me())
            .unwrap_err();
        assert!(err.is_soft_degrade());
    }

    #[test]
    fn token_failure_surfaces_and_blocks_dispatch() {
        struct FailTokens;
        impl TokenSource for FailTokens {
            fn access_token(&self, _u: &str, _c: &str, _n: u64) -> Result<String, String> {
                Err("re-auth required".into())
            }
        }
        let stub = StubTransport::new();
        let inv = ConnectorInvoker::new(
            runtime(Box::new(AllowAllPolicy)),
            Box::new(stub.clone()),
            Box::new(FailTokens),
        );
        let p = Principal::user("u", &["connector.graph"]);
        let err = inv
            .invoke(&p, 0, DataClass::Internal, Graph::new().get_me())
            .unwrap_err();
        assert!(matches!(err, ConnectorCallError::Token(_)));
        assert_eq!(stub.sent_count(), 0);
    }

    // ---- refresh executor ----

    #[test]
    fn http_refresh_executor_posts_form_and_parses_token() {
        let stub = StubTransport::new();
        stub.push_response(HttpResponse::new(
            200,
            br#"{"access_token":"NEW","refresh_token":"R2","expires_in":3600,"token_type":"Bearer"}"#.to_vec(),
        ));
        let exec = HttpRefreshExecutor::new(Box::new(stub.clone()));
        let req = TokenRequest {
            token_endpoint: "https://idp/token".into(),
            form: vec![
                ("grant_type".into(), "refresh_token".into()),
                ("refresh_token".into(), "R1".into()),
            ],
        };
        let ts = exec.execute(&req).unwrap();
        assert_eq!(ts.access_token, "NEW");
        assert_eq!(ts.refresh_token.as_deref(), Some("R2"));
        let sent = stub.sent();
        assert_eq!(sent[0].url, "https://idp/token");
        let body = String::from_utf8_lossy(sent[0].body.as_ref().unwrap()).into_owned();
        assert!(body.contains("grant_type=refresh_token"));
        assert!(body.contains("refresh_token=R1"));
        assert!(sent[0]
            .headers
            .iter()
            .any(|(k, v)| k == "Content-Type" && v == "application/x-www-form-urlencoded"));
    }

    #[test]
    fn http_refresh_executor_surfaces_oauth_error() {
        let stub = StubTransport::new();
        stub.push_response(HttpResponse::new(
            400,
            br#"{"error":"invalid_grant"}"#.to_vec(),
        ));
        let exec = HttpRefreshExecutor::new(Box::new(stub));
        let req = TokenRequest {
            token_endpoint: "https://idp/token".into(),
            form: vec![],
        };
        assert!(
            exec.execute(&req).is_err(),
            "an OAuth error response must be an Err"
        );
    }

    #[test]
    fn form_urlencode_encodes_reserved() {
        let s = form_urlencode(&[("a b".into(), "c/d=e".into())]);
        assert_eq!(s, "a%20b=c%2Fd%3De");
    }

    #[test]
    fn proxy_config_helpers() {
        assert!(ProxyConfig::direct().proxy_url.is_none());
        assert_eq!(
            ProxyConfig::via("http://web02:9301").proxy_url.as_deref(),
            Some("http://web02:9301")
        );
    }

    // ---- deauthorize verb: see the doc comment at "Authorization lifecycle (deauthorize verb)"
    // above — `ConnectorLifecycle` (which used to be tested here) was removed as a superseded
    // duplicate of `ConnectorGateway::deauthorize`/`authorized`, which are exercised end-to-end via
    // the real `DELETE /connectors/{id}` / `GET /connectors` routes in `ainxt-server`'s own tests.

    // ---- IDN-01: the payment action boundary (EgressGuard) runs on the live egress path ----

    #[test]
    fn wire_idn_01() {
        use ainxt_payments::boundary::InitiationReason;

        // A benign connector call to a normal host still dispatches — the guard is default-deny on
        // value movement, NOT on ordinary traffic (this is the preserve-behavior half of the wire).
        let stub = StubTransport::new();
        stub.push_response(HttpResponse::new(200, br#"{"id":1}"#.to_vec()));
        let inv = invoker(Box::new(AllowAllPolicy), stub.clone());
        let p = Principal::user("u", &["connector.gitlab"]);
        inv.invoke(
            &p,
            0,
            DataClass::Internal,
            GitLab::new("https://gl.internal").get_project("g/r"),
        )
        .expect("a benign adjacent connector call must still dispatch");
        assert_eq!(stub.sent_count(), 1);

        // A connector call whose resolved URL lands inside the un-allow-listable settlement
        // perimeter (§4.4) is refused BEFORE any bytes leave. Before this wire the call dispatched;
        // now the EgressGuard tripwire (Layer 6) denies it.
        let stub = StubTransport::new();
        let inv = invoker(Box::new(AllowAllPolicy), stub.clone());
        let perimeter_call =
            GitLab::new("https://upi-settlement.example.internal").get_project("g/r");
        let err = inv
            .invoke(&p, 0, DataClass::Internal, perimeter_call)
            .expect_err("a settlement-perimeter destination must be refused pre-dispatch");
        match &err {
            ConnectorCallError::PaymentBoundary(d) => {
                assert!(
                    d.is_payment_initiation(),
                    "a perimeter destination is a Layer-6 payment-initiation denial, got {d:?}"
                );
                match d {
                    DispatchDenied::PaymentInitiation(b) => assert!(b
                        .reasons
                        .contains(&InitiationReason::SettlementPerimeterDestination)),
                    other => panic!("expected PaymentInitiation, got {other:?}"),
                }
            }
            other => panic!("expected PaymentBoundary denial, got {other:?}"),
        }
        assert_eq!(
            stub.sent_count(),
            0,
            "a call to the settlement perimeter must never reach the network"
        );

        // A mis-declared call to a benign host whose resource NAMES a settlement write target is
        // also caught by the resource-key signature (§4.5), independent of the destination.
        let stub = StubTransport::new();
        let inv = invoker(Box::new(AllowAllPolicy), stub.clone());
        let settle_resource =
            GitLab::new("https://benign.internal").get_project("settlement-account:HDFC0001");
        let err = inv
            .invoke(&p, 0, DataClass::Internal, settle_resource)
            .expect_err("a settlement-account resource must be refused pre-dispatch");
        assert!(
            matches!(err, ConnectorCallError::PaymentBoundary(ref d) if d.is_payment_initiation())
        );
        assert_eq!(stub.sent_count(), 0);
    }

    // ---- IDN-09 (R14): the §4.6 graduated tripwire remediation is ENACTED on the live egress path
    //      — a payment-initiation tripwire emits all three actions (quarantine + revoke + incident),
    //      not a bare deny. A benign call never touches the remediator. ----

    #[test]
    fn r14_tripwire_enacts_graduated_remediation() {
        use ainxt_payments::boundary::RecordingRemediation;

        // A shared recording remediator, observed after the live invoke. In production this is a
        // control-plane-backed implementor (ainxt-identity::remediation::ControlPlaneRemediator);
        // recording here proves the live path DRIVES the seam on every tripwire.
        let remediator = Arc::new(RecordingRemediation::new());

        let stub = StubTransport::new();
        let inv = invoker(Box::new(AllowAllPolicy), stub.clone())
            .with_tripwire_remediation(remediator.clone());
        let p = Principal::user("mallory", &["connector.gitlab"]);

        // BENIGN call first: dispatches, and the remediator is NEVER touched (no false remediation).
        stub.push_response(HttpResponse::new(200, br#"{"id":1}"#.to_vec()));
        inv.invoke(
            &p,
            0,
            DataClass::Internal,
            GitLab::new("https://gl.internal").get_project("g/r"),
        )
        .expect("a benign adjacent call must still dispatch");
        assert_eq!(stub.sent_count(), 1);
        assert!(
            remediator.quarantined().is_empty()
                && remediator.revoked().is_empty()
                && remediator.incident_count() == 0,
            "a benign call must NOT trigger any §4.6 remediation"
        );

        // TRIPWIRE: a call whose resolved URL lands in the un-allow-listable settlement perimeter
        // (§4.4) is a Layer-6 payment-initiation match. Before this wire the live path returned a bare
        // PaymentBoundary denial and enacted NOTHING; now it builds + enacts the full graduated
        // response through the remediator seam before returning the fail-closed denial.
        let perimeter_call =
            GitLab::new("https://upi-settlement.example.internal").get_project("g/r");
        let err = inv
            .invoke(&p, 0, DataClass::Internal, perimeter_call)
            .expect_err("a settlement-perimeter destination must be refused pre-dispatch");
        assert!(
            matches!(err, ConnectorCallError::PaymentBoundary(ref d) if d.is_payment_initiation()),
            "expected a Layer-6 payment-initiation denial, got {err:?}"
        );

        // ABORT: no bytes left (still just the one benign send).
        assert_eq!(
            stub.sent_count(),
            1,
            "the tripwire call must never reach the network"
        );
        // QUARANTINE: the offending connector capability is quarantined.
        assert_eq!(
            remediator.quarantined(),
            vec!["connector.gitlab".to_string()],
            "the offending capability must be quarantined"
        );
        // REVOKE: the acting identity is revoked.
        assert_eq!(
            remediator.revoked(),
            vec!["mallory".to_string()],
            "the acting identity must be revoked"
        );
        // INCIDENT: exactly one security incident raised.
        assert_eq!(
            remediator.incident_count(),
            1,
            "a security incident must be raised"
        );
    }

    // ---- CONN-05: egress DLP covers the request URL (path + query) ----

    #[test]
    fn gap_conn_05_url_dlp_blocks_pan_in_read_path() {
        // A read carries no body but its URL embeds user-controlled data. A PAN in a file path must
        // be caught fail-closed — before URL screening this egressed unredacted.
        let stub = StubTransport::new();
        stub.push_response(HttpResponse::new(200, Vec::new()));
        let inv = invoker(Box::new(AllowAllPolicy), stub.clone());
        let p = Principal::user("u", &["connector.gitlab"]);
        // PAN embedded in the file path segment of a GET.
        let call = GitLab::new("https://gl").get_file("g/r", "4111111111111111", "main");
        let err = inv.invoke(&p, 0, DataClass::Internal, call).unwrap_err();
        assert!(
            matches!(err, ConnectorCallError::Egress(_)),
            "PAN in URL must be refused, got {err:?}"
        );
        assert_eq!(
            stub.sent_count(),
            0,
            "a URL carrying a PAN must never be dispatched"
        );
    }

    #[test]
    fn gap_conn_05_clean_read_url_still_dispatches() {
        let stub = StubTransport::new();
        stub.push_response(HttpResponse::new(200, br#"{"id":1}"#.to_vec()));
        let inv = invoker(Box::new(AllowAllPolicy), stub.clone());
        let p = Principal::user("u", &["connector.gitlab"]);
        let call = GitLab::new("https://gl").get_file("g/r", "src/main.rs", "main");
        assert!(inv.invoke(&p, 0, DataClass::Internal, call).is_ok());
        assert_eq!(stub.sent_count(), 1);
    }

    // ---- CONN-03: Connector Runtime surface (gateway OAuth begin/callback + /connectors) ----

    fn gw_vault() -> ainxt_token::TokenVault {
        use ainxt_token::{AeadCodec, InMemoryTokenStore, KeyRing, TokenVault};
        TokenVault::new(
            Box::new(AeadCodec::new(KeyRing::new(1, [6u8; 32]))),
            Box::new(InMemoryTokenStore::new()),
        )
    }

    fn gw_provider() -> ainxt_oauth::OAuthProvider {
        ainxt_oauth::OAuthProvider {
            authorize_endpoint: "https://login.example.invalid/authorize".into(),
            token_endpoint: "https://login.example.invalid/token".into(),
            client_id: "client-1".into(),
            redirect_uri: "https://app.example.invalid/connectors/callback".into(),
            scopes: vec!["User.Read".into()],
        }
    }

    #[test]
    fn gap_conn_03_gateway_oauth_begin_callback_stores_token_and_lists() {
        use ainxt_oauth::InMemoryPendingAuthStore;
        let stub = StubTransport::new();
        // The IdP token endpoint returns a token set for the code exchange.
        stub.push_response(HttpResponse::new(
            200,
            br#"{"access_token":"AT","refresh_token":"RT","expires_in":3600,"scope":"User.Read Mail.Read","token_type":"Bearer"}"#.to_vec(),
        ));
        let vault = gw_vault();
        let gw = ConnectorGateway::new(
            runtime(Box::new(AllowAllPolicy)),
            vault,
            Box::new(InMemoryPendingAuthStore::new()),
            Box::new(stub.clone()),
            Box::new(InMemoryConnectorAudit::new()),
        )
        .with_provider("graph", gw_provider());

        let p = Principal::user("alice", &["connector.graph"]);
        // 1. Begin: an OAuth connector produces an authorize URL with PKCE S256 + a state.
        let start = gw
            .begin_authorization("tenant-1", &p, "graph", &["User.Read".into()], 1_000)
            .unwrap();
        assert!(start.authorize_url.contains("code_challenge_method=S256"));
        assert!(!start.state.is_empty());
        // Not yet authorized.
        assert!(gw.authorized("tenant-1", &p, "alice").unwrap().is_empty());

        // 2. Callback: the IdP echoes the state + a code → token is exchanged and sealed.
        let done = gw
            .complete_callback(&start.state, "auth-code", 1_100)
            .unwrap();
        assert_eq!(done.connector, "graph");
        assert_eq!(
            done.granted_scopes,
            vec!["User.Read".to_string(), "Mail.Read".to_string()]
        );

        // 3. The connector is now listed as authorized for (tenant-1, alice).
        assert_eq!(
            gw.authorized("tenant-1", &p, "alice").unwrap(),
            vec!["graph".to_string()]
        );
        // And nothing leaked into a different tenant.
        assert!(gw.authorized("tenant-2", &p, "alice").unwrap().is_empty());

        // 4. Deauthorize purges it.
        assert!(gw.deauthorize("tenant-1", &p, "alice", "graph").unwrap());
        assert!(gw.authorized("tenant-1", &p, "alice").unwrap().is_empty());
    }

    #[test]
    fn gap_conn_03_gateway_rejects_forged_callback_state_as_csrf() {
        use ainxt_oauth::InMemoryPendingAuthStore;
        let stub = StubTransport::new();
        let gw = ConnectorGateway::new(
            runtime(Box::new(AllowAllPolicy)),
            gw_vault(),
            Box::new(InMemoryPendingAuthStore::new()),
            Box::new(stub.clone()),
            Box::new(InMemoryConnectorAudit::new()),
        )
        .with_provider("graph", gw_provider());
        let p = Principal::user("alice", &["connector.graph"]);
        gw.begin_authorization("t", &p, "graph", &[], 1_000)
            .unwrap();
        // An attacker-invented state has no owner mapping → rejected, nothing exchanged.
        let err = gw
            .complete_callback("attacker-state", "code", 1_050)
            .unwrap_err();
        assert!(matches!(err, ConnectorCallError::Admission(_)));
        assert_eq!(
            stub.sent_count(),
            0,
            "a forged callback must never hit the token endpoint"
        );
    }

    // ---- r12: tenant axis is BOUND TO THE VERIFIED IDENTITY (not a self-asserted argument) ----

    /// A token source that echoes the tenant it is asked for, so a test can observe WHICH tenant the
    /// USE path resolved the token under.
    struct TenantEchoTokens;
    impl TokenSource for TenantEchoTokens {
        fn access_token_in(
            &self,
            tenant: &str,
            user: &str,
            _connector: &str,
            _now: u64,
        ) -> Result<String, String> {
            Ok(format!("tok:{tenant}:{user}"))
        }
        fn access_token(&self, user: &str, connector: &str, now: u64) -> Result<String, String> {
            self.access_token_in(DEFAULT_TENANT, user, connector, now)
        }
    }

    fn echo_invoker(stub: StubTransport) -> ConnectorInvoker {
        ConnectorInvoker::new(
            runtime(Box::new(AllowAllPolicy)),
            Box::new(stub),
            Box::new(TenantEchoTokens),
        )
    }

    #[test]
    fn r12_tenant_axis_bound_to_verified_identity_on_use_path() {
        use super::{BoundPrincipal, VerifiedTenant};

        // The tenant the USE path resolves the token under is the one BOUND to the verified caller —
        // there is no separate tenant argument on `invoke_for` for a caller to disagree with.
        let stub = StubTransport::new();
        stub.push_response(HttpResponse::new(200, br#"{"id":1}"#.to_vec()));
        stub.push_response(HttpResponse::new(200, br#"{"id":1}"#.to_vec()));
        stub.push_response(HttpResponse::new(200, br#"{"id":1}"#.to_vec()));
        let inv = echo_invoker(stub.clone());

        let alice = Principal::user("alice", &["connector.gitlab"]);
        // alice authenticated into tenant-a (the authenticator minted this from the verified claim).
        let bound_a = BoundPrincipal::new(
            alice.clone(),
            VerifiedTenant::from_authenticated_claim("tenant-a"),
        );
        inv.invoke_for(
            &bound_a,
            0,
            DataClass::Internal,
            GitLab::new("https://gl").get_project("g/r"),
        )
        .unwrap();

        // The SAME user id authenticated into tenant-b resolves tenant-b's token — never tenant-a's.
        let bound_b = BoundPrincipal::new(
            alice.clone(),
            VerifiedTenant::from_authenticated_claim("tenant-b"),
        );
        inv.invoke_for(
            &bound_b,
            0,
            DataClass::Internal,
            GitLab::new("https://gl").get_project("g/r"),
        )
        .unwrap();

        // A single-tenant deployment binds the DEFAULT_TENANT sentinel.
        let bound_default = BoundPrincipal::single_tenant(alice);
        inv.invoke_for(
            &bound_default,
            0,
            DataClass::Internal,
            GitLab::new("https://gl").get_project("g/r"),
        )
        .unwrap();

        let bearers: Vec<String> = stub
            .sent()
            .iter()
            .map(|r| {
                r.headers
                    .iter()
                    .find(|(k, _)| k == "Authorization")
                    .map(|(_, v)| v.clone())
                    .unwrap_or_default()
            })
            .collect();
        assert_eq!(
            bearers[0], "Bearer tok:tenant-a:alice",
            "tenant-a identity resolves tenant-a token"
        );
        assert_eq!(
            bearers[1], "Bearer tok:tenant-b:alice",
            "tenant-b identity resolves tenant-b token"
        );
        assert_eq!(
            bearers[2],
            format!("Bearer tok:{DEFAULT_TENANT}:alice"),
            "single-tenant identity binds the DEFAULT_TENANT sentinel"
        );
    }

    #[test]
    fn r12_gateway_authorized_for_is_tenant_bound_to_identity() {
        use super::{BoundPrincipal, VerifiedTenant};
        use ainxt_oauth::InMemoryPendingAuthStore;
        let stub = StubTransport::new();
        stub.push_response(HttpResponse::new(
            200,
            br#"{"access_token":"AT","refresh_token":"RT","expires_in":3600,"scope":"User.Read","token_type":"Bearer"}"#.to_vec(),
        ));
        let gw = ConnectorGateway::new(
            runtime(Box::new(AllowAllPolicy)),
            gw_vault(),
            Box::new(InMemoryPendingAuthStore::new()),
            Box::new(stub.clone()),
            Box::new(InMemoryConnectorAudit::new()),
        )
        .with_provider("graph", gw_provider());
        let alice = Principal::user("alice", &["connector.graph"]);
        let bound_a = BoundPrincipal::new(
            alice.clone(),
            VerifiedTenant::from_authenticated_claim("tenant-a"),
        );

        // Begin+complete bind the minted token to the verified tenant (tenant-a).
        let start = gw
            .begin_authorization_for(&bound_a, "graph", &["User.Read".into()], 1_000)
            .unwrap();
        gw.complete_callback(&start.state, "code", 1_100).unwrap();

        // authorized_for(tenant-a) sees it; a DIFFERENT verified tenant sees nothing (no leakage).
        assert_eq!(
            gw.authorized_for(&bound_a, "alice").unwrap(),
            vec!["graph".to_string()]
        );
        let bound_b =
            BoundPrincipal::new(alice, VerifiedTenant::from_authenticated_claim("tenant-b"));
        assert!(gw.authorized_for(&bound_b, "alice").unwrap().is_empty());
    }

    #[test]
    fn gap_conn_03_gateway_refuses_non_oauth_connector_begin() {
        use ainxt_oauth::InMemoryPendingAuthStore;
        let gw = ConnectorGateway::new(
            runtime(Box::new(AllowAllPolicy)),
            gw_vault(),
            Box::new(InMemoryPendingAuthStore::new()),
            Box::new(StubTransport::new()),
            Box::new(InMemoryConnectorAudit::new()),
        );
        let p = Principal::user("alice", &["connector.gitlab"]);
        // gitlab is an ApiToken connector — it has no OAuth begin flow.
        let err = gw
            .begin_authorization("t", &p, "gitlab", &[], 1_000)
            .unwrap_err();
        assert!(matches!(err, ConnectorCallError::Token(_)));
        // The catalog still lists it.
        assert!(gw.catalog().contains(&"gitlab".to_string()));
    }
}
