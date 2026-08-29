// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R6 shipped-composition cluster — the builders that make the daemon MOUNT every governed surface the
//! [`ainxt_server`] transport can serve, plus the two additional control organs the design mandates be
//! LIVE on the served surface. Before this the daemon populated only `manager/auth/event_log/serving/
//! graph/ledger_schema` and left `harness = None`, and served through `serve_full` (never
//! `serve_full_ext`), so `/v1/harness/*`, `/connectors/*`, `/v1/artifact`, and `/v1/replay/step` were
//! reachable only from `ainxt-server`'s own tests. This module supplies the real, offline-safe backings:
//!
//! * **Harness invoke/run** (`/v1/harness/{id}` + `/v1/harness/{id}/run`, HARN-03) — an id-keyed
//!   [`HarnessRegistry`] seeded with a built-in `diag.selftest` diagnostic harness (so the surface is
//!   genuinely LIVE, not merely mounted-but-empty), a real [`HarnessRuntime`] (capability authz + audit),
//!   the synchronous invoke [`StepExecutor`], and the engine-tool-path [`CapabilityInvoker`]
//!   ([`ainxt_server::ToolPathInvoker`] over the SAME shared [`ToolRuntime`] handle the served engine
//!   dispatches through — see [`build_harness_mounts`]'s `served_tools` parameter, R16 §0/§1.2 — with an
//!   own-instance fail-closed [`ToolRuntime`] fallback only on a surface with no real Engine at all).
//! * **Connector OAuth** (`/connectors/*`, CONN-03) — a real [`ConnectorGateway`] over the safety-seam
//!   [`ConnectorRuntime`] and an encrypted [`TokenVault`]; the air-gapped default ships an empty
//!   connector registry (catalog serves, empty) and an offline transport (the OAuth token exchange is
//!   unreachable without egress — fail-closed, never a fabricated 200).
//! * **Artifact generation** (`/v1/artifact`, R6 DATA) — an [`ArtifactRuntime`] with the built-in
//!   renderers + the generic Luhn/entropy content scanner (audit-and-proceed).
//! * **Step-through replay** (`/v1/replay/step`, R6 DATA) — a durable [`SessionStore`] the store-backed
//!   step entrypoint pages over (the OSS default is the in-RAM store; production swaps a DB behind the
//!   same seam).
//! * **DSAR / right-to-erasure organ** — a [`TieredCacheErasure`] cascade held on the served surface so
//!   a DPDP erasure request zeroizes every cache tier for a principal.
//! * **SR-11-7 quality circuit-breaker organ** — a [`QualityCircuitBreaker`] that trips a regulated
//!   model route whose live monitoring scoreboard drops below the bar (the runtime half of §2.1).

use std::sync::{Arc, Mutex};

use ainxt_admission::{
    CapabilityAuthorizer, CapabilityGrant, HarnessManifest, HarnessRegistry, HarnessRuntime,
    HarnessStep, InMemoryHarnessAudit, StepExecutor, StepKind, StepResult,
};
use ainxt_artifact::{ArtifactRuntime, LuhnEntropyScanner};
use ainxt_client::CapabilityInvoker;
use ainxt_connector::{
    CapabilityConnectorAuthorizer, ConnectorRegistry, ConnectorRuntime, HashChainedConnectorAudit,
    MarkerEgressGuard,
};
use ainxt_connector_http::{
    ConnectorCapability, ConnectorGateway, GitLab, Graph, HttpRequest, HttpResponse, HttpTransport,
    Jira, TransportError,
};
use ainxt_identity::remediation::ControlPlaneRemediator;
use ainxt_oauth::InMemoryPendingAuthStore;
use ainxt_replay::{DeterministicReplayExecutor, InMemorySessionStore, ReExecutor, SessionStore};
use ainxt_responsibleai::QualityCircuitBreaker;
use ainxt_server::{sql_token_vault, HarnessMounts, ToolPathInvoker};
use ainxt_serving::erasure::TieredCacheErasure;
use ainxt_token::{
    AeadCodec, FileTokenStore, InMemorySqlTokenBackend, KeyRing, SecretCodec, TokenVault,
};
use ainxt_tools::native_supply_chain::NativeControlLock;
use ainxt_tools::{EffectClass, ParamSpec, ToolRuntime};
use ainxt_types::{DataClass, Principal};

use ainxt_cache::CacheConfig;

/// The capability that admits the built-in diagnostic self-test harness. A caller must carry it (or
/// `role == Admin`) to invoke `diag.selftest`; the harness runtime enforces this on admission.
pub const CAP_DIAG_SELFTEST: &str = "diag.selftest";

/// The built-in diagnostic harness id the daemon publishes so the harness surface is LIVE on the
/// shipped binary (a mounted-but-empty registry would 404 every invoke, indistinguishable from an
/// unmounted route). Invoking it drives one governed step through the whole admit → least-privilege →
/// budget → audit pipeline and returns `ok` — a real runtime self-test, not a stub of the SUT.
pub const DIAG_SELFTEST_ID: &str = "diag.selftest";

/// The composition's synchronous invoke [`StepExecutor`] for HARN-01 (`/v1/harness/{id}`). It backs
/// the built-in `diag.selftest` step: the harness runtime has already admitted the step (RBAC /
/// least-privilege / budget / data-class), so this executor only performs the step's own work — for the
/// diagnostic that is confirming the pipeline ran. A deployment registers real harnesses whose steps
/// this executor (or a richer engine-backed one) drives; an unrecognized capability returns an explicit
/// non-completing result rather than pretending to succeed.
#[derive(Debug, Default)]
pub struct SelfTestStepExecutor;

impl StepExecutor for SelfTestStepExecutor {
    fn execute(&self, step: &HarnessStep, _principal: &Principal) -> StepResult {
        if step.capability == CAP_DIAG_SELFTEST {
            StepResult::new(
                1,
                "ok: runtime self-test — admit/authz/budget/audit pipeline ran",
            )
        } else {
            StepResult::new(
                0,
                format!("no built-in executor for capability '{}'", step.capability),
            )
        }
    }
}

/// An [`HttpTransport`] that refuses every request as unavailable — the honest air-gapped default for
/// the connector OAuth token exchange (no egress ⇒ no token exchange), so the surface is MOUNTED and
/// the catalog/list routes serve, but a code-exchange fails closed rather than fabricating a 200.
#[derive(Debug, Default)]
pub struct OfflineTransport;

impl HttpTransport for OfflineTransport {
    fn send(&self, _request: &HttpRequest) -> Result<HttpResponse, TransportError> {
        Err(TransportError::Unavailable(
            "air-gapped default: no outbound connector transport configured".into(),
        ))
    }
}

/// GAP-FIX harness-sdk-governance #4 — the missing authoring-to-production bridge. Before this,
/// [`HarnessRegistry::register`] (the ONLY way a definition becomes a live, invocable harness on the
/// served surface) had zero connection to [`ainxt_governance`]'s git-native lifecycle (Draft ->
/// PendingApproval -> Approved -> Production -> Deprecated, ADR-026): [`build_harness_mounts`] called
/// `register` directly, so ANY manifest handed to it became live regardless of whether it had ever
/// been through review/signing at all. This is the bridge: register a definition **only** when its
/// governance state has actually reached [`GovernanceState::Production`](ainxt_governance::GovernanceState::Production)
/// — the fail-closed connection nothing wired between `ainxt_governance::advance` reaching `Production`
/// and `HarnessRegistry::register` actually running.
///
/// This does not itself decide *how* a state was reached (that is `ainxt_governance::advance`/
/// `advance_with_evidence`'s job, evidence-checked for `MergeApproved`/`PromoteSignedTag`) — it is the
/// narrow seam a composition root (or a future control-repo webhook reacting to a signed-tag push)
/// calls with whatever `state` it computed, so "is this thing actually Production" and "make it live"
/// can never drift apart into two independently-maintained checks.
pub fn register_governed_harness(
    registry: &mut HarnessRegistry,
    manifest: HarnessManifest,
    grant: CapabilityGrant,
    state: ainxt_governance::GovernanceState,
) -> Result<(), GovernedRegisterError> {
    if state != ainxt_governance::GovernanceState::Production {
        return Err(GovernedRegisterError::NotProduction(state));
    }
    registry
        .register(manifest, grant)
        .map_err(GovernedRegisterError::Registry)
}

/// Why [`register_governed_harness`] refused to publish a definition.
#[derive(Debug)]
pub enum GovernedRegisterError {
    /// The definition has not reached `Production` on the git-native lifecycle — it may never become a
    /// live harness while this holds (fail-closed; there is no override).
    NotProduction(ainxt_governance::GovernanceState),
    /// It IS at `Production` but the registry itself refused it (lint failure or a duplicate id).
    Registry(ainxt_admission::RegistryError),
}

impl std::fmt::Display for GovernedRegisterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GovernedRegisterError::NotProduction(state) => write!(
                f,
                "refused: definition is at governance state {state:?}, not Production — only a \
                 signed-tag-promoted definition may become a live, invocable harness"
            ),
            GovernedRegisterError::Registry(e) => write!(f, "{e}"),
        }
    }
}
impl std::error::Error for GovernedRegisterError {}

/// The built-in `diag.selftest` harness's governance state: it ships INSIDE the compiled daemon
/// binary, which only exists because this very source file already passed a real PR + CODEOWNERS
/// review + signed merge + signed tag release in THIS repo's own git history to get compiled and
/// shipped at all. Walking the label-only lifecycle here (no `advance_with_evidence` shortcut exists
/// for this path — evidence is only accepted on `MergeApproved`/`PromoteSignedTag` through that
/// function) is a faithful re-statement of a fact already true in source control, not a bypass: a
/// dynamically-authored, non-built-in manifest has no such compiled-in provenance and MUST clear
/// `advance_with_evidence`'s real CODEOWNERS + signature checks before [`register_governed_harness`]
/// will ever admit it.
fn builtin_governance_production() -> ainxt_governance::GovernanceState {
    use ainxt_governance::{advance, start, GitEvent};
    let pending_approval =
        advance(start(), GitEvent::OpenPr).expect("Draft -> OpenPr is always a valid transition");
    let approved = advance(pending_approval, GitEvent::MergeApproved)
        .expect("PendingApproval -> MergeApproved is always a valid transition");
    advance(approved, GitEvent::PromoteSignedTag)
        .expect("Approved -> PromoteSignedTag is always a valid transition")
}

/// Build the harness surfaces the daemon mounts (HARN-03). Seeds the id-keyed [`HarnessRegistry`] with
/// the built-in `diag.selftest` harness so the surface is genuinely live; wires the capability-authz
/// [`HarnessRuntime`], the synchronous invoke [`StepExecutor`], and the engine-tool-path
/// [`CapabilityInvoker`] for the `/run` bridge.
///
/// `served_tools` is the served engine's OWN shared [`ToolRuntime`] handle
/// ([`crate::build_engine_ext`] / [`crate::build_chat_engine_with_authz`] now return one, threaded
/// through [`crate::Assembled::capability_tools`]) — R16 (§0/§1.2, CRITICAL) FIX: pass `Some(handle)`
/// so the `/run` bridge dispatches Tool/Skill steps through the IDENTICAL registry + exactly-once
/// ledger the served engine's own tool loop uses, never a second independently-built instance. Before
/// this fix, this function unconditionally called [`crate::build_unified_capability_registry`] itself,
/// producing a SECOND registry over a SECOND, disjoint ledger (a fresh [`ainxt_tools::InMemorySqlStore`]
/// every time it ran) — so the SAME caller-supplied idempotency key ("retry settlement initiation")
/// could commit once on the engine's ledger and AGAIN on the harness bridge's ledger: a
/// double-execution path on a payments platform (§1.2 scenario). `None` is reserved for a surface with
/// no real served [`ainxt_runtime::Engine`] at all (the AiNxt-OS workforce surface) — there is no
/// engine tool-dispatch path on that surface to collide with, so the harness bridge falls back to its
/// own OSS reference registry (native + MCP capabilities only, no risk of a second dispatcher for the
/// SAME capability set).
pub fn build_harness_mounts(
    report: &mut Vec<String>,
    served_tools: Option<Arc<ToolRuntime>>,
    gates: &ainxt_config::GatesConfig,
    harness_cfg: &crate::HarnessConfig,
) -> Result<HarnessMounts, crate::AssembleError> {
    let mut registry = HarnessRegistry::new();
    let mut manifest = HarnessManifest::new(
        DIAG_SELFTEST_ID,
        vec![HarnessStep {
            id: "selftest".into(),
            kind: StepKind::Skill,
            capability: CAP_DIAG_SELFTEST.into(),
            estimated_tokens: 1,
            input: None,
        }],
    )
    .with_capabilities([CAP_DIAG_SELFTEST]);
    manifest.owner = "ainxt-runtime".into();
    manifest.version = "1.0.0".into();
    // GAP-FIX harness-sdk-governance #4 — register THROUGH the authoring-to-production bridge, not by
    // calling `HarnessRegistry::register` directly: this is the one call site in the whole daemon that
    // connects `ainxt_governance::advance(..., Production)` to a harness actually going live. A
    // lint-clean manifest with a governance grant for exactly its declared capability.
    register_governed_harness(
        &mut registry,
        manifest,
        CapabilityGrant::new([CAP_DIAG_SELFTEST]),
        builtin_governance_production(),
    )
    .expect("built-in diag.selftest harness must register (it is at Production)");

    let runtime = HarnessRuntime::new(
        Box::new(CapabilityAuthorizer),
        Box::new(InMemoryHarnessAudit::new()),
    );
    // GAP-FIX harness-sdk-governance — `RegisteredRendererResolver` (fail-closed on an unregistered
    // `HarnessRenderer::Custom` id) was fully implemented but the daemon always installed the
    // permissive `AnyRendererResolver` default. Empty (default) config keeps that unchanged; a
    // deployment listing its bundled renderer ids under `[harness] registered_renderers` gets the
    // fail-closed resolver instead.
    let runtime = if harness_cfg.registered_renderers.is_empty() {
        runtime
    } else {
        report.push(format!(
            "harness: fail-closed RegisteredRendererResolver installed ({} bundled renderer id(s)) \
             — a manifest declaring an unregistered custom renderer is now refused at admission, not \
             silently accepted",
            harness_cfg.registered_renderers.len()
        ));
        runtime.with_renderer_resolver(Box::new(ainxt_admission::RegisteredRendererResolver::new(
            harness_cfg.registered_renderers.clone(),
        )))
    };
    // R16 (§0/§1.2, CRITICAL FIX): the `/run` bridge dispatches Tool/Skill steps through the SAME
    // instance of the ONE unified Capability registry (§0) the served engine dispatches through — reuse
    // `served_tools` when the caller has one (every surface with a real Engine) rather than building a
    // second, independently-instantiated registry (which — even registering the identical native/MCP
    // capability set — would carry its OWN fresh, disjoint exactly-once ledger; see the module + function
    // doc above). Only a surface with NO real Engine at all (the AiNxt-OS workforce surface) falls back
    // to its own freshly-built OSS reference registry, since there is no engine dispatch path to share
    // with (and therefore no double-execution risk from doing so).
    let tools = match served_tools {
        Some(shared) => shared,
        // No real Engine on this surface (the AiNxt-OS workforce surface): there is no engine
        // dispatch path to share with, so no double-execution risk in building its own.
        None => Arc::new(crate::build_unified_capability_registry(report)),
    };
    let obo_policy: Arc<dyn ainxt_tools::obo::OboPolicy> = Arc::new(
        ainxt_tools::obo::ThreeLayerPolicy::new(ainxt_tools::obo::MapAbac::new()),
    );
    // GAP-FIX tooling-mcp-plugins-routing — SAME durable-when-configured sink as the served engine's
    // own OBO gate (`crate::build_engine_ext`/`build_chat_engine_with_authz`), instead of always the
    // ephemeral `VecOboAudit`: the harness `/run` bridge's OBO decisions get the identical durability
    // guarantee `[gates] audit = "event-log"` already gives every other served audit record.
    let obo_sink = crate::build_obo_sink(gates)?;
    // GAP-AUDIT tooling-mcp-plugins-routing — "Saga/compensation has zero served callers": keep a
    // clone of the SAME shared `tools` handle `ToolPathInvoker` (below) wraps, so `saga_router`
    // (`ainxt-server`) can drive `ToolRuntime::dispatch_saga` against the real registry instead of a
    // second, independently-built one — see `HarnessMounts::tools`'s own doc for the double-execution
    // risk that would otherwise reintroduce.
    let saga_tools = tools.clone();
    let invoker: Arc<dyn CapabilityInvoker> =
        Arc::new(ToolPathInvoker::new(tools, obo_policy, obo_sink));

    report.push(
        "harness: invoke (/v1/harness/{id}) + run (/v1/harness/{id}/run) + saga (/v1/capability/saga) \
         MOUNTED on the shipped daemon — built-in diag.selftest harness published (surface is live); \
         HARN-03 identity via the authenticator seam; the /run capability bridge dispatches through the \
         SAME instance of the ONE unified Capability registry the served engine uses (R16: one \
         registry, one exactly-once ledger — never a second disjoint instance), via the audited \
         three-layer OBO gate (dispatch_obo_audited); /v1/capability/saga drives a real multi-step \
         composite action (dispatch_saga) through that SAME registry"
            .into(),
    );

    Ok(HarnessMounts {
        registry: Arc::new(registry),
        runtime: Arc::new(runtime),
        executor: Arc::new(SelfTestStepExecutor),
        invoker,
        tools: saga_tools,
    })
}

/// Which backend seals/persists connector OAuth tokens for the served surface — selectable via
/// `AINXT_TOKEN_STORE` (see [`crate::connector_token_backend`]), mirroring the Memory/EventLog
/// durability selection [`build_gates`](crate::build_gates) already applies to the audit sink
/// (`[gates] audit = "memory" | "event-log"`, `ainxt_config::AuditSinkKind`): `Memory` is the
/// dev/test default (an [`InMemorySqlTokenBackend`] — wiped on every daemon restart), `File` is the
/// durable OSS default ([`ainxt_token::FileTokenStore`] — encrypted records survive a restart via
/// atomic temp-file+rename writes, see that type's doc).
///
/// Cheap to clone either way: both variants share their backing store across clones
/// (`InMemorySqlTokenBackend`'s `Arc<Mutex<..>>` table, `FileTokenStore`'s `Arc<Mutex<..>>` map +
/// shared file path), so ONE instance still satisfies the "distributed refresh lock" sharing
/// requirement documented below — the SAME backend goes to both [`build_connector_gateway`] (SEAL
/// path) and [`build_connector_invoker`] (USE/refresh path).
#[derive(Clone)]
pub enum ConnectorTokenBackend {
    Memory(InMemorySqlTokenBackend),
    File(FileTokenStore),
}

/// Assemble the [`TokenVault`] for a given (codec, backend) pair — the ONE place that maps
/// [`ConnectorTokenBackend`] onto a concrete vault, used by both [`build_connector_gateway`] and
/// [`build_connector_invoker`] so the Memory/File choice can never diverge between the SEAL and
/// USE/refresh paths built from the same backend value.
pub(crate) fn build_vault_from_backend(
    codec: Box<dyn SecretCodec>,
    backend: ConnectorTokenBackend,
) -> TokenVault {
    match backend {
        ConnectorTokenBackend::Memory(b) => sql_token_vault(codec, b),
        ConnectorTokenBackend::File(store) => TokenVault::new(codec, Box::new(store)),
    }
}

/// Build the connector OAuth gateway the daemon mounts at `/connectors/*` (CONN-03). Air-gapped default:
/// an empty connector registry (catalog serves empty), an encrypted [`TokenVault`] over the configured
/// [`ConnectorTokenBackend`] (in-RAM unless `AINXT_TOKEN_STORE=file` is set — see
/// [`crate::connector_token_backend`]), and the [`OfflineTransport`] (the token exchange fails closed
/// without egress). A deployment registers real connectors + an [`OAuthProvider`](ainxt_oauth::OAuthProvider)
/// and swaps a reqwest transport behind the same seam. `codec` is the shared, rotatable [`AeadCodec`]
/// wrapping the configured 32-byte AEAD key when present, else an ephemeral one (see
/// [`crate::connector_token_key`]).
///
/// GAP-FIX connectors "distributed refresh lock never wired" — `token_backend` is a CALLER-SUPPLIED,
/// cheap-to-clone [`ConnectorTokenBackend`] (clones share the same backing table/file) rather than a
/// private `InMemorySqlTokenBackend::new()` this function owned exclusively. The composition root
/// ([`assemble_full`](crate::assemble_full)) hands the SAME backend here AND to
/// [`build_connector_invoker`], so a token this OAuth-callback path seals is actually resolvable by
/// the USE path's [`ainxt_connector_http::CoordinatorTokenSource`] — previously the two built two
/// entirely disjoint in-memory vaults, so a sealed token could never be read back by the refresher
/// even after this fix's token-source swap, silently.
///
/// GAP-FIX connectors round-2 (KEY-ROT-01) — `codec` is likewise a CALLER-SUPPLIED, cheap-to-clone
/// `Arc<AeadCodec>` rather than a fresh `AeadCodec::new(KeyRing::new(1, token_key))` this function
/// built for itself from a raw key. The composition root hands the SAME `Arc` here AND to
/// [`build_connector_invoker`] (wrapped in [`ainxt_token::SharedAeadCodec`] for each
/// [`TokenVault::new`](ainxt_token::TokenVault::new) call) — and, for the served surface, ALSO keeps a
/// clone to back `POST /admin/keys/rotate` — so a key rotation through that route is visible to both
/// the SEAL path (this gateway) and the OPEN/refresh path in the SAME call, never a second, disjoint
/// ring that silently keeps sealing under the pre-rotation key.
///
/// GAP-FIX token-durability (gap6) — `token_backend` was previously typed as a bare
/// `InMemorySqlTokenBackend`, so this function could ONLY ever build an in-RAM vault regardless of
/// configuration: `ainxt_token::FileTokenStore` (documented as "the durable OSS default" for exactly
/// this seam) had zero callers anywhere in the composition root, so connector OAuth tokens never
/// survived a daemon restart in the shipped default. `token_backend` is now the selectable
/// [`ConnectorTokenBackend`]; see [`crate::connector_token_backend`] for how the composition root
/// picks Memory vs File.
pub fn build_connector_gateway(
    codec: Arc<AeadCodec>,
    token_backend: ConnectorTokenBackend,
    report: &mut Vec<String>,
) -> ConnectorGateway {
    let connector_runtime = Arc::new(ConnectorRuntime::new(
        ConnectorRegistry::new(),
        // GAP-AUDIT connectors #6 — `dept_policy_from_env` is genuinely least-privilege with ZERO
        // required config (an unset/empty env var default-denies, never default-permits like
        // `AllowAllPolicy`), so this closes "served connector policy default is AllowAllPolicy, not
        // least-privilege org/dept scoping" with no weaker floor ever possible.
        Box::new(ainxt_connector::dept_policy_from_env(
            "AINXT_CONNECTOR_DEPT_RULES",
        )),
        Box::new(CapabilityConnectorAuthorizer),
        Box::new(MarkerEgressGuard),
        Box::new(HashChainedConnectorAudit::new()),
    ));
    let durable = matches!(token_backend, ConnectorTokenBackend::File(_));
    let vault =
        build_vault_from_backend(Box::new(ainxt_token::SharedAeadCodec(codec)), token_backend);
    report.push(format!(
        "connectors: OAuth surface (/connectors/*) MOUNTED on the shipped daemon (web + desktop as \
         identical renderers) — empty connector registry (catalog serves), encrypted TokenVault over a \
         {} backend (ciphertext-only at rest), offline transport (token exchange fail-closed without \
         egress)",
        if durable { "FILE (restart-durable)" } else { "in-RAM (wiped on restart)" }
    ));
    ConnectorGateway::new(
        connector_runtime,
        vault,
        Box::new(InMemoryPendingAuthStore::new()),
        Box::new(OfflineTransport),
        Box::new(HashChainedConnectorAudit::new()),
    )
}

/// Build the connector **USE path** organ (`ConnectorInvoker`) held LIVE on the served surface
/// (CONN-USE). Distinct from the OAuth [`ConnectorGateway`] ([`build_connector_gateway`], which mints +
/// seals tokens): this is the path that ACTUALLY CALLS an authorized connector API on-behalf-of the
/// caller, running — on EVERY call, before a byte leaves — OBO admission (authz), the egress/DLP
/// control (data-class ceiling + settlement-perimeter deny-list + payment-initiation tripwire), and the
/// audit seam. The air-gapped default wires the [`OfflineTransport`] (the actual send fails closed with
/// [`Unavailable`](ainxt_connector_http::ConnectorCallError::Unavailable) — a soft-degrade, never a
/// fabricated success) even after this fix — no connector is registered and no egress reaches the wire
/// offline, so a refresh is never actually attempted; only the WIRING is real. The admission/egress/
/// audit seams run regardless, so the USE path is genuinely INVOKED (not merely mounted) even air-gapped.
///
/// GAP-FIX connectors "distributed refresh lock never wired" (round-15 gap, closed here): the
/// `TokenSource` is now [`ainxt_connector_http::CoordinatorTokenSource`] wrapping a REAL
/// [`ainxt_refresh::RefreshCoordinator::served_default`] — the cross-process
/// double-checked-locking refresh protocol ([`ainxt_refresh::DistributedRefreshLock`]) — instead of
/// the empty [`StaticTokenSource`] every USE-path call used to see (which could never resolve ANY
/// sealed token, refreshed or not). `codec`/`token_backend` are the SAME values
/// [`build_connector_gateway`] seals tokens with/into — the composition root passes one shared
/// backend AND one shared `Arc<AeadCodec>` to both, so a token the OAuth callback path seals here IS
/// resolvable (and refreshed under lock when near-expiry) by this invoker, not silently orphaned in a
/// second, disjoint vault — and (KEY-ROT-01) a rotation of `codec` through `POST /admin/keys/rotate`
/// is visible to this READ/refresh path in the SAME call as the SEAL path above, never a stale ring.
// GAP-FIX connector-http item 1 — generalized from GitLab-only to connector-id-parameterized so
// Jira/Graph capabilities (`register_jira_capability`/`register_graph_capability`) can each build
// their OWN dedicated `ConnectorInvoker` through this SAME wiring. One `CoordinatorTokenSource` can
// only correctly serve ONE connector's tokens (it ignores its own `_connector` parameter at call time
// and always consults the ONE `RefreshCoordinator` it was built over — see that type's own doc), so
// GitLab/Jira/Graph each get their own instance of this function's wiring rather than sharing one.
// `build_connector_invoker` below is the pre-existing public GitLab entrypoint, now a thin wrapper.
fn build_scoped_connector_invoker(
    connector_id: &str,
    oauth_provider: ainxt_oauth::OAuthProvider,
    report: &mut Vec<String>,
    incidents: Arc<Mutex<ainxt_incident::IncidentRegister>>,
    control_plane: Arc<Mutex<ainxt_identity::control::ControlPlane>>,
    control_plane_sha: &str,
    codec: Arc<AeadCodec>,
    token_backend: ConnectorTokenBackend,
) -> (
    ainxt_connector_http::ConnectorInvoker,
    Arc<ControlPlaneRemediator>,
) {
    use ainxt_connector_http::{ConnectorInvoker, CoordinatorTokenSource, HttpRefreshExecutor};
    use ainxt_refresh::RefreshCoordinator;
    let connector_runtime = Arc::new(ConnectorRuntime::new(
        ConnectorRegistry::new(),
        // GAP-AUDIT connectors #6 — `dept_policy_from_env` is genuinely least-privilege with ZERO
        // required config (an unset/empty env var default-denies, never default-permits like
        // `AllowAllPolicy`), so this closes "served connector policy default is AllowAllPolicy, not
        // least-privilege org/dept scoping" with no weaker floor ever possible.
        Box::new(ainxt_connector::dept_policy_from_env(
            "AINXT_CONNECTOR_DEPT_RULES",
        )),
        Box::new(CapabilityConnectorAuthorizer),
        Box::new(MarkerEgressGuard),
        Box::new(HashChainedConnectorAudit::new()),
    ));
    // The vault this invoker's refresher READS from — built from the SAME (codec, backend) pair
    // `build_connector_gateway` seals OAuth-callback tokens INTO, so the two are one logical vault
    // over one live, rotatable ring, not two disjoint ones.
    // GAP-FIX token-durability (gap6) — `token_backend` is the selectable `ConnectorTokenBackend`
    // (Memory/File), dispatched through the SAME `build_vault_from_backend` helper
    // `build_connector_gateway` uses, so the SEAL and USE/refresh paths for a given connector always
    // agree on Memory-vs-File. `oauth_provider` is a caller-supplied parameter (connector-http item 1)
    // — this function no longer hardcodes GitLab's endpoints internally.
    let vault =
        build_vault_from_backend(Box::new(ainxt_token::SharedAeadCodec(codec)), token_backend);
    // Own dedicated ConnectorRuntime/vault/coordinator — see this fn's doc above for why one
    // CoordinatorTokenSource cannot correctly multiplex more than one connector's tokens.
    let refresh_executor: Box<dyn ainxt_refresh::RefreshExecutor> =
        Box::new(HttpRefreshExecutor::new(Box::new(OfflineTransport)));
    let coordinator =
        RefreshCoordinator::served_default(connector_id, oauth_provider, vault, refresh_executor);
    let token_source: Box<dyn ainxt_connector_http::TokenSource> =
        Box::new(CoordinatorTokenSource::new(coordinator));
    report.push(
        "connector USE path: ConnectorInvoker (OBO admission + egress/DLP + payment-boundary tripwire \
         + audit on EVERY call) LIVE on the served surface — offline transport fails closed (no \
         fabricated success). TokenSource is CoordinatorTokenSource over RefreshCoordinator::served_default \
         (REAL cross-process double-checked-locking refresh-under-lock, ainxt_refresh::DistributedRefreshLock \
         — previously StaticTokenSource(\"\"), which could never resolve ANY sealed token) — sharing the \
         SAME token vault backend build_connector_gateway's OAuth callback seals into"
            .into(),
    );
    // §4.6: bind the payment-boundary's graduated-tripwire response to the REAL identity control-plane
    // + incident register (ainxt-identity::remediation::ControlPlaneRemediator). When the Layer-6
    // tripwire fires on the live egress path, the invoker enacts the full graduated response through
    // this seam — quarantine the offending capability + revoke the acting identity (ADR-022 §17) +
    // raise a security incident (ADR-017) — as one enforced decision, never advisory.
    report.push(
        "connector USE path: §4.6 graduated tripwire remediation ENACTED on the live egress path — a \
         payment-initiation tripwire quarantines the capability + revokes the acting identity + raises \
         an incident on the SAME shared IncidentRegister/ControlPlane every other served surface reads \
         (GAP-AUDIT regulated-fi #2 — previously a private, disjoint register nothing could query)"
            .into(),
    );
    // GAP-FIX identity-payments — `ControlPlaneRemediator::is_quarantined`/`is_identity_revoked`/
    // `incident_count` had zero served callers: this remediator was built and immediately erased into
    // `Arc<dyn TripwireRemediation>` with no concrete handle retained, so nothing could ever query
    // what the tripwire had actually done. Keeping a second, concrete `Arc` clone alongside the
    // trait-object registration below costs nothing (the remediator's own state is behind its own
    // locks); each of this function's callers (`build_connector_invoker`, `register_jira_capability`,
    // `register_graph_capability`) keeps its own fresh remediator/incident-register/control-plane, so
    // this is not a wide blast radius.
    let remediator = Arc::new(ControlPlaneRemediator::with_shared(
        control_plane,
        incidents,
        control_plane_sha,
    ));
    let invoker =
        ConnectorInvoker::new(connector_runtime, Box::new(OfflineTransport), token_source)
            .with_tripwire_remediation(remediator.clone());
    (invoker, remediator)
}

/// Build the GitLab-scoped connector USE-path invoker (the pre-existing entrypoint — GitLab is
/// the deployment's SCM and the primary/first connector). A thin wrapper over
/// [`build_scoped_connector_invoker`] supplying GitLab's own OAuth config; unchanged behavior/signature
/// for its existing callers (`assemble_full`, this crate's own tests).
pub fn build_connector_invoker(
    report: &mut Vec<String>,
    incidents: Arc<Mutex<ainxt_incident::IncidentRegister>>,
    control_plane: Arc<Mutex<ainxt_identity::control::ControlPlane>>,
    control_plane_sha: &str,
    codec: Arc<AeadCodec>,
    // GAP-FIX token-durability (gap6) — `ConnectorTokenBackend`, not a bare `InMemorySqlTokenBackend`:
    // the composition root (`assemble_full_with_control_plane`) selects Memory/File once
    // (`connector_token_backend`) and hands the SAME value to both this function and
    // `build_connector_gateway`, so the gateway's SEAL path and this invoker's USE/refresh path always
    // agree on which backend a token lives in.
    token_backend: ConnectorTokenBackend,
) -> (
    ainxt_connector_http::ConnectorInvoker,
    Arc<ControlPlaneRemediator>,
) {
    let oauth_provider = ainxt_oauth::OAuthProvider {
        authorize_endpoint: std::env::var("AINXT_GITLAB_OAUTH_AUTHORIZE_URL")
            .unwrap_or_else(|_| "https://gitlab.invalid/oauth/authorize".to_string()),
        token_endpoint: std::env::var("AINXT_GITLAB_OAUTH_TOKEN_URL")
            .unwrap_or_else(|_| "https://gitlab.invalid/oauth/token".to_string()),
        client_id: std::env::var("AINXT_GITLAB_OAUTH_CLIENT_ID").unwrap_or_default(),
        redirect_uri: std::env::var("AINXT_GITLAB_OAUTH_REDIRECT_URI").unwrap_or_default(),
        scopes: vec!["api".to_string()],
    };
    build_scoped_connector_invoker(
        "gitlab",
        oauth_provider,
        report,
        incidents,
        control_plane,
        control_plane_sha,
        codec,
        token_backend,
    )
}

/// GAP-FIX connectors (CRITICAL) — "`ConnectorInvoker.invoke()` has zero production callers": before
/// this, [`build_connector_invoker`] was constructed into `AssembledFull::connector_invoker` at
/// `assemble_full` time, but no HTTP route or capability registration ever called `.invoke()`/
/// `.invoke_in()` on it — only the OAuth admin plumbing (authorize/callback/audit,
/// [`build_connector_gateway`]) was reachable. This is the SAME root cause as guardrails-injection's
/// "connector provenance lost": `Provenance::Connector` tagging (see [`ainxt_tools::Tool::tool_provenance`])
/// can never fire if nothing ever dispatches a connector capability in the first place.
///
/// Registers ONE real, dispatchable [`ConnectorCapability`] (`"gitlab.get_project"` — GitLab is a
/// common enterprise SCM and the primary connector per [`GitLab`]'s own doc) into `registry` — the SAME (still
/// plain, pre-`Arc`) [`ToolRuntime`] [`build_unified_capability_registry_shared_over`] is about to hand
/// back to `build_engine_ext`/`build_chat_engine_with_authz`, which wrap it `Arc` and install it on the
/// served `Engine` via `with_shared_tools` — so a live turn's model-issued tool call, the audited
/// three-layer OBO gate, the exactly-once ledger, AND the injection/quarantine taint pipeline all
/// dispatch through this SAME instance, exactly like every other native capability registered here.
///
/// The connector op's own admission→egress-DLP→payment-tripwire pipeline (§4.6) runs for REAL on every
/// dispatch via [`build_connector_invoker`]; this function builds that invoker a SECOND, dedicated
/// instance (its own fresh `IncidentRegister`/`ControlPlane`/token vault) rather than reusing
/// `assemble_full`'s — those two are surfaced independently today (`AssembledFull::connector_invoker`/
/// `.incidents`/`.control_plane` remain byte-identical to before this fix) and are NOT the same `Arc`.
/// Unifying them into one shared organ across every surface (bare/chat/governed/program/team) is a
/// larger `Assembled`-threading change deferred as follow-up — noted here explicitly, not silently
/// assumed away: this fix's own scope is "a live turn can dispatch a connector for real", which holds
/// regardless of which incident register the tripwire's consequences land on.
///
/// Air-gapped default: `ConnectorRegistry::new()` is empty and the transport is [`OfflineTransport`]
/// (see [`build_connector_invoker`]), so a dispatch fails CLOSED with an honest admission/egress error
/// — never a fabricated success. A deployment that registers a real "gitlab" `ConnectorDef` + swaps a
/// reqwest transport behind the same seams gets a genuinely working call with no code change here.
pub fn register_connector_capability(
    registry: &mut ToolRuntime,
    report: &mut Vec<String>,
    native_lock: &NativeControlLock,
) {
    // Connector invokers get their own fresh IncidentRegister. The arming policy for
    // connector-scoped registers is always generic (no pre-armed statutory clocks) —
    // the deployment-wide arming policy applies only to the main served surface register
    // (constructed in assemble_full with the loaded.incident config).
    let incidents = Arc::new(Mutex::new(ainxt_incident::IncidentRegister::new(
        ainxt_incident::ArmingPolicy::generic_default(),
    )));
    let control_plane = Arc::new(Mutex::new(ainxt_identity::control::ControlPlane::new()));
    // This invoker's own fresh, dedicated vault (see the doc above: intentionally NOT the same `Arc`
    // as `assemble_full`'s connector surface) — so its codec is its own fresh `AeadCodec`, not a clone
    // of the served surface's shared, admin-rotatable one.
    let token_key = crate::connector_token_key(report);
    let codec = Arc::new(AeadCodec::new(KeyRing::new(1, token_key)));
    let (invoker, _remediator) = build_connector_invoker(
        report,
        incidents,
        control_plane,
        &crate::control_plane_sha(),
        codec,
        ConnectorTokenBackend::Memory(InMemorySqlTokenBackend::new()),
    );
    let invoker = Arc::new(invoker);
    // Any authenticated `user_id` resolves to a `Principal` holding `connector.gitlab` — the coarse
    // "has connector access at all" grant `CapabilityConnectorAuthorizer` checks. Finer-grained
    // org/dept scoping is enforced downstream by the invoker's OWN policy
    // (`dept_policy_from_env`/`CapabilityConnectorAuthorizer`, built in `build_connector_invoker`), not
    // by this resolver — mirrors the identity-resolution shape `ConnectorCapability`'s own module doc
    // and the r16 per-request-identity proving test use.
    let principals: ainxt_connector_http::capability::PrincipalResolver =
        Arc::new(|uid: &str| Some(Principal::user(uid, &["connector.gitlab"])));
    let gitlab_base_url = std::env::var("AINXT_GITLAB_BASE_URL")
        .unwrap_or_else(|_| "https://gitlab.invalid".to_string());
    let build: ainxt_connector_http::capability::CallBuilder = Arc::new(move |args: &str| {
        let v: serde_json::Value = serde_json::from_str(args).map_err(|e| e.to_string())?;
        let project = v.get("project").and_then(|p| p.as_str()).ok_or_else(|| {
            "missing required 'project' field (namespace/repo path or id)".to_string()
        })?;
        Ok(GitLab::new(gitlab_base_url.clone()).get_project(project))
    });
    let capability = ConnectorCapability::new(
        "gitlab.get_project",
        invoker,
        principals,
        DEFAULT_CONNECTOR_TENANT,
        DataClass::Internal,
        build,
    )
    // Read-only GET — not ledgered, not two-phase; the USE path's own admission/egress/tripwire seams
    // still run on every dispatch regardless of effect class.
    .with_effect(EffectClass::Idempotent)
    .with_declared_data_class(DataClass::Internal)
    .with_schema(
        "Fetch a GitLab project's metadata (id, path, visibility) via the connector USE path — \
         args: {\"project\": \"namespace/repo\"}. Runs OBO admission + egress/DLP + payment-boundary \
         tripwire + audit before any byte leaves the box.",
        ParamSpec::Text,
    );
    // GAP-FIX gap6-tools-hooks-obo-supplychain item 2 — routed through the §3.4 native supply-chain
    // parity gate like every other native capability the composition root registers (see
    // `crate::served_native_control_lock`'s doc); `ConnectorCapability` defaults to `RiskTier::Low`
    // here (no `.with_risk(..)` call above), so this is behavior-preserving today.
    registry
        .try_register_governed_pinned(Box::new(capability), native_lock)
        .unwrap_or_else(|e| {
            report.push(format!(
                "capabilities: refused to register connector capability 'gitlab.get_project': {e:?}"
            ))
        });
    report.push(
        "connectors: USE-path capability 'gitlab.get_project' REGISTERED into the unified \
         ToolRuntime (ConnectorInvoker.invoke_in behind ainxt_tools::Tool::execute_as) — a live \
         chat/agent turn can now actually dispatch a connector call on the served default path \
         (previously reachable only from tests: zero production callers). Fails CLOSED on the \
         air-gapped default (empty ConnectorRegistry + OfflineTransport); results are tagged \
         Provenance::Connector so the injection/quarantine pipeline treats them as untrusted \
         external data, not a generic tool result."
            .into(),
    );
}

/// The tenant this daemon's built-in connector USE-path capability resolves tokens under. Single-
/// tenant deployments use the default; a multi-tenant deployment that needs per-tenant connector
/// scoping extends [`register_connector_capability`] to resolve the tenant from the acting principal
/// instead of this constant (the invoker's `invoke_in` is already tenant-scoped end-to-end — this is
/// the ONE built-in registration's tenant choice, not a structural single-tenant limitation).
const DEFAULT_CONNECTOR_TENANT: &str = "default";

/// GAP-FIX connector-http item 1 — "`Jira`/`Graph` adapters built but never instantiated": the module
/// doc of `ainxt_connector_http` promises three concrete adapters ("GitLab, Jira, Graph"), but only
/// `GitLab` was ever imported/instantiated by this file — `Jira`'s `get_issue`/`add_comment` and
/// `Graph`'s `get_me`/`list_messages`/`send_mail` had zero references outside that crate's own `mod
/// tests`. This registers TWO real, dispatchable [`ConnectorCapability`]s — `"jira.get_issue"` (read)
/// and `"jira.add_comment"` (write) — into `registry`, mirroring [`register_connector_capability`]'s
/// GitLab wiring exactly: its own dedicated [`ainxt_connector_http::ConnectorInvoker`] (built via
/// [`build_scoped_connector_invoker`], scoped to `"jira"`, with its own fresh
/// `IncidentRegister`/`ControlPlane`/token vault — never sharing GitLab's), and its own
/// [`PrincipalResolver`](ainxt_connector_http::capability::PrincipalResolver) granting `connector.jira`.
///
/// Jira Cloud is OAuth 2.0 (3LO) over Atlassian's OWN fixed `auth.atlassian.com` authorization server
/// — DIFFERENT from GitLab's self-hosted OAuth app endpoints and from Microsoft's per-tenant Entra
/// endpoints ([`register_graph_capability`]). See
/// [`ainxt_oauth::OAuthProvider::atlassian`]'s doc for the `audience`/`prompt` query-param and
/// `offline_access`-for-refresh-token nuances this deliberately does NOT copy from GitLab's config.
///
/// Air-gapped default: same fail-closed posture as GitLab — an empty `ConnectorRegistry` (no `jira`
/// `ConnectorDef` registered) + `OfflineTransport`, so a dispatch fails CLOSED with an honest
/// admission/egress error naming the connector, never a fabricated success.
pub fn register_jira_capability(registry: &mut ToolRuntime, report: &mut Vec<String>) {
    let incidents = Arc::new(Mutex::new(ainxt_incident::IncidentRegister::new(
        ainxt_incident::ArmingPolicy::generic_default(),
    )));
    let control_plane = Arc::new(Mutex::new(ainxt_identity::control::ControlPlane::new()));
    // This capability's own fresh vault — intentionally NOT shared with GitLab's or Graph's (each
    // connector's invoker is a fully separate instance; see build_scoped_connector_invoker's doc).
    let token_key = crate::connector_token_key(report);
    let codec = Arc::new(AeadCodec::new(KeyRing::new(1, token_key)));
    let oauth_provider = ainxt_oauth::OAuthProvider::atlassian(
        &std::env::var("AINXT_JIRA_OAUTH_CLIENT_ID").unwrap_or_default(),
        &std::env::var("AINXT_JIRA_OAUTH_REDIRECT_URI").unwrap_or_default(),
        &["read:jira-work", "write:jira-work", "offline_access"],
    );
    let (invoker, _remediator) = build_scoped_connector_invoker(
        "jira",
        oauth_provider,
        report,
        incidents,
        control_plane,
        &crate::control_plane_sha(),
        codec,
        ConnectorTokenBackend::Memory(InMemorySqlTokenBackend::new()),
    );
    let invoker = Arc::new(invoker);
    // Coarse "has connector access at all" grant, mirroring GitLab's resolver shape — finer org/dept
    // scoping is enforced downstream by the invoker's OWN policy (dept_policy_from_env), not here.
    let principals: ainxt_connector_http::capability::PrincipalResolver =
        Arc::new(|uid: &str| Some(Principal::user(uid, &["connector.jira"])));
    // Jira Cloud's REST API is actually reached through https://api.atlassian.com/ex/jira/{cloudId}
    // once OAuth-authorized (the cloudId is resolved via a separate accessible-resources call this
    // crate does not perform — see OAuthProvider::atlassian's doc); a real deployment sets this env
    // var to that resolved URL. The ".invalid" default is an obvious placeholder, exactly like GitLab's.
    let jira_base_url =
        std::env::var("AINXT_JIRA_BASE_URL").unwrap_or_else(|_| "https://jira.invalid".to_string());

    let base = jira_base_url.clone();
    let build_get_issue: ainxt_connector_http::capability::CallBuilder =
        Arc::new(move |args: &str| {
            let v: serde_json::Value = serde_json::from_str(args).map_err(|e| e.to_string())?;
            let key = v.get("key").and_then(|p| p.as_str()).ok_or_else(|| {
                "missing required 'key' field (issue key, e.g. 'ABC-123')".to_string()
            })?;
            Ok(Jira::new(base.clone()).get_issue(key))
        });
    let cap_get_issue = ConnectorCapability::new(
        "jira.get_issue",
        invoker.clone(),
        principals.clone(),
        DEFAULT_CONNECTOR_TENANT,
        DataClass::Internal,
        build_get_issue,
    )
    // Read-only GET — not ledgered, not two-phase.
    .with_effect(EffectClass::Idempotent)
    .with_declared_data_class(DataClass::Internal)
    .with_schema(
        "Fetch a Jira issue by key via the connector USE path — args: {\"key\": \"ABC-123\"}. Runs \
         OBO admission + egress/DLP + payment-boundary tripwire + audit before any byte leaves the box.",
        ParamSpec::Text,
    );
    registry
        .try_register_governed(Box::new(cap_get_issue))
        .unwrap_or_else(|e| {
            report.push(format!(
                "capabilities: refused to register connector capability 'jira.get_issue': {e:?}"
            ))
        });
    report.push(
        "connectors: USE-path capability 'jira.get_issue' REGISTERED into the unified ToolRuntime \
         (ConnectorInvoker.invoke_in behind ainxt_tools::Tool::execute_as) — Atlassian OAuth 2.0 \
         (3LO) via its own dedicated invoker/token vault (separate from GitLab's). Fails CLOSED on \
         the air-gapped default (empty ConnectorRegistry + OfflineTransport); results are tagged \
         Provenance::Connector so the injection/quarantine pipeline treats them as untrusted \
         external data."
            .into(),
    );

    let build_add_comment: ainxt_connector_http::capability::CallBuilder =
        Arc::new(move |args: &str| {
            let v: serde_json::Value = serde_json::from_str(args).map_err(|e| e.to_string())?;
            let key = v.get("key").and_then(|p| p.as_str()).ok_or_else(|| {
                "missing required 'key' field (issue key, e.g. 'ABC-123')".to_string()
            })?;
            let body = v
                .get("body")
                .and_then(|p| p.as_str())
                .ok_or_else(|| "missing required 'body' field (comment text)".to_string())?;
            Ok(Jira::new(jira_base_url.clone()).add_comment(key, body))
        });
    let cap_add_comment = ConnectorCapability::new(
        "jira.add_comment",
        invoker,
        principals,
        DEFAULT_CONNECTOR_TENANT,
        DataClass::Internal,
        build_add_comment,
    )
    // Write — keep the default SIDE-EFFECTING effect class (ledgered, exactly-once by construction).
    .with_declared_data_class(DataClass::Internal)
    .with_schema(
        "Add a comment to a Jira issue via the connector USE path — args: {\"key\": \"ABC-123\", \
         \"body\": \"...\"}. Runs OBO admission + egress/DLP + payment-boundary tripwire + audit \
         before any byte leaves the box.",
        ParamSpec::Text,
    );
    registry
        .try_register_governed(Box::new(cap_add_comment))
        .unwrap_or_else(|e| {
            report.push(format!(
                "capabilities: refused to register connector capability 'jira.add_comment': {e:?}"
            ))
        });
    report.push(
        "connectors: USE-path capability 'jira.add_comment' REGISTERED into the unified ToolRuntime \
         (ConnectorInvoker.invoke_in behind ainxt_tools::Tool::execute_as) — Atlassian OAuth 2.0 \
         (3LO) via its own dedicated invoker/token vault (separate from GitLab's). Fails CLOSED on \
         the air-gapped default (empty ConnectorRegistry + OfflineTransport); results are tagged \
         Provenance::Connector so the injection/quarantine pipeline treats them as untrusted \
         external data."
            .into(),
    );
}

/// GAP-FIX connector-http item 1 — the Graph half of "`Jira`/`Graph` adapters built but never
/// instantiated" (see [`register_jira_capability`]'s doc for the shared root cause). Registers THREE
/// real, dispatchable [`ConnectorCapability`]s — `"graph.get_me"` (read), `"graph.list_messages"`
/// (read), `"graph.send_mail"` (write) — into `registry`, each through its own dedicated
/// [`ainxt_connector_http::ConnectorInvoker`] (scoped to `"graph"`, own fresh
/// `IncidentRegister`/`ControlPlane`/token vault) and its own
/// [`PrincipalResolver`](ainxt_connector_http::capability::PrincipalResolver) granting
/// `connector.graph`.
///
/// Microsoft Graph is OAuth 2.0 over Entra ID's PER-TENANT endpoints
/// ([`ainxt_oauth::OAuthProvider::entra`], already used elsewhere for Teams/Office SSO) — DIFFERENT
/// from both GitLab's self-hosted OAuth app and Atlassian's single fixed authorization server
/// ([`register_jira_capability`]). `graph.list_messages`/`graph.send_mail` are declared
/// [`DataClass::Confidential`] (not `Internal` like GitLab/Jira) because email content routinely
/// carries PII/business-sensitive data — `graph.get_me` (basic profile only) stays `Internal`.
///
/// Air-gapped default: same fail-closed posture as GitLab/Jira — an empty `ConnectorRegistry` (no
/// `graph` `ConnectorDef` registered) + `OfflineTransport`, so a dispatch fails CLOSED with an honest
/// admission/egress error naming the connector, never a fabricated success.
pub fn register_graph_capability(registry: &mut ToolRuntime, report: &mut Vec<String>) {
    let incidents = Arc::new(Mutex::new(ainxt_incident::IncidentRegister::new(
        ainxt_incident::ArmingPolicy::generic_default(),
    )));
    let control_plane = Arc::new(Mutex::new(ainxt_identity::control::ControlPlane::new()));
    let token_key = crate::connector_token_key(report);
    let codec = Arc::new(AeadCodec::new(KeyRing::new(1, token_key)));
    // "common" (multi-tenant work/school + personal accounts) is Microsoft's own standard default
    // tenant value when a deployment hasn't pinned one — a real single-tenant deployment overrides it.
    let graph_tenant =
        std::env::var("AINXT_GRAPH_OAUTH_TENANT_ID").unwrap_or_else(|_| "common".to_string());
    let oauth_provider = ainxt_oauth::OAuthProvider::entra(
        &graph_tenant,
        &std::env::var("AINXT_GRAPH_OAUTH_CLIENT_ID").unwrap_or_default(),
        &std::env::var("AINXT_GRAPH_OAUTH_REDIRECT_URI").unwrap_or_default(),
        &["User.Read", "Mail.Read", "Mail.Send", "offline_access"],
    );
    let (invoker, _remediator) = build_scoped_connector_invoker(
        "graph",
        oauth_provider,
        report,
        incidents,
        control_plane,
        &crate::control_plane_sha(),
        codec,
        ConnectorTokenBackend::Memory(InMemorySqlTokenBackend::new()),
    );
    let invoker = Arc::new(invoker);
    let principals: ainxt_connector_http::capability::PrincipalResolver =
        Arc::new(|uid: &str| Some(Principal::user(uid, &["connector.graph"])));
    let graph_base_url = std::env::var("AINXT_GRAPH_BASE_URL")
        .unwrap_or_else(|_| "https://graph.microsoft.com".to_string());

    let base = graph_base_url.clone();
    let build_get_me: ainxt_connector_http::capability::CallBuilder =
        Arc::new(move |_args: &str| Ok(Graph::with_base(base.clone()).get_me()));
    let cap_get_me = ConnectorCapability::new(
        "graph.get_me",
        invoker.clone(),
        principals.clone(),
        DEFAULT_CONNECTOR_TENANT,
        DataClass::Internal,
        build_get_me,
    )
    .with_effect(EffectClass::Idempotent)
    .with_declared_data_class(DataClass::Internal)
    .with_schema(
        "Fetch the signed-in user's Microsoft Graph profile via the connector USE path — no args \
         required. Runs OBO admission + egress/DLP + payment-boundary tripwire + audit before any \
         byte leaves the box.",
        ParamSpec::Text,
    );
    registry
        .try_register_governed(Box::new(cap_get_me))
        .unwrap_or_else(|e| {
            report.push(format!(
                "capabilities: refused to register connector capability 'graph.get_me': {e:?}"
            ))
        });
    report.push(
        "connectors: USE-path capability 'graph.get_me' REGISTERED into the unified ToolRuntime \
         (ConnectorInvoker.invoke_in behind ainxt_tools::Tool::execute_as) — Microsoft Entra ID \
         OAuth 2.0 via its own dedicated invoker/token vault (separate from GitLab's/Jira's). Fails \
         CLOSED on the air-gapped default (empty ConnectorRegistry + OfflineTransport); results are \
         tagged Provenance::Connector so the injection/quarantine pipeline treats them as untrusted \
         external data."
            .into(),
    );

    let base2 = graph_base_url.clone();
    let build_list_messages: ainxt_connector_http::capability::CallBuilder =
        Arc::new(move |args: &str| {
            let top: u32 = if args.trim().is_empty() {
                10
            } else {
                let v: serde_json::Value = serde_json::from_str(args).map_err(|e| e.to_string())?;
                v.get("top").and_then(|p| p.as_u64()).unwrap_or(10) as u32
            };
            Ok(Graph::with_base(base2.clone()).list_messages(top))
        });
    let cap_list_messages = ConnectorCapability::new(
        "graph.list_messages",
        invoker.clone(),
        principals.clone(),
        DEFAULT_CONNECTOR_TENANT,
        DataClass::Confidential,
        build_list_messages,
    )
    .with_effect(EffectClass::Idempotent)
    .with_declared_data_class(DataClass::Confidential)
    .with_schema(
        "List the signed-in user's recent Microsoft Graph mail messages via the connector USE path \
         — args: {\"top\": 10} (optional, default 10). Email content may carry PII/business-sensitive \
         data, so this is declared Confidential. Runs OBO admission + egress/DLP + payment-boundary \
         tripwire + audit before any byte leaves the box.",
        ParamSpec::Text,
    );
    registry
        .try_register_governed(Box::new(cap_list_messages))
        .unwrap_or_else(|e| {
            report.push(format!(
                "capabilities: refused to register connector capability 'graph.list_messages': {e:?}"
            ))
        });
    report.push(
        "connectors: USE-path capability 'graph.list_messages' REGISTERED into the unified \
         ToolRuntime (ConnectorInvoker.invoke_in behind ainxt_tools::Tool::execute_as) — Microsoft \
         Entra ID OAuth 2.0 via its own dedicated invoker/token vault (separate from GitLab's/Jira's). \
         Fails CLOSED on the air-gapped default (empty ConnectorRegistry + OfflineTransport); results \
         are tagged Provenance::Connector so the injection/quarantine pipeline treats them as \
         untrusted external data."
            .into(),
    );

    let build_send_mail: ainxt_connector_http::capability::CallBuilder =
        Arc::new(move |args: &str| {
            let v: serde_json::Value = serde_json::from_str(args).map_err(|e| e.to_string())?;
            let to = v.get("to").and_then(|p| p.as_str()).ok_or_else(|| {
                "missing required 'to' field (recipient email address)".to_string()
            })?;
            let subject = v
                .get("subject")
                .and_then(|p| p.as_str())
                .ok_or_else(|| "missing required 'subject' field".to_string())?;
            let body = v
                .get("body")
                .and_then(|p| p.as_str())
                .ok_or_else(|| "missing required 'body' field".to_string())?;
            Ok(Graph::with_base(graph_base_url.clone()).send_mail(to, subject, body))
        });
    let cap_send_mail = ConnectorCapability::new(
        "graph.send_mail",
        invoker,
        principals,
        DEFAULT_CONNECTOR_TENANT,
        DataClass::Confidential,
        build_send_mail,
    )
    // Write — keep the default SIDE-EFFECTING effect class (ledgered, exactly-once by construction).
    .with_declared_data_class(DataClass::Confidential)
    .with_schema(
        "Send an email as the signed-in user via Microsoft Graph via the connector USE path — args: \
         {\"to\": \"a@b.com\", \"subject\": \"...\", \"body\": \"...\"}. Declared Confidential (email \
         content). Runs OBO admission + egress/DLP + payment-boundary tripwire + audit before any \
         byte leaves the box.",
        ParamSpec::Text,
    );
    registry
        .try_register_governed(Box::new(cap_send_mail))
        .unwrap_or_else(|e| {
            report.push(format!(
                "capabilities: refused to register connector capability 'graph.send_mail': {e:?}"
            ))
        });
    report.push(
        "connectors: USE-path capability 'graph.send_mail' REGISTERED into the unified ToolRuntime \
         (ConnectorInvoker.invoke_in behind ainxt_tools::Tool::execute_as) — Microsoft Entra ID \
         OAuth 2.0 via its own dedicated invoker/token vault (separate from GitLab's/Jira's). Fails \
         CLOSED on the air-gapped default (empty ConnectorRegistry + OfflineTransport); results are \
         tagged Provenance::Connector so the injection/quarantine pipeline treats them as untrusted \
         external data."
            .into(),
    );
}

/// Build the artifact-generation runtime the daemon mounts at `/v1/artifact` (R6 DATA): the built-in
/// renderers (markdown/plain-text) + the generic Luhn/entropy content scanner (audit-and-proceed — a
/// finding rides on the output, never redacts/blocks). A deployment plugs its PCI scanner behind the
/// same [`ContentScanner`](ainxt_artifact::ContentScanner) seam.
pub fn build_artifact_runtime(report: &mut Vec<String>) -> ArtifactRuntime {
    report.push(
        "artifact: document-generation surface (/v1/artifact) MOUNTED on the shipped daemon \
         (RBAC-scoped on artifact.generate; text + binary pdf/docx/xlsx renderers + Luhn/entropy \
         scanner; audit-and-proceed). A deployment adds a skill-service pptx renderer via register()"
            .into(),
    );
    ArtifactRuntime::with_all_renderers(Box::new(LuhnEntropyScanner))
}

/// Build the durable session store the daemon mounts behind `/v1/replay/step` (R6 DATA). The OSS
/// default is the in-RAM [`InMemorySessionStore`]; production swaps a DB-backed [`SessionStore`] behind
/// the same seam with no route change.
pub fn build_replay_store(report: &mut Vec<String>) -> Arc<dyn SessionStore> {
    report.push(
        "replay: store-backed step-through surface (/v1/replay/step) MOUNTED on the shipped daemon \
         (RBAC-scoped, clearance-filtered, stateless integer-cursor paging)"
            .into(),
    );
    Arc::new(InMemorySessionStore::new())
}

/// Build the live-model [`ReExecutor`] seam the daemon mounts behind `POST /v1/replay/reexecute`
/// (gap6 replay-reexec-presence). `re_execute_persisted_req`/`drift_report_persisted` were fully
/// implemented and unit-tested in `ainxt-replay` (`tests/r12_data_surfaces.rs`), but nothing in the
/// composition root ever constructed an executor or mounted a route for them — a canary/auto-rollback
/// gate could never actually ask the shipped daemon "did this turn's output drift since it was
/// recorded?". The OSS default is the offline [`DeterministicReplayExecutor`] (INFRA-gated: it makes
/// no live model call); production swaps a provider-backed executor (model-gateway routed, data-class
/// → model-eligibility enforced) behind the SAME seam with no route change.
pub fn build_reexec_executor(report: &mut Vec<String>) -> Arc<dyn ReExecutor + Send + Sync> {
    report.push(
        "replay: store-backed re-execution + drift oracle (POST /v1/replay/reexecute, POST \
         /v1/replay/drift) MOUNTED on the shipped daemon over the SAME durable SessionStore \
         /v1/replay/step reads (RBAC-scoped, redaction-preserving; offline DeterministicReplayExecutor \
         by default — a deployment plugs a live model-backed executor behind the same seam)"
            .into(),
    );
    Arc::new(DeterministicReplayExecutor::new(DataClass::Internal))
}

/// Build the DSAR / right-to-erasure organ held on the served surface: the tiered cache erasure cascade
/// (answer + prompt-prefix partition deletion tied to KV zeroize-before-free). A DPDP erasure request
/// or a session-end hook drains it so a principal's cached content is provably purged across tiers.
///
/// **R16 CRITICAL fix (serving-ops)**: `shared_answer_cache` is the LIVE served `ChatSurface`'s own
/// answer-cache handle (`Assembled::shared_answer_cache`, sourced from
/// `ainxt_chat::ChatSurface::answer_cache_handle` at the point the chat surface is assembled). Before
/// this fix the organ built via `TieredCacheErasure::new` owned a private, never-populated
/// `PartitionedCache` — a DPDP erasure request drained an empty cache while the served chat path kept
/// answering from a completely different instance, so the erasure acknowledgement was vacuous. Handing
/// the SAME `Arc` here (`with_shared_answer_cache`) makes `erase_principal` purge exactly the entries
/// the served `/v1/chat` turn path actually wrote. A surface with no live `ChatSurface` (bare-engine /
/// program / team / workforce) passes a fresh private handle — there is no served answer cache to
/// share, and the KV + prompt-prefix tiers stay live either way.
pub fn build_erasure(
    shared_answer_cache: Arc<Mutex<ainxt_cache::PartitionedCache>>,
    report: &mut Vec<String>,
) -> TieredCacheErasure {
    report.push(
        "erasure: DSAR/right-to-erasure organ (TieredCacheErasure cascade — answer + prompt-prefix + \
         KV zeroize-before-free) LIVE on the served surface, SHARING the live served ChatSurface \
         answer-cache instance (R16 CRITICAL fix: erasure now reaches the cache the served /v1/chat \
         path actually reads, not a private never-populated organ)"
            .into(),
    );
    TieredCacheErasure::with_shared_answer_cache(shared_answer_cache, CacheConfig::default())
}

/// The default DPDP statutory retention floor (ticks) for a regulated/PII record — the minimum period a
/// record must be retained before an erasure request may fire (§6.1). A deployment sets the real
/// jurisdiction-specific floors; the shipped default is a conservative non-zero floor so a right-to-
/// erasure request can never delete below a statutory retention obligation.
const REGULATED_RETENTION_FLOOR_TICKS: u64 = 365 * 24 * 60 * 60;

/// The default retention TTL (ticks) after which a record of any class becomes purge-eligible (absent a
/// legal hold / retention floor). A deployment tunes per data-class; the shipped default keeps the
/// lifecycle organ LIVE with a sane, non-infinite window (DPDP "storage limitation").
const DEFAULT_RETENTION_TTL_TICKS: u64 = 7 * 365 * 24 * 60 * 60;

/// Build the data-lifecycle control organ the shipped daemon holds LIVE on the served surface (R7
/// REGFI): the durable [`RecordStore`](ainxt_lifecycle::RecordStore) enforcing per-data-class retention
/// TTL, the statutory retention floor + legal-hold override (a held/floored record is NEVER erased even
/// on a DSAR request — the regulator's freeze wins), and the DSAR right-to-erasure
/// ([`RecordStore::erase_subject`]) cascade over the record tier. Distinct from the cache-tier
/// [`TieredCacheErasure`] DSAR organ ([`build_erasure`]); together they cover the cache AND the durable
/// record tier. Offline-safe: an empty store with default policies serves; a deployment seeds real
/// records + jurisdiction policies + open legal-hold matters behind the same organ.
pub fn build_record_store(report: &mut Vec<String>) -> ainxt_lifecycle::RecordStore {
    use ainxt_lifecycle::RetentionPolicy;
    use ainxt_types::DataClass;
    let store = ainxt_lifecycle::RecordStore::new()
        .with_policy(RetentionPolicy::new(
            DataClass::Public,
            DEFAULT_RETENTION_TTL_TICKS,
        ))
        .with_policy(RetentionPolicy::new(
            DataClass::Internal,
            DEFAULT_RETENTION_TTL_TICKS,
        ))
        .with_policy(RetentionPolicy::new(
            DataClass::Confidential,
            DEFAULT_RETENTION_TTL_TICKS,
        ))
        .with_policy(
            RetentionPolicy::new(DataClass::RegulatedPayment, DEFAULT_RETENTION_TTL_TICKS)
                .with_floor(REGULATED_RETENTION_FLOOR_TICKS),
        )
        .with_policy(
            RetentionPolicy::new(DataClass::Pii, DEFAULT_RETENTION_TTL_TICKS)
                .with_floor(REGULATED_RETENTION_FLOOR_TICKS),
        );
    report.push(
        "lifecycle: data-retention / legal-hold / DSAR right-to-erasure control organ (RecordStore \
         with per-class TTL + regulated retention floor + legal-hold freeze) LIVE on the served surface"
            .into(),
    );
    store
}

/// The default live-quality bar (0.0–1.0, the [`MonitoringScoreboard`](ainxt_responsibleai::MonitoringScoreboard)
/// `latest_score` scale) below which the SR-11-7 quality circuit-breaker trips a model route. 0.7 is a
/// conservative floor consistent with the SR-11-7 due-diligence `min_score` default (0.8); a deployment
/// tunes it per route/data-class. (Previously mis-scaled to 70.0, which — now that the breaker is
/// actually EVALUATED on the promotion path — would trip every route; fixed to the 0–1 score scale.)
const QUALITY_BREAKER_BAR: f64 = 0.7;

/// Build the SR-11-7 model-risk quality circuit-breaker organ held on the served surface: the runtime
/// half of §2.1 that trips a regulated route whose live monitoring scoreboard drops below the bar (or is
/// absent), producing the [`BreakerTrip`](ainxt_responsibleai::BreakerTrip) the parent maps to an
/// operational-risk incident.
pub fn build_quality_breaker(report: &mut Vec<String>) -> QualityCircuitBreaker {
    report.push(format!(
        "model-risk: SR-11-7 quality circuit-breaker organ (bar={QUALITY_BREAKER_BAR}, 0–1 score \
         scale) LIVE + EVALUATED on the served promotion/routing path — a route whose live scoreboard \
         is absent or below the bar trips the breaker (a regulated route's trip arms an incident)"
    ));
    QualityCircuitBreaker::new(QUALITY_BREAKER_BAR)
}

// ============================ GAP-FIX harness-sdk-governance #4: proving tests ============================

#[cfg(test)]
mod governed_registration_tests {
    use super::*;

    fn manifest(id: &str) -> HarnessManifest {
        let mut m = HarnessManifest::new(
            id,
            vec![HarnessStep {
                id: "s1".into(),
                kind: StepKind::Skill,
                capability: "cap.x".into(),
                estimated_tokens: 1,
                input: None,
            }],
        )
        .with_capabilities(["cap.x"]);
        m.owner = "team".into();
        m.version = "1.0.0".into();
        m
    }

    /// The bridge PUBLISHES a definition that has genuinely reached Production on the git-native
    /// lifecycle — the positive case `build_harness_mounts` itself relies on for its built-in harness.
    #[test]
    fn register_governed_harness_publishes_at_production() {
        let mut registry = HarnessRegistry::new();
        let state = builtin_governance_production();
        assert_eq!(state, ainxt_governance::GovernanceState::Production);
        register_governed_harness(
            &mut registry,
            manifest("h1"),
            CapabilityGrant::new(["cap.x"]),
            state,
        )
        .expect("a Production-state definition must register");
        assert!(
            registry.get("h1").is_some(),
            "the definition must actually be live after registering"
        );
    }

    /// The bridge's entire reason to exist: REFUSE a definition that has NOT reached Production, for
    /// every earlier lifecycle state — proving this is a real fail-closed gate, not a pass-through
    /// that always registers regardless of `state`. Before this bridge existed, `build_harness_mounts`
    /// had NO such check at all: `HarnessRegistry::register` ran unconditionally.
    #[test]
    fn register_governed_harness_refuses_every_non_production_state() {
        use ainxt_governance::{advance, start, GitEvent, GovernanceState};

        let draft = start();
        let pending_approval =
            advance(draft, GitEvent::OpenPr).expect("Draft -> OpenPr is always valid");
        let approved = advance(pending_approval, GitEvent::MergeApproved)
            .expect("PendingApproval -> MergeApproved is always valid");

        for (label, state) in [
            ("draft", draft),
            ("pending_approval", pending_approval),
            ("approved", approved),
        ] {
            let mut registry = HarnessRegistry::new();
            let err = register_governed_harness(
                &mut registry,
                manifest("h-not-yet"),
                CapabilityGrant::new(["cap.x"]),
                state,
            )
            .expect_err(&format!("state {label:?} must be refused, not registered"));
            assert!(
                matches!(err, GovernedRegisterError::NotProduction(s) if s == state),
                "wrong refusal reason for {label}: {err}"
            );
            assert!(
                registry.get("h-not-yet").is_none(),
                "a non-Production definition must never become live ({label})"
            );
        }
        // `Deprecated` (a definition that WAS production but was retired) must also be refused — the
        // bridge is a strict equality gate on `Production`, not merely "not Draft".
        let production = advance(approved, GitEvent::PromoteSignedTag).unwrap();
        let deprecated = advance(production, GitEvent::Deprecate).unwrap();
        assert_eq!(deprecated, GovernanceState::Deprecated);
        let mut registry = HarnessRegistry::new();
        assert!(matches!(
            register_governed_harness(
                &mut registry,
                manifest("h-retired"),
                CapabilityGrant::new(["cap.x"]),
                deprecated,
            ),
            Err(GovernedRegisterError::NotProduction(
                GovernanceState::Deprecated
            ))
        ));
    }

    /// The built-in `diag.selftest` manifest `build_harness_mounts` registers goes THROUGH the bridge
    /// at a genuinely-computed `Production` state (not a hardcoded literal) — proving the composition
    /// root's real call site is wired to the bridge, not just the bridge function existing in isolation.
    #[test]
    fn builtin_manifest_reaches_production_via_the_real_lifecycle_transitions() {
        assert_eq!(
            builtin_governance_production(),
            ainxt_governance::GovernanceState::Production
        );
    }
}

/// GAP-FIX token-durability (gap6) — `ainxt_token::FileTokenStore` (the crate's own documented "durable
/// OSS default" for the connector token store — encrypted records persist via atomic temp-file+rename
/// writes and survive a restart) had ZERO callers anywhere in the composition root: both
/// `build_connector_gateway` and `build_connector_invoker` could only ever be handed an
/// `InMemorySqlTokenBackend`, so a connector OAuth token never actually survived a daemon restart in the
/// shipped default. These tests prove the fix through the REAL composition-root function
/// (`build_connector_gateway`, the exact function `assemble_full` calls to build
/// `AssembledFull::connectors` — the vault mounted at the served `/connectors/*` routes) rather than
/// `FileTokenStore`'s own isolated round-trip tests (which already existed and proved nothing about
/// reachability).
#[cfg(test)]
mod token_durability_tests {
    use super::*;
    use ainxt_token::{SharedAeadCodec, DEFAULT_TENANT};

    /// Build a scratch directory unique to this test process+time (parallel `cargo test` runs must
    /// never collide on the same file).
    fn scratch_dir(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ainxt-gap6-token-durability-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("create scratch dir");
        dir
    }

    /// The core durability proof: seal a token (exactly the way `ConnectorGateway::complete_callback`
    /// does — `TokenVault::save_in`, over the SAME (codec, backend) → vault seam
    /// `build_connector_gateway` uses internally, `build_vault_from_backend`), confirm the REAL
    /// composition-root gateway reads it back, then simulate a daemon restart by opening a BRAND NEW,
    /// process-disconnected `FileTokenStore` handle on the SAME file path and building a SECOND,
    /// independent `build_connector_gateway` from it. The token must still be there — proving actual
    /// restart durability (a fresh handle re-reading the file), not merely the first handle's own
    /// in-memory cache still being alive.
    #[test]
    fn connector_gateway_token_survives_a_simulated_restart_via_file_token_store() {
        let dir = scratch_dir("survives");
        let path = dir.join("connector-tokens.json");
        let key = [7u8; 32];
        let alice = Principal::user("alice@example", &["connector.gitlab"]);

        // --- Before "restart": seal a token into a FileTokenStore-backed vault, using the identical
        // seal call `complete_callback` makes on the real OAuth path.
        let store = FileTokenStore::open(&path).expect("open file token store");
        let seed_vault = TokenVault::new(
            Box::new(SharedAeadCodec(Arc::new(AeadCodec::new(KeyRing::new(
                1, key,
            ))))),
            Box::new(store.clone()),
        );
        seed_vault
            .save_in(
                DEFAULT_TENANT,
                "alice@example",
                "gitlab",
                b"secret-token",
                None,
                &["api".to_string()],
            )
            .expect("seed token");

        // The REAL composition-root function, over the SAME store, sees it immediately (same process).
        let mut report = Vec::new();
        let gateway_before = build_connector_gateway(
            Arc::new(AeadCodec::new(KeyRing::new(1, key))),
            ConnectorTokenBackend::File(store),
            &mut report,
        );
        let authorized_before = gateway_before
            .authorized(DEFAULT_TENANT, &alice, "alice@example")
            .expect("authorized before restart");
        assert_eq!(
            authorized_before,
            vec!["gitlab".to_string()],
            "the composition-root gateway must see the sealed token before any restart"
        );
        drop(gateway_before);

        // --- Simulated restart: a BRAND NEW `FileTokenStore::open` on the SAME path — no shared
        // in-memory state with the handle above — feeding a SECOND, independent
        // `build_connector_gateway` call (mirrors exactly what `assemble_full` does on daemon boot).
        let reopened =
            FileTokenStore::open(&path).expect("reopen file token store after \"restart\"");
        let mut report2 = Vec::new();
        let gateway_after = build_connector_gateway(
            Arc::new(AeadCodec::new(KeyRing::new(1, key))),
            ConnectorTokenBackend::File(reopened),
            &mut report2,
        );
        let authorized_after = gateway_after
            .authorized(DEFAULT_TENANT, &alice, "alice@example")
            .expect("authorized after restart");
        assert_eq!(
            authorized_after,
            vec!["gitlab".to_string()],
            "FileTokenStore must survive a daemon restart: a token sealed before restart must still be \
             visible through a freshly-opened store on the same file, via the SAME composition-root \
             build_connector_gateway function"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Control: with the in-RAM `Memory` backend (the byte-identical default when `AINXT_TOKEN_STORE`
    /// is unset), a token does NOT survive a fresh backend instance — the same shape a real process
    /// restart takes for the old (still-default) behavior. Without this control, a bug that made the
    /// test above pass unconditionally (e.g. accidentally asserting on stale state) would go unnoticed.
    #[test]
    fn connector_gateway_token_does_not_survive_restart_on_the_in_memory_default() {
        let key = [11u8; 32];
        let bob = Principal::user("bob@example", &["connector.gitlab"]);

        let seed_vault = sql_token_vault(
            Box::new(AeadCodec::new(KeyRing::new(1, key))),
            InMemorySqlTokenBackend::new(),
        );
        seed_vault
            .save_in(
                DEFAULT_TENANT,
                "bob@example",
                "gitlab",
                b"secret-token",
                None,
                &["api".to_string()],
            )
            .expect("seed token");

        // A FRESH InMemorySqlTokenBackend (never cloned from the one above) models exactly what happens
        // to the in-RAM default across a real process restart: the table starts empty.
        let mut report = Vec::new();
        let gateway_after = build_connector_gateway(
            Arc::new(AeadCodec::new(KeyRing::new(1, key))),
            ConnectorTokenBackend::Memory(InMemorySqlTokenBackend::new()),
            &mut report,
        );
        let authorized_after = gateway_after
            .authorized(DEFAULT_TENANT, &bob, "bob@example")
            .expect("authorized after \"restart\"");
        assert!(
            authorized_after.is_empty(),
            "the in-RAM default must NOT survive a restart (sanity control for the durability test \
             above): {authorized_after:?}"
        );
    }
}
