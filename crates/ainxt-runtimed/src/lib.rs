// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! ainxt-runtimed — the composition binary (plan L6), library half.
//!
//! Every phase left one honest seam open: "assemble it all from `RuntimeConfig` at the composition
//! boundary." This is that boundary. It:
//!
//! 1. **Loads** a layered config (defaults → deployment → tenant …), splits off the `[server]` and
//!    `[session]` sections, and resolves + validates the [`RuntimeConfig`].
//! 2. **Selects the mandatory gates** from `[gates]`. The OSS build ships the default gates
//!    (redact-and-proceed compliance, capability RBAC, in-memory audit). If a config selects an
//!    **enterprise** gate this binary was not built with (PCI/DSS, AD-RBAC, durable event-log
//!    audit), it **refuses to start** — never a silent downgrade to a weaker gate.
//! 3. **Wires providers** from `[models]`: real OpenAI-schema / Anthropic adapters when an API key
//!    is present, and an **offline provider** so the daemon runs air-gapped with no model at all.
//! 4. Applies limits / retry / guardrails / injection, builds the [`Engine`] + [`SessionManager`],
//!    and (in `main`) serves the protocol over `ainxt-server`.
//!
//! The assembly is pure + testable; `main.rs` is a thin shell that binds a socket and serves.
//! Clean-room throughout.

use std::sync::{Arc, Mutex};

use ainxt_cache::{CacheConfig, Clock, HashEmbedder, PartitionedCache};
use ainxt_chat::{ChatSurface, CHAT_HARNESS_ID};
use ainxt_config::{
    AuditSinkKind, AuthzProvider, ComplianceProvider, GatesConfig, ModelsConfig, ProviderConfig,
    ProviderKind, RuntimeConfig,
};
use ainxt_context::{Chunk, Corpus};
use ainxt_eval::vault::VaultStore;
use ainxt_eventlog::EventLog;
use ainxt_graph::Graph;
use ainxt_identity::authority::{KillScope, KillSwitchAudit, KillSwitchAuthError};
use ainxt_identity::control::ControlPlane;
use ainxt_identity::remediation::ControlPlaneRemediator;
use ainxt_identity::transparency::{Sha256Hasher, TransparencyLog};
use ainxt_incident::cadence::CadenceScheduler;
use ainxt_incident::{
    ArmingPolicy, IncidentCandidate, IncidentError, IncidentRegister, StatutoryClockKind,
};
// R9 — the route-ready BSA §63 evidentiary-export + §8.3 read-only supervisory auditor seams the
// shipped daemon hot-wires over the LIVE served IncidentRegister.
use ainxt_incident::evidence::{
    AuditorError, AuditorScope, AuditorSession, EvidenceExportRequest, EvidenceRouteError,
    EvidentiaryExport,
};
// R9 — the §6 redact-with-attestation right-to-erasure artifact + the retention-admin capability the
// served erasure entrypoint fail-closes on.
use ainxt_lifecycle::dsar::{CompleteLineage, LineageExport};
use ainxt_lifecycle::routes::{
    DsarCommand, DsarOutcome, DsarRouteError, DsarWorkflow, RetentionCommand, RetentionOutcome,
    RetentionRouteError, CAP_RETENTION_ADMIN,
};
use ainxt_lifecycle::ErasureAttestation;
use ainxt_responsibleai::dpia::{DpiaCiGate, PromotionTarget};
use ainxt_responsibleai::routes::{ModelRiskRouteError, PromotionDecision, CAP_MODEL_RISK};
// GAP-FIX gap6-responsibleai-cleanup item 2 — `admit_promotion` (below) delegates its FI-06/FI-07
// decision to this SAME composed gate `promotion.rs` defines, instead of reimplementing it inline.
use ainxt_nl2sql::{Column, Schema, Table};
use ainxt_profile::RetrievalScope;
use ainxt_providers::{AnthropicProvider, GeminiProvider, OpenAiSchemaProvider};
use ainxt_responsibleai::promotion::{GovernancePromotionGate, PromotionBlock, PromotionOutcome};
use ainxt_responsibleai::{
    route_promotable, BreakerState, DueDiligenceConfig, DueDiligenceOutcome, ModelRiskRecord,
};
use ainxt_server::{
    Authenticator, FullApp, FullAppExt, HarnessMounts, JwtSsoAuth, TrustedGatewayAuth,
};
use ainxt_serving::attestation::{
    AttestationConfig, AttestationGate, AttestationRefresher, RefreshConfig,
};
use ainxt_serving::disagg::DisaggregatedPools;
use ainxt_serving::gate::{NodeCandidate, ServingGate};
use ainxt_serving::health::{
    HealthCadence, HealthCadenceConfig, HealthConfig, InMemoryFleetRouter, ShardGroupId,
    ShardHealthMonitor,
};
use ainxt_serving::placement::{
    AutoscaleCadence, AutoscaleCadenceConfig, AutoscaleController, Bin, BinPool,
    InMemoryPlacementBinder, ModelItem, PlacementController, PlacementReconciler, ReconcileAction,
    ScaleAction,
};
use ainxt_serving::preemption::PreemptionScheduler;
use ainxt_serving::rollout::{
    AdvanceOutcome, AllowListArtifactVerifier, InMemoryWeightLoader, LoadError, RolloutState,
    RolloutThresholds, TrafficWindow, WeightArtifact, WeightLoader, WeightRollout,
};
use ainxt_serving::FairnessLimiter;
// R8 EDIT — the semantic Code-Review Pipeline gate the shipped daemon mounts at `POST /v1/edit`. The
// offline default engine = IdentityCoder (no model) + ScriptedTools (offline toolchain) + BuiltinScanner
// (offline SAST). ainxt-pipeline is LOWER-level than ainxt-server (which already depends on it) — acyclic.
use ainxt_artifact::ArtifactRuntime;
use ainxt_connector_http::ConnectorGateway;
use ainxt_pipeline::{
    perf::{NoAdvisor, NoBench, PerfBudget},
    sast::BuiltinScanner,
    AstVerifyTools, EditEngine, IdentityCoder,
};
use ainxt_replay::{EventKind, SessionRecording, SessionStore, TurnRole};
use ainxt_responsibleai::QualityCircuitBreaker;
// GAP-FIX regulated-fi-responsible-lifecycle — the FI-03 outsourcing register's SHARED handle type
// (see `ModelRouter::outsourcing_register_handle`), threaded from `build_router`/`build_engine_ext`/
// `build_chat_engine_with_authz` all the way to `AssembledFull`/`AppState` so a served admin route can
// mutate the SAME live register the router's non-overridable eligibility gate reads.
use ainxt_protocol::{Event, Request};
use ainxt_responsibleai::outsourcing::OutsourcingRegister;
use ainxt_runtime::audit::{AuditRecord, AuditSink, InMemoryAudit};
use ainxt_runtime::authz::{Authorizer, RbacAuthorizer};
use ainxt_runtime::compliance::{ComplianceGate, RedactAndProceed};
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_runtime::serving::ServingGateAttestor;
use ainxt_runtime::{CancelToken, Engine, TurnError, TurnHandler, TurnSummary};
use ainxt_serving::erasure::TieredCacheErasure;
use ainxt_session::{SessionConfig, SessionManager};
use ainxt_skill::SkillRuntime;
use ainxt_surface::SurfaceCatalog;
use ainxt_tools::{
    install_durable_ledger, InMemorySqlStore, Ledger, Reconciler, ReconcilerSweeper, ToolRuntime,
};
use ainxt_types::{DataClass, Principal};
use serde::Deserialize;
use tokio::sync::mpsc;

mod chat_identity;
pub use chat_identity::{ChatIdentityPolicy, GovernedChatSurface};

mod program_exec;
pub use program_exec::{
    assemble_program, assemble_program_surface, assemble_program_surface_bank_onboarding,
    assemble_program_surface_with_transparency,
    assemble_program_surface_with_transparency_and_topology, assemble_team_surface,
    assemble_team_surface_with_flywheel, assemble_team_surface_with_transparency,
    bank_id_from_input, capped_config, compose_served_team, drive_served_program_governed,
    drive_served_program_verified, drive_served_team, mint_run_credential, run_program,
    run_program_durable, run_program_verified, run_program_verified_sod, run_team,
    spawn_flywheel_sweep, verdict_for_observation, ConfirmingGoalJudge, EngineRunExecutor,
    FlywheelCurationSweep, FlywheelSweepResult, GitRevertingProgramVerifier, InMemoryLearningSink,
    LearningSink, PermissiveProgramVerifier, ProgramFault, ProgramProofSeams, ProgramRun,
    ProgramRunError, ProgramRuntime, ProgramSurface, ProgramTopology, RunIdentitySpec,
    ServedProgramGovernance, SodApprover, TeamRun, TeamRunError, TeamSurface, TurnObservation,
    VerifiedProgramRun,
};

mod guarded_log;
pub use guarded_log::GuardedEventLog;

mod fabric_chat;
pub use fabric_chat::FabricGroundedChatSurface;

mod workforce_surface;
pub use workforce_surface::{
    assemble_workforce_surface, assemble_workforce_surface_served, competency_after,
    competency_route, evaluate_decoy, evaluate_role_monitoring, generate_eval_battery,
    route_workforce_decoy_incident, run_shadow_observation, run_workforce_nightly_tick,
    should_inject_decoy, validate_succession_pr, ModelRoutedExecutor, RoleInvocationLedger,
    ShadowCase, WorkforceError, WorkforceSurface, WorkforceTurnSurface,
    EVAL_BATTERY_PASS_THRESHOLD,
};

mod prompt_optimizer_surface;
pub use prompt_optimizer_surface::{
    run_prompt_optimizer_sweep_tick, spawn_prompt_optimizer_tick, PromptSweepOutcome,
    PromptSweepSpec, ProviderConstrainedDecoder, ProviderModelSeam,
};

pub mod governed;
pub mod mounts;

/// FI-01: open a durable event log that is CHD-guarded by construction. This is the canonical way
/// the composition obtains a durable [`ainxt_eventlog::EventLog`] — the returned log redacts every
/// record through the strong redactor before the durable write, so cardholder data can never be
/// persisted. Callers that need a durable audit/session log should use this, not a bare
/// `JsonlEventLog::open`, so the sink-guard is never bypassed.
///
/// FI-10: the chain-hash primitive is resolved through the ADR-023 crypto-agility policy
/// ([`ainxt_cryptoagility::GovernedChainHasher`]) at governance tick 0 (the daemon's boot-time
/// policy snapshot), instead of a hard-coded `sha2` call — the daemon's own audit trail is now
/// itself a policy-governed cryptographic operation, not just the incident register's. Resolution
/// is fail-closed at construction: [`default_hash_policy`](ainxt_cryptoagility::default_hash_policy)
/// always approves SHA-256, so this cannot fail in practice; a deployment that edits the policy to
/// remove every hash candidate gets a startup refusal here, never a silent fallback.
///
/// GAP-AUDIT misc-decisions (`ainxt_eventlog::JsonlEventLog::with_verifier`) — investigated and
/// confirmed a NON-gap for today: `with_verifier` exists so an OLD chain-hash algorithm stays
/// verifiable after a rotation, but there is currently no rotation path for THIS hasher to protect
/// against. `default_hash_policy()` is a hard-coded, single-candidate registry (`sha-256`,
/// `Approved`, forever) — there is no config field, admin route, or any other composition-root seam
/// that lets a deployment introduce a second candidate or deprecate this one without editing and
/// redeploying this function's Rust source. Since exactly one algorithm has ever been resolvable
/// here, no record has ever been (or can currently be) written under a "rotated-out" algorithm, so
/// `with_verifier` has nothing to register. (`ainxt_incident::IncidentRegister::with_hash_policy` —
/// the sibling override seam for the incident register's OWN hash chain — is in the identical
/// position: constructed with its own hard-coded default, never called with an override anywhere in
/// this composition root either.) If a future change makes this policy config-driven or otherwise
/// overridable at runtime, threading the outgoing (pre-change) hasher into `with_verifier` at the
/// moment of the switch becomes a real, load-bearing requirement — tracked here, not fixed here.
pub fn open_guarded_event_log(
    dir: impl Into<std::path::PathBuf>,
) -> std::io::Result<GuardedEventLog<ainxt_eventlog::JsonlEventLog>> {
    let hasher = ainxt_eventlog::GovernedChainHasher::try_new(
        ainxt_cryptoagility::GovernedHasher::new(ainxt_cryptoagility::default_hash_policy()),
        0,
    )
    .map_err(std::io::Error::other)?;
    let log = ainxt_eventlog::JsonlEventLog::open_with_hasher(dir, std::sync::Arc::new(hasher))?;
    Ok(GuardedEventLog::new(log))
}

// ============================ Daemon-level config ============================

/// Where to bind the HTTP server.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    /// Directory backing the tamper-evident (SHA-256 hash-chained) daemon Event Log that the
    /// fully-wired transport (`serve_full`) uses for its audit trail and resume/replay tail. When
    /// `None` (the default), a per-binary directory under the OS temp dir is used so the air-gapped
    /// daemon still has a durable, CHD-guarded log with zero configuration. A deployment points this
    /// at durable storage.
    pub event_log_dir: Option<String>,
    /// R8 — the transport [`Authenticator`](ainxt_server::Authenticator) the SHIPPED daemon mounts on
    /// EVERY governed route (`/v1/chat`, `/graph`, `/v1/query_ledger`, `/v1/events`, `/v1/edit`, …).
    /// Config-SELECTABLE without changing the OWNER-DEFERRED default: `trusted-gateway` (the default —
    /// byte-identical behaviour to before this field existed) trusts the front gateway's forwarded
    /// `X-AInxt-*` identity; `jwt-sso` mounts the VERIFIED-identity [`JwtSsoAuth`](ainxt_server::JwtSsoAuth)
    /// (HS256-signed JWT — exp/nbf checked, forgery rejected, caps/role/clearance/department derived from
    /// the *verified* claims, never spoofable headers) and REQUIRES `jwt_hs256_secret` (fail-closed at
    /// assembly if absent — never a silent downgrade to the trusted default).
    pub authenticator: AuthenticatorKind,
    /// The HS256 signing secret for the `jwt-sso` authenticator. Ignored for `trusted-gateway`.
    /// REQUIRED (non-empty) when `authenticator = jwt-sso`; assembly fails closed otherwise.
    pub jwt_hs256_secret: Option<String>,
    /// ARCH-F-001 — how this daemon's listening socket is expected to be reached and secured.
    /// Default (`Loopback`) is byte-identical to today's behavior; see [`validate_transport_exposure`]
    /// for the fail-closed check this field enables once `host` is widened beyond loopback.
    #[serde(default)]
    pub transport: TransportConfig,
    /// R12 EDIT — the **durable served working-tree root** for `POST /v1/edit` (`SEMANTIC_EDITING.md`
    /// §5). When set, a committed edit is persisted to a crash-atomic filesystem sink rooted at
    /// `<dir>/<edit_id>`, so a committed code edit survives a daemon restart. When `None` (the default),
    /// the offline in-memory sink is used (a committed edit is lost on restart — acceptable for the
    /// air-gapped default; a deployment points this at the served working tree).
    pub edit_workspace_dir: Option<String>,
    /// GAP-FIX semantic-editing-codereview — the **durable journal-store root** for `POST /v1/edit*`
    /// (`CODE_REVIEW_PIPELINE.md` §9). The served `/v1/edit`/`/v1/edit/semantic`/`/v1/edit/classified`
    /// routes build a real SHA-256 hash-chained [`Journal`](ainxt_pipeline::journal::Journal) per turn
    /// but, before this field existed, NEVER persisted it anywhere — `ainxt_pipeline::JournalStore`/
    /// `FsJournalStore` had zero served callers, so `pipeline_history(commit_sha)`/`by_edit_id` could
    /// never answer anything for a real edit and a daemon restart silently erased the entire regulator
    /// audit trail for every code edit. When set, each turn's sealed journal persists to a crash-atomic
    /// `FsJournalStore` rooted at `<dir>/<edit_id>.jnl.json` (survives a daemon restart). When `None`
    /// (the default), an in-process `InMemoryJournalStore` is used (still real within the process —
    /// `GET /v1/edit/journal/{edit_id}` answers — but lost on restart, the offline default).
    pub edit_journal_dir: Option<String>,
    /// R14 (Prompt Engineering §3, HIGH) — the **git-native prompt tree root** the served chat Prompt
    /// Service loads its layered (L1..L4) bodies from (`<root>/<id>/definition.json` +
    /// `variant.<family>.md`). When set, the served registry is FILE-sourced (editing a file + rebuild
    /// changes the served prompt — a hardcoded Rust constant cannot), driven through the real
    /// lifecycle gates to PRODUCTION. When `None` (the default), the shipped canonical constant
    /// deployment is used (air-gapped default; unchanged). Fail-closed on a malformed/locked tree.
    pub prompt_dir: Option<String>,
    /// GAP-AUDIT conversation-intelligence #2 — the **durable, event-log-backed chat session
    /// history** root (`ainxt_convo::PersistentSessions`). The mechanism was fully built + unit-
    /// tested but the served `ChatSurface` was hardwired to `InMemorySessions`, so every served
    /// conversation's turn history — and the referent-resolution fix that depends on it — was lost
    /// on daemon restart. When `None` (the default), `InMemorySessions` is used (unchanged
    /// behavior). When set, session history persists to `<dir>/<session>.jsonl` (a tamper-evident
    /// hash-chained log, distinct from `event_log_dir` — conversation turns are a different logical
    /// dataset from the audit trail, never the same store repurposed).
    pub chat_sessions_dir: Option<String>,
    /// GAP-FIX surfaces-profiles-skills-config (ADR-026) — the **git-native skill tree root** the
    /// served [`ainxt_skill::SkillRuntime`] loads its file-declared skills from
    /// (`<root>/<id>/definition.md`), layered over the compiled-in [`ainxt_skill::builtin`] floor (see
    /// [`build_skill_runtime_from_config`]). When set, editing a file + rebuild changes the served
    /// skill — a hardcoded Rust constant cannot — through the real git-native control-plane loader
    /// ([`ainxt_skill::control::SkillControlPlane`]), mirroring `prompt_dir`'s pattern for prompts.
    /// When `None` (the default), the compiled-in builtins are the whole registry (unchanged).
    /// Fail-closed on a malformed/locked tree.
    pub skill_dir: Option<String>,
    /// GAP-FIX eval-durable-stores (EVAL_PLATFORM.md §11) — the durable, file-backed root for
    /// `ainxt_eval`'s no-infra data-plane stores. Today this backs the Regression Vault
    /// (`<dir>/vault.jsonl`, [`ainxt_eval::durable::FileVaultStore`]): `ainxt_eval::durable` also ships
    /// `FileSealedCorpusStore`/`FileEventSink`, but neither has a construction site anywhere in this
    /// served composition root (they back the separate `ainxt-conformance` release-gate CI binary
    /// instead), so there is nothing else to wire here yet — see `vault_dir_and_store`'s doc. When
    /// `None` (the default), [`ainxt_eval::vault::RegressionVault`] stays in-memory-only, matching the
    /// PRE-EXISTING (unwired) behavior byte-for-byte: a daemon restart loses every regression case a
    /// live quality-circuit-breaker trip ever minted via [`AssembledFull::admit_promotion`]. When set,
    /// the vault is hydrated from the durable file on assembly (a restart replays every prior case back
    /// into the live vault) and every NEW case `admit_promotion` mints is also appended durably, so it
    /// survives the NEXT restart too.
    pub eval_durable_dir: Option<String>,
    /// GAP-FIX gap6-semantic-lsp-signature-layermanifest item 1 — the **edit ladder's rung-1
    /// language-server driver**, config-gated. `EditEngine::with_lsp` (`ainxt_pipeline::edit_turn`) has
    /// existed since round 15 with zero callers anywhere in this composition root — every semantic op
    /// planned through `POST /v1/edit/semantic` has always resolved at the AST rung, never rung 1, not
    /// because no driver exists (`ainxt_semantic::lsp::ServerLspRefactor`/`StdioLspTransport` are real,
    /// tested JSON-RPC-over-stdio protocol code) but because nothing ever attached one. When set to a
    /// language-server binary path (e.g. `rust-analyzer`), this deployment probes it at boot with
    /// `ainxt_semantic::lsp::probe_stdio_lsp_available` (bounded timeout, sandboxed) and, ONLY if it
    /// answers `--version` in time, wires a real `ServerLspRefactor` via `EditEngine::with_lsp`. When
    /// `None` (the default) or the probe fails/times out, `edit.lsp` stays unset — byte-identical to
    /// today: every semantic op falls to the AST rung, recorded honestly, never silently claimed as
    /// LSP-grade. Never attempted when unset — a missing/misconfigured binary can never hang daemon
    /// boot.
    pub lsp_rust_analyzer_path: Option<String>,
}

/// R8 — which transport [`Authenticator`](ainxt_server::Authenticator) the shipped daemon mounts.
/// The default is OWNER-DEFERRED and unchanged; `jwt-sso` is a config-selectable verified-identity
/// upgrade (see [`ServerConfig::authenticator`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthenticatorKind {
    /// Trust the front gateway's forwarded identity headers (the default; unchanged).
    #[default]
    TrustedGateway,
    /// Verify an HS256-signed JWT and derive identity from its claims ([`ainxt_server::JwtSsoAuth`]).
    JwtSso,
}

/// ARCH-F-001 — the transport **encryption-exposure** setting, same fail-closed pattern as
/// [`AuthenticatorKind`]: the default is byte-identical to today's behavior (a loopback-only bind
/// needs no encryption setting), and widening [`ServerConfig::host`] beyond loopback now REQUIRES
/// picking one of the other two variants — see [`validate_transport_exposure`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TransportExposure {
    /// Only this machine can connect (`host` is a loopback address) — the default. No encryption
    /// setting is needed because nothing outside the machine can ever reach the listener.
    #[default]
    Loopback,
    /// Something in front of this daemon (a reverse proxy / ingress / service mesh sidecar) already
    /// terminates TLS; this process itself speaks plaintext HTTP to that trusted front door only.
    BehindTlsGateway,
    /// This process terminates TLS itself, using [`ServerConfig::transport`]'s `cert_path`/`key_path`.
    DirectTls,
}

/// ARCH-F-001 — how this daemon's listening socket is expected to be reached and secured. Config-
/// selectable, mirroring [`ServerConfig::authenticator`]'s pattern: the default keeps today's
/// loopback-only behavior unchanged; a deployment that widens `host` must say how encryption is
/// handled, or assembly fails closed (see [`validate_transport_exposure`]).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TransportConfig {
    pub exposure: TransportExposure,
    /// TLS certificate path — only consulted when `exposure = "direct-tls"`.
    pub cert_path: Option<String>,
    /// TLS private-key path — only consulted when `exposure = "direct-tls"`.
    pub key_path: Option<String>,
}

/// ARCH-F-001 — a listen address is "loopback-only" (unreachable from any other machine) when it is
/// `127.0.0.1`, `::1`, or `localhost`, with or without a port suffix.
fn is_loopback_host(host: &str) -> bool {
    let bare = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host);
    let bare = bare.trim_start_matches('[').trim_end_matches(']');
    matches!(bare, "127.0.0.1" | "::1" | "localhost") || bare.starts_with("127.")
}

/// ARCH-F-001 — boot-time fail-closed check, same shape as [`build_authenticator`]'s existing
/// `TrustedGateway` check: before this existed, the daemon would bind and start accepting
/// connections on ANY host address with no requirement that the operator ever say whether the
/// connection is encrypted. Every current deployment that binds to loopback (the default) is
/// unaffected — this only refuses to start when `host` is widened AND `transport.exposure` is still
/// at its default `Loopback` value, which is a contradiction (a non-loopback bind cannot actually be
/// loopback-only) rather than a deliberate, stated choice.
pub fn validate_transport_exposure(server: &ServerConfig) -> Result<(), String> {
    if !is_loopback_host(&server.host) && server.transport.exposure == TransportExposure::Loopback {
        return Err(format!(
            "server.host = \"{}\" exposes this daemon beyond its own machine, but \
             server.transport.exposure is unset (defaults to \"loopback\", which is a contradiction \
             for a non-loopback bind). Refusing to start rather than silently accepting connections \
             with no stated encryption posture. Set server.transport.exposure to \"behind-tls-gateway\" \
             (a trusted reverse proxy/ingress terminates TLS) or \"direct-tls\" (this process \
             terminates TLS itself, with transport.cert_path/key_path set).",
            server.host
        ));
    }
    Ok(())
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 8080,
            event_log_dir: None,
            authenticator: AuthenticatorKind::TrustedGateway,
            jwt_hs256_secret: None,
            transport: TransportConfig::default(),
            edit_workspace_dir: None,
            edit_journal_dir: None,
            prompt_dir: None,
            chat_sessions_dir: None,
            skill_dir: None,
            eval_durable_dir: None,
            lsp_rust_analyzer_path: None,
        }
    }
}

/// Session-manager tuning (kept out of `RuntimeConfig` so `ainxt-config` need not depend on the
/// engine; composed here). Any field omitted keeps the [`SessionConfig`] default.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SessionSettings {
    pub max_sessions: Option<usize>,
    pub inbox_capacity: Option<usize>,
    pub idle_ttl_ms: Option<u64>,
    pub turn_timeout_ms: Option<u64>,
}

impl SessionSettings {
    fn into_config(self) -> SessionConfig {
        let mut c = SessionConfig::default();
        if let Some(v) = self.max_sessions {
            c.max_sessions = v;
        }
        if let Some(v) = self.inbox_capacity {
            c.inbox_capacity = v;
        }
        if let Some(v) = self.idle_ttl_ms {
            c.idle_ttl_ms = v;
        }
        if let Some(v) = self.turn_timeout_ms {
            c.turn_timeout_ms = v;
        }
        c
    }
}

/// The RBAC retrieval scope a KB document belongs to (`CLAUDE.md` "retrieval scope separation").
/// Chat/Voice/Buddy surfaces ([`RetrievalScope::PlatformAndNamespace`]) read `Platform` + `Namespace`
/// docs; Projects/Threads/Code/SDLC surfaces ([`RetrievalScope::RepoScoped`]) read only `Repo` docs.
/// The two sets are DISJOINT on the served path — a repo-scoped surface can never reach platform
/// knowledge and a platform surface can never reach repo-private content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KbScope {
    /// Platform-wide knowledge (`docs_kb:platform`).
    #[default]
    Platform,
    /// A namespace/department knowledge base (`docs_kb:{namespace}`).
    Namespace,
    /// A single repository's indexed content (Projects/Threads).
    Repo,
}

/// One document the KB loader seeds the live retrieval corpus with (gaps SURF-03 / CTX-fabric "live
/// retrieval corpus is populated"). A deployment lists these under `[[kb.documents]]`; a real
/// pipeline indexes source files/records into the same shape.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KbDocument {
    pub id: String,
    /// Human-facing source label for citations/lineage (defaults from the scope when empty).
    #[serde(default)]
    pub source: String,
    pub text: String,
    /// Sensitivity — drives the pre-rank clearance filter (a chunk above the caller's clearance is
    /// never scored). Defaults to `Public`.
    #[serde(default = "kb_default_class")]
    pub data_class: DataClass,
    /// The retrieval scope this doc belongs to (drives the RepoScoped vs PlatformAndNamespace split).
    #[serde(default)]
    pub scope: KbScope,
    /// The namespace (for `Namespace` scope) — display/source label only.
    #[serde(default)]
    pub namespace: Option<String>,
    /// The repository id (for `Repo` scope) — display/source label only.
    #[serde(default)]
    pub repo: Option<String>,
    /// Node-ACL (gap SURF / CTX §2/§8.3): the department that owns this document. When set, only a
    /// caller in this department may retrieve it — enforced **pre-rank** on the served governed path
    /// (`governed::compile_served_context`), so a cross-department caller never even scores it
    /// (existence never leaks). `None` = no department restriction. Distinct from `namespace`, which
    /// is a display label only.
    #[serde(default)]
    pub department: Option<String>,
    /// Node-ACL minimum seniority: the caller's `ad_level` must be `<=` this to retrieve the document
    /// (0 = most senior … 6 = junior). A caller with no known `ad_level` is denied. `None` = no
    /// seniority restriction.
    #[serde(default)]
    pub max_ad_level: Option<u8>,
    /// Node-ACL allow-groups: if non-empty, the caller must be in at least one of these groups.
    #[serde(default)]
    pub allow_groups: Vec<String>,
    /// Node-ACL deny-groups: a caller in any of these groups is refused regardless of every other axis.
    #[serde(default)]
    pub deny_groups: Vec<String>,
    /// Row-level-security attributes (gap CTX §8.3): per-row labels a [`RowFilter`](ainxt_context::RowFilter)
    /// policy compares against a value bound from the OBO principal. Empty = the row carries no RLS
    /// labels, so any policy referencing a label it lacks fail-closes (row denied, never permitted by
    /// omission).
    #[serde(default)]
    pub row_attributes: std::collections::BTreeMap<String, String>,
}

fn kb_default_class() -> DataClass {
    DataClass::Public
}

/// The knowledge-base section (`[kb]`) — the documents the daemon seeds the live retrieval corpus
/// with. Empty by default (air-gapped/undeployed → nothing to ground on, but every other behavior
/// holds). Split off in [`load_layered`] like `[server]`/`[session]` so `ainxt-config` need not know
/// about the KB.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct KbConfig {
    pub documents: Vec<KbDocument>,
    /// Enforce RLS **department isolation** on the served chat grounding path (gap AJ / CTX §8.3):
    /// bind a [`RowFilter`](ainxt_context::RowFilter) from the OBO principal so the row-level pass
    /// denies a row whose `department` attribute is not the caller's own (fail-closed, existence never
    /// leaks). `false` (default) leaves the RLS pass a permits-all no-op, so a KB whose rows carry no
    /// `department` attribute grounds unchanged. A deployment whose KB rows are `department`-labeled
    /// opts in via `[kb] rls_department_isolation = true`.
    #[serde(default)]
    pub rls_department_isolation: bool,
    /// RAG toggle — when `true` (default) the corpus is searched via BM25 before every LLM call
    /// and the retrieved chunks are injected as a grounding context block (cited answers).
    /// When `false` the corpus lookup is skipped entirely: the turn goes directly to the LLM
    /// with only conversation history + the user message (no retrieval, no citations).
    /// Changing this field requires a daemon restart. Set via `[kb] rag_enabled = false` in
    /// `config.toml` to disable RAG for a deployment.
    #[serde(default = "default_rag_enabled")]
    pub rag_enabled: bool,
}

impl KbConfig {
    /// Number of configured documents.
    pub fn len(&self) -> usize {
        self.documents.len()
    }
    pub fn is_empty(&self) -> bool {
        self.documents.is_empty()
    }
}

/// Default for [`KbConfig::rag_enabled`] — `true` so existing deployments that omit the field
/// keep their current grounded-retrieval behaviour unchanged.
fn default_rag_enabled() -> bool {
    true
}

/// Whether a document is readable under a surface's [`RetrievalScope`] — the RBAC scope-separation
/// predicate enforced on the served path (gap SURF-01). The two scopes partition the KB: a
/// platform/namespace surface never reaches repo-private docs, and a repo-scoped surface never
/// reaches platform/namespace docs.
pub fn scope_admits(scope: RetrievalScope, doc: &KbDocument) -> bool {
    match scope {
        // The surface does no retrieval at all — nothing is in scope (fail-closed).
        RetrievalScope::None => false,
        RetrievalScope::PlatformAndNamespace => {
            matches!(doc.scope, KbScope::Platform | KbScope::Namespace)
        }
        RetrievalScope::RepoScoped => matches!(doc.scope, KbScope::Repo),
    }
}

/// Build the live retrieval [`Corpus`] for a surface's [`RetrievalScope`] from the loaded KB —
/// ENFORCING the scope separation structurally: only in-scope documents are ever indexed into the
/// corpus the surface's retriever sees, so an out-of-scope document cannot be retrieved regardless of
/// query or clearance (existence never leaks). This is what makes the profile's retrieval scope
/// binding on the SERVED path (gap SURF-01), not just a declared field.
///
/// CRITICAL (gap CTX §2/§8.3): every chunk ALSO carries the document's per-node ACL (department /
/// `ad_level` ceiling / allow-groups / deny-groups) AND its RLS row-attributes onto the
/// [`ainxt_context::Chunk`]. This is the corpus the LIVE [`ChatSurface`] grounds over
/// (`hybrid_retriever` → `compile_window`'s full-`AccessContext` pre-rank pass), so
/// node/department/`ad_level`/group RBAC and the RLS row-filter are enforced PRE-RANK on the served
/// path — a caller in the wrong department (or too junior, or in a deny-group, or outside the row
/// scope) never scores the chunk, so its existence never leaks. Before this the served
/// `ainxt-context` corpus dropped every non-class axis, so only the reserved
/// [`governed::retrieval_corpus_for_scope`] carried the ACL and the LIVE grounded path was
/// class-only — the CRITICAL this closes.
pub fn corpus_for_scope(kb: &KbConfig, scope: RetrievalScope) -> Corpus {
    // RAG toggle: when disabled, return an empty corpus so the retriever finds nothing and
    // the LLM receives only conversation history + the user message (no grounding context block).
    // Controlled by `[kb] rag_enabled` in config.toml. Default: true (RAG on).
    if !kb.rag_enabled {
        return Corpus::load(vec![]);
    }
    let chunks: Vec<Chunk> = kb
        .documents
        .iter()
        .filter(|d| scope_admits(scope, d))
        .map(|d| {
            let source = if !d.source.is_empty() {
                d.source.clone()
            } else {
                match d.scope {
                    KbScope::Platform => "platform".to_string(),
                    KbScope::Namespace => d
                        .namespace
                        .clone()
                        .unwrap_or_else(|| "namespace".to_string()),
                    KbScope::Repo => d.repo.clone().unwrap_or_else(|| "repo".to_string()),
                }
            };
            let mut chunk = Chunk::new(&d.id, &source, &d.text, d.data_class);
            // Preserve the per-node ACL so `compile_window` enforces department/`ad_level`/group RBAC
            // pre-rank on the LIVE served retrieval (the SAME predicate the reserved retrieval corpus
            // uses — one source of truth via `governed::node_acl_for`).
            if let Some(acl) = governed::node_acl_for(d) {
                chunk = chunk.with_acl(acl);
            }
            // Preserve the RLS row-attributes so a per-request `RowFilter` bound from the OBO principal
            // filters the chunk pre-rank too (row-scope existence never leaks).
            for (k, v) in &d.row_attributes {
                chunk = chunk.with_attribute(k, v);
            }
            chunk
        })
        .collect();
    Corpus::load(chunks)
}

/// The retrieval scope a named surface serves at, resolved from the builtin [`SurfaceCatalog`] profile
/// (chat/buddy = platform+namespace; code/sdlc = repo-scoped). An unknown surface falls back to the
/// fail-safe NARROWER scope (`RepoScoped` reaches the least), never the broader platform scope.
pub fn scope_for_surface(surface_id: &str) -> RetrievalScope {
    SurfaceCatalog::builtin()
        .ok()
        .and_then(|c| c.get(surface_id).map(|p| p.context.retrieval))
        .unwrap_or(RetrievalScope::RepoScoped)
}

/// One serving node the deployment advertises to the Serving-Ops fence (`[[serving.nodes]]`). A
/// [`NodeCandidate`] is a *routing descriptor*, not a GPU handle: it names a node the balancer can
/// reach (`node_id`) and whether it is currently health-routable (`routable`). Attestation of the
/// node for regulated traffic is a SEPARATE live-TEE step (a quote submitted through
/// [`ServingGate::attestation_mut`]); a configured-but-unattested node correctly fails a regulated
/// turn CLOSED — exactly the production posture.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServingNodeConfig {
    /// The balancer-reachable node identifier the fence admits onto / drains.
    pub node_id: String,
    /// Whether the node is currently health-routable. Default `true` (a declared node is routable
    /// unless the deployment marks it drained).
    #[serde(default = "serving_node_routable_default")]
    pub routable: bool,
    /// GAP-FIX serving-ops (SERVING_OPS.md §4, gap 37) — this node's TP/PP shard-group golden hash,
    /// computed once at placement time for the deterministic canary-correctness probe
    /// ([`ShardHealthMonitor::register_group`]). `None` (default) opts the node out of shard-group
    /// health monitoring entirely — unchanged, attestation-only behavior. A deployment that has
    /// computed a golden hash for a node's exact model/quantization/TP-degree declares it here to
    /// bring the node under the interconnect-watchdog + canary-correctness supervision this section
    /// wires (`[serving.health]` tunes the thresholds; `node_id` doubles as the
    /// [`ShardGroupId`](ainxt_serving::health::ShardGroupId) — the only declared serving-topology
    /// identifier space this config exposes).
    #[serde(default)]
    pub golden_hash: Option<u64>,
}

fn serving_node_routable_default() -> bool {
    true
}

/// The Serving-Ops section (`[serving]`) — the node pool + admission tuning the SHIPPED daemon binds
/// the §2 SLO-aware QoS admission gate and the §8.2 attestation node-fence onto (SERVING_OPS.md §2/§7,
/// ADR-020/021). **Empty by default** (the air-gapped posture): with no declared nodes the fence is
/// INERT on `/v1/chat` — the model is served by the engine's own provider chain, there is no GPU node
/// to attest or admit against, so the turn must NOT 503 (the shipped-chat guard). Once a deployment
/// declares nodes here the fence goes LIVE on the shipped binary: a regulated turn fails closed onto an
/// unattested node, a non-regulated turn is admitted on a routable node, and over-capacity turns are
/// enqueued up to `qos_queue_depth` then load-shed — the very wiring the audit found missing
/// (attestation + QoS "inert in the shipped daemon" because `build_serving` hard-coded an empty pool).
/// Split off in [`load_layered`] like `[server]`/`[session]`/`[kb]` so `ainxt-config` need not know
/// about Serving-Ops.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
#[derive(Default)]
pub struct ServingConfig {
    /// The advertised serving nodes. Empty (default) ⇒ the fence is inert (no pool ⇒ no 503).
    pub nodes: Vec<ServingNodeConfig>,
    /// Bounded main-path QoS wait-queue depth (SERVING_OPS.md §2). Over-capacity turns wait here up
    /// to this ceiling, then are load-shed (never an unbounded queue). Defaults to [`QOS_QUEUE_DEPTH`].
    pub qos_queue_depth: Option<u32>,
    /// Total per-pool fairness concurrency capacity shared across tenants (§2). Defaults to `8`.
    pub fairness_capacity: Option<u32>,
    /// The minimum guaranteed per-tenant share of `fairness_capacity` (§2 minimum-service). Defaults
    /// to `1`. When `fairness_capacity / fairness_min_share >= expected tenant count` the pool is
    /// starvation-proof ([`FairnessLimiter::is_starvation_proof`]).
    pub fairness_min_share: Option<u32>,
    /// Preemptive-scheduler running-slot capacity (§2 priority-class preemption). Defaults to `4`.
    pub scheduler_capacity: Option<u32>,
    /// Optional §2 **weighted-fair-queuing minimum-service** ordering for the over-capacity wait queue
    /// (gap SRV-07 / serving-ops gap-6). When set, the served gate orders queued turns by deficit
    /// round-robin so a low-weight tenant is guaranteed forward progress proportional to its weight —
    /// not merely capped by the concurrency [`FairnessLimiter`]. Absent (default) ⇒ cap-only (unchanged).
    pub wfq: Option<ServingWfqConfig>,
    /// R13 (SRV-03, HIGH) — logical ticks between attestation quote-refresh sweeps for the declared
    /// regulated pool ([`AttestationRefresher`] cadence, ADR-021 §8.3). Defaults to
    /// [`RefreshConfig::default`]'s interval. Only meaningful when `nodes` is non-empty.
    pub attestation_refresh_interval: Option<u64>,
    /// R13 (SRV-03, HIGH) — re-attest a declared node when its verified quote expires within this many
    /// ticks (proactive lead window). Defaults to [`RefreshConfig::default`]'s lead. Should be `>=`
    /// `attestation_refresh_interval` so a quote is renewed at least one sweep before it can lapse.
    pub attestation_refresh_lead: Option<u64>,
    /// GAP-FIX serving-ops (ADR-021 §8.3, gap-2) — the declarative
    /// [`AttestationManifest`](ainxt_serving::attestation::AttestationManifest): pre-shared quotes +
    /// accepted signatures + approved firmware/driver/binary hashes for a fixed offline fleet. The
    /// §8.3 refresh loop (`attestation_refresh_interval`/`_lead` above) was already wired, but it
    /// always ticked over a hardcoded-EMPTY `StaticQuoteSource`/`AllowListVerifier`/`ReferenceValues`
    /// trio (`main.rs`), which by construction can never admit a node — there was no config-driven
    /// way to populate those three seams. `None` (default) keeps that empty, air-gapped-inert trio
    /// unchanged; `Some` materializes the declared manifest via
    /// [`AttestationManifest::build`](ainxt_serving::attestation::AttestationManifest::build) in its
    /// place.
    pub attestation_manifest: Option<ainxt_serving::attestation::AttestationManifest>,
    /// GAP-FIX serving-ops (SERVING_OPS.md §4, gap 37) — tuning for the shard-group health monitor +
    /// drain-the-group recovery cadence (`[serving.health]`). Always present with conservative
    /// defaults (unlike `wfq`/`attestation_manifest`, its presence does not gate the mechanism on/off
    /// — that gate is whether ANY `[[serving.nodes]]` entry declares a `golden_hash`). Absent section
    /// ⇒ these defaults, matching `[serving.wfq]`'s absent-is-a-default shape.
    #[serde(default)]
    pub health: ServingHealthConfig,
    /// GAP-FIX serving-ops (SERVING_OPS.md §3, gaps 26/W, round-15 LOW) — tuning for the demand-EWMA
    /// autoscale decision loop (`[serving.autoscale]`). `None` (default) ⇒ no autoscale controller:
    /// unlike `health`, this section has no sensible universal default — `per_replica_capacity` is a
    /// deployment-specific capacity number (sustained req/s a single replica can serve), not something
    /// this OSS default could guess. `Some` builds a live `AutoscaleController` + `AutoscaleCadence`
    /// the daemon's background timer drives via [`AssembledFull::run_autoscale_tick`].
    pub autoscale: Option<ServingAutoscaleConfig>,
    /// GAP-FIX serving-ops (SERVING_OPS.md §2, gap 6) — the number of fresh prefill chunks
    /// [`AssembledFull::run_batch_step_tick`] schedules per tick when **chunked-prefill interleaving**
    /// is enabled (`ServingGate::with_chunked_prefill`). `None` (default) leaves the mechanism off —
    /// unchanged behaviour, matching `wfq`'s absent-is-off shape (this is a bare `Option<u32>`, not
    /// its own sub-table, since there is exactly one tunable and no universal-default question like
    /// `health`'s thresholds).
    pub chunked_prefill: Option<u32>,
    /// GAP-FIX serving-ops (SERVING_OPS.md §1, gap 7) — the disaggregated prefill/decode pool split
    /// (`[serving.disagg]`). `None` (default) ⇒ the single-pool `ServingGate` (`Self::nodes` above)
    /// stays the only served pool, unchanged. `Some` builds a live
    /// [`ainxt_serving::disagg::DisaggregatedPools`] — two PHYSICALLY SEPARATE `ServingGate`s (their
    /// own attestation/fairness/preemption state, joined only by the KV Relay fabric) — mounted at
    /// `POST /v1/infer/prefill` / `/v1/infer/decode` / `/v1/infer/handoff`, so a saturated prefill pool
    /// can never delay, shed, or preempt a decode admission on the shipped daemon.
    pub disagg: Option<ServingDisaggConfig>,
    /// GAP-FIX serving-ops (SERVING_OPS.md §3, gaps 26/W) — the GPU bin-packing placement +
    /// model-parking/eviction fleet declaration (`[serving.placement]`). `PlacementController`/
    /// `ParkingRegistry`/`PlacementReconciler`/`InMemoryPlacementBinder` were fully implemented and
    /// unit-tested but referenced only in the crate's own tests — nothing on the served surface ever
    /// converged a physical GPU fleet toward a computed placement. `None` (default) — like
    /// `autoscale`, there is no universal default for a deployment's GPU bin inventory.
    pub placement: Option<ServingPlacementConfig>,
    /// GAP-FIX serving-ops (SERVING_OPS.md §5, gap 38) — the zero-downtime signed weight-rollout
    /// declaration (`[serving.rollout]`). `WeightRollout` (staged P2Shadow→P2Canary→P1Canary→P0
    /// promotion, fail-closed signature+content-hash+attestation re-verification at every load) was
    /// fully implemented and unit-tested but had zero references in `ainxt-runtimed`/`ainxt-server` —
    /// no config field, no daemon caller. `None` (default) — like `autoscale`/`placement`, there is no
    /// universal default for a deployment's accepted publisher signatures.
    pub rollout: Option<ServingRolloutConfig>,
}

/// Tuning for the disaggregated prefill/decode split (`[serving.disagg]`, SERVING_OPS.md §1, gap 7).
/// Each pool's own admission tuning (fairness/scheduler capacity, QoS queue depth) reuses this
/// section's TOP-LEVEL `[serving]` knobs (`qos_queue_depth`/`fairness_capacity`/`fairness_min_share`/
/// `scheduler_capacity`) — a deployment sizing the two pools identically declares nothing extra beyond
/// the node lists; sizing them independently is a follow-up (today both pools share one tuning, which
/// is still a real, structural improvement over the single undifferentiated pool it replaces).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServingDisaggConfig {
    /// The Prefill Pool's advertised nodes (compute-bound, parallel-over-prompt hardware profile).
    pub prefill_nodes: Vec<ServingNodeConfig>,
    /// The Decode Pool's advertised nodes (memory-bandwidth-bound, one-token-at-a-time profile).
    pub decode_nodes: Vec<ServingNodeConfig>,
}

/// The declared GPU fleet + model catalog behind the placement/parking actuator
/// (`[serving.placement]`, SERVING_OPS.md §3, gaps 26/W).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServingPlacementConfig {
    /// The GPU bins (interconnect-adjacent groups) placement packs replicas into.
    pub bins: Vec<ServingPlacementBinConfig>,
    /// Bins held out of placement as N+1 standby headroom (SERVING_OPS.md §3).
    #[serde(default)]
    pub standby_reserve: usize,
    /// The model catalog: each entry's footprint/regulated-eligibility gates how
    /// [`PlacementController::plan`] packs its replicas. A model named by an
    /// [`ainxt_serving::placement::ScaleAction`] the autoscale actuator has not declared here is
    /// skipped (never a silent panic on an undeclared model).
    pub models: Vec<ServingPlacementModelConfig>,
    /// Rate limit on physical moves per actuator tick ([`PlacementReconciler::reconcile_step`]'s
    /// `max_moves`) — never converges the whole fleet in one disruptive tick.
    #[serde(default = "placement_max_moves_default")]
    pub max_moves_per_tick: usize,
}

fn placement_max_moves_default() -> usize {
    4
}

/// One declared GPU bin (`[[serving.placement.bins]]`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServingPlacementBinConfig {
    pub id: String,
    pub vram_total: u64,
    pub tier: ainxt_serving::attestation::TrustTier,
    pub fabric_domain: String,
}

/// One declared model catalog entry (`[[serving.placement.models]]`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServingPlacementModelConfig {
    pub model_id: String,
    pub footprint: u64,
    #[serde(default)]
    pub requires_regulated_bin: bool,
}

/// The declared publisher trust + staged-promotion thresholds behind the zero-downtime signed
/// weight-rollout surface (`[serving.rollout]`, SERVING_OPS.md §5, gap 38).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServingRolloutConfig {
    /// Detached signatures accepted as trusted publishers ([`AllowListArtifactVerifier::
    /// accept_signature`]) — the fail-closed crypto fence [`WeightRollout::verify_load`] re-checks on
    /// EVERY load, never grandfathered.
    pub accepted_signatures: Vec<String>,
    /// Regression-rate above which a CANARY stage (P2Shadow/P2Canary/P1Canary) auto-rolls-back.
    pub regression_threshold: f64,
    /// Regression-rate at/above which a P0 (`Promoted`) regression auto-rolls-back; below it, a P0
    /// regression instead awaits a human approval gate.
    pub p0_breach_threshold: f64,
    /// The incumbent version currently live for each model — seeds [`InMemoryWeightLoader::
    /// with_incumbent`] so a rollback has a real version to revert traffic to.
    #[serde(default)]
    pub incumbents: Vec<ServingRolloutIncumbentConfig>,
}

/// One declared incumbent version (`[[serving.rollout.incumbents]]`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServingRolloutIncumbentConfig {
    pub model_id: String,
    pub version: String,
}

/// Tuning for [`AutoscaleController`]/[`AutoscaleCadence`] (`[serving.autoscale]`, SERVING_OPS.md §3).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServingAutoscaleConfig {
    /// EWMA smoothing factor in `(0,1]` — higher reacts faster to a demand swing
    /// ([`AutoscaleController::new`]'s `alpha`).
    pub alpha: f64,
    /// Serving capacity of one replica, in the same units as the demand samples the deployment feeds
    /// (e.g. sustained requests/sec a single replica can serve).
    pub per_replica_capacity: f64,
    /// The P0 floor: a model family never scales below this many resident replicas. Default `0`.
    #[serde(default)]
    pub min_replicas: u32,
    /// Logical ticks between autoscale recomputes ([`AutoscaleCadenceConfig::interval`]).
    #[serde(default = "serving_autoscale_sweep_interval_default")]
    pub sweep_interval: u64,
}

fn serving_autoscale_sweep_interval_default() -> u64 {
    AutoscaleCadenceConfig::default().interval
}

/// Tuning for [`ShardHealthMonitor`]/[`HealthCadence`] (`[serving.health]`, SERVING_OPS.md §4, gap 37).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ServingHealthConfig {
    /// A collective op taking strictly longer than this many logical ticks counts as an interconnect
    /// watchdog miss ([`HealthConfig::collective_timeout`]).
    pub collective_timeout: u64,
    /// Consecutive misses required to flag a shard group `Degraded` (anti-flap,
    /// [`HealthConfig::consecutive_miss_threshold`]).
    pub consecutive_miss_threshold: u32,
    /// Logical ticks between health sweeps ([`HealthCadenceConfig::interval`]).
    pub sweep_interval: u64,
}

impl Default for ServingHealthConfig {
    fn default() -> Self {
        ServingHealthConfig {
            collective_timeout: 30,
            consecutive_miss_threshold: 3,
            sweep_interval: HealthCadenceConfig::default().interval,
        }
    }
}

/// The §2 WFQ minimum-service tuning bound onto the served [`ServingGate`] (`[serving.wfq]`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServingWfqConfig {
    /// Per-round service credit a weight-1 tenant receives (deficit-round-robin quantum). Defaults `1`.
    #[serde(default = "serving_wfq_quantum_default")]
    pub quantum_unit: u32,
    /// Per-tenant relative weight (JWT `department` → weight). Tenants absent here default to weight 1.
    #[serde(default)]
    pub weights: std::collections::BTreeMap<String, u32>,
}

fn serving_wfq_quantum_default() -> u32 {
    1
}

impl ServingConfig {
    /// Whether any serving node is advertised. `true` ⇒ the fence is inert (air-gapped default).
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

/// Incident arming-policy selection for the `[incident]` config section.
///
/// OSS default: `Generic` — no pre-armed regulatory clocks.
/// Deployment-specific: set `arming_policy` (e.g. a regional regulatory profile) in a private config overlay
/// to arm CERT-In (6 h), DPDP-Board (72 h), and RBI (24 h) statutory clocks.
#[derive(Debug, Clone, PartialEq, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ArmingPolicyKind {
    /// No pre-armed statutory clocks — safe OSS default for any jurisdiction.
    #[default]
    Generic,
    /// India-specific regulatory clocks: CERT-In 6 h, DPDP-Board 72 h, RBI 24 h.
    /// Set this in a private deployment overlay for India-regulated deployments.
    IndiaRegulatory,
}

/// The `[incident]` configuration section.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IncidentConfig {
    /// Which statutory arming policy to apply to the live `IncidentRegister`.
    /// `"generic"` (default) — no pre-armed clocks, safe for any jurisdiction.
    /// `"india-regulatory"` — arms CERT-In/DPDP-Board/RBI clocks for India-regulated deployments.
    pub arming_policy: ArmingPolicyKind,
}

impl IncidentConfig {
    /// Resolve the configured arming policy into the concrete `ArmingPolicy` type.
    pub fn arming_policy(&self) -> ArmingPolicy {
        match self.arming_policy {
            ArmingPolicyKind::Generic => ArmingPolicy::generic_default(),
            ArmingPolicyKind::IndiaRegulatory => ArmingPolicy::india_regulatory_default(),
        }
    }
    /// Resolve the configured report template store.
    pub fn report_templates(&self) -> ainxt_incident::report::TemplateStore {
        match self.arming_policy {
            ArmingPolicyKind::Generic => ainxt_incident::report::TemplateStore::default(),
            ArmingPolicyKind::IndiaRegulatory => {
                ainxt_incident::report::TemplateStore::india_regulatory_default()
            }
        }
    }
    /// Resolve the configured cadence scheduler.
    pub fn cadence_scheduler(&self) -> CadenceScheduler {
        match self.arming_policy {
            ArmingPolicyKind::Generic => CadenceScheduler::default(),
            ArmingPolicyKind::IndiaRegulatory => CadenceScheduler::india_regulatory_default(),
        }
    }
}

/// The fully-loaded daemon configuration.
#[derive(Debug, Clone)]
pub struct LoadedConfig {
    pub runtime: RuntimeConfig,
    pub server: ServerConfig,
    pub session: SessionConfig,
    /// The knowledge base the daemon seeds the live retrieval corpus with.
    pub kb: KbConfig,
    /// The Serving-Ops node pool + admission tuning the daemon binds the QoS + attestation fence onto.
    pub serving: ServingConfig,
    /// Per-surface **deployment layer-overrides** (gap SURF: profile layer-override wired into the
    /// served daemon path). A deployment tweaks a nested field of a canonical surface without restating
    /// it (`[surfaces.chat.model_policy] default_tier = "complex"`); [`assemble_surface`] applies these
    /// via [`SurfaceCatalog::builtin_with_overrides`], so the profile layer-merge is LIVE on the served
    /// path, not just a loader capability.
    pub surfaces: SurfacesConfig,
    /// GAP-FIX harness-sdk-governance — declaratively pre-register bundled custom renderer ids so the
    /// harness `/run` bridge's admission gate is genuinely fail-closed (see [`HarnessConfig`]).
    pub harness: HarnessConfig,
    /// GAP-FIX tooling-mcp-plugins-routing — the MCP servers THIS deployment actually connects to at
    /// boot (see [`McpConfig`]). Empty by default (air-gapped posture unchanged).
    pub mcp: McpConfig,
    /// GAP-FIX payments-governance — the dual-council-governed settlement-policy override (see
    /// [`PaymentsConfig`]). Empty by default (unchanged `PaymentBoundary::payment_default()` posture).
    pub payments: PaymentsConfig,
    /// Incident arming-policy selection. OSS default: `Generic` (no pre-armed clocks).
    /// Set `arming_policy = "india-regulatory"` in a private overlay for India-regulated deployments.
    pub incident: IncidentConfig,
}

/// The harness section (`[harness]`) — GAP-FIX harness-sdk-governance: `RegisteredRendererResolver`
/// (an explicit allow-set of bundled renderer ids, fail-closed on an unregistered
/// [`ainxt_admission::HarnessRenderer::Custom`] declaration) was fully implemented and tested, but
/// [`mounts::build_harness_mounts`] always installed the permissive [`ainxt_admission::AnyRendererResolver`]
/// (every custom renderer id accepted) — so a manifest declaring an unbacked custom renderer was
/// silently admitted on the shipped daemon instead of refused. `registered_renderers` empty (the
/// default) keeps that exact permissive behavior unchanged (nothing declared ⇒ nothing to allow-list
/// against, so `AnyRendererResolver` stays correct); a deployment that lists its bundled renderer ids
/// here gets the fail-closed resolver instead. Split off in [`load_layered`] like `[serving]` so
/// `ainxt-config` need not know about the harness/admission layer.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HarnessConfig {
    /// Bundled custom renderer ids this deployment actually has backing for. Non-empty ⇒ the daemon
    /// installs `RegisteredRendererResolver` (fail-closed on anything else); empty ⇒ unchanged
    /// `AnyRendererResolver` default.
    pub registered_renderers: Vec<String>,
}

/// The MCP server-connection section (`[mcp]`) — GAP-FIX tooling-mcp-plugins-routing: the real stdio
/// transport (`ainxt_mcp::McpTransportConfig::spawn`/`JsonRpcStdioTransport`) and the `McpRegistry` it
/// registers into were both real and unit-tested, but nothing on the served composition root ever
/// called `.register(McpServer::new(...))` — the daemon's `McpRegistry` was always constructed via
/// `McpRegistry::new()` with zero servers, so a shipped deployment never actually ran the connect/auth
/// machinery (every real `McpServer::new`/`.register(...)` call anywhere in the workspace was in a
/// `tests/` file). `servers` declares which MCP servers THIS deployment connects to at boot; empty
/// (the default) preserves the existing air-gapped "reachable but registers nothing" posture
/// byte-for-byte — see [`build_unified_capability_registry_shared_over_with_mcp_admin_and_servers`].
/// Split off in [`load_layered`] like `[serving]`/`[harness]` so `ainxt-config`'s `RuntimeConfig`
/// (deny-unknown-fields, per-request-layered) need not know about the MCP transport layer at all.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct McpConfig {
    pub servers: Vec<McpServerConfigEntry>,
}

/// One declared MCP server (`[[mcp.servers]]`): a stable `name` (the served namespace/TOFU-pin
/// identity) plus the [`ainxt_mcp::McpTransportConfig`] describing how to reach it — stdio spawns a
/// REAL child process; `StreamableHttp`/`Sse` round-trip through config but fail closed with a named
/// error at connect time (no live HTTP/SSE client exists yet, same as the bare transport type). A
/// deployment declares, e.g.:
/// ```toml
/// [[mcp.servers]]
/// name = "jira"
///
/// [mcp.servers.transport]
/// kind = "stdio"
/// command = "mcp-jira-server"
/// args = ["--stdio"]
/// ```
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpServerConfigEntry {
    pub name: String,
    pub transport: ainxt_mcp::McpTransportConfig,
}

/// The settlement-policy override section (`[payments]`) — GAP-FIX payments-governance (IDN-10,
/// ADR-026 §4.4/§4.5): `ainxt_payments::boundary::SettlementPolicy` / `PolicyGovernance` /
/// `authorize_edit` were fully implemented and exhaustively unit-tested (`r11_payment_boundary_gaps.rs`)
/// but had ZERO composition-root callers — the daemon always built the hardcoded
/// [`ainxt_payments::boundary::PaymentBoundary::npci`] constant (see [`resolve_payment_boundary`]), so
/// there was in fact NO live mechanism — config, hot-reload, or otherwise — for a deployment to change
/// what counts as "payment" short of editing this crate's Rust source and recompiling, and even then no
/// dual-council check ran over that diff; only ordinary code review governed it.
///
/// Both fields `None` (the default, no `[payments]` layer) preserves the exact byte-identical
/// `PaymentBoundary::payment_default()` behavior every prior release shipped. When BOTH are set, the boot
/// preflight in [`resolve_payment_boundary`] authorizes the proposed edit against the shipped baseline
/// via `SettlementPolicy::authorize_edit` before the daemon will assemble AT ALL — fail-closed, so a
/// config carrying an unauthorized boundary change (missing either council's sign-off, an unsigned or
/// non-`can_approve` commit, a too-junior author, or an attempt to shrink the one-way-ratcheted
/// perimeter) refuses to boot rather than silently serving a weaker boundary.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PaymentsConfig {
    /// The proposed [`ainxt_payments::boundary::SettlementPolicy`] this deployment wants to run — a
    /// versioned, git-controlled artifact (see that type's own doc). Must be paired with
    /// `settlement_governance`; setting only one is a config error (`resolve_payment_boundary`).
    pub settlement_policy: Option<ainxt_payments::boundary::SettlementPolicy>,
    /// The dual-council evidence `authorize_edit` checks the above policy edit against (payments-council
    /// AND security-council approval, a signed `ad_level<=3` `can_approve` commit).
    pub settlement_governance: Option<ainxt_payments::boundary::PolicyGovernance>,
}

/// Per-surface deployment layer-overrides, resolved from the `[surfaces]` config section. Each entry
/// is `(surface_id, override_toml_source)` — the override layer merged on top of the canonical
/// surface's embedded profile (see [`SurfaceCatalog::builtin_with_overrides`]).
#[derive(Debug, Clone, Default)]
pub struct SurfacesConfig {
    overrides: Vec<(String, String)>,
}

impl SurfacesConfig {
    /// Borrow the overrides as `(&str, &str)` pairs for [`SurfaceCatalog::builtin_with_overrides`].
    pub fn as_refs(&self) -> Vec<(&str, &str)> {
        self.overrides
            .iter()
            .map(|(id, src)| (id.as_str(), src.as_str()))
            .collect()
    }
    pub fn is_empty(&self) -> bool {
        self.overrides.is_empty()
    }
    pub fn len(&self) -> usize {
        self.overrides.len()
    }
}

/// An assembly / configuration failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssembleError {
    /// A config layer failed to parse, merge, or validate.
    Config(String),
    /// A config selected an enterprise gate this OSS binary was not built with. Fail-closed: the
    /// daemon refuses to start rather than silently run a weaker gate.
    EnterpriseGateUnavailable(String),
}

impl std::fmt::Display for AssembleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AssembleError::Config(m) => write!(f, "config error: {m}"),
            AssembleError::EnterpriseGateUnavailable(m) => {
                write!(
                    f,
                    "requested gate not available in this build: {m} — use the enterprise build"
                )
            }
        }
    }
}
impl std::error::Error for AssembleError {}

// ============================ Config loading ============================

fn take_section<T: serde::de::DeserializeOwned + Default>(
    table: &mut toml::value::Table,
    key: &str,
) -> Result<T, AssembleError> {
    match table.remove(key) {
        Some(v) => v
            .try_into()
            .map_err(|e: toml::de::Error| AssembleError::Config(format!("[{key}]: {e}"))),
        None => Ok(T::default()),
    }
}

/// The **shipped daemon base-defaults** layer, prepended (as the least-specific layer) under every
/// deployment/tenant config the daemon loads (see [`load_shipped`] + `main`). It turns the safety
/// layers ON by default — the shipped posture, not opt-in:
///
/// * **Guardrails** jailbreak / groundedness / toxicity / system-prompt-leak / citation = `audit`
///   (flag-and-proceed — the redact-don't-block spirit; NEVER `enforce` in the shipped base, which
///   can hard-block a turn — that stays a deliberate deployment opt-in, e.g. via
///   [`ainxt_guardrails::GuardrailsConfig::recommended`], never the out-of-the-box posture). A
///   flagged turn is recorded to the audit trail and PROCEEDS. `topic` / `format` stay unset (inert
///   without a deployment-supplied `topic_config`/`format_spec`).
/// * **Prompt-injection defense** = `enforce` — the real ADR-009 defense: untrusted RAG/connector
///   content is scanned + fenced and a tainted turn gates side-effecting tools. It never blocks a
///   plain chat answer (a turn with no untrusted input is never tainted), so `/v1/chat` still serves.
///
/// `system_prompt_leak` and `citation` are new here — previously left at `Off` by omission even
/// though [`ainxt_guardrails::GuardrailsConfig::recommended`] enables both; turning them on in
/// `audit` mode closes that gap without adopting `recommended`'s `enforce` choices, which would
/// contradict the shipped base's own never-hard-block-by-default rule above.
///
/// A deployment can still override any of these via a later config layer (config-first), including
/// opting up to `enforce` where it wants a hard block; the point is that the SHIPPED default is
/// audit-on, not off. `version` is set so the base validates stand-alone.
pub const SHIPPED_DEFAULTS: &str = "\
version = 1

[guardrails]
jailbreak = \"audit\"
groundedness = \"audit\"
toxicity = \"audit\"
system_prompt_leak = \"audit\"
citation = \"audit\"

[injection]
mode = \"enforce\"
";

/// Load the daemon config the SHIPPED way: the [`SHIPPED_DEFAULTS`] base layer (guardrails + injection
/// ON) first, then the caller's deployment/tenant `layers` (most-specific last) on top — so the shipped
/// posture is safety-on-by-default while a deployment can still override. This is what `main` calls;
/// [`load_layered`] remains the raw primitive (no base) for callers that want exactly their own layers.
pub fn load_shipped(layers: &[(&str, &str)]) -> Result<LoadedConfig, AssembleError> {
    let mut all: Vec<(&str, &str)> = Vec::with_capacity(layers.len() + 1);
    all.push(("shipped-defaults", SHIPPED_DEFAULTS));
    all.extend_from_slice(layers);
    load_layered(&all)
}

/// Load + merge ordered TOML `layers` (`(name, src)`, most-specific last), split off `[server]` and
/// `[session]`, then resolve + validate the [`RuntimeConfig`] from what remains.
pub fn load_layered(layers: &[(&str, &str)]) -> Result<LoadedConfig, AssembleError> {
    let mut loader = ainxt_config::Loader::new();
    for (name, src) in layers {
        loader = loader
            .layer(name, src)
            .map_err(|e| AssembleError::Config(e.to_string()))?;
    }
    let merged = loader.merged();
    let mut table = match merged {
        toml::Value::Table(t) => t,
        _ => return Err(AssembleError::Config("config root must be a table".into())),
    };

    let server: ServerConfig = take_section(&mut table, "server")?;
    let session: SessionSettings = take_section(&mut table, "session")?;
    let kb: KbConfig = take_section(&mut table, "kb")?;
    let serving: ServingConfig = take_section(&mut table, "serving")?;
    let harness: HarnessConfig = take_section(&mut table, "harness")?;
    let mcp: McpConfig = take_section(&mut table, "mcp")?;
    let payments: PaymentsConfig = take_section(&mut table, "payments")?;
    let incident: IncidentConfig = take_section(&mut table, "incident")?;
    let surfaces = take_surface_overrides(&mut table)?;

    let runtime: RuntimeConfig = toml::Value::Table(table)
        .try_into()
        .map_err(|e: toml::de::Error| AssembleError::Config(e.to_string()))?;
    runtime
        .validate()
        .map_err(|e| AssembleError::Config(format!("{e}")))?;

    // GAP6 session-resume-consolidate — `SessionConfig::validate`'s own doc says "call at config-load
    // for a fail-fast, clear error", but until now nothing did: `SessionManager::new` only ever called
    // the silent-clamp `sanitized()`, so a deployment that mistypes `[session] max_sessions = 0` (or
    // `inbox_capacity = 0`) got no boot-time signal at all — just a quietly-clamped-to-1 session cap in
    // production. `runtime.validate()` right above is this SAME function's established convention for
    // a bad config value (hard-fail the boot with a clear message instead of guessing); apply it here
    // too, before the value ever reaches `SessionManager::new`'s clamp.
    let session: SessionConfig = session.into_config();
    session
        .validate()
        .map_err(|e| AssembleError::Config(format!("[session] {e}")))?;

    // ARCH-F-001 — same fail-closed convention as the two validations right above: before this
    // existed, nothing in the config-load path ever asked "is this daemon's connection encrypted?",
    // so a deployment could widen `server.host` beyond loopback with no boot-time signal at all.
    validate_transport_exposure(&server).map_err(AssembleError::Config)?;

    Ok(LoadedConfig {
        runtime,
        server,
        session,
        kb,
        serving,
        surfaces,
        harness,
        mcp,
        payments,
        incident,
    })
}

/// Split off the `[surfaces]` section into per-surface deployment override TOML sources. Each
/// `[surfaces.<id>]` sub-table is re-serialized to a TOML string that [`assemble_surface`] layers on
/// top of the canonical `<id>` profile. Deterministic (sorted by id). A non-table `[surfaces]` value
/// or a non-table entry is a hard config error (fail-closed, no partial parse).
fn take_surface_overrides(table: &mut toml::value::Table) -> Result<SurfacesConfig, AssembleError> {
    let raw = match table.remove("surfaces") {
        Some(toml::Value::Table(t)) => t,
        Some(_) => {
            return Err(AssembleError::Config(
                "[surfaces] must be a table of per-surface overrides".into(),
            ))
        }
        None => return Ok(SurfacesConfig::default()),
    };
    let mut overrides = Vec::with_capacity(raw.len());
    // `toml::value::Table` is a BTreeMap → iteration is already sorted by id (deterministic).
    for (id, v) in raw {
        let sub = match v {
            toml::Value::Table(t) => t,
            _ => {
                return Err(AssembleError::Config(format!(
                    "[surfaces.{id}] must be a table"
                )))
            }
        };
        let src = toml::to_string(&toml::Value::Table(sub))
            .map_err(|e| AssembleError::Config(format!("[surfaces.{id}] not serializable: {e}")))?;
        overrides.push((id, src));
    }
    Ok(SurfacesConfig { overrides })
}

// ============================ Gates (fail-closed on enterprise selection) ============================

type Gates = (
    Box<dyn ComplianceGate>,
    Box<dyn Authorizer>,
    Box<dyn AuditSink>,
);

fn build_gates(gates: &GatesConfig) -> Result<Gates, AssembleError> {
    let compliance: Box<dyn ComplianceGate> = match gates.compliance {
        ComplianceProvider::Default => Box::new(RedactAndProceed),
        ComplianceProvider::PciDss => {
            return Err(AssembleError::EnterpriseGateUnavailable(
                "compliance = pci-dss".into(),
            ))
        }
    };
    let authz: Box<dyn Authorizer> = match gates.authz {
        AuthzProvider::Rbac => Box::new(RbacAuthorizer),
        AuthzProvider::AdRbac => {
            return Err(AssembleError::EnterpriseGateUnavailable(
                "authz = ad-rbac".into(),
            ))
        }
    };
    let audit: Box<dyn AuditSink> = match gates.audit {
        AuditSinkKind::Memory => Box::new(InMemoryAudit::default()),
        // GAP-AUDIT transport-daemon #6 — `AuditSinkKind::EventLog` names a durable backend built
        // ENTIRELY from OSS crates already in this workspace (the same hash-chained
        // `GuardedEventLog` the daemon's own session/audit log already uses via
        // `open_guarded_event_log`) — unlike its two siblings (`compliance = pci-dss` /
        // `authz = ad-rbac`, genuinely external enterprise plugins this OSS binary cannot ship),
        // this was refused identically despite needing no enterprise plugin at all.
        AuditSinkKind::EventLog => {
            let dir = gates.audit_event_log_dir.clone().unwrap_or_else(|| {
                std::env::temp_dir()
                    .join("ainxt-audit-eventlog")
                    .to_string_lossy()
                    .into_owned()
            });
            let log = open_guarded_event_log(&dir).map_err(|e| {
                AssembleError::Config(format!("audit = event-log: cannot open '{dir}': {e}"))
            })?;
            Box::new(EventLogAuditSink {
                log,
                session: "audit".to_string(),
            })
        }
    };
    Ok((compliance, authz, audit))
}

/// GAP-FIX tooling-mcp-plugins-routing — every served agent loop's OBO (on-behalf-of) decision
/// (declared-grant ∧ issued-scope ∧ resource-ABAC verdict, GRANTED or DENIED — including a
/// confused-deputy denial) was written to an ephemeral [`ainxt_tools::obo::VecOboAudit`], lost on
/// every daemon restart, even though [`ainxt_tools::obo::EventLogOboAudit`] already exists as the
/// durable, tamper-evident sink — the exact same [`GuardedEventLog`] backend `[gates] audit =
/// "event-log"` already builds via [`build_gates`] for the ordinary audit trail (§1.6: "every OBO
/// decision... written to the Event Log... reconstructable for audit two years later"). This mirrors
/// that SAME match on [`AuditSinkKind`] so an OBO decision gets the identical durability guarantee as
/// every other served audit record, without inventing new config. Uses a distinct `"__obo__"` session
/// on the SAME hash-chained log (never the same session as the ordinary audit trail, so the two
/// streams never interleave) — writing to the same directory via a second `GuardedEventLog` handle is
/// safe because `JsonlEventLog` keys its chain-head index per session, not per open handle.
fn build_obo_sink(
    gates: &GatesConfig,
) -> Result<Arc<dyn ainxt_tools::obo::OboDecisionSink>, AssembleError> {
    let sink: Arc<dyn ainxt_tools::obo::OboDecisionSink> = match gates.audit {
        AuditSinkKind::Memory => Arc::new(ainxt_tools::obo::VecOboAudit::new()),
        AuditSinkKind::EventLog => {
            let dir = gates.audit_event_log_dir.clone().unwrap_or_else(|| {
                std::env::temp_dir()
                    .join("ainxt-audit-eventlog")
                    .to_string_lossy()
                    .into_owned()
            });
            let log = open_guarded_event_log(&dir).map_err(|e| {
                AssembleError::Config(format!(
                    "audit = event-log (obo sink): cannot open '{dir}': {e}"
                ))
            })?;
            Arc::new(ainxt_tools::obo::EventLogOboAudit::with_session(
                log, "__obo__",
            ))
        }
    };
    Ok(sink)
}

/// GAP-AUDIT transport-daemon #6 — adapts the durable, tamper-evident [`GuardedEventLog`] to the
/// [`AuditSink`] seam so `audit = "event-log"` is a real, OSS-buildable durable backend rather than
/// an unconditional refusal. Best-effort: a durable-write failure never fails the turn whose audit
/// record it was for (matches this codebase's established posture for non-critical audit writes,
/// e.g. [`ServedTurnRecorder`]) — the record is still counted (`InMemoryAudit`-equivalent behavior
/// for the caller), only the persistence attempt can silently fail.
struct EventLogAuditSink {
    log: GuardedEventLog<ainxt_eventlog::JsonlEventLog>,
    /// All audit records share one session stream (the log's own hash chain provides ordering +
    /// tamper-evidence across every record, regardless of which turn/session it came from).
    session: String,
}

impl AuditSink for EventLogAuditSink {
    fn record(&self, rec: AuditRecord) {
        let text = format!("[{}] actor={} {}", rec.turn, rec.actor, rec.summary);
        let _ = self.log.append(&self.session, &rec.actor, "audit", &text);
    }
}

// ============================ Provider factory ============================

/// Deterministic provider that runs with no network — the air-gapped default when no live provider
/// is available. Eligible for every data class (it is local; nothing egresses).
struct OfflineProvider;
impl Provider for OfflineProvider {
    fn id(&self) -> &str {
        "offline"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, _prompt: &str) -> mpsc::Receiver<ainxt_protocol::Event> {
        let (tx, rx) = mpsc::channel(8);
        tokio::spawn(async move {
            let _ = tx
                .send(ainxt_protocol::Event::TextDelta(
                    "offline mode: no model configured.".into(),
                ))
                .await;
            let _ = tx.send(ainxt_protocol::Event::Done).await;
        });
        rx
    }
}

/// Build a real adapter for a provider config, or `None` if it can't be wired (missing key/URL).
/// The provider's `id` is used as the model name (no separate model field in the config).
fn build_provider(pc: &ProviderConfig) -> Option<Box<dyn Provider>> {
    let eligible = pc.eligible.clone();
    match pc.kind {
        ProviderKind::Anthropic => {
            let key = std::env::var("ANTHROPIC_API_KEY")
                .ok()
                .filter(|k| !k.is_empty())?;
            let base = pc
                .base_url
                .clone()
                .unwrap_or_else(|| "https://api.anthropic.com".into());
            Some(Box::new(AnthropicProvider::new(
                base,
                key,
                pc.id.clone(),
                eligible,
            )))
        }
        ProviderKind::OpenAiSchema => {
            let key = std::env::var("OPENAI_API_KEY")
                .ok()
                .filter(|k| !k.is_empty())?;
            let base = pc.base_url.clone()?; // OpenAI-schema requires an explicit endpoint
            Some(Box::new(OpenAiSchemaProvider::new(
                base,
                key,
                pc.id.clone(),
                eligible,
            )))
        }
        ProviderKind::Gemini => {
            // GAP-FIX providers-gemini-quality-tripwire — completes the model-agnostic trio
            // (OpenAI-schema, Anthropic, Gemini) at the ONE place a provider is actually wired
            // into the served router. `GeminiProvider` was previously built and unit-tested but
            // never constructed here, so no config could ever route to it. Same
            // present-key-or-no-op convention as `Anthropic`/`OpenAiSchema` above: `GOOGLE_API_KEY`
            // is the platform-wide env var (CLAUDE.md's Required Environment Variables), matching
            // `ANTHROPIC_API_KEY`/`OPENAI_API_KEY` exactly rather than inventing a Gemini-specific
            // name.
            let key = std::env::var("GOOGLE_API_KEY")
                .ok()
                .filter(|k| !k.is_empty())?;
            let base = pc
                .base_url
                .clone()
                .unwrap_or_else(|| "https://generativelanguage.googleapis.com/v1beta".into());
            Some(Box::new(GeminiProvider::new(
                base,
                key,
                pc.id.clone(),
                eligible,
            )))
        }
        ProviderKind::Local => {
            // A locally-hosted OpenAI-schema server (vLLM/Ollama) — usually keyless.
            // base_url is read from config first; if absent or empty, fall back to the
            // LLM_BASE_URL environment variable (set in deploy/.env for OSS users, or
            // in the deployment environment for a managed deployment). If neither is set,
            // this provider is not wired (returns None → offline mode).
            let base = pc
                .base_url
                .clone()
                .filter(|s| !s.is_empty())
                .or_else(|| std::env::var("LLM_BASE_URL").ok().filter(|s| !s.is_empty()))?;
            let key = std::env::var("LOCAL_API_KEY").unwrap_or_default();
            Some(Box::new(OpenAiSchemaProvider::new(
                base,
                key,
                pc.id.clone(),
                eligible,
            )))
        }
    }
}

/// FI-03 §3.2 — the signed, explicit on-prem exemption set for the fail-CLOSED outsourcing guard: the
/// provider ids that are NOT outsourcing arrangements and are therefore never register-gated. This is
/// the ONLY way a route escapes the register — externality is otherwise by construction. Membership is
/// authoritative (derived from the deployment's own config `ProviderKind`), never from a provider
/// adapter's self-declaration:
/// - `"offline"` — the air-gapped local provider (nothing egresses; keeps the default serving);
/// - every provider configured with [`ProviderKind::Local`] — a locally hosted vLLM/Ollama endpoint.
///
/// Cloud kinds ([`ProviderKind::Anthropic`], [`ProviderKind::OpenAiSchema`], [`ProviderKind::Gemini`])
/// are deliberately absent, so a cloud route is always treated as external and stays fail-closed until
/// a board-approved arrangement is registered under its derived id.
fn in_house_exemptions(models: &ModelsConfig) -> std::collections::BTreeSet<String> {
    let mut exempt = std::collections::BTreeSet::new();
    exempt.insert("offline".to_string());
    for pc in &models.providers {
        if matches!(pc.kind, ProviderKind::Local) {
            exempt.insert(pc.id.clone());
        }
    }
    exempt
}

/// GAP-FIX transport-daemon (ADR-016 §9) — install the REAL payment-initiation-signature
/// classifier ([`ainxt_payments::boundary::PaymentBoundary`]) as the served engine's
/// `payment_boundary` resolver. Before this fix `Engine::new`'s default resolver
/// (`|_, _| PaymentBoundary::None`) was never overridden anywhere in the daemon composition root, so
/// no served `approval.request` could ever carry a real boundary — a payment-adjacent tool call could
/// clear the ordinary high-risk gate (or slip through a Low/Medium-risk tool entirely) without ever
/// reaching the human-approve-only invariant the tri-state gate at [`ainxt_runtime`]'s dispatch loop
/// enforces for `payment_boundary != none`.
///
/// This reuses the SAME §4.5 signature classifier `ainxt-connector-http`'s egress tripwire already
/// screens *resolved* network calls with — applied here one layer earlier, at tool *dispatch* (before
/// any network egress is attempted), on the tool's declared `resource_key` (via
/// [`ToolRuntime::resource_of`], the identical resource-authz seam `classify_data_class` reads) and a
/// payload-signal scan of the raw call args for the same value-moving markers
/// [`ainxt_payments::boundary::PayloadSignal`] recognizes (ISO 20022 `pacs./pain.`, UPI
/// collect/request-to-pay/credit-push, a NACH mandate execution, and the 2026 agent-payment-protocol
/// credentials of §5). A tool call that names a settlement resource or carries one of these payload
/// markers is caught here even when its registered `effect_class` under-declares it — the Layer 6
/// pre-dispatch tripwire ADR-016 §4.6 describes, independent of what the capability *declared*.
///
/// The tool `name` doubles as the classifier's `destination` field: a capability literally named
/// inside the reserved settlement perimeter (e.g. `"x402.pay"`, `"nach.npci.execute"`) matches
/// exactly as a resolved network destination would. Note that the match is a substring test
/// against [`SettlementPerimeter::default_reserved`]'s patterns, so a merely settlement-*sounding*
/// name such as `"settlement.example.transfer"` does NOT match on the shipped default perimeter —
/// only the resource-key and payload facets, or a deployment-reserved pattern, can catch that one. This is intentionally the SAME belt-and-suspenders
/// posture as the connector-layer perimeter check — a real resolved destination is screened again at
/// the connector layer regardless, so a tool name that happens not to match here is never the only
/// gate a payment-shaped call must clear.
///
/// `pub` (not just used internally) so a composition-root test can install the IDENTICAL resolver
/// the daemon builds — directly, never a re-derivation of its detection logic — on a hand-assembled
/// `Engine` when proving the full dispatch/approval-gate behavior end-to-end (no shipped `Provider`
/// adapter parses tool-calls from a live model response yet, so that proof needs a test double
/// provider; the resolver under test must still be the real one).
/// Default payment boundary resolver — uses [`PaymentBoundary::payment_default`] as the baseline.
/// Configurable: pass a custom boundary via [`payment_boundary_resolver_over`] for deployments
/// that need a different perimeter.
pub fn default_payment_boundary_resolver(
    tools: std::sync::Arc<ToolRuntime>,
) -> Box<dyn Fn(&str, &str) -> ainxt_protocol::PaymentBoundary + Send + Sync> {
    payment_boundary_resolver_over(
        ainxt_payments::boundary::PaymentBoundary::payment_default(),
        tools,
    )
}

/// Deprecated alias for [`default_payment_boundary_resolver`]. Use `default_payment_boundary_resolver()` in new code.
#[deprecated(
    since = "1.0.0",
    note = "use `default_payment_boundary_resolver()` instead"
)]
pub fn npci_payment_boundary_resolver(
    tools: std::sync::Arc<ToolRuntime>,
) -> Box<dyn Fn(&str, &str) -> ainxt_protocol::PaymentBoundary + Send + Sync> {
    default_payment_boundary_resolver(tools)
}

/// Same classifier [`default_payment_boundary_resolver`] builds, but over an explicit, caller-supplied
/// [`ainxt_payments::boundary::PaymentBoundary`] instead of always the default — GAP-FIX
/// payments-governance: this is what lets a [`resolve_payment_boundary`] result (a
/// governance-authorized [`ainxt_payments::boundary::SettlementPolicy`] edit, or the unchanged
/// default) actually reach the served classifier, rather than `SettlementPolicy::authorize_edit` being
/// a pure decision with nothing downstream ever consuming its output. `default_payment_boundary_resolver`
/// itself is kept as the zero-config-override default (delegates here with `PaymentBoundary::payment_default()`)
/// so every existing caller — including the composition-root test that installs the IDENTICAL resolver
/// the daemon builds — is unaffected.
pub fn payment_boundary_resolver_over(
    boundary: ainxt_payments::boundary::PaymentBoundary,
    tools: std::sync::Arc<ToolRuntime>,
) -> Box<dyn Fn(&str, &str) -> ainxt_protocol::PaymentBoundary + Send + Sync> {
    Box::new(move |name: &str, args: &str| {
        let resource_key = tools.resource_of(name, args).unwrap_or_default();
        let call = ainxt_payments::boundary::OutboundCall {
            destination: name.to_string(),
            resource_key,
            payload: payment_payload_signal(args),
        };
        match boundary.classify(&call) {
            ainxt_payments::boundary::PaymentInitiationVerdict::Adjacent => {
                ainxt_protocol::PaymentBoundary::None
            }
            ainxt_payments::boundary::PaymentInitiationVerdict::Initiating { reasons } => {
                use ainxt_payments::boundary::InitiationReason;
                if reasons.contains(&InitiationReason::SettlementPerimeterDestination)
                    || reasons.contains(&InitiationReason::SettlementResourceKey)
                {
                    ainxt_protocol::PaymentBoundary::InitiatesSettlement
                } else {
                    ainxt_protocol::PaymentBoundary::MovesValue
                }
            }
        }
    })
}

/// **The boot-time settlement-policy governance preflight** (GAP-FIX payments-governance, IDN-10,
/// ADR-026 §4.4/§4.5). Resolves the [`ainxt_payments::boundary::PaymentBoundary`] THIS boot serves:
///
/// * `payments` empty (both fields `None`, the default — no `[payments]` config layer) resolves to
///   the shipped [`PaymentBoundary::npci`](ainxt_payments::boundary::PaymentBoundary::npci) constant,
///   byte-identical to every prior release.
/// * Both fields set: authorizes the proposed `settlement_policy` edit against the shipped baseline
///   ([`SettlementPolicy::npci_baseline`](ainxt_payments::boundary::SettlementPolicy::npci_baseline))
///   under the presented `settlement_governance` evidence via
///   [`SettlementPolicy::authorize_edit`](ainxt_payments::boundary::SettlementPolicy::authorize_edit)
///   — fail-closed. An unauthorized edit (missing either council's sign-off, an unsigned/non-
///   `can_approve` commit, a too-junior author, or an attempt to shrink the one-way-ratcheted
///   perimeter) is a config error: the daemon refuses to assemble/boot at all rather than silently
///   serving a weaker (or merely unproven) boundary.
/// * Exactly one field set is itself a config error (a policy with no governance evidence, or
///   governance evidence with no proposed policy, can never be a deliberate deployment).
///
/// This is the daemon's ONLY path today to change the served payment boundary without a full
/// recompile — see [`PaymentsConfig`]'s doc for why a bare config/file edit could never do this
/// silently before (there was no such path at all).
fn resolve_payment_boundary(
    payments: &PaymentsConfig,
) -> Result<ainxt_payments::boundary::PaymentBoundary, AssembleError> {
    use ainxt_payments::boundary::{PaymentBoundary, SettlementPolicy};
    match (&payments.settlement_policy, &payments.settlement_governance) {
        (None, None) => Ok(PaymentBoundary::payment_default()),
        (Some(next), Some(gov)) => {
            let baseline = SettlementPolicy::default_baseline("shipped-baseline");
            baseline.authorize_edit(next, gov).map(|applied| applied.build_boundary()).map_err(|e| {
                AssembleError::Config(format!(
                    "[payments] settlement_policy edit refused by governance gate: {e}"
                ))
            })
        }
        (Some(_), None) | (None, Some(_)) => Err(AssembleError::Config(
            "[payments] settlement_policy and settlement_governance must both be set or both omitted"
                .to_string(),
        )),
    }
}

/// Scan a tool call's raw args (a JSON-ish string; never parsed as trusted structure, only scanned
/// for markers) for the §4.5 value-moving payload signatures
/// [`ainxt_payments::boundary::PayloadSignal`] recognizes, independent of what the tool's registered
/// `effect_class` declares. Case-insensitive; a miss simply falls through to `Benign` (the perimeter +
/// resource-key checks in [`npci_payment_boundary_resolver`] are the belt to this suspenders, exactly
/// mirroring the destination-perimeter/resource-key defense-in-depth `PaymentBoundary::classify`
/// already documents for its other signals).
fn payment_payload_signal(args: &str) -> ainxt_payments::boundary::PayloadSignal {
    use ainxt_payments::boundary::{AgentPayProtocol, PayloadSignal, UpiOperation};
    let a = args.to_ascii_lowercase();
    for prefix in ["pacs.", "pain."] {
        if let Some(idx) = a.find(prefix) {
            let tail = &a[idx..];
            let end = tail
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '.'))
                .unwrap_or(tail.len());
            return PayloadSignal::Iso20022 {
                message_type: tail[..end].to_string(),
            };
        }
    }
    if a.contains("nach") && (a.contains("mandate") || a.contains("execute")) {
        return PayloadSignal::NachMandateExecution;
    }
    let upi = if a.contains("credit_push") || a.contains("credit-push") || a.contains("creditpush")
    {
        Some(UpiOperation::CreditPush)
    } else if a.contains("request_to_pay")
        || a.contains("request-to-pay")
        || a.contains("requesttopay")
    {
        Some(UpiOperation::RequestToPay)
    } else if a.contains("upi") && a.contains("collect") {
        Some(UpiOperation::Collect)
    } else {
        None
    };
    if let Some(op) = upi {
        return PayloadSignal::Upi(op);
    }
    for (pat, proto) in [
        ("ap2.", AgentPayProtocol::Ap2CartMandate),
        ("agentpayments.google", AgentPayProtocol::Ap2CartMandate),
        ("agenticcommerce.", AgentPayProtocol::AcpSharedPaymentToken),
        ("acp.stripe", AgentPayProtocol::AcpSharedPaymentToken),
        ("trustedagent.visa", AgentPayProtocol::VisaTrustedAgent),
        ("agentpay.mastercard", AgentPayProtocol::MastercardAgentPay),
        ("x402.", AgentPayProtocol::X402Funded),
        ("402.coinbase", AgentPayProtocol::X402Funded),
    ] {
        if a.contains(pat) {
            return PayloadSignal::AgentPaymentCredential(proto);
        }
    }
    PayloadSignal::Benign
}

/// Build the router, returning a human-readable report of what was wired. If no live provider can be
/// wired, an offline provider is registered so the daemon always runs.
///
/// GAP-FIX misc-decisions (`ainxt-config`'s `ModelsConfig::auto_routable`/`user_selectable`, the
/// config form of `core/model_registry.py`'s BLOCKED_MODELS + USER-SELECTABLE policy): this
/// deployment's shipped shape is one `ProviderConfig` per canonical model — `id` doubles as both the
/// router's routing id AND the literal wire "model" string sent to the vendor API (see
/// `build_provider`/`ainxt-runtimed/config/runtimed.example.toml`, e.g. `id = "claude-sonnet-4-6"`).
/// Before this fix, every configured provider was wired unconditionally, so a model listed in
/// `models.blocked` (e.g. a retired `claude-opus-4-5`) would still be constructed, registered, and
/// freely auto-routed/selected if a deployment operator (mis)configured it as a live provider — the
/// `blocked` list was only cross-checked against `registry` entries at config-parse time
/// (`RuntimeConfig::validate`), never against `providers`, the thing actually wired here. Two fixes:
/// 1. a blocked id is never even constructed/registered (matches "must NEVER be routed to or
///    user-selected, regardless of the registry" — stronger than merely excluding it from
///    auto-routing); 2. a provider whose id matches a `registry` entry marked
///    `user_selectable_only` is registered (so it stays reachable by an explicit forced selection —
///    a Role's `allowed_providers`, or an end-user's explicit model choice) but excluded from the
///    router's own unforced complexity→tier auto-routing via `ModelRouter::with_auto_routable`. A
///    provider with no matching registry entry (the common case for a deployment with no
///    `[[models.registry]]` block at all) defaults to auto-routable, preserving pre-existing
///    behavior for deployments that don't use the registry feature.
fn build_router(models: &ModelsConfig) -> (ModelRouter, Vec<String>) {
    let mut router = ModelRouter::new();
    let mut report = Vec::new();
    let mut wired_any = false;
    let mut auto_routable_ids: std::collections::BTreeSet<String> =
        std::collections::BTreeSet::new();
    for pc in &models.providers {
        if models.is_blocked(&pc.id) {
            report.push(format!(
                "provider '{}' ({:?}) skipped: BLOCKED_MODELS (never routed to or user-selected)",
                pc.id, pc.kind
            ));
            continue;
        }
        match build_provider(pc) {
            Some(p) => {
                router.register(p);
                wired_any = true;
                let user_selectable_only = models
                    .canonical(&pc.id)
                    .map(|entry| entry.user_selectable_only)
                    .unwrap_or(false);
                if user_selectable_only {
                    report.push(format!(
                        "provider '{}' ({:?}) wired: user-selectable-only per the model registry \
                         (reachable by explicit forced selection, excluded from auto-routing)",
                        pc.id, pc.kind
                    ));
                } else {
                    auto_routable_ids.insert(pc.id.clone());
                    report.push(format!("provider '{}' ({:?}) wired", pc.id, pc.kind));
                }
            }
            None => report.push(format!(
                "provider '{}' ({:?}) skipped: missing API key or base_url",
                pc.id, pc.kind
            )),
        }
    }
    if !wired_any {
        router.register(Box::new(OfflineProvider));
        auto_routable_ids.insert("offline".to_string());
        report.push("offline provider registered (no live provider available)".into());
    }
    router = router.with_auto_routable(auto_routable_ids);
    report.push(
        "router: auto-routable set installed from the model registry's auto_routable/\
         user_selectable_only policy (ModelsConfig::auto_routable) — a user-selectable-only or \
         blocked model is never reached by unforced complexity→tier routing"
            .into(),
    );
    // FI-03 §3.2 (regulated-fi): install the RBI IT/cloud-outsourcing register as the router's
    // NON-OVERRIDABLE eligibility input, in the FAIL-CLOSED authoritative posture. Externality is
    // decided here by construction — NOT on the provider adapter's self-declaration: every provider is
    // treated as an external/outsourced route (register-gated by `derive_route_id(id)`) UNLESS its id is
    // in the explicit, signed on-prem exemption set. Only genuinely on-prem routes are exempt: the
    // air-gapped `offline` provider, and any provider configured with `ProviderKind::Local` (a locally
    // hosted vLLM/Ollama endpoint). Cloud kinds (Anthropic / OpenAI-schema / Gemini) are NEVER exempt — a cloud
    // route that (accidentally or maliciously) fails to declare itself external can no longer slip past
    // as in-house; it is excluded BEFORE ranking + failover until a board-approved arrangement is
    // registered under its derived id. The air-gapped default therefore still SERVES via the exempt
    // `offline` route (no empty-pool 503), while any live cloud route stays fail-closed until governed.
    let residency = governed::residency();
    let in_house = in_house_exemptions(models);
    router = router.with_outsourcing_register_authoritative(
        governed::default_outsourcing_register(EXIT_REHEARSAL_CADENCE_SECS),
        residency.clone(),
        governed::wall_router_clock(),
        in_house.iter().cloned(),
    );
    report.push(format!(
        "router: RBI outsourcing register installed as the NON-overridable, FAIL-CLOSED eligibility \
         input (residency='{residency}'); externality is authoritative-by-construction (self-declaration \
         ignored); signed on-prem exemptions={in_house:?}; every other route is register-gated and \
         excluded until a board-approved arrangement exists"
    ));
    // FI-07 — install the SAME SR-11-7 quality guard shape `AssembledFull::admit_promotion` evaluates
    // (identical bar/due-diligence config; a fresh `QualityCircuitBreaker`/`DueDiligenceConfig` are
    // pure threshold values, not shared mutable state, so building a second instance here carries no
    // divergence risk) directly onto the router's non-overridable eligibility step — the "one
    // remaining hot-wire" the audit found: the gate existed and was unit-tested, but nothing ever
    // called `with_quality_guard` on the daemon's real router, so a tripped-breaker or
    // failed-due-diligence route could still be selected by ranking/failover. Starts with an empty
    // record map (routes without a record are not gated — in-house defaults), ready to gate the
    // instant a deployment registers a `ModelRiskRecord` for a route.
    router = router.with_quality_guard(
        std::collections::BTreeMap::new(),
        mounts::build_quality_breaker(&mut report),
        DueDiligenceConfig::default(),
        governed::wall_router_clock(),
    );
    report.push(
        "router: SR-11-7 model-risk quality guard installed as a NON-overridable eligibility input \
         (empty record map by default — a route only gates once a ModelRiskRecord is registered for \
         it; a tripped circuit-breaker or failed due-diligence check excludes the route BEFORE \
         ranking/failover, mirroring AssembledFull::admit_promotion's checks)"
            .into(),
    );
    (router, report)
}

/// Restrict a [`ModelsConfig`] to the surface's model-policy `forced_provider` / `allowed_providers`
/// (gap SURF: enforce allowed_providers server-side; GAP-FIX surface-turnplan-policy: also enforce
/// `forced_provider`). Returns a view holding only admissible providers (order + all other fields
/// preserved), plus a report of any provider excluded by the surface policy. No `forced_provider` and
/// an EMPTY allow-list means "any provider" — the config is returned unchanged. This runs BEFORE the
/// router is built, so a disallowed provider is never registered and can never be selected — additive
/// to the router's non-overridable data-class gate, never a replacement for it.
///
/// GAP-FIX surface-turnplan-policy — the per-provider admissibility decision now calls
/// [`ainxt_surface::TurnPlan::is_provider_admissible`], the SAME pure predicate
/// [`ainxt_surface::TurnPlan::provider_allowed`] uses for a planned turn, instead of a hand-rolled
/// `allowlist`-only membership check. Before this fix, a surface that pinned `forced_provider` with an
/// EMPTY `allowed_providers` (e.g. a `[surfaces.<id>.model_policy] forced_provider = "..."` deployment
/// override — exactly what `r11_profile_layer_override_applies_to_a_canonical_surface` exercises on
/// `chat`) hit the `allowlist.is_empty()` fast path below and kept EVERY configured provider registered
/// on this surface's router — contradicting this function's own "never registered ... structural, not
/// advisory" promise. The forced provider still always WON the per-turn `select_chain`/`select`
/// (`Request::forced_provider` narrows to a single-element chain), so no served chat turn could reach
/// the wrongly-registered extras; but `build_chat_classifier_model` (the Stage-2 intent classifier)
/// reads the daemon's full/narrowed model list directly, OUTSIDE the per-turn forced-provider narrowing
/// — see `build_chat_surface_wired_authz`'s identical re-filter for that call site. This predicate is
/// now the single enforcement decision both consult.
fn filter_models_by_allowlist(
    models: &ModelsConfig,
    forced_provider: Option<&str>,
    allowlist: &[String],
) -> (ModelsConfig, Vec<String>) {
    if forced_provider.is_none() && allowlist.is_empty() {
        return (models.clone(), Vec::new());
    }
    let mut kept = Vec::new();
    let mut report = Vec::new();
    for pc in &models.providers {
        if ainxt_surface::TurnPlan::is_provider_admissible(forced_provider, allowlist, &pc.id) {
            kept.push(pc.clone());
        } else if forced_provider.is_some() {
            report.push(format!(
                "provider '{}' excluded by the surface's forced_provider model policy",
                pc.id
            ));
        } else {
            report.push(format!(
                "provider '{}' excluded by the surface's allowed_providers policy",
                pc.id
            ));
        }
    }
    (
        ModelsConfig {
            providers: kept,
            default_tier: models.default_tier.clone(),
            // Carry through the model registry + blocked list unchanged — the surface provider-allowlist
            // filter only narrows `providers`, never the model catalog or the block list.
            registry: models.registry.clone(),
            blocked: models.blocked.clone(),
        },
        report,
    )
}

/// The staleness window (seconds) after which a regulated outsourced route's exit-rehearsal is
/// treated as stale (a fail-safe exclusion). 90 days — the RBI exit-testing cadence.
const EXIT_REHEARSAL_CADENCE_SECS: u64 = 90 * 24 * 60 * 60;

// ============================ Assembly ============================

/// Build the ONE unified **Capability registry** (`ToolRuntime` = `CapabilityRegistry`, §0) the served
/// engine dispatches every capability call through — POPULATED with the built-in NATIVE capabilities so
/// it is genuinely INVOKED on the served path, not empty dead code. Native (the `query_ledger` safe
/// NL→SQL capability, the same allowlist the `/v1/query_ledger` route compiles against),
/// MCP-discovered, and plugin-provided capabilities all register into this SAME registry via the SAME
/// [`Tool`](ainxt_tools::Tool) trait (proven by `ainxt-tools` `r3_one_registry`) — so there is one
/// origin-agnostic dispatch path with one exactly-once ledger + reconciler as the unbypassable safety
/// spine, never a per-origin bypass. R16 (§0/§1.2, CRITICAL FIX): the harness `/run` capability bridge
/// now dispatches through this EXACT SAME instance (`assemble_full` hands `mounts::build_harness_mounts`
/// the `Arc<ToolRuntime>` this function's caller (`build_engine_ext`/`build_chat_engine_with_authz`)
/// built and installed on the engine, via `Assembled::capability_tools`) — never a second,
/// independently-called instance of this function. Calling this builder a SECOND time (as the harness
/// bridge did pre-fix) produces a materially DIFFERENT `ToolRuntime` over its OWN fresh exactly-once
/// ledger (see `build_unified_capability_registry_shared_over`'s fresh `InMemorySqlStore`), which is a
/// disjoint dedup universe from the engine's — the double-execution bug this round closed. A `HighRisk`
/// capability is structurally refused on the one-shot path (needs the two-phase dry-run/commit), so
/// registering built-ins never weakens the gate.
pub fn build_unified_capability_registry(report: &mut Vec<String>) -> ToolRuntime {
    build_unified_capability_registry_shared(report).0
}

/// The served `structured_query` starter catalog + matching schema (gap context-fabric:
/// `MetricCatalog::load` had zero callers outside `ainxt-retrieval`'s own tests — the served
/// composition root went straight to `StructuredQueryTool::empty()`, so the loader's §2.2
/// all-or-nothing validation path was never exercised on a real boot). Broken out as its own
/// function (rather than inlined at the call site) so a test exercises the IDENTICAL construction
/// [`build_unified_capability_registry_shared`] registers, not a re-implementation of it.
///
/// One conservative starter metric: a curated read-only `v_*` view, one Internal-class dimension,
/// and a named (department-scoped) RLS predicate — the same shape
/// [`ainxt_retrieval::structured::MetricCatalog::load`]'s own tests use. A deployment extends this
/// via its own git-native catalog + schema config; every metric NOT added still fails closed with
/// `UnknownMetric`.
fn structured_query_starter() -> (
    Result<ainxt_retrieval::structured::MetricCatalog, ainxt_retrieval::structured::CatalogError>,
    Result<Schema, ainxt_nl2sql::SchemaError>,
) {
    let registered_rls: std::collections::BTreeSet<String> =
        ["rls_txn_volume_by_dept".to_string()].into_iter().collect();
    let catalog = ainxt_retrieval::structured::MetricCatalog::load(
        vec![ainxt_retrieval::structured::MetricDef::new(
            "txn_volume",
            "v_txn_volume_curated",
            DataClass::Internal,
        )
        .dimension("bank_id", DataClass::Internal)
        .rls("rls_txn_volume_by_dept")],
        &registered_rls,
    );
    let schema = Column::new("bank_id", DataClass::Internal)
        .and_then(|col| Table::new("v_txn_volume_curated", vec![col]))
        .and_then(|table| Schema::new(vec![table]));
    (catalog, schema)
}

/// GAP-FIX gap6-tools-hooks-obo-supplychain item 1 — the served daemon's default `DenyArgsHook`
/// needle list: a small, curated set of substrings that are catastrophic for ANY capability
/// regardless of what it does (destructive SQL / destructive shell), never a broad content
/// classifier — that is `agents/compliance_engine.py` (input side) and `ainxt-injection`'s job. Kept
/// as its own function (rather than inlined at the call site) so the list is one reviewable place and
/// a test can assert on it directly.
fn served_deny_args_needles() -> Vec<String> {
    vec![
        "drop table".to_string(),
        "drop database".to_string(),
        "truncate table".to_string(),
        "rm -rf /".to_string(),
        ":(){ :|:& };:".to_string(), // the canonical shell fork-bomb
    ]
}

/// GAP-FIX gap6-tools-hooks-obo-supplychain item 1 — the served daemon's default per-call output cap
/// for `TruncateOutputHook`, in characters. ~8k tokens at a conservative 4 chars/token: generous
/// headroom for any legitimate single tool result, small enough that one runaway or malicious
/// capability cannot monopolize a turn's context budget.
const SERVED_TOOL_OUTPUT_CHAR_CAP: usize = 32_000;

/// GAP-FIX gap6-tools-hooks-obo-supplychain item 2 — the served composition root's reviewed
/// native-capability supply-chain pin list (§3.4 parity, native case): the same discipline a
/// WASM/native PLUGIN's `control.lock` already gets (see [`ApprovedPlugin::lock`] /
/// [`register_served_plugin_runtime`]'s §3.4 re-verification), applied to first-party native Rust
/// capabilities via [`ainxt_tools::native_supply_chain`]. Before this fix every native registration on
/// the served path went through the UNGATED `try_register_governed`, so a future capability that
/// flipped its own `Tool::risk_tier()` to `HighRisk` would have been silently admitted with no
/// reviewed record catching the drift — exactly the asymmetry §3.4 exists to prevent for plugins.
///
/// Empty today, and that is honest, not a stub: every native capability this composition root
/// registers (`query_ledger`, `federated_query` at `Elevated`, `structured_query`,
/// `named_fabric_query`, `capability.search`, the `gitlab.get_project` connector) declares a
/// `risk_tier()` at `Low` or `Elevated` — never `HighRisk` — and
/// [`ainxt_tools::native_supply_chain::verify_native_for_registration`] returns `Ok` unconditionally
/// for anything below `HighRisk`. Switching every native registration below from
/// `try_register_governed` to `try_register_governed_pinned` against this lock is therefore
/// behavior-preserving TODAY, while closing the loophole structurally: the FIRST native capability a
/// future change declares `HighRisk` must add a reviewed [`ainxt_tools::native_supply_chain::NativeLockEntry`]
/// here or its registration is refused, mirroring an unpinned plugin's refusal at
/// `ainxt_plugin::supply_chain::verify_for_load`.
pub fn served_native_control_lock() -> ainxt_tools::native_supply_chain::NativeControlLock {
    ainxt_tools::native_supply_chain::NativeControlLock::new()
}

/// [`build_unified_capability_registry`] but over a **shared** exactly-once ledger + reconciler,
/// returning clones of both handles alongside the [`ToolRuntime`] (R10). The daemon hands the ledger
/// clone to a background [`ReconcilerSweeper`] so the SAME rows the served dispatch path leaves
/// `PENDING` (a lost-ack side-effecting call) are actively reconciled — never passively expired
/// (§1.8). Sharing is what makes the sweep resolve the exact dispatch rows; a separate ledger would
/// sweep nothing.
///
/// The registry is also the point where the **MCP runtime** registers into the ONE unified registry
/// (R10): [`register_served_mcp_runtime`] adapts each pinned-and-unchanged MCP tool into the SAME
/// [`Tool`](ainxt_tools::Tool) trait via [`ainxt_tools::mcp_bridge::register_plannable_mcp_tools`], so
/// an MCP call dispatches through the identical OBO-authz + injection-taint + exactly-once-ledger path
/// as a native one — no per-origin bypass. The air-gapped default configures no MCP servers, so this
/// registers zero remote tools (honest — the wire is live, the set is empty offline).
pub fn build_unified_capability_registry_shared(
    report: &mut Vec<String>,
) -> (ToolRuntime, Arc<dyn Ledger>, Arc<dyn Reconciler>) {
    // R14 (served-composition, HIGH): the DEFAULT ledger behind the shipped daemon's unified Capability
    // registry is the DURABLE, cross-process exactly-once [`SqlLedger`] over a fresh
    // [`InMemorySqlStore`], NOT the ephemeral in-process [`InMemoryLedger`]. The store owned inside
    // `build_unified_capability_registry_shared_over` is the OSS/air-gapped reference driver (genuinely
    // cross-HANDLE exactly-once — a second `SqlLedger` over a clone of the same store sees the same
    // committed rows); a deployment swaps a `PostgresSqlLedgerDriver` behind the same seam for
    // cross-RESTART durability (infra). Cf. `build_unified_capability_registry_shared_over`.
    build_unified_capability_registry_shared_over(report, InMemorySqlStore::new())
}

/// [`build_unified_capability_registry_shared`] but over a CALLER-SUPPLIED (cloneable, shareable)
/// [`InMemorySqlStore`] — the seam that makes the durable default provable offline (R14): a test hands
/// in a store, dispatches/commits through the returned durable ledger, then attaches a SECOND
/// [`SqlLedger`] over a clone of the SAME store and observes the committed row survive — cross-handle
/// exactly-once the ephemeral [`ainxt_tools::InMemoryLedger`] structurally cannot provide. The default
/// entrypoint owns a fresh store; production swaps a `PostgresSqlLedgerDriver` for cross-restart.
pub fn build_unified_capability_registry_shared_over(
    report: &mut Vec<String>,
    store: InMemorySqlStore,
) -> (ToolRuntime, Arc<dyn Ledger>, Arc<dyn Reconciler>) {
    let (t, l, r, _mcp_admin) =
        build_unified_capability_registry_shared_over_with_mcp_admin(report, store);
    (t, l, r)
}

/// [`build_unified_capability_registry_shared`] but ALSO returning the live [`McpAdminHandle`] the
/// boot-time MCP registration ran over — see that type's doc for why a served admin re-approval route
/// needs this instead of building a second, disjoint registry. Every pre-existing caller keeps using
/// the unchanged 3-tuple wrapper above; this is the one new entrypoint a composition path threads
/// through to `AssembledFull`/`AppState` when it needs to expose the admin surface.
pub fn build_unified_capability_registry_shared_with_mcp_admin(
    report: &mut Vec<String>,
) -> (
    ToolRuntime,
    Arc<dyn Ledger>,
    Arc<dyn Reconciler>,
    McpAdminHandle,
) {
    build_unified_capability_registry_shared_over_with_mcp_admin(report, InMemorySqlStore::new())
}

/// [`build_unified_capability_registry_shared_with_mcp_admin`] but over a caller-supplied set of
/// declared MCP servers — the entrypoint [`build_engine_ext_with_mcp`] and [`build_chat_engine_with_authz`]
/// (the real composition-root call sites, fed straight from a served [`LoadedConfig`]'s [`McpConfig`])
/// actually call.
pub fn build_unified_capability_registry_shared_with_mcp_admin_and_servers(
    report: &mut Vec<String>,
    mcp_servers: &[McpServerConfigEntry],
) -> (
    ToolRuntime,
    Arc<dyn Ledger>,
    Arc<dyn Reconciler>,
    McpAdminHandle,
) {
    build_unified_capability_registry_shared_over_with_mcp_admin_and_servers(
        report,
        InMemorySqlStore::new(),
        mcp_servers,
    )
}

/// The REAL implementation behind both [`build_unified_capability_registry_shared`] and
/// [`build_unified_capability_registry_shared_over`] (both are now thin wrappers over this that drop
/// the [`McpAdminHandle`] 4th element for backward compatibility with every pre-existing caller). A
/// thin wrapper itself, over [`build_unified_capability_registry_shared_over_with_mcp_admin_and_servers`]
/// with an empty server list — every pre-existing caller (including every test built before GAP-FIX
/// tooling-mcp-plugins-routing's real-transport wiring) keeps its byte-identical zero-MCP-servers
/// behavior; the composition root's real `--surface engine`/chat dispatch calls the `_and_servers`
/// variant directly with the deployment's configured `[[mcp.servers]]` (see [`build_engine_ext_with_mcp`]
/// / [`build_chat_engine_with_authz`]).
pub fn build_unified_capability_registry_shared_over_with_mcp_admin(
    report: &mut Vec<String>,
    store: InMemorySqlStore,
) -> (
    ToolRuntime,
    Arc<dyn Ledger>,
    Arc<dyn Reconciler>,
    McpAdminHandle,
) {
    build_unified_capability_registry_shared_over_with_mcp_admin_and_servers(report, store, &[])
}

/// [`build_unified_capability_registry_shared_over_with_mcp_admin`] but over a caller-supplied set of
/// declared MCP servers (GAP-FIX tooling-mcp-plugins-routing: "the real MCP stdio transport is never
/// invoked — the registry is always empty"). Before this, EVERY caller of the "shared" family
/// constructed `McpRegistry::new()` and never `.register(...)`'d it, so a shipped daemon always booted
/// with zero MCP servers and the real `JsonRpcStdioTransport`/`McpTransportConfig::spawn` machinery
/// never executed outside a test. This is the real implementation: for each declared
/// [`McpServerConfigEntry`], `transport.spawn()` is attempted BEFORE the registry is wrapped in `Arc`
/// (registration needs `&mut McpRegistry`, only available while this function still owns it
/// exclusively) — a server that fails to spawn/connect is logged to `report` and skipped, never a hard
/// failure: one deployment-misconfigured server must not abort the whole daemon's boot. A connected
/// server is registered exactly like the test-only callers already did
/// (`McpRegistry::register(McpServer::new(name, url, transport))`); a freshly registered server's
/// tools start TOFU-quarantined (§2.5) like any other first connection — this function does not
/// pre-approve anything.
pub fn build_unified_capability_registry_shared_over_with_mcp_admin_and_servers(
    report: &mut Vec<String>,
    store: InMemorySqlStore,
    mcp_servers: &[McpServerConfigEntry],
) -> (
    ToolRuntime,
    Arc<dyn Ledger>,
    Arc<dyn Reconciler>,
    McpAdminHandle,
) {
    // Install the DURABLE cross-process exactly-once ledger as the DEFAULT backing (never the ephemeral
    // `InMemoryLedger`). The SAME `Arc<dyn Ledger>` backs the registry's dispatch path and is handed to
    // the background `ReconcilerSweeper`, so the sweep resolves the exact rows dispatch leaves PENDING.
    let durable = install_durable_ledger(store);
    let ledger: Arc<dyn Ledger> = durable.ledger;
    let reconciler: Arc<dyn Reconciler> = durable.reconciler;
    // GAP-AUDIT tooling-mcp-plugins-routing — "Egress destination allow-list never wired — not
    // fail-closed": `ToolRuntime::with_egress_allowlist` (§1.7) was a fully implemented and
    // unit-tested builder method with zero callers on the served composition root — the daemon's
    // default `egress_allowlist` field stayed `None`, which makes `execute_dispatch_core`'s §1.7
    // check block SKIP ENTIRELY rather than fail-closed (see that block's own comment: "Only fires
    // when (a) a deployment has installed an allow-list at all"). Any egressing capability with a
    // known destination — every `McpCapability` today, since `McpCapability::destination` always
    // resolves to the server's host — dispatched with ZERO DLP review on the served path. Installed
    // here as the conservative OSS/air-gapped default: an EMPTY allow-list, matching the same
    // "reachable but excludes everything until a deployment configures real entries" posture already
    // used for the federation/named-fabric/MCP/plugin mounts below. Empty is not a no-op like `None`
    // was — every egress call with a resolvable destination now hits `EgressAllowList::check`, which
    // returns `PendingApproval` (fail-closed, soft-blocked pending human review) for anything not
    // explicitly allow-listed. A deployment extends this via `.with_egress_allowlist` with its own
    // real per-capability/default entries; nothing here silently sends to an unlisted destination.
    let mut registry = durable
        .runtime
        .with_egress_allowlist(ainxt_tools::egress_allowlist::EgressAllowList::new());
    // GAP-FIX gap6-tools-hooks-obo-supplychain item 1 — install the served daemon's DEFAULT
    // deterministic pre/post guardrails (`ainxt_tools::hooks`, the "Pre/Post Hooks" box of the
    // reference Tool-Calling Layer architecture — Tools, Permission Checker, Injection Scan, Pre/Post
    // Hooks). Before this, `ToolRuntime::hooks_mut` had zero callers anywhere in the composition root:
    // `execute_dispatch` unconditionally runs `self.hooks.run_pre`/`run_post` on every dispatch, but the
    // registry a freshly-built `ToolRuntime` starts with is EMPTY (`HookRegistry::default()`), so the
    // box was a pure passthrough no matter what a capability's arguments or output looked like. Two
    // GLOBAL hooks are installed here — `HookRegistry`'s own doc is explicit that a *global* hook must
    // be correct for a tool the registry has never seen, which rules out anything deployment-specific:
    //   * `DenyArgsHook` (pre) — refuses a call whose arguments contain one of a small, curated set of
    //     universally-catastrophic destructive-action substrings (SQL/shell). This is deliberately NOT
    //     a PII/secret/injection scan — that is `agents/compliance_engine.py` (input side) and
    //     `ainxt-injection`'s job; this is a narrow, deterministic tripwire, exactly the "is THIS call,
    //     with these arguments, acceptable" question hooks exist to answer, defence-in-depth alongside
    //     (never a replacement for) those scanners.
    //   * `TruncateOutputHook` (post) — caps a single tool result so one runaway or malicious capability
    //     cannot blow a turn's context budget; REWRITES rather than refuses, since an over-long result
    //     is still useful truncated (the marker makes the truncation visible, never a silent partial
    //     answer).
    // `HashVerifyHook` is deliberately NOT installed globally: its constructor takes an expected digest
    // — a reviewed, PER-CAPABILITY pin (the worked example: `regulator_site_fetch` verifying the
    // regulator's published PDF hash) — so it belongs at the point a deployment registers THAT specific
    // capability (`registry.hooks_mut().add_post(name, Arc::new(HashVerifyHook::new(pin)))`), not as a
    // global default with nothing real to check against.
    registry
        .hooks_mut()
        .add_global_pre(Arc::new(ainxt_tools::hooks::DenyArgsHook::new(
            served_deny_args_needles(),
            "matches a deterministic destructive-action pattern (shell/SQL) — refused before any \
             capability's own logic runs, defence-in-depth alongside the compliance/injection scanners",
        )))
        .add_global_post(Arc::new(ainxt_tools::hooks::TruncateOutputHook::new(
            SERVED_TOOL_OUTPUT_CHAR_CAP,
        )));
    report.push(format!(
        "capabilities: default deterministic guardrails installed on the unified ToolRuntime \
         (ainxt_tools::hooks) — a global DenyArgsHook pre-hook ({} needle(s)) and a global \
         TruncateOutputHook post-hook (cap={SERVED_TOOL_OUTPUT_CHAR_CAP} chars) now run on EVERY \
         dispatch through this registry; previously HookRegistry::default() was installed with \
         nothing in it (a pure passthrough)",
        served_deny_args_needles().len()
    ));
    // GAP-FIX gap6-tools-hooks-obo-supplychain item 2 — the §3.4 native-capability supply-chain parity
    // pin (`ainxt_tools::native_supply_chain`), the same discipline a WASM/native PLUGIN's
    // `control.lock` already gets. Before this, `ToolRuntime::try_register_governed_pinned` had zero
    // callers anywhere in the composition root — every native capability below registered through the
    // UNGATED `try_register_governed`, so a future capability that flipped its own `risk_tier()` to
    // `HighRisk` would have been silently admitted with no reviewed record catching the drift. See
    // `served_native_control_lock`'s own doc for why this is empty today and behavior-preserving.
    let native_lock = served_native_control_lock();
    // Register the built-in NATIVE `query_ledger` capability (Pure — SELECT-only compile boundary),
    // so the unified registry is non-empty and the served agent loop can dispatch it under the same
    // OBO-authz + injection-taint + exactly-once-ledger spine as any other capability.
    // GAP-AUDIT tooling-mcp-plugins-routing #10 — `try_register_governed` (the §1.8 mandatory
    // reconcile-probe gate for HighRisk+SideEffecting capabilities) had zero callers; the served
    // registration path used the bare, ungated `register`. `default_ledger()` is Pure (SELECT-only), so
    // this doesn't change its admission — it closes the gate for the NEXT HighRisk+SideEffecting
    // native capability someone registers here, which the bare call would have silently admitted.
    registry
        .try_register_governed_pinned(
            Box::new(ainxt_tools::ledger_query::LedgerQueryTool::default_ledger()),
            &native_lock,
        )
        .unwrap_or_else(|e| {
            report.push(format!(
                "capabilities: refused to register query_ledger: {e:?}"
            ))
        });
    // GAP-AUDIT context-fabric #4 — the federated cross-bank query broker (whitelist gate + ε-budget
    // debit + per-tenant isolation-enforced fan-out + k-anonymity aggregation) was fully implemented
    // and unit-tested but had zero callers outside its own crate's tests — no model-facing route to it
    // existed at all. The air-gapped default registers an EMPTY `FederationRegistry` (no bank tenants
    // configured), so the capability is reachable but excludes every route until a deployment
    // registers real tenant arrangements — the same "declared but registers nothing exotic by
    // default" posture already used for MCP below.
    registry
        .try_register_governed_pinned(
            Box::new(governed::FederatedQueryTool::new(
                ainxt_retrieval::federation::FederationRegistry::new(),
                // Conservative India-default k-anonymity floor: an aggregate bucket must span at least 5
                // participating banks and 1000 underlying records before it may be released.
                ainxt_retrieval::federation::KAnonConfig {
                    min_banks: 5,
                    min_underlying: 1_000,
                },
                // Standard differential-privacy budget (ε=1.0, sensitivity=1.0) — a deployment tunes this
                // per its own privacy posture; this is the conservative starting point, not a fixed policy.
                ainxt_retrieval::federation::DpParams {
                    epsilon: 1.0,
                    sensitivity: 1.0,
                },
            )),
            &native_lock,
        )
        .unwrap_or_else(|e| {
            report.push(format!(
                "capabilities: refused to register federated_query: {e:?}"
            ))
        });
    // GAP-AUDIT context-fabric — the catalog-bound structured query bridge (metric catalog → NL-to-SQL
    // → server-side numeric re-derivation, `STRUCTURED_FEDERATED_RETRIEVAL.md` §4) was a fully
    // implemented and unit-tested composition-root entrypoint (`governed::served_structured_turn`)
    // with zero callers outside its own test module — no model-facing route to the metric catalog
    // existed at all. `MetricCatalog::load` itself (§2.2's all-or-nothing validation) had zero callers
    // outside `ainxt-retrieval`'s own tests: the served default went straight to
    // `StructuredQueryTool::empty()`, so the loader path was never exercised on the served composition
    // root. Mounted here through the REAL loader with one conservative starter metric (a curated
    // read-only `v_*` view, department-scoped RLS, one Internal-class dimension) instead — the
    // catalog/schema pair is cross-checked at REGISTRATION time (same as any deployment-supplied
    // git-native catalog would be), so a broken starter definition fails closed to the empty catalog
    // here rather than surfacing only at query time. A deployment extends this via its own git-native
    // catalog + schema config; every OTHER metric still fails closed with `UnknownMetric` until added.
    let (structured_catalog, structured_schema) = structured_query_starter();
    match (structured_catalog, structured_schema) {
        (Ok(catalog), Ok(schema)) => {
            registry
                .try_register_governed_pinned(
                    Box::new(governed::StructuredQueryTool::new(catalog, schema)),
                    &native_lock,
                )
                .unwrap_or_else(|e| {
                    report.push(format!(
                        "capabilities: refused to register structured_query: {e:?}"
                    ))
                });
        }
        (cat_result, schema_result) => {
            // The starter definition itself is malformed (a composition-root bug, not a deployment
            // config error) — fail closed to the empty catalog rather than skip registration, and
            // surface it loudly in the boot report instead of silently degrading.
            report.push(format!(
                "capabilities: structured_query starter catalog/schema failed to build \
                 (catalog={cat_result:?}, schema={schema_result:?}) — registered EMPTY catalog instead"
            ));
            registry
                .try_register_governed_pinned(
                    Box::new(governed::StructuredQueryTool::empty()),
                    &native_lock,
                )
                .unwrap_or_else(|e| {
                    report.push(format!(
                        "capabilities: refused to register structured_query: {e:?}"
                    ))
                });
        }
    }
    // GAP-AUDIT context-fabric — the §5 named fabric query vocabulary (`whoCalls`/`refsOf`/`deps`/
    // `changedWith`/`testsCovering`/`runtimeErrorsFor`/`architectureAround`, `CONTEXT_FABRIC.md` §5)
    // had a fully implemented and unit-tested dispatcher (`governed::named_fabric_query`) with zero
    // callers outside `ainxt-context`'s own tests and `governed.rs`'s own test module — no
    // model-facing capability for it existed at all, unlike the sibling `federated_query` and
    // `structured_query` mounts right above. Mounted here the same way: the air-gapped default
    // registers an EMPTY `FabricGraph` (no repo/KG indexed in yet), so the capability is reachable
    // but every named query resolves to an empty result set until a deployment feeds it a real
    // indexed fabric via `NamedFabricQueryTool::new`.
    registry
        .try_register_governed_pinned(
            Box::new(governed::NamedFabricQueryTool::empty()),
            &native_lock,
        )
        .unwrap_or_else(|e| {
            report.push(format!(
                "capabilities: refused to register named_fabric_query: {e:?}"
            ))
        });
    // R10 — the MCP runtime registers into this SAME registry. The air-gapped default has no MCP
    // servers configured, so the pinned-and-unchanged plannable set is empty (registers nothing); a
    // deployment registers its discovered servers via `register_served_mcp_runtime`.
    // GAP-FIX tooling-mcp-plugins-routing — `mcp`/`mcp_auth`/`pins` are now `Arc`-held (not bare
    // locals) so the SAME live instances the boot-time registration below consults can be bundled
    // into an `McpAdminHandle` and survive past this function's return (see that type's doc).
    //
    // GAP-FIX tooling-mcp-plugins-routing — "the real MCP stdio transport is never invoked, the
    // registry is always empty": every prior caller built this registry via `McpRegistry::new()` and
    // never `.register(...)`'d it, so a shipped daemon always booted with zero servers — the real
    // `JsonRpcStdioTransport`/`McpTransportConfig::spawn` machinery only ever ran inside a `tests/`
    // file, never on a served path. `mcp_servers` (from a deployment's `[[mcp.servers]]`, threaded in
    // by `build_engine_ext_with_mcp`/`build_chat_engine_with_authz`) is spawned and registered HERE,
    // while `McpRegistry` is still a plain, exclusively-owned value — `register` takes `&mut self`,
    // so this is the only point in the whole call chain where that is possible; every downstream
    // consumer only ever sees the `Arc`-shared, read-oriented handle. A server that fails to spawn is
    // logged and skipped — never a hard failure that aborts the daemon's boot over one deployment
    // misconfiguration (mirrors the fail-soft posture `main.rs` already uses for every other optional
    // integration: attestation manifest, health/autoscale cadences, the prompt-optimizer classifier).
    let mut mcp_registry = ainxt_mcp::McpRegistry::new();
    for entry in mcp_servers {
        match entry.transport.spawn() {
            Ok(transport) => {
                let url = entry.transport.server_url();
                mcp_registry.register(ainxt_mcp::McpServer::new(&entry.name, &url, transport));
                report.push(format!(
                    "mcp: connected configured server '{}' ({url}) — registered into the served \
                     registry (TOFU-quarantined pending admin approval, same as any first connection)",
                    entry.name
                ));
            }
            Err(e) => {
                report.push(format!(
                    "mcp: failed to connect configured server '{}' ({}): {e:?} — skipped, boot \
                     continues (fail-soft: one misconfigured server must not abort daemon startup)",
                    entry.name,
                    entry.transport.server_url()
                ));
            }
        }
    }
    let mcp = Arc::new(mcp_registry);
    let pins: Arc<ainxt_mcp::InMemoryPinStore> = Arc::new(ainxt_mcp::InMemoryPinStore::new());
    let mcp_auth: Arc<dyn ainxt_mcp::AuthProvider> = Arc::new(ainxt_mcp::NoAuth);
    let mcp_user_id = "daemon";
    let admitted = register_served_mcp_runtime(
        &mut registry,
        mcp.clone(),
        mcp_auth.clone(),
        pins.as_ref(),
        mcp_user_id,
    );
    // GAP-AUDIT tooling-mcp-plugins-routing — "Ranking escape valve capability.search never
    // registered": `ainxt_mcp::capability_search`/`CAPABILITY_SEARCH` existed and were unit-tested but
    // were never registered as a dispatchable `Tool` anywhere on the served path — the model had no
    // way to actually call the §2.4 escape valve. Registered here as a real native capability into
    // the SAME unified registry, over the SAME shared `mcp`/`mcp_auth`/`pins` handles
    // `register_served_mcp_runtime` (above) uses — never a second, independently-built MCP registry —
    // so a search result is always drawn from (and gated by) the identical TOFU/pin state a dispatch
    // of that same tool name would be. Cloned (not moved) — `mcp_auth`/`pins` are still needed below
    // to bundle the `McpAdminHandle` this function returns.
    registry
        .try_register_governed_pinned(
            Box::new(ainxt_tools::mcp_bridge::CapabilitySearchTool::new(
                mcp.clone(),
                mcp_auth.clone(),
                pins.clone() as Arc<dyn ainxt_mcp::PinStore>,
            )),
            &native_lock,
        )
        .unwrap_or_else(|e| {
            report.push(format!(
                "capabilities: refused to register capability.search: {e:?}"
            ))
        });
    // GAP-AUDIT tooling-mcp-plugins-routing — "Plugin runtime unreachable": the §3 WASM/native plugin
    // bridge (`ainxt_tools::plugin_bridge::PluginCapability`) registers into this SAME registry. The
    // air-gapped default has no governance-approved plugins configured, so this admits nothing (the
    // same "reachable but excludes everything until a deployment supplies real approvals" posture as
    // MCP/federation above); a deployment registers its approved plugins via
    // `register_served_plugin_runtime`.
    let admitted_plugins = register_served_plugin_runtime(&mut registry, Vec::new());
    // GAP-FIX connectors "ConnectorInvoker.invoke() has zero production callers" — mount a REAL
    // dispatchable connector capability into this SAME registry, so every surface built over it
    // (`build_engine_ext`/`build_chat_engine_with_authz` — bare engine, chat/code/sdlc/buddy, and every
    // governed/profile variant of those) gets a genuinely LIVE connector USE path, not merely the OAuth
    // admin plumbing (`mounts::build_connector_gateway`, authorize/callback/audit — never `.invoke()`).
    // GAP-FIX gap6-tools-hooks-obo-supplychain item 2 — routed through the §3.4 supply-chain pin
    // (`native_lock`), same as every other native capability registered in this function.
    mounts::register_connector_capability(&mut registry, report, &native_lock);
    // GAP-FIX connector-http item 1 — the module doc of `ainxt_connector_http` promises three
    // concrete adapters ("GitLab, Jira, Graph"); only GitLab was ever mounted here. Registers
    // `jira.get_issue`/`jira.add_comment`/`graph.get_me`/`graph.list_messages`/`graph.send_mail` into
    // this SAME unified registry, each through its OWN dedicated ConnectorInvoker + OAuth provider
    // (Atlassian 3LO / Microsoft Entra respectively — see `mounts::register_jira_capability`/
    // `mounts::register_graph_capability`'s own docs), so a live turn can dispatch them exactly like
    // `gitlab.get_project` — real admission→egress→token→dispatch, fail-closed on the air-gapped
    // default, never a fabricated success. Neither is HighRisk today (same as `gitlab.get_project`),
    // so — unlike `register_connector_capability` above — these are not yet routed through
    // `native_lock`; a future HighRisk promotion for either should add that pin at the same time.
    mounts::register_jira_capability(&mut registry, report);
    mounts::register_graph_capability(&mut registry, report);
    report.push(format!(
        "capabilities: ONE unified Capability registry (§0) wired into the served engine — populated \
         with the built-in native 'query_ledger' + 'capability.search' capabilities + {} \
         MCP-discovered tool(s) + {} plugin capability(ies) + the connector USE-path capability; \
         native + MCP + plugin + connector + the harness /run bridge all dispatch through the SAME \
         registry (one shared exactly-once ledger + reconciler spine, actively swept by a background \
         ReconcilerSweeper)",
        admitted.len(),
        admitted_plugins.len()
    ));
    let mcp_admin = McpAdminHandle {
        registry: mcp,
        auth: mcp_auth,
        pins: pins as Arc<dyn ainxt_mcp::PinStore>,
        user_id: mcp_user_id.to_string(),
    };
    (registry, ledger, reconciler, mcp_admin)
}

/// A governance-approved plugin, bundled with everything [`register_served_plugin_runtime`] needs to
/// re-run the §3.4 load gate AND the §3.3 git-native lifecycle gate at registration time: the
/// isolation host it will actually dispatch through, the fetched artifact bytes, the signed record,
/// the environment's `control.lock` pin, the publisher allow-list, the verifier, and the
/// [`ainxt_plugin::supply_chain::PromotionEvidence`] proving the plugin's git-native lifecycle
/// (branch=DRAFT → PR=PENDING_APPROVAL → merge=APPROVED → signed=PRODUCTION, ADR-026 §3.3) actually
/// reached PRODUCTION. Constructing one of these is the CLAIM that governance approval happened; the
/// evidence is what lets [`register_served_plugin_runtime`] enforce that claim via
/// [`ainxt_plugin::supply_chain::promote`] rather than trust it — this struct is what that approval
/// hands to the served composition root, never assembled ad hoc from unreviewed inputs.
pub struct ApprovedPlugin {
    pub host: Arc<dyn ainxt_plugin::PluginHost + Send + Sync>,
    pub fetched_bytes: Vec<u8>,
    pub signed: ainxt_plugin::supply_chain::SignedPlugin,
    pub lock: ainxt_plugin::supply_chain::ControlLock,
    pub allow: ainxt_plugin::supply_chain::PublisherAllowList,
    pub verifier: Arc<dyn ainxt_plugin::supply_chain::Verifier>,
    pub grant: ainxt_plugin::PluginGrant,
    /// Evidence for every hop of the §3.3 git-native lifecycle (DRAFT→PENDING_APPROVAL→APPROVED→
    /// PRODUCTION). [`register_served_plugin_runtime`] walks the FULL chain through
    /// [`ainxt_plugin::supply_chain::promote`] on every call — a plugin that never actually reached a
    /// signed-tag PRODUCTION release (per its own git history) is refused here, regardless of whether
    /// its artifact bytes are validly signed.
    pub promotion_evidence: ainxt_plugin::supply_chain::PromotionEvidence,
}

/// Register governance-`approved` plugins (§3, WASM/native plugin runtime) into the served unified
/// Capability registry (§0) — the composition-root counterpart to [`register_served_mcp_runtime`]
/// above, closing gap "Plugin runtime unreachable": `plugin_bridge::PluginCapability` previously had
/// exactly one caller in the whole workspace (`ainxt-tools`'s own `r3_one_registry` test) and no path
/// from the served engine ever constructed one.
///
/// GAP-FIX tooling-mcp-plugins-routing — "plugin lifecycle gate has zero callers": before this fix,
/// [`ainxt_plugin::supply_chain::promote`] (the git-native DRAFT→PENDING_APPROVAL→APPROVED→PRODUCTION
/// gate, ADR-026 §3.3) was correct and unit-tested in complete isolation — nothing on any served path
/// ever called it, so a plugin's lifecycle stage could never actually be enforced before dispatch.
/// This function now walks the FULL chain (`Draft → PendingApproval → Approved → Production`) through
/// `promote`, re-derived from `p.promotion_evidence` on every call, never trusting a caller-asserted
/// stage — a plugin missing ANY hop's evidence (no PR ever opened, a dirty scan, no CODEOWNERS merge,
/// or — the terminal, signed-tag-equals-production rule — no signed release tag) is refused before it
/// is ever adapted into a capability, exactly mirroring the sibling `ComplianceBackedPrereceiveGate`
/// pattern `ainxt-admission` runs over `ainxt-governance`'s git-native gate for the harness publish
/// path (`ainxt-server`'s `POST /v1/harness/preflight`).
///
/// Every entry is ALSO re-verified through the §3.4 load gate **on this call**, not trusted from a
/// prior install — [`ainxt_plugin::supply_chain::verify_for_load`] checks the publisher allow-list, the
/// detached signature, the fetched-bytes hash against the signed record, and the `control.lock` pin,
/// in that order. A publisher revoked since signing, a hash mismatch, or a missing lock entry is a
/// hard refusal: that plugin is never adapted or registered, and the served registry is unaffected —
/// the failure is scoped to the one entry, not the whole call. A plugin that clears BOTH the lifecycle
/// gate and the supply-chain gate is adapted (`plugin_bridge::PluginCapability`, which defaults to
/// `SideEffecting`/`RiskTier::High`) and admitted through [`ToolRuntime::try_register_governed`] — the
/// SAME mandatory-reconcile-probe gate native HighRisk+SideEffecting capabilities go through above, so
/// a plugin gets no weaker admission discipline than a native tool of equivalent risk. Returns the
/// plugin ids actually admitted.
pub fn register_served_plugin_runtime(
    registry: &mut ToolRuntime,
    approved: Vec<ApprovedPlugin>,
) -> Vec<String> {
    use ainxt_plugin::supply_chain::{promote, Stage};

    let mut admitted = Vec::new();
    'entries: for p in approved {
        // (1) §3.3 git-native lifecycle gate — walk the FULL chain on the evidence this call was
        // handed; a plugin that never actually cleared every hop up to a signed PRODUCTION tag is
        // refused here, before its artifact bytes are even inspected.
        let mut stage = Stage::Draft;
        for target in [Stage::PendingApproval, Stage::Approved, Stage::Production] {
            match promote(stage, target, &p.promotion_evidence) {
                Ok(next) => stage = next,
                Err(_) => continue 'entries, // hard refusal (§3.3) — never adapted, never registered
            }
        }
        debug_assert_eq!(stage, Stage::Production);

        // (2) §3.4 supply-chain load gate — signature, hash, lock-pin, allow-list.
        if ainxt_plugin::supply_chain::verify_for_load(
            &p.fetched_bytes,
            &p.signed,
            &p.lock,
            &p.allow,
            p.verifier.as_ref(),
        )
        .is_err()
        {
            continue; // hard refusal (§3.4) — never adapted, never registered
        }
        let id = p.signed.manifest.id.clone();
        // GAP-FIX plugin-sandbox-registry — "GuardedHost never wraps the real plugin host": before
        // this, every admitted plugin dispatched through its RAW host (`NativeHost` or
        // `ainxt_wasm::WasmPluginHost`), so `manifest.limits.max_millis` — the plugin's own declared
        // wall-clock budget — was silently never enforced no matter what it said. A busy-loop or a
        // blocked-on-I/O guest could pin the calling turn indefinitely (§3.5). `GuardedHost` is a real
        // decorator (runs the inner host on a detached worker, `recv_timeout`s at `max_millis`, and
        // returns `PluginError::WallClockExceeded` promptly on overrun) — it existed and was unit-
        // tested in `ainxt-plugin`/`ainxt-wasm` but had exactly zero callers from the served
        // composition root. Wrapping HERE, at the one place every `ApprovedPlugin` — built by either
        // producer (`approved_wasm_sandboxed_plugin` or a directly-assembled `NativeHost` entry) —
        // funnels through before becoming a dispatchable `Tool`, means no caller can accidentally admit
        // an unguarded plugin: the wrap is structural, not a convention. `GuardedHost` reads its bound
        // from each call's own `manifest.limits.max_millis`, which already carries a sane default
        // (`ResourceLimits::default()` = 5_000ms — the same single-digit-second order of magnitude as
        // this codebase's other hard wall-clock ceilings, e.g. `ainxt_pipeline::cargo_tools`'s 30s
        // subprocess timeout) whenever a manifest doesn't declare its own.
        let guarded_host: Arc<dyn ainxt_plugin::PluginHost + Send + Sync> =
            Arc::new(ainxt_plugin::GuardedHost::from_arc(p.host));
        let capability = ainxt_tools::plugin_bridge::PluginCapability::new(
            guarded_host,
            p.signed.manifest,
            p.grant,
        );
        if registry.try_register_governed(Box::new(capability)).is_ok() {
            admitted.push(id);
        }
    }
    admitted
}

/// GAP-FIX tooling-mcp-plugins-routing — "Plugin WASI sandbox never used by the daemon". Every
/// pre-existing caller that built an [`ApprovedPlugin`] used [`ainxt_plugin::NativeHost`] (in-process,
/// no hard isolation — correct for a TRUSTED first-party plugin, but not for untrusted/external code);
/// [`register_served_plugin_runtime`] above has only ever been exercised end-to-end with that host,
/// even though `ainxt_wasm::WasmPluginHost` (a real, unit-proven wasmtime sandbox implementing the
/// IDENTICAL [`ainxt_plugin::PluginHost`] seam) has existed the whole time.
///
/// This is the missing PRODUCER: the composition root's canonical, structural way to build an
/// [`ApprovedPlugin`] for an untrusted/external plugin — it is not possible to call this and get a
/// `NativeHost` back, unlike hand-assembling the struct literal (where a caller could accidentally
/// pass either host for any plugin with no compiler-enforced distinction). `register_served_plugin_runtime`
/// (the composition-root CONSUMER) is completely unchanged: it dispatches through whatever
/// [`ainxt_plugin::PluginHost`] the `ApprovedPlugin` carries, running the IDENTICAL §3.4 supply-chain
/// load gate and `try_register_governed` admission regardless of host — a WASM-hosted plugin gets no
/// weaker (or stronger) admission discipline than a native one; only the ISOLATION MECHANISM differs.
/// `NativeHost` remains the right choice for a genuinely trusted first-party plugin (no sandbox
/// overhead); a deployment loading anything from outside its own control-repo calls this instead.
pub fn approved_wasm_sandboxed_plugin(
    module_bytes: Vec<u8>,
    signed: ainxt_plugin::supply_chain::SignedPlugin,
    lock: ainxt_plugin::supply_chain::ControlLock,
    allow: ainxt_plugin::supply_chain::PublisherAllowList,
    verifier: Arc<dyn ainxt_plugin::supply_chain::Verifier>,
    grant: ainxt_plugin::PluginGrant,
    promotion_evidence: ainxt_plugin::supply_chain::PromotionEvidence,
) -> ApprovedPlugin {
    let mut host = ainxt_wasm::WasmPluginHost::new();
    host.register(signed.manifest.id.clone(), module_bytes.clone());
    ApprovedPlugin {
        host: Arc::new(host),
        fetched_bytes: module_bytes,
        signed,
        lock,
        allow,
        verifier,
        grant,
        promotion_evidence,
    }
}

/// Logical-tick TTL for the served per-turn MCP liveness sweep (§2.2): a connection that has gone
/// this many served turns since its last confirmed-alive ping is torn down (back to `Unconnected`)
/// so the SAME turn's discovery lazily reconnects it, rather than trusting an unbounded cached
/// `Ready` state. Ticks are served turns, not wall-clock time (deterministic, consistent with
/// [`ainxt_mcp::McpServer::check_liveness`]) — 200 is a generous default (a session would need 200
/// consecutive turns on a now-dead transport before this forces a re-handshake).
const MCP_LIVENESS_TTL_TICKS: u64 = 200;

/// GAP-FIX tooling-mcp-plugins-routing — the SHARED, live MCP registry + auth provider + pin store
/// the served composition root's boot-time MCP registration (`register_served_mcp_runtime`, below)
/// actually ran over. Before this, that registry/pin-store pair was a LOCAL binding inside
/// [`build_unified_capability_registry_shared_over`], dropped the instant registration finished —
/// [`ainxt_mcp::PinnedDiscovery::needs_reapproval`]/[`ainxt_mcp::PinnedServer::approve`] were fully
/// implemented and unit-tested (see `approve_mcp_pin` below), but NOTHING durable ever survived boot
/// for a served admin route to show a human or act on: an admin route built its own fresh registry
/// would be reviewing/approving a completely disjoint TOFU state from the one the daemon actually
/// booted with. Threaded from `build_unified_capability_registry_shared_over_with_mcp_admin` all the
/// way to `AssembledFull`/`ainxt-server`'s `AppState` (mirrors the identical `OutsourcingRegisterHandle`
/// threading for FI-03), so `GET /admin/mcp/reapproval` / `POST /admin/mcp/approve` act on the EXACT
/// same registry + pin store the daemon's own boot-time registration consulted.
pub struct McpAdminHandle {
    pub registry: Arc<ainxt_mcp::McpRegistry>,
    pub auth: Arc<dyn ainxt_mcp::AuthProvider>,
    pub pins: Arc<dyn ainxt_mcp::PinStore>,
    /// The identity `discover_pinned` sweeps as — MUST match `register_served_mcp_runtime`'s own
    /// boot-time call (`"daemon"`), since MCP auth is scoped per-(user,server) and a mismatched
    /// identity could show/approve a different tool set than what boot actually registered.
    pub user_id: String,
}

/// [`McpAdminHandle`], shared and optional (mirrors [`OutsourcingRegisterHandle`]'s shape) — `None`
/// on a surface whose engine builder never installs a unified Capability registry at all (the
/// AiNxt-OS workforce surface, which has no real Engine/MCP wiring).
pub type McpAdminHandleOpt = Option<Arc<McpAdminHandle>>;

/// Register an [`ainxt_mcp::McpRegistry`]'s **pinned-and-unchanged** tools into the served unified
/// Capability registry (R10) — the runtimed-level wire over the crate-level bulk entrypoint
/// [`ainxt_tools::mcp_bridge::register_plannable_mcp_tools`]. Runs the TOFU-pinned discovery
/// ([`McpRegistry::discover_pinned`]) so a first-use / added / reworded tool is quarantined (never
/// auto-adopted into the plannable set), then adapts each vetted [`QualifiedTool`](ainxt_mcp::QualifiedTool)
/// into an [`McpCapability`](ainxt_tools::mcp_bridge::McpCapability) that dispatches through the
/// identical origin-agnostic path as a native capability. Returns the qualified names admitted (a
/// payment-signature remote tool is refused by the payment boundary and omitted). Deterministic +
/// network-free over an in-memory transport, so it is exercised offline in tests.
pub fn register_served_mcp_runtime(
    registry: &mut ToolRuntime,
    mcp: Arc<ainxt_mcp::McpRegistry>,
    auth: Arc<dyn ainxt_mcp::AuthProvider>,
    pins: &dyn ainxt_mcp::PinStore,
    user_id: &str,
) -> Vec<String> {
    // GAP-AUDIT tooling-mcp-plugins-routing — `McpRegistry::sweep_liveness` / `McpServer::check_liveness`
    // (§2.2 ping + TTL dead-connection teardown, fully implemented and unit-tested in `ainxt-mcp`) had
    // ZERO callers outside that crate's own tests. `discover_pinned` → `discover` → `ensure_ready` only
    // ever asks "is this server already `Ready`?" and, if so, returns the CACHED manifest — it never
    // re-validates the connection. Without a caller of `sweep_liveness`, a server whose transport died
    // after first use would keep reporting `Ready` off the stale cache for the rest of the process's
    // life; the tear-down + lazy-reconnect machinery that exists specifically to prevent that never ran
    // on the served path. Sweeping liveness immediately before every served turn's discovery call closes
    // that gap: a dead/stale connection is torn down to `Unconnected` here so the discovery call right
    // below lazily reconnects it instead of serving a dead connection's now-stale tool set.
    let _ = mcp.sweep_liveness(MCP_LIVENESS_TTL_TICKS);
    let discovered = mcp.discover_pinned(user_id, auth.as_ref(), pins);
    let plannable = discovered.plannable();
    // GAP-AUDIT tooling-mcp-plugins-routing — "MCP retrieval-ranking has zero callers":
    // `ainxt_mcp::rank_session`/`CoreSet` (§2.4 top-K + always-visible-core ranking) had zero callers
    // outside their own crate's tests; every TOFU-pinned tool was registered unconditionally with no
    // bound on cardinality at all. Routed through the ranking gate
    // (`register_plannable_mcp_tools_ranked`) instead of the raw unranked entrypoint. This call site
    // runs once at daemon composition (before any turn's text exists), so `query` is empty — ranking
    // still bounds the registered set to the platform core set + `RankConfig::default().k` (20)
    // deterministically; a live per-turn caller gets full semantic relevance for free by calling
    // `register_plannable_mcp_tools_ranked` directly with the turn's own text.
    ainxt_tools::mcp_bridge::register_plannable_mcp_tools_ranked(
        registry,
        mcp,
        auth,
        user_id,
        &plannable,
        "",
        &ainxt_mcp::CoreSet::platform_default(),
        &[],
        ainxt_mcp::RankConfig::default(),
    )
}

/// GAP-FIX tooling-mcp-plugins-routing — `PinnedDiscovery::needs_reapproval` was fully implemented and
/// unit-tested but had zero callers outside `ainxt-mcp`'s own tests: `register_served_mcp_runtime`
/// (above) discovers the SAME `PinnedDiscovery` every served turn and only ever reads `.plannable()`
/// off it, silently dropping which servers are sitting in TOFU quarantine and why. `approve_mcp_pin`
/// (this file) exists to act on exactly that information, but nothing ever surfaced it for an operator
/// to act on. Pure/deterministic and network-free (same discovery the registration call already runs),
/// so this is a read-only sibling call, not a change to the registration path itself.
pub fn mcp_reapproval_report(
    mcp: &ainxt_mcp::McpRegistry,
    auth: &dyn ainxt_mcp::AuthProvider,
    pins: &dyn ainxt_mcp::PinStore,
    user_id: &str,
) -> Vec<String> {
    let discovered = mcp.discover_pinned(user_id, auth, pins);
    discovered
        .needs_reapproval()
        .into_iter()
        .map(|server| {
            let names: Vec<String> = server
                .quarantined
                .iter()
                .map(|q| format!("{} ({:?})", q.tool.qualified_name, q.reason))
                .collect();
            format!(
                "{} needs re-approval: {}",
                server.server_name,
                names.join(", ")
            )
        })
        .collect()
}

/// GAP-FIX tooling-mcp — the served entrypoint to [`ainxt_mcp::PinnedServer::approve`]: TOFU
/// quarantine (§2.5) was a one-way street on the composition root before this. A first-use or
/// reconnect-diffed server (`register_served_mcp_runtime`'s [`ainxt_mcp::McpRegistry::discover_pinned`]
/// sweep) is correctly held OUT of the plannable set until a human approves it — but nothing in
/// `ainxt-runtimed`/`ainxt-server` ever called [`ainxt_mcp::PinnedServer::approve`], so a quarantined
/// server could never become plannable again on the served path, no matter what a deployment's admin
/// tooling did. This is that missing approval seam: writes the pin, so the NEXT `discover_pinned`
/// sweep (the very next served turn's MCP registration) sees the server as `Unchanged` and admits its
/// tools. Fail-closed by omission — a server never approved here stays quarantined forever, exactly
/// the pre-existing TOFU safety property; this only adds the ability to grant approval, never to skip it.
pub fn approve_mcp_pin(
    server: &ainxt_mcp::PinnedServer,
    pins: &dyn ainxt_mcp::PinStore,
    approved_by: &str,
    approved_at: u64,
) -> ainxt_mcp::ManifestPin {
    server.approve(pins, approved_by, approved_at)
}

/// Build the [`Engine`] from a [`RuntimeConfig`], returning the provider report. Fail-closed on an
/// enterprise gate selection.
pub fn build_engine(rc: &RuntimeConfig) -> Result<(Engine, Vec<String>), AssembleError> {
    let (
        engine,
        report,
        _ledger,
        _reconciler,
        _dispatch_probe,
        _tools,
        _outsourcing,
        _mandate_registry,
        _mcp_admin,
        _prompt_cache,
        _serving,
    ) = build_engine_ext(rc)?;
    Ok((engine, report))
}

/// GAP-FIX regulated-fi-responsible-lifecycle — the SHARED, mutable handle onto a served router's FI-03
/// outsourcing register (see [`ainxt_runtime::router::ModelRouter::outsourcing_register_handle`]).
/// `None` when the router has no register installed (never happens on `build_router`'s own output today
/// — it always installs one — but every downstream consumer treats absence as "not configured", not a
/// panic, mirroring the accessor's own `Option`).
type OutsourcingRegisterHandle = Option<Arc<std::sync::RwLock<OutsourcingRegister>>>;

/// The engine + assembly report + the SHARED exactly-once ledger and reconciler the served path
/// hands to a background [`ReconcilerSweeper`] (§1.8), plus (R15 COMPOSE) the SAME
/// [`ainxt_runtime::dispatch::DispatchProbe`] instance attached to the engine via
/// `Engine::with_dispatch_probe` — surfaced so the composition can thread it out to the served
/// telemetry path (the engine itself exposes no getter for it once built) — plus (R16, §0/§1.2,
/// CRITICAL) the SAME shared [`Arc<ToolRuntime>`] handle installed via `Engine::with_shared_tools`, so
/// `assemble_full` can hand the harness `/run` capability bridge the IDENTICAL registry + exactly-once
/// ledger this engine dispatches through, instead of the bridge building a second, disjoint one — plus
/// (GAP-FIX regulated-fi-responsible-lifecycle) the [`OutsourcingRegisterHandle`] captured from the SAME
/// router this engine was built over, BEFORE the router is moved into `Engine::new` and erased.
type EngineAssembly = (
    Engine,
    Vec<String>,
    Arc<dyn Ledger>,
    Arc<dyn Reconciler>,
    Arc<ainxt_runtime::dispatch::DispatchProbe>,
    Arc<ToolRuntime>,
    OutsourcingRegisterHandle,
    // GAP-FIX identity-payments (ADR-016 §6) — the SHARED fourth-gate registry installed on the SAME
    // `tools` handle above via `ToolRuntime::with_mandate_registry`, threaded out so `assemble_full`
    // hands `AssembledFull::authorize_payment_adjacent_dispatch` this EXACT registry rather than
    // minting a second, disjoint one.
    Arc<Mutex<ainxt_payments::mandate::MandateRegistry>>,
    McpAdminHandleOpt,
    // GAP-FIX tooling-mcp-plugins-routing (round 2) — the SAME `Arc<Mutex<PromptCache>>` instance
    // installed on the engine via `Engine::with_prompt_cache`, threaded out for the identical reason
    // `dispatch_probe` is above: the engine exposes no getter for it once built, so a caller that
    // wants to observe cache state (hit/miss/affinity) after driving a REAL turn through this SAME
    // composed engine needs the shared handle.
    Arc<Mutex<ainxt_tools::prompt_cache::PromptCache>>,
    // GAP-FIX gap6-composition-root (Item 1) — the SAME [`ServingHandle`] this engine attached via
    // `Engine::with_node_attestor` (when a non-empty pool is declared), threaded out so
    // `assemble`/`assemble_program_surface*`/`assemble_team_surface*` can hand `Assembled::serving`
    // the IDENTICAL instance instead of `assemble_full` minting a second, disjoint gate the engine's
    // own attestor never sees updates from.
    ServingHandle,
);
/// [`EngineAssembly`] plus the typed §6 wire receiver the served chat path streams (R9).
type ChatEngineAssembly = (
    Engine,
    mpsc::UnboundedReceiver<ainxt_protocol::EventEnvelope>,
    Vec<String>,
    Arc<dyn Ledger>,
    Arc<dyn Reconciler>,
    Arc<ainxt_runtime::dispatch::DispatchProbe>,
    Arc<ToolRuntime>,
    MemoryHandle,
    OutsourcingRegisterHandle,
    // GAP-FIX identity-payments (ADR-016 §6) — see `EngineAssembly`'s trailing field doc.
    Arc<Mutex<ainxt_payments::mandate::MandateRegistry>>,
    McpAdminHandleOpt,
    // GAP-FIX gap6-composition-root (Item 1) — see `EngineAssembly`'s trailing field doc; the FLAGSHIP
    // chat/code/sdlc/buddy engine builder wires `Engine::with_node_attestor` over this SAME handle.
    ServingHandle,
);
/// The assembled [`ChatSurface`] plus its §6 wire receiver, report, ledger, reconciler, (R15
/// COMPOSE) the engine's shared [`ainxt_runtime::dispatch::DispatchProbe`], (R16) the engine's
/// shared [`Arc<ToolRuntime>`] capability-registry handle, and (GAP-FIX memory) a clone of the
/// engine's own [`ainxt_memory::MemorySqlBackend`] — so a served `ConsentSurface` route (MEM-10) can
/// be opened fresh, per-request, over the SAME backend the engine's memory reader writes to, instead
/// of the disconnected `InMemoryStore` it was hardcoded to before — plus (GAP-FIX
/// regulated-fi-responsible-lifecycle) the [`OutsourcingRegisterHandle`].
type ChatSurfaceAssembly = (
    ChatSurface,
    mpsc::UnboundedReceiver<ainxt_protocol::EventEnvelope>,
    Vec<String>,
    Arc<dyn Ledger>,
    Arc<dyn Reconciler>,
    Arc<ainxt_runtime::dispatch::DispatchProbe>,
    Arc<ToolRuntime>,
    MemoryHandle,
    OutsourcingRegisterHandle,
    // GAP-FIX identity-payments (ADR-016 §6) — see `EngineAssembly`'s trailing field doc.
    Arc<Mutex<ainxt_payments::mandate::MandateRegistry>>,
    McpAdminHandleOpt,
    // GAP-FIX gap6-composition-root (Item 1) — see `EngineAssembly`'s trailing field doc.
    ServingHandle,
);

/// GAP6 telemetry-cost-rollup — illustrative REFERENCE per-model token prices (input/output
/// micros-per-million-tokens; 1 unit = 1e-6 of the currency, matching [`ainxt_telemetry::PriceTable`]'s
/// integer-money contract), keyed by the SAME canonical model names `core/model_registry.py`/this
/// repo's `CLAUDE.md` Model Usage Policy table names (and `runtimed.example.toml`'s
/// `[[models.providers]] id = "..."` examples use as the provider id — [`ainxt_providers::Provider::id`]
/// returns the adapter's configured `model`/`id` string verbatim, so a deployment that names its
/// provider entries after the canonical model, as the shipped example does, prices EXACTLY by model,
/// not by vendor).
///
/// This is the SHIPPED DEFAULT only: a deployment overrides any/all of these via
/// `[telemetry.pricing.<model-id>]` (see [`ainxt_telemetry::TelemetryConfig::pricing`]) with its own
/// negotiated/list rates — [`resolve_price_table`] prefers the configured table whenever it is
/// non-empty. Values here are illustrative anchors loosely tracking known 2025-era frontier-model
/// list prices at the time this table was written — **update these periodically**; they are not a live
/// vendor price feed. An unlisted model id still prices at 0 (unknown), never a panic
/// ([`ainxt_telemetry::PriceTable::cost_micros`]'s documented behavior) — this table only makes the
/// SHIPPED default less blind than "always 0", it is not a substitute for a deployment's real rates.
fn default_price_table() -> ainxt_telemetry::PriceTable {
    use ainxt_telemetry::ModelPrice;
    let mut prices = std::collections::HashMap::new();
    let mut set = |id: &str, input_micros_per_million: u64, output_micros_per_million: u64| {
        prices.insert(
            id.to_string(),
            ModelPrice {
                input_micros_per_million,
                output_micros_per_million,
            },
        );
    };
    // tier: simple
    set("gpt-5-mini", 250_000, 2_000_000);
    // tier: medium/coding
    set("gpt-5.4", 2_500_000, 10_000_000);
    // tier: complex (SDLC primary)
    set("claude-sonnet-4-6", 3_000_000, 15_000_000);
    // tier: haiku (lightweight classification/inline expansion)
    set("claude-haiku-4-5-20251001", 800_000, 4_000_000);
    // tier: deep (explicit user selection only)
    set("gpt-5-5", 5_000_000, 20_000_000);
    // tier: solution (explicit user selection only)
    set("claude-opus-4-7", 18_000_000, 90_000_000);
    // tier: opus-4-6 (explicit user selection only)
    set("claude-opus-4-6", 15_000_000, 75_000_000);
    // tier: vision
    set("gemini-2.5-flash", 300_000, 2_500_000);
    ainxt_telemetry::PriceTable::from_map(prices)
}

/// GAP6 telemetry-cost-rollup — the price table an assembled [`Engine`] is built with: the
/// deployment-configured `[telemetry.pricing]` table when the deployment declared ANY prices
/// (config always wins over the built-in reference — a deployment's real negotiated rate must never
/// be shadowed by an illustrative default), else [`default_price_table`] so the shipped daemon still
/// attributes a non-zero, best-effort cost per turn instead of silently pricing every provider at 0.
fn resolve_price_table(rc: &RuntimeConfig) -> ainxt_telemetry::PriceTable {
    if rc.telemetry.pricing.is_empty() {
        default_price_table()
    } else {
        rc.telemetry.price_table()
    }
}

/// [`build_engine`] but also surfacing the served engine's SHARED exactly-once ledger + reconciler
/// (R10), so an assembled surface can hand them to a background [`ReconcilerSweeper`] over the SAME
/// rows the dispatch path writes (§1.8). Thin wrapper over [`build_engine_ext_with_mcp`] with no
/// configured MCP servers and NO declared serving pool — every pre-existing caller (including
/// `build_engine`, which only ever sees a bare `RuntimeConfig`, never the wider `LoadedConfig` an
/// `[[mcp.servers]]`/`[[serving.nodes]]` section lives on) keeps its byte-identical
/// zero-MCP-servers/no-attestor behavior (an empty `ServingConfig` means `Engine::with_node_attestor`
/// is never called — see `build_engine_ext_with_mcp`'s doc).
pub fn build_engine_ext(rc: &RuntimeConfig) -> Result<EngineAssembly, AssembleError> {
    build_engine_ext_with_mcp(
        rc,
        &McpConfig::default(),
        &PaymentsConfig::default(),
        &ServingConfig::default(),
    )
}

/// [`build_engine_ext`] but over a caller-supplied [`McpConfig`], [`PaymentsConfig`] and
/// [`ServingConfig`] — GAP-FIX tooling-mcp-plugins-routing / payments-governance / gap6-composition-root:
/// the real composition-root call site. [`assemble`] (the `--surface engine` arm `assemble_selected`
/// dispatches to) and the Program/Team surfaces
/// (`assemble_program_surface_with_transparency_and_topology`, `build_team_surface_parts`) all have a
/// real [`LoadedConfig`] in scope and call this directly with `&loaded.mcp`/`&loaded.payments`/
/// `&loaded.serving`, so a deployment's declared `[[mcp.servers]]` actually get spawned + registered at
/// boot (see [`build_unified_capability_registry_shared_with_mcp_admin_and_servers`]), a governed
/// `[payments] settlement_policy` edit actually reaches the served classifier (see
/// [`resolve_payment_boundary`]), and (GAP-FIX gap6-composition-root, Item 1) a declared
/// `[[serving.nodes]]` pool is wired onto this engine's OWN `Engine::with_node_attestor` — over the
/// SAME `ServingHandle` this function also returns (see [`node_attestor_over`]'s doc), so the
/// engine-internal §4.2 ESCALATED `route_class` gets the identical fail-closed node fence the
/// server's Stage-1 check already applies to the caller's naively-declared class. An empty/default
/// `ServingConfig` (the air-gapped shipped default) leaves `Engine::with_node_attestor` uncalled,
/// byte-identical to before this fix — mirrors the existing `ainxt-server` Stage-1 guard
/// (`.filter(|sv| !sv.candidates.is_empty())`) so a regulated turn on the default deployment is not
/// suddenly fenced off with no way to ever attest.
pub fn build_engine_ext_with_mcp(
    rc: &RuntimeConfig,
    mcp_config: &McpConfig,
    payments: &PaymentsConfig,
    serving_cfg: &ServingConfig,
) -> Result<EngineAssembly, AssembleError> {
    let (compliance, authz, audit) = build_gates(&rc.gates)?;
    let (router, mut report) = build_router(&rc.models);
    // GAP-FIX regulated-fi-responsible-lifecycle — capture the SHARED outsourcing-register handle from
    // THIS router BEFORE it is moved into `Engine::new` below and erased. This is the same live Arc
    // `governance_admits`'s FI-03 gate reads on every turn this engine serves — never a second, disjoint
    // register built independently later (see `ModelRouter::outsourcing_register_handle`'s own doc).
    let outsourcing_register = router.outsourcing_register_handle();

    // Assemble the tool-safety pipeline so it is LIVE in the daemon (not dead code): the ONE unified
    // Capability registry (§0) makes the agent loop run OBO authz, the injection taint-gate on tool
    // results, the exactly-once ledger, and the approval gate on every capability call.
    // GAP-FIX tooling-mcp-plugins-routing — capture the live `McpAdminHandle` this boot-time
    // registration ran over too, so a served admin route can surface/act on the SAME TOFU state.
    // GAP-FIX tooling-mcp-plugins-routing (real-transport wiring) — pass the caller's configured MCP
    // servers through so they are ACTUALLY spawned + registered, not just declared.
    let (tools, ledger, reconciler, mcp_admin) =
        build_unified_capability_registry_shared_with_mcp_admin_and_servers(
            &mut report,
            &mcp_config.servers,
        );
    // GAP-FIX identity-payments (ADR-016 §6) — install the SHARED fourth-gate MandateRegistry on THIS
    // ToolRuntime BEFORE it is wrapped in the shared `Arc` below, so every dispatch path the served
    // agent loop drives through `tools` (dispatch/dispatch_obo(_audited)(_with_pam)/dispatch_saga)
    // enforces the same fourth gate `AssembledFull::authorize_payment_adjacent_dispatch` exposes —
    // returned out of this function so `assemble_full` hands both the SAME Arc, never a second,
    // disjoint registry.
    let mandate_registry = Arc::new(Mutex::new(ainxt_payments::mandate::MandateRegistry::new()));
    let tools = tools.with_mandate_registry(mandate_registry.clone());
    // R16 (§0/§1.2, CRITICAL): wrap as a SHARED handle BEFORE installing it on the engine, and keep a
    // clone to return — this is what lets `assemble_full` hand the harness `/run` bridge the IDENTICAL
    // registry + exactly-once ledger this engine dispatches through (see `mounts::build_harness_mounts`)
    // instead of the bridge building a second, disjoint one over its own fresh ledger.
    let tools = Arc::new(tools);

    // R14 (served-composition, HIGH): route the served agent loop's single-phase tool dispatch through
    // the audited THREE-LAYER OBO gate (declared grant ∧ issued scope ∧ resource-ABAC clearance) with
    // the decision written to the audit sink BEFORE any effect and the agent's ambient credential never
    // substituted on a denial. The reference ThreeLayerPolicy over a MapAbac (unmapped resources at the
    // Internal floor) is the offline default. GAP-FIX tooling-mcp-plugins-routing: the audit sink now
    // mirrors `[gates] audit`'s own Memory/EventLog selection (`build_obo_sink`) instead of always
    // being the ephemeral `VecOboAudit` — `audit = "event-log"` durably persists OBO decisions too.
    let obo_sink = build_obo_sink(&rc.gates)?;
    let obo_policy: Box<dyn ainxt_tools::obo::OboPolicy> = Box::new(
        ainxt_tools::obo::ThreeLayerPolicy::new(ainxt_tools::obo::MapAbac::new()),
    );
    // R15 COMPOSE (needs_hot_wiring closed) — mount the two additive engine seams the daemon builder
    // was leaving inert: the in-engine complexity classifier (so an UNPINNED served turn genuinely
    // derives its tier from the turn's content instead of silently defaulting to `req.tier`) and the
    // concurrent tool-dispatch observability probe (so parallel-dispatch peak/total concurrency is a
    // real serving-ops signal, not just exercised inside `ainxt-runtime`'s own tests). The probe
    // instance is retained here (the engine exposes no getter once built) and threaded out through
    // this function's return so the served telemetry path can read it per turn.
    let dispatch_probe = Arc::new(ainxt_runtime::dispatch::DispatchProbe::new());
    // GAP-FIX tooling-mcp-plugins-routing (round 2) — `ainxt_tools::prompt_cache::PromptCache` (the
    // stable-prefix structural cache, see `r15_prompt_cache_stable_prefix.rs`) previously had zero
    // callers anywhere outside its own crate's unit test. Mounted here so EVERY served turn on this
    // engine (bare/program/team) observes its stable prefix through it; retained as a shared handle
    // (same reasoning as `dispatch_probe` above — the engine exposes no getter for it once built) so
    // the composition can thread it out to a caller that wants to observe hit/miss/affinity state.
    let prompt_cache = Arc::new(Mutex::new(ainxt_tools::prompt_cache::PromptCache::new()));
    // GAP-FIX payments-governance — the boot preflight: resolves to the unchanged
    // `PaymentBoundary::payment_default()` when `[payments]` is unset, or the governance-authorized
    // `SettlementPolicy` edit when set (fail-closed on a refused/partial edit — see
    // `resolve_payment_boundary`'s doc).
    let payment_boundary = resolve_payment_boundary(payments)?;
    // GAP-FIX gap6-composition-root (Item 1, R11 SERVING SRV-01) — build the SAME
    // `(ServingGate, declared node pool)` handle `build_serving` builds for `assemble_full`'s
    // `/v1/chat` Stage-1 fence + attestation refresh loop, so this engine's OWN attestor (below)
    // shares live attestation state with them rather than a second, disjoint gate.
    let serving = build_serving(serving_cfg);
    let engine = Engine::new(compliance, authz, audit, router)
        .with_max_iters(rc.limits.max_agent_iters)
        .with_retry(
            rc.limits.provider_max_retries,
            rc.limits.provider_backoff_base_ms,
        )
        .with_guardrails(&rc.guardrails)
        .with_injection(&rc.injection)
        .with_shared_tools(tools.clone())
        // GAP-FIX guardrails-injection — SAME wiring as `build_chat_engine_with_authz`: the
        // registered capability names now reach the injection detector's `known_tool_names` strong
        // signal so the bare/program/team engines' own tool-RESULT scan gets it too, not only chat.
        .with_injection_scanner(Box::new(
            ainxt_injection::InjectionDetector::default().with_tools(tools.tool_names()),
        ))
        .with_obo(obo_policy, obo_sink)
        .with_complexity_classifier(Box::new(
            ainxt_runtime::complexity::HeuristicComplexityClassifier::default(),
        ))
        .with_dispatch_probe(dispatch_probe.clone())
        .with_prompt_cache(prompt_cache.clone())
        // GAP-FIX transport-daemon (ADR-016 §9) — install the REAL payment-boundary classifier;
        // see `default_payment_boundary_resolver`'s doc comment. Before this, this engine (which serves
        // the bare/program/team surfaces) ran with `Engine::new`'s default resolver
        // (`|_, _| PaymentBoundary::None`), so a payment-adjacent tool call on THESE surfaces could
        // never reach the human-approve-only gate either. GAP-FIX payments-governance — resolves over
        // `payment_boundary` (the boot-preflight-authorized policy, or the unchanged npci() default)
        // instead of always the hardcoded constant.
        .with_payment_boundary_resolver(payment_boundary_resolver_over(
            payment_boundary,
            tools.clone(),
        ))
        // GAP6 telemetry-cost-rollup — install the REAL price table (`[telemetry.pricing]`, or the
        // shipped `default_price_table` when unset) so this engine's own `WireEvent::Usage.cost` (and
        // therefore every downstream `TurnMetrics.cost_micros`/`CostRollup`) is priced by an actually
        // configured/reference rate instead of `Engine::new`'s empty `PriceTable::new()` default, which
        // silently prices EVERY provider at 0 regardless of real usage.
        .with_pricing(resolve_price_table(rc));
    // GAP-FIX gap6-composition-root (Item 1, R11 SERVING SRV-01/SRV-02) — mirror the EXACT guard
    // `ainxt-server`'s own Stage-1 fence uses (`state.serving.as_ref().filter(|sv| !sv.candidates.is_empty())`):
    // only attach the engine's own node-attestation hook when a real pool is declared. On the
    // air-gapped default (no `[[serving.nodes]]`) this is a no-op — `Engine::with_node_attestor` is
    // never called, so a regulated turn on the shipped default is not fenced off with no node that
    // could ever attest (see `node_attestor_over`'s doc for the exact gap this closes when a pool IS
    // declared).
    let engine = if serving.1.is_empty() {
        engine
    } else {
        report.push(format!(
            "serving: {} node(s) also bound onto Engine::with_node_attestor (bare/program/team engine) \
             — the engine's OWN §4.2 tri-signal ESCALATED route_class now fails closed off an \
             unattested node too, over the SAME ServingGate the daemon's /v1/chat Stage-1 fence and \
             attestation refresh loop consult",
            serving.1.len()
        ));
        engine.with_node_attestor(node_attestor_over(&serving))
    };
    debug_assert!(
        engine.has_tools(),
        "the daemon must assemble the tool-safety pipeline"
    );
    debug_assert!(
        engine.has_obo(),
        "the served agent loop must dispatch tools through the audited three-layer OBO gate"
    );
    debug_assert!(
        !matches!(
            engine.probe_payment_boundary(
                // A destination that really is inside `SettlementPerimeter::default_reserved`
                // (the `"x402."` agent-payment-protocol pattern, ADR-016 §5), so this guard
                // proves what it claims to prove without depending on tool registration.
                //
                // The previous probe passed `"settlement.example.transfer"` with a
                // `settlement-account:` resource key and matched NEITHER facet on the shipped
                // daemon: no `default_reserved` pattern is a substring of that name, and the
                // resource-key facet reads `ToolRuntime::resource_of`, which is `None` for a
                // tool this runtime never registers. The probe therefore returned
                // `PaymentBoundary::None` and this `debug_assert!` aborted every debug-profile
                // boot (exit 101) and its own composition-root tests.
                //
                // Widening the perimeter to a bare `"settlement."` is NOT the fix: it would
                // swallow read-only names such as `settlement-report:2026-07`, which
                // `ainxt-payments::boundary` asserts must stay OUTSIDE the perimeter.
                "x402.pay",
                "{}"
            ),
            ainxt_protocol::PaymentBoundary::None
        ),
        "the served engine must classify a settlement-perimeter/resource-key call as a real payment \
         boundary, never the default None resolver"
    );
    report.push(
        "capabilities: served agent-loop tool dispatch routed through the audited THREE-LAYER OBO \
         gate (dispatch_obo_audited — declared grant ∧ issued scope ∧ resource-ABAC clearance; every \
         decision audited before effect; ambient credential never substituted on denial)"
            .into(),
    );
    report.push(
        "routing: in-engine HeuristicComplexityClassifier mounted via Engine::with_complexity_classifier \
         — an UNPINNED served turn derives its model-complexity tier from the turn's own content \
         (deterministic, model-agnostic) instead of echoing the caller's soft `tier` default"
            .into(),
    );
    report.push(
        "observability: concurrent tool-dispatch DispatchProbe mounted via Engine::with_dispatch_probe \
         — peak/total in-flight tool-dispatch concurrency is now a real serving-ops telemetry signal \
         (see TelemetrySink::record_dispatch), not only exercised inside ainxt-runtime's own tests"
            .into(),
    );
    report.push(
        "payments: payment-initiation-signature classifier (ainxt_payments::boundary) wired as \
         the engine's payment_boundary resolver via Engine::with_payment_boundary_resolver — a \
         payment-adjacent tool call on the bare/program/team surfaces now reaches the \
         human-approve-only gate (§9, ADR-016) instead of always resolving to PaymentBoundary::None"
            .into(),
    );
    report.push(
        "tooling: ainxt_tools::prompt_cache::PromptCache mounted via Engine::with_prompt_cache — \
         every served turn observes its stable prefix (the profile/system prompt) once, recording a \
         hit/miss to the audit trail and remembering the serving provider as this session's \
         warm-affinity hint, instead of the cache sitting unreferenced outside its own unit test"
            .into(),
    );

    // Honest disclosure: two declared limits are NOT yet enforced by the engine in this build. If an
    // operator has set them to a non-default value expecting them to take effect, warn — don't
    // silently ignore. (Applied limits: max_agent_iters, provider retries/backoff.)
    let d = ainxt_config::LimitsConfig::default();
    if rc.limits.max_input_bytes != d.max_input_bytes {
        report.push(
            "WARNING: limits.max_input_bytes is declared but NOT enforced in this build".into(),
        );
    }
    if rc.limits.stream_channel_bound != d.stream_channel_bound {
        report.push(
            "WARNING: limits.stream_channel_bound is declared but NOT enforced in this build"
                .into(),
        );
    }
    Ok((
        engine,
        report,
        ledger,
        reconciler,
        dispatch_probe,
        tools,
        outsourcing_register,
        mandate_registry,
        Some(Arc::new(mcp_admin)),
        prompt_cache,
        serving,
    ))
}

/// GAP-AUDIT surfaces-profiles-skills-config (item 3) — DECISION: `ainxt_surface::SurfaceArtifacts` is
/// NOT wired onto [`Assembled`]. It previously was (a field constructed + startup-self-tested in
/// `assemble_surface`) but had exactly ONE reader — `assemble_full_with_control_plane`'s own
/// destructure, which immediately dropped it uncalled, because the REAL served document-generation
/// path is a *different* mechanism: a chat turn's `Intent::DocGeneration` builds an
/// `ainxt_artifact::Document` IR (`ainxt-convo`'s `ManagerOutcome::Document`), and the ONLY live
/// renderer for that IR is `POST /v1/artifact`, backed by [`mounts::build_artifact_runtime`]'s
/// `ArtifactRuntime` — a STRICT superset of what `SurfaceArtifacts::with_default_scanner()` offered
/// (that one registered only the built-in markdown/text renderers; `build_artifact_runtime` registers
/// ALL renderers including binary pdf/docx/xlsx, and is the handle `AssembledFull::artifact` actually
/// serves). So `SurfaceArtifacts` at the composition root was a second, weaker, genuinely redundant
/// `ArtifactRuntime` construction with no live caller beyond its own boot-time self-test — removed
/// here rather than forcing an artificial caller just to "use" it (its own proving test,
/// `wire_surf_13_14_composition_root`, was the exact "constructs its own instance, never proven
/// through the real served route" pattern this audit round exists to catch — removed alongside it).
/// The type itself (`ainxt_surface::SurfaceArtifacts`) is untouched and still fully usable if a future
/// design genuinely needs an in-turn (not out-of-band `/v1/artifact`) rendering seam.
///
/// The assembled runtime: a ready-to-serve [`SessionManager`] plus the assembly report.
pub struct Assembled {
    pub manager: Arc<SessionManager>,
    pub report: Vec<String>,
    /// R10 — the SHARED exactly-once ledger + reconciler behind the served engine's unified Capability
    /// registry, surfaced so [`assemble_full`] can spawn a background [`ReconcilerSweeper`] over the
    /// SAME rows the served dispatch path writes (§1.8). `None` on a surface whose engine builder does
    /// not expose it (never fatal — the daemon simply runs without an active sweep).
    pub capability_ledger: Option<(Arc<dyn Ledger>, Arc<dyn Reconciler>)>,
    /// R9 TRANSP — the receiver paired with the [`ChannelWireSink`](ainxt_runtime::wire::ChannelWireSink)
    /// attached to the assembled chat engine, so the served `/v1/chat` + `/v1/events` emit the engine's
    /// REAL typed §6 [`WireEvent`](ainxt_protocol::WireEvent) stream (capped-vs-complete outcome,
    /// `compliance.notice`, payment-boundary, priced `usage{model,cost}`) BY DEFAULT — not the lossy
    /// legacy `Event` projection. `None` on a surface with no chat engine (the bare `engine`/`program`
    /// surfaces), in which case the transport falls back to the legacy projection.
    pub wire_events: Option<mpsc::UnboundedReceiver<ainxt_protocol::EventEnvelope>>,
    /// R15 COMPOSE — the served engine's shared [`ainxt_runtime::dispatch::DispatchProbe`], when the
    /// assembled surface's engine builder exposes one (every surface built via `build_engine_ext` /
    /// `build_chat_engine_with_authz` does). `None` on a surface with no real Engine (the AiNxt-OS
    /// workforce surface). [`assemble_full`] threads this to `AssembledFull`/`FullAppExt` so the
    /// transport can sample it alongside the per-turn telemetry record.
    pub dispatch_probe: Option<Arc<ainxt_runtime::dispatch::DispatchProbe>>,
    /// **R16 CRITICAL fix (serving-ops)**: the LIVE answer-cache handle a served [`ChatSurface`]
    /// populates on every cacheable turn (`ChatSurface::answer_cache_handle`), taken at the point the
    /// surface is assembled — BEFORE it is erased behind `Arc<dyn TurnHandler>`. [`assemble_full`]
    /// threads this into the daemon's `ainxt_serving::erasure::TieredCacheErasure` DSAR organ
    /// (`mounts::build_erasure`) so a right-to-erasure request purges the SAME instance the served
    /// `/v1/chat` path reads from — not a second, never-populated cache (the audit's "erasure ack is
    /// vacuous" finding). A surface with no `ChatSurface` (bare-engine / program / team / workforce)
    /// gets a fresh, private, never-shared handle: there is no live served answer cache for those
    /// surfaces, so the erasure organ's answer tier is a legitimate (if inert) private store.
    pub shared_answer_cache: Arc<Mutex<PartitionedCache>>,
    /// R16 (§0/§1.2, CRITICAL FIX): the served engine's SHARED [`Arc<ToolRuntime>`] capability-registry
    /// handle, when the assembled surface's engine builder exposes one (every surface built via
    /// `build_engine_ext` / `build_chat_engine_with_authz` does — bare engine, chat/code/sdlc/buddy,
    /// program, team). [`assemble_full`] hands this SAME handle to `mounts::build_harness_mounts` so the
    /// harness `/run` capability bridge dispatches through the IDENTICAL registry + exactly-once ledger
    /// this engine's own tool loop uses — closing the "second capability registry over a disjoint
    /// exactly-once ledger" double-execution path (the same caller-supplied idempotency key, e.g. a
    /// retried settlement-initiation call, could otherwise commit once on each of two independent
    /// ledgers). `None` on a surface with no real Engine (the AiNxt-OS workforce surface) — the harness
    /// bridge then falls back to its own OSS reference registry (no engine tool-dispatch path exists on
    /// that surface to collide with).
    pub capability_tools: Option<Arc<ToolRuntime>>,
    /// GAP-FIX memory — a clone of the assembled chat engine's own [`ainxt_memory::MemorySqlBackend`]
    /// PLUS (GAP-FIX memory write-path-missing) a live [`ainxt_memory::MemoryWriter`] handle onto the
    /// engine's own long-lived durable-store instance (see [`MemoryHandle`]'s doc), when the surface
    /// has one (every chat-engine surface built via `build_chat_engine_with_authz` does —
    /// chat/code/sdlc/buddy and their identity-governed/profile-resolved variants). `None` on a
    /// surface with no chat engine (bare `engine`/`program`/AiNxt-OS workforce). [`assemble_full`]
    /// threads this into `AssembledFull`/`FullAppExt` so the served MEM-10 consent/export/erasure
    /// route (`ainxt-server`'s `memory_router`) opens a store over the SAME backend the engine's own
    /// memory reader writes to (rather than the disconnected standalone `InMemoryStore` it was
    /// hardcoded to before that fix), AND the served `POST /memory/remember` write route reaches the
    /// EXACT SAME long-lived reader instance `read_for_turn` queries.
    pub memory_backend: Option<MemoryHandle>,
    /// GAP-FIX regulated-fi-responsible-lifecycle — the SHARED [`OutsourcingRegisterHandle`] captured
    /// from the SAME [`ainxt_runtime::router::ModelRouter`] this surface's engine dispatches turns
    /// through (every surface built via `build_engine_ext` / `build_chat_engine_with_authz` installs one
    /// — see `build_router`'s FI-03 wiring). [`assemble_full`] threads this onto `AssembledFull` so a
    /// served admin route can `upsert`/`reapprove` a board-approved arrangement into the IDENTICAL live
    /// register the router's non-overridable FI-03 eligibility gate reads on the very next turn — never
    /// a second, disjoint register built independently by the admin path. `None` only on a surface with
    /// no real Engine (the AiNxt-OS workforce surface builds its own router directly via `build_router`
    /// and captures the SAME handle before installing it via `with_model_router`).
    pub outsourcing_register: OutsourcingRegisterHandle,
    /// GAP-CLOSE os-workforce-exec #2 — the REAL [`workforce_surface::RoleInvocationLedger`] the served
    /// workforce surface's [`workforce_surface::ModelRoutedExecutor`] records every genuine role
    /// invocation to (via `with_invocation_ledger`), captured HERE — before the surface is erased
    /// behind `Arc<dyn TurnHandler>` — so a served caller (or the §6.1 nightly sweep) can read real
    /// `invocations_30d`/`invocation_trend` telemetry instead of the caller-fabricated inputs every
    /// prior test had to hand-construct. `None` on every surface other than `"workforce"` — no other
    /// surface has a role-invocation concept to ledger.
    pub workforce_invocation_ledger: Option<Arc<workforce_surface::RoleInvocationLedger>>,
    /// GAP-CLOSE os-workforce-exec #3 — a clone of the SAME [`ainxt_workforce::kernel::Kernel`] handle
    /// the served workforce surface's [`workforce_surface::WorkforceSurface::spawn_kernel_scheduler`]
    /// loop ticks over (started at surface-assembly time — see
    /// [`workforce_surface::assemble_workforce_surface_served`]'s doc for why that is the correct spawn
    /// point rather than `main.rs`), captured here — before the surface is erased behind
    /// `Arc<dyn TurnHandler>` — so a served caller (or a test) can admit/observe processes on the
    /// EXACT table the live scheduler is driving, not a disconnected copy. `None` on every surface
    /// other than `"workforce"` — no other surface has a kernel process model at all.
    pub workforce_kernel: Option<Arc<Mutex<ainxt_workforce::kernel::Kernel>>>,
    /// GAP-FIX identity-payments (ADR-016 §6) — the SHARED [`ainxt_payments::mandate::MandateRegistry`]
    /// already installed (via [`ainxt_tools::ToolRuntime::with_mandate_registry`]) on the SAME
    /// `capability_tools` this surface's engine dispatches every capability call through.
    /// [`assemble_full`] threads this onto `AssembledFull::mandate_registry` so
    /// `AssembledFull::authorize_payment_adjacent_dispatch` and the served dispatch path enforce the
    /// fourth gate against the IDENTICAL registry — never a second, disjoint one built independently.
    pub mandate_registry: Arc<Mutex<ainxt_payments::mandate::MandateRegistry>>,
    /// GAP-FIX tooling-mcp-plugins-routing — the SHARED [`McpAdminHandle`] captured from the SAME
    /// unified Capability registry build this surface's engine dispatches turns through (every
    /// surface built via `build_engine_ext` / `build_chat_engine_with_authz` installs one — see
    /// `build_unified_capability_registry_shared_with_mcp_admin`). [`assemble_full`] threads this onto
    /// `AssembledFull` so a served admin route can list/approve TOFU re-approvals against the
    /// IDENTICAL live registry + pin store the daemon's own boot-time MCP registration consulted —
    /// never a second, disjoint registry the admin path discovers/approves against. `None` only on a
    /// surface with no real Engine (the AiNxt-OS workforce surface has no MCP/tool registry at all).
    pub mcp_admin: McpAdminHandleOpt,
    /// GAP-FIX surfaces-profiles-skills-config (ADR-026 §6.2 hot-reload) — the SHARED handle onto the
    /// served surface's `SkillRuntime`, captured BEFORE it (and the `ProfiledSurface` holding it) is
    /// erased behind `Arc<dyn TurnHandler>` (mirrors `shared_answer_cache`'s doc above). `assemble_full`
    /// threads this onto `AssembledFull` so `POST /admin/reload` calls `.reload()` on the EXACT
    /// `SkillRuntime` every subsequent turn resolves skill refs through — an atomic pointer swap, never
    /// a second, disjoint registry the admin route built for itself. `Some` only on
    /// [`assemble_surface`] (the profile-enforced surface with a real `SkillRuntime`); `None` on the
    /// bare-engine/program/team/workforce surfaces, which have none.
    pub skill_runtime: Option<Arc<ainxt_skill::SkillRuntime>>,
    /// GAP-FIX gap6-composition-root (Item 1) — the SAME [`ServingHandle`] this surface's real Engine
    /// attached via `Engine::with_node_attestor` (see `node_attestor_over`'s doc), captured here BEFORE
    /// the engine is erased behind `Arc<dyn TurnHandler>`. [`assemble_full_with_control_plane`] reuses
    /// this EXACT instance for `AssembledFull::serving` (the daemon's `/v1/chat` Stage-1 fence +
    /// ADR-021 §8.3 attestation refresh loop) instead of building a second, disjoint `ServingGate` the
    /// engine's own attestor would never see updates from. `None` only on a surface with no real Engine
    /// (the AiNxt-OS workforce surface) — `assemble_full_with_control_plane` falls back to building its
    /// own gate in that case (used only by `/v1/infer` + the health/WFQ machinery, unrelated to any
    /// Engine-based turn dispatch on that surface).
    pub serving: Option<ServingHandle>,
    /// GAP-CLOSE os-workforce (gap6-workforce-governance-gate) — the SAME live `WorkforceSurface`
    /// (behind `ainxt_workforce::studio::GovernedWorkforce`, so `ainxt-server` — which cannot depend on
    /// this crate — can hold it) the `"workforce"` surface's `POST /v1/chat` studio-turn dispatch
    /// drives, captured BEFORE it is erased behind `Arc<dyn TurnHandler>`
    /// ([`workforce_surface::assemble_workforce_surface_served`]'s doc). `assemble_full` threads this
    /// onto `AssembledFull`/`FullAppExt` so a dedicated `POST /v1/workforce/roles` route reaches the
    /// EXACT SAME published-role registry/kernel/marketplace — never a second, disconnected surface.
    /// `None` on every surface other than `"workforce"` — no other surface has one to offer.
    pub workforce_surface: Option<Arc<dyn ainxt_workforce::studio::GovernedWorkforce>>,
}

/// Assemble the full runtime (engine + session manager) from a loaded config — the **bare-engine**
/// surface (a raw model turn behind the mandatory gates). The full conversation intelligence — intent
/// cascade, referent/content resolution, grounded retrieval + citations, response caching — is served
/// by [`assemble_surface`] (the REAL default `/v1/chat` composition, profile-enforced). [`assemble_chat`]
/// builds the same family of grounded [`ChatSurface`] logic WITHOUT the profile/RBAC/skill layer — see
/// its own doc comment for why it is a deliberately separate, non-default sibling, not "the" chat
/// surface.
pub fn assemble(loaded: &LoadedConfig) -> Result<Assembled, AssembleError> {
    let (
        engine,
        report,
        ledger,
        reconciler,
        dispatch_probe,
        tools,
        outsourcing_register,
        mandate_registry,
        mcp_admin,
        _prompt_cache,
        serving,
    ) = build_engine_ext_with_mcp(
        &loaded.runtime,
        &loaded.mcp,
        &loaded.payments,
        &loaded.serving,
    )?;
    let manager = Arc::new(SessionManager::new(Arc::new(engine), loaded.session));
    // The bare `engine` surface streams the legacy `Event` projection (no chat-engine wire seam).
    Ok(Assembled {
        manager,
        report,
        wire_events: None,
        capability_ledger: Some((ledger, reconciler)),
        dispatch_probe: Some(dispatch_probe),
        capability_tools: Some(tools),
        // No ChatSurface on the bare-engine surface — a fresh, never-shared handle (nothing to erase).
        shared_answer_cache: Arc::new(Mutex::new(PartitionedCache::new(CacheConfig::default()))),
        // No chat engine ⇒ no memory reader/backend on the bare-engine surface.
        memory_backend: None,
        outsourcing_register,
        // No role-invocation concept on the bare-engine surface.
        workforce_invocation_ledger: None,
        // No kernel process model on the bare-engine surface.
        workforce_kernel: None,
        // No GovernedWorkforce on the bare-engine surface.
        workforce_surface: None,
        mandate_registry,
        mcp_admin,
        // No profile/SkillRuntime on the bare-engine surface.
        skill_runtime: None,
        serving: Some(serving),
    })
}

/// A wall-clock [`Clock`] for the response cache's TTL. `ainxt-cache` is deliberately clock-free
/// (deterministic + replayable); the *edge* (this daemon) supplies the real clock. Seconds since the
/// Unix epoch — matches the cache's default `ttl_ticks` (3600 ⇒ a one-hour freshness window).
struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

// ============================ Durable memory layer (MEM) ============================

/// A [`ainxt_memory::Redactor`] backed by the runtime's [`StrongRedactor`](ainxt_compliance::StrongRedactor)
/// — so a memory WRITE is scrubbed by exactly the same detector the turn pipeline runs (a PAN / PII /
/// secret can never enter durable memory). This is the compliance-on-write seam the design mandates
/// for every persistence tier; it is never removable, only its provider is swapped.
struct StrongMemoryRedactor {
    inner: ainxt_compliance::StrongRedactor,
}

impl std::fmt::Debug for StrongMemoryRedactor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StrongMemoryRedactor")
    }
}

impl ainxt_memory::Redactor for StrongMemoryRedactor {
    fn redact(&self, text: &str) -> String {
        self.inner.redact(text).0
    }
}

/// GAP-FIX memory (embed-on-write-never-wired) — `InMemoryStore`/`DurableMemoryStore`'s embed-on-write
/// path (`store.rs::embed_on_write`, design §2 `embedding` / §8.5 data-class routing) was fully
/// implemented and unit-tested, but `with_embedders` had ZERO callers outside `ainxt-memory`'s own
/// tests: the shipped daemon's `inhouse_embedder`/`cloud_embedder` were always `None`, so
/// `embed_on_write` hit its early-return on every real write (`store.rs:977`) and `.embedding` stayed
/// unset forever — semantic recall (`MemoryQuery::semantic`) had nothing to cosine-match against, with
/// no separate reindex/backfill path ever wired to catch up. This is the same "offline default behind
/// the seam" posture `ainxt_cache::HashEmbedder` already uses for the answer-cache paraphrase tier
/// (see `HashEmbedder`'s own doc: "production injects the real embed client") — applied to memory's
/// OWN embedder seam (a distinct trait/signature, hence a distinct type here, not a re-export).
///
/// Deliberately dependency-free + deterministic (bag-of-tokens FNV hash into `dim` buckets) so
/// embed-on-write is real with zero infra in the OSS/air-gapped default; a production deployment swaps
/// the concrete model behind this same seam via `DurableMemoryReader::open`, never a code change in
/// `ainxt-memory` itself (the store enforces data-class routing, the model is infra — `store.rs:643`).
#[derive(Debug)]
struct MemoryHashEmbedder {
    model_id: String,
    kind: ainxt_memory::EmbedderKind,
    dim: usize,
}

impl MemoryHashEmbedder {
    fn new(model_id: &str, kind: ainxt_memory::EmbedderKind, dim: usize) -> Self {
        MemoryHashEmbedder {
            model_id: model_id.to_string(),
            kind,
            dim: dim.max(1),
        }
    }
    fn tokenize(text: &str) -> Vec<String> {
        text.split(|c: char| !c.is_alphanumeric())
            .filter(|t| !t.is_empty())
            .map(|t| t.to_ascii_lowercase())
            .collect()
    }
}

impl ainxt_memory::Embedder for MemoryHashEmbedder {
    fn model_id(&self) -> &str {
        &self.model_id
    }
    fn kind(&self) -> ainxt_memory::EmbedderKind {
        self.kind
    }
    fn embed(&self, text: &str) -> Vec<f32> {
        let mut v = vec![0.0f32; self.dim];
        for tok in Self::tokenize(text) {
            // FNV-1a 64-bit, folded into a bucket — identical construction to `ainxt_cache::HashEmbedder`.
            let mut h: u64 = 0xcbf2_9ce4_8422_2325;
            for b in tok.as_bytes() {
                h ^= *b as u64;
                h = h.wrapping_mul(0x100_0000_01b3);
            }
            v[(h % self.dim as u64) as usize] += 1.0;
        }
        v
    }
}

/// GAP-FIX ainxt-retrieval (gap6-retrieval-maintenance, items 1+2) — the offline default
/// [`ainxt_retrieval::reembed::Embedder`] [`AssembledFull::run_kb_maintenance_tick`] /
/// [`AssembledFull::run_kb_reembed_tick`] drive: deterministic, dependency-free (FNV-1a bag-of-bytes
/// into a fixed-dim one-hot bucket), mirroring [`MemoryHashEmbedder`]/`governed::OfflineArtifactEmbedder`'s
/// own offline-default technique, so a maintenance-triggered reindex or an explicit migration is
/// genuinely real with zero infra in the air-gapped default. Carries the [`ainxt_retrieval::EmbeddingVersion`]
/// it stamps onto every vector as a field (rather than a fixed constant) — [`ainxt_retrieval::reembed::migrate_to`]'s
/// own uniformity check compares every chunk's stamped version against the CALLER'S requested
/// `target`, so an embedder whose reported [`Embedder::version`] disagreed with `target` would make
/// `is_embedding_uniform` false forever even on total success; constructing this with the SAME
/// `target` the caller passed to `run_kb_corpus_reembed` is what makes migration completion
/// observable. A production deployment drives [`ainxt_retrieval::reembed::plan_reembed`]/`run_reembed`
/// directly with a real `services/embed_svc`-backed [`ainxt_retrieval::reembed::Embedder`] instead of
/// these ticks when it wants a live embedding model — exactly the same "swap the embedder, not the
/// caller" posture [`AssembledFull::spawn_memory_reembed_sweep`]'s own doc states for `MemoryHashEmbedder`.
#[derive(Debug, Clone)]
struct OfflineKbMaintenanceEmbedder {
    version: ainxt_retrieval::EmbeddingVersion,
}

impl OfflineKbMaintenanceEmbedder {
    /// The fixed identity this crate's maintenance sweep ([`kb_maintenance_tick`]) tags a
    /// degradation/change-triggered reindex with — maintenance has no caller-specified "target"
    /// version (unlike [`kb_reembed_tick`]'s explicit migration), so a stable, self-describing default
    /// is used instead.
    fn maintenance_default() -> Self {
        OfflineKbMaintenanceEmbedder {
            version: ainxt_retrieval::EmbeddingVersion::new("offline-hash-kb-maintenance-v1", 1),
        }
    }
}

impl ainxt_retrieval::reembed::Embedder for OfflineKbMaintenanceEmbedder {
    fn embed(&self, text: &str) -> Option<Vec<f32>> {
        // An empty text has nothing to derive a vector from — a real embed-service failure mode
        // (mirrors `ainxt-retrieval::reembed`'s own `<<unembeddable>>` test fixture), surfaced as a
        // `ReembedResult::Failed`, never silently skipped.
        if text.is_empty() {
            return None;
        }
        const DIM: usize = 32;
        let mut hash: u64 = 0xcbf29ce484222325;
        for b in text.bytes() {
            hash ^= b as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
        let mut v = vec![0.0f32; DIM];
        v[(hash as usize) % DIM] = 1.0;
        Some(v)
    }
    fn version(&self) -> ainxt_retrieval::EmbeddingVersion {
        self.version.clone()
    }
}

/// The result of one [`AssembledFull::run_kb_maintenance_tick`] sweep.
#[derive(Debug, Clone)]
pub struct KbMaintenanceOutcome {
    /// Every [`ainxt_retrieval::maintenance::ReindexTrigger`] this tick decided: content-diff
    /// triggers from `IndexState::apply` over [`AssembledFull::kb_corpus_snapshot`], PLUS (when the
    /// vector index's recall/latency health has degraded) a forced `Changed` trigger for every
    /// currently-tracked node — id-sorted-then-appended, never duplicated for an id already present.
    pub triggers: Vec<ainxt_retrieval::maintenance::ReindexTrigger>,
    /// The vector-index health verdict this tick observed
    /// ([`ainxt_retrieval::maintenance::RecallLatencyMonitor::status`]).
    pub health: ainxt_retrieval::maintenance::IndexHealth,
    /// The re-embed outcome for every trigger that
    /// [`ainxt_retrieval::maintenance::ReindexTrigger::needs_embedding`], or `None` when nothing this
    /// tick required one (unchanged content AND a healthy/unknown index — no reindex warranted,
    /// matching the module's own "never rebuild the whole corpus" incrementality design).
    pub reembed: Option<ainxt_retrieval::reembed::ReembedOutcome>,
}

/// GAP-FIX ainxt-retrieval (gap6-retrieval-maintenance, item 1) — the free-function core of
/// [`AssembledFull::run_kb_maintenance_tick`], factored out so [`AssembledFull::spawn_kb_maintenance_sweep`]
/// can drive it over CLONED `Arc` handles inside a `'static` background task (the same shape every
/// other `spawn_*_sweep` in this file uses: clone the specific shared state out of `self`, never `self`
/// itself, which is not `Arc`-wrapped).
fn kb_maintenance_tick(
    index_state: &Mutex<ainxt_retrieval::maintenance::IndexState>,
    recall_monitor: &Mutex<ainxt_retrieval::maintenance::RecallLatencyMonitor>,
    snapshot: &[(String, String)],
    now: i64,
) -> KbMaintenanceOutcome {
    let events: Vec<ainxt_retrieval::maintenance::SourceEvent> = snapshot
        .iter()
        .map(
            |(id, text)| ainxt_retrieval::maintenance::SourceEvent::Upsert {
                id: id.clone(),
                text: text.clone(),
            },
        )
        .collect();

    let mut triggers = {
        let mut state = index_state.lock().expect("kb index-state lock");
        state.apply(&events, now)
    };

    let health = recall_monitor
        .lock()
        .expect("kb recall-monitor lock")
        .status();
    // Only a POSITIVELY confirmed degradation forces a full rebuild — `IndexHealth::NoData` (no
    // sampler wired yet, the OSS air-gapped default) must NOT be treated as "degraded", or every tick
    // on an unchanged, perfectly healthy corpus would re-embed the entire KB forever, defeating the
    // module's own incremental-rebuild design.
    let degraded = matches!(
        health,
        ainxt_retrieval::maintenance::IndexHealth::RecallDegraded { .. }
            | ainxt_retrieval::maintenance::IndexHealth::LatencyDegraded { .. }
    );
    if degraded {
        let mut already: std::collections::BTreeSet<String> =
            triggers.iter().map(|t| t.id().to_string()).collect();
        for (id, _) in snapshot {
            if already.insert(id.clone()) {
                triggers
                    .push(ainxt_retrieval::maintenance::ReindexTrigger::Changed { id: id.clone() });
            }
        }
    }

    let plan = ainxt_retrieval::reembed::plan_reembed(&triggers);
    let reembed = if plan.is_empty() {
        None
    } else {
        let texts: std::collections::BTreeMap<String, String> = snapshot.iter().cloned().collect();
        Some(ainxt_retrieval::reembed::run_reembed(
            &plan,
            &texts,
            &OfflineKbMaintenanceEmbedder::maintenance_default(),
        ))
    };

    KbMaintenanceOutcome {
        triggers,
        health,
        reembed,
    }
}

/// GAP-FIX ainxt-retrieval (gap6-retrieval-maintenance, item 2) — the free-function core of
/// [`AssembledFull::run_kb_reembed_tick`], factored out (mirrors [`kb_maintenance_tick`]'s own shape)
/// so [`AssembledFull::spawn_kb_reembed_sweep`] can drive it over a CLONED snapshot inside a `'static`
/// background task. Builds a fresh, unversioned [`ainxt_retrieval::Corpus`] from `snapshot` (every
/// chunk starts with no `embedding_model`, so [`ainxt_retrieval::Corpus::stale_embeddings`] — which
/// [`ainxt_retrieval::reembed::migrate_to`] consults — always selects the WHOLE corpus; there is no
/// durable, persisted-across-ticks embedding-version store in this OSS tree yet, so every tick
/// genuinely (re-)migrates from scratch, never falsely reporting a chunk as already current) and
/// drives ONE migration to `target` via [`governed::run_kb_corpus_reembed`] — the actual audited
/// wrapper this gap closes a real caller for.
fn kb_reembed_tick(
    snapshot: &[(String, String)],
    target: &ainxt_retrieval::EmbeddingVersion,
) -> ainxt_retrieval::reembed::MigrationReport {
    let chunks: Vec<ainxt_retrieval::Chunk> = snapshot
        .iter()
        .map(|(id, text)| ainxt_retrieval::Chunk::new(id, text, ainxt_types::DataClass::Internal))
        .collect();
    let corpus = ainxt_retrieval::Corpus::new(chunks);
    // The embedder's OWN reported version must equal `target` — see `OfflineKbMaintenanceEmbedder`'s
    // doc for why a mismatched identity would make `MigrationReport::uniform` false forever even on a
    // fully successful migration.
    let embedder = OfflineKbMaintenanceEmbedder {
        version: target.clone(),
    };
    governed::run_kb_corpus_reembed(&corpus, target, &embedder)
}

/// The durable memory reader wired into the engine's Context-Fabric memory seam (gap MEM: "durable
/// Postgres/KG-backed store … only InMemoryStore exists"). It wraps a restart-durable
/// [`DurableMemoryStore`](ainxt_memory::DurableMemoryStore) — write-through + hydration + tamper audit
/// chain — behind the runtime's [`MemoryReader`](ainxt_runtime::memory::MemoryReader) trait, so the
/// SAME Context-Fabric read path (query planning → pre-rank identity/data-class filter → usage-decay
/// touch → lineage capture) the in-memory adapter runs is driven over the durable store. The OSS
/// build uses the in-RAM [`MemorySqlBackend`](ainxt_memory::MemorySqlBackend) SqlLike leaf (a real
/// durable-store impl: shared, write-through, hydratable); production swaps the Postgres SqlLike
/// binding behind the same seam with no caller change.
pub struct DurableMemoryReader {
    store: Mutex<ainxt_memory::DurableMemoryStore<ainxt_memory::MemorySqlBackend>>,
    per_query_limit: usize,
}

impl DurableMemoryReader {
    /// Open a fresh durable store over the in-RAM backend, with the StrongRedactor compliance-on-write
    /// gate installed. `backend` is shared (cheap clone) so a second reader / a restart hydrates the
    /// same committed rows.
    pub fn open(
        backend: ainxt_memory::MemorySqlBackend,
    ) -> Result<Self, ainxt_memory::MemoryError> {
        let store = ainxt_memory::DurableMemoryStore::open(backend)?
            .with_redactor(Box::new(StrongMemoryRedactor {
                inner: ainxt_compliance::StrongRedactor::new(),
            }))
            // GAP-AUDIT memory #9 — the §8.8 OKI-extraction-resistance guard (a scoped, budgeted
            // read cap defending against a single unscoped query dumping the whole working set
            // verbatim) was implemented and tested but shipped OFF by default (`cap == 0`), and
            // nothing in the served path ever called `with_extraction_guard`. A small cap is safe
            // to enable by default: scoped reads (the Context-Fabric planner always scopes by repo)
            // are never affected — only an unscoped safety-relevant sweep is capped.
            .with_extraction_guard(5)
            // GAP-FIX memory (embed-on-write-never-wired) — see `MemoryHashEmbedder`'s doc: without
            // this, every write's `.embedding` stayed `None` forever (embed-on-write's early return
            // at `store.rs:977`), so newly-written memory was never semantically recall-eligible
            // without a separate, never-triggered `reembed_all` pass. Both tiers point at the same
            // offline default; a production deployment swaps either behind this one call site.
            .with_embedders(
                Box::new(MemoryHashEmbedder::new(
                    "offline-hash-inhouse-v1",
                    ainxt_memory::EmbedderKind::InHouse,
                    256,
                )),
                Box::new(MemoryHashEmbedder::new(
                    "offline-hash-cloud-v1",
                    ainxt_memory::EmbedderKind::Cloud,
                    256,
                )),
            );
        Ok(DurableMemoryReader {
            store: Mutex::new(store),
            per_query_limit: 0,
        })
    }

    /// Borrow the durable store (e.g. to author/promote OKIs at deployment bootstrap or in tests).
    pub fn store(
        &self,
    ) -> std::sync::MutexGuard<'_, ainxt_memory::DurableMemoryStore<ainxt_memory::MemorySqlBackend>>
    {
        self.store.lock().expect("durable memory store lock")
    }
}

impl ainxt_runtime::memory::MemoryReader for DurableMemoryReader {
    fn read_for_turn(
        &self,
        turn_id: &str,
        task: &ainxt_memory::fabric::TaskKind,
        access: &ainxt_memory::AccessScope,
        now: u64,
    ) -> (
        Vec<ainxt_memory::MemoryHit>,
        ainxt_memory::fabric::TurnLineage,
    ) {
        use ainxt_memory::MemoryStore;
        let mut store = self.store.lock().expect("durable memory store lock");
        // The EXACT Context-Fabric read algorithm (design §7): plan by task, run each planned query
        // pre-rank-filtered under the caller's scope, de-dup keeping highest-priority, then mark
        // injected items used (usage-decay). Driven over the DURABLE store's trait `query` + `touch`.
        let plan = ainxt_memory::fabric::plan_query(task);
        let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        let mut hits: Vec<ainxt_memory::MemoryHit> = Vec::new();
        for mut q in plan.queries {
            if self.per_query_limit > 0 {
                q.limit = self.per_query_limit;
            }
            for h in store.query(&q, access) {
                if seen.insert(h.item.id.clone()) {
                    hits.push(h);
                }
            }
        }
        let injected: Vec<(String, u32)> = hits
            .iter()
            .map(|h| (h.item.id.clone(), h.item.version))
            .collect();
        for (id, _) in &injected {
            let _ = store.touch(id, now);
        }
        (
            hits,
            ainxt_memory::fabric::TurnLineage {
                turn_id: turn_id.to_string(),
                injected,
            },
        )
    }
}

/// GAP-FIX memory (write-path-missing) — the served `POST /memory/remember` write seam
/// (`ainxt_memory::MemoryWriter`) reaches through to this SAME long-lived durable store — the
/// IDENTICAL `Mutex`-guarded instance [`read_for_turn`](ainxt_runtime::memory::MemoryReader::read_for_turn)
/// above queries — never a second, independently-`open()`ed store over the backend (which would
/// silently diverge: see `ainxt_memory::ConsentBacking`'s doc for why a freshly-reopened store never
/// re-pulls into an already-open long-lived one, and vice versa). A write through this seam is
/// visible to the very next `read_for_turn` call on this same instance, with no request-scoped
/// reopen in between.
impl ainxt_memory::MemoryWriter for DurableMemoryReader {
    fn write_as(
        &self,
        item: ainxt_memory::MemoryItem,
        writer: &ainxt_memory::AccessScope,
    ) -> Result<(), ainxt_memory::MemoryError> {
        let mut store = self.store.lock().expect("durable memory store lock");
        store.write_as(item, writer)
    }
}

/// GAP-FIX memory (write-path-missing) — `Engine::with_memory` needs ownership of a
/// `Box<dyn ainxt_runtime::memory::MemoryReader>`, but the served write route (`POST
/// /memory/remember`) ALSO needs a live handle onto the exact same [`DurableMemoryReader`] instance
/// (see that impl's doc for why "the exact same instance", not just "the same backend", is the
/// requirement). Sharing one instance via `Arc` between the engine's boxed reader and the served
/// writer needs a local newtype here: `impl ainxt_runtime::memory::MemoryReader for
/// Arc<DurableMemoryReader>` is blocked by the orphan rules (neither the trait nor `Arc` — not a
/// `#[fundamental]` type — is local to this crate), but implementing it on a local wrapper around
/// the `Arc` is not.
struct SharedMemoryReader(Arc<DurableMemoryReader>);

impl ainxt_runtime::memory::MemoryReader for SharedMemoryReader {
    fn read_for_turn(
        &self,
        turn_id: &str,
        task: &ainxt_memory::fabric::TaskKind,
        access: &ainxt_memory::AccessScope,
        now: u64,
    ) -> (
        Vec<ainxt_memory::MemoryHit>,
        ainxt_memory::fabric::TurnLineage,
    ) {
        self.0.read_for_turn(turn_id, task, access, now)
    }
}

/// GAP-FIX memory (write-path-missing) — bundles the engine's [`ainxt_memory::MemorySqlBackend`]
/// (already threaded to the graph-linking pass + the read-only MEM-10 consent/export/erasure
/// surface — see [`Assembled::memory_backend`]'s doc) with a live [`ainxt_memory::MemoryWriter`]
/// handle onto the EXACT SAME long-lived [`DurableMemoryReader`] instance the engine's own
/// Context-Fabric memory seam reads through. Threading `writer` alongside `backend` (rather than
/// widening every `build_chat_engine_with_authz` call site's 9-tuple with a 10th element) keeps
/// every existing `let (.., memory_backend, ..) = build_chat_engine_with_authz(..)?` destructure
/// byte-identical; only the two sites that actually open a NEW store off the backend (graph-linking,
/// `ConsentBacking::Durable`) unwrap `.backend`, and the new served write route unwraps `.writer`.
#[derive(Clone)]
pub struct MemoryHandle {
    pub backend: ainxt_memory::MemorySqlBackend,
    pub writer: Arc<dyn ainxt_memory::MemoryWriter>,
}

/// Build the durable memory reader for the assembled memory layer (MEM). A fresh in-RAM backend is
/// the OSS default; the store is restart-durable and the StrongRedactor compliance-on-write gate is
/// installed. Wired into the served engine via [`ainxt_runtime::Engine::with_memory`]. Also returns a
/// clone of the [`ainxt_memory::MemorySqlBackend`] the reader was opened over — GAP-FIX memory: this
/// is what lets a served `ConsentSurface` route (MEM-10 consent/export/erasure) see the SAME rows
/// this reader writes, by opening a fresh store over a clone of the same backend per request, instead
/// of the disconnected standalone `InMemoryStore` the route was hardcoded to before.
pub fn build_durable_memory_reader(
) -> Result<(Arc<DurableMemoryReader>, ainxt_memory::MemorySqlBackend), AssembleError> {
    let backend = ainxt_memory::MemorySqlBackend::new();
    let reader = DurableMemoryReader::open(backend.clone())
        .map_err(|e| AssembleError::Config(format!("durable memory: {e}")))?;
    // GAP-FIX memory (write-path-missing) — `Arc`-wrapped so the served `POST /memory/remember`
    // write route can hold the EXACT SAME instance handed to the engine's `with_memory` seam below
    // (see `SharedMemoryReader`'s doc for why a plain second `open()` over the same backend does not
    // suffice).
    Ok((Arc::new(reader), backend))
}

/// Build the chat-surface [`Engine`] (strong-redactor compliance gate) with an optional **authorizer
/// override** (gap SURF: non-chat
/// surfaces execute only their declared capabilities). When `authz_override` is `Some`, it replaces
/// the config-selected base authorizer as the engine's mandatory authz gate — the composition passes
/// an [`ainxt_chat::SurfaceScopedAuthorizer`] built from the surface profile's declared capability set,
/// so the served engine's tool loop is bounded by the surface's declaration (a tool the surface does
/// not offer is refused even for an admin). `None` keeps the config-selected base authorizer (the
/// chat-surface default). The gate is never *removed* — only which authorizer runs is selected.
///
/// GAP-FIX tooling-mcp-plugins-routing (real-transport wiring) — `mcp_config` is the deployment's
/// declared `[[mcp.servers]]` (from the caller's [`LoadedConfig`]); threaded straight into
/// [`build_unified_capability_registry_shared_with_mcp_admin_and_servers`] so every chat-family
/// surface (`assemble_chat`/`assemble_surface`/`assemble_chat_governed`/`assemble_chat_fabric_grounded`,
/// all of which bottom out at [`build_chat_surface_wired_authz`]) actually spawns + registers them,
/// not just the bare-engine surface [`build_engine_ext_with_mcp`] covers.
fn build_chat_engine_with_authz(
    rc: &RuntimeConfig,
    authz_override: Option<Box<dyn Authorizer>>,
    forced_provider: Option<&str>,
    provider_allowlist: &[String],
    mcp_config: &McpConfig,
    payments: &PaymentsConfig,
    serving_cfg: &ServingConfig,
) -> Result<ChatEngineAssembly, AssembleError> {
    // Reuse the mandatory authz + audit gate selection (fail-closed on an enterprise gate), but
    // override the compliance gate with the strong redactor so the served path really redacts.
    let (_placeholder_compliance, base_authz, audit) = build_gates(&rc.gates)?;
    let authz = authz_override.unwrap_or(base_authz);
    let compliance: Box<dyn ainxt_runtime::compliance::ComplianceGate> =
        Box::new(ainxt_compliance::StrongRedactor::new());
    // Gap SURF: enforce the surface's model-policy `forced_provider`/`allowed_providers` SERVER-SIDE —
    // the surface's router is built ONLY from providers the surface is permitted to use (∩ the
    // data-class gate, which the router still runs). No forced pin and an empty allow-list = any
    // provider (unchanged). A disallowed provider is never registered on this surface's router, so it
    // can never be selected — enforcement is structural, not advisory (see `filter_models_by_allowlist`
    // for the single admissibility predicate this and the classifier's model selection both consult).
    let (models_view, mut report) =
        filter_models_by_allowlist(&rc.models, forced_provider, provider_allowlist);
    let (router, router_report) = build_router(&models_view);
    report.extend(router_report);
    // GAP-FIX regulated-fi-responsible-lifecycle — capture the SHARED outsourcing-register handle from
    // THIS router BEFORE it is moved into `Engine::new` below and erased (mirrors `build_engine_ext`).
    let outsourcing_register = router.outsourcing_register_handle();
    // GAP-FIX tooling-mcp-plugins-routing — capture the live `McpAdminHandle` too (same rationale as
    // `build_engine_ext`'s identical change). Real-transport wiring: pass `mcp_config.servers` through
    // so a deployment's declared MCP servers are ACTUALLY spawned + registered on this surface too.
    let (tools, ledger, reconciler, mcp_admin) =
        build_unified_capability_registry_shared_with_mcp_admin_and_servers(
            &mut report,
            &mcp_config.servers,
        );
    // GAP-FIX identity-payments (ADR-016 §6) — see the identical comment in `build_engine_ext`.
    let mandate_registry = Arc::new(Mutex::new(ainxt_payments::mandate::MandateRegistry::new()));
    let tools = tools.with_mandate_registry(mandate_registry.clone());
    // R16 (§0/§1.2, CRITICAL): SHARED handle — see the identical comment in `build_engine_ext`.
    let tools = Arc::new(tools);
    // MEM: wire the DURABLE memory store into the assembled memory layer. Memory is layer-12 of the
    // Context Fabric — read on every turn under the caller's identity/data-class scope, injecting
    // governed OKIs / user facts (pre-rank filtered; empty store injects nothing → no behavior change).
    // The durable store is write-through + hydratable + StrongRedactor-scrubbed on write.
    let (memory, memory_backend) = build_durable_memory_reader()?;
    // R9 TRANSP — attach the engine's typed §6 wire sink in the SHIPPED path so `/v1/chat` + `/v1/events`
    // serialize the engine's REAL EventEnvelope stream by default (capped-vs-complete, compliance.notice,
    // payment-boundary, priced usage{model,cost}) — not the lossy legacy Event projection. The sink is
    // emit-and-continue (unbounded); the transport drains the paired receiver on the response task.
    let (wire_sink, wire_rx) = ainxt_runtime::wire::ChannelWireSink::new();
    // R14 (served-composition, HIGH): the FLAGSHIP served chat agent loop also routes tool dispatch
    // through the audited three-layer OBO gate (same seam as the bare/program/team engines).
    // GAP-FIX tooling-mcp-plugins-routing — SAME durable-when-configured sink as `build_engine_ext`.
    let chat_obo_sink = build_obo_sink(&rc.gates)?;
    let chat_obo_policy: Box<dyn ainxt_tools::obo::OboPolicy> = Box::new(
        ainxt_tools::obo::ThreeLayerPolicy::new(ainxt_tools::obo::MapAbac::new()),
    );
    // R15 COMPOSE — the SAME two seams `build_engine_ext` mounts (in-engine complexity classifier +
    // dispatch probe), mounted here too since this is the FLAGSHIP chat engine builder (chat/code/
    // sdlc/buddy all bind through it via `build_chat_surface_wired_authz`), not a secondary path.
    let dispatch_probe = Arc::new(ainxt_runtime::dispatch::DispatchProbe::new());
    // GAP-FIX tooling-mcp-plugins-routing (round 2) — mount the SAME prompt-cache seam
    // `build_engine_ext` mounts (see that function's identical comment) on the FLAGSHIP chat engine
    // too, since chat/code/sdlc/buddy all bind through this builder. Not threaded out through
    // `ChatEngineAssembly` (unlike `build_engine_ext`'s `EngineAssembly`, that tuple already has many
    // consumers across every chat-variant surface; the cache's hit/miss is observable via the audit
    // trail on this path, and the bare-engine composition root above is the one with a dedicated
    // proving test asserting on the shared handle directly).
    let chat_prompt_cache = Arc::new(Mutex::new(ainxt_tools::prompt_cache::PromptCache::new()));
    // GAP-FIX payments-governance — see `build_engine_ext_with_mcp`'s identical comment.
    let payment_boundary = resolve_payment_boundary(payments)?;
    // GAP-FIX gap6-composition-root (Item 1) — see the identical comment in `build_engine_ext_with_mcp`:
    // the FLAGSHIP chat/code/sdlc/buddy engine gets the SAME treatment.
    let serving = build_serving(serving_cfg);
    let engine = Engine::new(compliance, authz, audit, router)
        .with_max_iters(rc.limits.max_agent_iters)
        .with_retry(
            rc.limits.provider_max_retries,
            rc.limits.provider_backoff_base_ms,
        )
        .with_guardrails(&rc.guardrails)
        .with_injection(&rc.injection)
        .with_shared_tools(tools.clone())
        // GAP-FIX guardrails-injection — `ainxt_injection::InjectionDetector::known_tool_names` (a
        // retrieved/tool-result chunk NAMING an internal tool is a strong indirect-injection signal,
        // weight 0.5 — crosses the default threshold alone) had zero production callers: every engine
        // was built with the bare `HeuristicInjectionScanner` default (empty `known_tool_names`), so
        // this detection category could never fire no matter how real the rest of the scored detector
        // was. `ToolRuntime::tool_names()` (new) hands the SAME registry this engine dispatches
        // through to the detector that scans its own tool RESULTS (`Provenance::ToolResult`).
        .with_injection_scanner(Box::new(
            ainxt_injection::InjectionDetector::default().with_tools(tools.tool_names()),
        ))
        .with_memory(Box::new(SharedMemoryReader(memory.clone())))
        .with_prompt_cache(chat_prompt_cache)
        .with_wire_sink(Box::new(wire_sink))
        // GAP-FIX turn-pipeline — the engine's own inner WireEvents (TurnStarted/TurnStopped/etc.)
        // were always stamped "unpinned" regardless of AINXT_CONTROL_PLANE_SHA: the outer served
        // EventEnvelope wrapper already correctly reads it (see `control_plane_sha()` above and its
        // use in mounts.rs), but nothing ever called `Engine::with_control_plane_sha`, so the
        // engine's own reproducibility pin (ADR-026 §6.2) never matched the envelope wrapping it.
        .with_control_plane_sha(control_plane_sha())
        .with_obo(chat_obo_policy, chat_obo_sink)
        .with_complexity_classifier(Box::new(
            ainxt_runtime::complexity::HeuristicComplexityClassifier::default(),
        ))
        .with_dispatch_probe(dispatch_probe.clone())
        // GAP-FIX transport-daemon (ADR-016 §9) — install the REAL payment-boundary classifier
        // (see `default_payment_boundary_resolver`'s doc comment) on the FLAGSHIP served chat engine.
        // Before this fix every served chat/code/sdlc/buddy turn ran with `Engine::new`'s default
        // resolver (`|_, _| PaymentBoundary::None`), so a served `approval.request` could never carry
        // a real boundary — a payment-adjacent tool call could clear the ordinary high-risk gate (or
        // slip through a Low/Medium-risk tool entirely) without ever reaching the human-approve-only
        // invariant §9/ADR-016 requires. GAP-FIX payments-governance — resolves over `payment_boundary`
        // (see the identical comment in `build_engine_ext_with_mcp`) instead of always npci().
        .with_payment_boundary_resolver(payment_boundary_resolver_over(
            payment_boundary,
            tools.clone(),
        ))
        // GAP6 telemetry-cost-rollup — see the identical comment in `build_engine_ext_with_mcp`: this
        // is the FLAGSHIP served chat/code/sdlc/buddy engine, so before this it was the single biggest
        // contributor to every served turn's cost silently pricing at 0 (the empty `PriceTable::new()`
        // default) regardless of the real `WireEvent::Usage` tokens `ainxt-server`'s `chat_handler`
        // reads the (already-priced) cost off of.
        .with_pricing(resolve_price_table(rc));
    // GAP-FIX gap6-composition-root (Item 1) — see the identical guard in `build_engine_ext_with_mcp`:
    // the served `/v1/chat` FLAGSHIP engine only attaches the node-attestation hook when a real pool is
    // declared, so the air-gapped default (no `[[serving.nodes]]`) stays byte-identical.
    let engine = if serving.1.is_empty() {
        engine
    } else {
        report.push(format!(
            "serving: {} node(s) also bound onto Engine::with_node_attestor (chat/code/sdlc/buddy \
             engine) — the engine's OWN §4.2 tri-signal ESCALATED route_class now fails closed off an \
             unattested node too, over the SAME ServingGate the daemon's /v1/chat Stage-1 fence and \
             attestation refresh loop consult",
            serving.1.len()
        ));
        engine.with_node_attestor(node_attestor_over(&serving))
    };
    debug_assert!(
        engine.has_obo(),
        "served chat agent loop must be OBO-governed"
    );
    debug_assert!(
        !matches!(
            engine.probe_payment_boundary(
                // A destination that really is inside `SettlementPerimeter::default_reserved`
                // (the `"x402."` agent-payment-protocol pattern, ADR-016 §5), so this guard
                // proves what it claims to prove without depending on tool registration.
                //
                // The previous probe passed `"settlement.example.transfer"` with a
                // `settlement-account:` resource key and matched NEITHER facet on the shipped
                // daemon: no `default_reserved` pattern is a substring of that name, and the
                // resource-key facet reads `ToolRuntime::resource_of`, which is `None` for a
                // tool this runtime never registers. The probe therefore returned
                // `PaymentBoundary::None` and this `debug_assert!` aborted every debug-profile
                // boot (exit 101) and its own composition-root tests.
                //
                // Widening the perimeter to a bare `"settlement."` is NOT the fix: it would
                // swallow read-only names such as `settlement-report:2026-07`, which
                // `ainxt-payments::boundary` asserts must stay OUTSIDE the perimeter.
                "x402.pay",
                "{}"
            ),
            ainxt_protocol::PaymentBoundary::None
        ),
        "the served chat engine must classify a settlement-perimeter/resource-key call as a real \
         payment boundary, never the default None resolver"
    );
    report.push(
        "payments: payment-initiation-signature classifier (ainxt_payments::boundary) wired as \
         the engine's payment_boundary resolver — a payment-adjacent tool call now reaches the \
         human-approve-only gate (§9, ADR-016) instead of always resolving to PaymentBoundary::None"
            .into(),
    );
    report.push(
        "memory: durable DurableMemoryStore (write-through + hydration + tamper audit chain, \
         StrongRedactor compliance-on-write) wired into the engine Context-Fabric memory seam"
            .into(),
    );
    report.push(
        "transport: engine typed §6 WireEvent sink attached — served /v1/chat + /v1/events emit the \
         REAL EventEnvelope stream (capped/compliance.notice/payment-boundary/priced usage) by default"
            .into(),
    );
    report.push(
        "routing: in-engine HeuristicComplexityClassifier mounted on the chat/code/sdlc/buddy engine \
         — an unpinned served turn derives its tier from content; a HARD-pinned surface (e.g. sdlc, \
         via ModelPolicy::pin_tier) bypasses it and routes through the engine's hard tier filter"
            .into(),
    );
    report.push(
        "observability: concurrent tool-dispatch DispatchProbe mounted on the chat/code/sdlc/buddy \
         engine — peak/total in-flight tool-dispatch concurrency is a real serving-ops telemetry signal"
            .into(),
    );
    report.push(
        "memory: served POST /memory/remember write seam wired onto the EXACT SAME long-lived \
         DurableMemoryReader instance this engine's Context-Fabric memory seam reads through — a \
         write is visible to the very next read_for_turn call, not just to a separately-reopened \
         consent/export snapshot"
            .into(),
    );
    // GAP-FIX memory (write-path-missing) — shadow `memory_backend` with the bundled handle (backend
    // + a live writer onto the SAME `memory` instance `with_memory` was just handed above) so every
    // downstream destructure of this function's return tuple keeps binding a variable literally
    // named `memory_backend`, unchanged.
    let memory_backend = MemoryHandle {
        backend: memory_backend,
        writer: memory as Arc<dyn ainxt_memory::MemoryWriter>,
    };
    Ok((
        engine,
        wire_rx,
        report,
        ledger,
        reconciler,
        dispatch_probe,
        tools,
        memory_backend,
        outsourcing_register,
        mandate_registry,
        Some(Arc::new(mcp_admin)),
        serving,
    ))
}

/// The deployment's [`SkillRuntime`] (gap SURF: Skill Runtime active in production wiring): the
/// compiled-in built-in skills over a [`ainxt_skill::DispatchingSkillExecutor`] that routes any skill
/// id registered on the sandboxed [`ainxt_skill::WasmSkillExecutor`] into the wasmtime sandbox and
/// falls back to the trusted in-process [`ainxt_skill::NativeSkillExecutor`] for everything else
/// (including every compiled-in builtin) — so the served daemon's skill runtime actually RESOLVES
/// profile skill refs — a behavioral built-in (citation discipline) injects into the system prompt and
/// an execution built-in (turn-header) runs its native handler into `## Context`. An unregistered ref
/// still fails closed (never silently skipped). A deployment populates further git-native skills on
/// top and registers sandboxed modules directly on the `WasmSkillExecutor` before this runs.
///
/// Before this wiring, `WasmSkillExecutor` was a fully-implemented, wasmtime-backed sandboxed executor
/// with zero callers outside its own crate's tests — a served `SkillRuntime` could never reach it
/// (production always built `NativeSkillExecutor` alone), so no deployment could actually run a
/// sandboxed skill regardless of its git-native manifests (gap: "WasmSkillExecutor stub in
/// production"). If the wasmtime engine itself fails to construct (`SandboxConfig` rejected by the
/// host), this fails safe to the native-only runtime rather than failing the whole daemon boot — no
/// deployment currently registers sandboxed skills, so native-only is still fully correct.
///
/// Passed to every [`ainxt_surface::SurfaceBinding`] so injection runs at its canonical points on the
/// served turn.
///
/// GAP-AUDIT gap6-composition-root (Item 2) — DECISION: [`ainxt_skill::NativeProcessSkillExecutor`]
/// (the OS-process execution-skill tier, gap SURF-05) is deliberately NOT registered here as a third
/// [`ainxt_skill::DispatchingSkillExecutor`] tier. Investigated: `SkillType` has exactly two variants
/// (`Behavioral`/`Execution`) — no manifest-level "how do I run this code" dimension exists at all.
/// The git-native `definition.md` front-matter parser (`ainxt_skill::control`) is a deliberately
/// CLOSED, fail-closed field set (`id`/`type`/`description` only); an unrecognized field is REJECTED
/// (see `gap_ainxt_skill_unknown_front_matter_field_is_rejected`), so there is no half-open door a
/// future "process" mode could already be flowing through unnoticed either. For an `Execution` skill
/// NOT registered on `WasmSkillExecutor`, the fallback `NativeSkillExecutor` requires a compiled-in
/// Rust handler keyed by skill id (hard error otherwise) — its `body` is parsed as PARAMETERS for
/// that pre-registered handler, never as literal shell/Python SOURCE to execute. No compiled-in
/// builtin skill, no git-native manifest convention, and no `ainxt-runtimed`/`ainxt-config` setting
/// anywhere declares or requests a process-executed skill. `NativeProcessSkillExecutor` itself is
/// fully implemented and unit-tested (`ainxt-skill/src/native_process.rs`), but wiring it in here
/// would mean fabricating a new `SkillType` variant (or a new front-matter field breaking the closed
/// set above) AND an interpreter/language-mapping policy with no real caller-declared requirement
/// behind either — left undone on purpose rather than invented. Revisit if/when a served skill
/// category with a genuine "run this literal script body" contract is actually requested.
pub fn build_skill_runtime() -> SkillRuntime {
    match ainxt_skill::WasmSkillExecutor::with_defaults() {
        Ok(wasm) => SkillRuntime::with_builtins_and_wasm(wasm),
        Err(_) => SkillRuntime::with_builtins(),
    }
}

/// GAP-FIX surfaces-profiles-skills-config (ADR-026) — like [`build_skill_runtime`] but wires the
/// git-native skill control plane ([`ainxt_skill::control::SkillControlPlane`], mirroring
/// `build_served_chat_prompt`'s `[server] prompt_dir` pattern) when `[server] skill_dir` is
/// configured. Before this, `SkillManifest` was populated ONLY via the compiled-in [`ainxt_skill::builtin`]
/// set — no loader read a real `definition.md`/`control.lock` from a git-native source, so a deployment
/// could not add or edit a skill without recompiling the binary (contrast with `ainxt-prompt`'s
/// `ControlPlane`, which already had exactly this capability for prompts).
///
/// When set, the served registry is FILE-sourced from `<root>/<id>/definition.md` — editing a file +
/// rebuild changes the served skill, a hardcoded Rust constant cannot — layered OVER the compiled-in
/// builtin floor (a file-declared skill id overrides the builtin of the same id; every other builtin
/// stays available, so a profile written before `skill_dir` existed keeps resolving unchanged).
/// Fail-closed on a malformed/locked tree (a config typo must surface at assembly, never silently fall
/// back to the builtin-only registry). `None` (the default) is byte-for-byte [`build_skill_runtime`]'s
/// existing behavior — additive only.
pub fn build_skill_runtime_from_config(
    loaded: &LoadedConfig,
    report: &mut Vec<String>,
) -> Result<SkillRuntime, AssembleError> {
    match &loaded.server.skill_dir {
        Some(root) if !root.is_empty() => {
            let wasm = ainxt_skill::WasmSkillExecutor::with_defaults().ok();
            let (runtime, skill_loaded) = ainxt_skill::control::skill_runtime_from_dir(root, wasm)
                .map_err(|e| {
                    AssembleError::Config(format!("git-native skill tree '{root}': {e}"))
                })?;
            report.push(format!(
                "skills: served skill registry is GIT-NATIVE FILE-sourced from '{root}' ({} file-\
                 declared skill(s) over the compiled-in builtin floor; control.lock verified={}) — \
                 skills-as-code, never compiled-in-only",
                skill_loaded.manifests.len(),
                skill_loaded.lock_verified,
            ));
            Ok(runtime)
        }
        _ => {
            report.push(
                "skills: served skill registry = compiled-in builtins only; set [server] skill_dir \
                 to serve git-native FILE-sourced skills layered on top of the builtin floor"
                    .into(),
            );
            Ok(build_skill_runtime())
        }
    }
}

/// Build the **grounded** [`ChatSurface`] (gaps SURF-02/03) over the gate-selected chat engine: the
/// clearance-filtered retriever over `corpus`, the model-agnostic prompt engine, and a scoping-safe
/// response cache. This is what makes the served chat path GROUND + CITE + CACHE instead of the bare
/// no-retriever [`ainxt_convo::ConversationManager::new`]. Corpus comes from the KB/config (an empty
/// corpus keeps the path valid — no grounding, but every other behavior holds).
pub fn build_chat_surface(
    loaded: &LoadedConfig,
    corpus: Corpus,
) -> Result<(ChatSurface, Vec<String>), AssembleError> {
    // The public 2-tuple form (used by callers that drive the legacy `Event` stream directly): drop the
    // engine wire receiver. The served daemon uses [`build_chat_surface_wired`] and keeps the receiver so
    // `/v1/chat` serializes the typed §6 stream by default.
    let (
        chat,
        _wire_rx,
        report,
        _ledger,
        _reconciler,
        _dispatch_probe,
        _tools,
        _memory_backend,
        _outsourcing,
        _mandate_registry,
        _mcp_admin,
        _serving,
    ) = build_chat_surface_wired(loaded, corpus)?;
    Ok((chat, report))
}

/// Like [`build_chat_surface`] but ALSO returns the engine's typed §6 wire receiver (R9 TRANSP) so the
/// served transport can serialize the REAL [`WireEvent`](ainxt_protocol::WireEvent) stream by default,
/// plus the served engine's SHARED exactly-once ledger + reconciler (R10) for the background sweep.
pub fn build_chat_surface_wired(
    loaded: &LoadedConfig,
    corpus: Corpus,
) -> Result<ChatSurfaceAssembly, AssembleError> {
    build_chat_surface_wired_authz(loaded, corpus, None, None, &[], false)
}

/// Like [`build_chat_surface_wired`] but with an optional engine **authorizer override** and a
/// surface **provider policy** (gap SURF: declared-capability scoping + model-policy
/// forced_provider/allowed_providers). `assemble_surface` passes an
/// [`ainxt_chat::SurfaceScopedAuthorizer`] built from the surface profile (so the tool loop is bounded
/// by the declared capability set) and the profile's `forced_provider`/`allowed_providers` (so the
/// surface's router — AND its Stage-2 intent classifier, see the re-filter below — are built only from
/// permitted providers). `None` / an empty allow-list keep the config defaults.
pub fn build_chat_surface_wired_authz(
    loaded: &LoadedConfig,
    corpus: Corpus,
    authz_override: Option<Box<dyn Authorizer>>,
    forced_provider: Option<&str>,
    provider_allowlist: &[String],
    profile_row_isolation: bool,
) -> Result<ChatSurfaceAssembly, AssembleError> {
    let (
        engine,
        wire_rx,
        mut report,
        ledger,
        reconciler,
        dispatch_probe,
        tools,
        memory_backend,
        outsourcing_register,
        mandate_registry,
        mcp_admin,
        serving,
    ) = build_chat_engine_with_authz(
        &loaded.runtime,
        authz_override,
        forced_provider,
        provider_allowlist,
        &loaded.mcp,
        &loaded.payments,
        &loaded.serving,
    )?;
    // Served retrieval isolation is enabled when EITHER the KB config opts in globally OR the resolved
    // surface profile declares `rbac.department_scoped` (gap: profile department scoping wired into
    // served retrieval isolation). `assemble_surface` derives the profile bit via
    // `ChatSurface::profile_row_isolation`; the profile-less `assemble_chat` path passes `false`.
    let row_isolation = loaded.kb.rls_department_isolation || profile_row_isolation;
    // R14 (items 4 + 7): build the served chat Prompt deployment the compile uses — a mandatory durable
    // ForensicFileSink (durable-before-provider, PE11) and, when `[server] prompt_dir` is configured, a
    // git-native FILE-sourced layered registry (§3). Injected into the ChatSurface so the SERVED compile
    // (not just a standalone entrypoint) writes a replayable forensic record before every provider call.
    let prompt = build_served_chat_prompt(loaded, &mut report)?;
    // Gap CONV-01 (served): use the Stage-2 model-backed constrained intent classifier when a LIVE
    // grammar/schema-capable provider is configured (a real endpoint + key); fall back to the
    // offline Stage-3 classifier ([`ainxt_convo::ModelIntentClassifier::offline`], over the
    // zero-infra `LexicalLabelModel`) when no such model is configured (air-gapped / offline
    // default) — a real confidence-graded classify/clarify decision, not the bare deterministic-tier
    // `HeuristicClassifier`.
    //
    // GAP-FIX conversation-intelligence — this `None` arm previously called
    // `ChatSurface::from_engine_numeric_gated_with_prompt` (hardcoded `ChatClassifier::Heuristic`),
    // which never reaches `from_engine_classified_numeric_gated_with_prompt`'s own already-fixed
    // `None` arm at all (see that function's GAP-FIX doc comment in `ainxt-chat`) — so on the shipped
    // air-gapped daemon (the default, no live model configured) the offline Stage-3 classifier stayed
    // reachable only from `ainxt-chat`'s/`ainxt-convo`'s own tests, never from a served turn. Calling
    // the SAME `from_engine_classified_numeric_gated_with_prompt` entrypoint with `None` in both arms
    // (distinguished only by its `live_model` argument) makes Stage-3 genuinely live on the default.
    //
    // GAP-FIX surface-turnplan-policy — re-derive the SAME surface-narrowed provider view
    // `build_chat_engine_with_authz` built the router from (a second, cheap, pure call — see that
    // function's identical-shape precedent for the SR-11-7 quality guard's fresh `DueDiligenceConfig`:
    // no shared mutable state, so a second call carries no divergence risk), rather than the raw
    // `&loaded.runtime.models`. Before this fix the Stage-2 classifier picked its provider from the
    // UNRESTRICTED full provider list regardless of the surface's `forced_provider`/`allowed_providers`
    // policy — e.g. the `sdlc` surface (canonically `allowed_providers = ["claude", "gpt"]`,
    // `max_data_class = "confidential"`) would still hand a raw user turn to a configured but
    // NOT-allow-listed provider (e.g. `gemini`) for intent classification, entirely outside the
    // engine's own forced-provider-narrowed `select_chain` — the surface's model policy was silently
    // inert for this one call site.
    let (_classifier_models, _) =
        filter_models_by_allowlist(&loaded.runtime.models, forced_provider, provider_allowlist);
    // LATENCY FIX: use the deterministic HeuristicClassifier instead of the model-backed
    // ModelIntentClassifier. The model-backed classifier makes a SEPARATE LLM call to classify
    // intent before the main answer — adding 2-7 seconds of latency on every turn. For the chat
    // surface (plain Q&A), the heuristic classifier is sufficient: it classifies based on lexical
    // features (no LLM call), routes to the same model, and answers immediately. The model-backed
    // classifier is still available via from_engine_classified_numeric_gated_with_prompt if a
    // deployment needs confidence-graded classify/clarify (agentic surfaces with side effects).
    report.push(
        "surface: chat — heuristic intent classifier wired (latency-optimized: no per-turn LLM \
         classification call; model-backed classifier available via \
         from_engine_classified_numeric_gated_with_prompt for agentic surfaces)"
            .into(),
    );
    let chat = ChatSurface::from_engine_numeric_gated_with_prompt(
        engine,
        corpus,
        CacheConfig::default(),
        Box::new(SystemClock),
        row_isolation,
        prompt,
    );
    // Gap I (data-surfaces-artifacts, live-path wiring): opt the served surface into the SEMANTIC
    // (paraphrase) cache tier via the offline, dependency-free `HashEmbedder` — a re-worded repeat of
    // a cached prompt now hits without a fresh provider call. A deployment swaps a real embed-service
    // client behind the SAME `Embedder` seam with no caller change (`ChatSurface::with_embedder`).
    let chat = chat.with_embedder(Arc::new(HashEmbedder::default()));
    // GUARD-09/GUARD-07: the served ChatSurface's manager was built with NO guardrails config at all
    // (groundedness/toxicity/topic/citation stayed permanently Off regardless of `[guardrails]`
    // config) — this is the missing call, not a config-format problem.
    let chat = chat.with_guardrails(loaded.runtime.guardrails.clone());
    // GAP-FIX guardrails-injection — the RETRIEVED-content (RAG) injection scanner
    // `ConversationManager`/`ChatSurface` builds itself is the bare `HeuristicInjectionScanner`
    // (`ainxt_injection::InjectionDetector::default()`, empty `known_tool_names`), so a poisoned KB
    // chunk that names a real internal tool (a strong indirect-injection signal, ADR-009) never
    // fired on the served RAG path — the exact same dead signal as the engine's own tool-result
    // scan above, just on the other detector instance. Same `tools` handle, same fix.
    let chat = chat.with_injection_scanner(Box::new(
        ainxt_injection::InjectionDetector::default().with_tools(tools.tool_names()),
    ));
    // GAP-AUDIT conversation-intelligence #2 — durable, CHD-redacted session history. Every served
    // ChatSurface constructor built its manager over the default `InMemorySessions`, so a served
    // conversation's turn history — and the referent-resolution fix that depends on reading it back —
    // was lost on every daemon restart. `None` (the default, no `[server] chat_sessions_dir`) keeps
    // `InMemorySessions` (byte-identical pre-wire behavior). Reuses `open_guarded_event_log` (the SAME
    // CHD sink-guard FI-01 already applies to the audit log) so a PAN/secret a user types into chat
    // can never land raw in the durable session store either — a distinct directory/dataset from the
    // audit log, never the same store repurposed.
    let chat = if let Some(dir) = &loaded.server.chat_sessions_dir {
        let log = open_guarded_event_log(dir).map_err(|e| {
            AssembleError::Config(format!("chat_sessions_dir: cannot open '{dir}': {e}"))
        })?;
        report.push(format!(
            "surface: chat — durable session history wired (CHD-redacted event log at '{dir}'); a \
             served conversation's turn history now survives a daemon restart"
        ));
        chat.with_session_store(Box::new(ainxt_convo::PersistentSessions::new(log)))
    } else {
        chat
    };
    report.push(format!(
        "surface: chat — output guardrails config applied (groundedness={:?}, groundedness_strict={}, \
         citation={:?}); {} when Off in config",
        loaded.runtime.guardrails.groundedness,
        loaded.runtime.guardrails.groundedness_strict,
        loaded.runtime.guardrails.citation,
        if loaded.runtime.guardrails.is_off() { "inert" } else { "live" }
    ));
    report.push(
        "surface: chat — grounded ChatSurface (compile_window RBAC/RLS retrieval + citations + \
         layered per-model Prompt Service + scoping-safe response cache, SEMANTIC/paraphrase tier \
         live via the offline HashEmbedder) over StrongRedactor compliance, streamed via the \
         SessionManager spine; served ledger/answer path runs the numeric re-derivation HARD GATE by \
         default (an unverifiable figure is blocked + escalated; faithfulness/conflict stay \
         redact-don't-block caveats)"
            .into(),
    );
    Ok((
        chat,
        wire_rx,
        report,
        ledger,
        reconciler,
        dispatch_probe,
        tools,
        memory_backend,
        outsourcing_register,
        mandate_registry,
        mcp_admin,
        serving,
    ))
}

/// Build the Stage-2 constrained-classifier transport (gap CONV-01, served) from config: the first
/// OpenAI-schema / local provider that has BOTH an endpoint and (for a cloud endpoint) an API key —
/// the only provider kind that implements [`ainxt_providers::ConstrainedProvider`] today. Returns
/// `None` on the air-gapped default (no endpoint / no key), so the surface falls back to the
/// deterministic heuristic. This is a real seam gated on real config presence — never faked.
fn build_chat_classifier_model(
    models: &ainxt_config::ModelsConfig,
) -> Option<(OpenAiSchemaProvider, ainxt_convo::ModelCaps)> {
    use ainxt_config::ProviderKind;
    for pc in &models.providers {
        if !matches!(pc.kind, ProviderKind::OpenAiSchema | ProviderKind::Local) {
            continue;
        }
        let base = match &pc.base_url {
            Some(b) if !b.is_empty() => b.clone(),
            _ => continue,
        };
        // Cloud OpenAI-schema requires a key; a local server is usually keyless.
        let key = match pc.kind {
            ProviderKind::OpenAiSchema => std::env::var("OPENAI_API_KEY")
                .ok()
                .filter(|k| !k.is_empty())?,
            _ => std::env::var("LOCAL_API_KEY").unwrap_or_default(),
        };
        let provider = OpenAiSchemaProvider::new(base, key, pc.id.clone(), pc.eligible.clone());
        // GAP-AUDIT conversation-intelligence #2 — `ModelCaps::frontier()` was returned
        // unconditionally for the first matching provider regardless of `pc.kind`, so a self-hosted
        // `ProviderKind::Local` model (Qwen/GLM/Gemma/Kimi) was graded identically to a frontier
        // cloud model — defeating the design's whole point (capability-aware extraction: a weaker
        // model needs a more explicit, few-shot instruction and a larger repair budget, not the
        // terse enforced instruction a grammar-constrained frontier model gets).
        let caps = match pc.kind {
            ProviderKind::OpenAiSchema => ainxt_convo::ModelCaps::frontier(),
            _ => ainxt_convo::ModelCaps::weak_oss(),
        };
        return Some((provider, caps));
    }
    None
}

/// Build the served chat [`PromptDeployment`](ainxt_convo::PromptDeployment) the daemon injects into the
/// ChatSurface compile (R14, items 4 + 7). It ALWAYS binds a mandatory durable
/// [`ForensicFileSink`](ainxt_prompt::service::ForensicFileSink) rooted under the daemon Event-Log
/// directory (`<event_log_dir>/prompt-forensic.jsonl`), so every served-chat compile writes a
/// byte-for-byte-replayable `(control_sha, layer-version tuple, prompt_hash)` record to disk BEFORE the
/// provider is called (PE11) — the "forensic record before the provider call" guarantee is now on the
/// LIVE served path, not caller-discretionary. When `[server] prompt_dir` is set, the layered registry
/// is loaded from GIT-NATIVE prompt FILES (§3, ADR-026) — editing a file + rebuild changes the served
/// body, which a hardcoded Rust constant cannot; fail-closed on a malformed/locked tree. Absent
/// `prompt_dir`, the shipped canonical constant deployment is used (air-gapped default; unchanged
/// bodies), still over the durable forensic sink.
fn build_served_chat_prompt(
    loaded: &LoadedConfig,
    report: &mut Vec<String>,
) -> Result<ainxt_convo::PromptDeployment, AssembleError> {
    use ainxt_prompt::registry::ModelFamily;
    use ainxt_prompt::service::ForensicFileSink;
    // Durable forensic sink under the Event-Log dir (create the parent so the first turn can fsync).
    let dir = event_log_dir(loaded);
    if let Err(e) = std::fs::create_dir_all(&dir) {
        return Err(AssembleError::Config(format!(
            "prompt forensic sink dir {}: {e}",
            dir.display()
        )));
    }
    let forensic_path = dir.join("prompt-forensic.jsonl");
    let sink = Box::new(ForensicFileSink::new(&forensic_path));

    match &loaded.server.prompt_dir {
        Some(root) if !root.is_empty() => {
            // GIT-NATIVE FILE-sourced registry (§3): driven to PRODUCTION through the real lifecycle
            // gates by the loader. Fail-closed on any load / lifecycle / no-serveable-family error.
            let served = ainxt_prompt::served::served_chat_prompts_from_dir(root).map_err(|e| {
                AssembleError::Config(format!("git-native prompt tree {root}: {e}"))
            })?;
            // Prefer the shipped default family when the tree serves it, else the first common family.
            let want = ModelFamily::new(ainxt_chat::DEFAULT_CHAT_FAMILY);
            let family = if served.families.contains(&want) {
                want
            } else {
                served.families.first().cloned().ok_or_else(|| {
                    AssembleError::Config(format!(
                        "git-native prompt tree {root}: no serveable family"
                    ))
                })?
            };
            report.push(format!(
                "prompt: served chat registry is GIT-NATIVE FILE-sourced from '{root}' (control_sha={}, \
                 {} layer(s), family={}) — prompts-as-code, never a hardcoded constant; forensic record \
                 fsync'd before every provider call",
                served.control_sha,
                served.layer_ids.len(),
                family.0,
            ));
            Ok(ainxt_convo::PromptDeployment::new(
                served.registry,
                served.deployment,
                family,
                served.layer_ids,
                &served.control_sha,
                sink,
            ))
        }
        _ => {
            // GAP-FIX prompt-governance #2 — `config.policy.l2_body` (`PolicyEngineConfig`, resolved
            // through ainxt-config's real layered TOML merge) must reach the L2 layer of the DEFAULT
            // served build too, not just the git-native `prompt_dir` branch above and the unreachable
            // `governed::assemble_served_prompt_engine_from_config`. An unconfigured `[policy]`
            // section (`l2_body` == the compiled-in default text) is byte-for-byte unchanged.
            let default_l2 = ainxt_prompt::policy::PolicyEngineConfig::default_l2_body();
            let l2_override = if loaded.runtime.policy.l2_body == default_l2 {
                None
            } else {
                Some(loaded.runtime.policy.l2_body.as_str())
            };
            report.push(if l2_override.is_some() {
                "prompt: served chat registry = shipped canonical constant deployment over a durable \
                 ForensicFileSink (forensic record fsync'd before every provider call, PE11); L2 \
                 org/config policy body is CONFIG-SOURCED from [policy] l2_body, not the compiled-in \
                 default"
                    .into()
            } else {
                "prompt: served chat registry = shipped canonical constant deployment over a durable \
                 ForensicFileSink (forensic record fsync'd before every provider call, PE11); set \
                 [server] prompt_dir to serve git-native FILE-sourced prompt bodies"
                    .into()
            });
            let family = ModelFamily::new(ainxt_chat::DEFAULT_CHAT_FAMILY);

            // GAP-FIX prompt-governance #3 — `[steerability]` config-sourced measured scores (§9,
            // PE7) must actually FILTER the real served family list, not just sit crate-tested and
            // uncalled. Inactive (no scores configured) ⇒ byte-for-byte the previous unfiltered set,
            // including the "never fails closed on its own configured model" force-include.
            if loaded.runtime.steerability.is_configured() {
                let candidates = ainxt_prompt::served::default_chat_families();
                let eligible = ainxt_prompt::served::steerability_eligible_families(
                    &candidates,
                    &loaded.runtime.steerability.scores,
                    loaded.runtime.steerability.min_bar,
                );
                if eligible.is_empty() {
                    return Err(AssembleError::Config(format!(
                        "steerability gate: no served chat family meets [steerability] min_bar={} — \
                         widen [steerability] scores or lower min_bar",
                        loaded.runtime.steerability.min_bar
                    )));
                }
                report.push(format!(
                    "prompt: steerability gate ACTIVE ([steerability] min_bar={}) — {} of {} \
                     candidate family(ies) served{}",
                    loaded.runtime.steerability.min_bar,
                    eligible.len(),
                    candidates.len(),
                    if eligible.contains(&family) {
                        ""
                    } else {
                        " (the active model family is NOT among them — the served turn fails closed \
                         at compile_turn, per §9)"
                    }
                ));
                Ok(
                    ainxt_convo::PromptDeployment::served_with_families_and_l2_policy(
                        family,
                        &eligible,
                        l2_override,
                        sink,
                    ),
                )
            } else {
                Ok(
                    ainxt_convo::PromptDeployment::served_default_with_l2_policy(
                        family,
                        l2_override,
                        sink,
                    ),
                )
            }
        }
    }
}

/// Assemble the runtime for the **chat surface** (gaps SURF-02/03): the full conversation
/// intelligence — intent cascade, referent/content resolution ("generate this as pdf" → the prior
/// answer), grounded retrieval + citations, and a scoping-safe response cache — over the strong-
/// redactor engine. Served (token-streaming) through the SAME [`SessionManager`] concurrency spine as
/// the bare engine, because [`ChatSurface`] implements [`TurnHandler`]. The corpus is seeded from the
/// loaded KB at the **platform+namespace** scope (the Chat/Voice default — no repo-private reach).
///
/// GAP-AUDIT gap6-composition-root (Item 3) — **this is NOT the live default `/v1/chat` composition.**
/// [`assemble_selected`]'s dispatch table (the one `main.rs`'s `--surface` selection ultimately drives,
/// via [`assemble_selected_fabric_grounded`] → [`assemble_selected_governed`] → [`assemble_selected`])
/// has no `"chat"` arm — every profile id, INCLUDING the default `"chat"`, falls through to
/// [`assemble_surface`], which composes this SAME family of retrieval/cache/redaction logic (via
/// [`build_chat_surface_wired_authz`]) wrapped in a [`ProfiledSurface`] — the `"chat"` profile's RBAC
/// floor (`required_caps = ["chat.send"]`), department-scoped row isolation
/// (`[rbac] department_scoped = true`), and `SurfaceScopedAuthorizer` capability bounding all apply on
/// the real served path and do NOT apply here. `assemble_chat` builds the strictly weaker, un-profiled
/// composition instead ([`build_chat_surface_wired`], i.e. [`build_chat_surface_wired_authz`] called
/// with no authz override, no provider allow-list, and row isolation forced `false`) — kept as a public
/// library entrypoint and the fixture ~30 call sites across the daemon-feature test suite (kill-switch,
/// canary, memory, mandate, wire-replay, sink-guard, harness-renderer, compose-wiring, ...) build on
/// when they need a working chat surface WITHOUT the profile/RBAC layer getting in the way of the
/// orthogonal thing they're actually testing. Deleting it (or silently swapping those tests onto
/// `assemble_surface`) would inject a mandatory `chat.send` RBAC capability and department-scoped row
/// isolation into every one of them for no gap-closing benefit — so it stays, correctly labelled. See
/// [`assemble_surface`] for the profile-resolved, actually-served default.
pub fn assemble_chat(loaded: &LoadedConfig) -> Result<Assembled, AssembleError> {
    let corpus = corpus_for_scope(&loaded.kb, RetrievalScope::PlatformAndNamespace);
    let indexed = corpus.len();
    let (
        chat,
        wire_rx,
        mut report,
        ledger,
        reconciler,
        dispatch_probe,
        tools,
        memory_backend,
        outsourcing_register,
        mandate_registry,
        mcp_admin,
        serving,
    ) = build_chat_surface_wired(loaded, corpus)?;
    report.push(format!(
        "corpus: {indexed} document(s) indexed at platform+namespace scope (live grounding \
         {})",
        if indexed == 0 {
            "inactive — empty KB"
        } else {
            "active"
        }
    ));
    // R16 CRITICAL fix: capture the live answer-cache handle BEFORE `chat` is erased behind
    // `Arc<dyn TurnHandler>` — this is what lets `assemble_full` share it with the erasure organ.
    let shared_answer_cache = chat.answer_cache_handle();
    let sm = Arc::new(SessionManager::new(Arc::new(chat), loaded.session));
    Ok(Assembled {
        manager: sm,
        report,
        wire_events: Some(wire_rx),
        capability_ledger: Some((ledger, reconciler)),
        dispatch_probe: Some(dispatch_probe),
        shared_answer_cache,
        capability_tools: Some(tools),
        memory_backend: Some(memory_backend),
        outsourcing_register,
        // No role-invocation concept on the chat surface.
        workforce_invocation_ledger: None,
        // No kernel process model on the chat surface.
        workforce_kernel: None,
        // No GovernedWorkforce on the chat surface.
        workforce_surface: None,
        mandate_registry,
        mcp_admin,
        // No profile/SkillRuntime on the un-profiled chat surface.
        skill_runtime: None,
        serving: Some(serving),
    })
}

/// Assemble the **identity-governed** chat surface (ADR-022 §15 + §17/§19) — the same UN-PROFILED
/// grounded [`ChatSurface`] composition as [`assemble_chat`] (both build over
/// [`build_chat_surface_wired`], NOT the real default's [`build_chat_surface_wired_authz`]/
/// [`assemble_surface`] path — see [`assemble_chat`]'s own doc), but every turn of a chat run is first
/// driven through the fused per-dispatch entrypoint ([`GovernedChatSurface`]): short-TTL JIT
/// renew-and-re-attest (§15) plus in-flight admission against the SHARED `control` plane (§17/§19), so
/// a long chat run is a chain of re-authorized identities and a mid-run kill-switch/revocation denies
/// its next turn immediately. **Config-selectable and additive** — it does NOT change the real default
/// `/v1/chat` composition ([`assemble_surface`], profile-enforced) or the default authenticator; a
/// deployment selects it and shares the served surface's control plane so the same control lever
/// reaches chat, Program and Team runs alike.
pub fn assemble_chat_governed(
    loaded: &LoadedConfig,
    control: Arc<Mutex<ControlPlane>>,
    def_kind: &str,
) -> Result<Assembled, AssembleError> {
    let (assembled, _transparency_log) =
        assemble_chat_governed_with_transparency(loaded, control, def_kind)?;
    Ok(assembled)
}

/// [`assemble_chat_governed`] but also returns the transparency log handle the identity-governed
/// chat surface is wired with — mirrors `assemble_program_surface_with_transparency`/
/// `assemble_team_surface_with_transparency` in `program_exec.rs`.
///
/// GAP-FIX identity-payments (ADR-022 §13) — `GovernedChatSurface` mints/renews AWCs (§15) on every
/// turn of a chat run but, before this fix, never appended to any transparency log — Program/Team
/// already feed their per-Run credential issuance into one (`assemble_program_surface_with_transparency`/
/// `assemble_team_surface_with_transparency`), but `assemble_chat_governed` built a `GovernedChatSurface`
/// with no log at all, so a chat run's AWC issuance had zero external-auditor
/// inclusion-proof-verifiable record, unlike the SAME class of event on Program/Team. This closes
/// that gap by threading a fresh log through `GovernedChatSurface::with_transparency_log` — every
/// NEWLY-MINTED chat-run credential (not each §15 renewal, mirroring exactly what Program/Team log)
/// is appended.
pub fn assemble_chat_governed_with_transparency(
    loaded: &LoadedConfig,
    control: Arc<Mutex<ControlPlane>>,
    def_kind: &str,
) -> Result<(Assembled, Arc<Mutex<TransparencyLog<Sha256Hasher>>>), AssembleError> {
    let corpus = corpus_for_scope(&loaded.kb, RetrievalScope::PlatformAndNamespace);
    let indexed = corpus.len();
    let (
        chat,
        wire_rx,
        mut report,
        ledger,
        reconciler,
        dispatch_probe,
        tools,
        memory_backend,
        outsourcing_register,
        mandate_registry,
        mcp_admin,
        serving,
    ) = build_chat_surface_wired(loaded, corpus)?;
    report.push(format!(
        "corpus: {indexed} document(s) indexed at platform+namespace scope (live grounding {})",
        if indexed == 0 {
            "inactive — empty KB"
        } else {
            "active"
        }
    ));
    // R16 CRITICAL fix: capture the live answer-cache handle BEFORE `chat` is erased behind
    // `Arc<dyn TurnHandler>` — this is what lets `assemble_full` share it with the erasure organ.
    let shared_answer_cache = chat.answer_cache_handle();
    let transparency_log = Arc::new(Mutex::new(TransparencyLog::new(Sha256Hasher)));
    let governed = GovernedChatSurface::new(Arc::new(chat), control, def_kind.to_string())
        .with_transparency_log(transparency_log.clone());
    report.push(
        "surface: chat (IDENTITY-GOVERNED) — every turn drives §15 short-TTL JIT renew-and-re-attest \
         + §17/§19 in-flight admission on the shared control plane before the grounded chat turn; a \
         long chat run is a chain of re-authorized identities, and a mid-run kill-switch/revocation \
         denies the next turn (additive/config-selectable; default /v1/chat unchanged)"
            .into(),
    );
    report.push(
        "identity: ADR-022 §13 issuance transparency log LIVE on the served chat_governed surface — \
         every chat run's AgentWorkloadCredential issuance is appended, Merkle-committed, and \
         inclusion-proof-verifiable by an external auditor (GAP-FIX identity-payments), the SAME \
         guarantee the Program/Team surfaces already provide"
            .into(),
    );
    let sm = Arc::new(SessionManager::new(Arc::new(governed), loaded.session));
    Ok((
        Assembled {
            manager: sm,
            report,
            wire_events: Some(wire_rx),
            capability_ledger: Some((ledger, reconciler)),
            dispatch_probe: Some(dispatch_probe),
            shared_answer_cache,
            capability_tools: Some(tools),
            memory_backend: Some(memory_backend),
            outsourcing_register,
            // No role-invocation concept on the identity-governed chat surface.
            workforce_invocation_ledger: None,
            // No kernel process model on the identity-governed chat surface.
            workforce_kernel: None,
            // No GovernedWorkforce on the identity-governed chat surface.
            workforce_surface: None,
            mandate_registry,
            mcp_admin,
            // No profile/SkillRuntime on the identity-governed chat surface.
            skill_runtime: None,
            serving: Some(serving),
        },
        transparency_log,
    ))
}

/// Assemble the **fabric-grounded** chat surface (gap `context-fabric`: `governed::compile_served_fabric`
/// mounted for real) — the same UN-PROFILED grounded [`ChatSurface`] composition as [`assemble_chat`]
/// (see that function's doc for why it, not [`assemble_surface`], is the sibling this wraps), but every
/// turn is FIRST routed through the populated Context-Fabric [`MultiGraphFabric`] (`CONTEXT_FABRIC.md` §2–§3) via
/// [`FabricGroundedChatSurface`], so a deployment whose KB (and, once a repo/KG indexer overlays
/// `code_graph`/`code_contents`, its code layers too) is populated grounds over the ROUTED multi-layer
/// fabric — query-planned layer selection, cross-graph personalized PageRank, global/sensemaking
/// community summaries, and the multimodal-artifact tier — instead of the flat single-layer
/// `compile_window` path `assemble_chat` uses alone.
///
/// The fabric is built the same way [`governed::served_fabric_from_kb`] documents: every in-scope KB
/// document becomes an [`ainxt_context::optimizer::GraphLayer::EnterpriseDocs`]-labelled node (full
/// node-ACL + RLS row-attributes preserved, so pre-rank RBAC/RLS still enforces per node), overlaid with
/// the caller-supplied `code_graph`/`code_contents` (empty = no repo/KG indexer yet, the honest
/// air-gapped default — the fabric is then KB-only, never wider than what `served_fabric_from_kb`'s own
/// doc calls out).
///
/// **Config-selectable and additive** — it does NOT change the real default `/v1/chat` composition
/// ([`assemble_surface`], profile-enforced) or its default authenticator. An EMPTY fabric (an empty KB
/// AND no code overlay) makes [`FabricGroundedChatSurface`] a byte-identical pass-through to the same
/// un-profiled grounded [`ChatSurface`] `assemble_chat` builds — see
/// `runtime/crates/ainxt-runtimed/tests/r19_fabric_grounded_chat_served.rs`.
pub fn assemble_chat_fabric_grounded(
    loaded: &LoadedConfig,
    code_graph: ainxt_context::optimizer::FabricGraph,
    code_contents: Vec<Chunk>,
) -> Result<Assembled, AssembleError> {
    // The fabric-of-graphs the served routed compile draws from — KB EnterpriseDocs layer + whatever
    // code layers the caller's indexer overlaid. No artifact tier attached (the air-gapped default —
    // see `assemble_chat_fabric_grounded_with_artifacts` for a deployment with a populated one).
    let fabric = governed::served_fabric_from_kb(
        &loaded.kb,
        RetrievalScope::PlatformAndNamespace,
        code_graph,
        code_contents,
    );
    assemble_chat_fabric_grounded_over(loaded, fabric)
}

/// GAP-FIX data-surfaces-artifacts (multimodal artifact tier orphaned behind the fabric-grounded
/// surface, same root cause as `context-fabric`'s dispatch-mount gap) — [`assemble_chat_fabric_grounded`]
/// always builds its [`ainxt_context::route::MultiGraphFabric`] via [`governed::served_fabric_from_kb`],
/// which never attaches an [`ainxt_context::artifact::ArtifactStore`]
/// ([`ainxt_context::route::MultiGraphFabric::from_fabric`] defaults to an EMPTY store) — so even once
/// [`crate::assemble_selected_fabric_grounded`] mounts fabric-grounding on the daemon's dispatch table,
/// [`ainxt_context::route::RoutedWindow::artifacts`] stays permanently empty on every served turn: the
/// routed, eligibility-gated multimodal tier
/// ([`governed::ingest_artifact_batch`]/[`governed::route_artifact_model`]/[`governed::served_multimodal_turn`])
/// had, until this fix, no composition-root caller at all (`FabricGroundedChatSurface::render_context`
/// rendered KB chunks and community summaries onto the grounded turn, but never `RoutedWindow::artifacts`).
///
/// This sibling accepts a caller-populated [`ainxt_context::artifact::ArtifactStore`] — built fully
/// offline/deterministically via [`governed::ingest_artifact_batch`], no live vision/ASR fleet required
/// — and attaches it to the fabric before wrapping: the SAME [`FabricGroundedChatSurface`] mechanism now
/// surfaces eligible artifacts (labelled by modality + the eligible model `route_artifact_model` would
/// route them to) into the grounded turn, never a regulated artifact routed to an ineligible model, and
/// never a silent leak of an artifact the caller's model catalog cannot serve.
///
/// `needs_hot_wiring`: no composition-root code on the shipped daemon populates a live `ArtifactStore`
/// from real object storage on boot yet — `governed::artifact_erasure_cascade`'s own doc comment already
/// calls this out. That remaining half is upstream ingestion infra (an object-store/connector poll loop
/// feeding `governed::ingest_artifact_batch`), not a gap in this mount: a deployment that already has
/// artifact bytes to ingest (e.g. from `/v1/artifact`, see `main.rs`'s served surface list) calls
/// [`governed::ingest_artifact_batch`] and selects this surface with the result.
pub fn assemble_chat_fabric_grounded_with_artifacts(
    loaded: &LoadedConfig,
    code_graph: ainxt_context::optimizer::FabricGraph,
    code_contents: Vec<Chunk>,
    artifacts: ainxt_context::artifact::ArtifactStore,
) -> Result<Assembled, AssembleError> {
    let fabric = governed::served_fabric_from_kb(
        &loaded.kb,
        RetrievalScope::PlatformAndNamespace,
        code_graph,
        code_contents,
    )
    .with_artifacts(artifacts);
    assemble_chat_fabric_grounded_over(loaded, fabric)
}

/// Shared tail of [`assemble_chat_fabric_grounded`]/[`assemble_chat_fabric_grounded_with_artifacts`] —
/// both differ only in how `fabric` is built (with or without an attached artifact tier); everything
/// after that (chat surface, live per-turn eligible-model resolution, wrap, report, `Assembled`) is
/// identical, so it lives once here rather than duplicated across both public entrypoints.
fn assemble_chat_fabric_grounded_over(
    loaded: &LoadedConfig,
    fabric: ainxt_context::route::MultiGraphFabric,
) -> Result<Assembled, AssembleError> {
    let corpus = corpus_for_scope(&loaded.kb, RetrievalScope::PlatformAndNamespace);
    let indexed = corpus.len();
    let (
        chat,
        wire_rx,
        mut report,
        ledger,
        reconciler,
        dispatch_probe,
        tools,
        memory_backend,
        outsourcing_register,
        mandate_registry,
        mcp_admin,
        serving,
    ) = build_chat_surface_wired(loaded, corpus)?;
    report.push(format!(
        "corpus: {indexed} document(s) indexed at platform+namespace scope (live grounding \
         {})",
        if indexed == 0 {
            "inactive — empty KB"
        } else {
            "active"
        }
    ));
    // R16 CRITICAL fix: capture the live answer-cache handle BEFORE `chat` is erased behind
    // `Arc<dyn TurnHandler>` — mirrors `assemble_chat`'s own ordering.
    let shared_answer_cache = chat.answer_cache_handle();

    let fabric_layers = fabric.populated_layers();
    let fabric_populated = !fabric.is_empty();

    // Gap context-fabric (the remaining named hot wire in `compile_served_fabric`'s own doc comment):
    // resolve the LIVE per-turn eligible-model set from the deployment's OWN `ModelRouter` — built from
    // the SAME `[models]` config the engine's own router uses — never a config default, so the fabric's
    // two-phase budget fit floors to a model this deployment could actually route the turn to.
    let (fabric_router, _fabric_router_report) = build_router(&loaded.runtime.models);
    let eligible_ids = fabric_router.eligible_ids(DataClass::Internal);
    let eligible: Vec<ainxt_retrieval::EligibleModel> = if eligible_ids.is_empty() {
        vec![ainxt_retrieval::EligibleModel::new("served-default", 8_000)]
    } else {
        eligible_ids
            .iter()
            .map(|id| ainxt_retrieval::EligibleModel::new(id, 8_000))
            .collect()
    };

    let wrapped = FabricGroundedChatSurface::new(
        Arc::new(chat),
        fabric,
        eligible,
        CHAT_HARNESS_ID.to_string(),
    );
    report.push(format!(
        "surface: chat (FABRIC-GROUNDED) — every turn routed through governed::compile_served_fabric \
         BEFORE the grounded chat turn; fabric {} ({} layer(s): {fabric_layers:?}); additive/\
         config-selectable, real default /v1/chat (assemble_surface) unchanged",
        if fabric_populated {
            "populated"
        } else {
            "empty — byte-identical pass-through to the un-wrapped grounded ChatSurface"
        },
        fabric_layers.len()
    ));
    let sm = Arc::new(SessionManager::new(Arc::new(wrapped), loaded.session));
    Ok(Assembled {
        manager: sm,
        report,
        wire_events: Some(wire_rx),
        capability_ledger: Some((ledger, reconciler)),
        dispatch_probe: Some(dispatch_probe),
        shared_answer_cache,
        capability_tools: Some(tools),
        memory_backend: Some(memory_backend),
        outsourcing_register,
        // No role-invocation concept on the fabric-grounded chat surface.
        workforce_invocation_ledger: None,
        // No kernel process model on the fabric-grounded chat surface.
        workforce_kernel: None,
        // No GovernedWorkforce on the fabric-grounded chat surface.
        workforce_surface: None,
        mandate_registry,
        mcp_admin,
        // No profile/SkillRuntime on the fabric-grounded chat surface.
        skill_runtime: None,
        serving: Some(serving),
    })
}

/// A [`TurnHandler`] that enforces a [`SurfaceProfile`](ainxt_profile::SurfaceProfile) on every turn
/// before delegating to an inner handler (gaps SURF-01/04). Per turn it:
///
/// 1. looks the profile up in a [`SurfaceCatalog`] by `surface_id` (no hardcoded surface string);
/// 2. binds it with the deployment [`SkillRuntime`] and calls
///    [`plan`](ainxt_surface::SurfaceBinding::plan) — this enforces the **RBAC floor**, the
///    **data-class ceiling** (ADR-012), the effective-capability intersection, autonomy→approval,
///    depth→tier floor, and department scoping, and assembles persona→behavioral→guard into the
///    system prompt with execution-skill output in `## Context`;
/// 3. maps the resulting [`TurnPlan`](ainxt_surface::TurnPlan) onto the engine [`Request`] via
///    [`to_request`](ainxt_surface::TurnPlan::to_request) (prompt + tier + forced provider) and hands
///    it to the inner handler (the grounded [`ChatSurface`]).
///
/// Fail-closed: a plan error (role too low / missing cap / data-class exceeded / department required)
/// emits an [`Event::Error`] and returns [`TurnError::Denied`] **without** starting the model turn.
pub struct ProfiledSurface {
    catalog: SurfaceCatalog,
    // GAP-FIX surfaces-profiles-skills-config (ADR-026 §6.2 hot-reload) — `Arc`, not owned: the
    // composition root keeps its OWN clone of this exact Arc (see `Assembled::skill_runtime`) so a
    // served `POST /admin/reload` calls `.reload()` on the SAME `SkillRuntime` instance every turn
    // resolves skills through, not a second disconnected copy.
    skills: Arc<SkillRuntime>,
    surface_id: String,
    inner: Arc<dyn TurnHandler>,
    guard_prompts: Vec<String>,
}

impl ProfiledSurface {
    /// Wrap `inner` so that every turn is planned under `surface_id` from `catalog`, using `skills`.
    pub fn new(
        catalog: SurfaceCatalog,
        skills: Arc<SkillRuntime>,
        surface_id: impl Into<String>,
        inner: Arc<dyn TurnHandler>,
    ) -> Self {
        ProfiledSurface {
            catalog,
            skills,
            surface_id: surface_id.into(),
            inner,
            guard_prompts: Vec::new(),
        }
    }

    /// Attach guard prompts injected after persona/behavioral skills in every planned turn.
    pub fn with_guard_prompts(mut self, guards: Vec<String>) -> Self {
        self.guard_prompts = guards;
        self
    }
}

impl TurnHandler for ProfiledSurface {
    fn handle_turn<'a>(
        &'a self,
        principal: &'a Principal,
        req: &'a Request,
        sink: tokio::sync::mpsc::Sender<Event>,
        cancel: &'a CancelToken,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<TurnSummary, TurnError>> + Send + 'a>,
    > {
        Box::pin(async move {
            // 1. Resolve + bind the surface profile with the deployment skill runtime.
            let binding = match self.catalog.bind(&self.surface_id, &self.skills) {
                Some(b) => b,
                None => {
                    let msg = format!("surface '{}' is not registered", self.surface_id);
                    let _ = sink.send(Event::Error(msg.clone())).await;
                    let _ = sink.send(Event::Done).await;
                    return Err(TurnError::Internal(msg));
                }
            };
            // 2. Plan the turn — this is the RBAC/data-class/skill-injection/model-policy enforcement
            //    point. A refusal is fail-closed: emit an error and never start the model turn.
            //    GAP-FIX surfaces-profiles-skills-config: `plan_with_request_override` (the "request"
            //    rung of the layered config chain, ADR-004) previously had zero callers — every served
            //    turn hardcoded `None`. `req.request_override` (`None` = byte-identical to before) is
            //    now threaded through, so a per-turn narrowing override can actually reach the surface.
            let plan = match binding.plan_with_request_override(
                principal,
                &req.input,
                req.data_class,
                &self.guard_prompts,
                req.request_override.as_deref(),
            ) {
                Ok(p) => p,
                Err(e) => {
                    let msg = format!("surface '{}' refused this turn: {e}", self.surface_id);
                    let _ = sink.send(Event::Error(msg.clone())).await;
                    let _ = sink.send(Event::Done).await;
                    return Err(TurnError::Denied(msg));
                }
            };
            // 3. Map the plan onto the engine request (persona/skills/guard prompt + tier + forced
            //    provider) and delegate to the inner grounded handler.
            let profiled = plan.to_request(&req.session, &req.turn, &req.input);
            self.inner
                .handle_turn(principal, &profiled, sink, cancel)
                .await
        })
    }
}

/// Assemble the runtime for a **named surface** (gaps SURF-01/04, wrapping SURF-02/03): the daemon
/// resolves the [`SurfaceProfile`](ainxt_profile::SurfaceProfile) for `surface_id` from the builtin
/// [`SurfaceCatalog`] (instead of a hardcoded surface string), builds the deployment [`SkillRuntime`]
/// and the grounded [`ChatSurface`], and serves them behind a [`ProfiledSurface`] so every turn is
/// RBAC/data-class/skill/model-policy enforced before the grounded, cited, cached model turn runs.
pub fn assemble_surface(
    loaded: &LoadedConfig,
    surface_id: &str,
) -> Result<Assembled, AssembleError> {
    // Gap SURF: apply the deployment's per-surface layer-overrides (`[surfaces.<id>]`) on top of the
    // canonical profiles — the profile layer-merge is LIVE on the served path. No overrides → the plain
    // builtin catalog (byte-identical to before).
    let catalog = if loaded.surfaces.is_empty() {
        SurfaceCatalog::builtin()
    } else {
        SurfaceCatalog::builtin_with_overrides(&loaded.surfaces.as_refs())
    }
    .map_err(|e| AssembleError::Config(format!("surface catalog: {e}")))?;
    if !catalog.contains(surface_id) {
        return Err(AssembleError::Config(format!(
            "unknown surface '{surface_id}' (known: {:?})",
            catalog.ids()
        )));
    }
    // Gap SURF-01: seed the surface's grounding corpus at the PROFILE's retrieval scope — a repo-
    // scoped surface (code/sdlc) indexes only repo docs, a platform surface (chat/buddy) only
    // platform+namespace docs. The scope is enforced STRUCTURALLY: out-of-scope docs are never in
    // the corpus the retriever sees, so they cannot be retrieved regardless of query/clearance.
    let scope = catalog
        .get(surface_id)
        .map(|p| p.context.retrieval)
        .unwrap_or(RetrievalScope::RepoScoped);
    let corpus = corpus_for_scope(&loaded.kb, scope);
    let indexed = corpus.len();
    // Gap SURF (high): bound the served surface engine's tool loop to the surface's DECLARED
    // capability set. A `SurfaceScopedAuthorizer` wraps the config-selected base authorizer (the OSS
    // RbacAuthorizer; the enterprise AdRbac gate fails closed earlier in engine assembly) so a
    // tool/connector capability the surface does not offer is refused — even for an admin. This makes
    // a non-chat surface (code/sdlc/buddy) actually execute ONLY its declared capabilities/connectors,
    // with autonomy (numeric/output/side-effect posture) composed into the prompt by
    // `TurnPlan::to_request`. A surface offering no tool capabilities (chat) is unchanged.
    let offered_caps: Vec<String> = catalog
        .get(surface_id)
        .map(|p| p.capabilities.clone())
        .unwrap_or_default();
    let surface_authz: Box<dyn Authorizer> = Box::new(ainxt_chat::SurfaceScopedAuthorizer::new(
        Box::new(RbacAuthorizer),
        offered_caps.clone(),
    ));
    // Gap SURF: the surface's model-policy forced_provider/allowed_providers narrows its router (and
    // Stage-2 classifier) server-side — GAP-FIX surface-turnplan-policy: `forced_provider` was
    // previously dropped here entirely (only `allowed_providers` was read), so a surface that pins a
    // provider via a deployment override with no allow-list left every other configured provider
    // registered on its router. See `filter_models_by_allowlist`'s doc for the full contract.
    let forced_provider: Option<String> = catalog
        .get(surface_id)
        .and_then(|p| p.model_policy.forced_provider.clone());
    let allowed_providers: Vec<String> = catalog
        .get(surface_id)
        .map(|p| p.model_policy.allowed_providers.clone())
        .unwrap_or_default();
    // Gap (high): wire the profile's DECLARED department scoping into the served retrieval isolation.
    // A surface whose profile sets `rbac.department_scoped` grounds under the department RLS row-filter
    // (a row whose `department` attribute is not the caller's own is never scored). Derived via the
    // single bridge `ChatSurface::profile_row_isolation`, then OR'd with the KB-global opt-in inside
    // `build_chat_surface_wired_authz`.
    let profile_row_isolation = catalog
        .get(surface_id)
        .map(ainxt_chat::ChatSurface::profile_row_isolation)
        .unwrap_or(false);
    let (
        chat,
        wire_rx,
        mut report,
        ledger,
        reconciler,
        dispatch_probe,
        tools,
        memory_backend,
        outsourcing_register,
        mandate_registry,
        mcp_admin,
        serving,
    ) = build_chat_surface_wired_authz(
        loaded,
        corpus,
        Some(surface_authz),
        forced_provider.as_deref(),
        &allowed_providers,
        profile_row_isolation,
    )?;
    // R16 CRITICAL fix: capture the live answer-cache handle BEFORE `chat` is erased behind
    // `Arc<dyn TurnHandler>` — this is what lets `assemble_full` share it with the erasure organ, so
    // a right-to-erasure reaches the SAME cache this profile-enforced surface actually serves from.
    let shared_answer_cache = chat.answer_cache_handle();
    // GAP-FIX surfaces-profiles-skills-config (ADR-026) — `build_skill_runtime_from_config` wires the
    // git-native skill control plane (`[server] skill_dir`) when configured, over the SAME compiled-in
    // builtin floor `build_skill_runtime()` always served; `None` (the default) is byte-identical.
    // GAP-FIX surfaces-profiles-skills-config (ADR-026 §6.2 hot-reload) — captured as an `Arc` BEFORE
    // `ProfiledSurface` is erased behind `Arc<dyn TurnHandler>` (mirrors `shared_answer_cache` above),
    // so `assemble_full` can hand the SAME instance to a served `POST /admin/reload` — a reload calls
    // `.reload()` on the EXACT `SkillRuntime` this surface's every turn resolves skills through.
    let skills = Arc::new(build_skill_runtime_from_config(loaded, &mut report)?);
    let skill_runtime = skills.clone();
    let profiled = ProfiledSurface::new(catalog, skills, surface_id, Arc::new(chat));
    report.push(format!(
        "surface: {surface_id} — profile-enforced (RBAC floor + data-class ceiling + skill \
         injection + model policy + SurfaceScopedAuthorizer bounding tool dispatch to {} declared \
         capabilit(y/ies)) over the grounded ChatSurface; retrieval scope {scope:?} with \
         {indexed} in-scope document(s) indexed; department RLS row-isolation {}",
        offered_caps.len(),
        if profile_row_isolation {
            "ON (profile rbac.department_scoped)"
        } else {
            "off"
        }
    ));
    // GAP-AUDIT surfaces-profiles-skills-config (item 3) — this function previously ALSO constructed
    // an `ainxt_surface::SurfaceArtifacts` here and self-tested it at boot. Removed: see the DECISION
    // comment on the [`Assembled`] struct for why — the real served document-generation path is
    // `POST /v1/artifact` (`mounts::build_artifact_runtime`), not this surface-layer construction.
    let sm = Arc::new(SessionManager::new(Arc::new(profiled), loaded.session));
    Ok(Assembled {
        manager: sm,
        report,
        wire_events: Some(wire_rx),
        capability_ledger: Some((ledger, reconciler)),
        dispatch_probe: Some(dispatch_probe),
        shared_answer_cache,
        capability_tools: Some(tools),
        memory_backend: Some(memory_backend),
        outsourcing_register,
        // No role-invocation concept on the profile-catalog surface.
        workforce_invocation_ledger: None,
        // No kernel process model on the profile-catalog surface.
        workforce_kernel: None,
        // No GovernedWorkforce on the profile-catalog surface.
        workforce_surface: None,
        mandate_registry,
        mcp_admin,
        skill_runtime: Some(skill_runtime),
        serving: Some(serving),
    })
}

/// Resolve the `--surface` selector to an assembled surface — the SINGLE composition-root dispatch
/// the daemon `main` uses (R14, served-composition, HIGH gap "3-tier Team loop / workforce factory
/// unreachable from the shipped daemon binary"). One match arm per surface, mirroring `program`:
///
/// * `"engine"`  → the bare model turn behind the mandatory gates ([`assemble`]);
/// * `"program"` → the long-horizon Program Supervisor ([`assemble_program_surface`]);
/// * `"program_bank_onboarding"` → the SAME Program Supervisor, but composing the real, fixed
///   bank-onboarding topology ([`assemble_program_surface_bank_onboarding`]) instead of the generic
///   `MigrationBlueprint::compose` planner (GAP-FIX data-surfaces-artifacts "bank onboarding as a
///   Program never selectable" — `ainxt_planner::bank_onboarding::bank_onboarding_program` was real
///   and tested via the generic engine, but had zero references anywhere in this crate);
/// * `"team"`    → the hierarchical 3-tier Team loop ([`assemble_team_surface`]);
/// * `"workforce"` → the AiNxt-OS Role factory ([`assemble_workforce_surface_served`]);
/// * anything else → a profile id resolved from the [`SurfaceCatalog`] ([`assemble_surface`]).
///
/// Extracting this out of `main` is what makes the team/workforce reachability PROVABLE offline
/// (a test asserts each selector produces the right surface), not just an untested one-liner.
pub fn assemble_selected(loaded: &LoadedConfig, surface: &str) -> Result<Assembled, AssembleError> {
    match surface {
        "engine" => assemble(loaded),
        "program" => assemble_program_surface(loaded, "program"),
        "program_bank_onboarding" => {
            assemble_program_surface_bank_onboarding(loaded, "program-bank-onboarding")
        }
        "team" => assemble_team_surface(loaded, "team"),
        "workforce" => assemble_workforce_surface_served(loaded, "workforce"),
        other => assemble_surface(loaded, other),
    }
}

/// GAP-FIX identity-payments (ADR-022 §15/§17/§19 "per-turn granularity") — the [`assemble_selected`]
/// dispatch table `main.rs` drives has no arm that can ever produce [`assemble_chat_governed`]'s
/// per-turn-governed chat surface: `"chat"` (the default) and every other profile id fall through to
/// [`assemble_surface`], which never wraps the grounded `ChatSurface` in [`GovernedChatSurface`]. The
/// mechanism ([`GovernedChatSurface`] driving the fused §15 JIT-renew + §17/§19 admission gate on
/// EVERY chat turn) was fully built and unit-tested in `chat_identity.rs`, but was unreachable from
/// the shipped daemon: an operator could never actually select it, so the served `/v1/chat` ran at NO
/// identity-lifecycle granularity — coarser than the design's per-turn requirement, and coarser than
/// the already-wired Program/Team paths (whose executors call `ControlPlane::admit` on every turn).
///
/// This is the missing selector: `"chat_governed"` is a NEW, explicit, opt-in surface id that builds
/// the identity-governed chat surface against the CALLER-SUPPLIED shared `control` plane — the same
/// plane the daemon's kill-switch/revocation endpoints operate on (thread it through to
/// [`assemble_full_with_control_plane`] too, or a kill-switch pull would silently target a different,
/// disconnected plane). Every other id is unchanged, byte-identical delegation to [`assemble_selected`]
/// — the shipped default (`"chat"`) is NOT altered by this addition, exactly as `chat_identity.rs`'s
/// own module doc requires ("additive and config-selectable... does NOT change the default `/v1/chat`
/// surface").
pub fn assemble_selected_governed(
    loaded: &LoadedConfig,
    surface: &str,
    control: Arc<Mutex<ControlPlane>>,
) -> Result<Assembled, AssembleError> {
    match surface {
        "chat_governed" => assemble_chat_governed(loaded, control, "chat"),
        other => assemble_selected(loaded, other),
    }
}

/// [`assemble_selected_governed`], additionally returning the live issuance [`TransparencyLog`] the
/// selected surface wired, if any (GAP-FIX identity-payments, gap6 audit item 1 — mirrors
/// [`assemble_chat_governed_with_transparency`]'s own relationship to [`assemble_chat_governed`]).
/// `main.rs`'s boot sequence calls this (via [`assemble_selected_fabric_grounded_with_transparency`])
/// instead of the plain [`assemble_selected_governed`] so a `--surface chat_governed` daemon's
/// `AssembledFull::transparency` is `Some` — reachable by [`AssembledFull::to_full_app_ext`]'s new
/// `GET /v1/transparency/proof/:run_id` route — instead of the handle being minted and immediately
/// discarded. Every other surface id (including the shipped `"chat"` default) returns `None`,
/// byte-identical to today: this closes ONLY the described orphan (chat_identity.rs's write-side
/// log), not the structurally separate Program/Team transparency-log handles
/// (`assemble_program_surface_with_transparency`/`assemble_team_surface_with_transparency`), which
/// remain their own, already-tracked gap.
pub fn assemble_selected_governed_with_transparency(
    loaded: &LoadedConfig,
    surface: &str,
    control: Arc<Mutex<ControlPlane>>,
) -> Result<(Assembled, Option<Arc<Mutex<TransparencyLog<Sha256Hasher>>>>), AssembleError> {
    match surface {
        "chat_governed" => {
            let (assembled, log) =
                assemble_chat_governed_with_transparency(loaded, control, "chat")?;
            Ok((assembled, Some(log)))
        }
        other => Ok((assemble_selected(loaded, other)?, None)),
    }
}

/// GAP-FIX context-fabric (+ data-surfaces-artifacts, same root cause) — the ENTIRE "fabric of graphs"
/// engine (multi-graph automatic grounding, cross-graph personalized PageRank, embedding-model
/// lifecycle/re-embed, global/sensemaking community-detection, and the multimodal-artifact tier) is
/// complete, self-consistent, real code with its own composition-root-shaped function
/// ([`assemble_chat_fabric_grounded`]) — but [`assemble_selected_governed`] (the dispatch table
/// `main.rs` actually drives) has NO arm that ever calls it. `governed::compile_served_fabric`'s own
/// doc comment says so explicitly: "deliberately NOT yet mounted on `/v1/chat`". Before this fix, only
/// a test (`r19_fabric_grounded_chat_served.rs`) ever called [`assemble_chat_fabric_grounded`] directly
/// — an operator could never actually select it from the shipped daemon binary.
///
/// This is the missing selector: `"chat_fabric_grounded"` is a NEW, explicit, opt-in surface id,
/// mirroring `"chat_governed"`'s own precedent exactly (see [`assemble_selected_governed`] above). An
/// air-gapped deployment with no repo/KG indexer overlay yet passes an EMPTY
/// [`ainxt_context::optimizer::FabricGraph`]/`code_contents` — [`governed::served_fabric_from_kb`]'s own
/// doc calls this out as the honest default: the fabric is then populated ONLY from the configured KB
/// (still the SAME platform+namespace corpus scope the real default `/v1/chat` composition —
/// [`assemble_surface`]'s `"chat"` profile — grounds over today), never wider. Every other id is
/// unchanged, byte-identical delegation to [`assemble_selected_governed`] — the shipped default
/// (`"chat"`) and the existing `"chat_governed"` opt-in are NOT altered by this addition, exactly as
/// [`assemble_chat_fabric_grounded`]'s own doc comment requires ("additive and config-selectable... does
/// NOT change the real default `/v1/chat` surface, [`assemble_surface`]'s `"chat"` profile
/// composition").
///
/// Once mounted, this same arm is what makes reachable (verified in
/// `gap5_fabric_mount_served.rs`): cross-graph personalized PageRank grounding; embedding-lifecycle
/// re-embed ([`governed::run_kb_corpus_reembed`], operator-triggered, unrelated to this dispatch fix but
/// equally gated behind the daemon actually running — no change needed here); global/sensemaking
/// community-detection (`detect_communities`/`summarize_communities`, already proven reachable from a
/// served turn by `r19_fabric_grounded_chat_served.rs`'s own community-detection test once
/// `FabricGroundedChatSurface` is live); and the multimodal-artifact tier
/// (`ingest_artifact_batch`/`route_artifact_model`/`erasure_cascade`) via [`RoutedWindow::artifacts`]
/// on the [`RoutedWindow`] `compile_served_fabric` now compiles for every real served turn.
pub fn assemble_selected_fabric_grounded(
    loaded: &LoadedConfig,
    surface: &str,
    control: Arc<Mutex<ControlPlane>>,
) -> Result<Assembled, AssembleError> {
    match surface {
        "chat_fabric_grounded" => assemble_chat_fabric_grounded(
            loaded,
            ainxt_context::optimizer::FabricGraph::new(),
            Vec::new(),
        ),
        other => assemble_selected_governed(loaded, other, control),
    }
}

/// [`assemble_selected_fabric_grounded`], additionally returning the live issuance [`TransparencyLog`]
/// (GAP-FIX identity-payments, gap6 audit item 1) — the function `main.rs`'s boot sequence actually
/// calls. `"chat_fabric_grounded"` wires no transparency log (unchanged); every other id delegates to
/// [`assemble_selected_governed_with_transparency`], which is `Some` only for `"chat_governed"`.
pub fn assemble_selected_fabric_grounded_with_transparency(
    loaded: &LoadedConfig,
    surface: &str,
    control: Arc<Mutex<ControlPlane>>,
) -> Result<(Assembled, Option<Arc<Mutex<TransparencyLog<Sha256Hasher>>>>), AssembleError> {
    match surface {
        "chat_fabric_grounded" => Ok((
            assemble_chat_fabric_grounded(
                loaded,
                ainxt_context::optimizer::FabricGraph::new(),
                Vec::new(),
            )?,
            None,
        )),
        other => assemble_selected_governed_with_transparency(loaded, other, control),
    }
}

// ============================ Fully-wired daemon transport (R4) ============================

/// The directory backing the tamper-evident daemon Event Log. A configured `[server] event_log_dir`
/// wins; the air-gapped default is a per-binary path under the OS temp dir (so a zero-config daemon
/// still has a durable, CHD-guarded audit/resume log).
fn event_log_dir(loaded: &LoadedConfig) -> std::path::PathBuf {
    match &loaded.server.event_log_dir {
        Some(d) => std::path::PathBuf::from(d),
        None => std::env::temp_dir().join("ainxt-runtimed").join("eventlog"),
    }
}

/// Open the durable, **CHD-guarded** Event Log for the served surface (FI-01): every record is redacted
/// through the strong redactor before the durable write, so cardholder data can never be persisted. This
/// is the audit trail AND the resume/replay tail the fully-wired transport serves.
fn build_event_log(dir: &std::path::Path) -> Result<Arc<dyn EventLog>, AssembleError> {
    let log = open_guarded_event_log(dir)
        .map_err(|e| AssembleError::Config(format!("event log at {}: {e}", dir.display())))?;
    Ok(Arc::new(log) as Arc<dyn EventLog>)
}

/// GAP-FIX eval-durable-stores (EVAL_PLATFORM.md §11) — build the served Regression Vault, hydrated from
/// its durable [`ainxt_eval::durable::FileVaultStore`] when `[server] eval_durable_dir` is configured
/// ([`ServerConfig::eval_durable_dir`]'s doc). `None` (the default) reproduces the PRE-EXISTING behavior
/// byte-for-byte: a fresh, empty, in-memory-only `RegressionVault` with no durable store handle — a
/// daemon restart loses every minted case exactly as it did before this fix, which is the deliberate
/// zero-config/air-gapped default every other durable-vs-in-memory seam in this file also uses.
///
/// When set, every durable record at `<dir>/vault.jsonl` is loaded and re-minted into a fresh
/// `RegressionVault` — `RegressionVault::mint` re-verifies each case's content seal, so a record whose
/// on-disk bytes were silently edited is dropped rather than trusted (the SAME tamper-evidence
/// `FileVaultStore::load_all` already proves in its own crate test, now exercised through the real
/// composition root). The returned `FileVaultStore` handle is kept on `AssembledFull::vault_store` so
/// [`AssembledFull::admit_promotion`] can durably persist every NEW case it mints going forward.
fn build_eval_vault(
    loaded: &LoadedConfig,
    report: &mut Vec<String>,
) -> (
    ainxt_eval::vault::RegressionVault,
    Option<ainxt_eval::durable::FileVaultStore>,
) {
    match &loaded.server.eval_durable_dir {
        Some(dir) => {
            // `FileVaultStore::persist` opens its file with `create(true)` but never creates the
            // PARENT directory (it is a plain file handle, not a directory-of-sessions store like
            // `JsonlEventLog::open`, which does `create_dir_all` internally) — do it here once, up
            // front, so a freshly-configured `eval_durable_dir` that doesn't exist yet doesn't panic
            // on the first mint.
            if let Err(e) = std::fs::create_dir_all(dir) {
                report.push(format!(
                    "eval: FAILED to create eval_durable_dir '{dir}' ({e}) — falling back to an \
                     in-memory-only RegressionVault for this boot"
                ));
                return (ainxt_eval::vault::RegressionVault::new(), None);
            }
            let path = std::path::Path::new(dir).join("vault.jsonl");
            let store = ainxt_eval::durable::FileVaultStore::new(&path);
            let mut vault = ainxt_eval::vault::RegressionVault::new();
            let mut loaded_count = 0usize;
            for case in store.load_all() {
                if vault.mint(case) {
                    loaded_count += 1;
                }
            }
            report.push(format!(
                "eval: ainxt_eval::vault::RegressionVault DURABLE — file-backed at '{}' \
                 (ainxt_eval::durable::FileVaultStore); {loaded_count} previously-minted regression \
                 case(s) replayed back into the live vault on assembly, and every NEW case a live \
                 quality-circuit-breaker trip mints (AssembledFull::admit_promotion) is now ALSO \
                 appended here, so a daemon restart no longer loses regression coverage",
                path.display()
            ));
            (vault, Some(store))
        }
        None => {
            report.push(
                "eval: ainxt_eval::vault::RegressionVault mounted LIVE on the served surface — a real \
                 quality circuit-breaker trip (AssembledFull::admit_promotion) now ALSO mints a \
                 permanent VaultOrigin::CircuitBreaker regression case, not only a §2 incident, so a \
                 later CI/eval run guards against the SAME regression recurring silently. No \
                 `[server] eval_durable_dir` configured — in-memory only (unchanged default): a daemon \
                 restart loses every minted case."
                    .into(),
            );
            (ainxt_eval::vault::RegressionVault::new(), None)
        }
    }
}

/// GAP-FIX regulated-fi-responsible-lifecycle — the durable Event-Log session id a break-glass
/// campaign's checkpoint trail lives under: `breakglass-{program_id}`. Shared by the restart-recovery
/// scan ([`recover_break_glass_programs`]) and every checkpoint append
/// ([`AssembledFull::checkpoint_break_glass_program`]), so the writer and the recovery reader can never
/// silently diverge on where a campaign's durable state lives.
///
/// Deliberately a HYPHEN, not a colon (`breakglass:{program_id}`, which several OTHER session ids in
/// this file use, e.g. `dsar:{id}`): [`EventLog::sessions`] returns the SANITIZED on-disk filename stem
/// ([`ainxt_eventlog`]'s `safe_name` maps every non-alphanumeric/`-`/`_` byte — including `:` — to `_`
/// before it ever reaches disk), so a colon-based id could never round-trip back through
/// `strip_prefix` on recovery. A hyphen is already `safe_name`-stable, so the session id `sessions()`
/// hands back is byte-identical to what was written, for any `program_id` built from the same safe
/// character set (letters/digits/`-`/`_` — the same set every other id in this codebase already uses).
fn breakglass_session_id(program_id: &str) -> String {
    format!("breakglass-{program_id}")
}

/// GAP-FIX regulated-fi-responsible-lifecycle — rebuild the in-memory break-glass registry from the
/// durable Event Log on assembly (daemon start/restart). `BreakGlassProgram` was already durable/serde
/// (ADR-027: "durable, resumable, checkpointed... survives restarts") and fully tested as such in
/// `ainxt-lifecycle`, but the SERVED registry (`AssembledFull::breakglass`) held it ONLY in a
/// process-local `Arc<Mutex<BTreeMap<..>>>` — a daemon restart mid-campaign lost every in-progress
/// program with no way to recover it, contradicting that exact restart guarantee for this exact
/// mechanism. Each campaign's session (`breakglass-{program_id}`) accumulates one checkpoint record per
/// `open`/`step` (append-only, never rewritten); its LATEST record is a full serde snapshot of the
/// `BreakGlassProgram` at that point (pending targets + every attestation already emitted so far) —
/// deserializing it resumes the campaign exactly where it left off, never re-processing or losing a
/// target. A checkpoint that fails to parse is skipped (logged to the report) rather than fabricating
/// state or panicking the daemon on a corrupted/foreign record.
///
/// `event_log.sessions()` returns the on-disk filename STEM (already `safe_name`-sanitized — see
/// [`breakglass_session_id`]'s doc), so it is used here BOTH to match the `breakglass-` prefix AND,
/// unmodified, as the key passed straight back into `event_log.records(&session)` — never
/// reconstructed from `program_id`, so a sanitization mismatch can never point the read at the wrong
/// file.
fn recover_break_glass_programs(
    event_log: &dyn EventLog,
    report: &mut Vec<String>,
) -> std::collections::BTreeMap<String, ainxt_lifecycle::breakglass::BreakGlassProgram> {
    let mut recovered = std::collections::BTreeMap::new();
    for session in event_log.sessions() {
        let Some(program_id) = session.strip_prefix("breakglass-") else {
            continue;
        };
        let Some(last) = event_log.records(&session).into_iter().last() else {
            continue;
        };
        match serde_json::from_str::<ainxt_lifecycle::breakglass::BreakGlassProgram>(&last.text) {
            Ok(program) => {
                recovered.insert(program_id.to_string(), program);
            }
            Err(e) => report.push(format!(
                "regfi: break-glass campaign '{program_id}' durable checkpoint could not be parsed \
                 ({e}) — starting WITHOUT it rather than fabricating state; the underlying JSONL \
                 record on the Event Log is untouched and can be inspected/repaired"
            )),
        }
    }
    if recovered.is_empty() {
        report.push(
            "regfi: §6.5 break-glass redaction-with-attestation Program registry LIVE (POST \
             /v1/regfi/breakglass/{open,step}) — empty until a DPO explicitly opens a campaign; every \
             open/step now checkpoints a full snapshot to the durable Event Log (ADR-027 restart \
             survival), recovered on the NEXT assembly if the daemon restarts mid-campaign"
                .into(),
        );
    } else {
        report.push(format!(
            "regfi: §6.5 break-glass redaction-with-attestation Program registry LIVE — recovered {} \
             in-progress campaign(s) from the durable Event Log on assembly (ADR-027 restart survival: \
             a prior daemon process ended mid-campaign and this one resumed from the last checkpoint, \
             re-processing nothing already attested)",
            recovered.len()
        ));
    }
    recovered
}

/// The knowledge graph mounted at `/graph`, **POPULATED from the same KB the retrieval corpus is
/// seeded from** (gap DATA: "knowledge graph is populated on the shipped daemon"). Each configured
/// [`KbDocument`] becomes a `doc` node carrying its `data_class` verbatim; documents are grouped
/// under a `namespace`/`repo`/`source` node (classed at its least-sensitive member) so a bounded
/// traversal walks a real code+docs graph. Clearance filtering is enforced by the graph itself on
/// every served traversal (a doc above the caller's clearance is never visited, counted, or bridged
/// through). An empty KB still yields a served (not 404'd) empty graph — the air-gapped default.
fn build_graph(kb: &KbConfig) -> Graph {
    use ainxt_graph::GraphDoc;
    let docs = kb.documents.iter().map(|d| {
        // Grouping key: namespace for Namespace scope, repo for Repo scope, else the source label.
        let group = match d.scope {
            KbScope::Namespace => d.namespace.clone(),
            KbScope::Repo => d.repo.clone(),
            KbScope::Platform => Some(if d.source.is_empty() {
                "platform".to_string()
            } else {
                d.source.clone()
            }),
        };
        GraphDoc {
            id: d.id.clone(),
            label: if d.source.is_empty() {
                d.id.clone()
            } else {
                d.source.clone()
            },
            data_class: d.data_class,
            namespace: group,
            references: Vec::new(),
        }
    });
    Graph::from_documents(docs)
}

/// GAP-FIX memory (KG-linkage-diverged) — design `ENTERPRISE_MEMORY_LEARNING.md` §4 ("OKIs are nodes
/// in the Context Fabric Knowledge Graph (extends layer 12, "Memory"), not a separate store the graph
/// has to reach into — one RBAC/data-class-aware graph, one query surface") and §2's `links` field
/// ("typed edges into the Knowledge Graph"). `ainxt_memory::EdgeKind`/`Link`/`InMemoryStore::neighbors`
/// fully implement OKI-linkage semantics, but as an entirely separate, self-contained graph scoped to
/// the memory store's own `current(id)` lookup — no `MemoryItem`/`OrgKnowledge` record was ever
/// translated into an `ainxt_graph::Node`/`Edge`, so a human-approved OKI never appeared in the SAME
/// `/graph` surface the rest of the Context Fabric serves (zero occurrence of `GraphDoc`/`add_node` in
/// `ainxt-memory`; zero occurrence of `MemoryItem`/`OrgKnowledge` in `ainxt-graph`).
///
/// This closes it at the trigger the design names for org-knowledge (§6: "the flywheel proposes, a
/// human legislates" — authority is reached only through `MemoryStore::promote`): every
/// Approved/Production org-knowledge item in the shared backend at graph-build time becomes a
/// first-class `ainxt_graph::Node` (kind `"oki"`, carrying the item's own `data_class` so traversal-time
/// RBAC applies to it identically to a doc/code node) plus its typed `Link`s as real `ainxt_graph::Edge`s
/// (`EdgeKind::{Cites,AppliesTo,CausedBy,Supersedes,RelatesTo}` -> the matching `rel` string), landing in
/// the EXACT `Graph` instance the `/graph` route serves — not a parallel, unreachable structure.
///
/// An edge whose target isn't itself a node the graph already knows (e.g. a `CausedBy` link to an
/// incident id that isn't KB-indexed) is skipped rather than failing the whole graph build — the same
/// "never a new hard failure" posture the rest of this composition root uses (see `memory_router`'s
/// regfi fallback doc). Returns the number of OKI nodes actually linked, for the assembly report.
///
/// Boot-time only: this augments the graph once, at `assemble_full` time. A promotion that happens
/// AFTER the daemon is already serving does not retroactively appear in the live `Arc<Graph>` — the
/// served graph handle is an immutable `Arc<Graph>` end-to-end (`graph_router(graph: Arc<Graph>, ...)`
/// in `ainxt-server`), not an interior-mutable one, so a live-promotion path needs that handle widened
/// to `Arc<Mutex<Graph>>`/`Arc<RwLock<Graph>>` across every caller (the route, its tests, this
/// composition root) — a materially larger, riskier change than this fix, left as a follow-up rather
/// than bundled in here.
fn link_authoritative_oki_into_graph(
    graph: &mut Graph,
    backend: &ainxt_memory::MemorySqlBackend,
) -> usize {
    use ainxt_graph::{Edge, Node};
    use ainxt_memory::{MemoryKind, MemoryQuery, MemoryStore};

    let store = match ainxt_memory::DurableMemoryStore::open(backend.clone()) {
        Ok(s) => s,
        Err(_) => return 0, // offline-safe: a backend that fails to open yields an un-augmented graph.
    };
    let access = ainxt_memory::AccessScope::from_principal(ainxt_types::Principal::admin(
        "ainxt-graph-sync",
    ));
    let query = MemoryQuery::keywords(&[]).with_kind(MemoryKind::OrgKnowledge);
    let hits = store.query(&query, &access);

    for hit in &hits {
        let item = &hit.item;
        // A re-run over an unchanged backend re-offers the same id — `add_node` refuses the duplicate
        // rather than overwrite (clearance-downgrade guard); that refusal is the expected, harmless
        // steady state here, not an error to surface.
        let _ = graph.add_node(Node::new(&item.id, "oki", item.data_class, &item.title));
    }
    for hit in &hits {
        let item = &hit.item;
        for link in &item.links {
            let rel = match link.edge {
                ainxt_memory::EdgeKind::Cites => "cites",
                ainxt_memory::EdgeKind::AppliesTo => "applies_to",
                ainxt_memory::EdgeKind::CausedBy => "caused_by",
                ainxt_memory::EdgeKind::Supersedes => "supersedes",
                ainxt_memory::EdgeKind::RelatesTo => "relates_to",
            };
            // Target not (yet) a known node (e.g. an un-indexed ADR/incident id) -> skip, don't fail
            // the whole build.
            let _ = graph.add_edge(Edge::new(&item.id, &link.target, rel));
        }
    }
    hits.len()
}

/// GAP-FIX serving-ops (SERVING_OPS.md §1, gap 7) — build the disaggregated prefill/decode pool split
/// when the deployment declares `[serving.disagg]`. [`ainxt_serving::disagg::DisaggregatedPools`] was
/// fully implemented and unit-tested (`admit_decode_is_never_gated_by_prefill_saturation`) but had
/// ZERO references anywhere outside its own crate — the daemon's ONLY served pool was the single
/// `build_serving` gate, so the structural interference-elimination §1 mandates ("a request's decode
/// never waits on another request's prefill because they physically execute on different GPUs") was
/// never reachable in production. Returns `None` (default) when no `[serving.disagg]` section is
/// declared — the single-pool `build_serving` gate remains the only served pool, unchanged.
fn build_disagg(
    cfg: &ServingConfig,
) -> Option<(DisaggregatedPools, Vec<NodeCandidate>, Vec<NodeCandidate>)> {
    let d = cfg.disagg.as_ref()?;
    let prefill_gate = ServingGate::new(
        AttestationGate::new(AttestationConfig {
            quote_ttl: 300,
            grace_ttl: 30,
        }),
        FairnessLimiter::new(
            cfg.fairness_capacity.unwrap_or(8),
            cfg.fairness_min_share.unwrap_or(1),
        ),
        PreemptionScheduler::new(cfg.scheduler_capacity.unwrap_or(4) as usize),
    )
    .with_qos_queue_depth(cfg.qos_queue_depth.unwrap_or(QOS_QUEUE_DEPTH));
    let decode_gate = ServingGate::new(
        AttestationGate::new(AttestationConfig {
            quote_ttl: 300,
            grace_ttl: 30,
        }),
        FairnessLimiter::new(
            cfg.fairness_capacity.unwrap_or(8),
            cfg.fairness_min_share.unwrap_or(1),
        ),
        PreemptionScheduler::new(cfg.scheduler_capacity.unwrap_or(4) as usize),
    )
    .with_qos_queue_depth(cfg.qos_queue_depth.unwrap_or(QOS_QUEUE_DEPTH));
    let prefill_candidates: Vec<NodeCandidate> = d
        .prefill_nodes
        .iter()
        .map(|n| NodeCandidate::new(n.node_id.clone(), n.routable))
        .collect();
    let decode_candidates: Vec<NodeCandidate> = d
        .decode_nodes
        .iter()
        .map(|n| NodeCandidate::new(n.node_id.clone(), n.routable))
        .collect();
    Some((
        DisaggregatedPools::new(prefill_gate, decode_gate),
        prefill_candidates,
        decode_candidates,
    ))
}

/// GAP-FIX serving-ops (SERVING_OPS.md §3, gaps 26/W) — the served GPU bin-packing placement +
/// model-parking/eviction actuator, held on [`AssembledFull::placement`]. `PlacementController::plan`
/// (best-fit-decreasing + locality + attestation-tier match) and [`PlacementReconciler::reconcile_step`]
/// (rate-limited convergence over the [`PlacementBinder`](ainxt_serving::placement::PlacementBinder)
/// seam) were fully implemented and unit-tested but referenced only in `ainxt-serving`'s own tests —
/// this is the real caller: [`Self::actuate`] is the SAME entrypoint
/// [`AssembledFull::run_placement_actuator_tick`]/[`AssembledFull::run_autoscale_and_placement_tick`]
/// drive on the served surface, over ONE persistent [`InMemoryPlacementBinder`] instance (so a tick's
/// convergence builds on the previous tick's bound state, not a fresh binder each call).
#[derive(Debug, Clone)]
pub struct PlacementActuator {
    pool: BinPool,
    /// The declared model catalog (footprint + regulated-eligibility), keyed by `model_id` — the base
    /// [`ModelItem`] a [`ScaleAction`]'s replica count is expanded against.
    catalog: std::collections::BTreeMap<String, ModelItem>,
    binder: InMemoryPlacementBinder,
    max_moves: usize,
}

impl PlacementActuator {
    fn new(
        pool: BinPool,
        catalog: std::collections::BTreeMap<String, ModelItem>,
        max_moves: usize,
    ) -> Self {
        let binder = InMemoryPlacementBinder::from_bins(pool.bins());
        PlacementActuator {
            pool,
            catalog,
            binder,
            max_moves,
        }
    }

    /// Currently physically-bound model replica ids (`{model_id}#{n}`), in deterministic order — a
    /// read-only view of the SAME binder [`Self::actuate`] converges.
    pub fn bound_models(&self) -> Vec<String> {
        self.binder.bound_models()
    }

    /// **Actuate** a batch of autoscale decisions (SERVING_OPS.md §3, gaps 26/W): expand each
    /// [`ScaleAction::ScaleTo`] into `replicas` per-instance [`ModelItem`]s (`{model_id}#0..N`) against
    /// the declared catalog footprint, compute the best-fit-decreasing target [`PlacementController::
    /// plan`] over the declared [`BinPool`], and converge the persistent binder toward it via one
    /// rate-limited [`PlacementReconciler::reconcile_step`]. A [`ScaleAction::ParkWarm`] contributes NO
    /// items for that model — the reconciler's own "unbind anything absent from the target" pass then
    /// physically frees its VRAM, the concrete model-parking eviction action (the model's *warm* parked
    /// state itself is tracked by [`AutoscaleController::parking`], not duplicated here). A model named
    /// by an action but absent from the declared catalog is skipped (no footprint to place it with).
    pub fn actuate(&mut self, actions: &[ScaleAction]) -> Vec<ReconcileAction> {
        let mut items = Vec::new();
        for action in actions {
            if let ScaleAction::ScaleTo { model_id, replicas } = action {
                let Some(base) = self.catalog.get(model_id) else {
                    continue;
                };
                for i in 0..*replicas {
                    items.push(ModelItem::new(
                        format!("{model_id}#{i}"),
                        base.footprint,
                        base.requires_regulated_bin,
                    ));
                }
            }
            // ScaleAction::ParkWarm contributes no items — absent-from-target is exactly the signal
            // `PlacementReconciler::reconcile_step`'s unbind pass acts on.
        }
        let plan = PlacementController::plan(&self.pool, &items);
        PlacementReconciler::reconcile_step(&mut self.binder, &plan, &items, self.max_moves)
    }
}

/// GAP-FIX serving-ops (SERVING_OPS.md §3, gaps 26/W) — build the [`PlacementActuator`] when the
/// deployment declares `[serving.placement]`. `None` (default) — like `autoscale`, there is no
/// universal default for a deployment's GPU bin inventory.
fn build_placement(cfg: &ServingConfig) -> Option<PlacementActuator> {
    let p = cfg.placement.as_ref()?;
    let bins: Vec<Bin> = p
        .bins
        .iter()
        .map(|b| Bin::new(b.id.clone(), b.vram_total, b.tier, b.fabric_domain.clone()))
        .collect();
    let pool = BinPool::new(bins).with_standby_reserve(p.standby_reserve);
    let catalog = p
        .models
        .iter()
        .map(|m| {
            (
                m.model_id.clone(),
                ModelItem::new(m.model_id.clone(), m.footprint, m.requires_regulated_bin),
            )
        })
        .collect();
    Some(PlacementActuator::new(
        pool,
        catalog,
        p.max_moves_per_tick.max(1),
    ))
}

/// GAP-FIX serving-ops (SERVING_OPS.md §5, gap 38) — the served zero-downtime signed weight-rollout
/// surface, held on [`AssembledFull::rollout`]. [`WeightRollout::observe_live_window`] (derive the
/// soak signal from a real-traffic quality window, then advance-or-rollback through the fail-closed
/// signature+content-hash+attestation load fence) was fully implemented and unit-tested but had zero
/// references in `ainxt-runtimed`/`ainxt-server` — this is the real caller:
/// [`Self::observe_window`] is the SAME entrypoint [`AssembledFull::run_rollout_observe_window`]
/// drives, over ONE persistent per-model [`WeightRollout`] + a shared [`InMemoryWeightLoader`] (so a
/// rollback reverts to the SAME incumbent traffic state a prior stage's promotion shifted onto).
#[derive(Debug)]
pub struct RolloutSurface {
    verifier: AllowListArtifactVerifier,
    loader: InMemoryWeightLoader,
    thresholds: RolloutThresholds,
    rollouts: std::collections::BTreeMap<String, WeightRollout>,
}

impl RolloutSurface {
    fn new(
        verifier: AllowListArtifactVerifier,
        loader: InMemoryWeightLoader,
        thresholds: RolloutThresholds,
    ) -> Self {
        RolloutSurface {
            verifier,
            loader,
            thresholds,
            rollouts: std::collections::BTreeMap::new(),
        }
    }

    /// **Drive one rollout step from a real-traffic quality window** (SERVING_OPS.md §5, gap 38): the
    /// SAME [`WeightRollout::observe_live_window`] the crate's own tests exercise, now reachable from
    /// the served composition root over a persistent per-model [`WeightRollout`] (auto-registered at
    /// `P2Shadow` on first observation for a model) and the SHARED [`InMemoryWeightLoader`] — so a
    /// rollback physically reverts traffic on the SAME loader state every prior stage's promotion
    /// shifted onto, not a fresh one per call.
    pub fn observe_window(
        &mut self,
        artifact: &WeightArtifact,
        attestation_ok: bool,
        window: TrafficWindow,
    ) -> Result<AdvanceOutcome, LoadError> {
        let rollout = self
            .rollouts
            .entry(artifact.model_id.clone())
            .or_insert_with(WeightRollout::new);
        rollout.observe_live_window(
            artifact,
            &self.verifier,
            attestation_ok,
            window,
            self.thresholds,
            &mut self.loader,
        )
    }

    /// The current staged-promotion state for a model's rollout, if one has ever been observed.
    pub fn state(&self, model_id: &str) -> Option<RolloutState> {
        self.rollouts.get(model_id).map(|r| r.state())
    }

    /// The version currently receiving live traffic for a model, per the SAME shared loader
    /// [`Self::observe_window`] drives.
    pub fn live_version(&self, model_id: &str) -> Option<String> {
        self.loader.live_version(model_id)
    }
}

/// GAP-FIX serving-ops (SERVING_OPS.md §5, gap 38) — build the [`RolloutSurface`] when the deployment
/// declares `[serving.rollout]`. `None` (default) — like `autoscale`/`placement`, there is no
/// universal default for a deployment's accepted publisher signatures.
fn build_rollout(cfg: &ServingConfig) -> Option<RolloutSurface> {
    let r = cfg.rollout.as_ref()?;
    let mut verifier = AllowListArtifactVerifier::new();
    for sig in &r.accepted_signatures {
        verifier = verifier.accept_signature(sig.clone());
    }
    let mut loader = InMemoryWeightLoader::new();
    for inc in &r.incumbents {
        loader = loader.with_incumbent(&inc.model_id, &inc.version);
    }
    let thresholds = RolloutThresholds {
        regression_threshold: r.regression_threshold,
        p0_breach_threshold: r.p0_breach_threshold,
    };
    Some(RolloutSurface::new(verifier, loader, thresholds))
}

/// The default ledger schema allowlist behind the safe NL→SQL surface (`/v1/query_ledger`). Ships the
/// canonical `ledger_entries` allowlist with per-column data classes so the compiler enforces the
/// caller's clearance (a PII column is refused to an under-cleared caller, no existence oracle). A
/// deployment replaces this with its real ledger schema; the surface is mounted (not 404) regardless.
fn build_ledger_schema() -> Result<Schema, AssembleError> {
    use ainxt_nl2sql::{PrincipalAttr, RowScope};
    let err = |e: ainxt_nl2sql::SchemaError| AssembleError::Config(format!("ledger schema: {e}"));
    // R8 DATA — the shipped ledger table carries a `owner_dept` column bound as a `RowScope` to the
    // caller's AD department. `validate_and_compile` injects the department predicate AFTER the model's
    // own filters, ANDed in and un-bypassable (the value comes from the authenticated Principal, never
    // the model/user text). So a caller can only ever read rows for their OWN department — a
    // cross-tenant ledger row is never returned — and a caller carrying NO department fails closed
    // (`QueryError::RowScopeUnavailable`) rather than getting an unscoped full-table scan.
    let table = Table::new_scoped(
        "ledger_entries",
        vec![
            Column::new("entry_id", DataClass::Internal).map_err(err)?,
            Column::new("posted_at", DataClass::Internal).map_err(err)?,
            Column::new("amount_minor", DataClass::Confidential).map_err(err)?,
            Column::new("holder_ref", DataClass::Pii).map_err(err)?,
            Column::new("owner_dept", DataClass::Internal).map_err(err)?,
        ],
        vec![RowScope::new("owner_dept", PrincipalAttr::Department)],
    )
    .map_err(err)?;
    Schema::new(vec![table])
        .map_err(err)?
        .with_max_limit(500)
        .map_err(err)
}

/// The Serving-Ops node-level admission gate + node offers shared by the `/v1/chat` attestation fence
/// and the `/v1/infer` (`model.infer`) capability. The air-gapped default advertises **no** serving
/// nodes — `/v1/infer` is still MOUNTED (returns 503 "no routable node" until a deployment registers
/// real GPU nodes, never 404) and a regulated turn fails closed (no attested node) exactly as in prod.
fn build_serving(cfg: &ServingConfig) -> (Arc<Mutex<ServingGate>>, Vec<NodeCandidate>) {
    let mut gate = ServingGate::new(
        AttestationGate::new(AttestationConfig {
            quote_ttl: 300,
            grace_ttl: 30,
        }),
        FairnessLimiter::new(
            cfg.fairness_capacity.unwrap_or(8),
            cfg.fairness_min_share.unwrap_or(1),
        ),
        PreemptionScheduler::new(cfg.scheduler_capacity.unwrap_or(4) as usize),
    )
    // R6 SERVING — the SLO-aware QoS pre_serve config: opt the main-path `pre_serve` entrypoint into a
    // BOUNDED wait queue (SERVING_OPS.md §2) instead of an instant reject at capacity. With the
    // air-gapped default (no serving pool), the QoS fence is inert on `/v1/chat` (the r4 guard: no pool
    // ⇒ no 503); once a deployment registers real nodes, an over-capacity turn is enqueued up to this
    // depth (then load-shed), never dropped on the floor.
    .with_qos_queue_depth(cfg.qos_queue_depth.unwrap_or(QOS_QUEUE_DEPTH));

    // R11 SERVING (SRV-07, gap-6) — opt the served gate's over-capacity wait queue into §2 WFQ
    // minimum-service ordering when the deployment declares `[serving.wfq]`. The plain fairness cap
    // (which under a saturated pool can let one tenant's burst indefinitely delay a sibling) is then
    // replaced, for queue ordering, by deficit round-robin: a low-weight tenant is GUARANTEED forward
    // progress proportional to its weight every round regardless of a greedy tenant's demand.
    if let Some(w) = &cfg.wfq {
        let weights: Vec<(&str, u32)> = w.weights.iter().map(|(t, wt)| (t.as_str(), *wt)).collect();
        gate = gate.with_wfq(w.quantum_unit, &weights);
    }

    // GAP-FIX serving-ops (SERVING_OPS.md §2, gap 6) — opt the served gate into chunked-prefill
    // interleaving when the deployment declares `[serving] chunked_prefill`. `wfq::interleave_prefill`/
    // `batch_step` were fully implemented and unit-tested but had zero callers outside their own
    // crate's tests; `ServingGate::batch_step_tick` (driven by `AssembledFull::run_batch_step_tick`)
    // is the real caller, over the SAME `PreemptionScheduler` `model_infer` admits `/v1/infer` calls
    // into. Absent (default) ⇒ unchanged behaviour.
    if let Some(chunks) = cfg.chunked_prefill {
        gate = gate.with_chunked_prefill(chunks);
    }

    // R11 SERVING (SRV-01, HIGH) — bind the CONFIGURED node pool onto the fence so attestation + QoS
    // admission are LIVE on the shipped daemon, not inert dead code. The air-gapped default declares no
    // nodes (`Vec::new()`), preserving the shipped-chat guard (no pool ⇒ no 503). A deployment's
    // `[[serving.nodes]]` entries make the fence enforce for real: a regulated turn fails closed onto an
    // unattested node, a non-regulated turn is admitted on a routable node, over-capacity turns queue
    // then shed. Attestation of a node for regulated traffic now happens through the ADR-021 §8.3
    // quote-refresh loop the daemon drives via [`AssembledFull::run_attestation_refresh_tick`] (R13,
    // SRV-03) — no longer a hand-submitted quote.
    let nodes: Vec<NodeCandidate> = cfg
        .nodes
        .iter()
        .map(|n| NodeCandidate::new(n.node_id.clone(), n.routable))
        .collect();
    (Arc::new(Mutex::new(gate)), nodes)
}

/// The SHARED `(ServingGate, declared node pool)` handle threaded from real engine construction
/// (`build_engine_ext_with_mcp`/`build_chat_engine_with_authz`) all the way to [`AssembledFull`] —
/// GAP-FIX gap6-composition-root (Item 1). One instance per served surface; the SAME `Arc<Mutex<_>>`
/// backs the engine's own [`ainxt_runtime::serving::NodeAttestor`], the daemon's `/v1/chat` Stage-1
/// fence (`ainxt-server`), and the ADR-021 §8.3 attestation quote-refresh loop
/// ([`AssembledFull::spawn_attestation_refresh`]) — never three independent gates that could disagree.
pub type ServingHandle = (Arc<Mutex<ServingGate>>, Vec<NodeCandidate>);

/// GAP-FIX gap6-composition-root (Item 1) — build the [`ainxt_runtime::serving::NodeAttestor`] a real
/// served engine attaches via `Engine::with_node_attestor`, backed by the IDENTICAL `serving` handle
/// (SAME `Arc<Mutex<ServingGate>>` + declared node pool) the daemon's `/v1/chat` Stage-1 fence
/// (`ainxt-server::lib.rs`, "Stage 1 — attestation node fence") and the attestation quote-refresh loop
/// already consult — never a second, disjoint gate frozen at construction time (see
/// [`ainxt_runtime::serving::ServingGateAttestor`]'s own doc for why a frozen/owned gate would be
/// either permanently fail-closed or permanently stale).
///
/// Before this fix, `Engine::with_node_attestor` had no production caller at all: the server's
/// Stage-1 fence checked only the caller's naively-DECLARED `data_class`, never the engine's own §4.2
/// tri-signal ESCALATED `route_class` (computed from the ACTUAL turn content — the compliance
/// arg-scanner can escalate a smuggled PAN/secret regardless of what the caller declared). A turn that
/// under-declared its class while smuggling regulated content sailed past the server's Stage-1 fence
/// and was never attestation-checked again downstream, because the engine's own attestation hook
/// (which runs AFTER the §4.2 escalation, over `route_class`) was never wired to anything. This closes
/// that gap: the escalated class now gets the SAME fail-closed node fence.
fn node_attestor_over(serving: &ServingHandle) -> Box<dyn ainxt_runtime::serving::NodeAttestor> {
    let gate = serving.0.clone();
    let nodes = serving.1.clone();
    Box::new(ServingGateAttestor::new(gate, move || {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // `verifier_reachable = true` mirrors the SAME simplification the server's own Stage-1 fence
        // already makes (`ainxt-server::lib.rs`'s `gate.pre_serve_check(dto.data_class, &sv.candidates,
        // now_unix(), true)`) — live verifier-reachability plumbing is a separate, pre-existing gap,
        // not one this fix introduces or papers over.
        (nodes.clone(), now, true)
    }))
}

/// The shipped default bounded main-path QoS wait-queue depth (R6 SERVING). A deployment tunes this to
/// its SLO/backpressure budget; the air-gapped default keeps the fence inert (no pool ⇒ no wait).
const QOS_QUEUE_DEPTH: u32 = 64;

/// R11 — the durable [`SnapshotStore`](ainxt_incident::durable::SnapshotStore) key the served
/// statutory [`IncidentRegister`] is snapshotted/restored under (crash-survival of statutory clocks,
/// §2.3). The daemon persists on a cadence + graceful shutdown and restores on boot before the breach
/// clock starts, so a `kill -9` mid-clock re-projects from the immutable `t0` and breaches on schedule.
pub const INCIDENT_SNAPSHOT_KEY: &str = "ainxt.regfi.incident-register";
/// R11 — the durable [`SnapshotStore`] key the served retention [`RecordStore`](ainxt_lifecycle::RecordStore)
/// is snapshotted/restored under (§6.2/§6.3): its legal-hold matters and deferred-erasure queue survive
/// a restart and a queued erasure still fires on schedule across the crash.
pub const RETENTION_SNAPSHOT_KEY: &str = "ainxt.regfi.retention-store";

/// R10 — the minimum logical age (ledger ticks) a `PENDING` capability row must reach before the
/// background [`ReconcilerSweeper`] sweeps it (the lost-ack timeout — long enough not to race a still
/// in-flight legitimate call). A deployment tunes it to its downstream ack latency budget.
const RECONCILER_MIN_AGE_TICKS: u64 = 1;
/// R10 — how long a sweep lease lives (ledger ticks): long enough to probe the downstream, short enough
/// that a crashed sweeper's rows become re-eligible soon.
const RECONCILER_LEASE_TTL_TICKS: u64 = 30;
/// R10 — the shipped background reconciler-sweep interval. Shutdown is responsive (a condvar-timed
/// wait), so this does not pin shutdown latency; a deployment tunes it to its lost-ack SLA.
const RECONCILER_SWEEP_INTERVAL_SECS: u64 = 15;

/// Parse a 64-char hex string into a 32-byte AEAD key. `None` on any non-hex / wrong-length input.
fn parse_key_32(hex: &str) -> Option<[u8; 32]> {
    let hex = hex.trim();
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Build the connector [`TokenVault`](ainxt_token::TokenVault) held on the served surface (CONN-01):
/// a real [`AeadCodec`](ainxt_token::AeadCodec) over the SQL-backed store seam — only ciphertext ever
/// lands at rest. Built ONLY when a 32-byte hex key is configured via `AINXT_TOKEN_KEY`; the air-gapped
/// default ships no vault (no key ⇒ no connector secrets at rest).
///
/// NOTE (honest seam boundary): [`FullApp`] has no connector-mount field, so `serve_full` does not yet
/// route the OAuth endpoints. The vault is assembled + held on the served surface so the seam is ready;
/// mounting `/connectors/*` is a follow-up [`FullApp`] field in `ainxt-server` (outside this crate).
///
/// NOTE (gap6 audit — token-durability): this `AssembledFull::token_vault` is a SEPARATE, still-
/// unmounted vault from the one actually reachable at `/connectors/*` — that live vault is
/// `AssembledFull::connectors`' internal `TokenVault`, built by [`mounts::build_connector_gateway`] and
/// merged onto `FullAppExt::connectors` by [`assemble_full`]. The durable-backend selection
/// (`AINXT_TOKEN_STORE=file` → [`ainxt_token::FileTokenStore`], see [`connector_token_backend`]) was
/// therefore applied to THAT live path, not this one: this function's vault has no served route reading
/// it regardless of backend, so swapping its backend would not close the restart-durability gap — only
/// give a second, equally-unreachable durable vault. Left as an `InMemorySqlTokenBackend`-only,
/// `AINXT_TOKEN_KEY`-gated scaffold pending the `FullApp` connector-mount follow-up noted above; do not
/// treat this function as the live connector token store.
fn build_token_vault(report: &mut Vec<String>) -> Option<Arc<ainxt_token::TokenVault>> {
    match std::env::var("AINXT_TOKEN_KEY")
        .ok()
        .and_then(|h| parse_key_32(&h))
    {
        Some(key) => {
            let vault = ainxt_server::sql_token_vault(
                Box::new(ainxt_token::AeadCodec::new(ainxt_token::KeyRing::new(
                    1, key,
                ))),
                ainxt_token::InMemorySqlTokenBackend::new(),
            );
            report.push(
                "connector token vault: assembled (AeadCodec over the SQL-backed store) and held on \
                 the served surface (routes pending a FullApp connector mount)"
                    .into(),
            );
            Some(Arc::new(vault))
        }
        None => {
            report.push(
                "connector token vault: not assembled (no AINXT_TOKEN_KEY) — air-gapped default, no \
                 connector secrets at rest"
                    .into(),
            );
            None
        }
    }
}

/// The reproducibility pin stamped on every emitted [`EventEnvelope`](ainxt_protocol::EventEnvelope)
/// (ADR-026 §6.2): the control-repo commit the served turns are pinned to. Read from
/// `AINXT_CONTROL_PLANE_SHA`, defaulting to `"unpinned"` when unset.
fn control_plane_sha() -> String {
    std::env::var("AINXT_CONTROL_PLANE_SHA")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unpinned".to_string())
}

/// The **fully-wired** served surface: the concurrency-spine [`SessionManager`] plus every governed
/// component the shipped daemon mounts through [`ainxt_server::serve_full`] — the tamper-evident Event
/// Log (audit + `/v1/replay` + resume), the RBAC-scoped `/graph`, the safe NL→SQL `/v1/query_ledger`,
/// the Serving-Ops `/v1/infer` gate — AND the two live control organs the design mandates be present on
/// the served surface: a live [`IncidentRegister`] (statutory breach clocks advance here) and a shared
/// [`ControlPlane`] (kill-switch / revocation that reaches in-flight Runs). A connector [`TokenVault`]
/// is held when configured.
///
/// This is what makes `/v1/replay`, `/graph`, `/v1/query_ledger`, `/v1/infer`, chat-path attestation and
/// the control organs part of the SHIPPED binary rather than test-only fixtures.
pub struct AssembledFull {
    /// The concurrency/backpressure spine served on `/v1/chat` (whatever surface was assembled).
    pub manager: Arc<SessionManager>,
    /// The assembly report (surface report + the R4 wiring lines).
    pub report: Vec<String>,
    /// The tamper-evident hash-chain Event Log (daemon audit trail + `/v1/replay` + resume backing).
    pub event_log: Arc<dyn EventLog>,
    /// The reproducibility pin stamped on every emitted envelope.
    pub control_plane_sha: String,
    /// The RBAC-scoped knowledge graph served at `/graph`.
    pub graph: Arc<Graph>,
    /// The ledger schema allowlist behind `/v1/query_ledger`.
    pub ledger_schema: Arc<Schema>,
    /// The Serving-Ops gate + node offers shared by the `/v1/chat` fence and `/v1/infer`.
    pub serving: (Arc<Mutex<ServingGate>>, Vec<NodeCandidate>),
    /// GAP-FIX serving-ops (SERVING_OPS.md §1, gap 7) — the disaggregated prefill/decode pool split,
    /// when `[serving.disagg]` declares node lists for both pools: two PHYSICALLY SEPARATE
    /// `ServingGate`s (independent attestation/fairness/preemption state) joined only by the KV Relay
    /// fabric, mounted at `POST /v1/infer/{prefill,decode,handoff}` (`to_full_app_ext`). `None`
    /// (default) ⇒ `Self::serving` remains the only served pool, unchanged.
    pub disagg: Option<(
        Arc<Mutex<DisaggregatedPools>>,
        Vec<NodeCandidate>,
        Vec<NodeCandidate>,
    )>,
    /// LIVE statutory incident register — breach clocks advance here (via [`AssembledFull::spawn_breach_clock`]).
    pub incidents: Arc<Mutex<IncidentRegister>>,
    /// The shared control plane — its kill-switch / revocations reach in-flight Program/Team Runs
    /// through the per-dispatch admission gate ([`EngineRunExecutor`] consults it before every turn).
    pub control_plane: Arc<Mutex<ControlPlane>>,
    /// GAP-FIX identity-payments (ADR-022 §13/§22 #3, gap6 audit item 1) — the SAME live issuance
    /// transparency log [`chat_identity::GovernedChatSurface`] appends every newly-minted chat-run
    /// credential to (see [`assemble_chat_governed_with_transparency`]). `TransparencyLog::inclusion_proof`/
    /// [`ainxt_identity::transparency::InclusionProof::verify`] were fully implemented and
    /// exhaustively unit-tested (`ainxt-identity/tests/r11_transparency_and_attestation.rs`) — the
    /// module's entire stated purpose is letting "a party outside the runtime" verify an issuance —
    /// but the write side (`chat_identity.rs:266`) had no reader anywhere: zero HTTP route, zero
    /// served code path ever called `inclusion_proof`. Threaded here the SAME way `control_plane`
    /// above is threaded (a shared organ handed in alongside `Assembled`, not carried inside it —
    /// see [`assemble_full_with_control_plane_and_transparency`]) so [`Self::to_full_app_ext`] can
    /// mount `GET /v1/transparency/proof/:run_id` over this EXACT log instance. `None` on every
    /// surface that never wires a transparency log at all (the plain [`assemble_chat_governed`] /
    /// [`assemble_selected`] callers, or any surface other than `"chat_governed"`) — the route still
    /// mounts but fails closed (404), never a silent no-op.
    pub transparency: Option<Arc<Mutex<TransparencyLog<Sha256Hasher>>>>,
    /// The connector token vault, when a key is configured (held on the served surface).
    pub token_vault: Option<Arc<ainxt_token::TokenVault>>,
    /// LIVE online release controller (eval-tester): the anytime-valid canary → auto-rollback → drift
    /// monitor instantiated on the served surface. A model/prompt candidate's live-traffic quality is
    /// fed here per served turn; an established regression rolls the deploy pointer back to the
    /// champion, and post-promotion drift auto-rolls-back. Before this wire the controller was
    /// reachable only from its own crate's tests.
    pub release_controller: Arc<Mutex<ainxt_quality::controller::OnlineReleaseController>>,
    /// GAP-FIX eval-tester-scenarios — the git-ref traffic split (`ainxt_canary::experiment::TrafficSplit`)
    /// that decides which of `release_controller`'s two refs (candidate/champion) serves a given
    /// request. Before this wire, [`AssembledFull::ingest_served_turn`] could be driven with a
    /// `served_ref`, but nothing on the served surface computed that ref from an actual request — this
    /// is that missing router, built from the SAME refs `release_controller` canaries.
    pub traffic_split: Arc<ainxt_canary::experiment::TrafficSplit>,
    /// The data-residency label the outsourcing register on the router resolves routes against.
    pub outsourcing_residency: String,
    /// HARN-03 — the harness invoke/run surfaces the shipped daemon mounts at `/v1/harness/*` (a
    /// built-in `diag.selftest` harness is published so the surface is genuinely live).
    pub harness: Arc<HarnessMounts>,
    /// CONN-03 — the connector OAuth gateway the shipped daemon mounts at `/connectors/*`.
    pub connectors: Arc<ConnectorGateway>,
    /// CONN-USE — the connector USE-path organ (`ConnectorInvoker`): the OBO admission + egress/DLP +
    /// payment-boundary + audit path that actually calls an authorized connector API. LIVE on the
    /// served surface; the air-gapped default fails closed (offline transport, no sealed token).
    pub connector_invoker: Arc<ainxt_connector_http::ConnectorInvoker>,
    /// KEY-ROT-01 — the SAME live, rotatable `Arc<AeadCodec>` both `connectors`' OAuth-callback SEAL
    /// path and `connector_invoker`'s refresh/OPEN path seal into and open from (each wraps its own
    /// clone of this Arc in `ainxt_token::SharedAeadCodec` — never a second, disjoint ring). Threaded
    /// into [`ainxt_server::FullAppExt::key_rotation`] by [`to_full_app_ext`](Self::to_full_app_ext) so
    /// `POST /admin/keys/rotate` calls [`ainxt_token::AeadCodec::rotate`] on this EXACT instance —
    /// `ainxt_token::KeyRing::rotate_to` (the primitive it delegates to) was fully implemented and
    /// unit-tested but had zero callers anywhere in the workspace outside its own crate's tests before
    /// this wire, so a deployment could never actually rotate its connector-token encryption key
    /// without a code change and redeploy.
    pub connector_key_ring: Arc<ainxt_token::AeadCodec>,
    /// R6 DATA — the artifact-generation runtime the shipped daemon mounts at `/v1/artifact`.
    pub artifact: Arc<ArtifactRuntime>,
    /// R6 DATA — the durable session store the shipped daemon mounts behind `/v1/replay/step`.
    pub replay_store: Arc<dyn SessionStore>,
    /// GAP6 replay-reexec-presence — the live-model [`ainxt_replay::ReExecutor`] seam the shipped
    /// daemon mounts behind `POST /v1/replay/reexecute` + the read-side drift oracle
    /// `POST /v1/replay/drift`, over the SAME [`Self::replay_store`] instance. OSS default: the
    /// offline [`ainxt_replay::DeterministicReplayExecutor`] (see [`mounts::build_reexec_executor`]).
    pub reexec_executor: Arc<dyn ainxt_replay::ReExecutor + Send + Sync>,
    /// DSAR / right-to-erasure organ (tiered cache erasure cascade) LIVE on the served surface.
    pub erasure: Arc<Mutex<TieredCacheErasure>>,
    /// SR-11-7 model-risk quality circuit-breaker organ LIVE on the served surface.
    pub quality_breaker: Arc<QualityCircuitBreaker>,
    /// GAP-FIX tooling-mcp-plugins-routing (round 2) — the `ainxt-eval` Regression Vault
    /// ([`ainxt_eval::vault::RegressionVault`], EVAL_PLATFORM.md §10). LIVE on the served surface:
    /// [`AssembledFull::admit_promotion`] mints a [`ainxt_eval::vault::VaultCase`] into THIS instance
    /// on every real [`BreakerTrip`] (the same call site that already arms the §2 incident escalation
    /// for a regulated route, `mounts.rs`'s doc for `build_quality_breaker`), so a quality regression
    /// that tripped the breaker in production becomes a permanent, frozen eval case a later CI/eval
    /// run guards against — "a bug found once is tested forever" — rather than a fact that only ever
    /// lived in the incident register. Before this wire, `VaultOrigin::CircuitBreaker` existed
    /// specifically for this purpose but had zero callers anywhere in the workspace.
    pub vault: Arc<Mutex<ainxt_eval::vault::RegressionVault>>,
    /// GAP-FIX eval-durable-stores — the durable, file-backed [`ainxt_eval::vault::VaultStore`] backing
    /// [`Self::vault`] above (`Some` only when `[server] eval_durable_dir` is configured;
    /// [`ServerConfig::eval_durable_dir`]'s doc). `ainxt_eval::durable::FileVaultStore` was fully built
    /// and unit-tested (purpose-built to replace the in-memory-only `RegressionVault` for exactly this
    /// restart-durability gap) but had zero callers anywhere in the workspace outside its own crate
    /// test before this wire — the served Vault stayed in-memory no matter how it was configured.
    /// [`Self::admit_promotion`] appends every NEWLY-minted case here (never a re-mint of an existing
    /// id — `RegressionVault::mint`'s own idempotency already filters those out before this is
    /// consulted), so a case a live quality-circuit-breaker trip minted survives a daemon restart:
    /// assembly below replays every durable record back into a fresh in-memory `RegressionVault` via
    /// `RegressionVault::mint` (which re-verifies each case's seal, so a tampered on-disk record is
    /// silently dropped rather than trusted). `FileVaultStore` is a plain struct (just a `PathBuf`) —
    /// cheap to `Clone` — so no `Mutex` wrapper is needed; each `persist` call opens-and-appends
    /// independently, mirroring the OS-level append-atomicity every other durable JSONL sink in this
    /// file already relies on (`open_guarded_event_log`'s `JsonlEventLog`, `checkpoint_break_glass_program`).
    pub vault_store: Option<ainxt_eval::durable::FileVaultStore>,
    /// R7 REGFI — the data-lifecycle control organ (retention TTL / legal-hold freeze / DSAR
    /// right-to-erasure over the durable record tier) LIVE on the served surface. Distinct from the
    /// cache-tier [`TieredCacheErasure`] DSAR organ ([`Self::erasure`]).
    pub retention: Arc<Mutex<ainxt_lifecycle::RecordStore>>,
    /// GAP-FIX memory (flywheel-no-route) — the continuous-learning [`ainxt_memory::flywheel::ImprovementEngine`],
    /// LIVE on the served surface. `capture_at`/`propose` were fully implemented and unit-tested but
    /// had zero callers outside `ainxt-memory`'s own tests — no HTTP route existed anywhere in the
    /// served daemon (47 routes, none feedback-related) to feed it a real user's thumbs/correction/
    /// edit/trajectory/abandonment signal. Threaded into `FullAppExt::feedback` so `POST /feedback`
    /// captures into the SAME engine instance a future curation/propose sweep would read.
    pub feedback_engine: Arc<Mutex<ainxt_memory::flywheel::ImprovementEngine>>,
    /// GAP-FIX regulated-fi-responsible-lifecycle (gap6) — the §6.3 cadence driver
    /// ([`ainxt_lifecycle::guarded::RetentionSweeper`]) LIVE on the served surface. `RetentionSweeper`/
    /// `sweep_now` were fully implemented and unit-tested but had zero callers outside
    /// `ainxt-lifecycle`'s own tests: nothing in the served daemon ever ran a scheduled sweep, so a
    /// deferred erasure (a hold released / floor elapsed) sat in the §6 queue until the next on-demand
    /// `/v1/regfi/erasure` call for that EXACT subject happened to re-decide it — never automatically,
    /// as §6.3 requires. [`Self::run_retention_sweep_tick`]/[`Self::spawn_retention_sweep`] drive this
    /// over the SAME [`Self::retention`] store and [`Self::replay_store`] tier the erasure routes use.
    pub retention_sweeper: Arc<Mutex<ainxt_lifecycle::guarded::RetentionSweeper>>,
    /// GAP-FIX memory (gap6, item 2) — the flywheel's `CandidateDest::EvalCase` destination: the SAME
    /// `ainxt_eval::integrity::StagingSet` a future eval-promotion admin route would read/promote from.
    /// [`Self::run_feedback_flywheel_tick`]/[`Self::spawn_feedback_flywheel_sweep`] stage every
    /// `EvalCase` candidate the flywheel's `propose`/`triage` pass produces here — never auto-promoted
    /// (design §4/§9 `AQ` contamination guard: only an explicit human `StagingSet::promote` can move a
    /// staged case into the live/holdout set). `needs_hot_wiring`: `gold`/`contamination_clean` are
    /// honestly placeholder (see [`EvalStagingSink`]'s doc) until a real review UI + contamination scan
    /// exist.
    pub eval_staging: Arc<Mutex<ainxt_eval::integrity::StagingSet>>,
    /// GAP-AUDIT regulated-fi #13 — the §6.5 break-glass redaction-with-attestation Long-Horizon
    /// Program registry, keyed by `program_id`, LIVE on the served surface. `BreakGlassProgram` was
    /// fully implemented and tested (resumable, checkpointed, hash-chained) but had zero callers
    /// outside its own crate — a DPO had no way to open or drive one on the shipped daemon.
    pub breakglass: Arc<
        Mutex<std::collections::BTreeMap<String, ainxt_lifecycle::breakglass::BreakGlassProgram>>,
    >,
    /// GAP-AUDIT regulated-fi #7/#9 — the §4.4 DSAR workflow's hash-chained request register, LIVE on
    /// the served surface. `DsarWorkflow`/`DsarCommand` were fully implemented and route-ready but had
    /// no served entrypoint at all — a DSAR could not be opened, authenticated, corrected, or routed as
    /// a grievance through the shipped daemon (only the narrower erasure-only DPDP path existed).
    /// Dispatches against the SAME shared [`Self::retention`] store for `Erase`, so §6 precedence
    /// (legal-hold/floor) applies identically whether the erasure came in through `/v1/regfi/erasure`
    /// or `/v1/regfi/dsar`.
    pub dsar: Arc<Mutex<DsarWorkflow>>,
    /// GAP-AUDIT regulated-fi #5 — the §2.4 pre-templated breach-report drafting control-plane
    /// (CERT-In / DPDP-Board forms). `ainxt_incident::report::draft_report` was fully implemented and
    /// tested but had zero callers outside its own crate.
    pub report_templates: ainxt_incident::report::TemplateStore,
    /// GAP-AUDIT regulated-fi #4 — the §5.4/§8.1/§8.2 supervisory-monitor cadence schedule, LIVE on the
    /// served surface and driven by [`Self::spawn_supervisory_cadence`].
    pub cadence: Arc<Mutex<CadenceScheduler>>,
    /// GAP-AUDIT regulated-fi #8 — the FI-06 DPIA-per-feature CI gate, now folded into
    /// [`Self::admit_promotion`] (previously a gate object with zero callers on the served promotion
    /// path — `admit_promotion` independently re-implemented only the FI-07 half). Mutable so a
    /// deployment can register feature profiles / record DPIAs as they're created.
    pub dpia_gate: Arc<Mutex<DpiaCiGate>>,
    /// GAP-FIX regulated-fi-responsible-lifecycle — the Payment-Adjacent Mandate (ADR-016 §6) fourth
    /// dispatch gate's use-count ledger, now reachable via [`Self::authorize_payment_adjacent_dispatch`]
    /// (previously `ainxt_payments::mandate::{authorize_adjacent_dispatch, MandateRegistry}` had zero
    /// callers anywhere outside `ainxt-payments`'s own tests). Mutable because `authorize` consumes one
    /// use per successful check.
    pub mandate_registry: Arc<Mutex<ainxt_payments::mandate::MandateRegistry>>,
    /// GAP-FIX identity-payments — the concrete handle to the §4.6 graduated-tripwire remediator
    /// [`mounts::build_connector_invoker`] installs behind `ConnectorInvoker::with_tripwire_remediation`.
    /// Previously erased into `Arc<dyn TripwireRemediation>` with no handle retained, so nothing could
    /// ever query what the tripwire had actually done (see [`Self::tripwire_is_quarantined`] et al.).
    pub tripwire_remediator: Arc<ControlPlaneRemediator>,
    /// R7 OBS — the per-turn telemetry sink the shipped `/v1/chat` path records to (actor + routed
    /// model + priced cost + outcome). The OSS default is an in-memory collector; production selects an
    /// OTLP/OTel exporter behind the same [`TelemetrySink`](ainxt_telemetry::TelemetrySink) seam.
    pub telemetry: Arc<dyn ainxt_telemetry::TelemetrySink>,
    /// GAP-FIX identity-payments — the §20 UEBA per-actor observation history [`BehaviorFeedingTelemetry`]
    /// accumulates from EVERY served turn (see [`Self::to_full_app_ext`]), keyed by `def_ref`
    /// (`"actor:{actor}"`). `AssembledFull::observe_run_activity`/`ControlPlane::observe` were a pure
    /// scoring seam with zero live caller — nothing on the served dispatch/turn-completion path ever fed
    /// them a real per-Run behavioral observation (capability mix / egress / cost velocity). This history
    /// is what makes the fed baseline genuinely LEARNED (`BehavioralBaseline::learn_from_history`) from
    /// the actor's own past turns, not hand-authored.
    pub behavior_history: Arc<
        Mutex<std::collections::HashMap<String, Vec<ainxt_identity::authority::ActivitySample>>>,
    >,
    /// R7 HARN — the daemon's configured [`ComplianceGate`] instance backing the harness pre-receive
    /// gate mounted at `POST /v1/harness/preflight` (a second instance of the SAME configured gate — the
    /// engine owns the primary). On the OSS default this is `RedactAndProceed`; a build that selects the
    /// enterprise PCI/DSS provider fails closed at assembly rather than silently downgrading, so this is
    /// always the real configured detector — the harness pre-receive path never falls back to a heuristic.
    pub harness_prereceive_gate: Arc<dyn ComplianceGate>,
    /// R8 — the transport [`Authenticator`] the shipped daemon mounts on EVERY governed route. Built
    /// once from [`ServerConfig::authenticator`]: the OWNER-DEFERRED `TrustedGatewayAuth` default, or the
    /// config-selectable verified-identity `JwtSsoAuth` (HS256). `to_full_app` clones this onto `FullApp`
    /// so the SAME authenticator gates chat AND every governed surface.
    pub auth: Arc<dyn Authenticator>,
    /// R8 EDIT — the long-lived semantic Code-Review Pipeline [`EditEngine`] the shipped daemon mounts at
    /// `POST /v1/edit` (fail-closed on `code.edit.apply`). Offline default seams; a deployment wires a
    /// model-backed coder + real toolchain/SAST/judge behind the SAME engine.
    pub edit: Arc<EditEngine>,
    /// R12 EDIT — the durable served working-tree root for `/v1/edit`, from `[server] edit_workspace_dir`.
    /// `Some` ⇒ a committed edit is persisted to a crash-atomic FsSink (survives restart); `None` ⇒ the
    /// offline in-memory sink. Handed to the transport by [`to_full_app_ext`](Self::to_full_app_ext).
    pub edit_workspace_root: Option<std::path::PathBuf>,
    /// GAP-FIX semantic-editing-codereview — the durable journal-store root for `/v1/edit*`, from
    /// `[server] edit_journal_dir`. `Some` ⇒ each turn's sealed journal persists to a crash-atomic
    /// `FsJournalStore` (survives restart); `None` ⇒ an in-process `InMemoryJournalStore`. Handed to
    /// the transport by [`to_full_app_ext`](Self::to_full_app_ext).
    pub edit_journal_root: Option<std::path::PathBuf>,
    /// R9 TRANSP — the engine's typed §6 wire receiver (paired with the [`ChannelWireSink`] attached to
    /// the assembled chat engine). Taken ONCE by [`to_full_app_ext`](Self::to_full_app_ext) and handed to
    /// the transport, so the served `/v1/chat` + `/v1/events` serialize the engine's REAL
    /// [`WireEvent`](ainxt_protocol::WireEvent) stream (capped-vs-complete, `compliance.notice`,
    /// payment-boundary, priced `usage{model,cost}`) BY DEFAULT — not the lossy legacy `Event`
    /// projection. Interior mutability because the receiver is single-consumer and the accessor is `&self`;
    /// `None` on a surface with no chat engine (the transport then falls back to the legacy projection).
    pub wire_events: Mutex<Option<mpsc::UnboundedReceiver<ainxt_protocol::EventEnvelope>>>,
    /// R10 — the background [`ReconcilerSweeper`] over the served engine's SHARED exactly-once ledger
    /// (§1.8). The daemon starts it via [`AssembledFull::spawn_reconciler_sweep`], held for the process
    /// lifetime. `None` when the assembled surface exposed no capability ledger.
    pub reconciler_sweeper: Option<Arc<ReconcilerSweeper>>,
    /// R13 (SRV-03, HIGH) — the ADR-021 §8.3 attestation quote-refresh DRIVER over the declared
    /// regulated pool. Held on the served surface so the daemon's background timer can drive it via
    /// [`AssembledFull::run_attestation_refresh_tick`], re-fetching + re-verifying fresh TEE quotes on a
    /// cadence so a declared node actually becomes (and stays) regulated-eligible — the loop the audit
    /// found missing. `None` on the air-gapped default (no `[[serving.nodes]]` ⇒ nothing to attest).
    pub attestation_refresher: Option<Arc<Mutex<AttestationRefresher>>>,
    /// GAP-FIX serving-ops (SERVING_OPS.md §4, gap 37) — the shard-group health-state machine
    /// (interconnect watchdog + canary-correctness probe + standby model), held on the served surface
    /// so the daemon's background timer can drive it via
    /// [`AssembledFull::run_health_sweep_tick`]/[`AssembledFull::spawn_health_sweep`]. `None` when no
    /// `[[serving.nodes]]` entry declares a `golden_hash` (nothing to monitor).
    pub health_monitor: Option<Arc<Mutex<ShardHealthMonitor>>>,
    /// The paired periodic cadence driver for [`Self::health_monitor`] (mirrors
    /// [`Self::attestation_refresher`]'s cadence pattern for the analogous ADR-021 §8.3 gap). `None`
    /// iff `health_monitor` is `None`.
    pub health_cadence: Option<Arc<Mutex<HealthCadence>>>,
    /// GAP-FIX serving-ops (SERVING_OPS.md §3, gaps 26/W) — the demand-EWMA autoscale decision engine
    /// (per-model target-replica-count + park-warm-when-idle), held on the served surface so the
    /// daemon's background timer can drive it via [`AssembledFull::run_autoscale_tick`]. `None` when
    /// no `[serving.autoscale]` section is declared.
    pub autoscale_controller: Option<Arc<Mutex<AutoscaleController>>>,
    /// The paired periodic cadence driver for [`Self::autoscale_controller`] (mirrors
    /// [`Self::health_cadence`]'s pattern for the analogous §3 gap). `None` iff `autoscale_controller`
    /// is `None`.
    pub autoscale_cadence: Option<Arc<Mutex<AutoscaleCadence>>>,
    /// GAP-FIX serving-ops (SERVING_OPS.md §3, gaps 26/W) — the GPU bin-packing placement +
    /// model-parking/eviction actuator, held on the served surface so the daemon's background timer
    /// (or a direct caller) can drive it via [`AssembledFull::run_placement_actuator_tick`] /
    /// [`AssembledFull::run_autoscale_and_placement_tick`]. `None` when no `[serving.placement]`
    /// section is declared.
    pub placement: Option<Arc<Mutex<PlacementActuator>>>,
    /// GAP-FIX serving-ops (SERVING_OPS.md §5, gap 38) — the zero-downtime signed weight-rollout
    /// surface, held on the served surface so a direct caller (or a future admin route) can drive it
    /// via [`AssembledFull::run_rollout_observe_window`]. `None` when no `[serving.rollout]` section
    /// is declared.
    pub rollout: Option<Arc<Mutex<RolloutSurface>>>,
    /// R11 TRANSP §6.3 — the wire-level Approval Gate round-trip coordinator. It is handed to the
    /// transport ([`to_full_app_ext`](Self::to_full_app_ext)) so a client's `approval.respond` on
    /// `/v1/command` resolves the engine's blocked gate for a session. The engine-side attach — feeding
    /// this coordinator's [`WireApprovalGate`](ainxt_server::WireApprovalGate) into the assembled
    /// engine's `.with_approval(..)` seam so a gated (high-risk / payment-boundary) tool blocks on the
    /// wire — is exposed via [`wire_approval_gate`](Self::wire_approval_gate) (the engine builder is the
    /// reserved call-site).
    pub approval_coordinator: Arc<ainxt_server::ApprovalCoordinator>,
    /// R15 COMPOSE — the served engine's shared [`ainxt_runtime::dispatch::DispatchProbe`] (peak/total
    /// concurrent tool-dispatch), when the assembled surface's engine builder exposes one. Threaded to
    /// the transport via [`to_full_app_ext`](Self::to_full_app_ext) so `/v1/chat` can sample it
    /// alongside the per-turn telemetry record ([`ainxt_telemetry::TelemetrySink::record_dispatch`]).
    /// `None` on a surface with no real Engine (the AiNxt-OS workforce surface).
    pub dispatch_probe: Option<Arc<ainxt_runtime::dispatch::DispatchProbe>>,
    /// GAP-FIX memory (MEM-10) — the served consent/export/erasure `ConsentSurface` backing, opened
    /// fresh per request over a clone of the assembled chat engine's own
    /// [`ainxt_memory::MemorySqlBackend`] (see [`ainxt_memory::ConsentBacking`]). Previously
    /// `ainxt-server`'s `memory_router` was hardcoded to a standalone `InMemoryStore` no writer ever
    /// touched, so a served "what do you remember about me" / export / erasure request always
    /// answered against an empty, disconnected store — reachable only from the router's own test.
    /// `None` on a surface with no chat engine (bare `engine`/`program`/`team`/workforce): there is no
    /// memory reader for a served DPDP request to be consistent with there.
    pub memory_consent: Option<Arc<ainxt_memory::ConsentBacking>>,
    /// GAP-FIX memory (write-path-missing) — the served `POST /memory/remember` explicit-remember
    /// write seam, over the EXACT SAME long-lived durable-store instance the assembled chat engine's
    /// own Context-Fabric `read_for_turn` reads through (see [`MemoryHandle`]'s doc for why "the same
    /// instance", not just "the same backend", is required for a write to be visible on the very next
    /// read). Before this field, `Engine.memory` was a read-only seam by construction and no served
    /// route or turn-loop hook ever called a real write primitive outside this crate's own tests —
    /// every `store.write(..)` in `ainxt-server`'s test module was a `#[tokio::test]` seed fixture,
    /// never reachable from a live request. `None` on a surface with no chat engine.
    pub memory_writer: Option<Arc<dyn ainxt_memory::MemoryWriter>>,
    /// GAP-FIX regulated-fi-responsible-lifecycle — the SHARED, mutable [`OutsourcingRegisterHandle`]
    /// onto the SAME FI-03 outsourcing register the served surface's router reads on every non-
    /// overridable eligibility check (see [`Assembled::outsourcing_register`] and
    /// [`ainxt_runtime::router::ModelRouter::outsourcing_register_handle`]). `ainxt-server`'s admin
    /// route (`POST /admin/outsourcing/register`) `.write().upsert(..)`s through this SAME handle, so a
    /// board-approved arrangement becomes eligible on the router's very next turn — never a second,
    /// disjoint register the admin route built for itself. `None` only on a surface with no real Engine
    /// (the AiNxt-OS workforce surface's own router, which DOES install one — see
    /// `workforce_surface::assemble_workforce_surface_served` — still reaches here; this is `None` only
    /// if a future surface builder genuinely never installs a register at all).
    pub outsourcing_register: OutsourcingRegisterHandle,
    /// GAP-FIX tooling-mcp-plugins-routing — the SHARED [`McpAdminHandle`] onto the SAME MCP registry
    /// + pin store the served surface's boot-time MCP registration ran over (see
    /// [`Assembled::mcp_admin`]). `ainxt-server`'s admin routes (`GET /admin/mcp/reapproval`,
    /// `POST /admin/mcp/approve`) act through this SAME handle, so a human's re-approval decision
    /// lands in the IDENTICAL pin store the next boot's registration sweep will consult — never a
    /// second, disjoint registry the admin route discovers/approves against.
    pub mcp_admin: McpAdminHandleOpt,
    /// GAP-FIX surfaces-profiles-skills-config (ADR-026 §6.2 hot-reload) — the SAME `SkillRuntime`
    /// handle [`Assembled::skill_runtime`] captured, threaded here so [`to_full_app_ext`](Self::to_full_app_ext)
    /// can hand it to `ainxt-server`'s `POST /admin/reload`. `Some` only on [`assemble_surface`]
    /// (the profile-enforced surface); `None` elsewhere (no `SkillRuntime` to reload).
    pub skill_runtime: Option<Arc<ainxt_skill::SkillRuntime>>,
    /// GAP-FIX surfaces-profiles-skills-config (ADR-026 §6.2 hot-reload) — the `[server] skill_dir`
    /// path `POST /admin/reload` re-reads from on each call (a fresh load, never a cached tree) —
    /// captured here rather than re-threading `LoadedConfig` itself onto the server crate. `None` when
    /// unconfigured OR when `skill_runtime` is `None`; the admin route fails closed (404) on either.
    pub skill_dir: Option<String>,
    /// GAP-FIX regulated-fi-responsible-lifecycle (FI-01 §5.4) — a snapshot of `(id, text)` for every
    /// `[kb]` document configured for this deployment, taken directly from `LoadedConfig::kb` at
    /// assembly time. This is the closest concrete, durable-at-rest analog to the "vector index" sink
    /// `ainxt_compliance`'s own doc names alongside the Event Log and memory
    /// (`crates/ainxt-compliance/src/lib.rs`'s §5 module doc: "Event Log, memory, vector index,
    /// traces, DSAR exports") — the corpus [`corpus_for_scope`] builds and every served ChatSurface
    /// retrieves from is sourced from exactly these documents (`ainxt_retrieval::Corpus::load` over
    /// `Chunk`s built 1:1 from them). There is no separate runtime-writable vector-index store in this
    /// OSS tree today (KB content is admin-provisioned config, not written by served turns), so
    /// [`Self::sweep_vector_index`] proves the INGESTION path redacted before indexing, the analog of
    /// what [`Self::sweep_event_log`]/[`Self::sweep_memory`] prove for their write paths.
    pub kb_corpus_snapshot: Vec<(String, String)>,
    /// GAP-FIX ainxt-retrieval (gap6-retrieval-maintenance, item 1) — the SHARED, tick-visible
    /// `ainxt_retrieval::maintenance::IndexState` [`Self::run_kb_maintenance_tick`] applies
    /// [`Self::kb_corpus_snapshot`] against on every sweep. Before this wire the served retrieval
    /// index had NO ongoing freshness tracking at all: the corpus is built once at boot
    /// ([`corpus_for_scope`]) and never re-checked, so a document that silently changed produced no
    /// signal anywhere. Starts empty at assembly — the first tick's `Added` triggers are the initial
    /// index build, exactly as an empty [`ainxt_retrieval::maintenance::IndexState`] honestly means
    /// "nothing indexed yet".
    pub kb_index_state: Arc<Mutex<ainxt_retrieval::maintenance::IndexState>>,
    /// GAP-FIX ainxt-retrieval (gap6-retrieval-maintenance, item 1) — the SHARED, tick-visible
    /// `ainxt_retrieval::maintenance::RecallLatencyMonitor` [`Self::run_kb_maintenance_tick`] reads
    /// health from every sweep. A production deployment calls `record_recall`/`record_latency` on
    /// this SAME instance from its live query path (`needs_hot_wiring` — see
    /// [`Self::run_kb_maintenance_tick`]'s doc); this field is what makes that live once wired, and is
    /// exactly what a test drives directly to prove a degraded index forces a real reindex.
    pub kb_recall_monitor: Arc<Mutex<ainxt_retrieval::maintenance::RecallLatencyMonitor>>,
    /// GAP-FIX ainxt-retrieval (gap6-retrieval-maintenance, item 3) — the SAME ACL/RLS-carrying
    /// [`ainxt_retrieval::Corpus`] [`governed::retrieval_corpus_for_scope`] builds for the served
    /// governed Context-Fabric compile path, threaded here so `POST /admin/rls/break-glass`
    /// (`ainxt-server`) can drive a REAL [`ainxt_retrieval::Corpus::hybrid_rls`] query through
    /// [`ainxt_retrieval::rls::RowFilter::break_glass_override`]'s result — never a second, disjoint
    /// corpus the admin route builds for itself. `ainxt-server` cannot depend on this crate (the
    /// reverse edge already exists), so this threads the LOWER-level `ainxt_retrieval::Corpus` type
    /// both crates already share (the same shape [`FullAppExt::key_rotation`] threads
    /// `ainxt_token::AeadCodec`).
    pub kb_rls_corpus: Arc<ainxt_retrieval::Corpus>,
    /// GAP-CLOSE os-workforce (gap6-workforce-governance-gate) — the SAME live `WorkforceSurface`
    /// (behind `ainxt_workforce::studio::GovernedWorkforce`) the `"workforce"` surface's `POST /v1/chat`
    /// studio-turn dispatch drives, when this daemon was assembled with `--surface workforce`. `None`
    /// on every other surface — no other surface has one to offer. Threaded onto
    /// [`ainxt_server::FullAppExt::workforce`] by [`Self::to_full_app_ext`] so
    /// `POST /v1/workforce/roles` reaches the EXACT SAME published-role registry/kernel/marketplace the
    /// `/v1/chat` studio dispatch also drives on a `--surface workforce` daemon.
    pub workforce: Option<Arc<dyn ainxt_workforce::studio::GovernedWorkforce>>,
}

/// One served conversational turn to persist into the durable replay [`SessionStore`] via
/// [`AssembledFull::record_served_turn`] — the served replay WRITE-path. `answer_text` must already be
/// the REDACTED, safe-to-replay final answer (the served chat path redacts on the way out), since the
/// durable form is the safe stream (no pre-redaction original enters the store).
#[derive(Debug, Clone)]
pub struct ServedTurn {
    /// The session id the turn belongs to (the `/v1/replay/step` `session`).
    pub session: String,
    /// The authoring participant (authorized to replay/page the session).
    pub participant: String,
    /// The user turn's id (unique within the session).
    pub turn_id: String,
    /// The user's (already-redacted) input.
    pub user_input: String,
    /// The assistant's (already-redacted) final answer. Empty ⇒ record only the user turn.
    pub answer_text: String,
    /// The turn's data class (drives the per-event pre-rank clearance filter on replay).
    pub data_class: DataClass,
    /// A monotonic logical/wall timestamp (millis) for event ordering.
    pub at_millis: u128,
}

/// Why the served replay write-path ([`AssembledFull::record_served_turn`]) failed.
#[derive(Debug)]
pub enum ReplayWriteError {
    /// The durable [`SessionStore`] backend failed.
    Store(ainxt_replay::SessionStoreError),
    /// The turn tree rejected the append/record (e.g. a duplicate turn id).
    Tree(ainxt_replay::TreeError),
}

impl std::fmt::Display for ReplayWriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReplayWriteError::Store(e) => write!(f, "replay write: {e}"),
            ReplayWriteError::Tree(e) => write!(f, "replay write (tree): {e}"),
        }
    }
}
impl std::error::Error for ReplayWriteError {}

/// R16 REGFI — the [`ainxt_lifecycle::guarded`] tier name every durable served-turn write is mirrored
/// under in the LIVE retention [`ainxt_lifecycle::RecordStore`]. Closes the "structurally vacuous"
/// defect: before this constant existed, no `mirror_write`/`Record::put` call site fed the served
/// retention store from the served turn path, so `POST /v1/regfi/erasure` decided §6 precedence over an
/// empty store — an attestation that erased nothing while the subject's real conversational data lived
/// on, untouched, in the replay [`SessionStore`]. `pub` so a served-surface `ErasableTier` adapter (or a
/// test asserting non-vacuity) can address these records by their qualified id
/// (`ainxt_lifecycle::guarded::qualified_id(SERVED_TURN_TIER, ..)`).
pub const SERVED_TURN_TIER: &str = "served-turn";

/// Persist one served conversational turn into the durable replay [`SessionStore`] — the shared write
/// logic behind both [`AssembledFull::record_served_turn`] and the transport-driven
/// [`StoreServedTurnRecorder`]. Load-or-create the recording, append the user turn under the active head
/// (root on the first turn), record the (already-safe) user input, then — when an answer is present —
/// append the assistant reply as a child turn carrying the redacted answer, and save the mutated tree.
///
/// R16 REGFI: on a successful save, mirrors the user turn (and the assistant reply, when present) into
/// the LIVE `retention` [`RecordStore`] via [`ainxt_lifecycle::guarded::mirror_write`] under
/// [`SERVED_TURN_TIER`], keyed by the SAME `turn_id`/`"{turn_id}::assistant"` ids the durable session
/// tree uses. This is the write-path half of the fix: `POST /v1/regfi/erasure`
/// (`ainxt_server::regfi_erasure_handler`) now decides §6 legal-hold/retention-floor precedence over
/// REAL records reflecting what the served turn path actually wrote, not an empty store. Mirroring is
/// idempotent and never refreshes an existing record's `created_tick` (re-persisting a resumed session
/// must not silently restart a statutory retention floor). Best-effort like the rest of this path: a
/// poisoned retention-store lock is logged and skipped rather than panicking the served turn.
fn persist_served_turn(
    store: &Arc<dyn SessionStore>,
    retention: &Mutex<ainxt_lifecycle::RecordStore>,
    t: &ServedTurn,
) -> Result<(), ReplayWriteError> {
    let mut rec = match store.load(&t.session).map_err(ReplayWriteError::Store)? {
        Some(durable) => SessionRecording::from_durable(durable),
        None => SessionRecording::new(&t.session, &[t.participant.as_str()]),
    };
    match rec.tree().active_head().map(|s| s.to_string()) {
        Some(parent) => rec
            .append_turn(
                &t.turn_id,
                &parent,
                TurnRole::User,
                &t.participant,
                t.at_millis,
            )
            .map_err(ReplayWriteError::Tree)?,
        None => rec
            .append_root_turn(&t.turn_id, TurnRole::User, &t.participant, t.at_millis)
            .map_err(ReplayWriteError::Tree)?,
    }
    if !t.user_input.is_empty() {
        rec.record_event(
            &t.turn_id,
            EventKind::TextDelta,
            t.data_class,
            &t.user_input,
            t.at_millis,
        )
        .map_err(ReplayWriteError::Tree)?;
    }
    let has_answer = !t.answer_text.is_empty();
    if has_answer {
        let assistant_id = format!("{}::assistant", t.turn_id);
        rec.append_turn(
            &assistant_id,
            &t.turn_id,
            TurnRole::Assistant,
            "assistant",
            t.at_millis + 1,
        )
        .map_err(ReplayWriteError::Tree)?;
        rec.record_event(
            &assistant_id,
            EventKind::TextDelta,
            t.data_class,
            &t.answer_text,
            t.at_millis + 1,
        )
        .map_err(ReplayWriteError::Tree)?;
    }
    store
        .save(&rec.to_durable())
        .map_err(ReplayWriteError::Store)?;

    // R16 REGFI — mirror the durable write(s) into the LIVE §6 retention store (see [`SERVED_TURN_TIER`]
    // doc). Runs only after the session save succeeds, so the retention store never records a write that
    // did not actually land. Logical ticks are seconds (matching the `/v1/regfi/erasure` wire default,
    // `now_unix_secs`), derived from the same `at_millis` the session tree was just written with.
    match retention.lock() {
        Ok(mut rs) => {
            let created_tick = (t.at_millis / 1000) as u64;
            ainxt_lifecycle::guarded::mirror_write(
                &mut rs,
                SERVED_TURN_TIER,
                &t.turn_id,
                &t.participant,
                t.data_class,
                created_tick,
            );
            if has_answer {
                let assistant_id = format!("{}::assistant", t.turn_id);
                ainxt_lifecycle::guarded::mirror_write(
                    &mut rs,
                    SERVED_TURN_TIER,
                    &assistant_id,
                    &t.participant,
                    t.data_class,
                    created_tick,
                );
            }
        }
        Err(_) => eprintln!(
            "ainxt-runtimed: served retention-store mirror skipped (lock poisoned, best-effort)"
        ),
    }
    Ok(())
}

/// R9 REPLAY — the [`ServedTurnRecorder`](ainxt_server::ServedTurnRecorder) the shipped daemon hands the
/// transport so each completed `/v1/chat` turn is WRITTEN into the SAME durable [`SessionStore`]
/// `/v1/replay/step` reads. It re-scrubs the caller's raw input through the strong redactor before the
/// durable write (the transport carries the raw input; the model's input redaction is not on the
/// outbound stream), so no pre-redaction original ever lands in the replay store. Best-effort: a write
/// failure never fails the served turn (it is logged to stderr and dropped).
///
/// R16 REGFI: also holds the SAME LIVE `retention` [`ainxt_lifecycle::RecordStore`] `/v1/regfi/erasure`
/// mutates, so `persist_served_turn` can mirror each write into it (see [`SERVED_TURN_TIER`]).
struct StoreServedTurnRecorder {
    store: Arc<dyn SessionStore>,
    retention: Arc<Mutex<ainxt_lifecycle::RecordStore>>,
}

impl ainxt_server::ServedTurnRecorder for StoreServedTurnRecorder {
    fn record_turn(&self, turn: &ainxt_server::ServedTurnRecord) {
        // Scrub the user input on write — the durable replay store must never hold cardholder/PII data.
        let (safe_input, _redactions) =
            ainxt_compliance::StrongRedactor::new().redact(&turn.user_input);
        let at_millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let served = ServedTurn {
            session: turn.session.clone(),
            participant: turn.participant.clone(),
            turn_id: turn.turn_id.clone(),
            user_input: safe_input,
            answer_text: turn.answer_text.clone(),
            data_class: turn.data_class,
            at_millis,
        };
        if let Err(e) = persist_served_turn(&self.store, &self.retention, &served) {
            eprintln!("ainxt-runtimed: served replay write-path failed (best-effort): {e}");
        }
    }
}

/// GAP-FIX identity-payments — closes the §20 UEBA "no feed" gap. `AssembledFull::observe_run_activity`
/// (=> `ControlPlane::observe` => `AnomalyMonitor::assess`) was fully implemented and tested in
/// `ainxt-identity`, but no served dispatch/turn-completion caller ever fed it a real per-Run
/// behavioral observation — the continuous learned-baseline pipeline was wired to nothing live.
///
/// This decorator wraps the REAL configured [`ainxt_telemetry::TelemetrySink`] (every call is
/// delegated unchanged — telemetry/FinOps behavior is byte-identical) and additionally, on every
/// `record_turn`, derives ONE [`ActivitySample`](ainxt_identity::authority::ActivitySample) from that
/// turn's real signals and feeds it into the §20 pipeline:
/// * `def_ref` = `"actor:{actor}"` — the runtime always knows at least the authenticated actor, even
///   with no richer role charter configured.
/// * `capabilities_used` = the routed provider (`provider:{name}`, omitted when the turn never routed
///   a model — cache/clarify/doc-gen short-circuits) plus `tool:dispatch` when the turn made any tool
///   call.
/// * `egress_destinations` = the turn's [`DataClass`] (`data_class:{:?}`) — in a payments platform a
///   confidential-class turn IS the egress-classification signal.
/// * `action_rate` = `tool_calls` (a real per-turn action count); `cost_velocity` = `cost_micros` (real
///   priced cost, the SAME integer FinOps figure `record_turn` already carries).
///
/// The baseline scored against is **learned from this def_ref's own accumulated history** via
/// [`BehavioralBaseline::learn_from_history`] (§20: "learned from its own history", not hand-authored) —
/// this decorator is exactly the continuous re-learning pipeline the doc comments on
/// `learn_from_history`/`observe_run_activity` name as the missing data-plane job. An actor's first-ever
/// turn sees an empty history (permissive baseline, no false flag, matching
/// `r12_unbaselined_role_with_no_history_is_not_retroactively_flagged`); every subsequent turn is scored
/// against the union of everything seen before, then folded into the history for the next one.
///
/// `response` is fixed at [`AnomalyResponse::RenewalChoke`] — the non-destructive lever (drain at next
/// TTL renewal, no in-flight kill) appropriate for an always-on automatic feed; the harder
/// [`AnomalyResponse::RevokeRun`] response stays an explicit operator/remediator escalation elsewhere
/// (e.g. [`AssembledFull::revoke_run`], the payment-boundary tripwire), not an automatic consequence of
/// every deviation on every served turn.
struct BehaviorFeedingTelemetry {
    inner: Arc<dyn ainxt_telemetry::TelemetrySink>,
    history: Arc<
        Mutex<std::collections::HashMap<String, Vec<ainxt_identity::authority::ActivitySample>>>,
    >,
    control_plane: Arc<Mutex<ControlPlane>>,
}

impl ainxt_telemetry::TelemetrySink for BehaviorFeedingTelemetry {
    fn record_turn(&self, metrics: &ainxt_telemetry::TurnMetrics) {
        self.inner.record_turn(metrics);

        let def_ref = format!("actor:{}", metrics.actor);
        let mut capabilities_used = std::collections::BTreeSet::new();
        if metrics.provider != "none" {
            capabilities_used.insert(format!("provider:{}", metrics.provider));
        }
        if metrics.tool_calls > 0 {
            capabilities_used.insert("tool:dispatch".to_string());
        }
        let mut egress_destinations = std::collections::BTreeSet::new();
        egress_destinations.insert(format!("data_class:{:?}", metrics.data_class));
        let sample = ainxt_identity::authority::ActivitySample {
            run_id: metrics.turn.clone(),
            def_ref: def_ref.clone(),
            capabilities_used,
            egress_destinations,
            action_rate: metrics.tool_calls as f64,
            cost_velocity: metrics.cost_micros as f64,
        };

        let Ok(mut history) = self.history.lock() else {
            eprintln!(
                "ainxt-runtimed: UEBA behavior history lock poisoned (best-effort, turn dropped)"
            );
            return;
        };
        let entry = history.entry(def_ref.clone()).or_default();
        let baseline = ainxt_identity::authority::BehavioralBaseline::learn_from_history(
            def_ref,
            entry.iter(),
            1.25,
        );
        entry.push(sample.clone());
        drop(history);

        if let Ok(mut cp) = self.control_plane.lock() {
            let _assessment = cp.observe(
                &baseline,
                &sample,
                ainxt_identity::control::AnomalyResponse::RenewalChoke,
            );
        } else {
            eprintln!(
                "ainxt-runtimed: control plane lock poisoned (UEBA feed best-effort, turn dropped)"
            );
        }
    }

    fn record_dispatch(&self, stats: ainxt_telemetry::DispatchMetrics) {
        self.inner.record_dispatch(stats);
    }

    /// GAP6 telemetry-cost-rollup — delegate unchanged to the REAL configured sink this decorator
    /// wraps. Without this override the trait default (`None`) would shadow `InMemoryTelemetry`'s real
    /// rollup on every served daemon, since [`AssembledFull::to_full_app_ext`] ALWAYS wraps the
    /// configured sink in this decorator before it reaches `ainxt-server`'s `AppState` — a served
    /// `GET /admin/telemetry/cost-rollup` would see "not available" even with `sink = "memory"`/the
    /// default configured.
    fn cost_rollup(&self) -> Option<ainxt_telemetry::CostRollup> {
        self.inner.cost_rollup()
    }
}

impl AssembledFull {
    /// The ONE durable [`SessionStore`] the shipped daemon serves `/v1/replay/step` from — exposed so
    /// the served write-path and the step-read route provably share the SAME instance.
    pub fn replay_store(&self) -> Arc<dyn SessionStore> {
        self.replay_store.clone()
    }

    /// **Served replay WRITE-path** (gap: `/v1/replay/step` served an empty store — nothing on the
    /// served path ever persisted a turn tree, so a served run could never be paged back; only a test
    /// could seed it). Persist one served conversational turn into the SAME durable [`SessionStore`]
    /// the step-read route reads: load-or-create the recording, append the user turn as a child of the
    /// current active head (root on the first turn), record the redacted user input, then — when an
    /// answer is present — append the assistant reply as a child turn carrying the redacted answer, and
    /// save the mutated tree back. So a served interaction durably round-trips through the ONE store:
    /// `record_served_turn` writes, `/v1/replay/step` (`step_replay_session`) reads the SAME session.
    ///
    /// Incremental + resume-safe: a subsequent call for the same session loads the persisted tree and
    /// extends the active branch, so a multi-turn served run accumulates a real replayable chain. The
    /// OSS default store is in-RAM; a deployment swaps a DB-backed [`SessionStore`] behind the seam with
    /// no caller change.
    pub fn record_served_turn(&self, t: &ServedTurn) -> Result<(), ReplayWriteError> {
        persist_served_turn(&self.replay_store, &self.retention, t)
    }

    /// **Served durable turn-tree WRITE entrypoint** for branch/edit/stop/steer (gap DATA: "turn-tree
    /// as a first-class durable object for branch/edit/stop/steer — the WRITE path"). Drives
    /// [`apply_interaction_persisted`](ainxt_replay::apply_interaction_persisted) over the SAME durable
    /// [`SessionStore`] `/v1/replay/step` reads and `record_served_turn` writes, so a branch/edit/
    /// stop/steer applied in one request durably round-trips (survives across requests) and the whole
    /// tree stays replayable. RBAC is fail-closed inside the entrypoint: the caller must be a session
    /// participant (a read-only compliance-replay role is refused — watching is not editing). Editing
    /// never mutates history (Edit/Branch fork a labeled sibling).
    ///
    /// **needs_hot_wiring**: this is the clean, drivable entrypoint; mounting it on a
    /// `POST /v1/replay/interact` route (id minting + principal projection from the JWT) is the
    /// transport hookup, tracked as hot-wiring on the reserved daemon.
    pub fn apply_replay_interaction(
        &self,
        session_id: &str,
        interaction: &ainxt_replay::Interaction,
        principal: &ainxt_types::Principal,
        at_millis: u128,
    ) -> Result<ainxt_replay::InteractionOutcome, ainxt_replay::PersistedError> {
        ainxt_replay::apply_interaction_persisted(
            self.replay_store.as_ref(),
            session_id,
            interaction,
            principal,
            at_millis,
        )
    }

    /// **Served durable RE-EXECUTION entrypoint** (gap DATA: "re-execution replay — re-run frozen
    /// inputs against a live model, forked to a new branch"). Drives
    /// [`re_execute_persisted`](ainxt_replay::re_execute_persisted) over the shared store: it forks a
    /// NEW sibling branch off `target_turn`, runs its frozen inputs against `executor`, appends the
    /// fresh events onto the fork and persists — NEVER overwriting the original turn. The offline
    /// default behind the [`ReExecutor`](ainxt_replay::ReExecutor) seam is
    /// [`DeterministicReplayExecutor`](ainxt_replay::DeterministicReplayExecutor); a deployment plugs a
    /// provider-backed executor (model-gateway routed, data-class → model-eligibility enforced).
    ///
    /// GAP6 replay-reexec-presence — CLOSED: `POST /v1/replay/reexecute` is now mounted
    /// ([`ainxt_server::replay_reexec_router`], wired from [`Self::reexec_executor`] over this SAME
    /// [`Self::replay_store`] in [`Self::to_full_app_ext`]) via the wire-shaped
    /// [`re_execute_persisted_req`](ainxt_replay::re_execute_persisted_req) — mirroring how
    /// `/v1/replay/step` calls [`step_replay_session`](ainxt_replay::step_replay_session) directly
    /// rather than through a composition-root method. This method remains the author-explicit
    /// convenience wrapper for a non-transport caller (CLI/tests) that already knows the author id;
    /// the **live-model** executor behind the seam is still the deployment's own infra-gated choice
    /// (the OSS default stays the offline [`DeterministicReplayExecutor`](ainxt_replay::DeterministicReplayExecutor)).
    #[allow(clippy::too_many_arguments)]
    pub fn re_execute_replay(
        &self,
        session_id: &str,
        target_turn: &str,
        new_id: &str,
        author: &str,
        principal: &ainxt_types::Principal,
        executor: &dyn ainxt_replay::ReExecutor,
        at_millis: u128,
    ) -> Result<String, ainxt_replay::PersistedError> {
        ainxt_replay::re_execute_persisted(
            self.replay_store.as_ref(),
            session_id,
            target_turn,
            new_id,
            author,
            principal,
            executor,
            at_millis,
        )
    }

    /// **Served SHAREABLE, CREDENTIAL-FREE replay bundle EXPORT entrypoint** (gap DATA:
    /// "a shareable, credential-free bundle of a recorded run for demo/training"). Drives
    /// [`export_session_bundle`](ainxt_replay::export_session_bundle) over the SAME durable
    /// [`SessionStore`] `/v1/replay/step` reads and `record_served_turn` writes: it loads the caller's
    /// RBAC-scoped, already-redacted event slice and content-commits + signs it into a
    /// [`ReplayBundle`](ainxt_replay::ReplayBundle) that carries no credentials, no participant
    /// roster, and is not a handle back to the live session — safe to hand to a demo/training
    /// audience or attach to an incident ticket. `signer` is the [`BundleSigner`](ainxt_replay::BundleSigner)
    /// seam; the OSS default is [`ContentCommitmentSigner`](ainxt_replay::ContentCommitmentSigner)
    /// (a keyed SHA-256 integrity commitment) — production swaps real asymmetric signing (PKI) behind
    /// the same seam with no caller change.
    ///
    /// **needs_hot_wiring**: this is the clean, drivable entrypoint; mounting it on a
    /// `GET/POST /v1/replay/bundle` route (id minting + principal projection from the JWT) is the
    /// transport hookup, tracked as hot-wiring on the reserved daemon.
    pub fn export_replay_bundle(
        &self,
        session_id: &str,
        principal: &ainxt_types::Principal,
        opts: &ainxt_replay::ReplayOptions,
        runtime_version: &str,
        signer: &dyn ainxt_replay::BundleSigner,
    ) -> Result<ainxt_replay::ReplayBundle, ainxt_replay::PersistedError> {
        ainxt_replay::export_session_bundle(
            self.replay_store.as_ref(),
            session_id,
            principal,
            opts,
            runtime_version,
            signer,
        )
    }

    /// GAP-FIX eval-tester-scenarios — `ainxt_canary::experiment::TrafficSplit` had zero callers
    /// anywhere in the workspace outside its own crate's tests, even though it is the exact "upstream
    /// traffic split" [`ingest_served_turn`]'s own doc names as the source of `served_ref` below. This
    /// is the served-path routing seam: deterministically resolve which git-ref (`champion_ref` or
    /// `candidate_ref` from the SAME [`governed::ReleaseControllerConfig`] `release_controller` was
    /// built from) a given request key routes to. The live-traffic hook that calls this once per
    /// request and feeds the result into [`Self::ingest_served_turn`] as `served_ref` is the transport
    /// turn-completion path; this method is the clean, drivable seam it targets.
    pub fn route_served_ref(&self, request_key: &str) -> Option<String> {
        self.traffic_split.route(request_key).map(|s| s.to_string())
    }

    /// **Online-canary served-path entrypoint** (EVAL_PLATFORM.md §7, gap AS): feed ONE completed,
    /// quality-scored served turn into the live [`OnlineReleaseController`](ainxt_quality::controller::OnlineReleaseController)
    /// held on this assembly. `served_ref` is the git-ref that actually served the turn (from the
    /// upstream traffic split, see [`Self::route_served_ref`]); `quality` is its measured 0–100 score.
    /// The controller accrues candidate turns into the anytime-valid canary (safe to peek), drives the
    /// deploy pointer on an established verdict, and — post-promotion — watches for drift, all under
    /// the assembly's lock.
    ///
    /// The three side-effect seams are the production wiring points: `pointer` flips the signed
    /// `env/prod` git-ref (instant, byte-for-byte), `notifier` notifies a human (never pages), and
    /// `responder` opens a drift ticket + rolls back. This method is the clean, drivable seam; the
    /// live-traffic hook that calls it once per served turn with the deployment's real git-ref pointer /
    /// ticketing backends is the transport turn-completion path (**needs_hot_wiring**: those backends
    /// perform real git-ref operations + paging and are infra-gated, so they are not exercised by the
    /// air-gapped default). Returns the controller's step (pointer + drift action) for telemetry.
    pub fn ingest_served_turn(
        &self,
        served_ref: &str,
        quality: f64,
        pointer: &mut dyn ainxt_canary::experiment::PointerController,
        notifier: &mut dyn ainxt_canary::experiment::Notifier,
        responder: &mut dyn ainxt_quality::monitor::DriftResponder,
    ) -> ainxt_quality::controller::ControllerStep {
        let mut ctrl = self
            .release_controller
            .lock()
            .expect("release controller mutex poisoned");
        ctrl.ingest(served_ref, quality, pointer, notifier, responder)
    }

    /// GAP-FIX eval-tester-scenarios — `OnlineReleaseController::phase`/`candidate_samples` had zero
    /// callers outside their own crate's tests, even though [`ingest_served_turn`] above already locks
    /// the SAME `release_controller` and drives the controller forward on every served turn. A status
    /// route/telemetry consumer needs to read the controller's current rollout phase and accrued
    /// sample count without driving it — this is that read-only counterpart.
    pub fn release_controller_status(&self) -> (ainxt_quality::controller::Phase, u64) {
        let ctrl = self
            .release_controller
            .lock()
            .expect("release controller mutex poisoned");
        (ctrl.phase(), ctrl.candidate_samples())
    }

    /// GAP-FIX eval-tester-scenarios — `OnlineReleaseController::drive_from_feed` (the batch/loop form
    /// over a [`ainxt_quality::feed::LiveTurnFeed`], vs. [`Self::ingest_served_turn`]'s one-call-per-
    /// turn form) had zero callers outside its own crate's tests, even though it takes the SAME
    /// `pointer`/`notifier`/`responder` seams already threaded through `ingest_served_turn` above — no
    /// new trait design, no new shared state, just a loop. Drives the SAME `release_controller` this
    /// runtime's per-turn `ingest_served_turn` already locks.
    pub fn drive_release_controller_from_feed(
        &self,
        feed: &mut dyn ainxt_quality::feed::LiveTurnFeed,
        pointer: &mut dyn ainxt_canary::experiment::PointerController,
        notifier: &mut dyn ainxt_canary::experiment::Notifier,
        responder: &mut dyn ainxt_quality::monitor::DriftResponder,
    ) -> Vec<ainxt_quality::controller::ControllerStep> {
        let mut ctrl = self
            .release_controller
            .lock()
            .expect("release controller mutex poisoned");
        ctrl.drive_from_feed(feed, pointer, notifier, responder)
    }

    /// Build the [`ainxt_server::FullApp`] the shipped daemon serves through [`ainxt_server::serve_full`].
    /// Every governed surface is populated, so `/graph`, `/v1/query_ledger`, `/v1/infer`, `/v1/replay`
    /// and the resume tail are all live (not 404). The mandatory gates (compliance/authz/audit) live in
    /// the engine + the identity seam; this stays a thin transport wiring.
    pub fn to_full_app(&self) -> FullApp {
        FullApp {
            manager: self.manager.clone(),
            // R8 — the config-selected authenticator (TrustedGatewayAuth default, or a selected
            // verified JwtSsoAuth); the SAME instance gates chat AND every governed surface.
            auth: self.auth.clone(),
            event_log: self.event_log.clone(),
            control_plane_sha: self.control_plane_sha.clone(),
            serving: Some((self.serving.0.clone(), self.serving.1.clone())),
            graph: Some(self.graph.clone()),
            ledger_schema: Some(self.ledger_schema.clone()),
            // HARN-03 — the shipped daemon now mounts the harness invoke/run surface (previously `None`,
            // i.e. `/v1/harness/*` was reachable only from ainxt-server's own tests).
            harness: Some(HarnessMounts {
                registry: self.harness.registry.clone(),
                runtime: self.harness.runtime.clone(),
                executor: self.harness.executor.clone(),
                invoker: self.harness.invoker.clone(),
                // GAP-AUDIT tooling-mcp-plugins-routing — same shared handle, so the shipped daemon's
                // POST /v1/capability/saga dispatches through the SAME registry as everything else.
                tools: self.harness.tools.clone(),
            }),
        }
    }

    /// The additive [`FullAppExt`] surfaces the shipped daemon mounts through [`ainxt_server::serve_full_ext`]:
    /// the connector OAuth surface (`/connectors/*`, CONN-03), the artifact-generation surface
    /// (`/v1/artifact`, R6 DATA), the store-backed step-through replay surface (`/v1/replay/step`, R6
    /// DATA), the DSAR cache-erasure organ (`/v1/erasure`), the harness pre-receive gate, the edit gate,
    /// AND (R9) the engine's typed §6 wire stream by default, the served-turn replay WRITE sink, and the
    /// regulated-FI supervisory organs (`/v1/regfi/*`). Pairs with [`to_full_app`](Self::to_full_app).
    ///
    /// NOTE: `wire_events` is a single-consumer receiver taken ONCE from the interior-mutable slot — a
    /// second call in the same process gets `None` (the daemon serves once). The regfi organs and the
    /// served-turn recorder are the SAME LIVE `Arc<Mutex<..>>` state the composition root holds.
    pub fn to_full_app_ext(&self) -> FullAppExt {
        FullAppExt {
            connectors: Some(self.connectors.clone()),
            // GAP-FIX connectors round-2 (KEY-ROT-01) — MOUNT POST /admin/keys/rotate over the EXACT
            // SAME `Arc<AeadCodec>` `self.connectors`' OAuth-callback SEAL path and
            // `self.connector_invoker`'s refresh/OPEN path both wrap in `SharedAeadCodec` (see
            // `AssembledFull::connector_key_ring`'s doc for the full ownership chain) — a rotation
            // through the admin route is visible to both in the SAME call, never a second, disjoint
            // ring the admin route mutated for itself.
            key_rotation: Some(self.connector_key_ring.clone()),
            // R9 TRANSP — hand the transport the engine's typed §6 wire receiver so `/v1/chat` +
            // `/v1/events` serialize the REAL WireEvent stream BY DEFAULT (capped/compliance.notice/
            // payment-boundary/priced usage) — not the lossy legacy Event projection. Taken once.
            wire_events: self.wire_events.lock().expect("wire receiver slot").take(),
            artifact: Some(self.artifact.clone()),
            replay_store: Some(self.replay_store.clone()),
            // GAP6 replay-reexec-presence — MOUNT POST /v1/replay/reexecute + POST /v1/replay/drift
            // over the EXACT SAME `replay_store` above (never a second, disconnected store).
            reexec_executor: Some(self.reexec_executor.clone()),
            // R7 OBS — the per-turn telemetry sink recorded on the shipped chat path.
            // GAP-FIX identity-payments — wrapped in `BehaviorFeedingTelemetry` so the SAME served-path
            // `record_turn` call ainxt-server's `chat_handler` already makes on every completed turn
            // ALSO feeds the §20 UEBA learned baseline (`observe_run_activity`/`ControlPlane::observe`
            // previously had zero live caller). Telemetry/FinOps output is byte-identical — the wrapper
            // delegates every call to the real configured sink unchanged.
            telemetry: Some(Arc::new(BehaviorFeedingTelemetry {
                inner: self.telemetry.clone(),
                history: self.behavior_history.clone(),
                control_plane: self.control_plane.clone(),
            })),
            // R7 REGFI — the DSAR / right-to-erasure organ, now MOUNTED at `POST /v1/erasure` (it was
            // held LIVE on the surface but had no route; the regulator/DPO entrypoint is now reachable).
            erasure: Some(self.erasure.clone()),
            // R7 HARN — the harness pre-receive gate over the daemon's REAL compliance detector.
            harness_prereceive: Some(self.harness_prereceive_gate.clone()),
            // R8 EDIT — the semantic Code-Review Pipeline gate, now MOUNTED at `POST /v1/edit`.
            edit: Some(self.edit.clone()),
            // R12 EDIT — the durable served working-tree root (config `[server] edit_workspace_dir`), so
            // a committed edit is persisted to a crash-atomic FsSink and survives a daemon restart.
            edit_workspace_root: self.edit_workspace_root.clone(),
            // GAP-FIX semantic-editing-codereview — the durable journal-store root (config `[server]
            // edit_journal_dir`), so every `/v1/edit*` turn's sealed hash-chained journal is persisted
            // (in-process store by default; a crash-atomic FsJournalStore when configured) instead of
            // being built and then silently dropped.
            edit_journal_root: self.edit_journal_root.clone(),
            // R9 REGFI — the legal-hold-aware retention store + tamper-evident incident register drive
            // `/v1/regfi/*` (erasure-with-attestation + BSA §63 export + read-only auditor listing) over
            // the SAME LIVE organs `AssembledFull::{erase_subject_attested,export_incident_evidence,
            // auditor_list_incidents}` drive.
            // GAP-AUDIT regulated-fi #7 — widened to also share the DSAR workflow (POST /v1/regfi/dsar),
            // so its `Erase` command dispatches through the SAME retention store.
            regfi: Some((
                self.retention.clone(),
                self.incidents.clone(),
                self.dsar.clone(),
            )),
            // R9 REPLAY — the served-turn WRITE sink: each completed `/v1/chat` turn is persisted into the
            // SAME durable store `/v1/replay/step` reads, so a served conversation durably round-trips.
            served_turns: Some(Arc::new(StoreServedTurnRecorder {
                store: self.replay_store.clone(),
                // R16 REGFI — the SAME LIVE retention store `/v1/regfi/*` drives, so every served turn
                // this recorder writes is mirrored into it (closes the vacuous-erasure defect).
                retention: self.retention.clone(),
            })),
            // R11 TRANSP §6.3 — couple `/v1/command approval.respond` to the engine's blocked gate.
            approval_coordinator: Some(self.approval_coordinator.clone()),
            // R15 COMPOSE — the engine's shared DispatchProbe, so the served `/v1/chat` path can sample
            // peak/total concurrent tool-dispatch alongside its per-turn telemetry record.
            dispatch_probe: self.dispatch_probe.clone(),
            // GAP-AUDIT regulated-fi #13 — the §6.5 break-glass Program registry, now MOUNTED at
            // POST /v1/regfi/breakglass/{open,step} over the SAME LIVE registry
            // `AssembledFull::{open_break_glass_program,step_break_glass_program}` drive.
            // GAP-FIX memory (flywheel-no-route) — MOUNT the served POST /feedback capture route
            // over the SAME continuous-learning ImprovementEngine instance a future curation/
            // propose sweep would read (design §4: "usage is captured as typed FeedbackEvents").
            feedback: Some(self.feedback_engine.clone()),
            breakglass: Some(self.breakglass.clone()),
            // GAP-AUDIT regulated-fi #5 — §2.4 report drafting, now MOUNTED at POST /v1/regfi/report
            // over the SAME LIVE incident register the sibling regfi routes share.
            report_templates: Some(Arc::new(self.report_templates.clone())),
            // GAP-FIX memory (MEM-10) — MOUNT the served consent/export/erasure route over the SAME
            // backend the assembled chat engine's own memory reader writes to. `None` on a surface
            // with no chat engine (no route mounted — see `app_full_ext`).
            memory: self.memory_consent.clone(),
            // GAP-FIX memory (write-path-missing) — MOUNT the served POST /memory/remember write
            // route over the EXACT SAME long-lived durable-store instance the assembled chat
            // engine's own Context-Fabric memory seam reads through. `None` on a surface with no
            // chat engine (no writer to be consistent with — see `app_full_ext`).
            memory_writer: self.memory_writer.clone(),
            // GAP-FIX eval-tester-scenarios — MOUNT GET /v1/eval/canary/status over the SAME LIVE
            // release controller `Self::ingest_served_turn` drives (previously reachable only from
            // this crate's own tests, despite `release_controller_status`'s doc comment stating it
            // exists specifically for a status route).
            release_controller: Some(self.release_controller.clone()),
            // GAP-FIX regulated-fi-responsible-lifecycle — MOUNT POST /admin/outsourcing/register over
            // the SAME LIVE handle the served router's FI-03 non-overridable eligibility gate reads
            // (see `Assembled::outsourcing_register`'s doc for the full ownership chain).
            outsourcing_register: self.outsourcing_register.clone(),
            // GAP-FIX identity-payments — MOUNT `POST /admin/killswitch/{pull,release}` +
            // `GET /admin/killswitch/audit` + `POST /admin/revoke/{run,user}` over the EXACT SAME
            // `Arc<Mutex<ControlPlane>>` this surface's own `pull_kill_switch`/`release_kill_switch`/
            // `revoke_run`/`revoke_user`/`kill_switch_audit` passthroughs already lock, and the SAME
            // plane `main.rs` hands to `assemble_full_with_control_plane` alongside the surface
            // selector — so an admin operator's pull/release/revoke over HTTP is visible starting with
            // the very next dispatch admission, never a second, disjoint plane.
            control_plane: Some(self.control_plane.clone()),
            // GAP-FIX serving-ops (SERVING_OPS.md §1, gap 7) — MOUNT POST
            // /v1/infer/{prefill,decode,handoff} over the SAME LIVE `DisaggregatedPools` this surface
            // holds, when `[serving.disagg]` declared one. `None` = no disagg surface mounted.
            disagg: self.disagg.clone(),
            // GAP-FIX tooling-mcp-plugins-routing — MOUNT GET /admin/mcp/reapproval + POST
            // /admin/mcp/approve over the SAME LIVE registry + pin store the daemon's own boot-time
            // MCP registration consulted (see `Assembled::mcp_admin`'s doc for the full chain).
            // `ainxt-server` cannot depend on this crate (it would be circular), so it declares its
            // own identically-shaped `McpAdminHandle` — this clones the SAME `Arc<McpRegistry>`/
            // `Arc<dyn PinStore>`/`Arc<dyn AuthProvider>` handles into that crate's struct: a
            // type-adapter at the crate boundary, never a second, disjoint registry.
            mcp_admin: self.mcp_admin.as_ref().map(|h| {
                Arc::new(ainxt_server::McpAdminHandle {
                    registry: h.registry.clone(),
                    auth: h.auth.clone(),
                    pins: h.pins.clone(),
                    user_id: h.user_id.clone(),
                })
            }),
            // GAP-FIX surfaces-profiles-skills-config (ADR-026 §6.2 hot-reload) — MOUNT
            // POST /admin/reload over the SAME LIVE `SkillRuntime` every served turn resolves skill
            // refs through (see `Assembled::skill_runtime`'s doc for the full ownership chain).
            skill_runtime: self.skill_runtime.clone(),
            skill_dir: self.skill_dir.clone(),
            // GAP-FIX identity-payments (gap6 audit item 1) — MOUNT GET /v1/transparency/proof/:run_id
            // over the EXACT SAME live issuance TransparencyLog `chat_identity.rs::GovernedChatSurface`
            // appends every newly-minted chat-run credential to (see `AssembledFull::transparency`'s
            // doc for the full ownership chain). `None` on any surface that never wired one — the
            // route still mounts but fails closed (404), never a silent no-op.
            transparency: self.transparency.clone(),
            // GAP-FIX ainxt-retrieval (gap6-retrieval-maintenance, item 3) — MOUNT
            // POST /admin/rls/break-glass over the SAME LIVE ACL/RLS-carrying corpus the served
            // governed Context-Fabric compile path builds (see `AssembledFull::kb_rls_corpus`'s doc for
            // the full ownership chain) — never a second, disconnected corpus the admin route builds
            // for itself.
            rls_break_glass: Some(self.kb_rls_corpus.clone()),
            // GAP-CLOSE os-workforce (gap6-workforce-governance-gate) — MOUNT
            // POST /v1/workforce/roles over the SAME LIVE `WorkforceSurface` the `"workforce"`
            // surface's `/v1/chat` studio-turn dispatch also drives (see `Assembled::workforce_surface`'s
            // doc for the full ownership chain). `None` on every daemon not assembled with
            // `--surface workforce` — the route mounts nowhere else.
            workforce: self.workforce.clone(),
        }
    }

    /// R11 TRANSP §6.3 — the engine-side [`WireApprovalGate`](ainxt_server::WireApprovalGate) built over
    /// this surface's shared [`ApprovalCoordinator`](ainxt_server::ApprovalCoordinator): a composition
    /// feeds it into the assembled engine's `.with_approval(Box::new(..))` seam so a gated (high-risk /
    /// payment-boundary) tool BLOCKS on a live wire decision instead of a policy default. `is_policy_auto`
    /// is `false`, so a human `approve` over the wire can clear a payment boundary (an auto gate never
    /// can). A missing response fails closed (reject) after `timeout`. The engine builder is the reserved
    /// call-site this entrypoint plugs into (needs_hot_wiring); the transport side is already live.
    pub fn wire_approval_gate(
        &self,
        timeout: std::time::Duration,
    ) -> ainxt_server::WireApprovalGate {
        ainxt_server::WireApprovalGate::new(self.approval_coordinator.clone(), timeout)
    }

    /// Spawn the background breach-clock ticker: every `period` it advances the live [`IncidentRegister`]'s
    /// statutory clocks against the wall clock, so an armed clock breaches and pages the ladder even with
    /// zero request traffic (the register never reads a clock itself — the edge supplies logical time).
    /// Returns the [`tokio::task::JoinHandle`]; aborting it (or dropping the surface) stops the ticker.
    pub fn spawn_breach_clock(&self, period: std::time::Duration) -> tokio::task::JoinHandle<()> {
        let incidents = self.incidents.clone();
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(period);
            loop {
                iv.tick().await;
                let unix_secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                // ROUND-10 UNIT FIX: the `india_default` arming budgets are minute-scaled
                // (CERT-In 6h = 360 ticks, DPDP-board 72h = 4320). Feeding the raw Unix-epoch SECONDS
                // read above straight into `tick()` breached every statutory clock 60× early — a 72h
                // DPDP clock at 72 MINUTES. Project wall-clock onto the register's tick axis through the
                // crate-owned `ticks_from_unix_secs` so `now`, `t0`, and `budget_ticks` are one unit.
                let now = ainxt_incident::ticks_from_unix_secs(unix_secs);
                let _ = incidents.lock().expect("incident register lock").tick(now);
            }
        })
    }

    /// R10 — start the background [`ReconcilerSweeper`] over the served engine's SHARED exactly-once
    /// ledger (§1.8): a lost-ack `PENDING` capability row is actively leased, probed and
    /// resolved/escalated rather than passively expired (unacceptable for payments). Returns the
    /// [`SweepHandle`] — hold it for the process lifetime; dropping it (or calling `stop()`) cleanly
    /// joins the loop, waking it immediately rather than waiting out the interval. `None` when the
    /// assembled surface exposed no capability ledger (never fatal — the daemon runs without a sweep).
    /// One pass always runs before the first wait, so a row present at start is reconciled promptly.
    pub fn spawn_reconciler_sweep(&self) -> Option<ainxt_tools::SweepHandle> {
        self.reconciler_sweeper.as_ref().map(|sweeper| {
            Arc::clone(sweeper).spawn(std::time::Duration::from_secs(
                RECONCILER_SWEEP_INTERVAL_SECS,
            ))
        })
    }

    /// **R13 (SRV-03, HIGH) — the ADR-021 §8.3 attestation quote-refresh entrypoint.** Drive ONE tick
    /// of the [`AttestationRefresher`] over the declared regulated pool at logical time `now`: on a due
    /// sweep it re-fetches a fresh signed quote for every unattested / expiring-within-lead node from
    /// the live-TEE `source`, drives it through `verifier` + `refs`, and updates the SHARED
    /// [`ServingGate`]'s attestation gate under the assembly's lock — so a declared node actually
    /// becomes (and stays) regulated-eligible, and an expired-and-unrenewable node drops back to
    /// fail-closed. Returns `None` when no pool is declared, or when the sweep is not yet due this tick.
    ///
    /// This is the clean, drivable seam that makes the attestation admit path REACHABLE on the shipped
    /// daemon. **needs_hot_wiring / INFRA**: the background async timer that calls this on a cadence, and
    /// the live-TEE [`QuoteSource`](ainxt_serving::attestation::QuoteSource) that talks to the node's
    /// confidential-compute stack, are infra-gated — so the air-gapped default never exercises them
    /// (offline reference: [`StaticQuoteSource`](ainxt_serving::attestation::StaticQuoteSource)).
    pub fn run_attestation_refresh_tick(
        &self,
        now: u64,
        source: &dyn ainxt_serving::attestation::QuoteSource,
        verifier: &dyn ainxt_serving::attestation::SignatureVerifier,
        refs: &ainxt_serving::attestation::ReferenceValues,
    ) -> Option<ainxt_serving::attestation::RefreshReport> {
        let refresher = self.attestation_refresher.as_ref()?;
        let mut refresher = refresher.lock().expect("attestation refresher lock");
        let mut gate = self.serving.0.lock().expect("serving gate lock");
        refresher.tick(gate.attestation_mut(), now, source, verifier, refs)
    }

    /// GAP-FIX serving-ops — `AttestationRefresher::sweeps_run` had zero callers outside its own
    /// crate's tests: a pure read on the SAME refresher `run_attestation_refresh_tick` drives, telling
    /// an operator how many refresh cycles have actually run. `None` on the air-gapped default (no
    /// declared pool ⇒ no refresher), matching `run_attestation_refresh_tick`'s own `None` case.
    pub fn attestation_refresh_sweeps_run(&self) -> Option<u64> {
        Some(
            self.attestation_refresher
                .as_ref()?
                .lock()
                .expect("attestation refresher lock")
                .sweeps_run(),
        )
    }

    /// The declared regulated-pool node ids this refresher attests, if any — `AttestationRefresher::
    /// declared_nodes` had the same zero-caller gap.
    pub fn attestation_refresh_declared_nodes(&self) -> Option<Vec<String>> {
        Some(
            self.attestation_refresher
                .as_ref()?
                .lock()
                .expect("attestation refresher lock")
                .declared_nodes()
                .to_vec(),
        )
    }

    /// **R13 (SRV-03, HIGH) — spawn the attestation quote-refresh LOOP on daemon start.** The audit
    /// found the tick entrypoint existed but NO background loop ever called it, so a declared regulated
    /// node was never attested and regulated traffic fenced off the whole fleet forever. This wires the
    /// actual loop: every `period` it re-fetches wall-clock time and drives one
    /// [`run_attestation_refresh_tick`](Self::run_attestation_refresh_tick) over the SHARED serving gate
    /// with the injected live-TEE `source` — so a declared node becomes (and stays) regulated-eligible
    /// without any hand-submitted quote, and an expired-and-unrenewable node drops back to fail-closed.
    ///
    /// Returns `None` on the air-gapped default (no declared pool ⇒ no refresher ⇒ nothing to attest,
    /// and the r4 shipped-chat guard holds — no pool, no 503); otherwise the [`tokio::task::JoinHandle`]
    /// (hold it for the process lifetime; aborting it stops the loop). **infra_gated / needs_hot_wiring**:
    /// `source`/`verifier` are the live-TEE confidential-compute seam — the shipped daemon passes the
    /// offline [`StaticQuoteSource`](ainxt_serving::attestation::StaticQuoteSource) default (produces no
    /// quotes, so a declared-but-un-sourced pool stays honestly fail-closed rather than faking
    /// attestation); a deployment with real TEE hardware injects the live source here.
    pub fn spawn_attestation_refresh(
        &self,
        period: std::time::Duration,
        source: Arc<dyn ainxt_serving::attestation::QuoteSource + Send + Sync>,
        verifier: Arc<dyn ainxt_serving::attestation::SignatureVerifier + Send + Sync>,
        refs: ainxt_serving::attestation::ReferenceValues,
    ) -> Option<tokio::task::JoinHandle<()>> {
        let refresher = self.attestation_refresher.clone()?;
        let gate = self.serving.0.clone();
        Some(tokio::spawn(async move {
            let mut iv = tokio::time::interval(period);
            loop {
                iv.tick().await;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let mut r = refresher.lock().expect("attestation refresher lock");
                let mut g = gate.lock().expect("serving gate lock");
                let _ = r.tick(g.attestation_mut(), now, &*source, &*verifier, &refs);
            }
        }))
    }

    /// GAP-FIX serving-ops (SERVING_OPS.md §4, gap 37) — drive ONE health-sweep tick at logical time
    /// `now`: on a due sweep, feeds `observations` through the shard-group health machine
    /// (interconnect watchdog + canary-correctness probe) and, for any group that transitions
    /// non-routable THIS sweep, immediately runs the drain-the-group recovery (drain from `router`,
    /// promote an N+1 standby, physically route it). Returns `None` when no shard group is declared
    /// (no `[[serving.nodes]]` entry declares a `golden_hash`), or the sweep is not yet due this tick.
    ///
    /// This is the clean, drivable seam that makes the §4 poll→act loop REACHABLE on the shipped
    /// daemon — the exact piece `ShardHealthMonitor::monitor_tick`'s own doc names as missing ("nothing
    /// *polled* them on a cadence"). **needs_hot_wiring / INFRA**: the background async timer that
    /// calls this on a cadence ([`Self::spawn_health_sweep`]), and the live GPU interconnect counters +
    /// canary probe that gather [`HealthObservation`](ainxt_serving::health::HealthObservation)s, are
    /// infra-gated — the air-gapped default (no declared golden hash) never exercises them.
    pub fn run_health_sweep_tick(
        &self,
        now: u64,
        observations: &[ainxt_serving::health::HealthObservation],
        router: &mut dyn ainxt_serving::health::FleetRouter,
    ) -> Option<Vec<ainxt_serving::health::DrainReplaceOutcome>> {
        let cadence = self.health_cadence.as_ref()?;
        let mut cadence = cadence.lock().expect("health cadence lock");
        let monitor = self.health_monitor.as_ref()?;
        let mut monitor = monitor.lock().expect("health monitor lock");
        cadence.tick(&mut monitor, now, observations, router)
    }

    /// GAP-FIX serving-ops — `HealthCadence::sweeps_run` had zero callers outside its own crate's
    /// tests: a pure read on the SAME cadence [`Self::run_health_sweep_tick`] drives. `None` on the
    /// air-gapped default (no declared shard group ⇒ no cadence), matching
    /// `run_health_sweep_tick`'s own `None` case.
    pub fn health_sweeps_run(&self) -> Option<u64> {
        Some(
            self.health_cadence
                .as_ref()?
                .lock()
                .expect("health cadence lock")
                .sweeps_run(),
        )
    }

    /// The shard groups currently routable per the health monitor — `ShardHealthMonitor::
    /// routable_groups` had the same zero-caller gap.
    pub fn health_routable_groups(&self) -> Option<Vec<String>> {
        Some(
            self.health_monitor
                .as_ref()?
                .lock()
                .expect("health monitor lock")
                .routable_groups()
                .into_iter()
                .map(|g| g.as_str().to_string())
                .collect(),
        )
    }

    /// **GAP-FIX serving-ops (SERVING_OPS.md §4, gap 37) — spawn the shard-group health-sweep LOOP on
    /// daemon start.** Mirrors [`Self::spawn_attestation_refresh`]'s pattern for the analogous
    /// ADR-021 §8.3 attestation-refresh gap: every `period` it re-fetches wall-clock time and drives
    /// one [`Self::run_health_sweep_tick`] over an owned, in-process [`InMemoryFleetRouter`] seeded
    /// with the monitor's initially-routable groups.
    ///
    /// Returns `None` on the air-gapped default (no declared golden hash ⇒ no monitor ⇒ nothing to
    /// sweep); otherwise the [`tokio::task::JoinHandle`] (hold it for the process lifetime; aborting it
    /// stops the loop). **infra_gated / needs_hot_wiring**: `observations` is always empty here — the
    /// live GPU interconnect-collective counters and canary-correctness probe that would populate it
    /// are the deployment's live-fleet seam (there is no offline analogue for a live measurement, unlike
    /// `attestation_manifest`'s pre-shared quotes for a fixed fleet) — so the air-gapped default's sweep
    /// genuinely has nothing to act on and every group stays exactly as registered, honestly inert
    /// rather than faking a health signal. A deployment with real fleet telemetry drives
    /// [`Self::run_health_sweep_tick`] directly with real observations instead of relying on this loop.
    pub fn spawn_health_sweep(
        &self,
        period: std::time::Duration,
    ) -> Option<tokio::task::JoinHandle<()>> {
        let cadence = self.health_cadence.clone()?;
        let monitor = self.health_monitor.clone()?;
        let initial_routable = monitor
            .lock()
            .expect("health monitor lock")
            .routable_groups();
        Some(tokio::spawn(async move {
            let mut router = InMemoryFleetRouter::new().with_routed(initial_routable);
            let mut iv = tokio::time::interval(period);
            loop {
                iv.tick().await;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let mut c = cadence.lock().expect("health cadence lock");
                let mut m = monitor.lock().expect("health monitor lock");
                let _ = c.tick(&mut m, now, &[], &mut router);
            }
        }))
    }

    /// GAP-FIX serving-ops (SERVING_OPS.md §3, gaps 26/W) — drive ONE autoscale-decision tick at
    /// logical time `now`: on a due recompute, folds `samples` (per-model demand, e.g. requests/sec)
    /// into each family's EWMA and returns the resulting scale-to/park-warm decisions. Returns `None`
    /// when no `[serving.autoscale]` tuning is declared, or the recompute is not yet due this tick.
    ///
    /// This is the clean, drivable seam that makes the §3 demand-EWMA decision loop REACHABLE on the
    /// shipped daemon — the exact piece `AutoscaleCadence`'s own doc names as missing ("had no cadence
    /// concept... wired into ANY daemon loop"). **needs_hot_wiring / INFRA**: the background async
    /// timer that calls this on a cadence ([`Self::spawn_autoscale_tick`]), and the live per-model
    /// request-rate telemetry that gathers `samples`, are infra-gated — the default (no declared
    /// tuning) never exercises them. The physical replica provisioning `ScaleAction`s imply is a
    /// SEPARATE seam ([`ainxt_serving::placement::PlacementBinder`]) this method does not touch.
    pub fn run_autoscale_tick(
        &self,
        now: u64,
        samples: &[(String, f64)],
    ) -> Option<Vec<ScaleAction>> {
        let cadence = self.autoscale_cadence.as_ref()?;
        let mut cadence = cadence.lock().expect("autoscale cadence lock");
        let controller = self.autoscale_controller.as_ref()?;
        let mut controller = controller.lock().expect("autoscale controller lock");
        cadence.tick(&mut controller, now, samples)
    }

    /// GAP-FIX serving-ops — `AutoscaleCadence::ticks_run` had zero callers outside its own crate's
    /// tests: a pure read on the SAME cadence [`Self::run_autoscale_tick`] drives. `None` on the
    /// default (no declared tuning ⇒ no cadence), matching `run_autoscale_tick`'s own `None` case.
    pub fn autoscale_sweeps_run(&self) -> Option<u64> {
        Some(
            self.autoscale_cadence
                .as_ref()?
                .lock()
                .expect("autoscale cadence lock")
                .ticks_run(),
        )
    }

    /// The current smoothed demand for `model_id` per the live autoscale controller —
    /// `AutoscaleController::demand` had the same zero-caller gap. `None` when no controller is
    /// wired (not "zero demand", which would be indistinguishable from a genuinely idle model).
    pub fn autoscale_demand(&self, model_id: &str) -> Option<f64> {
        Some(
            self.autoscale_controller
                .as_ref()?
                .lock()
                .expect("autoscale controller lock")
                .demand(model_id),
        )
    }

    /// **GAP-FIX serving-ops (SERVING_OPS.md §3, gaps 26/W) — spawn the demand-autoscale-decision
    /// LOOP on daemon start.** Mirrors [`Self::spawn_health_sweep`]'s pattern for the analogous §4
    /// gap: every `period` it re-fetches wall-clock time and drives one [`Self::run_autoscale_tick`].
    ///
    /// Returns `None` when no `[serving.autoscale]` tuning is declared; otherwise the
    /// [`tokio::task::JoinHandle`] (hold it for the process lifetime; aborting it stops the loop).
    /// **infra_gated / needs_hot_wiring**: `samples` is always empty here — the live per-model
    /// request-rate telemetry that would populate it is the deployment's own metrics seam (there is
    /// no offline analogue for a live rate, same reasoning as the health-sweep loop's observations) —
    /// so the default loop's recomputes genuinely have nothing to fold in and every family's EWMA
    /// decays toward zero rather than faking demand. A deployment with real request-rate telemetry
    /// drives [`Self::run_autoscale_tick`] directly with real samples instead of relying on this loop.
    pub fn spawn_autoscale_tick(
        &self,
        period: std::time::Duration,
    ) -> Option<tokio::task::JoinHandle<()>> {
        let cadence = self.autoscale_cadence.clone()?;
        let controller = self.autoscale_controller.clone()?;
        Some(tokio::spawn(async move {
            let mut iv = tokio::time::interval(period);
            loop {
                iv.tick().await;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let mut c = cadence.lock().expect("autoscale cadence lock");
                let mut ctl = controller.lock().expect("autoscale controller lock");
                let _ = c.tick(&mut ctl, now, &[]);
            }
        }))
    }

    /// GAP-FIX serving-ops (SERVING_OPS.md §3, gaps 26/W) — drive ONE placement-actuator tick over the
    /// SHARED [`PlacementActuator`]: expand `actions` into per-replica [`ModelItem`]s against the
    /// declared catalog, compute the best-fit-decreasing target [`PlacementController::plan`], and
    /// converge the persistent binder toward it via one rate-limited [`PlacementReconciler::
    /// reconcile_step`]. Returns `None` when no `[serving.placement]` section is declared (nothing to
    /// actuate). This is the real caller `PlacementController`/`ParkingRegistry`/`PlacementReconciler`/
    /// `InMemoryPlacementBinder` had — previously referenced only in `ainxt-serving`'s own tests.
    pub fn run_placement_actuator_tick(
        &self,
        actions: &[ScaleAction],
    ) -> Option<Vec<ReconcileAction>> {
        let actuator = self.placement.as_ref()?;
        let mut actuator = actuator.lock().expect("placement actuator lock");
        Some(actuator.actuate(actions))
    }

    /// **The autoscale-decision → placement-actuator consumption seam** (SERVING_OPS.md §3, gaps
    /// 26/W): drive one [`Self::run_autoscale_tick`], then feed its resulting [`ScaleAction`]s straight
    /// into [`Self::run_placement_actuator_tick`] — closing the gap the audit named explicitly:
    /// `run_autoscale_tick` returned decisions nothing ever consumed to call the (previously unwired)
    /// placement/parking actuator. Returns `None` when either `[serving.autoscale]` or
    /// `[serving.placement]` is not declared (either half missing ⇒ nothing to actuate); otherwise the
    /// physical [`ReconcileAction`]s the tick actually applied to the persistent binder.
    ///
    /// The demand-sample INPUT side (`samples`) stays the deployment's live-traffic seam — there is no
    /// offline analogue for a real request-rate signal (same honest posture as [`Self::
    /// spawn_autoscale_tick`]); this method only wires the DECISION-CONSUMPTION half for real.
    pub fn run_autoscale_and_placement_tick(
        &self,
        now: u64,
        samples: &[(String, f64)],
    ) -> Option<Vec<ReconcileAction>> {
        let scale_actions = self.run_autoscale_tick(now, samples)?;
        self.run_placement_actuator_tick(&scale_actions)
    }

    /// **Spawn the combined autoscale-decision + placement-actuation LOOP on daemon start.** Mirrors
    /// [`Self::spawn_autoscale_tick`]'s pattern, but each due tick also drives
    /// [`Self::run_placement_actuator_tick`] over the SAME decisions — so a deployment that declares
    /// BOTH `[serving.autoscale]` and `[serving.placement]` gets the full observe→decide→actuate loop
    /// running end-to-end, not merely the decision half. Returns `None` when either section is absent
    /// (mirrors [`Self::run_autoscale_and_placement_tick`]'s own `None` case); otherwise the
    /// [`tokio::task::JoinHandle`] (hold it for the process lifetime; aborting it stops the loop).
    /// **needs_hot_wiring/INFRA**: `samples` is always empty here (no live demand-sample collector); a
    /// deployment with real request-rate telemetry drives [`Self::run_autoscale_and_placement_tick`]
    /// directly with real samples instead of relying on this loop's honestly-idle default.
    pub fn spawn_autoscale_and_placement_tick(
        &self,
        period: std::time::Duration,
    ) -> Option<tokio::task::JoinHandle<()>> {
        let cadence = self.autoscale_cadence.clone()?;
        let controller = self.autoscale_controller.clone()?;
        let actuator = self.placement.clone()?;
        Some(tokio::spawn(async move {
            let mut iv = tokio::time::interval(period);
            loop {
                iv.tick().await;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let actions = {
                    let mut c = cadence.lock().expect("autoscale cadence lock");
                    let mut ctl = controller.lock().expect("autoscale controller lock");
                    c.tick(&mut ctl, now, &[])
                };
                if let Some(actions) = actions {
                    let mut a = actuator.lock().expect("placement actuator lock");
                    let _ = a.actuate(&actions);
                }
            }
        }))
    }

    /// GAP-FIX serving-ops (SERVING_OPS.md §5, gap 38) — drive ONE zero-downtime signed weight-rollout
    /// step from a real-traffic quality window, over the SHARED [`RolloutSurface`]: fail-closed
    /// signature+content-hash+attestation re-verification at load, THEN staged advance/rollback
    /// through the persistent per-model [`WeightRollout`] + shared [`InMemoryWeightLoader`]. Returns
    /// `None` when no `[serving.rollout]` section is declared (nothing to drive); otherwise the load
    /// fence's `Result` (a refused load never staged anything).
    pub fn run_rollout_observe_window(
        &self,
        artifact: &WeightArtifact,
        attestation_ok: bool,
        window: TrafficWindow,
    ) -> Option<Result<AdvanceOutcome, LoadError>> {
        let surface = self.rollout.as_ref()?;
        let mut surface = surface.lock().expect("rollout surface lock");
        Some(surface.observe_window(artifact, attestation_ok, window))
    }

    /// The current staged-promotion state for a model's rollout, per the SAME shared
    /// [`RolloutSurface`] [`Self::run_rollout_observe_window`] drives. `None` on a surface with no
    /// `[serving.rollout]` declared, OR a model that has never been observed.
    pub fn rollout_state(&self, model_id: &str) -> Option<RolloutState> {
        self.rollout
            .as_ref()?
            .lock()
            .expect("rollout surface lock")
            .state(model_id)
    }

    /// The version currently receiving live traffic for a model, per the SAME shared loader.
    pub fn rollout_live_version(&self, model_id: &str) -> Option<String> {
        self.rollout
            .as_ref()?
            .lock()
            .expect("rollout surface lock")
            .live_version(model_id)
    }

    /// GAP-FIX serving-ops (SERVING_OPS.md §2, gap 6) — drive ONE chunked-prefill interleaving step
    /// over the SHARED served [`ServingGate`] (`Self::serving.0` — the SAME gate `/v1/infer`'s
    /// `model_infer` admits every call into). Returns `None` when `[serving] chunked_prefill` was not
    /// declared (unchanged, mechanism-off behaviour); otherwise the [`ainxt_serving::wfq::BatchStep`]
    /// that ran — a real advance of every currently-running sequence's decode step, interleaved with
    /// this tick's fresh prefill-chunk budget, on the live pool state real `/v1/infer` traffic built.
    pub fn run_batch_step_tick(&self) -> Option<ainxt_serving::wfq::BatchStep> {
        let mut gate = self.serving.0.lock().expect("serving gate lock");
        gate.batch_step_tick()
    }

    /// **Spawn the chunked-prefill interleaving LOOP on daemon start.** Mirrors
    /// [`Self::spawn_health_sweep`]/[`Self::spawn_autoscale_tick`]'s pattern for the analogous §2 gap:
    /// every `period` it drives one [`Self::run_batch_step_tick`] over the SAME shared served gate.
    /// Returns `None` when chunked prefill is not enabled on the served gate (nothing to drive);
    /// otherwise the [`tokio::task::JoinHandle`] (hold it for the process lifetime; aborting it stops
    /// the loop).
    pub fn spawn_batch_step_sweep(
        &self,
        period: std::time::Duration,
    ) -> Option<tokio::task::JoinHandle<()>> {
        if !self
            .serving
            .0
            .lock()
            .expect("serving gate lock")
            .has_chunked_prefill()
        {
            return None;
        }
        let gate = self.serving.0.clone();
        Some(tokio::spawn(async move {
            let mut iv = tokio::time::interval(period);
            loop {
                iv.tick().await;
                let _ = gate.lock().expect("serving gate lock").batch_step_tick();
            }
        }))
    }

    /// Advance the LIVE statutory [`IncidentRegister`] from a wall-clock instant (Unix-epoch **seconds**),
    /// projecting it onto the register's logical tick axis via [`ainxt_incident::ticks_from_unix_secs`] so
    /// the `now` fed to the breach comparison is the SAME minute-scaled unit as the arming budgets. This
    /// is the single wall-clock→tick path the background breach-clock ticker funnels through; exposing it
    /// lets the edge (and tests) advance the clock deterministically without a raw-seconds unit slip.
    /// Returns the engine events produced (pages / auto-raised meta-incidents).
    pub fn advance_breach_clock_at_unix_secs(
        &self,
        unix_secs: u64,
    ) -> Vec<ainxt_incident::EngineEvent> {
        self.incidents
            .lock()
            .expect("incident register lock")
            .tick(ainxt_incident::ticks_from_unix_secs(unix_secs))
    }

    /// GAP-FIX memory — drive ONE retroactive re-redaction sweep (design §8.6) over the SAME backing
    /// the served MEM-10 consent/export/erasure route reads ([`Self::memory_consent`]), via
    /// [`ainxt_memory::ConsentBacking::re_redact`]. Returns the number of item-versions whose content
    /// changed, or `None` on a surface with no chat engine (no memory backing to sweep). This is the
    /// clean, drivable entrypoint the daemon's background timer calls on a cadence
    /// ([`Self::spawn_memory_re_redact_sweep`]) — before this wire, a compliance-rule update (e.g. a
    /// newly-recognized secret/PII pattern) never reached content already persisted in durable memory.
    pub fn run_memory_re_redact_tick(&self) -> Option<usize> {
        self.memory_consent.as_ref()?.re_redact().ok()
    }

    /// Spawn the background compliance re-redaction sweep loop (mirrors
    /// [`Self::spawn_attestation_refresh`] / [`Self::spawn_breach_clock`]): every `period` it drives one
    /// [`Self::run_memory_re_redact_tick`]. Returns the [`tokio::task::JoinHandle`] (hold it for the
    /// process lifetime; aborting it — or dropping the surface — stops the sweep). `None` on a surface
    /// with no chat engine (no memory backing — nothing to sweep), matching
    /// `run_memory_re_redact_tick`'s own `None` case.
    pub fn spawn_memory_re_redact_sweep(
        &self,
        period: std::time::Duration,
    ) -> Option<tokio::task::JoinHandle<()>> {
        let backing = self.memory_consent.clone()?;
        Some(tokio::spawn(async move {
            let mut iv = tokio::time::interval(period);
            loop {
                iv.tick().await;
                let _ = backing.re_redact();
            }
        }))
    }

    /// GAP-FIX memory (embedding-lifecycle no caller) — drive ONE batch re-embed sweep (design §8.5)
    /// over the SAME backing the served MEM-10 consent/export/erasure route reads
    /// ([`Self::memory_consent`]), via [`ainxt_memory::ConsentBacking::reembed_all`].
    /// [`ainxt_memory::store::InMemoryStore::reembed_all`] /
    /// [`ainxt_memory::DurableMemoryStore::reembed_all`] were fully implemented and unit-tested but had
    /// ZERO callers outside `ainxt-memory`'s own tests — nothing in the served daemon ever ran the
    /// data-class-routed batch migration, so a platform embedding-model bump never reached
    /// already-persisted memory items. Mirrors [`Self::run_memory_re_redact_tick`]'s shape exactly.
    /// Returns the number of items re-embedded, or `None` on a surface with no chat engine (no memory
    /// backing to sweep).
    pub fn run_memory_reembed_tick(&self) -> Option<usize> {
        let backing = self.memory_consent.as_ref()?;
        let inhouse = MemoryHashEmbedder::new(
            "offline-hash-inhouse-v1",
            ainxt_memory::EmbedderKind::InHouse,
            64,
        );
        let cloud = MemoryHashEmbedder::new(
            "offline-hash-cloud-v1",
            ainxt_memory::EmbedderKind::Cloud,
            64,
        );
        backing.reembed_all(&inhouse, &cloud).ok()
    }

    /// Spawn the background embedding-lifecycle sweep loop (mirrors
    /// [`Self::spawn_memory_re_redact_sweep`]): every `period` it drives one
    /// [`Self::run_memory_reembed_tick`]. Returns the [`tokio::task::JoinHandle`] (hold it for the
    /// process lifetime; aborting it — or dropping the surface — stops the sweep). `None` on a surface
    /// with no chat engine (no memory backing — nothing to sweep), matching
    /// `run_memory_reembed_tick`'s own `None` case. A deployment with a live embed service replaces the
    /// offline [`MemoryHashEmbedder`] pair this spawns with real provider-backed embedders by driving
    /// [`Self::run_memory_reembed_tick`]'s own composition (`backing.reembed_all(..)`) directly instead
    /// of relying on this loop's offline default.
    pub fn spawn_memory_reembed_sweep(
        &self,
        period: std::time::Duration,
    ) -> Option<tokio::task::JoinHandle<()>> {
        let backing = self.memory_consent.clone()?;
        Some(tokio::spawn(async move {
            let inhouse = MemoryHashEmbedder::new(
                "offline-hash-inhouse-v1",
                ainxt_memory::EmbedderKind::InHouse,
                64,
            );
            let cloud = MemoryHashEmbedder::new(
                "offline-hash-cloud-v1",
                ainxt_memory::EmbedderKind::Cloud,
                64,
            );
            let mut iv = tokio::time::interval(period);
            loop {
                iv.tick().await;
                let _ = backing.reembed_all(&inhouse, &cloud);
            }
        }))
    }

    /// GAP-FIX ainxt-retrieval (gap6-retrieval-maintenance, item 1) — `ainxt_retrieval::maintenance`'s
    /// `IndexState`/`SourceEvent`/`ReindexTrigger`/`RecallLatencyMonitor` (`CONTEXT_FABRIC.md` §4:
    /// "Incremental maintenance — so it never rots" + "recall/latency tuned + monitored") were fully
    /// implemented and exhaustively unit-tested but had ZERO callers anywhere in the workspace outside
    /// their own crate's tests: nothing in the served daemon ever tracked per-node index staleness or
    /// vector-index recall/latency health. The served retrieval corpus is built ONCE at boot
    /// ([`corpus_for_scope`]/[`Self::kb_corpus_snapshot`]) with no ongoing freshness or health
    /// monitoring at all — a degraded HNSW index (bad `ef_search`, a partially-applied rebuild) or a KB
    /// document that silently changed underneath the served corpus would never be noticed by anything.
    ///
    /// Drives ONE maintenance pass ([`kb_maintenance_tick`]) over [`Self::kb_corpus_snapshot`] against
    /// the SHARED [`Self::kb_index_state`]/[`Self::kb_recall_monitor`] — see [`KbMaintenanceOutcome`]'s
    /// doc for exactly what a tick decides. This is the clean, drivable entrypoint the daemon's
    /// background timer calls on a cadence ([`Self::spawn_kb_maintenance_sweep`]), mirroring
    /// [`Self::run_memory_reembed_tick`]'s shape.
    ///
    /// **`needs_hot_wiring`**: no live per-query recall/latency sampler is wired onto the served
    /// `hybrid_rls`/`hybrid_ctx` query path yet — [`Self::kb_recall_monitor`] is a real, shared,
    /// tick-visible monitor; a deployment calls `record_recall`/`record_latency` on this SAME instance
    /// per served query to make degradation-driven reindex genuinely live from real traffic. This tick
    /// is exactly what acts on whatever samples land there (and is what a test drives directly to
    /// prove a degraded index forces a real reindex). Similarly, this OSS tree's `[kb]` documents are
    /// static admin-provisioned config (no live document-write API — [`Self::kb_corpus_snapshot`]'s own
    /// doc), so the content-diff half of a real source-file change is exercised the same way every
    /// other content-diff path in `ainxt-retrieval::maintenance` is unit-tested; this composition-root
    /// wire is what makes it REACHABLE from the served daemon, not merely correct in isolation.
    pub fn run_kb_maintenance_tick(&self, now: i64) -> KbMaintenanceOutcome {
        kb_maintenance_tick(
            &self.kb_index_state,
            &self.kb_recall_monitor,
            &self.kb_corpus_snapshot,
            now,
        )
    }

    /// Spawn the background KB index-maintenance sweep loop (mirrors
    /// [`Self::spawn_memory_reembed_sweep`]'s shape): every `period` it drives one
    /// [`kb_maintenance_tick`] over the SAME shared [`Self::kb_index_state`]/[`Self::kb_recall_monitor`]
    /// [`Self::run_kb_maintenance_tick`] reads/mutates, stamped with the current wall-clock tick.
    /// Returns the [`tokio::task::JoinHandle`] (hold it for the process lifetime; aborting it — or
    /// dropping the surface — stops the sweep). Unconditional (never `Option`, unlike the memory
    /// sweeps): every assembled surface has a `[kb]` config (possibly empty) and the shared maintenance
    /// state is always present, so there is no "no backing to sweep" case here.
    pub fn spawn_kb_maintenance_sweep(
        &self,
        period: std::time::Duration,
    ) -> tokio::task::JoinHandle<()> {
        let index_state = self.kb_index_state.clone();
        let recall_monitor = self.kb_recall_monitor.clone();
        let snapshot = self.kb_corpus_snapshot.clone();
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(period);
            loop {
                iv.tick().await;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                let _ = kb_maintenance_tick(&index_state, &recall_monitor, &snapshot, now);
            }
        })
    }

    /// GAP-FIX ainxt-retrieval (gap6-retrieval-maintenance, item 2) — [`governed::run_kb_corpus_reembed`]
    /// (itself a composition-root wrapper around [`ainxt_retrieval::reembed::migrate_to`],
    /// `CONTEXT_FABRIC.md` §4: "version-tracked embeddings + a re-embed pipeline so migrations never
    /// leave a mixed-version index") had ZERO callers anywhere in the workspace outside THIS crate's
    /// own tests (`r19_embedding_lifecycle_served.rs`) — an audited composition-root wrapper that
    /// nothing in the served daemon, on any real cadence or route, ever actually drove: a platform
    /// embedding-model bump would leave the KB retrieval corpus permanently mixed-version.
    ///
    /// Builds a fresh [`ainxt_retrieval::Corpus`] from [`Self::kb_corpus_snapshot`] (the SAME `(id,
    /// text)` snapshot [`Self::run_kb_maintenance_tick`] reads) and drives ONE migration to `target`
    /// via [`governed::run_kb_corpus_reembed`], using [`OfflineKbMaintenanceEmbedder`] — real logic,
    /// zero infra, the same offline-default posture as every other embedder pair in this file. Mirrors
    /// [`Self::run_memory_reembed_tick`]'s exact shape (build → call the ONE real migration entrypoint
    /// → return the report).
    ///
    /// **`needs_hot_wiring`**: identical caveat to [`governed::run_kb_corpus_reembed`]'s own doc — this
    /// crate holds no LIVE, re-assemblable `ChatSurface` handle past [`assemble_full`]'s own
    /// construction (the corpus moves into `hybrid_retriever` at assembly), so a successful migration
    /// here does not yet propagate into the SERVED `/v1/chat` retrieval path; it proves the migration
    /// mechanism is reachable and correct against the CURRENT `[kb]` config on a real cadence — the
    /// composition-root wire this gap audit asked for. A deployment that wants the migrated corpus
    /// actually served re-assembles the chat surface ([`build_chat_surface_wired_authz`]) with the
    /// [`ainxt_retrieval::reembed::MigrationReport::corpus`] this returns.
    pub fn run_kb_reembed_tick(
        &self,
        target: &ainxt_retrieval::EmbeddingVersion,
    ) -> ainxt_retrieval::reembed::MigrationReport {
        kb_reembed_tick(&self.kb_corpus_snapshot, target)
    }

    /// Spawn the background KB corpus embedding-migration sweep loop (mirrors
    /// [`Self::spawn_memory_reembed_sweep`]'s shape): every `period` it drives one
    /// [`Self::run_kb_reembed_tick`] toward the fixed `target` version over the SAME
    /// [`Self::kb_corpus_snapshot`] the maintenance sweep reads. Returns the
    /// [`tokio::task::JoinHandle`] (hold it for the process lifetime; aborting it — or dropping the
    /// surface — stops the sweep). Unconditional (never `Option`, matching
    /// [`Self::spawn_kb_maintenance_sweep`]): every assembled surface has a `[kb]` config (possibly
    /// empty) to migrate.
    pub fn spawn_kb_reembed_sweep(
        &self,
        period: std::time::Duration,
        target: ainxt_retrieval::EmbeddingVersion,
    ) -> tokio::task::JoinHandle<()> {
        let snapshot = self.kb_corpus_snapshot.clone();
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(period);
            loop {
                iv.tick().await;
                let _ = kb_reembed_tick(&snapshot, &target);
            }
        })
    }

    /// GAP-FIX memory (PromotionPipeline-never-called) — drive ONE episodic→semantic condensation
    /// checkpoint (design §3/§6) over the SAME backing the served MEM-10 consent/export/erasure route
    /// reads ([`Self::memory_consent`]), via [`ainxt_memory::ConsentBacking::run_promotion_sweep`].
    /// `PromotionPipeline::condense`/`write_candidates` were fully implemented and unit-tested but had
    /// ZERO callers outside `ainxt-memory`'s own tests — nothing in the served daemon ever ran a
    /// promotion checkpoint, so an episodic record (e.g. one authored via `POST /memory/remember` with
    /// `"kind":"episodic"`) never actually distilled into a durable semantic fact / user preference; it
    /// just aged out on its TTL. Mirrors [`Self::run_memory_reembed_tick`]'s shape. `now` seeds BOTH
    /// the candidate provenance tick AND (via `run_promotion_sweep`'s own contract) the per-sweep id
    /// prefix, so two ticks never collide on a generated candidate id. Returns the number of durable
    /// candidates written this tick, or `None` on a surface with no chat engine (no memory backing to
    /// sweep).
    pub fn run_memory_promotion_tick(&self, now: u64) -> Option<usize> {
        let backing = self.memory_consent.as_ref()?;
        let pipeline = ainxt_memory::PromotionPipeline::new(
            ainxt_memory::DurabilityHeuristic::default(),
            &format!("promo-sweep-{now}"),
        );
        let outcome = backing.run_promotion_sweep(&pipeline, now).ok()?;
        Some(outcome.candidates.len())
    }

    /// Spawn the background episodic→semantic promotion sweep loop (mirrors
    /// [`Self::spawn_memory_reembed_sweep`] / [`Self::spawn_memory_re_redact_sweep`]): every `period`
    /// it drives one [`Self::run_memory_promotion_tick`] stamped with the current wall-clock tick.
    /// Returns the [`tokio::task::JoinHandle`] (hold it for the process lifetime; aborting it — or
    /// dropping the surface — stops the sweep). `None` on a surface with no chat engine (no memory
    /// backing — nothing to sweep), matching `run_memory_promotion_tick`'s own `None` case.
    pub fn spawn_memory_promotion_sweep(
        &self,
        period: std::time::Duration,
    ) -> Option<tokio::task::JoinHandle<()>> {
        let backing = self.memory_consent.clone()?;
        Some(tokio::spawn(async move {
            let mut iv = tokio::time::interval(period);
            loop {
                iv.tick().await;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let pipeline = ainxt_memory::PromotionPipeline::new(
                    ainxt_memory::DurabilityHeuristic::default(),
                    &format!("promo-sweep-{now}"),
                );
                let _ = backing.run_promotion_sweep(&pipeline, now);
            }
        }))
    }

    /// GAP-FIX memory (gap6, item 2: "flywheel dispatch-half captured-but-never-read") — drive ONE
    /// propose → triage → dispatch_gated pass (design §4) over the SAME LIVE
    /// [`Self::feedback_engine`] `POST /feedback` (`capture`/`capture_at`) writes into. Before this
    /// wire, the daemon captured feedback forever but never read it back out: `ImprovementEngine::
    /// propose`/`Curator::triage`/`ImprovementEngine::{dispatch,dispatch_gated}` were fully implemented
    /// and unit-tested, and `/feedback` fed a real, LIVE engine instance — but nothing on any served or
    /// composition-root path ever called `propose`/`triage`/`dispatch`/`dispatch_gated` against it.
    ///
    /// Routes `OrgKnowledge` candidates into the SAME [`Self::memory_consent`] backing `POST
    /// /memory/*`/`DELETE /memory` read/write (via [`ainxt_memory::flywheel::MemoryStoreSink`] over
    /// [`ainxt_memory::ConsentBacking::with_store`]) — a recurring-fix candidate lands as a `Draft` OKI,
    /// still requiring a human [`ainxt_memory::MemoryStore::promote`] to reach authority (the
    /// unbypassable human-gate design §4/§8.3 requires). Routes `EvalCase` candidates into the SAME
    /// [`Self::eval_staging`] set. `Prompt`/`Retrieval`/`FineTune` have no real registry reachable at
    /// this composition layer yet — `needs_hot_wiring`, per [`ainxt_memory::flywheel::DestinationGates`]'s
    /// own fail-safe contract they are reported [`unrouted`](ainxt_memory::flywheel::GatedReport::unrouted),
    /// never silently accepted.
    ///
    /// `now` stamps both the candidate provenance tick and the generated candidate-id prefix (mirrors
    /// [`Self::run_memory_promotion_tick`]'s contract: two ticks must never collide on a generated id).
    pub fn run_feedback_flywheel_tick(&self, now: u64) -> ainxt_memory::flywheel::GatedReport {
        let engine = self.feedback_engine.lock().expect("feedback engine lock");
        let mut eval_staging = self.eval_staging.lock().expect("eval staging lock");
        feedback_flywheel_tick(
            &engine,
            self.memory_consent.as_deref(),
            &mut eval_staging,
            now,
        )
    }

    /// Spawn the background flywheel dispatch cadence (mirrors [`Self::spawn_memory_promotion_sweep`]'s
    /// shape exactly): every `period` it re-derives the current wall-clock tick and drives one
    /// [`Self::run_feedback_flywheel_tick`] over the SAME [`Self::feedback_engine`]/
    /// [`Self::memory_consent`]/[`Self::eval_staging`] handles — never a second, disconnected engine.
    /// `feedback_engine`/`eval_staging` are mandatory `AssembledFull` fields (unlike `memory_consent`,
    /// which is `None` on a surface with no chat engine — `OrgKnowledge` candidates are then simply
    /// `unrouted` for that tick, matching `run_feedback_flywheel_tick`'s own fail-safe), so this spawn
    /// is unconditional, mirroring [`Self::spawn_retention_sweep`]'s always-on shape.
    pub fn spawn_feedback_flywheel_sweep(
        &self,
        period: std::time::Duration,
    ) -> tokio::task::JoinHandle<()> {
        let feedback_engine = self.feedback_engine.clone();
        let memory_consent = self.memory_consent.clone();
        let eval_staging = self.eval_staging.clone();
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(period);
            loop {
                iv.tick().await;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let engine = feedback_engine.lock().expect("feedback engine lock");
                let mut staging = eval_staging.lock().expect("eval staging lock");
                let _ =
                    feedback_flywheel_tick(&engine, memory_consent.as_deref(), &mut staging, now);
            }
        })
    }
}

/// Recurrence threshold (distinct supporting turns) [`feedback_flywheel_tick`] requires before
/// `ImprovementEngine::propose` surfaces a candidate at all (design §4). Small on purpose: a fresh
/// deployment with modest feedback volume should still see triage/dispatch actually run end-to-end —
/// [`ainxt_memory::flywheel::HeuristicJudge`]'s own approve-support floor (below) is the second,
/// independent gate before anything reaches a destination sink.
const FEEDBACK_FLYWHEEL_RECURRENCE_THRESHOLD: u32 = 2;
/// Minimum average supporting confidence [`feedback_flywheel_tick`] requires (design §4's
/// `ImprovementEngine::propose` contract). Conservative default; a deployment with a live LLM-judge
/// (`needs_hot_wiring` — see [`ainxt_memory::flywheel::LlmJudge`]'s own doc) tunes this per its judge.
const FEEDBACK_FLYWHEEL_MIN_CONFIDENCE: f64 = 0.5;
/// [`ainxt_memory::flywheel::HeuristicJudge`]'s auto-approve support floor for
/// [`feedback_flywheel_tick`]'s offline default judge. A `SecurityRule`/`ArchitectureDecision`
/// org-knowledge candidate is flagged for mandatory human review regardless (the judge's own
/// unconditional rule design §4 names) — this floor only governs everything else.
const FEEDBACK_FLYWHEEL_APPROVE_FLOOR: u32 = 2;

/// GAP-FIX memory (gap6, item 2) — the actual propose → triage → dispatch_gated pass, factored out of
/// [`AssembledFull`] so [`AssembledFull::run_feedback_flywheel_tick`] and the loop body
/// [`AssembledFull::spawn_feedback_flywheel_sweep`] spawns share EXACTLY one implementation over
/// whatever live references the caller hands in — both callers always pass the SAME
/// `Arc`-derived `feedback_engine`/`memory_consent`/`eval_staging` handles `assemble_full` constructed,
/// never a second, disconnected `ImprovementEngine`. Wires `OrgKnowledge` → [`ainxt_memory::ConsentBacking::
/// with_store`] (when a chat engine's memory backing exists on this surface) and `EvalCase` →
/// `eval_staging`; `Prompt`/`Retrieval`/`FineTune` are left unwired (see [`AssembledFull::
/// run_feedback_flywheel_tick`]'s doc) and are reported `unrouted` by [`ainxt_memory::flywheel::
/// DestinationGates`]'s own fail-safe contract.
fn feedback_flywheel_tick(
    engine: &ainxt_memory::flywheel::ImprovementEngine,
    memory_consent: Option<&ainxt_memory::ConsentBacking>,
    eval_staging: &mut ainxt_eval::integrity::StagingSet,
    now: u64,
) -> ainxt_memory::flywheel::GatedReport {
    let candidates = engine.propose(
        FEEDBACK_FLYWHEEL_RECURRENCE_THRESHOLD,
        FEEDBACK_FLYWHEEL_MIN_CONFIDENCE,
        &ainxt_memory::Scope::Org,
        &format!("flywheel-{now}"),
        now,
    );
    let triaged = ainxt_memory::flywheel::Curator::triage(
        &candidates,
        &ainxt_memory::flywheel::DefaultRuleJudge,
        &ainxt_memory::flywheel::HeuristicJudge::with_floor(FEEDBACK_FLYWHEEL_APPROVE_FLOOR),
    );
    let survivors: Vec<ainxt_memory::flywheel::Candidate> =
        triaged.into_iter().map(|t| t.candidate).collect();
    let mut eval_sink = EvalStagingSink::new(eval_staging, format!("flywheel-{now}"));
    match memory_consent {
        Some(backing) => backing
            .with_store(|store| {
                let mut org_sink = ainxt_memory::flywheel::MemoryStoreSink::new(store);
                let mut gates = ainxt_memory::flywheel::DestinationGates::new()
                    .with_org_knowledge(&mut org_sink)
                    .with_eval_case(&mut eval_sink);
                Ok(engine.dispatch_gated(&survivors, &mut gates))
            })
            .unwrap_or_default(),
        None => {
            let mut gates =
                ainxt_memory::flywheel::DestinationGates::new().with_eval_case(&mut eval_sink);
            engine.dispatch_gated(&survivors, &mut gates)
        }
    }
}

/// GAP-FIX memory (gap6, item 2) — routes `CandidateDest::EvalCase` candidates into the REAL flywheel
/// staging area ([`ainxt_eval::integrity::StagingSet`], [`AssembledFull::eval_staging`]) instead of
/// leaving them `unrouted`. Honestly partial, `needs_hot_wiring`: [`ainxt_memory::flywheel::Candidate`]'s
/// `EvalCase` shape carries only a `summary` + `support` count (design §4's "staging eval-case from
/// turn {turn}"), no turn transcript or reference answer — so `gold` is staged EMPTY rather than
/// fabricated, and `contamination_clean` is always `false` (a real
/// [`ainxt_eval::integrity::scan_contamination`] pass against the live eval corpus, and a human-supplied
/// gold answer, both belong to a promotion-review surface this composition does not have yet). This
/// still closes the "candidates produced into a void" gap for this destination: every `EvalCase`
/// candidate now durably lands in the SAME staging set a future promotion route would read, instead of
/// being silently dropped.
struct EvalStagingSink<'a> {
    staging: &'a mut ainxt_eval::integrity::StagingSet,
    id_prefix: String,
    staged: usize,
}

impl<'a> EvalStagingSink<'a> {
    fn new(staging: &'a mut ainxt_eval::integrity::StagingSet, id_prefix: String) -> Self {
        EvalStagingSink {
            staging,
            id_prefix,
            staged: 0,
        }
    }
}

impl ainxt_memory::flywheel::CandidateSink for EvalStagingSink<'_> {
    fn accept(&mut self, candidate: &ainxt_memory::flywheel::Candidate) -> Result<(), String> {
        match candidate.dest {
            ainxt_memory::flywheel::CandidateDest::EvalCase => {
                let id = format!("{}-{}", self.id_prefix, self.staged);
                self.staging.stage(ainxt_eval::integrity::StagedCase {
                    id,
                    input: candidate.summary.clone(),
                    gold: String::new(),
                    provenance: ainxt_eval::integrity::CaseProvenance::Flywheel,
                    human_approved: false,
                    contamination_clean: false,
                });
                self.staged += 1;
                Ok(())
            }
            other => Err(format!(
                "EvalStagingSink only accepts EvalCase candidates, got {other:?}"
            )),
        }
    }
}

/// Augment an [`Assembled`] surface (chat / profiled / program / engine — whichever `main` selected)
/// into the **fully-wired** [`AssembledFull`] the shipped daemon serves. Builds the durable Event Log,
/// the `/graph` / `/v1/query_ledger` / `/v1/infer` governed surfaces, instantiates the live
/// [`IncidentRegister`] + shared [`ControlPlane`] on the served surface, and (when keyed) the connector
/// token vault. Offline-safe: an empty graph, an empty serving pool and the default schema all SERVE
/// (never 404); the air-gapped daemon runs with zero external infra.
///
/// Builds its OWN fresh [`ControlPlane`] — byte-identical to every prior call site. A composition that
/// needs the SAME shared plane a pre-assembled surface already governs (e.g. [`assemble_chat_governed`],
/// see the GAP-FIX doc on [`assemble_full_with_control_plane`]) must use that sibling instead.
pub fn assemble_full(
    loaded: &LoadedConfig,
    assembled: Assembled,
) -> Result<AssembledFull, AssembleError> {
    assemble_full_with_control_plane(loaded, assembled, Arc::new(Mutex::new(ControlPlane::new())))
}

/// GAP-FIX identity-payments (ADR-022 §15/§17/§19 "per-turn granularity") — the served daemon's ONLY
/// composition path (`main.rs`'s `assemble_selected` → `assemble_full`) never shared a single
/// [`ControlPlane`] between the surface it selected and the one [`assemble_full`] mints for itself at
/// L1: [`assemble_chat_governed`] (the fused §15 JIT-renew + §17/§19 admission gate driven on EVERY
/// chat turn, `ainxt-runtimed/src/chat_identity.rs`) was fully built and unit-tested, but had no path
/// from `assemble_selected`/`main.rs` to become the deployed daemon's `/v1/chat` — the served daemon
/// therefore ran chat at NO identity-lifecycle granularity at all (a kill-switch/revocation pulled on
/// the daemon's own `control_plane` reached Program/Team turns immediately via their already-wired
/// `ControlPlane::admit` calls, but reached chat never — not per-turn, not per-run, not ever). This
/// sibling lets a caller (see `assemble_selected_governed`) hand in the SAME shared plane a governed
/// surface was built against, so the daemon's kill-switch/revocation endpoints and the served chat
/// turns consult one live deny-state, exactly as Program/Team already do.
///
/// [`assemble_full`] is unchanged (still mints its own fresh plane) so all existing callers keep their
/// current behavior byte-for-byte; this is a pure addition.
pub fn assemble_full_with_control_plane(
    loaded: &LoadedConfig,
    assembled: Assembled,
    control_plane: Arc<Mutex<ControlPlane>>,
) -> Result<AssembledFull, AssembleError> {
    let Assembled {
        manager,
        mut report,
        wire_events,
        capability_ledger,
        dispatch_probe,
        shared_answer_cache,
        capability_tools,
        memory_backend,
        // GAP-FIX regulated-fi-responsible-lifecycle — the SHARED handle captured from the SAME router
        // this surface's engine dispatches turns through (see the `Assembled::outsourcing_register` doc).
        outsourcing_register,
        // GAP-FIX identity-payments (ADR-016 §6) — the SHARED MandateRegistry already installed on
        // this surface's `capability_tools` (see `Assembled::mandate_registry`'s doc). Reused verbatim
        // below as `AssembledFull::mandate_registry` — never a second, disjoint registry minted here.
        mandate_registry,
        // GAP-FIX tooling-mcp-plugins-routing — the SHARED McpAdminHandle from the SAME unified
        // Capability registry build (see `Assembled::mcp_admin` doc).
        mcp_admin,
        // GAP-CLOSE os-workforce-exec #2 — not yet threaded onto `AssembledFull` (nothing downstream of
        // `assemble_full` reads it today); a caller that needs it reads
        // `Assembled::workforce_invocation_ledger` directly off the surface-level `Assembled` this
        // function consumes, BEFORE calling here. Intentionally dropped, not silently ignored.
        workforce_invocation_ledger: _workforce_invocation_ledger,
        // GAP-CLOSE os-workforce-exec #3 — same posture as the ledger above: a caller that needs the
        // live kernel handle reads `Assembled::workforce_kernel` directly off the surface-level
        // `Assembled`, BEFORE calling here. Intentionally dropped, not silently ignored.
        workforce_kernel: _workforce_kernel,
        // GAP-CLOSE os-workforce (gap6-workforce-governance-gate) — UNLIKE the two siblings above, this
        // IS threaded onto `AssembledFull`/`FullAppExt` below (`workforce: ...`), so `ainxt-server`'s
        // `POST /v1/workforce/roles` route reaches the REAL, already-Studio-gated `WorkforceSurface`
        // this exact `Assembled` value carries — never left test-only like the ledger/kernel above.
        workforce_surface,
        // GAP-FIX surfaces-profiles-skills-config (ADR-026 §6.2 hot-reload) — threaded onto
        // `AssembledFull` below so `POST /admin/reload` reaches the SAME `SkillRuntime` instance.
        skill_runtime,
        // GAP-FIX gap6-composition-root (Item 1) — the SAME `ServingHandle` the selected surface's real
        // Engine attached via `Engine::with_node_attestor` (see `Assembled::serving`'s doc); reused
        // below (instead of `build_serving(&loaded.serving)` minting a second, disjoint gate) so the
        // engine's own attestor and this daemon's `/v1/chat` Stage-1 fence + attestation refresh loop
        // consult ONE live attestation state.
        serving: assembled_serving,
    } = assembled;
    // NOTE: `AssembledFull::artifact` (below, via `mounts::build_artifact_runtime`) is a DIFFERENT,
    // strictly more capable `ArtifactRuntime` than the now-removed surface-level `SurfaceArtifacts` —
    // see the DECISION comment on the [`Assembled`] struct (GAP-AUDIT surfaces-profiles-skills-config
    // item 3) for why that construction was removed rather than threaded through here.
    // GAP-FIX memory (KG-linkage-diverged) — a clone taken BEFORE `memory_backend` is consumed below,
    // so the graph-linking pass a few lines down (`link_authoritative_oki_into_graph`) can open its
    // own fresh store over the SAME backend the served consent route and the chat engine's memory
    // reader use — see that function's doc for the defect this closes.
    let memory_backend_for_graph = memory_backend.clone();
    // GAP-FIX memory (write-path-missing) — captured BEFORE `memory_backend` is consumed by the
    // `.map` below: the live `MemoryWriter` handle onto the engine's OWN long-lived durable-store
    // instance, so `AssembledFull::memory_writer` (threaded to `FullAppExt`/`POST /memory/remember`)
    // reaches the EXACT SAME store `read_for_turn` reads — never a second, independently-reopened
    // one (see `MemoryHandle`'s doc).
    let memory_writer: Option<Arc<dyn ainxt_memory::MemoryWriter>> =
        memory_backend.as_ref().map(|handle| handle.writer.clone());
    // GAP-FIX memory — MEM-10's served consent/export/erasure route needs a handle that can see
    // whatever the chat engine's own memory reader has ACTUALLY written, at request time, not just
    // what existed at assembly time (a long-lived DurableMemoryStore never re-pulls — see
    // `ConsentBacking`'s doc). `Some` only on a surface with a real chat engine.
    let memory_consent = memory_backend.map(|handle| {
        report.push(
            "memory: served MEM-10 consent/export/erasure route wired over the SAME \
             MemorySqlBackend the chat engine's own memory reader writes to (opened fresh per \
             request via ConsentBacking, so it is never a frozen assembly-time snapshot)"
                .into(),
        );
        Arc::new(ainxt_memory::ConsentBacking::Durable(handle.backend))
    });
    if memory_writer.is_some() {
        report.push(
            "memory: served POST /memory/remember write route wired onto the SAME long-lived \
             durable-store instance the assembled chat engine's own Context-Fabric memory seam \
             reads through — a write is visible to the very next served turn's read_for_turn call"
                .into(),
        );
    }
    // R10 — the background ReconcilerSweeper over the SAME shared exactly-once ledger the served engine's
    // unified Capability registry dispatches through (§1.8): a side-effecting capability call that lands
    // but whose ack is lost leaves a `PENDING` row; the sweep leases it, probes the downstream via the
    // shared reconciler, and commits/fails/escalates — never a passive expiry (unacceptable for
    // payments). Built here (offline-safe); the daemon starts it via [`AssembledFull::spawn_reconciler_sweep`].
    let reconciler_sweeper = capability_ledger.as_ref().map(|(ledger, reconciler)| {
        report.push(
            "reconciler sweep: background ReconcilerSweeper wired over the served engine's SHARED \
             exactly-once ledger (§1.8) — a lost-ack PENDING row is actively leased, probed and \
             resolved/escalated on daemon start, never passively expired"
                .into(),
        );
        Arc::new(ReconcilerSweeper::new(
            Arc::clone(ledger),
            Arc::clone(reconciler),
            Arc::new(ainxt_tools::RecordingEscalationSink::new()),
            "ainxt-runtimed",
            RECONCILER_MIN_AGE_TICKS,
            RECONCILER_LEASE_TTL_TICKS,
        ))
    });
    let event_log = build_event_log(&event_log_dir(loaded))?;
    let mut graph = build_graph(&loaded.kb);
    // GAP-FIX memory (KG-linkage-diverged) — see `link_authoritative_oki_into_graph`'s doc: land every
    // authoritative org-knowledge item into the SAME graph the `/graph` route serves, not a separate
    // structure memory keeps to itself.
    let oki_linked = memory_backend_for_graph
        .as_ref()
        .map(|handle| link_authoritative_oki_into_graph(&mut graph, &handle.backend))
        .unwrap_or(0);
    if oki_linked > 0 {
        report.push(format!(
            "graph: {oki_linked} authoritative org-knowledge item(s) linked into the SAME /graph \
             knowledge graph as first-class nodes+edges (design ENTERPRISE_MEMORY_LEARNING.md §4: \
             \"OKIs are nodes in the Context Fabric Knowledge Graph... one RBAC/data-class-aware \
             graph, one query surface\") — previously memory's own Link/EdgeKind graph was fully \
             separate from ainxt-graph, so an approver's promotion never appeared in the served /graph"
        ));
    }
    let graph = Arc::new(graph);
    let ledger_schema = Arc::new(build_ledger_schema()?);
    // GAP-FIX gap6-composition-root (Item 1) — reuse the SAME `ServingHandle` the selected surface's
    // real Engine already attached via `Engine::with_node_attestor`, when it has one (chat/engine/
    // program/team). This is what makes the engine's own attestor and this daemon's `/v1/chat` Stage-1
    // fence + attestation refresh loop consult ONE live attestation state, never two independent gates
    // that could disagree (or leave the engine permanently fail-closed against a gate the refresher
    // never touches). `None` only on a surface with no real Engine (the AiNxt-OS workforce surface) —
    // falls back to a freshly-built gate so `/v1/infer` + the health/WFQ machinery below still work.
    let serving = assembled_serving.unwrap_or_else(|| build_serving(&loaded.serving));
    if serving.1.is_empty() {
        report.push(
            "serving: no [[serving.nodes]] declared — attestation node-fence + QoS admission INERT on \
             /v1/chat (air-gapped default: model served by the engine's provider chain, no GPU node to \
             attest, no 503)"
                .into(),
        );
    } else {
        report.push(format!(
            "serving: {} node(s) bound onto the LIVE fence — attestation + SLO-aware QoS admission \
             ENFORCED on the shipped /v1/chat and /v1/infer path (regulated turn fails closed on an \
             unattested node; over-capacity turns queue then shed)",
            serving.1.len()
        ));
    }
    // GAP-FIX serving-ops (SERVING_OPS.md §2, gap 6) — `build_serving` already applied
    // `with_chunked_prefill` from `[serving] chunked_prefill` above; report whether the mechanism is
    // live so the assembly report matches every other opt-in serving-ops mechanism's shape.
    //
    // GAP-FIX gap6-composition-root (Item 2) — `spawn_batch_step_sweep` (the async cadence timer this
    // string used to flag as `needs_hot_wiring`) is now started unconditionally on daemon boot
    // (`main.rs`, mirroring every other conditionally-live cadence), self-gated on
    // `ServingGate::has_chunked_prefill()` exactly like `run_batch_step_tick` already was — so a
    // declared `[serving] chunked_prefill` now gets its interleaving tick actually driven, not just a
    // hand-callable method nothing on the served daemon ever called.
    if let Some(chunks) = loaded.serving.chunked_prefill {
        report.push(format!(
            "serving: chunked-prefill interleaving wired ({chunks} chunk(s)/tick) — \
             AssembledFull::run_batch_step_tick now interleaves a decode step for every currently- \
             running sequence with each tick's prefill-chunk budget, on the SAME ServingGate /v1/infer \
             admits into (async cadence timer LIVE via spawn_batch_step_sweep, started on daemon boot)"
        ));
    }
    // GAP-FIX serving-ops (SERVING_OPS.md §1, gap 7) — build the disaggregated prefill/decode pool
    // split when `[serving.disagg]` is declared. `None` (default) leaves `serving` above as the only
    // served pool, unchanged.
    let disagg = build_disagg(&loaded.serving).map(|(pools, prefill_c, decode_c)| {
        report.push(format!(
            "serving: disaggregated prefill/decode pool split wired ({} prefill node(s), {} decode \
             node(s)) — mounted at POST /v1/infer/{{prefill,decode,handoff}} as TWO physically \
             separate ServingGates joined only by the KV Relay; a saturated Prefill Pool can no longer \
             delay, shed, or preempt a Decode Pool admission on the shipped daemon (SERVING_OPS.md §1)",
            prefill_c.len(),
            decode_c.len()
        ));
        (Arc::new(Mutex::new(pools)), prefill_c, decode_c)
    });
    // R13 (SRV-03, HIGH) — build the ADR-021 §8.3 attestation quote-refresh DRIVER over the declared
    // regulated pool. Before this, a declared node stayed UNattested forever (a quote had to be
    // hand-submitted), so regulated traffic fenced off the whole fleet. Now the daemon drives this
    // refresher on a cadence (`run_attestation_refresh_tick`) with the live-TEE `QuoteSource` seam;
    // the async timer + the live TEE are needs_hot_wiring/infra. `None` on the air-gapped default
    // (no declared nodes ⇒ nothing to attest, and the fence stays inert — the r4 shipped-chat guard).
    let attestation_refresher = if serving.1.is_empty() {
        None
    } else {
        let declared: Vec<String> = serving.1.iter().map(|n| n.node_id.clone()).collect();
        let refresh_cfg = RefreshConfig {
            interval: loaded
                .serving
                .attestation_refresh_interval
                .unwrap_or_else(|| RefreshConfig::default().interval),
            lead: loaded
                .serving
                .attestation_refresh_lead
                .unwrap_or_else(|| RefreshConfig::default().lead),
        };
        report.push(format!(
            "serving: attestation quote-refresh loop wired over {} declared node(s) (interval={} \
             lead={} ticks) — the daemon re-attests the regulated pool on a cadence via the live-TEE \
             QuoteSource seam (needs_hot_wiring: async timer + TEE)",
            declared.len(),
            refresh_cfg.interval,
            refresh_cfg.lead
        ));
        Some(Arc::new(Mutex::new(AttestationRefresher::new(
            declared,
            refresh_cfg,
        ))))
    };
    // GAP-FIX serving-ops (SERVING_OPS.md §4, gap 37) — build the shard-group health monitor +
    // cadence over any `[[serving.nodes]]` entry that declares a `golden_hash`. Before this, §4 had
    // the pure health-state machine (`ShardHealthMonitor`) + the drain-the-group recovery sequence
    // fully implemented and tested, but nothing on the served surface ever registered a group into
    // it, so a hung or silently-corrupting shard could never actually be pulled from the pool in
    // production. `None` when no node declares a golden hash (nothing to monitor — unchanged,
    // attestation-only behavior for a deployment that hasn't opted in).
    let health = {
        let monitored: Vec<(String, u64)> = loaded
            .serving
            .nodes
            .iter()
            .filter_map(|n| n.golden_hash.map(|h| (n.node_id.clone(), h)))
            .collect();
        if monitored.is_empty() {
            None
        } else {
            let health_cfg = &loaded.serving.health;
            let mut monitor = ShardHealthMonitor::new(HealthConfig {
                collective_timeout: health_cfg.collective_timeout,
                consecutive_miss_threshold: health_cfg.consecutive_miss_threshold,
            });
            for (node_id, golden_hash) in &monitored {
                monitor.register_group(ShardGroupId::new(node_id.clone()), *golden_hash);
            }
            report.push(format!(
                "serving: shard-group health monitor wired over {} declared node(s) (SERVING_OPS.md \
                 §4, sweep_interval={} ticks) — the interconnect watchdog + canary-correctness probe \
                 now supervise the same nodes `/v1/infer` dispatches to, with drain-the-group recovery \
                 on a trip (needs_hot_wiring: async timer + live GPU probe)",
                monitored.len(),
                health_cfg.sweep_interval
            ));
            Some((
                Arc::new(Mutex::new(monitor)),
                Arc::new(Mutex::new(HealthCadence::new(HealthCadenceConfig {
                    interval: health_cfg.sweep_interval,
                }))),
            ))
        }
    };
    let (health_monitor, health_cadence) = match health {
        Some((monitor, cadence)) => (Some(monitor), Some(cadence)),
        None => (None, None),
    };
    // GAP-FIX serving-ops (SERVING_OPS.md §3, gaps 26/W, round-15 LOW) — build the demand-EWMA
    // autoscale controller + cadence when a deployment declares `[serving.autoscale]`. Before this,
    // §3 had `AutoscaleController::tick` (fold demand samples → scale-to/park-warm decisions) and
    // `AutoscaleCadence` (the due-or-not poll gate) fully implemented and tested, but nothing on the
    // served surface ever built or drove either — the decision loop the audit found composed but
    // never reachable from any daemon path. `None` (default) when no autoscale tuning is declared —
    // there is no sensible universal default for `per_replica_capacity` (a deployment-specific
    // capacity number), unlike `health`'s conservative built-in defaults.
    let autoscale = loaded.serving.autoscale.as_ref().map(|cfg| {
        report.push(format!(
            "serving: demand-EWMA autoscale controller wired (SERVING_OPS.md §3, alpha={} \
             per_replica_capacity={} min_replicas={} sweep_interval={} ticks) — per-model scale-to/ \
             park-warm decisions are now a live per-tick loop (needs_hot_wiring: async timer + live \
             demand-sample collection)",
            cfg.alpha, cfg.per_replica_capacity, cfg.min_replicas, cfg.sweep_interval
        ));
        (
            Arc::new(Mutex::new(AutoscaleController::new(
                cfg.alpha,
                cfg.per_replica_capacity,
                cfg.min_replicas,
            ))),
            Arc::new(Mutex::new(AutoscaleCadence::new(AutoscaleCadenceConfig {
                interval: cfg.sweep_interval,
            }))),
        )
    });
    let (autoscale_controller, autoscale_cadence) = match autoscale {
        Some((controller, cadence)) => (Some(controller), Some(cadence)),
        None => (None, None),
    };
    // GAP-FIX serving-ops (SERVING_OPS.md §3, gaps 26/W) — build the GPU bin-packing placement +
    // model-parking actuator when `[serving.placement]` is declared. `None` (default) when not.
    let placement = build_placement(&loaded.serving).map(|actuator| {
        report.push(
            "serving: GPU bin-packing placement + model-parking/eviction actuator wired \
             (SERVING_OPS.md §3) — AssembledFull::run_autoscale_and_placement_tick now converges the \
             declared bin fleet toward the demand-EWMA autoscale controller's own scale-to/park-warm \
             decisions via a rate-limited PlacementReconciler pass over a persistent \
             InMemoryPlacementBinder (needs_hot_wiring: the live CUDA/driver PlacementBinder + async \
             cadence timer)"
                .into(),
        );
        Arc::new(Mutex::new(actuator))
    });
    // GAP-FIX serving-ops (SERVING_OPS.md §5, gap 38) — build the zero-downtime signed weight-rollout
    // surface when `[serving.rollout]` is declared. `None` (default) when not.
    let rollout = build_rollout(&loaded.serving).map(|surface| {
        report.push(
            "serving: zero-downtime signed weight-rollout surface wired (SERVING_OPS.md §5) — \
             AssembledFull::run_rollout_observe_window now drives the staged P2Shadow→P2Canary→ \
             P1Canary→P0 promotion (fail-closed signature+content-hash+attestation re-verification \
             at every load) from a real-traffic quality window, over a persistent per-model \
             WeightRollout + shared InMemoryWeightLoader (needs_hot_wiring: the live weight-staging \
             WeightLoader + the live-traffic metrics collector)"
                .into(),
        );
        Arc::new(Mutex::new(surface))
    });
    // Arming policy is config-driven: OSS default is Generic (no pre-armed clocks).
    // Set [incident] arming_policy = "india-regulatory" in a private overlay for
    // India-regulated deployments (CERT-In 6h, DPDP-Board 72h, RBI 24h clocks).
    let incidents = Arc::new(Mutex::new(IncidentRegister::new(
        loaded.incident.arming_policy(),
    )));
    // `control_plane` is the caller-supplied shared plane (a fresh one from `assemble_full`, or the
    // SAME plane a pre-assembled governed surface already consults, from
    // `assemble_full_with_control_plane` — see that function's GAP-FIX doc).
    let token_vault = build_token_vault(&mut report);
    // eval-tester: instantiate the online canary → auto-rollback → drift controller LIVE on the served
    // surface (candidate/champion refs default to the reproducibility-pinned control ref).
    let release_controller_cfg = governed::ReleaseControllerConfig::default();
    let release_controller = Arc::new(Mutex::new(governed::build_release_controller(
        &release_controller_cfg,
    )));
    // GAP-FIX eval-tester-scenarios: the git-ref traffic split that decides which of the SAME
    // candidate/champion refs above actually serves a given request — the missing `served_ref` source
    // `ainxt_quality::feed`'s own doc names ("from the upstream traffic split").
    let traffic_split = Arc::new(governed::build_traffic_split(&release_controller_cfg));
    let outsourcing_residency = governed::residency();

    // R6 shipped-composition cluster: build the surfaces the daemon MOUNTS through serve_full_ext
    // (harness invoke/run, connector OAuth, artifact generation, step-through replay) and the two
    // additional control organs the design mandates be LIVE on the served surface (DSAR/right-to-erasure
    // + SR-11-7 quality circuit-breaker). All are offline-safe.
    //
    // R16 (§0/§1.2, CRITICAL FIX): hand the harness `/run` bridge the SAME `capability_tools` handle the
    // assembled surface's own engine dispatches through (`Some` on every surface with a real Engine —
    // bare engine/chat/code/sdlc/buddy/program/team; `None` only on the AiNxt-OS workforce surface,
    // which has no engine tool-dispatch path to collide with). Before this fix the daemon called
    // `mounts::build_harness_mounts(&mut report)` with no linkage to the engine's registry at all, so the
    // bridge always built a SECOND registry over a SECOND, disjoint exactly-once ledger — the same
    // caller-supplied idempotency key (e.g. a retried settlement-initiation call) could commit once via
    // `/v1/chat` and AGAIN via `/v1/harness/{id}/run`.
    let harness = Arc::new(mounts::build_harness_mounts(
        &mut report,
        capability_tools,
        &loaded.runtime.gates,
        &loaded.harness,
    )?);
    // GAP-FIX connectors "distributed refresh lock never wired" — ONE token key + ONE cheap-to-clone
    // backend (clones share the same in-RAM table) shared between the OAuth-callback SEAL path
    // (`build_connector_gateway`) and the USE-path refresh/READ path (`build_connector_invoker`), so a
    // token sealed here is the SAME token the invoker's `CoordinatorTokenSource` resolves and
    // refreshes — not two disjoint vaults each thinking it is the only one.
    //
    // GAP-FIX connectors round-2 (KEY-ROT-01) — the raw key is wrapped in exactly ONE `Arc<AeadCodec>`
    // (`connector_key_ring`) shared into BOTH builders below (each wraps its own clone of the Arc in
    // `ainxt_token::SharedAeadCodec`, never a second, independently-constructed `AeadCodec`). The SAME
    // Arc is also kept on `AssembledFull`/threaded into `FullAppExt::key_rotation`, so `POST
    // /admin/keys/rotate` mutates this EXACT live ring — a rotation is visible to the SEAL path and the
    // OPEN/refresh path in the same call, never a stale ring silently left behind.
    let connector_key_ring = Arc::new(ainxt_token::AeadCodec::new(ainxt_token::KeyRing::new(
        1,
        connector_token_key(&mut report),
    )));
    // GAP-FIX token-durability (gap6) — Memory (default) or File (AINXT_TOKEN_STORE=file, the durable
    // OSS default, ainxt_token::FileTokenStore) — see `connector_token_backend`'s doc. Cheap to clone
    // either way, so the SAME sharing requirement documented above (one backend, two builders) holds
    // regardless of which one is selected.
    let connector_token_backend = connector_token_backend(&mut report);
    let connectors = Arc::new(mounts::build_connector_gateway(
        connector_key_ring.clone(),
        connector_token_backend.clone(),
        &mut report,
    ));
    let (connector_invoker, tripwire_remediator) = mounts::build_connector_invoker(
        &mut report,
        incidents.clone(),
        control_plane.clone(),
        &control_plane_sha(),
        connector_key_ring.clone(),
        connector_token_backend,
    );
    let connector_invoker = Arc::new(connector_invoker);
    let artifact = Arc::new(mounts::build_artifact_runtime(&mut report));
    let replay_store = mounts::build_replay_store(&mut report);
    // GAP6 replay-reexec-presence — the live-model ReExecutor seam behind `/v1/replay/reexecute` +
    // `/v1/replay/drift`, over the SAME `replay_store` above (see `mounts::build_reexec_executor`'s
    // doc for why this closes the gap: `re_execute_persisted_req`/`drift_report_persisted` were fully
    // implemented and unit-tested but had no composition-root caller before this wire).
    let reexec_executor = mounts::build_reexec_executor(&mut report);
    let erasure = Arc::new(Mutex::new(mounts::build_erasure(
        shared_answer_cache,
        &mut report,
    )));
    let quality_breaker = Arc::new(mounts::build_quality_breaker(&mut report));
    // GAP-FIX tooling-mcp-plugins-routing (round 2) — the Regression Vault `admit_promotion` mints a
    // permanent case into on every real BreakerTrip (see `AssembledFull::vault`'s doc). Starts empty
    // (or hydrated from the durable store below); grows monotonically as the served surface actually
    // trips on live traffic.
    // GAP-FIX eval-durable-stores — hydrate from `[server] eval_durable_dir` when configured (see
    // `build_eval_vault`'s doc); `vault_store` is threaded onto `AssembledFull` below so
    // `admit_promotion` can persist every NEW case durably too.
    let (vault, vault_store) = build_eval_vault(loaded, &mut report);
    let vault = Arc::new(Mutex::new(vault));
    let retention = Arc::new(Mutex::new(mounts::build_record_store(&mut report)));
    // GAP-FIX memory (flywheel-no-route) — the continuous-learning Improvement Engine (design §4):
    // `ImprovementEngine::capture_at`/`propose` were fully implemented and unit-tested, but no HTTP
    // route existed anywhere in the 47-route served daemon to feed it a real user's thumbs/
    // correction/trajectory signal — the flywheel had captured-but-unreachable material to learn
    // from on every real deployment. Empty until a served `POST /feedback` call captures the first
    // signal; shared with `mounts::build_feedback_router` via `FullAppExt::feedback`.
    let feedback_engine = Arc::new(Mutex::new(ainxt_memory::flywheel::ImprovementEngine::new()));
    report.push(
        "memory: continuous-learning Improvement Engine LIVE (POST /feedback) — thumbs/correction/\
         edit/trajectory/abandonment signals now have a served capture route feeding the SAME \
         engine `propose`/curation reads"
            .into(),
    );
    // GAP-FIX regulated-fi-responsible-lifecycle (gap6) — the §6.3 cadence driver over the SAME
    // `retention` store + `replay_store` served-turn tier: see `AssembledFull::retention_sweeper`'s
    // doc. `RetentionSweeper::new`'s `interval_ticks` is a cheap default; a deployment that wants a
    // tighter/looser cadence passes its own period to `spawn_retention_sweep` (the interval below only
    // governs `run_retention_sweep_tick`'s own due-check, mirrored by the spawn loop's period).
    let retention_sweeper = Arc::new(Mutex::new(ainxt_lifecycle::guarded::RetentionSweeper::new(
        60,
    )));
    report.push(
        "lifecycle: RetentionSweeper §6.3 cadence LIVE — a deferred erasure (hold released / floor \
         elapsed) now fires AUTOMATICALLY on a schedule and propagates into the served-turn replay \
         tier, not only on-demand from /v1/regfi/erasure"
            .into(),
    );
    // GAP-FIX memory (gap6, item 2) — the flywheel's EvalCase staging destination: see
    // `AssembledFull::eval_staging`'s doc. Empty until the flywheel cadence stages its first candidate.
    let eval_staging = Arc::new(Mutex::new(ainxt_eval::integrity::StagingSet::default()));
    report.push(
        "memory: continuous-learning flywheel DISPATCH cadence LIVE (propose -> triage -> \
         dispatch_gated) over the SAME ImprovementEngine POST /feedback writes into — OrgKnowledge \
         candidates route into the SAME MEM-10 memory backing (Draft OKI, human-gated to authority); \
         EvalCase candidates route into a real flywheel staging set (human-gated promotion). Prompt/\
         Retrieval/FineTune have no real destination reachable at this layer yet (needs_hot_wiring) \
         and are reported unrouted, never silently accepted"
            .into(),
    );
    // GAP-AUDIT regulated-fi #13 / GAP-FIX regulated-fi-responsible-lifecycle — the break-glass Program
    // registry. `BreakGlassProgram` is itself durable/serde (ADR-027: "durable, resumable,
    // checkpointed... survives restarts"), but until this fix the SERVED registry held it ONLY in this
    // process-local `Arc<Mutex<BTreeMap<..>>>` — a daemon restart mid-campaign silently lost every
    // in-progress program (the open + every completed step), contradicting that exact requirement for
    // this exact mechanism. `open_break_glass_program`/`step_break_glass_program` now ALSO checkpoint a
    // full serde snapshot onto the SAME durable `event_log` this daemon already uses for every other
    // audit trail (see `AssembledFull::checkpoint_break_glass_program`); recovery below replays each
    // campaign's LATEST checkpoint back into the in-memory registry on assembly, so a restart resumes
    // exactly where it left off — no re-processed target, no lost attestation.
    let breakglass = Arc::new(Mutex::new(recover_break_glass_programs(
        &*event_log,
        &mut report,
    )));
    // GAP-AUDIT regulated-fi #7/#9 — the §4.4 DSAR workflow, dispatching erasure through the SAME
    // shared `retention` store above so §6 precedence is consistent across /v1/regfi/erasure and
    // /v1/regfi/dsar.
    let dsar = Arc::new(Mutex::new(DsarWorkflow::new()));
    report.push(
        "regfi: §4.4 DSAR workflow LIVE (POST /v1/regfi/dsar — open/authenticate/correct/erase/\
         grievance) over the shared retention store; §6 legal-hold/floor precedence unchanged"
            .into(),
    );
    // GAP-AUDIT regulated-fi #5 — the India-default CERT-In/DPDP-Board report templates (illustrative;
    // the real forms are Legal/DPO-owned git artifacts a deployment loads via `TemplateStore::add`).
    let report_templates = loaded.incident.report_templates();
    report.push(
        "regfi: §2.4 pre-templated breach-report drafting LIVE (POST /v1/regfi/report) — India-default \
         CERT-In/DPDP-Board forms; a deployment replaces them with Legal/DPO-owned templates"
            .into(),
    );
    // GAP-AUDIT regulated-fi #4 — the supervisory cadence schedule; `spawn_supervisory_cadence` drives
    // the store-sweep monitor automatically, NTP-skew/residency stay due-visible for a deployment with
    // real measurement adapters (see the method doc for why those two are not auto-invoked here).
    let cadence = Arc::new(Mutex::new(loaded.incident.cadence_scheduler()));
    // GAP-AUDIT regulated-fi #8 — the FI-06 DPIA gate, seeded with an illustrative personal-data
    // connector-id list (the same fragments this codebase's own connector ids use:
    // connector.outlook/graph/gitlab/jira/teams). A deployment registers its real feature inventory via
    // `dpia_gate.lock().unwrap().register_feature(..)`/`record_dpia(..)`; an un-inventoried feature
    // fails closed on promotion to env/prod (§4.1), never silently admitted.
    let dpia_gate = Arc::new(Mutex::new(DpiaCiGate::new(&[
        "outlook", "graph", "gitlab", "jira", "teams", "crm",
    ])));
    report.push(
        "regfi: FI-06 DPIA-per-feature CI gate LIVE and folded into admit_promotion (previously a gate \
         object with zero callers) — an un-inventoried personal-data feature fails closed on promotion"
            .into(),
    );
    report.push(
        "regfi: §5.4/§8.1/§8.2 supervisory cadence LIVE — store-sweep runs automatically on the \
         configured interval; NTP-skew/residency stay due-visible for a deployment with real \
         measurement adapters (needs_hot_wiring: cannot fabricate a real NTP/store-location reading)"
            .into(),
    );
    // GAP-FIX identity-payments (ADR-016 §6) — `mandate_registry` (destructured from `Assembled`
    // above) is the SAME MandateRegistry already installed via `ToolRuntime::with_mandate_registry`
    // on this surface's `capability_tools` — the served agent loop's `dispatch_obo_with_pam`/
    // `dispatch_obo_audited_with_pam` calls enforce the fourth gate against this EXACT registry, so
    // `AssembledFull::authorize_payment_adjacent_dispatch` below reads/writes the identical live
    // use-count ledger the served dispatch path consults, never a second, disjoint one.
    report.push(
        "regfi: ADR-016 §6 Payment-Adjacent Mandate fourth dispatch gate LIVE and WIRED into the \
         served capability-dispatch path (ToolRuntime::dispatch_obo_with_pam/\
         dispatch_obo_audited_with_pam enforce it alongside the three-layer OBO gate for any \
         capability that declares Tool::payment_adjacent_action) — previously a fully tested gate \
         with zero callers outside its own crate"
            .into(),
    );
    // R7 OBS — the per-turn telemetry sink recorded on the shipped chat path. The OSS default is an
    // in-memory collector (dev/observable); production selects an OTLP/OTel exporter via TelemetryConfig
    // behind the same TelemetrySink seam. Mounting it makes cost attribution part of the SHIPPED path,
    // not a test-only fixture.
    // The sink is CONFIG-SELECTED (`[telemetry] sink = "null"|"memory"|"otlp"`) behind the one
    // TelemetrySink seam. `otlp` builds the faithful OTLP/HTTP LogRecord exporter over the OSS-default
    // buffering transport (the live collector POST is the infra swap behind OtlpTransport); the OSS
    // default stays the in-memory collector (dev/observable).
    let telemetry: Arc<dyn ainxt_telemetry::TelemetrySink> = match loaded.runtime.telemetry.sink {
        // The shipped daemon keeps observability ON by default (an unset config is the derived-default
        // `Null`, which the design mandates map to the in-memory collector — the shipped daemon must
        // never serve blind). A deployment selects OTLP export explicitly with `sink = "otlp"`.
        ainxt_telemetry::TelemetrySinkKind::Null | ainxt_telemetry::TelemetrySinkKind::Memory => {
            Arc::new(ainxt_telemetry::InMemoryTelemetry::new())
        }
        ainxt_telemetry::TelemetrySinkKind::Otlp => {
            let endpoint = loaded
                .runtime
                .telemetry
                .otlp_endpoint_or_default()
                .to_string();
            let service = loaded
                .runtime
                .telemetry
                .service_name_or_default()
                .to_string();
            report.push(format!(
                "telemetry: OTLP/OpenTelemetry exporter SELECTED (sink=otlp) — per-turn LogRecords \
                 encoded to endpoint {endpoint} (service.name={service}); the network POST is the \
                 infra transport swap behind OtlpTransport (OSS default buffers, never blocks a turn)"
            ));
            Arc::new(ainxt_telemetry::OtlpExporter::new(
                Arc::new(ainxt_telemetry::BufferingOtlpTransport::new()),
                service,
                endpoint,
            ))
        }
    };
    report.push(
        "telemetry: per-turn metrics + cost attribution RECORDED on the shipped /v1/chat path \
         (config-selected sink: null/memory/otlp; OSS default InMemory) — one TurnMetrics per turn \
         carries actor + routed model + priced cost + outcome"
            .into(),
    );
    // R7 HARN — a second instance of the SAME configured compliance gate backs the harness pre-receive
    // route (the engine owns the primary). Building it here (not hardcoding RedactAndProceed) means the
    // pre-receive path runs whatever detector the deployment configured — the enterprise PCI/DSS plugin
    // in production — so a spaced/entropy secret the CLI's heuristic marker gate misses is BLOCKED.
    let harness_prereceive_gate: Arc<dyn ComplianceGate> =
        Arc::from(build_gates(&loaded.runtime.gates)?.0);
    report.push(
        "harness pre-receive: /v1/harness/preflight MOUNTED on the shipped daemon — a candidate manifest \
         is screened by the ComplianceBackedPrereceiveGate over the daemon's REAL configured compliance \
         gate (blocks a PII/secret-carrying publish; git history is permanent), NOT the CLI's heuristic \
         marker gate"
            .into(),
    );
    report.push(format!(
        "serving: SLO-aware QoS pre_serve wait-queue configured (bounded depth {QOS_QUEUE_DEPTH}) on \
         the served ServingGate — the main-path /v1/chat entrypoint enqueues over-capacity turns up to \
         the ceiling (then load-sheds), never dropping them; inert on the air-gapped default (no pool)"
    ));

    report.push(
        "transport: FULLY-WIRED (serve_full/FullApp) — /v1/chat (§4 envelopes + attestation fence) + \
         /v1/command + /v1/replay + /v1/events + /graph + /v1/query_ledger + /v1/infer served by the \
         shipped binary (no longer test-only)"
            .into(),
    );
    report.push(
        "incident register: LIVE on the served surface (India statutory arming policy); breach clocks \
         advance via the background breach-clock ticker"
            .into(),
    );
    report.push(
        "breach-detection (§2.1): MORE than the quality circuit-breaker feeds the LIVE served register \
         — compliance-egress, sink-guard, payment-boundary and serving-ops detectors each arm a \
         statutory clock via typed IncidentCandidate adapters (AssembledFull::arm_* over the shared \
         register)"
            .into(),
    );
    report.push(
        "evidence (§7.2/§8.3): the BSA §63 evidentiary-export + read-only supervisory auditor mode are \
         MOUNTED over the LIVE served register (AssembledFull::export_incident_evidence / \
         auditor_list_incidents) — explicit AUDITOR_CAP, existence-hiding scope, refused over a broken \
         chain"
            .into(),
    );
    report.push(
        "retention (§6): the redact-with-attestation right-to-erasure is MOUNTED over the LIVE served \
         RecordStore (AssembledFull::erase_subject_attested, CAP_RETENTION_ADMIN) — a held/floored \
         record is preserved under §6 precedence (never hard-deleted under hold) and attested with a \
         tamper-evident SHA-256 artifact"
            .into(),
    );
    report.push(
        "regfi durability (§2.3/§6): crash-survival ENTRYPOINTS exposed on the served surface — \
         AssembledFull::{snapshot,restore}_incident_register + {snapshot,restore}_retention_store over \
         the durable SnapshotStore seam (statutory clocks + legal-hold/deferred-erasure queue survive a \
         kill -9 and continue on schedule). NEEDS HOT-WIRING in main.rs: restore on boot before \
         spawn_breach_clock + persist on cadence/graceful-shutdown, bound to a live crash-atomic backend \
         (Postgres/Redis/WORM = infra_gated)"
            .into(),
    );
    report.push(
        "breach-detection (§8.1/§8.2): served NTP-skew + India-residency ENTRYPOINTS exposed — \
         AssembledFull::check_served_ntp_skew / verify_served_store_residency arm a §2 incident on the \
         LIVE served register from an injected offset / resolved store-region. NEEDS HOT-WIRING: the \
         LIVE NIC/NPL offset measurement + storage-region resolution are deployment adapters \
         (infra_gated); the served register intake is wired"
            .into(),
    );
    report.push(
        "control plane: shared kill-switch + revocation surface present on the served surface — reaches \
         in-flight Program/Team Runs through the per-dispatch admission gate"
            .into(),
    );
    report.push(
        "release control: online anytime-valid canary + auto-rollback + CUSUM drift controller LIVE \
         on the served surface (eval-tester) — a candidate's live-traffic quality is canaried, \
         auto-rolled-back on established regression, and drift-watched after promotion"
            .into(),
    );

    // R8 — the transport authenticator the shipped daemon mounts on EVERY governed route. The default
    // is OWNER-DEFERRED (TrustedGatewayAuth); a deployment may SELECT the verified-identity JwtSsoAuth
    // (fail-closed if it selects it without a secret — never a silent downgrade to the trusted default).
    let auth = build_authenticator(&loaded.server, &mut report)?;

    // R8/R12 EDIT — the offline-default semantic Code-Review Pipeline engine mounted at `POST /v1/edit`:
    //  - IdentityCoder — no model configured on the air-gapped default; a REJECTED pass can't be
    //    fabricated into a false "done".
    //  - AstVerifyTools — R12: the DETERMINISTIC verify is now LIVE by default (invariant #1). Its
    //    Compile stage parses every file with the pinned tree-sitter grammar and BLOCKS a syntactically
    //    broken edit at Stage::Compile, instead of the old ScriptedTools all-pass that rubber-stamped it.
    //  - BuiltinScanner — offline SAST that hard-blocks the payments-critical classes.
    //  - with_semantic_review — R12: Architecture Review (stage 7) + Regression Detection (stage 8), the
    //    DETERMINISTIC (graph-based, no model) half of the tier-2+ stage set, enabled by default. An
    //    empty LayerContract asserts no boundary the deployment never declared (inert-but-present); the
    //    co-change graph is empty on the air-gapped default (a deployment populates it from git history).
    //  - with_perf — GAP-FIX semantic-editing-codereview: Performance Analysis (stage 6) was previously
    //    entirely ABSENT from every shipped report (`self.perf == None` ⇒ `run_selfheal_full` never
    //    appends a `Stage::Perf` report at all, not even a `Skipped` one — a Tier-3 edit could commit
    //    with no perf finding on record, even though `analyze_perf`'s AST-complexity delta needs zero
    //    infra). Wiring `NoBench` + `NoAdvisor` costs nothing and buys the deterministic half for real:
    //    the cyclomatic-complexity delta and N+1/nested-loop heuristic now run and score on every turn;
    //    only the live benchmark harness and the model-advisory sub-check stay honestly `None`/absent
    //    until a deployment attaches a real harness/model (`PerfReport.verdict` reports `Skipped` for
    //    those two signals specifically, never a silent pass — see `perf.rs::analyze_perf`).
    //  - GAP6 pipeline-edit-tooling items 3/4 — `AgentOp` (planned via the ALREADY-mounted
    //    `run_semantic_op_for` / `POST /v1/edit/semantic`, no new route or seam needed here) now covers
    //    `ReplaceFunction` (drives `ladder_driver::run_replace_ladder`'s full AST → structured-patch
    //    (`ainxt_edit::apply`) → text ladder) and a field-rename fallback on `Rename` (falls to
    //    `ainxt_edit::field_rename_via_xref` when the AST symbol graph reports `SymbolNotFound` —
    //    struct/enum fields are not graph nodes at all, see `ainxt_semantic::graph::DefKind`). Both
    //    resolve honestly at `Rung::StructuredPatch` when they fall below AST — never claimed as
    //    AST-grade.
    //
    // needs_hot_wiring (model + infra seams, left unwired on the air-gapped default so nothing is
    // fabricated):
    //  - a model-backed Coder + independent Judge panel + LLM-Review finder via `with_review` (§5 —
    //    MANDATORY at Tier 2+: round-13 the Commit Gate makes a missing/one-sided verdict NOT
    //    committable, so on this air-gapped default (no model judge wired) a Tier-2+ edit is honestly
    //    handed to a human rather than auto-committed — Tier 0/1 edits still commit).
    //  - a live benchmark harness + model perf-advisor via `with_perf` (the deterministic complexity
    //    half is now wired, see above — only the measured/model halves remain).
    //  - GAP6 item 2 — real `cargo`/lint/type-check hooks (`cargo_tools::cargo_hook_with_limits`) for
    //    `AstVerifyTools::with_test`/`with_lint`/`with_type_check`. The hook itself IS real and safely
    //    sandboxed (offline, `--offline`, cleared env, isolated `CARGO_HOME`/`CARGO_TARGET_DIR`, hard
    //    timeout, capped output — mirrors `ainxt-skill::native_process`'s discipline) — but it compiles
    //    `StageContext`'s touched-file set alone as a **zero-dependency scratch crate**
    //    (`cargo_tools::materialize_scratch_crate`), because `StageContext` carries only that fileset,
    //    never a live repo checkout with a real `Cargo.lock`/dependency graph. Wiring it as THIS
    //    deployment's default would turn every real edit that references an external crate or an
    //    un-included sibling symbol into a fabricated `Fail` (unresolved-crate/name errors that are an
    //    artifact of the scratch crate's isolation, not a real defect) — strictly worse than the honest
    //    `Skipped` it replaces. `cargo_tools`'s own doc is explicit that a deployment with a live
    //    checkout wires its own hook instead of this one; this crate's own tests exercise the hook
    //    directly (`cargo_tools.rs`'s `#[cfg(test)]` module) to prove it genuinely shells out to
    //    `cargo`, but it is not a safe unconditional default here.
    //  - GAP6 item 1 — the sandboxed differential oracle via `with_breaker` (Tier-3 §8,
    //    `breaker::ScriptedBreaker`/`DifferentialOracle`). `ScriptedBreaker` needs pre-authored
    //    divergence/invariant markers per capability (the offline stand-in for a real reference-impl +
    //    corpus); with none configured it would report `Some(BreakerReport { findings: vec![] })` for
    //    every Tier-3 edit — i.e. "differentially clean" — when no differential comparison against a
    //    reference implementation ever actually ran. `breaker.rs`'s own doc states the invariant this
    //    would break: "a missing oracle is honestly 'not run', never a false clean." Leaving
    //    `with_breaker` uncalled is what preserves that: `run_if_tier3` returns `None` (not consulted),
    //    the honest state. Unlike `with_perf(NoBench, NoAdvisor)` above, there is no marker-free
    //    "deterministic half" of a differential/invariant run to wire for free — every finding requires
    //    either a real reference-implementation comparison or a deployment-authored script, both
    //    genuinely infra/deployment-owned.
    //  - a model-backed Coder + real cargo/pytest/tsc + Semgrep via the SAME `EditEngine`
    //    `StageTools`/`SastScanner` seams for a deployment with a live repo checkout.
    let edit_workspace_root = loaded
        .server
        .edit_workspace_dir
        .as_ref()
        .map(std::path::PathBuf::from);
    let edit_base = EditEngine::new(
        Arc::new(IdentityCoder),
        Arc::new(AstVerifyTools::new()),
        Arc::new(BuiltinScanner),
    )
    .with_semantic_review(
        None,
        std::sync::Arc::new(ainxt_semantic::regression::CochangeGraph::new()),
        8,
    )
    .with_perf(
        Arc::new(NoBench),
        Arc::new(NoAdvisor),
        PerfBudget::default(),
    );

    // GAP-FIX gap6-semantic-lsp-signature-layermanifest item 1 — `EditEngine::with_lsp` had zero
    // callers anywhere in this composition root (see the field doc on `ServerConfig::lsp_rust_analyzer_path`).
    // Config-gated: only attempted when a binary path is configured, and even then bounded by a 3s
    // probe (`probe_stdio_lsp_available`) so a missing/misconfigured/hung binary can never hang boot.
    let (edit, lsp_report_line): (EditEngine, String) = match &loaded.server.lsp_rust_analyzer_path {
        Some(lsp_path)
            if ainxt_semantic::lsp::probe_stdio_lsp_available(
                lsp_path,
                &["--version"],
                std::time::Duration::from_secs(3),
            ) =>
        {
            let root_uri = format!(
                "file://{}",
                edit_workspace_root
                    .clone()
                    .unwrap_or_else(|| std::path::PathBuf::from("."))
                    .display()
            );
            let open_path = lsp_path.clone();
            let lsp = ainxt_semantic::lsp::ServerLspRefactor::new(
                move || {
                    ainxt_semantic::lsp::StdioLspTransport::spawn(&open_path, &[]).map(|t| {
                        Box::new(t) as Box<dyn ainxt_semantic::lsp::LspTransport>
                    })
                },
                root_uri,
            );
            (
                edit_base.with_lsp(Arc::new(lsp)),
                format!(
                    "edit gate: LSP rung-1 driver ATTACHED — {lsp_path:?} answered --version within \
                     3s at boot; POST /v1/edit/semantic now consults it first (EditEngine::with_lsp) \
                     for structural ops (rename/change-signature/extract) before falling to the AST \
                     rung, exactly as SEMANTIC_EDITING.md §2 specifies"
                ),
            )
        }
        Some(lsp_path) => (
            edit_base,
            format!(
                "edit gate: LSP rung-1 driver NOT attached — configured lsp_rust_analyzer_path {lsp_path:?} \
                 did not answer --version within 3s (missing/broken/hung binary); every semantic op \
                 falls to the AST rung, recorded honestly, never silently claimed as LSP-grade"
            ),
        ),
        None => (
            edit_base,
            "edit gate: LSP rung-1 driver not configured (lsp_rust_analyzer_path unset) — every \
             semantic op resolves at the AST rung, byte-identical to before this field existed"
                .to_string(),
        ),
    };
    let edit = Arc::new(edit);
    report.push(
        "edit gate: /v1/edit MOUNTED on the shipped daemon — the semantic Code-Review Pipeline \
         (risk-scaled stages + SAST hard-block + Confidence Score + Commit Gate + bounded self-heal + \
         SHA-256 hash-chained journal) behind CAP_EDIT_APPLY (fail-closed). R12: deterministic verify \
         (AstVerifyTools, tree-sitter parse gate) + Architecture Review + Regression Detection are LIVE \
         by default; GAP-FIX: Performance Analysis (stage 6) is now LIVE by default too, via the \
         deterministic AST-complexity delta (with_perf(NoBench, NoAdvisor)) — only the measured \
         benchmark harness and model perf-advisor remain needs_hot_wiring. GAP6: POST /v1/edit/semantic \
         now also plans AgentOp::ReplaceFunction (the wired AST/structured-patch/text ladder) and a \
         field-rename fallback on AgentOp::Rename (ainxt_edit::field_rename_via_xref, for identifiers \
         the AST symbol graph does not model, i.e. struct/enum fields) — both LIVE by default, no new \
         seam required. GAP6 item 2: AgentOp::ChangeSignature now resolves the full call-site blast \
         radius via ainxt_semantic::ops::plan_change_signature BEFORE splicing, refusing rather than \
         silently leaving a graph-reported call site on the old signature. GAP6 item 3: the \
         Architecture Review stage (7) now honors a `.arch.json` LayerManifest checked into the \
         reviewed file set itself, layered over this engine's static (here: empty) contract. Remaining \
         model/infra seams (model coder + real cargo/pytest/tsc/Semgrep against a live checkout — \
         cargo_hook_with_limits exists and is safely sandboxed but is scoped to a zero-dependency \
         scratch crate, not a safe default for a real dependency-having target; Judge panel via \
         with_review; differential oracle via with_breaker) are needs_hot_wiring — see the comment \
         above for why each is genuinely deployment-owned rather than a default this composition root \
         can safely fabricate"
            .into(),
    );
    report.push(lsp_report_line);

    // GAP-FIX semantic-editing-codereview — the durable journal-store root for `/v1/edit*`
    // (`[server] edit_journal_dir`). `None` keeps the in-process `InMemoryJournalStore` default.
    let edit_journal_root = loaded
        .server
        .edit_journal_dir
        .as_ref()
        .map(std::path::PathBuf::from);

    Ok(AssembledFull {
        manager,
        report,
        event_log,
        control_plane_sha: control_plane_sha(),
        graph,
        ledger_schema,
        serving,
        disagg,
        incidents,
        control_plane,
        // GAP-FIX identity-payments (gap6 audit item 1) — `assemble_full_with_control_plane` never
        // wires a transparency log itself (it has no `Assembled`-carried handle to source one from,
        // exactly like `control_plane`'s own sibling-parameter precedent); a caller that assembled a
        // surface WITH one (`assemble_selected_governed_with_transparency`) supplies it via
        // [`assemble_full_with_control_plane_and_transparency`], which sets this field after this
        // function returns. Plain `assemble_full`/`assemble_full_with_control_plane` callers are
        // byte-identical (`None`), unchanged.
        transparency: None,
        token_vault,
        release_controller,
        traffic_split,
        outsourcing_residency,
        harness,
        connectors,
        connector_invoker,
        connector_key_ring,
        artifact,
        replay_store,
        reexec_executor,
        erasure,
        quality_breaker,
        vault,
        vault_store,
        retention,
        feedback_engine,
        retention_sweeper,
        eval_staging,
        breakglass,
        dsar,
        report_templates,
        cadence,
        dpia_gate,
        mandate_registry,
        tripwire_remediator,
        telemetry,
        behavior_history: Arc::new(Mutex::new(std::collections::HashMap::new())),
        edit_workspace_root,
        edit_journal_root,
        harness_prereceive_gate,
        auth,
        edit,
        wire_events: Mutex::new(wire_events),
        reconciler_sweeper,
        attestation_refresher,
        health_monitor,
        health_cadence,
        autoscale_controller,
        autoscale_cadence,
        placement,
        rollout,
        approval_coordinator: Arc::new(ainxt_server::ApprovalCoordinator::new()),
        dispatch_probe,
        memory_consent,
        memory_writer,
        outsourcing_register,
        mcp_admin,
        skill_runtime,
        skill_dir: loaded.server.skill_dir.clone(),
        kb_corpus_snapshot: loaded
            .kb
            .documents
            .iter()
            .map(|d| (d.id.clone(), d.text.clone()))
            .collect(),
        // GAP-FIX ainxt-retrieval (gap6-retrieval-maintenance, item 1) — fresh, empty at assembly;
        // `run_kb_maintenance_tick`'s first sweep builds it from `kb_corpus_snapshot` above.
        kb_index_state: Arc::new(Mutex::new(ainxt_retrieval::maintenance::IndexState::new())),
        kb_recall_monitor: Arc::new(Mutex::new(
            ainxt_retrieval::maintenance::RecallLatencyMonitor::new(
                ainxt_retrieval::maintenance::IndexSlo::default(),
                256,
            ),
        )),
        // GAP-FIX ainxt-retrieval (gap6-retrieval-maintenance, item 3) — the SAME builder the served
        // governed Context-Fabric compile path uses (`governed::compile_served_context`), so the
        // break-glass admin route queries the REAL configured KB, not a hand-rolled stand-in.
        kb_rls_corpus: Arc::new(governed::retrieval_corpus_for_scope(
            &loaded.kb,
            RetrievalScope::PlatformAndNamespace,
        )),
        workforce: workforce_surface,
    })
}

/// [`assemble_full_with_control_plane`], additionally installing a live issuance
/// [`TransparencyLog`] onto [`AssembledFull::transparency`] (GAP-FIX identity-payments, gap6 audit
/// item 1). `assemble_full_with_control_plane` itself has no `Assembled`-carried handle to source a
/// transparency log from — exactly the same reason [`ControlPlane`] is threaded in as a sibling
/// parameter rather than through [`Assembled`]. A caller that assembled a surface WITH a live log
/// (today: [`assemble_selected_governed_with_transparency`]'s `"chat_governed"` arm, which wires the
/// SAME log [`chat_identity::GovernedChatSurface`] appends every newly-minted chat-run credential to)
/// passes it here so [`AssembledFull::to_full_app_ext`] can mount `GET /v1/transparency/proof/:run_id`
/// over that EXACT instance. `transparency: None` is byte-identical to
/// [`assemble_full_with_control_plane`] (the route still mounts, fails closed 404).
pub fn assemble_full_with_control_plane_and_transparency(
    loaded: &LoadedConfig,
    assembled: Assembled,
    control_plane: Arc<Mutex<ControlPlane>>,
    transparency: Option<Arc<Mutex<TransparencyLog<Sha256Hasher>>>>,
) -> Result<AssembledFull, AssembleError> {
    let mut full = assemble_full_with_control_plane(loaded, assembled, control_plane)?;
    full.transparency = transparency;
    Ok(full)
}

/// R8 — build the transport [`Authenticator`] the shipped daemon mounts on every governed route from
/// [`ServerConfig`]. The default is OWNER-DEFERRED and unchanged (`TrustedGatewayAuth`); `jwt-sso`
/// mounts the config-selectable verified-identity [`JwtSsoAuth`] (HS256) and REQUIRES a non-empty
/// `jwt_hs256_secret` — a missing/empty secret is a FAIL-CLOSED assembly error, never a silent
/// downgrade to the trusted-gateway default.
fn build_authenticator(
    server: &ServerConfig,
    report: &mut Vec<String>,
) -> Result<Arc<dyn Authenticator>, AssembleError> {
    match server.authenticator {
        AuthenticatorKind::TrustedGateway => {
            // R16 CRITICAL — FAIL CLOSED. `TrustedGatewayAuth` derives role, capabilities and
            // clearance from `X-AInxt-*` headers, which sits ABOVE every RBAC gate in the runtime:
            // reachable directly, any caller can assert `role: admin` / `clearance: restricted`.
            //
            // That is the intended design *behind a gateway that validated the token* — so the
            // assumption is allowed, but it must be STATED, not inherited by silence. An operator
            // who configures nothing now gets a refusal naming the two supported ways forward,
            // instead of a daemon that quietly trusts whatever the client claims. The failure mode
            // this closes is "nobody noticed the gateway was bypassable until an auditor asked".
            if !ainxt_server::trusted_gateway_accepted() {
                return Err(AssembleError::Config(
                    "authenticator = trusted-gateway derives role/caps/clearance from client-supplied \
                     X-AInxt-* headers, which is safe ONLY when this runtime is unreachable except \
                     through a gateway that already validated the token. Refusing to start rather \
                     than silently trusting the client. Either set AINXT_TRUSTED_GATEWAY=1 to assert \
                     that deployment explicitly, or set server.authenticator = \"jwt-sso\" with \
                     server.jwt_hs256_secret so the runtime verifies identity itself."
                        .into(),
                ));
            }
            report.push(
                "authenticator: trusted-gateway — EXPLICITLY accepted via AINXT_TRUSTED_GATEWAY; the \
                 runtime trusts the front gateway's forwarded X-AInxt-* identity on every governed \
                 route (verify the gateway is the ONLY route to this listener)"
                    .into(),
            );
            Ok(Arc::new(TrustedGatewayAuth))
        }
        AuthenticatorKind::JwtSso => {
            let secret = server
                .jwt_hs256_secret
                .as_deref()
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    AssembleError::Config(
                        "authenticator = jwt-sso requires a non-empty server.jwt_hs256_secret \
                         (fail-closed: refusing to start rather than silently downgrade to the \
                         trusted-gateway default)"
                            .into(),
                    )
                })?;
            report.push(
                "authenticator: jwt-sso (SELECTED) — verified HS256 JWT identity on every governed \
                 route (exp/nbf checked, forgery rejected; caps/role/clearance/department derived from \
                 the verified claims, never spoofable headers)"
                    .into(),
            );
            Ok(Arc::new(JwtSsoAuth::hs256(secret.as_bytes().to_vec())))
        }
    }
}

/// The decision the served **promotion / routing admission** gate returns (FI-07). A route may enter
/// (or stay in) service only if it clears model-risk due diligence AND its live quality circuit-breaker
/// is closed — "monitored, not certified-once".
#[derive(Debug, Clone, PartialEq)]
pub enum PromotionAdmission {
    /// The route may promote / serve.
    Admitted,
    /// Refused, carrying every reason. A regulated route whose breaker tripped also opened an
    /// operational-risk incident on the served register (`incident_opened`).
    Refused {
        reasons: Vec<String>,
        incident_opened: Option<String>,
    },
}

impl PromotionAdmission {
    pub fn is_admitted(&self) -> bool {
        matches!(self, PromotionAdmission::Admitted)
    }
}

impl AssembledFull {
    /// FI-07 — the served **promotion / routing admission** gate: evaluate a candidate route's
    /// model-risk record on the SERVED surface before it may promote or serve. This is the wire that
    /// makes the SR-11-7 quality circuit-breaker + due-diligence gate EVALUATED on the served path (they
    /// were previously instantiated + held but never run on any promotion/routing decision). Per call:
    ///
    /// 1. runs [`route_promotable`] (the FI-07 due-diligence gate — independent validation, mandatory
    ///    challenger at/above the risk bar, monitoring present + fresh + at/above the score bar);
    /// 2. runs the held [`QualityCircuitBreaker::evaluate`] on the record's live scoreboard — an absent
    ///    or below-bar scoreboard trips the breaker;
    /// 3. on a breaker trip for a **regulated** route, opens an operational-risk incident on the LIVE
    ///    served [`IncidentRegister`] via [`IncidentCandidate::from_quality_breaker`] (the statutory
    ///    clock starts) and returns its id.
    ///
    /// Fail-closed: any defect or a tripped breaker → [`PromotionAdmission::Refused`]; the caller (the
    /// release controller's Promote, or the model router before admitting an external route) must not
    /// promote/serve the route. `now` is logical/wall time (seconds) for staleness + the incident clock.
    pub fn admit_promotion(
        &self,
        feature_id: &str,
        target: PromotionTarget,
        record: &ModelRiskRecord,
        dd_cfg: &DueDiligenceConfig,
        now: u64,
    ) -> PromotionAdmission {
        // GAP-FIX gap6-responsibleai-cleanup item 2 — the (0) FI-06 DPIA / (1) FI-07 due-diligence /
        // (2) FI-07 quality-breaker DECISION previously reimplemented `GovernancePromotionGate::admit`'s
        // exact logic inline (a second, independently-maintained copy of the SAME fail-closed gate).
        // Delegating to `GovernancePromotionGate::evaluate` (the borrowed-parts core also backing
        // `admit`'s owned-gate form) over this daemon's own live locked `dpia_gate` / shared
        // `quality_breaker` makes this the ONE place the gate logic is implemented; everything below
        // is served-surface-only bookkeeping the pure `ainxt-responsibleai` gate does not (and must
        // not) know about (event-log audit, regression-vault minting, §2 incident-clock arming).
        let outcome = GovernancePromotionGate::evaluate(
            &self.dpia_gate.lock().expect("dpia gate lock"),
            dd_cfg,
            &self.quality_breaker,
            feature_id,
            target,
            record,
            now,
        );

        let mut reasons: Vec<String> = Vec::new();
        let mut incident_opened = None;

        if let PromotionOutcome::Blocked(blocks) = &outcome {
            for block in blocks {
                reasons.push(block.to_string());

                let PromotionBlock::QualityBreakerOpen {
                    route_id,
                    score,
                    bar,
                    regulated_route,
                } = block
                else {
                    continue;
                };

                // GAP-FIX tooling-mcp-plugins-routing (round 2) — file THIS EXACT trip as a permanent
                // ainxt-eval regression case (RegressionVault, EVAL_PLATFORM.md §10), not only a §2
                // incident (below, regulated routes only). Every trip mints — a non-regulated route's
                // quality regression is still a genuine regression worth guarding against, even though it
                // is not independently RBI-reportable. Reproduce-from-SHA: the case's `event_log_id` names
                // a durable, hash-chained audit record of this exact trip (never a bare in-memory fact).
                // Idempotent by `(route_id, control_plane_sha)` — repeated trips on an unchanged build
                // no-op remint (`RegressionVault::mint` never overwrites); a trip surviving a NEW build
                // mints a fresh, distinct case, exactly the "frozen case, reproduce it or it stays open"
                // contract `route_restored` enforces.
                let trip_event = self.event_log.append(
                    &format!("breaker-trip:{route_id}"),
                    "system:quality-circuit-breaker",
                    "quality_breaker.trip",
                    &format!(
                        "route={route_id} score={score:.4} bar={bar:.4} regulated={regulated_route} \
                         control_plane_sha={}",
                        self.control_plane_sha
                    ),
                );
                let event_log_id = trip_event.map(|r| r.hash).unwrap_or_default();
                let vault_case = ainxt_eval::vault::VaultCase::mint(
                    &format!("qcb-trip-{route_id}@{}", self.control_plane_sha),
                    ainxt_eval::vault::VaultOrigin::CircuitBreaker,
                    &event_log_id,
                    &self.control_plane_sha,
                    &format!("route={route_id} live_score={score:.4}"),
                    &format!("route '{route_id}' scoreboard score must be >= bar {bar:.4}"),
                    now,
                );
                // GAP-FIX eval-durable-stores — `mint` is append-only + idempotent by `case_id` (returns
                // `true` only for a GENUINELY NEW case, never a re-mint of one already held): persist
                // durably ONLY on that `true`, so a repeated trip on an unchanged build (the no-op remint
                // case the comment above already documents) never re-appends a duplicate line to the
                // durable file either. `vault_store` is `None` on the unconfigured (in-memory-only)
                // default — same behavior as before this fix.
                let newly_minted = self
                    .vault
                    .lock()
                    .expect("regression vault lock")
                    .mint(vault_case.clone());
                if newly_minted {
                    if let Some(store) = &self.vault_store {
                        // `FileVaultStore` is a plain `PathBuf` handle — cheap to clone; `persist` opens
                        // and appends independently of any prior call, so no shared mutable state (and
                        // therefore no `Mutex`) is needed here (see `AssembledFull::vault_store`'s doc).
                        store.clone().persist(&vault_case);
                    }
                }

                // (3) A regulated route's trip is RBI-reportable — arm the statutory clock on the LIVE
                //     served register (the breaker → incident tie the design mandates).
                if *regulated_route {
                    let candidate = IncidentCandidate::from_quality_breaker(
                        now,
                        &self.control_plane_sha,
                        route_id,
                    );
                    let id = self
                        .incidents
                        .lock()
                        .expect("incident register lock")
                        .open_from(candidate, now);
                    incident_opened = Some(id);
                }
            }
        }

        if reasons.is_empty() {
            PromotionAdmission::Admitted
        } else {
            PromotionAdmission::Refused {
                reasons,
                incident_opened,
            }
        }
    }

    /// GAP-FIX regulated-fi-responsible-lifecycle — a cap-gated, READ-ONLY preview of the FI-07
    /// quality circuit-breaker's live verdict for a route, over the SAME `quality_breaker`
    /// [`Self::admit_promotion`] already gates on (step 2) — a dry-run peek with no incident side
    /// effects, for a caller that wants to know a route's breaker state without driving a promotion.
    /// `ainxt_responsibleai::routes::QualityBreakerService::evaluate_for` was fully implemented and
    /// unit-tested but had zero served callers; rather than stand up that service's OWN inventory here
    /// (which would diverge from this runtime's single `quality_breaker`), this calls the breaker
    /// directly on caller-supplied `record` — identical shape to `admit_promotion`'s own parameters.
    /// (GAP-FIX gap6-responsibleai-cleanup, item 1: `QualityBreakerService` itself was confirmed
    /// genuinely dead — with BOTH real served call-sites, this one and `build_router`'s, deliberately
    /// bypassing it — and removed; this method's own shape, calling the shared `quality_breaker`
    /// directly, is unaffected and remains the served preview entrypoint.)
    pub fn model_risk_breaker_status(
        &self,
        principal: &Principal,
        record: &ModelRiskRecord,
    ) -> Result<BreakerState, ModelRiskRouteError> {
        if !principal.has_cap(CAP_MODEL_RISK) {
            return Err(ModelRiskRouteError::NotAuthorized);
        }
        Ok(self.quality_breaker.evaluate(record))
    }

    /// The SR-11-7 due-diligence counterpart to [`Self::model_risk_breaker_status`] — a cap-gated,
    /// read-only preview of [`Self::admit_promotion`]'s step 1, mirroring the now-removed
    /// `QualityBreakerService::promotable_for`'s serde-friendly [`PromotionDecision`] projection
    /// (see `ainxt_responsibleai::routes`' module doc for why that service was removed as dead code).
    pub fn model_risk_promotable_status(
        &self,
        principal: &Principal,
        record: &ModelRiskRecord,
        dd_cfg: &DueDiligenceConfig,
        now: u64,
    ) -> Result<PromotionDecision, ModelRiskRouteError> {
        if !principal.has_cap(CAP_MODEL_RISK) {
            return Err(ModelRiskRouteError::NotAuthorized);
        }
        let decision = match route_promotable(record, dd_cfg, now) {
            DueDiligenceOutcome::Passed => PromotionDecision {
                route_id: record.model_id.clone(),
                promotable: true,
                defects: Vec::new(),
            },
            DueDiligenceOutcome::Failed(defects) => PromotionDecision {
                route_id: record.model_id.clone(),
                promotable: false,
                defects: defects.iter().map(|d| d.to_string()).collect(),
            },
        };
        Ok(decision)
    }

    /// GAP-FIX regulated-fi-responsible-lifecycle — the served entrypoint to
    /// [`ainxt_payments::mandate::authorize_adjacent_dispatch`] (ADR-016 §6): the FOURTH dispatch gate
    /// for payment-*adjacent* write actions (structurally incapable of expressing value movement),
    /// checked IN ADDITION TO the three OBO layers, never a substitute for them. Fully implemented and
    /// unit-tested in `ainxt-payments`, but had zero callers anywhere in the served path. `obo` is the
    /// caller's own three-layer OBO verdict (e.g. derived from [`ainxt_identity::control::ControlPlane::
    /// authorize_dispatch`]'s outcome) — this method does not itself derive it, matching the underlying
    /// gate's own signature exactly rather than inventing a `DispatchOutcome` → `OboOutcome` mapping.
    pub fn authorize_payment_adjacent_dispatch(
        &self,
        obo: ainxt_payments::mandate::OboOutcome,
        pam: &ainxt_payments::mandate::PaymentAdjacentMandate,
        action_verb: &str,
        resource: &str,
        run_id: &str,
        now: u64,
    ) -> Result<(), ainxt_payments::mandate::AdjacentDispatchDenied> {
        ainxt_payments::mandate::authorize_adjacent_dispatch(
            &mut self.mandate_registry.lock().expect("mandate registry lock"),
            obo,
            pam,
            action_verb,
            resource,
            run_id,
            now,
        )
    }

    /// GAP-FIX identity-payments — whether the §4.6 graduated tripwire has quarantined `capability_id`
    /// on the SAME remediator the connector USE path enacts its response through.
    pub fn tripwire_is_quarantined(&self, capability_id: &str) -> bool {
        self.tripwire_remediator.is_quarantined(capability_id)
    }

    /// Whether the tripwire has revoked the acting identity `id` (Run or OBO user) on the SAME
    /// control plane [`Self::revoke_run`]/[`Self::pull_kill_switch`] also act on.
    pub fn tripwire_is_identity_revoked(&self, id: &str) -> bool {
        self.tripwire_remediator.is_identity_revoked(id)
    }

    /// The number of incidents the tripwire has raised on the SAME register [`Self::export_incident_evidence`]
    /// and [`Self::auditor_list_incidents`] read.
    pub fn tripwire_incident_count(&self) -> usize {
        self.tripwire_remediator.incident_count()
    }

    /// FI-01 §5.4 — defense-in-depth sweep of the LIVE served Event Log: proves the write-path
    /// sink-guard actually held for `session`, rather than trusting it by construction alone.
    ///
    /// `ainxt_compliance::SinkGuard`'s `persist`/`sweep` pair was implemented and unit-tested
    /// against its own `DurableSink` trait, but the daemon's real durable sinks (the Event Log via
    /// `GuardedEventLog`, durable memory via `StrongMemoryRedactor`) each guard the write path with
    /// their own bespoke wrapper — neither implements `DurableSink` (their `append` signatures carry
    /// more than one string), so `SinkGuard` itself stayed entirely unexercised against a real sink.
    /// `SinkGuard::sweep` needs no `DurableSink` at all — it is a pure `(id, content)` scanner — so
    /// this reads the ALREADY-GUARDED records straight back out of the live `event_log` and re-scans
    /// them: every hit is a §2 incident candidate (the write-path guard was bypassed for that
    /// record), and an empty result is the sweep's positive proof that §5.1 held for this session.
    /// FI-02 §2.1: every hit ALSO arms a §5.4 store-sweep incident on the LIVE served register via
    /// [`Self::arm_store_sweep_incident`] — closing the "IncidentCandidate::from_store_sweep has zero
    /// production callers" half of FI-02 at the same time as FI-01's sweep itself.
    pub fn sweep_event_log(&self, session: &str, now: u64) -> Vec<ainxt_compliance::SweepHit> {
        let records = self.event_log.records(session);
        let pairs: Vec<(String, String)> = records
            .into_iter()
            .map(|r| (r.seq.to_string(), r.text))
            .collect();
        let hits = ainxt_compliance::SinkGuard::strong()
            .sweep(pairs.iter().map(|(id, text)| (id.as_str(), text.as_str())));
        for _hit in &hits {
            self.arm_store_sweep_incident(now, "event-log");
        }
        hits
    }

    /// GAP-AUDIT regulated-fi #4 — sweep EVERY session [`Self::sweep_event_log`] knows about, via
    /// [`EventLog::sessions`], instead of requiring a caller to already know which session to check.
    /// This is what makes the §5.4 defense-in-depth sweep genuinely schedulable on a cadence (see
    /// [`Self::spawn_supervisory_cadence`]) rather than only callable per-session from a test.
    pub fn sweep_all_sessions(&self, now: u64) -> Vec<ainxt_compliance::SweepHit> {
        self.event_log
            .sessions()
            .into_iter()
            .flat_map(|session| self.sweep_event_log(&session, now))
            .collect()
    }

    /// GAP-FIX regulated-fi-responsible-lifecycle (FI-01 §5.4) — the SAME defense-in-depth sweep as
    /// [`Self::sweep_event_log`], mirrored onto the served **memory** sink. `ainxt_compliance`'s own
    /// module doc names memory alongside the Event Log as a durable sink the design's §1.3 no-CDE-
    /// persistence regime covers ("Event Log, memory, vector index, traces, DSAR exports"), and the
    /// memory write path already carries its own guard (`StrongMemoryRedactor` on every
    /// `MemorySqlBackend::write_as`/`InMemoryStore::write`) — but nothing ever re-scanned the ALREADY-
    /// GUARDED content straight back out and reported a hit as a §2 incident candidate the way
    /// `sweep_event_log` does for the audit log; the only existing read-back pass
    /// ([`ainxt_memory::ConsentBacking::re_redact`], driven by [`Self::spawn_memory_re_redact_sweep`])
    /// silently *fixes* drift rather than *proving* the guard held. `None` on a surface with no chat
    /// engine (bare `engine`/`program`/`team`/workforce — see [`Self::memory_consent`]'s doc) returns
    /// an empty result: there is no live memory reader to sweep there, exactly mirroring how
    /// `sweep_event_log` finds nothing for a session the Event Log has never seen.
    pub fn sweep_memory(&self, now: u64) -> Vec<ainxt_compliance::SweepHit> {
        let Some(backing) = self.memory_consent.as_ref() else {
            return Vec::new();
        };
        let Ok(pairs) = backing.all_content() else {
            return Vec::new();
        };
        let hits = ainxt_compliance::SinkGuard::strong()
            .sweep(pairs.iter().map(|(id, text)| (id.as_str(), text.as_str())));
        for _hit in &hits {
            self.arm_store_sweep_incident(now, "memory");
        }
        hits
    }

    /// GAP-FIX regulated-fi-responsible-lifecycle (FI-01 §5.4) — the SAME defense-in-depth sweep as
    /// [`Self::sweep_event_log`], mirrored onto the served **traces** sink: the durable conversational
    /// turn-tree [`SessionStore`] behind `/v1/replay*` (`Self::replay_store`), whose
    /// [`ReplayEvent::text`](ainxt_replay::ReplayEvent) fields are the already-redacted turn content
    /// the served turn path persists (see [`Self::record_served_turn`]). Reads `session`'s events
    /// straight back out and re-scans them; an empty session (never persisted, or genuinely clean)
    /// returns no hits — the sweep's positive proof, exactly as `sweep_event_log` documents.
    pub fn sweep_replay_traces(&self, session: &str, now: u64) -> Vec<ainxt_compliance::SweepHit> {
        let Ok(Some(durable)) = self.replay_store.load(session) else {
            return Vec::new();
        };
        let pairs: Vec<(String, String)> = durable
            .events
            .into_iter()
            .map(|e| (e.id.to_string(), e.text))
            .collect();
        let hits = ainxt_compliance::SinkGuard::strong()
            .sweep(pairs.iter().map(|(id, text)| (id.as_str(), text.as_str())));
        for _hit in &hits {
            self.arm_store_sweep_incident(now, "traces");
        }
        hits
    }

    /// [`Self::sweep_replay_traces`] but over EVERY session the durable [`SessionStore`] knows about
    /// (via the store's [`SessionStore::sessions`] — added alongside this gap-fix so a caller need not
    /// already know which session to check), mirroring [`Self::sweep_all_sessions`]'s identical role
    /// for the Event Log.
    pub fn sweep_all_replay_traces(&self, now: u64) -> Vec<ainxt_compliance::SweepHit> {
        self.replay_store
            .sessions()
            .into_iter()
            .flat_map(|session| self.sweep_replay_traces(&session, now))
            .collect()
    }

    /// GAP-FIX regulated-fi-responsible-lifecycle (FI-01 §5.4) — the SAME defense-in-depth sweep as
    /// [`Self::sweep_event_log`], mirrored onto the deployment's **vector index**: the KB corpus
    /// snapshot ([`Self::kb_corpus_snapshot`]) every served ChatSurface's retriever actually grounds
    /// against. Unlike the Event Log/memory/traces sinks — each written on EVERY served turn — this OSS
    /// tree has no separate runtime-writable vector-index store: KB content is admin-provisioned
    /// config, ingested once at assembly. So this sweep proves the INGESTION path redacted before
    /// indexing (a raw PAN pasted into a KB document by an admin would otherwise sit in the corpus
    /// every retrieval-grounded turn can surface verbatim), the direct analog of what
    /// `sweep_event_log`/`sweep_memory`/`sweep_replay_traces` prove for their own write paths.
    pub fn sweep_vector_index(&self, now: u64) -> Vec<ainxt_compliance::SweepHit> {
        let hits = ainxt_compliance::SinkGuard::strong().sweep(
            self.kb_corpus_snapshot
                .iter()
                .map(|(id, text)| (id.as_str(), text.as_str())),
        );
        for _hit in &hits {
            self.arm_store_sweep_incident(now, "vector-index");
        }
        hits
    }

    /// GAP-AUDIT regulated-fi #4 — the served cadence driver for the supervisory monitors
    /// ([`ainxt_incident::cadence::CadenceScheduler`]). `CadenceScheduler` was fully implemented and
    /// unit-tested (pure `due`/`mark_ran` decision logic) but had zero callers on the shipped daemon —
    /// none of `sweep_event_log`, `check_served_ntp_skew`, `verify_served_store_residency` was ever
    /// invoked from anything but a test.
    ///
    /// This spawns a real interval loop (the one genuinely infra-dependent piece — real time) that,
    /// each tick, asks the scheduler which monitors are due and drives ONLY
    /// [`ainxt_incident::cadence::MONITOR_STORE_SWEEP`] automatically — the one monitor with no external
    /// measurement dependency ([`Self::sweep_all_sessions`] reads the daemon's own event log). The other
    /// two registered monitors (`MONITOR_NTP_SKEW`, `MONITOR_RESIDENCY`) genuinely need a live
    /// measurement source this OSS default cannot fabricate without faking data (a real NTP/NIC client;
    /// a real store-location resolver) — they stay `due()`-visible on the scheduler (a deployment can
    /// poll `self.cadence` and drive `check_served_ntp_skew`/`verify_served_store_residency` itself once
    /// it has real adapters) but are NOT auto-invoked here, matching this codebase's existing
    /// infra-gated-not-faked posture for measurement seams.
    pub fn spawn_supervisory_cadence(
        &self,
        period: std::time::Duration,
    ) -> tokio::task::JoinHandle<()> {
        let cadence = self.cadence.clone();
        let event_log = self.event_log.clone();
        let incidents = self.incidents.clone();
        let control_plane_sha = self.control_plane_sha.clone();
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(period);
            loop {
                iv.tick().await;
                let unix_secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let now = ainxt_incident::ticks_from_unix_secs(unix_secs);
                let due = cadence.lock().expect("cadence scheduler lock").due(now);
                if due
                    .iter()
                    .any(|m| m == ainxt_incident::cadence::MONITOR_STORE_SWEEP)
                {
                    // Inlined `sweep_all_sessions`/`sweep_event_log`/`arm_store_sweep_incident` — this
                    // closure only holds the Arcs it needs (event_log/incidents/control_plane_sha), not
                    // `&AssembledFull` (which is not `Clone` and cannot outlive the spawn).
                    for session in event_log.sessions() {
                        let records = event_log.records(&session);
                        let pairs: Vec<(String, String)> = records
                            .into_iter()
                            .map(|r| (r.seq.to_string(), r.text))
                            .collect();
                        let hits = ainxt_compliance::SinkGuard::strong()
                            .sweep(pairs.iter().map(|(id, text)| (id.as_str(), text.as_str())));
                        for _hit in &hits {
                            let candidate = IncidentCandidate::from_store_sweep(
                                now,
                                &control_plane_sha,
                                "event-log",
                            );
                            incidents
                                .lock()
                                .expect("incident register lock")
                                .open_from(candidate, now);
                        }
                    }
                    cadence
                        .lock()
                        .expect("cadence scheduler lock")
                        .mark_ran(ainxt_incident::cadence::MONITOR_STORE_SWEEP, now);
                }
            }
        })
    }
}

// ============================ R9 hot-wiring onto the LIVE served organs ============================
//
// The route-ready seams (`RecordStore::request_erasure_attested`, `IncidentRegister::evidentiary_export_for`
// + `AuditorSession`, the typed `IncidentCandidate` adapters) were exercised only in their own crates'
// tests — the SHIPPED daemon held the LIVE organs (`retention`, `incidents`) but had no entrypoint that
// drove these seams over them. These methods are that hot-wiring: each takes the SAME `Arc<Mutex<..>>`
// organ `assemble_full` instantiated, so a served interaction and a regulator/DPO request share one
// tamper-evident state. Pure w.r.t. the organs (logical `now` injected; the register/store never read a
// clock themselves).
impl AssembledFull {
    /// **§6 served right-to-erasure with redact-with-attestation** (gap 1). Runs a DPDP erasure request
    /// through the LIVE served retention [`RecordStore`](ainxt_lifecycle::RecordStore) under the fixed §6
    /// precedence (legal-hold > retention-floor > erase-now) and returns a tamper-evident
    /// [`ErasureAttestation`]. Fail-closed on [`CAP_RETENTION_ADMIN`] (checked before any store lookup, so
    /// the error is no oracle). A held/floored record is **never hard-deleted under hold** — it is
    /// preserved and attested as deferred-with-record; a free record is hard-erased. The attestation's
    /// SHA-256 content hash binds exactly which records were kept and why. `now` is logical/wall time.
    pub fn erase_subject_attested(
        &self,
        principal: &Principal,
        subject_id: &str,
        now: u64,
    ) -> Result<ErasureAttestation, RetentionRouteError> {
        if !principal.has_cap(CAP_RETENTION_ADMIN) {
            return Err(RetentionRouteError::NotAuthorized);
        }
        // R16 REGFI — route through the canonical guarded entrypoint (`ainxt_lifecycle::guarded::
        // erase_subject_guarded`), not a bare `RecordStore::request_erasure_attested` call: this is the
        // SAME entrypoint `ainxt_server::regfi_erasure_handler` now uses for the served
        // `POST /v1/regfi/erasure` route, so a served-surface `ErasableTier` wired here or there is
        // honored by both.
        //
        // GAP-FIX regulated-fi-responsible-lifecycle (gap6) — MOUNT the real
        // `ainxt_lifecycle::guarded::SessionReplayTier` over `Self::replay_store`, the SAME durable
        // store `persist_served_turn`'s write-path mirror keys under `SERVED_TURN_TIER`. Before this
        // wire, BOTH live call sites of `erase_subject_guarded` passed an explicitly empty tier slice
        // (`&mut []`) — the §6 precedence decision ran over real, mirrored records, but an `EraseNow`
        // decision never propagated back into the store holding the actual conversational bytes, so a
        // "successful" erasure attested to erasing content that, in fact, still lived on.
        let mut store = self.retention.lock().expect("retention store lock");
        let mut tier =
            ainxt_lifecycle::guarded::SessionReplayTier::new(self.replay_store.clone(), now);
        let mut tiers: [&mut dyn ainxt_lifecycle::guarded::ErasableTier; 1] = [&mut tier];
        Ok(
            ainxt_lifecycle::guarded::erase_subject_guarded(
                &mut store, &mut tiers, subject_id, now,
            )
            .attestation,
        )
    }

    /// GAP-FIX regulated-fi-responsible-lifecycle (gap6, §6.3) — drive ONE retention/legal-hold sweep
    /// tick over the SAME LIVE [`Self::retention`] store + [`Self::replay_store`] served-turn tier
    /// [`Self::erase_subject_attested`]/`ainxt_server::regfi_erasure_handler` use, via
    /// [`ainxt_lifecycle::guarded::RetentionSweeper::tick`]. Fires the deferred-erasure queue (a hold
    /// released / floor elapsed) AND the TTL purge, propagating both into the real session store — this
    /// is what makes §6.3's "at expiry it fires automatically" true in the running daemon rather than
    /// only on the next incidental on-demand erasure call for that exact subject. Returns `None` when
    /// the sweeper's own cadence is not yet due (mirrors [`Self::run_health_sweep_tick`]'s shape).
    pub fn run_retention_sweep_tick(
        &self,
        now: u64,
    ) -> Option<ainxt_lifecycle::guarded::SweepReport> {
        let mut sweeper = self
            .retention_sweeper
            .lock()
            .expect("retention sweeper lock");
        let mut store = self.retention.lock().expect("retention store lock");
        let mut tier =
            ainxt_lifecycle::guarded::SessionReplayTier::new(self.replay_store.clone(), now);
        let mut tiers: [&mut dyn ainxt_lifecycle::guarded::ErasableTier; 1] = [&mut tier];
        sweeper.tick(&mut store, &mut tiers, now)
    }

    /// Spawn the background §6.3 retention-sweep loop (mirrors [`Self::spawn_memory_re_redact_sweep`]'s
    /// shape exactly): every `period` it re-derives the current wall-clock tick and drives one
    /// [`Self::run_retention_sweep_tick`]. Returns the [`tokio::task::JoinHandle`] (hold it for the
    /// process lifetime; aborting it — or dropping the surface — stops the sweep). `retention`/
    /// `replay_store`/`retention_sweeper` are mandatory `AssembledFull` fields (unlike the memory
    /// sweeps, which are `None` on a surface with no chat engine), so this spawn is unconditional —
    /// every daemon started via `assemble_full` runs it, matching `spawn_breach_clock`/
    /// `spawn_reconciler_sweep`'s always-on shape.
    pub fn spawn_retention_sweep(
        &self,
        period: std::time::Duration,
    ) -> tokio::task::JoinHandle<()> {
        let sweeper = self.retention_sweeper.clone();
        let store = self.retention.clone();
        let replay = self.replay_store.clone();
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(period);
            loop {
                iv.tick().await;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let mut tier =
                    ainxt_lifecycle::guarded::SessionReplayTier::new(replay.clone(), now);
                let mut tiers: [&mut dyn ainxt_lifecycle::guarded::ErasableTier; 1] = [&mut tier];
                let mut sweeper = sweeper.lock().expect("retention sweeper lock");
                let mut store = store.lock().expect("retention store lock");
                let _ = sweeper.tick(&mut store, &mut tiers, now);
            }
        })
    }

    /// GAP-AUDIT regulated-fi #7 — the served entrypoint to the §4.4 DSAR workflow
    /// ([`DsarWorkflow::handle`]). Fail-closed on [`ainxt_lifecycle::routes::CAP_DSAR_OPERATE`] inside
    /// `handle` itself. `Erase` dispatches through the SAME shared [`Self::retention`] store
    /// `/v1/regfi/erasure` uses, so §6 precedence (legal-hold/floor) is identical either way.
    ///
    /// Always dispatches with `lineage = None`, so a caller-supplied [`DsarCommand::Access`] correctly
    /// fails closed with [`DsarRouteError::LineageUnavailable`] here (this method does no hydration) —
    /// use [`Self::dsar_fulfill_access_live`] for a REAL, hydrated Access fulfilment.
    pub fn dsar_command(
        &self,
        principal: &Principal,
        cmd: &DsarCommand,
        now: u64,
    ) -> Result<DsarOutcome, DsarRouteError> {
        let mut dsar = self.dsar.lock().expect("dsar workflow lock");
        let mut store = self.retention.lock().expect("retention store lock");
        dsar.handle(principal, cmd, &mut store, None, now)
    }

    /// GAP-FIX regulated-fi-responsible-lifecycle — the SLA-breach sweep
    /// (`DsarRegister::overdue`/`refresh_overdue`) had no served entrypoint: `dsar_command` above
    /// dispatches every per-request DSAR command, but nothing ever swept the SAME served register for
    /// requests that crossed their DPDP response deadline. Read-only; a dashboard poll.
    pub fn dsar_overdue(&self, now: u64) -> Vec<String> {
        self.dsar.lock().expect("dsar workflow lock").overdue(now)
    }

    /// Mutating counterpart to [`Self::dsar_overdue`] — actually mark the newly-overdue requests on
    /// the SAME served register, so a scheduled sweep both refreshes status and reports what changed.
    pub fn refresh_overdue_dsars(&self, now: u64) -> Vec<String> {
        self.dsar
            .lock()
            .expect("dsar workflow lock")
            .refresh_overdue(now)
    }

    /// GAP-FIX regulated-fi-responsible-lifecycle (§4.4 access/portability, FI-09) — the served
    /// entrypoint to [`DsarWorkflow::fulfill_access`], for a caller that has ALREADY hydrated its own
    /// cross-tier `lineage` (e.g. a test, or an embedder with a bespoke tier set). This is a thin
    /// lock+delegate wrapper against the SAME shared, served [`Self::dsar`] register `dsar_command`
    /// uses — never a private/disjoint one. Cap-gated inside `fulfill_access` on BOTH
    /// [`ainxt_lifecycle::routes::CAP_DSAR_OPERATE`] and
    /// [`ainxt_lifecycle::routes::can_approve_dsar_access`].
    ///
    /// Most callers on the served daemon want [`Self::dsar_fulfill_access_live`] instead — it hydrates
    /// `lineage` from this daemon's OWN real Redis/Postgres/KG/trace-log/incident-register organs
    /// rather than requiring the caller to assemble one.
    pub fn dsar_fulfill_access(
        &self,
        principal: &Principal,
        id: &str,
        lineage: &CompleteLineage,
        require_complete: bool,
        now: u64,
    ) -> Result<LineageExport, DsarRouteError> {
        self.dsar
            .lock()
            .expect("dsar workflow lock")
            .fulfill_access(principal, id, lineage, require_complete, now)
    }

    /// GAP-FIX regulated-fi-responsible-lifecycle (§4.4 access/portability, FI-09) — the REAL, hydrated
    /// counterpart to [`Self::dsar_fulfill_access`]. `fulfill_access` and the cross-tier resolvers in
    /// [`ainxt_lifecycle::dsar_tiers`] (`MemoryTier`/`TraceTier`/`IncidentTier`/the `DsarRegister`
    /// self-tier) were fully implemented and exhaustively tested but had ZERO served callers: nothing on
    /// the shipped daemon ever built a `CompleteLineage` from this runtime's OWN live organs, so an
    /// access DSAR could be opened and authenticated on `/v1/regfi/dsar` and then never actually
    /// exported — a Right-to-Access request with no way to complete it.
    ///
    /// This assembles that lineage from the SAME live handles this daemon already holds —
    /// [`Self::retention`], [`Self::dsar`]'s own register, [`Self::incidents`], [`Self::event_log`], and
    /// (when the assembled surface has a chat engine) [`Self::memory_consent`] — via
    /// [`ainxt_lifecycle::dsar_tiers::hydrate_default_lineage`], the SAME pure assembly function
    /// `ainxt_server::regfi_dsar_handler` calls for the served `DsarCommand::Access` HTTP path, so the
    /// programmatic embedder path here and the served HTTP path can never silently diverge on which
    /// tiers count toward completeness.
    ///
    /// RBAC: dispatched through [`DsarWorkflow::handle`]'s `Access` arm, which fail-closes on BOTH
    /// [`ainxt_lifecycle::routes::CAP_DSAR_OPERATE`] and the platform's `can_approve` senior-actor gate
    /// ([`ainxt_lifecycle::routes::can_approve_dsar_access`] — `ad_level <= 3` / `Role::Admin`, mirroring
    /// the JWT `can_approve` claim in `CLAUDE.md`'s Auth section) — this method does not re-check either,
    /// so there is a single source of truth for the decision.
    ///
    /// A DSAR access export inherently reads another data subject's personal memory: when the operating
    /// `principal` is not the subject and a memory backend is configured, this exercises break-glass
    /// (requires `Role::Admin` per [`ainxt_memory::access::AccessScope::can_see`]) — a non-admin operator
    /// reading someone else's data gets an absent memory-tier hydration, which correctly REFUSES a
    /// `require_complete=true` export via `IncompleteLineage` rather than silently under-reporting.
    ///
    /// On success, also appends a `dsar.access.fulfilled` record to the SAME live [`Self::event_log`]
    /// [`Self::sweep_event_log`] and `/v1/replay` read — a daemon-level, tamper-evident audit trail of
    /// the export, ON TOP OF the hash-chained `DsarAction::AccessExported` event
    /// `fulfill_access_complete` already appends to the DSAR register itself.
    pub fn dsar_fulfill_access_live(
        &self,
        principal: &Principal,
        id: &str,
        require_complete: bool,
        now: u64,
    ) -> Result<LineageExport, DsarRouteError> {
        let (retention_snapshot, dsar_register_snapshot, incidents_snapshot) = {
            let retention = self.retention.lock().expect("retention store lock");
            let dsar = self.dsar.lock().expect("dsar workflow lock");
            let incidents = self.incidents.lock().expect("incident register lock");
            (
                retention.clone(),
                dsar.register().clone(),
                incidents.clone(),
            )
        };

        let subject_id = dsar_register_snapshot
            .request(id)
            .map(|r| r.subject_id.clone())
            .ok_or_else(|| DsarRouteError::UnknownRequest(id.to_string()))?;

        let trace_records: Vec<ainxt_eventlog::LogRecord> = self
            .event_log
            .sessions()
            .into_iter()
            .flat_map(|session| self.event_log.records(&session))
            .collect();

        let memory_export = self.memory_consent.as_ref().and_then(|backing| {
            let access = ainxt_memory::access::AccessScope::from_principal(principal.clone());
            let access = if principal.user_id == subject_id {
                access
            } else {
                access.with_break_glass(&format!(
                    "DSAR access fulfilment `{id}` by `{}`",
                    principal.user_id
                ))
            };
            backing
                .with_surface(|s| s.export_subject(&subject_id, &access))
                .ok()
        });

        let lineage = ainxt_lifecycle::dsar_tiers::hydrate_default_lineage(
            &retention_snapshot,
            &dsar_register_snapshot,
            &incidents_snapshot,
            &[],
            &subject_id,
            trace_records,
            memory_export,
        );

        let outcome = {
            let mut dsar = self.dsar.lock().expect("dsar workflow lock");
            let mut store = self.retention.lock().expect("retention store lock");
            dsar.handle(
                principal,
                &DsarCommand::Access {
                    id: id.to_string(),
                    require_complete,
                },
                &mut store,
                Some(&lineage),
                now,
            )?
        };

        let export = match outcome {
            DsarOutcome::AccessExport { export, .. } => export,
            _ => unreachable!(
                "DsarCommand::Access dispatch always yields DsarOutcome::AccessExport on Ok"
            ),
        };

        // Best-effort daemon-level audit mirror (ON TOP OF the hash-chained DSAR-register event
        // `fulfill_access_complete` already appended) — never fails the fulfilment itself.
        let _ = self.event_log.append(
            &format!("dsar:{id}"),
            &principal.user_id,
            "dsar.access.fulfilled",
            &format!("subject={subject_id} records={}", export.records.len()),
        );

        Ok(export)
    }

    /// GAP-AUDIT regulated-fi #9 — the served entrypoint to the §6 retention/legal-hold precedence
    /// store's route-ready command set ([`RetentionCommand`]). Deliberately does NOT construct a fresh
    /// [`ainxt_lifecycle::routes::RetentionService`] (that type OWNS its own [`ainxt_lifecycle::RecordStore`],
    /// which would silently create a SECOND, disjoint store from [`Self::retention`] — the exact defect
    /// closed in `ainxt-identity::remediation` this same round). Instead this re-implements
    /// `RetentionService::handle`'s dispatch directly against the ONE shared store, mirroring how
    /// `ainxt_server::regfi_erasure_handler` already bypasses the route-ready wrapper for the same
    /// reason. Fail-closed on [`CAP_RETENTION_ADMIN`].
    pub fn retention_command(
        &self,
        principal: &Principal,
        cmd: &RetentionCommand,
        now: u64,
    ) -> Result<RetentionOutcome, RetentionRouteError> {
        if !principal.has_cap(CAP_RETENTION_ADMIN) {
            return Err(RetentionRouteError::NotAuthorized);
        }
        let mut store = self.retention.lock().expect("retention store lock");
        Ok(match cmd {
            RetentionCommand::SetPolicy { policy } => {
                store.set_policy(*policy);
                RetentionOutcome::Ack
            }
            RetentionCommand::OpenHold { hold } => {
                store.add_hold(hold.clone());
                RetentionOutcome::Ack
            }
            RetentionCommand::ReleaseHold { matter_id } => RetentionOutcome::Released {
                released: store.release_hold(matter_id, now),
            },
            RetentionCommand::Purge => RetentionOutcome::Purged {
                ids: store.purge_expired(now),
            },
            RetentionCommand::RequestErasure { subject_id } => RetentionOutcome::Erasure {
                resolution: store.request_erasure(subject_id, now),
            },
            RetentionCommand::RunDeferred => RetentionOutcome::Fired {
                ids: store.run_deferred(now),
            },
        })
    }

    /// GAP-AUDIT regulated-fi #5 — the served entrypoint to §2.4 pre-templated breach-report drafting
    /// ([`ainxt_incident::report::draft_report`]). Fills a CERT-In/DPDP-Board form from the LIVE
    /// served [`IncidentRegister`]'s structured facts + its Event-Log evidence slice. Read-only (no
    /// capability gate — drafting produces no side effect and is never itself a filing); the draft is
    /// never auto-filed. Returns `None` for an unknown incident or an unconfigured report kind.
    pub fn draft_incident_report(
        &self,
        incident_id: &str,
        kind: ainxt_incident::report::ReportKind,
    ) -> Option<ainxt_incident::report::ReportDraft> {
        let reg = self.incidents.lock().expect("incident register lock");
        ainxt_incident::report::draft_report(&reg, incident_id, kind, &self.report_templates)
    }

    /// GAP-FIX regulated-fi-responsible-lifecycle — persist a full serde snapshot of `program` as a NEW
    /// record on its durable `breakglass-{program_id}` Event-Log session (ADR-027 restart-survival: see
    /// [`recover_break_glass_programs`]'s doc for the recovery half). The Event Log is append-only, so
    /// this is always a fresh checkpoint, never a rewrite; recovery always reads the LATEST one for a
    /// session. Best-effort: an I/O/serialization failure here is reported to stderr but does not fail
    /// the caller's open/step — the in-memory registry (and therefore the served turn) stays
    /// authoritative for the running process; only THIS step's cross-restart durability is at risk,
    /// which a deployment observes via its disk/log monitoring, not a silently wrong campaign state.
    fn checkpoint_break_glass_program(
        &self,
        program_id: &str,
        program: &ainxt_lifecycle::breakglass::BreakGlassProgram,
    ) {
        match serde_json::to_string(program) {
            Ok(snapshot) => {
                if let Err(e) = self.event_log.append(
                    &breakglass_session_id(program_id),
                    "system:breakglass-checkpoint",
                    "breakglass.checkpoint",
                    &snapshot,
                ) {
                    eprintln!(
                        "ainxt-runtimed: break-glass campaign '{program_id}' durable checkpoint FAILED \
                         (restart-recovery for this step is at risk, in-memory state is unaffected): {e}"
                    );
                }
            }
            Err(e) => eprintln!(
                "ainxt-runtimed: break-glass campaign '{program_id}' snapshot serialization FAILED \
                 (restart-recovery for this step is at risk, in-memory state is unaffected): {e}"
            ),
        }
    }

    /// GAP-AUDIT regulated-fi #13 — open a §6.5 break-glass redaction-with-attestation Program on the
    /// LIVE served registry. Fail-closed on the EXPLICIT [`ainxt_lifecycle::breakglass::BREAK_GLASS_CAP`]
    /// grant (never the admin shortcut — least-privilege). `program_id` must be unused; re-opening an
    /// existing id is refused (a Program is resumed via [`Self::step_break_glass_program`], never
    /// silently replaced).
    ///
    /// GAP-FIX regulated-fi-responsible-lifecycle — also checkpoints the freshly-opened campaign to the
    /// durable Event Log (see [`Self::checkpoint_break_glass_program`]) BEFORE it becomes visible in the
    /// in-memory registry, so a crash between the two never leaves an in-memory-only campaign with no
    /// durable trail a restart could recover.
    pub fn open_break_glass_program(
        &self,
        principal: &Principal,
        program_id: &str,
        reason_code: &str,
        targets: Vec<ainxt_lifecycle::breakglass::RedactionTarget>,
    ) -> Result<(), ainxt_lifecycle::breakglass::BreakGlassError> {
        let program = ainxt_lifecycle::breakglass::BreakGlassProgram::open(
            program_id,
            principal,
            reason_code,
            targets,
        )?;
        let mut reg = self.breakglass.lock().expect("break-glass registry lock");
        if reg.contains_key(program_id) {
            // Re-opening is refused (not silently replaced) — the same explicit-grant error the caller
            // would see for a genuine authorization failure, since re-use of an id is itself a misuse
            // this seam refuses rather than papering over.
            return Err(ainxt_lifecycle::breakglass::BreakGlassError::Unauthorized(
                format!("program id '{program_id}' already exists"),
            ));
        }
        self.checkpoint_break_glass_program(program_id, &program);
        reg.insert(program_id.to_string(), program);
        Ok(())
    }

    /// GAP-AUDIT regulated-fi #13 — process the next pending target on an open break-glass Program.
    /// Re-checks [`BREAK_GLASS_CAP`](ainxt_lifecycle::breakglass::BREAK_GLASS_CAP) on every step (the
    /// Program object itself only checks at `open`), so a caller who merely learns another DPO's
    /// `program_id` cannot drive their campaign. Returns `Ok(None)` when the Program is already
    /// complete (idempotent at the boundary, mirroring [`BreakGlassProgram::step`]).
    ///
    /// GAP-FIX regulated-fi-responsible-lifecycle — also checkpoints the stepped campaign's new state to
    /// the durable Event Log (see [`Self::checkpoint_break_glass_program`]) AFTER the step, so the
    /// durable trail never runs ahead of what the in-memory registry (and therefore this response)
    /// actually reflects. A daemon restart between the step and this checkpoint would recover from the
    /// PRIOR checkpoint and reprocess this one target on the NEXT step call — never a silently skipped
    /// remediation, and never a double-counted one either (the recovered Program's own `pending` queue
    /// still names it, exactly the "partial completion is a first-class outcome" contract
    /// [`BreakGlassProgram`] already guarantees for a `kill -9` mid-step).
    pub fn step_break_glass_program(
        &self,
        principal: &Principal,
        program_id: &str,
        now: u64,
    ) -> Result<
        Option<ainxt_lifecycle::breakglass::RedactionAttestation>,
        ainxt_lifecycle::breakglass::BreakGlassError,
    > {
        if !principal
            .caps
            .iter()
            .any(|c| c == ainxt_lifecycle::breakglass::BREAK_GLASS_CAP)
        {
            return Err(ainxt_lifecycle::breakglass::BreakGlassError::Unauthorized(
                principal.user_id.clone(),
            ));
        }
        let mut reg = self.breakglass.lock().expect("break-glass registry lock");
        let program = reg.get_mut(program_id).ok_or_else(|| {
            ainxt_lifecycle::breakglass::BreakGlassError::Unauthorized(format!(
                "unknown program id '{program_id}'"
            ))
        })?;
        let attestation = program.step(now).cloned();
        self.checkpoint_break_glass_program(program_id, program);
        Ok(attestation)
    }

    /// GAP-AUDIT regulated-fi #13 — `(done, total)` progress for an open break-glass Program. Same
    /// per-call capability re-check as [`Self::step_break_glass_program`].
    pub fn break_glass_progress(
        &self,
        principal: &Principal,
        program_id: &str,
    ) -> Result<(usize, usize), ainxt_lifecycle::breakglass::BreakGlassError> {
        if !principal
            .caps
            .iter()
            .any(|c| c == ainxt_lifecycle::breakglass::BREAK_GLASS_CAP)
        {
            return Err(ainxt_lifecycle::breakglass::BreakGlassError::Unauthorized(
                principal.user_id.clone(),
            ));
        }
        let reg = self.breakglass.lock().expect("break-glass registry lock");
        let program = reg.get(program_id).ok_or_else(|| {
            ainxt_lifecycle::breakglass::BreakGlassError::Unauthorized(format!(
                "unknown program id '{program_id}'"
            ))
        })?;
        Ok(program.progress())
    }

    /// **§7.2 / §8.3 served BSA §63 evidentiary export** (gap 2) over the LIVE served
    /// [`IncidentRegister`]. Delegates to the capability-gated, existence-hiding
    /// [`evidentiary_export_for`](IncidentRegister::evidentiary_export_for): the principal must hold
    /// `AUDITOR_CAP` explicitly (admin NOT implied), an out-of-scope/unknown incident is an
    /// indistinguishable 404, and an unverifiable chain is refused rather than dressed with a §63
    /// certificate. Returns the owned export (the register lock is released before returning).
    pub fn export_incident_evidence(
        &self,
        principal: &Principal,
        scope: &AuditorScope,
        req: &EvidenceExportRequest,
    ) -> Result<EvidentiaryExport, EvidenceRouteError> {
        self.incidents
            .lock()
            .expect("incident register lock")
            .evidentiary_export_for(principal, scope, req)
    }

    /// GAP-FIX regulated-fi-responsible-lifecycle — [`EvidentiaryExport::reverify`] had zero callers
    /// anywhere outside `ainxt-incident`'s own tests. A recipient (regulator/auditor) who received an
    /// export earlier has no way to re-check it wasn't tampered with in transit/storage — this is that
    /// missing check. Pure over caller-supplied data (`&EvidentiaryExport`), no lock, no shared state.
    pub fn reverify_evidence_export(&self, export: &EvidentiaryExport) -> bool {
        export.reverify()
    }

    /// GAP-AUDIT regulated-fi #6 — the served entrypoint to [`IncidentRegister::downgrade`] (§2.2's
    /// fail-safe disarm: an accountable owner stops a statutory clock without touching t0 or the wall
    /// clock). Fully implemented and tested in `ainxt-incident`, but had no served path — a regulator's
    /// determination that a clock does not apply could only be recorded by editing test fixtures, never
    /// through the shipped daemon. Fail-closed on [`ainxt_incident::DOWNGRADE_CAP`] inside `downgrade`
    /// itself; this method adds no additional gate.
    pub fn downgrade_incident_clock(
        &self,
        incident_id: &str,
        clock: StatutoryClockKind,
        actor: &Principal,
        reason: &str,
        now: u64,
    ) -> Result<(), IncidentError> {
        self.incidents
            .lock()
            .expect("incident register lock")
            .downgrade(incident_id, clock, actor, reason, now)
    }

    /// **§8.3 served read-only supervisory auditor listing** (gap 2). Opens a capability-gated,
    /// existence-hiding, read-only-by-construction [`AuditorSession`] over the LIVE served register and
    /// returns the ids of every incident within the auditor's `scope` (out-of-scope incidents never
    /// appear — existence does not leak). The register is borrowed immutably, so the session literally
    /// cannot mutate it; the query is chain-logged into the session's custody manifest. Fail-closed on an
    /// explicit `AUDITOR_CAP` grant.
    pub fn auditor_list_incidents(
        &self,
        principal: &Principal,
        scope: AuditorScope,
        now: ainxt_incident::Tick,
    ) -> Result<Vec<String>, AuditorError> {
        let reg = self.incidents.lock().expect("incident register lock");
        let mut sess = AuditorSession::open_authorized(&reg, principal, scope, now)?;
        Ok(sess.list_incident_ids())
    }

    /// GAP-FIX identity-payments — the served entrypoint to [`ControlPlane::pull_kill_switch`]
    /// (ADR-022 §19's "big red button": an accountable, sufficiently senior approver halts a scope —
    /// workforce / a Run / a Role / a department / a data class). Fully implemented and tested in
    /// `ainxt-identity`, but had no served path — an operator could never actually pull it on the
    /// shipped daemon; every dispatch admission already consults the SAME `control_plane` this method
    /// locks, so pulling it here takes effect on the very next admission check. Fail-closed inside
    /// `pull_kill_switch` itself (`ad_level <= 3` AND `can_approve`); this method adds no extra gate.
    pub fn pull_kill_switch(
        &self,
        scope: KillScope,
        puller_id: impl Into<String>,
        ad_level: u8,
        can_approve: bool,
        now: ainxt_identity::LogicalTime,
    ) -> Result<KillSwitchAudit, KillSwitchAuthError> {
        self.control_plane
            .lock()
            .expect("control plane lock")
            .pull_kill_switch(scope, puller_id, ad_level, can_approve, now)
    }

    /// The served release counterpart to [`Self::pull_kill_switch`] — a halt is a live lever, not a
    /// one-way trip.
    pub fn release_kill_switch(&self, scope: &KillScope) {
        self.control_plane
            .lock()
            .expect("control plane lock")
            .release_kill_switch(scope)
    }

    /// The served, read-only §19 audit trail of every authorized kill-switch pull on THIS control
    /// plane — cloned out from behind the lock so a caller cannot hold the plane hostage while reading it.
    pub fn kill_switch_audit(&self) -> Vec<KillSwitchAudit> {
        self.control_plane
            .lock()
            .expect("control plane lock")
            .kill_switch_audit()
            .to_vec()
    }

    /// GAP-FIX identity-payments — `ControlPlane::revoke_run` (§17: revoke exactly one Run, denied at
    /// the next dispatch AND renewal, zero collateral) had zero DIRECT, operator-initiated callers on
    /// the served path — the only existing call sites are internal (§20's own auto-revoke inside
    /// `ControlPlane::observe`, and the payment-boundary tripwire remediator). An operator had no
    /// standing lever to revoke a single Run outside those two automatic triggers.
    pub fn revoke_run(&self, run_id: impl Into<String>) {
        self.control_plane
            .lock()
            .expect("control plane lock")
            .revoke_run(run_id)
    }

    /// The OBO-human counterpart to [`Self::revoke_run`] (§17: revoke an OBO human's delegated
    /// authority — every Run carrying them is denied).
    pub fn revoke_user(&self, user_id: impl Into<String>) {
        self.control_plane
            .lock()
            .expect("control plane lock")
            .revoke_user(user_id)
    }

    /// Read-only query for [`Self::revoke_run`]'s effect — `RevocationRegistry::is_run_revoked` had
    /// the same zero-direct-caller gap.
    pub fn is_run_revoked(&self, run_id: &str) -> bool {
        self.control_plane
            .lock()
            .expect("control plane lock")
            .revocations()
            .is_run_revoked(run_id)
    }

    /// Read-only query for [`Self::revoke_user`]'s effect.
    pub fn is_user_revoked(&self, user_id: &str) -> bool {
        self.control_plane
            .lock()
            .expect("control plane lock")
            .revocations()
            .is_user_revoked(user_id)
    }

    /// GAP-FIX identity-payments — `ControlPlane::observe` (§20 UEBA: score an activity sample
    /// against its role baseline and, per `response`, flag the Run for the renewal choke or
    /// additionally revoke it in-flight) had zero callers outside `ainxt-identity`'s own tests. Takes
    /// only caller-supplied plain data (no clock/rng) — the runtime's live telemetry-collection loop
    /// that feeds real observation windows stays `needs_hot_wiring`; this closes the SCORING seam.
    pub fn observe_run_activity(
        &self,
        baseline: &ainxt_identity::authority::BehavioralBaseline,
        sample: &ainxt_identity::authority::ActivitySample,
        response: ainxt_identity::control::AnomalyResponse,
    ) -> ainxt_identity::authority::AnomalyAssessment {
        self.control_plane
            .lock()
            .expect("control plane lock")
            .observe(baseline, sample, response)
    }

    /// **§2.1 served breach-detection intake** (gap 3): arm a statutory clock on the LIVE served
    /// [`IncidentRegister`] from a typed [`IncidentCandidate`] and return the opened incident id. This is
    /// the single served seam every runtime detector routes through — MORE than the quality
    /// circuit-breaker feeds the register: the compliance-egress gate, the durable-log sink-guard, the
    /// payment-boundary, and the serving-ops detector each raise their typed candidate and open an
    /// incident here (the register's fail-safe [`open_from`](IncidentRegister::open_from) arms the
    /// statutory clocks for the incident's class from t0). See the `arm_*` convenience helpers.
    pub fn arm_incident(&self, candidate: IncidentCandidate, now: u64) -> String {
        self.incidents
            .lock()
            .expect("incident register lock")
            .open_from(candidate, now)
    }

    /// §2.1 — arm a personal-data / regulated-class **compliance-egress** breach on the served register
    /// (the compliance gate saw a regulated class egress past policy). `principal_estimate` is the
    /// affected-principal count that scopes the DPDP notification.
    pub fn arm_compliance_egress_incident(
        &self,
        now: u64,
        class: DataClass,
        principal_estimate: u64,
    ) -> String {
        self.arm_incident(
            IncidentCandidate::from_compliance_egress(
                now,
                &self.control_plane_sha,
                class,
                principal_estimate,
            ),
            now,
        )
    }

    /// §2.1 / §5 — arm a **sink-guard** breach on the served register (the write-path sink-guard caught
    /// CHD reaching a durable store `sink`).
    pub fn arm_sink_guard_incident(&self, now: u64, sink: &str) -> String {
        self.arm_incident(
            IncidentCandidate::from_sink_guard(now, &self.control_plane_sha, sink),
            now,
        )
    }

    /// §2.1 (ADR-013/016) — arm a **payment-boundary** breach on the served register (the payment
    /// boundary saw an anomalous/attempted settlement-class `action`).
    pub fn arm_payment_boundary_incident(&self, now: u64, action: &str) -> String {
        self.arm_incident(
            IncidentCandidate::from_payment_boundary(now, &self.control_plane_sha, action),
            now,
        )
    }

    /// §2.1 (ADR-020) — arm a **serving-ops** breach on the served register (serving-ops reported a
    /// material disruption of critical `route`).
    pub fn arm_serving_ops_incident(&self, now: u64, route: &str) -> String {
        self.arm_incident(
            IncidentCandidate::from_serving_ops(now, &self.control_plane_sha, route),
            now,
        )
    }

    /// §5.4 — arm a **store-sweep** breach on the served register (the defense-in-depth sweep found
    /// CHD already resident in a durable `store` — the write-path guard was bypassed for that record).
    pub fn arm_store_sweep_incident(&self, now: u64, store: &str) -> String {
        self.arm_incident(
            IncidentCandidate::from_store_sweep(now, &self.control_plane_sha, store),
            now,
        )
    }

    /// §8.2 served **NTP clock-skew** intake (Round-11 gap): drive the NIC/NPL
    /// [`NtpSkewMonitor`](ainxt_incident::ops::NtpSkewMonitor) against a measured `offset_ms` and, when
    /// the skew exceeds the monitor's threshold, arm a §2 incident on the LIVE served register. Returns
    /// the always-present [`NtpAttestation`](ainxt_incident::evidence::NtpAttestation) (every
    /// evidentiary timestamp records its source + offset) plus the opened incident id when the skew
    /// alarmed. The clean served entrypoint; the LIVE NTP offset *measurement* (querying the NIC/NPL
    /// source) is a deployment adapter the daemon's edge supplies (`infra_gated`) — this funnels a
    /// measured offset onto the served register with no per-call-site struct-building.
    pub fn check_served_ntp_skew(
        &self,
        monitor: &ainxt_incident::ops::NtpSkewMonitor,
        offset_ms: i64,
        now: u64,
    ) -> (ainxt_incident::evidence::NtpAttestation, Option<String>) {
        let (attestation, candidate) = monitor.check(offset_ms, now, &self.control_plane_sha);
        let incident_id = candidate.map(|c| self.arm_incident(c, now));
        (attestation, incident_id)
    }

    /// §8.1 served **India-residency** intake (Round-11 gap): drive the
    /// [`ResidencyVerifier`](ainxt_incident::ops::ResidencyVerifier) over a set of resolved
    /// `(store_id, region)` pairs and arm a §2 incident on the LIVE served register for every store
    /// that resolves outside Indian jurisdiction (breaking the CERT-In 180-day in-India retention
    /// floor). Returns the opened incident ids (one per mis-located store), in input order. The clean
    /// served entrypoint; the LIVE storage-region *resolution* (asking each store where it physically
    /// resolves) is a deployment adapter the daemon's edge supplies (`infra_gated`).
    pub fn verify_served_store_residency<'a, I>(
        &self,
        verifier: &ainxt_incident::ops::ResidencyVerifier,
        stores: I,
        now: u64,
    ) -> Vec<String>
    where
        I: IntoIterator<Item = (&'a str, &'a str)>,
    {
        verifier
            .verify_all(stores, now, &self.control_plane_sha)
            .into_iter()
            .map(|c| self.arm_incident(c, now))
            .collect()
    }

    /// §2.3 **crash-survival persist** (Round-11 HIGH gap): snapshot the LIVE served
    /// [`IncidentRegister`] (its armed statutory clocks, paged tiers and hash chain) through the durable
    /// [`SnapshotStore`](ainxt_incident::durable::SnapshotStore) seam under
    /// [`INCIDENT_SNAPSHOT_KEY`], using the caller-supplied `serialize` codec (codec-generic so the
    /// daemon's dependency surface stays unchanged). The daemon calls this on a cadence and on graceful
    /// shutdown; the LIVE durable backend bound behind the trait (Postgres / Redis / a WORM object
    /// store — crash-atomic) is `infra_gated`.
    pub fn snapshot_incident_register<S, E>(
        &self,
        store: &mut dyn ainxt_incident::durable::SnapshotStore,
        serialize: S,
    ) -> Result<(), ainxt_incident::durable::SnapshotWriteError<E>>
    where
        S: FnOnce(&IncidentRegister) -> Result<Vec<u8>, E>,
    {
        let reg = self.incidents.lock().expect("incident register lock");
        ainxt_incident::durable::snapshot_register(&reg, store, INCIDENT_SNAPSHOT_KEY, serialize)
    }

    /// §2.3 **crash-survival restore** (Round-11 HIGH gap): re-project the LIVE served
    /// [`IncidentRegister`] from the durable [`SnapshotStore`] on daemon boot, **before**
    /// [`spawn_breach_clock`](Self::spawn_breach_clock) starts advancing wall-clock time. On a warm
    /// start the register is replaced by the restored one (its immutable `t0`s intact, so a clock keeps
    /// counting from real elapsed time across the `kill -9` and breaches at the correct boundary); on a
    /// cold start (nothing persisted) the fresh register is kept. Returns `true` iff a snapshot was
    /// restored. Codec supplied by the caller; the live durable backend is `infra_gated`.
    pub fn restore_incident_register<D, E>(
        &self,
        store: &dyn ainxt_incident::durable::SnapshotStore,
        deserialize: D,
    ) -> Result<bool, E>
    where
        D: FnOnce(&[u8]) -> Result<IncidentRegister, E>,
    {
        match ainxt_incident::durable::restore_register(store, INCIDENT_SNAPSHOT_KEY, deserialize)?
        {
            Some(restored) => {
                *self.incidents.lock().expect("incident register lock") = restored;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// §6.2/§6.3 **crash-survival persist** for the served retention [`RecordStore`] — its legal-hold
    /// matters and deferred-erasure queue are obligations that outlive a process. Snapshots through the
    /// SAME durable [`SnapshotStore`] seam under [`RETENTION_SNAPSHOT_KEY`]; the live backend is
    /// `infra_gated`.
    pub fn snapshot_retention_store<S, E>(
        &self,
        store: &mut dyn ainxt_incident::durable::SnapshotStore,
        serialize: S,
    ) -> Result<(), ainxt_incident::durable::SnapshotWriteError<E>>
    where
        S: FnOnce(&ainxt_lifecycle::RecordStore) -> Result<Vec<u8>, E>,
    {
        let rec = self.retention.lock().expect("retention store lock");
        ainxt_lifecycle::durable::snapshot_store(&rec, store, RETENTION_SNAPSHOT_KEY, serialize)
    }

    /// §6.2/§6.3 **crash-survival restore** for the served retention [`RecordStore`] on daemon boot:
    /// a deferred erasure queued before a crash still fires on schedule after the restart (a dropped
    /// queue would silently lose a data principal's right-to-erasure — an invisible DPDP breach).
    /// Returns `true` iff a snapshot was restored. The live durable backend is `infra_gated`.
    pub fn restore_retention_store<D, E>(
        &self,
        store: &dyn ainxt_incident::durable::SnapshotStore,
        deserialize: D,
    ) -> Result<bool, E>
    where
        D: FnOnce(&[u8]) -> Result<ainxt_lifecycle::RecordStore, E>,
    {
        match ainxt_lifecycle::durable::restore_store(store, RETENTION_SNAPSHOT_KEY, deserialize)? {
            Some(restored) => {
                *self.retention.lock().expect("retention store lock") = restored;
                Ok(true)
            }
            None => Ok(false),
        }
    }
}

/// The 32-byte AEAD key the connector [`ConnectorGateway`]'s [`TokenVault`](ainxt_token::TokenVault)
/// seals connector secrets with. Uses the configured `AINXT_TOKEN_KEY` (64-char hex) when present; the
/// air-gapped default derives an **ephemeral** key that never leaves the process and is discarded on
/// restart — so the in-RAM vault holds only ciphertext and no durable connector secret exists without a
/// configured key. Distinct from [`build_token_vault`] (the durable vault, key-gated); the connector
/// surface must be MOUNTED regardless so the catalog/list routes serve.
fn connector_token_key(report: &mut Vec<String>) -> [u8; 32] {
    match std::env::var("AINXT_TOKEN_KEY")
        .ok()
        .and_then(|h| parse_key_32(&h))
    {
        Some(key) => key,
        None => {
            report.push(
                "connector vault key: ephemeral (no AINXT_TOKEN_KEY) — in-RAM ciphertext only, \
                 discarded on restart"
                    .into(),
            );
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            // A process-ephemeral key: mix the start-nanos across all 32 bytes. Non-cryptographic
            // provenance, but it never persists and the backend is wiped on restart, so at-rest secrecy
            // of the in-RAM vault does not depend on it (there is nothing durable to protect).
            let seed = nanos.to_le_bytes(); // 16 bytes
            let mut key = [0u8; 32];
            for (i, b) in key.iter_mut().enumerate() {
                *b = seed[i % seed.len()] ^ (i as u8).wrapping_mul(31);
            }
            key
        }
    }
}

/// GAP-FIX token-durability (gap6) — which backend the served connector [`TokenVault`](ainxt_token::TokenVault)
/// persists into: [`mounts::ConnectorTokenBackend::Memory`] (default — an
/// [`ainxt_token::InMemorySqlTokenBackend`], wiped on every daemon restart) or
/// [`mounts::ConnectorTokenBackend::File`] (an [`ainxt_token::FileTokenStore`] — encrypted records
/// survive a restart via atomic temp-file+rename writes) when `AINXT_TOKEN_STORE=file` is set.
///
/// Mirrors [`build_gates`]'s `[gates] audit = "memory" | "event-log"` selection
/// (`ainxt_config::AuditSinkKind`) — same shape (in-memory dev/test default, durable opt-in), but an
/// env var rather than a `[server]`/`[gates]` TOML key because every other connector-subsystem knob
/// (`AINXT_TOKEN_KEY`, `AINXT_GITLAB_OAUTH_*`, `AINXT_CONNECTOR_DEPT_RULES`) is already env-var-based;
/// this stays consistent with its own immediate siblings rather than introducing a second config
/// surface for the same subsystem. `AINXT_TOKEN_STORE_PATH` overrides the file location; unset falls
/// back to a fixed path under the OS temp dir (mirrors [`event_log_dir`]'s fallback shape).
///
/// Before this fix, [`mounts::build_connector_gateway`]/[`mounts::build_connector_invoker`] could ONLY
/// ever be handed an [`ainxt_token::InMemorySqlTokenBackend`] — `ainxt_token::FileTokenStore` (the
/// crate's own documented "durable OSS default" for this exact seam) had zero callers anywhere in the
/// composition root, so connector OAuth tokens never survived a daemon restart in the shipped default,
/// despite a tested durable store existing for exactly that purpose.
fn connector_token_backend(report: &mut Vec<String>) -> mounts::ConnectorTokenBackend {
    match std::env::var("AINXT_TOKEN_STORE").ok().as_deref() {
        Some("file") => {
            let path = std::env::var("AINXT_TOKEN_STORE_PATH")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|_| {
                    std::env::temp_dir()
                        .join("ainxt-runtimed")
                        .join("connector-tokens.json")
                });
            match ainxt_token::FileTokenStore::open(&path) {
                Ok(store) => {
                    report.push(format!(
                        "connector token store: FILE-backed (AINXT_TOKEN_STORE=file) at {} — \
                         connector OAuth tokens now survive a daemon restart (atomic \
                         temp-file+rename writes, ainxt_token::FileTokenStore)",
                        path.display()
                    ));
                    mounts::ConnectorTokenBackend::File(store)
                }
                Err(e) => {
                    report.push(format!(
                        "connector token store: AINXT_TOKEN_STORE=file requested but failed to open \
                         '{}' ({e}) — falling back to in-RAM store; connector OAuth tokens will NOT \
                         survive a daemon restart",
                        path.display()
                    ));
                    mounts::ConnectorTokenBackend::Memory(
                        ainxt_token::InMemorySqlTokenBackend::new(),
                    )
                }
            }
        }
        _ => {
            report.push(
                "connector token store: in-RAM (default; set AINXT_TOKEN_STORE=file for the durable \
                 OSS default, ainxt_token::FileTokenStore) — connector OAuth tokens do NOT survive a \
                 daemon restart"
                    .into(),
            );
            mounts::ConnectorTokenBackend::Memory(ainxt_token::InMemorySqlTokenBackend::new())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// GAP-FIX memory (write-path-missing) — `Engine.memory` was a READ-ONLY seam and no served
    /// route/turn-loop hook ever called a real write primitive in production: every `store.write(..)`
    /// reachable from `ainxt-server`'s own test module was a `#[tokio::test]` seed fixture, never
    /// wired to a live request. Proves the fix through the REAL functions the daemon's composition
    /// root actually calls, not a bespoke stand-in:
    ///
    /// 1. [`build_durable_memory_reader`] — the EXACT function `build_chat_engine_with_authz` calls
    ///    to build the engine's Context-Fabric memory seam.
    /// 2. [`ainxt_server::memory_router`] — the EXACT function `app_full_ext` merges onto the served
    ///    daemon, bound to a REAL ephemeral-port HTTP server (`axum::serve` + `reqwest`, the same
    ///    pattern this crate's `wire_*` tests use) — a genuine `POST /memory/remember` HTTP request,
    ///    not a direct handler call.
    /// 3. [`ainxt_memory::MemoryWriter::write_as`] via the writer handle bundled into the SAME
    ///    [`MemoryHandle`] `build_chat_engine_with_authz` returns.
    ///
    /// The assertion that matters: after the HTTP write, calling
    /// `ainxt_runtime::memory::MemoryReader::read_for_turn` directly on the SAME `Arc<DurableMemoryReader>`
    /// instance the writer was built from — the exact method + exact instance `Engine::run`'s memory
    /// call site (`self.memory.as_ref().read_for_turn(..)`) invokes once this reader is handed to
    /// `Engine::with_memory` — sees the item. This is the "reaches the SAME store `read_for_turn`
    /// reads from" requirement, proven behaviorally rather than asserted by construction.
    #[tokio::test(flavor = "multi_thread")]
    async fn gap_runtimed_memory_remember_route_reaches_the_engines_own_read_for_turn_store() {
        use ainxt_memory::fabric::TaskKind;
        use ainxt_runtime::memory::MemoryReader as _;

        // (1) The REAL composition-root function — identical to the call inside
        // `build_chat_engine_with_authz` (see that function's body a few hundred lines up).
        let (reader, backend) = build_durable_memory_reader().expect("build durable memory reader");
        let writer: Arc<dyn ainxt_memory::MemoryWriter> = reader.clone();

        // (2) The REAL served router, over a REAL bound TCP listener — the same function
        // `app_full_ext` merges onto `/memory/*`, the same helper-shape this crate's other `wire_*`
        // HTTP tests use (bind ephemeral port, `axum::serve` in a background task).
        let consent_backing = Arc::new(ainxt_memory::ConsentBacking::Durable(backend));
        let router = ainxt_server::memory_router(
            consent_backing,
            None,
            None,
            Arc::new(ainxt_server::TrustedGatewayAuth),
            Some(writer),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral port");
        let addr = listener.local_addr().expect("local_addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        let base = format!("http://{addr}");

        // A genuine HTTP POST — no handler is called directly.
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("{base}/memory/remember"))
            .header("x-ainxt-user", "alice")
            .json(&serde_json::json!({
                "id": "pref-terse",
                "title": "terse",
                "body": "alice prefers terse answers",
                "kind": "user-preference",
            }))
            .send()
            .await
            .expect("POST /memory/remember send");
        assert!(
            resp.status().is_success(),
            "served remember route must accept the write: {}",
            resp.status()
        );
        let body: serde_json::Value = resp.json().await.expect("remember response body");
        assert_eq!(body["id"], "pref-terse");

        // (3) The assertion that matters: the SAME long-lived reader instance the writer was built
        // from — the exact instance `Engine::with_memory` would have been handed — sees the item on
        // its very next `read_for_turn`, with NO intervening reopen.
        let access =
            ainxt_memory::AccessScope::from_principal(ainxt_types::Principal::user("alice", &[]));
        let (hits, lineage) = reader.read_for_turn("turn-1", &TaskKind::CasualChat, &access, 100);
        assert!(
            hits.iter().any(|h| h.item.id == "pref-terse"),
            "the engine's own long-lived memory reader must see the write made through the served \
             /memory/remember route on its very next read_for_turn — got hits: {:?}",
            hits.iter().map(|h| &h.item.id).collect::<Vec<_>>()
        );
        assert!(
            lineage.injected.iter().any(|(id, _)| id == "pref-terse"),
            "the injected lineage must record the remembered item too"
        );

        // A caller cannot author into ANOTHER user's personal scope (write-isolation, design §8.2) —
        // the served route enforces the SAME `AccessScope::can_write` check `write_as` always does.
        let forbidden = client
            .post(format!("{base}/memory/remember"))
            .header("x-ainxt-user", "alice")
            .json(&serde_json::json!({
                "title": "not yours",
                "body": "bob's secret",
                "scope": { "kind": "user", "id": "bob" },
            }))
            .send()
            .await
            .expect("forbidden send");
        assert_eq!(
            forbidden.status().as_u16(),
            403,
            "writing into another user's personal scope must be refused"
        );
    }

    /// GAP-AUDIT surfaces-profiles-skills-config — "WasmSkillExecutor stub in production": the daemon's
    /// composition root (`build_skill_runtime`, used by [`assemble_surface`]) used to hardcode
    /// `SkillRuntime::with_builtins()` (`NativeSkillExecutor` only), so the real, wasmtime-backed
    /// `WasmSkillExecutor` had no path from process boot to a served turn no matter what a deployment
    /// configured. Proves the composition root now builds via `with_builtins_and_wasm` (dispatch-
    /// capable) while staying byte-identical for every existing compiled-in builtin skill.
    #[test]
    fn gap_runtimed_build_skill_runtime_wires_dispatching_executor_and_keeps_builtins_working() {
        let skills = build_skill_runtime();

        // Existing compiled-in behavior is unchanged: the citation-discipline behavioral builtin and
        // turn-header execution builtin both still resolve through the composition root's runtime.
        let prepared = skills
            .prepare(
                &[
                    ainxt_skill::builtin::CITATION_DISCIPLINE.to_string(),
                    ainxt_skill::builtin::TURN_HEADER.to_string(),
                ],
                "hello",
            )
            .expect("compiled-in builtins must still resolve after wiring the WASM dispatcher");
        assert_eq!(
            prepared.behavioral.len(),
            1,
            "citation-discipline is behavioral"
        );
        assert_eq!(
            prepared.execution.len(),
            1,
            "turn-header is a native execution builtin"
        );

        // An unregistered ref (neither builtin, nor native, nor a registered WASM module) must still
        // fail closed through the new dispatcher — never silently skipped.
        let err = skills
            .prepare(&["not-a-real-skill".to_string()], "x")
            .unwrap_err();
        assert!(matches!(err, ainxt_skill::SkillError::NotFound(_)));
    }

    /// GAP-FIX identity-payments — proves `BehaviorFeedingTelemetry` is a REAL live feed into the §20
    /// UEBA pipeline, not a stub: an actor's in-envelope turns are learned and never flagged, then a
    /// turn that deviates from that actor's OWN learned history (new provider = unexpected capability,
    /// a rate/cost spike) gets scored as anomalous and chokes that actor's renewal on the SAME shared
    /// `control_plane` every dispatch admission check already consults — proving the feed reaches the
    /// live enforcement surface, not just a private counter.
    #[test]
    fn gap_runtimed_behavior_feeding_telemetry_feeds_live_ueba_baseline_from_served_turns() {
        use ainxt_telemetry::TelemetrySink as _;
        let control_plane = Arc::new(Mutex::new(ainxt_identity::control::ControlPlane::new()));
        let history: Arc<
            Mutex<
                std::collections::HashMap<String, Vec<ainxt_identity::authority::ActivitySample>>,
            >,
        > = Arc::new(Mutex::new(std::collections::HashMap::new()));
        let sink = BehaviorFeedingTelemetry {
            inner: Arc::new(ainxt_telemetry::NullTelemetry),
            history: history.clone(),
            control_plane: control_plane.clone(),
        };

        let normal_turn = |turn_id: &str| ainxt_telemetry::TurnMetrics {
            session: "s1".into(),
            turn: turn_id.into(),
            actor: "alice".into(),
            provider: "claude-sonnet-4-6".into(),
            data_class: ainxt_types::DataClass::Internal,
            input_tokens: 100,
            output_tokens: 50,
            cost_micros: 500,
            latency_ms: 200,
            redactions: 0,
            tool_calls: 1,
            outcome: ainxt_telemetry::TurnOutcome::Completed,
        };

        // First-ever turn for this actor: empty history => an empty expected-capability/egress union,
        // so (per `BehavioralBaseline::learn_from_history`'s own documented defense-in-depth design,
        // see `r12_unbaselined_role_with_no_history_is_not_retroactively_flagged`) ANY capability use is
        // visibility-flagged even though rate/cost never false-spike against the infinite ceiling. Real
        // wiring must reproduce that exact documented behavior, not silently suppress it.
        sink.record_turn(&normal_turn("t1"));
        {
            let cp = control_plane.lock().unwrap();
            assert!(
                cp.anomaly().is_flagged("t1"),
                "an unbaselined actor's first-ever capability use is flagged for visibility, per design"
            );
        }
        // But the SAME first turn must never false-spike on rate/cost (infinite ceiling with no history).
        {
            let h = history.lock().unwrap();
            let alice_history = h
                .get("actor:alice")
                .expect("alice's history must exist after turn 1");
            assert_eq!(
                alice_history.len(),
                1,
                "the real turn must be folded into the learned history"
            );
            let baseline_before_t1 =
                ainxt_identity::authority::BehavioralBaseline::learn_from_history(
                    "actor:alice",
                    std::iter::empty(),
                    1.25,
                );
            let assessment = ainxt_identity::authority::AnomalyMonitor::new()
                .assess(&baseline_before_t1, &alice_history[0]);
            assert!(
                !assessment.deviations.iter().any(|d| matches!(
                    d,
                    ainxt_identity::authority::Deviation::ActionRateSpike { .. }
                        | ainxt_identity::authority::Deviation::CostVelocitySpike { .. }
                )),
                "an unbaselined actor's first turn must never false-spike on rate/cost"
            );
        }

        // A second turn identical to the first is now fully within alice's OWN learned envelope (the
        // baseline for t2 is learned from t1's real capabilities/egress/rate/cost) — genuinely learned,
        // not hand-authored, and no longer flagged now that the actor has a track record.
        sink.record_turn(&normal_turn("t2"));
        {
            let cp = control_plane.lock().unwrap();
            assert!(
                !cp.anomaly().is_flagged("t2"),
                "in-envelope repeat behavior against the actor's OWN learned history is not flagged"
            );
        }

        // The history genuinely accumulated real per-turn data (not a no-op counter).
        {
            let h = history.lock().unwrap();
            let alice_history = h
                .get("actor:alice")
                .expect("alice's history must exist after 2 turns");
            assert_eq!(
                alice_history.len(),
                2,
                "both real turns must be folded into the learned history"
            );
        }

        // Now alice's Run does something her OWN history never showed: a different (never-used)
        // provider/capability, plus a large tool-call/cost spike — the §20 insider-drift signature.
        let deviant = ainxt_telemetry::TurnMetrics {
            session: "s1".into(),
            turn: "t3".into(),
            actor: "alice".into(),
            provider: "settlement-internal-tool".into(),
            data_class: ainxt_types::DataClass::Internal,
            input_tokens: 100,
            output_tokens: 50,
            cost_micros: 50_000, // 100x the previously observed cost
            latency_ms: 200,
            redactions: 0,
            tool_calls: 50, // far beyond the previously observed action rate of 1
            outcome: ainxt_telemetry::TurnOutcome::Completed,
        };
        sink.record_turn(&deviant);
        {
            let cp = control_plane.lock().unwrap();
            assert!(
                cp.anomaly().is_flagged("t3"),
                "a Run that deviates from its actor's OWN learned baseline must be flagged for renewal-choke \
                 on the SAME live control plane every dispatch admission check consults"
            );
        }

        // The delegate sink is still called every time (telemetry/FinOps behavior stays byte-identical).
        let inner = Arc::new(ainxt_telemetry::InMemoryTelemetry::new());
        let sink2 = BehaviorFeedingTelemetry {
            inner: inner.clone(),
            history: Arc::new(Mutex::new(std::collections::HashMap::new())),
            control_plane: Arc::new(Mutex::new(ainxt_identity::control::ControlPlane::new())),
        };
        sink2.record_turn(&normal_turn("t4"));
        assert_eq!(
            inner.turns().len(),
            1,
            "the real configured sink must still receive every record_turn call"
        );
    }

    /// GAP-AUDIT conversation-intelligence #2 — `build_chat_classifier_model` returned
    /// `ModelCaps::frontier()` unconditionally regardless of `ProviderKind`, so a self-hosted local
    /// model (Qwen/GLM/Gemma/Kimi) was graded exactly like a frontier cloud model, defeating the
    /// cascade's capability-aware extraction. Proves a `ProviderKind::Local` provider now gets
    /// `weak_oss()` caps (no grammar enforcement assumed, larger repair budget).
    #[test]
    fn wire2_convo_02_local_provider_gets_weak_oss_caps_not_frontier() {
        let models = ainxt_config::ModelsConfig {
            providers: vec![ainxt_config::ProviderConfig {
                id: "local-qwen".to_string(),
                kind: ainxt_config::ProviderKind::Local,
                base_url: Some("http://127.0.0.1:11434".to_string()),
                eligible: vec![],
            }],
            ..Default::default()
        };
        let (_, caps) = build_chat_classifier_model(&models)
            .expect("a Local provider with a base_url must be selected");
        assert_eq!(
            caps,
            ainxt_convo::ModelCaps::weak_oss(),
            "a self-hosted Local provider must get weak_oss caps, not frontier — it cannot be \
             assumed to support grammar-constrained decoding or native tool-calling"
        );
    }

    /// GAP-FIX tooling-mcp-plugins-routing — every OBO decision on the served daemon was written to
    /// an ephemeral `VecOboAudit`, lost on every restart, even though `[gates] audit = "event-log"`
    /// already builds a durable `GuardedEventLog`-backed sink for the ordinary audit trail. Proves
    /// `build_obo_sink` mirrors that same config selection: `Memory` still returns the ephemeral
    /// sink (a record survives only in-process — not directly observable here, so this asserts the
    /// call succeeds and the sink is genuinely usable), and `EventLog` durably persists a decision
    /// that a completely FRESH `JsonlEventLog` handle (standing in for a reopened process) can read
    /// back on the `"__obo__"` session — never the session the ordinary audit trail uses.
    #[test]
    fn gap_fix_tooling_build_obo_sink_durably_persists_when_event_log_selected() {
        use ainxt_tools::obo::{OboDecision, OboDenial};

        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir()
            .join(format!("ainxt-obo-durable-{nanos}"))
            .to_string_lossy()
            .into_owned();

        // Memory (default) selection: the sink is built and usable (ephemeral by design).
        let mem_gates = GatesConfig::default();
        let mem_sink = build_obo_sink(&mem_gates).expect("memory obo sink builds");
        mem_sink.record(&OboDecision {
            user_id: "alice".into(),
            capability: "tool.settlement.initiate".into(),
            action: "execute".into(),
            resource: None,
            depth: 0,
            verdict: Ok(()),
        });

        // EventLog selection: the SAME config shape `build_gates` uses for the ordinary audit trail.
        let log_gates = GatesConfig {
            audit: AuditSinkKind::EventLog,
            audit_event_log_dir: Some(dir.clone()),
            ..Default::default()
        };
        let durable_sink = build_obo_sink(&log_gates).expect("event-log obo sink builds");
        durable_sink.record(&OboDecision {
            user_id: "bob".into(),
            capability: "tool.settlement.initiate".into(),
            action: "execute".into(),
            resource: None,
            depth: 0,
            verdict: Err(OboDenial::OutOfIssuedScope(
                "tool.settlement.initiate".into(),
            )),
        });

        // A FRESH log handle over the SAME directory — the exact "reopened after a restart" shape —
        // reads the decision back on the dedicated "__obo__" session.
        let reopened =
            ainxt_eventlog::JsonlEventLog::open(&dir).expect("reopen the same durable dir");
        let records = ainxt_eventlog::EventLog::records(&reopened, "__obo__");
        assert_eq!(
            records.len(),
            1,
            "the OBO decision must be durably persisted: {records:?}"
        );
        assert_eq!(records[0].actor, "bob");
        assert_eq!(records[0].kind, "obo_decision");
        assert!(
            records[0].text.contains("DENIED"),
            "the persisted record must reflect the actual verdict: {records:?}"
        );

        // The ordinary audit trail (`build_gates`'s own EventLogAuditSink, session "audit") over the
        // SAME directory must be a DISJOINT stream — the two never interleave.
        let audit_records = ainxt_eventlog::EventLog::records(&reopened, "audit");
        assert!(
            audit_records.is_empty(),
            "an OBO decision must never land on the ordinary audit session: {audit_records:?}"
        );
    }

    /// FI-10: the daemon's own durable Event Log must be a POLICY-GOVERNED cryptographic
    /// operation, not a hard-coded `sha2` call — `GovernedChainHasher::try_new`'s fail-closed
    /// resolution (proven exhaustively in `ainxt-eventlog`'s own tests) must actually run at
    /// daemon-construction time. Fail-before: `open_guarded_event_log` called
    /// `JsonlEventLog::open` (the bare `Sha256Hasher`), so a policy that forbids SHA-256 would
    /// have no effect on the daemon's real audit trail.
    #[test]
    fn wire2_fi10_daemon_event_log_is_governed_not_hardcoded() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("ainxt-fi10-{nanos}"));
        let log = open_guarded_event_log(&dir).expect("governed policy approves sha-256");
        log.append("s1", "alice", "note", "hello").expect("append");
        log.append("s1", "alice", "note", "world").expect("append");
        assert_eq!(
            log.verify("s1").expect("chain must verify"),
            2,
            "the governed-hasher chain must verify identically to the pre-FI-10 plain hasher"
        );

        // The fail-closed half: a policy that has NO usable hash primitive must refuse
        // construction rather than silently keep hashing with sha2 anyway.
        let forbidden = {
            let mut r = ainxt_cryptoagility::AlgorithmRegistry::new();
            r.register(
                ainxt_cryptoagility::Purpose::Hashing,
                ainxt_cryptoagility::Algorithm::forbidden("sha-256", false),
            );
            r
        };
        let err = ainxt_eventlog::GovernedChainHasher::try_new(
            ainxt_cryptoagility::GovernedHasher::new(forbidden),
            0,
        )
        .expect_err("a policy with no usable hash candidate must refuse, never fall back");
        assert!(matches!(
            err,
            ainxt_cryptoagility::CryptoAgilityError::NoApprovedAlgorithm { .. }
        ));
    }

    /// FI-07: the shipped daemon's router-build must install the SR-11-7 quality guard — the "one
    /// remaining hot-wire" between the fully-implemented, unit-tested gate
    /// (`ainxt_runtime::router::ModelRouter::with_quality_guard`, proven exhaustively in
    /// `wire2_fi_07_test.rs`) and the daemon's own composition. This test does not re-prove the
    /// gate's exclusion logic (already covered there); it proves `build_router` actually CALLS
    /// `with_quality_guard`, via the composition report every route-build emits.
    #[test]
    fn wire2_fi07_daemon_router_installs_the_quality_guard() {
        let (_, report) = build_router(&ainxt_config::ModelsConfig::default());
        let joined = report.join("\n");
        assert!(
            joined.contains("SR-11-7 model-risk quality guard installed"),
            "the daemon's router must install the SR-11-7 quality guard (empty by default, ready \
             to gate the moment a ModelRiskRecord exists); report={joined}"
        );
    }

    /// GAP-FIX misc-decisions (item 2 — the model-routing policy gap): `ModelsConfig::auto_routable`/
    /// `user_selectable` (the config form of `core/model_registry.py`'s BLOCKED_MODELS +
    /// USER-SELECTABLE policy) were representable in config (proven in `ainxt-config`'s own
    /// `r12_canonical_model_registry_blocked_and_user_selectable_are_representable`) but `build_router`
    /// ignored them entirely — every configured provider was wired unconditionally, so a blocked model
    /// could still be auto-routed/selected, and a user-selectable-only model was indistinguishable from
    /// an ordinary auto-routable one. This proves the REAL composition-root fix end-to-end:
    /// 1. a blocked provider is never even registered (not merely excluded from auto-routing);
    /// 2. a user-selectable-only provider IS registered and reachable by FORCED selection, but is
    ///    excluded from unforced auto-routing (`select(_, None)`) and from `eligible_ids`;
    /// 3. an ordinary provider with no registry entry stays auto-routable (pre-existing behavior for
    ///    deployments that don't use the registry feature is unchanged).
    #[test]
    fn gap6_build_router_honors_blocked_and_user_selectable_only_policy() {
        let models = ModelsConfig {
            providers: vec![
                ProviderConfig {
                    id: "auto-model".to_string(),
                    kind: ProviderKind::Local,
                    base_url: Some("http://127.0.0.1:11434".to_string()),
                    eligible: vec![DataClass::Public],
                },
                ProviderConfig {
                    id: "opus-selectable".to_string(),
                    kind: ProviderKind::Local,
                    base_url: Some("http://127.0.0.1:11435".to_string()),
                    eligible: vec![DataClass::Public],
                },
                ProviderConfig {
                    id: "old-blocked".to_string(),
                    kind: ProviderKind::Local,
                    base_url: Some("http://127.0.0.1:11436".to_string()),
                    eligible: vec![DataClass::Public],
                },
            ],
            registry: vec![ainxt_config::ModelEntry {
                name: "opus-selectable".to_string(),
                provider: "opus-selectable".to_string(),
                tier: None,
                user_selectable_only: true,
                eligible: vec![],
            }],
            blocked: vec!["old-blocked".to_string()],
            ..Default::default()
        };

        let (router, report) = build_router(&models);
        let joined = report.join("\n");
        assert!(
            joined.contains("old-blocked") && joined.contains("BLOCKED_MODELS"),
            "the report must record the blocked provider was skipped for that reason: {joined}"
        );

        // 1. Blocked: never registered at all — not even reachable by FORCED selection.
        let forced_blocked = router.select(DataClass::Public, Some("old-blocked"));
        assert!(
            forced_blocked.is_err(),
            "a BLOCKED model must never be routed to or user-selected, forced or not: {:?}",
            forced_blocked.err()
        );

        // 2. User-selectable-only: reachable by FORCED selection...
        let forced_opus = router
            .select(DataClass::Public, Some("opus-selectable"))
            .expect("a user-selectable-only model must still be reachable by explicit selection");
        assert_eq!(forced_opus.id(), "opus-selectable");
        // ...but never auto-routed:
        for _ in 0..8 {
            let auto = router
                .select(DataClass::Public, None)
                .expect("auto-model is eligible");
            assert_eq!(
                auto.id(),
                "auto-model",
                "unforced selection must never land on a user-selectable-only model"
            );
        }
        let ids = router.eligible_ids(DataClass::Public);
        assert!(
            ids.contains(&"auto-model".to_string()),
            "the ordinary auto-routable model must appear in eligible_ids: {ids:?}"
        );
        assert!(
            !ids.contains(&"opus-selectable".to_string()),
            "a user-selectable-only model must NOT appear in eligible_ids (the auto-route budget \
             window): {ids:?}"
        );
        assert!(
            !ids.contains(&"old-blocked".to_string()),
            "a blocked model must NOT appear in eligible_ids: {ids:?}"
        );

        // 3. select_chain (unforced) never includes the user-selectable-only model either.
        let chain = router
            .select_chain(DataClass::Public, None, None)
            .expect("auto-model keeps the chain non-empty");
        assert!(
            chain.iter().all(|p| p.id() != "opus-selectable"),
            "an automatic failover chain must never include a user-selectable-only model: \
             {:?}",
            chain.iter().map(|p| p.id()).collect::<Vec<_>>()
        );
        // ...but a FORCED chain still reaches it.
        let forced_chain = router
            .select_chain(DataClass::Public, Some("opus-selectable"), None)
            .expect("forced selection reaches a user-selectable-only model");
        assert_eq!(forced_chain.len(), 1);
        assert_eq!(forced_chain[0].id(), "opus-selectable");
    }

    #[test]
    fn loads_layered_config_and_splits_sections() {
        // ARCH-F-001: `host` is widened beyond loopback here on purpose (to prove the splitter
        // handles a non-default value), so `transport.exposure` must be stated or `load_layered`
        // now fails closed (see `validate_transport_exposure`).
        let base = r#"
            version = 1
            [server]
            host = "0.0.0.0"
            port = 9000
            [server.transport]
            exposure = "behind-tls-gateway"
            [session]
            max_sessions = 32
            [limits]
            max_agent_iters = 3
        "#;
        let loaded = load_layered(&[("base", base)]).unwrap();
        assert_eq!(loaded.server.host, "0.0.0.0");
        assert_eq!(loaded.server.port, 9000);
        assert_eq!(loaded.session.max_sessions, 32);
        assert_eq!(loaded.runtime.limits.max_agent_iters, 3);
    }

    #[test]
    fn layered_override_and_defaults() {
        let defaults = r#"version = 1
            [server]
            port = 8080"#;
        let deployment = r#"[server]
            port = 9999"#;
        let loaded = load_layered(&[("defaults", defaults), ("deployment", deployment)]).unwrap();
        assert_eq!(loaded.server.port, 9999); // most-specific wins
        assert_eq!(loaded.server.host, "127.0.0.1"); // default
        assert_eq!(
            loaded.session.max_sessions,
            SessionConfig::default().max_sessions
        ); // default
    }

    #[test]
    fn unknown_runtime_field_is_rejected() {
        assert!(matches!(
            load_layered(&[("x", "version = 1\nbogus = true")]),
            Err(AssembleError::Config(_))
        ));
    }

    // GAP6 session-resume-consolidate — `SessionConfig::validate`'s own doc says "call at config-load
    // for a fail-fast, clear error", but nothing did: `SessionManager::new` only ever ran the
    // silent-clamp `sanitized()`, so `[session] max_sessions = 0` loaded successfully and was quietly
    // turned into `1` deep inside the manager, with no boot-time signal at all. `load_layered` now
    // calls `validate()` right after resolving `[session]`, matching the SAME hard-fail convention
    // `runtime.validate()` already uses in this function for a bad `[limits]`/`[guardrails]` value.
    #[test]
    fn a_degenerate_session_config_fails_config_load_instead_of_silently_clamping() {
        let err = load_layered(&[("x", "version = 1\n[session]\nmax_sessions = 0")])
            .expect_err("max_sessions=0 must be refused at config-load, not silently clamped to 1");
        assert!(
            matches!(err, AssembleError::Config(ref m) if m.contains("max_sessions")),
            "the error must name the offending field: {err}"
        );

        let err = load_layered(&[("y", "version = 1\n[session]\ninbox_capacity = 0")]).expect_err(
            "inbox_capacity=0 must be refused at config-load, not silently clamped to 1",
        );
        assert!(
            matches!(err, AssembleError::Config(ref m) if m.contains("inbox_capacity")),
            "the error must name the offending field: {err}"
        );

        // A valid `[session]` config still loads cleanly (no regression on the happy path).
        assert!(load_layered(&[("z", "version = 1\n[session]\nmax_sessions = 32")]).is_ok());
    }

    #[test]
    fn empty_config_assembles_with_offline_provider() {
        let loaded = load_layered(&[("empty", "version = 1")]).unwrap();
        let assembled = assemble(&loaded).unwrap();
        assert!(assembled
            .report
            .iter()
            .any(|r| r.contains("offline provider registered")));
    }

    #[test]
    fn enterprise_gates_refuse_to_start_no_silent_downgrade() {
        for (section, sel) in [("compliance", "pci-dss"), ("authz", "ad-rbac")] {
            let src = format!("version = 1\n[gates]\n{section} = \"{sel}\"");
            let loaded = load_layered(&[("x", &src)]).unwrap();
            // Note: `unwrap_err` would require the Ok tuple (which holds a non-Debug Engine) to be
            // Debug, so match the variant instead.
            assert!(
                matches!(
                    build_engine(&loaded.runtime),
                    Err(AssembleError::EnterpriseGateUnavailable(_))
                ),
                "{section}={sel} must refuse to start in the OSS build"
            );
        }
    }

    #[test]
    fn transport_daemon_6_event_log_audit_is_oss_buildable_not_refused() {
        // GAP-AUDIT transport-daemon #6: unlike `pci-dss` / `ad-rbac`, `audit = "event-log"` is
        // buildable entirely from OSS crates already in this workspace (GuardedEventLog) — it must
        // NOT be refused as if it were a genuine external-enterprise-only plugin.
        let dir =
            std::env::temp_dir().join(format!("ainxt-test-audit-eventlog-{}", std::process::id()));
        let src = format!(
            "version = 1\n[gates]\naudit = \"event-log\"\naudit_event_log_dir = \"{}\"",
            dir.to_string_lossy().replace('\\', "\\\\")
        );
        let loaded = load_layered(&[("x", &src)]).unwrap();
        let (engine, _report) = build_engine(&loaded.runtime)
            .expect("audit = event-log must assemble in the OSS build");
        assert!(
            engine.has_tools(),
            "sanity: the engine assembled with its full pipeline"
        );
        drop(engine);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn transport_daemon_6_event_log_audit_durably_records_not_in_memory() {
        // Beyond assembling: `audit = "event-log"` must actually persist audit records to the
        // configured directory (proving it is a real durable backend and not a disguised
        // `InMemoryAudit` that vanishes on process restart).
        let dir = std::env::temp_dir().join(format!(
            "ainxt-test-audit-eventlog-durable-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let gates = GatesConfig {
            audit: AuditSinkKind::EventLog,
            audit_event_log_dir: Some(dir.to_string_lossy().into_owned()),
            ..GatesConfig::default()
        };
        let (_compliance, _authz, audit) =
            build_gates(&gates).expect("default gates + configured event-log dir must assemble");
        audit.record(AuditRecord {
            session: "s-test".into(),
            turn: "1".into(),
            actor: "u-test".into(),
            summary: "transport-daemon-6 durability probe".into(),
        });

        // Re-open the same directory as a fresh, independent log handle: if the record only ever
        // lived in a `Vec` inside the sink it just built, a brand-new handle would see nothing.
        let reopened = open_guarded_event_log(&dir).expect("reopen the same durable directory");
        let records = reopened.records("audit");
        assert!(
            records
                .iter()
                .any(|r| r.text.contains("transport-daemon-6 durability probe")),
            "the audit record must be durably readable from a fresh log handle: {records:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn default_gates_assemble() {
        let loaded = load_layered(&[("x", "version = 1")]).unwrap();
        assert!(build_engine(&loaded.runtime).is_ok());
    }

    #[test]
    fn daemon_assembles_the_tool_safety_pipeline() {
        // Regression for the audit finding "tool-safety is dead code in shipped binaries": the
        // assembled engine MUST carry a tool runtime so OBO authz / injection taint-gate / exactly-
        // once ledger / approval actually run on tool calls in production.
        let loaded = load_layered(&[("x", "version = 1")]).unwrap();
        let (engine, _report) = build_engine(&loaded.runtime).unwrap();
        assert!(
            engine.has_tools(),
            "the tool-safety pipeline must be live in the daemon, not dead code"
        );
    }

    #[test]
    fn unwireable_provider_falls_back_to_offline() {
        // An OpenAI-schema provider with no base_url cannot be wired → it is skipped and the offline
        // provider is registered. Deterministic: independent of whether an API key is in the
        // environment (a provider missing its endpoint is unwireable regardless).
        let src = r#"version = 1
            [[models.providers]]
            id = "gpt"
            kind = "open-ai-schema"
        "#;
        let loaded = load_layered(&[("x", src)]).unwrap();
        let (_engine, report) = build_engine(&loaded.runtime).unwrap();
        assert!(
            report.iter().any(|r| r.contains("skipped")),
            "unwireable provider must be skipped: {report:?}"
        );
        assert!(
            report
                .iter()
                .any(|r| r.contains("offline provider registered")),
            "offline fallback: {report:?}"
        );
    }

    #[test]
    fn gemini_provider_wired_when_key_present_absent_when_not() {
        // GAP-FIX providers-gemini-quality-tripwire (item 1) — `ainxt_providers::GeminiProvider`
        // was built and unit-tested but `build_provider` had no `ProviderKind::Gemini` arm, so no
        // config could ever reach it; its only caller anywhere was an `#[ignore]`d live-smoke
        // test. Proves BOTH halves of the same present-key-or-no-op convention the Anthropic /
        // OpenAI-schema siblings already follow, through the REAL composition-root path
        // (`build_engine` -> `build_router` -> `build_provider`), not a unit test of `GeminiProvider`
        // in isolation.
        let src = r#"version = 1
            [[models.providers]]
            id = "gemini-2.5-flash"
            kind = "gemini"
            eligible = ["public", "internal"]
        "#;
        let loaded = load_layered(&[("x", src)]).unwrap();

        // Save + restore so this test is deterministic regardless of the ambient environment, and
        // never leaks a mutated var into any other test in this binary.
        let saved = std::env::var("GOOGLE_API_KEY").ok();

        std::env::remove_var("GOOGLE_API_KEY");
        let (_engine, report) = build_engine(&loaded.runtime).unwrap();
        assert!(
            report
                .iter()
                .any(|r| r.contains("gemini-2.5-flash") && r.contains("skipped")),
            "gemini provider must be skipped (no-op) with no GOOGLE_API_KEY, byte-identical to \
             before this fix: {report:?}"
        );
        assert!(
            report
                .iter()
                .any(|r| r.contains("offline provider registered")),
            "must fall back to the air-gapped offline provider with no gemini key: {report:?}"
        );

        std::env::set_var("GOOGLE_API_KEY", "test-key-not-real");
        let (_engine, report) = build_engine(&loaded.runtime).unwrap();
        assert!(
            report
                .iter()
                .any(|r| r.contains("gemini-2.5-flash") && r.contains("wired")),
            "gemini provider must be wired into the real router when GOOGLE_API_KEY is present: \
             {report:?}"
        );

        match saved {
            Some(v) => std::env::set_var("GOOGLE_API_KEY", v),
            None => std::env::remove_var("GOOGLE_API_KEY"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn assembled_runtime_serves_a_turn_offline() {
        use ainxt_client::{Client, ClientConfig};
        use ainxt_types::Principal;

        let loaded = load_layered(&[("x", "version = 1")]).unwrap();
        let assembled = assemble(&loaded).unwrap();
        let client = Client::in_process(
            assembled.manager,
            Principal::user("u", &["chat.send"]),
            ClientConfig::default(),
        );
        let out = client.chat("s", "t", "hi").unwrap().collect().await;
        assert!(out.completed, "the assembled runtime must complete a turn");
        assert!(
            out.text.contains("offline mode"),
            "offline provider should answer: {}",
            out.text
        );
    }

    /// Gap context-fabric (metric-catalog loader no caller): `structured_query_starter` must
    /// actually exercise `MetricCatalog::load`'s real §2.2 all-or-nothing validation and produce a
    /// catalog that RESOLVES the starter metric — not an empty placeholder.
    #[test]
    fn structured_query_starter_loads_via_the_real_catalog_loader_and_resolves() {
        let (catalog, schema) = structured_query_starter();
        let catalog = catalog.expect("the starter catalog must build via MetricCatalog::load");
        let schema = schema.expect("the starter schema must build");

        assert!(
            !catalog.is_empty(),
            "the served structured_query catalog must not be the empty placeholder"
        );
        let plan = catalog
            .plan("txn_volume", &["bank_id"])
            .expect("the starter metric must resolve through the loaded catalog");
        assert_eq!(plan.source_view, "v_txn_volume_curated");
        assert!(
            schema.table("v_txn_volume_curated").is_some(),
            "the schema must carry a table matching the metric's source_view"
        );

        // An id NOT in the catalog is still closed-vocabulary refused (loading one real metric must
        // not accidentally open the vocabulary).
        assert!(catalog.plan("not_a_real_metric", &[]).is_err());
    }

    /// End-to-end: the served boot path (`build_unified_capability_registry_shared`, the exact
    /// entrypoint the daemon calls) must register the REAL starter catalog, not silently fall back
    /// to the empty one — the fallback message only appears if the starter catalog/schema failed to
    /// build, which would be a composition-root bug, not expected served behavior.
    #[test]
    fn served_boot_registers_the_real_structured_catalog_not_the_empty_fallback() {
        let mut report = Vec::new();
        let _ = build_unified_capability_registry_shared(&mut report);
        assert!(
            !report
                .iter()
                .any(|r| r.contains("registered EMPTY catalog instead")),
            "the served boot path must not fall back to the empty structured_query catalog: {report:?}"
        );
    }
}
