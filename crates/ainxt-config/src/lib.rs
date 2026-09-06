// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! ainxt-config — layered, schema-validated runtime configuration (ADR-004, Part A1).
//!
//! **Config-first, safety-invariant.** Everything the runtime does is declarative and
//! configurable — models/providers, routing, limits, budgets, guardrails, telemetry — merged
//! from ordered layers with the most specific winning:
//!
//! ```text
//! built-in defaults → deployment → tenant/org → surface profile → per-request overrides
//! ```
//!
//! The ONE thing you cannot express is a runtime with a mandatory gate removed. Compliance,
//! authorization, and audit are **selectable, never removable**: [`GatesConfig`] lets you pick
//! WHICH provider runs each gate, but there is no `off`/`enabled=false` variant anywhere in the
//! type. A config that tries to disable a gate fails to parse. This mirrors the engine, where
//! the gates are required constructor arguments — config cannot weaken that invariant.
//!
//! The layer-merge operates on `toml::Value` (deep table merge; scalars/arrays: later wins),
//! then deserializes into the typed [`RuntimeConfig`] — so both the merge and the schema are
//! deterministic and testable.

use std::collections::HashSet;
use std::fmt;

use ainxt_types::DataClass;
use serde::Deserialize;

pub use ainxt_guardrails::GuardrailsConfig;
pub use ainxt_injection::InjectionConfig;
pub use ainxt_prompt::policy::PolicyEngineConfig;
pub use ainxt_prompt::steerability::SteerabilityConfig;
pub use ainxt_prompt::PromptConfig;
pub use ainxt_telemetry::TelemetryConfig;

/// The config schema version this build understands. Bump on breaking schema changes.
pub const CONFIG_VERSION: u32 = 1;
/// Hard ceiling on the agent-loop iteration cap, regardless of config (defense in depth).
pub const MAX_AGENT_ITERS_CEILING: usize = 64;
/// Hard ceiling on `limits.max_input_bytes`, regardless of config (defense in depth). The
/// request-size guard itself must not be configurable into an unbounded value.
pub const MAX_INPUT_BYTES_CEILING: usize = 64 * 1024 * 1024;

fn default_version() -> u32 {
    CONFIG_VERSION
}

// ============================ errors ============================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// A layer failed to parse as TOML, or the merged config failed to deserialize.
    Parse(String),
    /// The config parsed but violates a validation rule.
    Invalid(String),
    /// The config declares a schema version this build does not support.
    UnsupportedVersion(u32),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Parse(m) => write!(f, "config parse error: {m}"),
            ConfigError::Invalid(m) => write!(f, "invalid config: {m}"),
            ConfigError::UnsupportedVersion(v) => {
                write!(
                    f,
                    "unsupported config version {v} (this build supports {CONFIG_VERSION})"
                )
            }
        }
    }
}

impl std::error::Error for ConfigError {}

// ============================ typed schema ============================

/// The fully-resolved runtime configuration (the product of merging all layers).
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfig {
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default)]
    pub models: ModelsConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
    /// Additional guardrail rails (ADR-008). Default OFF.
    #[serde(default)]
    pub guardrails: GuardrailsConfig,
    /// Prompt-injection defense (ADR-009). Default OFF.
    #[serde(default)]
    pub injection: InjectionConfig,
    /// Observability sink + cost-attribution price table (gap J/V). Default: Null sink, no prices.
    #[serde(default)]
    pub telemetry: TelemetryConfig,
    /// Prompt Engine (BE/BH/BG): reasoning depth, numeric discipline, output format, system role.
    #[serde(default)]
    pub prompt: PromptConfig,
    /// Mandatory-gate provider SELECTION (never removal).
    #[serde(default)]
    pub gates: GatesConfig,
    /// L2 org/config policy body (`PROMPT_ENGINEERING.md` §2) — config-sourced, not hardcoded: a
    /// deployment/tenant layer can override the shipped-default L2 text (e.g. a new RBI disclosure
    /// requirement) without a code change or crate redeploy. Resolved through the SAME layered merge
    /// as every other config domain here.
    #[serde(default)]
    pub policy: PolicyEngineConfig,
    /// Steerability / instruction-following model-eligibility gate (§9, PE7) — config-sourced measured
    /// per-family scores + minimum bar. Empty `scores` (default, no `[steerability]` layer) means the
    /// gate is inactive: byte-for-byte the pre-existing unfiltered served family list.
    #[serde(default)]
    pub steerability: SteerabilityConfig,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        RuntimeConfig {
            version: CONFIG_VERSION,
            models: ModelsConfig::default(),
            limits: LimitsConfig::default(),
            guardrails: GuardrailsConfig::default(),
            injection: InjectionConfig::default(),
            telemetry: TelemetryConfig::default(),
            prompt: PromptConfig::default(),
            gates: GatesConfig::default(),
            policy: PolicyEngineConfig::default(),
            steerability: SteerabilityConfig::default(),
        }
    }
}

impl RuntimeConfig {
    /// Validate structural invariants that types alone can't express.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.version != CONFIG_VERSION {
            return Err(ConfigError::UnsupportedVersion(self.version));
        }
        let iters = self.limits.max_agent_iters;
        if iters == 0 || iters > MAX_AGENT_ITERS_CEILING {
            return Err(ConfigError::Invalid(format!(
                "limits.max_agent_iters must be 1..={MAX_AGENT_ITERS_CEILING} (got {iters})"
            )));
        }
        if self.limits.stream_channel_bound == 0 {
            return Err(ConfigError::Invalid(
                "limits.stream_channel_bound must be >= 1".into(),
            ));
        }
        if self.limits.provider_max_retries > 10 {
            return Err(ConfigError::Invalid(
                "limits.provider_max_retries must be <= 10".into(),
            ));
        }
        if self.limits.max_input_bytes == 0 || self.limits.max_input_bytes > MAX_INPUT_BYTES_CEILING
        {
            return Err(ConfigError::Invalid(format!(
                "limits.max_input_bytes must be 1..={MAX_INPUT_BYTES_CEILING} (got {})",
                self.limits.max_input_bytes
            )));
        }
        if self.limits.provider_backoff_base_ms > 60_000 {
            return Err(ConfigError::Invalid(
                "limits.provider_backoff_base_ms must be <= 60000".into(),
            ));
        }
        // An empty L2 body would silently drop the org/compliance policy layer from every served
        // Role — a misconfigured deployment/tenant layer must fail closed, not serve with a missing
        // policy clause.
        if self.policy.l2_body.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "policy.l2_body must not be empty (would silently drop the L2 policy layer)".into(),
            ));
        }
        // The steerability bar is a pass-RATE (0.0-1.0, §9); a caller that mistypes a percentage
        // (e.g. `90`) must fail closed at config load, not silently gate every family out (>1.0) or
        // let every family through unmeasured (a negative bar).
        if !(0.0..=1.0).contains(&self.steerability.min_bar) {
            return Err(ConfigError::Invalid(format!(
                "steerability.min_bar must be within 0.0..=1.0 (got {})",
                self.steerability.min_bar
            )));
        }
        for s in &self.steerability.scores {
            if s.model_family.trim().is_empty() {
                return Err(ConfigError::Invalid(
                    "a steerability.scores entry has an empty model_family".into(),
                ));
            }
        }
        let mut seen = HashSet::new();
        for p in &self.models.providers {
            if p.id.trim().is_empty() {
                return Err(ConfigError::Invalid("a provider has an empty id".into()));
            }
            if !seen.insert(p.id.as_str()) {
                return Err(ConfigError::Invalid(format!(
                    "duplicate provider id '{}'",
                    p.id
                )));
            }
        }
        // Model registry (the canonical-model policy in config form): names are unique, each entry
        // references a declared provider, and a registered model may not also be blocked (declare it
        // one way or the other — a model that is both listed and forbidden is a contradiction).
        let mut model_names = HashSet::new();
        for m in &self.models.registry {
            if m.name.trim().is_empty() {
                return Err(ConfigError::Invalid(
                    "a model registry entry has an empty name".into(),
                ));
            }
            if !model_names.insert(m.name.as_str()) {
                return Err(ConfigError::Invalid(format!(
                    "duplicate model registry entry '{}'",
                    m.name
                )));
            }
            if !seen.contains(m.provider.as_str()) {
                return Err(ConfigError::Invalid(format!(
                    "model '{}' references undeclared provider '{}'",
                    m.name, m.provider
                )));
            }
            if self.models.is_blocked(&m.name) {
                return Err(ConfigError::Invalid(format!(
                    "model '{}' is both registered and blocked (a blocked model must not also be a \
                     live registry entry)",
                    m.name
                )));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelsConfig {
    #[serde(default)]
    pub providers: Vec<ProviderConfig>,
    /// Default tier hint when a request doesn't specify one (advisory; router decides).
    #[serde(default)]
    pub default_tier: Option<String>,
    /// The **canonical model registry** — the config-representable form of the platform's model
    /// policy (`core/model_registry.py`): each entry names a canonical model, the provider that
    /// serves it, the routing tier it belongs to, and whether it is *user-selectable only* (offered
    /// for explicit selection but never auto-routed). Empty = the deployment routes purely by
    /// provider (no per-model policy). See [`ModelEntry`].
    #[serde(default)]
    pub registry: Vec<ModelEntry>,
    /// **BLOCKED_MODELS** — canonical model names that are retired/forbidden and must NEVER be routed
    /// to or user-selected, regardless of the registry. Authoritative: a name here overrides any
    /// registry entry (a blocked model is excluded from [`ModelsConfig::auto_routable`] and
    /// [`ModelsConfig::user_selectable`] even if it appears in [`registry`](ModelsConfig::registry)).
    /// This is the config form of the platform's hard block-list (e.g. `claude-opus-4-5` and older,
    /// retired `gpt-5.2*`).
    #[serde(default)]
    pub blocked: Vec<String>,
}

impl ModelsConfig {
    /// Whether `model` is on the BLOCKED_MODELS list (never routable, never selectable).
    pub fn is_blocked(&self, model: &str) -> bool {
        self.blocked.iter().any(|b| b == model)
    }

    /// Look up a canonical registry entry by model name.
    pub fn canonical(&self, model: &str) -> Option<&ModelEntry> {
        self.registry.iter().find(|e| e.name == model)
    }

    /// The registry entries the router may **auto-route** to: registered, not blocked, and not
    /// user-selectable-only. This is the set the complexity→tier router draws from.
    pub fn auto_routable(&self) -> Vec<&ModelEntry> {
        self.registry
            .iter()
            .filter(|e| !e.user_selectable_only && !self.is_blocked(&e.name))
            .collect()
    }

    /// Whether `model` may be chosen by **explicit user selection** — it is registered and not
    /// blocked. (A user-selectable-only model is selectable but not auto-routed; a normal routable
    /// model is both selectable and auto-routed; a blocked model is neither.)
    pub fn user_selectable(&self, model: &str) -> bool {
        !self.is_blocked(model) && self.canonical(model).is_some()
    }
}

/// A single canonical model in the [`ModelsConfig::registry`]. The config-representable projection of
/// the platform's per-model policy: which provider serves it, which routing tier it belongs to, and
/// whether it is offered for explicit user selection only (never auto-routed).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelEntry {
    /// The canonical model name (e.g. `claude-sonnet-4-6`, `gpt-5.4`).
    pub name: String,
    /// The id of the [`ProviderConfig`] that serves this model. Validated to exist.
    pub provider: String,
    /// The routing tier this model serves (`simple` / `medium` / `complex` / …). Advisory to the
    /// router; `None` means the model is not tied to a tier (typically a user-selectable-only model).
    #[serde(default)]
    pub tier: Option<String>,
    /// When true the model is offered for **explicit user selection only** and is never auto-routed
    /// (the platform's USER-SELECTABLE list, e.g. `claude-opus-4-7`, `gpt-5-5`).
    #[serde(default)]
    pub user_selectable_only: bool,
    /// Data classes this specific model may serve (ADR-012, per-model ceiling). Empty = defer to the
    /// provider's own eligibility. Never a widening: routing still intersects the provider gate.
    #[serde(default)]
    pub eligible: Vec<DataClass>,
}

/// A declared model provider. The runtime's provider factory consumes this to build the actual
/// `Provider` trait object; the data-class eligibility feeds the (non-overridable) router gate.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfig {
    pub id: String,
    pub kind: ProviderKind,
    #[serde(default)]
    pub base_url: Option<String>,
    /// Data classes this provider may serve (ADR-012). Empty = the deployment must treat it as
    /// public/internal only; regulated/PII data will never route here unless listed.
    #[serde(default)]
    pub eligible: Vec<DataClass>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderKind {
    /// OpenAI-compatible schema (OpenAI / vLLM / Groq / most local servers).
    OpenAiSchema,
    Anthropic,
    /// Google Gemini `:streamGenerateContent` (generative-language API).
    Gemini,
    /// A locally-hosted model (in-house OSS: Qwen/GLM/Gemma/Kimi).
    Local,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsConfig {
    /// Agent-loop hard iteration cap (defense in depth; also ceilinged at compile time).
    #[serde(default = "default_max_iters")]
    pub max_agent_iters: usize,
    /// Bounded stream channel capacity (backpressure).
    #[serde(default = "default_channel_bound")]
    pub stream_channel_bound: usize,
    /// Maximum accepted input size in bytes (huge-input guard).
    #[serde(default = "default_max_input")]
    pub max_input_bytes: usize,
    /// How many times to retry the SAME provider on a retryable error before failing over.
    #[serde(default = "default_provider_retries")]
    pub provider_max_retries: usize,
    /// Exponential-backoff base (ms) between same-provider retries; 0 = no delay.
    #[serde(default = "default_provider_backoff_ms")]
    pub provider_backoff_base_ms: u64,
    /// Hard dollar ceiling (micro-USD; 1 USD = 1_000_000) across a served Team run's rolled-up
    /// sub-agent cost (LOOP-12/LOOP §4). `None` (default) = unbounded — a deployment opts in.
    /// Other cost dimensions (tokens/tool_calls/wall_time) stay unbounded when only this is set.
    #[serde(default)]
    pub team_run_cost_ceiling_dollars_micros: Option<u64>,
    /// GAP-AUDIT loop-teams-longhorizon (gap 5) — the total concurrent-module GPU/inference-fleet
    /// slots this deployment's fleet provides, feeding `ainxt_planner::qos::ElasticFanoutPolicy` to
    /// decide the served long-horizon Program driver's parallel fan-out width (LONG_HORIZON §7).
    /// `None` (default) keeps the served Program driver strictly sequential (wave ceiling 1) —
    /// byte-identical to the pre-wire behavior; a deployment opts in to real parallel fan-out by
    /// declaring its fleet size. The LIVE in-flight-usage / higher-priority-queued fleet telemetry
    /// stays infra-gated (`needs_hot_wiring`); this config seeds the policy's static capacity input.
    #[serde(default)]
    pub program_fan_out_fleet_slots: Option<usize>,
    /// GAP-FIX loop-teams-longhorizon (gap 1a) — the directory a served `--surface program` daemon
    /// persists its Program state under (a hash-chained JSONL event log per `{session}_{turn}`, via
    /// `ainxt_eventlog::ProgramEventSink`). `None` (default) keeps the served path in-memory-only
    /// (byte-identical to the pre-wire behavior: a daemon crash mid-Program loses the entire in-flight
    /// Run). Setting this makes `assemble_program_surface_with_transparency` call
    /// `ProgramSurface::with_durable_dir`, so the SAME served daemon a real deployment runs gets
    /// crash-resumable Programs — `ProgramSurface::with_durable_dir` existed and was proven only via a
    /// direct-constructor test; no config knob ever reached it from the served composition root.
    #[serde(default)]
    pub program_durable_dir: Option<String>,
}

fn default_max_iters() -> usize {
    4
}
fn default_channel_bound() -> usize {
    64
}
fn default_max_input() -> usize {
    1_000_000
}
fn default_provider_retries() -> usize {
    2
}
fn default_provider_backoff_ms() -> u64 {
    20
}

impl Default for LimitsConfig {
    fn default() -> Self {
        LimitsConfig {
            max_agent_iters: default_max_iters(),
            stream_channel_bound: default_channel_bound(),
            max_input_bytes: default_max_input(),
            provider_max_retries: default_provider_retries(),
            provider_backoff_base_ms: default_provider_backoff_ms(),
            team_run_cost_ceiling_dollars_micros: None,
            program_fan_out_fleet_slots: None,
            program_durable_dir: None,
        }
    }
}

/// **Mandatory-gate provider selection — the safety invariant made a type.**
///
/// There is deliberately NO field to disable a gate and NO `Off` variant in any of these enums.
/// You choose which implementation runs; you cannot choose to run none. The engine takes the
/// gates as required constructor args, so a config can only ever *select* a provider.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatesConfig {
    #[serde(default)]
    pub compliance: ComplianceProvider,
    #[serde(default)]
    pub authz: AuthzProvider,
    #[serde(default)]
    pub audit: AuditSinkKind,
    /// GAP-AUDIT transport-daemon #6 — the directory `audit = "event-log"` opens its durable,
    /// tamper-evident hash-chained log in. `None` (the default) falls back to a fixed path under
    /// the OS temp dir — set this to pin the durable audit trail somewhere persistent.
    #[serde(default)]
    pub audit_event_log_dir: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ComplianceProvider {
    /// The OSS default redact-and-proceed detector.
    #[default]
    Default,
    /// enterprise PCI/DSS engine (private enterprise plugin).
    PciDss,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthzProvider {
    /// Capability-based RBAC (OSS default).
    #[default]
    Rbac,
    /// AD-backed RBAC (private enterprise plugin).
    AdRbac,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuditSinkKind {
    /// In-memory (dev/test).
    #[default]
    Memory,
    /// Durable tamper-evident event log.
    EventLog,
}

// ============================ layer merge + loader ============================

/// Deep-merge two TOML values: tables merge key-by-key (recursively); any other value (scalar,
/// array, or a type mismatch) is replaced by `over`. `over` is the more-specific layer.
pub fn merge_toml(base: toml::Value, over: toml::Value) -> toml::Value {
    match (base, over) {
        (toml::Value::Table(mut b), toml::Value::Table(o)) => {
            for (k, ov) in o {
                let merged = match b.remove(&k) {
                    Some(bv) => merge_toml(bv, ov),
                    None => ov,
                };
                b.insert(k, merged);
            }
            toml::Value::Table(b)
        }
        (_, over) => over,
    }
}

/// Accumulates config layers in precedence order and resolves the typed config.
///
/// Layers are applied in the order they are added; a later layer overrides an earlier one. Use
/// the named helpers ([`Loader::defaults`], [`Loader::deployment`], …) to make the canonical
/// ordering explicit, or [`Loader::layer`] for an arbitrarily-named layer.
#[derive(Debug, Default)]
pub struct Loader {
    layers: Vec<(String, toml::Value)>,
}

impl Loader {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a named TOML layer (parsed now; a parse error is reported against `name`).
    pub fn layer(mut self, name: &str, toml_src: &str) -> Result<Self, ConfigError> {
        let v: toml::Value =
            toml::from_str(toml_src).map_err(|e| ConfigError::Parse(format!("{name}: {e}")))?;
        self.layers.push((name.to_string(), v));
        Ok(self)
    }

    pub fn layer_value(mut self, name: &str, value: toml::Value) -> Self {
        self.layers.push((name.to_string(), value));
        self
    }

    // Canonical layering helpers (most-specific last).
    pub fn defaults(self, toml_src: &str) -> Result<Self, ConfigError> {
        self.layer("defaults", toml_src)
    }
    pub fn deployment(self, toml_src: &str) -> Result<Self, ConfigError> {
        self.layer("deployment", toml_src)
    }
    pub fn tenant(self, toml_src: &str) -> Result<Self, ConfigError> {
        self.layer("tenant", toml_src)
    }
    pub fn profile(self, toml_src: &str) -> Result<Self, ConfigError> {
        self.layer("profile", toml_src)
    }
    pub fn request(self, toml_src: &str) -> Result<Self, ConfigError> {
        self.layer("request", toml_src)
    }

    /// The merged TOML value across all layers (built-in defaults are supplied by the schema's
    /// serde defaults, so an empty loader still resolves to a valid config).
    pub fn merged(&self) -> toml::Value {
        let mut acc = toml::Value::Table(Default::default());
        for (_, v) in &self.layers {
            acc = merge_toml(acc, v.clone());
        }
        acc
    }

    /// Merge + deserialize into an arbitrary schema type.
    pub fn resolve<T: serde::de::DeserializeOwned>(&self) -> Result<T, ConfigError> {
        self.merged()
            .try_into()
            .map_err(|e: toml::de::Error| ConfigError::Parse(e.to_string()))
    }

    /// Merge + deserialize + validate into the [`RuntimeConfig`].
    pub fn resolve_runtime(&self) -> Result<RuntimeConfig, ConfigError> {
        let cfg: RuntimeConfig = self.resolve()?;
        cfg.validate()?;
        Ok(cfg)
    }
}
