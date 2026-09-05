// SPDX-License-Identifier: MIT
//! Service-wide configuration for `ainxt-injection-svc`.
//!
//! ## Loading order (highest priority wins)
//!
//! 1. **Environment variables** — always checked first.
//! 2. **TOML file** — path given by `AINXT_INJECTION_CONFIG` env var, or the
//!    default `config.toml` in the current working directory.
//!    Missing file is silently ignored.
//!
//! Env-var-driven deployments (systemd, PM2, k8s, Docker) work unchanged.
//! Local development can use `config.toml` without setting any env vars.
//!
//! ## Env var reference
//!
//! | Env var                          | TOML key                        | Default          |
//! |----------------------------------|---------------------------------|------------------|
//! | `AINXT_INJECTION_SVC_HOST`       | `server.host`                   | `127.0.0.1`      |
//! | `AINXT_INJECTION_SVC_PORT`       | `server.port`                   | `8007`           |
//! | `AINXT_INJECTION_MODE`           | `server.mode`                   | `enforce`        |
//! | `JUDGE_LITELLM_URL`              | `judges.litellm_url`            | *(disabled)*     |
//! | `JUDGE_LITELLM_API_KEY`          | `judges.litellm_api_key`        | *(disabled)*     |
//! | `JUDGE1_MODEL`                   | `judges.judge1_model`           | `judge1`         |
//! | `JUDGE2_MODEL`                   | `judges.judge2_model`           | `judge2`         |
//! | `JUDGE_CONFIDENCE_THRESHOLD`     | `judges.confidence_threshold`   | `0.9`            |
//! | `KEYWORD_SCAN_SAFE_SCORE`               | `keyword_scan.safe_score`                    | `0.1`            |
//! | `KEYWORD_SCAN_BLOCK_SCORE`              | `keyword_scan.block_score`                   | `0.8`            |
//! | `JUDGE_SKIP_CROSS_ON_CONSENSUS`  | `judges.skip_cross_on_consensus`| `true`           |
//! | `JUDGE_TIE_BEHAVIOUR`            | `judges.tie_behaviour`          | `block`          |
//! | `JUDGE_TIMEOUT_MS`               | `judges.timeout_ms`             | `30000`          |
//! | `JUDGES_LLM_UNAVAILABLE`         | `judges.llm_unavailable`        | `block`          |
//! | `JUDGE_FALLBACK_MODELS`          | `judges.fallback_models`        | *(none)*         |
//! | `JUDGE_MAX_FALLBACK_ATTEMPTS`    | `judges.max_fallback_attempts`  | `2`              |
//! | `JUDGE_CB_FAILURES`              | `judges.circuit_breaker_failures` | `3`            |
//! | `JUDGE_CB_TIMEOUT_S`             | `judges.circuit_breaker_timeout_s` | `30`           |
//! | `ALL_LAYERS_DISABLED`            | `server.all_layers_disabled`    | `block`          |
//! | `GUARDRAILS_POLICY_RULES_PATH`              | `config.guardrails_policy_rules_path`      | *(none)*         |
//! | `LLM_JUDGE_RULES_PATH`             | `config.llm_judge_rules_path`     | *(none)*         |


use serde::Deserialize;

// ─────────────────────────────────────────────────────────────────────────────
// TOML sub-sections
// ─────────────────────────────────────────────────────────────────────────────

/// `[server]` section of `config.toml`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ServerToml {
    pub host: Option<String>,
    pub port: Option<u16>,
    pub mode: Option<String>,
    /// Behaviour when ALL layers are disabled: "allow" (default) or "block".
    pub all_layers_disabled: Option<String>,
    /// Maximum number of chunks accepted per /scan request. Default: 256.
    pub max_chunks: Option<usize>,
    /// Directory for log files. `None` → logs to stderr only.
    pub log_dir: Option<String>,
    /// Log level: trace | debug | info | warn | error. Default: info.
    pub log_level: Option<String>,
}

/// `[judges]` section of `config.toml`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct JudgesToml {
    pub litellm_url: Option<String>,
    pub litellm_api_key: Option<String>,
    pub judge1_model: Option<String>,
    pub judge2_model: Option<String>,
    pub confidence_threshold: Option<f32>,

    pub skip_cross_on_consensus: Option<bool>,
    pub tie_behaviour: Option<String>,
    pub timeout_ms: Option<u64>,
    /// Behaviour when both LLM judges are unavailable: "block" (default) or "allow".
    pub llm_unavailable: Option<String>,
    /// Ordered list of fallback models (excludes judge1/judge2 at startup).
    pub fallback_models: Option<Vec<String>>,
    /// Max models to try per judge call (primary + fallbacks). Default: 2.
    pub max_fallback_attempts: Option<usize>,
    /// Consecutive failures before circuit opens. Default: 3.
    pub circuit_breaker_failures: Option<usize>,
    /// Seconds to skip a failed model before probing again. Default: 30.
    pub circuit_breaker_timeout_s: Option<u64>,
    /// Path to llm-judge-rules.toml containing the LLM judge system prompts.
    /// If set, prompts are loaded from this file at startup (no recompile needed).
    /// Falls back to compiled-in defaults if the file is missing or invalid.
    pub policy_path: Option<String>,
    /// LLM sampling temperature. Default: 0.0 (deterministic).
    pub temperature: Option<f32>,
    /// Max tokens per judge response. Default: 1024.
    pub max_tokens: Option<u32>,
    /// Max tokens for Stage 2 cross_check calls. Default: 2048.
    pub cross_check_max_tokens: Option<u32>,
    /// Per-model token overrides. Falls back to max_tokens if model not listed.
    #[serde(default)]
    pub model_max_tokens: std::collections::HashMap<String, u32>,
    /// Accept invalid TLS certificates for the LiteLLM proxy. Default: true.
    pub accept_invalid_certs: Option<bool>,
    /// Max warm connections kept per LiteLLM host. Default: 32.
    pub pool_max_idle_per_host: Option<usize>,
    /// How long an idle pooled connection may sit before it is closed (seconds). Default: 60.
    pub pool_idle_timeout_secs: Option<u64>,
}

/// `[keyword_scan]` section of `config.toml` — L3 keyword scan settings.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct KeywordScanToml {
    /// Score at or below which L2/L3 judges are skipped (clearly clean). Default: 0.1.
    pub safe_score: Option<f32>,
    /// Score at or above which the request is blocked immediately (clearly malicious). Default: 0.8.
    pub block_score: Option<f32>,
}

/// `[guardrails]` section of `config.toml`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct GuardrailsToml {
    pub rules_path: Option<String>,
    /// Guardrail mode for jailbreak detection: "audit" (default) or "enforce".
    pub guardrail_jailbreak_mode: Option<String>,
    /// Guardrail mode for toxicity detection: "enforce" (default) or "audit".
    pub guardrail_toxicity_mode: Option<String>,
}

/// `[layers]` section of `config.toml` — per-layer enable/disable toggles.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct LayersToml {
    /// L1 — Compliance (ainxt-compliance input scan + output redact). Default: true.
    pub compliance_layer:        Option<bool>,
    /// L2 — Guardrails + Policy (ainxt-guardrails ML + TOML rules). Default: true.
    pub guardrails_policy_layer: Option<bool>,
    /// L3 — Keyword Scan Detector (ainxt-injection crate). Default: true.
    pub keyword_scan_layer:         Option<bool>,
    /// L4/L5 — LLM Judge Pipeline (LiteLLM). Default: true.
    pub llm_judges_layer:        Option<bool>,
}

impl Default for LayersToml {
    fn default() -> Self {
        LayersToml {
            compliance_layer:        None,
            guardrails_policy_layer: None,
            keyword_scan_layer:         None,
            llm_judges_layer:        None,
        }
    }
}

/// `[config]` section of `config.toml` — external file paths.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ConfigFilesSection {
    /// Path to `llm-judge-rules.toml` containing LLM judge system prompts.
    pub llm_judge_rules_path: Option<String>,
    /// Path to `guardrails-policy-rules.toml` containing L2 deny/allow rules.
    pub guardrails_policy_rules_path: Option<String>,
}

/// Root of `config.toml`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
struct ConfigFile {
    config:    ConfigFilesSection,
    server:    ServerToml,
    layers:    LayersToml,
    guardrails: GuardrailsToml,
    keyword_scan: KeywordScanToml,
    judges:    JudgesToml,
}

// ─────────────────────────────────────────────────────────────────────────────
// Resolved config — all fields have concrete types, no Option
// ─────────────────────────────────────────────────────────────────────────────

/// Fully-resolved service configuration.
///
/// Build with [`ServiceConfig::load()`].
#[derive(Debug, Clone)]
pub struct ServiceConfig {
    // ── Server ──────────────────────────────────────────────────────────────
    /// Bind host — e.g. `"0.0.0.0"` or `"127.0.0.1"`.
    pub host: String,
    /// Bind port.
    pub port: u16,
    /// Injection mode: `"enforce"`, `"audit"`, or `"off"`.
    pub mode: String,

    // ── Judges ──────────────────────────────────────────────────────────────
    /// LiteLLM proxy base URL. `None` → judge pipeline disabled.
    pub litellm_url: Option<String>,
    /// LiteLLM API key. `None` → judge pipeline disabled.
    pub litellm_api_key: Option<String>,
    /// Model name for Judge 1.
    pub judge1_model: String,
    /// Model name for Judge 2.
    pub judge2_model: String,
    /// Minimum confidence for a verdict to count in the majority vote.
    pub confidence_threshold: f32,
    /// Heuristic score at or below which judges are skipped (clearly clean).
    pub keyword_scan_safe_score: f32,
    /// Heuristic score at or above which the request is blocked immediately (clearly malicious).
    pub keyword_scan_block_score: f32,
    /// Skip Stage 2 cross-validation when Stage 1 judges agree.
    pub skip_cross_on_consensus: bool,
    /// Tie-breaking behaviour: `"block"` (default) or `"allow"`.
    pub tie_behaviour: String,
    /// Per-judge HTTP request timeout in milliseconds.
    pub timeout_ms: u64,
    /// Behaviour when both LLM judges are unavailable: `"block"` (default) or `"allow"`.
    pub llm_unavailable: String,
    /// Ordered fallback model pool (deduplicated against judge1/judge2 at startup).
    pub fallback_models: Vec<String>,
    /// Max models to try per judge call (primary + fallbacks). Default: 2.
    pub max_fallback_attempts: usize,
    /// Consecutive failures before circuit opens. Default: 3.
    pub circuit_breaker_failures: usize,
    /// Seconds to skip a failed model before probing again. Default: 30.
    pub circuit_breaker_timeout_s: u64,
    /// Behaviour when ALL layers are disabled: `"allow"` (default) or `"block"`.
    pub all_layers_disabled: String,

    // ── Policy ───────────────────────────────────────────────────────────────
    /// Path to `guardrails-policy-rules.toml`. `None` → TOML rules disabled (guardrails + compliance still run).
    pub guardrails_policy_rules_path: Option<String>,
    /// Path to `llm-judge-rules.toml` containing LLM judge system prompts.
    /// `None` → compiled-in default prompts are used.
    pub llm_judge_rules_path: Option<String>,

    // ── Judge tuning ─────────────────────────────────────────────────────────
    /// LLM sampling temperature. Default: 0.0.
    pub judge_temperature: f32,
    pub judge_max_tokens: u32,
    pub judge_cross_check_max_tokens: u32,
    pub judge_model_max_tokens: std::collections::HashMap<String, u32>,
    /// Accept invalid TLS certificates for the LiteLLM proxy. Default: true.
    pub judge_accept_invalid_certs: bool,
    /// Max warm (idle) TCP connections kept per LiteLLM host. Default: 32.
    pub judge_pool_max_idle_per_host: usize,
    /// How long an idle pooled connection may sit before it is closed (seconds). Default: 60.
    pub judge_pool_idle_timeout_secs: u64,
    // ── Server ───────────────────────────────────────────────────────────────
    /// Maximum chunks per /scan request. Default: 256.
    pub max_chunks: usize,
    /// Directory for log files. `None` → logs to stderr only.
    pub log_dir: Option<String>,
    /// Log level: trace | debug | info | warn | error. Default: info.
    pub log_level: String,
    // ── Policy guardrails ────────────────────────────────────────────────────
    /// Guardrail mode for jailbreak: "audit" (default) or "enforce".
    pub guardrail_jailbreak_mode: String,
    /// Guardrail mode for toxicity: "enforce" (default) or "audit".
    pub guardrail_toxicity_mode: String,

    // ── Layer toggles ────────────────────────────────────────────────────────
    /// L1 — Compliance (ainxt-compliance input + output). Default: true.
    pub layer_compliance: bool,
    pub layer_guardrails_policy: bool,
    /// L3 — Keyword Scan Detector enabled.
    pub layer_keyword_scan:      bool,
    /// L4/L5 — LLM Judge Pipeline enabled.
    pub layer_llm_judges:     bool,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        ServiceConfig {
            host:                    "127.0.0.1".into(),
            port:                    8007,
            mode:                    "enforce".into(),
            litellm_url:             None,
            litellm_api_key:         None,
            judge1_model:            "judge1".into(),
            judge2_model:            "judge2".into(),
            confidence_threshold:    0.8,   // matches config.toml
            keyword_scan_safe_score:              0.1,
            keyword_scan_block_score:             0.8,
            skip_cross_on_consensus: true,
            tie_behaviour:           "block".into(),
            timeout_ms:              30000, // matches config.toml
            llm_unavailable:         "block".into(),
            fallback_models:         Vec::new(),
            max_fallback_attempts:   3,     // matches config.toml
            circuit_breaker_failures: 5,   // matches config.toml
            circuit_breaker_timeout_s: 10, // matches config.toml
            all_layers_disabled:     "block".into(),
            guardrails_policy_rules_path:       None,
            llm_judge_rules_path:          None,

            judge_temperature:               0.0,
            judge_max_tokens:                1024,
            judge_cross_check_max_tokens:    2048,
            judge_model_max_tokens:          std::collections::HashMap::new(),
            judge_accept_invalid_certs:      true,
            judge_pool_max_idle_per_host: 32,
            judge_pool_idle_timeout_secs: 60,
            max_chunks:                 256,
            log_dir:                    None,
            log_level:                  "info".into(),
            guardrail_jailbreak_mode:   "audit".into(),
            guardrail_toxicity_mode:    "enforce".into(),
            // All layers enabled by default
            layer_compliance:        true,
            layer_guardrails_policy: true,
            layer_keyword_scan:         true,
            layer_llm_judges:        true,

        }
    }
}

impl ServiceConfig {
    /// Load configuration: compiled-in defaults → TOML file (if present)
    /// → environment variables (highest priority).
    pub fn load() -> Self {
        let mut cfg = ServiceConfig::default();

        // Step 1: TOML file. Use AINXT_INJECTION_CONFIG if set, else search
        // CWD, binary dir, workspace root, crates/ainxt-injection-svc/.
        let toml_path = std::env::var("AINXT_INJECTION_CONFIG").ok();
        let toml_name = "config.toml";

        let candidates: Vec<String> = if let Some(p) = toml_path {
            vec![p]
        } else {
            let mut c = vec![toml_name.to_string()]; // CWD-relative
            // Binary directory
            if let Some(bin_dir) = std::env::current_exe().ok().and_then(|p| p.parent().map(|p| p.to_path_buf())) {
                c.push(bin_dir.join(toml_name).to_string_lossy().into_owned());
            }
            // Workspace root (binary is typically in target/release/, so go up three levels)
            if let Some(workspace_root) = std::env::current_exe().ok()
                .and_then(|p| p.parent().map(|p| p.to_path_buf()))
                .and_then(|p| p.parent().map(|p| p.to_path_buf()))
                .and_then(|p| p.parent().map(|p| p.to_path_buf()))
            {
                c.push(workspace_root.join(toml_name).to_string_lossy().into_owned());
            }
            // crates/ainxt-injection-svc/ relative to workspace root
            if let Some(workspace_root) = std::env::current_exe().ok()
                .and_then(|p| p.parent().map(|p| p.to_path_buf()))
                .and_then(|p| p.parent().map(|p| p.to_path_buf()))
                .and_then(|p| p.parent().map(|p| p.to_path_buf()))
            {
                let crate_dir = workspace_root.join("crates").join("ainxt-injection-svc");
                c.push(crate_dir.join(toml_name).to_string_lossy().into_owned());
            }
            c
        };

        let mut loaded = false;
        for candidate in &candidates {
            if let Ok(content) = std::fs::read_to_string(candidate) {
                match toml::from_str::<ConfigFile>(&content) {
                    Ok(file) => {
                        eprintln!("config: loaded from {candidate}");
                        cfg.apply_toml(&file);
                        loaded = true;
                        break;
                    }
                    Err(e) => {
                        eprintln!("config: failed to parse {candidate}: {e} — trying next location");
                    }
                }
            }
        }
        if !loaded {
            eprintln!("config: config.toml not found — using defaults");
        }

        // ── Step 2: env var overrides ──────────────────────────────────────
        cfg.apply_env();

        cfg
    }

    // ── TOML overlay ──────────────────────────────────────────────────────

    fn apply_toml(&mut self, file: &ConfigFile) {
        // Server
        if let Some(ref v) = file.server.host  { self.host = v.clone(); }
        if let Some(v)     = file.server.port  { self.port = v; }
        if let Some(ref v) = file.server.mode  { self.mode = v.clone(); }

        // Judges
        if let Some(ref v) = file.judges.litellm_url     { self.litellm_url = Some(v.clone()); }
        if let Some(ref v) = file.judges.litellm_api_key { self.litellm_api_key = Some(v.clone()); }
        if let Some(ref v) = file.judges.judge1_model    { self.judge1_model = v.clone(); }
        if let Some(ref v) = file.judges.judge2_model    { self.judge2_model = v.clone(); }
        if let Some(v)     = file.judges.confidence_threshold    { self.confidence_threshold = v; }

        if let Some(v)     = file.judges.skip_cross_on_consensus { self.skip_cross_on_consensus = v; }
        if let Some(ref v) = file.judges.tie_behaviour           { self.tie_behaviour = v.clone(); }
        if let Some(v)     = file.judges.timeout_ms              { self.timeout_ms = v; }
        if let Some(ref v) = file.judges.llm_unavailable         { self.llm_unavailable = v.clone(); }
        if let Some(ref v) = file.judges.fallback_models         { self.fallback_models = v.clone(); }
        if let Some(v)     = file.judges.max_fallback_attempts   { self.max_fallback_attempts = v; }
        if let Some(v)     = file.judges.circuit_breaker_failures { self.circuit_breaker_failures = v; }
        if let Some(v)     = file.judges.circuit_breaker_timeout_s { self.circuit_breaker_timeout_s = v; }

        // Server-level safety
        if let Some(ref v) = file.server.all_layers_disabled     { self.all_layers_disabled = v.clone(); }

        // Policy
        // [config] section — all external file paths in one place
        if let Some(ref v) = file.config.llm_judge_rules_path { self.llm_judge_rules_path = Some(v.clone()); }

        if let Some(ref v) = file.config.guardrails_policy_rules_path  { self.guardrails_policy_rules_path  = Some(v.clone()); }
        if let Some(ref v) = file.guardrails.rules_path              { self.guardrails_policy_rules_path = Some(v.clone()); }
        if let Some(ref v) = file.guardrails.guardrail_jailbreak_mode { self.guardrail_jailbreak_mode = v.clone(); }
        if let Some(ref v) = file.guardrails.guardrail_toxicity_mode  { self.guardrail_toxicity_mode  = v.clone(); }

        // Server extras
        if let Some(v) = file.server.max_chunks          { self.max_chunks  = v; }
        if let Some(ref v) = file.server.log_dir         { self.log_dir     = Some(v.clone()); }
        if let Some(ref v) = file.server.log_level       { self.log_level   = v.clone(); }

        // Judge tuning
        if let Some(ref v) = file.judges.policy_path        { self.llm_judge_rules_path = Some(v.clone()); }
        if let Some(v)     = file.judges.temperature         { self.judge_temperature = v; }
        if let Some(v)     = file.judges.max_tokens             { self.judge_max_tokens  = v; }
        if let Some(v)     = file.judges.cross_check_max_tokens { self.judge_cross_check_max_tokens = v; }
        else if let Some(v) = file.judges.max_tokens            { self.judge_cross_check_max_tokens = v; }
        if !file.judges.model_max_tokens.is_empty()             { self.judge_model_max_tokens = file.judges.model_max_tokens.clone(); }
        if let Some(v)     = file.judges.accept_invalid_certs   { self.judge_accept_invalid_certs = v; }
        if let Some(v)     = file.judges.pool_max_idle_per_host { self.judge_pool_max_idle_per_host = v; }
        if let Some(v)     = file.judges.pool_idle_timeout_secs { self.judge_pool_idle_timeout_secs = v; }

        // Layer toggles
        if let Some(v) = file.layers.compliance_layer      { self.layer_compliance        = v; }
        if let Some(v) = file.layers.guardrails_policy_layer { self.layer_guardrails_policy = v; }
        if let Some(v) = file.layers.keyword_scan_layer      { self.layer_keyword_scan      = v; }
        if let Some(v) = file.layers.llm_judges_layer     { self.layer_llm_judges     = v; }




        // [keyword_scan] section
        if let Some(v) = file.keyword_scan.safe_score  { self.keyword_scan_safe_score  = v; }
        if let Some(v) = file.keyword_scan.block_score { self.keyword_scan_block_score = v; }
    }

    // ── Env var overlay ───────────────────────────────────────────────────

    fn apply_env(&mut self) {
        // Server
        if let Ok(v) = std::env::var("AINXT_INJECTION_SVC_HOST") { self.host = v; }
        if let Ok(v) = std::env::var("AINXT_INJECTION_SVC_PORT") {
            if let Ok(p) = v.parse() { self.port = p; }
        }
        if let Ok(v) = std::env::var("AINXT_INJECTION_MODE") { self.mode = v; }

        // Judges
        if let Ok(v) = std::env::var("JUDGE_LITELLM_URL")     { self.litellm_url = Some(v); }
        if let Ok(v) = std::env::var("JUDGE_LITELLM_API_KEY") { self.litellm_api_key = Some(v); }
        if let Ok(v) = std::env::var("JUDGE1_MODEL")          { self.judge1_model = v; }
        if let Ok(v) = std::env::var("JUDGE2_MODEL")          { self.judge2_model = v; }
        if let Ok(v) = std::env::var("JUDGE_CONFIDENCE_THRESHOLD") {
            if let Ok(f) = v.parse() { self.confidence_threshold = f; }
        }
        if let Ok(v) = std::env::var("KEYWORD_SCAN_SAFE_SCORE") {
            if let Ok(f) = v.parse() { self.keyword_scan_safe_score = f; }
        }
        if let Ok(v) = std::env::var("KEYWORD_SCAN_BLOCK_SCORE") {
            if let Ok(f) = v.parse() { self.keyword_scan_block_score = f; }
        }
        if let Ok(v) = std::env::var("JUDGE_SKIP_CROSS_ON_CONSENSUS") {
            self.skip_cross_on_consensus = v.trim().to_ascii_lowercase() != "false";
        }
        if let Ok(v) = std::env::var("JUDGE_TIE_BEHAVIOUR") { self.tie_behaviour = v; }
        if let Ok(v) = std::env::var("JUDGE_TIMEOUT_MS") {
            if let Ok(n) = v.parse() { self.timeout_ms = n; }
        }
        if let Ok(v) = std::env::var("JUDGES_LLM_UNAVAILABLE") {
            let v = v.trim().to_ascii_lowercase();
            if v == "block" || v == "allow" {
                self.llm_unavailable = v;
            }
        }
        if let Ok(v) = std::env::var("JUDGE_FALLBACK_MODELS") {
            // Comma-separated list
            self.fallback_models = v.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
        if let Ok(v) = std::env::var("JUDGE_MAX_FALLBACK_ATTEMPTS") {
            if let Ok(n) = v.parse() { self.max_fallback_attempts = n; }
        }
        if let Ok(v) = std::env::var("JUDGE_CB_FAILURES") {
            if let Ok(n) = v.parse() { self.circuit_breaker_failures = n; }
        }
        if let Ok(v) = std::env::var("JUDGE_CB_TIMEOUT_S") {
            if let Ok(n) = v.parse() { self.circuit_breaker_timeout_s = n; }
        }
        if let Ok(v) = std::env::var("ALL_LAYERS_DISABLED") {
            let v = v.trim().to_ascii_lowercase();
            if v == "block" || v == "allow" {
                self.all_layers_disabled = v;
            }
        }

        // Policy
        if let Ok(v) = std::env::var("GUARDRAILS_POLICY_RULES_PATH") { self.guardrails_policy_rules_path = Some(v); }
        if let Ok(v) = std::env::var("LLM_JUDGE_RULES_PATH")         { self.llm_judge_rules_path = Some(v); }

        if let Ok(v) = std::env::var("JUDGE_TEMPERATURE")         { if let Ok(f) = v.parse() { self.judge_temperature = f; } }
        if let Ok(v) = std::env::var("JUDGE_MAX_TOKENS")             { if let Ok(n) = v.parse() { self.judge_max_tokens  = n; } }
        if let Ok(v) = std::env::var("JUDGE_CROSS_CHECK_MAX_TOKENS") { if let Ok(n) = v.parse() { self.judge_cross_check_max_tokens = n; } }
        if let Ok(v) = std::env::var("JUDGE_ACCEPT_INVALID_CERTS") { self.judge_accept_invalid_certs = v.trim().to_ascii_lowercase() != "false"; }
        if let Ok(v) = std::env::var("JUDGE_POOL_MAX_IDLE_PER_HOST") { if let Ok(n) = v.parse() { self.judge_pool_max_idle_per_host = n; } }
        if let Ok(v) = std::env::var("JUDGE_POOL_IDLE_TIMEOUT_SECS") { if let Ok(n) = v.parse() { self.judge_pool_idle_timeout_secs = n; } }
        if let Ok(v) = std::env::var("SERVER_MAX_CHUNKS")  { if let Ok(n) = v.parse() { self.max_chunks = n; } }
        if let Ok(v) = std::env::var("LOG_DIR")            { self.log_dir   = Some(v); }
        if let Ok(v) = std::env::var("LOG_LEVEL")          { self.log_level = v; }
        if let Ok(v) = std::env::var("GUARDRAIL_JAILBREAK_MODE")  { self.guardrail_jailbreak_mode = v; }
        if let Ok(v) = std::env::var("GUARDRAIL_TOXICITY_MODE")   { self.guardrail_toxicity_mode  = v; }

        // Layer toggles
        if let Ok(v) = std::env::var("COMPLIANCE_LAYER")         { self.layer_compliance        = v.trim().to_ascii_lowercase() != "false"; }
        if let Ok(v) = std::env::var("GUARDRAILS_POLICY_LAYER") { self.layer_guardrails_policy = v.trim().to_ascii_lowercase() != "false"; }
        if let Ok(v) = std::env::var("KEYWORD_SCAN_LAYER")      { self.layer_keyword_scan      = v.trim().to_ascii_lowercase() != "false"; }
        if let Ok(v) = std::env::var("LLM_JUDGES_LAYER")     { self.layer_llm_judges     = v.trim().to_ascii_lowercase() != "false"; }

    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sane() {
        let cfg = ServiceConfig::default();
        assert_eq!(cfg.host, "127.0.0.1");
        assert_eq!(cfg.port, 8007);
        assert_eq!(cfg.mode, "enforce");
        assert!(cfg.litellm_url.is_none());
        assert!(cfg.litellm_api_key.is_none());
        assert_eq!(cfg.judge1_model, "judge1");
        assert_eq!(cfg.judge2_model, "judge2");
        assert!((cfg.confidence_threshold - 0.8).abs() < 1e-6);
        assert!((cfg.keyword_scan_safe_score - 0.1).abs() < 1e-6);
        assert!((cfg.keyword_scan_block_score - 0.8).abs() < 1e-6);
        assert!(cfg.skip_cross_on_consensus);
        assert_eq!(cfg.tie_behaviour, "block");
        assert_eq!(cfg.timeout_ms, 30000);
        assert!(cfg.guardrails_policy_rules_path.is_none());
    }

    #[test]
    fn toml_overlay_applies_values() {
        let mut cfg = ServiceConfig::default();
        let file = ConfigFile {
            config: ConfigFilesSection {
                llm_judge_rules_path:         Some("test-judge-rules.toml".into()),
                guardrails_policy_rules_path: Some("/etc/ainxt/guardrails-policy-rules.toml".into()),
            },
            server: ServerToml {
                host:               Some("0.0.0.0".into()),
                port:               Some(9000),
                mode:               Some("audit".into()),
                all_layers_disabled: Some("block".into()),
                max_chunks:         Some(128),
                log_dir:            None,
                log_level:          Some("info".into()),
            },
            judges: JudgesToml {
                litellm_url:               Some("http://localhost:4000".into()),
                litellm_api_key:           Some("test-key".into()),
                judge1_model:              Some("model-a".into()),
                judge2_model:              Some("model-b".into()),
                confidence_threshold:      Some(0.85),
                skip_cross_on_consensus:   Some(false),
                tie_behaviour:             Some("allow".into()),
                timeout_ms:                Some(3000),
                llm_unavailable:           Some("allow".into()),
                fallback_models:           Some(vec!["model-fallback-a".into(), "model-fallback-b".into()]),
                max_fallback_attempts:     Some(3),
                circuit_breaker_failures:  Some(5),
                circuit_breaker_timeout_s: Some(60),
                ..Default::default()
            },
            guardrails: GuardrailsToml {
                rules_path:               Some("/etc/ainxt/guardrails-policy-rules.toml".into()),
                guardrail_jailbreak_mode: Some("enforce".into()),
                guardrail_toxicity_mode:  Some("audit".into()),
            },
            keyword_scan: KeywordScanToml {
                safe_score:  Some(0.05),
                block_score: Some(0.75),
            },
            layers: LayersToml {
                compliance_layer:        Some(false),
                guardrails_policy_layer: Some(false),
                keyword_scan_layer:      Some(false),
                llm_judges_layer:        Some(true),
            },
        };
        cfg.apply_toml(&file);

        assert_eq!(cfg.host, "0.0.0.0");
        assert_eq!(cfg.port, 9000);
        assert_eq!(cfg.mode, "audit");
        assert_eq!(cfg.max_chunks, 128);
        assert_eq!(cfg.litellm_url.as_deref(), Some("http://localhost:4000"));
        assert_eq!(cfg.litellm_api_key.as_deref(), Some("test-key"));
        assert_eq!(cfg.judge1_model, "model-a");
        assert_eq!(cfg.judge2_model, "model-b");
        assert!((cfg.confidence_threshold - 0.85).abs() < 1e-6);
        assert!((cfg.keyword_scan_safe_score - 0.05).abs() < 1e-6);
        assert!((cfg.keyword_scan_block_score - 0.75).abs() < 1e-6);
        assert!(!cfg.skip_cross_on_consensus);
        assert_eq!(cfg.tie_behaviour, "allow");
        assert_eq!(cfg.timeout_ms, 3000);
        assert_eq!(cfg.llm_unavailable, "allow");
        assert_eq!(cfg.fallback_models, vec!["model-fallback-a", "model-fallback-b"]);
        assert_eq!(cfg.max_fallback_attempts, 3);
        assert_eq!(cfg.circuit_breaker_failures, 5);
        assert_eq!(cfg.circuit_breaker_timeout_s, 60);
        assert_eq!(cfg.guardrails_policy_rules_path.as_deref(), Some("/etc/ainxt/guardrails-policy-rules.toml"));
        assert_eq!(cfg.guardrail_jailbreak_mode, "enforce");
        assert_eq!(cfg.guardrail_toxicity_mode, "audit");
    }

    #[test]
    fn env_overlay_wins_over_toml() {
        std::env::set_var("AINXT_INJECTION_SVC_PORT", "7777");
        std::env::set_var("JUDGE_TIMEOUT_MS", "9999");

        let mut cfg = ServiceConfig::default();
        // Simulate TOML setting port to 9000
        cfg.port = 9000;
        cfg.timeout_ms = 1000;
        // Now apply env — should win
        cfg.apply_env();

        assert_eq!(cfg.port, 7777);
        assert_eq!(cfg.timeout_ms, 9999);

        // Clean up
        std::env::remove_var("AINXT_INJECTION_SVC_PORT");
        std::env::remove_var("JUDGE_TIMEOUT_MS");
    }
}
