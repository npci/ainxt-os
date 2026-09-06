// SPDX-License-Identifier: MIT
//! LLM-judge pipeline — Layer 1 + Layer 2 of the injection defence stack.
//!
//! Prefer [`JudgeConfig::from_config`] (takes a resolved [`crate::config::ServiceConfig`])
//! over [`JudgeConfig::from_env`] (reads env vars directly) — the former is used in `main`.
//!
//! ## Design
//!
//! Two generic LLM judges (Judge1 + Judge2) run in parallel (Stage 1).
//! If they agree with confidence >= threshold → decision is immediate (no Stage 2).
//! If they disagree → Stage 2 cross-validation fires: each judge reviews the other's verdict.
//! Final decision = majority vote across all confident verdicts (confidence >= threshold).
//! Tie → block (fail-closed).
//!
//! No model names are hardcoded. All config comes from env vars at startup.

use ainxt_injection::Provenance;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

// Default friendly messages for blocks where the judge did not produce one
// (Stage-2 tie fail-closed, keyword-scan block). Tone matches the FRIENDLY
// MESSAGE RULES in llm-judge-rules.toml.

/// Default for judge-tie / cross-check-tie fail-closed blocks.
const DEFAULT_TIE_FRIENDLY_MESSAGE: &str =
    "I couldn't confidently classify this request, so I'm holding back to be safe. \
Here are ways to move forward:\\n\
- Rephrase what you're trying to do in your own words\\n\
- Share the specific end goal (e.g. \"I'm reviewing my own config file\")\\n\
- Ask me to walk through the safe/legitimate options for this task\\n\
- Break the request into smaller, more explicit steps\\n\
Happy to help once I understand the intent clearly.";

/// Default for keyword-scan (Layer 3) blocks above threshold.
const DEFAULT_KEYWORD_FRIENDLY_MESSAGE: &str =
    "I can't help with this request as it matched a security pattern. \
Here are legitimate directions you can take:\\n\
- Rephrase the request without the sensitive keywords\\n\
- Describe your legitimate goal (e.g. debugging your own system)\\n\
- Ask about the topic conceptually rather than as an instruction\\n\
- Share more context about what you're building\\n\
Let me know a safer angle and I'll help.";

// ─────────────────────────────────────────────────────────────────────────────
// Request ID — monotonic counter, unique per evaluate() call
// ─────────────────────────────────────────────────────────────────────────────

/// Global monotonic counter combined with a nanosecond timestamp, hashed
/// via std DefaultHasher to produce a UUID-format ID with 128 bits of entropy
/// (e.g. `A3F7C12B-9E4D-7A2B-F103-8C5D2E1B4A9F`).
static REQ_COUNTER: AtomicUsize = AtomicUsize::new(1);

/// Collapse a model reply onto ONE log line — escape line breaks and cap length
/// so a rambling reply cannot flood the log or break `grep <req_id>` (continuation
/// lines would otherwise carry no id).
fn log_one_line(s: &str) -> String {
    const MAX: usize = 1000;
    let truncated: String = s.chars().take(MAX).collect();
    let escaped = truncated
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t");
    if s.chars().count() > MAX {
        format!("{escaped}…[truncated]")
    } else {
        escaped
    }
}

pub(crate) fn next_req_id() -> String {
    use std::hash::{Hash, Hasher};
    use std::collections::hash_map::DefaultHasher;

    let seq = REQ_COUNTER.fetch_add(1, Ordering::Relaxed);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();

    // First 64-bit hash: seq + whole seconds
    let mut h1 = DefaultHasher::new();
    seq.hash(&mut h1);
    now.as_secs().hash(&mut h1);
    let a = h1.finish();

    // Second 64-bit hash: seq XOR'd + nanoseconds (different seed)
    let mut h2 = DefaultHasher::new();
    (seq ^ 0xDEAD_BEEF).hash(&mut h2);
    now.subsec_nanos().hash(&mut h2);
    let b = h2.finish();

    // Pack into UUID format: 8-4-4-4-12
    let p1 = (a >> 32) as u32;
    let p2 = ((a >> 16) & 0xFFFF) as u16;
    let p3 = (a & 0xFFFF) as u16;
    let p4 = ((b >> 48) & 0xFFFF) as u16;
    let p5 = b & 0x0000_FFFF_FFFF_FFFF;

    format!("{:08X}-{:04X}-{:04X}-{:04X}-{:012X}", p1, p2, p3, p4, p5)
}

// ─────────────────────────────────────────────────────────────────────────────
// Circuit Breaker — per-model health tracking
// ─────────────────────────────────────────────────────────────────────────────

/// Circuit breaker state machine.
#[derive(Debug, Clone)]
enum CircuitState {
    /// Model is healthy — try it normally.
    Closed,
    /// Skip this model until `until` instant, then transition to HalfOpen.
    Open { until: Instant },
    /// One probe attempt allowed — success → Closed, failure → Open again.
    HalfOpen,
}

/// RwLock-wrapped circuit breaker for safe concurrent access across async tasks.
/// Always used behind `Arc` — does not implement `Clone` directly.
#[derive(Debug)]
pub struct CircuitBreaker {
    failures_before_open: usize,
    open_timeout_s: u64,
    consecutive_failures: AtomicUsize,
    state: std::sync::RwLock<CircuitState>,
}

impl CircuitBreaker {
    pub fn new(failures_before_open: usize, open_timeout_s: u64) -> Self {
        CircuitBreaker {
            failures_before_open,
            open_timeout_s,
            consecutive_failures: AtomicUsize::new(0),
            state: std::sync::RwLock::new(CircuitState::Closed),
        }
    }

    /// Check if this model should be tried now.
    pub fn should_try(&self) -> bool {
        let state = self.state.read().unwrap();
        match *state {
            CircuitState::Closed => true,
            CircuitState::HalfOpen => true,
            CircuitState::Open { until } => {
                if Instant::now() >= until {
                    drop(state);
                    let mut w = self.state.write().unwrap();
                    *w = CircuitState::HalfOpen;
                    true
                } else {
                    false
                }
            }
        }
    }

    /// Lightweight probe to check if the model is alive (used when transitioning
    /// from Open → HalfOpen). Sends a tiny request instead of the full judge prompt.
    pub async fn probe(&self, url: &str, api_key: &str, model: &str, client: &reqwest::Client, timeout_ms: u64) -> bool {
        let probe_body = serde_json::json!({
            "model": model,
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 1
        });
        match client.post(url)
            .bearer_auth(api_key)
            .json(&probe_body)
            .timeout(std::time::Duration::from_millis(timeout_ms))
            .send()
            .await
        {
            Ok(resp) => resp.status().is_success(),
            Err(_) => false,
        }
    }

    /// Record a successful call — resets the circuit to Closed.
    pub fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
        let mut w = self.state.write().unwrap();
        *w = CircuitState::Closed;
    }

    /// Record a failed call — may open the circuit after `failures_before_open` consecutive errors.
    pub fn record_failure(&self) {
        let failures = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
        if failures >= self.failures_before_open {
            let until = Instant::now() + std::time::Duration::from_secs(self.open_timeout_s);
            let mut w = self.state.write().unwrap();
            *w = CircuitState::Open { until };
        }
    }
}

/// A model entry with its own circuit breaker.
#[derive(Debug, Clone)]
pub struct ModelSlot {
    pub model:   String,
    pub circuit: Arc<CircuitBreaker>,
    /// Whether this is the primary model (true) or a fallback (false).
    #[allow(dead_code)]
    pub is_primary: bool,
    pub max_tokens: Option<u32>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Judge policy — loaded from llm-judge-rules.toml at startup
// ─────────────────────────────────────────────────────────────────────────────

/// TOML structure of `llm-judge-rules.toml`.
#[derive(serde::Deserialize, Default)]
struct JudgePolicyFile {
    #[serde(default)] assess:             AssessSection,
    #[serde(default)] assess_tool_result: AssessSection,
    #[serde(default)] cross_check:        CrossCheckSection,
    #[serde(default)] fallback:           FallbackSection,
}

#[derive(serde::Deserialize, Default)]
struct AssessSection {
    #[serde(default)] system_prompt:        String,
    #[serde(default)] user_prompt_template: String,
}

#[derive(serde::Deserialize, Default)]
struct CrossCheckSection {
    #[serde(default)] system_prompt:        String,
    #[serde(default)] user_prompt_template: String,
}

#[derive(serde::Deserialize, Default)]
struct FallbackSection {
    #[serde(default)] unsafe_signals:              Vec<String>,
    #[serde(default)] safe_signals:                Vec<String>,
    #[serde(default)] fallback_confidence:         Option<f32>,
    #[serde(default)] fallback_ambiguous_confidence: Option<f32>,
}

/// All loaded judge policy values.
pub struct JudgePolicy {
    pub assess_system_prompt:           String,
    pub assess_user_prompt_template:    String,
    pub assess_tool_result_system_prompt:        String,
    pub assess_tool_result_user_prompt_template: String,
    pub cross_check_system_prompt:      String,
    pub cross_check_user_prompt_template: String,
    pub fallback_unsafe_signals:        Vec<String>,
    pub fallback_safe_signals:          Vec<String>,
    pub fallback_confidence:            f32,
    pub fallback_ambiguous_confidence:  f32,
}

fn from_policy_file(p: JudgePolicyFile) -> JudgePolicy {
    // Tool-result prompts fall back to the ingress assess prompts if the
    // [assess_tool_result] section is absent, so an older TOML still works
    // (it will just judge tool-results with the stricter ingress rules).
    let tr_system = if p.assess_tool_result.system_prompt.is_empty() {
        p.assess.system_prompt.clone()
    } else {
        p.assess_tool_result.system_prompt
    };
    let tr_user = if p.assess_tool_result.user_prompt_template.is_empty() {
        p.assess.user_prompt_template.clone()
    } else {
        p.assess_tool_result.user_prompt_template
    };
    JudgePolicy {
        assess_system_prompt:             p.assess.system_prompt,
        assess_user_prompt_template:      p.assess.user_prompt_template,
        assess_tool_result_system_prompt:        tr_system,
        assess_tool_result_user_prompt_template: tr_user,
        cross_check_system_prompt:        p.cross_check.system_prompt,
        cross_check_user_prompt_template: p.cross_check.user_prompt_template,
        fallback_unsafe_signals:          p.fallback.unsafe_signals,
        fallback_safe_signals:            p.fallback.safe_signals,
        fallback_confidence:              p.fallback.fallback_confidence.unwrap_or(0.70),
        fallback_ambiguous_confidence:    p.fallback.fallback_ambiguous_confidence.unwrap_or(0.50),
    }
}

/// Load all judge policy values from a TOML file.
/// Falls back to the compiled-in `llm-judge-rules.toml` defaults on any error.
fn load_judge_policy(path: Option<&str>) -> JudgePolicy {
    fn parse_builtin() -> JudgePolicy {
        match toml::from_str::<JudgePolicyFile>(include_str!("../llm-judge-rules.toml")) {
            Ok(p) => from_policy_file(p),
            Err(e) => {
                eprintln!("judge: FATAL — cannot parse built-in llm-judge-rules.toml: {e}");
                JudgePolicy {
                    assess_system_prompt:             String::new(),
                    assess_user_prompt_template:      String::new(),
                    assess_tool_result_system_prompt:        String::new(),
                    assess_tool_result_user_prompt_template: String::new(),
                    cross_check_system_prompt:        String::new(),
                    cross_check_user_prompt_template: String::new(),
                    fallback_unsafe_signals:          Vec::new(),
                    fallback_safe_signals:            Vec::new(),
                    fallback_confidence:              0.70,
                    fallback_ambiguous_confidence:    0.50,
                }
            }
        }
    }

    let Some(p) = path else {
        eprintln!("judge: no policy_path configured — using built-in llm-judge-rules.toml");
        return parse_builtin();
    };

    match std::fs::read_to_string(p) {
        Ok(content) => match toml::from_str::<JudgePolicyFile>(&content) {
            Ok(policy) => {
                eprintln!("judge: loaded policy from {p}");
                from_policy_file(policy)
            }
            Err(e) => {
                eprintln!("judge: failed to parse {p}: {e} — using built-in default");
                parse_builtin()
            }
        },
        Err(e) => {
            eprintln!("judge: cannot read {p}: {e} — using built-in default");
            parse_builtin()
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Config — all from env vars, nothing hardcoded
// ─────────────────────────────────────────────────────────────────────────────

/// All judge configuration read from environment variables at startup.
#[derive(Debug, Clone)]
pub struct JudgeConfig {
    /// LiteLLM proxy base URL — e.g. `https://your-litellm-proxy.example.com/v1`
    pub litellm_url: String,
    /// API key for the LiteLLM proxy.
    pub litellm_api_key: String,
    /// Model identifier for Judge 1 (e.g. `qwen3-30b`). Read from `JUDGE1_MODEL`.
    pub judge1_model: String,
    /// Model identifier for Judge 2 (e.g. `glm-4`). Read from `JUDGE2_MODEL`.
    pub judge2_model: String,
    /// Minimum confidence for a verdict to count in the majority vote. Default: 0.9.
    pub confidence_threshold: f32,
    /// Keyword scan score below which judges are skipped entirely (clearly clean). Default: 0.1.
    pub keyword_scan_safe_score: f32,
    /// Keyword scan score above which the request is blocked immediately (clearly malicious). Default: 0.8.
    pub keyword_scan_block_score: f32,
    /// Skip Stage 2 cross-validation when Stage 1 judges agree. Default: true.
    pub skip_cross_on_consensus: bool,
    /// Tie-breaking behaviour when unsafe == safe count. `"block"` (default) or `"allow"`.
    pub tie_behaviour: TieBehaviour,
    /// Request timeout for each LLM judge call in milliseconds. Default: 5000.
    pub timeout_ms: u64,
    /// Ordered fallback model pool (deduplicated against judge1/judge2 at startup).
    pub fallback_models: Vec<String>,
    /// Max models to try per judge call (primary + fallbacks). Default: 2.
    pub max_fallback_attempts: usize,
    /// Consecutive failures before circuit opens. Default: 3.
    pub circuit_breaker_failures: usize,
    /// Seconds to skip a failed model before probing again. Default: 30.
    pub circuit_breaker_timeout_s: u64,
    /// LLM sampling temperature. Default: 0.0.
    pub temperature: f32,
    pub max_tokens: u32,
    pub cross_check_max_tokens: u32,
    pub model_max_tokens: std::collections::HashMap<String, u32>,
    /// Accept invalid TLS certificates for the LiteLLM proxy. Default: true.
    pub accept_invalid_certs: bool,
    /// Max warm (idle) TCP connections kept per LiteLLM host. Default: 32.
    pub pool_max_idle_per_host: usize,
    /// How long an idle pooled connection may sit before it is closed (seconds). Default: 60.
    pub pool_idle_timeout_secs: u64,
    /// System prompt for primary assessment.
    pub assess_system_prompt: String,
    /// User-turn template for primary assessment. Use `{text}` as placeholder.
    pub assess_user_prompt_template: String,
    /// System prompt for assessing tool-results / retrieved / connector data.
    pub assess_tool_result_system_prompt: String,
    /// User-turn template for tool-result assessment. Use `{text}` as placeholder.
    pub assess_tool_result_user_prompt_template: String,
    /// System prompt for Stage 2 cross-validation.
    pub cross_check_system_prompt: String,
    /// User-turn template for cross-validation. Placeholders: {other_judge_id}, {other_verdict_str}, {other_reason}, {text}.
    pub cross_check_user_prompt_template: String,
    /// Keywords in LLM prose indicating UNSAFE (plain-text fallback).
    pub fallback_unsafe_signals: Vec<String>,
    /// Keywords in LLM prose indicating SAFE (plain-text fallback).
    pub fallback_safe_signals: Vec<String>,
    /// Confidence cap for plain-text fallback verdicts. Default: 0.70.
    pub fallback_confidence: f32,
    /// Confidence for ambiguous plain-text fallback. Default: 0.50.
    pub fallback_ambiguous_confidence: f32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TieBehaviour {
    Block,
    Allow,
}

impl JudgeConfig {
    /// Build a `JudgeConfig` from a [`crate::config::ServiceConfig`].
    /// Returns `None` when `litellm_url` / `litellm_api_key` are absent (judge pipeline disabled).
    pub fn from_config(cfg: &crate::config::ServiceConfig) -> Option<Self> {
        let litellm_url = cfg.litellm_url.clone().filter(|s| !s.is_empty())?;
        let litellm_api_key = cfg.litellm_api_key.clone().filter(|s| !s.is_empty())?;

        let tie_behaviour = match cfg.tie_behaviour.trim().to_ascii_lowercase().as_str() {
            "allow" => TieBehaviour::Allow,
            _ => TieBehaviour::Block,
        };

        // Deduplicate fallback pool — remove any model that is judge1 or judge2.
        let mut fallback_models = cfg.fallback_models.clone();
        let primaries: Vec<&str> = [cfg.judge1_model.as_str(), cfg.judge2_model.as_str()].into_iter().collect();
        let before = fallback_models.len();
        fallback_models.retain(|m| !primaries.contains(&m.as_str()));
        if fallback_models.len() < before {
            eprintln!(
                "judge: removed {} model(s) from fallback pool (duplicate of judge1/judge2)",
                before - fallback_models.len()
            );
        }
        if fallback_models.is_empty() {
            eprintln!("judge: fallback pool is empty — no fallback available if a primary model fails");
        } else {
            eprintln!("judge: fallback pool = {:?}", fallback_models);
        }

        // Load all policy values from file or fall back to built-in defaults
        let policy = load_judge_policy(cfg.llm_judge_rules_path.as_deref());

        Some(JudgeConfig {
            litellm_url,
            litellm_api_key,
            judge1_model: cfg.judge1_model.clone(),
            judge2_model: cfg.judge2_model.clone(),
            confidence_threshold: cfg.confidence_threshold,
            keyword_scan_safe_score: cfg.keyword_scan_safe_score,
            keyword_scan_block_score: cfg.keyword_scan_block_score,
            skip_cross_on_consensus: cfg.skip_cross_on_consensus,
            tie_behaviour,
            timeout_ms: cfg.timeout_ms,
            fallback_models,
            max_fallback_attempts: cfg.max_fallback_attempts,
            circuit_breaker_failures: cfg.circuit_breaker_failures,
            circuit_breaker_timeout_s: cfg.circuit_breaker_timeout_s,
            temperature:              cfg.judge_temperature,
            max_tokens:               cfg.judge_max_tokens,
            cross_check_max_tokens:   cfg.judge_cross_check_max_tokens,
            model_max_tokens:         cfg.judge_model_max_tokens.clone(),
            accept_invalid_certs:     cfg.judge_accept_invalid_certs,
            pool_max_idle_per_host:   cfg.judge_pool_max_idle_per_host,
            pool_idle_timeout_secs:   cfg.judge_pool_idle_timeout_secs,
            assess_system_prompt:             policy.assess_system_prompt,
            assess_user_prompt_template:      policy.assess_user_prompt_template,
            assess_tool_result_system_prompt:        policy.assess_tool_result_system_prompt,
            assess_tool_result_user_prompt_template: policy.assess_tool_result_user_prompt_template,
            cross_check_system_prompt:        policy.cross_check_system_prompt,
            cross_check_user_prompt_template: policy.cross_check_user_prompt_template,
            fallback_unsafe_signals:          policy.fallback_unsafe_signals,
            fallback_safe_signals:            policy.fallback_safe_signals,
            fallback_confidence:              policy.fallback_confidence,
            fallback_ambiguous_confidence:    policy.fallback_ambiguous_confidence,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Verdict types
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Safe,
    Unsafe,
}

#[derive(Debug, Clone)]
pub struct JudgeVerdict {
    pub verdict: Verdict,
    pub confidence: f32,
    pub reason: String,
    /// Threat category (e.g. "violence_extremism", "financial_fraud"); "other" if unknown.
    /// Logged via req_id log lines.
    #[allow(dead_code)]
    pub category: String,
    /// Friendly refusal message for the UI (empty when SAFE).
    pub friendly_message: String,
    /// Judge role that produced this verdict (e.g. "judge1", "judge2-cross").
    /// Read via req_id log lines.
    #[allow(dead_code)]
    pub judge_id: &'static str,
    /// The actual model name that produced this verdict (may be a fallback).
    pub model: String,
}

/// Final outcome of the full judge pipeline.
#[derive(Debug, Clone)]
pub enum JudgeOutcome {
    /// Request is safe — allow through to next layer.
    Allow { stage: &'static str, score: f32 },
    /// Request is unsafe — block with reason and optional friendly message.
    Block { reason: String, stage: &'static str, score: f32, friendly_message: String },
    /// Judges were skipped (heuristic score outside borderline zone).
    Skipped { stage: &'static str, score: f32 },
    /// One or both judges unavailable (timeout / error) — main.rs decides based on config.
    Unavailable { reason: String },
}

// ─────────────────────────────────────────────────────────────────────────────
// LiteLLM wire types
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct LiteLlmRequest {
    model: String,
    messages: Vec<LiteLlmMessage>,
    temperature: f32,
    max_tokens: u32,
    stream: bool,
    /// Suppress chain-of-thought on reasoning models so they emit JSON directly.
    /// Omitted for non-reasoning models that would reject the field.
    #[serde(skip_serializing_if = "Option::is_none")]
    reasoning_effort: Option<&'static str>,
}

#[derive(Serialize)]
struct LiteLlmMessage {
    role: &'static str,
    content: String,
}

#[derive(Deserialize)]
struct LiteLlmResponse {
    choices: Vec<LiteLlmChoice>,
}

#[derive(Deserialize)]
struct LiteLlmChoice {
    message: LiteLlmChoiceMessage,
}

#[derive(Deserialize)]
struct LiteLlmChoiceMessage {
    /// `null` when the model uses reasoning_content or when output is truncated.
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    reasoning_content: Option<String>,
    #[serde(default)]
    provider_specific_fields: Option<LiteLlmProviderFields>,
}

#[derive(Deserialize)]
struct LiteLlmProviderFields {
    #[serde(default)]
    reasoning_content: Option<String>,
}

/// The JSON structure we ask the LLM to return.
#[derive(Deserialize)]
struct LlmJudgeReply {
    verdict: String,
    confidence: f32,
    reason: String,
    /// Threat category identified by the judge (e.g. "violence_extremism", "financial_fraud").
    /// Defaults to "other" if the model omits it.
    #[serde(default = "default_category")]
    category: String,
    #[serde(default)]
    friendly_message: String,
}

fn default_category() -> String { "other".to_string() }

// ─────────────────────────────────────────────────────────────────────────────
// LlmJudge — generic judge, model-agnostic with fallback + circuit breaker
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct LlmJudge {
    /// Ordered list of model slots: [primary, fallback1, fallback2, ...].
    /// Each slot has its own circuit breaker.
    models: Vec<ModelSlot>,
    /// Which model slot was last successfully used (for audit).
    #[allow(dead_code)]
    last_used_model: String,
    litellm_url: String,
    api_key: String,
    timeout_ms: u64,
    /// Max models to try per call (primary + fallbacks).
    max_attempts: usize,
    client: reqwest::Client,
    /// LLM sampling temperature.
    temperature: f32,
    max_tokens: u32,
    cross_check_max_tokens: u32,
    /// System prompt for primary assessment.
    assess_system_prompt: String,
    /// User-turn template for primary assessment.
    assess_user_prompt_template: String,
    /// System prompt for tool-result / retrieved / connector assessment.
    assess_tool_result_system_prompt: String,
    /// User-turn template for tool-result assessment.
    assess_tool_result_user_prompt_template: String,
    /// System prompt for Stage 2 cross-validation.
    cross_check_system_prompt: String,
    /// User-turn template for cross-validation.
    cross_check_user_prompt_template: String,
    /// Fallback unsafe signal keywords.
    fallback_unsafe_signals: Vec<String>,
    /// Fallback safe signal keywords.
    fallback_safe_signals: Vec<String>,
    /// Confidence cap for plain-text fallback verdicts.
    fallback_confidence: f32,
    /// Confidence for ambiguous plain-text fallback.
    fallback_ambiguous_confidence: f32,
}

impl LlmJudge {
    pub fn new(
        primary_model: String,
        fallback_pool: Vec<String>,
        judge_index: usize,
        max_attempts: usize,
        cb_failures: usize,
        cb_timeout_s: u64,
        litellm_url: String,
        api_key: String,
        timeout_ms: u64,
        temperature: f32,
        max_tokens: u32,
        cross_check_max_tokens: u32,
        model_max_tokens: std::collections::HashMap<String, u32>,
        accept_invalid_certs: bool,
        pool_max_idle_per_host: usize,
        pool_idle_timeout_secs: u64,
        assess_system_prompt: String,
        assess_user_prompt_template: String,
        assess_tool_result_system_prompt: String,
        assess_tool_result_user_prompt_template: String,
        cross_check_system_prompt: String,
        cross_check_user_prompt_template: String,
        fallback_unsafe_signals: Vec<String>,
        fallback_safe_signals: Vec<String>,
        fallback_confidence: f32,
        fallback_ambiguous_confidence: f32,
    ) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(timeout_ms))
            .danger_accept_invalid_certs(accept_invalid_certs)
            .pool_max_idle_per_host(pool_max_idle_per_host)
            .pool_idle_timeout(std::time::Duration::from_secs(pool_idle_timeout_secs))
            .build()
            .expect("failed to build reqwest client");

        // Build rotated fallback order: each judge starts at a different offset
        // so judge1 and judge2 never pick the same fallback first.
        let rotated = if fallback_pool.is_empty() || fallback_pool.len() <= 1 {
            fallback_pool.clone()
        } else {
            let offset = judge_index % fallback_pool.len();
            let mut rotated = Vec::with_capacity(fallback_pool.len());
            for i in 0..fallback_pool.len() {
                rotated.push(fallback_pool[(offset + i) % fallback_pool.len()].clone());
            }
            rotated
        };

        // Build model slots: primary first, then rotated fallbacks.
        // Each slot carries its own max_tokens override (None = use judge default).
        let mut models = Vec::new();
        models.push(ModelSlot {
            model: primary_model.clone(),
            circuit: Arc::new(CircuitBreaker::new(cb_failures, cb_timeout_s)),
            is_primary: true,
            max_tokens: model_max_tokens.get(&primary_model).copied(),
        });
        for fb in &rotated {
            models.push(ModelSlot {
                model: fb.clone(),
                circuit: Arc::new(CircuitBreaker::new(cb_failures, cb_timeout_s)),
                is_primary: false,
                max_tokens: model_max_tokens.get(fb).copied(),
            });
        }

        if !rotated.is_empty() {
            eprintln!(
                "judge[{}]: model order = [{}] (fallback offset={})",
                judge_index,
                models.iter().map(|m| m.model.as_str()).collect::<Vec<_>>().join(", "),
                if fallback_pool.len() > 1 { judge_index % fallback_pool.len() } else { 0 }
            );
        }

        LlmJudge {
            models,
            last_used_model: primary_model.clone(),
            litellm_url,
            api_key,
            timeout_ms,
            max_attempts: max_attempts.max(1),
            client,
            temperature,
            max_tokens,
            cross_check_max_tokens,
            assess_system_prompt,
            assess_user_prompt_template,
            assess_tool_result_system_prompt,
            assess_tool_result_user_prompt_template,
            cross_check_system_prompt,
            cross_check_user_prompt_template,
            fallback_unsafe_signals,
            fallback_safe_signals,
            fallback_confidence,
            fallback_ambiguous_confidence,
        }
    }

    /// Send a chat request to LiteLLM and parse the verdict. Tries models in order,
    /// skipping open-circuit ones. Shared by `assess()` and `cross_check()`.
    /// `req_id` correlates all log lines for one prompt.
    async fn call(&self, system: &str, user: &str, judge_id: &'static str, req_id: &str, skip_set: &Arc<Mutex<HashSet<String>>>) -> Result<JudgeVerdict, String> {
        self.call_with_tokens(system, user, judge_id, req_id, self.max_tokens, skip_set).await
    }

    async fn call_with_tokens(&self, system: &str, user: &str, judge_id: &'static str, req_id: &str, default_max_tokens: u32, skip_set: &Arc<Mutex<HashSet<String>>>) -> Result<JudgeVerdict, String> {
        let url = format!("{}/chat/completions", self.litellm_url.trim_end_matches('/'));
        let mut errors: Vec<String> = Vec::new();
        let mut attempts = 0;

        for slot in &self.models {
            if attempts >= self.max_attempts {
                break;
            }

            // Skip models that timed out earlier in this same request — no point
            // waiting another 30s for a model we already know is dead right now.
            if skip_set.lock().unwrap().contains(&slot.model) {
                tracing::info!("[{}] [{}] model={} result=SKIP reason=request_skip_set", req_id, judge_id, slot.model);
                errors.push(format!("{}: skipped (timed out earlier this request)", slot.model));
                continue;
            }

            // Check circuit breaker — skip models that are currently open
            if !slot.circuit.should_try() {
                tracing::info!("[{}] [{}] model={} result=SKIP reason=circuit_open", req_id, judge_id, slot.model);
                errors.push(format!("{}: circuit open", slot.model));
                continue;
            }

            // If circuit just transitioned to HalfOpen, send a lightweight probe
            // before the full judge request to avoid re-opening the circuit
            let is_halfopen = {
                let s = slot.circuit.state.read().unwrap();
                matches!(*s, CircuitState::HalfOpen)
            };
            if is_halfopen {
                let probe_url = format!("{}/chat/completions", self.litellm_url.trim_end_matches('/'));
                let probe_ok = slot.circuit.probe(
                    &probe_url, &self.api_key, &slot.model, &self.client, 10_000
                ).await;
                if !probe_ok {
                    tracing::info!("[{}] [{}] model={} result=SKIP reason=probe_failed", req_id, judge_id, slot.model);
                    slot.circuit.record_failure();
                    errors.push(format!("{}: probe failed", slot.model));
                    continue;
                }
                // Probe succeeded — close the circuit and proceed with full request
                slot.circuit.record_success();
            }
            attempts += 1;
            let t_attempt = Instant::now();

            let request_body = LiteLlmRequest {
                model: slot.model.clone(),
                messages: vec![
                    LiteLlmMessage { role: "system", content: system.to_string() },
                    LiteLlmMessage { role: "user", content: user.to_string() },
                ],
                temperature: self.temperature,
                max_tokens: slot.max_tokens.unwrap_or(default_max_tokens),
                stream: false,
                // Reasoning models can exhaust max_tokens on chain-of-thought and
                // never emit the JSON verdict — forcing the Safe @ 0.50 fallback.
                // "none" makes them return the verdict directly. LiteLLM drops
                // the field for unsupported models, so this is safe to send always.
                reasoning_effort: Some("none"),
            };

            let resp = match self.client.post(&url).bearer_auth(&self.api_key).json(&request_body).send().await {
                Ok(r) => r,
                Err(e) => {
                    slot.circuit.record_failure();
                    let err_msg = if e.is_timeout() {
                        // Add to per-request skip set so Stage 2 doesn't retry this model
                        skip_set.lock().unwrap().insert(slot.model.clone());
                        format!("timeout after {}ms", self.timeout_ms)
                    } else if e.is_connect() {
                        format!("connection refused")
                    } else {
                        format!("{}", e)
                    };
                    tracing::warn!("[{}] [{}] model={} result=FAILED duration={}ms reason=\"{}\"",
                        req_id, judge_id, slot.model, t_attempt.elapsed().as_millis(), err_msg);
                    errors.push(format!("{}: {}", slot.model, err_msg));
                    continue;
                }
            };

            if !resp.status().is_success() {
                let status = resp.status();
                let err_body = resp.text().await.unwrap_or_default();
                let err_body_preview = err_body.chars().take(300).collect::<String>();
                let err_msg = format!("HTTP {} — {}", status, err_body_preview);

                // On HTTP 500/503 — retry same model with exponential backoff
                // before giving up and moving to next fallback
                if status.as_u16() == 500 || status.as_u16() == 503 {
                    for backoff_ms in [1_000u64, 2_000, 4_000] {
                        tracing::warn!(
                            "[{}] [{}] model={} result=FAILED duration={}ms reason=\"{}\" — retrying in {}ms",
                            req_id, judge_id, slot.model, t_attempt.elapsed().as_millis(), err_msg, backoff_ms
                        );
                        tokio::time::sleep(tokio::time::Duration::from_millis(backoff_ms)).await;

                        // Retry the same model
                        let retry_resp = match self.client.post(&url).bearer_auth(&self.api_key).json(&request_body).send().await {
                            Ok(r) => r,
                            Err(e) => {
                                tracing::warn!("[{}] [{}] model={} retry FAILED reason=\"{}\"", req_id, judge_id, slot.model, e);
                                slot.circuit.record_failure();
                                continue;
                            }
                        };

                        let retry_status = retry_resp.status();
                        if retry_status.is_success() {
                            let raw_body = retry_resp.text().await.unwrap_or_default();
                            let content = extract_content(&raw_body);
                            if !content.is_empty() {
                                slot.circuit.record_success();
                                let (verdict, confidence, reason, category, friendly_message) = match parse_verdict(
                                    &content, &slot.model,
                                    &self.fallback_unsafe_signals,
                                    &self.fallback_safe_signals,
                                    self.fallback_confidence,
                                    self.fallback_ambiguous_confidence,
                                ) {
                                    Ok(v) => v,
                                    Err(e) => { errors.push(format!("{}: parse error after retry: {}", slot.model, e)); break; }
                                };
                                tracing::info!(
                                    "[{}] [{}] model={} result=OK(retry) verdict={:?} conf={:.2} category={} duration={}ms reason=\"{}\" json_response={}",
                                    req_id, judge_id, slot.model, verdict, confidence, category, t_attempt.elapsed().as_millis(), reason,
                                    log_one_line(&content)
                                );
                                return Ok(JudgeVerdict { verdict, confidence, reason, category, friendly_message, judge_id, model: slot.model.clone() });
                            }
                        }
                        tracing::warn!("[{}] [{}] model={} retry still failing status={}", req_id, judge_id, slot.model, retry_status);
                    }
                    slot.circuit.record_failure();
                } else {
                    slot.circuit.record_failure();
                }

                tracing::warn!("[{}] [{}] model={} result=FAILED duration={}ms reason=\"{}\"",
                    req_id, judge_id, slot.model, t_attempt.elapsed().as_millis(), err_msg);
                errors.push(format!("{}: {}", slot.model, err_msg));
                continue;
            }

            let raw_body = resp.text().await.unwrap_or_default();
            let content = extract_content(&raw_body);

            if content.is_empty() {
                slot.circuit.record_failure();
                tracing::warn!("[{}] [{}] model={} result=FAILED duration={}ms reason=\"empty response from LLM\"",
                    req_id, judge_id, slot.model, t_attempt.elapsed().as_millis());
                errors.push(format!("{}: empty response from LLM", slot.model));
                continue;
            }



            // Success — reset circuit breaker for this model
            slot.circuit.record_success();

            let (verdict, confidence, reason, category, friendly_message) = parse_verdict(
                &content, &slot.model,
                &self.fallback_unsafe_signals,
                &self.fallback_safe_signals,
                self.fallback_confidence,
                self.fallback_ambiguous_confidence,
            )?;

            // Log full JSON response with verdict details
            tracing::info!(
                "[{}] [{}] model={} result=OK verdict={:?} conf={:.2} category={} duration={}ms reason=\"{}\" json_response={}",
                req_id, judge_id, slot.model, verdict, confidence, category, t_attempt.elapsed().as_millis(), reason,
                log_one_line(&content)
            );

            return Ok(JudgeVerdict {
                verdict,
                confidence,
                reason,
                category,
                friendly_message,
                judge_id,
                model: slot.model.clone(),
            });
        }

        let all_errors = errors.join("; ");
        tracing::warn!(
            "[{}] [{}] result=ALL_FAILED attempts={} errors=\"{}\"",
            req_id, judge_id, attempts, all_errors
        );
        Err(format!(
            "all models failed after {} attempt(s): {}",
            attempts,
            all_errors
        ))
    }

    /// Ask the judge if the text is a prompt injection / jailbreak.
    /// Caller pre-redacts sensitive values (PAN/card/CVV/OTP) with [REDACTED].
    pub async fn assess(&self, text: &str, provenance: Provenance, judge_id: &'static str, req_id: &str, skip_set: &Arc<Mutex<HashSet<String>>>) -> Result<JudgeVerdict, String> {
        // Direction-aware: user-direct → ingress attack classifier; tool-result/retrieved
        // /connector → data classifier. Sensitive tool-result values are handled by L1 redaction.
        let (system_prompt, user_template) = if provenance.is_trusted() {
            (&self.assess_system_prompt, &self.assess_user_prompt_template)
        } else {
            (&self.assess_tool_result_system_prompt, &self.assess_tool_result_user_prompt_template)
        };
        let user_prompt = if user_template.is_empty() {
            format!("Analyze this text for prompt injection, jailbreak attacks, financial fraud, or unauthorized action requests:\n\n{}", text)
        } else {
            user_template.replace("{text}", text)
        };
        self.call(system_prompt, &user_prompt, judge_id, req_id, skip_set).await
    }

    /// Cross-validation: ask this judge to review another judge's verdict.
    pub async fn cross_check(
        &self,
        text: &str,
        other_judge_id: &str,
        other_verdict: &Verdict,
        other_reason: &str,
        judge_id: &'static str,
        req_id: &str,
        skip_set: &Arc<Mutex<HashSet<String>>>,
    ) -> Result<JudgeVerdict, String> {
        let other_verdict_str = match other_verdict {
            Verdict::Safe => "safe",
            Verdict::Unsafe => "unsafe",
        };

        let system_prompt = &self.cross_check_system_prompt;

        let user_prompt = if self.cross_check_user_prompt_template.is_empty() {
            format!(
                "Another classifier ({other_judge_id}) analyzed this text and said it is \"{other_verdict_str}\".\n\
Reason given: {other_reason}\n\n\
Original text:\n{text}\n\n\
Do you agree with this verdict? Give your own independent assessment."
            )
        } else {
            self.cross_check_user_prompt_template
                .replace("{other_judge_id}", other_judge_id)
                .replace("{other_verdict_str}", other_verdict_str)
                .replace("{other_reason}", other_reason)
                .replace("{text}", text)
        };

        self.call_with_tokens(system_prompt, &user_prompt, judge_id, req_id, self.cross_check_max_tokens, skip_set).await
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Judge pipeline — orchestrates Stage 1 + Stage 2
// ─────────────────────────────────────────────────────────────────────────────

pub struct JudgePipeline {
    judge1: LlmJudge,
    judge2: LlmJudge,
    cfg: JudgeConfig,
}

impl JudgePipeline {
    pub fn new(cfg: JudgeConfig) -> Self {
        let judge1 = LlmJudge::new(
            cfg.judge1_model.clone(),
            cfg.fallback_models.clone(),
            0, // judge_index for rotation offset
            cfg.max_fallback_attempts,
            cfg.circuit_breaker_failures,
            cfg.circuit_breaker_timeout_s,
            cfg.litellm_url.clone(),
            cfg.litellm_api_key.clone(),
            cfg.timeout_ms,
            cfg.temperature,
            cfg.max_tokens,
            cfg.cross_check_max_tokens,
            cfg.model_max_tokens.clone(),
            cfg.accept_invalid_certs,
            cfg.pool_max_idle_per_host,
            cfg.pool_idle_timeout_secs,
            cfg.assess_system_prompt.clone(),
            cfg.assess_user_prompt_template.clone(),
            cfg.assess_tool_result_system_prompt.clone(),
            cfg.assess_tool_result_user_prompt_template.clone(),
            cfg.cross_check_system_prompt.clone(),
            cfg.cross_check_user_prompt_template.clone(),
            cfg.fallback_unsafe_signals.clone(),
            cfg.fallback_safe_signals.clone(),
            cfg.fallback_confidence,
            cfg.fallback_ambiguous_confidence,
        );
        let judge2 = LlmJudge::new(
            cfg.judge2_model.clone(),
            cfg.fallback_models.clone(),
            1, // judge_index for rotation offset (different from judge1)
            cfg.max_fallback_attempts,
            cfg.circuit_breaker_failures,
            cfg.circuit_breaker_timeout_s,
            cfg.litellm_url.clone(),
            cfg.litellm_api_key.clone(),
            cfg.timeout_ms,
            cfg.temperature,
            cfg.max_tokens,
            cfg.cross_check_max_tokens,
            cfg.model_max_tokens.clone(),
            cfg.accept_invalid_certs,
            cfg.pool_max_idle_per_host,
            cfg.pool_idle_timeout_secs,
            cfg.assess_system_prompt.clone(),
            cfg.assess_user_prompt_template.clone(),
            cfg.assess_tool_result_system_prompt.clone(),
            cfg.assess_tool_result_user_prompt_template.clone(),
            cfg.cross_check_system_prompt.clone(),
            cfg.cross_check_user_prompt_template.clone(),
            cfg.fallback_unsafe_signals.clone(),
            cfg.fallback_safe_signals.clone(),
            cfg.fallback_confidence,
            cfg.fallback_ambiguous_confidence,
        );
        JudgePipeline { judge1, judge2, cfg }
    }

    /// Run the full judge pipeline for a given text and keyword scan score.
    /// - Score outside borderline zone → skip judges.
    /// - Stage 1: both judges in parallel; agree with conf ≥ threshold → decide.
    /// - Stage 2: cross-validation on disagreement.
    /// - Final: majority vote across confident verdicts.
    /// `req_id` is caller-supplied so all log lines correlate.
    pub async fn evaluate(&self, text: &str, provenance: Provenance, keyword_scan_score: f32, req_id: &str) -> JudgeOutcome {
        // ── Skip zone (safety net; main.rs already gates on these scores) ──
        if keyword_scan_score <= self.cfg.keyword_scan_safe_score {
            return JudgeOutcome::Skipped { stage: "skipped", score: keyword_scan_score };
        }
        if keyword_scan_score >= self.cfg.keyword_scan_block_score {
            return JudgeOutcome::Block {
                reason: format!(
                    "keyword scan score {:.2} exceeds block threshold {:.2}",
                    keyword_scan_score, self.cfg.keyword_scan_block_score
                ),
                stage: "skipped",
                score: keyword_scan_score,
                friendly_message: DEFAULT_KEYWORD_FRIENDLY_MESSAGE.to_string(),
            };
        }

        // ── Timer — req_id comes from the caller so all lines correlate ──────
        let t_start = Instant::now();

        // ── Log: full input + judge assignments (untruncated for audit) ────
        // Newlines escaped so one request stays on one log line.
        let input_logged = text.replace('\n', "\\n").replace('\r', "\\r");
        tracing::info!("[{}] INPUT=\"{}\"", req_id, input_logged);
        tracing::info!(
            "[{}] provenance={:?} prompt={} judge1_primary={} judge2_primary={}",
            req_id,
            provenance,
            if provenance.is_trusted() { "assess" } else { "assess_tool_result" },
            self.judge1.models.first().map(|s| s.model.as_str()).unwrap_or("unknown"),
            self.judge2.models.first().map(|s| s.model.as_str()).unwrap_or("unknown"),
        );

        // ── Per-request skip set: Stage 1 timeouts skipped in Stage 2 ──────
        // Saves up to 30s per timed-out model; dropped when evaluate() returns.
        let skip_set: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));

        // ── Stage 1: parallel judges ───────────────────────────────────────
        let (r1, r2) = tokio::join!(
            self.judge1.assess(text, provenance, "judge1", &req_id, &skip_set),
            self.judge2.assess(text, provenance, "judge2", &req_id, &skip_set),
        );

        // Collect errors from failed judges
        let mut errors: Vec<String> = Vec::new();
        let v1 = match r1 {
            Ok(v)  => Some(v),
            Err(e) => { errors.push(format!("judge1: {e}")); None }
        };
        let v2 = match r2 {
            Ok(v)  => Some(v),
            Err(e) => { errors.push(format!("judge2: {e}")); None }
        };
        // Log stage 1 verdicts
        if let (Some(ref j1), Some(ref j2)) = (&v1, &v2) {
            tracing::info!(
                "[{}] stage1_result judge1_verdict={:?} judge1_conf={:.2} judge1_model={} judge1_category=\"{}\" | judge2_verdict={:?} judge2_conf={:.2} judge2_model={} judge2_category=\"{}\"",
                req_id, j1.verdict, j1.confidence, j1.model, j1.category, j2.verdict, j2.confidence, j2.model, j2.category
            );
        }

        // If one or both judges failed → let main.rs decide based on config
        if v1.is_none() && v2.is_none() {
            let reason = errors.join(" | ");
            tracing::warn!("[{}] ALL_JUDGES_UNAVAILABLE {}", req_id, reason);
            return JudgeOutcome::Unavailable { reason };
        }
        if v1.is_none() {
            tracing::warn!("[{}] judge1=UNAVAILABLE — proceeding with judge2 only", req_id);
            return JudgeOutcome::Unavailable { reason: errors[0].clone() };
        }
        if v2.is_none() {
            tracing::warn!("[{}] judge2=UNAVAILABLE — proceeding with judge1 only", req_id);
            return JudgeOutcome::Unavailable { reason: errors[0].clone() };
        }

        // ── Consensus check ────────────────────────────────────────────────
        if self.cfg.skip_cross_on_consensus {
            if let (Some(ref j1), Some(ref j2)) = (&v1, &v2) {
                if j1.confidence >= self.cfg.confidence_threshold
                    && j2.confidence >= self.cfg.confidence_threshold
                    && j1.verdict == j2.verdict
                {
                    let avg_score = (j1.confidence + j2.confidence) / 2.0;
                    let outcome = match j1.verdict {
                        Verdict::Unsafe => {
                            let reason = format!(
                                "consensus unsafe — judge1: {}; judge2: {}",
                                j1.reason, j2.reason
                            );
                            let s1_unsafe = [&j1.verdict, &j2.verdict].iter().filter(|v| ***v == Verdict::Unsafe).count();
                            let s1_safe   = [&j1.verdict, &j2.verdict].iter().filter(|v| ***v == Verdict::Safe).count();
                            let s1_total  = s1_unsafe + s1_safe;
                            tracing::info!(
                                "[{}] judge_decision=BLOCKED decided_by=stage1 unsafe_votes={} safe_votes={} total_votes={} final_score={:.2} final_category=\"{}\" duration={}ms",
                                req_id, s1_unsafe, s1_safe, s1_total, avg_score,
                                if !j1.category.is_empty() && j1.category != "other" { &j1.category } else { &j2.category },
                                t_start.elapsed().as_millis()
                            );
                            JudgeOutcome::Block {
                                reason,
                                stage: "stage1_consensus",
                                score: avg_score,
                                friendly_message: if j1.friendly_message.is_empty() { j2.friendly_message.clone() } else { j1.friendly_message.clone() },
                            }
                        }
                        Verdict::Safe => {
                            let s1_unsafe = [&j1.verdict, &j2.verdict].iter().filter(|v| ***v == Verdict::Unsafe).count();
                            let s1_safe   = [&j1.verdict, &j2.verdict].iter().filter(|v| ***v == Verdict::Safe).count();
                            let s1_total  = s1_unsafe + s1_safe;
                            tracing::info!(
                                "[{}] judge_decision=ALLOWED decided_by=stage1 unsafe_votes={} safe_votes={} total_votes={} final_score={:.2} duration={}ms",
                                req_id, s1_unsafe, s1_safe, s1_total, avg_score, t_start.elapsed().as_millis()
                            );
                            JudgeOutcome::Allow {
                                stage: "stage1_consensus",
                                score: avg_score,
                            }
                        }
                    };
                    return outcome;
                }
            }
        }

        // Stage 2: cross-validation on disagreement only.
        // Skip below-threshold verdicts — reviewing a 0.50 fallback is just noise.
        tracing::info!("[{}] stage=stage2_cross_validation (judges disagreed or below threshold)", req_id);

        // Both cross-checks run on disagreement.
        // judge1-cross: judge2 reviews judge1; judge2-cross: judge1 reviews judge2.
        let (cr1, cr2) = tokio::join!(
            async {
                match &v1 {
                    Some(j1) => self.judge2
                        .cross_check(text, "judge1", &j1.verdict, &j1.reason, "judge1-cross", &req_id, &skip_set)
                        .await
                        .ok(),
                    None => None,
                }
            },
            async {
                match &v2 {
                    Some(j2) => self.judge1
                        .cross_check(text, "judge2", &j2.verdict, &j2.reason, "judge2-cross", &req_id, &skip_set)
                        .await
                        .ok(),
                    None => None,
                }
            }
        );
        let cross1 = cr1;
        let cross2 = cr2;

        // ── Majority vote across all 4 verdicts ───────────────────────────
        let all_verdicts: Vec<&JudgeVerdict> = [&v1, &v2, &cross1, &cross2]
            .iter()
            .filter_map(|v| v.as_ref())
            .collect();

        let confident: Vec<&JudgeVerdict> = all_verdicts
            .iter()
            .filter(|v| v.confidence >= self.cfg.confidence_threshold)
            .copied()
            .collect();
        let total_votes = all_verdicts.len();
        // Summarise below-threshold votes as "N(Safe@0.50,Unsafe@0.60)" for the log
        let below_threshold_votes: Vec<&JudgeVerdict> = all_verdicts
            .iter()
            .filter(|v| v.confidence < self.cfg.confidence_threshold)
            .copied()
            .collect();
        let below_threshold = below_threshold_votes.len();
        let below_threshold_detail = if below_threshold == 0 {
            String::new()
        } else {
            let parts: Vec<String> = below_threshold_votes
                .iter()
                .map(|v| format!("{:?}@{:.2}", v.verdict, v.confidence))
                .collect();
            format!("({})", parts.join(","))
        };
        // Log cross-validation results
        tracing::info!(
            "[{}] stage2_cross_result \
             judge1_cross_verdict={} judge1_cross_conf={} judge1_cross_model={} judge1_cross_category=\"{}\" | \
             judge2_cross_verdict={} judge2_cross_conf={} judge2_cross_model={} judge2_cross_category=\"{}\" \
             confident_count={}",
            req_id,
            cross1.as_ref().map(|v| format!("{:?}", v.verdict)).unwrap_or("NONE".into()),
            cross1.as_ref().map(|v| format!("{:.2}", v.confidence)).unwrap_or("-".into()),
            cross1.as_ref().map(|v| v.model.as_str()).unwrap_or("-"),
            cross1.as_ref().map(|v| v.category.as_str()).unwrap_or("-"),
            cross2.as_ref().map(|v| format!("{:?}", v.verdict)).unwrap_or("NONE".into()),
            cross2.as_ref().map(|v| format!("{:.2}", v.confidence)).unwrap_or("-".into()),
            cross2.as_ref().map(|v| v.model.as_str()).unwrap_or("-"),
            cross2.as_ref().map(|v| v.category.as_str()).unwrap_or("-"),
            confident.len()
        );

        // If no verdict is confident enough → allow (models are uncertain)
        if confident.is_empty() {
            let all_unsafe = all_verdicts.iter().filter(|v| v.verdict == Verdict::Unsafe).count();
            let all_safe   = all_verdicts.iter().filter(|v| v.verdict == Verdict::Safe).count();
            tracing::info!(
                "[{}] judge_decision=ALLOWED decided_by=stage2 reason=no_confident_verdict unsafe_votes={} safe_votes={} total_votes={} below_threshold={}{} final_score=0.00 duration={}ms",
                req_id, all_unsafe, all_safe, total_votes, below_threshold, below_threshold_detail, t_start.elapsed().as_millis()
            );
            return JudgeOutcome::Allow { stage: "stage2_cross_validation", score: 0.0 };
        }

        let avg_score = confident.iter().map(|v| v.confidence).sum::<f32>() / confident.len() as f32;
        let unsafe_count = confident.iter().filter(|v| v.verdict == Verdict::Unsafe).count();
        let safe_count   = confident.iter().filter(|v| v.verdict == Verdict::Safe).count();

        if unsafe_count > safe_count {
            let reasons: Vec<&str> = confident
                .iter()
                .filter(|v| v.verdict == Verdict::Unsafe)
                .map(|v| v.reason.as_str())
                .collect();
            // Pick the best friendly_message from the unsafe verdicts
            let friendly_message = confident.iter()
                .filter(|v| v.verdict == Verdict::Unsafe)
                .find(|v| !v.friendly_message.is_empty())
                .map(|v| v.friendly_message.clone())
                .unwrap_or_default();
            let reason = if below_threshold > 0 {
                format!("majority unsafe ({unsafe_count} vs {safe_count}, {below_threshold} below threshold): {}", reasons.join("; "))
            } else {
                format!("majority unsafe ({unsafe_count} vs {safe_count}): {}", reasons.join("; "))
            };
            // Consolidated final category: unique non-"other" values from unsafe verdicts, "other" as fallback
            let mut cats: Vec<&str> = confident.iter()
                .filter(|v| v.verdict == Verdict::Unsafe)
                .map(|v| v.category.as_str())
                .collect();
            cats.sort_by_key(|c| if *c == "other" { 1 } else { 0 });
            cats.dedup();
            let category_final = cats.join(", ");
            tracing::info!(
                "[{}] judge_decision=BLOCKED decided_by=stage2 unsafe_votes={} safe_votes={} total_votes={} below_threshold={}{} final_score={:.2} final_category=\"{}\" duration={}ms",
                req_id, unsafe_count, safe_count, total_votes, below_threshold, below_threshold_detail, avg_score, category_final, t_start.elapsed().as_millis()
            );
            JudgeOutcome::Block {
                reason,
                stage:  "stage2_cross_validation",
                score:  avg_score,
                friendly_message,
            }
        } else if safe_count > unsafe_count {
            tracing::info!(
                "[{}] judge_decision=ALLOWED decided_by=stage2 unsafe_votes={} safe_votes={} total_votes={} below_threshold={}{} final_score={:.2} duration={}ms",
                req_id, unsafe_count, safe_count, total_votes, below_threshold, below_threshold_detail, avg_score, t_start.elapsed().as_millis()
            );
            JudgeOutcome::Allow { stage: "stage2_cross_validation", score: avg_score }
        } else {
            // Tie — apply configured tie behaviour
            match self.cfg.tie_behaviour {
                TieBehaviour::Block => {
                    let reason = format!("tie ({unsafe_count} unsafe vs {safe_count} safe) — fail-closed");
                    tracing::info!(
                        "[{}] judge_decision=BLOCKED decided_by=stage2 result=TIE unsafe_votes={} safe_votes={} total_votes={} below_threshold={}{} final_score={:.2} duration={}ms",
                        req_id, unsafe_count, safe_count, total_votes, below_threshold, below_threshold_detail, avg_score, t_start.elapsed().as_millis()
                    );
                    JudgeOutcome::Block {
                        reason,
                        stage:  "stage2_cross_validation",
                        score:  avg_score,
                        friendly_message: DEFAULT_TIE_FRIENDLY_MESSAGE.to_string(),
                    }
                }
                TieBehaviour::Allow => {
                    tracing::info!(
                        "[{}] judge_decision=ALLOWED decided_by=stage2 result=TIE unsafe_votes={} safe_votes={} total_votes={} below_threshold={}{} final_score={:.2} duration={}ms",
                        req_id, unsafe_count, safe_count, total_votes, below_threshold, below_threshold_detail, avg_score, t_start.elapsed().as_millis()
                    );
                    JudgeOutcome::Allow {
                        stage: "stage2_cross_validation",
                        score: avg_score,
                    }
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Extract the first JSON object from a string — handles markdown code fences.
fn extract_json(s: &str) -> Option<String> {
    let s = s
        .trim()
        .trim_start_matches("```json")
        .trim_start_matches("```")
        .trim_end_matches("```")
        .trim();
    let start = s.find('{')?;
    let end = s.rfind('}')?;
    if end < start {
        return None;
    }
    Some(s[start..=end].to_string())
}

/// Extract text content from a LiteLLM response body.
/// Handles reasoning models (content in `reasoning_content`); falls back to raw body.
fn extract_content(raw_body: &str) -> String {
    if let Ok(llm_resp) = serde_json::from_str::<LiteLlmResponse>(raw_body) {
        if let Some(c) = llm_resp.choices.first() {
            // 1. message.content — primary field (may be null/empty when truncated).
            // Reasoning models emit CoT prose before the JSON verdict; extract JSON if present.
            if let Some(ref text) = c.message.content {
                let t = text.trim();
                if !t.is_empty() {
                    // Try to extract JSON verdict from within the prose first
                    if let Some(json) = extract_json(t) {
                        if json.contains("verdict") {
                            return json.to_string();
                        }
                    }
                    return t.to_string();
                }
            }

            // 2. reasoning_content — used by reasoning models (DeepSeek-R1, QwQ, etc.)
            let reasoning = c.message.reasoning_content
                .as_ref()
                .or_else(|| {
                    c.message.provider_specific_fields
                        .as_ref()
                        .and_then(|f| f.reasoning_content.as_ref())
                });
            if let Some(rc) = reasoning {
                if let Some(json) = extract_json(rc) {
                    return json.to_string();
                }
                let t = rc.trim();
                if !t.is_empty() {
                    return t.to_string();
                }
            }

            // 3. content null/empty (e.g. qwen finish_reason=length) — try to extract
            //    a JSON verdict from the raw body (model may have written it pre-truncation).
            if let Some(json) = extract_json(raw_body) {
                // Only use it if it looks like a judge reply (has "verdict" key)
                if json.contains("verdict") {
                    return json.to_string();
                }
            }
        }
    }

    // Final fallback — return raw body so parse_verdict can attempt keyword scan
    raw_body.trim().to_string()
}

/// Parse the LLM response into a verdict; tries JSON first, then keyword scan.
/// Returns (verdict, confidence, reason, category, friendly_message).
fn parse_verdict(
    content: &str,
    model: &str,
    fallback_unsafe: &[String],
    fallback_safe: &[String],
    fallback_confidence: f32,
    fallback_ambiguous_confidence: f32,
) -> Result<(Verdict, f32, String, String, String), String> {
    // Try up to 3 forms: direct JSON, unescaped JSON (deepseek wraps output
    // in quotes: "{\"verdict\":...}"), and outer-quote-stripped + unescaped.
    if let Some(json_str) = extract_json(content) {
        // Attempt 1: parse directly
        if let Ok(reply) = serde_json::from_str::<LlmJudgeReply>(&json_str) {
            let v = match reply.verdict.trim().to_ascii_lowercase().as_str() {
                "unsafe" => Verdict::Unsafe,
                _ => Verdict::Safe,
            };
            return Ok((v, reply.confidence.clamp(0.0, 1.0), reply.reason, reply.category, reply.friendly_message));
        }

        // Attempt 2: unescape escaped JSON (e.g. deepseek returns "{\"verdict\":\"unsafe\"...}")
        let unescaped = json_str.replace("\\\"", "\"").replace("\\'", "'");
        if let Ok(reply) = serde_json::from_str::<LlmJudgeReply>(&unescaped) {
            let v = match reply.verdict.trim().to_ascii_lowercase().as_str() {
                "unsafe" => Verdict::Unsafe,
                _ => Verdict::Safe,
            };
            return Ok((v, reply.confidence.clamp(0.0, 1.0), reply.reason, reply.category, reply.friendly_message));
        }
    }

    // Attempt 3: content itself is a JSON string literal — strip outer quotes and unescape
    let trimmed = content.trim();
    if trimmed.starts_with('"') && trimmed.ends_with('"') {
        let inner = &trimmed[1..trimmed.len()-1];
        let unescaped = inner.replace("\\\"", "\"").replace("\\'", "'").replace("\\n", "\n");
        if let Some(json_str) = extract_json(&unescaped) {
            if let Ok(reply) = serde_json::from_str::<LlmJudgeReply>(&json_str) {
                let v = match reply.verdict.trim().to_ascii_lowercase().as_str() {
                    "unsafe" => Verdict::Unsafe,
                    _ => Verdict::Safe,
                };
                return Ok((v, reply.confidence.clamp(0.0, 1.0), reply.reason, reply.category, reply.friendly_message));
            }
        }
    }

    // Attempt 4: JSON may be truncated (no closing }) — search for "verdict":"unsafe" or "verdict":"safe"
    // directly in the raw content. Handles models that get cut off by max_tokens.
    let lower = content.to_lowercase();
    if let Some(idx) = lower.find("\"verdict\"") {
        let after = &lower[idx + 9..]; // skip past "verdict"
        if let Some(quote_start) = after.find('"') {
            let after_quote = &after[quote_start + 1..];
            if let Some(quote_end) = after_quote.find('"') {
                let verdict_val = after_quote[..quote_end].trim();
                let v = if verdict_val == "unsafe" { Verdict::Unsafe } else { Verdict::Safe };
                // Try to extract confidence if present
                let conf_str = &lower[idx..];
                let mut conf = 0.95f32; // high confidence since model explicitly stated verdict
                if let Some(conf_idx) = conf_str.find("\"confidence\"") {
                    let after_conf = &conf_str[conf_idx + 13..]; // skip past "confidence"
                    if let Some(colon) = after_conf.find(':') {
                        let num_part = after_conf[colon + 1..].trim_start();
                        if let Some(dot_idx) = num_part.find('.') {
                            let slice = &num_part[..dot_idx + 4]; // e.g. "0.98"
                            if let Ok(c) = slice.parse::<f32>() {
                                conf = c.clamp(0.0, 1.0);
                            }
                        } else if let Ok(c) = num_part[..num_part.len().min(3)].parse::<f32>() {
                            conf = c.clamp(0.0, 1.0);
                        }
                    }
                }
                let reason = format!("[truncated JSON] {}", &content[..content.len().min(200)]);
                return Ok((v, conf, reason, "other".into(), String::new()));
            }
        }
    }

    fallback_verdict(content, model, fallback_unsafe, fallback_safe, fallback_confidence, fallback_ambiguous_confidence)
}

/// Plain-text fallback verdict — used when the LLM returns prose instead of JSON.
/// Signals and confidence values are loaded from llm-judge-rules.toml at startup.
fn fallback_verdict(
    content: &str,
    _model: &str,
    unsafe_signals: &[String],
    safe_signals: &[String],
    fallback_confidence: f32,
    fallback_ambiguous_confidence: f32,
) -> Result<(Verdict, f32, String, String, String), String> {
    let lower = content.to_ascii_lowercase();
    let unsafe_hit = unsafe_signals.iter().any(|s| lower.contains(s.as_str()));
    let safe_hit   = safe_signals.iter().any(|s| lower.contains(s.as_str()));

    if unsafe_hit && !safe_hit {
        Ok((Verdict::Unsafe, fallback_confidence, "[plain-text fallback] suspicious prose from judge".into(), "other".into(), String::new()))
    } else if safe_hit && !unsafe_hit {
        let end = content.char_indices().nth(200).map(|(i,_)| i).unwrap_or(content.len());
        let reason = format!("[plain-text fallback] {}", &content[..end]);
        Ok((Verdict::Safe, fallback_confidence, reason, "safe".into(), String::new()))
    } else {
        Ok((Verdict::Safe, fallback_ambiguous_confidence, "[plain-text fallback] ambiguous prose — no clear verdict".into(), "other".into(), String::new()))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_json_plain() {
        let s = r#"{"verdict":"unsafe","confidence":0.95,"reason":"injection"}"#;
        assert!(extract_json(s).is_some());
    }

    #[test]
    fn extract_json_with_fences() {
        let s = "```json\n{\"verdict\":\"safe\",\"confidence\":0.1,\"reason\":\"clean\"}\n```";
        let extracted = extract_json(s).unwrap();
        assert!(extracted.contains("safe"));
    }

    #[test]
    fn extract_json_returns_none_on_empty() {
        assert!(extract_json("no json here").is_none());
    }

    #[test]
    fn builtin_toml_has_tool_result_prompt() {
        // The built-in llm-judge-rules.toml must define [assess_tool_result].
        let policy = load_judge_policy(None);
        assert!(!policy.assess_tool_result_system_prompt.is_empty(),
            "assess_tool_result system prompt must be loaded from built-in TOML");
        // It must be a DIFFERENT prompt from the ingress assess prompt.
        assert_ne!(policy.assess_tool_result_system_prompt, policy.assess_system_prompt,
            "tool-result prompt must differ from ingress assess prompt");
        // It must encode the core tool-result principle (data, not attack classifier).
        let p = policy.assess_tool_result_system_prompt.to_ascii_lowercase();
        assert!(p.contains("tool result") || p.contains("tool-result"),
            "tool-result prompt must state it is judging tool results");
        assert!(p.contains("redaction"),
            "tool-result prompt must defer sensitive values to redaction, not block");
    }

    #[test]
    fn tool_result_prompt_falls_back_to_assess_when_section_absent() {
        // A TOML with only [assess] and no [assess_tool_result] must fall back to
        // the ingress prompt, so older policy files keep working.
        let toml = r#"
[assess]
system_prompt = "INGRESS PROMPT"
user_prompt_template = "{text}"
[cross_check]
system_prompt = "X"
user_prompt_template = "{text}"
"#;
        let p: JudgePolicyFile = toml::from_str(toml).unwrap();
        let policy = from_policy_file(p);
        assert_eq!(policy.assess_tool_result_system_prompt, "INGRESS PROMPT",
            "absent [assess_tool_result] must fall back to [assess] system prompt");
    }

    #[test]
    fn judge_config_defaults_when_env_not_set() {
        // Without litellm_url/api_key in config, from_config() returns None
        let cfg = crate::config::ServiceConfig::default(); // litellm_url = None
        assert!(JudgeConfig::from_config(&cfg).is_none());
    }

    #[test]
    fn tie_behaviour_defaults_to_block() {
        std::env::remove_var("JUDGE_TIE_BEHAVIOUR");
        // Simulate reading tie behaviour
        let tie = match std::env::var("JUDGE_TIE_BEHAVIOUR")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "allow" => TieBehaviour::Allow,
            _ => TieBehaviour::Block,
        };
        assert_eq!(tie, TieBehaviour::Block);
    }

    #[test]
    fn skip_cross_on_consensus_defaults_to_true() {
        std::env::remove_var("JUDGE_SKIP_CROSS_ON_CONSENSUS");
        let skip = std::env::var("JUDGE_SKIP_CROSS_ON_CONSENSUS")
            .map(|v| v.trim().to_ascii_lowercase() != "false")
            .unwrap_or(true);
        assert!(skip);
    }
}
