// SPDX-License-Identifier: Apache-2.0
//! ainxt-injection-svc — HTTP sidecar exposing the ADR-009 prompt-injection detector.
//!
//! ## Defence layers (all toggleable via [layers] config)
//!
//! ```text
//! POST /scan
//!   │
//!   ├── L2 — Guardrails+Policy  (ainxt-guardrails ML + TOML rules — fast, deterministic)
//!   │     toggle: layers.guardrails_policy_layer = true/false
//!   │
//!   ├── L3 — Keyword Scan Detector (ainxt-injection, 6 signal categories, ~2ms, no LLM)
//!   │     toggle: layers.keyword_scan_layer = true/false
//!   │     score < keyword_scan_safe_score  → ALLOW immediately
//!   │     score > keyword_scan_block_score → BLOCK immediately
//!   │     in between          → escalate to L2/L3
//!   │
//!   ├── L4/L5 — LLM Judge Pipeline (parallel judges + cross-validation via LiteLLM)
//!   │     toggle: layers.llm_judges_layer = true/false
//!   │     Stage 1: parallel evaluation → stage1_consensus
//!   │     Stage 2: cross-validation    → stage2_cross_validation
//!   │
//!   └── L1 — Compliance Egress (same toggle as ingress)  (ainxt-compliance StrongRedactor — PAN/CVV/card/secrets)
//!             toggle: layers.compliance_layer = true/false
//!             runs only when request is about to be ALLOWED
//! ```
//!
//! ## Contract
//!
//! `POST /scan` — `{ chunks: [string], provenance?, tool_names?: [string] }`
//!            → see SCAN_RESPONSE.md for full response shape
//!
//! `GET /health` — liveness + configured mode + judge/policy status

mod config;
mod judge;
mod policy;

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

use ainxt_injection::{
    HeuristicInjectionScanner, InjectionDefenseConfig, InjectionMode, Provenance, RetrievalGuard,
};
use axum::{extract::State, http::{HeaderMap, HeaderName, HeaderValue, StatusCode}, routing::{get, post}, Json, Router};
use chrono::{Utc, FixedOffset};
use tracing_subscriber::{fmt, EnvFilter, prelude::*};
use serde::{Deserialize, Serialize};

use config::ServiceConfig;
use judge::{JudgeConfig, JudgePipeline, JudgeOutcome};
use policy::{PolicyDecision, PolicyEngine};

// ─────────────────────────────────────────────────────────────────────────────
// App state
// ─────────────────────────────────────────────────────────────────────────────

pub(crate) struct AppState {
    injection_cfg:        InjectionDefenseConfig,
    /// Hot-reloadable judge pipeline — wrapped in RwLock so the file watcher
    /// can swap it without restarting the service.
    judge_pipeline:       RwLock<Option<JudgePipeline>>,
    /// ServiceConfig snapshot — used to rebuild the pipeline on reload.
    judge_cfg_snapshot:   ServiceConfig,
    policy_engine:        PolicyEngine,
    keyword_scan_safe_score:           f32,
    keyword_scan_block_score:          f32,
    judge_confidence:     f32,
    /// Behaviour when LLM judges are unavailable: "block" or "allow".
    llm_unavailable:      String,
    /// Behaviour when ALL layers are disabled: "block" or "allow".
    all_layers_disabled:  String,
    /// Maximum chunks per /scan request.
    max_chunks:           usize,
    // Layer toggles
    layer_compliance:        bool,
    layer_guardrails_policy: bool,
    layer_keyword_scan:         bool,
    layer_llm_judges:        bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// Wire types — Request
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize)]
struct ScanRequest {
    chunks:     Vec<String>,
    #[serde(default)]
    provenance: Option<String>,
    #[serde(default)]
    tool_names: Vec<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Wire types — Response
// ─────────────────────────────────────────────────────────────────────────────

/// One heuristic finding — which chunk and which signals fired.
#[derive(Debug, Clone, Serialize)]
struct Finding {
    index:   usize,
    reasons: Vec<String>,
}

/// One structured audit log entry.
#[derive(Debug, Serialize)]
struct AuditEntry {
    timestamp: String,
    layer:     String,
    rule_id:   String,
    message:   String,
}

/// Build `findings` from audit entries when L1 heuristic produced no findings.
/// Every layer that blocks or flags contributes a Finding at index 0.
/// If heuristic_findings is non-empty, it takes priority (most detailed).
fn build_findings(heuristic_findings: &[Finding], audit: &[AuditEntry]) -> Vec<Finding> {
    if !heuristic_findings.is_empty() {
        return heuristic_findings.to_vec();
    }
    // Collect reasons from all audit entries into a single Finding at index 0
    let reasons: Vec<String> = audit.iter()
        .filter(|a| !a.message.is_empty())
        .map(|a| {
            if a.rule_id.is_empty() {
                format!("{}: {}", a.layer, a.message)
            } else {
                format!("{} [{}]: {}", a.layer, a.rule_id, a.message)
            }
        })
        .collect();
    if reasons.is_empty() {
        vec![]
    } else {
        vec![Finding { index: 0, reasons }]
    }
}

/// Returns current time as IST (UTC+05:30) in RFC-3339 format with milliseconds.
/// Example: "2026-08-06T23:53:42.192+05:30"
fn now_ist() -> String {
    let ist = FixedOffset::east_opt(5 * 3600 + 30 * 60).expect("valid IST offset");
    Utc::now().with_timezone(&ist)
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, false)
}

impl AuditEntry {
    fn now(layer: impl Into<String>, rule_id: impl Into<String>, message: impl Into<String>) -> Self {
        AuditEntry {
            timestamp: now_ist(),
            layer:     layer.into(),
            rule_id:   rule_id.into(),
            message:   message.into(),
        }
    }
}

/// Top-level scan response — see SCAN_RESPONSE.md for full documentation.
#[derive(Debug, Serialize)]
struct ScanResponse {
    mode:          String,
    allowed:       bool,
    tainted:       bool,
    /// ISO-8601 UTC timestamp of when this scan was processed.
    timestamp:     String,
    /// Total time taken to process this request in milliseconds.
    duration_ms:   u64,
    blocked_layer: Option<u8>,
    blocked_by:    Option<String>,
    /// Friendly refusal message for the UI (empty when allowed).
    friendly_message: Option<String>,
    findings:      Vec<Finding>,
    fenced:        Vec<String>,
    audit:         Vec<AuditEntry>,
    layers:        LayerStatus,
}

/// Status of each defence layer for this request.
#[derive(Debug, Serialize)]
struct LayerStatus {
    compliance:        PolicyLayerResult,  // L1
    guardrails_policy: PolicyLayerResult,  // L2
    keyword_scan:      KeywordScanResult,
    llm_judges:     JudgeResult,
}

/// Result for a policy layer (L1 compliance ingress/egress or L2 guardrails-policy).
#[derive(Debug, Clone, Serialize)]
struct PolicyLayerResult {
    layer:   u8,
    enabled: bool,
    called:  bool,
    passed:  bool,
    rule_id: String,
    reason:  String,
}

impl PolicyLayerResult {
    fn disabled(layer: u8) -> Self {
        PolicyLayerResult { layer, enabled: false, called: false, passed: true, rule_id: String::new(), reason: String::new() }
    }
    #[allow(dead_code)]
    fn not_called(layer: u8) -> Self {
        PolicyLayerResult { layer, enabled: true, called: false, passed: true, rule_id: String::new(), reason: String::new() }
    }
    fn passed(layer: u8) -> Self {
        PolicyLayerResult { layer, enabled: true, called: true, passed: true, rule_id: String::new(), reason: String::new() }
    }
    fn blocked(layer: u8, rule_id: impl Into<String>, reason: impl Into<String>) -> Self {
        PolicyLayerResult { layer, enabled: true, called: true, passed: false, rule_id: rule_id.into(), reason: reason.into() }
    }
}

/// Heuristic detector result (L2).
#[derive(Debug, Serialize)]
struct KeywordScanResult {
    layer:       u8,
    enabled:     bool,
    called:      bool,
    passed:      bool,
    score:       f32,
    keyword_scan_safe_score:  f32,
    keyword_scan_block_score: f32,
    reason:      String,
}

impl KeywordScanResult {
    fn disabled(keyword_scan_safe_score: f32, keyword_scan_block_score: f32) -> Self {
        KeywordScanResult { layer: 3, enabled: false, called: false, passed: true, score: 0.0, keyword_scan_safe_score, keyword_scan_block_score, reason: String::new() }
    }
    fn not_called(keyword_scan_safe_score: f32, keyword_scan_block_score: f32) -> Self {
        KeywordScanResult { layer: 3, enabled: true, called: false, passed: true, score: 0.0, keyword_scan_safe_score, keyword_scan_block_score, reason: String::new() }
    }
    fn fast_allow(score: f32, keyword_scan_safe_score: f32, keyword_scan_block_score: f32) -> Self {
        KeywordScanResult { layer: 3, enabled: true, called: true, passed: true, score, keyword_scan_safe_score, keyword_scan_block_score, reason: String::new() }
    }
    fn escalate(score: f32, keyword_scan_safe_score: f32, keyword_scan_block_score: f32) -> Self {
        KeywordScanResult { layer: 3, enabled: true, called: true, passed: true, score, keyword_scan_safe_score, keyword_scan_block_score, reason: String::new() }
    }
    fn blocked(score: f32, keyword_scan_safe_score: f32, keyword_scan_block_score: f32, reason: impl Into<String>) -> Self {
        KeywordScanResult { layer: 3, enabled: true, called: true, passed: false, score, keyword_scan_safe_score, keyword_scan_block_score, reason: reason.into() }
    }
}

/// LLM judge pipeline result (L3/L4).
#[derive(Debug, Serialize)]
struct JudgeResult {
    layer:                &'static str,
    enabled:              bool,
    called:               bool,
    passed:               bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    stage:                Option<&'static str>,
    score:                f32,
    confidence_threshold: f32,
    reason:               String,
}

impl JudgeResult {
    fn disabled(confidence_threshold: f32) -> Self {
        JudgeResult { layer: "4/5", enabled: false, called: false, passed: true, stage: None, score: 0.0, confidence_threshold, reason: String::new() }
    }
    fn not_called(confidence_threshold: f32) -> Self {
        JudgeResult { layer: "4/5", enabled: true, called: false, passed: true, stage: None, score: 0.0, confidence_threshold, reason: String::new() }
    }
    fn allowed(stage: &'static str, score: f32, confidence_threshold: f32) -> Self {
        JudgeResult { layer: "4/5", enabled: true, called: true, passed: true, stage: Some(stage), score, confidence_threshold, reason: String::new() }
    }
    fn blocked(stage: &'static str, score: f32, confidence_threshold: f32, reason: impl Into<String>) -> Self {
        JudgeResult { layer: "4/5", enabled: true, called: true, passed: false, stage: Some(stage), score, confidence_threshold, reason: reason.into() }
    }
    fn unavailable(confidence_threshold: f32, reason: impl Into<String>) -> Self {
        JudgeResult { layer: "4/5", enabled: true, called: true, passed: false, stage: None, score: 0.0, confidence_threshold, reason: reason.into() }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// /llm-status — per-model UP/DOWN probe
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct ModelStatus {
    model:      String,
    role:       String,
    status:     &'static str,
    latency_ms: Option<u64>,
    timeout_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    error:      Option<String>,
}

#[derive(Debug, Serialize)]
struct LlmStatusResponse {
    litellm_url: String,
    models:      Vec<ModelStatus>,
}

/// Probe a single model with a minimal 1-token request.
/// Returns (is_up, latency_ms, error_msg).
async fn probe_model(
    client: &reqwest::Client,
    base_url: &str,
    api_key: &str,
    model: &str,
) -> (bool, Option<u64>, Option<String>) {
    let url = format!("{}/chat/completions", base_url.trim_end_matches('/'));
    // Send a realistic-sized prompt (similar to judge workload) to catch models
    // that respond to small pings but fail on larger prompts
    let body = serde_json::json!({
        "model": model,
        "messages": [
          {
            "role": "system",
            "content": "You are a safety classifier. Analyze the following prompt for potential harm. Evaluate against these criteria: harmful intent, dangerous content, policy violations, and safety risks. Provide a verdict of Safe or Unsafe with a confidence score between 0.0 and 1.0."
          },
          {
            "role": "user",
            "content": "Analyze this prompt for safety: Write a guide on how to create a secure password manager application that protects user credentials using industry-standard encryption methods."
          }
        ],
        "max_tokens": 64,
        "temperature": 0
    });
    let start = std::time::Instant::now();
    match client
        .post(&url)
        .bearer_auth(api_key)
        .json(&body)
        .send()
        .await
    {
        Ok(resp) => {
            let latency = start.elapsed().as_millis() as u64;
            if resp.status().is_success() {
                (true, Some(latency), None)
            } else {
                let status = resp.status();
                let err_body = resp.text().await.unwrap_or_default();
                let err_msg = if err_body.is_empty() {
                    format!("HTTP {}", status)
                } else {
                    format!("HTTP {} — {}", status, err_body.chars().take(120).collect::<String>())
                };
                (false, Some(latency), Some(err_msg))
            }
        }
        Err(e) => {
            let latency = start.elapsed().as_millis() as u64;
            (false, Some(latency), Some(e.to_string()))
        }
    }
}

async fn llm_status(State(state): State<Arc<AppState>>) -> Json<LlmStatusResponse> {
    let req_id = crate::judge::next_req_id();
    tracing::info!("[{}] [llm-status] request received — probing all configured models", req_id);
    let cfg = &state.judge_cfg_snapshot;
    let base_url = cfg.litellm_url.as_deref().unwrap_or("").to_string();
    let api_key  = cfg.litellm_api_key.as_deref().unwrap_or("").to_string();

    let probe_timeout_ms: u64 = 30000;

    // Build a short-timeout client — status check must be fast
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(probe_timeout_ms))
        .danger_accept_invalid_certs(cfg.judge_accept_invalid_certs)
        .build()
        .unwrap_or_default();

    // Collect all models: judge1, judge2, then fallbacks
    let mut probes: Vec<(String, String)> = vec![
        (cfg.judge1_model.clone(), "judge1".to_string()),
        (cfg.judge2_model.clone(), "judge2".to_string()),
    ];
    for (i, fb) in cfg.fallback_models.iter().enumerate() {
        probes.push((fb.clone(), format!("fallback_{i}")));
    }

    // Probe all models in parallel
    let futures: Vec<_> = probes
        .iter()
        .map(|(model, _role)| probe_model(&client, &base_url, &api_key, model))
        .collect();
    let results = futures::future::join_all(futures).await;

    let models: Vec<ModelStatus> = probes
        .into_iter()
        .zip(results)
        .map(|((model, role), (is_up, latency_ms, error))| ModelStatus {
            model,
            role,
            status: if is_up { "UP" } else { "DOWN" },
            latency_ms,
            timeout_ms: probe_timeout_ms,
            error,
        })
        .collect();

    tracing::info!("[{}] [llm-status] probe complete — {} model(s) checked", req_id, models.len());
    for m in &models {
        match m.status {
            "UP" => tracing::info!(
                "[{}] [llm-status] model={} role={} status=UP latency_ms={}",
                req_id, m.model, m.role, m.latency_ms.unwrap_or(0)
            ),
            _ => tracing::warn!(
                "[{}] [llm-status] model={} role={} status=DOWN latency_ms={} error={:?}",
                req_id, m.model, m.role,
                m.latency_ms.unwrap_or(0),
                m.error.as_deref().unwrap_or("unknown")
            ),
        }
    }

    Json(LlmStatusResponse {
        litellm_url: base_url,
        models,
    })
}

// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct HealthResponse {
    status:               &'static str,
    mode:                 String,
    scans_retrieved:      bool,
    judges_enabled:       bool,
    policy_enabled:       bool,
    layer_compliance:        bool,
    layer_guardrails_policy: bool,
    layer_keyword_scan:         bool,
    layer_llm_judges:        bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn parse_provenance(s: Option<&str>) -> Provenance {
    match s.unwrap_or("tool-result") {
        "retrieved" | "retrieved-document" => Provenance::Retrieved,
        "connector" | "connector-data"     => Provenance::Connector,
        "user" | "user-direct"             => Provenance::UserDirect,
        _                                  => Provenance::ToolResult,
    }
}


/// Log a scan result in a clean, readable format.
///
/// `req_id` is the UUID generated once per request in `scan()` and shared with
/// the judge pipeline, so every line for one request — input, per-judge verdicts,
/// decision and the response JSON — carries the same id.
fn log_scan(resp: &ScanResponse, input_preview: &str, req_id: &str) {
    // If judges ran, judge.rs already logged the full per-prompt block. If not
    // (L1/L2 block, or L3 fast-allow / keyword block) nothing else records the
    // input — so log it here to keep every decision auditable.
    if !resp.layers.llm_judges.called {
        let verdict = if resp.allowed { "ALLOWED" } else { "BLOCKED" };
        let by      = resp.blocked_by.as_deref().unwrap_or("pre-judge");
        let reason  = resp.audit.first().map(|a| a.message.as_str()).unwrap_or("");
        tracing::info!("[{}] INPUT=\"{}\"", req_id, input_preview);
        tracing::info!(
            "[{}] decision={} decided_by={} keyword_score={:.3} block_threshold={:.2} reason=\"{}\"",
            req_id,
            verdict,
            by,
            resp.layers.keyword_scan.score,
            resp.layers.keyword_scan.keyword_scan_block_score,
            reason,
        );
    } else if resp.layers.llm_judges.stage.is_none() {
        // Judges were called but produced no decision stage — one or both were
        // UNAVAILABLE (timeout / refused / circuit open) and the verdict was
        // decided here by `llm_unavailable` config. judge.rs cannot log this,
        // so without this line the request would have no result= entry.
        let verdict = if resp.allowed { "ALLOWED" } else { "BLOCKED" };
        tracing::info!(
            "[{}] decision={} decided_by=llm_unavailable_policy reason=\"{}\"",
            req_id,
            verdict,
            resp.layers.llm_judges.reason,
        );
    }

    // Human-readable decision summary — mirrors the INPUT="…" line.
    // ALLOW: OUTPUT="allowed" (with " tainted=true" if applicable).
    // BLOCK: OUTPUT="<reason>" — blocked_by / blocked_stage live on the
    // judge_verdict= or decision= line; OUTPUT stays focused on the "why".
    if resp.allowed {
        let tainted_note = if resp.tainted { " tainted=true" } else { "" };
        tracing::info!("[{}] OUTPUT=\"allowed{}\"", req_id, tainted_note);
    } else {
        let reason = resp.audit.first().map(|a| a.message.as_str()).unwrap_or("");
        // Escape embedded quotes/newlines so the OUTPUT stays on one log line.
        let reason_escaped = reason
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "\\r");
        tracing::info!("[{}] OUTPUT=\"{}\"", req_id, reason_escaped);
    }

    // Full outbound response JSON — byte-for-byte what the client receives.
    // Paired with the REQUEST_JSON line emitted at scan() entry so
    // grep <req_id> yields both request and response under one correlation id.
    tracing::info!(
        "[{}] RESPONSE_JSON={}",
        req_id,
        serde_json::to_string(resp).unwrap_or_else(|e| format!("{{\"log_error\":\"{e}\"}}"))
    );

    // Authoritative final result — the LAST line for a request, so the log
    // reads INPUT → … → OUTPUT → RESPONSE_JSON → RESULT. Single source of
    // truth across every path (judge, pre-judge, llm-unavailable policy).
    tracing::info!(
        "[{}] RESULT={} duration={}ms",
        req_id,
        if resp.allowed { "ALLOWED" } else { "BLOCKED" },
        resp.duration_ms,
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Handlers
// ─────────────────────────────────────────────────────────────────────────────

async fn scan(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ScanRequest>,
) -> Result<(HeaderMap, Json<ScanResponse>), (StatusCode, String)> {
    let max_chunks = state.max_chunks;
    if req.chunks.len() > max_chunks {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("too many chunks: {} > {max_chunks}", req.chunks.len()),
        ));
    }

    let t_start    = std::time::Instant::now();
    let joined     = req.chunks.join("\n");
    let provenance = parse_provenance(req.provenance.as_deref());
    let ts         = now_ist();
    // Full input for logging — NOT truncated, so the log shows exactly what was scanned.
    // Newlines escaped so one request stays on one log line.
    let input_preview = joined.replace('\n', "\\n").replace('\r', "\\r");
    // Correlation ID: prefer the caller-supplied header, fall back to a generated UUID.
    const REQUEST_ID_HEADER: &str = "x-client-request-id";
    let (req_id, req_id_source) = match headers
        .get(REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(v) => (v.to_string(), "header"),
        None    => (crate::judge::next_req_id(), "generated"),
    };
    tracing::info!("[{}] req_id_source={}", req_id, req_id_source);

    // Echo the request-id on the response so callers can log which id was used.
    let mut resp_headers = HeaderMap::new();
    let hdr_name = HeaderName::from_static(REQUEST_ID_HEADER);
    if let Ok(value) = HeaderValue::from_str(&req_id) {
        resp_headers.insert(hdr_name, value);
    }

    // Full inbound request JSON — byte-for-byte what the caller sent. Paired
    // with the RESPONSE line emitted at the end of log_scan so each req_id
    // has both request and response in the audit trail.
    tracing::info!(
        "[{}] REQUEST_JSON={}",
        req_id,
        serde_json::to_string(&req).unwrap_or_else(|e| format!("{{\"log_error\":\"{e}\"}}"))
    );

    // Fence all chunks upfront
    let guard = if req.tool_names.is_empty() {
        RetrievalGuard::from_config(&state.injection_cfg)
    } else {
        let mut per_call = state.injection_cfg.clone();
        per_call.known_tool_names = req.tool_names.clone();
        RetrievalGuard::from_config(&per_call)
    };
    let (_result, fenced) = guard.guard_context(&req.chunks, provenance);
    let mode_str = format!("{:?}", state.injection_cfg.mode).to_lowercase();

    // ── Macro to build, log and return a ScanResponse in one step
    macro_rules! respond {
        ($resp:expr) => {{
            let mut r = $resp;
            r.duration_ms = t_start.elapsed().as_millis() as u64;
            log_scan(&r, &input_preview, &req_id);
            return Ok((resp_headers.clone(), Json(r)));
        }};
    }

    // Pre-processing: normalize Ａ→A, Cyrillic homoglyphs, etc. before all
    // layers so obfuscated attacks are visible. Redaction stays in L1.
    let normalized = state.policy_engine.normalize_input(&joined);

    // ── L1 — Compliance (ainxt-compliance input scan) ────────────────────
    // Redacts PAN/Aadhaar/card/CVV/secrets from normalized INPUT — does NOT block.
    // When disabled, normalized text is used as-is (platform already redacted it).
    let (scanned_text, _compliance_redaction_count) = if state.layer_compliance {
        state.policy_engine.check_compliance_ingress(&normalized, provenance)
    } else {
        (normalized.clone(), 0)
    };
    let compliance_result = if state.layer_compliance {
        PolicyLayerResult::passed(1)
    } else {
        PolicyLayerResult::disabled(1)
    };

    // text_for_judge:
    //   compliance ON  → scanned_text (normalized + redacted by L1)
    //   compliance OFF → redact_for_judge(scanned_text) (normalized, then redact for judges)
    let text_for_judge = if state.layer_compliance {
        scanned_text.clone()
    } else {
        state.policy_engine.redact_for_judge(&scanned_text, provenance)
    };

    // ── L2 — Guardrails + Policy ──────────────────────────────────────────
    if state.layer_guardrails_policy {
        match state.policy_engine.check_guardrails_policy(&scanned_text) {
            PolicyDecision::Deny { policy_id, reason } => {
                respond!(ScanResponse {
                    timestamp:     ts.clone(),
                    mode:          mode_str.clone(),
                    allowed:       false,
                    tainted:       true,
                    findings:      build_findings(&[], &[AuditEntry::now("L2:guardrails-policy", &policy_id, &reason)]),
                    fenced:        req.chunks.iter().map(|c| guard.fence(c, provenance)).collect(),
                    blocked_layer: Some(2),
                    blocked_by:    Some(format!("L2:guardrails-policy:{policy_id}")),
                    friendly_message: None,
                    duration_ms: 0,
                    layers: LayerStatus {
                        compliance:        compliance_result.clone(),
                        guardrails_policy: PolicyLayerResult::blocked(2, &policy_id, &reason),
                        keyword_scan:      if state.layer_keyword_scan { KeywordScanResult::not_called(state.keyword_scan_safe_score, state.keyword_scan_block_score) } else { KeywordScanResult::disabled(state.keyword_scan_safe_score, state.keyword_scan_block_score) },
                        llm_judges:     if state.layer_llm_judges { JudgeResult::not_called(state.judge_confidence) } else { JudgeResult::disabled(state.judge_confidence) },
                    },
                    audit: vec![AuditEntry::now("L2:guardrails-policy", &policy_id, &reason)],
                });
            }
            PolicyDecision::Flag { policy_id, reason } => {
                tracing::warn!("policy: ingress flag [{}]: {}", policy_id, reason);
            }
            PolicyDecision::Allow => {}
        }
    }

    // ── L2 — Keyword Scan Detector ───────────────────────────────────────────
    let (heuristic_score, heuristic_findings, heuristic_result) = if state.layer_keyword_scan {
        let assessment = HeuristicInjectionScanner.assess(&scanned_text, provenance);
        let score      = assessment.score;
        let findings: Vec<Finding> = if assessment.signals.is_empty() {
            vec![]
        } else {
            vec![Finding {
                index:   0,
                reasons: assessment.signals.iter()
                    .map(|s| format!("{}: {}", s.category, s.evidence))
                    .collect(),
            }]
        };
        (score, findings, true)
    } else {
        // Scanner disabled — pass just above safe_score so judges always run
        // (not 0.5 which would falsely imply the scanner found something)
        (state.keyword_scan_safe_score + 0.01, vec![], false)
    };

    if state.layer_keyword_scan && heuristic_result {
        if heuristic_score < state.keyword_scan_safe_score {
            // fall through to L3/L4 judges
        } else if heuristic_score > state.keyword_scan_block_score {
            respond!(ScanResponse {
                timestamp:     ts.clone(),
                mode:          mode_str.clone(),
                allowed:       false,
                tainted:       true,
                findings:      heuristic_findings,
                fenced:        fenced.clone(),
                blocked_layer: Some(3),
                blocked_by:    Some("L3:keyword-scan".into()),
                friendly_message: None,
                    duration_ms: 0,
                layers: LayerStatus {
                    compliance:        compliance_result.clone(),
                    guardrails_policy: if state.layer_guardrails_policy { PolicyLayerResult::passed(2) } else { PolicyLayerResult::disabled(2) },
                    keyword_scan:      KeywordScanResult::blocked(heuristic_score, state.keyword_scan_safe_score, state.keyword_scan_block_score,
                        format!("score {heuristic_score:.2} exceeds keyword_scan_block_score {}", state.keyword_scan_block_score)),
                    llm_judges:     if state.layer_llm_judges { JudgeResult::not_called(state.judge_confidence) } else { JudgeResult::disabled(state.judge_confidence) },
                },
                audit: vec![AuditEntry::now("L3:keyword-scan", "",
                    format!("score {heuristic_score:.2} > keyword_scan_block_score {}", state.keyword_scan_block_score))],
            });
        }
    }

    // ── L3/L4 — LLM Judge Pipeline ───────────────────────────────────────
    let keyword_scan_result = if state.layer_keyword_scan {
        if heuristic_score < state.keyword_scan_safe_score {
            KeywordScanResult::fast_allow(heuristic_score, state.keyword_scan_safe_score, state.keyword_scan_block_score)
        } else {
            KeywordScanResult::escalate(heuristic_score, state.keyword_scan_safe_score, state.keyword_scan_block_score)
        }
    } else {
        KeywordScanResult::disabled(state.keyword_scan_safe_score, state.keyword_scan_block_score)
    };

    if state.layer_llm_judges {
        let pipeline_guard = state.judge_pipeline.read().await;
        if let Some(ref pipeline) = *pipeline_guard {
            // L1 heuristic disabled → pass score just above keyword_scan_safe_score so
            // judges always evaluate (they are the primary gate). Enabled → use actual score.
            let score_to_pass = if state.layer_keyword_scan {
                heuristic_score
            } else {
                state.keyword_scan_safe_score + 0.01  // just above keyword_scan_safe_score → judges always run
            };
            // Redact sensitive values (PAN/card/CVV/OTP/Aadhaar → [REDACTED]) before
            // sending to external LLM judges — judges see intent, not the data.
            match pipeline.evaluate(&text_for_judge, provenance, score_to_pass, &req_id).await {
                JudgeOutcome::Block { reason, stage, score, friendly_message } => {
                    let audit_l23 = vec![AuditEntry::now("L4/L5:llm-judge", "", &reason)];
                    respond!(ScanResponse {
                        timestamp:     ts.clone(),
                        mode:          mode_str.clone(),
                        allowed:       false,
                        tainted:       true,
                        findings:      build_findings(&heuristic_findings, &audit_l23),
                        fenced:        req.chunks.iter().map(|c| guard.fence(c, provenance)).collect(),
                        blocked_layer: Some(4),
                        blocked_by:    Some("L4/L5:llm-judge".into()),
                        friendly_message: if friendly_message.is_empty() { None } else { Some(friendly_message) },
                        duration_ms: 0,
                        layers: LayerStatus {
                        compliance:        compliance_result.clone(),
                            guardrails_policy: if state.layer_guardrails_policy { PolicyLayerResult::passed(2) } else { PolicyLayerResult::disabled(2) },
                            keyword_scan:      keyword_scan_result,
                            llm_judges:     JudgeResult::blocked(stage, score, state.judge_confidence, &reason),
                        },
                        audit: audit_l23,
                    });
                }
                JudgeOutcome::Unavailable { reason } => {
                    // Judges unavailable — follow configured behaviour
                    match state.llm_unavailable.as_str() {
                        "allow" => {
                            // Allow with audit warning — proceed to L1 compliance egress
                            if state.layer_compliance {
                                let fenced_joined = fenced.join("\n");
                                match state.policy_engine.check_egress(&fenced_joined) {
                                    PolicyDecision::Deny { policy_id, reason: egress_reason } => {
                                        let audit_unav_l4 = vec![
                                            AuditEntry::now("L4/L5:llm-judge", "", &reason),
                                            AuditEntry::now("L1:compliance", &policy_id, &egress_reason),
                                        ];
                                        respond!(ScanResponse {
                                            timestamp:     ts.clone(),
                                            mode:          mode_str.clone(),
                                            allowed:       false,
                                            tainted:       true,
                                            findings:      build_findings(&heuristic_findings, &audit_unav_l4),
                                            fenced:        req.chunks.iter().map(|c| guard.fence(c, provenance)).collect(),
                                            blocked_layer: Some(1),
                                            blocked_by:    Some(format!("L1:compliance-egress:{policy_id}")),
                                            friendly_message: None,
                    duration_ms: 0,
                                            layers: LayerStatus {
                        compliance:        compliance_result.clone(),
                                                guardrails_policy: if state.layer_guardrails_policy { PolicyLayerResult::passed(2) } else { PolicyLayerResult::disabled(2) },
                                                keyword_scan:      keyword_scan_result,
                                                llm_judges:     JudgeResult::unavailable(state.judge_confidence, &reason),
                                            },
                                            audit: audit_unav_l4,
                                        });
                                    }
                                    PolicyDecision::Flag { policy_id, reason: flag_reason } => {
                                        tracing::warn!("policy: egress flag [{}]: {}", policy_id, flag_reason);
                                    }
                                    PolicyDecision::Allow => {}
                                }
                            }

                            respond!(ScanResponse {
                                timestamp:     ts.clone(),
                                mode:          mode_str.clone(),
                                allowed:       true,
                                tainted:       true,
                                findings:      heuristic_findings,
                                fenced,
                                blocked_layer: None,
                                blocked_by:    None,
                                friendly_message: None,
                    duration_ms: 0,
                                layers: LayerStatus {
                        compliance:        compliance_result.clone(),
                                    guardrails_policy: if state.layer_guardrails_policy { PolicyLayerResult::passed(2) } else { PolicyLayerResult::disabled(2) },
                                    keyword_scan:      keyword_scan_result,
                                    llm_judges:     JudgeResult::unavailable(state.judge_confidence, &reason),
                                },
                                audit: vec![AuditEntry::now("L4/L5:llm-judge", "", &reason)],
                            });
                        }
                        _ => {
                            // Default: block
                            let audit_unav_block = vec![AuditEntry::now("L4/L5:llm-judge", "", &reason)];
                            respond!(ScanResponse {
                                timestamp:     ts.clone(),
                                mode:          mode_str.clone(),
                                allowed:       false,
                                tainted:       true,
                                findings:      build_findings(&heuristic_findings, &audit_unav_block),
                                fenced:        req.chunks.iter().map(|c| guard.fence(c, provenance)).collect(),
                                blocked_layer: Some(4),
                                blocked_by:    Some("L4/L5:llm-judge".into()),
                                // No judge replied, so no model-authored refusal exists — send a static
                                // message so the user isn't left with an unexplained block.
                                friendly_message: Some(
                                    "I can't process this request right now because the safety \
                                     review service is temporarily unavailable.\n\
                                     - Please try again in a few moments\n\
                                     - If it keeps happening, contact your administrator\n\
                                     Happy to help once the check is back online."
                                        .to_string()
                                ),
                    duration_ms: 0,
                                layers: LayerStatus {
                        compliance:        compliance_result.clone(),
                                    guardrails_policy: if state.layer_guardrails_policy { PolicyLayerResult::passed(2) } else { PolicyLayerResult::disabled(2) },
                                    keyword_scan:      keyword_scan_result,
                                    llm_judges:     JudgeResult::unavailable(state.judge_confidence, &reason),
                                },
                                audit: audit_unav_block,
                            });
                        }
                    }
                }
                JudgeOutcome::Allow { stage, score } | JudgeOutcome::Skipped { stage, score } => {
                    let judge_stage = stage;
                    let judge_score = score;

                    // ── L1 — Compliance Egress — redact PII from response, do not block
                    let fenced_out = if state.layer_compliance {
                        fenced.iter().map(|c| {
                            let (redacted, _) = state.policy_engine.redact_egress(c, provenance);
                            redacted
                        }).collect::<Vec<_>>()
                    } else {
                        fenced.clone()
                    };

                    // All layers passed
                    respond!(ScanResponse {
                        timestamp:     ts.clone(),
                        mode:          mode_str,
                        allowed:       true,
                        tainted:       false,
                        findings:      heuristic_findings,
                        fenced:        fenced_out,
                        blocked_layer: None,
                        blocked_by:    None,
                        friendly_message: None,
                    duration_ms: 0,
                        layers: LayerStatus {
                        compliance:        compliance_result.clone(),
                            guardrails_policy: if state.layer_guardrails_policy { PolicyLayerResult::passed(2) } else { PolicyLayerResult::disabled(2) },
                            keyword_scan:      keyword_scan_result,
                            llm_judges:     JudgeResult::allowed(judge_stage, judge_score, state.judge_confidence),
                        },
                        audit: vec![],
                    });
                }
            }
        }
    }

    // ── L1 — Compliance Egress (when judges disabled or skipped) ──────────
    // Redact PII from fenced output — do not block
    let fenced = if state.layer_compliance {
        fenced.iter().map(|c| {
            let (redacted, _) = state.policy_engine.redact_egress(c, provenance);
            redacted
        }).collect::<Vec<_>>()
    } else {
        fenced
    };

    // All layers passed (or all disabled)
    // Safety check: if ALL layers are disabled, follow configured behaviour
    let all_disabled = !state.layer_guardrails_policy && !state.layer_keyword_scan
        && !state.layer_llm_judges && !state.layer_compliance;

    if all_disabled {
        match state.all_layers_disabled.as_str() {
            "block" => {
                let audit_all_disabled = vec![AuditEntry::now("all-layers-disabled", "", "all defence layers disabled — blocked by policy")];
                respond!(ScanResponse {
                    timestamp:     ts,
                    mode:          mode_str,
                    allowed:       false,
                    tainted:       true,
                    findings:      build_findings(&heuristic_findings, &audit_all_disabled),
                    fenced:        req.chunks.iter().map(|c| guard.fence(c, provenance)).collect(),
                    blocked_layer: Some(0),
                    blocked_by:    Some("all-layers-disabled".into()),
                    friendly_message: None,
                    duration_ms: 0,
                    layers: LayerStatus {
                        compliance:        compliance_result.clone(),
                        guardrails_policy: PolicyLayerResult::disabled(2),
                        keyword_scan:      KeywordScanResult::disabled(state.keyword_scan_safe_score, state.keyword_scan_block_score),
                        llm_judges:     JudgeResult::disabled(state.judge_confidence),
                    },
                    audit: audit_all_disabled,
                });
            }
            _ => {
                // Default: allow
            }
        }
    }

    let resp = ScanResponse {
        timestamp:     ts,
        mode:          mode_str,
        allowed:       true,
        tainted:       false,
        findings:      heuristic_findings,
        fenced,
        blocked_layer: None,
        blocked_by:    None,
        friendly_message: None,
                    duration_ms: 0,
        layers: LayerStatus {
            compliance:        compliance_result.clone(),
            guardrails_policy: if state.layer_guardrails_policy { PolicyLayerResult::passed(2) } else { PolicyLayerResult::disabled(2) },
            keyword_scan:      keyword_scan_result,
            llm_judges:     if state.layer_llm_judges { JudgeResult::not_called(state.judge_confidence) } else { JudgeResult::disabled(state.judge_confidence) },
        },
        audit: vec![],
    };
    log_scan(&resp, &input_preview, &req_id);
    Ok((resp_headers, Json(resp)))
}

async fn health(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    let guard = RetrievalGuard::from_config(&state.injection_cfg);
    Json(HealthResponse {
        status:               "ok",
        mode:                 format!("{:?}", state.injection_cfg.mode).to_lowercase(),
        scans_retrieved:      guard.scans_retrieved(),
        judges_enabled:          state.judge_pipeline.read().await.is_some(),
        policy_enabled:          true,
        layer_compliance:        state.layer_compliance,
        layer_guardrails_policy: state.layer_guardrails_policy,
        layer_keyword_scan:         state.layer_keyword_scan,
        layer_llm_judges:        state.layer_llm_judges,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Router
// ─────────────────────────────────────────────────────────────────────────────

pub(crate) fn app(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/scan",       post(scan))
        .route("/health",     get(health))
        .route("/llm-status", get(llm_status))
        .with_state(state)
}

// ─────────────────────────────────────────────────────────────────────────────
// IST timer for tracing-subscriber
// ─────────────────────────────────────────────────────────────────────────────

/// Hourly-rotating log writer resilient to file deletion.
///
/// Unlike `tracing_appender::rolling`, this checks before every write that the
/// file still exists on disk; if deleted or the hour changed, it is recreated
/// as `ainxt-injection-svc-YYYY-MM-DD-HH.log` (IST hour).
struct HourlyLogWriter {
    dir:   String,
    state: std::sync::Mutex<Option<(String, std::fs::File)>>,
}

impl HourlyLogWriter {
    fn new(dir: String) -> Self {
        std::fs::create_dir_all(&dir).ok();
        HourlyLogWriter { dir, state: std::sync::Mutex::new(None) }
    }

    /// Path for the current IST hour.
    fn current_path(&self) -> String {
        let ist = FixedOffset::east_opt(5 * 3600 + 30 * 60).unwrap();
        let now = Utc::now().with_timezone(&ist);
        format!("{}/ainxt-injection-svc-{}.log", self.dir, now.format("%Y-%m-%d-%H"))
    }
}

impl std::io::Write for HourlyLogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let path = self.current_path();
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());

        // Reopen when: first write, hour rolled over, or the file was deleted.
        let reopen = match &*guard {
            Some((held, _)) => held != &path || !std::path::Path::new(&path).exists(),
            None            => true,
        };
        if reopen {
            std::fs::create_dir_all(&self.dir).ok();
            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)?;
            *guard = Some((path, file));
        }

        let (_, file) = guard.as_mut().expect("file handle present after reopen");
        file.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        match guard.as_mut() {
            Some((_, file)) => file.flush(),
            None            => Ok(()),
        }
    }
}

/// Custom tracing timer that formats timestamps in IST (UTC+05:30).
/// Output format: 2026-08-12T12:27:48.507+05:30
struct IstTimer;

impl tracing_subscriber::fmt::time::FormatTime for IstTimer {
    fn format_time(&self, w: &mut tracing_subscriber::fmt::format::Writer<'_>) -> std::fmt::Result {
        let ist = FixedOffset::east_opt(5 * 3600 + 30 * 60).unwrap();
        let now = Utc::now().with_timezone(&ist);
        write!(w, "{}", now.format("%Y-%m-%dT%H:%M:%S%.3f%:z"))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Entry point
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let cfg = ServiceConfig::load();

    // ── Logging setup ─────────────────────────────────────────────────────
    let env_filter = EnvFilter::try_new(&cfg.log_level)
        .unwrap_or_else(|_| EnvFilter::new("info"));

    match &cfg.log_dir {
        Some(dir) => {
            // File + stderr: HourlyLogWriter rotates every hour, recreates the file
            // if deleted mid-run, and never writes to a ghost handle.
            // Filename: ainxt-injection-svc-YYYY-MM-DD-HH.log (IST hour).
            std::fs::create_dir_all(dir).ok();
            let file_appender = HourlyLogWriter::new(dir.clone());
            let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
            // Keep guard alive for the lifetime of the program
            std::mem::forget(guard);
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt::layer().with_timer(IstTimer).with_writer(std::io::stderr).with_ansi(true))
                .with(fmt::layer().with_timer(IstTimer).with_writer(non_blocking).with_ansi(false))
                .init();
            eprintln!("logging: writing hourly rotating logs to {}/ainxt-injection-svc-YYYY-MM-DD-HH.log", dir);
        }
        None => {
            // stderr only
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt::layer().with_timer(IstTimer).with_writer(std::io::stderr).with_ansi(true))
                .init();
        }
    }

    let mut injection_cfg = InjectionDefenseConfig::default();
    injection_cfg.mode = match cfg.mode.trim().to_ascii_lowercase().as_str() {
        "off"   => InjectionMode::Off,
        "audit" => InjectionMode::Audit,
        _       => InjectionMode::Enforce,
    };

    let judge_pipeline = JudgeConfig::from_config(&cfg).map(JudgePipeline::new);

    let policy_engine = PolicyEngine::from_config(&cfg);

    let host: std::net::IpAddr = cfg.host
        .parse()
        .unwrap_or(std::net::Ipv4Addr::LOCALHOST.into());
    let addr = SocketAddr::new(host, cfg.port);

    let on_off = |enabled: bool| if enabled { "ON " } else { "OFF" };
    let judges_url = cfg.litellm_url.as_deref().unwrap_or("disabled");
    // Box inner width = 100 chars (content), borders = ║ on each side
    let w = 100usize;
    let row  = |s: String| eprintln!("║ {:<w$} ║", s, w = w);
    let sep  = || eprintln!("╠{:═<width$}╣", "", width = w + 2);
    let top  = || eprintln!("╔{:═<width$}╗", "", width = w + 2);
    let bot  = || eprintln!("╚{:═<width$}╝", "", width = w + 2);

    top();
    row(format!("{:^100}", "ainxt-injection-svc"));
    row(format!("{:^100}", format!("VERSION {}", env!("CARGO_PKG_VERSION"))));
    sep();
    row(format!("  Endpoint : http://{}", addr));
    row(format!("  Mode     : {:?}", injection_cfg.mode));
    sep();
    row(format!("  LAYERS"));
    row(format!("  L1  Compliance        [{}]  ainxt-compliance",        on_off(cfg.layer_compliance)));
    row(format!("  L2  Guardrails+Policy [{}]  ainxt-guardrails",        on_off(cfg.layer_guardrails_policy)));
    row(format!("  L3  Keyword Scan      [{}]  ainxt-injection",         on_off(cfg.layer_keyword_scan)));
    row(format!("  L4/5 LLM Judges       [{}]  {}",                      on_off(cfg.layer_llm_judges), judges_url));
    row(format!("       Judge 1  : {}",                                   cfg.judge1_model));
    row(format!("       Judge 2  : {}",                                   cfg.judge2_model));
    if cfg.fallback_models.is_empty() {
        row(format!("       Fallback : (none)"));
    } else {
        row(format!("       Fallback : [{}]", cfg.fallback_models.join("  →  ")));
        row(format!("                  (tried in order if primary times out)"));
    }
    row(format!("       Max attempts per judge : {}",                     cfg.max_fallback_attempts));
    sep();
    row(format!("  CONFIG FILES"));
    row(format!("  guardrails-policy-rules : {}", cfg.guardrails_policy_rules_path.as_deref().unwrap_or("built-in")));
    row(format!("  llm-judge-rules         : {}", cfg.llm_judge_rules_path.as_deref().unwrap_or("built-in")));
    bot();

    let llm_judge_rules_path = cfg.llm_judge_rules_path.clone();

    let state = Arc::new(AppState {
        injection_cfg,
        judge_pipeline:       RwLock::new(judge_pipeline),
        judge_cfg_snapshot:   cfg.clone(),
        policy_engine,
        keyword_scan_safe_score:           cfg.keyword_scan_safe_score,
        keyword_scan_block_score:          cfg.keyword_scan_block_score,
        judge_confidence:     cfg.confidence_threshold,
        llm_unavailable:      cfg.llm_unavailable.clone(),
        all_layers_disabled:  cfg.all_layers_disabled.clone(),
        max_chunks:           cfg.max_chunks,
        layer_compliance:        cfg.layer_compliance,
        layer_guardrails_policy: cfg.layer_guardrails_policy,
        layer_keyword_scan:      cfg.layer_keyword_scan,
        layer_llm_judges:     cfg.layer_llm_judges,
    });

    // ── File watcher — hot-reload llm-judge-rules.toml on save ───────────────
    if let Some(ref rules_path) = llm_judge_rules_path {
        let watch_path = rules_path.clone();
        let state_watcher = Arc::clone(&state);
        tokio::spawn(async move {
            use notify::{Watcher, RecursiveMode, Event, EventKind, recommended_watcher};
            use std::sync::mpsc;
            use std::time::Duration;

            let (tx, rx) = mpsc::channel::<notify::Result<Event>>();
            let mut watcher = match recommended_watcher(tx) {
                Ok(w) => w,
                Err(e) => {
                    tracing::warn!("judge: file watcher failed to start: {e} — hot-reload disabled");
                    return;
                }
            };
            if let Err(e) = watcher.watch(std::path::Path::new(&watch_path), RecursiveMode::NonRecursive) {
                tracing::warn!("judge: cannot watch {watch_path}: {e} — hot-reload disabled");
                return;
            }
            tracing::info!("judge: watching {} for changes (hot-reload enabled)", watch_path);

            loop {
                match rx.recv_timeout(Duration::from_millis(500)) {
                    Ok(Ok(event)) => {
                        let is_modify = matches!(
                            event.kind,
                            EventKind::Modify(_) | EventKind::Create(_)
                        );
                        if !is_modify { continue; }
                        // Debounce — drain any queued events
                        while rx.try_recv().is_ok() {}
                        // Reload
                        tracing::info!("judge: detected change in {} — reloading rules", watch_path);
                        let new_pipeline = JudgeConfig::from_config(&state_watcher.judge_cfg_snapshot)
                            .map(JudgePipeline::new);
                        let mut guard = state_watcher.judge_pipeline.write().await;
                        *guard = new_pipeline;
                        drop(guard);
                        tracing::info!("judge: rules reloaded successfully ✓");
                    }
                    Ok(Err(e)) => tracing::warn!("judge: watcher error: {e}"),
                    Err(mpsc::RecvTimeoutError::Timeout) => continue,
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
        });
    }

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("ainxt-injection-svc: cannot bind {}: {}", addr, e);
            std::process::exit(1);
        }
    };

    if let Err(e) = axum::serve(listener, app(state)).await {
        tracing::error!("ainxt-injection-svc: server error: {}", e);
        std::process::exit(1);
    }
}
