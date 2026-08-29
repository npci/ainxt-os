// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! ainxt-skill — the Skill Runtime (Phase 3, increment #2).
//!
//! A skill augments a turn, and there are exactly two kinds, injected at **different points** of
//! context assembly (per the design's context-engine order):
//!
//! - **Behavioral** — a plain-text SOP / domain procedure. No code runs. It is injected into the
//!   **system prompt** with full instructional authority (e.g. "settlement RCA procedure"),
//!   shaping the whole turn.
//! - **Execution** — code that runs **before** the model call (in the sandbox) and whose output is
//!   injected into a `## Context` block the model reads. It grounds the turn with computed/live data.
//!   Running the code is a **seam** ([`SkillExecutor`]) — this crate orchestrates *where* the output
//!   goes, never *how* the code runs.
//!
//! A profile lists skill refs; [`SkillRuntime::prepare`] resolves them into the two injection
//! payloads, preserving ref order. The canonical prompt order is enforced by
//! [`SkillRuntime::system_prompt`]: **persona → behavioral skills → guard prompts** (the caller then
//! appends `## Context` → history → user turn).
//!
//! Clean-room: the manifest shape, the prepare/inject split, and the ordering are original to AiNxt.

use std::collections::BTreeMap;
use std::fmt;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

mod native_process;
pub use native_process::NativeProcessSkillExecutor;

// GAP-FIX surfaces-profiles-skills-config (ADR-026) — the git-native control-plane loader
// (`definition.md` + `control.lock`), analogous to `ainxt_prompt::control::ControlPlane`.
pub mod control;
pub use control::{ControlLock, LoadError, Loaded, SkillControlPlane};

/// The two skill kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SkillType {
    /// SOP text injected into the system prompt (no code).
    Behavioral,
    /// Code run before the LLM; output injected into `## Context`.
    Execution,
}

/// A skill's manifest. In production this is the front-matter of a git-native `definition.md`
/// (ADR-026); here it is the resolved struct the runtime reasons about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillManifest {
    pub id: String,
    #[serde(rename = "type")]
    pub skill_type: SkillType,
    /// A short description (used for relevance-based selection).
    #[serde(default)]
    pub description: String,
    /// For a behavioral skill: the SOP body injected into the system prompt. For an execution skill:
    /// an optional instruction/template for the runner (opaque to prompt assembly).
    #[serde(default)]
    pub body: String,
}

impl SkillManifest {
    pub fn behavioral(id: impl Into<String>, body: impl Into<String>) -> Self {
        SkillManifest {
            id: id.into(),
            skill_type: SkillType::Behavioral,
            description: String::new(),
            body: body.into(),
        }
    }
    pub fn execution(id: impl Into<String>, body: impl Into<String>) -> Self {
        SkillManifest {
            id: id.into(),
            skill_type: SkillType::Execution,
            description: String::new(),
            body: body.into(),
        }
    }

    /// Attach a relevance-selection description (builder-style). This is the field
    /// [`SkillRuntime::prepare`] matches against the turn's `user_input` — GAP-FIX
    /// surfaces-profiles-skills-config: before this wire `description` was documented as
    /// "used for relevance-based selection" but nothing ever read it, so it had no way to be set
    /// meaningfully either.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }
}

/// Whether a skill described by `description` is relevant to the turn's `user_input`, for
/// [`SkillRuntime::prepare`]'s relevance-based selection.
///
/// A skill with no description (the overwhelming majority today — no existing manifest sets one)
/// carries no selection metadata, so it is always relevant: this is what keeps every current
/// profile/skill config resolving exactly as before (byte-identical, additive-only). A skill that
/// DOES carry a description is matched by real case-insensitive keyword overlap: split the
/// description into its significant words (alphanumeric runs longer than 3 characters, so "the",
/// "for", "a" etc. never spuriously match), and the skill is relevant if the turn's input contains
/// at least one of them as a substring. This is a deliberately simple, deterministic, offline-safe
/// heuristic (no embeddings/network call) consistent with the rest of this crate's design — it is
/// real selection logic, not a stub, and it is the seam a smarter (embedding-based) implementation
/// would replace without touching `prepare`'s call site.
fn is_relevant(description: &str, user_input: &str) -> bool {
    let description = description.trim();
    if description.is_empty() {
        return true;
    }
    let significant_words: Vec<String> = description
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.len() > 3)
        .map(|w| w.to_lowercase())
        .collect();
    // A description with no significant words (e.g. all short/stop words) carries no usable
    // selection signal either — fail open rather than silently dropping the skill.
    if significant_words.is_empty() {
        return true;
    }
    let input_lower = user_input.to_lowercase();
    significant_words
        .iter()
        .any(|w| input_lower.contains(w.as_str()))
}

/// A skill error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkillError {
    /// A referenced skill is not registered — a profile/config error, surfaced (not silently skipped).
    NotFound(String),
    /// An execution skill's runner failed.
    Execution { skill: String, message: String },
}

impl fmt::Display for SkillError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SkillError::NotFound(id) => write!(f, "skill '{id}' is not registered"),
            SkillError::Execution { skill, message } => {
                write!(f, "execution skill '{skill}' failed: {message}")
            }
        }
    }
}
impl std::error::Error for SkillError {}

/// The catalog of available skills. Source of truth is the git-native control plane (ADR-026); this
/// is the in-memory projection the runtime consults.
#[derive(Debug, Default, Clone)]
pub struct SkillRegistry {
    skills: BTreeMap<String, SkillManifest>,
}

impl SkillRegistry {
    pub fn new() -> Self {
        SkillRegistry {
            skills: BTreeMap::new(),
        }
    }
    pub fn register(&mut self, manifest: SkillManifest) -> Option<SkillManifest> {
        self.skills.insert(manifest.id.clone(), manifest)
    }
    pub fn get(&self, id: &str) -> Option<&SkillManifest> {
        self.skills.get(id)
    }
    pub fn contains(&self, id: &str) -> bool {
        self.skills.contains_key(id)
    }
    pub fn ids(&self) -> Vec<&str> {
        self.skills.keys().map(String::as_str).collect()
    }
    pub fn len(&self) -> usize {
        self.skills.len()
    }
    pub fn is_empty(&self) -> bool {
        self.skills.is_empty()
    }
}

/// Runs an execution skill's code and returns its output text for the `## Context` block. This is
/// the seam the sandbox implements; the runtime never runs code itself.
pub trait SkillExecutor: Send + Sync {
    fn execute(&self, skill: &SkillManifest, user_input: &str) -> Result<String, SkillError>;
}

/// A no-op executor: refuses to run execution skills. Use when a surface offers only behavioral
/// skills, so an accidental execution ref fails closed rather than silently producing nothing.
pub struct NoExecutor;
impl SkillExecutor for NoExecutor {
    fn execute(&self, skill: &SkillManifest, _user_input: &str) -> Result<String, SkillError> {
        Err(SkillError::Execution {
            skill: skill.id.clone(),
            message: "no execution runtime configured".into(),
        })
    }
}

// ============================ real execution-skill executor ============================

/// Default ceiling on an execution skill's output size. A runaway skill fails closed rather than
/// injecting a huge (or half-written) `## Context` block into the prompt.
pub const DEFAULT_MAX_SKILL_OUTPUT_BYTES: usize = 64 * 1024;

/// Everything a native execution skill may read for one invocation. **Deterministic**: the runtime
/// hands the skill its inputs — no clock, no rng, no ambient I/O — so a skill's output is a pure
/// function of `(manifest, user_input)`. That is what makes execution-skill output replayable for
/// forensic reproducibility (gap X).
pub struct SkillInvocation<'a> {
    /// The skill id being run.
    pub skill_id: &'a str,
    /// The user's turn text.
    pub user_input: &'a str,
    /// The manifest `body` verbatim (the runner instruction/template).
    pub manifest_body: &'a str,
    /// `key = value` params parsed from the manifest body (see [`parse_params`]).
    pub params: &'a BTreeMap<String, String>,
}

/// A **native, in-process** execution skill — real Rust code that grounds a turn with computed data.
///
/// This is the *closable* half of the executor seam: skills whose logic ships with the runtime
/// (formatting, deterministic computation, templated context) run here, right now. The *other* half
/// — sandboxed arbitrary user code (Docker/WASM) — is a different [`SkillExecutor`] implementation
/// that requires a real sandbox host; it is out of scope for an offline build.
///
/// A handler returns `Err(message)` for an ordinary failure; a panic is isolated and reported as a
/// failure too (a misbehaving skill can never crash the turn).
pub trait NativeSkill: Send + Sync {
    fn run(&self, inv: &SkillInvocation<'_>) -> Result<String, String>;
}

/// Parse `key = value` lines from an execution skill's manifest body into params. Blank lines and
/// `#` comment lines are ignored; a line without `=` is ignored (it is prose for the runner). The
/// first `=` splits; both sides are trimmed. Later duplicate keys win (deterministic).
pub fn parse_params(body: &str) -> BTreeMap<String, String> {
    let mut params = BTreeMap::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let k = k.trim();
            if !k.is_empty() {
                params.insert(k.to_string(), v.trim().to_string());
            }
        }
    }
    params
}

/// A real executor that dispatches an execution skill to a **registered native handler**. Unlike
/// [`NoExecutor`] (which refuses everything), this actually runs skills — it is the production
/// execution seam for built-in/native skills. Enterprise-hard by construction:
///
/// - **not-registered → fail closed** (a profile referencing an unknown execution skill errors,
///   never silently produces empty context);
/// - **panic isolation** — a handler that panics is caught and reported as a failure;
/// - **output ceiling** — output larger than the configured cap is refused (no truncated/oversized
///   context injection).
pub struct NativeSkillExecutor {
    handlers: BTreeMap<String, Arc<dyn NativeSkill>>,
    max_output_bytes: usize,
}

impl Default for NativeSkillExecutor {
    fn default() -> Self {
        NativeSkillExecutor {
            handlers: BTreeMap::new(),
            max_output_bytes: DEFAULT_MAX_SKILL_OUTPUT_BYTES,
        }
    }
}

impl NativeSkillExecutor {
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the per-skill output ceiling (bytes).
    pub fn with_max_output_bytes(mut self, max_output_bytes: usize) -> Self {
        self.max_output_bytes = max_output_bytes;
        self
    }

    /// Register a native handler for a skill id. Returns the previous handler if one was registered.
    pub fn register(
        &mut self,
        id: impl Into<String>,
        handler: Arc<dyn NativeSkill>,
    ) -> Option<Arc<dyn NativeSkill>> {
        self.handlers.insert(id.into(), handler)
    }

    /// Builder form of [`register`](Self::register).
    pub fn with(mut self, id: impl Into<String>, handler: Arc<dyn NativeSkill>) -> Self {
        self.register(id, handler);
        self
    }

    pub fn is_registered(&self, id: &str) -> bool {
        self.handlers.contains_key(id)
    }
    pub fn len(&self) -> usize {
        self.handlers.len()
    }
    pub fn is_empty(&self) -> bool {
        self.handlers.is_empty()
    }
}

impl SkillExecutor for NativeSkillExecutor {
    fn execute(&self, skill: &SkillManifest, user_input: &str) -> Result<String, SkillError> {
        let handler = self
            .handlers
            .get(&skill.id)
            .ok_or_else(|| SkillError::Execution {
                skill: skill.id.clone(),
                message: format!(
                    "no native handler registered for execution skill '{}'",
                    skill.id
                ),
            })?;
        let params = parse_params(&skill.body);
        let inv = SkillInvocation {
            skill_id: &skill.id,
            user_input,
            manifest_body: &skill.body,
            params: &params,
        };
        // Panic isolation: a handler that panics is contained and reported, never propagated into
        // the turn. `AssertUnwindSafe` is sound here — we discard the payload and return an error.
        let ran = catch_unwind(AssertUnwindSafe(|| handler.run(&inv))).map_err(|_| {
            SkillError::Execution {
                skill: skill.id.clone(),
                message: "execution skill panicked (isolated)".into(),
            }
        })?;
        let output = ran.map_err(|message| SkillError::Execution {
            skill: skill.id.clone(),
            message,
        })?;
        if output.len() > self.max_output_bytes {
            return Err(SkillError::Execution {
                skill: skill.id.clone(),
                message: format!(
                    "output {} bytes exceeds the {}-byte ceiling",
                    output.len(),
                    self.max_output_bytes
                ),
            });
        }
        Ok(output)
    }
}

/// A ready-made native skill: render the manifest `body` as a template, substituting `{input}` with
/// the user's turn and `{key}` with `params[key]`. Reference to an undefined `{key}` is a hard error
/// (a config bug fails closed, never silently emits a stray `{placeholder}` into the prompt).
///
/// This proves the executor is real (it runs actual substitution logic) and is itself useful for
/// "computed header" context skills. `{{` / `}}` are literal braces.
pub struct TemplateSkill;

impl NativeSkill for TemplateSkill {
    fn run(&self, inv: &SkillInvocation<'_>) -> Result<String, String> {
        render_template(inv.manifest_body, inv.user_input, inv.params)
    }
}

/// Substitute `{input}` and `{key}` placeholders. `{{`/`}}` escape to literal braces. An unknown
/// placeholder or an unbalanced brace is an error.
fn render_template(
    template: &str,
    user_input: &str,
    params: &BTreeMap<String, String>,
) -> Result<String, String> {
    let mut out = String::with_capacity(template.len());
    let mut chars = template.char_indices().peekable();
    while let Some((_, c)) = chars.next() {
        match c {
            '{' => {
                // Escaped '{{' → literal '{'.
                if matches!(chars.peek(), Some((_, '{'))) {
                    chars.next();
                    out.push('{');
                    continue;
                }
                let mut key = String::new();
                let mut closed = false;
                for (_, kc) in chars.by_ref() {
                    if kc == '}' {
                        closed = true;
                        break;
                    }
                    key.push(kc);
                }
                if !closed {
                    return Err("unbalanced '{' in template".into());
                }
                let key = key.trim();
                if key == "input" {
                    out.push_str(user_input);
                } else if let Some(v) = params.get(key) {
                    out.push_str(v);
                } else {
                    return Err(format!(
                        "template references undefined placeholder '{{{key}}}'"
                    ));
                }
            }
            '}' => {
                // Escaped '}}' → literal '}'; a lone '}' is an error.
                if matches!(chars.peek(), Some((_, '}'))) {
                    chars.next();
                    out.push('}');
                } else {
                    return Err("unbalanced '}' in template".into());
                }
            }
            other => out.push(other),
        }
    }
    Ok(out)
}

// ============================ sandboxed execution-skill executor (WASM) ============================

/// A **sandboxed** execution-skill executor: the isolation half of the [`SkillExecutor`] seam
/// (gap SURF-05). Where [`NativeSkillExecutor`] runs trusted compiled-in Rust handlers in-process,
/// this runs an execution skill's **WebAssembly module** inside the capability-confined
/// [`ainxt_wasm::WasmSandbox`] (ADR-024):
///
/// - **zero ambient authority** — the module is instantiated against an EMPTY import set, so it has
///   no network, no filesystem, no clock, no host calls; a module that imports anything ungranted
///   fails to instantiate and no guest code runs;
/// - **resource-capped** — fuel-metered (an infinite loop is trapped as `OutOfFuel`, never hangs),
///   guest memory bounded, and output size bounded;
/// - **fail-closed** — a skill with no registered module errors (never silently empty context); a
///   guest trap / fuel exhaustion / oversized output surfaces as [`SkillError::Execution`], never a
///   crash or a hang of the turn.
///
/// Two ABIs are supported:
///
/// * **Numeric** (`register` / `with`) — the narrow numeric [`ainxt_wasm::Value`] contract: the skill
///   takes its inputs from the manifest's `argN` params (`arg0`, `arg1`, …, contiguous from 0;
///   integers unless the literal has a `.`/exponent, then f64) and returns numeric values rendered
///   into the `## Context` block. Best for deterministic computed grounding.
/// * **Text** (`register_text` / `with_text`) — the granted linear-memory ABI
///   ([`ainxt_wasm::WasmSandbox::run_with_input`]): the skill's guest receives the **user-turn text**
///   through its own linear memory (`alloc` + `(ptr,len) -> (out_ptr,out_len)`) and returns UTF-8 text
///   directly into `## Context`. This closes the earlier ABI limit (a sandboxed skill could not see the
///   user's turn text, only numeric args) — still ZERO ambient authority (empty import set; the host
///   only touches memory the guest allocated), fuel/memory/output-capped, fail-closed.
pub struct WasmSkillExecutor {
    sandbox: ainxt_wasm::WasmSandbox,
    modules: BTreeMap<String, WasmSkillModule>,
}

/// The ABI a registered WASM skill speaks.
enum WasmAbi {
    /// Numeric args in, numeric values out (`argN` params).
    Numeric,
    /// User-turn TEXT in via linear memory, UTF-8 text out. Carries the guest's allocator export name.
    Text { alloc: String },
}

/// A registered WASM skill: the module bytes (a wasm binary, or inline WAT text since the sandbox
/// enables the `wat` feature), the exported function to call, and the ABI it speaks.
struct WasmSkillModule {
    module_bytes: Vec<u8>,
    func: String,
    abi: WasmAbi,
}

impl WasmSkillExecutor {
    /// Build an executor with the given sandbox ceilings (fuel / memory / output). Returns an error
    /// only if the underlying wasmtime engine cannot be constructed.
    pub fn new(config: ainxt_wasm::SandboxConfig) -> Result<Self, ainxt_wasm::SandboxError> {
        Ok(WasmSkillExecutor {
            sandbox: ainxt_wasm::WasmSandbox::new(config)?,
            modules: BTreeMap::new(),
        })
    }

    /// Build an executor with conservative default ceilings ([`ainxt_wasm::SandboxConfig::default`]).
    pub fn with_defaults() -> Result<Self, ainxt_wasm::SandboxError> {
        Self::new(ainxt_wasm::SandboxConfig::default())
    }

    /// Register a **numeric-ABI** WASM module for a skill id, calling `func` on execute. `module_bytes`
    /// may be a wasm binary or inline WAT text. Returns whether it replaced an existing registration.
    pub fn register(
        &mut self,
        id: impl Into<String>,
        module_bytes: impl Into<Vec<u8>>,
        func: impl Into<String>,
    ) -> bool {
        self.modules
            .insert(
                id.into(),
                WasmSkillModule {
                    module_bytes: module_bytes.into(),
                    func: func.into(),
                    abi: WasmAbi::Numeric,
                },
            )
            .is_some()
    }

    /// Builder form of [`register`](Self::register).
    pub fn with(
        mut self,
        id: impl Into<String>,
        module_bytes: impl Into<Vec<u8>>,
        func: impl Into<String>,
    ) -> Self {
        self.register(id, module_bytes, func);
        self
    }

    /// Register a **text-ABI** WASM module for a skill id: on execute the guest receives the user-turn
    /// text through its own linear memory and returns UTF-8 text (see
    /// [`ainxt_wasm::WasmSandbox::run_with_input`]). `alloc` is the guest's `(i32)->i32` allocator
    /// export and `func` the `(i32,i32)->(i32,i32)` entrypoint. Returns whether it replaced a prior
    /// registration.
    pub fn register_text(
        &mut self,
        id: impl Into<String>,
        module_bytes: impl Into<Vec<u8>>,
        alloc: impl Into<String>,
        func: impl Into<String>,
    ) -> bool {
        self.modules
            .insert(
                id.into(),
                WasmSkillModule {
                    module_bytes: module_bytes.into(),
                    func: func.into(),
                    abi: WasmAbi::Text {
                        alloc: alloc.into(),
                    },
                },
            )
            .is_some()
    }

    /// Builder form of [`register_text`](Self::register_text).
    pub fn with_text(
        mut self,
        id: impl Into<String>,
        module_bytes: impl Into<Vec<u8>>,
        alloc: impl Into<String>,
        func: impl Into<String>,
    ) -> Self {
        self.register_text(id, module_bytes, alloc, func);
        self
    }

    pub fn is_registered(&self, id: &str) -> bool {
        self.modules.contains_key(id)
    }

    /// The sandbox ceilings enforced by this executor.
    pub fn config(&self) -> &ainxt_wasm::SandboxConfig {
        self.sandbox.config()
    }

    /// Collect the contiguous `arg0`, `arg1`, … params (stopping at the first gap) into sandbox args.
    fn collect_args(params: &BTreeMap<String, String>) -> Result<Vec<ainxt_wasm::Value>, String> {
        let mut args = Vec::new();
        let mut i = 0usize;
        while let Some(raw) = params.get(&format!("arg{i}")) {
            args.push(parse_wasm_arg(raw)?);
            i += 1;
        }
        Ok(args)
    }
}

/// Parse one `argN` literal into a sandbox [`ainxt_wasm::Value`]: integer unless the literal carries
/// a `.` or an exponent, in which case it is an f64. A payments platform does not guess at ABI, so an
/// unparseable literal is a hard error, never a silent 0.
fn parse_wasm_arg(raw: &str) -> Result<ainxt_wasm::Value, String> {
    let s = raw.trim();
    if s.contains('.') || s.contains('e') || s.contains('E') {
        s.parse::<f64>()
            .map(ainxt_wasm::Value::F64)
            .map_err(|_| format!("argument '{s}' is not a valid f64"))
    } else {
        s.parse::<i64>()
            .map(ainxt_wasm::Value::I64)
            .map_err(|_| format!("argument '{s}' is not a valid i64"))
    }
}

/// Render a returned sandbox value into the text that goes into the `## Context` block.
fn render_wasm_value(v: &ainxt_wasm::Value) -> String {
    match v {
        ainxt_wasm::Value::I32(x) => x.to_string(),
        ainxt_wasm::Value::I64(x) => x.to_string(),
        ainxt_wasm::Value::F32(x) => x.to_string(),
        ainxt_wasm::Value::F64(x) => x.to_string(),
    }
}

impl SkillExecutor for WasmSkillExecutor {
    fn execute(&self, skill: &SkillManifest, user_input: &str) -> Result<String, SkillError> {
        let module = self
            .modules
            .get(&skill.id)
            .ok_or_else(|| SkillError::Execution {
                skill: skill.id.clone(),
                message: format!(
                    "no WASM module registered for sandboxed execution skill '{}'",
                    skill.id
                ),
            })?;
        let map_err = |e: ainxt_wasm::SandboxError| SkillError::Execution {
            skill: skill.id.clone(),
            message: match e {
                ainxt_wasm::SandboxError::OutOfFuel => {
                    "sandboxed skill exhausted its fuel budget (trapped, not hung)".to_string()
                }
                other => format!("sandboxed execution failed: {other}"),
            },
        };
        match &module.abi {
            // Numeric ABI: `argN` params in, numeric values out.
            WasmAbi::Numeric => {
                let params = parse_params(&skill.body);
                let args =
                    Self::collect_args(&params).map_err(|message| SkillError::Execution {
                        skill: skill.id.clone(),
                        message,
                    })?;
                let output = self
                    .sandbox
                    .run(&module.module_bytes, &module.func, &args)
                    .map_err(map_err)?;
                Ok(output
                    .values
                    .iter()
                    .map(render_wasm_value)
                    .collect::<Vec<_>>()
                    .join(" "))
            }
            // Text ABI: the user-turn TEXT is passed to the guest via its linear memory; the guest
            // returns UTF-8 text straight into `## Context`.
            WasmAbi::Text { alloc } => {
                let output = self
                    .sandbox
                    .run_with_input(&module.module_bytes, alloc, &module.func, user_input)
                    .map_err(map_err)?;
                Ok(output.text)
            }
        }
    }
}

/// The two injection payloads for a turn, each in skill-ref order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PreparedSkills {
    /// Behavioral skills as `(id, body)` — go into the system prompt.
    pub behavioral: Vec<(String, String)>,
    /// Execution skills as `(id, output)` — go into the `## Context` block.
    pub execution: Vec<(String, String)>,
    /// Skill refs that WERE registered (never a [`SkillError::NotFound`]) but were filtered out of
    /// this turn by relevance-based selection — the skill's `description` shares no keyword with
    /// `user_input`. Kept for observability (a caller/report can log what was skipped and why),
    /// in ref order.
    pub skipped_irrelevant: Vec<String>,
}

impl PreparedSkills {
    /// The behavioral SOP text (bodies joined), for the system prompt. Empty if none.
    pub fn behavioral_text(&self) -> String {
        self.behavioral
            .iter()
            .map(|(_, body)| body.trim())
            .filter(|b| !b.is_empty())
            .collect::<Vec<_>>()
            .join("\n\n")
    }

    /// The `## Context` block from execution-skill outputs (each under a `### <id>` sub-header).
    /// Empty string if there are no execution outputs (so the caller can omit the block entirely).
    pub fn context_block(&self) -> String {
        if self.execution.is_empty() {
            return String::new();
        }
        let mut out = String::from("## Context");
        for (id, output) in &self.execution {
            out.push_str(&format!("\n\n### {id}\n{}", output.trim_end()));
        }
        out
    }
}

/// Selects skills for a turn and produces their injection payloads.
///
/// GAP-FIX surfaces-profiles-skills-config (ADR-026 §6.2 hot-reload) — `registry` is an
/// [`arc_swap::ArcSwap`], not a plain field: [`reload`](Self::reload) publishes a freshly-loaded
/// [`SkillRegistry`] with a single atomic pointer swap, so a `[server] skill_dir` edit reaches every
/// SUBSEQUENT turn without rebuilding the daemon's `Engine`/`ChatSurface` (which own this SAME
/// `SkillRuntime` — no caller-side change needed). [`prepare`](Self::prepare) loads ONE snapshot
/// (`Arc<SkillRegistry>`) at the top of the call and resolves every ref against that single snapshot —
/// in-flight-turn-pinning: a reload landing mid-`prepare()` can never make one turn see a mix of the
/// old and new registry.
pub struct SkillRuntime {
    registry: arc_swap::ArcSwap<SkillRegistry>,
    executor: Box<dyn SkillExecutor>,
}

impl SkillRuntime {
    pub fn new(registry: SkillRegistry, executor: Box<dyn SkillExecutor>) -> Self {
        SkillRuntime {
            registry: arc_swap::ArcSwap::from_pointee(registry),
            executor,
        }
    }

    /// A snapshot of the CURRENT registry (a lock-free atomic load — never blocks a concurrent
    /// [`reload`](Self::reload)). Callers that need multiple lookups within one logical operation
    /// should load once and reuse the snapshot (as [`prepare`](Self::prepare) does), not call this
    /// repeatedly, so that operation is pinned to one consistent registry even under a concurrent
    /// reload.
    pub fn registry(&self) -> Arc<SkillRegistry> {
        self.registry.load_full()
    }

    /// Atomically publish a freshly-loaded [`SkillRegistry`] (ADR-026 §6.2 hot-reload): every
    /// [`prepare`](Self::prepare) call that starts AFTER this returns sees the new registry; any
    /// `prepare()` call already in flight keeps resolving against the snapshot it loaded at its own
    /// start (in-flight-turn-pinning) — this never blocks it and never tears a single turn's
    /// resolution between old and new content.
    pub fn reload(&self, new_registry: SkillRegistry) {
        self.registry.store(Arc::new(new_registry));
    }

    /// Resolve `skill_refs` (a profile's skill list) into behavioral + execution payloads, in ref
    /// order. A missing ref is ALWAYS a hard error (a profile/config typo must surface, never be
    /// silently swallowed by selection) — relevance filtering only ever narrows an already-resolved
    /// ref. Execution skills are run via the [`SkillExecutor`].
    ///
    /// GAP-FIX surfaces-profiles-skills-config — relevance-based selection is now LIVE: each resolved
    /// manifest's `description` is matched against `user_input` via [`is_relevant`] before the skill
    /// is injected/executed. A skill with no description (or one whose description carries no usable
    /// keyword) is unconditionally relevant, so every existing profile with undescribed skills
    /// resolves exactly as before this fix (additive-only). A described skill that does not match the
    /// turn is recorded in [`PreparedSkills::skipped_irrelevant`] rather than injected — this is what
    /// stops every static profile skill ref from being unconditionally forced onto every turn
    /// regardless of what the user actually asked.
    pub fn prepare(
        &self,
        skill_refs: &[String],
        user_input: &str,
    ) -> Result<PreparedSkills, SkillError> {
        // ADR-026 §6.2 in-flight-turn-pinning: ONE snapshot for the whole call, taken before any
        // lookup — a concurrent `reload()` mid-call can never split this turn's resolution across two
        // registry versions.
        let registry = self.registry.load();
        let mut prepared = PreparedSkills::default();
        for id in skill_refs {
            let manifest = registry
                .get(id)
                .ok_or_else(|| SkillError::NotFound(id.clone()))?;
            if !is_relevant(&manifest.description, user_input) {
                prepared.skipped_irrelevant.push(manifest.id.clone());
                continue;
            }
            match manifest.skill_type {
                SkillType::Behavioral => prepared
                    .behavioral
                    .push((manifest.id.clone(), manifest.body.clone())),
                SkillType::Execution => {
                    let output = self.executor.execute(manifest, user_input)?;
                    prepared.execution.push((manifest.id.clone(), output));
                }
            }
        }
        Ok(prepared)
    }

    /// Assemble the SYSTEM-prompt segment in the canonical order:
    /// **persona → behavioral skills → guard prompts**. Empty sections are omitted. The caller
    /// appends `## Context` (execution output + retrieval) → history → user turn after this.
    pub fn system_prompt(
        persona: &str,
        prepared: &PreparedSkills,
        guard_prompts: &[String],
    ) -> String {
        let mut sections: Vec<String> = Vec::new();
        if !persona.trim().is_empty() {
            sections.push(persona.trim().to_string());
        }
        let behavioral = prepared.behavioral_text();
        if !behavioral.is_empty() {
            sections.push(behavioral);
        }
        for guard in guard_prompts {
            if !guard.trim().is_empty() {
                sections.push(guard.trim().to_string());
            }
        }
        sections.join("\n\n")
    }
}

// ============================ built-in skills (production wiring) ============================

/// The IDs of the compiled-in built-in skills a deployment [`SkillRuntime`] ships with. These are the
/// trusted, deterministic, native handlers that make the Skill Runtime *active in production* (gap
/// SURF: Skill Runtime active in production wiring) rather than an empty registry that fails closed on
/// every profile skill ref. A deployment adds its own git-native skills on top; these are always
/// present so a canonical profile can reference them out of the box.
pub mod builtin {
    use super::*;

    /// Behavioral: citation discipline injected into the system prompt (the enterprise accuracy mandate —
    /// never trade answer quality for speed).
    pub const CITATION_DISCIPLINE: &str = "citation-discipline";
    /// Execution: a deterministic turn-context header rendered from the user's turn.
    pub const TURN_HEADER: &str = "turn-header";
    /// Behavioral: Root-Cause-Analysis procedure for a production/settlement incident.
    pub const RCA: &str = "rca-procedure";
    /// Behavioral: test-generation SOP (unit + edge/adversarial cases, never happy-path-only).
    pub const TEST_GEN: &str = "test-gen-procedure";
    /// Behavioral: architecture/design-review SOP.
    pub const ARCHITECTURE_REVIEW: &str = "architecture-review";
    /// Behavioral: PCI/DSS + secrets compliance-review SOP for code and design output.
    pub const COMPLIANCE_REVIEW: &str = "compliance-review";
    /// Behavioral: settlement-batch investigation SOP (payments domain).
    pub const SETTLEMENT_INVESTIGATION: &str = "settlement-investigation";
    /// Behavioral: release-notes drafting SOP.
    pub const RELEASE_NOTES: &str = "release-notes";

    /// The manifests of the built-in skills (registry projection).
    pub fn manifests() -> Vec<SkillManifest> {
        vec![
            SkillManifest::behavioral(
                CITATION_DISCIPLINE,
                "Cite every factual claim to a retrieved source. If you cannot ground a claim in a \
                 cited source, say so explicitly rather than guessing.",
            ),
            // The body is BOTH the runner template and (harmlessly) has no `key=value` params, so
            // `TemplateSkill` renders `{input}` into a deterministic header.
            SkillManifest::execution(TURN_HEADER, "Request under consideration: {input}"),
            SkillManifest::behavioral(
                RCA,
                "Follow the Root-Cause-Analysis procedure: (1) state the observed symptom and its \
                 blast radius (which flows/services/tenants were affected, and since when); (2) build \
                 a timeline of the incident from logs/events/traces, never from assumption; (3) find \
                 the PROXIMATE cause (the specific commit/config/input that triggered it) and the \
                 ROOT cause (the systemic gap that let it happen — a missing test, a missing gate, an \
                 undetected assumption); (4) state the immediate remediation already taken or needed, \
                 separately from the durable fix that prevents recurrence; (5) never present a \
                 correlation as a root cause without a mechanism that explains WHY it produced the \
                 symptom. If the evidence is insufficient to be certain, say so explicitly rather than \
                 guessing at a plausible-sounding cause.",
            ),
            SkillManifest::behavioral(
                TEST_GEN,
                "Follow the test-generation procedure: for every function/endpoint under test, cover \
                 (1) the happy path, (2) boundary values (empty/zero/max/min/off-by-one), (3) invalid \
                 input (wrong type, malformed, oversized), (4) concurrency/idempotency where the code \
                 has shared state or side effects, and (5) at least one adversarial case (an input a \
                 hostile or careless caller would send). Never generate happy-path-only tests. Each \
                 test must assert an observable outcome, never just that the code 'ran without \
                 throwing'. Prefer real inputs/fixtures over mocks where the code under test is pure \
                 or the dependency is cheap to construct for real.",
            ),
            SkillManifest::behavioral(
                ARCHITECTURE_REVIEW,
                "Follow the architecture/design-review procedure: (1) identify the failure modes the \
                 design does NOT handle (timeout, retry, partial failure, backpressure, cancel) before \
                 praising what it does handle; (2) check for hidden shared mutable state across \
                 concurrent callers; (3) check that every mandatory safety gate (compliance/RBAC/audit) \
                 is a required input to the component, never an optional bolt-on; (4) check the design \
                 scales to the platform's real concurrency target, not just the demo path; (5) prefer \
                 the simplest design that meets the failure-mode bar over a more 'elegant' design that \
                 does not. State the concrete blast radius of the riskiest failure mode you find.",
            ),
            SkillManifest::behavioral(
                COMPLIANCE_REVIEW,
                "Follow the compliance-review procedure (PCI/DSS + secrets): (1) scan the reviewed \
                 content for PAN/CVV/expiry/PIN-block, Aadhaar/PAN(India), account-number+name \
                 combinations, IFSC codes, and any API key/token/private-key/certificate material; \
                 (2) flag every hit with its category and location, never silently drop or 'fix' it \
                 yourself; (3) prefer REDACT-and-proceed over a hard block, unless the content cannot \
                 be safely redacted without corrupting code syntax, in which case say so explicitly; \
                 (4) never repeat a flagged secret verbatim in your own response, even to explain the \
                 finding — describe it by category and location instead.",
            ),
            SkillManifest::behavioral(
                SETTLEMENT_INVESTIGATION,
                "Follow the settlement-batch investigation procedure: (1) identify the batch/cycle \
                 identifier, the settlement date, and the exact reconciliation discrepancy (count and \
                 amount, not just 'it failed'); (2) trace the batch through each stage it passed \
                 (capture → clearing → settlement → reconciliation) to find the stage where the \
                 numbers first diverge; (3) distinguish a DATA problem (a bad/duplicate/missing record) \
                 from a TIMING problem (a cutover/clock-boundary effect) from a LOGIC problem (a \
                 calculation or matching-rule defect); (4) never state a monetary figure without \
                 showing the underlying computation — arithmetic on payment data must be traceable, \
                 never asserted; (5) flag whether the discrepancy requires a reversal/adjustment entry \
                 versus a code fix, since these have different urgency and sign-off paths.",
            ),
            SkillManifest::behavioral(
                RELEASE_NOTES,
                "Follow the release-notes procedure: group changes under Added / Changed / Fixed / \
                 Deprecated / Security (omit empty groups); write each entry as a user-visible \
                 statement of WHAT changed and WHY it matters to the reader, never a raw commit \
                 message or internal file/function name; call out any breaking change and its \
                 migration step FIRST, before other entries; never invent a change that is not backed \
                 by the actual diff/changelog input.",
            ),
        ]
    }

    /// Register the built-in native handlers onto an executor. Only [`TURN_HEADER`] runs code (it is a
    /// [`TemplateSkill`]); [`CITATION_DISCIPLINE`] is behavioral (no handler). Idempotent.
    pub fn register_handlers(exec: &mut NativeSkillExecutor) {
        exec.register(TURN_HEADER, Arc::new(TemplateSkill));
    }
}

impl SkillRuntime {
    /// A deployment [`SkillRuntime`] pre-populated with the compiled-in [`builtin`] skills over a real
    /// [`NativeSkillExecutor`] — the production default (gap SURF: Skill Runtime active in production
    /// wiring). Unlike `SkillRuntime::new(SkillRegistry::new(), NativeSkillExecutor::new())` (an EMPTY
    /// registry that fails closed on any profile skill ref), this runtime actually resolves the
    /// built-in refs: a behavioral ref injects into the system prompt, an execution ref runs its native
    /// handler into `## Context`. A deployment registers its own git-native skills on top via
    /// [`SkillRuntime`] accessors before serving.
    pub fn with_builtins() -> Self {
        let mut registry = SkillRegistry::new();
        for m in builtin::manifests() {
            registry.register(m);
        }
        let mut exec = NativeSkillExecutor::new();
        builtin::register_handlers(&mut exec);
        SkillRuntime::new(registry, Box::new(exec))
    }

    /// Same built-in registry as [`with_builtins`](Self::with_builtins), but execution skills route
    /// through a [`DispatchingSkillExecutor`] instead of the bare [`NativeSkillExecutor`]: any skill id
    /// with a module registered on `wasm` runs sandboxed (fuel/memory/output-capped, zero ambient
    /// authority); every other execution ref — including all compiled-in builtins — still resolves via
    /// the trusted in-process native handlers, so this is byte-identical to `with_builtins()` until a
    /// deployment actually registers a WASM module.
    ///
    /// This is the real production wiring for the gap where [`WasmSkillExecutor`] was a fully
    /// implemented, wasmtime-backed sandboxed executor with zero callers outside its own crate's
    /// tests — a served [`SkillRuntime`] could never reach it, so a deployment had no way to run a
    /// sandboxed skill in production regardless of how it configured its git-native skill manifests.
    pub fn with_builtins_and_wasm(wasm: WasmSkillExecutor) -> Self {
        let mut registry = SkillRegistry::new();
        for m in builtin::manifests() {
            registry.register(m);
        }
        let mut native = NativeSkillExecutor::new();
        builtin::register_handlers(&mut native);
        SkillRuntime::new(
            registry,
            Box::new(DispatchingSkillExecutor::new(native, wasm)),
        )
    }
}

/// Routes an execution skill's id to the sandboxed [`WasmSkillExecutor`] when a WASM module is
/// registered for it, otherwise falls back to the trusted in-process [`NativeSkillExecutor`]. This is
/// the seam that makes the sandboxed executor reachable from a production [`SkillRuntime`] alongside
/// the compiled-in native handlers, rather than requiring a deployment to choose exactly one executor
/// for every skill.
pub struct DispatchingSkillExecutor {
    native: NativeSkillExecutor,
    wasm: WasmSkillExecutor,
}

impl DispatchingSkillExecutor {
    pub fn new(native: NativeSkillExecutor, wasm: WasmSkillExecutor) -> Self {
        DispatchingSkillExecutor { native, wasm }
    }
}

impl SkillExecutor for DispatchingSkillExecutor {
    fn execute(&self, skill: &SkillManifest, user_input: &str) -> Result<String, SkillError> {
        if self.wasm.is_registered(&skill.id) {
            self.wasm.execute(skill, user_input)
        } else {
            self.native.execute(skill, user_input)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// Executor that records which skills it ran and echoes a deterministic output.
    #[derive(Clone, Default)]
    struct RecordingExecutor {
        ran: Arc<Mutex<Vec<String>>>,
    }
    impl SkillExecutor for RecordingExecutor {
        fn execute(&self, skill: &SkillManifest, user_input: &str) -> Result<String, SkillError> {
            self.ran.lock().unwrap().push(skill.id.clone());
            Ok(format!("[{}] ran on: {user_input}", skill.id))
        }
    }

    fn registry() -> SkillRegistry {
        let mut r = SkillRegistry::new();
        r.register(SkillManifest::behavioral(
            "rca-sop",
            "Follow the settlement RCA procedure.",
        ));
        r.register(SkillManifest::execution("live-metrics", "fetch metrics"));
        r.register(SkillManifest::behavioral("tone", "Be concise and precise."));
        r
    }

    #[test]
    fn registry_queries() {
        let r = registry();
        assert_eq!(r.len(), 3);
        assert_eq!(r.ids(), vec!["live-metrics", "rca-sop", "tone"]); // sorted
        assert!(r.contains("rca-sop"));
        assert_eq!(
            r.get("live-metrics").unwrap().skill_type,
            SkillType::Execution
        );
    }

    #[test]
    fn prepare_separates_types_in_ref_order() {
        let exec = RecordingExecutor::default();
        let rt = SkillRuntime::new(registry(), Box::new(exec.clone()));
        let refs = vec![
            "rca-sop".to_string(),
            "live-metrics".to_string(),
            "tone".to_string(),
        ];
        let prepared = rt.prepare(&refs, "why did settlement fail?").unwrap();

        assert_eq!(
            prepared
                .behavioral
                .iter()
                .map(|(id, _)| id.as_str())
                .collect::<Vec<_>>(),
            vec!["rca-sop", "tone"]
        );
        assert_eq!(
            prepared
                .execution
                .iter()
                .map(|(id, _)| id.as_str())
                .collect::<Vec<_>>(),
            vec!["live-metrics"]
        );
        // Only the execution skill was run.
        assert_eq!(*exec.ran.lock().unwrap(), vec!["live-metrics".to_string()]);
        assert!(prepared.execution[0].1.contains("why did settlement fail?"));
    }

    #[test]
    fn missing_ref_is_a_hard_error() {
        let rt = SkillRuntime::new(registry(), Box::new(NoExecutor));
        let err = rt.prepare(&["ghost".to_string()], "x").unwrap_err();
        assert_eq!(err, SkillError::NotFound("ghost".to_string()));
    }

    #[test]
    fn execution_failure_surfaces() {
        // NoExecutor fails closed on any execution skill.
        let rt = SkillRuntime::new(registry(), Box::new(NoExecutor));
        let err = rt.prepare(&["live-metrics".to_string()], "x").unwrap_err();
        assert!(matches!(err, SkillError::Execution { .. }));
    }

    #[test]
    fn behavioral_text_joins_bodies_in_order() {
        let rt = SkillRuntime::new(registry(), Box::new(NoExecutor));
        let prepared = rt
            .prepare(&["rca-sop".to_string(), "tone".to_string()], "x")
            .unwrap();
        let text = prepared.behavioral_text();
        assert!(text.starts_with("Follow the settlement RCA procedure."));
        assert!(text.ends_with("Be concise and precise."));
    }

    #[test]
    fn context_block_formats_execution_output() {
        let rt = SkillRuntime::new(registry(), Box::new(RecordingExecutor::default()));
        let prepared = rt.prepare(&["live-metrics".to_string()], "load?").unwrap();
        let block = prepared.context_block();
        assert!(block.starts_with("## Context"));
        assert!(block.contains("### live-metrics"));
        assert!(block.contains("load?"));
        // No execution skills → empty block.
        let empty = rt.prepare(&["rca-sop".to_string()], "x").unwrap();
        assert_eq!(empty.context_block(), "");
    }

    #[test]
    fn system_prompt_enforces_persona_behavioral_guard_order() {
        let rt = SkillRuntime::new(registry(), Box::new(NoExecutor));
        let prepared = rt.prepare(&["rca-sop".to_string()], "x").unwrap();
        let sp = SkillRuntime::system_prompt(
            "You are the SDLC assistant.",
            &prepared,
            &["Never reveal secrets.".to_string()],
        );
        let persona_at = sp.find("SDLC assistant").unwrap();
        let behavioral_at = sp.find("RCA procedure").unwrap();
        let guard_at = sp.find("Never reveal secrets").unwrap();
        assert!(
            persona_at < behavioral_at,
            "persona must precede behavioral skills"
        );
        assert!(
            behavioral_at < guard_at,
            "behavioral skills must precede guard prompts"
        );
    }

    #[test]
    fn manifest_serde_round_trips() {
        let m = SkillManifest::behavioral("x", "body");
        let json = serde_json::to_string(&m).unwrap();
        assert!(json.contains("\"type\":\"behavioral\""));
        let back: SkillManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(m, back);
    }

    // ---- real native executor ----

    /// A native skill that echoes its params/input — proves real dispatch (not a stub).
    struct CountSkill;
    impl NativeSkill for CountSkill {
        fn run(&self, inv: &SkillInvocation<'_>) -> Result<String, String> {
            let words = inv.user_input.split_whitespace().count();
            let tag = inv.params.get("tag").cloned().unwrap_or_default();
            Ok(format!("{tag}words={words}"))
        }
    }

    #[test]
    fn native_executor_actually_runs_a_registered_skill() {
        let mut exec = NativeSkillExecutor::new();
        exec.register("counter", Arc::new(CountSkill));
        assert!(exec.is_registered("counter"));
        let m = SkillManifest::execution("counter", "tag = T:");
        let out = exec.execute(&m, "one two three").unwrap();
        assert_eq!(out, "T:words=3", "the handler really executed on the input");
    }

    #[test]
    fn native_executor_fails_closed_on_unregistered_skill() {
        let exec = NativeSkillExecutor::new();
        let m = SkillManifest::execution("ghost", "");
        let err = exec.execute(&m, "x").unwrap_err();
        match err {
            SkillError::Execution { skill, message } => {
                assert_eq!(skill, "ghost");
                assert!(message.contains("no native handler"), "{message}");
            }
            other => panic!("expected Execution error, got {other:?}"),
        }
    }

    struct PanicSkill;
    impl NativeSkill for PanicSkill {
        fn run(&self, _inv: &SkillInvocation<'_>) -> Result<String, String> {
            panic!("boom inside a skill");
        }
    }

    #[test]
    fn native_executor_isolates_a_panicking_skill() {
        // Silence the default panic hook so the (expected) panic does not spam test output.
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let mut exec = NativeSkillExecutor::new();
        exec.register("bomb", Arc::new(PanicSkill));
        let m = SkillManifest::execution("bomb", "");
        let err = exec.execute(&m, "x").unwrap_err();
        std::panic::set_hook(prev);
        assert!(
            matches!(&err, SkillError::Execution { message, .. } if message.contains("panicked")),
            "a panicking skill must be isolated as an error, got {err:?}"
        );
    }

    struct BigSkill;
    impl NativeSkill for BigSkill {
        fn run(&self, _inv: &SkillInvocation<'_>) -> Result<String, String> {
            Ok("x".repeat(100))
        }
    }

    #[test]
    fn native_executor_rejects_oversized_output() {
        let mut exec = NativeSkillExecutor::new().with_max_output_bytes(10);
        exec.register("big", Arc::new(BigSkill));
        let m = SkillManifest::execution("big", "");
        let err = exec.execute(&m, "x").unwrap_err();
        assert!(
            matches!(&err, SkillError::Execution { message, .. } if message.contains("ceiling")),
            "oversized output must fail closed, got {err:?}"
        );
    }

    #[test]
    fn parse_params_ignores_comments_prose_and_blanks() {
        let p = parse_params("# comment\n\nkey = value\njust prose\nn = 5\nkey = later");
        assert_eq!(p.get("key").map(String::as_str), Some("later")); // later wins
        assert_eq!(p.get("n").map(String::as_str), Some("5"));
        assert!(!p.contains_key("just prose"));
        assert_eq!(p.len(), 2);
    }

    #[test]
    fn template_skill_substitutes_input_and_params() {
        let mut exec = NativeSkillExecutor::new();
        exec.register("tmpl", Arc::new(TemplateSkill));
        // The body's `key=value` lines are BOTH params and the template — params parse from `=`
        // lines; the template renders the whole body. Use a body that has a param and a template.
        let m = SkillManifest::execution(
            "tmpl",
            "region = ap-south-1\nHost {region} handling: {input}",
        );
        let out = exec.execute(&m, "settlement query").unwrap();
        assert!(
            out.contains("Host ap-south-1 handling: settlement query"),
            "{out}"
        );
    }

    #[test]
    fn template_skill_rejects_undefined_placeholder() {
        let mut exec = NativeSkillExecutor::new();
        exec.register("tmpl", Arc::new(TemplateSkill));
        let m = SkillManifest::execution("tmpl", "Value is {missing}");
        let err = exec.execute(&m, "x").unwrap_err();
        assert!(
            matches!(&err, SkillError::Execution { message, .. } if message.contains("undefined placeholder")),
            "got {err:?}"
        );
    }

    #[test]
    fn template_handles_escaped_braces() {
        let out = render_template("literal {{braces}} and {input}", "V", &BTreeMap::new()).unwrap();
        assert_eq!(out, "literal {braces} and V");
        assert!(render_template("dangling {", "V", &BTreeMap::new()).is_err());
        assert!(render_template("dangling }", "V", &BTreeMap::new()).is_err());
    }

    // ---- gap SURF-04: behavioral + execution injected together in ONE prepared turn ----

    #[test]
    fn gap_ainxt_skill_surf_04_behavioral_and_execution_inject_at_their_points() {
        // One turn references BOTH a behavioral SOP (→ system prompt) and an execution skill
        // (→ ## Context). The runtime must place each at its own injection point in one prepare().
        let mut reg = SkillRegistry::new();
        reg.register(SkillManifest::behavioral(
            "rca-sop",
            "Follow the settlement RCA procedure.",
        ));
        reg.register(SkillManifest::execution("counter", "tag = "));
        let exec = NativeSkillExecutor::new().with("counter", Arc::new(CountSkill));
        let rt = SkillRuntime::new(reg, Box::new(exec));

        let prepared = rt
            .prepare(
                &["rca-sop".to_string(), "counter".to_string()],
                "alpha beta gamma",
            )
            .unwrap();

        // Behavioral → system prompt.
        let sp = SkillRuntime::system_prompt(
            "You are ops.",
            &prepared,
            &["Never leak secrets.".to_string()],
        );
        assert!(sp.contains("You are ops."));
        assert!(sp.contains("Follow the settlement RCA procedure."));
        assert!(sp.contains("Never leak secrets."));
        // Execution → ## Context (and NOT in the system prompt).
        assert!(
            !sp.contains("words="),
            "execution output must NOT leak into the system prompt"
        );
        let ctx = prepared.context_block();
        assert!(
            ctx.starts_with("## Context") && ctx.contains("### counter") && ctx.contains("words=3")
        );
    }

    // ---- gap SURF-05: real WASM-sandboxed execution-skill executor ----

    /// Inline WAT: `add(i64,i64)->i64`. Proves the executor really runs guest code and returns its
    /// computed value.
    const WAT_ADD: &str = r#"(module (func (export "add") (param i64 i64) (result i64)
        local.get 0 local.get 1 i64.add))"#;
    /// Inline WAT: an infinite loop — proves fuel metering (must trap, never hang).
    const WAT_SPIN: &str = r#"(module (func (export "spin") (result i64)
        (loop $l br $l) i64.const 0))"#;
    /// Inline WAT that imports a host function it was never granted — proves zero ambient authority
    /// (must fail to instantiate; no guest code runs).
    const WAT_IMPORTER: &str = r#"(module (import "env" "exfil" (func (param i64)))
        (func (export "go") (result i64) i64.const 0))"#;

    #[test]
    fn gap_ainxt_skill_surf_05_wasm_executor_runs_sandboxed_skill_into_context() {
        let mut exec = WasmSkillExecutor::with_defaults().unwrap();
        exec.register("adder", WAT_ADD.as_bytes().to_vec(), "add");
        assert!(exec.is_registered("adder"));
        // arg0 + arg1 computed inside the sandbox.
        let m = SkillManifest::execution("adder", "arg0 = 2\narg1 = 40");
        let out = exec.execute(&m, "ignored numeric ABI").unwrap();
        assert_eq!(out, "42", "the WASM guest actually computed the result");

        // End-to-end through the SkillRuntime: sandboxed output lands in ## Context.
        let mut reg = SkillRegistry::new();
        reg.register(SkillManifest::execution("adder", "arg0 = 1\narg1 = 4"));
        let rt = SkillRuntime::new(reg, Box::new(exec));
        let prepared = rt.prepare(&["adder".to_string()], "load?").unwrap();
        let block = prepared.context_block();
        assert!(
            block.starts_with("## Context") && block.contains("### adder") && block.contains('5'),
            "{block}"
        );
    }

    #[test]
    fn gap_ainxt_skill_surf_05_wasm_executor_fails_closed_on_unregistered() {
        let exec = WasmSkillExecutor::with_defaults().unwrap();
        let m = SkillManifest::execution("ghost", "");
        let err = exec.execute(&m, "x").unwrap_err();
        assert!(
            matches!(&err, SkillError::Execution { message, .. } if message.contains("no WASM module registered")),
            "an unregistered sandboxed skill must fail closed, got {err:?}"
        );
    }

    #[test]
    fn gap_ainxt_skill_surf_05_wasm_executor_traps_infinite_loop_via_fuel() {
        // A runaway skill must be bounded by fuel — a trap, never a hang. Cap fuel low so the trap
        // is fast and deterministic.
        let cfg = ainxt_wasm::SandboxConfig {
            fuel: 100_000,
            ..Default::default()
        };
        let mut exec = WasmSkillExecutor::new(cfg).unwrap();
        exec.register("spinner", WAT_SPIN.as_bytes().to_vec(), "spin");
        let m = SkillManifest::execution("spinner", "");
        let err = exec.execute(&m, "x").unwrap_err();
        assert!(
            matches!(&err, SkillError::Execution { message, .. } if message.contains("fuel")),
            "an infinite-loop skill must be trapped by the fuel cap, got {err:?}"
        );
    }

    #[test]
    fn gap_ainxt_skill_surf_05_wasm_executor_denies_ungranted_imports() {
        // Zero ambient authority: a module importing a host function it was never granted must fail
        // to instantiate — no guest code runs, nothing egresses.
        let mut exec = WasmSkillExecutor::with_defaults().unwrap();
        exec.register("exfiltrator", WAT_IMPORTER.as_bytes().to_vec(), "go");
        let m = SkillManifest::execution("exfiltrator", "");
        let err = exec.execute(&m, "x").unwrap_err();
        assert!(
            matches!(&err, SkillError::Execution { .. }),
            "a skill importing ungranted authority must be refused, got {err:?}"
        );
    }

    #[test]
    fn gap_ainxt_skill_surf_05_wasm_executor_rejects_unparseable_arg() {
        let mut exec = WasmSkillExecutor::with_defaults().unwrap();
        exec.register("adder", WAT_ADD.as_bytes().to_vec(), "add");
        let m = SkillManifest::execution("adder", "arg0 = 2\narg1 = xyz");
        let err = exec.execute(&m, "x").unwrap_err();
        assert!(
            matches!(&err, SkillError::Execution { message, .. } if message.contains("is not a valid")),
            "a bad ABI literal must be a hard error, not a silent 0: {err:?}"
        );
    }

    #[test]
    fn gap_ainxt_skill_wasm_stub_with_builtins_and_wasm_dispatches_sandboxed_skill_in_production_wiring(
    ) {
        // Proves the production constructor (`SkillRuntime::with_builtins_and_wasm`, the function
        // `ainxt-runtimed::build_skill_runtime` now calls) actually reaches the real, wasmtime-backed
        // WasmSkillExecutor — not a stand-in — for a sandboxed skill id, while every compiled-in
        // builtin (native) keeps working unchanged through the same runtime.
        let mut wasm = WasmSkillExecutor::with_defaults().unwrap();
        wasm.register("sandboxed-adder", WAT_ADD.as_bytes().to_vec(), "add");

        let rt = SkillRuntime::with_builtins_and_wasm(wasm);

        // A compiled-in native builtin still resolves via the native path (untouched byte-identical
        // behavior — this is NOT the skill registered on the wasm executor).
        let prepared = rt
            .prepare(&[builtin::TURN_HEADER.to_string()], "hello")
            .unwrap();
        assert!(
            !prepared.execution.is_empty(),
            "builtin execution skill must still run natively"
        );

        // A ref that only exists because a deployment registered it on the WASM executor is NOT in
        // the built-in registry, so resolve it directly against the dispatcher to prove real sandboxed
        // execution — the WASM guest genuinely computes 2 + 40 = 42, not a canned/stubbed value.
        let mut reg = SkillRegistry::new();
        reg.register(SkillManifest::execution(
            "sandboxed-adder",
            "arg0 = 2\narg1 = 40",
        ));
        let mut wasm2 = WasmSkillExecutor::with_defaults().unwrap();
        wasm2.register("sandboxed-adder", WAT_ADD.as_bytes().to_vec(), "add");
        let dispatch_rt = SkillRuntime::new(
            reg,
            Box::new(DispatchingSkillExecutor::new(
                NativeSkillExecutor::new(),
                wasm2,
            )),
        );
        let prepared = dispatch_rt
            .prepare(&["sandboxed-adder".to_string()], "ignored")
            .unwrap();
        let block = prepared.context_block();
        assert!(
            block.contains("42"),
            "dispatcher must route to the real WASM sandbox and return its computed value: {block}"
        );

        // A ref that is neither a builtin nor registered on the WASM executor still fails closed
        // (never silently produces nothing) — the dispatcher falls back to native, and native has no
        // handler for it either.
        let mut reg2 = SkillRegistry::new();
        reg2.register(SkillManifest::execution("neither-native-nor-wasm", ""));
        let dispatch_rt2 = SkillRuntime::new(
            reg2,
            Box::new(DispatchingSkillExecutor::new(
                NativeSkillExecutor::new(),
                WasmSkillExecutor::with_defaults().unwrap(),
            )),
        );
        let err = dispatch_rt2
            .prepare(&["neither-native-nor-wasm".to_string()], "x")
            .unwrap_err();
        assert!(matches!(err, SkillError::Execution { .. }));
    }

    #[test]
    fn runtime_prepare_runs_execution_skill_into_context_block() {
        // End-to-end through the SkillRuntime: an execution skill's REAL output lands in ## Context.
        let mut reg = SkillRegistry::new();
        reg.register(SkillManifest::execution("counter", "tag = "));
        let exec = NativeSkillExecutor::new().with("counter", Arc::new(CountSkill));
        let rt = SkillRuntime::new(reg, Box::new(exec));
        let prepared = rt.prepare(&["counter".to_string()], "alpha beta").unwrap();
        let block = prepared.context_block();
        assert!(block.starts_with("## Context"));
        assert!(block.contains("### counter"));
        assert!(
            block.contains("words=2"),
            "real computed output must appear: {block}"
        );
    }

    // ==================== relevance-based skill selection (SkillManifest::description) ====================

    /// A registry of three DESCRIBED skills (two behavioral, one execution) plus one undescribed
    /// legacy-style skill, to prove description-driven relevance selection is real and additive.
    fn described_registry() -> SkillRegistry {
        let mut r = SkillRegistry::new();
        r.register(
            SkillManifest::behavioral(
                "rca-sop",
                "Follow the settlement RCA procedure: symptom, blast radius, root cause.",
            )
            .with_description("Root-cause-analysis procedure for a settlement or payment failure."),
        );
        r.register(
            SkillManifest::behavioral(
                "release-notes",
                "Draft user-facing release notes from the merged changelog.",
            )
            .with_description("Drafting release notes for a shipped feature or fix."),
        );
        r.register(
            SkillManifest::execution("live-metrics", "fetch metrics")
                .with_description("Live settlement transaction volume and latency metrics."),
        );
        // No description at all — must remain unconditionally relevant (pre-existing behavior).
        r.register(SkillManifest::behavioral("tone", "Be concise and precise."));
        r
    }

    #[test]
    fn prepare_filters_out_irrelevant_described_skills() {
        let rt = SkillRuntime::new(described_registry(), Box::new(RecordingExecutor::default()));
        let refs = vec![
            "rca-sop".to_string(),
            "release-notes".to_string(),
            "live-metrics".to_string(),
            "tone".to_string(),
        ];
        // A settlement-failure question: matches "rca-sop" and "live-metrics" descriptions
        // (settlement), NOT "release-notes" (release/changelog/ship). The undescribed "tone" skill
        // is always included.
        let prepared = rt
            .prepare(&refs, "why did the settlement batch fail last night?")
            .unwrap();

        let behavioral_ids: Vec<&str> = prepared
            .behavioral
            .iter()
            .map(|(id, _)| id.as_str())
            .collect();
        assert_eq!(
            behavioral_ids,
            vec!["rca-sop", "tone"],
            "release-notes must be filtered out as irrelevant to a settlement-failure turn"
        );
        assert_eq!(
            prepared
                .execution
                .iter()
                .map(|(id, _)| id.as_str())
                .collect::<Vec<_>>(),
            vec!["live-metrics"]
        );
        assert_eq!(
            prepared.skipped_irrelevant,
            vec!["release-notes".to_string()]
        );
    }

    #[test]
    fn prepare_selects_the_other_described_skill_for_a_different_turn() {
        let rt = SkillRuntime::new(described_registry(), Box::new(RecordingExecutor::default()));
        let refs = vec![
            "rca-sop".to_string(),
            "release-notes".to_string(),
            "live-metrics".to_string(),
        ];
        // A release-notes turn: matches "release-notes" only.
        let prepared = rt
            .prepare(
                &refs,
                "draft the release notes for the v2 feature we just shipped",
            )
            .unwrap();

        assert_eq!(
            prepared
                .behavioral
                .iter()
                .map(|(id, _)| id.as_str())
                .collect::<Vec<_>>(),
            vec!["release-notes"]
        );
        assert!(
            prepared.execution.is_empty(),
            "live-metrics is irrelevant to this turn"
        );
        // Order-independent: both rca-sop and live-metrics were skipped as irrelevant.
        let mut skipped = prepared.skipped_irrelevant.clone();
        skipped.sort();
        assert_eq!(
            skipped,
            vec!["live-metrics".to_string(), "rca-sop".to_string()]
        );
    }

    #[test]
    fn a_filtered_execution_skill_is_never_run() {
        // Relevance filtering must happen BEFORE dispatch — an irrelevant execution skill must not
        // incur the (potentially expensive/side-effecting) executor call at all.
        let exec = RecordingExecutor::default();
        let rt = SkillRuntime::new(described_registry(), Box::new(exec.clone()));
        let prepared = rt
            .prepare(
                &["live-metrics".to_string()],
                "draft the release notes please",
            )
            .unwrap();
        assert!(prepared.execution.is_empty());
        assert_eq!(
            prepared.skipped_irrelevant,
            vec!["live-metrics".to_string()]
        );
        assert!(
            exec.ran.lock().unwrap().is_empty(),
            "an irrelevant execution skill must never be dispatched to the executor"
        );
    }

    #[test]
    fn undescribed_skills_remain_unconditionally_relevant() {
        // Backward compatibility: every EXISTING manifest in this codebase has an empty description
        // (nothing sets one before this fix), so relevance filtering must be a pure no-op for them —
        // additive-only, byte-identical to pre-fix behavior.
        let rt = SkillRuntime::new(registry(), Box::new(RecordingExecutor::default()));
        let refs = vec![
            "rca-sop".to_string(),
            "live-metrics".to_string(),
            "tone".to_string(),
        ];
        let prepared = rt
            .prepare(&refs, "completely unrelated turn about the weather")
            .unwrap();
        assert_eq!(prepared.behavioral.len(), 2);
        assert_eq!(prepared.execution.len(), 1);
        assert!(prepared.skipped_irrelevant.is_empty());
    }

    #[test]
    fn missing_ref_is_a_hard_error_even_when_it_would_be_irrelevant() {
        // Selection only ever narrows an ALREADY-RESOLVED ref; a typo'd/unregistered ref must still
        // hard-fail regardless of what the turn's input is.
        let rt = SkillRuntime::new(described_registry(), Box::new(NoExecutor));
        let err = rt
            .prepare(&["ghost".to_string()], "why did the settlement batch fail?")
            .unwrap_err();
        assert_eq!(err, SkillError::NotFound("ghost".to_string()));
    }

    #[test]
    fn is_relevant_matches_case_insensitively_on_significant_words_only() {
        assert!(is_relevant("", "anything at all"));
        assert!(is_relevant("   ", "anything at all"));
        assert!(is_relevant(
            "Settlement reconciliation procedure",
            "why did SETTLEMENT batch fail?"
        ));
        assert!(!is_relevant(
            "Settlement reconciliation procedure",
            "please draft release notes"
        ));
        // A description made ENTIRELY of short/stop words ("for", "the", "a") has no significant
        // words to match on at all — fails open (relevant) rather than being spuriously excluded.
        assert!(is_relevant("for the a", "totally unrelated sentence"));
        // A description with at least one significant word must actually match it, not fail open.
        assert!(!is_relevant("for the ledger", "totally unrelated sentence"));
        assert!(is_relevant("for the ledger", "check the ledger balance"));
    }
}
