// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Toolchain seams for the **top rung** of the edit ladder (`SEMANTIC_EDITING.md` §2 rung 1) and the
//! **deterministic-verify** gate that follows any edit.
//!
//! Two things a self-editing engine cannot honestly do in-process:
//!
//! 1. **Toolchain-guaranteed rename / find-references.** A language server (rust-analyzer, gopls,
//!    pyright, …) resolves a symbol through the *compiler's own* name resolution, so a rename touches
//!    exactly the real references and nothing that merely shares a spelling. The string-level
//!    [`crate::field_rename_via_xref`] cannot tell a field from a same-named local — it is rung 3.
//!    The real driver needs a **live** server, so it is a seam: [`LspClient`].
//!
//! 2. **Compile / test verification of an applied edit.** Whether an edit actually builds and passes
//!    tests can only be known by running the real toolchain (`cargo build`, `cargo test`, a linter).
//!    That is a live binding to compiler/test-runner infra → the [`VerifyToolchain`] seam.
//!
//! ## Honesty invariant (why this is infra-gated, not faked)
//!
//! Offline — no language server, no compiler — the stand-in impls here **must not manufacture a
//! green**. [`CannedLspClient`] answers only what it was explicitly scripted with and returns
//! [`LspError::Unavailable`] for anything else (so the ladder falls *down* to the AST/patch rungs,
//! recorded, never silent). [`OfflineVerifyToolchain`] reports [`VerifyOutcome::Inconclusive`] with a
//! [`StepStatus::ToolchainUnavailable`] for every step: absence of a compiler is *unknown*, never
//! *passed*. A false "verified" on a payments codebase is the exact failure mode this seam refuses.
//!
//! Deterministic throughout: no clocks, no rng, no I/O. Pure data in, pure data out — so the offline
//! impls are exhaustively testable and the real drivers (infra) slot in behind the same trait.

use serde::{Deserialize, Serialize};

// ============================ LSP client seam (ladder rung 1) ============================

/// A source position, 1-based line and 1-based UTF-8 column (LSP protocol is 0-based; drivers convert
/// at the boundary so the rest of the engine speaks one convention).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Position {
    pub line: usize,
    pub col: usize,
}

impl Position {
    #[must_use]
    pub fn new(line: usize, col: usize) -> Self {
        Position { line, col }
    }
}

/// A resolved reference to a symbol: which file, and where in it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolRef {
    pub path: String,
    pub position: Position,
}

/// A request to locate a symbol: the file + position the cursor sits on, plus the symbol text (used
/// only for scripting/telemetry — the *authoritative* locator is the position, as it is over LSP).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolQuery {
    pub path: String,
    pub position: Position,
    pub symbol: String,
}

/// A rename request: the symbol to rename (by position) and its new name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenameRequest {
    pub query: SymbolQuery,
    pub new_name: String,
}

/// The full new content of one file touched by a workspace edit. The engine applies these
/// all-or-nothing, exactly as the LSP server computed them (no re-derivation).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEdit {
    pub path: String,
    pub new_content: String,
    /// 1-based line numbers the server reports as changed (for the trace / review UI).
    pub changed_lines: Vec<usize>,
}

/// A cross-file edit as computed by the language server: the atomic unit rung 1 returns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceEdit {
    pub files: Vec<FileEdit>,
}

/// Why an LSP operation did not yield an edit. [`Unavailable`](LspError::Unavailable) is *not* a
/// failure — it means the rung is absent and the ladder should fall down without a trust penalty for
/// a "failed attempt". The others are real negatives the caller must surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "detail")]
pub enum LspError {
    /// No server is running for this language / the deployment has none. Ladder falls to AST.
    Unavailable(String),
    /// A server exists but has not finished indexing the workspace yet.
    NotReady(String),
    /// The position does not resolve to a renameable symbol.
    NoSuchSymbol(String),
    /// The server was consulted and refused the operation (e.g. rename would break the build).
    Refused(String),
}

impl std::fmt::Display for LspError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LspError::Unavailable(s) => write!(f, "lsp unavailable: {s}"),
            LspError::NotReady(s) => write!(f, "lsp not ready: {s}"),
            LspError::NoSuchSymbol(s) => write!(f, "no such symbol: {s}"),
            LspError::Refused(s) => write!(f, "lsp refused: {s}"),
        }
    }
}

impl std::error::Error for LspError {}

pub type LspResult<T> = Result<T, LspError>;

/// The seam a real language-server driver (rust-analyzer / gopls / pyright over JSON-RPC) implements.
///
/// It is deliberately narrow: the two operations the edit ladder's rung 1 actually needs are
/// **find-references** (to know a rename is complete and safe) and **rename** (the edit itself). The
/// real driver is **infra** — it needs a live server process, a warm workspace index, and stdio/pipe
/// transport. Offline, use [`CannedLspClient`].
pub trait LspClient {
    /// All references to the symbol at `query` (declaration + usages), across the workspace.
    fn references(&self, query: &SymbolQuery) -> LspResult<Vec<SymbolRef>>;

    /// Compute (do not apply) the workspace edit that renames the symbol at
    /// [`RenameRequest::query`] to [`RenameRequest::new_name`].
    fn rename(&self, req: &RenameRequest) -> LspResult<WorkspaceEdit>;
}

/// One scripted rename answer for [`CannedLspClient`], keyed by the exact position+new-name.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CannedRename {
    query: SymbolQuery,
    new_name: String,
    edit: WorkspaceEdit,
}

/// Offline stand-in for a real [`LspClient`]. It answers **only** with responses that were explicitly
/// scripted onto it; every other query returns [`LspError::Unavailable`]. This is the honest offline
/// contract — it never invents a rename by guessing — and it is what the seam's tests drive.
#[derive(Debug, Default, Clone)]
pub struct CannedLspClient {
    refs: Vec<(SymbolQuery, Vec<SymbolRef>)>,
    renames: Vec<CannedRename>,
}

impl CannedLspClient {
    #[must_use]
    pub fn new() -> Self {
        CannedLspClient::default()
    }

    /// Script the references answer for a given query.
    #[must_use]
    pub fn with_references(mut self, query: SymbolQuery, refs: Vec<SymbolRef>) -> Self {
        self.refs.push((query, refs));
        self
    }

    /// Script the workspace edit a rename should produce.
    #[must_use]
    pub fn with_rename(mut self, req: RenameRequest, edit: WorkspaceEdit) -> Self {
        self.renames.push(CannedRename {
            query: req.query,
            new_name: req.new_name,
            edit,
        });
        self
    }
}

impl LspClient for CannedLspClient {
    fn references(&self, query: &SymbolQuery) -> LspResult<Vec<SymbolRef>> {
        self.refs
            .iter()
            .find(|(q, _)| q == query)
            .map(|(_, r)| r.clone())
            .ok_or_else(|| {
                LspError::Unavailable(format!(
                    "no scripted references for {} at {}:{}",
                    query.symbol, query.position.line, query.position.col
                ))
            })
    }

    fn rename(&self, req: &RenameRequest) -> LspResult<WorkspaceEdit> {
        self.renames
            .iter()
            .find(|c| c.query == req.query && c.new_name == req.new_name)
            .map(|c| c.edit.clone())
            .ok_or_else(|| {
                LspError::Unavailable(format!(
                    "no scripted rename of {} -> {}",
                    req.query.symbol, req.new_name
                ))
            })
    }
}

// ============================ Deterministic-verify seam ============================

/// A verification step to run against an applied edit. The engine picks the subset appropriate to the
/// language/deployment; the toolchain runs them in order and stops reporting nothing on the first hard
/// failure only if the caller asks (default: run all, report all).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifyStep {
    /// Type-check / compile (`cargo build`, `tsc --noEmit`, `go build`).
    Compile,
    /// Run the test suite (`cargo test`, `pytest`, `go test`).
    Test,
    /// Static lints (`clippy`, `eslint`, `ruff`).
    Lint,
}

/// A request to verify an applied edit against the real toolchain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyRequest {
    pub workspace_root: String,
    /// Paths the edit touched (a driver may scope compilation/testing to these).
    pub changed_files: Vec<String>,
    pub steps: Vec<VerifyStep>,
}

/// Severity of a single diagnostic emitted by the toolchain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Error,
    Warning,
    Note,
}

/// One diagnostic line from the compiler/test-runner, normalized.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    pub path: String,
    pub line: usize,
    pub severity: Severity,
    pub message: String,
}

/// Outcome of a single [`VerifyStep`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepStatus {
    Passed,
    Failed,
    /// Not run (e.g. compile failed, so tests were not attempted).
    Skipped,
    /// The tool binary is not present in this deployment — result is *unknown*, never *passed*.
    ToolchainUnavailable,
}

/// The result of one verification step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepResult {
    pub step: VerifyStep,
    pub status: StepStatus,
    pub diagnostics: Vec<Diagnostic>,
}

/// The overall verdict for an edit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifyOutcome {
    /// Every requested step ran and passed.
    Verified,
    /// At least one step ran and failed.
    Rejected,
    /// No hard failure, but at least one step could not be run (toolchain absent) — the edit is
    /// **not** proven safe. Callers must treat this as "needs human/CI confirmation", not "green".
    Inconclusive,
}

/// The full verification report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyReport {
    pub outcome: VerifyOutcome,
    pub steps: Vec<StepResult>,
}

impl VerifyReport {
    /// Derive the overall outcome from the step results. A single `Failed` ⇒ `Rejected`; else any
    /// `ToolchainUnavailable`/`Skipped` ⇒ `Inconclusive`; else `Verified`. Empty ⇒ `Inconclusive`
    /// (nothing was proven).
    #[must_use]
    pub fn from_steps(steps: Vec<StepResult>) -> Self {
        let outcome = if steps.is_empty() {
            VerifyOutcome::Inconclusive
        } else if steps.iter().any(|s| s.status == StepStatus::Failed) {
            VerifyOutcome::Rejected
        } else if steps.iter().any(|s| {
            matches!(
                s.status,
                StepStatus::ToolchainUnavailable | StepStatus::Skipped
            )
        }) {
            VerifyOutcome::Inconclusive
        } else {
            VerifyOutcome::Verified
        };
        VerifyReport { outcome, steps }
    }

    /// True only when every requested step actually ran and passed. The one method the pipeline gate
    /// should trust before auto-merging an edit — `Inconclusive` is deliberately *not* enough.
    #[must_use]
    pub fn is_verified(&self) -> bool {
        self.outcome == VerifyOutcome::Verified
    }
}

/// The seam a real compile/test driver implements. The real driver is **infra**: it shells out to
/// `cargo`/`tsc`/`pytest` inside the sandbox, which needs the toolchains installed, a writable build
/// dir, and (for cross-language) network-fetched deps. Offline, use [`OfflineVerifyToolchain`].
pub trait VerifyToolchain {
    fn verify(&self, req: &VerifyRequest) -> VerifyReport;
}

/// Offline stand-in for [`VerifyToolchain`]: with no compiler present, **every** step is reported
/// [`StepStatus::ToolchainUnavailable`] and the overall outcome is [`VerifyOutcome::Inconclusive`].
/// It can never emit `Verified` — that is the whole point. Use it where the runtime must run without
/// a toolchain (air-gapped boxes, CI stages that only lint config) and still be honest about not
/// having proven the edit.
#[derive(Debug, Default, Clone, Copy)]
pub struct OfflineVerifyToolchain;

impl VerifyToolchain for OfflineVerifyToolchain {
    fn verify(&self, req: &VerifyRequest) -> VerifyReport {
        let steps = req
            .steps
            .iter()
            .map(|&step| StepResult {
                step,
                status: StepStatus::ToolchainUnavailable,
                diagnostics: Vec::new(),
            })
            .collect();
        VerifyReport::from_steps(steps)
    }
}

/// A scripted [`VerifyToolchain`] for tests: returns a fixed report regardless of the request, so a
/// test can drive the pipeline gate through a known "compile-failed" or "all-passed" toolchain
/// response without a live compiler.
#[derive(Debug, Clone)]
pub struct CannedVerifyToolchain {
    report: VerifyReport,
}

impl CannedVerifyToolchain {
    #[must_use]
    pub fn new(report: VerifyReport) -> Self {
        CannedVerifyToolchain { report }
    }
}

impl VerifyToolchain for CannedVerifyToolchain {
    fn verify(&self, _req: &VerifyRequest) -> VerifyReport {
        self.report.clone()
    }
}

// ============================ Local (offline-real) verify toolchain ============================

/// One file the offline toolchain actually verifies, held in memory (no disk I/O — the module's
/// determinism invariant). A real disk-reading driver would instead resolve
/// [`VerifyRequest::changed_files`] against [`VerifyRequest::workspace_root`]; the offline impl carries
/// the source inline so it stays pure and exhaustively testable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifySource {
    pub path: String,
    pub language: crate::Language,
    pub content: String,
}

impl VerifySource {
    #[must_use]
    pub fn new(
        path: impl Into<String>,
        language: crate::Language,
        content: impl Into<String>,
    ) -> Self {
        VerifySource {
            path: path.into(),
            language,
            content: content.into(),
        }
    }
}

/// A pluggable deterministic check for the Lint / Test / (override) Compile steps. A production
/// deployment wires the real linter / test-runner behind this (still gated on the tools being
/// present); an offline test wires a deterministic stand-in. **A step with no hook is reported
/// [`StepStatus::ToolchainUnavailable`], never a fabricated pass** — the anti-fake invariant survives
/// the pluggability.
pub type CheckHook = Box<dyn Fn(&[VerifySource]) -> StepResult + Send + Sync>;

/// A **real, offline** [`VerifyToolchain`] that actually *runs* the checks available without a live
/// compiler/test-runner — closing the "deterministic verify is parse-only / the tool stages never run"
/// gap on the shipped default:
///
/// - **Compile** — a real tree-sitter parse of every in-memory [`VerifySource`] via
///   [`ainxt_semantic::first_parse_error_line`]. A file with an `ERROR` node ⇒ [`StepStatus::Failed`]
///   with the exact `path:line` diagnostic; a grammar-less source ⇒ the step degrades to
///   [`StepStatus::ToolchainUnavailable`] (we cannot prove it parses — never a fabricated pass). This
///   runs by default with no hook: the parse gate is the deterministic floor guaranteed on every turn.
/// - **Lint** / **Test** — pluggable [`CheckHook`]s. When a hook is provided (a real linter/test-runner
///   binding, or a deterministic offline stand-in) the step **runs through the seam** and returns its
///   real verdict; when absent the step is [`StepStatus::ToolchainUnavailable`].
///
/// The `Compile` step can also be overridden with a real `cargo build`/`tsc` hook via
/// [`LocalVerifyToolchain::with_compile`]. That real toolchain binding is **infra** (a live compiler in
/// the serving-ops sandbox); this offline impl proves the seam runs the checks it *can* honestly run.
pub struct LocalVerifyToolchain {
    sources: Vec<VerifySource>,
    compile: Option<CheckHook>,
    lint: Option<CheckHook>,
    test: Option<CheckHook>,
}

impl std::fmt::Debug for LocalVerifyToolchain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalVerifyToolchain")
            .field("sources", &self.sources)
            .field("compile_hook", &self.compile.is_some())
            .field("lint_hook", &self.lint.is_some())
            .field("test_hook", &self.test.is_some())
            .finish()
    }
}

impl LocalVerifyToolchain {
    /// Build the toolchain over the files it will verify. Compile runs the built-in parse gate; Lint
    /// and Test are `ToolchainUnavailable` until a hook is attached.
    #[must_use]
    pub fn new(sources: Vec<VerifySource>) -> Self {
        LocalVerifyToolchain {
            sources,
            compile: None,
            lint: None,
            test: None,
        }
    }

    /// Override the Compile step with a real compiler hook (`cargo build`, `tsc --noEmit`, `go build`).
    /// Infra: needs a live toolchain. Without this the built-in tree-sitter parse gate is used.
    #[must_use]
    pub fn with_compile(mut self, hook: CheckHook) -> Self {
        self.compile = Some(hook);
        self
    }

    /// Attach the Lint check hook (real `clippy`/`eslint`/`ruff`, or a deterministic offline stand-in).
    #[must_use]
    pub fn with_lint(mut self, hook: CheckHook) -> Self {
        self.lint = Some(hook);
        self
    }

    /// Attach the Test check hook (real `cargo test`/`pytest`/`go test`, or an offline stand-in).
    #[must_use]
    pub fn with_test(mut self, hook: CheckHook) -> Self {
        self.test = Some(hook);
        self
    }

    /// The built-in real parse gate: every source must parse cleanly under its grammar. Grammar-less
    /// sources make the step `ToolchainUnavailable` (unverifiable), never a fabricated pass.
    fn parse_compile(sources: &[VerifySource]) -> StepResult {
        let mut diagnostics = Vec::new();
        let mut verified_any = false;
        let mut unverifiable = false;
        for s in sources {
            match to_semantic_language(s.language) {
                Some(lang) => match ainxt_semantic::first_parse_error_line(&s.content, lang) {
                    Ok(None) => verified_any = true,
                    Ok(Some(line)) => diagnostics.push(Diagnostic {
                        path: s.path.clone(),
                        line,
                        severity: Severity::Error,
                        message: format!(
                            "syntax error — the edit does not parse under the {lang:?} grammar"
                        ),
                    }),
                    Err(e) => diagnostics.push(Diagnostic {
                        path: s.path.clone(),
                        line: 1,
                        severity: Severity::Error,
                        message: format!("parse failed: {e}"),
                    }),
                },
                None => unverifiable = true,
            }
        }
        let status = if !diagnostics.is_empty() {
            StepStatus::Failed
        } else if unverifiable || !verified_any {
            // At least one file has no grammar (or there was nothing to parse): we cannot honestly
            // claim the compile-equivalent passed for every file.
            StepStatus::ToolchainUnavailable
        } else {
            StepStatus::Passed
        };
        StepResult {
            step: VerifyStep::Compile,
            status,
            diagnostics,
        }
    }

    fn run_hook(
        hook: &Option<CheckHook>,
        sources: &[VerifySource],
        step: VerifyStep,
    ) -> StepResult {
        match hook {
            Some(h) => {
                // Trust the hook's own step tag if it set one correctly; otherwise pin it to `step`
                // so the report is coherent regardless of how the hook was written.
                let mut r = h(sources);
                r.step = step;
                r
            }
            None => StepResult {
                step,
                status: StepStatus::ToolchainUnavailable,
                diagnostics: Vec::new(),
            },
        }
    }
}

impl VerifyToolchain for LocalVerifyToolchain {
    fn verify(&self, req: &VerifyRequest) -> VerifyReport {
        let steps = req
            .steps
            .iter()
            .map(|&step| match step {
                VerifyStep::Compile => match &self.compile {
                    Some(h) => {
                        let mut r = h(&self.sources);
                        r.step = VerifyStep::Compile;
                        r
                    }
                    None => Self::parse_compile(&self.sources),
                },
                VerifyStep::Lint => Self::run_hook(&self.lint, &self.sources, VerifyStep::Lint),
                VerifyStep::Test => Self::run_hook(&self.test, &self.sources, VerifyStep::Test),
            })
            .collect();
        VerifyReport::from_steps(steps)
    }
}

/// Map the edit engine's [`crate::Language`] to the AST engine's [`ainxt_semantic::Language`] for the
/// languages a tree-sitter grammar is bound for. `None` ⇒ grammar-less (the parse gate cannot verify).
fn to_semantic_language(lang: crate::Language) -> Option<ainxt_semantic::Language> {
    match lang {
        crate::Language::Rust => Some(ainxt_semantic::Language::Rust),
        crate::Language::Python => Some(ainxt_semantic::Language::Python),
        crate::Language::Java => Some(ainxt_semantic::Language::Java),
        crate::Language::JavaScript => Some(ainxt_semantic::Language::JavaScript),
        crate::Language::TypeScript => Some(ainxt_semantic::Language::TypeScript),
        crate::Language::Go => Some(ainxt_semantic::Language::Go),
        crate::Language::Other => None,
    }
}
