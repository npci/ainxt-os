// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! The **stage runner** (`docs/architecture/CODE_REVIEW_PIPELINE.md` §4) — the trait seams and the
//! deterministic driver that actually *runs* the pipeline's stages, rather than receiving already-run
//! `StageReport`s from a caller.
//!
//! - Deterministic tool stages (Compile / Test / Lint / Type-Check) are a [`StageTools`] seam a real
//!   toolchain (`cargo`, `pytest`, `tsc`, `clippy`, …) plugs into; the offline [`ScriptedTools`] makes
//!   the control flow exhaustively testable.
//! - **SAST is auto-run** here (the gap: `BuiltinScanner.scan` was previously only exercised in
//!   tests) — every file is scanned, findings are surfaced, and a critical/high finding turns the SAST
//!   stage into a gating `Fail` that the Commit Gate hard-blocks on.
//! - Stages honour the per-language **capability matrix** ([`crate::capability`]): a stage with no
//!   tool is `Skipped(reason)`, never a silent pass; a legacy language forces the manual-review skip.
//! - **Fail-fast ordering** (§3): compile → lint → type-check → tests, so an expensive stage is never
//!   spent on code that does not even compile; the first gating failure short-circuits the pass.

use crate::capability::{capability, Capability, Language, StageKind};
use crate::sast::{hard_block, SastFinding, SastScanner};
use crate::stage::{Stage, StageReport, StageVerdict};

/// The result of one deterministic tool invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolResult {
    pub passed: bool,
    /// Whether the tool actually executed. `false` means the caller must **not** report `Pass` —
    /// the anti-fake invariant (`toolchain.rs`'s honesty rule): absence of a real run is *unknown*,
    /// never *passed*. [`ToolResult::not_run`] is the only constructor that sets this to `false`.
    pub ran: bool,
    /// Exact tool output (file/line/message), fed verbatim as the self-heal Observation — never a
    /// paraphrase (§4 stage 1's "raw compiler output, not a paraphrase"). For [`ToolResult::not_run`]
    /// this carries the honest reason the check did not execute.
    pub diagnostics: Vec<String>,
}

impl ToolResult {
    #[must_use]
    pub fn pass() -> Self {
        ToolResult {
            passed: true,
            ran: true,
            diagnostics: Vec::new(),
        }
    }
    #[must_use]
    pub fn fail(diagnostics: Vec<String>) -> Self {
        ToolResult {
            passed: false,
            ran: true,
            diagnostics,
        }
    }
    /// The tool for this stage was never invoked (no real binding wired: no live compiler/linter/
    /// test-runner behind the seam). This is **not** a `Pass` and **not** a `Fail` — the stage runner
    /// turns it into `StageVerdict::Skipped(reason)`, scored as a skip penalty, never a fabricated
    /// green. Use this from any offline `StageTools` impl for a stage it cannot honestly execute.
    #[must_use]
    pub fn not_run(reason: impl Into<String>) -> Self {
        ToolResult {
            passed: false,
            ran: false,
            diagnostics: vec![reason.into()],
        }
    }
}

/// The files under review this pass, plus their language, for the tool seams.
#[derive(Debug, Clone)]
pub struct StageContext {
    pub lang: Language,
    /// `(path, source)` for every file in the edit set.
    pub files: Vec<(String, String)>,
}

/// The deterministic toolchain seam. A production impl shells out to the real tools (behind the
/// serving-ops sandbox); the offline impl is scripted. Each returns exact, un-paraphrased output.
pub trait StageTools: Send + Sync {
    fn compile(&self, ctx: &StageContext) -> ToolResult;
    fn test(&self, ctx: &StageContext) -> ToolResult;
    fn lint(&self, ctx: &StageContext) -> ToolResult;
    fn type_check(&self, ctx: &StageContext) -> ToolResult;
}

/// The output of one deterministic-stage pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageRunOutput {
    /// The stage reports in execution order (fed to [`crate::run_pipeline`]).
    pub reports: Vec<StageReport>,
    /// Every SAST finding produced this pass (fed to the Commit Gate for hard-block).
    pub sast_findings: Vec<SastFinding>,
    /// The earliest gating failure's exact diagnostics, for the self-heal Observation.
    pub failure_observation: Option<(Stage, Vec<String>)>,
}

/// Map a pipeline [`Stage`] to its capability [`StageKind`], if it is a capability-gated stage.
fn kind_of(stage: Stage) -> Option<StageKind> {
    match stage {
        Stage::Compile | Stage::Lint => Some(StageKind::Compile),
        Stage::Test => Some(StageKind::Test),
        Stage::TypeCheck => Some(StageKind::TypeCheck),
        Stage::Sast => Some(StageKind::Sast),
        Stage::Perf => Some(StageKind::Perf),
        _ => None,
    }
}

/// Run the deterministic Phase-A stages in fail-fast order, honouring the capability matrix and
/// auto-running SAST. Returns the stage reports, the SAST findings, and the first gating failure's
/// exact output (for self-heal). Stops at the first *gating* `Fail` (fail-fast economy, §3).
///
/// `scanner` is the SAST engine (offline [`crate::sast::BuiltinScanner`] or a real Semgrep seam).
#[must_use]
pub fn run_deterministic_stages(
    ctx: &StageContext,
    tools: &dyn StageTools,
    scanner: &dyn SastScanner,
) -> StageRunOutput {
    // Fail-fast order: compile → lint → type-check → tests → SAST.
    const ORDER: [Stage; 5] = [
        Stage::Compile,
        Stage::Lint,
        Stage::TypeCheck,
        Stage::Test,
        Stage::Sast,
    ];

    let mut reports = Vec::new();
    let mut sast_findings = Vec::new();
    let mut failure_observation = None;

    for stage in ORDER {
        // SAST is handled specially below (auto-scan, not a StageTools seam).
        if stage == Stage::Sast {
            for (path, src) in &ctx.files {
                sast_findings.extend(scanner.scan(path, src));
            }
            let cap = capability(ctx.lang, StageKind::Sast);
            let verdict = if let Some(f) = hard_block(&sast_findings) {
                let obs = vec![format!(
                    "{} ({:?}) at {}:{} — {}",
                    f.rule, f.severity, f.file, f.line, f.evidence
                )];
                if failure_observation.is_none() {
                    failure_observation = Some((Stage::Sast, obs.clone()));
                }
                StageVerdict::Fail {
                    detail: obs.join("; "),
                }
            } else if matches!(cap, Capability::Substitute(_)) {
                // Generic-only scan on a language with no maintained ruleset — honest partial skip.
                StageVerdict::Skipped {
                    reason: format!("{} (partial generic scan only)", cap.reason()),
                }
            } else {
                StageVerdict::Pass
            };
            reports.push(StageReport {
                stage: Stage::Sast,
                verdict,
                deterministic: true,
            });
            continue;
        }

        let kind = kind_of(stage).expect("Phase-A stages are capability-gated");
        let cap = capability(ctx.lang, kind);
        match cap {
            Capability::Skip(reason) => {
                reports.push(StageReport::skipped(stage, reason));
                continue;
            }
            Capability::ManualReview(reason) => {
                reports.push(StageReport::skipped(
                    stage,
                    format!("manual review required: {reason}"),
                ));
                continue;
            }
            Capability::Native(_) | Capability::Substitute(_) => {}
        }

        let result = match stage {
            Stage::Compile => tools.compile(ctx),
            Stage::Lint => tools.lint(ctx),
            Stage::TypeCheck => tools.type_check(ctx),
            Stage::Test => tools.test(ctx),
            _ => unreachable!(),
        };

        if !result.ran {
            // The tool exists in principle (capability said Native/Substitute) but no real binding
            // is wired on this deployment — honest Skipped, never a fabricated Pass. Does not
            // fail-fast: an un-run check is not a finding, just unproven.
            let reason = if result.diagnostics.is_empty() {
                format!("{} tool not wired on this deployment", cap.reason())
            } else {
                result.diagnostics.join("; ")
            };
            reports.push(StageReport::skipped(stage, reason));
            continue;
        }

        if result.passed {
            reports.push(StageReport::pass(stage, true));
        } else {
            reports.push(StageReport::fail(
                stage,
                true,
                result.diagnostics.join("; "),
            ));
            failure_observation = Some((stage, result.diagnostics));
            // Fail-fast: stop before the more expensive stages, but STILL run SAST — a broken build
            // can still be leaking a secret, and the gate must see it. Jump to SAST.
            for (path, src) in &ctx.files {
                sast_findings.extend(scanner.scan(path, src));
            }
            if let Some(f) = hard_block(&sast_findings) {
                reports.push(StageReport::fail(
                    Stage::Sast,
                    true,
                    format!("{} ({:?}) at {}:{}", f.rule, f.severity, f.file, f.line),
                ));
            }
            return StageRunOutput {
                reports,
                sast_findings,
                failure_observation,
            };
        }
    }

    StageRunOutput {
        reports,
        sast_findings,
        failure_observation,
    }
}

/// An offline, scripted [`StageTools`] for tests and dry-runs: each stage passes unless its name is
/// listed in `fail`, in which case it returns the scripted diagnostics.
#[derive(Debug, Clone, Default)]
pub struct ScriptedTools {
    pub compile_fail: Option<Vec<String>>,
    pub test_fail: Option<Vec<String>>,
    pub lint_fail: Option<Vec<String>>,
    pub typecheck_fail: Option<Vec<String>>,
}

impl StageTools for ScriptedTools {
    fn compile(&self, _c: &StageContext) -> ToolResult {
        self.compile_fail
            .clone()
            .map_or(ToolResult::pass(), ToolResult::fail)
    }
    fn test(&self, _c: &StageContext) -> ToolResult {
        self.test_fail
            .clone()
            .map_or(ToolResult::pass(), ToolResult::fail)
    }
    fn lint(&self, _c: &StageContext) -> ToolResult {
        self.lint_fail
            .clone()
            .map_or(ToolResult::pass(), ToolResult::fail)
    }
    fn type_check(&self, _c: &StageContext) -> ToolResult {
        self.typecheck_fail
            .clone()
            .map_or(ToolResult::pass(), ToolResult::fail)
    }
}

/// Map the pipeline's capability [`Language`] to the AST engine's [`ainxt_semantic::Language`], for
/// the languages a tree-sitter grammar is bound for. `None` for a grammar-less language (COBOL/Other),
/// which the capability matrix has already routed to a manual-review skip before a tool stage runs.
fn ast_language_of(lang: Language) -> Option<ainxt_semantic::Language> {
    match lang {
        Language::Rust => Some(ainxt_semantic::Language::Rust),
        Language::Python => Some(ainxt_semantic::Language::Python),
        Language::Go => Some(ainxt_semantic::Language::Go),
        Language::JavaScript => Some(ainxt_semantic::Language::JavaScript),
        Language::TypeScript => Some(ainxt_semantic::Language::TypeScript),
        Language::Java => Some(ainxt_semantic::Language::Java),
        Language::Cobol | Language::Other => None,
    }
}

/// A **real, offline, deterministic** [`StageTools`] whose Compile stage actually *verifies* the edit
/// set — the design's non-negotiable invariant #1 ("deterministic verify owns pass/fail",
/// `CODE_REVIEW_PIPELINE.md` §Anti-sycophancy) — instead of the vacuous all-pass of
/// [`ScriptedTools::default`].
///
/// This is the seam the shipped daemon wires by default: with no model or toolchain configured, the
/// pipeline still must not rubber-stamp a syntactically broken edit into a `Complete`. The Compile
/// stage parses every file with the pinned tree-sitter grammar ([`ainxt_semantic::parse`]) and fails —
/// with the exact `path: syntax error` diagnostic fed verbatim to the self-heal Observation — if any
/// file's parse tree carries an `ERROR` node. It is a true deterministic gate: an edit that does not
/// parse is blocked at [`Stage::Compile`], *before* the score is even consulted, exactly as the design
/// requires — no longer sneaking through to a post-approval atomic-apply rollback.
///
/// **Honest scope (`needs_hot_wiring` / infra):** a full type-check / test-run / lint requires the
/// real toolchain (`cargo`/`pytest`/`tsc`/`clippy`) behind the serving-ops sandbox, which is infra. So
/// `type_check`/`test`/`lint` here return [`ToolResult::not_run`] rather than *claiming* a check they
/// did not run — the stage runner turns that into an honest `StageVerdict::Skipped` (scored as a skip
/// penalty), never a fabricated `Pass` (the anti-fake invariant this round closed: these three stages
/// previously reported `Pass` on every fully-tooled language — Rust/Java/TypeScript/Go — without ever
/// invoking a tool). The capability matrix in [`run_deterministic_stages`] still turns a genuinely
/// *unsupported* stage/language pair into `Skipped` before this impl is even consulted. The parse-grade
/// Compile gate is the deterministic floor that is guaranteed on every served turn.
///
/// **Pluggable deeper verification** ([`AstVerifyTools::with_lint`] / [`with_test`](Self::with_test) /
/// [`with_type_check`](Self::with_type_check)): a deployment wires a real `clippy`/`tsc`/`mypy`/LSP-
/// diagnostics binding (or [`ainxt_edit::toolchain::LocalVerifyToolchain`]'s `CheckHook` seam, adapted)
/// behind the same trait a served turn already runs through — turning the honest `Skipped` into a real
/// `Pass`/`Fail` without changing a single call site. Until a hook is attached, the stage stays
/// `Skipped`, never a fabricated `Pass` — the real toolchain binding itself is **infra**.
pub struct AstVerifyTools {
    lint: Option<StageCheckHook>,
    test: Option<StageCheckHook>,
    type_check: Option<StageCheckHook>,
}

impl std::fmt::Debug for AstVerifyTools {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AstVerifyTools")
            .field("lint_hook", &self.lint.is_some())
            .field("test_hook", &self.test.is_some())
            .field("type_check_hook", &self.type_check.is_some())
            .finish()
    }
}

impl Default for AstVerifyTools {
    fn default() -> Self {
        AstVerifyTools::new()
    }
}

/// A pluggable deterministic check for [`AstVerifyTools`]'s Lint / Test / Type-Check stages: a real
/// linter/type-checker/test-runner binding (infra), or a deterministic offline stand-in for tests. A
/// stage with no hook attached is [`ToolResult::not_run`] — never a fabricated pass.
pub type StageCheckHook = Box<dyn Fn(&StageContext) -> ToolResult + Send + Sync>;

/// **Flaky-test discipline** (`CODE_REVIEW_PIPELINE.md` §4 stage 8's regression-filing rule): a single
/// failing run of `hook` is never filed as a regression on its own. On a first-run failure, `hook` is
/// invoked a **second time against the identical `StageContext`** (the same "seed" — no field on
/// `StageContext` varies between the two calls, so a hook backed by a seeded/randomized test-runner
/// reproduces under the same conditions) before the failure is trusted:
///
/// - **Reproduces** (fails both runs) → filed as a real regression: the second run's `ToolResult`
///   (its diagnostics — never a paraphrase) is returned as-is.
/// - **Does not reproduce** (passes on re-run) → **not** filed as a regression. Reported `Pass`, but
///   the first run's diagnostics are preserved (prefixed with an explicit `flaky:` note) rather than
///   silently dropped — an inconsistent test is an audit signal even when it does not block the commit.
///
/// Wrap any real (infra) `Test`/`Lint`/`Type-Check` hook with this before handing it to
/// [`AstVerifyTools::with_test`]/[`with_lint`](AstVerifyTools::with_lint)/
/// [`with_type_check`](AstVerifyTools::with_type_check) to get the discipline "for free": a passing
/// hook, or one that is already `not_run`, is untouched (the second call only happens on a genuine
/// first-run failure — no extra cost on the common path).
#[must_use]
pub fn flaky_aware(hook: StageCheckHook) -> StageCheckHook {
    Box::new(move |ctx: &StageContext| {
        let first = hook(ctx);
        if first.passed || !first.ran {
            return first;
        }
        let second = hook(ctx);
        if second.passed {
            let mut diagnostics = vec![
                "flaky: failed on the first run but passed on a re-run under the identical input — \
                 not filed as a regression"
                    .to_string(),
            ];
            diagnostics.extend(first.diagnostics);
            ToolResult {
                passed: true,
                ran: true,
                diagnostics,
            }
        } else {
            // Reproduced on the re-run: a real regression, filed with the re-run's exact diagnostics.
            second
        }
    })
}

impl AstVerifyTools {
    /// Build the tools with only the built-in real parse gate (Compile); Lint/Test/TypeCheck are
    /// `not_run` (⇒ honest `Skipped`) until a hook is attached.
    #[must_use]
    pub fn new() -> Self {
        AstVerifyTools {
            lint: None,
            test: None,
            type_check: None,
        }
    }

    /// Attach a real (or deterministic offline stand-in) Lint check behind the seam.
    #[must_use]
    pub fn with_lint(mut self, hook: StageCheckHook) -> Self {
        self.lint = Some(hook);
        self
    }

    /// Attach a real (or deterministic offline stand-in) Test check behind the seam. **Flaky-test
    /// discipline is applied automatically** ([`flaky_aware`]): a single failing run is never filed as
    /// a regression on its own — the hook is re-run once under the identical input before a failure is
    /// trusted. Use [`AstVerifyTools::with_test_raw`] to opt out (e.g. the hook already implements its
    /// own re-run discipline and a second wrapper would double the cost).
    #[must_use]
    pub fn with_test(mut self, hook: StageCheckHook) -> Self {
        self.test = Some(flaky_aware(hook));
        self
    }

    /// Attach a Test hook **without** the automatic flaky-test discipline [`with_test`](Self::with_test)
    /// applies — for a hook that already re-runs internally, or a test harness offline stand-in that
    /// must be invoked exactly once per call (as several of this crate's own tests require).
    #[must_use]
    pub fn with_test_raw(mut self, hook: StageCheckHook) -> Self {
        self.test = Some(hook);
        self
    }

    /// Attach a real (or deterministic offline stand-in) Type-Check (or LSP-diagnostics) hook behind
    /// the seam.
    #[must_use]
    pub fn with_type_check(mut self, hook: StageCheckHook) -> Self {
        self.type_check = Some(hook);
        self
    }
    /// Deterministically verify every file parses cleanly under its grammar. Returns the exact,
    /// un-paraphrased diagnostics for the first-through-last broken file (fed to self-heal verbatim).
    fn parse_verify(ctx: &StageContext) -> ToolResult {
        let Some(lang) = ast_language_of(ctx.lang) else {
            // Grammar-less language: the capability matrix already skipped it; nothing to verify.
            return ToolResult::pass();
        };
        let mut diagnostics = Vec::new();
        for (path, src) in &ctx.files {
            match ainxt_semantic::first_parse_error_line(src, lang) {
                Ok(None) => {}
                Ok(Some(line)) => diagnostics.push(format!(
                    "{path}:{line}: syntax error — the edit does not parse under the {lang:?} grammar"
                )),
                Err(e) => diagnostics.push(format!("{path}: parse failed — {e}")),
            }
        }
        if diagnostics.is_empty() {
            ToolResult::pass()
        } else {
            ToolResult::fail(diagnostics)
        }
    }
}

impl StageTools for AstVerifyTools {
    fn compile(&self, ctx: &StageContext) -> ToolResult {
        Self::parse_verify(ctx)
    }
    fn test(&self, ctx: &StageContext) -> ToolResult {
        match &self.test {
            // Real test execution is infra (a runner behind the sandbox); a wired hook runs through
            // the seam and returns its real verdict.
            Some(hook) => hook(ctx),
            // No hook: the offline default must not fabricate a test pass/fail — honestly report
            // "not run" (⇒ Skipped, penalized, never green).
            None => ToolResult::not_run(
                "test execution requires a live test-runner (infra) — not wired offline",
            ),
        }
    }
    fn lint(&self, ctx: &StageContext) -> ToolResult {
        match &self.lint {
            Some(hook) => hook(ctx),
            None => ToolResult::not_run("lint requires a live linter (infra) — not wired offline"),
        }
    }
    fn type_check(&self, ctx: &StageContext) -> ToolResult {
        match &self.type_check {
            // Real type-check is infra (`tsc`/`mypy`/`cargo check`/LSP diagnostics); a wired hook runs
            // through the seam.
            Some(hook) => hook(ctx),
            None => ToolResult::not_run(
                "type-check requires a live compiler/type-checker (infra) — not wired offline",
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sast::BuiltinScanner;

    fn ctx(lang: Language, files: &[(&str, &str)]) -> StageContext {
        StageContext {
            lang,
            files: files
                .iter()
                .map(|(p, s)| (p.to_string(), s.to_string()))
                .collect(),
        }
    }

    #[test]
    fn gap_ainxt_pipeline_edit_03_stages_actually_run_and_pass() {
        let c = ctx(Language::Rust, &[("a.rs", "fn f() -> i32 { 1 }\n")]);
        let out = run_deterministic_stages(&c, &ScriptedTools::default(), &BuiltinScanner);
        // Compile, Lint, TypeCheck, Test, SAST all ran (no caller pre-supplied them).
        let stages: Vec<Stage> = out.reports.iter().map(|r| r.stage).collect();
        assert_eq!(
            stages,
            vec![
                Stage::Compile,
                Stage::Lint,
                Stage::TypeCheck,
                Stage::Test,
                Stage::Sast
            ]
        );
        assert!(out.reports.iter().all(|r| r.verdict.is_pass()));
        assert!(out.sast_findings.is_empty());
    }

    #[test]
    fn fail_fast_stops_before_tests_but_still_runs_sast() {
        let tools = ScriptedTools {
            compile_fail: Some(vec!["E0433: unresolved import `foo`".into()]),
            ..Default::default()
        };
        let c = ctx(Language::Rust, &[("a.rs", "fn f() {}\n")]);
        let out = run_deterministic_stages(&c, &tools, &BuiltinScanner);
        // Compile failed → Test never ran (fail-fast).
        assert!(out
            .reports
            .iter()
            .any(|r| r.stage == Stage::Compile && r.verdict.is_fail()));
        assert!(!out.reports.iter().any(|r| r.stage == Stage::Test));
        // The exact compiler output is the observation, not a paraphrase.
        let (stage, diags) = out.failure_observation.unwrap();
        assert_eq!(stage, Stage::Compile);
        assert!(diags[0].contains("E0433"));
    }

    #[test]
    fn gap_ainxt_pipeline_edit_03_python_typecheck_is_skipped_honestly() {
        let c = ctx(Language::Python, &[("a.py", "def f():\n    return 1\n")]);
        let out = run_deterministic_stages(&c, &ScriptedTools::default(), &BuiltinScanner);
        let tc = out
            .reports
            .iter()
            .find(|r| r.stage == Stage::TypeCheck)
            .unwrap();
        assert!(tc.verdict.is_skipped());
    }

    #[test]
    fn cobol_stages_are_manual_review_skips_never_passes() {
        let c = ctx(
            Language::Cobol,
            &[("batch.cbl", "       IDENTIFICATION DIVISION.\n")],
        );
        let out = run_deterministic_stages(&c, &ScriptedTools::default(), &BuiltinScanner);
        let compile = out
            .reports
            .iter()
            .find(|r| r.stage == Stage::Compile)
            .unwrap();
        assert!(compile.verdict.is_skipped());
        if let StageVerdict::Skipped { reason } = &compile.verdict {
            assert!(reason.contains("manual review"));
        } else {
            panic!("expected skipped");
        }
    }

    // ---- R15: flaky-test discipline ------------------------------------------------------------

    #[test]
    fn r15_flaky_aware_does_not_file_a_regression_when_the_second_run_passes() {
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::Arc;

        let calls = Arc::new(AtomicU32::new(0));
        let calls2 = calls.clone();
        // Fails on call 1, passes on call 2 — a classic flaky/order-dependent test.
        let flaky = flaky_aware(Box::new(move |_c: &StageContext| {
            let n = calls2.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                ToolResult::fail(vec!["intermittent: connection reset".into()])
            } else {
                ToolResult::pass()
            }
        }));
        let c = ctx(Language::Rust, &[("a.rs", "fn f() {}\n")]);
        let result = flaky(&c);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "a first-run failure must trigger exactly one re-run"
        );
        assert!(
            result.passed,
            "an unreproduced failure must NOT be filed as a regression"
        );
        assert!(result.ran);
        assert!(
            result.diagnostics.iter().any(|d| d.starts_with("flaky:")),
            "the flaky run must still be recorded for audit: {:?}",
            result.diagnostics
        );
        assert!(result
            .diagnostics
            .iter()
            .any(|d| d.contains("connection reset")));
    }

    #[test]
    fn r15_flaky_aware_files_a_regression_when_it_reproduces() {
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::Arc;

        let calls = Arc::new(AtomicU32::new(0));
        let calls2 = calls.clone();
        // Fails on every call — a genuine regression, not flakiness.
        let always_fails = flaky_aware(Box::new(move |_c: &StageContext| {
            calls2.fetch_add(1, Ordering::SeqCst);
            ToolResult::fail(vec!["assertion failed: settle(1) == 2".into()])
        }));
        let c = ctx(Language::Rust, &[("a.rs", "fn f() {}\n")]);
        let result = always_fails(&c);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "a real regression is confirmed by exactly one re-run"
        );
        assert!(
            !result.passed,
            "a reproducing failure must be filed as a real regression"
        );
        assert!(result.ran);
        assert!(
            result.diagnostics[0].contains("settle(1) == 2"),
            "the exact re-run diagnostic is kept"
        );
    }

    #[test]
    fn r15_flaky_aware_never_re_runs_a_passing_or_not_run_hook() {
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::Arc;

        let calls = Arc::new(AtomicU32::new(0));
        let calls2 = calls.clone();
        let passing = flaky_aware(Box::new(move |_c: &StageContext| {
            calls2.fetch_add(1, Ordering::SeqCst);
            ToolResult::pass()
        }));
        let c = ctx(Language::Rust, &[("a.rs", "fn f() {}\n")]);
        assert!(passing(&c).passed);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "a passing hook incurs no extra call on the common path"
        );

        let not_run = flaky_aware(Box::new(|_c: &StageContext| {
            ToolResult::not_run("no binary")
        }));
        let result = not_run(&c);
        assert!(
            !result.ran,
            "an honestly not-run hook is passed through untouched, never re-run"
        );
    }
}
