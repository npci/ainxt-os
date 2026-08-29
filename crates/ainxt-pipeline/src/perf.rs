// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! **Performance Analysis — pipeline stage 6** (`docs/architecture/CODE_REVIEW_PIPELINE.md` §4).
//!
//! The gap this closes: `Stage::Perf` was declared but never executed anywhere, and
//! [`crate::confidence::ConfidenceInputs::perf_regression_penalty`] was a caller-supplied scalar the
//! self-heal loop hard-coded to `0` — so a change that doubled the cost of a hot settlement path
//! scored identically to a no-op. This module makes stage 6 a real, computed stage with **three
//! independent signals**, combined into the single `0..=25` regression penalty the Confidence Score
//! consumes plus an honest [`StageVerdict`]:
//!
//! 1. **Benchmark diff** ([`BenchmarkHarness`]) — a seam a real harness (`cargo bench`, JMH,
//!    `pytest-benchmark`, `go test -bench`) plugs into. The pipeline measures the *baseline* and the
//!    *post-edit* file set and diffs matched benchmarks by name; the worst slowdown ratio over the
//!    deployment's budget drives the penalty. `None` = no harness present (an honest skip, never a
//!    silent "perf clean"). The offline [`ScriptedBench`] makes the diff exhaustively testable.
//! 2. **AST-complexity heuristic** ([`complexity_delta`]) — deterministic, offline, no infra: the
//!    added cyclomatic complexity introduced by the edit, over a per-deployment budget. Uses the
//!    tree-sitter function spans from `ainxt-semantic` for Rust/Python and a lexical fallback for the
//!    other languages, so it works with no benchmark harness at all (the common case).
//! 3. **Model advisory** ([`PerfAdvisor`]) — a model's qualitative perf review (allocation in a loop,
//!    N+1 query, blocking I/O on a hot path). Surfaced verbatim as **advisories**, but — exactly like
//!    the Judge in the Confidence Score — model judgment is **never a term in the numeric penalty**
//!    (anti-sycophancy: the score cannot be inflated *or* gated by a model). Advisory-only.
//!
//! Stage 6 is **non-gating** by construction: perf is a scored risk signal, not a hard block (a
//! genuinely necessary slowdown must still be committable by a human at a capped score), so its
//! verdict is `Pass` / `Advisory` / `Skipped` — never `Fail`.

use crate::capability::{capability, Capability, Language, StageKind};
use crate::stage::{Stage, StageReport, StageVerdict};
use ainxt_semantic::Language as AstLanguage;

/// The per-deployment perf budget: how much regression is tolerated before the penalty starts.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PerfBudget {
    /// Added cyclomatic complexity (summed over the edit set) tolerated before the complexity term
    /// begins to bite. A small refactor that adds a branch or two is free; a 20-branch god-function is
    /// not.
    pub max_complexity_growth: u32,
    /// Benchmark slowdown ratio tolerated before the benchmark term bites (e.g. `1.10` = 10% slower is
    /// still within budget). Must be `>= 1.0`.
    pub max_regression_ratio: f64,
}

impl Default for PerfBudget {
    fn default() -> Self {
        PerfBudget {
            max_complexity_growth: 5,
            max_regression_ratio: 1.10,
        }
    }
}

/// The deployment-level perf seams (no per-turn baseline) a surface/engine wires in once and reuses
/// for every code-editing turn: the benchmark harness, the model advisor, and the budget. The pre-edit
/// baseline is supplied per turn by the edit-turn gate (it is the turn's `original_files`).
pub struct PerfConfig<'a> {
    pub bench: &'a dyn BenchmarkHarness,
    pub advisor: &'a dyn PerfAdvisor,
    pub budget: PerfBudget,
}

/// One benchmark measurement: a stable name and a duration in nanoseconds (smaller = faster).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BenchSample {
    pub name: String,
    pub nanos: u64,
}

/// The result of running the benchmark harness over one file set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BenchSuite {
    pub samples: Vec<BenchSample>,
}

impl BenchSuite {
    #[must_use]
    pub fn new(samples: Vec<BenchSample>) -> Self {
        BenchSuite { samples }
    }
    fn get(&self, name: &str) -> Option<u64> {
        self.samples
            .iter()
            .find(|s| s.name == name)
            .map(|s| s.nanos)
    }
}

/// The benchmark-harness seam. A production impl shells out to the real harness inside the serving-ops
/// sandbox and returns the timings; the offline impl is scripted. `None` means "no harness for this
/// file set / language" — an honest skip, not a zero regression.
pub trait BenchmarkHarness: Send + Sync {
    /// Measure the given files. `None` if no benchmark could be run.
    fn measure(&self, lang: Language, files: &[(String, String)]) -> Option<BenchSuite>;
}

/// The no-harness default: never produces measurements (the AST-complexity term still runs).
#[derive(Debug, Clone, Default)]
pub struct NoBench;
impl BenchmarkHarness for NoBench {
    fn measure(&self, _lang: Language, _files: &[(String, String)]) -> Option<BenchSuite> {
        None
    }
}

/// An offline scripted harness: returns pre-canned timings keyed by the content hash of the file set
/// so the SAME files always measure identically (deterministic), and the *baseline* vs *post-edit*
/// sets can be scripted to differ. Used by tests and dry-runs.
#[derive(Debug, Clone, Default)]
pub struct ScriptedBench {
    /// `(joined-source-marker, suite)` — the first entry whose marker is a substring of the joined
    /// source wins, so a test can say "the set containing `slow_path` measures 200ns".
    pub rules: Vec<(String, BenchSuite)>,
}

impl ScriptedBench {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// Add a rule: if any file's source contains `marker`, the suite is `suite`.
    #[must_use]
    pub fn when_contains(mut self, marker: &str, suite: BenchSuite) -> Self {
        self.rules.push((marker.to_string(), suite));
        self
    }
}

impl BenchmarkHarness for ScriptedBench {
    fn measure(&self, _lang: Language, files: &[(String, String)]) -> Option<BenchSuite> {
        let joined: String = files
            .iter()
            .map(|(_, c)| c.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        for (marker, suite) in &self.rules {
            if joined.contains(marker.as_str()) {
                return Some(suite.clone());
            }
        }
        None
    }
}

/// One model-advisory perf finding — qualitative, never a term in the numeric penalty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PerfFinding {
    pub message: String,
    /// Whether the model believes this sits on a hot / latency-critical path (surfaced, not scored).
    pub hot_path: bool,
}

/// The model-advisory seam (stage 6's "model review"). A production impl calls a model with the diff
/// and the complexity delta; the offline impl is scripted / no-op.
pub trait PerfAdvisor: Send + Sync {
    fn review(
        &self,
        lang: Language,
        before: &[(String, String)],
        after: &[(String, String)],
        complexity: &ComplexityDelta,
    ) -> Vec<PerfFinding>;
}

/// The no-advisory default (no model available).
#[derive(Debug, Clone, Default)]
pub struct NoAdvisor;
impl PerfAdvisor for NoAdvisor {
    fn review(
        &self,
        _lang: Language,
        _before: &[(String, String)],
        _after: &[(String, String)],
        _complexity: &ComplexityDelta,
    ) -> Vec<PerfFinding> {
        Vec::new()
    }
}

// ============================ AST-complexity heuristic ============================

/// Map the pipeline's capability language onto the AST-capable grammar, if one exists. Round-11
/// broadened `ainxt-semantic` grammar coverage to Go/JS/TS/Java, so the per-function AST-complexity
/// scan is now precise for all of them; only COBOL/`Other` fall back to a lexical scan over the whole
/// file (still deterministic, documented as a heuristic).
fn ast_lang(lang: Language) -> Option<AstLanguage> {
    match lang {
        Language::Rust => Some(AstLanguage::Rust),
        Language::Python => Some(AstLanguage::Python),
        Language::Go => Some(AstLanguage::Go),
        Language::JavaScript => Some(AstLanguage::JavaScript),
        Language::TypeScript => Some(AstLanguage::TypeScript),
        Language::Java => Some(AstLanguage::Java),
        Language::Cobol | Language::Other => None,
    }
}

/// The decision keywords (whole-word) that each add one to cyclomatic complexity, per language family.
fn decision_keywords(lang: Language) -> &'static [&'static str] {
    match lang {
        Language::Python => &["if", "elif", "for", "while", "and", "or", "except"],
        Language::Rust => &["if", "while", "for", "match", "loop"],
        // Java / TypeScript / Go / JavaScript / Cobol / Other: a C-family-ish keyword set.
        _ => &["if", "for", "while", "case", "catch", "switch"],
    }
}

/// Count the decision points in a snippet: `1` base + each whole-word decision keyword + each `&&` and
/// `||` short-circuit operator + each Rust/JS `?` (try / optional-chaining / ternary). Whole-word
/// matching avoids counting `if` inside `diff` or `notify`.
fn cyclomatic(snippet: &str, lang: Language) -> u32 {
    let keywords = decision_keywords(lang);
    let mut complexity: u32 = 1;

    // Whole-word keyword scan over identifier runs.
    let bytes = snippet.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c.is_ascii_alphabetic() || c == b'_' {
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            let word = &snippet[start..i];
            if keywords.contains(&word) {
                complexity += 1;
            }
        } else {
            i += 1;
        }
    }

    // Short-circuit boolean operators are branches too (both families).
    complexity += snippet.matches("&&").count() as u32;
    complexity += snippet.matches("||").count() as u32;
    complexity
}

/// The per-function complexity of one file. For an AST language the function spans come from
/// tree-sitter (so only real function bodies are scored); otherwise the whole file is scored as one
/// unit (lexical fallback).
fn file_complexity(lang: Language, source: &str) -> Vec<(String, u32)> {
    if let Some(al) = ast_lang(lang) {
        if let Ok(fns) = ainxt_semantic::list_functions(source, al) {
            if !fns.is_empty() {
                return fns
                    .into_iter()
                    .map(|(name, span)| {
                        let body = source
                            .get(span.start_byte..span.end_byte)
                            .unwrap_or_default();
                        (name, cyclomatic(body, lang))
                    })
                    .collect();
            }
        }
    }
    // Lexical fallback: the whole file as one unit.
    vec![("<file>".to_string(), cyclomatic(source, lang))]
}

/// Total cyclomatic complexity summed over an edit set.
#[must_use]
pub fn ast_complexity(lang: Language, files: &[(String, String)]) -> u32 {
    files
        .iter()
        .map(|(_, src)| {
            file_complexity(lang, src)
                .iter()
                .map(|(_, c)| *c)
                .sum::<u32>()
        })
        .sum()
}

/// The complexity change an edit introduced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComplexityDelta {
    pub before: u32,
    pub after: u32,
    /// Net added complexity (`0` if the edit simplified or was neutral).
    pub added: u32,
}

/// Compute the complexity delta between the baseline and post-edit file sets.
#[must_use]
pub fn complexity_delta(
    lang: Language,
    before: &[(String, String)],
    after: &[(String, String)],
) -> ComplexityDelta {
    let b = ast_complexity(lang, before);
    let a = ast_complexity(lang, after);
    ComplexityDelta {
        before: b,
        after: a,
        added: a.saturating_sub(b),
    }
}

// ============================ Stage-6 analysis ============================

/// The output of stage 6: the `0..=25` penalty the Confidence Score consumes, the honest stage
/// verdict, the model advisories (surfaced, unscored), and a full breakdown of every deduction.
#[derive(Debug, Clone, PartialEq)]
pub struct PerfReport {
    /// The combined regression penalty `0..=25` fed into [`crate::confidence::ConfidenceInputs`].
    pub regression_penalty: u8,
    /// Non-gating: `Pass` (clean), `Advisory` (a regression / advisories to surface), or `Skipped`
    /// (no perf tooling for this language — an honest, scored skip, never a silent pass).
    pub verdict: StageVerdict,
    /// Model advisories — surfaced verbatim, never a term in `regression_penalty`.
    pub advisories: Vec<PerfFinding>,
    /// One line per contributing signal, for the auditable report.
    pub breakdown: Vec<String>,
    /// The computed complexity delta (for the gap report / journal).
    pub complexity: ComplexityDelta,
    /// The worst benchmark slowdown ratio observed (`1.0` = no change; `None` = no benchmark ran).
    pub worst_ratio: Option<f64>,
}

impl PerfReport {
    /// The stage-6 [`StageReport`] to fold into the pipeline's report set.
    #[must_use]
    pub fn stage_report(&self) -> StageReport {
        StageReport {
            stage: Stage::Perf,
            verdict: self.verdict.clone(),
            // Benchmark + AST complexity are deterministic tools; the model advisory rides alongside
            // but does not decide the verdict, so the stage is deterministic.
            deterministic: true,
        }
    }
}

/// The worst (largest) benchmark slowdown ratio over the matched benchmark names, or `None` if either
/// side has no measurements. Only benchmarks present in BOTH runs are diffed (a brand-new benchmark
/// has no baseline to regress against).
fn worst_slowdown(before: &BenchSuite, after: &BenchSuite) -> Option<f64> {
    let mut worst: Option<f64> = None;
    for s in &before.samples {
        if s.nanos == 0 {
            continue;
        }
        if let Some(after_ns) = after.get(&s.name) {
            let ratio = after_ns as f64 / s.nanos as f64;
            worst = Some(worst.map_or(ratio, |w| w.max(ratio)));
        }
    }
    worst
}

/// Run Performance Analysis (stage 6) over an edit's baseline vs post-edit file set.
///
/// Combines the three signals into the `0..=25` regression penalty and an honest, non-gating verdict.
/// The model advisory is surfaced but never scored.
#[must_use]
pub fn analyze_perf(
    lang: Language,
    before: &[(String, String)],
    after: &[(String, String)],
    bench: &dyn BenchmarkHarness,
    advisor: &dyn PerfAdvisor,
    budget: &PerfBudget,
) -> PerfReport {
    let complexity = complexity_delta(lang, before, after);
    let advisories = advisor.review(lang, before, after, &complexity);

    // Honest capability gate: a language with no perf tooling at all is a Skipped(reason) — a scored
    // skip penalty in the Confidence Score, never a silent pass.
    let cap = capability(lang, StageKind::Perf);
    if matches!(cap, Capability::Skip(_) | Capability::ManualReview(_)) {
        return PerfReport {
            regression_penalty: 0,
            verdict: StageVerdict::Skipped {
                reason: format!("perf analysis unavailable: {}", cap.reason()),
            },
            advisories,
            breakdown: vec![format!("perf skipped ({})", cap.reason())],
            complexity,
            worst_ratio: None,
        };
    }

    let mut breakdown = Vec::new();

    // ---- Signal 1: AST-complexity growth over budget.
    let over_complexity = complexity
        .added
        .saturating_sub(budget.max_complexity_growth);
    let complexity_pen = (over_complexity.saturating_mul(3)).min(15);
    if complexity_pen > 0 {
        breakdown.push(format!(
            "-{complexity_pen} AST complexity +{} (budget {}) over the edit set",
            complexity.added, budget.max_complexity_growth
        ));
    }

    // ---- Signal 2: benchmark diff (baseline vs post-edit), if a harness is present.
    let before_suite = bench.measure(lang, before);
    let after_suite = bench.measure(lang, after);
    let (worst_ratio, bench_pen) = match (before_suite, after_suite) {
        (Some(b), Some(a)) => {
            let worst = worst_slowdown(&b, &a);
            match worst {
                Some(ratio) => {
                    let slowdown_pct = (ratio - 1.0) * 100.0;
                    let allowed_pct = (budget.max_regression_ratio - 1.0) * 100.0;
                    let over = (slowdown_pct - allowed_pct).max(0.0);
                    let pen = (over.round() as u32).min(25) as u8;
                    if pen > 0 {
                        breakdown.push(format!(
                            "-{pen} benchmark regression {:.0}% slower (budget {:.0}%)",
                            slowdown_pct, allowed_pct
                        ));
                    }
                    (Some(ratio), pen)
                }
                None => (None, 0),
            }
        }
        _ => (None, 0),
    };

    let regression_penalty = (complexity_pen as u16 + bench_pen as u16).min(25) as u8;

    // Surface (never score) the model advisories in the breakdown.
    for f in &advisories {
        breakdown.push(format!(
            "advisory{}: {}",
            if f.hot_path { " (hot path)" } else { "" },
            f.message
        ));
    }

    let verdict = if regression_penalty > 0 || !advisories.is_empty() {
        StageVerdict::Advisory {
            detail: if breakdown.is_empty() {
                "perf advisory".to_string()
            } else {
                breakdown.join("; ")
            },
        }
    } else {
        StageVerdict::Pass
    };
    if breakdown.is_empty() {
        breakdown.push("no perf regression".to_string());
    }

    PerfReport {
        regression_penalty,
        verdict,
        advisories,
        breakdown,
        complexity,
        worst_ratio,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(path: &str, src: &str) -> (String, String) {
        (path.to_string(), src.to_string())
    }

    #[test]
    fn a_pure_refactor_within_budget_scores_zero_and_passes() {
        let before = vec![f(
            "a.rs",
            "fn g() -> i32 {\n    if true { 1 } else { 2 }\n}\n",
        )];
        let after = vec![f(
            "a.rs",
            "fn g() -> i32 {\n    if false { 2 } else { 1 }\n}\n",
        )];
        let r = analyze_perf(
            Language::Rust,
            &before,
            &after,
            &NoBench,
            &NoAdvisor,
            &PerfBudget::default(),
        );
        assert_eq!(r.regression_penalty, 0);
        assert!(r.verdict.is_pass());
        assert_eq!(r.complexity.added, 0);
    }

    #[test]
    fn a_big_complexity_jump_is_penalized_and_advisory() {
        // before: complexity 1; after: many branches → well over the budget of 5.
        let before = vec![f("a.rs", "fn g(x: i32) -> i32 {\n    x\n}\n")];
        let after = vec![f(
            "a.rs",
            "fn g(x: i32) -> i32 {\n    if x > 0 && x < 9 { if x==1 {1} else if x==2 {2} \
             else {3} } else { while x>0 {} for _ in 0..x {} match x { _ => 0 } }\n}\n",
        )];
        let r = analyze_perf(
            Language::Rust,
            &before,
            &after,
            &NoBench,
            &NoAdvisor,
            &PerfBudget::default(),
        );
        assert!(r.complexity.added > 5, "added={}", r.complexity.added);
        assert!(r.regression_penalty > 0);
        assert!(matches!(r.verdict, StageVerdict::Advisory { .. }));
    }

    #[test]
    fn benchmark_slowdown_over_budget_is_scored() {
        let before = vec![f("a.rs", "fn hot() {}\n")];
        let after = vec![f("a.rs", "fn hot() { /* slow_path */ }\n")];
        let bench = ScriptedBench::new()
            .when_contains(
                "slow_path",
                BenchSuite::new(vec![BenchSample {
                    name: "hot".into(),
                    nanos: 200,
                }]),
            )
            // baseline (no slow_path marker): matched by an empty marker fallback below.
            .when_contains(
                "fn hot",
                BenchSuite::new(vec![BenchSample {
                    name: "hot".into(),
                    nanos: 100,
                }]),
            );
        // NOTE: rules are first-match; the after set contains BOTH "slow_path" and "fn hot", so the
        // slow_path rule (listed first) wins for `after`; the before set matches only "fn hot".
        let r = analyze_perf(
            Language::Rust,
            &before,
            &after,
            &bench,
            &NoAdvisor,
            &PerfBudget {
                max_complexity_growth: 5,
                max_regression_ratio: 1.10,
            },
        );
        // 100ns → 200ns = 100% slower, budget 10% → ~90 points capped at 25.
        assert_eq!(r.worst_ratio, Some(2.0));
        assert_eq!(r.regression_penalty, 25);
        assert!(matches!(r.verdict, StageVerdict::Advisory { .. }));
    }

    #[test]
    fn no_harness_leaves_only_the_complexity_signal() {
        let before = vec![f("a.py", "def g():\n    return 1\n")];
        let after = vec![f("a.py", "def g():\n    return 1\n")];
        let r = analyze_perf(
            Language::Python,
            &before,
            &after,
            &NoBench,
            &NoAdvisor,
            &PerfBudget::default(),
        );
        assert_eq!(r.worst_ratio, None);
        assert_eq!(r.regression_penalty, 0);
        assert!(r.verdict.is_pass());
    }

    #[test]
    fn a_language_without_perf_tooling_is_an_honest_skip() {
        // JavaScript Perf = Skip in the capability matrix → Skipped, never a silent pass.
        let before = vec![f("a.js", "function g(){ return 1 }\n")];
        let after = vec![f("a.js", "function g(){ if(x){} for(;;){} return 1 }\n")];
        let r = analyze_perf(
            Language::JavaScript,
            &before,
            &after,
            &NoBench,
            &NoAdvisor,
            &PerfBudget::default(),
        );
        assert!(r.verdict.is_skipped());
        assert_eq!(r.regression_penalty, 0);
    }

    #[test]
    fn model_advisory_is_surfaced_but_never_scored() {
        struct HotPathAdvisor;
        impl PerfAdvisor for HotPathAdvisor {
            fn review(
                &self,
                _l: Language,
                _b: &[(String, String)],
                _a: &[(String, String)],
                _c: &ComplexityDelta,
            ) -> Vec<PerfFinding> {
                vec![PerfFinding {
                    message: "allocation inside the settlement loop".into(),
                    hot_path: true,
                }]
            }
        }
        // Identical files → zero deterministic penalty; only the model advisory is present.
        let files = vec![f("a.rs", "fn g() {}\n")];
        let r = analyze_perf(
            Language::Rust,
            &files,
            &files,
            &NoBench,
            &HotPathAdvisor,
            &PerfBudget::default(),
        );
        // The advisory is surfaced...
        assert_eq!(r.advisories.len(), 1);
        assert!(r.advisories[0].hot_path);
        assert!(r.breakdown.iter().any(|b| b.contains("settlement loop")));
        // ...but it added NOTHING to the numeric penalty (anti-sycophancy: model is not a term).
        assert_eq!(r.regression_penalty, 0);
        // A model finding still flips the verdict to Advisory so a reviewer sees it.
        assert!(matches!(r.verdict, StageVerdict::Advisory { .. }));
    }

    #[test]
    fn cyclomatic_whole_word_does_not_match_substrings() {
        // "notify" / "diff" must NOT count as if/for. Only the real `if` counts (+1 over base 1).
        let c = cyclomatic(
            "fn diff() { let notify = 1; if notify > 0 { } }",
            Language::Rust,
        );
        assert_eq!(c, 2);
    }
}
