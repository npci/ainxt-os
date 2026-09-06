// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! ainxt-scenario — the AiNxt scenario-matrix runner (the Definition-of-Done engine).
//!
//! Design: `docs/architecture/SCENARIO_MATRIX.md`, `EVAL_PLATFORM.md`, `AGENT_TESTER.md`.
//!
//! The runner drives a [`Target`] through a set of [`Scenario`]s, applies layered
//! [`Oracle`]s to each [`Observation`], and produces a [`Report`] (with JUnit XML for CI).
//! It is the harness every phase's "done" is measured against.
//!
//! This is the Phase-0 skeleton: **zero external dependencies** (std only), so the
//! legal / supply-chain surface stays empty for Gate #0. `Target` is synchronous for
//! now; an async target adapter is wired when the real runtime lands (P1) — the
//! `Target` trait is the seam that change slots into without touching oracles or runner.

use std::collections::BTreeMap;
use std::fmt;

pub mod breaker;
pub mod matrix;
pub mod pairwise;
pub mod soak;

/// Scenario categories — mirror `SCENARIO_MATRIX.md`. Extend via [`Category::Custom`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Category {
    MalformedModelOutput,
    ProviderFailover,
    CancelMidTurn,
    Concurrency,
    Backpressure,
    HugeInput,
    UnicodeRtl,
    AuthExpiry,
    ComplianceRedaction,
    RbacDeny,
    AirGap,
    ResumeCrash,
    DoubleExecution,
    DataClassLeak,
    Injection,
    TokenizerWindow,
    ReferentResolution,
    Custom,
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Category::MalformedModelOutput => "malformed-model-output",
            Category::ProviderFailover => "provider-failover",
            Category::CancelMidTurn => "cancel-mid-turn",
            Category::Concurrency => "concurrency",
            Category::Backpressure => "backpressure",
            Category::HugeInput => "huge-input",
            Category::UnicodeRtl => "unicode-rtl",
            Category::AuthExpiry => "auth-expiry",
            Category::ComplianceRedaction => "compliance-redaction",
            Category::RbacDeny => "rbac-deny",
            Category::AirGap => "air-gap",
            Category::ResumeCrash => "resume-crash",
            Category::DoubleExecution => "double-execution",
            Category::DataClassLeak => "data-class-leak",
            Category::Injection => "injection",
            Category::TokenizerWindow => "tokenizer-window",
            Category::ReferentResolution => "referent-resolution",
            Category::Custom => "custom",
        };
        f.write_str(s)
    }
}

/// Data-only expectation a scenario carries; oracles read it. No behavior here.
#[derive(Debug, Clone, Default)]
pub struct Expectation {
    /// Output must contain each of these substrings.
    pub must_contain: Vec<String>,
    /// Output must contain NONE of these (e.g., the instruction text — the UPI→PDF bug).
    pub must_not_contain: Vec<String>,
    /// The turn must complete without an error.
    pub must_complete: bool,
    /// If set, latency must be ≤ this.
    pub max_latency_ms: Option<u64>,
    /// Side-effect ids must be unique (no double-execution / double-debit).
    pub forbid_side_effect_dupes: bool,
    /// These markers must NEVER appear in output (PAN/PII/secret leak, cross-tenant leak).
    pub forbidden_leak_markers: Vec<String>,
    /// The turn must FAIL and its error must contain each of these (for expected-denial scenarios
    /// like RBAC-deny / auth-expiry — a positive assertion that the gate refused).
    pub must_error_contains: Vec<String>,
}

/// One scenario: an input + what correct looks like.
#[derive(Debug, Clone)]
pub struct Scenario {
    pub id: String,
    pub name: String,
    pub category: Category,
    pub tags: Vec<String>,
    pub input: String,
    pub expect: Expectation,
}

impl Scenario {
    pub fn new(id: &str, name: &str, category: Category, input: &str, expect: Expectation) -> Self {
        Scenario {
            id: id.to_string(),
            name: name.to_string(),
            category,
            tags: Vec::new(),
            input: input.to_string(),
            expect,
        }
    }
}

/// What a [`Target`] produced for a scenario.
#[derive(Debug, Clone, Default)]
pub struct Observation {
    pub output: String,
    pub error: Option<String>,
    /// Ids of side-effecting actions dispatched (a duplicate = double-execution).
    pub side_effects: Vec<String>,
    pub latency_ms: u64,
}

/// The system under test. The real runtime implements this (later, via an async adapter);
/// tests use mock/faulty targets. This is the only seam between the harness and the runtime.
pub trait Target {
    fn run(&self, scenario: &Scenario) -> Observation;
}

/// A single oracle's verdict on one observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OracleVerdict {
    Pass,
    Fail(String),
    NotApplicable,
}

/// An oracle decides whether an observation is correct — layered per `AGENT_TESTER.md`.
pub trait Oracle {
    fn name(&self) -> &'static str;
    fn judge(&self, scenario: &Scenario, obs: &Observation) -> OracleVerdict;
}

// ---- Concrete oracles ----

/// Fails if the turn errored when it was expected to complete.
pub struct CrashOracle;
impl Oracle for CrashOracle {
    fn name(&self) -> &'static str {
        "crash"
    }
    fn judge(&self, s: &Scenario, o: &Observation) -> OracleVerdict {
        match (&o.error, s.expect.must_complete) {
            (Some(e), true) => OracleVerdict::Fail(format!("errored but must complete: {e}")),
            _ => OracleVerdict::Pass,
        }
    }
}

/// Spec oracle: enforces `must_contain` / `must_not_contain` against the output.
/// This is the oracle that catches the "generate this as pdf" content bug.
pub struct SpecOracle;
impl Oracle for SpecOracle {
    fn name(&self) -> &'static str {
        "spec"
    }
    fn judge(&self, s: &Scenario, o: &Observation) -> OracleVerdict {
        if s.expect.must_contain.is_empty()
            && s.expect.must_not_contain.is_empty()
            && s.expect.must_error_contains.is_empty()
        {
            return OracleVerdict::NotApplicable;
        }
        // Expected-denial: the turn must have errored with the stated reason.
        for needle in &s.expect.must_error_contains {
            match &o.error {
                Some(e) if e.contains(needle.as_str()) => {}
                Some(e) => {
                    return OracleVerdict::Fail(format!("error {e:?} missing expected {needle:?}"))
                }
                None => {
                    return OracleVerdict::Fail(format!(
                        "expected an error containing {needle:?}, but the turn succeeded"
                    ))
                }
            }
        }
        // Check the "must not echo the instruction / forbidden content" invariant first —
        // it is the primary signal for the referent/content-resolution bug class.
        for banned in &s.expect.must_not_contain {
            if o.output.contains(banned.as_str()) {
                return OracleVerdict::Fail(format!(
                    "output contains forbidden substring: {banned:?}"
                ));
            }
        }
        for needle in &s.expect.must_contain {
            if !o.output.contains(needle.as_str()) {
                return OracleVerdict::Fail(format!(
                    "output missing required substring: {needle:?}"
                ));
            }
        }
        OracleVerdict::Pass
    }
}

/// Invariant oracle: leak markers must never appear; side effects must be unique.
pub struct InvariantOracle;
impl Oracle for InvariantOracle {
    fn name(&self) -> &'static str {
        "invariant"
    }
    fn judge(&self, s: &Scenario, o: &Observation) -> OracleVerdict {
        for marker in &s.expect.forbidden_leak_markers {
            if o.output.contains(marker.as_str()) {
                return OracleVerdict::Fail(format!("leak marker present in output: {marker:?}"));
            }
        }
        if s.expect.forbid_side_effect_dupes {
            let mut seen = std::collections::HashSet::new();
            for eff in &o.side_effects {
                if !seen.insert(eff.as_str()) {
                    return OracleVerdict::Fail(format!(
                        "duplicate side effect (double-execution): {eff:?}"
                    ));
                }
            }
        }
        if s.expect.forbidden_leak_markers.is_empty() && !s.expect.forbid_side_effect_dupes {
            return OracleVerdict::NotApplicable;
        }
        OracleVerdict::Pass
    }
}

/// Performance oracle: latency must be within budget when one is set.
pub struct PerformanceOracle;
impl Oracle for PerformanceOracle {
    fn name(&self) -> &'static str {
        "performance"
    }
    fn judge(&self, s: &Scenario, o: &Observation) -> OracleVerdict {
        match s.expect.max_latency_ms {
            Some(max) if o.latency_ms > max => {
                OracleVerdict::Fail(format!("latency {}ms > budget {}ms", o.latency_ms, max))
            }
            Some(_) => OracleVerdict::Pass,
            None => OracleVerdict::NotApplicable,
        }
    }
}

/// Visual oracle (`AGENT_TESTER.md` §2, "a vision model judges the rendered UI broken"). We have no
/// pixel renderer in the runtime harness, so this is its text-surface analogue: a *structural render
/// integrity* check over the produced output — the class of breakage a vision oracle would catch
/// (garbled glyphs, an empty panel where content was promised, a cut-off / unclosed structure).
///
/// It only fires on a turn that was expected to complete AND actually produced an answer, and it is
/// deliberately conservative (it must never RED a correct answer): it flags only
/// * a Unicode **replacement character** `U+FFFD` — the on-screen "broken glyph" a corrupted
///   decode/round-trip produces (directly the 1.6 unicode/RTL corruption class), or
/// * an **empty render** where the spec required visible content (`must_contain` non-empty but the
///   output is blank/whitespace — the "empty panel" a vision oracle reports), or
/// * an **unclosed code fence** (an odd number of ``` markers — the "cut-off diff/panel" class).
pub struct VisualOracle;
impl Oracle for VisualOracle {
    fn name(&self) -> &'static str {
        "visual"
    }
    fn judge(&self, s: &Scenario, o: &Observation) -> OracleVerdict {
        // Only meaningful for a turn that was supposed to complete and did.
        if !s.expect.must_complete || o.error.is_some() {
            return OracleVerdict::NotApplicable;
        }
        if o.output.contains('\u{FFFD}') {
            return OracleVerdict::Fail(
                "rendered output contains the Unicode replacement glyph U+FFFD (corrupted render)"
                    .to_string(),
            );
        }
        if !s.expect.must_contain.is_empty() && o.output.trim().is_empty() {
            return OracleVerdict::Fail(
                "empty render: content was required but the output panel is blank".to_string(),
            );
        }
        if o.output.matches("```").count() % 2 != 0 {
            return OracleVerdict::Fail(
                "unclosed code fence: the rendered structure is cut off".to_string(),
            );
        }
        OracleVerdict::Pass
    }
}

/// A **pair oracle** decides correctness from *two* observations of the same scenario — the two
/// oracle classes in `AGENT_TESTER.md` §2 that a single observation cannot express:
/// **metamorphic** (a required relation between two runs must hold) and **differential** (a candidate
/// must not diverge from a reference / prior-version / shadow implementation). It is a distinct trait
/// from [`Oracle`] precisely because it needs the reference run — keeping the single-observation
/// oracles unchanged and non-breaking.
pub trait PairOracle {
    fn name(&self) -> &'static str;
    /// `primary` is the observation under judgement; `reference` is the comparison run (a repeat of
    /// the same input for metamorphic stability, or a reference/shadow implementation for
    /// differential parity).
    fn judge(
        &self,
        scenario: &Scenario,
        primary: &Observation,
        reference: &Observation,
    ) -> OracleVerdict;
}

/// Metamorphic oracle: the **same input asked twice must yield a materially-equal answer**
/// (`AGENT_TESTER.md` §2 metamorphic row — "ask same question twice ⇒ materially different answer"
/// is the bug). Non-determinism that changes the answer is a defect the single-run oracles cannot
/// see. Equality is on the trimmed output; both runs must have the same completion status.
pub struct MetamorphicOracle;
impl PairOracle for MetamorphicOracle {
    fn name(&self) -> &'static str {
        "metamorphic"
    }
    fn judge(&self, _s: &Scenario, a: &Observation, b: &Observation) -> OracleVerdict {
        if a.error.is_some() != b.error.is_some() {
            return OracleVerdict::Fail(format!(
                "metamorphic instability: same input completed inconsistently ({:?} vs {:?})",
                a.error, b.error
            ));
        }
        if a.output.trim() != b.output.trim() {
            return OracleVerdict::Fail(
                "metamorphic instability: the same question produced two materially-different answers"
                    .to_string(),
            );
        }
        OracleVerdict::Pass
    }
}

/// Differential oracle: the candidate must **not diverge from the reference implementation**
/// (`AGENT_TESTER.md` §2 differential row — the shadow-mode Rust-vs-Python parity check that guards a
/// strangler-fig cut-over). A byte-identical output is parity; any divergence on a turn both
/// implementations completed is a finding to investigate before cut-over.
pub struct DifferentialOracle;
impl PairOracle for DifferentialOracle {
    fn name(&self) -> &'static str {
        "differential"
    }
    fn judge(
        &self,
        _s: &Scenario,
        candidate: &Observation,
        reference: &Observation,
    ) -> OracleVerdict {
        if candidate.error.is_some() != reference.error.is_some() {
            return OracleVerdict::Fail(format!(
                "shadow divergence: candidate {:?} vs reference {:?} completion mismatch",
                candidate.error, reference.error
            ));
        }
        if candidate.output != reference.output {
            return OracleVerdict::Fail(
                "shadow divergence: candidate output differs from the reference implementation"
                    .to_string(),
            );
        }
        OracleVerdict::Pass
    }
}

/// The complete layered-oracle taxonomy (`AGENT_TESTER.md` §2), in the doc's order. Used for the
/// coverage-honesty report so a run can prove every oracle class was represented.
pub fn oracle_taxonomy() -> &'static [&'static str] {
    &[
        "crash",
        "spec",
        "invariant",
        "metamorphic",
        "differential",
        "visual",
        "performance",
    ]
}

/// The result of running one scenario through all oracles.
#[derive(Debug, Clone)]
pub struct ScenarioResult {
    pub id: String,
    pub name: String,
    pub category: Category,
    pub verdicts: Vec<(String, OracleVerdict)>,
}

impl ScenarioResult {
    pub fn passed(&self) -> bool {
        self.verdicts
            .iter()
            .all(|(_, v)| !matches!(v, OracleVerdict::Fail(_)))
    }
    pub fn failures(&self) -> Vec<String> {
        self.verdicts
            .iter()
            .filter_map(|(name, v)| match v {
                OracleVerdict::Fail(r) => Some(format!("[{name}] {r}")),
                _ => None,
            })
            .collect()
    }
}

/// The aggregate report — the DoD signal.
#[derive(Debug, Clone)]
pub struct Report {
    pub results: Vec<ScenarioResult>,
}

impl Report {
    pub fn total(&self) -> usize {
        self.results.len()
    }
    pub fn passed(&self) -> usize {
        self.results.iter().filter(|r| r.passed()).count()
    }
    pub fn failed(&self) -> usize {
        self.total() - self.passed()
    }
    pub fn all_passed(&self) -> bool {
        self.results.iter().all(|r| r.passed())
    }
    /// Categories exercised → count (honest coverage; empty categories are visible by absence).
    pub fn coverage(&self) -> BTreeMap<Category, usize> {
        let mut m = BTreeMap::new();
        for r in &self.results {
            *m.entry(r.category).or_insert(0) += 1;
        }
        m
    }

    pub fn summary(&self) -> String {
        let mut s = format!(
            "scenarios: {} | passed: {} | failed: {}\n",
            self.total(),
            self.passed(),
            self.failed()
        );
        for r in &self.results {
            if !r.passed() {
                s.push_str(&format!(
                    "  FAIL {} ({}): {}\n",
                    r.id,
                    r.category,
                    r.failures().join("; ")
                ));
            }
        }
        s.push_str("coverage:");
        for (cat, n) in self.coverage() {
            s.push_str(&format!(" {cat}={n}"));
        }
        s.push('\n');
        s
    }

    /// JUnit XML for GitLab CI test reports.
    pub fn junit_xml(&self) -> String {
        fn esc(s: &str) -> String {
            s.replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;")
                .replace('"', "&quot;")
        }
        let mut xml = String::new();
        xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.push_str(&format!(
            "<testsuite name=\"ainxt-scenario\" tests=\"{}\" failures=\"{}\">\n",
            self.total(),
            self.failed()
        ));
        for r in &self.results {
            xml.push_str(&format!(
                "  <testcase classname=\"{}\" name=\"{}\">",
                esc(&r.category.to_string()),
                esc(&format!("{} — {}", r.id, r.name))
            ));
            if !r.passed() {
                xml.push_str(&format!(
                    "\n    <failure message=\"{}\"/>\n  ",
                    esc(&r.failures().join("; "))
                ));
            }
            xml.push_str("</testcase>\n");
        }
        xml.push_str("</testsuite>\n");
        xml
    }
}

/// The runner: scenarios × target → oracles → report.
pub struct Runner {
    pub oracles: Vec<Box<dyn Oracle>>,
}

impl Runner {
    /// The default layered oracle set (crash, spec, invariant, performance).
    pub fn with_default_oracles() -> Self {
        Runner {
            oracles: vec![
                Box::new(CrashOracle),
                Box::new(SpecOracle),
                Box::new(InvariantOracle),
                Box::new(PerformanceOracle),
            ],
        }
    }

    /// The full single-observation taxonomy — adds the [`VisualOracle`] (structural render integrity)
    /// on top of the default set. The pair oracles (metamorphic/differential) are driven separately
    /// via [`Runner::run_shadow_parity`] because they need a reference run.
    pub fn with_full_taxonomy() -> Self {
        Runner {
            oracles: vec![
                Box::new(CrashOracle),
                Box::new(SpecOracle),
                Box::new(InvariantOracle),
                Box::new(VisualOracle),
                Box::new(PerformanceOracle),
            ],
        }
    }

    pub fn run(&self, scenarios: &[Scenario], target: &dyn Target) -> Report {
        let mut results = Vec::with_capacity(scenarios.len());
        for s in scenarios {
            let obs = target.run(s);
            let verdicts = self
                .oracles
                .iter()
                .map(|o| (o.name().to_string(), o.judge(s, &obs)))
                .collect();
            results.push(ScenarioResult {
                id: s.id.clone(),
                name: s.name.clone(),
                category: s.category,
                verdicts,
            });
        }
        Report { results }
    }

    /// Run each scenario through the pair oracles by driving a `primary` target and a `reference`
    /// target and comparing. This is the metamorphic/differential half of the taxonomy: pass the same
    /// target twice to test **metamorphic stability**, or a candidate + reference to test
    /// **differential (shadow-mode) parity**. Returns one [`ScenarioResult`] per scenario carrying the
    /// pair-oracle verdicts, so the aggregate [`Report`] machinery (pass/fail, JUnit) applies uniformly.
    pub fn run_shadow_parity(
        &self,
        scenarios: &[Scenario],
        primary: &dyn Target,
        reference: &dyn Target,
        pair_oracles: &[Box<dyn PairOracle>],
    ) -> Report {
        let mut results = Vec::with_capacity(scenarios.len());
        for s in scenarios {
            let a = primary.run(s);
            let b = reference.run(s);
            let verdicts = pair_oracles
                .iter()
                .map(|o| (o.name().to_string(), o.judge(s, &a, &b)))
                .collect();
            results.push(ScenarioResult {
                id: s.id.clone(),
                name: s.name.clone(),
                category: s.category,
                verdicts,
            });
        }
        Report { results }
    }
}

/// A built-in sample suite — real scenarios (incl. the UPI→PDF regression) so the harness
/// runs green against a correct target and RED against a faulty one. The full 1,000+ matrix
/// (git-native scenario files) loads on top of this once the real runtime target is wired.
pub fn sample_suite() -> Vec<Scenario> {
    vec![
        Scenario::new(
            "REF-001",
            "generate-this-as-pdf resolves to the prior answer, not the instruction",
            Category::ReferentResolution,
            "generate this as pdf",
            Expectation {
                must_contain: vec!["UPI".to_string()],
                must_not_contain: vec!["generate this as pdf".to_string()],
                must_complete: true,
                ..Default::default()
            },
        ),
        Scenario::new(
            "IDEM-001",
            "retried settlement action does not double-execute",
            Category::DoubleExecution,
            "initiate settlement batch NEFT-2026-07-18",
            Expectation {
                must_complete: true,
                forbid_side_effect_dupes: true,
                ..Default::default()
            },
        ),
        Scenario::new(
            "LEAK-001",
            "response never leaks a PAN marker",
            Category::DataClassLeak,
            "show me the account details",
            Expectation {
                must_complete: true,
                forbidden_leak_markers: vec!["PAN=".to_string()],
                ..Default::default()
            },
        ),
    ]
}
