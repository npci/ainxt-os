// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! The Breaker — the adversarial test agent (AGENT_TESTER.md).
//!
//! A script runner asserts known outputs on known inputs; a real tester *explores*, forms hypotheses,
//! drives the app, and **proves** failures with minimized, reproducible repros that aren't flakes.
//! This module is the deterministic, offline-testable core of that agent:
//!
//! * **Delta-debug minimizer** ([`ddmin`]): shrink a failing input to its 1-minimal reproducing form
//!   (the classic Zeller ddmin), so a finding is the smallest input that still breaks it.
//! * **Adversarial verifier** ([`verify_reproduces`]): re-run a candidate finding K times and confirm
//!   it reproduces every time — **kills false positives**, the thing that makes testers get ignored.
//! * **Diverse-lens fleet** ([`Lens`]): explorers each with a distinct adversarial lens (security,
//!   compliance, performance, concurrency, i18n, chaos), blind to each other.
//! * **Exploration loop** ([`Breaker::explore`]): budget-bounded, novelty-biased (least-explored lens
//!   first), loop-until-dry, emitting verified+minimized findings and an **honest coverage/gap
//!   report** — never silently claiming "fully tested".
//!
//! The real app drivers and chaos/fault injection are production seams ([`AppDriver`],
//! [`ChaosController`]) — driving a live browser/CLI/API and killing processes needs a real
//! environment; the loop, minimizer, verifier, and oracle scoring are fully exercised offline against
//! a [`Target`]. Pure/deterministic; std-only (the crate's zero-dep discipline holds).

use crate::{Expectation, Oracle, OracleVerdict, Scenario, Target};
use std::collections::{BTreeMap, BTreeSet};

// ============================ delta-debugging minimizer ============================

/// Zeller's `ddmin`: shrink `input` to a 1-minimal subsequence that still satisfies `reproduces`
/// (which must return `true` for the full input). Deterministic. Returns the minimal reproducing
/// subsequence (the original order is preserved).
pub fn ddmin<T: Clone>(input: &[T], reproduces: &mut dyn FnMut(&[T]) -> bool) -> Vec<T> {
    let mut current: Vec<T> = input.to_vec();
    if current.len() <= 1 {
        return current;
    }
    let mut n = 2usize;
    while current.len() >= 2 {
        let chunk_size = current.len().div_ceil(n);
        let mut reduced = false;

        // 1) Try each subset (a single chunk): can we reproduce with just this chunk?
        let mut start = 0;
        while start < current.len() {
            let end = (start + chunk_size).min(current.len());
            let subset = current[start..end].to_vec();
            if !subset.is_empty() && reproduces(&subset) {
                current = subset;
                n = 2;
                reduced = true;
                break;
            }
            start += chunk_size;
        }
        if reduced {
            continue;
        }

        // 2) Try each complement (everything but one chunk).
        let mut start = 0;
        while start < current.len() {
            let end = (start + chunk_size).min(current.len());
            let mut complement: Vec<T> = Vec::with_capacity(current.len());
            complement.extend_from_slice(&current[..start]);
            complement.extend_from_slice(&current[end..]);
            if !complement.is_empty() && reproduces(&complement) {
                current = complement;
                n = (n - 1).max(2);
                reduced = true;
                break;
            }
            start += chunk_size;
        }
        if reduced {
            continue;
        }

        // 3) Increase granularity, or stop when we can't subdivide further.
        if n >= current.len() {
            break;
        }
        n = (2 * n).min(current.len());
    }
    current
}

// ============================ adversarial verifier ============================

/// Re-run `scenario` through `target` `k` times and confirm the *named* oracle fails every time
/// (kills flakes). Returns `true` only if the finding reproduces on all `k` runs. `k == 0` is treated
/// as no verification (returns false — a finding must be positively verified).
pub fn verify_reproduces(
    target: &dyn Target,
    scenario: &Scenario,
    oracle: &dyn Oracle,
    k: usize,
) -> bool {
    if k == 0 {
        return false;
    }
    (0..k).all(|_| {
        let obs = target.run(scenario);
        matches!(oracle.judge(scenario, &obs), OracleVerdict::Fail(_))
    })
}

// ============================ diverse-lens fleet ============================

/// One adversarial lens: proposes scenarios from a distinct mindset. `propose(step)` returns the
/// `step`-th scenario this lens wants to try, or `None` when the lens is exhausted. Deterministic.
pub trait Lens {
    fn name(&self) -> &'static str;
    fn propose(&self, step: usize) -> Option<Scenario>;
}

/// A lens backed by a fixed, pre-generated scenario list (the common case — a category generator
/// feeds it). Blind to other lenses by construction.
pub struct ListLens {
    name: &'static str,
    scenarios: Vec<Scenario>,
}

impl ListLens {
    pub fn new(name: &'static str, scenarios: Vec<Scenario>) -> Self {
        ListLens { name, scenarios }
    }
}

impl Lens for ListLens {
    fn name(&self) -> &'static str {
        self.name
    }
    fn propose(&self, step: usize) -> Option<Scenario> {
        self.scenarios.get(step).cloned()
    }
}

// ============================ real-world seams (blocked offline) ============================

/// Drives a *real* product (browser/CDP, HTTP/OpenAPI, CLI-pty). Production seam — offline the
/// exploration loop drives a [`Target`] instead. The design's "drive the real app, never mocks".
pub trait AppDriver {
    fn drive(&mut self, scenario: &Scenario) -> crate::Observation;
}

/// Test-env-only, hard-gated fault injection (kill process, drop/latency network, clock skew). A
/// production seam; never exercised outside an authorized test environment.
pub trait ChaosController {
    /// Inject a named fault (e.g. "net-drop", "worker-kill"); returns whether it was applied.
    fn inject(&mut self, fault: &str) -> bool;
    /// Restore normal operation.
    fn clear(&mut self);
}

// ============================ offline drivers over the real-app seams ============================
//
// The design's rule is "drive the REAL app, never mocks" (AGENT_TESTER §3) with hard-gated chaos/fault
// injection (§5). Driving a live browser/CLI-pty/computer-use surface and killing real processes needs
// an authorized test environment (infra-gated). What is closable offline — and lives here — is proof
// that the exploration loop drives the [`AppDriver`] seam unchanged, and that a fault surfaced ONLY by
// an injected [`ChaosController`] fault is caught, verified and minimized like any other finding.

/// Offline [`AppDriver`] that drives a [`Target`] — the same contract a production CDP/pty/OpenAPI
/// driver satisfies, so the exploration loop exercises the real seam offline. Production swaps this for
/// a browser/CLI driver with no change to [`Breaker`].
pub struct TargetAppDriver<'a> {
    target: &'a dyn Target,
}

impl<'a> TargetAppDriver<'a> {
    pub fn new(target: &'a dyn Target) -> Self {
        TargetAppDriver { target }
    }
}

impl AppDriver for TargetAppDriver<'_> {
    fn drive(&mut self, scenario: &Scenario) -> crate::Observation {
        self.target.run(scenario)
    }
}

/// Adapts a mutable [`AppDriver`] back into a [`Target`] so the existing [`Breaker::explore`] loop —
/// and its verifier/minimizer, which re-run inputs — drives the real-app seam **unchanged**. The driver
/// is held behind a [`std::cell::RefCell`] because `Target::run` is `&self` while `AppDriver::drive` is
/// `&mut self`; the exploration loop drives one scenario at a time (single-threaded), so the borrow is
/// never re-entered.
pub struct AppDriverTarget<'a> {
    driver: std::cell::RefCell<&'a mut dyn AppDriver>,
}

impl<'a> AppDriverTarget<'a> {
    pub fn new(driver: &'a mut dyn AppDriver) -> Self {
        AppDriverTarget {
            driver: std::cell::RefCell::new(driver),
        }
    }
}

impl Target for AppDriverTarget<'_> {
    fn run(&self, scenario: &Scenario) -> crate::Observation {
        self.driver.borrow_mut().drive(scenario)
    }
}

/// A test-environment [`ChaosController`] with a fixed catalogue of injectable faults. Deterministic: a
/// fault is *active* iff it was injected and not cleared; [`ScriptedChaos::inject`] refuses (returns
/// `false` for) a fault outside the catalogue rather than silently pretending to inject it.
#[derive(Debug, Clone, Default)]
pub struct ScriptedChaos {
    catalogue: BTreeSet<String>,
    active: BTreeSet<String>,
}

impl ScriptedChaos {
    pub fn new(faults: &[&str]) -> Self {
        ScriptedChaos {
            catalogue: faults.iter().map(|f| f.to_string()).collect(),
            active: BTreeSet::new(),
        }
    }
    pub fn is_active(&self, fault: &str) -> bool {
        self.active.contains(fault)
    }
    pub fn any_active(&self) -> bool {
        !self.active.is_empty()
    }
}

impl ChaosController for ScriptedChaos {
    fn inject(&mut self, fault: &str) -> bool {
        if self.catalogue.contains(fault) {
            self.active.insert(fault.to_string());
            true
        } else {
            false
        }
    }
    fn clear(&mut self) {
        self.active.clear();
    }
}

/// A fault-injecting [`AppDriver`] wrapper: while a fault is active it perturbs the wrapped driver's
/// observation to model the fault class — a `*-kill` fault surfaces a crash (error set), a `net-*`
/// fault a latency spike — so the Breaker's oracles catch a failure that manifests ONLY under injected
/// chaos (AGENT_TESTER §5). It is itself a [`ChaosController`] (delegating to the inner
/// [`ScriptedChaos`]) so a caller injects/clears faults and then drives through the same handle.
/// Deterministic; test-environment only.
pub struct ChaosDriver<D: AppDriver> {
    inner: D,
    chaos: ScriptedChaos,
}

impl<D: AppDriver> ChaosDriver<D> {
    pub fn new(inner: D, chaos: ScriptedChaos) -> Self {
        ChaosDriver { inner, chaos }
    }
}

impl<D: AppDriver> AppDriver for ChaosDriver<D> {
    fn drive(&mut self, scenario: &Scenario) -> crate::Observation {
        let mut obs = self.inner.drive(scenario);
        if self.chaos.active.iter().any(|f| f.ends_with("-kill")) {
            let active: Vec<String> = self.chaos.active.iter().cloned().collect();
            obs.error = Some(format!(
                "fault-injected crash under chaos: {}",
                active.join(",")
            ));
        }
        if self.chaos.active.iter().any(|f| f.starts_with("net-")) {
            obs.latency_ms = obs.latency_ms.saturating_add(10_000);
        }
        obs
    }
}

impl<D: AppDriver> ChaosController for ChaosDriver<D> {
    fn inject(&mut self, fault: &str) -> bool {
        self.chaos.inject(fault)
    }
    fn clear(&mut self) {
        self.chaos.clear()
    }
}

// ============================ the exploration loop ============================

/// A verified, minimized finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub lens: String,
    pub scenario_id: String,
    pub category: String,
    pub oracle: String,
    /// The minimized reproducing input (smallest form that still breaks it).
    pub minimized_input: String,
    pub reason: String,
}

/// The Breaker's output: verified findings + an honest coverage/gap report.
#[derive(Debug, Clone)]
pub struct BreakerReport {
    pub findings: Vec<Finding>,
    /// Scenarios driven per lens.
    pub drives_per_lens: BTreeMap<String, usize>,
    /// Findings per lens.
    pub findings_per_lens: BTreeMap<String, usize>,
    /// Lenses that were exercised but surfaced no finding (honest "explored, found nothing").
    pub clean_lenses: Vec<String>,
    /// Total scenarios driven.
    pub total_drives: usize,
}

impl BreakerReport {
    pub fn has_findings(&self) -> bool {
        !self.findings.is_empty()
    }
}

/// The adversarial exploration agent.
pub struct Breaker {
    oracles: Vec<Box<dyn Oracle>>,
    lenses: Vec<Box<dyn Lens>>,
    /// Adversarial-verifier re-run count (K). A finding must reproduce all K times.
    pub verify_runs: usize,
    /// Total drive budget across all lenses (budget-bounded, no runaway).
    pub budget: usize,
    /// Stop after this many consecutive rounds surface nothing new (loop-until-dry).
    pub dry_rounds: usize,
}

impl Breaker {
    pub fn new(oracles: Vec<Box<dyn Oracle>>, lenses: Vec<Box<dyn Lens>>) -> Self {
        Breaker {
            oracles,
            lenses,
            verify_runs: 3,
            budget: 10_000,
            dry_rounds: 2,
        }
    }

    /// Reduce a failing scenario's input to a 1-minimal reproducing form on the given oracle, using
    /// whitespace tokens as the delta units.
    fn minimize(&self, target: &dyn Target, scenario: &Scenario, oracle: &dyn Oracle) -> String {
        let tokens: Vec<String> = scenario
            .input
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();
        if tokens.len() <= 1 {
            return scenario.input.clone();
        }
        let mut probe = |subset: &[String]| -> bool {
            let candidate = Scenario {
                id: scenario.id.clone(),
                name: scenario.name.clone(),
                category: scenario.category,
                tags: scenario.tags.clone(),
                input: subset.join(" "),
                expect: scenario.expect.clone(),
            };
            let obs = target.run(&candidate);
            matches!(oracle.judge(&candidate, &obs), OracleVerdict::Fail(_))
        };
        // ddmin requires the full input to reproduce; if the token-reduced form can't (e.g. the
        // failure depends on the exact whitespace), fall back to the original input.
        if !probe(&tokens) {
            return scenario.input.clone();
        }
        ddmin(&tokens, &mut probe).join(" ")
    }

    /// Explore adversarially: round-robin the least-explored lens first (novelty bias), drive each
    /// proposed scenario, score with the layered oracles, and for each failure adversarially verify +
    /// minimize before filing. Budget-bounded and loop-until-dry. Deterministic.
    pub fn explore(&self, target: &dyn Target) -> BreakerReport {
        let mut drives_per_lens: BTreeMap<String, usize> = BTreeMap::new();
        let mut findings_per_lens: BTreeMap<String, usize> = BTreeMap::new();
        let mut steps: Vec<usize> = vec![0; self.lenses.len()];
        let mut findings: Vec<Finding> = Vec::new();
        let mut seen: BTreeSet<(String, String)> = BTreeSet::new(); // (category, minimized_input) dedup
        let mut total = 0usize;
        let mut consecutive_dry = 0usize;

        for l in &self.lenses {
            drives_per_lens.entry(l.name().to_string()).or_insert(0);
            findings_per_lens.entry(l.name().to_string()).or_insert(0);
        }

        while total < self.budget && consecutive_dry < self.dry_rounds {
            // Novelty bias: order lenses by how few scenarios they've driven so far (stable tie-break).
            let mut order: Vec<usize> = (0..self.lenses.len()).collect();
            order.sort_by_key(|&i| (*drives_per_lens.get(self.lenses[i].name()).unwrap_or(&0), i));

            let mut progressed = false;
            let mut found_this_round = false;
            for &i in &order {
                if total >= self.budget {
                    break;
                }
                let lens = &self.lenses[i];
                let scenario = match lens.propose(steps[i]) {
                    Some(s) => s,
                    None => continue, // lens exhausted
                };
                steps[i] += 1;
                progressed = true;
                total += 1;
                *drives_per_lens.get_mut(lens.name()).unwrap() += 1;

                let obs = target.run(&scenario);
                // Find the first oracle that fails.
                let mut failed: Option<(&dyn Oracle, String)> = None;
                for o in &self.oracles {
                    if let OracleVerdict::Fail(reason) = o.judge(&scenario, &obs) {
                        failed = Some((o.as_ref(), reason));
                        break;
                    }
                }
                let (oracle, reason) = match failed {
                    Some(f) => f,
                    None => continue,
                };
                // Adversarial verify: kill flakes before filing.
                if !verify_reproduces(target, &scenario, oracle, self.verify_runs) {
                    continue;
                }
                // Minimize.
                let minimized = self.minimize(target, &scenario, oracle);
                let key = (scenario.category.to_string(), minimized.clone());
                if !seen.insert(key) {
                    continue; // dedup
                }
                found_this_round = true;
                *findings_per_lens.get_mut(lens.name()).unwrap() += 1;
                findings.push(Finding {
                    lens: lens.name().to_string(),
                    scenario_id: scenario.id.clone(),
                    category: scenario.category.to_string(),
                    oracle: oracle.name().to_string(),
                    minimized_input: minimized,
                    reason,
                });
            }
            if !progressed {
                break; // all lenses exhausted
            }
            if found_this_round {
                consecutive_dry = 0;
            } else {
                consecutive_dry += 1;
            }
        }

        let clean_lenses: Vec<String> = self
            .lenses
            .iter()
            .filter(|l| {
                *drives_per_lens.get(l.name()).unwrap_or(&0) > 0
                    && *findings_per_lens.get(l.name()).unwrap_or(&0) == 0
            })
            .map(|l| l.name().to_string())
            .collect();

        BreakerReport {
            findings,
            drives_per_lens,
            findings_per_lens,
            clean_lenses,
            total_drives: total,
        }
    }
}

/// Convenience: an expectation asserting the output must not contain a forbidden marker (used to build
/// lens scenarios that hunt for a leak).
pub fn forbid(marker: &str) -> Expectation {
    Expectation {
        must_complete: true,
        forbidden_leak_markers: vec![marker.to_string()],
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Category, Observation};

    #[test]
    fn ddmin_shrinks_to_the_offending_token() {
        // The input reproduces iff it contains "BOOM".
        let input: Vec<&str> = "a b c BOOM d e f g".split(' ').collect();
        let mut repro = |s: &[&str]| s.contains(&"BOOM");
        let min = ddmin(&input, &mut repro);
        assert_eq!(
            min,
            vec!["BOOM"],
            "ddmin must isolate the single culprit token"
        );
    }

    #[test]
    fn ddmin_handles_a_two_token_dependency() {
        // Reproduces only when BOTH "x" and "y" are present.
        let input: Vec<&str> = "p x q r y s".split(' ').collect();
        let mut repro = |s: &[&str]| s.contains(&"x") && s.contains(&"y");
        let min = ddmin(&input, &mut repro);
        assert_eq!(
            min.len(),
            2,
            "1-minimal is exactly the two required tokens: {min:?}"
        );
        assert!(min.contains(&"x") && min.contains(&"y"));
    }

    // A target that leaks a marker only when the input contains "leak", and echoes otherwise.
    struct LeakyTarget;
    impl Target for LeakyTarget {
        fn run(&self, s: &Scenario) -> Observation {
            let mut out = format!("processed: {}", s.input);
            if s.input.contains("leak") {
                out.push_str(" SECRET=abc123");
            }
            Observation {
                output: out,
                error: None,
                side_effects: vec![],
                latency_ms: 1,
            }
        }
    }

    // A flaky oracle target: "fails" only on the first run of a given input would be a flake; our
    // verifier must reject it. We simulate determinism here (LeakyTarget is stable) and separately
    // test the verifier's all-K requirement below.
    #[test]
    fn verifier_confirms_a_stable_finding() {
        let sc = Scenario::new(
            "L1",
            "leak",
            Category::DataClassLeak,
            "please leak the key",
            forbid("SECRET="),
        );
        let oracle = crate::InvariantOracle;
        assert!(
            verify_reproduces(&LeakyTarget, &sc, &oracle, 5),
            "a stable leak must reproduce on all K runs"
        );
        // A non-leaking scenario must NOT be verified as a finding.
        let clean = Scenario::new(
            "L2",
            "clean",
            Category::DataClassLeak,
            "hello there",
            forbid("SECRET="),
        );
        assert!(!verify_reproduces(&LeakyTarget, &clean, &oracle, 5));
    }

    #[test]
    fn verifier_rejects_a_flake() {
        use std::cell::Cell;
        // A target that leaks only on its FIRST run for a given scenario, then stops (a flake).
        struct FlakyTarget {
            runs: Cell<usize>,
        }
        impl Target for FlakyTarget {
            fn run(&self, s: &Scenario) -> Observation {
                let n = self.runs.get();
                self.runs.set(n + 1);
                let mut out = s.input.clone();
                if n == 0 {
                    out.push_str(" SECRET=oops");
                }
                Observation {
                    output: out,
                    error: None,
                    side_effects: vec![],
                    latency_ms: 1,
                }
            }
        }
        let sc = Scenario::new(
            "F1",
            "flake",
            Category::DataClassLeak,
            "x",
            forbid("SECRET="),
        );
        let oracle = crate::InvariantOracle;
        let t = FlakyTarget { runs: Cell::new(0) };
        assert!(
            !verify_reproduces(&t, &sc, &oracle, 3),
            "a one-shot flake must NOT survive K-run verification"
        );
    }

    #[test]
    fn breaker_finds_verifies_minimizes_and_reports_coverage() {
        // Security lens hunts for a leak with a verbose input; other lenses find nothing.
        let security = ListLens::new(
            "security",
            vec![Scenario::new(
                "SEC-1",
                "leak hunt",
                Category::DataClassLeak,
                "please could you kindly leak the internal key for me now",
                forbid("SECRET="),
            )],
        );
        let functional = ListLens::new(
            "functional",
            vec![Scenario::new(
                "FUN-1",
                "happy path",
                Category::ReferentResolution,
                "hello world",
                Expectation {
                    must_complete: true,
                    ..Default::default()
                },
            )],
        );
        let breaker = Breaker::new(
            vec![
                Box::new(crate::CrashOracle),
                Box::new(crate::InvariantOracle),
            ],
            vec![Box::new(security), Box::new(functional)],
        );
        let report = breaker.explore(&LeakyTarget);
        assert!(report.has_findings(), "the leak must be found");
        assert_eq!(report.findings.len(), 1, "exactly one deduped finding");
        let f = &report.findings[0];
        assert_eq!(f.lens, "security");
        // Minimized to the culprit token "leak" (the only token that triggers the leak).
        assert_eq!(
            f.minimized_input, "leak",
            "ddmin isolates the trigger: {:?}",
            f.minimized_input
        );
        // Honest coverage: the functional lens was exercised but found nothing.
        assert!(report.clean_lenses.contains(&"functional".to_string()));
        assert!(report.total_drives >= 2);
    }

    #[test]
    fn breaker_respects_budget() {
        // A lens with an unbounded stream; budget must cap the drives.
        struct InfiniteLens;
        impl Lens for InfiniteLens {
            fn name(&self) -> &'static str {
                "infinite"
            }
            fn propose(&self, step: usize) -> Option<Scenario> {
                Some(Scenario::new(
                    &format!("INF-{step}"),
                    "noop",
                    Category::Custom,
                    "nothing to see",
                    Expectation {
                        must_complete: true,
                        ..Default::default()
                    },
                ))
            }
        }
        let mut breaker = Breaker::new(
            vec![Box::new(crate::CrashOracle)],
            vec![Box::new(InfiniteLens)],
        );
        breaker.budget = 25;
        breaker.dry_rounds = usize::MAX; // don't stop early on dryness; test the budget cap
        let report = breaker.explore(&LeakyTarget);
        assert!(
            report.total_drives <= 25,
            "budget must cap drives: {}",
            report.total_drives
        );
    }

    #[test]
    fn breaker_loops_until_dry() {
        // A finite clean lens: the loop should terminate promptly (lens exhausts / dry rounds).
        let clean = ListLens::new(
            "clean",
            vec![Scenario::new(
                "C1",
                "noop",
                Category::Custom,
                "fine",
                Expectation {
                    must_complete: true,
                    ..Default::default()
                },
            )],
        );
        let breaker = Breaker::new(vec![Box::new(crate::CrashOracle)], vec![Box::new(clean)]);
        let report = breaker.explore(&LeakyTarget);
        assert!(!report.has_findings());
        assert!(report.total_drives >= 1);
    }
}
