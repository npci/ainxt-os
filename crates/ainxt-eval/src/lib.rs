// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! ainxt-eval — the Eval Platform core (Phase R3, ADR-010): **eval-as-continuous-gate**.
//!
//! The scorecard names the eval platform the keystone: routing "quality-not-regressed", prompt
//! drift, review confidence, and every quality "10" *assume it exists*. This crate is its core — a
//! gate that can genuinely FAIL:
//!
//! 1. A **gold set** of [`EvalCase`]s (input + rubric + passing threshold).
//! 2. A **system under eval** ([`EvalSystem`]) and an **independent judge** ([`QualityJudge`]) — both
//!    seams. Each case is scored on its own (no judge sees another's verdict). The LLM-judge plugs in
//!    here; tests use deterministic judges so the gate's own logic is trustworthy.
//! 3. A [`GatePolicy`] combining **absolute** thresholds (min pass-rate, min mean) with
//!    **non-inferiority** vs a stored [`EvalReport`] baseline: a run that regresses below
//!    `baseline − margin` **fails the gate**, even if it clears the absolutes. This is what turns
//!    "we have evals" into "a change can't ship if it made quality worse."
//!
//! [`EvalReport`] serializes, so it is the regression-vault baseline. Online canary/auto-rollback and
//! drift monitoring are downstream of this core (they re-run it on live traffic / over time).
//!
//! Clean-room; deterministic; the gate is exhaustively testable.

use serde::{Deserialize, Serialize};

pub mod audit;
pub mod ci;
pub mod dogfood;
pub mod durable;
pub mod integrity;
pub mod judge;
pub mod live;
pub mod manifest;
pub mod pipeline;
pub mod rag;
pub mod semantic;
pub mod stats;
pub mod vault;

/// Default significance level (α) the statistical non-inferiority branch uses when a caller has no
/// pre-registered value of its own.
pub const DEFAULT_GATE_ALPHA: f64 = 0.05;
/// Default FDR `q` the statistical non-inferiority branch uses when a caller has no pre-registered
/// value of its own.
pub const DEFAULT_GATE_Q: f64 = 0.05;

/// What "good" means for a case, and the score at/above which it passes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvalCriteria {
    pub rubric: String,
    /// Passing score (0–100).
    pub threshold: u8,
}

/// One gold-set case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvalCase {
    pub id: String,
    pub input: String,
    pub criteria: EvalCriteria,
}

impl EvalCase {
    pub fn new(id: &str, input: &str, rubric: &str, threshold: u8) -> Self {
        EvalCase {
            id: id.into(),
            input: input.into(),
            criteria: EvalCriteria {
                rubric: rubric.into(),
                threshold,
            },
        }
    }
}

/// A judge's independent verdict on one output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QualityScore {
    pub score: u8,
    pub rationale: String,
}

/// Scores an output against a case's criteria. An LLM-judge (calibrated, pinned) implements this;
/// tests use deterministic judges. Judges are consulted per-case and never see peers' verdicts.
pub trait QualityJudge: Send + Sync {
    fn score(&self, input: &str, output: &str, criteria: &EvalCriteria) -> QualityScore;
}

/// The system being evaluated — produces an output for a case input.
pub trait EvalSystem: Send + Sync {
    fn respond(&self, input: &str) -> String;
}

/// The scored result for one case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaseResult {
    pub id: String,
    pub output: String,
    pub score: u8,
    pub passed: bool,
    pub rationale: String,
}

/// The aggregate of an eval run — also the serializable regression-vault baseline.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvalReport {
    pub results: Vec<CaseResult>,
    pub n: usize,
    pub passed: usize,
    /// Mean score across cases (0–100).
    pub mean: u8,
    /// Fraction of cases that passed (0.0–1.0).
    pub pass_rate: f64,
}

/// Run a gold set through `system`, scoring each case with `judge`. Deterministic given deterministic
/// seams.
pub fn run_eval(
    cases: &[EvalCase],
    system: &dyn EvalSystem,
    judge: &dyn QualityJudge,
) -> EvalReport {
    let mut results = Vec::with_capacity(cases.len());
    let mut passed = 0usize;
    let mut score_sum = 0u32;
    for case in cases {
        let output = system.respond(&case.input);
        let verdict = judge.score(&case.input, &output, &case.criteria);
        let pass = verdict.score >= case.criteria.threshold;
        if pass {
            passed += 1;
        }
        score_sum += verdict.score as u32;
        results.push(CaseResult {
            id: case.id.clone(),
            output,
            score: verdict.score,
            passed: pass,
            rationale: verdict.rationale,
        });
    }
    let n = cases.len();
    let mean = if n == 0 {
        0
    } else {
        (score_sum / n as u32) as u8
    };
    let pass_rate = if n == 0 {
        0.0
    } else {
        passed as f64 / n as f64
    };
    EvalReport {
        results,
        n,
        passed,
        mean,
        pass_rate,
    }
}

/// The gate policy: absolute floors + a non-inferiority margin vs a baseline.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct GatePolicy {
    /// Minimum acceptable pass-rate (0.0–1.0).
    pub min_pass_rate: f64,
    /// Minimum acceptable mean score (0–100).
    pub min_mean: u8,
    /// Non-inferiority margin (pass-rate points, 0.0–1.0): a new run must be within this of the
    /// baseline's pass-rate, else it is a blocking regression.
    pub noninferiority_margin: f64,
}

impl Default for GatePolicy {
    fn default() -> Self {
        GatePolicy {
            min_pass_rate: 0.9,
            min_mean: 70,
            noninferiority_margin: 0.02,
        }
    }
}

/// The gate decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateOutcome {
    Pass,
    /// Blocked — carries the failing reasons.
    Fail(Vec<String>),
}

impl GateOutcome {
    pub fn is_pass(&self) -> bool {
        matches!(self, GateOutcome::Pass)
    }
}

/// Apply the gate: absolute floors, then non-inferiority vs `baseline` (if provided). Fail-closed and
/// collects every reason so a change author sees all problems at once.
pub fn evaluate_gate(
    report: &EvalReport,
    policy: &GatePolicy,
    baseline: Option<&EvalReport>,
) -> GateOutcome {
    let mut reasons = Vec::new();
    if report.n == 0 {
        return GateOutcome::Fail(vec![
            "empty eval run (no cases) — cannot certify quality".into()
        ]);
    }
    if report.pass_rate < policy.min_pass_rate {
        reasons.push(format!(
            "pass-rate {:.3} below floor {:.3}",
            report.pass_rate, policy.min_pass_rate
        ));
    }
    if report.mean < policy.min_mean {
        reasons.push(format!(
            "mean score {} below floor {}",
            report.mean, policy.min_mean
        ));
    }
    if let Some(base) = baseline {
        if report.pass_rate + policy.noninferiority_margin < base.pass_rate {
            reasons.push(format!(
                "regression: pass-rate {:.3} is more than {:.3} below the baseline {:.3}",
                report.pass_rate, policy.noninferiority_margin, base.pass_rate
            ));
        }
    }
    if reasons.is_empty() {
        GateOutcome::Pass
    } else {
        GateOutcome::Fail(reasons)
    }
}

/// Statistically-valid replacement for the non-inferiority branch of [`evaluate_gate`] (gap [40]).
///
/// [`evaluate_gate`]'s baseline comparison blocks when `candidate.pass_rate + margin < baseline
/// .pass_rate` — aggregate arithmetic that "blocks on coin-flips". This function instead **pairs the
/// two runs by case id** (the default paired eval design) and applies the rigorous per-cell
/// [`stats::statistical_gate`]: a change blocks only when it is worse than baseline by more than
/// `margin` (score points) **at significance after correction**. A null change comes back `Pass`, a
/// genuine regression comes back `Fail`. Cases present in only one run are ignored (they carry no
/// paired signal). This is the drop-in the downstream consumers (`ainxt-prompt`, `ainxt-promptopt`)
/// should call in place of the naive baseline branch.
pub fn evaluate_gate_statistical(
    candidate: &EvalReport,
    baseline: &EvalReport,
    margin: f64,
    alpha: f64,
    q: f64,
) -> GateOutcome {
    use std::collections::BTreeMap;
    if candidate.n == 0 {
        return GateOutcome::Fail(vec![
            "empty eval run (no cases) — cannot certify quality".into()
        ]);
    }
    let base_by_id: BTreeMap<&str, u8> = baseline
        .results
        .iter()
        .map(|r| (r.id.as_str(), r.score))
        .collect();
    let mut diffs = Vec::new();
    for r in &candidate.results {
        if let Some(&b) = base_by_id.get(r.id.as_str()) {
            diffs.push(r.score as f64 - b as f64);
        }
    }
    if diffs.len() < 2 {
        return GateOutcome::Fail(vec![
            "fewer than 2 paired cases — cannot run a statistically-valid non-inferiority test"
                .into(),
        ]);
    }
    let cell = stats::MetricCell {
        name: "quality".into(),
        diffs,
        margin,
        hard_safety: false,
    };
    let report = stats::statistical_gate(&[cell], alpha, q);
    if report.passed() {
        GateOutcome::Pass
    } else {
        GateOutcome::Fail(
            report
                .cells
                .iter()
                .filter(|c| c.blocked)
                .map(|c| {
                    format!(
                        "statistical regression in '{}': effect {:.2} (p={:.4})",
                        c.name, c.effect, c.p_regression
                    )
                })
                .collect(),
        )
    }
}

/// Signature-compatible, **statistically-valid** replacement for [`evaluate_gate`] — the drop-in the
/// keystone's *first consumers* should call so the merge-blocking decision is no longer aggregate
/// pass-rate arithmetic (which "blocks on coin-flips"). The design names those first consumers
/// explicitly: the prompt-registry `EvalDelta` (`ainxt-prompt`, `PROMPT_ENGINEERING.md` §8) and the
/// prompt-optimizer holdout guard (`ainxt-promptopt`, gap AQ). Both currently call [`evaluate_gate`];
/// swapping that single identifier to this function makes their gate the statistically-valid one with
/// no other change.
///
/// It applies the **same absolute floors** as [`evaluate_gate`] (min pass-rate, min mean, empty-run
/// refusal) and replaces ONLY the non-inferiority branch: instead of comparing aggregate pass-rates it
/// **pairs the candidate and baseline reports by case id** and runs the per-cell
/// [`stats::statistical_gate`] via [`evaluate_gate_statistical`]. A null change comes back `Pass`; a
/// genuine regression comes back `Fail`. The policy's `noninferiority_margin` (a pass-rate-point
/// tolerance) is interpreted as a score-point margin (`× 100`, floored at 0.5) for the paired per-case
/// test; `alpha`/`q` default to [`DEFAULT_GATE_ALPHA`]/[`DEFAULT_GATE_Q`].
///
/// When fewer than two paired cases exist the paired test cannot run, so this **falls back to the
/// aggregate arithmetic** of [`evaluate_gate`] — fail-closed on tiny sets, never a silent pass.
pub fn evaluate_gate_statistical_dropin(
    report: &EvalReport,
    policy: &GatePolicy,
    baseline: Option<&EvalReport>,
) -> GateOutcome {
    let mut reasons = Vec::new();
    if report.n == 0 {
        return GateOutcome::Fail(vec![
            "empty eval run (no cases) — cannot certify quality".into()
        ]);
    }
    if report.pass_rate < policy.min_pass_rate {
        reasons.push(format!(
            "pass-rate {:.3} below floor {:.3}",
            report.pass_rate, policy.min_pass_rate
        ));
    }
    if report.mean < policy.min_mean {
        reasons.push(format!(
            "mean score {} below floor {}",
            report.mean, policy.min_mean
        ));
    }
    if let Some(base) = baseline {
        // How many cases are present in BOTH runs (the paired signal the statistical test needs)?
        let base_ids: std::collections::BTreeSet<&str> =
            base.results.iter().map(|r| r.id.as_str()).collect();
        let paired = report
            .results
            .iter()
            .filter(|r| base_ids.contains(r.id.as_str()))
            .count();
        if paired >= 2 {
            // Pass-rate-point tolerance → score-point margin for the paired per-case test.
            let margin_points = (policy.noninferiority_margin * 100.0).max(0.5);
            if let GateOutcome::Fail(rs) = evaluate_gate_statistical(
                report,
                base,
                margin_points,
                DEFAULT_GATE_ALPHA,
                DEFAULT_GATE_Q,
            ) {
                reasons.extend(rs);
            }
        } else if report.pass_rate + policy.noninferiority_margin < base.pass_rate {
            // < 2 paired cases: the paired test cannot run — fall back to the aggregate arithmetic.
            reasons.push(format!(
                "regression: pass-rate {:.3} is more than {:.3} below the baseline {:.3}",
                report.pass_rate, policy.noninferiority_margin, base.pass_rate
            ));
        }
    }
    if reasons.is_empty() {
        GateOutcome::Pass
    } else {
        GateOutcome::Fail(reasons)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A judge that scores by keyword presence (90 if the output contains the case's expected token,
    /// else 20). The expected token is the rubric's last word.
    struct KeywordJudge;
    impl QualityJudge for KeywordJudge {
        fn score(&self, _input: &str, output: &str, criteria: &EvalCriteria) -> QualityScore {
            let needle = criteria.rubric.split_whitespace().last().unwrap_or("");
            if !needle.is_empty() && output.contains(needle) {
                QualityScore {
                    score: 90,
                    rationale: "matched".into(),
                }
            } else {
                QualityScore {
                    score: 20,
                    rationale: format!("missing '{needle}'"),
                }
            }
        }
    }

    /// A system that echoes a fixed answer per input keyword; `broken` toggles a regression.
    struct StubSystem {
        broken: bool,
    }
    impl EvalSystem for StubSystem {
        fn respond(&self, input: &str) -> String {
            if self.broken {
                "sorry, I cannot help".into()
            } else {
                format!("The answer involves {input}")
            }
        }
    }

    fn goldset() -> Vec<EvalCase> {
        vec![
            EvalCase::new("c1", "UPI", "must mention UPI", 60),
            EvalCase::new("c2", "NEFT", "must mention NEFT", 60),
            EvalCase::new("c3", "RTGS", "must mention RTGS", 60),
        ]
    }

    #[test]
    fn run_scores_and_aggregates() {
        let report = run_eval(&goldset(), &StubSystem { broken: false }, &KeywordJudge);
        assert_eq!(report.n, 3);
        assert_eq!(report.passed, 3);
        assert!((report.pass_rate - 1.0).abs() < 1e-9);
        assert_eq!(report.mean, 90);
        assert!(report.results.iter().all(|r| r.passed));
    }

    #[test]
    fn gate_passes_a_good_run_and_fails_a_bad_one() {
        let good = run_eval(&goldset(), &StubSystem { broken: false }, &KeywordJudge);
        assert!(evaluate_gate(&good, &GatePolicy::default(), None).is_pass());

        let bad = run_eval(&goldset(), &StubSystem { broken: true }, &KeywordJudge);
        match evaluate_gate(&bad, &GatePolicy::default(), None) {
            GateOutcome::Fail(reasons) => assert!(reasons.iter().any(|r| r.contains("pass-rate"))),
            GateOutcome::Pass => panic!("a 0%-pass run must fail the gate"),
        }
    }

    #[test]
    fn non_inferiority_blocks_a_regression_vs_baseline() {
        // Baseline: everything passes (pass-rate 1.0).
        let baseline = run_eval(&goldset(), &StubSystem { broken: false }, &KeywordJudge);
        // A candidate that regresses (0% pass) must FAIL non-inferiority even if we relax absolutes.
        let candidate = run_eval(&goldset(), &StubSystem { broken: true }, &KeywordJudge);
        let lax = GatePolicy {
            min_pass_rate: 0.0,
            min_mean: 0,
            noninferiority_margin: 0.02,
        };
        match evaluate_gate(&candidate, &lax, Some(&baseline)) {
            GateOutcome::Fail(reasons) => assert!(reasons.iter().any(|r| r.contains("regression"))),
            GateOutcome::Pass => {
                panic!("a regression vs baseline must be blocked even under lax absolutes")
            }
        }
        // An equal run passes non-inferiority.
        let equal = run_eval(&goldset(), &StubSystem { broken: false }, &KeywordJudge);
        assert!(evaluate_gate(&equal, &lax, Some(&baseline)).is_pass());
    }

    #[test]
    fn empty_run_cannot_certify() {
        let empty = run_eval(&[], &StubSystem { broken: false }, &KeywordJudge);
        assert!(
            !evaluate_gate(&empty, &GatePolicy::default(), None).is_pass(),
            "no cases must not pass the gate"
        );
    }

    #[test]
    fn report_serializes_as_a_baseline() {
        let report = run_eval(&goldset(), &StubSystem { broken: false }, &KeywordJudge);
        let json = serde_json::to_string(&report).unwrap();
        let back: EvalReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back, report);
    }

    #[test]
    fn gap_ainxt_eval_01_statistical_drop_in_replaces_the_coin_flip_gate() {
        // Craft two runs of EQUAL true quality with a tiny non-significant sampling dip: the naive
        // non-inferiority branch blocks (coin-flip bug); the statistical drop-in must NOT block.
        let base: Vec<CaseResult> = (0..120)
            .map(|i| CaseResult {
                id: format!("c{i}"),
                output: String::new(),
                score: if i % 20 == 0 { 61 } else { 80 },
                passed: true,
                rationale: String::new(),
            })
            .collect();
        let cand: Vec<CaseResult> = (0..120)
            .map(|i| CaseResult {
                id: format!("c{i}"),
                output: String::new(),
                score: if i % 20 == 0 { 59 } else { 80 },
                passed: i % 20 != 0,
                rationale: String::new(),
            })
            .collect();
        let mk = |rs: Vec<CaseResult>| {
            let passed = rs.iter().filter(|r| r.passed).count();
            let n = rs.len();
            EvalReport {
                mean: (rs.iter().map(|r| r.score as u32).sum::<u32>() / n as u32) as u8,
                pass_rate: passed as f64 / n as f64,
                passed,
                n,
                results: rs,
            }
        };
        let base_r = mk(base);
        let cand_r = mk(cand);
        // Naive baseline branch blocks this non-significant dip.
        let naive = evaluate_gate(
            &cand_r,
            &GatePolicy {
                min_pass_rate: 0.0,
                min_mean: 0,
                noninferiority_margin: 0.02,
            },
            Some(&base_r),
        );
        assert!(!naive.is_pass(), "naive gate flaps on the tiny dip");
        // Statistically-valid drop-in: no significant regression → Pass.
        assert!(
            evaluate_gate_statistical(&cand_r, &base_r, 2.0, 0.05, 0.05).is_pass(),
            "the statistical drop-in must not flap on non-significant noise"
        );
        // But a genuine 8-point regression across every case must block.
        let reg: Vec<CaseResult> = (0..120)
            .map(|i| CaseResult {
                id: format!("c{i}"),
                output: String::new(),
                score: 72,
                passed: true,
                rationale: String::new(),
            })
            .collect();
        let reg_r = mk(reg);
        assert!(
            !evaluate_gate_statistical(&reg_r, &base_r, 2.0, 0.05, 0.05).is_pass(),
            "a real regression must block the statistical drop-in"
        );
    }

    #[test]
    fn mean_floor_can_fail_independently_of_pass_rate() {
        // A judge that scores everyone at exactly the threshold: pass-rate is high but mean is low.
        struct LowScorer;
        impl QualityJudge for LowScorer {
            fn score(&self, _i: &str, _o: &str, _c: &EvalCriteria) -> QualityScore {
                QualityScore {
                    score: 61,
                    rationale: "barely".into(),
                }
            }
        }
        let report = run_eval(&goldset(), &StubSystem { broken: false }, &LowScorer);
        assert!((report.pass_rate - 1.0).abs() < 1e-9, "all pass (61 >= 60)");
        let policy = GatePolicy {
            min_pass_rate: 0.9,
            min_mean: 70,
            noninferiority_margin: 0.02,
        };
        match evaluate_gate(&report, &policy, None) {
            GateOutcome::Fail(reasons) => assert!(reasons.iter().any(|r| r.contains("mean score"))),
            GateOutcome::Pass => panic!("mean below floor must fail even at 100% pass-rate"),
        }
    }
}
