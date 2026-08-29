// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! The **Confidence Score** (`docs/architecture/CODE_REVIEW_PIPELINE.md` §7) — a computed function
//! over every prior stage's structured output, answering "given that everything deterministic
//! passed, how much residual risk remains?".
//!
//! Two anti-sycophancy properties are load-bearing and enforced here, not incidental:
//! 1. **The Judge's verdict is not an input to the arithmetic.** It is a gate *on top of* the score
//!    (see [`crate::gate`]); no term in this function can be inflated by model judgment.
//! 2. **A skip is a penalty, not neutral** — otherwise the cheapest route to a high score is "run
//!    fewer checks", exactly backwards.
//!
//! The score is returned with its **full breakdown** (every deduction), because an opaque "87/100"
//! is not auditable and a reviewer two years later needs to see *why* 87.

use crate::sast::{SastFinding, Severity};
use ainxt_judge::{ReviewFinding, ReviewSeverity};
use ainxt_semantic::ladder::Rung;
use serde::{Deserialize, Serialize};

/// The structured inputs to the score. Critical/high SAST findings are NOT passed here — they
/// hard-block before scoring ([`crate::gate`]); only medium/low are scored.
#[derive(Debug, Clone)]
pub struct ConfidenceInputs<'a> {
    pub sast: &'a [SastFinding],
    /// 0..=25, scaled to how far a benchmark regression went over budget; 0 if no benchmark ran.
    pub perf_regression_penalty: u8,
    /// Number of unremediated deterministic architecture boundary violations.
    pub architecture_violations: u32,
    /// Fraction `[0,1]` of the blast radius covered by tests.
    pub blast_radius_test_coverage: f64,
    /// Unresolved LLM Review findings (severity-weighted, capped).
    pub review_findings: &'a [ReviewFinding],
    /// The number of stages that returned `Skipped(no_tool)` rather than a real verdict.
    pub skipped_stages: u32,
    /// The lowest (least-trusted) edit-engine rung used across the edit set.
    pub rung: Rung,
}

/// The score plus its full, auditable breakdown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidenceScore {
    pub score: u8,
    /// One human-readable line per deduction, in application order.
    pub breakdown: Vec<String>,
}

const REVIEW_CAP: u32 = 30;
const SAST_CAP: u32 = 40;

fn review_penalty(sev: ReviewSeverity) -> u32 {
    match sev {
        ReviewSeverity::Critical => 10,
        ReviewSeverity::Major => 6,
        ReviewSeverity::Minor => 3,
        ReviewSeverity::Info => 2,
    }
}

/// Compute the Confidence Score. Deterministic; the Judge verdict is deliberately absent.
#[must_use]
pub fn compute(inp: &ConfidenceInputs) -> ConfidenceScore {
    let mut score: i64 = 100;
    let mut breakdown = Vec::new();

    // SAST medium/low (critical/high hard-block elsewhere and must not be here).
    let mut sast_pen: u32 = 0;
    for f in inp.sast {
        if matches!(f.severity, Severity::Medium | Severity::Low) {
            sast_pen += f.severity.score_penalty();
        }
    }
    sast_pen = sast_pen.min(SAST_CAP);
    if sast_pen > 0 {
        score -= sast_pen as i64;
        breakdown.push(format!(
            "-{sast_pen} SAST medium/low findings (capped {SAST_CAP})"
        ));
    }

    // Performance regression.
    let perf = inp.perf_regression_penalty.min(25) as i64;
    if perf > 0 {
        score -= perf;
        breakdown.push(format!("-{perf} performance regression over budget"));
    }

    // Architecture boundary violations.
    if inp.architecture_violations > 0 {
        let pen = (inp.architecture_violations * 15) as i64;
        score -= pen;
        breakdown.push(format!(
            "-{pen} {} unremediated architecture boundary violation(s)",
            inp.architecture_violations
        ));
    }

    // Regression risk = 30 * (1 - coverage).
    let coverage = inp.blast_radius_test_coverage.clamp(0.0, 1.0);
    let reg = (30.0 * (1.0 - coverage)).round() as i64;
    if reg > 0 {
        score -= reg;
        breakdown.push(format!(
            "-{reg} regression risk ({:.0}% of blast radius uncovered)",
            (1.0 - coverage) * 100.0
        ));
    }

    // Unresolved LLM Review findings (severity-weighted, capped).
    let mut review_pen: u32 = 0;
    for f in inp.review_findings {
        review_pen += review_penalty(f.severity);
    }
    review_pen = review_pen.min(REVIEW_CAP);
    if review_pen > 0 {
        score -= review_pen as i64;
        breakdown.push(format!(
            "-{review_pen} unresolved review findings (capped {REVIEW_CAP})"
        ));
    }

    // Skipped-stage penalty — a skip is never free.
    if inp.skipped_stages > 0 {
        let pen = (inp.skipped_stages * 5) as i64;
        score -= pen;
        breakdown.push(format!(
            "-{pen} {} stage(s) skipped for want of tooling",
            inp.skipped_stages
        ));
    }

    // Edit-engine rung adjustment.
    let rung_pen = inp.rung.confidence_penalty() as i64;
    if rung_pen > 0 {
        score -= rung_pen;
        breakdown.push(format!(
            "-{rung_pen} {} rung edit (lower fidelity)",
            inp.rung.as_str()
        ));
    }

    let clamped = score.clamp(0, 100) as u8;
    if breakdown.is_empty() {
        breakdown.push("no deductions".to_string());
    }
    ConfidenceScore {
        score: clamped,
        breakdown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs() -> ConfidenceInputs<'static> {
        ConfidenceInputs {
            sast: &[],
            perf_regression_penalty: 0,
            architecture_violations: 0,
            blast_radius_test_coverage: 1.0,
            review_findings: &[],
            skipped_stages: 0,
            rung: Rung::Ast,
        }
    }

    #[test]
    fn perfect_edit_scores_100() {
        let s = compute(&inputs());
        assert_eq!(s.score, 100);
        assert_eq!(s.breakdown, vec!["no deductions".to_string()]);
    }

    #[test]
    fn uncovered_blast_radius_caps_the_score_even_when_all_gates_pass() {
        // 40% uncovered → -12; the §11 scenario "tests green but 40% uncovered".
        let mut i = inputs();
        i.blast_radius_test_coverage = 0.6;
        let s = compute(&i);
        assert_eq!(s.score, 88);
        assert!(s.breakdown.iter().any(|b| b.contains("regression risk")));
    }

    #[test]
    fn a_skip_is_strictly_worse_than_ran_and_passed() {
        let mut with_skip = inputs();
        with_skip.skipped_stages = 2;
        assert_eq!(compute(&with_skip).score, 90); // -5 each
        assert!(compute(&with_skip).score < compute(&inputs()).score);
    }

    #[test]
    fn text_patch_rung_costs_more_than_ast() {
        let mut i = inputs();
        i.rung = Rung::TextPatch;
        assert_eq!(compute(&i).score, 92); // -8
    }

    #[test]
    fn medium_sast_is_scored_but_high_is_not_expected_here() {
        let findings = vec![SastFinding {
            rule: "x".into(),
            severity: Severity::Medium,
            file: "a".into(),
            line: 1,
            evidence: "".into(),
        }];
        let mut i = inputs();
        i.sast = &findings;
        assert_eq!(compute(&i).score, 92); // -8 medium
    }

    #[test]
    fn review_findings_are_capped() {
        let many: Vec<ReviewFinding> = (0..20)
            .map(|_| ReviewFinding {
                severity: ReviewSeverity::Critical,
                lines: vec![1],
                message: "concrete failure mode".into(),
            })
            .collect();
        let mut i = inputs();
        i.review_findings = &many;
        // 20 * 10 = 200 but capped at 30.
        assert_eq!(compute(&i).score, 70);
    }

    #[test]
    fn score_clamps_at_zero() {
        let mut i = inputs();
        i.perf_regression_penalty = 25;
        i.architecture_violations = 10; // -150
        i.blast_radius_test_coverage = 0.0; // -30
        assert_eq!(compute(&i).score, 0);
    }

    #[test]
    fn breakdown_is_present_for_every_deduction() {
        let mut i = inputs();
        i.perf_regression_penalty = 10;
        i.skipped_stages = 1;
        let s = compute(&i);
        assert!(s.breakdown.iter().any(|b| b.contains("performance")));
        assert!(s.breakdown.iter().any(|b| b.contains("skipped")));
    }
}
