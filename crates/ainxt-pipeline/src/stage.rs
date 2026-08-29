// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Pipeline **stages** and their verdicts (`docs/architecture/CODE_REVIEW_PIPELINE.md` §4).
//!
//! The honesty rule that runs through the whole design lives here: a `Skipped(reason)` is a
//! first-class verdict, **never** silently treated as a pass. A missing tool must not masquerade as
//! a green check — [`StageVerdict::Skipped`] feeds the Confidence Score's skip penalty (§7) and, for
//! whole languages with no tooling, forces the report to say "manual review required" (§10).

use serde::{Deserialize, Serialize};

/// The twelve stages, in canonical order. `Ord` follows the pipeline order so a "blocking stage"
/// comparison is meaningful.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    /// Register the applied edit set (diff, rung-per-file, blast radius).
    Generate,
    Compile,
    Test,
    Lint,
    TypeCheck,
    Sast,
    Perf,
    Architecture,
    Regression,
    LlmReview,
    Confidence,
    CommitGate,
}

impl Stage {
    /// The Phase-A deterministic stages (1–5): an unresolved failure here blocks before scoring.
    #[must_use]
    pub fn is_phase_a(self) -> bool {
        matches!(
            self,
            Stage::Compile | Stage::Test | Stage::Lint | Stage::TypeCheck | Stage::Sast
        )
    }
}

/// The verdict of one stage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum StageVerdict {
    /// The stage ran and passed.
    Pass,
    /// The stage ran and produced a gating failure.
    Fail { detail: String },
    /// The stage could not run (no tool for this language). NOT a pass — carries the reason.
    Skipped { reason: String },
    /// The stage produced non-gating findings (e.g. an advisory perf estimate).
    Advisory { detail: String },
}

impl StageVerdict {
    #[must_use]
    pub fn is_pass(&self) -> bool {
        matches!(self, StageVerdict::Pass)
    }
    #[must_use]
    pub fn is_fail(&self) -> bool {
        matches!(self, StageVerdict::Fail { .. })
    }
    #[must_use]
    pub fn is_skipped(&self) -> bool {
        matches!(self, StageVerdict::Skipped { .. })
    }
}

/// One stage's structured report entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StageReport {
    pub stage: Stage,
    pub verdict: StageVerdict,
    /// Whether this stage's verdict was decided by a deterministic tool (vs. model judgment).
    pub deterministic: bool,
}

impl StageReport {
    #[must_use]
    pub fn pass(stage: Stage, deterministic: bool) -> Self {
        StageReport {
            stage,
            verdict: StageVerdict::Pass,
            deterministic,
        }
    }
    #[must_use]
    pub fn fail(stage: Stage, deterministic: bool, detail: impl Into<String>) -> Self {
        StageReport {
            stage,
            verdict: StageVerdict::Fail {
                detail: detail.into(),
            },
            deterministic,
        }
    }
    #[must_use]
    pub fn skipped(stage: Stage, reason: impl Into<String>) -> Self {
        StageReport {
            stage,
            verdict: StageVerdict::Skipped {
                reason: reason.into(),
            },
            deterministic: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase_a_membership_is_exactly_stages_1_to_5() {
        assert!(Stage::Compile.is_phase_a());
        assert!(Stage::Sast.is_phase_a());
        assert!(!Stage::Perf.is_phase_a());
        assert!(!Stage::CommitGate.is_phase_a());
    }

    #[test]
    fn stage_ordering_matches_pipeline_order() {
        assert!(Stage::Compile < Stage::Sast);
        assert!(Stage::Sast < Stage::CommitGate);
    }

    #[test]
    fn skipped_is_not_a_pass() {
        let s = StageReport::skipped(Stage::TypeCheck, "no typechecker");
        assert!(s.verdict.is_skipped());
        assert!(!s.verdict.is_pass());
    }

    #[test]
    fn verdict_serde_round_trips() {
        let v = StageVerdict::Fail {
            detail: "boom".into(),
        };
        let json = serde_json::to_string(&v).unwrap();
        assert_eq!(serde_json::from_str::<StageVerdict>(&json).unwrap(), v);
    }
}
