// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! The **typed pipeline outcome** (`docs/architecture/CODE_REVIEW_PIPELINE.md` §1) — the property
//! that makes "never declare done until the gate succeeds" *structural* rather than a polite prompt.
//!
//! A code-editing turn's success affordance ([`CommitApproval`]) has **no public constructor**. The
//! only way to obtain one is [`PipelineOutcome::commit_approval`], which returns `Some` exclusively
//! for the [`PipelineOutcome::Complete`] variant. A renderer therefore has no code path that emits a
//! "done" / commit affordance without a `Complete` in hand — `Capped` and `Blocked` can only render
//! as an honest gap report. This is the anti-sycophancy invariant expressed in the type system.

use crate::stage::{Stage, StageReport};
use serde::{Deserialize, Serialize};

/// The one and only completion signal for a code-editing turn. Constructed **only** by
/// [`PipelineOutcome::commit_approval`]; the private `seal` field makes it un-forgeable outside this
/// module, so no renderer can synthesize a success without a `Complete` outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitApproval {
    confidence: u8,
    spot_audit: bool,
    seal: (),
}

impl CommitApproval {
    /// The Confidence Score that cleared the gate.
    #[must_use]
    pub fn confidence(&self) -> u8 {
        self.confidence
    }
    /// Whether this commit is flagged for sampled post-commit human spot-audit (the "trust but
    /// verify" tier — `CODE_REVIEW_PIPELINE.md` §8).
    #[must_use]
    pub fn spot_audit(&self) -> bool {
        self.spot_audit
    }
}

/// The typed result of running the pipeline over one edit. There is no fourth "mostly done" variant
/// by design.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum PipelineOutcome {
    /// The gate cleared. Carries the Confidence Score and the full stage report.
    Complete {
        confidence: u8,
        /// Whether the commit is flagged for post-commit spot-audit (score in the review band).
        spot_audit: bool,
        report: Vec<StageReport>,
    },
    /// The self-heal budget (or stuck detector) ran out without clearing the gate. An honest gap
    /// report + human hand-off — NEVER rendered as a soft "done".
    Capped {
        blocking_stage: Stage,
        reason: String,
        rounds_exhausted: u8,
        gap_report: Vec<StageReport>,
    },
    /// A deterministic hard gate failed (a Phase-A failure, or a SAST critical/high). The score is
    /// irrelevant; there is no commit.
    Blocked {
        stage: Stage,
        deterministic_failure: String,
    },
}

impl PipelineOutcome {
    /// The commit affordance — `Some` **iff** this is a `Complete`. The sole path to a success token.
    #[must_use]
    pub fn commit_approval(&self) -> Option<CommitApproval> {
        match self {
            PipelineOutcome::Complete {
                confidence,
                spot_audit,
                ..
            } => Some(CommitApproval {
                confidence: *confidence,
                spot_audit: *spot_audit,
                seal: (),
            }),
            _ => None,
        }
    }

    #[must_use]
    pub fn is_complete(&self) -> bool {
        matches!(self, PipelineOutcome::Complete { .. })
    }

    /// The stage that owns this outcome (for the journal / renderer).
    #[must_use]
    pub fn stage(&self) -> Stage {
        match self {
            PipelineOutcome::Complete { .. } => Stage::CommitGate,
            PipelineOutcome::Capped { blocking_stage, .. } => *blocking_stage,
            PipelineOutcome::Blocked { stage, .. } => *stage,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stage::Stage;

    #[test]
    fn only_complete_yields_a_commit_approval() {
        let complete = PipelineOutcome::Complete {
            confidence: 92,
            spot_audit: false,
            report: vec![],
        };
        let capped = PipelineOutcome::Capped {
            blocking_stage: Stage::Regression,
            reason: "uncovered call sites".into(),
            rounds_exhausted: 5,
            gap_report: vec![],
        };
        let blocked = PipelineOutcome::Blocked {
            stage: Stage::Sast,
            deterministic_failure: "hard-coded secret".into(),
        };

        let approval = complete.commit_approval().expect("Complete must approve");
        assert_eq!(approval.confidence(), 92);
        // The ONLY paths to a success token are closed for the non-Complete variants.
        assert!(capped.commit_approval().is_none());
        assert!(blocked.commit_approval().is_none());
        assert!(complete.is_complete());
        assert!(!capped.is_complete());
    }

    #[test]
    fn outcome_serde_round_trips_tagged() {
        let o = PipelineOutcome::Blocked {
            stage: Stage::Compile,
            deterministic_failure: "E0433".into(),
        };
        let json = serde_json::to_string(&o).unwrap();
        assert!(json.contains("\"outcome\":\"blocked\""));
        assert_eq!(serde_json::from_str::<PipelineOutcome>(&json).unwrap(), o);
    }
}
