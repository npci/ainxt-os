// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! The **Commit Gate** (`docs/architecture/CODE_REVIEW_PIPELINE.md` §8) — the policy decision that
//! consumes the Confidence Score plus every hard gate and yields the typed decision.
//!
//! The ordering is exact and non-negotiable: Phase-A failures, then SAST critical/high, then
//! architecture violations, hard-block *before* the score is even consulted (a critical secret leak
//! at Confidence 100 still does not commit). Only then does the score decide, and Tier 3 forces a
//! human regardless of how good the score looks.

use crate::confidence::ConfidenceScore;
use crate::risk::RiskTier;
use crate::sast::{hard_block, SastFinding};
use crate::stage::Stage;
use serde::{Deserialize, Serialize};

/// The tunable thresholds. Defaults follow the design's illustrative values (§8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatePolicy {
    /// Score at/above which an edit auto-completes (Judge, if run, must also approve).
    pub auto_complete_threshold: u8,
    /// Score at/above which an edit completes but is flagged for post-commit spot-audit.
    pub review_threshold: u8,
    /// **Trivial auto-approve floor** (`CODE_REVIEW_PIPELINE.md` §3/§8). A [`RiskTier::Trivial`]
    /// edit (doc/comment/formatting only, zero blast radius) that clears every deterministic hard
    /// gate auto-completes at/above this floor **without** a spot-audit — so a docstring typo does
    /// not get dragged through the full review band and train users to distrust the gate. The floor
    /// is well below `review_threshold` but never zero: a trivial edit that somehow scores beneath
    /// it (e.g. many honestly-skipped stages) still falls through to the normal bands. It NEVER
    /// bypasses a hard gate — a SAST/Phase-A/architecture block still stops a trivial edit cold.
    pub trivial_auto_approve_floor: u8,
}

impl Default for GatePolicy {
    fn default() -> Self {
        GatePolicy {
            auto_complete_threshold: 90,
            review_threshold: 70,
            trivial_auto_approve_floor: 60,
        }
    }
}

/// Everything the gate needs beyond the score.
#[derive(Debug, Clone)]
pub struct GateContext<'a> {
    pub tier: RiskTier,
    /// Any unresolved Phase-A (compile/test/lint/type) failure — `Some(stage, detail)` blocks.
    pub phase_a_failure: Option<(Stage, String)>,
    pub sast: &'a [SastFinding],
    /// Unremediated deterministic architecture boundary violations.
    pub architecture_violations: u32,
    /// Whether the Judge ran and approved. `None` = did not run (allowed only below Tier 2 per §5).
    pub judge_approved: Option<bool>,
    /// Whether `judge_approved` came from a **genuine, context-isolated independent Judge panel**
    /// (`CODE_REVIEW_PIPELINE.md` §5 — the panel scores the candidate on its own, never seeing the
    /// coder's self-summary). This is the *provenance* of the verdict, not its value: a real
    /// [`ainxt_judge::JudgePanel`] run sets it `true`; a caller self-asserting `judge_approved =
    /// Some(true)` with no panel behind it leaves it `false`. At Tier 2+ the Commit Gate requires
    /// `true` — a self-graded "done" (one-sided approval) is exactly what §5's independence rule
    /// forbids and can never satisfy the mandatory-Judge gate.
    pub judge_independent: bool,
}

/// The gate's decision. `RequiresHitl` and `Blocked`/`Capped` never carry a commit affordance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum GateDecision {
    /// A deterministic hard gate failed; no score computed.
    Blocked {
        stage: Stage,
        deterministic_failure: String,
    },
    /// Tier 3 / critical-path: commit needs a human even at a perfect score.
    RequiresHitl { score: u8, judge_ran: bool },
    /// The gate cleared. `spot_audit` marks the "trust but verify" band.
    Complete { score: u8, spot_audit: bool },
    /// Score below the review band, or the Judge withheld approval — hand to human, keep self-healing.
    Capped {
        blocking_stage: Stage,
        reason: String,
        score: u8,
    },
}

/// Decide. `score` is the already-computed Confidence Score (only meaningful once hard gates clear).
#[must_use]
pub fn decide(ctx: &GateContext, score: &ConfidenceScore, policy: GatePolicy) -> GateDecision {
    // 1. Phase-A failures block before scoring.
    if let Some((stage, detail)) = &ctx.phase_a_failure {
        return GateDecision::Blocked {
            stage: *stage,
            deterministic_failure: detail.clone(),
        };
    }
    // 2. SAST critical/high hard-block regardless of score.
    if let Some(f) = hard_block(ctx.sast) {
        return GateDecision::Blocked {
            stage: Stage::Sast,
            deterministic_failure: format!(
                "{} ({:?}) at {}:{}",
                f.rule, f.severity, f.file, f.line
            ),
        };
    }
    // 3. Architecture boundary violations block.
    if ctx.architecture_violations > 0 {
        return GateDecision::Blocked {
            stage: Stage::Architecture,
            deterministic_failure: format!(
                "{} unremediated boundary violation(s)",
                ctx.architecture_violations
            ),
        };
    }

    let s = score.score;

    // 4. Tier 3 forces HITL even at a perfect score.
    if ctx.tier.forces_hitl() {
        return GateDecision::RequiresHitl {
            score: s,
            judge_ran: ctx.judge_approved.is_some(),
        };
    }

    // 4b. **Independent Judge is MANDATORY at Tier 2+** (`CODE_REVIEW_PIPELINE.md` §5: the Judge is
    // "mandatory at Tier 2+ and always at Tier 3"; the §3 tier table gives Tier 2 the Judge stage).
    // Tier 3 is already a forced HITL above; this closes Tier 2 (`Moderate`): a multi-file /
    // signature-changing edit is **not committable** without a genuine, context-isolated independent
    // panel verdict. Both failure shapes cap to an honest human hand-off — the Confidence Score cannot
    // buy the missing adjudication back (a self-graded "done" is precisely §5's forbidden case):
    //   • ABSENT   — no panel ran (`judge_approved.is_none()`).
    //   • ONE-SIDED — an approval that did not come from a context-isolated independent panel
    //     (`judge_independent == false`), e.g. a caller self-asserting `judge_approved = Some(true)`.
    // The shipped daemon wires a real Judge panel (`EditEngine::with_review`), whose context-isolated
    // strict-majority consensus is the only thing that satisfies this gate for a Tier-2+ edit.
    if ctx.tier >= RiskTier::Moderate && !(ctx.judge_approved.is_some() && ctx.judge_independent) {
        let reason = if ctx.judge_approved.is_none() {
            "independent Judge mandatory at Tier 2+ (§5/§8): no panel verdict present".to_string()
        } else {
            "independent Judge mandatory at Tier 2+ (§5/§8): approval is not from a \
             context-isolated independent panel (one-sided / self-asserted)"
                .to_string()
        };
        return GateDecision::Capped {
            blocking_stage: Stage::CommitGate,
            reason,
            score: s,
        };
    }

    // A Judge that ran must have approved (folded into every score-band decision below). Below Tier 2
    // a missing Judge is allowed (`None` ⇒ `true`); at Tier 2+ the mandatory-Judge gate above has
    // already guaranteed a present, independent verdict, so this reflects its real consensus value.
    let judge_ok = ctx.judge_approved.unwrap_or(true);

    // 5. Trivial auto-approve floor. A doc/comment-only edit with zero blast radius that cleared
    // every hard gate above auto-completes (no spot-audit) at/above the floor — so a docstring typo
    // does not get dragged through the full review band. Hard gates already ran; this only relaxes
    // the *score-band* decision, and only for Tier 0.
    if ctx.tier == RiskTier::Trivial && judge_ok && s >= policy.trivial_auto_approve_floor {
        return GateDecision::Complete {
            score: s,
            spot_audit: false,
        };
    }

    // 6. Score-driven decision. Any Tier-2+ edit that reaches here carries a present, independent Judge
    //    verdict (enforced in 4b), so a high score auto-completes with no spot-audit.
    if s >= policy.auto_complete_threshold && judge_ok {
        GateDecision::Complete {
            score: s,
            spot_audit: false,
        }
    } else if s >= policy.review_threshold && judge_ok {
        GateDecision::Complete {
            score: s,
            spot_audit: true,
        }
    } else {
        let reason = if !judge_ok {
            "Judge withheld approval".to_string()
        } else {
            format!("Confidence Score {s} below review threshold")
        };
        GateDecision::Capped {
            blocking_stage: Stage::CommitGate,
            reason,
            score: s,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sast::Severity;

    fn score(n: u8) -> ConfidenceScore {
        ConfidenceScore {
            score: n,
            breakdown: vec![],
        }
    }

    fn clean_ctx() -> GateContext<'static> {
        GateContext {
            tier: RiskTier::Local,
            phase_a_failure: None,
            sast: &[],
            architecture_violations: 0,
            judge_approved: None,
            judge_independent: false,
        }
    }

    #[test]
    fn phase_a_failure_blocks_before_scoring() {
        let mut ctx = clean_ctx();
        ctx.phase_a_failure = Some((Stage::Compile, "E0433".into()));
        // Even a perfect score cannot rescue a broken build.
        assert!(matches!(
            decide(&ctx, &score(100), GatePolicy::default()),
            GateDecision::Blocked {
                stage: Stage::Compile,
                ..
            }
        ));
    }

    #[test]
    fn sast_critical_blocks_at_score_100() {
        let findings = vec![SastFinding {
            rule: "hardcoded-secret".into(),
            severity: Severity::Critical,
            file: "k.rs".into(),
            line: 3,
            evidence: "".into(),
        }];
        let mut ctx = clean_ctx();
        ctx.sast = &findings;
        // The §11 scenario: hard-blocked at Confidence 100 with the exact rule named.
        match decide(&ctx, &score(100), GatePolicy::default()) {
            GateDecision::Blocked {
                stage: Stage::Sast,
                deterministic_failure,
            } => assert!(deterministic_failure.contains("hardcoded-secret")),
            other => panic!("expected SAST block, got {other:?}"),
        }
    }

    #[test]
    fn tier_3_requires_hitl_even_at_100() {
        let mut ctx = clean_ctx();
        ctx.tier = RiskTier::HighRisk;
        ctx.judge_approved = Some(true);
        assert_eq!(
            decide(&ctx, &score(100), GatePolicy::default()),
            GateDecision::RequiresHitl {
                score: 100,
                judge_ran: true
            }
        );
    }

    #[test]
    fn high_score_auto_completes() {
        assert_eq!(
            decide(&clean_ctx(), &score(95), GatePolicy::default()),
            GateDecision::Complete {
                score: 95,
                spot_audit: false
            }
        );
    }

    #[test]
    fn review_band_completes_with_spot_audit() {
        assert_eq!(
            decide(&clean_ctx(), &score(75), GatePolicy::default()),
            GateDecision::Complete {
                score: 75,
                spot_audit: true
            }
        );
    }

    #[test]
    fn below_review_band_caps() {
        assert!(matches!(
            decide(&clean_ctx(), &score(50), GatePolicy::default()),
            GateDecision::Capped { .. }
        ));
    }

    #[test]
    fn judge_disapproval_caps_even_at_high_score() {
        let mut ctx = clean_ctx();
        ctx.judge_approved = Some(false);
        match decide(&ctx, &score(99), GatePolicy::default()) {
            GateDecision::Capped { reason, .. } => assert!(reason.contains("Judge")),
            other => panic!("expected Capped, got {other:?}"),
        }
    }

    #[test]
    fn trivial_edit_auto_approves_below_the_review_band_without_spot_audit() {
        let mut ctx = clean_ctx();
        ctx.tier = RiskTier::Trivial;
        // 65 is below the 70 review band — a Local edit would be Capped here...
        assert!(matches!(
            decide(&clean_ctx(), &score(65), GatePolicy::default()),
            GateDecision::Capped { .. }
        ));
        // ...but a Trivial edit auto-completes at/above the floor (60), with NO spot-audit.
        assert_eq!(
            decide(&ctx, &score(65), GatePolicy::default()),
            GateDecision::Complete {
                score: 65,
                spot_audit: false
            }
        );
    }

    #[test]
    fn trivial_floor_never_bypasses_a_hard_gate() {
        // A trivial edit that still leaks a secret is hard-blocked — the floor only relaxes the
        // score band, never a deterministic gate.
        let findings = vec![SastFinding {
            rule: "hardcoded-secret".into(),
            severity: Severity::Critical,
            file: "k.rs".into(),
            line: 1,
            evidence: "".into(),
        }];
        let mut ctx = clean_ctx();
        ctx.tier = RiskTier::Trivial;
        ctx.sast = &findings;
        assert!(matches!(
            decide(&ctx, &score(100), GatePolicy::default()),
            GateDecision::Blocked {
                stage: Stage::Sast,
                ..
            }
        ));
    }

    #[test]
    fn trivial_edit_beneath_the_floor_falls_through_to_normal_bands() {
        let mut ctx = clean_ctx();
        ctx.tier = RiskTier::Trivial;
        // Below the 60 floor: even a trivial edit is not rubber-stamped.
        assert!(matches!(
            decide(&ctx, &score(50), GatePolicy::default()),
            GateDecision::Capped { .. }
        ));
    }

    #[test]
    fn tier2_without_any_judge_verdict_is_not_committable() {
        // §5/§8: a Tier-2 (Moderate) edit with NO panel verdict caps — even at a perfect score it is
        // never Complete. This is the round-13 tightening of the round-12 "spot-audit band" compromise.
        let mut ctx = clean_ctx();
        ctx.tier = RiskTier::Moderate;
        // judge_approved: None (absent), judge_independent: false.
        match decide(&ctx, &score(100), GatePolicy::default()) {
            GateDecision::Capped {
                reason,
                blocking_stage,
                ..
            } => {
                assert_eq!(blocking_stage, Stage::CommitGate);
                assert!(reason.contains("mandatory at Tier 2+") && reason.contains("no panel"));
            }
            other => panic!("expected Capped (no judge at Tier 2+), got {other:?}"),
        }
    }

    #[test]
    fn tier2_one_sided_self_asserted_approval_is_not_committable() {
        // A caller self-asserting approval with NO independent panel behind it (judge_independent =
        // false) is "one-sided" and does not satisfy the mandate — capped regardless of score.
        let mut ctx = clean_ctx();
        ctx.tier = RiskTier::Moderate;
        ctx.judge_approved = Some(true); // asserted...
        ctx.judge_independent = false; // ...but not from a context-isolated panel.
        match decide(&ctx, &score(100), GatePolicy::default()) {
            GateDecision::Capped { reason, .. } => {
                assert!(reason.contains("one-sided") || reason.contains("context-isolated"));
            }
            other => panic!("expected Capped (one-sided judge at Tier 2+), got {other:?}"),
        }
    }

    #[test]
    fn tier2_with_independent_panel_approval_auto_completes() {
        // The shipped shape: a genuine context-isolated panel approved → auto-completes, no spot-audit.
        let mut ctx = clean_ctx();
        ctx.tier = RiskTier::Moderate;
        ctx.judge_approved = Some(true);
        ctx.judge_independent = true;
        assert_eq!(
            decide(&ctx, &score(95), GatePolicy::default()),
            GateDecision::Complete {
                score: 95,
                spot_audit: false
            }
        );
    }

    #[test]
    fn tier2_with_independent_panel_disapproval_caps() {
        // An independent panel that WITHHELD approval caps regardless of score (§5: a gate on top of
        // the score, not a term it can buy back).
        let mut ctx = clean_ctx();
        ctx.tier = RiskTier::Moderate;
        ctx.judge_approved = Some(false);
        ctx.judge_independent = true;
        match decide(&ctx, &score(99), GatePolicy::default()) {
            GateDecision::Capped { reason, .. } => assert!(reason.contains("Judge")),
            other => panic!("expected Capped, got {other:?}"),
        }
    }

    #[test]
    fn architecture_violation_blocks() {
        let mut ctx = clean_ctx();
        ctx.architecture_violations = 1;
        assert!(matches!(
            decide(&ctx, &score(100), GatePolicy::default()),
            GateDecision::Blocked {
                stage: Stage::Architecture,
                ..
            }
        ));
    }
}
