// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-12 — **the independent Judge is enforced at Tier 2** (`CODE_REVIEW_PIPELINE.md` §5: the
//! Judge is "mandatory at Tier 2+ and always at Tier 3"; §3 tier table gives Tier 2 the Judge stage).
//!
//! The gap: the Commit Gate treated a *missing* Judge verdict as `judge_ok = true`
//! (`judge_approved.unwrap_or(true)`), so a Tier-2 edit (multi-file / signature change) with **no
//! independent completion adjudication** silently auto-completed at a high score. Round-12 closes it:
//! at Tier 2+ with no Judge verdict the edit is **never silently auto-approved** — even at a perfect
//! score it can at most reach the human spot-audit band; and a Judge that *withheld* approval still
//! caps the turn regardless of score. The shipped daemon wires a real Judge panel so a served Tier-2
//! edit is actually adjudicated; this proves the gate is the fail-safe when the seam is absent.

use ainxt_judge::{
    CoderSubmission, Judge, JudgeCriteria, JudgePanel, JudgeVerdict, ReviewFinding, Reviewer,
};
use ainxt_pipeline::journal::Journal;
use ainxt_pipeline::sast::BuiltinScanner;
use ainxt_pipeline::stages::ScriptedTools;
use ainxt_pipeline::{
    Coder, EditEngine, EditTurn, Observation, RiskTier, SelfHealConfig, TurnOutcome,
};
use ainxt_semantic::workspace::MemorySink;
use std::sync::Arc;

struct NoOpCoder;
impl Coder for NoOpCoder {
    fn fix(&self, _r: u8, files: &[(String, String)], _o: &Observation) -> Vec<(String, String)> {
        files.to_vec()
    }
}

/// A one-judge panel with a fixed verdict, to drive the gate's `judge_approved` deterministically.
struct FixedJudge {
    approve: bool,
}
impl Judge for FixedJudge {
    fn id(&self) -> &str {
        "fixed"
    }
    fn score(&self, _c: &str, _cr: &JudgeCriteria) -> JudgeVerdict {
        JudgeVerdict {
            judge: "fixed".into(),
            score: if self.approve { 95 } else { 10 },
            passed: self.approve,
            notes: "fixed".into(),
        }
    }
}

/// An LLM-Review finder that finds nothing (so the Confidence Score stays high and the *only* thing
/// deciding the outcome is the Judge verdict, not review findings).
struct QuietReviewer;
impl Reviewer for QuietReviewer {
    fn review(&self, _s: &CoderSubmission, _t: &str) -> Vec<ReviewFinding> {
        Vec::new()
    }
}

fn moderate_cfg() -> SelfHealConfig {
    SelfHealConfig {
        lang: ainxt_pipeline::Language::Rust,
        // A floor of Local; the two-file edit below escalates the classifier to Tier 2 (Moderate) on
        // its own (files_touched > 1), exactly as a real multi-file edit would.
        tier: RiskTier::Local,
        max_rounds: 2,
        ..Default::default()
    }
}

/// A clean, parseable **two-file** edit → the deterministic classifier escalates it to Tier 2.
fn tier2_turn(id: &str) -> EditTurn {
    EditTurn {
        edit_id: id.into(),
        original_files: vec![
            ("a.rs".into(), "fn a() -> i32 {\n    1\n}\n".into()),
            ("b.rs".into(), "fn b() -> i32 {\n    1\n}\n".into()),
        ],
        applied_files: vec![
            ("a.rs".into(), "fn a() -> i32 {\n    2\n}\n".into()),
            ("b.rs".into(), "fn b() -> i32 {\n    2\n}\n".into()),
        ],
        config: moderate_cfg(),
    }
}

#[test]
fn r12_tier2_without_judge_never_silently_auto_completes() {
    // No `.with_review(...)` → no Judge verdict reaches the gate. Round-12 allowed this to commit in
    // the human spot-audit band; round-13 tightens it to the design's actual mandate (§5/§8: the Judge
    // is "mandatory at Tier 2+"): with no independent panel verdict a Tier-2 edit is NOT committable at
    // all — even at a perfect score it caps to an honest human hand-off. "Never silently auto-completes"
    // now holds in its strongest form: it does not commit.
    let engine = EditEngine::new(
        Arc::new(NoOpCoder),
        Arc::new(ScriptedTools::default()),
        Arc::new(BuiltinScanner),
    );
    let mut sink = MemorySink::new();
    let mut j = Journal::new("r12-t2-nojudge");
    let out = engine.run_turn(tier2_turn("r12-t2-nojudge"), &mut sink, &mut j);
    assert!(
        !out.committed(),
        "a Tier-2 edit with no independent Judge verdict must NOT commit (§5/§8 mandatory Judge), \
         got {out:?}"
    );
}

#[test]
fn r12_tier2_with_approving_judge_auto_completes() {
    // The shipped-daemon shape: a real Judge panel wired in. An approving verdict at a clean high score
    // clears the auto-complete band with NO spot-audit — the Judge did its job.
    let panel = Arc::new(JudgePanel::new(vec![Box::new(FixedJudge {
        approve: true,
    })]));
    let engine = EditEngine::new(
        Arc::new(NoOpCoder),
        Arc::new(ScriptedTools::default()),
        Arc::new(BuiltinScanner),
    )
    .with_review(
        Arc::new(QuietReviewer),
        panel,
        JudgeCriteria {
            goal: "edit a+b".into(),
            threshold: 60,
        },
        "edit a+b",
    );
    let mut sink = MemorySink::new();
    let mut j = Journal::new("r12-t2-approve");
    let out = engine.run_turn(tier2_turn("r12-t2-approve"), &mut sink, &mut j);
    match out {
        TurnOutcome::Committed { approval, .. } => {
            assert!(
                !approval.spot_audit(),
                "an independently-adjudicated (approved) Tier-2 edit auto-completes without spot-audit"
            );
        }
        other => panic!("expected a clean adjudicated commit, got {other:?}"),
    }
}

#[test]
fn r12_tier2_with_disapproving_judge_is_capped() {
    // A Judge that withheld approval caps the turn regardless of how high the Confidence Score is — the
    // completion adjudication is a gate ON TOP of the score, never a term the score can buy back (§5).
    let panel = Arc::new(JudgePanel::new(vec![Box::new(FixedJudge {
        approve: false,
    })]));
    let engine = EditEngine::new(
        Arc::new(NoOpCoder),
        Arc::new(ScriptedTools::default()),
        Arc::new(BuiltinScanner),
    )
    .with_review(
        Arc::new(QuietReviewer),
        panel,
        JudgeCriteria {
            goal: "edit a+b".into(),
            threshold: 60,
        },
        "edit a+b",
    );
    let mut sink = MemorySink::new();
    let mut j = Journal::new("r12-t2-reject");
    let out = engine.run_turn(tier2_turn("r12-t2-reject"), &mut sink, &mut j);
    assert!(
        !out.committed(),
        "a Tier-2 edit the Judge disapproved must never commit, got {out:?}"
    );
}
