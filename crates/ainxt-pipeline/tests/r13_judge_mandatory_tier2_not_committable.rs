// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-13 — **the independent Judge is a hard commit requirement at Tier 2+**
//! (`CODE_REVIEW_PIPELINE.md` §5: the Judge is "mandatory at Tier 2+ and always at Tier 3"; §8 tier
//! table gives Tier 2 the Judge stage).
//!
//! Round-12 fixed the "silent auto-approve" hole by dropping a no-Judge Tier-2 edit into the human
//! spot-audit band — but a spot-audit-band commit is still a **commit**, and the design says the Judge
//! is *mandatory*, not *advisory*. Round-13 closes the residual gap: at Tier 2+ the Commit Gate
//! **requires a genuine, context-isolated independent panel verdict** — anything less is *not
//! committable*:
//!   • ABSENT     — no panel ran at all.
//!   • ONE-SIDED  — an approval that did not come from a context-isolated independent panel (a caller
//!                  self-asserting `config.judge_approved = Some(true)` with no panel behind it).
//! Both cap to an honest human hand-off regardless of Confidence Score. The contrast cases prove the
//! requirement is *exactly* the independent-panel adjudication (not something else) doing the gating,
//! and that the mandate is correctly scoped to Tier 2+ (a Local edit still commits without a Judge).

use ainxt_judge::{
    CoderSubmission, Judge, JudgeCriteria, JudgePanel, JudgeVerdict, ReviewFinding, Reviewer,
};
use ainxt_pipeline::journal::{Journal, PipelineEvent};
use ainxt_pipeline::sast::BuiltinScanner;
use ainxt_pipeline::stage::Stage;
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

/// A genuine, independent judge with a fixed verdict — wired through `EditEngine::with_review`, so the
/// panel runs via the context-isolated `evaluate_submission` path (the only thing that satisfies §5).
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

/// A finder that finds nothing — so the Confidence Score stays high and the ONLY thing deciding the
/// outcome is the Judge requirement, not review findings.
struct QuietReviewer;
impl Reviewer for QuietReviewer {
    fn review(&self, _s: &CoderSubmission, _t: &str) -> Vec<ReviewFinding> {
        Vec::new()
    }
}

fn cfg(tier: RiskTier) -> SelfHealConfig {
    SelfHealConfig {
        lang: ainxt_pipeline::Language::Rust,
        tier,
        max_rounds: 2,
        ..Default::default()
    }
}

/// A clean, parseable **two-file** edit → the deterministic classifier escalates it to Tier 2
/// (`files_touched > 1`), exactly as a real multi-file edit would.
fn tier2_turn(id: &str, config: SelfHealConfig) -> EditTurn {
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
        config,
    }
}

fn engine_no_review() -> EditEngine {
    EditEngine::new(
        Arc::new(NoOpCoder),
        Arc::new(ScriptedTools::default()),
        Arc::new(BuiltinScanner),
    )
}

fn engine_with_panel(approve: bool) -> EditEngine {
    let panel = Arc::new(JudgePanel::new(vec![Box::new(FixedJudge { approve })]));
    engine_no_review().with_review(
        Arc::new(QuietReviewer),
        panel,
        JudgeCriteria {
            goal: "edit a+b".into(),
            threshold: 60,
        },
        "edit a+b",
    )
}

/// THE proof: a Tier-2 edit with **no** Judge verdict cannot commit.
#[test]
fn r13_tier2_without_judge_verdict_cannot_commit() {
    let engine = engine_no_review();
    let mut sink = MemorySink::new();
    let mut j = Journal::new("r13-absent");
    let out = engine.run_turn(
        tier2_turn("r13-absent", cfg(RiskTier::Local)),
        &mut sink,
        &mut j,
    );

    // Not committable — handed to a human, owned by the Commit Gate with the §5/§8 mandate as reason.
    assert!(
        !out.committed(),
        "no-Judge Tier-2 edit must not commit, got {out:?}"
    );
    match out {
        TurnOutcome::HandedToHuman { outcome, .. } => {
            assert_eq!(outcome.stage(), Stage::CommitGate);
        }
        other => panic!("expected HandedToHuman, got {other:?}"),
    }
    // The sink was never written — the pre-edit baseline survives.
    assert_eq!(sink.files["a.rs"], "fn a() -> i32 {\n    1\n}\n");
    assert_eq!(j.verify(), Ok(()));
}

/// A **one-sided / self-asserted** approval (a caller sets `config.judge_approved = Some(true)` with
/// NO panel behind it) is not an independent adjudication and also cannot commit at Tier 2+.
#[test]
fn r13_tier2_one_sided_self_asserted_approval_cannot_commit() {
    let mut config = cfg(RiskTier::Local);
    config.judge_approved = Some(true); // asserted "done" with no independent panel — §5's forbidden case.
    let engine = engine_no_review(); // no `.with_review` → no panel ever runs.
    let mut sink = MemorySink::new();
    let mut j = Journal::new("r13-onesided");
    let out = engine.run_turn(tier2_turn("r13-onesided", config), &mut sink, &mut j);

    assert!(
        !out.committed(),
        "a self-asserted (one-sided) approval must not satisfy the Tier-2 mandate, got {out:?}"
    );
    // The gate recorded the verdict as NON context-isolated — the honest forensic trail.
    assert!(
        j.records().iter().any(|r| matches!(
            &r.event,
            PipelineEvent::JudgeVerdict {
                context_isolation_confirmed: false,
                ..
            }
        )),
        "the self-asserted verdict must be journaled as non-context-isolated"
    );
}

/// CONTRAST 1 (pass-after): the same Tier-2 edit WITH a genuine context-isolated approving panel
/// commits — proving it is exactly the independent-panel requirement doing the gating.
#[test]
fn r13_tier2_with_independent_panel_commits() {
    let engine = engine_with_panel(true);
    let mut sink = MemorySink::new();
    let mut j = Journal::new("r13-panel-ok");
    let out = engine.run_turn(
        tier2_turn("r13-panel-ok", cfg(RiskTier::Local)),
        &mut sink,
        &mut j,
    );

    match out {
        TurnOutcome::Committed { approval, .. } => {
            assert!(
                !approval.spot_audit(),
                "an independently-adjudicated Tier-2 edit auto-completes"
            );
        }
        other => panic!("expected Committed, got {other:?}"),
    }
    // The panel's verdict is journaled as context-isolated (the genuine §5 adjudication).
    assert!(
        j.records().iter().any(|r| matches!(
            &r.event,
            PipelineEvent::JudgeVerdict {
                approved: true,
                context_isolation_confirmed: true,
                ..
            }
        )),
        "the independent panel verdict must be journaled as context-isolated"
    );
}

/// CONTRAST 2: an independent panel that WITHHELD approval caps regardless of score — the completion
/// adjudication is a gate ON TOP of the Confidence Score, never a term the score can buy back (§5).
#[test]
fn r13_tier2_with_independent_panel_withholding_caps() {
    let engine = engine_with_panel(false);
    let mut sink = MemorySink::new();
    let mut j = Journal::new("r13-panel-no");
    let out = engine.run_turn(
        tier2_turn("r13-panel-no", cfg(RiskTier::Local)),
        &mut sink,
        &mut j,
    );
    assert!(
        !out.committed(),
        "a Judge-withheld Tier-2 edit must never commit, got {out:?}"
    );
}

/// SCOPE proof: the mandate is Tier-2+ ONLY. A Local (Tier-1) single-file edit with no Judge still
/// commits — the tightening does not turn into a blanket block on all edits.
#[test]
fn r13_local_tier_edit_without_judge_still_commits() {
    let engine = engine_no_review();
    let turn = EditTurn {
        edit_id: "r13-local".into(),
        original_files: vec![("a.rs".into(), "fn a() -> i32 {\n    1\n}\n".into())],
        applied_files: vec![("a.rs".into(), "fn a() -> i32 {\n    2\n}\n".into())],
        config: cfg(RiskTier::Local),
    };
    let mut sink = MemorySink::new();
    let mut j = Journal::new("r13-local");
    let out = engine.run_turn(turn, &mut sink, &mut j);
    assert!(
        out.committed(),
        "a Local edit with no Judge is allowed to commit (§5), got {out:?}"
    );
}
