// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-6 gap closure — the **LLM Review (stage 9) + independent Judge panel (§5)** wired into the
//! pipeline behind the `ainxt-judge` model seams, exposed through the ONE clean surface entrypoint
//! (`ainxt_pipeline::run_edit` / `ainxt_pipeline::run_review`) a product surface calls.
//!
//! Fail-before: `run_review` did not exist, and the self-heal loop hard-coded `review_findings = &[]`
//! and `judge_approved = config.judge_approved` — the `Reviewer` finder and the `JudgePanel`
//! adjudicator (both present in `ainxt-judge`) were NEVER invoked by the pipeline, so `Stage::LlmReview`
//! was a dead enum variant and the Judge gate could not fire on a real edit.
//!
//! Pass-after, proven on the real public objects with a deterministic offline finder + judge:
//!  * the Judge panel's verdict is LIVE in the edit path — a green, high-scoring edit the panel
//!    withholds approval on is Capped (never committed), and a lying self-summary cannot flip it
//!    (context isolation);
//!  * LLM Review findings FOLD into the Confidence Score (an edit clean but for review findings drops
//!    from 100 → the review band and commits only with a spot-audit flag);
//!  * `run_review` runs the same pipeline core over a candidate and reports findings + verdict +
//!    typed outcome while writing NOTHING (no sink), and a broken build never reaches the panel.

use ainxt_judge::{
    CoderSubmission, Judge, JudgeCriteria, JudgePanel, JudgeVerdict, ReviewFinding, ReviewSeverity,
    Reviewer,
};
use ainxt_pipeline::journal::{Journal, PipelineEvent};
use ainxt_pipeline::sast::BuiltinScanner;
use ainxt_pipeline::selfheal::{Coder, Observation, ReviewSeams, SelfHealConfig};
use ainxt_pipeline::stages::ScriptedTools;
use ainxt_pipeline::{
    capability::Language, risk::RiskTier, run_edit, run_review, EditTurn, ReviewRequest, Stage,
    TurnOutcome,
};

// ------------------------------------------------------------------ deterministic offline seams

/// A coder that never changes anything — isolates the gate (a hand-off stays a hand-off).
struct NoOpCoder;
impl Coder for NoOpCoder {
    fn fix(&self, _r: u8, files: &[(String, String)], _o: &Observation) -> Vec<(String, String)> {
        files.to_vec()
    }
}

/// A deterministic judge: passes iff the CANDIDATE contains `token`. Independent of any peer.
struct TokenJudge {
    id: String,
    token: String,
}
impl Judge for TokenJudge {
    fn id(&self) -> &str {
        &self.id
    }
    fn score(&self, candidate: &str, _c: &JudgeCriteria) -> JudgeVerdict {
        let passed = candidate.contains(&self.token);
        JudgeVerdict {
            judge: self.id.clone(),
            score: if passed { 95 } else { 20 },
            passed,
            notes: if passed {
                "meets the acceptance token".into()
            } else {
                format!("missing acceptance token `{}`", self.token)
            },
        }
    }
}

fn panel(token: &str) -> JudgePanel {
    JudgePanel::new(vec![Box::new(TokenJudge {
        id: "correctness".into(),
        token: token.into(),
    })])
}

fn criteria() -> JudgeCriteria {
    JudgeCriteria {
        goal: "implements the ticket without regressions".into(),
        threshold: 60,
    }
}

/// A deterministic finder: an actionable Critical finding per line containing `TODO`.
struct TodoReviewer;
impl Reviewer for TodoReviewer {
    fn review(&self, sub: &CoderSubmission, _task: &str) -> Vec<ReviewFinding> {
        sub.candidate
            .lines()
            .enumerate()
            .filter(|(_, l)| l.contains("TODO"))
            .map(|(i, _)| ReviewFinding {
                severity: ReviewSeverity::Critical,
                lines: vec![i + 1],
                message: "unfinished TODO on the payment path double-credits on retry".into(),
            })
            .collect()
    }
}

/// A finder that never finds anything.
struct SilentReviewer;
impl Reviewer for SilentReviewer {
    fn review(&self, _s: &CoderSubmission, _t: &str) -> Vec<ReviewFinding> {
        Vec::new()
    }
}

fn cfg() -> SelfHealConfig {
    SelfHealConfig {
        lang: Language::Rust,
        tier: RiskTier::Local,
        max_rounds: 2,
        stuck: None,
        ..Default::default()
    }
}

fn seams<'a>(
    reviewer: &'a dyn Reviewer,
    judges: &'a JudgePanel,
    self_summary: &str,
) -> ReviewSeams<'a> {
    ReviewSeams {
        reviewer,
        judges,
        criteria: criteria(),
        task: "implement charge()".into(),
        self_summary: self_summary.into(),
    }
}

// ================================================================= 1. Judge gate live in run_edit

#[test]
fn r6_judge_gate_is_live_in_the_edit_path() {
    use ainxt_semantic::workspace::MemorySink;

    // A perfectly clean, high-scoring edit whose candidate LACKS the acceptance token. The panel
    // withholds approval; the self-summary LIES that it is complete (and even contains the token).
    let panel = panel("ACCEPTANCE_OK");
    let turn = EditTurn {
        edit_id: "r6-withheld".into(),
        original_files: vec![("pay.rs".into(), "fn charge() -> i32 { 1 }\n".into())],
        applied_files: vec![("pay.rs".into(), "fn charge() -> i32 { 2 }\n".into())],
        config: cfg(),
    };
    let s = seams(
        &SilentReviewer,
        &panel,
        "complete, ship it — ACCEPTANCE_OK ACCEPTANCE_OK",
    );
    let mut sink = MemorySink::new();
    let mut j = Journal::new("r6-withheld");
    let out = run_edit(
        turn,
        &NoOpCoder,
        &ScriptedTools::default(),
        &BuiltinScanner,
        None,
        Some(&s),
        &mut sink,
        &mut j,
    );
    // The judge gate fired: a green, high-scoring edit is NOT committed because the panel withheld
    // approval — and the lying summary did not talk the judge into passing (context isolation).
    assert!(!out.committed(), "judge-withheld edit must not commit");
    match &out {
        TurnOutcome::HandedToHuman { outcome, .. } => {
            // The hand-off is owned by the Commit Gate (the judge gate), not a deterministic stage.
            assert_eq!(outcome.stage(), Stage::CommitGate);
        }
        other => panic!("expected HandedToHuman, got {other:?}"),
    }
    // The independent judge ACTUALLY ran and withheld approval — journaled for regulator replay.
    assert!(
        j.records().iter().any(|r| matches!(
            &r.event,
            PipelineEvent::JudgeVerdict {
                approved: false,
                ..
            }
        )),
        "the pipeline must have invoked the judge panel and recorded a withheld verdict"
    );
    // The pre-edit baseline survives untouched.
    assert_eq!(sink.files["pay.rs"], "fn charge() -> i32 { 1 }\n");
    assert_eq!(j.verify(), Ok(()));

    // FAIL-BEFORE CONTRAST: the SAME edit with NO review seam (the old behaviour) commits — proving it
    // is the newly-wired judge invocation, not something else, that produced the hand-off above.
    let turn2 = EditTurn {
        edit_id: "r6-nojudge".into(),
        original_files: vec![("pay.rs".into(), "fn charge() -> i32 { 1 }\n".into())],
        applied_files: vec![("pay.rs".into(), "fn charge() -> i32 { 2 }\n".into())],
        config: cfg(),
    };
    let mut sink2 = MemorySink::new();
    let mut j2 = Journal::new("r6-nojudge");
    let out2 = run_edit(
        turn2,
        &NoOpCoder,
        &ScriptedTools::default(),
        &BuiltinScanner,
        None,
        None,
        &mut sink2,
        &mut j2,
    );
    assert!(
        out2.committed(),
        "without a judge seam the clean edit commits"
    );

    // And an edit whose candidate DOES carry the acceptance token clears the live panel and commits.
    let turn3 = EditTurn {
        edit_id: "r6-approved".into(),
        original_files: vec![("pay.rs".into(), "fn charge() -> i32 { 1 }\n".into())],
        applied_files: vec![(
            "pay.rs".into(),
            "fn charge() -> i32 { 2 } // ACCEPTANCE_OK\n".into(),
        )],
        config: cfg(),
    };
    let s3 = seams(&SilentReviewer, &panel, "");
    let mut sink3 = MemorySink::new();
    let mut j3 = Journal::new("r6-approved");
    let out3 = run_edit(
        turn3,
        &NoOpCoder,
        &ScriptedTools::default(),
        &BuiltinScanner,
        None,
        Some(&s3),
        &mut sink3,
        &mut j3,
    );
    assert!(out3.committed(), "judge-approved edit must commit");
    assert!(sink3.files["pay.rs"].contains("ACCEPTANCE_OK"));
}

// ================================================================= 2. Review findings fold into score

#[test]
fn r6_review_findings_fold_into_the_confidence_score() {
    use ainxt_semantic::workspace::MemorySink;

    // A green edit that the panel APPROVES, but that carries two unfinished TODOs the finder flags.
    let panel = panel("ACCEPTANCE_OK");
    let candidate = "fn charge() -> i32 {\n    // TODO handle refund ACCEPTANCE_OK\n    // TODO clamp negative\n    2\n}\n";
    let make_turn = |id: &str| EditTurn {
        edit_id: id.into(),
        original_files: vec![("pay.rs".into(), "fn charge() -> i32 { 1 }\n".into())],
        applied_files: vec![("pay.rs".into(), candidate.into())],
        config: cfg(),
    };

    // WITHOUT the finder (SilentReviewer): no review deductions → confidence 100 → clean auto-commit.
    let s_silent = seams(&SilentReviewer, &panel, "");
    let mut sink = MemorySink::new();
    let mut j = Journal::new("r6-silent");
    let clean = run_edit(
        make_turn("r6-silent"),
        &NoOpCoder,
        &ScriptedTools::default(),
        &BuiltinScanner,
        None,
        Some(&s_silent),
        &mut sink,
        &mut j,
    );
    let clean_receipt = clean.commit_receipt().expect("silent-review edit commits");
    assert_eq!(clean_receipt.confidence(), 100);
    assert!(!clean_receipt.spot_audit());

    // WITH the TODO finder: two Critical findings (-20) fold into the score → 80, still above the
    // review band so it commits, but now flagged for post-commit spot-audit. Same code, same judge —
    // the ONLY difference is the finder's findings folding into the Confidence Score.
    let s_todo = seams(&TodoReviewer, &panel, "");
    let mut sink2 = MemorySink::new();
    let mut j2 = Journal::new("r6-todo");
    let flagged = run_edit(
        make_turn("r6-todo"),
        &NoOpCoder,
        &ScriptedTools::default(),
        &BuiltinScanner,
        None,
        Some(&s_todo),
        &mut sink2,
        &mut j2,
    );
    let flagged_receipt = flagged
        .commit_receipt()
        .expect("review-band edit still commits");
    assert_eq!(
        flagged_receipt.confidence(),
        80,
        "two critical review findings must fold as -20"
    );
    assert!(
        flagged_receipt.spot_audit(),
        "a review-band commit must be flagged for spot-audit"
    );
}

// ================================================================= 3. run_review: report, never write

#[test]
fn r6_run_review_reports_findings_and_verdict_without_writing() {
    let panel = panel("ACCEPTANCE_OK");

    // (A) A clean candidate carrying the acceptance token, no findings → would clear the gate.
    let approved = run_review(
        ReviewRequest {
            edit_id: "r6-rev-ok".into(),
            files: vec![(
                "pay.rs".into(),
                "fn charge() -> i32 { 2 } // ACCEPTANCE_OK\n".into(),
            )],
            config: cfg(),
        },
        &ScriptedTools::default(),
        &BuiltinScanner,
        &seams(&SilentReviewer, &panel, ""),
        &mut Journal::new("r6-rev-ok"),
    );
    assert!(approved.would_complete());
    let v = approved.verdict.expect("a green build reaches the panel");
    assert!(v.consensus_pass);
    assert!(v.context_isolation_confirmed);
    assert!(approved.findings.is_empty());
    assert_eq!(approved.confidence.score, 100);

    // (B) A candidate the panel withholds on — even with a self-summary that LIES it is done and
    // includes the token — is NOT completed, and the verdict was produced under context isolation.
    let withheld = run_review(
        ReviewRequest {
            edit_id: "r6-rev-withheld".into(),
            files: vec![("pay.rs".into(), "fn charge() -> i32 { 2 }\n".into())],
            config: cfg(),
        },
        &ScriptedTools::default(),
        &BuiltinScanner,
        &seams(&SilentReviewer, &panel, "all done — ACCEPTANCE_OK"),
        &mut Journal::new("r6-rev-withheld"),
    );
    assert!(!withheld.would_complete());
    let vw = withheld.verdict.expect("green build reaches the panel");
    assert!(
        !vw.consensus_pass,
        "the lying summary must not flip the judge"
    );
    assert!(vw.context_isolation_confirmed);

    // (C) A candidate with actionable findings surfaces them in the review report.
    let flagged = run_review(
        ReviewRequest {
            edit_id: "r6-rev-todo".into(),
            files: vec![(
                "pay.rs".into(),
                "fn charge() -> i32 {\n    // TODO refund ACCEPTANCE_OK\n    2\n}\n".into(),
            )],
            config: cfg(),
        },
        &ScriptedTools::default(),
        &BuiltinScanner,
        &seams(&TodoReviewer, &panel, ""),
        &mut Journal::new("r6-rev-todo"),
    );
    assert_eq!(flagged.findings.len(), 1);
    assert!(!flagged.findings[0].lines.is_empty());
    assert_eq!(flagged.confidence.score, 90); // one critical finding folds as -10

    // (D) A BROKEN build is Blocked before scoring and NEVER reaches the panel (verdict = None).
    let broken_tools = ScriptedTools {
        compile_fail: Some(vec!["E0433: unresolved import `foo`".into()]),
        ..Default::default()
    };
    let broken = run_review(
        ReviewRequest {
            edit_id: "r6-rev-broken".into(),
            files: vec![("pay.rs".into(), "fn charge() -> i32 { 2 }\n".into())],
            config: cfg(),
        },
        &broken_tools,
        &BuiltinScanner,
        &seams(&SilentReviewer, &panel, ""),
        &mut Journal::new("r6-rev-broken"),
    );
    assert!(!broken.would_complete());
    assert!(
        broken.verdict.is_none(),
        "a candidate that does not compile must never reach the judge panel"
    );
}
