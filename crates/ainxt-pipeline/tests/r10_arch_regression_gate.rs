// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R10 gap: **Architecture Review (stage 7) + Regression Detection (stage 8) wired into the LIVE edit
//! turn.**
//!
//! Before this round the deterministic module-boundary check (`ainxt_semantic::arch`) and the
//! blast-radius test-coverage computation (`ainxt_semantic::regression`) existed, and the Commit Gate
//! already hard-blocked on `architecture_violations > 0` and folded `blast_radius_test_coverage` into
//! the Confidence Score — but **nothing computed those two numbers from a live edit**. The self-heal
//! loop consumed them as caller-supplied scalars (`SelfHealConfig`), so a boundary-violating edit that
//! declared `architecture_violations = 0` sailed through, and coverage was whatever the caller invented.
//!
//! This test drives the REAL surface entrypoint a served daemon holds — one [`EditEngine`] assembled
//! once from `Arc` seams, now with stages 7+8 wired via [`EditEngine::with_semantic_review`], cloned
//! across turns — and proves both stages now actually run against the edit itself:
//!
//! * **fail-before / pass-after** — `EditEngine::with_semantic_review`, the `semantic` param on
//!   `run_edit_turn_full`, `SemanticGateConfig`/`SemanticGateSeams`, and `analyze_semantic_gate` did
//!   not exist, so this file did not compile against the pre-round crate.
//! * **a boundary-violating edit is gated** — an edit that introduces a forbidden `ui → db` import
//!   edge is blocked at `Stage::Architecture` and never commits, while the same file importing an
//!   ALLOWED layer through the SAME engine commits — isolating the boundary crossing as the cause.
//! * **low blast-radius coverage lowers confidence** — an edit to a function no test reaches commits
//!   at a lowered Confidence Score through the wired engine, but at full confidence through a
//!   semantic-DISABLED engine (which trusts the caller's `1.0` scalar) — isolating the computed
//!   coverage as the cause.

use std::sync::Arc;

use ainxt_judge::{
    CoderSubmission, Judge, JudgeCriteria, JudgePanel, JudgeVerdict, ReviewFinding, Reviewer,
};
use ainxt_pipeline::edit_turn::{EditEngine, EditTurn, TurnOutcome};
use ainxt_pipeline::journal::{Journal, PipelineEvent};
use ainxt_pipeline::sast::BuiltinScanner;
use ainxt_pipeline::selfheal::{Coder, Observation, SelfHealConfig};
use ainxt_pipeline::stage::{Stage, StageVerdict};
use ainxt_pipeline::stages::ScriptedTools;
use ainxt_pipeline::{capability::Language, risk::RiskTier};
use ainxt_semantic::arch::LayerContract;
use ainxt_semantic::regression::CochangeGraph;
use ainxt_semantic::workspace::MemorySink;

/// A coder that never changes anything — the offline/air-gapped default. A clean edit needs no heal;
/// a gated edit it cannot fix caps honestly (never a fabricated "done").
struct NoOpCoder;
impl Coder for NoOpCoder {
    fn fix(&self, _r: u8, files: &[(String, String)], _o: &Observation) -> Vec<(String, String)> {
        files.to_vec()
    }
}

fn cfg(tier: RiskTier) -> SelfHealConfig {
    SelfHealConfig {
        lang: Language::Rust,
        tier,
        max_rounds: 2,
        stuck: None,
        ..Default::default()
    }
}

/// A layering contract: `ui` may depend on `api`, `api` on `db`; `ui → db` is forbidden.
fn contract() -> LayerContract {
    LayerContract::new()
        .layer("api", &["api"])
        .layer("db", &["db::"])
        .layer("ui", &["ui/"])
        .allow("ui", "api")
        .allow("api", "db")
}

/// A genuine, always-approving independent judge, and a finder that finds nothing. These edits are
/// multi-file / dependency-introducing → Tier 2 (Moderate), where the independent Judge is MANDATORY
/// (§5/§8, round-13). Wiring a real context-isolated panel makes each engine a valid Tier-2 config so
/// this test can isolate the ARCHITECTURE / REGRESSION behavior it is actually about; the panel always
/// approves, so it never changes any arch/coverage assertion below.
struct ApprovingJudge;
impl Judge for ApprovingJudge {
    fn id(&self) -> &str {
        "approving"
    }
    fn score(&self, _c: &str, _cr: &JudgeCriteria) -> JudgeVerdict {
        JudgeVerdict {
            judge: "approving".into(),
            score: 95,
            passed: true,
            notes: "ok".into(),
        }
    }
}
struct QuietReviewer;
impl Reviewer for QuietReviewer {
    fn review(&self, _s: &CoderSubmission, _t: &str) -> Vec<ReviewFinding> {
        Vec::new()
    }
}

/// Wire the mandatory Tier-2+ independent Judge (always-approve) onto an engine.
fn with_judge(engine: EditEngine) -> EditEngine {
    engine.with_review(
        Arc::new(QuietReviewer),
        Arc::new(JudgePanel::new(vec![Box::new(ApprovingJudge)])),
        JudgeCriteria {
            goal: "edit".into(),
            threshold: 60,
        },
        "edit",
    )
}

fn arch_engine() -> EditEngine {
    with_judge(
        EditEngine::new(
            Arc::new(NoOpCoder),
            Arc::new(ScriptedTools::default()),
            Arc::new(BuiltinScanner),
        )
        .with_semantic_review(
            Some(Arc::new(contract())),
            Arc::new(CochangeGraph::new()),
            3,
        ),
    )
}

/// The Architecture stage verdict the pipeline journaled this turn, if any.
fn journaled_arch_verdict(j: &Journal) -> Option<StageVerdict> {
    j.records().iter().find_map(|r| match &r.event {
        PipelineEvent::StageResult {
            stage: Stage::Architecture,
            verdict,
            ..
        } => Some(verdict.clone()),
        _ => None,
    })
}

#[test]
fn r10_arch_regression_gate() {
    // ============================================================================================
    // Stage 7 — a boundary-violating edit is GATED by the live edit turn.
    // ============================================================================================
    let engine = arch_engine();

    // A `ui` file that newly imports `db` directly — a forbidden `ui → db` boundary crossing. It
    // compiles/tests/lints clean (ScriptedTools passes everything) and trips no SAST rule, so the ONLY
    // thing that can stop it is the deterministic Architecture hard-gate.
    let forbidden = EditTurn {
        edit_id: "r10-forbidden".into(),
        original_files: vec![("src/ui/screen.rs".into(), "fn render() {}\n".into())],
        applied_files: vec![(
            "src/ui/screen.rs".into(),
            "use crate::db::conn;\nfn render() {}\n".into(),
        )],
        config: cfg(RiskTier::Local),
    };
    let mut sink = MemorySink::new();
    let mut journal = Journal::new("r10-forbidden");
    let out = engine.run_turn(forbidden, &mut sink, &mut journal);

    assert!(
        !out.committed(),
        "a forbidden ui→db boundary edit must never auto-commit, got {out:?}"
    );
    match &out {
        TurnOutcome::HandedToHuman { .. } => {}
        other => {
            panic!("expected an honest human hand-off for a boundary violation, got {other:?}")
        }
    }
    // The sink was NEVER written — the pre-edit baseline stands.
    assert_eq!(sink.files["src/ui/screen.rs"], "fn render() {}\n");
    // The tamper-evident journal carries an honest Architecture FAIL naming the crossed boundary.
    match journaled_arch_verdict(&journal).expect("Stage::Architecture must have run + journaled") {
        StageVerdict::Fail { detail } => {
            assert!(
                detail.contains("ui"),
                "arch failure should name the from-layer: {detail}"
            );
            assert!(
                detail.contains("db"),
                "arch failure should name the to-layer: {detail}"
            );
        }
        other => panic!("expected an Architecture Fail verdict, got {other:?}"),
    }
    assert_eq!(journal.verify(), Ok(()));

    // ISOLATION: the SAME file importing an ALLOWED layer (`ui → api`) through the SAME engine commits,
    // proving the boundary crossing — not the new import per se — is what gated the edit above.
    let allowed = EditTurn {
        edit_id: "r10-allowed".into(),
        original_files: vec![("src/ui/screen.rs".into(), "fn render() {}\n".into())],
        applied_files: vec![(
            "src/ui/screen.rs".into(),
            "use crate::api::conn;\nfn render() {}\n".into(),
        )],
        config: cfg(RiskTier::Local),
    };
    let mut sink = MemorySink::new();
    let mut journal = Journal::new("r10-allowed");
    let out = engine.run_turn(allowed, &mut sink, &mut journal);
    assert!(
        out.committed(),
        "an allowed ui→api import must commit through the same engine, got {out:?}"
    );
    assert!(sink.files["src/ui/screen.rs"].contains("api::conn"));

    // ============================================================================================
    // Stage 8 — low blast-radius test coverage LOWERS the committed Confidence Score.
    // ============================================================================================
    // `covered()` is reached by a #[test]; `naked()` is reached by nobody. Editing `naked`'s body
    // touches an UNCOVERED symbol → the computed coverage is 0, which the Confidence Score folds in.
    let lib_before = "pub fn covered() -> i32 { 1 }\npub fn naked() -> i32 { 2 }\n";
    let lib_after = "pub fn covered() -> i32 { 1 }\npub fn naked() -> i32 { 3 }\n";
    let test_file = "#[test]\nfn test_it() { let _ = covered(); }\n";

    let uncovered_turn = || EditTurn {
        edit_id: "r10-uncovered".into(),
        original_files: vec![
            ("lib.rs".into(), lib_before.into()),
            ("t.rs".into(), test_file.into()),
        ],
        applied_files: vec![
            ("lib.rs".into(), lib_after.into()),
            ("t.rs".into(), test_file.into()),
        ],
        config: cfg(RiskTier::Local),
    };

    // (a) Through the WIRED engine (stage 8 computes coverage from the test graph).
    let reg_engine = with_judge(
        EditEngine::new(
            Arc::new(NoOpCoder),
            Arc::new(ScriptedTools::default()),
            Arc::new(BuiltinScanner),
        )
        .with_semantic_review(None, Arc::new(CochangeGraph::new()), 3),
    );
    let mut sink = MemorySink::new();
    let mut journal = Journal::new("r10-uncovered");
    let wired = reg_engine.run_turn(uncovered_turn(), &mut sink, &mut journal);
    let wired_conf = match wired {
        TurnOutcome::Committed { approval, .. } => approval.confidence(),
        other => panic!("the uncovered edit is non-gating and should still commit, got {other:?}"),
    };

    // (b) Through a semantic-DISABLED engine (trusts the caller's default 1.0 coverage scalar).
    let plain = with_judge(EditEngine::new(
        Arc::new(NoOpCoder),
        Arc::new(ScriptedTools::default()),
        Arc::new(BuiltinScanner),
    ));
    let mut sink = MemorySink::new();
    let mut journal = Journal::new("r10-uncovered-plain");
    let plain_out = plain.run_turn(uncovered_turn(), &mut sink, &mut journal);
    let plain_conf = match plain_out {
        TurnOutcome::Committed { approval, .. } => approval.confidence(),
        other => panic!("expected commit at full confidence, got {other:?}"),
    };

    // The wired engine COMPUTED the uncovered blast radius and docked the score; the plain engine
    // trusted the caller's 1.0 and did not. 100% uncovered → -30 regression risk (100 → 70).
    assert_eq!(
        plain_conf, 100,
        "semantic-disabled trusts the caller scalar → full confidence"
    );
    assert_eq!(
        wired_conf, 70,
        "100% uncovered blast radius costs 30 confidence points"
    );
    assert!(
        wired_conf < plain_conf,
        "computed low coverage must lower confidence ({wired_conf} !< {plain_conf})"
    );
}
