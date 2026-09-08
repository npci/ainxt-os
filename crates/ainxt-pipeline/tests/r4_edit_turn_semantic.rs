// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-4 gap closures, proven on the REAL public objects a surface/renderer assembles.
//!
//! * `r4_render_gated_on_committed` — the typed pipeline outcome enforced on a real edit turn: a
//!   renderer's "done" affordance ([`CommitReceipt`]) is obtainable ONLY from `TurnOutcome::Committed`.
//!   Fail-before: `commit_receipt()` did not exist, so a renderer had only a boolean it could ignore.
//!   Pass-after: `HandedToHuman` (both Blocked and Capped) yields `None`; only a real commit yields a
//!   receipt carrying the durable versions + confidence.
//!
//! * `r4_semantic_op_through_ladder` — an agent-expressed semantic op (rename / change-signature /
//!   extract) plans through the ladder (AST rung) and applies through the atomic verify+rollback gate.
//!   Fail-before: `run_semantic_turn`/`AgentOp` did not exist — nothing bound an agent op to the gate.
//!   Pass-after: a clean rename commits atomically at the AST rung; and a FAILED VERIFY NEVER COMMITS
//!   — proven two ways: (a) a deterministic verify failure the coder cannot heal, and (b) a post-write
//!   atomic-apply regression that rolls the sink back to the pre-edit baseline.

use std::collections::BTreeMap;

use ainxt_judge::{
    CoderSubmission, Judge, JudgeCriteria, JudgePanel, JudgeVerdict, ReviewFinding, Reviewer,
};
use ainxt_pipeline::edit_turn::{run_edit_turn, EditTurn, TurnOutcome};
use ainxt_pipeline::journal::Journal;
use ainxt_pipeline::sast::{BuiltinScanner, SastScanner};
use ainxt_pipeline::selfheal::{Coder, Observation, ReviewSeams, SelfHealConfig};
use ainxt_pipeline::semantic_turn::{
    run_semantic_turn, run_semantic_turn_full, AgentOp, PlanError, SemanticTurn,
    SemanticTurnOutcome,
};
use ainxt_pipeline::stages::{ScriptedTools, StageContext, StageTools, ToolResult};
use ainxt_pipeline::{capability::Language, risk::RiskTier};
use ainxt_semantic::graph::SourceFile;
use ainxt_semantic::ladder::Rung;
use ainxt_semantic::ops::AddParamSpec;
use ainxt_semantic::workspace::{MemorySink, WorkspaceSink};
use ainxt_semantic::Language as AstLang;

// A cross-file rename / change-signature is a signature/API change → Tier 2, where the independent
// Judge is MANDATORY (§5/§8, round-13). These fixtures wire a genuine always-approve context-isolated
// panel so each structural turn is a valid Tier-2 config; the panel always approves, so it never
// changes any rung / atomic-commit / rollback assertion below.
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

/// Run a semantic turn with the mandatory Tier-2+ independent Judge (always-approve) wired in.
fn sem_reviewed(
    turn: SemanticTurn,
    coder: &dyn Coder,
    tools: &dyn StageTools,
    scanner: &dyn SastScanner,
    sink: &mut dyn WorkspaceSink,
    j: &mut Journal,
) -> Result<SemanticTurnOutcome, PlanError> {
    let reviewer = QuietReviewer;
    let panel = JudgePanel::new(vec![Box::new(ApprovingJudge)]);
    let review = ReviewSeams {
        reviewer: &reviewer,
        judges: &panel,
        criteria: JudgeCriteria {
            goal: "refactor".into(),
            threshold: 60,
        },
        task: "refactor".into(),
        self_summary: String::new(),
    };
    run_semantic_turn_full(turn, None, Some(&review), coder, tools, scanner, sink, j)
}

// ------------------------------------------------------------------ seams

/// A coder that cannot fix anything → a hard-blocked/failing turn stays a hand-off.
struct NoOpCoder;
impl Coder for NoOpCoder {
    fn fix(&self, _r: u8, files: &[(String, String)], _o: &Observation) -> Vec<(String, String)> {
        files.to_vec()
    }
}

/// Tools whose compile fails whenever the renamed symbol (`assist`) is present — a deterministic
/// verify failure a no-op coder cannot heal.
struct RejectRenamedTools;
impl StageTools for RejectRenamedTools {
    fn compile(&self, ctx: &StageContext) -> ToolResult {
        if ctx.files.iter().any(|(_, c)| c.contains("assist")) {
            ToolResult::fail(vec!["E: renamed symbol rejected by verify".into()])
        } else {
            ToolResult::pass()
        }
    }
    fn test(&self, _c: &StageContext) -> ToolResult {
        ToolResult::pass()
    }
    fn lint(&self, _c: &StageContext) -> ToolResult {
        ToolResult::pass()
    }
    fn type_check(&self, _c: &StageContext) -> ToolResult {
        ToolResult::pass()
    }
}

/// A sink that accepts commits but lies on read-back, forcing the atomic apply's POST-WRITE verify to
/// regress and roll back — the strongest "failed verify never commits" proof. The underlying store is
/// inspectable so we can assert the rollback restored the pre-edit baseline.
#[derive(Default)]
struct LyingSink {
    inner: MemorySink,
    corrupt: bool,
}
impl WorkspaceSink for LyingSink {
    fn commit(&mut self, files: &BTreeMap<String, String>) -> Result<(), String> {
        self.inner.commit(files)
    }
    fn read(&self, path: &str) -> Option<String> {
        if self.corrupt {
            Some("fn broken( {{{ not valid rust".to_string())
        } else {
            self.inner.read(path)
        }
    }
}

fn cfg(tier: RiskTier) -> SelfHealConfig {
    SelfHealConfig {
        lang: Language::Rust,
        tier,
        max_rounds: 3,
        stuck: None,
        ..Default::default()
    }
}

fn rs(path: &str, src: &str) -> SourceFile {
    SourceFile::new(path, AstLang::Rust, src)
}

fn rs_py(path: &str, src: &str) -> SourceFile {
    SourceFile::new(path, AstLang::Python, src)
}

// ================================================================= GAP 1

#[test]
fn r4_render_gated_on_committed() {
    // A clean edit turn commits → a renderer CAN obtain the sealed done-affordance, carrying the real
    // durable versions + confidence.
    let clean = EditTurn {
        edit_id: "r4-clean".into(),
        original_files: vec![("a.rs".into(), "fn f() -> i32 { 1 }\n".into())],
        applied_files: vec![("a.rs".into(), "fn f() -> i32 { 2 }\n".into())],
        config: cfg(RiskTier::Local),
    };
    let mut sink = MemorySink::new();
    let mut j = Journal::new("r4-clean");
    let out = run_edit_turn(
        clean,
        &NoOpCoder,
        &ScriptedTools::default(),
        &BuiltinScanner,
        &mut sink,
        &mut j,
    );
    assert!(out.committed());
    let receipt = out
        .commit_receipt()
        .expect("a committed turn must yield a render receipt");
    assert!(receipt.confidence() >= 90);
    assert_eq!(receipt.committed_versions()["a.rs"], 1);

    // A Tier-3 (settlement) edit that scores perfectly is still forced to a human → Capped, no receipt.
    let capped = EditTurn {
        edit_id: "r4-settle".into(),
        original_files: vec![("settlement/x.rs".into(), "fn f() -> i32 { 1 }\n".into())],
        applied_files: vec![("settlement/x.rs".into(), "fn f() -> i32 { 2 }\n".into())],
        config: cfg(RiskTier::HighRisk),
    };
    let mut sink = MemorySink::new();
    let mut j = Journal::new("r4-settle");
    let out = run_edit_turn(
        capped,
        &NoOpCoder,
        &ScriptedTools::default(),
        &BuiltinScanner,
        &mut sink,
        &mut j,
    );
    assert!(!out.committed());
    assert!(
        out.commit_receipt().is_none(),
        "a Tier-3 human-gated turn must NOT hand the renderer a done affordance"
    );
    match out {
        TurnOutcome::HandedToHuman { .. } => {}
        other => panic!("expected HandedToHuman for Tier-3, got {other:?}"),
    }
}

// ================================================================= GAP 2

#[test]
fn r4_semantic_op_through_ladder() {
    let lib_src = "pub fn helper() -> i32 {\n    7\n}\n";
    let main_src = "fn run() -> i32 {\n    helper() + helper()\n}\n";

    // ---- (A) HAPPY PATH: an agent-expressed cross-file RENAME plans at the AST rung and commits
    //          atomically through the verify gate.
    let turn = SemanticTurn {
        edit_id: "r4-rename".into(),
        files: vec![rs("lib.rs", lib_src), rs("main.rs", main_src)],
        op: AgentOp::Rename {
            old: "helper".into(),
            new: "assist".into(),
        },
        config: cfg(RiskTier::Local),
    };
    let mut sink = MemorySink::new();
    let mut j = Journal::new("r4-rename");
    let res = sem_reviewed(
        turn,
        &NoOpCoder,
        &ScriptedTools::default(),
        &BuiltinScanner,
        &mut sink,
        &mut j,
    )
    .expect("rename must plan");
    // Planned at the highest-fidelity rung (AST), zero fidelity penalty.
    assert_eq!(res.rung, Rung::Ast);
    assert_eq!(res.rung.confidence_penalty(), 0);
    // The plan touched both files.
    assert_eq!(res.plan.len(), 2);
    // It committed atomically, and the rename is durably in BOTH files.
    assert!(
        res.committed(),
        "clean rename must commit, got {:?}",
        res.turn
    );
    assert!(sink.files["lib.rs"].contains("fn assist()"));
    assert!(!sink.files["lib.rs"].contains("helper"));
    assert_eq!(sink.files["main.rs"].matches("assist()").count(), 2);
    assert_eq!(j.verify(), Ok(()));

    // ---- (B) FAILED DETERMINISTIC VERIFY NEVER COMMITS: the compile stage rejects the renamed symbol
    //          and the no-op coder cannot heal → HandedToHuman, sink holds the pre-edit baseline.
    let turn = SemanticTurn {
        edit_id: "r4-rename-reject".into(),
        files: vec![rs("lib.rs", lib_src), rs("main.rs", main_src)],
        op: AgentOp::Rename {
            old: "helper".into(),
            new: "assist".into(),
        },
        config: cfg(RiskTier::Local),
    };
    let mut sink = MemorySink::new();
    let mut j = Journal::new("r4-rename-reject");
    let res = run_semantic_turn(
        turn,
        &NoOpCoder,
        &RejectRenamedTools,
        &BuiltinScanner,
        &mut sink,
        &mut j,
    )
    .expect("rename must plan");
    assert!(!res.committed(), "a failed verify must never commit");
    assert!(res.turn.commit_receipt().is_none());
    // The rename was rolled back / never durably applied — both files still hold `helper`.
    assert_eq!(sink.files["lib.rs"], lib_src);
    assert_eq!(sink.files["main.rs"], main_src);

    // ---- (C) FAILED POST-WRITE ATOMIC VERIFY NEVER COMMITS: the pipeline reaches Complete, but the
    //          sink lies on read-back → the atomic apply's post-verify regresses and ROLLS BACK. The
    //          turn degrades to HandedToHuman and the baseline survives.
    let turn = SemanticTurn {
        edit_id: "r4-rename-rollback".into(),
        files: vec![rs("lib.rs", lib_src), rs("main.rs", main_src)],
        op: AgentOp::Rename {
            old: "helper".into(),
            new: "assist".into(),
        },
        config: cfg(RiskTier::Local),
    };
    let mut sink = LyingSink {
        corrupt: true,
        ..Default::default()
    };
    let mut j = Journal::new("r4-rename-rollback");
    let res = sem_reviewed(
        turn,
        &NoOpCoder,
        &ScriptedTools::default(),
        &BuiltinScanner,
        &mut sink,
        &mut j,
    )
    .expect("rename must plan");
    assert!(
        !res.committed(),
        "a post-write verify regression must never commit, got {:?}",
        res.turn
    );
    match &res.turn {
        TurnOutcome::HandedToHuman { outcome, .. } => {
            // The atomic apply failed AFTER approval → the durable write was refused + rolled back.
            assert!(format!("{outcome:?}").contains("atomic apply failed post-approval"));
        }
        other => panic!("expected HandedToHuman after rollback, got {other:?}"),
    }
    // The underlying store was rolled back to the pre-edit baseline (original `helper`).
    assert_eq!(sink.inner.files["lib.rs"], lib_src);
    assert_eq!(sink.inner.files["main.rs"], main_src);

    // ---- (D) CHANGE-SIGNATURE + EXTRACT also plan+commit through the same gate (agent-expressed).
    let sig_turn = SemanticTurn {
        edit_id: "r4-sig".into(),
        files: vec![
            rs(
                "lib.rs",
                "pub fn charge(amount: i32) -> i32 {\n    amount\n}\n",
            ),
            rs("main.rs", "fn run() -> i32 {\n    charge(10)\n}\n"),
        ],
        op: AgentOp::ChangeSignature {
            name: "charge".into(),
            spec: AddParamSpec {
                declaration_param: "ctx: i32".into(),
                call_argument: "0".into(),
            },
        },
        config: cfg(RiskTier::Local),
    };
    let mut sink = MemorySink::new();
    let mut j = Journal::new("r4-sig");
    let res = sem_reviewed(
        sig_turn,
        &NoOpCoder,
        &ScriptedTools::default(),
        &BuiltinScanner,
        &mut sink,
        &mut j,
    )
    .expect("change-signature must plan");
    assert!(res.committed());
    assert!(sink.files["lib.rs"].contains("fn charge(amount: i32, ctx: i32)"));
    assert!(sink.files["main.rs"].contains("charge(10, 0)"));

    let extract_turn = SemanticTurn {
        edit_id: "r4-extract".into(),
        files: vec![rs(
            "m.rs",
            "fn outer() {\n    let a = 1;\n    let b = 2;\n    let _ = a + b;\n}\n",
        )],
        op: AgentOp::Extract {
            file: "m.rs".into(),
            enclosing: "outer".into(),
            start_line: 2,
            end_line: 3,
            new_name: "setup".into(),
        },
        config: cfg(RiskTier::Local),
    };
    let mut sink = MemorySink::new();
    let mut j = Journal::new("r4-extract");
    let res = sem_reviewed(
        extract_turn,
        &NoOpCoder,
        &ScriptedTools::default(),
        &BuiltinScanner,
        &mut sink,
        &mut j,
    )
    .expect("extract must plan");
    assert!(res.committed());
    assert!(sink.files["m.rs"].contains("fn setup()"));
    assert!(sink.files["m.rs"].contains("setup();"));

    // ---- (E) A Python cross-file rename plans + commits at the AST rung too (language-agnostic gate).
    let py_turn = SemanticTurn {
        edit_id: "r4-py".into(),
        files: vec![
            rs_py("lib.py", "def helper():\n    return 1\n"),
            rs_py("main.py", "def run():\n    return helper()\n"),
        ],
        op: AgentOp::Rename {
            old: "helper".into(),
            new: "assist".into(),
        },
        config: cfg(RiskTier::Local),
    };
    let mut sink = MemorySink::new();
    let mut j = Journal::new("r4-py");
    let res = sem_reviewed(
        py_turn,
        &NoOpCoder,
        &ScriptedTools::default(),
        &BuiltinScanner,
        &mut sink,
        &mut j,
    )
    .expect("python rename must plan");
    assert_eq!(res.rung, Rung::Ast);
    assert!(res.committed());
    assert!(sink.files["lib.py"].contains("def assist()"));
    assert!(sink.files["main.py"].contains("assist()"));

    // ---- (F) A planning rejection (rename collides with an existing symbol) fails BEFORE any write.
    let bad_turn = SemanticTurn {
        edit_id: "r4-collide".into(),
        files: vec![rs("a.rs", "fn helper() {}\nfn other() {}\n")],
        op: AgentOp::Rename {
            old: "helper".into(),
            new: "other".into(),
        },
        config: cfg(RiskTier::Local),
    };
    let mut sink = MemorySink::new();
    let mut j = Journal::new("r4-collide");
    let err = run_semantic_turn(
        bad_turn,
        &NoOpCoder,
        &ScriptedTools::default(),
        &BuiltinScanner,
        &mut sink,
        &mut j,
    )
    .expect_err("a colliding rename must be a PlanError, not a write");
    assert!(matches!(err, PlanError::Plan(_)));
    // Nothing was written — the sink never saw the pre-edit baseline either (plan failed first).
    assert!(sink.files.is_empty());

    // ---- (G) GAP-FIX semantic-editing-codereview — an agent-expressed INLINE plans + commits at the
    //          AST rung too: `ops::plan_inline_function` was fully implemented and unit-tested but had
    //          zero callers outside its own crate until `AgentOp::Inline` bound it into this ladder.
    let inline_turn = SemanticTurn {
        edit_id: "r4-inline".into(),
        files: vec![rs(
            "m.rs",
            "fn base() -> i32 { 42 }\nfn a() -> i32 { base() + 1 }\nfn b() -> i32 { base() }\n",
        )],
        op: AgentOp::Inline {
            name: "base".into(),
        },
        config: cfg(RiskTier::Local),
    };
    let mut sink = MemorySink::new();
    let mut j = Journal::new("r4-inline");
    let res = sem_reviewed(
        inline_turn,
        &NoOpCoder,
        &ScriptedTools::default(),
        &BuiltinScanner,
        &mut sink,
        &mut j,
    )
    .expect("inline must plan");
    assert_eq!(res.rung, Rung::Ast);
    assert!(
        res.committed(),
        "clean inline must commit, got {:?}",
        res.turn
    );
    assert!(
        !sink.files["m.rs"].contains("fn base"),
        "the definition must be removed"
    );
    assert!(
        sink.files["m.rs"].contains("(42) + 1"),
        "call sites carry the inlined expression"
    );
    assert!(sink.files["m.rs"].contains("fn b() -> i32 { (42) }"));
    assert_eq!(j.verify(), Ok(()));

    // ---- (H) GAP-FIX semantic-editing-codereview — an agent-expressed MOVE (across files) plans +
    //          commits at the AST rung too: `ops::plan_move_definition` was fully implemented and
    //          unit-tested but had zero callers outside its own crate until `AgentOp::Move` bound it in.
    let move_turn = SemanticTurn {
        edit_id: "r4-move".into(),
        files: vec![
            rs("a.rs", "fn keep() {}\n\nfn mover() -> i32 {\n    7\n}\n"),
            rs("b.rs", "fn other() {}\n"),
        ],
        op: AgentOp::Move {
            name: "mover".into(),
            from_file: "a.rs".into(),
            to_file: "b.rs".into(),
        },
        config: cfg(RiskTier::Local),
    };
    let mut sink = MemorySink::new();
    let mut j = Journal::new("r4-move");
    let res = sem_reviewed(
        move_turn,
        &NoOpCoder,
        &ScriptedTools::default(),
        &BuiltinScanner,
        &mut sink,
        &mut j,
    )
    .expect("move must plan");
    assert_eq!(res.rung, Rung::Ast);
    assert!(
        res.committed(),
        "clean move must commit, got {:?}",
        res.turn
    );
    assert!(
        !sink.files["a.rs"].contains("fn mover"),
        "removed from source"
    );
    assert!(sink.files["a.rs"].contains("fn keep"));
    assert!(
        sink.files["b.rs"].contains("fn mover() -> i32 {"),
        "appended to destination"
    );
    assert!(sink.files["b.rs"].contains("fn other"));
    assert_eq!(j.verify(), Ok(()));
}
