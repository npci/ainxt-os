// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-11 — **the LSP rung (edit-ladder rung 1), the design's highest-fidelity rung**
//! (`SEMANTIC_EDITING.md` §2). The ladder always declared rung 1 as a seam, but no served/composed
//! path drove it: `run_semantic_turn` hard-coded `Rung::Ast`. This proves the served semantic-op turn
//! now consults a language-server driver FIRST and, when it computes the refactor, adopts that
//! toolchain-grade result and records `Rung::Lsp` (zero Confidence-Score penalty) — and falls *down*
//! to the AST rung, recorded, when no server answers.
//!
//! The real language server is **infra** (a live rust-analyzer/gopls/… process + warm index); this
//! test drives the seam with the offline [`ScriptedLspRefactor`] stand-in, which never manufactures a
//! rung-1 result it was not given. Fail-before: `run_semantic_turn_with_lsp` / `ScriptedLspRefactor`
//! did not exist before round-11.

use ainxt_judge::{
    CoderSubmission, Judge, JudgeCriteria, JudgePanel, JudgeVerdict, ReviewFinding, Reviewer,
};
use ainxt_pipeline::journal::Journal;
use ainxt_pipeline::sast::BuiltinScanner;
use ainxt_pipeline::selfheal::ReviewSeams;
use ainxt_pipeline::stages::ScriptedTools;
use ainxt_pipeline::{
    run_semantic_turn_full, AgentOp, Coder, Observation, RiskTier, SelfHealConfig, SemanticTurn,
};
use ainxt_semantic::graph::SourceFile;
use ainxt_semantic::ladder::{CodeLanguage, LspRefactor, Rung, ScriptedLspRefactor, SemanticOp};
use ainxt_semantic::Language;

struct NoOpCoder;
impl Coder for NoOpCoder {
    fn fix(&self, _r: u8, files: &[(String, String)], _o: &Observation) -> Vec<(String, String)> {
        files.to_vec()
    }
}

// A cross-file rename is a signature/API change → Tier 2, where the independent Judge is MANDATORY
// (§5/§8, round-13). These fixtures wire a genuine always-approve context-isolated panel so each turn
// is a valid Tier-2 config; the panel always approves, so it never changes the rung/commit assertions.
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
fn run_reviewed(
    turn: SemanticTurn,
    lsp: Option<&dyn LspRefactor>,
    coder: &dyn Coder,
    sink: &mut ainxt_semantic::workspace::MemorySink,
    j: &mut Journal,
) -> ainxt_pipeline::SemanticTurnOutcome {
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
    run_semantic_turn_full(
        turn,
        lsp,
        Some(&review),
        coder,
        &ScriptedTools::default(),
        &BuiltinScanner,
        sink,
        j,
    )
    .expect("planned")
}

const SRC: &str =
    "fn caller() -> i32 {\n    charge() + charge()\n}\n\nfn charge() -> i32 {\n    1\n}\n";

fn turn() -> SemanticTurn {
    SemanticTurn {
        edit_id: "t-rename".into(),
        files: vec![SourceFile::new("pay.rs", Language::Rust, SRC)],
        op: AgentOp::Rename {
            old: "charge".into(),
            new: "settle".into(),
        },
        config: SelfHealConfig {
            lang: ainxt_pipeline::Language::Rust,
            tier: RiskTier::Local,
            max_rounds: 3,
            ..Default::default()
        },
    }
}

#[test]
fn r11_no_lsp_driver_falls_to_ast_rung() {
    use ainxt_semantic::workspace::MemorySink;
    let mut sink = MemorySink::new();
    let mut j = Journal::new("t-rename");
    let out = run_reviewed(turn(), None, &NoOpCoder, &mut sink, &mut j);
    // With no server, the highest available rung is AST — recorded honestly, not claimed as LSP.
    assert_eq!(out.rung, Rung::Ast);
    assert!(out.committed());
    assert!(sink.files["pay.rs"].contains("fn settle()"));
}

#[test]
fn r11_lsp_driver_present_resolves_at_rung_one() {
    use ainxt_semantic::workspace::MemorySink;
    // The server computes the whole-file refactor — carrying a marker so we can prove ITS result was
    // adopted, not the AST engine's. (A real server resolves references through the compiler's own
    // name resolution; here the scripted answer stands in for that.)
    let lsp_result =
        "// refactored by language server\nfn caller() -> i32 {\n    settle() + settle()\n}\n\nfn settle() -> i32 {\n    1\n}\n";
    let driver = ScriptedLspRefactor::new().with_answer(
        CodeLanguage::Rust,
        SemanticOp::RenameSymbol,
        SRC,
        lsp_result,
    );

    let mut sink = MemorySink::new();
    let mut j = Journal::new("t-rename");
    let out = run_reviewed(turn(), Some(&driver), &NoOpCoder, &mut sink, &mut j);

    // Rung 1 was used: highest fidelity, zero edit-fidelity penalty.
    assert_eq!(out.rung, Rung::Lsp);
    assert!(out.committed());
    // The language server's own result was committed (the marker proves it, not the AST path).
    assert!(sink.files["pay.rs"].contains("refactored by language server"));
    assert!(sink.files["pay.rs"].contains("fn settle()"));
}

#[test]
fn r11_unscripted_lsp_query_is_unavailable_and_degrades_to_ast() {
    use ainxt_semantic::workspace::MemorySink;
    // The driver has NO answer for this source → Unavailable → the turn must fall to the AST rung,
    // never silently claim a rung-1 refactor the server did not produce.
    let driver = ScriptedLspRefactor::new(); // scripted with nothing
    let mut sink = MemorySink::new();
    let mut j = Journal::new("t-rename");
    let out = run_reviewed(turn(), Some(&driver), &NoOpCoder, &mut sink, &mut j);
    assert_eq!(out.rung, Rung::Ast);
    assert!(out.committed());
    assert!(!sink.files["pay.rs"].contains("language server"));
}
