// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-15 (semantic-editing-codereview) — closes:
//!
//!  - **HIGH**: deterministic verify honesty — `Test`/`Lint`/`Type-Check` reported `Pass` on the
//!    shipped default (`AstVerifyTools`) for every fully-tooled language (Rust/Java/TypeScript/Go)
//!    **without ever running a tool**. Fixed: those three stages now honestly report `Skipped` (a
//!    scored penalty, never a fabricated `Pass`) until a real hook is wired via
//!    [`AstVerifyTools::with_lint`]/[`with_test`](AstVerifyTools::with_test)/
//!    [`with_type_check`](AstVerifyTools::with_type_check) — which also closes the paired **LOW**
//!    ("deeper deterministic verifier … before commit") by proving a wired hook's real verdict flows
//!    through the exact same stage the served daemon runs.
//!  - **MEDIUM**: the add/replace-method guards (import-restore + method-preservation) existed
//!    (`guarded_full_file_apply`) but no apply path ever called them. Now wired into the atomic-apply
//!    call site in `edit_turn.rs`: a silently-dropped method blocks the commit; a dropped import is
//!    transparently restored.
//!
//! Fail-before/pass-after is proven for both: the HIGH item contrasts `AstVerifyTools`'s honest
//! `Skipped` against the pre-fix behavior (documented in `r14_deterministic_verify_stages_run.rs`'s
//! equivalent contrast for the `ainxt-edit` seam) and against a wired hook's real verdict; the MEDIUM
//! item shows a run with the guard producing a block where the pre-fix code would have silently
//! committed the drop (`guarded_full_file_apply` was never on the apply path).

use ainxt_judge::{
    CoderSubmission, Judge, JudgeCriteria, JudgePanel, JudgeVerdict, ReviewFinding, Reviewer,
};
use ainxt_pipeline::journal::Journal;
use ainxt_pipeline::sast::BuiltinScanner;
use ainxt_pipeline::stages::{
    run_deterministic_stages, AstVerifyTools, StageContext, StageTools, ToolResult,
};
use ainxt_pipeline::{
    stage::StageVerdict, AgentOp, Coder, EditEngine, EditTurn, Language, Observation, RiskTier,
    SelfHealConfig, Stage, TurnOutcome,
};
use ainxt_semantic::workspace::MemorySink;
use std::sync::Arc;

struct NoOpCoder;
impl Coder for NoOpCoder {
    fn fix(&self, _r: u8, files: &[(String, String)], _o: &Observation) -> Vec<(String, String)> {
        files.to_vec()
    }
}

/// A genuine, always-approving independent judge + a silent finder. A structural op (a function
/// removal, a rename) classifies to Moderate/Tier 2, where an independent Judge is mandatory (§5/§8,
/// round-13) — wiring a real context-isolated panel makes the engine a valid Tier-2 config so these
/// tests isolate the method-preservation-guard / rung behavior they are actually about.
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

fn ctx(files: &[(&str, &str)]) -> StageContext {
    StageContext {
        lang: Language::Rust,
        files: files
            .iter()
            .map(|(p, s)| (p.to_string(), s.to_string()))
            .collect(),
    }
}

// ---- HIGH + LOW: deterministic-verify honesty + pluggable deeper verifier ------------------------

#[test]
fn r15_ast_verify_tools_test_lint_typecheck_are_honestly_skipped_not_fabricated_pass() {
    let clean = ctx(&[("src/pay.rs", "fn settle(a: u64) -> u64 {\n    a + 1\n}\n")]);
    let tools = AstVerifyTools::new();

    // Before this round: `test`/`lint`/`type_check` returned `ToolResult::pass()` unconditionally —
    // a fabricated green on every fully-tooled language. After: honestly `not_run` ⇒ `Skipped`.
    for (name, result) in [
        ("test", tools.test(&clean)),
        ("lint", tools.lint(&clean)),
        ("type_check", tools.type_check(&clean)),
    ] {
        assert!(
            !result.passed,
            "{name} must not report a fabricated pass with no hook wired"
        );
        assert!(!result.ran, "{name} must honestly report it did not run");
    }

    // The stage runner turns that into a real `Skipped` verdict, not `Pass` — visible on the full
    // stage set the served daemon runs through `run_deterministic_stages`.
    let out = run_deterministic_stages(&clean, &tools, &BuiltinScanner);
    for stage in [Stage::Test, Stage::Lint, Stage::TypeCheck] {
        let report = out.reports.iter().find(|r| r.stage == stage).unwrap();
        assert!(
            matches!(report.verdict, StageVerdict::Skipped { .. }),
            "{stage:?} must be Skipped (never Pass) with no real toolchain wired: {:?}",
            report.verdict
        );
    }
    // Compile still runs the real parse gate and passes a clean edit — the deterministic floor.
    let compile = out
        .reports
        .iter()
        .find(|r| r.stage == Stage::Compile)
        .unwrap();
    assert!(compile.verdict.is_pass());
}

#[test]
fn r15_ast_verify_tools_wired_hook_runs_for_real_closing_deeper_verifier_gap() {
    // A deterministic offline stand-in for a real clippy/tsc/LSP-diagnostics binding: any line with
    // `unwrap()` is a gating lint finding. Stands in for the real infra hook a deployment wires.
    let lint_hook = Box::new(|c: &StageContext| {
        let mut diags = Vec::new();
        for (path, src) in &c.files {
            for (i, line) in src.lines().enumerate() {
                if line.contains("unwrap()") {
                    diags.push(format!(
                        "{path}:{}: lint: forbidden unwrap() on a gated path",
                        i + 1
                    ));
                }
            }
        }
        if diags.is_empty() {
            ToolResult::pass()
        } else {
            ToolResult::fail(diags)
        }
    });

    let flagged = ctx(&[(
        "src/pay.rs",
        "fn f() -> u64 {\n    None::<u64>.unwrap()\n}\n",
    )]);
    let tools = AstVerifyTools::new().with_lint(lint_hook);
    let result = tools.lint(&flagged);
    assert!(result.ran, "a wired hook must actually run");
    assert!(
        !result.passed,
        "the wired hook's real verdict must flow through, not a fabricated pass"
    );
    assert!(result.diagnostics[0].contains("unwrap"));

    // Type-check/test remain honestly Skipped — wiring one hook never fabricates the others.
    assert!(!tools.test(&flagged).ran);
    assert!(!tools.type_check(&flagged).ran);

    // And on a clean file the SAME wired hook reports a real Pass (not just a real Fail) — proving
    // the seam carries genuine verdicts both ways.
    let clean = ctx(&[("src/pay.rs", "fn f() -> u64 {\n    1\n}\n")]);
    assert!(tools.lint(&clean).passed);
}

// ---- MEDIUM: add/replace-method guards now run as part of the atomic apply ------------------------

fn cfg() -> SelfHealConfig {
    SelfHealConfig {
        lang: Language::Rust,
        tier: RiskTier::Local,
        max_rounds: 1,
        ..Default::default()
    }
}

/// A "coder" standing in for a full-file LLM regeneration that silently drops a method the original
/// defined (the exact failure mode `CLAUDE.md`'s "Import overwriting" known-bug note describes) — it
/// hands back fixed content on every round regardless of the observation, mirroring a one-shot
/// full-file rewrite.
struct DroppingRegenCoder {
    regenerated: String,
}
impl Coder for DroppingRegenCoder {
    fn fix(&self, _r: u8, _files: &[(String, String)], _o: &Observation) -> Vec<(String, String)> {
        vec![("src/pay.rs".to_string(), self.regenerated.clone())]
    }
}

#[test]
fn r15_method_preservation_guard_blocks_a_silently_dropped_method_on_atomic_apply() {
    let original =
        "use std::fmt;\n\nfn keep() -> i32 {\n    1\n}\n\nfn also_keep() -> i32 {\n    2\n}\n";
    // The regeneration compiles cleanly on its own (so nothing else blocks it) but silently drops
    // `also_keep` — exactly the "silent drop" `guarded_full_file_apply` exists to catch, now wired
    // into the atomic-apply path so a REJECTED first pass immediately re-enters the self-heal loop
    // where the (identical) regeneration keeps dropping it, capping the turn honestly.
    let regenerated = "use std::fmt;\n\nfn keep() -> i32 {\n    1\n}\n";

    // The function removal classifies to Moderate (Tier 2), where an independent Judge is mandatory
    // (round-13) — wire an always-approving panel so the Commit Gate isolates the method-preservation
    // guard's own behavior rather than tripping the (unrelated) missing-Judge refusal.
    let engine = with_judge(EditEngine::new(
        Arc::new(DroppingRegenCoder {
            regenerated: regenerated.to_string(),
        }),
        Arc::new(AstVerifyTools::new()),
        Arc::new(BuiltinScanner),
    ));
    let mut sink = MemorySink::new();
    let mut j = Journal::new("r15-drop-method");
    let turn = EditTurn {
        edit_id: "r15-drop-method".into(),
        original_files: vec![("src/pay.rs".into(), original.into())],
        // The applied set starts already regenerated (the coder is only consulted on a REJECTED
        // pass) — Compile/Lint/etc all honestly Skipped/Pass, so nothing else would block this.
        applied_files: vec![("src/pay.rs".into(), regenerated.into())],
        config: cfg(),
    };
    let out = engine.run_turn(turn, &mut sink, &mut j);
    match out {
        TurnOutcome::HandedToHuman { outcome, .. } => {
            assert_eq!(
                outcome.stage(),
                Stage::CommitGate,
                "the method-preservation guard must block at the Commit Gate: {outcome:?}"
            );
            if let ainxt_pipeline::PipelineOutcome::Blocked {
                deterministic_failure,
                ..
            } = &outcome
            {
                assert!(
                    deterministic_failure.contains("also_keep"),
                    "the exact dropped method must be named: {deterministic_failure}"
                );
            } else {
                panic!("expected a Blocked outcome naming the dropped method: {outcome:?}");
            }
        }
        TurnOutcome::Committed { .. } => {
            panic!("a regeneration that silently drops a pre-edit method must never commit")
        }
    }
    // Nothing was durably written — the pre-edit baseline is intact.
    assert_eq!(
        sink.files.get("src/pay.rs").map(String::as_str),
        Some(original)
    );
}

#[test]
fn r15_import_restore_guard_runs_transparently_on_atomic_apply_without_blocking() {
    let original = "use std::io::Read;\n\nfn f() -> i32 {\n    1\n}\n";
    // Drops the import but keeps every method — should be silently repaired and commit clean.
    let applied = "fn f() -> i32 {\n    2\n}\n";

    let engine = EditEngine::new(
        Arc::new(NoOpCoder),
        Arc::new(AstVerifyTools::new()),
        Arc::new(BuiltinScanner),
    );
    let mut sink = MemorySink::new();
    let mut j = Journal::new("r15-import-restore");
    let turn = EditTurn {
        edit_id: "r15-import-restore".into(),
        original_files: vec![("src/pay.rs".into(), original.into())],
        applied_files: vec![("src/pay.rs".into(), applied.into())],
        config: cfg(),
    };
    let out = engine.run_turn(turn, &mut sink, &mut j);
    assert!(
        out.committed(),
        "a dropped-import-only edit must commit (import restore, not a block): {out:?}"
    );
    let committed = sink.files.get("src/pay.rs").expect("committed content");
    assert!(
        committed.contains("use std::io::Read;"),
        "the dropped import must be re-injected: {committed}"
    );
    assert!(committed.contains("fn f() -> i32 {\n    2\n}"));
}

/// R15 LOW ("Edit ladder rung 1 reachable on the served path") + confirms `guard_methods = false` on
/// the planned-op path: a rename legitimately makes the old symbol name vanish — the guard must NOT
/// mistake that for a silent drop, and `EditEngine::run_semantic_op_for` is the route-ready entrypoint
/// that makes rung 1 (LSP) reachable once a deployment wires `EditEngine::with_lsp`.
#[test]
fn r15_semantic_op_rename_is_not_blocked_by_the_method_preservation_guard() {
    use ainxt_pipeline::edit_turn::SemanticEditRequest;
    use ainxt_semantic::graph::SourceFile;

    let src =
        "fn caller() -> i32 {\n    charge() + charge()\n}\n\nfn charge() -> i32 {\n    1\n}\n";
    // A cross-file-shaped rename classifies to Moderate (Tier 2), where an independent Judge is
    // mandatory (round-13) — wire an always-approving panel so this isolates the rung/guard behavior.
    let engine = with_judge(EditEngine::new(
        Arc::new(NoOpCoder),
        Arc::new(AstVerifyTools::new()),
        Arc::new(BuiltinScanner),
    ));
    let principal =
        ainxt_types::Principal::user("u1", &[ainxt_pipeline::edit_turn::CAP_EDIT_APPLY]);
    let req = SemanticEditRequest {
        edit_id: "r15-rename".into(),
        files: vec![SourceFile::new(
            "pay.rs",
            ainxt_semantic::Language::Rust,
            src,
        )],
        op: AgentOp::Rename {
            old: "charge".into(),
            new: "settle".into(),
        },
        config: cfg(),
    };
    let mut sink = MemorySink::new();
    let mut j = Journal::new("r15-rename");
    let resp = engine
        .run_semantic_op_for(&principal, req, &mut sink, &mut j)
        .expect("authorized");
    match resp {
        ainxt_pipeline::edit_turn::SemanticEditResponse::Resolved { rung, response } => {
            assert_eq!(
                rung,
                ainxt_semantic::ladder::Rung::Ast,
                "no LSP driver wired ⇒ AST rung"
            );
            assert!(
                matches!(response, ainxt_pipeline::edit_turn::EditResponse::Committed { .. }),
                "a legitimate rename must commit, never blocked as a false 'dropped method': {response:?}"
            );
        }
        ainxt_pipeline::edit_turn::SemanticEditResponse::PlanRejected { reason } => {
            panic!("rename must plan successfully: {reason}")
        }
    }
    let committed = sink.files.get("pay.rs").expect("committed content");
    assert!(committed.contains("fn settle() -> i32"));
    assert!(!committed.contains("fn charge"));
}

/// R15 LOW ("Edit ladder rung 1 reachable on the served path") — the full closure: with a real (here,
/// scripted-offline) LSP driver wired via `EditEngine::with_lsp`, the SAME route-ready
/// `run_semantic_op_for` entrypoint resolves the op at `Rung::Lsp`, not just the AST fallback. Before
/// this round `EditEngine` (the served `/v1/edit` engine) had no `lsp` field and no method-preservation-
/// aware planned-op entrypoint at all, so rung 1 was unreachable from the served path in principle, not
/// just unconfigured. The real driver is infra (a live language-server process); `ScriptedLspRefactor`
/// is the honest offline stand-in the seam is built to accept.
#[test]
fn r15_semantic_op_for_resolves_at_lsp_rung_when_a_driver_is_wired() {
    use ainxt_pipeline::edit_turn::SemanticEditRequest;
    use ainxt_semantic::graph::SourceFile;
    use ainxt_semantic::ladder::{CodeLanguage, ScriptedLspRefactor, SemanticOp};

    let src =
        "fn caller() -> i32 {\n    charge() + charge()\n}\n\nfn charge() -> i32 {\n    1\n}\n";
    let lsp_edited =
        "fn caller() -> i32 {\n    settle() + settle()\n}\n\nfn settle() -> i32 {\n    1\n}\n";
    let lsp = ScriptedLspRefactor::new().with_answer(
        CodeLanguage::Rust,
        SemanticOp::RenameSymbol,
        src,
        lsp_edited,
    );

    let engine = with_judge(
        EditEngine::new(
            Arc::new(NoOpCoder),
            Arc::new(AstVerifyTools::new()),
            Arc::new(BuiltinScanner),
        )
        .with_lsp(Arc::new(lsp)),
    );
    let principal =
        ainxt_types::Principal::user("u1", &[ainxt_pipeline::edit_turn::CAP_EDIT_APPLY]);
    let req = SemanticEditRequest {
        edit_id: "r15-rename-lsp".into(),
        files: vec![SourceFile::new(
            "pay.rs",
            ainxt_semantic::Language::Rust,
            src,
        )],
        op: AgentOp::Rename {
            old: "charge".into(),
            new: "settle".into(),
        },
        config: cfg(),
    };
    let mut sink = MemorySink::new();
    let mut j = Journal::new("r15-rename-lsp");
    let resp = engine
        .run_semantic_op_for(&principal, req, &mut sink, &mut j)
        .expect("authorized");
    match resp {
        ainxt_pipeline::edit_turn::SemanticEditResponse::Resolved { rung, response } => {
            assert_eq!(
                rung,
                ainxt_semantic::ladder::Rung::Lsp,
                "a wired, answering LSP driver must resolve rung 1 through the route-ready entrypoint"
            );
            assert!(
                matches!(
                    response,
                    ainxt_pipeline::edit_turn::EditResponse::Committed { .. }
                ),
                "the LSP-resolved rename must still commit through the full gate: {response:?}"
            );
        }
        ainxt_pipeline::edit_turn::SemanticEditResponse::PlanRejected { reason } => {
            panic!("rename must plan successfully: {reason}")
        }
    }
    let committed = sink.files.get("pay.rs").expect("committed content");
    assert_eq!(
        committed, lsp_edited,
        "the toolchain-grade LSP edit is adopted verbatim"
    );
}

#[test]
fn r15_semantic_op_for_refuses_unauthorized_principal_before_planning() {
    use ainxt_pipeline::edit_turn::SemanticEditRequest;
    use ainxt_semantic::graph::SourceFile;

    let src = "fn charge() -> i32 {\n    1\n}\n";
    let engine = EditEngine::new(
        Arc::new(NoOpCoder),
        Arc::new(AstVerifyTools::new()),
        Arc::new(BuiltinScanner),
    );
    let principal = ainxt_types::Principal::user("u1", &[]); // no CAP_EDIT_APPLY
    let req = SemanticEditRequest {
        edit_id: "r15-rename-unauth".into(),
        files: vec![SourceFile::new(
            "pay.rs",
            ainxt_semantic::Language::Rust,
            src,
        )],
        op: AgentOp::Rename {
            old: "charge".into(),
            new: "settle".into(),
        },
        config: cfg(),
    };
    let mut sink = MemorySink::new();
    let mut j = Journal::new("r15-rename-unauth");
    let err = engine
        .run_semantic_op_for(&principal, req, &mut sink, &mut j)
        .expect_err("unauthorized principal must be refused");
    assert_eq!(err, ainxt_pipeline::edit_turn::EditRefused::NotAuthorized);
    assert!(
        sink.files.is_empty(),
        "an unauthorized call must never touch the sink"
    );
}
