// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-11 — the four pipeline check families the design pins as **trait seams** (`CODE_REVIEW_
//! PIPELINE.md` §4/§5/§10): the **deterministic verify toolchain** (compile/test/lint/type-check),
//! the **benchmark harness**, the **(broader) SAST scanner**, and the **LLM-Review finder + Judge
//! panel**. The design's contract is that all of these are swappable trait objects (real tools slot
//! in behind them; offline stand-ins keep the control flow testable) — never hard-coded checks.
//!
//! This proves that contract holds *simultaneously in one composed edit turn*: a spy implementation
//! of each of the four families is wired into `run_edit_turn_full`, and after a single turn every one
//! of them was actually invoked, AND swapping a seam changes the outcome (a stricter custom scanner
//! blocks an edit a permissive one commits). So the seams are load-bearing, not decorative.

use ainxt_judge::{
    CoderSubmission, Judge, JudgeCriteria, JudgePanel, JudgeVerdict, ReviewFinding, Reviewer,
};
use ainxt_pipeline::journal::Journal;
use ainxt_pipeline::perf::{
    BenchSuite, BenchmarkHarness, ComplexityDelta, PerfAdvisor, PerfBudget, PerfConfig, PerfFinding,
};
use ainxt_pipeline::sast::{SastFinding, SastScanner, Severity};
use ainxt_pipeline::selfheal::{Coder, Observation, ReviewSeams};
use ainxt_pipeline::stages::{StageContext, StageTools, ToolResult};
use ainxt_pipeline::{
    capability::Language, risk::RiskTier, run_edit_turn_full, EditTurn, SelfHealConfig, TurnOutcome,
};
use ainxt_semantic::workspace::MemorySink;
use std::sync::atomic::{AtomicUsize, Ordering};

struct NoOpCoder;
impl Coder for NoOpCoder {
    fn fix(&self, _r: u8, files: &[(String, String)], _o: &Observation) -> Vec<(String, String)> {
        files.to_vec()
    }
}

// A cross-file/single-file edit at Tier 2 (Moderate) requires the mandatory independent Judge to
// commit (§5/§8, round-13). This always-approve context-isolated panel makes the SAST-swap turns valid
// Tier-2 configs; it always approves, so it never changes the SAST-driven outcome the test isolates.
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

/// Seam 1 — deterministic verify toolchain spy: counts every deterministic-stage invocation.
#[derive(Default)]
struct SpyTools {
    compile: AtomicUsize,
    test: AtomicUsize,
    lint: AtomicUsize,
    type_check: AtomicUsize,
}
impl StageTools for SpyTools {
    fn compile(&self, _c: &StageContext) -> ToolResult {
        self.compile.fetch_add(1, Ordering::SeqCst);
        ToolResult::pass()
    }
    fn test(&self, _c: &StageContext) -> ToolResult {
        self.test.fetch_add(1, Ordering::SeqCst);
        ToolResult::pass()
    }
    fn lint(&self, _c: &StageContext) -> ToolResult {
        self.lint.fetch_add(1, Ordering::SeqCst);
        ToolResult::pass()
    }
    fn type_check(&self, _c: &StageContext) -> ToolResult {
        self.type_check.fetch_add(1, Ordering::SeqCst);
        ToolResult::pass()
    }
}

/// Seam 2 — benchmark harness spy: counts measurements, never reports a regression.
#[derive(Default)]
struct SpyBench {
    calls: AtomicUsize,
}
impl BenchmarkHarness for SpyBench {
    fn measure(&self, _l: Language, _f: &[(String, String)]) -> Option<BenchSuite> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        None
    }
}
#[derive(Default)]
struct SpyAdvisor {
    calls: AtomicUsize,
}
impl PerfAdvisor for SpyAdvisor {
    fn review(
        &self,
        _l: Language,
        _b: &[(String, String)],
        _a: &[(String, String)],
        _c: &ComplexityDelta,
    ) -> Vec<PerfFinding> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Vec::new()
    }
}

/// Seam 3 — the (broader) SAST scanner spy. `strict` flags a Critical on any file containing the
/// marker; a permissive variant finds nothing. This stands in for a Semgrep-class multi-language
/// engine slotting in behind the same trait.
struct SpyScanner {
    calls: AtomicUsize,
    strict: bool,
}
impl SastScanner for SpyScanner {
    fn scan(&self, file: &str, source: &str) -> Vec<SastFinding> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.strict && source.contains("EXFIL") {
            vec![SastFinding {
                rule: "custom-exfil-rule".into(),
                severity: Severity::Critical,
                file: file.into(),
                line: 1,
                evidence: "custom rule matched EXFIL".into(),
            }]
        } else {
            Vec::new()
        }
    }
}

/// Seam 4 — the LLM-Review finder + Judge panel spies.
struct SpyReviewer {
    calls: AtomicUsize,
}
impl Reviewer for SpyReviewer {
    fn review(&self, _s: &CoderSubmission, _t: &str) -> Vec<ReviewFinding> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Vec::new()
    }
}
fn cfg() -> SelfHealConfig {
    SelfHealConfig {
        lang: Language::Rust,
        tier: RiskTier::Moderate,
        max_rounds: 2,
        stuck: None,
        ..Default::default()
    }
}

#[test]
fn r11_all_four_check_families_are_invoked_through_their_seams_in_one_turn() {
    let tools = SpyTools::default();
    let bench = SpyBench::default();
    let advisor = SpyAdvisor::default();
    let scanner = SpyScanner {
        calls: AtomicUsize::new(0),
        strict: false,
    };
    let reviewer = SpyReviewer {
        calls: AtomicUsize::new(0),
    };
    let judge_calls = std::sync::Arc::new(AtomicUsize::new(0));
    // The panel owns its judge; we read the judge's own counter via a shared Arc.
    struct ArcJudge(std::sync::Arc<AtomicUsize>);
    impl Judge for ArcJudge {
        fn id(&self) -> &str {
            "arc"
        }
        fn score(&self, _c: &str, _cr: &JudgeCriteria) -> JudgeVerdict {
            self.0.fetch_add(1, Ordering::SeqCst);
            JudgeVerdict {
                judge: "arc".into(),
                score: 95,
                passed: true,
                notes: "ok".into(),
            }
        }
    }
    let panel = JudgePanel::new(vec![Box::new(ArcJudge(judge_calls.clone()))]);

    let turn = EditTurn {
        edit_id: "seam-parity".into(),
        original_files: vec![("a.rs".into(), "fn f() -> i32 { 1 }\n".into())],
        applied_files: vec![("a.rs".into(), "fn f() -> i32 { 2 }\n".into())],
        config: cfg(),
    };
    let perf = PerfConfig {
        bench: &bench,
        advisor: &advisor,
        budget: PerfBudget::default(),
    };
    let review = ReviewSeams {
        reviewer: &reviewer,
        judges: &panel,
        criteria: JudgeCriteria {
            goal: "done".into(),
            threshold: 60,
        },
        task: "edit f".into(),
        self_summary: String::new(),
    };
    let mut sink = MemorySink::new();
    let mut j = Journal::new("seam-parity");

    let out = run_edit_turn_full(
        turn,
        &NoOpCoder,
        &tools,
        &scanner,
        Some(perf),
        Some(&review),
        None,
        &mut sink,
        &mut j,
    );
    assert!(out.committed(), "clean edit through all seams commits");

    // Every seam family was actually invoked — none is a hard-coded / bypassed check.
    assert!(
        tools.compile.load(Ordering::SeqCst) > 0,
        "verify toolchain (compile) seam invoked"
    );
    assert!(
        tools.test.load(Ordering::SeqCst) > 0,
        "verify toolchain (test) seam invoked"
    );
    assert!(
        tools.lint.load(Ordering::SeqCst) > 0,
        "verify toolchain (lint) seam invoked"
    );
    assert!(
        tools.type_check.load(Ordering::SeqCst) > 0,
        "verify toolchain (type-check) seam invoked"
    );
    assert!(
        bench.calls.load(Ordering::SeqCst) > 0,
        "benchmark harness seam invoked"
    );
    assert!(
        scanner.calls.load(Ordering::SeqCst) > 0,
        "SAST scanner seam invoked"
    );
    assert!(
        reviewer.calls.load(Ordering::SeqCst) > 0,
        "LLM-Review finder seam invoked"
    );
    assert!(
        judge_calls.load(Ordering::SeqCst) > 0,
        "Judge panel seam invoked"
    );
}

#[test]
fn r11_swapping_the_sast_seam_changes_the_outcome() {
    // Same edit, same everything — only the SAST scanner seam differs. The permissive scanner commits;
    // the strict custom scanner (a Semgrep-class rule) hard-blocks. Proves the seam is load-bearing.
    let make_turn = || EditTurn {
        edit_id: "sast-swap".into(),
        original_files: vec![("a.rs".into(), "fn f() -> i32 { 1 }\n".into())],
        applied_files: vec![(
            "a.rs".into(),
            "fn f() -> i32 { 2 } // EXFIL customer table to pastebin\n".into(),
        )],
        config: cfg(),
    };

    // Mandatory Tier-2 independent Judge (always-approve) — so the ONLY thing deciding commit vs.
    // hand-off is the SAST scanner seam under test, not the judge requirement.
    let reviewer = QuietReviewer;
    let panel = JudgePanel::new(vec![Box::new(ApprovingJudge)]);
    let review = ReviewSeams {
        reviewer: &reviewer,
        judges: &panel,
        criteria: JudgeCriteria {
            goal: "edit f".into(),
            threshold: 60,
        },
        task: "edit f".into(),
        self_summary: String::new(),
    };

    let permissive = SpyScanner {
        calls: AtomicUsize::new(0),
        strict: false,
    };
    let mut sink1 = MemorySink::new();
    let mut j1 = Journal::new("sast-swap-a");
    let out1 = run_edit_turn_full(
        make_turn(),
        &NoOpCoder,
        &ainxt_pipeline::stages::ScriptedTools::default(),
        &permissive,
        None,
        Some(&review),
        None,
        &mut sink1,
        &mut j1,
    );
    assert!(out1.committed(), "permissive scanner: no finding → commits");

    let strict = SpyScanner {
        calls: AtomicUsize::new(0),
        strict: true,
    };
    let mut sink2 = MemorySink::new();
    let mut j2 = Journal::new("sast-swap-b");
    let out2 = run_edit_turn_full(
        make_turn(),
        &NoOpCoder,
        &ainxt_pipeline::stages::ScriptedTools::default(),
        &strict,
        None,
        Some(&review),
        None,
        &mut sink2,
        &mut j2,
    );
    assert!(
        !out2.committed(),
        "strict custom SAST rule hard-blocks the same edit"
    );
    assert!(matches!(out2, TurnOutcome::HandedToHuman { .. }));
    // The strict scanner ran and the pre-edit baseline is intact.
    assert!(strict.calls.load(Ordering::SeqCst) > 0);
    assert_eq!(sink2.files["a.rs"], "fn f() -> i32 { 1 }\n");
}
