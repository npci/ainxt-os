// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-12 — **deterministic verify is LIVE on the shipped-daemon default edit engine**
//! (`CODE_REVIEW_PIPELINE.md` §Anti-sycophancy invariant #1: "deterministic verify owns pass/fail").
//!
//! The gap: the shipped daemon assembled its `EditEngine` with `ScriptedTools::default()`, whose every
//! deterministic stage vacuously passes — so a *syntactically broken* edit sailed through Phase A,
//! scored 100, and reached `Complete`; only the atomic-apply post-write re-parse caught it, as a
//! `CommitGate` post-approval failure. The #1 pipeline invariant (a tool, not the model, owns the
//! pass/fail a tool can decide) was inert on the default served path.
//!
//! Round-12 wires the real offline [`AstVerifyTools`]: its Compile stage parses every file with the
//! pinned tree-sitter grammar and FAILS at [`Stage::Compile`] — the designed deterministic gate,
//! before the score is ever consulted — when a file does not parse. Fail-before/pass-after is proven
//! *in one test*: the identical broken edit blocks at `CommitGate` (post-approval) under the old
//! `ScriptedTools`, and at `Compile` (deterministic verify) under `AstVerifyTools`.

use ainxt_pipeline::journal::Journal;
use ainxt_pipeline::sast::BuiltinScanner;
use ainxt_pipeline::{
    AstVerifyTools, Coder, EditEngine, EditTurn, Observation, PipelineOutcome, RiskTier,
    ScriptedTools, SelfHealConfig, Stage, TurnOutcome,
};
use ainxt_semantic::workspace::MemorySink;
use std::sync::Arc;

/// A coder that cannot fix anything (the air-gapped default has no model): it returns the files as-is,
/// so a real deterministic failure is never healed away and the gate is forced to be honest.
struct NoOpCoder;
impl Coder for NoOpCoder {
    fn fix(&self, _r: u8, files: &[(String, String)], _o: &Observation) -> Vec<(String, String)> {
        files.to_vec()
    }
}

fn cfg() -> SelfHealConfig {
    SelfHealConfig {
        lang: ainxt_pipeline::Language::Rust,
        tier: RiskTier::Local,
        max_rounds: 2,
        ..Default::default()
    }
}

const CLEAN: &str = "fn f() -> i32 {\n    1\n}\n";
// Missing the closing brace — a real syntax error the tree-sitter grammar reports as an ERROR node.
const BROKEN: &str = "fn f() -> i32 {\n    1\n";

fn turn(applied: &str) -> EditTurn {
    EditTurn {
        edit_id: "r12-verify".into(),
        original_files: vec![("src/a.rs".into(), CLEAN.into())],
        applied_files: vec![("src/a.rs".into(), applied.into())],
        config: cfg(),
    }
}

#[test]
fn r12_deterministic_verify_blocks_broken_edit_on_served_engine() {
    // ── FAIL-BEFORE: the old inert seam lets a broken edit through Phase A; only the atomic-apply
    //    post-write re-parse rejects it, as a CommitGate post-approval failure. ──
    let inert = EditEngine::new(
        Arc::new(NoOpCoder),
        Arc::new(ScriptedTools::default()),
        Arc::new(BuiltinScanner),
    );
    let mut sink = MemorySink::new();
    let mut j = Journal::new("r12-verify-inert");
    let out = inert.run_turn(turn(BROKEN), &mut sink, &mut j);
    match out {
        TurnOutcome::HandedToHuman { outcome, .. } => {
            // With ScriptedTools the deterministic Compile stage never fired: the block only happened
            // at the CommitGate, AFTER the pipeline had already declared the edit ready.
            assert_eq!(
                outcome.stage(),
                Stage::CommitGate,
                "with the inert scripted tools, deterministic verify did NOT own the failure"
            );
        }
        TurnOutcome::Committed { .. } => panic!("a broken edit must never commit"),
    }

    // ── PASS-AFTER: the shipped-daemon default seam. AstVerifyTools' Compile stage parses the edit and
    //    blocks it at Stage::Compile — a real deterministic gate, before the score is consulted. ──
    let served = EditEngine::new(
        Arc::new(NoOpCoder),
        Arc::new(AstVerifyTools::new()),
        Arc::new(BuiltinScanner),
    );
    let mut sink = MemorySink::new();
    let mut j = Journal::new("r12-verify-served");
    let out = served.run_turn(turn(BROKEN), &mut sink, &mut j);
    match out {
        TurnOutcome::HandedToHuman { outcome, .. } => {
            assert_eq!(
                outcome.stage(),
                Stage::Compile,
                "deterministic verify must own the pass/fail — the broken edit blocks at Compile"
            );
            // The exact, un-paraphrased parse diagnostic is on the honest gap report.
            if let PipelineOutcome::Capped { reason, .. } = &outcome {
                assert!(
                    reason.contains("Compile"),
                    "gap report names the Compile stage: {reason}"
                );
            }
        }
        TurnOutcome::Committed { .. } => {
            panic!("a syntactically broken edit must never reach Committed under real verify")
        }
    }
    // Nothing broken was ever durably written.
    assert_eq!(sink.files.get("src/a.rs").map(String::as_str), Some(CLEAN));
}

#[test]
fn r12_deterministic_verify_admits_a_clean_edit() {
    // No false positives: a clean edit still commits through the real verifier.
    let served = EditEngine::new(
        Arc::new(NoOpCoder),
        Arc::new(AstVerifyTools::new()),
        Arc::new(BuiltinScanner),
    );
    let mut sink = MemorySink::new();
    let mut j = Journal::new("r12-verify-clean");
    let clean_applied = "fn f() -> i32 {\n    2\n}\n";
    let out = served.run_turn(turn(clean_applied), &mut sink, &mut j);
    assert!(
        out.committed(),
        "a clean, parseable edit must commit: {out:?}"
    );
    assert_eq!(sink.files["src/a.rs"], clean_applied);
    assert_eq!(j.verify(), Ok(()));
}
