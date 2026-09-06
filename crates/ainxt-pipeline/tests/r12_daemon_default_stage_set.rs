// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-12 — **the daemon-default edit engine actually enables the stage SET the design mandates**
//! (`CODE_REVIEW_PIPELINE.md` §3 tier table). The gap: the shipped daemon assembled its `EditEngine`
//! with only `ScriptedTools::default()` — deterministic verify was inert and the Architecture (stage
//! 7) / Regression (stage 8) stages were not wired at all, so a served edit ran a hollow pipeline.
//!
//! This test assembles the engine **exactly as `ainxt-runtimed` assembles it for `/v1/edit`** —
//! `EditEngine::new(IdentityCoder-shaped coder, AstVerifyTools, BuiltinScanner)
//! .with_semantic_review(None, CochangeGraph::new(), 8)` — and proves, on that precise assembly:
//!
//!  1. **Deterministic verify is LIVE** — a syntactically broken edit is blocked at `Stage::Compile`
//!     (invariant #1), before the score is consulted; nothing is durably written.
//!  2. **Architecture (7) + Regression (8) are enabled** — both journal a `StageResult` on a clean
//!     turn, so a deployment that populates a `LayerContract` / co-change graph gets a real gate (they
//!     are inert-but-present on the air-gapped default, never silently absent).
//!  3. **The model/infra stages are honestly NOT faked** — with no `with_review` / `with_perf`, no
//!     `Stage::LlmReview` and no `Stage::Performance` result is journaled (those are `needs_hot_wiring`:
//!     they require a model + benchmark/sandbox infra). The Commit Gate fail-safe still holds: a Tier-2
//!     edit with no independent Judge never silently auto-completes.

use ainxt_pipeline::journal::{Journal, PipelineEvent};
use ainxt_pipeline::sast::BuiltinScanner;
use ainxt_pipeline::{
    AstVerifyTools, Coder, EditEngine, EditTurn, Observation, RiskTier, SelfHealConfig, Stage,
    TurnOutcome,
};
use ainxt_semantic::regression::CochangeGraph;
use ainxt_semantic::workspace::MemorySink;
use std::sync::Arc;

/// The air-gapped default coder: no model, returns files unchanged (a REJECTED pass can't be
/// fabricated into a false "done"). Mirrors `ainxt-runtimed`'s `IdentityCoder`.
struct NoOpCoder;
impl Coder for NoOpCoder {
    fn fix(&self, _r: u8, files: &[(String, String)], _o: &Observation) -> Vec<(String, String)> {
        files.to_vec()
    }
}

/// Assemble the engine EXACTLY as the shipped daemon does for `POST /v1/edit`.
fn daemon_default_engine() -> EditEngine {
    EditEngine::new(
        Arc::new(NoOpCoder),
        Arc::new(AstVerifyTools::new()),
        Arc::new(BuiltinScanner),
    )
    .with_semantic_review(None, Arc::new(CochangeGraph::new()), 8)
}

fn journaled_stages(j: &Journal) -> Vec<Stage> {
    j.records()
        .iter()
        .filter_map(|r| match &r.event {
            PipelineEvent::StageResult { stage, .. } => Some(*stage),
            _ => None,
        })
        .collect()
}

const CLEAN: &str = "fn f() -> i32 {\n    1\n}\n";
const BROKEN: &str = "fn f() -> i32 {\n    1\n"; // missing closing brace

fn cfg() -> SelfHealConfig {
    SelfHealConfig {
        lang: ainxt_pipeline::Language::Rust,
        tier: RiskTier::Local,
        max_rounds: 2,
        ..Default::default()
    }
}

#[test]
fn r12_daemon_default_enables_deterministic_verify_and_semantic_review_stages() {
    let engine = daemon_default_engine();

    // ---- (1) deterministic verify LIVE: a broken edit blocks at Stage::Compile ----
    let mut sink = MemorySink::new();
    let mut j = Journal::new("r12-daemon-broken");
    let broken = EditTurn {
        edit_id: "r12-daemon-broken".into(),
        original_files: vec![("src/a.rs".into(), CLEAN.into())],
        applied_files: vec![("src/a.rs".into(), BROKEN.into())],
        config: cfg(),
    };
    match engine.run_turn(broken, &mut sink, &mut j) {
        TurnOutcome::HandedToHuman { outcome, .. } => {
            assert_eq!(
                outcome.stage(),
                Stage::Compile,
                "deterministic verify must own the fail on the daemon-default engine"
            );
        }
        TurnOutcome::Committed { .. } => panic!("a broken edit must never commit"),
    }
    assert_eq!(sink.files.get("src/a.rs").map(String::as_str), Some(CLEAN));

    // ---- (2) Architecture + Regression stages are enabled (journal a StageResult on a clean turn) ----
    let mut sink = MemorySink::new();
    let mut j = Journal::new("r12-daemon-clean");
    let clean = EditTurn {
        edit_id: "r12-daemon-clean".into(),
        original_files: vec![("src/a.rs".into(), CLEAN.into())],
        applied_files: vec![("src/a.rs".into(), "fn f() -> i32 {\n    2\n}\n".into())],
        config: cfg(),
    };
    let out = engine.run_turn(clean, &mut sink, &mut j);
    let stages = journaled_stages(&j);
    assert!(
        stages.contains(&Stage::Architecture),
        "Architecture (stage 7) must be enabled on the daemon default; journaled: {stages:?}"
    );
    assert!(
        stages.contains(&Stage::Regression),
        "Regression (stage 8) must be enabled on the daemon default; journaled: {stages:?}"
    );
    // The deterministic Compile stage also runs on the clean turn.
    assert!(stages.contains(&Stage::Compile));

    // ---- (3) model/infra stages are honestly NOT faked (needs_hot_wiring) ----
    assert!(
        !stages.contains(&Stage::LlmReview),
        "LLM Review must NOT be faked without a wired reviewer/judge: {stages:?}"
    );
    assert!(
        !stages.contains(&Stage::Perf),
        "Performance analysis (stage 6) must NOT be faked without a wired benchmark harness: {stages:?}"
    );

    // R15: with the deterministic-verify honesty fix, Lint/TypeCheck/Test on the air-gapped daemon
    // default are honestly `Skipped` (no live linter/type-checker/test-runner wired) rather than a
    // fabricated `Pass` — so, combined with the real (also honest) 0%-blast-radius-coverage penalty
    // from Regression, this single-file edit with no covering test correctly does NOT silently
    // auto-complete on the daemon default; it is hand-off for human/CI confirmation instead of a false
    // "done". This is the intended tightening, not a regression: before this fix the fabricated
    // Lint/TypeCheck/Test `Pass`es papered over the exact same unverified edit.
    assert_eq!(j.verify(), Ok(()), "the hash-chained journal must verify");
    match out {
        TurnOutcome::HandedToHuman { outcome, .. } => {
            assert_eq!(
                outcome.stage(),
                Stage::CommitGate,
                "an edit with no covering test and no wired tool hooks must be handed to a human at \
                 the Commit Gate, not silently completed: {outcome:?}"
            );
        }
        TurnOutcome::Committed { .. } => {
            panic!(
                "an unverified, uncovered edit must not silently auto-commit on the honest default"
            )
        }
    }
    // Nothing broken was durably written either — the pre-edit content is still what is on disk.
    assert_eq!(sink.files.get("src/a.rs").map(String::as_str), Some(CLEAN));
}
