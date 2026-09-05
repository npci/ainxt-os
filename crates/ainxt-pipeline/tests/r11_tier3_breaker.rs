// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-11 — the **optional Tier-3 Breaker differential/invariant run** wired onto the served edit
//! engine (`CODE_REVIEW_PIPELINE.md` §3 Tier 3 / §8 high-risk escalation). `EditEngine::with_breaker`
//! installs a differential oracle that is consulted **only** for Tier-3 (critical-path/high-risk)
//! edits, and whose result is journaled onto the tamper-evident Event Log for the mandatory human
//! hand-off. Below Tier 3 the oracle is never consulted (no differential run on a trivial edit).
//!
//! Fail-before: `with_breaker` / `DifferentialOracle` / `ScriptedBreaker` / the `BreakerDifferential`
//! journal event did not exist before round-11.

use ainxt_pipeline::journal::{Journal, PipelineEvent};
use ainxt_pipeline::sast::BuiltinScanner;
use ainxt_pipeline::stages::ScriptedTools;
use ainxt_pipeline::{
    Coder, EditEngine, EditTurn, Observation, RiskTier, ScriptedBreaker, SelfHealConfig,
};
use ainxt_semantic::workspace::MemorySink;
use std::sync::Arc;

struct NoOpCoder;
impl Coder for NoOpCoder {
    fn fix(&self, _r: u8, files: &[(String, String)], _o: &Observation) -> Vec<(String, String)> {
        files.to_vec()
    }
}

fn engine_with_breaker() -> EditEngine {
    EditEngine::new(
        Arc::new(NoOpCoder),
        Arc::new(ScriptedTools::default()),
        Arc::new(BuiltinScanner),
    )
    .with_breaker(Arc::new(
        ScriptedBreaker::new().with_divergence_marker("REWRITE_SETTLEMENT"),
    ))
}

fn breaker_event(j: &Journal) -> Option<(usize, usize, bool)> {
    j.records().iter().find_map(|r| match &r.event {
        PipelineEvent::BreakerDifferential {
            divergences,
            invariant_violations,
            gating,
        } => Some((*divergences, *invariant_violations, *gating)),
        _ => None,
    })
}

#[test]
fn r11_tier3_edit_triggers_the_breaker_and_journals_a_gating_divergence() {
    // A critical-path (Tier-3) edit whose candidate introduces the divergence marker.
    let turn = EditTurn {
        edit_id: "t3-diverge".into(),
        original_files: vec![(
            "settlement/x.rs".into(),
            "fn settle() -> i32 { 1 }\n".into(),
        )],
        applied_files: vec![(
            "settlement/x.rs".into(),
            "fn settle() -> i32 { 2 /* REWRITE_SETTLEMENT */ }\n".into(),
        )],
        config: SelfHealConfig {
            tier: RiskTier::HighRisk,
            max_rounds: 2,
            ..Default::default()
        },
    };
    let mut sink = MemorySink::new();
    let mut j = Journal::new("t3-diverge");
    let out = engine_with_breaker().run_turn(turn, &mut sink, &mut j);

    // The breaker ran (Tier 3) and journaled a gating divergence.
    let (div, inv, gating) =
        breaker_event(&j).expect("Tier-3 edit must journal a BreakerDifferential");
    assert_eq!(div, 1);
    assert_eq!(inv, 0);
    assert!(gating, "a Tier-3 divergence is gating");
    // Tier-3 edits are a mandatory human hand-off regardless (never auto-commit).
    assert!(!out.committed());
    assert_eq!(j.verify(), Ok(()));
}

#[test]
fn r11_sub_tier3_edit_never_consults_the_breaker() {
    // The SAME engine, but a Local (Tier-1) edit that even contains the marker — the oracle must NOT
    // be consulted below Tier 3, so no BreakerDifferential event is journaled.
    let turn = EditTurn {
        edit_id: "t1-noop".into(),
        original_files: vec![("util/x.rs".into(), "fn helper() -> i32 { 1 }\n".into())],
        applied_files: vec![(
            "util/x.rs".into(),
            "fn helper() -> i32 { 2 /* REWRITE_SETTLEMENT */ }\n".into(),
        )],
        config: SelfHealConfig {
            tier: RiskTier::Local,
            max_rounds: 2,
            ..Default::default()
        },
    };
    let mut sink = MemorySink::new();
    let mut j = Journal::new("t1-noop");
    let _ = engine_with_breaker().run_turn(turn, &mut sink, &mut j);
    assert!(
        breaker_event(&j).is_none(),
        "the breaker must not be consulted below Tier 3"
    );
}

#[test]
fn r11_tier3_edit_with_no_divergence_records_a_clean_breaker_run() {
    // A Tier-3 edit that does NOT introduce the marker → the oracle is consulted and finds nothing.
    let turn = EditTurn {
        edit_id: "t3-clean".into(),
        original_files: vec![(
            "settlement/x.rs".into(),
            "fn settle() -> i32 { 1 }\n".into(),
        )],
        applied_files: vec![(
            "settlement/x.rs".into(),
            "fn settle() -> i32 { 2 }\n".into(),
        )],
        config: SelfHealConfig {
            tier: RiskTier::HighRisk,
            max_rounds: 2,
            ..Default::default()
        },
    };
    let mut sink = MemorySink::new();
    let mut j = Journal::new("t3-clean");
    let _ = engine_with_breaker().run_turn(turn, &mut sink, &mut j);
    let (div, _inv, gating) = breaker_event(&j).expect("Tier-3 edit is still consulted");
    assert_eq!(div, 0);
    assert!(
        !gating,
        "no divergence → not gating (but honestly recorded as run)"
    );
}
