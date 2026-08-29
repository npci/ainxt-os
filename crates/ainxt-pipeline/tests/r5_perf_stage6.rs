// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R5 gap: **Performance Analysis (stage 6) wired into the review pipeline.**
//!
//! Before this round `Stage::Perf` was declared but executed nowhere, and the Confidence Score's
//! `perf_regression_penalty` was a caller-supplied scalar the self-heal loop hard-coded to `0` — so a
//! change that doubled the cost of a hot settlement path scored identically to a no-op, and no
//! benchmark / complexity / model-advisory code existed at all.
//!
//! This test drives the REAL surface entrypoint a served daemon holds — one [`EditEngine`] assembled
//! once from `Arc` seams (now with perf wired via [`EditEngine::with_perf`]), cloned across turns — and
//! proves stage 6 now actually runs and feeds the gate:
//!
//! * **fail-before / pass-after** — `EditEngine::with_perf`, `run_edit_turn_with_perf`, `PerfConfig`,
//!   `ScriptedBench`, and the whole `ainxt_pipeline::perf` module did not exist, so this file did not
//!   compile against the pre-round crate; it compiles and passes against the wired one.
//! * a **benchmark regression** on a hot path lowers the committed Confidence Score and surfaces an
//!   honest `Stage::Perf` Advisory in the tamper-evident journal — while remaining **non-gating** (a
//!   necessary slowdown still commits, in the spot-audit band, never a silent block);
//! * the SAME edit through a perf-DISABLED engine commits at full confidence — isolating perf as the
//!   cause of the deduction;
//! * the **AST-complexity heuristic** deducts with NO benchmark harness present (the common case);
//! * a **model advisory** is surfaced in the journal but never inflates or deflates the numeric score.

use std::sync::Arc;

use ainxt_pipeline::edit_turn::{run_edit_turn_with_perf, EditEngine, EditTurn, TurnOutcome};
use ainxt_pipeline::journal::{Journal, PipelineEvent};
use ainxt_pipeline::perf::{
    BenchSample, BenchSuite, ComplexityDelta, NoAdvisor, NoBench, PerfAdvisor, PerfBudget,
    PerfConfig, PerfFinding, ScriptedBench,
};
use ainxt_pipeline::sast::BuiltinScanner;
use ainxt_pipeline::selfheal::{Coder, Observation, SelfHealConfig};
use ainxt_pipeline::stage::{Stage, StageVerdict};
use ainxt_pipeline::stages::ScriptedTools;
use ainxt_pipeline::{capability::Language, risk::RiskTier};
use ainxt_semantic::workspace::MemorySink;

/// A coder that never changes anything — a clean edit needs no heal.
struct NoOpCoder;
impl Coder for NoOpCoder {
    fn fix(&self, _r: u8, files: &[(String, String)], _o: &Observation) -> Vec<(String, String)> {
        files.to_vec()
    }
}

fn cfg() -> SelfHealConfig {
    SelfHealConfig {
        lang: Language::Rust,
        tier: RiskTier::Local,
        max_rounds: 3,
        stuck: None,
        ..Default::default()
    }
}

/// The Perf stage report the pipeline journaled this turn (there is exactly one per completed pass).
fn journaled_perf_verdict(j: &Journal) -> Option<StageVerdict> {
    j.records().iter().find_map(|r| match &r.event {
        PipelineEvent::StageResult {
            stage: Stage::Perf,
            verdict,
            ..
        } => Some(verdict.clone()),
        _ => None,
    })
}

#[test]
fn r5_perf_stage6() {
    // ---- (1) A benchmark regression on a hot path, through the surface entrypoint a daemon holds.
    // The post-edit set carries a `slow_path` marker so the scripted harness measures it slower.
    let bench = ScriptedBench::new()
        // after (contains both markers) → the slow measurement wins (rule order: first match).
        .when_contains(
            "slow_path",
            BenchSuite::new(vec![BenchSample {
                name: "hot".into(),
                nanos: 200,
            }]),
        )
        // baseline (contains only "fn hot") → the fast measurement.
        .when_contains(
            "fn hot",
            BenchSuite::new(vec![BenchSample {
                name: "hot".into(),
                nanos: 100,
            }]),
        );

    let engine = EditEngine::new(
        Arc::new(NoOpCoder),
        Arc::new(ScriptedTools::default()),
        Arc::new(BuiltinScanner),
    )
    .with_perf(Arc::new(bench), Arc::new(NoAdvisor), PerfBudget::default());

    let turn = EditTurn {
        edit_id: "r5-bench".into(),
        original_files: vec![("hot.rs".into(), "fn hot() -> i32 { 1 }\n".into())],
        applied_files: vec![(
            "hot.rs".into(),
            "fn hot() -> i32 { 2 /* slow_path */ }\n".into(),
        )],
        config: cfg(),
    };
    let mut sink = MemorySink::new();
    let mut journal = Journal::new("r5-bench");
    let out = engine.run_turn(turn, &mut sink, &mut journal);

    // A 100ns→200ns (2x) regression, budget 10% → the full 25-point perf penalty → score 75. That is
    // in the review/spot-audit band, so it STILL commits (perf is non-gating) but at a lowered score.
    match out {
        TurnOutcome::Committed { approval, .. } => {
            assert_eq!(
                approval.confidence(),
                75,
                "perf regression should cost 25 pts"
            );
            assert!(
                approval.spot_audit(),
                "a lowered score commits with a spot-audit flag"
            );
        }
        other => panic!("perf is non-gating — a real regression must still commit, got {other:?}"),
    }
    assert!(
        sink.files["hot.rs"].contains("slow_path"),
        "the edit was durably applied"
    );
    // The honest Stage::Perf report is in the tamper-evident journal as an Advisory naming the cause.
    let perf_verdict =
        journaled_perf_verdict(&journal).expect("Stage::Perf must have run + journaled");
    match perf_verdict {
        StageVerdict::Advisory { detail } => assert!(
            detail.contains("benchmark regression"),
            "perf advisory should name the regression, got: {detail}"
        ),
        other => panic!("expected a Perf Advisory, got {other:?}"),
    }
    assert_eq!(journal.verify(), Ok(()));

    // ---- (2) ISOLATION: the identical edit through a perf-DISABLED engine commits at FULL confidence,
    //          proving perf (not something else) caused the deduction above.
    let plain = EditEngine::new(
        Arc::new(NoOpCoder),
        Arc::new(ScriptedTools::default()),
        Arc::new(BuiltinScanner),
    );
    let turn = EditTurn {
        edit_id: "r5-noperf".into(),
        original_files: vec![("hot.rs".into(), "fn hot() -> i32 { 1 }\n".into())],
        applied_files: vec![(
            "hot.rs".into(),
            "fn hot() -> i32 { 2 /* slow_path */ }\n".into(),
        )],
        config: cfg(),
    };
    let mut sink = MemorySink::new();
    let mut journal = Journal::new("r5-noperf");
    let out = plain.run_turn(turn, &mut sink, &mut journal);
    match out {
        TurnOutcome::Committed { approval, .. } => {
            assert_eq!(approval.confidence(), 100);
            assert!(!approval.spot_audit());
        }
        other => panic!("expected a clean full-confidence commit, got {other:?}"),
    }
    // With perf disabled, Stage::Perf never ran → no Perf record in the journal.
    assert!(journaled_perf_verdict(&journal).is_none());

    // ---- (3) The AST-complexity heuristic deducts with NO benchmark harness present. A large branch
    //          explosion over the budget lowers the score even though `NoBench` measures nothing.
    let complex_after =
        "fn hot() -> i32 {\n    if a && b { if c { 1 } else if d { 2 } else { 3 } } \
                         else { while e {} for _ in 0..n {} match m { _ => 0 } }\n}\n";
    let turn = EditTurn {
        edit_id: "r5-complexity".into(),
        original_files: vec![("hot.rs".into(), "fn hot() -> i32 { 1 }\n".into())],
        applied_files: vec![("hot.rs".into(), complex_after.into())],
        config: cfg(),
    };
    let mut sink = MemorySink::new();
    let mut journal = Journal::new("r5-complexity");
    let out = run_edit_turn_with_perf(
        turn,
        &NoOpCoder,
        &ScriptedTools::default(),
        &BuiltinScanner,
        Some(PerfConfig {
            bench: &NoBench,
            advisor: &NoAdvisor,
            budget: PerfBudget::default(),
        }),
        &mut sink,
        &mut journal,
    );
    match out {
        TurnOutcome::Committed { approval, .. } => {
            assert!(
                approval.confidence() < 100,
                "an over-budget complexity jump must lower the score with no benchmark at all"
            );
        }
        other => panic!("a complexity-only deduction is still non-gating, got {other:?}"),
    }
    match journaled_perf_verdict(&journal).expect("Stage::Perf must run on the complexity path") {
        StageVerdict::Advisory { detail } => assert!(detail.contains("AST complexity")),
        other => panic!("expected a complexity Advisory, got {other:?}"),
    }

    // ---- (4) A MODEL ADVISORY is surfaced but NEVER a term in the numeric score (anti-sycophancy).
    struct HotPathAdvisor;
    impl PerfAdvisor for HotPathAdvisor {
        fn review(
            &self,
            _l: Language,
            _b: &[(String, String)],
            _a: &[(String, String)],
            _c: &ComplexityDelta,
        ) -> Vec<PerfFinding> {
            vec![PerfFinding {
                message: "allocation inside the settlement loop".into(),
                hot_path: true,
            }]
        }
    }
    // A trivial, within-budget edit: zero deterministic penalty. The advisor still fires.
    let turn = EditTurn {
        edit_id: "r5-advisory".into(),
        original_files: vec![("hot.rs".into(), "fn hot() -> i32 { 1 }\n".into())],
        applied_files: vec![("hot.rs".into(), "fn hot() -> i32 { 2 }\n".into())],
        config: cfg(),
    };
    let mut sink = MemorySink::new();
    let mut journal = Journal::new("r5-advisory");
    let out = run_edit_turn_with_perf(
        turn,
        &NoOpCoder,
        &ScriptedTools::default(),
        &BuiltinScanner,
        Some(PerfConfig {
            bench: &NoBench,
            advisor: &HotPathAdvisor,
            budget: PerfBudget::default(),
        }),
        &mut sink,
        &mut journal,
    );
    match out {
        TurnOutcome::Committed { approval, .. } => {
            // The model advisory did NOT lower the score — full confidence despite the "hot path" note.
            assert_eq!(
                approval.confidence(),
                100,
                "a model advisory must not deflate the numeric score"
            );
        }
        other => panic!("expected a clean commit with only an advisory, got {other:?}"),
    }
    // ...yet it is surfaced in the journal for the reviewer.
    match journaled_perf_verdict(&journal).expect("Stage::Perf must run") {
        StageVerdict::Advisory { detail } => assert!(detail.contains("settlement loop")),
        other => panic!("expected the advisory surfaced as a Perf Advisory, got {other:?}"),
    }
}
