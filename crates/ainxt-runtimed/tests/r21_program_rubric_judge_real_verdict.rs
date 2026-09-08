// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! r21 (gap6-planner-assurance-revision, item 1) — `ainxt_planner::assurance::RubricJudge` was fully
//! built, unit-tested against `three_way_gate`, and documented as the semantic-Judge matched pair to
//! `AdversarialBreaker` (which a prior round already wired into
//! `ainxt_teams::tiers::BreakerAdversarialGate`) — but the served long-horizon Program driver never
//! called it: `program_exec.rs`'s `EngineRunExecutor::execute_module`, `ServedModuleJudge::judge`, and
//! `ServedProgramVerifier::program_judge` all fabricated a FIXED `JudgeVerdict::pass(95, 80, ..)`
//! regardless of what the engine turn actually produced, so "three-way verification" on the served
//! Program path collapsed to the deterministic gate alone (the Judge could never catch a bad module).
//!
//! This proves the fix through the REAL served composition-root entrypoint
//! (`drive_served_program_governed`, the exact function `ProgramSurface::handle_turn` calls) with the
//! offline default `ProgramProofSeams::offline_default()` (no injected fault — every proof, including
//! the Judge, is now genuinely derived from the real turn). A test-double `Provider` stands in for the
//! live model (no shipped `Provider` adapter parses this codebase's engine responses beyond raw text —
//! the same substitution every other content-dependent test in this suite uses, e.g.
//! `gap5_transport_payment_boundary_served.rs`), but the Judge under test, the gate combinator, and the
//! Program driver are all the REAL production code.
//!
//! * A single-node program whose engine turn produces a substantive, on-goal, tested, safe artifact
//!   (byte-for-byte the artifact `ainxt_planner::assurance`'s own
//!   `judge_score_varies_with_content_and_is_cross_model` unit test already proves scores >= threshold)
//!   must reach `ProgramOutcome::Completed` with the node committed.
//! * The SAME program, same goal, same graph shape — the ONLY thing that changes is the engine turn's
//!   produced text, now a bare `"// TODO"` stub (the exact off-goal/incomplete artifact that unit test
//!   proves scores far below threshold) — must now be REFUSED: `ProgramOutcome::CappedPartial`, zero
//!   nodes committed. Before this fix both runs reached `Completed` regardless of content, because the
//!   Judge was a fixed 95/80 pass no matter what text the engine produced.
//!
//! The engine's own deterministic + adversarial verdicts (`verdict_for_observation`) are IDENTICAL
//! green in both runs (both texts are non-empty and the turn completes without error) — isolating the
//! Judge as the ONLY proof that can explain the outcome flipping between the two runs.

use std::sync::Arc;

use ainxt_planner::program::{NodeClass, NodeDecl, ProgramOutcome};
use ainxt_protocol::Event;
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_runtime::{engine_with_defaults, CancelToken};
use ainxt_runtimed::{
    drive_served_program_governed, ProgramProofSeams, RunIdentitySpec, ServedProgramGovernance,
    SodApprover,
};
use ainxt_types::DataClass;
use tokio::sync::mpsc;

/// A test-double model [`Provider`] that always streams the SAME fixed text, regardless of prompt —
/// the standard substitution this workspace's own tests use to control produced content deterministically
/// (no shipped adapter parses a live model's response beyond raw text yet). Mirrors `OfflineProvider`'s
/// shape (`ainxt_runtimed::lib.rs`) and `OneToolProvider` (`gap5_transport_payment_boundary_served.rs`).
struct FixedTextProvider {
    text: String,
}

impl Provider for FixedTextProvider {
    fn id(&self) -> &str {
        "r21-test-producer"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, _prompt: &str) -> mpsc::Receiver<Event> {
        let (tx, rx) = mpsc::channel(8);
        let text = self.text.clone();
        tokio::spawn(async move {
            let _ = tx.send(Event::TextDelta(text)).await;
            let _ = tx.send(Event::Done).await;
        });
        rx
    }
}

/// The exact goal `ainxt_planner::assurance::assurance::tests::good_artifact` (and its paired bad case)
/// scores against — reused verbatim so this served-path proof rides the SAME already-unit-tested
/// content, just driven through the real composition root instead of calling `RubricJudge` directly.
const GOAL: &str = "validate the settlement amount and reject negative values";

/// Byte-for-byte the substantive, on-goal, boundary-tested artifact
/// `ainxt_planner::assurance::tests::good_artifact` uses — already proven (in that unit test) to score
/// >= the RubricJudge's default threshold of 80.
const GOOD_TEXT: &str = "fn validate(amount: i64) -> Result<(), Error> { if amount < 0 { return Err(Error::Negative); } Ok(()) }\n#[test] fn rejects_negative_and_zero_boundary() { assert!(validate(-1).is_err()); assert!(validate(0).is_ok()); }";

/// A bare unfinished-stub marker — the exact shape `ainxt_planner::assurance::tests::judge_score_varies_with_content_and_is_cross_model`
/// proves scores far below threshold (substance ~0, completeness 0 for the `todo` stub marker,
/// goal-relevance 0 — none of the goal's keywords appear in it).
const BAD_TEXT: &str = "// TODO";

fn one_node() -> Vec<NodeDecl> {
    vec![NodeDecl::new("n1", NodeClass::MigrationRun)]
}

fn engine_with_fixed_text(text: &str) -> Arc<ainxt_runtime::Engine> {
    let mut router = ModelRouter::new();
    router.register(Box::new(FixedTextProvider {
        text: text.to_string(),
    }));
    Arc::new(engine_with_defaults(router))
}

#[tokio::test(flavor = "multi_thread")]
async fn r21_a_genuinely_good_artifact_passes_the_real_rubric_judge_and_completes() {
    let engine = engine_with_fixed_text(GOOD_TEXT);
    let run = drive_served_program_governed(
        engine,
        RunIdentitySpec::new(
            "agent",
            "r21-good",
            "run-good",
            DataClass::Internal,
            "u-alice",
        ),
        GOAL,
        one_node(),
        None,
        None,
        None,
        SodApprover::Distinct,
        CancelToken::new(),
        ProgramProofSeams::offline_default(),
        ServedProgramGovernance::served_default(),
    )
    .await
    .expect("a genuinely good artifact must drive to a clean terminal outcome");

    assert_eq!(
        run.outcome,
        ProgramOutcome::Completed,
        "a substantive, on-goal, tested, safe artifact must pass the REAL RubricJudge (score >= 80) \
         and reach Completed — before this fix the Judge was a fabricated fixed pass(95, 80) that would \
         have let ANY content through identically"
    );
    assert_eq!(
        run.program.state().committed_node_ids().len(),
        1,
        "the single node must have actually committed"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn r21_a_genuinely_bad_artifact_fails_the_real_rubric_judge_and_never_completes() {
    let engine = engine_with_fixed_text(BAD_TEXT);
    let run = drive_served_program_governed(
        engine,
        RunIdentitySpec::new(
            "agent",
            "r21-bad",
            "run-bad",
            DataClass::Internal,
            "u-alice",
        ),
        GOAL,
        one_node(),
        None,
        None,
        None,
        SodApprover::Distinct,
        CancelToken::new(),
        ProgramProofSeams::offline_default(),
        ServedProgramGovernance::served_default(),
    )
    .await
    .expect("an exhausted-attempts quarantine is a clean terminal outcome, never an error");

    assert_eq!(
        run.outcome,
        ProgramOutcome::CappedPartial,
        "a bare '// TODO' stub — non-empty, so the deterministic + adversarial verdicts are IDENTICAL \
         green to the good run above — must now be REFUSED by the REAL, content-varying RubricJudge \
         (score far below 80: no goal keywords, a stub marker, near-zero substance). Before this fix \
         the fabricated pass(95, 80) would have committed this stub exactly like the good artifact."
    );
    assert_eq!(
        run.program.state().committed_node_ids().len(),
        0,
        "the stub must never have committed — the real Judge, not the deterministic/adversarial gate, \
         is what blocks it (both of those are green for any non-empty completed turn)"
    );
}
