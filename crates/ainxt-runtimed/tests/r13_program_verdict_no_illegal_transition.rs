// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! r13_program_verdict_no_illegal_transition — fixes a real, previously-latent bug in
//! `run_program_verified_blocking` (`program_exec.rs`): when a module's three-way gate came back
//! non-`Complete`, the code called BOTH `program.record_verdict(..)` (whose own state-machine
//! apply-logic already demotes the node `InProgress → Pending` on any non-Complete outcome — a
//! fully-handled failed attempt) AND `program.fail_node(..)` on the SAME branch — which requires the
//! node to still be `InProgress`/`Verifying`. It never is by that point, so `apply()` raised
//! `IllegalNodeTransition { from: Ready, to: Pending }`.
//!
//! This was 100% dead code before now: `EngineRunExecutor::execute_module` has always returned a
//! hardcoded `JudgeVerdict::pass(95, 80, ..)`, so `three_way_gate` was always `Complete` and the
//! non-Complete branch never ran in any test. This test reproduces a genuine non-Complete verdict
//! WITHOUT touching the Judge/Breaker scoring at all: `three_way_gate`'s own cross-model-violation
//! check (`ainxt_planner::verify`) fires whenever `judge.producer_model == judge.judge_model` —
//! `EngineRunExecutor` always sets `judge_model = "runtime-judge"`, so a provider whose `id()` is
//! ALSO `"runtime-judge"` deterministically forces exactly the non-Complete branch this bug lived in,
//! with zero changes to any judge/breaker/assurance code.
//!
//! Fail-before/pass-after: before the fix, this test's `run_program_verified_sod` call panics with
//! `IllegalNodeTransition`. After the fix, the same non-Complete verdict is handled once (by
//! `record_verdict` alone), the node returns to the schedulable pool, retries up to the attempt cap,
//! and the Run ends in an honest `CappedPartial` — never a panic, never a fabricated `Completed`.

use ainxt_planner::program::{NodeClass, NodeDecl, ProgramOutcome};
use ainxt_protocol::Event;
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_runtime::{engine_with_defaults, Engine};
use ainxt_runtimed::{run_program_verified_sod, RunIdentitySpec, SodApprover};
use ainxt_types::DataClass;
use std::sync::Arc;
use tokio::sync::mpsc;

/// A provider whose `id()` is deliberately `"runtime-judge"` — the SAME literal
/// `EngineRunExecutor::execute_module` hardcodes as `JudgeVerdict`'s `judge_model`. Since the
/// verdict's `producer_model` is always the serving provider's id, this collides the cross-model
/// check on purpose, forcing a genuine non-`Complete` three-way gate outcome deterministically.
struct SameAsJudgeProvider;
impl Provider for SameAsJudgeProvider {
    fn id(&self) -> &str {
        "runtime-judge"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, _prompt: &str) -> mpsc::Receiver<Event> {
        let (tx, rx) = mpsc::channel(8);
        tokio::spawn(async move {
            let _ = tx
                .send(Event::TextDelta("some real work product".into()))
                .await;
            let _ = tx.send(Event::Done).await;
        });
        rx
    }
}

fn engine() -> Arc<Engine> {
    let mut router = ModelRouter::new();
    router.register(Box::new(SameAsJudgeProvider));
    Arc::new(engine_with_defaults(router))
}

#[tokio::test(flavor = "multi_thread")]
async fn r13_non_complete_verdict_never_panics_and_ends_capped_not_completed() {
    let identity = RunIdentitySpec::new(
        "agent",
        "r13-illegal-transition",
        "run-r13-illegal-transition",
        DataClass::Internal,
        "u-alice",
    );
    let nodes = vec![NodeDecl::new("mod-a", NodeClass::MigrationRun)];

    // Before the fix: this call panics with `IllegalNodeTransition { from: Ready, to: Pending }`
    // the first time the module's verdict comes back non-Complete. After the fix: it returns
    // cleanly with an honest CappedPartial (the cross-model violation can never resolve to Complete,
    // so every retry fails the SAME way, exhausting the attempt cap without ever committing).
    let run = run_program_verified_sod(
        engine(),
        identity,
        "do some real work",
        nodes,
        None,
        None,
        SodApprover::Distinct,
        ainxt_runtime::CancelToken::new(),
    )
    .await
    .expect("a non-Complete verdict must be handled cleanly, never panic");

    assert_eq!(
        run.outcome,
        ProgramOutcome::CappedPartial,
        "a module that can never pass the cross-model check must end honestly capped, not \
         Completed and not an error: {:?}",
        run.outcome
    );
    assert_eq!(
        run.program.state().committed_node_ids().len(),
        0,
        "a permanently-non-Complete module must never commit"
    );
    assert_eq!(
        run.sod_approvals, 0,
        "no commit occurred, so no SoD authorization should have been counted"
    );
}
