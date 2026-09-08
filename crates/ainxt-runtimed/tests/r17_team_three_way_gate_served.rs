// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! r17 (loop-teams-longhorizon) — the LOOP §7 anti-sycophancy three-way gate
//! (`ainxt_teams::tiers::run_team_3tier_verified_cancellable` + the offline-default
//! `ContentDeterministicGate` / `BreakerAdversarialGate`) had ZERO callers from the served composition
//! root: `drive_served_team_blocking` (the function `TeamSurface` — the `TurnHandler` mounted on
//! `POST /v1/chat` by `assemble_team_surface` — actually drives) called the judge-ONLY
//! `run_team_3tier_cancellable`, and the served judge (`ConfirmingGoalJudge`) confirms as soon as ANY
//! task produces a non-empty output, regardless of content. That is exactly the "textbook sycophancy
//! failure" `run_team_3tier_verified`'s own module doc names: a judge talked into agreement on a
//! stubbed/broken deliverable could single-handedly complete a served team Run.
//!
//! A second, related gap made the fix meaningful rather than cosmetic: `EngineRunExecutor::run_task`
//! (the tier-1 executor backing every served task) set `output_ref` to a synthetic
//! `artifact://<task>#<len>` reference — never the real produced text — so even if the three-way gate
//! were wired in, `ContentDeterministicGate` / `BreakerAdversarialGate` would only ever inspect a
//! meaningless length-tagged string that can never contain a stub marker or a PAN-shaped literal.
//!
//! Fail-before/pass-after: before the fix, a served team turn whose engine backing always returns a
//! stub ("`todo!()`") completes with `TeamOutcome::Complete` (the judge sees non-empty output and
//! confirms; the fabricated `output_ref` could not have caught it even if a gate were wired in). After
//! the fix, the SAME scenario ends an honest `TeamOutcome::Capped`. A genuine, substantive deliverable
//! (this file's second test) still completes — the fix does not turn the served path into a
//! false-positive machine.
//!
//! GAP-AUDIT loop-teams-longhorizon (tier2/tier3 rubber-stamp, a later round): `drive_served_team_
//! blocking` ALSO wired `AcceptingCritic` at tier 2 — every step "served" regardless of content — so
//! in practice the stub above was only ever caught by the tier-3 gates two full judge-rounds later.
//! With `ContentStepCritic` now wired at tier 2, the SAME stub is instead caught immediately: the
//! per-step critic rejects it, the stuck detector aborts the task after the identical deficiency
//! repeats, and its dependents are bulkhead-blocked — the Run still ends the same honest `Capped`, now
//! via the cheaper, earlier tier-2 catch. The three-way gate remains the backstop for content that
//! passes tier 2 but is still off-goal at the whole-deliverable level (proven in isolation by
//! `ainxt-teams`'s `r15_three_way_gate_and_depth_cap.rs`).

use std::sync::Arc;

use ainxt_protocol::Event;
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_runtime::{engine_with_defaults, CancelToken, Engine};
use ainxt_runtimed::{compose_served_team, drive_served_team, RunIdentitySpec};
use ainxt_teams::tiers::TeamOutcome;
use ainxt_types::DataClass;
use tokio::sync::mpsc;

/// A provider whose response is fixed content, independent of the prompt — deterministic and cheap to
/// reason about, matching the pattern `r13_program_verdict_no_illegal_transition.rs` uses for the
/// Program path.
struct FixedTextProvider {
    id: &'static str,
    text: &'static str,
}
impl Provider for FixedTextProvider {
    fn id(&self) -> &str {
        self.id
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, _prompt: &str) -> mpsc::Receiver<Event> {
        let (tx, rx) = mpsc::channel(8);
        let text = self.text.to_string();
        tokio::spawn(async move {
            let _ = tx.send(Event::TextDelta(text)).await;
            let _ = tx.send(Event::Done).await;
        });
        rx
    }
}

fn engine_with_fixed_text(id: &'static str, text: &'static str) -> Arc<Engine> {
    let mut router = ModelRouter::new();
    router.register(Box::new(FixedTextProvider { id, text }));
    Arc::new(engine_with_defaults(router))
}

#[tokio::test(flavor = "multi_thread")]
async fn r17_served_team_blocks_a_confidently_stubbed_deliverable() {
    // Every task turn returns the SAME unfinished-stub marker. `ConfirmingGoalJudge` alone would
    // confirm (non-empty output), which is exactly the pre-fix served behavior this test proves is
    // gone. GAP-AUDIT loop-teams-longhorizon (tier2/tier3 rubber-stamp): `drive_served_team_blocking`
    // now wires `ContentStepCritic` at tier 2 (the SAME real content check `ContentDeterministicGate`
    // runs at tier 3, scoped to one step), so the stub is caught immediately at the per-step critic —
    // the architect and independent tester tasks each get stuck (the SAME deficiency repeats every
    // attempt) and fail before ever reaching tier 3, and their dependents (`code`, `review`) are
    // bulkhead-blocked, never attempted. The three-way gate (det/adv gates) remains the backstop for a
    // step that *would* pass tier 2 but is still off-goal at the whole-deliverable level (see
    // `r15_three_way_gate_and_depth_cap.rs` in `ainxt-teams` for that scenario in isolation) — this
    // test's job is only to prove the end-to-end served path still ends an honest `Capped`, now via
    // the EARLIER, cheaper tier-2 catch rather than surviving to the tier-3 audit.
    let engine = engine_with_fixed_text("stub-model", "fn placeholder() { todo!() }");
    let identity = RunIdentitySpec::new(
        "agent",
        "r17-team-stub",
        "run-r17-team-stub",
        DataClass::Internal,
        "u-r17",
    );
    let (graph, team, seed) = compose_served_team("ship the feature").unwrap();

    let run = drive_served_team(
        engine,
        identity,
        graph,
        team,
        "ship the feature",
        seed,
        Default::default(),
        None,
        None,
        None,
        CancelToken::new(),
    )
    .await
    .expect("a stubbed deliverable must be handled cleanly, never panic or error");

    assert!(
        matches!(run.report.outcome, TeamOutcome::Capped { .. }),
        "a served team run whose every task produces an unfinished stub must end an honest Capped, \
         never a fabricated Complete: {:?}",
        run.report.outcome
    );
    // The tier-2 critic must have actually inspected the content and rejected it (not a rubber-stamp)
    // — the self-heal audit trail names the SAME real finding `ContentDeterministicGate` would report.
    assert!(
        run.report.self_heal.iter().any(|e| e.kind == ainxt_teams::tiers::SelfHealKind::CriticRejected
            && e.detail.contains("todo!")),
        "tier 2 (ContentStepCritic) must reject the stub with an attributable, content-based reason, \
         not silently accept it like the pre-fix AcceptingCritic would: {:#?}",
        run.report.self_heal
    );
    // The identical stub reproduces on every retry, so the deterministic stuck detector — not just an
    // exhausted attempt budget — is what ultimately aborts each affected task.
    assert!(
        run.report
            .self_heal
            .iter()
            .any(|e| e.kind == ainxt_teams::tiers::SelfHealKind::Stuck),
        "a step that never improves must trip the stuck detector, not silently retry forever: {:#?}",
        run.report.self_heal
    );
    // Every turn that DID run was real (never a synthetic placeholder) and carried the stub text, and
    // the run never fabricated success by skipping turns — this is a content judgement, not starvation.
    let task_turns: Vec<_> = run
        .turns
        .iter()
        .filter(|t| t.label.starts_with("task:"))
        .collect();
    assert!(
        !task_turns.is_empty(),
        "the block must follow real engine turns, not zero-turn starvation"
    );
    assert!(task_turns.iter().all(|t| t.ok && t.text.contains("todo!")));
}

#[tokio::test(flavor = "multi_thread")]
async fn r17_served_team_completes_a_genuine_substantive_deliverable() {
    // A real, substantive, on-goal produced artifact with no stub markers and no PAN-shaped literal —
    // the three-way gate's happy path. Proves the wiring is not a false-positive machine: a served team
    // whose tasks produce real content still reaches Complete.
    let engine = engine_with_fixed_text(
        "real-model",
        "fn validate_settlement(amount: i64) -> Result<(), String> { \
         if amount < 0 { return Err(\"negative settlement amount rejected\".into()); } Ok(()) }",
    );
    let identity = RunIdentitySpec::new(
        "agent",
        "r17-team-good",
        "run-r17-team-good",
        DataClass::Internal,
        "u-r17",
    );
    let (graph, team, seed) = compose_served_team("ship the feature").unwrap();

    let run = drive_served_team(
        engine,
        identity,
        graph,
        team,
        "ship the feature",
        seed,
        Default::default(),
        None,
        None,
        None,
        CancelToken::new(),
    )
    .await
    .expect("a genuine deliverable must run cleanly");

    assert_eq!(
        run.report.outcome,
        TeamOutcome::Complete,
        "a served team run producing real, substantive, on-goal content across every task must still \
         reach Complete — the anti-sycophancy wiring must not false-positive on good work: {:?}",
        run.report.outcome
    );
    assert!(run.report.last_run.all_succeeded());
}

/// Regression guard for the companion fix: `EngineRunExecutor::run_task` must set `output_ref` to the
/// REAL produced text, not a synthetic `artifact://<task>#<len>` reference — otherwise the two tests
/// above could never distinguish a stub from real content (both gates would be auditing a placeholder
/// string that can never contain a stub marker). Proven indirectly: the "stub" test above blocks and
/// the "genuine" test completes on the SAME wiring, which is only possible if the gates see real text.
#[tokio::test(flavor = "multi_thread")]
async fn r17_output_ref_carries_real_text_not_a_synthetic_placeholder() {
    let engine = engine_with_fixed_text("stub-model-2", "todo!()");
    let identity = RunIdentitySpec::new(
        "agent",
        "r17-team-outputref",
        "run-r17-team-outputref",
        DataClass::Internal,
        "u-r17",
    );
    let (graph, team, seed) = compose_served_team("ship the feature").unwrap();
    let run = drive_served_team(
        engine,
        identity,
        graph,
        team,
        "ship the feature",
        seed,
        Default::default(),
        None,
        None,
        None,
        CancelToken::new(),
    )
    .await
    .unwrap();
    // A synthetic `artifact://task#7` reference would never contain the literal stub text, yet the
    // engine turn's own observation does (proving the same real string is what the gates now see).
    let task_turns: Vec<_> = run
        .turns
        .iter()
        .filter(|t| t.label.starts_with("task:"))
        .collect();
    assert!(task_turns.iter().all(|t| t.text == "todo!()"));
    assert!(matches!(run.report.outcome, TeamOutcome::Capped { .. }));
}
