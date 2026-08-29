// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R9 — the served **Program** surface threads the transport's user-stop [`CancelToken`] into the
//! long-horizon executing loop (requirement: "never stubbed green; thread the user-stop cancel token
//! into the executing loop"). Before this round the [`ProgramSurface`] ignored the transport token
//! (`_cancel`) and the driver loop used a no-op `|| false` cancel, so a user-stop could NEVER halt an
//! in-flight Program Run — it drove every module to a fabricated completion regardless.
//!
//! These two tests drive the EXACT served surface code path (`ProgramSurface::handle_turn` →
//! `run_program_verified` → the driver loop's per-module cancel check) over the air-gapped offline
//! provider, deterministically:
//!
//!   * `r9_program_surface_user_stop_drains_before_module` (FAIL-BEFORE) — a PRE-cancelled token makes
//!     the driver loop break at the FIRST module boundary: zero module turns run and the terminal
//!     outcome is an honest `CappedPartial`, never `Completed`. Before the fix the token was ignored, so
//!     the Run completed every module (this assertion would fail).
//!   * `r9_program_no_stop_runs_to_completion` (PASS-AFTER contrast) — the SAME surface + SAME goal with
//!     a fresh (never-cancelled) token drives real module turns to a `Completed` outcome, proving the
//!     drain above is caused by the threaded user-stop token, not a broken pipeline.

use ainxt_protocol::{Event, Request};
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_runtime::{engine_with_defaults, CancelToken, TurnHandler};
use ainxt_runtimed::{assemble_program, load_layered, ProgramSurface};
use ainxt_types::{DataClass, Principal};
use std::sync::Arc;

fn offline_config() -> ainxt_runtimed::LoadedConfig {
    load_layered(&[("x", "version = 1")]).unwrap()
}

/// GAP-FIX planner-assurance-revision (item 1) — a fixed-text model [`Provider`]: the served Program
/// driver's semantic Judge is now a REAL, content-varying `RubricJudge`, never a fabricated fixed pass,
/// so the air-gapped `OfflineProvider`'s prompt-invariant "offline mode: no model configured." text can
/// no longer stand in for "the Run genuinely completes" — it carries none of a real goal's keywords.
struct FixedTextProvider {
    text: String,
}
impl Provider for FixedTextProvider {
    fn id(&self) -> &str {
        "r9-test-producer"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, _prompt: &str) -> tokio::sync::mpsc::Receiver<Event> {
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        let text = self.text.clone();
        tokio::spawn(async move {
            let _ = tx.send(Event::TextDelta(text)).await;
            let _ = tx.send(Event::Done).await;
        });
        rx
    }
}

fn engine_with_fixed_text(text: &str) -> Arc<ainxt_runtime::Engine> {
    let mut router = ModelRouter::new();
    router.register(Box::new(FixedTextProvider {
        text: text.to_string(),
    }));
    Arc::new(engine_with_defaults(router))
}

/// Drive the served [`ProgramSurface`] for one turn with the supplied cancel token, returning the
/// surface's human-readable terminal projection (the `program <id>: <Outcome> (<n> module turn(s); …)`
/// line the SSE body carries). Drains the event sink to completion so the run task fully finishes.
async fn drive_program(
    engine: Arc<ainxt_runtime::Engine>,
    goal: &str,
    cancel: &CancelToken,
) -> String {
    let surface = ProgramSurface::new(engine, "program");
    let principal = Principal::user("u-alice", &["chat.send"]).with_clearance(DataClass::Internal);
    let req = Request::chat("prog-stop", "t1", goal, DataClass::Internal);

    let (tx, mut rx) = tokio::sync::mpsc::channel::<Event>(64);
    let summary = surface
        .handle_turn(&principal, &req, tx, cancel)
        .await
        .expect(
        "the program turn drives to a terminal outcome (a stop is a capped-partial, not a crash)",
    );

    // Drain any streamed events (the surface sent its projection + Done); the terminal projection is
    // also on the summary's final text.
    while rx.recv().await.is_some() {}
    summary.final_text
}

#[tokio::test(flavor = "multi_thread")]
async fn r9_program_surface_user_stop_drains_before_module() {
    // A user-stop that arrived BEFORE the Run started (the token is already cancelled when the loop
    // first checks it): the driver must break at the first module boundary.
    let cancel = CancelToken::new();
    cancel.cancel();

    // A pre-cancelled token drains before any module turn runs, so the (unaffected) offline engine is
    // fine here — content never gets a chance to matter.
    let pr = assemble_program(&offline_config()).expect("assemble program runtime");
    let out = drive_program(pr.engine(), "migrate the settlement module", &cancel).await;

    assert!(
        out.contains("CappedPartial"),
        "a user-stopped Program Run must report an honest CappedPartial outcome, never Completed; \
         projection was:\n{out}"
    );
    assert!(
        !out.contains("Completed"),
        "a user-stopped Run must NOT be dressed as Completed; projection was:\n{out}"
    );
    assert!(
        out.contains("0 module turn(s)"),
        "a pre-cancelled Run must drain BEFORE any module engine turn runs; projection was:\n{out}"
    );
    assert!(
        out.contains("0 committed"),
        "a user-stopped Run commits NOTHING (no fabricated green); projection was:\n{out}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn r9_program_no_stop_runs_to_completion() {
    // PASS-AFTER contrast: the SAME surface + goal with a never-cancelled token drives real module
    // turns to a Completed outcome — proving the drain above is the threaded user-stop, not a broken run.
    let cancel = CancelToken::new();
    // GAP-FIX planner-assurance-revision (item 1) — a genuinely substantive, on-goal artifact is
    // required for the REAL RubricJudge to pass; see `FixedTextProvider`'s doc comment.
    let engine = engine_with_fixed_text(
        "migrated the settlement module: assessed dependencies and executed the settlement cutover \
         successfully, with boundary tests covering empty and negative edge cases.",
    );
    let out = drive_program(engine, "migrate the settlement module", &cancel).await;

    assert!(
        out.contains("Completed"),
        "without a stop the Program Run drives its modules to a Completed outcome; projection was:\n{out}"
    );
    assert!(
        !out.contains("0 module turn(s)"),
        "a completed Run must have driven ≥1 real module engine turn; projection was:\n{out}"
    );
}
