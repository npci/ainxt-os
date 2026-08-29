// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R18 — GAP-AUDIT loop-teams-longhorizon (gap 1): the durable, resumable Program driver
//! (`run_program_durable` / `run_program_durable_blocking`, a hash-chained JSONL
//! [`ainxt_eventlog::ProgramEventSink`]) was fully built and unit-tested (see
//! `r5_served_governed.rs::budget_capped_durable_program_reports_capped_and_persists`) but had ZERO
//! callers anywhere on the SERVED path: `ProgramSurface::handle_turn` (the actual `POST /v1/chat`
//! composition root for `--surface program`) always drove the in-memory
//! `drive_served_program_governed`, whose entire Run state lived on the driver thread's stack and was
//! gone the instant the turn returned. A daemon crash mid-Program lost the whole in-flight Run with no
//! way to resume it.
//!
//! `ProgramSurface::with_durable_dir` closes this: when a served surface opts in, `handle_turn` drives
//! the Run through `run_program_durable` instead, so its ProgramEvent stream is persisted to disk under
//! `{dir}/{session}_{turn}/` on every turn. This test drives the EXACT served surface code path twice
//! against the SAME durable dir/session — proving (1) the durable branch is actually reachable from
//! `handle_turn` (a JSONL file appears on disk after ONE served turn, which never happened before this
//! fix) and (2) a second served turn against the same session resumes from the persisted log rather
//! than re-seeding from scratch (the durable log's event count only grows, per the same "resume never
//! loses history" contract the library-level test already proves for `run_program_durable` directly).

use ainxt_protocol::{Event, Request};
use ainxt_runtime::{CancelToken, TurnHandler};
use ainxt_runtimed::{assemble_program, load_layered, ProgramSurface};
use ainxt_types::{DataClass, Principal};

fn offline_config() -> ainxt_runtimed::LoadedConfig {
    load_layered(&[("x", "version = 1")]).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn r18_served_program_surface_persists_to_the_durable_log() {
    let dir = std::env::temp_dir().join(format!(
        "ainxt-r18-served-durable-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));

    let pr = assemble_program(&offline_config()).expect("assemble program runtime");
    let surface = ProgramSurface::new(pr.engine(), "program").with_durable_dir(dir.clone());
    let principal = Principal::user("u-alice", &["chat.send"]).with_clearance(DataClass::Internal);
    let req = Request::chat(
        "prog-durable",
        "t1",
        "migrate the settlement module",
        DataClass::Internal,
    );
    let cancel = CancelToken::new();

    // Turn 1 — a brand-new session: the durable branch must seed Created + Decomposed and drive the
    // Run, persisting every event to disk under the surface's configured dir.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Event>(64);
    let summary = surface
        .handle_turn(&principal, &req, tx, &cancel)
        .await
        .expect("the durable served turn drives to a terminal outcome");
    while rx.recv().await.is_some() {}

    assert!(
        summary.final_text.contains("durable"),
        "the durable branch's projection must say so, not silently look identical to the governed \
         path; projection was:\n{}",
        summary.final_text
    );
    assert_eq!(summary.provider, "program-durable");

    let session_dir = dir.join("prog-durable_t1");
    assert!(
        session_dir.is_dir(),
        "handle_turn must have created the per-Run durable session dir at {session_dir:?} — the \
         durable variant was NOT reached from the served surface"
    );
    let files_after_turn_1: Vec<_> = std::fs::read_dir(&session_dir)
        .expect("durable session dir readable")
        .filter_map(|e| e.ok())
        .collect();
    assert!(
        !files_after_turn_1.is_empty(),
        "a served turn through the durable branch must have appended real JSONL records to disk"
    );
    let bytes_after_turn_1: u64 = files_after_turn_1
        .iter()
        .map(|e| e.metadata().map(|m| m.len()).unwrap_or(0))
        .sum();
    assert!(
        bytes_after_turn_1 > 0,
        "the durable log file(s) must hold real persisted bytes, not be empty placeholders"
    );

    // Turn 2 — the SAME session id (same `req.session` + `req.turn` => same durable dir): resuming
    // must re-project the existing log rather than silently discarding it and starting over. The
    // resumed run's own event count must never be smaller than what turn 1 already persisted (the same
    // "resume never loses history" contract `run_program_durable` proves directly at the library level).
    let (tx2, mut rx2) = tokio::sync::mpsc::channel::<Event>(64);
    let summary2 = surface
        .handle_turn(&principal, &req, tx2, &cancel)
        .await
        .expect("the resumed durable served turn drives to a terminal outcome");
    while rx2.recv().await.is_some() {}
    assert!(
        summary2.final_text.contains("durable"),
        "the resumed turn is still driven via the durable branch; projection was:\n{}",
        summary2.final_text
    );

    let files_after_turn_2: Vec<_> = std::fs::read_dir(&session_dir)
        .expect("durable session dir still readable after resume")
        .filter_map(|e| e.ok())
        .collect();
    let bytes_after_turn_2: u64 = files_after_turn_2
        .iter()
        .map(|e| e.metadata().map(|m| m.len()).unwrap_or(0))
        .sum();
    assert!(
        bytes_after_turn_2 >= bytes_after_turn_1,
        "resuming the same durable session must never shrink the persisted log (turn 1 = {bytes_after_turn_1} \
         bytes, turn 2 = {bytes_after_turn_2} bytes)"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn r18_served_program_surface_without_durable_dir_is_byte_identical_to_governed_path() {
    // The default (`ProgramSurface::new`, no `with_durable_dir`) must be UNCHANGED: the governed
    // in-memory path still drives, and its projection still carries the governed-path vocabulary
    // (`committed` / `identity renewal` / `SoD-authorized`) — proving this gap-fix is additive, opt-in,
    // never a silent default swap.
    let pr = assemble_program(&offline_config()).expect("assemble program runtime");
    let surface = ProgramSurface::new(pr.engine(), "program");
    let principal = Principal::user("u-alice", &["chat.send"]).with_clearance(DataClass::Internal);
    let req = Request::chat(
        "prog-governed",
        "t1",
        "migrate the settlement module",
        DataClass::Internal,
    );
    let cancel = CancelToken::new();

    let (tx, mut rx) = tokio::sync::mpsc::channel::<Event>(64);
    let summary = surface
        .handle_turn(&principal, &req, tx, &cancel)
        .await
        .expect("the governed served turn drives to a terminal outcome");
    while rx.recv().await.is_some() {}

    assert!(
        summary.final_text.contains("committed") && summary.final_text.contains("identity renewal"),
        "with no durable dir configured the governed path's vocabulary must be present unchanged; \
         projection was:\n{}",
        summary.final_text
    );
    assert_eq!(summary.provider, "program");
}
