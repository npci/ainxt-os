// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R20 — GAP-AUDIT loop-teams-longhorizon (gap 1), independent re-audit.
//!
//! `r18_program_durable_served.rs` proved `ProgramSurface::with_durable_dir` end-to-end, but by
//! HAND-BUILDING a `ProgramSurface` directly and calling `.handle_turn()` on it — never by exercising
//! `assemble_program_surface`/`assemble_program_surface_with_transparency`, the REAL composition root
//! `assemble_selected("program", ..)` calls on the daemon's `--surface program` path (see
//! `ainxt-runtimed/src/lib.rs::assemble_selected`). Before this fix, `assemble_program_surface_with_transparency`
//! never called `.with_durable_dir(..)` at all and `ainxt-config::LimitsConfig` had no field to express
//! it, so a REAL served daemon had NO way to opt into crash-resumable Programs — the mechanism existed
//! and was unit-proven, but was unreachable from the one path that matters.
//!
//! Separately, wiring durability alone would have been a *regression*: `run_program_durable_blocking`
//! drove the Supervisor with `PermissiveProgramVerifier` (an unconditional-`Complete` rubber stamp) and
//! `AutoApprove` (approves every checkpoint, including a §8 critical-path human-checkpoint,
//! unconditionally) — dropping the real three-way verification / §18 SoD / §8 critical-path gate the
//! non-durable governed path (`drive_served_program_governed` / `ServedModuleExecutor`) enforces. A
//! served deployment that opted into durability would have silently traded away real verification to
//! get it. This file proves BOTH halves are now true together:
//!
//! 1. `[limits] program_durable_dir` reaches the REAL composition root — a served turn through
//!    `assemble_program_surface` (exactly what `assemble_selected("program", ..)` calls) persists a
//!    hash-chained JSONL log to disk, and a second turn against the same session resumes it (grows,
//!    never shrinks) — never a hand-built surface bypassing the composition function.
//! 2. The durable driver's REAL entrypoint (`run_program_durable` — the exact function
//!    `ProgramSurface::handle_turn`'s durable branch calls) now HOLDS a §8 critical-path node rather
//!    than force-committing it, proving `AutoApprove` is gone (it always approved, so the OLD code would
//!    have force-committed this node and reported `Completed` — see `r14_program_budget_checkpoint.rs`'s
//!    identical assertion for the non-durable governed path, which this test now mirrors for the
//!    durable path via the exact same public entrypoint the daemon uses).
//! 3. Regression: an unconfigured deployment stays byte-identical to the pre-wire in-memory-only
//!    default (no durable dir is ever created), through the SAME composition root.

use ainxt_client::{Client, ClientConfig};
use ainxt_planner::program::{CheckpointClass, NodeClass, NodeDecl, ProgramOutcome};
use ainxt_planner::supervisor::SupervisorConfig;
use ainxt_protocol::Event;
use ainxt_runtime::engine_with_defaults;
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_runtimed::{
    assemble_program_surface, load_layered, run_program_durable, LoadedConfig, RunIdentitySpec,
};
use ainxt_types::{DataClass, Principal};
use std::sync::Arc;
use tokio::sync::mpsc;

fn offline() -> LoadedConfig {
    load_layered(&[("x", "version = 1")]).unwrap()
}

/// GAP-FIX planner-assurance-revision (item 1) — a fixed-text model [`Provider`]: the served Program
/// driver's semantic Judge is now a REAL, content-varying `RubricJudge`, never a fabricated fixed pass,
/// so the air-gapped `OfflineProvider`'s prompt-invariant "offline mode: no model configured." text can
/// no longer stand in for "ordinary work commits" — it carries none of a real goal's keywords.
struct FixedTextProvider {
    text: String,
}
impl Provider for FixedTextProvider {
    fn id(&self) -> &str {
        "r20-test-producer"
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

fn engine_with_fixed_text(text: &str) -> Arc<ainxt_runtime::Engine> {
    let mut router = ModelRouter::new();
    router.register(Box::new(FixedTextProvider {
        text: text.to_string(),
    }));
    Arc::new(engine_with_defaults(router))
}

fn tmp_dir(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "ainxt-r20-{tag}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

// ================== 1. `program_durable_dir` reaches the REAL composition root ==================

#[tokio::test(flavor = "multi_thread")]
async fn r20_composition_root_wires_program_durable_dir_from_config() {
    let dir = tmp_dir("comproot");
    let toml = format!(
        "version = 1\n[limits]\nprogram_durable_dir = \"{}\"\n",
        dir.display()
    );
    let configured = load_layered(&[("t", &toml)]).unwrap();
    assert_eq!(
        configured.runtime.limits.program_durable_dir.as_deref(),
        Some(dir.to_str().unwrap()),
        "sanity: the config layer must parse the new [limits] field"
    );

    // The EXACT function `assemble_selected("program", ..)` calls on the daemon's `--surface program`
    // path — not a hand-built `ProgramSurface`.
    let assembled = assemble_program_surface(&configured, "program").expect("composition succeeds");
    let joined = assembled.report.join("\n");
    assert!(
        joined.contains(&format!("durable_dir={}", dir.display())),
        "the served program surface must report the config-driven durable dir it actually installed \
         (gap 1a), not silently ignore it: {joined}"
    );

    let client = Client::in_process(
        assembled.manager,
        Principal::user("dev", &["chat.send"]),
        ClientConfig::default(),
    );

    // Turn 1 — new session: the durable branch must seed + persist to disk under the CONFIGURED dir.
    let out1 = client
        .chat("s-r20", "t-r20", "migrate the legacy settlement module")
        .unwrap()
        .collect()
        .await;
    assert!(
        out1.completed,
        "the durable served turn must drive to a terminal outcome"
    );
    assert!(
        out1.text.contains("durable"),
        "the durable branch's projection must say so: {}",
        out1.text
    );

    let session_dir = dir.join("s-r20_t-r20");
    assert!(
        session_dir.is_dir(),
        "handle_turn (through the REAL composition root) must have created the per-Run durable \
         session dir at {session_dir:?} — the config wire did not actually reach the served surface"
    );
    let bytes_after_1: u64 = std::fs::read_dir(&session_dir)
        .expect("durable session dir readable")
        .filter_map(|e| e.ok())
        .map(|e| e.metadata().map(|m| m.len()).unwrap_or(0))
        .sum();
    assert!(
        bytes_after_1 > 0,
        "turn 1 must have persisted real JSONL bytes to disk"
    );

    // Turn 2 — SAME session: resuming through the composition root must never shrink the durable log.
    let out2 = client
        .chat("s-r20", "t-r20", "migrate the legacy settlement module")
        .unwrap()
        .collect()
        .await;
    assert!(out2.completed);
    let bytes_after_2: u64 = std::fs::read_dir(&session_dir)
        .expect("durable session dir still readable after resume")
        .filter_map(|e| e.ok())
        .map(|e| e.metadata().map(|m| m.len()).unwrap_or(0))
        .sum();
    assert!(
        bytes_after_2 >= bytes_after_1,
        "resuming the same durable session through the composition root must never shrink the \
         persisted log (turn 1 = {bytes_after_1} bytes, turn 2 = {bytes_after_2} bytes)"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn r20_composition_root_unconfigured_stays_in_memory_only() {
    // Regression guard: no `program_durable_dir` configured -> the pre-wire in-memory-only governed
    // path, unchanged, through the SAME composition root.
    let unconfigured = offline();
    let assembled =
        assemble_program_surface(&unconfigured, "program").expect("composition succeeds");
    assert!(
        assembled
            .report
            .iter()
            .any(|r| r.contains("durable_dir=None")),
        "an unconfigured deployment must stay in-memory only (no accidental durability): {:?}",
        assembled.report
    );

    let client = Client::in_process(
        assembled.manager,
        Principal::user("dev", &["chat.send"]),
        ClientConfig::default(),
    );
    let out = client
        .chat(
            "s-r20-mem",
            "t-r20-mem",
            "migrate the legacy settlement module",
        )
        .unwrap()
        .collect()
        .await;
    assert!(out.completed);
    assert!(
        out.text.contains("committed") && out.text.contains("identity renewal"),
        "with no durable dir configured the governed path's vocabulary must be present unchanged: {}",
        out.text
    );
}

// ============ 2. the durable driver's REAL entrypoint enforces the §8 critical-path gate ============

fn identity(run: &str) -> RunIdentitySpec {
    RunIdentitySpec::new("agent", "r20-durable", run, DataClass::Internal, "u-alice")
}

fn critical_path_nodes() -> Vec<NodeDecl> {
    vec![
        NodeDecl::new("assess", NodeClass::MigrationRun),
        // The settlement cutover is a CRITICAL-PATH human checkpoint — mirrors
        // `r14_program_budget_checkpoint.rs::critical_path_nodes` for the non-durable governed path.
        NodeDecl::new("migrate", NodeClass::MigrationRun)
            .depends_on("assess")
            .checkpoint(CheckpointClass::CriticalPath),
    ]
}

#[tokio::test(flavor = "multi_thread")]
async fn r20_durable_driver_holds_critical_path_node_without_human_approval() {
    let dir = tmp_dir("critpath");
    // GAP-FIX planner-assurance-revision (item 1) — a genuinely substantive, on-goal artifact so the
    // non-critical-path 'assess' node's REAL RubricJudge passes; see `FixedTextProvider`'s doc comment.
    let engine = engine_with_fixed_text(
        "migrated the settlement module: assessed dependencies and executed the settlement cutover \
         successfully, with boundary tests covering empty and negative edge cases.",
    );

    // `run_program_durable` is the EXACT function `ProgramSurface::handle_turn`'s durable branch calls
    // (program_exec.rs's `with_durable_dir` path) — not a bespoke test-only driver.
    let run = run_program_durable(
        engine,
        identity("checkpoint-held"),
        "migrate the settlement module",
        critical_path_nodes(),
        SupervisorConfig::default(),
        None,
        dir.clone(),
    )
    .await
    .expect("the durable run drives to a terminal outcome");

    assert_eq!(
        run.report.outcome,
        ProgramOutcome::CappedPartial,
        "a critical-path node with no human checkpoint must NOT force the durable Run Completed — \
         under the OLD `AutoApprove` gate this would have reported `Completed` instead, exactly the \
         force-commit hole `ServedProgramApprovalGate` closes"
    );
    let committed: Vec<String> = run
        .report
        .final_state
        .committed_node_ids()
        .iter()
        .map(|n| n.as_str().to_string())
        .collect();
    assert!(
        !committed.contains(&"migrate".to_string()),
        "the critical-path 'migrate' node must NOT be force-committed by the durable driver without a \
         human checkpoint: {committed:?}"
    );
    assert!(
        committed.contains(&"assess".to_string()),
        "the non-critical-path 'assess' node commits normally — proving the new SoD-gated \
         `DurableServedExecutor` still lets ordinary work through: {committed:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
