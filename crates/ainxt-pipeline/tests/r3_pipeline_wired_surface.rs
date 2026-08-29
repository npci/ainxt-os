// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R3 gap: "Pipeline/semantic engine wired into a real surface (the 'renderer has no path to done
//! without Complete' invariant enforced on actual turns)".
//!
//! The surface binding itself lives in reserved crates this round does not own
//! (`ainxt-runtimed` / `ainxt-surface`), so it is marked `needs_hot_wiring`. What we CAN prove here,
//! against the REAL public object a surface will assemble, is that the exposed entrypoint
//! ([`EditEngine`] + [`run_edit_turn`]) is genuinely surface-ready and that the "no path to done
//! without a `Complete`" invariant holds on actual turns driven exactly as a served surface drives
//! them: one engine assembled at startup from `Arc` seams, cheaply cloned and shared across
//! concurrent worker turns, each turn owning its own [`WorkspaceSink`] + [`Journal`].
//!
//! Fail-before/pass-after: before this round `EditEngine` borrowed `&'a dyn` seams and so was neither
//! `'static`, `Send + Sync`, nor `Clone` — a daemon surface could not store it in shared state nor
//! hand a clone to a worker thread. This test statically requires all three (`assert_send_sync`,
//! the spawned-thread turn, the `.clone()`), so it did not compile against the borrowed engine and
//! compiles + passes against the owning one.

use std::sync::Arc;
use std::thread;

use ainxt_pipeline::edit_turn::{run_edit_turn, EditEngine, EditTurn, TurnOutcome};
use ainxt_pipeline::journal::Journal;
use ainxt_pipeline::sast::BuiltinScanner;
use ainxt_pipeline::selfheal::{Coder, Observation, SelfHealConfig};
use ainxt_pipeline::stages::{ScriptedTools, StageContext, StageTools, ToolResult};
use ainxt_pipeline::{capability::Language, risk::RiskTier};
use ainxt_semantic::workspace::{MemorySink, WorkspaceSink};

/// A no-op coder: it cannot fix anything, so a hard-blocked turn stays blocked (honest hand-off).
struct NoOpCoder;
impl Coder for NoOpCoder {
    fn fix(&self, _r: u8, files: &[(String, String)], _o: &Observation) -> Vec<(String, String)> {
        files.to_vec()
    }
}

/// A coder that removes the `// broken` marker, so a compile failure self-heals then commits.
struct HealCoder;
impl Coder for HealCoder {
    fn fix(&self, _r: u8, files: &[(String, String)], _o: &Observation) -> Vec<(String, String)> {
        files
            .iter()
            .map(|(p, c)| (p.clone(), c.replace("// broken", "")))
            .collect()
    }
}

/// Deterministic tools whose compile fails while the source still contains "broken".
struct CompileGate;
impl StageTools for CompileGate {
    fn compile(&self, ctx: &StageContext) -> ToolResult {
        if ctx.files.iter().any(|(_, c)| c.contains("broken")) {
            ToolResult::fail(vec!["E: broken".into()])
        } else {
            ToolResult::pass()
        }
    }
    fn test(&self, _c: &StageContext) -> ToolResult {
        ToolResult::pass()
    }
    fn lint(&self, _c: &StageContext) -> ToolResult {
        ToolResult::pass()
    }
    fn type_check(&self, _c: &StageContext) -> ToolResult {
        ToolResult::pass()
    }
}

fn cfg(tier: RiskTier) -> SelfHealConfig {
    SelfHealConfig {
        lang: Language::Rust,
        tier,
        max_rounds: 3,
        stuck: None,
        ..Default::default()
    }
}

fn assert_send_sync<T: Send + Sync + 'static>() {}

#[test]
fn r3_pipeline_wired_surface() {
    // (1) The exposed engine must be exactly the shape a served surface needs: assembled once from
    //     owned `Arc` seams, `Send + Sync + 'static`, and `Clone`. This is the fail-before line —
    //     the borrowed `&'a dyn` engine satisfied none of these.
    assert_send_sync::<EditEngine>();

    let engine = EditEngine::new(
        Arc::new(HealCoder),
        Arc::new(CompileGate),
        Arc::new(BuiltinScanner),
    );

    // (2) A clean/heal-able edit routed through the SAME engine handle a surface would hold reaches
    //     `Complete` → the healed set is durably committed, and only through a real CommitApproval.
    let heal_turn = EditTurn {
        edit_id: "surf-heal".into(),
        original_files: vec![("a.rs".into(), "fn f() -> i32 { 1 }\n".into())],
        applied_files: vec![("a.rs".into(), "fn f() -> i32 { 2 } // broken\n".into())],
        config: cfg(RiskTier::Local),
    };
    let mut sink = MemorySink::new();
    let mut journal = Journal::new("surf-heal");
    let out = engine.run_turn(heal_turn, &mut sink, &mut journal);
    match out {
        TurnOutcome::Committed {
            approval, versions, ..
        } => {
            assert!(approval.confidence() >= 90);
            assert_eq!(versions["a.rs"], 1);
            assert!(sink.files["a.rs"].contains('2'));
            assert!(!sink.files["a.rs"].contains("broken"));
        }
        other => panic!("expected Committed via the pipeline, got {other:?}"),
    }
    // Tamper-evident journal chain is intact for the committed turn.
    assert_eq!(journal.verify(), Ok(()));

    // (3) Cross-thread parity: a CLONE of the same engine, driven from a worker thread exactly as the
    //     daemon fans turns out, still gates a settlement-path (Tier-3) edit to a human even at a
    //     perfect score — the "no path to done without Complete" invariant holds on the served path.
    let worker_engine = engine.clone();
    let handle = thread::spawn(move || {
        let turn = EditTurn {
            edit_id: "surf-settle".into(),
            original_files: vec![("settlement/x.rs".into(), "fn f() -> i32 { 1 }\n".into())],
            applied_files: vec![("settlement/x.rs".into(), "fn f() -> i32 { 2 }\n".into())],
            config: cfg(RiskTier::HighRisk),
        };
        let mut sink = MemorySink::new();
        let mut journal = Journal::new("surf-settle");
        let out = worker_engine.run_turn(turn, &mut sink, &mut journal);
        // Not committed despite a clean edit; the sink still holds the pre-edit baseline.
        (out.committed(), sink.read("settlement/x.rs").unwrap())
    });
    let (committed, persisted) = handle.join().expect("worker turn panicked");
    assert!(!committed, "Tier-3 settlement edit must never auto-commit");
    assert_eq!(persisted, "fn f() -> i32 { 1 }\n");
}
