// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-11 — **served-path durability of a committed edit** (`SEMANTIC_EDITING.md` §5). The R7 route
//! (`EditEngine::run_turn_for`) proved a clean edit reaches `Committed` and *a* sink is written, but
//! the only sink was [`MemorySink`] — process memory, lost on restart. A payments platform's
//! committed edit must survive a daemon restart. This proves the durable [`FsSink`] does exactly that
//! through the real served entrypoint: commit an edit, drop the whole engine + sink (simulating a
//! process exit), reopen a *fresh* `FsSink` at the same root, and read the committed bytes back.
//!
//! Fail-before: `FsSink` did not exist prior to round-11, so there was no durable served sink at all.
//! The daemon route mount that constructs an `FsSink` rooted at the served working tree lives in the
//! reserved `ainxt-runtimed` transport crate (**needs_hot_wiring**); the durable sink itself — the
//! part that was missing — is proven here end-to-end through `run_turn_for`.

use ainxt_pipeline::journal::Journal;
use ainxt_pipeline::sast::BuiltinScanner;
use ainxt_pipeline::stages::ScriptedTools;
use ainxt_pipeline::{
    Coder, EditEngine, EditRequest, EditResponse, Observation, RiskTier, SelfHealConfig,
    CAP_EDIT_APPLY,
};
use ainxt_semantic::workspace::{FsSink, WorkspaceSink};
use ainxt_types::Principal;
use std::sync::Arc;

struct NoOpCoder;
impl Coder for NoOpCoder {
    fn fix(&self, _r: u8, files: &[(String, String)], _o: &Observation) -> Vec<(String, String)> {
        files.to_vec()
    }
}

fn engine() -> EditEngine {
    EditEngine::new(
        Arc::new(NoOpCoder),
        Arc::new(ScriptedTools::default()),
        Arc::new(BuiltinScanner),
    )
}

/// A unique scratch directory under the OS temp dir (no external tempfile dependency).
fn scratch(tag: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("ainxt-r11-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn r11_committed_edit_survives_a_process_restart_via_fs_sink() {
    let root = scratch("durable");
    let req = EditRequest {
        edit_id: "t-durable".into(),
        original_files: vec![("src/a.rs".into(), "fn f() -> i32 { 1 }\n".into())],
        applied_files: vec![("src/a.rs".into(), "fn f() -> i32 { 2 }\n".into())],
        config: SelfHealConfig {
            tier: RiskTier::Local,
            max_rounds: 3,
            ..Default::default()
        },
    };
    let dev = Principal::user("dev", &[CAP_EDIT_APPLY]);

    // ── "Process instance 1": assemble the engine + a durable FsSink, run the served turn. ──
    {
        let eng = engine();
        let mut sink = FsSink::new(&root).expect("open fs sink");
        let mut j = Journal::new("t-durable");
        let res = eng
            .run_turn_for(&dev, req, &mut sink, &mut j)
            .expect("authorized");
        match res {
            EditResponse::Committed { versions, .. } => {
                assert_eq!(versions["src/a.rs"], 1);
            }
            other => panic!("expected Committed, got {other:?}"),
        }
        // Everything (engine, sink, journal) is dropped at the end of this block — a "restart".
    }

    // ── "Process instance 2": a brand-new FsSink at the same root reads the durable committed bytes. ──
    let reopened = FsSink::new(&root).expect("reopen fs sink");
    let back = reopened
        .read("src/a.rs")
        .expect("committed file must persist across the restart");
    assert!(
        back.contains("fn f() -> i32 { 2 }"),
        "durable content missing after restart: {back:?}"
    );

    // And it is really on disk, not just in the reopened handle.
    let on_disk = std::fs::read_to_string(root.join("src/a.rs")).unwrap();
    assert!(on_disk.contains("{ 2 }"));

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn r11_fs_sink_rejects_a_path_escaping_the_workspace_root() {
    // A durable sink must never write outside the served tree, even if an edit path tries to climb out.
    let root = scratch("escape");
    let mut sink = FsSink::new(&root).unwrap();
    let mut files = std::collections::BTreeMap::new();
    files.insert("../evil.rs".to_string(), "pwned".to_string());
    let err = sink.commit(&files).unwrap_err();
    assert!(err.contains("escapes workspace root"));
    // Nothing was written above the root.
    assert!(!root.parent().unwrap().join("evil.rs").exists());
    let _ = std::fs::remove_dir_all(&root);
}
