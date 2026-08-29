// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R13 (Prompt Engine + Prompt Optimizer §7 / PE11, HIGH) — the forensic prompt event record is
//! DURABLY persisted BEFORE the provider call, wired from the daemon composition root.
//!
//! The round-12 gap: `PromptService::compile_turn` recorded "before the provider call" only for
//! whatever sink the caller passed — a served daemon could pass `NullSink` and silently skip forensic
//! persistence, so PE11 lived in caller discipline. `ainxt_runtimed::governed::assemble_served_prompt_engine`
//! closes it at the composition root: it returns a `ServedPromptEngine` that OWNS a mandatory durable
//! `ForensicFileSink` (fsync-before-return) — there is NO way to compile a served turn through it
//! without the record landing on disk first.
//!
//! FAIL-BEFORE: `governed::assemble_served_prompt_engine` did not exist (this file would not resolve).
//! PASS-AFTER: green, offline, deterministic. **infra_gated**: production injects a Postgres/WORM
//! Event-Log sink behind the same `EventSink` trait via `ServedPromptEngine::new`. **needs_hot_wiring**:
//! the `/v1/chat` compile still uses the flat engine; the remaining wire is the transport swapping in
//! this engine per turn.

use ainxt_prompt::layered::{HeuristicTokens, TruncatingCondenser};
use ainxt_prompt::registry::{content_fingerprint, ModelFamily};
use ainxt_prompt::service::{ForensicFileSink, PromptService};
use ainxt_runtimed::governed::{
    assemble_payments_served_prompt_engine, assemble_served_prompt_engine,
};
use std::sync::atomic::{AtomicU64, Ordering};

fn tmp_path(tag: &str) -> std::path::PathBuf {
    static CTR: AtomicU64 = AtomicU64::new(0);
    let n = CTR.fetch_add(1, Ordering::SeqCst);
    let p = std::env::temp_dir().join(format!(
        "ainxt-r13-forensic-served-{tag}-{}-{n}.jsonl",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&p);
    p
}

#[test]
fn r13_composition_root_served_engine_persists_forensically_before_provider() {
    let path = tmp_path("chat");
    // The daemon assembles the served-chat prompt engine BOUND to a mandatory durable file sink.
    let engine = assemble_served_prompt_engine(&path);
    let svc = PromptService::new(&HeuristicTokens, &TruncatingCondenser, 10_000);
    let fam = ModelFamily::new("claude");
    assert!(
        engine.serves(&fam),
        "the shipped served default deploys the claude family"
    );

    let compiled = engine
        .compile_turn(
            &svc,
            "turn-forensic-1",
            &fam,
            "Retrieved: the settlement window closes 22:00 IST.",
        )
        .expect("shipped served family compiles");

    // compile_turn RETURNED → the record was already fsync'd. A FRESH reader over the same path (an
    // independent auditor / a process that restarted) sees the durable record BEFORE any provider call
    // could have run — no shared in-process state.
    let reread = ForensicFileSink::new(&path)
        .records()
        .expect("durable records readable after 'restart'");
    assert_eq!(
        reread.len(),
        1,
        "exactly one durable record on disk before the provider call"
    );
    assert_eq!(
        reread[0].prompt_hash,
        content_fingerprint(&compiled.text),
        "persisted hash matches the compiled prompt text → byte-for-byte replayable (PE11)"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn r13_payments_served_engine_is_durable_and_undeployed_family_writes_no_phantom() {
    let path = tmp_path("pay");
    let engine = assemble_payments_served_prompt_engine(&path);
    let svc = PromptService::new(&HeuristicTokens, &TruncatingCondenser, 10_000);

    // A family with no pinned served variant fails closed BEFORE any record is written — a failed
    // serve must never leave a phantom prompt on disk.
    let err = engine.compile_turn(&svc, "t", &ModelFamily::new("no-such-family"), "ctx");
    assert!(err.is_err(), "an undeployed family fails closed");
    assert!(
        ForensicFileSink::new(&path).records().unwrap().is_empty(),
        "a failed serve persists no phantom prompt"
    );
    let _ = std::fs::remove_file(&path);
}
