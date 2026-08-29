// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R12 (Prompt Engineering, §7 / PE11) — the forensic prompt record is DURABLY PERSISTED before the
//! model call. `ForensicFileSink` fsyncs each compiled-prompt record to disk inside `record_prompt`,
//! which `PromptService::compile_turn` invokes BEFORE returning (and therefore before the caller makes
//! the provider call). This proves the record survives to a FRESH reader (crash/restart) and matches
//! the exact text that was compiled (byte-for-byte replayable).
//!
//! FAIL-BEFORE: `ainxt_prompt::service::ForensicFileSink` did not exist (won't compile). PASS-AFTER:
//! green. Offline + deterministic. A Postgres/WORM Event-Log-backed sink plugs in behind the same
//! `EventSink` trait; the served daemon injects one in place of `NullSink` (needs_hot_wiring).

use ainxt_prompt::layered::{HeuristicTokens, TruncatingCondenser};
use ainxt_prompt::registry::{content_fingerprint, ModelFamily};
use ainxt_prompt::served::default_served_chat_prompts;
use ainxt_prompt::service::{ForensicFileSink, PromptService};
use std::sync::atomic::{AtomicU64, Ordering};

struct TmpFile(std::path::PathBuf);
impl TmpFile {
    fn new() -> Self {
        static CTR: AtomicU64 = AtomicU64::new(0);
        let n = CTR.fetch_add(1, Ordering::SeqCst);
        let p =
            std::env::temp_dir().join(format!("ainxt-forensic-{}-{n}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&p);
        TmpFile(p)
    }
}
impl Drop for TmpFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[test]
fn r12_forensic_file_sink_persists_durably_before_returning() {
    let tmp = TmpFile::new();
    let served = default_served_chat_prompts();
    let sink = ForensicFileSink::new(&tmp.0);
    let svc = PromptService::new(&HeuristicTokens, &TruncatingCondenser, 10_000);
    let ids: Vec<&str> = served.layer_ids.iter().map(|s| s.as_str()).collect();

    let compiled = svc
        .compile_turn(
            &served.registry,
            &served.deployment,
            &sink,
            "turn-90-days-ago",
            &ModelFamily::new("claude"),
            &ids,
            "Retrieved: the settlement window closes 22:00 IST.",
            &served.control_sha,
        )
        .unwrap();

    // compile_turn has RETURNED — so the record was already fsync'd. A FRESH reader over the same path
    // (simulating a process restart / a separate auditor) sees the durable record.
    let reread = ForensicFileSink::new(&tmp.0).records().unwrap();
    assert_eq!(reread.len(), 1, "exactly one durable record on disk");
    assert_eq!(reread[0].control_sha, served.control_sha);
    assert_eq!(reread[0].layers.len(), 4);
    assert_eq!(
        reread[0].prompt_hash,
        content_fingerprint(&compiled.text),
        "the persisted hash matches the compiled text → byte-for-byte replayable (PE11)"
    );
}

#[test]
fn r12_forensic_file_sink_appends_every_turn() {
    let tmp = TmpFile::new();
    let served = default_served_chat_prompts();
    let sink = ForensicFileSink::new(&tmp.0);
    let svc = PromptService::new(&HeuristicTokens, &TruncatingCondenser, 10_000);
    let ids: Vec<&str> = served.layer_ids.iter().map(|s| s.as_str()).collect();
    for i in 0..5 {
        svc.compile_turn(
            &served.registry,
            &served.deployment,
            &sink,
            &format!("turn-{i}"),
            &ModelFamily::new("claude"),
            &ids,
            "ctx",
            &served.control_sha,
        )
        .unwrap();
    }
    assert_eq!(
        sink.records().unwrap().len(),
        5,
        "append-only: one durable line per turn"
    );
}
