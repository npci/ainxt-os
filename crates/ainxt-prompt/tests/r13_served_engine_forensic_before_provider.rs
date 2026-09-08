// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R13 (Prompt Engine + Prompt Optimizer, §7 / PE11) — the forensic prompt event record is DURABLY
//! persisted BEFORE the provider call **on the shipped served path**, and that guarantee is now
//! STRUCTURAL, not caller-discretionary.
//!
//! Round-12 flagged the HIGH: `PromptService::compile_turn` records "before the provider call" only for
//! whatever sink the caller passes — a served daemon could pass `NullSink` and silently skip forensic
//! persistence, so the durable-before-provider guarantee lived in caller discipline. `ServedPromptEngine`
//! closes it: it OWNS a mandatory durable `EventSink` (the offline default binds a `ForensicFileSink`,
//! fsync-before-return), and exposes NO way to compile a served turn without recording through it first.
//!
//! FAIL-BEFORE: `ainxt_prompt::service::ServedPromptEngine` did not exist (this file won't compile).
//! PASS-AFTER: green. Offline + deterministic. The production Postgres/WORM Event-Log sink plugs in
//! behind the same `EventSink` trait via `ServedPromptEngine::new` (infra_gated); the served daemon
//! constructing the engine per deployment is needs_hot_wiring in `ainxt-runtimed`.

use ainxt_prompt::layered::{HeuristicTokens, PromptEventRecord, TruncatingCondenser};
use ainxt_prompt::registry::{content_fingerprint, ModelFamily, ServeError};
use ainxt_prompt::served::{default_payments_served_chat_prompts, default_served_chat_prompts};
use ainxt_prompt::service::{EventSink, ForensicFileSink, PromptService, ServedPromptEngine};
use ainxt_prompt::NumericPolicy;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

struct TmpFile(std::path::PathBuf);
impl TmpFile {
    fn new(tag: &str) -> Self {
        static CTR: AtomicU64 = AtomicU64::new(0);
        let n = CTR.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!(
            "ainxt-r13-served-{tag}-{}-{n}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&p);
        TmpFile(p)
    }
}
impl Drop for TmpFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// A durable sink wrapper that ALSO appends an ordered marker the instant it records — so the test can
/// assert the forensic write strictly precedes the (simulated) provider call, while the bytes still hit
/// disk via the inner `ForensicFileSink`.
struct OrderedDurableSink {
    inner: ForensicFileSink,
    log: Arc<Mutex<Vec<String>>>,
}
impl EventSink for OrderedDurableSink {
    fn record_prompt(&self, record: &PromptEventRecord) {
        self.inner.record_prompt(record); // fsync-before-return
        self.log.lock().unwrap().push("prompt-recorded".to_string());
    }
}

#[test]
fn r13_served_engine_persists_forensically_before_provider_and_survives_crash() {
    let tmp = TmpFile::new("crash");
    // The shipped served default deployment, BOUND to a mandatory durable file sink at construction.
    let engine = ServedPromptEngine::with_forensic_file(default_served_chat_prompts(), &tmp.0);
    let svc = PromptService::new(&HeuristicTokens, &TruncatingCondenser, 10_000);
    let fam = ModelFamily::new("claude");
    assert!(engine.serves(&fam));

    let compiled = engine
        .compile_turn(
            &svc,
            "turn-forensic-1",
            &fam,
            "Retrieved: the settlement window closes 22:00 IST.",
        )
        .expect("shipped served family compiles");

    // compile_turn RETURNED → the record was already fsync'd. A FRESH reader over the same path
    // (process restart / independent auditor) sees the durable record — no shared in-process state.
    let reread = ForensicFileSink::new(&tmp.0)
        .records()
        .expect("durable records are readable after 'crash'");
    assert_eq!(
        reread.len(),
        1,
        "exactly one durable record on disk before any provider call"
    );
    assert_eq!(reread[0].control_sha, engine.prompts().control_sha);
    assert_eq!(reread[0].layers.len(), 4);
    assert_eq!(
        reread[0].prompt_hash,
        content_fingerprint(&compiled.text),
        "persisted hash matches the compiled text → byte-for-byte replayable (PE11)"
    );
}

#[test]
fn r13_forensic_write_strictly_precedes_provider_call_through_owned_sink() {
    let tmp = TmpFile::new("order");
    let log = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::new(OrderedDurableSink {
        inner: ForensicFileSink::new(&tmp.0),
        log: log.clone(),
    });
    // The engine OWNS the durable sink — the caller cannot swap it per turn.
    let engine = ServedPromptEngine::new(default_served_chat_prompts(), sink);
    let svc = PromptService::new(&HeuristicTokens, &TruncatingCondenser, 10_000);

    let _compiled = engine
        .compile_turn(&svc, "turn-1", &ModelFamily::new("qwen"), "ctx")
        .expect("qwen serves");

    // The provider call happens strictly AFTER compile_turn returns — simulate it now.
    {
        let mut guard = log.lock().unwrap();
        guard.push("provider-called".to_string());
    } // guard released here before the next lock acquisition

    let log_snapshot = log.lock().unwrap().clone();
    assert_eq!(
        log_snapshot,
        vec!["prompt-recorded".to_string(), "provider-called".to_string()],
        "the durable forensic record must land before the provider call, structurally"
    );
    // And the bytes are actually on disk (the durable inner sink ran, not a no-op).
    assert_eq!(ForensicFileSink::new(&tmp.0).records().unwrap().len(), 1);
}

#[test]
fn r13_failed_serve_records_no_phantom_prompt() {
    let tmp = TmpFile::new("fail");
    let engine = ServedPromptEngine::with_forensic_file(default_served_chat_prompts(), &tmp.0);
    let svc = PromptService::new(&HeuristicTokens, &TruncatingCondenser, 10_000);

    // A family with no pinned variant → serve fails closed BEFORE any record is written.
    let err = engine
        .compile_turn(&svc, "t", &ModelFamily::new("no-such-family"), "ctx")
        .unwrap_err();
    assert!(matches!(err, ServeError::VariantNotDeployed { .. }));
    // Nothing durable was written for the failed compile (file may not even exist).
    assert!(
        ForensicFileSink::new(&tmp.0).records().unwrap().is_empty(),
        "a failed serve must not persist a phantom prompt on disk"
    );
}

#[test]
fn r13_payments_engine_ships_toolsonly_numeric_and_records_every_turn() {
    let tmp = TmpFile::new("pay");
    let engine =
        ServedPromptEngine::with_forensic_file(default_payments_served_chat_prompts(), &tmp.0);
    assert_eq!(
        engine.numeric_policy(),
        NumericPolicy::ToolsOnly,
        "the payments served engine ships numeric-via-tools ON by default (BH)"
    );
    let svc = PromptService::new(&HeuristicTokens, &TruncatingCondenser, 10_000);
    for i in 0..4 {
        engine
            .compile_turn(
                &svc,
                &format!("turn-{i}"),
                &ModelFamily::new("claude"),
                "ctx",
            )
            .expect("payments family serves");
    }
    // Append-only durability: one persisted line per served turn.
    assert_eq!(
        ForensicFileSink::new(&tmp.0).records().unwrap().len(),
        4,
        "every served payments turn is durably recorded before its provider call"
    );
}
