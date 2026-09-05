// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R11 (Prompt Engineering, §7 / PE11) — the forensic Event-Log record is written BEFORE the provider
//! call, on the shipped served path. `compile_turn` emits the record to the injected [`EventSink`] and
//! returns; the caller then makes the provider call. This test threads a shared ordered log through the
//! sink and a stand-in provider seam to prove the record STRICTLY precedes the provider call, and that
//! a fail-closed serve emits NO record (no phantom prompt).
//!
//! FAIL-BEFORE: n/a for ordering (this asserts the guarantee end-to-end from outside the crate).
//! Offline + deterministic. The durable Event Log itself (Postgres) is the injected sink — infra.

use ainxt_prompt::layered::{HeuristicTokens, PromptEventRecord, TruncatingCondenser};
use ainxt_prompt::registry::{content_fingerprint, ModelFamily, ServeError};
use ainxt_prompt::served::default_served_chat_prompts;
use ainxt_prompt::service::{EventSink, PromptService};
use std::sync::{Arc, Mutex};

/// A sink that appends to a shared ordered log the instant it records — so we can assert the record
/// lands before the (simulated) provider call.
struct OrderedSink {
    log: Arc<Mutex<Vec<String>>>,
    last: Mutex<Option<PromptEventRecord>>,
}
impl EventSink for OrderedSink {
    fn record_prompt(&self, record: &PromptEventRecord) {
        self.log.lock().unwrap().push("prompt-recorded".to_string());
        *self.last.lock().unwrap() = Some(record.clone());
    }
}

#[test]
fn r11_forensic_record_strictly_precedes_the_provider_call() {
    let served = default_served_chat_prompts();
    let ids: Vec<&str> = served.layer_ids.iter().map(|s| s.as_str()).collect();
    let fam = &served.families[0];
    let log = Arc::new(Mutex::new(Vec::new()));
    let sink = OrderedSink {
        log: log.clone(),
        last: Mutex::new(None),
    };
    let est = HeuristicTokens;
    let cond = TruncatingCondenser;
    let svc = PromptService::new(&est, &cond, 10_000);

    let compiled = svc
        .compile_turn(
            &served.registry,
            &served.deployment,
            &sink,
            "turn-1",
            fam,
            &ids,
            "Retrieved: window closes 22:00 IST.",
            &served.control_sha,
        )
        .unwrap();

    // The provider call happens AFTER compile_turn returns — simulate it now.
    {
        let mut guard = log.lock().unwrap();
        guard.push("provider-called".to_string());
    } // guard released here before the next lock acquisition

    let log_snapshot = log.lock().unwrap().clone();
    assert_eq!(
        log_snapshot,
        vec!["prompt-recorded".to_string(), "provider-called".to_string()],
        "the forensic record must be written before the provider call"
    );
    // The recorded hash matches the exact text that would be sent → byte-for-byte replayable.
    let rec = sink.last.lock().unwrap().clone().unwrap();
    assert_eq!(rec.prompt_hash, content_fingerprint(&compiled.text));
}

#[test]
fn r11_failed_serve_records_no_phantom_prompt() {
    let served = default_served_chat_prompts();
    let ids: Vec<&str> = served.layer_ids.iter().map(|s| s.as_str()).collect();
    let log = Arc::new(Mutex::new(Vec::new()));
    let sink = OrderedSink {
        log: log.clone(),
        last: Mutex::new(None),
    };
    let est = HeuristicTokens;
    let cond = TruncatingCondenser;
    let svc = PromptService::new(&est, &cond, 10_000);

    // A family with no pinned variant → serve fails closed BEFORE any record is emitted.
    let err = svc
        .compile_turn(
            &served.registry,
            &served.deployment,
            &sink,
            "t",
            &ModelFamily::new("no-such-family"),
            &ids,
            "ctx",
            &served.control_sha,
        )
        .unwrap_err();
    assert!(matches!(err, ServeError::VariantNotDeployed { .. }));
    assert!(
        log.lock().unwrap().is_empty(),
        "a failed compile must not record a phantom prompt"
    );
}
