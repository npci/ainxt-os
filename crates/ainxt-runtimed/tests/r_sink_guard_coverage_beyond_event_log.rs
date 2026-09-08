// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX regulated-fi-responsible-lifecycle — FI-01 §5.4 defense-in-depth sink sweep, extended
//! BEYOND the Event Log (`AssembledFull::sweep_event_log`/`sweep_all_sessions`) to the other durable
//! sinks `ainxt_compliance`'s own module doc names alongside it (`crates/ainxt-compliance/src/lib.rs`:
//! "Event Log, memory, vector index, traces, DSAR exports"): **memory**
//! (`AssembledFull::sweep_memory`), the durable turn-tree **traces** store behind `/v1/replay*`
//! (`AssembledFull::sweep_replay_traces`/`sweep_all_replay_traces`), and the KB **vector-index**
//! corpus every served ChatSurface's retriever grounds against (`AssembledFull::sweep_vector_index`).
//!
//! Each proof mirrors `r5_served_governed.rs`'s `sweep_event_log_catches_a_bypassed_raw_write` EXACTLY:
//! a baseline clean sweep (empty hits, zero incidents armed), then a write-path bypass that lands raw
//! CHD directly in the sink underneath the guard, and a sweep that catches EXACTLY that record while
//! never echoing the raw PAN in its own reported sample, and arms exactly one §5.4 store-sweep
//! incident on the live served register.

use std::collections::BTreeMap;

use ainxt_memory::durable::SqlLike;
use ainxt_memory::{ConsentBacking, MemoryItem, MemoryKind, Provenance, Scope};
use ainxt_replay::{DurableSession, EventKind, ReplayEvent, TurnTree};
use ainxt_runtimed::{assemble_chat, assemble_full, load_layered, KbConfig, KbDocument, KbScope};
use ainxt_types::DataClass;

// =========================== memory sink ===========================

/// FI-01 §5.4 — `AssembledFull::sweep_memory` must catch a write that bypassed the memory store's own
/// write-path redactor (`StrongMemoryRedactor` on every `write_as`), mirroring
/// `sweep_event_log_catches_a_bypassed_raw_write`'s exact structure over a different sink.
#[test]
fn sweep_memory_catches_a_bypassed_raw_write() {
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let loaded = load_layered(&[("t", "version = 1\n")]).unwrap();
    let assembled = assemble_chat(&loaded).unwrap();
    let full = assemble_full(&loaded, assembled).unwrap();
    let backing = full
        .memory_consent
        .clone()
        .expect("a chat surface must expose a memory_consent backing");

    // Baseline: no items at all sweeps clean (the positive proof) — mirrors the event log test's
    // "a session with only guarded writes must sweep clean" baseline.
    assert!(
        full.sweep_memory(1000).is_empty(),
        "an empty/guarded-only memory store must sweep clean"
    );
    assert_eq!(
        full.incidents.lock().unwrap().incidents().count(),
        0,
        "a clean sweep must arm no incident"
    );

    // Simulate a write-path bypass: reach BELOW `InMemoryStore`'s mandatory redactor gate and land a
    // raw PAN straight into the durable backend's `memory_items` table via `SqlLike::upsert_item` —
    // exactly the shape of bypass `sweep_event_log`'s own test simulates with a bare `JsonlEventLog`
    // pointed at the SAME directory instead of going through `GuardedEventLog`.
    let ConsentBacking::Durable(backend) = &*backing else {
        panic!("assemble_chat's memory_consent must be the Durable variant");
    };
    let mut raw = MemoryItem::new(
        "bypassed-item",
        MemoryKind::Episodic,
        Scope::User("eve".into()),
        "note",
        "refund to card 4111111111111111 done",
        Provenance::human("eve", 1.0),
    );
    raw.data_class = DataClass::Internal;
    let body = serde_json::to_string(&raw).expect("serialize raw item");
    backend
        .upsert_item(&raw.id, raw.version, &body)
        .expect("simulate a write-path bypass directly on the durable backend");

    let hits = full.sweep_memory(2000);
    assert_eq!(
        hits.len(),
        1,
        "the sweep must catch exactly the bypassed record: {hits:?}"
    );
    assert!(
        hits[0].record_id.starts_with("bypassed-item@v"),
        "the hit id must identify the bypassed item/version: {hits:?}"
    );
    assert!(
        !hits[0].sample.contains("4111111111111111"),
        "the sweep's own sample must be redacted, never echo the raw PAN it found"
    );
    assert_eq!(
        full.incidents.lock().unwrap().incidents().count(),
        1,
        "a memory sweep hit must arm exactly one store-sweep incident on the live served register"
    );
}

/// A surface with no chat engine (bare-engine) has no memory reader — `sweep_memory` must return an
/// empty result rather than panicking on the `None` backing, exactly mirroring `sweep_event_log`'s own
/// "nothing to check" behavior for a session the log has never seen.
#[test]
fn sweep_memory_is_a_harmless_empty_result_with_no_chat_engine() {
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let loaded = load_layered(&[("t", "version = 1\n")]).unwrap();
    let assembled = ainxt_runtimed::assemble(&loaded).unwrap(); // bare engine — no ChatSurface
    let full = assemble_full(&loaded, assembled).unwrap();
    assert!(
        full.memory_consent.is_none(),
        "the bare-engine surface has no memory reader"
    );
    assert!(full.sweep_memory(1).is_empty());
}

// =========================== traces (replay store) sink ===========================

fn raw_pan_session(session_id: &str, event_id: u64, text: &str) -> DurableSession {
    DurableSession {
        id: session_id.to_string(),
        tree: TurnTree::new(),
        events: vec![ReplayEvent {
            id: event_id,
            turn_id: "t1".to_string(),
            seq: event_id,
            ts_millis: 0,
            kind: EventKind::TextDelta,
            data_class: DataClass::Internal,
            text: text.to_string(),
        }],
        participants: vec!["eve".to_string()],
        next_event_id: event_id + 1,
    }
}

/// FI-01 §5.4 — `AssembledFull::sweep_replay_traces` must catch a raw PAN saved directly through the
/// `SessionStore` seam (the durable turn-tree store behind `/v1/replay*`), mirroring
/// `sweep_event_log_catches_a_bypassed_raw_write` over the "traces" sink.
#[test]
fn sweep_replay_traces_catches_a_bypassed_raw_write() {
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let loaded = load_layered(&[("t", "version = 1\n")]).unwrap();
    let assembled = assemble_chat(&loaded).unwrap();
    let full = assemble_full(&loaded, assembled).unwrap();

    // Baseline: a clean session sweeps empty.
    full.replay_store
        .save(&raw_pan_session(
            "sweep-sess",
            1,
            "hello, nothing sensitive here",
        ))
        .unwrap();
    assert!(
        full.sweep_replay_traces("sweep-sess", 1000).is_empty(),
        "a session with only clean text must sweep clean"
    );
    assert_eq!(full.incidents.lock().unwrap().incidents().count(), 0);

    // A write-path bypass: a raw PAN saved straight through the `SessionStore` seam (the redaction
    // step lives in the caller — `persist_served_turn`/`record_served_turn` — never in the store
    // itself, so a caller that skips it looks exactly like this).
    full.replay_store
        .save(&raw_pan_session(
            "sweep-sess",
            2,
            "refund to card 4111111111111111 done",
        ))
        .unwrap();

    let hits = full.sweep_replay_traces("sweep-sess", 2000);
    assert_eq!(
        hits.len(),
        1,
        "the sweep must catch exactly the bypassed record: {hits:?}"
    );
    assert!(!hits[0].sample.contains("4111111111111111"));
    assert_eq!(
        full.incidents.lock().unwrap().incidents().count(),
        1,
        "a traces sweep hit must arm exactly one store-sweep incident"
    );
}

/// GAP-FIX regulated-fi-responsible-lifecycle — `sweep_all_replay_traces` covers every session the
/// durable `SessionStore` knows about (via the new `SessionStore::sessions()`), without the caller
/// already knowing which session to check — mirrors `sweep_all_sessions`'s identical role for the
/// Event Log.
#[test]
fn sweep_all_replay_traces_catches_a_bypass_without_being_told_the_session_name() {
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let loaded = load_layered(&[("t", "version = 1\n")]).unwrap();
    let assembled = assemble_chat(&loaded).unwrap();
    let full = assemble_full(&loaded, assembled).unwrap();

    full.replay_store
        .save(&raw_pan_session("sess-a", 1, "clean"))
        .unwrap();
    full.replay_store
        .save(&raw_pan_session("sess-b", 1, "also clean"))
        .unwrap();
    full.replay_store
        .save(&raw_pan_session(
            "sess-c-bypassed",
            1,
            "refund to card 4111111111111111 done",
        ))
        .unwrap();

    assert!(
        full.replay_store.sessions().len() >= 3,
        "the store must enumerate all three sessions it holds: {:?}",
        full.replay_store.sessions()
    );

    let hits = full.sweep_all_replay_traces(500);
    assert_eq!(
        hits.len(),
        1,
        "sweep_all_replay_traces must find the bypassed record without being told which session: {hits:?}"
    );
    assert_eq!(full.incidents.lock().unwrap().incidents().count(), 1);
}

// =========================== vector-index (KB corpus) sink ===========================

fn kb_doc(id: &str, text: &str) -> KbDocument {
    KbDocument {
        id: id.into(),
        source: format!("{id}.md"),
        text: text.into(),
        data_class: DataClass::Internal,
        scope: KbScope::Platform,
        namespace: None,
        repo: None,
        department: None,
        max_ad_level: None,
        allow_groups: vec![],
        deny_groups: vec![],
        row_attributes: BTreeMap::new(),
    }
}

/// FI-01 §5.4 — `AssembledFull::sweep_vector_index` must catch a raw PAN that landed in a `[kb]`
/// document — the analog, for the KB corpus every served ChatSurface actually retrieves from, of what
/// `sweep_event_log` proves for the Event Log's write path (here: the INGESTION path, since this OSS
/// tree's KB content is admin-provisioned config, not written by a served turn).
#[test]
fn sweep_vector_index_catches_a_raw_pan_in_a_kb_document() {
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let mut loaded = load_layered(&[("t", "version = 1\n")]).unwrap();
    loaded.kb = KbConfig {
        documents: vec![
            kb_doc(
                "clean-doc",
                "settlement reconciliation runbook, nothing sensitive",
            ),
            kb_doc("bypassed-doc", "refund to card 4111111111111111 done"),
        ],
        rls_department_isolation: false,
        rag_enabled: true,
    };
    let assembled = assemble_chat(&loaded).unwrap();
    let full = assemble_full(&loaded, assembled).unwrap();

    let hits = full.sweep_vector_index(1000);
    assert_eq!(
        hits.len(),
        1,
        "the sweep must catch exactly the PAN-carrying document: {hits:?}"
    );
    assert_eq!(hits[0].record_id, "bypassed-doc");
    assert!(!hits[0].sample.contains("4111111111111111"));
    assert_eq!(
        full.incidents.lock().unwrap().incidents().count(),
        1,
        "a vector-index sweep hit must arm exactly one store-sweep incident"
    );
}

/// A KB whose documents are all clean sweeps empty and arms no incident — the sweep's positive proof,
/// exactly mirroring the Event Log sweep's baseline.
#[test]
fn sweep_vector_index_is_clean_when_kb_documents_are_clean() {
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let mut loaded = load_layered(&[("t", "version = 1\n")]).unwrap();
    loaded.kb = KbConfig {
        documents: vec![kb_doc("clean-doc", "settlement reconciliation runbook")],
        rls_department_isolation: false,
        rag_enabled: true,
    };
    let assembled = assemble_chat(&loaded).unwrap();
    let full = assemble_full(&loaded, assembled).unwrap();
    assert!(full.sweep_vector_index(1).is_empty());
    assert_eq!(full.incidents.lock().unwrap().incidents().count(), 0);
}
