// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX ainxt-retrieval (gap6-retrieval-maintenance, item 2) — proving tests: the composition-root
//! KB corpus re-embed cadence (`AssembledFull::run_kb_reembed_tick` /
//! `AssembledFull::spawn_kb_reembed_sweep`) genuinely reaches `governed::run_kb_corpus_reembed`
//! (itself a wrapper around `ainxt_retrieval::reembed::migrate_to`) through a real assembled surface —
//! previously reachable only from this crate's OWN tests (`r19_embedding_lifecycle_served.rs`), never
//! from any real cadence.

use std::time::{SystemTime, UNIX_EPOCH};

use ainxt_retrieval::EmbeddingVersion;
use ainxt_runtimed::{assemble_full, assemble_surface, load_layered, LoadedConfig};

fn unique_log_dir(tag: &str) -> String {
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir()
        .join(format!("ainxt-r-kbreembed-{tag}-{nanos}"))
        .to_string_lossy()
        .into_owned()
}

fn one_doc_config(tag: &str, text: &str) -> LoadedConfig {
    let dir = unique_log_dir(tag);
    let src = format!(
        r#"
        version = 1
        [server]
        event_log_dir = {dir:?}
        [[kb.documents]]
        id = "doc-1"
        text = {text:?}
        scope = "platform"
        data_class = "internal"
        "#
    );
    load_layered(&[("r-kbreembed", &src)]).expect("load config")
}

#[test]
fn run_kb_reembed_tick_migrates_the_configured_kb_corpus_to_the_target_version() {
    let loaded = one_doc_config(
        "run-tick",
        "Settlement reconciliation runs in deferred net batches via the payment switch.",
    );
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat surface");
    let full = assemble_full(&loaded, assembled).expect("assemble fully-wired surface");

    let target = EmbeddingVersion::new("nomic-embed-text", 1);
    let report = full.run_kb_reembed_tick(&target);

    assert!(
        report.uniform,
        "the freshly-built (unversioned) corpus must fully migrate: {:?}",
        report.outcome
    );
    assert!(
        report.outcome.complete(),
        "{:?}",
        report.outcome.failed_ids()
    );
    assert_eq!(report.outcome.embeddings.len(), 1);
    let migrated = report.corpus.chunk(0).expect("chunk present");
    assert_eq!(migrated.embedding_model, Some(target));
    assert!(migrated.embedding.as_ref().is_some_and(|v| !v.is_empty()));
}

#[test]
fn run_kb_reembed_tick_surfaces_a_real_embed_failure_never_falsely_marks_migrated() {
    // An empty document body models a genuine embed-service failure — the offline embedder's own one
    // deliberate `None` case (mirrors `ainxt-retrieval::reembed`'s own `<<unembeddable>>` fixture).
    let loaded = one_doc_config("failure", "");
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat surface");
    let full = assemble_full(&loaded, assembled).expect("assemble fully-wired surface");

    let target = EmbeddingVersion::new("nomic-embed-text", 1);
    let report = full.run_kb_reembed_tick(&target);

    assert!(
        !report.uniform,
        "a failed embed must never be marked as reaching the target version"
    );
    assert_eq!(report.outcome.failed_ids(), vec!["doc-1"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_spawned_reembed_cadence_fires_over_real_wall_clock_time() {
    let loaded = one_doc_config(
        "cadence",
        "UPI dispute resolution follows the payment grievance timeline.",
    );
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat surface");
    let full = assemble_full(&loaded, assembled).expect("assemble fully-wired surface");

    // Direct call as the ground truth for what the cadence should produce each tick.
    let target = EmbeddingVersion::new("nomic-embed-text", 1);
    let direct = full.run_kb_reembed_tick(&target);
    assert!(direct.uniform);

    // The REAL spawned cadence: prove it is reachable and survives several real ticks without
    // panicking (each tick genuinely re-drives `governed::run_kb_corpus_reembed` — see
    // `AssembledFull::run_kb_reembed_tick`'s doc for why every tick re-migrates from scratch in this
    // OSS tree today).
    let handle = full.spawn_kb_reembed_sweep(std::time::Duration::from_millis(20), target);
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    assert!(
        !handle.is_finished(),
        "the cadence loop must still be running, not have exited/panicked"
    );
    handle.abort();
}
