// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX ainxt-retrieval (gap6-retrieval-maintenance, item 1) — proving tests: the composition-root
//! KB index-maintenance cadence (`AssembledFull::run_kb_maintenance_tick` /
//! `AssembledFull::spawn_kb_maintenance_sweep`) genuinely reaches `ainxt_retrieval::maintenance`'s
//! `IndexState`/`ReindexTrigger`/`RecallLatencyMonitor` through a real assembled surface — previously
//! reachable only from `ainxt-retrieval`'s own unit tests, with zero callers anywhere in the served
//! daemon.

use std::time::{SystemTime, UNIX_EPOCH};

use ainxt_retrieval::maintenance::IndexHealth;
use ainxt_runtimed::{assemble_full, assemble_surface, load_layered, LoadedConfig};

fn unique_log_dir(tag: &str) -> String {
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir()
        .join(format!("ainxt-r-kbmaint-{tag}-{nanos}"))
        .to_string_lossy()
        .into_owned()
}

fn two_doc_config(tag: &str) -> LoadedConfig {
    let dir = unique_log_dir(tag);
    let src = format!(
        r#"
        version = 1
        [server]
        event_log_dir = {dir:?}
        [[kb.documents]]
        id = "doc-1"
        text = "Settlement reconciliation runs in deferred net batches via the payment switch."
        scope = "platform"
        data_class = "internal"
        [[kb.documents]]
        id = "doc-2"
        text = "UPI dispute resolution follows the payment grievance redressal timeline."
        scope = "platform"
        data_class = "internal"
        "#
    );
    load_layered(&[("r-kbmaint", &src)]).expect("load config")
}

#[test]
fn initial_tick_builds_the_index_and_embeds_every_configured_document() {
    let loaded = two_doc_config("initial");
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat surface");
    let full = assemble_full(&loaded, assembled).expect("assemble fully-wired surface");

    let outcome = full.run_kb_maintenance_tick(100);
    assert_eq!(
        outcome.triggers.len(),
        2,
        "both configured docs are new: {:?}",
        outcome.triggers
    );
    assert!(outcome.triggers.iter().all(|t| t.needs_embedding()));
    let reembed = outcome
        .reembed
        .expect("a non-empty trigger set must drive a real reembed");
    assert!(
        reembed.complete(),
        "the offline embedder never fails on real text: {:?}",
        reembed.failed_ids()
    );
    assert_eq!(reembed.embeddings.len(), 2);

    // Re-ticking with IDENTICAL content and no recorded degradation produces NO further triggers —
    // proving this is genuinely incremental, never a full rebuild every tick.
    let outcome2 = full.run_kb_maintenance_tick(101);
    assert!(
        outcome2.triggers.is_empty(),
        "unchanged content + no degradation must warrant no reindex: {:?}",
        outcome2.triggers
    );
    assert!(outcome2.reembed.is_none());
}

#[test]
fn a_recorded_recall_degradation_forces_a_real_full_reindex() {
    let loaded = two_doc_config("degraded");
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat surface");
    let full = assemble_full(&loaded, assembled).expect("assemble fully-wired surface");

    // Build the initial index.
    let first = full.run_kb_maintenance_tick(100);
    assert_eq!(first.triggers.len(), 2);

    // Simulate a live query-time sampler recording a recall measurement that breaches the configured
    // SLO floor (0.95 default) — exactly the seam `record_recall` exists for.
    full.kb_recall_monitor.lock().unwrap().record_recall(0.40);

    let degraded = full.run_kb_maintenance_tick(200);
    assert!(
        matches!(degraded.health, IndexHealth::RecallDegraded { .. }),
        "expected a degraded verdict: {:?}",
        degraded.health
    );
    assert_eq!(
        degraded.triggers.len(),
        2,
        "a degraded index must force a FULL rebuild of every tracked node, even though no content \
         changed: {:?}",
        degraded.triggers
    );
    assert!(degraded.triggers.iter().all(|t| t.needs_embedding()));
    let reembed = degraded
        .reembed
        .expect("a degraded index must drive a real reindex");
    assert!(reembed.complete(), "{:?}", reembed.failed_ids());
    assert_eq!(
        reembed.embeddings.len(),
        2,
        "every node must be re-embedded on a forced rebuild"
    );

    // Once health recovers (enough fresh, good recall samples to pull the rolling mean back above
    // the SLO floor) and content is still unchanged, the next tick warrants no further reindex —
    // degradation-driven rebuilds are not permanently sticky.
    {
        let mut monitor = full.kb_recall_monitor.lock().unwrap();
        for _ in 0..50 {
            monitor.record_recall(1.0);
        }
    }
    let recovered = full.run_kb_maintenance_tick(300);
    assert!(recovered.health.is_healthy(), "{:?}", recovered.health);
    assert!(recovered.triggers.is_empty(), "{:?}", recovered.triggers);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_spawned_cadence_reaches_the_real_shared_maintenance_state() {
    let loaded = two_doc_config("cadence");
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat surface");
    let full = assemble_full(&loaded, assembled).expect("assemble fully-wired surface");

    assert!(
        full.kb_index_state.lock().unwrap().is_empty(),
        "precondition: nothing indexed yet"
    );

    let handle = full.spawn_kb_maintenance_sweep(std::time::Duration::from_millis(20));
    // Let the REAL background task run several real ticks over real wall-clock time.
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    handle.abort();

    let state = full.kb_index_state.lock().unwrap();
    assert_eq!(
        state.len(),
        2,
        "the REAL spawned cadence — not a direct call — must have built the index"
    );
    assert!(state.indexed_tick("doc-1").is_some());
    assert!(state.indexed_tick("doc-2").is_some());
}
