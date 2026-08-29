// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R19 (gap `context-fabric` / memory: embedding-lifecycle no caller) — two independent embedding
//! pipelines were fully implemented and unit-tested but had ZERO callers outside their own crates:
//!
//!   1. `ainxt_memory::store::InMemoryStore::reembed_all` / `DurableMemoryStore::reembed_all` (design
//!      §8.5: data-class-routed batch re-embed) — nothing in the served daemon ever ran it, so a
//!      platform embedding-model bump never reached already-persisted memory items.
//!   2. `ainxt_retrieval::reembed::migrate_to` (`CONTEXT_FABRIC.md` §4: "version-tracked embeddings +
//!      a re-embed pipeline so migrations never leave a mixed-version index") — nothing in the
//!      composition root ever ran the KB corpus migration.
//!
//! This wires (1) into `AssembledFull::run_memory_reembed_tick` / `spawn_memory_reembed_sweep`
//! (mirrors `run_memory_re_redact_tick` / `spawn_memory_re_redact_sweep` exactly), and (2) into
//! `ainxt_runtimed::governed::run_kb_corpus_reembed` (the explicit admin-triggered composition-root
//! entrypoint, mirroring `route_artifact_model`'s standalone-wrapper shape).

use std::time::{SystemTime, UNIX_EPOCH};

use ainxt_memory::{
    ConsentBacking, DurableMemoryStore, MemoryItem, MemoryKind, MemoryStore, Provenance, Scope,
};
use ainxt_retrieval::reembed::Embedder as RetrievalEmbedder;
use ainxt_retrieval::{Chunk, Corpus, EmbeddingVersion};
use ainxt_runtimed::governed::run_kb_corpus_reembed;
use ainxt_runtimed::{assemble_full, assemble_surface, load_layered, LoadedConfig};
use ainxt_types::DataClass;

fn unique_log_dir(tag: &str) -> String {
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir()
        .join(format!("ainxt-r19-embedlifecycle-{tag}-{nanos}"))
        .to_string_lossy()
        .into_owned()
}

fn chat_config() -> LoadedConfig {
    let dir = unique_log_dir("cfg");
    let src = format!("version = 1\n[server]\nevent_log_dir = {dir:?}\n");
    load_layered(&[("r19", &src)]).expect("load default config")
}

// ---- (1) memory reembed sweep, driven through the composition root ----

#[test]
fn r19_memory_reembed_tick_embeds_previously_unembedded_items_through_the_composition_root() {
    let loaded = chat_config();
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat surface");
    let full = assemble_full(&loaded, assembled).expect("assemble fully-wired surface");

    let backing = full
        .memory_consent
        .clone()
        .expect("a chat-engine surface exposes a memory backing (MEM-10)");
    let backend = match backing.as_ref() {
        ConsentBacking::Durable(backend) => backend.clone(),
        ConsentBacking::InMemory(_) => panic!("the shipped chat surface uses the Durable backing"),
    };

    // Write a plain (Internal data-class, non-regulated) item with NO embedding — exactly the shape a
    // real write leaves before any embed-on-write config is installed.
    {
        let mut store = DurableMemoryStore::open(backend.clone()).expect("open store");
        store
            .write(MemoryItem::new(
                "note-1",
                MemoryKind::Episodic,
                Scope::User("alice".into()),
                "call note",
                "customer asked about settlement timing",
                Provenance::human("alice", 1.0),
            ))
            .expect("write accepted");
        assert!(
            store.get("note-1").unwrap().embedding.is_none(),
            "precondition: freshly-written item carries no embedding"
        );
    }

    // The daemon's periodic sweep entrypoint — the exact call `spawn_memory_reembed_sweep`'s
    // background loop makes — drives ONE batch re-embed pass through the SAME `ConsentBacking` the
    // served MEM-10 consent/export/erasure route reads.
    let embedded = full
        .run_memory_reembed_tick()
        .expect("a chat-engine surface has a memory backing to sweep");
    assert_eq!(
        embedded, 1,
        "exactly the one item should have been embedded"
    );

    // Durable: a fresh, independently-opened store over the SAME backend sees the vector.
    let after = DurableMemoryStore::open(backend).expect("reopen after the sweep");
    let item = after.get("note-1").expect("row still exists");
    let embedding = item
        .embedding
        .as_ref()
        .expect("the item must now carry an embedding");
    assert!(
        !embedding.vector.is_empty(),
        "the computed vector must be non-empty"
    );
    // Internal (non-regulated) data-class routes to the CLOUD tier (design §8.5).
    assert_eq!(embedding.kind, ainxt_memory::EmbedderKind::Cloud);
    assert_eq!(embedding.model_id, "offline-hash-cloud-v1");

    // Re-running the sweep is deterministic: the same content re-embeds to the SAME vector (the
    // offline hash embedder has no hidden state), even though `reembed_all` is a full batch sweep
    // (not skip-if-already-embedded) — proving determinism, not merely "ran once".
    let embedded_again = full.run_memory_reembed_tick().expect("sweep again");
    assert_eq!(embedded_again, 1);
    let after2 = DurableMemoryStore::open(match backing.as_ref() {
        ConsentBacking::Durable(b) => b.clone(),
        _ => unreachable!(),
    })
    .unwrap();
    assert_eq!(
        after2
            .get("note-1")
            .unwrap()
            .embedding
            .as_ref()
            .unwrap()
            .vector,
        embedding.vector,
        "a deterministic embedder must reproduce the identical vector on a second sweep"
    );
}

#[test]
fn r19_memory_reembed_tick_none_on_a_surface_with_no_chat_engine() {
    let loaded = chat_config();
    let assembled = ainxt_runtimed::assemble(&loaded).expect("assemble the bare-engine surface");
    let full = assemble_full(&loaded, assembled).expect("assemble fully-wired surface");
    assert!(
        full.memory_consent.is_none(),
        "bare-engine surface has no memory backing"
    );
    assert_eq!(full.run_memory_reembed_tick(), None);
    assert!(full
        .spawn_memory_reembed_sweep(std::time::Duration::from_secs(300))
        .is_none());
}

// ---- (2) KB corpus embedding-version migration, driven through governed::run_kb_corpus_reembed ----

/// A tiny deterministic embedder for the retrieval-corpus migration path — refuses a sentinel text to
/// model a real embed-service failure (mirrors `ainxt-retrieval::reembed`'s own test fixture).
struct FakeCorpusEmbedder {
    version: EmbeddingVersion,
}
impl RetrievalEmbedder for FakeCorpusEmbedder {
    fn embed(&self, text: &str) -> Option<Vec<f32>> {
        if text == "<<unembeddable>>" {
            return None;
        }
        Some(vec![text.len() as f32])
    }
    fn version(&self) -> EmbeddingVersion {
        self.version.clone()
    }
}

#[test]
fn r19_run_kb_corpus_reembed_migrates_a_mixed_version_corpus_to_a_single_target_version() {
    let old = EmbeddingVersion::new("legacy-model", 1);
    let target = EmbeddingVersion::new("nomic-embed-text", 2);

    let mut stale_chunk = Chunk::new(
        "c1",
        "settlement reconciliation runbook",
        DataClass::Internal,
    );
    stale_chunk.embedding = Some(vec![0.0]);
    stale_chunk.embedding_model = Some(old.clone());
    let mut current_chunk = Chunk::new("c2", "already migrated", DataClass::Internal);
    current_chunk.embedding = Some(vec![1.0]);
    current_chunk.embedding_model = Some(target.clone());

    let corpus = Corpus::new(vec![stale_chunk, current_chunk]);
    assert!(
        !corpus.is_embedding_uniform(&target),
        "precondition: mixed-version corpus"
    );

    let embedder = FakeCorpusEmbedder {
        version: target.clone(),
    };
    let report = run_kb_corpus_reembed(&corpus, &target, &embedder);

    assert!(
        report.uniform,
        "every stale chunk must migrate to the target version: {:?}",
        report.outcome
    );
    assert!(
        report.outcome.complete(),
        "no embed failures expected: {:?}",
        report.outcome.failed_ids()
    );
    let migrated = report.corpus.chunk(0).expect("chunk c1 present");
    assert_eq!(migrated.embedding_model, Some(target.clone()));
    // The already-current chunk is untouched (not re-embedded — `stale_embeddings` only selects c1).
    let untouched = report.corpus.chunk(1).expect("chunk c2 present");
    assert_eq!(untouched.embedding, Some(vec![1.0]));
}

#[test]
fn r19_run_kb_corpus_reembed_surfaces_partial_failures_never_marks_falsely_migrated() {
    let target = EmbeddingVersion::new("nomic-embed-text", 2);
    let bad_chunk = Chunk::new("bad", "<<unembeddable>>", DataClass::Internal);
    let corpus = Corpus::new(vec![bad_chunk]);

    let embedder = FakeCorpusEmbedder {
        version: target.clone(),
    };
    let report = run_kb_corpus_reembed(&corpus, &target, &embedder);

    assert!(
        !report.uniform,
        "a failed embed must never be marked as reaching the target version"
    );
    assert_eq!(report.outcome.failed_ids(), vec!["bad"]);
}
