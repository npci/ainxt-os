// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-3 memory — embed-on-write was never wired into the served daemon.
//!
//! `ainxt_memory::store::InMemoryStore::embed_on_write` (design `ENTERPRISE_MEMORY_LEARNING.md` §2
//! `embedding` field / §8.5 data-class routing) is fully implemented and unit-tested inside
//! `ainxt-memory` itself, but `with_embedders` had ZERO callers outside that crate's own tests: the
//! shipped daemon's `DurableMemoryReader::open` (`ainxt-runtimed/src/lib.rs`) never configured an
//! embedder, so `inhouse_embedder`/`cloud_embedder` were always `None` and `embed_on_write` hit its
//! early return (`store.rs:977`, "embed-on-write not configured for this tier") on every real write.
//! A freshly-written memory item's `.embedding` stayed `None` forever, and there was no separate
//! reindex/backfill path that ever ran in the served daemon to catch up — semantic recall
//! (`MemoryQuery::semantic`) had structurally nothing to match against.
//!
//! Fail-before: before this fix, `store.get(id).unwrap().embedding` was `None` immediately after
//! `write()` on the shipped daemon's own `ConsentBacking`-backed store, and a semantic query over the
//! item's own body-derived vector matched nothing. Pass-after (this test): `DurableMemoryReader::open`
//! now installs a real (`MemoryHashEmbedder`) offline default at both tiers, so a write gets a
//! populated, correctly-tiered `.embedding` synchronously, in the SAME call that persists it — no
//! separate reindex step required for the item to become recall-eligible.

use ainxt_memory::{
    AccessScope, ConsentBacking, EmbedderKind, MemoryItem, MemoryKind, MemoryQuery, MemoryStore,
    Provenance, Scope,
};
use ainxt_runtimed::{assemble_chat, assemble_full, load_layered, DurableMemoryReader};
use ainxt_types::{DataClass, Principal};
use std::time::{SystemTime, UNIX_EPOCH};

fn loaded_with_unique_log() -> ainxt_runtimed::LoadedConfig {
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("ainxt-r-embedonwrite-{nanos}"));
    let src = format!(
        "version = 1\n[server]\nevent_log_dir = {:?}\n",
        dir.to_string_lossy()
    );
    load_layered(&[("r-embedonwrite", &src)]).expect("load offline config")
}

#[test]
fn r_embed_on_write_makes_a_fresh_write_semantically_recall_eligible_with_no_reindex_step() {
    let loaded = loaded_with_unique_log();
    let assembled = assemble_chat(&loaded).expect("assemble chat");
    let full = assemble_full(&loaded, assembled).expect("assemble full");

    let backing = full
        .memory_consent
        .clone()
        .expect("a chat-engine surface exposes a memory backing (MEM-10)");
    let backend = match backing.as_ref() {
        ConsentBacking::Durable(backend) => backend.clone(),
        ConsentBacking::InMemory(_) => panic!("the shipped chat surface uses the Durable backing"),
    };

    // `DurableMemoryReader::open` is the EXACT function the daemon itself calls (via
    // `build_durable_memory_reader`) to construct the served chat engine's own persistent memory
    // writer — this is where the embed-on-write fix lives (`.with_embedders(...)`), not on the
    // consent surface's own per-request, ad-hoc-opened stores (those are read/promote-only). Calling
    // the SAME public constructor over a clone of the SAME backend proves the fix is really reachable
    // from the daemon's real write path, not a bespoke test-only store.
    let reader = DurableMemoryReader::open(backend).expect("open the daemon's real memory writer");
    let mut store = reader.store();

    // A plain (non-regulated) write must be embedded via the CLOUD tier. Written `write_as` under an
    // approve-capable principal (design §8.2): a shared `Scope::Org` write via the bare `write()` would
    // otherwise be parked `Draft` (never authoritative) pending human approval — orthogonal to this
    // item's embed-on-write behavior, so authorize it explicitly rather than switching to `User` scope.
    let approver = AccessScope::from_principal(Principal::admin("oncall-approver"));
    store
        .write_as(
            MemoryItem::new(
                "incident-fx-gateway-restart",
                MemoryKind::Semantic,
                Scope::Org,
                "known fix for stuck FX queue",
                "restart the payment gateway service to clear the stuck settlement queue",
                Provenance::human("oncall", 1.0),
            ),
            &approver,
        )
        .expect("write plain item");

    // A regulated write must be embedded via the IN-HOUSE tier — never the cloud tier (ADR-012 /
    // design §8.5: regulated/PII content must never reach a shared cloud embedding API).
    store
        .write(
            MemoryItem::new(
                "customer-pan-note",
                MemoryKind::Semantic,
                Scope::User("agent7".into()),
                "cardholder callback note",
                "customer confirmed card ending in the usual digits, no PAN captured here",
                Provenance::human("agent7", 1.0),
            )
            .with_data_class(DataClass::Pii),
        )
        .expect("write regulated item");

    // ---- No reindex step: the vectors must already be populated right after write() returns. ----
    let plain = store
        .get("incident-fx-gateway-restart")
        .expect("plain item exists")
        .clone();
    let plain_embedding = plain
        .embedding
        .as_ref()
        .expect("embed-on-write must populate .embedding synchronously at write time, not later");
    assert_eq!(
        plain_embedding.kind,
        EmbedderKind::Cloud,
        "non-regulated content must route to the cloud embedder tier"
    );
    assert!(
        plain_embedding.vector.iter().any(|&x| x != 0.0),
        "the embedding must be a real (non-all-zero) vector derived from the body text"
    );

    let regulated = store
        .get("customer-pan-note")
        .expect("regulated item exists")
        .clone();
    let regulated_embedding = regulated
        .embedding
        .as_ref()
        .expect("embed-on-write must also cover regulated/PII-classed writes");
    assert_eq!(
        regulated_embedding.kind,
        EmbedderKind::InHouse,
        "regulated/PII content must NEVER be routed to the cloud embedder tier (ADR-012)"
    );

    // ---- Recall-eligible immediately: a semantic query over the item's own vector must retrieve it,
    // with no separate reindex/backfill call in between the write and this query. ----
    let access = AccessScope::from_principal(Principal::admin("test-reader"));
    let hits = store.query(
        &MemoryQuery::semantic(plain_embedding.vector.clone()).with_kind(MemoryKind::Semantic),
        &access,
    );
    assert!(
        hits.iter().any(|h| h.item.id == "incident-fx-gateway-restart" && h.score > 0.0),
        "the freshly-written item must be semantically recall-eligible immediately, with no reindex \
         step: got hits {:?}",
        hits.iter().map(|h| (&h.item.id, h.score)).collect::<Vec<_>>()
    );
}
