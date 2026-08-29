// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-16 memory — GAP-FIX: `ainxt_memory::PromotionPipeline::condense` / `write_candidates`
//! (design §3/§6: episodic → semantic distillation, "promotion, not duplication") were fully
//! implemented and unit-tested but had ZERO callers outside `ainxt-memory`'s own tests: nothing in
//! the served daemon ever ran a condensation checkpoint, so a durable, confidently-authored episodic
//! record never actually promoted to a durable semantic fact / user preference on any real
//! deployment — it just aged out on its TTL, however durable and well-confirmed it was.
//!
//! This wires [`ainxt_memory::ConsentBacking::run_promotion_sweep`] into
//! [`AssembledFull::run_memory_promotion_tick`] (the pure, synchronously-drivable entrypoint) and
//! [`AssembledFull::spawn_memory_promotion_sweep`] (the background timer loop, mirroring
//! `spawn_memory_reembed_sweep`/`spawn_memory_re_redact_sweep`), and threads
//! `main.rs`'s missing boot-time spawn call.
//!
//! Fail-before: `AssembledFull` had no `run_memory_promotion_tick` entrypoint at all — this file
//! would not compile. Pass-after: an episodic record written through the SAME served write seam
//! `POST /memory/remember` uses (`AssembledFull::memory_writer`) is distilled into a durable
//! `UserPreference` fact by the composition root's own sweep entrypoint, and that fact is visible
//! through the SAME served MEM-10 consent/export surface (`AssembledFull::memory_consent`) — not a
//! side channel only the sweep itself can see.

use std::time::{SystemTime, UNIX_EPOCH};

use ainxt_memory::{AccessScope, MemoryItem, MemoryKind, Provenance, Scope};
use ainxt_runtimed::{assemble_full, assemble_surface, load_layered, LoadedConfig};
use ainxt_types::Principal;

fn unique_log_dir(tag: &str) -> String {
    // R16 critical: the daemon refuses the header-trusting default authenticator unless the
    // deployment states the assumption (see r10_breach_clock_unit.rs / r13_attestation_refresh_wired.rs).
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir()
        .join(format!("ainxt-r16-mempromo-{tag}-{nanos}"))
        .to_string_lossy()
        .into_owned()
}

fn chat_config() -> LoadedConfig {
    let dir = unique_log_dir("cfg");
    let src = format!("version = 1\n[server]\nevent_log_dir = {dir:?}\n");
    load_layered(&[("r16", &src)]).expect("load default config")
}

#[test]
fn r16_memory_promotion_tick_distills_an_episodic_record_reachable_from_the_served_consent_surface()
{
    let loaded = chat_config();
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat surface");
    let full = assemble_full(&loaded, assembled).expect("assemble fully-wired surface");

    let writer = full
        .memory_writer
        .clone()
        .expect("a chat-engine surface exposes a live memory writer (write-path-missing fix)");
    let access = AccessScope::from_principal(Principal::user("alice", &[]));

    // The SAME write seam `POST /memory/remember` uses authors a durable, confidently-stated
    // episodic preference — no transient marker, confidence above the default 0.6 floor, so it
    // clears the durability heuristic.
    writer
        .write_as(
            MemoryItem::new(
                "ep-1",
                MemoryKind::Episodic,
                Scope::User("alice".into()),
                "editor preference",
                "alice prefers dark mode in the editor",
                Provenance::human("alice", 0.95),
            )
            // `PromotionPipeline::build_candidate` promotes a `preference`-tagged episodic record
            // to `MemoryKind::UserPreference` rather than the plain `Semantic` default.
            .with_tags(&["preference"]),
            &access,
        )
        .expect("write the episodic record through the served write seam");

    // Precondition: nothing durable exists for alice yet — only the raw episodic row.
    let backing = full
        .memory_consent
        .clone()
        .expect("chat surface exposes MEM-10 consent backing");
    let before = backing
        .with_surface(|s| s.export_subject("alice", &access))
        .expect("export before the sweep");
    assert!(
        !before
            .items
            .iter()
            .any(|i| i.kind == MemoryKind::UserPreference),
        "precondition: no durable preference exists yet: {:?}",
        before.items
    );

    // The daemon's periodic sweep entrypoint — the exact call `spawn_memory_promotion_sweep`'s
    // background loop makes — drives ONE condensation checkpoint through the SAME `ConsentBacking`
    // the served MEM-10 consent/export/erasure route reads.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let written = full
        .run_memory_promotion_tick(now)
        .expect("a chat-engine surface has a memory backing to sweep");
    assert_eq!(
        written, 1,
        "exactly the one qualifying episodic record should have been promoted"
    );

    // The promoted fact is visible through the SAME served consent/export surface — not a side
    // channel only the sweep's own internal store can see.
    let after = backing
        .with_surface(|s| s.export_subject("alice", &access))
        .expect("export after the sweep");
    let promoted = after
        .items
        .iter()
        .find(|i| i.kind == MemoryKind::UserPreference)
        .expect("the distilled UserPreference fact must be visible via the served consent surface");
    assert!(
        promoted.body.contains("dark mode"),
        "the promoted fact must carry the distilled content: {}",
        promoted.body
    );
    // The raw episodic source is retained (never deleted by promotion — it ages out on its own TTL).
    assert!(
        after
            .items
            .iter()
            .any(|i| i.id == "ep-1" && i.kind == MemoryKind::Episodic),
        "promotion must not delete the source episodic record"
    );

    // A second sweep on an unchanged store is a safe no-op: the still-present source episodic record
    // is now rejected as a duplicate of the fact it already produced (design §3: "promotion, not
    // duplication") — it does not double-promote or overwrite.
    let second = full
        .run_memory_promotion_tick(now + 1)
        .expect("second sweep runs");
    assert_eq!(
        second, 0,
        "a repeat sweep over an unchanged store must not re-promote"
    );
}

#[test]
fn r16_memory_promotion_tick_none_on_a_surface_with_no_chat_engine() {
    let loaded = chat_config();
    // The bare-engine surface (`assemble`, not `assemble_surface`) has no chat engine, hence no
    // memory reader/writer/backend at all (see `Assembled::memory_backend`'s doc) — the promotion
    // sweep has nothing to run over, matching `run_memory_re_redact_tick`'s own `None`-on-nothing-
    // declared shape.
    let assembled = ainxt_runtimed::assemble(&loaded).expect("assemble the bare-engine surface");
    let full = assemble_full(&loaded, assembled).expect("assemble fully-wired surface");
    assert!(
        full.memory_consent.is_none(),
        "bare-engine surface has no memory backing"
    );
    assert_eq!(full.run_memory_promotion_tick(0), None);
    // Spawning the sweep loop is likewise a harmless no-op (never panics, no task spun up).
    assert!(full
        .spawn_memory_promotion_sweep(std::time::Duration::from_secs(600))
        .is_none());
}
