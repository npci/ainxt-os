// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-16 memory — GAP-FIX: `ainxt_memory::store::InMemoryStore::re_redact` /
//! `durable::DurableMemoryStore::re_redact` (design §8.6: "when compliance rules change, previously-
//! stored memory is re-scanned and re-redacted — leakage defense isn't only at write-time") were fully
//! implemented and unit-tested but had ZERO callers outside `ainxt-memory`'s own tests: nothing in the
//! served daemon ever re-swept an already-persisted row after a compliance-rule update, so content
//! written under a weaker/older rule-set stayed exposed in durable memory indefinitely.
//!
//! This wires [`ainxt_memory::ConsentBacking::re_redact`] into [`AssembledFull::run_memory_re_redact_tick`]
//! (the pure, synchronously-drivable entrypoint) and [`AssembledFull::spawn_memory_re_redact_sweep`] (the
//! background timer loop, mirroring `spawn_attestation_refresh`/`spawn_breach_clock`).
//!
//! Fail-before: `AssembledFull` had no `run_memory_re_redact_tick` entrypoint at all — this file would
//! not compile. Pass-after: a row written through a WEAK (no-op) redactor — simulating data persisted
//! before a compliance-rule tightened, or migrated in from a legacy source — is retroactively scrubbed
//! by the SAME strong redactor the served MEM-10 consent/export route already reads through, and the
//! scrub is durable (visible from a THIRD, independently-opened store over the same backend).

use std::time::{SystemTime, UNIX_EPOCH};

use ainxt_memory::{
    ConsentBacking, DurableMemoryStore, MemoryItem, MemoryKind, MemoryStore, Provenance, Redactor,
    Scope,
};
use ainxt_runtimed::{assemble_full, assemble_surface, load_layered, LoadedConfig};

const TEST_PAN: &str = "4111111111111111"; // canonical Visa test PAN used across this workspace's tests

/// An OLD (weak) rule-set that misses the PAN pattern entirely — `ainxt-memory`'s own default
/// (`BuiltinRedactor`) already catches this literal, so a genuinely no-op stand-in is needed to
/// simulate "data written before the daemon's compliance rules existed / migrated in from a legacy
/// source" (mirrors `store.rs`'s own `re_redaction_scrubs_previously_stored_items` test fixture).
#[derive(Debug)]
struct WeakRedactor;
impl Redactor for WeakRedactor {
    fn redact(&self, text: &str) -> String {
        text.to_string()
    }
}

fn unique_log_dir(tag: &str) -> String {
    // R16 critical: the daemon refuses the header-trusting default authenticator unless the deployment
    // states the assumption (see r10_breach_clock_unit.rs / r13_attestation_refresh_wired.rs).
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir()
        .join(format!("ainxt-r16-memredact-{tag}-{nanos}"))
        .to_string_lossy()
        .into_owned()
}

fn chat_config() -> LoadedConfig {
    let dir = unique_log_dir("cfg");
    let src = format!("version = 1\n[server]\nevent_log_dir = {dir:?}\n");
    load_layered(&[("r16", &src)]).expect("load default config")
}

#[test]
fn r16_memory_re_redact_tick_scrubs_previously_persisted_pan_through_the_composition_root() {
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

    // Simulate data that predates today's compliance rules (or was migrated from a legacy source): a
    // store opened over the SAME backend with an explicitly WEAK (no-op) redactor installed — never
    // the daemon's own StrongMemoryRedactor — writes a PAN straight through, unredacted.
    {
        let mut weak = DurableMemoryStore::open(backend.clone())
            .expect("open weak store")
            .with_redactor(Box::new(WeakRedactor));
        weak.write(MemoryItem::new(
            "legacy-note",
            MemoryKind::Episodic,
            Scope::User("alice".into()),
            "call note",
            &format!("customer read out card {TEST_PAN} over the phone"),
            Provenance::human("alice", 1.0),
        ))
        .expect("weak store accepts the write (no redactor installed)");
        assert!(
            weak.get_unchecked("legacy-note").unwrap().body.contains(TEST_PAN),
            "precondition: the PAN is genuinely unredacted in the pre-existing row"
        );
    }

    // Before the sweep: the SAME backend, reopened fresh, still shows the PAN — proving it is really
    // durable/committed, not merely held in the dropped `weak` instance's RAM.
    {
        let fresh =
            DurableMemoryStore::open(backend.clone()).expect("reopen over the same backend");
        assert!(fresh.get_unchecked("legacy-note").unwrap().body.contains(TEST_PAN));
    }

    // The daemon's periodic sweep entrypoint — the exact call `spawn_memory_re_redact_sweep`'s
    // background loop makes — drives ONE re-redaction pass through the SAME `ConsentBacking` the served
    // MEM-10 consent/export/erasure route reads.
    let changed = full
        .run_memory_re_redact_tick()
        .expect("a chat-engine surface has a memory backing to sweep");
    assert_eq!(
        changed, 1,
        "exactly the one legacy row should have been re-redacted"
    );

    // The scrub is durable: a THIRD, independently-opened store over a clone of the SAME backend sees
    // the PAN gone — not an artifact of the transient store the sweep opened internally.
    let after = DurableMemoryStore::open(backend).expect("reopen after the sweep");
    let item = after
        .get_unchecked("legacy-note")
        .expect("row still exists (redaction edits, never deletes)");
    assert!(
        !item.body.contains(TEST_PAN),
        "PAN must be scrubbed after the sweep: {}",
        item.body
    );

    // A second sweep is idempotent: nothing left to change.
    assert_eq!(
        full.run_memory_re_redact_tick(),
        Some(0),
        "idempotent: nothing left to re-redact"
    );
}

#[test]
fn r16_memory_re_redact_tick_none_on_a_surface_with_no_chat_engine() {
    let loaded = chat_config();
    // The bare-engine surface (`assemble`, not `assemble_surface`) has no chat engine, hence no memory
    // reader/backend at all (see `Assembled::memory_backend`'s doc) — the retroactive sweep has nothing
    // to run over, matching `run_attestation_refresh_tick`'s own `None`-on-nothing-declared shape.
    let assembled = ainxt_runtimed::assemble(&loaded).expect("assemble the bare-engine surface");
    let full = assemble_full(&loaded, assembled).expect("assemble fully-wired surface");
    assert!(
        full.memory_consent.is_none(),
        "bare-engine surface has no memory backing"
    );
    assert_eq!(full.run_memory_re_redact_tick(), None);
    // Spawning the sweep loop is likewise a harmless no-op (never panics, no task spun up).
    assert!(full
        .spawn_memory_re_redact_sweep(std::time::Duration::from_secs(300))
        .is_none());
}
