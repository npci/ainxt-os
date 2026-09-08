// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX memory — `ConsentSurface` is the thin seam a served surface can be generic over so it can
//! be handed EITHER `InMemoryStore` or `DurableMemoryStore`. `ConsentBacking::Durable` opens a FRESH
//! store from the shared backend on every call (a long-lived store only ever reads the snapshot it
//! was opened with — see the type doc on `ConsentBacking`), so a served DPDP request always reflects
//! whatever the real writer (e.g. the chat engine's own memory reader, opened over a clone of the
//! SAME backend) has committed, however recently — not a frozen startup-time snapshot.

use ainxt_memory::{
    AccessScope, ConsentBacking, DurableMemoryStore, MemoryItem, MemoryKind, MemorySqlBackend,
    MemoryStore, Provenance, Scope,
};
use ainxt_types::Principal;

fn item(id: &str, subject: &str, body: &str) -> MemoryItem {
    MemoryItem::new(
        id,
        MemoryKind::UserPreference,
        Scope::User(subject.to_string()),
        "pref",
        body,
        Provenance::human(subject, 1.0),
    )
}

fn scope_for(user: &str) -> AccessScope {
    AccessScope::from_principal(Principal::user(user, &[]))
}

#[test]
fn a_backing_opened_fresh_per_call_sees_every_write_a_separate_store_over_the_same_backend_makes() {
    let backend = MemorySqlBackend::new();

    // Store A: the served chat engine's own memory reader (writes a fact as part of a normal turn).
    let mut engine_store = DurableMemoryStore::open(backend.clone()).expect("open engine store");
    engine_store
        .write(item("p1", "alice", "prefers dark mode"))
        .expect("write");

    // The served route's handle: holds only the BACKEND clone, not a long-lived store.
    let backing = ConsentBacking::Durable(backend.clone());
    let access = scope_for("alice");

    let view = backing
        .with_surface(|s| s.remembered_about("alice", &access))
        .expect("remembered_about");
    assert_eq!(view.subject, "alice");
    assert!(
        view.by_kind
            .iter()
            .any(|(_, items)| items.iter().any(|i| i.id == "p1")),
        "a fresh-opened backing must see a write the engine store already committed: {view:?}"
    );

    // The engine keeps serving turns and writes a SECOND fact AFTER the first served read above.
    engine_store
        .write(item("p2", "alice", "prefers compact layout"))
        .expect("write second fact");

    // A backing over the SAME backend clone, called again, sees the new write immediately — proving
    // this is not a one-time snapshot copied at construction.
    let export = backing
        .with_surface(|s| s.export_subject("alice", &access))
        .expect("export_subject");
    assert!(export.items.iter().any(|i| i.id == "p1"));
    assert!(
        export.items.iter().any(|i| i.id == "p2"),
        "a backing must reflect writes made AFTER it was constructed, not just at construction time: \
         {export:?}"
    );

    // Right-to-erasure through the backing purges both — and the effect is visible back on the
    // ORIGINAL engine store too, once it reopens/re-syncs (same backend, same rows).
    let receipt = backing
        .with_surface(|s| s.erase_subject("alice"))
        .expect("erase_subject");
    assert!(receipt.removed_ids.contains(&"p1".to_string()));
    assert!(receipt.removed_ids.contains(&"p2".to_string()));

    let reopened = DurableMemoryStore::open(backend).expect("reopen over the same backend");
    assert!(
        reopened.get_unchecked("p1").is_none() && reopened.get_unchecked("p2").is_none(),
        "an erasure driven through the served backing must be durable on the SAME backend"
    );
}

#[test]
fn a_caller_who_may_not_see_the_subject_is_refused_through_the_backing() {
    let backend = MemorySqlBackend::new();
    let mut store = DurableMemoryStore::open(backend.clone()).expect("open");
    store
        .write(item("p1", "alice", "prefers dark mode"))
        .expect("write");

    let backing = ConsentBacking::Durable(backend);
    let mallory = scope_for("mallory");
    assert!(
        backing
            .with_surface(|s| s.remembered_about("alice", &mallory))
            .is_err(),
        "a caller who is not the subject (and not an admin) must be refused"
    );
}

#[test]
fn the_in_memory_backing_variant_shares_the_one_instance_it_was_given() {
    use std::sync::{Arc, Mutex};

    let store = Arc::new(Mutex::new(ainxt_memory::InMemoryStore::new()));
    {
        let mut guard = store.lock().unwrap();
        guard
            .write(item("p1", "alice", "prefers dark mode"))
            .expect("write");
    }

    let backing = ConsentBacking::InMemory(store.clone());
    let access = scope_for("alice");
    let view = backing
        .with_surface(|s| s.remembered_about("alice", &access))
        .expect("remembered_about");
    assert!(view
        .by_kind
        .iter()
        .any(|(_, items)| items.iter().any(|i| i.id == "p1")));

    backing
        .with_surface(|s| s.erase_subject("alice"))
        .expect("erase_subject");
    assert!(
        store.lock().unwrap().get_unchecked("p1").is_none(),
        "erasure through the in-memory backing must mutate the SAME shared instance"
    );
}
