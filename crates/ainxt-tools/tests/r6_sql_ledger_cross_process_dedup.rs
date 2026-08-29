// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! r6_sql_ledger_cross_process_dedup — durable cross-process exactly-once via the unique-key upsert
//! (§1.2, gap R+S).
//!
//! Fail-before: the only durable ledger was `EventLogLedger`, whose exactly-once is guarded by an
//! **in-process** `claim_lock` — invisible to a second daemon, so two processes over one log both
//! read "key absent" and both get `Fresh` → a double debit. There was no store-arbitrated claim and
//! no `SqlLedger`/`SqlLedgerDriver` type at all (this test would not compile against the old crate).
//!
//! Pass-after: `SqlLedger` over a SHARED `InMemorySqlStore` (the offline stand-in for one Postgres
//! table) holds NO per-process lock; the store's atomic unique-key upsert arbitrates the race, so
//! across two independent process handles — and across many concurrent threads — exactly ONE claim
//! is `Fresh`, every duplicate is `InDoubt`/`Committed`, and a committed result is deduped for BOTH
//! processes.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};

use ainxt_tools::{Claim, InMemorySqlStore, Ledger, SqlLedger};

/// Build one "process" handle (its own `SqlLedger`, no shared in-process state) over a clone of the
/// SAME durable store — exactly how two daemons attach to one database.
fn process(store: &InMemorySqlStore) -> SqlLedger<InMemorySqlStore> {
    SqlLedger::new(store.clone())
}

#[test]
fn r6_sql_ledger_cross_process_dedup() {
    // ---- Scenario 1: two processes, sequential claim on the same key ----
    let store = InMemorySqlStore::new();
    let proc_a = process(&store);
    let proc_b = process(&store);

    // Process A wins the unique-key claim.
    assert_eq!(
        proc_a.claim("settle:batch-7"),
        Claim::Fresh,
        "A took the slot"
    );
    // Process B, a *different* handle with no shared lock, sees the in-doubt row — NOT a second Fresh.
    assert_eq!(
        proc_b.claim("settle:batch-7"),
        Claim::InDoubt,
        "B must never get a second Fresh for the same key (that would double-execute)"
    );

    // A finishes the side effect and commits under the key.
    proc_a.commit("settle:batch-7", "settlement-ref-9931");
    // Both processes now dedup to the stored result — a retry on either node re-executes nothing.
    assert_eq!(
        proc_a.claim("settle:batch-7"),
        Claim::Committed("settlement-ref-9931".into())
    );
    assert_eq!(
        proc_b.claim("settle:batch-7"),
        Claim::Committed("settlement-ref-9931".into()),
        "the commit written by A is visible to B — one shared durable store"
    );

    // ---- Scenario 2: a cleanly-FAILED row is re-claimable (safe to re-attempt) ----
    assert_eq!(proc_a.claim("mr:feature-x"), Claim::Fresh);
    proc_a.fail("mr:feature-x", "downstream 500, no effect landed");
    assert_eq!(
        proc_b.claim("mr:feature-x"),
        Claim::Fresh,
        "a FAILED row (no effect) is re-claimable by any process"
    );

    // ---- Scenario 3: N threads across TWO processes race the SAME key → exactly one Fresh ----
    let store2 = InMemorySqlStore::new();
    let pa = Arc::new(process(&store2));
    let pb = Arc::new(process(&store2));
    const THREADS: usize = 64;
    let barrier = Arc::new(Barrier::new(THREADS));
    let fresh = Arc::new(AtomicUsize::new(0));
    let indoubt = Arc::new(AtomicUsize::new(0));

    let handles: Vec<_> = (0..THREADS)
        .map(|i| {
            // Half the threads dispatch through process A, half through process B.
            let ledger: Arc<SqlLedger<InMemorySqlStore>> =
                if i % 2 == 0 { pa.clone() } else { pb.clone() };
            let barrier = barrier.clone();
            let fresh = fresh.clone();
            let indoubt = indoubt.clone();
            std::thread::spawn(move || {
                barrier.wait(); // maximize the real contention window
                match ledger.claim("initiate_payment:txn-42") {
                    Claim::Fresh => fresh.fetch_add(1, Ordering::SeqCst),
                    _ => indoubt.fetch_add(1, Ordering::SeqCst),
                };
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }

    assert_eq!(
        fresh.load(Ordering::SeqCst),
        1,
        "the unique-key upsert must admit EXACTLY ONE claimant across all processes/threads"
    );
    assert_eq!(
        indoubt.load(Ordering::SeqCst),
        THREADS - 1,
        "every other claimant is deduped to in-doubt, never a second execution"
    );

    // The durable store holds exactly one row for that key.
    assert_eq!(store2.len(), 1, "one key ⇒ one durable ledger row");
}
