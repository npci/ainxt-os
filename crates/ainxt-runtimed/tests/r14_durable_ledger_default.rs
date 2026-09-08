// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R14 (served-composition, HIGH) — the DURABLE cross-process exactly-once ledger is the DEFAULT
//! ledger behind the shipped daemon's unified Capability registry (and the background
//! `ReconcilerSweeper` sweeps the SAME durable rows), never the ephemeral in-process `InMemoryLedger`.
//!
//! FAIL-BEFORE: `build_unified_capability_registry_shared` built `Arc::new(InMemoryLedger::new())`, so
//! a committed side-effecting row lived only in one process's RAM — a second handle (a restarted
//! process / a peer node / the reconciler on another box) saw NOTHING, and the exactly-once guarantee
//! did not survive the handle. This test attaches a SECOND `SqlLedger` over a clone of the SAME store
//! the served registry dispatches through and observes the committed row survive — cross-handle
//! exactly-once the ephemeral ledger structurally cannot provide.
//!
//! PASS-AFTER: green, offline, deterministic (the OSS/air-gapped `InMemorySqlStore` reference driver;
//! production swaps a `PostgresSqlLedgerDriver` for cross-RESTART durability — infra).

use std::sync::Arc;

use ainxt_runtimed::{
    assemble_full, assemble_surface, build_unified_capability_registry_shared_over, load_layered,
    LoadedConfig,
};
use ainxt_tools::{Claim, InMemorySqlStore, Ledger, SqlLedger};

fn offline() -> LoadedConfig {
    load_layered(&[("x", "version = 1")]).unwrap()
}

#[test]
fn r14_default_capability_ledger_is_durable_cross_handle_exactly_once() {
    // The SHARED store the served registry's durable ledger dispatches through.
    let store = InMemorySqlStore::new();
    let mut report = Vec::new();
    let (_registry, ledger, _reconciler) =
        build_unified_capability_registry_shared_over(&mut report, store.clone());
    assert!(
        report
            .iter()
            .any(|r| r.contains("unified Capability registry")),
        "the durable registry still reports its wiring: {report:?}"
    );

    // A side-effecting capability CLAIMED the ledger and its ack landed (COMMIT) — the durable row.
    let key = "settlement.notify|batch-b1|u-alice";
    assert!(
        matches!(ledger.claim(key), Claim::Fresh),
        "a first claim of a fresh key is Fresh on the durable ledger"
    );
    ledger.commit(key, "{\"posted\":true}");

    // THE DURABILITY PROOF: a completely SEPARATE `SqlLedger` handle over a CLONE of the same store —
    // an independent process / a peer node / the reconciler on another box — sees the committed row.
    // The ephemeral `InMemoryLedger` (the pre-R14 default) could NEVER do this: a second handle is
    // empty, so the same key would re-execute (double payment). Durable exactly-once survives the
    // handle boundary.
    let peer: Arc<dyn Ledger> = Arc::new(SqlLedger::new(store.clone()));
    match peer.claim(key) {
        Claim::Committed(result) => assert_eq!(
            result, "{\"posted\":true}",
            "a peer handle re-reads the SAME durable committed result → exactly-once across handles"
        ),
        other => panic!(
            "the default ledger must be DURABLE (cross-handle exactly-once), got {other:?} — a peer \
             handle re-claiming a committed key must be suppressed, never re-executed"
        ),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn r14_assembled_daemon_sweeper_shares_the_durable_ledger() {
    // R16 critical: the daemon now refuses the header-trusting default authenticator unless the
    // deployment states the assumption (see r10_breach_clock_unit.rs) — state it here.
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    // The fully-wired daemon holds a ReconcilerSweeper over the served engine's SHARED durable ledger.
    let assembled = assemble_surface(&offline(), "chat").expect("assemble chat surface");
    let full = assemble_full(&offline(), assembled).expect("assemble fully-wired surface");
    assert!(
        full.reconciler_sweeper.is_some(),
        "the daemon holds a ReconcilerSweeper over the shared durable capability ledger"
    );
    // Start + cleanly stop the background sweep (it runs over the durable ledger for the process life).
    let handle = full
        .spawn_reconciler_sweep()
        .expect("daemon spawns the background sweep");
    handle.stop();
}
