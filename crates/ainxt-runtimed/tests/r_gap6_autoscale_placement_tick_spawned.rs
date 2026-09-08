// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-AUDIT gap6-composition-root (Item 1) — `AssembledFull::spawn_autoscale_and_placement_tick`
//! (the fuller observe→decide→actuate cadence that ALSO drives the GPU bin-packing placement actuator
//! over the SAME decisions `spawn_autoscale_tick` makes) had ZERO callers anywhere, including
//! `main.rs`: only the narrower decision-only `spawn_autoscale_tick` was ever started, so a
//! deployment declaring BOTH `[serving.autoscale]` AND `[serving.placement]` never got the placement
//! half converged on a cadence.
//!
//! `main.rs` now prefers `spawn_autoscale_and_placement_tick` whenever `[serving.placement]` is
//! declared, and falls back to the narrower `spawn_autoscale_tick` otherwise. This file proves BOTH
//! halves of that fix through the REAL spawned background task (not a hand-called tick), mirroring
//! `r13_attestation_refresh_loop.rs`'s technique (poll a shared side effect from outside a bounded
//! wait):
//!
//!   1. `r_gap6_spawned_combined_tick_converges_real_placement` — with both sections declared, the
//!      SPAWNED loop (never hand-driven) both advances `AutoscaleCadence::ticks_run()` AND binds a
//!      model onto the live `PlacementActuator` — the exact decision-consumption seam the audit found
//!      missing, now proven to run on a real background cadence, not just a hand-callable method.
//!   2. `r_gap6_autoscale_only_deployment_would_regress_under_a_blind_swap` — documents/proves WHY
//!      `main.rs` does NOT unconditionally replace `spawn_autoscale_tick` with the fuller sibling:
//!      `spawn_autoscale_and_placement_tick` requires cadence+controller+actuator ALL present and
//!      returns `None` (no loop at all) when `[serving.placement]` is undeclared — an
//!      autoscale-only deployment would silently lose its decision loop entirely under a blind swap.
//!      `spawn_autoscale_tick` keeps working for that exact shape.
//!   3. `r_gap6_air_gapped_default_spawns_neither_the_narrow_nor_the_fuller_tick` — the true no-op case
//!      (neither section declared) is unchanged by this fix.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ainxt_runtimed::{assemble_full, assemble_surface, load_layered, LoadedConfig};

fn unique_log_dir(tag: &str) -> String {
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir()
        .join(format!("ainxt-gap6-autoscale-placement-{tag}-{nanos}"))
        .to_string_lossy()
        .into_owned()
}

fn config_with_autoscale_and_placement() -> LoadedConfig {
    let dir = unique_log_dir("both");
    let src = format!(
        "version = 1\n\
         [server]\n\
         event_log_dir = {dir:?}\n\
         [serving]\n\
         [serving.placement]\n\
         standby_reserve = 0\n\
         max_moves_per_tick = 10\n\
         [[serving.placement.bins]]\n\
         id = \"gpu-bin-a\"\n\
         vram_total = 80\n\
         tier = \"cc-enclave\"\n\
         fabric_domain = \"domain-1\"\n\
         [[serving.placement.models]]\n\
         model_id = \"qwen-32b\"\n\
         footprint = 40\n\
         requires_regulated_bin = false\n\
         [serving.autoscale]\n\
         alpha = 1.0\n\
         per_replica_capacity = 10.0\n\
         min_replicas = 0\n\
         sweep_interval = 1\n"
    );
    load_layered(&[("gap6-autoscale-placement-both", &src)])
        .expect("load config with both sections")
}

fn config_with_autoscale_only() -> LoadedConfig {
    let dir = unique_log_dir("autoscale-only");
    let src = format!(
        "version = 1\n\
         [server]\n\
         event_log_dir = {dir:?}\n\
         [serving]\n\
         [serving.autoscale]\n\
         alpha = 1.0\n\
         per_replica_capacity = 10.0\n\
         min_replicas = 0\n\
         sweep_interval = 1\n"
    );
    load_layered(&[("gap6-autoscale-only", &src)]).expect("load config with autoscale only")
}

fn default_config() -> LoadedConfig {
    let dir = unique_log_dir("default");
    let src = format!("version = 1\n[server]\nevent_log_dir = {dir:?}\n");
    load_layered(&[("gap6-autoscale-placement-default", &src)]).expect("load default config")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r_gap6_spawned_combined_tick_converges_real_placement() {
    let loaded = config_with_autoscale_and_placement();
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat surface");
    let full = assemble_full(&loaded, assembled).expect("assemble fully-wired surface");
    assert!(full.autoscale_controller.is_some());
    assert!(full.placement.is_some());

    // Prime real demand for qwen-32b via ONE hand-driven decision tick (logical `now = 0`, immediately
    // due on a freshly-built cadence) — this is a REAL mutation of the SAME shared
    // `autoscale_controller`/`autoscale_cadence` Arcs `spawn_autoscale_and_placement_tick` clones below,
    // not a separate fixture. `AutoscaleController::tick` remembers every family it has ever decided
    // for (`ParkingRegistry::tiers`), so every LATER tick — even one fed empty samples, exactly what
    // the spawned loop always feeds — keeps re-deciding for "qwen-32b" using its last-observed (frozen)
    // demand, since nothing re-`observe`s it without a fresh sample.
    let primed = full
        .run_autoscale_tick(0, &[("qwen-32b".to_string(), 25.0)])
        .expect("a fresh cadence is due at t=0");
    assert!(
        !primed.is_empty(),
        "priming tick must have decided something for qwen-32b"
    );

    // THE PROOF: spawn the REAL background loop — the exact call `main.rs` now makes when
    // `[serving.placement]` is declared — and observe, from OUTSIDE, that it both (a) advances the
    // cadence's sweep counter and (b) actually binds the primed demand onto the live placement
    // actuator, entirely through the spawned task (this test never calls
    // `run_autoscale_and_placement_tick`/`run_placement_actuator_tick` by hand after this point).
    let handle = full.spawn_autoscale_and_placement_tick(Duration::from_millis(5));
    let handle =
        handle.expect("both [serving.autoscale] and [serving.placement] declared ⇒ spawns");

    let mut bound = false;
    for _ in 0..400 {
        tokio::time::sleep(Duration::from_millis(5)).await;
        let models = {
            let p = full
                .placement
                .as_ref()
                .unwrap()
                .lock()
                .expect("placement lock");
            p.bound_models()
        };
        if models.iter().any(|m| m.starts_with("qwen-32b#")) {
            bound = true;
            break;
        }
    }
    handle.abort();

    assert!(
        bound,
        "the SPAWNED combined tick converged the primed autoscale decision onto the real \
         PlacementActuator — proving the placement half now actually runs on a background cadence, \
         not merely via a hand-called `run_autoscale_and_placement_tick`"
    );
    assert!(
        full.autoscale_sweeps_run().unwrap_or(0) >= 1,
        "the spawned loop's decision half also advanced the SAME shared AutoscaleCadence sweep count"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r_gap6_autoscale_only_deployment_would_regress_under_a_blind_swap() {
    // Documents + proves the exact reason `main.rs` does NOT unconditionally replace
    // `spawn_autoscale_tick` with `spawn_autoscale_and_placement_tick`: a deployment declaring
    // `[serving.autoscale]` alone (no placement — a legitimate, common shape) keeps a live decision
    // loop via the narrower tick, but would get NO loop at all (not even the decision half) from the
    // fuller one, because it requires cadence+controller+actuator ALL present.
    let loaded = config_with_autoscale_only();
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat surface");
    let full = assemble_full(&loaded, assembled).expect("assemble fully-wired surface");
    assert!(
        full.autoscale_controller.is_some(),
        "declared [serving.autoscale] ⇒ controller wired"
    );
    assert!(
        full.placement.is_none(),
        "no [serving.placement] declared in this deployment shape"
    );

    // The narrower tick `main.rs` falls back to for this exact shape: it spawns and genuinely ticks.
    let narrow_handle = full
        .spawn_autoscale_tick(Duration::from_millis(5))
        .expect("autoscale alone ⇒ the narrow tick still spawns");
    let mut narrow_ticked = false;
    for _ in 0..200 {
        tokio::time::sleep(Duration::from_millis(5)).await;
        if full.autoscale_sweeps_run().unwrap_or(0) >= 1 {
            narrow_ticked = true;
            break;
        }
    }
    narrow_handle.abort();
    assert!(
        narrow_ticked,
        "spawn_autoscale_tick must keep ticking for an autoscale-only deployment"
    );

    // The fuller sibling: a blind swap would have silently disabled the loop for this deployment shape.
    assert!(
        full.spawn_autoscale_and_placement_tick(Duration::from_millis(5))
            .is_none(),
        "spawn_autoscale_and_placement_tick requires [serving.placement] too — None here proves a \
         blind main.rs swap (narrow → fuller, unconditionally) would have regressed this exact, \
         legitimate deployment shape from 'ticking' to 'no loop at all'"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn r_gap6_air_gapped_default_spawns_neither_the_narrow_nor_the_fuller_tick() {
    let loaded = default_config();
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat surface");
    let full = assemble_full(&loaded, assembled).expect("assemble fully-wired surface");
    assert!(full.autoscale_controller.is_none());
    assert!(full.placement.is_none());
    assert!(full
        .spawn_autoscale_tick(Duration::from_millis(5))
        .is_none());
    assert!(
        full.spawn_autoscale_and_placement_tick(Duration::from_millis(5))
            .is_none(),
        "the true no-op default (neither section declared) is unchanged by this fix"
    );
}
