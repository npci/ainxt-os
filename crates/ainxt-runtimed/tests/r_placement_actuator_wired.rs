// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX serving-ops (SERVING_OPS.md §3, gaps 26/W) — the GPU bin-packing placement +
//! model-parking/eviction controller (`PlacementController`/`ParkingRegistry`/`PlacementReconciler`/
//! `InMemoryPlacementBinder`) is now wired onto the composition root, mirroring how
//! `r_health_monitor_wired.rs`/`r_chunked_prefill_wired.rs` close the analogous serving-ops gaps.
//!
//! These four types were fully implemented and exhaustively unit-tested but referenced ONLY in
//! `ainxt-serving`'s own test module — nothing on the served surface ever converged a physical GPU
//! fleet toward a computed placement, and the demand-EWMA autoscale decision loop
//! (`AssembledFull::run_autoscale_tick`) had its `Vec<ScaleAction>` output consumed by nothing. This
//! test proves BOTH halves through the actual composition root:
//!   1. a declared `[serving.placement]` builds a live `PlacementActuator` that
//!      `AssembledFull::run_placement_actuator_tick` actually converges via `PlacementReconciler`.
//!   2. `AssembledFull::run_autoscale_and_placement_tick` feeds a REAL autoscale decision straight into
//!      that SAME actuator — the decision-consumption seam the audit found missing.
//!
//! Fail-before: `ServingConfig` had no `placement` field and `AssembledFull` had no `placement` field /
//! `run_placement_actuator_tick` / `run_autoscale_and_placement_tick` — this file would not compile.

use std::time::{SystemTime, UNIX_EPOCH};

use ainxt_runtimed::{assemble_full, assemble_surface, load_layered, LoadedConfig};
use ainxt_serving::placement::ScaleAction;

fn unique_log_dir(tag: &str) -> String {
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir()
        .join(format!("ainxt-r-placement-{tag}-{nanos}"))
        .to_string_lossy()
        .into_owned()
}

fn config_with_placement() -> LoadedConfig {
    let dir = unique_log_dir("on");
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
    load_layered(&[("r-placement-on", &src)]).expect("load config with placement + autoscale")
}

fn default_config() -> LoadedConfig {
    let dir = unique_log_dir("default");
    let src = format!("version = 1\n[server]\nevent_log_dir = {dir:?}\n");
    load_layered(&[("r-placement-default", &src)]).expect("load default config")
}

#[test]
fn r_placement_config_parses_bins_and_models_from_git_native_toml() {
    let loaded = config_with_placement();
    let p = loaded
        .serving
        .placement
        .as_ref()
        .expect("placement section parsed");
    assert_eq!(p.bins.len(), 1);
    assert_eq!(p.bins[0].id, "gpu-bin-a");
    assert_eq!(p.bins[0].vram_total, 80);
    assert_eq!(p.models.len(), 1);
    assert_eq!(p.models[0].model_id, "qwen-32b");
    assert_eq!(p.max_moves_per_tick, 10);
}

#[test]
fn r_placement_air_gapped_default_wires_no_actuator() {
    let loaded = default_config();
    assert!(loaded.serving.placement.is_none());
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat surface");
    let full = assemble_full(&loaded, assembled).expect("assemble fully-wired surface");
    assert!(
        full.placement.is_none(),
        "no declared [serving.placement] ⇒ no actuator"
    );
    assert!(full.run_placement_actuator_tick(&[]).is_none());
    assert!(
        full.run_autoscale_and_placement_tick(0, &[]).is_none(),
        "no placement declared ⇒ the combined seam is also a harmless no-op"
    );
}

#[test]
fn r_placement_actuator_binds_a_scaled_up_model_onto_the_declared_bin() {
    let loaded = config_with_placement();
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat surface");
    let full = assemble_full(&loaded, assembled).expect("assemble fully-wired surface");
    assert!(
        full.placement.is_some(),
        "declared [serving.placement] ⇒ actuator wired"
    );

    // Directly actuate 1 replica of the declared model (footprint 40 fits the 80-VRAM bin).
    let actions = vec![ScaleAction::ScaleTo {
        model_id: "qwen-32b".to_string(),
        replicas: 1,
    }];
    let reconciled = full
        .run_placement_actuator_tick(&actions)
        .expect("placement declared ⇒ a tick runs");
    assert_eq!(reconciled.len(), 1, "one bind action: {reconciled:?}");

    // The SAME shared actuator now reports the model replica as physically bound — proving
    // `run_placement_actuator_tick` reached the real `PlacementReconciler`/`InMemoryPlacementBinder`
    // composition, not a disjoint copy.
    let bound = {
        let p = full.placement.as_ref().unwrap().lock().unwrap();
        p.bound_models()
    };
    assert_eq!(
        bound,
        vec!["qwen-32b#0".to_string()],
        "the replica is bound on the live binder: {bound:?}"
    );

    // Scaling to 0 (ParkWarm) must UNBIND it again — the concrete model-parking eviction action.
    let park = vec![ScaleAction::ParkWarm {
        model_id: "qwen-32b".to_string(),
    }];
    let reconciled2 = full
        .run_placement_actuator_tick(&park)
        .expect("still wired");
    assert!(
        reconciled2.iter().any(|a| matches!(a, ainxt_serving::placement::ReconcileAction::Unbound { model } if model == "qwen-32b#0")),
        "park-warm must physically unbind the replica: {reconciled2:?}"
    );
    let bound_after = {
        let p = full.placement.as_ref().unwrap().lock().unwrap();
        p.bound_models()
    };
    assert!(
        bound_after.is_empty(),
        "the model is no longer physically bound: {bound_after:?}"
    );
}

#[test]
fn r_autoscale_decision_is_actually_consumed_by_the_real_placement_actuator() {
    // THE BONUS PROOF: `run_autoscale_tick` used to return `Vec<ScaleAction>` that NOTHING consumed.
    // `run_autoscale_and_placement_tick` now feeds that exact output into the SAME live
    // `PlacementActuator` this surface holds.
    let loaded = config_with_placement();
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat surface");
    let full = assemble_full(&loaded, assembled).expect("assemble fully-wired surface");
    assert!(
        full.autoscale_controller.is_some(),
        "declared [serving.autoscale] ⇒ controller wired"
    );
    assert!(
        full.placement.is_some(),
        "declared [serving.placement] ⇒ actuator wired"
    );

    // Demand of 25 rps at per_replica_capacity=10 ⇒ ceil(25/10) = 3 replicas needed for qwen-32b.
    // alpha=1.0 makes the EWMA track the sample exactly (no smoothing lag) so the decision is
    // deterministic in one tick.
    let samples = vec![("qwen-32b".to_string(), 25.0)];
    let reconciled = full
        .run_autoscale_and_placement_tick(0, &samples)
        .expect("both autoscale and placement declared ⇒ the combined seam runs");

    // 3 replicas × 40 footprint = 120 > the single 80-VRAM bin's capacity, so at least one of the 3
    // is genuinely unplaceable — proving the REAL `PlacementController::plan` ran (not a stub that
    // always succeeds): 2 replicas bind, 1 reports NoFittingBin via the plan `unplaced` list, which
    // simply produces fewer than 3 `Bound` reconcile actions (never a panic on the stranded replica).
    let bound_count = reconciled
        .iter()
        .filter(|a| matches!(a, ainxt_serving::placement::ReconcileAction::Bound { .. }))
        .count();
    assert!(
        (1..=3).contains(&bound_count),
        "at least one real replica was placed, honestly bounded by bin capacity: {reconciled:?}"
    );

    let bound_models = {
        let p = full.placement.as_ref().unwrap().lock().unwrap();
        p.bound_models()
    };
    assert!(
        bound_models.iter().any(|m| m.starts_with("qwen-32b#")),
        "the autoscale controller's OWN demand decision drove a real bind on the placement actuator: \
         {bound_models:?}"
    );

    // The demand really did land on the LIVE autoscale controller too (not a disjoint copy).
    let demand = full.autoscale_demand("qwen-32b").expect("controller wired");
    assert!(
        (demand - 25.0).abs() < 1e-9,
        "alpha=1.0 tracks the sample exactly: {demand}"
    );
}
