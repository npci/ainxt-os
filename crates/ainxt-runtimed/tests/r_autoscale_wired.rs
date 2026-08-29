// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX serving-ops (SERVING_OPS.md §3, gaps 26/W, round-15 LOW) — the demand-EWMA autoscale
//! decision loop is now wired onto the composition root, mirroring `r_health_monitor_wired.rs`'s fix
//! for the analogous §4 gap (and the already-closed ADR-021 §8.3 attestation-refresh gap before it).
//!
//! `ainxt-serving::placement` had `AutoscaleController::tick` (fold per-model demand samples into an
//! EWMA, decide scale-to-N-replicas vs. park-warm-when-idle) and `AutoscaleCadence` (the due-or-not
//! poll gate) fully implemented and exhaustively unit-tested, but ZERO callers outside the crate's
//! own tests — confirmed via grep across the whole workspace. Nothing on the served composition root
//! ever built or drove either, so the demand-driven scale/park decision loop §3 describes could never
//! actually run in production — exactly the gap `AutoscaleCadence`'s own doc names ("had no cadence
//! concept... wired into ANY daemon loop"). This test proves the fix through the actual composition
//! root: a declared `[serving.autoscale]` section builds a live `AutoscaleController`+`AutoscaleCadence`
//! on `AssembledFull`, and driving `run_autoscale_tick` for real produces the documented scale-to /
//! park-warm decisions.
//!
//! Fail-before: `ServingConfig` had no `autoscale` field, and `AssembledFull` had no
//! `autoscale_controller`/`autoscale_cadence`/`run_autoscale_tick` — this file would not compile
//! (`deny_unknown_fields` would also reject the `[serving.autoscale]` TOML).

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
        .join(format!("ainxt-r-autoscale-{tag}-{nanos}"))
        .to_string_lossy()
        .into_owned()
}

fn config_with_autoscale() -> LoadedConfig {
    let dir = unique_log_dir("pool");
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
    load_layered(&[("r-autoscale-pool", &src)]).expect("load config with autoscale tuning")
}

fn default_config() -> LoadedConfig {
    let dir = unique_log_dir("default");
    let src = format!("version = 1\n[server]\nevent_log_dir = {dir:?}\n");
    load_layered(&[("r-autoscale-default", &src)]).expect("load default config")
}

#[test]
fn r_autoscale_config_parses_tuning_from_git_native_toml() {
    let loaded = config_with_autoscale();
    let cfg = loaded
        .serving
        .autoscale
        .as_ref()
        .expect("[serving.autoscale] must parse");
    assert_eq!(cfg.alpha, 1.0);
    assert_eq!(cfg.per_replica_capacity, 10.0);
    assert_eq!(cfg.min_replicas, 0);
    assert_eq!(cfg.sweep_interval, 1);
}

#[test]
fn r_autoscale_default_config_declares_no_tuning() {
    let loaded = default_config();
    assert!(
        loaded.serving.autoscale.is_none(),
        "no [serving.autoscale] declared ⇒ None (byte-identical to before this fix)"
    );
}

#[test]
fn r_autoscale_air_gapped_default_wires_no_controller() {
    let loaded = default_config();
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat surface");
    let full = assemble_full(&loaded, assembled).expect("assemble fully-wired surface");

    assert!(
        full.autoscale_controller.is_none(),
        "no declared tuning ⇒ no controller"
    );
    assert!(full.autoscale_cadence.is_none());
    assert_eq!(
        full.autoscale_sweeps_run(),
        None,
        "no controller ⇒ no sweep count either"
    );
    assert_eq!(full.autoscale_demand("any-model"), None);

    // Driving a tick on a surface with no controller is a harmless no-op (never panics).
    assert!(full
        .run_autoscale_tick(0, &[("ghost-model".to_string(), 999.0)])
        .is_none());
}

#[test]
fn r_autoscale_wired_scales_up_on_demand_then_parks_warm_when_idle() {
    let loaded = config_with_autoscale();
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat surface");
    let full = assemble_full(&loaded, assembled).expect("assemble fully-wired surface");

    // The controller + cadence are WIRED onto the shipped surface (was missing entirely).
    assert!(
        full.autoscale_controller.is_some(),
        "declared tuning exposes an autoscale controller"
    );
    assert!(full.autoscale_cadence.is_some());
    assert_eq!(full.autoscale_sweeps_run(), Some(0), "no sweep has run yet");
    assert_eq!(
        full.autoscale_demand("qwen-32b"),
        Some(0.0),
        "never observed ⇒ zero demand"
    );

    // Sweep 1 (t=0, due immediately): a burst of demand (alpha=1.0 ⇒ EWMA snaps straight to the
    // sample) at 25 req/s against per_replica_capacity=10 ⇒ ceil(25/10) = 3 replicas needed.
    let outcomes = full
        .run_autoscale_tick(0, &[("qwen-32b".to_string(), 25.0)])
        .expect("sweep must be due at t=0");
    assert_eq!(
        outcomes,
        vec![ScaleAction::ScaleTo {
            model_id: "qwen-32b".to_string(),
            replicas: 3
        }],
        "the live composition-root controller actually folded the sample and decided to scale up"
    );
    assert_eq!(
        full.autoscale_demand("qwen-32b"),
        Some(25.0),
        "the EWMA reflects the real sample"
    );
    assert_eq!(full.autoscale_sweeps_run(), Some(1));

    // Sweep 2 (t=1, due per sweep_interval=1): demand collapses to 0 ⇒ below the idle threshold, and
    // with min_replicas=0 there is no P0 floor to keep a replica warm for — the controller parks the
    // family warm rather than cold-evicting it (SERVING_OPS.md §3, gap W).
    let outcomes = full
        .run_autoscale_tick(1, &[("qwen-32b".to_string(), 0.0)])
        .expect("sweep must be due at t=1 (sweep_interval=1)");
    assert_eq!(
        outcomes,
        vec![ScaleAction::ParkWarm {
            model_id: "qwen-32b".to_string()
        }],
        "demand collapsing to idle with no P0 floor parks the family warm, not a ScaleTo"
    );
    assert_eq!(
        full.autoscale_sweeps_run(),
        Some(2),
        "both sweeps actually ran"
    );

    // A tick before the next due point (sweep_interval=1, next due at t=2) is a genuine no-op.
    assert!(
        full.run_autoscale_tick(1, &[("qwen-32b".to_string(), 999.0)])
            .is_none(),
        "re-driving the SAME tick time again must not double-count as a second sweep"
    );
    assert_eq!(
        full.autoscale_sweeps_run(),
        Some(2),
        "the no-op tick did not advance the sweep count"
    );
}
