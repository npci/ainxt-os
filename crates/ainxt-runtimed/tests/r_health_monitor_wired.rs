// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX serving-ops (SERVING_OPS.md §4, gap 37) — the shard-group health monitor + drain-the-group
//! recovery cadence is now wired onto the composition root, mirroring how `r13_attestation_refresh_
//! wired.rs` / `r_attestation_manifest_config.rs` close the analogous ADR-021 §8.3 attestation gap.
//!
//! `ainxt-serving::health` had `ShardHealthMonitor` (the two-signal health state machine + standby
//! model), `HealthCadence` (the due-or-not poll cadence), and `monitor_tick`/`drain_and_replace` (the
//! poll→act + drain-the-group recovery sequence) fully implemented and exhaustively unit-tested, but
//! ZERO callers outside the crate's own tests: nothing on the served surface ever registered a shard
//! group into it, so a hung or silently-corrupting GPU group could never actually be pulled from the
//! routable pool in production — exactly the gap the module's own doc names ("nothing polled them on a
//! cadence"). This test proves the fix through the actual composition root: a declared
//! `[[serving.nodes]] golden_hash` builds a live `ShardHealthMonitor`+`HealthCadence` on
//! `AssembledFull`, and driving `run_health_sweep_tick` for real actually drains a degraded group from
//! the live `FleetRouter`.
//!
//! Fail-before: `ServingNodeConfig` had no `golden_hash` field, `ServingConfig` had no `health` field,
//! and `AssembledFull` had no `health_monitor`/`health_cadence`/`run_health_sweep_tick` — this file
//! would not compile (`deny_unknown_fields` would also reject the `[serving.health]` TOML).

use std::time::{SystemTime, UNIX_EPOCH};

use ainxt_runtimed::{assemble_full, assemble_surface, load_layered, LoadedConfig};
use ainxt_serving::health::{FleetRouter, HealthObservation, InMemoryFleetRouter, ShardGroupId};

fn unique_log_dir(tag: &str) -> String {
    // R16 critical: the daemon refuses the header-trusting default authenticator unless the
    // deployment states the assumption — state it here (same pattern as the attestation tests).
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir()
        .join(format!("ainxt-r-health-{tag}-{nanos}"))
        .to_string_lossy()
        .into_owned()
}

fn config_with_monitored_node() -> LoadedConfig {
    let dir = unique_log_dir("pool");
    let src = format!(
        "version = 1\n\
         [server]\n\
         event_log_dir = {dir:?}\n\
         [serving]\n\
         [[serving.nodes]]\n\
         node_id = \"gpu-a\"\n\
         routable = true\n\
         golden_hash = 42\n\
         [serving.health]\n\
         sweep_interval = 1\n\
         collective_timeout = 10\n\
         consecutive_miss_threshold = 3\n"
    );
    load_layered(&[("r-health-pool", &src)]).expect("load config with a monitored node")
}

fn config_with_unmonitored_node() -> LoadedConfig {
    let dir = unique_log_dir("unmonitored");
    let src = format!(
        "version = 1\n\
         [server]\n\
         event_log_dir = {dir:?}\n\
         [serving]\n\
         [[serving.nodes]]\n\
         node_id = \"gpu-a\"\n\
         routable = true\n"
    );
    load_layered(&[("r-health-unmonitored", &src)]).expect("load config with an unmonitored node")
}

fn default_config() -> LoadedConfig {
    let dir = unique_log_dir("default");
    let src = format!("version = 1\n[server]\nevent_log_dir = {dir:?}\n");
    load_layered(&[("r-health-default", &src)]).expect("load default config")
}

#[test]
fn r_health_config_parses_golden_hash_and_tuning_from_git_native_toml() {
    let loaded = config_with_monitored_node();
    assert_eq!(loaded.serving.nodes.len(), 1);
    assert_eq!(loaded.serving.nodes[0].golden_hash, Some(42));
    assert_eq!(loaded.serving.health.sweep_interval, 1);
    assert_eq!(loaded.serving.health.collective_timeout, 10);
    assert_eq!(loaded.serving.health.consecutive_miss_threshold, 3);
}

#[test]
fn r_health_default_config_has_no_monitored_node_but_still_has_tuning_defaults() {
    let loaded = default_config();
    assert!(loaded.serving.nodes.is_empty());
    // `[serving.health]` is always present with conservative defaults, even though nothing is
    // monitored — mirrors `[serving.wfq]`'s absent-is-a-default shape, NOT `attestation_manifest`'s
    // `Option` shape (this section's gate is per-node `golden_hash`, not its own presence).
    assert!(loaded.serving.health.collective_timeout > 0);
    assert!(loaded.serving.health.consecutive_miss_threshold >= 1);
}

#[test]
fn r_health_air_gapped_default_wires_no_monitor() {
    let loaded = default_config();
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat surface");
    let full = assemble_full(&loaded, assembled).expect("assemble fully-wired surface");

    assert!(
        full.health_monitor.is_none(),
        "no declared golden_hash ⇒ no monitor"
    );
    assert!(full.health_cadence.is_none());
    assert_eq!(
        full.health_sweeps_run(),
        None,
        "no monitor ⇒ no sweep count either"
    );
    assert_eq!(full.health_routable_groups(), None);

    // Driving a tick on a surface with no monitor is a harmless no-op (never panics).
    let mut router = InMemoryFleetRouter::new();
    let obs = vec![HealthObservation::new(ShardGroupId::new("ghost")).collective(9999)];
    assert!(full.run_health_sweep_tick(0, &obs, &mut router).is_none());
}

#[test]
fn r_health_a_declared_node_without_golden_hash_still_wires_no_monitor() {
    // A node declared purely for the §8.2 attestation fence (no golden_hash) must NOT accidentally
    // become a monitored shard group — the two mechanisms are opt-in independently.
    let loaded = config_with_unmonitored_node();
    assert_eq!(loaded.serving.nodes.len(), 1);
    assert_eq!(loaded.serving.nodes[0].golden_hash, None);

    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat surface");
    let full = assemble_full(&loaded, assembled).expect("assemble fully-wired surface");
    assert!(
        full.health_monitor.is_none(),
        "declared node has no golden_hash ⇒ still no monitor"
    );
    assert!(full.health_cadence.is_none());
}

#[test]
fn r_health_monitor_wired_drains_a_degraded_group_from_the_live_router() {
    let loaded = config_with_monitored_node();
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat surface");
    let full = assemble_full(&loaded, assembled).expect("assemble fully-wired surface");

    // The monitor + cadence are WIRED onto the shipped surface (was missing entirely).
    assert!(
        full.health_monitor.is_some(),
        "declared golden_hash exposes a health monitor"
    );
    assert!(full.health_cadence.is_some());
    assert_eq!(full.health_sweeps_run(), Some(0), "no sweep has run yet");
    assert_eq!(
        full.health_routable_groups(),
        Some(vec!["gpu-a".to_string()]),
        "the declared node is registered and routable at boot"
    );

    let group = ShardGroupId::new("gpu-a");
    let mut router = InMemoryFleetRouter::new().with_routed(vec![group.clone()]);
    assert!(
        router.is_routed(&group),
        "the live router starts with gpu-a routed"
    );

    // Drive 3 due sweeps (sweep_interval=1 ⇒ due at t=0,1,2), each reporting a collective duration
    // well over the configured `collective_timeout=10` — the interconnect-watchdog "hung collective"
    // signal. The first two misses must NOT drain (anti-flap); the third (consecutive_miss_threshold=3)
    // must drain the group AND physically remove it from the live `FleetRouter` in the same tick — the
    // exact drain-the-group recovery sequence the audit found unpolled.
    for t in 0..3u64 {
        let obs = vec![HealthObservation::new(group.clone()).collective(999)];
        let outcomes = full
            .run_health_sweep_tick(t, &obs, &mut router)
            .unwrap_or_else(|| panic!("sweep must be due at t={t} (sweep_interval=1)"));
        if t < 2 {
            assert!(
                outcomes.is_empty(),
                "miss #{} alone must not drain (anti-flap)",
                t + 1
            );
        } else {
            assert_eq!(
                outcomes.len(),
                1,
                "the 3rd consecutive miss drains exactly one group"
            );
            assert_eq!(
                outcomes[0].drained, group,
                "gpu-a is the group that trips the watchdog"
            );
            assert_eq!(
                outcomes[0].promoted, None,
                "no N+1 standby was declared to promote"
            );
        }
    }

    assert_eq!(
        full.health_sweeps_run(),
        Some(3),
        "all 3 sweeps actually ran"
    );
    assert_eq!(
        full.health_routable_groups(),
        Some(vec![]),
        "gpu-a was pulled from the monitor's routable pool"
    );
    assert!(
        !router.is_routed(&group),
        "gpu-a was ALSO physically removed from the live FleetRouter, not just the monitor's own \
         bookkeeping — this is the concrete 'drain-the-group' action a real load balancer would see"
    );
}
