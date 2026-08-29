// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-15 serving-ops (MEDIUM) — SERVING_OPS.md §4 (gap 37): the audit found
//! `ShardHealthMonitor::monitor_tick` (the poll→act loop body) had no cadence concept at all — every
//! call was treated as due, so nothing decided WHEN a health sweep should run independent of however
//! often a caller happened to invoke it. `HealthCadence` closes that with the same
//! is-due/next-due-cursor pattern `AttestationRefresher` uses for the analogous attestation gap.
//!
//! Fail-before: `ainxt_serving::health::HealthCadence` did not exist — this file would not compile.
//! Pass-after: a tick before the cadence's due point is a genuine no-op (the sweep does NOT run, and a
//! hung/corrupt group is NOT drained early); a tick at/after the due point runs the sweep and drains a
//! group that failed its signal, promoting its N+1 standby.

use ainxt_serving::health::{
    FleetRouter, HealthCadence, HealthCadenceConfig, HealthConfig, HealthObservation,
    InMemoryFleetRouter, ShardGroupId, ShardHealthMonitor,
};

fn gid(s: &str) -> ShardGroupId {
    ShardGroupId::new(s)
}

#[test]
fn r15_cadence_gates_the_sweep_by_due_time() {
    let mut monitor = ShardHealthMonitor::new(HealthConfig {
        collective_timeout: 100,
        consecutive_miss_threshold: 1, // one miss is enough, so the test is about CADENCE not flapping
    });
    let primary = gid("tp0");
    let standby = gid("tp0-standby");
    monitor.register_group(primary.clone(), 1);
    monitor.add_standby(standby.clone(), 1);

    let mut router = InMemoryFleetRouter::new().with_routed(vec![primary.clone()]);
    let mut cadence = HealthCadence::new(HealthCadenceConfig { interval: 10 });

    // A hung collective observation, but the sweep is called BEFORE the cadence's due point (t=0 IS
    // due for the very first sweep per the driver's contract, so use a SECOND early call instead).
    let obs = vec![HealthObservation::new(primary.clone()).collective(500)];

    // First tick at t=0 is due (fresh driver) and DOES drain the hung group.
    let first = cadence.tick(&mut monitor, 0, &obs, &mut router);
    assert!(first.is_some(), "the first tick is always due");
    let outcomes = first.unwrap();
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].drained, primary);
    assert_eq!(outcomes[0].promoted, Some(standby.clone()));
    assert!(
        !router.is_routed(&primary),
        "the hung group is physically pulled from the routable set"
    );
    assert!(
        router.is_routed(&standby),
        "the N+1 standby is physically promoted"
    );
    assert_eq!(cadence.sweeps_run(), 1);

    // A SECOND tick immediately after (t=1, well before the next due point at t=10) is a genuine
    // no-op — even feeding it another failing observation for a THIRD group does not drain it, because
    // the cadence itself gates whether the sweep body runs at all.
    let third = gid("tp1");
    monitor.register_group(third.clone(), 1);
    router.promote_route(&third);
    let obs2 = vec![HealthObservation::new(third.clone()).collective(500)];
    let second = cadence.tick(&mut monitor, 1, &obs2, &mut router);
    assert!(
        second.is_none(),
        "a tick before the next due point must be a no-op"
    );
    assert!(
        router.is_routed(&third),
        "the third group is UNTOUCHED — the not-yet-due tick never ran monitor_tick at all"
    );
    assert_eq!(
        cadence.sweeps_run(),
        1,
        "still only one sweep has actually run"
    );

    // At/after the due point (t=10), the sweep runs again and now DOES drain the third group.
    let due = cadence.tick(&mut monitor, 10, &obs2, &mut router);
    assert!(due.is_some());
    assert!(
        !router.is_routed(&third),
        "the due sweep drains the group the earlier no-op tick missed"
    );
    assert_eq!(cadence.sweeps_run(), 2);
}

#[test]
fn r15_cadence_config_zero_interval_never_busy_loops() {
    // A configured interval of 0 must degrade to "every tick", never a panic or an infinite-due state
    // that never advances (the same saturating-floor discipline the attestation refresher uses).
    let cfg = HealthCadenceConfig { interval: 0 };
    let mut cadence = HealthCadence::new(cfg);
    let mut monitor = ShardHealthMonitor::new(HealthConfig {
        collective_timeout: 100,
        consecutive_miss_threshold: 5,
    });
    monitor.register_group(gid("g"), 1);
    let mut router = InMemoryFleetRouter::new();
    assert!(cadence.tick(&mut monitor, 0, &[], &mut router).is_some());
    assert!(
        cadence.tick(&mut monitor, 1, &[], &mut router).is_some(),
        "interval=0 sweeps every tick"
    );
}
