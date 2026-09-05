// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-12 Serving-Ops gap-5 (MEDIUM) — the multi-GPU shard-health MONITORING LOOP: the §4 two-signal
//! health machine + drain-the-group recovery now run as a single per-tick poll→act loop, not just as
//! library primitives nothing invoked on a cadence.
//!
//! The audit found §4 had the pure state machine (`record_collective`/`record_canary`) and the
//! `drain_and_replace` recovery sequence, but no loop that *polled* them — so a hung or silently-corrupt
//! shard group was never actually pulled from the live pool in production. This closes the loop BODY
//! ([`ShardHealthMonitor::monitor_tick`]): the async timer + live GPU probe / interconnect counters are
//! the infra seams; the poll→detect→drain→promote orchestration is proven here against the offline
//! [`InMemoryFleetRouter`].
//!
//! Fail-before: `HealthObservation`/`monitor_tick` did not exist — this file would not compile.
//! Pass-after: one loop tick drains a hung group AND a silently-corrupt group, promotes N+1 standbys,
//! and mutates the live router — while a healthy group is untouched.

use ainxt_serving::health::{
    FleetRouter, HealthConfig, HealthObservation, HealthState, InMemoryFleetRouter, ShardGroupId,
    ShardHealthMonitor,
};

fn g(s: &str) -> ShardGroupId {
    ShardGroupId::new(s)
}

#[test]
fn r12_monitor_tick_drains_hung_and_corrupt_groups_and_promotes_standbys() {
    let mut mon = ShardHealthMonitor::new(HealthConfig {
        collective_timeout: 100,
        // One miss is enough to flag Degraded, so a single tick's observation can transition it.
        consecutive_miss_threshold: 1,
    });
    // Three live groups + two N+1 standbys.
    for grp in ["tp-hung", "tp-corrupt", "tp-ok"] {
        mon.register_group(g(grp), 0xC0DE);
    }
    mon.add_standby(g("standby-1"), 0xC0DE);
    mon.add_standby(g("standby-2"), 0xC0DE);

    let mut router =
        InMemoryFleetRouter::new().with_routed([g("tp-hung"), g("tp-corrupt"), g("tp-ok")]);
    assert_eq!(router.routed_count(), 3);

    // One monitoring tick: tp-hung's collective blew the deadline, tp-corrupt's canary hash mismatched
    // (silent corruption, liveness green), tp-ok is healthy on both signals.
    let obs = vec![
        HealthObservation::new(g("tp-hung"))
            .collective(999)
            .canary(0xC0DE),
        HealthObservation::new(g("tp-corrupt"))
            .collective(10)
            .canary(0xBAD),
        HealthObservation::new(g("tp-ok"))
            .collective(10)
            .canary(0xC0DE),
    ];
    let outcomes = mon.monitor_tick(&obs, &mut router);

    // Both faulty groups were drained AND a standby promoted for each (capacity restored).
    assert_eq!(
        outcomes.len(),
        2,
        "both faulty groups drained this tick: {outcomes:?}"
    );
    assert!(
        outcomes.iter().all(|o| o.promoted.is_some()),
        "each drain promotes an N+1 standby"
    );
    let drained: std::collections::BTreeSet<_> =
        outcomes.iter().map(|o| o.drained.clone()).collect();
    assert!(drained.contains(&g("tp-hung")) && drained.contains(&g("tp-corrupt")));

    // Health state machine reflects the transitions.
    assert_eq!(mon.state_of(&g("tp-hung")), Some(HealthState::Degraded));
    assert_eq!(
        mon.state_of(&g("tp-corrupt")),
        Some(HealthState::SuspectCorrupt)
    );
    assert!(
        mon.state_of(&g("tp-ok")).unwrap().is_routable(),
        "the healthy group is untouched"
    );

    // The LIVE router was mutated: faulty groups pulled, standbys routed, tp-ok retained.
    assert!(!router.is_routed(&g("tp-hung")) && !router.is_routed(&g("tp-corrupt")));
    assert!(router.is_routed(&g("tp-ok")));
    // Two standbys were routed in to replace the two drained groups.
    assert_eq!(
        router.routed_count(),
        3,
        "capacity restored to 3 routable groups"
    );
    assert_eq!(mon.standby_count(), 0, "both N+1 standbys were consumed");
}

#[test]
fn r12_monitor_tick_is_a_noop_when_all_groups_healthy() {
    let mut mon = ShardHealthMonitor::new(HealthConfig {
        collective_timeout: 100,
        consecutive_miss_threshold: 1,
    });
    mon.register_group(g("tp0"), 42);
    mon.add_standby(g("s0"), 42);
    let mut router = InMemoryFleetRouter::new().with_routed([g("tp0")]);
    let obs = vec![HealthObservation::new(g("tp0")).collective(50).canary(42)];
    let outcomes = mon.monitor_tick(&obs, &mut router);
    assert!(
        outcomes.is_empty(),
        "a healthy tick drains nothing and consumes no standby"
    );
    assert_eq!(mon.standby_count(), 1);
    assert_eq!(router.routed_count(), 1);
}

#[test]
fn r12_monitor_tick_drains_a_group_only_once_even_if_both_signals_fail() {
    // A group that hangs AND corrupts in the same tick must be drained exactly once (never double-spend
    // the standby pool on one failed group).
    let mut mon = ShardHealthMonitor::new(HealthConfig {
        collective_timeout: 100,
        consecutive_miss_threshold: 1,
    });
    mon.register_group(g("tp0"), 42);
    mon.add_standby(g("s0"), 42);
    mon.add_standby(g("s1"), 42);
    let mut router = InMemoryFleetRouter::new().with_routed([g("tp0")]);
    let obs = vec![HealthObservation::new(g("tp0"))
        .collective(999)
        .canary(0xBAD)];
    let outcomes = mon.monitor_tick(&obs, &mut router);
    assert_eq!(outcomes.len(), 1, "one failed group → one drain, not two");
    assert_eq!(mon.standby_count(), 1, "only one standby consumed");
}
