// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Cadence scheduling for the supervisory governance monitors (§5.4 store-sweep, §8.2 NTP-skew,
//! §8.1 India-residency).
//!
//! [`crate::ops::NtpSkewMonitor`], [`crate::ops::ResidencyVerifier`], and the compliance store-sweep
//! ([`ainxt_compliance::SinkGuard::sweep`](../../ainxt_compliance) — a different crate) are all pure,
//! callable *detectors*: given a measurement they decide whether it is a §2 incident. But a detector
//! that is never *run on a cadence* alarms nothing — the gap was that these entrypoints existed with no
//! schedule. [`CadenceScheduler`] is that schedule: a deterministic, pure policy that, given logical
//! `now` and each monitor's period + last-run tick, returns which monitors are **due**. The served
//! daemon ticks it from a real timer (that wall-clock interval loop is the one infra piece — the
//! decision logic is here and fully testable offline); on each tick it runs every due monitor, feeds a
//! resulting [`crate::IncidentCandidate`] to the register, and calls [`mark_ran`](CadenceScheduler::mark_ran).
//!
//! No clock/RNG/I/O — `now` is injected (the same [`crate::Tick`] axis as the register, see
//! [`crate::SECONDS_PER_TICK`]).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::Tick;

/// Canonical id for the §5.4 defense-in-depth CHD store-sweep monitor.
pub const MONITOR_STORE_SWEEP: &str = "store-sweep";
/// Canonical id for the §8.2 NIC/NPL NTP clock-skew monitor.
pub const MONITOR_NTP_SKEW: &str = "ntp-skew";
/// Canonical id for the §8.1 India-residency verifier.
pub const MONITOR_RESIDENCY: &str = "residency-verify";

/// One monitor's cadence entry: how often it must run (`period_ticks`) and when it last ran.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonitorCadence {
    pub monitor_id: String,
    /// The run period in [`Tick`]s. `0` is treated as "every tick".
    pub period_ticks: Tick,
    /// The tick this monitor last ran at. `None` ⇒ never run ⇒ due immediately.
    pub last_run: Option<Tick>,
}

impl MonitorCadence {
    /// Whether this monitor is due at `now`: never-run monitors are due immediately; otherwise due once
    /// at least `period_ticks` have elapsed since the last run (saturating; never due "in the past").
    pub fn is_due(&self, now: Tick) -> bool {
        match self.last_run {
            None => true,
            Some(last) => now.saturating_sub(last) >= self.period_ticks,
        }
    }

    /// The next tick this monitor becomes due (a never-run monitor: `0` — due now).
    pub fn next_due(&self) -> Tick {
        match self.last_run {
            None => 0,
            Some(last) => last.saturating_add(self.period_ticks),
        }
    }
}

/// A deterministic cadence scheduler for the supervisory monitors (§5.4 / §8.1 / §8.2). Pure: the
/// daemon supplies `now`; the scheduler decides which monitors are due. Serde-round-trippable so the
/// schedule + last-run state survives a restart (the "survive kill -9" property the register has).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CadenceScheduler {
    monitors: BTreeMap<String, MonitorCadence>,
}

impl CadenceScheduler {
    /// An empty scheduler.
    pub fn new() -> Self {
        Self::default()
    }

    /// The RBI-default schedule: the three supervisory monitors registered at sensible cadences,
    /// **all due immediately** (never-run) so the first tick runs each once. Cadences are expressed on
    /// Generic default cadence — no pre-registered monitors.
    /// Use this as the OSS baseline; add monitors via `register()` for your deployment.
    pub fn generic_default() -> Self {
        Self::new()
    }

    /// India regulatory default cadence — store-sweep, NTP-skew, and residency monitors
    /// pre-registered on the [`crate::SECONDS_PER_TICK`]-scaled (minute) axis:
    /// * store-sweep — every 60 ticks (hourly)
    /// * NTP-skew — every 5 ticks (5 min)
    /// * India-residency — every 1440 ticks (daily)
    pub fn india_regulatory_default() -> Self {
        let mut s = Self::new();
        s.register(MONITOR_STORE_SWEEP, 60);
        s.register(MONITOR_NTP_SKEW, 5);
        s.register(MONITOR_RESIDENCY, 1440);
        s
    }

    /// Deprecated alias for [`india_regulatory_default`](CadenceScheduler::india_regulatory_default).
    /// Use `india_regulatory_default()` in new code.
    #[deprecated(since = "1.0.0", note = "use `india_regulatory_default()` instead")]
    pub fn india_default() -> Self {
        Self::india_regulatory_default()
    }

    /// Register/replace a monitor with the given period (never-run ⇒ due immediately). Chainable.
    pub fn register(&mut self, monitor_id: &str, period_ticks: Tick) -> &mut Self {
        self.monitors.insert(
            monitor_id.to_string(),
            MonitorCadence {
                monitor_id: monitor_id.to_string(),
                period_ticks,
                last_run: None,
            },
        );
        self
    }

    /// The monitor ids due at `now`, in deterministic id order.
    pub fn due(&self, now: Tick) -> Vec<String> {
        self.monitors
            .values()
            .filter(|m| m.is_due(now))
            .map(|m| m.monitor_id.clone())
            .collect()
    }

    /// Whether a specific monitor is due at `now` (unknown id ⇒ `false`).
    pub fn is_due(&self, monitor_id: &str, now: Tick) -> bool {
        self.monitors.get(monitor_id).is_some_and(|m| m.is_due(now))
    }

    /// Record that `monitor_id` ran at `now` (advances its last-run; no-op for an unknown id). The
    /// daemon calls this after running the monitor's detector on a tick.
    pub fn mark_ran(&mut self, monitor_id: &str, now: Tick) {
        if let Some(m) = self.monitors.get_mut(monitor_id) {
            m.last_run = Some(now);
        }
    }

    /// The next tick at which ANY monitor becomes due (for a sleep-until-next-due driver). `None` when
    /// no monitors are registered.
    pub fn next_wakeup(&self) -> Option<Tick> {
        self.monitors.values().map(MonitorCadence::next_due).min()
    }

    /// Borrow a monitor's cadence entry.
    pub fn get(&self, monitor_id: &str) -> Option<&MonitorCadence> {
        self.monitors.get(monitor_id)
    }

    /// Number of registered monitors.
    pub fn len(&self) -> usize {
        self.monitors.len()
    }

    /// Whether no monitors are registered.
    pub fn is_empty(&self) -> bool {
        self.monitors.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn never_run_monitors_are_due_immediately_then_respect_their_period() {
        let mut s = CadenceScheduler::india_regulatory_default();
        assert_eq!(s.len(), 3);

        // First tick (t=0): all three are due (never run).
        let mut due = s.due(0);
        due.sort();
        assert_eq!(due, vec!["ntp-skew", "residency-verify", "store-sweep"]);

        // Run them all at t=0.
        for id in [MONITOR_STORE_SWEEP, MONITOR_NTP_SKEW, MONITOR_RESIDENCY] {
            s.mark_ran(id, 0);
        }
        // Immediately after, none are due.
        assert!(s.due(0).is_empty());
        assert!(s.due(4).is_empty());

        // At t=5 the 5-tick NTP monitor is due again; the others are not.
        assert_eq!(s.due(5), vec!["ntp-skew".to_string()]);
        assert!(!s.is_due(MONITOR_STORE_SWEEP, 5));

        // At t=60 store-sweep + ntp-skew are due; residency (daily=1440) is not.
        s.mark_ran(MONITOR_NTP_SKEW, 5);
        let mut due60 = s.due(60);
        due60.sort();
        assert_eq!(due60, vec!["ntp-skew", "store-sweep"]);
        assert!(!s.is_due(MONITOR_RESIDENCY, 60));

        // Residency comes due at t=1440.
        assert!(s.is_due(MONITOR_RESIDENCY, 1440));
    }

    #[test]
    fn next_wakeup_is_the_earliest_due_tick() {
        let mut s = CadenceScheduler::new();
        s.register("a", 10);
        s.register("b", 3);
        // Both never-run ⇒ next_due 0 ⇒ wakeup now.
        assert_eq!(s.next_wakeup(), Some(0));
        s.mark_ran("a", 0);
        s.mark_ran("b", 0);
        // a next due at 10, b at 3 ⇒ earliest is 3.
        assert_eq!(s.next_wakeup(), Some(3));
    }

    #[test]
    fn period_zero_is_every_tick_and_unknown_ids_are_inert() {
        let mut s = CadenceScheduler::new();
        s.register("hot", 0);
        assert!(s.is_due("hot", 0));
        s.mark_ran("hot", 0);
        assert!(s.is_due("hot", 0), "period 0 ⇒ always due");
        // Unknown ids never crash and are never due.
        assert!(!s.is_due("ghost", 100));
        s.mark_ran("ghost", 100); // no-op
        assert!(s.get("ghost").is_none());
    }

    #[test]
    fn scheduler_state_survives_a_serde_round_trip() {
        let mut s = CadenceScheduler::india_regulatory_default();
        s.mark_ran(MONITOR_NTP_SKEW, 42);
        let json = serde_json::to_string(&s).unwrap();
        let back: CadenceScheduler = serde_json::from_str(&json).unwrap();
        assert_eq!(back.get(MONITOR_NTP_SKEW).unwrap().last_run, Some(42));
        assert!(!back.is_due(MONITOR_NTP_SKEW, 43));
        assert!(back.is_due(MONITOR_NTP_SKEW, 47));
    }
}
