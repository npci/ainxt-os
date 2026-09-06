// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Multi-GPU shard-level health + drain-the-group recovery (SERVING_OPS.md §4, gap 37).
//!
//! Process liveness is the wrong signal: a tensor/pipeline-parallel (TP/PP) shard group can have
//! every rank alive (process running, socket open) while the group is functionally dead — a hung
//! collective op (one rank stuck in an all-reduce, the rest blocked) or, worse, **silently
//! producing corrupted output** (a numerics fault averaging garbage into an otherwise-fine
//! result) — with nothing in process/container liveness ever going red. This module models the two
//! independent signals SERVING_OPS.md §4 requires, plus drain-the-group recovery:
//!
//! * **Interconnect/collective watchdog** ([`ShardHealthMonitor::record_collective`]) — each
//!   collective op's duration is compared to a timeout tuned above measured p99.9; **N consecutive
//!   misses** (never one slow tick — that would flap) flags the group `Degraded`. A success resets
//!   the miss counter. Catches hangs.
//! * **Canary correctness probe** ([`ShardHealthMonitor::record_canary`] / [`ShardHealthMonitor::run_probe`])
//!   — a deterministic (temperature-0, fixed-seed, fixed-prompt) request's output hash is compared
//!   to a golden hash computed once at placement time. A mismatch flags the group `SuspectCorrupt`
//!   **even though process and collective liveness are both green** — the concrete answer to
//!   "corrupts silently, invisible to process liveness."
//! * **Drain-the-group** — a `Degraded`/`SuspectCorrupt` group is pulled from the routable pool the
//!   instant either signal fires (a placement-table update, not a process kill — the group keeps
//!   running for forensics). An N+1 **standby** is promoted to restore capacity. In-flight requests
//!   recover under the existing idempotency-ledger discipline (a seam here, not reinvented).
//!
//! The actual GPU inference behind the canary is a **seam** ([`CanaryProbe`]). Everything else is
//! pure and deterministic — the watchdog counts, the golden-hash compare, and the routable-set are
//! all unit-assertable with no GPU and no clock (durations are logical ticks passed in).

use std::collections::{BTreeMap, BTreeSet};

/// A TP/PP shard group — the unit health is tracked at (a group of interconnect-adjacent GPUs
/// serving one model replica). Opaque id.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ShardGroupId(pub String);

impl ShardGroupId {
    pub fn new(s: impl Into<String>) -> Self {
        ShardGroupId(s.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The health state of a shard group (SERVING_OPS.md §4). Only [`HealthState::Healthy`] groups are
/// routable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthState {
    /// Passing both signals; in the routable pool.
    Healthy,
    /// The interconnect watchdog tripped (hung collective) — pulled from the pool.
    Degraded,
    /// The canary probe's golden-hash compare failed (silent corruption) — pulled from the pool.
    SuspectCorrupt,
    /// Explicitly drained (e.g. for a weight rollout's staged replacement) — pulled from the pool.
    Drained,
}

impl HealthState {
    /// Whether a group in this state may receive new admissions.
    pub fn is_routable(self) -> bool {
        matches!(self, HealthState::Healthy)
    }
}

/// The result of feeding one signal to the monitor — what the caller should act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthEvent {
    /// Signal healthy; nothing to do.
    Ok,
    /// A collective op missed the deadline but the consecutive-miss threshold is not yet reached.
    WatchdogMiss { consecutive: u32 },
    /// The group just transitioned to a non-routable state and must be drained from the pool.
    PulledFromPool { state: HealthState },
    /// A signal arrived for a group not registered / already non-routable — ignored.
    Ignored,
}

/// The GPU-inference seam behind the canary probe (SERVING_OPS.md §4). Real implementations run a
/// fixed deterministic request through the shard group and return its output hash; this pure crate
/// only consumes the hash.
pub trait CanaryProbe {
    /// Run the deterministic probe against `group`, returning the output hash.
    fn probe(&self, group: &ShardGroupId) -> u64;
}

/// Monitor configuration (SERVING_OPS.md §4). `collective_timeout` is a logical-tick duration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HealthConfig {
    /// A collective op taking strictly longer than this (logical ticks) counts as a miss.
    pub collective_timeout: u64,
    /// Consecutive misses required to flag `Degraded` (>=1). Guards against flapping on one slow tick.
    pub consecutive_miss_threshold: u32,
}

#[derive(Debug, Clone)]
struct GroupState {
    state: HealthState,
    golden_hash: u64,
    consecutive_misses: u32,
}

/// Multi-GPU shard health monitor + drain-the-group recovery (SERVING_OPS.md §4).
#[derive(Debug, Clone)]
pub struct ShardHealthMonitor {
    cfg: HealthConfig,
    groups: BTreeMap<ShardGroupId, GroupState>,
    /// N+1 standby reservation: `(group, golden_hash)` pairs promotable on a drain (§3/§4 step 3).
    standby: Vec<(ShardGroupId, u64)>,
}

impl ShardHealthMonitor {
    pub fn new(cfg: HealthConfig) -> Self {
        ShardHealthMonitor {
            cfg,
            groups: BTreeMap::new(),
            standby: Vec::new(),
        }
    }

    /// Register a group into the routable pool at placement time, with the golden hash computed
    /// once for its exact model/quantization/TP-degree (SERVING_OPS.md §4).
    pub fn register_group(&mut self, id: ShardGroupId, golden_hash: u64) {
        self.groups.insert(
            id,
            GroupState {
                state: HealthState::Healthy,
                golden_hash,
                consecutive_misses: 0,
            },
        );
    }

    /// Reserve an N+1 standby (SERVING_OPS.md §3/§4 step 3) — promoted into the pool on a drain.
    pub fn add_standby(&mut self, id: ShardGroupId, golden_hash: u64) {
        self.standby.push((id, golden_hash));
    }

    pub fn standby_count(&self) -> usize {
        self.standby.len()
    }

    /// Feed one collective-op duration (interconnect watchdog, SERVING_OPS.md §4). A duration over
    /// the timeout increments the consecutive-miss counter; reaching the threshold flags `Degraded`.
    /// A duration within the timeout resets the counter (anti-flap).
    pub fn record_collective(&mut self, id: &ShardGroupId, duration: u64) -> HealthEvent {
        let threshold = self.cfg.consecutive_miss_threshold.max(1);
        let timeout = self.cfg.collective_timeout;
        let Some(g) = self.groups.get_mut(id) else {
            return HealthEvent::Ignored;
        };
        if !g.state.is_routable() {
            return HealthEvent::Ignored;
        }
        if duration <= timeout {
            g.consecutive_misses = 0;
            return HealthEvent::Ok;
        }
        g.consecutive_misses += 1;
        if g.consecutive_misses >= threshold {
            g.state = HealthState::Degraded;
            HealthEvent::PulledFromPool {
                state: HealthState::Degraded,
            }
        } else {
            HealthEvent::WatchdogMiss {
                consecutive: g.consecutive_misses,
            }
        }
    }

    /// Feed one canary output hash (SERVING_OPS.md §4). A mismatch against the golden hash flags
    /// `SuspectCorrupt` — even while liveness signals are green.
    pub fn record_canary(&mut self, id: &ShardGroupId, observed_hash: u64) -> HealthEvent {
        let Some(g) = self.groups.get_mut(id) else {
            return HealthEvent::Ignored;
        };
        if !g.state.is_routable() {
            return HealthEvent::Ignored;
        }
        if observed_hash == g.golden_hash {
            HealthEvent::Ok
        } else {
            g.state = HealthState::SuspectCorrupt;
            HealthEvent::PulledFromPool {
                state: HealthState::SuspectCorrupt,
            }
        }
    }

    /// Run the canary probe seam against `group` and record its result (SERVING_OPS.md §4).
    pub fn run_probe(&mut self, id: &ShardGroupId, probe: &dyn CanaryProbe) -> HealthEvent {
        if !self.groups.contains_key(id) {
            return HealthEvent::Ignored;
        }
        let observed = probe.probe(id);
        self.record_canary(id, observed)
    }

    /// Explicitly drain a group (e.g. for a staged weight rollout, §5). Returns whether it was a
    /// known routable group.
    pub fn drain(&mut self, id: &ShardGroupId) -> bool {
        match self.groups.get_mut(id) {
            Some(g) if g.state.is_routable() => {
                g.state = HealthState::Drained;
                true
            }
            _ => false,
        }
    }

    /// Promote one reserved standby into the routable pool (SERVING_OPS.md §4 step 3), restoring
    /// capacity after a drain. Returns the promoted group's id, or `None` if no standby remains.
    pub fn promote_standby(&mut self) -> Option<ShardGroupId> {
        let (id, golden) = self.standby.pop()?;
        self.groups.insert(
            id.clone(),
            GroupState {
                state: HealthState::Healthy,
                golden_hash: golden,
                consecutive_misses: 0,
            },
        );
        Some(id)
    }

    /// Return a recovered group to the standby reservation. A recovered node must **re-earn its
    /// trust** first (ADR-021 §8 — `attested` is that precondition, verified by the attestation
    /// gate; passed in here as the seam result). Returns `Ok(())`, or an error if the group is
    /// unknown / still healthy, or was not re-attested.
    pub fn recover_to_standby(
        &mut self,
        id: &ShardGroupId,
        golden_hash: u64,
        attested: bool,
    ) -> Result<(), RecoverError> {
        if !attested {
            return Err(RecoverError::NotAttested);
        }
        // Read the state as a Copy value so the immutable borrow ends before we mutate `groups`.
        match self.groups.get(id).map(|g| g.state) {
            Some(state) if !state.is_routable() => {
                self.groups.remove(id);
                self.standby.push((id.clone(), golden_hash));
                Ok(())
            }
            Some(_) => Err(RecoverError::StillHealthy),
            None => Err(RecoverError::Unknown),
        }
    }

    /// The routable pool: every group currently `Healthy`, in deterministic id order.
    pub fn routable_groups(&self) -> Vec<ShardGroupId> {
        self.groups
            .iter()
            .filter(|(_, g)| g.state.is_routable())
            .map(|(id, _)| id.clone())
            .collect()
    }

    pub fn state_of(&self, id: &ShardGroupId) -> Option<HealthState> {
        self.groups.get(id).map(|g| g.state)
    }
    pub fn routable_count(&self) -> usize {
        self.groups
            .values()
            .filter(|g| g.state.is_routable())
            .count()
    }
}

/// Why returning a group to standby failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoverError {
    /// The recovered node has not re-earned its attestation (ADR-021 §8).
    NotAttested,
    /// The group is unknown to the monitor.
    Unknown,
    /// The group is currently healthy — nothing to recover.
    StillHealthy,
}

// ---------------------------------------------------------------------------
// Physical routing-table actuation seam + drain-the-group driver
// (SERVING_OPS.md §4, INFRA-GATED)
// ---------------------------------------------------------------------------
//
// [`ShardHealthMonitor`] above is the pure health-state machine (both signals + the standby model),
// fully testable with no GPU and no clock. Two adjacent actions touch live serving infra: (a)
// physically pulling a drained group out of the load-balancer's routable set, and (b) bringing a
// promoted standby physically online. Those are isolated behind the [`FleetRouter`] seam so the
// drain-the-group RECOVERY SEQUENCE (drain the failed group → promote an N+1 standby → route it)
// stays pure and offline-testable via [`InMemoryFleetRouter`]. The live router (Envoy/xDS or the
// gateway's balancer) is the only part deferred to real infra.

/// The physical load-balancer routing-table seam (SERVING_OPS.md §4, INFRA-GATED). Real
/// implementations mutate the live balancer's routable set (xDS push / gateway reload) and bring a
/// promoted standby online. [`InMemoryFleetRouter`] is the deterministic offline reference.
pub trait FleetRouter {
    /// Physically remove `group` from the routable set the instant a health signal drains it — the
    /// group keeps running for forensics; it just stops receiving new admissions.
    fn drain_route(&mut self, group: &ShardGroupId);
    /// Physically bring a promoted standby `group` online and into the routable set. Returns whether
    /// it was newly routed.
    fn promote_route(&mut self, group: &ShardGroupId) -> bool;
    /// Whether `group` is currently in the live routable set.
    fn is_routed(&self, group: &ShardGroupId) -> bool;
}

/// A deterministic in-memory [`FleetRouter`] — the live routable set as a sorted set.
#[derive(Debug, Clone, Default)]
pub struct InMemoryFleetRouter {
    routed: BTreeSet<ShardGroupId>,
}

impl InMemoryFleetRouter {
    pub fn new() -> Self {
        InMemoryFleetRouter::default()
    }
    /// Seed the initial routable set (the groups placement brought online).
    pub fn with_routed(mut self, groups: impl IntoIterator<Item = ShardGroupId>) -> Self {
        self.routed.extend(groups);
        self
    }
    /// The live routable set in deterministic id order.
    pub fn routed(&self) -> Vec<ShardGroupId> {
        self.routed.iter().cloned().collect()
    }
    pub fn routed_count(&self) -> usize {
        self.routed.len()
    }
}

impl FleetRouter for InMemoryFleetRouter {
    fn drain_route(&mut self, group: &ShardGroupId) {
        self.routed.remove(group);
    }
    fn promote_route(&mut self, group: &ShardGroupId) -> bool {
        self.routed.insert(group.clone())
    }
    fn is_routed(&self, group: &ShardGroupId) -> bool {
        self.routed.contains(group)
    }
}

/// The result of a drain-the-group recovery step (SERVING_OPS.md §4 step 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrainReplaceOutcome {
    /// The group physically pulled from the routable set.
    pub drained: ShardGroupId,
    /// The N+1 standby promoted + physically routed to restore capacity, or `None` if none remained
    /// (a capacity shortfall reported honestly, never hidden).
    pub promoted: Option<ShardGroupId>,
}

impl ShardHealthMonitor {
    /// Execute the physical drain-the-group recovery for a group the monitor just pulled from the
    /// pool (SERVING_OPS.md §4): drain it from the live router, then promote one N+1 standby into the
    /// monitor and physically route it. Pure sequencing over the [`FleetRouter`] seam — the offline
    /// impl makes it deterministically testable without a GPU or a live balancer.
    pub fn drain_and_replace(
        &mut self,
        drained: &ShardGroupId,
        router: &mut dyn FleetRouter,
    ) -> DrainReplaceOutcome {
        router.drain_route(drained);
        let promoted = self.promote_standby();
        if let Some(p) = &promoted {
            router.promote_route(p);
        }
        DrainReplaceOutcome {
            drained: drained.clone(),
            promoted,
        }
    }
}

/// One shard group's observations for a single monitoring tick (SERVING_OPS.md §4): the interconnect
/// watchdog's last collective-op duration (`None` = no collective completed this tick) and the canary
/// probe's last output hash (`None` = no probe this tick). A real monitor gathers these from the
/// live fleet; a test supplies them directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthObservation {
    pub group: ShardGroupId,
    pub collective_duration: Option<u64>,
    pub canary_hash: Option<u64>,
}

impl HealthObservation {
    pub fn new(group: ShardGroupId) -> Self {
        HealthObservation {
            group,
            collective_duration: None,
            canary_hash: None,
        }
    }
    pub fn collective(mut self, duration: u64) -> Self {
        self.collective_duration = Some(duration);
        self
    }
    pub fn canary(mut self, hash: u64) -> Self {
        self.canary_hash = Some(hash);
        self
    }
}

impl ShardHealthMonitor {
    /// **The live monitoring-loop body** (SERVING_OPS.md §4; serving-ops gap-5). One tick: feed each
    /// group's watchdog + canary observation through the two-signal health machine, and for every group
    /// that transitions non-routable THIS tick, immediately run the physical drain-the-group recovery
    /// (drain from the live router → promote an N+1 standby → route it). Returns the recovery outcomes,
    /// in deterministic group-id order. A group that both misses collectives AND fails its canary in one
    /// tick is drained exactly once (never double-counted against the standby pool).
    ///
    /// This is the piece the audit found missing: §4 had the pure state machine + the `drain_and_replace`
    /// sequence, but nothing *polled* them on a cadence, so a hung/corrupt group was never actually
    /// pulled in production. The async timer that calls this each interval and the live GPU probe /
    /// interconnect counters are the infra seams (needs_hot_wiring); the poll→act loop is proven here.
    pub fn monitor_tick(
        &mut self,
        observations: &[HealthObservation],
        router: &mut dyn FleetRouter,
    ) -> Vec<DrainReplaceOutcome> {
        let mut pulled: BTreeSet<ShardGroupId> = BTreeSet::new();
        for obs in observations {
            if let Some(d) = obs.collective_duration {
                if let HealthEvent::PulledFromPool { .. } = self.record_collective(&obs.group, d) {
                    pulled.insert(obs.group.clone());
                }
            }
            // Only probe the canary if the group is still routable after the watchdog (a group already
            // pulled this tick needs no second signal — it is out of the pool either way).
            if let Some(h) = obs.canary_hash {
                if let HealthEvent::PulledFromPool { .. } = self.record_canary(&obs.group, h) {
                    pulled.insert(obs.group.clone());
                }
            }
        }
        pulled
            .into_iter()
            .map(|g| self.drain_and_replace(&g, router))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// The periodic health-sweep DRIVER (SERVING_OPS.md §4, gap 37; serving-ops gap-5, round-15)
// ---------------------------------------------------------------------------
//
// [`ShardHealthMonitor::monitor_tick`] (round-12) is the pure poll→act loop BODY — feed it
// observations, it drains the two-signal health machine and runs drain-the-group recovery for
// whatever transitions non-routable. But it has no notion of "is a sweep due yet": every call is
// treated as due, so the only thing standing between this crate and a real cadence was the daemon's
// own bespoke timer bookkeeping — exactly the gap the audit flagged as "not driven by any daemon
// cadence" (there is a poll body, but nothing that decides WHEN to poll). [`HealthCadence`] closes
// that the same way [`crate::attestation::AttestationRefresher`] closes the analogous attestation
// gap: it owns the cadence + a next-due cursor, so the daemon's async timer has exactly ONE call —
// [`HealthCadence::tick`] — every tick, and the sweep itself only actually runs when it is due.

/// Cadence tuning for [`HealthCadence`] (SERVING_OPS.md §4). A logical-tick duration, so the driver
/// stays deterministic and exhaustively testable (no wall clock).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HealthCadenceConfig {
    /// Logical ticks between health sweeps. A tick before the next due point is a no-op
    /// ([`HealthCadence::tick`] returns `None`).
    pub interval: u64,
}

impl Default for HealthCadenceConfig {
    fn default() -> Self {
        // A conservative default sweep cadence; a deployment tunes this to its GPU-probe budget.
        HealthCadenceConfig { interval: 10 }
    }
}

impl HealthCadenceConfig {
    /// The effective (never-zero) cadence — a `0` interval degrades to "every tick", never a busy-loop
    /// (the same saturating-floor discipline [`crate::attestation::RefreshConfig`] uses).
    fn effective_interval(self) -> u64 {
        self.interval.max(1)
    }
}

/// A stateful, periodic driver for [`ShardHealthMonitor::monitor_tick`] (SERVING_OPS.md §4, gap 37;
/// serving-ops gap-5, round-15).
///
/// Holds its own cadence + next-due cursor, mirroring [`crate::attestation::AttestationRefresher`]'s
/// pattern for the analogous attestation-refresh gap. On a due [`HealthCadence::tick`] it runs one
/// [`ShardHealthMonitor::monitor_tick`] pass over the supplied observations (feeding the interconnect
/// watchdog + canary signals through the health machine and, for anything that transitions
/// non-routable this sweep, immediately draining the group and promoting an N+1 standby through the
/// [`FleetRouter`] seam) and advances the cadence. A tick before the next due point does nothing and
/// returns `None` — the daemon's async timer granularity no longer has to match the desired GPU-probe
/// frequency exactly; this driver throttles it.
///
/// The async timer + the live GPU probe / interconnect counters that gather [`HealthObservation`]s
/// are the daemon's needs_hot_wiring/infra concern; the due-or-not decision and the poll→act sequence
/// it gates are proven here, offline.
#[derive(Debug, Clone)]
pub struct HealthCadence {
    cfg: HealthCadenceConfig,
    next_due_at: u64,
    sweeps: u64,
}

impl HealthCadence {
    /// Build a driver at this cadence. The first [`Self::tick`] at any `now` is due (a fresh fleet must
    /// be health-swept as early as possible after boot, mirroring the attestation refresher).
    pub fn new(cfg: HealthCadenceConfig) -> Self {
        HealthCadence {
            cfg,
            next_due_at: 0,
            sweeps: 0,
        }
    }

    /// The cadence tuning.
    pub fn config(&self) -> HealthCadenceConfig {
        self.cfg
    }

    /// Whether a sweep is due at `now` (the periodic cadence gate).
    pub fn is_due(&self, now: u64) -> bool {
        now >= self.next_due_at
    }

    /// How many sweeps have actually run (a `None`-returning tick does not count).
    pub fn sweeps_run(&self) -> u64 {
        self.sweeps
    }

    /// One driver tick at logical time `now`. Returns `None` when a sweep is not yet due; on a due
    /// tick it runs [`ShardHealthMonitor::monitor_tick`] over `observations` through `router`, advances
    /// the cadence to `now + interval`, and returns the [`DrainReplaceOutcome`]s (possibly empty — a
    /// clean sweep with nothing to drain is still a sweep that ran).
    pub fn tick(
        &mut self,
        monitor: &mut ShardHealthMonitor,
        now: u64,
        observations: &[HealthObservation],
        router: &mut dyn FleetRouter,
    ) -> Option<Vec<DrainReplaceOutcome>> {
        if !self.is_due(now) {
            return None;
        }
        let outcomes = monitor.monitor_tick(observations, router);
        self.next_due_at = now.saturating_add(self.cfg.effective_interval());
        self.sweeps = self.sweeps.saturating_add(1);
        Some(outcomes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> HealthConfig {
        HealthConfig {
            collective_timeout: 100,
            consecutive_miss_threshold: 3,
        }
    }

    fn gid(s: &str) -> ShardGroupId {
        ShardGroupId::new(s)
    }

    struct FixedProbe(u64);
    impl CanaryProbe for FixedProbe {
        fn probe(&self, _group: &ShardGroupId) -> u64 {
            self.0
        }
    }

    #[test]
    fn watchdog_flags_degraded_only_after_consecutive_misses() {
        let mut m = ShardHealthMonitor::new(cfg());
        let g = gid("tp0");
        m.register_group(g.clone(), 42);
        // A single slow tick must NOT drain (anti-flap).
        assert_eq!(
            m.record_collective(&g, 200),
            HealthEvent::WatchdogMiss { consecutive: 1 }
        );
        assert_eq!(
            m.record_collective(&g, 200),
            HealthEvent::WatchdogMiss { consecutive: 2 }
        );
        assert!(
            m.state_of(&g).unwrap().is_routable(),
            "still routable at 2 misses"
        );
        // Third consecutive miss trips the threshold.
        assert_eq!(
            m.record_collective(&g, 200),
            HealthEvent::PulledFromPool {
                state: HealthState::Degraded
            }
        );
        assert_eq!(m.state_of(&g), Some(HealthState::Degraded));
        assert!(m.routable_groups().is_empty());
    }

    #[test]
    fn a_good_collective_resets_the_miss_counter() {
        let mut m = ShardHealthMonitor::new(cfg());
        let g = gid("tp0");
        m.register_group(g.clone(), 1);
        m.record_collective(&g, 200); // miss 1
        m.record_collective(&g, 200); // miss 2
        assert_eq!(m.record_collective(&g, 50), HealthEvent::Ok); // fast → reset
                                                                  // Two more misses must NOT trip (counter was reset), because threshold is 3.
        assert_eq!(
            m.record_collective(&g, 200),
            HealthEvent::WatchdogMiss { consecutive: 1 }
        );
        assert_eq!(
            m.record_collective(&g, 200),
            HealthEvent::WatchdogMiss { consecutive: 2 }
        );
        assert!(m.state_of(&g).unwrap().is_routable());
    }

    #[test]
    fn boundary_duration_equal_to_timeout_is_not_a_miss() {
        let mut m = ShardHealthMonitor::new(cfg());
        let g = gid("tp0");
        m.register_group(g.clone(), 1);
        assert_eq!(
            m.record_collective(&g, 100),
            HealthEvent::Ok,
            "== timeout is OK"
        );
        assert_eq!(
            m.record_collective(&g, 101),
            HealthEvent::WatchdogMiss { consecutive: 1 }
        );
    }

    #[test]
    fn canary_mismatch_flags_suspect_corrupt_despite_liveness() {
        let mut m = ShardHealthMonitor::new(cfg());
        let g = gid("tp0");
        m.register_group(g.clone(), 0xABCD);
        // Liveness is fine (fast collectives)...
        assert_eq!(m.record_collective(&g, 10), HealthEvent::Ok);
        // ...but the deterministic canary returns the wrong hash → silent corruption caught.
        assert_eq!(
            m.record_canary(&g, 0xDEAD),
            HealthEvent::PulledFromPool {
                state: HealthState::SuspectCorrupt
            }
        );
        assert_eq!(m.state_of(&g), Some(HealthState::SuspectCorrupt));
        assert!(!m.state_of(&g).unwrap().is_routable());
    }

    #[test]
    fn canary_match_keeps_group_healthy() {
        let mut m = ShardHealthMonitor::new(cfg());
        let g = gid("tp0");
        m.register_group(g.clone(), 777);
        assert_eq!(m.record_canary(&g, 777), HealthEvent::Ok);
        assert!(m.state_of(&g).unwrap().is_routable());
    }

    #[test]
    fn run_probe_seam_records_the_probe_result() {
        let mut m = ShardHealthMonitor::new(cfg());
        let g = gid("tp0");
        m.register_group(g.clone(), 555);
        // Probe returns a mismatching hash → SuspectCorrupt.
        assert_eq!(
            m.run_probe(&g, &FixedProbe(999)),
            HealthEvent::PulledFromPool {
                state: HealthState::SuspectCorrupt
            }
        );
        // Unknown group → ignored, no panic.
        assert_eq!(
            m.run_probe(&gid("nope"), &FixedProbe(1)),
            HealthEvent::Ignored
        );
    }

    #[test]
    fn drain_and_promote_standby_restores_capacity() {
        let mut m = ShardHealthMonitor::new(cfg());
        let primary = gid("tp0");
        let standby = gid("tp0-standby");
        m.register_group(primary.clone(), 1);
        m.add_standby(standby.clone(), 1);
        assert_eq!(m.routable_count(), 1);
        assert_eq!(m.standby_count(), 1);

        // A hang drains the primary...
        for _ in 0..3 {
            m.record_collective(&primary, 999);
        }
        assert_eq!(m.routable_count(), 0);
        // ...the N+1 standby is promoted, restoring routable capacity.
        assert_eq!(m.promote_standby(), Some(standby.clone()));
        assert_eq!(m.routable_count(), 1);
        assert_eq!(m.routable_groups(), vec![standby]);
        assert_eq!(m.standby_count(), 0);
        // No standby left → promotion yields None (honest, not a panic).
        assert_eq!(m.promote_standby(), None);
    }

    #[test]
    fn signals_on_already_drained_group_are_ignored() {
        let mut m = ShardHealthMonitor::new(cfg());
        let g = gid("tp0");
        m.register_group(g.clone(), 1);
        assert!(m.drain(&g));
        assert_eq!(m.record_collective(&g, 999), HealthEvent::Ignored);
        assert_eq!(m.record_canary(&g, 2), HealthEvent::Ignored);
        // Draining an already-drained (non-routable) group returns false.
        assert!(!m.drain(&g));
    }

    #[test]
    fn recovery_requires_re_attestation() {
        let mut m = ShardHealthMonitor::new(cfg());
        let g = gid("tp0");
        m.register_group(g.clone(), 1);
        for _ in 0..3 {
            m.record_collective(&g, 999);
        }
        assert_eq!(m.state_of(&g), Some(HealthState::Degraded));
        // A recovered-but-not-re-attested group is refused (ADR-021 §8 — must re-earn trust).
        assert_eq!(
            m.recover_to_standby(&g, 1, false),
            Err(RecoverError::NotAttested)
        );
        // Re-attested → returns to the standby reservation, out of the live groups.
        assert!(m.recover_to_standby(&g, 1, true).is_ok());
        assert_eq!(m.state_of(&g), None);
        assert_eq!(m.standby_count(), 1);
    }

    #[test]
    fn recover_rejects_healthy_and_unknown_groups() {
        let mut m = ShardHealthMonitor::new(cfg());
        let g = gid("tp0");
        m.register_group(g.clone(), 1);
        assert_eq!(
            m.recover_to_standby(&g, 1, true),
            Err(RecoverError::StillHealthy)
        );
        assert_eq!(
            m.recover_to_standby(&gid("ghost"), 1, true),
            Err(RecoverError::Unknown)
        );
    }

    #[test]
    fn unknown_group_signals_are_ignored_not_panicked() {
        let mut m = ShardHealthMonitor::new(cfg());
        assert_eq!(m.record_collective(&gid("x"), 1), HealthEvent::Ignored);
        assert_eq!(m.record_canary(&gid("x"), 1), HealthEvent::Ignored);
    }
}
