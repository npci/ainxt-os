// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! GPU-fleet **QoS admission** for program Runs: a workload class + a preemptible low-priority tier +
//! an **elastic fan-out** policy that decides how wide a wave of independent modules may dispatch onto
//! a shared, finite GPU fleet.
//!
//! Design: `docs/architecture/LONG_HORIZON_PROGRAMS.md` (ADR-027) §7 (time-feasibility / parallel
//! fan-out) and `docs/architecture/SUBSYSTEM_DEEP_DIVES.md` (serving-ops gap W — OSS inference at
//! scale). Gap: the parallel fan-out width ([`crate::driver::drive_program_verified_fanout`]) was a
//! fixed ceiling with no notion of *who else is on the fleet* — a 1M-LOC batch migration would either
//! starve interactive traffic (fan out to everything) or leave the fleet idle (fan out to one). A
//! regulated FI runs Programs on the SAME GPU fleet as live chat; a long migration must yield to
//! interactive traffic and burst only into genuinely spare capacity.
//!
//! # What is closed here vs. what stays infra
//!
//! This module is the **pure admission policy**: given the free capacity, the number of ready modules,
//! the Run's workload class, and whether higher-priority work is queued, it computes the number of
//! modules to admit *this instant* — deterministic, no clock/rng/I/O, every rule a unit-test property.
//! The **live GPU fleet** it feeds (vLLM batching, real GPU counts, autoscale, actual preemption of an
//! in-flight kernel) is infrastructure the deployment wires behind this decision (`needs_hot_wiring` /
//! infra-gated); the *decision of how wide to go* — the part that made fan-out either unsafe or
//! useless — now lives here and is enforced before the driver dispatches a wave.

use serde::{Deserialize, Serialize};

/// The QoS class a program Run occupies on the shared GPU fleet (§7). Higher-priority classes are
/// admitted ahead of, and can preempt, lower ones. Ordered by descending priority (Interactive first)
/// so `Interactive < Batch < PreemptibleLowPriority` expresses "cheaper to shed".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WorkloadClass {
    /// Latency-sensitive, human-in-the-loop (a chat/edit surface Run). Never preempted; admitted up to
    /// its full ready width against free capacity.
    Interactive,
    /// A normal long-horizon Program migration. Bursts into free capacity but always leaves headroom
    /// for interactive traffic, and yields (does not preempt) when higher-priority work is queued.
    Batch,
    /// Best-effort, preemptible background work (a speculative re-verification sweep, a nightly
    /// backfill). Admitted ONLY into capacity no one else wants, and the first to be shed — it yields
    /// entirely the moment any higher-priority work is queued.
    PreemptibleLowPriority,
}

impl WorkloadClass {
    /// Whether a Run of this class may be preempted (its in-flight wave cut short) to free capacity for
    /// higher-priority work. Only [`WorkloadClass::PreemptibleLowPriority`] is preemptible (§7).
    pub fn is_preemptible(self) -> bool {
        matches!(self, WorkloadClass::PreemptibleLowPriority)
    }
}

/// The live GPU-fleet capacity snapshot the elastic policy reads — populated by the deployment's fleet
/// telemetry (a real GPU-count / KV-cache / batch-slot reading is `needs_hot_wiring`; the shape is
/// stable so the policy is testable offline). All counts are in units of concurrent module Runs the
/// fleet can serve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FleetCapacity {
    /// Total concurrent-Run slots the fleet can serve at full utilisation.
    pub total_slots: usize,
    /// Slots currently occupied by in-flight Runs (any class).
    pub in_use: usize,
    /// Slots to keep free as headroom for interactive traffic — never consumed by `Batch` or lower.
    pub interactive_reserve: usize,
    /// Whether higher-priority work (a queued Interactive Run, or an operator burst) is waiting. When
    /// true, `Batch` stops bursting and `PreemptibleLowPriority` yields entirely (§7).
    pub higher_priority_queued: bool,
}

impl FleetCapacity {
    pub fn new(total_slots: usize, in_use: usize) -> Self {
        FleetCapacity {
            total_slots,
            in_use,
            interactive_reserve: 0,
            higher_priority_queued: false,
        }
    }
    /// Builder: keep `n` slots as interactive headroom (never consumed by Batch or lower).
    pub fn with_interactive_reserve(mut self, n: usize) -> Self {
        self.interactive_reserve = n;
        self
    }
    /// Builder: mark that higher-priority work is queued (Batch stops bursting, low-priority yields).
    pub fn with_higher_priority_queued(mut self, queued: bool) -> Self {
        self.higher_priority_queued = queued;
        self
    }
    /// Free slots right now (never below 0).
    pub fn free(&self) -> usize {
        self.total_slots.saturating_sub(self.in_use)
    }
}

/// The elastic fan-out admission policy (§7): how wide a wave of independent, dependency-satisfied
/// modules may dispatch onto the shared GPU fleet, given the Run's [`WorkloadClass`] and the live
/// [`FleetCapacity`]. Pure + deterministic.
#[derive(Debug, Clone, Copy, Default)]
pub struct ElasticFanoutPolicy {
    /// A hard per-wave ceiling regardless of free capacity (bounds blast radius / cost even when the
    /// fleet is huge). `0` means "no explicit ceiling" (bounded only by capacity + ready width).
    pub max_wave: usize,
}

impl ElasticFanoutPolicy {
    pub fn new(max_wave: usize) -> Self {
        ElasticFanoutPolicy { max_wave }
    }

    /// Decide how many of `ready` independent modules to admit this instant for a Run of `class`
    /// against the live `capacity`.
    ///
    /// The rules (§7), applied per class:
    /// * **Interactive** — admit up to its full ready width against *all* free capacity (it may consume
    ///   the interactive reserve; it IS the interactive traffic). Never yields.
    /// * **Batch** — admit into free capacity **minus** the interactive reserve (always leave headroom),
    ///   and admit **nothing** while higher-priority work is queued (it yields, but is not preempted —
    ///   its in-flight wave finishes; only its *next* wave is held).
    /// * **PreemptibleLowPriority** — admit into free capacity minus the reserve, and admit **nothing**
    ///   the moment any higher-priority work is queued (it yields entirely; a live deployment also
    ///   preempts its in-flight wave — that cut is the infra half, [`WorkloadClass::is_preemptible`]).
    ///
    /// The result is `min(ready, admissible_capacity, max_wave?)` and is never larger than `ready`, so
    /// the driver never over-admits. `0` is a legitimate answer (hold this wave / yield).
    pub fn admit(&self, ready: usize, class: WorkloadClass, capacity: &FleetCapacity) -> usize {
        if ready == 0 {
            return 0;
        }
        let free = capacity.free();
        let admissible = match class {
            WorkloadClass::Interactive => free,
            WorkloadClass::Batch => {
                if capacity.higher_priority_queued {
                    0
                } else {
                    free.saturating_sub(capacity.interactive_reserve)
                }
            }
            WorkloadClass::PreemptibleLowPriority => {
                if capacity.higher_priority_queued {
                    0
                } else {
                    free.saturating_sub(capacity.interactive_reserve)
                }
            }
        };
        let mut width = ready.min(admissible);
        if self.max_wave > 0 {
            width = width.min(self.max_wave);
        }
        width
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interactive_uses_all_free_capacity_including_the_reserve() {
        let cap = FleetCapacity::new(10, 2).with_interactive_reserve(3);
        // 8 free; interactive may use all of it (up to its 5 ready modules).
        assert_eq!(
            ElasticFanoutPolicy::default().admit(5, WorkloadClass::Interactive, &cap),
            5
        );
        assert_eq!(
            ElasticFanoutPolicy::default().admit(20, WorkloadClass::Interactive, &cap),
            8
        );
    }

    #[test]
    fn batch_leaves_interactive_headroom() {
        let cap = FleetCapacity::new(10, 2).with_interactive_reserve(3);
        // 8 free - 3 reserve = 5 admissible for batch.
        assert_eq!(
            ElasticFanoutPolicy::default().admit(20, WorkloadClass::Batch, &cap),
            5
        );
    }

    #[test]
    fn batch_yields_when_higher_priority_is_queued() {
        let cap = FleetCapacity::new(10, 2)
            .with_interactive_reserve(0)
            .with_higher_priority_queued(true);
        // Even with 8 free slots, batch holds its next wave while interactive work is queued.
        assert_eq!(
            ElasticFanoutPolicy::default().admit(8, WorkloadClass::Batch, &cap),
            0
        );
    }

    #[test]
    fn low_priority_only_uses_slack_and_yields_first() {
        let idle = FleetCapacity::new(10, 2).with_interactive_reserve(3);
        assert_eq!(
            ElasticFanoutPolicy::default().admit(9, WorkloadClass::PreemptibleLowPriority, &idle),
            5 // 8 free - 3 reserve
        );
        let busy = idle.with_higher_priority_queued(true);
        assert_eq!(
            ElasticFanoutPolicy::default().admit(9, WorkloadClass::PreemptibleLowPriority, &busy),
            0
        );
        assert!(WorkloadClass::PreemptibleLowPriority.is_preemptible());
        assert!(!WorkloadClass::Batch.is_preemptible());
        assert!(!WorkloadClass::Interactive.is_preemptible());
    }

    #[test]
    fn max_wave_caps_even_a_huge_fleet() {
        let cap = FleetCapacity::new(1000, 0);
        assert_eq!(
            ElasticFanoutPolicy::new(8).admit(500, WorkloadClass::Batch, &cap),
            8
        );
    }

    #[test]
    fn never_admits_more_than_ready_or_when_full() {
        let full = FleetCapacity::new(4, 4);
        assert_eq!(
            ElasticFanoutPolicy::default().admit(10, WorkloadClass::Interactive, &full),
            0
        );
        let cap = FleetCapacity::new(10, 0);
        assert_eq!(
            ElasticFanoutPolicy::default().admit(2, WorkloadClass::Batch, &cap),
            2
        );
    }

    #[test]
    fn class_ordering_reflects_shed_priority() {
        assert!(WorkloadClass::Interactive < WorkloadClass::Batch);
        assert!(WorkloadClass::Batch < WorkloadClass::PreemptibleLowPriority);
    }
}
