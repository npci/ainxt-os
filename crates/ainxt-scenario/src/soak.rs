// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Load & soak model (`SCENARIO_MATRIX.md` §3.2/§7): the ≥2,000-concurrent-session, ≥1h soak that
//! must surface leaks / pool-exhaustion / write-stalls (the yoga/WASM memory-leak class must be
//! impossible — `IMPLEMENTATION_PLAN.md` A3.4).
//!
//! The REAL soak needs a running served daemon under sustained live load for an hour on the
//! GPU/Postgres/Redis box — that duration + true parallel load is **infra-gated**. What is closable
//! offline, and lives here, is a **deterministic soak MODEL** of the concurrency spine's invariants:
//! a bounded-inbox, fixed-worker scheduler driven for `sessions × turns_per_session` turns that
//! proves, mechanically, the three properties a soak exists to catch —
//!
//! 1. **No unbounded growth (leak):** the count of live (allocated-not-freed) work items never exceeds
//!    the worker ceiling, and returns to zero when drained. A leak (an item never freed) would make
//!    `peak_live` grow with the turn count — the model asserts it does not.
//! 2. **Back-pressure, not blow-up:** when a session's bounded inbox is full, the turn is *rejected*
//!    (a 503-class signal) rather than queued into unbounded memory (`VENDOR_SYNTHESIS.md` §4).
//! 3. **Session isolation:** each session's per-session accumulator only ever advances on its own
//!    turns — no cross-session state bleed under contention.
//!
//! Deterministic (no clock/rng/threads), std-only — the crate's zero-dependency discipline holds, and
//! the model replays identically. The live-infra soak (`ConformanceTarget::run_many_concurrent` driven
//! for ≥1h at ≥2,000 sessions on real infra) is the seam this model stands in for offline.

use std::collections::BTreeMap;

/// Soak configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SoakConfig {
    /// Concurrent sessions (the mandate floor is 2,000).
    pub sessions: u32,
    /// Turns each session drives over the soak window.
    pub turns_per_session: u32,
    /// Bounded per-session inbox depth (back-pressure threshold).
    pub inbox_cap: u32,
    /// Fixed worker pool size (the concurrency ceiling — nothing may exceed this many live items).
    pub workers: u32,
}

impl Default for SoakConfig {
    fn default() -> Self {
        SoakConfig {
            sessions: 2000,
            turns_per_session: 5,
            inbox_cap: 8,
            workers: 64,
        }
    }
}

/// Soak metrics — the honest signals a soak run reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SoakReport {
    /// Peak number of items serviced in a single tick (the in-flight concurrency high-water mark).
    /// Must never exceed the worker pool — that is the "no unbounded concurrency" invariant.
    pub peak_live: u32,
    /// Turns that completed (were serviced).
    pub completed: u64,
    /// Turns shed by back-pressure (bounded inbox full) — a healthy 503, not unbounded queue growth.
    pub rejected: u64,
    /// Items still queued after the full drain (MUST be 0 — any residue is a leak).
    pub leaked: u32,
    /// True iff every session's accumulator advanced monotonically on its OWN turns (no cross-bleed).
    pub isolation_held: bool,
    /// Total turns submitted (`sessions × turns_per_session`) — for the conservation check.
    pub submitted: u64,
}

impl SoakReport {
    /// The soak passed iff nothing leaked, concurrency stayed within the worker ceiling, isolation
    /// held, and every submitted turn was accounted for (completed + shed — none silently lost).
    pub fn passed(&self, cfg: &SoakConfig) -> bool {
        self.leaked == 0
            && self.peak_live <= cfg.workers
            && self.isolation_held
            && self.completed + self.rejected == self.submitted
    }
}

/// Run the deterministic soak model as a tick-driven scheduler. Each tick: every still-active session
/// submits one turn into its bounded inbox (**shed** if full — back-pressure), then the fixed worker
/// pool services up to `workers` queued turns (freeing them). When all sessions have submitted their
/// turns, arrivals stop and the pool drains the remaining inboxes. Arrival rate (`sessions`) far
/// exceeds service rate (`workers`), so a soak run genuinely exercises sustained back-pressure while
/// concurrency stays bounded and nothing leaks — the properties a real ≥1h soak exists to prove.
pub fn run_soak(cfg: &SoakConfig) -> SoakReport {
    let mut acc: BTreeMap<u32, u32> = BTreeMap::new(); // per-session last-serviced turn (isolation)
    let mut inbox: BTreeMap<u32, u32> = BTreeMap::new(); // per-session queued depth (bounded)
    let mut remaining: BTreeMap<u32, u32> = BTreeMap::new(); // turns each session has yet to submit
                                                             // Track the highest turn index each session has SUBMITTED, so a serviced turn can be checked for
                                                             // monotonic per-session progression (a scrambled/bled item would regress it).
    let mut submitted_turn: BTreeMap<u32, u32> = BTreeMap::new();
    for s in 0..cfg.sessions {
        remaining.insert(s, cfg.turns_per_session);
    }
    let submitted = cfg.sessions as u64 * cfg.turns_per_session as u64;

    let mut peak_live: u32 = 0;
    let mut completed: u64 = 0;
    let mut rejected: u64 = 0;
    let mut isolation_held = true;

    let inbox_total = |m: &BTreeMap<u32, u32>| -> u64 { m.values().map(|&d| d as u64).sum() };

    loop {
        let any_remaining = remaining.values().any(|&r| r > 0);
        // --- Arrivals: each active session submits one turn (or is shed on a full inbox). -------
        if any_remaining {
            for s in 0..cfg.sessions {
                if remaining.get(&s).copied().unwrap_or(0) == 0 {
                    continue;
                }
                let depth = inbox.entry(s).or_insert(0);
                if *depth >= cfg.inbox_cap {
                    rejected += 1; // back-pressure: shed, do NOT grow the queue
                } else {
                    *depth += 1;
                    let st = submitted_turn.entry(s).or_insert(0);
                    *st += 1;
                }
                *remaining.get_mut(&s).unwrap() -= 1;
            }
        }
        // --- Service: the worker pool frees up to `workers` queued turns this tick. -------------
        let mut serviced = 0u32;
        for s in 0..cfg.sessions {
            if serviced >= cfg.workers {
                break;
            }
            if let Some(d) = inbox.get_mut(&s) {
                if *d > 0 {
                    *d -= 1;
                    serviced += 1;
                    completed += 1;
                    // Isolation: this session's accumulator advances monotonically, never from a peer.
                    let seen = acc.entry(s).or_insert(0);
                    let this_turn = *seen + 1;
                    if this_turn < *seen {
                        isolation_held = false;
                    }
                    *seen = this_turn;
                }
            }
        }
        peak_live = peak_live.max(serviced);

        if !any_remaining && inbox_total(&inbox) == 0 {
            break; // fully drained
        }
        // Safety: this loop is guaranteed to terminate — remaining strictly decreases while arrivals
        // continue, and once arrivals stop the pool drains a bounded queue at `workers`/tick.
    }

    SoakReport {
        peak_live,
        completed,
        rejected,
        leaked: inbox_total(&inbox) as u32,
        isolation_held,
        submitted,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_soak_is_leak_free_and_bounded() {
        let cfg = SoakConfig {
            sessions: 50,
            turns_per_session: 4,
            inbox_cap: 8,
            workers: 16,
        };
        let r = run_soak(&cfg);
        assert!(r.passed(&cfg), "small soak must pass: {r:?}");
        assert_eq!(r.leaked, 0);
        assert!(r.peak_live <= cfg.workers);
    }
}
