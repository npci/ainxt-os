// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-12 gap-closing integration test (eval-tester-scenarios, LOW):
//! **"≥2,000-session / ≥1h load + soak run (SCENARIO_MATRIX §3.2/§7)."**
//!
//! The REAL soak — a running served daemon under sustained live load for an hour at ≥2,000 concurrent
//! sessions on the GPU/Postgres/Redis box — is infra-gated (that duration + true parallel load needs
//! live infra). What is closable offline is the deterministic soak MODEL of the concurrency spine's
//! invariants, driven at the mandate floor (2,000 sessions) over a sustained turn count. This proves,
//! mechanically, the three properties a soak exists to catch: no unbounded growth (leak), back-pressure
//! (bounded inbox shed, not memory blow-up), and per-session isolation — plus turn conservation.
//!
//! Fail-before: no test drove `run_soak` at the ≥2,000-session floor. Pass-after: the mandate-floor
//! soak passes every invariant while genuinely exercising back-pressure (arrival rate ≫ service rate).

use ainxt_scenario::soak::{run_soak, SoakConfig};

#[test]
fn r12_soak_mandate_floor() {
    // Mandate floor: 2,000 concurrent sessions. 20 turns/session models sustained load (the ≥1h
    // window compresses to turn count in the deterministic model); workers ≪ sessions so back-pressure
    // is genuinely exercised rather than a happy-path drain.
    let cfg = SoakConfig {
        sessions: 2000,
        turns_per_session: 20,
        inbox_cap: 8,
        workers: 64,
    };
    let report = run_soak(&cfg);

    // The soak passed iff nothing leaked, concurrency stayed within the worker ceiling, isolation
    // held, and every submitted turn was accounted for.
    assert!(
        report.passed(&cfg),
        "the ≥2,000-session soak must pass every invariant: {report:?}"
    );

    // Explicit invariants (so a regression names the property it broke):
    assert_eq!(
        report.leaked, 0,
        "no work item may be left allocated after the drain (leak)"
    );
    assert!(
        report.peak_live <= cfg.workers,
        "concurrency never exceeds the worker ceiling"
    );
    assert!(
        report.isolation_held,
        "no cross-session state bleed under contention"
    );
    assert_eq!(
        report.submitted,
        cfg.sessions as u64 * cfg.turns_per_session as u64,
        "every session's turns are submitted"
    );
    assert_eq!(
        report.completed + report.rejected,
        report.submitted,
        "every submitted turn is accounted for (completed or shed) — none silently lost"
    );

    // Back-pressure was genuinely exercised: 2,000 arrivals/tick against 64 workers must shed.
    assert!(
        report.rejected > 0,
        "sustained overload at the mandate floor must trigger back-pressure (503-class sheds), got {}",
        report.rejected
    );
    // And concurrency actually saturated the pool (peak_live reaches the ceiling under overload).
    assert_eq!(
        report.peak_live, cfg.workers,
        "the worker pool saturates under sustained load"
    );
}
