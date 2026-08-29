// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R12 gap (medium): "Store-sweep, NTP-skew monitor, and India-residency verifier are callable
//! entrypoints but not scheduled on any cadence."
//!
//! Closure: [`CadenceScheduler`] is the deterministic schedule that decides which supervisory monitors
//! are due at a given logical tick. This integration test drives the FULL loop offline — exactly what
//! the served daemon does on each timer fire, minus the wall-clock `tokio::interval` (the one infra
//! piece; `needs_hot_wiring` in the reserved daemon): advance `now`, ask the scheduler which monitors
//! are due, RUN each due detector (NTP-skew + India-residency here — real `ainxt-incident` detectors),
//! open any resulting candidate on the LIVE register, then `mark_ran`. Proves the schedule fires the
//! detectors at their cadence and arms real statutory clocks, and that a healthy tick arms nothing.

use ainxt_incident::cadence::{
    CadenceScheduler, MONITOR_NTP_SKEW, MONITOR_RESIDENCY, MONITOR_STORE_SWEEP,
};
use ainxt_incident::ops::{NtpSkewMonitor, ResidencyVerifier};
use ainxt_incident::{ArmingPolicy, CandidateSource, IncidentRegister, StatutoryClockKind};

#[test]
fn r12_scheduler_dispatches_due_monitors_across_ticks_and_arms_real_incidents() {
    let mut sched = CadenceScheduler::india_regulatory_default();
    let mut reg = IncidentRegister::new(ArmingPolicy::india_regulatory_default());

    let ntp = NtpSkewMonitor::new("nic-ntp.gov.in", 100);
    let residency = ResidencyVerifier::india();

    // A deliberately mis-located store (caught by the residency verifier) and an in-country one.
    let stores = [("trace-store", "us-east-1"), ("eventlog", "ap-south-1")];
    // A drifting clock offset by tick (in-threshold at t=0, way out at t=5).
    let offset_at = |now: u64| -> i64 {
        if now >= 5 {
            -350
        } else {
            10
        }
    };

    let mut opened: Vec<String> = Vec::new();

    // Simulate the daemon timer over ticks 0..=6, running whatever the SCHEDULE says is due.
    for now in 0u64..=6 {
        for monitor in sched.due(now) {
            match monitor.as_str() {
                MONITOR_NTP_SKEW => {
                    let (_att, cand) = ntp.check(offset_at(now), now, "cp-sha");
                    if let Some(c) = cand {
                        assert_eq!(c.source, CandidateSource::NtpSkew);
                        opened.push(reg.open_from(c, now));
                    }
                }
                MONITOR_RESIDENCY => {
                    for c in residency.verify_all(stores, now, "cp-sha") {
                        assert_eq!(c.source, CandidateSource::ResidencyViolation);
                        opened.push(reg.open_from(c, now));
                    }
                }
                MONITOR_STORE_SWEEP => { /* driven by ainxt-compliance's SinkGuard::sweep; no CHD here */
                }
                other => panic!("unexpected monitor id {other}"),
            }
            sched.mark_ran(&monitor, now);
        }
    }

    // The residency verifier ran at t=0 (never-run ⇒ due) and flagged exactly the mis-located store.
    // The NTP monitor ran at t=0 (in-threshold, no incident) and again at t=5 (5-tick cadence) where the
    // skew was out of bounds → an incident. So we opened at least the residency + the t>=5 skew incident.
    assert!(
        opened.len() >= 2,
        "schedule must have fired residency + the out-of-threshold NTP skew, got {}",
        opened.len()
    );

    // Every opened incident armed a real statutory clock (the engine is actually fed).
    for id in &opened {
        let inc = reg.incident(id).expect("incident present");
        assert!(
            inc.clock(StatutoryClockKind::CertIn).is_some(),
            "a cyber-class incident must arm the CERT-In clock"
        );
    }

    // After the run the schedule advanced: NTP last-ran recently (not due at t=6), residency next due daily.
    assert!(
        !sched.is_due(MONITOR_RESIDENCY, 6),
        "residency is a daily cadence"
    );
}

#[test]
fn r12_healthy_ticks_arm_nothing() {
    let mut sched = CadenceScheduler::india_regulatory_default();
    let ntp = NtpSkewMonitor::new("nic-ntp.gov.in", 100);
    let residency = ResidencyVerifier::india();
    let stores = [("eventlog", "ap-south-1"), ("trace", "india")]; // both in-country

    let mut opened = 0usize;
    for now in 0u64..=120 {
        for monitor in sched.due(now) {
            match monitor.as_str() {
                MONITOR_NTP_SKEW => {
                    let (_a, c) = ntp.check(20, now, "cp"); // always in-threshold
                    if c.is_some() {
                        opened += 1;
                    }
                }
                MONITOR_RESIDENCY => {
                    opened += residency.verify_all(stores, now, "cp").len();
                }
                _ => {}
            }
            sched.mark_ran(&monitor, now);
        }
    }
    assert_eq!(opened, 0, "no incidents on healthy measurements");
}
