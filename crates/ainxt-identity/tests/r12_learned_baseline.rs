// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-12 closure of the §20 (LOW) gap — **the per-role UEBA behavioral baseline is learned from
//! the role's OWN history**, not merely injected. `BehavioralBaseline::learn_from_history` derives
//! the expected envelope (capability mix ∪, egress ∪, peak action-rate/cost-velocity × slack) from
//! the role's historical activity samples, then the existing `AnomalyMonitor::assess` scores new
//! activity against the learned envelope.
//!
//! Fail-before/pass-after: `learn_from_history` is new this round; before, a baseline had to be
//! hand-authored. The pure derivation math is real and tested here; the *continuous* re-learning
//! pipeline off streaming telemetry is the data-plane job that calls this math.

use ainxt_identity::authority::{ActivitySample, AnomalyMonitor, BehavioralBaseline};

fn sample(
    run: &str,
    def: &str,
    caps: &[&str],
    egress: &[&str],
    rate: f64,
    cost: f64,
) -> ActivitySample {
    ActivitySample {
        run_id: run.into(),
        def_ref: def.into(),
        capabilities_used: caps.iter().map(|s| s.to_string()).collect(),
        egress_destinations: egress.iter().map(|s| s.to_string()).collect(),
        action_rate: rate,
        cost_velocity: cost,
    }
}

#[test]
fn r12_baseline_learned_from_history_flags_deviation_from_own_past() {
    let def = "def:role/triage@v2";
    // The triage role's own history: it reads repos and queries Jira; modest rate/cost.
    let history = vec![
        sample("h1", def, &["repo:read"], &["jira.internal"], 4.0, 1.0),
        sample(
            "h2",
            def,
            &["repo:read", "jira:read"],
            &["jira.internal"],
            6.0,
            2.0,
        ),
        // A sample from a DIFFERENT role must be ignored by the learner.
        sample(
            "other",
            "def:role/settlement@v1",
            &["settlement:release"],
            &["rails.prod"],
            99.0,
            99.0,
        ),
    ];
    // Learn with 25% headroom over observed peaks.
    let baseline = BehavioralBaseline::learn_from_history(def, &history, 1.25);

    // The learned envelope is the union of the role's OWN behavior only.
    assert!(baseline.expected_capabilities.contains("repo:read"));
    assert!(baseline.expected_capabilities.contains("jira:read"));
    assert!(
        !baseline
            .expected_capabilities
            .contains("settlement:release"),
        "other role's history ignored"
    );
    assert!(baseline.allowed_egress.contains("jira.internal"));
    assert!(!baseline.allowed_egress.contains("rails.prod"));
    // Peak action-rate 6.0 × 1.25 = 7.5; peak cost 2.0 × 1.25 = 2.5.
    assert!((baseline.max_action_rate - 7.5).abs() < 1e-9);
    assert!((baseline.max_cost_velocity - 2.5).abs() < 1e-9);

    let monitor = AnomalyMonitor::new();
    // Normal in-envelope activity is NOT flagged.
    let normal = sample("live-1", def, &["repo:read"], &["jira.internal"], 5.0, 1.5);
    assert!(!monitor.assess(&baseline, &normal).is_anomalous());

    // The insider-threat signature §20 names: a triage Run suddenly enumerating settlement tables,
    // egressing off-net, and spiking rate — every dimension deviates from its LEARNED past.
    let anomalous = sample(
        "live-2",
        def,
        &["settlement:enumerate"],
        &["exfil.example.com"],
        50.0,
        40.0,
    );
    let assessment = monitor.assess(&baseline, &anomalous);
    assert!(assessment.is_anomalous());
    assert!(
        assessment.deviations.len() >= 3,
        "capability + egress + rate/cost spikes all flagged"
    );
}

#[test]
fn r12_unbaselined_role_with_no_history_is_not_retroactively_flagged() {
    // A role with no track record learns a maximally-permissive envelope (infinite ceilings) so it
    // is not falsely flagged; the caller decides whether an unbaselined role may run.
    let baseline =
        BehavioralBaseline::learn_from_history("def:role/new@v1", std::iter::empty(), 1.3);
    assert_eq!(baseline.max_action_rate, f64::INFINITY);
    assert_eq!(baseline.max_cost_velocity, f64::INFINITY);
    let monitor = AnomalyMonitor::new();
    let s = sample(
        "r",
        "def:role/new@v1",
        &["anything"],
        &["anywhere"],
        1e6,
        1e6,
    );
    // Rate/cost never spike against infinite ceilings; capability/egress unions were empty so any
    // use is "unexpected" — the design's defense-in-depth visibility, but no false rate/cost spike.
    let a = monitor.assess(&baseline, &s);
    assert!(!a.deviations.iter().any(|d| matches!(
        d,
        ainxt_identity::authority::Deviation::ActionRateSpike { .. }
            | ainxt_identity::authority::Deviation::CostVelocitySpike { .. }
    )));
}
