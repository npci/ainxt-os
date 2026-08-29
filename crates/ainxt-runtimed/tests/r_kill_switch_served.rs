// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX identity-payments (ADR-022 §19 "big red button") — `ControlPlane::pull_kill_switch`/
//! `release_kill_switch`/`kill_switch_audit` were fully implemented and unit-tested in
//! `ainxt-identity`, but `AssembledFull` never exposed them: an operator could never actually pull the
//! kill-switch on the shipped daemon, even though every dispatch admission already consults the SAME
//! `control_plane` field. Proves the served passthroughs are reachable, fail-closed on authority, and
//! that a pull/release round-trip is visible in the audit trail.

use ainxt_identity::authority::{KillScope, KillSwitchAuthError};
use ainxt_identity::LogicalTime;
use ainxt_runtimed::{assemble_chat, assemble_full, load_layered};

fn full() -> ainxt_runtimed::AssembledFull {
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let loaded = load_layered(&[("base", "version = 1")]).unwrap();
    let assembled = assemble_chat(&loaded).unwrap();
    assemble_full(&loaded, assembled).unwrap()
}

#[test]
fn r_kill_switch_pull_is_fail_closed_on_authority() {
    let f = full();

    // Too junior (ad_level above the §19 bar) is refused, even with can_approve set.
    let junior = f.pull_kill_switch(KillScope::Workforce, "u-junior", 5, true, LogicalTime(1));
    assert!(
        matches!(
            junior,
            Err(KillSwitchAuthError::InsufficientSeniority {
                ad_level: 5,
                max: 3
            })
        ),
        "an over-junior puller must be refused, got {junior:?}"
    );
    assert!(
        f.kill_switch_audit().is_empty(),
        "a refused pull leaves no audit trail"
    );

    // Sufficiently senior but lacking `can_approve` is refused too (master-switch-style AND gate).
    let no_approve = f.pull_kill_switch(KillScope::Workforce, "u-exec", 1, false, LogicalTime(1));
    assert!(matches!(
        no_approve,
        Err(KillSwitchAuthError::NotApprover(_))
    ));
    assert!(f.kill_switch_audit().is_empty());
}

#[test]
fn r_kill_switch_pull_release_round_trip_is_audited() {
    let f = full();

    let audit = f
        .pull_kill_switch(KillScope::Workforce, "u-exec", 1, true, LogicalTime(5))
        .expect("a senior approver may pull the workforce kill-switch");
    assert_eq!(audit.scope, KillScope::Workforce);
    assert_eq!(audit.puller, "u-exec");
    assert_eq!(audit.ad_level, 1);

    // The served, read-only audit trail reflects the pull.
    let log = f.kill_switch_audit();
    assert_eq!(log.len(), 1);
    assert_eq!(log[0], audit);

    // The release counterpart clears it — a halt is a live lever, not a one-way trip. Releasing does
    // not erase history: the audit trail is immutable.
    f.release_kill_switch(&KillScope::Workforce);
    assert_eq!(
        f.kill_switch_audit().len(),
        1,
        "release does not erase the immutable audit trail"
    );
}

// GAP-FIX identity-payments (§17) — `ControlPlane::revoke_run`/`revoke_user` had zero DIRECT,
// operator-initiated callers on the served path (only internal auto-revoke triggers existed). Proves
// the served passthroughs reach the SAME revocation registry `ControlPlane::admit` consults.
#[test]
fn r_revoke_run_and_revoke_user_reachable_from_the_served_composition_root() {
    let f = full();
    assert!(!f.is_run_revoked("run-1"));
    assert!(!f.is_user_revoked("u-alice"));

    f.revoke_run("run-1");
    assert!(
        f.is_run_revoked("run-1"),
        "the served revoke must be visible on the SAME registry"
    );
    assert!(
        !f.is_run_revoked("run-2"),
        "revocation is scoped to the named run, not a blanket halt"
    );

    f.revoke_user("u-alice");
    assert!(f.is_user_revoked("u-alice"));
    assert!(!f.is_user_revoked("u-bob"));
}

// GAP-FIX identity-payments (§20 UEBA) — `ControlPlane::observe` had zero callers outside
// `ainxt-identity`'s own tests. Proves the served scoring seam detects a real deviation and, under
// `RevokeRun`, drives the SAME revocation registry `revoke_run`/`is_run_revoked` above expose.
#[test]
fn r_observe_run_activity_detects_deviation_and_can_revoke_in_flight() {
    use ainxt_identity::authority::{ActivitySample, BehavioralBaseline};
    use ainxt_identity::control::AnomalyResponse;

    let f = full();
    let baseline = BehavioralBaseline::new("role-analyst").with_capabilities(["kb.search"]);

    // A sample that stays within the baseline is NOT anomalous.
    let clean = ActivitySample {
        run_id: "run-1".into(),
        def_ref: "role-analyst".into(),
        capabilities_used: ["kb.search".to_string()].into_iter().collect(),
        ..Default::default()
    };
    let assessment = f.observe_run_activity(&baseline, &clean, AnomalyResponse::RenewalChoke);
    assert!(
        !assessment.is_anomalous(),
        "in-baseline activity must not be flagged"
    );
    assert!(!f.is_run_revoked("run-1"));

    // A sample using a capability OUTSIDE the baseline deviates — RevokeRun revokes it in-flight on
    // the SAME registry `is_run_revoked` reads.
    let rogue = ActivitySample {
        run_id: "run-1".into(),
        def_ref: "role-analyst".into(),
        capabilities_used: ["settlement.initiate".to_string()].into_iter().collect(),
        ..Default::default()
    };
    let assessment = f.observe_run_activity(&baseline, &rogue, AnomalyResponse::RevokeRun);
    assert!(
        assessment.is_anomalous(),
        "an out-of-baseline capability must be flagged: {assessment:?}"
    );
    assert!(
        f.is_run_revoked("run-1"),
        "RevokeRun must revoke the run in-flight on the served registry"
    );
}

// GAP-FIX identity-payments (§4.6) — `ControlPlaneRemediator::is_quarantined`/`is_identity_revoked`/
// `incident_count` had zero served callers: the remediator was built and immediately erased into
// `Arc<dyn TripwireRemediation>` with no concrete handle retained, so nothing could query what the
// §4.6 graduated tripwire had actually enacted. Proves the served query passthroughs reflect the
// SAME remediator the connector USE path's tripwire response drives.
#[test]
fn r_tripwire_remediator_queries_reflect_the_same_remediator_the_connector_path_drives() {
    use ainxt_payments::boundary::{InitiationReason, TripwireRemediation};
    use std::collections::BTreeSet;

    let f = full();
    assert!(!f.tripwire_is_quarantined("connector.evil"));
    assert!(!f.tripwire_is_identity_revoked("run-rogue"));
    assert_eq!(f.tripwire_incident_count(), 0);

    // Drive the SAME remediator's TripwireRemediation trait methods the connector invoker calls when
    // its §4.6 graduated response fires on a live egress path.
    f.tripwire_remediator
        .quarantine_capability("connector.evil");
    f.tripwire_remediator.revoke_acting_identity("run-rogue");
    let mut reasons = BTreeSet::new();
    reasons.insert(InitiationReason::UpiValueOperation);
    f.tripwire_remediator
        .raise_incident("connector.evil", "run-rogue", &reasons);

    assert!(f.tripwire_is_quarantined("connector.evil"));
    assert!(
        !f.tripwire_is_quarantined("connector.other"),
        "quarantine is scoped, not a blanket halt"
    );
    assert!(f.tripwire_is_identity_revoked("run-rogue"));
    // The identity revocation also lands on the SHARED control plane other seams read.
    assert!(
        f.is_run_revoked("run-rogue"),
        "the tripwire's revoke must be visible on the shared registry"
    );
    assert_eq!(f.tripwire_incident_count(), 1);
}
