// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX os-workforce — the §7.2/§7.3 oversight-health decoy/competency quartet
//! (`should_inject_decoy`/`evaluate_decoy`/`competency_after`/`competency_route`) was fully
//! implemented and unit-tested in `ainxt-workforce` but had zero callers anywhere outside its own
//! crate's tests — `run_workforce_nightly_tick` drives `decay_sweep`/`orphan_sweep`/`oversight_health`/
//! `recert_sweep`, but never this path. Proves `ainxt_runtimed`'s bare re-exports (mirroring
//! `validate_succession_pr`'s precedent) enforce the SAME §7.2/§7.3 rules.

use ainxt_runtimed::{competency_after, competency_route, evaluate_decoy, should_inject_decoy};
use ainxt_types::DataClass;
use ainxt_workforce::oversight::{ApprovalRoute, AttentionCheck, CompetencyStatus, DecoyOutcome};
use ainxt_workforce::role::PaymentBoundary;

#[test]
fn r_decoy_eligibility_and_outcome_reachable_from_ainxt_runtimed() {
    // §7.2: decoys only for high-stakes (payment-boundary or regulated/PII data).
    assert!(should_inject_decoy(
        PaymentBoundary::Direct,
        DataClass::Internal
    ));
    assert!(should_inject_decoy(
        PaymentBoundary::None,
        DataClass::RegulatedPayment
    ));
    assert!(!should_inject_decoy(
        PaymentBoundary::None,
        DataClass::Internal
    ));

    let check = AttentionCheck {
        decoy_id: "d1".into(),
        role: "risk".into(),
    };
    match evaluate_decoy(&check, "carol", true) {
        DecoyOutcome::Incident {
            approver,
            mandatory_retraining,
        } => {
            assert_eq!(approver, "carol");
            assert!(
                mandatory_retraining,
                "approving a decoy mandates retraining"
            );
        }
        other => panic!("approving a decoy must be an incident, got {other:?}"),
    }
    assert_eq!(
        evaluate_decoy(&check, "carol", false),
        DecoyOutcome::CorrectlyRejected
    );
}

#[test]
fn r_competency_expiry_and_reroute_reachable_from_ainxt_runtimed() {
    // §7.3: expired competency (a failed attention-check, or too-long zero-override streak).
    assert_eq!(competency_after(30, 25, false), CompetencyStatus::Expired);
    assert_eq!(competency_after(5, 25, false), CompetencyStatus::Current);
    assert_eq!(competency_after(0, 25, true), CompetencyStatus::Expired);

    // Expired competency RE-ROUTES to a secondary — the gate never blocks the workflow outright.
    match competency_route("primary", CompetencyStatus::Expired, "secondary") {
        ApprovalRoute::Rerouted { from, to, .. } => {
            assert_eq!(from, "primary");
            assert_eq!(to, "secondary");
        }
        other => panic!("expired competency must re-route, got {other:?}"),
    }
    assert_eq!(
        competency_route("primary", CompetencyStatus::Current, "secondary"),
        ApprovalRoute::Primary("primary".into())
    );
}
