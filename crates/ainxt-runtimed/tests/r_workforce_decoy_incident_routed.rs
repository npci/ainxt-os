// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX os-workforce — `NightlyControls::route_decoy_incident` (§7.2: an approver who approved a
//! known-bad attention-check decoy is a hard-fail — logged to the tamper-evident Event Log AND
//! escalated to the manager for immediate review + mandatory retraining) was fully implemented and
//! unit-tested in `ainxt-workforce` (`r12_workforce.rs`) but had zero callers anywhere outside its own
//! crate's tests. The decoy DECISION quartet (`should_inject_decoy`/`evaluate_decoy`/
//! `competency_after`/`competency_route`) was already wired to this composition root, but the
//! routing/audit action that must fire once `evaluate_decoy` resolves to its hard-fail `Incident`
//! outcome was never reachable here. Proves `ainxt_runtimed::route_workforce_decoy_incident` drives
//! the SAME `NightlyControls::route_decoy_incident` the library's own tests exercise, end to end:
//! both the Event Log entry and the manager digest land.

use ainxt_runtimed::{evaluate_decoy, route_workforce_decoy_incident};
use ainxt_workforce::controls::{InMemoryDataPlane, InMemoryEventLog, RecordingNotifier};
use ainxt_workforce::oversight::{AttentionCheck, DecoyOutcome};

#[test]
fn r_decoy_incident_routed_from_composition_root() {
    let check = AttentionCheck {
        decoy_id: "d1".into(),
        role: "risk".into(),
    };

    // First, drive the already-wired decision logic: an approver who approves a known-bad decoy
    // resolves to the hard-fail `Incident` outcome.
    let outcome = evaluate_decoy(&check, "carol", true);
    let DecoyOutcome::Incident {
        approver,
        mandatory_retraining,
    } = outcome
    else {
        panic!("approving a decoy must resolve to Incident, got {outcome:?}");
    };
    assert!(mandatory_retraining);

    // Now drive the routing/audit half through the composition root's re-export — this is the hop
    // that had zero callers outside `ainxt-workforce`'s own tests before this fix.
    let mut store = InMemoryDataPlane::default();
    let mut notifier = RecordingNotifier::default();
    let mut log = InMemoryEventLog::default();

    route_workforce_decoy_incident(
        &mut store,
        &mut notifier,
        &mut log,
        &approver,
        &check.role,
        "manager-x",
    );

    assert_eq!(
        log.count_of_kind("attention-check-incident"),
        1,
        "the incident must be routed to the tamper-evident Event Log"
    );
    assert_eq!(
        notifier.count_for("manager-x"),
        1,
        "the manager must be escalated for immediate review + mandatory retraining"
    );
    let sent = &notifier.sent[0];
    assert!(
        sent.body.contains("carol"),
        "the digest must name the offending approver: {sent:?}"
    );
    assert!(
        sent.body.contains("risk"),
        "the digest must name the affected role: {sent:?}"
    );
}
