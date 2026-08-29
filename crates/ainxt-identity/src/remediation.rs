// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! ainxt-identity::remediation — bind the payment-boundary's §4.6 **graduated tripwire response** to
//! the REAL identity control-plane + incident register.
//!
//! Design: `docs/architecture/AGENT_IDENTITY_AND_PAYMENT_BOUNDARY.md` ADR-016 **§4.6** (the Layer-6
//! pre-dispatch tripwire's *graduated* remediation) + ADR-022 **§17** (individual Run/OBO-user
//! revocation) + ADR-017 (statutory incident breach clock).
//!
//! # Why this lives here (and not in `ainxt-payments`)
//!
//! `ainxt-payments` stays a **pure** decision core: it *emits* the graduated response as ordered,
//! structured directives ([`GraduatedResponse`](ainxt_payments::boundary::GraduatedResponse)) and
//! defines the [`TripwireRemediation`](ainxt_payments::boundary::TripwireRemediation) seam — but it
//! performs no side effects and depends on neither identity nor incident (acyclic). This module is the
//! runtime-side *enactment*: a [`ControlPlaneRemediator`] that turns each directive into a real,
//! queryable control-plane state change —
//!
//! * **quarantine** the offending capability → a real quarantine ledger the runtime consults before
//!   re-selecting/dispatching a capability (§3.5, a stronger state than "disabled");
//! * **revoke** the acting identity → the REAL [`ControlPlane`] revocation registry (ADR-022 §17), so
//!   an in-flight dispatch carrying that Run/OBO-user is denied immediately;
//! * **raise** a security incident → the REAL [`IncidentRegister`] on the breach clock (ADR-017),
//!   armed from [`CandidateSource::PaymentBoundary`] ⇒ `AgentSettlementAction`.
//!
//! So when the live egress path (`ainxt-connector-http`) drives `GraduatedResponse::enact` against a
//! [`ControlPlaneRemediator`], the three escalation actions are *enforced*, not advisory — each leaves
//! a control-plane fact a test (and a regulator) can observe.

use std::collections::{BTreeSet, HashSet};
use std::sync::{Arc, Mutex};

use ainxt_incident::{ArmingPolicy, IncidentCandidate, IncidentRegister};
use ainxt_payments::boundary::{InitiationReason, TripwireRemediation};

use crate::control::ControlPlane;

/// A [`TripwireRemediation`] that enacts the §4.6 graduated response against the **real** identity
/// control-plane and incident register. Interior-mutable (each side effect takes `&self`) and
/// `Send + Sync`, so a single instance can be held (behind an `Arc`) by the live connector dispatch
/// gate and shared across worker threads. Every directive produces a durable, queryable fact:
/// revocations land in the [`ControlPlane`], quarantines in an internal ledger, incidents in the
/// [`IncidentRegister`].
///
/// GAP-AUDIT regulated-fi #2 — `control`/`incidents` are [`Arc<Mutex<..>>`], not owned `Mutex<..>`,
/// specifically so the runtime composition root can hand this remediator the SAME shared organs it
/// gives every other served surface (`/v1/regfi/*`, `spawn_breach_clock`, `AssembledFull::arm_incident`).
/// [`ControlPlaneRemediator::new`] (an owned, private pair) previously made this the ONLY payment-
/// boundary incident source whose output no `/v1/regfi/auditor` call or breach-clock sweep could ever
/// see — the tripwire fired, quarantined, and revoked correctly, but the incident landed in a register
/// nobody but this struct's own accessors could read.
pub struct ControlPlaneRemediator {
    control: Arc<Mutex<ControlPlane>>,
    incidents: Arc<Mutex<IncidentRegister>>,
    /// Capabilities quarantined by a fired tripwire — neither re-selectable nor dispatchable until an
    /// authenticated review clears them (§3.5).
    quarantined: Mutex<HashSet<String>>,
    /// The control-plane commit SHA in force (evidentiary — "which policy definitions were live").
    control_plane_sha: String,
}

impl ControlPlaneRemediator {
    /// A remediator over a fresh, private control-plane + a default-armed incident register — for
    /// tests and standalone use. A served deployment must use [`ControlPlaneRemediator::with_shared`]
    /// so payment-boundary incidents land on the daemon's real, queryable register instead of a
    /// throwaway one (see the struct doc comment).
    pub fn new() -> Self {
        Self::with_shared(
            Arc::new(Mutex::new(ControlPlane::new())),
            Arc::new(Mutex::new(IncidentRegister::new(ArmingPolicy::new()))),
            "uncommitted",
        )
    }

    /// A remediator over caller-supplied, OWNED organs (kept for compatibility with existing tests
    /// that don't need sharing). Wraps them in fresh `Arc`s — this instance is still the sole owner.
    pub fn with_parts(
        control: ControlPlane,
        incidents: IncidentRegister,
        control_plane_sha: impl Into<String>,
    ) -> Self {
        Self::with_shared(
            Arc::new(Mutex::new(control)),
            Arc::new(Mutex::new(incidents)),
            control_plane_sha,
        )
    }

    /// A remediator over the runtime's SHARED control-plane + incident register [`Arc`]s — the
    /// production constructor. Every side effect this remediator performs (revoke/quarantine/raise)
    /// is now visible to every other holder of the same `Arc` (the served `/v1/regfi/*` routes, the
    /// statutory breach clock, `AssembledFull::arm_incident`).
    pub fn with_shared(
        control: Arc<Mutex<ControlPlane>>,
        incidents: Arc<Mutex<IncidentRegister>>,
        control_plane_sha: impl Into<String>,
    ) -> Self {
        ControlPlaneRemediator {
            control,
            incidents,
            quarantined: Mutex::new(HashSet::new()),
            control_plane_sha: control_plane_sha.into(),
        }
    }

    /// Whether `capability_id` is currently quarantined by a fired tripwire.
    pub fn is_quarantined(&self, capability_id: &str) -> bool {
        self.quarantined
            .lock()
            .expect("quarantine lock")
            .contains(capability_id)
    }

    /// Whether the acting identity `id` has been revoked on the control-plane (either as a Run or an
    /// OBO user — the tripwire revokes both namespaces fail-closed).
    pub fn is_identity_revoked(&self, id: &str) -> bool {
        let cp = self.control.lock().expect("control lock");
        cp.revocations().is_run_revoked(id) || cp.revocations().is_user_revoked(id)
    }

    /// The number of incidents opened on the register (each fired tripwire opens exactly one).
    pub fn incident_count(&self) -> usize {
        self.incidents
            .lock()
            .expect("incident lock")
            .incidents()
            .count()
    }

    /// Read access to the register (assertions / further wiring).
    pub fn incident_ids(&self) -> Vec<String> {
        self.incidents
            .lock()
            .expect("incident lock")
            .incidents()
            .map(|i| i.id.clone())
            .collect()
    }
}

impl Default for ControlPlaneRemediator {
    fn default() -> Self {
        Self::new()
    }
}

impl TripwireRemediation for ControlPlaneRemediator {
    fn quarantine_capability(&self, capability_id: &str) {
        self.quarantined
            .lock()
            .expect("quarantine lock")
            .insert(capability_id.to_string());
    }

    fn revoke_acting_identity(&self, acting_identity: &str) {
        // Fail-closed across both identity namespaces: the actor URI carried by the mis-declared call
        // is treated as BOTH a Run id and an OBO-user id, so whichever it is, the in-flight dispatch
        // carrying it is denied at the next dispatch/renewal (ADR-022 §17).
        let mut cp = self.control.lock().expect("control lock");
        cp.revoke_run(acting_identity);
        cp.revoke_user(acting_identity);
    }

    fn raise_incident(
        &self,
        capability_id: &str,
        acting_identity: &str,
        reasons: &BTreeSet<InitiationReason>,
    ) {
        // GAP-AUDIT regulated-fi #2 — real wall-clock seconds, not a private monotonic counter from 0.
        // This register is now shared with the daemon's other incident sources (breach clock,
        // `/v1/regfi/*`), whose statutory notification deadlines are computed off `noticed_at` as a
        // real Unix timestamp; a counter starting at 0 would look like a decades-overdue breach.
        let tick = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // PII-free description: capability + actor + the deterministic signature reasons (enum labels).
        let description = format!(
            "payment-boundary tripwire: capability={capability_id} actor={acting_identity} reasons={reasons:?}"
        );
        // The typed §2.2 detection-source adapter (source = PaymentBoundary ⇒ arms
        // `AgentSettlementAction`), with the offending capability as the involved system and the
        // signature reasons as the description.
        let candidate =
            IncidentCandidate::from_payment_boundary(tick, &self.control_plane_sha, capability_id)
                .with_description(&description);
        self.incidents
            .lock()
            .expect("incident lock")
            .open_from(candidate, tick);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ainxt_payments::boundary::{BoundaryDenied, GraduatedResponse};

    fn denial() -> BoundaryDenied {
        BoundaryDenied {
            destination: "https://upi-settlement.example.internal".into(),
            resource_key: String::new(),
            reasons: [InitiationReason::SettlementPerimeterDestination]
                .into_iter()
                .collect(),
        }
    }

    #[test]
    fn r14_enact_binds_all_three_to_real_organs() {
        let rem = ControlPlaneRemediator::new();
        let resp = GraduatedResponse::plan(&denial(), "turn-1", "connector.gitlab", "user:mallory");

        assert!(!rem.is_quarantined("connector.gitlab"));
        assert!(!rem.is_identity_revoked("user:mallory"));
        assert_eq!(rem.incident_count(), 0);

        let receipt = resp.enact(&rem);
        assert!(receipt.is_complete());

        assert!(
            rem.is_quarantined("connector.gitlab"),
            "capability must be quarantined"
        );
        assert!(
            rem.is_identity_revoked("user:mallory"),
            "acting identity must be revoked"
        );
        assert_eq!(
            rem.incident_count(),
            1,
            "exactly one incident must be raised"
        );
    }

    /// GAP-AUDIT regulated-fi #2 — `with_shared` must raise into the CALLER's `Arc`, not a private
    /// copy: another holder of the SAME `Arc<Mutex<IncidentRegister>>` (standing in for the daemon's
    /// `/v1/regfi/auditor` route) must see the incident the tripwire raised.
    #[test]
    fn gap_regfi_02_shared_register_incident_is_visible_to_the_other_arc_holder() {
        let shared_control = Arc::new(Mutex::new(ControlPlane::new()));
        let shared_incidents = Arc::new(Mutex::new(IncidentRegister::new(ArmingPolicy::new())));
        let rem = ControlPlaneRemediator::with_shared(
            shared_control.clone(),
            shared_incidents.clone(),
            "sha-abc123",
        );

        assert_eq!(
            shared_incidents.lock().expect("lock").incidents().count(),
            0,
            "the shared register starts empty"
        );

        let resp = GraduatedResponse::plan(&denial(), "turn-1", "connector.gitlab", "user:mallory");
        let receipt = resp.enact(&rem);
        assert!(receipt.is_complete());

        // The "auditor" (the other Arc holder) sees the incident the remediator raised — this is
        // exactly what `/v1/regfi/auditor` and the statutory breach clock need to be able to do.
        assert_eq!(
            shared_incidents.lock().expect("lock").incidents().count(),
            1,
            "the incident must land on the SAME shared register, not a private copy"
        );
        assert!(
            shared_control
                .lock()
                .expect("lock")
                .revocations()
                .is_run_revoked("user:mallory"),
            "the revocation must also land on the shared control-plane"
        );
    }
}
