// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! The **shared, live control surface** for the running non-human workforce — the single
//! operational-state object the runtime holds *once* at its composition root and consults for
//! **every** Run, and the **short-TTL renewal driver** that turns a long-lived Run into a chain of
//! re-authorized identities.
//!
//! Design: `docs/architecture/AGENT_IDENTITY_AND_PAYMENT_BOUNDARY.md` — ADR-022 §15
//! (JIT/short-TTL/renew-and-re-attest; the *when-to-renew* lever), §17 (individual + en-masse
//! revocation consulted **per dispatch** so in-flight calls are denied immediately), §19 (workforce
//! kill-switch), §20 (anomaly monitor whose strongest lever is the renewal choke).
//!
//! # The gap this closes
//!
//! [`super::authority`] already implements the revocation registry, kill-switch, anomaly monitor,
//! and the [`IdentityAuthority::renew`](crate::authority::IdentityAuthority::renew) re-check — but
//! they were only reachable as *per-Run, composition-local, empty* state: each Run built its own
//! authority, so a revocation or kill-switch pull touched nothing already running, and no code
//! decided *when* a long Run should renew. This module supplies the two missing entrypoints:
//!
//! * [`ControlPlane`] — **one** shareable deny-state surface (revocation ∪ kill-switch ∪ anomaly)
//!   the runtime constructs once and shares across all Runs. Its [`admit`](ControlPlane::admit) is
//!   the **in-flight, per-dispatch gate** the design's §17/§19 call for: an expired, revoked,
//!   killed, or anomaly-flagged credential is denied *immediately*, not merely at its next renewal.
//! * [`RunLease`] + [`ControlPlane::renew_if_due`] — the **short-TTL JIT renewal driver**: the lease
//!   decides when a Run is within its renew-ahead margin (with per-Run jitter to avoid a
//!   thundering herd at the TTL boundary), and `renew_if_due` performs *conditional continuation* —
//!   re-checking the **shared** deny-state before delegating the attestation/definition/TTL mint to
//!   the [`IdentityAuthority`]. A kill-switch or revocation on the shared surface therefore drains a
//!   running Run within one TTL even mid-Program.
//!
//! # Determinism & concurrency
//!
//! Pure: no clock, no rng — `now` and jitter are supplied. `ControlPlane` is plain data (`Clone`,
//! `serde`); the runtime wraps the single instance in its own `Arc<RwLock<..>>` at the composition
//! root (the crate stays lock-free and deterministic so every decision is unit-testable).

use crate::authority::{
    AgentWorkloadCredential, AnomalyAssessment, AnomalyMonitor, AttestationQuote,
    AttestationVerifier, BehavioralBaseline, IdentityAuthority, IssueError, IssueRequest,
    KillScope, KillSwitch, KillSwitchAudit, KillSwitchAuthError, RenewError, RevocationRegistry,
};
use crate::LogicalTime;
use serde::{Deserialize, Serialize};
use std::fmt;

// ===========================================================================
// In-flight admission — ADR-022 §17/§19 ("consulted per dispatch")
// ===========================================================================

/// Why a credential was refused admission for an **in-flight** dispatch (§17/§19). Ordered from
/// most-fundamental (already expired) outward, so the first matching reason is reported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "denial", rename_all = "snake_case")]
pub enum AdmissionDenial {
    /// The credential's short TTL has lapsed at `now` — it must renew before acting (§15).
    Expired {
        expires_at: LogicalTime,
        now: LogicalTime,
    },
    /// This exact Run was individually revoked (§17) — zero collateral to siblings.
    RunRevoked { run_id: String },
    /// The OBO human's delegated authority was revoked (§17) — every Run carrying them is denied.
    UserRevoked { user_id: String },
    /// An active kill-switch scope halts this Run (§19).
    KillSwitchActive { scope: KillScope },
}

impl fmt::Display for AdmissionDenial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdmissionDenial::Expired { expires_at, now } => {
                write!(f, "credential expired at {expires_at} (now {now})")
            }
            AdmissionDenial::RunRevoked { run_id } => write!(f, "run {run_id:?} is revoked"),
            AdmissionDenial::UserRevoked { user_id } => {
                write!(f, "OBO user {user_id:?} is revoked")
            }
            AdmissionDenial::KillSwitchActive { scope } => {
                write!(f, "an active kill-switch scope {scope:?} halts this Run")
            }
        }
    }
}

/// The outcome of the in-flight admission gate: [`Admit`](AdmissionDecision::Admit) or a named
/// [`AdmissionDenial`]. Serializable for the Event Log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "admission", rename_all = "snake_case")]
pub enum AdmissionDecision {
    Admit,
    Deny(AdmissionDenial),
}

impl AdmissionDecision {
    pub fn is_admitted(&self) -> bool {
        matches!(self, AdmissionDecision::Admit)
    }
    pub fn denial(&self) -> Option<&AdmissionDenial> {
        match self {
            AdmissionDecision::Deny(d) => Some(d),
            AdmissionDecision::Admit => None,
        }
    }
}

/// What the anomaly hook should do when a sample deviates (§20 "graduated response"). Both are
/// honest, design-named responses — the default choke drains the Run at its next TTL without a hard
/// kill; the hard escalation (used by the §4.5 effect-classifier tripwire) revokes the acting Run
/// so even its *in-flight* dispatches are denied immediately.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyResponse {
    /// Flag the Run for the renewal choke only (drain at next TTL).
    RenewalChoke,
    /// Also revoke the Run so in-flight dispatches are denied immediately.
    RevokeRun,
}

// ===========================================================================
// Short-TTL renewal lease — ADR-022 §15
// ===========================================================================

/// Where a credential sits in its short TTL relative to a renew-ahead margin (§15).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseState {
    /// Comfortably within TTL — no renewal needed yet.
    Valid,
    /// Within the renew-ahead margin (or exactly at it) — renew now to avoid a lapse.
    RenewDue,
    /// The TTL has already lapsed — the Run cannot act until it renews.
    Expired,
}

/// The renewal cadence for a long-lived Run (§15): renew when `now` is within `renew_ahead` ticks of
/// expiry, with per-Run [`jittered_renew_at`](RunLease::jittered_renew_at) so thousands of
/// concurrent Program Runs do not all renew on the same tick (the §15/§22-#16 jitter discipline).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunLease {
    /// Ticks before `expires_at` at which renewal becomes due.
    pub renew_ahead: u64,
}

impl RunLease {
    /// A lease that renews `renew_ahead` ticks before expiry.
    pub fn new(renew_ahead: u64) -> Self {
        RunLease { renew_ahead }
    }

    /// Classify a credential's position in its TTL at `now`.
    pub fn state(&self, awc: &AgentWorkloadCredential, now: LogicalTime) -> LeaseState {
        if awc.is_expired_at(now) {
            return LeaseState::Expired;
        }
        if now.tick().saturating_add(self.renew_ahead) >= awc.expires_at.tick() {
            return LeaseState::RenewDue;
        }
        LeaseState::Valid
    }

    /// True iff renewal should happen at or before `now` (due or already expired).
    pub fn is_renew_due(&self, awc: &AgentWorkloadCredential, now: LogicalTime) -> bool {
        !matches!(self.state(awc, now), LeaseState::Valid)
    }

    /// A per-Run jittered target renewal tick inside the renew-ahead window — spreads the renewal of
    /// N concurrent Runs across the margin rather than piling them on the `expires_at - renew_ahead`
    /// boundary. `jitter` is a caller-supplied per-Run value (e.g. a hash of the run_id); the crate
    /// reads no rng, so the schedule is reproducible.
    pub fn jittered_renew_at(&self, awc: &AgentWorkloadCredential, jitter: u64) -> LogicalTime {
        let window = self.renew_ahead.max(1);
        let base = awc.expires_at.tick().saturating_sub(self.renew_ahead);
        LogicalTime(base.saturating_add(jitter % window))
    }
}

/// The outcome of a conditional-continuation renewal step (§15). This is a transient control-flow
/// return value (one per renewal check), never bulk-allocated or stored in a collection, so the
/// size difference between `StillValid` and `Renewed` does not matter — boxing would only add an
/// allocation on the hot renewal path.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Renewal {
    /// The lease is still comfortably valid — no renewal performed; keep using the current AWC.
    StillValid,
    /// A fresh AWC was minted (new `issued_at`/`expires_at`, current signing key).
    Renewed(AgentWorkloadCredential),
}

impl Renewal {
    /// True iff a fresh credential was minted this step.
    pub fn was_renewed(&self) -> bool {
        matches!(self, Renewal::Renewed(_))
    }
    /// The fresh credential, if one was minted.
    pub fn credential(&self) -> Option<&AgentWorkloadCredential> {
        match self {
            Renewal::Renewed(c) => Some(c),
            Renewal::StillValid => None,
        }
    }
}

// ===========================================================================
// Per-dispatch authorization — the single entrypoint the composition drives
// on EVERY capability-bearing dispatch (ADR-022 §15 + §17/§19 combined)
// ===========================================================================

/// Why [`ControlPlane::authorize_dispatch`] refused a capability-bearing dispatch. A dispatch is
/// gated in two stages — a JIT short-TTL renew-and-re-attest (§15) followed by the in-flight
/// admission gate (§17/§19) — so a denial is attributed to whichever stage refused, with the
/// underlying reason named for the Event Log.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchDenial {
    /// The short-TTL renewal this dispatch triggered was refused (revoked / killed / anomaly-choked /
    /// deprecated definition / failed-or-missing attestation) — the Run cannot mint a fresh identity,
    /// so it drains. This is the choke that stops a long-lived Run at its next TTL (§15/§17).
    RenewalRefused(RenewError),
    /// The (current-or-renewed) credential failed the per-dispatch admission gate (§17/§19): an
    /// expired TTL, an individually-revoked Run, a revoked OBO human, or an active kill-switch scope.
    /// This is what makes a mid-run control action deny the *next* dispatch immediately.
    Admission(AdmissionDenial),
}

impl fmt::Display for DispatchDenial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DispatchDenial::RenewalRefused(e) => write!(f, "dispatch denied at renewal: {e}"),
            DispatchDenial::Admission(d) => write!(f, "dispatch denied at admission: {d}"),
        }
    }
}

/// The outcome of the single per-dispatch authorization entrypoint
/// ([`ControlPlane::authorize_dispatch`]). Either the dispatch may
/// [`Proceed`](DispatchOutcome::Proceed) under a named credential, or it is
/// [`Deny`](DispatchOutcome::Deny)ed with the stage + reason.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchOutcome {
    /// The dispatch is authorized. `credential` is the credential to act under for THIS dispatch —
    /// the freshly re-attested one when a JIT renewal fired this tick (`renewed = true`), otherwise
    /// the current one unchanged. The composition threads this credential as the turn's actor of
    /// record so a renewed identity is attributed to the fresh key/attestation, never the lapsed one.
    Proceed {
        credential: AgentWorkloadCredential,
        renewed: bool,
    },
    /// The dispatch is denied — the composition MUST NOT perform the capability-bearing action.
    Deny(DispatchDenial),
}

impl DispatchOutcome {
    /// True iff the dispatch is authorized to proceed.
    pub fn is_proceed(&self) -> bool {
        matches!(self, DispatchOutcome::Proceed { .. })
    }
    /// The credential to act under, if the dispatch is authorized.
    pub fn credential(&self) -> Option<&AgentWorkloadCredential> {
        match self {
            DispatchOutcome::Proceed { credential, .. } => Some(credential),
            DispatchOutcome::Deny(_) => None,
        }
    }
    /// True iff a JIT renewal minted a fresh credential for this dispatch.
    pub fn was_renewed(&self) -> bool {
        matches!(self, DispatchOutcome::Proceed { renewed: true, .. })
    }
    /// The denial reason, if the dispatch was refused.
    pub fn denial(&self) -> Option<&DispatchDenial> {
        match self {
            DispatchOutcome::Deny(d) => Some(d),
            DispatchOutcome::Proceed { .. } => None,
        }
    }
}

// ===========================================================================
// The shared control plane — ADR-022 §17/§19/§20
// ===========================================================================

/// The single, **shared** live control surface for the whole non-human workforce. The runtime
/// builds ONE of these at its composition root and consults it for every Run — this is what makes a
/// revocation, a kill-switch pull, or an anomaly flag actually reach the Runs already in flight
/// (the previous per-Run, composition-local authorities each carried their *own* empty registries,
/// so a control action reached nothing running).
///
/// It composes the three deny-state facets from [`super::authority`] and exposes:
/// * [`admit`](ControlPlane::admit) — the per-dispatch in-flight gate (§17/§19);
/// * [`revoke_run`](ControlPlane::revoke_run) / [`revoke_user`](ControlPlane::revoke_user) /
///   [`pull_kill_switch`](ControlPlane::pull_kill_switch) — the control actions;
/// * [`observe`](ControlPlane::observe) — the anomaly hook (§20);
/// * [`renew_if_due`](ControlPlane::renew_if_due) — the short-TTL renewal driver (§15) that gates
///   continuation on *this shared* deny-state before delegating the mint to the [`IdentityAuthority`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlPlane {
    revocations: RevocationRegistry,
    kill_switch: KillSwitch,
    anomaly: AnomalyMonitor,
}

impl ControlPlane {
    pub fn new() -> Self {
        Self::default()
    }

    // ---- accessors (for advanced/composed use) ---------------------------
    pub fn revocations(&self) -> &RevocationRegistry {
        &self.revocations
    }
    pub fn revocations_mut(&mut self) -> &mut RevocationRegistry {
        &mut self.revocations
    }
    pub fn kill_switch(&self) -> &KillSwitch {
        &self.kill_switch
    }
    pub fn kill_switch_mut(&mut self) -> &mut KillSwitch {
        &mut self.kill_switch
    }
    pub fn anomaly(&self) -> &AnomalyMonitor {
        &self.anomaly
    }
    pub fn anomaly_mut(&mut self) -> &mut AnomalyMonitor {
        &mut self.anomaly
    }

    // ---- control actions -------------------------------------------------

    /// Revoke exactly one Run (§17) — denied at the next dispatch *and* renewal, zero collateral.
    pub fn revoke_run(&mut self, run_id: impl Into<String>) {
        self.revocations.revoke_run(run_id);
    }

    /// Revoke an OBO human's delegated authority (§17) — every Run carrying them is denied.
    pub fn revoke_user(&mut self, user_id: impl Into<String>) {
        self.revocations.revoke_user(user_id);
    }

    /// Pull a kill-switch scope with the §19 authority gate (`can_approve` + `ad_level <= 3`) and
    /// record the audited pull. Returns the [`KillSwitchAudit`] for the caller to log, or the
    /// authority error if the puller is not permitted.
    pub fn pull_kill_switch(
        &mut self,
        scope: KillScope,
        puller_id: impl Into<String>,
        ad_level: u8,
        can_approve: bool,
        now: LogicalTime,
    ) -> Result<KillSwitchAudit, KillSwitchAuthError> {
        self.kill_switch
            .pull_authorized(scope, puller_id, ad_level, can_approve, now)
    }

    /// Release a previously-engaged kill-switch scope.
    pub fn release_kill_switch(&mut self, scope: &KillScope) {
        self.kill_switch.release(scope);
    }

    /// The immutable audit trail of every authorized kill-switch pull (§19).
    pub fn kill_switch_audit(&self) -> &[KillSwitchAudit] {
        self.kill_switch.audit_log()
    }

    // ---- anomaly hook (§20) ----------------------------------------------

    /// Score an activity sample against its role baseline and, per `response`, either flag the Run
    /// for the renewal choke (drain at next TTL) or additionally revoke it (deny in-flight now).
    /// Returns the assessment for the caller's evidence trail (§20 graduated response). This is the
    /// hook the runtime's UEBA telemetry feeds each observation window into.
    pub fn observe(
        &mut self,
        baseline: &BehavioralBaseline,
        sample: &crate::authority::ActivitySample,
        response: AnomalyResponse,
    ) -> AnomalyAssessment {
        let assessment = self.anomaly.observe(baseline, sample);
        if assessment.is_anomalous() && response == AnomalyResponse::RevokeRun {
            self.revocations.revoke_run(sample.run_id.clone());
        }
        assessment
    }

    // ---- in-flight admission gate (§17/§19) ------------------------------

    /// The **per-dispatch, in-flight** admission gate: may this already-issued credential act at
    /// `now`? Denies (in order) an expired TTL, an individually-revoked Run, a revoked OBO human, an
    /// active kill-switch scope, or an anomaly-flagged Run — each with the reason named. This is the
    /// check the runtime performs before every capability-bearing dispatch, so a control action on
    /// the shared surface stops in-flight work immediately rather than only at the next renewal.
    pub fn admit(&self, awc: &AgentWorkloadCredential, now: LogicalTime) -> AdmissionDecision {
        if awc.is_expired_at(now) {
            return AdmissionDecision::Deny(AdmissionDenial::Expired {
                expires_at: awc.expires_at,
                now,
            });
        }
        if self.revocations.is_run_revoked(&awc.run_id) {
            return AdmissionDecision::Deny(AdmissionDenial::RunRevoked {
                run_id: awc.run_id.clone(),
            });
        }
        if self.revocations.is_user_revoked(&awc.obo_user_id) {
            return AdmissionDecision::Deny(AdmissionDenial::UserRevoked {
                user_id: awc.obo_user_id.clone(),
            });
        }
        if let Some(scope) = self.kill_switch.blocking_scope(awc) {
            return AdmissionDecision::Deny(AdmissionDenial::KillSwitchActive {
                scope: scope.clone(),
            });
        }
        // NOTE: an anomaly *flag* is deliberately NOT an in-flight denial — the §20 graduated
        // response is a renewal *choke* (drain the Run at its next TTL without a hard kill), enforced
        // in [`renew_if_due`]. A flag that must stop in-flight work escalates to a revocation via
        // [`observe`] with [`AnomalyResponse::RevokeRun`], which is caught by the run-revoked arm above.
        AdmissionDecision::Admit
    }

    // ---- JIT initial issuance (§13 attest-before-issue + §17/§19 shared gate) ----

    /// **The entrypoint the composition drives to mint a Run's FIRST short-TTL credential**, JIT at
    /// Run start (§15 "no standing credentials"). It gates the mint on *this shared* deny-state
    /// **before** delegating the attested, per-Run, TTL-bound mint to the [`IdentityAuthority`] —
    /// the issuance-side symmetry of [`renew_if_due`](ControlPlane::renew_if_due).
    ///
    /// # The gap this closes
    ///
    /// `IdentityAuthority::issue` re-checks revocation / kill-switch against the AIA's **own**
    /// registries. In the composition model the AIA is a stateless minting service and the live
    /// deny-state lives on the ONE shared [`ControlPlane`] the runtime holds at its composition root
    /// (the AIA's local registries are empty). So an en-masse kill-switch (§19 "big red button") or a
    /// revoked OBO human (§17) pulled on the shared plane would correctly stop every *renewal* — yet a
    /// brand-new Run could still slip through `issue` and obtain a fresh credential, because that path
    /// consulted the empty local sets, not the shared one. `issue_jit` re-checks the shared plane
    /// first, so the same control action that drains running Runs also **refuses new ones** — a
    /// workforce halt is total, not "everything already running plus whatever starts next".
    ///
    /// Order (fail-closed, most-fundamental first): a Run individually revoked, its OBO human
    /// revoked, or a §19 kill-switch scope matching the request's facets each deny issuance with a
    /// named [`IssueError`]; otherwise attestation-before-issuance, definition validity (fail-closed
    /// on a stale projection), per-Run uniqueness, and the short-TTL mint are the AIA's job.
    pub fn issue_jit<V: AttestationVerifier>(
        &self,
        aia: &mut IdentityAuthority<V>,
        req: &IssueRequest,
        quote: &AttestationQuote,
        now: LogicalTime,
    ) -> Result<AgentWorkloadCredential, IssueError> {
        // Re-check the SHARED deny-state before minting a NEW Run's identity (not the per-Run,
        // composition-local empty registries the AIA carries).
        if self.revocations.is_run_revoked(&req.run_id) {
            return Err(IssueError::Revoked(format!("run {}", req.run_id)));
        }
        if self.revocations.is_user_revoked(&req.obo_user_id) {
            return Err(IssueError::Revoked(format!("user {}", req.obo_user_id)));
        }
        if self
            .kill_switch
            .blocking_scope_for(
                &req.run_id,
                &req.def_ref(),
                req.obo_department.as_deref(),
                &req.data_class,
            )
            .is_some()
        {
            return Err(IssueError::KillSwitchActive);
        }
        // Attestation + definition-validity + per-Run uniqueness + TTL/key mint stay the AIA's job.
        aia.issue(req, quote, now)
    }

    // ---- short-TTL renewal driver (§15) ----------------------------------

    /// **Conditional continuation** for a long-lived Run (§15): if the `lease` says the credential
    /// is still comfortably valid, do nothing ([`Renewal::StillValid`]); otherwise re-check this
    /// **shared** deny-state (revocation / kill-switch / anomaly) and, if it still permits, delegate
    /// the attestation + definition-validity + TTL mint to `aia` to produce a fresh AWC.
    ///
    /// The shared re-check is the point: a kill-switch pulled or a Run revoked on *this* control
    /// plane denies the renewal even though the per-Run `aia` may carry empty local registries — so
    /// a running Program Run drains within one TTL by ceasing to renew. For a TEE Run, a fresh
    /// `quote` must be supplied (the AIA enforces it). This is the single entrypoint a supervisor
    /// loop calls at each checkpoint.
    pub fn renew_if_due<V: AttestationVerifier>(
        &self,
        aia: &IdentityAuthority<V>,
        awc: &AgentWorkloadCredential,
        lease: &RunLease,
        quote: Option<&AttestationQuote>,
        now: LogicalTime,
    ) -> Result<Renewal, RenewError> {
        if matches!(lease.state(awc, now), LeaseState::Valid) {
            return Ok(Renewal::StillValid);
        }
        // Re-check the SHARED deny-state before continuing (not the per-Run empty local one).
        if self.revocations.is_run_revoked(&awc.run_id) {
            return Err(RenewError::Revoked(format!("run {}", awc.run_id)));
        }
        if self.revocations.is_user_revoked(&awc.obo_user_id) {
            return Err(RenewError::Revoked(format!("user {}", awc.obo_user_id)));
        }
        if !self.kill_switch.permits(awc) {
            return Err(RenewError::KillSwitchActive);
        }
        if self.anomaly.is_flagged(&awc.run_id) {
            return Err(RenewError::AnomalyChoke(awc.run_id.clone()));
        }
        // Delegate the attestation/definition/TTL/key mint to the issuing authority.
        aia.renew(awc, quote, now).map(Renewal::Renewed)
    }

    // ---- the single per-dispatch authorization entrypoint (§15 + §17/§19) --

    /// **The one entrypoint the composition drives before EVERY capability-bearing dispatch.** It
    /// fuses the two enterprise seams that were previously only reachable as separate primitives —
    /// the short-TTL JIT [`renew_if_due`](ControlPlane::renew_if_due) (§15) and the in-flight
    /// [`admit`](ControlPlane::admit) gate (§17/§19) — into a single, deterministic decision so the
    /// composition never has to remember to call both (and never dispatches on a lapsing credential
    /// or past a mid-run control action):
    ///
    /// 1. **JIT renew-and-re-attest.** If the `lease` says the short TTL is within its renew-ahead
    ///    margin (or lapsed), a fresh credential is minted — but only after re-checking *this shared*
    ///    deny-state, so a revocation / kill-switch / anomaly choke refuses the renewal
    ///    ([`DispatchDenial::RenewalRefused`]) and the Run drains. A TEE Run must supply a fresh
    ///    `quote`.
    /// 2. **Per-dispatch admission.** The credential to act under (the freshly-renewed one, or the
    ///    current one if renewal was not yet due) is then run through the in-flight admission gate.
    ///    An expired TTL, an individually-revoked Run, a revoked OBO human, or an active kill-switch
    ///    scope denies the dispatch ([`DispatchDenial::Admission`]) — *immediately*, at the very next
    ///    dispatch, not merely at the next renewal.
    ///
    /// Because both stages consult the **shared** [`ControlPlane`] the runtime holds once at its
    /// composition root, a kill-switch pulled or a Run revoked mid-Run reaches the Run already in
    /// flight: its next `authorize_dispatch` is denied (via stage 2 when renewal is not yet due, or
    /// via stage 1 when it is). On success the returned [`DispatchOutcome::Proceed`] carries the exact
    /// credential to attribute the action to — the fresh one when a renewal fired this tick — so the
    /// actor of record is always the currently-valid identity, never a lapsed token.
    ///
    /// This is *not* a clearance/turn denial: a data-class clearance mismatch is a retrieval
    /// read-filter elsewhere, never an admission refusal here (compliance redacts-and-proceeds).
    pub fn authorize_dispatch<V: AttestationVerifier>(
        &self,
        aia: &IdentityAuthority<V>,
        awc: &AgentWorkloadCredential,
        lease: &RunLease,
        quote: Option<&AttestationQuote>,
        now: LogicalTime,
    ) -> DispatchOutcome {
        // Stage 1: JIT renew-and-re-attest (gated on the shared deny-state inside renew_if_due).
        let (effective, renewed) = match self.renew_if_due(aia, awc, lease, quote, now) {
            Ok(Renewal::StillValid) => (awc.clone(), false),
            Ok(Renewal::Renewed(fresh)) => (fresh, true),
            Err(e) => return DispatchOutcome::Deny(DispatchDenial::RenewalRefused(e)),
        };
        // Stage 2: in-flight admission on the credential this dispatch will actually act under.
        match self.admit(&effective, now) {
            AdmissionDecision::Admit => DispatchOutcome::Proceed {
                credential: effective,
                renewed,
            },
            AdmissionDecision::Deny(d) => DispatchOutcome::Deny(DispatchDenial::Admission(d)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::{
        ActivitySample, AttestationQuote, ControlPlaneProjection, IdentityAuthority, IssueRequest,
        ReferenceValueVerifier,
    };
    use ainxt_types::DataClass;

    fn aia() -> IdentityAuthority<ReferenceValueVerifier> {
        let verifier = ReferenceValueVerifier::new().with_measurement("m-ok");
        let projection = ControlPlaneProjection::new(
            ["def:role/coder@v3".to_string()],
            LogicalTime(0),
            "commit-shared",
        );
        // Short TTL = 10 ticks; freshness never lapses in these tests.
        IdentityAuthority::new(verifier, projection, 10, 1_000_000, "key-v1")
    }

    fn req(run_id: &str, user: &str) -> IssueRequest {
        IssueRequest {
            def_kind: "role".into(),
            def_id: "coder".into(),
            def_version: "v3".into(),
            run_id: run_id.into(),
            data_class: DataClass::Internal,
            requires_tee: false,
            obo_user_id: user.into(),
            obo_department: Some("payments-eng".into()),
            obo_ad_level: Some(4),
            obo_can_approve: false,
        }
    }

    fn quote() -> AttestationQuote {
        AttestationQuote {
            def_content_hash: "h".into(),
            control_commit_sha: "commit-shared".into(),
            measurement: "m-ok".into(),
            tee_quote: None,
        }
    }

    fn issue(
        aia: &mut IdentityAuthority<ReferenceValueVerifier>,
        run: &str,
        user: &str,
    ) -> AgentWorkloadCredential {
        aia.issue(&req(run, user), &quote(), LogicalTime(1))
            .unwrap()
    }

    // R3: one SHARED control plane gates in-flight dispatch across independently-minted Runs, and a
    // control action (revoke / kill-switch / anomaly) reaches the Runs already in flight — the thing
    // per-Run composition-local empty registries could never do.
    #[test]
    fn r3_shared_control_surface_in_flight_and_kill_switch() {
        let mut aia = aia();
        // Two independently-minted Runs (as the runtime mints them per-Run today).
        let r1 = issue(&mut aia, "run-1", "u-alice");
        let r2 = issue(&mut aia, "run-2", "u-bob");

        // One shared control plane the runtime holds once.
        let mut cp = ControlPlane::new();

        // Both admit while healthy and within TTL.
        assert!(cp.admit(&r1, LogicalTime(2)).is_admitted());
        assert!(cp.admit(&r2, LogicalTime(2)).is_admitted());

        // In-flight individual revocation: run-1 is denied its NEXT dispatch immediately; run-2 is
        // untouched (zero collateral) — the whole point of a shared surface.
        cp.revoke_run("run-1");
        assert_eq!(
            cp.admit(&r1, LogicalTime(2)),
            AdmissionDecision::Deny(AdmissionDenial::RunRevoked {
                run_id: "run-1".into()
            })
        );
        assert!(
            cp.admit(&r2, LogicalTime(2)).is_admitted(),
            "sibling unaffected"
        );

        // Authorized scoped kill-switch halts run-2's data-class in flight; the pull is authority-
        // gated and audited (§19).
        let audit = cp
            .pull_kill_switch(
                KillScope::Department("payments-eng".into()),
                "u-exec",
                2,
                true,
                LogicalTime(3),
            )
            .expect("senior approver may pull");
        assert_eq!(audit.puller, "u-exec");
        assert_eq!(cp.kill_switch_audit().len(), 1);
        assert!(matches!(
            cp.admit(&r2, LogicalTime(3)),
            AdmissionDecision::Deny(AdmissionDenial::KillSwitchActive { .. })
        ));
        // A junior / non-approver cannot pull.
        assert!(cp
            .pull_kill_switch(KillScope::Workforce, "u-junior", 6, true, LogicalTime(3))
            .is_err());

        // Expiry is an in-flight denial too: past its TTL, a credential cannot act until renewed.
        assert_eq!(
            cp.admit(&r2, LogicalTime(999)),
            AdmissionDecision::Deny(AdmissionDenial::Expired {
                expires_at: r2.expires_at,
                now: LogicalTime(999)
            })
        );
    }

    // R3: the short-TTL JIT renewal driver — the lease decides WHEN, and renew_if_due performs
    // conditional continuation gated on the SHARED deny-state.
    #[test]
    fn r3_jit_renewal_driver_conditional_continuation() {
        let mut aia = aia();
        let awc = issue(&mut aia, "run-long", "u-alice"); // issued t=1, TTL 10 -> expires t=11
        let cp = ControlPlane::new();
        let lease = RunLease::new(3); // renew when within 3 ticks of expiry

        // Comfortably valid mid-life: the driver does nothing.
        assert_eq!(lease.state(&awc, LogicalTime(5)), LeaseState::Valid);
        assert_eq!(
            cp.renew_if_due(&aia, &awc, &lease, None, LogicalTime(5))
                .unwrap(),
            Renewal::StillValid
        );

        // Within the renew-ahead margin (t=9, expiry 11, margin 3): renewal is due and performed.
        assert_eq!(lease.state(&awc, LogicalTime(9)), LeaseState::RenewDue);
        let renewal = cp
            .renew_if_due(&aia, &awc, &lease, None, LogicalTime(9))
            .unwrap();
        assert!(renewal.was_renewed());
        let fresh = renewal.credential().unwrap();
        assert_eq!(fresh.issued_at, LogicalTime(9));
        assert_eq!(
            fresh.expires_at,
            LogicalTime(19),
            "fresh short TTL past now"
        );
        assert_eq!(fresh.run_id, awc.run_id, "identity facets carried over");

        // Jitter spreads renewals across the margin window rather than piling on expiry-3.
        let at = lease.jittered_renew_at(&awc, 2);
        assert!(
            (8..=10).contains(&at.tick()),
            "jittered inside the renew-ahead window: {at}"
        );
    }

    // R3: a control action on the SHARED plane drains a running long Run within one TTL by choking
    // its renewal — even though the per-Run `aia` carries empty local registries.
    #[test]
    fn r3_shared_control_drains_long_run_via_renewal_choke() {
        let mut aia = aia();
        let awc = issue(&mut aia, "run-prog", "u-alice");
        let mut cp = ControlPlane::new();
        let lease = RunLease::new(3);

        // First renewal (due) succeeds against a clean shared plane.
        let r1 = cp
            .renew_if_due(&aia, &awc, &lease, None, LogicalTime(9))
            .unwrap();
        let awc2 = r1.credential().unwrap().clone();

        // A UEBA observation deviates -> the anomaly hook flags AND (RevokeRun policy) revokes the
        // Run on the shared plane, so it is denied both in-flight and at renewal.
        let baseline =
            BehavioralBaseline::new("def:role/coder@v3").with_capabilities(["repo:read"]);
        let sample = ActivitySample {
            run_id: "run-prog".into(),
            def_ref: "def:role/coder@v3".into(),
            capabilities_used: ["settlement:release".to_string()].into_iter().collect(),
            ..Default::default()
        };
        let assessment = cp.observe(&baseline, &sample, AnomalyResponse::RevokeRun);
        assert!(assessment.is_anomalous());

        // In-flight: denied immediately (revoked by the hook).
        assert!(matches!(
            cp.admit(&awc2, LogicalTime(12)),
            AdmissionDecision::Deny(AdmissionDenial::RunRevoked { .. })
        ));
        // Renewal: the shared deny-state chokes continuation -> the Run drains at its next TTL.
        assert_eq!(
            cp.renew_if_due(&aia, &awc2, &lease, None, LogicalTime(17))
                .unwrap_err(),
            RenewError::Revoked("run run-prog".into())
        );

        // And a RenewalChoke-only observation on a fresh plane flags without revoking (in-flight
        // still admitted until TTL; only renewal is choked) — the graduated §20 response.
        let mut cp2 = ControlPlane::new();
        cp2.observe(&baseline, &sample, AnomalyResponse::RenewalChoke);
        assert!(
            cp2.admit(&awc2, LogicalTime(12)).is_admitted(),
            "in-flight not hard-killed"
        );
        assert_eq!(
            cp2.renew_if_due(&aia, &awc2, &lease, None, LogicalTime(17))
                .unwrap_err(),
            RenewError::AnomalyChoke("run-prog".into())
        );
    }
}
