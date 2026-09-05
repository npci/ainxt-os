// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Agent Identity Authority (AIA) — attested, JIT, short-TTL agent workload credentials.
//!
//! Design: `docs/architecture/AGENT_IDENTITY_AND_PAYMENT_BOUNDARY.md` — ADR-022 §12 (composite
//! per-Run identity), §13 (attestation-before-issuance), §15 (no standing credentials; short-TTL
//! renew-and-re-attest; fail-closed-on-stale projection), §17 (individual + en-masse revocation),
//! §19 (workforce kill-switch hierarchy), §20 (anomaly renewal-choke), §16 (crypto-agility key
//! rotation).
//!
//! # What this module guarantees
//!
//! Every agent action is performed under an [`AgentWorkloadCredential`] (AWC) that is:
//! * **per-Run, never shared** — two Runs of the same role get distinct `run_id`s and distinct
//!   credentials, so revoking one touches exactly one Run;
//! * **issued only after attestation** — [`IdentityAuthority::issue`] refuses without a passing
//!   [`AttestationQuote`] verified by an [`AttestationVerifier`] against a reference-value
//!   allow-list (the stand-in for external TEE remote attestation, §13);
//! * **short-TTL and JIT** — an AWC carries `issued_at`/`expires_at`; there is no standing token.
//!   Long-lived Program Runs are a *chain* of renewals, each of which **re-checks** definition
//!   validity, the kill-switch, revocation, anomaly state, and (for TEE Runs) a fresh attestation
//!   ([`IdentityAuthority::renew`], §15) — conditional continuation, not a standing grant;
//! * **individually and en-masse revocable** — a single Run, an OBO human's whole delegated
//!   authority, a deprecated definition, or a scoped/whole-workforce kill-switch each deny the
//!   *next* issuance/renewal so the affected actors **drain within one TTL by expiry alone**
//!   (§17/§19), even if an in-flight deny-push is dropped.
//!
//! # Determinism
//!
//! No clock, no rng, no I/O. Logical time is a caller-supplied [`crate::LogicalTime`]; the `run_id`
//! and `key_id` are supplied; attestation quotes and reference values are injected. The same inputs
//! always produce the same credential and the same allow/deny decision — every property below is a
//! unit-testable assertion, not a hope.
//!
//! # What is deliberately a seam (infra, not faked here)
//!
//! Real hardware/TEE remote attestation, the transparency log's cryptographic inclusion proofs,
//! the network deny-push transport for revocation, and learned UEBA anomaly *baselines* are I/O /
//! infra / data concerns. This module owns their pure decision cores behind traits/sets: the
//! [`AttestationVerifier`] trait (reference-value impl provided), the [`RevocationRegistry`], the
//! [`KillSwitch`], the [`AnomalyMonitor`] renewal-choke, and the fail-closed
//! [`ControlPlaneProjection`]. Wiring these to real infra is the runtime's job, not this crate's.

use crate::LogicalTime;
use ainxt_types::DataClass;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

// ===========================================================================
// The composite Agent Workload Credential (AWC) — ADR-022 §12
// ===========================================================================

/// A short-TTL, per-Run Agent Workload Credential (ADR-022 §12): the composite of three facets —
/// *definition* (which git-rooted role), *workload* (which Run + validity window), and *OBO* (on
/// whose behalf) — plus the attestation and crypto-agility bindings that make it externally
/// verifiable (§13) and rotatable (§16). Constructed **only** by [`IdentityAuthority::issue`] /
/// [`IdentityAuthority::renew`] after their checks pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentWorkloadCredential {
    // ---- definition facet (git control plane, ADR-026) --------------------
    /// e.g. `"role"`, `"agent"`.
    pub def_kind: String,
    /// e.g. `"coder"`.
    pub def_id: String,
    /// e.g. `"v3"`.
    pub def_version: String,
    /// The attested content hash of the definition as approved in git (§13 — an attested fact).
    pub def_content_hash: String,
    /// The attested control-plane commit SHA the workload loaded (§13).
    pub control_commit_sha: String,
    // ---- workload facet ---------------------------------------------------
    /// The ephemeral per-Run instance id — unique per Run (not a shared token).
    pub run_id: String,
    /// Logical tick the credential was issued at.
    pub issued_at: LogicalTime,
    /// Logical tick the credential expires at (inclusive) — a short TTL past `issued_at`.
    pub expires_at: LogicalTime,
    /// The sensitivity class this Run operates on — drives the data-class kill-switch scope (§19)
    /// and whether renewal demands a fresh TEE attestation (§15).
    pub data_class: DataClass,
    /// True if this Run executes in a confidential-computing enclave, so every renewal must
    /// present a fresh attestation quote (§15).
    pub requires_tee: bool,
    // ---- OBO delegation facet (ADR-022 §12, TOOLING §1.6) -----------------
    pub obo_user_id: String,
    pub obo_department: Option<String>,
    pub obo_ad_level: Option<u8>,
    pub obo_can_approve: bool,
    // ---- attestation + crypto-agility -------------------------------------
    /// A reference to the attestation evidence this credential was minted against (§13).
    pub attestation_ref: String,
    /// The versioned signing-key id (ADR-023 crypto-agility, §16). Rotating the AIA key changes
    /// this for *new* credentials; existing ones keep theirs and verify-then-expire.
    pub key_id: String,
}

impl AgentWorkloadCredential {
    /// The stable definition reference used by the control-plane projection and the role-scoped
    /// kill-switch: `def:<kind>/<id>@<version>`.
    pub fn def_ref(&self) -> String {
        format!("def:{}/{}@{}", self.def_kind, self.def_id, self.def_version)
    }

    /// The clean-room trust-domain identity URI recorded as the actor of record (§14).
    /// The trust domain segment is configurable via the `AINXT_TRUST_DOMAIN` environment variable
    /// (default: `"ainxt"`). Set it to your organisation's identifier at deployment time.
    pub fn uri(&self) -> String {
        let trust_domain =
            std::env::var("AINXT_TRUST_DOMAIN").unwrap_or_else(|_| "ainxt".to_string());
        format!(
            "ainxt-id://{}/agent/{}/{}/{}/run/{}",
            trust_domain, self.def_kind, self.def_id, self.def_version, self.run_id
        )
    }

    /// True once `now` has moved strictly past `expires_at` (valid *through* expiry, inclusive).
    pub fn is_expired_at(&self, now: LogicalTime) -> bool {
        now > self.expires_at
    }

    /// True while the credential is still within its TTL at `now`.
    pub fn is_valid_at(&self, now: LogicalTime) -> bool {
        !self.is_expired_at(now)
    }
}

impl fmt::Display for AgentWorkloadCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} (obo {}, key {})",
            self.uri(),
            self.obo_user_id,
            self.key_id
        )
    }
}

/// The composite **actor of record** the Event Log records for every agent action (ADR-022 §14):
/// *which Run of which git-SHA'd definition, on whose behalf, attested how, under which key*. This
/// is what the runtime writes into `ainxt-eventlog` as the `actor` field — never a service account,
/// never a bare role name — completing ADR-026 §9's two-trail (authoring-in-git / execution-in-log)
/// audit. It is a projection of the AWC's immutable, content-addressed facets (the credential
/// *material* stays data-plane, §21; this *reference* is court-grade and reconstructable).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActorRecord {
    pub actor_uri: String,
    pub def_ref: String,
    pub run_id: String,
    pub obo_user_id: String,
    pub control_commit_sha: String,
    pub attestation_ref: String,
    pub key_id: String,
}

impl fmt::Display for ActorRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} (obo {}, def@{}, attest {})",
            self.actor_uri, self.obo_user_id, self.control_commit_sha, self.attestation_ref
        )
    }
}

impl AgentWorkloadCredential {
    /// The composite [`ActorRecord`] for the Event Log (§14) — the entrypoint the agent loop calls
    /// to obtain the actor to attribute every action to.
    pub fn actor_of_record(&self) -> ActorRecord {
        ActorRecord {
            actor_uri: self.uri(),
            def_ref: self.def_ref(),
            run_id: self.run_id.clone(),
            obo_user_id: self.obo_user_id.clone(),
            control_commit_sha: self.control_commit_sha.clone(),
            attestation_ref: self.attestation_ref.clone(),
            key_id: self.key_id.clone(),
        }
    }

    /// A compact single-string actor label for `ainxt-eventlog`'s `&str` actor field (§14). Carries
    /// the full composite so "who did this" is answerable from one log line.
    pub fn actor_label(&self) -> String {
        format!(
            "{}|obo={}|commit={}|key={}",
            self.uri(),
            self.obo_user_id,
            self.control_commit_sha,
            self.key_id
        )
    }
}

// ===========================================================================
// Attestation — ADR-022 §13
// ===========================================================================

/// The evidence a requesting workload presents to prove *what it is* before an AWC is minted
/// (§13). `measurement` is the binary/image measurement; `tee_quote` is present for
/// confidential-computing Runs and is the externally-verifiable remote-attestation quote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationQuote {
    pub def_content_hash: String,
    pub control_commit_sha: String,
    /// The workload/image measurement — matched against reference values.
    pub measurement: String,
    /// A TEE remote-attestation quote reference, present only for enclave Runs.
    pub tee_quote: Option<String>,
}

/// Why attestation failed (§13). Fail-closed: any of these refuses issuance/renewal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationError {
    /// The presented measurement is not in the reference-value allow-list.
    UnknownMeasurement(String),
    /// A TEE Run presented a quote that is not a trusted reference quote.
    UntrustedTeeQuote(String),
    /// A TEE Run presented no quote at all.
    TeeQuoteRequired,
}

impl fmt::Display for AttestationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AttestationError::UnknownMeasurement(m) => {
                write!(f, "measurement {m:?} is not an accepted reference value")
            }
            AttestationError::UntrustedTeeQuote(q) => {
                write!(f, "TEE quote {q:?} is not a trusted reference quote")
            }
            AttestationError::TeeQuoteRequired => {
                write!(
                    f,
                    "a TEE Run requires a fresh attestation quote; none was presented"
                )
            }
        }
    }
}

impl std::error::Error for AttestationError {}

/// Verifies attestation before the AIA issues/renews a credential (§13). The trait is the seam a
/// real TEE/remote-attestation verifier plugs into; [`ReferenceValueVerifier`] is a real,
/// deterministic reference-value implementation used offline and in tests.
pub trait AttestationVerifier {
    /// `Ok(())` iff the quote is acceptable. If `requires_tee`, a trusted `tee_quote` is mandatory.
    fn verify(&self, quote: &AttestationQuote, requires_tee: bool) -> Result<(), AttestationError>;
}

/// A deterministic attestation verifier that checks the presented measurement (and, for TEE Runs,
/// the quote) against injected **reference-value allow-lists** — the pure decision core of §13's
/// "issue only to attested, unmodified, approved code", externally checkable because the accepted
/// values are explicit data, not a trust-me assertion.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferenceValueVerifier {
    accepted_measurements: BTreeSet<String>,
    accepted_tee_quotes: BTreeSet<String>,
}

impl ReferenceValueVerifier {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an accepted workload measurement (a reference value).
    pub fn with_measurement(mut self, m: impl Into<String>) -> Self {
        self.accepted_measurements.insert(m.into());
        self
    }

    /// Add an accepted TEE quote reference.
    pub fn with_tee_quote(mut self, q: impl Into<String>) -> Self {
        self.accepted_tee_quotes.insert(q.into());
        self
    }
}

impl AttestationVerifier for ReferenceValueVerifier {
    fn verify(&self, quote: &AttestationQuote, requires_tee: bool) -> Result<(), AttestationError> {
        if !self.accepted_measurements.contains(&quote.measurement) {
            return Err(AttestationError::UnknownMeasurement(
                quote.measurement.clone(),
            ));
        }
        if requires_tee {
            match &quote.tee_quote {
                Some(q) if self.accepted_tee_quotes.contains(q) => {}
                Some(q) => return Err(AttestationError::UntrustedTeeQuote(q.clone())),
                None => return Err(AttestationError::TeeQuoteRequired),
            }
        }
        Ok(())
    }
}

// ===========================================================================
// External TEE remote attestation — ADR-022 §13 / ADR-021 (hardware root-of-trust)
// ===========================================================================

/// A **structured** TEE remote-attestation quote (ADR-021 / §13) — the externally-verifiable evidence
/// a confidential-computing Run presents. Unlike a bare reference string, a real hardware quote
/// *binds* four facts together under the hardware root-of-trust: the code **measurement**, the
/// **definition content hash** the enclave loaded, a per-issuance freshness **nonce** (the AIA's
/// challenge, echoed back — anti-replay), and the **attestation-root** version that signed it. This
/// is the shape an auditor OUTSIDE the runtime checks: the load-bearing "external" of §13.
///
/// The *cryptographic* verification of the quote's hardware signature is TEE infra behind
/// [`AttestationVerifier`]; this struct + [`ExternalAttestationVerifier`] implement the pure
/// *binding/freshness/reference-value* verification an auditor performs deterministically offline, so
/// "the auditor can independently verify the code measurement" is a real, tested property, not a
/// promise. Swapping the offline reference check for a real hardware-quote signature check needs no
/// algorithm change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeeQuoteClaims {
    /// The workload/image measurement sealed into the hardware quote (what the running code IS).
    pub measurement: String,
    /// The attested definition content hash the enclave loaded — binds code identity to the def.
    pub def_content_hash: String,
    /// The AIA's per-issuance challenge nonce, echoed into the quote (anti-replay / freshness).
    pub nonce: String,
    /// The attestation-root / key version that signed the quote (ADR-021 root, rotatable §16).
    pub attestation_root: String,
}

/// Why an external TEE-quote verification failed (§13 / ADR-021). Fail-closed: any arm denies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TeeVerifyError {
    /// The quote was signed by an attestation root not in the auditor's trusted set.
    UntrustedRoot(String),
    /// The measurement in the quote is not an accepted reference value.
    UnknownMeasurement(String),
    /// The measurement in the quote does not match the code identity the caller expected.
    MeasurementMismatch { expected: String, in_quote: String },
    /// The definition content hash bound in the quote does not match the definition being issued.
    DefHashMismatch { expected: String, in_quote: String },
    /// The quote's nonce does not match the challenge the AIA issued — a stale / replayed quote.
    StaleNonce { expected: String, in_quote: String },
}

impl fmt::Display for TeeVerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TeeVerifyError::UntrustedRoot(r) => write!(f, "TEE quote signed by untrusted root {r:?}"),
            TeeVerifyError::UnknownMeasurement(m) => {
                write!(f, "TEE quote measurement {m:?} is not an accepted reference value")
            }
            TeeVerifyError::MeasurementMismatch { expected, in_quote } => write!(
                f,
                "TEE quote measurement {in_quote:?} does not match expected code identity {expected:?}"
            ),
            TeeVerifyError::DefHashMismatch { expected, in_quote } => write!(
                f,
                "TEE quote def-hash {in_quote:?} does not match definition {expected:?}"
            ),
            TeeVerifyError::StaleNonce { expected, in_quote } => {
                write!(f, "TEE quote nonce {in_quote:?} does not match challenge {expected:?} (replay)")
            }
        }
    }
}

impl std::error::Error for TeeVerifyError {}

/// The measurement an external verification **independently confirmed** — the court-grade fact §13
/// promises: *this code, this definition, freshly attested by a trusted root*. Only constructed by a
/// passing [`ExternalAttestationVerifier::verify_external`], so its existence is the proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedMeasurement {
    pub measurement: String,
    pub def_content_hash: String,
    pub attestation_root: String,
}

/// The **external** attestation verifier (§13 / ADR-021): the deterministic reference-value +
/// binding + freshness check a party *outside* the runtime performs on a [`TeeQuoteClaims`], trusting
/// only its own published set of accepted attestation roots and reference measurements — never the
/// runtime's say-so. This is the pure decision core of "external cryptographic attestation"; the
/// hardware quote-signature check is the TEE infra that sits in front of it behind
/// [`AttestationVerifier`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalAttestationVerifier {
    accepted_roots: BTreeSet<String>,
    accepted_measurements: BTreeSet<String>,
}

impl ExternalAttestationVerifier {
    pub fn new() -> Self {
        Self::default()
    }
    /// Trust an attestation-root/key version (ADR-021 root, versioned for rotation §16).
    pub fn with_root(mut self, r: impl Into<String>) -> Self {
        self.accepted_roots.insert(r.into());
        self
    }
    /// Accept a reference measurement (the approved, reviewed code image).
    pub fn with_measurement(mut self, m: impl Into<String>) -> Self {
        self.accepted_measurements.insert(m.into());
        self
    }

    /// **Independently verify** a TEE quote (§13) against the auditor's own reference values and the
    /// AIA's issuance challenge. Fail-closed and in order of fundamentality:
    /// 1. the signing **root** is trusted;
    /// 2. the **measurement** is an accepted reference value AND matches the `expected_measurement`
    ///    the caller intended to run (so a valid quote for *different* code is rejected);
    /// 3. the quote's **def hash** binds to the `expected_def_hash` being issued;
    /// 4. the **nonce** equals the `challenge_nonce` (a replayed / stale quote is rejected).
    ///
    /// On success returns the [`VerifiedMeasurement`] — the fact the auditor can attest to without
    /// trusting the runtime.
    pub fn verify_external(
        &self,
        quote: &TeeQuoteClaims,
        expected_measurement: &str,
        expected_def_hash: &str,
        challenge_nonce: &str,
    ) -> Result<VerifiedMeasurement, TeeVerifyError> {
        if !self.accepted_roots.contains(&quote.attestation_root) {
            return Err(TeeVerifyError::UntrustedRoot(
                quote.attestation_root.clone(),
            ));
        }
        if !self.accepted_measurements.contains(&quote.measurement) {
            return Err(TeeVerifyError::UnknownMeasurement(
                quote.measurement.clone(),
            ));
        }
        if quote.measurement != expected_measurement {
            return Err(TeeVerifyError::MeasurementMismatch {
                expected: expected_measurement.to_string(),
                in_quote: quote.measurement.clone(),
            });
        }
        if quote.def_content_hash != expected_def_hash {
            return Err(TeeVerifyError::DefHashMismatch {
                expected: expected_def_hash.to_string(),
                in_quote: quote.def_content_hash.clone(),
            });
        }
        if quote.nonce != challenge_nonce {
            return Err(TeeVerifyError::StaleNonce {
                expected: challenge_nonce.to_string(),
                in_quote: quote.nonce.clone(),
            });
        }
        Ok(VerifiedMeasurement {
            measurement: quote.measurement.clone(),
            def_content_hash: quote.def_content_hash.clone(),
            attestation_root: quote.attestation_root.clone(),
        })
    }
}

// ===========================================================================
// Control-plane projection — ADR-022 §15 (fail-closed on staleness)
// ===========================================================================

/// The AIA's fast, in-memory projection of which definitions are currently valid (non-deprecated)
/// in the git control plane (ADR-022 §15). The renewal hot path reads *this*, never the git repo.
/// It is content-addressed to the `commit_sha` it reflects and carries the `synced_at` tick it was
/// last refreshed at, so a stale projection **fails closed**: past a freshness bound, every
/// definition is treated as deprecated (deny-and-drain) rather than trusting a stale cache.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlPlaneProjection {
    valid_definitions: BTreeSet<String>,
    synced_at: LogicalTime,
    commit_sha: String,
}

impl ControlPlaneProjection {
    /// A fresh projection reflecting `commit_sha` at `synced_at`, with `valid` the set of
    /// non-deprecated `def_ref`s.
    pub fn new(
        valid: impl IntoIterator<Item = String>,
        synced_at: LogicalTime,
        commit_sha: impl Into<String>,
    ) -> Self {
        ControlPlaneProjection {
            valid_definitions: valid.into_iter().collect(),
            synced_at,
            commit_sha: commit_sha.into(),
        }
    }

    /// The commit SHA this projection reflects (an AWC's `control_commit_sha` is attributable to it).
    pub fn commit_sha(&self) -> &str {
        &self.commit_sha
    }

    /// Rebuild the projection from a control-plane change notification (ADR-026 §6.2 hot-reload).
    pub fn sync(
        &mut self,
        valid: impl IntoIterator<Item = String>,
        synced_at: LogicalTime,
        commit_sha: impl Into<String>,
    ) {
        self.valid_definitions = valid.into_iter().collect();
        self.synced_at = synced_at;
        self.commit_sha = commit_sha.into();
    }

    /// Deprecate a single definition (§17 role deprovision) — it gets no new AWC and no renewal.
    pub fn deprecate(&mut self, def_ref: &str) {
        self.valid_definitions.remove(def_ref);
    }

    /// True iff `def_ref` is valid for issuance/renewal at `now`. **Fail-closed:** if the
    /// projection's sync lag (`now - synced_at`) exceeds `freshness`, returns `false` for every
    /// definition — a stale cache never fails open (§15).
    pub fn is_definition_valid(&self, def_ref: &str, now: LogicalTime, freshness: u64) -> bool {
        let lag = now.tick().saturating_sub(self.synced_at.tick());
        if lag > freshness {
            return false;
        }
        self.valid_definitions.contains(def_ref)
    }
}

// ===========================================================================
// Revocation — ADR-022 §17
// ===========================================================================

/// Individual and targeted revocation sets consulted at every issuance/renewal (§17). Because the
/// AIA re-checks these on the renewal path and AWCs are short-TTL, a revocation **degrades safe**:
/// even if an in-flight deny were missed, the credential expires and its renewal is denied.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationRegistry {
    runs: BTreeSet<String>,
    users: BTreeSet<String>,
}

impl RevocationRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Revoke exactly one Run — zero collateral to sibling Runs (§17).
    pub fn revoke_run(&mut self, run_id: impl Into<String>) {
        self.runs.insert(run_id.into());
    }

    /// Revoke an OBO human's delegated authority — every AWC carrying this `user_id` is denied at
    /// the next dispatch/renewal (§17).
    pub fn revoke_user(&mut self, user_id: impl Into<String>) {
        self.users.insert(user_id.into());
    }

    pub fn is_run_revoked(&self, run_id: &str) -> bool {
        self.runs.contains(run_id)
    }

    pub fn is_user_revoked(&self, user_id: &str) -> bool {
        self.users.contains(user_id)
    }

    /// True if this credential is revoked by *either* its Run or its OBO human.
    pub fn is_revoked(&self, awc: &AgentWorkloadCredential) -> bool {
        self.is_run_revoked(&awc.run_id) || self.is_user_revoked(&awc.obo_user_id)
    }
}

// ===========================================================================
// Kill-switch hierarchy — ADR-022 §19
// ===========================================================================

/// A scope of the workforce kill-switch (§19) — a precision instrument *and* a big red button.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KillScope {
    /// Halt a single Run (equivalent to revoking its AWC).
    Run(String),
    /// Halt all Runs of a definition (`def_ref`).
    Role(String),
    /// Halt all Runs whose OBO human is in a department.
    Department(String),
    /// Halt all Runs operating on a data class (e.g. all regulated-payment Runs).
    DataClass(DataClass),
    /// Halt the entire non-human workforce.
    Workforce,
}

/// The maximum AD seniority level permitted to pull the kill-switch (§19): `ad_level <= 3` (lower =
/// more senior), the same authority bar ADR-026 §5 uses for the payment-boundary front-matter class.
pub const KILL_SWITCH_MAX_AD_LEVEL: u8 = 3;

/// An audit record of a kill-switch pull (§19 "its own use is itself audited to the Event Log with
/// the pulling human's identity"). Immutable; the runtime writes it to `ainxt-eventlog`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KillSwitchAudit {
    pub scope: KillScope,
    pub puller: String,
    pub ad_level: u8,
    pub at: LogicalTime,
}

/// Why a kill-switch pull was refused (§19): the authority gate is `ad_level <= 3` **and**
/// `can_approve`, master-switch-style.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KillSwitchAuthError {
    /// The puller does not hold the `can_approve` claim.
    NotApprover(String),
    /// The puller is too junior (`ad_level > KILL_SWITCH_MAX_AD_LEVEL`).
    InsufficientSeniority { ad_level: u8, max: u8 },
}

impl fmt::Display for KillSwitchAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KillSwitchAuthError::NotApprover(who) => {
                write!(f, "kill-switch pull denied: {who} lacks can_approve")
            }
            KillSwitchAuthError::InsufficientSeniority { ad_level, max } => write!(
                f,
                "kill-switch pull denied: ad_level {ad_level} exceeds the required <= {max}"
            ),
        }
    }
}

impl std::error::Error for KillSwitchAuthError {}

/// The set of active kill-switch halts (§19). Any matching active scope denies a credential's next
/// issuance/renewal, so the halted set **drains within one TTL by expiry** even without reaching
/// every process. Every *authorized* pull is recorded to the [`audit_log`](KillSwitch::audit_log).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KillSwitch {
    active: BTreeSet<KillScope>,
    #[serde(default)]
    audit: Vec<KillSwitchAudit>,
}

impl KillSwitch {
    pub fn new() -> Self {
        Self::default()
    }

    /// Engage a halt scope **without** an authority check — an internal/mechanical primitive. The
    /// gated, audited entrypoint is [`pull_authorized`](KillSwitch::pull_authorized); production
    /// control-plane callers must use that so the pull is authority-checked and recorded.
    pub fn pull(&mut self, scope: KillScope) {
        self.active.insert(scope);
    }

    /// Pull a kill-switch scope with an authority check (§19): the puller must hold `can_approve`
    /// and be senior enough (`ad_level <= KILL_SWITCH_MAX_AD_LEVEL`). On success the scope is
    /// engaged **and** an immutable [`KillSwitchAudit`] is recorded with the pulling human's
    /// identity; on failure nothing changes. Returns the audit record for the caller to log.
    pub fn pull_authorized(
        &mut self,
        scope: KillScope,
        puller_id: impl Into<String>,
        ad_level: u8,
        can_approve: bool,
        now: LogicalTime,
    ) -> Result<KillSwitchAudit, KillSwitchAuthError> {
        let puller = puller_id.into();
        if !can_approve {
            return Err(KillSwitchAuthError::NotApprover(puller));
        }
        if ad_level > KILL_SWITCH_MAX_AD_LEVEL {
            return Err(KillSwitchAuthError::InsufficientSeniority {
                ad_level,
                max: KILL_SWITCH_MAX_AD_LEVEL,
            });
        }
        self.active.insert(scope.clone());
        let record = KillSwitchAudit {
            scope,
            puller,
            ad_level,
            at: now,
        };
        self.audit.push(record.clone());
        Ok(record)
    }

    /// The immutable audit trail of every authorized pull (§19).
    pub fn audit_log(&self) -> &[KillSwitchAudit] {
        &self.audit
    }

    /// Release a previously-engaged halt scope.
    pub fn release(&mut self, scope: &KillScope) {
        self.active.remove(scope);
    }

    /// True iff *no* active halt scope matches this credential — i.e. it may (continue to) run.
    pub fn permits(&self, awc: &AgentWorkloadCredential) -> bool {
        self.blocking_scope(awc).is_none()
    }

    /// The first active halt scope that matches this credential, if any (the reason a dispatch or
    /// renewal is denied, §19). `None` means the credential is permitted.
    pub fn blocking_scope(&self, awc: &AgentWorkloadCredential) -> Option<&KillScope> {
        self.blocking_scope_for(
            &awc.run_id,
            &awc.def_ref(),
            awc.obo_department.as_deref(),
            &awc.data_class,
        )
    }

    /// The first active halt scope that matches a set of credential *facets*, if any — the
    /// facet-level core of [`blocking_scope`](KillSwitch::blocking_scope). Factored out so the
    /// kill-switch can gate an **initial issuance** (which has an [`IssueRequest`], not yet an
    /// [`AgentWorkloadCredential`]) with the exact same §19 scope-matching the dispatch/renewal
    /// path uses — no drift between "may this Run start?" and "may this Run continue?".
    pub fn blocking_scope_for(
        &self,
        run_id: &str,
        def_ref: &str,
        department: Option<&str>,
        data_class: &DataClass,
    ) -> Option<&KillScope> {
        self.active.iter().find(|scope| match scope {
            KillScope::Workforce => true,
            KillScope::Run(id) => run_id == id,
            KillScope::Role(dr) => def_ref == dr,
            KillScope::Department(d) => department == Some(d.as_str()),
            KillScope::DataClass(dc) => data_class == dc,
        })
    }
}

// ===========================================================================
// Serving-Ops preemption signal — ADR-022 §19 (c) / ADR-020 / ADR-027 §7
// ===========================================================================

/// A running Program Run (ADR-027) as Serving-Ops sees it — the facets a kill-switch scope matches on
/// to decide whether it must be preempted. `is_program` distinguishes a long-lived Program Run (which
/// checkpoints to `PENDING` and can resume later) from a transient dispatch (which simply drains);
/// only Program Runs carry resumable state, so only they are checkpointed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunningProgramRun {
    pub run_id: String,
    pub def_ref: String,
    pub department: Option<String>,
    pub data_class: DataClass,
    /// True for an ADR-027 Program Run (resumable, checkpoints to PENDING); false for a transient run.
    pub is_program: bool,
}

/// A Serving-Ops preemption directive (§19 (c) / ADR-020 / ADR-027 §7): halt this Run and, for a
/// resumable Program Run, **checkpoint it to `PENDING`** so it stops cleanly and does not resume,
/// losing nothing. Carries the matching [`KillScope`] as the audited reason. This is what the AIA
/// kill-switch *emits*; delivering it to the scheduler is the [`PreemptionSink`] seam.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreemptDirective {
    pub run_id: String,
    /// True iff the Run is a resumable Program Run and must checkpoint to `PENDING` (never lose work).
    pub checkpoint_to_pending: bool,
    pub reason: KillScope,
}

/// The Serving-Ops signal seam (ADR-020): the AIA kill-switch produces [`PreemptDirective`]s; the
/// scheduler consumes them to actually preempt/drain the affected Runs. Injected as a trait so the
/// identity crate stays free of any scheduler dependency (acyclic); the real deployment wires
/// `ainxt-serving`'s preemptor in behind it.
pub trait PreemptionSink {
    /// Deliver one preemption directive to the scheduler (idempotent by `run_id` on the sink side).
    fn preempt(&mut self, directive: &PreemptDirective);
}

impl KillSwitch {
    /// Compute the Serving-Ops preemption directives (§19 (c)) for a snapshot of `running` Program
    /// Runs: every Run matched by an active kill-switch scope is halted, and a resumable Program Run
    /// is checkpointed to `PENDING` (ADR-027 §7 — stop cleanly, resume never, lose nothing). Pure and
    /// deterministic: the same active scopes + snapshot always yield the same directive set, so the
    /// preempt/drain signal is reproducible and auditable. This is the "big red button" arm that stops
    /// *in-flight* Program work immediately, complementing the drain-by-expiry that the issuance/
    /// renewal deny already guarantees (so a workforce halt does not merely stop *new* work).
    pub fn preemption_directives(&self, running: &[RunningProgramRun]) -> Vec<PreemptDirective> {
        running
            .iter()
            .filter_map(|run| {
                self.blocking_scope_for(
                    &run.run_id,
                    &run.def_ref,
                    run.department.as_deref(),
                    &run.data_class,
                )
                .map(|scope| PreemptDirective {
                    run_id: run.run_id.clone(),
                    checkpoint_to_pending: run.is_program,
                    reason: scope.clone(),
                })
            })
            .collect()
    }

    /// Compute and **signal** the preemption directives to a Serving-Ops [`PreemptionSink`] (§19 (c))
    /// in one call — the entrypoint the control plane drives right after an authorized workforce/scope
    /// kill-switch pull so the halt reaches Runs already in flight, not only at their next TTL. Returns
    /// the directives emitted (for the audit trail).
    pub fn signal_preemption<S: PreemptionSink>(
        &self,
        running: &[RunningProgramRun],
        sink: &mut S,
    ) -> Vec<PreemptDirective> {
        let directives = self.preemption_directives(running);
        for d in &directives {
            sink.preempt(d);
        }
        directives
    }
}

// ===========================================================================
// Anomaly renewal-choke — ADR-022 §20
// ===========================================================================

/// A per-role expected behavioral envelope (§20): the capability mix, egress destinations, action
/// rate, and cost velocity a definition's Runs are expected to stay within, drawn from its role
/// charter (WORKFORCE §2) and its own history. In the real deployment the *learning* of this
/// baseline from history is a data-plane job; this struct is the pure, injected envelope the
/// deviation computation scores against.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct BehavioralBaseline {
    pub def_ref: String,
    /// Capabilities this role is expected to use. A used capability outside this set is a deviation.
    pub expected_capabilities: BTreeSet<String>,
    /// Egress destinations this role is expected to reach. An out-of-set destination is a deviation.
    pub allowed_egress: BTreeSet<String>,
    /// Upper bound on actions/tick before an action-rate spike is flagged.
    pub max_action_rate: f64,
    /// Upper bound on cost/tick before a cost-velocity spike is flagged.
    pub max_cost_velocity: f64,
}

impl BehavioralBaseline {
    pub fn new(def_ref: impl Into<String>) -> Self {
        BehavioralBaseline {
            def_ref: def_ref.into(),
            max_action_rate: f64::INFINITY,
            max_cost_velocity: f64::INFINITY,
            ..Default::default()
        }
    }
    pub fn with_capabilities<I: IntoIterator<Item = S>, S: Into<String>>(
        mut self,
        caps: I,
    ) -> Self {
        self.expected_capabilities = caps.into_iter().map(Into::into).collect();
        self
    }
    pub fn with_egress<I: IntoIterator<Item = S>, S: Into<String>>(mut self, dests: I) -> Self {
        self.allowed_egress = dests.into_iter().map(Into::into).collect();
        self
    }
    pub fn with_max_action_rate(mut self, r: f64) -> Self {
        self.max_action_rate = r;
        self
    }
    pub fn with_max_cost_velocity(mut self, v: f64) -> Self {
        self.max_cost_velocity = v;
        self
    }

    /// **Learn** a per-role behavioral envelope from the role's *own history* (§20 "learned from its
    /// own history"). Given the historical [`ActivitySample`]s observed for `def_ref` (only samples
    /// matching that def are considered), derive:
    /// * `expected_capabilities` = the union of every capability the role has legitimately used;
    /// * `allowed_egress` = the union of every egress destination it has legitimately reached;
    /// * `max_action_rate` / `max_cost_velocity` = the peak observed, scaled by `slack` (a headroom
    ///   multiplier ≥ 1.0, e.g. 1.3 for +30% tolerance) so normal variance is not flagged but a real
    ///   spike beyond learned behavior is.
    ///
    /// Pure and deterministic — no clock, no rng: the same history always yields the same baseline,
    /// so a learned envelope is reproducible and auditable. The *continuous* re-learning pipeline
    /// (streaming history off telemetry) is a data-plane job; this is the derivation math it applies.
    /// With no matching history the baseline is maximally permissive (infinite ceilings, empty
    /// allow-sets under an empty union) — a role with no track record is not retroactively flagged;
    /// the deviation-scoring caller decides whether an unbaselined role may run.
    pub fn learn_from_history<'a, I>(def_ref: impl Into<String>, history: I, slack: f64) -> Self
    where
        I: IntoIterator<Item = &'a ActivitySample>,
    {
        let def_ref = def_ref.into();
        let slack = if slack.is_finite() && slack >= 1.0 {
            slack
        } else {
            1.0
        };
        let mut expected_capabilities = BTreeSet::new();
        let mut allowed_egress = BTreeSet::new();
        let mut peak_action_rate = 0.0f64;
        let mut peak_cost_velocity = 0.0f64;
        let mut seen = false;
        for sample in history {
            if sample.def_ref != def_ref {
                continue;
            }
            seen = true;
            for cap in &sample.capabilities_used {
                expected_capabilities.insert(cap.clone());
            }
            for dest in &sample.egress_destinations {
                allowed_egress.insert(dest.clone());
            }
            peak_action_rate = peak_action_rate.max(sample.action_rate);
            peak_cost_velocity = peak_cost_velocity.max(sample.cost_velocity);
        }
        BehavioralBaseline {
            def_ref,
            expected_capabilities,
            allowed_egress,
            // No history => infinite ceilings (nothing to flag yet); otherwise learned peak × slack.
            max_action_rate: if seen {
                peak_action_rate * slack
            } else {
                f64::INFINITY
            },
            max_cost_velocity: if seen {
                peak_cost_velocity * slack
            } else {
                f64::INFINITY
            },
        }
    }
}

/// An observed activity window for one Run actor (§20) — what the UEBA monitor scores against the
/// role baseline. An injected observation (the runtime collects it from telemetry).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ActivitySample {
    pub run_id: String,
    pub def_ref: String,
    pub capabilities_used: BTreeSet<String>,
    pub egress_destinations: BTreeSet<String>,
    pub action_rate: f64,
    pub cost_velocity: f64,
}

/// A single way a sample deviated from its role baseline (§20). Carries floats, so it is `PartialEq`
/// (not `Eq`) — comparisons in tests use exact injected values.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "deviation", rename_all = "snake_case")]
pub enum Deviation {
    /// The Run used a capability outside its role's expected mix (e.g. a triage role suddenly
    /// enumerating settlement tables).
    UnexpectedCapability(String),
    /// The Run egressed to a destination outside its role's allowed set (drift toward exfiltration).
    UnexpectedEgress(String),
    /// The action rate exceeded the baseline ceiling.
    ActionRateSpike { observed: f64, ceiling: f64 },
    /// The cost velocity exceeded the baseline ceiling.
    CostVelocitySpike { observed: f64, ceiling: f64 },
}

/// The outcome of scoring one [`ActivitySample`] against its [`BehavioralBaseline`] (§20).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnomalyAssessment {
    pub run_id: String,
    pub deviations: Vec<Deviation>,
}

impl AnomalyAssessment {
    /// True iff any deviation was detected — the actor-behavior deviation the monitor flags on.
    pub fn is_anomalous(&self) -> bool {
        !self.deviations.is_empty()
    }
}

/// The UEBA Run-Actor Anomaly Monitor (§20). It both **detects** actor-behavior deviation against a
/// per-role baseline ([`assess`](AnomalyMonitor::assess)) and holds the **renewal-choke lever**
/// (`flag`/`is_flagged`): a flagged Run's *renewal* is denied so it drains at the next TTL without a
/// hard kill — the "stop renewing this actor's identity" response the design calls the monitor's
/// strongest lever. [`observe`](AnomalyMonitor::observe) does both: it scores a sample and flags the
/// Run if it deviated. (Learning the baseline from history is data/infra; the deviation *scoring* is
/// the pure core implemented here.)
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnomalyMonitor {
    flagged: BTreeSet<String>,
}

impl AnomalyMonitor {
    pub fn new() -> Self {
        Self::default()
    }

    /// Flag a Run actor as anomalous (choke its renewal).
    pub fn flag(&mut self, run_id: impl Into<String>) {
        self.flagged.insert(run_id.into());
    }

    /// Clear a Run's anomaly flag (e.g. after human review cleared it).
    pub fn clear(&mut self, run_id: &str) {
        self.flagged.remove(run_id);
    }

    pub fn is_flagged(&self, run_id: &str) -> bool {
        self.flagged.contains(run_id)
    }

    /// Score a sample against a role baseline (§20) — a pure, side-effect-free deviation computation
    /// across the four dimensions (capability mix, egress, action rate, cost velocity). Every
    /// deviation is reported (defense-in-depth visibility); the caller decides the graduated
    /// response (checkpoint / renewal-choke / kill-switch).
    pub fn assess(
        &self,
        baseline: &BehavioralBaseline,
        sample: &ActivitySample,
    ) -> AnomalyAssessment {
        let mut deviations = Vec::new();
        for cap in &sample.capabilities_used {
            if !baseline.expected_capabilities.contains(cap) {
                deviations.push(Deviation::UnexpectedCapability(cap.clone()));
            }
        }
        for dest in &sample.egress_destinations {
            if !baseline.allowed_egress.contains(dest) {
                deviations.push(Deviation::UnexpectedEgress(dest.clone()));
            }
        }
        if sample.action_rate > baseline.max_action_rate {
            deviations.push(Deviation::ActionRateSpike {
                observed: sample.action_rate,
                ceiling: baseline.max_action_rate,
            });
        }
        if sample.cost_velocity > baseline.max_cost_velocity {
            deviations.push(Deviation::CostVelocitySpike {
                observed: sample.cost_velocity,
                ceiling: baseline.max_cost_velocity,
            });
        }
        AnomalyAssessment {
            run_id: sample.run_id.clone(),
            deviations,
        }
    }

    /// Assess a sample and, if it deviated, **flag the Run** so its next renewal is choked (§20).
    /// Returns the assessment for the caller's evidence trail / anomaly checkpoint.
    pub fn observe(
        &mut self,
        baseline: &BehavioralBaseline,
        sample: &ActivitySample,
    ) -> AnomalyAssessment {
        let assessment = self.assess(baseline, sample);
        if assessment.is_anomalous() {
            self.flag(sample.run_id.clone());
        }
        assessment
    }
}

// ===========================================================================
// Issue / renew requests & errors
// ===========================================================================

/// A request to mint a per-Run AWC (§12). The `run_id`/`key_id` are supplied (no rng); validity is
/// derived from the caller-supplied `now` and the AIA's TTL (no clock).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssueRequest {
    pub def_kind: String,
    pub def_id: String,
    pub def_version: String,
    pub run_id: String,
    pub data_class: DataClass,
    pub requires_tee: bool,
    pub obo_user_id: String,
    pub obo_department: Option<String>,
    pub obo_ad_level: Option<u8>,
    pub obo_can_approve: bool,
}

impl IssueRequest {
    /// The stable `def:<kind>/<id>@<version>` reference this request will mint — used by the
    /// control-plane projection check and the §19 role/kill-switch scope match at issuance time.
    pub fn def_ref(&self) -> String {
        format!("def:{}/{}@{}", self.def_kind, self.def_id, self.def_version)
    }
}

/// Why the AIA refused to issue an AWC. Every arm is fail-closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssueError {
    /// Attestation did not verify (§13) — no credential is minted.
    AttestationFailed(AttestationError),
    /// The definition is deprecated, unknown, or the projection is stale (fail-closed, §15).
    DefinitionNotIssuable(String),
    /// A credential was already issued for this `run_id` — identity is per-Run, not re-mintable.
    DuplicateRun(String),
    /// The requesting OBO human or Run is already revoked (§17).
    Revoked(String),
    /// An active kill-switch scope halts this Run (§19).
    KillSwitchActive,
}

impl fmt::Display for IssueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IssueError::AttestationFailed(e) => write!(f, "attestation failed: {e}"),
            IssueError::DefinitionNotIssuable(d) => {
                write!(
                    f,
                    "definition {d:?} is not issuable (deprecated/unknown/stale projection)"
                )
            }
            IssueError::DuplicateRun(r) => {
                write!(
                    f,
                    "an AWC was already issued for run {r:?} (identity is per-Run)"
                )
            }
            IssueError::Revoked(who) => write!(f, "issuance denied: {who} is revoked"),
            IssueError::KillSwitchActive => {
                write!(
                    f,
                    "issuance denied: an active kill-switch scope halts this Run"
                )
            }
        }
    }
}

impl std::error::Error for IssueError {}

/// Why the AIA refused to renew an AWC (§15 conditional continuation). Renewal re-runs every
/// issuance check plus anomaly, and (for TEE Runs) a fresh attestation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenewError {
    /// The definition is no longer valid in the projection (deprecated mid-run, or stale) — the
    /// Run drains at its next TTL (§15/§17).
    DefinitionNoLongerValid(String),
    /// The Run or its OBO human was revoked (§17).
    Revoked(String),
    /// An active kill-switch scope halts this Run (§19).
    KillSwitchActive,
    /// The Run actor was flagged anomalous; renewal is choked (§20).
    AnomalyChoke(String),
    /// A TEE Run presented no fresh attestation quote at renewal (§15).
    FreshAttestationRequired,
    /// The presented fresh attestation quote did not verify (§13).
    AttestationFailed(AttestationError),
}

impl fmt::Display for RenewError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RenewError::DefinitionNoLongerValid(d) => {
                write!(
                    f,
                    "renewal denied: definition {d:?} is no longer valid; Run drains at TTL"
                )
            }
            RenewError::Revoked(who) => write!(f, "renewal denied: {who} is revoked"),
            RenewError::KillSwitchActive => {
                write!(
                    f,
                    "renewal denied: an active kill-switch scope halts this Run"
                )
            }
            RenewError::AnomalyChoke(r) => {
                write!(
                    f,
                    "renewal denied: run {r:?} is flagged anomalous (renewal choke)"
                )
            }
            RenewError::FreshAttestationRequired => {
                write!(
                    f,
                    "renewal denied: a TEE Run requires a fresh attestation quote"
                )
            }
            RenewError::AttestationFailed(e) => write!(f, "renewal attestation failed: {e}"),
        }
    }
}

impl std::error::Error for RenewError {}

// ===========================================================================
// The Agent Identity Authority (AIA) — ADR-022 §12/§15/§17/§19
// ===========================================================================

/// The sole issuer of agent workload credentials (ADR-022 §12). It composes the attestation
/// verifier, the fail-closed control-plane projection, the revocation registry, the kill-switch,
/// and the anomaly monitor into one gate: [`issue`](IdentityAuthority::issue) mints an AWC only
/// after attestation + all deny-checks pass, and [`renew`](IdentityAuthority::renew) re-runs those
/// checks on every short-TTL renewal so long-lived Runs are a *chain of re-authorized identities*,
/// not a standing token.
///
/// Deterministic: TTL/`now`/`run_id`/`key_id` are all supplied; no clock, no rng.
#[derive(Debug, Clone)]
pub struct IdentityAuthority<V: AttestationVerifier> {
    verifier: V,
    projection: ControlPlaneProjection,
    revocations: RevocationRegistry,
    kill_switch: KillSwitch,
    anomaly: AnomalyMonitor,
    /// Short credential TTL in logical ticks (§15).
    ttl: u64,
    /// The projection staleness bound; past it the projection fails closed (§15).
    freshness_threshold: u64,
    /// The current signing-key id (ADR-023 crypto-agility, §16). [`rotate_key`] advances it.
    key_id: String,
    /// Run ids already issued — enforces one credential per Run.
    issued_runs: BTreeSet<String>,
}

impl<V: AttestationVerifier> IdentityAuthority<V> {
    /// Construct an AIA. `ttl` is the short credential lifetime (ticks); `freshness_threshold` is
    /// the max projection sync lag before it fails closed; `key_id` is the initial signing key.
    pub fn new(
        verifier: V,
        projection: ControlPlaneProjection,
        ttl: u64,
        freshness_threshold: u64,
        key_id: impl Into<String>,
    ) -> Self {
        IdentityAuthority {
            verifier,
            projection,
            revocations: RevocationRegistry::new(),
            kill_switch: KillSwitch::new(),
            anomaly: AnomalyMonitor::new(),
            ttl,
            freshness_threshold,
            key_id: key_id.into(),
            issued_runs: BTreeSet::new(),
        }
    }

    // ---- control surface (single point of operational state, §12) ---------

    pub fn projection_mut(&mut self) -> &mut ControlPlaneProjection {
        &mut self.projection
    }
    pub fn revocations_mut(&mut self) -> &mut RevocationRegistry {
        &mut self.revocations
    }
    pub fn kill_switch_mut(&mut self) -> &mut KillSwitch {
        &mut self.kill_switch
    }
    pub fn anomaly_mut(&mut self) -> &mut AnomalyMonitor {
        &mut self.anomaly
    }

    /// The current signing-key id (§16).
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Rotate the AIA signing key (ADR-023 §16). New issuance/renewal stamps the new `key_id`;
    /// already-issued short-TTL credentials keep theirs (verify-then-expire), so rotation is a
    /// non-event with no outage.
    pub fn rotate_key(&mut self, new_key_id: impl Into<String>) {
        self.key_id = new_key_id.into();
    }

    /// Issue a per-Run AWC (§12/§13). Checks, fail-closed and in order of fundamentality:
    /// 1. **attestation** verifies (else no credential exists at all, §13);
    /// 2. the **definition is issuable** in the fail-closed projection (§15);
    /// 3. the **run_id is fresh** (one credential per Run, §12);
    /// 4. neither the **Run nor the OBO human is revoked** (§17);
    /// 5. **no kill-switch scope** halts this Run (§19).
    pub fn issue(
        &mut self,
        req: &IssueRequest,
        quote: &AttestationQuote,
        now: LogicalTime,
    ) -> Result<AgentWorkloadCredential, IssueError> {
        self.verifier
            .verify(quote, req.requires_tee)
            .map_err(IssueError::AttestationFailed)?;

        let def_ref = req.def_ref();
        if !self
            .projection
            .is_definition_valid(&def_ref, now, self.freshness_threshold)
        {
            return Err(IssueError::DefinitionNotIssuable(def_ref));
        }

        if self.issued_runs.contains(&req.run_id) {
            return Err(IssueError::DuplicateRun(req.run_id.clone()));
        }

        let awc = AgentWorkloadCredential {
            def_kind: req.def_kind.clone(),
            def_id: req.def_id.clone(),
            def_version: req.def_version.clone(),
            def_content_hash: quote.def_content_hash.clone(),
            control_commit_sha: quote.control_commit_sha.clone(),
            run_id: req.run_id.clone(),
            issued_at: now,
            expires_at: LogicalTime(now.tick().saturating_add(self.ttl)),
            data_class: req.data_class,
            requires_tee: req.requires_tee,
            obo_user_id: req.obo_user_id.clone(),
            obo_department: req.obo_department.clone(),
            obo_ad_level: req.obo_ad_level,
            obo_can_approve: req.obo_can_approve,
            attestation_ref: quote.measurement.clone(),
            key_id: self.key_id.clone(),
        };

        if self.revocations.is_run_revoked(&awc.run_id) {
            return Err(IssueError::Revoked(format!("run {}", awc.run_id)));
        }
        if self.revocations.is_user_revoked(&awc.obo_user_id) {
            return Err(IssueError::Revoked(format!("user {}", awc.obo_user_id)));
        }
        if !self.kill_switch.permits(&awc) {
            return Err(IssueError::KillSwitchActive);
        }

        self.issued_runs.insert(awc.run_id.clone());
        Ok(awc)
    }

    /// Renew a short-TTL AWC into a fresh one (§15 conditional continuation). Re-checks, in order:
    /// definition still valid (fail-closed on stale/deprecated); Run/human not revoked; kill-switch
    /// permits; the Run is not anomaly-flagged; and — for a TEE Run — a fresh attestation quote is
    /// present and verifies. On success the returned credential has `issued_at = now`,
    /// `expires_at = now + ttl`, and the AIA's *current* `key_id` (so a mid-life key rotation rolls
    /// forward). Identity facets (def, run, OBO) are carried over unchanged.
    pub fn renew(
        &self,
        awc: &AgentWorkloadCredential,
        quote: Option<&AttestationQuote>,
        now: LogicalTime,
    ) -> Result<AgentWorkloadCredential, RenewError> {
        let def_ref = awc.def_ref();
        if !self
            .projection
            .is_definition_valid(&def_ref, now, self.freshness_threshold)
        {
            return Err(RenewError::DefinitionNoLongerValid(def_ref));
        }
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
        if awc.requires_tee {
            match quote {
                Some(q) => self
                    .verifier
                    .verify(q, true)
                    .map_err(RenewError::AttestationFailed)?,
                None => return Err(RenewError::FreshAttestationRequired),
            }
        }

        Ok(AgentWorkloadCredential {
            issued_at: now,
            expires_at: LogicalTime(now.tick().saturating_add(self.ttl)),
            key_id: self.key_id.clone(),
            ..awc.clone()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verifier() -> ReferenceValueVerifier {
        ReferenceValueVerifier::new()
            .with_measurement("m-coder-ok")
            .with_tee_quote("tee-ok")
    }

    fn projection(now: u64) -> ControlPlaneProjection {
        ControlPlaneProjection::new(
            [
                "def:role/coder@v3".to_string(),
                "def:role/tester@v2".to_string(),
            ],
            LogicalTime(now),
            "commit-abc",
        )
    }

    fn aia() -> IdentityAuthority<ReferenceValueVerifier> {
        // TTL = 5 ticks; projection fails closed past 50 ticks of lag.
        IdentityAuthority::new(verifier(), projection(0), 5, 50, "key-v1")
    }

    fn quote() -> AttestationQuote {
        AttestationQuote {
            def_content_hash: "hash-coder-v3".to_string(),
            control_commit_sha: "commit-abc".to_string(),
            measurement: "m-coder-ok".to_string(),
            tee_quote: None,
        }
    }

    fn req(run_id: &str) -> IssueRequest {
        IssueRequest {
            def_kind: "role".to_string(),
            def_id: "coder".to_string(),
            def_version: "v3".to_string(),
            run_id: run_id.to_string(),
            data_class: DataClass::Internal,
            requires_tee: false,
            obo_user_id: "u-alice".to_string(),
            obo_department: Some("payments-eng".to_string()),
            obo_ad_level: Some(4),
            obo_can_approve: false,
        }
    }

    // ---- issuance happy path + per-Run identity shape --------------------
    #[test]
    fn issue_mints_attested_short_ttl_per_run_credential() {
        let mut aia = aia();
        let awc = aia.issue(&req("run-1"), &quote(), LogicalTime(10)).unwrap();
        assert_eq!(awc.def_ref(), "def:role/coder@v3");
        assert_eq!(awc.uri(), "ainxt-id://ainxt/agent/role/coder/v3/run/run-1");
        // Attested facts came from the quote, not self-assertion.
        assert_eq!(awc.def_content_hash, "hash-coder-v3");
        assert_eq!(awc.control_commit_sha, "commit-abc");
        assert_eq!(awc.attestation_ref, "m-coder-ok");
        assert_eq!(awc.key_id, "key-v1");
        // Short TTL: valid through issued_at+ttl, expired after.
        assert_eq!(awc.issued_at, LogicalTime(10));
        assert_eq!(awc.expires_at, LogicalTime(15));
        assert!(awc.is_valid_at(LogicalTime(15)));
        assert!(awc.is_expired_at(LogicalTime(16)));
    }

    #[test]
    fn two_runs_of_same_role_get_distinct_credentials() {
        let mut aia = aia();
        let a = aia.issue(&req("run-1"), &quote(), LogicalTime(1)).unwrap();
        let b = aia.issue(&req("run-2"), &quote(), LogicalTime(1)).unwrap();
        assert_ne!(a.run_id, b.run_id);
        assert_ne!(a.uri(), b.uri(), "not a shared token");
        assert_eq!(a.def_ref(), b.def_ref(), "same role, different Run");
    }

    #[test]
    fn duplicate_run_id_is_refused() {
        let mut aia = aia();
        aia.issue(&req("run-1"), &quote(), LogicalTime(1)).unwrap();
        let err = aia
            .issue(&req("run-1"), &quote(), LogicalTime(1))
            .unwrap_err();
        assert_eq!(err, IssueError::DuplicateRun("run-1".to_string()));
    }

    // ---- attestation gate (§13) -----------------------------------------
    #[test]
    fn issue_refused_without_valid_attestation() {
        let mut aia = aia();
        let bad = AttestationQuote {
            measurement: "m-tampered".to_string(),
            ..quote()
        };
        let err = aia.issue(&req("run-1"), &bad, LogicalTime(1)).unwrap_err();
        assert_eq!(
            err,
            IssueError::AttestationFailed(AttestationError::UnknownMeasurement(
                "m-tampered".to_string()
            ))
        );
        // A refused issuance minted nothing: the run_id is still free to issue later (once fixed).
        assert!(aia.issue(&req("run-1"), &quote(), LogicalTime(1)).is_ok());
    }

    #[test]
    fn tee_run_requires_a_trusted_quote() {
        let mut aia = aia();
        let mut r = req("run-tee");
        r.requires_tee = true;
        r.data_class = DataClass::RegulatedPayment;

        // No TEE quote -> refused.
        let no_quote = AttestationQuote {
            tee_quote: None,
            ..quote()
        };
        assert_eq!(
            aia.issue(&r, &no_quote, LogicalTime(1)).unwrap_err(),
            IssueError::AttestationFailed(AttestationError::TeeQuoteRequired)
        );
        // Untrusted TEE quote -> refused.
        let untrusted = AttestationQuote {
            tee_quote: Some("tee-forged".to_string()),
            ..quote()
        };
        assert_eq!(
            aia.issue(&r, &untrusted, LogicalTime(1)).unwrap_err(),
            IssueError::AttestationFailed(AttestationError::UntrustedTeeQuote(
                "tee-forged".to_string()
            ))
        );
        // Trusted TEE quote -> issued.
        let good = AttestationQuote {
            tee_quote: Some("tee-ok".to_string()),
            ..quote()
        };
        assert!(aia.issue(&r, &good, LogicalTime(1)).unwrap().requires_tee);
    }

    // ---- definition validity + fail-closed staleness (§15) --------------
    #[test]
    fn deprecated_definition_gets_no_credential() {
        let mut aia = aia();
        aia.projection_mut().deprecate("def:role/coder@v3");
        let err = aia
            .issue(&req("run-1"), &quote(), LogicalTime(1))
            .unwrap_err();
        assert_eq!(
            err,
            IssueError::DefinitionNotIssuable("def:role/coder@v3".to_string())
        );
    }

    #[test]
    fn stale_projection_fails_closed() {
        let mut aia = aia(); // synced at t=0, freshness bound 50
                             // At t=51 the projection is stale -> deny even a known-good definition.
        let err = aia
            .issue(&req("run-1"), &quote(), LogicalTime(51))
            .unwrap_err();
        assert_eq!(
            err,
            IssueError::DefinitionNotIssuable("def:role/coder@v3".to_string())
        );
        // Re-syncing at a fresh tick restores issuance.
        aia.projection_mut().sync(
            ["def:role/coder@v3".to_string()],
            LogicalTime(51),
            "commit-def",
        );
        assert!(aia.issue(&req("run-1"), &quote(), LogicalTime(51)).is_ok());
    }

    // ---- revocation (§17) ------------------------------------------------
    #[test]
    fn revoked_user_is_denied_issuance() {
        let mut aia = aia();
        aia.revocations_mut().revoke_user("u-alice");
        let err = aia
            .issue(&req("run-1"), &quote(), LogicalTime(1))
            .unwrap_err();
        assert_eq!(err, IssueError::Revoked("user u-alice".to_string()));
    }

    #[test]
    fn individual_run_revocation_denies_renewal_but_not_siblings() {
        let mut aia = aia();
        let r1 = aia.issue(&req("run-1"), &quote(), LogicalTime(1)).unwrap();
        let r2 = aia.issue(&req("run-2"), &quote(), LogicalTime(1)).unwrap();
        aia.revocations_mut().revoke_run("run-1");
        // run-1 cannot renew (drains at its TTL); run-2 renews fine — zero collateral.
        assert_eq!(
            aia.renew(&r1, None, LogicalTime(2)).unwrap_err(),
            RenewError::Revoked("run run-1".to_string())
        );
        let r2b = aia.renew(&r2, None, LogicalTime(2)).unwrap();
        assert_eq!(r2b.expires_at, LogicalTime(7));
    }

    // ---- kill-switch hierarchy (§19) ------------------------------------
    #[test]
    fn workforce_kill_switch_halts_all_issuance() {
        let mut aia = aia();
        aia.kill_switch_mut().pull(KillScope::Workforce);
        assert_eq!(
            aia.issue(&req("run-1"), &quote(), LogicalTime(1))
                .unwrap_err(),
            IssueError::KillSwitchActive
        );
    }

    #[test]
    fn scoped_kill_switch_is_precise() {
        let mut aia = aia();
        // Halt only regulated-payment data-class Runs.
        aia.kill_switch_mut()
            .pull(KillScope::DataClass(DataClass::RegulatedPayment));

        // An internal-class Run is unaffected.
        assert!(aia
            .issue(&req("run-internal"), &quote(), LogicalTime(1))
            .is_ok());

        // A regulated-payment Run is halted.
        let mut reg = req("run-reg");
        reg.data_class = DataClass::RegulatedPayment;
        assert_eq!(
            aia.issue(&reg, &quote(), LogicalTime(1)).unwrap_err(),
            IssueError::KillSwitchActive
        );
    }

    #[test]
    fn department_and_role_scopes_match_on_credential_facets() {
        let mut aia = aia();
        let awc = aia.issue(&req("run-1"), &quote(), LogicalTime(1)).unwrap();
        // Department scope on the OBO facet.
        aia.kill_switch_mut()
            .pull(KillScope::Department("payments-eng".to_string()));
        assert_eq!(
            aia.renew(&awc, None, LogicalTime(2)).unwrap_err(),
            RenewError::KillSwitchActive
        );
        // Releasing it, then a role-scoped halt on the def_ref.
        aia.kill_switch_mut()
            .release(&KillScope::Department("payments-eng".to_string()));
        aia.kill_switch_mut()
            .pull(KillScope::Role("def:role/coder@v3".to_string()));
        assert_eq!(
            aia.renew(&awc, None, LogicalTime(2)).unwrap_err(),
            RenewError::KillSwitchActive
        );
    }

    // ---- renewal re-checks: conditional continuation (§15) --------------
    #[test]
    fn renewal_re_checks_definition_and_drains_on_deprecation() {
        let mut aia = aia();
        let awc = aia
            .issue(&req("run-long"), &quote(), LogicalTime(1))
            .unwrap();
        // A first renewal within its life succeeds and extends the TTL.
        let awc2 = aia.renew(&awc, None, LogicalTime(4)).unwrap();
        assert_eq!(awc2.issued_at, LogicalTime(4));
        assert_eq!(awc2.expires_at, LogicalTime(9));
        // Mid-run the role is deprecated in the control plane -> next renewal is denied.
        aia.projection_mut().deprecate("def:role/coder@v3");
        assert_eq!(
            aia.renew(&awc2, None, LogicalTime(6)).unwrap_err(),
            RenewError::DefinitionNoLongerValid("def:role/coder@v3".to_string())
        );
    }

    #[test]
    fn anomaly_flag_chokes_renewal_only() {
        let mut aia = aia();
        let awc = aia.issue(&req("run-x"), &quote(), LogicalTime(1)).unwrap();
        aia.anomaly_mut().flag("run-x");
        assert_eq!(
            aia.renew(&awc, None, LogicalTime(2)).unwrap_err(),
            RenewError::AnomalyChoke("run-x".to_string())
        );
        // Clearing the flag restores renewal.
        aia.anomaly_mut().clear("run-x");
        assert!(aia.renew(&awc, None, LogicalTime(2)).is_ok());
    }

    #[test]
    fn tee_renewal_demands_a_fresh_quote_every_time() {
        let mut aia = aia();
        let mut r = req("run-tee");
        r.requires_tee = true;
        let good = AttestationQuote {
            tee_quote: Some("tee-ok".to_string()),
            ..quote()
        };
        let awc = aia.issue(&r, &good, LogicalTime(1)).unwrap();
        // Renewal without a fresh quote is refused.
        assert_eq!(
            aia.renew(&awc, None, LogicalTime(2)).unwrap_err(),
            RenewError::FreshAttestationRequired
        );
        // With a fresh trusted quote it renews.
        assert!(aia.renew(&awc, Some(&good), LogicalTime(2)).is_ok());
    }

    // ---- crypto-agility key rotation is a non-event (§16) ---------------
    #[test]
    fn key_rotation_stamps_new_credentials_only() {
        let mut aia = aia();
        let old = aia.issue(&req("run-1"), &quote(), LogicalTime(1)).unwrap();
        assert_eq!(old.key_id, "key-v1");
        aia.rotate_key("key-v2");
        // A NEW Run gets the new key.
        let fresh = aia.issue(&req("run-2"), &quote(), LogicalTime(1)).unwrap();
        assert_eq!(fresh.key_id, "key-v2");
        // The old credential still carries its own key and remains verifiable-then-expiring; a
        // renewal rolls it forward to the new key with no outage.
        assert_eq!(old.key_id, "key-v1");
        let rolled = aia.renew(&old, None, LogicalTime(2)).unwrap();
        assert_eq!(rolled.key_id, "key-v2");
    }

    // ---- external verifiability of reference values (§13) ----------------
    #[test]
    fn reference_value_verifier_is_explicit_allow_list() {
        let v = ReferenceValueVerifier::new().with_measurement("m-ok");
        let ok = AttestationQuote {
            def_content_hash: "h".to_string(),
            control_commit_sha: "c".to_string(),
            measurement: "m-ok".to_string(),
            tee_quote: None,
        };
        assert_eq!(v.verify(&ok, false), Ok(()));
        let bad = AttestationQuote {
            measurement: "m-evil".to_string(),
            ..ok
        };
        assert_eq!(
            v.verify(&bad, false),
            Err(AttestationError::UnknownMeasurement("m-evil".to_string()))
        );
    }

    // ---- IDN-03: actor-of-record for the Event Log (§14) -----------------
    #[test]
    fn gap_idn_03_awc_produces_composite_actor_of_record() {
        let mut aia = aia();
        let awc = aia.issue(&req("run-1"), &quote(), LogicalTime(10)).unwrap();
        // The agent loop obtains the actor to attribute every action to — a composite, never a
        // service account.
        let actor = awc.actor_of_record();
        assert_eq!(
            actor.actor_uri,
            "ainxt-id://ainxt/agent/role/coder/v3/run/run-1"
        );
        assert_eq!(actor.def_ref, "def:role/coder@v3");
        assert_eq!(actor.run_id, "run-1");
        assert_eq!(actor.obo_user_id, "u-alice");
        assert_eq!(actor.control_commit_sha, "commit-abc");
        assert_eq!(actor.attestation_ref, "m-coder-ok");
        assert_eq!(actor.key_id, "key-v1");
        // The compact label the &str event-log actor field receives carries the full composite.
        let label = awc.actor_label();
        assert!(label.contains("run/run-1"));
        assert!(label.contains("obo=u-alice"));
        assert!(label.contains("commit=commit-abc"));
        // Two Runs of the same role produce DISTINCT actor records (not a shared token).
        let awc2 = aia.issue(&req("run-2"), &quote(), LogicalTime(10)).unwrap();
        assert_ne!(awc.actor_of_record(), awc2.actor_of_record());
    }

    // ---- IDN-08: kill-switch authority gating + audit (§19) --------------
    #[test]
    fn gap_idn_08_kill_switch_pull_requires_authority_and_is_audited() {
        let mut ks = KillSwitch::new();
        // A non-approver cannot pull.
        assert_eq!(
            ks.pull_authorized(KillScope::Workforce, "u-bob", 2, false, LogicalTime(5))
                .unwrap_err(),
            KillSwitchAuthError::NotApprover("u-bob".to_string())
        );
        // A too-junior approver (ad_level 6 > 3) cannot pull.
        assert_eq!(
            ks.pull_authorized(KillScope::Workforce, "u-carol", 6, true, LogicalTime(5))
                .unwrap_err(),
            KillSwitchAuthError::InsufficientSeniority {
                ad_level: 6,
                max: 3
            }
        );
        // Nothing was engaged or audited by the refused pulls.
        assert!(ks.audit_log().is_empty());
        // A senior approver (ad_level 3, can_approve) succeeds and is audited with their identity.
        let record = ks
            .pull_authorized(KillScope::Workforce, "u-exec", 3, true, LogicalTime(7))
            .unwrap();
        assert_eq!(record.puller, "u-exec");
        assert_eq!(record.scope, KillScope::Workforce);
        assert_eq!(record.at, LogicalTime(7));
        assert_eq!(ks.audit_log().len(), 1);
        assert_eq!(ks.audit_log()[0].puller, "u-exec");
    }

    #[test]
    fn gap_idn_08_authorized_pull_actually_halts_issuance() {
        let mut aia = aia();
        aia.kill_switch_mut()
            .pull_authorized(KillScope::Workforce, "u-exec", 1, true, LogicalTime(1))
            .unwrap();
        assert_eq!(
            aia.issue(&req("run-1"), &quote(), LogicalTime(1))
                .unwrap_err(),
            IssueError::KillSwitchActive
        );
    }

    // ---- IDN-09: UEBA baseline + deviation detector (§20) ----------------
    #[test]
    fn gap_idn_09_anomaly_detector_flags_behavioral_deviation() {
        // A triage role baseline: reads issues, egresses only to Jira; no settlement anything.
        let baseline = BehavioralBaseline::new("def:role/triage@v1")
            .with_capabilities(["issue:read", "issue:comment"])
            .with_egress(["jira.example.internal"])
            .with_max_action_rate(10.0)
            .with_max_cost_velocity(5.0);

        let mut monitor = AnomalyMonitor::new();

        // A normal window: within the envelope -> not anomalous, not flagged.
        let normal = ActivitySample {
            run_id: "run-triage-1".to_string(),
            def_ref: "def:role/triage@v1".to_string(),
            capabilities_used: ["issue:read".to_string()].into_iter().collect(),
            egress_destinations: ["jira.example.internal".to_string()].into_iter().collect(),
            action_rate: 3.0,
            cost_velocity: 1.0,
        };
        let a0 = monitor.observe(&baseline, &normal);
        assert!(!a0.is_anomalous());
        assert!(!monitor.is_flagged("run-triage-1"));

        // The weaponized/compromised window: the triage Run suddenly enumerates settlement tables,
        // egresses somewhere new, and spikes its rate + cost — every dimension deviates.
        let deviant = ActivitySample {
            run_id: "run-triage-1".to_string(),
            def_ref: "def:role/triage@v1".to_string(),
            capabilities_used: ["issue:read".to_string(), "settlement:enumerate".to_string()]
                .into_iter()
                .collect(),
            egress_destinations: ["settlement.example.internal".to_string()]
                .into_iter()
                .collect(),
            action_rate: 200.0,
            cost_velocity: 50.0,
        };
        let a1 = monitor.observe(&baseline, &deviant);
        assert!(
            a1.is_anomalous(),
            "actor-behavior deviation must be detected"
        );
        assert!(a1.deviations.contains(&Deviation::UnexpectedCapability(
            "settlement:enumerate".to_string()
        )));
        assert!(a1.deviations.contains(&Deviation::UnexpectedEgress(
            "settlement.example.internal".to_string()
        )));
        assert!(a1
            .deviations
            .iter()
            .any(|d| matches!(d, Deviation::ActionRateSpike { .. })));
        assert!(a1
            .deviations
            .iter()
            .any(|d| matches!(d, Deviation::CostVelocitySpike { .. })));
        // The strongest lever: the Run is now flagged, so its next renewal is choked.
        assert!(monitor.is_flagged("run-triage-1"));
    }

    #[test]
    fn gap_idn_09_detected_anomaly_chokes_renewal_end_to_end() {
        // The detector's flag composes with the renewal choke: a flagged Run cannot renew.
        let mut aia = aia();
        let awc = aia.issue(&req("run-x"), &quote(), LogicalTime(1)).unwrap();
        let baseline =
            BehavioralBaseline::new("def:role/coder@v3").with_capabilities(["repo:read"]);
        let deviant = ActivitySample {
            run_id: "run-x".to_string(),
            def_ref: "def:role/coder@v3".to_string(),
            capabilities_used: ["settlement:release".to_string()].into_iter().collect(),
            ..Default::default()
        };
        let assessment = aia.anomaly_mut().observe(&baseline, &deviant);
        assert!(assessment.is_anomalous());
        assert_eq!(
            aia.renew(&awc, None, LogicalTime(2)).unwrap_err(),
            RenewError::AnomalyChoke("run-x".to_string())
        );
    }

    // ---- IDN-10: renewal-throughput capacity load test (§22 #16) ---------
    #[test]
    fn gap_idn_10_renewal_throughput_capacity_model_and_concurrent_load() {
        use std::sync::Arc;
        use std::thread;

        // Capacity model (§15): N concurrent Runs, TTL T ticks; sustained renewal rate ~ N/T,
        // ~x1.3 with retry margin. For N=5000, T=300s: ~16.7/s, ~21.7/s with margin — within the
        // §22 #16 band of 17-22/s.
        const N: usize = 5_000;
        const TTL_SECS: f64 = 300.0;
        let sustained = N as f64 / TTL_SECS;
        let with_margin = sustained * 1.3;
        assert!(
            (17.0..=22.0).contains(&with_margin),
            "capacity model {with_margin:.1}/s must land in the §22 #16 band"
        );

        // Build an AIA whose projection is valid for the whole window, and ISSUE N per-Run AWCs.
        // TTL is large enough that the window covers >= 2 renewal cycles; freshness never lapses.
        let mut aia = IdentityAuthority::new(
            verifier(),
            ControlPlaneProjection::new(
                ["def:role/coder@v3".to_string()],
                LogicalTime(0),
                "commit-load",
            ),
            1_000_000,
            1_000_000,
            "key-load",
        );
        let mut creds = Vec::with_capacity(N);
        for i in 0..N {
            let c = aia
                .issue(&req(&format!("run-{i}")), &quote(), LogicalTime(1))
                .unwrap();
            creds.push(c);
        }
        assert_eq!(creds.len(), N);

        // Renew concurrently across threads for >= 2 TTL cycles. `renew(&self)` reads only the
        // in-memory projection / kill-switch / anomaly / revocation state — there is NO git handle
        // on the type at all, so "zero git reads on the renewal path" is structural, not hoped-for.
        let aia = Arc::new(aia);
        let creds = Arc::new(creds);
        const THREADS: usize = 8;
        const CYCLES: usize = 2;
        let mut handles = Vec::new();
        for tix in 0..THREADS {
            let aia = Arc::clone(&aia);
            let creds = Arc::clone(&creds);
            handles.push(thread::spawn(move || {
                let mut ok = 0usize;
                for cycle in 0..CYCLES {
                    let mut i = tix;
                    while i < creds.len() {
                        // Per-Run renewal-time jitter so renewals spread across the TTL window,
                        // never a thundering herd at the T-boundary (the §15 jitter discipline).
                        let jitter = (i % 17) as u64;
                        let now = LogicalTime(10 + cycle as u64 * 100 + jitter);
                        if aia.renew(&creds[i], None, now).is_ok() {
                            ok += 1;
                        }
                        i += THREADS;
                    }
                }
                ok
            }));
        }
        let total_ok: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();
        assert_eq!(
            total_ok,
            N * CYCLES,
            "every renewal across {CYCLES} cycles resolves against the in-memory projection"
        );

        // A definition deprecated mid-run drains within one TTL purely via projection sync (git
        // could be disconnected — the renewal path never touches it).
        let mut aia2 = IdentityAuthority::new(
            verifier(),
            ControlPlaneProjection::new(
                ["def:role/coder@v3".to_string()],
                LogicalTime(0),
                "commit-load",
            ),
            1_000_000,
            1_000_000,
            "key-load",
        );
        let c = aia2
            .issue(&req("run-drain"), &quote(), LogicalTime(1))
            .unwrap();
        assert!(aia2.renew(&c, None, LogicalTime(2)).is_ok());
        aia2.projection_mut().deprecate("def:role/coder@v3");
        assert_eq!(
            aia2.renew(&c, None, LogicalTime(3)).unwrap_err(),
            RenewError::DefinitionNoLongerValid("def:role/coder@v3".to_string())
        );
    }
}
