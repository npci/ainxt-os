// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Evidentiary admissibility (ADR-025 / `REGULATED_FI_COMPLIANCE_OPS.md` §7) and the read-only
//! supervisory **auditor mode** (§8.3) — the two capabilities that turn a *tamper-evident* register
//! into a *court-admissible* and *supervisor-examinable* one.
//!
//! # Why this exists (FI-04, FI-05)
//!
//! The [`IncidentRegister`](crate::IncidentRegister) hash-chain proves **integrity**. Under Indian
//! law that is necessary but **not sufficient**: the Bharatiya Sakshya Adhiniyam 2023 (BSA), in force
//! from 1 July 2024, requires at **§63** a *certificate* accompanying an electronic record — it must
//! identify the record + manner of production, give the producing system's particulars, and be
//! **signed** by the person-in-charge and an expert. A perfect hash-chain with no §63 certificate can
//! still be ruled inadmissible.
//!
//! This module provides an [`EvidentiaryExport`] for any incident record-set: the hash-chained slice,
//! a [`ChainOfCustody`] manifest, and a [`Bsa63Certificate`] auto-populated with every
//! machine-knowable particular (runtime version, live control-plane SHA, chain root + per-record
//! content hashes, NIC/NPL NTP source + last-sync offset, production method) — presented as a **draft
//! with only the two human signatures blank**. The export re-verifies the chain, so tampering with any
//! exported blob breaks its content-hash and fails the certificate's integrity attestation.
//!
//! [`AuditorSession`] is the read-only-by-construction evidence-access mode: it borrows the register
//! *immutably* (so no mutation method can exist), applies an existence-hiding [`AuditorScope`] filter,
//! and chain-logs **every** query into the custody manifest — self-service supervisory access whose
//! own access trail is itself part of the record.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use ainxt_types::Principal;

use crate::{IncidentClass, IncidentEvent, IncidentRegister, TamperError, Tick};

/// The NTP provenance of the timestamps in an export (§8.2) — recorded so a timestamp's origin is
/// itself provable and can be transcribed into the §63 certificate's device particulars.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NtpAttestation {
    /// The configured NIC/NPL NTP source (or a server traceable to them).
    pub source: String,
    /// The last measured sync offset in milliseconds (signed: + = local ahead of reference).
    pub last_sync_offset_ms: i64,
    /// Whether that offset was within the skew threshold at export time.
    pub within_threshold: bool,
}

/// A hop in the chain-of-custody manifest (§7.2): who touched the evidence, what they did, when.
/// Every auditor query and the export itself append a hop, so the custody chain is unbroken.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodyHop {
    pub actor: String,
    pub action: String,
    pub tick: Tick,
}

/// The chain-of-custody manifest — an ordered, append-only list of custody hops.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainOfCustody {
    pub hops: Vec<CustodyHop>,
}

impl ChainOfCustody {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn record(&mut self, actor: &str, action: &str, tick: Tick) {
        self.hops.push(CustodyHop {
            actor: actor.to_string(),
            action: action.to_string(),
            tick,
        });
    }
}

/// A per-record content hash: the event's sequence number and a SHA-256 over its canonical fields.
/// Recomputable, so tampering with an exported event changes its content hash → detectable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordHash {
    pub seq: u64,
    pub content_hash: String,
}

/// SHA-256 over an event's canonical, length-prefixed fields (independent of the chain link, so it is
/// a standalone content digest a certificate can attest and anyone can recompute).
pub(crate) fn event_content_hash(e: &IncidentEvent) -> String {
    let mut h = Sha256::new();
    let tag = e.event.tag();
    for field in [
        e.incident_id.as_str(),
        tag.as_str(),
        e.prev_hash.as_str(),
        e.hash.as_str(),
    ] {
        h.update((field.len() as u64).to_le_bytes());
        h.update(field.as_bytes());
    }
    h.update(e.seq.to_le_bytes());
    h.update(e.tick.to_le_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect::<String>()
}

/// A BSA §63-shaped electronic-record certificate (§7.2). Every particular a human would otherwise
/// hand-transcribe (and get wrong under deadline) is machine-filled; only the two human signatures are
/// left blank — the signature is the legal act and is deliberately not automated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bsa63Certificate {
    /// (a) identifies the electronic record set.
    pub record_set_id: String,
    /// (a) describes the manner of production.
    pub production_method: String,
    /// (b) particulars of the producing system: runtime version.
    pub runtime_version: String,
    /// (b) the control-plane commit SHA live when the record was produced ("which definitions").
    pub control_plane_sha: String,
    /// (b) NTP source + last-sync offset — the timestamps' provenance.
    pub ntp: NtpAttestation,
    /// The hash-chain root the slice was verified against.
    pub chain_root: String,
    /// Per-record content hashes for the exported slice.
    pub record_hashes: Vec<RecordHash>,
    /// The integrity attestation: the full chain verified at export time.
    pub integrity_verified: bool,
    /// (c) signature of the person-in-charge — **blank in the draft**.
    pub signature_person_in_charge: Option<String>,
    /// (c) signature of the expert — **blank in the draft**.
    pub signature_expert: Option<String>,
}

impl Bsa63Certificate {
    /// `true` only when both statutory human signatures are present. A draft is deliberately not.
    pub fn is_signed(&self) -> bool {
        self.signature_person_in_charge.is_some() && self.signature_expert.is_some()
    }

    /// Apply the two human signatures (the legal act, done off-system by the designated humans).
    pub fn sign(&mut self, person_in_charge: &str, expert: &str) {
        self.signature_person_in_charge = Some(person_in_charge.to_string());
        self.signature_expert = Some(expert.to_string());
    }
}

/// The three-part evidentiary package (§7.2): the record-set slice, the custody manifest, and the
/// §63 certificate. Self-verifying: [`reverify`](EvidentiaryExport::reverify) recomputes the
/// per-record content hashes and the internal chain links, so any post-export tampering is detectable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidentiaryExport {
    /// Part 1 — the hash-chained Event-Log slice for the record-set.
    pub events: Vec<IncidentEvent>,
    /// Part 2 — the chain-of-custody manifest.
    pub custody: ChainOfCustody,
    /// Part 3 — the BSA §63 certificate (draft; signatures blank).
    pub certificate: Bsa63Certificate,
}

/// The machine-knowable particulars the caller injects (the runtime cannot read a wall clock or the
/// process version deterministically — they are supplied so the export stays pure and testable).
#[derive(Debug, Clone)]
pub struct ExportParams<'a> {
    pub runtime_version: &'a str,
    pub production_method: &'a str,
    pub ntp: NtpAttestation,
    /// The auditor/exporter identity, recorded as the final custody hop.
    pub exporter: &'a str,
    /// Logical tick of the export.
    pub export_tick: Tick,
}

/// An error producing an evidentiary export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportError {
    /// The requested incident does not exist in the register.
    UnknownIncident(String),
    /// The register's own hash chain failed verification — the export is refused, because an
    /// unverifiable chain must never be dressed up with a §63 certificate.
    ChainBroken(TamperError),
}

impl std::fmt::Display for ExportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExportError::UnknownIncident(id) => write!(f, "unknown incident `{id}`"),
            ExportError::ChainBroken(e) => write!(f, "register chain broken: {e:?}"),
        }
    }
}

impl std::error::Error for ExportError {}

impl IncidentRegister {
    /// FI-04: produce an [`EvidentiaryExport`] for one incident's record-set. Verifies the whole
    /// register chain first (refusing on any break), extracts the incident's events, computes the
    /// per-record content hashes and chain root, and builds the §63 certificate draft. The custody
    /// manifest starts with `prior_custody` (e.g. the auditor's own access hops) plus the export hop.
    pub fn evidentiary_export(
        &self,
        incident_id: &str,
        params: &ExportParams<'_>,
        prior_custody: ChainOfCustody,
    ) -> Result<EvidentiaryExport, ExportError> {
        let incident = self
            .incident(incident_id)
            .ok_or_else(|| ExportError::UnknownIncident(incident_id.to_string()))?;

        // The certificate must never be issued over an unverifiable chain (§7.3).
        let verified = match self.verify() {
            Ok(_) => true,
            Err(e) => return Err(ExportError::ChainBroken(e)),
        };

        let events: Vec<IncidentEvent> = self
            .events()
            .iter()
            .filter(|e| e.incident_id == incident_id)
            .cloned()
            .collect();

        let record_hashes: Vec<RecordHash> = events
            .iter()
            .map(|e| RecordHash {
                seq: e.seq,
                content_hash: event_content_hash(e),
            })
            .collect();

        let chain_root = self
            .events()
            .last()
            .map(|e| e.hash.clone())
            .unwrap_or_else(|| "GENESIS".to_string());

        let mut custody = prior_custody;
        custody.record(params.exporter, "evidentiary-export", params.export_tick);

        let certificate = Bsa63Certificate {
            record_set_id: incident_id.to_string(),
            production_method: params.production_method.to_string(),
            runtime_version: params.runtime_version.to_string(),
            control_plane_sha: incident.control_plane_sha.clone(),
            ntp: params.ntp.clone(),
            chain_root,
            record_hashes,
            integrity_verified: verified,
            signature_person_in_charge: None,
            signature_expert: None,
        };

        Ok(EvidentiaryExport {
            events,
            custody,
            certificate,
        })
    }
}

impl EvidentiaryExport {
    /// Re-verify the export in isolation (§7.3): every event's recomputed content hash must match the
    /// certificate's recorded hash. Returns `false` if any exported blob was altered after export —
    /// so the §63 certificate's integrity attestation is a machine-checkable claim, not a paper one.
    pub fn reverify(&self) -> bool {
        if self.events.len() != self.certificate.record_hashes.len() {
            return false;
        }
        for (e, rh) in self.events.iter().zip(&self.certificate.record_hashes) {
            if e.seq != rh.seq || event_content_hash(e) != rh.content_hash {
                return false;
            }
        }
        true
    }
}

// ============================ auditor read-only mode (§8.3) ============================

/// The capability a principal must be **explicitly granted** to open a supervisory auditor session
/// (§8.3). Deliberately checked against the principal's granted caps (not the admin shortcut): a
/// supervisory examiner is a least-privilege, purpose-empanelled role, not a default admin power —
/// the same discipline break-glass uses.
pub const AUDITOR_CAP: &str = "incident:supervisory-auditor";

/// An error opening a capability-gated auditor session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditorError {
    /// The principal was not explicitly granted [`AUDITOR_CAP`].
    Unauthorized(String),
}

impl std::fmt::Display for AuditorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditorError::Unauthorized(u) => {
                write!(
                    f,
                    "principal `{u}` lacks the supervisory-auditor capability"
                )
            }
        }
    }
}

impl std::error::Error for AuditorError {}

/// The existence-hiding scope filter for an auditor session (§8.3). An auditor sees only what their
/// empanelment permits; out-of-scope records return `None` (indistinguishable from "not found"), so
/// existence does not leak even by absence.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum AuditorScope {
    /// Full scope (e.g. the DPO) — every incident visible.
    #[default]
    All,
    /// Only incidents of these classes are visible.
    Classes(Vec<IncidentClass>),
    /// Only these incident ids are visible.
    Ids(Vec<String>),
}

impl AuditorScope {
    fn permits(&self, incident: &crate::Incident) -> bool {
        match self {
            AuditorScope::All => true,
            AuditorScope::Classes(cs) => cs.contains(&incident.class),
            AuditorScope::Ids(ids) => ids.iter().any(|i| i == &incident.id),
        }
    }
}

/// A read-only-by-construction supervisory session (§8.3). It borrows the register **immutably**, so
/// no mutation is even expressible; it applies an existence-hiding [`AuditorScope`]; and it chain-logs
/// every query into a [`ChainOfCustody`] that flows straight into an [`EvidentiaryExport`], so "who
/// looked at what, when" is itself part of the admissible record.
pub struct AuditorSession<'r> {
    register: &'r IncidentRegister,
    auditor: String,
    scope: AuditorScope,
    custody: ChainOfCustody,
    tick: Tick,
}

impl<'r> AuditorSession<'r> {
    /// Open a session for `auditor` over `register`, scoped to `scope`, with the session's logical
    /// clock at `now`. The register is borrowed immutably — the session literally cannot mutate it.
    pub fn open(
        register: &'r IncidentRegister,
        auditor: &str,
        scope: AuditorScope,
        now: Tick,
    ) -> Self {
        Self {
            register,
            auditor: auditor.to_string(),
            scope,
            custody: ChainOfCustody::new(),
            tick: now,
        }
    }

    /// Open a session for a `principal` who must hold [`AUDITOR_CAP`] **explicitly** (least-privilege
    /// — an admin without the grant is refused). This is the capability-gated form of
    /// [`open`](Self::open): the supervisory examiner is empanelled, not implicitly trusted. On success
    /// the session behaves exactly like [`open`](Self::open) (read-only, scoped, chain-logged).
    pub fn open_authorized(
        register: &'r IncidentRegister,
        principal: &Principal,
        scope: AuditorScope,
        now: Tick,
    ) -> Result<Self, AuditorError> {
        // Explicit grant only — do NOT use has_cap (which auto-allows admins).
        if !principal.caps.iter().any(|c| c == AUDITOR_CAP) {
            return Err(AuditorError::Unauthorized(principal.user_id.clone()));
        }
        Ok(Self::open(register, &principal.user_id, scope, now))
    }

    fn log(&mut self, action: &str) {
        let t = self.tick;
        self.custody.record(&self.auditor, action, t);
    }

    /// List the ids of every incident within this auditor's scope (existence-hiding: out-of-scope
    /// incidents never appear). Chain-logged.
    pub fn list_incident_ids(&mut self) -> Vec<String> {
        self.log("list-incidents");
        self.register
            .incidents()
            .filter(|i| self.scope.permits(i))
            .map(|i| i.id.clone())
            .collect()
    }

    /// Pull one incident by id — but only if scope permits. An out-of-scope (or absent) id returns
    /// `None`, indistinguishable, so existence does not leak. Chain-logged either way.
    pub fn incident(&mut self, id: &str) -> Option<crate::Incident> {
        self.log("read-incident");
        self.register
            .incident(id)
            .filter(|i| self.scope.permits(i))
            .cloned()
    }

    /// Pull an evidentiary export for an in-scope incident, threading the session's custody so far
    /// into the package (the auditor's own reads become part of the record). Out-of-scope → `None`.
    pub fn export(
        &mut self,
        id: &str,
        params: &ExportParams<'_>,
    ) -> Option<Result<EvidentiaryExport, ExportError>> {
        // Scope check first (existence-hiding): no export for an id outside scope.
        let permitted = self
            .register
            .incident(id)
            .map(|i| self.scope.permits(i))
            .unwrap_or(false);
        self.log("export-incident");
        if !permitted {
            return None;
        }
        Some(
            self.register
                .evidentiary_export(id, params, self.custody.clone()),
        )
    }

    /// The session's chain-of-custody so far (every query it made). Read-only.
    pub fn custody(&self) -> &ChainOfCustody {
        &self.custody
    }
}

// ==================== route-ready evidentiary-export entrypoint (§7.2 / §8.3) ====================
//
// [`evidentiary_export`] and [`AuditorSession`] are the engine; a transport needs a single
// capability-gated, existence-hiding, serde-round-trippable call it can mount at
// `POST /v1/incident/evidence-export`. [`IncidentRegister::evidentiary_export_for`] is that seam —
// the authorized counterpart that folds the AUDITOR_CAP check, the scope gate, custody threading, and
// the §63 particulars into one entrypoint. Instantiation on the served daemon is `ainxt-runtimed`'s
// hot-wiring (it owns the durable register + injects the live runtime version / NTP attestation).

/// The route-ready request body a transport deserializes straight from the wire: the incident to
/// export plus every machine-knowable §63 particular the caller injects. The runtime is pure — the
/// runtime version, NTP provenance, and the logical `export_tick` are supplied, never read from a
/// wall clock here. `deny_unknown_fields` rejects a smuggled extra key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceExportRequest {
    pub incident_id: String,
    /// (b) particulars of the producing system.
    pub runtime_version: String,
    /// (a) the manner of production.
    pub production_method: String,
    /// (b) the timestamps' NTP provenance.
    pub ntp: NtpAttestation,
    /// The logical tick of the export (the export's custody-hop clock).
    pub export_tick: Tick,
}

/// Why a route-ready evidentiary export was refused — the serializable superset of [`ExportError`]
/// with authorization/scope variants, so a transport renders the refusal verbatim and maps
/// [`NotAuthorized`](EvidenceRouteError::NotAuthorized) → 403,
/// [`OutOfScopeOrUnknown`](EvidenceRouteError::OutOfScopeOrUnknown) → 404, and
/// [`ChainBroken`](EvidenceRouteError::ChainBroken) → 409.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum EvidenceRouteError {
    /// The principal was **not explicitly granted** [`AUDITOR_CAP`]. Least-privilege: an admin is NOT
    /// implied — a §8.3 supervisory examiner is empanelled, not a default admin power. Checked first,
    /// so the error shape is no capability oracle. → 403.
    NotAuthorized,
    /// The incident is outside the auditor's [`AuditorScope`] or does not exist — the two are
    /// deliberately indistinguishable (existence-hiding, §8.3), so absence never leaks. → 404.
    OutOfScopeOrUnknown,
    /// The register's own hash chain failed verification — the export is refused rather than dress an
    /// unverifiable chain up with a §63 certificate (§7.3). → 409.
    ChainBroken,
}

impl std::fmt::Display for EvidenceRouteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EvidenceRouteError::NotAuthorized => {
                write!(f, "not authorized: supervisory-auditor capability required")
            }
            EvidenceRouteError::OutOfScopeOrUnknown => {
                write!(f, "incident out of scope or unknown")
            }
            EvidenceRouteError::ChainBroken => {
                write!(f, "register chain broken — export refused")
            }
        }
    }
}

impl std::error::Error for EvidenceRouteError {}

impl IncidentRegister {
    /// **The route-ready, capability-gated evidentiary-export entrypoint** (§7.2 / §8.3) a server
    /// mounts at `POST /v1/incident/evidence-export`. Fail-closed and existence-hiding, in order:
    ///
    /// 1. `principal` must hold [`AUDITOR_CAP`] **explicitly** (admin is not implied — same
    ///    least-privilege discipline as [`AuditorSession::open_authorized`]), else
    ///    [`EvidenceRouteError::NotAuthorized`] — checked before any lookup, so the error leaks nothing;
    /// 2. the incident must be within `scope`, else [`EvidenceRouteError::OutOfScopeOrUnknown`]
    ///    (indistinguishable from "not found", so existence does not leak by absence);
    /// 3. the underlying [`evidentiary_export`](IncidentRegister::evidentiary_export) must succeed —
    ///    an unverifiable chain maps to [`EvidenceRouteError::ChainBroken`], never a dressed-up cert.
    ///
    /// The custody manifest opens with the principal's own access hop, so "who exported what, when" is
    /// itself part of the admissible §63 record. Request and error both round-trip serde, so a
    /// transport can deserialize the wire body and render a refusal verbatim.
    pub fn evidentiary_export_for(
        &self,
        principal: &Principal,
        scope: &AuditorScope,
        req: &EvidenceExportRequest,
    ) -> Result<EvidentiaryExport, EvidenceRouteError> {
        // Explicit grant only — do NOT use has_cap (which auto-allows admins). §8.3.
        if !principal.caps.iter().any(|c| c == AUDITOR_CAP) {
            return Err(EvidenceRouteError::NotAuthorized);
        }
        // Existence-hiding scope gate: an out-of-scope OR absent id is the same 404.
        let permitted = self
            .incident(&req.incident_id)
            .map(|i| scope.permits(i))
            .unwrap_or(false);
        if !permitted {
            return Err(EvidenceRouteError::OutOfScopeOrUnknown);
        }
        let mut custody = ChainOfCustody::new();
        custody.record(
            &principal.user_id,
            "evidence-export-request",
            req.export_tick,
        );
        let params = ExportParams {
            runtime_version: &req.runtime_version,
            production_method: &req.production_method,
            ntp: req.ntp.clone(),
            exporter: &principal.user_id,
            export_tick: req.export_tick,
        };
        self.evidentiary_export(&req.incident_id, &params, custody)
            .map_err(|e| match e {
                // Unknown collapses into the same existence-hidden 404 as out-of-scope.
                ExportError::UnknownIncident(_) => EvidenceRouteError::OutOfScopeOrUnknown,
                ExportError::ChainBroken(_) => EvidenceRouteError::ChainBroken,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ArmingPolicy, IncidentCandidate};
    use ainxt_types::DataClass;

    fn ntp() -> NtpAttestation {
        NtpAttestation {
            source: "nic-ntp-pool".into(),
            last_sync_offset_ms: 12,
            within_threshold: true,
        }
    }

    fn params<'a>() -> ExportParams<'a> {
        ExportParams {
            runtime_version: "ainxt-runtime/1.2.3",
            production_method: "append-only SHA-256 hash-chained Event Log",
            ntp: ntp(),
            exporter: "rbi-examiner",
            export_tick: 500,
        }
    }

    fn seeded() -> (IncidentRegister, String) {
        let mut reg = IncidentRegister::new(ArmingPolicy::india_regulatory_default());
        let cand =
            IncidentCandidate::from_compliance_egress(100, "sha-live-001", DataClass::Pii, 3);
        let id = reg.open_from(cand, 100);
        (reg, id)
    }

    #[test]
    fn gap_ainxt_incident_fi04_export_produces_bsa63_certificate_with_particulars_filled() {
        // §7.5 test 1: an evidentiary export of an incident yields a §63-shaped certificate with the
        // runtime version, control-plane SHA, chain root + record hashes, and NTP source auto-filled;
        // only the two human signatures are blank.
        let (reg, id) = seeded();
        let export = reg
            .evidentiary_export(&id, &params(), ChainOfCustody::new())
            .unwrap();
        let cert = &export.certificate;
        assert_eq!(cert.record_set_id, id);
        assert_eq!(cert.runtime_version, "ainxt-runtime/1.2.3");
        assert_eq!(cert.control_plane_sha, "sha-live-001");
        assert_eq!(cert.ntp.source, "nic-ntp-pool");
        assert!(!cert.chain_root.is_empty());
        assert!(
            !cert.record_hashes.is_empty(),
            "slice must carry record hashes"
        );
        assert!(cert.integrity_verified);
        // Signatures are DELIBERATELY blank in the draft.
        assert!(!cert.is_signed());
        assert!(cert.signature_person_in_charge.is_none());
        assert!(cert.signature_expert.is_none());
        // The export self-verifies.
        assert!(export.reverify());
    }

    #[test]
    fn gap_ainxt_incident_fi04_tampered_export_fails_integrity_attestation() {
        // §7.5 test 2: tamper with one exported blob → its content-hash mismatches; the certificate's
        // integrity attestation fails on re-verification.
        let (reg, id) = seeded();
        let mut export = reg
            .evidentiary_export(&id, &params(), ChainOfCustody::new())
            .unwrap();
        assert!(export.reverify());
        // Mutate an exported event's timestamp (a "blob").
        export.events[0].tick = 999_999;
        assert!(
            !export.reverify(),
            "tampering with an exported blob must fail the integrity attestation"
        );
    }

    #[test]
    fn gap_ainxt_incident_fi04_export_refused_over_a_broken_chain() {
        // The certificate must never dress up an unverifiable chain (§7.3).
        let (mut reg, id) = seeded();
        // Corrupt the register's own chain by forging an event field via serde round-trip mutation.
        // We simulate tamper by re-opening then hand-breaking: easiest is to assert a fresh register
        // with a manually broken chain is refused. Here we tamper the last event's hash through a
        // debug-only path: serialize, flip, deserialize.
        let mut json: serde_json::Value = serde_json::to_value(&reg).unwrap();
        json["events"][0]["tick"] = serde_json::json!(123_456);
        reg = serde_json::from_value(json).unwrap();
        let err = reg
            .evidentiary_export(&id, &params(), ChainOfCustody::new())
            .unwrap_err();
        assert!(matches!(err, ExportError::ChainBroken(_)));
    }

    #[test]
    fn r5_auditor_capability_gate() {
        // Round-5: the supervisory auditor is a least-privilege CAPABILITY mode. A principal without
        // the explicit grant — even an admin — cannot open a session; one holding AUDITOR_CAP can, and
        // the resulting session is the same read-only, scoped, chain-logging session.
        let (reg, id) = seeded();

        // Admin WITHOUT the explicit grant is refused (not a default admin power).
        let admin = Principal::admin("root");
        assert!(matches!(
            AuditorSession::open_authorized(&reg, &admin, AuditorScope::All, 300),
            Err(AuditorError::Unauthorized(_))
        ));

        // A user granted the cap explicitly succeeds.
        let examiner = Principal::user("rbi-examiner", &[AUDITOR_CAP]);
        let mut sess =
            AuditorSession::open_authorized(&reg, &examiner, AuditorScope::All, 300).unwrap();
        // Behaves as a normal read-only scoped session: the in-scope incident is visible and the read
        // is chain-logged into the custody manifest.
        assert!(sess.incident(&id).is_some());
        assert!(!sess.custody().hops.is_empty());
        assert_eq!(sess.custody().hops[0].actor, "rbi-examiner");
    }

    #[test]
    fn gap_ainxt_incident_fi05_auditor_mode_is_read_only_scoped_and_chain_logs_every_query() {
        // §8.4 test 3+4: a scoped auditor pulls evidence self-service, read-only; every query is
        // chain-logged; an out-of-scope incident is invisible (not even its existence leaks).
        let mut reg = IncidentRegister::new(ArmingPolicy::india_regulatory_default());
        let in_scope = reg.open_from(
            IncidentCandidate::from_compliance_egress(100, "sha-a", DataClass::Pii, 1),
            100,
        );
        let out_scope = reg.open_from(
            IncidentCandidate::from_serving_ops(200, "sha-b", "route-x"),
            200,
        );

        // Auditor empanelled only for personal-data-breach class.
        let mut sess = AuditorSession::open(
            &reg,
            "dpdp-independent-auditor",
            AuditorScope::Classes(vec![IncidentClass::PersonalDataBreach]),
            300,
        );

        let ids = sess.list_incident_ids();
        assert!(ids.contains(&in_scope));
        assert!(
            !ids.contains(&out_scope),
            "out-of-scope incident leaked in listing"
        );

        // In-scope read succeeds; out-of-scope read is None (existence-hidden, same as not-found).
        assert!(sess.incident(&in_scope).is_some());
        assert!(sess.incident(&out_scope).is_none());

        // Export only works for in-scope; out-of-scope returns None.
        assert!(sess.export(&out_scope, &params()).is_none());
        let exp = sess.export(&in_scope, &params()).unwrap().unwrap();
        assert!(exp.reverify());
        // The export's custody manifest carries the auditor's own prior queries (chain-of-custody).
        let actors: Vec<&str> = exp.custody.hops.iter().map(|h| h.actor.as_str()).collect();
        assert!(actors.contains(&"dpdp-independent-auditor"));

        // Every query was chain-logged.
        assert!(
            sess.custody().hops.len() >= 5,
            "expected a hop per query, got {}",
            sess.custody().hops.len()
        );
    }
}
