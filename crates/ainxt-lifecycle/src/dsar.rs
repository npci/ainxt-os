// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! DSAR workflow — Data-Subject Access Request state machine (`REGULATED_FI_COMPLIANCE_OPS.md`
//! §4.4; DPDP access/correction/erasure/grievance rights).
//!
//! A DSAR is a **governed, SLA-clocked** operation over the data plane. The four load-bearing
//! properties the design demands, all implemented here as deterministic logic (logical ticks passed
//! in — no clock, no RNG, no I/O):
//!
//! 1. **Identity-proofing gates every DSAR** — no fulfilment (access export, erasure, correction)
//!    proceeds until the request is authenticated. An un-proofed access request is refused, so a
//!    DSAR can never become a self-service data-leak channel.
//! 2. **Cross-tier lineage resolution** — an access/portability export resolves the subject's data
//!    across *every* tier through the [`LineageResolver`] seam (Redis/Postgres/KG/embeddings/traces
//!    in production; any deterministic resolver here). [`MultiTierLineage`] fans out and merges, so
//!    "find *everything* about this person" is complete, not best-effort.
//! 3. **Erasure runs through the retention/hold precedence** — an erasure DSAR calls
//!    [`RecordStore::request_erasure`](crate::RecordStore::request_erasure), so a held or
//!    floor-bound record is deferred-with-record (§6), and the subject receives the
//!    "honored to the extent legally permissible" notice.
//! 4. **A hash-chained DSAR register** — every state transition is an append-only, hash-chained
//!    [`DsarEvent`]; [`DsarRegister::verify`] recomputes the chain so fulfilment is *provable* and
//!    tamper-evident to an auditor. The SLA clock ([`DsarRequest::is_overdue`]) makes a missed
//!    response window an explicit, queryable state, not a silent lapse.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

use ainxt_types::DataClass;

use crate::{ErasureResolution, RecordStore};

/// The DPDP right a DSAR exercises.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DsarKind {
    /// Right to access (a copy of the data held).
    Access,
    /// Right to data portability (a machine-readable export).
    Portability,
    /// Right to correction.
    Correction,
    /// Right to erasure.
    Erasure,
    /// A grievance to be routed to the DPO.
    Grievance,
}

/// The lifecycle state of a DSAR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DsarStatus {
    /// Opened, awaiting identity proofing.
    Received,
    /// Identity proofing failed — terminal, nothing fulfilled (no leak).
    IdentityRejected,
    /// Authenticated; ready to fulfil.
    InProgress,
    /// Fulfilled (access exported / corrected / erasure processed / grievance routed).
    Fulfilled,
    /// Non-terminal request whose SLA window has elapsed.
    Overdue,
}

impl DsarStatus {
    /// Terminal states carry no further obligation and stop the SLA clock.
    pub fn is_terminal(&self) -> bool {
        matches!(self, DsarStatus::IdentityRejected | DsarStatus::Fulfilled)
    }
}

/// One DSAR, with its SLA clock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DsarRequest {
    pub id: String,
    pub subject_id: String,
    pub kind: DsarKind,
    /// Logical tick the request was received (SLA anchor).
    pub opened_tick: u64,
    /// SLA budget in ticks (the DPDP response window; config-driven per the design).
    pub sla_ticks: u64,
    /// Whether identity proofing has succeeded — a hard precondition for any fulfilment.
    pub identity_proofed: bool,
    pub status: DsarStatus,
    /// Logical tick the request reached a terminal state, if it has.
    pub closed_tick: Option<u64>,
}

impl DsarRequest {
    /// The tick at which the SLA is breached (inclusive deadline is `opened + sla`). Saturating.
    pub fn deadline(&self) -> u64 {
        self.opened_tick.saturating_add(self.sla_ticks)
    }

    /// Whether the request is past its SLA deadline and not yet terminal at `now`.
    pub fn is_overdue(&self, now: u64) -> bool {
        !self.status.is_terminal() && now > self.deadline()
    }
}

/// A single tier's record about a subject, surfaced for a lineage/access export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineageRecord {
    /// The tier this record lives in (e.g. `"lifecycle-store"`, `"redis-session"`, `"kg"`).
    pub tier: String,
    pub record_id: String,
    pub subject_id: String,
    pub data_class: DataClass,
    /// A short, machine-readable description of the record (never the raw PII payload).
    pub summary: String,
}

/// The cross-tier lineage seam (§4.4 step 2). Production implementations wrap Redis/Postgres/KG/
/// embeddings/traces; any deterministic resolver satisfies the trait for offline testing.
pub trait LineageResolver {
    /// Every record this tier holds about `subject_id`.
    fn resolve(&self, subject_id: &str) -> Vec<LineageRecord>;
}

/// Fan-out lineage resolution across every registered tier, merged into one deterministic export.
/// This is what makes an access/portability response *complete* rather than best-effort.
#[derive(Default)]
pub struct MultiTierLineage {
    tiers: Vec<Box<dyn LineageResolver>>,
}

impl MultiTierLineage {
    pub fn new() -> Self {
        Self { tiers: Vec::new() }
    }

    /// Register a tier resolver (chainable).
    pub fn with_tier(mut self, tier: Box<dyn LineageResolver>) -> Self {
        self.tiers.push(tier);
        self
    }
}

impl LineageResolver for MultiTierLineage {
    fn resolve(&self, subject_id: &str) -> Vec<LineageRecord> {
        let mut out: Vec<LineageRecord> = self
            .tiers
            .iter()
            .flat_map(|t| t.resolve(subject_id))
            .collect();
        // Deterministic merge order: by tier, then record id.
        out.sort_by(|a, b| a.tier.cmp(&b.tier).then(a.record_id.cmp(&b.record_id)));
        out
    }
}

/// The [`RecordStore`] as a single lineage tier (the "lifecycle-store" tier).
impl LineageResolver for RecordStore {
    fn resolve(&self, subject_id: &str) -> Vec<LineageRecord> {
        self.records_for_subject(subject_id)
            .into_iter()
            .map(|r| LineageRecord {
                tier: "lifecycle-store".to_string(),
                record_id: r.id.clone(),
                subject_id: r.subject_id.clone(),
                data_class: r.data_class,
                summary: format!("record `{}` (class {})", r.id, r.data_class.as_str()),
            })
            .collect()
    }
}

// ============================ FI-09: provable cross-tier completeness ============================
//
// [`MultiTierLineage`] fans out, but nothing forced *which* tiers had to be present — a DSAR could
// silently omit a tier (KG, embeddings, traces) and still "succeed", making "find everything"
// best-effort. [`CompleteLineage`] closes that: it holds a **required-tier manifest** and, on resolve,
// reports which required tiers actually contributed and which are **missing** (registered but returned
// nothing is fine; *not registered at all* is a completeness failure). A DSAR access fulfilment can
// then refuse to certify completeness unless every mandated tier was queried — so a missing resolver
// is a detectable defect, not a silent gap. The real Redis/KG/embeddings/trace resolvers are the parent
// runtime's (reserved crates); this makes their *presence* a provable precondition.

/// The canonical set of data tiers a DPDP access export must span (§4.4 step 2). A deployment may
/// extend it; a tier absent from the registered resolvers makes an export **incomplete**.
pub const REQUIRED_DSAR_TIERS: &[&str] = &[
    "lifecycle-store",
    "redis-session",
    "postgres-episodic",
    "kg-memoryfact",
    "embeddings",
    "traces",
    "incident-register",
    "dsar-register",
];

/// The outcome of a complete-lineage resolve: the merged records plus the completeness proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineageExport {
    pub records: Vec<LineageRecord>,
    /// Required tiers that had a registered resolver (queried).
    pub covered_tiers: Vec<String>,
    /// Required tiers with **no** registered resolver — the export is not provably complete.
    pub missing_tiers: Vec<String>,
}

impl LineageExport {
    /// `true` only when every required tier had a registered resolver — "complete, not best-effort".
    pub fn is_complete(&self) -> bool {
        self.missing_tiers.is_empty()
    }
}

/// A completeness-checked cross-tier lineage resolver (§4.4 step 2). Each tier is registered under a
/// name; resolving computes the export and, against the required manifest, the missing tiers.
#[derive(Default)]
pub struct CompleteLineage {
    tiers: BTreeMap<String, Box<dyn LineageResolver>>,
    required: Vec<String>,
}

impl CompleteLineage {
    /// A resolver requiring the canonical [`REQUIRED_DSAR_TIERS`].
    pub fn with_default_required() -> Self {
        Self {
            tiers: BTreeMap::new(),
            required: REQUIRED_DSAR_TIERS.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// A resolver with an explicit required-tier manifest.
    pub fn new(required: &[&str]) -> Self {
        Self {
            tiers: BTreeMap::new(),
            required: required.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// Register a named tier resolver (chainable). The name must match a required-tier label for it
    /// to count toward completeness.
    pub fn with_named_tier(mut self, name: &str, resolver: Box<dyn LineageResolver>) -> Self {
        self.tiers.insert(name.to_string(), resolver);
        self
    }

    /// The required tiers not yet registered (a live "what would make a DSAR incomplete" view).
    pub fn missing_tiers(&self) -> Vec<String> {
        self.required
            .iter()
            .filter(|t| !self.tiers.contains_key(*t))
            .cloned()
            .collect()
    }

    /// Resolve the subject across every registered tier and report completeness against the manifest.
    pub fn resolve_complete(&self, subject_id: &str) -> LineageExport {
        let mut records: Vec<LineageRecord> = self
            .tiers
            .values()
            .flat_map(|t| t.resolve(subject_id))
            .collect();
        records.sort_by(|a, b| a.tier.cmp(&b.tier).then(a.record_id.cmp(&b.record_id)));
        let covered: Vec<String> = self
            .required
            .iter()
            .filter(|t| self.tiers.contains_key(*t))
            .cloned()
            .collect();
        LineageExport {
            records,
            covered_tiers: covered,
            missing_tiers: self.missing_tiers(),
        }
    }
}

impl LineageResolver for CompleteLineage {
    fn resolve(&self, subject_id: &str) -> Vec<LineageRecord> {
        self.resolve_complete(subject_id).records
    }
}

impl DsarRegister {
    /// FI-09: fulfil an access request with a **completeness-checked** cross-tier resolve. Returns the
    /// [`LineageExport`] (records + completeness proof). If `require_complete` and a mandated tier has
    /// no resolver, the fulfilment is **refused** ([`DsarError::IncompleteLineage`]) rather than
    /// certifying a best-effort export as done — so a missing tier can never silently under-report.
    pub fn fulfill_access_complete(
        &mut self,
        id: &str,
        lineage: &CompleteLineage,
        require_complete: bool,
        now: u64,
    ) -> Result<LineageExport, DsarError> {
        let kind = self
            .requests
            .get(id)
            .ok_or_else(|| DsarError::UnknownRequest(id.to_string()))?
            .kind;
        if kind != DsarKind::Access && kind != DsarKind::Portability {
            return Err(DsarError::WrongKind {
                expected: DsarKind::Access,
                got: kind,
            });
        }
        // Refuse *before* mutating state if completeness is required and unmet.
        if require_complete {
            let missing = lineage.missing_tiers();
            if !missing.is_empty() {
                return Err(DsarError::IncompleteLineage { missing });
            }
        }
        let req = self.ready_for(id, kind)?;
        let subject = req.subject_id.clone();
        let export = lineage.resolve_complete(&subject);
        req.status = DsarStatus::Fulfilled;
        req.closed_tick = Some(now);
        self.append(
            id,
            DsarAction::AccessExported {
                n_records: export.records.len(),
            },
            now,
        );
        Ok(export)
    }
}

/// What happened in the DSAR register — the payload of one hash-chained event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "action")]
pub enum DsarAction {
    Opened { kind: DsarKind, sla_ticks: u64 },
    IdentityProofed,
    IdentityRejected,
    AccessExported { n_records: usize },
    Corrected { n_records: usize },
    ErasureProcessed { erased: usize, deferred: usize },
    GrievanceRouted,
    MarkedOverdue,
}

impl DsarAction {
    /// A stable label used in the hash-chain input (canonical, not the Debug format).
    fn tag(&self) -> String {
        match self {
            DsarAction::Opened { kind, sla_ticks } => format!("opened:{kind:?}:{sla_ticks}"),
            DsarAction::IdentityProofed => "identity-proofed".into(),
            DsarAction::IdentityRejected => "identity-rejected".into(),
            DsarAction::AccessExported { n_records } => format!("access-exported:{n_records}"),
            DsarAction::Corrected { n_records } => format!("corrected:{n_records}"),
            DsarAction::ErasureProcessed { erased, deferred } => {
                format!("erasure-processed:{erased}:{deferred}")
            }
            DsarAction::GrievanceRouted => "grievance-routed".into(),
            DsarAction::MarkedOverdue => "marked-overdue".into(),
        }
    }
}

/// One hash-chained DSAR-register event. `hash` chains `prev_hash` + the canonical fields, so any
/// after-the-fact edit, reorder, or deletion breaks the chain (detected by [`DsarRegister::verify`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DsarEvent {
    pub seq: u64,
    pub request_id: String,
    pub action: DsarAction,
    pub tick: u64,
    pub prev_hash: String,
    pub hash: String,
}

const GENESIS: &str = "GENESIS";

/// SHA-256 hash-chain link over canonical, length-prefixed fields (a value boundary cannot be forged
/// by shifting bytes between adjacent fields). Deterministic: no wall clock, no RNG.
fn chain_hash(prev: &str, seq: u64, request_id: &str, action_tag: &str, tick: u64) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for field in [prev, request_id, action_tag] {
        h.update((field.len() as u64).to_le_bytes());
        h.update(field.as_bytes());
    }
    h.update(seq.to_le_bytes());
    h.update(tick.to_le_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect::<String>()
}

/// A detected break in the DSAR register's append-only hash chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DsarTamper {
    SeqGap { expected: u64, found: u64 },
    BrokenChain { seq: u64 },
    HashMismatch { seq: u64 },
}

/// An error from a DSAR operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DsarError {
    UnknownRequest(String),
    DuplicateRequest(String),
    /// A fulfilment was attempted before identity proofing (would leak / act without authentication).
    IdentityNotProofed(String),
    /// The operation does not match the request's kind (e.g. erasure on an access request).
    WrongKind {
        expected: DsarKind,
        got: DsarKind,
    },
    /// The request is already terminal and cannot be advanced.
    AlreadyTerminal(String),
    /// A completeness-required access fulfilment was refused because one or more mandated data tiers
    /// had no registered resolver — certifying it would under-report (§4.4 step 2 / FI-09).
    IncompleteLineage {
        missing: Vec<String>,
    },
}

impl fmt::Display for DsarError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DsarError::UnknownRequest(id) => write!(f, "unknown DSAR request `{id}`"),
            DsarError::DuplicateRequest(id) => write!(f, "duplicate DSAR request `{id}`"),
            DsarError::IdentityNotProofed(id) => {
                write!(f, "DSAR `{id}`: identity not proofed — fulfilment refused")
            }
            DsarError::WrongKind { expected, got } => {
                write!(f, "DSAR kind mismatch: expected {expected:?}, got {got:?}")
            }
            DsarError::AlreadyTerminal(id) => write!(f, "DSAR `{id}` is already terminal"),
            DsarError::IncompleteLineage { missing } => write!(
                f,
                "DSAR access refused — cross-tier lineage incomplete, missing tiers: {}",
                missing.join(", ")
            ),
        }
    }
}

impl std::error::Error for DsarError {}

/// The DSAR register: the live request table plus the append-only, hash-chained event log.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DsarRegister {
    requests: BTreeMap<String, DsarRequest>,
    events: Vec<DsarEvent>,
}

impl DsarRegister {
    pub fn new() -> Self {
        Self::default()
    }

    /// A read-only view of a request.
    pub fn request(&self, id: &str) -> Option<&DsarRequest> {
        self.requests.get(id)
    }

    /// All requests, id-sorted.
    pub fn requests(&self) -> impl Iterator<Item = &DsarRequest> {
        self.requests.values()
    }

    /// The append-only, hash-chained event log.
    pub fn events(&self) -> &[DsarEvent] {
        &self.events
    }

    /// Append a hash-chained event (internal). Seq is the next index; the chain links the prior hash.
    fn append(&mut self, request_id: &str, action: DsarAction, tick: u64) {
        let seq = self.events.len() as u64;
        let prev = self.events.last().map_or(GENESIS, |e| e.hash.as_str());
        let hash = chain_hash(prev, seq, request_id, &action.tag(), tick);
        self.events.push(DsarEvent {
            seq,
            request_id: request_id.to_string(),
            action,
            tick,
            prev_hash: prev.to_string(),
            hash,
        });
    }

    /// Open a new DSAR. Fails on a duplicate id. Status starts [`DsarStatus::Received`].
    pub fn open(
        &mut self,
        id: &str,
        subject_id: &str,
        kind: DsarKind,
        opened_tick: u64,
        sla_ticks: u64,
    ) -> Result<(), DsarError> {
        if self.requests.contains_key(id) {
            return Err(DsarError::DuplicateRequest(id.to_string()));
        }
        self.requests.insert(
            id.to_string(),
            DsarRequest {
                id: id.to_string(),
                subject_id: subject_id.to_string(),
                kind,
                opened_tick,
                sla_ticks,
                identity_proofed: false,
                status: DsarStatus::Received,
                closed_tick: None,
            },
        );
        self.append(id, DsarAction::Opened { kind, sla_ticks }, opened_tick);
        Ok(())
    }

    /// Authenticate the data principal (§4.4 step 1). `proof_ok=false` rejects the request
    /// (terminal, nothing fulfilled — no leak). `proof_ok=true` marks it in-progress. Returns
    /// whether proofing succeeded.
    pub fn authenticate(&mut self, id: &str, proof_ok: bool, now: u64) -> Result<bool, DsarError> {
        let req = self
            .requests
            .get_mut(id)
            .ok_or_else(|| DsarError::UnknownRequest(id.to_string()))?;
        if req.status.is_terminal() {
            return Err(DsarError::AlreadyTerminal(id.to_string()));
        }
        if proof_ok {
            req.identity_proofed = true;
            req.status = DsarStatus::InProgress;
            self.append(id, DsarAction::IdentityProofed, now);
            Ok(true)
        } else {
            req.status = DsarStatus::IdentityRejected;
            req.closed_tick = Some(now);
            self.append(id, DsarAction::IdentityRejected, now);
            Ok(false)
        }
    }

    /// Common guard for a fulfilment: request exists, is not terminal, identity is proofed, and the
    /// kind matches. Returns a mutable handle if all pass.
    fn ready_for(&mut self, id: &str, kind: DsarKind) -> Result<&mut DsarRequest, DsarError> {
        let req = self
            .requests
            .get_mut(id)
            .ok_or_else(|| DsarError::UnknownRequest(id.to_string()))?;
        if req.status.is_terminal() {
            return Err(DsarError::AlreadyTerminal(id.to_string()));
        }
        if !req.identity_proofed {
            return Err(DsarError::IdentityNotProofed(id.to_string()));
        }
        if req.kind != kind {
            return Err(DsarError::WrongKind {
                expected: kind,
                got: req.kind,
            });
        }
        Ok(req)
    }

    /// Fulfil an access/portability request (§4.4 step 3): resolve the subject's cross-tier lineage
    /// and return the machine-readable export. Refused unless identity is proofed. The request kind
    /// must be [`DsarKind::Access`] or [`DsarKind::Portability`].
    pub fn fulfill_access(
        &mut self,
        id: &str,
        resolver: &dyn LineageResolver,
        now: u64,
    ) -> Result<Vec<LineageRecord>, DsarError> {
        // Resolve the required kind first (Access vs Portability) without holding a mutable borrow.
        let kind = self
            .requests
            .get(id)
            .ok_or_else(|| DsarError::UnknownRequest(id.to_string()))?
            .kind;
        if kind != DsarKind::Access && kind != DsarKind::Portability {
            return Err(DsarError::WrongKind {
                expected: DsarKind::Access,
                got: kind,
            });
        }
        let req = self.ready_for(id, kind)?;
        let subject = req.subject_id.clone();
        let export = resolver.resolve(&subject);
        req.status = DsarStatus::Fulfilled;
        req.closed_tick = Some(now);
        self.append(
            id,
            DsarAction::AccessExported {
                n_records: export.len(),
            },
            now,
        );
        Ok(export)
    }

    /// Fulfil an erasure request (§4.4 step 3) **through the retention/hold precedence** (§6):
    /// records not held/floor-bound are erased now; the rest are deferred-with-record and the subject
    /// receives the deferral notices. Refused unless identity is proofed and the kind is
    /// [`DsarKind::Erasure`].
    pub fn fulfill_erasure(
        &mut self,
        id: &str,
        store: &mut RecordStore,
        now: u64,
    ) -> Result<ErasureResolution, DsarError> {
        let req = self.ready_for(id, DsarKind::Erasure)?;
        let subject = req.subject_id.clone();
        let resolution = store.request_erasure(&subject, now);
        req.status = DsarStatus::Fulfilled;
        req.closed_tick = Some(now);
        self.append(
            id,
            DsarAction::ErasureProcessed {
                erased: resolution.erased.len(),
                deferred: resolution.deferred.len(),
            },
            now,
        );
        Ok(resolution)
    }

    /// Record a correction fulfilment (§4.4 step 3). `n_records` corrected. Refused unless proofed;
    /// kind must be [`DsarKind::Correction`].
    pub fn fulfill_correction(
        &mut self,
        id: &str,
        n_records: usize,
        now: u64,
    ) -> Result<(), DsarError> {
        let req = self.ready_for(id, DsarKind::Correction)?;
        req.status = DsarStatus::Fulfilled;
        req.closed_tick = Some(now);
        self.append(id, DsarAction::Corrected { n_records }, now);
        Ok(())
    }

    /// Route a grievance to the DPO (§4.4 step 3). Refused unless proofed; kind must be
    /// [`DsarKind::Grievance`].
    pub fn route_grievance(&mut self, id: &str, now: u64) -> Result<(), DsarError> {
        let req = self.ready_for(id, DsarKind::Grievance)?;
        req.status = DsarStatus::Fulfilled;
        req.closed_tick = Some(now);
        self.append(id, DsarAction::GrievanceRouted, now);
        Ok(())
    }

    /// Mark every non-terminal request past its SLA deadline as [`DsarStatus::Overdue`] at `now`,
    /// appending a `MarkedOverdue` event for each newly-overdue request (idempotent — a request
    /// already `Overdue` is not re-marked). Returns the newly-overdue ids in ascending order.
    pub fn refresh_overdue(&mut self, now: u64) -> Vec<String> {
        let mut newly: Vec<String> = self
            .requests
            .values()
            .filter(|r| r.status != DsarStatus::Overdue && r.is_overdue(now))
            .map(|r| r.id.clone())
            .collect();
        newly.sort();
        for id in &newly {
            if let Some(r) = self.requests.get_mut(id) {
                r.status = DsarStatus::Overdue;
            }
            self.append(id, DsarAction::MarkedOverdue, now);
        }
        newly
    }

    /// Every currently-overdue request id, ascending (a live SLA-breach view for the dashboard).
    pub fn overdue(&self, now: u64) -> Vec<String> {
        let mut v: Vec<String> = self
            .requests
            .values()
            .filter(|r| r.is_overdue(now))
            .map(|r| r.id.clone())
            .collect();
        v.sort();
        v
    }

    /// Recompute the hash chain end-to-end; returns the verified event count or the first break.
    pub fn verify(&self) -> Result<usize, DsarTamper> {
        let mut prev = GENESIS.to_string();
        for (i, e) in self.events.iter().enumerate() {
            let expected_seq = i as u64;
            if e.seq != expected_seq {
                return Err(DsarTamper::SeqGap {
                    expected: expected_seq,
                    found: e.seq,
                });
            }
            if e.prev_hash != prev {
                return Err(DsarTamper::BrokenChain { seq: e.seq });
            }
            let recomputed = chain_hash(&prev, e.seq, &e.request_id, &e.action.tag(), e.tick);
            if recomputed != e.hash {
                return Err(DsarTamper::HashMismatch { seq: e.seq });
            }
            prev = e.hash.clone();
        }
        Ok(self.events.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HoldScope, LegalHold, Record, RetentionPolicy};

    fn store_with(subject: &str) -> RecordStore {
        let mut s =
            RecordStore::new().with_policy(RetentionPolicy::new(DataClass::Internal, 1_000));
        s.put(Record::new("r1", subject, DataClass::Internal, 0));
        s.put(Record::new("r2", subject, DataClass::Internal, 1));
        s
    }

    // ---- a second, fixed lineage tier, to prove cross-tier merge ----
    struct RedisTier;
    impl LineageResolver for RedisTier {
        fn resolve(&self, subject_id: &str) -> Vec<LineageRecord> {
            vec![LineageRecord {
                tier: "redis-session".into(),
                record_id: format!("sess-{subject_id}"),
                subject_id: subject_id.into(),
                data_class: DataClass::Internal,
                summary: "session".into(),
            }]
        }
    }

    /// A fixed KG tier double.
    struct KgTier;
    impl LineageResolver for KgTier {
        fn resolve(&self, subject_id: &str) -> Vec<LineageRecord> {
            vec![LineageRecord {
                tier: "kg-memoryfact".into(),
                record_id: format!("fact-{subject_id}"),
                subject_id: subject_id.into(),
                data_class: DataClass::Pii,
                summary: "memory fact".into(),
            }]
        }
    }

    #[test]
    fn gap_ainxt_lifecycle_fi09_incomplete_lineage_is_refused_complete_is_certified() {
        // FI-09: an access fulfilment that requires completeness is REFUSED when a mandated tier has
        // no resolver (so a DSAR can never silently under-report), and is certified complete only when
        // every required tier is registered.
        let subject = "alice";

        // Only two of the required tiers registered → incomplete.
        let partial = CompleteLineage::with_default_required()
            .with_named_tier("lifecycle-store", Box::new(store_with(subject)))
            .with_named_tier("redis-session", Box::new(RedisTier));
        assert!(!partial.missing_tiers().is_empty());

        let mut reg = DsarRegister::new();
        reg.open("d1", subject, DsarKind::Access, 0, 100).unwrap();
        reg.authenticate("d1", true, 1).unwrap();
        let err = reg
            .fulfill_access_complete("d1", &partial, true, 2)
            .unwrap_err();
        match err {
            DsarError::IncompleteLineage { missing } => {
                assert!(missing.contains(&"kg-memoryfact".to_string()));
                assert!(missing.contains(&"traces".to_string()));
            }
            other => panic!("expected IncompleteLineage, got {other:?}"),
        }
        // The request was NOT closed by the refused fulfilment.
        assert_ne!(reg.request("d1").unwrap().status, DsarStatus::Fulfilled);

        // Register every required tier → complete + certified.
        let mut complete =
            CompleteLineage::new(&["lifecycle-store", "redis-session", "kg-memoryfact"])
                .with_named_tier("lifecycle-store", Box::new(store_with(subject)))
                .with_named_tier("redis-session", Box::new(RedisTier));
        complete = complete.with_named_tier("kg-memoryfact", Box::new(KgTier));
        assert!(complete.missing_tiers().is_empty());

        let export = reg
            .fulfill_access_complete("d1", &complete, true, 3)
            .unwrap();
        assert!(export.is_complete());
        // Records were merged across all three tiers.
        let tiers: std::collections::BTreeSet<&str> =
            export.records.iter().map(|r| r.tier.as_str()).collect();
        assert!(tiers.contains("lifecycle-store"));
        assert!(tiers.contains("redis-session"));
        assert!(tiers.contains("kg-memoryfact"));
        assert_eq!(reg.request("d1").unwrap().status, DsarStatus::Fulfilled);
        assert!(reg.verify().is_ok());
    }

    #[test]
    fn access_refused_without_identity_proofing() {
        let mut reg = DsarRegister::new();
        reg.open("d1", "alice", DsarKind::Access, 0, 100).unwrap();
        let store = store_with("alice");
        // No authenticate() call → identity not proofed → refused (no leak).
        let err = reg.fulfill_access("d1", &store, 5).unwrap_err();
        assert_eq!(err, DsarError::IdentityNotProofed("d1".into()));
        // The request is untouched (still Received).
        assert_eq!(reg.request("d1").unwrap().status, DsarStatus::Received);
    }

    #[test]
    fn failed_identity_proof_terminates_without_fulfilment() {
        let mut reg = DsarRegister::new();
        reg.open("d1", "mallory", DsarKind::Access, 0, 100).unwrap();
        let ok = reg.authenticate("d1", false, 3).unwrap();
        assert!(!ok);
        assert_eq!(
            reg.request("d1").unwrap().status,
            DsarStatus::IdentityRejected
        );
        // A rejected request cannot then be fulfilled.
        let store = store_with("mallory");
        assert_eq!(
            reg.fulfill_access("d1", &store, 4).unwrap_err(),
            DsarError::AlreadyTerminal("d1".into())
        );
    }

    #[test]
    fn access_export_resolves_cross_tier_lineage() {
        let mut reg = DsarRegister::new();
        reg.open("d1", "alice", DsarKind::Access, 0, 100).unwrap();
        reg.authenticate("d1", true, 1).unwrap();
        let store = store_with("alice");
        let lineage = MultiTierLineage::new()
            .with_tier(Box::new(store.clone()))
            .with_tier(Box::new(RedisTier));
        let export = reg.fulfill_access("d1", &lineage, 5).unwrap();
        // Two lifecycle-store records + one redis-session record, merged and sorted by tier.
        assert_eq!(export.len(), 3);
        assert_eq!(export[0].tier, "lifecycle-store");
        assert_eq!(export[2].tier, "redis-session");
        assert_eq!(reg.request("d1").unwrap().status, DsarStatus::Fulfilled);
    }

    #[test]
    fn erasure_dsar_runs_through_hold_precedence() {
        // §6.6 test 6: an erasure DSAR against a held record → deferred-with-record, not deleted.
        let mut reg = DsarRegister::new();
        reg.open("d1", "carol", DsarKind::Erasure, 0, 100).unwrap();
        reg.authenticate("d1", true, 1).unwrap();
        let mut store = store_with("carol");
        // Hold r1 only.
        store.add_hold(LegalHold::open(
            "m",
            "dpo",
            HoldScope::any()
                .with_subject("carol")
                .with_created_range(Some(0), Some(0)),
            0,
        ));
        let res = reg.fulfill_erasure("d1", &mut store, 5).unwrap();
        assert_eq!(res.erased, vec!["r2".to_string()]);
        assert_eq!(res.deferred.len(), 1);
        assert_eq!(res.deferred[0].record_id, "r1");
        assert!(res.deferred[0]
            .notice
            .contains("honored to the extent legally permissible"));
        assert_eq!(reg.request("d1").unwrap().status, DsarStatus::Fulfilled);
        // The held record survives; the DSAR is still recorded as fulfilled (answered w/ deferral).
        assert!(store.get("r1").is_some());
    }

    #[test]
    fn wrong_kind_is_refused() {
        let mut reg = DsarRegister::new();
        reg.open("d1", "bob", DsarKind::Access, 0, 100).unwrap();
        reg.authenticate("d1", true, 1).unwrap();
        let mut store = store_with("bob");
        // Erasure op on an Access request.
        assert_eq!(
            reg.fulfill_erasure("d1", &mut store, 2).unwrap_err(),
            DsarError::WrongKind {
                expected: DsarKind::Erasure,
                got: DsarKind::Access
            }
        );
    }

    #[test]
    fn sla_clock_marks_overdue() {
        let mut reg = DsarRegister::new();
        reg.open("d1", "alice", DsarKind::Access, 0, 30).unwrap(); // deadline 30
        reg.open("d2", "bob", DsarKind::Access, 0, 100).unwrap(); // deadline 100
                                                                  // At tick 31, d1 is overdue, d2 is not.
        assert_eq!(reg.overdue(31), vec!["d1".to_string()]);
        let marked = reg.refresh_overdue(31);
        assert_eq!(marked, vec!["d1".to_string()]);
        assert_eq!(reg.request("d1").unwrap().status, DsarStatus::Overdue);
        // Idempotent: re-running does not re-mark d1.
        assert!(reg.refresh_overdue(31).is_empty());
        // A fulfilled request never goes overdue.
        reg.authenticate("d2", true, 40).unwrap();
        let store = store_with("bob");
        reg.fulfill_access("d2", &store, 50).unwrap();
        assert!(reg.refresh_overdue(1_000).is_empty());
    }

    #[test]
    fn register_is_hash_chained_and_tamper_evident() {
        let mut reg = DsarRegister::new();
        reg.open("d1", "alice", DsarKind::Erasure, 0, 100).unwrap();
        reg.authenticate("d1", true, 1).unwrap();
        let mut store = store_with("alice");
        reg.fulfill_erasure("d1", &mut store, 5).unwrap();
        // Chain verifies: 3 events (opened, proofed, erasure).
        assert_eq!(reg.verify().unwrap(), 3);
        // Tamper: flip an action payload after the fact → verify fails.
        reg.events[1].action = DsarAction::IdentityRejected;
        assert!(matches!(
            reg.verify(),
            Err(DsarTamper::HashMismatch { seq: 1 })
        ));
    }

    #[test]
    fn duplicate_open_is_refused() {
        let mut reg = DsarRegister::new();
        reg.open("d1", "alice", DsarKind::Access, 0, 100).unwrap();
        assert_eq!(
            reg.open("d1", "alice", DsarKind::Access, 0, 100)
                .unwrap_err(),
            DsarError::DuplicateRequest("d1".into())
        );
    }

    #[test]
    fn register_serde_roundtrips_and_still_verifies() {
        let mut reg = DsarRegister::new();
        reg.open("d1", "alice", DsarKind::Grievance, 0, 100)
            .unwrap();
        reg.authenticate("d1", true, 1).unwrap();
        reg.route_grievance("d1", 2).unwrap();
        let json = serde_json::to_string(&reg).unwrap();
        let back: DsarRegister = serde_json::from_str(&json).unwrap();
        assert_eq!(back.verify().unwrap(), 3);
        assert_eq!(back.request("d1").unwrap().status, DsarStatus::Fulfilled);
    }
}
