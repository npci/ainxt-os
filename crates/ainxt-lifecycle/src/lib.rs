// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! ainxt-lifecycle — data lifecycle / retention core (gap **Q**, ADR-015,
//! `REGULATED_FI_COMPLIANCE_OPS.md` §6).
//!
//! The Event Log and durable memories **cannot live forever**. Three obligations pull against
//! each other:
//!
//! - **DPDP right-to-erasure** — a data principal (subject) can demand their records be erased.
//! - **Statutory retention (TTL)** — records expire and must be purged once past their window.
//! - **Legal-hold** — a litigation/investigation preservation obligation that **overrides both**:
//!   a held record is neither swept by TTL nor deleted by an erasure request.
//!
//! This crate is the **deterministic precedence core** that resolves the tension. It is pure —
//! logical time is passed in as a tick, there is no clock, no RNG, no I/O — so purge, erasure, and
//! deferral are all reproducible and provable to a regulator.
//!
//! # Precedence (highest first — §6.1)
//!
//! 1. **Legal-hold.** If a record's [`DataClass`] is under an active legal hold, it is **preserved**.
//!    A TTL sweep skips it; an erasure request is **refused-with-record** — a reason-coded,
//!    deferred entry ("honored to the extent legally permissible"), *never* a silent keep and
//!    *never* a silent drop. A "forget everything" cannot delete held records.
//! 2. **TTL / erasure.** Otherwise the record is purged once past `created + ttl`, or erased on
//!    request.
//!
//! # Surface
//!
//! - [`RetentionPolicy`] — `{ data_class, ttl_ticks, legal_hold }`, keyed by [`DataClass`].
//! - [`Record`] — `{ id, subject_id, data_class, created_tick }`.
//! - [`RecordStore`] — `put`/`get` plus [`purge_expired`](RecordStore::purge_expired) and
//!   [`erase_subject`](RecordStore::erase_subject), backed by an
//!   [`audit`](RecordStore::audit) trail.
//!
//! Records with **no policy** for their class have no defined expiry, so TTL never purges them
//! (fail-safe: you cannot expire what you never scheduled); erasure still honors them (a subject's
//! right does not depend on an operator having filed a retention rule). Both choices are the
//! conservative, auditable default and are asserted in the tests.
//!
//! Clean-room; deterministic; exhaustively testable.

pub mod breakglass;
pub mod dsar;
pub mod dsar_tiers;
pub mod durable;
pub mod guarded;
pub mod routes;

use ainxt_types::DataClass;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Retention rule for one [`DataClass`].
///
/// Two distinct time bounds, easy to conflate but opposite in meaning (§6):
/// - `ttl_ticks` is the retention **ceiling** — a record is *purged* once past `created + ttl`.
/// - `floor_ticks` is the statutory retention **floor** (RBI/PMLA/CERT-In minima) — a record
///   **must be kept** until `created + floor`, so a right-to-erasure request against it is
///   *deferred to floor-expiry*, never honored early. `floor_ticks == 0` (the default) means no
///   floor. A well-formed policy has `floor_ticks <= ttl_ticks`, but the type does not force it —
///   the two bounds are enforced independently so a mis-ordered policy still fails safe (the floor
///   defers erasure; the ceiling purges; whichever the clock reaches governs).
///
/// `legal_hold` (when true) preserves **every** record of this class regardless of TTL or erasure —
/// the coarse, class-wide override retained for backward compatibility. The finer, per-matter
/// override with a scope predicate is [`LegalHold`] (§6.2), which is the mechanism a regulator
/// actually expects; `legal_hold` remains as a blunt whole-class switch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionPolicy {
    pub data_class: DataClass,
    pub ttl_ticks: u64,
    pub legal_hold: bool,
    /// Statutory minimum-retention window (§6.1 step 2). `0` = no floor. Additive; defaults to `0`
    /// so a policy serialized before this field deserializes as "no floor".
    #[serde(default)]
    pub floor_ticks: u64,
}

impl RetentionPolicy {
    /// A policy that expires records `ttl_ticks` after creation, with no legal hold and no floor.
    pub fn new(data_class: DataClass, ttl_ticks: u64) -> Self {
        Self {
            data_class,
            ttl_ticks,
            legal_hold: false,
            floor_ticks: 0,
        }
    }

    /// Set the legal-hold flag (builder-style).
    pub fn with_legal_hold(mut self, held: bool) -> Self {
        self.legal_hold = held;
        self
    }

    /// Set the statutory retention floor (builder-style) — the minimum ticks a record of this class
    /// must be retained before an erasure request may fire (§6.1 step 2).
    pub fn with_floor(mut self, floor_ticks: u64) -> Self {
        self.floor_ticks = floor_ticks;
        self
    }

    /// The tick at which a record created at `created_tick` becomes eligible for purge.
    /// Saturating so a large TTL never overflows into an early expiry.
    fn expiry_tick(&self, created_tick: u64) -> u64 {
        created_tick.saturating_add(self.ttl_ticks)
    }

    /// The tick at which the statutory retention floor elapses for a record created at
    /// `created_tick` — i.e. the earliest tick at which a deferred erasure may fire. Saturating.
    fn floor_expiry_tick(&self, created_tick: u64) -> u64 {
        created_tick.saturating_add(self.floor_ticks)
    }
}

/// One stored record. `subject_id` is the data principal (the erasure unit); `created_tick` is the
/// logical time the record was written (the TTL anchor).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub id: String,
    pub subject_id: String,
    pub data_class: DataClass,
    pub created_tick: u64,
}

impl Record {
    pub fn new(id: &str, subject_id: &str, data_class: DataClass, created_tick: u64) -> Self {
        Self {
            id: id.to_string(),
            subject_id: subject_id.to_string(),
            data_class,
            created_tick,
        }
    }
}

/// What happened to a record in the lifecycle pipeline. Recorded on the [`audit`](RecordStore::audit)
/// trail so retention, purge, and deferral are all equally provable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LifecycleAction {
    /// Removed by a TTL sweep ([`purge_expired`](RecordStore::purge_expired)).
    Purged,
    /// Removed by a right-to-erasure request ([`erase_subject`](RecordStore::erase_subject)).
    Erased,
    /// An erasure request that was refused because the record is under legal hold — the record was
    /// preserved and the deferral recorded (§6.1). Produced by the legacy class-wide
    /// [`erase_subject`](RecordStore::erase_subject).
    ErasureRefused,
    /// An erasure request that was **deferred** by the precedence function
    /// ([`request_erasure`](RecordStore::request_erasure)) because the record is under an active
    /// legal-hold matter or within its statutory retention floor — the record is preserved and the
    /// request queued to fire on hold-release / floor-expiry (§6.1/§6.3). Never a silent keep.
    ErasureDeferred,
}

/// One line of the audit trail. `tick` carries the sweep's `now_tick` for a purge and is `None` for
/// an erasure request (which takes no time argument). `reason` is populated for a refusal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    pub action: LifecycleAction,
    pub record_id: String,
    pub subject_id: String,
    pub data_class: DataClass,
    pub tick: Option<u64>,
    pub reason: Option<String>,
}

/// A record whose erasure was refused because its class is under legal hold. Carries the
/// reason-coded, human-legible explanation returned to the requesting subject.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refusal {
    pub record_id: String,
    pub reason: String,
}

/// Result of an [`erase_subject`](RecordStore::erase_subject) request: exactly which records were
/// erased and which were refused (with a reason). Both lists are ordered deterministically by
/// record id.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ErasureOutcome {
    pub erased: Vec<String>,
    pub refused: Vec<Refusal>,
}

impl ErasureOutcome {
    /// True when nothing at all matched the subject (no erasures, no refusals).
    pub fn is_empty(&self) -> bool {
        self.erased.is_empty() && self.refused.is_empty()
    }
}

/// The reason code attached to a legal-hold erasure refusal.
fn legal_hold_reason(data_class: DataClass) -> String {
    format!(
        "legal-hold: class `{}` is under an active legal hold; erasure deferred and recorded \
         (honored to the extent legally permissible)",
        data_class.as_str()
    )
}

// ============================ legal-hold matters (§6.2) ============================

/// The scope predicate of a [`LegalHold`] matter — the rule that decides which records the matter
/// *covers* (§6.2). Every specified facet is an **AND** constraint; an unspecified facet (empty set
/// / `None` bound) is a wildcard. A fully-unspecified scope therefore covers **every** record — an
/// intentional "hold everything" matter, and a dangerous one: the correctness of a matter is only as
/// good as its predicate (design residual 4), so authoring is Legal's responsibility, not this code's.
///
/// A record is covered iff **all** hold:
/// - its `subject_id` is in `subjects` (or `subjects` is empty), AND
/// - its `data_class` is in `data_classes` (or `data_classes` is empty), AND
/// - its `created_tick` is within `[created_from, created_to]` (each bound optional/inclusive).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct HoldScope {
    /// Custodians / data principals held. Empty = any subject.
    pub subjects: BTreeSet<String>,
    /// Data classes held. Empty = any class.
    pub data_classes: BTreeSet<DataClass>,
    /// Inclusive lower bound on `created_tick`. `None` = open below.
    pub created_from: Option<u64>,
    /// Inclusive upper bound on `created_tick`. `None` = open above.
    pub created_to: Option<u64>,
}

impl HoldScope {
    /// An all-wildcard scope (covers every record). Narrow it with the builders below.
    pub fn any() -> Self {
        Self::default()
    }

    /// Restrict to a set of subjects (chainable).
    pub fn with_subject(mut self, subject_id: &str) -> Self {
        self.subjects.insert(subject_id.to_string());
        self
    }

    /// Restrict to a data class (chainable).
    pub fn with_data_class(mut self, class: DataClass) -> Self {
        self.data_classes.insert(class);
        self
    }

    /// Restrict to an inclusive `created_tick` range (chainable). Either bound may be `None`.
    pub fn with_created_range(mut self, from: Option<u64>, to: Option<u64>) -> Self {
        self.created_from = from;
        self.created_to = to;
        self
    }

    /// Whether this scope covers `record` — all specified facets must match (see the type doc).
    pub fn covers(&self, record: &Record) -> bool {
        let subject_ok = self.subjects.is_empty() || self.subjects.contains(&record.subject_id);
        let class_ok =
            self.data_classes.is_empty() || self.data_classes.contains(&record.data_class);
        let from_ok = self.created_from.is_none_or(|lo| record.created_tick >= lo);
        let to_ok = self.created_to.is_none_or(|hi| record.created_tick <= hi);
        subject_ok && class_ok && from_ok && to_ok
    }
}

/// A per-matter legal hold — a litigation/investigation preservation obligation that overrides
/// erasure and TTL for exactly the records its [`HoldScope`] covers (§6.2). It is a data-plane
/// object (it names data principals) with a lifecycle: opened at `opened_tick`, active until
/// `released_tick` is set by an authorized, reason-coded release (§6.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegalHold {
    /// Matter id (e.g. `"matter-2026-0042"`).
    pub id: String,
    /// The custodian accountable for the matter.
    pub custodian: String,
    /// The predicate defining which records the matter holds.
    pub scope: HoldScope,
    /// Logical tick the matter was opened.
    pub opened_tick: u64,
    /// Logical tick the matter was released, if it has been. `None` = still active.
    pub released_tick: Option<u64>,
}

impl LegalHold {
    /// Open a new, active matter.
    pub fn open(id: &str, custodian: &str, scope: HoldScope, opened_tick: u64) -> Self {
        Self {
            id: id.to_string(),
            custodian: custodian.to_string(),
            scope,
            opened_tick,
            released_tick: None,
        }
    }

    /// Whether the matter is currently active (not yet released).
    pub fn is_active(&self) -> bool {
        self.released_tick.is_none()
    }
}

/// Why an erasure was deferred rather than performed (§6.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum DeferralCause {
    /// Under an active legal-hold matter — deferred until the matter is released.
    LegalHold { matter_id: String },
    /// Within a statutory retention floor — deferred until the floor elapses at `floor_expiry`.
    RetentionFloor { floor_expiry: u64 },
}

/// The deterministic keep/erase/defer decision for a single record at a logical time (§6.1). The
/// precedence is fixed and **not** model-judged: legal-hold beats retention-floor beats erase-now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErasureDecision {
    /// No hold and no floor in the way — erase immediately.
    EraseNow,
    /// Preserve and queue; carries the reason.
    Defer(DeferralCause),
}

/// A queued erasure awaiting a hold-release or floor-expiry (§6.3). Re-evaluated on every
/// [`run_deferred`](RecordStore::run_deferred) so a change in either condition fires it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeferredErasure {
    pub record_id: String,
    pub subject_id: String,
    pub requested_tick: u64,
    pub cause: DeferralCause,
}

/// A human-legible deferral returned to the requesting subject ("honored to the extent legally
/// permissible"). Distinct from a legacy [`Refusal`]: a deferral *will* fire later, a refusal is a
/// class-wide block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Deferral {
    pub record_id: String,
    pub cause: DeferralCause,
    pub notice: String,
}

/// Result of a [`request_erasure`](RecordStore::request_erasure): which records were erased now and
/// which were deferred (with cause). Both lists are ordered deterministically by record id.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ErasureResolution {
    pub erased: Vec<String>,
    pub deferred: Vec<Deferral>,
}

impl ErasureResolution {
    /// True when nothing matched the subject.
    pub fn is_empty(&self) -> bool {
        self.erased.is_empty() && self.deferred.is_empty()
    }
}

/// A signed-shape, regulator-provable attestation that a right-to-erasure request was honored under
/// §6 precedence (§6.1 / §6.3). It is the **redact-with-attestation** artifact: for every record the
/// request touched it records the deterministic outcome — hard-erased (no hold, no floor) vs
/// *preserved-under-precedence* (a legal-held or floor-bound record is **never hard-deleted under
/// hold**; the erasure is deferred-with-record and queued to fire on release/floor-expiry). A SHA-256
/// content hash over the canonical fields makes the attestation **tamper-evident**: altering any
/// field (which records were kept, why, or when) breaks [`verify`](ErasureAttestation::verify), so the
/// "we honored the request to the extent legally permissible" claim is machine-checkable, not paper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErasureAttestation {
    /// The data principal whose erasure was requested.
    pub subject_id: String,
    /// The logical tick at which the request was resolved.
    pub tick: u64,
    /// The §6 precedence resolution: erased-now ids + deferred-with-record (held/floored) entries.
    pub resolution: ErasureResolution,
    /// SHA-256 over the canonical, length-prefixed fields — the tamper-evident digest.
    pub content_hash: String,
}

impl ErasureAttestation {
    /// Build an attestation over a completed §6 [`ErasureResolution`], content-hashing every field so
    /// the artifact is tamper-evident.
    pub fn new(subject_id: &str, tick: u64, resolution: ErasureResolution) -> Self {
        let content_hash = Self::hash(subject_id, tick, &resolution);
        Self {
            subject_id: subject_id.to_string(),
            tick,
            resolution,
            content_hash,
        }
    }

    /// The records that were **hard-erased** now (no hold, no floor stood in the way).
    pub fn hard_erased(&self) -> &[String] {
        &self.resolution.erased
    }

    /// The records **preserved under §6 precedence** — legal-held or floor-bound, so NOT hard-deleted;
    /// each carries its reason-coded [`Deferral::cause`] and human-legible notice.
    pub fn preserved_under_hold(&self) -> &[Deferral] {
        &self.resolution.deferred
    }

    /// Re-verify the attestation in isolation: the recomputed content hash must match. Returns `false`
    /// if any field was altered after issuance.
    pub fn verify(&self) -> bool {
        Self::hash(&self.subject_id, self.tick, &self.resolution) == self.content_hash
    }

    /// SHA-256 over canonical, length-prefixed fields (a value boundary cannot be forged by shifting
    /// bytes between adjacent fields). Deterministic: no wall clock, no RNG.
    fn hash(subject_id: &str, tick: u64, resolution: &ErasureResolution) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        fn put(h: &mut Sha256, bytes: &[u8]) {
            h.update((bytes.len() as u64).to_le_bytes());
            h.update(bytes);
        }
        put(&mut h, subject_id.as_bytes());
        h.update(tick.to_le_bytes());
        h.update((resolution.erased.len() as u64).to_le_bytes());
        for id in &resolution.erased {
            put(&mut h, id.as_bytes());
        }
        h.update((resolution.deferred.len() as u64).to_le_bytes());
        for d in &resolution.deferred {
            put(&mut h, d.record_id.as_bytes());
            let cause_tag = match &d.cause {
                DeferralCause::LegalHold { matter_id } => format!("legal-hold:{matter_id}"),
                DeferralCause::RetentionFloor { floor_expiry } => {
                    format!("retention-floor:{floor_expiry}")
                }
            };
            put(&mut h, cause_tag.as_bytes());
            put(&mut h, d.notice.as_bytes());
        }
        h.finalize().iter().map(|b| format!("{b:02x}")).collect::<String>()
    }
}

/// The reason code attached to a per-matter legal-hold deferral.
fn matter_deferral_notice(matter_id: &str) -> String {
    format!(
        "legal-hold: record is within active matter `{matter_id}`; erasure deferred and recorded, \
         and will fire when the matter is released (honored to the extent legally permissible)"
    )
}

/// The reason code attached to a statutory-retention-floor deferral.
fn floor_deferral_notice(floor_expiry: u64) -> String {
    format!(
        "statutory-retention-floor: record must be retained until tick {floor_expiry}; erasure \
         deferred and queued to fire automatically at floor-expiry (honored to the extent legally \
         permissible)"
    )
}

/// A deterministic, in-memory lifecycle store. Records are keyed by id in a [`BTreeMap`] so every
/// sweep, erasure, and audit line is produced in a stable, id-sorted order (no hash randomness).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RecordStore {
    policies: BTreeMap<DataClass, RetentionPolicy>,
    records: BTreeMap<String, Record>,
    audit: Vec<AuditEntry>,
    /// Active + released legal-hold matters, keyed by matter id (§6.2). Additive — deserializes as
    /// empty for a store serialized before matters existed.
    #[serde(default)]
    holds: BTreeMap<String, LegalHold>,
    /// The deferred-erasure queue (§6.3): erasures awaiting hold-release or floor-expiry.
    #[serde(default)]
    deferred: Vec<DeferredErasure>,
}

impl RecordStore {
    /// An empty store with no policies.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register/replace the retention policy for a data class (builder-style).
    pub fn with_policy(mut self, policy: RetentionPolicy) -> Self {
        self.set_policy(policy);
        self
    }

    /// Register/replace the retention policy for a data class.
    pub fn set_policy(&mut self, policy: RetentionPolicy) {
        self.policies.insert(policy.data_class, policy);
    }

    /// The policy for a class, if one is registered.
    pub fn policy(&self, data_class: DataClass) -> Option<&RetentionPolicy> {
        self.policies.get(&data_class)
    }

    /// True when the class is under an active legal hold. A class with no policy is not held.
    pub fn is_legal_held(&self, data_class: DataClass) -> bool {
        self.policies.get(&data_class).is_some_and(|p| p.legal_hold)
    }

    /// Insert (or overwrite) a record.
    pub fn put(&mut self, record: Record) {
        self.records.insert(record.id.clone(), record);
    }

    /// Fetch a record by id.
    pub fn get(&self, id: &str) -> Option<&Record> {
        self.records.get(id)
    }

    /// Snapshot of `record id → subject_id` for every live record.
    ///
    /// Taken *before* a purge/deferred run, this is what lets erasure propagation attribute each
    /// tier-level delete to the record's own data subject: once a row is removed the store can no
    /// longer say whose right was being exercised, and an unattributed hard-delete of governed data
    /// is precisely the defect the attributed tier API exists to prevent.
    pub fn subject_index(&self) -> std::collections::BTreeMap<String, String> {
        self.records
            .iter()
            .map(|(id, r)| (id.clone(), r.subject_id.clone()))
            .collect()
    }

    /// Every live record belonging to `subject_id`, id-sorted (deterministic). The single-tier
    /// input to DSAR cross-tier lineage resolution ([`dsar::LineageResolver`]).
    pub fn records_for_subject(&self, subject_id: &str) -> Vec<&Record> {
        self.records
            .values()
            .filter(|r| r.subject_id == subject_id)
            .collect()
    }

    /// Number of live records.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// True when no records are stored.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// The append-only audit trail of every purge / erasure / refusal, in the order it occurred.
    pub fn audit(&self) -> &[AuditEntry] {
        self.audit.as_slice()
    }

    /// Whether a record is past its retention window at `now_tick`. A record is expired when its
    /// class has a policy **and** `now_tick` is strictly past `created + ttl`. No policy ⇒ no
    /// defined expiry ⇒ never expired (you cannot purge what was never scheduled).
    fn is_expired(&self, record: &Record, now_tick: u64) -> bool {
        match self.policies.get(&record.data_class) {
            Some(policy) => now_tick > policy.expiry_tick(record.created_tick),
            None => false,
        }
    }

    /// TTL sweep. Removes every record that is past `created + ttl` **except** records whose class
    /// is under a legal hold (which are preserved regardless of age — §6.1). Returns the purged ids
    /// in ascending order, and appends one [`LifecycleAction::Purged`] audit line per removal.
    ///
    /// Deterministic: same store + same `now_tick` always yields the same result and audit.
    pub fn purge_expired(&mut self, now_tick: u64) -> Vec<String> {
        // Phase 1: decide (immutable borrow) which ids to purge, capturing what the audit needs.
        let doomed: Vec<AuditEntry> = self
            .records
            .values()
            .filter(|r| {
                // A TTL sweep never removes a record that is class-held, matter-held, or still
                // within its statutory retention floor — retention/hold always beat purge (§6).
                !self.is_legal_held(r.data_class)
                    && !self.is_under_active_matter(r)
                    && !self.is_within_floor(r, now_tick)
                    && self.is_expired(r, now_tick)
            })
            .map(|r| AuditEntry {
                action: LifecycleAction::Purged,
                record_id: r.id.clone(),
                subject_id: r.subject_id.clone(),
                data_class: r.data_class,
                tick: Some(now_tick),
                reason: None,
            })
            .collect();

        // Phase 2: apply (mutable borrow). BTreeMap iteration was sorted, so `doomed` is sorted.
        let mut purged = Vec::with_capacity(doomed.len());
        for entry in doomed {
            self.records.remove(&entry.record_id);
            purged.push(entry.record_id.clone());
            self.audit.push(entry);
        }
        purged
    }

    /// Right-to-erasure for one subject. Removes every record belonging to `subject_id` **except**
    /// records whose class is under a legal hold: those are **refused-with-record** — preserved,
    /// returned in [`ErasureOutcome::refused`] with a reason, and logged as
    /// [`LifecycleAction::ErasureRefused`] (never silently kept, never silently dropped — §6.1).
    ///
    /// Both result lists and the audit lines are ordered deterministically by record id.
    pub fn erase_subject(&mut self, subject_id: &str) -> ErasureOutcome {
        // Phase 1: decide over the id-sorted map.
        let mut to_erase: Vec<AuditEntry> = Vec::new();
        let mut refusals: Vec<(AuditEntry, String)> = Vec::new();
        for record in self.records.values() {
            if record.subject_id != subject_id {
                continue;
            }
            let base = AuditEntry {
                action: LifecycleAction::Erased,
                record_id: record.id.clone(),
                subject_id: record.subject_id.clone(),
                data_class: record.data_class,
                tick: None,
                reason: None,
            };
            if self.is_legal_held(record.data_class) {
                let reason = legal_hold_reason(record.data_class);
                let entry = AuditEntry {
                    action: LifecycleAction::ErasureRefused,
                    reason: Some(reason.clone()),
                    ..base
                };
                refusals.push((entry, reason));
            } else {
                to_erase.push(base);
            }
        }

        // Phase 2: apply. Refusals preserve the record and only log the deferral.
        let mut outcome = ErasureOutcome::default();
        for entry in to_erase {
            self.records.remove(&entry.record_id);
            outcome.erased.push(entry.record_id.clone());
            self.audit.push(entry);
        }
        for (entry, reason) in refusals {
            outcome.refused.push(Refusal {
                record_id: entry.record_id.clone(),
                reason,
            });
            self.audit.push(entry);
        }
        outcome
    }

    // ==================== legal-hold matters + floor + deferral (§6) ====================

    /// Register (or replace) a legal-hold matter (§6.2).
    pub fn add_hold(&mut self, hold: LegalHold) {
        self.holds.insert(hold.id.clone(), hold);
    }

    /// Fetch a matter by id.
    pub fn hold(&self, id: &str) -> Option<&LegalHold> {
        self.holds.get(id)
    }

    /// All matters (active and released), id-sorted.
    pub fn holds(&self) -> impl Iterator<Item = &LegalHold> {
        self.holds.values()
    }

    /// The pending deferred-erasure queue, id-sorted at query time.
    pub fn deferred_queue(&self) -> Vec<&DeferredErasure> {
        let mut v: Vec<&DeferredErasure> = self.deferred.iter().collect();
        v.sort_by(|a, b| a.record_id.cmp(&b.record_id));
        v
    }

    /// Release a matter at `release_tick` (§6.3) — an authorized, reason-coded action that flips the
    /// matter inactive. Returns `true` if a matter with `id` existed (and was active). Releasing does
    /// **not** itself erase anything; call [`run_deferred`](RecordStore::run_deferred) to fire the
    /// now-unheld erasures. An already-released matter is left unchanged and returns `false`.
    pub fn release_hold(&mut self, id: &str, release_tick: u64) -> bool {
        match self.holds.get_mut(id) {
            Some(h) if h.is_active() => {
                h.released_tick = Some(release_tick);
                true
            }
            _ => false,
        }
    }

    /// The active matters that cover `record` (§6.2), id-sorted.
    pub fn active_holds_covering(&self, record: &Record) -> Vec<&LegalHold> {
        self.holds
            .values()
            .filter(|h| h.is_active() && h.scope.covers(record))
            .collect()
    }

    /// Whether any active matter covers `record`.
    fn is_under_active_matter(&self, record: &Record) -> bool {
        self.holds
            .values()
            .any(|h| h.is_active() && h.scope.covers(record))
    }

    /// The id of the first (lexicographically smallest) active matter covering `record`, if any.
    /// Deterministic because `holds` is a [`BTreeMap`].
    fn covering_matter_id(&self, record: &Record) -> Option<String> {
        self.holds
            .values()
            .find(|h| h.is_active() && h.scope.covers(record))
            .map(|h| h.id.clone())
    }

    /// Whether `record` is still within its class's statutory retention floor at `now_tick`
    /// (§6.1 step 2). No policy, or a zero floor, ⇒ not within any floor.
    fn is_within_floor(&self, record: &Record, now_tick: u64) -> bool {
        match self.policies.get(&record.data_class) {
            Some(p) if p.floor_ticks > 0 => now_tick < p.floor_expiry_tick(record.created_tick),
            _ => false,
        }
    }

    /// The floor-expiry tick for a record, if its class has a floor (else `None`).
    fn floor_expiry(&self, record: &Record) -> Option<u64> {
        self.policies
            .get(&record.data_class)
            .filter(|p| p.floor_ticks > 0)
            .map(|p| p.floor_expiry_tick(record.created_tick))
    }

    /// The deterministic keep/erase/defer decision for one record at `now_tick` (§6.1). Precedence
    /// is fixed: **legal-hold matter → statutory retention floor → erase-now**. No model judgment.
    pub fn erasure_decision(&self, record: &Record, now_tick: u64) -> ErasureDecision {
        if let Some(matter_id) = self.covering_matter_id(record) {
            return ErasureDecision::Defer(DeferralCause::LegalHold { matter_id });
        }
        if self.is_within_floor(record, now_tick) {
            // safe: is_within_floor is only true when floor_expiry is Some.
            let floor_expiry = self.floor_expiry(record).unwrap_or(now_tick);
            return ErasureDecision::Defer(DeferralCause::RetentionFloor { floor_expiry });
        }
        ErasureDecision::EraseNow
    }

    /// Right-to-erasure for one subject **through the precedence function** (§6.1) — the mechanism a
    /// DPDP erasure and an account offboarding both use. For each of the subject's records:
    /// - an [`ErasureDecision::EraseNow`] record is erased and logged [`LifecycleAction::Erased`];
    /// - an [`ErasureDecision::Defer`] record is **preserved**, queued in the deferred-erasure queue,
    ///   and logged [`LifecycleAction::ErasureDeferred`] with its cause — never silently kept, never
    ///   silently dropped. A "forget everything" cannot delete a held or floor-bound record.
    ///
    /// Idempotent on the queue: a record already queued for deferral is not enqueued twice. Both
    /// result lists and the audit lines are ordered deterministically by record id.
    pub fn request_erasure(&mut self, subject_id: &str, now_tick: u64) -> ErasureResolution {
        // Phase 1: decide over the id-sorted map (immutable borrow).
        let mut erase_ids: Vec<(String, DataClass)> = Vec::new();
        let mut defer: Vec<(String, DataClass, DeferralCause)> = Vec::new();
        for record in self.records.values() {
            if record.subject_id != subject_id {
                continue;
            }
            match self.erasure_decision(record, now_tick) {
                ErasureDecision::EraseNow => erase_ids.push((record.id.clone(), record.data_class)),
                ErasureDecision::Defer(cause) => {
                    defer.push((record.id.clone(), record.data_class, cause))
                }
            }
        }

        // Phase 2: apply (mutable borrow).
        let mut resolution = ErasureResolution::default();
        for (id, class) in erase_ids {
            self.records.remove(&id);
            self.audit.push(AuditEntry {
                action: LifecycleAction::Erased,
                record_id: id.clone(),
                subject_id: subject_id.to_string(),
                data_class: class,
                tick: Some(now_tick),
                reason: None,
            });
            resolution.erased.push(id);
        }
        for (id, class, cause) in defer {
            let already_queued = self.deferred.iter().any(|d| d.record_id == id);
            if !already_queued {
                self.deferred.push(DeferredErasure {
                    record_id: id.clone(),
                    subject_id: subject_id.to_string(),
                    requested_tick: now_tick,
                    cause: cause.clone(),
                });
            }
            let notice = match &cause {
                DeferralCause::LegalHold { matter_id } => matter_deferral_notice(matter_id),
                DeferralCause::RetentionFloor { floor_expiry } => {
                    floor_deferral_notice(*floor_expiry)
                }
            };
            self.audit.push(AuditEntry {
                action: LifecycleAction::ErasureDeferred,
                record_id: id.clone(),
                subject_id: subject_id.to_string(),
                data_class: class,
                tick: Some(now_tick),
                reason: Some(notice.clone()),
            });
            resolution.deferred.push(Deferral {
                record_id: id,
                cause,
                notice,
            });
        }
        resolution
    }

    /// Right-to-erasure through §6 precedence ([`request_erasure`](Self::request_erasure)) that returns
    /// a tamper-evident [`ErasureAttestation`] — the **redact-with-attestation** artifact a regulator/DPO
    /// receives. Held/floored records are preserved (never hard-deleted under hold) and recorded as
    /// deferred-with-record; the SHA-256 content hash binds exactly which records were kept and why, so
    /// the "honored to the extent legally permissible" claim is machine-checkable. Identical state
    /// mutation to [`request_erasure`](Self::request_erasure) — this is the attesting wrapper.
    pub fn request_erasure_attested(
        &mut self,
        subject_id: &str,
        now_tick: u64,
    ) -> ErasureAttestation {
        let resolution = self.request_erasure(subject_id, now_tick);
        ErasureAttestation::new(subject_id, now_tick, resolution)
    }

    /// Fire every queued deferred erasure whose blocking condition has cleared at `now_tick` (§6.3):
    /// the covering matter has been released **and** the retention floor has elapsed. A still-blocked
    /// entry stays queued (re-evaluated on the next call). A queued record that no longer exists is
    /// dropped from the queue silently (it was erased by another path). Returns the fired record ids
    /// in ascending order; each firing appends a [`LifecycleAction::Erased`] audit line.
    ///
    /// This is the durable state-machine step: same store + same `now_tick` always fires the same
    /// set, so a restart that re-projects the queue continues deterministically.
    pub fn run_deferred(&mut self, now_tick: u64) -> Vec<String> {
        // Decide which queued entries can fire now, re-evaluating the live precedence.
        let mut fire: Vec<(String, String, DataClass)> = Vec::new();
        let mut keep: Vec<DeferredErasure> = Vec::new();
        for entry in std::mem::take(&mut self.deferred) {
            match self.records.get(&entry.record_id) {
                None => {
                    // Record already gone — drop the stale queue entry.
                }
                Some(record) => match self.erasure_decision(record, now_tick) {
                    ErasureDecision::EraseNow => {
                        fire.push((entry.record_id, entry.subject_id, record.data_class));
                    }
                    ErasureDecision::Defer(cause) => {
                        // Still blocked — refresh the cause (a released hold may now be a floor).
                        keep.push(DeferredErasure { cause, ..entry });
                    }
                },
            }
        }
        self.deferred = keep;
        // Deterministic firing order.
        fire.sort_by(|a, b| a.0.cmp(&b.0));
        let mut fired = Vec::with_capacity(fire.len());
        for (id, subject_id, class) in fire {
            self.records.remove(&id);
            self.audit.push(AuditEntry {
                action: LifecycleAction::Erased,
                record_id: id.clone(),
                subject_id,
                data_class: class,
                tick: Some(now_tick),
                reason: Some("deferred-erasure fired (hold released / floor elapsed)".to_string()),
            });
            fired.push(id);
        }
        fired
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store_with_ttl(class: DataClass, ttl: u64) -> RecordStore {
        RecordStore::new().with_policy(RetentionPolicy::new(class, ttl))
    }

    #[test]
    fn expired_record_purged_fresh_kept() {
        let mut store = store_with_ttl(DataClass::Internal, 10);
        // created at 0, ttl 10 => expiry 10; now 20 => past => purge.
        store.put(Record::new("old", "alice", DataClass::Internal, 0));
        // created at 18, ttl 10 => expiry 28; now 20 => not past => keep.
        store.put(Record::new("new", "alice", DataClass::Internal, 18));

        let purged = store.purge_expired(20);
        assert_eq!(purged, vec!["old".to_string()]);
        assert!(store.get("old").is_none());
        assert!(store.get("new").is_some());
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn legal_held_class_not_purged_even_when_expired() {
        let mut store = RecordStore::new().with_policy(
            RetentionPolicy::new(DataClass::RegulatedPayment, 5).with_legal_hold(true),
        );
        // Well past expiry (created 0, ttl 5, now 1000) but the class is under legal hold.
        store.put(Record::new("held", "bob", DataClass::RegulatedPayment, 0));

        let purged = store.purge_expired(1_000);
        assert!(
            purged.is_empty(),
            "legal-held class must never be TTL-purged"
        );
        assert!(store.get("held").is_some());
        // Preservation is silent for a sweep (nothing to defer), so no audit line is written.
        assert!(store.audit().is_empty());
    }

    #[test]
    fn erase_subject_removes_only_that_subject() {
        let mut store = store_with_ttl(DataClass::Internal, 100);
        store.put(Record::new("a1", "alice", DataClass::Internal, 0));
        store.put(Record::new("a2", "alice", DataClass::Internal, 1));
        store.put(Record::new("b1", "bob", DataClass::Internal, 2));

        let outcome = store.erase_subject("alice");
        assert_eq!(outcome.erased, vec!["a1".to_string(), "a2".to_string()]);
        assert!(outcome.refused.is_empty());
        assert!(store.get("a1").is_none());
        assert!(store.get("a2").is_none());
        assert!(
            store.get("b1").is_some(),
            "another subject's record must survive"
        );
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn legal_held_record_refused_erasure_with_reason() {
        let mut store = RecordStore::new()
            .with_policy(
                RetentionPolicy::new(DataClass::RegulatedPayment, 30).with_legal_hold(true),
            )
            .with_policy(RetentionPolicy::new(DataClass::Internal, 30));
        store.put(Record::new("chat", "carol", DataClass::Internal, 0));
        store.put(Record::new(
            "settle",
            "carol",
            DataClass::RegulatedPayment,
            0,
        ));

        let outcome = store.erase_subject("carol");
        // The unheld record is erased; the held one is refused, not silently ignored.
        assert_eq!(outcome.erased, vec!["chat".to_string()]);
        assert_eq!(outcome.refused.len(), 1);
        let refusal = &outcome.refused[0];
        assert_eq!(refusal.record_id, "settle");
        assert!(refusal.reason.contains("legal-hold"));
        assert!(refusal.reason.contains("regulated-payment"));
        // "forget everything" cannot delete the held record.
        assert!(store.get("settle").is_some());
        assert!(store.get("chat").is_none());
    }

    #[test]
    fn audit_trail_records_what_happened() {
        let mut store = RecordStore::new()
            .with_policy(RetentionPolicy::new(DataClass::Pii, 10).with_legal_hold(true))
            .with_policy(RetentionPolicy::new(DataClass::Internal, 10));
        store.put(Record::new("exp", "dave", DataClass::Internal, 0)); // will expire
        store.put(Record::new("keep", "dave", DataClass::Internal, 100)); // fresh
        store.put(Record::new("pii", "dave", DataClass::Pii, 0)); // held

        let purged = store.purge_expired(50);
        assert_eq!(purged, vec!["exp".to_string()]);

        let outcome = store.erase_subject("dave");
        // "keep" erased (fresh but subject requested); "pii" refused (held). "exp" already purged.
        assert_eq!(outcome.erased, vec!["keep".to_string()]);
        assert_eq!(outcome.refused.len(), 1);

        let audit = store.audit();
        assert_eq!(audit.len(), 3);
        // 1) the purge, carrying the sweep tick.
        assert_eq!(audit[0].action, LifecycleAction::Purged);
        assert_eq!(audit[0].record_id, "exp");
        assert_eq!(audit[0].tick, Some(50));
        assert!(audit[0].reason.is_none());
        // 2) the erasure (no tick).
        assert_eq!(audit[1].action, LifecycleAction::Erased);
        assert_eq!(audit[1].record_id, "keep");
        assert!(audit[1].tick.is_none());
        // 3) the refusal, reason-coded and legible.
        assert_eq!(audit[2].action, LifecycleAction::ErasureRefused);
        assert_eq!(audit[2].record_id, "pii");
        assert!(audit[2].reason.as_deref().unwrap().contains("legal-hold"));
    }

    #[test]
    fn ttl_zero_and_empty_store_edges_are_safe() {
        // Empty store: both operations are no-ops, nothing panics.
        let mut empty = RecordStore::new();
        assert!(empty.purge_expired(999).is_empty());
        assert!(empty.erase_subject("nobody").is_empty());
        assert!(empty.audit().is_empty());

        // ttl = 0: expiry == created; purge only strictly *past* that tick.
        let mut store = store_with_ttl(DataClass::Internal, 0);
        store.put(Record::new("z", "eve", DataClass::Internal, 5));
        assert!(
            store.purge_expired(5).is_empty(),
            "at exactly created+ttl the record is not yet past expiry"
        );
        assert!(store.get("z").is_some());
        assert_eq!(
            store.purge_expired(6),
            vec!["z".to_string()],
            "one tick past => purged"
        );
        assert!(store.is_empty());
    }

    #[test]
    fn no_policy_class_is_never_purged_but_still_erasable() {
        // A record whose class has no registered policy: no defined expiry => never TTL-purged,
        // but a subject's right-to-erasure still honors it (right doesn't depend on a filed rule).
        let mut store = RecordStore::new(); // no policies at all
        store.put(Record::new("orphan", "frank", DataClass::Confidential, 0));

        assert!(
            store.purge_expired(u64::MAX).is_empty(),
            "unscheduled class must not be purged even at max tick"
        );
        assert!(store.get("orphan").is_some());
        assert!(!store.is_legal_held(DataClass::Confidential));

        let outcome = store.erase_subject("frank");
        assert_eq!(outcome.erased, vec!["orphan".to_string()]);
        assert!(outcome.refused.is_empty());
        assert!(store.is_empty());
    }

    #[test]
    fn purge_and_erasure_ids_are_deterministically_sorted() {
        let mut store = store_with_ttl(DataClass::Internal, 0);
        // Insert out of order; BTreeMap + sweep must emit ascending ids.
        for id in ["m", "a", "z", "c"] {
            store.put(Record::new(id, "gina", DataClass::Internal, 0));
        }
        let purged = store.purge_expired(10);
        assert_eq!(
            purged,
            vec![
                "a".to_string(),
                "c".to_string(),
                "m".to_string(),
                "z".to_string()
            ]
        );
    }

    #[test]
    fn saturating_expiry_does_not_overflow_into_early_purge() {
        // A near-max created tick + large ttl must not wrap and cause an early purge.
        let mut store = store_with_ttl(DataClass::Internal, u64::MAX);
        store.put(Record::new(
            "safe",
            "hank",
            DataClass::Internal,
            u64::MAX - 1,
        ));
        assert!(
            store.purge_expired(u64::MAX).is_empty(),
            "saturating expiry must clamp at u64::MAX, never wrap to purge early"
        );
        assert!(store.get("safe").is_some());
    }

    #[test]
    fn record_serde_roundtrip() {
        let store = RecordStore::new()
            .with_policy(RetentionPolicy::new(DataClass::Pii, 42).with_legal_hold(true));
        let json = serde_json::to_string(&store).unwrap();
        let back: RecordStore = serde_json::from_str(&json).unwrap();
        assert_eq!(back.policy(DataClass::Pii).unwrap().ttl_ticks, 42);
        assert!(back.is_legal_held(DataClass::Pii));
    }

    // ==================== §6.2 per-matter legal hold ====================

    #[test]
    fn hold_scope_predicate_matches_all_specified_facets() {
        let scope = HoldScope::any()
            .with_subject("alice")
            .with_data_class(DataClass::RegulatedPayment)
            .with_created_range(Some(10), Some(20));
        // Matches: right subject, right class, created within range.
        assert!(scope.covers(&Record::new("r", "alice", DataClass::RegulatedPayment, 15)));
        // Wrong subject.
        assert!(!scope.covers(&Record::new("r", "bob", DataClass::RegulatedPayment, 15)));
        // Wrong class.
        assert!(!scope.covers(&Record::new("r", "alice", DataClass::Internal, 15)));
        // Out of range (below and above, boundaries inclusive).
        assert!(!scope.covers(&Record::new("r", "alice", DataClass::RegulatedPayment, 9)));
        assert!(scope.covers(&Record::new("r", "alice", DataClass::RegulatedPayment, 10)));
        assert!(scope.covers(&Record::new("r", "alice", DataClass::RegulatedPayment, 20)));
        assert!(!scope.covers(&Record::new("r", "alice", DataClass::RegulatedPayment, 21)));
    }

    #[test]
    fn empty_scope_covers_everything() {
        let scope = HoldScope::any();
        assert!(scope.covers(&Record::new("r", "anyone", DataClass::Public, 0)));
        assert!(scope.covers(&Record::new("r", "other", DataClass::Pii, u64::MAX)));
    }

    #[test]
    fn matter_held_record_is_deferred_not_deleted_and_forget_everything_cannot_touch_it() {
        // §6.6 test 1: DSAR erasure against records within an active legal-hold matter.
        let mut store =
            RecordStore::new().with_policy(RetentionPolicy::new(DataClass::Internal, 100));
        store.put(Record::new("chat", "carol", DataClass::Internal, 5));
        store.put(Record::new("settle", "carol", DataClass::Internal, 15));
        // A matter holds only records created in [10,20] for carol → covers "settle", not "chat".
        store.add_hold(LegalHold::open(
            "matter-1",
            "dpo",
            HoldScope::any()
                .with_subject("carol")
                .with_created_range(Some(10), Some(20)),
            8,
        ));

        let res = store.request_erasure("carol", 30);
        assert_eq!(res.erased, vec!["chat".to_string()]);
        assert_eq!(res.deferred.len(), 1);
        assert_eq!(res.deferred[0].record_id, "settle");
        assert_eq!(
            res.deferred[0].cause,
            DeferralCause::LegalHold {
                matter_id: "matter-1".into()
            }
        );
        // The held record survives the "forget everything".
        assert!(store.get("settle").is_some());
        assert!(store.get("chat").is_none());
        // And it is queued, not lost.
        assert_eq!(store.deferred_queue().len(), 1);
    }

    #[test]
    fn releasing_matter_fires_deferred_erasure() {
        // §6.6 test 2: releasing the matter → the deferred-erasure queue fires.
        let mut store =
            RecordStore::new().with_policy(RetentionPolicy::new(DataClass::Confidential, 100));
        store.put(Record::new("doc", "dave", DataClass::Confidential, 0));
        store.add_hold(LegalHold::open(
            "matter-2",
            "legal",
            HoldScope::any().with_subject("dave"),
            0,
        ));

        let res = store.request_erasure("dave", 10);
        assert!(res.erased.is_empty());
        assert_eq!(res.deferred.len(), 1);
        // Running the queue while the matter is still active fires nothing.
        assert!(store.run_deferred(11).is_empty());
        assert!(store.get("doc").is_some());
        // Release the matter, then run the queue → the erasure fires.
        assert!(store.release_hold("matter-2", 12));
        let fired = store.run_deferred(13);
        assert_eq!(fired, vec!["doc".to_string()]);
        assert!(store.get("doc").is_none());
        assert!(store.deferred_queue().is_empty());
        // Releasing an already-released matter is a no-op.
        assert!(!store.release_hold("matter-2", 14));
    }

    // ==================== §6.1 statutory retention floor ====================

    #[test]
    fn erasure_within_retention_floor_is_deferred_then_fires_at_expiry() {
        // §6.6 test 3: erasure within the RBI/PMLA floor → queued to fire at floor-expiry.
        // Floor 180 (created 0 → floor-expiry 180); ttl large so the record is not otherwise purged.
        let mut store = RecordStore::new()
            .with_policy(RetentionPolicy::new(DataClass::RegulatedPayment, 10_000).with_floor(180));
        store.put(Record::new("txn", "erin", DataClass::RegulatedPayment, 0));

        // Request erasure at tick 50 — inside the floor → deferred, not deleted.
        let res = store.request_erasure("erin", 50);
        assert!(res.erased.is_empty());
        assert_eq!(
            res.deferred[0].cause,
            DeferralCause::RetentionFloor { floor_expiry: 180 }
        );
        assert!(store.get("txn").is_some());

        // Before floor-expiry the queue does not fire.
        assert!(store.run_deferred(179).is_empty());
        assert!(store.get("txn").is_some());
        // At floor-expiry (now >= 180) it fires automatically.
        let fired = store.run_deferred(180);
        assert_eq!(fired, vec!["txn".to_string()]);
        assert!(store.get("txn").is_none());
    }

    #[test]
    fn legal_hold_beats_retention_floor_in_precedence() {
        // A record under BOTH a floor and a matter: legal-hold wins (§6.1 precedence).
        let mut store = RecordStore::new()
            .with_policy(RetentionPolicy::new(DataClass::Pii, 10_000).with_floor(100));
        store.put(Record::new("rec", "frank", DataClass::Pii, 0));
        store.add_hold(LegalHold::open(
            "m",
            "dpo",
            HoldScope::any().with_data_class(DataClass::Pii),
            0,
        ));
        match store.erasure_decision(store.get("rec").unwrap(), 50) {
            ErasureDecision::Defer(DeferralCause::LegalHold { matter_id }) => {
                assert_eq!(matter_id, "m")
            }
            other => panic!("expected legal-hold precedence, got {other:?}"),
        }
        // Release the hold: now inside floor → decision falls to the floor.
        store.release_hold("m", 60);
        assert_eq!(
            store.erasure_decision(store.get("rec").unwrap(), 61),
            ErasureDecision::Defer(DeferralCause::RetentionFloor { floor_expiry: 100 })
        );
        // Past the floor with no hold → erase now.
        assert_eq!(
            store.erasure_decision(store.get("rec").unwrap(), 100),
            ErasureDecision::EraseNow
        );
    }

    #[test]
    fn erase_now_when_no_hold_and_no_floor() {
        let mut store =
            RecordStore::new().with_policy(RetentionPolicy::new(DataClass::Internal, 100));
        store.put(Record::new("r", "gary", DataClass::Internal, 0));
        let res = store.request_erasure("gary", 5);
        assert_eq!(res.erased, vec!["r".to_string()]);
        assert!(res.deferred.is_empty());
        assert!(store.get("r").is_none());
    }

    #[test]
    fn floor_bound_record_is_not_ttl_purged_before_floor() {
        // A perverse policy (ttl < floor): the floor must still protect the record from a purge.
        let mut store = RecordStore::new()
            .with_policy(RetentionPolicy::new(DataClass::RegulatedPayment, 5).with_floor(180));
        store.put(Record::new("t", "h", DataClass::RegulatedPayment, 0));
        // now 100: past ttl (5) but within floor (180) → purge must skip it.
        assert!(store.purge_expired(100).is_empty());
        assert!(store.get("t").is_some());
        // now 200: past floor → purge removes it.
        assert_eq!(store.purge_expired(200), vec!["t".to_string()]);
    }

    #[test]
    fn matter_held_record_is_not_ttl_purged() {
        let mut store =
            RecordStore::new().with_policy(RetentionPolicy::new(DataClass::Internal, 5));
        store.put(Record::new("h", "i", DataClass::Internal, 0));
        store.add_hold(LegalHold::open("m", "dpo", HoldScope::any(), 0));
        assert!(
            store.purge_expired(1_000).is_empty(),
            "a matter-held record must never be TTL-purged"
        );
        assert!(store.get("h").is_some());
        // Releasing the matter lets the (long-expired) record purge.
        store.release_hold("m", 1_001);
        assert_eq!(store.purge_expired(1_002), vec!["h".to_string()]);
    }

    #[test]
    fn request_erasure_is_idempotent_on_the_queue() {
        let mut store = RecordStore::new()
            .with_policy(RetentionPolicy::new(DataClass::Internal, 10_000).with_floor(100));
        store.put(Record::new("r", "jane", DataClass::Internal, 0));
        store.request_erasure("jane", 5);
        store.request_erasure("jane", 6);
        // The record is queued exactly once despite two requests.
        assert_eq!(store.deferred_queue().len(), 1);
    }

    #[test]
    fn deferred_audit_trail_is_reason_coded() {
        let mut store = RecordStore::new()
            .with_policy(RetentionPolicy::new(DataClass::RegulatedPayment, 10_000).with_floor(180));
        store.put(Record::new("t", "k", DataClass::RegulatedPayment, 0));
        store.request_erasure("k", 10);
        let last = store.audit().last().unwrap();
        assert_eq!(last.action, LifecycleAction::ErasureDeferred);
        assert!(last
            .reason
            .as_deref()
            .unwrap()
            .contains("statutory-retention-floor"));
        store.run_deferred(180);
        let fired = store.audit().last().unwrap();
        assert_eq!(fired.action, LifecycleAction::Erased);
        assert!(fired
            .reason
            .as_deref()
            .unwrap()
            .contains("deferred-erasure fired"));
    }

    #[test]
    fn store_with_holds_and_queue_serde_roundtrips() {
        let mut store = RecordStore::new()
            .with_policy(RetentionPolicy::new(DataClass::Pii, 100).with_floor(50));
        store.put(Record::new("r", "s", DataClass::Pii, 0));
        store.add_hold(LegalHold::open(
            "matter-x",
            "dpo",
            HoldScope::any().with_subject("s"),
            0,
        ));
        store.request_erasure("s", 10);
        let json = serde_json::to_string(&store).unwrap();
        let back: RecordStore = serde_json::from_str(&json).unwrap();
        assert_eq!(back.deferred_queue().len(), 1);
        assert!(back.hold("matter-x").unwrap().is_active());
        assert_eq!(back.policy(DataClass::Pii).unwrap().floor_ticks, 50);
    }

    #[test]
    fn store_serialized_before_new_fields_deserializes_with_defaults() {
        // Backward-compat: JSON with no `holds`/`deferred`/`floor_ticks` must still load.
        let legacy = r#"{
            "policies": {"internal": {"data_class":"internal","ttl_ticks":10,"legal_hold":false}},
            "records": {},
            "audit": []
        }"#;
        let store: RecordStore = serde_json::from_str(legacy).unwrap();
        assert_eq!(store.policy(DataClass::Internal).unwrap().floor_ticks, 0);
        assert!(store.deferred_queue().is_empty());
        assert_eq!(store.holds().count(), 0);
    }
}
