// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! **Precedence-guarded erasure across the real durable tiers** —
//! `REGULATED_FI_COMPLIANCE_OPS.md` §6.1 / §6.3, acceptance test 15.
//!
//! # The two defects this module closes
//!
//! The §6 precedence core ([`RecordStore::erasure_decision`], [`RecordStore::request_erasure`]) is
//! correct and proven, but until now **nothing on the live erasure path went through it**:
//!
//! 1. **Bypass (spoliation).** The one erasure path a real user can reach — `DELETE /memory` —
//!    called the memory fabric's own cascade (`ainxt_memory::store::InMemoryStore::erase_subject`)
//!    *directly*. That cascade hard-deletes **every** item scoped to the subject. It knows nothing
//!    about legal-hold matters or statutory retention floors, so a record frozen by a live
//!    litigation matter was destroyed on request — destruction of evidence under a preservation
//!    obligation, which is regulator-fatal and irreversible.
//! 2. **Vacuity.** The §6 [`RecordStore`] that `POST /v1/regfi/erasure` mutates was only ever
//!    seeded with *policies*, never with *records*: no `Record::new(` / `.put(` call site existed
//!    outside tests. So the attested erasure attested to erasing nothing while the subject's data
//!    lived on in the tier the turn path actually writes.
//!
//! Both are the *same* structural defect: the precedence store and the tiers that hold the bytes
//! were disconnected. This module connects them, in one direction only and with one entrypoint.
//!
//! # The model
//!
//! - An [`ErasableTier`] is a durable store that actually holds a subject's bytes and can (a)
//!   enumerate them and (b) hard-delete an **individual** record. [`MemoryFabricTier`] is the real
//!   adapter over the live [`ainxt_memory`] fabric the served `DELETE /memory` route owns;
//!   [`MapTier`] is the offline adapter used by tests and by tiers with no richer API.
//! - [`mirror_tier`] / [`mirror_write`] project tier records into the §6 [`RecordStore`] as
//!   [`Record`]s under a **tier-qualified id** (`"tier::id"`), so the precedence store is populated
//!   by the same writes the turn path performs. Mirroring is idempotent and **never rewrites an
//!   existing record's `created_tick`** — re-mirroring must not silently restart a retention floor.
//! - [`erase_subject_guarded`] is *the* erasure entrypoint: mirror → decide per record through
//!   [`RecordStore::request_erasure`] → hard-delete **only** the `EraseNow` records from their
//!   owning tier → leave every held/floored record physically intact and attested as
//!   deferred-with-record. It returns the tamper-evident [`ErasureAttestation`].
//! - [`RetentionSweeper`] is the cadence driver that makes "fires automatically at floor-expiry"
//!   true: on each due tick it runs the deferred queue and the TTL sweep **and propagates both into
//!   the tiers**, so a fired deferral deletes the actual bytes, not just the mirror row.
//!
//! # Redact-and-proceed
//!
//! Nothing here blocks a user. An erasure request is always accepted and always returns an
//! attestation; precedence only decides *which* records are destroyed **now** versus preserved and
//! queued. A subject under a legal hold gets a reason-coded notice, never a refusal-shaped error.
//!
//! # Conservative age anchoring
//!
//! A tier record with no trustworthy creation anchor is dated with the caller-supplied
//! `unanchored_tick`. Callers pass `now`, which makes an unanchored record look **newest** — so a
//! statutory floor *applies* rather than being silently skipped. Failing toward preservation is the
//! only safe direction: an over-preserved record can be erased later, a wrongly-destroyed one
//! cannot be restored.
//!
//! Pure and deterministic: logical ticks are passed in; no clock, no RNG, no I/O.

use ainxt_types::DataClass;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::{ErasureAttestation, Record, RecordStore};

/// The separator between the tier name and the tier-local record id in a qualified id. Chosen so it
/// cannot occur in a tier name (which is validated to be a simple slug by convention) and is
/// unlikely in a record id; [`split_qualified`] resolves ambiguity by splitting on the **first**
/// occurrence, so a record id containing the separator still round-trips.
pub const TIER_SEP: &str = "::";

/// The §6 [`RecordStore`] id for a tier-local record. Qualifying by tier is what lets a single
/// precedence store cover many durable tiers without id collisions, and what lets
/// [`erase_subject_guarded`] route each `EraseNow` decision back to the tier that owns the bytes.
pub fn qualified_id(tier: &str, record_id: &str) -> String {
    format!("{tier}{TIER_SEP}{record_id}")
}

/// Split a qualified id back into `(tier, record_id)`. `None` when the id carries no tier prefix
/// (e.g. a record seeded directly into the precedence store by an operator) — such a record is
/// erased from the store but dispatched to no tier.
pub fn split_qualified(qualified: &str) -> Option<(&str, &str)> {
    qualified.split_once(TIER_SEP)
}

/// One record as a durable tier reports it: enough to make the §6 precedence decision, and no
/// payload (the precedence core never touches content).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierRecord {
    /// Tier-local record id (the id the tier's own delete takes).
    pub id: String,
    /// The record's data class — selects the retention policy / floor and matches hold scopes.
    pub data_class: DataClass,
    /// The logical tick the record was created (the TTL / floor anchor).
    pub created_tick: u64,
}

impl TierRecord {
    pub fn new(id: &str, data_class: DataClass, created_tick: u64) -> Self {
        Self {
            id: id.to_string(),
            data_class,
            created_tick,
        }
    }
}

/// A durable store that holds a data principal's bytes and supports **per-record** hard deletion.
///
/// Per-record deletion is the whole point: an all-or-nothing `erase_subject` cascade *cannot*
/// express "destroy these three, preserve that one under matter-2026-0042", which is exactly what
/// §6.1 requires. A tier that can only erase wholesale must not be driven by this module.
pub trait ErasableTier {
    /// The tier's stable name (used as the qualified-id prefix and in the audit trail).
    fn tier_name(&self) -> &str;

    /// Every live record the tier holds for `subject_id`. `&mut self` because a real tier's
    /// subject-scoped read is itself an audited event.
    fn subject_records(&mut self, subject_id: &str) -> Vec<TierRecord>;

    /// Hard-delete exactly the tier-local ids in `ids`, on behalf of `subject_id`. Returns the ids
    /// actually removed (an id already gone is simply absent from the result — deletion is
    /// idempotent).
    ///
    /// `subject_id` is required, not convenience: a tier whose delete is *attributed* (the memory
    /// store's is) cannot authorize the erasure without knowing whose right is being exercised, and
    /// an unattributed hard-delete of governed data is the defect this signature exists to prevent.
    fn erase_records(&mut self, subject_id: &str, ids: &[String]) -> Vec<String>;
}

// ============================ mirroring (closes the vacuity defect) ============================

/// Mirror one durable **write** into the §6 precedence store (the write-path hook the served turn
/// path calls). Idempotent: an already-mirrored record is left untouched — in particular its
/// `created_tick` is **not** refreshed, so re-mirroring can never restart a statutory retention
/// floor. Returns `true` when a new record was inserted.
pub fn mirror_write(
    store: &mut RecordStore,
    tier: &str,
    record_id: &str,
    subject_id: &str,
    data_class: DataClass,
    created_tick: u64,
) -> bool {
    let qid = qualified_id(tier, record_id);
    if store.get(&qid).is_some() {
        return false;
    }
    store.put(Record::new(&qid, subject_id, data_class, created_tick));
    true
}

/// Mirror every record a tier currently holds for `subject_id` into the precedence store. This is
/// the reconciling projection used at erasure time so a store that was never write-path-mirrored
/// (or that drifted) is still non-vacuous when the decision is made. Returns how many **new**
/// records were inserted.
pub fn mirror_tier(
    store: &mut RecordStore,
    tier: &mut dyn ErasableTier,
    subject_id: &str,
) -> usize {
    let name = tier.tier_name().to_string();
    let mut inserted = 0usize;
    for tr in tier.subject_records(subject_id) {
        if mirror_write(
            store,
            &name,
            &tr.id,
            subject_id,
            tr.data_class,
            tr.created_tick,
        ) {
            inserted += 1;
        }
    }
    inserted
}

// ============================ guarded erasure (closes the bypass defect) ====================

/// The result of a guarded erasure: the regulator-facing attestation plus exactly what happened in
/// the durable tiers, so "the bytes are gone" and "the bytes were preserved under a matter" are
/// both machine-checkable rather than asserted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardedErasure {
    /// The tamper-evident §6 attestation (erased-now ids + deferred-with-record entries).
    pub attestation: ErasureAttestation,
    /// Qualified ids whose bytes were hard-deleted from their owning tier, id-sorted.
    pub tier_erased: Vec<String>,
    /// Qualified ids **preserved** in their tier under §6 precedence (legal hold / retention
    /// floor), id-sorted. These records physically still exist — that is the point.
    pub tier_preserved: Vec<String>,
    /// Records the precedence store erased that belong to no registered tier (operator-seeded, or a
    /// tier not passed to this call). Surfaced rather than hidden so a partial cascade is visible.
    pub unrouted: Vec<String>,
    /// How many tier records this call newly mirrored into the precedence store.
    pub mirrored: usize,
}

impl GuardedErasure {
    /// True when at least one record was physically preserved under a hold or floor.
    pub fn preserved_anything(&self) -> bool {
        !self.tier_preserved.is_empty()
    }
}

/// **The** right-to-erasure entrypoint for the served path (`DELETE /memory`, `POST /v1/regfi/erasure`,
/// account offboarding, DSAR erasure). Replaces every direct call to a tier's own
/// `erase_subject` cascade.
///
/// Order is fixed and load-bearing:
/// 1. **Mirror** each tier's live records into the §6 store (so the decision is made over real
///    records, never an empty store).
/// 2. **Decide** through [`RecordStore::request_erasure`] — legal-hold matter → statutory retention
///    floor → erase-now. Deferred records are queued and audited, never silently kept.
/// 3. **Propagate** only the `EraseNow` outcomes into the owning tiers. A held or floored record's
///    bytes are left physically intact.
///
/// Always succeeds (redact-and-proceed): a fully-held subject yields an attestation with an empty
/// `hard_erased` list and reason-coded deferrals, not an error.
pub fn erase_subject_guarded(
    store: &mut RecordStore,
    tiers: &mut [&mut dyn ErasableTier],
    subject_id: &str,
    now: u64,
) -> GuardedErasure {
    // 1. Mirror.
    let mut mirrored = 0usize;
    for tier in tiers.iter_mut() {
        mirrored += mirror_tier(store, *tier, subject_id);
    }

    // 2. Decide through the precedence function. Capture owners first: `request_erasure_attested`
    // removes the erase-now rows, after which the store can no longer attribute them.
    let owners = store.subject_index();
    let attestation = store.request_erasure_attested(subject_id, now);

    // 3. Propagate erase-now into the tiers; leave deferred records physically intact.
    let (tier_erased, unrouted) = propagate_erasures(tiers, &owners, attestation.hard_erased());
    let tier_preserved: Vec<String> = attestation
        .preserved_under_hold()
        .iter()
        .map(|d| d.record_id.clone())
        .collect();

    GuardedErasure {
        attestation,
        tier_erased,
        tier_preserved,
        unrouted,
        mirrored,
    }
}

/// Single-tier convenience over [`erase_subject_guarded`].
pub fn erase_subject_from_tier(
    store: &mut RecordStore,
    tier: &mut dyn ErasableTier,
    subject_id: &str,
    now: u64,
) -> GuardedErasure {
    erase_subject_guarded(store, &mut [tier], subject_id, now)
}

/// Route a set of qualified, already-decided-erasable ids into their owning tiers.
/// Returns `(erased_qualified_ids, unrouted_qualified_ids)`, both id-sorted.
fn propagate_erasures(
    tiers: &mut [&mut dyn ErasableTier],
    owners: &BTreeMap<String, String>,
    qualified: &[String],
) -> (Vec<String>, Vec<String>) {
    // Group by (tier, subject) so each tier takes one batched, *attributed* delete per subject. A
    // sweep spans many subjects, so a single subject id would be wrong here — the tier must be told
    // whose right each batch belongs to, or an attributed tier cannot authorize the delete.
    let mut by_tier: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
    let mut unrouted: Vec<String> = Vec::new();
    for qid in qualified {
        match split_qualified(qid) {
            Some((tier, local)) => {
                let subject = owners.get(qid).cloned().unwrap_or_default();
                by_tier
                    .entry((tier.to_string(), subject))
                    .or_default()
                    .push(local.to_string())
            }
            None => unrouted.push(qid.clone()),
        }
    }
    let mut erased: Vec<String> = Vec::new();
    for tier in tiers.iter_mut() {
        let name = tier.tier_name().to_string();
        let batches: Vec<(String, Vec<String>)> = by_tier
            .keys()
            .filter(|(t, _)| *t == name)
            .map(|k| k.1.clone())
            .collect::<Vec<_>>()
            .into_iter()
            .filter_map(|subject| {
                by_tier
                    .remove(&(name.clone(), subject.clone()))
                    .map(|ids| (subject, ids))
            })
            .collect();
        for (subject, ids) in batches {
            for removed in tier.erase_records(&subject, &ids) {
                erased.push(qualified_id(&name, &removed));
            }
        }
    }
    // Anything left in `by_tier` named a tier that was not passed in — surface it.
    for ((tier, _subject), ids) in by_tier {
        for id in ids {
            unrouted.push(qualified_id(&tier, &id));
        }
    }
    erased.sort();
    unrouted.sort();
    (erased, unrouted)
}

// ============================ cadence driver (§6.3 "fires automatically") ====================

/// What one [`RetentionSweeper`] tick did — the auditable record of an automatic sweep.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SweepReport {
    /// The tick the sweep ran at.
    pub tick: u64,
    /// Qualified ids fired from the deferred-erasure queue (hold released / floor elapsed).
    pub deferred_fired: Vec<String>,
    /// Qualified ids purged by the TTL sweep.
    pub ttl_purged: Vec<String>,
    /// Qualified ids whose bytes were actually deleted from a tier by this sweep.
    pub tier_erased: Vec<String>,
    /// Ids the sweep removed from the store that belong to no registered tier.
    pub unrouted: Vec<String>,
}

impl SweepReport {
    /// True when the sweep changed nothing.
    pub fn is_empty(&self) -> bool {
        self.deferred_fired.is_empty() && self.ttl_purged.is_empty()
    }
}

/// The cadence driver that makes §6.3's "at expiry it fires automatically" and §6's TTL purge
/// **true in a running system**: the precedence core already computes both correctly, but nothing
/// called it on a schedule, so a deferred erasure sat in the queue forever and an expired record was
/// never purged.
///
/// Deterministic and clock-free: the parent supplies `now`; the sweeper only decides *whether* the
/// interval has elapsed. Persisting `last_run` alongside the [`RecordStore`] snapshot (see
/// [`crate::durable`]) makes the cadence survive a restart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionSweeper {
    /// Minimum ticks between sweeps.
    pub interval_ticks: u64,
    /// The tick of the last sweep; `None` until the first run (so the first `due` is always true).
    pub last_run: Option<u64>,
}

impl RetentionSweeper {
    /// A sweeper that runs at most once per `interval_ticks`.
    pub fn new(interval_ticks: u64) -> Self {
        Self {
            interval_ticks,
            last_run: None,
        }
    }

    /// Whether a sweep is due at `now`. Always true before the first run (a fresh/restored process
    /// sweeps immediately, so a restart cannot skip an elapsed obligation).
    pub fn due(&self, now: u64) -> bool {
        match self.last_run {
            None => true,
            Some(last) => now.saturating_sub(last) >= self.interval_ticks,
        }
    }

    /// Run one sweep if due, propagating both the fired deferrals and the TTL purges into the
    /// durable tiers. Returns `None` when not due (so a caller can drive it from a tight loop).
    pub fn tick(
        &mut self,
        store: &mut RecordStore,
        tiers: &mut [&mut dyn ErasableTier],
        now: u64,
    ) -> Option<SweepReport> {
        if !self.due(now) {
            return None;
        }
        self.last_run = Some(now);
        Some(sweep_now(store, tiers, now))
    }

    /// Force a sweep regardless of cadence (operator-triggered / shutdown drain).
    pub fn force(
        &mut self,
        store: &mut RecordStore,
        tiers: &mut [&mut dyn ErasableTier],
        now: u64,
    ) -> SweepReport {
        self.last_run = Some(now);
        sweep_now(store, tiers, now)
    }
}

/// One unconditional sweep: fire the deferred queue, then TTL-purge, then propagate both into the
/// tiers. Deferred-first so a record whose hold released *and* whose TTL expired is attributed to
/// the erasure obligation (the subject's right), not to housekeeping.
pub fn sweep_now(
    store: &mut RecordStore,
    tiers: &mut [&mut dyn ErasableTier],
    now: u64,
) -> SweepReport {
    // Owners must be captured before the rows are removed (see `RecordStore::subject_index`).
    let owners = store.subject_index();
    let deferred_fired = store.run_deferred(now);
    let ttl_purged = store.purge_expired(now);
    let mut all: Vec<String> = deferred_fired.to_vec();
    all.extend(ttl_purged.iter().cloned());
    let (tier_erased, unrouted) = propagate_erasures(tiers, &owners, &all);
    SweepReport {
        tick: now,
        deferred_fired,
        ttl_purged,
        tier_erased,
        unrouted,
    }
}

// ============================ tier adapters ============================

/// The **real** adapter over the live [`ainxt_memory`] fabric — the tier the served `DELETE /memory`
/// route owns and the turn path writes. Enumerates the subject's current items through the fabric's
/// own DPDP subject export and deletes per-item through [`ainxt_memory::MemoryStore::delete`], so a
/// held record can be preserved while its unheld siblings are destroyed (which the fabric's own
/// wholesale `erase_subject` cascade structurally cannot do).
///
/// `unanchored_tick` dates items that carry no `effective_from` anchor. Pass `now`: an unanchored
/// item then looks newest, so a statutory floor applies instead of being silently skipped
/// (fail-toward-preservation — see the module doc).
pub struct MemoryFabricTier<'a> {
    store: &'a mut ainxt_memory::store::InMemoryStore,
    tier: String,
    unanchored_tick: u64,
}

impl<'a> MemoryFabricTier<'a> {
    /// The default tier name for the memory fabric.
    pub const TIER: &'static str = "memory-fabric";

    /// Wrap the live fabric store. `unanchored_tick` should be the request's `now`.
    pub fn new(store: &'a mut ainxt_memory::store::InMemoryStore, unanchored_tick: u64) -> Self {
        Self {
            store,
            tier: Self::TIER.to_string(),
            unanchored_tick,
        }
    }

    /// Override the tier name (a deployment running several fabrics distinguishes them).
    pub fn with_tier_name(mut self, tier: &str) -> Self {
        self.tier = tier.to_string();
        self
    }
}

impl ErasableTier for MemoryFabricTier<'_> {
    fn tier_name(&self) -> &str {
        &self.tier
    }

    fn subject_records(&mut self, subject_id: &str) -> Vec<TierRecord> {
        use ainxt_memory::access::AccessScope;
        use ainxt_types::Principal;
        // Self-scope: the export is of the subject's OWN data, so no cross-subject visibility is
        // requested and no break-glass is asserted. A fabric that refuses the export contributes
        // nothing rather than erroring — the erasure still proceeds over the other tiers.
        let who = AccessScope::from_principal(Principal::user(subject_id, &[]));
        let Ok(export) = self.store.export_subject(subject_id, &who) else {
            return Vec::new();
        };
        // The export carries every version; the precedence unit is the ITEM (delete removes all its
        // versions), so collapse to the current version — the highest `version` per id.
        let mut current: BTreeMap<String, TierRecord> = BTreeMap::new();
        let mut best_version: BTreeMap<String, u32> = BTreeMap::new();
        for item in export.items {
            let keep = best_version
                .get(&item.id)
                .is_none_or(|v| item.version >= *v);
            if !keep {
                continue;
            }
            best_version.insert(item.id.clone(), item.version);
            current.insert(
                item.id.clone(),
                TierRecord::new(
                    &item.id,
                    item.data_class,
                    item.effective_from.unwrap_or(self.unanchored_tick),
                ),
            );
        }
        current.into_values().collect()
    }

    fn erase_records(&mut self, subject_id: &str, ids: &[String]) -> Vec<String> {
        use ainxt_memory::access::AccessScope;
        use ainxt_memory::MemoryStore;
        use ainxt_types::Principal;
        // The subject exercising their OWN right-to-erasure: the memory store authorizes the delete
        // against the item's scope and records the actor in its tamper-evident chain. An item the
        // subject may not erase (shared-scope knowledge retained for audit) is refused there and is
        // simply absent from `removed` — the §6 precedence guard above has already decided which ids
        // are eligible, so a refusal here is reported, never silently treated as erased.
        let who = AccessScope::from_principal(Principal::user(subject_id, &[]));
        let mut removed = Vec::new();
        for id in ids {
            if self.store.delete_as(id, &who).unwrap_or(false) {
                removed.push(id.clone());
            }
        }
        removed
    }
}

/// The **real** adapter over the live [`ainxt_replay`] turn-tree/replay store — the tier
/// `ainxt_runtimed::persist_served_turn`'s write-path mirror already keys its records under
/// (`SERVED_TURN_TIER` = `"served-turn"`, see [`Self::TIER`]). Before this adapter existed, both live
/// call sites of [`erase_subject_guarded`] passed an explicitly empty tier slice — the §6 precedence
/// decision was made over real, mirrored records, but nothing ever propagated an `EraseNow`/fired
/// deferral back into the store that actually holds the conversational bytes, so a "successful"
/// erasure never touched the subject's real durable data.
///
/// # Never deletes a [`Turn`](ainxt_replay::Turn) — erases its bytes
///
/// `ainxt_replay`'s own module doc is explicit: "a turn is never deleted — a stopped or superseded
/// turn stays fully replayable and audit-visible." [`ErasableTier::erase_records`] must still
/// hard-delete the actual regulated bytes (§6.3: "a fired deferral deletes the actual bytes, not just
/// the mirror row"), so this adapter reconciles both invariants the same way
/// [`ainxt_memory`]'s `re_redact` reconciles "never lose the item" with "content must not survive a
/// compliance rule": it clears the **content** of every event belonging to the erased turn
/// ([`ainxt_replay::SessionRecording::erase_turn_content`]) in place and leaves the turn id / tree
/// position / role as a tombstone. The turn's `author` (the subject's own id) also remains — this is
/// the honest boundary of this adapter: it erases the CONTENT a subject exercises DPDP erasure over,
/// not the tree metadata that keeps the session structurally replayable and audit-visible for every
/// OTHER participant's turns.
///
/// # Attributing the assistant's reply to the subject
///
/// `persist_served_turn` mirrors BOTH the user turn and its assistant reply under the SAME
/// `subject_id` (the participant), even though the assistant [`Turn`](ainxt_replay::Turn)'s own
/// `author` field is the literal string `"assistant"`. [`Self::subject_records`] reproduces that
/// attribution by walking each subject-authored turn's direct tree children for an `Assistant`-role
/// turn — exactly the `"{turn_id}::assistant"` shape `persist_served_turn` always produces — rather
/// than matching on `Turn::author`, which would silently miss every assistant reply.
///
/// `unanchored_tick` dates a turn with no recorded event (e.g. a served turn whose `user_input` was
/// empty) with the caller-supplied `now`, so a statutory floor applies rather than being silently
/// skipped — the same fail-toward-preservation posture [`MemoryFabricTier`] documents.
pub struct SessionReplayTier {
    store: std::sync::Arc<dyn ainxt_replay::SessionStore>,
    tier: String,
    unanchored_tick: u64,
}

impl SessionReplayTier {
    /// The tier name `persist_served_turn` mirrors served-turn records under
    /// (`ainxt_runtimed::SERVED_TURN_TIER`). Not a shared constant — `ainxt-lifecycle` has no
    /// dependency on `ainxt-runtimed` (that edge runs the other way); the two crates agree on this
    /// literal by convention, exactly as `ainxt_server::regfi_erasure_handler`'s doc already commits to.
    pub const TIER: &'static str = "served-turn";

    /// Wrap the live replay/session store. `unanchored_tick` should be the request's/sweep's `now`.
    pub fn new(
        store: std::sync::Arc<dyn ainxt_replay::SessionStore>,
        unanchored_tick: u64,
    ) -> Self {
        Self {
            store,
            tier: Self::TIER.to_string(),
            unanchored_tick,
        }
    }

    /// Override the tier name (a deployment running several replay stores distinguishes them).
    pub fn with_tier_name(mut self, tier: &str) -> Self {
        self.tier = tier.to_string();
        self
    }

    /// The most sensitive [`DataClass`] recorded among a turn's events, or `None` if the turn has no
    /// non-`TurnStart` event yet (`TurnStart` is always stamped `DataClass::Internal` by
    /// `ainxt_replay::SessionRecording::append_turn`/`append_root_turn`, which under-states a turn
    /// whose real content event has not been observed in this pass).
    fn turn_data_class(events: &[ainxt_replay::ReplayEvent], turn_id: &str) -> Option<DataClass> {
        events
            .iter()
            .filter(|e| e.turn_id == turn_id)
            .map(|e| e.data_class)
            .max_by_key(|c| c.sensitivity())
    }

    /// The earliest `ts_millis` among a turn's events, if any.
    fn turn_earliest_ms(events: &[ainxt_replay::ReplayEvent], turn_id: &str) -> Option<u128> {
        events
            .iter()
            .filter(|e| e.turn_id == turn_id)
            .map(|e| e.ts_millis)
            .min()
    }
}

impl ErasableTier for SessionReplayTier {
    fn tier_name(&self) -> &str {
        &self.tier
    }

    fn subject_records(&mut self, subject_id: &str) -> Vec<TierRecord> {
        use ainxt_replay::{SessionRecording, TurnRole};
        let mut out = Vec::new();
        for session_id in self.store.sessions() {
            let Ok(Some(durable)) = self.store.load(&session_id) else {
                continue;
            };
            let rec = SessionRecording::from_durable(durable);
            let tree = rec.tree();
            let events = rec.events();
            for (turn_id, turn) in events
                .iter()
                .map(|e| e.turn_id.as_str())
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .filter_map(|id| tree.turn(id).map(|t| (id, t)))
            {
                if turn.author != subject_id {
                    continue;
                }
                let created_tick = Self::turn_earliest_ms(events, turn_id)
                    .map(|ms| (ms / 1000) as u64)
                    .unwrap_or(self.unanchored_tick);
                let data_class =
                    Self::turn_data_class(events, turn_id).unwrap_or(DataClass::Internal);
                out.push(TierRecord::new(turn_id, data_class, created_tick));
                // The assistant's reply is mirrored under the SAME subject id by
                // `persist_served_turn` even though its own `author` is "assistant" — attribute it
                // here via the tree, not `Turn::author` (see the type doc).
                for child_id in tree.children(turn_id) {
                    if tree.turn(child_id).map(|c| c.role) == Some(TurnRole::Assistant) {
                        let child_tick = Self::turn_earliest_ms(events, child_id)
                            .map(|ms| (ms / 1000) as u64)
                            .unwrap_or(created_tick);
                        let child_class =
                            Self::turn_data_class(events, child_id).unwrap_or(data_class);
                        out.push(TierRecord::new(child_id, child_class, child_tick));
                    }
                }
            }
        }
        out
    }

    fn erase_records(&mut self, _subject_id: &str, ids: &[String]) -> Vec<String> {
        use ainxt_replay::SessionRecording;
        let want: std::collections::BTreeSet<&str> = ids.iter().map(String::as_str).collect();
        let mut removed = Vec::new();
        for session_id in self.store.sessions() {
            let Ok(Some(durable)) = self.store.load(&session_id) else {
                continue;
            };
            let mut rec = SessionRecording::from_durable(durable);
            let mut touched: Vec<String> = Vec::new();
            for id in &want {
                if rec.erase_turn_content(id) {
                    touched.push(id.to_string());
                }
            }
            if !touched.is_empty() && self.store.save(&rec.to_durable()).is_ok() {
                removed.extend(touched);
            }
        }
        removed
    }
}

/// An offline [`ErasableTier`] over a plain map — the adapter for tiers whose durable binding is
/// infra (event log, replay store, vector index) and the double used to prove the guard itself.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct MapTier {
    tier: String,
    /// record id → (subject, class, created tick).
    rows: BTreeMap<String, (String, DataClass, u64)>,
}

impl MapTier {
    pub fn new(tier: &str) -> Self {
        Self {
            tier: tier.to_string(),
            rows: BTreeMap::new(),
        }
    }

    /// Insert a row (chainable).
    pub fn with_row(
        mut self,
        id: &str,
        subject_id: &str,
        data_class: DataClass,
        created_tick: u64,
    ) -> Self {
        self.put(id, subject_id, data_class, created_tick);
        self
    }

    /// Insert/overwrite a row.
    pub fn put(&mut self, id: &str, subject_id: &str, data_class: DataClass, created_tick: u64) {
        self.rows.insert(
            id.to_string(),
            (subject_id.to_string(), data_class, created_tick),
        );
    }

    /// Whether the tier still holds `id`.
    pub fn contains(&self, id: &str) -> bool {
        self.rows.contains_key(id)
    }

    /// Number of live rows.
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// True when the tier holds nothing.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
}

impl ErasableTier for MapTier {
    fn tier_name(&self) -> &str {
        &self.tier
    }

    fn subject_records(&mut self, subject_id: &str) -> Vec<TierRecord> {
        self.rows
            .iter()
            .filter(|(_, (s, _, _))| s == subject_id)
            .map(|(id, (_, class, tick))| TierRecord::new(id, *class, *tick))
            .collect()
    }

    fn erase_records(&mut self, _subject_id: &str, ids: &[String]) -> Vec<String> {
        let mut removed = Vec::new();
        for id in ids {
            if self.rows.remove(id).is_some() {
                removed.push(id.clone());
            }
        }
        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DeferralCause, HoldScope, LegalHold, RetentionPolicy};

    fn store() -> RecordStore {
        RecordStore::new()
            .with_policy(RetentionPolicy::new(DataClass::Internal, 10_000))
            .with_policy(RetentionPolicy::new(DataClass::Pii, 10_000).with_floor(500))
            .with_policy(RetentionPolicy::new(DataClass::Confidential, 10_000))
    }

    #[test]
    fn mirroring_is_idempotent_and_never_restarts_a_floor() {
        let mut rs = store();
        let mut tier = MapTier::new("t").with_row("a", "alice", DataClass::Pii, 10);
        assert_eq!(mirror_tier(&mut rs, &mut tier, "alice"), 1);
        // A second mirror inserts nothing and leaves created_tick at 10 (not refreshed to 900).
        assert_eq!(mirror_tier(&mut rs, &mut tier, "alice"), 0);
        assert!(!mirror_write(
            &mut rs,
            "t",
            "a",
            "alice",
            DataClass::Pii,
            900
        ));
        assert_eq!(rs.get(&qualified_id("t", "a")).unwrap().created_tick, 10);
    }

    #[test]
    fn unrouted_records_are_surfaced_not_hidden() {
        let mut rs = store();
        rs.put(Record::new(
            "operator-seeded",
            "alice",
            DataClass::Internal,
            0,
        ));
        let mut tier = MapTier::new("t");
        let out = erase_subject_from_tier(&mut rs, &mut tier, "alice", 100);
        assert_eq!(out.unrouted, vec!["operator-seeded".to_string()]);
        assert!(out.tier_erased.is_empty());
    }

    #[test]
    fn deferred_queue_fires_into_the_tier_at_floor_expiry() {
        let mut rs = store();
        let mut tier = MapTier::new("t").with_row("p", "alice", DataClass::Pii, 0);
        let out = erase_subject_from_tier(&mut rs, &mut tier, "alice", 10);
        assert!(out.attestation.hard_erased().is_empty());
        assert!(tier.contains("p"), "floor-bound bytes preserved");
        match &out.attestation.preserved_under_hold()[0].cause {
            DeferralCause::RetentionFloor { floor_expiry } => assert_eq!(*floor_expiry, 500),
            other => panic!("expected a retention-floor deferral, got {other:?}"),
        }

        let mut sweeper = RetentionSweeper::new(60);
        // Not yet at floor-expiry: due (first run), but nothing fires.
        let r = sweeper.tick(&mut rs, &mut [&mut tier], 100).unwrap();
        assert!(r.is_empty());
        assert!(tier.contains("p"));
        // Cadence not elapsed → no sweep at all.
        assert!(sweeper.tick(&mut rs, &mut [&mut tier], 130).is_none());
        // At floor-expiry the queued erasure fires AND the tier bytes go.
        let r = sweeper.tick(&mut rs, &mut [&mut tier], 500).unwrap();
        assert_eq!(r.deferred_fired, vec![qualified_id("t", "p")]);
        assert_eq!(r.tier_erased, vec![qualified_id("t", "p")]);
        assert!(
            !tier.contains("p"),
            "bytes destroyed once the floor elapsed"
        );
    }

    #[test]
    fn legal_hold_matter_preserves_bytes_while_free_siblings_are_destroyed() {
        let mut rs = store();
        rs.add_hold(LegalHold::open(
            "matter-1",
            "dpo",
            HoldScope::any()
                .with_subject("alice")
                .with_data_class(DataClass::Confidential),
            0,
        ));
        let mut tier = MapTier::new("t")
            .with_row("free", "alice", DataClass::Internal, 0)
            .with_row("held", "alice", DataClass::Confidential, 0);
        let out = erase_subject_from_tier(&mut rs, &mut tier, "alice", 1_000);
        assert_eq!(out.tier_erased, vec![qualified_id("t", "free")]);
        assert!(!tier.contains("free"));
        assert!(tier.contains("held"), "matter-held bytes must survive");
        assert!(out.preserved_anything());
    }

    #[test]
    fn ttl_purge_propagates_into_the_tier() {
        let mut rs = RecordStore::new().with_policy(RetentionPolicy::new(DataClass::Internal, 10));
        let mut tier = MapTier::new("t").with_row("old", "alice", DataClass::Internal, 0);
        mirror_tier(&mut rs, &mut tier, "alice");
        let report = sweep_now(&mut rs, &mut [&mut tier], 1_000);
        assert_eq!(report.ttl_purged, vec![qualified_id("t", "old")]);
        assert!(!tier.contains("old"));
    }

    // ============================ SessionReplayTier ============================

    fn seeded_replay_store(
        session: &str,
        turn_id: &str,
        subject: &str,
        data_class: DataClass,
        ms: u128,
    ) -> std::sync::Arc<dyn ainxt_replay::SessionStore> {
        use ainxt_replay::{SessionRecording, TurnRole};
        let store: std::sync::Arc<dyn ainxt_replay::SessionStore> =
            std::sync::Arc::new(ainxt_replay::InMemorySessionStore::new());
        let mut rec = SessionRecording::new(session, &[subject]);
        rec.append_root_turn(turn_id, TurnRole::User, subject, ms)
            .unwrap();
        rec.record_event(
            turn_id,
            ainxt_replay::EventKind::TextDelta,
            data_class,
            "hello",
            ms,
        )
        .unwrap();
        let assistant_id = format!("{turn_id}::assistant");
        rec.append_turn(
            &assistant_id,
            turn_id,
            TurnRole::Assistant,
            "assistant",
            ms + 1,
        )
        .unwrap();
        rec.record_event(
            &assistant_id,
            ainxt_replay::EventKind::TextDelta,
            data_class,
            "hi there",
            ms + 1,
        )
        .unwrap();
        store.save(&rec.to_durable()).unwrap();
        store
    }

    #[test]
    fn session_replay_tier_finds_both_the_user_turn_and_its_assistant_reply() {
        let store = seeded_replay_store("s1", "u1", "alice", DataClass::Pii, 5_000);
        let mut tier = SessionReplayTier::new(store, 0);
        let mut records = tier.subject_records("alice");
        records.sort_by(|a, b| a.id.cmp(&b.id));
        assert_eq!(
            records.len(),
            2,
            "the user turn AND the attributed assistant reply"
        );
        assert_eq!(records[0].id, "u1");
        assert_eq!(records[1].id, "u1::assistant");
        for r in &records {
            assert_eq!(
                r.data_class,
                DataClass::Pii,
                "content data-class carried through"
            );
            assert_eq!(r.created_tick, 5, "5000ms -> tick 5");
        }
        // A stranger's records are never returned.
        assert!(tier.subject_records("mallory").is_empty());
    }

    #[test]
    fn session_replay_tier_erase_records_clears_bytes_never_deletes_the_turn() {
        let store = seeded_replay_store("s1", "u1", "alice", DataClass::Pii, 5_000);
        let mut tier = SessionReplayTier::new(store.clone(), 0);
        let removed = tier.erase_records("alice", &["u1".to_string(), "u1::assistant".to_string()]);
        assert_eq!(
            removed.len(),
            2,
            "both turns had non-empty content to erase"
        );

        // The bytes are gone from the LIVE store (read back through the store, not the tier).
        let durable = store.load("s1").unwrap().unwrap();
        let rec = ainxt_replay::SessionRecording::from_durable(durable);
        for e in rec.events() {
            assert!(e.text.is_empty(), "event {:?} must be byte-erased", e.kind);
        }
        // The turns themselves are never deleted — still present, still linked.
        assert!(rec.tree().turn("u1").is_some());
        assert!(rec.tree().turn("u1::assistant").is_some());
        assert!(rec.tree().children("u1").contains(&"u1::assistant"));

        // Idempotent: a second erase over the same ids finds nothing left to remove.
        let mut tier2 = SessionReplayTier::new(store, 0);
        assert!(tier2
            .erase_records("alice", &["u1".to_string(), "u1::assistant".to_string()])
            .is_empty());
    }

    #[test]
    fn session_replay_tier_wired_through_guarded_erasure_deletes_real_bytes_at_floor_expiry() {
        // End-to-end over the REAL RecordStore precedence + RetentionSweeper cadence, with the
        // SessionReplayTier as the propagation target — the exact shape the two composition-root call
        // sites (`ainxt_runtimed::AssembledFull::erase_subject_attested`,
        // `ainxt_server::regfi_erasure_handler`) now drive, minus the HTTP/composition scaffolding.
        let mut rs = RecordStore::new()
            .with_policy(RetentionPolicy::new(DataClass::Pii, 100_000).with_floor(500));
        let store = seeded_replay_store("s1", "u1", "alice", DataClass::Pii, 10_000); // tick 10
        let mut tier = SessionReplayTier::new(store.clone(), 10);

        // Request erasure well before the floor: both turns are DEFERRED, bytes untouched.
        let out = erase_subject_from_tier(&mut rs, &mut tier, "alice", 50);
        assert!(
            out.attestation.hard_erased().is_empty(),
            "floor not yet elapsed"
        );
        assert_eq!(out.tier_preserved.len(), 2);
        {
            let durable = store.load("s1").unwrap().unwrap();
            let rec = ainxt_replay::SessionRecording::from_durable(durable);
            assert!(
                rec.events().iter().any(|e| !e.text.is_empty()),
                "bytes must survive while the floor holds"
            );
        }

        // At floor-expiry (created_tick=10 + floor=500 => 510), a sweep fires the deferred queue AND
        // propagates the erasure into the SessionReplayTier — the REAL bytes must now be gone.
        let mut sweeper = RetentionSweeper::new(1);
        let report = sweeper.force(&mut rs, &mut [&mut tier], 510);
        assert_eq!(
            report.deferred_fired.len(),
            2,
            "both mirrored turns fire at floor-expiry"
        );
        assert_eq!(
            report.tier_erased.len(),
            2,
            "both propagate into the real session store"
        );

        let durable = store.load("s1").unwrap().unwrap();
        let rec = ainxt_replay::SessionRecording::from_durable(durable);
        for e in rec.events() {
            assert!(
                e.text.is_empty(),
                "the sweep must delete the ACTUAL bytes, not just the mirror row"
            );
        }
        // And the turn is still there — never deleted, only its content.
        assert!(rec.tree().turn("u1").is_some());
    }
}
