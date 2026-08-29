// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Durable persistence for the memory core (design §2/§3: "OKIs remain stored in Postgres with full
//! lifecycle governance"; MemoryFacts + consent/erasure receipts + the tamper-evident audit chain
//! are durable too). This module is the **seam** between the governance logic (which lives, proven,
//! in [`InMemoryStore`]) and a relational database — so the exact same invariants (human-gate,
//! typed-payload schema, compliance-on-write redaction, edit-free versioning, RBAC pre-rank) run
//! whether memory is ephemeral or Postgres-backed.
//!
//! Shape (mirrors the [`ainxt_token`](../../ainxt-token) durable-token pattern):
//!
//! - [`SqlLike`] — a narrow, row-oriented relational seam. Every method maps 1:1 to one
//!   parameterized statement against the [`MEMORY_STORE_DDL`] tables (`memory_items`,
//!   `memory_audit`, `memory_consent`). The seam is the *only* thing that talks to a DB driver.
//! - [`MemorySqlBackend`] — an offline, cloneable in-memory backend that models those three tables
//!   exactly (append-only versions, ordered audit, consent receipts). It lets the durable store's
//!   logic be proven **without a live database**; cloning it models several processes sharing one DB.
//! - [`DurableMemoryStore`] — composes an in-RAM [`InMemoryStore`] working set (all governance logic
//!   reused, not re-implemented) with a [`SqlLike`] backend, **write-through** on every mutation and
//!   **hydrated** from the backend on [`open`](DurableMemoryStore::open). Restart-durable: reopen
//!   over the same backend and every governed item, audit entry, and erasure receipt is still there.
//! - [`pg`] (feature `postgres`) — a driver-agnostic Postgres binding that issues the real SQL. It
//!   pulls **no** database crate; a deployment backs it with rust-postgres/sqlx. Off by default so
//!   the default build and the tests never touch a live database.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use crate::store::AuditEntry;
use crate::{
    AccessScope, ConsentView, ErasureReceipt, GovernanceState, InMemoryStore, MemoryError,
    MemoryHit, MemoryItem, MemoryQuery, MemoryStore, Principal, Redactor, RetentionPolicy,
    SubjectExport,
};

// ============================ Canonical schema ============================

/// Idempotent DDL for the durable memory schema. A production [`SqlLike`] backend runs this once at
/// startup. `memory_items` is append-only per `(id, version)` (edit-free versioning + forensic
/// replay); `memory_audit` is the ordered hash chain (`AK`: erasure/governance provable, not just
/// performed); `memory_consent` holds DPDP right-to-erasure receipts keyed to the audit entry that
/// signed them. Column types are Postgres; other backends map them.
pub const MEMORY_STORE_DDL: &str = "\
CREATE TABLE IF NOT EXISTS memory_items (
    id      text   NOT NULL,
    version integer NOT NULL,
    body    text   NOT NULL,
    PRIMARY KEY (id, version)
);
CREATE TABLE IF NOT EXISTS memory_audit (
    seq       bigint NOT NULL PRIMARY KEY,
    action    text   NOT NULL,
    subject   text   NOT NULL,
    detail    text   NOT NULL,
    prev_hash bigint NOT NULL,
    hash      bigint NOT NULL,
    prev_digest text NOT NULL DEFAULT '',
    digest      text NOT NULL DEFAULT '',
    hasher      text NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS memory_consent (
    audit_seq bigint NOT NULL PRIMARY KEY,
    subject   text   NOT NULL,
    body      text   NOT NULL
);";

// ============================ Row DTOs ============================

/// One `memory_items` row: an item version serialized as JSON in `body`. This is the exact shape a
/// backend reads/writes; the JSON is already compliance-redacted (redaction happens before the write
/// reaches this layer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemRow {
    /// Item id.
    pub id: String,
    /// Per-id version (edit-free versioning; last = current).
    pub version: u32,
    /// The [`MemoryItem`] serialized as JSON.
    pub body: String,
}

/// One `memory_audit` row — a hash-chained governance/erasure entry (mirrors [`AuditEntry`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRow {
    /// Monotonic audit index.
    pub seq: u64,
    /// What happened (`promote`, `erase-subject`, `break-glass-read`, …).
    pub action: String,
    /// The subject (item id / user id).
    pub subject: String,
    /// Free detail.
    pub detail: String,
    /// 64-bit fold of the previous entry's digest (0 for the first).
    pub prev_hash: u64,
    /// 64-bit fold of this entry's digest.
    pub hash: u64,
    /// The previous entry's full-width digest.
    pub prev_digest: String,
    /// This entry's full-width digest — the authoritative chain value.
    pub digest: String,
    /// Name of the hasher that produced `digest`.
    pub hasher: String,
}

impl From<&AuditEntry> for AuditRow {
    fn from(e: &AuditEntry) -> Self {
        AuditRow {
            seq: e.seq,
            action: e.action.clone(),
            subject: e.subject.clone(),
            detail: e.detail.clone(),
            prev_hash: e.prev_hash,
            hash: e.hash,
            prev_digest: e.prev_digest.clone(),
            digest: e.digest.clone(),
            hasher: e.hasher.clone(),
        }
    }
}

impl From<AuditRow> for AuditEntry {
    fn from(r: AuditRow) -> Self {
        AuditEntry {
            seq: r.seq,
            action: r.action,
            subject: r.subject,
            detail: r.detail,
            prev_hash: r.prev_hash,
            hash: r.hash,
            prev_digest: r.prev_digest,
            digest: r.digest,
            hasher: r.hasher,
        }
    }
}

/// One `memory_consent` row — a DPDP right-to-erasure receipt, keyed to the signed audit entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentRow {
    /// The audit-chain seq of the signed erasure entry.
    pub audit_seq: u64,
    /// The subject the receipt is about.
    pub subject: String,
    /// The [`ErasureReceipt`] serialized as JSON.
    pub body: String,
}

// ============================ Errors ============================

/// A durable-backend failure (driver/IO). The in-memory backend never returns this; a real Postgres
/// backend surfaces its errors so the store's write-through path fails closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqlError(pub String);

impl std::fmt::Display for SqlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "sql backend error: {}", self.0)
    }
}
impl std::error::Error for SqlError {}

impl From<SqlError> for MemoryError {
    fn from(e: SqlError) -> Self {
        MemoryError::Storage(e.0)
    }
}

// ============================ The relational seam ============================

/// The narrow, row-oriented relational seam behind [`DurableMemoryStore`]. Every method maps to one
/// parameterized SQL statement against the [`MEMORY_STORE_DDL`] tables; the trait is the boundary a
/// DB driver lives behind, so the store logic is testable without a live database. Implementations
/// must be internally consistent (append-only versions, monotonic audit) — the store relies on it.
pub trait SqlLike: std::fmt::Debug + Send + Sync {
    /// `INSERT INTO memory_items (id,version,body) VALUES ($1,$2,$3)
    ///  ON CONFLICT (id,version) DO UPDATE SET body = EXCLUDED.body` — idempotent version upsert.
    fn upsert_item(&self, id: &str, version: u32, body: &str) -> Result<(), SqlError>;
    /// `DELETE FROM memory_items WHERE id=$1` — returns the number of version rows removed.
    fn delete_item(&self, id: &str) -> Result<u64, SqlError>;
    /// `SELECT id,version,body FROM memory_items` — all versions (hydration on restart).
    fn load_items(&self) -> Result<Vec<ItemRow>, SqlError>;
    /// `INSERT INTO memory_audit (...) VALUES (...)` — append one hash-chained entry.
    fn append_audit(&self, row: &AuditRow) -> Result<(), SqlError>;
    /// `SELECT ... FROM memory_audit ORDER BY seq` — the full chain (hydration on restart).
    fn load_audit(&self) -> Result<Vec<AuditRow>, SqlError>;
    /// `INSERT INTO memory_consent (audit_seq,subject,body) VALUES ($1,$2,$3)
    ///  ON CONFLICT (audit_seq) DO NOTHING` — persist a DPDP erasure receipt.
    fn record_consent(&self, audit_seq: u64, subject: &str, body: &str) -> Result<(), SqlError>;
    /// `SELECT audit_seq,subject,body FROM memory_consent ORDER BY audit_seq` — all receipts.
    fn load_consent(&self) -> Result<Vec<ConsentRow>, SqlError>;
}

// ============================ In-memory backend (offline test double) ============================

/// An offline fake of the relational backend that models the three tables exactly: `memory_items`
/// keyed by `(id, version)` with upsert + per-id delete; `memory_audit` ordered by `seq`;
/// `memory_consent` keyed by `audit_seq`. Proves [`DurableMemoryStore`]'s logic without a live DB;
/// production replaces it with a Postgres-backed [`SqlLike`]. **Cheap to clone — clones share the
/// tables**, modelling several worker processes talking to one database (so a store opened over a
/// clone sees another store's committed writes: real cross-process durability semantics).
#[derive(Debug, Clone, Default)]
pub struct MemorySqlBackend {
    items: Arc<Mutex<HashMap<(String, u32), String>>>,
    audit: Arc<Mutex<Vec<AuditRow>>>,
    consent: Arc<Mutex<HashMap<u64, ConsentRow>>>,
}

impl MemorySqlBackend {
    /// A fresh, empty backend (the three tables exist and are empty).
    pub fn new() -> Self {
        Self::default()
    }
}

fn poisoned() -> SqlError {
    SqlError("backend mutex poisoned".into())
}

impl SqlLike for MemorySqlBackend {
    fn upsert_item(&self, id: &str, version: u32, body: &str) -> Result<(), SqlError> {
        self.items
            .lock()
            .map_err(|_| poisoned())?
            .insert((id.to_string(), version), body.to_string());
        Ok(())
    }
    fn delete_item(&self, id: &str) -> Result<u64, SqlError> {
        let mut t = self.items.lock().map_err(|_| poisoned())?;
        let before = t.len();
        t.retain(|(k, _), _| k != id);
        Ok((before - t.len()) as u64)
    }
    fn load_items(&self) -> Result<Vec<ItemRow>, SqlError> {
        let t = self.items.lock().map_err(|_| poisoned())?;
        let mut rows: Vec<ItemRow> = t
            .iter()
            .map(|((id, version), body)| ItemRow {
                id: id.clone(),
                version: *version,
                body: body.clone(),
            })
            .collect();
        rows.sort_by(|a, b| a.id.cmp(&b.id).then(a.version.cmp(&b.version)));
        Ok(rows)
    }
    fn append_audit(&self, row: &AuditRow) -> Result<(), SqlError> {
        let mut a = self.audit.lock().map_err(|_| poisoned())?;
        // Primary key on seq — reject a duplicate rather than silently double-append.
        if a.iter().any(|e| e.seq == row.seq) {
            return Err(SqlError(format!("duplicate audit seq {}", row.seq)));
        }
        a.push(row.clone());
        Ok(())
    }
    fn load_audit(&self) -> Result<Vec<AuditRow>, SqlError> {
        let mut a = self.audit.lock().map_err(|_| poisoned())?.clone();
        a.sort_by_key(|e| e.seq);
        Ok(a)
    }
    fn record_consent(&self, audit_seq: u64, subject: &str, body: &str) -> Result<(), SqlError> {
        self.consent.lock().map_err(|_| poisoned())?.insert(
            audit_seq,
            ConsentRow {
                audit_seq,
                subject: subject.to_string(),
                body: body.to_string(),
            },
        );
        Ok(())
    }
    fn load_consent(&self) -> Result<Vec<ConsentRow>, SqlError> {
        let c = self.consent.lock().map_err(|_| poisoned())?;
        let mut rows: Vec<ConsentRow> = c.values().cloned().collect();
        rows.sort_by_key(|r| r.audit_seq);
        Ok(rows)
    }
}

// ============================ Durable store ============================

/// A FNV-1a fingerprint of a persisted row body — lets write-through upsert only the versions whose
/// serialized content actually changed (immutable older versions are skipped after first persist).
fn fingerprint(s: &str) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// A durable [`MemoryStore`] backed by a [`SqlLike`] database. Composes an in-RAM [`InMemoryStore`]
/// (all governance/compliance logic reused verbatim) with a relational backend, writing through on
/// every mutation and hydrating from the backend on [`open`](DurableMemoryStore::open). The result
/// is restart-durable and cross-process-shareable while preserving *every* invariant the reference
/// store enforces. Mutating operations return [`MemoryError::Storage`] if the backend fails, so the
/// write-through fails closed.
#[derive(Debug)]
pub struct DurableMemoryStore<D: SqlLike> {
    mem: InMemoryStore,
    db: D,
    /// (id, version) → fingerprint of the last-persisted body (incremental write-through).
    persisted: HashMap<(String, u32), u64>,
    /// Number of audit entries already persisted (append-only tail beyond this is flushed).
    persisted_audit: usize,
    /// Deferred backend error from an infallible trait method (surfaced via [`take_sync_error`]).
    sync_error: Option<MemoryError>,
}

impl<D: SqlLike> DurableMemoryStore<D> {
    /// Open a durable store over `db`, hydrating the in-RAM working set from the backend: every
    /// persisted item version (regrouped so "last = current"), the full audit chain, and the logical
    /// clock (restored to the max persisted `seq`). A freshly-created backend yields an empty store;
    /// a backend that already holds another process's committed writes yields those writes.
    pub fn open(db: D) -> Result<Self, MemoryError> {
        let item_rows = db.load_items()?;
        let mut versions = Vec::with_capacity(item_rows.len());
        let mut persisted = HashMap::with_capacity(item_rows.len());
        for r in item_rows {
            let item: MemoryItem =
                serde_json::from_str(&r.body).map_err(|e| MemoryError::Storage(e.to_string()))?;
            persisted.insert((r.id.clone(), r.version), fingerprint(&r.body));
            versions.push(item);
        }
        let mut audit: Vec<AuditEntry> =
            db.load_audit()?.into_iter().map(AuditEntry::from).collect();
        audit.sort_by_key(|e| e.seq);
        let persisted_audit = audit.len();
        let mem = InMemoryStore::from_persisted(versions, audit);
        Ok(DurableMemoryStore {
            mem,
            db,
            persisted,
            persisted_audit,
            sync_error: None,
        })
    }

    /// Swap the compliance-gate *provider* on the in-RAM working set (e.g. an adapter over the
    /// runtime's full compliance engine so a memory write is redacted by exactly the same detector
    /// the turn pipeline uses). The gate is never removable — this only changes which redactor runs.
    pub fn with_redactor(mut self, redactor: Box<dyn Redactor>) -> Self {
        let mem = std::mem::replace(&mut self.mem, InMemoryStore::new());
        self.mem = mem.with_redactor(redactor);
        self
    }

    /// Configure embed-on-write on the working set (design §2 `embedding` / §8.5 data-class routing)
    /// — see [`InMemoryStore::with_embedders`]. Vectors are computed before persistence and written
    /// through, so the durable corpus is semantically queryable at scale after a reopen.
    pub fn with_embedders(
        mut self,
        inhouse: Box<dyn crate::store::Embedder>,
        cloud: Box<dyn crate::store::Embedder>,
    ) -> Self {
        let mem = std::mem::replace(&mut self.mem, InMemoryStore::new());
        self.mem = mem.with_embedders(inhouse, cloud);
        self
    }

    /// Enable the OKI-extraction guard on the working set (design §8.8) — see
    /// [`InMemoryStore::with_extraction_guard`].
    pub fn with_extraction_guard(mut self, cap: usize) -> Self {
        let mem = std::mem::replace(&mut self.mem, InMemoryStore::new());
        self.mem = mem.with_extraction_guard(cap);
        self
    }

    /// Install a governed, versioned [`SchemaRegistry`](crate::oki::SchemaRegistry) on the working
    /// set — see [`InMemoryStore::with_schema_registry`]. DurableMemoryStore parity gap: before this,
    /// a production (Postgres-backed) deployment had no way to install a bumped schema registry at
    /// all — only the ephemeral [`InMemoryStore`] exposed the setter, so every durable OKI write was
    /// silently pinned to the fresh (v1-everywhere) default registry regardless of what a deployment
    /// governed via [`SchemaRegistry::bump`](crate::oki::SchemaRegistry::bump).
    pub fn with_schema_registry(mut self, registry: crate::oki::SchemaRegistry) -> Self {
        let mem = std::mem::replace(&mut self.mem, InMemoryStore::new());
        self.mem = mem.with_schema_registry(registry);
        self
    }

    /// The versioned OKI schema registry currently enforced on writes — see
    /// [`InMemoryStore::schema_registry`].
    pub fn schema_registry(&self) -> &crate::oki::SchemaRegistry {
        self.mem.schema_registry()
    }

    /// Outgoing knowledge-graph neighbors of `id` over the durable corpus — see
    /// [`InMemoryStore::neighbors`].
    pub fn neighbors(
        &self,
        id: &str,
        access: &AccessScope,
        authoritative_only: bool,
    ) -> Vec<(crate::EdgeKind, MemoryItem)> {
        self.mem.neighbors(id, access, authoritative_only)
    }

    /// BFS knowledge-graph traversal over the durable corpus — see [`InMemoryStore::traverse`].
    pub fn traverse(
        &self,
        start_id: &str,
        max_depth: usize,
        edges: &[crate::EdgeKind],
        access: &AccessScope,
        authoritative_only: bool,
    ) -> Vec<MemoryItem> {
        self.mem
            .traverse(start_id, max_depth, edges, access, authoritative_only)
    }

    /// Borrow the underlying backend (e.g. to open a second store over the same database in a test).
    pub fn backend(&self) -> &D {
        &self.db
    }

    /// Take any deferred backend error from an infallible trait call ([`MemoryStore::delete`]).
    /// `None` means every persistence has succeeded.
    pub fn take_sync_error(&mut self) -> Option<MemoryError> {
        self.sync_error.take()
    }

    // -------- write-through --------

    /// Flush the in-RAM state delta to the backend: upsert new/changed item versions, delete rows
    /// for ids removed from RAM, and append newly-created audit entries. Incremental (immutable older
    /// versions are persisted once) and idempotent.
    fn sync(&mut self) -> Result<(), MemoryError> {
        let versions = self.mem.export_versions();
        // Current version per id (only the current version can mutate in place).
        let mut current: HashMap<&str, u32> = HashMap::new();
        for it in &versions {
            let e = current.entry(it.id.as_str()).or_insert(0);
            if it.version > *e {
                *e = it.version;
            }
        }
        let mut live_ids: HashSet<String> = HashSet::new();
        for it in &versions {
            live_ids.insert(it.id.clone());
            let key = (it.id.clone(), it.version);
            let is_current = current.get(it.id.as_str()) == Some(&it.version);
            // Skip immutable, already-persisted, non-current versions (never change again).
            if !is_current && self.persisted.contains_key(&key) {
                continue;
            }
            let body =
                serde_json::to_string(it).map_err(|e| MemoryError::Storage(e.to_string()))?;
            let fp = fingerprint(&body);
            if self.persisted.get(&key) == Some(&fp) {
                continue;
            }
            self.db.upsert_item(&it.id, it.version, &body)?;
            self.persisted.insert(key, fp);
        }
        // Deletes: ids we persisted that are no longer in RAM (hard-delete / erasure).
        let dead_ids: HashSet<String> = self
            .persisted
            .keys()
            .map(|(id, _)| id.clone())
            .filter(|id| !live_ids.contains(id))
            .collect();
        for id in &dead_ids {
            self.db.delete_item(id)?;
        }
        self.persisted.retain(|(id, _), _| live_ids.contains(id));
        // Audit: append the tail beyond what we've flushed.
        let new_rows: Vec<AuditRow> = {
            let audit = self.mem.audit_log();
            audit[self.persisted_audit.min(audit.len())..]
                .iter()
                .map(AuditRow::from)
                .collect()
        };
        for r in &new_rows {
            self.db.append_audit(r)?;
        }
        self.persisted_audit += new_rows.len();
        Ok(())
    }

    /// Sync in an infallible context; stash any error for [`take_sync_error`].
    fn sync_soft(&mut self) {
        if let Err(e) = self.sync() {
            self.sync_error = Some(e);
        }
    }

    fn persist_consent(&mut self, receipt: &ErasureReceipt) -> Result<(), MemoryError> {
        let body =
            serde_json::to_string(receipt).map_err(|e| MemoryError::Storage(e.to_string()))?;
        self.db
            .record_consent(receipt.audit_seq, &receipt.subject, &body)?;
        Ok(())
    }

    // -------- reads (no write-through) --------

    /// Number of live items (by id).
    pub fn len(&self) -> usize {
        self.mem.len()
    }
    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.mem.is_empty()
    }
    /// A specific historical version (forensic replay).
    pub fn get_version(&self, id: &str, version: u32) -> Option<&MemoryItem> {
        self.mem.get_version(id, version)
    }
    /// All versions of an item (oldest first).
    pub fn versions(&self, id: &str) -> &[MemoryItem] {
        self.mem.versions(id)
    }
    /// Resolve `(id, version)` refs to content snapshots (forensic replay).
    pub fn resolve(&self, refs: &[(String, u32)]) -> Vec<Option<MemoryItem>> {
        self.mem.resolve(refs)
    }
    /// The in-RAM audit log (also durably persisted; hydrated on reopen).
    pub fn audit_entries(&self) -> &[AuditEntry] {
        self.mem.audit_entries()
    }
    /// Recompute + verify the hash chain (integrity check across a reopen).
    pub fn verify_audit_chain(&self) -> Option<usize> {
        self.mem.verify_audit_chain()
    }
    /// All durably-persisted DPDP erasure receipts, ordered by signing audit seq.
    pub fn consent_receipts(&self) -> Result<Vec<ConsentRow>, MemoryError> {
        Ok(self.db.load_consent()?)
    }

    // -------- attributed write + governance (write-through) --------

    /// Attributed, identity-checked write ([`InMemoryStore::write_as`]) + write-through.
    pub fn write_as(&mut self, item: MemoryItem, writer: &AccessScope) -> Result<(), MemoryError> {
        self.mem.write_as(item, writer)?;
        self.sync()
    }
    /// Promote an org item to `Production` ([`InMemoryStore::productionize`]) + write-through.
    pub fn productionize(&mut self, id: &str, actor: &Principal) -> Result<(), MemoryError> {
        self.mem.productionize(id, actor)?;
        self.sync()
    }
    /// Human conflict arbitration ([`InMemoryStore::arbitrate`]) + write-through.
    pub fn arbitrate(
        &mut self,
        winner_id: &str,
        loser_id: &str,
        actor: &Principal,
    ) -> Result<(), MemoryError> {
        self.mem.arbitrate(winner_id, loser_id, actor)?;
        self.sync()
    }
    /// Mark an item used ([`InMemoryStore::touch`]) + write-through. Returns `false` if unknown.
    pub fn touch(&mut self, id: &str, now: u64) -> Result<bool, MemoryError> {
        let ok = self.mem.touch(id, now);
        self.sync()?;
        Ok(ok)
    }
    /// Mark an item confirmed ([`InMemoryStore::confirm`]) + write-through.
    pub fn confirm(&mut self, id: &str, now: u64, actor: &Principal) -> Result<bool, MemoryError> {
        let ok = self.mem.confirm(id, now, actor);
        self.sync()?;
        Ok(ok)
    }
    /// Purge expired raw tiers ([`InMemoryStore::purge_expired`]) + write-through.
    pub fn purge_expired(
        &mut self,
        now: u64,
        policy: RetentionPolicy,
    ) -> Result<usize, MemoryError> {
        let n = self.mem.purge_expired(now, policy);
        self.sync()?;
        Ok(n)
    }
    /// Usage-based decay expiry ([`InMemoryStore::expire_decayed`]) + write-through. DurableMemoryStore
    /// parity gap (design §6): retention TTL-decay was previously only reachable on the ephemeral
    /// [`InMemoryStore`] — a production deployment backed by [`DurableMemoryStore`] had no method to
    /// run the decay sweep at all, so "a fact unconfirmed and unused past N months drops priority"
    /// could never fire against the store real deployments actually use. The deprecation this applies
    /// is written through to the backend like any other governance-state mutation, so it survives a
    /// restart/reopen.
    pub fn expire_decayed(
        &mut self,
        now: u64,
        half_life: u64,
        floor: f64,
    ) -> Result<usize, MemoryError> {
        let n = self.mem.expire_decayed(now, half_life, floor);
        self.sync()?;
        Ok(n)
    }
    /// Retroactive re-redaction ([`InMemoryStore::re_redact`]) + write-through.
    pub fn re_redact(&mut self) -> Result<usize, MemoryError> {
        let n = self.mem.re_redact();
        self.sync()?;
        Ok(n)
    }
    /// GAP-FIX regulated-fi-responsible-lifecycle (FI-01 §5.4) — the durable-backed counterpart of
    /// [`InMemoryStore::all_content`]: a read-only snapshot of the CURRENTLY HYDRATED working set (the
    /// same in-RAM state [`Self::open`] just re-pulled from the backend), for a defense-in-depth sweep.
    /// No write-through (nothing is mutated).
    pub fn all_content(&self) -> Vec<(String, String)> {
        self.mem.all_content()
    }
    /// GAP-FIX memory (embedding-lifecycle no caller) — the durable-backed counterpart of
    /// [`InMemoryStore::reembed_all`] + write-through, so a `Durable`-backed deployment's embedding-model
    /// migration (design §8.5: data-class-routed re-embed) actually persists the freshly-computed
    /// vectors, not just the in-RAM copy — mirroring exactly how [`Self::re_redact`] backs
    /// [`crate::ConsentBacking::reembed_all`]'s `Durable` variant.
    pub fn reembed_all(
        &mut self,
        inhouse: &dyn crate::store::Embedder,
        cloud: &dyn crate::store::Embedder,
    ) -> Result<usize, MemoryError> {
        let n = self.mem.reembed_all(inhouse, cloud)?;
        self.sync()?;
        Ok(n)
    }
    /// Right-to-erasure cascade ([`InMemoryStore::erase_subject`]) + write-through, and persist the
    /// signed receipt as a durable consent record (DPDP, provable erasure).
    pub fn erase_subject(&mut self, subject: &str) -> Result<ErasureReceipt, MemoryError> {
        let receipt = self.mem.erase_subject(subject);
        self.sync()?;
        self.persist_consent(&receipt)?;
        Ok(receipt)
    }
    /// Right-to-erasure cascade ([`crate::store::cascade_erasure`]) run against the durable store's
    /// OWN in-RAM working set + write-through + durable receipt persistence — the `Durable`
    /// counterpart to [`Self::erase_subject`]. `DurableMemoryStore` cannot hand its private `mem`
    /// field to the free function from outside the crate (it has no public accessor, deliberately —
    /// see the type doc: every mutation must go through a method that also write-throughs), so this
    /// inherent method is the seam [`crate::ConsentBacking::erase_subject_cascaded`] calls for its
    /// `Durable` variant, mirroring exactly how [`Self::erase_subject`] backs
    /// [`crate::ConsentBacking::with_surface`]'s plain erasure.
    pub fn erase_subject_cascaded(
        &mut self,
        subject: &str,
        tiers: &mut [&mut dyn crate::store::ErasureTier],
    ) -> Result<ErasureReceipt, MemoryError> {
        let receipt = crate::store::cascade_erasure(&mut self.mem, subject, tiers);
        self.sync()?;
        self.persist_consent(&receipt)?;
        Ok(receipt)
    }
    /// Automatic offboarding erasure ([`InMemoryStore::offboard_subject`]) + write-through + receipt.
    pub fn offboard_subject(&mut self, subject: &str) -> Result<ErasureReceipt, MemoryError> {
        let receipt = self.mem.offboard_subject(subject);
        self.sync()?;
        self.persist_consent(&receipt)?;
        Ok(receipt)
    }
    /// The "what do you remember about me" view ([`InMemoryStore::remembered_about`]); may emit an
    /// audited break-glass entry, which is written through.
    pub fn remembered_about(
        &mut self,
        subject: &str,
        access: &AccessScope,
    ) -> Result<ConsentView, MemoryError> {
        let view = self.mem.remembered_about(subject, access)?;
        self.sync()?;
        Ok(view)
    }
    /// Machine-readable subject export ([`InMemoryStore::export_subject`]) + write-through of any
    /// audited break-glass entry.
    pub fn export_subject(
        &mut self,
        subject: &str,
        access: &AccessScope,
    ) -> Result<SubjectExport, MemoryError> {
        let export = self.mem.export_subject(subject, access)?;
        self.sync()?;
        Ok(export)
    }
    /// Audited query ([`InMemoryStore::query_audited`]) — writes through any break-glass audit entry.
    pub fn query_audited(
        &mut self,
        q: &MemoryQuery,
        access: &AccessScope,
    ) -> Result<Vec<MemoryHit>, MemoryError> {
        let hits = self.mem.query_audited(q, access);
        self.sync()?;
        Ok(hits)
    }
}

impl<D: SqlLike> MemoryStore for DurableMemoryStore<D> {
    fn write(&mut self, item: MemoryItem) -> Result<(), MemoryError> {
        self.mem.write(item)?;
        self.sync()
    }
    fn get_unchecked(&self, id: &str) -> Option<&MemoryItem> {
        self.mem.get_unchecked(id)
    }
    fn promote(&mut self, id: &str, approver: &Principal) -> Result<GovernanceState, MemoryError> {
        let state = self.mem.promote(id, approver)?;
        self.sync()?;
        Ok(state)
    }
    fn deprecate(&mut self, id: &str, actor: &Principal) -> Result<(), MemoryError> {
        self.mem.deprecate(id, actor)?;
        self.sync()
    }
    fn delete_as(&mut self, id: &str, actor: &AccessScope) -> Result<bool, MemoryError> {
        // Authorization and attribution are decided by the in-memory store (one implementation of
        // the contract, so the durable path cannot drift into a laxer rule); persistence follows.
        let removed = self.mem.delete_as(id, actor)?;
        if removed {
            self.sync_soft();
        }
        Ok(removed)
    }
    fn query(&self, q: &MemoryQuery, access: &AccessScope) -> Vec<MemoryHit> {
        self.mem.query(q, access)
    }
}

// ============================ Postgres binding (feature = "postgres") ============================

/// A driver-agnostic Postgres binding for the [`SqlLike`] seam. It issues the real parameterized SQL
/// against the [`MEMORY_STORE_DDL`] tables but pulls **no** database crate: a deployment implements
/// [`PgExecutor`] over rust-postgres / sqlx (or a pooled connection) and injects it. This keeps the
/// OSS core dependency-light while proving the SQL shape compiles; no live DB is touched by tests.
#[cfg(feature = "postgres")]
pub mod pg {
    use super::{AuditRow, ItemRow, SqlError, SqlLike, MEMORY_STORE_DDL};

    /// A bound parameter value for a parameterized statement (positional, `$1`, `$2`, …).
    #[derive(Debug, Clone, PartialEq)]
    pub enum SqlParam {
        /// A text/`varchar` value.
        Text(String),
        /// A `bigint`/`integer` value.
        Int(i64),
    }

    /// A synchronous SQL executor a deployment backs with a real Postgres driver. `execute` returns
    /// rows-affected; `query` returns rows as positional cells matching the `SELECT` column order.
    pub trait PgExecutor: std::fmt::Debug + Send + Sync {
        /// Run a non-`SELECT` statement; return rows affected.
        fn execute(&self, sql: &str, params: &[SqlParam]) -> Result<u64, SqlError>;
        /// Run a `SELECT`; return each row's cells positionally.
        fn query(&self, sql: &str, params: &[SqlParam]) -> Result<Vec<Vec<SqlParam>>, SqlError>;
    }

    /// A [`SqlLike`] backend that maps each seam method to one parameterized Postgres statement.
    #[derive(Debug)]
    pub struct PgBackend<E: PgExecutor> {
        exec: E,
    }

    impl<E: PgExecutor> PgBackend<E> {
        /// Bind an executor and run the idempotent schema DDL once.
        pub fn connect(exec: E) -> Result<Self, SqlError> {
            exec.execute(MEMORY_STORE_DDL, &[])?;
            Ok(PgBackend { exec })
        }
    }

    fn as_text(cell: Option<&SqlParam>) -> Result<String, SqlError> {
        match cell {
            Some(SqlParam::Text(s)) => Ok(s.clone()),
            _ => Err(SqlError("expected text column".into())),
        }
    }
    fn as_int(cell: Option<&SqlParam>) -> Result<i64, SqlError> {
        match cell {
            Some(SqlParam::Int(i)) => Ok(*i),
            _ => Err(SqlError("expected integer column".into())),
        }
    }

    impl<E: PgExecutor> SqlLike for PgBackend<E> {
        fn upsert_item(&self, id: &str, version: u32, body: &str) -> Result<(), SqlError> {
            self.exec.execute(
                "INSERT INTO memory_items (id,version,body) VALUES ($1,$2,$3) \
                 ON CONFLICT (id,version) DO UPDATE SET body = EXCLUDED.body",
                &[
                    SqlParam::Text(id.to_string()),
                    SqlParam::Int(version as i64),
                    SqlParam::Text(body.to_string()),
                ],
            )?;
            Ok(())
        }
        fn delete_item(&self, id: &str) -> Result<u64, SqlError> {
            self.exec.execute(
                "DELETE FROM memory_items WHERE id=$1",
                &[SqlParam::Text(id.to_string())],
            )
        }
        fn load_items(&self) -> Result<Vec<ItemRow>, SqlError> {
            let rows = self.exec.query(
                "SELECT id,version,body FROM memory_items ORDER BY id,version",
                &[],
            )?;
            rows.into_iter()
                .map(|r| {
                    Ok(ItemRow {
                        id: as_text(r.first())?,
                        version: as_int(r.get(1))? as u32,
                        body: as_text(r.get(2))?,
                    })
                })
                .collect()
        }
        fn append_audit(&self, row: &AuditRow) -> Result<(), SqlError> {
            self.exec.execute(
                "INSERT INTO memory_audit (seq,action,subject,detail,prev_hash,hash,prev_digest,digest,hasher) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
                &[
                    SqlParam::Int(row.seq as i64),
                    SqlParam::Text(row.action.clone()),
                    SqlParam::Text(row.subject.clone()),
                    SqlParam::Text(row.detail.clone()),
                    SqlParam::Int(row.prev_hash as i64),
                    SqlParam::Int(row.hash as i64),
                    SqlParam::Text(row.prev_digest.clone()),
                    SqlParam::Text(row.digest.clone()),
                    SqlParam::Text(row.hasher.clone()),
                ],
            )?;
            Ok(())
        }
        fn load_audit(&self) -> Result<Vec<AuditRow>, SqlError> {
            let rows = self.exec.query(
                "SELECT seq,action,subject,detail,prev_hash,hash,prev_digest,digest,hasher \
                 FROM memory_audit ORDER BY seq",
                &[],
            )?;
            rows.into_iter()
                .map(|r| {
                    Ok(AuditRow {
                        seq: as_int(r.first())? as u64,
                        action: as_text(r.get(1))?,
                        subject: as_text(r.get(2))?,
                        detail: as_text(r.get(3))?,
                        prev_hash: as_int(r.get(4))? as u64,
                        hash: as_int(r.get(5))? as u64,
                        prev_digest: as_text(r.get(6))?,
                        digest: as_text(r.get(7))?,
                        hasher: as_text(r.get(8))?,
                    })
                })
                .collect()
        }
        fn record_consent(
            &self,
            audit_seq: u64,
            subject: &str,
            body: &str,
        ) -> Result<(), SqlError> {
            self.exec.execute(
                "INSERT INTO memory_consent (audit_seq,subject,body) VALUES ($1,$2,$3) \
                 ON CONFLICT (audit_seq) DO NOTHING",
                &[
                    SqlParam::Int(audit_seq as i64),
                    SqlParam::Text(subject.to_string()),
                    SqlParam::Text(body.to_string()),
                ],
            )?;
            Ok(())
        }
        fn load_consent(&self) -> Result<Vec<super::ConsentRow>, SqlError> {
            let rows = self.exec.query(
                "SELECT audit_seq,subject,body FROM memory_consent ORDER BY audit_seq",
                &[],
            )?;
            rows.into_iter()
                .map(|r| {
                    Ok(super::ConsentRow {
                        audit_seq: as_int(r.first())? as u64,
                        subject: as_text(r.get(1))?,
                        body: as_text(r.get(2))?,
                    })
                })
                .collect()
        }
    }
}
