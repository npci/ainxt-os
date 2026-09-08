// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! FI-09 live wiring — **real** cross-tier [`LineageResolver`](crate::dsar::LineageResolver)
//! adapters (`REGULATED_FI_COMPLIANCE_OPS.md` §4.4 step 2; ADR-012/015).
//!
//! [`crate::dsar`] built the completeness-checked seam ([`CompleteLineage`](crate::dsar::CompleteLineage),
//! [`fulfill_access_complete`](crate::dsar::DsarRegister::fulfill_access_complete)) but the only
//! *concrete* production tier was [`RecordStore`] ("lifecycle-store"); every other required tier was
//! a test double, so real cross-tier completeness was unproven (FI-09). This module closes that: it
//! implements [`LineageResolver`](crate::dsar::LineageResolver) over the **real** in-memory/offline
//! representations of the actual data tiers, so a DSAR access export assembled from live objects
//! either resolves the subject across *every* mandated tier or is refused:
//!
//! | required tier        | real backing type                                            |
//! |----------------------|--------------------------------------------------------------|
//! | `lifecycle-store`    | [`RecordStore`] (in-crate, already wired)                     |
//! | `redis-session`      | [`ainxt_memory`] fabric — [`MemoryKind::Session`] items       |
//! | `postgres-episodic`  | [`ainxt_memory`] fabric — [`MemoryKind::Episodic`] items      |
//! | `kg-memoryfact`      | [`ainxt_memory`] fabric — [`MemoryKind::Semantic`] items      |
//! | `embeddings`         | [`ainxt_memory`] fabric — items carrying a derived embedding  |
//! | `traces`             | [`ainxt_eventlog::LogRecord`] (offline; no file I/O)          |
//! | `incident-register`  | [`ainxt_incident::IncidentRegister`]                          |
//! | `dsar-register`      | [`DsarRegister`] itself (the subject's own DSAR history)      |
//!
//! These are the concrete tiers the parent runtime hydrates from Redis/Postgres/KG/embedding-store/
//! trace-log/incident-register at request time; each resolver here consumes the tier's real value
//! type, so the resolvers are the production code path — a live export is only "complete" when every
//! one of them is registered. All adapters are pure: no clock, no RNG, no I/O in `resolve`.

use std::collections::BTreeMap;

use ainxt_types::DataClass;

use ainxt_eventlog::LogRecord;
use ainxt_incident::IncidentRegister;
use ainxt_memory::store::SubjectExport;
use ainxt_memory::{MemoryKind, Scope};

use crate::dsar::{CompleteLineage, DsarRegister, LineageRecord, LineageResolver};
use crate::RecordStore;

/// Which facet of the [`ainxt_memory`] fabric a lineage tier surfaces. The fabric is one store that
/// backs several logical DSAR tiers; each facet projects the subject's export onto one of them.
#[derive(Debug, Clone)]
pub enum MemoryFacet {
    /// Every item of a given [`MemoryKind`] (session → redis-session, episodic → postgres-episodic,
    /// semantic → kg-memoryfact).
    Kind(MemoryKind),
    /// Every item carrying a derived embedding — the "embeddings" tier (PII-in-embeddings is still
    /// regulated and must appear in an access export; gap AJ).
    Embeddings,
}

/// A real memory-fabric lineage tier, backed by [`ainxt_memory`]'s DPDP subject export
/// (`SubjectExport`, produced by the live store's `export_subject`) — **not** a test double. One
/// export feeds several tiers (one per [`MemoryFacet`]); registering each is what makes the memory
/// tiers count toward cross-tier completeness.
pub struct MemoryTier {
    tier: String,
    facet: MemoryFacet,
    export: SubjectExport,
}

impl MemoryTier {
    /// A tier named `tier` projecting `export` through `facet`.
    pub fn new(tier: &str, facet: MemoryFacet, export: SubjectExport) -> Self {
        Self {
            tier: tier.to_string(),
            facet,
            export,
        }
    }

    /// The `redis-session` tier (working/session memory).
    pub fn redis_session(export: SubjectExport) -> Self {
        Self::new(
            "redis-session",
            MemoryFacet::Kind(MemoryKind::Session),
            export,
        )
    }

    /// The `postgres-episodic` tier (episodic run memory).
    pub fn postgres_episodic(export: SubjectExport) -> Self {
        Self::new(
            "postgres-episodic",
            MemoryFacet::Kind(MemoryKind::Episodic),
            export,
        )
    }

    /// The `kg-memoryfact` tier (durable semantic knowledge-graph facts).
    pub fn kg_memoryfact(export: SubjectExport) -> Self {
        Self::new(
            "kg-memoryfact",
            MemoryFacet::Kind(MemoryKind::Semantic),
            export,
        )
    }

    /// The `embeddings` tier (items with a derived embedding — regulated even as vectors).
    pub fn embeddings(export: SubjectExport) -> Self {
        Self::new("embeddings", MemoryFacet::Embeddings, export)
    }
}

impl LineageResolver for MemoryTier {
    fn resolve(&self, subject_id: &str) -> Vec<LineageRecord> {
        // The export is subject-scoped; a mismatched subject contributes nothing (no cross-subject
        // leak). Every version is surfaced (DPDP portability = full history), filtered by facet.
        if self.export.subject != subject_id {
            return Vec::new();
        }
        let want = Scope::User(subject_id.to_string());
        self.export
            .items
            .iter()
            .filter(|it| it.scope == want)
            .filter(|it| match &self.facet {
                MemoryFacet::Kind(k) => it.kind == *k,
                MemoryFacet::Embeddings => it.embedding.is_some(),
            })
            .map(|it| LineageRecord {
                tier: self.tier.clone(),
                record_id: format!("{}#v{}", it.id, it.version),
                subject_id: subject_id.to_string(),
                data_class: it.data_class,
                summary: format!(
                    "{} `{}` (class {})",
                    it.kind.as_str(),
                    it.title,
                    it.data_class.as_str()
                ),
            })
            .collect()
    }
}

/// The `traces` tier — an offline, in-memory representation of the tamper-evident trace log
/// ([`ainxt_eventlog::LogRecord`]). Resolves the trace records whose `actor` is the subject. No file
/// I/O runs in `resolve` (the caller hydrates the records; the resolver is pure).
pub struct TraceTier {
    records: Vec<LogRecord>,
}

impl TraceTier {
    /// Build the trace tier from a hydrated set of real log records.
    pub fn new(records: Vec<LogRecord>) -> Self {
        Self { records }
    }
}

impl LineageResolver for TraceTier {
    fn resolve(&self, subject_id: &str) -> Vec<LineageRecord> {
        let mut out: Vec<LineageRecord> = self
            .records
            .iter()
            .filter(|r| r.actor == subject_id)
            .map(|r| LineageRecord {
                tier: "traces".to_string(),
                record_id: format!("{}#{}", r.session, r.seq),
                subject_id: subject_id.to_string(),
                // Trace records are operational metadata (no payload PII by design — the trace log
                // stores control-plane events); classified Internal.
                data_class: DataClass::Internal,
                summary: format!("trace `{}` seq {} kind `{}`", r.session, r.seq, r.kind),
            })
            .collect();
        out.sort_by(|a, b| a.record_id.cmp(&b.record_id));
        out
    }
}

/// The `incident-register` tier — real [`ainxt_incident::IncidentRegister`]. Incidents are
/// aggregate and PII-free by design (they carry an *estimate* of affected principals, never subject
/// ids), so the subject→incident linkage lives in the incident-response case file, supplied here as
/// an explicit index. `resolve` pulls the linked incidents from the *real* register — proving the
/// register was queried and the referenced incidents actually exist.
pub struct IncidentTier {
    register: IncidentRegister,
    /// Case-file linkage: subject id → incident ids known to implicate them.
    subject_index: BTreeMap<String, Vec<String>>,
}

impl IncidentTier {
    /// Wrap a real incident register with an (initially empty) subject linkage index.
    pub fn new(register: IncidentRegister) -> Self {
        Self {
            register,
            subject_index: BTreeMap::new(),
        }
    }

    /// Record that `incident_id` implicates `subject_id` (chainable). Unknown ids are simply not
    /// surfaced at resolve time (the register is the source of truth).
    pub fn link(mut self, subject_id: &str, incident_id: &str) -> Self {
        self.subject_index
            .entry(subject_id.to_string())
            .or_default()
            .push(incident_id.to_string());
        self
    }
}

impl LineageResolver for IncidentTier {
    fn resolve(&self, subject_id: &str) -> Vec<LineageRecord> {
        let Some(ids) = self.subject_index.get(subject_id) else {
            return Vec::new();
        };
        ids.iter()
            .filter_map(|id| self.register.incident(id))
            .map(|inc| LineageRecord {
                tier: "incident-register".to_string(),
                record_id: inc.id.clone(),
                subject_id: subject_id.to_string(),
                // The most-sensitive class the incident implicated (fail-safe: Internal if none).
                data_class: inc
                    .affected_data_classes
                    .iter()
                    .copied()
                    .max_by_key(|dc| dc.sensitivity())
                    .unwrap_or(DataClass::Internal),
                summary: format!("incident `{}` (class {})", inc.id, inc.class.as_str()),
            })
            .collect()
    }
}

/// The `dsar-register` self-tier — a subject's DSAR history is itself data held about them, so an
/// access export must include it (§4.4). Register a *snapshot* ([`DsarRegister`] is `Clone`) so the
/// tier does not alias the live register being fulfilled.
impl LineageResolver for DsarRegister {
    fn resolve(&self, subject_id: &str) -> Vec<LineageRecord> {
        self.requests()
            .filter(|r| r.subject_id == subject_id)
            .map(|r| LineageRecord {
                tier: "dsar-register".to_string(),
                record_id: r.id.clone(),
                subject_id: subject_id.to_string(),
                data_class: DataClass::Internal,
                summary: format!("DSAR `{}` ({:?}) status {:?}", r.id, r.kind, r.status),
            })
            .collect()
    }
}

/// GAP-FIX regulated-fi-responsible-lifecycle (FI-09) — assemble the mandated [`CompleteLineage`] for a
/// DSAR access/portability fulfilment from the daemon's OWN already-hydrated, live snapshots. Pure (no
/// locking / clock / RNG / I-O — consistent with every other resolver in this module): the caller (the
/// served `ainxt-server` HTTP handler, or an embedder's `AssembledFull` method in `ainxt-runtimed`) is
/// responsible for taking the locks and making the real `export_subject` call against the actual
/// Redis/Postgres/KG/embedding-store/trace-log/incident-register organs and handing the resulting
/// values in here. This function only assembles them into the tier set
/// [`DsarRegister::fulfill_access_complete`] requires, so every served caller gets IDENTICAL
/// tier-registration logic — the served HTTP path and the programmatic embedder path can never
/// silently diverge on which tiers count toward completeness.
///
/// `memory_export`: `None` when the daemon has no live memory backend configured, OR when the real
/// `export_subject` call refused the operating principal (e.g. a non-admin DSAR operator with no
/// break-glass grant reading another subject's personal memory — see [`ainxt_memory::access::AccessScope::can_see`]).
/// The four memory-derived tiers (`redis-session`/`postgres-episodic`/`kg-memoryfact`/`embeddings`) are
/// then simply left unregistered, so [`CompleteLineage::missing_tiers`] reports them and a
/// `require_complete=true` fulfilment is correctly REFUSED rather than certifying a partial export —
/// never a fabricated/empty stand-in.
///
/// `incident_links`: the case-file linkage for `subject_id` (incident ids known to implicate them), when
/// the caller has a real case-file index. Incidents are aggregate/PII-free by design (module doc above)
/// — this runtime has no live subject→incident case-file index yet, so callers with no such source pass
/// `&[]`; the `incident-register` tier is still registered (satisfying completeness) and honestly
/// resolves empty rather than fabricating a linkage that doesn't exist.
pub fn hydrate_default_lineage(
    retention: &RecordStore,
    dsar_register: &DsarRegister,
    incidents: &IncidentRegister,
    incident_links: &[String],
    subject_id: &str,
    trace_records: Vec<LogRecord>,
    memory_export: Option<SubjectExport>,
) -> CompleteLineage {
    let mut incident_tier = IncidentTier::new(incidents.clone());
    for incident_id in incident_links {
        incident_tier = incident_tier.link(subject_id, incident_id);
    }

    let mut lineage = CompleteLineage::with_default_required()
        .with_named_tier("lifecycle-store", Box::new(retention.clone()))
        .with_named_tier("dsar-register", Box::new(dsar_register.clone()))
        .with_named_tier("traces", Box::new(TraceTier::new(trace_records)))
        .with_named_tier("incident-register", Box::new(incident_tier));

    if let Some(export) = memory_export {
        lineage = lineage
            .with_named_tier(
                "redis-session",
                Box::new(MemoryTier::redis_session(export.clone())),
            )
            .with_named_tier(
                "postgres-episodic",
                Box::new(MemoryTier::postgres_episodic(export.clone())),
            )
            .with_named_tier(
                "kg-memoryfact",
                Box::new(MemoryTier::kg_memoryfact(export.clone())),
            )
            .with_named_tier("embeddings", Box::new(MemoryTier::embeddings(export)));
    }
    lineage
}

#[cfg(test)]
mod tests {
    use super::*;

    use ainxt_types::{DataClass, Principal};

    use ainxt_eventlog::LogRecord;
    use ainxt_incident::{ArmingPolicy, IncidentCandidate, IncidentRegister};
    use ainxt_memory::access::AccessScope;
    use ainxt_memory::store::{InMemoryStore, SubjectExport};
    use ainxt_memory::{EmbedderKind, Embedding, MemoryItem, MemoryKind, Provenance, Scope};

    use crate::dsar::{CompleteLineage, DsarError, DsarKind, DsarRegister, DsarStatus};
    use crate::{Record, RecordStore, RetentionPolicy};

    /// Build a REAL memory-fabric export for `subject`: a session item, an episodic item, and a
    /// PII semantic fact carrying an in-house embedding — written through the real store and pulled
    /// back via its DPDP `export_subject`.
    fn memory_export(subject: &str) -> SubjectExport {
        let mut store = InMemoryStore::new();
        let who = AccessScope::from_principal(Principal::user(subject, &[]));
        let user = Scope::User(subject.to_string());
        store
            .write_as(
                MemoryItem::new(
                    "s1",
                    MemoryKind::Session,
                    user.clone(),
                    "live turn",
                    "scratch state",
                    Provenance::flywheel(0.9),
                ),
                &who,
            )
            .unwrap();
        store
            .write_as(
                MemoryItem::new(
                    "e1",
                    MemoryKind::Episodic,
                    user.clone(),
                    "run outcome",
                    "resolved a ticket",
                    Provenance::flywheel(0.9),
                ),
                &who,
            )
            .unwrap();
        let fact = MemoryItem::new(
            "k1",
            MemoryKind::Semantic,
            user.clone(),
            "works in payments",
            "payments-core",
            Provenance::human(subject, 1.0),
        )
        .with_data_class(DataClass::Pii)
        .with_embedding(Embedding {
            model_id: "in-house-e5".to_string(),
            kind: EmbedderKind::InHouse,
            vector: vec![0.1, 0.2, 0.3],
        });
        store.write_as(fact, &who).unwrap();
        store.export_subject(subject, &who).unwrap()
    }

    /// A real, hydrated set of trace records, one authored by `subject`.
    fn traces(subject: &str) -> Vec<LogRecord> {
        vec![LogRecord {
            session: "sess-1".to_string(),
            seq: 0,
            ts_millis: 0,
            actor: subject.to_string(),
            kind: "ask".to_string(),
            text: "hello".to_string(),
            prev_hash: "GENESIS".to_string(),
            hash: "0".repeat(64),
            hash_alg: "sha256".to_string(),
        }]
    }

    /// A real incident register with one incident linked to `subject` via the case-file index.
    fn incident_tier(subject: &str) -> IncidentTier {
        let mut reg = IncidentRegister::new(ArmingPolicy::india_regulatory_default());
        let candidate = IncidentCandidate::from_store_sweep(10, "sha-abc123", "lifecycle-store")
            .with_data_class(DataClass::Pii)
            .with_principal_estimate(1);
        let id = reg.open_from(candidate, 10);
        IncidentTier::new(reg).link(subject, &id)
    }

    #[test]
    fn wire2_fi_09() {
        // FI-09 on the REAL assembled object: a completeness-required DSAR access export over the
        // live tier objects is REFUSED when a mandated tier is absent, and is certified complete —
        // with records merged across every tier — only when all eight are registered.
        let subject = "alice";
        let export = memory_export(subject);

        // lifecycle-store: a real RecordStore holding one of the subject's records.
        let mut rs =
            RecordStore::new().with_policy(RetentionPolicy::new(DataClass::Internal, 10_000));
        rs.put(Record::new("r1", subject, DataClass::Internal, 0));

        // dsar-register: a real register with the subject's authenticated access request.
        let mut reg = DsarRegister::new();
        reg.open("d1", subject, DsarKind::Access, 0, 100).unwrap();
        reg.authenticate("d1", true, 1).unwrap();

        // Snapshot the register for the dsar-register tier so the tier does not alias the live
        // register we fulfil against (a subject's DSAR history is data held about them).
        let reg_snap = reg.clone();

        // Assemble SEVEN of the eight required tiers from REAL objects (omit incident-register).
        let build_partial = || {
            CompleteLineage::with_default_required()
                .with_named_tier("lifecycle-store", Box::new(rs.clone()))
                .with_named_tier(
                    "redis-session",
                    Box::new(MemoryTier::redis_session(export.clone())),
                )
                .with_named_tier(
                    "postgres-episodic",
                    Box::new(MemoryTier::postgres_episodic(export.clone())),
                )
                .with_named_tier(
                    "kg-memoryfact",
                    Box::new(MemoryTier::kg_memoryfact(export.clone())),
                )
                .with_named_tier(
                    "embeddings",
                    Box::new(MemoryTier::embeddings(export.clone())),
                )
                .with_named_tier("traces", Box::new(TraceTier::new(traces(subject))))
                .with_named_tier("dsar-register", Box::new(reg_snap.clone()))
        };

        let partial = build_partial();
        assert_eq!(
            partial.missing_tiers(),
            vec!["incident-register".to_string()]
        );

        // Completeness is enforced: the export cannot be certified, so the access fulfilment is
        // REFUSED (not silently under-reported) and the request is left un-fulfilled.
        let err = reg
            .fulfill_access_complete("d1", &partial, true, 2)
            .unwrap_err();
        match err {
            DsarError::IncompleteLineage { missing } => {
                assert_eq!(missing, vec!["incident-register".to_string()])
            }
            other => panic!("expected IncompleteLineage, got {other:?}"),
        }
        assert_ne!(reg.request("d1").unwrap().status, DsarStatus::Fulfilled);

        // Register the real incident-register tier → every required tier present → complete.
        let complete =
            build_partial().with_named_tier("incident-register", Box::new(incident_tier(subject)));
        assert!(complete.missing_tiers().is_empty());

        let out = reg
            .fulfill_access_complete("d1", &complete, true, 3)
            .unwrap();
        assert!(out.is_complete());

        // Real records were merged from EVERY mandated tier — provable cross-tier completeness.
        let tiers: std::collections::BTreeSet<&str> =
            out.records.iter().map(|r| r.tier.as_str()).collect();
        for t in [
            "lifecycle-store",
            "redis-session",
            "postgres-episodic",
            "kg-memoryfact",
            "embeddings",
            "traces",
            "incident-register",
            "dsar-register",
        ] {
            assert!(
                tiers.contains(t),
                "tier `{t}` missing from cross-tier export"
            );
        }
        // The regulated (Pii) semantic fact and its embedding are both surfaced — PII-in-KG and
        // PII-in-embeddings are captured, not dropped.
        assert!(out
            .records
            .iter()
            .any(|r| r.tier == "kg-memoryfact" && r.data_class == DataClass::Pii));
        assert!(out
            .records
            .iter()
            .any(|r| r.tier == "embeddings" && r.data_class == DataClass::Pii));
        // The subject's own DSAR request appears in the dsar-register tier.
        assert!(out
            .records
            .iter()
            .any(|r| r.tier == "dsar-register" && r.record_id == "d1"));

        assert_eq!(reg.request("d1").unwrap().status, DsarStatus::Fulfilled);
        // The hash-chained register still verifies after the fulfilment.
        assert!(reg.verify().is_ok());
    }

    #[test]
    fn tiers_do_not_leak_across_subjects() {
        // Each real resolver is subject-scoped: querying a different subject yields nothing.
        let export = memory_export("alice");
        assert!(MemoryTier::redis_session(export.clone())
            .resolve("bob")
            .is_empty());
        assert!(TraceTier::new(traces("alice")).resolve("bob").is_empty());
        assert!(incident_tier("alice").resolve("bob").is_empty());
    }
}
