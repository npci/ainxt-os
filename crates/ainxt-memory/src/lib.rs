// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! ainxt-memory — the AiNxt runtime's enterprise memory & learning core.
//!
//! Design: `docs/architecture/ENTERPRISE_MEMORY_LEARNING.md`.
//!
//! Memory here is **typed, governed, queryable knowledge** — never a free-text blob and never
//! a per-user-only afterthought. Every unit is a [`MemoryItem`] with a [`MemoryKind`], a
//! [`Scope`], a [`DataClass`](ainxt_types::DataClass), a [`Provenance`] record, and a
//! [`GovernanceState`] lifecycle. Items are read through a single [`MemoryStore`] surface that
//! filters on RBAC/data-class + **identity-derived scope** ([`AccessScope`]) *before* ranking and
//! never serves un-approved organizational knowledge as authoritative.
//!
//! ## Load-bearing invariants
//!
//! 1. **Org-knowledge is human-gated.** [`MemoryKind::OrgKnowledge`] can only be *written*
//!    [`Draft`](GovernanceState::Draft); a write that tries to land it already
//!    [`Approved`](GovernanceState::Approved) is rejected. Promotion Draft → Approved happens
//!    **only** via an explicit [`MemoryStore::promote`] by a principal holding [`CAP_APPROVE`].
//!    The flywheel proposes, a human legislates — no amount of repeated assertion skips the gate
//!    (direct- and volume-poisoning defense, design §8).
//! 2. **Compliance-on-write.** A [`Redactor`] seam runs on every write *before* persistence
//!    (PAN/PII/secret never enters durable memory), and [`InMemoryStore::re_redact`] re-applies it
//!    retroactively when rules change.
//! 3. **Scope isolation is identity-derived**, not caller-optional: [`MemoryStore::query`] takes an
//!    [`AccessScope`] built from the caller's identity + memberships; an item outside the caller's
//!    reachable scope is filtered pre-rank (existence not leaked). Personal (`User`) memory is
//!    visible to its owner, or to an admin **only** under an audited break-glass justification.
//! 4. **Edit-free versioning.** Content is never mutated in place — every edit is a new version,
//!    old versions retained. This is what makes forensic point-in-time replay (design §7.5) and
//!    bi-temporal `validAsOf` queries (§7 bi-temporal) possible.
//! 5. **Typed OKI payloads.** Organizational knowledge carries a schema-validated [`OrgPayload`]
//!    for one of the 7 canonical [`OrgKnowledgeType`]s — an invalid payload is rejected, never
//!    persisted "as text" as a fallback.
//!
//! Pure and deterministic (logical clock, no wall time / rng in non-test logic). The
//! [`InMemoryStore`] is the reference impl and test target; a durable Postgres/KG-backed impl
//! slots in behind the same trait/inherent surface without touching callers.

pub mod access;
pub mod durable;
pub mod fabric;
pub mod flywheel;
pub mod oki;
pub mod promotion;
pub mod session;
pub mod store;

use serde::{Deserialize, Serialize};

pub use ainxt_types::{DataClass, Principal, Role};

pub use access::AccessScope;
pub use durable::{
    AuditRow, ConsentRow, DurableMemoryStore, ItemRow, MemorySqlBackend, SqlError, SqlLike,
    MEMORY_STORE_DDL,
};
pub use flywheel::{
    Curator, DefaultRuleJudge, EvidenceKind, HeuristicJudge, JudgeVerdict, LlmJudge, RuleJudge,
    TriagedCandidate,
};
pub use oki::{
    Enforcement, OrgKnowledgeType, OrgPayload, SchemaBump, SchemaError, SchemaRegistry, Severity,
    OKI_SCHEMA_VERSION,
};
pub use promotion::{
    DurabilityHeuristic, NonDurable, PromotionCandidate, PromotionOutcome, PromotionPipeline,
};
pub use session::{InMemorySessionSeam, SessionCache, SessionErasureTier, SessionSeam};
pub use store::{
    cascade_erasure, AuditEntry, AuditHasher, ConsentView, Embedder, ErasureReceipt, ErasureTier,
    Fnv1aAuditHasher, HmacSha256AuditHasher, InMemoryStore, RetentionPolicy, Sha256AuditHasher,
    SubjectExport, TierErasure,
};

/// Capability a [`Principal`] must hold to approve (promote) organizational knowledge.
/// Admins hold every capability implicitly (see [`Principal::has_cap`]).
pub const CAP_APPROVE: &str = "memory:approve";

// ============================ Typed memory kinds ============================

/// The type of a memory item. The kind determines governance treatment: only
/// [`OrgKnowledge`](MemoryKind::OrgKnowledge) is human-gated; the rest are usable on write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MemoryKind {
    /// Working memory for the live turn/conversation — scratch state, tool results pending use
    /// (design §3 "Session (Redis)"). Ephemeral by design: aged out by a short per-conversation TTL
    /// ([`RetentionPolicy::session_ttl`](store::RetentionPolicy)); nothing here is durable unless
    /// promoted. The durable Redis backing is infra; the tier's lifecycle/TTL semantics live here.
    Session,
    /// What happened in a specific run/session — intent, entities, outcome. Raw flywheel material.
    Episodic,
    /// Durable cross-session factual knowledge (e.g. "this user works in payments-core").
    Semantic,
    /// A reusable procedure / how-to distilled from experience (a "known good" sequence).
    Procedural,
    /// A per-user preference (style, verbosity, tone). Narrow scope, low blast radius.
    UserPreference,
    /// Organizational knowledge with org-wide blast radius — **human-gated** (see module docs).
    OrgKnowledge,
}

impl MemoryKind {
    /// Human-readable slug.
    pub fn as_str(&self) -> &'static str {
        match self {
            MemoryKind::Session => "session",
            MemoryKind::Episodic => "episodic",
            MemoryKind::Semantic => "semantic",
            MemoryKind::Procedural => "procedural",
            MemoryKind::UserPreference => "user-preference",
            MemoryKind::OrgKnowledge => "org-knowledge",
        }
    }
    /// Whether this kind requires a human approval gate before it may be served as authoritative.
    pub fn is_human_gated(&self) -> bool {
        matches!(self, MemoryKind::OrgKnowledge)
    }
}

// ============================ Governance lifecycle ============================

/// The governance state of a memory item — the same vocabulary the platform uses for Roles/Skills/
/// Agents, so one governance model covers every composition (design §2). Org-knowledge starts
/// [`Draft`](GovernanceState::Draft); an explicit, authorized [`promote`](MemoryStore::promote)
/// reaches [`Approved`](GovernanceState::Approved) and optionally
/// [`productionize`](InMemoryStore::productionize) → [`Production`](GovernanceState::Production).
/// [`Conflicted`](GovernanceState::Conflicted) marks the newer of two disagreeing OKIs pending
/// human arbitration; [`Superseded`](GovernanceState::Superseded) is replaced-but-retained;
/// [`Deprecated`](GovernanceState::Deprecated) is retired. None but Approved/Production are
/// authoritative for org-knowledge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GovernanceState {
    /// Proposed / unreviewed. For org-knowledge this means "NOT authoritative yet."
    Draft,
    /// Human-approved and authoritative.
    Approved,
    /// Promoted to production (authoritative). Reached only from `Approved`.
    Production,
    /// Two OKIs disagree on the same subject; the newer is parked here for human arbitration and
    /// is never served as authoritative until a human resolves it.
    Conflicted,
    /// Replaced by a newer version/item (a `SUPERSEDES` edge or auto-resolution). Retained for
    /// audit and forensic replay, excluded from authoritative retrieval.
    Superseded,
    /// Retired — retained for audit, excluded from authoritative retrieval.
    Deprecated,
}

impl GovernanceState {
    /// Whether this state may be served as authoritative (Approved/Production).
    pub fn is_authoritative_state(&self) -> bool {
        matches!(
            self,
            GovernanceState::Approved | GovernanceState::Production
        )
    }
}

// ============================ Scope ============================

/// The narrowest applicable scope of a memory item — drives cross-tenant isolation. A caller only
/// sees an item whose scope their [`AccessScope`] reaches.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind", content = "id")]
pub enum Scope {
    /// The whole organization — visible to every authenticated caller.
    Org,
    /// A department / AD org unit.
    Department(String),
    /// A team.
    Team(String),
    /// A single repository.
    Repo(String),
    /// A single user (personal memory).
    User(String),
}

impl Scope {
    /// The scope's discriminator string, used in conflict-subject keys.
    pub fn key(&self) -> String {
        match self {
            Scope::Org => "org".to_string(),
            Scope::Department(d) => format!("department:{d}"),
            Scope::Team(t) => format!("team:{t}"),
            Scope::Repo(r) => format!("repo:{r}"),
            Scope::User(u) => format!("user:{u}"),
        }
    }
}

// ============================ Per-item RBAC scope ============================

/// A per-item retrieval grant (design §2 envelope field `rbac_scope`): the roles/departments
/// allowed to retrieve an item, *independent of and in addition to* its [`Scope`]. Enforced
/// **pre-rank** (design §7.2 / acceptance "RBAC/data-class pre-rank") — an item the caller is not
/// granted is filtered out of the candidate set before ranking, so its existence is never leaked
/// via omission-from-a-ranked-list. An empty grant (`roles` and `departments` both empty) means
/// "no extra restriction" — visibility falls back to [`Scope`] alone.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RbacScope {
    /// Roles allowed to retrieve (empty = any role, subject to `departments`).
    #[serde(default)]
    pub roles: Vec<Role>,
    /// Departments allowed to retrieve (empty = any department, subject to `roles`).
    #[serde(default)]
    pub departments: Vec<String>,
}

impl RbacScope {
    /// A grant restricting retrieval to the given departments.
    pub fn departments(departments: &[&str]) -> Self {
        RbacScope {
            roles: Vec::new(),
            departments: departments.iter().map(|d| d.to_string()).collect(),
        }
    }
    /// A grant restricting retrieval to the given roles.
    pub fn roles(roles: &[Role]) -> Self {
        RbacScope {
            roles: roles.to_vec(),
            departments: Vec::new(),
        }
    }
    /// Whether this grant imposes no extra restriction.
    pub fn is_unrestricted(&self) -> bool {
        self.roles.is_empty() && self.departments.is_empty()
    }
    /// Whether `principal` is granted retrieval by this scope. An unrestricted grant allows anyone;
    /// an [`Role::Admin`] is always allowed (admins hold every capability); otherwise the principal
    /// must match a listed role **or** a listed department (union grant).
    pub fn allows(&self, principal: &Principal) -> bool {
        if self.is_unrestricted() {
            return true;
        }
        if principal.role == Role::Admin {
            return true;
        }
        if self.roles.contains(&principal.role) {
            return true;
        }
        if let Some(dept) = &principal.department {
            if self.departments.iter().any(|d| d == dept) {
                return true;
            }
        }
        false
    }
}

// ============================ Knowledge-graph links ============================

/// A typed edge from a memory item into the unified Context-Fabric Knowledge Graph (design §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EdgeKind {
    /// Cites an ADR / doc / source.
    Cites,
    /// Applies to a repo / module / language.
    AppliesTo,
    /// Caused by an incident.
    CausedBy,
    /// Supersedes another memory item (writing this edge retires the target).
    Supersedes,
    /// Relates to another memory item.
    RelatesTo,
}

/// A typed edge instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Link {
    /// The edge kind.
    pub edge: EdgeKind,
    /// The target id (an OKI id, ADR ref, repo/module, incident id, …).
    pub target: String,
}

impl Link {
    /// Construct a link.
    pub fn new(edge: EdgeKind, target: &str) -> Self {
        Link {
            edge,
            target: target.to_string(),
        }
    }
}

// ============================ Embeddings ============================

/// Where an embedding was computed. Regulated/PII content may only ever be embedded in-house
/// (design §8.5): a shared cloud vector API must never see it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EmbedderKind {
    /// A self-hosted / in-country embedding model — the only tier permitted for regulated/PII.
    InHouse,
    /// A cloud embedding API — forbidden for regulated/PII data.
    Cloud,
}

/// An embedding attached to a memory item, tagged with the model + tier that produced it so a
/// data-class violation (regulated content embedded via cloud) is detectable and re-embeddable.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Embedding {
    /// The embedding model id.
    pub model_id: String,
    /// The tier that produced the vector.
    pub kind: EmbedderKind,
    /// The dense vector.
    pub vector: Vec<f32>,
}

/// The embedder tier a given data-class *must* use. Regulated/PII → in-house only (design §8.5).
pub fn required_embedder_kind(dc: DataClass) -> EmbedderKind {
    if dc.is_regulated() {
        EmbedderKind::InHouse
    } else {
        EmbedderKind::Cloud
    }
}

/// Whether embedding data of class `dc` via `kind` is permitted. Regulated/PII forbids `Cloud`.
pub fn embedder_allowed(dc: DataClass, kind: EmbedderKind) -> bool {
    match kind {
        EmbedderKind::InHouse => true,
        EmbedderKind::Cloud => !dc.is_regulated(),
    }
}

// ============================ Provenance ============================

/// Who authored a memory item. There is no path from tool/RAG-read content to a memory write on
/// its own (design §8.1) — writes are either an explicit human action, a system ingest, or the
/// governed flywheel — so the author is always one of these three, never "a document said so."
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "source")]
pub enum Author {
    /// A named human (the requesting user, or an approving owner).
    Human { user_id: String },
    /// The continuous-learning flywheel proposed it (can only ever reach Draft).
    SystemFlywheel,
    /// A structured ingest job (e.g. incident intake) authored it.
    SystemIngest,
}

/// Provenance envelope carried by every memory item — makes "why does it know that" answerable
/// and makes org-knowledge citable rather than an unexplained assertion.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Provenance {
    /// Who authored the item.
    pub author: Author,
    /// The Event-Log turn id this was derived from, if any.
    #[serde(default)]
    pub source_turn: Option<String>,
    /// Authoring confidence in `[0.0, 1.0]`.
    pub confidence: f32,
    /// Who last verified/approved the item (set on promotion).
    #[serde(default)]
    pub last_verified_by: Option<String>,
    /// Logical clock tick when last verified/approved (set on promotion).
    #[serde(default)]
    pub last_verified_at: Option<u64>,
}

impl Provenance {
    /// Provenance for a fact a named user asserted about themselves.
    pub fn human(user_id: &str, confidence: f32) -> Self {
        Provenance {
            author: Author::Human {
                user_id: user_id.to_string(),
            },
            source_turn: None,
            confidence: clamp_unit(confidence),
            last_verified_by: None,
            last_verified_at: None,
        }
    }
    /// Provenance for a flywheel-proposed candidate (can only reach Draft).
    pub fn flywheel(confidence: f32) -> Self {
        Provenance {
            author: Author::SystemFlywheel,
            source_turn: None,
            confidence: clamp_unit(confidence),
            last_verified_by: None,
            last_verified_at: None,
        }
    }
    /// Provenance for a structured system ingest (e.g. incident intake).
    pub fn ingest(confidence: f32) -> Self {
        Provenance {
            author: Author::SystemIngest,
            source_turn: None,
            confidence: clamp_unit(confidence),
            last_verified_by: None,
            last_verified_at: None,
        }
    }
}

pub(crate) fn clamp_unit(v: f32) -> f32 {
    if v.is_nan() {
        0.0
    } else {
        v.clamp(0.0, 1.0)
    }
}

// ============================ MemoryItem ============================

/// One typed, governed unit of memory.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemoryItem {
    /// Stable id (caller-assigned; unique within a store).
    pub id: String,
    /// The typed kind.
    pub kind: MemoryKind,
    /// The canonical org-knowledge type (only set when `kind == OrgKnowledge`).
    #[serde(default)]
    pub org_type: Option<OrgKnowledgeType>,
    /// Narrowest applicable scope.
    pub scope: Scope,
    /// Short, indexable title / summary.
    pub title: String,
    /// The substance (free text summary; typed substance is in `payload` for OKIs).
    pub body: String,
    /// Schema-validated typed payload (only set when `kind == OrgKnowledge`).
    #[serde(default)]
    pub payload: Option<OrgPayload>,
    /// Free tags — searched alongside title/body.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Typed knowledge-graph edges.
    #[serde(default)]
    pub links: Vec<Link>,
    /// Data sensitivity class — filters retrieval pre-rank.
    pub data_class: DataClass,
    /// Per-item retrieval grant (roles/departments) — enforced pre-rank in addition to `scope`
    /// (design §2 `rbac_scope`). `None` = no extra restriction beyond `scope`.
    #[serde(default)]
    pub rbac_scope: Option<RbacScope>,
    /// Governance lifecycle state.
    pub governance: GovernanceState,
    /// Provenance envelope.
    pub provenance: Provenance,
    /// Optional embedding (with the tier that produced it — data-class routing, §8.5).
    #[serde(default)]
    pub embedding: Option<Embedding>,
    /// Valid-time start (logical tick) — when the knowledge became operationally true. `None` =
    /// always-from-creation. Drives bi-temporal `validAsOf` queries (§7).
    #[serde(default)]
    pub effective_from: Option<u64>,
    /// Valid-time end (logical tick) — when the knowledge stopped being true. `None` = open-ended.
    #[serde(default)]
    pub expires_at: Option<u64>,
    /// Per-id version number (`0` until first written; store assigns `1..`). Edits create a new
    /// version, never an in-place mutation — enabling forensic replay.
    #[serde(default)]
    pub version: u32,
    /// Store-assigned logical write tick (monotonic across all writes). `0` until first written.
    /// Drives recency and transaction-time (`as_of`) replay.
    #[serde(default)]
    pub seq: u64,
    /// The **per-type schema version** the store validated this OKI's typed payload against, stamped
    /// on write from the store's [`SchemaRegistry`](oki::SchemaRegistry) (design §2 `type_payload`:
    /// "validated against a per-type JSON-schema registry (versioned)"). `0` = not an OKI / not yet
    /// written through a registry-enforcing store. Makes "which schema version was in force when this
    /// record was persisted" answerable per item, not just globally.
    #[serde(default)]
    pub schema_version: u32,
    /// Logical tick this item was last *used* (retrieved/injected). Drives usage-based confidence
    /// decay (design §6: "a fact unconfirmed and **unused** past N months drops priority") — so a
    /// freshly-used old fact is not penalized as if it were stale. `None` = never used since write.
    #[serde(default)]
    pub last_used: Option<u64>,
    /// Logical tick this item was last *confirmed* (re-verified as still true). `None` = only ever
    /// confirmed at write. Also feeds usage/recency for decay.
    #[serde(default)]
    pub last_confirmed: Option<u64>,
}

impl MemoryItem {
    /// Build a non-org item with sensible governance defaults (`Approved` = usable immediately).
    /// Data class defaults to `Internal`; override with [`with_data_class`](MemoryItem::with_data_class).
    pub fn new(
        id: &str,
        kind: MemoryKind,
        scope: Scope,
        title: &str,
        body: &str,
        provenance: Provenance,
    ) -> Self {
        debug_assert!(
            kind != MemoryKind::OrgKnowledge,
            "use MemoryItem::org for org-knowledge (it requires a typed payload)"
        );
        MemoryItem {
            id: id.to_string(),
            kind,
            org_type: None,
            scope,
            title: title.to_string(),
            body: body.to_string(),
            payload: None,
            tags: Vec::new(),
            links: Vec::new(),
            data_class: DataClass::Internal,
            rbac_scope: None,
            governance: GovernanceState::Approved,
            provenance,
            embedding: None,
            effective_from: None,
            expires_at: None,
            version: 0,
            seq: 0,
            schema_version: 0,
            last_used: None,
            last_confirmed: None,
        }
    }

    /// Build an org-knowledge item from a typed payload. It always starts `Draft` (human-gated).
    /// The `payload` determines [`org_type`](MemoryItem::org_type); the store validates the payload
    /// against its schema on write.
    pub fn org(
        id: &str,
        scope: Scope,
        title: &str,
        payload: OrgPayload,
        provenance: Provenance,
    ) -> Self {
        let body = payload.summary_text();
        MemoryItem {
            id: id.to_string(),
            kind: MemoryKind::OrgKnowledge,
            org_type: Some(payload.oki_type()),
            scope,
            title: title.to_string(),
            body,
            payload: Some(payload),
            tags: Vec::new(),
            links: Vec::new(),
            data_class: DataClass::Internal,
            rbac_scope: None,
            governance: GovernanceState::Draft,
            provenance,
            embedding: None,
            effective_from: None,
            expires_at: None,
            version: 0,
            seq: 0,
            schema_version: 0,
            last_used: None,
            last_confirmed: None,
        }
    }

    /// Set the data-class.
    pub fn with_data_class(mut self, dc: DataClass) -> Self {
        self.data_class = dc;
        self
    }

    /// Attach a per-item retrieval grant (roles/departments allowed to retrieve — §2 `rbac_scope`).
    pub fn with_rbac_scope(mut self, rbac: RbacScope) -> Self {
        self.rbac_scope = Some(rbac);
        self
    }

    /// Attach tags.
    pub fn with_tags(mut self, tags: &[&str]) -> Self {
        self.tags = tags.iter().map(|t| t.to_string()).collect();
        self
    }

    /// Attach a typed knowledge-graph link.
    pub fn with_link(mut self, edge: EdgeKind, target: &str) -> Self {
        self.links.push(Link::new(edge, target));
        self
    }

    /// Set the valid-time window (`effective_from`, `expires_at`) for bi-temporal queries.
    pub fn with_validity(mut self, effective_from: Option<u64>, expires_at: Option<u64>) -> Self {
        self.effective_from = effective_from;
        self.expires_at = expires_at;
        self
    }

    /// Attach an embedding (normally set by the re-embed pipeline, not by hand).
    pub fn with_embedding(mut self, embedding: Embedding) -> Self {
        self.embedding = Some(embedding);
        self
    }

    /// Whether this item may be served as **authoritative** right now. Org-knowledge is
    /// authoritative only once `Approved`/`Production`. Non-org items are authoritative unless they
    /// are still in the governance queue (`Draft`/`Conflicted`) or have been retired
    /// (`Deprecated`/`Superseded`). This is what makes a shared-scope (org/dept/team/repo) non-OKI
    /// write land in the governance queue rather than as instant org-wide authority (design §8.2):
    /// a `Draft` fact — whatever its kind — is never served as an authoritative "fact."
    pub fn is_authoritative(&self) -> bool {
        match self.kind {
            MemoryKind::OrgKnowledge => self.governance.is_authoritative_state(),
            _ => !matches!(
                self.governance,
                GovernanceState::Deprecated
                    | GovernanceState::Superseded
                    | GovernanceState::Draft
                    | GovernanceState::Conflicted
            ),
        }
    }

    /// The conflict-subject key: two OKIs of the same key that disagree cannot both be
    /// authoritative (design §6). Non-org items have no conflict key.
    pub fn conflict_key(&self) -> Option<String> {
        let payload = self.payload.as_ref()?;
        Some(format!("{}|{}", self.scope.key(), payload.subject_key()))
    }

    /// A normalized subject for personal-fact auto-supersession (recency wins for same subject).
    pub(crate) fn personal_subject(&self) -> String {
        format!(
            "{}|{}|{}",
            self.scope.key(),
            self.kind.as_str(),
            self.title.trim().to_lowercase()
        )
    }

    /// Lowercased haystack of title + body + tags, used for keyword relevance.
    fn haystack(&self) -> String {
        let mut s = String::with_capacity(self.title.len() + self.body.len() + 16);
        s.push_str(&self.title.to_lowercase());
        s.push(' ');
        s.push_str(&self.body.to_lowercase());
        for t in &self.tags {
            s.push(' ');
            s.push_str(&t.to_lowercase());
        }
        s
    }

    /// The most recent logical tick at which this item was written, used, or confirmed — the
    /// "last activity" that usage-based decay measures against (design §6).
    pub fn last_active(&self) -> u64 {
        let mut t = self.seq;
        if let Some(u) = self.last_used {
            t = t.max(u);
        }
        if let Some(c) = self.last_confirmed {
            t = t.max(c);
        }
        t
    }

    /// Multiplicative recency-decay factor in `(0, 1]` at logical time `now`, halving every
    /// `half_life` ticks since this item's **last activity** ([`last_active`](MemoryItem::last_active)
    /// = write, use, or confirmation) — not merely its write tick. This implements design §6's
    /// "a fact unconfirmed **and unused** past N months drops priority": a freshly-used old fact is
    /// not penalized as stale, while an old fact nobody has touched decays. Decay is a **ranking**
    /// signal, never a silent deletion. `half_life == 0` disables decay (returns `1.0`).
    pub fn decay_factor(&self, now: u64, half_life: u64) -> f64 {
        if half_life == 0 {
            return 1.0;
        }
        let age = now.saturating_sub(self.last_active()) as f64;
        0.5f64.powf(age / half_life as f64)
    }

    /// Whether this item has decayed below `floor` at `now` (a candidate for eventual expiry).
    pub fn is_decayed(&self, now: u64, half_life: u64, floor: f64) -> bool {
        self.decay_factor(now, half_life) < floor
    }

    /// Whether the item is valid at logical valid-time `t` (`effective_from <= t < expires_at`).
    pub fn valid_at(&self, t: u64) -> bool {
        let from_ok = self.effective_from.map(|f| f <= t).unwrap_or(true);
        let to_ok = self.expires_at.map(|e| t < e).unwrap_or(true);
        from_ok && to_ok
    }
}

// ============================ Precedence ============================

/// Injection precedence class (lower = injected first / wins). Fixes the design's ordering:
/// safety/compliance org rule > other org-knowledge > substantive user facts > style preference
/// (design §6/§7). A `UserPreference` can therefore never outrank a `SecurityRule`.
pub fn precedence_class(item: &MemoryItem) -> u8 {
    match item.kind {
        MemoryKind::OrgKnowledge => match item.org_type {
            Some(OrgKnowledgeType::SecurityRule) | Some(OrgKnowledgeType::ArchitectureDecision) => {
                0
            }
            _ => 1,
        },
        MemoryKind::Semantic | MemoryKind::Procedural => 2,
        MemoryKind::Episodic | MemoryKind::Session => 3,
        MemoryKind::UserPreference => 4,
    }
}

// ============================ Query ============================

/// The ordering discipline applied to results after pre-rank filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RankOrder {
    /// Pure relevance (keyword weight dominates, recency breaks ties). The default.
    #[default]
    Relevance,
    /// Injection ordering: [`precedence_class`] first, then relevance within a class. Use this when
    /// fitting memory into a context budget so safety rules are never crowded out by chit-chat.
    Precedence,
}

/// Confidence/recency decay parameters applied to ranking (design §6).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DecayParams {
    /// Logical "now" tick.
    pub now: u64,
    /// Ticks over which a score halves.
    pub half_life: u64,
}

/// A relevance query over memory. RBAC/data-class + identity-scope filtering happen **pre-rank**
/// against the supplied [`AccessScope`]; `authoritative_only` (default `true`) additionally
/// excludes un-approved org-knowledge so it can never be served as authority.
#[derive(Debug, Clone)]
pub struct MemoryQuery {
    /// A dense query vector for **semantic recall** (design §2 envelope `embedding`: "for semantic
    /// recall — computed under the same data-class rules as any other embedding"). When set, an
    /// item's [`Embedding`] vector is cosine-scored against this vector and blended with keyword
    /// relevance (hybrid). `None` = pure keyword/recency recall (unchanged behaviour). The vector's
    /// dimensionality must match the stored embeddings; a mismatched item contributes no semantic
    /// signal (it can still match on keywords).
    pub semantic: Option<Vec<f32>>,
    /// Keywords (matched case-insensitively as substrings). Empty = match all (recency only).
    pub keywords: Vec<String>,
    /// Restrict to a single kind, if set.
    pub kind: Option<MemoryKind>,
    /// Restrict to a single org-knowledge type, if set.
    pub org_type: Option<OrgKnowledgeType>,
    /// Restrict to an exact scope, if set (in addition to identity-scope filtering).
    pub scope: Option<Scope>,
    /// Exclude un-approved org-knowledge (and any deprecated/superseded/conflicted item). Default `true`.
    pub authoritative_only: bool,
    /// Result ordering discipline.
    pub order: RankOrder,
    /// Transaction-time replay: resolve each id to the version whose write tick is `<= as_of`.
    /// `None` = current version.
    pub as_of: Option<u64>,
    /// Valid-time filter: keep only items valid at this logical valid-time. `None` = no filter.
    pub valid_as_of: Option<u64>,
    /// Apply recency decay to scores.
    pub decay: Option<DecayParams>,
    /// Max hits to return (`0` = unlimited).
    pub limit: usize,
}

impl Default for MemoryQuery {
    fn default() -> Self {
        MemoryQuery {
            semantic: None,
            keywords: Vec::new(),
            kind: None,
            org_type: None,
            scope: None,
            authoritative_only: true,
            order: RankOrder::Relevance,
            as_of: None,
            valid_as_of: None,
            decay: None,
            limit: 0,
        }
    }
}

impl MemoryQuery {
    /// A keyword query (authoritative-only, all kinds/scopes).
    pub fn keywords(words: &[&str]) -> Self {
        MemoryQuery {
            keywords: words.iter().map(|w| w.to_lowercase()).collect(),
            ..Default::default()
        }
    }
    /// A pure **semantic recall** query over a dense query vector (no keywords) — ranks candidates by
    /// cosine similarity of their [`Embedding`] against `vector`.
    pub fn semantic(vector: Vec<f32>) -> Self {
        MemoryQuery {
            semantic: Some(vector),
            ..Default::default()
        }
    }
    /// Attach a semantic query vector to blend with keyword relevance (hybrid recall).
    pub fn with_semantic(mut self, vector: Vec<f32>) -> Self {
        self.semantic = Some(vector);
        self
    }
    /// Restrict to a kind.
    pub fn with_kind(mut self, kind: MemoryKind) -> Self {
        self.kind = Some(kind);
        self
    }
    /// Restrict to an org-knowledge type.
    pub fn with_org_type(mut self, t: OrgKnowledgeType) -> Self {
        self.org_type = Some(t);
        self
    }
    /// Restrict to a scope.
    pub fn with_scope(mut self, scope: Scope) -> Self {
        self.scope = Some(scope);
        self
    }
    /// Include un-approved / non-authoritative items (e.g. an owner reviewing their Draft queue).
    pub fn including_non_authoritative(mut self) -> Self {
        self.authoritative_only = false;
        self
    }
    /// Order by injection precedence rather than pure relevance.
    pub fn by_precedence(mut self) -> Self {
        self.order = RankOrder::Precedence;
        self
    }
    /// Transaction-time replay to `as_of`.
    pub fn as_of(mut self, tick: u64) -> Self {
        self.as_of = Some(tick);
        self
    }
    /// Valid-time filter to `t`.
    pub fn valid_as_of(mut self, t: u64) -> Self {
        self.valid_as_of = Some(t);
        self
    }
    /// Apply recency decay.
    pub fn with_decay(mut self, now: u64, half_life: u64) -> Self {
        self.decay = Some(DecayParams { now, half_life });
        self
    }
    /// Cap the number of hits.
    pub fn limit(mut self, n: usize) -> Self {
        self.limit = n;
        self
    }

    /// Whether this query is a **bulk, unscoped sweep of extraction-sensitive org-knowledge** — the
    /// shape of an OKI-extraction recon attempt (design §8.8 / gap AM: "get the agent to dump its
    /// full `SecurityRule`/`ApprovedLibrary` set verbatim"). True when the query has **no scope
    /// restriction** and either targets an extraction-sensitive [`OrgKnowledgeType`] outright or is a
    /// keyword-less request that would sweep all authoritative org-knowledge. A properly scoped read
    /// (as the Context-Fabric planner always issues — `with_scope(Repo(..))`) is never a recon sweep.
    /// This is the *shape* test; the store's [`extraction guard`](store::InMemoryStore::with_extraction_guard)
    /// decides whether to fail closed on it.
    pub fn is_unscoped_safety_recon(&self) -> bool {
        if self.scope.is_some() {
            return false;
        }
        match self.org_type {
            Some(t) => t.is_extraction_sensitive(),
            // A keyword-less, kind-unfiltered (or OrgKnowledge-only) unscoped query would return the
            // whole authoritative OKI corpus — the classic "dump everything" shape.
            None => {
                self.keywords.is_empty()
                    && matches!(self.kind, None | Some(MemoryKind::OrgKnowledge))
            }
        }
    }
}

/// A scored query result.
#[derive(Debug, Clone, PartialEq)]
pub struct MemoryHit {
    /// The matched item (a snapshot copy at the resolved version).
    pub item: MemoryItem,
    /// Relevance score — higher is more relevant.
    pub score: f64,
    /// Injection precedence class (lower wins). Populated for ordering transparency.
    pub precedence: u8,
}

/// Keyword relevance: distinct keyword occurrences across the haystack, with a title boost. Score
/// is `keyword_weight * 1e6 + seq` so keyword relevance strictly dominates and recency (higher
/// `seq`) breaks ties. Returns `None` when keywords are supplied but none match.
pub(crate) fn relevance(item: &MemoryItem, keywords: &[String]) -> Option<f64> {
    if keywords.is_empty() {
        return Some(item.seq as f64);
    }
    let hay = item.haystack();
    let title = item.title.to_lowercase();
    let mut weight = 0.0f64;
    let mut any = false;
    for kw in keywords {
        if kw.is_empty() {
            continue;
        }
        let occ = hay.matches(kw.as_str()).count();
        if occ > 0 {
            any = true;
            weight += occ as f64;
            if title.contains(kw.as_str()) {
                weight += 2.0;
            }
        }
    }
    if !any {
        return None;
    }
    Some(weight * 1_000_000.0 + item.seq as f64)
}

/// Cosine similarity of two dense vectors in `[-1.0, 1.0]`, or `None` if either is empty, their
/// dimensionalities differ, or a norm is zero. The metric behind [`MemoryQuery::semantic`] recall.
pub(crate) fn cosine(a: &[f32], b: &[f32]) -> Option<f64> {
    if a.is_empty() || a.len() != b.len() {
        return None;
    }
    let mut dot = 0.0f64;
    let mut na = 0.0f64;
    let mut nb = 0.0f64;
    for (x, y) in a.iter().zip(b.iter()) {
        let (x, y) = (*x as f64, *y as f64);
        dot += x * y;
        na += x * x;
        nb += y * y;
    }
    if na == 0.0 || nb == 0.0 {
        return None;
    }
    Some(dot / (na.sqrt() * nb.sqrt()))
}

/// Semantic relevance of `item` against a query vector: the cosine similarity of the item's stored
/// [`Embedding`] against `query_vec`, or `None` when the item has no (dimension-compatible)
/// embedding. Used to blend semantic recall into ranking (design §2 `embedding` "for semantic recall").
pub(crate) fn semantic_score(item: &MemoryItem, query_vec: &[f32]) -> Option<f64> {
    let emb = item.embedding.as_ref()?;
    cosine(&emb.vector, query_vec)
}

// ============================ Errors ============================

/// Errors from the memory store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemoryError {
    /// No item with that id.
    NotFound(String),
    /// The write violates an invariant (e.g. org-knowledge written already-approved, empty id).
    InvalidWrite(String),
    /// The typed OKI payload failed schema validation (never persisted "as text").
    SchemaViolation(String),
    /// The caller lacks authority for the operation (e.g. promote without [`CAP_APPROVE`]).
    NotAuthorized(String),
    /// The requested lifecycle transition is not legal from the current state.
    InvalidTransition(String),
    /// A durable-backend (storage) failure while persisting/loading through the
    /// [`SqlLike`](durable::SqlLike) seam — the in-memory backend never returns this; a Postgres
    /// backend surfaces its driver/IO errors here so the write-through path fails closed.
    Storage(String),
}

impl std::fmt::Display for MemoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MemoryError::NotFound(id) => write!(f, "memory item not found: {id}"),
            MemoryError::InvalidWrite(m) => write!(f, "invalid memory write: {m}"),
            MemoryError::SchemaViolation(m) => write!(f, "schema violation: {m}"),
            MemoryError::NotAuthorized(m) => write!(f, "not authorized: {m}"),
            MemoryError::InvalidTransition(m) => write!(f, "invalid transition: {m}"),
            MemoryError::Storage(m) => write!(f, "durable store error: {m}"),
        }
    }
}

impl std::error::Error for MemoryError {}

// ============================ Redactor seam ============================

/// The compliance/guardrails redaction seam applied to EVERY write BEFORE persistence — the
/// memory-side compliance gate (a PAN/PII/secret must never enter durable memory). The store stays
/// dependency-light; a higher crate adapts the runtime's compliance gate (e.g. `StrongRedactor`)
/// into this trait so a memory write is redacted by exactly the same detector the turn pipeline
/// uses. [`InMemoryStore::re_redact`] re-applies it retroactively when rules change (design §8.6).
pub trait Redactor: std::fmt::Debug + Send + Sync {
    /// Return `text` with any sensitive content redacted. Called on title/body/tags at write time.
    fn redact(&self, text: &str) -> String;
}

// ============================ Store trait ============================

/// The single surface for reading and governing memory. A durable (Postgres/KG) impl slots in
/// behind this trait without changing callers.
pub trait MemoryStore {
    /// Persist an item as a new version. Enforces every write invariant (human-gate, typed-payload
    /// schema, approved-org immutability, compliance redaction). Assigns `version` + `seq`.
    fn write(&mut self, item: MemoryItem) -> Result<(), MemoryError>;

    /// Fetch the current version of an item regardless of governance state (owner review / audit),
    /// **skipping every access check** (scope, per-item RBAC, data-class clearance). Renamed from
    /// the historical `get` so the lack of authorization is visible at every call site — prefer
    /// [`get_authorized`](MemoryStore::get_authorized) unless the caller has already independently
    /// established the requester is allowed to see this item (e.g. internal governance workflows
    /// that already gate on a capability check first).
    fn get_unchecked(&self, id: &str) -> Option<&MemoryItem>;

    /// Fetch the current version of an item, enforcing the same reachable-scope, per-item RBAC, and
    /// data-class clearance checks [`query`](MemoryStore::query) applies. Returns `Ok(None)` both
    /// when the item does not exist and when it exists but `access` may not see it — the two cases
    /// are made indistinguishable on purpose (design contract on [`delete_as`](MemoryStore::delete_as)
    /// applies here too: refusing with an error would leak the item's existence).
    fn get_authorized(
        &self,
        id: &str,
        access: &AccessScope,
    ) -> Result<Option<&MemoryItem>, MemoryError> {
        Ok(self.get_unchecked(id).filter(|item| {
            let (visible, used_break_glass) = access.can_see(&item.scope);
            if !visible || used_break_glass {
                return false;
            }
            if let Some(rb) = &item.rbac_scope {
                if !rb.allows(access.principal()) {
                    return false;
                }
            }
            if item.data_class.sensitivity() > access.principal().clearance.sensitivity()
                && !access.is_own_personal(&item.scope)
            {
                return false;
            }
            true
        }))
    }

    /// Promote a `Draft` org item toward authority. Requires [`CAP_APPROVE`]/admin. If promoting
    /// would create two authoritative OKIs disagreeing on the same subject, the item is parked
    /// `Conflicted` (design §6) instead of `Approved`. Returns the resulting state.
    fn promote(&mut self, id: &str, approver: &Principal) -> Result<GovernanceState, MemoryError>;

    /// Retire an item (→ `Deprecated`). Requires [`CAP_APPROVE`]/admin. Retained for audit.
    fn deprecate(&mut self, id: &str, actor: &Principal) -> Result<(), MemoryError>;

    /// Hard-delete an item and all its versions (right-to-erasure, design §5: "delete is a user's
    /// right over their OWN items"). **Attributed and authorized** — there is deliberately no
    /// unattributed `delete`: every mutating memory op carries a principal and is authorized against
    /// the item's scope *and* governance state.
    ///
    /// Contract every implementation must honour:
    /// - an item the caller cannot [see](AccessScope::can_see) is indistinguishable from a missing
    ///   one (`Ok(false)`) — refusing with an error would leak its existence;
    /// - personal ([`Scope::User`]) items may be hard-deleted by their **owner** (or an admin under
    ///   an audited break-glass justification) — that is the DPDP/right-to-erasure path;
    /// - shared-scope items (`Org`/`Department`/`Team`/`Repo`) that ever reached authority
    ///   (`Approved`/`Production`) or were retired (`Deprecated`/`Superseded`) are **kept for audit**
    ///   (design §6) and are never hard-deletable — retire them via
    ///   [`deprecate`](MemoryStore::deprecate) instead;
    /// - a still-queued shared-scope item (`Draft`/`Conflicted`) may be discarded only by a holder of
    ///   [`CAP_APPROVE`] (the same human gate that governs promotion);
    /// - the deletion is recorded to the tamper-evident audit chain **with the actor's identity**.
    fn delete_as(&mut self, id: &str, actor: &AccessScope) -> Result<bool, MemoryError>;

    /// Relevance query: pre-rank RBAC/data-class + identity-scope + governance filtering, then
    /// keyword/recency ranking. Results sorted most-relevant first (or by precedence if requested).
    fn query(&self, q: &MemoryQuery, access: &AccessScope) -> Vec<MemoryHit>;
}

/// GAP-FIX memory — the served MEM-10 governed memory surface (`GET /memory/consent`, `GET
/// /memory/export`, `DELETE /memory`, DPDP consent/portability/right-to-erasure) was hardcoded to a
/// bare [`InMemoryStore`] that received none of the writes the served chat engine's
/// [`DurableMemoryStore`](durable::DurableMemoryStore) actually makes — so a subject's "what do you
/// remember about me" / export / erasure always answered against an empty, disconnected store,
/// regardless of what the real Context-Fabric memory layer held. `InMemoryStore` and
/// `DurableMemoryStore` already implement identically-shaped `remembered_about`/`export_subject`/
/// `erase_subject` inherent methods (the durable variant adds write-through persistence + a durable
/// consent receipt); this trait is the thin common seam a served surface can be generic over so it can
/// be handed EITHER store — in particular, the SAME [`MemorySqlBackend`](durable::MemorySqlBackend)
/// the served chat engine's memory reader is opened over (a cheap, shared clone — the whole backend is
/// `Arc`-internal — so a second `DurableMemoryStore` opened over it sees every row the chat engine
/// writes).
/// GAP-FIX memory (write-path-missing) — the served EXPLICIT-REMEMBER write seam (`POST
/// /memory/remember`). `write_as` (an inherent method on both [`store::InMemoryStore`] and
/// [`durable::DurableMemoryStore`], identically shaped) is the real, fully governed write primitive
/// (write-isolation via [`AccessScope::can_write`], human-gate for org-knowledge, compliance
/// redaction, embed-on-write) — but before this trait nothing served ever called it outside this
/// crate's own tests: every served route/turn-loop hook touching memory was read-only
/// (`ainxt_runtime::memory::MemoryReader`'s `read_for_turn`, [`ConsentSurface`]'s read/erase trio).
/// `Engine.memory` was a read-only seam by construction — `MemoryReader` has no write method,
/// deliberately (design §8.1: no code path from "a tool/RAG result said so" straight into memory) —
/// so a served WRITE seam has to be a *separate* trait a surface can hold alongside the reader, not
/// a widening of `MemoryReader` itself. This is that seam: the thin common surface a served route
/// can be handed to author a NEW item into the SAME store `read_for_turn` reads from, kept
/// dependency-light exactly like [`MemoryStore`]/[`ConsentSurface`] (no concrete durable-store type
/// leaks into the served crate). A production adapter wraps the SAME long-lived durable-reader
/// instance the engine's Context-Fabric memory seam is built over (never a second, independently
/// opened store — see `ConsentBacking`'s doc for why a freshly-reopened store silently diverges from
/// a long-lived one that never re-pulls).
pub trait MemoryWriter: Send + Sync {
    /// Attributed, identity-checked write (see [`store::InMemoryStore::write_as`] /
    /// [`AccessScope::can_write`]). `&self` (not `&mut self`) because every real implementation
    /// holds its interior-mutable store behind a lock — mirrors the read seam's `&self` shape.
    fn write_as(&self, item: MemoryItem, writer: &AccessScope) -> Result<(), MemoryError>;
}

pub trait ConsentSurface: Send {
    /// The "what do you remember about me" view (DPDP transparency).
    fn remembered_about(
        &mut self,
        subject: &str,
        access: &AccessScope,
    ) -> Result<ConsentView, MemoryError>;
    /// Machine-readable export of everything held for a subject (DPDP portability).
    fn export_subject(
        &mut self,
        subject: &str,
        access: &AccessScope,
    ) -> Result<SubjectExport, MemoryError>;
    /// Right-to-erasure. `Result`-wrapped (not the bare `ErasureReceipt` [`InMemoryStore::erase_subject`]
    /// returns) because the durable variant's write-through sync is fallible; the caller's own
    /// [`AccessScope::can_see`] check gates whether this is ever called, same as both concrete stores.
    fn erase_subject(&mut self, subject: &str) -> Result<ErasureReceipt, MemoryError>;
    /// GAP-FIX memory (bi-temporal-valid-as-of-no-surface) — a general, caller-identity-scoped
    /// [`MemoryQuery`] (including its `valid_as_of` bi-temporal filter — design §7 "validAsOf
    /// query"). Audited exactly like [`Self::remembered_about`]/[`Self::export_subject`] when it
    /// reaches a personal item via break-glass (`query_audited`, never the fail-closed plain
    /// `MemoryStore::query`). This is the served surface `q.valid_as_of` was missing: before it,
    /// `MemoryQuery::valid_as_of` worked and was unit-tested, but the only served reader
    /// (`read_for_turn`, driving `/v1/chat`'s Context-Fabric injection) always queries "now" — no
    /// `/memory/*` route accepted a date parameter at all.
    fn query(
        &mut self,
        q: &MemoryQuery,
        access: &AccessScope,
    ) -> Result<Vec<MemoryHit>, MemoryError>;
}

impl ConsentSurface for store::InMemoryStore {
    fn remembered_about(
        &mut self,
        subject: &str,
        access: &AccessScope,
    ) -> Result<ConsentView, MemoryError> {
        store::InMemoryStore::remembered_about(self, subject, access)
    }
    fn export_subject(
        &mut self,
        subject: &str,
        access: &AccessScope,
    ) -> Result<SubjectExport, MemoryError> {
        store::InMemoryStore::export_subject(self, subject, access)
    }
    fn erase_subject(&mut self, subject: &str) -> Result<ErasureReceipt, MemoryError> {
        Ok(store::InMemoryStore::erase_subject(self, subject))
    }
    fn query(
        &mut self,
        q: &MemoryQuery,
        access: &AccessScope,
    ) -> Result<Vec<MemoryHit>, MemoryError> {
        Ok(store::InMemoryStore::query_audited(self, q, access))
    }
}

impl<D: durable::SqlLike + Send> ConsentSurface for durable::DurableMemoryStore<D> {
    fn remembered_about(
        &mut self,
        subject: &str,
        access: &AccessScope,
    ) -> Result<ConsentView, MemoryError> {
        durable::DurableMemoryStore::remembered_about(self, subject, access)
    }
    fn export_subject(
        &mut self,
        subject: &str,
        access: &AccessScope,
    ) -> Result<SubjectExport, MemoryError> {
        durable::DurableMemoryStore::export_subject(self, subject, access)
    }
    fn erase_subject(&mut self, subject: &str) -> Result<ErasureReceipt, MemoryError> {
        durable::DurableMemoryStore::erase_subject(self, subject)
    }
    fn query(
        &mut self,
        q: &MemoryQuery,
        access: &AccessScope,
    ) -> Result<Vec<MemoryHit>, MemoryError> {
        durable::DurableMemoryStore::query_audited(self, q, access)
    }
}

/// GAP-FIX memory — the handle a served `ConsentSurface` route holds. `DurableMemoryStore` only ever
/// reads its own in-RAM snapshot (loaded once at [`durable::DurableMemoryStore::open`]); writes sync
/// through to the backend, but a long-lived store instance never re-pulls, so two instances opened
/// once at startup over even the SAME [`MemorySqlBackend`] silently diverge forever — the served
/// route would keep answering "what do you remember about me" from a stale, ever-emptier snapshot
/// while the real store (e.g. the chat engine's own memory reader) keeps writing. This handle instead
/// holds the *backend*, not a store, and opens a fresh, fully-current [`durable::DurableMemoryStore`]
/// on every call — `open()`'s `db.load_items()`/`db.load_audit()` always re-read the shared backend,
/// so every call sees every write any other handle over a clone of the SAME backend has made,
/// however recently. `InMemoryStore` has no such backend to reopen from, so that variant instead
/// holds the one shared instance directly.
pub enum ConsentBacking {
    InMemory(std::sync::Arc<std::sync::Mutex<store::InMemoryStore>>),
    Durable(durable::MemorySqlBackend),
}

impl ConsentBacking {
    /// Run `f` against a live, up-to-date [`ConsentSurface`]. For [`ConsentBacking::Durable`] this
    /// opens a fresh store from the current backend contents on every call — see the type doc for why
    /// that (not a cached long-lived store) is the only way to observe concurrent writers.
    pub fn with_surface<R>(
        &self,
        f: impl FnOnce(&mut dyn ConsentSurface) -> Result<R, MemoryError>,
    ) -> Result<R, MemoryError> {
        match self {
            ConsentBacking::InMemory(store) => {
                let mut guard = store.lock().expect("memory store lock");
                f(&mut *guard)
            }
            ConsentBacking::Durable(backend) => {
                let mut store = durable::DurableMemoryStore::open(backend.clone())?;
                f(&mut store)
            }
        }
    }

    /// GAP-FIX memory — retroactive re-redaction sweep (design §8.6: "when compliance rules change,
    /// previously-stored memory is re-scanned and re-redacted — leakage defense isn't only at
    /// write-time"). [`store::InMemoryStore::re_redact`] /
    /// [`durable::DurableMemoryStore::re_redact`] were fully implemented and unit-tested but had ZERO
    /// callers outside this crate's own tests: nothing in the served daemon ever re-swept an
    /// already-persisted row after a compliance-rule update, so content redacted under a since-tightened
    /// rule (e.g. a newly-recognized secret/PII pattern) stayed exposed in durable memory indefinitely.
    ///
    /// Deliberately narrower than [`with_surface`](Self::with_surface): re-redaction has no `now`/TTL
    /// argument and is never subject-scoped, so it does not belong on [`ConsentSurface`] (which is
    /// keyed by subject + [`AccessScope`]) — this is a plain compliance-wide sweep, safe to drive on a
    /// timer. Opens a live store the SAME way `with_surface` does (a fresh, fully-current
    /// [`durable::DurableMemoryStore`] for the `Durable` variant, so this sees every row any other
    /// handle over a clone of the SAME backend has written; the one shared instance for `InMemory`).
    /// Returns the number of item-versions whose content actually changed.
    ///
    /// NOTE: [`store::InMemoryStore::purge_expired`] (TTL-based purge of raw episodic/session tiers) is
    /// a companion built-but-unwired maintenance op that is deliberately NOT exposed here yet: its `now`
    /// argument is compared against [`MemoryItem::seq`]/`last_active`, which are stamped from the
    /// store's own internal write-order clock (small monotonically-increasing integers), not wall time.
    /// The served daemon's only other caller of a memory `now` ([`crate::fabric`]'s `touch`, driven by
    /// `DurableMemoryReader` with real Unix-epoch seconds) already feeds a wall-clock value into that
    /// same logical-clock axis for `last_used`/`last_confirmed` — so a purge sweep driven the same way
    /// would treat every untouched episodic/session item as instantly older than any human-scale TTL and
    /// mass-delete it on the very first tick. Wiring `purge_expired` safely needs that clock-model
    /// mismatch resolved first (a real logical-clock/wall-clock reconciliation), not just a call site.
    pub fn re_redact(&self) -> Result<usize, MemoryError> {
        match self {
            ConsentBacking::InMemory(store) => {
                let mut guard = store.lock().expect("memory store lock");
                Ok(store::InMemoryStore::re_redact(&mut guard))
            }
            ConsentBacking::Durable(backend) => {
                let mut store = durable::DurableMemoryStore::open(backend.clone())?;
                durable::DurableMemoryStore::re_redact(&mut store)
            }
        }
    }

    /// GAP-FIX regulated-fi-responsible-lifecycle (FI-01 §5.4) — a **read-only** snapshot of every
    /// stored item's free text (title/body/tags/typed-payload-as-JSON), for the served daemon's
    /// defense-in-depth CHD sink-sweep (`ainxt_runtimed::AssembledFull::sweep_memory`), mirroring the
    /// SAME proof [`Self::re_redact`]'s write-path guard already gets over the Event Log
    /// (`AssembledFull::sweep_event_log`). Unlike [`Self::re_redact`], this NEVER mutates the store —
    /// it exists to *prove* the write-path guard held, not to fix a drift. Opens a live store the SAME
    /// way [`Self::with_surface`]/[`Self::re_redact`] do (a fresh, fully-current
    /// [`durable::DurableMemoryStore`] for the `Durable` variant, so every concurrent writer's content
    /// is visible; the one shared instance for `InMemory`).
    pub fn all_content(&self) -> Result<Vec<(String, String)>, MemoryError> {
        match self {
            ConsentBacking::InMemory(store) => {
                let guard = store.lock().expect("memory store lock");
                Ok(store::InMemoryStore::all_content(&guard))
            }
            ConsentBacking::Durable(backend) => {
                let store = durable::DurableMemoryStore::open(backend.clone())?;
                Ok(durable::DurableMemoryStore::all_content(&store))
            }
        }
    }

    /// GAP-FIX memory (embedding-lifecycle no caller) — [`store::InMemoryStore::reembed_all`] (design
    /// §8.5: data-class-routed batch re-embed, regulated/PII content restricted to the in-house model)
    /// was fully implemented and unit-tested but had ZERO callers outside this crate's own tests: no
    /// served entrypoint ever ran the batch migration, so a platform embedding-model bump never actually
    /// re-embedded already-persisted memory items — they stayed on the old model's vector space
    /// indefinitely, silently degrading retrieval quality (and, if a stale item happened to have been
    /// mis-tiered before a compliance fix, never getting the chance to correct onto the in-house model).
    ///
    /// Mirrors [`Self::re_redact`]'s shape exactly (same two backings, same open-mutate-sync pattern) —
    /// this is the served daemon's batch embedding-lifecycle sweep, driven on a timer by
    /// `ainxt_runtimed::AssembledFull::spawn_memory_reembed_sweep`.
    pub fn reembed_all(
        &self,
        inhouse: &dyn store::Embedder,
        cloud: &dyn store::Embedder,
    ) -> Result<usize, MemoryError> {
        match self {
            ConsentBacking::InMemory(store) => {
                let mut guard = store.lock().expect("memory store lock");
                store::InMemoryStore::reembed_all(&mut guard, inhouse, cloud)
            }
            ConsentBacking::Durable(backend) => {
                let mut store = durable::DurableMemoryStore::open(backend.clone())?;
                durable::DurableMemoryStore::reembed_all(&mut store, inhouse, cloud)
            }
        }
    }

    /// GAP-FIX memory (PromotionPipeline-never-called) — [`PromotionPipeline::condense`] +
    /// [`PromotionPipeline::write_candidates`] (design §3/§6: episodic → semantic distillation) were
    /// fully implemented and unit-tested but had ZERO callers outside this crate's own tests: no
    /// served entrypoint ever ran a condensation checkpoint, so an episodic record never actually
    /// promoted to a durable semantic fact / user preference on any real deployment — it just aged
    /// out on its TTL, however durable and well-confirmed it was. This is the served daemon's
    /// promotion sweep, driven on a timer by
    /// `ainxt_runtimed::AssembledFull::spawn_memory_promotion_sweep` (mirrors [`Self::reembed_all`]'s
    /// shape: same two backings, same open-mutate-sync pattern).
    ///
    /// Runs an ADMIN-scoped (unscoped) query for every `Episodic` item against every existing
    /// `Semantic`/`UserPreference` item (the durability heuristic's own duplicate/contradiction
    /// check is scope+title keyed, so it needs to see across the whole store, not one caller's
    /// scope), then `condense`s and writes through the qualifying candidates. `pipeline`'s
    /// `id_prefix` MUST vary per call (the caller stamps in `now`, e.g. `format!("promo-{now}")`) —
    /// candidate ids are `{prefix}-{idx}` by *position* in the episodic batch, so reusing a prefix
    /// across two sweep ticks with a different episodic set at the same position would silently
    /// overwrite an unrelated, already-promoted fact under the same id. A still-present source
    /// episodic that was already promoted on a prior tick is naturally re-rejected as
    /// [`NonDurable::Duplicate`] on the next tick (the durable fact it produced now shows up in
    /// `existing_durable`), so a sweep is safe to repeat on an unchanged store.
    pub fn run_promotion_sweep(
        &self,
        pipeline: &PromotionPipeline,
        now: u64,
    ) -> Result<PromotionOutcome, MemoryError> {
        // GAP-FIX memory (PromotionPipeline-never-called) — an admin `AccessScope` with NO
        // break-glass justification still cannot see personal (`Scope::User`) items
        // (`AccessScope::can_see`'s own rule: personal scope is visible only to its owner, or to an
        // admin under an AUDITED break-glass justification — never to a bare admin). The sweep must
        // see across every scope, personal included, to detect subject-key duplicates/contradictions
        // and to promote a personal episodic fact into a personal durable one — so it is honestly
        // exercising break-glass on every personal item it reads, distinctly justified (and hence
        // distinctly audited) from a human DPO's break-glass read.
        let access = AccessScope::from_principal(Principal::admin("ainxt-memory-promotion-sweep"))
            .with_break_glass(
                "scheduled episodic-to-semantic promotion sweep (automated, design §3/§6)",
            );
        let episodic_query = MemoryQuery::keywords(&[])
            .with_kind(MemoryKind::Episodic)
            .including_non_authoritative();
        let semantic_query = MemoryQuery::keywords(&[])
            .with_kind(MemoryKind::Semantic)
            .including_non_authoritative();
        let preference_query = MemoryQuery::keywords(&[])
            .with_kind(MemoryKind::UserPreference)
            .including_non_authoritative();
        match self {
            ConsentBacking::InMemory(store) => {
                let mut guard = store.lock().expect("memory store lock");
                // `query_audited` (not the plain `MemoryStore::query` trait method, which fails
                // closed on break-glass — see its own doc) so a personal item this sweep reaches via
                // break-glass is actually served, with a provable audit entry.
                let episodics: Vec<MemoryItem> = guard
                    .query_audited(&episodic_query, &access)
                    .into_iter()
                    .map(|h| h.item)
                    .collect();
                let mut existing: Vec<MemoryItem> = guard
                    .query_audited(&semantic_query, &access)
                    .into_iter()
                    .map(|h| h.item)
                    .collect();
                existing.extend(
                    guard
                        .query_audited(&preference_query, &access)
                        .into_iter()
                        .map(|h| h.item),
                );
                let outcome = pipeline.condense(&episodics, &existing, now);
                pipeline.write_candidates(&mut *guard, &outcome)?;
                Ok(outcome)
            }
            ConsentBacking::Durable(backend) => {
                let mut store = durable::DurableMemoryStore::open(backend.clone())?;
                let episodics: Vec<MemoryItem> = store
                    .query_audited(&episodic_query, &access)?
                    .into_iter()
                    .map(|h| h.item)
                    .collect();
                let mut existing: Vec<MemoryItem> = store
                    .query_audited(&semantic_query, &access)?
                    .into_iter()
                    .map(|h| h.item)
                    .collect();
                existing.extend(
                    store
                        .query_audited(&preference_query, &access)?
                        .into_iter()
                        .map(|h| h.item),
                );
                let outcome = pipeline.condense(&episodics, &existing, now);
                pipeline.write_candidates(&mut store, &outcome)?;
                Ok(outcome)
            }
        }
    }

    /// GAP-FIX memory (erasure-cascade-not-reached) — [`store::cascade_erasure`] and
    /// [`session::SessionErasureTier`] were fully implemented and unit-tested (design §5 "the
    /// cascade must reach the Session (Redis) tier and captured feedback, not just the durable item
    /// store") but the served `DELETE /memory` route (`ainxt-server`'s `memory_delete_handler`)
    /// never called either: it only ever reached [`Self::with_surface`]'s bare wholesale
    /// [`ConsentSurface::erase_subject`], which erases the durable item store alone. A subject who
    /// erased their data still had every scratch item any other tier (session/Redis, captured
    /// feedback) held for them.
    ///
    /// This is [`with_surface`](Self::with_surface)'s erasure counterpart, generic over the SAME two
    /// backings, but driving [`store::cascade_erasure`] instead of the trait's plain
    /// `erase_subject` so each `tiers` entry gets its own proved, individually-audited removal count
    /// in [`ErasureReceipt::cascaded`] — not a single opaque item-store ack. `tiers` is borrowed, not
    /// owned, so the SAME [`ErasureTier`] objects (e.g. a [`session::SessionErasureTier`] bound to
    /// the caller-supplied session ids) can be reused across a retry.
    ///
    /// `ConsentBacking::Durable` has no directly-reachable `InMemoryStore` to hand the free function
    /// (it wraps one privately inside [`durable::DurableMemoryStore`]), so that variant instead calls
    /// [`durable::DurableMemoryStore::erase_subject_cascaded`] — the durable store's own
    /// write-through + durable-receipt-persisting counterpart to its plain `erase_subject`.
    pub fn erase_subject_cascaded(
        &self,
        subject: &str,
        tiers: &mut [&mut dyn ErasureTier],
    ) -> Result<ErasureReceipt, MemoryError> {
        match self {
            ConsentBacking::InMemory(store) => {
                let mut guard = store.lock().expect("memory store lock");
                Ok(store::cascade_erasure(&mut guard, subject, tiers))
            }
            ConsentBacking::Durable(backend) => {
                let mut store = durable::DurableMemoryStore::open(backend.clone())?;
                store.erase_subject_cascaded(subject, tiers)
            }
        }
    }

    /// GAP-FIX memory — the served OKI governance surface (design §3: "the flywheel proposes, a human
    /// legislates" — a queued `Draft` org-knowledge candidate reaches authority **only** through an
    /// explicit [`MemoryStore::promote`] by a [`CAP_APPROVE`] holder). `MemoryStore::promote`/
    /// `MemoryStore::deprecate` were fully implemented and unit-tested but had ZERO callers outside
    /// this crate's own tests: there was no served way for an approver to actually promote a queued
    /// candidate to authority, or retire an authoritative one — the governance half of the design's
    /// central human-gate was unreachable on the shipped daemon (only the DPDP consent/export/erasure
    /// half, MEM-10, was ever wired).
    ///
    /// Generic over the full [`MemoryStore`] trait (not the narrower [`ConsentSurface`]) since
    /// promotion/deprecation/attributed-delete/query are keyed by a [`Principal`]/[`AccessScope`], not
    /// a DPDP subject string. Opens a live store the SAME way [`with_surface`](Self::with_surface)
    /// does — a fresh, fully-current store for the `Durable` variant, the one shared instance for
    /// `InMemory` — so this sees, and durably commits alongside, every write any other handle over a
    /// clone of the SAME backend has made.
    pub fn with_store<R>(
        &self,
        f: impl FnOnce(&mut dyn MemoryStore) -> Result<R, MemoryError>,
    ) -> Result<R, MemoryError> {
        match self {
            ConsentBacking::InMemory(store) => {
                let mut guard = store.lock().expect("memory store lock");
                f(&mut *guard)
            }
            ConsentBacking::Durable(backend) => {
                let mut store = durable::DurableMemoryStore::open(backend.clone())?;
                f(&mut store)
            }
        }
    }
}
