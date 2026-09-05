// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! ainxt-context — the Context Fabric (retrieval + grounding + citations).
//!
//! Design: `docs/architecture/CONTEXT_FABRIC.md`, ADR-012. This is the minimal-but-real
//! slice: a `Retriever` trait (the seam), a lexical default retriever, **pre-rank data-class
//! filtering** (a chunk above the caller's clearance is removed BEFORE ranking, so its very
//! existence never leaks), context assembly, and citation lineage.
//!
//! The production retriever (pgvector HNSW + BM25 → RRF → rerank) implements the SAME
//! `Retriever` trait; nothing above it changes. Groundedness *verification* (does the answer
//! actually use the cited sources) is the guardrail/eval layer (ADR-008/010), not here — here
//! we ground the prompt and record which sources contributed.

use std::collections::BTreeSet;

use ainxt_types::DataClass;
use serde::{Deserialize, Serialize};

pub mod artifact;
pub mod extract;
pub mod optimizer;
pub mod route;

/// The numeric-claim contract + server-side re-derivation gate (`STRUCTURED_FEDERATED_RETRIEVAL.md`
/// §5, gap BH), re-exported so the compile/verify path exposes the whole "never trust model
/// arithmetic" gate as one surface the chat/convo caller drives without reaching into
/// `ainxt-synthesis` directly. [`CompiledWindow::verify_answer`] runs these on the live path.
pub use ainxt_synthesis::rederive::{
    lint_numeric_claims, numeric_gate, rederive_and_verify, ClaimSource, NumericClaim,
    NumericGateOutcome, NumericLintReport, RederivationReport, Rederiver, Tolerance, ValueClass,
};

/// The ledger-class answer gate — the `from_engine_verified`-style numeric DEFAULT (gap BH):
/// server-side numeric re-derivation as a HARD block on ledger-class answers (Confidential+ sources),
/// shipping only when every stated figure re-derives from the server's own data and blocking on any
/// mismatch. [`SourceRederiver`] is the production offline re-deriver over the governed
/// structured-retrieval result; [`is_ledger_class`] decides when the hard gate is armed. Re-exported
/// so a served surface drives the whole "never trust model arithmetic" default through the Context
/// Fabric without reaching into `ainxt-synthesis` directly (see [`CompiledWindow::verify_ledger_answer`]).
pub use ainxt_synthesis::{
    extract_ledger_figures, is_ledger_class, is_ledger_class_at, verify_answer, verify_answer_live,
    AnswerVerification, BlockReason, LedgerAnswerGate, LedgerFigureFinding, LedgerFigureVerdict,
    LiveNumericReport, Source, SourceRederiver, VerificationPolicy, LEDGER_CLASS_FLOOR,
};

/// The pre-rank access model re-exported so the single [`compile_window`] entrypoint is ONE
/// surface the chat/convo caller drives without reaching into `ainxt-retrieval` directly:
/// [`AccessContext`] (class + department + `ad_level` + allow/deny groups — the node/edge RBAC the
/// served path must carry, not just the data-class scalar), [`NodeAcl`] (the per-node predicate),
/// and the RLS [`RowFilter`]/[`RlsSession`] (the SET LOCAL-style row-filter bound from the OBO
/// principal). All are enforced **pre-rank** so a node the caller may not see never enters the
/// window — its existence never leaks (`CONTEXT_FABRIC.md` §3, §8.3).
pub use ainxt_retrieval::acl::{AccessContext, NodeAcl};
pub use ainxt_retrieval::rls::{RlsPolicy, RlsSession, RowFilter};
/// The eligible-model window descriptor for [`OptimizerConfig::eligible`], re-exported so a served
/// surface can build the two-phase budget-fit floor without a direct `ainxt-retrieval` dependency.
pub use ainxt_retrieval::EligibleModel;

/// One retrievable unit of knowledge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Chunk {
    pub id: String,
    pub source: String,
    pub text: String,
    pub data_class: DataClass,
    /// A monotonic freshness stamp (a caller-supplied logical tick — no wall clock enters this
    /// crate, `DETERMINISTIC` mandate). Higher = fresher. `None` = undated. The Context Optimizer
    /// uses it to prefer fresh sources (`CONTEXT_FABRIC.md` §3) when `OptimizerConfig::prefer_fresh`
    /// is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<i64>,
    /// Optional per-node RBAC beyond the data-class scalar (`CONTEXT_FABRIC.md` §8.3): which
    /// department owns the node, a minimum seniority, and allow/deny groups. `None` = class-only
    /// (visible to any caller cleared for `data_class`). When set, [`hybrid_retriever`] maps it onto
    /// the retrieval engine's [`NodeAcl`] so [`compile_window`] enforces it **pre-rank** — a caller
    /// in the wrong department (or too junior, or in a deny-group) never scores the node, so its
    /// existence never leaks. Additive + serde-skipped so an older serialized [`Chunk`] loads as
    /// class-only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acl: Option<NodeAcl>,
    /// Per-node **row attributes** for row-level-security filtering (`CONTEXT_FABRIC.md` §8.3, gap
    /// AJ) — the label values a per-request [`RowFilter`] binds the OBO principal's session settings
    /// against (e.g. `department = "settlement-eng"`, `tenant = "acme"`). `acl` gates on labels baked
    /// into the node (its owning department / seniority ceiling / groups); `attributes` closes the
    /// orthogonal half — a policy value **bound from the caller at query time**. When [`from_corpus`]
    /// maps this chunk onto the retrieval engine, these attributes carry through so
    /// [`compile_window`] → `hybrid_ctx_rls` can enforce the RLS row-filter **pre-rank** on the LIVE
    /// grounded path (a row outside the caller's row scope is never scored, so its existence never
    /// leaks). Additive + serde-skipped when empty, so an older serialized [`Chunk`] loads clean.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub attributes: std::collections::BTreeMap<String, String>,
    /// **Source authority** for conflict arbitration (`CONTEXT_FABRIC.md` §3 "arbitrate conflicts by
    /// recency/authority"). Higher = more authoritative (e.g. an approved runbook = 100, a wiki draft
    /// = 10). `None` = unranked (treated as the lowest authority, 0). When two candidate chunks claim
    /// the SAME `topic` (a conflict group), the optimizer keeps the higher-authority one — then, on an
    /// authority tie, the fresher (`timestamp`) one — and records the loser in the lineage as
    /// `SupersededByConflict` (accounted, never silently kept alongside a contradiction). Additive +
    /// serde-skipped so an older serialized [`Chunk`] loads as unranked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<u8>,
    /// The **conflict-group key** for recency/authority arbitration: chunks sharing a non-empty
    /// `topic` are treated as competing statements of the same fact, so only the winner grounds the
    /// answer (the design's conflict arbitration, not merely a freshness bonus). `None` = the chunk
    /// never conflicts (it stands alone). Additive + serde-skipped when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
}

impl Chunk {
    pub fn new(id: &str, source: &str, text: &str, data_class: DataClass) -> Self {
        Chunk {
            id: id.into(),
            source: source.into(),
            text: text.into(),
            data_class,
            timestamp: None,
            acl: None,
            attributes: std::collections::BTreeMap::new(),
            authority: None,
            topic: None,
        }
    }

    /// Attach a freshness stamp (builder style; higher = fresher).
    pub fn with_timestamp(mut self, timestamp: i64) -> Self {
        self.timestamp = Some(timestamp);
        self
    }

    /// Attach a source-authority rank for conflict arbitration (higher = more authoritative).
    pub fn with_authority(mut self, authority: u8) -> Self {
        self.authority = Some(authority);
        self
    }

    /// Attach a conflict-group `topic`: chunks sharing this key compete, and only the winner
    /// (highest authority, then freshest) grounds the answer — the design's recency/authority
    /// conflict arbitration.
    pub fn with_topic(mut self, topic: &str) -> Self {
        self.topic = Some(topic.to_string());
        self
    }

    /// Attach per-node RBAC (department / seniority / groups) beyond the data-class scalar. Enforced
    /// pre-rank by [`compile_window`] once the chunk is indexed through [`hybrid_retriever`].
    pub fn with_acl(mut self, acl: NodeAcl) -> Self {
        self.acl = Some(acl);
        self
    }

    /// Attach a row attribute (builder style) for RLS row-filtering. Carried through [`from_corpus`]
    /// onto the retrieval engine so a per-request [`RowFilter`] bound from the OBO principal filters
    /// the chunk **pre-rank** on the live grounded path (existence never leaks).
    pub fn with_attribute(mut self, key: &str, value: &str) -> Self {
        self.attributes.insert(key.to_string(), value.to_string());
        self
    }
}

/// A corpus of chunks (the knowledge base). Production sources index into pgvector; this
/// in-memory corpus backs the lexical retriever and tests.
#[derive(Debug, Default, Clone)]
pub struct Corpus {
    pub chunks: Vec<Chunk>,
}

impl Corpus {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with(mut self, chunk: Chunk) -> Self {
        self.chunks.push(chunk);
        self
    }

    // --- corpus-load API (the "populatable corpus" the live serving path seeds) -----------
    //
    // The daemon currently assembles the chat surface with `Corpus::new()` (empty), so live
    // grounding retrieves nothing regardless of retriever quality. These are the ingestion
    // entrypoints a KB/config loader calls to seed documents before serving. Wiring the
    // loader into the daemon's surface assembly is the remaining hot-crate change (see
    // `hybrid_retriever`); the entrypoints below make that a one-line call over real data.

    /// Populate a corpus in one shot from a batch of chunks — the primary corpus-load
    /// entrypoint that replaces the empty `Corpus::new()` on the served path.
    pub fn load(chunks: Vec<Chunk>) -> Self {
        Corpus { chunks }
    }

    /// Ingest a single document into the corpus (incremental indexing).
    pub fn add(&mut self, chunk: Chunk) {
        self.chunks.push(chunk);
    }

    /// Ingest a document from its raw parts (convenience over [`Corpus::add`]) — the shape a
    /// KB loader has after reading a source file/record.
    pub fn ingest(&mut self, id: &str, source: &str, text: &str, data_class: DataClass) {
        self.chunks.push(Chunk::new(id, source, text, data_class));
    }

    /// Ingest a batch of documents (incremental).
    pub fn extend(&mut self, chunks: impl IntoIterator<Item = Chunk>) {
        self.chunks.extend(chunks);
    }

    /// Number of indexed chunks.
    pub fn len(&self) -> usize {
        self.chunks.len()
    }

    /// Whether the corpus has no documents (an empty corpus grounds nothing — the exact
    /// stub condition the daemon ships with today).
    pub fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }

    /// Build the **ACL/RLS-carrying** retrieval [`ainxt_retrieval::Corpus`] this Context-Fabric
    /// corpus grounds over — the single public **corpus builder** the live daemon's
    /// `corpus_for_scope` adopts so the served grounded path enforces node-ACL **and** the RLS
    /// row-filter pre-rank (gap CTX: the plain `ainxt-context` corpus dropped every non-class RBAC
    /// axis AND every row attribute, so department/seniority/group RBAC and RLS were structurally
    /// unenforceable on grounding). Each chunk's per-node [`NodeAcl`] and its row [`attributes`] are
    /// PRESERVED onto the retrieval chunk, so `compile_window` → `hybrid_ctx_rls` filters a node the
    /// caller may not see on ANY axis (class / department / seniority / group / row-scope) before it
    /// is ever scored — its existence never leaks. Scope separation, if applied, is upstream of this
    /// (only in-scope chunks are in `self`), so it composes structurally.
    ///
    /// Wiring this into the reserved daemon `corpus_for_scope` is the remaining hot-crate change
    /// (see `needs_hot_wiring`); every preservation guarantee is verified here on the real object.
    pub fn to_retrieval_corpus(&self) -> ainxt_retrieval::Corpus {
        let rchunks: Vec<ainxt_retrieval::Chunk> =
            self.chunks.iter().map(context_chunk_to_retrieval).collect();
        ainxt_retrieval::Corpus::new(rchunks)
    }
}

/// Map one Context-Fabric [`Chunk`] onto an [`ainxt_retrieval::Chunk`], PRESERVING both the per-node
/// [`NodeAcl`] and the row [`attributes`] so the retrieval engine can enforce node-ACL + RLS
/// row-filter pre-rank. The single source of truth for the context→retrieval chunk mapping (shared
/// by [`Corpus::to_retrieval_corpus`] and [`HybridRetriever::from_corpus`]).
pub(crate) fn context_chunk_to_retrieval(c: &Chunk) -> ainxt_retrieval::Chunk {
    let mut rc = ainxt_retrieval::Chunk::new(&c.id, &c.text, c.data_class);
    if let Some(acl) = &c.acl {
        rc = rc.with_acl(acl.clone());
    }
    for (k, v) in &c.attributes {
        rc = rc.with_attribute(k, v);
    }
    rc
}

/// A scored retrieval hit.
#[derive(Debug, Clone)]
pub struct Scored {
    pub chunk: Chunk,
    pub score: f32,
}

/// The retrieval seam. `clearance` is the caller's max readable data class — chunks above it
/// are filtered **before** ranking (existence never leaks). The production hybrid retriever
/// implements this same trait.
pub trait Retriever: Send + Sync {
    fn retrieve(&self, query: &str, clearance: DataClass, k: usize) -> Vec<Scored>;

    /// RLS-scoped retrieval: retrieve under the OBO `principal` with a **row-level-security
    /// row-filter** applied pre-rank (SET LOCAL-style, bound from the principal). This is the seam
    /// the live compile path uses so the OBO caller's row scope shapes retrieval *before* ranking,
    /// never as a post-filter (existence never leaks).
    ///
    /// The default honors only the principal's clearance (a retriever with no row attributes has
    /// nothing to filter on); the production [`HybridRetriever`] overrides it to enforce the full
    /// [`ainxt_retrieval::rls::RowFilter`] on the real engine. An empty filter reduces to
    /// [`Retriever::retrieve`]. This is a read-filter, not an admission decision — it never denies
    /// the turn.
    fn retrieve_scoped(
        &self,
        query: &str,
        principal: &ainxt_types::Principal,
        _filter: &ainxt_retrieval::rls::RowFilter,
        k: usize,
    ) -> Vec<Scored> {
        self.retrieve(query, principal.clearance, k)
    }

    /// The full served-path retrieval seam: retrieve under the caller's complete OBO
    /// [`AccessContext`] (class + department + `ad_level` + allow/deny groups) with the RLS
    /// [`RowFilter`] applied in the SAME pre-rank pass. This is the seam [`compile_window`] uses so
    /// **node/department/ad_level RBAC** and the row-filter shape the candidate set *before* ranking
    /// — not just the data-class scalar (the gap the served synthetic `Principal::user("ctx-hybrid",
    /// &[])` path left open by dropping the real caller's department/seniority/groups).
    ///
    /// The default honors only the caller's class clearance (a retriever with no node-ACL/row
    /// attributes has nothing else to filter on, so falling back to [`Retriever::retrieve`] is
    /// honest, not a bypass). The production [`HybridRetriever`] overrides it to enforce the full
    /// [`ainxt_retrieval::acl::NodeAcl`] + [`RowFilter`] on the real engine. This is a retrieval
    /// read-filter, never a turn-admission decision — it never denies the turn.
    fn retrieve_ctx(
        &self,
        query: &str,
        access: &AccessContext,
        _filter: &RowFilter,
        k: usize,
    ) -> Vec<Scored> {
        self.retrieve(query, access.clearance, k)
    }
}

fn tokenize(s: &str) -> Vec<String> {
    s.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.len() > 2)
        .map(|w| w.to_string())
        .collect()
}

/// Lexical (term-overlap) retriever — no embeddings/network. Placeholder for the production
/// hybrid retriever, but real enough to demonstrate relevance ordering + the security filter.
pub struct LexicalRetriever {
    corpus: Corpus,
}

impl LexicalRetriever {
    pub fn new(corpus: Corpus) -> Self {
        LexicalRetriever { corpus }
    }
}

impl Retriever for LexicalRetriever {
    fn retrieve(&self, query: &str, clearance: DataClass, k: usize) -> Vec<Scored> {
        let terms = tokenize(query);
        let mut scored: Vec<Scored> = self
            .corpus
            .chunks
            .iter()
            // SECURITY FILTER — pre-rank: drop anything above the caller's clearance.
            .filter(|c| c.data_class.sensitivity() <= clearance.sensitivity())
            .filter_map(|c| {
                let doc = tokenize(&c.text);
                let score: f32 = terms
                    .iter()
                    .map(|t| doc.iter().filter(|w| *w == t).count() as f32)
                    .sum();
                if score > 0.0 {
                    Some(Scored {
                        chunk: c.clone(),
                        score,
                    })
                } else {
                    None
                }
            })
            .collect();
        scored.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        scored.truncate(k);
        scored
    }
}

/// Optional seam to turn a query string into a dense query vector for the hybrid retriever's
/// dense arm. A real deployment plugs in the embed service; when absent, [`HybridRetriever`]
/// runs lexical-only (still fused, so scores stay on the RRF scale).
pub trait QueryEmbedder: Send + Sync {
    fn embed(&self, query: &str) -> Option<Vec<f32>>;
}

/// The production hybrid retriever (`ainxt-retrieval`: BM25 + dense-cosine + RRF + rerank, with
/// pre-rank chunk-level ACL) adapted to the Context Fabric [`Retriever`] seam. This is the real
/// engine the design promises "implements the SAME `Retriever` trait" — swapping
/// [`LexicalRetriever`] for this in the live path is a one-line change, and every ACL/ranking
/// guarantee of `ainxt-retrieval` (an above-clearance chunk is never scored) carries over
/// unchanged because the clearance is mapped into an `ainxt_types::Principal` before retrieval.
pub struct HybridRetriever {
    corpus: ainxt_retrieval::Corpus,
    embedder: Option<Box<dyn QueryEmbedder>>,
    /// The reranker the fused candidates are re-scored by (`CONTEXT_FABRIC.md` §2 layer 11:
    /// pgvector + BM25 → RRF → **rerank**). `None` = the lexical fallback; a real deployment
    /// injects `ainxt_retrieval::SharedCrossEncoderReranker` over the `/rerank` cross-encoder.
    /// Previously the reranker was hardcoded at every call site, so the cross-encoder was
    /// structurally unreachable through the fabric.
    reranker: Option<Box<dyn ainxt_retrieval::Reranker>>,
    /// Source label per chunk id (the retrieval corpus is source-agnostic); falls back to the
    /// chunk id when unmapped.
    sources: std::collections::HashMap<String, String>,
    /// Optimizer metadata (`timestamp`, `authority`, `topic`) per chunk id that the retrieval engine
    /// does not carry. Re-attached onto the returned [`Chunk`] so the Context Optimizer's freshness
    /// preference AND its recency/authority conflict arbitration run on the LIVE hybrid path — not
    /// only over the [`LexicalRetriever`] (which keeps the whole chunk). A corpus built from a bare
    /// retrieval corpus has no such metadata (empty map, honest).
    meta: std::collections::HashMap<String, ChunkMeta>,
}

/// Optimizer-only metadata the retrieval engine does not carry, re-attached on the way out.
#[derive(Debug, Clone, Default)]
struct ChunkMeta {
    timestamp: Option<i64>,
    authority: Option<u8>,
    topic: Option<String>,
}

impl HybridRetriever {
    /// Build from a retrieval corpus (lexical-only dense arm off).
    pub fn new(corpus: ainxt_retrieval::Corpus) -> Self {
        HybridRetriever {
            corpus,
            embedder: None,
            reranker: None,
            sources: std::collections::HashMap::new(),
            meta: std::collections::HashMap::new(),
        }
    }

    /// Rebuild the Context-Fabric [`Chunk`] for a retrieval [`Candidate`], re-attaching the source
    /// label and the optimizer metadata (`timestamp`/`authority`/`topic`) the retrieval engine drops.
    /// The `acl`/`attributes` were already enforced pre-rank inside the engine, so they are not
    /// needed on the surfaced chunk.
    fn rebuild(&self, c: ainxt_retrieval::Candidate) -> Scored {
        let m = self.meta.get(&c.id).cloned().unwrap_or_default();
        Scored {
            chunk: Chunk {
                source: self.source_for(&c.id),
                id: c.id,
                text: c.text,
                data_class: c.data_class,
                timestamp: m.timestamp,
                acl: None,
                attributes: std::collections::BTreeMap::new(),
                authority: m.authority,
                topic: m.topic,
            },
            score: c.score as f32,
        }
    }

    /// Attach a query embedder to enable the dense arm.
    pub fn with_embedder(mut self, embedder: Box<dyn QueryEmbedder>) -> Self {
        self.embedder = Some(embedder);
        self
    }

    /// Attach the reranker the fused candidates are re-scored by — the injection point that makes
    /// the real cross-encoder (`ainxt_retrieval::SharedCrossEncoderReranker` over the `/rerank`
    /// service) reachable through the Context Fabric instead of the lexical fallback.
    pub fn with_reranker(mut self, reranker: Box<dyn ainxt_retrieval::Reranker>) -> Self {
        self.reranker = Some(reranker);
        self
    }

    /// Is a non-lexical reranker installed? (Used by the served composition root to report which
    /// retrieval arms are actually live, rather than assuming.)
    pub fn has_reranker(&self) -> bool {
        self.reranker.is_some()
    }

    /// Is the dense (vector) arm live?
    pub fn has_dense_arm(&self) -> bool {
        self.embedder.is_some()
    }

    /// The reranker to use for this retrieval: the injected one, else the lexical fallback.
    fn reranker(&self) -> &dyn ainxt_retrieval::Reranker {
        match &self.reranker {
            Some(r) => r.as_ref(),
            None => &ainxt_retrieval::LexicalReranker,
        }
    }

    /// Map a chunk id to a human-facing source label (used in citations/lineage).
    pub fn with_source(mut self, chunk_id: &str, source: &str) -> Self {
        self.sources
            .insert(chunk_id.to_string(), source.to_string());
        self
    }

    /// Build the production hybrid retriever **directly from a Context-Fabric [`Corpus`]** — the
    /// drop-in replacement for `LexicalRetriever::new(corpus)` on the live serving path. Each
    /// context chunk becomes a retrieval chunk (id + text + `data_class`), its `source` label is
    /// preserved for citations/lineage, and the retrieval crate's pre-rank chunk-level ACL applies
    /// unchanged (a chunk above the caller's clearance is never scored — existence never leaks).
    ///
    /// BM25 + RRF fusion + the [`ainxt_retrieval::LexicalReranker`] run immediately over whatever is
    /// populated; the dense arm stays dormant until [`HybridRetriever::with_embedder`] and per-chunk
    /// embeddings are attached (via [`HybridRetriever::from_retrieval_corpus`]), matching the design's
    /// "lexical-only is still fused, so scores stay on the RRF scale" contract.
    pub fn from_corpus(corpus: &Corpus) -> Self {
        let mut sources = std::collections::HashMap::new();
        let mut meta = std::collections::HashMap::new();
        let rchunks: Vec<ainxt_retrieval::Chunk> = corpus
            .chunks
            .iter()
            .map(|c| {
                sources.insert(c.id.clone(), c.source.clone());
                meta.insert(
                    c.id.clone(),
                    ChunkMeta {
                        timestamp: c.timestamp,
                        authority: c.authority,
                        topic: c.topic.clone(),
                    },
                );
                // Carry BOTH the Context-Fabric node ACL (department / seniority / groups) AND the
                // per-node row attributes onto the retrieval chunk so `compile_window` →
                // `hybrid_ctx_rls` enforces node-ACL + RLS row-filter pre-rank. Without this map the
                // served grounded path silently dropped every non-class RBAC axis and every row
                // attribute (any RLS policy then fail-closed to empty). Shared mapper, single source
                // of truth with `Corpus::to_retrieval_corpus`.
                context_chunk_to_retrieval(c)
            })
            .collect();
        HybridRetriever {
            corpus: ainxt_retrieval::Corpus::new(rchunks),
            embedder: None,
            reranker: None,
            sources,
            meta,
        }
    }

    /// Build from an already-indexed retrieval [`ainxt_retrieval::Corpus`] (carries embeddings for a
    /// live dense arm). Alias of [`HybridRetriever::new`] with an intent-revealing name for the
    /// dense-enabled path.
    pub fn from_retrieval_corpus(corpus: ainxt_retrieval::Corpus) -> Self {
        HybridRetriever::new(corpus)
    }

    fn source_for(&self, id: &str) -> String {
        self.sources
            .get(id)
            .cloned()
            .unwrap_or_else(|| id.to_string())
    }
}

/// The single ready entrypoint the live serving path calls in place of the lexical placeholder:
/// a boxed, production hybrid **RRF + rerank** [`Retriever`] over a populatable [`Corpus`]. This is
/// the drop-in for `Box::new(LexicalRetriever::new(corpus))` in the daemon's chat-surface assembly
/// (`ainxt-chat`/`ainxt-runtimed`). Populate the [`Corpus`] with the corpus-load API
/// ([`Corpus::load`]/[`Corpus::ingest`]/[`Corpus::extend`]) first; retrieval, pre-rank ACL,
/// citations, and lineage then all run on the real engine unchanged.
///
/// Wiring this into the reserved daemon crates is the remaining hot-crate change (see
/// `needs_hot_wiring`); every guarantee above is verified here on the real object.
pub fn hybrid_retriever(corpus: &Corpus) -> Box<dyn Retriever> {
    Box::new(HybridRetriever::from_corpus(corpus))
}

/// The **full layer-11 hybrid arm** (`CONTEXT_FABRIC.md` §2: pgvector HNSW + BM25 → RRF →
/// cross-encoder rerank) as one composition-root call: the same retriever as
/// [`hybrid_retriever`], plus the dense arm and the reranker actually injected.
///
/// `embedder`: the query-embedding seam (the embed service) — `None` leaves the dense arm dormant
/// and the retriever lexical-only, exactly as before. `reranker`: the rerank seam — pass
/// `Box::new(ainxt_retrieval::SharedCrossEncoderReranker::new(client))` to put the real
/// cross-encoder on the fabric's retrieval path; `None` keeps the lexical reranker.
///
/// Both are *retrieval read-filter/ordering* concerns: a dead embed/rerank service degrades the
/// ordering (fail-open), it never blocks a turn or drops a candidate.
pub fn hybrid_retriever_full(
    corpus: &Corpus,
    embedder: Option<Box<dyn QueryEmbedder>>,
    reranker: Option<Box<dyn ainxt_retrieval::Reranker>>,
) -> Box<dyn Retriever> {
    let mut r = HybridRetriever::from_corpus(corpus);
    if let Some(e) = embedder {
        r = r.with_embedder(e);
    }
    if let Some(rr) = reranker {
        r = r.with_reranker(rr);
    }
    Box::new(r)
}

impl Retriever for HybridRetriever {
    fn retrieve(&self, query: &str, clearance: DataClass, k: usize) -> Vec<Scored> {
        // Map the Context Fabric clearance onto a Principal so the retrieval crate applies its
        // identical pre-rank ACL (existence never leaks).
        let principal = ainxt_types::Principal::user("ctx-hybrid", &[]).with_clearance(clearance);
        let qvec = self.embedder.as_ref().and_then(|e| e.embed(query));
        let candidates = self
            .corpus
            .hybrid(query, qvec.as_deref(), &principal, k, self.reranker());
        candidates.into_iter().map(|c| self.rebuild(c)).collect()
    }

    /// Enforce the OBO principal's RLS row-filter on the real hybrid engine, pre-rank. Delegates to
    /// [`ainxt_retrieval::Corpus::hybrid_rls`], so the row-filter runs in the SAME pass as the
    /// class/node ACL — a row outside the caller's row scope is never scored, fused, reranked, or
    /// counted.
    fn retrieve_scoped(
        &self,
        query: &str,
        principal: &ainxt_types::Principal,
        filter: &ainxt_retrieval::rls::RowFilter,
        k: usize,
    ) -> Vec<Scored> {
        let qvec = self.embedder.as_ref().and_then(|e| e.embed(query));
        let candidates = self.corpus.hybrid_rls(
            query,
            qvec.as_deref(),
            principal,
            filter,
            k,
            self.reranker(),
        );
        candidates.into_iter().map(|c| self.rebuild(c)).collect()
    }

    /// Enforce the caller's full [`AccessContext`] node/edge RBAC (class + department + `ad_level` +
    /// groups) AND the RLS row-filter on the real hybrid engine, both pre-rank. Delegates to
    /// [`ainxt_retrieval::Corpus::hybrid_ctx_rls`], so a node the caller may not see by class,
    /// department, seniority, group, OR row scope is never scored, fused, reranked, or counted — its
    /// existence never leaks. This is the seam [`compile_window`] drives on the served path.
    fn retrieve_ctx(
        &self,
        query: &str,
        access: &AccessContext,
        filter: &RowFilter,
        k: usize,
    ) -> Vec<Scored> {
        let qvec = self.embedder.as_ref().and_then(|e| e.embed(query));
        let candidates =
            self.corpus
                .hybrid_ctx_rls(query, qvec.as_deref(), access, filter, k, self.reranker());
        candidates.into_iter().map(|c| self.rebuild(c)).collect()
    }
}

/// A citation into the assembled context. Carries the contributing chunk's `data_class` so a
/// downstream router/auditor knows the true sensitivity of the material a citation rests on,
/// and a `source` for display — the citation is the *user-facing* projection of the fuller
/// [`LineageNode`] audit record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Citation {
    pub marker: String,
    pub source: String,
    pub chunk_id: String,
    pub data_class: DataClass,
}

/// Why a retrieved node did or did not end up in the assembled window — every retrieved node is
/// accounted for, so nothing is *silently* dropped (`CONTEXT_FABRIC.md` §3, "a lineage record …
/// every included/excluded node is accounted for").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LineageOutcome {
    /// Included in the grounding context.
    Included,
    /// Retrieved and allowed, but dropped because it did not fit the token budget.
    DroppedByBudget,
    /// Retrieved and allowed, but **arbitrated out of a conflict**: another chunk in the same
    /// `topic` conflict-group was more authoritative (or, on an authority tie, fresher), so this
    /// contradicting statement was superseded rather than grounded alongside it
    /// (`CONTEXT_FABRIC.md` §3, "arbitrate conflicts by recency/authority"). Accounted in lineage —
    /// never silently kept next to the winning claim — so the arbitration is auditable + erasable.
    SupersededByConflict,
}

/// One node's full lineage entry: which chunk, from which source, at what data class, its
/// provenance label, and its fate. This is the audit/erasure record the Context Fabric requires
/// — it carries `data_class` + `provenance` (which the bare [`Citation`] omits) and is what the
/// right-to-erasure cascade consumes ([`Context::erasure_targets`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineageNode {
    pub chunk_id: String,
    pub source: String,
    pub data_class: DataClass,
    /// Where the chunk came from (retriever/provenance label), for audit.
    pub provenance: String,
    pub outcome: LineageOutcome,
}

/// Assembled context for one turn: the chunks that will ground the answer, their citations, and
/// a full lineage record (every retrieved node, included or dropped, with class + provenance)
/// for audit, citations, trust, and right-to-erasure.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Context {
    pub chunks: Vec<Chunk>,
    pub citations: Vec<Citation>,
    pub lineage: Vec<LineageNode>,
}

impl Context {
    pub fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }

    /// The chunk ids that actually grounded the answer (lineage outcome `Included`).
    pub fn contributed_chunk_ids(&self) -> Vec<&str> {
        self.lineage
            .iter()
            .filter(|n| n.outcome == LineageOutcome::Included)
            .map(|n| n.chunk_id.as_str())
            .collect()
    }

    /// Right-to-erasure cascade (`CONTEXT_FABRIC.md` §3, ADR-015): given the set of chunk ids
    /// being erased, return the lineage nodes in THIS assembled context that referenced them —
    /// so an erasure request can find, and purge, every place a to-be-erased source contributed.
    /// Includes budget-dropped nodes: a chunk that was retrieved (and thus read/logged) but not
    /// shown is still a place the data was touched.
    pub fn erasure_targets(&self, erased_chunk_ids: &BTreeSet<String>) -> Vec<&LineageNode> {
        self.lineage
            .iter()
            .filter(|n| erased_chunk_ids.contains(&n.chunk_id))
            .collect()
    }

    /// The highest data class among the nodes that actually grounded the answer — the true
    /// sensitivity the response rests on (`None` for empty context).
    pub fn max_included_data_class(&self) -> Option<DataClass> {
        self.lineage
            .iter()
            .filter(|n| n.outcome == LineageOutcome::Included)
            .map(|n| n.data_class)
            .max()
    }

    /// Build a grounded prompt: the cited context, then the question, then an instruction to
    /// answer only from the context and cite with the given markers.
    ///
    /// The retrieved context is **fenced as untrusted data** (instruction/data separation,
    /// ADR-009): RAG content is the classic *indirect* prompt-injection vector, so it is wrapped
    /// and labelled as information — never instructions — before the model sees it.
    pub fn to_prompt(&self, query: &str) -> String {
        if self.chunks.is_empty() {
            return query.to_string();
        }
        let mut body = String::from("Context:\n");
        for (c, cite) in self.chunks.iter().zip(self.citations.iter()) {
            body.push_str(&format!("{} {}: {}\n", cite.marker, c.source, c.text));
        }
        let fenced = ainxt_injection::wrap_untrusted(&body, ainxt_injection::Provenance::Retrieved);
        let first = self
            .citations
            .first()
            .map(|c| c.marker.as_str())
            .unwrap_or("[1]");
        format!(
            "Use ONLY the following context to answer, and cite sources with the given markers.\n\n\
             {fenced}\n\nQuestion: {query}\nAnswer (cite like {first}):"
        )
    }
}

/// Retrieve + assemble a grounded [`Context`] for `query`, filtered to `clearance`. Populates
/// the full lineage record (every retrieved node marked `Included`, with class + provenance).
pub fn assemble(query: &str, retriever: &dyn Retriever, clearance: DataClass, k: usize) -> Context {
    let scored = retriever.retrieve(query, clearance, k);
    build_context(scored, &[])
}

/// Retrieve, then fit the retrieved chunks to a token `budget` before grounding — recording the
/// nodes that were retrieved-and-allowed but dropped for budget as `DroppedByBudget` lineage
/// entries (accounted, never silently truncated). Reuses ainxt-retrieval's [`TokenCounter`] seam
/// so the same tokenizer discipline applies here as in the hybrid engine's budget fit.
pub fn assemble_with_budget(
    query: &str,
    retriever: &dyn Retriever,
    clearance: DataClass,
    k: usize,
    budget: usize,
    counter: &dyn ainxt_retrieval::TokenCounter,
) -> Context {
    let scored = retriever.retrieve(query, clearance, k);
    // Greedy fit in rank order; record which allowed-but-unfitted nodes were dropped.
    let mut used = 0usize;
    let mut kept = Vec::new();
    let mut dropped = Vec::new();
    for s in scored {
        let cost = counter.count(&s.chunk.text);
        if used + cost <= budget {
            used += cost;
            kept.push(s);
        } else {
            dropped.push(s);
        }
    }
    build_context(kept, &dropped)
}

/// Shared assembly: turn kept (and optionally budget-dropped) scored hits into a [`Context`]
/// with citations over the kept chunks and a lineage entry for every node (kept + dropped).
fn build_context(kept: Vec<Scored>, dropped: &[Scored]) -> Context {
    let mut chunks = Vec::with_capacity(kept.len());
    let mut citations = Vec::with_capacity(kept.len());
    let mut lineage = Vec::with_capacity(kept.len() + dropped.len());
    for (i, s) in kept.into_iter().enumerate() {
        citations.push(Citation {
            marker: format!("[{}]", i + 1),
            source: s.chunk.source.clone(),
            chunk_id: s.chunk.id.clone(),
            data_class: s.chunk.data_class,
        });
        lineage.push(LineageNode {
            chunk_id: s.chunk.id.clone(),
            source: s.chunk.source.clone(),
            data_class: s.chunk.data_class,
            provenance: format!("retrieved:{}", s.chunk.source),
            outcome: LineageOutcome::Included,
        });
        chunks.push(s.chunk);
    }
    for s in dropped {
        lineage.push(LineageNode {
            chunk_id: s.chunk.id.clone(),
            source: s.chunk.source.clone(),
            data_class: s.chunk.data_class,
            provenance: format!("retrieved:{}", s.chunk.source),
            outcome: LineageOutcome::DroppedByBudget,
        });
    }
    Context {
        chunks,
        citations,
        lineage,
    }
}

// ---------------------------------------------------------------------------------------
// The Context Optimizer — the "compiler: graphs → window" (CONTEXT_FABRIC.md §3)
// ---------------------------------------------------------------------------------------

use std::collections::BTreeMap;

use ainxt_retrieval::{Candidate, FittedContext, TokenCounter};
use optimizer::{personalized_pagerank, plan_query, QueryPlan, RankGraph};

/// Tuning for a [`compile`] pass. The eligible-model set is resolved by the Model Router from
/// task-type ∩ data-class *before* fitting (`CONTEXT_FABRIC.md` §3, Gap-22), so the window is
/// never wider than the narrowest model that might answer — including a failover target.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OptimizerConfig {
    /// How many candidates to retrieve before ranking/fitting.
    pub k: usize,
    /// `tier_eligible ∩ class_eligible` models with their real context windows; the fit targets
    /// the narrowest ([`ainxt_retrieval::eligible_floor_window`]).
    pub eligible: Vec<EligibleModel>,
    /// Prefer fresher sources when relevance is close (`CONTEXT_FABRIC.md` §3).
    pub prefer_fresh: bool,
    /// Bounded weight of the freshness bonus (added to the normalized relevance score).
    pub freshness_weight: f64,
    /// Weight of the cross-graph personalized-PageRank score fused into ranking (0 = ignore the
    /// graph, pure retrieval order).
    pub graph_weight: f64,
    /// PageRank damping + iteration count (deterministic; caller-fixed).
    pub damping: f64,
    pub iterations: usize,
}

impl Default for OptimizerConfig {
    fn default() -> Self {
        OptimizerConfig {
            k: 12,
            eligible: Vec::new(),
            prefer_fresh: true,
            freshness_weight: 0.25,
            graph_weight: 0.5,
            damping: 0.85,
            iterations: 50,
        }
    }
}

/// The optimizer's output for one turn: the query plan, the assembled + positioned [`Context`]
/// (with full lineage), the token-budget fit lineage, the target window, and the ranked candidate
/// list retained so a failover can re-fit without re-retrieving (`CONTEXT_FABRIC.md` §3, "re-fit on
/// model-confirm and on every failover").
#[derive(Debug, Clone)]
pub struct CompiledWindow {
    pub plan: QueryPlan,
    pub context: Context,
    pub fitted: FittedContext,
    pub window_tokens: usize,
    /// The reweighted, ranked candidates (post cross-graph + freshness fusion) — the input to any
    /// re-fit.
    pub ranked: Vec<Candidate>,
    /// id → assembled chunk, so a re-fit can rebuild the [`Context`] cheaply.
    chunk_by_id: BTreeMap<String, Chunk>,
}

impl CompiledWindow {
    /// Re-fit the SAME ranked candidates to a new model's window — used on model-confirm (a wider
    /// window admits more) and on failover (a narrower window must shrink again), always
    /// accounting every candidate and never exceeding the new cap (`CONTEXT_FABRIC.md` §3).
    pub fn refit_to(&self, model: &EligibleModel, counter: &dyn TokenCounter) -> CompiledWindow {
        let fitted = ainxt_retrieval::refit(&self.ranked, model.window_tokens, counter);
        let context = context_from_fit(&fitted, &self.chunk_by_id);
        CompiledWindow {
            plan: self.plan.clone(),
            context,
            window_tokens: model.window_tokens,
            fitted,
            ranked: self.ranked.clone(),
            chunk_by_id: self.chunk_by_id.clone(),
        }
    }

    /// The **verify** half of the compile/verify path (`STRUCTURED_FEDERATED_RETRIEVAL.md` §5, gap
    /// BH): run the numeric gate over the model's `answer` and its declared numeric `claims`. Never
    /// trust model arithmetic — every sourced number is *independently re-derived from source* via
    /// the [`Rederiver`] seam (a read-replica query / deterministic tool) and diffed against what
    /// the model stated; a stray number in prose with no sourced backing, a value the server cannot
    /// reproduce, or a value that differs beyond tolerance all **block** the answer from shipping.
    ///
    /// This lives on [`CompiledWindow`] so the SAME object that assembled and grounded the context
    /// also gates the answer's numbers — the verify step is part of the live compile path, not a
    /// detached utility. Blocking here forces regeneration of the *answer*; it is a correctness gate
    /// on model output, never a clearance/row-scope denial of the turn.
    pub fn verify_answer(
        &self,
        answer: &str,
        claims: &[NumericClaim],
        rederiver: &dyn Rederiver,
        tolerance: &Tolerance,
    ) -> VerifiedAnswer {
        VerifiedAnswer {
            gate: numeric_gate(answer, claims, rederiver, tolerance),
        }
    }

    /// The `from_engine_verified`-style DEFAULT the served surface uses for ledger-class answers
    /// (gap BH). Builds the [`LedgerAnswerGate`] (payments-safe policy + the default
    /// [`LEDGER_CLASS_FLOOR`]) over the SAME window that grounded the answer, and runs the full
    /// fail-closed verification — faithfulness + cross-source conflict + **server-side numeric
    /// re-derivation** — with the numeric gate armed as a HARD block *because the window's own
    /// sources are ledger-class*. The answer ships iff every stated figure re-derives from the
    /// server's own data via `rederiver`; a figure that differs from the server's recomputation is
    /// BLOCKED (`AnswerVerification::blocked_on_mismatch`). A window grounded on non-ledger sources
    /// leaves the numeric hard-block disarmed, so ordinary prose numbers never over-block.
    ///
    /// The window's assembled [`Chunk`]s are the grounding sources; `rederiver` is the server-side
    /// re-execution seam — [`SourceRederiver`] offline, or the live read-replica / sandbox executor
    /// in production. This lives on [`CompiledWindow`] so the object that grounded the context also
    /// verifies the answer's numbers against that same ledger-class material.
    ///
    /// GAP-AUDIT gap6-synthesis-teams-scheduler — reachability check: this method's only caller
    /// anywhere is `ainxt-context/tests/r7_ledger_rederivation.rs`; the live `/v1/chat` served path
    /// (`ainxt-convo`) calls `ainxt_synthesis::verify_answer_live_rederived` instead, never this. That
    /// is intentional, not an unwired gap: see the DECISION comment on
    /// `ainxt_synthesis::LedgerAnswerGate` for the full analysis — this method needs a typed
    /// `NumericClaim` contract the live prose path structurally does not have, and calling it with an
    /// empty contract would over-block (round-14 regression), not add protection.
    pub fn verify_ledger_answer(
        &self,
        answer: &str,
        claims: &[NumericClaim],
        rederiver: &dyn Rederiver,
    ) -> AnswerVerification {
        let sources: Vec<Source> = self
            .context
            .chunks
            .iter()
            .map(|c| Source::new(&c.id, &c.text, c.data_class))
            .collect();
        LedgerAnswerGate::from_engine_verified(rederiver).verify(&sources, answer, claims)
    }
}

/// The outcome of running the numeric re-derivation gate over an answer on the compile/verify path
/// ([`CompiledWindow::verify_answer`]). Wraps the [`NumericGateOutcome`] with intent-revealing
/// ship/block accessors for the calling surface.
#[derive(Debug, Clone)]
pub struct VerifiedAnswer {
    /// The full contract-lint + server-side re-derivation report.
    pub gate: NumericGateOutcome,
}

impl VerifiedAnswer {
    /// True iff the answer cleared BOTH the numeric-claim contract lint and server-side
    /// re-derivation — the only state in which the answer's numbers may ship.
    pub fn ships(&self) -> bool {
        self.gate.ships()
    }

    /// True iff at least one claim's server-recomputed value differed from what the model stated —
    /// the payment-incident signal the gate exists to catch (fed to the eval/incident platform).
    pub fn blocked_on_mismatch(&self) -> bool {
        self.gate.rederivation.has_mismatch()
    }
}

/// The **ONE Event-Log-ready record** for a served turn (round-15 `context-fabric` gap:
/// "lineage/epsilon/re-derivation-hash written to the one Event Log tagged with the control-plane
/// commit SHA"). Before this, three facts each real and each tested lived in three different
/// crates with no single payload joining them for an auditor: this window's own [`LineageNode`]
/// trail (which nodes grounded / were dropped / superseded), the numeric re-derivation gate's
/// `rederive_key` hashes (verified + failed), and — when the turn queried a federated cross-bank
/// signal — the privacy epsilon it spent. Tagging the whole record with the live
/// `control_plane_sha` answers the auditor's actual question: "which definitions (metric catalog /
/// RLS policy / federation whitelist) produced this turn's numbers, and how much privacy budget did
/// it cost." Pure/serializable — the actual `EventLog::append` call is the composition-root's job
/// (a served-path call site in a reserved hot crate); this is the clean payload that call makes
/// with (**`needs_hot_wiring`**: `ainxt_eventlog`/`ainxt_runtimed` owns the actual append).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TurnEventRecord {
    /// The control-plane commit SHA live when this turn's numbers were produced.
    pub control_plane_sha: String,
    /// Every retrieved node's fate for this turn (included / dropped-by-budget / superseded).
    pub lineage: Vec<LineageNode>,
    /// The numeric re-derivation report: verified claims (carrying their `rederive_key` hash) and
    /// any failures (unsourced / not-reproducible / mismatch).
    pub rederivation: RederivationReport,
    /// The privacy epsilon this turn spent against a federated cross-bank query's budget, if it
    /// queried one (`ainxt_retrieval::federation::EpsilonLedger::spent`). `None` — never `0.0` — when
    /// the turn never federated, so "spent nothing" and "did not federate" are never confused.
    pub federated_epsilon_spent: Option<f64>,
}

impl VerifiedAnswer {
    /// Build the one Event-Log record for this verified turn, tagged with the live control-plane
    /// SHA — the clean entrypoint a composition root calls right before `EventLog::append`.
    pub fn to_event_record(
        &self,
        lineage: Vec<LineageNode>,
        control_plane_sha: &str,
        federated_epsilon_spent: Option<f64>,
    ) -> TurnEventRecord {
        TurnEventRecord {
            control_plane_sha: control_plane_sha.to_string(),
            lineage,
            rederivation: self.gate.rederivation.clone(),
            federated_epsilon_spent,
        }
    }
}

/// Normalize a slice of scores to `[0, 1]` by the max (all-zero / empty → all zeros).
fn normalize(scores: &[f64]) -> Vec<f64> {
    let max = scores.iter().cloned().fold(0.0f64, f64::max);
    if max <= 0.0 {
        return vec![0.0; scores.len()];
    }
    scores.iter().map(|s| s / max).collect()
}

/// Build a [`Context`] from a budget fit + the id→chunk map: citations over the included
/// (positioned) chunks and a lineage entry for every candidate (included or budget-dropped).
/// Conflict arbitration by **authority then recency** (`CONTEXT_FABRIC.md` §3). Given the retrieved
/// candidates and their fused-rank order, return the set of chunk ids that lose a conflict: for each
/// `topic` conflict-group with more than one member, the winner is the chunk with the highest
/// `authority` (unranked = 0), then the freshest `timestamp` (undated = `i64::MIN`), then the best
/// fused rank (earliest in `fused`), then the smallest id — fully deterministic. Every other member
/// of the group is superseded. Chunks with no `topic` never conflict.
fn arbitrate_conflicts(scored: &[Scored], fused: &[(usize, f64)]) -> BTreeSet<String> {
    // Fused-rank position per scored index (lower = more relevant), for the final tiebreak.
    let mut rank_of: BTreeMap<usize, usize> = BTreeMap::new();
    for (pos, (i, _)) in fused.iter().enumerate() {
        rank_of.insert(*i, pos);
    }
    // Group candidate indices by conflict topic.
    let mut groups: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (i, s) in scored.iter().enumerate() {
        if let Some(topic) = &s.chunk.topic {
            if !topic.is_empty() {
                groups.entry(topic.clone()).or_default().push(i);
            }
        }
    }
    let mut superseded = BTreeSet::new();
    for (_topic, members) in groups {
        if members.len() < 2 {
            continue; // a lone claim is not a conflict.
        }
        // Winner: max authority, then freshest, then best (smallest) fused rank, then smallest id.
        let winner = members
            .iter()
            .copied()
            .max_by(|&a, &b| {
                let ca = &scored[a].chunk;
                let cb = &scored[b].chunk;
                ca.authority
                    .unwrap_or(0)
                    .cmp(&cb.authority.unwrap_or(0))
                    .then(
                        ca.timestamp
                            .unwrap_or(i64::MIN)
                            .cmp(&cb.timestamp.unwrap_or(i64::MIN)),
                    )
                    // Better fused rank (smaller position) should win → reverse the cmp so it is "greater".
                    .then(
                        rank_of
                            .get(&b)
                            .copied()
                            .unwrap_or(usize::MAX)
                            .cmp(&rank_of.get(&a).copied().unwrap_or(usize::MAX)),
                    )
                    // Smaller id wins → reverse so it ranks as "greater" in max_by.
                    .then(cb.id.cmp(&ca.id))
            })
            .expect("non-empty group");
        for m in members {
            if m != winner {
                superseded.insert(scored[m].chunk.id.clone());
            }
        }
    }
    superseded
}

/// [`context_from_fit`] plus the conflict-arbitration lineage: every chunk arbitrated out of a
/// conflict is recorded as `SupersededByConflict` (accounted, never silently kept alongside the
/// winning claim, never shown). Superseded ids are excluded from `fitted` upstream, so they can only
/// appear here as lineage — never as a citation or grounded chunk.
fn context_from_fit_with_conflicts(
    fitted: &FittedContext,
    chunk_by_id: &BTreeMap<String, Chunk>,
    superseded: &BTreeSet<String>,
) -> Context {
    let mut context = context_from_fit(fitted, chunk_by_id);
    for id in superseded {
        if let Some(chunk) = chunk_by_id.get(id) {
            context.lineage.push(LineageNode {
                chunk_id: chunk.id.clone(),
                source: chunk.source.clone(),
                data_class: chunk.data_class,
                provenance: format!("conflict-superseded:{}", chunk.source),
                outcome: LineageOutcome::SupersededByConflict,
            });
        }
    }
    context
}

fn context_from_fit(fitted: &FittedContext, chunk_by_id: &BTreeMap<String, Chunk>) -> Context {
    let mut chunks = Vec::new();
    let mut citations = Vec::new();
    let mut lineage = Vec::new();
    // Included, in the position-aware order the fit produced.
    for (i, c) in fitted.included.iter().enumerate() {
        if let Some(chunk) = chunk_by_id.get(&c.id) {
            citations.push(Citation {
                marker: format!("[{}]", i + 1),
                source: chunk.source.clone(),
                chunk_id: chunk.id.clone(),
                data_class: chunk.data_class,
            });
            lineage.push(LineageNode {
                chunk_id: chunk.id.clone(),
                source: chunk.source.clone(),
                data_class: chunk.data_class,
                provenance: format!("optimized:{}", chunk.source),
                outcome: LineageOutcome::Included,
            });
            chunks.push(chunk.clone());
        }
    }
    // Budget-dropped candidates → accounted lineage (retrieved/allowed but not shown).
    for d in fitted.dropped_ids() {
        if let Some(chunk) = chunk_by_id.get(d) {
            lineage.push(LineageNode {
                chunk_id: chunk.id.clone(),
                source: chunk.source.clone(),
                data_class: chunk.data_class,
                provenance: format!("optimized:{}", chunk.source),
                outcome: LineageOutcome::DroppedByBudget,
            });
        }
    }
    Context {
        chunks,
        citations,
        lineage,
    }
}

/// The Context Optimizer's compile step (`CONTEXT_FABRIC.md` §3): plan the query → retrieve through
/// the [`Retriever`] seam (the production [`HybridRetriever`] plugs straight in) → **fuse a
/// cross-graph personalized-PageRank score** so nodes reachable from the query's in-scope entities
/// outrank equally-lexical but unrelated ones → **prefer fresh sources** → **fit to the narrowest
/// eligible model window** with **position-aware assembly** (most-relevant at the edges,
/// lost-in-the-middle mitigation) → emit the window + full lineage.
///
/// This is the composition the design promised and the audit flagged as missing: `plan_query` and
/// `personalized_pagerank` are now *used* on the assembly path, and the eligible-floor budget fit
/// and position-aware arrangement run on the live `assemble`-class entrypoint rather than only in
/// unit tests. Pass `graph = None` to skip cross-graph ranking (pure retrieval order).
#[allow(clippy::too_many_arguments)]
pub fn compile(
    query: &str,
    retriever: &dyn Retriever,
    clearance: DataClass,
    cfg: &OptimizerConfig,
    counter: &dyn TokenCounter,
    graph: Option<&RankGraph>,
    seeds: &BTreeMap<String, f64>,
) -> CompiledWindow {
    let scored = retriever.retrieve(query, clearance, cfg.k);
    compile_ranked(query, scored, cfg, counter, graph, seeds)
}

/// The **RLS-scoped** compile path (`CONTEXT_FABRIC.md` §3 + §8.3): identical optimizer composition
/// (plan → cross-graph rank → freshness → eligible-floor position-aware fit, with full lineage) as
/// [`compile`], but retrieval runs through [`Retriever::retrieve_scoped`] so the OBO `principal`'s
/// **row-level-security row-filter** shapes the candidate set *pre-rank*. A row outside the caller's
/// row scope is therefore never ranked, positioned, fitted, cited, or recorded in the window's
/// lineage — its existence never leaks. This is the entrypoint the chat/convo surface calls when it
/// has resolved the OBO principal + row-filter for the turn.
///
/// RLS here is a retrieval read-filter, never a turn-admission decision.
#[allow(clippy::too_many_arguments)]
pub fn compile_rls(
    query: &str,
    retriever: &dyn Retriever,
    principal: &ainxt_types::Principal,
    filter: &ainxt_retrieval::rls::RowFilter,
    cfg: &OptimizerConfig,
    counter: &dyn TokenCounter,
    graph: Option<&RankGraph>,
    seeds: &BTreeMap<String, f64>,
) -> CompiledWindow {
    let scored = retriever.retrieve_scoped(query, principal, filter, cfg.k);
    compile_ranked(query, scored, cfg, counter, graph, seeds)
}

/// The turn's full access + policy inputs for [`compile_window`], gathered into one value so the
/// single served entrypoint carries EVERYTHING the Context Fabric composes for a turn:
///
/// - **`access`** — the caller's complete OBO [`AccessContext`]: class clearance **and** the
///   orthogonal node/edge RBAC axes (department, `ad_level` seniority, allow/deny groups). Enforced
///   pre-rank, so a node the caller may not see on ANY axis never enters the window.
/// - **`row_filter`** — the RLS [`RowFilter`] (SET LOCAL-style, bound from the OBO principal),
///   applied in the SAME pre-rank pass. `None` = no row policy (reduces to node-RBAC-only).
/// - **`graph` + `seeds`** — the cross-graph [`RankGraph`] and the query's in-scope seed entities
///   for the personalized-PageRank fuse. `graph = None` = pure retrieval order.
///
/// Everything else (the eligible-model set for the two-phase budget fit, freshness/graph weights,
/// `k`) lives in [`OptimizerConfig`]. The numeric re-derivation gate is applied *after* generation
/// via [`CompiledWindow::verify_answer`] on the returned window — so ONE object carries assembly,
/// grounding, and the "never trust model arithmetic" gate.
pub struct CompileRequest<'a> {
    /// The caller's full OBO access claims — class + department + `ad_level` + groups.
    pub access: &'a AccessContext,
    /// The RLS row-filter for the turn, if any (bound from the OBO principal).
    pub row_filter: Option<&'a RowFilter>,
    /// The cross-graph adjacency for personalized PageRank, if any.
    pub graph: Option<&'a RankGraph>,
    /// The query's in-scope seed entities for the personalized teleport.
    pub seeds: &'a BTreeMap<String, f64>,
}

/// The **single** Context-Fabric compile entrypoint the served path (chat/convo → runtimed) calls:
/// ONE call that carries ALL of the fabric's per-turn concerns end to end
/// (`CONTEXT_FABRIC.md` §3, §8.3):
///
/// 1. **Pre-rank node/department/`ad_level`/group RBAC** — via [`Retriever::retrieve_ctx`] driven by
///    the request's full [`AccessContext`], not just the data-class scalar (the served gap: the old
///    synthetic `Principal::user("ctx-hybrid", &[])` dropped department/seniority/groups).
/// 2. **RLS row-filter** — the request's [`RowFilter`] applied in the SAME pre-rank pass, so a row
///    outside the caller's row scope is never scored (existence never leaks). Absent → open.
/// 3. **Cross-graph personalized PageRank** — fused into ranking from `graph` + `seeds`.
/// 4. **Freshness preference** + **position-aware assembly** (lost-in-the-middle mitigation).
/// 5. **Two-phase budget fit against the eligible-model set** — [`ainxt_retrieval::budget_fit_eligible`]
///    to the narrowest eligible window ([`OptimizerConfig::eligible`], resolved by the Model Router
///    from task-type ∩ data-class), re-fittable on model-confirm/failover via
///    [`CompiledWindow::refit_to`].
///
/// The returned [`CompiledWindow`] then gates the model's numbers via
/// [`CompiledWindow::verify_answer`] (the numeric-claim contract + server-side re-derivation, gap
/// BH) — so this one object spans plan → RBAC/RLS retrieval → cross-graph rank → eligible-floor fit
/// → numeric gate. Wiring this into the reserved daemon crates is the remaining hot-crate change
/// (`needs_hot_wiring: ainxt_context::compile_window`); every guarantee above is a crate-level fact
/// verified here on the real objects.
///
/// This is a retrieval read-filter path, never a turn-admission decision: an empty eligible set or a
/// fully-filtered corpus yields an empty grounded window, never a denied turn.
pub fn compile_window(
    query: &str,
    retriever: &dyn Retriever,
    cfg: &OptimizerConfig,
    counter: &dyn TokenCounter,
    req: &CompileRequest<'_>,
) -> CompiledWindow {
    let empty = RowFilter::new(RlsSession::new());
    let filter = req.row_filter.unwrap_or(&empty);
    let scored = retriever.retrieve_ctx(query, req.access, filter, cfg.k);
    compile_ranked(query, scored, cfg, counter, req.graph, req.seeds)
}

/// The shared optimizer composition over an already-retrieved candidate set: plan the query →
/// fuse a cross-graph personalized-PageRank score → prefer fresh → fit to the narrowest eligible
/// window position-aware → emit window + full lineage. Both [`compile`] and [`compile_rls`] route
/// through here so the ONLY difference between them is the pre-rank retrieval scope.
fn compile_ranked(
    query: &str,
    scored: Vec<Scored>,
    cfg: &OptimizerConfig,
    counter: &dyn TokenCounter,
    graph: Option<&RankGraph>,
    seeds: &BTreeMap<String, f64>,
) -> CompiledWindow {
    let plan = plan_query(query);

    // Cross-graph personalized PageRank (CONTEXT_FABRIC.md §3), if a graph is supplied.
    let pr: BTreeMap<String, f64> = match graph {
        Some(g) => personalized_pagerank(g, seeds, cfg.damping, cfg.iterations),
        None => BTreeMap::new(),
    };

    // Fuse: normalized retrieval score + graph_weight·normalized PageRank + freshness bonus.
    let base: Vec<f64> = scored.iter().map(|s| s.score as f64).collect();
    let base_n = normalize(&base);
    let pr_vals: Vec<f64> = scored
        .iter()
        .map(|s| pr.get(&s.chunk.id).copied().unwrap_or(0.0))
        .collect();
    let pr_n = normalize(&pr_vals);
    let ts_vals: Vec<f64> = scored
        .iter()
        .map(|s| s.chunk.timestamp.map(|t| t as f64).unwrap_or(0.0))
        .collect();
    let ts_n = normalize(&ts_vals);

    let mut fused: Vec<(usize, f64)> = scored
        .iter()
        .enumerate()
        .map(|(i, _)| {
            let mut score = base_n[i] + cfg.graph_weight * pr_n[i];
            if cfg.prefer_fresh {
                score += cfg.freshness_weight * ts_n[i];
            }
            (i, score)
        })
        .collect();
    // Deterministic: score desc, then original retrieval order (stable), then id.
    fused.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.0.cmp(&b.0))
    });

    // Conflict arbitration by authority/recency (CONTEXT_FABRIC.md §3): among candidates that claim
    // the SAME `topic` (a conflict-group of competing statements of one fact), keep only the winner —
    // highest authority, then freshest, then best fused rank / smallest id — and account the losers
    // as `SupersededByConflict` rather than grounding a contradiction alongside the winning claim.
    let superseded = arbitrate_conflicts(&scored, &fused);

    // Build the ranked candidate list + id→chunk map in the fused order, skipping superseded chunks.
    let mut ranked = Vec::with_capacity(fused.len());
    let mut chunk_by_id = BTreeMap::new();
    for (i, s) in &fused {
        let chunk = &scored[*i].chunk;
        // Every retrieved chunk enters the id→chunk map so the lineage can reference a superseded one.
        chunk_by_id.insert(chunk.id.clone(), chunk.clone());
        if superseded.contains(&chunk.id) {
            continue;
        }
        ranked.push(Candidate {
            id: chunk.id.clone(),
            text: chunk.text.clone(),
            data_class: chunk.data_class,
            score: *s,
        });
    }

    // Phase-1 fit to the narrowest eligible window, position-aware (lost-in-the-middle).
    let fitted = ainxt_retrieval::budget_fit_eligible(&ranked, &cfg.eligible, counter);
    let window_tokens = ainxt_retrieval::eligible_floor_window(&cfg.eligible).unwrap_or(0);
    let context = context_from_fit_with_conflicts(&fitted, &chunk_by_id, &superseded);

    CompiledWindow {
        plan,
        context,
        fitted,
        window_tokens,
        ranked,
        chunk_by_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn corpus() -> Corpus {
        Corpus::new()
            .with(Chunk::new(
                "c1",
                "upi.md",
                "UPI enables instant bank transfer",
                DataClass::Public,
            ))
            .with(Chunk::new(
                "c2",
                "neft.md",
                "NEFT settles bank transfer in batches",
                DataClass::Public,
            ))
            .with(Chunk::new(
                "c3",
                "margins.md",
                "confidential settlement margin transfer",
                DataClass::Confidential,
            ))
    }

    #[test]
    fn assemble_records_full_lineage_with_class_and_provenance() {
        let r = LexicalRetriever::new(corpus());
        let ctx = assemble("bank transfer", &r, DataClass::Public, 5);
        assert!(!ctx.is_empty());
        // Every included chunk has a lineage node with the correct class + provenance.
        for n in &ctx.lineage {
            assert_eq!(n.outcome, LineageOutcome::Included);
            assert_eq!(n.data_class, DataClass::Public);
            assert!(n.provenance.starts_with("retrieved:"));
        }
        // Citations carry data_class now.
        assert!(ctx
            .citations
            .iter()
            .all(|c| c.data_class == DataClass::Public));
        assert_eq!(ctx.max_included_data_class(), Some(DataClass::Public));
    }

    #[test]
    fn budget_assemble_accounts_dropped_nodes_in_lineage() {
        let r = LexicalRetriever::new(corpus());
        // Both c1 and c2 match "bank transfer"; a tiny budget fits only the top one.
        let counter = ainxt_retrieval::WordTokenCounter;
        let ctx = assemble_with_budget("bank transfer", &r, DataClass::Public, 5, 5, &counter);
        let included: Vec<_> = ctx
            .lineage
            .iter()
            .filter(|n| n.outcome == LineageOutcome::Included)
            .collect();
        let dropped: Vec<_> = ctx
            .lineage
            .iter()
            .filter(|n| n.outcome == LineageOutcome::DroppedByBudget)
            .collect();
        assert!(!included.is_empty(), "at least one chunk should fit");
        assert!(
            !dropped.is_empty(),
            "the budget should force at least one accounted drop"
        );
        // A dropped node is NOT cited (not shown) but IS in the lineage (was retrieved).
        for d in &dropped {
            assert!(ctx.citations.iter().all(|c| c.chunk_id != d.chunk_id));
        }
    }

    #[test]
    fn erasure_targets_finds_contributing_and_dropped_nodes() {
        let r = LexicalRetriever::new(corpus());
        let counter = ainxt_retrieval::WordTokenCounter;
        let ctx = assemble_with_budget("bank transfer", &r, DataClass::Public, 5, 5, &counter);
        // Erase c2 — even if it was budget-dropped, it was retrieved/logged, so it's a target.
        let mut erase = BTreeSet::new();
        erase.insert("c2".to_string());
        let targets = ctx.erasure_targets(&erase);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].chunk_id, "c2");
        // A chunk that never entered this context yields no erasure target here.
        let mut none = BTreeSet::new();
        none.insert("does-not-exist".to_string());
        assert!(ctx.erasure_targets(&none).is_empty());
    }

    #[test]
    fn context_serializes_for_the_event_log() {
        let r = LexicalRetriever::new(corpus());
        let ctx = assemble("bank transfer", &r, DataClass::Public, 5);
        let json = serde_json::to_string(&ctx).expect("serialize");
        assert!(json.contains("\"outcome\":\"included\""));
        let back: Context = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, ctx);
    }

    // --- hybrid adapter ------------------------------------------------------------

    #[test]
    fn hybrid_adapter_retrieves_through_context_seam_and_enforces_acl() {
        use ainxt_retrieval::Chunk as RChunk;
        let rcorpus = ainxt_retrieval::Corpus::new(vec![
            RChunk::new(
                "pub",
                "UPI instant bank transfer settlement",
                DataClass::Public,
            ),
            RChunk::new(
                "reg",
                "PAN card full settlement transfer",
                DataClass::RegulatedPayment,
            ),
        ]);
        let hybrid = HybridRetriever::new(rcorpus).with_source("pub", "upi.md");
        // A Public-cleared caller queries text that also matches the regulated chunk.
        let hits = hybrid.retrieve("settlement transfer", DataClass::Public, 10);
        assert!(!hits.is_empty());
        assert!(
            hits.iter().all(|h| h.chunk.data_class == DataClass::Public),
            "the regulated chunk must never surface for a Public caller (pre-rank ACL)"
        );
        // Source mapping is applied; the adapter is usable as a drop-in Retriever.
        assert!(hits
            .iter()
            .any(|h| h.chunk.id == "pub" && h.chunk.source == "upi.md"));

        // A cleared caller CAN see the regulated chunk — proving the ACL is clearance-driven,
        // not a blanket filter.
        let cleared = hybrid.retrieve("settlement transfer", DataClass::RegulatedPayment, 10);
        assert!(cleared.iter().any(|h| h.chunk.id == "reg"));
    }

    #[test]
    fn hybrid_adapter_uses_dense_arm_when_embedder_present() {
        use ainxt_retrieval::Chunk as RChunk;
        // "densewin" only wins via the vector; its text does not match the query lexically.
        let rcorpus = ainxt_retrieval::Corpus::new(vec![
            RChunk::new("lexwin", "unique keyword settlement", DataClass::Public)
                .with_embedding(vec![0.0, 1.0]),
            RChunk::new("densewin", "unrelated prose", DataClass::Public)
                .with_embedding(vec![1.0, 0.0]),
        ]);

        struct FixedEmbedder;
        impl QueryEmbedder for FixedEmbedder {
            fn embed(&self, _q: &str) -> Option<Vec<f32>> {
                Some(vec![1.0, 0.0]) // points at densewin
            }
        }
        let hybrid = HybridRetriever::new(rcorpus).with_embedder(Box::new(FixedEmbedder));
        let hits = hybrid.retrieve("unique keyword", DataClass::Public, 10);
        let ids: Vec<&str> = hits.iter().map(|h| h.chunk.id.as_str()).collect();
        assert!(ids.contains(&"lexwin"), "lexical match surfaces");
        assert!(
            ids.contains(&"densewin"),
            "dense arm surfaces the vector-nearest chunk"
        );
    }

    // --- Context Optimizer composition (CTX-01/02/03/11) ---------------------------

    fn seeds(pairs: &[(&str, f64)]) -> BTreeMap<String, f64> {
        pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    #[test]
    fn gap_ctx_01_optimizer_composes_plan_and_cross_graph_pagerank_into_assembly() {
        // Two equally-relevant chunks; only the graph (reachable from the seed) separates them.
        // Would FAIL before: plan_query/personalized_pagerank were never referenced by assembly.
        let corpus = Corpus::new()
            .with(Chunk::new(
                "c1",
                "a.md",
                "settlement failure",
                DataClass::Public,
            ))
            .with(Chunk::new(
                "c2",
                "b.md",
                "settlement failure",
                DataClass::Public,
            ));
        let r = LexicalRetriever::new(corpus);
        let counter = ainxt_retrieval::WordTokenCounter;
        let cfg = OptimizerConfig {
            eligible: vec![EligibleModel::new("m", 8000)],
            prefer_fresh: false,
            ..OptimizerConfig::default()
        };

        // No graph → tie broken by retrieval order (c1 inserted first).
        let no_graph = compile(
            "settlement failure",
            &r,
            DataClass::Public,
            &cfg,
            &counter,
            None,
            &BTreeMap::new(),
        );
        assert!(
            no_graph.plan.includes(optimizer::GraphLayer::Conversation),
            "plan is computed"
        );
        assert_eq!(no_graph.ranked[0].id, "c1");

        // Seed personalized PageRank on c2 → the cross-graph score floats c2 to the top.
        let graph = RankGraph::new().with_node("c1").with_node("c2");
        let compiled = compile(
            "settlement failure",
            &r,
            DataClass::Public,
            &cfg,
            &counter,
            Some(&graph),
            &seeds(&[("c2", 1.0)]),
        );
        assert_eq!(
            compiled.ranked[0].id, "c2",
            "cross-graph PageRank must reorder toward the seed"
        );
    }

    #[test]
    fn gap_ctx_02_optimizer_drives_the_real_hybrid_engine_and_enforces_acl() {
        use ainxt_retrieval::Chunk as RChunk;
        // CTX-02: the production hybrid retriever is the live engine behind `compile` (not the
        // lexical placeholder), and its pre-rank ACL carries through.
        let rcorpus = ainxt_retrieval::Corpus::new(vec![
            RChunk::new("pub", "UPI settlement transfer", DataClass::Public),
            RChunk::new(
                "reg",
                "PAN full card settlement transfer",
                DataClass::RegulatedPayment,
            ),
        ]);
        let hybrid = HybridRetriever::new(rcorpus).with_source("pub", "upi.md");
        let counter = ainxt_retrieval::WordTokenCounter;
        let cfg = OptimizerConfig {
            eligible: vec![EligibleModel::new("m", 8000)],
            graph_weight: 0.0,
            ..OptimizerConfig::default()
        };
        let compiled = compile(
            "settlement transfer",
            &hybrid,
            DataClass::Public,
            &cfg,
            &counter,
            None,
            &BTreeMap::new(),
        );
        assert!(
            !compiled.context.is_empty(),
            "the hybrid engine produced grounded context"
        );
        assert!(
            compiled
                .context
                .chunks
                .iter()
                .all(|c| c.data_class == DataClass::Public),
            "the regulated chunk must never enter the window for a Public caller"
        );
    }

    #[test]
    fn gap_ctx_11_optimizer_prefers_fresh_and_positions_for_attention() {
        // Two identical-relevance chunks; freshness must decide, and the winner sits at the edge.
        let corpus = Corpus::new()
            .with(
                Chunk::new("old", "a.md", "settlement report", DataClass::Public).with_timestamp(1),
            )
            .with(
                Chunk::new("new", "b.md", "settlement report", DataClass::Public)
                    .with_timestamp(100),
            );
        let r = LexicalRetriever::new(corpus);
        let counter = ainxt_retrieval::WordTokenCounter;
        let base = OptimizerConfig {
            eligible: vec![EligibleModel::new("m", 8000)],
            graph_weight: 0.0,
            ..OptimizerConfig::default()
        };

        // prefer_fresh off → tie broken by retrieval order (old inserted first).
        let stale = OptimizerConfig {
            prefer_fresh: false,
            ..base.clone()
        };
        let a = compile(
            "settlement report",
            &r,
            DataClass::Public,
            &stale,
            &counter,
            None,
            &BTreeMap::new(),
        );
        assert_eq!(a.ranked[0].id, "old");

        // prefer_fresh on → the fresher source wins the tie and sits at the front window edge.
        let b = compile(
            "settlement report",
            &r,
            DataClass::Public,
            &base,
            &counter,
            None,
            &BTreeMap::new(),
        );
        assert_eq!(
            b.ranked[0].id, "new",
            "fresher source preferred on a relevance tie"
        );
        assert_eq!(
            b.context.chunks.first().unwrap().id,
            "new",
            "most relevant sits at the edge"
        );
    }

    #[test]
    fn gap_ctx_03_optimizer_fits_eligible_floor_and_refits_on_failover() {
        // Five ~2-token chunks; the eligible floor is a narrow window, and a failover is narrower.
        let mut corpus = Corpus::new();
        for i in 0..5 {
            corpus = corpus.with(Chunk::new(
                &format!("c{i}"),
                "s.md",
                "settlement report",
                DataClass::Public,
            ));
        }
        let r = LexicalRetriever::new(corpus);
        let counter = ainxt_retrieval::WordTokenCounter; // 2 tokens per chunk
        let cfg = OptimizerConfig {
            // Floor = 5 tokens: fits 2 chunks (2+2=4), the 3rd (→6) overflows.
            eligible: vec![
                EligibleModel::new("wide", 8000),
                EligibleModel::new("narrow", 5),
            ],
            prefer_fresh: false,
            graph_weight: 0.0,
            ..OptimizerConfig::default()
        };
        let compiled = compile(
            "settlement report",
            &r,
            DataClass::Public,
            &cfg,
            &counter,
            None,
            &BTreeMap::new(),
        );
        assert_eq!(
            compiled.window_tokens, 5,
            "fit to the narrowest eligible window"
        );
        assert!(compiled.fitted.used_tokens <= 5);
        assert!(
            compiled.fitted.fully_accounted(5),
            "every candidate accounted, none silently dropped"
        );
        assert!(
            !compiled.fitted.dropped_ids().is_empty(),
            "the narrow floor forces accounted drops"
        );

        // Model-confirm a WIDER window → re-fit admits everything.
        let confirmed = compiled.refit_to(&EligibleModel::new("wide", 8000), &counter);
        assert!(
            confirmed.fitted.dropped_ids().is_empty(),
            "the wide window fits all five"
        );
        assert!(confirmed.fitted.fully_accounted(5));

        // Failover to a NARROWER window than the floor → shrink again, still fully accounted.
        let failover = confirmed.refit_to(&EligibleModel::new("tiny", 2), &counter);
        assert!(failover.fitted.used_tokens <= 2);
        assert!(failover.fitted.fully_accounted(5));
        assert!(failover.context.chunks.len() <= 1);
    }

    struct FixedRederiver(BTreeMap<String, f64>);
    impl Rederiver for FixedRederiver {
        fn rederive(&self, source: &ClaimSource) -> Option<f64> {
            self.0.get(&source.rederive_key()?).copied()
        }
    }

    #[test]
    fn r15_verified_answer_builds_one_tagged_event_record_with_lineage_and_epsilon() {
        // A claim that re-derives cleanly (verified → carries its `rederive_key` hash) plus one that
        // mismatches (the incident-adjacent signal) — proving the built record carries BOTH, not
        // just the happy path.
        let claims = vec![
            NumericClaim::metric(
                42.0,
                "count",
                ValueClass::Exact,
                "failed_settlements",
                "hash-a",
            ),
            NumericClaim::metric(
                99.0,
                "count",
                ValueClass::Exact,
                "failed_settlements",
                "hash-b",
            ),
        ];
        let mut truth = BTreeMap::new();
        truth.insert("metric:failed_settlements:hash-a".to_string(), 42.0);
        truth.insert("metric:failed_settlements:hash-b".to_string(), 7.0); // disagrees with the claim
        let rederiver = FixedRederiver(truth);

        // Any real `CompiledWindow` works here — `verify_answer` gates purely on the claims +
        // rederiver, independent of what grounded the window — so a trivial empty-corpus compile is
        // enough to drive it.
        let counter = ainxt_retrieval::WordTokenCounter;
        let empty = Corpus::new();
        let r = LexicalRetriever::new(empty);
        let window = compile(
            "failed settlements",
            &r,
            DataClass::Confidential,
            &OptimizerConfig::default(),
            &counter,
            None,
            &BTreeMap::new(),
        );
        let verified =
            window.verify_answer("42 failures", &claims, &rederiver, &Tolerance::default());
        assert!(!verified.ships(), "a mismatched claim must never ship");
        assert!(verified.blocked_on_mismatch());

        let lineage = vec![LineageNode {
            chunk_id: "c1".to_string(),
            source: "v_settlement_failures".to_string(),
            data_class: DataClass::Confidential,
            provenance: "retrieved:structured".to_string(),
            outcome: LineageOutcome::Included,
        }];
        let record = verified.to_event_record(lineage.clone(), "sha-deadbeef", Some(0.35));

        assert_eq!(record.control_plane_sha, "sha-deadbeef");
        assert_eq!(record.lineage, lineage);
        assert_eq!(record.federated_epsilon_spent, Some(0.35));
        // The re-derivation hash of the VERIFIED claim rides in the record, tagged with the SHA —
        // the exact "which definitions produced this turn's numbers" audit fact.
        assert!(record
            .rederivation
            .verified
            .iter()
            .any(|v| v.rederive_key == "metric:failed_settlements:hash-a"));
        assert!(record.rederivation.failures.iter().any(|f| matches!(
            f,
            ainxt_synthesis::rederive::RederiveFailure::Mismatch { .. }
        )));

        // A turn that never federates carries `None`, never a bare `0.0` (the two must never be
        // confused — "spent nothing" vs "did not query a federated signal").
        let no_fed = verified.to_event_record(lineage, "sha-deadbeef", None);
        assert_eq!(no_fed.federated_epsilon_spent, None);

        // The record is a clean serializable payload — the actual sink is the composition root's.
        let json = serde_json::to_string(&no_fed).expect("event record serializes");
        assert!(json.contains("sha-deadbeef"));
    }
}
