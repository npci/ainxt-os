// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! ainxt-retrieval — the AiNxt hybrid retrieval / RAG core.
//!
//! Design: `docs/architecture/STRUCTURED_FEDERATED_RETRIEVAL.md`, `CONTEXT_FABRIC.md`.
//!
//! This crate is the in-process, dependency-light heart of Context Fabric layer 11
//! (hybrid docs retrieval) and the pre-rank security filter (`CONTEXT_FABRIC.md` §3).
//! It implements, on real inputs, the pieces the fabric composes:
//!
//! 1. **Lexical index (BM25 / Okapi)** — a TF-IDF-family ranker over a [`Corpus`] of
//!    [`Chunk`]s. Document-frequency and average-length statistics are computed at
//!    index-build time; per-query scoring uses the standard `k1`/`b` saturation form.
//! 2. **Dense vector index (cosine)** — ranks chunks by cosine similarity against a
//!    caller-supplied query embedding. Embeddings are *accepted precomputed*: producing
//!    them is an explicit seam (an embed service, `services/embed_svc`), never done here.
//! 3. **Reciprocal-Rank Fusion (RRF)** — merges the lexical and dense rankings by the
//!    rank-only `1/(k + rank)` formula, so the two incomparable score scales never have
//!    to be normalized against each other. See [`rrf_fuse`].
//! 4. **Rerank seam** — the [`Reranker`] trait plus an [`IdentityReranker`] default. A
//!    real cross-encoder reranker (the `/rerank` endpoint) slots in without touching the
//!    fusion or ACL code.
//! 5. **Chunk-level ACL, applied PRE-rank** — a chunk whose [`DataClass`] exceeds the
//!    [`Principal`]'s clearance is removed from the candidate set *before* any ranker
//!    scores it (`CONTEXT_FABRIC.md` §3: "filtering happens before ranking so existence
//!    never leaks"). A post-filter would leak existence via result counts, score gaps,
//!    or IDF perturbation; here an above-clearance chunk is never scored, ranked, fused,
//!    reranked, or returned by any surface.
//! 6. **Position-aware budget fit** — [`budget_fit`] selects the highest-ranked chunks
//!    that fit a token budget, then arranges them so the most relevant sit at the *edges*
//!    of the window ("lost-in-the-middle" mitigation, `CONTEXT_FABRIC.md` §3), never
//!    exceeding the cap. Token counting is itself a seam ([`TokenCounter`]).
//!
//! The crate is pure and synchronous: no I/O, no external vector DB, no ML runtime — the
//! embedding, the reranker model, and the tokenizer are all traits/inputs, keeping the
//! legal + supply-chain surface to `serde` + `ainxt-types`. The clearance model is the
//! shared [`ainxt_types::DataClass`] / [`ainxt_types::Principal`], so a retrieval ACL
//! decision and a model-routing decision read the *same* labels (`CONTEXT_FABRIC.md` §9,
//! "one security filter").

use std::collections::HashMap;

use ainxt_types::{DataClass, Principal};
use serde::{Deserialize, Serialize};

pub mod acl;
pub mod federation;
pub mod maintenance;
pub mod reembed;
pub mod rls;
pub mod structured;
pub mod structured_pipeline;

/// Okapi BM25 term-frequency saturation parameter (standard default).
/// Algorithm: Robertson, S. et al. "Okapi at TREC-3" (1994); Robertson & Zaragoza,
/// "The Probabilistic Relevance Framework: BM25 and Beyond" (2009). Public domain.
pub const BM25_K1: f64 = 1.2;
/// Okapi BM25 length-normalization parameter (standard default).
pub const BM25_B: f64 = 0.75;
/// RRF rank-damping constant (Cormack et al. default). Larger = flatter fusion.
/// Algorithm: Cormack, G.V. et al. "Reciprocal Rank Fusion outperforms Condorcet
/// and individual Rank Learning Methods" (SIGIR 2009). Public domain.
pub const RRF_K: f64 = 60.0;

/// The identity of the embedding model + generation that produced a vector. Two vectors are
/// only comparable when this matches exactly — a `nomic-embed-text@v2` vector and a
/// `nomic-embed-text@v3` vector live in different spaces, and cosine between them is a
/// meaningless number that silently degrades recall (`CONTEXT_FABRIC.md` §4, "no silent
/// mixed-version degradation"). Carrying it on the chunk makes cross-version comparison a
/// *representable, refusable* condition instead of an invisible bug.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EmbeddingVersion {
    pub model: String,
    pub version: u32,
}

impl EmbeddingVersion {
    pub fn new(model: &str, version: u32) -> Self {
        EmbeddingVersion {
            model: model.to_string(),
            version,
        }
    }
}

/// A single retrievable unit: an id, its text, and the data class that gates who may see
/// it. `embedding` is optional and *precomputed* — a chunk without one still participates
/// in lexical retrieval but not in dense retrieval. `embedding_model` records which model
/// generated the vector so the version-aware dense path ([`Corpus::cosine_versioned`]) never
/// compares across incompatible embedding spaces; `None` = unversioned/legacy (dimension-only
/// comparability, the pre-lifecycle behavior).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Chunk {
    pub id: String,
    pub text: String,
    pub data_class: DataClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embedding: Option<Vec<f32>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embedding_model: Option<EmbeddingVersion>,
    /// Optional per-node ACL beyond the [`DataClass`] scalar (`CONTEXT_FABRIC.md` §2 "node/edge-
    /// level RBAC + data-class labels", §8.3 department/ad_level pre-rank existence filtering).
    /// `None` = class-only gating (back-compat). When present it is enforced **pre-rank** alongside
    /// the class check, so a node the caller may not see by department/seniority/group is never
    /// scored — its existence cannot leak (see [`acl::NodeAcl`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acl: Option<acl::NodeAcl>,
    /// Row attributes for row-level-security filtering (`CONTEXT_FABRIC.md` §8.3, gap AJ) — the
    /// per-row labels a [`rls::RowFilter`] policy compares against a value bound from the OBO
    /// principal (SET LOCAL-style). Empty = the row carries no RLS labels, so any policy that
    /// references a label it lacks fail-closes (the row is denied), never permitted by omission.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub attributes: std::collections::BTreeMap<String, String>,
}

impl Chunk {
    /// A chunk with no embedding (lexical-only until one is attached).
    pub fn new(id: &str, text: &str, data_class: DataClass) -> Self {
        Chunk {
            id: id.to_string(),
            text: text.to_string(),
            data_class,
            embedding: None,
            embedding_model: None,
            acl: None,
            attributes: std::collections::BTreeMap::new(),
        }
    }

    /// Attach a per-node ACL (builder style) — enforced pre-rank alongside the data-class check.
    pub fn with_acl(mut self, acl: acl::NodeAcl) -> Self {
        self.acl = Some(acl);
        self
    }

    /// Attach one row-security attribute (builder style) — a per-row label an [`rls::RowFilter`]
    /// policy compares against a value bound from the OBO principal.
    pub fn with_attribute(mut self, key: &str, value: &str) -> Self {
        self.attributes.insert(key.to_string(), value.to_string());
        self
    }

    /// Attach a precomputed but *unversioned* embedding (builder style). Comparable to a query
    /// vector by dimension only — use [`Chunk::with_versioned_embedding`] to opt into
    /// version-gated dense retrieval.
    pub fn with_embedding(mut self, embedding: Vec<f32>) -> Self {
        self.embedding = Some(embedding);
        self
    }

    /// Attach a precomputed embedding tagged with the model/version that produced it (builder
    /// style). Only such a chunk participates in [`Corpus::cosine_versioned`].
    pub fn with_versioned_embedding(
        mut self,
        embedding: Vec<f32>,
        version: EmbeddingVersion,
    ) -> Self {
        self.embedding = Some(embedding);
        self.embedding_model = Some(version);
        self
    }
}

/// A scored corpus position — internal ranking currency (index into the corpus + score).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Scored {
    pub index: usize,
    pub score: f64,
}

/// A retrieval candidate surfaced to callers and rerankers. Carries the text and data
/// class so a content-aware reranker (cross-encoder) has what it needs; a `score` in the
/// fused-ranking scale.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Candidate {
    pub id: String,
    pub text: String,
    pub data_class: DataClass,
    pub score: f64,
}

/// Lowercase alphanumeric tokenizer — the analyzer shared by index build and query.
/// Splits on any non-alphanumeric boundary (Unicode-aware via `char::is_alphanumeric`).
fn tokenize(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_lowercase())
        .collect()
}

/// Cosine similarity in `[-1, 1]`, or `None` if the vectors are incomparable (differing
/// dimension, empty, or a zero-magnitude vector for which cosine is undefined).
fn cosine_sim(a: &[f32], b: &[f32]) -> Option<f64> {
    if a.is_empty() || a.len() != b.len() {
        return None;
    }
    let mut dot = 0.0f64;
    let mut norm_a = 0.0f64;
    let mut norm_b = 0.0f64;
    for (x, y) in a.iter().zip(b.iter()) {
        let (x, y) = (*x as f64, *y as f64);
        dot += x * y;
        norm_a += x * x;
        norm_b += y * y;
    }
    if norm_a == 0.0 || norm_b == 0.0 {
        return None;
    }
    Some(dot / (norm_a.sqrt() * norm_b.sqrt()))
}

/// Sort scored positions by score descending, breaking ties by ascending index so the
/// ordering is total and deterministic (no reliance on unstable float ordering).
fn sort_scored(mut v: Vec<Scored>) -> Vec<Scored> {
    v.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.index.cmp(&b.index))
    });
    v
}

/// The corpus + its precomputed lexical statistics. Immutable after construction; rebuild
/// to add documents (matches the "index is a snapshot" discipline — a live mutation would
/// invalidate the df/avgdl stats mid-query).
#[derive(Debug, Clone)]
pub struct Corpus {
    chunks: Vec<Chunk>,
    /// Per-document term frequencies (over the tokenized text).
    term_freqs: Vec<HashMap<String, u32>>,
    /// Per-document length in tokens.
    doc_len: Vec<u32>,
    /// Corpus-wide document frequency per term.
    df: HashMap<String, u32>,
    /// Mean document length in tokens (0.0 for an empty corpus).
    avgdl: f64,
}

impl Corpus {
    /// Build the corpus and its lexical index in one pass over the documents.
    pub fn new(chunks: Vec<Chunk>) -> Self {
        let mut term_freqs = Vec::with_capacity(chunks.len());
        let mut doc_len = Vec::with_capacity(chunks.len());
        let mut df: HashMap<String, u32> = HashMap::new();
        let mut total_len: u64 = 0;

        for chunk in &chunks {
            let tokens = tokenize(&chunk.text);
            let mut tf: HashMap<String, u32> = HashMap::new();
            for tok in &tokens {
                *tf.entry(tok.clone()).or_insert(0) += 1;
            }
            // Document frequency: count each term once per document.
            for term in tf.keys() {
                *df.entry(term.clone()).or_insert(0) += 1;
            }
            doc_len.push(tokens.len() as u32);
            total_len += tokens.len() as u64;
            term_freqs.push(tf);
        }

        let avgdl = if chunks.is_empty() {
            0.0
        } else {
            total_len as f64 / chunks.len() as f64
        };

        Corpus {
            chunks,
            term_freqs,
            doc_len,
            df,
            avgdl,
        }
    }

    /// Number of documents in the corpus.
    pub fn len(&self) -> usize {
        self.chunks.len()
    }

    /// True if the corpus holds no documents.
    pub fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }

    /// The chunk at a corpus index, if it exists.
    pub fn chunk(&self, index: usize) -> Option<&Chunk> {
        self.chunks.get(index)
    }

    /// Whether `principal` may read `chunk`. Two gates, both fail-closed:
    ///
    /// 1. **Data class** — the chunk's sensitivity must not exceed the principal's clearance.
    /// 2. **Node ACL** — if the chunk carries an [`acl::NodeAcl`], it is enforced too. The bare
    ///    [`Principal`] path can only supply `department`; `ad_level` and group membership are
    ///    unknown here, so an ACL that *requires* a seniority ceiling or an allow-group is treated
    ///    as **not satisfied** (deny) unless the department alone permits — the safe default. For a
    ///    query that carries seniority/groups, use the richer [`acl::AccessContext`] path
    ///    ([`Corpus::hybrid_ctx`]).
    ///
    /// Every retrieval surface routes candidate selection through [`Corpus::allowed`] /
    /// [`Corpus::allowed_ctx`], which use this, so a node the caller may not see is never scored.
    pub fn is_visible(chunk: &Chunk, principal: &Principal) -> bool {
        if chunk.data_class.sensitivity() > principal.clearance.sensitivity() {
            return false;
        }
        match &chunk.acl {
            None => true,
            Some(node_acl) => {
                let ctx = acl::AccessContext::from_principal(principal);
                node_acl.permits(&ctx)
            }
        }
    }

    /// Whether an [`acl::AccessContext`] (clearance + department + ad_level + groups, sourced from
    /// the OBO/JWT claims) may read `chunk` — the richer node/edge RBAC path (`CONTEXT_FABRIC.md`
    /// §8.3). Data class first, then the node ACL (if any), both fail-closed.
    pub fn is_visible_ctx(chunk: &Chunk, ctx: &acl::AccessContext) -> bool {
        if chunk.data_class.sensitivity() > ctx.clearance.sensitivity() {
            return false;
        }
        match &chunk.acl {
            None => true,
            Some(node_acl) => node_acl.permits(ctx),
        }
    }

    /// The PRE-rank ACL: the corpus indices this principal may see. Every ranker starts
    /// from this set, so an above-clearance chunk is never scored — its existence cannot
    /// leak through result counts, score gaps, or ranking side effects.
    fn allowed(&self, principal: &Principal) -> Vec<usize> {
        self.chunks
            .iter()
            .enumerate()
            .filter(|(_, c)| Corpus::is_visible(c, principal))
            .map(|(i, _)| i)
            .collect()
    }

    /// The PRE-rank ACL under the richer [`acl::AccessContext`] (department/ad_level/groups).
    fn allowed_ctx(&self, ctx: &acl::AccessContext) -> Vec<usize> {
        self.chunks
            .iter()
            .enumerate()
            .filter(|(_, c)| Corpus::is_visible_ctx(c, ctx))
            .map(|(i, _)| i)
            .collect()
    }

    /// BM25 score of a single document (by index) against the unique query terms. Uses
    /// the corpus-wide `df`/`avgdl`; returns 0.0 when no query term occurs in the doc.
    fn bm25_score(&self, index: usize, query_terms: &[String]) -> f64 {
        let n = self.chunks.len() as f64;
        let tf = &self.term_freqs[index];
        let dl = self.doc_len[index] as f64;
        let mut score = 0.0f64;
        for term in query_terms {
            let f = match tf.get(term) {
                Some(&f) if f > 0 => f as f64,
                _ => continue,
            };
            let df_t = *self.df.get(term).unwrap_or(&0) as f64;
            // Okapi BM25 IDF (always positive form): ln(1 + (N - df + 0.5)/(df + 0.5)).
            let idf = (1.0 + (n - df_t + 0.5) / (df_t + 0.5)).ln();
            let denom = f + BM25_K1 * (1.0 - BM25_B + BM25_B * dl / self.avgdl.max(1.0));
            score += idf * (f * (BM25_K1 + 1.0)) / denom;
        }
        score
    }

    /// Full lexical ranking over the ACL-allowed set: only documents with a positive
    /// BM25 score (i.e. that actually contain a query term), sorted best-first.
    fn bm25_all(&self, query: &str, principal: &Principal) -> Vec<Scored> {
        self.bm25_over(query, &self.allowed(principal))
    }

    /// [`Corpus::bm25_all`] restricted to a caller-supplied allowed-index set (the pre-rank ACL).
    fn bm25_over(&self, query: &str, allowed: &[usize]) -> Vec<Scored> {
        let query_terms = dedup(tokenize(query));
        if query_terms.is_empty() {
            return Vec::new();
        }
        let scored: Vec<Scored> = allowed
            .iter()
            .map(|&i| Scored {
                index: i,
                score: self.bm25_score(i, &query_terms),
            })
            .filter(|s| s.score > 0.0)
            .collect();
        sort_scored(scored)
    }

    /// Full dense ranking over the ACL-allowed set: every allowed chunk that has a
    /// comparable embedding, sorted by cosine similarity best-first.
    fn cosine_all(&self, query_vec: &[f32], principal: &Principal) -> Vec<Scored> {
        self.cosine_over(query_vec, &self.allowed(principal))
    }

    /// [`Corpus::cosine_all`] restricted to a caller-supplied allowed-index set (the pre-rank ACL).
    fn cosine_over(&self, query_vec: &[f32], allowed: &[usize]) -> Vec<Scored> {
        if query_vec.is_empty() {
            return Vec::new();
        }
        let scored: Vec<Scored> = allowed
            .iter()
            .filter_map(|&i| {
                let emb = self.chunks[i].embedding.as_deref()?;
                let sim = cosine_sim(query_vec, emb)?;
                Some(Scored {
                    index: i,
                    score: sim,
                })
            })
            .collect();
        sort_scored(scored)
    }

    /// Top-`top_n` lexical (BM25) results, ACL-filtered pre-rank.
    pub fn bm25(&self, query: &str, principal: &Principal, top_n: usize) -> Vec<Scored> {
        let mut r = self.bm25_all(query, principal);
        r.truncate(top_n);
        r
    }

    /// Top-`top_n` dense (cosine) results, ACL-filtered pre-rank.
    pub fn cosine(&self, query_vec: &[f32], principal: &Principal, top_n: usize) -> Vec<Scored> {
        let mut r = self.cosine_all(query_vec, principal);
        r.truncate(top_n);
        r
    }

    /// Version-gated dense ranking: only chunks whose `embedding_model` matches `query_ver`
    /// **exactly** are scored — a vector produced by a different model/generation is skipped,
    /// never compared (`CONTEXT_FABRIC.md` §4, "no silent mixed-version degradation"). Unversioned
    /// chunks (`embedding_model == None`) are skipped in this mode because their comparability
    /// cannot be guaranteed. ACL is still applied pre-rank.
    fn cosine_versioned_all(
        &self,
        query_vec: &[f32],
        query_ver: &EmbeddingVersion,
        principal: &Principal,
    ) -> Vec<Scored> {
        if query_vec.is_empty() {
            return Vec::new();
        }
        let scored: Vec<Scored> = self
            .allowed(principal)
            .into_iter()
            .filter_map(|i| {
                let chunk = &self.chunks[i];
                if chunk.embedding_model.as_ref() != Some(query_ver) {
                    return None;
                }
                let emb = chunk.embedding.as_deref()?;
                let sim = cosine_sim(query_vec, emb)?;
                Some(Scored {
                    index: i,
                    score: sim,
                })
            })
            .collect();
        sort_scored(scored)
    }

    /// Top-`top_n` version-gated dense results (see [`Corpus::cosine_versioned_all`]).
    pub fn cosine_versioned(
        &self,
        query_vec: &[f32],
        query_ver: &EmbeddingVersion,
        principal: &Principal,
        top_n: usize,
    ) -> Vec<Scored> {
        let mut r = self.cosine_versioned_all(query_vec, query_ver, principal);
        r.truncate(top_n);
        r
    }

    /// The corpus indices whose embedding is missing or NOT at `target` — i.e. the re-embed
    /// worklist for an embedding-model migration. Ordered by index for a deterministic sweep.
    /// This is the concrete "re-embed pipeline" trigger the design calls for: after bumping the
    /// platform embedding model, this enumerates exactly what still needs regenerating, so a
    /// migration never silently leaves a mixed-version index behind.
    pub fn stale_embeddings(&self, target: &EmbeddingVersion) -> Vec<usize> {
        self.chunks
            .iter()
            .enumerate()
            .filter(|(_, c)| c.embedding_model.as_ref() != Some(target))
            .map(|(i, _)| i)
            .collect()
    }

    /// True iff every chunk carries an embedding at exactly `target` — the post-migration
    /// invariant a re-embed job drives toward (empty [`Corpus::stale_embeddings`]).
    pub fn is_embedding_uniform(&self, target: &EmbeddingVersion) -> bool {
        self.stale_embeddings(target).is_empty()
    }

    /// The full hybrid pipeline: ACL pre-filter → BM25 ranking → cosine ranking →
    /// [`rrf_fuse`] merge → truncate to `top_n` → [`Reranker`]. `query_vec` is optional:
    /// with `None`, the dense arm is skipped and the result is lexical-only (still fused,
    /// so scores stay on the RRF scale). The returned [`Candidate`]s are ACL-clean by
    /// construction — nothing above clearance ever entered any ranking.
    pub fn hybrid(
        &self,
        query: &str,
        query_vec: Option<&[f32]>,
        principal: &Principal,
        top_n: usize,
        reranker: &dyn Reranker,
    ) -> Vec<Candidate> {
        self.hybrid_over(query, query_vec, &self.allowed(principal), top_n, reranker)
    }

    /// [`Corpus::hybrid`] under the richer [`acl::AccessContext`] — the department/ad_level/group
    /// node-RBAC path (`CONTEXT_FABRIC.md` §8.3). Identical fusion + rerank; the ONLY difference is
    /// the pre-rank ACL, which now honors node-level department/seniority/group predicates so a
    /// node the caller may not see is never scored, fused, reranked, or returned.
    pub fn hybrid_ctx(
        &self,
        query: &str,
        query_vec: Option<&[f32]>,
        ctx: &acl::AccessContext,
        top_n: usize,
        reranker: &dyn Reranker,
    ) -> Vec<Candidate> {
        self.hybrid_over(query, query_vec, &self.allowed_ctx(ctx), top_n, reranker)
    }

    /// [`Corpus::hybrid`] with a **row-level-security row-filter** applied in the SAME pre-rank
    /// pass as the class/node ACL (`CONTEXT_FABRIC.md` §8.3, gap AJ). The [`rls::RowFilter`]'s
    /// policies compare each row's attributes against values bound from the OBO principal at query
    /// start (SET LOCAL-style, [`rls::RlsSession::bind`]); a row that fails any policy — or lacks a
    /// referenced attribute, or whose bound setting is absent — is **denied and never scored**, so
    /// its existence never leaks through result counts or score gaps. The class/node ACL still runs
    /// first, so RLS is strictly *additional* filtering, never a way to widen visibility. An empty
    /// filter (no policies) reduces to plain [`Corpus::hybrid`].
    ///
    /// This is a read-filter, not an admission decision: it shapes *which rows* a turn may read,
    /// never whether the turn proceeds.
    pub fn hybrid_rls(
        &self,
        query: &str,
        query_vec: Option<&[f32]>,
        principal: &Principal,
        filter: &rls::RowFilter,
        top_n: usize,
        reranker: &dyn Reranker,
    ) -> Vec<Candidate> {
        self.hybrid_over(
            query,
            query_vec,
            &self.allowed_rls(principal, filter),
            top_n,
            reranker,
        )
    }

    /// The PRE-rank allowed set under the class/node ACL **and** the RLS row-filter. A chunk must
    /// pass BOTH ([`Corpus::is_visible`] first, then [`rls::RowFilter::permits`]) to be scored.
    fn allowed_rls(&self, principal: &Principal, filter: &rls::RowFilter) -> Vec<usize> {
        self.chunks
            .iter()
            .enumerate()
            .filter(|(_, c)| Corpus::is_visible(c, principal) && filter.permits(c))
            .map(|(i, _)| i)
            .collect()
    }

    /// The full pre-rank filter for the served path: the richer [`acl::AccessContext`] node/edge RBAC
    /// (class + department + `ad_level` + allow/deny groups, [`Corpus::is_visible_ctx`]) **and** the
    /// RLS row-filter, both applied in the SAME pass. A chunk must pass BOTH to be scored — the node
    /// ACL first (an above-clearance / wrong-department / too-junior / denied-group node is dropped),
    /// then the row-filter. This is the composition the live compile path needs: unlike
    /// [`Corpus::hybrid_rls`] (which uses a bare [`Principal`] and therefore cannot prove `ad_level`
    /// or group claims, fail-closing every `ad_level`/group-gated node), this carries the caller's
    /// full OBO claims so those axes are enforced from the real identity rather than dropped.
    pub fn hybrid_ctx_rls(
        &self,
        query: &str,
        query_vec: Option<&[f32]>,
        ctx: &acl::AccessContext,
        filter: &rls::RowFilter,
        top_n: usize,
        reranker: &dyn Reranker,
    ) -> Vec<Candidate> {
        self.hybrid_over(
            query,
            query_vec,
            &self.allowed_ctx_rls(ctx, filter),
            top_n,
            reranker,
        )
    }

    /// The PRE-rank allowed set under the [`acl::AccessContext`] node/edge RBAC **and** the RLS
    /// row-filter. A chunk must pass BOTH ([`Corpus::is_visible_ctx`] first — class + department +
    /// `ad_level` + groups — then [`rls::RowFilter::permits`]) to be scored. Fail-closed on either.
    fn allowed_ctx_rls(&self, ctx: &acl::AccessContext, filter: &rls::RowFilter) -> Vec<usize> {
        self.chunks
            .iter()
            .enumerate()
            .filter(|(_, c)| Corpus::is_visible_ctx(c, ctx) && filter.permits(c))
            .map(|(i, _)| i)
            .collect()
    }

    /// The shared hybrid pipeline over an already-resolved allowed-index set (the pre-rank ACL).
    fn hybrid_over(
        &self,
        query: &str,
        query_vec: Option<&[f32]>,
        allowed: &[usize],
        top_n: usize,
        reranker: &dyn Reranker,
    ) -> Vec<Candidate> {
        let lexical = self.bm25_over(query, allowed);
        let dense = match query_vec {
            Some(v) => self.cosine_over(v, allowed),
            None => Vec::new(),
        };

        let rankings: Vec<Vec<usize>> = [lexical, dense]
            .into_iter()
            .filter(|r| !r.is_empty())
            .map(|r| r.into_iter().map(|s| s.index).collect())
            .collect();

        let fused = rrf_fuse(&rankings, RRF_K);

        let mut candidates: Vec<Candidate> = fused
            .into_iter()
            .take(top_n)
            .map(|(index, score)| {
                let c = &self.chunks[index];
                Candidate {
                    id: c.id.clone(),
                    text: c.text.clone(),
                    data_class: c.data_class,
                    score,
                }
            })
            .collect();

        candidates = reranker.rerank(query, candidates);
        candidates
    }
}

/// Deduplicate while preserving first-seen order (query terms are scored once each).
fn dedup(items: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    items
        .into_iter()
        .filter(|t| seen.insert(t.clone()))
        .collect()
}

/// Reciprocal-Rank Fusion. Each input is one ranking as an ordered list of corpus
/// indices (best-first). A document's fused score is `Σ 1/(k + rank)` over the rankings
/// that contain it, with `rank` 1-based. Because RRF uses only *rank position*, the
/// incomparable BM25 and cosine score scales never need normalization. Output is sorted
/// best-first, ties broken by ascending index for determinism.
pub fn rrf_fuse(rankings: &[Vec<usize>], k: f64) -> Vec<(usize, f64)> {
    let mut acc: HashMap<usize, f64> = HashMap::new();
    for ranking in rankings {
        for (rank0, &idx) in ranking.iter().enumerate() {
            let rank = (rank0 + 1) as f64;
            *acc.entry(idx).or_insert(0.0) += 1.0 / (k + rank);
        }
    }
    let mut out: Vec<(usize, f64)> = acc.into_iter().collect();
    out.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.0.cmp(&b.0))
    });
    out
}

/// The rerank seam: given the query and the fused candidates, return a (possibly
/// reordered, possibly rescored) list. Implementors MUST NOT introduce candidates that
/// were not passed in — the ACL guarantee holds only if reranking is order/score-only.
/// `Send + Sync` because a reranker is installed into shared, thread-crossing retrievers (the
/// Context Fabric's `Retriever` is itself `Send + Sync`, and one retriever serves concurrent turns).
/// A real cross-encoder is a stateless scorer behind an inference seam, so this costs nothing.
pub trait Reranker: Send + Sync {
    fn rerank(&self, query: &str, candidates: Vec<Candidate>) -> Vec<Candidate>;
}

/// The default reranker: pass candidates through unchanged. A real cross-encoder
/// reranker replaces this without any other code moving.
#[derive(Debug, Default, Clone, Copy)]
pub struct IdentityReranker;

impl Reranker for IdentityReranker {
    fn rerank(&self, _query: &str, candidates: Vec<Candidate>) -> Vec<Candidate> {
        candidates
    }
}

/// A lexical **coverage** reranker: rescores each candidate by the fraction of the query's DISTINCT
/// terms present in the document (coverage), breaking ties by total query-term frequency, then
/// re-sorts best-first. It is a cheap, dependency-free stand-in for a cross-encoder — strictly better
/// than [`IdentityReranker`] at surfacing the doc that actually covers the whole query — and it
/// upholds the ACL guarantee by construction: it only reorders/rescores the candidates it is given
/// and NEVER introduces a new one (so an above-clearance chunk, already excluded pre-rank, cannot
/// reappear). A real cross-encoder model replaces this behind the same [`Reranker`] seam.
#[derive(Debug, Default, Clone, Copy)]
pub struct LexicalReranker;

impl Reranker for LexicalReranker {
    fn rerank(&self, query: &str, mut candidates: Vec<Candidate>) -> Vec<Candidate> {
        let q = dedup(tokenize(query));
        if q.is_empty() {
            return candidates;
        }
        for c in &mut candidates {
            let doc = tokenize(&c.text);
            let covered = q.iter().filter(|t| doc.contains(t)).count();
            let coverage = covered as f64 / q.len() as f64;
            // Total occurrences of query terms in the doc — a within-coverage tiebreak only, so
            // coverage always dominates (the small weight can never flip two different coverages).
            let tf = doc.iter().filter(|t| q.contains(t)).count();
            c.score = coverage + (tf as f64) * 1e-6;
        }
        candidates.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(a.id.cmp(&b.id))
        });
        candidates
    }
}

/// The client seam for a real cross-encoder scoring service (round-15 `context-fabric` LOW gap:
/// "cross-encoder reranker on the retrieval path"). This is the platform's existing `/rerank`
/// endpoint (`services/embed_svc`, TinyBERT `ms-marco-TinyBERT-L-2-v2`) from the Rust side: a
/// transport-agnostic trait so [`CrossEncoderReranker`] stays pure/testable and the live HTTP call is
/// the ONLY infra-gated piece behind it. Returns one relevance score per input text, aligned by
/// index (`texts[i]` ↔ `scores[i]`); `Err` on any transport/model failure.
/// `Send + Sync` for the same reason as [`Reranker`]: the client is reached from a shared retriever
/// serving concurrent turns. A real implementation wraps an HTTP client, which already is.
pub trait RerankClient: Send + Sync {
    fn score(&self, query: &str, texts: &[String]) -> Result<Vec<f32>, String>;
}

/// A [`Reranker`] backed by a real cross-encoder scoring model via [`RerankClient`]. Re-sorts
/// candidates by the client's returned score, ties broken by id (deterministic). **Fails OPEN** to
/// the order it was given on any transport/model error or a malformed (wrong-length) response — a
/// reranker is a retrieval read-filter/ordering concern, never a turn-admission decision, so a
/// `/rerank` outage must degrade to the prior fused order, never drop candidates or block the turn.
/// Upholds the [`Reranker`] ACL guarantee by construction: it only reorders/rescores what it is
/// given, exactly like [`LexicalReranker`].
pub struct CrossEncoderReranker<'a> {
    client: &'a dyn RerankClient,
}

impl<'a> CrossEncoderReranker<'a> {
    pub fn new(client: &'a dyn RerankClient) -> Self {
        CrossEncoderReranker { client }
    }
}

impl Reranker for CrossEncoderReranker<'_> {
    fn rerank(&self, query: &str, mut candidates: Vec<Candidate>) -> Vec<Candidate> {
        let texts: Vec<String> = candidates.iter().map(|c| c.text.clone()).collect();
        let scores = match self.client.score(query, &texts) {
            Ok(s) if s.len() == candidates.len() => s,
            // Fail OPEN: transport error, or a response whose length doesn't match the request —
            // never trust a misaligned score vector onto candidates by position.
            _ => return candidates,
        };
        for (c, s) in candidates.iter_mut().zip(scores.iter()) {
            c.score = *s as f64;
        }
        candidates.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(a.id.cmp(&b.id))
        });
        candidates
    }
}

/// An **owned** cross-encoder reranker: the same behaviour as [`CrossEncoderReranker`] but holding
/// its [`RerankClient`] in an [`Arc`](std::sync::Arc) instead of borrowing it, so it can be stored
/// as a `Box<dyn Reranker>` on a long-lived retriever (the Context Fabric's `HybridRetriever`) and
/// shared across threads. Without this, the cross-encoder was structurally unreachable from the
/// fabric: `CrossEncoderReranker<'a>` cannot be held by a `'static` retriever.
///
/// Same fail-OPEN discipline: any transport/model error degrades to the fused order, never a block.
pub struct SharedCrossEncoderReranker {
    client: std::sync::Arc<dyn RerankClient + Send + Sync>,
}

impl SharedCrossEncoderReranker {
    pub fn new(client: std::sync::Arc<dyn RerankClient + Send + Sync>) -> Self {
        SharedCrossEncoderReranker { client }
    }
}

impl Reranker for SharedCrossEncoderReranker {
    fn rerank(&self, query: &str, candidates: Vec<Candidate>) -> Vec<Candidate> {
        CrossEncoderReranker::new(self.client.as_ref()).rerank(query, candidates)
    }
}

/// Token-counting seam for budget fitting. A real deployment plugs in the eligible
/// model's actual tokenizer (`CONTEXT_FABRIC.md` §3, fit-to-eligible-floor); the default
/// is a whitespace word counter for tests and lexical estimation.
pub trait TokenCounter {
    fn count(&self, text: &str) -> usize;
}

/// Whitespace word counter — a conservative, tokenizer-free estimate.
#[derive(Debug, Default, Clone, Copy)]
pub struct WordTokenCounter;

impl TokenCounter for WordTokenCounter {
    fn count(&self, text: &str) -> usize {
        text.split_whitespace().count()
    }
}

/// Greedily select the highest-ranked candidates whose cumulative token cost stays within
/// `budget`, preserving rank order. An item too large to fit is skipped (a later, smaller
/// item may still fit) — this maximizes budget use without ever exceeding the cap. A
/// single item larger than the whole budget is never included.
pub fn select_within_budget(
    ranked: &[Candidate],
    budget: usize,
    counter: &dyn TokenCounter,
) -> Vec<Candidate> {
    let mut used = 0usize;
    let mut selected = Vec::new();
    for c in ranked {
        let cost = counter.count(&c.text);
        if used + cost <= budget {
            used += cost;
            selected.push(c.clone());
        }
    }
    selected
}

/// Reorder a relevance-ordered list so the most relevant items sit at the *edges* of the
/// window and the least relevant in the middle ("lost-in-the-middle" mitigation).
/// Technique: Liu, N.F. et al. "Lost in the Middle: How Language Models Use Long Contexts"
/// (TACL 2024, arXiv:2307.03172). Independently implemented; no code copied. Given
/// `[c0(best), c1, c2, …]`, even-ranked items go to the front and odd-ranked to the back,
/// yielding e.g. `[c0, c2, c4, …, c3, c1]` — so `c0` is first and `c1` is last.
pub fn position_aware(ranked: Vec<Candidate>) -> Vec<Candidate> {
    let mut front = Vec::new();
    let mut back = Vec::new();
    for (i, c) in ranked.into_iter().enumerate() {
        if i % 2 == 0 {
            front.push(c);
        } else {
            back.push(c);
        }
    }
    back.reverse();
    front.extend(back);
    front
}

/// Position-aware budget fit: select the top candidates that fit `budget`, then arrange
/// them for attention. The returned list never exceeds the cap and places the most
/// relevant survivors at the window edges. This is the function the Context Optimizer
/// calls to turn a ranked candidate list into a fitted, positioned window slice.
pub fn budget_fit(
    ranked: &[Candidate],
    budget: usize,
    counter: &dyn TokenCounter,
) -> Vec<Candidate> {
    position_aware(select_within_budget(ranked, budget, counter))
}

// ---------------------------------------------------------------------------------------
// Two-phase budget fitting against the *eligible model set* (CONTEXT_FABRIC.md §3, Gap [22])
// ---------------------------------------------------------------------------------------

/// One model in the turn's `tier_eligible ∩ class_eligible` candidate set, with the context
/// window (in the token unit the [`TokenCounter`] measures) it can actually accept. The Model
/// Router resolves this set from task-type + data-class *before* budget fitting runs, so the
/// assembled window is never wider than what the eventual model — including a failover target —
/// can accept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EligibleModel {
    pub id: String,
    pub window_tokens: usize,
}

impl EligibleModel {
    pub fn new(id: &str, window_tokens: usize) -> Self {
        EligibleModel {
            id: id.to_string(),
            window_tokens,
        }
    }
}

/// What happened to one candidate during a fit — every candidate is accounted for, so nothing
/// is ever *silently* dropped or truncated (the acceptance property in `CONTEXT_FABRIC.md` §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FitOutcome {
    /// Included in the fitted window.
    Included,
    /// Dropped because adding it would exceed the target window — an *accounted* exclusion,
    /// recorded in the lineage, never a raw string truncation.
    DroppedOverBudget,
}

/// The lineage entry for one candidate: which node, its token cost, and its fate. The full set
/// of these is the "lineage record (which nodes contributed)" the Context Optimizer must emit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FitDecision {
    pub id: String,
    pub tokens: usize,
    pub outcome: FitOutcome,
}

/// The result of fitting a ranked candidate list to a specific window: the positioned included
/// slice plus a complete lineage of every candidate's fate. Invariant:
/// `lineage.len() == ranked.len()` — total accountability.
#[derive(Debug, Clone, PartialEq)]
pub struct FittedContext {
    /// The fitted, position-aware-arranged candidates (most relevant at the window edges).
    pub included: Vec<Candidate>,
    /// One entry per input candidate, in rank order, recording included/dropped + token cost.
    pub lineage: Vec<FitDecision>,
    /// The window this fit targeted.
    pub window: usize,
    /// Total tokens the included set consumes (always `<= window`).
    pub used_tokens: usize,
}

impl FittedContext {
    /// Ids dropped for budget, in rank order — the accounted exclusions.
    pub fn dropped_ids(&self) -> Vec<&str> {
        self.lineage
            .iter()
            .filter(|d| d.outcome == FitOutcome::DroppedOverBudget)
            .map(|d| d.id.as_str())
            .collect()
    }

    /// True iff every input candidate appears in the lineage exactly once (no silent loss).
    pub fn fully_accounted(&self, input_len: usize) -> bool {
        self.lineage.len() == input_len
    }
}

/// The narrowest window among an eligible set — the "fit-to-eligible-floor" (§3). `None` for an
/// empty set (no eligible model resolved yet).
pub fn eligible_floor_window(models: &[EligibleModel]) -> Option<usize> {
    models.iter().map(|m| m.window_tokens).min()
}

/// Fit a ranked candidate list to an explicit `window`, recording a full lineage. Greedy in
/// rank order (a candidate too large is skipped so a later smaller one may still fit), then the
/// survivors are position-aware arranged. Every input candidate — included or dropped — gets a
/// [`FitDecision`], so the result is fully accountable and the emitted window never silently
/// truncates evidence. Used both for the initial floor fit and for every re-fit (§3).
pub fn refit(ranked: &[Candidate], window: usize, counter: &dyn TokenCounter) -> FittedContext {
    let mut used = 0usize;
    let mut included = Vec::new();
    let mut lineage = Vec::with_capacity(ranked.len());
    for c in ranked {
        let cost = counter.count(&c.text);
        if used + cost <= window {
            used += cost;
            included.push(c.clone());
            lineage.push(FitDecision {
                id: c.id.clone(),
                tokens: cost,
                outcome: FitOutcome::Included,
            });
        } else {
            lineage.push(FitDecision {
                id: c.id.clone(),
                tokens: cost,
                outcome: FitOutcome::DroppedOverBudget,
            });
        }
    }
    FittedContext {
        included: position_aware(included),
        lineage,
        window,
        used_tokens: used,
    }
}

/// Phase 1 of two-phase fitting (`CONTEXT_FABRIC.md` §3): fit to the **narrowest window among
/// the eligible model set** (the fit-to-eligible-floor), so the assembled window is never wider
/// than what the eventual model can accept — even before the router picks the specific one. An
/// empty eligible set fits to zero (nothing is eligible → nothing is safely includable).
pub fn budget_fit_eligible(
    ranked: &[Candidate],
    models: &[EligibleModel],
    counter: &dyn TokenCounter,
) -> FittedContext {
    let floor = eligible_floor_window(models).unwrap_or(0);
    refit(ranked, floor, counter)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn internal(id: &str, text: &str) -> Chunk {
        Chunk::new(id, text, DataClass::Internal)
    }

    /// A small, realistic docs corpus: one clearly on-topic doc plus distractors sharing
    /// some vocabulary.
    fn payments_corpus() -> Corpus {
        Corpus::new(vec![
            internal(
                "upi",
                "UPI is a real-time payment system enabling instant bank transfer between accounts using a virtual address",
            ),
            internal(
                "neft",
                "NEFT settles payment in half-hourly batches between banks across the country",
            ),
            internal(
                "weather",
                "The monsoon brought heavy rain and cool weather to the coastal region this week",
            ),
            internal(
                "cooking",
                "Slow cooking a stew requires patience, fresh vegetables, and a good pot",
            ),
        ])
    }

    #[test]
    fn bm25_ranks_on_topic_doc_first() {
        let corpus = payments_corpus();
        let p = Principal::user("u1", &[]);
        let results = corpus.bm25("instant UPI bank transfer between accounts", &p, 10);
        assert!(!results.is_empty(), "expected lexical matches");
        assert_eq!(
            corpus.chunk(results[0].index).unwrap().id,
            "upi",
            "the on-topic UPI doc must rank first"
        );
        // The off-topic docs must not out-rank the on-topic one; weather/cooking share no
        // query terms so they should not appear at all.
        let ids: Vec<&str> = results
            .iter()
            .map(|s| corpus.chunk(s.index).unwrap().id.as_str())
            .collect();
        assert!(!ids.contains(&"weather"));
        assert!(!ids.contains(&"cooking"));
    }

    #[test]
    fn bm25_idf_prefers_rarer_discriminating_term() {
        // "payment" occurs in two docs; "monsoon" occurs in one. A query with both should
        // rank the doc containing the rarer term when tf is otherwise comparable.
        let corpus = payments_corpus();
        let p = Principal::user("u1", &[]);
        let res = corpus.bm25("monsoon payment", &p, 10);
        assert_eq!(corpus.chunk(res[0].index).unwrap().id, "weather");
    }

    #[test]
    fn cosine_ranks_nearest_vector() {
        let corpus = Corpus::new(vec![
            internal("a", "alpha").with_embedding(vec![1.0, 0.0, 0.0]),
            internal("b", "beta").with_embedding(vec![0.0, 1.0, 0.0]),
            internal("c", "gamma").with_embedding(vec![0.9, 0.1, 0.0]),
        ]);
        let p = Principal::user("u1", &[]);
        // Query points almost along x — nearest is "a", then "c", then "b".
        let res = corpus.cosine(&[1.0, 0.05, 0.0], &p, 10);
        let ids: Vec<&str> = res
            .iter()
            .map(|s| corpus.chunk(s.index).unwrap().id.as_str())
            .collect();
        assert_eq!(ids, vec!["a", "c", "b"]);
        // Cosine of the exact match is ~1.0 minus the tiny y-component.
        assert!(res[0].score > 0.99);
    }

    #[test]
    fn cosine_skips_missing_or_mismatched_embeddings() {
        let corpus = Corpus::new(vec![
            internal("has", "x").with_embedding(vec![1.0, 0.0]),
            internal("none", "y"), // no embedding
            internal("wrongdim", "z").with_embedding(vec![1.0, 0.0, 0.0]),
        ]);
        let p = Principal::user("u1", &[]);
        let res = corpus.cosine(&[1.0, 0.0], &p, 10);
        // Only the comparable-dimension, embedded chunk participates.
        assert_eq!(res.len(), 1);
        assert_eq!(corpus.chunk(res[0].index).unwrap().id, "has");
    }

    #[test]
    fn rrf_merges_rankings() {
        // Doc 2 is mid-ranked in BOTH lists; doc 0 tops one but is absent from the other,
        // doc 1 tops the other but is absent from the first. RRF should reward the doc
        // that appears (reasonably) in both over docs that top only one list.
        let lex = vec![0usize, 2, 3];
        let dense = vec![1usize, 2, 4];
        let fused = rrf_fuse(&[lex, dense], RRF_K);
        let top = fused[0].0;
        assert_eq!(
            top, 2,
            "the doc present in both rankings should fuse to the top"
        );
        // Every input doc appears exactly once in the fused output.
        let mut ids: Vec<usize> = fused.iter().map(|(i, _)| *i).collect();
        ids.sort();
        assert_eq!(ids, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn rrf_score_matches_formula() {
        let fused = rrf_fuse(&[vec![7usize], vec![7usize]], 60.0);
        // doc 7 at rank 1 in both lists: 2 * 1/(60+1).
        assert_eq!(fused.len(), 1);
        assert!((fused[0].1 - 2.0 / 61.0).abs() < 1e-12);
    }

    #[test]
    fn above_clearance_chunk_never_appears_prerank() {
        // The regulated-payment chunk is BOTH the best lexical match AND the nearest
        // vector — if ACL were post-rank or absent, it would top every surface. With an
        // Internal-clearance principal it must never appear anywhere.
        let corpus = Corpus::new(vec![
            Chunk::new(
                "pan",
                "primary account number PAN full card data settlement ledger",
                DataClass::RegulatedPayment,
            )
            .with_embedding(vec![1.0, 0.0, 0.0]),
            internal(
                "public-note",
                "a general note about settlement ledger reports",
            )
            .with_embedding(vec![0.2, 1.0, 0.0]),
        ]);
        let p = Principal::user("analyst", &[]); // Internal clearance
        let query = "PAN full card data settlement ledger";
        let qvec = [1.0f32, 0.0, 0.0];

        // Lexical surface.
        for s in corpus.bm25(query, &p, 10) {
            assert_ne!(corpus.chunk(s.index).unwrap().id, "pan");
        }
        // Dense surface.
        for s in corpus.cosine(&qvec, &p, 10) {
            assert_ne!(corpus.chunk(s.index).unwrap().id, "pan");
        }
        // Hybrid surface.
        let hits = corpus.hybrid(query, Some(&qvec), &p, 10, &IdentityReranker);
        assert!(
            hits.iter().all(|c| c.id != "pan"),
            "regulated chunk leaked into hybrid results"
        );
        assert!(
            hits.iter().any(|c| c.id == "public-note"),
            "allowed doc should still surface"
        );
    }

    #[test]
    fn higher_clearance_sees_regulated_chunk() {
        let corpus = Corpus::new(vec![Chunk::new(
            "pan",
            "primary account number settlement",
            DataClass::RegulatedPayment,
        )]);
        // Admin ctor grants Pii clearance (>= RegulatedPayment).
        let admin = Principal::admin("root");
        let res = corpus.bm25("settlement account", &admin, 10);
        assert_eq!(res.len(), 1);
        assert_eq!(corpus.chunk(res[0].index).unwrap().id, "pan");

        // A principal whose clearance is exactly RegulatedPayment can see it too.
        let cleared = Principal::user("ops", &[]).with_clearance(DataClass::RegulatedPayment);
        assert_eq!(corpus.bm25("settlement account", &cleared, 10).len(), 1);
    }

    #[test]
    fn clearance_boundary_is_inclusive_and_exclusive() {
        let corpus = Corpus::new(vec![
            internal("i", "internal settlement data"),
            Chunk::new("c", "confidential settlement data", DataClass::Confidential),
        ]);
        // Internal clearance: sees internal, not confidential.
        let p_internal = Principal::user("u", &[]); // Internal
        let ids: Vec<String> = corpus
            .bm25("settlement data", &p_internal, 10)
            .iter()
            .map(|s| corpus.chunk(s.index).unwrap().id.clone())
            .collect();
        assert_eq!(ids, vec!["i"]);
        // Confidential clearance: sees both.
        let p_conf = Principal::user("u", &[]).with_clearance(DataClass::Confidential);
        assert_eq!(corpus.bm25("settlement data", &p_conf, 10).len(), 2);
    }

    #[test]
    fn hybrid_combines_lexical_and_dense() {
        let corpus = Corpus::new(vec![
            internal("lexwin", "unique keyword tokenizer settlement")
                .with_embedding(vec![0.0, 1.0]),
            internal("densewin", "generic text").with_embedding(vec![1.0, 0.0]),
        ]);
        let p = Principal::user("u", &[]);
        // Query text matches "lexwin" lexically; query vector matches "densewin".
        let hits = corpus.hybrid(
            "unique keyword tokenizer",
            Some(&[1.0, 0.0]),
            &p,
            10,
            &IdentityReranker,
        );
        let ids: Vec<&str> = hits.iter().map(|c| c.id.as_str()).collect();
        assert!(ids.contains(&"lexwin"));
        assert!(ids.contains(&"densewin"));
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn hybrid_lexical_only_when_no_query_vector() {
        let corpus = payments_corpus();
        let p = Principal::user("u", &[]);
        let hits = corpus.hybrid("instant UPI transfer", None, &p, 10, &IdentityReranker);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].id, "upi");
    }

    #[test]
    fn custom_reranker_reorders_candidates() {
        struct BoostReranker {
            boost_id: String,
        }
        impl Reranker for BoostReranker {
            fn rerank(&self, _q: &str, mut cands: Vec<Candidate>) -> Vec<Candidate> {
                for c in &mut cands {
                    if c.id == self.boost_id {
                        c.score += 1000.0;
                    }
                }
                cands.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());
                cands
            }
        }
        let corpus = payments_corpus();
        let p = Principal::user("u", &[]);
        let base = corpus.hybrid("payment settlement", None, &p, 10, &IdentityReranker);
        assert!(base.len() >= 2);
        let boosted_id = base.last().unwrap().id.clone();
        let reranked = corpus.hybrid(
            "payment settlement",
            None,
            &p,
            10,
            &BoostReranker {
                boost_id: boosted_id.clone(),
            },
        );
        assert_eq!(
            reranked[0].id, boosted_id,
            "reranker should float the boosted doc to the top"
        );
    }

    fn cand(id: &str, text: &str, score: f64) -> Candidate {
        Candidate {
            id: id.into(),
            text: text.into(),
            data_class: DataClass::Internal,
            score,
        }
    }

    #[test]
    fn budget_fit_respects_cap() {
        let counter = WordTokenCounter;
        let ranked = vec![
            cand("a", "one two three four five", 5.0), // 5 tokens
            cand("b", "six seven eight", 4.0),         // 3 tokens
            cand("c", "nine ten eleven twelve", 3.0),  // 4 tokens
            cand("d", "thirteen", 2.0),                // 1 token
        ];
        let fitted = budget_fit(&ranked, 9, &counter);
        let total: usize = fitted.iter().map(|c| counter.count(&c.text)).sum();
        assert!(
            total <= 9,
            "budget fit must never exceed the cap (got {total})"
        );
        let ids: Vec<&str> = fitted.iter().map(|c| c.id.as_str()).collect();
        // a(5)+b(3)=8 fits; c(4) would overflow to 12 → skipped; d(1) fits → 9.
        assert!(ids.contains(&"a"));
        assert!(ids.contains(&"b"));
        assert!(ids.contains(&"d"));
        assert!(
            !ids.contains(&"c"),
            "an item that overflows the cap must be skipped"
        );
    }

    #[test]
    fn budget_fit_drops_oversized_single_item() {
        let counter = WordTokenCounter;
        let ranked = vec![cand("huge", "a b c d e f g h", 9.0), cand("tiny", "x", 1.0)];
        let fitted = budget_fit(&ranked, 3, &counter);
        let ids: Vec<&str> = fitted.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(
            ids,
            vec!["tiny"],
            "an item larger than the whole budget is never included"
        );
    }

    #[test]
    fn position_aware_places_best_at_edges() {
        let ranked = vec![
            cand("best", "t", 5.0),
            cand("second", "t", 4.0),
            cand("third", "t", 3.0),
            cand("fourth", "t", 2.0),
            cand("fifth", "t", 1.0),
        ];
        let arranged = position_aware(ranked);
        assert_eq!(
            arranged.first().unwrap().id,
            "best",
            "top result must sit at the front edge"
        );
        assert_eq!(
            arranged.last().unwrap().id,
            "second",
            "2nd result must sit at the back edge"
        );
        // Expected interleave: [best, third, fifth, fourth, second].
        let ids: Vec<&str> = arranged.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids, vec!["best", "third", "fifth", "fourth", "second"]);
    }

    #[test]
    fn empty_query_and_empty_corpus_are_safe() {
        let corpus = payments_corpus();
        let p = Principal::user("u", &[]);
        assert!(corpus.bm25("", &p, 10).is_empty());
        assert!(corpus.cosine(&[], &p, 10).is_empty());
        assert!(corpus
            .hybrid("", None, &p, 10, &IdentityReranker)
            .is_empty());

        let empty = Corpus::new(vec![]);
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
        assert!(empty.bm25("anything", &p, 10).is_empty());
        assert!(empty
            .hybrid("anything", Some(&[1.0]), &p, 10, &IdentityReranker)
            .is_empty());
    }

    #[test]
    fn top_n_truncates() {
        let corpus = payments_corpus();
        let p = Principal::user("u", &[]);
        let one = corpus.bm25("payment settlement bank UPI NEFT", &p, 1);
        assert_eq!(one.len(), 1);
    }

    #[test]
    fn lexical_reranker_floats_full_coverage_doc_and_preserves_candidates() {
        let input = vec![
            cand("partial", "settlement only", 5.0), // covers 1/3 query terms but has the top prior score
            cand("full", "instant upi settlement transfer", 1.0), // covers all 3
            cand("none", "weather forecast today", 4.0), // covers 0
        ];
        let out = LexicalReranker.rerank("upi settlement transfer", input);
        assert_eq!(
            out[0].id, "full",
            "the doc covering all query terms must rank first"
        );
        assert_eq!(
            out.last().unwrap().id,
            "none",
            "a doc covering no query term ranks last"
        );
        // ACL-preserving: exactly the same candidate set, nothing added or dropped.
        let mut ids: Vec<&str> = out.iter().map(|c| c.id.as_str()).collect();
        ids.sort_unstable();
        assert_eq!(ids, vec!["full", "none", "partial"]);
        // An empty query is a no-op (leaves the input order untouched).
        let same = LexicalReranker.rerank("", vec![cand("a", "x", 1.0), cand("b", "y", 2.0)]);
        assert_eq!(
            same.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(),
            vec!["a", "b"]
        );
    }

    // --- cross-encoder reranker seam (round-15 `context-fabric` LOW) ---------------

    struct FixedScoreClient {
        scores: Vec<f32>,
    }
    impl RerankClient for FixedScoreClient {
        fn score(&self, _query: &str, texts: &[String]) -> Result<Vec<f32>, String> {
            if texts.len() != self.scores.len() {
                return Err("length mismatch".into());
            }
            Ok(self.scores.clone())
        }
    }
    struct FailingClient;
    impl RerankClient for FailingClient {
        fn score(&self, _query: &str, _texts: &[String]) -> Result<Vec<f32>, String> {
            Err("rerank service unreachable".into())
        }
    }
    struct MisalignedClient;
    impl RerankClient for MisalignedClient {
        fn score(&self, _query: &str, _texts: &[String]) -> Result<Vec<f32>, String> {
            Ok(vec![1.0]) // deliberately wrong length vs. the candidate set
        }
    }

    #[test]
    fn r15_cross_encoder_reranker_reorders_by_model_score() {
        // A prior fused order [low, mid, high] that the cross-encoder model reverses — proving the
        // seam actually drives ranking from the model's score, not the prior candidate score.
        let input = vec![
            cand("low", "a", 1.0),
            cand("mid", "b", 2.0),
            cand("high", "c", 3.0),
        ];
        let client = FixedScoreClient {
            scores: vec![0.1, 0.5, 0.9],
        };
        let reranker = CrossEncoderReranker::new(&client);
        let out = reranker.rerank("q", input);
        assert_eq!(
            out.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(),
            vec!["high", "mid", "low"],
            "reordered strictly by the cross-encoder's returned score"
        );
        // ACL-preserving: exactly the same candidate set, nothing added or dropped.
        let mut ids: Vec<&str> = out.iter().map(|c| c.id.as_str()).collect();
        ids.sort_unstable();
        assert_eq!(ids, vec!["high", "low", "mid"]);
    }

    #[test]
    fn r15_cross_encoder_reranker_fails_open_never_admission() {
        // A `/rerank` transport failure degrades to the PRIOR order (fail-open) — a retrieval
        // read-filter/ordering concern must never drop candidates or block the turn on an outage.
        let input = vec![cand("a", "x", 1.0), cand("b", "y", 2.0)];
        let failing = CrossEncoderReranker::new(&FailingClient);
        let out = failing.rerank("q", input.clone());
        assert_eq!(
            out.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(),
            vec!["a", "b"]
        );

        // A malformed (wrong-length) response is treated identically to a transport failure — never
        // zipped onto candidates by position, which would silently mis-score them.
        let misaligned = CrossEncoderReranker::new(&MisalignedClient);
        let out2 = misaligned.rerank("q", input);
        assert_eq!(
            out2.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(),
            vec!["a", "b"]
        );
    }

    // --- embedding-version lifecycle -----------------------------------------------

    #[test]
    fn versioned_dense_never_compares_across_embedding_versions() {
        let v2 = EmbeddingVersion::new("nomic", 2);
        let v3 = EmbeddingVersion::new("nomic", 3);
        let corpus = Corpus::new(vec![
            Chunk::new("a", "alpha", DataClass::Internal)
                .with_versioned_embedding(vec![1.0, 0.0], v2.clone()),
            // Same dimension, same direction, but a DIFFERENT model version — comparing it to a
            // v3 query is meaningless and must be refused, not silently scored.
            Chunk::new("b", "beta", DataClass::Internal)
                .with_versioned_embedding(vec![1.0, 0.0], v3.clone()),
            // Unversioned legacy vector — also excluded from the versioned path.
            Chunk::new("c", "gamma", DataClass::Internal).with_embedding(vec![1.0, 0.0]),
        ]);
        let p = Principal::user("u", &[]);
        let res = corpus.cosine_versioned(&[1.0, 0.0], &v3, &p, 10);
        assert_eq!(res.len(), 1, "only the v3 chunk is comparable");
        assert_eq!(corpus.chunk(res[0].index).unwrap().id, "b");
    }

    #[test]
    fn stale_embeddings_lists_the_reembed_worklist() {
        let v2 = EmbeddingVersion::new("nomic", 2);
        let v3 = EmbeddingVersion::new("nomic", 3);
        let corpus = Corpus::new(vec![
            Chunk::new("uptodate", "x", DataClass::Internal)
                .with_versioned_embedding(vec![1.0], v3.clone()),
            Chunk::new("oldver", "y", DataClass::Internal).with_versioned_embedding(vec![1.0], v2),
            Chunk::new("noembed", "z", DataClass::Internal),
        ]);
        assert!(!corpus.is_embedding_uniform(&v3));
        let stale: Vec<&str> = corpus
            .stale_embeddings(&v3)
            .into_iter()
            .map(|i| corpus.chunk(i).unwrap().id.as_str())
            .collect();
        assert_eq!(
            stale,
            vec!["oldver", "noembed"],
            "old-version + no-embed need re-embed"
        );
    }

    #[test]
    fn versioned_dense_still_enforces_acl_prerank() {
        let v = EmbeddingVersion::new("m", 1);
        let corpus = Corpus::new(vec![
            Chunk::new("reg", "regulated", DataClass::RegulatedPayment)
                .with_versioned_embedding(vec![1.0, 0.0], v.clone()),
            Chunk::new("pub", "public", DataClass::Public)
                .with_versioned_embedding(vec![1.0, 0.0], v.clone()),
        ]);
        let p = Principal::user("u", &[]); // Internal clearance
        let res = corpus.cosine_versioned(&[1.0, 0.0], &v, &p, 10);
        assert!(
            res.iter()
                .all(|s| corpus.chunk(s.index).unwrap().id != "reg"),
            "the regulated chunk must never be scored, even in the versioned path"
        );
    }

    // --- two-phase eligible-floor budget fit (Gap [22]) ----------------------------

    fn wc() -> WordTokenCounter {
        WordTokenCounter
    }

    fn ranked3() -> Vec<Candidate> {
        vec![
            cand("a", "one two three four", 3.0), // 4 tokens
            cand("b", "five six", 2.0),           // 2 tokens
            cand("c", "seven eight nine", 1.0),   // 3 tokens
        ]
    }

    #[test]
    fn eligible_floor_is_narrowest_window() {
        let models = vec![
            EligibleModel::new("wide", 8000),
            EligibleModel::new("narrow", 6), // the floor
            EligibleModel::new("mid", 100),
        ];
        assert_eq!(eligible_floor_window(&models), Some(6));
        assert_eq!(eligible_floor_window(&[]), None);
    }

    #[test]
    fn floor_fit_never_exceeds_any_eligible_window_and_accounts_every_node() {
        let models = vec![
            EligibleModel::new("wide", 8000),
            EligibleModel::new("narrow", 6),
        ];
        let ranked = ranked3();
        let fitted = budget_fit_eligible(&ranked, &models, &wc());
        // Floor = 6 tokens: a(4) fits→4, b(2) fits→6, c(3) would overflow→dropped.
        assert!(fitted.used_tokens <= 6);
        assert!(
            fitted.used_tokens <= eligible_floor_window(&models).unwrap(),
            "must fit the narrowest eligible window"
        );
        // Every candidate is accounted for — nothing silently dropped.
        assert!(fitted.fully_accounted(ranked.len()));
        assert_eq!(fitted.lineage.len(), 3);
        assert_eq!(fitted.dropped_ids(), vec!["c"]);
        let included: Vec<&str> = fitted.included.iter().map(|c| c.id.as_str()).collect();
        assert!(included.contains(&"a") && included.contains(&"b") && !included.contains(&"c"));
    }

    #[test]
    fn refit_widens_on_confirmed_model_and_narrows_on_failover() {
        let ranked = ranked3(); // total 9 tokens
                                // Phase 1: floor of a narrow eligible set.
        let floor = refit(&ranked, 6, &wc());
        assert_eq!(floor.dropped_ids(), vec!["c"]);

        // Phase 2: the router confirms a WIDER model — re-fit includes everything.
        let confirmed = refit(&ranked, 9, &wc());
        assert!(
            confirmed.dropped_ids().is_empty(),
            "the wider window fits all"
        );
        assert_eq!(confirmed.used_tokens, 9);
        assert!(confirmed.fully_accounted(ranked.len()));

        // Failover: the fallback model is NARROWER than the primary — re-fit must shrink again,
        // and STILL never exceed the failover window, with every drop accounted.
        let failover = refit(&ranked, 4, &wc());
        assert!(failover.used_tokens <= 4);
        assert!(failover.fully_accounted(ranked.len()));
        // a(4) fits exactly; b and c drop.
        let inc: Vec<&str> = failover.included.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(inc, vec!["a"]);
        assert_eq!(failover.dropped_ids(), vec!["b", "c"]);
    }

    #[test]
    fn empty_eligible_set_includes_nothing() {
        let fitted = budget_fit_eligible(&ranked3(), &[], &wc());
        assert!(fitted.included.is_empty());
        assert_eq!(fitted.used_tokens, 0);
        // Still fully accounted — all three appear as dropped.
        assert!(fitted.fully_accounted(3));
        assert_eq!(fitted.dropped_ids().len(), 3);
    }

    // --- node/edge RBAC + department/ad_level pre-rank (CTX-10) ---------------------

    #[test]
    fn gap_ctx_10_node_edge_rbac_department_ad_level_prerank() {
        use crate::acl::{AccessContext, NodeAcl};
        // Two Internal-class docs matching the same query. One is department+seniority locked.
        // Would FAIL before this change: retrieve took only DataClass, so the locked node would
        // surface for anyone class-cleared.
        let corpus = Corpus::new(vec![
            internal("open", "settlement reconciliation nightly report"),
            internal("locked", "settlement reconciliation postmortem details").with_acl(
                NodeAcl::new()
                    .departments(&["settlement-eng"])
                    .max_ad_level(3),
            ),
        ]);

        // A class-cleared but wrong-department caller must NEVER see the locked node's existence.
        let outsider = AccessContext::new(DataClass::Internal, Some("hr"), Some(2), &[]);
        let hits = corpus.hybrid_ctx(
            "settlement reconciliation",
            None,
            &outsider,
            10,
            &IdentityReranker,
        );
        assert!(
            hits.iter().all(|c| c.id != "locked"),
            "wrong department leaked a locked node"
        );
        assert!(hits.iter().any(|c| c.id == "open"));

        // Right department but too junior (ad_level 5 > ceiling 3) → still denied.
        let junior = AccessContext::new(DataClass::Internal, Some("settlement-eng"), Some(5), &[]);
        assert!(corpus
            .hybrid_ctx(
                "settlement reconciliation",
                None,
                &junior,
                10,
                &IdentityReranker
            )
            .iter()
            .all(|c| c.id != "locked"));

        // Right department AND senior enough → can see it.
        let insider = AccessContext::new(DataClass::Internal, Some("settlement-eng"), Some(2), &[]);
        assert!(corpus
            .hybrid_ctx(
                "settlement reconciliation",
                None,
                &insider,
                10,
                &IdentityReranker
            )
            .iter()
            .any(|c| c.id == "locked"));

        // The bare-Principal path is fail-closed on the ad_level-gated node (no seniority claim).
        let p = Principal::user("u", &[]).with_department("settlement-eng");
        assert!(corpus
            .hybrid("settlement reconciliation", None, &p, 10, &IdentityReranker)
            .iter()
            .all(|c| c.id != "locked"));
    }

    // --- re-embed lifecycle → live pipeline (CTX-14) -------------------------------

    #[test]
    fn gap_ctx_14_reembed_pipeline_drives_index_to_uniform_version() {
        use crate::reembed::{migrate_to, Embedder};
        // A mixed-version index: one chunk already at v3, one at v2, one with no embedding.
        let v2 = EmbeddingVersion::new("nomic", 2);
        let v3 = EmbeddingVersion::new("nomic", 3);
        let corpus = Corpus::new(vec![
            Chunk::new("current", "already migrated", DataClass::Internal)
                .with_versioned_embedding(vec![1.0, 2.0], v3.clone()),
            Chunk::new("old", "needs re-embed", DataClass::Internal)
                .with_versioned_embedding(vec![9.0, 9.0], v2),
            Chunk::new("fresh", "brand new node", DataClass::Internal),
        ]);
        assert!(
            !corpus.is_embedding_uniform(&v3),
            "precondition: mixed-version index"
        );

        struct V3Embedder;
        impl Embedder for V3Embedder {
            fn embed(&self, text: &str) -> Option<Vec<f32>> {
                Some(vec![text.len() as f32, 3.0])
            }
            fn version(&self) -> EmbeddingVersion {
                EmbeddingVersion::new("nomic", 3)
            }
        }
        let report = migrate_to(&corpus, &v3, &V3Embedder);
        assert!(report.outcome.complete(), "all stale chunks re-embedded");
        assert!(
            report.uniform,
            "the corpus reached a single embedding version"
        );
        assert!(report.corpus.is_embedding_uniform(&v3));
        // The already-current chunk kept its original vector (not needlessly re-embedded).
        let current = report.corpus.chunk(0).unwrap();
        assert_eq!(current.embedding.as_deref(), Some(&[1.0f32, 2.0][..]));
    }
}
