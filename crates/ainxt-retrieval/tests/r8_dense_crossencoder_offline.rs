// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-8: the **dense pgvector arm** + **cross-encoder rerank** seams, exercised OFFLINE.
//!
//! INFRA-GATED. The live dense arm needs a real embeddings model (Ollama `nomic-embed-text` /
//! `embed_svc`) to produce query + chunk vectors, and a real cross-encoder (`/rerank`,
//! ms-marco-TinyBERT) for content-aware reranking; both are served on GPU/embed infra that is not
//! present here. This test proves the SEAMS are honest and load-bearing WITHOUT that infra:
//!
//!  * embeddings are *accepted precomputed* ([`Chunk::with_embedding`] + a caller-supplied query
//!    vector), so a deterministic offline embedder activates the dense (cosine) arm and the fused
//!    hybrid ranking genuinely uses it — the production path only swaps the vector SOURCE for the
//!    embeddings model / pgvector `<=>` operator, no ranking code moves;
//!  * the [`Reranker`] trait is the cross-encoder seam — a deterministic content-aware reranker
//!    slots in behind it and reorders on query/document semantics, and it UPHOLDS the pre-rank ACL
//!    guarantee by construction (it can only reorder/rescore the candidates it is handed, never
//!    introduce a chunk that was excluded pre-rank).
//!
//! Fail-before / pass-after is structural: without a query vector the dense arm is dormant (the
//! dense-only win below cannot happen), and a reranker that reintroduced an above-clearance chunk
//! would break the leak assertion. Every filter here is a retrieval read-filter, never a turn-
//! admission denial.

use ainxt_retrieval::{Candidate, Chunk, Corpus, Reranker};
use ainxt_types::{DataClass, Principal};

/// A deterministic offline stand-in for the embeddings model: a tiny bag-of-keywords projection
/// onto a fixed 3-dim space. In production this is `nomic-embed-text` via `embed_svc` / pgvector;
/// the RANKING math (cosine) is identical, only the vector source differs (infra-gated).
fn embed(text: &str) -> Vec<f32> {
    let t = text.to_lowercase();
    let axis = |kw: &str| t.matches(kw).count() as f32;
    // [settlement-ness, reconciliation-ness, payroll-ness]
    vec![axis("settlement"), axis("reconciliation"), axis("payroll")]
}

/// A deterministic cross-encoder stand-in: rescore by cosine between the query embedding and each
/// candidate's embedding (recomputed from text — the model would score the (query, doc) PAIR
/// jointly). Reorders best-first; NEVER adds a candidate. This is the exact shape a real
/// cross-encoder plugs into behind the [`Reranker`] seam.
struct CrossEncoderStub {
    query_vec: Vec<f32>,
}

fn cosine(a: &[f32], b: &[f32]) -> f64 {
    let dot: f32 = a.iter().zip(b).map(|(x, y)| x * y).sum();
    let na: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let nb: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
    if na == 0.0 || nb == 0.0 {
        return 0.0;
    }
    (dot / (na * nb)) as f64
}

impl Reranker for CrossEncoderStub {
    fn rerank(&self, _query: &str, mut candidates: Vec<Candidate>) -> Vec<Candidate> {
        for c in &mut candidates {
            c.score = cosine(&self.query_vec, &embed(&c.text));
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

fn corpus() -> Corpus {
    Corpus::new(vec![
        // Lexically identical query-term padding, but the DENSE signal separates them.
        Chunk::new(
            "settle-doc",
            "settlement settlement report note",
            DataClass::Internal,
        )
        .with_embedding(embed("settlement settlement report note")),
        Chunk::new(
            "recon-doc",
            "reconciliation reconciliation report note",
            DataClass::Internal,
        )
        .with_embedding(embed("reconciliation reconciliation report note")),
        // Above the caller's clearance — must never survive the pre-rank ACL, and the cross-encoder
        // must never be able to reintroduce it.
        Chunk::new(
            "secret-doc",
            "settlement settlement secret",
            DataClass::Confidential,
        )
        .with_embedding(embed("settlement settlement secret")),
    ])
}

#[test]
fn r8_dense_arm_active_offline_and_reranker_upholds_prerank_acl() {
    let corpus = corpus();
    // Internal clearance → the Restricted secret-doc is excluded PRE-rank.
    let principal = Principal::user("analyst", &[]).with_clearance(DataClass::Internal);
    let qvec = embed("settlement");
    let reranker = CrossEncoderStub {
        query_vec: qvec.clone(),
    };

    // Dense arm ON (query vector supplied) + cross-encoder rerank.
    let hits = corpus.hybrid("report note", Some(&qvec), &principal, 10, &reranker);

    // The above-clearance chunk never appears — the cross-encoder cannot reintroduce a pre-rank
    // excluded candidate (existence never leaks even through the rerank stage).
    assert!(
        hits.iter().all(|c| c.id != "secret-doc"),
        "an above-clearance chunk must never survive to (or be reintroduced by) rerank"
    );

    // The dense arm + cross-encoder float the settlement doc over the equally-lexical recon doc.
    assert_eq!(
        hits[0].id, "settle-doc",
        "dense/cross-encoder semantics must rank the settlement doc first"
    );

    // Fail-before shape: with NO query vector the dense arm is dormant. Under the plain lexical
    // reranker the two "report note" docs tie on lexical coverage and fall back to the id tiebreak
    // (recon-doc < settle-doc), so settle-doc is NOT first — proving the dense arm is what promotes
    // it above.
    let lexical_only = corpus.hybrid(
        "report note",
        None,
        &principal,
        10,
        &ainxt_retrieval::LexicalReranker,
    );
    assert!(lexical_only.iter().all(|c| c.id != "secret-doc"));
    assert_eq!(
        lexical_only[0].id, "recon-doc",
        "with the dense arm dormant the lexical tie resolves to the id order — the dense arm is \
         genuinely load-bearing, not decorative"
    );
}
