// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-16 HIGH (`context-fabric`): **the dense arm and the cross-encoder rerank are reachable
//! through the Context Fabric.**
//!
//! `CONTEXT_FABRIC.md` §2 layer 11 specifies hybrid RAG as pgvector HNSW + BM25 → RRF → rerank.
//! What shipped: `HybridRetriever::from_corpus` always set `embedder: None` and every retrieval
//! call site hardcoded `LexicalReranker` with no injection point, so the fabric could only ever run
//! the lexical arms; `CrossEncoderReranker` had zero call sites outside its own unit tests and,
//! being lifetime-bound to a borrowed client, could not even be stored on a retriever.
//!
//! Fail-before / pass-after: `hybrid_retriever_full`, `HybridRetriever::with_reranker` and
//! `ainxt_retrieval::SharedCrossEncoderReranker` did not exist. This test drives a cross-encoder
//! whose scores DISAGREE with the lexical order and asserts the fabric honors it — impossible
//! before, because the reranker was not injectable.
//!
//! Reranking is a retrieval read-filter/ordering concern: a `/rerank` outage degrades to the fused
//! order (fail-open), it never blocks a turn or drops a candidate.

use ainxt_context::{
    hybrid_retriever, hybrid_retriever_full, Chunk, Corpus, HybridRetriever, QueryEmbedder,
    Retriever,
};
use ainxt_retrieval::{RerankClient, SharedCrossEncoderReranker};
use ainxt_types::DataClass;
use std::sync::Arc;

fn corpus() -> Corpus {
    Corpus::new()
        .with(Chunk::new(
            "settlement-a",
            "runbook-a.md",
            "settlement settlement settlement retry runbook",
            DataClass::Public,
        ))
        .with(Chunk::new(
            "settlement-b",
            "postmortem-b.md",
            "settlement outage root cause analysis",
            DataClass::Public,
        ))
}

/// A cross-encoder that deliberately DISAGREES with the lexical ranking: it prefers whichever text
/// mentions "root cause", which BM25 term-frequency ranks second.
struct SemanticRerank;

impl RerankClient for SemanticRerank {
    fn score(&self, _query: &str, texts: &[String]) -> Result<Vec<f32>, String> {
        Ok(texts
            .iter()
            .map(|t| if t.contains("root cause") { 0.99 } else { 0.10 })
            .collect())
    }
}

/// A cross-encoder service that is DOWN — the fail-open case.
struct DeadRerank;

impl RerankClient for DeadRerank {
    fn score(&self, _query: &str, _texts: &[String]) -> Result<Vec<f32>, String> {
        Err("rerank service unavailable".to_string())
    }
}

struct FixedEmbedder;

impl QueryEmbedder for FixedEmbedder {
    fn embed(&self, _query: &str) -> Option<Vec<f32>> {
        Some(vec![1.0, 0.0, 0.0])
    }
}

fn ids(r: &dyn Retriever) -> Vec<String> {
    r.retrieve("settlement failure", DataClass::Public, 5)
        .into_iter()
        .map(|s| s.chunk.id)
        .collect()
}

#[test]
fn r16_fabric_hybrid_arm_honors_the_injected_cross_encoder() {
    // The fabric's default retriever: lexical arms only. Term frequency puts `settlement-a` first.
    let lexical = hybrid_retriever(&corpus());
    let lexical_order = ids(lexical.as_ref());
    assert_eq!(
        lexical_order.first().map(String::as_str),
        Some("settlement-a"),
        "baseline lexical order"
    );

    // With the real cross-encoder injected, the fabric's ordering follows the MODEL's relevance,
    // not term frequency — the layer-11 rerank stage is now actually on the path.
    let reranked = hybrid_retriever_full(
        &corpus(),
        None,
        Some(Box::new(SharedCrossEncoderReranker::new(Arc::new(
            SemanticRerank,
        )))),
    );
    let reranked_order = ids(reranked.as_ref());
    assert_eq!(
        reranked_order.first().map(String::as_str),
        Some("settlement-b"),
        "the cross-encoder's ordering must reach the fabric: {reranked_order:?}"
    );
    assert_eq!(
        reranked_order.len(),
        lexical_order.len(),
        "a reranker only reorders — it never drops a candidate"
    );
}

#[test]
fn r16_rerank_outage_degrades_the_order_and_never_blocks() {
    // Fail-OPEN: a dead /rerank service leaves the fused order intact and every candidate present.
    let dead = hybrid_retriever_full(
        &corpus(),
        None,
        Some(Box::new(SharedCrossEncoderReranker::new(Arc::new(
            DeadRerank,
        )))),
    );
    let order = ids(dead.as_ref());
    assert_eq!(order.len(), 2, "a rerank outage must not drop candidates");
    assert!(order.contains(&"settlement-a".to_string()));
    assert!(order.contains(&"settlement-b".to_string()));
}

#[test]
fn r16_dense_and_rerank_arms_report_honestly() {
    // The composition root can now ASK which arms are live instead of assuming them.
    let plain = HybridRetriever::from_corpus(&corpus());
    assert!(!plain.has_dense_arm());
    assert!(!plain.has_reranker());

    let full = HybridRetriever::from_corpus(&corpus())
        .with_embedder(Box::new(FixedEmbedder))
        .with_reranker(Box::new(SharedCrossEncoderReranker::new(Arc::new(
            SemanticRerank,
        ))));
    assert!(
        full.has_dense_arm(),
        "the dense arm is injectable through the fabric"
    );
    assert!(full.has_reranker());

    // And it still retrieves (the dense arm fuses with BM25 rather than replacing it).
    let hits = full.retrieve("settlement failure", DataClass::Public, 5);
    assert_eq!(hits.len(), 2);
}
