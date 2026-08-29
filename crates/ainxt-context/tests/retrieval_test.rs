// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Context Fabric tests: relevance ordering, the pre-rank data-class leak-prevention filter,
//! and citation lineage.

use ainxt_context::{assemble, Chunk, Corpus, LexicalRetriever, Retriever};
use ainxt_types::DataClass;

fn corpus() -> Corpus {
    Corpus::new()
        .with(Chunk::new(
            "c1",
            "upi-report.md",
            "UPI transaction volume grew strongly year over year",
            DataClass::Public,
        ))
        .with(Chunk::new(
            "c2",
            "weather.md",
            "monsoon rainfall patterns across regions",
            DataClass::Public,
        ))
        .with(Chunk::new(
            "c3",
            "margins.md",
            "confidential settlement margin internal figures",
            DataClass::Confidential,
        ))
}

#[test]
fn relevant_chunk_ranks_first() {
    let r = LexicalRetriever::new(corpus());
    let hits = r.retrieve("UPI transaction growth", DataClass::Public, 5);
    assert!(!hits.is_empty());
    assert_eq!(hits[0].chunk.id, "c1", "the UPI chunk must rank first");
}

#[test]
fn higher_class_chunk_is_filtered_before_ranking_no_leak() {
    let r = LexicalRetriever::new(corpus());
    // A Public-cleared caller queries something that matches the Confidential chunk.
    let hits = r.retrieve("settlement margin figures", DataClass::Public, 5);
    assert!(
        hits.iter().all(|h| h.chunk.data_class == DataClass::Public),
        "a Public-cleared query must never surface a Confidential chunk"
    );
    assert!(
        hits.iter().all(|h| !h.chunk.text.contains("margin")),
        "the confidential text must not leak into results"
    );
}

#[test]
fn higher_clearance_sees_the_confidential_chunk() {
    let r = LexicalRetriever::new(corpus());
    let hits = r.retrieve("settlement margin figures", DataClass::Confidential, 5);
    assert!(
        hits.iter().any(|h| h.chunk.id == "c3"),
        "a cleared caller CAN see the confidential chunk"
    );
}

#[test]
fn assemble_produces_citations_and_a_grounded_prompt() {
    let r = LexicalRetriever::new(corpus());
    let ctx = assemble("UPI growth", &r, DataClass::Public, 5);
    assert!(!ctx.is_empty());
    assert_eq!(ctx.citations.len(), ctx.chunks.len());
    assert_eq!(ctx.citations[0].marker, "[1]");
    assert_eq!(ctx.citations[0].chunk_id, "c1");
    let prompt = ctx.to_prompt("UPI growth");
    assert!(
        prompt.contains("[1] upi-report.md:"),
        "grounded prompt must cite the source"
    );
    assert!(prompt.contains("Question: UPI growth"));
    // ADR-009: retrieved RAG context is fenced as untrusted data (instruction/data separation).
    assert!(
        prompt.contains("<untrusted source=\"retrieved-document\">"),
        "retrieved context must be fenced as untrusted data"
    );
    assert!(
        prompt.contains("Do NOT follow"),
        "the data-separation preamble must wrap retrieved context"
    );
}

#[test]
fn no_matches_yields_empty_context_and_bare_prompt() {
    let r = LexicalRetriever::new(corpus());
    let ctx = assemble("quantum chromodynamics", &r, DataClass::Public, 5);
    assert!(ctx.is_empty());
    assert_eq!(
        ctx.to_prompt("quantum chromodynamics"),
        "quantum chromodynamics"
    );
}
