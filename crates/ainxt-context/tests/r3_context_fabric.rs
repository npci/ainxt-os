// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-3 context-fabric gap closures, exercised on the REAL public objects exactly as the
//! live serving path (`ainxt-chat`/`ainxt-runtimed`) would call them.
//!
//! - `r3_hybrid_retriever_live_entrypoint`: the production hybrid RRF + rerank retriever is
//!   reachable as a one-line drop-in over a Context-Fabric `Corpus`, with the pre-rank ACL and
//!   source/citation lineage carried through. (Gap: "Hybrid RRF+rerank retriever wired into the
//!   live serving path" — previously `HybridRetriever` had ZERO constructors outside its own
//!   crate; `hybrid_retriever`/`HybridRetriever::from_corpus` did not exist.)
//! - `r3_live_corpus_populated`: the corpus is populatable through a real load API, and an empty
//!   corpus grounds nothing (the exact daemon stub condition) while a populated one retrieves.
//!   (Gap: "Live retrieval corpus is populated" — `Corpus` had only `new()`/`with()`, no load
//!   API for a KB seeder to call.)
//!
//! Both fail to COMPILE before the closure (the referenced entrypoints did not exist) and pass
//! after — fail-before / pass-after on the real objects.

use ainxt_context::{assemble, hybrid_retriever, Chunk, Corpus, HybridRetriever, Retriever};
use ainxt_types::DataClass;

fn seeded_corpus() -> Corpus {
    // Populate via the corpus-load API (batch load), then incrementally add/ingest/extend —
    // the shapes a KB/config loader has when seeding the served corpus.
    let mut c = Corpus::load(vec![
        Chunk::new(
            "upi",
            "upi.md",
            "UPI enables instant bank transfer settlement",
            DataClass::Public,
        ),
        Chunk::new(
            "neft",
            "neft.md",
            "NEFT settles bank transfer in timed batches",
            DataClass::Public,
        ),
    ]);
    c.add(Chunk::new(
        "reg",
        "margins.md",
        "confidential settlement margin transfer detail",
        DataClass::RegulatedPayment,
    ));
    c.ingest(
        "rtgs",
        "rtgs.md",
        "RTGS is real time gross settlement transfer",
        DataClass::Public,
    );
    c.extend(vec![Chunk::new(
        "imps",
        "imps.md",
        "IMPS immediate mobile payment settlement transfer",
        DataClass::Internal,
    )]);
    c
}

#[test]
fn r3_hybrid_retriever_live_entrypoint() {
    let corpus = seeded_corpus();

    // The single ready drop-in the daemon calls in place of `Box::new(LexicalRetriever::new(..))`.
    let retriever = hybrid_retriever(&corpus);

    // A Public-cleared caller queries text that ALSO matches the RegulatedPayment chunk.
    let ctx = assemble("settlement transfer", &*retriever, DataClass::Public, 10);
    assert!(
        !ctx.is_empty(),
        "the hybrid engine must produce grounded context over the corpus"
    );

    // Pre-rank chunk-level ACL carries through: the regulated chunk is never scored/returned —
    // its very existence must not leak to a Public caller.
    assert!(
        ctx.chunks
            .iter()
            .all(|c| c.data_class.sensitivity() <= DataClass::Public.sensitivity()),
        "an above-clearance chunk must never surface (pre-rank ACL)"
    );
    assert!(
        ctx.chunks.iter().all(|c| c.id != "reg"),
        "the RegulatedPayment chunk must be filtered before ranking for a Public caller"
    );

    // Source labels are preserved for citations/lineage (retrieval corpus is source-agnostic).
    assert!(
        ctx.chunks
            .iter()
            .any(|c| c.id == "upi" && c.source == "upi.md"),
        "source label must be preserved through the hybrid adapter for citations"
    );
    assert_eq!(
        ctx.citations.len(),
        ctx.chunks.len(),
        "every grounded chunk is cited"
    );
    assert!(ctx.citations.iter().all(|c| !c.marker.is_empty()));

    // A cleared caller CAN reach the regulated chunk — proving the filter is clearance-driven,
    // not a blanket drop (the mandatory ACL seam is enforced, not bypassed).
    let cleared = HybridRetriever::from_corpus(&corpus);
    let hits = cleared.retrieve("margin transfer", DataClass::RegulatedPayment, 10);
    assert!(
        hits.iter().any(|h| h.chunk.id == "reg"),
        "a RegulatedPayment-cleared caller must be able to retrieve the regulated chunk"
    );
}

#[test]
fn r3_live_corpus_populated() {
    // The exact daemon stub condition: an empty corpus grounds nothing regardless of retriever.
    let empty = Corpus::new();
    assert!(empty.is_empty());
    assert_eq!(empty.len(), 0);
    let empty_ctx = assemble(
        "settlement transfer",
        &*hybrid_retriever(&empty),
        DataClass::Public,
        10,
    );
    assert!(
        empty_ctx.is_empty(),
        "an empty corpus must retrieve nothing (the stub we are closing)"
    );

    // Populated through the real corpus-load API → retrieval now returns real, grounded hits.
    let corpus = seeded_corpus();
    assert!(!corpus.is_empty());
    assert_eq!(
        corpus.len(),
        5,
        "load + add + ingest + extend all populate the corpus"
    );

    let ctx = assemble(
        "settlement transfer",
        &*hybrid_retriever(&corpus),
        DataClass::Public,
        10,
    );
    assert!(
        !ctx.chunks.is_empty(),
        "grounding must retrieve from the populated corpus — not the empty stub"
    );
    // Full lineage is recorded for every grounded node (audit / right-to-erasure).
    assert!(!ctx.lineage.is_empty());
    assert_eq!(ctx.contributed_chunk_ids().len(), ctx.chunks.len());
}
