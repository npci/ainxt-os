// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-8 gap closure: the LIVE grounded path carries per-node RBAC (department / `ad_level` /
//! allow-deny groups) **and** row-level-security row attributes THROUGH TO PRE-RANK.
//!
//! The served chat/voice surface grounds over an `ainxt_context::Corpus` seeded by the daemon's
//! `corpus_for_scope`, adapted onto the real retrieval engine via
//! [`ainxt_context::Corpus::to_retrieval_corpus`] / [`ainxt_context::hybrid_retriever`]. Before this
//! round that adapter carried the node [`NodeAcl`] but **dropped every row attribute** — so the RLS
//! [`RowFilter`] bound from the OBO principal fail-closed on ALL rows (a caller could not even read
//! their OWN department's rows), and RLS was structurally inert on the live path.
//!
//! This test drives the SINGLE [`compile_window`] entrypoint over a Context-Fabric [`Corpus`] built
//! with `ainxt_context::Chunk` (the exact shape `corpus_for_scope` produces once hot-wired to
//! preserve ACL+attributes) and proves:
//!
//!  * the rightful caller's own-department node **grounds** — the row attribute survived the
//!    context→retrieval mapping, so the RLS filter permits it (the behavioral fail-before: without
//!    attribute carry-through this node is denied and the window is empty);
//!  * a wrong-department row (RLS attribute mismatch) and a wrong-department / too-junior node
//!    (NodeAcl) **never appear anywhere** — ranked, chunks, citations, or lineage — existence never
//!    leaks;
//!  * the same guarantees hold through BOTH exposed builders (`to_retrieval_corpus` and the boxed
//!    `hybrid_retriever`), so the runtimed call-site can adopt either.
//!
//! Fails to COMPILE before the closure (`Chunk::with_attribute` / `Corpus::to_retrieval_corpus` did
//! not exist) and, once built, fails behaviorally without the attribute carry-through (the rightful
//! caller grounds nothing). Every filter here is a retrieval read-filter, never a turn-admission
//! denial.

use std::collections::BTreeMap;

use ainxt_context::{
    compile_window, hybrid_retriever, AccessContext, Chunk, CompileRequest, Corpus, NodeAcl,
    OptimizerConfig, Retriever, RowFilter,
};
use ainxt_retrieval::{EligibleModel, WordTokenCounter};
use ainxt_types::{DataClass, Principal};

/// A Context-Fabric corpus in the shape the daemon `corpus_for_scope` produces once hot-wired to
/// preserve ACL + attributes: each chunk carries a per-node [`NodeAcl`] AND a `department` row
/// attribute for the RLS row-filter.
fn context_corpus() -> Corpus {
    Corpus::load(vec![
        // settlement-eng, senior-gated, row-scoped to settlement-eng — the rightful caller's node.
        Chunk::new(
            "own-dept",
            "settlement",
            "settlement failure postmortem",
            DataClass::Internal,
        )
        .with_acl(
            NodeAcl::new()
                .departments(&["settlement-eng"])
                .max_ad_level(3),
        )
        .with_attribute("department", "settlement-eng"),
        // Node-ACL locks this to a MORE senior tier → denied for an ad_level-3 caller (node RBAC).
        Chunk::new(
            "exec-only",
            "settlement",
            "settlement failure postmortem",
            DataClass::Internal,
        )
        .with_acl(
            NodeAcl::new()
                .departments(&["settlement-eng"])
                .max_ad_level(1),
        )
        .with_attribute("department", "settlement-eng"),
        // Wrong RLS row scope (hr row) → denied by the department-isolation row-filter (RLS).
        Chunk::new(
            "hr-row",
            "settlement",
            "settlement failure postmortem",
            DataClass::Internal,
        )
        .with_attribute("department", "hr"),
    ])
}

/// The rightful caller: cleared Internal, in settlement-eng, senior enough (ad_level 3), OBO-bound
/// for RLS department isolation.
fn rightful() -> (AccessContext, RowFilter) {
    let principal = Principal::user("analyst", &[]).with_department("settlement-eng");
    let row_filter = RowFilter::department_isolation(&principal);
    let access = AccessContext::new(DataClass::Internal, Some("settlement-eng"), Some(3), &[]);
    (access, row_filter)
}

fn cfg() -> OptimizerConfig {
    OptimizerConfig {
        eligible: vec![EligibleModel::new("m", 8000)],
        graph_weight: 0.0,
        prefer_fresh: false,
        ..OptimizerConfig::default()
    }
}

fn assert_only_own_dept_grounds(retriever: &dyn Retriever) {
    let (access, row_filter) = rightful();
    let counter = WordTokenCounter;
    let seeds = BTreeMap::new();
    let req = CompileRequest {
        access: &access,
        row_filter: Some(&row_filter),
        graph: None,
        seeds: &seeds,
    };
    let w = compile_window("settlement failure", retriever, &cfg(), &counter, &req);

    // The rightful caller's own-department node grounds — the row ATTRIBUTE survived the
    // context→retrieval mapping, so the RLS filter permits it. This is the behavioral fail-before:
    // without attribute carry-through the RLS filter fail-closes on the missing attribute and this
    // assertion fails (the window is empty).
    assert!(
        w.context.chunks.iter().any(|c| c.id == "own-dept"),
        "the rightful caller must ground their OWN department's row — the RLS attribute must survive \
         the live context->retrieval corpus mapping"
    );

    // The node-ACL-locked node and the wrong-RLS-row node never appear ANYWHERE — existence never
    // leaks through ranked / chunks / citations / lineage.
    for leaked in ["exec-only", "hr-row"] {
        assert!(
            w.ranked.iter().all(|c| c.id != leaked),
            "{leaked} leaked into ranked"
        );
        assert!(
            w.context.chunks.iter().all(|c| c.id != leaked),
            "{leaked} leaked into chunks"
        );
        assert!(
            w.context.citations.iter().all(|c| c.chunk_id != leaked),
            "{leaked} leaked into citations"
        );
        assert!(
            w.context.lineage.iter().all(|n| n.chunk_id != leaked),
            "{leaked} leaked into lineage"
        );
    }
}

#[test]
fn r8_to_retrieval_corpus_preserves_acl_and_attributes_prerank() {
    // The exposed corpus builder the runtimed `corpus_for_scope` adopts.
    let rcorpus = context_corpus().to_retrieval_corpus();
    let hybrid = ainxt_context::HybridRetriever::from_retrieval_corpus(rcorpus);
    assert_only_own_dept_grounds(&hybrid);
}

#[test]
fn r8_hybrid_retriever_builder_preserves_acl_and_attributes_prerank() {
    // The boxed ready-retriever builder (the drop-in the daemon assembly calls).
    let corpus = context_corpus();
    let retriever = hybrid_retriever(&corpus);
    assert_only_own_dept_grounds(retriever.as_ref());
}

#[test]
fn r8_wrong_department_caller_grounds_nothing_existence_never_leaks() {
    // A caller in another department (cleared, senior) grounds NOTHING: the node-ACL denies the
    // settlement-eng nodes on the department axis, and the RLS filter (bound to "risk-eng") denies
    // the settlement-eng rows on the row axis. No count/score gap reveals the locked nodes.
    let corpus = context_corpus();
    let retriever = hybrid_retriever(&corpus);
    let counter = WordTokenCounter;
    let principal = Principal::user("outsider", &[]).with_department("risk-eng");
    let row_filter = RowFilter::department_isolation(&principal);
    let access = AccessContext::new(DataClass::Internal, Some("risk-eng"), Some(1), &[]);
    let seeds = BTreeMap::new();
    let req = CompileRequest {
        access: &access,
        row_filter: Some(&row_filter),
        graph: None,
        seeds: &seeds,
    };
    let w = compile_window(
        "settlement failure",
        retriever.as_ref(),
        &cfg(),
        &counter,
        &req,
    );
    assert!(
        w.context.is_empty(),
        "a wrong-department caller grounds nothing — node-ACL + RLS both filter pre-rank on the live \
         path; existence never leaks"
    );
}
