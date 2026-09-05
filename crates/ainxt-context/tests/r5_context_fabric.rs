// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-5 gap closure: the SINGLE Context-Fabric compile entrypoint
//! ([`ainxt_context::compile_window`]) carries ALL of a turn's fabric concerns in one call, over the
//! REAL production hybrid engine ([`HybridRetriever`]):
//!
//! 1. **Pre-rank node/department/`ad_level`/group RBAC** driven by the caller's full
//!    [`AccessContext`] — not just the data-class scalar (the served gap: the old synthetic
//!    `Principal::user("ctx-hybrid", &[])` dropped department/seniority/groups).
//! 2. **RLS row-filter** applied in the SAME pre-rank pass.
//! 3. **Cross-graph personalized PageRank** fused into ranking.
//! 4. **Two-phase budget fit against the eligible-model set** (fit-to-eligible-floor, fully
//!    accounted, re-fittable).
//! 5. **Numeric-claim contract + server-side re-derivation gate** on the SAME returned window.
//!
//! A node the caller may not see on ANY axis is never scored, ranked, positioned, fitted, cited, or
//! recorded in the lineage — existence never leaks. Fails to COMPILE before the closure
//! (`compile_window` / `CompileRequest` / `Retriever::retrieve_ctx` / re-exported `AccessContext`
//! did not exist); passes after — fail-before / pass-after on the real objects. Every filter here is
//! a retrieval read-filter, never a turn-admission denial.

use std::collections::BTreeMap;

use ainxt_context::optimizer::{GraphLayer, RankGraph};
use ainxt_context::{
    compile_window, AccessContext, ClaimSource, CompileRequest, HybridRetriever, NodeAcl,
    NumericClaim, OptimizerConfig, Rederiver, RowFilter, Tolerance, ValueClass,
};
use ainxt_retrieval::{Chunk as RChunk, Corpus as RCorpus, EligibleModel, WordTokenCounter};
use ainxt_types::{DataClass, Principal};

struct MapRederiver {
    truth: BTreeMap<String, f64>,
}
impl Rederiver for MapRederiver {
    fn rederive(&self, source: &ClaimSource) -> Option<f64> {
        self.truth.get(&source.rederive_key()?).copied()
    }
}

/// A settlement-eng, on-call node visible at ad_level <= 3, row-scoped to settlement-eng.
fn oncall_node(id: &str) -> RChunk {
    RChunk::new(id, "settlement failure", DataClass::Internal)
        .with_acl(
            NodeAcl::new()
                .departments(&["settlement-eng"])
                .max_ad_level(3)
                .allow_groups(&["settlement-oncall"]),
        )
        .with_attribute("department", "settlement-eng")
}

fn corpus() -> RCorpus {
    RCorpus::new(vec![
        oncall_node("graph-hit"),  // reachable from the PageRank seed
        oncall_node("graph-miss"), // equally lexical, NOT seeded
        // Locked to a more senior tier → denied for an ad_level-3 caller.
        RChunk::new("exec-only", "settlement failure", DataClass::Internal)
            .with_acl(
                NodeAcl::new()
                    .departments(&["settlement-eng"])
                    .max_ad_level(2),
            )
            .with_attribute("department", "settlement-eng"),
        // Wrong RLS row scope → denied by the row-filter.
        RChunk::new("hr-row", "settlement failure", DataClass::Internal)
            .with_attribute("department", "hr"),
    ])
}

#[test]
fn r5_compile_window_unified() {
    let hybrid = HybridRetriever::from_retrieval_corpus(corpus());
    let counter = WordTokenCounter;

    // OBO principal → binds the RLS department-isolation session.
    let principal = Principal::user("analyst", &[]).with_department("settlement-eng");
    let row_filter = RowFilter::department_isolation(&principal);

    // Full OBO access claims: senior enough (ad_level 3) + the on-call group.
    let access = AccessContext::new(
        DataClass::Internal,
        Some("settlement-eng"),
        Some(3),
        &["settlement-oncall"],
    );

    // Cross-graph: seed the PageRank on "graph-hit" so it must outrank the equally-lexical miss.
    let graph = RankGraph::new()
        .with_node("graph-hit")
        .with_node("graph-miss");
    let mut seeds = BTreeMap::new();
    seeds.insert("graph-hit".to_string(), 1.0);

    let cfg = OptimizerConfig {
        // Two admitted chunks × 2 tokens = 4; the narrow floor (3) fits one and forces an accounted drop.
        eligible: vec![
            EligibleModel::new("wide", 8000),
            EligibleModel::new("narrow", 3),
        ],
        prefer_fresh: false,
        graph_weight: 5.0,
        ..OptimizerConfig::default()
    };

    let req = CompileRequest {
        access: &access,
        row_filter: Some(&row_filter),
        graph: Some(&graph),
        seeds: &seeds,
    };
    let window = compile_window("settlement failure", &hybrid, &cfg, &counter, &req);

    // (1)+(2) Pre-rank RBAC + RLS: the denied nodes never appear ANYWHERE — ranked, chunks,
    // citations, or lineage. Existence never leaks.
    for leaked in ["exec-only", "hr-row"] {
        assert!(
            window.ranked.iter().all(|c| c.id != leaked),
            "{leaked} leaked into ranked"
        );
        assert!(
            window.context.chunks.iter().all(|c| c.id != leaked),
            "{leaked} leaked into chunks"
        );
        assert!(
            window
                .context
                .citations
                .iter()
                .all(|c| c.chunk_id != leaked),
            "{leaked} cited"
        );
        assert!(
            window.context.lineage.iter().all(|n| n.chunk_id != leaked),
            "{leaked} in lineage"
        );
    }
    // The two admitted nodes DID pass every axis.
    assert!(window.ranked.iter().any(|c| c.id == "graph-hit"));
    assert!(window.ranked.iter().any(|c| c.id == "graph-miss"));

    // (3) Cross-graph PageRank reordered the seeded node to the top of an otherwise-lexical tie.
    assert_eq!(
        window.ranked[0].id, "graph-hit",
        "personalized PageRank must float the seeded node"
    );

    // (4) Two-phase fit to the narrowest eligible window, fully accounted (nothing silently dropped).
    assert_eq!(window.window_tokens, 3, "fit to the eligible floor");
    assert!(window.fitted.used_tokens <= 3);
    assert!(
        window.fitted.fully_accounted(2),
        "both admitted candidates accounted for"
    );
    assert!(
        !window.fitted.dropped_ids().is_empty(),
        "the narrow floor forces an accounted drop"
    );
    // The plan is computed on the same entrypoint.
    assert!(window.plan.includes(GraphLayer::Conversation));

    // A wider model re-fit admits both, without re-retrieving.
    let confirmed = window.refit_to(&EligibleModel::new("wide", 8000), &counter);
    assert!(
        confirmed.fitted.dropped_ids().is_empty(),
        "the wide window fits both admitted nodes"
    );

    // (5) Numeric gate on the SAME window: a re-derived match ships; a mismatch blocks.
    let answer = "There were 47 failed settlements.";
    let claims = vec![NumericClaim::metric(
        47.0,
        "count",
        ValueClass::Exact,
        "failed_settlement_count",
        "h1",
    )];
    let good = MapRederiver {
        truth: [("metric:failed_settlement_count:h1".to_string(), 47.0)]
            .into_iter()
            .collect(),
    };
    assert!(
        window
            .verify_answer(answer, &claims, &good, &Tolerance::default())
            .ships(),
        "a server-re-derived matching number ships"
    );
    let bad = MapRederiver {
        truth: [("metric:failed_settlement_count:h1".to_string(), 52.0)]
            .into_iter()
            .collect(),
    };
    let blocked = window.verify_answer(answer, &claims, &bad, &Tolerance::default());
    assert!(
        !blocked.ships(),
        "a server/model numeric mismatch blocks the answer"
    );
    assert!(
        blocked.blocked_on_mismatch(),
        "mismatch is the payments-incident signal"
    );
}

#[test]
fn r5_compile_window_enforces_the_rbac_axes_live() {
    // The RBAC axes are actually evaluated on the single entrypoint, not decoration: dropping the
    // caller's seniority or group makes the otherwise-permitted nodes vanish — the exact axes the
    // old synthetic-Principal served path could never prove.
    let hybrid = HybridRetriever::from_retrieval_corpus(corpus());
    let counter = WordTokenCounter;
    let principal = Principal::user("analyst", &[]).with_department("settlement-eng");
    let row_filter = RowFilter::department_isolation(&principal);
    let cfg = OptimizerConfig {
        eligible: vec![EligibleModel::new("m", 8000)],
        graph_weight: 0.0,
        prefer_fresh: false,
        ..OptimizerConfig::default()
    };
    let empty_seeds = BTreeMap::new();

    // Senior + on-call → the ad_level<=3 on-call nodes are grounded.
    let full = AccessContext::new(
        DataClass::Internal,
        Some("settlement-eng"),
        Some(3),
        &["settlement-oncall"],
    );
    let req = CompileRequest {
        access: &full,
        row_filter: Some(&row_filter),
        graph: None,
        seeds: &empty_seeds,
    };
    let w = compile_window("settlement failure", &hybrid, &cfg, &counter, &req);
    assert!(
        w.context.chunks.iter().any(|c| c.id == "graph-hit"),
        "a fully-qualified caller grounds the node"
    );

    // Same clearance + department, but junior (ad_level 5) → the ad_level ceiling denies pre-rank.
    let junior = AccessContext::new(
        DataClass::Internal,
        Some("settlement-eng"),
        Some(5),
        &["settlement-oncall"],
    );
    let req_j = CompileRequest {
        access: &junior,
        row_filter: Some(&row_filter),
        graph: None,
        seeds: &empty_seeds,
    };
    let wj = compile_window("settlement failure", &hybrid, &cfg, &counter, &req_j);
    assert!(
        wj.context.is_empty(),
        "a junior caller grounds nothing — the ad_level axis is live on compile_window"
    );

    // Senior but missing the on-call group → the allow-group axis denies pre-rank.
    let no_group = AccessContext::new(DataClass::Internal, Some("settlement-eng"), Some(3), &[]);
    let req_g = CompileRequest {
        access: &no_group,
        row_filter: Some(&row_filter),
        graph: None,
        seeds: &empty_seeds,
    };
    let wg = compile_window("settlement failure", &hybrid, &cfg, &counter, &req_g);
    assert!(
        wg.context.is_empty(),
        "missing the allow-group grounds nothing — the group axis is live"
    );
}
