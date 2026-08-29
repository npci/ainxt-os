// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-11 Context-Fabric gap closures, verified on the real objects the served grounding path
//! drives. Each test fails before its closure (a new entrypoint/behavior) and passes after.
//!
//!  * **Node-RBAC `ad_level` + allow/deny groups on the LIVE grounding path** — the served path
//!    builds its [`AccessContext`] via [`AccessContext::from_principal`] (`ainxt-convo`'s
//!    `assemble_grounding`). Before the closure that dropped the seniority + group claims, so an
//!    `ad_level`/group-gated node was unenforceable (the entitled senior lost grounding; the axes
//!    never bound). Now [`Principal`] carries `ad_level`+`groups` and `from_principal` reads them.
//!  * **Multi-graph fabric as a live retrieval source + query planning routes retrieval** — the
//!    [`MultiGraphFabric`] is retrieved over; an out-of-plan layer is never scored.
//!  * **Cross-graph personalized PageRank on the served path** — the routed call fuses PageRank from
//!    the fabric's edges/seeds (dormant before: the served call passed `graph = None`).
//!  * **Global/sensemaking + multimodal-artifact tiers routed + RBAC-filtered.**
//!  * **Two-phase budget fit driven on model-confirm + every failover.**
//!  * **Conflict arbitration by authority/recency** (not merely a freshness bonus).

use std::collections::BTreeMap;

use ainxt_context::artifact::{Artifact, ArtifactStore, Modality};
use ainxt_context::optimizer::{EdgeKind, FabricGraph, GraphLayer};
use ainxt_context::route::MultiGraphFabric;
use ainxt_context::{
    compile_window, AccessContext, Chunk, CompileRequest, LineageOutcome, NodeAcl, OptimizerConfig,
};
use ainxt_retrieval::{EligibleModel, WordTokenCounter};
use ainxt_types::{DataClass, Principal};

fn cfg() -> OptimizerConfig {
    OptimizerConfig {
        eligible: vec![EligibleModel::new("m", 8000)],
        ..OptimizerConfig::default()
    }
}

// ============================ gap 1: ad_level + groups on the live grounding path ================

#[test]
fn r11_node_rbac_ad_level_and_groups_enforced_via_from_principal() {
    // A node gated on ALL three orthogonal axes: department, seniority ceiling, and an allow-group.
    let corpus = ainxt_context::Corpus::load(vec![Chunk::new(
        "postmortem",
        "settlement.md",
        "settlement failure postmortem detail",
        DataClass::Internal,
    )
    .with_acl(
        NodeAcl::new()
            .departments(&["settlement-eng"])
            .max_ad_level(3)
            .allow_groups(&["oncall"]),
    )]);
    let retriever = ainxt_context::hybrid_retriever(&corpus);
    let counter = WordTokenCounter;
    let seeds = BTreeMap::new();
    let ground = |p: &Principal| {
        // The LIVE served builder — the exact call `assemble_grounding` makes every turn.
        let access = AccessContext::from_principal(p);
        let req = CompileRequest {
            access: &access,
            row_filter: None,
            graph: None,
            seeds: &seeds,
        };
        compile_window(
            "settlement failure",
            retriever.as_ref(),
            &cfg(),
            &counter,
            &req,
        )
        .context
        .chunks
        .iter()
        .any(|c| c.id == "postmortem")
    };

    // Entitled: settlement-eng, senior enough (ad_level 2 <= 3), in the oncall allow-group → grounds.
    let entitled = Principal::user("sr", &[])
        .with_clearance(DataClass::Internal)
        .with_department("settlement-eng")
        .with_ad_level(2)
        .with_groups(&["oncall"]);
    assert!(
        ground(&entitled),
        "the entitled senior in the allow-group must ground the node — before the closure \
         from_principal dropped ad_level/groups and this node was denied to everyone"
    );

    // Too junior (ad_level 5 > 3): filtered pre-rank, existence never leaks.
    let junior = Principal::user("jr", &[])
        .with_clearance(DataClass::Internal)
        .with_department("settlement-eng")
        .with_ad_level(5)
        .with_groups(&["oncall"]);
    assert!(
        !ground(&junior),
        "a too-junior caller must be filtered on the seniority axis"
    );

    // Right seniority + department but NOT in the allow-group: filtered on the group axis.
    let no_group = Principal::user("x", &[])
        .with_clearance(DataClass::Internal)
        .with_department("settlement-eng")
        .with_ad_level(2);
    assert!(
        !ground(&no_group),
        "a caller outside the allow-group must be filtered"
    );

    // Deny-group wins unconditionally.
    let denied_corpus = ainxt_context::Corpus::load(vec![Chunk::new(
        "n",
        "s.md",
        "settlement failure postmortem detail",
        DataClass::Internal,
    )
    .with_acl(NodeAcl::new().deny_groups(&["contractor"]))]);
    let r2 = ainxt_context::hybrid_retriever(&denied_corpus);
    let contractor = Principal::user("c", &[])
        .with_clearance(DataClass::Internal)
        .with_groups(&["contractor", "oncall"]);
    let access = AccessContext::from_principal(&contractor);
    let req = CompileRequest {
        access: &access,
        row_filter: None,
        graph: None,
        seeds: &seeds,
    };
    let w = compile_window("settlement failure", r2.as_ref(), &cfg(), &counter, &req);
    assert!(
        w.context.is_empty(),
        "a deny-group member is refused on the live path (deny wins)"
    );
}

// ============================ gaps 2 + 3: fabric as live source + plan routes retrieval ==========

fn refactor_fabric() -> MultiGraphFabric {
    MultiGraphFabric::new()
        .with_node(
            GraphLayer::Symbol,
            Chunk::new(
                "sym1",
                "parser.rs",
                "settlement parser signature definition",
                DataClass::Internal,
            ),
        )
        .with_node(
            GraphLayer::Call,
            Chunk::new(
                "call1",
                "caller.rs",
                "settlement parser call site",
                DataClass::Internal,
            ),
        )
        // An out-of-plan layer for a refactor turn (Runtime logs) — lexically matches but must not
        // be routed to.
        .with_node(
            GraphLayer::Runtime,
            Chunk::new(
                "log1",
                "trace.log",
                "settlement parser runtime error trace",
                DataClass::Internal,
            ),
        )
}

#[test]
fn r11_query_planning_routes_retrieval_over_the_fabric() {
    let fabric = refactor_fabric();
    let counter = WordTokenCounter;
    let access = AccessContext::new(DataClass::Internal, None, None, &[]);
    let routed = fabric.route(
        "refactor the settlement parser signature",
        &access,
        None,
        &cfg(),
        &counter,
        "",
    );
    // The plan routes a refactor to code layers, never to Runtime logs.
    assert!(routed.plan.includes(GraphLayer::Symbol));
    assert!(!routed.plan.includes(GraphLayer::Runtime));

    let ids: Vec<&str> = routed
        .window
        .context
        .chunks
        .iter()
        .map(|c| c.id.as_str())
        .collect();
    assert!(
        ids.contains(&"sym1"),
        "the Symbol-layer node is routed to: {ids:?}"
    );
    assert!(
        ids.contains(&"call1"),
        "the Call-layer node is routed to: {ids:?}"
    );
    assert!(
        !ids.contains(&"log1"),
        "the Runtime node lexically matches but is OUT of the refactor plan — it must never be \
         scored (query planning routes retrieval): {ids:?}"
    );
    // It never leaks into ranked/lineage either — an out-of-plan layer is not a candidate at all.
    assert!(routed.window.ranked.iter().all(|c| c.id != "log1"));
    assert!(routed
        .window
        .context
        .lineage
        .iter()
        .all(|n| n.chunk_id != "log1"));
}

// ============================ gap 4: personalized PageRank on the served path ====================

#[test]
fn r11_cross_graph_pagerank_ranks_on_the_served_routed_path() {
    // Three Enterprise-docs nodes with IDENTICAL text → identical lexical score. Only the graph
    // separates them: A→B (so B accrues PageRank mass from A), C is unconnected. On the routed path
    // PageRank must lift B above C. Before the closure the served call passed graph=None and the
    // three tied purely on retrieval order.
    let same = "settlement reconciliation detail";
    let fabric = MultiGraphFabric::new()
        .with_node(
            GraphLayer::EnterpriseDocs,
            Chunk::new("a", "a.md", same, DataClass::Internal),
        )
        .with_node(
            GraphLayer::EnterpriseDocs,
            Chunk::new("b", "b.md", same, DataClass::Internal),
        )
        .with_node(
            GraphLayer::EnterpriseDocs,
            Chunk::new("c", "c.md", same, DataClass::Internal),
        )
        .with_graph(FabricGraph::new().with_edge("a", EdgeKind::References, "b"));

    let counter = WordTokenCounter;
    let access = AccessContext::new(DataClass::Internal, None, None, &[]);
    let routed = fabric.route(
        "settlement reconciliation",
        &access,
        None,
        &cfg(),
        &counter,
        "",
    );

    let pos = |id: &str| {
        routed
            .window
            .ranked
            .iter()
            .position(|c| c.id == id)
            .unwrap()
    };
    assert!(
        pos("b") < pos("c"),
        "PageRank (B reachable from the seed A) must rank B above the unconnected C on the served \
         routed path — ranked: {:?}",
        routed
            .window
            .ranked
            .iter()
            .map(|c| &c.id)
            .collect::<Vec<_>>()
    );
}

// ============================ gap 7: global/sensemaking (GraphRAG) tier routed ===================

#[test]
fn r11_global_summary_tier_routed_and_clearance_filtered() {
    // One community of two connected nodes; its max class is Confidential (one member is).
    let fabric = MultiGraphFabric::new()
        .with_node(
            GraphLayer::EnterpriseDocs,
            Chunk::new(
                "n1",
                "1.md",
                "recurring settlement root causes",
                DataClass::Confidential,
            ),
        )
        .with_node(
            GraphLayer::EnterpriseDocs,
            Chunk::new(
                "n2",
                "2.md",
                "recurring settlement root causes",
                DataClass::Internal,
            ),
        )
        .with_graph(FabricGraph::new().with_edge("n1", EdgeKind::ChangedWith, "n2"));
    let counter = WordTokenCounter;
    let query = "recurring root causes this quarter";

    // A Confidential-cleared caller gets the community summary.
    let cleared = AccessContext::new(DataClass::Confidential, None, None, &[]);
    let routed = fabric.route(query, &cleared, None, &cfg(), &counter, "");
    assert!(
        routed.plan.includes(GraphLayer::GlobalSummary),
        "global query routes to the summary tier"
    );
    assert!(
        !routed.community_summaries.is_empty(),
        "a cleared caller gets the routed community summary"
    );

    // A Public caller must NOT get the Confidential summary — existence never leaks at the summary level.
    let public = AccessContext::new(DataClass::Public, None, None, &[]);
    let routed_pub = fabric.route(query, &public, None, &cfg(), &counter, "");
    assert!(
        routed_pub.community_summaries.is_empty(),
        "the Confidential community summary must be filtered for a Public caller"
    );
}

// ============================ gap 8: multimodal artifact tier routed + ACL-scoped ================

#[test]
fn r11_multimodal_artifact_tier_routed_and_acl_scoped() {
    let mut store = ArtifactStore::new();
    store.add_artifact(Artifact::new(
        "scan-open",
        "kyc:bankA",
        Modality::Image,
        DataClass::Confidential,
    ));
    store.add_artifact(
        Artifact::new(
            "scan-locked",
            "kyc:bankA",
            Modality::Image,
            DataClass::Confidential,
        )
        .with_acl(NodeAcl::new().departments(&["kyc-ops"])),
    );
    let fabric = MultiGraphFabric::new().with_artifacts(store);
    let counter = WordTokenCounter;
    let query = "pull the kyc scan";

    // In-department, cleared: sees both artifacts.
    let insider = AccessContext::new(DataClass::Confidential, Some("kyc-ops"), None, &[]);
    let routed = fabric.route(query, &insider, None, &cfg(), &counter, "kyc:bankA");
    assert!(
        routed.plan.includes(GraphLayer::MultimodalArtifact),
        "kyc/scan query routes to artifacts"
    );
    let ids: Vec<&str> = routed.artifacts.iter().map(|a| a.id.as_str()).collect();
    assert!(
        ids.contains(&"scan-open") && ids.contains(&"scan-locked"),
        "insider sees both: {ids:?}"
    );

    // Wrong department: the node-ACL-locked artifact is filtered pre-result (existence never leaks).
    let outsider = AccessContext::new(DataClass::Confidential, Some("hr"), None, &[]);
    let routed2 = fabric.route(query, &outsider, None, &cfg(), &counter, "kyc:bankA");
    let ids2: Vec<&str> = routed2.artifacts.iter().map(|a| a.id.as_str()).collect();
    assert_eq!(
        ids2,
        vec!["scan-open"],
        "the dept-locked artifact must be filtered for another dept"
    );
}

// ============================ gap 9: two-phase budget fit driven on confirm + failover ===========

#[test]
fn r11_two_phase_budget_fit_driven_on_confirm_and_failover() {
    let same_len = "settlement reconciliation ledger detail entry";
    let fabric = MultiGraphFabric::new()
        .with_node(
            GraphLayer::EnterpriseDocs,
            Chunk::new("d1", "1.md", same_len, DataClass::Internal),
        )
        .with_node(
            GraphLayer::EnterpriseDocs,
            Chunk::new("d2", "2.md", same_len, DataClass::Internal),
        );
    let counter = WordTokenCounter;
    let access = AccessContext::new(DataClass::Internal, None, None, &[]);
    let routed = fabric.route(
        "settlement reconciliation ledger",
        &access,
        None,
        &cfg(),
        &counter,
        "",
    );
    let phase1_included = routed.window.context.chunks.len();
    assert!(
        phase1_included >= 1,
        "phase-1 grounds at the eligible floor"
    );

    // Phase-2: confirm a wide model (widens/holds), then FAILOVER to a 3-token window (narrower).
    let final_window = routed.two_phase_fit(
        &EligibleModel::new("confirmed-wide", 64_000),
        &[EligibleModel::new("failover-tiny", 3)],
        &counter,
    );
    assert_eq!(
        final_window.window_tokens, 3,
        "the final fit targets the failover model's real window"
    );
    assert!(
        final_window.context.chunks.len() < phase1_included
            || final_window.context.chunks.len() <= 1,
        "the narrower failover window must shed evidence"
    );
    // Every shed node is ACCOUNTED (never a silent truncation) — the design's zero-silent-drop rule.
    assert!(
        final_window
            .context
            .lineage
            .iter()
            .any(|n| n.outcome == LineageOutcome::DroppedByBudget),
        "a dropped node must be accounted in the failover window's lineage"
    );
}

// ============================ gap 10: conflict arbitration by authority/recency ==================

#[test]
fn r11_conflict_arbitration_by_authority_then_recency() {
    // Two chunks state the SAME fact (topic "settlement-window") with different authority. The
    // authoritative runbook must win and the low-authority wiki draft must be superseded (not shown),
    // even though both are equally relevant. Before the closure both grounded side by side.
    let corpus = ainxt_context::Corpus::load(vec![
        Chunk::new(
            "wiki",
            "wiki.md",
            "the settlement window closes at 1730",
            DataClass::Internal,
        )
        .with_topic("settlement-window")
        .with_authority(10)
        .with_timestamp(100),
        Chunk::new(
            "runbook",
            "runbook.md",
            "the settlement window closes at 1700",
            DataClass::Internal,
        )
        .with_topic("settlement-window")
        .with_authority(90)
        .with_timestamp(50),
    ]);
    let retriever = ainxt_context::hybrid_retriever(&corpus);
    let counter = WordTokenCounter;
    let access = AccessContext::new(DataClass::Internal, None, None, &[]);
    let seeds = BTreeMap::new();
    let req = CompileRequest {
        access: &access,
        row_filter: None,
        graph: None,
        seeds: &seeds,
    };
    let w = compile_window(
        "settlement window closes",
        retriever.as_ref(),
        &cfg(),
        &counter,
        &req,
    );

    let grounded: Vec<&str> = w.context.chunks.iter().map(|c| c.id.as_str()).collect();
    assert_eq!(
        grounded,
        vec!["runbook"],
        "the higher-authority runbook wins the conflict: {grounded:?}"
    );
    assert!(
        w.context.citations.iter().all(|c| c.chunk_id != "wiki"),
        "the superseded lower-authority chunk is never cited"
    );
    // The loser is ACCOUNTED as SupersededByConflict (auditable + erasable), not silently kept.
    assert!(
        w.context
            .lineage
            .iter()
            .any(|n| n.chunk_id == "wiki" && n.outcome == LineageOutcome::SupersededByConflict),
        "the superseded chunk must be accounted in the lineage as a conflict loss"
    );
}

// A conflict tie on authority falls through to recency (fresher wins).
#[test]
fn r11_conflict_arbitration_recency_breaks_authority_tie() {
    let corpus = ainxt_context::Corpus::load(vec![
        Chunk::new(
            "old",
            "old.md",
            "the cutoff time is noon",
            DataClass::Internal,
        )
        .with_topic("cutoff")
        .with_authority(50)
        .with_timestamp(10),
        Chunk::new(
            "new",
            "new.md",
            "the cutoff time is noon",
            DataClass::Internal,
        )
        .with_topic("cutoff")
        .with_authority(50)
        .with_timestamp(999),
    ]);
    let retriever = ainxt_context::hybrid_retriever(&corpus);
    let counter = WordTokenCounter;
    let access = AccessContext::new(DataClass::Internal, None, None, &[]);
    let seeds = BTreeMap::new();
    let req = CompileRequest {
        access: &access,
        row_filter: None,
        graph: None,
        seeds: &seeds,
    };
    let w = compile_window("cutoff time", retriever.as_ref(), &cfg(), &counter, &req);
    let grounded: Vec<&str> = w.context.chunks.iter().map(|c| c.id.as_str()).collect();
    assert_eq!(
        grounded,
        vec!["new"],
        "on an authority tie the fresher source wins: {grounded:?}"
    );
}
