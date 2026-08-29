// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-13 Context-Fabric HIGH gap closures, proven on the real served-ready entrypoint.
//!
//! * **12+ graph layers compiled into the window each turn (the "fabric of graphs")**
//!   (`CONTEXT_FABRIC.md` §2): a *populated* [`FabricGraph`] — each node labelled with its
//!   [`GraphLayer`] plus the typed cross-graph edges — is fed to the fabric via
//!   [`MultiGraphFabric::from_fabric`] and compiled into ONE window each turn. A broad turn draws
//!   candidates from 12+ distinct layers at once, and [`RoutedWindow::compiled_layers`] reports
//!   exactly which layers were compiled. An out-of-plan layer is never scored (existence-preserving
//!   query planning). Fails before: `from_fabric` / `layer_of_node` / `RoutedWindow::compiled_layers`
//!   did not exist and the served routed compile could not report layer coverage.
//!
//! * **Budget-fit resolved against the eligible-model set from the Model Router (Gap-22)**
//!   (`CONTEXT_FABRIC.md` §3, anti-silent-truncation on failover): the served-ready
//!   [`MultiGraphFabric::route_eligible`] accepts the eligible-model set the Model Router resolved for
//!   THIS turn as an explicit parameter — the runtimed served wire passes the real one — overriding
//!   any config default, so the assembled window is fit to the narrowest model that could actually
//!   answer (including a failover target), and every shed candidate is ACCOUNTED (never a silent
//!   truncation). Fails before: `route_eligible` did not exist; the routed compile could only read the
//!   eligible set from a config default, so the router's per-turn set never bound.

use ainxt_context::optimizer::{EdgeKind, FabricGraph, GraphLayer};
use ainxt_context::route::MultiGraphFabric;
use ainxt_context::{AccessContext, Chunk, LineageOutcome, OptimizerConfig};
use ainxt_retrieval::{EligibleModel, WordTokenCounter};
use ainxt_types::DataClass;

fn cfg() -> OptimizerConfig {
    OptimizerConfig {
        // A deliberately WRONG, wide config default so `route_eligible` proving the router set wins is
        // unambiguous — a bug that read this default would fit to ~1e6 tokens, never the router floor.
        eligible: vec![EligibleModel::new("cfg-default-wide", 1_000_000)],
        k: 64,
        ..OptimizerConfig::default()
    }
}

/// A content chunk labelled INTO a specific fabric layer: the chunk carries a shared lexical term so
/// it is retrieved, and the graph labels its id with `layer` so the planner can route to/away from it.
fn labelled(graph: FabricGraph, id: &str, layer: GraphLayer) -> (FabricGraph, Chunk) {
    let g = graph.with_layer(id, layer);
    // Every node shares the "settlement" term so the lexical retriever surfaces it for the broad turn.
    let chunk = Chunk::new(
        id,
        &format!("{id}.src"),
        &format!("settlement {id} detail"),
        DataClass::Internal,
    );
    (g, chunk)
}

// ==================== gap 1: 12+ fabric graph layers compiled into the window each turn ====================

#[test]
fn r13_populated_fabric_graph_compiles_12plus_layers_into_the_window() {
    // A broad turn that trips code-navigation + debugging + structured-count + federated + multimodal
    // planning rules at once — the plan therefore routes over 12+ distinct fabric layers.
    let query =
        "why did the settlement refactor fail: rename the signature, count the import dependencies \
         across banks, and scan the kyc image";

    // Build a POPULATED FabricGraph: one node labelled into each of the 13 planned layers (round-15
    // `context-fabric` correctly added Repository to the code-nav rule — a navigation query needs
    // file-level repository context too, so it is no longer a valid out-of-plan example here), plus a
    // typed cross-graph edge so the served PageRank fuse has a real graph to walk, plus one node in
    // the OUT-of-plan Memory layer (only ever added by the unspecialized fallback, which this broad,
    // heavily-specialized turn never hits) that must never be compiled in for this turn.
    let in_plan = [
        ("conv", GraphLayer::Conversation),
        ("repo", GraphLayer::Repository),
        ("sym", GraphLayer::Symbol),
        ("ast", GraphLayer::Ast),
        ("call", GraphLayer::Call),
        ("imp", GraphLayer::Import),
        ("test", GraphLayer::Test),
        ("git", GraphLayer::GitHistory),
        ("docs", GraphLayer::EnterpriseDocs),
        ("rt", GraphLayer::Runtime),
        ("struct", GraphLayer::Structured),
        ("fed", GraphLayer::Federated),
        ("art", GraphLayer::MultimodalArtifact),
    ];
    let out_of_plan = [("mem", GraphLayer::Memory)];

    let mut graph = FabricGraph::new().with_edge("sym", EdgeKind::Calls, "call");
    let mut contents = Vec::new();
    for (id, layer) in in_plan.iter().chain(out_of_plan.iter()) {
        let (g, c) = labelled(graph, id, *layer);
        graph = g;
        contents.push(c);
    }

    // Feed the populated FabricGraph to the served fabric — the "fabric of graphs".
    let fabric = MultiGraphFabric::from_fabric(graph, contents);
    assert_eq!(
        fabric.len(),
        14,
        "all labelled nodes indexed (13 in-plan + 1 out-of-plan)"
    );

    let counter = WordTokenCounter;
    let access = AccessContext::new(DataClass::Internal, None, None, &[]);
    // A wide eligible set so the budget never limits layer coverage — this test isolates layer compile.
    let eligible = [EligibleModel::new("wide", 1_000_000)];
    let routed = fabric.route_eligible(query, &access, None, &eligible, &cfg(), &counter, "");

    // The plan itself routed to 12+ layers this turn.
    assert!(
        routed.plan.layers.len() >= 12,
        "the broad turn plans 12+ fabric layers: {:?}",
        routed.plan.layers
    );

    // And 12+ DISTINCT layers were actually COMPILED into the window (grounded chunks mapped back to
    // their fabric layer) — the "fabric of graphs compiled into the window each turn" fact.
    assert!(
        routed.layer_count() >= 12,
        "12+ fabric graph layers compiled into the window this turn, got {}: {:?}",
        routed.layer_count(),
        routed.compiled_layers
    );

    // Every in-plan layer's node was grounded; neither out-of-plan layer leaked in.
    let grounded: Vec<&str> = routed
        .window
        .context
        .chunks
        .iter()
        .map(|c| c.id.as_str())
        .collect();
    for (id, _) in &in_plan {
        assert!(
            grounded.contains(id),
            "in-plan layer node `{id}` must be compiled in: {grounded:?}"
        );
    }
    assert!(
        !routed.compiled_layers.contains(&GraphLayer::Memory),
        "Memory layer is out of plan"
    );
    for (id, _) in &out_of_plan {
        assert!(
            !grounded.contains(id),
            "out-of-plan node `{id}` must never be scored/compiled: {grounded:?}"
        );
        // It never leaks into the ranked candidate list or the lineage either.
        assert!(routed.window.ranked.iter().all(|c| c.id != *id));
        assert!(routed
            .window
            .context
            .lineage
            .iter()
            .all(|n| n.chunk_id != *id));
    }
}

#[test]
fn r13_from_fabric_skips_unlabelled_content_never_mislayers() {
    // A content chunk whose id the populated graph does NOT label is not part of the fabric: it must
    // be skipped, never silently mis-layered into a wrong (possibly in-plan) layer.
    let graph = FabricGraph::new().with_layer("docs", GraphLayer::EnterpriseDocs);
    let contents = vec![
        Chunk::new(
            "docs",
            "d.md",
            "settlement reconciliation policy detail",
            DataClass::Internal,
        ),
        Chunk::new(
            "stray",
            "s.md",
            "settlement reconciliation policy detail",
            DataClass::Internal,
        ),
    ];
    let fabric = MultiGraphFabric::from_fabric(graph, contents);
    assert_eq!(
        fabric.len(),
        1,
        "the unlabelled `stray` chunk is not indexed into the fabric"
    );
    assert_eq!(
        fabric.layer_of_node("docs"),
        Some(GraphLayer::EnterpriseDocs)
    );
    assert_eq!(fabric.layer_of_node("stray"), None);
}

// ==================== gap 2: budget-fit against the Model-Router eligible set (Gap-22) ====================

fn prose_fabric() -> MultiGraphFabric {
    // Three equal-length EnterpriseDocs nodes for a general prose turn (plan → docs + memory).
    let same = "settlement reconciliation ledger policy detail entry alpha";
    let graph = FabricGraph::new()
        .with_layer("d1", GraphLayer::EnterpriseDocs)
        .with_layer("d2", GraphLayer::EnterpriseDocs)
        .with_layer("d3", GraphLayer::EnterpriseDocs);
    let contents = vec![
        Chunk::new("d1", "1.md", same, DataClass::Internal),
        Chunk::new("d2", "2.md", same, DataClass::Internal),
        Chunk::new("d3", "3.md", same, DataClass::Internal),
    ];
    MultiGraphFabric::from_fabric(graph, contents)
}

#[test]
fn r13_route_eligible_binds_the_router_set_not_the_config_default() {
    let fabric = prose_fabric();
    let counter = WordTokenCounter;
    let access = AccessContext::new(DataClass::Internal, None, None, &[]);
    let query = "what is the settlement reconciliation policy";

    // The Model Router resolved a NARROW eligible set for this turn (a 3-token failover-tight model).
    // `cfg()` carries a wildly-wide default (1e6). If the router set did not bind, the window would fit
    // to 1e6 and ground all three docs — the silent-truncation-on-failover bug Gap-22 exists to stop.
    let router_tiny = [EligibleModel::new("router-tiny", 3)];
    let routed = fabric.route_eligible(query, &access, None, &router_tiny, &cfg(), &counter, "");
    assert_eq!(
        routed.window.window_tokens, 3,
        "the router's per-turn eligible set (not the config default) resolves the budget floor"
    );
    // The window shed evidence to fit the router floor, and every shed node is ACCOUNTED.
    assert!(
        routed.window.context.chunks.len() < 3,
        "the narrow router floor must shed evidence: {:?}",
        routed
            .window
            .context
            .chunks
            .iter()
            .map(|c| &c.id)
            .collect::<Vec<_>>()
    );
    assert!(
        routed
            .window
            .context
            .lineage
            .iter()
            .any(|n| n.outcome == LineageOutcome::DroppedByBudget),
        "a dropped node must be ACCOUNTED in the lineage — never a silent truncation"
    );

    // The SAME fabric with a wide router set grounds all three — proving the parameter, not a cap, drives it.
    let router_wide = [EligibleModel::new("router-wide", 64_000)];
    let wide = fabric.route_eligible(query, &access, None, &router_wide, &cfg(), &counter, "");
    assert_eq!(wide.window.window_tokens, 64_000);
    assert_eq!(
        wide.window.context.chunks.len(),
        3,
        "a wide router window grounds all three docs"
    );
}

#[test]
fn r13_route_eligible_fits_to_the_narrowest_including_a_failover_target() {
    let fabric = prose_fabric();
    let counter = WordTokenCounter;
    let access = AccessContext::new(DataClass::Internal, None, None, &[]);
    let query = "what is the settlement reconciliation policy";

    // The router set = {primary 64k, failover 3}. The fit must target the NARROWEST (the failover
    // target's real window), so the window is never wider than the model that actually serves the turn
    // can accept on failover — anti-silent-truncation on failover.
    let with_failover = [
        EligibleModel::new("primary-64k", 64_000),
        EligibleModel::new("failover-tiny", 3),
    ];
    let routed = fabric.route_eligible(query, &access, None, &with_failover, &cfg(), &counter, "");
    assert_eq!(
        routed.window.window_tokens, 3,
        "the fit targets the narrowest eligible window — the failover target"
    );
    assert!(
        routed
            .window
            .context
            .lineage
            .iter()
            .filter(|n| n.outcome == LineageOutcome::DroppedByBudget)
            .count()
            >= 1,
        "shedding to the failover floor is fully accounted"
    );
}

#[test]
fn r13_empty_eligible_set_grounds_empty_window_never_a_denied_turn() {
    // The empty-pool guard: an empty eligible set yields an EMPTY grounded window — never a panic,
    // never a denied turn (this is a retrieval read-filter, not an admission gate; the model call
    // still happens elsewhere, so this never reintroduces the empty-pool serving 503).
    let fabric = prose_fabric();
    let counter = WordTokenCounter;
    let access = AccessContext::new(DataClass::Internal, None, None, &[]);
    let empty: [EligibleModel; 0] = [];
    let routed = fabric.route_eligible(
        "what is the settlement reconciliation policy",
        &access,
        None,
        &empty,
        &cfg(),
        &counter,
        "",
    );
    assert_eq!(
        routed.window.window_tokens, 0,
        "no eligible model → zero window"
    );
    assert!(
        routed.window.context.chunks.is_empty(),
        "empty window grounds nothing, not a denial"
    );
    // The candidates were still retrieved + accounted (they exist, just none fit) — no silent loss.
    assert!(
        !routed.window.context.lineage.is_empty(),
        "every retrieved candidate is still accounted in the lineage"
    );
}
