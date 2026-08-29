// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! The Context Optimizer's **served routing** layer — the "compiler: graphs → window" wired as a
//! live, query-planned retrieval router over the unified multi-graph fabric
//! (`CONTEXT_FABRIC.md` §2–§3, `STRUCTURED_FEDERATED_RETRIEVAL.md` §1, §7).
//!
//! Before this layer the fabric's pieces existed but were dormant on any served retrieval path:
//! [`plan_query`](crate::optimizer::plan_query) computed the layer set but did not *route* retrieval;
//! the typed [`FabricGraph`](crate::optimizer::FabricGraph) was never a retrieval source;
//! [`personalized_pagerank`](crate::optimizer::personalized_pagerank) never ran because the served
//! [`compile_window`] call-site passed `graph = None`; and the global/sensemaking (community) and
//! multimodal-artifact tiers were library-only. This module composes them into ONE routed entrypoint
//! that every grounding surface can call:
//!
//! 1. **Multi-graph fabric as a live retrieval source** — a [`MultiGraphFabric`] holds the layered
//!    nodes (each an RBAC/RLS-labelled [`Chunk`] tagged with its [`GraphLayer`]) plus the typed
//!    [`FabricGraph`] edges. [`MultiGraphFabric::retriever_for_plan`] builds a real [`Retriever`]
//!    over the nodes the plan selected — so the fabric is *retrieved over*, not just modelled.
//! 2. **Query planning routes retrieval** — only nodes whose layer is in the [`QueryPlan`] enter the
//!    candidate set; an out-of-plan layer is never scored (a "refactor X" turn does not fan out over
//!    runtime-logs or KYC scans).
//! 3. **Cross-graph personalized PageRank on the served path** — the fabric's edges become the
//!    [`RankGraph`] and the query's in-scope nodes become the seed vector, so PageRank actually fuses
//!    into ranking on the routed call (the served dormancy is closed).
//! 4. **Global/sensemaking + multimodal tiers routed by plan** — a global query returns
//!    clearance-filtered community summaries; an artifact query returns ACL-scoped artifact handles.
//! 5. **Two-phase budget fit driven** — phase-1 fits to the eligible floor inside [`compile_window`];
//!    [`RoutedWindow::two_phase_fit`] then re-fits on model-confirm and re-fits again on every
//!    failover, exactly as the design's two-phase fit requires.
//!
//! Everything here is a retrieval read-filter / ranking concern — never a turn-admission decision.
//! An empty plan, a fully-filtered fabric, or an empty artifact tier yields an empty routed window,
//! never a denied turn (compliance still redacts-and-proceeds elsewhere).

use std::collections::BTreeMap;

use ainxt_retrieval::{acl::AccessContext, rls::RowFilter, EligibleModel, TokenCounter};

use crate::artifact::{Artifact, ArtifactStore};
use crate::optimizer::{
    communities_for_seeds, detect_communities, plan_query, summarize_communities, CommunitySummary,
    FabricGraph, GraphLayer, QueryPlan, RankGraph,
};
use crate::{
    compile_window, Chunk, CompileRequest, CompiledWindow, HybridRetriever, OptimizerConfig,
};

/// One node of the unified fabric: an RBAC/RLS-labelled [`Chunk`] plus the [`GraphLayer`] it belongs
/// to (so the query planner can route retrieval to it, or away from it).
#[derive(Debug, Clone)]
pub struct FabricNode {
    pub layer: GraphLayer,
    pub chunk: Chunk,
}

impl FabricNode {
    pub fn new(layer: GraphLayer, chunk: Chunk) -> Self {
        FabricNode { layer, chunk }
    }
}

/// The unified, queryable multi-graph fabric as a **live retrieval source** (`CONTEXT_FABRIC.md`
/// §2). Holds the layered nodes, the typed [`FabricGraph`] (the cross-graph edges PageRank walks),
/// and the multimodal [`ArtifactStore`]. Populating it from real repositories/traces/KG is the
/// indexing crates' job (tree-sitter, git blame, runtime traces — an infra concern); this type owns
/// the retrieval-source substrate + the routing so the optimizer retrieves over the fabric today.
#[derive(Debug, Clone, Default)]
pub struct MultiGraphFabric {
    nodes: Vec<FabricNode>,
    graph: FabricGraph,
    artifacts: ArtifactStore,
}

impl MultiGraphFabric {
    pub fn new() -> Self {
        MultiGraphFabric::default()
    }

    /// Index a layered node into the fabric.
    pub fn with_node(mut self, layer: GraphLayer, chunk: Chunk) -> Self {
        self.nodes.push(FabricNode::new(layer, chunk));
        self
    }

    /// Attach the typed cross-graph edges (the substrate PageRank + the `whoCalls`/`deps`/… interface
    /// walk).
    pub fn with_graph(mut self, graph: FabricGraph) -> Self {
        self.graph = graph;
        self
    }

    /// Attach the multimodal artifact tier.
    pub fn with_artifacts(mut self, artifacts: ArtifactStore) -> Self {
        self.artifacts = artifacts;
        self
    }

    /// Build the fabric's live, routable retrieval source **directly from a populated
    /// [`FabricGraph`]** — the graph the indexing/extractor path emits (`ainxt_context::extract::
    /// build_fabric`, or a hand-populated KG), carrying each node's [`GraphLayer`] label
    /// (`FabricGraph::with_layer`) plus the typed cross-graph edges. `contents` supplies the
    /// retrievable, RBAC/RLS-carrying [`Chunk`] body for each labelled node id.
    ///
    /// This is the "fabric of graphs" the served compile consumes each turn: ONE populated
    /// `FabricGraph` (layer 1–12 core + 13–16 structured/federated labels + edges) becomes the layered,
    /// query-planned, PageRank-fused multi-graph fabric. A content chunk whose id the graph does **not**
    /// label is *not* part of the fabric and is skipped — never silently mis-layered into a wrong layer
    /// (which would let the planner route to, or away from, it incorrectly). The retained `graph` is the
    /// same populated object, so its typed edges drive the served personalized-PageRank fuse.
    pub fn from_fabric(graph: FabricGraph, contents: Vec<Chunk>) -> Self {
        let nodes = contents
            .into_iter()
            .filter_map(|c| graph.layer_of(&c.id).map(|layer| FabricNode::new(layer, c)))
            .collect();
        MultiGraphFabric {
            nodes,
            graph,
            artifacts: ArtifactStore::default(),
        }
    }

    /// Number of indexed nodes across all layers.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// The layers actually present in the fabric (deduped, sorted). A diagnostic / test aid.
    pub fn populated_layers(&self) -> Vec<GraphLayer> {
        let mut v: Vec<GraphLayer> = self.nodes.iter().map(|n| n.layer).collect();
        v.sort();
        v.dedup();
        v
    }

    /// Build a live [`Retriever`] over exactly the nodes whose layer the `plan` selected — the
    /// query-planning-routes-retrieval step. Each selected node maps onto the production retrieval
    /// engine PRESERVING its node-ACL + RLS row-attributes, so [`compile_window`] enforces the full
    /// pre-rank RBAC/RLS over the routed candidate set (existence never leaks). Nodes in an
    /// out-of-plan layer are never indexed into the candidate set, so they are never scored.
    pub fn retriever_for_plan(&self, plan: &QueryPlan) -> HybridRetriever {
        let chunks: Vec<Chunk> = self
            .nodes
            .iter()
            .filter(|n| plan.includes(n.layer))
            .map(|n| n.chunk.clone())
            .collect();
        // `from_corpus` preserves the per-node ACL + RLS row-attributes (enforced pre-rank) AND the
        // optimizer metadata (timestamp/authority/topic) so freshness + conflict arbitration run on
        // the routed path.
        HybridRetriever::from_corpus(&crate::Corpus::load(chunks))
    }

    /// The cross-graph [`RankGraph`] the served PageRank fuse walks — the fabric's typed edges
    /// projected onto the untyped adjacency.
    pub fn rank_graph(&self) -> RankGraph {
        self.graph.to_rank_graph()
    }

    /// The query's in-scope **seed** nodes for the personalized-PageRank teleport: every node whose
    /// text lexically matches a query term is a seed (weight 1.0). This is what makes PageRank
    /// *personalized to the query's entities* on the served path — a node two hops from what the user
    /// asked about outranks an unrelated one with the same lexical score. Deterministic (sorted map).
    pub fn seeds_for(&self, query: &str) -> BTreeMap<String, f64> {
        let terms = query_terms(query);
        let mut seeds = BTreeMap::new();
        for n in &self.nodes {
            let text = n.chunk.text.to_lowercase();
            if terms.iter().any(|t| text.contains(t.as_str())) {
                seeds.insert(n.chunk.id.clone(), 1.0);
            }
        }
        seeds
    }

    /// The global/sensemaking (GraphRAG) tier (`STRUCTURED_FEDERATED_RETRIEVAL.md` §7): community
    /// detection over the fabric graph, each community summarized with the **max** data-class over
    /// its members, then filtered to the caller's clearance so a summary is never shown to a caller
    /// not cleared for the most-sensitive node it summarizes (existence-never-leaks at the summary
    /// level). Returned only when the plan routes to [`GraphLayer::GlobalSummary`].
    pub fn global_summaries(&self, query: &str, access: &AccessContext) -> Vec<CommunitySummary> {
        let rg = self.rank_graph();
        let communities = detect_communities(&rg);
        // class_of over the fabric nodes (unknown node → Public, the least sensitive).
        let class_of = |id: &str| {
            self.nodes
                .iter()
                .find(|n| n.chunk.id == id)
                .map(|n| n.chunk.data_class)
                .unwrap_or(ainxt_types::DataClass::Public)
        };
        let summaries = summarize_communities(&communities, class_of);
        // Reduce to the communities the query's seed nodes fall in.
        let seed_ids: Vec<String> = self.seeds_for(query).keys().cloned().collect();
        let seed_refs: Vec<&str> = seed_ids.iter().map(String::as_str).collect();
        let hit_ids = communities_for_seeds(&communities, &seed_refs);
        summaries
            .into_iter()
            .filter(|s| hit_ids.is_empty() || hit_ids.contains(&s.community_id))
            // Clearance filter — a summary above the caller's clearance never surfaces.
            .filter(|s| s.data_class.sensitivity() <= access.clearance.sensitivity())
            .collect()
    }

    /// The multimodal-artifact tier (`STRUCTURED_FEDERATED_RETRIEVAL.md` §8), ACL-scoped: artifacts
    /// in `namespace` visible to the caller's full [`AccessContext`] (namespace isolation + pre-rank
    /// class/node-ACL). Returned only when the plan routes to [`GraphLayer::MultimodalArtifact`].
    pub fn artifacts_for(&self, namespace: &str, access: &AccessContext) -> Vec<Artifact> {
        self.artifacts
            .search(namespace, access)
            .into_iter()
            .cloned()
            .collect()
    }

    /// **The single routed served entrypoint.** Plan the query → route retrieval to the planned
    /// layers over the fabric → fuse cross-graph personalized PageRank from the fabric edges/seeds →
    /// pre-rank node-ACL + RLS from the caller's [`AccessContext`] + [`RowFilter`] → phase-1
    /// eligible-floor budget fit → and (when routed) attach the global-summary + artifact tiers.
    /// Closes: multi-graph-as-live-source, plan-routes-retrieval, PageRank-on-served-path,
    /// global/multimodal-tier-mounting — all on ONE call the grounding surface drives.
    pub fn route(
        &self,
        query: &str,
        access: &AccessContext,
        row_filter: Option<&RowFilter>,
        cfg: &OptimizerConfig,
        counter: &dyn TokenCounter,
        namespace: &str,
    ) -> RoutedWindow {
        let plan = plan_query(query);
        let retriever = self.retriever_for_plan(&plan);
        let graph = self.rank_graph();
        let seeds = self.seeds_for(query);
        let req = CompileRequest {
            access,
            row_filter,
            graph: Some(&graph),
            seeds: &seeds,
        };
        let window = compile_window(query, &retriever, cfg, counter, &req);

        // The distinct fabric graph layers actually COMPILED into this turn's window: map every
        // grounded chunk back to the fabric layer its node belongs to (`CONTEXT_FABRIC.md` §2, "the
        // fabric of graphs"). This is the observable proof that the served compile drew from the
        // populated fabric's layers this turn — not a single flat corpus.
        let mut compiled_layers: Vec<GraphLayer> = window
            .context
            .chunks
            .iter()
            .filter_map(|c| self.layer_of_node(&c.id))
            .collect();
        compiled_layers.sort();
        compiled_layers.dedup();

        let community_summaries = if plan.includes(GraphLayer::GlobalSummary) {
            self.global_summaries(query, access)
        } else {
            Vec::new()
        };
        let artifacts = if plan.includes(GraphLayer::MultimodalArtifact) {
            self.artifacts_for(namespace, access)
        } else {
            Vec::new()
        };

        RoutedWindow {
            plan,
            window,
            community_summaries,
            artifacts,
            compiled_layers,
        }
    }

    /// The fabric [`GraphLayer`] a node id belongs to (its layer label in the fabric), or `None` if the
    /// id is not an indexed fabric node. Lets a caller map a grounded chunk back to the layer it was
    /// compiled from — the basis of [`RoutedWindow::compiled_layers`].
    pub fn layer_of_node(&self, id: &str) -> Option<GraphLayer> {
        self.nodes
            .iter()
            .find(|n| n.chunk.id == id)
            .map(|n| n.layer)
    }

    /// The **served-ready** routed compile: identical to [`route`](MultiGraphFabric::route) but the
    /// two-phase budget-fit is resolved against the **eligible-model set the Model Router resolved for
    /// THIS turn** — passed EXPLICITLY (`eligible`) rather than read from a config default. The runtimed
    /// served wire hands in the real per-request set (task-type ∩ data-class ∩ residency), so the
    /// assembled window is never wider than the narrowest model that could actually answer, *including
    /// a failover target* (`CONTEXT_FABRIC.md` §3, Gap-22 — anti-silent-truncation on failover). The
    /// explicit set overrides `cfg.eligible`; everything else (freshness/graph weights, `k`) still comes
    /// from `cfg`.
    ///
    /// An empty eligible set grounds an EMPTY window — never a denied turn (this is a retrieval
    /// read-filter, not a turn-admission gate; compliance still redacts-and-proceeds and the model call
    /// still happens, so this never reintroduces an empty-pool serving 503).
    #[allow(clippy::too_many_arguments)]
    pub fn route_eligible(
        &self,
        query: &str,
        access: &AccessContext,
        row_filter: Option<&RowFilter>,
        eligible: &[EligibleModel],
        cfg: &OptimizerConfig,
        counter: &dyn TokenCounter,
        namespace: &str,
    ) -> RoutedWindow {
        let cfg = OptimizerConfig {
            eligible: eligible.to_vec(),
            ..cfg.clone()
        };
        self.route(query, access, row_filter, &cfg, counter, namespace)
    }
}

/// Lowercase alphanumeric query terms (len > 2), matching the crate's tokenization discipline.
fn query_terms(query: &str) -> Vec<String> {
    query
        .to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.len() > 2)
        .map(|w| w.to_string())
        .collect()
}

/// The routed optimizer output: the query plan, the compiled + ranked + budget-fit window, and the
/// two plan-routed tiers (global-summary + multimodal-artifact). The two-phase budget fit is driven
/// via [`RoutedWindow::two_phase_fit`].
#[derive(Debug, Clone)]
pub struct RoutedWindow {
    pub plan: QueryPlan,
    pub window: CompiledWindow,
    pub community_summaries: Vec<CommunitySummary>,
    pub artifacts: Vec<Artifact>,
    /// The distinct fabric graph layers actually **compiled into this turn's window** — every grounded
    /// chunk mapped back to the fabric layer its node belongs to, deduped in canonical order. This is
    /// the observable "fabric of graphs compiled into the window each turn" fact (`CONTEXT_FABRIC.md`
    /// §2): a broad turn draws candidates from many layers at once; an out-of-plan layer never appears.
    pub compiled_layers: Vec<GraphLayer>,
}

impl RoutedWindow {
    /// How many distinct fabric graph layers were compiled into this turn's window.
    pub fn layer_count(&self) -> usize {
        self.compiled_layers.len()
    }

    /// Drive the design's **two-phase** budget fit on the served path (`CONTEXT_FABRIC.md` §3,
    /// "re-fit on model-confirm and on every failover"). Phase-1 already fit to the eligible floor
    /// inside [`compile_window`]; this re-fits to the specific `confirmed` model the Model Router
    /// picked at step 5 (its exact window typically widens the floor), then re-fits again to EACH
    /// `failover` model in the chain (a failover target can be narrower than the primary). Every
    /// candidate is re-accounted on each re-fit — never a silent truncation — so the final window is
    /// never wider than the model that actually serves the turn can accept. Returns the final window.
    pub fn two_phase_fit(
        &self,
        confirmed: &EligibleModel,
        failovers: &[EligibleModel],
        counter: &dyn TokenCounter,
    ) -> CompiledWindow {
        let mut w = self.window.refit_to(confirmed, counter);
        for m in failovers {
            w = w.refit_to(m, counter);
        }
        w
    }

    /// GAP-AUDIT data-surfaces-artifacts (multimodal model-eligibility not wired): `self.artifacts`
    /// (populated when the plan routes to [`GraphLayer::MultimodalArtifact`]) previously reached every
    /// caller with **no model-eligibility check at all** — a regulated-data cheque scan and a public
    /// marketing image came back identically, so a caller wiring this straight into a model dispatch
    /// had nothing in this crate stopping it from sending a regulated artifact to a cloud vision model.
    /// [`crate::artifact::route_model`] already encodes the correct eligibility rule (modality match +
    /// "regulated data never resolves to a cloud model") but had zero callers reaching this window.
    ///
    /// This is the missing gate: every artifact in the window is routed through `route_model` against
    /// the caller's real model catalog. Artifacts with an eligible model are returned paired with it;
    /// artifacts with none are returned in `dropped` (with the specific [`RoutingError`]) instead of
    /// being silently forwarded to an ineligible model or silently vanishing — a caller can turn a
    /// non-empty `dropped` into a compliance/observability finding, the same audit-and-proceed
    /// discipline [`crate::audit_document`]-style callers already use elsewhere.
    pub fn eligible_artifacts<'a>(
        &self,
        models: &'a [crate::artifact::ArtifactModel],
    ) -> (
        Vec<(Artifact, &'a crate::artifact::ArtifactModel)>,
        Vec<(Artifact, crate::artifact::RoutingError)>,
    ) {
        let mut eligible = Vec::new();
        let mut dropped = Vec::new();
        for artifact in &self.artifacts {
            match crate::artifact::route_model(artifact.data_class, artifact.modality, models) {
                Ok(m) => eligible.push((artifact.clone(), m)),
                Err(e) => dropped.push((artifact.clone(), e)),
            }
        }
        (eligible, dropped)
    }
}
