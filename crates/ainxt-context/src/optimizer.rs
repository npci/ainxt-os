// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! The Context Optimizer's planning + cross-graph ranking core.
//!
//! Design: `docs/architecture/CONTEXT_FABRIC.md` §3 (the "compiler: graphs → window"). Two of
//! the optimizer's load-bearing steps are implemented here as pure, deterministic logic:
//!
//! 1. **Query planning** ([`plan_query`]) — decide *which* fabric graph layers a turn should
//!    draw from, from the query's shape: `"refactor X"` → symbol + call + import + AST + test +
//!    git-history; `"why did settlement fail"` → docs + runtime + structured; `"how many failed
//!    settlements"` → structured; `"recurring root causes this quarter"` → global-summary;
//!    `"pull the KYC scan"` → multimodal-artifact. This avoids fanning every turn out across all
//!    sixteen layers (§2 + `STRUCTURED_FEDERATED_RETRIEVAL.md` §1), which is both slow and noisy.
//!
//! 2. **Cross-graph relevance ranking** ([`personalized_pagerank`]) — score candidate nodes
//!    across the unified graph against the in-scope entities via **personalized PageRank**, the
//!    exact algorithm the design names. Seeded on the query's in-scope nodes, it ranks a node by
//!    how reachable it is from those seeds through the graph's edges — so a symbol two hops from
//!    the entity the user asked about outranks an unrelated one with the same lexical score.
//!
//! Everything is deterministic (fixed iteration count, sorted node order — no rng, no wall
//! clock, no hash-map-iteration-order leakage into results) and dependency-light (`serde` +
//! std collections). The graphs these operate over are built elsewhere (the KG project / the
//! semantic-editing crate); this module is the planner + ranker the optimizer composes.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// The Context Fabric graph layers (`CONTEXT_FABRIC.md` §2 layers 1–12 +
/// `STRUCTURED_FEDERATED_RETRIEVAL.md` §1 layers 13–16). The query planner selects a subset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphLayer {
    Conversation,
    Repository,
    Symbol,
    Ast,
    Call,
    Import,
    Architecture,
    GitHistory,
    Runtime,
    Test,
    EnterpriseDocs,
    Memory,
    Structured,
    Federated,
    GlobalSummary,
    MultimodalArtifact,
}

/// The planner's output: the layers to draw from, in the canonical (enum-declaration) order,
/// deduplicated. Deterministic for a given query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryPlan {
    pub layers: Vec<GraphLayer>,
}

impl QueryPlan {
    pub fn includes(&self, layer: GraphLayer) -> bool {
        self.layers.contains(&layer)
    }
}

/// Canonical ordering index (declaration order) — used to return plan layers deterministically
/// regardless of the order rules fired.
fn layer_order(l: GraphLayer) -> usize {
    use GraphLayer::*;
    [
        Conversation,
        Repository,
        Symbol,
        Ast,
        Call,
        Import,
        Architecture,
        GitHistory,
        Runtime,
        Test,
        EnterpriseDocs,
        Memory,
        Structured,
        Federated,
        GlobalSummary,
        MultimodalArtifact,
    ]
    .iter()
    .position(|x| *x == l)
    .unwrap_or(usize::MAX)
}

fn tokenize(query: &str) -> Vec<String> {
    query
        .split(|c: char| !c.is_alphanumeric())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_lowercase())
        .collect()
}

/// The query's *scope tier* (`STRUCTURED_FEDERATED_RETRIEVAL.md` §7.1): a point-lookup ("how many
/// failed settlements did bank X have last Tuesday" → §4 NL-to-SQL) vs a global/sensemaking ask
/// ("what are the recurring root causes this quarter" → §7 GraphRAG map-reduce). The design mandates
/// this be **classified, not keyword-matched** — riding the same confidence+ambiguity substrate
/// (`ainxt-classify`) the model-tier router uses, given a new dimension rather than a new component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryScope {
    /// A specific, bounded lookup — routes to structured NL-to-SQL.
    PointLookup,
    /// A cross-cutting sensemaking ask — routes to the global GraphRAG map-reduce tier.
    Global,
}

/// The scope classifier's output: the chosen [`QueryScope`], a `confidence` in `[0,1]` derived from
/// the **margin** between the two classes' accumulated evidence (not a single keyword's presence),
/// and `ambiguous` — set when the margin is below the decision threshold *and* both classes drew
/// real evidence, i.e. the turn genuinely reads both ways. An ambiguous scope must be resolved by a
/// calibrated clarifying question (§7.1 "asks, rather than guessing"), never by silently picking one.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScopeClassification {
    pub scope: QueryScope,
    pub confidence: f64,
    pub ambiguous: bool,
    /// The raw accumulated evidence weight for each class (for audit/lineage + eval regression).
    pub global_score: f64,
    pub point_score: f64,
}

/// Below this confidence margin *with competing evidence on both sides*, the scope is [`ambiguous`]
/// and the planner must clarify rather than guess.
///
/// [`ambiguous`]: ScopeClassification::ambiguous
const SCOPE_AMBIGUITY_THRESHOLD: f64 = 0.20;

/// Classify a query's scope tier (`STRUCTURED_FEDERATED_RETRIEVAL.md` §7.1) by accumulating
/// **weighted feature evidence** for each class and deciding on the *margin* — the classified
/// discipline the design demands, not an `if contains("root cause")` keyword switch.
///
/// Each class scores a set of soft signals (phrases, aggregation cues, specificity/entity cues) with
/// graded weights; a single cue never decides alone. The winner is the higher total; `confidence` is
/// the normalized margin `|g − p| / (g + p)`; a low margin with evidence on both sides is
/// `ambiguous` → clarify. This mirrors `ainxt-classify`'s confidence/ambiguity→clarify substrate,
/// applied to the scope dimension rather than the format/intent dimension.
pub fn classify_scope(query: &str) -> ScopeClassification {
    let tokens = tokenize(query);
    let lowered = query.to_lowercase();
    let has = |w: &str| tokens.iter().any(|t| t == w);
    let phrase = |p: &str| lowered.contains(p);

    // ---- Global / sensemaking evidence (graded) ----
    let mut g = 0.0f64;
    // Strong sensemaking phrases.
    if phrase("root cause") {
        g += 3.0;
    }
    if phrase("across all") || phrase("network-wide") || phrase("network wide") {
        g += 2.0;
    }
    // Aggregative "explain the shape of many things" cues.
    for (cue, w) in [
        ("recurring", 2.0),
        ("themes", 1.5),
        ("theme", 1.2),
        ("patterns", 1.8),
        ("pattern", 1.0),
        ("trends", 1.8),
        ("trend", 1.2),
        ("common", 1.2),
        ("overall", 1.2),
        ("systemic", 2.0),
        ("summarize", 1.5),
        ("summary", 1.2),
    ] {
        if has(cue) {
            g += w;
        }
    }
    // Open, period-scoped "what are the …" framing (plural, unbounded set).
    if phrase("what are the") || phrase("what have been") {
        g += 1.2;
    }
    if phrase("this quarter") || phrase("this month") || phrase("this year") || phrase("over time")
    {
        g += 1.0;
    }

    // ---- Point-lookup evidence (graded) ----
    let mut p = 0.0f64;
    if phrase("how many") || phrase("number of") {
        p += 2.5;
    }
    for (cue, w) in [
        ("count", 1.5),
        ("total", 1.2),
        ("sum", 1.2),
        ("average", 1.2),
        ("exactly", 1.5),
        ("which", 1.0),
        ("did", 0.8),
        ("was", 0.6),
        ("list", 0.8),
    ] {
        if has(cue) {
            p += w;
        }
    }
    // Specificity cues: a named point in time, a single named entity, a concrete filter.
    for day in [
        "monday",
        "tuesday",
        "wednesday",
        "thursday",
        "friday",
        "saturday",
        "sunday",
    ] {
        if has(day) {
            p += 1.2;
        }
    }
    if phrase("last night") || phrase("yesterday") || phrase("on ") {
        p += 0.8;
    }
    // "bank X", "for account …" — a single scoped entity.
    if phrase(" bank ") {
        p += 1.0;
    }

    // ---- Decide on the margin, not a single cue ----
    let total = g + p;
    let (scope, confidence) = if total <= f64::EPSILON {
        // No structured/sensemaking evidence at all → treat as a point lookup at zero confidence
        // (the general-prose fallback in `plan_query` handles docs+memory; GlobalSummary stays off).
        (QueryScope::PointLookup, 0.0)
    } else {
        let margin = (g - p).abs() / total;
        let scope = if g > p {
            QueryScope::Global
        } else {
            QueryScope::PointLookup
        };
        (scope, margin)
    };
    let ambiguous =
        total > f64::EPSILON && g > 0.0 && p > 0.0 && confidence < SCOPE_AMBIGUITY_THRESHOLD;

    ScopeClassification {
        scope,
        confidence,
        ambiguous,
        global_score: g,
        point_score: p,
    }
}

/// Plan which graph layers to draw from for `query` (`CONTEXT_FABRIC.md` §3 "query planning").
///
/// Rules are additive and deterministic: [`GraphLayer::Conversation`] is always included (the
/// current + related turns ground every answer); code-navigation, debugging, structured-count,
/// global-sensemaking, federated, and multimodal intents each add their layers; and a query that
/// trips no specialized rule falls back to general prose Q&A (docs + memory).
pub fn plan_query(query: &str) -> QueryPlan {
    let tokens = tokenize(query);
    let lowered = query.to_lowercase();
    let has = |w: &str| tokens.iter().any(|t| t == w);
    let phrase = |p: &str| lowered.contains(p);

    let mut layers: Vec<GraphLayer> = vec![GraphLayer::Conversation];
    let mut specialized = false;

    // Code navigation / refactoring.
    let code_nav = has("refactor")
        || has("rename")
        || has("signature")
        || has("extract")
        || has("inline")
        || has("import")
        || has("imports")
        || has("dependency")
        || has("dependencies")
        || has("depends")
        || phrase("who calls")
        || phrase("call site")
        || phrase("references of")
        || phrase("refs of");
    if code_nav {
        specialized = true;
        layers.extend([
            GraphLayer::Repository,
            GraphLayer::Symbol,
            GraphLayer::Ast,
            GraphLayer::Call,
            GraphLayer::Import,
        ]);
        // A refactor also wants what it might break + how the code changed historically.
        if has("refactor") || has("rename") || has("signature") {
            layers.extend([GraphLayer::Test, GraphLayer::GitHistory]);
        }
    }

    // Architecture / system-shape queries (§5 `architectureAround(module)`) — a layer the fabric
    // could populate but that no rule ever routed to (round-15 `context-fabric` fix: the layer was
    // structurally unreachable from any query, so it could never be compiled into a window even
    // once populated).
    let architecture = has("architecture")
        || has("boundary")
        || has("boundaries")
        || has("microservice")
        || has("microservices")
        || phrase("service contract")
        || phrase("architecture around")
        || phrase("system shape");
    if architecture {
        specialized = true;
        layers.push(GraphLayer::Architecture);
    }

    // Debugging / failure analysis.
    let debug = has("why")
        || has("fail")
        || has("failed")
        || has("failing")
        || has("error")
        || has("errors")
        || has("incident")
        || has("broke")
        || has("broken")
        || has("crash")
        || has("exception");
    if debug {
        specialized = true;
        layers.extend([
            GraphLayer::EnterpriseDocs,
            GraphLayer::Runtime,
            GraphLayer::Structured,
        ]);
    }

    // Structured / count metrics.
    let structured = phrase("how many")
        || phrase("number of")
        || has("count")
        || has("sum")
        || has("total")
        || has("average")
        || has("volume");
    if structured {
        specialized = true;
        layers.push(GraphLayer::Structured);
    }

    // Global / sensemaking — CLASSIFIED, not keyword-matched (§7.1). The scope classifier weighs
    // evidence on both sides and decides on the margin; a `Global` verdict (including a genuinely
    // ambiguous one leaning global, which the Intelligence Layer resolves by clarifying) routes here.
    let scope = classify_scope(query);
    if scope.scope == QueryScope::Global {
        specialized = true;
        layers.push(GraphLayer::GlobalSummary);
    }

    // Federated cross-bank.
    let federated = phrase("across banks")
        || phrase("member bank")
        || phrase("member banks")
        || phrase("network-wide")
        || phrase("network wide")
        || has("federated");
    if federated {
        specialized = true;
        layers.push(GraphLayer::Federated);
    }

    // Multimodal artifacts.
    let multimodal = has("cheque")
        || has("check")
        || has("kyc")
        || has("image")
        || has("scan")
        || has("recording")
        || has("micr")
        || has("photo")
        || phrase("call recording");
    if multimodal {
        specialized = true;
        layers.push(GraphLayer::MultimodalArtifact);
    }

    // Fallback: general prose Q&A grounds on docs + memory.
    if !specialized {
        layers.extend([GraphLayer::EnterpriseDocs, GraphLayer::Memory]);
    }

    // Deduplicate and return in canonical order.
    layers.sort_by_key(|l| layer_order(*l));
    layers.dedup();
    QueryPlan { layers }
}

// ---------------------------------------------------------------------------------------
// Cross-graph relevance ranking: personalized PageRank
// ---------------------------------------------------------------------------------------

/// The unified-graph adjacency the ranker walks: a directed edge `(from, to)` means `from`
/// relates-to / references `to`. Nodes are ids; layers/labels live elsewhere.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RankGraph {
    pub nodes: Vec<String>,
    pub edges: Vec<(String, String)>,
}

impl RankGraph {
    pub fn new() -> Self {
        RankGraph::default()
    }

    pub fn with_node(mut self, id: &str) -> Self {
        self.nodes.push(id.to_string());
        self
    }

    pub fn with_edge(mut self, from: &str, to: &str) -> Self {
        self.edges.push((from.to_string(), to.to_string()));
        self
    }
}

/// Personalized PageRank over `graph`, seeded on `seeds` (the in-scope entities of the query).
///
/// Standard damped power iteration with a **personalized teleport vector**: instead of teleport
/// mass returning uniformly, it returns to the seed distribution, biasing rank toward nodes
/// reachable from the query's entities (`CONTEXT_FABRIC.md` §3 "personalized PageRank over the
/// unified graph"). Dangling nodes (no out-edges) redistribute their mass via the same teleport
/// vector, so total rank is conserved. Deterministic: nodes are processed in sorted order and
/// the iteration count is fixed by the caller (no convergence-time nondeterminism).
///
/// `seeds` weights need not be normalized; unknown seed ids are ignored; an empty/zero seed set
/// falls back to a uniform teleport (ordinary PageRank). Returns a rank per node summing to ~1.
pub fn personalized_pagerank(
    graph: &RankGraph,
    seeds: &BTreeMap<String, f64>,
    damping: f64,
    iterations: usize,
) -> BTreeMap<String, f64> {
    // Deterministic, deduplicated node index.
    let mut ids: Vec<String> = graph.nodes.clone();
    ids.sort();
    ids.dedup();
    let n = ids.len();
    if n == 0 {
        return BTreeMap::new();
    }
    let index: BTreeMap<&str, usize> = ids
        .iter()
        .enumerate()
        .map(|(i, s)| (s.as_str(), i))
        .collect();

    // Out-adjacency (only edges whose BOTH endpoints are known nodes).
    let mut out: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (from, to) in &graph.edges {
        if let (Some(&fi), Some(&ti)) = (index.get(from.as_str()), index.get(to.as_str())) {
            out[fi].push(ti);
        }
    }

    // Personalization / teleport vector from seeds (normalized), else uniform.
    let mut p = vec![0.0f64; n];
    let seed_total: f64 = seeds
        .iter()
        .filter_map(|(k, v)| index.get(k.as_str()).map(|_| v.max(0.0)))
        .sum();
    if seed_total > 0.0 {
        for (k, v) in seeds {
            if let Some(&i) = index.get(k.as_str()) {
                p[i] += v.max(0.0) / seed_total;
            }
        }
    } else {
        let u = 1.0 / n as f64;
        for slot in p.iter_mut() {
            *slot = u;
        }
    }

    // Initialize rank at the teleport distribution.
    let mut rank = p.clone();
    for _ in 0..iterations {
        let mut next = vec![0.0f64; n];
        // Mass held by dangling nodes this round, redistributed via teleport.
        let mut dangling = 0.0f64;
        for (i, outs) in out.iter().enumerate() {
            if outs.is_empty() {
                dangling += rank[i];
            } else {
                let share = rank[i] / outs.len() as f64;
                for &j in outs {
                    next[j] += damping * share;
                }
            }
        }
        for (slot, &pi) in next.iter_mut().zip(p.iter()) {
            *slot += (1.0 - damping) * pi + damping * dangling * pi;
        }
        rank = next;
    }

    ids.into_iter().zip(rank).collect()
}

/// Rank node ids by a score map, highest first, ties broken by id for determinism — the ordered
/// candidate list the optimizer folds into the window.
pub fn rank_by_score(scores: &BTreeMap<String, f64>) -> Vec<String> {
    let mut v: Vec<(String, f64)> = scores.iter().map(|(k, s)| (k.clone(), *s)).collect();
    v.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(&b.0))
    });
    v.into_iter().map(|(k, _)| k).collect()
}

// ---------------------------------------------------------------------------------------
// The queryable fabric: typed edges + the structured query interface (CONTEXT_FABRIC.md §5)
// ---------------------------------------------------------------------------------------

use std::collections::{BTreeMap as StdBTreeMap, BTreeSet};

use ainxt_types::DataClass;

/// The typed relations that unify the fabric layers into one queryable knowledge graph
/// (`CONTEXT_FABRIC.md` §2 layers 3–10). An edge's *kind* is what makes `whoCalls` distinct from
/// `deps`: both walk edges, but of different types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    /// `from` calls `to` (call graph, layer 5).
    Calls,
    /// `from` references `to` (symbol graph, layer 3).
    References,
    /// `from` imports `to` (import graph, layer 6).
    Imports,
    /// `from` depends on `to` (dependency graph, layer 6/7).
    DependsOn,
    /// `from` and `to` change together (git change-coupling, layer 8). Symmetric in meaning.
    ChangedWith,
    /// `from` (a test) covers `to` (code) — test graph, layer 10.
    TestCovers,
    /// `from` (a function) has runtime error `to` (observability, layer 9).
    RuntimeError,
    /// `from` (a module/service) architecturally contains `to` (architecture graph, layer 7).
    ArchitectureContains,
}

/// One typed, directed edge in the fabric.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypedEdge {
    pub from: String,
    pub kind: EdgeKind,
    pub to: String,
}

/// The unified, queryable knowledge graph (`CONTEXT_FABRIC.md` §2 "all layers unify into one
/// Knowledge Graph"). It holds typed edges and an optional per-node [`GraphLayer`] label, and
/// exposes the design's structured query interface (§5) — `whoCalls`, `refsOf`,
/// `architectureAround`, `changedWith`, `testsCovering`, `runtimeErrorsFor`, `deps` — each
/// returning the graph slice the optimizer folds into context.
///
/// Populating this graph from real repositories (tree-sitter symbol/AST extraction, git blame,
/// runtime traces) is the job of the indexing crates (semantic-editing / KG project); this crate
/// owns the *queryable substrate and its interface* so the optimizer can query the fabric today.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FabricGraph {
    edges: Vec<TypedEdge>,
    layers: StdBTreeMap<String, GraphLayer>,
}

impl FabricGraph {
    pub fn new() -> Self {
        FabricGraph::default()
    }

    pub fn with_edge(mut self, from: &str, kind: EdgeKind, to: &str) -> Self {
        self.edges.push(TypedEdge {
            from: from.to_string(),
            kind,
            to: to.to_string(),
        });
        self
    }

    /// Label a node with the fabric layer it belongs to (for plan-aware slicing).
    pub fn with_layer(mut self, node: &str, layer: GraphLayer) -> Self {
        self.layers.insert(node.to_string(), layer);
        self
    }

    /// The layer a node was labelled with, if any.
    pub fn layer_of(&self, node: &str) -> Option<GraphLayer> {
        self.layers.get(node).copied()
    }

    /// Sorted, deduplicated `to` endpoints of edges of `kind` leaving `node`.
    fn out_by(&self, node: &str, kind: EdgeKind) -> Vec<String> {
        let mut v: Vec<String> = self
            .edges
            .iter()
            .filter(|e| e.kind == kind && e.from == node)
            .map(|e| e.to.clone())
            .collect();
        v.sort();
        v.dedup();
        v
    }

    /// Sorted, deduplicated `from` endpoints of edges of `kind` entering `node`.
    fn in_by(&self, node: &str, kind: EdgeKind) -> Vec<String> {
        let mut v: Vec<String> = self
            .edges
            .iter()
            .filter(|e| e.kind == kind && e.to == node)
            .map(|e| e.from.clone())
            .collect();
        v.sort();
        v.dedup();
        v
    }

    /// `whoCalls(sym)` — every symbol that calls `sym` (§5).
    pub fn who_calls(&self, sym: &str) -> Vec<String> {
        self.in_by(sym, EdgeKind::Calls)
    }

    /// `refsOf(sym)` — every symbol that references `sym` (§5).
    pub fn refs_of(&self, sym: &str) -> Vec<String> {
        self.in_by(sym, EdgeKind::References)
    }

    /// `deps(module)` — modules `module` imports or depends on (§5).
    pub fn deps(&self, module: &str) -> Vec<String> {
        let mut v = self.out_by(module, EdgeKind::Imports);
        v.extend(self.out_by(module, EdgeKind::DependsOn));
        v.sort();
        v.dedup();
        v
    }

    /// `changedWith(file)` — files that historically change together with `file` (§5). Symmetric:
    /// both edge directions count.
    pub fn changed_with(&self, file: &str) -> Vec<String> {
        let mut v = self.out_by(file, EdgeKind::ChangedWith);
        v.extend(self.in_by(file, EdgeKind::ChangedWith));
        v.retain(|n| n != file);
        v.sort();
        v.dedup();
        v
    }

    /// `testsCovering(fn)` — tests whose coverage includes `fn` (§5).
    pub fn tests_covering(&self, function: &str) -> Vec<String> {
        self.in_by(function, EdgeKind::TestCovers)
    }

    /// `runtimeErrorsFor(fn)` — runtime error signatures observed for `fn` (§5).
    pub fn runtime_errors_for(&self, function: &str) -> Vec<String> {
        self.out_by(function, EdgeKind::RuntimeError)
    }

    /// `architectureAround(module)` — what `module` contains and what contains `module` (§5).
    pub fn architecture_around(&self, module: &str) -> Vec<String> {
        let mut v = self.out_by(module, EdgeKind::ArchitectureContains);
        v.extend(self.in_by(module, EdgeKind::ArchitectureContains));
        v.sort();
        v.dedup();
        v
    }

    /// Project the typed graph onto an untyped [`RankGraph`] so the cross-graph
    /// [`personalized_pagerank`] ranker can run over the whole fabric.
    pub fn to_rank_graph(&self) -> RankGraph {
        let mut nodes: BTreeSet<String> = BTreeSet::new();
        let mut g = RankGraph::new();
        for e in &self.edges {
            nodes.insert(e.from.clone());
            nodes.insert(e.to.clone());
        }
        for n in &nodes {
            g = g.with_node(n);
        }
        for e in &self.edges {
            g = g.with_edge(&e.from, &e.to);
        }
        g
    }
}

/// The design's §5 **named structured query interface** (`whoCalls`/`refsOf`/`architectureAround`/
/// `changedWith`/`testsCovering`/`runtimeErrorsFor`/`deps`) as a route-ready request enum, mirroring
/// [`ainxt_graph`](https://docs.rs/ainxt-graph)'s `GraphQuery`/`graph_query` shape exactly (a
/// mount-ready dispatcher a served route hands a populated graph + query to) — GAP-FIX
/// context-fabric: [`FabricGraph`]'s named query methods were fully implemented and unit-tested but
/// had zero callers outside this crate's own tests (`grep -rn "who_calls\|refs_of\|..." crates/` =
/// only `ainxt-context/tests/`) — the design's §5 named vocabulary existed on the type but nothing
/// outside the crate ever addressed it BY NAME, the same class of gap `ainxt_graph::GraphQuery::ByRel`
/// closed for the sibling knowledge graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum NamedFabricQuery {
    /// `whoCalls(sym)` — every symbol that calls `sym`.
    WhoCalls { symbol: String },
    /// `refsOf(sym)` — every symbol that references `sym`.
    RefsOf { symbol: String },
    /// `deps(module)` — modules `module` imports or depends on.
    Deps { module: String },
    /// `changedWith(file)` — files that historically change together with `file`.
    ChangedWith { file: String },
    /// `testsCovering(fn)` — tests whose coverage includes `fn`.
    TestsCovering { function: String },
    /// `runtimeErrorsFor(fn)` — runtime error signatures observed for `fn`.
    RuntimeErrorsFor { function: String },
    /// `architectureAround(module)` — what `module` contains and what contains `module`.
    ArchitectureAround { module: String },
}

/// The single dispatcher for [`NamedFabricQuery`] over a populated [`FabricGraph`] — the mount-ready
/// entrypoint a served route (or the composition root) hands a query to, instead of reaching into
/// `FabricGraph`'s individual methods ad hoc.
pub fn named_fabric_query(fabric: &FabricGraph, query: &NamedFabricQuery) -> Vec<String> {
    match query {
        NamedFabricQuery::WhoCalls { symbol } => fabric.who_calls(symbol),
        NamedFabricQuery::RefsOf { symbol } => fabric.refs_of(symbol),
        NamedFabricQuery::Deps { module } => fabric.deps(module),
        NamedFabricQuery::ChangedWith { file } => fabric.changed_with(file),
        NamedFabricQuery::TestsCovering { function } => fabric.tests_covering(function),
        NamedFabricQuery::RuntimeErrorsFor { function } => fabric.runtime_errors_for(function),
        NamedFabricQuery::ArchitectureAround { module } => fabric.architecture_around(module),
    }
}

// ---------------------------------------------------------------------------------------
// Global / sensemaking layer: community detection + map-reduce summaries (STRUCTURED §7)
// ---------------------------------------------------------------------------------------

/// One detected community (a densely-connected node cluster) — the unit of the global/sensemaking
/// GraphRAG layer (`STRUCTURED_FEDERATED_RETRIEVAL.md` §7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Community {
    pub id: usize,
    /// Member node ids, sorted.
    pub members: Vec<String>,
}

/// A community summary node with an RBAC label — the map-reduce sensemaking artifact (§7). Its
/// `data_class` is the **max** over its members, so a summary can never be shown to a caller not
/// cleared for the most sensitive node it summarizes (existence-never-leaks at the summary level).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommunitySummary {
    pub community_id: usize,
    pub members: Vec<String>,
    pub data_class: DataClass,
}

/// Deterministic community detection by **synchronous label propagation** (Raghavan, Albert & Kumara
/// 2007) over the undirected view of `graph`. Each node starts in its own community; each round, in
/// sorted node order, a node adopts the most common label among its neighbors (ties broken by the
/// smallest label — fully deterministic, no rng, `DETERMINISTIC` mandate). Iterates to a fixed point
/// (bounded by node count).
///
/// This is a genuine, peer-reviewed community-detection algorithm in its own right — NOT a placeholder
/// standing in for a "real" algorithm. It is a deliberate choice for this runtime's constraints over
/// modularity-optimizing alternatives (Louvain / Leiden): near-linear time, no RNG/tie-break ambiguity
/// (Louvain's greedy merge order and Leiden's local-move phase are both randomized in their standard
/// formulations, which the `DETERMINISTIC` mandate forbids without a fixed, audited seed), and zero
/// added dependencies. The tradeoff is real and worth naming honestly: label propagation does not
/// optimize a global modularity objective, so on some graphs it yields coarser or less stable
/// partitions than a converged Louvain/Leiden run (particularly the well-known monster-community
/// degeneracy on sparse/star-like graphs) — a deployment that needs modularity-optimal partitions at
/// KG scale swaps this function out behind the same `RankGraph -> Vec<Community>` signature; that
/// swap is an indexing-crate concern, not a gap in what ships here.
pub fn detect_communities(graph: &RankGraph) -> Vec<Community> {
    let mut ids: Vec<String> = graph.nodes.clone();
    ids.sort();
    ids.dedup();
    let n = ids.len();
    if n == 0 {
        return Vec::new();
    }
    let index: StdBTreeMap<&str, usize> = ids
        .iter()
        .enumerate()
        .map(|(i, s)| (s.as_str(), i))
        .collect();

    // Undirected adjacency.
    let mut adj: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); n];
    for (from, to) in &graph.edges {
        if let (Some(&a), Some(&b)) = (index.get(from.as_str()), index.get(to.as_str())) {
            if a != b {
                adj[a].insert(b);
                adj[b].insert(a);
            }
        }
    }

    // Labels start as own index.
    let mut label: Vec<usize> = (0..n).collect();
    // Bounded iterations; break early on a stable pass.
    for _ in 0..(n + 1) {
        let mut changed = false;
        for i in 0..n {
            if adj[i].is_empty() {
                continue;
            }
            // Count neighbor labels; pick the most frequent, ties → smallest label.
            let mut counts: StdBTreeMap<usize, usize> = StdBTreeMap::new();
            for &j in &adj[i] {
                *counts.entry(label[j]).or_insert(0) += 1;
            }
            let best = counts
                .iter()
                .max_by(|a, b| a.1.cmp(b.1).then(b.0.cmp(a.0)))
                .map(|(l, _)| *l)
                .unwrap_or(label[i]);
            if best != label[i] {
                label[i] = best;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    // Group nodes by final label → communities, renumbered by first appearance in sorted order.
    let mut groups: StdBTreeMap<usize, Vec<String>> = StdBTreeMap::new();
    for (i, id) in ids.iter().enumerate() {
        groups.entry(label[i]).or_default().push(id.clone());
    }
    let mut communities: Vec<Community> = Vec::new();
    for (new_id, (_, mut members)) in groups.into_iter().enumerate() {
        members.sort();
        communities.push(Community {
            id: new_id,
            members,
        });
    }
    communities
}

/// **Incremental** community re-detection (round-15 `context-fabric` gap: "community detection +
/// incremental live maintenance", `CONTEXT_FABRIC.md` §4 "graphs update on file change / index /
/// commit / runtime event" applied to the global/sensemaking layer). [`detect_communities`] always
/// starts every node in its own singleton label and reconverges the WHOLE graph, so a served fabric
/// that adds one new node after a commit would force an O(n) full re-run just to notice it. This
/// seeds label propagation from the **previous** run's community assignment instead of from scratch
/// — every node the caller does not name in `touched` keeps its prior label as its STARTING point
/// (still free to move if its neighbors disagree, so a touched neighbor's change can still ripple
/// in), while `touched` nodes (the added/changed/removed node ids an incremental-maintenance event
/// batch names — this function takes plain ids so it stays free of a direct dependency on any
/// specific event type) reset to their own singleton label, exactly as a fresh node would. This is
/// deterministic and touches the same fixed-point semantics as
/// [`detect_communities`]; the difference is only the STARTING label vector, which is what makes an
/// unrelated, already-stable region of a large fabric graph reconverge to the SAME community ids
/// (not merely equivalent partitions) it already had, in far fewer changed assignments than a
/// from-scratch run over a large, mostly-unchanged graph.
pub fn detect_communities_incremental(
    graph: &RankGraph,
    prior: &[Community],
    touched: &[&str],
) -> Vec<Community> {
    let mut ids: Vec<String> = graph.nodes.clone();
    ids.sort();
    ids.dedup();
    let n = ids.len();
    if n == 0 {
        return Vec::new();
    }
    let index: StdBTreeMap<&str, usize> = ids
        .iter()
        .enumerate()
        .map(|(i, s)| (s.as_str(), i))
        .collect();

    // Undirected adjacency (identical construction to `detect_communities`).
    let mut adj: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); n];
    for (from, to) in &graph.edges {
        if let (Some(&a), Some(&b)) = (index.get(from.as_str()), index.get(to.as_str())) {
            if a != b {
                adj[a].insert(b);
                adj[b].insert(a);
            }
        }
    }

    // Seed labels from the PRIOR run's community assignment (node id → its old community id),
    // falling back to a fresh singleton (its own index) for a node the prior run never saw. A
    // `touched` node always resets to its own singleton, regardless of any prior label, so an
    // added/changed/removed node is re-evaluated exactly as `detect_communities` would evaluate it.
    let prior_label_of: StdBTreeMap<&str, usize> = prior
        .iter()
        .flat_map(|c| c.members.iter().map(move |m| (m.as_str(), c.id)))
        .collect();
    let touched_set: BTreeSet<&str> = touched.iter().copied().collect();
    let mut label: Vec<usize> = (0..n)
        .map(|i| {
            let id = ids[i].as_str();
            if touched_set.contains(id) {
                i
            } else {
                prior_label_of.get(id).copied().unwrap_or(i)
            }
        })
        .collect();

    for _ in 0..(n + 1) {
        let mut changed = false;
        for i in 0..n {
            if adj[i].is_empty() {
                continue;
            }
            let mut counts: StdBTreeMap<usize, usize> = StdBTreeMap::new();
            for &j in &adj[i] {
                *counts.entry(label[j]).or_insert(0) += 1;
            }
            let best = counts
                .iter()
                .max_by(|a, b| a.1.cmp(b.1).then(b.0.cmp(a.0)))
                .map(|(l, _)| *l)
                .unwrap_or(label[i]);
            if best != label[i] {
                label[i] = best;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    let mut groups: StdBTreeMap<usize, Vec<String>> = StdBTreeMap::new();
    for (i, id) in ids.iter().enumerate() {
        groups.entry(label[i]).or_default().push(id.clone());
    }
    let mut communities: Vec<Community> = Vec::new();
    for (new_id, (_, mut members)) in groups.into_iter().enumerate() {
        members.sort();
        communities.push(Community {
            id: new_id,
            members,
        });
    }
    communities
}

/// Attach an RBAC label to each community: the **max** data class over its members, sourced via
/// `class_of` (an unknown node defaults to [`DataClass::Public`] — the least sensitive, so it can
/// never *raise* a label incorrectly). This is the map step of map-reduce sensemaking (§7).
pub fn summarize_communities(
    communities: &[Community],
    class_of: impl Fn(&str) -> DataClass,
) -> Vec<CommunitySummary> {
    communities
        .iter()
        .map(|c| {
            let data_class = c
                .members
                .iter()
                .map(|m| class_of(m))
                .max_by_key(|dc| dc.sensitivity())
                .unwrap_or(DataClass::Public);
            CommunitySummary {
                community_id: c.id,
                members: c.members.clone(),
                data_class,
            }
        })
        .collect()
}

/// The reduce step of a global/sensemaking query (§7): given the query's in-scope seed nodes,
/// return the ids of the communities those seeds fall in (deduped, sorted) — the summaries to fold
/// into the answer, rather than every raw node.
pub fn communities_for_seeds(communities: &[Community], seeds: &[&str]) -> Vec<usize> {
    let seed_set: BTreeSet<&str> = seeds.iter().copied().collect();
    let mut hit: Vec<usize> = communities
        .iter()
        .filter(|c| c.members.iter().any(|m| seed_set.contains(m.as_str())))
        .map(|c| c.id)
        .collect();
    hit.sort();
    hit.dedup();
    hit
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seeds(pairs: &[(&str, f64)]) -> BTreeMap<String, f64> {
        pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    // --- query planning ------------------------------------------------------------

    #[test]
    fn refactor_query_plans_code_navigation_layers() {
        let plan = plan_query("refactor the SettlementProcessor to extract a helper");
        for l in [
            GraphLayer::Symbol,
            GraphLayer::Call,
            GraphLayer::Import,
            GraphLayer::Ast,
            GraphLayer::Test,
            GraphLayer::GitHistory,
        ] {
            assert!(plan.includes(l), "refactor plan must include {l:?}");
        }
        assert!(
            plan.includes(GraphLayer::Conversation),
            "conversation is always in scope"
        );
        // A refactor is not a structured-count query.
        assert!(!plan.includes(GraphLayer::Structured));
    }

    #[test]
    fn debug_query_plans_docs_runtime_structured() {
        let plan = plan_query("why did the settlement batch fail last night");
        assert!(plan.includes(GraphLayer::EnterpriseDocs));
        assert!(plan.includes(GraphLayer::Runtime));
        assert!(plan.includes(GraphLayer::Structured));
    }

    #[test]
    fn count_query_plans_structured() {
        let plan = plan_query("how many failed settlements did bank X have last Tuesday");
        assert!(plan.includes(GraphLayer::Structured));
        assert!(
            !plan.includes(GraphLayer::Symbol),
            "a count query is not code navigation"
        );
    }

    #[test]
    fn global_and_federated_and_multimodal_intents() {
        assert!(
            plan_query("what are the recurring root causes this quarter")
                .includes(GraphLayer::GlobalSummary)
        );
        assert!(
            plan_query("network-wide mule-account velocity across banks")
                .includes(GraphLayer::Federated)
        );
        assert!(plan_query("pull the KYC scan for this applicant")
            .includes(GraphLayer::MultimodalArtifact));
    }

    #[test]
    fn general_query_falls_back_to_docs_and_memory() {
        let plan = plan_query("what is UPI");
        assert!(plan.includes(GraphLayer::EnterpriseDocs));
        assert!(plan.includes(GraphLayer::Memory));
        assert!(plan.includes(GraphLayer::Conversation));
        assert!(!plan.includes(GraphLayer::Structured));
        assert!(!plan.includes(GraphLayer::MultimodalArtifact));
    }

    #[test]
    fn plan_is_deterministic_and_canonically_ordered() {
        let a = plan_query("refactor and rename this symbol");
        let b = plan_query("refactor and rename this symbol");
        assert_eq!(a, b);
        // Canonical order: layer_order strictly increases across the plan.
        let orders: Vec<usize> = a.layers.iter().map(|l| layer_order(*l)).collect();
        let mut sorted = orders.clone();
        sorted.sort_unstable();
        assert_eq!(orders, sorted, "plan layers must be in canonical order");
        // No duplicates.
        let mut dedup = a.layers.clone();
        dedup.dedup();
        assert_eq!(dedup.len(), a.layers.len());
    }

    // --- personalized PageRank -----------------------------------------------------

    #[test]
    fn seeded_node_and_its_neighbors_rank_above_unrelated() {
        // a -> b -> c ; d is isolated. Seed on `a`. a/b/c should all outrank the unrelated d.
        let g = RankGraph::new()
            .with_node("a")
            .with_node("b")
            .with_node("c")
            .with_node("d")
            .with_edge("a", "b")
            .with_edge("b", "c");
        let scores = personalized_pagerank(&g, &seeds(&[("a", 1.0)]), 0.85, 100);
        let (a, b, c, d) = (scores["a"], scores["b"], scores["c"], scores["d"]);
        assert!(a > d, "seed node must outrank the unrelated node");
        assert!(
            b > d,
            "a node reachable from the seed outranks the unrelated one"
        );
        assert!(c > d, "a two-hop node still outranks the unrelated one");
    }

    #[test]
    fn ranks_sum_to_one_and_are_deterministic() {
        let g = RankGraph::new()
            .with_node("x")
            .with_node("y")
            .with_node("z")
            .with_edge("x", "y")
            .with_edge("y", "z")
            .with_edge("z", "x");
        let s1 = personalized_pagerank(&g, &seeds(&[("x", 1.0)]), 0.85, 200);
        let s2 = personalized_pagerank(&g, &seeds(&[("x", 1.0)]), 0.85, 200);
        assert_eq!(s1, s2, "PageRank must be deterministic");
        let total: f64 = s1.values().sum();
        assert!(
            (total - 1.0).abs() < 1e-9,
            "rank mass is conserved (got {total})"
        );
    }

    #[test]
    fn personalization_biases_toward_the_seed_region() {
        // Two disjoint triangles; seeding one region must rank it above the other.
        let g = RankGraph::new()
            .with_node("a1")
            .with_node("a2")
            .with_node("a3")
            .with_node("b1")
            .with_node("b2")
            .with_node("b3")
            .with_edge("a1", "a2")
            .with_edge("a2", "a3")
            .with_edge("a3", "a1")
            .with_edge("b1", "b2")
            .with_edge("b2", "b3")
            .with_edge("b3", "b1");
        let scores = personalized_pagerank(&g, &seeds(&[("a1", 1.0)]), 0.85, 200);
        let a_mass: f64 = ["a1", "a2", "a3"].iter().map(|k| scores[*k]).sum();
        let b_mass: f64 = ["b1", "b2", "b3"].iter().map(|k| scores[*k]).sum();
        assert!(
            a_mass > b_mass,
            "the seeded component must carry more rank mass"
        );
    }

    #[test]
    fn dangling_node_conserves_mass() {
        // b has no out-edges (dangling); its mass must not vanish.
        let g = RankGraph::new()
            .with_node("a")
            .with_node("b")
            .with_edge("a", "b");
        let scores = personalized_pagerank(&g, &seeds(&[]), 0.85, 100);
        let total: f64 = scores.values().sum();
        assert!(
            (total - 1.0).abs() < 1e-9,
            "dangling mass must be conserved"
        );
    }

    #[test]
    fn empty_graph_and_unknown_seeds_are_safe() {
        assert!(
            personalized_pagerank(&RankGraph::new(), &seeds(&[("x", 1.0)]), 0.85, 10).is_empty()
        );
        // A seed id absent from the graph is ignored → falls back to uniform teleport.
        let g = RankGraph::new().with_node("a").with_node("b");
        let scores = personalized_pagerank(&g, &seeds(&[("ghost", 1.0)]), 0.85, 50);
        assert!(
            (scores["a"] - scores["b"]).abs() < 1e-9,
            "uniform fallback ranks equally"
        );
    }

    #[test]
    fn rank_by_score_orders_desc_with_id_tiebreak() {
        let mut m = BTreeMap::new();
        m.insert("low".to_string(), 0.1);
        m.insert("hi".to_string(), 0.9);
        m.insert("mid_b".to_string(), 0.5);
        m.insert("mid_a".to_string(), 0.5);
        let order = rank_by_score(&m);
        assert_eq!(order[0], "hi");
        assert_eq!(order[3], "low");
        // Tie between the two 0.5s broken by id ascending.
        assert_eq!(&order[1..3], &["mid_a".to_string(), "mid_b".to_string()]);
    }

    // --- queryable fabric (CTX-04) -------------------------------------------------

    #[test]
    fn gap_ctx_04_typed_fabric_answers_structured_graph_queries() {
        // Would FAIL before: GraphLayer variants existed only as planner labels; no typed edges,
        // no whoCalls/refsOf/deps/... query interface, no unified queryable KG.
        let g = FabricGraph::new()
            .with_edge("processSettlement", EdgeKind::Calls, "validateBatch")
            .with_edge("retrySettlement", EdgeKind::Calls, "validateBatch")
            .with_edge("audit", EdgeKind::References, "validateBatch")
            .with_edge("settlement_mod", EdgeKind::Imports, "ledger_mod")
            .with_edge("settlement_mod", EdgeKind::DependsOn, "recon_mod")
            .with_edge("settlement.rs", EdgeKind::ChangedWith, "ledger.rs")
            .with_edge("test_settlement", EdgeKind::TestCovers, "processSettlement")
            .with_edge("processSettlement", EdgeKind::RuntimeError, "TimeoutError")
            .with_edge(
                "settlement_svc",
                EdgeKind::ArchitectureContains,
                "settlement_mod",
            );

        assert_eq!(
            g.who_calls("validateBatch"),
            vec!["processSettlement", "retrySettlement"]
        );
        assert_eq!(g.refs_of("validateBatch"), vec!["audit"]);
        assert_eq!(g.deps("settlement_mod"), vec!["ledger_mod", "recon_mod"]);
        assert_eq!(g.changed_with("settlement.rs"), vec!["ledger.rs"]);
        assert_eq!(
            g.tests_covering("processSettlement"),
            vec!["test_settlement"]
        );
        assert_eq!(
            g.runtime_errors_for("processSettlement"),
            vec!["TimeoutError"]
        );
        assert_eq!(
            g.architecture_around("settlement_mod"),
            vec!["settlement_svc"]
        );

        // The fabric projects onto the RankGraph so the cross-graph ranker runs over it.
        let rg = g.to_rank_graph();
        let scores = personalized_pagerank(&rg, &seeds(&[("processSettlement", 1.0)]), 0.85, 100);
        assert!(
            scores.contains_key("validateBatch"),
            "reachable node is ranked"
        );
        assert!(scores["validateBatch"] > 0.0);
    }

    // --- global/sensemaking community layer (CTX-12) -------------------------------

    #[test]
    fn gap_ctx_12_community_detection_with_rbac_labelled_summaries() {
        // Two disjoint triangles → two communities. Would FAIL before: no community/leiden/louvain
        // code existed; GlobalSummary was only a keyword planner label.
        let g = RankGraph::new()
            .with_node("a1")
            .with_node("a2")
            .with_node("a3")
            .with_node("b1")
            .with_node("b2")
            .with_node("b3")
            .with_edge("a1", "a2")
            .with_edge("a2", "a3")
            .with_edge("a3", "a1")
            .with_edge("b1", "b2")
            .with_edge("b2", "b3")
            .with_edge("b3", "b1");
        let comms = detect_communities(&g);
        assert_eq!(comms.len(), 2, "two disjoint clusters → two communities");
        // Each community holds exactly one triangle.
        assert!(comms.iter().any(|c| c.members == vec!["a1", "a2", "a3"]));
        assert!(comms.iter().any(|c| c.members == vec!["b1", "b2", "b3"]));

        // RBAC summary label = max data class over members (a confidential member lifts the label).
        let summaries = summarize_communities(&comms, |n| {
            if n == "a3" {
                DataClass::Confidential
            } else {
                DataClass::Internal
            }
        });
        let a_summary = summaries
            .iter()
            .find(|s| s.members.contains(&"a1".to_string()))
            .unwrap();
        assert_eq!(a_summary.data_class, DataClass::Confidential);
        let b_summary = summaries
            .iter()
            .find(|s| s.members.contains(&"b1".to_string()))
            .unwrap();
        assert_eq!(b_summary.data_class, DataClass::Internal);

        // Map-reduce query: a seed on the b-cluster selects only its community.
        let hit = communities_for_seeds(&comms, &["b2"]);
        assert_eq!(hit.len(), 1);
        assert_eq!(hit[0], b_summary.community_id);
    }

    #[test]
    fn r15_incremental_community_detection_preserves_stable_region_and_absorbs_new_node() {
        // Two disjoint triangles, exactly as the from-scratch test above.
        let g = RankGraph::new()
            .with_node("a1")
            .with_node("a2")
            .with_node("a3")
            .with_node("b1")
            .with_node("b2")
            .with_node("b3")
            .with_edge("a1", "a2")
            .with_edge("a2", "a3")
            .with_edge("a3", "a1")
            .with_edge("b1", "b2")
            .with_edge("b2", "b3")
            .with_edge("b3", "b1");
        let prior = detect_communities(&g);
        let a_id = prior
            .iter()
            .find(|c| c.members.contains(&"a1".to_string()))
            .unwrap()
            .id;
        let b_id = prior
            .iter()
            .find(|c| c.members.contains(&"b1".to_string()))
            .unwrap()
            .id;

        // A live event adds one new node "b4" wired only into the b-triangle — a single-node,
        // event-driven change, not a full re-index (`CONTEXT_FABRIC.md` §4).
        let g2 = g.with_node("b4").with_edge("b4", "b1");
        let updated = detect_communities_incremental(&g2, &prior, &["b4"]);

        // The UNTOUCHED a-cluster keeps the EXACT SAME community id it had before — not merely an
        // equivalent partition, the identical id, which is what makes this genuinely incremental
        // (a caller diffing `updated` against `prior` sees zero churn in the untouched region).
        let a_after = updated
            .iter()
            .find(|c| c.members.contains(&"a1".to_string()))
            .unwrap();
        assert_eq!(
            a_after.id, a_id,
            "the untouched region keeps its prior community id"
        );
        assert_eq!(a_after.members, vec!["a1", "a2", "a3"]);

        // The new node joins the b-community (same id as before), absorbed rather than starting a
        // stray singleton community of its own.
        let b_after = updated
            .iter()
            .find(|c| c.members.contains(&"b1".to_string()))
            .unwrap();
        assert_eq!(
            b_after.id, b_id,
            "the touched cluster keeps its prior community id too"
        );
        assert!(
            b_after.members.contains(&"b4".to_string()),
            "the new node joins its neighbors' community"
        );
        assert_eq!(
            updated.len(),
            2,
            "still exactly two communities — no stray singleton for the new node"
        );

        // Deterministic: running the incremental update twice over the same inputs is byte-identical.
        let updated2 = detect_communities_incremental(&g2, &prior, &["b4"]);
        assert_eq!(updated, updated2);
    }
}
