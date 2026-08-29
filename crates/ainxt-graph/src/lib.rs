// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! ainxt-graph — the AiNxt knowledge-graph core (Pass-5 / the platform's `/graph`, clean core).
//!
//! A unified **code + docs** graph: nodes are code symbols, files, documents, chunks, tickets,
//! etc.; edges are the relations between them (`calls`, `imports`, `documents`, `references`, …).
//! The single hard requirement this crate exists to guarantee is **RBAC enforced at *traversal*
//! time**, not as a post-filter on results.
//!
//! # Why traversal-time and not post-filter
//!
//! In a payments platform the *existence* of a node is itself sensitive: knowing that
//! `settlement_key_rotation()` calls `hsm_unwrap()` leaks architecture even if you never see
//! the body. A post-filter (traverse the whole graph, then drop nodes above the caller's
//! clearance from the returned list) leaks that existence three ways:
//!
//! 1. **Path counts** — "there are 4 shortest paths from A to B" reveals a hidden bridge even
//!    when every hidden node is scrubbed from the output.
//! 2. **Stepping-stones** — a restricted node used only as an intermediate would connect two
//!    visible nodes the caller should believe are *unconnected*.
//! 3. **Reachability** — "is B reachable from A?" answered `yes` via a hidden bridge tells the
//!    caller a privileged edge exists.
//!
//! So here an above-clearance node is **never enqueued, never counted, never bridged through,
//! and never returned** by any surface. Every algorithm walks only the caller's *visible
//! subgraph*, computed lazily during the walk:
//!
//! * [`Graph::neighbors`] — outgoing neighbours the caller may see (above-clearance filtered
//!   *before* return; querying the neighbours of a node the caller cannot see yields nothing,
//!   identical to an unknown node, so invisibility is indistinguishable from absence).
//! * [`Graph::traversal`] — bounded BFS to `max_depth`; a restricted node is not a hop, so it
//!   can neither be reached *through* nor reveal a node reachable *only* through it.
//! * [`Graph::shortest_path`] — BFS over visible nodes only; a path whose sole route runs
//!   through a restricted bridge returns [`None`] for the under-cleared caller (the bridge's
//!   existence never leaks) and [`Some`] for a cleared one.
//! * [`Graph::query_by_kind`] / [`Graph::query_by_rel`] — filtered projections over the
//!   visible subgraph (an edge is visible only when *both* endpoints are).
//!
//! # Clearance model
//!
//! Visibility is the shared [`ainxt_types::DataClass`] ladder: a node is visible to a
//! [`Principal`] iff `node.data_class.sensitivity() <= principal.clearance.sensitivity()`.
//! This is the *same* predicate `ainxt-retrieval` uses for chunk ACL, so a graph decision and
//! a retrieval decision read identical labels.
//!
//! # Determinism
//!
//! No clock, rng, or I/O. Nodes live in a [`BTreeMap`] and outgoing edges are kept sorted by
//! `(to, rel)`, so neighbour order, BFS visitation order, shortest-path tie-breaking, and query
//! order are all fully determined by the data — repeatable across runs and machines.
//!
//! # Construction integrity
//!
//! [`Graph::add_edge`] rejects an edge that references an unknown endpoint (a dangling edge
//! could otherwise imply a node that was never admitted, or silently create one with an
//! attacker-chosen — i.e. defaulted — clearance). [`Graph::add_node`] rejects a duplicate id
//! rather than overwrite, because overwriting a node's `data_class` is a clearance-downgrade
//! attack.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub use ainxt_types::{DataClass, Principal};
use serde::{Deserialize, Serialize};

/// A vertex in the knowledge graph: a code symbol, file, document, chunk, ticket, …
///
/// `data_class` is the sole gate on who may see the node. `kind` is a free-form category
/// (e.g. `"function"`, `"doc"`, `"file"`) used by [`Graph::query_by_kind`]; `label` is a
/// human-readable display name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Node {
    pub id: String,
    pub kind: String,
    pub data_class: DataClass,
    pub label: String,
}

impl Node {
    /// Construct a node.
    pub fn new(id: &str, kind: &str, data_class: DataClass, label: &str) -> Self {
        Node {
            id: id.to_string(),
            kind: kind.to_string(),
            data_class,
            label: label.to_string(),
        }
    }
}

/// A directed relation `from -> to` labelled `rel` (e.g. `"calls"`, `"imports"`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Edge {
    pub from: String,
    pub to: String,
    pub rel: String,
}

impl Edge {
    /// Construct an edge.
    pub fn new(from: &str, to: &str, rel: &str) -> Self {
        Edge {
            from: from.to_string(),
            to: to.to_string(),
            rel: rel.to_string(),
        }
    }
}

/// A construction-time integrity failure. Serializable so a gateway can surface it verbatim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "error", content = "id")]
pub enum GraphError {
    /// An edge referenced a node id that was never added. Carries the offending id.
    UnknownNode(String),
    /// A node with this id already exists; overwriting is refused (clearance-downgrade guard).
    DuplicateNode(String),
}

impl std::fmt::Display for GraphError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GraphError::UnknownNode(id) => write!(f, "edge references unknown node: {id}"),
            GraphError::DuplicateNode(id) => write!(f, "node already exists: {id}"),
        }
    }
}

impl std::error::Error for GraphError {}

/// A unified code+docs graph with traversal-time RBAC.
///
/// See the [module docs](crate) for the security model. All read surfaces take a [`Principal`]
/// and expose only that principal's visible subgraph.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Graph {
    /// Nodes keyed by id. A `BTreeMap` so every value-iteration is id-sorted (deterministic).
    nodes: BTreeMap<String, Node>,
    /// Outgoing adjacency, keyed by `from`. Each bucket is kept sorted by `(to, rel)` and free
    /// of exact-duplicate edges, so neighbour and BFS order are fully determined by the data.
    out: BTreeMap<String, Vec<Edge>>,
}

impl Graph {
    /// An empty graph.
    pub fn new() -> Self {
        Graph::default()
    }

    /// Number of nodes admitted (all classes; this is not a visibility surface).
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Add a node. Refuses a duplicate id with [`GraphError::DuplicateNode`] rather than
    /// overwrite an existing node's `data_class` (silent clearance downgrade).
    pub fn add_node(&mut self, node: Node) -> Result<(), GraphError> {
        if self.nodes.contains_key(&node.id) {
            return Err(GraphError::DuplicateNode(node.id));
        }
        self.nodes.insert(node.id.clone(), node);
        Ok(())
    }

    /// Add a directed edge. Both endpoints must already exist, else [`GraphError::UnknownNode`]
    /// (carrying the missing id) — a dangling edge is never admitted. Exact-duplicate edges
    /// `(from, to, rel)` are idempotent no-ops. The bucket is kept sorted by `(to, rel)`.
    pub fn add_edge(&mut self, edge: Edge) -> Result<(), GraphError> {
        if !self.nodes.contains_key(&edge.from) {
            return Err(GraphError::UnknownNode(edge.from));
        }
        if !self.nodes.contains_key(&edge.to) {
            return Err(GraphError::UnknownNode(edge.to));
        }
        let bucket = self.out.entry(edge.from.clone()).or_default();
        let pos = bucket.binary_search_by(|e| {
            e.to.as_str()
                .cmp(edge.to.as_str())
                .then_with(|| e.rel.as_str().cmp(edge.rel.as_str()))
        });
        match pos {
            Ok(_) => {} // exact duplicate — idempotent
            Err(i) => bucket.insert(i, edge),
        }
        Ok(())
    }

    /// The stored key `&str` for `id` (self-lifetime), or `None` if absent. Used to keep every
    /// traversal collection on a single lifetime.
    fn key(&self, id: &str) -> Option<&str> {
        self.nodes.get_key_value(id).map(|(k, _)| k.as_str())
    }

    /// Whether `principal` may see the node `id`: it must exist AND its sensitivity must not
    /// exceed the principal's clearance. An absent node and an above-clearance node both return
    /// `false`, so the two are indistinguishable to every caller.
    fn is_visible(&self, id: &str, principal: &Principal) -> bool {
        self.nodes
            .get(id)
            .is_some_and(|n| n.data_class.sensitivity() <= principal.clearance.sensitivity())
    }

    /// Fetch a node only if the principal may see it. `None` for absent OR above-clearance.
    pub fn get_visible(&self, id: &str, principal: &Principal) -> Option<&Node> {
        self.is_visible(id, principal)
            .then(|| self.nodes.get(id))
            .flatten()
    }

    /// Sorted, de-duplicated ids of the *visible* outgoing neighbours of `id`. This is the one
    /// place the clearance filter is applied during a walk: a restricted `to` endpoint is
    /// dropped here, so it is never enqueued, counted, or bridged through downstream.
    fn visible_out_ids(&self, id: &str, principal: &Principal) -> Vec<&str> {
        let mut ids: BTreeSet<&str> = BTreeSet::new();
        if let Some(edges) = self.out.get(id) {
            for e in edges {
                if self.is_visible(&e.to, principal) {
                    ids.insert(e.to.as_str());
                }
            }
        }
        ids.into_iter().collect()
    }

    /// Outgoing neighbours of `id` the principal may see, sorted by id.
    ///
    /// Above-clearance neighbours are filtered *before* return. If `id` itself is not visible
    /// (absent or above clearance) the result is empty — identical to a node with no neighbours,
    /// so the caller cannot distinguish "hidden" from "leaf" from "absent".
    pub fn neighbors(&self, id: &str, principal: &Principal) -> Vec<&Node> {
        if !self.is_visible(id, principal) {
            return Vec::new();
        }
        self.visible_out_ids(id, principal)
            .into_iter()
            .filter_map(|nb| self.nodes.get(nb))
            .collect()
    }

    /// Bounded breadth-first traversal from `start`, over the visible subgraph only.
    ///
    /// Returns the visible nodes reachable within `max_depth` hops (`max_depth == 0` yields just
    /// `start`), in BFS visitation order. An above-clearance node is never a hop: it is not
    /// enqueued, so it can be neither reached *through* nor used to surface a node reachable
    /// *only* through it. If `start` is not visible the result is empty.
    pub fn traversal(&self, start: &str, principal: &Principal, max_depth: usize) -> Vec<&Node> {
        let mut order: Vec<&Node> = Vec::new();
        let Some(start_key) = self.key(start) else {
            return order;
        };
        if !self.is_visible(start_key, principal) {
            return order;
        }
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        let mut queue: VecDeque<(&str, usize)> = VecDeque::new();
        seen.insert(start_key);
        queue.push_back((start_key, 0));
        while let Some((id, depth)) = queue.pop_front() {
            if let Some(node) = self.nodes.get(id) {
                order.push(node);
            }
            if depth >= max_depth {
                continue;
            }
            for nb in self.visible_out_ids(id, principal) {
                if seen.insert(nb) {
                    queue.push_back((nb, depth + 1));
                }
            }
        }
        order
    }

    /// Shortest path (fewest hops) from `from` to `to` over the visible subgraph, as the node
    /// sequence including both endpoints, or `None` if there is no *visible* route.
    ///
    /// Because every hop is drawn from [`Graph::visible_out_ids`], a route that exists only
    /// through a restricted bridge returns `None` for an under-cleared principal — the bridge's
    /// existence never leaks — and `Some` for a principal cleared to see the bridge. `from` or
    /// `to` not being visible also yields `None`. Ties are broken by sorted neighbour order, so
    /// the returned path is deterministic.
    pub fn shortest_path(&self, from: &str, to: &str, principal: &Principal) -> Option<Vec<&Node>> {
        let (from_key, to_key) = (self.key(from)?, self.key(to)?);
        if !self.is_visible(from_key, principal) || !self.is_visible(to_key, principal) {
            return None;
        }
        if from_key == to_key {
            return self.nodes.get(from_key).map(|n| vec![n]);
        }
        // BFS with predecessor tracking over visible nodes only.
        let mut prev: BTreeMap<&str, &str> = BTreeMap::new();
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        let mut queue: VecDeque<&str> = VecDeque::new();
        seen.insert(from_key);
        queue.push_back(from_key);
        while let Some(id) = queue.pop_front() {
            for nb in self.visible_out_ids(id, principal) {
                if seen.insert(nb) {
                    prev.insert(nb, id);
                    if nb == to_key {
                        return Some(self.reconstruct(&prev, from_key, nb));
                    }
                    queue.push_back(nb);
                }
            }
        }
        None
    }

    /// Walk `prev` from `end` back to `start`, returning the forward node sequence.
    fn reconstruct<'a>(
        &'a self,
        prev: &BTreeMap<&'a str, &'a str>,
        start: &'a str,
        end: &'a str,
    ) -> Vec<&'a Node> {
        let mut ids: Vec<&str> = vec![end];
        let mut cur = end;
        while cur != start {
            // Every non-start node in a completed BFS path has a predecessor by construction.
            match prev.get(cur) {
                Some(&p) => {
                    cur = p;
                    ids.push(cur);
                }
                None => break,
            }
        }
        ids.reverse();
        ids.into_iter()
            .filter_map(|id| self.nodes.get(id))
            .collect()
    }

    /// All visible nodes whose `kind` equals `kind`, sorted by id. Above-clearance nodes are
    /// excluded, so a query can never enumerate a restricted category member.
    pub fn query_by_kind(&self, kind: &str, principal: &Principal) -> Vec<&Node> {
        self.nodes
            .values()
            .filter(|n| {
                n.kind == kind && n.data_class.sensitivity() <= principal.clearance.sensitivity()
            })
            .collect()
    }

    /// All edges with relation `rel` where BOTH endpoints are visible, ordered by `(from, to,
    /// rel)`. An edge touching an above-clearance node is omitted — revealing it would leak the
    /// hidden endpoint's existence and its connectivity.
    pub fn query_by_rel(&self, rel: &str, principal: &Principal) -> Vec<&Edge> {
        let mut out: Vec<&Edge> = Vec::new();
        for edges in self.out.values() {
            for e in edges {
                if e.rel == rel
                    && self.is_visible(&e.from, principal)
                    && self.is_visible(&e.to, principal)
                {
                    out.push(e);
                }
            }
        }
        out
    }
}

// ===========================================================================
// graph_query — the RBAC-scoped, mount-ready read entrypoint (SURF-10 / R3 DATA)
// ===========================================================================

/// A read query against the knowledge graph, deserialized straight from the wire (`op` tag).
/// Every variant is evaluated ONLY over the caller's visible subgraph, so no query shape can be
/// used as an existence oracle for an above-clearance node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum GraphQuery {
    /// Bounded BFS reachability from `start` within `max_depth` hops.
    Traverse { start: String, max_depth: usize },
    /// Shortest path from `from` to `to` (empty if unreachable *or* blocked by an invisible hop).
    Path { from: String, to: String },
    /// Immediate visible neighbours of `id`.
    Neighbors { id: String },
    /// All visible nodes of a given `kind`.
    ByKind { kind: String },
    /// Resolve a single node by `id`, if visible.
    Node { id: String },
    /// All edges labelled `rel` with BOTH endpoints visible (gap: [`Graph::query_by_rel`] was a
    /// real, unit-tested RBAC-safe projection with no [`GraphQuery`] variant routing to it, so it
    /// was structurally unreachable from the served `POST /graph` entrypoint — a caller could ask
    /// "what kind is this node" or "who does this node touch" but never "show me every `calls`
    /// edge I'm allowed to see").
    ByRel { rel: String },
}

/// The result of a [`graph_query`], serialized back to the wire. Only node ids the caller may see
/// appear — the projection to ids (never full nodes) keeps the response shape uniform across query
/// kinds and avoids echoing labels the transport may want to withhold.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphQueryResponse {
    /// Visible node ids in traversal / path / BTree order (deterministic).
    #[serde(default)]
    pub nodes: Vec<String>,
    /// Visible `(from, to)` pairs for [`GraphQuery::ByRel`], ordered by [`Graph::query_by_rel`]
    /// (i.e. `(from, to, rel)`). Empty for every other query kind — additive field, so an existing
    /// client decoding only `nodes` is unaffected.
    #[serde(default)]
    pub edges: Vec<(String, String)>,
}

/// The single RBAC-scoped entrypoint a transport route (`POST /graph`) mounts over a loaded
/// [`Graph`]. It dispatches `query` against the caller's clearance-filtered subgraph: a node above
/// `principal.clearance` is never visited, returned, counted, or used as a stepping-stone, so its
/// existence cannot leak through a reachability / path / neighbour answer. Pure and deterministic —
/// no clock, rng, or I/O; identical inputs give identical output.
pub fn graph_query(graph: &Graph, query: &GraphQuery, principal: &Principal) -> GraphQueryResponse {
    let nodes = match query {
        GraphQuery::Traverse { start, max_depth } => graph
            .traversal(start, principal, *max_depth)
            .iter()
            .map(|n| n.id.clone())
            .collect(),
        GraphQuery::Path { from, to } => graph
            .shortest_path(from, to, principal)
            .map(|p| p.iter().map(|n| n.id.clone()).collect())
            .unwrap_or_default(),
        GraphQuery::Neighbors { id } => graph
            .neighbors(id, principal)
            .iter()
            .map(|n| n.id.clone())
            .collect(),
        GraphQuery::ByKind { kind } => graph
            .query_by_kind(kind, principal)
            .iter()
            .map(|n| n.id.clone())
            .collect(),
        GraphQuery::Node { id } => graph
            .get_visible(id, principal)
            .map(|n| vec![n.id.clone()])
            .unwrap_or_default(),
        GraphQuery::ByRel { .. } => Vec::new(),
    };
    let edges = match query {
        GraphQuery::ByRel { rel } => graph
            .query_by_rel(rel, principal)
            .iter()
            .map(|e| (e.from.clone(), e.to.clone()))
            .collect(),
        _ => Vec::new(),
    };
    GraphQueryResponse { nodes, edges }
}

/// A source document descriptor the daemon (or an indexing pipeline) hands to
/// [`Graph::from_documents`] to POPULATE a live code+docs knowledge graph — closing the
/// "knowledge graph is empty on the shipped daemon" gap without any live infra. Deliberately a
/// small, owned shape (not `ainxt-runtimed`'s `KbDocument`) so this crate stays leaf/acyclic: the
/// reserved daemon maps its KB rows onto this, keeping the population logic pure and unit-testable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphDoc {
    /// Stable node id (the daemon uses the KB document id).
    pub id: String,
    /// Human-readable label.
    pub label: String,
    /// Sensitivity — the SOLE visibility gate (carried straight onto the node's `data_class`).
    pub data_class: DataClass,
    /// Optional grouping (namespace / repo / source): a `namespace` node is minted per distinct
    /// value with a `contains` edge to each of its documents.
    #[serde(default)]
    pub namespace: Option<String>,
    /// Other document ids this doc references (a `mentions` edge is added when the target exists).
    #[serde(default)]
    pub references: Vec<String>,
}

/// **Populate a knowledge graph from source documents** (gap: "knowledge graph is populated on the
/// shipped daemon"). Deterministic and pure — no clock/rng/I/O — so the same KB always yields the
/// same graph and every guarantee is unit-testable:
///
/// * one `doc` node per [`GraphDoc`], carrying the document's `data_class` verbatim (the visibility
///   gate is never widened here);
/// * one `namespace` node per distinct `namespace`, classed at the **least-sensitive** member so a
///   grouping node never leaks the existence of a more-restricted document (a low-clearance caller
///   sees the namespace but a `contains` edge to an above-clearance doc is never traversed);
/// * a `contains` edge `namespace -> doc`, and a `mentions` edge `doc -> ref` for every reference
///   whose target document exists (a dangling reference is silently dropped, never a broken edge).
///
/// RBAC is unchanged: it is enforced at TRAVERSAL time by the graph itself, so a restricted document
/// admitted here is still invisible to (and un-bridgeable by) an under-cleared caller.
pub fn from_documents(docs: impl IntoIterator<Item = GraphDoc>) -> Graph {
    let docs: Vec<GraphDoc> = docs.into_iter().collect();
    let mut g = Graph::new();

    // Doc nodes first (idempotent on duplicate id — the first admission's class wins, never a
    // silent downgrade, mirroring `add_node`'s duplicate refusal).
    for d in &docs {
        let _ = g.add_node(Node::new(&d.id, "doc", d.data_class, &d.label));
    }

    // Namespace nodes classed at the least-sensitive contained document.
    let mut ns_class: BTreeMap<String, DataClass> = BTreeMap::new();
    for d in &docs {
        if let Some(ns) = &d.namespace {
            let entry = ns_class.entry(ns.clone()).or_insert(d.data_class);
            if d.data_class.sensitivity() < entry.sensitivity() {
                *entry = d.data_class;
            }
        }
    }
    for (ns, class) in &ns_class {
        let ns_id = format!("ns:{ns}");
        let _ = g.add_node(Node::new(&ns_id, "namespace", *class, ns));
    }

    // Containment + reference edges (add_edge drops any edge with a missing endpoint).
    for d in &docs {
        if let Some(ns) = &d.namespace {
            let _ = g.add_edge(Edge::new(&format!("ns:{ns}"), &d.id, "contains"));
        }
        for r in &d.references {
            let _ = g.add_edge(Edge::new(&d.id, r, "mentions"));
        }
    }
    g
}

impl Graph {
    /// Convenience associated form of [`from_documents`] so callers can write
    /// `Graph::from_documents(kb)`.
    pub fn from_documents(docs: impl IntoIterator<Item = GraphDoc>) -> Graph {
        from_documents(docs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Low-clearance caller: `Internal` (sees Public + Internal, not Confidential/Regulated/Pii).
    fn low() -> Principal {
        Principal::user("analyst", &[])
    }

    /// Caller cleared to `Confidential` (sees the restricted bridge but not Pii/Regulated).
    fn cleared() -> Principal {
        Principal::user("lead", &[]).with_clearance(DataClass::Confidential)
    }

    /// Fixture:
    /// ```text
    ///   a(Public,code) --calls--> b(Internal,code) --imports--> d(Public,doc)
    ///   a --calls--> e(Public,code)
    ///   a --calls--> bridge(Confidential,code) --calls--> c(Public,doc)
    /// ```
    /// The ONLY route a -> c runs through the Confidential `bridge`.
    fn fixture() -> Graph {
        let mut g = Graph::new();
        g.add_node(Node::new("a", "code", DataClass::Public, "root"))
            .unwrap();
        g.add_node(Node::new("b", "code", DataClass::Internal, "beta"))
            .unwrap();
        g.add_node(Node::new("c", "doc", DataClass::Public, "gamma"))
            .unwrap();
        g.add_node(Node::new("d", "doc", DataClass::Public, "delta"))
            .unwrap();
        g.add_node(Node::new("e", "code", DataClass::Public, "epsilon"))
            .unwrap();
        g.add_node(Node::new(
            "bridge",
            "code",
            DataClass::Confidential,
            "restricted",
        ))
        .unwrap();
        // Insert edges out of sorted order to prove ordering is imposed by the graph, not input.
        g.add_edge(Edge::new("a", "e", "calls")).unwrap();
        g.add_edge(Edge::new("a", "bridge", "calls")).unwrap();
        g.add_edge(Edge::new("a", "b", "calls")).unwrap();
        g.add_edge(Edge::new("b", "d", "imports")).unwrap();
        g.add_edge(Edge::new("bridge", "c", "calls")).unwrap();
        g
    }

    fn ids(nodes: &[&Node]) -> Vec<String> {
        nodes.iter().map(|n| n.id.clone()).collect()
    }

    #[test]
    fn neighbors_filter_above_clearance_and_sort() {
        let g = fixture();
        // Low clearance: `bridge` (Confidential) is filtered out; b + e remain, id-sorted
        // despite being inserted e, bridge, b.
        assert_eq!(ids(&g.neighbors("a", &low())), vec!["b", "e"]);
        // Cleared: the restricted bridge becomes visible and sorts between b and e.
        assert_eq!(ids(&g.neighbors("a", &cleared())), vec!["b", "bridge", "e"]);
    }

    #[test]
    fn neighbors_of_invisible_node_are_indistinguishable_from_absent() {
        let g = fixture();
        // Querying neighbours of the hidden bridge yields nothing for the under-cleared caller —
        // identical to an unknown id — so its existence (and its edge to c) cannot be inferred.
        assert!(g.neighbors("bridge", &low()).is_empty());
        assert!(g.neighbors("does-not-exist", &low()).is_empty());
        // The cleared caller does see the bridge's neighbour.
        assert_eq!(ids(&g.neighbors("bridge", &cleared())), vec!["c"]);
    }

    #[test]
    fn bfs_respects_max_depth() {
        let g = fixture();
        // depth 0 = start only.
        assert_eq!(ids(&g.traversal("a", &low(), 0)), vec!["a"]);
        // depth 1 = a + its visible direct neighbours (b, e) in BFS/sorted order.
        assert_eq!(ids(&g.traversal("a", &low(), 1)), vec!["a", "b", "e"]);
        // depth 2 additionally reaches d (via b). c is NOT reachable — its only route is
        // through the restricted bridge, which is not a hop.
        assert_eq!(ids(&g.traversal("a", &low(), 2)), vec!["a", "b", "e", "d"]);
    }

    #[test]
    fn bfs_never_uses_restricted_node_as_stepping_stone() {
        let g = fixture();
        // Even at unlimited depth the low-clearance BFS can never reach c: c hangs off the
        // Confidential bridge only. The bridge is never enqueued, so neither the bridge nor c
        // ever appear — no stepping-stone, no existence leak via reachability.
        let seen = ids(&g.traversal("a", &low(), 100));
        assert!(!seen.contains(&"bridge".to_string()));
        assert!(!seen.contains(&"c".to_string()));
        assert_eq!(seen, vec!["a", "b", "e", "d"]);
        // A caller cleared for the bridge reaches everything through it.
        let seen_hi = ids(&g.traversal("a", &cleared(), 100));
        assert_eq!(seen_hi, vec!["a", "b", "bridge", "e", "d", "c"]);
    }

    #[test]
    fn bfs_from_invisible_start_is_empty() {
        let g = fixture();
        assert!(g.traversal("bridge", &low(), 5).is_empty());
        assert!(g.traversal("nope", &low(), 5).is_empty());
    }

    #[test]
    fn shortest_path_hides_restricted_bridge() {
        let g = fixture();
        // The only a->c route is a->bridge->c. For the under-cleared caller this is None: the
        // hidden bridge's existence never leaks via a reachability answer.
        assert!(g.shortest_path("a", "c", &low()).is_none());
        // For a caller cleared to the bridge it resolves, through the bridge, deterministically.
        let path = g.shortest_path("a", "c", &cleared()).unwrap();
        assert_eq!(ids(&path), vec!["a", "bridge", "c"]);
    }

    #[test]
    fn shortest_path_over_visible_nodes_and_self() {
        let g = fixture();
        // a->d via the fully-visible chain a->b->d.
        let path = g.shortest_path("a", "d", &low()).unwrap();
        assert_eq!(ids(&path), vec!["a", "b", "d"]);
        // from == to is the trivial single-node path.
        let selfp = g.shortest_path("a", "a", &low()).unwrap();
        assert_eq!(ids(&selfp), vec!["a"]);
        // A target that is itself invisible yields None (not a leak).
        assert!(g.shortest_path("a", "bridge", &low()).is_none());
    }

    #[test]
    fn add_edge_to_missing_node_errors() {
        let mut g = Graph::new();
        g.add_node(Node::new("a", "code", DataClass::Public, "a"))
            .unwrap();
        // Missing destination.
        assert_eq!(
            g.add_edge(Edge::new("a", "ghost", "calls")),
            Err(GraphError::UnknownNode("ghost".to_string()))
        );
        // Missing source.
        assert_eq!(
            g.add_edge(Edge::new("ghost", "a", "calls")),
            Err(GraphError::UnknownNode("ghost".to_string()))
        );
        // No dangling edge was recorded.
        assert!(g.neighbors("a", &low()).is_empty());
    }

    #[test]
    fn add_node_rejects_duplicate_downgrade() {
        let mut g = Graph::new();
        g.add_node(Node::new("x", "code", DataClass::Confidential, "x"))
            .unwrap();
        // A second add with a LOWER class must be refused — no silent clearance downgrade.
        assert_eq!(
            g.add_node(Node::new("x", "code", DataClass::Public, "x")),
            Err(GraphError::DuplicateNode("x".to_string()))
        );
        // Original (Confidential) class stands: still hidden from the low-clearance caller.
        assert!(g.get_visible("x", &low()).is_none());
        assert!(g.get_visible("x", &cleared()).is_some());
    }

    #[test]
    fn queries_are_deterministic_and_clearance_gated() {
        let g = fixture();
        // query_by_kind: code nodes for the low caller exclude the Confidential bridge.
        assert_eq!(ids(&g.query_by_kind("code", &low())), vec!["a", "b", "e"]);
        assert_eq!(
            ids(&g.query_by_kind("code", &cleared())),
            vec!["a", "b", "bridge", "e"]
        );
        // query_by_rel: 'calls' edges with BOTH endpoints visible. a->bridge and bridge->c are
        // hidden from the low caller; only a->b and a->e survive, ordered by (from, to).
        let low_calls: Vec<(String, String)> = g
            .query_by_rel("calls", &low())
            .iter()
            .map(|e| (e.from.clone(), e.to.clone()))
            .collect();
        assert_eq!(
            low_calls,
            vec![
                ("a".to_string(), "b".to_string()),
                ("a".to_string(), "e".to_string()),
            ]
        );
        // The cleared caller additionally sees the two bridge edges, still deterministically.
        let hi_calls: Vec<(String, String)> = g
            .query_by_rel("calls", &cleared())
            .iter()
            .map(|e| (e.from.clone(), e.to.clone()))
            .collect();
        assert_eq!(
            hi_calls,
            vec![
                ("a".to_string(), "b".to_string()),
                ("a".to_string(), "bridge".to_string()),
                ("a".to_string(), "e".to_string()),
                ("bridge".to_string(), "c".to_string()),
            ]
        );
    }

    #[test]
    fn cleared_principal_sees_the_full_graph() {
        let g = fixture();
        // An admin (Pii clearance) sees every node via traversal from a...
        let admin = Principal::admin("root");
        let seen = ids(&g.traversal("a", &admin, 100));
        assert_eq!(seen, vec!["a", "b", "bridge", "e", "d", "c"]);
        assert_eq!(seen.len(), g.node_count());
        // ...and every previously-restricted surface now resolves.
        assert!(g.shortest_path("a", "c", &admin).is_some());
        assert_eq!(ids(&g.neighbors("a", &admin)), vec!["b", "bridge", "e"]);
    }

    #[test]
    fn duplicate_edge_is_idempotent() {
        let mut g = Graph::new();
        g.add_node(Node::new("a", "code", DataClass::Public, "a"))
            .unwrap();
        g.add_node(Node::new("b", "code", DataClass::Public, "b"))
            .unwrap();
        g.add_edge(Edge::new("a", "b", "calls")).unwrap();
        g.add_edge(Edge::new("a", "b", "calls")).unwrap(); // same triple again
                                                           // Neighbour appears exactly once — no duplicate hop that could double a path count.
        assert_eq!(ids(&g.neighbors("a", &low())), vec!["b"]);
    }

    #[test]
    fn graph_error_serializes_stably() {
        // A tag/content shape a gateway can render; asserts a concrete computed string, not a
        // round-trip tautology.
        let json = serde_json::to_string(&GraphError::UnknownNode("z".to_string())).unwrap();
        assert_eq!(json, r#"{"error":"unknown_node","id":"z"}"#);
    }

    // =======================================================================
    // SURF-10 — the live `/graph` request-dispatch the parent (ainxt-server) wires.
    // A request arrives with the caller's JWT-derived Principal; the handler dispatches to the
    // RBAC-scoped traversal primitives. The SAME query under two clearances must never leak a
    // restricted node's existence via a reachability answer or a path.
    // =======================================================================

    /// A minimal `/graph` request the parent deserializes from the wire.
    enum GraphRequest {
        Traverse { start: String, max_depth: usize },
        Path { from: String, to: String },
    }

    /// The endpoint handler shape the parent will implement: dispatch under the caller's Principal.
    /// Kept in-test to prove the wiring is closeable with only the public API.
    fn handle_graph_request(g: &Graph, req: &GraphRequest, principal: &Principal) -> Vec<String> {
        match req {
            GraphRequest::Traverse { start, max_depth } => {
                ids(&g.traversal(start, principal, *max_depth))
            }
            GraphRequest::Path { from, to } => g
                .shortest_path(from, to, principal)
                .map(|p| ids(&p))
                .unwrap_or_default(),
        }
    }

    #[test]
    fn gap_ainxt_graph_surf10_endpoint_traversal_is_rbac_scoped_no_leak() {
        let g = fixture();
        let traverse = GraphRequest::Traverse {
            start: "a".into(),
            max_depth: 100,
        };
        // Under-cleared caller: c is unreachable (its only route is the Confidential bridge) and
        // the bridge itself never surfaces — no stepping-stone / reachability leak.
        let low_view = handle_graph_request(&g, &traverse, &low());
        assert_eq!(low_view, vec!["a", "b", "e", "d"]);
        assert!(!low_view.contains(&"bridge".to_string()));
        assert!(!low_view.contains(&"c".to_string()));
        // Cleared caller: the same request now traverses through the visible bridge.
        let hi_view = handle_graph_request(&g, &traverse, &cleared());
        assert_eq!(hi_view, vec!["a", "b", "bridge", "e", "d", "c"]);
    }

    #[test]
    fn gap_ainxt_graph_surf10_endpoint_shortest_path_hides_restricted_bridge() {
        let g = fixture();
        let path = GraphRequest::Path {
            from: "a".into(),
            to: "c".into(),
        };
        // The only a->c route runs through the restricted bridge: the under-cleared caller gets an
        // empty answer identical to "no such route", never learning the bridge (or c) exists.
        assert!(handle_graph_request(&g, &path, &low()).is_empty());
        // The cleared caller gets the real path through the bridge.
        assert_eq!(
            handle_graph_request(&g, &path, &cleared()),
            vec!["a", "bridge", "c"]
        );
    }
}
