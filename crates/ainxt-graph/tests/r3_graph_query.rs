// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R3 DATA — integration coverage for the mount-ready `graph_query` entrypoint (SURF-10).
//!
//! Gap: "Knowledge-graph /graph RBAC endpoint not mounted on the served app." The traversal
//! primitives existed, but the request-dispatch + RBAC projection lived hand-rolled inside the
//! (reserved) transport crate. `graph_query` + `GraphQuery`/`GraphQueryResponse` move that into a
//! single clean entrypoint a route mounts directly.
//!
//! Fail-before/pass-after: `graph_query` / `GraphQuery` / `GraphQueryResponse` did not exist, so
//! this test crate would not compile before the change.

use ainxt_graph::{graph_query, DataClass, Edge, Graph, GraphQuery, Node, Principal};

/// a --(calls)--> secret --(calls)--> c, where `secret` is Pii and the only bridge from a to c.
/// A stepping-stone graph: reaching `c` from `a` REQUIRES passing through the restricted node.
fn bridged_graph() -> Graph {
    let mut g = Graph::new();
    g.add_node(Node::new("a", "function", DataClass::Internal, "pub_a"))
        .unwrap();
    g.add_node(Node::new("secret", "function", DataClass::Pii, "secret_fn"))
        .unwrap();
    g.add_node(Node::new("c", "function", DataClass::Internal, "pub_c"))
        .unwrap();
    g.add_edge(Edge::new("a", "secret", "calls")).unwrap();
    g.add_edge(Edge::new("secret", "c", "calls")).unwrap();
    g
}

fn low() -> Principal {
    // Cleared only to Internal — must never see the Pii `secret` node.
    Principal::user("dev", &[]).with_clearance(DataClass::Internal)
}
fn high() -> Principal {
    Principal::user("dpo", &[]).with_clearance(DataClass::Pii)
}

#[test]
fn r3_graph_query_traverse_never_steps_through_restricted_node() {
    let g = bridged_graph();
    let q = GraphQuery::Traverse {
        start: "a".to_string(),
        max_depth: 10,
    };

    // Low clearance: the traversal cannot hop through `secret`, so `c` is unreachable and `secret`
    // is never listed. Only `a` (the visible start) comes back.
    let low_view = graph_query(&g, &q, &low());
    assert_eq!(low_view.nodes, vec!["a".to_string()]);
    assert!(!low_view.nodes.contains(&"secret".to_string()));
    assert!(!low_view.nodes.contains(&"c".to_string()));

    // High clearance: the whole chain is visible.
    let high_view = graph_query(&g, &q, &high());
    assert!(high_view.nodes.contains(&"secret".to_string()));
    assert!(high_view.nodes.contains(&"c".to_string()));
}

#[test]
fn r3_graph_query_path_is_blocked_by_invisible_hop() {
    let g = bridged_graph();
    let q = GraphQuery::Path {
        from: "a".to_string(),
        to: "c".to_string(),
    };

    // The only a→c path runs through the hidden `secret`; a low-clearance caller must get NO path
    // (never a "bridged" answer that would confirm `c`'s reachability via the hidden node).
    assert!(graph_query(&g, &q, &low()).nodes.is_empty());

    // With clearance the full path is returned in order.
    assert_eq!(
        graph_query(&g, &q, &high()).nodes,
        vec!["a".to_string(), "secret".to_string(), "c".to_string()]
    );
}

#[test]
fn r3_graph_query_node_and_bykind_hide_restricted_and_serialize() {
    let g = bridged_graph();

    // Direct node lookup of a restricted node yields nothing for the low caller (no existence leak).
    let node_q = GraphQuery::Node {
        id: "secret".to_string(),
    };
    assert!(graph_query(&g, &node_q, &low()).nodes.is_empty());
    assert_eq!(
        graph_query(&g, &node_q, &high()).nodes,
        vec!["secret".to_string()]
    );

    // ByKind excludes the restricted node from the low caller's result set.
    let kind_q = GraphQuery::ByKind {
        kind: "function".to_string(),
    };
    let low_ids = graph_query(&g, &kind_q, &low()).nodes;
    assert!(low_ids.contains(&"a".to_string()) && low_ids.contains(&"c".to_string()));
    assert!(!low_ids.contains(&"secret".to_string()));

    // Mount-readiness: request deserializes from the wire, response serializes back.
    let parsed: GraphQuery =
        serde_json::from_value(serde_json::json!({"op": "neighbors", "id": "a"})).unwrap();
    let resp = graph_query(&g, &parsed, &high());
    let json = serde_json::to_value(&resp).unwrap();
    assert_eq!(json["nodes"], serde_json::json!(["secret"]));
}
