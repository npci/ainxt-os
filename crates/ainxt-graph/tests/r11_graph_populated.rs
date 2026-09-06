// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R11 DATA — the knowledge graph is POPULATED from source documents (gap: "knowledge graph is
//! populated on the shipped daemon"). The traversal + RBAC primitives existed and the `/graph`
//! route was mounted, but `build_graph()` on the daemon returned `Graph::new()` — an empty graph, so
//! every served traversal reached nothing. `Graph::from_documents` builds a real code+docs graph
//! (doc nodes + namespace grouping + reference edges) from the same KB the retrieval corpus is
//! seeded from, and the daemon's `build_graph()` now calls it.
//!
//! Fail-before/pass-after: `GraphDoc` / `Graph::from_documents` did not exist, so this test crate
//! would not compile before the change; and a populated graph's `node_count > 0` with real
//! reachable neighbours is asserted here (the empty graph could never satisfy it).

use ainxt_graph::{from_documents, DataClass, GraphDoc, GraphQuery, Principal};

fn kb() -> Vec<GraphDoc> {
    vec![
        GraphDoc {
            id: "doc:onboarding".to_string(),
            label: "Onboarding Guide".to_string(),
            data_class: DataClass::Public,
            namespace: Some("platform".to_string()),
            references: vec!["doc:runbook".to_string(), "doc:missing".to_string()],
        },
        GraphDoc {
            id: "doc:runbook".to_string(),
            label: "Ops Runbook".to_string(),
            data_class: DataClass::Internal,
            namespace: Some("platform".to_string()),
            references: vec![],
        },
        GraphDoc {
            id: "doc:incident".to_string(),
            label: "PII Incident Report".to_string(),
            data_class: DataClass::Pii,
            namespace: Some("platform".to_string()),
            references: vec![],
        },
    ]
}

fn internal() -> Principal {
    Principal::user("dev", &[]).with_clearance(DataClass::Internal)
}
fn dpo() -> Principal {
    Principal::user("dpo", &[]).with_clearance(DataClass::Pii)
}

#[test]
fn r11_graph_populated_from_documents_is_non_empty_and_reachable() {
    let g = from_documents(kb());
    // 3 docs + 1 namespace node = 4. The empty daemon graph could never pass this.
    assert_eq!(g.node_count(), 4, "graph must be populated");

    // The namespace node reaches its contained docs (bounded traversal). At Internal clearance the
    // Pii incident doc is NEVER visited, counted, or bridged through — its existence never leaks.
    let q = GraphQuery::Traverse {
        start: "ns:platform".to_string(),
        max_depth: 5,
    };
    let view = ainxt_graph::graph_query(&g, &q, &internal());
    assert!(view.nodes.contains(&"ns:platform".to_string()));
    assert!(view.nodes.contains(&"doc:onboarding".to_string()));
    assert!(view.nodes.contains(&"doc:runbook".to_string()));
    assert!(
        !view.nodes.contains(&"doc:incident".to_string()),
        "Pii doc must be invisible to Internal clearance"
    );
}

#[test]
fn r11_graph_namespace_node_classed_at_least_sensitive_member() {
    // The namespace groups a Public + Internal + Pii doc; the grouping node must be visible to a
    // Public caller (least-sensitive member) yet never expose the restricted docs it groups.
    let g = from_documents(kb());
    let public = Principal::user("anon", &[]).with_clearance(DataClass::Public);
    let ns = GraphQuery::Node {
        id: "ns:platform".to_string(),
    };
    assert_eq!(
        ainxt_graph::graph_query(&g, &ns, &public).nodes,
        vec!["ns:platform".to_string()],
        "namespace node classed at its least-sensitive member (Public)"
    );
    // But a Public caller reaches only the Public doc via containment — Internal/Pii stay hidden.
    let trav = GraphQuery::Traverse {
        start: "ns:platform".to_string(),
        max_depth: 5,
    };
    let view = ainxt_graph::graph_query(&g, &trav, &public);
    assert!(view.nodes.contains(&"doc:onboarding".to_string()));
    assert!(!view.nodes.contains(&"doc:runbook".to_string()));
    assert!(!view.nodes.contains(&"doc:incident".to_string()));
}

#[test]
fn r11_graph_reference_edges_drop_dangling_targets() {
    // The onboarding doc references a non-existent "doc:missing"; that edge must be dropped, not
    // admitted as a dangling edge. The real "mentions" edge to runbook survives for the DPO.
    let g = from_documents(kb());
    let q = GraphQuery::Neighbors {
        id: "doc:onboarding".to_string(),
    };
    let view = ainxt_graph::graph_query(&g, &q, &dpo());
    assert!(view.nodes.contains(&"doc:runbook".to_string()));
    assert!(!view.nodes.contains(&"doc:missing".to_string()));
}
