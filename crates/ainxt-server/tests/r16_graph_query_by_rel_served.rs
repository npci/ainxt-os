// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R16 — `context-fabric` gap: [`ainxt_graph::Graph::query_by_rel`] (all edges labelled `rel` with
//! BOTH endpoints RBAC-visible) was a real, unit-tested projection with no [`ainxt_graph::GraphQuery`]
//! variant routing to it. The served `POST /graph` entrypoint (`ainxt_server::graph_router` →
//! `ainxt_graph::graph_query`) only ever dispatched `traverse` / `path` / `neighbors` / `by_kind` /
//! `node` — `query_by_rel` had zero callers outside `ainxt-graph`'s own tests, so a renderer could
//! never ask "show me every `calls` edge I'm allowed to see" over the wire even though the RBAC-safe
//! primitive existed and worked.
//!
//! Fix: added `GraphQuery::ByRel { rel }` + a `GraphQueryResponse.edges` field (additive, `#[serde(default)]`
//! so an existing decoder that only reads `nodes` is unaffected) and wired the new dispatcher arm to
//! `Graph::query_by_rel`.
//!
//! This test drives the SERVED app (`ainxt_server::app_full` + a real HTTP round trip), not the
//! library function directly, and proves the RBAC guarantee still holds on the new path: an edge
//! whose far endpoint is above the caller's clearance must not appear.
//!
//! FAIL-BEFORE: the request below is rejected by serde with an "unknown variant `by_rel`" 400 (or,
//! before that, could not even be expressed) because no such `GraphQuery` variant existed.
//! PASS-AFTER: 200, the low-clearance caller sees only the `pub1 -> pub2` edge; the high-clearance
//! caller also sees the edge bridging to the confidential node.

use ainxt_graph::{Edge, Graph, Node};
use ainxt_runtime::engine_with_defaults;
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_server::{app_full, FullApp, TrustedGatewayAuth};
use ainxt_session::{SessionConfig, SessionManager};
use ainxt_types::DataClass;
use std::sync::Arc;
use tokio::sync::mpsc;

struct Fixed;
impl Provider for Fixed {
    fn id(&self) -> &str {
        "fixed"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, _prompt: &str) -> mpsc::Receiver<ainxt_protocol::Event> {
        let (tx, rx) = mpsc::channel(8);
        tokio::spawn(async move {
            let _ = tx.send(ainxt_protocol::Event::Done).await;
        });
        rx
    }
}

fn manager() -> Arc<SessionManager> {
    let mut router = ModelRouter::new();
    router.register(Box::new(Fixed));
    Arc::new(SessionManager::new(
        Arc::new(engine_with_defaults(router)),
        SessionConfig::default(),
    ))
}

fn temp_log_dir(tag: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("ainxt-r16-graph-byrel-{tag}-{nanos}"))
}

async fn spawn_app() -> String {
    // pub1 --calls--> pub2   (both public, visible to everyone)
    // pub1 --calls--> sec1   (sec1 is confidential — the bridge must not leak to a low-clearance caller)
    let mut g = Graph::new();
    g.add_node(Node::new("pub1", "fn", DataClass::Public, "pub1"))
        .unwrap();
    g.add_node(Node::new("pub2", "fn", DataClass::Public, "pub2"))
        .unwrap();
    g.add_node(Node::new("sec1", "fn", DataClass::Confidential, "sec1"))
        .unwrap();
    g.add_edge(Edge::new("pub1", "pub2", "calls")).unwrap();
    g.add_edge(Edge::new("pub1", "sec1", "calls")).unwrap();
    // A differently-labelled edge that must never show up in a "calls" projection.
    g.add_edge(Edge::new("pub2", "pub1", "imports")).unwrap();

    let event_log: Arc<dyn ainxt_eventlog::EventLog> =
        Arc::new(ainxt_eventlog::JsonlEventLog::open(&temp_log_dir("app")).expect("open log"));
    let cfg = FullApp {
        manager: manager(),
        auth: Arc::new(TrustedGatewayAuth),
        event_log,
        control_plane_sha: "sha-r16-graph".to_string(),
        serving: None,
        graph: Some(Arc::new(g)),
        ledger_schema: None,
        harness: None,
    };
    let router = app_full(cfg);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    addr
}

#[tokio::test(flavor = "multi_thread")]
async fn r16_by_rel_is_reachable_from_the_served_graph_endpoint_and_stays_rbac_safe() {
    let addr = spawn_app().await;
    let client = reqwest::Client::new();

    // A low-clearance caller (default Principal::user clearance is Public) asks for every "calls"
    // edge. Before the fix this `op` did not exist at all.
    let low = client
        .post(format!("http://{addr}/graph"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header("x-ainxt-user", "analyst")
        .body(serde_json::json!({"op": "by_rel", "rel": "calls"}).to_string())
        .send()
        .await
        .expect("low request")
        .text()
        .await
        .expect("low body");
    assert!(
        low.contains("pub1") && low.contains("pub2"),
        "the visible pub1->pub2 `calls` edge must be present: {low}"
    );
    assert!(
        !low.contains("sec1"),
        "an edge bridging to an above-clearance node must never leak its existence: {low}"
    );
    assert!(
        !low.contains("imports"),
        "a `calls` query must never surface an `imports` edge: {low}"
    );

    // A confidential-cleared caller sees the bridging edge too — proving the endpoint is genuinely
    // RBAC-scoped per-caller, not just hardcoded to omit `sec1`.
    let high = client
        .post(format!("http://{addr}/graph"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header("x-ainxt-user", "auditor")
        .header("x-ainxt-clearance", "confidential")
        .body(serde_json::json!({"op": "by_rel", "rel": "calls"}).to_string())
        .send()
        .await
        .expect("high request")
        .text()
        .await
        .expect("high body");
    assert!(
        high.contains("sec1"),
        "a cleared caller must see the bridging edge to the confidential node: {high}"
    );

    // The existing `by_kind` op on the SAME served endpoint still works unchanged (no regression on
    // the response shape's `nodes` field from adding the additive `edges` field).
    let by_kind = client
        .post(format!("http://{addr}/graph"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header("x-ainxt-user", "analyst")
        .body(serde_json::json!({"op": "by_kind", "kind": "fn"}).to_string())
        .send()
        .await
        .expect("by_kind request");
    assert!(
        by_kind.status().is_success(),
        "by_kind must still succeed: {}",
        by_kind.status()
    );
    let by_kind_body = by_kind.text().await.expect("by_kind body");
    assert!(
        by_kind_body.contains("pub1")
            && by_kind_body.contains("pub2")
            && !by_kind_body.contains("sec1"),
        "by_kind must keep its own RBAC-scoped behavior unchanged: {by_kind_body}"
    );
}
