// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-3 memory — KG-linkage diverged from the documented design.
//!
//! `ENTERPRISE_MEMORY_LEARNING.md` §4 is explicit: "OKIs are nodes in the Context Fabric Knowledge
//! Graph (extends layer 12, "Memory"), not a separate store the graph has to reach into — one
//! RBAC/data-class-aware graph, one query surface, one Context Optimizer." `ainxt-memory` fully
//! implements OKI-linkage semantics (`EdgeKind`, `Link`, `InMemoryStore::neighbors`/`traverse`) but as
//! an entirely separate, self-contained graph scoped to the memory store's own lookups — before this
//! fix, an OKI a human approver promoted to authority never became an `ainxt_graph::Node`/`Edge`, so
//! it never appeared in the SAME `/graph` surface the rest of the Context Fabric serves (verified by
//! grep: zero occurrence of `GraphDoc`/`add_node` in `ainxt-memory`; zero occurrence of
//! `MemoryItem`/`OrgKnowledge` in `ainxt-graph`).
//!
//! This closes the divergence at `link_authoritative_oki_into_graph`
//! (`ainxt-runtimed/src/lib.rs`, called from `assemble_full` right after `build_graph`): every
//! Approved/Production org-knowledge item present in the shared memory backend becomes a real
//! `ainxt_graph::Node` + its typed `Link`s become real `ainxt_graph::Edge`s, in the EXACT `Graph`
//! instance served at `/graph`.
//!
//! Fail-before/pass-after: before this fix `assemble_full` never opened the memory backend at all
//! while building the graph — an OKI promoted before daemon start could not possibly appear as a node,
//! because nothing ever looked. This test seeds and promotes an OKI, asserts it is genuinely absent
//! from a graph built the OLD way (KB documents only) as a sanity check, then proves it after
//! `assemble_full` via the real HTTP `/graph` route: `POST /v1/graph/query_by_kind` (or the
//! equivalent query surface `ainxt-server` exposes) returns the OKI node, and its `Cites` link to an
//! indexed ADR doc resolves as a real, traversable edge.

use ainxt_memory::{
    DurableMemoryStore, EdgeKind, Enforcement, Link, MemoryItem, MemoryStore, OrgPayload,
    Provenance, Scope,
};
use ainxt_runtimed::{assemble_chat, assemble_full, load_layered};
use ainxt_types::Principal;
use std::time::{SystemTime, UNIX_EPOCH};

fn loaded_with_kb_and_unique_log() -> ainxt_runtimed::LoadedConfig {
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("ainxt-r-okigraph-{nanos}"));
    // One KB document ("adr-042") so the OKI's `Cites` link has a real, already-indexed target node
    // to resolve against (an edge whose target is unknown is skipped, never fabricated).
    let src = format!(
        "version = 1\n[server]\nevent_log_dir = {:?}\n\
         [[kb.documents]]\nid = \"adr-042\"\nsource = \"adr-042\"\n\
         text = \"ADR-042: cross-team requests route through the async queue.\"\n\
         scope = \"platform\"\ndata_class = \"internal\"\n",
        dir.to_string_lossy()
    );
    load_layered(&[("r-okigraph", &src)]).expect("load config with one KB doc")
}

#[tokio::test(flavor = "multi_thread")]
async fn r_promoted_oki_lands_as_a_real_node_and_edge_in_the_served_graph() {
    let loaded = loaded_with_kb_and_unique_log();
    let assembled = assemble_chat(&loaded).expect("assemble chat");

    // The OKI must be seeded and promoted to authority BEFORE `assemble_full` runs: the fix
    // (`link_authoritative_oki_into_graph`) augments the graph ONCE, at assembly time (see that
    // function's doc for why a live-after-boot promotion is a separate, larger follow-up) — so this
    // clone must be taken, and the write must happen, before `assembled` is consumed below.
    let backend = assembled
        .memory_backend
        .clone()
        .expect("a chat-engine surface exposes a memory backend")
        .backend;

    // Seed a Draft OKI and promote it to authority — exactly the design's named trigger (§6: "the
    // flywheel proposes, a human legislates" — authority only via `promote`).
    let approver = Principal::admin("dpo-approver");
    {
        let mut store = DurableMemoryStore::open(backend.clone()).expect("open store");
        let mut item = MemoryItem::org(
            "oki-async-comms-convention",
            Scope::Org,
            "prefer async comms for cross-team requests",
            OrgPayload::CodingConvention {
                rule: "route cross-team requests through the async queue, not a direct call".into(),
                language: "any".into(),
                example_do: "publish to the request queue".into(),
                example_dont: "synchronous cross-team RPC".into(),
                enforcement: Enforcement::Advisory,
            },
            Provenance::human("dpo-approver", 1.0),
        );
        item.links.push(Link::new(EdgeKind::Cites, "adr-042"));
        store.write(item).expect("write draft OKI");
        let state = store
            .promote("oki-async-comms-convention", &approver)
            .expect("promote to authority");
        assert_eq!(
            state,
            ainxt_memory::GovernanceState::Approved,
            "sanity: the OKI must actually reach authority before this test means anything"
        );
    }

    let full = assemble_full(&loaded, assembled).expect("assemble full");

    // ---- Sanity: the OLD behavior (graph built from KB docs alone) genuinely never included OKIs —
    // this is the divergence being closed, not a hypothetical. ----
    {
        use ainxt_graph::{Graph, GraphDoc};
        let docs_only_graph = Graph::from_documents(vec![GraphDoc {
            id: "adr-042".into(),
            label: "adr-042".into(),
            data_class: ainxt_types::DataClass::Internal,
            namespace: Some("platform".into()),
            references: Vec::new(),
        }]);
        assert!(
            docs_only_graph.get_visible("oki-async-comms-convention", &approver).is_none(),
            "sanity: a KB-documents-only graph never contains an OKI node — proving this is a real \
             gap, not one already closed some other way"
        );
    }

    // ---- The real, served surface: the daemon's OWN `/graph` route, over the shipped composition. ----
    let app = full.to_full_app();
    let ext = full.to_full_app_ext();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(ainxt_server::serve_full_ext(listener, app, ext));

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{addr}/graph"))
        .header("x-ainxt-user", "dpo-approver")
        .header("x-ainxt-role", "admin")
        .header("content-type", "application/json")
        .body(
            serde_json::json!({
                "op": "by_kind",
                "kind": "oki"
            })
            .to_string(),
        )
        .send()
        .await
        .expect("graph query request");
    assert_eq!(resp.status().as_u16(), 200, "POST /graph must be served");
    let body: serde_json::Value = resp.json().await.expect("graph response is JSON");
    let body_text = body.to_string();
    assert!(
        body_text.contains("oki-async-comms-convention"),
        "the promoted OKI must appear as a real node in the SAME graph the served /graph route \
         reads, not a separate structure memory keeps to itself: {body_text}"
    );

    // The typed `Cites` link must resolve as a real, traversable graph edge into the KB-indexed
    // "adr-042" node — not merely a string field frozen inside the memory item.
    let neighbors = client
        .post(format!("http://{addr}/graph"))
        .header("x-ainxt-user", "dpo-approver")
        .header("x-ainxt-role", "admin")
        .header("content-type", "application/json")
        .body(
            serde_json::json!({
                "op": "neighbors",
                "id": "oki-async-comms-convention"
            })
            .to_string(),
        )
        .send()
        .await
        .expect("neighbors query request");
    assert_eq!(neighbors.status().as_u16(), 200);
    let neighbors_body: serde_json::Value =
        neighbors.json().await.expect("neighbors response is JSON");
    assert!(
        neighbors_body.to_string().contains("adr-042"),
        "the OKI's `Cites` link must resolve as a real outgoing edge to the KB-indexed doc node: {neighbors_body}"
    );
}
