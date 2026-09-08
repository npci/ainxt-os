// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R19 (gap `context-fabric`) — `governed::compile_served_fabric` is MOUNTED on the served chat path.
//!
//! Before this, `compile_served_fabric` (the routed, multi-layer, PageRank-fused fabric-of-graphs
//! compile — `CONTEXT_FABRIC.md` §2–§3) was reachable only from `r13_context_fabric_served.rs`'s direct
//! unit-style calls; its own doc comment said so explicitly: "deliberately NOT yet mounted on
//! `/v1/chat`". `FabricGroundedChatSurface` (`ainxt-runtimed/src/fabric_chat.rs`) is the wire, and
//! `assemble_chat_fabric_grounded` is the composition-root entrypoint that mounts it.
//!
//! This file proves, on the SERVED turn path (not a direct library call):
//!   1. an EMPTY fabric is a byte-identical no-op — the wrapped surface produces the SAME served answer
//!      as the unwrapped default `assemble_chat` surface (the explicit regression proof);
//!   2. a POPULATED fabric actually grounds the turn — the inner handler receives the fabric's content,
//!      labelled by which fabric layer it came from;
//!   3. the wrap still enforces pre-rank node-ACL (department) RBAC — a caller outside the node's
//!      department gets the SAME transparent (ungrounded) behavior as the empty-fabric case, never a
//!      leak and never a denial.

use std::sync::Arc;

use ainxt_context::optimizer::{EdgeKind, FabricGraph, GraphLayer};
use ainxt_context::route::MultiGraphFabric;
use ainxt_context::Chunk as CtxChunk;
use ainxt_profile::RetrievalScope;
use ainxt_protocol::{Event, Request};
use ainxt_retrieval::EligibleModel;
use ainxt_runtime::{CancelToken, TurnError, TurnHandler, TurnSummary};
use ainxt_runtimed::governed::served_fabric_from_kb;
use ainxt_runtimed::{
    assemble_chat, assemble_chat_fabric_grounded, load_layered, FabricGroundedChatSurface,
    KbConfig, KbDocument, KbScope,
};
use ainxt_types::{DataClass, Principal, Tier};
use tokio::sync::mpsc;

/// An inner [`TurnHandler`] standing in for the grounded chat turn: it records the exact [`Request`]
/// it received and echoes the input back. If the recorded input differs from what the CALLER sent,
/// the fabric wrapper rewrote it — the observable proof of live grounding (or its absence).
struct RecordingHandler {
    seen: std::sync::Mutex<Option<Request>>,
}

impl RecordingHandler {
    fn new() -> Self {
        RecordingHandler {
            seen: std::sync::Mutex::new(None),
        }
    }
}

impl TurnHandler for RecordingHandler {
    fn handle_turn<'a>(
        &'a self,
        _principal: &'a Principal,
        req: &'a Request,
        sink: mpsc::Sender<Event>,
        _cancel: &'a CancelToken,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<TurnSummary, TurnError>> + Send + 'a>,
    > {
        Box::pin(async move {
            *self.seen.lock().unwrap() = Some(req.clone());
            let text = format!("echo:{}", req.input);
            let _ = sink.send(Event::TextDelta(text.clone())).await;
            let _ = sink.send(Event::Done).await;
            Ok(TurnSummary {
                final_text: text,
                redactions: 0,
                provider: "echo".into(),
                ..Default::default()
            })
        })
    }
}

fn principal(dept: Option<&str>) -> Principal {
    let mut p = Principal::user("u-alice", &["chat.send"]).with_clearance(DataClass::Internal);
    if let Some(d) = dept {
        p = p.with_department(d);
    }
    p
}

fn req(input: &str) -> Request {
    Request {
        session: "s1".into(),
        turn: "t1".into(),
        input: input.into(),
        data_class: DataClass::Internal,
        tier: Tier::Medium,
        forced_provider: None,
        untrusted_tainted: false,
        user_turn: None,
        namespace: None,
        pinned_tier: None,
        request_override: None,
        history_budget_tokens: None,
    }
}

async fn drive(
    surface: &FabricGroundedChatSurface,
    p: &Principal,
    r: &Request,
) -> Result<TurnSummary, TurnError> {
    let (tx, mut rx) = mpsc::channel::<Event>(64);
    let cancel = CancelToken::new();
    let res = surface.handle_turn(p, r, tx, &cancel).await;
    while rx.recv().await.is_some() {}
    res
}

fn kb_doc(id: &str, text: &str, dept: Option<&str>) -> KbDocument {
    KbDocument {
        id: id.into(),
        source: "kb".into(),
        text: text.into(),
        data_class: DataClass::Internal,
        scope: KbScope::Platform,
        namespace: None,
        repo: None,
        department: dept.map(|d| d.to_string()),
        max_ad_level: None,
        allow_groups: vec![],
        deny_groups: vec![],
        row_attributes: Default::default(),
    }
}

// (1) An EMPTY fabric must be a byte-identical pass-through at the wrapper level: the recording
// handler must see the EXACT SAME request the caller sent (no rewritten `input`, no `user_turn` set).
#[tokio::test]
async fn r19_fabric_wrapper_is_transparent_over_an_empty_fabric() {
    let recorder = Arc::new(RecordingHandler::new());
    let surface = FabricGroundedChatSurface::new(
        recorder.clone(),
        MultiGraphFabric::new(),
        vec![EligibleModel::new("served-default", 8_000)],
        "chat",
    );
    let p = principal(None);
    let r = req("what is the settlement cutoff?");
    let out = drive(&surface, &p, &r).await.expect("turn completes");
    assert_eq!(out.final_text, "echo:what is the settlement cutoff?");

    let seen = recorder
        .seen
        .lock()
        .unwrap()
        .clone()
        .expect("inner handler was invoked");
    assert_eq!(
        seen.input, r.input,
        "empty fabric must not rewrite the request input"
    );
    assert!(
        seen.user_turn.is_none(),
        "empty fabric must not synthesize a user_turn either"
    );
}

// (2) A POPULATED fabric must actually ground the turn: the inner handler must observe the fabric's
// content, labelled by the fabric layer it was routed from — the live-wiring proof.
#[tokio::test]
async fn r19_fabric_wrapper_grounds_the_turn_from_a_populated_fabric() {
    let kb = KbConfig {
        documents: vec![kb_doc(
            "settle-1",
            "Payment settlement reconciliation batches run in deferred net cycles at 20:00 IST.",
            None,
        )],
        rls_department_isolation: false,
        rag_enabled: true,
    };
    let fabric = served_fabric_from_kb(
        &kb,
        RetrievalScope::PlatformAndNamespace,
        FabricGraph::new(),
        vec![],
    );
    assert!(
        !fabric.is_empty(),
        "the KB document must populate the fabric"
    );

    let recorder = Arc::new(RecordingHandler::new());
    let surface = FabricGroundedChatSurface::new(
        recorder.clone(),
        fabric,
        vec![EligibleModel::new("served-default", 8_000)],
        "chat",
    );
    let p = principal(None);
    let raw = "when does settlement reconciliation run";
    let r = req(raw);
    drive(&surface, &p, &r).await.expect("turn completes");

    let seen = recorder
        .seen
        .lock()
        .unwrap()
        .clone()
        .expect("inner handler was invoked");
    assert!(
        seen.input.contains("deferred net cycles at 20:00 IST"),
        "the grounded input must carry the fabric's retrieved content: {}",
        seen.input
    );
    assert!(
        seen.input.contains("context-fabric"),
        "the grounded input must be labelled as fabric-compiled: {}",
        seen.input
    );
    assert_eq!(
        seen.user_turn.as_deref(),
        Some(raw),
        "the RAW user turn must be preserved for intent classification, never overwritten by the \
         composed grounding prompt"
    );
}

// (3) The wrap must still enforce pre-rank node-ACL (department) RBAC: a caller outside the document's
// department gets the SAME transparent behavior as an empty fabric — existence never leaks, and the
// turn is never denied (a retrieval read-filter, not an admission gate).
#[tokio::test]
async fn r19_fabric_wrapper_still_enforces_pre_rank_department_rbac() {
    let kb = KbConfig {
        documents: vec![kb_doc(
            "beta-only",
            "Beta-department incident runbook: escalate to the beta on-call channel.",
            Some("beta"),
        )],
        rls_department_isolation: false,
        rag_enabled: true,
    };
    let fabric = served_fabric_from_kb(
        &kb,
        RetrievalScope::PlatformAndNamespace,
        FabricGraph::new(),
        vec![],
    );

    let recorder = Arc::new(RecordingHandler::new());
    let surface = FabricGroundedChatSurface::new(
        recorder.clone(),
        fabric,
        vec![EligibleModel::new("served-default", 8_000)],
        "chat",
    );
    // Caller is in "alpha", not "beta" — the node is department-locked to beta.
    let p = principal(Some("alpha"));
    let r = req("what is the beta incident runbook");
    let out = drive(&surface, &p, &r)
        .await
        .expect("turn completes — never a denial");

    assert_eq!(out.final_text, "echo:what is the beta incident runbook");
    let seen = recorder
        .seen
        .lock()
        .unwrap()
        .clone()
        .expect("inner handler was invoked");
    assert_eq!(
        seen.input, r.input,
        "a dept-locked node must ground NOTHING for an out-of-department caller — existence never \
         leaks, and the turn falls back to the same transparent path as an empty fabric"
    );
}

// (3b) Gap `context-fabric` (community detection reachable after the fabric is mounted): a
// global/sensemaking query (`optimizer::classify_scope` → `QueryScope::Global`) routes the query plan
// to `GraphLayer::GlobalSummary`, which drives `MultiGraphFabric::global_summaries` →
// `optimizer::detect_communities` (synchronous label propagation) on the SERVED path, now that
// `FabricGroundedChatSurface` mounts `compile_served_fabric`. Before item 1's wiring, this deterministic
// community-detection algorithm was reachable only from `ainxt-context`'s own unit tests +
// `r13_context_fabric_served.rs`'s direct library calls — never from a served turn.
#[tokio::test]
async fn r19_fabric_wrapper_reaches_community_detection_for_a_global_sensemaking_query() {
    // A small connected cluster (a triangle) — label propagation converges all three into ONE
    // community.
    let code_graph = FabricGraph::new()
        .with_layer("n1", GraphLayer::Symbol)
        .with_layer("n2", GraphLayer::Symbol)
        .with_layer("n3", GraphLayer::Symbol)
        .with_edge("n1", EdgeKind::Calls, "n2")
        .with_edge("n2", EdgeKind::Calls, "n3")
        .with_edge("n1", EdgeKind::Calls, "n3");
    let text = "recurring settlement timeout pattern across regions";
    let code_contents = vec![
        CtxChunk::new("n1", "trace-1", text, DataClass::Internal),
        CtxChunk::new("n2", "trace-2", text, DataClass::Internal),
        CtxChunk::new("n3", "trace-3", text, DataClass::Internal),
    ];
    let kb = KbConfig {
        documents: vec![],
        rls_department_isolation: false,
        rag_enabled: true,
    };
    let fabric = served_fabric_from_kb(
        &kb,
        RetrievalScope::PlatformAndNamespace,
        code_graph,
        code_contents,
    );

    let recorder = Arc::new(RecordingHandler::new());
    let surface = FabricGroundedChatSurface::new(
        recorder.clone(),
        fabric,
        vec![EligibleModel::new("served-default", 8_000)],
        "chat",
    );
    let p = principal(None);
    // "what are the" + "recurring" + "patterns" scores decisively Global in `classify_scope` (no
    // point-lookup cues at all) — this is a CLASSIFIED decision, not a keyword lookup table.
    let raw = "what are the recurring patterns behind the settlement timeouts";
    let r = req(raw);
    drive(&surface, &p, &r).await.expect("turn completes");

    let seen = recorder
        .seen
        .lock()
        .unwrap()
        .clone()
        .expect("inner handler was invoked");
    assert!(
        seen.input.contains("[community"),
        "a global/sensemaking query must ground a community summary from detect_communities: {}",
        seen.input
    );
}

// (4) Composition-root regression proof: `assemble_chat_fabric_grounded` with an EMPTY fabric (no KB
// documents, no code overlay — the same config `assemble_chat` sees) must serve the SAME turn
// byte-identically to the default, un-wrapped `assemble_chat` surface.
#[tokio::test(flavor = "multi_thread")]
async fn r19_assemble_chat_fabric_grounded_matches_assemble_chat_when_fabric_is_empty() {
    use ainxt_client::{Client, ClientConfig};

    let loaded = load_layered(&[("x", "version = 1")]).unwrap();

    let baseline = assemble_chat(&loaded).unwrap();
    let baseline_client = Client::in_process(
        baseline.manager,
        Principal::user("u", &["chat.send"]),
        ClientConfig::default(),
    );
    let baseline_out = baseline_client
        .chat("s", "t", "hi")
        .unwrap()
        .collect()
        .await;

    let fabric_grounded =
        assemble_chat_fabric_grounded(&loaded, FabricGraph::new(), vec![]).unwrap();
    assert!(
        fabric_grounded
            .report
            .iter()
            .any(|r| r.contains("FABRIC-GROUNDED") && r.contains("empty")),
        "an empty fabric must be reported as the byte-identical pass-through: {:?}",
        fabric_grounded.report
    );
    let fg_client = Client::in_process(
        fabric_grounded.manager,
        Principal::user("u", &["chat.send"]),
        ClientConfig::default(),
    );
    let fg_out = fg_client.chat("s", "t", "hi").unwrap().collect().await;

    assert!(baseline_out.completed && fg_out.completed);
    assert_eq!(
        baseline_out.text, fg_out.text,
        "an empty fabric must serve the SAME answer as the default assemble_chat surface — no \
         regression on the served /v1/chat hot path"
    );
}

// (5) Composition-root live-wiring proof: a deployment with a populated KB grounds turns over the
// routed fabric via `assemble_chat_fabric_grounded` — reachable end-to-end from config, not just the
// direct wrapper unit tests above.
#[tokio::test(flavor = "multi_thread")]
async fn r19_assemble_chat_fabric_grounded_reports_populated_layers_from_kb_config() {
    let cfg = r#"
        version = 1
        [[kb.documents]]
        id = "settle-1"
        source = "settlement-runbook"
        text = "Settlement reconciliation runs in deferred net batches via the national switch."
        scope = "platform"
        data_class = "internal"
    "#;
    let loaded = load_layered(&[("t", cfg)]).unwrap();
    let assembled = assemble_chat_fabric_grounded(&loaded, FabricGraph::new(), vec![]).unwrap();
    assert!(
        assembled
            .report
            .iter()
            .any(|r| r.contains("FABRIC-GROUNDED")
                && r.contains("populated")
                && r.contains("EnterpriseDocs")),
        "a configured KB document must populate the EnterpriseDocs fabric layer: {:?}",
        assembled.report
    );
    // Sanity: the layer enum used in the report is the real one the fabric actually indexes into.
    let _ = GraphLayer::EnterpriseDocs;
    let _ = CtxChunk::new("x", "y", "z", DataClass::Public);
}
