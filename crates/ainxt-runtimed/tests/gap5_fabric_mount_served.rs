// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX context-fabric (+ data-surfaces-artifacts, same root cause) — proves the fix is mounted on
//! the REAL `--surface` dispatch table `main.rs` drives, not merely reachable via a direct library call.
//!
//! Before this fix: `assemble_chat_fabric_grounded` (the fabric-of-graphs composition-root function —
//! multi-graph automatic grounding, cross-graph personalized PageRank, global/sensemaking community
//! detection, the multimodal-artifact tier) was complete, unit-tested, and even served-turn-tested in
//! `r19_fabric_grounded_chat_served.rs` — but `main.rs`'s ONLY dispatch table
//! ([`assemble_selected_governed`]) had NO arm that could ever produce it: `"chat_fabric_grounded"` fell
//! through, like any unrecognized id, to the profile-catalog path (`assemble_surface`), which never
//! wraps in [`ainxt_runtimed::FabricGroundedChatSurface`]. An operator could never actually select it
//! from the shipped daemon binary; only a test ever called the composition-root function directly.
//!
//! This test drives [`assemble_selected_fabric_grounded`] — the new dispatch layer — exactly as
//! `main.rs` does, wraps it in the SAME [`assemble_full_with_control_plane`] the daemon uses, serves it
//! over a REAL socket via `ainxt_server::serve_full_ext` (mirrors `r9_served_wire_replay_regfi.rs` /
//! `r16_regfi_erasure_guards_mirrored_turn.rs`), and drives a REAL `POST /v1/chat` over `reqwest`.
//!
//! The served daemon's air-gapped default (`OfflineProvider`) always returns a fixed, prompt-invariant
//! string ("offline mode: no model configured."), so a served turn's FINAL ANSWER TEXT can never show
//! whether retrieval fired. To observe the real, wire-level effect of mounting fabric-grounding on a
//! served turn, this test configures a `kind = "local"` (in-house, keyless) model provider pointed at a
//! tiny hand-rolled mock `/chat/completions` upstream that captures the EXACT outbound prompt the real
//! `OpenAiSchemaProvider` sends — the transport boundary any composed/grounded content must cross to
//! ever influence a real model's answer. This is not a stub of the mechanism under test; it stubs only
//! the vendor HTTP endpoint the REAL provider adapter calls, exactly as a live deployment's own
//! `[[models.providers]] kind = "local"` entry would point at a real local vLLM/Ollama endpoint.
//!
//! Fail-before / pass-after: before this fix, `assemble_selected_fabric_grounded` did not exist, so this
//! test could not compile against the old API; even calling `assemble_selected_governed` with the
//! `"chat_fabric_grounded"` id would silently resolve to the (nonexistent) profile-catalog path and the
//! captured prompt would carry no `[context-fabric` marker at all.

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use ainxt_context::artifact::{Artifact, Modality};
use ainxt_context::optimizer::FabricGraph;
use ainxt_identity::control::ControlPlane;
use ainxt_runtimed::{
    assemble_chat_fabric_grounded_with_artifacts, assemble_full_with_control_plane,
    assemble_selected_fabric_grounded, LoadedConfig,
};
use ainxt_types::DataClass;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// A distinctive KB fact only findable via the fabric's routed (multi-graph, PageRank-fused,
/// community-detection-eligible) EnterpriseDocs layer — never present in the raw user turn.
const KB_MARKER: &str = "deferred net cycles at 20:00 IST via the RTGS switch";

/// Find the first `\r\n\r\n` header/body separator in a raw byte buffer.
fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// A raw, hand-rolled mock OpenAI-`/chat/completions`-schema upstream (no axum/hyper dependency
/// needed): captures every request's `messages[0].content` (the exact outbound prompt the real
/// `OpenAiSchemaProvider` sends) into `captured`, in arrival order, then replies with a minimal,
/// deterministic SSE stream so the REAL `OpenAiNormalizer` on the served path completes the turn
/// normally (mirrors the exact wire fixture `ainxt-providers`'s own unit tests use).
async fn spawn_mock_llm(captured: Arc<Mutex<Vec<String>>>) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock llm");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => break,
            };
            let captured = captured.clone();
            tokio::spawn(async move {
                let mut buf: Vec<u8> = Vec::new();
                let mut chunk = [0u8; 8192];
                let (headers_end, content_length) = loop {
                    let n = match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(pos) = find_double_crlf(&buf) {
                        let headers = String::from_utf8_lossy(&buf[..pos]).to_string();
                        let cl = headers
                            .lines()
                            .find_map(|l| {
                                let (k, v) = l.split_once(':')?;
                                if k.trim().eq_ignore_ascii_case("content-length") {
                                    v.trim().parse::<usize>().ok()
                                } else {
                                    None
                                }
                            })
                            .unwrap_or(0);
                        if buf.len() >= pos + 4 + cl {
                            break (pos, cl);
                        }
                    }
                };
                let body_start = headers_end + 4;
                let body = &buf[body_start..body_start + content_length];
                let body_str = String::from_utf8_lossy(body);
                let value: serde_json::Value = serde_json::from_str(&body_str).unwrap_or_default();
                let prompt = value["messages"][0]["content"]
                    .as_str()
                    .unwrap_or("")
                    .to_string();
                captured.lock().unwrap().push(prompt.clone());

                // The engine issues MORE than one model call per turn — a constrained intent
                // classification call first (`ChatClassifier`, on the RAW user turn), then the answer
                // generation call (on the composed/grounded prompt). This mock must answer the
                // classification call with a VALID label or the engine's retry/fallback logic never
                // reaches the generation call at all — reply "qa" for that one, "ok" for every other
                // (the generation call's reply content is irrelevant to this test; only the CAPTURED
                // outbound prompt for the generation call is asserted on).
                let reply = if prompt.contains("Classify the user's intent") {
                    "qa"
                } else {
                    "ok"
                };
                let sse = format!(
                    "data: {{\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"model\":\"mock\",\"choices\":[{{\"index\":0,\"delta\":{{\"content\":{reply:?}}},\"finish_reason\":null}}]}}\n\n\
                     data: {{\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"model\":\"mock\",\"choices\":[{{\"index\":0,\"delta\":{{}},\"finish_reason\":\"stop\"}}]}}\n\n\
                     data: [DONE]\n\n"
                );
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    sse.len(),
                    sse
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    addr
}

/// A config with one KB document carrying [`KB_MARKER`] and one `kind = "local"` provider pointed at
/// `mock_addr` — the SAME config both the baseline `"chat"` id and the new `"chat_fabric_grounded"` id
/// are assembled from, so the ONLY variable between the two served turns below is the surface id.
fn loaded_with_mock_llm(mock_addr: std::net::SocketAddr, tag: &str) -> LoadedConfig {
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("ainxt-gap5-fabric-{tag}-{nanos}"));
    let src = format!(
        "version = 1\n\
         [server]\n\
         event_log_dir = {:?}\n\
         [[kb.documents]]\n\
         id = \"settle-1\"\n\
         source = \"settlement-runbook\"\n\
         text = \"Payment settlement reconciliation batches run in {KB_MARKER}.\"\n\
         scope = \"platform\"\n\
         data_class = \"internal\"\n\
         [[models.providers]]\n\
         id = \"mock-llm\"\n\
         kind = \"local\"\n\
         base_url = \"http://{mock_addr}\"\n\
         eligible = [\"internal\", \"regulated-payment\"]\n",
        dir.to_string_lossy()
    );
    ainxt_runtimed::load_layered(&[("gap5-fabric", &src)]).expect("load config")
}

/// Serve the EXACT fully-wired app `main` ships (`to_full_app`/`to_full_app_ext` over
/// `serve_full_ext`) and return the bound address.
async fn serve_shipped(full: &ainxt_runtimed::AssembledFull) -> std::net::SocketAddr {
    let app = full.to_full_app();
    let ext = full.to_full_app_ext();
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(ainxt_server::serve_full_ext(listener, app, ext));
    addr
}

/// Drive one ordinary `POST /v1/chat` turn against `addr`, exactly as `r9_served_wire_replay_regfi.rs`
/// does, and return `(status, sse_body)`.
async fn drive_chat_turn(addr: std::net::SocketAddr, session: &str, input: &str) -> (u16, String) {
    drive_chat_turn_at_clearance(addr, session, input, "internal").await
}

/// Same as [`drive_chat_turn`] but with an explicit `x-ainxt-clearance`/`data_class` (needed by the
/// multimodal-artifact test, whose artifact is `RegulatedPayment` — above the "internal" default).
async fn drive_chat_turn_at_clearance(
    addr: std::net::SocketAddr,
    session: &str,
    input: &str,
    clearance: &str,
) -> (u16, String) {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{addr}/v1/chat"))
        .header("content-type", "application/json")
        .header("x-ainxt-user", "alice")
        .header("x-ainxt-clearance", clearance)
        .header("x-ainxt-department", "payments")
        .header("x-ainxt-caps", "chat.send")
        .body(
            serde_json::json!({
                "session": session, "turn": "t1", "input": input,
                "data_class": clearance, "caps": ["chat.send"]
            })
            .to_string(),
        )
        .send()
        .await
        .expect("chat send");
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    (status, body)
}

/// **The missing-selector proof**: `"chat_fabric_grounded"` is selectable from
/// [`assemble_selected_fabric_grounded`] — the EXACT dispatch function `main.rs` calls — and serves an
/// ordinary turn successfully. Fail-before: the function did not exist at all.
#[tokio::test(flavor = "multi_thread")]
async fn chat_fabric_grounded_is_selectable_from_the_real_dispatch_table_and_serves_a_turn() {
    let captured = Arc::new(Mutex::new(Vec::<String>::new()));
    let mock_addr = spawn_mock_llm(captured).await;
    let loaded = loaded_with_mock_llm(mock_addr, "select");
    let control = Arc::new(Mutex::new(ControlPlane::new()));

    let assembled = assemble_selected_fabric_grounded(&loaded, "chat_fabric_grounded", control.clone())
        .expect("the new 'chat_fabric_grounded' surface id must be selectable from the daemon's real dispatch table");
    assert!(
        assembled
            .report
            .iter()
            .any(|r| r.contains("FABRIC-GROUNDED") && r.contains("populated") && r.contains("EnterpriseDocs")),
        "the configured KB document must populate the EnterpriseDocs fabric layer through the real \
         dispatch path: {:?}",
        assembled.report
    );
    let full = assemble_full_with_control_plane(&loaded, assembled, control)
        .expect("assemble_full_with_control_plane must accept the fabric-grounded surface");
    let addr = serve_shipped(&full).await;

    let (status, _body) =
        drive_chat_turn(addr, "gap5-fabric-s1", "what is the settlement cutoff?").await;
    assert_eq!(
        status, 200,
        "an ordinary turn on the new chat_fabric_grounded surface must succeed"
    );
}

/// **The load-bearing wire proof**: driving the SAME KB config through `"chat_fabric_grounded"` on the
/// REAL dispatch table produces an outbound model prompt containing the fabric's routed KB content —
/// proving retrieval genuinely fired and reached the model-call transport boundary, not merely that
/// assembly succeeded. The plain `"chat"` id on the IDENTICAL config is driven first as a same-run
/// regression guard: its captured prompt must NOT carry the fabric's `[context-fabric` render, proving
/// this fix is additive and did not silently change the shipped default `/v1/chat` surface either.
#[tokio::test(flavor = "multi_thread")]
async fn chat_fabric_grounded_actually_grounds_the_served_turn_over_the_configured_kb() {
    let captured = Arc::new(Mutex::new(Vec::<String>::new()));
    let mock_addr = spawn_mock_llm(captured.clone()).await;
    let loaded = loaded_with_mock_llm(mock_addr, "ground");
    let raw_turn = "when does settlement reconciliation run";

    // --- Baseline: the plain "chat" id, driven through the SAME real dispatch table. ---
    let control_a = Arc::new(Mutex::new(ControlPlane::new()));
    let assembled_a = assemble_selected_fabric_grounded(&loaded, "chat", control_a.clone()).expect(
        "assemble_selected_fabric_grounded('chat') must still work (byte-identical fallthrough)",
    );
    let full_a = assemble_full_with_control_plane(&loaded, assembled_a, control_a).unwrap();
    let addr_a = serve_shipped(&full_a).await;
    let (status_a, body_a) = drive_chat_turn(addr_a, "gap5-fabric-baseline", raw_turn).await;
    assert_eq!(
        status_a, 200,
        "the baseline 'chat' turn must complete: {body_a}"
    );
    // Snapshot how many model calls the baseline turn made (intent classification + answer
    // generation), so the grounded turn's own calls below can be isolated by index, not guessed.
    let after_baseline = {
        let guard = captured.lock().unwrap();
        guard.len()
    }; // guard released immediately after reading the length

    // --- The new opt-in id, driven through the SAME real dispatch table, SAME KB config. ---
    let control_b = Arc::new(Mutex::new(ControlPlane::new()));
    let assembled_b =
        assemble_selected_fabric_grounded(&loaded, "chat_fabric_grounded", control_b.clone())
            .expect("'chat_fabric_grounded' must be selectable from the real dispatch table");
    let full_b = assemble_full_with_control_plane(&loaded, assembled_b, control_b).unwrap();
    let addr_b = serve_shipped(&full_b).await;
    let (status_b, body_b) = drive_chat_turn(addr_b, "gap5-fabric-grounded", raw_turn).await;
    assert_eq!(
        status_b, 200,
        "the fabric-grounded turn must complete: {body_b}"
    );

    // Each served turn issues MORE than one model call (intent classification on the RAW user turn —
    // by design `FabricGroundedChatSurface` preserves `req.user_turn` for classification, never the
    // composed/grounded prompt — plus the actual answer-generation call on the composed prompt).
    // Isolate each turn's own calls by the snapshot above, not a guessed positional index.
    let seen = {
        let guard = captured.lock().unwrap();
        guard.clone()
    }; // guard released immediately after cloning
    let (baseline_prompts, grounded_prompts) = seen.split_at(after_baseline);
    assert!(
        !grounded_prompts.is_empty(),
        "the fabric-grounded turn must have made at least one model call"
    );

    assert!(
        baseline_prompts.iter().all(|p| !p.contains("[context-fabric")),
        "the plain 'chat' id must stay byte-identical to before this fix — no fabric render leaking \
         into the default /v1/chat surface: {baseline_prompts:?}"
    );
    // The load-bearing assertion: at least one of the fabric-grounded turn's model calls (the answer
    // generation call, not the classification call, which correctly still runs on the raw user turn)
    // carries the fabric's own routed-and-labelled render AND the KB's actual EnterpriseDocs content —
    // proving retrieval genuinely fired through the REAL dispatch table, all the way to the model-call
    // transport boundary, not merely that assembly reported the fabric as "populated".
    assert!(
        grounded_prompts
            .iter()
            .any(|p| p.contains("[context-fabric") && p.contains(KB_MARKER)),
        "the fabric-grounded surface must have routed the KB's EnterpriseDocs content — labelled by \
         fabric layer — into an outbound model prompt: {grounded_prompts:?}"
    );
}

// NOTE on item 3/5 (global/sensemaking community detection): confirmed genuinely infra-deferred, not
// fixable by this dispatch mount alone. `MultiGraphFabric::rank_graph` -> `FabricGraph::to_rank_graph`
// (ainxt-context/src/optimizer.rs) only admits nodes that appear in a declared EDGE
// (`for e in &self.edges { nodes.insert(e.from); nodes.insert(e.to); }`) — a KB document, which
// `governed::served_fabric_from_kb` only ever `.with_layer()`-labels (never `.with_edge()`s), is NEVER
// added to the RankGraph. So `detect_communities` receives an EMPTY graph for any KB-only fabric —
// exactly the shipped daemon's air-gapped default (`--surface chat_fabric_grounded` passes an empty
// `FabricGraph`; no CLI/config path yet supplies a populated one). `global_summaries` therefore always
// returns `Vec::new()` on the current wiring, confirmed empirically (an earlier version of this file
// asserted a `[community` render for a decisively-global-scoped query against the single configured KB
// doc and failed: `classify_scope` correctly routed Global, `communities_for_seeds` had a real seed hit,
// but `detect_communities` never had a node to place it in). This matches the design intent, not a bug:
// `CONTEXT_FABRIC.md` names community detection over the CODE graph layers (Symbol/Call/Import/etc.),
// populated by a real repo/KG indexer — `served_fabric_from_kb`'s own doc calls the indexer overlay
// "empty = no repo/KG indexer yet, the honest air-gapped default", and `named_fabric_query`'s doc
// makes the same "no composition-root code populates a live FabricGraph from a real repo/KG indexer
// yet" call precisely for this reason. The MECHANISM is real and already wired end-to-end — proven at
// the composition-root level (with a hand-populated code_graph, not a bespoke test double) by the
// PRE-EXISTING `r19_fabric_wrapper_reaches_community_detection_for_a_global_sensemaking_query` test in
// `r19_fabric_grounded_chat_served.rs` — and now that `assemble_selected_fabric_grounded` mounts
// `FabricGroundedChatSurface` on the real `--surface` dispatch table, ANY future repo/KG indexer that
// constructs a populated `FabricGraph` and calls `assemble_chat_fabric_grounded`/
// `assemble_chat_fabric_grounded_with_artifacts` gets community detection on the served path for free.
// The remaining gap — an indexer that actually populates a live `FabricGraph` from a real repository —
// is upstream ingestion infra genuinely out of scope for a dispatch-table mount.

/// **Item 4/6 — the multimodal-artifact tier, wired through a REAL composition-root sibling function.**
///
/// `main.rs`'s simple `--surface <ID>` string dispatch has no channel to hand in per-deployment binary
/// artifact data (the SAME "needs_hot_wiring: no composition-root code populates a live ArtifactStore
/// from object storage yet" gap `governed::artifact_erasure_cascade`'s own doc comment already named,
/// unrelated to whether the dispatch table has an arm). That upstream ingestion half (an object-store
/// poll loop) is genuinely out of scope here. The actionable half — wiring the DECISION-CONSUMPTION
/// side once an artifact store DOES exist — is what this test proves for real:
///
/// [`governed::ingest_artifact_batch`] (fully offline/deterministic — no live vision/ASR fleet) builds
/// a real [`ainxt_context::artifact::ArtifactStore`]; [`assemble_chat_fabric_grounded_with_artifacts`]
/// (a REAL composition-root function added alongside the dispatch mount, not a test double — the exact
/// sibling shape `assemble_chat_fabric_grounded` already has, which a deployment with an ingestion
/// pipeline calls directly, the same level main.rs's own `--surface` string id operates at) attaches it
/// to the fabric; [`FabricGroundedChatSurface::render_context`]'s new artifact-rendering block routes it
/// through [`governed::route_artifact_model`]'s eligibility gate before labelling it onto a REAL served
/// HTTP turn — driven the same way `chat_fabric_grounded_actually_grounds_the_served_turn_over_the_configured_kb`
/// drives its turn: a live socket, `serve_full_ext`, a real `reqwest` POST, and the SAME mock model
/// upstream capturing the exact outbound prompt.
#[tokio::test(flavor = "multi_thread")]
async fn chat_fabric_grounded_with_artifacts_routes_the_multimodal_tier_into_a_served_turn() {
    let captured = Arc::new(Mutex::new(Vec::<String>::new()));
    let mock_addr = spawn_mock_llm(captured.clone()).await;
    let loaded = loaded_with_mock_llm(mock_addr, "artifacts");

    // A REGULATED-PAYMENT cheque-scan artifact, ingested fully offline/deterministically — the SAME
    // real pipeline `POST /v1/artifact` (see main.rs's served surface list) would drive. Regulated
    // (not merely Internal) so the eligibility gate's "never a cloud model" rule is the one actually
    // exercised, not incidentally satisfied by alphabetic tie-breaking among two equally-eligible ids.
    let artifact = Artifact::new(
        "cheque-scan-1",
        "chat",
        Modality::Image,
        DataClass::RegulatedPayment,
    );
    let (store, outcomes) = ainxt_runtimed::governed::ingest_artifact_batch(vec![artifact]);
    assert!(
        outcomes.iter().all(|o| o.is_ok()),
        "the artifact must ingest cleanly offline: {outcomes:?}"
    );

    let assembled = assemble_chat_fabric_grounded_with_artifacts(
        &loaded,
        FabricGraph::new(),
        Vec::new(),
        store,
    )
    .expect("assemble_chat_fabric_grounded_with_artifacts is a real composition-root function");
    let control = Arc::new(Mutex::new(ControlPlane::new()));
    let full = assemble_full_with_control_plane(&loaded, assembled, control).unwrap();
    let addr = serve_shipped(&full).await;

    // A multimodal-triggering turn (`plan_query`'s "cheque"/"scan" cues route to
    // `GraphLayer::MultimodalArtifact`), at a clearance that can actually see a RegulatedPayment node.
    let (status, body) = drive_chat_turn_at_clearance(
        addr,
        "gap5-fabric-artifacts",
        "please review this cheque scan",
        "regulated-payment",
    )
    .await;
    assert_eq!(
        status, 200,
        "the multimodal-artifact turn must complete: {body}"
    );

    let seen = {
        let guard = captured.lock().unwrap();
        guard.clone()
    }; // guard released immediately after cloning
    assert!(
        seen.iter().any(|p| p.contains("[artifact cheque-scan-1") && p.contains("modality=Image") && p.contains("eligible model: inhouse-vision-v1")),
        "the ingested artifact, routed through the model-eligibility gate, must be labelled onto the \
         outbound model prompt of a REAL served turn: {seen:?}"
    );
}
