// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX serving-ops (SERVING_OPS.md §1, gap 7) — the disaggregated prefill/decode pool split
//! (`ainxt_serving::disagg::DisaggregatedPools` + `kv_relay::KvRelay`/`prefill_to_decode_handoff`) is
//! now wired onto the composition root and the served HTTP transport, mirroring how
//! `r11_serving_pool_wired.rs` closes the analogous single-pool gap.
//!
//! `DisaggregatedPools` was fully implemented and unit-tested
//! (`admit_decode_is_never_gated_by_prefill_saturation`) but had ZERO references anywhere outside its
//! own crate — the daemon's ONLY served inference pool was the single `build_serving` gate, so the §1
//! structural interference-elimination mandate ("a request's decode never waits on another request's
//! prefill because they physically execute on different GPUs") was never reachable in production. This
//! test proves the fix through the actual composition root AND the real served HTTP path: a declared
//! `[serving.disagg]` builds a live `DisaggregatedPools` on `AssembledFull`, mounted at
//! `POST /v1/infer/{prefill,decode,handoff}` — and saturating the Prefill Pool over a REAL HTTP call
//! never gates a Decode Pool admission over another REAL HTTP call on the SAME shared instance.
//!
//! Fail-before: `ServingConfig` had no `disagg` field, `AssembledFull` had no `disagg` field, and
//! `ainxt-server` had no `disagg_router` — this file would not compile.

use std::time::{SystemTime, UNIX_EPOCH};

use ainxt_runtimed::{assemble_full, assemble_surface, load_layered, LoadedConfig};

fn unique_log_dir(tag: &str) -> String {
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir()
        .join(format!("ainxt-r-disagg-{tag}-{nanos}"))
        .to_string_lossy()
        .into_owned()
}

fn config_with_disagg() -> LoadedConfig {
    let dir = unique_log_dir("on");
    let src = format!(
        "version = 1\n\
         [server]\n\
         event_log_dir = {dir:?}\n\
         [serving]\n\
         scheduler_capacity = 1\n\
         fairness_capacity = 100\n\
         fairness_min_share = 100\n\
         [serving.disagg]\n\
         [[serving.disagg.prefill_nodes]]\n\
         node_id = \"prefill-a\"\n\
         routable = true\n\
         [[serving.disagg.decode_nodes]]\n\
         node_id = \"decode-a\"\n\
         routable = true\n"
    );
    load_layered(&[("r-disagg-on", &src)]).expect("load config with disagg")
}

fn default_config() -> LoadedConfig {
    let dir = unique_log_dir("default");
    let src = format!("version = 1\n[server]\nevent_log_dir = {dir:?}\n");
    load_layered(&[("r-disagg-default", &src)]).expect("load default config")
}

#[test]
fn r_disagg_config_parses_prefill_and_decode_node_lists() {
    let loaded = config_with_disagg();
    let d = loaded
        .serving
        .disagg
        .as_ref()
        .expect("disagg section parsed");
    assert_eq!(d.prefill_nodes.len(), 1);
    assert_eq!(d.decode_nodes.len(), 1);
    assert_eq!(d.prefill_nodes[0].node_id, "prefill-a");
    assert_eq!(d.decode_nodes[0].node_id, "decode-a");
}

#[test]
fn r_disagg_air_gapped_default_wires_no_split() {
    let loaded = default_config();
    assert!(loaded.serving.disagg.is_none());
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat surface");
    let full = assemble_full(&loaded, assembled).expect("assemble fully-wired surface");
    assert!(
        full.disagg.is_none(),
        "no declared [serving.disagg] ⇒ single-pool serving unchanged"
    );
}

#[test]
fn r_disagg_wired_builds_two_independent_pools_with_declared_candidates() {
    let loaded = config_with_disagg();
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat surface");
    let full = assemble_full(&loaded, assembled).expect("assemble fully-wired surface");
    let (_pools, prefill_c, decode_c) = full.disagg.as_ref().expect("disagg declared ⇒ wired");
    assert_eq!(prefill_c.len(), 1, "prefill pool candidates bound");
    assert_eq!(decode_c.len(), 1, "decode pool candidates bound");
    assert_eq!(prefill_c[0].node_id, "prefill-a");
    assert_eq!(decode_c[0].node_id, "decode-a");
}

async fn post_infer(
    client: &reqwest::Client,
    base: &str,
    path: &str,
    seq_id: u64,
    priority: &str,
    tenant_header: &str,
) -> u16 {
    client
        .post(format!("{base}{path}"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header("x-ainxt-user", "svc")
        .header("x-ainxt-department", tenant_header)
        .body(
            serde_json::json!({
                "seq_id": seq_id, "model_id": "qwen-32b", "priority": priority,
                "data_class": "internal", "total_units": 100, "kv_pages": 1
            })
            .to_string(),
        )
        .send()
        .await
        .expect("send")
        .status()
        .as_u16()
}

#[tokio::test(flavor = "multi_thread")]
async fn r_disagg_decode_admission_is_never_gated_by_a_saturated_prefill_pool_over_real_http() {
    let loaded = config_with_disagg();
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat surface");
    let full = assemble_full(&loaded, assembled).expect("assemble fully-wired surface");
    assert!(full.disagg.is_some());

    let app = full.to_full_app();
    let ext = full.to_full_app_ext();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(ainxt_server::serve_full_ext(listener, app, ext));
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    // Fill the Prefill Pool's ONLY slot (scheduler_capacity=1) via a REAL HTTP call.
    let s1 = post_infer(&client, &base, "/v1/infer/prefill", 1, "batch", "sdlc").await;
    assert_eq!(s1, 200, "first prefill call fills the pool's only slot");

    // A second same-priority prefill arrival finds the Prefill Pool genuinely full with nothing lower
    // to preempt → honest backpressure (503), over REAL HTTP, on the composition-root-built pool.
    let s2 = post_infer(&client, &base, "/v1/infer/prefill", 2, "batch", "sdlc").await;
    assert_eq!(s2, 503, "the Prefill Pool is genuinely saturated: got {s2}");

    // THE STRUCTURAL PROOF: a decode request for an unrelated turn is admitted immediately over REAL
    // HTTP against the Decode Pool — it never observes, waits on, or is shed by the Prefill Pool's
    // saturation, because `disagg_decode_handler` admits against a COMPLETELY SEPARATE `ServingGate`
    // inside the SAME shared `DisaggregatedPools` instance the prefill calls above just saturated.
    let s3 = post_infer(
        &client,
        &base,
        "/v1/infer/decode",
        10,
        "interactive",
        "chat",
    )
    .await;
    assert_eq!(
        s3, 200,
        "decode admission must be structurally independent of Prefill Pool saturation: got {s3}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn r_disagg_handoff_moves_kv_blocks_between_the_two_pools_over_real_http() {
    let loaded = config_with_disagg();
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat surface");
    let full = assemble_full(&loaded, assembled).expect("assemble fully-wired surface");
    let (pools, _, _) = full.disagg.as_ref().expect("disagg declared");
    // Grant landing credits on the decode node directly on the SAME live pools instance the served
    // HTTP handoff route below will drive.
    {
        let mut p = pools.lock().expect("pools lock");
        p.relay_mut()
            .grant_credits(&ainxt_serving::kv_relay::DecodeNodeId::new("decode-a"), 4);
    }

    let app = full.to_full_app();
    let ext = full.to_full_app_ext();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(ainxt_server::serve_full_ext(listener, app, ext));
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{base}/v1/infer/handoff"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header("x-ainxt-user", "svc")
        .body(
            serde_json::json!({
                "req_key": "req-1", "decode_node_id": "decode-a", "pages": 4, "cross_domain": false
            })
            .to_string(),
        )
        .send()
        .await
        .expect("send handoff");
    assert!(resp.status().is_success());
    let body: serde_json::Value = serde_json::from_str(&resp.text().await.expect("body")).unwrap();
    assert_eq!(
        body["delivered"], true,
        "the KV handoff over real HTTP must deliver: {body}"
    );

    // The SAME live relay was debited by the real HTTP call — proving the route reaches the SAME
    // shared instance, not a disjoint copy built for the request.
    let remaining = pools
        .lock()
        .expect("pools lock")
        .relay_mut()
        .credits(&ainxt_serving::kv_relay::DecodeNodeId::new("decode-a"));
    assert_eq!(
        remaining, 0,
        "credits were debited on the SAME shared relay instance: {remaining}"
    );
}
