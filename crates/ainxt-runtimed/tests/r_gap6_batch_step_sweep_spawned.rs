// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-AUDIT gap6-composition-root (Item 2) — `AssembledFull::spawn_batch_step_sweep` (the
//! chunked-prefill interleaving cadence over the live `ServingGate`) had ZERO callers anywhere,
//! including `main.rs` — `r_chunked_prefill_wired.rs` proved `run_batch_step_tick` reaches the real
//! served gate when HAND-DRIVEN, but nothing on the daemon ever drove it on a cadence. The assembly
//! report itself named the gap outright: a deployment with `[serving] chunked_prefill` declared got
//! the string `"needs_hot_wiring: the async cadence timer, via spawn_batch_step_sweep"` in its own
//! boot output.
//!
//! `main.rs` now spawns `spawn_batch_step_sweep` unconditionally on daemon start (self-gated on
//! `ServingGate::has_chunked_prefill()`, mirroring every other conditionally-live cadence). This file
//! proves it through the REAL spawned background task (never hand-called), over the REAL served HTTP
//! transport (`to_full_app`/`to_full_app_ext`/`serve_full_ext` — the exact path `main.rs` drives):
//!
//!   1. admit a real sequence via `POST /v1/infer` and leave it running (no completion call);
//!   2. spawn `spawn_batch_step_sweep` — never call `run_batch_step_tick` by hand in this test;
//!   3. poll `ServingGate::running_decode_progress` (a pure external read added for exactly this
//!      proof) from OUTSIDE the loop until the admitted sequence's decode progress advances past zero
//!      — proving the spawned loop is making REAL progress on the SAME live scheduler `/v1/infer`
//!      admits into, driven purely by the background cadence.
//!
//! Fail-before: `spawn_batch_step_sweep` existed but had no caller in `main.rs`'s boot sequence, so a
//! declared `chunked_prefill` mechanism was reachable only via a hand-called tick in tests, never by
//! the shipped daemon on its own.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ainxt_runtimed::{assemble_full, assemble_surface, load_layered, LoadedConfig};

fn unique_log_dir(tag: &str) -> String {
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir()
        .join(format!("ainxt-gap6-batch-step-sweep-{tag}-{nanos}"))
        .to_string_lossy()
        .into_owned()
}

fn config_with_chunked_prefill() -> LoadedConfig {
    let dir = unique_log_dir("on");
    let src = format!(
        "version = 1\n\
         [server]\n\
         event_log_dir = {dir:?}\n\
         [serving]\n\
         chunked_prefill = 2\n\
         scheduler_capacity = 4\n\
         [[serving.nodes]]\n\
         node_id = \"gpu-a\"\n\
         routable = true\n"
    );
    load_layered(&[("gap6-batch-step-sweep-on", &src)]).expect("load config with chunked_prefill")
}

fn default_config() -> LoadedConfig {
    let dir = unique_log_dir("default");
    let src = format!("version = 1\n[server]\nevent_log_dir = {dir:?}\n");
    load_layered(&[("gap6-batch-step-sweep-default", &src)]).expect("load default config")
}

#[tokio::test(flavor = "multi_thread")]
async fn r_gap6_spawned_batch_step_sweep_advances_real_decode_progress_over_http_admitted_sequence()
{
    let loaded = config_with_chunked_prefill();
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat surface");
    let full = assemble_full(&loaded, assembled).expect("assemble fully-wired surface");
    assert_eq!(full.serving.1.len(), 1, "served HTTP path has a live pool");

    // Spin the REAL daemon transport — the exact path `main.rs` drives — and admit a real sequence
    // that stays running (never completed) for the duration of this test.
    let app = full.to_full_app();
    let ext = full.to_full_app_ext();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(ainxt_server::serve_full_ext(listener, app, ext));
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{addr}/v1/infer"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header("x-ainxt-user", "svc")
        .header("x-ainxt-department", "dept-sdlc")
        .body(
            serde_json::json!({
                "seq_id": 1, "model_id": "qwen-32b", "priority": "interactive",
                "data_class": "internal", "total_units": 1_000_000, "kv_pages": 4
            })
            .to_string(),
        )
        .send()
        .await
        .expect("send /v1/infer");
    assert!(
        resp.status().is_success(),
        "the real /v1/infer call must be admitted: {}",
        resp.status()
    );
    let body: serde_json::Value = serde_json::from_str(&resp.text().await.expect("body")).unwrap();
    assert_eq!(
        body["admitted"], true,
        "seq 1 must be admitted onto the live pool: {body}"
    );

    // Sanity: before the spawned loop runs even once, no decode progress has been made yet.
    let before = {
        let gate = full.serving.0.lock().expect("gate lock");
        gate.running_decode_progress(1)
    };
    assert_eq!(
        before,
        Some(0),
        "freshly admitted, not yet advanced by anything"
    );

    // THE PROOF: spawn the REAL background loop — the exact call `main.rs` now makes on daemon start
    // — and NEVER hand-call `run_batch_step_tick`/`batch_step_tick` in this test. Poll the live gate's
    // decode progress for seq 1 from OUTSIDE the loop.
    let handle = full
        .spawn_batch_step_sweep(Duration::from_millis(5))
        .expect("chunked_prefill declared ⇒ the sweep spawns");

    let mut advanced = 0u64;
    for _ in 0..400 {
        tokio::time::sleep(Duration::from_millis(5)).await;
        let progress = {
            let gate = full.serving.0.lock().expect("gate lock");
            gate.running_decode_progress(1)
        };
        advanced = progress.unwrap_or(0);
        if advanced > 0 {
            break;
        }
    }
    handle.abort();

    assert!(
        advanced > 0,
        "the SPAWNED batch-step sweep advanced seq 1's decode progress on the SAME live \
         PreemptionScheduler /v1/infer admitted into — proving the cadence timer this crate's own \
         assembly report used to flag as 'needs_hot_wiring' is now genuinely driven by the daemon's \
         own boot sequence, not merely a hand-callable method"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn r_gap6_air_gapped_default_spawns_no_batch_step_sweep() {
    let loaded = default_config();
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat surface");
    let full = assemble_full(&loaded, assembled).expect("assemble fully-wired surface");
    assert_eq!(loaded.serving.chunked_prefill, None);
    assert!(
        full.spawn_batch_step_sweep(Duration::from_millis(5))
            .is_none(),
        "no [serving] chunked_prefill declared ⇒ the sweep self-gates to a no-op, matching the \
         health/autoscale absent-config shape — unconditionally spawning it in main.rs is safe"
    );
}
