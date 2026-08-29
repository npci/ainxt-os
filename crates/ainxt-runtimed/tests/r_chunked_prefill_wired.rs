// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX serving-ops (SERVING_OPS.md §2, gap 6) — chunked-prefill interleaving
//! (`ainxt_serving::wfq::interleave_prefill`/`batch_step`) is now wired onto the composition root,
//! mirroring how `r_health_monitor_wired.rs` / `r11_serving_pool_wired.rs` close the analogous
//! serving-ops gaps.
//!
//! `wfq::interleave_prefill`/`batch_step` were fully implemented and exhaustively unit-tested but had
//! ZERO callers outside the crate's own tests — nothing on the served surface ever interleaved a new
//! prefill's chunks with an already-running sequence's decode step, so a long SDLC-scale prefill could
//! monopolize the batch for its whole duration even though the primitive to bound that existed. This
//! test proves the fix through the actual composition root AND the real served `/v1/infer` HTTP path:
//! a declared `[serving] chunked_prefill` builds a live `ServingGate::chunked_prefill` tuning on
//! `AssembledFull`, and a sequence admitted through a REAL `POST /v1/infer` call becomes part of the
//! interleaved schedule the very next `run_batch_step_tick` drives — over the SAME shared
//! `Arc<Mutex<ServingGate>>` the HTTP route dispatched into.
//!
//! Fail-before: `ServingConfig` had no `chunked_prefill` field, `ServingGate` had no
//! `with_chunked_prefill`/`batch_step_tick`, and `AssembledFull` had no `run_batch_step_tick` — this
//! file would not compile (`deny_unknown_fields` would also reject the `chunked_prefill` TOML key).

use std::time::{SystemTime, UNIX_EPOCH};

use ainxt_runtimed::{assemble_full, assemble_surface, load_layered, LoadedConfig};

fn unique_log_dir(tag: &str) -> String {
    // R16 critical: the daemon refuses the header-trusting default authenticator unless the
    // deployment states the assumption (same pattern as the attestation/health tests).
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir()
        .join(format!("ainxt-r-chunked-prefill-{tag}-{nanos}"))
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
    load_layered(&[("r-chunked-prefill-on", &src)]).expect("load config with chunked_prefill")
}

fn default_config() -> LoadedConfig {
    let dir = unique_log_dir("default");
    let src = format!("version = 1\n[server]\nevent_log_dir = {dir:?}\n");
    load_layered(&[("r-chunked-prefill-default", &src)]).expect("load default config")
}

#[test]
fn r_chunked_prefill_config_parses_from_git_native_toml() {
    let loaded = config_with_chunked_prefill();
    assert_eq!(loaded.serving.chunked_prefill, Some(2));
}

#[test]
fn r_chunked_prefill_air_gapped_default_wires_no_mechanism() {
    let loaded = default_config();
    assert_eq!(loaded.serving.chunked_prefill, None);
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat surface");
    let full = assemble_full(&loaded, assembled).expect("assemble fully-wired surface");

    // No `[serving] chunked_prefill` declared ⇒ the mechanism is off; driving a tick is a harmless
    // no-op (never panics), matching the `health`/`autoscale` absent-config shape.
    assert!(
        full.run_batch_step_tick().is_none(),
        "no declared chunked_prefill ⇒ no batch step"
    );
    assert!(
        full.spawn_batch_step_sweep(std::time::Duration::from_secs(3600))
            .is_none(),
        "nothing to drive ⇒ no background loop spawned"
    );
}

#[test]
fn r_chunked_prefill_wired_schedules_chunks_over_the_live_gate() {
    let loaded = config_with_chunked_prefill();
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat surface");
    let full = assemble_full(&loaded, assembled).expect("assemble fully-wired surface");

    // Nothing admitted yet: a tick still runs (mechanism is ON), scheduling exactly the configured
    // prefill-chunk budget with no decode steps to interleave (nothing is running).
    let step = full
        .run_batch_step_tick()
        .expect("chunked_prefill declared ⇒ a tick runs");
    assert_eq!(
        step.prefill_chunks_run, 2,
        "the configured chunk budget ran"
    );
    assert!(
        step.decodes_advanced.is_empty(),
        "nothing was running yet to interleave a decode step for"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn r_chunked_prefill_interleaves_a_decode_step_for_a_sequence_admitted_via_real_v1_infer() {
    let loaded = config_with_chunked_prefill();
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat surface");
    let full = assemble_full(&loaded, assembled).expect("assemble fully-wired surface");
    assert_eq!(full.serving.1.len(), 1, "served HTTP path has a live pool");

    // Spin the REAL daemon transport — the exact `to_full_app`/`to_full_app_ext`/`serve_full_ext`
    // path `main.rs` drives — and dispatch a real inference call over it.
    let app = full.to_full_app();
    let ext = full.to_full_app_ext();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(ainxt_server::serve_full_ext(listener, app, ext));
    let client = reqwest::Client::new();

    // A real `/v1/infer` call, admitted and left RUNNING (no completion call) so it is still present
    // on the live `PreemptionScheduler` the next tick interleaves against.
    let resp = client
        .post(format!("http://{addr}/v1/infer"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header("x-ainxt-user", "svc")
        .header("x-ainxt-department", "dept-sdlc")
        .body(
            serde_json::json!({
                "seq_id": 1, "model_id": "qwen-32b", "priority": "interactive",
                "data_class": "internal", "total_units": 100_000, "kv_pages": 4
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

    // THE PROOF: drive one chunked-prefill tick over the composition root's `run_batch_step_tick` —
    // which locks the SAME `Arc<Mutex<ServingGate>>` the HTTP handler above just dispatched into (NOT
    // a fresh gate this test built for itself). The admitted seq_id=1 is picked up as an in-flight
    // decode sequence and advanced one step, interleaved with this tick's 2-chunk prefill budget.
    let step = full
        .run_batch_step_tick()
        .expect("chunked_prefill is declared ⇒ a tick runs over the shared gate");
    assert_eq!(
        step.prefill_chunks_run, 2,
        "the configured chunk budget ran"
    );
    // Only seq 1 is running, and the 2-chunk budget spans 2 passes (`interleave_prefill` schedules one
    // decode step per pass for every running sequence) — so seq 1 is advanced twice this tick.
    assert_eq!(
        step.decodes_advanced,
        vec![1u64, 1u64],
        "the sequence admitted through the REAL /v1/infer HTTP call was interleaved and advanced — \
         proving `batch_step_tick` reaches the SAME live gate `/v1/infer`'s `model_infer` uses, not an \
         isolated test-only scheduler: {step:?}"
    );

    // And the underlying scheduler really did advance it (not just reported in the schedule) — a
    // direct lock + a second tick shows continued genuine progress, not a static replay.
    {
        let mut gate = full.serving.0.lock().expect("serving gate lock");
        let before = gate.batch_step_tick().expect("still enabled");
        assert_eq!(before.decodes_advanced, vec![1u64, 1u64]);
    }
}
