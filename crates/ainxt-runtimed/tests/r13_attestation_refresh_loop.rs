// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R13 (serving-ops SRV-03, HIGH) — the attestation quote-refresh LOOP is spawned on daemon start.
//!
//! The audit found the tick entrypoint existed but NO background loop ever drove it, so a declared
//! regulated node was never attested and regulated traffic fenced off the whole fleet forever.
//! `AssembledFull::spawn_attestation_refresh` spawns the real background loop (the daemon calls it in
//! `main` alongside the breach-clock + reconciler-sweep loops). This drives the SPAWNED loop (not just
//! a hand-called tick) and proves the SHARED served gate flips to admitting regulated traffic once the
//! loop runs a sweep over a live-TEE quote source.
//!
//! FAIL-BEFORE: `spawn_attestation_refresh` did not exist (this file would not compile). PASS-AFTER:
//! green, offline. **infra_gated**: the live-TEE `QuoteSource` is confidential-compute hardware — the
//! offline `StaticQuoteSource` stands in; the shipped daemon passes the empty default (no quotes ⇒ a
//! declared-but-un-sourced pool stays honestly fail-closed rather than faking attestation).

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ainxt_runtimed::{assemble_full, assemble_surface, load_layered, LoadedConfig};
use ainxt_serving::attestation::{
    AllowListVerifier, AttestationQuote, Measurements, ReferenceValues, StaticQuoteSource,
    TrustTier,
};
use ainxt_serving::gate::PreServeVerdict;
use ainxt_types::DataClass;

fn unique_log_dir(tag: &str) -> String {
    // R16 critical: the daemon now refuses the header-trusting default authenticator unless the
    // deployment states the assumption (see r10_breach_clock_unit.rs) — state it here.
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir()
        .join(format!("ainxt-r13loop-{tag}-{nanos}"))
        .to_string_lossy()
        .into_owned()
}

fn served_pool_config() -> LoadedConfig {
    let dir = unique_log_dir("pool");
    let src = format!(
        "version = 1\n\
         [server]\n\
         event_log_dir = {dir:?}\n\
         [serving]\n\
         attestation_refresh_interval = 30\n\
         attestation_refresh_lead = 40\n\
         [[serving.nodes]]\n\
         node_id = \"gpu-a\"\n\
         routable = true\n"
    );
    load_layered(&[("r13loop", &src)]).expect("load config with a serving pool")
}

fn refs() -> ReferenceValues {
    ReferenceValues::new()
        .allow_firmware("fw-1")
        .allow_driver("drv-1")
        .allow_binary("bin-1")
}

fn good_quote(node: &str) -> AttestationQuote {
    AttestationQuote {
        node_id: node.into(),
        tier: TrustTier::CcEnclave,
        measurements: Measurements {
            firmware_hash: "fw-1".into(),
            driver_version: "drv-1".into(),
            binary_hash: "bin-1".into(),
        },
        signature: "sig-ok".into(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r13_spawned_refresh_loop_admits_regulated_traffic_on_the_served_gate() {
    let loaded = served_pool_config();
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat surface");
    let full = assemble_full(&loaded, assembled).expect("assemble fully-wired surface");
    let nodes = full.serving.1.clone();

    // Pre-state: declared-but-unattested pool fails closed for regulated traffic through the REAL fence.
    {
        let gate = full.serving.0.lock().expect("gate lock");
        assert_eq!(
            gate.pre_serve_check(DataClass::RegulatedPayment, &nodes, 0, true),
            PreServeVerdict::FailClosedNoAttestedCapacity,
            "declared-but-unattested pool fails closed for regulated traffic (the bug's symptom)"
        );
    }

    // Spawn the REAL background loop with a tight cadence + a live-TEE (offline reference) that can
    // quote gpu-a. This is the exact call `main` makes on daemon start (with an empty default source).
    let source = Arc::new(StaticQuoteSource::new().with_quote(good_quote("gpu-a")));
    let verifier = Arc::new(AllowListVerifier::new().accept("sig-ok"));
    let handle = full
        .spawn_attestation_refresh(Duration::from_millis(5), source, verifier, refs())
        .expect("a declared pool spawns the refresh loop");

    // Poll the SHARED gate until the spawned loop has run a sweep and re-attested gpu-a (bounded wait).
    let mut admitted = false;
    for _ in 0..400 {
        tokio::time::sleep(Duration::from_millis(5)).await;
        let verdict = {
            let gate = full.serving.0.lock().expect("gate lock");
            gate.pre_serve_check(DataClass::RegulatedPayment, &nodes, 0, true)
        };
        if matches!(verdict, PreServeVerdict::Admit { .. }) {
            admitted = true;
            break;
        }
    }
    handle.abort();
    assert!(
        admitted,
        "the spawned refresh loop re-attested the declared node and the shared gate now admits \
         regulated traffic — the loop is wired, not just a hand-called tick"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r13_air_gapped_default_spawns_no_refresh_loop() {
    let dir = unique_log_dir("default");
    let src = format!("version = 1\n[server]\nevent_log_dir = {dir:?}\n");
    let loaded = load_layered(&[("r13ld", &src)]).expect("load default config");
    assert!(
        loaded.serving.is_empty(),
        "default config declares no serving nodes"
    );
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat surface");
    let full = assemble_full(&loaded, assembled).expect("assemble fully-wired surface");

    // No declared pool ⇒ no refresher ⇒ the loop is a no-op (`None`); the fence stays inert (r4 guard).
    let handle = full.spawn_attestation_refresh(
        Duration::from_millis(5),
        Arc::new(StaticQuoteSource::new()),
        Arc::new(AllowListVerifier::new()),
        refs(),
    );
    assert!(
        handle.is_none(),
        "air-gapped default spawns no attestation refresh loop"
    );
}
