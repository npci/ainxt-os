// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-13 Serving-Ops (SRV-03, HIGH) — the attestation admit path is now REACHABLE on the shipped
//! daemon: the ADR-021 §8.3 quote-refresh loop is wired onto the assembled surface.
//!
//! The audit found that although R11 bound the declared node pool onto the §8.2 fence, NO loop ever
//! re-attested it — a live-TEE quote had to be hand-submitted through `ServingGate::attestation_mut`,
//! so on the shipped `ainxt-runtimed` binary a declared regulated node stayed UNattested and regulated
//! traffic fenced off the WHOLE fleet forever. This wires an [`AttestationRefresher`] onto
//! [`AssembledFull`] and exposes [`AssembledFull::run_attestation_refresh_tick`] — the clean, drivable
//! entrypoint the daemon's background timer calls on a cadence with the live-TEE `QuoteSource`
//! (needs_hot_wiring: the async timer + the TEE are infra; the offline `StaticQuoteSource` stands in).
//!
//! Fail-before: `AssembledFull` had no `attestation_refresher` field and no
//! `run_attestation_refresh_tick` entrypoint — this file would not compile. Pass-after: a declared
//! pool exposes a refresher; one refresh tick re-admits a regulated turn onto the now-attested node on
//! the SHARED served gate; an expired-and-unrenewable node falls back fail-closed; and the air-gapped
//! default (no pool) exposes no refresher (the r4 shipped-chat guard holds — no pool ⇒ no 503).

use std::time::{SystemTime, UNIX_EPOCH};

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
        .join(format!("ainxt-r13-{tag}-{nanos}"))
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
         routable = true\n\
         [[serving.nodes]]\n\
         node_id = \"gpu-b\"\n\
         routable = true\n"
    );
    load_layered(&[("r13", &src)]).expect("load config with a serving pool")
}

fn default_config() -> LoadedConfig {
    let dir = unique_log_dir("default");
    let src = format!("version = 1\n[server]\nevent_log_dir = {dir:?}\n");
    load_layered(&[("r13d", &src)]).expect("load default config")
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

#[test]
fn r13_refresh_loop_wired_re_admits_regulated_traffic_on_the_served_gate() {
    let loaded = served_pool_config();
    assert_eq!(
        loaded.serving.attestation_refresh_interval,
        Some(30),
        "[serving] cadence parsed"
    );
    assert_eq!(loaded.serving.attestation_refresh_lead, Some(40));

    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat surface");
    let full = assemble_full(&loaded, assembled).expect("assemble fully-wired surface");

    // The refresh loop is WIRED onto the shipped surface (was missing entirely).
    assert!(
        full.attestation_refresher.is_some(),
        "declared pool exposes an attestation refresher"
    );
    assert_eq!(
        full.serving.1.len(),
        2,
        "the configured pool is bound onto the served gate"
    );

    // GAP-FIX serving-ops — `AttestationRefresher::sweeps_run`/`declared_nodes` had zero callers.
    assert_eq!(
        full.attestation_refresh_sweeps_run(),
        Some(0),
        "no sweep has run yet"
    );
    let mut declared = full
        .attestation_refresh_declared_nodes()
        .expect("a pool is declared");
    declared.sort();
    assert_eq!(declared, vec!["gpu-a".to_string(), "gpu-b".to_string()]);

    let verifier = AllowListVerifier::new().accept("sig-ok");
    let refs = refs();

    let nodes = full.serving.1.clone();

    // Pre-state: the declared pool is UNattested → a regulated turn fails closed on the whole pool
    // through the REAL served fence (`pre_serve_check`), the decision `/v1/chat` makes first.
    {
        let gate = full.serving.0.lock().expect("gate lock");
        assert_eq!(
            gate.pre_serve_check(DataClass::RegulatedPayment, &nodes, 0, true),
            PreServeVerdict::FailClosedNoAttestedCapacity,
            "declared-but-unattested pool fails closed for regulated traffic (the bug's symptom)"
        );
    }

    // The live TEE (offline reference) can now quote gpu-a. Drive ONE refresh tick through the shipped
    // daemon entrypoint — the exact call the background timer makes.
    let source = StaticQuoteSource::new().with_quote(good_quote("gpu-a"));
    let report = full
        .run_attestation_refresh_tick(0, &source, &verifier, &refs)
        .expect("first tick is due and a pool is declared");
    assert_eq!(
        report.refreshed_count(),
        1,
        "gpu-a re-attested from the live TEE quote: {report:?}"
    );
    assert_eq!(
        full.attestation_refresh_sweeps_run(),
        Some(1),
        "the sweep counter reflects the SAME refresher the tick just drove"
    );

    // The SAME shared served gate now admits a regulated turn onto the attested node — the fence no
    // longer drains the whole fleet.
    {
        let gate = full.serving.0.lock().expect("gate lock");
        assert_eq!(
            gate.pre_serve_check(DataClass::RegulatedPayment, &nodes, 0, true),
            PreServeVerdict::Admit {
                node_id: "gpu-a".into()
            },
            "after the wired refresh tick, a regulated turn is admitted onto the now-attested node"
        );
    }

    // FAIL-CLOSED: time passes past the quote window and the TEE goes dark → the next due sweep finds
    // no quote and the node drops back to fail-closed (never a stale-quote fallback).
    let dark = StaticQuoteSource::new();
    let report = full
        .run_attestation_refresh_tick(400, &dark, &verifier, &refs)
        .expect("sweep due at t=400");
    assert_eq!(
        report.refreshed_count(),
        0,
        "dark TEE → nothing re-attested: {report:?}"
    );
    {
        let gate = full.serving.0.lock().expect("gate lock");
        assert_eq!(
            gate.pre_serve_check(DataClass::RegulatedPayment, &nodes, 400, true),
            PreServeVerdict::FailClosedNoAttestedCapacity,
            "expired-and-unrenewable node fails closed on the served gate"
        );
    }
}

#[test]
fn r13_air_gapped_default_wires_no_refresher() {
    let loaded = default_config();
    assert!(
        loaded.serving.is_empty(),
        "default config declares no serving nodes"
    );
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat surface");
    let full = assemble_full(&loaded, assembled).expect("assemble fully-wired surface");
    assert!(
        full.attestation_refresher.is_none(),
        "no declared pool ⇒ no refresher (nothing to attest; the fence stays inert — r4 guard)"
    );
    assert_eq!(
        full.attestation_refresh_sweeps_run(),
        None,
        "no refresher ⇒ no sweep count either"
    );
    assert_eq!(full.attestation_refresh_declared_nodes(), None);
    // Driving a tick on a surface with no pool is a harmless no-op (never panics).
    let verifier = AllowListVerifier::new().accept("sig-ok");
    assert!(full
        .run_attestation_refresh_tick(0, &StaticQuoteSource::new(), &verifier, &refs())
        .is_none());
}
