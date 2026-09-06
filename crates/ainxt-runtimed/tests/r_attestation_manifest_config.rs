// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX serving-ops (ADR-021 §8.3, gap-2) — `[serving] attestation_manifest` is now a real,
//! parseable config section, and `main.rs`'s daemon-start `spawn_attestation_refresh` call now
//! materializes it via `AttestationManifest::build` in place of the permanently-empty
//! `StaticQuoteSource`/`AllowListVerifier`/`ReferenceValues` trio it was hardcoded to.
//!
//! `r13_attestation_refresh_wired.rs` already proved the REFRESH LOOP itself is wired onto
//! `AssembledFull` and re-admits regulated traffic given a live-TEE quote fed in by hand. This test
//! proves the other, previously-missing half: that a deployment's git-native `[serving]` TOML can
//! DECLARE that quote/allow-list data instead of a test hand-constructing `StaticQuoteSource`/
//! `AllowListVerifier`/`ReferenceValues` directly — i.e. the exact trio `main.rs` now builds from
//! `loaded.serving.attestation_manifest`. Fail-before: `attestation_manifest` did not exist on
//! `ServingConfig` — this file would not compile (`deny_unknown_fields` would also reject the TOML).

use std::time::{SystemTime, UNIX_EPOCH};

use ainxt_runtimed::{assemble_full, assemble_surface, load_layered};
use ainxt_serving::gate::PreServeVerdict;
use ainxt_types::DataClass;

fn unique_log_dir(tag: &str) -> String {
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir()
        .join(format!("ainxt-r-attn-manifest-{tag}-{nanos}"))
        .to_string_lossy()
        .into_owned()
}

fn config_with_manifest() -> ainxt_runtimed::LoadedConfig {
    let dir = unique_log_dir("pool");
    let src = format!(
        "version = 1\n\
         [server]\n\
         event_log_dir = {dir:?}\n\
         [serving]\n\
         [[serving.nodes]]\n\
         node_id = \"gpu-a\"\n\
         routable = true\n\
         [serving.attestation_manifest]\n\
         approved_firmware = [\"fw-1\"]\n\
         approved_drivers = [\"drv-1\"]\n\
         approved_binaries = [\"bin-1\"]\n\
         accepted_signatures = [\"sig-ok\"]\n\
         [[serving.attestation_manifest.quotes]]\n\
         node_id = \"gpu-a\"\n\
         tier = \"cc-enclave\"\n\
         signature = \"sig-ok\"\n\
         [serving.attestation_manifest.quotes.measurements]\n\
         firmware_hash = \"fw-1\"\n\
         driver_version = \"drv-1\"\n\
         binary_hash = \"bin-1\"\n"
    );
    load_layered(&[("r-attn-manifest", &src)]).expect("load config with a declared manifest")
}

#[test]
fn r_attestation_manifest_parses_from_git_native_toml() {
    let loaded = config_with_manifest();
    let manifest = loaded
        .serving
        .attestation_manifest
        .as_ref()
        .expect("[serving.attestation_manifest] must parse into ServingConfig");
    assert!(
        !manifest.is_empty(),
        "a manifest with a declared quote is not the inert default"
    );
    assert_eq!(manifest.quotes.len(), 1);
    assert_eq!(manifest.quotes[0].node_id, "gpu-a");
    assert_eq!(manifest.approved_firmware, vec!["fw-1".to_string()]);
}

#[test]
fn r_default_config_declares_no_manifest_and_stays_air_gapped_inert() {
    let dir = unique_log_dir("default");
    let src = format!("version = 1\n[server]\nevent_log_dir = {dir:?}\n");
    let loaded = load_layered(&[("r-attn-manifest-default", &src)]).expect("load default config");
    assert!(
        loaded.serving.attestation_manifest.is_none(),
        "no [serving.attestation_manifest] declared ⇒ None (byte-identical to before this fix)"
    );
}

#[test]
fn r_manifest_built_trio_re_admits_regulated_traffic_on_the_served_gate() {
    let loaded = config_with_manifest();
    let manifest = loaded.serving.attestation_manifest.as_ref().unwrap();

    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat surface");
    let full = assemble_full(&loaded, assembled).expect("assemble fully-wired surface");
    assert!(
        full.attestation_refresher.is_some(),
        "declared pool exposes a refresher"
    );

    // Pre-state: the declared pool is UNattested — the exact symptom the audit found.
    let nodes = full.serving.1.clone();
    {
        let gate = full.serving.0.lock().expect("gate lock");
        assert_eq!(
            gate.pre_serve_check(DataClass::RegulatedPayment, &nodes, 0, true),
            PreServeVerdict::FailClosedNoAttestedCapacity,
        );
    }

    // This is the EXACT call `main.rs` now makes: materialize the declared manifest into the three
    // refresh-loop seams (previously main.rs hardcoded these three constructors to their empty
    // defaults, unconditionally, regardless of any config).
    let (source, verifier, refs) = manifest.build();
    let report = full
        .run_attestation_refresh_tick(0, &source, &verifier, &refs)
        .expect("first tick is due and a pool is declared");
    assert_eq!(
        report.refreshed_count(),
        1,
        "the declared quote re-attests gpu-a: {report:?}"
    );

    // The served gate now admits regulated traffic onto the node the MANIFEST (not a hand-built
    // trio) declared trustworthy.
    let gate = full.serving.0.lock().expect("gate lock");
    assert_eq!(
        gate.pre_serve_check(DataClass::RegulatedPayment, &nodes, 0, true),
        PreServeVerdict::Admit { node_id: "gpu-a".into() },
        "a config-declared manifest must be able to admit regulated traffic, not just a hand-built trio"
    );
}
