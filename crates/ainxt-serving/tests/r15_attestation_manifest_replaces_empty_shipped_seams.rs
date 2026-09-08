// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-15 serving-ops (MEDIUM) — the shipped daemon's default attestation wiring constructs an
//! EMPTY `StaticQuoteSource`, EMPTY `AllowListVerifier`, and EMPTY `ReferenceValues`
//! (`ainxt-runtimed/src/main.rs`), which is correct for the air-gapped default but left NO
//! declarative way for a deployment that wants to attest a fixed, offline fleet (pre-shared quotes,
//! no live TEE network call) to populate the three seams without hand-writing Rust builder calls.
//!
//! Fail-before: `ainxt_serving::attestation::AttestationManifest` did not exist — this file would not
//! compile, and the default trio (`StaticQuoteSource::new()`, `AllowListVerifier::new()`,
//! `ReferenceValues::new()`) can never admit any node BY CONSTRUCTION regardless of what a deployment
//! declares elsewhere. Pass-after: one manifest + one `.build()` call materializes a trio that DOES
//! admit the declared node through the real refresh loop.

use ainxt_serving::attestation::{
    AllowListVerifier, AttestationGate, AttestationManifest, AttestationQuote, Measurements,
    ReferenceValues, StaticQuoteSource, TrustTier,
};
use ainxt_types::DataClass;

fn quote() -> AttestationQuote {
    AttestationQuote {
        node_id: "n1".into(),
        tier: TrustTier::CcEnclave,
        measurements: Measurements {
            firmware_hash: "fw-1".into(),
            driver_version: "drv-1".into(),
            binary_hash: "bin-1".into(),
        },
        signature: "sig-good".into(),
    }
}

#[test]
fn r15_default_empty_trio_is_inert_by_construction() {
    // The shipped daemon's default — proving the PRECONDITION the manifest closes.
    let source = StaticQuoteSource::new();
    let verifier = AllowListVerifier::new();
    let refs = ReferenceValues::new();
    let mut gate = AttestationGate::new(ainxt_serving::attestation::AttestationConfig {
        quote_ttl: 100,
        grace_ttl: 10,
    });
    let report = ainxt_serving::attestation::refresh_regulated_nodes(
        &mut gate,
        &["n1".to_string()],
        0,
        50,
        &source,
        &verifier,
        &refs,
    );
    assert_eq!(
        report.refreshed_count(),
        0,
        "the empty default can never attest anything"
    );
    assert!(!gate
        .evaluate("n1", DataClass::Confidential, 0, true)
        .is_admitted());
}

#[test]
fn r15_manifest_build_produces_a_trio_that_actually_admits_the_declared_node() {
    let manifest = AttestationManifest {
        approved_firmware: vec!["fw-1".into()],
        approved_drivers: vec!["drv-1".into()],
        approved_binaries: vec!["bin-1".into()],
        accepted_signatures: vec!["sig-good".into()],
        quotes: vec![quote()],
    };
    assert!(!manifest.is_empty());

    let (source, verifier, refs) = manifest.build();
    let mut gate = AttestationGate::new(ainxt_serving::attestation::AttestationConfig {
        quote_ttl: 100,
        grace_ttl: 10,
    });

    // ONE call, over the manifest-built trio, refreshes and admits the declared node — where the
    // default trio provably could not (previous test).
    let report = ainxt_serving::attestation::refresh_regulated_nodes(
        &mut gate,
        &["n1".to_string()],
        0,
        50,
        &source,
        &verifier,
        &refs,
    );
    assert_eq!(
        report.refreshed_count(),
        1,
        "the manifest-built trio actually attests the node"
    );
    assert!(
        gate.evaluate("n1", DataClass::RegulatedPayment, 0, true)
            .is_admitted(),
        "regulated traffic is now admitted through the manifest-driven seams"
    );
}

#[test]
fn r15_manifest_with_no_quotes_and_no_signatures_is_honestly_still_empty() {
    // A manifest a deployment forgot to populate is exactly as inert as the shipped default — the
    // honesty check `AttestationManifest::is_empty` provides, so a startup log can flag it.
    let manifest = AttestationManifest::new();
    assert!(manifest.is_empty());
    let (source, verifier, refs) = manifest.build();
    let mut gate = AttestationGate::new(ainxt_serving::attestation::AttestationConfig {
        quote_ttl: 100,
        grace_ttl: 10,
    });
    let report = ainxt_serving::attestation::refresh_regulated_nodes(
        &mut gate,
        &["n1".to_string()],
        0,
        50,
        &source,
        &verifier,
        &refs,
    );
    assert_eq!(report.refreshed_count(), 0);
}
