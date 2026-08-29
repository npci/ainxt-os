// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-11 exercise of IDN-08 (low) — ADR-022 §13/§22#3: **external cryptographic attestation +
//! tamper-evident transparency log**. This is the *offline seam test* for an INFRA-gated item: the
//! pure structure (Merkle append-only log + inclusion-proof algorithm + attestation-before-issuance
//! decision core) is implemented and exhaustively testable here; the *cryptographic strength* (an
//! ADR-023 collision-resistant / PQC hash behind [`MerkleHasher`]) and *real TEE remote attestation*
//! (real hardware quote behind [`AttestationVerifier`]) are the injected infra a deployment plugs
//! in. This test proves the seam is correct and tamper-*evident* with the offline hash; swapping in
//! a cryptographic hash makes it tamper-*proof* with no algorithm change.
//!
//! Fail-before/pass-after: it composes `IdentityAuthority` issuance with `IssuanceEntry::from_awc`,
//! the `TransparencyLog`, and external `InclusionProof::verify`.

use ainxt_identity::authority::{
    AttestationError, AttestationQuote, ControlPlaneProjection, IdentityAuthority, IssueError,
    IssueRequest, ReferenceValueVerifier,
};
use ainxt_identity::transparency::{FnvHasher, IssuanceEntry, TransparencyLog};
use ainxt_identity::LogicalTime;
use ainxt_types::DataClass;

fn issuable_req(run_id: &str, tee: bool) -> IssueRequest {
    IssueRequest {
        def_kind: "role".into(),
        def_id: "coder".into(),
        def_version: "v3".into(),
        run_id: run_id.into(),
        data_class: if tee {
            DataClass::RegulatedPayment
        } else {
            DataClass::Internal
        },
        requires_tee: tee,
        obo_user_id: "u-alice".into(),
        obo_department: None,
        obo_ad_level: Some(3),
        obo_can_approve: true,
    }
}

#[test]
fn r11_attestation_gated_issuance() {
    // The verifier accepts exactly one measurement and one TEE quote (external reference values).
    let verifier = ReferenceValueVerifier::new()
        .with_measurement("sha256:coder-image-v3")
        .with_tee_quote("tee-quote-good");
    let projection = ControlPlaneProjection::new(
        ["def:role/coder@v3".to_string()],
        LogicalTime::new(0),
        "control-sha-777",
    );
    let mut aia = IdentityAuthority::new(verifier, projection, 5, 50, "key-v1");

    // An unattested measurement is refused — no credential exists at all (§13).
    let bad_quote = AttestationQuote {
        def_content_hash: "h".into(),
        control_commit_sha: "control-sha-777".into(),
        measurement: "sha256:UNKNOWN".into(),
        tee_quote: None,
    };
    assert!(matches!(
        aia.issue(
            &issuable_req("run-1", false),
            &bad_quote,
            LogicalTime::new(1)
        ),
        Err(IssueError::AttestationFailed(
            AttestationError::UnknownMeasurement(_)
        ))
    ));

    // A TEE Run with no quote is refused (§13/§15).
    let no_tee = AttestationQuote {
        def_content_hash: "h".into(),
        control_commit_sha: "control-sha-777".into(),
        measurement: "sha256:coder-image-v3".into(),
        tee_quote: None,
    };
    assert!(matches!(
        aia.issue(&issuable_req("run-2", true), &no_tee, LogicalTime::new(1)),
        Err(IssueError::AttestationFailed(
            AttestationError::TeeQuoteRequired
        ))
    ));

    // A good attestation issues.
    let good = AttestationQuote {
        def_content_hash: "def-hash-v3".into(),
        control_commit_sha: "control-sha-777".into(),
        measurement: "sha256:coder-image-v3".into(),
        tee_quote: Some("tee-quote-good".into()),
    };
    assert!(aia
        .issue(&issuable_req("run-3", true), &good, LogicalTime::new(1))
        .is_ok());
}

#[test]
fn r11_transparency_log_external_inclusion_proof_is_tamper_evident() {
    let verifier = ReferenceValueVerifier::new().with_measurement("sha256:coder-image-v3");
    let projection = ControlPlaneProjection::new(
        ["def:role/coder@v3".to_string()],
        LogicalTime::new(0),
        "control-sha-777",
    );
    let mut aia = IdentityAuthority::new(verifier, projection, 5, 50, "key-v1");
    let quote = AttestationQuote {
        def_content_hash: "def-hash-v3".into(),
        control_commit_sha: "control-sha-777".into(),
        measurement: "sha256:coder-image-v3".into(),
        tee_quote: None,
    };

    // Log several real issuances into the append-only Merkle transparency log.
    let mut log = TransparencyLog::new(FnvHasher);
    for i in 0..4u64 {
        let awc = aia
            .issue(
                &issuable_req(&format!("run-{i}"), false),
                &quote,
                LogicalTime::new(1),
            )
            .unwrap();
        log.append(IssuanceEntry::from_awc(&awc));
    }
    assert_eq!(log.len(), 4);

    // An external auditor obtains the root independently and verifies an inclusion proof WITHOUT
    // trusting the runtime (§22 #3).
    let root = log.root();
    let idx = log.index_of_run("run-2").unwrap();
    let proof = log.inclusion_proof(idx).unwrap();
    assert!(proof.verify(&FnvHasher, &root));
    assert_eq!(proof.entry.run_id, "run-2");
    assert_eq!(proof.entry.control_commit_sha, "control-sha-777");

    // Tamper-evidence: a proof whose entry was altered no longer verifies against the true root.
    let mut forged = proof.clone();
    forged.entry.control_commit_sha = "control-sha-EVIL".into();
    assert!(
        !forged.verify(&FnvHasher, &root),
        "a tampered issuance entry must fail external verification"
    );

    // And a proof against a wrong root fails (belt-and-suspenders on the external check).
    let wrong_root = vec![0u8; root.len().max(1)];
    assert!(!proof.verify(&FnvHasher, &wrong_root));
}
