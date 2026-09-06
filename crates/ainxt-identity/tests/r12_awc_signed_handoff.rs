// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-12 offline seam test for the §18 (LOW) item — **signed handoffs signed with the AWC's real
//! ADR-023 key material, unforgeable across the trust domain.**
//!
//! The real signature is ADR-023 crypto (infra) behind the [`HandoffSigner`]/[`HandoffVerifier`]
//! seam. This test proves the unforgeability *property* offline via [`AwcKeySigner`]/[`AwcKeyVerifier`],
//! which bind the signature to a specific AWC's `key_id` + `run_id` AND a trust-domain root: a Run in
//! one trust domain cannot mint a signature a verifier bound to a *different* domain accepts, and the
//! SoD self-approval rule still blocks a validly-signed self-approval. Two *real* AWCs are minted by
//! the [`IdentityAuthority`] so the signing identity is genuinely the credential's.
//!
//! Fail-before/pass-after: `AwcKeySigner`/`AwcKeyVerifier` are new this round.

use ainxt_identity::authority::AgentWorkloadCredential;
use ainxt_identity::authority::{
    AttestationQuote, ControlPlaneProjection, IdentityAuthority, IssueRequest,
    ReferenceValueVerifier,
};
use ainxt_identity::sod::{
    AwcKeySigner, AwcKeyVerifier, Handoff, ProducedArtifact, SignedHandoff, SodError, SodPolicy,
    WorkloadRef,
};
use ainxt_identity::LogicalTime;
use ainxt_types::DataClass;

fn mint(run_id: &str) -> AgentWorkloadCredential {
    let mut aia = IdentityAuthority::new(
        ReferenceValueVerifier::new().with_measurement("m-ok"),
        ControlPlaneProjection::new(["def:role/judge@v2".to_string()], LogicalTime(0), "c"),
        5,
        50,
        "key-v1",
    );
    let q = AttestationQuote {
        def_content_hash: "h".into(),
        control_commit_sha: "c".into(),
        measurement: "m-ok".into(),
        tee_quote: None,
    };
    let req = IssueRequest {
        def_kind: "role".into(),
        def_id: "judge".into(),
        def_version: "v2".into(),
        run_id: run_id.into(),
        data_class: DataClass::Internal,
        requires_tee: false,
        obo_user_id: "u-alice".into(),
        obo_department: None,
        obo_ad_level: Some(3),
        obo_can_approve: true,
    };
    aia.issue(&req, &q, LogicalTime(1)).unwrap()
}

#[test]
fn r12_awc_signed_handoff_verifies_within_trust_domain() {
    let judge = mint("run-judge-1");
    // The Judge signs a handoff to a distinct deployer Run with ITS AWC key material.
    let signer = AwcKeySigner::for_credential(&judge, "example-trust-root", "judge-privkey");
    let verifier = AwcKeyVerifier::for_credential(&judge, "example-trust-root", "judge-privkey");

    let deployer = WorkloadRef::new("def:role/deployer@v1", "run-deployer-1");
    let handoff = Handoff::new(
        "mr-42",
        WorkloadRef::from(&judge),
        deployer.clone(),
        "digest-abc",
    );
    let signed = SignedHandoff {
        signature: ainxt_identity::sod::HandoffSigner::sign(&signer, &handoff),
        handoff,
    };
    let expected = ProducedArtifact::new("mr-42", WorkloadRef::from(&judge), "digest-abc");

    let decision = SodPolicy::identity_only()
        .accept_handoff(&signed, &expected, &verifier)
        .expect("a genuinely AWC-signed handoff to a distinct receiver is accepted");
    assert_eq!(decision.approver, deployer);
    assert_eq!(decision.producer, WorkloadRef::from(&judge));
}

#[test]
fn r12_handoff_forged_across_trust_domain_is_rejected() {
    let judge = mint("run-judge-1");
    // A compromised signer in a DIFFERENT trust domain (or with the wrong key secret) forges a
    // handoff claiming the judge produced it.
    let attacker = AwcKeySigner::for_credential(&judge, "attacker-domain", "stolen-guess");
    let deployer = WorkloadRef::new("def:role/deployer@v1", "run-deployer-1");
    let handoff = Handoff::new("mr-42", WorkloadRef::from(&judge), deployer, "digest-abc");
    let forged = SignedHandoff {
        signature: ainxt_identity::sod::HandoffSigner::sign(&attacker, &handoff),
        handoff,
    };
    let expected = ProducedArtifact::new("mr-42", WorkloadRef::from(&judge), "digest-abc");

    // The verifier is bound to the REAL trust domain + key material; the cross-domain forgery fails.
    let verifier = AwcKeyVerifier::for_credential(&judge, "example-trust-root", "judge-privkey");
    assert!(matches!(
        SodPolicy::identity_only().accept_handoff(&forged, &expected, &verifier),
        Err(SodError::SignatureInvalid { .. })
    ));
}

#[test]
fn r12_validly_signed_self_approval_still_blocked_by_sod() {
    // Even a perfectly valid AWC signature cannot let a Run approve its OWN handoff (SoD keys on
    // identity, independent of the signature).
    let coder = mint("run-solo-1");
    let signer = AwcKeySigner::for_credential(&coder, "example-trust-root", "coder-privkey");
    let verifier = AwcKeyVerifier::for_credential(&coder, "example-trust-root", "coder-privkey");
    let wref = WorkloadRef::from(&coder);
    let handoff = Handoff::new("mr-1", wref.clone(), wref.clone(), "d1"); // producer == receiver
    let signed = SignedHandoff {
        signature: ainxt_identity::sod::HandoffSigner::sign(&signer, &handoff),
        handoff,
    };
    let expected = ProducedArtifact::new("mr-1", wref, "d1");
    assert!(matches!(
        SodPolicy::identity_only().accept_handoff(&signed, &expected, &verifier),
        Err(SodError::SelfApproval { .. })
    ));
}
