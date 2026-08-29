// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-12 offline seam test for the INFRA-gated §13 item (HIGH) — **external TEE remote
//! attestation, hardware root-of-trust, auditor-independent measurement verification**.
//!
//! The real hardware quote-signature verification is TEE infra (a confidential-computing enclave +
//! its attestation service) behind the [`AttestationVerifier`] seam — that cannot run offline. What
//! *is* real and exhaustively testable here is the **external verification decision core**
//! ([`ExternalAttestationVerifier`]): the reference-value + binding + freshness checks a party
//! OUTSIDE the runtime performs on a structured [`TeeQuoteClaims`], trusting only its own published
//! roots/measurements. This proves the load-bearing "external" property of §13 — *the auditor can
//! independently verify the code measurement* — without trusting the runtime's say-so. Swapping the
//! offline reference check for a real hardware-quote signature check needs no algorithm change.
//!
//! Fail-before/pass-after: `verify_external` / `TeeQuoteClaims` / `VerifiedMeasurement` are new this
//! round; before, only set-membership existed and no binding/freshness/measurement-match was checked.

use ainxt_identity::authority::{ExternalAttestationVerifier, TeeQuoteClaims, TeeVerifyError};

fn auditor() -> ExternalAttestationVerifier {
    // An external auditor trusts exactly one attestation root and one reviewed code measurement.
    ExternalAttestationVerifier::new()
        .with_root("tee-root-example-2026")
        .with_measurement("sha256:coder-image-v3")
}

fn good_quote(nonce: &str) -> TeeQuoteClaims {
    TeeQuoteClaims {
        measurement: "sha256:coder-image-v3".into(),
        def_content_hash: "def-hash-v3".into(),
        nonce: nonce.into(),
        attestation_root: "tee-root-example-2026".into(),
    }
}

#[test]
fn r12_external_tee_auditor_independently_verifies_measurement() {
    let auditor = auditor();
    // The AIA challenged with this nonce; the enclave echoed it back in the quote.
    let challenge = "nonce-issuance-42";
    let verified = auditor
        .verify_external(
            &good_quote(challenge),
            "sha256:coder-image-v3",
            "def-hash-v3",
            challenge,
        )
        .expect("a well-formed, fresh, correctly-bound quote verifies externally");
    // The auditor can attest to the exact code identity WITHOUT trusting the runtime.
    assert_eq!(verified.measurement, "sha256:coder-image-v3");
    assert_eq!(verified.def_content_hash, "def-hash-v3");
    assert_eq!(verified.attestation_root, "tee-root-example-2026");
}

#[test]
fn r12_external_tee_untrusted_root_is_rejected() {
    let auditor = auditor();
    let mut q = good_quote("n1");
    q.attestation_root = "tee-root-ATTACKER".into();
    assert_eq!(
        auditor.verify_external(&q, "sha256:coder-image-v3", "def-hash-v3", "n1"),
        Err(TeeVerifyError::UntrustedRoot("tee-root-ATTACKER".into()))
    );
}

#[test]
fn r12_external_tee_measurement_mismatch_is_rejected() {
    let auditor = auditor();
    // A valid quote, trusted root, accepted measurement — but for DIFFERENT code than intended.
    let mut q = good_quote("n1");
    q.measurement = "sha256:UNREVIEWED".into();
    // Unknown reference value.
    assert!(matches!(
        auditor.verify_external(&q, "sha256:coder-image-v3", "def-hash-v3", "n1"),
        Err(TeeVerifyError::UnknownMeasurement(_))
    ));
    // Even an ACCEPTED measurement that is not the one the caller expected to run is refused
    // (a quote for a different approved image cannot be substituted).
    let auditor2 = auditor.clone().with_measurement("sha256:other-approved");
    let mut q2 = good_quote("n1");
    q2.measurement = "sha256:other-approved".into();
    assert_eq!(
        auditor2.verify_external(&q2, "sha256:coder-image-v3", "def-hash-v3", "n1"),
        Err(TeeVerifyError::MeasurementMismatch {
            expected: "sha256:coder-image-v3".into(),
            in_quote: "sha256:other-approved".into(),
        })
    );
}

#[test]
fn r12_external_tee_replayed_nonce_and_swapped_def_are_rejected() {
    let auditor = auditor();
    // A quote minted for an old challenge (replay) does not match the fresh challenge.
    assert_eq!(
        auditor.verify_external(
            &good_quote("OLD-nonce"),
            "sha256:coder-image-v3",
            "def-hash-v3",
            "fresh-nonce"
        ),
        Err(TeeVerifyError::StaleNonce {
            expected: "fresh-nonce".into(),
            in_quote: "OLD-nonce".into(),
        })
    );
    // A quote whose bound def-hash is not the definition being issued is rejected (code/def swap).
    assert_eq!(
        auditor.verify_external(
            &good_quote("n1"),
            "sha256:coder-image-v3",
            "def-hash-EVIL",
            "n1"
        ),
        Err(TeeVerifyError::DefHashMismatch {
            expected: "def-hash-EVIL".into(),
            in_quote: "def-hash-v3".into(),
        })
    );
}
