// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-12 closure of the §13/§16 (MEDIUM) gap — **cryptographically tamper-evident transparency-log
//! inclusion via a Signed Tree Head (STH) under ADR-023 keys.**
//!
//! The inclusion-proof algorithm was already tamper-evident given a collision-resistant hash (r11).
//! What was missing is the **Signed Tree Head**: a checkpoint {tree_size, root, timestamp} *signed*
//! under a versioned ADR-023 `key_id`, so the root itself is non-repudiable — a log server cannot
//! later present a different root under the same key without detection, and an auditor verifies the
//! STH signature ONCE and thereafter checks any inclusion proof against its root.
//!
//! Fail-before/pass-after: `SignedTreeHead`, `TreeHeadSigner`/`TreeHeadVerifier`,
//! `TransparencyLog::signed_tree_head` are new this round. The cryptographic *strength* of the hash +
//! signature is ADR-023 infra behind the injected seams; the STH *structure* and its tamper-evidence
//! algorithm are real and fully tested offline here.

use ainxt_identity::transparency::{
    FakeTreeHeadSigner, FakeTreeHeadVerifier, FnvHasher, IssuanceEntry, SignedTreeHead,
    TransparencyLog,
};

fn entry(run: &str) -> IssuanceEntry {
    IssuanceEntry {
        run_id: run.to_string(),
        def_ref: "def:role/coder@v3".to_string(),
        def_content_hash: "hash-coder-v3".to_string(),
        control_commit_sha: "commit-abc".to_string(),
        attestation_ref: "sha256:coder-image-v3".to_string(),
        key_id: "key-v1".to_string(),
        issued_at: 10,
    }
}

#[test]
fn r12_signed_tree_head_verifies_and_anchors_inclusion() {
    let mut log = TransparencyLog::new(FnvHasher);
    for i in 0..5 {
        log.append(entry(&format!("run-{i}")));
    }
    // The log server signs a checkpoint under its ADR-023 key.
    let signer = FakeTreeHeadSigner::new("log-key-2026", "log-secret");
    let sth = log.signed_tree_head(&signer, 1234);
    assert_eq!(sth.tree_size, 5);
    assert_eq!(sth.key_id, "log-key-2026");
    assert_eq!(sth.root_hash, log.root());

    // An external auditor holds only the public verifier; the STH signature verifies once.
    let verifier = FakeTreeHeadVerifier::new("log-key-2026", "log-secret");
    assert!(
        sth.verify(&verifier),
        "the signed checkpoint verifies under the ADR-023 key"
    );

    // Thereafter, inclusion proofs check against the STH's non-repudiable root.
    let idx = log.index_of_run("run-3").unwrap();
    let proof = log.inclusion_proof(idx).unwrap();
    assert!(proof.verify(&FnvHasher, &sth.root_hash));
}

#[test]
fn r12_forged_sth_signature_is_rejected() {
    let mut log = TransparencyLog::new(FnvHasher);
    log.append(entry("run-0"));
    let signer = FakeTreeHeadSigner::new("log-key-2026", "log-secret");
    let sth = log.signed_tree_head(&signer, 1);

    // A verifier for a DIFFERENT key rejects (wrong ADR-023 key version).
    assert!(!sth.verify(&FakeTreeHeadVerifier::new("other-key", "log-secret")));
    // A verifier without the correct secret (a forger) cannot accept the signature.
    assert!(!sth.verify(&FakeTreeHeadVerifier::new("log-key-2026", "WRONG-secret")));
}

#[test]
fn r12_tampered_sth_root_or_size_fails_verification() {
    let mut log = TransparencyLog::new(FnvHasher);
    for i in 0..3 {
        log.append(entry(&format!("run-{i}")));
    }
    let signer = FakeTreeHeadSigner::new("log-key-2026", "log-secret");
    let verifier = FakeTreeHeadVerifier::new("log-key-2026", "log-secret");
    let sth = log.signed_tree_head(&signer, 99);
    assert!(sth.verify(&verifier));

    // A server that rewrites the root but keeps the old signature is caught (the body no longer
    // matches what was signed).
    let mut tampered_root = sth.clone();
    tampered_root.root_hash = vec![0xde, 0xad, 0xbe, 0xef];
    assert!(
        !tampered_root.verify(&verifier),
        "a swapped root breaks the signed checkpoint"
    );

    // A forged larger tree_size under the same signature is caught too.
    let mut tampered_size = sth.clone();
    tampered_size.tree_size = 9999;
    assert!(
        !tampered_size.verify(&verifier),
        "a forged size breaks the signed checkpoint"
    );

    // An empty checkpoint never verifies (fail-closed).
    let empty = SignedTreeHead {
        tree_size: 0,
        root_hash: Vec::new(),
        timestamp: 0,
        key_id: "log-key-2026".into(),
        signature: sth.signature.clone(),
    };
    assert!(!empty.verify(&verifier));
}
