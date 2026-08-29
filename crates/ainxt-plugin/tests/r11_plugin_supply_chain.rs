// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R11 §3.3/§3.4 — plugin supply-chain: signing, publisher allow-list, control.lock hash-pin,
//! load-time re-verification, import-vs-declared-need, dependency scan, and git-native lifecycle.
//! Scenario 15 (tamper / bad-signature load refusal) and scenario 25 (publish gate) from the design.

use ainxt_plugin::supply_chain::{
    artifact_hash, promote, AdvisoryScanner, ControlLock, HmacSigner, HmacVerifier, LoadError,
    LockEntry, PromoteError, PromotionEvidence, PublisherAllowList, SignedPlugin, Signer, Stage,
};
use ainxt_plugin::{PluginManifest, ResourceLimits};

fn manifest(id: &str, caps: &[&str]) -> PluginManifest {
    PluginManifest {
        id: id.into(),
        requested_capabilities: caps.iter().map(|s| s.to_string()).collect(),
        limits: ResourceLimits::default(),
    }
}

fn signed_env() -> (
    Vec<u8>,
    PluginManifest,
    SignedPlugin,
    ControlLock,
    PublisherAllowList,
    HmacVerifier,
) {
    let wasm = b"\x00asm\x01\x00\x00\x00plugin-body".to_vec();
    let m = manifest("acme.reporter", &["fs.read", "net.fetch"]);
    let signer = HmacSigner::new("acme", "acme-secret");
    let signed = SignedPlugin::sign(&wasm, &m, "1.2.3", &signer);
    let mut lock = ControlLock::new();
    lock.pin(LockEntry {
        plugin_id: m.id.clone(),
        version: "1.2.3".into(),
        content_hash: signed.artifact_hash.clone(),
        signer: "acme".into(),
    });
    let allow = PublisherAllowList::new(["acme"]);
    let verifier = HmacVerifier::new().with_key("acme", "acme-secret");
    (wasm, m, signed, lock, allow, verifier)
}

#[test]
fn a_correctly_signed_pinned_plugin_loads() {
    let (wasm, _m, signed, lock, allow, verifier) = signed_env();
    assert!(
        ainxt_plugin::supply_chain::verify_for_load(&wasm, &signed, &lock, &allow, &verifier)
            .is_ok()
    );
}

#[test]
fn a_tampered_binary_is_refused_at_load() {
    let (_wasm, _m, signed, lock, allow, verifier) = signed_env();
    // FAIL-BEFORE would be "loads anyway"; PASS-AFTER: the bytes no longer hash to the signed record.
    let tampered = b"\x00asm\x01\x00\x00\x00EVIL-PAYLOAD".to_vec();
    let err =
        ainxt_plugin::supply_chain::verify_for_load(&tampered, &signed, &lock, &allow, &verifier)
            .unwrap_err();
    assert_eq!(err, LoadError::SignedHashMismatch);
}

#[test]
fn a_revoked_publisher_stops_loading_even_if_previously_installed() {
    let (wasm, _m, signed, lock, mut allow, verifier) = signed_env();
    // Loads while trusted…
    assert!(
        ainxt_plugin::supply_chain::verify_for_load(&wasm, &signed, &lock, &allow, &verifier)
            .is_ok()
    );
    // …key compromised, publisher revoked → every subsequent load is refused (not install-time-only).
    allow.revoke("acme");
    let err = ainxt_plugin::supply_chain::verify_for_load(&wasm, &signed, &lock, &allow, &verifier)
        .unwrap_err();
    assert_eq!(err, LoadError::PublisherNotAllowed("acme".into()));
}

#[test]
fn a_forged_signature_by_a_different_key_does_not_verify() {
    let (wasm, m, _signed, mut lock, allow, verifier) = signed_env();
    // Attacker re-signs the SAME artifact with their own key but claims to be "acme".
    let forged_hash = artifact_hash(&wasm, &m);
    let forged = SignedPlugin {
        manifest: m.clone(),
        artifact_hash: forged_hash.clone(),
        publisher: "acme".into(),
        version: "1.2.3".into(),
        signature: HmacSigner::new("acme", "WRONG-secret").sign(&forged_hash),
    };
    lock.pin(LockEntry {
        plugin_id: m.id.clone(),
        version: "1.2.3".into(),
        content_hash: forged_hash,
        signer: "acme".into(),
    });
    let err = ainxt_plugin::supply_chain::verify_for_load(&wasm, &forged, &lock, &allow, &verifier)
        .unwrap_err();
    assert_eq!(err, LoadError::SignatureInvalid);
}

#[test]
fn an_unpinned_plugin_is_refused() {
    let (wasm, _m, signed, _lock, allow, verifier) = signed_env();
    let empty_lock = ControlLock::new();
    let err =
        ainxt_plugin::supply_chain::verify_for_load(&wasm, &signed, &empty_lock, &allow, &verifier)
            .unwrap_err();
    assert_eq!(err, LoadError::NotInLock("acme.reporter".into()));
}

#[test]
fn lockfile_hash_pin_catches_a_swapped_but_validly_signed_artifact() {
    // The publisher validly signs a NEW binary, but the environment's control.lock still pins the OLD
    // hash → load refused (the git-tracked pin governs, not the freshest signature).
    let (_wasm, m, _signed, mut lock, allow, verifier) = signed_env();
    let new_wasm = b"\x00asm\x01\x00\x00\x00v2-body".to_vec();
    let new_signed = SignedPlugin::sign(
        &new_wasm,
        &m,
        "1.2.3",
        &HmacSigner::new("acme", "acme-secret"),
    );
    // lock still holds the v1 pin from signed_env()
    let err = ainxt_plugin::supply_chain::verify_for_load(
        &new_wasm,
        &new_signed,
        &lock,
        &allow,
        &verifier,
    )
    .unwrap_err();
    assert!(matches!(err, LoadError::HashMismatch { .. }));
    // Re-pin to the new hash → now it loads.
    lock.pin(LockEntry {
        plugin_id: m.id.clone(),
        version: "1.2.3".into(),
        content_hash: new_signed.artifact_hash.clone(),
        signer: "acme".into(),
    });
    assert!(ainxt_plugin::supply_chain::verify_for_load(
        &new_wasm,
        &new_signed,
        &lock,
        &allow,
        &verifier
    )
    .is_ok());
}

#[test]
fn import_vs_declared_need_fails_an_unjustified_capability() {
    // Manifest asks for fs.write; the PR only justified fs.read + net.fetch → PR fails (§3.3).
    let m = manifest("acme.reporter", &["fs.read", "net.fetch", "fs.write"]);
    let unjustified = ainxt_plugin::supply_chain::import_check(&m, &["fs.read", "net.fetch"]);
    assert_eq!(unjustified, vec!["fs.write".to_string()]);

    // A manifest within the justified set passes clean.
    let ok = manifest("acme.reporter", &["fs.read"]);
    assert!(ainxt_plugin::supply_chain::import_check(&ok, &["fs.read", "net.fetch"]).is_empty());
}

#[test]
fn dependency_scan_flags_a_known_bad_dependency() {
    let scanner = AdvisoryScanner::new(["evil-lib@0.1.0"]);
    let hits = scanner.scan(&["serde@1".into(), "evil-lib@0.1.0".into()]);
    assert_eq!(hits, vec!["evil-lib@0.1.0".to_string()]);
    assert!(scanner.scan(&["serde@1".into()]).is_empty());
}

#[test]
fn git_native_lifecycle_requires_a_signed_tag_for_production() {
    // Draft -> PendingApproval needs an open PR.
    assert!(matches!(
        promote(
            Stage::Draft,
            Stage::PendingApproval,
            &PromotionEvidence::default()
        ),
        Err(PromoteError::MissingEvidence(_))
    ));
    let ev_pr = PromotionEvidence {
        pull_request_open: true,
        ..Default::default()
    };
    assert_eq!(
        promote(Stage::Draft, Stage::PendingApproval, &ev_pr).unwrap(),
        Stage::PendingApproval
    );

    // PendingApproval -> Approved needs import-check + clean scan + CODEOWNERS merge.
    let ev_approve = PromotionEvidence {
        import_check_passed: true,
        scan_clean: true,
        codeowners_merge: true,
        ..Default::default()
    };
    assert_eq!(
        promote(Stage::PendingApproval, Stage::Approved, &ev_approve).unwrap(),
        Stage::Approved
    );
    // Missing the CODEOWNERS merge is refused.
    let missing = PromotionEvidence {
        import_check_passed: true,
        scan_clean: true,
        ..Default::default()
    };
    assert!(matches!(
        promote(Stage::PendingApproval, Stage::Approved, &missing),
        Err(PromoteError::MissingEvidence(_))
    ));

    // Approved -> Production WITHOUT a signed tag is refused; WITH it, promoted.
    assert!(matches!(
        promote(
            Stage::Approved,
            Stage::Production,
            &PromotionEvidence::default()
        ),
        Err(PromoteError::MissingEvidence(_))
    ));
    let ev_prod = PromotionEvidence {
        signed_release_tag: true,
        ..Default::default()
    };
    assert_eq!(
        promote(Stage::Approved, Stage::Production, &ev_prod).unwrap(),
        Stage::Production
    );

    // No stage-skipping (Draft -> Production is illegal even with all evidence).
    let all = PromotionEvidence {
        pull_request_open: true,
        import_check_passed: true,
        scan_clean: true,
        codeowners_merge: true,
        signed_release_tag: true,
    };
    assert!(matches!(
        promote(Stage::Draft, Stage::Production, &all),
        Err(PromoteError::IllegalTransition { .. })
    ));
}
