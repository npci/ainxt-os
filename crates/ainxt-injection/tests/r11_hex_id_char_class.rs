// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R11 gap closure: high-entropy secret detector CHARACTER-CLASS filter. A pure-hexadecimal token
//! (content digest / commit-sha / dashless-UUID / hex id) is NOT a credential even at high entropy;
//! the generic heuristic now requires at least one alphabetic char OUTSIDE the hex alphabet
//! (g-z / G-Z) so those dominant false positives are suppressed, while real mixed-class secrets and
//! all formatted provider secrets (sk-/AKIA/ghp_/JWT/PEM) are still caught.
//!
//! Written to FAIL before the character-class refinement (the sha256 hex id would flag as a
//! high-entropy-secret) and PASS after.

use ainxt_injection::{scan_egress, EgressPolicy};

#[test]
fn r11_pure_hex_id_is_not_a_high_entropy_secret() {
    // A 64-char lowercase sha256 digest: high entropy, has digits + letters, but pure hex.
    let sha = "3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b";
    let a = scan_egress(&format!("commit {sha} merged"), &EgressPolicy::default());
    assert!(
        !a.has_secret(),
        "a pure-hex digest must not be flagged as a secret: {:?}",
        a.findings
    );

    // An uppercase hex id (dashless UUID) is likewise not a secret.
    let uuid_hex = "550E8400E29B41D4A716446655440000";
    let b = scan_egress(uuid_hex, &EgressPolicy::default());
    assert!(
        !b.has_secret(),
        "uppercase hex id must not flag: {:?}",
        b.findings
    );
}

#[test]
fn r11_formatted_secrets_unaffected_by_hex_filter() {
    // Formatted provider secrets are caught by their specific detectors regardless of the generic
    // hex filter — even if their body happened to be hex-only after the prefix.
    let cases = [
        ("AKIAIOSFODNN7EXAMPLE", "aws-access-key"),
        ("sk-abcd1234abcd1234abcd1234", "api-key"),
    ];
    for (payload, cat) in cases {
        let a = scan_egress(payload, &EgressPolicy::default());
        assert!(
            a.findings.iter().any(|f| f.category == cat),
            "{payload} should be {cat}: {:?}",
            a.findings
        );
    }
}
