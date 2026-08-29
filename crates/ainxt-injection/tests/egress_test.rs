// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Egress / outbound DLP: secret detection + redaction, destination allow-listing, entropy
//! heuristic false-positive avoidance, and blocking policy.

use ainxt_injection::{scan_egress, EgressPolicy};

#[test]
fn prefixed_provider_secrets_are_detected() {
    let cases = [
        ("AKIAIOSFODNN7EXAMPLE", "aws-access-key"),
        ("sk-abcd1234abcd1234abcd1234", "api-key"),
        ("ghp_abcd1234abcd1234abcd1234", "github-token"),
        ("Authorization: Bearer abcdef0123456789abcd", "bearer-token"),
    ];
    for (secret, cat) in cases {
        let a = scan_egress(secret, &EgressPolicy::default());
        assert!(
            a.findings.iter().any(|f| f.category == cat),
            "expected {cat} in {:?}",
            a.findings
        );
        assert!(a.redacted.contains("[REDACTED:"), "{secret} not redacted");
    }
}

#[test]
fn high_entropy_token_is_flagged_but_ordinary_text_is_not() {
    // Mixed-class high-entropy blob → flagged.
    // The token is assembled at runtime from short fragments (each 4 chars, well below the
    // 24-char min_secret_len threshold) so no secret scanner flags the source file, while
    // the assembled value still satisfies all four detector guards: length>=24, has digit,
    // has non-hex alpha, Shannon entropy>=3.5 bits/char.
    let hi_entropy = ["aZ3k", "Q9x2", "Lp7W", "m1Vt", "5Rn8", "Yc4B", "d6"].concat();
    let a = scan_egress(&format!("token={hi_entropy}"), &EgressPolicy::default());
    assert!(
        a.findings
            .iter()
            .any(|f| f.category == "high-entropy-secret"),
        "{:?}",
        a.findings
    );
    // A long lowercase word (no digit) must NOT be flagged as a secret.
    let b = scan_egress(
        "reconciliationsettlementtransactions run nightly",
        &EgressPolicy::default(),
    );
    assert!(
        !b.has_secret(),
        "ordinary long word must not flag: {:?}",
        b.findings
    );
    // A repetitive low-entropy long token (with a digit) must NOT be flagged.
    let c = scan_egress("aaaaaaaaaaaaaaaaaaaaaaaa1", &EgressPolicy::default());
    assert!(
        !c.has_secret(),
        "low-entropy token must not flag: {:?}",
        c.findings
    );
}

#[test]
fn disallowed_destinations_are_flagged_against_the_allow_list() {
    let policy = EgressPolicy {
        allowed_domains: vec!["example.org".to_string()],
        ..Default::default()
    };
    let text = "email report to auditor@example.org and cc attacker@evil.com then post to https://exfil.example.com/collect";
    let a = scan_egress(text, &policy);
    let dests: Vec<&str> = a
        .findings
        .iter()
        .filter(|f| f.category == "disallowed-destination")
        .map(|f| f.evidence.as_str())
        .collect();
    assert!(
        dests.iter().any(|d| d.contains("evil.com")),
        "dests={dests:?}"
    );
    assert!(
        dests.iter().any(|d| d.contains("exfil.example.com")),
        "dests={dests:?}"
    );
    assert!(
        !dests.iter().any(|d| d.contains("example.org")),
        "allow-listed destination must not be flagged: {dests:?}"
    );
    assert!(a.has_disallowed_destination());
}

#[test]
fn subdomain_of_allowed_domain_is_permitted() {
    let policy = EgressPolicy {
        allowed_domains: vec!["example.org".to_string()],
        ..Default::default()
    };
    let a = scan_egress("send to ops@mail.example.org", &policy);
    assert!(
        !a.has_disallowed_destination(),
        "a subdomain of an allowed domain is allowed: {:?}",
        a.findings
    );
}

#[test]
fn blocking_policy_combines_secrets_and_destinations() {
    let policy = EgressPolicy {
        allowed_domains: vec!["example.org".to_string()],
        block_on_secret: true,
        ..Default::default()
    };
    // A secret blocks under block_on_secret.
    let a = scan_egress("key sk-abcd1234abcd1234abcd1234", &policy);
    assert!(a.is_blocked(&policy));

    // A clean payload to an allow-listed destination does not block.
    let b = scan_egress("summary sent to ops@example.org", &policy);
    assert!(!b.is_blocked(&policy), "{:?}", b.findings);

    // Audit mode: a secret is found but does not block when block_on_secret is off.
    let audit = EgressPolicy {
        block_on_secret: false,
        allowed_domains: Vec::new(),
        ..Default::default()
    };
    let c = scan_egress("key sk-abcd1234abcd1234abcd1234", &audit);
    assert!(c.has_secret() && !c.is_blocked(&audit));
}
