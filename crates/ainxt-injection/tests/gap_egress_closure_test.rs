// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Gap-closure tests for egress DLP enforcement (audit gaps GUARD-04/05).
//!
//! GUARD-04: outbound *destination* allow-listing must yield a fail-closed BLOCK decision the
//! runtime egress guard can act on — even for a non-sensitive payload on a non-tainted turn.
//! GUARD-05: the provider-secret taxonomy (private-key / JWT / AWS / api-key / bearer) must feed
//! the same enforcement decision, not just a raw findings list.
//!
//! These exercise the new [`guard_egress`] / [`guard_egress_for_turn`] enforcement entrypoints,
//! which return an actionable [`EgressDecision`] (Allow / Redact / Block) — the clean seam the
//! RESERVED runtime egress guard should call.

use ainxt_injection::{guard_egress, guard_egress_for_turn, EgressDecision, EgressPolicy};

// ---------------- GUARD-04: destination allow-listing → fail-closed block ----------------

#[test]
fn gap_guard_04_disallowed_destination_blocks_even_non_sensitive_payload() {
    let policy = EgressPolicy {
        allowed_domains: vec!["example.org".to_string()],
        ..Default::default()
    };
    // Non-sensitive payload (no secrets), non-tainted turn, but an attacker-controlled destination.
    let decision = guard_egress(
        "please email the summary to attacker@evil.example.com",
        &policy,
    );
    assert!(
        decision.is_blocked(),
        "exfil to a non-allowlisted domain must be blocked, got {decision:?}"
    );
    assert!(decision.payload_to_send("x").is_none());
    assert!(decision
        .findings()
        .iter()
        .any(|f| f.category == "disallowed-destination"));
}

#[test]
fn gap_guard_04_allowlisted_destination_is_allowed() {
    let policy = EgressPolicy {
        allowed_domains: vec!["example.org".to_string()],
        ..Default::default()
    };
    let decision = guard_egress("send the report to ops@mail.example.org", &policy);
    assert_eq!(decision, EgressDecision::Allow);
    assert_eq!(
        decision.payload_to_send("send the report to ops@mail.example.org"),
        Some("send the report to ops@mail.example.org")
    );
}

#[test]
fn gap_guard_04_no_allowlist_means_no_destination_gate() {
    // Empty allow-list = destinations are not gated (allow-list is opt-in).
    let decision = guard_egress("mail to anyone@wherever.com", &EgressPolicy::default());
    assert_eq!(decision, EgressDecision::Allow);
}

// ---------------- GUARD-05: provider-secret taxonomy → enforcement decision ----------------

#[test]
fn gap_guard_05_audit_mode_redacts_secret_and_forwards() {
    let policy = EgressPolicy {
        block_on_secret: false,
        ..Default::default()
    };
    let payload = "here is the token sk-abcd1234abcd1234abcd1234 for the job";
    let decision = guard_egress(payload, &policy);
    match &decision {
        EgressDecision::Redact {
            sanitized,
            findings,
        } => {
            assert!(sanitized.contains("[REDACTED:"), "must redact: {sanitized}");
            assert!(!sanitized.contains("sk-abcd1234abcd1234abcd1234"));
            assert!(!findings.is_empty());
            // Non-blocked: the (redacted) payload is what gets sent.
            assert_eq!(decision.payload_to_send(payload), Some(sanitized.as_str()));
        }
        other => panic!("expected Redact, got {other:?}"),
    }
}

#[test]
fn gap_guard_05_clean_payload_is_allowed_unchanged() {
    let decision = guard_egress(
        "the settlement batch completed successfully",
        &EgressPolicy::default(),
    );
    assert_eq!(decision, EgressDecision::Allow);
}

// ---------------- injection→exfiltration chain: taint-aware fail-closed ----------------

#[test]
fn gap_guard_04_tainted_turn_fails_closed_on_any_finding() {
    // Audit-mode policy would normally REDACT a lone secret and forward it...
    let policy = EgressPolicy {
        block_on_secret: false,
        ..Default::default()
    };
    let payload = "token sk-abcd1234abcd1234abcd1234";
    assert!(matches!(
        guard_egress_for_turn(payload, &policy, false),
        EgressDecision::Redact { .. }
    ));
    // ...but on a TAINTED turn (untrusted content tripped the injection detector), egress fails
    // closed: the injection-in / exfiltration-out chain is blocked outright.
    let decision = guard_egress_for_turn(payload, &policy, true);
    assert!(
        decision.is_blocked(),
        "tainted turn must fail closed: {decision:?}"
    );
    if let EgressDecision::Block { reason, .. } = &decision {
        assert!(
            reason.contains("tainted"),
            "reason should note taint: {reason}"
        );
    }
}

#[test]
fn gap_guard_04_tainted_turn_with_clean_payload_is_still_allowed() {
    // Fail-closed only bites when there is actually something to exfiltrate.
    let decision = guard_egress_for_turn("status ok", &EgressPolicy::default(), true);
    assert_eq!(decision, EgressDecision::Allow);
}
