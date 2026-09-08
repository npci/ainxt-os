// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R12 gap (low): "Region-specific CHD/PII detectors (Aadhaar, UPI VPA, IFSC, India-PAN) absent from the
//! compliance detector set."
//!
//! Per the core/enterprise split (ADR-028) those region-specific patterns MUST stay in the PRIVATE
//! plugin — shipping an India-region detector in the OSS tree is an IP/legal liability. The real gap was
//! that the detector set was *not composable*: a deployment could not extend it behind the same
//! `ComplianceGate` seam. [`CompositeGate`] closes that — it chains additional detector gates AFTER the
//! generic [`StrongRedactor`] so the private plugin plugs in without any region-specific pattern living in OSS.
//!
//! Fail-before / pass-after is proven WITHIN this test: a UPI VPA (`handle@bank`, no dot ⇒ not an email)
//! is deliberately something the generic redactor leaves intact; the composed chain (generic + a stand-in
//! plugin gate) redacts it, while the generic-alone baseline leaks it.

use ainxt_compliance::{CompositeGate, StrongRedactor};
use ainxt_runtime::compliance::{ComplianceGate, Direction, Redacted};

/// A STAND-IN for the private plugin's detector gate — lives ONLY in this OSS test, never in the
/// crate. Redacts a UPI-VPA-shaped token (`local@bank`, no TLD dot) to demonstrate that an
/// enterprise/region detector composes behind the same seam. (The real plugin's patterns stay private.)
struct StandInUpiVpaGate;

impl ComplianceGate for StandInUpiVpaGate {
    fn scan(&self, text: &str, _dir: Direction) -> Redacted {
        // Minimal, deliberately-narrow: a run `word@word` where the domain part has NO dot (so the
        // generic email detector — which requires a TLD — does not already catch it).
        let bytes = text.as_bytes();
        let is_tok = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-');
        let mut out = String::with_capacity(text.len());
        let mut i = 0usize;
        let mut count = 0usize;
        let mut last = 0usize;
        while i < bytes.len() {
            if bytes[i] == b'@' {
                // walk left over the handle
                let mut ls = i;
                while ls > 0 && is_tok(bytes[ls - 1]) {
                    ls -= 1;
                }
                // walk right over the bank part
                let mut k = i + 1;
                let mut has_dot = false;
                while k < bytes.len() && is_tok(bytes[k]) {
                    if bytes[k] == b'.' {
                        has_dot = true;
                    }
                    k += 1;
                }
                if ls < i && k > i + 1 && !has_dot {
                    out.push_str(&text[last..ls]);
                    out.push_str("[REDACTED-UPI-VPA]");
                    last = k;
                    count += 1;
                    i = k;
                    continue;
                }
            }
            i += 1;
        }
        out.push_str(&text[last..]);
        Redacted {
            text: out,
            redactions: count,
        }
    }
}

const SAMPLE: &str = "pay ravi@okhdfcbank now, card 4111 1111 1111 1111, mail a@b.com";

#[test]
fn r12_composite_seam_chains_a_plugin_detector_after_the_generic_redactor() {
    // FAIL-BEFORE (baseline): the generic redactor alone LEAKS the UPI VPA (no TLD ⇒ not an email),
    // even though it correctly strips the card + the real email.
    let generic = StrongRedactor::new();
    let base = generic.scan(SAMPLE, Direction::Output);
    assert!(!base.text.contains("4111"), "generic must strip the card");
    assert!(
        !base.text.contains("a@b.com"),
        "generic must strip the email"
    );
    assert!(
        base.text.contains("ravi@okhdfcbank"),
        "baseline: generic redactor LEAKS the UPI VPA — this is the gap: {}",
        base.text
    );

    // PASS-AFTER: compose the generic redactor with the (stand-in) plugin gate behind the SAME seam.
    let composed = CompositeGate::with_strong().then(Box::new(StandInUpiVpaGate));
    assert_eq!(composed.len(), 2);
    let r = composed.scan(SAMPLE, Direction::Output);
    assert!(!r.text.contains("4111"), "card still stripped");
    assert!(!r.text.contains("a@b.com"), "email still stripped");
    assert!(
        !r.text.contains("ravi@okhdfcbank"),
        "composed chain must redact the UPI VPA via the plugin gate: {}",
        r.text
    );
    assert!(r.text.contains("[REDACTED-UPI-VPA]"));
    // Total redactions sum across the chain: card + email (generic) + UPI VPA (plugin) >= 3.
    assert!(
        r.redactions >= 3,
        "redaction counts sum across the chain: {r:?}"
    );
}

#[test]
fn r12_composite_is_order_deterministic_and_dyn_seam_usable() {
    // The chain is usable as ONE `dyn ComplianceGate` — the exact seam the engine enforces.
    let gate: Box<dyn ComplianceGate> =
        Box::new(CompositeGate::with_strong().then(Box::new(StandInUpiVpaGate)));
    for dir in [Direction::Input, Direction::ToolResult, Direction::Output] {
        let r = gate.scan(SAMPLE, dir);
        assert!(!r.text.contains("ravi@okhdfcbank"));
        assert!(!r.text.contains("4111"));
    }
    // An empty composite is a faithful no-op (redacts nothing, returns input verbatim).
    let empty = CompositeGate::new();
    assert!(empty.is_empty());
    let r = empty.scan(SAMPLE, Direction::Output);
    assert_eq!(r.redactions, 0);
    assert_eq!(r.text, SAMPLE);
}

#[test]
fn r12_composite_only_removes_never_resurrects_a_redacted_span() {
    // Redact-and-proceed composes safely: a second pass over already-redacted text cannot re-expose a
    // span the first pass removed (each gate only substitutes labels for values).
    let composed = CompositeGate::new()
        .then(Box::new(StrongRedactor::new()))
        .then(Box::new(StrongRedactor::new()));
    let r = composed.scan("card 4111111111111111 twice", Direction::Output);
    assert!(!r.text.contains("4111"));
    assert!(r.text.contains("[REDACTED-PAN]"));
}
