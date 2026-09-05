// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R11 §1.9 — detector DoS hardening: input bounding (overlapping chunks), a per-call wall-clock
//! budget, and fail-closed on timeout, wrapped around any ArgClassScanner. Scenario 22.

use std::time::Duration;

use ainxt_tools::{ArgClassScanner, BoundedArgScanner, MarkerArgScanner};
use ainxt_types::DataClass;

/// A pathological inner scanner that hangs far past any budget — the ReDoS/super-linear stand-in.
struct HangingScanner;
impl ArgClassScanner for HangingScanner {
    fn classify_args(&self, _args: &str) -> Option<DataClass> {
        std::thread::sleep(Duration::from_secs(30));
        None // if it ever returned, it would (wrongly) wave the payload through
    }
}

#[test]
fn a_scanner_that_exceeds_its_budget_fails_closed_not_open() {
    let scanner = BoundedArgScanner::new(HangingScanner).with_budget(Duration::from_millis(50));
    let started = std::time::Instant::now();
    // FAIL-BEFORE (unhardened): this pins a worker for 30s and returns None (waved through).
    // PASS-AFTER: returns promptly with the MOST-sensitive class (un-scannable ⇒ un-sendable).
    let cls = scanner.classify_args("a crafted multi-megabyte adversarial payload");
    assert_eq!(cls, Some(DataClass::RegulatedPayment));
    assert!(
        started.elapsed() < Duration::from_millis(1500),
        "the detector must return near its budget, not hang; took {:?}",
        started.elapsed()
    );
}

#[test]
fn input_bounding_still_catches_a_token_past_the_chunk_boundary() {
    // Bound to tiny chunks; a sensitive email marker sits far past the first chunk. Overlapping
    // chunking must still catch it (bounding must not become a blind spot).
    let scanner = BoundedArgScanner::new(MarkerArgScanner)
        .with_max_chunk(64)
        .with_overlap(16)
        .with_budget(Duration::from_secs(5));
    let mut payload = "x".repeat(5000);
    payload.push_str(" contact user@example.com now");
    assert_eq!(scanner.classify_args(&payload), Some(DataClass::Pii));
}

#[test]
fn a_pan_split_across_a_chunk_boundary_is_still_detected() {
    // A Luhn-valid PAN positioned so a naive fixed-window split would cut it; overlap keeps it whole.
    let scanner = BoundedArgScanner::new(MarkerArgScanner)
        .with_max_chunk(20)
        .with_overlap(19)
        .with_budget(Duration::from_secs(5));
    // 4111111111111111 is a well-known Luhn-valid test PAN.
    let payload = format!("{}4111111111111111{}", "p".repeat(15), "q".repeat(40));
    // The PAN is still detected as a REGULATED class despite the boundary (a naive fixed-window split
    // would have missed it). It may surface as RegulatedPayment or Pii depending on which overlapping
    // window a chunk captures — both are `is_regulated()`, i.e. fail-closed for routing/egress.
    let cls = scanner
        .classify_args(&payload)
        .expect("a split PAN must still be caught");
    assert!(
        cls.is_regulated(),
        "split PAN must classify as a regulated class, got {cls:?}"
    );
}

#[test]
fn normal_small_input_classifies_identically_to_the_inner_scanner() {
    let inner = MarkerArgScanner;
    let bounded = BoundedArgScanner::new(MarkerArgScanner).with_budget(Duration::from_secs(5));
    for s in [
        "{\"note\":\"hello world\"}",
        "email me at bob@corp.co",
        "password=hunter2",
        "nothing sensitive here",
    ] {
        assert_eq!(
            bounded.classify_args(s),
            inner.classify_args(s),
            "mismatch for {s:?}"
        );
    }
}
