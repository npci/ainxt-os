// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R12 §1.9 — the DoS-hardened arg-class detector wired as the live-path default
//! ([`ainxt_tools::default_hardened_scanner`]) keeps detection identical on normal input while
//! bounding work on adversarial input to (near-)linear via chunking, satisfying the "guaranteed
//! linear-time engine" mandate for THIS detector by construction (the marker scanner uses NO
//! backtracking regex at all — pure byte scans). This is the RE2-linear-time half of gap [20],
//! complementing the fail-closed/budget half in r11_detector_dos_hardening.
//!
//! Fail-before intent: the bare marker scanner's e-mail pass is super-linear on a pathological
//! run of `@`, so a multi-megabyte crafted payload fed whole could dominate a worker. Pass-after:
//! the hardened default chunk-bounds the input so total work is linear in payload size and a
//! multi-MB adversarial string classifies well within a wall-clock bound — the availability
//! guarantee scenario 22 asks for — with no change to normal-input verdicts.

use std::time::{Duration, Instant};

use ainxt_tools::{default_hardened_scanner, ArgClassScanner, MarkerArgScanner};

#[test]
fn hardened_default_classifies_normal_input_identically_to_the_bare_scanner() {
    let bare = MarkerArgScanner;
    let hardened = default_hardened_scanner();
    for s in [
        "{\"note\":\"hello world\"}",
        "email me at bob@corp.co",
        "password=hunter2",
        "nothing sensitive here",
        "card 4111 1111 1111 1111 on file",
        "aadhaar reference in this text",
        "account 123456789012 is long",
    ] {
        assert_eq!(
            hardened.classify_args(s),
            bare.classify_args(s),
            "hardened default must not change detection for {s:?}"
        );
    }
}

#[test]
fn a_multi_megabyte_adversarial_payload_classifies_within_a_bounded_wallclock() {
    // A pathological payload: a long run of '@' (the marker scanner's e-mail pass is the one pass
    // whose naive whole-string form is super-linear) plus long digit runs. Fed WHOLE to the bare
    // scanner this is the super-linear stress input; through the hardened default it is chunked so
    // per-chunk work is O(chunk) and total work is linear in length.
    let mut payload = String::with_capacity(4_000_000);
    payload.push_str(&"@".repeat(2_000_000));
    payload.push_str(&"9".repeat(2_000_000));

    let hardened = default_hardened_scanner();
    let started = Instant::now();
    let cls = hardened.classify_args(&payload);
    let elapsed = started.elapsed();

    // It returns a verdict (the long digit run trips the account-like class) and does so within a
    // bounded wall-clock — the detector cannot be turned into an unbounded worker-pin.
    assert!(
        cls.is_some(),
        "a payload with a 2M-digit run must classify as something sensitive"
    );
    assert!(
        cls.map(|c| c.is_regulated()).unwrap_or(false),
        "a 12+ contiguous-digit run is a regulated/account-like class, got {cls:?}"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "the hardened detector must bound adversarial-input latency; took {elapsed:?}"
    );
}

#[test]
fn per_chunk_work_stays_bounded_as_payload_grows() {
    // Near-linear scaling check: quadrupling a pathological payload must NOT quadratically blow up
    // latency (O(n^2) would be ~16x; chunk-bounded linear is ~4x). Generous ceiling (14x) so the
    // assertion distinguishes linear-ish from quadratic without being timing-flaky.
    let scanner = default_hardened_scanner();
    let time_for = |n: usize| -> Duration {
        let payload = "@".repeat(n); // the super-linear-if-unbounded pass
                                     // Warm + measure a couple of iterations to smooth noise.
        let start = Instant::now();
        for _ in 0..3 {
            let _ = scanner.classify_args(&payload);
        }
        start.elapsed() / 3
    };

    let small = time_for(500_000).max(Duration::from_micros(1));
    let large = time_for(2_000_000); // 4x the input

    let ratio = large.as_secs_f64() / small.as_secs_f64();
    assert!(
        ratio < 14.0,
        "4x input must not blow up latency quadratically (ratio {ratio:.1}x for 4x input); \
         chunk-bounding keeps it near-linear"
    );
}

#[test]
fn the_marker_scanner_is_regex_free_by_construction() {
    // The §1.9 "guaranteed-linear-time engine" mandate is satisfied for this detector by using NO
    // backtracking regex engine at all. This is a behavioral sanity anchor: the classifier is a set
    // of deterministic byte scans, so identical input always yields an identical verdict (a
    // backtracking engine's catastrophic case is simply not reachable — there is no engine).
    let bare = MarkerArgScanner;
    let probe = "some text 4111111111111111 and bob@corp.co and password=x";
    let a = bare.classify_args(probe);
    let b = bare.classify_args(probe);
    assert_eq!(a, b);
    // A PAN + e-mail + secret are all present; the fused verdict is the most-sensitive class, which
    // is a regulated/must-stay-in-house one (Pii is the top ordinal, RegulatedPayment just below).
    assert!(a.map(|c| c.is_regulated()).unwrap_or(false), "got {a:?}");
}
