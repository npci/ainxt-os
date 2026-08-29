// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Proves the NAMED "scenario-matrix" CI gate — the exact `cargo run --locked --bin
//! scenario-runner -p ainxt-conformance` invocation `runtime/.gitlab-ci.yml`'s `scenario-matrix`
//! job runs — drives the REAL, fully-assembled `ainxt_runtime::Engine` through the REAL 1,000+
//! generated matrix + pairwise corpora, not a hand-coded `ReferenceTarget` over a ~10-scenario
//! sample suite.
//!
//! This test runs the literal compiled `scenario-runner` binary as a subprocess — the same
//! composition-root the CI job invokes — rather than constructing a bespoke harness that calls
//! `run_matrix()`/`run_pairwise_matrix()` directly. That closes the exact failure mode this round
//! is about: a test that proves a sibling function works is not proof the shipped CI gate reaches
//! it.

use std::process::Command;

#[test]
fn scenario_runner_bin_drives_the_real_matrix_and_is_green() {
    let junit_path =
        std::env::temp_dir().join(format!("scenario-junit-{}.xml", std::process::id()));

    let bin = env!("CARGO_BIN_EXE_scenario-runner");
    let output = Command::new(bin)
        .arg(&junit_path)
        .output()
        .expect("the scenario-runner binary must run");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "the real scenario-matrix CI gate must be green against the real runtime:\n{stderr}"
    );
    assert!(
        stderr.contains("against the real ainxt_runtime::Engine"),
        "the gate must report it ran against the real engine, got: {stderr}"
    );

    let junit = std::fs::read_to_string(&junit_path).expect("the JUnit report must be written");
    let _ = std::fs::remove_file(&junit_path);
    assert!(
        junit.contains("<testsuite"),
        "JUnit output must be well-formed"
    );

    // The gate must run 1,000+ REAL scenarios against the real engine — not the ~10-scenario
    // sample_suite()/ReferenceTarget the gate used to grade.
    let tests_attr = junit
        .split("tests=\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .and_then(|s| s.parse::<usize>().ok())
        .expect("the JUnit testsuite must carry a tests= count");
    assert!(
        tests_attr >= 1000,
        "the named CI gate must exercise 1,000+ real scenarios (ran {tests_attr})"
    );
}
