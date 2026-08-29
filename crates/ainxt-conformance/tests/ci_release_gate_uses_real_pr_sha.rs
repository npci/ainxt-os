// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Proves the NAMED "release-gate" CI job — the exact `cargo run --locked --bin release-gate-ci
//! -p ainxt-conformance` invocation `runtime/.gitlab-ci.yml`'s `release-gate` job runs — is a real,
//! non-test entrypoint that (a) actually runs the composed eval release gate against the real
//! `ainxt_runtime::Engine`, and (b) attributes the run to the ACTUAL commit SHA of the diff under
//! review (as GitLab CI supplies it via `CI_MERGE_REQUEST_DIFF_HEAD_SHA`/`CI_COMMIT_SHA`), not the
//! hardcoded placeholder `"dogfood-candidate-sha"` every prior caller used.
//!
//! Runs the literal compiled `release-gate-ci` binary as a subprocess with the same environment
//! shape GitLab CI provides — the same composition-root the required status check invokes.

use std::process::Command;

const FAKE_MR_HEAD_SHA: &str = "deadbeefcafef00d1234567890abcdef12345678";
const FAKE_COMMIT_SHA: &str = "0000000000000000000000000000000000000fee";

#[test]
fn release_gate_ci_bin_ships_a_null_change_using_the_real_mr_diff_sha() {
    let bin = env!("CARGO_BIN_EXE_release-gate-ci");
    let output = Command::new(bin)
        .env("CI_MERGE_REQUEST_DIFF_HEAD_SHA", FAKE_MR_HEAD_SHA)
        .env("CI_COMMIT_SHA", FAKE_COMMIT_SHA)
        .env("CI_COMMIT_REF_NAME", "refs/merge-requests/42/head")
        .output()
        .expect("the release-gate-ci binary must run");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "a null-change candidate against the real runtime must SHIP (exit 0):\nstdout: {stdout}\nstderr: {stderr}"
    );

    // The MR diff head SHA — not CI_COMMIT_SHA, and DEFINITELY not "dogfood-candidate-sha" — must
    // have been the one actually evaluated end-to-end (printed on stdout AND recorded in the
    // verdict on stderr).
    assert!(
        stdout.contains(FAKE_MR_HEAD_SHA),
        "stdout must report the real MR diff SHA under evaluation: {stdout}"
    );
    assert!(
        stderr.contains(FAKE_MR_HEAD_SHA),
        "the composed gate's verdict must be attributed to the real MR diff SHA, not a hardcoded \
         placeholder: {stderr}"
    );
    assert!(
        !stdout.contains("dogfood-candidate-sha") && !stderr.contains("dogfood-candidate-sha"),
        "the hardcoded placeholder SHA must never appear once a real CI SHA is supplied: \
         stdout={stdout} stderr={stderr}"
    );
}

#[test]
fn release_gate_ci_bin_falls_back_to_commit_sha_outside_a_merge_request_pipeline() {
    let bin = env!("CARGO_BIN_EXE_release-gate-ci");
    let output = Command::new(bin)
        .env_remove("CI_MERGE_REQUEST_DIFF_HEAD_SHA")
        .env("CI_COMMIT_SHA", FAKE_COMMIT_SHA)
        .env("CI_COMMIT_REF_NAME", "main")
        .output()
        .expect("the release-gate-ci binary must run");

    assert!(output.status.success(), "a null-change candidate must SHIP");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(FAKE_COMMIT_SHA),
        "without an MR pipeline, the branch pipeline's own CI_COMMIT_SHA must be used: {stdout}"
    );
}
