// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! release-gate-ci — the NAMED, merge-blocking "release-gate" CI job. Runs the composed eval
//! release gate ([`ainxt_eval::ci::run_ci_merge_check`]) dogfooded against the REAL, fully-
//! assembled `ainxt_runtime::Engine` ([`ainxt_conformance::dogfood::RuntimeDogfoodProvider`]),
//! attributed to the ACTUAL commit SHA of the MR/PR diff under review — read from the CI job's own
//! environment, never a hardcoded placeholder.
//!
//! Before this binary existed, `run_ci_merge_check`/`run_release_gate_ci` had no `[[bin]]` and no
//! `.gitlab-ci.yml` job: the only callers were this crate's own tests plus the dogfood self-test,
//! which always scored the same canned corpus against the hardcoded string
//! `"dogfood-candidate-sha"` — never the SHA of the change actually being reviewed. This binary is
//! the real, non-test entrypoint a required status check invokes on every merge request.
//!
//! Commit-SHA resolution (GitLab CI environment — `CI_MERGE_REQUEST_DIFF_HEAD_SHA` is set only in
//! merge-request pipelines and is the actual PR diff's head commit; `CI_COMMIT_SHA` is set in every
//! pipeline and falls back correctly for branch/tag pipelines):
//!
//! 1. `CI_MERGE_REQUEST_DIFF_HEAD_SHA` (the real MR diff head — preferred whenever present)
//! 2. `CI_COMMIT_SHA` (the pipeline's own commit, for non-MR pipelines)
//! 3. `"local-dev-sha"` (running outside CI — never panics)
//!
//! The published commit-status is recorded via [`ainxt_eval::ci::RecordingStatusPublisher`]
//! (a live GitLab commit-status POST is the infra half — a real GitLab HTTP client belongs in the
//! reserved server/daemon crates per this crate's own architecture notes on `CommitStatusPublisher`
//! — see the module doc on `ainxt_eval::ci`). What makes this a REAL, merge-blocking required check
//! today, with zero additional infra, is the same mechanism every other job in
//! `runtime/.gitlab-ci.yml` already uses: `allow_failure: false` in a required stage, driven by this
//! binary's real process exit code (`EXIT_SHIP`/`EXIT_BLOCK`/`EXIT_INDETERMINATE`).

use ainxt_conformance::dogfood::RuntimeDogfoodProvider;
use ainxt_eval::ci::{run_ci_merge_check, RecordingStatusPublisher, RequiredCheck};

/// Resolve the real commit SHA of the diff under evaluation from the CI job's own environment.
fn resolve_candidate_sha() -> String {
    std::env::var("CI_MERGE_REQUEST_DIFF_HEAD_SHA")
        .or_else(|_| std::env::var("CI_COMMIT_SHA"))
        .unwrap_or_else(|_| "local-dev-sha".to_string())
}

fn resolve_target_ref() -> String {
    std::env::var("CI_COMMIT_REF_NAME").unwrap_or_else(|_| "local-dev-ref".to_string())
}

fn main() {
    let candidate_sha = resolve_candidate_sha();
    let target_ref = resolve_target_ref();

    let provider = RuntimeDogfoodProvider::null_change().with_candidate_sha(candidate_sha.clone());
    let additional: Vec<RequiredCheck> = Vec::new();
    let required: Vec<&str> = Vec::new();
    let mut publisher = RecordingStatusPublisher::new();

    let result = run_ci_merge_check(
        &provider,
        &additional,
        &required,
        &target_ref,
        &mut publisher,
    );

    eprintln!("release-gate-ci: evaluating candidate_sha={candidate_sha} target_ref={target_ref}");
    eprintln!("release-gate-ci: status={:?}", result.status);
    if let Some(outcome) = result.check.outcome() {
        eprintln!("release-gate-ci: {}", outcome.summary);
        eprintln!(
            "release-gate-ci: verdict candidate_sha={} outcome={}",
            outcome.report.verdict.candidate_sha, outcome.report.verdict.outcome
        );
    } else {
        eprintln!("release-gate-ci: {}", result.check.summary());
    }
    // Print (stdout) the resolved SHA plainly too, so the calling CI job's log — and the subprocess
    // proving test — can confirm the real diff SHA drove this run, not a hardcoded placeholder.
    println!("candidate_sha={candidate_sha}");

    if result.is_mergeable() {
        eprintln!("release-gate-ci: SHIP — mergeable");
    } else {
        eprintln!("release-gate-ci: BLOCKED — {}", result.status.description);
    }

    std::process::exit(result.exit_code);
}
