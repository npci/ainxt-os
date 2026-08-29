// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! scenario-runner — the NAMED "scenario-matrix" CI gate (`.gitlab-ci.yml`'s `scenario-matrix`
//! job runs exactly this binary). It drives the REAL, fully-assembled [`ainxt_runtime::Engine`]
//! (via [`ainxt_conformance::ConformanceTarget`] — compliance `StrongRedactor` + RBAC + audit +
//! provider failover + tool ledger + the injection taint-gate) through the REAL generated
//! 1,000+-scenario matrix ([`ainxt_scenario::matrix::matrix_suite`]) AND the pairwise-generated
//! corpus ([`ainxt_scenario::matrix::pairwise_matrix_suite`]) — never a hand-coded
//! `ReferenceTarget` returning the "correct" answer for a ~10-scenario sample suite.
//!
//! Before this binary moved here (it originally lived in `ainxt-scenario`, which is
//! zero-dependency by design and therefore CANNOT reach the real runtime), the named CI gate could
//! not meaningfully fail: it graded a mock that always returned the expected output. Now a real
//! regression in the assembled pipeline — a leaked PAN, a double-executed settlement, an injected
//! instruction that drove a side effect, an unauthorized turn that was served — fails this gate RED
//! for real. See `crates/ainxt-conformance/tests/ci_wires_the_real_scenario_matrix.rs`, which runs
//! this exact compiled binary (the same invocation CI performs) and asserts it is green.
//!
//! Usage: `scenario-runner [junit-output-path]` (default: scenario-junit.xml)

use ainxt_conformance::{run_matrix, run_pairwise_matrix};
use ainxt_scenario::Report;

/// Combine two reports into one aggregate (both corpora count toward the single DoD signal).
fn combined(a: Report, b: Report) -> Report {
    Report {
        results: a.results.into_iter().chain(b.results).collect(),
    }
}

fn main() {
    let matrix_report = run_matrix();
    let pairwise_report = run_pairwise_matrix();
    let report = combined(matrix_report, pairwise_report);

    print!("{}", report.summary());

    let out_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "scenario-junit.xml".to_string());
    if let Err(e) = std::fs::write(&out_path, report.junit_xml()) {
        eprintln!("warning: could not write JUnit report to {out_path}: {e}");
    } else {
        eprintln!("JUnit report written to {out_path}");
    }

    if report.all_passed() {
        eprintln!(
            "scenario matrix: PASS ({} scenarios against the real ainxt_runtime::Engine)",
            report.total()
        );
        std::process::exit(0);
    } else {
        eprintln!(
            "scenario matrix: FAIL ({} of {} failed against the real ainxt_runtime::Engine)",
            report.failed(),
            report.total()
        );
        std::process::exit(1);
    }
}
