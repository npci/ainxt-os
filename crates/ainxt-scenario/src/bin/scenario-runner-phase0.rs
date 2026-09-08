// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! scenario-runner — runs the AiNxt scenario matrix and emits a JUnit report for CI.
//!
//! Usage: `scenario-runner [junit-output-path]`  (default: scenario-junit.xml)
//!
//! Phase-0 state: runs the built-in `sample_suite()` against a reference-correct target,
//! so CI has a green DoD signal today. When the real runtime target is wired (P1), it is
//! passed here instead of `ReferenceTarget`, and the full git-native scenario set loads on
//! top of the sample suite. Exit code is non-zero if any scenario fails — the DoD gate.

use ainxt_scenario::{sample_suite, Category, Observation, Runner, Scenario, Target};

/// A reference-correct target: models what a correct runtime returns for the sample suite,
/// so the harness demonstrably runs GREEN. (Tests use faulty targets to prove it runs RED.)
struct ReferenceTarget;

impl Target for ReferenceTarget {
    fn run(&self, s: &Scenario) -> Observation {
        match s.category {
            // "generate this as pdf" → resolve the referent to the prior UPI answer.
            Category::ReferentResolution => Observation {
                output: "UPI transaction volume grew ~45% YoY in the prior analysis.".to_string(),
                latency_ms: 12,
                ..Default::default()
            },
            // Retried settlement dispatches the action exactly once (idempotency ledger).
            Category::DoubleExecution => Observation {
                output: "settlement initiated".to_string(),
                side_effects: vec!["settle:NEFT-2026-07-18".to_string()],
                latency_ms: 20,
                ..Default::default()
            },
            // Account details returned with the PAN redacted — no leak marker.
            Category::DataClassLeak => Observation {
                output: "Account ending 1234 (PAN redacted).".to_string(),
                latency_ms: 8,
                ..Default::default()
            },
            _ => Observation {
                output: String::new(),
                latency_ms: 1,
                ..Default::default()
            },
        }
    }
}

fn main() {
    let suite = sample_suite();
    let runner = Runner::with_default_oracles();
    let report = runner.run(&suite, &ReferenceTarget);

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
        eprintln!("scenario matrix: PASS ({} scenarios)", report.total());
        std::process::exit(0);
    } else {
        eprintln!(
            "scenario matrix: FAIL ({} of {} failed)",
            report.failed(),
            report.total()
        );
        std::process::exit(1);
    }
}
