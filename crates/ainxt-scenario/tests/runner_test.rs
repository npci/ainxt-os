// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Integration tests for the scenario runner. The important ones prove the harness
//! CATCHES failures (a runner that only ever goes green is worthless).

use ainxt_scenario::{sample_suite, Category, Expectation, Observation, Runner, Scenario, Target};

/// A correct target: satisfies every sample scenario's expectation.
struct GoodTarget;
impl Target for GoodTarget {
    fn run(&self, s: &Scenario) -> Observation {
        match s.category {
            Category::ReferentResolution => Observation {
                output: "UPI grew ~45% YoY (prior answer).".to_string(),
                latency_ms: 5,
                ..Default::default()
            },
            Category::DoubleExecution => Observation {
                output: "ok".to_string(),
                side_effects: vec!["settle:NEFT-2026-07-18".to_string()],
                ..Default::default()
            },
            Category::DataClassLeak => Observation {
                output: "Account ending 1234 (redacted).".to_string(),
                ..Default::default()
            },
            _ => Observation::default(),
        }
    }
}

/// The exact UPI→PDF bug: doc-gen puts the INSTRUCTION in the output instead of the
/// resolved referent. The harness MUST catch this.
struct FaultyReferentTarget;
impl Target for FaultyReferentTarget {
    fn run(&self, s: &Scenario) -> Observation {
        Observation {
            output: s.input.clone(), // returns "generate this as pdf" as the content — the bug
            latency_ms: 5,
            ..Default::default()
        }
    }
}

/// Double-execution: the retried action dispatches twice.
struct DoubleExecTarget;
impl Target for DoubleExecTarget {
    fn run(&self, _s: &Scenario) -> Observation {
        Observation {
            output: "ok".to_string(),
            side_effects: vec![
                "settle:NEFT-2026-07-18".to_string(),
                "settle:NEFT-2026-07-18".to_string(), // duplicate = double debit
            ],
            ..Default::default()
        }
    }
}

#[test]
fn good_target_passes_the_sample_suite() {
    let report = Runner::with_default_oracles().run(&sample_suite(), &GoodTarget);
    assert!(
        report.all_passed(),
        "good target should pass:\n{}",
        report.summary()
    );
    assert_eq!(report.total(), 3);
    assert_eq!(report.failed(), 0);
}

#[test]
fn harness_catches_the_upi_to_pdf_referent_bug() {
    let suite = vec![sample_suite().into_iter().next().unwrap()]; // REF-001
    let report = Runner::with_default_oracles().run(&suite, &FaultyReferentTarget);
    assert!(!report.all_passed(), "harness must catch the referent bug");
    let failures = report.results[0].failures().join(" ");
    assert!(
        failures.contains("forbidden substring"),
        "spec oracle should flag it: {failures}"
    );
}

#[test]
fn harness_catches_double_execution() {
    let suite: Vec<Scenario> = sample_suite()
        .into_iter()
        .filter(|s| s.category == Category::DoubleExecution)
        .collect();
    let report = Runner::with_default_oracles().run(&suite, &DoubleExecTarget);
    assert!(!report.all_passed(), "harness must catch double-execution");
    assert!(report.results[0]
        .failures()
        .iter()
        .any(|f| f.contains("double-execution")));
}

#[test]
fn empty_suite_runs_green() {
    let report = Runner::with_default_oracles().run(&[], &GoodTarget);
    assert!(report.all_passed());
    assert_eq!(report.total(), 0);
}

#[test]
fn performance_oracle_fails_over_budget() {
    let s = Scenario::new(
        "PERF-001",
        "latency budget",
        Category::Backpressure,
        "x",
        Expectation {
            max_latency_ms: Some(10),
            must_complete: true,
            ..Default::default()
        },
    );
    struct Slow;
    impl Target for Slow {
        fn run(&self, _s: &Scenario) -> Observation {
            Observation {
                output: "ok".into(),
                latency_ms: 999,
                ..Default::default()
            }
        }
    }
    let report = Runner::with_default_oracles().run(&[s], &Slow);
    assert!(!report.all_passed());
}

#[test]
fn junit_xml_is_well_formed_and_escaped() {
    let report = Runner::with_default_oracles().run(&sample_suite(), &GoodTarget);
    let xml = report.junit_xml();
    assert!(xml.starts_with("<?xml"));
    assert!(xml.contains("<testsuite"));
    assert!(!xml.contains("<script")); // no raw injection
}
