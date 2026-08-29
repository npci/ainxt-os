// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-11 gap closures for ainxt-scenario:
//!
//! * **Gap (medium): layered oracle taxonomy** — the full `AGENT_TESTER.md` §2 set
//!   (crash / spec / invariant / metamorphic / differential / visual / performance) exists in code and
//!   each class fires RED on a crafted violation and PASSES on a correct observation.
//! * **Gap (medium): 7-axis pairwise expansion as the mechanism producing the 1,000+ matrix** —
//!   the corpus size is the emergent `templates × pairwise_rows × bands`, every axis value is
//!   represented, and the covering array actually covers every cross-axis value pair.

use ainxt_scenario::matrix::{pairwise_matrix_suite, PAIRWISE_SEED_BANDS, PAIRWISE_TEMPLATES};
use ainxt_scenario::pairwise::{pairwise_plan, plan_covers_all_pairs, seven_axes, seven_axis_plan};
use ainxt_scenario::{
    oracle_taxonomy, Category, DifferentialOracle, Expectation, MetamorphicOracle, Observation,
    Oracle, OracleVerdict, PairOracle, Scenario, VisualOracle,
};
use ainxt_scenario::{CrashOracle, InvariantOracle, PerformanceOracle, SpecOracle};

fn sc(cat: Category, expect: Expectation) -> Scenario {
    Scenario::new("T", "t", cat, "in", expect)
}

// ---------------------------------------------------------------------------------------------
// Gap: layered oracle taxonomy — all seven classes present, each fires and each passes.
// ---------------------------------------------------------------------------------------------

#[test]
fn r11_layered_oracle_taxonomy_all_seven_present() {
    let names = oracle_taxonomy();
    for want in [
        "crash",
        "spec",
        "invariant",
        "metamorphic",
        "differential",
        "visual",
        "performance",
    ] {
        assert!(
            names.contains(&want),
            "taxonomy missing oracle class {want}"
        );
    }
    assert_eq!(
        names.len(),
        7,
        "the taxonomy is exactly the seven §2 classes"
    );
}

#[test]
fn r11_layered_oracle_taxonomy_each_class_fires_and_passes() {
    // ---- crash ----
    let s = sc(
        Category::Custom,
        Expectation {
            must_complete: true,
            ..Default::default()
        },
    );
    let bad = Observation {
        error: Some("boom".into()),
        ..Default::default()
    };
    assert!(matches!(
        CrashOracle.judge(&s, &bad),
        OracleVerdict::Fail(_)
    ));
    assert_eq!(
        CrashOracle.judge(&s, &Observation::default()),
        OracleVerdict::Pass
    );

    // ---- spec (must_not_contain: the instruction-echo bug) ----
    let s = sc(
        Category::ReferentResolution,
        Expectation {
            must_complete: true,
            must_not_contain: vec!["generate this as pdf".into()],
            ..Default::default()
        },
    );
    let echoed = Observation {
        output: "here is: generate this as pdf".into(),
        ..Default::default()
    };
    assert!(matches!(
        SpecOracle.judge(&s, &echoed),
        OracleVerdict::Fail(_)
    ));
    let clean = Observation {
        output: "the prior answer as a pdf".into(),
        ..Default::default()
    };
    assert_eq!(SpecOracle.judge(&s, &clean), OracleVerdict::Pass);

    // ---- invariant (leak marker) ----
    let s = sc(
        Category::DataClassLeak,
        Expectation {
            must_complete: true,
            forbidden_leak_markers: vec!["PAN=".into()],
            ..Default::default()
        },
    );
    let leaked = Observation {
        output: "PAN=4111...".into(),
        ..Default::default()
    };
    assert!(matches!(
        InvariantOracle.judge(&s, &leaked),
        OracleVerdict::Fail(_)
    ));
    let ok = Observation {
        output: "[REDACTED-PAN]".into(),
        ..Default::default()
    };
    assert_eq!(InvariantOracle.judge(&s, &ok), OracleVerdict::Pass);

    // ---- performance ----
    let s = sc(
        Category::Custom,
        Expectation {
            must_complete: true,
            max_latency_ms: Some(100),
            ..Default::default()
        },
    );
    let slow = Observation {
        latency_ms: 250,
        ..Default::default()
    };
    assert!(matches!(
        PerformanceOracle.judge(&s, &slow),
        OracleVerdict::Fail(_)
    ));
    let fast = Observation {
        latency_ms: 10,
        ..Default::default()
    };
    assert_eq!(PerformanceOracle.judge(&s, &fast), OracleVerdict::Pass);

    // ---- visual (structural render integrity) ----
    let s = sc(
        Category::UnicodeRtl,
        Expectation {
            must_complete: true,
            must_contain: vec!["report".into()],
            ..Default::default()
        },
    );
    let corrupt = Observation {
        output: "report \u{FFFD}\u{FFFD}".into(),
        ..Default::default()
    };
    assert!(matches!(
        VisualOracle.judge(&s, &corrupt),
        OracleVerdict::Fail(_)
    ));
    let cutoff = Observation {
        output: "```rust\nfn x() {".into(),
        ..Default::default()
    };
    assert!(
        matches!(VisualOracle.judge(&s, &cutoff), OracleVerdict::Fail(_)),
        "an unclosed code fence is a cut-off render"
    );
    let good = Observation {
        output: "the report is ready".into(),
        ..Default::default()
    };
    assert_eq!(VisualOracle.judge(&s, &good), OracleVerdict::Pass);

    // ---- metamorphic (same question twice → same answer) ----
    let s = sc(Category::Custom, Expectation::default());
    let a = Observation {
        output: "42".into(),
        ..Default::default()
    };
    let a2 = Observation {
        output: "42".into(),
        ..Default::default()
    };
    let drift = Observation {
        output: "43".into(),
        ..Default::default()
    };
    assert_eq!(MetamorphicOracle.judge(&s, &a, &a2), OracleVerdict::Pass);
    assert!(matches!(
        MetamorphicOracle.judge(&s, &a, &drift),
        OracleVerdict::Fail(_)
    ));

    // ---- differential (shadow-mode Rust vs reference) ----
    let candidate = Observation {
        output: "answer".into(),
        ..Default::default()
    };
    let reference = Observation {
        output: "answer".into(),
        ..Default::default()
    };
    let diverged = Observation {
        output: "different".into(),
        ..Default::default()
    };
    assert_eq!(
        DifferentialOracle.judge(&s, &candidate, &reference),
        OracleVerdict::Pass
    );
    assert!(matches!(
        DifferentialOracle.judge(&s, &candidate, &diverged),
        OracleVerdict::Fail(_)
    ));
}

// ---------------------------------------------------------------------------------------------
// Gap: 7-axis pairwise expansion is the mechanism producing the 1,000+ matrix.
// ---------------------------------------------------------------------------------------------

#[test]
fn r11_pairwise_is_the_1000_mechanism() {
    let plan = seven_axis_plan();
    let rows = plan.len();
    let suite = pairwise_matrix_suite();

    // The size is EMERGENT from the plan, not a hardcoded literal.
    assert_eq!(
        suite.len(),
        PAIRWISE_TEMPLATES * rows * PAIRWISE_SEED_BANDS as usize,
        "corpus size must equal templates × pairwise_rows × bands"
    );
    assert!(
        suite.len() >= 1000,
        "the pairwise mechanism must clear the 1,000 floor (got {})",
        suite.len()
    );

    // No clones: every id is unique.
    let mut ids: Vec<&str> = suite.iter().map(|s| s.id.as_str()).collect();
    ids.sort_unstable();
    let unique = ids.len();
    ids.dedup();
    assert_eq!(
        ids.len(),
        unique,
        "all pairwise scenario ids must be distinct"
    );

    // Every axis VALUE from the seven-axis vocabulary is represented in the emitted tags — coverage
    // honesty: no axis value is silently unexercised.
    let axes = seven_axes();
    let axis_names = [
        "surface",
        "model",
        "data_class",
        "locale",
        "transport",
        "concurrency",
        "fault",
    ];
    let all_tags: std::collections::BTreeSet<String> =
        suite.iter().flat_map(|s| s.tags.clone()).collect();
    for (name, values) in axis_names.iter().zip(axes.iter()) {
        for v in *values {
            let tag = format!("{name}={v}");
            assert!(
                all_tags.contains(&tag),
                "axis value {tag} never appears in the pairwise corpus"
            );
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Gap: load & soak ≥2,000 concurrent sessions (offline deterministic model; live ≥1h is infra).
// ---------------------------------------------------------------------------------------------

#[test]
fn r11_soak_2000_sessions_bounded_and_leak_free() {
    use ainxt_scenario::soak::{run_soak, SoakConfig};
    let cfg = SoakConfig {
        sessions: 2000,
        turns_per_session: 5,
        inbox_cap: 8,
        workers: 64,
    };
    let r = run_soak(&cfg);
    assert!(
        r.passed(&cfg),
        "the 2,000-session soak model must be leak-free, worker-bounded, isolated and conserving: {r:?}"
    );
    // No leak: nothing left queued after a full drain.
    assert_eq!(r.leaked, 0, "leaked work items after drain");
    // Bounded concurrency: never exceeded the worker ceiling despite 2,000 sessions.
    assert!(
        r.peak_live <= cfg.workers,
        "peak live {} exceeded worker ceiling {}",
        r.peak_live,
        cfg.workers
    );
    // Conservation: every submitted turn is accounted for (serviced or shed) — none silently lost.
    assert_eq!(
        r.completed + r.rejected,
        cfg.sessions as u64 * cfg.turns_per_session as u64,
        "no turn may vanish under sustained load"
    );
    assert!(r.completed > 0, "work must actually be serviced");
    assert!(r.isolation_held, "no cross-session state bleed");
}

#[test]
fn r11_soak_applies_backpressure_not_unbounded_growth() {
    use ainxt_scenario::soak::{run_soak, SoakConfig};
    // A tiny inbox vs many turns forces back-pressure: excess turns are REJECTED (503-class), the
    // live-item ceiling still holds, and nothing leaks — the opposite of unbounded queue growth.
    let cfg = SoakConfig {
        sessions: 2000,
        turns_per_session: 20,
        inbox_cap: 2,
        workers: 64,
    };
    let r = run_soak(&cfg);
    assert!(
        r.rejected > 0,
        "a full bounded inbox must reject, not grow: {r:?}"
    );
    assert_eq!(r.leaked, 0);
    assert!(r.peak_live <= cfg.workers);
}

#[test]
fn r11_pairwise_covering_array_covers_every_pair() {
    // The planner's covering array covers every cross-axis value pair at a tiny fraction of the
    // full cross-product — this is what makes "pairwise, not padding" true.
    let sizes: Vec<usize> = seven_axes().iter().map(|a| a.len()).collect();
    let rows = pairwise_plan(&sizes);
    assert!(
        plan_covers_all_pairs(&sizes, &rows),
        "the seven-axis plan must cover every cross-axis value pair"
    );
    let full: usize = sizes.iter().product();
    assert!(
        rows.len() * 20 < full,
        "pairwise ({}) must be far smaller than full-cross ({full})",
        rows.len()
    );
}
