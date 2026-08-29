// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-12 Context-Fabric gap closures.
//!
//! * **Fabric graph layers 2–10 real extractors** (`CONTEXT_FABRIC.md` §2): [`build_fabric`] turns
//!   real source files + a commit log + a runtime-error log + a coverage report + architecture
//!   containment into the typed [`FabricGraph`] the optimizer queries — previously the graph was a
//!   substrate populated only by hand in tests, with no extractor. Fails before: `ainxt_context::
//!   extract` did not exist.
//! * **Scope classifier is classified, not keyword-matched** (`STRUCTURED_FEDERATED_RETRIEVAL.md`
//!   §7.1): [`classify_scope`] accumulates weighted evidence on both sides and decides on the
//!   margin, with an `ambiguous → clarify` verdict — not an `if contains("root cause")` switch.
//!   Fails before: `classify_scope` / `QueryScope` did not exist and `plan_query` keyword-matched.

use ainxt_context::extract::{
    build_fabric, extract_code, CommitTouch, Containment, CoverageRecord, FabricInputs, Language,
    RuntimeObservation, SourceFile,
};
use ainxt_context::optimizer::{classify_scope, plan_query, GraphLayer, QueryScope};

// ============================ gap: fabric layers 2–10 extractors =============================

#[test]
fn r12_fabric_extractors_populate_layers_2_through_10() {
    let rust = SourceFile::new(
        "settlement.rs",
        Language::Rust,
        "use crate::ledger::Ledger;\n\
         pub fn process_settlement(b: &Batch) {\n\
         \x20   validate_batch(b);\n\
         \x20   post_ledger(b);\n\
         }\n\
         fn validate_batch(b: &Batch) {}\n\
         fn post_ledger(b: &Batch) {}\n",
    );

    let inputs = FabricInputs {
        sources: vec![rust],
        // git-history change-coupling (layer 8): two files co-changed in one commit.
        commits: vec![CommitTouch::new(&["settlement.rs", "ledger.rs"])],
        // runtime/observability (layer 9).
        runtime: vec![RuntimeObservation {
            function: "post_ledger".into(),
            error_signature: "TimeoutError".into(),
        }],
        // test-coverage (layer 10).
        coverage: vec![CoverageRecord {
            test: "test_settlement".into(),
            covers: vec!["process_settlement".into()],
        }],
        // architecture (layer 7).
        architecture: vec![Containment {
            parent: "settlement_svc".into(),
            child: "settlement.rs".into(),
        }],
    };

    let g = build_fabric(&inputs);

    // Layer 5 (call graph) — extracted from real source, not hand-built.
    assert_eq!(
        g.who_calls("validate_batch"),
        vec!["process_settlement".to_string()],
        "call graph extracted from source"
    );
    assert_eq!(
        g.who_calls("post_ledger"),
        vec!["process_settlement".to_string()]
    );

    // Layer 6 (import graph).
    assert!(
        g.deps("settlement.rs").iter().any(|m| m.contains("ledger")),
        "import edge extracted from `use`"
    );

    // Layer 8 (git-history change-coupling), symmetric.
    assert_eq!(
        g.changed_with("settlement.rs"),
        vec!["ledger.rs".to_string()]
    );

    // Layer 9 (runtime errors).
    assert_eq!(
        g.runtime_errors_for("post_ledger"),
        vec!["TimeoutError".to_string()]
    );

    // Layer 10 (test coverage).
    assert_eq!(
        g.tests_covering("process_settlement"),
        vec!["test_settlement".to_string()]
    );

    // Layer 7 (architecture containment).
    assert_eq!(
        g.architecture_around("settlement.rs"),
        vec!["settlement_svc".to_string()]
    );

    // Layers 3/4 (symbol + AST spans) present in the extraction.
    let ex = extract_code(&inputs.sources[0]);
    assert!(ex
        .defined_symbols
        .contains(&"process_settlement".to_string()));
    assert!(ex
        .spans
        .iter()
        .any(|s| s.name == "process_settlement" && s.end_line > s.start_line));
}

#[test]
fn r12_fabric_ranks_over_extracted_graph() {
    // The extracted graph must project onto the ranker so the optimizer ranks over the REAL fabric.
    let src = SourceFile::new(
        "a.rs",
        Language::Rust,
        "fn top() { mid(); }\nfn mid() { leaf(); }\nfn leaf() {}\nfn unrelated() {}\n",
    );
    let g = build_fabric(&FabricInputs {
        sources: vec![src],
        ..Default::default()
    });
    let rg = g.to_rank_graph();
    let mut seeds = std::collections::BTreeMap::new();
    seeds.insert("top".to_string(), 1.0);
    let scores = ainxt_context::optimizer::personalized_pagerank(&rg, &seeds, 0.85, 100);
    assert!(
        scores.get("mid").copied().unwrap_or(0.0) > 0.0,
        "reachable callee ranked"
    );
    // `unrelated` has no edges → isolated; the seeded region carries more mass.
    let mid = scores.get("mid").copied().unwrap_or(0.0);
    let unrelated = scores.get("unrelated").copied().unwrap_or(0.0);
    assert!(
        mid > unrelated,
        "a node reachable from the seed outranks the unrelated one"
    );
}

// ============================ gap: scope classifier (classified, not keyword) ================

#[test]
fn r12_scope_classifier_decides_on_margin_not_a_keyword() {
    // Point lookup: strong count + specificity evidence, no sensemaking evidence.
    let point = classify_scope("how many failed settlements did bank X have last Tuesday");
    assert_eq!(point.scope, QueryScope::PointLookup);
    assert!(!point.ambiguous);
    assert!(point.point_score > point.global_score);

    // Global sensemaking: accumulated sensemaking evidence dominates.
    let global = classify_scope(
        "what are the recurring root causes behind settlement failures this quarter",
    );
    assert_eq!(global.scope, QueryScope::Global);
    assert!(!global.ambiguous);
    assert!(global.global_score > global.point_score);

    // The classifier is NOT a single keyword: "root cause" alone does NOT force global when strong
    // point evidence competes — a genuinely two-sided turn is flagged AMBIGUOUS (clarify), the
    // discipline a keyword `contains("root cause")` switch cannot express.
    let mixed = classify_scope("how many root cause tickets were counted");
    assert!(
        mixed.global_score > 0.0 && mixed.point_score > 0.0,
        "evidence on both sides"
    );
    assert!(
        mixed.ambiguous,
        "low-margin two-sided query is ambiguous → clarify, not a silent pick"
    );
}

#[test]
fn r12_scope_classifier_drives_plan_query_global_routing() {
    // The planner's GlobalSummary routing now rides the classifier, not a keyword list.
    let plan =
        plan_query("what are the recurring systemic patterns across all settlement incidents");
    assert!(
        plan.includes(GraphLayer::GlobalSummary),
        "classified-global routes to the global layer"
    );

    // A pure count query is classified point → no global layer.
    let count = plan_query("how many failed settlements did bank X have last Tuesday");
    assert!(count.includes(GraphLayer::Structured));
    assert!(
        !count.includes(GraphLayer::GlobalSummary),
        "a point count is not a global-summary query"
    );
}

#[test]
fn r12_scope_classifier_zero_evidence_is_point_not_global() {
    // A general prose question trips neither side → PointLookup at zero confidence, GlobalSummary off.
    let c = classify_scope("what is UPI");
    assert_eq!(c.scope, QueryScope::PointLookup);
    assert_eq!(c.confidence, 0.0);
    assert!(!c.ambiguous);
    assert!(!plan_query("what is UPI").includes(GraphLayer::GlobalSummary));
}
