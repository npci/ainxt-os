// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX context-fabric — `governed::served_structured_turn` (the catalog → NL-to-SQL →
//! server-side-numeric-re-derivation bridge, `STRUCTURED_FEDERATED_RETRIEVAL.md` §4) was a fully
//! implemented and unit-tested composition-root entrypoint with ZERO callers outside its own crate's
//! `#[cfg(test)]` module — no model-facing route to the metric catalog existed anywhere on the served
//! path, exactly the same class of gap `governed::FederatedQueryTool` closed for the federation
//! broker one section above it in `governed.rs`.
//!
//! Fail-before: `ainxt_runtimed::build_unified_capability_registry_shared` (the daemon's REAL unified
//! `ToolRuntime`, exercised by the shipped composition root) registered `query_ledger` and
//! `federated_query` but had no `structured_query` capability at all — `governed::StructuredQueryTool`
//! did not exist, so `served_structured_turn` was reachable only from `governed.rs`'s own tests.
//! Pass-after: the SAME served registry the daemon builds carries a `structured_query` capability
//! (reachable in the model's function-calling manifest, dispatched through the identical
//! OBO-authz/exactly-once path as every other capability), and `StructuredQueryTool::dispatch` proves
//! the real catalog → NL-to-SQL round trip works end to end when a deployment loads real metrics.

use ainxt_retrieval::structured::{MetricCatalog, MetricDef};
use ainxt_retrieval::structured_pipeline::{Aggregation, DimensionFilter};
use ainxt_runtimed::build_unified_capability_registry_shared;
use ainxt_runtimed::governed::StructuredQueryTool;
use ainxt_types::{DataClass, Principal};
use std::collections::BTreeSet;

fn settlement_catalog() -> MetricCatalog {
    let metric = MetricDef::new(
        "failed_settlement_count",
        "v_settlement_failures_curated",
        DataClass::Confidential,
    )
    .dimension("bank_id", DataClass::Internal)
    .rls("rls_settlement_by_dept");
    let mut rls = BTreeSet::new();
    rls.insert("rls_settlement_by_dept".to_string());
    MetricCatalog::load(vec![metric], &rls).unwrap()
}

fn settlement_view_schema() -> ainxt_nl2sql::Schema {
    use ainxt_nl2sql::{Column, Table};
    ainxt_nl2sql::Schema::new(vec![Table::new(
        "v_settlement_failures_curated",
        vec![Column::new("bank_id", DataClass::Internal).unwrap()],
    )
    .unwrap()])
    .unwrap()
}

/// The REAL served composition root's unified capability registry carries `structured_query` in its
/// manifest — reachable through the SAME `ToolRuntime` every other daemon capability (`query_ledger`,
/// `federated_query`) dispatches through, not a bespoke structured-query-only surface. This is the
/// exact "no model-facing route to it existed at all" gap closing: the capability now genuinely
/// appears on the served path, not just inside `governed.rs`'s own test module.
#[test]
fn r_structured_query_capability_is_registered_on_the_served_unified_registry() {
    let mut report = Vec::new();
    let (registry, _ledger, _reconciler) = build_unified_capability_registry_shared(&mut report);

    let schemas = registry.schemas();
    let structured = schemas
        .iter()
        .find(|s| s.name == "structured_query")
        .expect("structured_query must be registered on the served unified capability registry");
    assert!(
        structured.description.contains("catalog"),
        "the manifest description must name the governed catalog boundary"
    );

    // Registration must not have been silently refused (would show up as a report line, exactly
    // like the existing query_ledger/federated_query registration checks do).
    assert!(
        !report
            .iter()
            .any(|l| l.contains("refused to register structured_query")),
        "structured_query registration was refused: {report:?}"
    );

    // The one-shot `Tool::execute` path must fail closed exactly like `query_ledger`/`federated_query`
    // — a structured metric compile needs the caller's classified turn text + Principal clearance,
    // neither of which the sync dispatch signature carries.
    let result = registry.dispatch("structured_query", "{}");
    assert!(
        matches!(result, ainxt_tools::DispatchResult::Failed(_)),
        "the one-shot capability path must refuse, not silently succeed: {result:?}"
    );
}

/// The functional round trip through the governed capability wrapper: a deployment that loads real
/// metrics into the catalog (via `StructuredQueryTool::new`, mirroring how `FederatedQueryTool::new`
/// takes a real `FederationRegistry`) gets a genuinely working catalog → NL-to-SQL compile — proving
/// `StructuredQueryTool::dispatch` is not just a registered stub but the real, previously-orphaned
/// `served_structured_turn` entrypoint running end to end.
#[test]
fn r_structured_query_tool_dispatch_compiles_a_real_point_lookup() {
    let catalog = settlement_catalog();
    let schema = settlement_view_schema();
    let tool = StructuredQueryTool::new(catalog, schema);
    let analyst = Principal::user("analyst", &[]).with_clearance(DataClass::Confidential);

    let compiled = tool
        .dispatch(
            "how many failed settlements did bank X have on tuesday",
            "failed_settlement_count",
            &["bank_id"],
            &[DimensionFilter::eq_text("bank_id", "BANKX")],
            Aggregation::Count,
            &analyst,
        )
        .unwrap()
        .expect("a point-lookup turn must reach the structured pipeline");
    assert!(compiled.query.sql.starts_with("SELECT "));
    assert!(!compiled.query_hash.is_empty());

    // A global/sensemaking ask must NOT drive the single-metric structured round trip through the
    // SAME governed capability wrapper a served turn would dispatch.
    let none = tool
        .dispatch(
            "what are the recurring root causes of settlement failure this quarter",
            "failed_settlement_count",
            &[],
            &[],
            Aggregation::Count,
            &analyst,
        )
        .unwrap();
    assert!(
        none.is_none(),
        "a global/sensemaking ask must not reach the structured pipeline"
    );
}

/// The AIR-GAPPED SERVED DEFAULT (`StructuredQueryTool::empty`, what
/// `build_unified_capability_registry_shared` actually installs) excludes every metric until a
/// deployment loads its own catalog — the same "declared but registers nothing exotic by default"
/// posture `FederatedQueryTool`'s empty `FederationRegistry` uses. A point-lookup-classified turn must
/// fail closed with `UnknownMetric`, never a panic and never a silently-executed unscoped query.
#[test]
fn r_structured_query_empty_default_excludes_every_metric_until_configured() {
    let tool = StructuredQueryTool::empty();
    let analyst = Principal::user("analyst", &[]);
    let err = tool
        .dispatch(
            "how many failed settlements did bank X have on tuesday",
            "failed_settlement_count",
            &["bank_id"],
            &[],
            Aggregation::Count,
            &analyst,
        )
        .expect_err("the empty default catalog must refuse every metric_id");
    assert!(
        matches!(
            err,
            ainxt_retrieval::structured_pipeline::PipelineError::Catalog(
                ainxt_retrieval::structured::CatalogError::UnknownMetric { .. }
            )
        ),
        "expected UnknownMetric on the empty default catalog, got {err:?}"
    );
}
