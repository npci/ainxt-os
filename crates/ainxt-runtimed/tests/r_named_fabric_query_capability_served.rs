// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX context-fabric — `governed::named_fabric_query` (the §5 named fabric query vocabulary
//! dispatcher, `CONTEXT_FABRIC.md` §5) was a fully implemented and unit-tested composition-root
//! entrypoint (proven in `r_named_fabric_query_served.rs`) with ZERO model-facing route: unlike the
//! sibling `FederatedQueryTool`/`StructuredQueryTool`, there was no governed `Tool` wrapping it and no
//! registration in the served unified capability registry — a served turn's function-calling loop
//! could never select `named_fabric_query` because it simply did not exist in the manifest.
//!
//! Fail-before: `ainxt_runtimed::governed::NamedFabricQueryTool` did not exist and
//! `build_unified_capability_registry_shared`'s manifest carried `query_ledger` + `federated_query` +
//! `structured_query` but no `named_fabric_query` entry — this file would not resolve.
//! Pass-after: the SAME served registry the daemon builds carries a `named_fabric_query` capability,
//! dispatched through the identical OBO-authz/exactly-once path as every other capability, and
//! `NamedFabricQueryTool::dispatch` proves the real §5 vocabulary resolves against a populated fabric.

use ainxt_context::optimizer::{EdgeKind, FabricGraph, NamedFabricQuery};
use ainxt_runtimed::build_unified_capability_registry_shared;
use ainxt_runtimed::governed::NamedFabricQueryTool;

/// The REAL served composition root's unified capability registry carries `named_fabric_query` in its
/// manifest — reachable through the SAME `ToolRuntime` every other daemon capability (`query_ledger`,
/// `federated_query`, `structured_query`) dispatches through, not a bespoke fabric-only surface.
#[test]
fn r_named_fabric_query_capability_is_registered_on_the_served_unified_registry() {
    let mut report = Vec::new();
    let (registry, _ledger, _reconciler) = build_unified_capability_registry_shared(&mut report);

    let schemas = registry.schemas();
    let named_query = schemas
        .iter()
        .find(|s| s.name == "named_fabric_query")
        .expect("named_fabric_query must be registered on the served unified capability registry");
    assert!(
        named_query.description.contains("whoCalls"),
        "the manifest description must name the §5 vocabulary"
    );

    // Registration must not have been silently refused (would show up as a report line, exactly
    // like the existing query_ledger/federated_query/structured_query registration checks do).
    assert!(
        !report
            .iter()
            .any(|l| l.contains("refused to register named_fabric_query")),
        "named_fabric_query registration was refused: {report:?}"
    );

    // The one-shot `Tool::execute` path must fail closed exactly like `structured_query`/
    // `federated_query` — a named query needs the caller's structured `NamedFabricQuery` enum,
    // which the sync dispatch signature doesn't carry.
    let result = registry.dispatch("named_fabric_query", "{}");
    assert!(
        matches!(result, ainxt_tools::DispatchResult::Failed(_)),
        "the one-shot capability path must refuse, not silently succeed: {result:?}"
    );
}

/// The functional round trip through the governed capability wrapper: a deployment that loads a real
/// indexed fabric (via `NamedFabricQueryTool::new`, mirroring how `StructuredQueryTool::new` takes a
/// real `MetricCatalog`) gets a genuinely working §5 named query — proving `dispatch` is not just a
/// registered stub but the real, previously-orphaned `named_fabric_query` dispatcher running end to
/// end against every named-query kind.
#[test]
fn r_named_fabric_query_tool_dispatch_resolves_every_named_kind() {
    let fabric = FabricGraph::new()
        .with_edge("process_settlement", EdgeKind::Calls, "post_ledger")
        .with_edge("validate_batch", EdgeKind::References, "settlement_schema")
        .with_edge("settlement.rs", EdgeKind::Imports, "ledger.rs");
    let tool = NamedFabricQueryTool::new(fabric);

    assert_eq!(
        tool.dispatch(&NamedFabricQuery::WhoCalls {
            symbol: "post_ledger".to_string()
        }),
        vec!["process_settlement".to_string()]
    );
    assert_eq!(
        tool.dispatch(&NamedFabricQuery::RefsOf {
            symbol: "settlement_schema".to_string()
        }),
        vec!["validate_batch".to_string()]
    );
    assert_eq!(
        tool.dispatch(&NamedFabricQuery::Deps {
            module: "settlement.rs".to_string()
        }),
        vec!["ledger.rs".to_string()]
    );
}

/// The AIR-GAPPED SERVED DEFAULT (`NamedFabricQueryTool::empty`, what
/// `build_unified_capability_registry_shared` actually installs) excludes every node until a
/// deployment loads a real indexed fabric — the same "declared but registers nothing exotic by
/// default" posture `StructuredQueryTool`'s empty `MetricCatalog` uses. A query against the empty
/// default must return an empty result, never a panic.
#[test]
fn r_named_fabric_query_empty_default_returns_empty_until_configured() {
    let tool = NamedFabricQueryTool::empty();
    let result = tool.dispatch(&NamedFabricQuery::WhoCalls {
        symbol: "anything".to_string(),
    });
    assert!(
        result.is_empty(),
        "the empty default fabric must resolve every query to no results"
    );
}
