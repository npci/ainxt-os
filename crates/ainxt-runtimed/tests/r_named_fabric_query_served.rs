// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX context-fabric — `ainxt_context::optimizer::FabricGraph`'s named query methods
//! (`who_calls`/`refs_of`/`deps`/`changed_with`/`tests_covering`/`runtime_errors_for`/
//! `architecture_around` — the design's §5 named vocabulary `CONTEXT_FABRIC.md` calls `whoCalls`/
//! `refsOf`/`deps`/`changedWith`/`testsCovering`/`runtimeErrorsFor`/`architectureAround`) were fully
//! implemented and unit-tested but had ZERO callers outside `ainxt-context`'s own `tests/` directory
//! (verified via `grep -rn "who_calls\|refs_of\|changed_with\|tests_covering\|runtime_errors_for\|
//! architecture_around" --include="*.rs" crates/` — only `ainxt-context/src/optimizer.rs` and
//! `ainxt-context/tests/r12_context_fabric.rs` matched). The design's §5 named query surface existed
//! on the type but nothing outside the crate ever addressed it BY NAME — the exact same class of gap
//! `ainxt_graph::GraphQuery::ByRel` closed for the sibling knowledge graph (a caller could ask "what
//! kind is this node" but never "who calls this symbol").
//!
//! Fail-before: `ainxt_context::optimizer::NamedFabricQuery` did not exist and
//! `governed::named_fabric_query` did not exist — this file would not resolve.
//! Pass-after: the composition-root's own wrapper dispatches every one of the seven named query
//! kinds to the real `FabricGraph` methods, reachable from `ainxt_runtimed::governed` exactly like
//! `governed::route_artifact_model` already is for the sibling `data-surfaces-artifacts` gap.

use ainxt_context::optimizer::{EdgeKind, FabricGraph, NamedFabricQuery};
use ainxt_runtimed::governed::named_fabric_query;

/// A small fabric mirroring the design's own §5 worked examples: a call edge, a reference edge, an
/// import, a change-coupling pair, a test-covers edge, a runtime error, and an architecture-contains
/// edge — one of each `EdgeKind` so every `NamedFabricQuery` variant has a real hit.
fn settlement_fabric() -> FabricGraph {
    FabricGraph::new()
        .with_edge("process_settlement", EdgeKind::Calls, "post_ledger")
        .with_edge("validate_batch", EdgeKind::References, "settlement_schema")
        .with_edge("settlement.rs", EdgeKind::Imports, "ledger.rs")
        .with_edge("settlement.rs", EdgeKind::ChangedWith, "ledger.rs")
        .with_edge(
            "test_settlement",
            EdgeKind::TestCovers,
            "process_settlement",
        )
        .with_edge("post_ledger", EdgeKind::RuntimeError, "TimeoutError")
        .with_edge(
            "settlement_svc",
            EdgeKind::ArchitectureContains,
            "settlement.rs",
        )
}

#[test]
fn r_named_fabric_query_dispatches_every_named_kind_through_the_composition_root() {
    let fabric = settlement_fabric();

    assert_eq!(
        named_fabric_query(
            &fabric,
            &NamedFabricQuery::WhoCalls {
                symbol: "post_ledger".to_string()
            }
        ),
        vec!["process_settlement".to_string()],
        "whoCalls must resolve through governed::named_fabric_query"
    );
    assert_eq!(
        named_fabric_query(
            &fabric,
            &NamedFabricQuery::RefsOf {
                symbol: "settlement_schema".to_string()
            }
        ),
        vec!["validate_batch".to_string()]
    );
    assert_eq!(
        named_fabric_query(
            &fabric,
            &NamedFabricQuery::Deps {
                module: "settlement.rs".to_string()
            }
        ),
        vec!["ledger.rs".to_string()]
    );
    assert_eq!(
        named_fabric_query(
            &fabric,
            &NamedFabricQuery::ChangedWith {
                file: "settlement.rs".to_string()
            }
        ),
        vec!["ledger.rs".to_string()]
    );
    assert_eq!(
        named_fabric_query(
            &fabric,
            &NamedFabricQuery::TestsCovering {
                function: "process_settlement".to_string()
            }
        ),
        vec!["test_settlement".to_string()]
    );
    assert_eq!(
        named_fabric_query(
            &fabric,
            &NamedFabricQuery::RuntimeErrorsFor {
                function: "post_ledger".to_string()
            }
        ),
        vec!["TimeoutError".to_string()]
    );
    assert_eq!(
        named_fabric_query(
            &fabric,
            &NamedFabricQuery::ArchitectureAround {
                module: "settlement.rs".to_string()
            }
        ),
        vec!["settlement_svc".to_string()]
    );

    // An unknown symbol yields an empty (never a panic, never a wildcard match) result.
    assert!(named_fabric_query(
        &fabric,
        &NamedFabricQuery::WhoCalls {
            symbol: "nonexistent_symbol".to_string()
        }
    )
    .is_empty());
}
