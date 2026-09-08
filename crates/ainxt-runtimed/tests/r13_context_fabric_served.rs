// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R13 (context-fabric, HIGH ×2) — the "fabric of graphs" is REACHABLE from the composition root and
//! budget-fits against the Model-Router eligible set on a served-shaped turn:
//!   1. 12+ graph layers compiled into the window each turn (the fabric of graphs), and
//!   2. budget-fit resolved against the eligible-model set the Model Router resolved for THIS turn
//!      (Gap-22, anti-silent-truncation on failover).
//!
//! Before this the multi-graph compile (`ainxt_context::route::MultiGraphFabric::route_eligible`) was
//! reachable only from the reserved chat/convo crates + `ainxt-context`'s own tests — never from the
//! daemon composition root. `ainxt_runtimed::governed::{served_fabric_from_kb, compile_served_fabric}`
//! is the clean, drivable composition-root entrypoint that overlays the repo/KG code layers onto the
//! KB EnterpriseDocs layer and fits the window to the per-turn eligible set.
//!
//! FAIL-BEFORE: the `governed::compile_served_fabric` / `served_fabric_from_kb` entrypoints did not
//! exist as public composition-root API (this file would not compile / resolve). PASS-AFTER: green,
//! offline, deterministic. **needs_hot_wiring**: the `/v1/chat` transport call-site owning (a) the
//! per-namespace populated fabric from the repo/KG indexer and (b) the live per-turn eligible set from
//! `ainxt_runtime::router::ModelRouter` — deliberately NOT mounted so the air-gapped default is
//! unchanged (empty-eligible ⇒ empty grounded window, never a denied turn — no empty-pool 503).

use std::collections::BTreeMap;

use ainxt_context::optimizer::{EdgeKind, FabricGraph, GraphLayer};
use ainxt_context::{Chunk as CtxChunk, LineageOutcome};
use ainxt_profile::RetrievalScope;
use ainxt_retrieval::EligibleModel;
use ainxt_runtimed::governed::{
    access_for, compile_served_fabric, eligible_default, refit_served_window, served_fabric_from_kb,
};
use ainxt_runtimed::{KbConfig, KbDocument, KbScope};
use ainxt_types::{DataClass, Principal};

fn doc(id: &str, source: &str, text: &str, dept: Option<&str>) -> KbDocument {
    KbDocument {
        id: id.into(),
        source: source.into(),
        text: text.into(),
        data_class: DataClass::Internal,
        scope: KbScope::Platform,
        namespace: None,
        repo: None,
        department: dept.map(|d| d.to_string()),
        max_ad_level: None,
        allow_groups: vec![],
        deny_groups: vec![],
        row_attributes: BTreeMap::new(),
    }
}

/// A repo-indexed code fabric spanning MANY of the 12 fabric layers (symbol/AST/call/import/git/
/// runtime/test/architecture) + their content chunks — the shape the per-namespace indexer feeds.
fn code_fabric() -> (FabricGraph, Vec<CtxChunk>) {
    let g = FabricGraph::new()
        .with_layer("sym1", GraphLayer::Symbol)
        .with_layer("ast1", GraphLayer::Ast)
        .with_layer("call1", GraphLayer::Call)
        .with_layer("imp1", GraphLayer::Import)
        .with_layer("git1", GraphLayer::GitHistory)
        .with_layer("run1", GraphLayer::Runtime)
        .with_layer("test1", GraphLayer::Test)
        .with_layer("arch1", GraphLayer::Architecture)
        .with_edge("sym1", EdgeKind::Calls, "call1")
        .with_edge("sym1", EdgeKind::Imports, "imp1");
    let c = |id: &str, src: &str| {
        CtxChunk::new(
            id,
            src,
            "settlement import dependency refactor failure signature",
            DataClass::Internal,
        )
    };
    (
        g,
        vec![
            c("sym1", "parser.rs"),
            c("ast1", "ast.rs"),
            c("call1", "caller.rs"),
            c("imp1", "imports.rs"),
            c("git1", "history"),
            c("run1", "trace"),
            c("test1", "test.rs"),
            c("arch1", "arch.md"),
        ],
    )
}

#[test]
fn r13_served_fabric_compiles_many_layers_and_fits_router_eligible_set() {
    let (graph, contents) = code_fabric();
    let kb = KbConfig {
        documents: vec![doc(
            "runbook",
            "runbook.md",
            "settlement import dependency refactor runbook",
            None,
        )],
        rls_department_isolation: false,
        rag_enabled: true,
    };
    // Composition-root fabric assembly: 8 code layers overlaid with the KB EnterpriseDocs layer.
    let fabric = served_fabric_from_kb(&kb, RetrievalScope::PlatformAndNamespace, graph, contents);
    assert_eq!(
        fabric.len(),
        9,
        "8 code layers + KB enterprise-docs layer indexed into the fabric"
    );

    let principal = Principal::user("u", &["chat.send"]).with_clearance(DataClass::Internal);
    let access = access_for(&principal, None, &[]);
    let query = "why did the settlement import dependency refactor fail";

    // A wide router-eligible set compiles many distinct fabric layers into the window (the fabric of
    // graphs — not a single flat retrieval list).
    let wide = compile_served_fabric(&fabric, query, &access, None, &eligible_default(), "");
    assert!(
        wide.layer_count() >= 3,
        "multiple distinct fabric layers compiled into the window: {:?}",
        wide.compiled_layers
    );
    assert!(wide.compiled_layers.contains(&GraphLayer::EnterpriseDocs));

    // The Model-Router's per-turn eligible set (a failover-tight 3-token model) binds the budget floor
    // — proving the explicit eligible set, not a config default, resolves the fit (Gap-22).
    let router_tiny = [EligibleModel::new("failover-tiny", 3)];
    let tight = compile_served_fabric(&fabric, query, &access, None, &router_tiny, "");
    assert_eq!(
        tight.window.window_tokens, 3,
        "the router eligible set (not a default) resolves the budget floor"
    );
    assert!(
        tight.window.context.chunks.len() < wide.window.context.chunks.len(),
        "the narrow router floor sheds evidence vs the wide set"
    );
    // Anti-silent-truncation: shed evidence is ACCOUNTED in lineage, never dropped silently on failover.
    assert!(
        tight
            .window
            .context
            .lineage
            .iter()
            .any(|n| n.outcome == LineageOutcome::DroppedByBudget),
        "shed evidence is accounted as DroppedByBudget — never a silent failover truncation"
    );
}

// GAP-FIX context-fabric — `RoutedWindow::two_phase_fit` was fully implemented and unit-tested but
// had zero callers outside `ainxt-context`'s own tests, even though `compile_served_fabric` above
// already builds the exact `RoutedWindow` it re-fits. Proves the composition-root wrapper re-fits the
// window to the model that ACTUALLY confirmed (not the wide set the initial compile assumed).
#[test]
fn r_refit_served_window_re_fits_to_the_confirmed_model_not_the_initial_wide_set() {
    let (graph, contents) = code_fabric();
    let kb = KbConfig {
        documents: vec![doc(
            "runbook",
            "runbook.md",
            "settlement import dependency refactor runbook",
            None,
        )],
        rls_department_isolation: false,
        rag_enabled: true,
    };
    let fabric = served_fabric_from_kb(&kb, RetrievalScope::PlatformAndNamespace, graph, contents);
    let principal = Principal::user("u", &["chat.send"]).with_clearance(DataClass::Internal);
    let access = access_for(&principal, None, &[]);
    let query = "why did the settlement import dependency refactor fail";

    // Compiled wide against the default eligible set (never wider than the narrowest candidate, 8k).
    let wide = compile_served_fabric(&fabric, query, &access, None, &eligible_default(), "");
    assert_eq!(wide.window.window_tokens, 8_000);

    // The model that actually confirmed for THIS turn is far tighter — re-fit must narrow to it, not
    // stay pinned to the wide compile-time assumption.
    let confirmed = EligibleModel::new("confirmed-tiny", 3);
    let refit = refit_served_window(&wide, &confirmed, &[]);
    assert_eq!(
        refit.window_tokens, 3,
        "the refit window is bound by the CONFIRMED model, not the wide set"
    );
    assert!(
        refit.context.chunks.len() <= wide.window.context.chunks.len(),
        "re-fitting to a tighter model never grows the evidence set"
    );
}

#[test]
fn r13_served_fabric_is_node_acl_filtered_pre_rank() {
    // The fabric compile still enforces per-node RBAC pre-rank (existence never leaks): a dept-locked
    // KB node is filtered for an out-of-department caller before it is ever scored/positioned/cited.
    let kb = KbConfig {
        documents: vec![doc(
            "beta-only",
            "beta.md",
            "settlement reconciliation runbook",
            Some("beta"),
        )],
        rls_department_isolation: false,
        rag_enabled: true,
    };
    let fabric = served_fabric_from_kb(
        &kb,
        RetrievalScope::PlatformAndNamespace,
        FabricGraph::new(),
        vec![],
    );
    let principal = Principal::user("u-alpha", &["chat.send"])
        .with_clearance(DataClass::Confidential)
        .with_department("alpha");
    let access = access_for(&principal, Some(3), &[]);
    let routed = compile_served_fabric(
        &fabric,
        "settlement reconciliation",
        &access,
        None,
        &eligible_default(),
        "",
    );
    assert!(
        routed.window.context.chunks.is_empty(),
        "a beta-locked node must be filtered pre-rank for an alpha caller — existence never leaks"
    );
}
