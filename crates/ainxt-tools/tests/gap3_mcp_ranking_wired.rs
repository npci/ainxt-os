// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-AUDIT tooling-mcp-plugins-routing — "MCP retrieval-ranking has zero callers".
//!
//! `ainxt_mcp::rank_session`/`CoreSet`/`capability_search` (§2.4's BM25 retrieval-ranking + always-
//! visible core set + session stickiness — the concrete answer to "hundreds of tools degrade tool-
//! choice") were fully implemented and unit-tested in `ainxt-mcp`, but the ONE real production
//! entrypoint that puts a discovered MCP tool in front of the model
//! (`mcp_bridge::register_plannable_mcp_tools`) registered every TOFU-pinned tool unconditionally —
//! no caller anywhere ever asked the ranker anything. `register_plannable_mcp_tools_ranked` closes
//! this: it is `register_plannable_mcp_tools` with the ranking gate genuinely in front of it.
//!
//! These tests drive the REAL function end-to-end against a REAL (in-memory, network-free) MCP
//! discovery + a REAL unified `CapabilityRegistry`, proving the ranker actually bounds what gets
//! registered (and therefore what the model can ever be shown/dispatch), not merely that the ranking
//! math is correct in isolation (already proven by `ainxt-mcp`'s own `r11_ranking_at_scale.rs`).

use std::sync::Arc;

use ainxt_mcp::{
    AuthProvider, CoreSet, InMemoryPinStore, McpError, McpRegistry, McpServer, McpTransport,
    NoAuth, RankConfig, ToolManifest, ToolResult,
};
use ainxt_tools::mcp_bridge::register_plannable_mcp_tools_ranked;
use ainxt_tools::{CapabilityRegistry, DispatchResult, InMemoryLedger, ManualReconciler};

const GIT_SERVER_URL: &str = "https://git.example/mcp";

struct ThreeToolTransport;
impl McpTransport for ThreeToolTransport {
    fn connect(&self, _token: Option<&str>) -> Result<(), McpError> {
        Ok(())
    }
    fn list_tools(&self) -> Result<Vec<ToolManifest>, McpError> {
        Ok(vec![
            ToolManifest::new("create_mr", "open a merge request in gitlab from a branch"),
            ToolManifest::new(
                "search_code",
                "search the repository source code for a function",
            ),
            ToolManifest::new(
                "send_email",
                "send an email notification to a distribution list",
            ),
        ])
    }
    fn call_tool(&self, tool: &str, args: &str) -> Result<ToolResult, McpError> {
        Ok(ToolResult::ok(&format!("mcp:{tool}:{args}")))
    }
}

/// Discover + TOFU-approve all three tools, returning the plannable set (shared setup for both tests).
fn discover_three_tools() -> (
    Arc<McpRegistry>,
    Arc<dyn AuthProvider>,
    Vec<ainxt_mcp::QualifiedTool>,
) {
    let mut mcp = McpRegistry::new();
    mcp.register(McpServer::new(
        "git",
        GIT_SERVER_URL,
        Box::new(ThreeToolTransport),
    ));
    let mcp = Arc::new(mcp);
    let auth: Arc<dyn AuthProvider> = Arc::new(NoAuth);
    let pins = InMemoryPinStore::new();

    let d1 = mcp.discover_pinned("alice", auth.as_ref(), &pins);
    assert!(
        d1.plannable().is_empty(),
        "TOFU: nothing plannable before approval"
    );
    d1.servers[0].approve(&pins, "alice", 1);
    let d2 = mcp.discover_pinned("alice", auth.as_ref(), &pins);
    let plannable = d2.plannable();
    assert_eq!(
        plannable.len(),
        3,
        "all three tools plannable after approval"
    );
    (mcp, auth, plannable)
}

#[test]
fn only_the_top_ranked_tool_is_registered_not_the_full_discovered_set() {
    let (mcp, auth, plannable) = discover_three_tools();

    let mut reg =
        CapabilityRegistry::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler));
    let config = RankConfig {
        k: 1,
        ..RankConfig::default()
    };
    // No core set — ranking alone decides. The query strongly favors "search the repository source
    // code for a function" (search_code) over the other two, which share none of its terms.
    let admitted = register_plannable_mcp_tools_ranked(
        &mut reg,
        mcp,
        auth,
        "alice",
        &plannable,
        "search the code repository for a function definition",
        &CoreSet::new(Vec::<String>::new()),
        &[],
        config,
    );

    assert_eq!(
        admitted,
        vec![McpRegistry::qualify(GIT_SERVER_URL, "search_code")],
        "only the top-1 ranked tool must be registered, not all 3 discovered/pinned tools"
    );

    // The two lower-ranked tools were never registered — the registry, not just a display list,
    // refuses them as unknown (they cannot be dispatched, exactly as an unregistered native tool).
    assert!(matches!(
        reg.dispatch(&McpRegistry::qualify(GIT_SERVER_URL, "create_mr"), "{}"),
        DispatchResult::Blocked(_)
    ));
    assert!(matches!(
        reg.dispatch(&McpRegistry::qualify(GIT_SERVER_URL, "send_email"), "{}"),
        DispatchResult::Blocked(_)
    ));
    // The top-ranked tool dispatches through the identical origin-agnostic path.
    assert!(matches!(
        reg.dispatch(
            &McpRegistry::qualify(GIT_SERVER_URL, "search_code"),
            "{\"q\":\"main\"}"
        ),
        DispatchResult::Ok(_)
    ));
}

#[test]
fn the_core_set_is_always_registered_regardless_of_ranking() {
    let (mcp, auth, plannable) = discover_three_tools();

    let mut reg =
        CapabilityRegistry::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler));
    // Zero ranked-tail budget (k=0): NOTHING would be admitted by ranking alone. "send_email" is
    // pinned into the always-visible core set despite scoring 0 against a query that shares none of
    // its terms — proving the core set bypasses ranking entirely, as §2.4 requires.
    let config = RankConfig {
        k: 0,
        ..RankConfig::default()
    };
    let core = CoreSet::new([McpRegistry::qualify(GIT_SERVER_URL, "send_email")]);
    let admitted = register_plannable_mcp_tools_ranked(
        &mut reg,
        mcp,
        auth,
        "alice",
        &plannable,
        "search the code repository for a function definition",
        &core,
        &[],
        config,
    );

    assert_eq!(
        admitted,
        vec![McpRegistry::qualify(GIT_SERVER_URL, "send_email")],
        "the core-set tool must be admitted even with a zero ranked-tail budget and no query overlap"
    );
    assert!(matches!(
        reg.dispatch(&McpRegistry::qualify(GIT_SERVER_URL, "send_email"), "{}"),
        DispatchResult::Ok(_)
    ));
}
