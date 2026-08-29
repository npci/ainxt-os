// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! r10_mcp_runtime_into_unified_registry — the MCP runtime registers its discovered tools into the
//! ONE unified Capability registry (§0), so an MCP tool dispatches through the identical path as a
//! native one.
//!
//! `r3_one_capability_registry` proves a *single* hand-built `McpCapability` co-registers with a
//! native + plugin tool. THIS test closes the remaining seam: the bulk entrypoint the served engine
//! hot-wires (runtimed→needs_hot_wiring) — take a REAL `ainxt_mcp::McpRegistry`, run its full
//! TOFU-pinned discovery, and register the *whole* plannable set into the shared
//! `CapabilityRegistry` in one call — then prove every registered MCP tool dispatches through the
//! same origin-agnostic path, including the exactly-once ledger dedup, with nothing branching on
//! origin.
//!
//! Fail-before: there was no bulk registration entrypoint from an `McpRegistry` discovery into the
//! Capability registry (`mcp_bridge::register_plannable_mcp_tools` did not exist), so this test
//! would not compile — the served engine had no clean way to admit a discovered MCP tool set.
//! Pass-after: `register_plannable_mcp_tools` adapts each plannable `QualifiedTool` into an
//! `McpCapability` and registers it, and each dispatches identically to a native capability.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use ainxt_tools::mcp_bridge::register_plannable_mcp_tools;
use ainxt_tools::{CapabilityRegistry, DispatchResult, InMemoryLedger, ManualReconciler};

use ainxt_mcp::{
    AuthProvider, InMemoryPinStore, McpError, McpRegistry, McpServer, McpTransport, NoAuth,
    ToolManifest, ToolResult,
};

/// A real (in-memory, network-free) MCP transport exposing two tools and counting invocations, so
/// we can prove exactly-once dispatch per logical call.
struct CountingTransport {
    create_calls: Arc<AtomicUsize>,
    search_calls: Arc<AtomicUsize>,
}
impl McpTransport for CountingTransport {
    fn connect(&self, _token: Option<&str>) -> Result<(), McpError> {
        Ok(())
    }
    fn list_tools(&self) -> Result<Vec<ToolManifest>, McpError> {
        Ok(vec![
            ToolManifest::new("create_mr", "open a merge request in gitlab from a branch"),
            ToolManifest::new("search_code", "search the repository source code"),
        ])
    }
    fn call_tool(&self, tool: &str, args: &str) -> Result<ToolResult, McpError> {
        match tool {
            "create_mr" => self.create_calls.fetch_add(1, Ordering::SeqCst),
            "search_code" => self.search_calls.fetch_add(1, Ordering::SeqCst),
            _ => 0,
        };
        Ok(ToolResult::ok(&format!("mcp:{tool}:{args}")))
    }
}

#[test]
fn r10_mcp_runtime_into_unified_registry() {
    let create_calls = Arc::new(AtomicUsize::new(0));
    let search_calls = Arc::new(AtomicUsize::new(0));

    // ---- Build the real MCP runtime and run its TOFU-pinned discovery ----
    let mut mcp = McpRegistry::new();
    mcp.register(McpServer::new(
        "git",
        "https://git.example/mcp",
        Box::new(CountingTransport {
            create_calls: create_calls.clone(),
            search_calls: search_calls.clone(),
        }),
    ));
    let mcp = Arc::new(mcp);
    let auth: Arc<dyn AuthProvider> = Arc::new(NoAuth);
    let pins = InMemoryPinStore::new();

    // First discovery = trust-on-first-use: nothing is plannable until a human approves. This is the
    // safety invariant the bulk-register entrypoint relies on (it only ever sees vetted tools).
    let d1 = mcp.discover_pinned("alice", auth.as_ref(), &pins);
    assert!(
        d1.plannable().is_empty(),
        "TOFU: nothing plannable before approval"
    );
    assert_eq!(d1.needs_reapproval().len(), 1);

    // A human approves the shown manifest, then re-discovery yields the pinned-and-unchanged set.
    d1.servers[0].approve(&pins, "alice", 1);
    let d2 = mcp.discover_pinned("alice", auth.as_ref(), &pins);
    let plannable = d2.plannable();
    assert_eq!(plannable.len(), 2, "both tools plannable after approval");

    // ---- Bulk-register the whole plannable set into the ONE unified Capability registry ----
    let mut reg =
        CapabilityRegistry::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler));
    let admitted =
        register_plannable_mcp_tools(&mut reg, mcp.clone(), auth.clone(), "alice", &plannable);
    assert_eq!(admitted.len(), 2, "both MCP tools admitted");
    let git_create = McpRegistry::qualify("https://git.example/mcp", "create_mr");
    let git_search = McpRegistry::qualify("https://git.example/mcp", "search_code");
    assert!(admitted.contains(&git_create));
    assert!(admitted.contains(&git_search));

    // They appear in the unified manifest exactly like native tools.
    let names: Vec<String> = reg.schemas().into_iter().map(|s| s.name).collect();
    assert!(names.contains(&git_create));
    assert!(names.contains(&git_search));

    // The registry classifies them uniformly (the seams the injection taint-gate + egress DLP key
    // on — no origin branch): egressing + side-effecting.
    assert_eq!(reg.egress_of(&git_create), Some(true));
    assert_eq!(reg.is_side_effecting(&git_search), Some(true));

    // ---- One dispatch path: each MCP tool executes AND is deduped by the SAME ledger ----
    match reg.dispatch(&git_create, "{\"branch\":\"x\"}") {
        DispatchResult::Ok(r) => assert_eq!(r, "mcp:create_mr:{\"branch\":\"x\"}"),
        other => panic!("expected Ok from bulk-registered MCP tool, got {other:?}"),
    }
    // A byte-identical retry (lost-ack) is deduped, not re-executed — exactly-once through the
    // shared ledger, identical to a native capability.
    assert!(matches!(
        reg.dispatch(&git_create, "{\"branch\":\"x\"}"),
        DispatchResult::Deduped(_)
    ));
    // A reordered/reformatted retry is the SAME logical call → still deduped (canonical key).
    assert!(matches!(
        reg.dispatch(&git_create, "{ \"branch\" : \"x\" }"),
        DispatchResult::Deduped(_)
    ));
    assert_eq!(
        create_calls.load(Ordering::SeqCst),
        1,
        "create_mr executed exactly once across retries via the shared ledger"
    );

    // The second tool dispatches through the identical path, independently deduped.
    assert!(matches!(
        reg.dispatch(&git_search, "{\"q\":\"fn main\"}"),
        DispatchResult::Ok(_)
    ));
    assert!(matches!(
        reg.dispatch(&git_search, "{\"q\":\"fn main\"}"),
        DispatchResult::Deduped(_)
    ));
    assert_eq!(
        search_calls.load(Ordering::SeqCst),
        1,
        "search_code exactly-once"
    );

    // An unknown MCP-qualified tool that was NOT registered is refused by the unified path — the
    // registry never guesses (parity with native unknown-tool handling).
    assert!(matches!(
        reg.dispatch(
            &McpRegistry::qualify("https://git.example/mcp", "delete_everything"),
            "{}"
        ),
        DispatchResult::Blocked(_)
    ));
}
