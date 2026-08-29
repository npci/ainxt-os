// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! r13_mcp_pin_approval — GAP-FIX tooling-mcp-plugins-routing.
//!
//! `ainxt_mcp::PinnedServer::approve` (the TOFU §2.5 re-approval seam) had zero callers anywhere in
//! `ainxt-runtimed`/`ainxt-server` — a first-use or reconnect-diffed MCP server was correctly
//! quarantined (never auto-adopted), but nothing at the composition root could ever grant approval,
//! so a quarantined server would stay quarantined FOREVER on the served path regardless of what a
//! deployment's admin tooling did. `ainxt_runtimed::approve_mcp_pin` is the missing seam.

use ainxt_mcp::{
    InMemoryPinStore, McpError, McpRegistry, McpServer, McpTransport, NoAuth, ToolManifest,
    ToolResult,
};
use ainxt_runtimed::{approve_mcp_pin, mcp_reapproval_report};

/// Minimal offline transport: always connects, lists a fixed tool set, never actually calls one.
struct FixedTransport(Vec<ToolManifest>);
impl McpTransport for FixedTransport {
    fn connect(&self, _token: Option<&str>) -> Result<(), McpError> {
        Ok(())
    }
    fn list_tools(&self) -> Result<Vec<ToolManifest>, McpError> {
        Ok(self.0.clone())
    }
    fn call_tool(&self, _tool: &str, _args: &str) -> Result<ToolResult, McpError> {
        unreachable!("not exercised by this test")
    }
}

#[test]
fn r13_approve_mcp_pin_un_quarantines_a_first_use_server() {
    let server = McpServer::new(
        "jira",
        "https://jira.example/mcp",
        Box::new(FixedTransport(vec![ToolManifest::new(
            "search",
            "search issues",
        )])),
    );
    let mut reg = McpRegistry::new();
    reg.register(server);
    let pins = InMemoryPinStore::new();

    // First discovery: TOFU quarantine — nothing plannable, re-approval required.
    let d1 = reg.discover_pinned("alice", &NoAuth, &pins);
    assert!(
        d1.plannable().is_empty(),
        "a first-use server must start fully quarantined"
    );
    let needs = d1.needs_reapproval();
    assert_eq!(needs.len(), 1, "exactly one server must need re-approval");

    // The composition-root seam: before this fix, nothing could reach this point in ainxt-runtimed.
    approve_mcp_pin(needs[0], &pins, "alice", 42);

    // Next discovery: the approved server is now Unchanged and its tools are plannable.
    let d2 = reg.discover_pinned("alice", &NoAuth, &pins);
    assert!(
        d2.needs_reapproval().is_empty(),
        "the approved server must no longer require re-approval"
    );
    assert_eq!(
        d2.plannable().len(),
        1,
        "the approved server's tool must now be plannable"
    );
}

// GAP-FIX tooling-mcp-plugins-routing — `mcp_reapproval_report` surfaces exactly the quarantine info
// `register_served_mcp_runtime` discovers every turn but previously discarded (only `.plannable()`
// was read off the `PinnedDiscovery`), so an operator had no way to see which servers were stuck
// waiting on a human before this fix.
#[test]
fn r_mcp_reapproval_report_names_a_quarantined_server_then_clears_on_approval() {
    let server = McpServer::new(
        "jira",
        "https://jira.example/mcp",
        Box::new(FixedTransport(vec![ToolManifest::new(
            "search",
            "search issues",
        )])),
    );
    let mut reg = McpRegistry::new();
    reg.register(server);
    let pins = InMemoryPinStore::new();

    let report = mcp_reapproval_report(&reg, &NoAuth, &pins, "alice");
    assert_eq!(
        report.len(),
        1,
        "a first-use server must be named in the reapproval report"
    );
    assert!(
        report[0].contains("jira"),
        "the report names the server: {report:?}"
    );
    assert!(
        report[0].contains("search"),
        "the report names the quarantined tool: {report:?}"
    );

    // Approve through the SAME discovery this report reads.
    let d = reg.discover_pinned("alice", &NoAuth, &pins);
    approve_mcp_pin(d.needs_reapproval()[0], &pins, "alice", 42);

    let cleared = mcp_reapproval_report(&reg, &NoAuth, &pins, "alice");
    assert!(
        cleared.is_empty(),
        "an approved server must no longer appear in the report: {cleared:?}"
    );
}
