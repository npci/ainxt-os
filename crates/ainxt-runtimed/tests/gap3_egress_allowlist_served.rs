// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-AUDIT tooling-mcp-plugins-routing — "Egress destination allow-list never wired — not
//! fail-closed". `ToolRuntime::with_egress_allowlist` (`ainxt-tools/src/lib.rs`) was a fully
//! implemented and unit-tested (§1.7) builder method, proven end-to-end against an `McpCapability`
//! in `r16_egress_allowlist_wired.rs` — but that test built its OWN `CapabilityRegistry` by hand and
//! called `.with_egress_allowlist(...)` itself. The REAL served composition root,
//! `ainxt_runtimed::build_unified_capability_registry_shared` (the exact function `build_engine_ext`
//! calls, which is what every served turn dispatches through), never called it: the daemon's default
//! `egress_allowlist` field stayed `None`, so `execute_dispatch_core`'s §1.7 check block was SKIPPED
//! ENTIRELY for every capability the served engine ever registered — including every `McpCapability`,
//! which always egresses to its server's host. Not fail-closed; the mechanism simply never ran.
//!
//! Fail-before (pre-fix): dispatching an MCP capability registered into the SAME served registry
//! `build_unified_capability_registry_shared` returns would `Ok(..)` unconditionally — the egress
//! destination was never even inspected, no matter how untrusted. Pass-after: the served composition
//! root now installs a conservative empty default `EgressAllowList` (deny-by-omission per §1.7), so
//! the exact same dispatch is `Blocked` pending approval — fail-closed by default, not skipped.

use std::sync::Arc;

use ainxt_mcp::{
    AuthProvider, InMemoryPinStore, McpError, McpRegistry, McpServer, McpTransport, NoAuth,
    ToolManifest, ToolResult,
};
use ainxt_runtimed::{build_unified_capability_registry_shared, register_served_mcp_runtime};
use ainxt_tools::DispatchResult;

/// A deterministic, network-free MCP transport exposing one read-only tool — same shape as
/// `r10_served_gaps.rs`'s `FakeTransport`, kept local so this file has no cross-test dependency.
struct FakeTransport;
impl McpTransport for FakeTransport {
    fn connect(&self, _token: Option<&str>) -> Result<(), McpError> {
        Ok(())
    }
    fn list_tools(&self) -> Result<Vec<ToolManifest>, McpError> {
        Ok(vec![ToolManifest::new("post", "post a message off-box")])
    }
    fn call_tool(&self, tool: &str, args: &str) -> Result<ToolResult, McpError> {
        // If this is ever reached in the fail-before scenario, the call must be observably
        // distinguishable from a `Blocked` refusal.
        Ok(ToolResult::ok(&format!("{tool}:{args}")))
    }
}

/// Register a real (in-memory) MCP server into a fresh `McpRegistry`, TOFU-approve it, and admit its
/// tools into `registry` through the SAME runtimed-level wire the daemon uses
/// (`register_served_mcp_runtime`) — returns the qualified tool name to dispatch.
fn admit_mcp_tool(registry: &mut ainxt_tools::ToolRuntime, server_url: &str) -> String {
    let mut mcp = McpRegistry::new();
    mcp.register(McpServer::new("chat", server_url, Box::new(FakeTransport)));
    let mcp = Arc::new(mcp);
    let auth: Arc<dyn AuthProvider> = Arc::new(NoAuth);
    let pins = InMemoryPinStore::new();
    // TOFU: first discovery is quarantined; approve it so it becomes plannable, mirroring exactly
    // what `register_served_mcp_runtime`'s own doc says a deployment does after first use.
    let d1 = mcp.discover_pinned("alice", auth.as_ref(), &pins);
    assert!(
        d1.plannable().is_empty(),
        "TOFU: nothing plannable before approval"
    );
    d1.servers[0].approve(&pins, "alice", 1);

    let admitted = register_served_mcp_runtime(registry, mcp, auth, &pins, "alice");
    let qualified_name = McpRegistry::qualify(server_url, "post");
    assert!(
        admitted.contains(&qualified_name),
        "the MCP tool must register into the served unified registry: {admitted:?}"
    );
    qualified_name
}

#[test]
fn served_registry_fails_closed_on_unlisted_mcp_egress_by_default() {
    // The EXACT served composition-root function — not a hand-assembled registry.
    let mut report = Vec::new();
    let (mut registry, _ledger, _reconciler) =
        build_unified_capability_registry_shared(&mut report);

    let qualified_name = admit_mcp_tool(&mut registry, "https://untrusted.example/mcp");

    // Dispatch through the SAME `ToolRuntime::dispatch` every served turn uses.
    match registry.dispatch(&qualified_name, "{\"text\":\"hi\"}") {
        DispatchResult::Blocked(msg) => {
            assert!(
                msg.contains("§1.7") && msg.contains("untrusted.example"),
                "must name the §1.7 mandate and the refused destination, got: {msg}"
            );
        }
        other => panic!(
            "the served registry's default egress allow-list must fail-closed on an unlisted \
             MCP destination (previously this dispatched unconditionally): {other:?}"
        ),
    }
}

#[test]
fn served_registry_is_the_same_default_across_two_independent_builds() {
    // Determinism / no hidden per-process state: two fresh calls to the real composition-root
    // function both fail-closed on the same unlisted destination, proving the allow-list is a
    // property of the composition function itself, not of test ordering or a shared static.
    for _ in 0..2 {
        let mut report = Vec::new();
        let (mut registry, _ledger, _reconciler) =
            build_unified_capability_registry_shared(&mut report);
        let qualified_name = admit_mcp_tool(&mut registry, "https://anywhere.example/mcp");
        match registry.dispatch(&qualified_name, "{}") {
            DispatchResult::Blocked(msg) => assert!(msg.contains("§1.7")),
            other => panic!("expected fail-closed refusal on every fresh build, got {other:?}"),
        }
    }
}

#[test]
fn served_registry_native_query_ledger_capability_is_unaffected() {
    // Additivity check: the built-in native `query_ledger` capability declares no egress
    // (`Tool::egress()` default `false`), so installing the default allow-list must NOT touch it —
    // it should behave exactly as it did before this capability-registry-level default existed.
    let mut report = Vec::new();
    let (registry, _ledger, _reconciler) = build_unified_capability_registry_shared(&mut report);
    let names: Vec<String> = registry.schemas().into_iter().map(|s| s.name).collect();
    assert!(
        names.iter().any(|n| n == "query_ledger"),
        "the served registry ships the native query_ledger capability: {names:?}"
    );
    // A call that never reaches the §1.7 check block (non-egressing tool) must never come back
    // `Blocked` with the egress-refusal message, regardless of whether it succeeds or fails on its
    // own schema/args validation.
    match registry.dispatch("query_ledger", "not valid ledger query args") {
        DispatchResult::Blocked(msg) => assert!(
            !msg.contains("§1.7"),
            "a non-egressing native capability must never be refused by the egress allow-list: {msg}"
        ),
        _ => {}
    }
}
