// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-AUDIT tooling-mcp-plugins-routing — `McpRegistry::sweep_liveness`/`McpServer::check_liveness`
//! (§2.2 ping + TTL dead-connection teardown, fully implemented and unit-tested in `ainxt-mcp`) had
//! zero callers anywhere in the served composition root. `register_served_mcp_runtime`'s discovery
//! path (`discover_pinned` → `discover` → `ensure_ready`) only ever asks "is this server already
//! `Ready`?" and returns the CACHED manifest if so — it never re-validates the connection. So once a
//! transport died mid-session, the served path would keep reporting the stale `Ready` cache forever,
//! never attempting a reconnect. Proves the fix: a served turn's registration call now sweeps
//! liveness first, so a dead transport is torn down and the SAME call's discovery lazily reconnects.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use ainxt_mcp::{
    InMemoryPinStore, McpError, McpRegistry, McpServer, McpTransport, NoAuth, ToolManifest,
    ToolResult,
};
use ainxt_runtimed::register_served_mcp_runtime;
use ainxt_tools::ToolRuntime;

/// A transport whose liveness ping can be toggled dead, counting real reconnect attempts.
struct FlakyPingTransport {
    ping_ok: Arc<AtomicBool>,
    connect_calls: Arc<AtomicUsize>,
}
impl McpTransport for FlakyPingTransport {
    fn connect(&self, _token: Option<&str>) -> Result<(), McpError> {
        self.connect_calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn list_tools(&self) -> Result<Vec<ToolManifest>, McpError> {
        Ok(vec![ToolManifest::new("search", "search issues")])
    }
    fn call_tool(&self, _tool: &str, _args: &str) -> Result<ToolResult, McpError> {
        unreachable!("not exercised by this test")
    }
    fn ping(&self) -> bool {
        self.ping_ok.load(Ordering::SeqCst)
    }
}

#[test]
fn r_served_registration_sweeps_liveness_and_reconnects_a_dead_server() {
    let ping_ok = Arc::new(AtomicBool::new(true));
    let connect_calls = Arc::new(AtomicUsize::new(0));
    let server = McpServer::new(
        "jira",
        "https://jira.example/mcp",
        Box::new(FlakyPingTransport {
            ping_ok: ping_ok.clone(),
            connect_calls: connect_calls.clone(),
        }),
    );
    let mut reg = McpRegistry::new();
    reg.register(server);
    let mcp = Arc::new(reg);
    let auth = Arc::new(NoAuth) as Arc<dyn ainxt_mcp::AuthProvider>;
    let pins = InMemoryPinStore::new();
    // Pre-approve so the tool is plannable from the first turn (TOFU quarantine is a separate gap).
    {
        let d = mcp.discover_pinned("alice", auth.as_ref(), &pins);
        for id in d.needs_reapproval() {
            ainxt_runtimed::approve_mcp_pin(id, &pins, "alice", 0);
        }
    }

    let mut registry = ToolRuntime::new(
        Box::new(ainxt_tools::InMemoryLedger::new()),
        Box::new(ainxt_tools::ManualReconciler),
    );
    let admitted1 =
        register_served_mcp_runtime(&mut registry, mcp.clone(), auth.clone(), &pins, "alice");
    assert_eq!(
        admitted1.len(),
        1,
        "the server's tool must be admitted on first use"
    );
    assert_eq!(
        connect_calls.load(Ordering::SeqCst),
        1,
        "exactly one real connect so far"
    );

    // The transport goes dark (its liveness ping now fails) — simulates a died mid-session
    // connection, the exact bug scenario ("a server whose transport died after first use").
    ping_ok.store(false, Ordering::SeqCst);

    let mut registry2 = ToolRuntime::new(
        Box::new(ainxt_tools::InMemoryLedger::new()),
        Box::new(ainxt_tools::ManualReconciler),
    );
    let admitted2 =
        register_served_mcp_runtime(&mut registry2, mcp.clone(), auth.clone(), &pins, "alice");

    // FAIL-BEFORE (documents the bug this closes): without the sweep, `ensure_ready` never
    // re-validates a cached `Ready` state, so `connect_calls` would stay at 1 forever and the dead
    // connection would keep reporting `Ready` off the stale cache.
    assert_eq!(
        connect_calls.load(Ordering::SeqCst),
        2,
        "the liveness sweep must tear down the dead connection so THIS turn's discovery lazily \
         reconnects — a real second connect() attempt, not a trust of the stale Ready cache"
    );
    // The reconnect attempt itself succeeds (connect() is infallible here; only ping() is flaky),
    // so the tool is still plannable — the sweep causes a reconnect, not a spurious outage.
    assert_eq!(
        admitted2.len(),
        1,
        "a successful reconnect must still admit the tool"
    );
}
