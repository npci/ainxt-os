// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R16 — "per-capability egress allowlist" (§1.7) wiring.
//!
//! `egress_allowlist::EgressAllowList` (deny-by-omission, per-capability + platform-default
//! destination patterns up to a data-class ceiling) was fully built and unit-tested
//! (`r15_egress_allowlist.rs`) but had ZERO callers anywhere in the workspace — no field on
//! `ToolRuntime`, no call from `execute_dispatch`/`execute_dispatch_core`. A capability's egress
//! payload was scanned for CONTENT (DLP) via a completely separate path in `ainxt-connector-http`,
//! but nothing gated the DESTINATION itself against a per-capability allow-list — the literal §1.7
//! mechanism the design names existed and was simply never reached.
//!
//! This closes that: `ToolRuntime::with_egress_allowlist` installs one, and `execute_dispatch_core`
//! checks it BEFORE any lock/ledger claim for any tool that both egresses AND can name a destination
//! (`Tool::destination`, new, additive, default `None`). `McpCapability` — the one adapter that
//! ALWAYS egresses to a well-known place (the MCP server's URL) — now names it, so a real MCP
//! capability is genuinely gated end-to-end, not just the standalone module in isolation.
//!
//! Fail-before: `ToolRuntime` had no `with_egress_allowlist` method and `Tool` had no `destination`
//! method, so this file would not compile. Pass-after: an MCP capability whose server URL is not on
//! the allow-list is refused before it ever reaches the wire; one that IS listed dispatches exactly
//! as before, so the change is additive, not a behavior change for every existing capability.

use std::sync::Arc;

use ainxt_mcp::{
    AuthProvider, McpError, McpRegistry, McpServer, McpTransport, NoAuth, QualifiedTool,
    ToolManifest, ToolResult,
};
use ainxt_tools::egress_allowlist::EgressAllowList;
use ainxt_tools::mcp_bridge::McpCapability;
use ainxt_tools::{
    CapabilityRegistry, DispatchResult, EffectClass, InMemoryLedger, ManualReconciler,
};
use ainxt_types::DataClass;

struct EchoTransport;
impl McpTransport for EchoTransport {
    fn connect(&self, _token: Option<&str>) -> Result<(), McpError> {
        Ok(())
    }
    fn list_tools(&self) -> Result<Vec<ToolManifest>, McpError> {
        Ok(vec![ToolManifest::new("post", "post a message")])
    }
    fn call_tool(&self, tool: &str, args: &str) -> Result<ToolResult, McpError> {
        Ok(ToolResult::ok(&format!("{tool}:{args}")))
    }
}

fn build(server_url: &str) -> (Arc<McpRegistry>, Arc<dyn AuthProvider>, QualifiedTool) {
    let mut mcp = McpRegistry::new();
    mcp.register(McpServer::new("chat", server_url, Box::new(EchoTransport)));
    let qualified = QualifiedTool {
        qualified_name: McpRegistry::qualify(server_url, "post"),
        server_name: "chat".to_string(),
        server_url: server_url.to_string(),
        manifest: ToolManifest::new("post", "post a message"),
    };
    (Arc::new(mcp), Arc::new(NoAuth), qualified)
}

#[test]
fn mcp_capability_to_an_unlisted_destination_is_refused_before_the_wire() {
    let (mcp, auth, qualified) = build("https://untrusted.example/mcp");
    let qualified_name = qualified.qualified_name.clone();
    let cap =
        McpCapability::new(mcp, auth, "alice", qualified).with_effect(EffectClass::Idempotent); // single-phase path, isolates the egress check itself

    let allowlist =
        EgressAllowList::new().allow_default("*.internal.example", DataClass::Confidential);
    let mut reg =
        CapabilityRegistry::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler))
            .with_egress_allowlist(allowlist);
    reg.try_register(Box::new(cap)).expect("registers");

    match reg.dispatch(&qualified_name, "{}") {
        DispatchResult::Blocked(msg) => assert!(
            msg.contains("§1.7") && msg.contains("untrusted.example"),
            "must name the mandate and the refused destination, got: {msg}"
        ),
        other => panic!("expected the unlisted destination to be refused, got {other:?}"),
    }
}

#[test]
fn mcp_capability_to_an_allow_listed_destination_dispatches_normally() {
    let (mcp, auth, qualified) = build("https://chat.internal.example/mcp");
    let qualified_name = qualified.qualified_name.clone();
    let cap =
        McpCapability::new(mcp, auth, "alice", qualified).with_effect(EffectClass::Idempotent);

    let allowlist =
        EgressAllowList::new().allow_default("*.internal.example", DataClass::Confidential);
    let mut reg =
        CapabilityRegistry::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler))
            .with_egress_allowlist(allowlist);
    reg.try_register(Box::new(cap)).expect("registers");

    match reg.dispatch(&qualified_name, "{\"text\":\"hi\"}") {
        DispatchResult::Ok(r) => assert_eq!(r, "post:{\"text\":\"hi\"}"),
        other => panic!("allow-listed destination must dispatch normally, got {other:?}"),
    }
}

#[test]
fn no_allowlist_installed_is_byte_identical_to_before_this_feature_existed() {
    let (mcp, auth, qualified) = build("https://anywhere.example/mcp");
    let qualified_name = qualified.qualified_name.clone();
    let cap =
        McpCapability::new(mcp, auth, "alice", qualified).with_effect(EffectClass::Idempotent);

    // No .with_egress_allowlist(...) call at all — the default `None` passthrough.
    let mut reg =
        CapabilityRegistry::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler));
    reg.try_register(Box::new(cap)).expect("registers");

    match reg.dispatch(&qualified_name, "{}") {
        DispatchResult::Ok(_) => {}
        other => panic!("with no allow-list installed, dispatch must be unaffected, got {other:?}"),
    }
}
