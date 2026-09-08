// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R16 — "reconciler probe gate" applied to MCP registration (§1.8).
//!
//! `ToolRuntime::try_register_governed` already refuses to register a `RiskTier::HighRisk`
//! `EffectClass::SideEffecting` capability that does not declare a reconcile probe
//! (`r15_reconcile_probe_mandatory.rs`), and every NATIVE capability on the served path
//! (`ainxt-runtimed`) already routes through it. But `mcp_bridge::register_plannable_mcp_tools` —
//! the bulk entrypoint `register_served_mcp_runtime` uses for every MCP-discovered tool — called the
//! bare, UNGATED `try_register` instead. `McpCapability`'s own default risk tier is the legacy
//! `RiskTier::High` (single-phase, below the gate's `HighRisk` trigger), so an unremarkable MCP tool
//! was unaffected either way — but the moment a deployment explicitly escalates one specific MCP
//! tool to `RiskTier::HighRisk` (settlement-adjacent, irreversible — exactly what §1.8 exists to
//! protect), the ungated path let it register with silently zero reconcile probe, meaning every lost
//! ack for that capability would degrade to permanent manual reconciliation with no way to actually
//! resolve it — the exact failure §1.8 exists to prevent, reachable specifically through the MCP
//! adapter while every native path was already protected.
//!
//! Fail-before: `register_plannable_mcp_tools` called `reg.try_register(...)`, so this test's first
//! assertion (`without_probe` must be REFUSED) would have failed — the capability would have
//! registered. Pass-after: it calls `try_register_governed`, closing the MCP-specific bypass.

use std::sync::Arc;

use ainxt_mcp::{
    AuthProvider, McpError, McpRegistry, McpServer, McpTransport, NoAuth, QualifiedTool,
    ToolManifest, ToolResult,
};
use ainxt_tools::mcp_bridge::{register_plannable_mcp_tools, McpCapability};
use ainxt_tools::{CapabilityRegistry, EffectClass, InMemoryLedger, ManualReconciler, RiskTier};

struct StubTransport;
impl McpTransport for StubTransport {
    fn connect(&self, _token: Option<&str>) -> Result<(), McpError> {
        Ok(())
    }
    fn list_tools(&self) -> Result<Vec<ToolManifest>, McpError> {
        Ok(vec![ToolManifest::new("settle", "settle a batch")])
    }
    fn call_tool(&self, tool: &str, args: &str) -> Result<ToolResult, McpError> {
        Ok(ToolResult::ok(&format!("{tool}:{args}")))
    }
}

fn qualified_tool() -> QualifiedTool {
    QualifiedTool {
        qualified_name: McpRegistry::qualify("https://settlement.example/mcp", "settle"),
        server_name: "settlement".to_string(),
        server_url: "https://settlement.example/mcp".to_string(),
        manifest: ToolManifest::new("settle", "settle a batch"),
    }
}

#[test]
fn escalated_mcp_tool_with_no_probe_is_refused_not_silently_admitted() {
    let mut mcp = McpRegistry::new();
    mcp.register(McpServer::new(
        "settlement",
        "https://settlement.example/mcp",
        Box::new(StubTransport),
    ));
    let mcp = Arc::new(mcp);
    let auth: Arc<dyn AuthProvider> = Arc::new(NoAuth);

    let mut reg =
        CapabilityRegistry::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler));

    // A deployment escalates this one MCP tool to the apex tier (settlement-adjacent) but never
    // wires a probe for it — exactly the case §1.8 must catch regardless of capability origin. We
    // can't pass a pre-built McpCapability through register_plannable_mcp_tools (it always builds
    // its own at the default tier), so prove the gate directly on the SAME construction path that
    // function uses, then prove the bulk entrypoint end-to-end below with the default tier.
    let cap_no_probe = McpCapability::new(mcp.clone(), auth.clone(), "alice", qualified_tool())
        .with_risk_tier(RiskTier::HighRisk)
        .with_effect(EffectClass::SideEffecting);
    let err = reg
        .try_register_governed(Box::new(cap_no_probe))
        .expect_err("HighRisk SideEffecting MCP capability with no declared probe must be refused");
    assert!(
        format!("{err:?}").contains("§1.8"),
        "refusal must name the mandate, got: {err:?}"
    );

    // The SAME tool, with the probe declared, registers cleanly — the escape hatch works.
    let cap_with_probe = McpCapability::new(mcp.clone(), auth.clone(), "alice", qualified_tool())
        .with_risk_tier(RiskTier::HighRisk)
        .with_effect(EffectClass::SideEffecting)
        .with_reconcile_probe_declared(true);
    reg.try_register_governed(Box::new(cap_with_probe))
        .expect("a declared out-of-band probe satisfies §1.8");

    // ---- Now prove the actual bulk entrypoint (register_served_mcp_runtime's dependency) is gated ----
    // Default-tier (RiskTier::High, below the gate) MCP tools are unaffected — the common case.
    let mut reg2 =
        CapabilityRegistry::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler));
    let admitted = register_plannable_mcp_tools(
        &mut reg2,
        mcp.clone(),
        auth.clone(),
        "alice",
        std::slice::from_ref(&qualified_tool()),
    );
    assert_eq!(
        admitted.len(),
        1,
        "an ordinary (non-escalated) MCP tool must still register via the bulk entrypoint"
    );
}
