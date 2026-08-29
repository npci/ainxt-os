// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! r3_one_capability_registry — one Capability trait / one CapabilityRegistry across
//! native + MCP + plugin (§0, the one-registry principle).
//!
//! Fail-before: `ainxt_mcp::McpRegistry`/`QualifiedTool` and `ainxt_plugin` capabilities were
//! referenced by nothing in the tool runtime; there was no way to register an MCP-discovered tool
//! or a plugin export into the single `ToolRuntime`, so the adapter types below did not exist and
//! this test could not compile. Pass-after: a native fn, an MCP tool (adapted via
//! `mcp_bridge::McpCapability` over the REAL `ainxt_mcp::McpRegistry`), and a plugin export
//! (adapted via `plugin_bridge::PluginCapability` over the REAL `ainxt_plugin::NativeHost`) all
//! register into ONE `CapabilityRegistry` and dispatch through the identical path — including the
//! same exactly-once ledger dedup — with nothing downstream branching on origin.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use ainxt_tools::mcp_bridge::McpCapability;
use ainxt_tools::plugin_bridge::PluginCapability;
use ainxt_tools::{
    CapabilityRegistry, DispatchResult, EffectClass, InMemoryLedger, ManualReconciler, Tool,
    ToolError,
};

use ainxt_mcp::{
    AuthProvider, McpError, McpRegistry, McpServer, McpTransport, NoAuth, QualifiedTool,
    ToolManifest, ToolResult,
};
use ainxt_plugin::{NativeHost, PluginGrant, PluginManifest};

// ---- A native side-effecting capability ----
struct NativeWrite {
    calls: Arc<AtomicUsize>,
}
impl Tool for NativeWrite {
    fn name(&self) -> &str {
        "native_write"
    }
    fn effect_class(&self) -> EffectClass {
        EffectClass::SideEffecting
    }
    fn idempotency_key(&self, args: &str) -> Option<String> {
        Some(format!("native_write:{args}"))
    }
    fn execute(&self, args: &str) -> Result<String, ToolError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(format!("native:{args}"))
    }
}

// ---- A real (in-memory, network-free) MCP transport counting its invocations ----
struct CountingTransport {
    calls: Arc<AtomicUsize>,
}
impl McpTransport for CountingTransport {
    fn connect(&self, _token: Option<&str>) -> Result<(), McpError> {
        Ok(())
    }
    fn list_tools(&self) -> Result<Vec<ToolManifest>, McpError> {
        Ok(vec![ToolManifest::new("create_mr", "open a merge request")])
    }
    fn call_tool(&self, tool: &str, args: &str) -> Result<ToolResult, McpError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(ToolResult::ok(&format!("mcp:{tool}:{args}")))
    }
}

#[test]
fn r3_one_capability_registry() {
    let native_calls = Arc::new(AtomicUsize::new(0));
    let mcp_calls = Arc::new(AtomicUsize::new(0));
    let plugin_calls = Arc::new(AtomicUsize::new(0));

    // ---------- Build the ONE registry (aliased as CapabilityRegistry per §0) ----------
    let mut reg =
        CapabilityRegistry::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler));

    // (a) native origin
    reg.register(Box::new(NativeWrite {
        calls: native_calls.clone(),
    }));

    // (b) MCP origin — the real ainxt_mcp::McpRegistry, adapted into a Tool.
    let mut mcp = McpRegistry::new();
    mcp.register(McpServer::new(
        "git",
        "https://git.example/mcp",
        Box::new(CountingTransport {
            calls: mcp_calls.clone(),
        }),
    ));
    let mcp = Arc::new(mcp);
    let auth: Arc<dyn AuthProvider> = Arc::new(NoAuth);
    let qualified = QualifiedTool {
        // Namespaced on the server URL (§2.5), never the display name — must match how the real
        // `McpRegistry::call` resolves it, or dispatch would 404 against its own fixture.
        qualified_name: McpRegistry::qualify("https://git.example/mcp", "create_mr"),
        server_name: "git".to_string(),
        server_url: "https://git.example/mcp".to_string(),
        manifest: ToolManifest::new("create_mr", "open a merge request"),
    };
    let git_create_mr = qualified.qualified_name.clone();
    reg.register(Box::new(McpCapability::new(
        mcp.clone(),
        auth,
        "alice",
        qualified,
    )));

    // (c) plugin origin — the real ainxt_plugin::NativeHost, adapted into a Tool.
    let mut host = NativeHost::new();
    let pc = plugin_calls.clone();
    host.register(
        "reformat",
        Box::new(move |input: &str, _ctx| {
            pc.fetch_add(1, Ordering::SeqCst);
            Ok(format!("plugin:{input}"))
        }),
    );
    let host: Arc<dyn ainxt_plugin::PluginHost + Send + Sync> = Arc::new(host);
    reg.register(Box::new(PluginCapability::new(
        host,
        PluginManifest {
            id: "reformat".into(),
            requested_capabilities: vec![],
            limits: Default::default(),
        },
        PluginGrant::default(),
    )));

    // ---------- One manifest: all three origins appear identically ----------
    let names: Vec<String> = reg.schemas().into_iter().map(|s| s.name).collect();
    assert!(names.contains(&"native_write".to_string()));
    assert!(names.contains(&git_create_mr));
    assert!(names.contains(&"reformat".to_string()));

    // ---------- One dispatch path: each origin executes AND is deduped by the SAME ledger ----------

    // native
    assert!(matches!(
        reg.dispatch("native_write", "{\"a\":1}"),
        DispatchResult::Ok(_)
    ));
    assert!(matches!(
        reg.dispatch("native_write", "{\"a\":1}"),
        DispatchResult::Deduped(_)
    ));
    assert_eq!(
        native_calls.load(Ordering::SeqCst),
        1,
        "native exactly-once"
    );

    // MCP — same exactly-once treatment, proving no origin branch.
    match reg.dispatch(&git_create_mr, "{\"branch\":\"x\"}") {
        DispatchResult::Ok(r) => assert_eq!(r, "mcp:create_mr:{\"branch\":\"x\"}"),
        other => panic!("expected Ok from MCP capability, got {other:?}"),
    }
    assert!(matches!(
        reg.dispatch(&git_create_mr, "{\"branch\":\"x\"}"),
        DispatchResult::Deduped(_)
    ));
    assert_eq!(
        mcp_calls.load(Ordering::SeqCst),
        1,
        "MCP exactly-once via the shared ledger"
    );

    // plugin — same exactly-once treatment.
    match reg.dispatch("reformat", "hello") {
        DispatchResult::Ok(r) => assert_eq!(r, "plugin:hello"),
        other => panic!("expected Ok from plugin capability, got {other:?}"),
    }
    assert!(matches!(
        reg.dispatch("reformat", "hello"),
        DispatchResult::Deduped(_)
    ));
    assert_eq!(
        plugin_calls.load(Ordering::SeqCst),
        1,
        "plugin exactly-once via the shared ledger"
    );

    // The registry reports MCP + plugin as egressing / side-effecting uniformly (used by the
    // injection taint-gate and egress DLP — the same seams, no origin branch).
    assert_eq!(reg.egress_of(&git_create_mr), Some(true));
    assert_eq!(reg.is_side_effecting("reformat"), Some(true));
}
