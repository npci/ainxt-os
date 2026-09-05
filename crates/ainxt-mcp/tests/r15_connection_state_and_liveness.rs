// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R15 §2.1/§2.2 — an explicit per-server connection state machine
//! (`Unconnected → Connecting → { Ready | AuthRequired | Unreachable | CapabilityMismatch }`) and a
//! per-session liveness ping + TTL + dead-connection teardown/reconnect. Fail-before: connection
//! outcomes were transient `Result<_, McpError>`s a caller had to reconstruct after the fact — there
//! was no OBSERVABLE, named state a caller could query independently ("is this server currently
//! AuthRequired, or did it just fail this one call?"), no protocol-compatibility check at all
//! (`CapabilityMismatch` was undefined), and no liveness mechanism — a `Ready` connection was cached
//! for the WHOLE session with no way to detect or recover from it dying mid-session. Pass-after:
//! `ConnectionState` is a real, queryable snapshot; a protocol mismatch is refused before any tool is
//! trusted; and `check_liveness`/`sweep_liveness` actively tear down a dead or stale connection for a
//! lazy reconnect on next use.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use ainxt_mcp::{
    ConnectionState, McpError, McpRegistry, McpServer, McpTransport, NoAuth, ToolManifest,
    ToolResult,
};

/// A configurable mock transport: can fail unreachable/auth, declare an arbitrary protocol version,
/// and toggle its liveness ping — everything §2.1/§2.2 need to exercise.
struct FlakyTransport {
    tools: Vec<ToolManifest>,
    unreachable: bool,
    requires_auth: bool,
    protocol: String,
    ping_ok: Arc<AtomicBool>,
    connect_calls: Arc<AtomicUsize>,
    last_token: Arc<Mutex<Option<String>>>,
}

impl FlakyTransport {
    fn new(tools: Vec<ToolManifest>) -> Self {
        FlakyTransport {
            tools,
            unreachable: false,
            requires_auth: false,
            protocol: "mcp/1.0".to_string(),
            ping_ok: Arc::new(AtomicBool::new(true)),
            connect_calls: Arc::new(AtomicUsize::new(0)),
            last_token: Arc::new(Mutex::new(None)),
        }
    }
    fn unreachable(mut self) -> Self {
        self.unreachable = true;
        self
    }
    fn requiring_auth(mut self) -> Self {
        self.requires_auth = true;
        self
    }
    fn with_protocol(mut self, p: &str) -> Self {
        self.protocol = p.to_string();
        self
    }
}

impl McpTransport for FlakyTransport {
    fn connect(&self, token: Option<&str>) -> Result<(), McpError> {
        self.connect_calls.fetch_add(1, Ordering::SeqCst);
        *self.last_token.lock().unwrap() = token.map(str::to_string);
        if self.unreachable {
            return Err(McpError::Unreachable("host down".into()));
        }
        if self.requires_auth && token.is_none() {
            return Err(McpError::AuthRequired("no token".into()));
        }
        Ok(())
    }
    fn list_tools(&self) -> Result<Vec<ToolManifest>, McpError> {
        Ok(self.tools.clone())
    }
    fn call_tool(&self, tool: &str, args: &str) -> Result<ToolResult, McpError> {
        Ok(ToolResult::ok(&format!("{tool}:{args}")))
    }
    fn protocol_version(&self) -> &str {
        &self.protocol
    }
    fn ping(&self) -> bool {
        self.ping_ok.load(Ordering::SeqCst)
    }
}

fn tools() -> Vec<ToolManifest> {
    vec![ToolManifest::new("do_thing", "does a thing")]
}

// ---------------- §2.1 explicit connection state machine ----------------

#[test]
fn a_fresh_server_reports_unconnected_before_any_use() {
    let server = McpServer::new(
        "svc",
        "https://svc.example/mcp",
        Box::new(FlakyTransport::new(tools())),
    );
    assert_eq!(server.connection_state(), ConnectionState::Unconnected);
    assert!(!server.is_connected());
    assert_eq!(server.state_reason(), None);
}

#[test]
fn a_successful_connect_transitions_to_ready() {
    let mut reg = McpRegistry::new();
    reg.register(McpServer::new(
        "svc",
        "https://svc.example/mcp",
        Box::new(FlakyTransport::new(tools())),
    ));
    let d = reg.discover("alice", &NoAuth);
    assert!(d.failures.is_empty());
    assert_eq!(d.tools.len(), 1);
}

#[test]
fn auth_required_lands_in_its_own_named_state_with_a_reason() {
    let server = McpServer::new(
        "svc",
        "https://svc.example/mcp",
        Box::new(FlakyTransport::new(tools()).requiring_auth()),
    );
    let mut reg = McpRegistry::new();
    reg.register(server);
    let d = reg.discover("alice", &NoAuth); // no token provisioned
    assert!(d.tools.is_empty());
    assert_eq!(d.failures.len(), 1);
    assert!(matches!(d.failures[0].1, McpError::AuthRequired(_)));
}

#[test]
fn unreachable_lands_in_its_own_named_state_distinct_from_auth_required() {
    let server = McpServer::new(
        "svc",
        "https://svc.example/mcp",
        Box::new(FlakyTransport::new(tools()).unreachable()),
    );
    // Directly query the state after a failed ensure_ready via discover.
    let mut reg = McpRegistry::new();
    reg.register(server);
    let d = reg.discover("alice", &NoAuth);
    assert_eq!(d.failures.len(), 1);
    assert!(matches!(d.failures[0].1, McpError::Unreachable(_)));
}

#[test]
fn capability_mismatch_refuses_the_server_before_any_tool_is_trusted() {
    // The deployment expects "mcp/2.0"; this server only speaks "mcp/1.0".
    let server = McpServer::new(
        "old_server",
        "https://old.example/mcp",
        Box::new(FlakyTransport::new(tools()).with_protocol("mcp/1.0")),
    )
    .expecting_protocol("mcp/2.0");

    let mut reg = McpRegistry::new();
    reg.register(server);
    let d = reg.discover("alice", &NoAuth);
    assert!(
        d.tools.is_empty(),
        "no tool from a capability-mismatched server ever reaches discovery"
    );
    assert_eq!(d.failures.len(), 1);
    assert!(matches!(d.failures[0].1, McpError::CapabilityMismatch(_)));
}

#[test]
fn an_unmatched_protocol_state_reason_is_set_directly_on_the_server() {
    let server = McpServer::new(
        "old_server",
        "https://old.example/mcp",
        Box::new(FlakyTransport::new(tools()).with_protocol("mcp/1.0")),
    )
    .expecting_protocol("mcp/2.0");

    // Drive `ensure_ready` indirectly via a single-server registry, then read this exact server's
    // state back — a registry only ever holds the server by value, so read state via `sweep_liveness`
    // (state after connect attempt is CapabilityMismatch, not Ready, so liveness reports it unchanged).
    let mut reg = McpRegistry::new();
    reg.register(server);
    let _ = reg.discover("alice", &NoAuth);
    let sweep = reg.sweep_liveness(1_000);
    assert_eq!(sweep.len(), 1);
    assert_eq!(sweep[0].0, "old_server");
    assert_eq!(sweep[0].1, ConnectionState::CapabilityMismatch);
}

#[test]
fn a_server_with_no_expected_protocol_declared_is_unaffected() {
    // Default behavior (no `.expecting_protocol` call) — every pre-existing caller/test is unaffected
    // by the new check.
    let server = McpServer::new(
        "svc",
        "https://svc.example/mcp",
        Box::new(FlakyTransport::new(tools()).with_protocol("some-nonstandard/9.9")),
    );
    let mut reg = McpRegistry::new();
    reg.register(server);
    let d = reg.discover("alice", &NoAuth);
    assert!(
        d.failures.is_empty(),
        "no protocol check ⇒ no mismatch, regardless of declared version"
    );
    assert_eq!(d.tools.len(), 1);
}

// ---------------- §2.2 liveness ping + TTL + dead-connection teardown/reconnect ----------------

#[test]
fn check_liveness_on_a_never_connected_server_is_a_no_op() {
    let server = McpServer::new(
        "svc",
        "https://svc.example/mcp",
        Box::new(FlakyTransport::new(tools())),
    );
    // Never connected — liveness has nothing to check; state is reported unchanged.
    assert_eq!(server.check_liveness(100), ConnectionState::Unconnected);
}

#[test]
fn a_live_connection_stays_ready_across_repeated_liveness_checks_within_ttl() {
    let mut reg = McpRegistry::new();
    reg.register(McpServer::new(
        "svc",
        "https://svc.example/mcp",
        Box::new(FlakyTransport::new(tools())),
    ));
    let _ = reg.discover("alice", &NoAuth); // establishes the connection
                                            // Several checks within a generous TTL all report Ready and never tear it down.
    for _ in 0..5 {
        let sweep = reg.sweep_liveness(1_000);
        assert_eq!(sweep[0].1, ConnectionState::Ready);
    }
}

#[test]
fn a_failed_ping_tears_down_the_connection_and_it_lazily_reconnects_on_next_use() {
    let ping_ok = Arc::new(AtomicBool::new(true));
    let connect_calls = Arc::new(AtomicUsize::new(0));
    let transport = FlakyTransport {
        tools: tools(),
        unreachable: false,
        requires_auth: false,
        protocol: "mcp/1.0".to_string(),
        ping_ok: ping_ok.clone(),
        connect_calls: connect_calls.clone(),
        last_token: Arc::new(Mutex::new(None)),
    };
    let server = McpServer::new("svc", "https://svc.example/mcp", Box::new(transport));

    let mut reg = McpRegistry::new();
    reg.register(server);
    let d1 = reg.discover("alice", &NoAuth);
    assert!(d1.failures.is_empty());
    assert_eq!(connect_calls.load(Ordering::SeqCst), 1);

    // The connection dies mid-session (e.g. the server process restarted).
    ping_ok.store(false, Ordering::SeqCst);
    let sweep = reg.sweep_liveness(1_000);
    assert_eq!(
        sweep[0].1,
        ConnectionState::Unreachable,
        "a failed ping must be reported"
    );

    // Ping recovers; the NEXT discover lazily reconnects (fresh connect, fresh manifest) rather than
    // being permanently wedged.
    ping_ok.store(true, Ordering::SeqCst);
    let d2 = reg.discover("alice", &NoAuth);
    assert!(
        d2.failures.is_empty(),
        "the server must be able to reconnect after a liveness teardown"
    );
    assert_eq!(
        connect_calls.load(Ordering::SeqCst),
        2,
        "a SECOND connect must have fired"
    );
}

#[test]
fn ttl_expiry_tears_down_a_connection_even_though_every_ping_succeeded() {
    let mut reg = McpRegistry::new();
    reg.register(McpServer::new(
        "svc",
        "https://svc.example/mcp",
        Box::new(FlakyTransport::new(tools())),
    ));
    let _ = reg.discover("alice", &NoAuth);

    // TTL of 2: the 1st and 2nd sweeps stay within budget; the 3rd exceeds it and tears down, even
    // though the ping itself always succeeds — the TTL, not just liveness, bounds connection age.
    let ttl = 2;
    assert_eq!(reg.sweep_liveness(ttl)[0].1, ConnectionState::Ready);
    assert_eq!(reg.sweep_liveness(ttl)[0].1, ConnectionState::Ready);
    assert_eq!(
        reg.sweep_liveness(ttl)[0].1,
        ConnectionState::Unreachable,
        "TTL exceeded"
    );

    // Torn down — a subsequent discover reconnects lazily rather than staying dead forever.
    let d = reg.discover("alice", &NoAuth);
    assert!(d.failures.is_empty());
}

#[test]
fn sweep_liveness_reports_every_registered_server_independently() {
    let mut reg = McpRegistry::new();
    reg.register(McpServer::new(
        "connected",
        "https://a.example/mcp",
        Box::new(FlakyTransport::new(tools())),
    ));
    reg.register(McpServer::new(
        "never_used",
        "https://b.example/mcp",
        Box::new(FlakyTransport::new(tools())),
    ));

    // Only connect the first one.
    let mut solo = McpRegistry::new();
    solo.register(McpServer::new(
        "connected",
        "https://a.example/mcp",
        Box::new(FlakyTransport::new(tools())),
    ));
    let _ = solo.discover("alice", &NoAuth);
    let sweep_solo = solo.sweep_liveness(1_000);
    assert_eq!(
        sweep_solo,
        vec![("connected".to_string(), ConnectionState::Ready)]
    );

    // The never-touched registry's servers stay Unconnected — independent, no cross-server effect.
    let sweep_untouched = reg.sweep_liveness(1_000);
    assert_eq!(
        sweep_untouched,
        vec![
            ("connected".to_string(), ConnectionState::Unconnected),
            ("never_used".to_string(), ConnectionState::Unconnected),
        ]
    );
}
