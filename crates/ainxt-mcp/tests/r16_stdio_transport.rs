// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R16 — "MCP transport config" gap. §2's own docs mark a live network/process transport a
//! deliberate LATER increment behind the [`ainxt_mcp::McpTransport`] seam, but there was no typed,
//! serializable representation of HOW a deployment reaches a server at all — no
//! `McpServerConfig`/`TransportKind` existed anywhere in the tree (confirmed by grep across the
//! whole workspace), so a harness/control-plane config had nothing to declare per server.
//!
//! This closes that gap for real: [`ainxt_mcp::McpTransportConfig`] is the typed vocabulary
//! (Stdio/StreamableHttp/Sse), and [`ainxt_mcp::McpTransportConfig::spawn`] on a `Stdio` config
//! builds a REAL `JsonRpcStdioTransport` that speaks actual JSON-RPC 2.0 (MCP's real stdio wire
//! format) to a genuinely separate child process — proven end-to-end below by spawning the
//! `mcp_fixture_server` binary (a real, protocol-correct MCP stdio peer built by this same crate for
//! exactly this purpose) via `env!("CARGO_BIN_EXE_mcp_fixture_server")`.
//!
//! A second suite proves the JSON-RPC framing/correlation/error-mapping logic itself (id matching,
//! `error` → `McpError::Transport`, malformed/desynchronized-peer/disconnect handling) over a real
//! duplex Unix socket via `RawIoStdioTransport`, independent of process-spawn cost — the wire logic
//! is the thing actually being proven; the child-process test proves the *production construction
//! path* wires that same logic up correctly.
//!
//! Fail-before: `McpTransportConfig` did not exist, so this file would not compile. Pass-after: a
//! deployment can declare `{"kind":"stdio","command":"...","args":[...]}`, spawn a live transport
//! from it, and route it through the SAME `McpRegistry`/`McpServer` discovery+call path as
//! `MockTransport` — nothing above the transport seam changes.

use std::io::Write;
#[cfg(unix)]
use std::os::unix::net::UnixStream;

use ainxt_mcp::{
    McpError, McpRegistry, McpServer, McpTransport, McpTransportConfig, NoAuth, RawIoStdioTransport,
};

fn fixture_server_path() -> &'static str {
    env!("CARGO_BIN_EXE_mcp_fixture_server")
}

// ---------------------------------------------------------------------------------------------
// Suite 1: the real McpTransportConfig -> spawn -> real child process path.
// ---------------------------------------------------------------------------------------------

#[test]
fn stdio_config_serializes_and_derives_a_stable_synthetic_url() {
    let cfg = McpTransportConfig::Stdio {
        command: "mcp_fixture_server".to_string(),
        args: vec!["--flag".to_string()],
        env: Default::default(),
    };
    // Real, versioned, serializable — a harness/control-plane file can declare this today.
    let json = serde_json::to_string(&cfg).unwrap();
    assert!(json.contains("\"kind\":\"stdio\""));
    let round_tripped: McpTransportConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(round_tripped, cfg);

    // A stdio server has no network URL, but it still needs a stable identity for §2.2 auth keying
    // and §2.5 namespacing — derived deterministically from command+args, not a network address.
    assert_eq!(cfg.server_url(), "stdio://mcp_fixture_server --flag");
}

#[test]
fn http_and_sse_configs_are_real_but_spawn_fails_closed_not_silently() {
    // The HTTP/SSE config vocabulary is real (serializable, has a url), but there is no live client
    // behind it yet — `spawn` must fail with a NAMED, structured error, never silently return a
    // transport that pretends to work.
    let http = McpTransportConfig::StreamableHttp {
        url: "https://example.com/mcp".to_string(),
        headers: Default::default(),
    };
    let err = http
        .spawn()
        .err()
        .expect("HTTP spawn must fail closed with a structured error, not silently succeed");
    match err {
        McpError::Transport(msg) => assert!(
            msg.contains("no live HTTP/SSE"),
            "must name exactly what's missing, got: {msg}"
        ),
        other => panic!("expected McpError::Transport, got {other:?}"),
    }
    let sse = McpTransportConfig::Sse {
        url: "https://example.com/sse".to_string(),
        headers: Default::default(),
    };
    assert!(sse.spawn().is_err());

    // Round-trips too — real config either way, only the live client is deferred.
    let json = serde_json::to_string(&http).unwrap();
    assert!(json.contains("\"kind\":\"streamable_http\""));
}

#[test]
fn stdio_spawn_talks_to_a_real_separate_process_end_to_end() {
    // The config is exactly what a harness would declare; `spawn()` launches an ACTUAL OS process
    // (not a mock), and the resulting transport is routed through the same McpRegistry discovery +
    // call path every other transport uses.
    let cfg = McpTransportConfig::Stdio {
        command: fixture_server_path().to_string(),
        args: vec![],
        env: Default::default(),
    };
    let transport = cfg.spawn().expect("a real child process must spawn");

    let mut reg = McpRegistry::new();
    reg.register(McpServer::new("fixture", &cfg.server_url(), transport));

    let d = reg.discover("alice", &NoAuth);
    assert!(
        d.failures.is_empty(),
        "the real subprocess must connect cleanly: {:?}",
        d.failures
    );
    assert_eq!(d.tools.len(), 1, "the fixture declares exactly one tool");
    assert_eq!(d.tools[0].manifest.name, "echo");
    assert!(d.tools[0].manifest.schema.contains("properties"));

    let qualified = &d.tools[0].qualified_name;
    let result = reg
        .call("alice", &NoAuth, qualified, "{\"text\":\"hi\"}")
        .expect("a real tools/call round trip against the real child process");
    assert!(!result.is_error);
    assert_eq!(result.content, "fixture:echo:{\"text\":\"hi\"}");
}

#[test]
fn stdio_spawn_of_a_nonexistent_command_is_a_structured_unreachable_not_a_panic() {
    let cfg = McpTransportConfig::Stdio {
        command: "/definitely/not/a/real/binary/on/this/machine".to_string(),
        args: vec![],
        env: Default::default(),
    };
    let err = cfg
        .spawn()
        .err()
        .expect("spawning a nonexistent binary must fail, not silently succeed");
    match err {
        McpError::Unreachable(msg) => assert!(msg.contains("failed to spawn")),
        other => panic!("expected a structured Unreachable, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------------------------
// Suite 2: the JSON-RPC wire framing itself, over a real duplex socket (no process spawn cost).
// Unix-only: uses UnixStream which is not available on Windows.
// ---------------------------------------------------------------------------------------------

#[cfg(unix)]
fn peer_thread(sock: UnixStream, script: fn(UnixStream)) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || script(sock))
}

#[cfg(unix)]
#[test]
fn raw_io_transport_full_round_trip_over_a_real_socket() {
    let (a, b) = UnixStream::pair().expect("unix socket pair");
    let handle = peer_thread(b, |mut sock| {
        let mut reader = std::io::BufReader::new(sock.try_clone().unwrap());
        for _ in 0..2 {
            let mut line = String::new();
            std::io::BufRead::read_line(&mut reader, &mut line).unwrap();
            let req: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
            let id = req["id"].clone();
            let method = req["method"].as_str().unwrap();
            let result = match method {
                "initialize" => serde_json::json!({"protocolVersion": "mcp/1.0"}),
                "tools/list" => serde_json::json!({"tools": [{"name": "t1", "description": "d1"}]}),
                _ => serde_json::json!({}),
            };
            let resp = serde_json::json!({"jsonrpc": "2.0", "id": id, "result": result});
            writeln!(sock, "{resp}").unwrap();
        }
    });

    let (read_half, write_half) = (a.try_clone().unwrap(), a);
    let transport = RawIoStdioTransport::new(Box::new(write_half), Box::new(read_half));
    transport
        .connect(None)
        .expect("real initialize round trip over the socket");
    let tools = transport.list_tools().expect("real tools/list round trip");
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].name, "t1");

    handle.join().unwrap();

    // RawIoStdioTransport is a real implementor of the same trait every other transport uses.
    fn assert_is_mcp_transport<T: ainxt_mcp::McpTransport>() {}
    assert_is_mcp_transport::<RawIoStdioTransport>();
}

#[cfg(unix)]
#[test]
fn raw_io_transport_maps_a_jsonrpc_error_response_not_a_panic() {
    let (a, b) = UnixStream::pair().unwrap();
    let handle = peer_thread(b, |mut sock| {
        let mut reader = std::io::BufReader::new(sock.try_clone().unwrap());
        let mut line = String::new();
        std::io::BufRead::read_line(&mut reader, &mut line).unwrap();
        let req: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        let resp = serde_json::json!({
            "jsonrpc": "2.0", "id": req["id"],
            "error": {"code": -32000, "message": "server on fire"}
        });
        writeln!(sock, "{resp}").unwrap();
    });
    let (read_half, write_half) = (a.try_clone().unwrap(), a);
    let transport = RawIoStdioTransport::new(Box::new(write_half), Box::new(read_half));
    let err = transport.connect(None).unwrap_err();
    match err {
        McpError::Transport(msg) => assert!(msg.contains("server on fire")),
        other => panic!("expected Transport error carrying the peer's message, got {other:?}"),
    }
    handle.join().unwrap();
}

#[cfg(unix)]
#[test]
fn raw_io_transport_detects_a_desynchronized_peer_by_id_mismatch() {
    let (a, b) = UnixStream::pair().unwrap();
    let handle = peer_thread(b, |mut sock| {
        let mut reader = std::io::BufReader::new(sock.try_clone().unwrap());
        let mut line = String::new();
        std::io::BufRead::read_line(&mut reader, &mut line).unwrap();
        // Deliberately reply with the WRONG id — a desynchronized/buggy peer.
        let resp = serde_json::json!({"jsonrpc": "2.0", "id": 999999, "result": {}});
        writeln!(sock, "{resp}").unwrap();
    });
    let (read_half, write_half) = (a.try_clone().unwrap(), a);
    let transport = RawIoStdioTransport::new(Box::new(write_half), Box::new(read_half));
    let err = transport.connect(None).unwrap_err();
    match err {
        McpError::Transport(msg) => assert!(msg.contains("id mismatch")),
        other => panic!("expected an id-mismatch Transport error, got {other:?}"),
    }
    handle.join().unwrap();
}

#[cfg(unix)]
#[test]
fn raw_io_transport_treats_peer_disconnect_as_unreachable() {
    let (a, b) = UnixStream::pair().unwrap();
    drop(b); // Peer gone before ever responding.
    let (read_half, write_half) = (a.try_clone().unwrap(), a);
    let transport = RawIoStdioTransport::new(Box::new(write_half), Box::new(read_half));
    let err = transport.connect(None).unwrap_err();
    assert!(matches!(err, McpError::Unreachable(_)));
}
