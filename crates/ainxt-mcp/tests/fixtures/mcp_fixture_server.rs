// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! A minimal, protocol-correct MCP stdio server, used ONLY as a real child-process fixture by
//! `tests/r16_stdio_transport.rs` to prove `McpTransportConfig::Stdio::spawn` +
//! `JsonRpcStdioTransport` against an actual separate OS process — not an in-process mock.
//!
//! Speaks exactly the wire format `ainxt_mcp::JsonRpcStdioTransport` expects: one JSON-RPC 2.0
//! message per line on stdin, one JSON-RPC 2.0 response per line on stdout, flushed immediately
//! (the same discipline MCP's real stdio transport uses — no Content-Length framing, unlike LSP).

use std::io::{self, BufRead, Write};

fn main() {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) if !l.trim().is_empty() => l,
            Ok(_) => continue,
            Err(_) => break,
        };
        let req: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                // Malformed request from the harness side — echo a JSON-RPC parse error, id null.
                let resp = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": serde_json::Value::Null,
                    "error": {"code": -32700, "message": format!("parse error: {e}")}
                });
                writeln!(stdout, "{resp}").ok();
                stdout.flush().ok();
                continue;
            }
        };
        let id = req.get("id").cloned().unwrap_or(serde_json::Value::Null);
        let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let result = match method {
            "initialize" => serde_json::json!({
                "protocolVersion": "mcp/1.0",
                "serverInfo": {"name": "mcp_fixture_server", "version": "0.0.0"}
            }),
            "tools/list" => serde_json::json!({
                "tools": [
                    {
                        "name": "echo",
                        "description": "echoes its input back, prefixed",
                        "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}}
                    }
                ]
            }),
            "tools/call" => {
                let params = req.get("params").cloned().unwrap_or(serde_json::json!({}));
                let name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
                let args = params
                    .get("arguments")
                    .map(|a| a.to_string())
                    .unwrap_or_default();
                if name == "boom" {
                    let resp = serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {"code": -32000, "message": "fixture: deliberate tool failure"}
                    });
                    writeln!(stdout, "{resp}").ok();
                    stdout.flush().ok();
                    continue;
                }
                serde_json::json!({
                    "content": [{"type": "text", "text": format!("fixture:{name}:{args}")}],
                    "isError": false
                })
            }
            other => {
                let resp = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {"code": -32601, "message": format!("method not found: {other}")}
                });
                writeln!(stdout, "{resp}").ok();
                stdout.flush().ok();
                continue;
            }
        };
        let resp = serde_json::json!({"jsonrpc": "2.0", "id": id, "result": result});
        writeln!(stdout, "{resp}").ok();
        stdout.flush().ok();
    }
}
