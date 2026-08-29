// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! GAP6 — "the real MCP stdio transport is never invoked, the registry is always empty". Before this
//! fix, EVERY caller of `build_unified_capability_registry_shared_over_with_mcp_admin` (the function
//! behind every served surface's `McpRegistry`) constructed it via `ainxt_mcp::McpRegistry::new()` and
//! never called `.register(McpServer::new(...))` — a shipped daemon always booted with ZERO MCP
//! servers, so `ainxt_mcp::JsonRpcStdioTransport`/`McpTransportConfig::spawn` (the real stdio
//! connect/auth machinery) never executed outside a `tests/` file anywhere in the workspace.
//!
//! This test drives the REAL composition root end-to-end: `ainxt_runtimed::load_layered` (the exact
//! TOML-config-loading function `main.rs` calls) parses a `[[mcp.servers]]` section pointing at
//! `ainxt-mcp`'s own real stdio fixture (`mcp_fixture_server` — a genuinely separate OS process, the
//! SAME fixture `ainxt-mcp/tests/r16_stdio_transport.rs` uses to prove the bare transport), then
//! `ainxt_runtimed::assemble_selected(&loaded, "engine")` (the exact dispatch arm `main.rs`'s
//! `--surface engine` selects) assembles the daemon. It proves the `McpRegistry` the daemon actually
//! serves from — not a hand-built one in isolation — contains a registered, genuinely CONNECTED
//! server (a real subprocess `initialize`/`tools/list` round trip), that it starts TOFU-quarantined
//! like any first connection, and that a real `tools/call` round trip succeeds once approved —
//! mirroring exactly what the served `POST /admin/mcp/approve` route does over this same handle.
//!
//! Fail-before: this whole file could compile against the fix but every assertion below the `assemble`
//! call would fail, because `build_unified_capability_registry_shared_over_with_mcp_admin` never read
//! `loaded.mcp` at all — `[[mcp.servers]]` had nowhere to go. Pass-after: a deployment's declared MCP
//! server is actually spawned, registered, and dispatchable through the daemon's own composition root.

use std::path::PathBuf;

/// Cross-crate fixture-binary lookup. `ainxt-mcp`'s OWN tests reach `mcp_fixture_server` via
/// `env!("CARGO_BIN_EXE_mcp_fixture_server")`, but that Cargo-supplied env var is only populated for
/// integration tests compiled as part of the SAME package that declares the `[[bin]]` target (verified
/// empirically: referencing it from an `ainxt-runtimed` test fails to compile with "environment
/// variable not defined at compile time" — Cargo does not propagate a dependency's `CARGO_BIN_EXE_*`
/// vars across crates). So this shells out to the SAME `cargo` driving this test run and asks it
/// directly, via `--message-format=json`, for the artifact path — the standard cross-crate
/// fixture-binary technique (the same one `escargot`/`trybuild`-style tooling uses), deterministic
/// regardless of profile or `CARGO_TARGET_DIR`, no path-guessing. `ainxt-mcp` already builds this exact
/// binary for its own tests; this just asks Cargo where it put it (rebuilding only if needed).
fn build_fixture_server_bin() -> PathBuf {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let manifest_dir =
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set by cargo");
    // `runtime/crates/ainxt-runtimed` -> `runtime/crates` -> `runtime` (the workspace root).
    let workspace_manifest = PathBuf::from(&manifest_dir).join("../../Cargo.toml");

    let output = std::process::Command::new(&cargo)
        .arg("build")
        .arg("--message-format=json")
        .arg("--manifest-path")
        .arg(&workspace_manifest)
        .args(["-p", "ainxt-mcp", "--bin", "mcp_fixture_server"])
        .output()
        .expect("cargo build for the mcp_fixture_server fixture must run");
    assert!(
        output.status.success(),
        "building the real mcp_fixture_server fixture failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let msg: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let is_fixture_artifact = msg.get("reason").and_then(|r| r.as_str())
            == Some("compiler-artifact")
            && msg
                .get("target")
                .and_then(|t| t.get("name"))
                .and_then(|n| n.as_str())
                == Some("mcp_fixture_server");
        if is_fixture_artifact {
            if let Some(exe) = msg.get("executable").and_then(|e| e.as_str()) {
                return PathBuf::from(exe);
            }
        }
    }
    panic!(
        "mcp_fixture_server executable path not found in `cargo build --message-format=json` output \
         (stdout was: {stdout})"
    );
}

#[test]
fn configured_mcp_server_is_spawned_registered_and_connected_through_the_real_composition_root() {
    let fixture = build_fixture_server_bin();
    // TOML basic strings only need `"`/`\` escaped; a temp-dir path on any real CI/dev machine won't
    // contain anything else that needs escaping.
    let fixture_str = fixture
        .to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"");

    let config_toml = format!(
        "version = 1\n\
         \n\
         [[mcp.servers]]\n\
         name = \"fixture\"\n\
         \n\
         [mcp.servers.transport]\n\
         kind = \"stdio\"\n\
         command = \"{fixture_str}\"\n\
         args = []\n"
    );

    // The exact config-loading entrypoint `main.rs` calls (`load_shipped`/`load_layered`).
    let loaded = ainxt_runtimed::load_layered(&[("test", &config_toml)])
        .expect("a [[mcp.servers]] config section must load and deserialize cleanly");
    assert_eq!(
        loaded.mcp.servers.len(),
        1,
        "the declared server must survive config loading"
    );
    assert_eq!(loaded.mcp.servers[0].name, "fixture");

    // The exact composition-root dispatch `main.rs`'s `--surface engine` selects.
    let assembled = ainxt_runtimed::assemble_selected(&loaded, "engine")
        .expect("assembling the engine surface with a configured MCP server must succeed");

    let mcp_admin = assembled
        .mcp_admin
        .clone()
        .expect("the engine surface always builds a real McpAdminHandle");

    // (1) The gap itself: the registry the daemon ACTUALLY serves from is no longer empty.
    assert_eq!(
        mcp_admin.registry.server_count(),
        1,
        "the configured server must be registered into the SAME registry the daemon boots with"
    );

    // (2) It is genuinely CONNECTED, not merely registered inertly — a real subprocess round trip
    // (`initialize` + `tools/list`) against an actual separate `mcp_fixture_server` OS process.
    let discovery = mcp_admin
        .registry
        .discover(&mcp_admin.user_id, mcp_admin.auth.as_ref());
    assert!(
        discovery.failures.is_empty(),
        "the real fixture subprocess must connect cleanly: {:?}",
        discovery.failures
    );
    assert_eq!(
        discovery.tools.len(),
        1,
        "the fixture declares exactly one real tool"
    );
    assert_eq!(discovery.tools[0].manifest.name, "echo");

    // (3) TOFU quarantine still applies to a freshly configured server — this fix does not silently
    // auto-trust a newly connected server just because it came from config instead of a test.
    let pinned = mcp_admin.registry.discover_pinned(
        &mcp_admin.user_id,
        mcp_admin.auth.as_ref(),
        mcp_admin.pins.as_ref(),
    );
    assert!(
        pinned.plannable().is_empty(),
        "a first-use server must not be auto-plannable"
    );
    assert_eq!(
        pinned.needs_reapproval().len(),
        1,
        "the new server must need human re-approval"
    );

    // (4) Approve it — mirroring exactly what the served `POST /admin/mcp/approve` route does over
    // this SAME handle (`ainxt-server`'s admin route reads `state.mcp_admin` and calls
    // `server.approve(mcp_admin.pins.as_ref(), ..)`) — then prove a REAL `tools/call` round trip
    // through the registry the composition root produced.
    pinned.servers[0].approve(mcp_admin.pins.as_ref(), "test-admin", 1);
    let reapproved = mcp_admin.registry.discover_pinned(
        &mcp_admin.user_id,
        mcp_admin.auth.as_ref(),
        mcp_admin.pins.as_ref(),
    );
    let plannable = reapproved.plannable();
    assert_eq!(
        plannable.len(),
        1,
        "after approval the tool must be plannable"
    );

    let result = mcp_admin
        .registry
        .call(
            &mcp_admin.user_id,
            mcp_admin.auth.as_ref(),
            &plannable[0].qualified_name,
            "{\"text\":\"hi\"}",
        )
        .expect("a real tools/call round trip against the real child process");
    assert!(!result.is_error);
    assert_eq!(result.content, "fixture:echo:{\"text\":\"hi\"}");

    // (5) The boot report honestly names the connected server — never silent.
    assert!(
        assembled
            .report
            .iter()
            .any(|line| line.contains("fixture") && line.contains("mcp:")),
        "the assembly report must record the connected MCP server: {:?}",
        assembled.report
    );
}

#[test]
fn an_unreachable_configured_mcp_server_fails_soft_and_never_blocks_daemon_boot() {
    let config_toml = "version = 1\n\
         \n\
         [[mcp.servers]]\n\
         name = \"broken\"\n\
         \n\
         [mcp.servers.transport]\n\
         kind = \"stdio\"\n\
         command = \"/definitely/not/a/real/binary/on/this/machine\"\n\
         args = []\n";

    let loaded = ainxt_runtimed::load_layered(&[("test", config_toml)])
        .expect("config must still load even with an unreachable server declared");

    // The composition root must NOT fail daemon boot over one bad MCP server entry (fail-soft: log +
    // skip, mirroring every other optional-integration boot step in `main.rs`).
    let assembled = ainxt_runtimed::assemble_selected(&loaded, "engine")
        .expect("one unreachable configured MCP server must fail SOFT, never abort assembly");

    let mcp_admin = assembled
        .mcp_admin
        .expect("the engine surface always builds a real McpAdminHandle");
    assert_eq!(
        mcp_admin.registry.server_count(),
        0,
        "a server whose transport failed to spawn must never be registered"
    );
    assert!(
        assembled
            .report
            .iter()
            .any(|line| line.contains("broken") && line.to_lowercase().contains("fail")),
        "the boot report must honestly record the failed connection, not swallow it: {:?}",
        assembled.report
    );
}
