// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-AUDIT tooling-mcp-plugins-routing — "Plugin WASI sandbox never used by the daemon".
//!
//! `gap3_plugin_runtime_reachable.rs` closed "plugin runtime unreachable" by proving
//! `register_served_plugin_runtime` (the composition root) dispatches a `NativeHost`-backed
//! `ApprovedPlugin` end-to-end. But EVERY caller — including that test — built the plugin with
//! `NativeHost`; `ainxt_wasm::WasmPluginHost` (a real, unit-proven wasmtime sandbox implementing the
//! IDENTICAL `ainxt_plugin::PluginHost` seam) had never once been exercised through this composition
//! root. `ainxt_runtimed::approved_wasm_sandboxed_plugin` is the missing producer — the canonical,
//! structural way to build an `ApprovedPlugin` for an untrusted/external plugin, so hard wasmtime
//! isolation is the default for that case rather than a caller-remembered convention.
//!
//! These tests drive the REAL function end-to-end against a REAL wasm module (inline WAT, no mocks):
//!   1. A properly signed + allow-listed + lockfile-pinned WASM plugin is admitted and a call to it
//!      dispatches through the FULL exactly-once path (ledger claim + commit) — proving genuine
//!      wasmtime execution reaches the served registry, not just NativeHost.
//!   2. The IDENTICAL §3.4 supply-chain gate a NativeHost-backed plugin goes through also refuses a
//!      tampered WASM artifact — proving a WASM host gets no weaker admission discipline.

use std::sync::Arc;

use ainxt_plugin::supply_chain::{
    ControlLock, HmacSigner, HmacVerifier, LockEntry, PromotionEvidence, PublisherAllowList,
    SignedPlugin,
};
use ainxt_plugin::{PluginGrant, PluginManifest, ResourceLimits};
use ainxt_runtimed::{approved_wasm_sandboxed_plugin, register_served_plugin_runtime};
use ainxt_tools::{DispatchResult, InMemoryLedger, ManualReconciler, ToolRuntime};

/// Evidence for a plugin that has legitimately cleared every hop of the §3.3 git-native lifecycle —
/// the fixture these supply-chain-focused tests use so the lifecycle gate itself is a no-op here (it
/// is proven separately, in `gap5_plugin_lifecycle_promotion_gate_served.rs`).
fn fully_promoted_evidence() -> PromotionEvidence {
    PromotionEvidence {
        pull_request_open: true,
        import_check_passed: true,
        scan_clean: true,
        codeowners_merge: true,
        signed_release_tag: true,
    }
}

/// A guest that echoes its input back out through its OWN linear memory (text ABI): `alloc` bumps a
/// pointer, `run(ptr,len)` returns exactly `(ptr,len)` — the input is already sitting at `ptr`. The
/// SAME fixture `ainxt-wasm`'s own `r13_wasm_plugin_host_seam.rs` uses, so this is a known-good,
/// already-proven module — the gap being closed here is reachability through the DAEMON'S composition
/// root, not the wasm sandbox mechanics themselves (already proven in `ainxt-wasm`).
const ECHO_WAT: &str = r#"
    (module
      (memory (export "memory") 1)
      (global $bump (mut i32) (i32.const 1024))
      (func (export "alloc") (param $len i32) (result i32)
        (local $p i32)
        global.get $bump
        local.set $p
        global.get $bump
        local.get $len
        i32.add
        global.set $bump
        local.get $p)
      (func (export "run") (param $ptr i32) (param $len i32) (result i32 i32)
        local.get $ptr
        local.get $len))
"#;

fn signed_wasm_plugin(bytes: &[u8]) -> (PluginManifest, SignedPlugin) {
    let manifest = PluginManifest {
        id: "echo_wasm_plugin".to_string(),
        requested_capabilities: vec![],
        limits: ResourceLimits::default(),
    };
    let signer = HmacSigner::new("acme-publisher", "topsecret-signing-key");
    let signed = SignedPlugin::sign(bytes, &manifest, "1.0.0", &signer);
    (manifest, signed)
}

fn lock_for(signed: &SignedPlugin) -> ControlLock {
    let mut lock = ControlLock::new();
    lock.pin(LockEntry {
        plugin_id: signed.manifest.id.clone(),
        version: signed.version.clone(),
        content_hash: signed.artifact_hash.clone(),
        signer: signed.publisher.clone(),
    });
    lock
}

#[test]
fn a_wasm_sandboxed_plugin_is_admitted_and_dispatches_through_the_full_registry_path_via_real_wasmtime(
) {
    let module_bytes = ECHO_WAT.as_bytes().to_vec();
    let (manifest, signed) = signed_wasm_plugin(&module_bytes);

    let approved = approved_wasm_sandboxed_plugin(
        module_bytes,
        signed.clone(),
        lock_for(&signed),
        PublisherAllowList::new(["acme-publisher"]),
        Arc::new(HmacVerifier::new().with_key("acme-publisher", "topsecret-signing-key")),
        PluginGrant::new(Vec::<String>::new()),
        fully_promoted_evidence(),
    );

    let mut registry =
        ToolRuntime::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler));
    let admitted = register_served_plugin_runtime(&mut registry, vec![approved]);

    assert_eq!(
        admitted,
        vec!["echo_wasm_plugin".to_string()],
        "a properly signed, allow-listed, lockfile-pinned WASM plugin must be admitted through the \
         SAME composition-root entrypoint a NativeHost plugin uses"
    );
    assert!(registry
        .tool_names()
        .contains(&"echo_wasm_plugin".to_string()));

    // Dispatch through the REAL registry path — ledger claim, effect-class check, execute (REAL
    // wasmtime, not a native closure), and commit — the same path any native or MCP capability goes
    // through (§0 one-registry). The echo module genuinely ran inside the wasm sandbox: if this were
    // silently falling back to some native no-op, the output would not round-trip through wasm linear
    // memory at all.
    let result = registry.dispatch(&manifest.id, "settlement-batch-9");
    match result {
        DispatchResult::Ok(out) => assert_eq!(out, "settlement-batch-9"),
        other => panic!(
            "expected the WASM plugin to actually execute through the registry, got {other:?}"
        ),
    }
}

#[test]
fn a_tampered_wasm_artifact_is_refused_by_the_identical_gate_a_native_plugin_goes_through() {
    let signed_bytes = ECHO_WAT.as_bytes().to_vec();
    let (_manifest, signed) = signed_wasm_plugin(&signed_bytes);
    // The FETCHED module bytes at load time differ from what was actually signed.
    let mut tampered_bytes = signed_bytes.clone();
    tampered_bytes.extend_from_slice(b"\n;; tampered after signing");

    let approved = approved_wasm_sandboxed_plugin(
        tampered_bytes,
        signed.clone(),
        lock_for(&signed),
        PublisherAllowList::new(["acme-publisher"]),
        Arc::new(HmacVerifier::new().with_key("acme-publisher", "topsecret-signing-key")),
        PluginGrant::new(Vec::<String>::new()),
        fully_promoted_evidence(),
    );

    let mut registry =
        ToolRuntime::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler));
    let admitted = register_served_plugin_runtime(&mut registry, vec![approved]);

    assert!(
        admitted.is_empty(),
        "a tampered WASM artifact must never be admitted, got {admitted:?}"
    );
    assert!(!registry
        .tool_names()
        .contains(&"echo_wasm_plugin".to_string()));
    assert!(
        matches!(
            registry.dispatch("echo_wasm_plugin", "x"),
            DispatchResult::Blocked(_)
        ),
        "a refused WASM plugin is unknown to the registry — dispatch must refuse it as an unknown tool"
    );
}
