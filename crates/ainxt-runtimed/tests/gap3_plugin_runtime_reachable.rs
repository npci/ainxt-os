// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-AUDIT tooling-mcp-plugins-routing — "Plugin runtime unreachable".
//!
//! `ainxt_tools::plugin_bridge::PluginCapability` (the §0 one-registry bridge adapting a WASM/native
//! plugin export into the same `Tool`/`CapabilityRegistry` a native or MCP capability dispatches
//! through) had exactly ONE caller in the whole workspace before this fix — `ainxt-tools`'s own
//! `r3_one_registry` test. No path from the served composition root (`ainxt-runtimed`) ever
//! constructed a `PluginHost`, ran the §3.4 supply-chain load gate, or registered a plugin capability
//! into the live registry the served agent loop actually dispatches through: the crate (NativeHost +
//! the signing/lockfile supply chain + the bridge adapter) was fully built and completely unreachable.
//!
//! `register_served_plugin_runtime` (in `ainxt_runtimed::lib`) closes this: it re-runs the §3.4 load
//! gate on every call and only a plugin that survives it is adapted and admitted into the registry via
//! the SAME `try_register_governed` gate native HighRisk+SideEffecting capabilities use.
//!
//! These tests drive the REAL function end-to-end against a REAL (native-hosted) plugin:
//!   1. A properly signed + allow-listed + lockfile-pinned plugin is admitted, and a call to it
//!      dispatches through the FULL exactly-once path (ledger claim + commit), producing the plugin's
//!      real output — proving the bridge is not just constructible but actually reachable and live.
//!   2. A plugin whose fetched bytes no longer match what was signed (tampered artifact) is refused —
//!      never adapted, never registered, invisible to `tool_names()` — proving the supply-chain gate
//!      is actually consulted on this path, not merely a function that exists elsewhere unused.

use std::sync::Arc;

use ainxt_plugin::supply_chain::{
    ControlLock, HmacSigner, HmacVerifier, LockEntry, PromotionEvidence, PublisherAllowList,
    SignedPlugin,
};
use ainxt_plugin::{NativeHost, PluginGrant, PluginManifest, ResourceLimits};
use ainxt_runtimed::{register_served_plugin_runtime, ApprovedPlugin};
use ainxt_tools::{DispatchResult, InMemoryLedger, ManualReconciler, ToolRuntime};

/// Evidence for a plugin that has legitimately cleared every hop of the §3.3 git-native lifecycle
/// (DRAFT→PENDING_APPROVAL→APPROVED→PRODUCTION) — the fixture these supply-chain-focused tests use so
/// the lifecycle gate itself is a no-op here (it is proven separately, in
/// `gap5_plugin_lifecycle_promotion_gate_served.rs`).
fn fully_promoted_evidence() -> PromotionEvidence {
    PromotionEvidence {
        pull_request_open: true,
        import_check_passed: true,
        scan_clean: true,
        codeowners_merge: true,
        signed_release_tag: true,
    }
}

fn signed_echo_plugin(bytes: &[u8]) -> (PluginManifest, SignedPlugin) {
    let manifest = PluginManifest {
        id: "echo_plugin".to_string(),
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
fn a_properly_signed_plugin_is_admitted_and_dispatches_through_the_full_registry_path() {
    let artifact_bytes = b"echo-plugin-artifact-v1".to_vec();
    let (manifest, signed) = signed_echo_plugin(&artifact_bytes);

    let mut host = NativeHost::new();
    host.register(
        "echo_plugin",
        Box::new(|input, _ctx| Ok(format!("echo:{input}"))),
    );

    let approved = ApprovedPlugin {
        host: Arc::new(host),
        fetched_bytes: artifact_bytes,
        signed: signed.clone(),
        lock: lock_for(&signed),
        allow: PublisherAllowList::new(["acme-publisher"]),
        verifier: Arc::new(HmacVerifier::new().with_key("acme-publisher", "topsecret-signing-key")),
        grant: PluginGrant::new(Vec::<String>::new()),
        promotion_evidence: fully_promoted_evidence(),
    };

    let mut registry =
        ToolRuntime::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler));
    let admitted = register_served_plugin_runtime(&mut registry, vec![approved]);

    assert_eq!(
        admitted,
        vec!["echo_plugin".to_string()],
        "a properly signed, allow-listed, lockfile-pinned plugin must be admitted"
    );
    assert!(registry.tool_names().contains(&"echo_plugin".to_string()));

    // Dispatch through the REAL registry path — ledger claim, effect-class check, execute, commit —
    // the same path any native or MCP capability goes through (§0 one-registry).
    let result = registry.dispatch(&manifest.id, "hello");
    match result {
        DispatchResult::Ok(out) => assert_eq!(out, "echo:hello"),
        other => {
            panic!("expected the plugin to actually execute through the registry, got {other:?}")
        }
    }
}

#[test]
fn a_tampered_artifact_is_refused_and_never_reaches_the_registry() {
    let signed_bytes = b"echo-plugin-artifact-v1".to_vec();
    let (_manifest, signed) = signed_echo_plugin(&signed_bytes);
    // The FETCHED bytes at load time differ from what was actually signed (a swap / corruption
    // after signing) — `verify_for_load` must recompute the hash over what was fetched and refuse
    // on mismatch, never trusting the signed record's own claim about itself.
    let tampered_bytes = b"echo-plugin-artifact-v1-TAMPERED".to_vec();

    let mut host = NativeHost::new();
    host.register(
        "echo_plugin",
        Box::new(|input, _ctx| Ok(format!("echo:{input}"))),
    );

    let approved = ApprovedPlugin {
        host: Arc::new(host),
        fetched_bytes: tampered_bytes,
        signed: signed.clone(),
        lock: lock_for(&signed),
        allow: PublisherAllowList::new(["acme-publisher"]),
        verifier: Arc::new(HmacVerifier::new().with_key("acme-publisher", "topsecret-signing-key")),
        grant: PluginGrant::new(Vec::<String>::new()),
        promotion_evidence: fully_promoted_evidence(),
    };

    let mut registry =
        ToolRuntime::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler));
    let admitted = register_served_plugin_runtime(&mut registry, vec![approved]);

    assert!(
        admitted.is_empty(),
        "a tampered artifact must never be admitted, got {admitted:?}"
    );
    assert!(
        !registry.tool_names().contains(&"echo_plugin".to_string()),
        "a refused plugin must never appear in the served registry"
    );
    assert!(
        matches!(
            registry.dispatch("echo_plugin", "hello"),
            DispatchResult::Blocked(_)
        ),
        "a refused plugin is unknown to the registry — dispatch must refuse it as an unknown tool"
    );
}

#[test]
fn a_publisher_removed_from_the_allow_list_is_refused_even_with_a_valid_signature() {
    // Simulates a signing key compromised after install: the signature and hash are still valid,
    // but the publisher has been revoked from the allow-list. §3.4 requires this check on EVERY
    // load, not just at install, so a previously-trusted publisher stops being loadable immediately.
    let artifact_bytes = b"echo-plugin-artifact-v1".to_vec();
    let (_manifest, signed) = signed_echo_plugin(&artifact_bytes);

    let mut host = NativeHost::new();
    host.register(
        "echo_plugin",
        Box::new(|input, _ctx| Ok(format!("echo:{input}"))),
    );

    let approved = ApprovedPlugin {
        host: Arc::new(host),
        fetched_bytes: artifact_bytes,
        signed: signed.clone(),
        lock: lock_for(&signed),
        allow: PublisherAllowList::new(Vec::<String>::new()), // "acme-publisher" NOT allow-listed
        verifier: Arc::new(HmacVerifier::new().with_key("acme-publisher", "topsecret-signing-key")),
        grant: PluginGrant::new(Vec::<String>::new()),
        promotion_evidence: fully_promoted_evidence(),
    };

    let mut registry =
        ToolRuntime::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler));
    let admitted = register_served_plugin_runtime(&mut registry, vec![approved]);

    assert!(
        admitted.is_empty(),
        "a plugin from a non-allow-listed publisher must never be admitted"
    );
    assert!(!registry.tool_names().contains(&"echo_plugin".to_string()));
}
