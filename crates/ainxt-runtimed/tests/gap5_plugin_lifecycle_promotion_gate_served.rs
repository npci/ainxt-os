// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX tooling-mcp-plugins-routing (round 2) — "plugin lifecycle gate has zero callers".
//!
//! `ainxt_plugin::supply_chain::promote` (the git-native DRAFT→PENDING_APPROVAL→APPROVED→PRODUCTION
//! gate, ADR-026 §3.3) was correct and unit-tested in complete isolation
//! (`ainxt-plugin/tests/r11_plugin_supply_chain.rs`) — `grep -rn "Stage::promote\|::promote("
//! crates/` found ZERO callers anywhere in the workspace outside that crate's own tests. A plugin's
//! lifecycle stage could never actually be enforced on any served path: the gate existed and was
//! correct in isolation but nothing in the real plugin registration flow ever called it.
//!
//! `register_served_plugin_runtime` (the SAME composition-root function `gap3_plugin_runtime_reachable.rs`
//! proved reachable for the §3.4 supply-chain gate) now ALSO walks the full §3.3 lifecycle chain via
//! `promote`, driven by the `promotion_evidence` every `ApprovedPlugin` carries — never trusting a
//! caller-asserted stage. These tests drive that REAL function end-to-end and prove:
//!   1. A plugin whose git-native history never produced a signed release tag (stuck at APPROVED) is
//!      refused — even though its artifact signature, hash, and lock-pin are all perfectly valid —
//!      proving the lifecycle gate is a REAL, independent barrier and not merely redundant with §3.4.
//!   2. A plugin that never even had a PR opened (stuck at DRAFT) is refused for the same reason.
//!   3. A plugin with a complete, evidenced lifecycle (every hop's evidence present) legitimately
//!      reaches PRODUCTION and is admitted — the positive control proving the gate is not a hard block
//!      that always refuses.

use std::sync::Arc;

use ainxt_plugin::supply_chain::{
    ControlLock, HmacSigner, HmacVerifier, LockEntry, PromotionEvidence, PublisherAllowList,
    SignedPlugin,
};
use ainxt_plugin::{NativeHost, PluginGrant, PluginManifest, ResourceLimits};
use ainxt_runtimed::{register_served_plugin_runtime, ApprovedPlugin};
use ainxt_tools::{DispatchResult, InMemoryLedger, ManualReconciler, ToolRuntime};

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

/// A fully cryptographically-valid `ApprovedPlugin` (would pass §3.4 on its own), parameterized only
/// by its `promotion_evidence` so each test isolates the §3.3 lifecycle gate specifically.
fn approved_plugin_with_evidence(evidence: PromotionEvidence) -> ApprovedPlugin {
    let artifact_bytes = b"echo-plugin-artifact-v1".to_vec();
    let (_manifest, signed) = signed_echo_plugin(&artifact_bytes);

    let mut host = NativeHost::new();
    host.register(
        "echo_plugin",
        Box::new(|input, _ctx| Ok(format!("echo:{input}"))),
    );

    ApprovedPlugin {
        host: Arc::new(host),
        fetched_bytes: artifact_bytes,
        signed: signed.clone(),
        lock: lock_for(&signed),
        allow: PublisherAllowList::new(["acme-publisher"]),
        verifier: Arc::new(HmacVerifier::new().with_key("acme-publisher", "topsecret-signing-key")),
        grant: PluginGrant::new(Vec::<String>::new()),
        promotion_evidence: evidence,
    }
}

#[test]
fn a_plugin_stuck_at_approved_with_no_signed_release_tag_is_refused_despite_a_valid_signature() {
    // Every hop up to APPROVED cleared (PR opened, import check passed, scan clean, CODEOWNERS
    // merge) but NO signed release tag exists on the prod ref — per the signed-tag-equals-production
    // rule, this plugin never actually reached PRODUCTION, regardless of how valid its bytes/signature
    // are.
    let evidence = PromotionEvidence {
        pull_request_open: true,
        import_check_passed: true,
        scan_clean: true,
        codeowners_merge: true,
        signed_release_tag: false,
    };
    let approved = approved_plugin_with_evidence(evidence);

    let mut registry =
        ToolRuntime::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler));
    let admitted = register_served_plugin_runtime(&mut registry, vec![approved]);

    assert!(
        admitted.is_empty(),
        "a plugin without a signed release tag must never be admitted, even with a valid \
         signature/hash/lock-pin, got {admitted:?}"
    );
    assert!(!registry.tool_names().contains(&"echo_plugin".to_string()));
    assert!(
        matches!(
            registry.dispatch("echo_plugin", "hello"),
            DispatchResult::Blocked(_)
        ),
        "a lifecycle-refused plugin is unknown to the registry — dispatch must refuse it as an \
         unknown tool"
    );
}

#[test]
fn a_plugin_that_never_had_a_pr_opened_is_refused_at_the_first_lifecycle_hop() {
    // No evidence at all — this plugin never even left DRAFT (no PR ever opened). Distinct from the
    // "stuck at Approved" case above: this must fail the VERY FIRST hop of the chain, not the last.
    let approved = approved_plugin_with_evidence(PromotionEvidence::default());

    let mut registry =
        ToolRuntime::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler));
    let admitted = register_served_plugin_runtime(&mut registry, vec![approved]);

    assert!(
        admitted.is_empty(),
        "a plugin with zero lifecycle evidence must never be admitted, got {admitted:?}"
    );
    assert!(!registry.tool_names().contains(&"echo_plugin".to_string()));
}

#[test]
fn a_plugin_with_a_complete_evidenced_lifecycle_reaches_production_and_is_admitted() {
    // The positive control: every hop's evidence is present, so `promote` legitimately walks
    // Draft -> PendingApproval -> Approved -> Production, and — combined with valid §3.4 supply-chain
    // evidence — the plugin is admitted and dispatchable through the REAL registry path.
    let evidence = PromotionEvidence {
        pull_request_open: true,
        import_check_passed: true,
        scan_clean: true,
        codeowners_merge: true,
        signed_release_tag: true,
    };
    let approved = approved_plugin_with_evidence(evidence);

    let mut registry =
        ToolRuntime::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler));
    let admitted = register_served_plugin_runtime(&mut registry, vec![approved]);

    assert_eq!(
        admitted,
        vec!["echo_plugin".to_string()],
        "a plugin with a complete, evidenced lifecycle must be admitted"
    );
    assert!(registry.tool_names().contains(&"echo_plugin".to_string()));

    let result = registry.dispatch("echo_plugin", "hello");
    match result {
        DispatchResult::Ok(out) => assert_eq!(out, "echo:hello"),
        other => {
            panic!("expected the plugin to actually execute through the registry, got {other:?}")
        }
    }
}
