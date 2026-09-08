// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-AUDIT plugin-sandbox-registry — "GuardedHost never wraps the real plugin host" (§3.5).
//!
//! `ainxt_plugin::GuardedHost<H>` is a real [`ainxt_plugin::PluginHost`] decorator: it runs the
//! wrapped host's invocation on a detached worker thread and, once `manifest.limits.max_millis`
//! elapses, stops waiting and returns [`ainxt_plugin::PluginError::WallClockExceeded`] promptly — so
//! a busy-loop or a blocked-forever guest can never pin the calling turn. It was fully implemented
//! and unit-tested in `ainxt-plugin`/`ainxt-wasm`, but `register_served_plugin_runtime`
//! (`ainxt-runtimed`, the served composition root) and `approved_wasm_sandboxed_plugin` both handed
//! `ainxt_tools::plugin_bridge::PluginCapability` the RAW host — so `max_millis` was silently never
//! enforced for anything the daemon actually admitted, regardless of what a plugin's own manifest
//! declared. `register_served_plugin_runtime` now wraps every admitted plugin's host in
//! `GuardedHost` before adapting it into a capability.
//!
//! This test drives the REAL function end-to-end against a REAL runaway (native-hosted) plugin: a
//! plugin that sleeps for 10 real seconds — ten times longer than its own declared 100ms wall-clock
//! budget — is admitted, but a dispatch through the served registry returns in well under a second
//! with an explicit `WallClockExceeded` refusal, proving the turn is never held hostage by a hung
//! plugin. A second test proves the wrap does not regress a plugin that finishes within its own
//! budget: it still dispatches normally and returns its real output.

use std::sync::Arc;
use std::time::{Duration, Instant};

use ainxt_plugin::supply_chain::{
    ControlLock, HmacSigner, HmacVerifier, LockEntry, PromotionEvidence, PublisherAllowList,
    SignedPlugin,
};
use ainxt_plugin::{NativeHost, PluginGrant, PluginManifest, ResourceLimits};
use ainxt_runtimed::{register_served_plugin_runtime, ApprovedPlugin};
use ainxt_tools::{DispatchResult, InMemoryLedger, ManualReconciler, ToolRuntime};

/// Evidence for a plugin that has legitimately cleared every hop of the §3.3 git-native lifecycle —
/// the fixture these tests use so the lifecycle gate itself is a no-op here (proven separately in
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

fn signed_plugin(id: &str, limits: ResourceLimits, bytes: &[u8]) -> (PluginManifest, SignedPlugin) {
    let manifest = PluginManifest {
        id: id.to_string(),
        requested_capabilities: vec![],
        limits,
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

fn approved(host: NativeHost, fetched_bytes: Vec<u8>, signed: SignedPlugin) -> ApprovedPlugin {
    ApprovedPlugin {
        host: Arc::new(host),
        fetched_bytes,
        signed: signed.clone(),
        lock: lock_for(&signed),
        allow: PublisherAllowList::new(["acme-publisher"]),
        verifier: Arc::new(HmacVerifier::new().with_key("acme-publisher", "topsecret-signing-key")),
        grant: PluginGrant::new(Vec::<String>::new()),
        promotion_evidence: fully_promoted_evidence(),
    }
}

#[test]
fn a_hanging_plugin_is_stopped_by_guarded_host_and_never_hangs_the_served_dispatch() {
    // Declares a 100ms wall-clock budget for itself...
    let limits = ResourceLimits {
        max_output_bytes: 64 * 1024,
        max_millis: 100,
        max_memory_bytes: 16 * 1024 * 1024,
    };
    let artifact_bytes = b"slow-plugin-artifact-v1".to_vec();
    let (manifest, signed) = signed_plugin("slow_plugin", limits, &artifact_bytes);

    let mut host = NativeHost::new();
    host.register(
        "slow_plugin",
        // ...but the guest itself sleeps for 10 real seconds — 100x its declared budget. A native
        // host cannot forcibly kill this thread (documented, honest scope of `GuardedHost`), so it
        // keeps running detached; the point is that the CALLER must never wait for it.
        Box::new(|_input, _ctx| {
            std::thread::sleep(Duration::from_secs(10));
            Ok("this output must never reach the caller".to_string())
        }),
    );

    let mut registry =
        ToolRuntime::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler));
    let admitted = register_served_plugin_runtime(
        &mut registry,
        vec![approved(host, artifact_bytes, signed.clone())],
    );
    assert_eq!(
        admitted,
        vec!["slow_plugin".to_string()],
        "the runaway plugin still passes the lifecycle + supply-chain gates and must be admitted \
         (GuardedHost enforces the RUNTIME budget, it is not a load-time admission gate)"
    );

    let start = Instant::now();
    let result = registry.dispatch(&manifest.id, "hello");
    let elapsed = start.elapsed();

    // The proof that this discriminates real behavior, not merely "the wrapper was applied": the
    // plugin's own closure takes 10 real seconds to return. If `register_served_plugin_runtime` were
    // still handing `PluginCapability` the raw, unwrapped host, this assertion would time out this
    // test (or at best pass only after a literal 10-second block) instead of completing almost
    // immediately.
    assert!(
        elapsed < Duration::from_secs(2),
        "GuardedHost must return once the plugin's declared 100ms wall-clock budget elapses, not \
         block for the plugin's actual 10s runtime — actual elapsed: {elapsed:?}"
    );
    match result {
        DispatchResult::Failed(msg) => assert!(
            msg.contains("wall-clock"),
            "expected the plugin's PluginError::WallClockExceeded to surface as the dispatch \
             failure reason, got: {msg}"
        ),
        other => panic!(
            "expected the runaway plugin to be refused by GuardedHost's wall-clock enforcement \
             (a Failed dispatch), got {other:?} instead"
        ),
    }
}

#[test]
fn a_plugin_that_finishes_within_its_declared_budget_still_dispatches_normally_through_guarded_host(
) {
    // A generous (but not infinite) budget and a guest that returns almost instantly — proves the
    // GuardedHost wrap is a pure pass-through for well-behaved plugins, not a source of new latency
    // or false refusals.
    let limits = ResourceLimits {
        max_output_bytes: 64 * 1024,
        max_millis: 5_000,
        max_memory_bytes: 16 * 1024 * 1024,
    };
    let artifact_bytes = b"fast-plugin-artifact-v1".to_vec();
    let (manifest, signed) = signed_plugin("fast_plugin", limits, &artifact_bytes);

    let mut host = NativeHost::new();
    host.register(
        "fast_plugin",
        Box::new(|input, _ctx| Ok(format!("echo:{input}"))),
    );

    let mut registry =
        ToolRuntime::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler));
    let admitted =
        register_served_plugin_runtime(&mut registry, vec![approved(host, artifact_bytes, signed)]);
    assert_eq!(admitted, vec!["fast_plugin".to_string()]);

    let start = Instant::now();
    let result = registry.dispatch(&manifest.id, "hello");
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(1),
        "a well-behaved plugin must not be slowed down by the GuardedHost wrap, elapsed: {elapsed:?}"
    );
    match result {
        DispatchResult::Ok(out) => assert_eq!(out, "echo:hello"),
        other => panic!("expected the fast plugin to dispatch normally, got {other:?}"),
    }
}
