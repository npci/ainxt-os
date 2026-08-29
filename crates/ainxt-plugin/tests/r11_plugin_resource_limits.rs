// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R11 §3.5 — host-enforced wall-clock resource limit. A runaway/sleeping plugin is bounded by the
//! HOST (via [`GuardedHost`]), not by the guest's cooperation: the calling turn stays responsive and
//! co-located work is unaffected. (Hard CPU/memory kill is the deferred wasmtime host — infra-gated.)

use ainxt_plugin::{
    GuardedHost, NativeHost, PluginError, PluginFn, PluginGrant, PluginHost, PluginManifest,
    ResourceLimits,
};

fn manifest(id: &str, max_millis: u64) -> PluginManifest {
    PluginManifest {
        id: id.into(),
        requested_capabilities: vec![],
        limits: ResourceLimits {
            max_output_bytes: 64 * 1024,
            max_millis,
            max_memory_bytes: 16 * 1024 * 1024,
        },
    }
}

fn host_with(id: &str, plugin: PluginFn) -> GuardedHost<NativeHost> {
    let mut inner = NativeHost::new();
    inner.register(id, plugin);
    GuardedHost::new(inner)
}

#[test]
fn runaway_plugin_is_bounded_by_the_host_not_the_guest() {
    // A plugin that sleeps FAR past its budget. FAIL-BEFORE: without host-side enforcement this call
    // would block ~2s; with GuardedHost it returns within the ~50ms budget as WallClockExceeded.
    let host = host_with(
        "slow",
        Box::new(|_i, _ctx| {
            std::thread::sleep(std::time::Duration::from_millis(2000));
            Ok("eventually".into())
        }),
    );
    let started = std::time::Instant::now();
    let err = host
        .invoke(&manifest("slow", 50), &PluginGrant::default(), "x")
        .unwrap_err();
    let elapsed = started.elapsed();
    assert_eq!(err, PluginError::WallClockExceeded { limit_millis: 50 });
    // The host returned PROMPTLY — it did not wait out the plugin's 2s sleep.
    assert!(
        elapsed < std::time::Duration::from_millis(1000),
        "host must return near the budget, not after the plugin finishes; took {elapsed:?}"
    );
}

#[test]
fn host_survives_a_timeout_and_keeps_serving() {
    let host = host_with(
        "slow",
        Box::new(|_i, _ctx| {
            std::thread::sleep(std::time::Duration::from_millis(1000));
            Ok("late".into())
        }),
    );
    assert!(host
        .invoke(&manifest("slow", 30), &PluginGrant::default(), "x")
        .is_err());

    // A subsequent well-behaved plugin on a fresh host still works — the timeout did not poison it.
    let ok = host_with("fast", Box::new(|i, _ctx| Ok(format!("done:{i}"))));
    let out = ok
        .invoke(&manifest("fast", 5_000), &PluginGrant::default(), "y")
        .unwrap();
    assert_eq!(out.output, "done:y");
}

#[test]
fn under_budget_plugin_succeeds_normally() {
    let host = host_with("quick", Box::new(|i, _ctx| Ok(format!("hi {i}"))));
    let out = host
        .invoke(&manifest("quick", 5_000), &PluginGrant::default(), "bob")
        .unwrap();
    assert_eq!(out.output, "hi bob");
    assert!(out.used_capabilities.is_empty());
}

#[test]
fn zero_budget_means_no_wall_clock_bound_passthrough() {
    // max_millis == 0 → run inline; the capability + output contract still applies.
    let host = host_with(
        "cap",
        Box::new(|_i, ctx| {
            ctx.use_capability("net")?;
            Ok("ok".into())
        }),
    );
    let err = host
        .invoke(&manifest("cap", 0), &PluginGrant::default(), "x")
        .unwrap_err();
    assert_eq!(err, PluginError::CapabilityDenied("net".into()));
}
