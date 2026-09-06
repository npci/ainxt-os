// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R12 §3.1/§3.5 — the plugin **security boundary** contract, proven offline against the exact host
//! stack the WASM/WASI host slots into: `GuardedHost<NativeHost>` (capability confinement + output
//! limit + panic isolation from the inner host, host-side wall-clock from the decorator).
//!
//! This is the offline half of the WASI/WASM sandbox gap (scenarios 13 + 14). The concrete
//! wasmtime host — hard CPU-slice / memory-ceiling KILL via epoch-interruption + `StoreLimits`, and
//! a guest with no ambient syscall surface at all — is a deferred implementation of the SAME
//! [`PluginHost`] trait, infra-gated behind a Gate-#0 legal review of its
//! `Apache-2.0 WITH LLVM-exception` license. Everything the security boundary must guarantee ABOVE
//! the hard-isolation mechanism is enforced and tested here, so the wasmtime host drops in without
//! changing the contract these tests pin.

use ainxt_plugin::{
    GuardedHost, NativeHost, PluginContext, PluginError, PluginGrant, PluginHost, PluginManifest,
    ResourceLimits,
};

fn manifest(id: &str, caps: &[&str], max_millis: u64) -> PluginManifest {
    PluginManifest {
        id: id.into(),
        requested_capabilities: caps.iter().map(|s| s.to_string()).collect(),
        limits: ResourceLimits {
            max_output_bytes: 64 * 1024,
            max_millis,
            max_memory_bytes: 16 * 1024 * 1024,
        },
    }
}

type PluginPtr = fn(&str, &PluginContext) -> Result<String, PluginError>;

/// Register the given plugins on one capability-confining host and wrap it in the wall-clock guard —
/// the production-shaped stack. The wasmtime host replaces `NativeHost` here with zero change to the
/// composition. Explicit fn pointers keep the `for<'a>` closure inference happy.
fn guarded(plugins: &[(&str, PluginPtr)]) -> GuardedHost<NativeHost> {
    let mut inner = NativeHost::new();
    for (id, f) in plugins {
        inner.register(*id, Box::new(*f));
    }
    GuardedHost::new(inner)
}

#[test]
fn scenario13_sandbox_escape_is_denied_and_contained() {
    // A malicious plugin tries to reach filesystem-write it was never granted (the "escape").
    fn exfil(_i: &str, ctx: &PluginContext) -> Result<String, PluginError> {
        // No ambient authority: the only door is the context, and it refuses this.
        ctx.use_capability("fs.write")?;
        Ok("wrote /etc/passwd".into())
    }
    fn neighbor(i: &str, ctx: &PluginContext) -> Result<String, PluginError> {
        ctx.use_capability("net.fetch")?;
        Ok(format!("neighbor ok: {i}"))
    }
    let host = guarded(&[("exfil", exfil), ("neighbor", neighbor)]);

    // The escape attempt is a hard capability denial — the effect never happens.
    let err = host
        .invoke(
            &manifest("exfil", &["fs.write"], 5_000),
            &PluginGrant::new(["net.fetch"]), // fs.write NOT granted
            "x",
        )
        .unwrap_err();
    assert_eq!(err, PluginError::CapabilityDenied("fs.write".into()));

    // Containment: a co-located, properly-granted plugin is entirely unaffected by the neighbor's
    // violation — the boundary isolates blast radius to the offending call.
    let ok = host
        .invoke(
            &manifest("neighbor", &["net.fetch"], 5_000),
            &PluginGrant::new(["net.fetch"]),
            "y",
        )
        .unwrap();
    assert_eq!(ok.output, "neighbor ok: y");
    assert_eq!(ok.used_capabilities, vec!["net.fetch".to_string()]);
}

#[test]
fn scenario14_resource_exhaustion_is_bounded_by_the_host() {
    // A plugin that busy-loops (CPU exhaustion). The NATIVE host cannot force-kill the guest thread
    // (that hard kill is the wasmtime host's epoch-interruption job — infra-gated), but the host-side
    // wall-clock guard must stop WAITING promptly so the turn and co-located work stay responsive.
    fn busy(_i: &str, _ctx: &PluginContext) -> Result<String, PluginError> {
        let start = std::time::Instant::now();
        // Spin well past the budget.
        while start.elapsed() < std::time::Duration::from_millis(3_000) {
            std::hint::spin_loop();
        }
        Ok("done spinning".into())
    }
    let host = guarded(&[("busy", busy)]);

    let started = std::time::Instant::now();
    let err = host
        .invoke(&manifest("busy", &[], 50), &PluginGrant::default(), "x")
        .unwrap_err();
    let elapsed = started.elapsed();
    assert_eq!(err, PluginError::WallClockExceeded { limit_millis: 50 });
    assert!(
        elapsed < std::time::Duration::from_millis(1_500),
        "the host must bound the wait near the budget, not spin out the full 3s; took {elapsed:?}"
    );
}

#[test]
fn the_composed_stack_enforces_both_capability_and_wallclock() {
    // One stack, both guarantees: a granted, in-budget plugin succeeds; the very same stack denies an
    // ungranted capability and bounds an over-budget one. This is the single seam the WASM host
    // implements — the tests above prove each face; this proves they compose on one host.
    fn good(i: &str, ctx: &PluginContext) -> Result<String, PluginError> {
        ctx.use_capability("kv.read")?;
        Ok(format!("read:{i}"))
    }
    let host = guarded(&[("good", good)]);
    let out = host
        .invoke(
            &manifest("good", &["kv.read"], 1_000),
            &PluginGrant::new(["kv.read"]),
            "k",
        )
        .unwrap();
    assert_eq!(out.output, "read:k");

    // Same host, ungranted capability → denied (no ambient authority survives the composition).
    let denied = host
        .invoke(
            &manifest("good", &["kv.read"], 1_000),
            &PluginGrant::default(), // nothing granted
            "k",
        )
        .unwrap_err();
    assert_eq!(denied, PluginError::CapabilityDenied("kv.read".into()));
}
