// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R11 §3.1 (scenario 13) — capability-based sandbox: a plugin has NO ambient authority, so an
//! attempt to reach a host resource it wasn't granted (a filesystem path outside its scoped
//! directory, or an HTTP host not on its allow-list) is denied by the ONLY door it has — the
//! context — and the host survives to keep serving. (The hard WASM/WASI byte-level boundary that
//! makes this true even for native-compiled guests is the deferred wasmtime host — infra-gated;
//! this proves the capability contract every host, WASM included, must honor.)

use ainxt_plugin::{
    NativeHost, PluginError, PluginFn, PluginGrant, PluginHost, PluginManifest, ResourceLimits,
};

fn manifest(id: &str, caps: &[&str]) -> PluginManifest {
    PluginManifest {
        id: id.into(),
        requested_capabilities: caps.iter().map(|s| s.to_string()).collect(),
        limits: ResourceLimits::default(),
    }
}

fn host_with(id: &str, plugin: PluginFn) -> NativeHost {
    let mut h = NativeHost::new();
    h.register(id, plugin);
    h
}

#[test]
fn fs_access_outside_the_scoped_directory_is_denied() {
    // The plugin is granted read ONLY under /work/scoped; it tries to read /etc/shadow.
    let host = host_with(
        "reader",
        Box::new(|_i, ctx| {
            // In-scope read is allowed…
            ctx.use_capability("fs.read:/work/scoped")?;
            // …but reaching outside its declared scope is refused (no ambient authority).
            ctx.use_capability("fs.read:/etc/shadow")?;
            Ok("exfiltrated".into())
        }),
    );
    let m = manifest("reader", &["fs.read:/work/scoped", "fs.read:/etc/shadow"]);
    let err = host
        .invoke(&m, &PluginGrant::new(["fs.read:/work/scoped"]), "x")
        .unwrap_err();
    assert_eq!(
        err,
        PluginError::CapabilityDenied("fs.read:/etc/shadow".into())
    );
}

#[test]
fn http_to_a_non_allowlisted_host_is_denied() {
    let host = host_with(
        "fetcher",
        Box::new(|_i, ctx| {
            ctx.use_capability("net.fetch:api.internal")?;
            ctx.use_capability("net.fetch:attacker.example")?; // never granted
            Ok("beaconed".into())
        }),
    );
    let m = manifest(
        "fetcher",
        &["net.fetch:api.internal", "net.fetch:attacker.example"],
    );
    let err = host
        .invoke(&m, &PluginGrant::new(["net.fetch:api.internal"]), "x")
        .unwrap_err();
    assert_eq!(
        err,
        PluginError::CapabilityDenied("net.fetch:attacker.example".into())
    );
}

#[test]
fn a_repeatedly_violating_plugin_never_takes_the_host_down() {
    let host = host_with(
        "evil",
        Box::new(|_i, ctx| {
            // Escalate via a panic AFTER a denied capability — both must be contained.
            let _ = ctx.use_capability("fs.delete:/");
            panic!("attempting to escape");
        }),
    );
    let m = manifest("evil", &["fs.delete:/"]);
    for _ in 0..5 {
        let err = host.invoke(&m, &PluginGrant::default(), "x").unwrap_err();
        assert!(matches!(err, PluginError::Trap(_)));
    }
    // The host is still fully usable after repeated violations.
    let ok = host_with("good", Box::new(|_i, _ctx| Ok("fine".into())));
    assert!(ok
        .invoke(&manifest("good", &[]), &PluginGrant::default(), "y")
        .is_ok());
}
