// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R13 §3.1/§3.2/§3.5 — the **real** WASM sandbox proven behind the `ainxt_plugin::PluginHost` seam.
//!
//! `WasmPluginHost` is the concrete wasmtime implementation of the same trait `NativeHost` implements,
//! so the security-boundary composition (`GuardedHost<H>`) is unchanged whether the inner host is
//! native or WASM. These tests run the ACTUAL wasmtime engine (offline, via inline WAT — no external
//! .wasm) to pin: the isolation boundary (§3.1), per-invocation dependency/state isolation (§3.2), and
//! the hard resource ceilings (§3.5). The only thing separating this from the served path is the
//! Gate-#0 license review + a live runtime in the deploy image — the isolation code itself is real.

use ainxt_plugin::{
    GuardedHost, PluginError, PluginGrant, PluginHost, PluginManifest, ResourceLimits,
};
use ainxt_wasm::{SandboxConfig, SandboxError, Value, WasmPluginHost, WasmSandbox};

/// A guest that echoes its input back out through its OWN linear memory (text ABI): `alloc` bumps a
/// pointer, `run(ptr,len)` returns exactly `(ptr,len)` — the input is already sitting at `ptr`.
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

fn manifest(id: &str, caps: &[&str]) -> PluginManifest {
    PluginManifest {
        id: id.into(),
        requested_capabilities: caps.iter().map(|s| s.to_string()).collect(),
        limits: ResourceLimits::default(),
    }
}

#[test]
fn wasm_host_implements_the_seam_end_to_end() {
    let mut host = WasmPluginHost::new();
    host.register("echo", ECHO_WAT.as_bytes().to_vec());

    let out = host
        .invoke(
            &manifest("echo", &[]),
            &PluginGrant::default(),
            "settlement-batch-9",
        )
        .expect("wasm echo runs through the PluginHost seam");
    assert_eq!(out.output, "settlement-batch-9");
    // Zero ambient authority: the guest had no host imports, so it exercised no capability.
    assert!(out.used_capabilities.is_empty());
}

#[test]
fn the_real_wasm_host_composes_under_the_wallclock_guard_unchanged() {
    // The exact production-shaped stack from r12, but with the WASM host as the inner host instead of
    // NativeHost — proving the seam swap is transparent to the composition.
    let mut inner = WasmPluginHost::new();
    inner.register("echo", ECHO_WAT.as_bytes().to_vec());
    let host = GuardedHost::new(inner);

    let out = host
        .invoke(&manifest("echo", &[]), &PluginGrant::default(), "hello")
        .expect("guarded wasm host runs");
    assert_eq!(out.output, "hello");
}

#[test]
fn missing_module_is_not_found_through_the_seam() {
    let host = WasmPluginHost::new();
    let err = host
        .invoke(&manifest("ghost", &[]), &PluginGrant::default(), "x")
        .unwrap_err();
    assert_eq!(err, PluginError::NotFound("ghost".into()));
}

#[test]
fn ambient_authority_is_denied_at_the_boundary_via_the_seam() {
    // §3.1: a module importing a host function must fail — no ambient syscall surface. Through the seam
    // this surfaces as an isolated Trap (the host survives).
    let evil = r#"
        (module
          (import "env" "exfiltrate" (func (param i32)))
          (memory (export "memory") 1)
          (func (export "alloc") (param i32) (result i32) i32.const 0)
          (func (export "run") (param i32 i32) (result i32 i32)
            i32.const 0 i32.const 0))
    "#;
    let mut host = WasmPluginHost::new();
    host.register("evil", evil.as_bytes().to_vec());
    let err = host
        .invoke(&manifest("evil", &[]), &PluginGrant::default(), "x")
        .unwrap_err();
    assert!(
        matches!(err, PluginError::Trap(_)),
        "an ungranted import must be denied at instantiation, got {err:?}"
    );
    // Host survives — a subsequent good plugin still runs on the same host.
    host.register("echo", ECHO_WAT.as_bytes().to_vec());
    assert_eq!(
        host.invoke(&manifest("echo", &[]), &PluginGrant::default(), "ok")
            .unwrap()
            .output,
        "ok"
    );
}

#[test]
fn output_cap_is_enforced_through_the_seam() {
    // §3.5: a tiny output ceiling rejects an over-cap result as the seam's OutputTooLarge.
    let mut host = WasmPluginHost::new();
    host.register("echo", ECHO_WAT.as_bytes().to_vec());
    let m = PluginManifest {
        id: "echo".into(),
        requested_capabilities: vec![],
        limits: ResourceLimits {
            max_output_bytes: 4,
            ..Default::default()
        },
    };
    let err = host
        .invoke(&m, &PluginGrant::default(), "way-too-long-for-four-bytes")
        .unwrap_err();
    assert!(
        matches!(err, PluginError::OutputTooLarge { limit: 4, .. }),
        "expected OutputTooLarge, got {err:?}"
    );
}

#[test]
fn dependency_isolation_fresh_instance_state_never_carries_across_invocations() {
    // §3.2: a module with a MUTABLE global that increments per call. Because every invocation gets a
    // fresh Store+Instance, the counter resets — call N returns 1, never N. One plugin's state can
    // never accumulate or leak into the next run.
    let counter = r#"
        (module
          (global $c (mut i32) (i32.const 0))
          (func (export "tick") (result i32)
            global.get $c
            i32.const 1
            i32.add
            global.set $c
            global.get $c))
    "#;
    let sb = WasmSandbox::new(SandboxConfig::default()).unwrap();
    for _ in 0..3 {
        let out = sb.run(counter.as_bytes(), "tick", &[]).expect("tick runs");
        // Always 1 — a fresh instance each time, no shared mutable state across invocations.
        assert_eq!(out.values, vec![Value::I32(1)]);
    }
}

#[test]
fn out_of_fuel_maps_to_an_isolated_trap_not_a_hang() {
    // §3.5: a bounded fuel budget turns an infinite loop into a clean SandboxError::OutOfFuel, which the
    // seam surfaces as an isolated Trap — the test returning at all proves it did not hang.
    let cfg = SandboxConfig {
        fuel: 100_000,
        max_memory_bytes: 1 << 20,
        max_output_bytes: 1024,
        max_wall_clock_ms: None,
    };
    let sb = WasmSandbox::new(cfg).unwrap();
    let spin = r#"(module (func (export "spin") (loop br 0)))"#;
    assert_eq!(
        sb.run(spin.as_bytes(), "spin", &[]).unwrap_err(),
        SandboxError::OutOfFuel
    );
}
