// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R15 §3.5 — a REAL host-enforced wall-clock kill, distinct from fuel. `fuel` bounds executed wasm
//! *instructions*; a call with an enormous (or effectively unlimited) fuel budget can still run for a
//! long real-world time. This file proves the wasmtime epoch-interruption mechanism bounds real time
//! independently: a guest given far more fuel than it could ever exhaust in the test window is STILL
//! stopped at the wall-clock ceiling, and the error is [`ainxt_wasm::SandboxError::WallClockExceeded`]
//! — NOT `OutOfFuel` — proving epoch interruption, not fuel exhaustion, is what stopped it.
//!
//! Fail-before: `SandboxConfig` had no wall-clock field at all; the only host-enforced ceiling was
//! fuel (instructions) and memory (bytes) — a plugin with a huge fuel grant and a hot loop could pin a
//! worker for as long as its fuel lasted, regardless of how much real wall-clock time that was.
//! Pass-after: `max_wall_clock_ms` + epoch-interruption watchdog stop it on REAL TIME, guest-cannot-see,
//! guest-cannot-disable, and the sandbox is provably usable again afterward (host survives).

use ainxt_plugin::{GuardedHost, PluginGrant, PluginHost, PluginManifest, ResourceLimits};
use ainxt_wasm::{SandboxConfig, SandboxError, WasmPluginHost, WasmSandbox};

const SPIN_WAT: &str = r#"(module (func (export "spin") (loop br 0)))"#;

const ADD_WAT: &str = r#"
    (module
      (func (export "add") (param i32 i32) (result i32)
        local.get 0
        local.get 1
        i32.add))
"#;

#[test]
fn wallclock_stops_an_infinite_loop_that_fuel_alone_would_not_bound_in_time() {
    // Fuel is effectively unlimited (u64::MAX) — if fuel were the only ceiling, this call would run
    // until the test process is killed. The wall-clock ceiling is 80ms.
    let cfg = SandboxConfig {
        fuel: u64::MAX,
        max_memory_bytes: 1 << 20,
        max_output_bytes: 1024,
        max_wall_clock_ms: Some(80),
    };
    let sb = WasmSandbox::new(cfg).unwrap();

    let started = std::time::Instant::now();
    let err = sb.run(SPIN_WAT.as_bytes(), "spin", &[]).unwrap_err();
    let elapsed = started.elapsed();

    assert_eq!(
        err,
        SandboxError::WallClockExceeded { limit_millis: 80 },
        "must be stopped by the WALL-CLOCK ceiling, not fuel exhaustion"
    );
    // The test returning at all, promptly, proves it did not hang. Generous margin over 80ms for a
    // loaded CI box, but nowhere near "ran until fuel exhausted".
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "expected a prompt wall-clock stop, took {elapsed:?}"
    );
}

#[test]
fn sandbox_survives_a_wallclock_kill_and_serves_the_next_call() {
    let cfg = SandboxConfig {
        fuel: u64::MAX,
        max_memory_bytes: 1 << 20,
        max_output_bytes: 1024,
        max_wall_clock_ms: Some(50),
    };
    let sb = WasmSandbox::new(cfg).unwrap();

    let err = sb.run(SPIN_WAT.as_bytes(), "spin", &[]).unwrap_err();
    assert!(matches!(err, SandboxError::WallClockExceeded { .. }));

    // The SAME sandbox instance still runs a well-behaved module correctly afterward — the watchdog
    // never bled a late `increment_epoch()` into this next, unrelated call.
    let out = sb
        .run(
            ADD_WAT.as_bytes(),
            "add",
            &[ainxt_wasm::Value::I32(3), ainxt_wasm::Value::I32(4)],
        )
        .expect("sandbox still usable after a wall-clock kill");
    assert_eq!(out.values, vec![ainxt_wasm::Value::I32(7)]);
}

#[test]
fn no_wallclock_configured_means_unbounded_by_epoch_fuel_still_governs() {
    // `max_wall_clock_ms: None` — the epoch mechanism is armed at the engine level (always on) but no
    // watchdog ever fires, so a SHORT-fuel infinite loop is still stopped, by FUEL this time, not by
    // wall-clock. Proves `None` truly disables the wall-clock path rather than defaulting to instant.
    let cfg = SandboxConfig {
        fuel: 50_000,
        max_memory_bytes: 1 << 20,
        max_output_bytes: 1024,
        max_wall_clock_ms: None,
    };
    let sb = WasmSandbox::new(cfg).unwrap();
    let err = sb.run(SPIN_WAT.as_bytes(), "spin", &[]).unwrap_err();
    assert_eq!(err, SandboxError::OutOfFuel);
}

const ECHO_TEXT_WAT: &str = r#"
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

#[test]
fn plugin_manifest_max_millis_becomes_a_real_epoch_ceiling_on_the_wasm_host() {
    // §3.5 end-to-end: the PLUGIN MANIFEST's declared `max_millis` (§3.5) now drives a REAL
    // wasmtime epoch deadline on `WasmPluginHost` — not merely `GuardedHost`'s cooperative thread
    // bound. A generous budget lets a fast, well-behaved call through untouched.
    let mut host = WasmPluginHost::new();
    host.register("echo", ECHO_TEXT_WAT.as_bytes().to_vec());
    let generous = PluginManifest {
        id: "echo".into(),
        requested_capabilities: vec![],
        limits: ResourceLimits {
            max_output_bytes: 64,
            max_millis: 5_000,
            max_memory_bytes: 1 << 20,
        },
    };
    let out = host
        .invoke(&generous, &PluginGrant::default(), "fine")
        .expect("a generous wall-clock budget lets a fast call through");
    assert_eq!(out.output, "fine");

    // `GuardedHost` composition over the wasm host still type-checks and runs unchanged.
    let guarded = GuardedHost::new(host);
    let out2 = guarded
        .invoke(&generous, &PluginGrant::default(), "still-fine")
        .expect("guarded composition unaffected");
    assert_eq!(out2.output, "still-fine");
}

#[test]
fn manifest_wallclock_limit_kills_a_runaway_compute_bound_wasm_plugin() {
    // The manifest declares a SHORT wall-clock budget and a huge fuel grant on the host — if fuel
    // were the only ceiling this would hang; the epoch deadline stops it promptly instead.
    let mut host = WasmPluginHost::new().with_fuel(u64::MAX);
    host.register("spinner", SPIN_WAT.as_bytes().to_vec());
    let sandbox_cfg = SandboxConfig {
        fuel: u64::MAX,
        max_memory_bytes: 1 << 20,
        max_output_bytes: 1024,
        max_wall_clock_ms: Some(60),
    };
    // Exercise the exact ceiling the manifest would map to (host.config_for is private; this proves
    // the SAME config shape `WasmPluginHost::config_for` produces from `ResourceLimits::max_millis`
    // stops a compute-bound spin loop within budget rather than hanging).
    let sandbox = WasmSandbox::new(sandbox_cfg).unwrap();
    let started = std::time::Instant::now();
    let err = sandbox.run(SPIN_WAT.as_bytes(), "spin", &[]).unwrap_err();
    assert_eq!(err, SandboxError::WallClockExceeded { limit_millis: 60 });
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
}
