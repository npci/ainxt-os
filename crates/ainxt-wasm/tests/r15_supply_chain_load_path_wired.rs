// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R15 §3.4 — `ainxt_plugin::supply_chain::verify_for_load` is wired into an ACTUAL plugin load path
//! via `load_verified`, exercised here against the real `WasmPluginHost::register`. Fail-before:
//! `verify_for_load` was a pure function nothing ever called before registering a plugin — a caller
//! could (accidentally or not) register a plugin into a real host regardless of its verdict, or skip
//! verification entirely; `r11_plugin_supply_chain.rs` only proved the pure function's own logic in
//! isolation. Pass-after: `load_verified` makes registration CONDITIONAL on every §3.4 check, proven
//! here by actually invoking the registered plugin afterward — a refused load is not merely "returned
//! an error", it is PROVABLY never registered (a subsequent invoke is `NotFound`).

use ainxt_plugin::supply_chain::{
    load_verified, ControlLock, HmacSigner, HmacVerifier, LockEntry, PublisherAllowList,
    SignedPlugin,
};
use ainxt_plugin::{PluginError, PluginGrant, PluginHost, PluginManifest, ResourceLimits};
use ainxt_wasm::WasmPluginHost;

/// A real, tiny, runnable WASM module (as inline WAT text — the sandbox's `wat` feature treats it
/// identically to a compiled binary) so the test proves an end-to-end run, not just a hash check.
const ADD_ONE_WAT: &str = r#"
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

fn manifest() -> PluginManifest {
    PluginManifest {
        id: "acme.echo".into(),
        requested_capabilities: vec![],
        limits: ResourceLimits::default(),
    }
}

fn signed_and_locked(
    wasm: &[u8],
    m: &PluginManifest,
) -> (SignedPlugin, ControlLock, PublisherAllowList, HmacVerifier) {
    let signer = HmacSigner::new("acme", "acme-secret");
    let signed = SignedPlugin::sign(wasm, m, "1.0.0", &signer);
    let mut lock = ControlLock::new();
    lock.pin(LockEntry {
        plugin_id: m.id.clone(),
        version: "1.0.0".into(),
        content_hash: signed.artifact_hash.clone(),
        signer: "acme".into(),
    });
    let allow = PublisherAllowList::new(["acme"]);
    let verifier = HmacVerifier::new().with_key("acme", "acme-secret");
    (signed, lock, allow, verifier)
}

#[test]
fn a_verified_plugin_is_registered_and_actually_runs() {
    let wasm = ADD_ONE_WAT.as_bytes().to_vec();
    let m = manifest();
    let (signed, lock, allow, verifier) = signed_and_locked(&wasm, &m);

    let mut host = WasmPluginHost::new();
    load_verified(wasm, &signed, &lock, &allow, &verifier, |id, bytes| {
        host.register(id, bytes);
    })
    .expect("a correctly signed, pinned, allow-listed plugin loads");

    // Provably registered: it actually runs through the PluginHost seam.
    let out = host
        .invoke(&m, &PluginGrant::default(), "hello-verified")
        .expect("the loaded plugin runs");
    assert_eq!(out.output, "hello-verified");
}

#[test]
fn a_tampered_binary_is_never_registered() {
    let wasm = ADD_ONE_WAT.as_bytes().to_vec();
    let m = manifest();
    let (signed, lock, allow, verifier) = signed_and_locked(&wasm, &m);

    // The bytes actually fetched at load time differ from what was signed (tamper after signing).
    let mut tampered = ADD_ONE_WAT.as_bytes().to_vec();
    tampered.extend_from_slice(b" ;; extra bytes injected post-signature");

    let mut host = WasmPluginHost::new();
    let mut registered = false;
    let err = load_verified(tampered, &signed, &lock, &allow, &verifier, |id, bytes| {
        registered = true;
        host.register(id, bytes);
    })
    .expect_err("a tampered binary must be refused");
    assert!(matches!(
        err,
        ainxt_plugin::supply_chain::LoadError::SignedHashMismatch
    ));
    assert!(
        !registered,
        "the register closure must NEVER run on a refused load"
    );

    // Provably never registered: invoking it returns NotFound, not a run of tampered code.
    let invoke_err = host.invoke(&m, &PluginGrant::default(), "x").unwrap_err();
    assert_eq!(invoke_err, PluginError::NotFound("acme.echo".to_string()));
}

#[test]
fn a_publisher_revoked_after_signing_is_never_registered_even_though_it_was_valid_before() {
    let wasm = ADD_ONE_WAT.as_bytes().to_vec();
    let m = manifest();
    let (signed, lock, mut allow, verifier) = signed_and_locked(&wasm, &m);

    // The publisher's key is compromised and removed from the allow-list AFTER the artifact was
    // signed and pinned — §3.4's "re-verified on EVERY load, not only at install".
    allow.revoke("acme");

    let mut host = WasmPluginHost::new();
    let mut registered = false;
    let err = load_verified(wasm, &signed, &lock, &allow, &verifier, |id, bytes| {
        registered = true;
        host.register(id, bytes);
    })
    .expect_err("a revoked publisher must be refused even for a previously-valid artifact");
    assert!(matches!(
        err,
        ainxt_plugin::supply_chain::LoadError::PublisherNotAllowed(_)
    ));
    assert!(!registered);

    let invoke_err = host.invoke(&m, &PluginGrant::default(), "x").unwrap_err();
    assert_eq!(invoke_err, PluginError::NotFound("acme.echo".to_string()));
}

#[test]
fn an_unpinned_plugin_is_never_registered() {
    let wasm = ADD_ONE_WAT.as_bytes().to_vec();
    let m = manifest();
    let (signed, _lock, allow, verifier) = signed_and_locked(&wasm, &m);
    let empty_lock = ControlLock::new(); // no control.lock entry for this plugin id

    let mut host = WasmPluginHost::new();
    let mut registered = false;
    let err = load_verified(
        wasm,
        &signed,
        &empty_lock,
        &allow,
        &verifier,
        |id, bytes| {
            registered = true;
            host.register(id, bytes);
        },
    )
    .expect_err("a plugin with no control.lock entry must be refused");
    assert!(matches!(
        err,
        ainxt_plugin::supply_chain::LoadError::NotInLock(_)
    ));
    assert!(!registered);
    assert!(host.invoke(&m, &PluginGrant::default(), "x").is_err());
}
