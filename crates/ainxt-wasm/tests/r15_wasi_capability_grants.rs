// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R15 §3.1 — the sandbox is a CAPABILITY model, not merely deny-all. Every prior test in this crate
//! proves the DENY half (an ungranted import fails to instantiate). This file proves the GRANT half:
//! a call that IS granted `fs.read:<root>` or `kv:<prefix>` gets a real, host-enforced, SCOPED host
//! function — a guest that tries to escape the scope (path traversal, an out-of-prefix key) is refused
//! by the HOST, never by the guest's own cooperation — and a call that is NOT granted still fails to
//! instantiate exactly as before.
//!
//! Fail-before: `WasmPluginHost`/`WasmSandbox` exposed NO host imports ever (deny-all, unconditionally)
//! — a plugin that legitimately needed a scoped filesystem read or a KV slice had nowhere to get one,
//! so "capability-based" was aspirational. Pass-after: `GrantedCapabilities` + `Linker`-based
//! instantiation make specific, scoped authority real and host-enforced.

use ainxt_plugin::{PluginError, PluginGrant, PluginHost, PluginManifest, ResourceLimits};
use ainxt_wasm::{
    FsReadCapability, GrantedCapabilities, KvCapability, KvStore, SandboxConfig, WasmPluginHost,
    WasmSandbox,
};

/// A guest that reads its input (treated as a path) via the granted `env.fs_read` capability and
/// echoes the file's content back. `alloc` bump-allocates in [4096, ...); the fixed output buffer for
/// `fs_read` lives at a disjoint offset (1024) so it never collides with the input the harness wrote.
const FS_READ_WAT: &str = r#"
    (module
      (import "env" "fs_read" (func $fs_read (param i32 i32 i32 i32) (result i32)))
      (memory (export "memory") 2)
      (global $bump (mut i32) (i32.const 4096))
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
        (local $n i32)
        local.get $ptr
        local.get $len
        i32.const 1024
        i32.const 512
        call $fs_read
        local.set $n
        i32.const 1024
        local.get $n))
"#;

/// A guest exporting two entrypoints sharing the granted `env.kv_set`/`env.kv_get` capability:
/// `run_set(key_ptr,key_len)` stores a fixed 12-byte constant ("stored-value", at data offset 2048)
/// under the given key; `run_get(key_ptr,key_len)` reads it back into a buffer at offset 3072.
const KV_WAT: &str = r#"
    (module
      (import "env" "kv_set" (func $kv_set (param i32 i32 i32 i32) (result i32)))
      (import "env" "kv_get" (func $kv_get (param i32 i32 i32 i32) (result i32)))
      (memory (export "memory") 2)
      (data (i32.const 2048) "stored-value")
      (global $bump (mut i32) (i32.const 4096))
      (func (export "alloc") (param $len i32) (result i32)
        (local $p i32)
        global.get $bump
        local.set $p
        global.get $bump
        local.get $len
        i32.add
        global.set $bump
        local.get $p)
      (func (export "run_set") (param $ptr i32) (param $len i32) (result i32 i32)
        (local $n i32)
        local.get $ptr
        local.get $len
        i32.const 2048
        i32.const 12
        call $kv_set
        local.set $n
        i32.const 0
        local.get $n)
      (func (export "run_get") (param $ptr i32) (param $len i32) (result i32 i32)
        (local $n i32)
        local.get $ptr
        local.get $len
        i32.const 3072
        i32.const 512
        call $kv_get
        local.set $n
        i32.const 3072
        local.get $n))
"#;

fn write_file(dir: &std::path::Path, name: &str, content: &str) {
    std::fs::write(dir.join(name), content).expect("write fixture file");
}

// ---------------- §3.1 fs.read: granted, scoped, host-enforced ----------------

#[test]
fn granted_fs_read_reads_a_file_inside_the_scoped_root() {
    let dir = std::env::temp_dir().join(format!("ainxt-wasm-r15-fs-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    write_file(&dir, "greeting.txt", "hello-from-scoped-fs");

    let sandbox = WasmSandbox::new(SandboxConfig::default()).unwrap();
    let caps = GrantedCapabilities::none().with_fs_read(FsReadCapability::new(&dir).unwrap());

    let (out, used) = sandbox
        .run_with_capabilities(
            FS_READ_WAT.as_bytes(),
            "alloc",
            "run",
            "greeting.txt",
            &caps,
        )
        .expect("granted, in-scope read succeeds");
    assert_eq!(out.text, "hello-from-scoped-fs");
    assert_eq!(
        used,
        vec!["fs.read"],
        "the guest actually exercised fs.read"
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn granted_fs_read_refuses_a_path_traversal_escape() {
    let dir = std::env::temp_dir().join(format!("ainxt-wasm-r15-fs-escape-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // A secret OUTSIDE the scoped root, one level up.
    write_file(
        dir.parent().unwrap(),
        "ainxt-wasm-r15-secret.txt",
        "top-secret",
    );

    let sandbox = WasmSandbox::new(SandboxConfig::default()).unwrap();
    let caps = GrantedCapabilities::none().with_fs_read(FsReadCapability::new(&dir).unwrap());

    // The guest asks for the escape path; the fs_read capability IS granted, but the HOST refuses the
    // specific path because it resolves outside the scoped root — a negative host result surfaces as
    // an isolated Trapped error, never a silent success and never a crash.
    let err = sandbox
        .run_with_capabilities(
            FS_READ_WAT.as_bytes(),
            "alloc",
            "run",
            "../ainxt-wasm-r15-secret.txt",
            &caps,
        )
        .unwrap_err();
    assert!(
        matches!(err, ainxt_wasm::SandboxError::Trapped(_)),
        "path traversal must be refused by the host, got {err:?}"
    );

    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_file(dir.parent().unwrap().join("ainxt-wasm-r15-secret.txt")).ok();
}

#[test]
fn granted_fs_read_reports_not_found_for_a_missing_in_scope_file() {
    let dir =
        std::env::temp_dir().join(format!("ainxt-wasm-r15-fs-missing-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    let sandbox = WasmSandbox::new(SandboxConfig::default()).unwrap();
    let caps = GrantedCapabilities::none().with_fs_read(FsReadCapability::new(&dir).unwrap());

    let err = sandbox
        .run_with_capabilities(
            FS_READ_WAT.as_bytes(),
            "alloc",
            "run",
            "does-not-exist.txt",
            &caps,
        )
        .unwrap_err();
    assert!(matches!(err, ainxt_wasm::SandboxError::Trapped(_)));

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn ungranted_fs_read_fails_to_instantiate_not_merely_denied_at_call_time() {
    // No `fs_read` capability granted at all — the Linker never defines the import, so the module
    // fails at INSTANTIATION, before any guest code runs (zero ambient authority, §3.1's other half).
    let sandbox = WasmSandbox::new(SandboxConfig::default()).unwrap();
    let caps = GrantedCapabilities::none();
    let err = sandbox
        .run_with_capabilities(
            FS_READ_WAT.as_bytes(),
            "alloc",
            "run",
            "anything.txt",
            &caps,
        )
        .unwrap_err();
    assert!(
        matches!(err, ainxt_wasm::SandboxError::Instantiate(_)),
        "expected Instantiate (ungranted import), got {err:?}"
    );
}

// ---------------- §3.1 kv: granted, scoped, host-enforced ----------------

#[test]
fn granted_kv_set_then_get_round_trips_within_the_granted_prefix() {
    let store = KvStore::new();
    let sandbox = WasmSandbox::new(SandboxConfig::default()).unwrap();
    let caps = GrantedCapabilities::none().with_kv(KvCapability::new(store, "tenantA:"));

    let (set_out, used_set) = sandbox
        .run_with_capabilities(
            KV_WAT.as_bytes(),
            "alloc",
            "run_set",
            "tenantA:greeting",
            &caps,
        )
        .expect("set within the granted prefix succeeds");
    assert_eq!(set_out.text, "", "kv_set returns 0 (success) => empty text");
    assert_eq!(used_set, vec!["kv.set"]);

    let (get_out, used_get) = sandbox
        .run_with_capabilities(
            KV_WAT.as_bytes(),
            "alloc",
            "run_get",
            "tenantA:greeting",
            &caps,
        )
        .expect("get within the granted prefix succeeds");
    assert_eq!(get_out.text, "stored-value");
    assert_eq!(used_get, vec!["kv.get"]);
}

#[test]
fn kv_key_outside_the_granted_prefix_is_refused_by_the_host() {
    let store = KvStore::new();
    let sandbox = WasmSandbox::new(SandboxConfig::default()).unwrap();
    let caps = GrantedCapabilities::none().with_kv(KvCapability::new(store, "tenantA:"));

    // The capability IS granted, but this specific key is outside the granted prefix — the host
    // refuses it (never silently redirects into another tenant's slice).
    let err = sandbox
        .run_with_capabilities(
            KV_WAT.as_bytes(),
            "alloc",
            "run_get",
            "tenantB:secret",
            &caps,
        )
        .unwrap_err();
    assert!(matches!(err, ainxt_wasm::SandboxError::Trapped(_)));
}

#[test]
fn two_prefixes_sharing_one_store_never_see_each_others_keys() {
    // One shared backing store, two independently-scoped capabilities — the isolation is per-prefix,
    // not per-store.
    let store = KvStore::new();
    let sandbox = WasmSandbox::new(SandboxConfig::default()).unwrap();
    let caps_a = GrantedCapabilities::none().with_kv(KvCapability::new(store.clone(), "a:"));
    let caps_b = GrantedCapabilities::none().with_kv(KvCapability::new(store, "b:"));

    sandbox
        .run_with_capabilities(KV_WAT.as_bytes(), "alloc", "run_set", "a:x", &caps_a)
        .expect("tenant A writes its own key");

    // Tenant B, even with ITS OWN valid grant, cannot read tenant A's key (out of B's prefix).
    let err = sandbox
        .run_with_capabilities(KV_WAT.as_bytes(), "alloc", "run_get", "a:x", &caps_b)
        .unwrap_err();
    assert!(matches!(err, ainxt_wasm::SandboxError::Trapped(_)));
}

#[test]
fn ungranted_kv_fails_to_instantiate() {
    let sandbox = WasmSandbox::new(SandboxConfig::default()).unwrap();
    let caps = GrantedCapabilities::none();
    let err = sandbox
        .run_with_capabilities(KV_WAT.as_bytes(), "alloc", "run_get", "a:x", &caps)
        .unwrap_err();
    assert!(matches!(err, ainxt_wasm::SandboxError::Instantiate(_)));
}

// ---------------- §3.1 through the PluginHost seam (WasmPluginHost) ----------------

#[test]
fn wasm_plugin_host_grants_fs_read_from_a_grant_string_end_to_end() {
    let dir = std::env::temp_dir().join(format!("ainxt-wasm-r15-host-fs-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    write_file(&dir, "note.txt", "plugin-read-me");

    let mut host = WasmPluginHost::new();
    host.register("reader", FS_READ_WAT.as_bytes().to_vec());

    let manifest = PluginManifest {
        id: "reader".into(),
        requested_capabilities: vec!["fs.read".into()],
        limits: ResourceLimits::default(),
    };
    // The grant is a parameterized string: `fs.read:<root>`. Governance decides the root; the seam
    // never lets a plugin choose its own scope.
    let grant = PluginGrant::new([format!("fs.read:{}", dir.display())]);

    let out = host
        .invoke(&manifest, &grant, "note.txt")
        .expect("granted read succeeds");
    assert_eq!(out.output, "plugin-read-me");
    assert_eq!(out.used_capabilities, vec!["fs.read".to_string()]);

    // Same plugin, same manifest, but a grant with NO fs.read entry at all: the capability is never
    // resolved, so the import is never linked, and the module fails to instantiate — through the seam
    // this surfaces as an isolated Trap, not a silent no-op.
    let err = host
        .invoke(&manifest, &PluginGrant::default(), "note.txt")
        .unwrap_err();
    assert!(matches!(err, PluginError::Trap(_)));

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn wasm_plugin_host_requires_both_requested_and_granted_fs_read() {
    // The grant offers fs.read, but the MANIFEST never requested it — requested∩granted is empty, so
    // the capability is still not resolved (least privilege: a plugin cannot silently pick up an
    // ambient over-grant it never asked for).
    let dir =
        std::env::temp_dir().join(format!("ainxt-wasm-r15-host-unreq-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    write_file(&dir, "note.txt", "irrelevant");

    let mut host = WasmPluginHost::new();
    host.register("reader", FS_READ_WAT.as_bytes().to_vec());
    let manifest = PluginManifest {
        id: "reader".into(),
        requested_capabilities: vec![], // did NOT request fs.read
        limits: ResourceLimits::default(),
    };
    let grant = PluginGrant::new([format!("fs.read:{}", dir.display())]);

    let err = host.invoke(&manifest, &grant, "note.txt").unwrap_err();
    assert!(matches!(err, PluginError::Trap(_)));

    std::fs::remove_dir_all(&dir).ok();
}
