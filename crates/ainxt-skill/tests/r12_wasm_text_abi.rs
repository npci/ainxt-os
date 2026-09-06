// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-12 closure (LOW): the WASM execution-skill ABI can now pass the **user-turn text** to the
//! guest. `WasmSkillExecutor::register_text` binds a text-ABI module that receives the user's turn via
//! the guest's own linear memory (`alloc` + `(ptr,len)->(out_ptr,out_len)`) and returns UTF-8 text
//! straight into `## Context` — closing the earlier limit where a sandboxed skill could only take
//! numeric `argN` args and never saw the user's words.
//!
//! Fails before `register_text` / `WasmSandbox::run_with_input` existed (the only ABI was numeric, so
//! there was no way to hand a guest the turn text); passes after. Still ZERO ambient authority
//! (empty import set), fuel/memory/output-capped, fail-closed.

use ainxt_skill::{SkillManifest, SkillRegistry, SkillRuntime, WasmSkillExecutor};

/// Inline WAT: a text-ABI module. `alloc` is a bump allocator over the module's own memory; `shift`
/// reads the `len` input bytes at `ptr`, writes each byte +1 (a Caesar shift) into a fresh region,
/// and returns `(out_ptr, out_len)`. The +1 transform PROVES the guest actually read every input
/// byte (a pure echo of the host's pointer could not).
const WAT_SHIFT: &str = r#"(module
  (memory (export "memory") 1)
  (global $bump (mut i32) (i32.const 1024))
  (func (export "alloc") (param $len i32) (result i32)
    (local $p i32)
    (local.set $p (global.get $bump))
    (global.set $bump (i32.add (global.get $bump) (local.get $len)))
    (local.get $p))
  (func (export "shift") (param $ptr i32) (param $len i32) (result i32 i32)
    (local $out i32) (local $i i32)
    (local.set $out (global.get $bump))
    (global.set $bump (i32.add (global.get $bump) (local.get $len)))
    (block $done
      (loop $l
        (br_if $done (i32.ge_u (local.get $i) (local.get $len)))
        (i32.store8
          (i32.add (local.get $out) (local.get $i))
          (i32.add (i32.load8_u (i32.add (local.get $ptr) (local.get $i))) (i32.const 1)))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $l)))
    (local.get $out) (local.get $len)))"#;

#[test]
fn r12_wasm_text_abi_passes_user_turn_text_to_the_guest() {
    let mut exec = WasmSkillExecutor::with_defaults().unwrap();
    exec.register_text("shifter", WAT_SHIFT.as_bytes().to_vec(), "alloc", "shift");
    assert!(exec.is_registered("shifter"));

    // The user's turn text reaches the guest; the guest transforms it and returns TEXT.
    use ainxt_skill::SkillExecutor;
    let m = SkillManifest::execution("shifter", "");
    let out = exec.execute(&m, "abc").unwrap();
    assert_eq!(
        out, "bcd",
        "the guest read the user text byte-by-byte and returned +1 of each"
    );

    // End-to-end through the SkillRuntime: the transformed user text lands in the ## Context block.
    let mut reg = SkillRegistry::new();
    reg.register(SkillManifest::execution("shifter", ""));
    let rt = SkillRuntime::new(reg, Box::new(exec));
    let prepared = rt.prepare(&["shifter".to_string()], "HAL").unwrap();
    let block = prepared.context_block();
    assert!(
        block.starts_with("## Context") && block.contains("### shifter") && block.contains("IBM"),
        "the sandboxed skill's TEXT output (shift of the user turn 'HAL') must reach ## Context: {block}"
    );
}

#[test]
fn r12_wasm_text_abi_handles_empty_and_multibyte_input() {
    use ainxt_skill::SkillExecutor;
    let exec = WasmSkillExecutor::with_defaults().unwrap().with_text(
        "shifter",
        WAT_SHIFT.as_bytes().to_vec(),
        "alloc",
        "shift",
    );
    // Empty input → empty output (no bytes read, valid UTF-8).
    let m = SkillManifest::execution("shifter", "");
    assert_eq!(exec.execute(&m, "").unwrap(), "");
    // A longer turn is shifted end to end.
    assert_eq!(exec.execute(&m, "IBM9000").unwrap(), "JCN:111");
}

#[test]
fn r12_wasm_text_abi_fails_closed_on_unregistered() {
    use ainxt_skill::{SkillError, SkillExecutor};
    let exec = WasmSkillExecutor::with_defaults().unwrap();
    let m = SkillManifest::execution("ghost", "");
    let err = exec.execute(&m, "hello").unwrap_err();
    assert!(
        matches!(&err, SkillError::Execution { message, .. } if message.contains("no WASM module registered")),
        "an unregistered text-ABI skill must fail closed, got {err:?}"
    );
}
