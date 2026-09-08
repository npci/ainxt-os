// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-11 — **change-signature adapter-synthesis breadth** (`SEMANTIC_EDITING.md` §4 — "insert
//! defaults/adapters where needed"). The trailing-only `apply_change_signature` could express just
//! one shape (append a parameter + splice one adapter arg at every call). `apply_change_signature_ex`
//! broadens that to:
//!   * **leading / positional** parameter insertion (a new first `ctx`, or an insert at an index);
//!   * a **declaration-only defaulted parameter** that leaves every call site untouched — the common
//!     "add an optional knob with a default" refactor the trailing-only form could not do.
//!
//! Fail-before: `apply_change_signature_ex` / `ChangeSigSpec` / `ParamPosition` did not exist.

use ainxt_semantic::graph::SourceFile;
use ainxt_semantic::ops::{apply_change_signature_ex, ChangeSigSpec, ParamPosition};
use ainxt_semantic::{parse, Language};

fn rs(path: &str, src: &str) -> SourceFile {
    SourceFile::new(path, Language::Rust, src)
}

fn parses(src: &str) -> bool {
    !parse(src, Language::Rust).unwrap().root_node().has_error()
}

#[test]
fn r11_leading_parameter_insertion_at_decl_and_call_sites() {
    let lib = rs(
        "lib.rs",
        "pub fn charge(amount: i32) -> i32 {\n    amount\n}\n",
    );
    let main = rs(
        "main.rs",
        "fn run() -> i32 {\n    charge(10) + charge(20)\n}\n",
    );
    let spec = ChangeSigSpec {
        declaration_param: "ctx: &Ctx".into(),
        call_argument: Some("&ctx".into()),
        position: ParamPosition::Leading,
    };
    let edits = apply_change_signature_ex(&[lib, main], "charge", &spec, |_| 0).unwrap();
    let libe = edits.iter().find(|e| e.path == "lib.rs").unwrap();
    // The new parameter is FIRST, before the existing one.
    assert!(libe
        .new_content
        .contains("fn charge(ctx: &Ctx, amount: i32)"));
    let maine = edits.iter().find(|e| e.path == "main.rs").unwrap();
    assert!(maine.new_content.contains("charge(&ctx, 10)"));
    assert!(maine.new_content.contains("charge(&ctx, 20)"));
    assert!(parses(&libe.new_content) && parses(&maine.new_content));
}

#[test]
fn r11_declaration_only_defaulted_param_leaves_callers_untouched() {
    // Adding a defaulted parameter: the declaration changes, but existing call sites must NOT — they
    // still compile against the default. call_argument = None expresses exactly that.
    let src = "fn charge(amount: i32) -> i32 { amount }\nfn run() -> i32 { charge(10) }\n";
    let spec = ChangeSigSpec {
        declaration_param: "retries: i32".into(),
        call_argument: None,
        position: ParamPosition::Trailing,
    };
    let edits = apply_change_signature_ex(&[rs("a.rs", src)], "charge", &spec, |_| 0).unwrap();
    let e = &edits[0];
    assert!(e
        .new_content
        .contains("fn charge(amount: i32, retries: i32)"));
    // The call site is UNCHANGED — no adapter was spliced.
    assert!(e.new_content.contains("charge(10)"));
    assert!(!e.new_content.contains("charge(10,"));
}

#[test]
fn r11_positional_index_insertion_respects_nested_generics() {
    // Insert at index 1 (between the two existing params). The generic `Map<K, V>`'s inner comma must
    // NOT be treated as a parameter separator.
    let src = "fn f(a: i32, m: Map<K, V>) -> i32 { a }\nfn c() -> i32 { f(1, mk()) }\n";
    let spec = ChangeSigSpec {
        declaration_param: "b: bool".into(),
        call_argument: Some("true".into()),
        position: ParamPosition::Index(1),
    };
    let edits = apply_change_signature_ex(&[rs("a.rs", src)], "f", &spec, |_| 0).unwrap();
    let e = &edits[0];
    // `b: bool` landed between `a` and `m` — the generic stayed one argument.
    assert!(e
        .new_content
        .contains("fn f(a: i32, b: bool, m: Map<K, V>)"));
    assert!(e.new_content.contains("f(1, true, mk())"));
}
