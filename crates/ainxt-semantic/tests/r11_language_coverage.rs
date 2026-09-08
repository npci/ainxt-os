// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-11 — **AST-precise capability coverage for the full declared language set**
//! (`SEMANTIC_EDITING.md` §6 / `CODE_REVIEW_PIPELINE.md` §10). Before this round the AST rung parsed
//! only Rust + Python; every other declared language silently degraded to structured/text patching.
//! These tests prove the design's core AST-precise capabilities — declaration-preferring
//! `find_function` (never a call site), byte-precise `replace_function`, `list_definitions`, and
//! cross-file `plan_rename_symbol` — now work for **Go, JavaScript, TypeScript, and Java**.
//!
//! Fail-before: with the old `Language::{Rust,Python}`-only enum these languages could not even be
//! named, so the ops could not be invoked at the AST rung at all.

use ainxt_semantic::graph::SourceFile;
use ainxt_semantic::ops::plan_rename_symbol;
use ainxt_semantic::{find_function, list_definitions, replace_function, DefKind, Language};

/// A caller that invokes the target textually BEFORE the target is defined — the "first `foo(` wins"
/// trap. `find_function` must return the *definition* span, never the earlier call site, in every
/// language.
fn assert_prefers_declaration(lang: Language, src: &str, name: &str, def_prefix: &str) {
    let span = find_function(src, lang, name)
        .unwrap()
        .unwrap_or_else(|| panic!("{lang:?}: definition `{name}` must be found"));
    let call_idx = src.find(&format!("{name}(")).unwrap();
    assert!(
        span.start_byte > call_idx,
        "{lang:?}: matched the call site at {call_idx}, not the definition at {}",
        span.start_byte
    );
    assert!(
        src[span.start_byte..].starts_with(def_prefix),
        "{lang:?}: span did not start at the `{def_prefix}` definition",
    );
}

#[test]
fn r11_go_ast_precise_find_replace_and_types() {
    let src = "package m\n\nfunc caller() int {\n    return target()\n}\n\nfunc target() int {\n    return 1\n}\n\ntype Ledger struct {\n    balance int\n}\n";
    assert_prefers_declaration(Language::Go, src, "target", "func target()");

    // Byte-precise replacement leaves the caller and the struct untouched.
    let out = replace_function(
        src,
        Language::Go,
        "target",
        "func target() int {\n    return 2\n}",
    )
    .unwrap();
    assert!(out.contains("func target() int {\n    return 2\n}"));
    assert!(out.contains("func caller() int {\n    return target()\n}"));
    assert!(out.contains("type Ledger struct"));
    assert!(!out.contains("return 1"));

    // list_definitions sees both funcs and the Go type (named on its `type_spec`).
    let defs = list_definitions(src, Language::Go).unwrap();
    let fns: Vec<&str> = defs
        .iter()
        .filter(|d| d.kind == DefKind::Function)
        .map(|d| d.name.as_str())
        .collect();
    assert_eq!(fns, vec!["caller", "target"]);
    assert!(defs
        .iter()
        .any(|d| d.kind == DefKind::Type && d.name == "Ledger"));
}

#[test]
fn r11_javascript_ast_precise_find_replace() {
    let src = "function caller() {\n    return target();\n}\n\nfunction target() {\n    return 1;\n}\n\nclass Ledger {\n    total() { return 0; }\n}\n";
    assert_prefers_declaration(Language::JavaScript, src, "target", "function target()");

    let out = replace_function(
        src,
        Language::JavaScript,
        "target",
        "function target() {\n    return 2;\n}",
    )
    .unwrap();
    assert!(out.contains("return 2;"));
    assert!(out.contains("function caller()"));
    assert!(!out.contains("return 1;"));

    // The class definition and its method are both listed.
    let defs = list_definitions(src, Language::JavaScript).unwrap();
    assert!(defs
        .iter()
        .any(|d| d.kind == DefKind::Type && d.name == "Ledger"));
    assert!(defs
        .iter()
        .any(|d| d.kind == DefKind::Function && d.name == "total"));
}

#[test]
fn r11_typescript_ast_precise_types_and_replace() {
    let src = "function caller(): number {\n    return target();\n}\n\nfunction target(): number {\n    return 1;\n}\n\ninterface Account {\n    id: string;\n}\n\nenum Status { Open, Closed }\n";
    assert_prefers_declaration(Language::TypeScript, src, "target", "function target()");

    let out = replace_function(
        src,
        Language::TypeScript,
        "target",
        "function target(): number {\n    return 2;\n}",
    )
    .unwrap();
    assert!(out.contains("return 2;"));
    assert!(out.contains("interface Account"));

    // TS type-level constructs are AST definitions: interface + enum both surface.
    let defs = list_definitions(src, Language::TypeScript).unwrap();
    assert!(defs
        .iter()
        .any(|d| d.kind == DefKind::Type && d.name == "Account"));
    assert!(defs
        .iter()
        .any(|d| d.kind == DefKind::Type && d.name == "Status"));
}

#[test]
fn r11_java_ast_precise_method_find_replace() {
    // Java has no free functions: `charge` is a method inside a class, and `run` calls it earlier in
    // the file. The declaration-preferring locator must still land on the method definition.
    let src = "class Payments {\n    int run() {\n        return charge(10);\n    }\n\n    int charge(int amount) {\n        return amount;\n    }\n}\n\ninterface Gateway {}\n";
    assert_prefers_declaration(Language::Java, src, "charge", "int charge(int amount)");

    let out = replace_function(
        src,
        Language::Java,
        "charge",
        "int charge(int amount) {\n        return amount * 2;\n    }",
    )
    .unwrap();
    assert!(out.contains("return amount * 2;"));
    assert!(out.contains("int run()"));
    assert!(out.contains("interface Gateway"));

    let defs = list_definitions(src, Language::Java).unwrap();
    let fns: Vec<&str> = defs
        .iter()
        .filter(|d| d.kind == DefKind::Function)
        .map(|d| d.name.as_str())
        .collect();
    assert!(fns.contains(&"run") && fns.contains(&"charge"));
    assert!(defs
        .iter()
        .any(|d| d.kind == DefKind::Type && d.name == "Payments"));
    assert!(defs
        .iter()
        .any(|d| d.kind == DefKind::Type && d.name == "Gateway"));
}

#[test]
fn r11_cross_file_rename_works_for_go() {
    // The cross-file rename op (whole-word, atomic, parse-verified) now applies to Go sources.
    let lib = SourceFile::new(
        "lib.go",
        Language::Go,
        "package m\n\nfunc helper() int {\n    return 7\n}\n",
    );
    let main = SourceFile::new(
        "main.go",
        Language::Go,
        "package m\n\nfunc run() int {\n    return helper() + helper()\n}\n",
    );
    let edits = plan_rename_symbol(&[lib, main], "helper", "assist", |_| 0).unwrap();
    assert_eq!(edits.len(), 2);
    let mainedit = edits.iter().find(|e| e.path == "main.go").unwrap();
    assert_eq!(mainedit.new_content.matches("assist()").count(), 2);
    assert!(!mainedit.new_content.contains("helper"));
}

#[test]
fn r11_replace_rejects_unparseable_in_every_language() {
    // The DRY-RUN parse guard is language-agnostic: a broken replacement is refused, not committed.
    let cases = [
        (
            Language::Go,
            "package m\nfunc f() int { return 1 }\n",
            "f",
            "func f( { not go",
        ),
        (
            Language::JavaScript,
            "function f(){ return 1; }\n",
            "f",
            "function f( { not js",
        ),
        (
            Language::Java,
            "class C { int f(){ return 1; } }\n",
            "f",
            "int f( { not java",
        ),
    ];
    for (lang, src, name, bad) in cases {
        let err = replace_function(src, lang, name, bad);
        assert!(err.is_err(), "{lang:?}: broken replacement must be refused");
    }
}
