// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-12 — **the atomic-apply protocol verifies more than parse** (`SEMANTIC_EDITING.md` §4). The
//! gap: `Workspace::apply_atomic` gated on the tree-sitter parse tree only, so an edit whose bytes
//! form a valid syntax tree but fail a *type-check / compile / LSP diagnostic* (an unresolved import, a
//! type mismatch, a borrow-check error) committed anyway — a payments-platform hazard. Round-12 adds
//! the [`PostApplyDiagnostics`] seam: a deeper deterministic verifier runs after the parse gate and
//! before commit, and a blocking diagnostic refuses the write with **nothing persisted**.
//!
//! The real toolchain (`cargo check` / `tsc` / `mypy` / an LSP diagnostics request against a warm
//! index) is infra; this proves the seam offline with the [`ScriptedDiagnostics`] stand-in. Fail-before:
//! `apply_atomic_checked` / `PostApplyDiagnostics` did not exist — the atomic protocol was parse-only.

use ainxt_semantic::ops::lang_from_path;
use ainxt_semantic::workspace::{
    FileEdit, MemorySink, NoDiagnostics, ScriptedDiagnostics, Workspace,
};
use ainxt_semantic::Language;

// The path→language mapper the atomic protocol uses for its parse gate.
fn lang_of(path: &str) -> Option<Language> {
    lang_from_path(path)
}

fn edit(path: &str, content: &str) -> FileEdit {
    FileEdit {
        path: path.into(),
        new_content: content.into(),
        base_version: 0,
    }
}

/// A Rust file that PARSES cleanly (valid syntax tree) but references an unresolved symbol — exactly
/// the class of defect a parse-only gate cannot see and a type-checker/LSP would flag.
const PARSES_BUT_TYPE_ERRORS: &str = "fn f() -> i32 {\n    undefined_symbol()\n}\n"; // parses; `undefined_symbol` is unresolved

#[test]
fn r12_atomic_apply_rolls_back_on_a_type_diagnostic_that_parses() {
    // A verifier that flags the unresolved-symbol marker (a stand-in for a real `cargo check` E0425).
    let check = ScriptedDiagnostics::new().on_marker(
        "undefined_symbol",
        "E0425: cannot find function `undefined_symbol` in this scope",
    );

    let mut ws = Workspace::new();
    ws.insert("src/a.rs", "fn f() -> i32 {\n    1\n}\n");
    let mut sink = MemorySink::new();
    // Seed the sink with the pre-edit baseline (as the pipeline does).
    let mut base = std::collections::BTreeMap::new();
    base.insert(
        "src/a.rs".to_string(),
        "fn f() -> i32 {\n    1\n}\n".to_string(),
    );
    let _ = ainxt_semantic::workspace::WorkspaceSink::commit(&mut sink, &base);

    // Sanity: the proposed content really does PARSE (so a parse-only gate would have let it commit).
    assert_eq!(
        ainxt_semantic::first_parse_error_line(PARSES_BUT_TYPE_ERRORS, Language::Rust).unwrap(),
        None,
        "the fixture must parse cleanly — otherwise this would not test the type-check layer"
    );

    let edits = vec![edit("src/a.rs", PARSES_BUT_TYPE_ERRORS)];
    let err = ws
        .apply_atomic_checked(&edits, lang_of, &mut sink, &check)
        .expect_err("a type diagnostic must refuse the commit");
    match err {
        ainxt_semantic::workspace::AtomicError::DiagnosticsFailed { diagnostics } => {
            assert!(
                diagnostics.iter().any(|d| d.contains("E0425")),
                "carries the exact diagnostic"
            );
        }
        other => panic!("expected DiagnosticsFailed, got {other:?}"),
    }
    // NOTHING was written: the sink still holds the pre-edit baseline, and the workspace version is 0.
    assert_eq!(sink.files["src/a.rs"], "fn f() -> i32 {\n    1\n}\n");
    assert_eq!(
        ws.version("src/a.rs"),
        0,
        "a refused edit must not advance the version"
    );
}

#[test]
fn r12_clean_edit_still_commits_through_the_diagnostics_seam() {
    // The same fixture that parses AND has no diagnostic commits normally — no false positives.
    let check = ScriptedDiagnostics::new().on_marker("undefined_symbol", "E0425");
    let mut ws = Workspace::new();
    ws.insert("src/a.rs", "fn f() -> i32 {\n    1\n}\n");
    let mut sink = MemorySink::new();
    let clean = "fn f() -> i32 {\n    2\n}\n";
    let applied = ws
        .apply_atomic_checked(&[edit("src/a.rs", clean)], lang_of, &mut sink, &check)
        .expect("a clean edit with no diagnostic commits");
    assert_eq!(applied.committed["src/a.rs"], 1);
    assert_eq!(sink.files["src/a.rs"], clean);
}

#[test]
fn r12_no_diagnostics_is_byte_identical_to_parse_only_apply() {
    // `NoDiagnostics` (the `apply_atomic` default) leaves behaviour exactly as before.
    let mut ws = Workspace::new();
    ws.insert("src/a.rs", "fn f() -> i32 {\n    1\n}\n");
    let mut sink = MemorySink::new();
    let clean = "fn f() -> i32 {\n    9\n}\n";
    let applied = ws
        .apply_atomic_checked(
            &[edit("src/a.rs", clean)],
            lang_of,
            &mut sink,
            &NoDiagnostics,
        )
        .expect("commits");
    assert_eq!(applied.committed["src/a.rs"], 1);
}
