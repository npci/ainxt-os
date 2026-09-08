// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! ainxt-semantic — AST-precise semantic editing (Phase 3, Code + SDLC profiles).
//!
//! The lowest rung of the edit ladder is text patching; the highest that this crate reaches is an
//! **AST transform** over a tree-sitter concrete syntax tree (see `docs/architecture/SEMANTIC_EDITING.md`).
//! The point is to edit code by *meaning* rather than by characters, so the two failure modes that
//! silently corrupt real repositories are made structurally impossible:
//!
//! - **A call site is never mistaken for a definition.** A naive "first `foo(` wins" scanner will
//!   locate the *call* `foo()` in a caller that appears *before* `fn foo`/`def foo`, and then splice
//!   the replacement over the wrong region. This has burned the SDLC patch engine before. Here we
//!   only ever match a `function_item` (Rust) / `function_definition` (Python) AST node whose `name`
//!   field equals the target — a call expression is a different node kind, so it can never win.
//!
//! - **A replacement is never committed unless it parses.** [`replace_function`] performs a DRY-RUN
//!   parse of the new text before touching the source: text that fails to parse, or that parses but
//!   contains no function definition, is rejected with a structured error. As a second guard, an
//!   edit that would introduce a parse error into a file that parsed cleanly beforehand is also
//!   refused, so a locally-valid snippet that is invalid *in context* cannot slip through.
//!
//! Every successful [`replace_function`] is **byte-precise**: only the definition's own
//! `start_byte..end_byte` region changes; every other byte of the file — imports, sibling
//! functions, comments, trailing newline — is preserved exactly.
//!
//! ## Surface
//! - [`Language`] — the grammars we bind (`Rust`, `Python`).
//! - [`parse`] — `source → `[`tree_sitter::Tree`].
//! - [`find_function`] — locate a definition by name → [`Span`] (declaration-preferring).
//! - [`list_functions`] — every definition in the file, in source order.
//! - [`replace_function`] — byte-precise, parse-verified replacement of one definition.
//!
//! Clean-room throughout: no vendor identifiers, no borrowed layouts.
//!
//! ## Cross-file layers (this crate's higher rungs)
//! - [`graph`] — a code-derived symbol / call / import graph over a *set* of files, and the
//!   deterministic **blast-radius** resolver the Code-Review Pipeline consumes to size risk.
//! - [`workspace`] — the **multi-file atomic apply protocol**: dry-run parse → all-files-or-none
//!   commit → post-write re-verify → automatic rollback, with per-file optimistic-version conflict
//!   serialization and a [`workspace::WorkspaceSink`] seam for the real filesystem.
//! - [`ops`] — cross-file **semantic operations** (rename a symbol across every file, resolve the
//!   call sites a signature change touches) built on the graph + atomic apply.
//! - [`ladder`] — the **edit ladder** orchestrator (LSP → AST → structured-patch → text-patch): it
//!   picks the highest rung available for a language+operation and falls *down* on failure, recording
//!   the rung used and *why* it fell — the real LSP driver is a seam ([`ladder::LspRefactor`]).

use tree_sitter::{Node, Parser, Tree};

pub mod arch;
pub mod graph;
pub mod ladder;
pub mod lsp;
pub mod ops;
pub mod regression;
pub mod workspace;

// ============================ Language ============================

/// A source language this engine can parse and edit, bound to its tree-sitter grammar.
///
/// Round-11 broadened this from the tight `Rust | Python` pair to the full set the pipeline's
/// capability matrix declares AST-precise support for (`CODE_REVIEW_PIPELINE.md` §10,
/// `SEMANTIC_EDITING.md` §6): every variant binds a real tree-sitter grammar, so the AST rung —
/// definition location, byte-precise replacement, symbol/call graph, cross-file rename,
/// change-signature, and the arch/regression graph checks — works for all of them, not just Rust and
/// Python. Brace-block languages (Rust, Go, JavaScript, TypeScript, Java) share one structural model;
/// Python is the indentation-block outlier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Language {
    Rust,
    Python,
    Go,
    JavaScript,
    TypeScript,
    Java,
}

impl Language {
    /// The tree-sitter grammar for this language.
    fn grammar(self) -> tree_sitter::Language {
        match self {
            Language::Rust => tree_sitter_rust::LANGUAGE.into(),
            Language::Python => tree_sitter_python::LANGUAGE.into(),
            Language::Go => tree_sitter_go::LANGUAGE.into(),
            Language::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
            Language::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            Language::Java => tree_sitter_java::LANGUAGE.into(),
        }
    }

    /// The AST node kinds that denote a top-level or nested function/method *definition*. Several
    /// grammars distinguish free functions from methods/constructors (Go `method_declaration`, Java
    /// `constructor_declaration`, JS/TS `method_definition`); all such definition kinds are listed so
    /// a method is located exactly like a free function — and a *call* is never one of these kinds, so
    /// the "first `foo(` wins" call-site bug remains structurally impossible in every language.
    fn function_kinds(self) -> &'static [&'static str] {
        match self {
            Language::Rust => &["function_item"],
            Language::Python => &["function_definition"],
            Language::Go => &["function_declaration", "method_declaration"],
            Language::JavaScript | Language::TypeScript => &[
                "function_declaration",
                "method_definition",
                "generator_function_declaration",
            ],
            Language::Java => &["method_declaration", "constructor_declaration"],
        }
    }

    /// Whether this language's blocks are delimited by braces (as opposed to Python's indentation).
    /// Exposed for callers that need the block model without matching every variant.
    #[must_use]
    pub fn is_brace_block(self) -> bool {
        !matches!(self, Language::Python)
    }

    /// The field on that node that holds the function's name identifier. Every bound grammar names it
    /// `name`, but keeping this explicit documents the coupling and survives grammar divergence.
    fn name_field(self) -> &'static str {
        "name"
    }
}

// ============================ Span ============================

/// A half-open byte range `[start_byte, end_byte)` into the original source, covering the full
/// extent of a definition (signature through closing body). Indexing `source[start..end]` yields the
/// exact text of the definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub start_byte: usize,
    pub end_byte: usize,
}

impl Span {
    /// The byte length of the span.
    #[must_use]
    pub fn len(self) -> usize {
        self.end_byte.saturating_sub(self.start_byte)
    }

    /// Whether the span covers zero bytes.
    #[must_use]
    pub fn is_empty(self) -> bool {
        self.end_byte <= self.start_byte
    }
}

// ============================ Errors ============================

/// Why a semantic operation could not be completed. Every variant is actionable by the caller
/// (or by a bounded same-turn self-correction loop) rather than a silent best-effort guess.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SemanticError {
    /// The parser could not be configured for the language, or produced no tree at all. Carries a
    /// short human-readable reason.
    ParseFailed(String),
    /// No function/method *definition* with the requested name exists in the source.
    FunctionNotFound(String),
    /// The proposed replacement text does not itself parse cleanly (it contains syntax errors).
    NewDefUnparseable,
    /// The proposed replacement parses, but contains no function/method definition — replacing a
    /// function with a non-function (a bare statement, a struct, an expression) is refused.
    NewDefNotAFunction,
    /// The replacement parses in isolation, but splicing it in would introduce a parse error into a
    /// file that was previously clean (it is invalid *in this context*).
    ResultWouldNotParse,
}

impl std::fmt::Display for SemanticError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SemanticError::ParseFailed(why) => write!(f, "parse failed: {why}"),
            SemanticError::FunctionNotFound(name) => {
                write!(f, "no definition named `{name}` found")
            }
            SemanticError::NewDefUnparseable => {
                write!(f, "replacement text does not parse")
            }
            SemanticError::NewDefNotAFunction => {
                write!(f, "replacement text contains no function definition")
            }
            SemanticError::ResultWouldNotParse => {
                write!(f, "replacement would introduce a parse error in context")
            }
        }
    }
}

impl std::error::Error for SemanticError {}

// ============================ Parsing ============================

/// Parse `source` under `lang` into a concrete syntax tree.
///
/// # Errors
/// Returns [`SemanticError::ParseFailed`] if the grammar cannot be loaded or the parser yields no
/// tree. Note that a *syntactically broken* source still parses into a tree (with `ERROR` nodes);
/// use [`tree_sitter::Node::has_error`] on the root to detect that.
pub fn parse(source: &str, lang: Language) -> Result<Tree, SemanticError> {
    let mut parser = Parser::new();
    parser
        .set_language(&lang.grammar())
        .map_err(|e| SemanticError::ParseFailed(format!("set_language: {e}")))?;
    parser
        .parse(source, None)
        .ok_or_else(|| SemanticError::ParseFailed("parser returned no tree".to_string()))
}

/// Deterministically report whether `source` parses cleanly under `lang`, and if not, the 1-based line
/// of the first `ERROR`/missing node — a precise, actionable diagnostic the Code-Review Pipeline's
/// deterministic Compile gate feeds verbatim into the self-heal loop.
///
/// `Ok(None)` ⇒ the source parses with no error nodes (clean). `Ok(Some(line))` ⇒ the parse tree
/// carries a syntax error at `line`. `Err` ⇒ the grammar could not be loaded (see [`parse`]).
///
/// # Errors
/// Propagates [`SemanticError::ParseFailed`] from [`parse`].
pub fn first_parse_error_line(
    source: &str,
    lang: Language,
) -> Result<Option<usize>, SemanticError> {
    let tree = parse(source, lang)?;
    let root = tree.root_node();
    if !root.has_error() {
        return Ok(None);
    }
    // Walk the tree to the first ERROR/missing node and report its line.
    let mut cursor = root.walk();
    let mut stack = vec![root];
    let mut best: Option<usize> = None;
    while let Some(node) = stack.pop() {
        if node.is_error() || node.is_missing() {
            let line = node.start_position().row + 1;
            best = Some(best.map_or(line, |b| b.min(line)));
        }
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
    }
    // A tree can report `has_error` even when no single node is flagged ERROR (e.g. an unexpected EOF);
    // fall back to line 1 so the gate still fails honestly rather than silently passing.
    Ok(Some(best.unwrap_or(1)))
}

/// Recursively collect every function/method definition, in pre-order (source order for siblings).
fn collect_functions(node: Node<'_>, lang: Language, src: &[u8], out: &mut Vec<(String, Span)>) {
    if lang.function_kinds().contains(&node.kind()) {
        if let Some(name_node) = node.child_by_field_name(lang.name_field()) {
            if let Ok(name) = name_node.utf8_text(src) {
                out.push((
                    name.to_string(),
                    Span {
                        start_byte: node.start_byte(),
                        end_byte: node.end_byte(),
                    },
                ));
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_functions(child, lang, src, out);
    }
}

/// List every function/method definition in `source`, as `(name, span)`, in source order.
///
/// Only *definitions* are listed; call sites, imports, and references are never included. Nested
/// definitions (a `fn` inside a `fn`, a `def` inside a `def`, methods inside an `impl`/class) are
/// included at their own position.
///
/// # Errors
/// Propagates [`SemanticError::ParseFailed`] from [`parse`].
pub fn list_functions(source: &str, lang: Language) -> Result<Vec<(String, Span)>, SemanticError> {
    let tree = parse(source, lang)?;
    let mut out = Vec::new();
    collect_functions(tree.root_node(), lang, source.as_bytes(), &mut out);
    Ok(out)
}

// ============================ Definitions (functions + types) ============================

/// The kind of a top-level or nested *definition* the symbol graph tracks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefKind {
    /// A function or method definition.
    Function,
    /// A type definition: a Rust `struct`/`enum`/`trait`, or a Python `class`.
    Type,
}

/// A named definition located in a single file, with its exact byte span.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Definition {
    pub name: String,
    pub kind: DefKind,
    pub span: Span,
}

/// The AST node kinds that denote a *type* definition in this language.
fn type_kinds(lang: Language) -> &'static [&'static str] {
    match lang {
        Language::Rust => &["struct_item", "enum_item", "trait_item"],
        Language::Python => &["class_definition"],
        // Go names types on the `type_spec` child (the enclosing `type_declaration` has no name
        // field), so the spec is the name-bearing node.
        Language::Go => &["type_spec"],
        Language::JavaScript => &["class_declaration"],
        Language::TypeScript => &[
            "class_declaration",
            "interface_declaration",
            "enum_declaration",
            "type_alias_declaration",
        ],
        Language::Java => &[
            "class_declaration",
            "interface_declaration",
            "enum_declaration",
        ],
    }
}

fn collect_definitions_node(node: Node<'_>, lang: Language, src: &[u8], out: &mut Vec<Definition>) {
    let kind = node.kind();
    let def_kind = if lang.function_kinds().contains(&kind) {
        Some(DefKind::Function)
    } else if type_kinds(lang).contains(&kind) {
        Some(DefKind::Type)
    } else {
        None
    };
    if let Some(dk) = def_kind {
        if let Some(name_node) = node.child_by_field_name(lang.name_field()) {
            if let Ok(name) = name_node.utf8_text(src) {
                out.push(Definition {
                    name: name.to_string(),
                    kind: dk,
                    span: Span {
                        start_byte: node.start_byte(),
                        end_byte: node.end_byte(),
                    },
                });
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_definitions_node(child, lang, src, out);
    }
}

/// List every function/method AND type (`struct`/`enum`/`trait`/`class`) definition in `source`, in
/// source order. This is the symbol-extraction primitive the cross-file [`graph`] builds on.
///
/// # Errors
/// Propagates [`SemanticError::ParseFailed`] from [`parse`].
pub fn list_definitions(source: &str, lang: Language) -> Result<Vec<Definition>, SemanticError> {
    let tree = parse(source, lang)?;
    let mut out = Vec::new();
    collect_definitions_node(tree.root_node(), lang, source.as_bytes(), &mut out);
    Ok(out)
}

/// Locate the *definition* of a function/method named `name` and return its byte span.
///
/// Declaration-preferring by construction: only definition nodes are considered, so a call site
/// `name(...)` occurring *before* the definition can never be matched. If several definitions share
/// the name (e.g. an overload-like duplicate, or same-named methods on different types), the first
/// in source order is returned. Returns `None` if no definition with that name exists.
///
/// # Errors
/// Propagates [`SemanticError::ParseFailed`] from [`parse`].
pub fn find_function(
    source: &str,
    lang: Language,
    name: &str,
) -> Result<Option<Span>, SemanticError> {
    let mut best: Option<Span> = None;
    for (fname, span) in list_functions(source, lang)? {
        if fname == name {
            match best {
                Some(b) if b.start_byte <= span.start_byte => {}
                _ => best = Some(span),
            }
        }
    }
    Ok(best)
}

/// Replace the definition of `name` in `source` with `new_def`, returning the full rewritten source.
///
/// The replacement is byte-precise: only the target definition's span changes; every other byte —
/// imports, sibling functions, comments, whitespace, the trailing newline — is preserved exactly.
///
/// Before anything is spliced, `new_def` is DRY-RUN parsed and validated:
/// 1. it must parse without syntax errors, and
/// 2. it must itself contain a function/method definition.
///
/// After splicing, if the original parsed cleanly the result must also parse cleanly; an edit that
/// would introduce a parse error in context is refused.
///
/// # Errors
/// - [`SemanticError::FunctionNotFound`] if `name` has no definition in `source`.
/// - [`SemanticError::NewDefUnparseable`] if `new_def` contains syntax errors.
/// - [`SemanticError::NewDefNotAFunction`] if `new_def` parses but defines no function.
/// - [`SemanticError::ResultWouldNotParse`] if the splice would break a previously-clean file.
/// - [`SemanticError::ParseFailed`] on grammar/parser failure.
pub fn replace_function(
    source: &str,
    lang: Language,
    name: &str,
    new_def: &str,
) -> Result<String, SemanticError> {
    // Locate the target first so a missing function fails fast and cheaply.
    let span = find_function(source, lang, name)?
        .ok_or_else(|| SemanticError::FunctionNotFound(name.to_string()))?;

    // DRY-RUN: the replacement must parse cleanly on its own.
    let new_tree = parse(new_def, lang)?;
    if new_tree.root_node().has_error() {
        return Err(SemanticError::NewDefUnparseable);
    }
    // ...and must actually be a function definition, not some other construct.
    let mut new_fns = Vec::new();
    collect_functions(new_tree.root_node(), lang, new_def.as_bytes(), &mut new_fns);
    if new_fns.is_empty() {
        return Err(SemanticError::NewDefNotAFunction);
    }

    // Byte-precise splice.
    let mut result = String::with_capacity(source.len() - span.len() + new_def.len());
    result.push_str(&source[..span.start_byte]);
    result.push_str(new_def);
    result.push_str(&source[span.end_byte..]);

    // Second guard: do not introduce a parse error into a file that was previously clean.
    let orig_clean = !parse(source, lang)?.root_node().has_error();
    if orig_clean && parse(&result, lang)?.root_node().has_error() {
        return Err(SemanticError::ResultWouldNotParse);
    }

    Ok(result)
}

// ============================ Tests ============================

#[cfg(test)]
mod tests {
    use super::*;

    const RUST_TWO: &str =
        "fn alpha() -> i32 {\n    1\n}\n\nfn beta(x: i32) -> i32 {\n    x + 1\n}\n";

    // A caller that invokes `helper` textually BEFORE `helper` is defined. A first-`helper(`-wins
    // scanner would land on the call site inside `caller`.
    const RUST_CALL_BEFORE_DEF: &str =
        "fn caller() -> i32 {\n    helper()\n}\n\nfn helper() -> i32 {\n    42\n}\n";

    const PY_CALL_BEFORE_DEF: &str =
        "def outer():\n    return inner()\n\ndef inner():\n    return 7\n";

    #[test]
    fn finds_rust_function_true_span() {
        let span = find_function(RUST_TWO, Language::Rust, "beta")
            .unwrap()
            .expect("beta must be found");
        // The span must cover exactly the `beta` definition, byte for byte.
        assert_eq!(
            &RUST_TWO[span.start_byte..span.end_byte],
            "fn beta(x: i32) -> i32 {\n    x + 1\n}"
        );
        // And it must NOT bleed into alpha or the trailing newline.
        assert!(!RUST_TWO[span.start_byte..span.end_byte].contains("alpha"));
        assert!(!RUST_TWO[span.start_byte..span.end_byte].ends_with('\n'));
    }

    #[test]
    fn prefers_declaration_over_call_site() {
        let span = find_function(RUST_CALL_BEFORE_DEF, Language::Rust, "helper")
            .unwrap()
            .expect("helper definition must be found");

        // The call site appears earlier in the file than the definition.
        let call_idx = RUST_CALL_BEFORE_DEF.find("helper()").unwrap();
        // The returned span must start strictly AFTER the call site — i.e. at the definition.
        assert!(
            span.start_byte > call_idx,
            "span started at {} but call site is at {} — matched the call, not the def",
            span.start_byte,
            call_idx
        );
        assert!(RUST_CALL_BEFORE_DEF[span.start_byte..].starts_with("fn helper"));
        assert!(RUST_CALL_BEFORE_DEF[span.start_byte..span.end_byte].contains("42"));
    }

    #[test]
    fn replace_is_byte_identical_except_target() {
        let out = replace_function(
            RUST_CALL_BEFORE_DEF,
            Language::Rust,
            "helper",
            "fn helper() -> i32 {\n    99\n}",
        )
        .unwrap();

        assert_eq!(
            out,
            "fn caller() -> i32 {\n    helper()\n}\n\nfn helper() -> i32 {\n    99\n}\n"
        );
        // Everything before the target definition is untouched.
        assert!(out.contains("fn caller() -> i32 {\n    helper()\n}"));
        // The old body is gone, the new body is present.
        assert!(!out.contains("42"));
        assert!(out.contains("99"));
    }

    #[test]
    fn replace_rejects_unparseable_new_text() {
        let err = replace_function(
            RUST_CALL_BEFORE_DEF,
            Language::Rust,
            "helper",
            "fn helper( { this is not valid rust",
        )
        .unwrap_err();
        assert_eq!(err, SemanticError::NewDefUnparseable);
    }

    #[test]
    fn replace_rejects_non_function_new_text() {
        // Parses cleanly as Rust, but is a struct, not a function.
        let err = replace_function(RUST_TWO, Language::Rust, "beta", "struct Beta { x: i32 }")
            .unwrap_err();
        assert_eq!(err, SemanticError::NewDefNotAFunction);
    }

    #[test]
    fn replace_missing_function_errors() {
        let err = replace_function(
            RUST_TWO,
            Language::Rust,
            "does_not_exist",
            "fn does_not_exist() {}",
        )
        .unwrap_err();
        assert_eq!(
            err,
            SemanticError::FunctionNotFound("does_not_exist".to_string())
        );
    }

    #[test]
    fn find_missing_returns_none() {
        assert_eq!(
            find_function(RUST_TWO, Language::Rust, "gamma").unwrap(),
            None
        );
    }

    #[test]
    fn python_find_prefers_definition_and_replaces() {
        let span = find_function(PY_CALL_BEFORE_DEF, Language::Python, "inner")
            .unwrap()
            .expect("inner def must be found");
        let call_idx = PY_CALL_BEFORE_DEF.find("inner()").unwrap();
        assert!(
            span.start_byte > call_idx,
            "matched the Python call site instead of the def"
        );
        assert_eq!(
            &PY_CALL_BEFORE_DEF[span.start_byte..span.end_byte],
            "def inner():\n    return 7"
        );

        let out = replace_function(
            PY_CALL_BEFORE_DEF,
            Language::Python,
            "inner",
            "def inner():\n    return 8",
        )
        .unwrap();
        assert_eq!(
            out,
            "def outer():\n    return inner()\n\ndef inner():\n    return 8\n"
        );
    }

    #[test]
    fn python_rejects_unparseable_new_text() {
        let err = replace_function(
            PY_CALL_BEFORE_DEF,
            Language::Python,
            "inner",
            "def inner(:\n    return", // broken signature
        )
        .unwrap_err();
        assert_eq!(err, SemanticError::NewDefUnparseable);
    }

    #[test]
    fn list_functions_returns_all_definitions_in_order() {
        let fns = list_functions(RUST_TWO, Language::Rust).unwrap();
        let names: Vec<&str> = fns.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, vec!["alpha", "beta"]);
        // Each listed span must round-trip to real source text.
        assert_eq!(
            &RUST_TWO[fns[0].1.start_byte..fns[0].1.end_byte],
            "fn alpha() -> i32 {\n    1\n}"
        );
        assert_eq!(
            &RUST_TWO[fns[1].1.start_byte..fns[1].1.end_byte],
            "fn beta(x: i32) -> i32 {\n    x + 1\n}"
        );
    }

    #[test]
    fn list_functions_includes_impl_methods() {
        let src =
            "struct S;\nimpl S {\n    fn one(&self) {}\n    fn two(&self) {}\n}\nfn free() {}\n";
        let fns = list_functions(src, Language::Rust).unwrap();
        let names: Vec<&str> = fns.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, vec!["one", "two", "free"]);
        // A method can be located and its span is exact.
        let span = find_function(src, Language::Rust, "two").unwrap().unwrap();
        assert_eq!(&src[span.start_byte..span.end_byte], "fn two(&self) {}");
    }

    #[test]
    fn span_length_matches_slice() {
        let span = find_function(RUST_TWO, Language::Rust, "alpha")
            .unwrap()
            .unwrap();
        assert!(!span.is_empty());
        assert_eq!(span.len(), RUST_TWO[span.start_byte..span.end_byte].len());
    }
}
