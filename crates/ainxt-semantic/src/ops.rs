// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Cross-file **semantic operations** (`docs/architecture/SEMANTIC_EDITING.md` §4): rename a symbol
//! across every file that references it, and resolve the call sites a signature change touches.
//!
//! These plan a multi-file [`crate::workspace::FileEdit`] set that the caller commits through the
//! atomic apply protocol ([`crate::workspace::Workspace::apply_atomic`]) — so a rename is either
//! applied everywhere-or-nowhere, dry-run-parse-verified, and rolled back on regression, exactly
//! like every other edit. The rename rewrites whole-word identifier occurrences; it does **not**
//! resolve types (a string named `old` in a comment/string literal would be rewritten too), which is
//! precisely why the LSP rung sits above this one in [`crate::ladder`] — but with no language server
//! present this is the safe, atomic, verified rung, and it never silently corrupts syntax because the
//! apply protocol's parse gate rejects any rewrite that breaks a previously-clean file.

use crate::graph::{SourceFile, SymbolGraph, SymbolId};
use crate::workspace::FileEdit;
use crate::Language;
use std::collections::BTreeSet;

/// Why a semantic operation could not be planned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpError {
    /// The new name is not a valid identifier (empty, starts with a digit, or has non-ident chars).
    InvalidIdentifier(String),
    /// The new name already names a definition somewhere — the rename would collide/shadow.
    NameCollision(String),
    /// The symbol to operate on has no definition in the given files.
    SymbolNotFound(String),
    /// GAP-FIX gap6-semantic-lsp-signature-layermanifest item 2 — [`plan_change_signature`]'s
    /// independent, whole-word symbol-graph blast radius named a file as referencing the changed
    /// symbol, but the AST-rung text splice ([`apply_change_signature_ex`]) could not locate an
    /// actual `name(` call head in it to update with the new argument. Refused rather than silently
    /// committing a signature change with that one call site left on the OLD signature — the same
    /// "declaration changes, a usage goes stale" bug class `CLAUDE.md` documents against
    /// `sdlc_patch_engine.py`'s `changed_fields`.
    CallSiteUnresolved(String),
}

impl std::fmt::Display for OpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpError::InvalidIdentifier(s) => write!(f, "not a valid identifier: {s:?}"),
            OpError::NameCollision(s) => write!(f, "name {s:?} already exists (would collide)"),
            OpError::SymbolNotFound(s) => write!(f, "no definition named {s:?}"),
            OpError::CallSiteUnresolved(detail) => {
                write!(
                    f,
                    "a referenced call site could not be resolved and updated: {detail}"
                )
            }
        }
    }
}

impl std::error::Error for OpError {}

fn is_valid_ident(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_alphanumeric() || c == '_')
}

fn is_ident_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Rewrite every whole-word occurrence of `old` to `new` in `src`, returning `(new_src, count)`.
fn rewrite_whole_word(src: &str, old: &str, new: &str) -> (String, usize) {
    if old.is_empty() {
        return (src.to_string(), 0);
    }
    let bytes = src.as_bytes();
    let ob = old.as_bytes();
    let mut out = String::with_capacity(src.len());
    let mut i = 0usize;
    let mut count = 0usize;
    while i < bytes.len() {
        if i + ob.len() <= bytes.len() && &bytes[i..i + ob.len()] == ob {
            let before_ok = i == 0 || !is_ident_char(src[..i].chars().next_back().unwrap());
            let after = i + ob.len();
            let after_ok =
                after == bytes.len() || !is_ident_char(src[after..].chars().next().unwrap());
            if before_ok && after_ok {
                out.push_str(new);
                i = after;
                count += 1;
                continue;
            }
        }
        // Copy one full UTF-8 char to keep byte boundaries valid.
        let ch = src[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    (out, count)
}

/// Plan a cross-file **rename** of symbol `old` to `new`. Returns one [`FileEdit`] per file whose
/// content actually changes, each tagged with the file's current version for the atomic apply.
///
/// Guards:
/// - `new` must be a valid identifier.
/// - `new` must not already name a definition anywhere (collision refused, not silently shadowed).
/// - `old` must have at least one definition.
///
/// The caller passes the file versions (from the [`crate::workspace::Workspace`]) via `version_of`.
///
/// # Errors
/// See [`OpError`].
pub fn plan_rename_symbol(
    files: &[SourceFile],
    old: &str,
    new: &str,
    version_of: impl Fn(&str) -> u64,
) -> Result<Vec<FileEdit>, OpError> {
    if !is_valid_ident(new) {
        return Err(OpError::InvalidIdentifier(new.to_string()));
    }
    let graph = SymbolGraph::build(files);
    let defined: BTreeSet<String> = graph.symbols().into_iter().map(|s| s.name).collect();
    if !defined.contains(old) {
        return Err(OpError::SymbolNotFound(old.to_string()));
    }
    if defined.contains(new) {
        return Err(OpError::NameCollision(new.to_string()));
    }

    let mut edits = Vec::new();
    for f in files {
        let (rewritten, count) = rewrite_whole_word(&f.source, old, new);
        if count > 0 {
            edits.push(FileEdit {
                path: f.path.clone(),
                new_content: rewritten,
                base_version: version_of(&f.path),
            });
        }
    }
    Ok(edits)
}

/// A signature change is high-blast-radius: the declaration plus *every* call site must be reviewed.
/// This resolves the call sites deterministically from the graph so the pipeline can size the risk
/// and the coder can update each. Full argument-adapter synthesis needs type info (the LSP rung) and
/// is intentionally out of scope here — this crate reports *what* must change, never guesses *how*.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureChangePlan {
    /// The definition(s) whose declaration changes.
    pub declarations: Vec<SymbolId>,
    /// Every caller symbol whose call must be reviewed against the new signature.
    pub affected_call_sites: Vec<SymbolId>,
}

/// Resolve the blast radius of changing the signature of `name`.
///
/// # Errors
/// [`OpError::SymbolNotFound`] if `name` is not defined in `files`.
pub fn plan_change_signature(
    files: &[SourceFile],
    name: &str,
) -> Result<SignatureChangePlan, OpError> {
    let graph = SymbolGraph::build(files);
    let declarations: Vec<SymbolId> = graph
        .symbols()
        .into_iter()
        .filter(|s| s.name == name)
        .collect();
    if declarations.is_empty() {
        return Err(OpError::SymbolNotFound(name.to_string()));
    }
    // Direct callers are the call sites that must be updated for the new signature. A BTreeSet keeps
    // the result deterministically ordered.
    let mut affected: BTreeSet<SymbolId> = BTreeSet::new();
    for d in &declarations {
        affected.extend(graph.direct_callers(d));
    }
    Ok(SignatureChangePlan {
        declarations,
        affected_call_sites: affected.into_iter().collect(),
    })
}

// ============================ Change-signature APPLICATION ============================

/// The concrete edit a signature change performs: a new trailing parameter added to the declaration,
/// and the adapter/default argument spliced into every call site (`SEMANTIC_EDITING.md` §4 —
/// "update the declaration + every call site + imports; insert defaults/adapters where needed").
///
/// This is the AST-rung *application* (vs. [`plan_change_signature`], which only resolves the blast
/// radius). It handles the enterprise-common case deterministically: append a parameter and pass a
/// caller-supplied adapter expression at each call. Reordering/removing parameters or type-driven
/// adapter synthesis is the LSP rung; this rung refuses rather than guesses (see the guards below).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AddParamSpec {
    /// The new parameter text as it appears in the declaration, e.g. `ctx: &Context` or `retries=3`.
    pub declaration_param: String,
    /// The argument text spliced into each call site, e.g. `&ctx` or `retries=3` (the adapter/default).
    pub call_argument: String,
}

/// Where a new parameter is inserted in the parameter/argument list (`SEMANTIC_EDITING.md` §4 —
/// "insert defaults/adapters where needed"). Round-11 breadth: not just trailing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamPosition {
    /// Append after all existing parameters (the common, backward-compatible case).
    Trailing,
    /// Prepend before all existing parameters (e.g. a leading `self`/`ctx`/`this`).
    Leading,
    /// Insert at a specific 0-based index among the existing parameters (clamped to the count).
    Index(usize),
}

/// A broadened change-signature spec: a new parameter, where it goes, and how (or whether) call sites
/// adapt. This is the fuller form the design's "insert defaults/adapters where needed" calls for:
/// - `call_argument = Some(expr)` splices `expr` at every call site at the same position;
/// - `call_argument = None` is a **declaration-only** change — used when the new parameter carries a
///   language-level default (`retries: i32 = 3`, Python `retries=3`) so existing callers still
///   compile untouched. This is the enterprise-common "add an optional knob" refactor the trailing-
///   only [`AddParamSpec`] could not express.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeSigSpec {
    pub declaration_param: String,
    /// The adapter argument spliced at each call site, or `None` for a declaration-only (defaulted)
    /// parameter that leaves callers unchanged.
    pub call_argument: Option<String>,
    pub position: ParamPosition,
}

/// Split a parameter/argument list's inner text on **top-level** commas (commas not nested inside
/// `()`, `[]`, `<>`, or `{}`), so a generic `Map<K, V>` or a defaulted `= foo(1, 2)` is one argument.
fn split_top_level_args(inner: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut cur = String::new();
    for c in inner.chars() {
        match c {
            '(' | '[' | '{' | '<' => {
                depth += 1;
                cur.push(c);
            }
            ')' | ']' | '}' | '>' => {
                depth -= 1;
                cur.push(c);
            }
            ',' if depth == 0 => {
                out.push(cur.trim().to_string());
                cur.clear();
            }
            _ => cur.push(c),
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim().to_string());
    }
    out
}

/// Rebuild a `( … )` group at `open` in `src` with `new_arg` inserted at `position`. Returns
/// `(open, close, new_group_text)` where `new_group_text` includes the parens, so the caller can
/// replace `src[open..=close]`.
fn rebuilt_group(
    src: &str,
    open: usize,
    new_arg: &str,
    position: ParamPosition,
) -> Option<(usize, usize, String)> {
    let close = matching_paren(src, open)?;
    let inner = &src[open + 1..close];
    let mut args = split_top_level_args(inner);
    let idx = match position {
        ParamPosition::Leading => 0,
        ParamPosition::Trailing => args.len(),
        ParamPosition::Index(i) => i.min(args.len()),
    };
    args.insert(idx, new_arg.trim().to_string());
    Some((open, close, format!("({})", args.join(", "))))
}

/// Locate the byte index of the `)` matching the `(` at `open` (byte index of an opening paren).
fn matching_paren(src: &str, open: usize) -> Option<usize> {
    let bytes = src.as_bytes();
    if bytes.get(open) != Some(&b'(') {
        return None;
    }
    let mut depth = 0i32;
    let mut i = open;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Byte offsets of every whole-word `name(` in `src` (the `(` boundary makes it a call/decl head, not
/// a bare identifier). Returns the offset of the `(`.
///
/// GAP-FIX gap6-semantic-lsp-signature-layermanifest item 2 — tolerant of ASCII whitespace/newlines
/// between the identifier and its parenthesis (`name (`, `name  (`, `name\n(`). This is valid call/decl
/// syntax in every language this crate plans over (Rust/Python/Go/JS/TS/Java all allow it, however
/// unidiomatic), so a call site written that way — un-rustfmt'd code, or simply a different house
/// style — was previously **invisible** to the old literal-substring `"{name}("` scan: a signature
/// change would splice the declaration and every adjacent-paren call site, but silently leave that ONE
/// call site's argument list completely untouched, a stale call that would fail to compile the moment
/// the declaration gained a required parameter. Exactly the "changed_fields" bug class `CLAUDE.md`
/// documents against the Python SDLC pipeline's `sdlc_patch_engine.py`. Still whole-word bounded on
/// both sides — `bar_name`/`namebar` never match — and still requires an actual `(` to follow (a bare
/// reference with no call at all, e.g. a function used as a value, is correctly NOT a call head).
fn call_paren_offsets(src: &str, name: &str) -> Vec<usize> {
    if name.is_empty() {
        return Vec::new();
    }
    let bytes = src.as_bytes();
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(rel) = src[from..].find(name) {
        let pos = from + rel;
        let before_ok = pos == 0 || !is_ident_char(src[..pos].chars().next_back().unwrap());
        let end = pos + name.len();
        let after_ok = end >= bytes.len() || !is_ident_char(src[end..].chars().next().unwrap());
        if before_ok && after_ok {
            let mut i = end;
            while i < bytes.len() && (bytes[i] as char).is_ascii_whitespace() {
                i += 1;
            }
            if bytes.get(i) == Some(&b'(') {
                out.push(i); // index of the '('
            }
        }
        from = pos + 1;
    }
    out
}

/// Apply a signature change that **adds a trailing parameter**: rewrites the declaration's parameter
/// list and splices the adapter argument into every resolved call site, across every file, atomically
/// planned as [`FileEdit`]s.
///
/// Guards (refuse rather than corrupt):
/// - the symbol must be defined (else [`OpError::SymbolNotFound`]);
/// - `spec.declaration_param` / `spec.call_argument` must be non-empty.
///
/// The declaration's own signature paren is never treated as a call site (it is rewritten as the
/// declaration), so a definition is never double-edited.
///
/// # Errors
/// See [`OpError`].
pub fn apply_change_signature(
    files: &[SourceFile],
    name: &str,
    spec: &AddParamSpec,
    version_of: impl Fn(&str) -> u64,
) -> Result<Vec<FileEdit>, OpError> {
    if spec.declaration_param.trim().is_empty() || spec.call_argument.trim().is_empty() {
        return Err(OpError::InvalidIdentifier(
            "empty declaration_param/call_argument".to_string(),
        ));
    }
    apply_change_signature_ex(
        files,
        name,
        &ChangeSigSpec {
            declaration_param: spec.declaration_param.clone(),
            call_argument: Some(spec.call_argument.clone()),
            position: ParamPosition::Trailing,
        },
        version_of,
    )
}

/// The broadened change-signature application (`SEMANTIC_EDITING.md` §4). Beyond
/// [`apply_change_signature`]'s trailing-append case it supports **leading / positional** insertion
/// and a **declaration-only defaulted parameter** (`spec.call_argument == None`) that leaves every
/// call site untouched — the "add an optional knob with a default" refactor. Reordering / removing /
/// type-driven adapter synthesis remain the LSP rung; this rung refuses rather than guesses.
///
/// GAP-FIX gap6-semantic-lsp-signature-layermanifest item 2 — [`plan_change_signature`] (the blast-
/// radius resolver: declaration + every direct caller, from the SAME whole-word symbol graph
/// [`crate::graph::SymbolGraph::direct_callers`] uses for risk-sizing) is now consulted BEFORE any
/// text is touched, replacing the ad hoc `defined.contains(name)` re-check that used to stand in for
/// it. When `spec.call_argument` is `Some` (an intended call-site update, not a declaration-only
/// defaulted parameter), every file the graph names as a caller is cross-checked against the files
/// this splice actually changed; a caller file that produced NO edit — because the AST-rung text
/// splice below could not locate an actual `name(` call head in it, only a bare whole-word reference —
/// is refused via [`OpError::CallSiteUnresolved`] rather than silently committed with that call left on
/// the OLD signature. This closes the same bug class `apply_change_signature`'s own guard doc already
/// names: "the declaration changes, a usage goes stale."
///
/// # Errors
/// [`OpError::SymbolNotFound`] if `name` is not defined; [`OpError::InvalidIdentifier`] if the
/// declaration parameter is empty; [`OpError::CallSiteUnresolved`] if the blast radius names a call
/// site this splice could not actually update.
pub fn apply_change_signature_ex(
    files: &[SourceFile],
    name: &str,
    spec: &ChangeSigSpec,
    version_of: impl Fn(&str) -> u64,
) -> Result<Vec<FileEdit>, OpError> {
    if spec.declaration_param.trim().is_empty() {
        return Err(OpError::InvalidIdentifier(
            "empty declaration_param".to_string(),
        ));
    }
    if let Some(arg) = &spec.call_argument {
        if arg.trim().is_empty() {
            return Err(OpError::InvalidIdentifier(
                "empty call_argument".to_string(),
            ));
        }
    }
    // Resolve the full blast radius FIRST — the declaration(s) plus every direct caller — before any
    // text is touched. Also replaces the old standalone `defined.contains(name)` check: an empty
    // `declarations` set is exactly `OpError::SymbolNotFound`.
    let plan = plan_change_signature(files, name)?;

    let mut edits = Vec::new();
    for f in files {
        // The declaration's signature paren group in this file, if the def lives here.
        let decl_open: Option<usize> = crate::find_function(&f.source, f.lang, name)
            .ok()
            .flatten()
            .and_then(|span| {
                call_paren_offsets(&f.source[span.start_byte..span.end_byte], name)
                    .first()
                    .map(|rel| span.start_byte + rel)
            });

        // Collect full-group rewrites (open..=close -> new group text), applied back-to-front.
        let mut rewrites: Vec<(usize, usize, String)> = Vec::new();
        for open in call_paren_offsets(&f.source, name) {
            if Some(open) == decl_open {
                if let Some(r) =
                    rebuilt_group(&f.source, open, &spec.declaration_param, spec.position)
                {
                    rewrites.push(r);
                }
            } else if let Some(arg) = &spec.call_argument {
                // Declaration-only (`None`) leaves call sites untouched — defaulted parameter.
                if let Some(r) = rebuilt_group(&f.source, open, arg, spec.position) {
                    rewrites.push(r);
                }
            }
        }
        if rewrites.is_empty() {
            continue;
        }
        rewrites.sort_by_key(|(open, _, _)| std::cmp::Reverse(*open));
        let mut content = f.source.clone();
        for (open, close, text) in &rewrites {
            content.replace_range(*open..=*close, text);
        }
        edits.push(FileEdit {
            path: f.path.clone(),
            new_content: content,
            base_version: version_of(&f.path),
        });
    }

    // Cross-check the blast radius against what actually got edited — ONLY when this op intends to
    // touch call sites at all (`call_argument = None` is the declaration-only defaulted-parameter mode,
    // where every caller is deliberately left untouched by design, not by omission; see
    // `r11_declaration_only_defaulted_param_leaves_callers_untouched`). The graph is a documented
    // OVER-approximation (`graph.rs`: "missing a real caller is the dangerous error" — it counts any
    // whole-word reference, including one inside a comment/string, or a function used as a bare value
    // with no call parens at all), so this can rarely refuse a file that never truly needed an edit;
    // that false-refuse is the safe failure direction for a PCI/DSS commit gate — the reverse (a silent
    // stale call site) is the one this crate's guards exist to prevent.
    if spec.call_argument.is_some() {
        let edited_files: BTreeSet<&str> = edits.iter().map(|e| e.path.as_str()).collect();
        for site in &plan.affected_call_sites {
            if !edited_files.contains(site.file.as_str()) {
                return Err(OpError::CallSiteUnresolved(format!(
                    "{} references {name:?} (per the symbol graph's blast radius) but no call head \
                     could be located there to splice the new argument into — refusing rather than \
                     leaving it on the old signature",
                    site.file
                )));
            }
        }
    }

    Ok(edits)
}

// ============================ Extract / inline / move ============================

// Line-range structural operations. These are the AST-rung form of `SEMANTIC_EDITING.md` §4's
// "Extract / inline / move → structural AST transforms with reference rewrites": deterministic,
// parse-verified (through the atomic apply's parse gate), and guard-heavy. Data-flow-correct
// variable capture on extract, and multi-statement inline, are the LSP rung — refused here, never
// silently mis-transformed.

/// The 1-based inclusive line span of the definition of `name`, plus its byte span.
fn function_line_span(
    src: &str,
    lang: Language,
    name: &str,
) -> Option<(usize, usize, crate::Span)> {
    let span = crate::find_function(src, lang, name).ok().flatten()?;
    let start_line = src[..span.start_byte]
        .bytes()
        .filter(|&b| b == b'\n')
        .count()
        + 1;
    let end_line = src[..span.end_byte].bytes().filter(|&b| b == b'\n').count() + 1;
    Some((start_line, end_line, span))
}

fn leading_ws(line: &str) -> String {
    line.chars().take_while(|c| c.is_whitespace()).collect()
}

/// Extract lines `[start_line, end_line]` (1-based, inclusive) from inside `enclosing`'s body into a
/// new zero-arg function `new_name`, replacing them with a call. Returns a single-file [`FileEdit`].
///
/// Guards: `new_name` valid + not already defined; the range must lie strictly inside the enclosing
/// function's body (not the signature or closing line); the enclosing function must exist.
///
/// # Errors
/// See [`OpError`].
pub fn plan_extract_function(
    file: &SourceFile,
    enclosing: &str,
    start_line: usize,
    end_line: usize,
    new_name: &str,
    version: u64,
) -> Result<FileEdit, OpError> {
    if !is_valid_ident(new_name) {
        return Err(OpError::InvalidIdentifier(new_name.to_string()));
    }
    let graph = SymbolGraph::build(std::slice::from_ref(file));
    if graph.symbols().iter().any(|s| s.name == new_name) {
        return Err(OpError::NameCollision(new_name.to_string()));
    }
    let (fn_start, fn_end, _span) = function_line_span(&file.source, file.lang, enclosing)
        .ok_or_else(|| OpError::SymbolNotFound(enclosing.to_string()))?;
    if start_line <= fn_start || end_line >= fn_end || start_line > end_line {
        return Err(OpError::InvalidIdentifier(format!(
            "range {start_line}..={end_line} not strictly inside {enclosing} body ({fn_start}..={fn_end})"
        )));
    }

    let lines: Vec<&str> = file.source.lines().collect();
    let body: Vec<&str> = lines[start_line - 1..end_line].to_vec();
    let call_indent = leading_ws(body[0]);
    // Common indent to dedent the extracted body into the new function.
    let common: usize = body
        .iter()
        .filter(|l| !l.trim().is_empty())
        .map(|l| leading_ws(l).len())
        .min()
        .unwrap_or(0);

    let inner: Vec<String> = body
        .iter()
        .map(|l| {
            if l.len() >= common {
                format!("    {}", &l[common..])
            } else {
                format!("    {}", l.trim_start())
            }
        })
        .collect();
    // Brace-block languages (Rust, Go, JS, TS, Java) share one function-header + call shape; Python is
    // the indentation-block outlier. The extracted call is a bare zero-arg invocation in every case.
    let (new_fn, call): (String, String) = match file.lang {
        Language::Rust => (
            format!("fn {new_name}() {{\n{}\n}}", inner.join("\n")),
            format!("{call_indent}{new_name}();"),
        ),
        Language::Go => (
            format!("func {new_name}() {{\n{}\n}}", inner.join("\n")),
            format!("{call_indent}{new_name}()"),
        ),
        Language::JavaScript | Language::TypeScript => (
            format!("function {new_name}() {{\n{}\n}}", inner.join("\n")),
            format!("{call_indent}{new_name}();"),
        ),
        Language::Java => (
            format!("void {new_name}() {{\n{}\n}}", inner.join("\n")),
            format!("{call_indent}{new_name}();"),
        ),
        Language::Python => (
            format!("def {new_name}():\n{}", inner.join("\n")),
            format!("{call_indent}{new_name}()"),
        ),
    };

    // Rebuild: replace body lines with the call; append the new function after the enclosing fn.
    let mut out: Vec<String> = Vec::with_capacity(lines.len() + 4);
    for (i, l) in lines.iter().enumerate() {
        let ln = i + 1;
        if ln == start_line {
            out.push(call.clone());
        }
        if ln >= start_line && ln <= end_line {
            continue;
        }
        out.push((*l).to_string());
        if ln == fn_end {
            out.push(String::new());
            out.push(new_fn.clone());
        }
    }
    let mut content = out.join("\n");
    if file.source.ends_with('\n') {
        content.push('\n');
    }
    Ok(FileEdit {
        path: file.path.clone(),
        new_content: content,
        base_version: version,
    })
}

/// Inline a trivial zero-parameter, single-expression function `name` into every call site and remove
/// its definition. Returns one [`FileEdit`] per changed file.
///
/// Guards: the function must have zero parameters and a single-expression body (Rust `{ EXPR }` or
/// `{ EXPR }` with a trailing expr; Python `return EXPR`); it must have at least one call site. Any
/// non-trivial body is refused (the LSP rung handles those) rather than mis-inlined.
///
/// # Errors
/// See [`OpError`].
pub fn plan_inline_function(
    files: &[SourceFile],
    name: &str,
    version_of: impl Fn(&str) -> u64,
) -> Result<Vec<FileEdit>, OpError> {
    // Find the definition + extract its inlinable expression.
    let mut def_file: Option<&SourceFile> = None;
    let mut def_span: Option<crate::Span> = None;
    for f in files {
        if let Some(span) = crate::find_function(&f.source, f.lang, name).ok().flatten() {
            def_file = Some(f);
            def_span = Some(span);
            break;
        }
    }
    let (df, span) = match (def_file, def_span) {
        (Some(f), Some(s)) => (f, s),
        _ => return Err(OpError::SymbolNotFound(name.to_string())),
    };
    let def_text = &df.source[span.start_byte..span.end_byte];
    let expr = inlinable_expr(def_text, df.lang, name)
        .ok_or_else(|| OpError::InvalidIdentifier(format!("{name} is not trivially inlinable")))?;

    let call = format!("{name}()");
    let replacement = format!("({expr})");
    let mut edits = Vec::new();
    let mut any_call = false;
    for f in files {
        let mut content = f.source.clone();
        // First remove the definition (only in its own file), then rewrite calls.
        if std::ptr::eq(f, df) {
            // Remove the def span plus a trailing blank line if present.
            let mut end = span.end_byte;
            let after = &content[end..];
            if let Some(stripped) = after.strip_prefix('\n') {
                if stripped.starts_with('\n') {
                    end += 1; // swallow one blank separator line
                }
            }
            content.replace_range(span.start_byte..end, "");
        }
        let n = content.matches(&call).count();
        if n > 0 {
            any_call = true;
            content = content.replace(&call, &replacement);
        }
        if content != f.source {
            edits.push(FileEdit {
                path: f.path.clone(),
                new_content: content,
                base_version: version_of(&f.path),
            });
        }
    }
    if !any_call {
        return Err(OpError::SymbolNotFound(format!("{name} (no call sites)")));
    }
    Ok(edits)
}

/// Extract the single inlinable expression from a zero-arg function definition, or `None` if the body
/// is non-trivial (multiple statements, has parameters, etc.).
fn inlinable_expr(def_text: &str, lang: Language, name: &str) -> Option<String> {
    // Reject any parameter: the text between the signature parens must be empty.
    let open = def_text.find(&format!("{name}("))? + name.len();
    let close = matching_paren(def_text, open)?;
    if !def_text[open + 1..close].trim().is_empty() {
        return None;
    }
    match lang {
        // Brace-block languages: a single-expression body between `{ … }`. Rust allows a bare tail
        // expression (`{ EXPR }`); Go/JS/TS/Java write `{ return EXPR; }` — strip an optional leading
        // `return` and trailing `;` so the inlined form is the same bare expression in every case.
        Language::Rust
        | Language::Go
        | Language::JavaScript
        | Language::TypeScript
        | Language::Java => {
            let b_open = def_text.find('{')?;
            let b_close = def_text.rfind('}')?;
            if b_close <= b_open {
                return None;
            }
            let body = def_text[b_open + 1..b_close].trim();
            if body.is_empty() || body.lines().count() > 1 {
                return None;
            }
            let one = body
                .trim()
                .trim_end_matches(';')
                .trim()
                .strip_prefix("return ")
                .unwrap_or_else(|| body.trim().trim_end_matches(';').trim())
                .trim();
            // A single expression only — a remaining semicolon means multiple statements.
            if one.is_empty() || one.contains(';') {
                return None;
            }
            Some(one.to_string())
        }
        Language::Python => {
            // `def name():` then a single `return EXPR`.
            let colon = def_text.find(':')?;
            let rest = def_text[colon + 1..].trim();
            let ret = rest.strip_prefix("return ")?;
            let one = ret.trim();
            if one.is_empty() || one.contains('\n') {
                return None;
            }
            Some(one.to_string())
        }
    }
}

/// Move the definition of `name` from `from_path` to `to_path`, atomically (both files change in one
/// edit set). Returns two [`FileEdit`]s. The definition text is appended to the destination; the
/// source file has the span (plus one trailing blank line) removed.
///
/// Guards: `name` must be defined in `from_path`; both files must be present in `files`.
///
/// # Errors
/// See [`OpError`].
pub fn plan_move_definition(
    files: &[SourceFile],
    name: &str,
    from_path: &str,
    to_path: &str,
    version_of: impl Fn(&str) -> u64,
) -> Result<Vec<FileEdit>, OpError> {
    let from = files
        .iter()
        .find(|f| f.path == from_path)
        .ok_or_else(|| OpError::SymbolNotFound(format!("file {from_path}")))?;
    let to = files
        .iter()
        .find(|f| f.path == to_path)
        .ok_or_else(|| OpError::SymbolNotFound(format!("file {to_path}")))?;
    let span = crate::find_function(&from.source, from.lang, name)
        .ok()
        .flatten()
        .ok_or_else(|| OpError::SymbolNotFound(name.to_string()))?;
    let def_text = from.source[span.start_byte..span.end_byte].to_string();

    // Remove from source (+ a trailing blank separator line if present).
    let mut src_content = from.source.clone();
    let mut end = span.end_byte;
    if src_content[end..].starts_with('\n') {
        end += 1;
        if src_content[end..].starts_with('\n') {
            end += 1;
        }
    }
    src_content.replace_range(span.start_byte..end, "");

    // Append to destination.
    let mut dst_content = to.source.clone();
    if !dst_content.ends_with('\n') && !dst_content.is_empty() {
        dst_content.push('\n');
    }
    if !dst_content.is_empty() {
        dst_content.push('\n');
    }
    dst_content.push_str(&def_text);
    if !dst_content.ends_with('\n') {
        dst_content.push('\n');
    }

    Ok(vec![
        FileEdit {
            path: from.path.clone(),
            new_content: src_content,
            base_version: version_of(&from.path),
        },
        FileEdit {
            path: to.path.clone(),
            new_content: dst_content,
            base_version: version_of(&to.path),
        },
    ])
}

/// Convenience: the language of a rust/python path, for the atomic apply's parse gate.
#[must_use]
pub fn lang_from_path(path: &str) -> Option<Language> {
    match path.rsplit('.').next() {
        Some("rs") => Some(Language::Rust),
        Some("py") => Some(Language::Python),
        Some("go") => Some(Language::Go),
        Some("js" | "jsx" | "mjs" | "cjs") => Some(Language::JavaScript),
        Some("ts" | "tsx") => Some(Language::TypeScript),
        Some("java") => Some(Language::Java),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace::{MemorySink, Workspace};

    fn rs(path: &str, src: &str) -> SourceFile {
        SourceFile::new(path, Language::Rust, src)
    }

    #[test]
    fn rename_rewrites_definition_and_all_call_sites_across_files() {
        let lib = rs("lib.rs", "pub fn helper() -> i32 {\n    7\n}\n");
        let main = rs("main.rs", "fn run() -> i32 {\n    helper() + helper()\n}\n");
        let files = vec![lib, main];
        let edits = plan_rename_symbol(&files, "helper", "assist", |_| 0).unwrap();
        // Both files change.
        assert_eq!(edits.len(), 2);
        let libedit = edits.iter().find(|e| e.path == "lib.rs").unwrap();
        assert!(libedit.new_content.contains("fn assist()"));
        assert!(!libedit.new_content.contains("helper"));
        let mainedit = edits.iter().find(|e| e.path == "main.rs").unwrap();
        // BOTH call sites rewritten.
        assert_eq!(mainedit.new_content.matches("assist()").count(), 2);
        assert!(!mainedit.new_content.contains("helper"));
    }

    #[test]
    fn rename_does_not_touch_substring_matches() {
        let f = rs(
            "a.rs",
            "fn run() {}\nfn caller() { rerun(); run(); }\nfn rerun() {}\n",
        );
        let edits = plan_rename_symbol(&[f], "run", "go", |_| 0).unwrap();
        let e = &edits[0];
        // `rerun` must be untouched; `run` becomes `go`.
        assert!(e.new_content.contains("fn go()"));
        assert!(e.new_content.contains("rerun()")); // NOT `rego()`
        assert!(e.new_content.contains("fn rerun()"));
        assert!(e.new_content.contains("go();"));
    }

    #[test]
    fn rename_refuses_invalid_identifier() {
        let f = rs("a.rs", "fn helper() {}\n");
        assert_eq!(
            plan_rename_symbol(&[f], "helper", "9bad", |_| 0).unwrap_err(),
            OpError::InvalidIdentifier("9bad".into())
        );
    }

    #[test]
    fn rename_refuses_collision_with_existing_symbol() {
        let f = rs("a.rs", "fn helper() {}\nfn other() {}\n");
        assert_eq!(
            plan_rename_symbol(&[f], "helper", "other", |_| 0).unwrap_err(),
            OpError::NameCollision("other".into())
        );
    }

    #[test]
    fn rename_refuses_unknown_symbol() {
        let f = rs("a.rs", "fn helper() {}\n");
        assert_eq!(
            plan_rename_symbol(&[f], "ghost", "x", |_| 0).unwrap_err(),
            OpError::SymbolNotFound("ghost".into())
        );
    }

    #[test]
    fn planned_rename_applies_atomically_and_parses() {
        let lib = rs("lib.rs", "pub fn helper() -> i32 {\n    7\n}\n");
        let main = rs("main.rs", "fn run() -> i32 {\n    helper()\n}\n");
        let mut ws = Workspace::new();
        ws.insert("lib.rs", lib.source.clone());
        ws.insert("main.rs", main.source.clone());
        let mut sink = MemorySink::new();
        sink.files.insert("lib.rs".into(), lib.source.clone());
        sink.files.insert("main.rs".into(), main.source.clone());

        let edits =
            plan_rename_symbol(&[lib, main], "helper", "assist", |p| ws.version(p)).unwrap();
        let out = ws.apply_atomic(&edits, lang_from_path, &mut sink).unwrap();
        assert_eq!(out.committed.len(), 2);
        assert!(ws.content("lib.rs").unwrap().contains("fn assist()"));
        assert!(ws.content("main.rs").unwrap().contains("assist()"));
    }

    #[test]
    fn change_signature_reports_declaration_and_call_sites() {
        let src = "\
fn target(x: i32) -> i32 { x }
fn caller_one() -> i32 { target(1) }
fn caller_two() -> i32 { target(2) }
fn unrelated() -> i32 { 0 }
";
        let plan = plan_change_signature(&[rs("a.rs", src)], "target").unwrap();
        assert_eq!(plan.declarations, vec![SymbolId::new("a.rs", "target")]);
        assert_eq!(
            plan.affected_call_sites,
            vec![
                SymbolId::new("a.rs", "caller_one"),
                SymbolId::new("a.rs", "caller_two"),
            ]
        );
    }

    #[test]
    fn change_signature_unknown_symbol_errors() {
        assert_eq!(
            plan_change_signature(&[rs("a.rs", "fn a() {}\n")], "ghost").unwrap_err(),
            OpError::SymbolNotFound("ghost".into())
        );
    }

    // ---- EDIT-06: change-signature APPLICATION (decl + every call site + adapter) ----

    #[test]
    fn gap_ainxt_semantic_edit_06_change_signature_applies_decl_and_call_sites() {
        // A signature change that ADDS a parameter must rewrite the declaration AND every call site,
        // splicing in the adapter/default arg — not merely resolve the blast radius.
        let lib = rs(
            "lib.rs",
            "pub fn charge(amount: i32) -> i32 {\n    amount\n}\n",
        );
        let main = rs(
            "main.rs",
            "fn run() -> i32 {\n    charge(10) + charge(20)\n}\n",
        );
        let files = vec![lib, main];
        let spec = AddParamSpec {
            declaration_param: "ctx: &Ctx".into(),
            call_argument: "&ctx".into(),
        };
        let edits = apply_change_signature(&files, "charge", &spec, |_| 0).unwrap();
        let libe = edits.iter().find(|e| e.path == "lib.rs").unwrap();
        // Declaration got the new parameter appended after the existing one.
        assert!(libe
            .new_content
            .contains("fn charge(amount: i32, ctx: &Ctx)"));
        let maine = edits.iter().find(|e| e.path == "main.rs").unwrap();
        // BOTH call sites got the adapter argument.
        assert_eq!(maine.new_content.matches("&ctx").count(), 2);
        assert!(maine.new_content.contains("charge(10, &ctx)"));
        assert!(maine.new_content.contains("charge(20, &ctx)"));
        // And it still parses after the atomic apply's gate.
        assert!(!crate::parse(&libe.new_content, Language::Rust)
            .unwrap()
            .root_node()
            .has_error());
    }

    #[test]
    fn change_signature_apply_into_empty_param_list() {
        let f = rs("a.rs", "fn f() -> i32 {\n    1\n}\nfn c() { f(); }\n");
        let spec = AddParamSpec {
            declaration_param: "x: i32".into(),
            call_argument: "0".into(),
        };
        let edits = apply_change_signature(&[f], "f", &spec, |_| 0).unwrap();
        let e = &edits[0];
        assert!(e.new_content.contains("fn f(x: i32)"));
        assert!(e.new_content.contains("f(0)"));
    }

    #[test]
    fn change_signature_apply_refuses_unknown_symbol() {
        let f = rs("a.rs", "fn a() {}\n");
        let spec = AddParamSpec {
            declaration_param: "x: i32".into(),
            call_argument: "0".into(),
        };
        assert_eq!(
            apply_change_signature(&[f], "ghost", &spec, |_| 0).unwrap_err(),
            OpError::SymbolNotFound("ghost".into())
        );
    }

    // ---- GAP-FIX gap6-semantic-lsp-signature-layermanifest item 2: `plan_change_signature` wired in
    // BEFORE `apply_change_signature` runs, closing a genuine stale-call-site gap. ----

    #[test]
    fn gap6_change_signature_updates_a_call_site_separated_from_its_parens_by_whitespace() {
        // Valid (if unidiomatic) Rust: a space between the callee name and its call parens. The OLD
        // `call_paren_offsets` matched only the literal substring "charge(" — this call site would have
        // been silently left on the OLD signature (`charge (10)`, never `charge (10, &ctx)`) while the
        // declaration in lib.rs got the new parameter — a stale call site that would fail to compile.
        let lib = rs(
            "lib.rs",
            "pub fn charge(amount: i32) -> i32 {\n    amount\n}\n",
        );
        let main = rs("main.rs", "fn run() -> i32 {\n    charge (10)\n}\n");
        let spec = AddParamSpec {
            declaration_param: "ctx: &Ctx".into(),
            call_argument: "&ctx".into(),
        };
        let edits = apply_change_signature(&[lib, main], "charge", &spec, |_| 0).unwrap();
        let libe = edits.iter().find(|e| e.path == "lib.rs").unwrap();
        assert!(libe
            .new_content
            .contains("fn charge(amount: i32, ctx: &Ctx)"));
        let maine = edits.iter().find(|e| e.path == "main.rs").unwrap();
        // The whitespace-separated call site is NOW correctly updated, not left stale.
        assert!(
            maine.new_content.contains("charge (10, &ctx)"),
            "the whitespace-separated call site must be updated: {}",
            maine.new_content
        );
    }

    #[test]
    fn gap6_change_signature_also_declaration_written_with_whitespace_before_parens() {
        // The same gap, but on the DECLARATION side: `decl_open` is resolved via `call_paren_offsets`
        // too, so a declaration written `fn charge (amount: i32)` previously would never even be found
        // as its own call/decl head — the new parameter would never be added at all.
        let lib = rs(
            "lib.rs",
            "pub fn charge (amount: i32) -> i32 {\n    amount\n}\n",
        );
        let main = rs("main.rs", "fn run() -> i32 {\n    charge(10)\n}\n");
        let spec = AddParamSpec {
            declaration_param: "ctx: &Ctx".into(),
            call_argument: "&ctx".into(),
        };
        let edits = apply_change_signature(&[lib, main], "charge", &spec, |_| 0).unwrap();
        let libe = edits.iter().find(|e| e.path == "lib.rs").unwrap();
        assert!(
            libe.new_content.contains("charge (amount: i32, ctx: &Ctx)"),
            "the whitespace-separated declaration must gain the new parameter: {}",
            libe.new_content
        );
    }

    #[test]
    fn gap6_change_signature_refuses_rather_than_leave_a_referenced_but_uncallable_site_stale() {
        // `charge` is referenced in `indirect.rs` as a bare VALUE (a function pointer), never called —
        // the whole-word symbol graph conservatively counts it as a caller (`graph.rs`'s documented
        // over-approximation), but there is no `(` there at all for the AST-rung splice to update. This
        // must REFUSE the whole op rather than silently commit a signature change that leaves a
        // graph-reported reference sitting on the old (now-incompatible) function type.
        let lib = rs(
            "lib.rs",
            "pub fn charge(amount: i32) -> i32 {\n    amount\n}\n",
        );
        let indirect = rs(
            "indirect.rs",
            "fn get_fn() -> fn(i32) -> i32 {\n    charge\n}\n",
        );
        let spec = AddParamSpec {
            declaration_param: "ctx: &Ctx".into(),
            call_argument: "&ctx".into(),
        };
        let err = apply_change_signature(&[lib, indirect], "charge", &spec, |_| 0).unwrap_err();
        assert!(
            matches!(err, OpError::CallSiteUnresolved(ref detail) if detail.contains("indirect.rs")),
            "expected a CallSiteUnresolved naming indirect.rs, got {err:?}"
        );
    }

    #[test]
    fn gap6_change_signature_declaration_only_default_is_not_subject_to_the_call_site_cross_check()
    {
        // `call_argument: None` (a defaulted parameter) deliberately leaves EVERY call site untouched —
        // this is by design, not an unresolved call site, so the new cross-check must NOT fire here.
        let lib = rs(
            "lib.rs",
            "pub fn charge(amount: i32) -> i32 {\n    amount\n}\n",
        );
        let indirect = rs(
            "indirect.rs",
            "fn get_fn() -> fn(i32) -> i32 {\n    charge\n}\n",
        );
        let spec = ChangeSigSpec {
            declaration_param: "retries: i32".into(),
            call_argument: None,
            position: ParamPosition::Trailing,
        };
        let edits = apply_change_signature_ex(&[lib, indirect], "charge", &spec, |_| 0).unwrap();
        let libe = edits.iter().find(|e| e.path == "lib.rs").unwrap();
        assert!(libe
            .new_content
            .contains("fn charge(amount: i32, retries: i32)"));
        // indirect.rs is untouched by design, and correctly produces no edit at all.
        assert!(edits.iter().all(|e| e.path != "indirect.rs"));
    }

    // ---- EDIT-05: extract / inline / move ----

    #[test]
    fn gap_ainxt_semantic_edit_05_extract_function_pulls_range_into_new_fn() {
        let src = "fn outer() {\n    let a = 1;\n    let b = 2;\n    let c = a + b;\n}\n";
        let f = rs("m.rs", src);
        // Extract lines 2..=3 (the two `let` statements) into `setup`.
        let edit = plan_extract_function(&f, "outer", 2, 3, "setup", 0).unwrap();
        // The new function exists and carries the extracted statements.
        assert!(edit.new_content.contains("fn setup() {"));
        assert!(edit.new_content.contains("let a = 1;"));
        assert!(edit.new_content.contains("let b = 2;"));
        // The call replaced the range inside `outer`.
        assert!(edit.new_content.contains("setup();"));
        // `outer` no longer directly declares a/b before the call.
        let outer_body = &edit.new_content[edit.new_content.find("fn outer").unwrap()
            ..edit.new_content.find("fn setup").unwrap()];
        assert!(outer_body.contains("setup();"));
        assert!(!outer_body.contains("let a = 1;"));
        // Parses cleanly.
        assert!(!crate::parse(&edit.new_content, Language::Rust)
            .unwrap()
            .root_node()
            .has_error());
    }

    #[test]
    fn extract_refuses_range_outside_body() {
        let f = rs("m.rs", "fn outer() {\n    let a = 1;\n}\n");
        // Line 1 is the signature — not strictly inside the body.
        assert!(plan_extract_function(&f, "outer", 1, 1, "x", 0).is_err());
    }

    #[test]
    fn extract_refuses_name_collision() {
        let f = rs("m.rs", "fn outer() {\n    let a = 1;\n}\nfn taken() {}\n");
        assert_eq!(
            plan_extract_function(&f, "outer", 2, 2, "taken", 0).unwrap_err(),
            OpError::NameCollision("taken".into())
        );
    }

    #[test]
    fn gap_ainxt_semantic_edit_05_inline_trivial_function_into_call_sites() {
        let src =
            "fn base() -> i32 { 42 }\nfn a() -> i32 { base() + 1 }\nfn b() -> i32 { base() }\n";
        let f = rs("m.rs", src);
        let edits = plan_inline_function(&[f], "base", |_| 0).unwrap();
        let e = &edits[0];
        // The definition is gone; call sites carry the inlined expression.
        assert!(!e.new_content.contains("fn base"));
        assert!(e.new_content.contains("(42) + 1"));
        assert!(e.new_content.contains("fn b() -> i32 { (42) }"));
        assert!(!crate::parse(&e.new_content, Language::Rust)
            .unwrap()
            .root_node()
            .has_error());
    }

    #[test]
    fn inline_refuses_nontrivial_body() {
        // Multi-statement body → not inlinable, refused (never mis-inlined).
        let f = rs(
            "m.rs",
            "fn base() -> i32 {\n    let x = 1;\n    x + 1\n}\nfn a() { base(); }\n",
        );
        assert!(plan_inline_function(&[f], "base", |_| 0).is_err());
    }

    #[test]
    fn inline_refuses_function_with_parameters() {
        let f = rs(
            "m.rs",
            "fn base(x: i32) -> i32 { x }\nfn a() { base(1); }\n",
        );
        assert!(plan_inline_function(&[f], "base", |_| 0).is_err());
    }

    #[test]
    fn gap_ainxt_semantic_edit_05_move_definition_across_files() {
        let a = rs("a.rs", "fn keep() {}\n\nfn mover() -> i32 {\n    7\n}\n");
        let b = rs("b.rs", "fn other() {}\n");
        let files = vec![a, b];
        let edits = plan_move_definition(&files, "mover", "a.rs", "b.rs", |_| 0).unwrap();
        let ae = edits.iter().find(|e| e.path == "a.rs").unwrap();
        let be = edits.iter().find(|e| e.path == "b.rs").unwrap();
        // Removed from source, appended to destination.
        assert!(!ae.new_content.contains("fn mover"));
        assert!(ae.new_content.contains("fn keep"));
        assert!(be.new_content.contains("fn mover() -> i32 {"));
        assert!(be.new_content.contains("fn other"));
        assert!(!crate::parse(&be.new_content, Language::Rust)
            .unwrap()
            .root_node()
            .has_error());
    }

    #[test]
    fn move_definition_unknown_symbol_errors() {
        let a = rs("a.rs", "fn keep() {}\n");
        let b = rs("b.rs", "fn other() {}\n");
        assert!(plan_move_definition(&[a, b], "ghost", "a.rs", "b.rs", |_| 0).is_err());
    }
}
