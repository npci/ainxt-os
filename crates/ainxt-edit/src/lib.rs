// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! ainxt-edit — the edit engine (Phase 3, Code + SDLC profiles).
//!
//! Applying a model's edits to real source is where "helpful" code assistants quietly corrupt
//! files. This engine is deliberately conservative:
//!
//! - **Anchor matching is exact first, then whitespace-insensitive, and NEVER semantic-fuzzy.** A
//!   fuzzy match that silently lands on the wrong line is worse than no edit at all.
//! - **Ambiguous or unmatched anchors are structured errors, not guesses** — the caller feeds them
//!   back for bounded same-turn self-correction.
//! - **All-or-nothing.** A dry run classifies every edit against an in-memory snapshot; only if all
//!   are safe (and non-overlapping) is anything written. A half-applied edit set is never produced.
//!
//! It also encodes three edit bugs that have burned the SDLC pipeline before, as invariants:
//! - [`restore_missing_imports`] — a full-file regeneration silently drops imports; the ones present
//!   before but missing after are re-injected.
//! - [`field_rename_is_safe`] — renaming a field by editing only its declaration leaves every usage
//!   dangling; a field with live usages is refused (the model must add a new field instead).
//! - [`find_declaration_line`] — the first `name(` in a file is often a *call site*, not the
//!   definition; the span finder prefers the line that also carries a declaration keyword.
//!
//! Pure and string-based (no parser) so it is exhaustively testable; a tree-sitter-backed,
//! AST-precise variant can implement the same surface later. Clean-room throughout.

use serde::{Deserialize, Serialize};

/// Toolchain seams for the edit ladder's top rung (LSP rename/refs) and the deterministic-verify
/// (compile/test) gate. Both are infra-gated: real drivers need a live language server / compiler;
/// offline stand-ins ([`toolchain::CannedLspClient`], [`toolchain::OfflineVerifyToolchain`]) keep the
/// engine honest without faking a green.
pub mod toolchain;

// ============================ Language ============================

/// The languages the heuristics know about (import + declaration vocabulary). `Other` disables the
/// language-specific rules but leaves anchor editing fully functional.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    Rust,
    Python,
    Java,
    JavaScript,
    TypeScript,
    Go,
    Other,
}

impl Language {
    /// Best-effort language from a file extension.
    pub fn from_extension(ext: &str) -> Language {
        match ext.trim_start_matches('.').to_ascii_lowercase().as_str() {
            "rs" => Language::Rust,
            "py" => Language::Python,
            "java" => Language::Java,
            "js" | "jsx" | "mjs" | "cjs" => Language::JavaScript,
            "ts" | "tsx" => Language::TypeScript,
            "go" => Language::Go,
            _ => Language::Other,
        }
    }

    /// Whether `line` (already available whole) is an import statement in this language.
    fn is_import(&self, line: &str) -> bool {
        let t = line.trim_start();
        match self {
            Language::Rust => t.starts_with("use "),
            Language::Python => t.starts_with("import ") || t.starts_with("from "),
            Language::Java => t.starts_with("import "),
            Language::JavaScript | Language::TypeScript => {
                t.starts_with("import ") || (t.starts_with("const ") && t.contains("require("))
            }
            Language::Go => t.starts_with("import "),
            Language::Other => false,
        }
    }

    /// Declaration keywords whose presence on a line marks it as a *definition* (not a call site).
    fn decl_keywords(&self) -> &'static [&'static str] {
        match self {
            Language::Rust => &["fn", "struct", "enum", "trait", "impl"],
            Language::Python => &["def", "class"],
            Language::Java => &[
                "public",
                "private",
                "protected",
                "static",
                "class",
                "interface",
                "void",
            ],
            Language::JavaScript | Language::TypeScript => {
                &["function", "class", "const", "let", "async"]
            }
            Language::Go => &["func", "type"],
            Language::Other => &[],
        }
    }
}

// ============================ Edit envelope ============================

/// One edit. Anchors are literal text from the file; the engine locates them safely.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Edit {
    /// Replace the text matching `anchor` with `replacement`.
    Replace { anchor: String, replacement: String },
    /// Insert `content` immediately after the text matching `anchor`.
    InsertAfter { anchor: String, content: String },
    /// Delete the text matching `anchor`.
    Delete { anchor: String },
}

impl Edit {
    fn anchor(&self) -> &str {
        match self {
            Edit::Replace { anchor, .. }
            | Edit::InsertAfter { anchor, .. }
            | Edit::Delete { anchor } => anchor,
        }
    }
}

/// How an anchor was matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchKind {
    Exact,
    WhitespaceInsensitive,
}

/// A structured reason an edit could not be applied — fed back for self-correction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EditError {
    EmptyAnchor {
        index: usize,
    },
    UnmatchedAnchor {
        index: usize,
        anchor_preview: String,
    },
    AmbiguousAnchor {
        index: usize,
        count: usize,
        anchor_preview: String,
    },
    /// Two edits target overlapping spans of the file.
    Overlap {
        index: usize,
        other: usize,
    },
}

impl std::fmt::Display for EditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EditError::EmptyAnchor { index } => write!(f, "edit {index}: empty anchor"),
            EditError::UnmatchedAnchor {
                index,
                anchor_preview,
            } => {
                write!(f, "edit {index}: anchor not found: {anchor_preview:?}")
            }
            EditError::AmbiguousAnchor {
                index,
                count,
                anchor_preview,
            } => {
                write!(
                    f,
                    "edit {index}: anchor matched {count} places (ambiguous): {anchor_preview:?}"
                )
            }
            EditError::Overlap { index, other } => write!(f, "edit {index} overlaps edit {other}"),
        }
    }
}

/// One successfully-applied edit and how its anchor matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedEdit {
    pub index: usize,
    pub kind: MatchKind,
}

/// The result of a successful all-or-nothing apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditOutcome {
    pub content: String,
    pub applied: Vec<AppliedEdit>,
}

fn preview(anchor: &str) -> String {
    let first_line = anchor.lines().next().unwrap_or("").trim();
    if first_line.chars().count() > 48 {
        format!("{}…", first_line.chars().take(48).collect::<String>())
    } else {
        first_line.to_string()
    }
}

fn normalize_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Byte offsets of the start of every line (0 and each index just after a `\n`).
fn line_starts(s: &str) -> Vec<usize> {
    let mut v = vec![0usize];
    for (i, b) in s.bytes().enumerate() {
        if b == b'\n' {
            v.push(i + 1);
        }
    }
    v
}

/// Whitespace-insensitive spans whose normalized text equals the normalized `anchor`. Line-anchored
/// on both ends so we never match a fragment inside a line.
fn find_ws_insensitive(original: &str, anchor: &str) -> Vec<(usize, usize)> {
    let na = normalize_ws(anchor);
    if na.is_empty() {
        return Vec::new();
    }
    let starts = line_starts(original);
    let ends: Vec<usize> = starts
        .iter()
        .skip(1)
        .map(|&s| s - 1) // position of the '\n' ending the previous line
        .chain(std::iter::once(original.len()))
        .collect();
    let mut matches = Vec::new();
    for &start in &starts {
        for &end in ends.iter().filter(|&&e| e >= start) {
            let span = &original[start..end];
            let ns = normalize_ws(span);
            if ns.len() > na.len() {
                break; // extending further only grows it
            }
            if ns == na {
                matches.push((start, end));
                break;
            }
        }
    }
    matches
}

enum Located {
    At(usize, usize, MatchKind),
    Empty,
    Unmatched,
    Ambiguous(usize),
}

fn locate(original: &str, anchor: &str) -> Located {
    if anchor.is_empty() {
        return Located::Empty;
    }
    let exact: Vec<usize> = original.match_indices(anchor).map(|(i, _)| i).collect();
    match exact.len() {
        1 => return Located::At(exact[0], exact[0] + anchor.len(), MatchKind::Exact),
        n if n > 1 => return Located::Ambiguous(n),
        _ => {}
    }
    let ws = find_ws_insensitive(original, anchor);
    match ws.len() {
        1 => Located::At(ws[0].0, ws[0].1, MatchKind::WhitespaceInsensitive),
        0 => Located::Unmatched,
        n => Located::Ambiguous(n),
    }
}

/// Dry-run classify + apply a set of anchor edits **all-or-nothing**. Returns the new content, or
/// every structured error found (so the model can fix them all at once). Nothing is applied unless
/// every edit resolves to a unique, non-overlapping span.
pub fn apply(original: &str, edits: &[Edit]) -> Result<EditOutcome, Vec<EditError>> {
    let mut errors = Vec::new();
    // (index, start, end, new_text, kind)
    let mut resolved: Vec<(usize, usize, usize, String, MatchKind)> = Vec::new();

    for (i, edit) in edits.iter().enumerate() {
        match locate(original, edit.anchor()) {
            Located::Empty => errors.push(EditError::EmptyAnchor { index: i }),
            Located::Unmatched => errors.push(EditError::UnmatchedAnchor {
                index: i,
                anchor_preview: preview(edit.anchor()),
            }),
            Located::Ambiguous(count) => errors.push(EditError::AmbiguousAnchor {
                index: i,
                count,
                anchor_preview: preview(edit.anchor()),
            }),
            Located::At(start, end, kind) => {
                let (s, e, text) = match edit {
                    Edit::Replace { replacement, .. } => (start, end, replacement.clone()),
                    Edit::Delete { .. } => (start, end, String::new()),
                    Edit::InsertAfter { content, .. } => (end, end, content.clone()),
                };
                resolved.push((i, s, e, text, kind));
            }
        }
    }

    // Overlap detection (only meaningful if every anchor resolved).
    if errors.is_empty() {
        let mut order: Vec<&(usize, usize, usize, String, MatchKind)> = resolved.iter().collect();
        order.sort_by_key(|r| (r.1, r.2));
        for pair in order.windows(2) {
            let (a, b) = (pair[0], pair[1]);
            if b.1 < a.2 {
                errors.push(EditError::Overlap {
                    index: b.0,
                    other: a.0,
                });
            }
        }
    }

    if !errors.is_empty() {
        errors.sort_by_key(error_index);
        return Err(errors);
    }

    // Apply back-to-front so earlier byte offsets stay valid.
    let mut content = original.to_string();
    resolved.sort_by_key(|r| std::cmp::Reverse(r.1));
    for (_, s, e, text, _) in &resolved {
        content.replace_range(*s..*e, text);
    }
    let mut applied: Vec<AppliedEdit> = resolved
        .iter()
        .map(|(i, _, _, _, kind)| AppliedEdit {
            index: *i,
            kind: *kind,
        })
        .collect();
    applied.sort_by_key(|a| a.index);
    Ok(EditOutcome { content, applied })
}

fn error_index(e: &EditError) -> usize {
    match e {
        EditError::EmptyAnchor { index }
        | EditError::UnmatchedAnchor { index, .. }
        | EditError::AmbiguousAnchor { index, .. }
        | EditError::Overlap { index, .. } => *index,
    }
}

// ============================ Full-file: import restore ============================

/// The result of re-injecting imports the model dropped during a full-file regeneration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FullFileResult {
    pub content: String,
    /// The import lines that were present in the original but missing from the regeneration.
    pub restored: Vec<String>,
}

/// After a full-file regeneration, re-inject any import present in `original` but absent from
/// `generated` (comparison is on the trimmed line). Restored imports are inserted after the last
/// existing import in `generated`, or at the top if it has none.
pub fn restore_missing_imports(
    original: &str,
    generated: &str,
    language: Language,
) -> FullFileResult {
    if language == Language::Other {
        return FullFileResult {
            content: generated.to_string(),
            restored: Vec::new(),
        };
    }
    let gen_imports: Vec<String> = generated
        .lines()
        .filter(|l| language.is_import(l))
        .map(|l| l.trim().to_string())
        .collect();
    let mut restored = Vec::new();
    for line in original.lines().filter(|l| language.is_import(l)) {
        let trimmed = line.trim().to_string();
        if !gen_imports.contains(&trimmed) && !restored.contains(&trimmed) {
            restored.push(trimmed);
        }
    }
    if restored.is_empty() {
        return FullFileResult {
            content: generated.to_string(),
            restored,
        };
    }

    let mut lines: Vec<String> = generated.lines().map(str::to_string).collect();
    let insert_at = lines
        .iter()
        .rposition(|l| language.is_import(l))
        .map(|p| p + 1)
        .unwrap_or(0);
    for (offset, imp) in restored.iter().enumerate() {
        lines.insert(insert_at + offset, imp.clone());
    }
    let mut content = lines.join("\n");
    if generated.ends_with('\n') {
        content.push('\n');
    }
    FullFileResult { content, restored }
}

// ============================ Whole-word usage analysis ============================

/// The 1-based line numbers on which `ident` appears as a whole word (not as a substring of a
/// larger identifier).
pub fn identifier_lines(file: &str, ident: &str) -> Vec<usize> {
    let mut lines = Vec::new();
    if ident.is_empty() {
        return lines;
    }
    for (i, line) in file.lines().enumerate() {
        if line_has_whole_word(line, ident) {
            lines.push(i + 1);
        }
    }
    lines
}

fn is_ident_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

fn line_has_whole_word(line: &str, word: &str) -> bool {
    let bytes = line.as_bytes();
    let w = word.as_bytes();
    if w.is_empty() || w.len() > bytes.len() {
        return false;
    }
    let mut i = 0;
    while i + w.len() <= bytes.len() {
        if &bytes[i..i + w.len()] == w {
            let before_ok = i == 0 || !is_ident_char(line[..i].chars().next_back().unwrap());
            let after_idx = i + w.len();
            let after_ok = after_idx == bytes.len()
                || !is_ident_char(line[after_idx..].chars().next().unwrap());
            if before_ok && after_ok {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// Whether renaming/retyping a field named `field` by editing only its declaration is SAFE — i.e.
/// the identifier appears on **at most one** line (the declaration). If it appears on more lines
/// (live usages), the rename is refused and those usage lines are returned: the model must add a new
/// field via a separate edit instead of mutating the declaration and orphaning every call site.
///
/// This is the conservative *guard*; when a full xref rewrite is safe, prefer
/// [`field_rename_via_xref`], which performs the designed cross-reference rewrite instead of blocking.
pub fn field_rename_is_safe(file: &str, field: &str) -> Result<(), Vec<usize>> {
    let lines = identifier_lines(file, field);
    if lines.len() <= 1 {
        Ok(())
    } else {
        Err(lines)
    }
}

/// The outcome of an xref-based field rename: the rewritten file and the 1-based lines that changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldRenameResult {
    pub content: String,
    /// The 1-based line numbers on which an occurrence of the field was rewritten.
    pub rewritten_lines: Vec<usize>,
}

/// Why an xref field rename was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldRenameError {
    /// The old or new name is empty / not a bare identifier.
    InvalidName(String),
    /// The new name already occurs as a whole word in the file — the rename would collide with an
    /// existing identifier and silently merge two distinct fields. Refused; returns the collision
    /// lines so the caller can choose a different name.
    NameCollision { new: String, lines: Vec<usize> },
    /// The old field name does not occur in the file at all.
    NotFound(String),
}

impl std::fmt::Display for FieldRenameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FieldRenameError::InvalidName(s) => write!(f, "not a valid identifier: {s:?}"),
            FieldRenameError::NameCollision { new, lines } => {
                write!(f, "new name {new:?} already occurs on lines {lines:?}")
            }
            FieldRenameError::NotFound(s) => write!(f, "field {s:?} not found"),
        }
    }
}

impl std::error::Error for FieldRenameError {}

fn is_bare_ident(s: &str) -> bool {
    let mut c = s.chars();
    matches!(c.next(), Some(ch) if ch.is_alphabetic() || ch == '_')
        && c.all(|ch| ch.is_alphanumeric() || ch == '_')
}

/// Rename a field by rewriting **every** whole-word occurrence (declaration *and* all usages) —
/// the designed behavior (`SEMANTIC_EDITING.md` §4 "handled properly via xref rewrite instead of
/// blocking"), in contrast to the conservative [`field_rename_is_safe`] guard.
///
/// Refuses (rather than corrupt) when the new name would collide with an existing whole-word
/// identifier in the file: silently merging two fields is worse than not renaming. This is a
/// string-level rewrite (whole-word, identifier-boundary-aware); it does not distinguish a field
/// occurrence from a same-named local — the AST/LSP rungs (`ainxt-semantic`) are the higher-fidelity
/// path when available.
///
/// # Errors
/// See [`FieldRenameError`].
pub fn field_rename_via_xref(
    file: &str,
    old: &str,
    new: &str,
) -> Result<FieldRenameResult, FieldRenameError> {
    if !is_bare_ident(old) {
        return Err(FieldRenameError::InvalidName(old.to_string()));
    }
    if !is_bare_ident(new) {
        return Err(FieldRenameError::InvalidName(new.to_string()));
    }
    let old_lines = identifier_lines(file, old);
    if old_lines.is_empty() {
        return Err(FieldRenameError::NotFound(old.to_string()));
    }
    let collide = identifier_lines(file, new);
    if !collide.is_empty() {
        return Err(FieldRenameError::NameCollision {
            new: new.to_string(),
            lines: collide,
        });
    }

    let mut out_lines: Vec<String> = Vec::new();
    let mut rewritten_lines = Vec::new();
    let ends_with_newline = file.ends_with('\n');
    for (i, line) in file.lines().enumerate() {
        if line_has_whole_word(line, old) {
            out_lines.push(replace_whole_word(line, old, new));
            rewritten_lines.push(i + 1);
        } else {
            out_lines.push(line.to_string());
        }
    }
    let mut content = out_lines.join("\n");
    if ends_with_newline {
        content.push('\n');
    }
    Ok(FieldRenameResult {
        content,
        rewritten_lines,
    })
}

/// Replace every whole-word occurrence of `old` with `new` within a single line.
fn replace_whole_word(line: &str, old: &str, new: &str) -> String {
    let bytes = line.as_bytes();
    let ob = old.as_bytes();
    let mut out = String::with_capacity(line.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if i + ob.len() <= bytes.len() && &bytes[i..i + ob.len()] == ob {
            let before_ok = i == 0 || !is_ident_char(line[..i].chars().next_back().unwrap());
            let after = i + ob.len();
            let after_ok =
                after == bytes.len() || !is_ident_char(line[after..].chars().next().unwrap());
            if before_ok && after_ok {
                out.push_str(new);
                i = after;
                continue;
            }
        }
        let ch = line[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

// ============================ Declaration-preferring span finder ============================

/// Byte positions of every WHOLE-WORD occurrence of `name(` in `line` (so `compute(` does not match
/// inside `xcompute(`).
fn whole_word_call_positions(line: &str, name: &str) -> Vec<usize> {
    let needle = format!("{name}(");
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(rel) = line[from..].find(&needle) {
        let pos = from + rel;
        let boundary_ok = pos == 0 || !is_ident_char(line[..pos].chars().next_back().unwrap());
        if boundary_ok {
            out.push(pos);
        }
        from = pos + 1;
    }
    out
}

/// Whether `line` *declares* `name`: a whole-word `name(` occurrence that is immediately preceded
/// (ignoring spaces) by another identifier token — i.e. `<type-or-keyword> name(` — on a line that
/// also carries a declaration keyword. A call site like `{ compute(); }` fails the "preceded by a
/// token" test (the char before `compute` is `{`), so a caller never masquerades as the definition.
fn line_declares(line: &str, name: &str, keywords: &[&str]) -> bool {
    let has_kw = keywords.iter().any(|kw| line_has_whole_word(line, kw));
    if !has_kw {
        return false;
    }
    for pos in whole_word_call_positions(line, name) {
        let before = line[..pos].trim_end();
        if before.chars().next_back().is_some_and(is_ident_char) {
            return true; // `<token> name(` → a declaration
        }
    }
    false
}

/// Find the line (1-based) that *declares* `name`, preferring a real declaration (`<type> name(` on
/// a line with a declaration keyword) over any earlier call site. Returns the first call site if no
/// declaration is found, or `None` if `name(` appears nowhere.
pub fn find_declaration_line(file: &str, name: &str, language: Language) -> Option<usize> {
    let keywords = language.decl_keywords();
    let mut first_call: Option<usize> = None;
    for (i, line) in file.lines().enumerate() {
        if whole_word_call_positions(line, name).is_empty() {
            continue;
        }
        if first_call.is_none() {
            first_call = Some(i + 1);
        }
        if line_declares(line, name, keywords) {
            return Some(i + 1); // a real declaration wins immediately
        }
    }
    first_call // no declaration found → fall back to the first occurrence
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- anchor apply ----

    #[test]
    fn exact_replace_applies() {
        let src = "let x = 1;\nlet y = 2;\n";
        let out = apply(
            src,
            &[Edit::Replace {
                anchor: "let y = 2;".into(),
                replacement: "let y = 3;".into(),
            }],
        )
        .unwrap();
        assert_eq!(out.content, "let x = 1;\nlet y = 3;\n");
        assert_eq!(out.applied[0].kind, MatchKind::Exact);
    }

    #[test]
    fn whitespace_insensitive_match_when_exact_fails() {
        let src = "fn f() {\n    let  a =   1;\n}\n"; // odd spacing in the file
                                                      // Anchor uses normal spacing → no exact match, but ws-insensitive locates it.
        let out = apply(
            src,
            &[Edit::Replace {
                anchor: "let a = 1;".into(),
                replacement: "let a = 2;".into(),
            }],
        )
        .unwrap();
        assert_eq!(out.applied[0].kind, MatchKind::WhitespaceInsensitive);
        assert!(out.content.contains("let a = 2;"));
    }

    #[test]
    fn unmatched_anchor_is_structured_error() {
        let err = apply(
            "abc",
            &[Edit::Replace {
                anchor: "xyz".into(),
                replacement: "q".into(),
            }],
        )
        .unwrap_err();
        assert!(matches!(
            err[0],
            EditError::UnmatchedAnchor { index: 0, .. }
        ));
    }

    #[test]
    fn ambiguous_anchor_is_refused_not_guessed() {
        let src = "x;\nx;\n";
        let err = apply(
            src,
            &[Edit::Replace {
                anchor: "x;".into(),
                replacement: "y;".into(),
            }],
        )
        .unwrap_err();
        assert!(matches!(
            err[0],
            EditError::AmbiguousAnchor { count: 2, .. }
        ));
    }

    #[test]
    fn empty_anchor_is_rejected() {
        let err = apply(
            "abc",
            &[Edit::Delete {
                anchor: String::new(),
            }],
        )
        .unwrap_err();
        assert!(matches!(err[0], EditError::EmptyAnchor { index: 0 }));
    }

    #[test]
    fn insert_after_and_delete() {
        let src = "a\nb\nc\n";
        let out = apply(
            src,
            &[Edit::InsertAfter {
                anchor: "a".into(),
                content: "X".into(),
            }],
        )
        .unwrap();
        assert!(out.content.starts_with("aX\nb"));
        let out2 = apply(
            src,
            &[Edit::Delete {
                anchor: "b\n".into(),
            }],
        )
        .unwrap();
        assert_eq!(out2.content, "a\nc\n");
    }

    #[test]
    fn multiple_edits_apply_and_are_all_or_nothing() {
        let src = "one\ntwo\nthree\n";
        let out = apply(
            src,
            &[
                Edit::Replace {
                    anchor: "one".into(),
                    replacement: "1".into(),
                },
                Edit::Replace {
                    anchor: "three".into(),
                    replacement: "3".into(),
                },
            ],
        )
        .unwrap();
        assert_eq!(out.content, "1\ntwo\n3\n");

        // If ANY edit fails, nothing is applied and all errors are reported.
        let err = apply(
            src,
            &[
                Edit::Replace {
                    anchor: "one".into(),
                    replacement: "1".into(),
                },
                Edit::Replace {
                    anchor: "nope".into(),
                    replacement: "x".into(),
                },
            ],
        )
        .unwrap_err();
        assert_eq!(err.len(), 1);
        assert!(matches!(
            err[0],
            EditError::UnmatchedAnchor { index: 1, .. }
        ));
    }

    #[test]
    fn overlapping_edits_are_rejected() {
        let src = "abcdef";
        let err = apply(
            src,
            &[
                Edit::Replace {
                    anchor: "abcd".into(),
                    replacement: "X".into(),
                },
                Edit::Replace {
                    anchor: "cdef".into(),
                    replacement: "Y".into(),
                },
            ],
        )
        .unwrap_err();
        assert!(err.iter().any(|e| matches!(e, EditError::Overlap { .. })));
    }

    // ---- import restore (SDLC bug #1) ----

    #[test]
    fn full_file_regen_restores_dropped_imports() {
        let original = "use std::fmt;\nuse std::io::Read;\n\nfn main() {}\n";
        // The model regenerated the file but dropped `std::io::Read`.
        let generated = "use std::fmt;\n\nfn main() { /* changed */ }\n";
        let r = restore_missing_imports(original, generated, Language::Rust);
        assert_eq!(r.restored, vec!["use std::io::Read;".to_string()]);
        assert!(r.content.contains("use std::io::Read;"));
        // Inserted within the import block, before the function.
        assert!(r.content.find("use std::io::Read;").unwrap() < r.content.find("fn main").unwrap());
    }

    #[test]
    fn import_restore_noop_when_nothing_dropped() {
        let original = "import os\n\nx = 1\n";
        let generated = "import os\n\nx = 2\n";
        let r = restore_missing_imports(original, generated, Language::Python);
        assert!(r.restored.is_empty());
        assert_eq!(r.content, generated);
    }

    // ---- field rename guard (SDLC bug #2) ----

    #[test]
    fn field_rename_blocked_when_it_has_usages() {
        let file = "struct S { count: u32 }\nfn use_it(s: &S) -> u32 { s.count + 1 }\n";
        // `count` appears on the declaration AND a usage line → unsafe.
        let usages = field_rename_is_safe(file, "count").unwrap_err();
        assert_eq!(usages, vec![1, 2]);
    }

    #[test]
    fn field_rename_ok_when_declaration_only() {
        let file = "struct S { only_here: u32 }\nfn f() {}\n";
        assert!(field_rename_is_safe(file, "only_here").is_ok());
    }

    // ---- field rename via xref rewrite (the designed non-blocking path) ----

    #[test]
    fn xref_rename_rewrites_declaration_and_all_usages() {
        let file = "struct S { count: u32 }\nfn use_it(s: &S) -> u32 { s.count + s.count }\n";
        let r = field_rename_via_xref(file, "count", "total").unwrap();
        // Declaration + both usages rewritten; nothing named `count` survives.
        assert!(!r.content.contains("count"));
        assert_eq!(r.content.matches("total").count(), 3);
        // Lines 1 (decl) and 2 (usage) changed.
        assert_eq!(r.rewritten_lines, vec![1, 2]);
    }

    #[test]
    fn xref_rename_does_not_touch_substrings() {
        let file = "struct S { id: u32 }\nfn f(s: &S) -> u32 { s.id + s.idempotent }\n";
        let r = field_rename_via_xref(file, "id", "key").unwrap();
        // `idempotent` must be preserved verbatim; only the whole-word `id` becomes `key`.
        assert!(r.content.contains("idempotent"));
        assert!(r.content.contains("s.key"));
        assert!(!r.content.contains("s.id "));
    }

    #[test]
    fn xref_rename_refuses_collision_rather_than_merge_fields() {
        let file = "struct S { a: u32, b: u32 }\nfn f(s: &S) -> u32 { s.a + s.b }\n";
        let err = field_rename_via_xref(file, "a", "b").unwrap_err();
        assert!(matches!(err, FieldRenameError::NameCollision { .. }));
    }

    #[test]
    fn xref_rename_reports_missing_field() {
        let file = "struct S { a: u32 }\n";
        assert_eq!(
            field_rename_via_xref(file, "ghost", "x").unwrap_err(),
            FieldRenameError::NotFound("ghost".into())
        );
    }

    #[test]
    fn xref_rename_rejects_invalid_new_name() {
        let file = "struct S { a: u32 }\n";
        assert!(matches!(
            field_rename_via_xref(file, "a", "9bad").unwrap_err(),
            FieldRenameError::InvalidName(_)
        ));
    }

    #[test]
    fn whole_word_matching_does_not_fire_on_substrings() {
        // `count` must not match `accountount`/`counter`.
        let file = "let counter = 1;\nlet discount = 2;\n";
        assert!(identifier_lines(file, "count").is_empty());
    }

    // ---- declaration-preferring span (SDLC bug #3) ----

    #[test]
    fn declaration_wins_over_earlier_call_site() {
        // `helper(` is CALLED on line 2 before it is DEFINED on line 5.
        let file = "fn main() {\n    helper();\n}\n\nfn helper() {\n    // body\n}\n";
        assert_eq!(
            find_declaration_line(file, "helper", Language::Rust),
            Some(5)
        );
    }

    #[test]
    fn span_falls_back_to_first_call_if_no_declaration() {
        let file = "fn main() {\n    external_call();\n}\n";
        assert_eq!(
            find_declaration_line(file, "external_call", Language::Rust),
            Some(2)
        );
        assert_eq!(find_declaration_line(file, "missing", Language::Rust), None);
    }

    #[test]
    fn java_method_declaration_preferred() {
        let file = "class C {\n    void run() { compute(); }\n    private int compute() { return 1; }\n}\n";
        assert_eq!(
            find_declaration_line(file, "compute", Language::Java),
            Some(3)
        );
    }

    #[test]
    fn edit_serde_round_trips() {
        let e = Edit::Replace {
            anchor: "a".into(),
            replacement: "b".into(),
        };
        let json = serde_json::to_string(&e).unwrap();
        assert!(json.contains("\"op\":\"replace\""));
        assert_eq!(serde_json::from_str::<Edit>(&json).unwrap(), e);
    }
}
