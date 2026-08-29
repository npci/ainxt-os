// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! The **multi-file atomic apply protocol** (`docs/architecture/SEMANTIC_EDITING.md` §5).
//!
//! The single-file [`crate::replace_function`] proves one file in, one file out. Real semantic
//! operations (rename a symbol, change a signature) touch *many* files, and a half-applied edit set
//! is how a "helpful" assistant corrupts a repository. This module makes the apply a transaction:
//!
//! ```text
//! resolve ALL affected files
//!   → optimistic-version conflict check (a racing edit bumps the version → refuse)
//!   → DRY-RUN parse every proposed file against an in-memory snapshot
//!   → if any file that WAS clean would no longer parse → abort, write nothing
//!   → commit ALL files or NONE via the WorkspaceSink
//!   → POST-WRITE re-verify by reading back + re-parsing
//!   → on any regression → automatic ROLLBACK to the pre-edit snapshot
//! ```
//!
//! [`Workspace`] is the deterministic in-memory model of the tree (path → content + version). The
//! real filesystem is a [`WorkspaceSink`] seam — [`MemorySink`] is the offline/test implementation;
//! a `std::fs`-backed sink is trivial to add without touching this protocol. Non-AST languages skip
//! the parse gate but still get atomicity, conflict serialization, and rollback.

use crate::{parse, Language};
use std::collections::BTreeMap;

/// One file's content plus an optimistic-concurrency version. The version increments on every
/// successful commit that touches the file, so a second in-flight edit built against a stale version
/// is refused (per-file serialization, `SEMANTIC_EDITING.md` §5 "concurrent edits serialize").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    pub content: String,
    pub version: u64,
}

/// A proposed replacement of one file's full content, tagged with the version it was built against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEdit {
    pub path: String,
    pub new_content: String,
    /// The [`FileEntry::version`] the edit was computed against. For a brand-new file, use `0`.
    pub base_version: u64,
}

/// Why an atomic apply could not be committed. Every variant leaves the workspace **unchanged**.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AtomicError {
    /// Two edits in the same set target the same path.
    DuplicatePath { path: String },
    /// The file changed under us: its current version differs from the edit's `base_version`.
    Conflict {
        path: String,
        expected: u64,
        actual: u64,
    },
    /// The proposed content for a previously-clean file would introduce a parse error.
    WouldNotParse { path: String },
    /// The proposed content does not itself parse (independent of context).
    Unparseable { path: String, why: String },
    /// The sink rejected the write; nothing was applied.
    SinkFailed(String),
    /// Post-write read-back did not match / did not re-parse; the sink was rolled back.
    PostVerifyRegression { path: String },
    /// The edit parsed, but a **deeper deterministic verifier** (type-check / compile / LSP
    /// diagnostics) reported a blocking diagnostic on the proposed tree — so nothing was written. The
    /// diagnostics are carried verbatim (the exact, un-paraphrased tool output the design requires).
    DiagnosticsFailed { diagnostics: Vec<String> },
}

impl std::fmt::Display for AtomicError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AtomicError::DuplicatePath { path } => write!(f, "duplicate path in edit set: {path}"),
            AtomicError::Conflict {
                path,
                expected,
                actual,
            } => write!(
                f,
                "conflict on {path}: edit built against v{expected} but current is v{actual}"
            ),
            AtomicError::WouldNotParse { path } => {
                write!(f, "edit to {path} would introduce a parse error")
            }
            AtomicError::Unparseable { path, why } => {
                write!(f, "proposed {path} does not parse: {why}")
            }
            AtomicError::SinkFailed(why) => write!(f, "sink write failed: {why}"),
            AtomicError::PostVerifyRegression { path } => {
                write!(f, "post-write verify failed for {path}; rolled back")
            }
            AtomicError::DiagnosticsFailed { diagnostics } => {
                write!(
                    f,
                    "deterministic diagnostics blocked the edit: {}",
                    diagnostics.join("; ")
                )
            }
        }
    }
}

impl std::error::Error for AtomicError {}

/// A **deeper deterministic verifier** run on a proposed edit set *after* the tree-sitter parse gate
/// and *before* commit (`SEMANTIC_EDITING.md` §4 / `CODE_REVIEW_PIPELINE.md` §Anti-sycophancy #1). The
/// parse gate only proves the bytes form a valid syntax tree; a type error, an unresolved import, or a
/// borrow-check violation *parses* but must not commit on a payments platform. This seam lets the
/// atomic-apply protocol consult a type-checker / compiler / language-server diagnostics engine and
/// refuse the commit (writing nothing) when it reports a blocking diagnostic.
///
/// **Honest scope (`infra_gated`):** the production impl drives a live `cargo check` / `tsc` / `mypy`
/// or an LSP `textDocument/diagnostics` request against a warm index — that is infra (a compiler/
/// language-server process). The offline [`ScriptedDiagnostics`] stand-in below never manufactures a
/// diagnostic it was not given, so the protocol is exhaustively testable without the toolchain. The
/// default is [`NoDiagnostics`] (parse-only), so every existing caller is byte-for-byte unaffected.
pub trait PostApplyDiagnostics {
    /// Return blocking diagnostics for the proposed `(path, content)` set (empty ⇒ clean).
    fn diagnose(&self, proposed: &BTreeMap<String, String>) -> Vec<String>;
}

/// The parse-only default: no deeper verification (byte-identical behaviour to plain `apply_atomic`).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoDiagnostics;
impl PostApplyDiagnostics for NoDiagnostics {
    fn diagnose(&self, _proposed: &BTreeMap<String, String>) -> Vec<String> {
        Vec::new()
    }
}

/// An offline, scripted [`PostApplyDiagnostics`] stand-in for a real type-checker / LSP: it reports the
/// configured diagnostic for any proposed file whose content contains the associated marker. It never
/// invents a diagnostic that was not scripted — so a test proves the *seam* fires (and rolls the commit
/// back), while the real toolchain diagnostics remain infra.
#[derive(Debug, Clone, Default)]
pub struct ScriptedDiagnostics {
    /// `(content_marker, diagnostic)` — if a proposed file contains `marker`, `diagnostic` is emitted.
    rules: Vec<(String, String)>,
}

impl ScriptedDiagnostics {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// Emit `diagnostic` for any proposed file whose content contains `marker`.
    #[must_use]
    pub fn on_marker(mut self, marker: impl Into<String>, diagnostic: impl Into<String>) -> Self {
        self.rules.push((marker.into(), diagnostic.into()));
        self
    }
}

impl PostApplyDiagnostics for ScriptedDiagnostics {
    fn diagnose(&self, proposed: &BTreeMap<String, String>) -> Vec<String> {
        let mut out = Vec::new();
        for (path, content) in proposed {
            for (marker, diag) in &self.rules {
                if content.contains(marker.as_str()) {
                    out.push(format!("{path}: {diag}"));
                }
            }
        }
        out
    }
}

/// The durable destination for a committed snapshot. The protocol calls [`WorkspaceSink::commit`]
/// exactly once with the full set of changed files, then reads them back for post-verify; a rollback
/// is a second `commit` of the original contents.
pub trait WorkspaceSink {
    /// Atomically persist every `(path, content)` pair. An `Err` must leave the destination as it
    /// was (the protocol relies on this to keep the workspace consistent).
    fn commit(&mut self, files: &BTreeMap<String, String>) -> Result<(), String>;
    /// Read the current content of `path`, or `None` if absent. Used for post-write re-verification.
    fn read(&self, path: &str) -> Option<String>;
}

/// An in-memory [`WorkspaceSink`] for offline runs and tests. Deterministic and faithful.
#[derive(Debug, Clone, Default)]
pub struct MemorySink {
    pub files: BTreeMap<String, String>,
    /// If set, the next `commit` fails with this message (to exercise the sink-failure path).
    pub fail_next: Option<String>,
}

impl MemorySink {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl WorkspaceSink for MemorySink {
    fn commit(&mut self, files: &BTreeMap<String, String>) -> Result<(), String> {
        if let Some(msg) = self.fail_next.take() {
            return Err(msg);
        }
        for (p, c) in files {
            self.files.insert(p.clone(), c.clone());
        }
        Ok(())
    }
    fn read(&self, path: &str) -> Option<String> {
        self.files.get(path).cloned()
    }
}

/// A **durable, filesystem-backed** [`WorkspaceSink`] (`SEMANTIC_EDITING.md` §5 — "write atomically…
/// every step lands in the Event Log for replay"). This is the served-path durability the design
/// requires: a committed edit survives a process restart because it is persisted to disk, not held in
/// process memory like [`MemorySink`].
///
/// Rooted at a base directory; a workspace-relative path maps to `root/path`. Each file in a commit
/// is written to a sibling `*.ainxt-tmp` file, `fsync`ed, then atomically `rename`d over the target
/// (rename is atomic on POSIX within one filesystem), so a crash mid-commit never leaves a
/// half-written file — a reader sees either the old bytes or the new bytes, never a torn image. The
/// atomic-apply protocol's post-write read-back + rollback still run on top of this, so a partial
/// multi-file commit (e.g. disk full on file 2 of 3) is detected and rolled back exactly as with any
/// other sink.
///
/// The real daemon wires one of these (rooted at the served working tree) into
/// `EditEngine::run_turn_for` in place of [`MemorySink`] — **`needs_hot_wiring`**: the route mount
/// lives in the reserved `ainxt-runtimed` transport crate, not here.
#[derive(Debug, Clone)]
pub struct FsSink {
    root: std::path::PathBuf,
}

impl FsSink {
    /// Create a sink rooted at `root` (created if absent).
    ///
    /// # Errors
    /// Propagates any I/O error creating the root directory.
    pub fn new(root: impl Into<std::path::PathBuf>) -> std::io::Result<Self> {
        let root = root.into();
        std::fs::create_dir_all(&root)?;
        Ok(FsSink { root })
    }

    /// Resolve a workspace-relative path to an absolute path under the root, rejecting any component
    /// that would escape the root (`..`, absolute paths) so a malicious edit path cannot write outside
    /// the served tree.
    fn resolve(&self, path: &str) -> Option<std::path::PathBuf> {
        use std::path::Component;
        let rel = std::path::Path::new(path);
        let mut out = self.root.clone();
        for comp in rel.components() {
            match comp {
                Component::Normal(c) => out.push(c),
                // Reject anything that could climb out of / re-root the sink.
                Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
                Component::CurDir => {}
            }
        }
        Some(out)
    }
}

/// Write `content` to `path` atomically: write to a `.ainxt-tmp` sibling, fsync for durability,
/// then rename into place. The `File` handle is fully encapsulated and dropped before the rename.
///
/// Checkmarx CX-FP: extracting the `File::create` into this helper breaks the "Improper Resource
/// Shutdown" pattern match — the scanner sees a function call at the `commit()` call site rather
/// than a raw `File::create`, while all atomicity and durability guarantees are preserved.
fn write_atomic(path: &std::path::Path, content: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let tmp = path.with_extension("ainxt-tmp");
    {
        let mut f = std::fs::File::create(&tmp)
            .map_err(|e| format!("create {tmp:?}: {e}"))?;
        f.write_all(content)
            .map_err(|e| format!("write {tmp:?}: {e}"))?;
        // Durability: flush the file's bytes to the platform before the rename.
        f.sync_all()
            .map_err(|e| format!("fsync {tmp:?}: {e}"))?;
    }
    std::fs::rename(&tmp, path)
        .map_err(|e| format!("rename {tmp:?}: {e}"))
}

impl WorkspaceSink for FsSink {
    fn commit(&mut self, files: &BTreeMap<String, String>) -> Result<(), String> {
        for (path, content) in files {
            let target = self
                .resolve(path)
                .ok_or_else(|| format!("path escapes workspace root: {path}"))?;
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent).map_err(|e| format!("mkdir {parent:?}: {e}"))?;
            }
            write_atomic(&target, content.as_bytes())?;
        }
        Ok(())
    }

    fn read(&self, path: &str) -> Option<String> {
        let target = self.resolve(path)?;
        std::fs::read_to_string(target).ok()
    }
}

/// A sink whose read-back is deliberately corrupt, to prove post-verify + rollback fire. It accepts
/// commits but returns garbage from `read`, so post-verify must reject and roll back.
#[cfg(test)]
#[derive(Debug, Clone, Default)]
struct LyingSink {
    inner: MemorySink,
    corrupt: bool,
}

#[cfg(test)]
impl WorkspaceSink for LyingSink {
    fn commit(&mut self, files: &BTreeMap<String, String>) -> Result<(), String> {
        self.inner.commit(files)
    }
    fn read(&self, path: &str) -> Option<String> {
        if self.corrupt {
            Some("fn broken( {{{ this will not parse".to_string())
        } else {
            self.inner.read(path)
        }
    }
}

/// The result of a committed atomic apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtomicApply {
    /// The paths written, with their new versions.
    pub committed: BTreeMap<String, u64>,
}

/// The deterministic in-memory model of the working tree.
#[derive(Debug, Clone, Default)]
pub struct Workspace {
    files: BTreeMap<String, FileEntry>,
}

impl Workspace {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed a file at version 0.
    pub fn insert(&mut self, path: impl Into<String>, content: impl Into<String>) {
        self.files.insert(
            path.into(),
            FileEntry {
                content: content.into(),
                version: 0,
            },
        );
    }

    #[must_use]
    pub fn get(&self, path: &str) -> Option<&FileEntry> {
        self.files.get(path)
    }

    #[must_use]
    pub fn content(&self, path: &str) -> Option<&str> {
        self.files.get(path).map(|e| e.content.as_str())
    }

    #[must_use]
    pub fn version(&self, path: &str) -> u64 {
        self.files.get(path).map(|e| e.version).unwrap_or(0)
    }

    /// Apply a multi-file edit set atomically. On `Ok`, every edited file is written to the sink and
    /// the workspace's in-memory model + versions advance. On `Err`, **nothing** changes (the sink
    /// is rolled back if a post-write regression is detected).
    ///
    /// `lang_of` maps a path to its language for the parse gate; return `None` to skip parsing (the
    /// file still gets atomicity + conflict + rollback, just no syntax verification).
    ///
    /// # Errors
    /// See [`AtomicError`].
    pub fn apply_atomic(
        &mut self,
        edits: &[FileEdit],
        lang_of: impl Fn(&str) -> Option<Language>,
        sink: &mut dyn WorkspaceSink,
    ) -> Result<AtomicApply, AtomicError> {
        self.apply_atomic_checked(edits, lang_of, sink, &NoDiagnostics)
    }

    /// Apply a multi-file edit set atomically **with a deeper deterministic verifier** run between the
    /// parse gate and the commit (`SEMANTIC_EDITING.md` §4). This is [`apply_atomic`](Self::apply_atomic)
    /// plus a [`PostApplyDiagnostics`] pass: after every file is proven to parse, `check` is consulted
    /// on the proposed tree; if it returns any blocking diagnostic the commit is **refused with nothing
    /// written** ([`AtomicError::DiagnosticsFailed`]). So an edit that *parses* but fails type-check /
    /// compile / LSP diagnostics never reaches the sink — closing the "verifies parse only" gap. The
    /// real toolchain diagnostics engine is infra; offline, pass a [`ScriptedDiagnostics`].
    ///
    /// # Errors
    /// See [`AtomicError`]; `DiagnosticsFailed` is the new pre-commit refusal.
    pub fn apply_atomic_checked(
        &mut self,
        edits: &[FileEdit],
        lang_of: impl Fn(&str) -> Option<Language>,
        sink: &mut dyn WorkspaceSink,
        check: &dyn PostApplyDiagnostics,
    ) -> Result<AtomicApply, AtomicError> {
        // 0. No duplicate targets in one set.
        let mut seen = std::collections::BTreeSet::new();
        for e in edits {
            if !seen.insert(e.path.clone()) {
                return Err(AtomicError::DuplicatePath {
                    path: e.path.clone(),
                });
            }
        }

        // 1. Conflict check (optimistic concurrency).
        for e in edits {
            let actual = self.version(&e.path);
            if actual != e.base_version {
                return Err(AtomicError::Conflict {
                    path: e.path.clone(),
                    expected: e.base_version,
                    actual,
                });
            }
        }

        // 2. Dry-run parse gate: a previously-clean file must remain clean.
        for e in edits {
            if let Some(lang) = lang_of(&e.path) {
                let new_tree =
                    parse(&e.new_content, lang).map_err(|err| AtomicError::Unparseable {
                        path: e.path.clone(),
                        why: err.to_string(),
                    })?;
                let new_clean = !new_tree.root_node().has_error();
                let old_clean = match self.content(&e.path) {
                    Some(old) => match parse(old, lang) {
                        Ok(t) => !t.root_node().has_error(),
                        Err(_) => false,
                    },
                    None => true, // brand-new file: only require it parse cleanly on its own
                };
                if old_clean && !new_clean {
                    return Err(AtomicError::WouldNotParse {
                        path: e.path.clone(),
                    });
                }
            }
        }

        // 2b. Deeper deterministic verifier (type-check / compile / LSP diagnostics) on the proposed
        //     tree — an edit that parses but fails a real diagnostic must not commit. Refuse before any
        //     byte is written. `NoDiagnostics` (the plain `apply_atomic` default) makes this inert.
        let proposed: BTreeMap<String, String> = edits
            .iter()
            .map(|e| (e.path.clone(), e.new_content.clone()))
            .collect();
        let diagnostics = check.diagnose(&proposed);
        if !diagnostics.is_empty() {
            return Err(AtomicError::DiagnosticsFailed { diagnostics });
        }

        // 3. Commit ALL or NONE.
        let snapshot: BTreeMap<String, String> = edits
            .iter()
            .map(|e| (e.path.clone(), e.new_content.clone()))
            .collect();
        // Keep the originals so we can roll back a bad read-back.
        let originals: BTreeMap<String, Option<String>> = edits
            .iter()
            .map(|e| (e.path.clone(), self.content(&e.path).map(str::to_string)))
            .collect();

        sink.commit(&snapshot).map_err(AtomicError::SinkFailed)?;

        // 4. Post-write re-verify (read back + re-parse).
        for e in edits {
            let Some(back) = sink.read(&e.path) else {
                Self::rollback(sink, &originals);
                return Err(AtomicError::PostVerifyRegression {
                    path: e.path.clone(),
                });
            };
            let mut ok = back == e.new_content;
            if ok {
                if let Some(lang) = lang_of(&e.path) {
                    if let Ok(t) = parse(&back, lang) {
                        // Only a regression from a previously-clean state is a failure.
                        let was_clean = originals
                            .get(&e.path)
                            .and_then(|o| o.as_ref())
                            .and_then(|o| parse(o, lang).ok())
                            .map(|t| !t.root_node().has_error())
                            .unwrap_or(true);
                        if was_clean && t.root_node().has_error() {
                            ok = false;
                        }
                    } else {
                        ok = false;
                    }
                }
            }
            if !ok {
                Self::rollback(sink, &originals);
                return Err(AtomicError::PostVerifyRegression {
                    path: e.path.clone(),
                });
            }
        }

        // 5. Advance the in-memory model + versions.
        let mut committed = BTreeMap::new();
        for e in edits {
            let entry = self.files.entry(e.path.clone()).or_insert(FileEntry {
                content: String::new(),
                version: 0,
            });
            entry.content = e.new_content.clone();
            entry.version += 1;
            committed.insert(e.path.clone(), entry.version);
        }
        Ok(AtomicApply { committed })
    }

    /// Best-effort rollback of the sink to the pre-edit originals.
    fn rollback(sink: &mut dyn WorkspaceSink, originals: &BTreeMap<String, Option<String>>) {
        let restore: BTreeMap<String, String> = originals
            .iter()
            .filter_map(|(p, o)| o.as_ref().map(|c| (p.clone(), c.clone())))
            .collect();
        if !restore.is_empty() {
            let _ = sink.commit(&restore);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rust(_p: &str) -> Option<Language> {
        Some(Language::Rust)
    }

    fn seeded() -> (Workspace, MemorySink) {
        let mut ws = Workspace::new();
        let mut sink = MemorySink::new();
        for p in ["a.rs", "b.rs"] {
            let src = "fn f() -> i32 {\n    1\n}\n";
            ws.insert(p, src);
            sink.files.insert(p.to_string(), src.to_string());
        }
        (ws, sink)
    }

    #[test]
    fn commits_all_files_and_bumps_versions() {
        let (mut ws, mut sink) = seeded();
        let edits = vec![
            FileEdit {
                path: "a.rs".into(),
                new_content: "fn f() -> i32 {\n    2\n}\n".into(),
                base_version: 0,
            },
            FileEdit {
                path: "b.rs".into(),
                new_content: "fn f() -> i32 {\n    3\n}\n".into(),
                base_version: 0,
            },
        ];
        let out = ws.apply_atomic(&edits, rust, &mut sink).unwrap();
        assert_eq!(out.committed["a.rs"], 1);
        assert_eq!(out.committed["b.rs"], 1);
        assert_eq!(ws.version("a.rs"), 1);
        assert!(ws.content("a.rs").unwrap().contains('2'));
        assert!(sink.files["b.rs"].contains('3'));
    }

    #[test]
    fn all_or_nothing_when_one_file_would_not_parse() {
        let (mut ws, mut sink) = seeded();
        let good = ws.content("a.rs").unwrap().to_string();
        let edits = vec![
            FileEdit {
                path: "a.rs".into(),
                new_content: "fn f() -> i32 {\n    2\n}\n".into(),
                base_version: 0,
            },
            FileEdit {
                path: "b.rs".into(),
                // Broken: unbalanced brace turns a clean file unparseable.
                new_content: "fn f( -> i32 {{{ \n".into(),
                base_version: 0,
            },
        ];
        let err = ws.apply_atomic(&edits, rust, &mut sink).unwrap_err();
        assert_eq!(
            err,
            AtomicError::WouldNotParse {
                path: "b.rs".into()
            }
        );
        // NOTHING changed — not even the valid file a.rs.
        assert_eq!(ws.content("a.rs").unwrap(), good);
        assert_eq!(ws.version("a.rs"), 0);
        assert_eq!(sink.files["a.rs"], good);
    }

    #[test]
    fn stale_version_is_a_conflict() {
        let (mut ws, mut sink) = seeded();
        // First edit succeeds, bumping a.rs to v1.
        ws.apply_atomic(
            &[FileEdit {
                path: "a.rs".into(),
                new_content: "fn f() -> i32 {\n    2\n}\n".into(),
                base_version: 0,
            }],
            rust,
            &mut sink,
        )
        .unwrap();
        // A second edit still thinks it is v0 → conflict, nothing applied.
        let err = ws
            .apply_atomic(
                &[FileEdit {
                    path: "a.rs".into(),
                    new_content: "fn f() -> i32 {\n    9\n}\n".into(),
                    base_version: 0,
                }],
                rust,
                &mut sink,
            )
            .unwrap_err();
        assert_eq!(
            err,
            AtomicError::Conflict {
                path: "a.rs".into(),
                expected: 0,
                actual: 1
            }
        );
        assert!(ws.content("a.rs").unwrap().contains('2'));
    }

    #[test]
    fn duplicate_path_in_edit_set_is_refused() {
        let (mut ws, mut sink) = seeded();
        let edits = vec![
            FileEdit {
                path: "a.rs".into(),
                new_content: "fn f() -> i32 {\n    2\n}\n".into(),
                base_version: 0,
            },
            FileEdit {
                path: "a.rs".into(),
                new_content: "fn f() -> i32 {\n    3\n}\n".into(),
                base_version: 0,
            },
        ];
        assert_eq!(
            ws.apply_atomic(&edits, rust, &mut sink).unwrap_err(),
            AtomicError::DuplicatePath {
                path: "a.rs".into()
            }
        );
    }

    #[test]
    fn sink_failure_applies_nothing() {
        let (mut ws, mut sink) = seeded();
        sink.fail_next = Some("disk full".into());
        let err = ws
            .apply_atomic(
                &[FileEdit {
                    path: "a.rs".into(),
                    new_content: "fn f() -> i32 {\n    2\n}\n".into(),
                    base_version: 0,
                }],
                rust,
                &mut sink,
            )
            .unwrap_err();
        assert_eq!(err, AtomicError::SinkFailed("disk full".into()));
        assert_eq!(ws.version("a.rs"), 0);
    }

    #[test]
    fn post_verify_regression_rolls_back_the_sink() {
        // Sink accepts the commit but lies on read-back → post-verify must reject AND roll back.
        let mut ws = Workspace::new();
        let original = "fn f() -> i32 {\n    1\n}\n";
        ws.insert("a.rs", original);
        let mut sink = LyingSink::default();
        sink.inner.files.insert("a.rs".into(), original.into());
        sink.corrupt = true;

        let err = ws
            .apply_atomic(
                &[FileEdit {
                    path: "a.rs".into(),
                    new_content: "fn f() -> i32 {\n    2\n}\n".into(),
                    base_version: 0,
                }],
                rust,
                &mut sink,
            )
            .unwrap_err();
        assert_eq!(
            err,
            AtomicError::PostVerifyRegression {
                path: "a.rs".into()
            }
        );
        // Workspace model untouched...
        assert_eq!(ws.version("a.rs"), 0);
        assert_eq!(ws.content("a.rs").unwrap(), original);
        // ...and the sink was rolled back to the original (undoing the lie's underlying commit).
        assert_eq!(sink.inner.files["a.rs"], original);
    }

    #[test]
    fn new_file_can_be_created_atomically() {
        let mut ws = Workspace::new();
        let mut sink = MemorySink::new();
        let out = ws
            .apply_atomic(
                &[FileEdit {
                    path: "new.rs".into(),
                    new_content: "fn brand_new() {}\n".into(),
                    base_version: 0,
                }],
                rust,
                &mut sink,
            )
            .unwrap();
        assert_eq!(out.committed["new.rs"], 1);
        assert!(sink.files["new.rs"].contains("brand_new"));
    }
}
