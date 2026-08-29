// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! A code-derived **symbol / call / import graph** over a set of source files, and the deterministic
//! **blast-radius** resolver the Code-Review Pipeline consumes to size the risk of an edit.
//!
//! The design (`docs/architecture/SEMANTIC_EDITING.md` §3, `CODE_REVIEW_PIPELINE.md` §3) says every
//! edit must know *everything it touches*: the fan-out in the call graph from every changed symbol.
//! This module builds that graph from tree-sitter definitions (via [`crate::list_definitions`]) plus
//! whole-word reference scanning, and answers [`SymbolGraph::blast_radius`] — the transitive set of
//! caller symbols and files that reach the touched symbols, plus the direct 1-hop fan-out count.
//!
//! It is intentionally a *conservative* index, not a type-resolving compiler front-end:
//! - A reference is a whole-word occurrence of a definition's name that is **not** the definition's
//!   own header line. Overload/same-name collisions across files are merged by name (documented).
//! - The enclosing caller of a reference is the definition in that file whose byte span contains the
//!   reference; a top-of-file reference is attributed to a synthetic `<file>::<module>` node.
//!
//! This over-approximates rather than under-approximates: for a *risk* signal, missing a real caller
//! (false-negative) is the dangerous error, so name-merging deliberately errs toward a larger blast
//! radius. LSP-grade precise xrefs are the higher rung (see [`crate::ladder`]); this is the rung that
//! works with no language server present.

use crate::{list_definitions, Language};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// One source file fed into the graph builder.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SourceFile {
    pub path: String,
    pub lang: Language,
    pub source: String,
}

impl SourceFile {
    pub fn new(path: impl Into<String>, lang: Language, source: impl Into<String>) -> Self {
        SourceFile {
            path: path.into(),
            lang,
            source: source.into(),
        }
    }
}

/// A fully-qualified symbol: `path::name`. Same-named definitions in different files are distinct
/// nodes; same-named definitions in the *same* file (e.g. a method and a free fn) merge — a known,
/// conservative approximation that only ever widens the blast radius.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SymbolId {
    pub file: String,
    pub name: String,
}

impl SymbolId {
    pub fn new(file: impl Into<String>, name: impl Into<String>) -> Self {
        SymbolId {
            file: file.into(),
            name: name.into(),
        }
    }
}

impl std::fmt::Display for SymbolId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}::{}", self.file, self.name)
    }
}

#[derive(Debug, Clone)]
struct DefRecord {
    id: SymbolId,
    start_byte: usize,
    end_byte: usize,
}

/// The result of resolving what an edit touches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlastRadius {
    /// The symbols the caller declared as directly changed (echoed back, resolved to graph nodes).
    pub touched: BTreeSet<SymbolId>,
    /// Every symbol that transitively reaches a touched symbol through the call graph (reverse
    /// reachability). Excludes the touched set itself.
    pub callers: BTreeSet<SymbolId>,
    /// Every file that contains a touched symbol or a caller — the file-level blast radius.
    pub files: BTreeSet<String>,
    /// The number of *direct* (1-hop) callers of any touched symbol. This is the fan-out the risk
    /// classifier tiers on.
    pub fan_out: usize,
}

impl BlastRadius {
    /// Total symbols implicated (touched + transitive callers).
    #[must_use]
    pub fn symbol_count(&self) -> usize {
        self.touched.len() + self.callers.len()
    }
}

/// The immutable, deterministic symbol/call/import graph.
#[derive(Debug, Clone, Default)]
pub struct SymbolGraph {
    /// Every definition, keyed by fully-qualified id.
    defs: BTreeMap<SymbolId, DefRecord>,
    /// `name -> {ids}` — lets a bare reference name resolve to candidate definitions.
    by_name: BTreeMap<String, BTreeSet<SymbolId>>,
    /// Call edges `caller -> callee` (both directions materialized for O(1) reverse lookup).
    callees: BTreeMap<SymbolId, BTreeSet<SymbolId>>,
    callers: BTreeMap<SymbolId, BTreeSet<SymbolId>>,
    /// `file -> imported module strings` (raw import targets, best-effort).
    imports: BTreeMap<String, BTreeSet<String>>,
}

/// Whether `c` is part of an identifier token.
fn is_ident_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Byte offsets of every whole-word occurrence of `name` in `src`.
fn whole_word_offsets(src: &str, name: &str) -> Vec<usize> {
    if name.is_empty() {
        return Vec::new();
    }
    let bytes = src.as_bytes();
    let nb = name.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + nb.len() <= bytes.len() {
        if &bytes[i..i + nb.len()] == nb {
            let before_ok = i == 0 || !is_ident_char(src[..i].chars().next_back().unwrap());
            let after = i + nb.len();
            let after_ok =
                after == bytes.len() || !is_ident_char(src[after..].chars().next().unwrap());
            if before_ok && after_ok {
                out.push(i);
                i = after;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// Best-effort import targets from a line, per language.
fn import_target(lang: Language, line: &str) -> Option<String> {
    let t = line.trim();
    match lang {
        Language::Rust => t
            .strip_prefix("use ")
            .map(|r| r.trim_end_matches(';').trim().to_string()),
        Language::Python => {
            if let Some(r) = t.strip_prefix("from ") {
                r.split_whitespace().next().map(str::to_string)
            } else {
                t.strip_prefix("import ").map(|r| r.trim().to_string())
            }
        }
        // Go: `import "path"` or a bare `"path"` line inside an `import ( … )` block.
        Language::Go => {
            let body = t.strip_prefix("import ").unwrap_or(t);
            let body = body.trim();
            if body.starts_with('"') {
                Some(body.trim_matches('"').to_string())
            } else {
                None
            }
        }
        // JS/TS: `import … from '…'` / `require('…')`. The module specifier is the quoted string.
        Language::JavaScript | Language::TypeScript => {
            if t.starts_with("import ") || t.contains("require(") || t.starts_with("export ") {
                let bytes = t.as_bytes();
                let q = bytes.iter().position(|&b| b == b'\'' || b == b'"')?;
                let quote = bytes[q];
                let rest = &t[q + 1..];
                rest.find(quote as char).map(|e| rest[..e].to_string())
            } else {
                None
            }
        }
        // Java: `import a.b.C;` (strip an optional `static`).
        Language::Java => t.strip_prefix("import ").map(|r| {
            r.trim()
                .strip_prefix("static ")
                .unwrap_or(r)
                .trim_end_matches(';')
                .trim()
                .to_string()
        }),
    }
}

impl SymbolGraph {
    /// Build the graph from a set of files. Files whose language fails to parse contribute no
    /// definitions (their references are still scanned against symbols defined elsewhere).
    #[must_use]
    pub fn build(files: &[SourceFile]) -> Self {
        let mut g = SymbolGraph::default();

        // Pass 1: definitions + imports.
        for f in files {
            let mut file_imports = BTreeSet::new();
            for line in f.source.lines() {
                if let Some(t) = import_target(f.lang, line) {
                    if !t.is_empty() {
                        file_imports.insert(t);
                    }
                }
            }
            g.imports.insert(f.path.clone(), file_imports);

            if let Ok(defs) = list_definitions(&f.source, f.lang) {
                for d in defs {
                    let id = SymbolId::new(f.path.clone(), d.name.clone());
                    g.by_name.entry(d.name).or_default().insert(id.clone());
                    // Same-name-in-same-file merge: keep the widest span (outermost def).
                    let entry = g.defs.entry(id.clone()).or_insert(DefRecord {
                        id: id.clone(),
                        start_byte: d.span.start_byte,
                        end_byte: d.span.end_byte,
                    });
                    if d.span.end_byte - d.span.start_byte > entry.end_byte - entry.start_byte {
                        entry.start_byte = d.span.start_byte;
                        entry.end_byte = d.span.end_byte;
                    }
                }
            }
        }

        // Pass 2: references → call edges. For each file, for each known symbol name, find whole-word
        // occurrences that are NOT the definition's own header, and attribute them to the enclosing
        // definition (or the file module).
        let names: Vec<String> = g.by_name.keys().cloned().collect();
        for f in files {
            // The definitions in THIS file, for enclosing-scope resolution and self-exclusion.
            let local: Vec<DefRecord> = g
                .defs
                .values()
                .filter(|d| d.id.file == f.path)
                .cloned()
                .collect();
            for name in &names {
                for off in whole_word_offsets(&f.source, name) {
                    // Skip the occurrence that IS a local definition's name token (the header).
                    let is_own_header = local.iter().any(|d| {
                        d.id.name == *name
                            && off >= d.start_byte
                            && off < d.start_byte + header_window(&f.source, d.start_byte)
                    });
                    if is_own_header {
                        continue;
                    }
                    // Resolve the callee(s): definitions anywhere with this name. Own the set so no
                    // borrow of `g.by_name` is held while we mutate the edge maps below.
                    let callee_ids: Vec<SymbolId> = match g.by_name.get(name) {
                        Some(s) => s.iter().cloned().collect(),
                        None => continue,
                    };
                    // Resolve the caller: the innermost local def whose span contains `off`.
                    let caller = enclosing(&local, off)
                        .map(|d| d.id.clone())
                        .unwrap_or_else(|| SymbolId::new(f.path.clone(), MODULE_NODE.to_string()));
                    for callee in &callee_ids {
                        if *callee == caller {
                            continue; // self-recursion is not a blast-radius edge
                        }
                        g.callees
                            .entry(caller.clone())
                            .or_default()
                            .insert(callee.clone());
                        g.callers
                            .entry(callee.clone())
                            .or_default()
                            .insert(caller.clone());
                    }
                }
            }
        }
        g
    }

    /// Every definition id in the graph, sorted.
    #[must_use]
    pub fn symbols(&self) -> Vec<SymbolId> {
        self.defs.keys().cloned().collect()
    }

    /// Direct callers of `sym` (1-hop reverse edges).
    #[must_use]
    pub fn direct_callers(&self, sym: &SymbolId) -> BTreeSet<SymbolId> {
        self.callers.get(sym).cloned().unwrap_or_default()
    }

    /// Direct callees of `sym`.
    #[must_use]
    pub fn direct_callees(&self, sym: &SymbolId) -> BTreeSet<SymbolId> {
        self.callees.get(sym).cloned().unwrap_or_default()
    }

    /// The raw import targets declared by `file`.
    #[must_use]
    pub fn imports_of(&self, file: &str) -> BTreeSet<String> {
        self.imports.get(file).cloned().unwrap_or_default()
    }

    /// Resolve a set of touched symbol *names* (or `path::name`, matched loosely by name) to graph
    /// nodes and compute the transitive reverse-reachable blast radius.
    ///
    /// `touched` entries match by bare `name` (all files) — the conservative choice for risk.
    #[must_use]
    pub fn blast_radius(&self, touched_names: &[&str]) -> BlastRadius {
        let mut touched: BTreeSet<SymbolId> = BTreeSet::new();
        for n in touched_names {
            if let Some(ids) = self.by_name.get(*n) {
                touched.extend(ids.iter().cloned());
            }
        }

        // Direct fan-out (1-hop) before transitive closure.
        let mut fan: BTreeSet<SymbolId> = BTreeSet::new();
        for t in &touched {
            for c in self.direct_callers(t) {
                if !touched.contains(&c) {
                    fan.insert(c);
                }
            }
        }
        let fan_out = fan.len();

        // Transitive reverse reachability (who reaches a touched symbol, at any depth).
        let mut callers: BTreeSet<SymbolId> = BTreeSet::new();
        let mut queue: VecDeque<SymbolId> = touched.iter().cloned().collect();
        let mut seen: BTreeSet<SymbolId> = touched.clone();
        while let Some(cur) = queue.pop_front() {
            for c in self.direct_callers(&cur) {
                if seen.insert(c.clone()) {
                    callers.insert(c.clone());
                    queue.push_back(c);
                }
            }
        }

        let mut files: BTreeSet<String> = BTreeSet::new();
        for s in touched.iter().chain(callers.iter()) {
            files.insert(s.file.clone());
        }

        BlastRadius {
            touched,
            callers,
            files,
            fan_out,
        }
    }
}

/// Synthetic name for a file-scope (top-level) caller.
pub const MODULE_NODE: &str = "<module>";

/// A rough length for a definition's "header" region used only for self-exclusion of the name token
/// — the first line of the definition is enough to cover `fn name(` / `def name(` / `struct name`.
fn header_window(src: &str, start: usize) -> usize {
    src[start..].find('\n').map_or(src.len() - start, |n| n + 1)
}

/// The innermost local definition whose byte span contains `off`.
fn enclosing(local: &[DefRecord], off: usize) -> Option<&DefRecord> {
    local
        .iter()
        .filter(|d| off >= d.start_byte && off < d.end_byte)
        .min_by_key(|d| d.end_byte - d.start_byte)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rs(path: &str, src: &str) -> SourceFile {
        SourceFile::new(path, Language::Rust, src)
    }

    #[test]
    fn builds_defs_and_call_edges_across_files() {
        // lib.rs defines `helper`; main.rs calls it inside `run`.
        let lib = rs("lib.rs", "pub fn helper() -> i32 {\n    7\n}\n");
        let main = rs(
            "main.rs",
            "use crate::helper;\nfn run() -> i32 {\n    helper() + 1\n}\n",
        );
        let g = SymbolGraph::build(&[lib, main]);

        let helper = SymbolId::new("lib.rs", "helper");
        let run = SymbolId::new("main.rs", "run");
        // `run` calls `helper`.
        assert!(g.direct_callees(&run).contains(&helper));
        assert!(g.direct_callers(&helper).contains(&run));
        // Import target captured.
        assert!(g.imports_of("main.rs").contains("crate::helper"));
    }

    #[test]
    fn definition_header_is_not_counted_as_a_self_call() {
        // `helper` appears once (its own def). It must have NO callers — the header is excluded.
        let lib = rs("lib.rs", "fn helper() -> i32 {\n    1\n}\n");
        let g = SymbolGraph::build(&[lib]);
        let helper = SymbolId::new("lib.rs", "helper");
        assert!(
            g.direct_callers(&helper).is_empty(),
            "the definition header must not be scanned as a call to itself"
        );
    }

    #[test]
    fn blast_radius_is_transitive_and_counts_direct_fan_out() {
        // low <- mid <- high  (high calls mid, mid calls low).
        let src = "\
fn low() -> i32 { 1 }
fn mid() -> i32 { low() + 1 }
fn high() -> i32 { mid() + 1 }
fn unrelated() -> i32 { 99 }
";
        let g = SymbolGraph::build(&[rs("a.rs", src)]);
        let br = g.blast_radius(&["low"]);

        let mid = SymbolId::new("a.rs", "mid");
        let high = SymbolId::new("a.rs", "high");
        let unrelated = SymbolId::new("a.rs", "unrelated");

        // Direct fan-out of `low` is just `mid`.
        assert_eq!(br.fan_out, 1);
        // Transitive callers include both mid and high, never unrelated.
        assert!(br.callers.contains(&mid));
        assert!(br.callers.contains(&high));
        assert!(!br.callers.contains(&unrelated));
        // touched excluded from callers.
        assert!(!br.callers.contains(&SymbolId::new("a.rs", "low")));
        assert_eq!(br.symbol_count(), 3); // low + mid + high
    }

    #[test]
    fn unrelated_edit_has_zero_blast_radius() {
        let src = "fn a() -> i32 { 1 }\nfn b() -> i32 { 2 }\n";
        let g = SymbolGraph::build(&[rs("a.rs", src)]);
        let br = g.blast_radius(&["a"]);
        assert_eq!(br.fan_out, 0);
        assert!(br.callers.is_empty());
        // Only the touched symbol's own file is implicated.
        assert_eq!(br.files, ["a.rs".to_string()].into_iter().collect());
    }

    #[test]
    fn same_name_in_two_files_merges_conservatively() {
        // `handle` defined in BOTH files; a call in c.rs implicates BOTH defs (widen, never miss).
        let a = rs("a.rs", "fn handle() {}\n");
        let b = rs("b.rs", "fn handle() {}\n");
        let c = rs("c.rs", "fn caller() { handle(); }\n");
        let g = SymbolGraph::build(&[a, b, c]);
        let br = g.blast_radius(&["handle"]);
        assert_eq!(br.touched.len(), 2, "both same-named defs are touched");
        assert!(br.callers.contains(&SymbolId::new("c.rs", "caller")));
    }

    #[test]
    fn python_class_and_method_are_definitions() {
        let src = "class Foo:\n    def method(self):\n        return other()\n\ndef other():\n    return 1\n";
        let g = SymbolGraph::build(&[SourceFile::new("m.py", Language::Python, src)]);
        let names: Vec<String> = g.symbols().into_iter().map(|s| s.name).collect();
        assert!(names.contains(&"Foo".to_string()));
        assert!(names.contains(&"method".to_string()));
        assert!(names.contains(&"other".to_string()));
        // `method` calls `other`.
        let br = g.blast_radius(&["other"]);
        assert!(br.callers.contains(&SymbolId::new("m.py", "method")));
    }

    #[test]
    fn whole_word_reference_does_not_fire_on_substring() {
        // `run` must NOT be seen as called by a reference to `rerun`.
        let src = "fn run() {}\nfn caller() { rerun(); }\nfn rerun() {}\n";
        let g = SymbolGraph::build(&[rs("a.rs", src)]);
        let run = SymbolId::new("a.rs", "run");
        assert!(
            g.direct_callers(&run).is_empty(),
            "`rerun()` must not count as a call to `run`"
        );
    }
}
