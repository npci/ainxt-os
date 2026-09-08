// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! **Regression Detection** signals (`docs/architecture/CODE_REVIEW_PIPELINE.md` §4 stage 8), the
//! deterministic sub-checks the design demands but the pipeline consumed only as caller-supplied
//! scalars before:
//!
//! - **Uncovered blast-radius fraction** = touched symbols minus test-graph coverage. A test function
//!   "covers" a symbol when the symbol is forward-reachable from the test through the call graph. This
//!   turns `blast_radius_test_coverage` from a number the caller invents into a graph computation.
//! - **Change-coupling cross-check** — from a git-history co-change graph: a file historically edited
//!   together with a touched file but absent from this edit is a (non-blocking) advisory.
//!
//! Both are computed from the same conservative graphs the rest of this crate builds; missing a real
//! caller (false-negative) is the dangerous error for a *risk* signal, so coverage is computed
//! forward from tests and any doubt widens the uncovered set rather than shrinking it.

use crate::graph::{SourceFile, SymbolGraph, SymbolId};
use crate::{list_definitions, DefKind};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// The regression signals for one edit.
#[derive(Debug, Clone, PartialEq)]
pub struct RegressionReport {
    /// Touched symbols with no covering test (transitively unreachable from any test function).
    pub uncovered: BTreeSet<SymbolId>,
    /// Touched symbols reached by at least one test.
    pub covered: BTreeSet<SymbolId>,
    /// Fraction `[0,1]` of the touched set that has *any* covering test.
    pub coverage_overlap: f64,
    /// Historically-coupled files not present in the edit set (advisory, never blocking).
    pub coupling_advisories: Vec<CouplingAdvisory>,
}

impl RegressionReport {
    /// `1 - coverage_overlap` — the uncovered fraction the Confidence Score's regression term uses.
    #[must_use]
    pub fn uncovered_fraction(&self) -> f64 {
        (1.0 - self.coverage_overlap).clamp(0.0, 1.0)
    }
}

/// A "these usually change together, confirm the other doesn't also need updating" advisory.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CouplingAdvisory {
    pub touched_file: String,
    pub coupled_file: String,
    pub cochange_count: usize,
}

/// A git-history co-change graph: for a pair of files, how many past commits changed both. Symmetric
/// by construction ([`CochangeGraph::record`] inserts both directions).
#[derive(Debug, Clone, Default)]
pub struct CochangeGraph {
    counts: BTreeMap<(String, String), usize>,
}

impl CochangeGraph {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that `a` and `b` changed together in `n` historical commits.
    pub fn record(&mut self, a: &str, b: &str, n: usize) {
        self.counts.insert((a.to_string(), b.to_string()), n);
        self.counts.insert((b.to_string(), a.to_string()), n);
    }

    /// **Populate the graph from git history** (`CODE_REVIEW_PIPELINE.md` §4 stage 8 — the git-history
    /// change-coupling graph). Each entry in `commits` is the set of file paths that changed in one
    /// past commit; every unordered pair of files in a commit has its co-change count incremented.
    ///
    /// Extracting the per-commit file sets from a repository is infra (`git log --name-only`); this
    /// populator is the offline, deterministic core that turns those file sets into the coupling graph,
    /// so it is exhaustively testable without a live repo. Duplicate paths within a commit are ignored
    /// (a file coupled with itself is meaningless).
    #[must_use]
    pub fn from_commits<S: AsRef<str>>(commits: &[Vec<S>]) -> Self {
        let mut g = CochangeGraph::new();
        for commit in commits {
            // De-dup + sort the files in this commit so each unordered pair is counted once.
            let files: BTreeSet<&str> = commit.iter().map(AsRef::as_ref).collect();
            let files: Vec<&str> = files.into_iter().collect();
            for i in 0..files.len() {
                for j in (i + 1)..files.len() {
                    let (a, b) = (files[i], files[j]);
                    let cur = g
                        .counts
                        .get(&(a.to_string(), b.to_string()))
                        .copied()
                        .unwrap_or(0);
                    g.record(a, b, cur + 1);
                }
            }
        }
        g
    }

    /// Files coupled to `file` at/above `threshold`, with their counts, deterministically ordered.
    #[must_use]
    pub fn coupled_with(&self, file: &str, threshold: usize) -> Vec<(String, usize)> {
        self.counts
            .iter()
            .filter(|((a, _), n)| a == file && **n >= threshold)
            .map(|((_, b), n)| (b.clone(), *n))
            .collect()
    }
}

/// Whether the definition at `name`/`span_start` is a test function (Rust `#[test]` attribute on the
/// preceding lines, or a `test`-prefixed name in either language).
fn is_test_fn(src: &str, name: &str, start_byte: usize) -> bool {
    if name.starts_with("test") {
        return true;
    }
    // Rust: scan the two lines immediately preceding the definition for a `#[test]`-family attribute.
    let head = &src[..start_byte];
    head.lines()
        .rev()
        .take(3)
        .any(|l| l.contains("#[test]") || l.contains("#[tokio::test]"))
}

/// Collect every test function's [`SymbolId`] across the file set.
fn test_symbols(files: &[SourceFile]) -> BTreeSet<SymbolId> {
    let mut out = BTreeSet::new();
    for f in files {
        if let Ok(defs) = list_definitions(&f.source, f.lang) {
            for d in defs {
                if d.kind == DefKind::Function && is_test_fn(&f.source, &d.name, d.span.start_byte)
                {
                    out.insert(SymbolId::new(f.path.clone(), d.name));
                }
            }
        }
    }
    out
}

/// Forward transitive callees of `roots` through the call graph (what the tests reach).
fn forward_closure(graph: &SymbolGraph, roots: &BTreeSet<SymbolId>) -> BTreeSet<SymbolId> {
    let mut seen: BTreeSet<SymbolId> = roots.clone();
    let mut queue: VecDeque<SymbolId> = roots.iter().cloned().collect();
    while let Some(cur) = queue.pop_front() {
        for callee in graph.direct_callees(&cur) {
            if seen.insert(callee.clone()) {
                queue.push_back(callee);
            }
        }
    }
    seen
}

/// Compute the regression report for an edit that touched `touched_names` in `touched_files`.
///
/// - `files` is the full (post-edit) file set, from which the symbol/call/test graphs are built.
/// - `cochange` is the git-history co-change graph; `coupling_threshold` is the minimum co-change
///   count for an advisory.
#[must_use]
pub fn analyze(
    files: &[SourceFile],
    touched_names: &[&str],
    touched_files: &[&str],
    cochange: &CochangeGraph,
    coupling_threshold: usize,
) -> RegressionReport {
    let graph = SymbolGraph::build(files);

    // Resolve the touched symbols by name (conservative: all files with that name).
    let mut touched: BTreeSet<SymbolId> = BTreeSet::new();
    for n in touched_names {
        for s in graph.symbols() {
            if s.name == *n {
                touched.insert(s);
            }
        }
    }

    // Test-graph coverage: a touched symbol is covered iff some test reaches it forward.
    let tests = test_symbols(files);
    let reachable = forward_closure(&graph, &tests);
    let mut covered = BTreeSet::new();
    let mut uncovered = BTreeSet::new();
    for t in &touched {
        // A test function itself is trivially covered (it is executed); otherwise it must be
        // forward-reachable from some test.
        if tests.contains(t) || reachable.contains(t) {
            covered.insert(t.clone());
        } else {
            uncovered.insert(t.clone());
        }
    }
    let coverage_overlap = if touched.is_empty() {
        1.0
    } else {
        covered.len() as f64 / touched.len() as f64
    };

    // Change-coupling: coupled files not in the edit set.
    let touched_set: BTreeSet<&str> = touched_files.iter().copied().collect();
    let mut coupling_advisories = Vec::new();
    for tf in touched_files {
        for (coupled, n) in cochange.coupled_with(tf, coupling_threshold) {
            if !touched_set.contains(coupled.as_str()) {
                coupling_advisories.push(CouplingAdvisory {
                    touched_file: (*tf).to_string(),
                    coupled_file: coupled,
                    cochange_count: n,
                });
            }
        }
    }
    coupling_advisories.sort();
    coupling_advisories.dedup();

    RegressionReport {
        uncovered,
        covered,
        coverage_overlap,
        coupling_advisories,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Language;

    fn rs(path: &str, src: &str) -> SourceFile {
        SourceFile::new(path, Language::Rust, src)
    }

    #[test]
    fn gap_ainxt_semantic_edit_08_uncovered_blast_radius_is_computed_from_the_test_graph() {
        // `covered_fn` is reached by a #[test]; `naked_fn` is reached by nobody.
        let lib = rs(
            "lib.rs",
            "pub fn covered_fn() -> i32 { 1 }\npub fn naked_fn() -> i32 { 2 }\n",
        );
        let tests = rs(
            "tests.rs",
            "#[test]\nfn test_it() {\n    assert_eq!(covered_fn(), 1);\n}\n",
        );
        let files = vec![lib, tests];
        let r = analyze(
            &files,
            &["covered_fn", "naked_fn"],
            &["lib.rs"],
            &CochangeGraph::new(),
            2,
        );
        assert!(r.covered.contains(&SymbolId::new("lib.rs", "covered_fn")));
        assert!(r.uncovered.contains(&SymbolId::new("lib.rs", "naked_fn")));
        // Exactly half the touched set is covered.
        assert!((r.coverage_overlap - 0.5).abs() < 1e-9);
        assert!((r.uncovered_fraction() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn fully_covered_edit_has_zero_uncovered_fraction() {
        let lib = rs("lib.rs", "pub fn f() -> i32 { 1 }\n");
        let tests = rs("t.rs", "#[test]\nfn test_f() { f(); }\n");
        let r = analyze(&[lib, tests], &["f"], &["lib.rs"], &CochangeGraph::new(), 2);
        assert!(r.uncovered.is_empty());
        assert!((r.uncovered_fraction()).abs() < 1e-9);
    }

    #[test]
    fn gap_ainxt_semantic_edit_08_change_coupling_flags_the_missing_partner() {
        // history: schema.rs and migration.rs changed together 5 times. Editing only schema.rs → flag.
        let mut cc = CochangeGraph::new();
        cc.record("schema.rs", "migration.rs", 5);
        cc.record("schema.rs", "unrelated.rs", 1);
        let lib = rs("schema.rs", "pub fn f() {}\n");
        let r = analyze(&[lib], &["f"], &["schema.rs"], &cc, 3);
        assert_eq!(r.coupling_advisories.len(), 1);
        assert_eq!(r.coupling_advisories[0].coupled_file, "migration.rs");
        assert_eq!(r.coupling_advisories[0].cochange_count, 5);
    }

    #[test]
    fn coupling_not_flagged_when_partner_is_in_the_edit() {
        let mut cc = CochangeGraph::new();
        cc.record("schema.rs", "migration.rs", 5);
        let a = rs("schema.rs", "pub fn f() {}\n");
        let b = rs("migration.rs", "pub fn g() {}\n");
        let r = analyze(&[a, b], &["f"], &["schema.rs", "migration.rs"], &cc, 3);
        assert!(r.coupling_advisories.is_empty());
    }
}
