// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! **Deterministic Architecture Review** (`docs/architecture/CODE_REVIEW_PIPELINE.md` §4 stage 7 +
//! §12): a new import edge the architecture graph does not allow is a *graph-membership* violation —
//! no model needed. This module encodes the declared module-boundary contract (layers + allowed
//! dependency edges) and diffs an edit's import edges against it, exactly the generalization of the
//! `sdlc_patch_engine.py` field-usage guard the design calls for.
//!
//! Resolution is deliberately conservative and language-agnostic: a file is assigned to a layer by a
//! keyword match on its path, and an import target is assigned to a layer by a keyword match on the
//! import string ([`crate::graph::SymbolGraph::imports_of`]). A cross-layer edge that is neither
//! same-layer nor in the allowed set — and whose target resolves to a *known* layer — is a hard
//! [`ArchViolation`]. Unknown-layer targets (third-party crates, std) are ignored, never guessed.

use crate::graph::{SourceFile, SymbolGraph};
use std::collections::{BTreeMap, BTreeSet};

/// A declared layering contract: named layers (each with the path/import keywords that identify it)
/// and the set of allowed `from → to` dependency edges. Any cross-layer edge not in `allowed` (and
/// not same-layer) is a violation.
#[derive(Debug, Clone, Default)]
pub struct LayerContract {
    /// `layer -> keywords`. A path or import string matching a keyword belongs to that layer.
    layers: BTreeMap<String, Vec<String>>,
    /// Allowed directed edges `(from_layer, to_layer)`.
    allowed: BTreeSet<(String, String)>,
}

/// A deterministic architecture boundary violation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ArchViolation {
    pub file: String,
    pub from_layer: String,
    pub to_layer: String,
    /// The exact import string that crossed the forbidden boundary (never a paraphrase).
    pub import: String,
}

impl std::fmt::Display for ArchViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: layer `{}` may not depend on `{}` (import `{}`)",
            self.file, self.from_layer, self.to_layer, self.import
        )
    }
}

/// A **declarative, git-controlled** layering contract (`CODE_REVIEW_PIPELINE.md` §4 stage 7 — the
/// architecture graph "declared once per module, read every time"). This is the on-disk / in-repo
/// form a deployment checks in (e.g. `.arch.toml` / `.arch.json`) and the pipeline loads, rather than
/// hand-wiring the fluent builder in code: layers with their identifying keywords, and the allowed
/// directed dependency edges. Round-trips serde so a change to the contract is itself a reviewable,
/// audited diff (a human amending a boundary rule, never a silent bypass).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct LayerManifest {
    /// `layer name -> identifying keywords` (matched against file paths and import strings).
    pub layers: BTreeMap<String, Vec<String>>,
    /// Allowed directed dependency edges as `[from, to]` pairs.
    #[serde(default)]
    pub allowed: Vec<(String, String)>,
}

impl LayerContract {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a contract from a declarative [`LayerManifest`] — the git-controlled population path.
    #[must_use]
    pub fn from_manifest(manifest: &LayerManifest) -> Self {
        let mut c = LayerContract::new();
        for (name, kws) in &manifest.layers {
            let refs: Vec<&str> = kws.iter().map(String::as_str).collect();
            c = c.layer(name, &refs);
        }
        for (from, to) in &manifest.allowed {
            c = c.allow(from, to);
        }
        c
    }

    /// Declare a layer identified by the given keywords (matched against paths and import strings).
    #[must_use]
    pub fn layer(mut self, name: &str, keywords: &[&str]) -> Self {
        self.layers.insert(
            name.to_string(),
            keywords.iter().map(|k| k.to_string()).collect(),
        );
        self
    }

    /// Allow the directed dependency edge `from → to`.
    #[must_use]
    pub fn allow(mut self, from: &str, to: &str) -> Self {
        self.allowed.insert((from.to_string(), to.to_string()));
        self
    }

    /// Resolve a path or import string to its layer (first matching layer, deterministically ordered).
    #[must_use]
    pub fn layer_of(&self, s: &str) -> Option<String> {
        for (layer, kws) in &self.layers {
            if kws.iter().any(|k| s.contains(k.as_str())) {
                return Some(layer.clone());
            }
        }
        None
    }

    /// Every deterministic boundary violation across `files`, sorted. A file whose path resolves to a
    /// known layer, importing a target that resolves to a *different* known layer via an edge not in
    /// `allowed`, is a violation.
    #[must_use]
    pub fn violations(&self, files: &[SourceFile]) -> Vec<ArchViolation> {
        let graph = SymbolGraph::build(files);
        let mut out = BTreeSet::new();
        for f in files {
            let Some(from_layer) = self.layer_of(&f.path) else {
                continue;
            };
            for import in graph.imports_of(&f.path) {
                let Some(to_layer) = self.layer_of(&import) else {
                    continue; // std / third-party / unknown — not our contract's concern
                };
                if to_layer == from_layer {
                    continue;
                }
                if !self
                    .allowed
                    .contains(&(from_layer.clone(), to_layer.clone()))
                {
                    out.insert(ArchViolation {
                        file: f.path.clone(),
                        from_layer: from_layer.clone(),
                        to_layer: to_layer.clone(),
                        import: import.clone(),
                    });
                }
            }
        }
        out.into_iter().collect()
    }

    /// Only the violations *introduced* by an edit — the set present in `after` but not in `before`.
    /// This is the "diff the edit's new/changed import edges against the contract" behaviour (§4/§7):
    /// a pre-existing violation is not attributed to this edit.
    #[must_use]
    pub fn new_violations(
        &self,
        before: &[SourceFile],
        after: &[SourceFile],
    ) -> Vec<ArchViolation> {
        let old: BTreeSet<ArchViolation> = self.violations(before).into_iter().collect();
        self.violations(after)
            .into_iter()
            .filter(|v| !old.contains(v))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Language;

    fn rs(path: &str, src: &str) -> SourceFile {
        SourceFile::new(path, Language::Rust, src)
    }

    fn contract() -> LayerContract {
        // ui may depend on api-client, never directly on db.
        LayerContract::new()
            .layer("ui", &["ui/", "/ui"])
            .layer("api", &["api/", "api_client"])
            .layer("db", &["db/", "db::", "database"])
            .allow("ui", "api")
            .allow("api", "db")
    }

    #[test]
    fn gap_ainxt_semantic_edit_07_forbidden_edge_is_a_deterministic_violation() {
        // ui importing db directly violates the layering contract — no model needed.
        let ui = rs("src/ui/screen.rs", "use crate::db::conn;\nfn render() {}\n");
        let vs = contract().violations(&[ui]);
        assert_eq!(vs.len(), 1);
        assert_eq!(vs[0].from_layer, "ui");
        assert_eq!(vs[0].to_layer, "db");
        assert!(vs[0].import.contains("db::conn"));
    }

    #[test]
    fn allowed_edge_produces_no_violation() {
        let ui = rs(
            "src/ui/screen.rs",
            "use crate::api_client::Client;\nfn render() {}\n",
        );
        assert!(contract().violations(&[ui]).is_empty());
    }

    #[test]
    fn unknown_target_layer_is_ignored_not_guessed() {
        let ui = rs("src/ui/screen.rs", "use std::collections::HashMap;\n");
        assert!(contract().violations(&[ui]).is_empty());
    }

    #[test]
    fn gap_ainxt_semantic_edit_07_only_new_edges_are_attributed_to_the_edit() {
        // A pre-existing ui→db violation is not blamed on this edit; only the newly-added one is.
        let before = vec![rs("src/ui/a.rs", "use crate::db::old;\nfn a() {}\n")];
        let after = vec![
            rs("src/ui/a.rs", "use crate::db::old;\nfn a() {}\n"),
            rs("src/ui/b.rs", "use crate::db::fresh;\nfn b() {}\n"),
        ];
        let fresh = contract().new_violations(&before, &after);
        assert_eq!(fresh.len(), 1);
        assert_eq!(fresh[0].file, "src/ui/b.rs");
        assert!(fresh[0].import.contains("fresh"));
    }
}
