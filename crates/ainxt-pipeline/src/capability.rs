// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! **Per-language capability-degradation matrix** (`docs/architecture/CODE_REVIEW_PIPELINE.md` §10).
//!
//! The pipeline's honesty depends on never letting a missing tool masquerade as a passed check. This
//! matrix — the same shape as the Semantic Editing engine's rung matrix — is read by the stage runner
//! ([`crate::stages`]) before it runs any stage: a stage with no tool for the language becomes a
//! `Skipped(reason)` verdict (a Confidence-Score *penalty*, never a silent pass), and a legacy
//! language with no toolchain at all (COBOL/mainframe) triggers the **"manual review required"** path
//! rather than a misleadingly-comparable score.

use serde::{Deserialize, Serialize};

/// The languages the pipeline classifies for capability. `Other` is the conservative catch-all
/// (generic scanning only), distinct from `Cobol`/legacy which additionally forces manual review.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    Rust,
    Java,
    TypeScript,
    Python,
    Go,
    JavaScript,
    Cobol,
    Other,
}

impl Language {
    /// Best-effort language from a file extension.
    #[must_use]
    pub fn from_extension(ext: &str) -> Language {
        match ext.trim_start_matches('.').to_ascii_lowercase().as_str() {
            "rs" => Language::Rust,
            "java" => Language::Java,
            "ts" | "tsx" => Language::TypeScript,
            "py" => Language::Python,
            "go" => Language::Go,
            "js" | "jsx" | "mjs" | "cjs" => Language::JavaScript,
            "cbl" | "cob" | "cobol" => Language::Cobol,
            _ => Language::Other,
        }
    }

    /// Whether this is a legacy/no-toolchain language that requires explicit manual review before
    /// commit (deterministic coverage is structurally unavailable — §10's COBOL row).
    #[must_use]
    pub fn requires_manual_review(self) -> bool {
        matches!(self, Language::Cobol)
    }
}

/// The four capability-bearing stage families the matrix tracks (the deterministic ones — §10's
/// columns). Lint always exists where a compile/build path exists, so it is folded into `Compile`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StageKind {
    Compile,
    Test,
    TypeCheck,
    Sast,
    Perf,
}

/// What tooling is available for a `(language, stage)` pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Capability {
    /// A native tool decides the verdict (e.g. `cargo build`, JUnit, native type-checker).
    Native(&'static str),
    /// A deterministic substitute stands in (e.g. tree-sitter syntax+import-resolve for a no-build
    /// language, generic entropy/secret scan for a no-SAST-ruleset language).
    Substitute(&'static str),
    /// No tool and no substitute — the stage is `Skipped(reason)`, a scored penalty, never a pass.
    Skip(&'static str),
    /// No toolchain at all for this language family — the report must say "manual review required".
    ManualReview(&'static str),
}

impl Capability {
    /// The human-readable reason (for a `Skipped`/`ManualReview` verdict, or the tool name).
    #[must_use]
    pub fn reason(&self) -> &'static str {
        match self {
            Capability::Native(s)
            | Capability::Substitute(s)
            | Capability::Skip(s)
            | Capability::ManualReview(s) => s,
        }
    }

    /// Whether a real (native or substitute) deterministic verdict can be produced.
    #[must_use]
    pub fn can_run(&self) -> bool {
        matches!(self, Capability::Native(_) | Capability::Substitute(_))
    }
}

/// The capability of `(lang, stage)` — the §10 table, encoded.
#[must_use]
pub fn capability(lang: Language, stage: StageKind) -> Capability {
    use Capability::*;
    use Language::*;
    use StageKind::*;
    match (lang, stage) {
        // Rust — the runtime's own language, fully tooled.
        (Rust, Compile) => Native("cargo build"),
        (Rust, Test) => Native("cargo test"),
        (Rust, TypeCheck) => Native("rustc (native)"),
        (Rust, Sast) => Native("cargo audit + semgrep"),
        (Rust, Perf) => Substitute("cargo bench (if present) / AST complexity"),

        (Java, Compile) => Native("javac / build tool"),
        (Java, Test) => Native("JUnit/TestNG"),
        (Java, TypeCheck) => Native("javac (native)"),
        (Java, Sast) => Native("semgrep + language rules"),
        (Java, Perf) => Substitute("JMH (if present) / AST complexity"),

        (TypeScript, Compile) => Native("tsc --noEmit"),
        (TypeScript, Test) => Native("jest/vitest"),
        (TypeScript, TypeCheck) => Native("tsc (native)"),
        (TypeScript, Sast) => Native("semgrep + eslint-security"),
        (TypeScript, Perf) => Substitute("benchmark.js (if present) / AST complexity"),

        (Python, Compile) => Substitute("tree-sitter syntax + import-resolve"),
        (Python, Test) => Native("pytest"),
        (Python, TypeCheck) => Skip("mypy not configured"),
        (Python, Sast) => Native("bandit + semgrep"),
        (Python, Perf) => Substitute("pytest-benchmark (if present) / AST complexity"),

        (Go, Compile) => Native("go build"),
        (Go, Test) => Native("go test"),
        (Go, TypeCheck) => Native("go (native)"),
        (Go, Sast) => Native("gosec + semgrep"),
        (Go, Perf) => Substitute("go test -bench / AST complexity"),

        (JavaScript, Compile) => Substitute("tree-sitter syntax + import-resolve"),
        (JavaScript, Test) => Skip("no test runner detected"),
        (JavaScript, TypeCheck) => Skip("no type-checker (untyped JS)"),
        (JavaScript, Sast) => Native("semgrep + eslint-security"),
        (JavaScript, Perf) => Skip("no perf harness"),

        // COBOL / mainframe batch — legacy settlement systems: no sandbox toolchain.
        (Cobol, Compile) => ManualReview("mainframe toolchain unavailable in sandbox"),
        (Cobol, Test) => ManualReview("no runnable harness"),
        (Cobol, TypeCheck) => Skip("n/a"),
        (Cobol, Sast) => Substitute("generic secret/entropy scan only (no COBOL ruleset)"),
        (Cobol, Perf) => Skip("no perf harness"),

        (Other, Compile) => Substitute("tree-sitter syntax check"),
        (Other, Test) => Skip("no test runner for language"),
        (Other, TypeCheck) => Skip("no type-checker for language"),
        (Other, Sast) => Substitute("generic secret/entropy scan only"),
        (Other, Perf) => Skip("no perf harness"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gap_ainxt_pipeline_edit_09_python_typecheck_is_an_honest_skip_not_a_pass() {
        let c = capability(Language::Python, StageKind::TypeCheck);
        assert!(matches!(c, Capability::Skip(_)));
        assert!(!c.can_run());
        assert!(c.reason().contains("mypy"));
    }

    #[test]
    fn gap_ainxt_pipeline_edit_09_cobol_forces_manual_review() {
        assert!(Language::Cobol.requires_manual_review());
        let compile = capability(Language::Cobol, StageKind::Compile);
        assert!(matches!(compile, Capability::ManualReview(_)));
        // SAST degrades to a generic scan, honestly labelled — never "SAST clean".
        let sast = capability(Language::Cobol, StageKind::Sast);
        assert!(matches!(sast, Capability::Substitute(_)));
        assert!(sast.reason().contains("generic"));
    }

    #[test]
    fn rust_is_fully_native() {
        for st in [
            StageKind::Compile,
            StageKind::Test,
            StageKind::TypeCheck,
            StageKind::Sast,
        ] {
            assert!(capability(Language::Rust, st).can_run());
        }
        assert!(!Language::Rust.requires_manual_review());
    }

    #[test]
    fn untyped_js_skips_typecheck_and_tests() {
        assert!(matches!(
            capability(Language::JavaScript, StageKind::TypeCheck),
            Capability::Skip(_)
        ));
        assert!(matches!(
            capability(Language::JavaScript, StageKind::Test),
            Capability::Skip(_)
        ));
    }

    #[test]
    fn language_from_extension_maps_known_and_legacy() {
        assert_eq!(Language::from_extension("rs"), Language::Rust);
        assert_eq!(Language::from_extension(".cbl"), Language::Cobol);
        assert_eq!(Language::from_extension("zig"), Language::Other);
    }
}
