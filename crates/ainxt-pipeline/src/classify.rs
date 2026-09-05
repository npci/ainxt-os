// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! **Pre-stage-1 deterministic edit classification** (`docs/architecture/CODE_REVIEW_PIPELINE.md`
//! §3). [`crate::risk::classify`] tiers a set of *already-computed* [`RiskInputs`]; this module is
//! the step **before** it: it derives those inputs from the raw edit — the pre-edit tree plus the
//! edit engine's applied edit set — using the Context-Fabric symbol graph ([`ainxt_semantic::graph`])
//! and an AST-precise diff, with **no LLM call and no I/O**. The classifier runs *before* stage 1 so
//! the tier that drives the Commit Gate is computed from the code itself, never trusted from the
//! caller or the wire.
//!
//! Two invariants are load-bearing here:
//! - **Escalate-only against the declared floor.** A surface may DECLARE a floor tier (e.g. an SDLC
//!   profile pinning every change to at least `Moderate`), but classification can only raise it
//!   ([`RiskTier::escalate`]): a client that under-declares a settlement-path edit as `Local` is
//!   still forced to Tier 3. A caller can never *lower* the graph-derived risk.
//! - **`DocOnly` is proven, never assumed.** A change is classified doc-only only when its
//!   comment-and-whitespace-stripped **code signature** is byte-identical before and after — a
//!   string-aware strip, so a change *inside a string literal* (a URL, a SQL fragment, a routing key)
//!   is never mistaken for a comment edit. Every ambiguous case degrades *upward* (more scrutiny).

use crate::capability::Language;
use crate::risk::{classify, DiffClass, RiskInputs, RiskTier};
use ainxt_semantic::graph::{SourceFile, SymbolGraph};
use ainxt_semantic::{list_definitions, Language as SemLang};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Path fragments that mark a **critical-path** module. A touched file whose path contains any of
/// these (case-insensitive) forces Tier 3 — a human approves even a one-character change on it.
/// Aligned with `CODE_REVIEW_PIPELINE.md` §3 (payments/settlement/ledger/compliance) plus the region-specific
/// clearing/reconciliation surfaces that carry the same double-payment blast radius.
pub const CRITICAL_PATH_FRAGMENTS: &[&str] = &[
    "payment",
    "settlement",
    "ledger",
    "compliance",
    "clearing",
    "reconcil",
];

/// The full, auditable result of classifying one edit — the tier the gate runs under plus *why*.
/// Serializable so a live surface can render the tier + rationale on the wire (a reviewer sees not
/// just "Tier 3" but the graph fact — "settlement/x.rs is on the critical path" — that forced it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EditRiskAssessment {
    /// The **effective** tier the Commit Gate runs under: `escalate(declared, classified)`.
    pub tier: RiskTier,
    /// The tier the caller declared (the floor). `tier >= declared_tier` always.
    pub declared_tier: RiskTier,
    /// The tier the graph-derived signals alone produced (before folding in the declared floor).
    pub classified_tier: RiskTier,
    /// The AST-diff class of the edit.
    pub diff_class: DiffClass,
    /// Number of files whose content actually changed.
    pub files_touched: usize,
    /// Direct 1-hop fan-out (callers) of the changed symbols — the blast radius the tier sizes on.
    pub blast_fan_out: usize,
    /// Whether any touched file sits on a critical payment/settlement path.
    pub critical_path: bool,
    /// Whether this edit is eligible for the trivial auto-approve floor (`tier == Trivial`).
    pub trivial_auto_approve_eligible: bool,
    /// One human-readable line per signal that drove the classification.
    pub rationale: Vec<String>,
}

/// Map the pipeline's capability language to the AST engine's grammar set. `None` = no tree-sitter
/// grammar (Java/Go/TS/…); classification falls back to string-signature + generic heuristics for
/// those, which can only *under*-detect a signature change (never falsely assert `DocOnly`).
fn sem_lang(lang: Language) -> Option<SemLang> {
    match lang {
        Language::Rust => Some(SemLang::Rust),
        Language::Python => Some(SemLang::Python),
        _ => None,
    }
}

/// Whether `path` sits on a critical payment/settlement path.
#[must_use]
pub fn is_critical_path(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    CRITICAL_PATH_FRAGMENTS.iter().any(|k| p.contains(k))
}

/// Whether **line structure is executable semantics** in this language. In Python a newline ends a
/// statement and the leading indentation selects the enclosing block; in JavaScript/TypeScript/Go a
/// newline can insert a semicolon (ASI / Go's lexer rule), so `return\nx` and `return x` are
/// different programs. For these languages the code signature must keep line boundaries, otherwise a
/// pure re-indent or a joined/split line is indistinguishable from a comment edit and the change is
/// mis-proven as `DocOnly` → Tier 0 → the trivial auto-approve floor with no spot audit.
fn line_structure_is_semantic(lang: Language) -> bool {
    matches!(
        lang,
        Language::Python | Language::JavaScript | Language::TypeScript | Language::Go
    )
}

/// Whether **leading indentation** is executable semantics (Python's block structure).
fn indentation_is_semantic(lang: Language) -> bool {
    matches!(lang, Language::Python)
}

/// A string-aware **code signature**: the source with all comments and all *non-semantic* whitespace
/// removed, but with string/char literals preserved verbatim. Two sources with the same signature
/// differ only in comments/formatting — the *only* condition under which an edit is `DocOnly`.
/// Because string literals are emitted verbatim, a `//` or `#` *inside a string* is never treated as
/// a comment, so a real logic change hidden in a URL/SQL/key literal can never be mis-scored as
/// doc-only.
///
/// **Whitespace is not uniformly insignificant.** For a brace language whose statements are
/// semicolon-terminated (Rust/Java) every whitespace run is dropped, as before. For a language where
/// line structure carries meaning ([`line_structure_is_semantic`]) the signature is *line-oriented*:
/// blank/comment-only lines vanish (so a comment edit is still `DocOnly`), but the surviving code
/// lines keep their boundaries — and in Python each also keeps its indentation width. A statement
/// dedented out of an `if`/`for` body, or a `return\nx` collapsed to `return x`, therefore changes
/// the signature and degrades *upward* out of `DocOnly`, which is the direction the §3 contract
/// requires for every ambiguous case.
pub(crate) fn code_signature(lang: Language, src: &str) -> String {
    let python = matches!(lang, Language::Python);
    let line_mode = line_structure_is_semantic(lang);
    let indent_mode = indentation_is_semantic(lang);
    let chars: Vec<char> = src.chars().collect();
    let n = chars.len();
    let mut out = String::with_capacity(src.len());
    // Line-oriented accumulation state (used only when `line_mode`).
    let mut line = String::new();
    let mut indent: usize = 0;
    let mut seen_code_on_line = false;
    let mut lines: Vec<String> = Vec::new();
    // Push a char into whichever accumulator is active.
    macro_rules! emit {
        ($c:expr) => {
            if line_mode {
                line.push($c);
                seen_code_on_line = true;
            } else {
                out.push($c);
            }
        };
    }
    let mut i = 0;
    let mut in_str: Option<char> = None;
    while i < n {
        let c = chars[i];
        if let Some(q) = in_str {
            emit!(c);
            if c == '\\' && i + 1 < n {
                // Escape: consume the escaped char verbatim so an escaped quote does not close.
                emit!(chars[i + 1]);
                i += 2;
                continue;
            }
            if c == q {
                in_str = None;
            }
            i += 1;
            continue;
        }
        // Not inside a string literal.
        if !python && c == '/' && i + 1 < n && chars[i + 1] == '/' {
            while i < n && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if !python && c == '/' && i + 1 < n && chars[i + 1] == '*' {
            i += 2;
            while i + 1 < n && !(chars[i] == '*' && chars[i + 1] == '/') {
                i += 1;
            }
            i = (i + 2).min(n);
            continue;
        }
        if python && c == '#' {
            while i < n && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if c == '"' || c == '\'' {
            in_str = Some(c);
            emit!(c);
            i += 1;
            continue;
        }
        if c.is_whitespace() {
            if line_mode && c == '\n' {
                // End of a source line: keep it only if it carried code (so a comment-only or blank
                // line still vanishes and a pure comment edit stays `DocOnly`).
                if seen_code_on_line && !line.is_empty() {
                    if indent_mode {
                        lines.push(format!("{indent}\u{1f}{line}"));
                    } else {
                        lines.push(std::mem::take(&mut line));
                    }
                }
                line.clear();
                seen_code_on_line = false;
                indent = 0;
            } else if line_mode && indent_mode && !seen_code_on_line {
                // Leading indentation of a not-yet-started Python line: measure it (tab = 8, the
                // reference interpreter's tabstop), never emit it as content.
                indent += if c == '\t' { 8 } else { 1 };
            }
            i += 1;
            continue;
        }
        emit!(c);
        i += 1;
    }
    if line_mode {
        if seen_code_on_line && !line.is_empty() {
            if indent_mode {
                lines.push(format!("{indent}\u{1f}{line}"));
            } else {
                lines.push(line);
            }
        }
        return lines.join("\n");
    }
    out
}

/// Best-effort import/dependency targets declared by a source, per language. Line-based and
/// intentionally conservative: it is only used to detect a *new* dependency (a target present after
/// but not before), which raises risk — a missed import can only under-detect, never falsely flag.
fn imports(lang: Language, src: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for raw in src.lines() {
        let t = raw.trim();
        let target = match lang {
            Language::Rust => t
                .strip_prefix("use ")
                .map(|r| r.trim_end_matches(';').trim()),
            Language::Python => t
                .strip_prefix("from ")
                .and_then(|r| r.split_whitespace().next())
                .or_else(|| t.strip_prefix("import ").map(str::trim)),
            Language::Java | Language::Go => t
                .strip_prefix("import ")
                .map(|r| r.trim_matches(['"', ';', ' '])),
            Language::TypeScript | Language::JavaScript => t
                .strip_prefix("import ")
                .map(str::trim)
                .filter(|_| t.contains(" from ") || t.contains('\'') || t.contains('"')),
            Language::Cobol | Language::Other => None,
        };
        if let Some(s) = target {
            if !s.is_empty() {
                out.insert(s.to_string());
            }
        }
    }
    out
}

/// `name -> full definition text` for every function/type definition in `src` (first span wins on a
/// duplicate name). Empty on a parse error — a file we cannot parse contributes no signature signal.
fn definitions(src: &str, sl: SemLang) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    if let Ok(defs) = list_definitions(src, sl) {
        for d in defs {
            let text = src
                .get(d.span.start_byte..d.span.end_byte)
                .unwrap_or_default()
                .to_string();
            out.entry(d.name).or_insert(text);
        }
    }
    out
}

/// The **signature/header** of a definition — the declaration up to the body. Rust/brace languages:
/// everything before the first `{`. Python: the first line (up to the `:`). Comparing headers (not
/// bodies) is what separates an API/signature change from a pure body-logic change.
fn header(python: bool, def_text: &str) -> &str {
    if python {
        def_text.split('\n').next().unwrap_or(def_text).trim_end()
    } else {
        def_text.split('{').next().unwrap_or(def_text).trim_end()
    }
}

/// Whether the set of definitions, or any surviving definition's header, changed between two versions
/// of a file (a signature/API change). An added or removed definition counts.
fn signature_changed(
    old: &BTreeMap<String, String>,
    new: &BTreeMap<String, String>,
    python: bool,
) -> bool {
    let old_names: BTreeSet<&String> = old.keys().collect();
    let new_names: BTreeSet<&String> = new.keys().collect();
    if old_names != new_names {
        return true;
    }
    new.iter().any(|(name, new_text)| {
        old.get(name)
            .is_some_and(|old_text| header(python, old_text) != header(python, new_text))
    })
}

/// The names of definitions that were added or whose text changed — the "touched symbols" fed to the
/// blast-radius resolver.
fn changed_symbols(old: &BTreeMap<String, String>, new: &BTreeMap<String, String>) -> Vec<String> {
    let mut names = Vec::new();
    for (name, new_text) in new {
        if old.get(name) != Some(new_text) {
            names.push(name.clone());
        }
    }
    for name in old.keys() {
        if !new.contains_key(name) {
            names.push(name.clone());
        }
    }
    names
}

/// A generic (no-AST) signature-change heuristic for languages without a tree-sitter grammar. A
/// changed line that looks like a declaration (a visibility/definition keyword followed by a `(`)
/// is treated as a signature change. Conservative: it can under-detect, so the diff class only ever
/// degrades *downward* to `LocalLogic` (still gated), never falsely up.
fn generic_signature_change(old_src: &str, new_src: &str) -> bool {
    let decl = |line: &str| -> bool {
        let l = line.trim();
        let kw = [
            "fn ",
            "func ",
            "function ",
            "def ",
            "public ",
            "private ",
            "protected ",
            "static ",
        ];
        l.contains('(') && kw.iter().any(|k| l.contains(k))
    };
    let old_decls: BTreeSet<&str> = old_src.lines().map(str::trim).filter(|l| decl(l)).collect();
    let new_decls: BTreeSet<&str> = new_src.lines().map(str::trim).filter(|l| decl(l)).collect();
    old_decls != new_decls
}

/// **Classify one edit into a risk tier, deterministically, before stage 1.** Derives the
/// [`RiskInputs`] from the pre-edit tree (`original`) and the applied edit set (`applied`) via the
/// symbol graph + AST diff, tiers them with [`crate::risk::classify`], then folds in the caller's
/// declared floor with the escalate-only combinator. No LLM, no I/O — pure and reproducible.
///
/// `prior_finding` carries a mid-run escalator (a previous self-heal round tripped a SAST/arch
/// finding); pass `false` for a fresh turn.
#[must_use]
pub fn classify_edit(
    original: &[(String, String)],
    applied: &[(String, String)],
    lang: Language,
    declared: RiskTier,
    rung: ainxt_semantic::ladder::Rung,
    prior_finding: bool,
) -> EditRiskAssessment {
    let orig: BTreeMap<&str, &str> = original
        .iter()
        .map(|(p, c)| (p.as_str(), c.as_str()))
        .collect();
    let sem = sem_lang(lang);
    let python = matches!(lang, Language::Python);

    let mut touched_paths: Vec<&str> = Vec::new();
    let mut new_dependency = false;
    let mut signature = false;
    let mut logic = false;
    let mut critical_path = false;
    let mut changed_names: Vec<String> = Vec::new();

    for (path, new_src) in applied {
        let old_src = orig.get(path.as_str()).copied().unwrap_or("");
        if old_src == new_src.as_str() {
            continue; // unchanged file — no signal
        }
        touched_paths.push(path.as_str());
        if is_critical_path(path) {
            critical_path = true;
        }

        // New dependency?
        let oi = imports(lang, old_src);
        let ni = imports(lang, new_src);
        if ni.difference(&oi).next().is_some() {
            new_dependency = true;
        }

        // Doc-only vs real change (string-aware code signature).
        let changed_code = code_signature(lang, old_src) != code_signature(lang, new_src);
        let is_new_file = old_src.is_empty();
        if changed_code || is_new_file {
            logic = true;
            if let Some(sl) = sem {
                let od = definitions(old_src, sl);
                let nd = definitions(new_src, sl);
                if signature_changed(&od, &nd, python) {
                    signature = true;
                }
                changed_names.extend(changed_symbols(&od, &nd));
            } else if generic_signature_change(old_src, new_src) {
                signature = true;
            }
        }
    }

    let files_touched = touched_paths.len();

    let diff_class = if new_dependency {
        DiffClass::NewDependency
    } else if signature {
        DiffClass::SignatureApi
    } else if logic {
        DiffClass::LocalLogic
    } else {
        DiffClass::DocOnly
    };

    // Blast radius from the post-edit symbol graph (AST languages only; 0 otherwise — a language we
    // cannot parse contributes no fan-out, and the tier degrades upward via files_touched instead).
    let blast_fan_out = match sem {
        Some(sl) if !changed_names.is_empty() => {
            let files: Vec<SourceFile> = applied
                .iter()
                .map(|(p, c)| SourceFile::new(p.clone(), sl, c.clone()))
                .collect();
            let g = SymbolGraph::build(&files);
            let names: Vec<&str> = changed_names.iter().map(String::as_str).collect();
            g.blast_radius(&names).fan_out
        }
        _ => 0,
    };

    let inputs = RiskInputs {
        diff_class,
        blast_fan_out,
        files_touched,
        critical_path,
        coverage_overlap: 1.0, // not consulted by classify(); coverage is a Confidence-Score term
        rung,
        prior_finding,
    };
    let classified = classify(&inputs);
    let tier = declared.escalate(classified);

    // Rationale — the auditable "why".
    let mut rationale = Vec::new();
    rationale.push(format!(
        "diff_class={diff_class:?}, files_touched={files_touched}, blast_fan_out={blast_fan_out}"
    ));
    if critical_path {
        rationale.push("critical payment/settlement path touched → Tier 3".to_string());
    }
    if prior_finding {
        rationale.push("prior-round SAST/architecture finding → Tier 3 (escalator)".to_string());
    }
    if classified != tier {
        rationale.push(format!(
            "graph classified {classified:?}; escalated to declared floor {declared:?}"
        ));
    } else if declared != classified {
        rationale.push(format!(
            "declared floor {declared:?} below graph-classified {classified:?} → {tier:?}"
        ));
    }
    if tier == RiskTier::Trivial {
        rationale
            .push("doc/comment-only, no blast radius → trivial auto-approve floor".to_string());
    }

    EditRiskAssessment {
        tier,
        declared_tier: declared,
        classified_tier: classified,
        diff_class,
        files_touched,
        blast_fan_out,
        critical_path,
        trivial_auto_approve_eligible: tier == RiskTier::Trivial,
        rationale,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ainxt_semantic::ladder::Rung;

    fn f(path: &str, src: &str) -> (String, String) {
        (path.to_string(), src.to_string())
    }

    #[test]
    fn comment_only_edit_is_trivial() {
        let orig = vec![f("a.rs", "fn add(a: i32, b: i32) -> i32 {\n    a + b\n}\n")];
        let app = vec![f(
            "a.rs",
            "// adds two numbers\nfn add(a: i32, b: i32) -> i32 {\n    a + b\n}\n",
        )];
        let got = classify_edit(
            &orig,
            &app,
            Language::Rust,
            RiskTier::Local,
            Rung::Ast,
            false,
        );
        assert_eq!(got.diff_class, DiffClass::DocOnly);
        // Declared floor Local, but doc-only → the classifier says Trivial; escalate keeps Local
        // (escalate-only never lowers below the declared floor).
        assert_eq!(got.classified_tier, RiskTier::Trivial);
        assert_eq!(got.tier, RiskTier::Local);
    }

    #[test]
    fn true_doc_only_with_trivial_floor_stays_trivial() {
        let orig = vec![f("a.rs", "fn add(a: i32, b: i32) -> i32 {\n    a + b\n}\n")];
        let app = vec![f(
            "a.rs",
            "fn add(a: i32, b: i32) -> i32 {\n    a + b // sum\n}\n",
        )];
        let got = classify_edit(
            &orig,
            &app,
            Language::Rust,
            RiskTier::Trivial,
            Rung::Ast,
            false,
        );
        assert_eq!(got.tier, RiskTier::Trivial);
        assert!(got.trivial_auto_approve_eligible);
    }

    #[test]
    fn a_change_inside_a_string_is_never_doc_only() {
        // The ONLY textual change is inside a string literal that also contains `//` — a naive
        // comment-stripper would call this doc-only. The string-aware signature must not.
        let orig = vec![f(
            "a.rs",
            "fn u() -> &'static str {\n    \"http://a\" // note\n}\n",
        )];
        let app = vec![f(
            "a.rs",
            "fn u() -> &'static str {\n    \"http://b\" // note\n}\n",
        )];
        let got = classify_edit(
            &orig,
            &app,
            Language::Rust,
            RiskTier::Local,
            Rung::Ast,
            false,
        );
        assert_ne!(got.diff_class, DiffClass::DocOnly);
    }

    #[test]
    fn signature_change_is_moderate() {
        let orig = vec![f("a.rs", "fn add(a: i32) -> i32 {\n    a\n}\n")];
        let app = vec![f("a.rs", "fn add(a: i32, b: i32) -> i32 {\n    a + b\n}\n")];
        let got = classify_edit(
            &orig,
            &app,
            Language::Rust,
            RiskTier::Local,
            Rung::Ast,
            false,
        );
        assert_eq!(got.diff_class, DiffClass::SignatureApi);
        assert_eq!(got.tier, RiskTier::Moderate);
    }

    #[test]
    fn new_dependency_is_moderate() {
        let orig = vec![f("a.rs", "fn g() -> i32 {\n    1\n}\n")];
        let app = vec![f("a.rs", "use std::fs;\nfn g() -> i32 {\n    1\n}\n")];
        let got = classify_edit(
            &orig,
            &app,
            Language::Rust,
            RiskTier::Local,
            Rung::Ast,
            false,
        );
        assert_eq!(got.diff_class, DiffClass::NewDependency);
        assert_eq!(got.tier, RiskTier::Moderate);
    }

    #[test]
    fn under_declared_settlement_edit_is_forced_to_tier3() {
        // The caller lies and says Local; the path is on the settlement critical path.
        let orig = vec![f("settlement/post.rs", "fn post() -> i32 {\n    1\n}\n")];
        let app = vec![f("settlement/post.rs", "fn post() -> i32 {\n    2\n}\n")];
        let got = classify_edit(
            &orig,
            &app,
            Language::Rust,
            RiskTier::Local,
            Rung::Ast,
            false,
        );
        assert!(got.critical_path);
        assert_eq!(got.classified_tier, RiskTier::HighRisk);
        assert_eq!(got.tier, RiskTier::HighRisk);
        assert!(got.tier.forces_hitl());
    }

    #[test]
    fn declared_floor_never_lowered() {
        // A trivial doc edit declared HighRisk stays HighRisk — escalate never de-escalates.
        let orig = vec![f("a.rs", "fn g() {}\n")];
        let app = vec![f("a.rs", "// doc\nfn g() {}\n")];
        let got = classify_edit(
            &orig,
            &app,
            Language::Rust,
            RiskTier::HighRisk,
            Rung::Ast,
            false,
        );
        assert_eq!(got.classified_tier, RiskTier::Trivial);
        assert_eq!(got.tier, RiskTier::HighRisk);
    }

    #[test]
    fn multi_file_edit_is_at_least_moderate() {
        let orig = vec![f("a.rs", "fn a() {}\n"), f("b.rs", "fn b() {}\n")];
        let app = vec![
            f("a.rs", "fn a() { let _ = 1; }\n"),
            f("b.rs", "fn b() { let _ = 2; }\n"),
        ];
        let got = classify_edit(
            &orig,
            &app,
            Language::Rust,
            RiskTier::Local,
            Rung::Ast,
            false,
        );
        assert_eq!(got.files_touched, 2);
        assert_eq!(got.tier, RiskTier::Moderate);
    }

    #[test]
    fn text_patch_rung_bumps_local_to_moderate() {
        let orig = vec![f("a.rs", "fn g() -> i32 {\n    1\n}\n")];
        let app = vec![f("a.rs", "fn g() -> i32 {\n    2\n}\n")];
        let got = classify_edit(
            &orig,
            &app,
            Language::Rust,
            RiskTier::Local,
            Rung::TextPatch,
            false,
        );
        // A raw text-patch (lowest fidelity) is scrutinized harder.
        assert_eq!(got.tier, RiskTier::Moderate);
    }

    #[test]
    fn unchanged_file_contributes_no_signal() {
        let orig = vec![f("a.rs", "fn g() {}\n")];
        let app = vec![f("a.rs", "fn g() {}\n")];
        let got = classify_edit(
            &orig,
            &app,
            Language::Rust,
            RiskTier::Local,
            Rung::Ast,
            false,
        );
        assert_eq!(got.files_touched, 0);
        assert_eq!(got.diff_class, DiffClass::DocOnly);
    }

    #[test]
    fn python_signature_change_detected() {
        let orig = vec![f("a.py", "def add(a):\n    return a\n")];
        let app = vec![f("a.py", "def add(a, b):\n    return a + b\n")];
        let got = classify_edit(
            &orig,
            &app,
            Language::Python,
            RiskTier::Local,
            Rung::Ast,
            false,
        );
        assert_eq!(got.diff_class, DiffClass::SignatureApi);
    }
}
