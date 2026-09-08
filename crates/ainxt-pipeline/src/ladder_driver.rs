// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! The **wired edit ladder** (`docs/architecture/SEMANTIC_EDITING.md` §2) — the composition the
//! design calls for but nothing performed: [`ainxt_semantic::ladder::EditLadder`] took bare closures
//! and had no callers, so no code ever bound rung 2 = `ainxt-semantic` `replace_function`, rung 3 =
//! `ainxt-edit` `apply`, rung 4 = text. This module is where the pipeline "wires them together".
//!
//! It also runs the **add/replace-method guards on the semantic apply path** (§4): after a full-file
//! regeneration, [`ainxt_edit::restore_missing_imports`] re-injects dropped imports and a
//! method-preservation check (via [`ainxt_semantic::list_functions`]) reports any definition the model
//! silently dropped — the two guards the design requires as part of the atomic apply, previously
//! tested in isolation but never invoked from an apply path.

use ainxt_edit::{apply as structured_apply, restore_missing_imports, Edit, Language as EditLang};
use ainxt_semantic::ladder::{
    CodeLanguage, EditLadder, FallTrail, LspEditTarget, LspRefactor, SemanticOp,
};
use ainxt_semantic::{list_functions, replace_function, Language as AstLang};

/// A fully-specified edit carrying the material each rung needs, so the ladder can fall from the
/// AST rung to structured patching to text without the caller re-driving it.
#[derive(Debug, Clone)]
pub struct WiredReplace {
    pub lang: CodeLanguage,
    pub source: String,
    /// AST rung: the definition name to replace and its new text.
    pub function_name: String,
    pub new_def: String,
    /// Structured rung: anchored edits to apply if the AST rung is unavailable/fails.
    pub anchored_edits: Vec<Edit>,
    /// Text rung: a literal find/replace of last resort.
    pub text_find: String,
    pub text_replace: String,
}

/// Map the ladder's broad [`CodeLanguage`] to the AST engine's tight language, if parseable.
fn ast_lang(lang: CodeLanguage) -> Option<AstLang> {
    lang.ast_language()
}

/// Run the wired ladder for a **replace-function** operation: it tries LSP (seam) → AST
/// (`ainxt-semantic`) → structured patch (`ainxt-edit`) → text, recording the rung used and every
/// fall reason in the returned [`FallTrail`]. The AST rung is skipped for languages this crate cannot
/// parse (recorded, never silent), so a Go edit with no LSP driver falls straight to structured patch.
#[must_use]
pub fn run_replace_ladder(req: &WiredReplace, lsp: Option<&dyn LspRefactor>) -> FallTrail {
    let ladder = EditLadder::new(lsp);
    // `ReplaceFunction` never offers the LSP rung in the capability matrix (see
    // `CodeLanguage::capable_rungs`), so the target is never actually read here — an empty one is the
    // honest choice (there is no rename symbol/new-name for this op).
    let target = LspEditTarget::default();
    ladder.run(
        req.lang,
        SemanticOp::ReplaceFunction,
        &req.source,
        &target,
        // rung 2 — AST transform via ainxt-semantic.
        |src| match ast_lang(req.lang) {
            Some(al) => replace_function(src, al, &req.function_name, &req.new_def)
                .map_err(|e| format!("ast: {e}")),
            None => Err("ast: no tree-sitter grammar for language".to_string()),
        },
        // rung 3 — structured anchored patch via ainxt-edit.
        |src| {
            if req.anchored_edits.is_empty() {
                return Err("structured: no anchored edits supplied".to_string());
            }
            structured_apply(src, &req.anchored_edits)
                .map(|o| o.content)
                .map_err(|errs| {
                    format!(
                        "structured: {}",
                        errs.iter()
                            .map(|e| e.to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                })
        },
        // rung 4 — literal text replace, last resort.
        |src| {
            if req.text_find.is_empty() || !src.contains(&req.text_find) {
                Err("text: anchor not present".to_string())
            } else {
                Ok(src.replacen(&req.text_find, &req.text_replace, 1))
            }
        },
    )
}

/// Convert a [`CodeLanguage`] to the `ainxt-edit` language vocabulary for the import guard.
fn edit_lang(lang: CodeLanguage) -> EditLang {
    match lang {
        CodeLanguage::Rust => EditLang::Rust,
        CodeLanguage::Python => EditLang::Python,
        CodeLanguage::JavaScript => EditLang::JavaScript,
        CodeLanguage::TypeScript => EditLang::TypeScript,
        CodeLanguage::Go => EditLang::Go,
        CodeLanguage::Java => EditLang::Java,
        _ => EditLang::Other,
    }
}

/// The result of a guarded full-file regeneration apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardedApply {
    /// The generated content with any dropped imports re-injected.
    pub content: String,
    /// Imports that were present before and re-injected (the import-restore guard).
    pub restored_imports: Vec<String>,
    /// Definitions present in the original but absent from the regeneration — the method-preservation
    /// guard's finding (empty ⇒ no methods were silently dropped).
    pub dropped_methods: Vec<String>,
}

impl GuardedApply {
    /// Whether the regeneration silently dropped a method the original defined.
    #[must_use]
    pub fn dropped_any_method(&self) -> bool {
        !self.dropped_methods.is_empty()
    }
}

/// Run the **add/replace-method guards** on a full-file regeneration before it is committed
/// (`SEMANTIC_EDITING.md` §4): re-inject dropped imports, then check that no method the original
/// defined vanished. Both guards run together, which is what "run as part of the atomic apply" means.
///
/// `ast` is the AST language for the method-preservation check; `None` disables that guard (a
/// non-parseable language still gets import restore). The import guard uses the `ainxt-edit`
/// vocabulary derived from `lang`.
#[must_use]
pub fn guarded_full_file_apply(
    original: &str,
    generated: &str,
    lang: CodeLanguage,
    ast: Option<AstLang>,
) -> GuardedApply {
    // Guard 1: import restore.
    let restored = restore_missing_imports(original, generated, edit_lang(lang));

    // Guard 2: method preservation — compare defined function names before/after.
    let dropped_methods = match ast {
        Some(al) => {
            let before: Vec<String> = list_functions(original, al)
                .map(|v| v.into_iter().map(|(n, _)| n).collect())
                .unwrap_or_default();
            let after: std::collections::BTreeSet<String> = list_functions(&restored.content, al)
                .map(|v| v.into_iter().map(|(n, _)| n).collect())
                .unwrap_or_default();
            before
                .into_iter()
                .filter(|n| !after.contains(n))
                .collect::<Vec<_>>()
        }
        None => Vec::new(),
    };

    GuardedApply {
        content: restored.content,
        restored_imports: restored.restored,
        dropped_methods,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ainxt_semantic::ladder::Rung;

    const RUST_SRC: &str =
        "fn caller() -> i32 {\n    target()\n}\n\nfn target() -> i32 {\n    1\n}\n";

    fn base_req(lang: CodeLanguage) -> WiredReplace {
        WiredReplace {
            lang,
            source: RUST_SRC.to_string(),
            function_name: "target".into(),
            new_def: "fn target() -> i32 {\n    2\n}".into(),
            anchored_edits: vec![Edit::Replace {
                anchor: "    1\n".into(),
                replacement: "    2\n".into(),
            }],
            text_find: "1".into(),
            text_replace: "2".into(),
        }
    }

    #[test]
    fn gap_ainxt_pipeline_edit_02_rust_replace_uses_the_ast_rung() {
        // A parseable Rust replace resolves at the AST rung (highest fidelity, zero penalty).
        let trail = run_replace_ladder(&base_req(CodeLanguage::Rust), None);
        assert_eq!(trail.applied_rung, Some(Rung::Ast));
        assert_eq!(trail.confidence_penalty(), 0);
        let out = trail.result.unwrap();
        // Byte-precise: only `target`'s body changed.
        assert!(out.contains("fn target() -> i32 {\n    2\n}"));
        assert!(out.contains("fn caller() -> i32 {\n    target()\n}"));
    }

    #[test]
    fn gap_ainxt_pipeline_edit_02_falls_from_ast_to_structured_then_records_rung() {
        // A language with no tree-sitter grammar → AST rung is skipped, structured (ainxt-edit)
        // applies. (Round-11 gave Go a grammar, so COBOL is the honest grammar-less stand-in.)
        let mut req = base_req(CodeLanguage::Cobol);
        req.source = "MOVE 1 TO WS-TARGET.\n".into();
        req.anchored_edits = vec![Edit::Replace {
            anchor: "MOVE 1".into(),
            replacement: "MOVE 2".into(),
        }];
        let trail = run_replace_ladder(&req, None);
        assert_eq!(trail.applied_rung, Some(Rung::StructuredPatch));
        assert!(trail.result.as_deref().unwrap().contains("MOVE 2"));
        // Honest degradation: COBOL has no tree-sitter grammar, so the AST rung is not even in the
        // plan — the ladder falls to the structured (ainxt-edit) rung with its trust penalty recorded.
        assert!(!CodeLanguage::Cobol
            .capable_rungs(SemanticOp::ReplaceFunction)
            .contains(&Rung::Ast));
        assert_eq!(
            trail.confidence_penalty(),
            Rung::StructuredPatch.confidence_penalty()
        );
    }

    #[test]
    fn gap_ainxt_pipeline_edit_02_go_replace_now_uses_the_ast_rung() {
        // Round-11: a Go replace-function resolves at the AST rung (grammar now bound), zero penalty.
        let mut req = base_req(CodeLanguage::Go);
        req.source =
            "func caller() int {\n    return target()\n}\n\nfunc target() int {\n    return 1\n}\n"
                .into();
        req.function_name = "target".into();
        req.new_def = "func target() int {\n    return 2\n}".into();
        let trail = run_replace_ladder(&req, None);
        assert_eq!(trail.applied_rung, Some(Rung::Ast));
        assert_eq!(trail.confidence_penalty(), 0);
        let out = trail.result.unwrap();
        assert!(out.contains("func target() int {\n    return 2\n}"));
        assert!(out.contains("func caller() int {\n    return target()\n}"));
    }

    #[test]
    fn ast_failure_falls_to_structured_patch() {
        // AST rung fails because the new_def does not parse; structured patch then applies.
        let mut req = base_req(CodeLanguage::Rust);
        req.new_def = "fn target( { not valid".into();
        let trail = run_replace_ladder(&req, None);
        assert_eq!(trail.applied_rung, Some(Rung::StructuredPatch));
        assert!(trail
            .attempts
            .iter()
            .any(|a| a.rung == Rung::Ast && !a.succeeded));
    }

    #[test]
    fn all_rungs_exhaust_when_nothing_applies() {
        let mut req = base_req(CodeLanguage::Cobol); // no AST
        req.source = "MOVE 1 TO WS-X.\n".into();
        req.anchored_edits = vec![Edit::Replace {
            anchor: "NOT-PRESENT".into(),
            replacement: "x".into(),
        }];
        req.text_find = "ALSO-ABSENT".into();
        let trail = run_replace_ladder(&req, None);
        assert!(!trail.succeeded());
        assert_eq!(trail.applied_rung, None);
    }

    // ---- EDIT-10: guarded full-file apply (import restore + method preservation) ----

    #[test]
    fn gap_ainxt_pipeline_edit_10_guards_restore_imports_and_flag_dropped_methods() {
        let original = "use std::fmt;\nuse std::io::Read;\n\nfn keep() {}\nfn also_keep() {}\n";
        // The regeneration dropped an import (`std::io::Read`) AND a method (`also_keep`).
        let generated = "use std::fmt;\n\nfn keep() { /* changed */ }\n";
        let g =
            guarded_full_file_apply(original, generated, CodeLanguage::Rust, Some(AstLang::Rust));
        // Import guard re-injected the dropped import.
        assert_eq!(g.restored_imports, vec!["use std::io::Read;".to_string()]);
        assert!(g.content.contains("use std::io::Read;"));
        // Method-preservation guard caught the silently-dropped method.
        assert!(g.dropped_any_method());
        assert_eq!(g.dropped_methods, vec!["also_keep".to_string()]);
    }

    #[test]
    fn guarded_apply_is_a_noop_when_nothing_dropped() {
        let original = "use std::fmt;\nfn f() {}\n";
        let generated = "use std::fmt;\nfn f() { let x = 1; let _ = x; }\n";
        let g =
            guarded_full_file_apply(original, generated, CodeLanguage::Rust, Some(AstLang::Rust));
        assert!(g.restored_imports.is_empty());
        assert!(!g.dropped_any_method());
    }
}
