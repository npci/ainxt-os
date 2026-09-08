// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! The **edit ladder** (`docs/architecture/SEMANTIC_EDITING.md` §2): the engine expresses a semantic
//! operation and the ladder applies it at the *highest fidelity rung available*, falling **down** on
//! failure and recording *why* it fell.
//!
//! ```text
//! rung 1  LSP semantic refactor   (toolchain-guaranteed; a seam — needs a live language server)
//! rung 2  AST transform           (tree-sitter; this crate's `ops`/`replace_function`)
//! rung 3  structured patch        (anchored search/replace — the `ainxt-edit` engine)
//! rung 4  text patch              (last resort; non-code or when 1–3 cannot apply)
//! ```
//!
//! This module owns the *orchestration*, not the rung implementations: a [`CodeLanguage`] capability
//! matrix declares which rungs exist for a language, [`LspRefactor`] is the seam a real LSP driver
//! plugs into, and [`EditLadder::run`] tries capable rungs top-down, returning the rung that
//! succeeded plus a full [`FallTrail`] of every rung skipped/failed and the reason. Nothing is ever
//! applied silently at a lower rung: the rung used is always reported, so quality evals can track
//! per-language edit fidelity (§6). Determinism: no clocks/rng; capability + trail are pure data.

use crate::Language as AstLanguage;

/// The rungs of the edit ladder, highest fidelity first. `Ord` follows fidelity: `Lsp < Ast < ...`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Rung {
    /// Language-server refactor (rename/organize-imports/code-actions). Highest fidelity.
    Lsp,
    /// tree-sitter AST transform.
    Ast,
    /// Anchored structured search/replace.
    StructuredPatch,
    /// Raw text patch — last resort.
    TextPatch,
}

impl Rung {
    /// A trust penalty the Code-Review Pipeline's Confidence Score applies to lower rungs
    /// (`CODE_REVIEW_PIPELINE.md` §7 `edit_engine_rung_adjustment`): LSP/AST carry none.
    #[must_use]
    pub fn confidence_penalty(self) -> u8 {
        match self {
            Rung::Lsp | Rung::Ast => 0,
            Rung::StructuredPatch => 3,
            Rung::TextPatch => 8,
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Rung::Lsp => "lsp",
            Rung::Ast => "ast",
            Rung::StructuredPatch => "structured-patch",
            Rung::TextPatch => "text-patch",
        }
    }
}

/// The class of semantic operation being applied — determines which rungs are even applicable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SemanticOp {
    /// Rename a symbol across files.
    RenameSymbol,
    /// Change a function/method signature.
    ChangeSignature,
    /// Replace a whole function/method body.
    ReplaceFunction,
    /// Add a method/function.
    AddFunction,
    /// Extract a statement range into a new function, replacing it with a call.
    ExtractFunction,
    /// Inline a trivial function into its call sites and remove the definition.
    InlineFunction,
    /// Move a definition from one file to another.
    MoveDefinition,
    /// A plain anchored patch (no structural meaning).
    AnchorPatch,
}

/// A language the pipeline may edit, with its capability matrix. Broader than the AST engine's tight
/// `Rust | Python` enum — non-AST languages degrade honestly instead of pretending.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeLanguage {
    Rust,
    Python,
    JavaScript,
    TypeScript,
    Go,
    Java,
    Cobol,
    Other,
}

impl CodeLanguage {
    /// The AST-engine language, if this crate can parse it. `None` ⇒ the AST rung is unavailable and
    /// the ladder degrades to structured/text patching (recorded, never silent).
    #[must_use]
    pub fn ast_language(self) -> Option<AstLanguage> {
        match self {
            CodeLanguage::Rust => Some(AstLanguage::Rust),
            CodeLanguage::Python => Some(AstLanguage::Python),
            CodeLanguage::Go => Some(AstLanguage::Go),
            CodeLanguage::JavaScript => Some(AstLanguage::JavaScript),
            CodeLanguage::TypeScript => Some(AstLanguage::TypeScript),
            CodeLanguage::Java => Some(AstLanguage::Java),
            CodeLanguage::Cobol | CodeLanguage::Other => None,
        }
    }

    /// Whether a language server exists for this language in the deployment. This is a *declared
    /// capability*, not a live probe — the actual driver is the [`LspRefactor`] seam, which may still
    /// return unavailable at runtime (then the ladder falls to AST).
    #[must_use]
    pub fn has_lsp(self) -> bool {
        matches!(
            self,
            CodeLanguage::Rust
                | CodeLanguage::Python
                | CodeLanguage::TypeScript
                | CodeLanguage::Go
                | CodeLanguage::Java
        )
    }

    /// The rungs applicable to `op` on this language, highest fidelity first.
    #[must_use]
    pub fn capable_rungs(self, op: SemanticOp) -> Vec<Rung> {
        let mut rungs = Vec::new();
        // LSP is only meaningfully higher-fidelity for structural ops.
        let structural = matches!(
            op,
            SemanticOp::RenameSymbol
                | SemanticOp::ChangeSignature
                | SemanticOp::AddFunction
                | SemanticOp::ExtractFunction
                | SemanticOp::InlineFunction
                | SemanticOp::MoveDefinition
        );
        if self.has_lsp() && structural {
            rungs.push(Rung::Lsp);
        }
        // AST rung: available when we can parse, and the op is structural or a function replace.
        let ast_op = structural || op == SemanticOp::ReplaceFunction;
        if self.ast_language().is_some() && ast_op {
            rungs.push(Rung::Ast);
        }
        // Structured patch works for any op on any language.
        rungs.push(Rung::StructuredPatch);
        // Text patch is always the floor.
        rungs.push(Rung::TextPatch);
        rungs
    }
}

/// Why a language server refactor could not be produced. Returning `Unavailable` makes the ladder
/// fall to the AST rung; `Failed` records a real attempt that errored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LspOutcome {
    /// The LSP produced the edited source.
    Applied(String),
    /// No server is running / the op is unsupported → fall down without penalty of a "failure".
    Unavailable(String),
    /// The server was consulted but rejected the op.
    Failed(String),
}

/// The symbol/position material the LSP rung needs beyond `(lang, op, source)` — a real
/// `textDocument/rename` request is against a *document* at a *position*, not a bare source string.
/// Before this type existed, [`crate::lsp::ServerLspRefactor`] had to bake one hardcoded
/// [`crate::lsp::RenamePlan`] in at *construction* time, which meant a single driver instance could
/// only ever answer for the one rename it was built for — it could never serve as the general-purpose,
/// constructed-once seam [`EditLadder`] is designed around (`EditLadder::new` takes the driver once;
/// `EditLadder::run` is called per edit). `LspEditTarget` is threaded through `apply()` per call so one
/// driver instance can serve arbitrary rename requests (`SEMANTIC_EDITING.md` §2 gap-3 item 1).
///
/// All fields are honestly optional: an op that needs none of them (anything but `RenameSymbol` today)
/// simply ignores the target, and the offline [`ScriptedLspRefactor`] stand-in also ignores it (it
/// already keys answers on `(lang, op, source)`, which is sufficient for a scripted/offline reply).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LspEditTarget {
    /// The document identity the driver correlates `didOpen`/`rename`/`WorkspaceEdit` by. In a live
    /// deployment this is a `file://` URI; offline/in tests any caller-consistent string works, since
    /// the driver only ever compares it against itself within one round trip.
    pub uri: String,
    /// The symbol's current name — the rename's search anchor when no exact position is supplied.
    pub symbol: Option<String>,
    /// The symbol's new name (`RenameSymbol`).
    pub new_name: Option<String>,
}

impl LspEditTarget {
    /// Build a target for a `RenameSymbol` op.
    #[must_use]
    pub fn rename(
        uri: impl Into<String>,
        old_name: impl Into<String>,
        new_name: impl Into<String>,
    ) -> Self {
        LspEditTarget {
            uri: uri.into(),
            symbol: Some(old_name.into()),
            new_name: Some(new_name.into()),
        }
    }
}

/// The seam a real language-server driver implements. Left unimplemented offline; the ladder treats
/// a `None` driver as "LSP rung unavailable" and degrades to AST.
///
/// The **real** driver is infra: it needs a live language server process (rust-analyzer / gopls /
/// pyright / tsserver / jdtls), a warm workspace index, and JSON-RPC transport. Offline, a deployment
/// or test wires a [`ScriptedLspRefactor`], which answers only what it was explicitly given and
/// returns [`LspOutcome::Unavailable`] otherwise — so the ladder falls *down* to the AST rung and the
/// stand-in never manufactures a rung-1 "green" it did not actually compute.
pub trait LspRefactor {
    fn apply(
        &self,
        lang: CodeLanguage,
        op: SemanticOp,
        source: &str,
        target: &LspEditTarget,
    ) -> LspOutcome;
}

/// A deterministic, offline [`LspRefactor`] for air-gapped runs and tests. It is scripted with exact
/// `(lang, op, source) -> edited_source` answers; any unscripted query returns
/// [`LspOutcome::Unavailable`], so the ladder degrades honestly to the AST rung. This is the seam's
/// offline contract — it lets the highest-fidelity rung be exercised end-to-end without a live server,
/// while never letting a missing server masquerade as a completed refactor.
#[derive(Debug, Default, Clone)]
pub struct ScriptedLspRefactor {
    answers: Vec<(CodeLanguage, SemanticOp, String, String)>,
}

impl ScriptedLspRefactor {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Script the edited source a `(lang, op, source)` refactor should produce at rung 1.
    #[must_use]
    pub fn with_answer(
        mut self,
        lang: CodeLanguage,
        op: SemanticOp,
        source: impl Into<String>,
        edited: impl Into<String>,
    ) -> Self {
        self.answers.push((lang, op, source.into(), edited.into()));
        self
    }
}

impl LspRefactor for ScriptedLspRefactor {
    fn apply(
        &self,
        lang: CodeLanguage,
        op: SemanticOp,
        source: &str,
        _target: &LspEditTarget,
    ) -> LspOutcome {
        match self
            .answers
            .iter()
            .find(|(l, o, s, _)| *l == lang && *o == op && s == source)
        {
            Some((_, _, _, edited)) => LspOutcome::Applied(edited.clone()),
            None => LspOutcome::Unavailable(
                "no scripted LSP answer (offline stand-in) — falling to AST rung".to_string(),
            ),
        }
    }
}

/// One rung attempt in the fall-down trail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RungAttempt {
    pub rung: Rung,
    /// Human-readable reason this rung was skipped or failed (empty for the rung that succeeded).
    pub reason: String,
    pub succeeded: bool,
}

/// The full record of a ladder run: the rung that applied (if any) and every attempt/skip before it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FallTrail {
    pub op: SemanticOp,
    pub applied_rung: Option<Rung>,
    pub result: Option<String>,
    pub attempts: Vec<RungAttempt>,
}

impl FallTrail {
    #[must_use]
    pub fn succeeded(&self) -> bool {
        self.applied_rung.is_some()
    }
    /// The confidence penalty for the rung that actually applied (max penalty if nothing applied).
    #[must_use]
    pub fn confidence_penalty(&self) -> u8 {
        self.applied_rung
            .map(Rung::confidence_penalty)
            .unwrap_or(Rung::TextPatch.confidence_penalty())
    }
}

/// The ladder orchestrator. Holds an optional LSP driver seam; the AST/patch/text rungs are supplied
/// by the caller as closures so this crate stays free of the `ainxt-edit` dependency (the pipeline
/// wires them together).
pub struct EditLadder<'a> {
    lsp: Option<&'a dyn LspRefactor>,
}

/// The result of a single rung handler: `Ok(new_source)` applied, `Err(reason)` fell down.
pub type RungResult = Result<String, String>;

impl<'a> EditLadder<'a> {
    #[must_use]
    pub fn new(lsp: Option<&'a dyn LspRefactor>) -> Self {
        EditLadder { lsp }
    }

    /// Run `op` on `source` for `lang`, trying each capable rung highest-first and falling down on
    /// failure. `target` carries the symbol/position material the LSP rung needs (ignored by the
    /// other rungs). `ast`, `structured`, `text` are the handlers for those rungs (the LSP rung uses
    /// the driver seam). A handler returning `Err(reason)` records the fall and the next rung is tried.
    ///
    /// Deterministic: rung order is the capability matrix's, and the trail is pure data.
    #[allow(clippy::too_many_arguments)]
    pub fn run(
        &self,
        lang: CodeLanguage,
        op: SemanticOp,
        source: &str,
        target: &LspEditTarget,
        ast: impl FnOnce(&str) -> RungResult,
        structured: impl FnOnce(&str) -> RungResult,
        text: impl FnOnce(&str) -> RungResult,
    ) -> FallTrail {
        let mut attempts = Vec::new();
        let mut ast = Some(ast);
        let mut structured = Some(structured);
        let mut text = Some(text);

        for rung in lang.capable_rungs(op) {
            let outcome: RungResult = match rung {
                Rung::Lsp => match self.lsp {
                    Some(driver) => match driver.apply(lang, op, source, target) {
                        LspOutcome::Applied(s) => Ok(s),
                        LspOutcome::Unavailable(why) => Err(format!("lsp unavailable: {why}")),
                        LspOutcome::Failed(why) => Err(format!("lsp failed: {why}")),
                    },
                    None => Err("no lsp driver configured".to_string()),
                },
                Rung::Ast => match ast.take() {
                    Some(h) => h(source),
                    None => Err("ast handler already consumed".to_string()),
                },
                Rung::StructuredPatch => match structured.take() {
                    Some(h) => h(source),
                    None => Err("structured handler already consumed".to_string()),
                },
                Rung::TextPatch => match text.take() {
                    Some(h) => h(source),
                    None => Err("text handler already consumed".to_string()),
                },
            };
            match outcome {
                Ok(s) => {
                    attempts.push(RungAttempt {
                        rung,
                        reason: String::new(),
                        succeeded: true,
                    });
                    return FallTrail {
                        op,
                        applied_rung: Some(rung),
                        result: Some(s),
                        attempts,
                    };
                }
                Err(reason) => attempts.push(RungAttempt {
                    rung,
                    reason,
                    succeeded: false,
                }),
            }
        }

        FallTrail {
            op,
            applied_rung: None,
            result: None,
            attempts,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(s: &str) -> RungResult {
        Ok(s.to_string())
    }
    fn fail(_s: &str) -> RungResult {
        Err("cannot apply".to_string())
    }
    /// A placeholder target for tests that don't care about the LSP rung's symbol/position material
    /// (either no driver is configured, or the driver ignores it).
    fn tgt() -> LspEditTarget {
        LspEditTarget::rename("file:///t", "old", "new")
    }

    #[test]
    fn rust_rename_prefers_lsp_when_driver_present() {
        struct FakeLsp;
        impl LspRefactor for FakeLsp {
            fn apply(
                &self,
                _l: CodeLanguage,
                _o: SemanticOp,
                _s: &str,
                _t: &LspEditTarget,
            ) -> LspOutcome {
                LspOutcome::Applied("lsp-renamed".into())
            }
        }
        let lsp = FakeLsp;
        let ladder = EditLadder::new(Some(&lsp));
        let trail = ladder.run(
            CodeLanguage::Rust,
            SemanticOp::RenameSymbol,
            "src",
            &tgt(),
            ok,
            ok,
            ok,
        );
        assert_eq!(trail.applied_rung, Some(Rung::Lsp));
        assert_eq!(trail.result.as_deref(), Some("lsp-renamed"));
        assert_eq!(trail.confidence_penalty(), 0);
        // AST/patch handlers were never consumed (LSP won first).
        assert_eq!(trail.attempts.len(), 1);
    }

    #[test]
    fn falls_from_lsp_unavailable_to_ast() {
        struct DeadLsp;
        impl LspRefactor for DeadLsp {
            fn apply(
                &self,
                _l: CodeLanguage,
                _o: SemanticOp,
                _s: &str,
                _t: &LspEditTarget,
            ) -> LspOutcome {
                LspOutcome::Unavailable("server not running".into())
            }
        }
        let lsp = DeadLsp;
        let ladder = EditLadder::new(Some(&lsp));
        let trail = ladder.run(
            CodeLanguage::Rust,
            SemanticOp::RenameSymbol,
            "src",
            &tgt(),
            |_s| ok("ast-renamed"),
            ok,
            ok,
        );
        assert_eq!(trail.applied_rung, Some(Rung::Ast));
        assert_eq!(trail.result.as_deref(), Some("ast-renamed"));
        // The LSP attempt is recorded as a fall, with its reason.
        assert_eq!(trail.attempts[0].rung, Rung::Lsp);
        assert!(!trail.attempts[0].succeeded);
        assert!(trail.attempts[0].reason.contains("server not running"));
        assert_eq!(trail.attempts[1].rung, Rung::Ast);
        assert!(trail.attempts[1].succeeded);
    }

    #[test]
    fn no_lsp_driver_falls_to_ast_for_rust() {
        let ladder = EditLadder::new(None);
        let trail = ladder.run(
            CodeLanguage::Rust,
            SemanticOp::RenameSymbol,
            "src",
            &tgt(),
            |_s| ok("ast"),
            ok,
            ok,
        );
        assert_eq!(trail.applied_rung, Some(Rung::Ast));
        assert!(trail.attempts[0].reason.contains("no lsp driver"));
    }

    #[test]
    fn non_ast_language_skips_ast_rung_entirely() {
        // A language with no tree-sitter grammar bound in this crate → the AST rung is not even in the
        // plan. (Round-11 broadened AST coverage to Go/JS/TS/Java, so COBOL — which genuinely has no
        // grammar — is now the honest stand-in for "no AST rung".) COBOL also declares no LSP.
        let rungs = CodeLanguage::Cobol.capable_rungs(SemanticOp::RenameSymbol);
        assert!(!rungs.contains(&Rung::Ast));
        assert!(!rungs.contains(&Rung::Lsp));
        assert!(rungs.contains(&Rung::StructuredPatch));

        // With no LSP driver, a COBOL rename falls straight to structured patch.
        let ladder = EditLadder::new(None);
        let trail = ladder.run(
            CodeLanguage::Cobol,
            SemanticOp::RenameSymbol,
            "src",
            &tgt(),
            ok,
            |_s| ok("patched"),
            ok,
        );
        assert_eq!(trail.applied_rung, Some(Rung::StructuredPatch));
        assert_eq!(trail.confidence_penalty(), 3);
    }

    #[test]
    fn go_is_now_ast_capable_for_structural_ops() {
        // Round-11: Go binds a tree-sitter grammar, so a structural op resolves at the AST rung
        // (highest-fidelity available without a language server), not the structured-patch fallback.
        let rungs = CodeLanguage::Go.capable_rungs(SemanticOp::RenameSymbol);
        assert!(rungs.contains(&Rung::Ast));
        let ladder = EditLadder::new(None);
        let trail = ladder.run(
            CodeLanguage::Go,
            SemanticOp::RenameSymbol,
            "src",
            &tgt(),
            |_s| ok("ast-renamed"),
            |_s| ok("patched"),
            ok,
        );
        assert_eq!(trail.applied_rung, Some(Rung::Ast));
        assert_eq!(trail.confidence_penalty(), 0);
    }

    #[test]
    fn cobol_degrades_to_text_patch_with_penalty() {
        // COBOL: no LSP, no AST, no structured meaning we trust → text patch, max penalty.
        let rungs = CodeLanguage::Cobol.capable_rungs(SemanticOp::AnchorPatch);
        assert_eq!(rungs, vec![Rung::StructuredPatch, Rung::TextPatch]);
        let ladder = EditLadder::new(None);
        let trail = ladder.run(
            CodeLanguage::Cobol,
            SemanticOp::AnchorPatch,
            "src",
            &tgt(),
            ok,
            fail, // structured patch cannot apply
            |_s| ok("text-patched"),
        );
        assert_eq!(trail.applied_rung, Some(Rung::TextPatch));
        assert_eq!(trail.confidence_penalty(), 8);
    }

    #[test]
    fn all_rungs_failing_yields_no_application() {
        let ladder = EditLadder::new(None);
        let trail = ladder.run(
            CodeLanguage::Rust,
            SemanticOp::RenameSymbol,
            "src",
            &tgt(),
            fail,
            fail,
            fail,
        );
        assert!(!trail.succeeded());
        assert_eq!(trail.applied_rung, None);
        // Every capable rung was attempted and fell.
        assert!(trail.attempts.iter().all(|a| !a.succeeded));
        assert_eq!(trail.confidence_penalty(), 8);
    }

    #[test]
    fn lsp_edit_target_rename_constructor_sets_symbol_and_new_name() {
        // GAP3-1 proving test: the target carries the exact symbol/position material the old trait
        // signature omitted, so a driver's `apply()` can resolve an arbitrary rename per call instead
        // of one baked in at construction.
        let t = LspEditTarget::rename("file:///repo/a.rs", "charge", "settle");
        assert_eq!(t.uri, "file:///repo/a.rs");
        assert_eq!(t.symbol.as_deref(), Some("charge"));
        assert_eq!(t.new_name.as_deref(), Some("settle"));
    }
}
