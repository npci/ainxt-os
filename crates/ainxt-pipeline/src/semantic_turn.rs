// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! The **semantic-op edit turn** (`SEMANTIC_EDITING.md` §2/§4 + `CODE_REVIEW_PIPELINE.md` §1/§2) —
//! the composition that binds an *agent-expressed* semantic operation (rename a symbol,
//! change a signature, extract a function) to the typed pipeline outcome.
//!
//! The pieces existed but nothing composed them: `ainxt-semantic`'s cross-file ops
//! ([`plan_rename_symbol`]/[`apply_change_signature`]/[`plan_extract_function`]) produced a multi-file
//! [`FileEdit`] set, the [`ladder`](ainxt_semantic::ladder) declared which rung a language+op resolves
//! at, and [`run_edit_turn`] enforced the atomic verify+rollback commit gate — but there was no path
//! from "the agent asks to rename `charge`" through the ladder to a gated, atomically-applied commit.
//! This is that path:
//!
//! ```text
//! AgentOp (rename / change-signature / extract)
//!   → ladder rung selection (structural ops resolve at the AST rung; no-AST language ⇒ refuse, never
//!     silently text-patch a rename)
//!   → plan a multi-file FileEdit set via ainxt-semantic's AST-precise ops
//!   → run_edit_turn: self-heal pipeline gate  →  atomic apply (dry-run parse → commit-all-or-none →
//!     post-write re-verify → ROLLBACK on regression)
//!   → TurnOutcome::Committed  (a durable write, only through a CommitApproval)
//!      OR  HandedToHuman       (a failed verify never commits; the sink holds the pre-edit baseline)
//! ```
//!
//! The selected [`Rung`] flows into the pipeline's Confidence Score as the honest edit-fidelity
//! penalty, so a lower-rung apply is never scored as if it were an LSP/AST transform.

use crate::edit_turn::{run_edit_turn_full_guarded, EditTurn, TurnOutcome};
use crate::journal::Journal;
use crate::ladder_driver::{run_replace_ladder, WiredReplace};
use crate::sast::SastScanner;
use crate::selfheal::{Coder, ReviewSeams, SelfHealConfig};
use crate::stages::StageTools;
use ainxt_edit::Edit;
use ainxt_semantic::graph::SourceFile;
use ainxt_semantic::ladder::{
    CodeLanguage, LspEditTarget, LspOutcome, LspRefactor, Rung, SemanticOp,
};
use ainxt_semantic::ops::{
    apply_change_signature, plan_extract_function, plan_inline_function, plan_move_definition,
    plan_rename_symbol, AddParamSpec, OpError,
};
use ainxt_semantic::workspace::{FileEdit, WorkspaceSink};
use ainxt_semantic::Language as AstLang;

/// A semantic operation the agent expressed, at the granularity the AST rung can plan deterministically.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum AgentOp {
    /// Rename symbol `old` to `new` across every file that references it.
    Rename { old: String, new: String },
    /// Add a trailing parameter to `name`'s signature and the adapter argument at every call site.
    ChangeSignature { name: String, spec: AddParamSpec },
    /// Extract lines `[start_line, end_line]` (1-based, inclusive) from `enclosing` in `file` into a
    /// new zero-arg function `new_name`, replacing them with a call.
    Extract {
        file: String,
        enclosing: String,
        start_line: usize,
        end_line: usize,
        new_name: String,
    },
    /// GAP-FIX semantic-editing-codereview — inline `name`'s single-expression body into every call
    /// site and delete its definition (the ladder's `InlineFunction` op; [`plan_inline_function`] was
    /// fully implemented and unit-tested but had zero callers outside its own crate's tests).
    Inline { name: String },
    /// GAP-FIX semantic-editing-codereview — move `name`'s definition from `from_file` to `to_file`,
    /// leaving call sites intact (the ladder's `MoveDefinition` op; [`plan_move_definition`] had the
    /// same zero-caller gap as [`AgentOp::Inline`]).
    Move {
        name: String,
        from_file: String,
        to_file: String,
    },
    /// GAP-FIX gap6-pipeline-edit-tooling item 3 — replace `function_name`'s body in `file` with
    /// `new_def`, resolved through the **full wired edit ladder**
    /// ([`crate::ladder_driver::run_replace_ladder`]): AST transform
    /// ([`ainxt_semantic::replace_function`]) first, falling to a structured anchored patch
    /// ([`ainxt_edit::apply`], via `anchored_edits`) and then a literal text find/replace
    /// (`text_find`/`text_replace`) if the AST rung cannot resolve `function_name` or `new_def` does
    /// not parse. This is the genuinely different, smaller-blast-radius sibling of an unplanned
    /// full-file regeneration ([`crate::edit_turn::run_turn_for`]'s plain [`EditTurn`] path): an agent
    /// proposing "replace this one function" never has to regenerate (and risk corrupting) the whole
    /// file. `anchored_edits`/`text_find`/`text_replace` are optional (`#[serde(default)]`) — a caller
    /// that only has the AST-level material may omit them, in which case the ladder simply has fewer
    /// rungs to fall to.
    ReplaceFunction {
        file: String,
        function_name: String,
        new_def: String,
        #[serde(default)]
        anchored_edits: Vec<Edit>,
        #[serde(default)]
        text_find: String,
        #[serde(default)]
        text_replace: String,
    },
}

impl AgentOp {
    /// The ladder's operation class for this agent op.
    #[must_use]
    pub fn semantic_op(&self) -> SemanticOp {
        match self {
            AgentOp::Rename { .. } => SemanticOp::RenameSymbol,
            AgentOp::ChangeSignature { .. } => SemanticOp::ChangeSignature,
            AgentOp::Extract { .. } => SemanticOp::ExtractFunction,
            AgentOp::Inline { .. } => SemanticOp::InlineFunction,
            AgentOp::Move { .. } => SemanticOp::MoveDefinition,
            AgentOp::ReplaceFunction { .. } => SemanticOp::ReplaceFunction,
        }
    }

    /// The symbol/position material an LSP driver's `apply()` needs for `path`, derived from this op
    /// (`gap3-semantic-editing` item 1: the trait's `(lang, op, source)` signature carried none of
    /// this, so [`ainxt_semantic::lsp::ServerLspRefactor`] had to bake a single hardcoded rename in at
    /// construction — see [`LspEditTarget`]'s docs). Only `Rename` populates `symbol`/`new_name` today;
    /// the driver wires only `RenameSymbol` and reports every other op `Unavailable` regardless.
    #[must_use]
    pub fn lsp_target(&self, path: &str) -> LspEditTarget {
        match self {
            AgentOp::Rename { old, new } => LspEditTarget::rename(path, old.clone(), new.clone()),
            AgentOp::ChangeSignature { .. }
            | AgentOp::Extract { .. }
            | AgentOp::Inline { .. }
            | AgentOp::Move { .. }
            | AgentOp::ReplaceFunction { .. } => LspEditTarget {
                uri: path.to_string(),
                symbol: None,
                new_name: None,
            },
        }
    }
}

/// One semantic-op turn: the pre-edit file set the op is planned against, the op, and the
/// self-heal/risk configuration for the pipeline pass.
#[derive(Debug, Clone)]
pub struct SemanticTurn {
    pub edit_id: String,
    /// The working tree the op reads + rewrites (AST-parseable sources).
    pub files: Vec<SourceFile>,
    pub op: AgentOp,
    pub config: SelfHealConfig,
}

/// Why a semantic op could not be planned into an edit turn (planning fails *before* any write; the
/// sink is never touched on a `PlanError`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanError {
    /// The AST-rung planner rejected the op (invalid identifier, name collision, symbol not found …).
    Plan(OpError),
    /// A file the op references is absent from the turn's file set.
    FileNotFound(String),
    /// GAP-FIX gap6-pipeline-edit-tooling item 4 — [`AgentOp::Rename`]'s fallback to
    /// [`ainxt_edit::field_rename_via_xref`] (taken when `old` is not a function/type-level symbol the
    /// AST symbol graph tracks — see [`ainxt_semantic::graph::DefKind`], which has no `Field` variant)
    /// was itself refused: `old` does not occur in the file at all, or `new` would collide with an
    /// existing identifier.
    FieldRenameRefused(String),
    /// GAP-FIX gap6-pipeline-edit-tooling item 3 — [`AgentOp::ReplaceFunction`]'s wired ladder
    /// ([`run_replace_ladder`]) exhausted every capable rung (AST / structured patch / text) without
    /// resolving. Carries the fall reason from every attempted rung — the exact, un-paraphrased trail,
    /// never a generic "failed".
    LadderExhausted(String),
}

impl std::fmt::Display for PlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PlanError::Plan(e) => write!(f, "plan rejected: {e}"),
            PlanError::FileNotFound(p) => write!(f, "file not in turn set: {p}"),
            PlanError::FieldRenameRefused(detail) => {
                write!(f, "field-rename fallback refused: {detail}")
            }
            PlanError::LadderExhausted(detail) => {
                write!(f, "replace-function ladder exhausted every rung: {detail}")
            }
        }
    }
}

impl std::error::Error for PlanError {}

/// The result of a planned + gated semantic-op turn.
#[derive(Debug, Clone)]
pub struct SemanticTurnOutcome {
    /// The ladder rung the op resolved at (the edit-fidelity the Confidence Score was penalized by).
    pub rung: Rung,
    /// The multi-file edit set the op planned (before the gate ran).
    pub plan: Vec<FileEdit>,
    /// The gated commit outcome. `Committed` iff the whole pipeline + atomic verify cleared.
    pub turn: TurnOutcome,
}

impl SemanticTurnOutcome {
    #[must_use]
    pub fn committed(&self) -> bool {
        self.turn.committed()
    }
}

fn code_lang(l: AstLang) -> CodeLanguage {
    match l {
        AstLang::Rust => CodeLanguage::Rust,
        AstLang::Python => CodeLanguage::Python,
        AstLang::Go => CodeLanguage::Go,
        AstLang::JavaScript => CodeLanguage::JavaScript,
        AstLang::TypeScript => CodeLanguage::TypeScript,
        AstLang::Java => CodeLanguage::Java,
    }
}

/// The source file that determines the op's primary language: the extract target file, or the first
/// file of the set for cross-file ops.
fn primary_source<'a>(files: &'a [SourceFile], op: &AgentOp) -> Result<&'a SourceFile, PlanError> {
    match op {
        AgentOp::Extract { file, .. } => files
            .iter()
            .find(|f| &f.path == file)
            .ok_or_else(|| PlanError::FileNotFound(file.clone())),
        AgentOp::Move { from_file, .. } => files
            .iter()
            .find(|f| &f.path == from_file)
            .ok_or_else(|| PlanError::FileNotFound(from_file.clone())),
        AgentOp::ReplaceFunction { file, .. } => files
            .iter()
            .find(|f| &f.path == file)
            .ok_or_else(|| PlanError::FileNotFound(file.clone())),
        _ => files
            .first()
            .ok_or_else(|| PlanError::FileNotFound("<empty file set>".to_string())),
    }
}

/// GAP-FIX gap6-pipeline-edit-tooling item 4 — fall from the AST symbol-graph rename
/// ([`plan_rename_symbol`], which only resolves function/type-level definitions — struct/enum
/// **fields** are not modeled as [`ainxt_semantic::graph`] nodes at all, so a field rename can never
/// hit anything but [`OpError::SymbolNotFound`] on that path) to `ainxt-edit`'s field-rename
/// primitives. [`ainxt_edit::field_rename_via_xref`] rewrites **every** whole-word occurrence of `old`
/// in the file — never a declaration-only edit that would leave a call site referencing a field that no
/// longer exists. That is precisely the historical bug `ainxt-edit`'s module doc encodes as an
/// invariant (the same "a structural field change only touches the declaration, every usage goes
/// stale" class this repo's own SDLC pipeline hit — see `sdlc_patch_engine.py`'s `_apply_patch`
/// `changed_fields` bug in `CLAUDE.md`), and `SEMANTIC_EDITING.md` §4 explicitly prefers rewriting over
/// blocking here. Single-file scoped (unlike [`plan_rename_symbol`]'s cross-file rewrite above) —
/// `ainxt-edit`'s field-rename primitives operate on one file's source. Recorded honestly at
/// [`Rung::StructuredPatch`], never [`Rung::Ast`]: this is a whole-word **text** rewrite, not a real
/// tree-sitter transform, so it never claims AST-grade fidelity it did not compute.
///
/// [`ainxt_edit::field_rename_is_safe`] — the narrower, more conservative guard that reports "unsafe"
/// (refuses) whenever `old` has any usage beyond a lone declaration — is intentionally NOT also
/// consulted here: `ainxt-edit`'s own doc on `field_rename_via_xref` frames it as the crate's designed
/// upgrade over `field_rename_is_safe`'s guard ("performs the designed cross-reference rewrite *instead
/// of blocking*"), and `field_rename_via_xref` already performs its own collision/not-found checks. A
/// caller wanting the stricter "refuse unless the field has no other usage at all" policy can call
/// [`ainxt_edit::field_rename_is_safe`] directly; it remains fully implemented and independently
/// tested, it simply is not the policy this dispatch path chooses.
fn field_rename_fallback(
    primary: &SourceFile,
    old: &str,
    new: &str,
) -> Result<FileEdit, PlanError> {
    ainxt_edit::field_rename_via_xref(&primary.source, old, new)
        .map(|r| FileEdit {
            path: primary.path.clone(),
            new_content: r.content,
            base_version: 0,
        })
        .map_err(|e| PlanError::FieldRenameRefused(e.to_string()))
}

/// Plan `turn.op` through the ladder and drive it through the full edit-turn gate.
///
/// A durable write to `sink` is reachable **only** through a `TurnOutcome::Committed`, itself reachable
/// **only** through a `CommitApproval` from a pipeline `Complete`. A failed verify — a deterministic
/// stage failure the coder cannot heal, **or** a post-write atomic-apply regression — never commits:
/// the atomic protocol rolls the sink back to the pre-edit baseline and the turn is `HandedToHuman`.
///
/// # Errors
/// [`PlanError`] if the op cannot be planned (no AST rung / planner rejection / missing file). On a
/// `PlanError` nothing is written; the sink is untouched.
pub fn run_semantic_turn(
    turn: SemanticTurn,
    coder: &dyn Coder,
    tools: &dyn StageTools,
    scanner: &dyn SastScanner,
    sink: &mut dyn WorkspaceSink,
    journal: &mut Journal,
) -> Result<SemanticTurnOutcome, PlanError> {
    run_semantic_turn_with_lsp(turn, None, coder, tools, scanner, sink, journal)
}

/// [`run_semantic_turn_with_lsp`] plus the **independent Judge panel (§5)** seam. A structural op that
/// classifies to Tier 2+ (a cross-file rename / change-signature is a signature/API change) requires a
/// context-isolated independent panel verdict to commit, exactly like any other Tier-2+ edit — the
/// Commit Gate does not exempt a toolchain-planned edit from the mandatory-Judge rule. Pass the
/// deployment's reviewer + panel via `review`; the durable-write invariant is unchanged.
#[allow(clippy::too_many_arguments)]
pub fn run_semantic_turn_full(
    turn: SemanticTurn,
    lsp: Option<&dyn LspRefactor>,
    review: Option<&ReviewSeams>,
    coder: &dyn Coder,
    tools: &dyn StageTools,
    scanner: &dyn SastScanner,
    sink: &mut dyn WorkspaceSink,
    journal: &mut Journal,
) -> Result<SemanticTurnOutcome, PlanError> {
    run_semantic_turn_inner(turn, lsp, review, coder, tools, scanner, sink, journal)
}

/// Plan `turn.op` through the ladder — driving the **rung-1 LSP refactor first when a driver is
/// present** (`SEMANTIC_EDITING.md` §2, the design's highest-fidelity rung) — and gate the result.
///
/// When `lsp` is `Some` and the op is structural, the language server is consulted for every file the
/// AST plan would touch. If it computes a refactor for **all** of them (`Applied`), that toolchain-
/// grade result is adopted and the turn records [`Rung::Lsp`] (zero Confidence-Score penalty). If the
/// server is unavailable / declines any file, the ladder falls *down* to the AST rung exactly as
/// [`run_semantic_turn`] does — recorded, never silent. The real language server is **infra**; offline,
/// pass an [`ainxt_semantic::ladder::ScriptedLspRefactor`].
#[allow(clippy::too_many_arguments)]
pub fn run_semantic_turn_with_lsp(
    turn: SemanticTurn,
    lsp: Option<&dyn LspRefactor>,
    coder: &dyn Coder,
    tools: &dyn StageTools,
    scanner: &dyn SastScanner,
    sink: &mut dyn WorkspaceSink,
    journal: &mut Journal,
) -> Result<SemanticTurnOutcome, PlanError> {
    run_semantic_turn_inner(turn, lsp, None, coder, tools, scanner, sink, journal)
}

#[allow(clippy::too_many_arguments)]
fn run_semantic_turn_inner(
    turn: SemanticTurn,
    lsp: Option<&dyn LspRefactor>,
    review: Option<&ReviewSeams>,
    coder: &dyn Coder,
    tools: &dyn StageTools,
    scanner: &dyn SastScanner,
    sink: &mut dyn WorkspaceSink,
    journal: &mut Journal,
) -> Result<SemanticTurnOutcome, PlanError> {
    // 1. Language + op class → ladder rung selection. We consult the ladder's capability matrix to
    //    record the rung the op resolves at (it feeds the Confidence Score's edit-fidelity penalty).
    //    Structural ops are planned by ainxt-semantic's AST-precise ops; the LSP rung is a seam we do
    //    not drive here. A rename/extract is never silently text-patched (that would rewrite string /
    //    comment occurrences and corrupt the repo) — the refusal is structural: the op's input is an
    //    AST-parseable `SourceFile` (Rust|Python), so a non-AST language cannot even be expressed, and
    //    the AST rung is therefore always present in the matrix for these ops.
    let primary = primary_source(&turn.files, &turn.op)?;
    let primary_lang = code_lang(primary.lang);
    let sop = turn.op.semantic_op();
    debug_assert!(
        primary_lang.capable_rungs(sop).contains(&Rung::Ast),
        "AST rung must be capable for a structural op over an AST-parseable SourceFile"
    );
    // GAP-FIX gap6-pipeline-edit-tooling item 4 — `mut`: the `AgentOp::Rename` field-rename fallback
    // below resolves at `Rung::StructuredPatch` (a text-level xref rewrite), never a fabricated `Ast`.
    // Every other arm still plans a genuine AST-precise transform, so `rung` stays `Ast` for them.
    let mut rung = Rung::Ast;

    // 2. Plan the multi-file edit set via the AST rung. Fresh turn ⇒ every file is at baseline v0.
    let version_of = |_p: &str| 0u64;
    let plan: Vec<FileEdit> = match &turn.op {
        AgentOp::Rename { old, new } => match plan_rename_symbol(&turn.files, old, new, version_of)
        {
            Ok(edits) => edits,
            // GAP-FIX gap6-pipeline-edit-tooling item 4 — `old` is not a function/type-level symbol
            // the AST graph tracks (most commonly: it is a struct/enum FIELD, which
            // `ainxt_semantic::graph::DefKind` does not model at all). Fall to the field-rename
            // primitives `ainxt-edit` carries for exactly this case, rather than refusing outright.
            Err(OpError::SymbolNotFound(_)) => {
                rung = Rung::StructuredPatch;
                vec![field_rename_fallback(primary, old, new)?]
            }
            Err(e) => return Err(PlanError::Plan(e)),
        },
        AgentOp::ChangeSignature { name, spec } => {
            apply_change_signature(&turn.files, name, spec, version_of).map_err(PlanError::Plan)?
        }
        AgentOp::Extract {
            file,
            enclosing,
            start_line,
            end_line,
            new_name,
        } => {
            let f = turn
                .files
                .iter()
                .find(|f| &f.path == file)
                .ok_or_else(|| PlanError::FileNotFound(file.clone()))?;
            vec![
                plan_extract_function(f, enclosing, *start_line, *end_line, new_name, 0)
                    .map_err(PlanError::Plan)?,
            ]
        }
        AgentOp::Inline { name } => {
            plan_inline_function(&turn.files, name, version_of).map_err(PlanError::Plan)?
        }
        AgentOp::Move {
            name,
            from_file,
            to_file,
        } => plan_move_definition(&turn.files, name, from_file, to_file, version_of)
            .map_err(PlanError::Plan)?,
        // GAP-FIX gap6-pipeline-edit-tooling item 3 — drive the FULL wired ladder
        // (`ladder_driver::run_replace_ladder`): AST `replace_function` → structured anchored patch
        // (`ainxt_edit::apply`) → literal text replace. The LSP rung is never capable for
        // `ReplaceFunction` (`CodeLanguage::capable_rungs`), so `lsp` is not threaded through here —
        // step 2b below (which DOES consult it for the other, structural ops) is skipped for this arm.
        AgentOp::ReplaceFunction {
            file,
            function_name,
            new_def,
            anchored_edits,
            text_find,
            text_replace,
        } => {
            let f = turn
                .files
                .iter()
                .find(|sf| &sf.path == file)
                .ok_or_else(|| PlanError::FileNotFound(file.clone()))?;
            let wired = WiredReplace {
                lang: code_lang(f.lang),
                source: f.source.clone(),
                function_name: function_name.clone(),
                new_def: new_def.clone(),
                anchored_edits: anchored_edits.clone(),
                text_find: text_find.clone(),
                text_replace: text_replace.clone(),
            };
            let trail = run_replace_ladder(&wired, None);
            match (trail.applied_rung, trail.result) {
                (Some(r), Some(new_source)) => {
                    rung = r;
                    vec![FileEdit {
                        path: file.clone(),
                        new_content: new_source,
                        base_version: 0,
                    }]
                }
                _ => {
                    let detail = trail
                        .attempts
                        .iter()
                        .map(|a| format!("{}: {}", a.rung.as_str(), a.reason))
                        .collect::<Vec<_>>()
                        .join("; ");
                    return Err(PlanError::LadderExhausted(detail));
                }
            }
        }
    };

    // 2b. Rung-1 LSP refactor, if a driver is present, for the *structural* ops planned above (never
    //     `ReplaceFunction`, whose ladder call above already consulted — and, per the capability
    //     matrix, never even offers — the LSP rung). Consult the language server for every file the
    //     plan would touch; adopt its toolchain-grade result ONLY if it computes a refactor for *all*
    //     of them (a partial LSP result is not mixed with AST edits — that would be a half-applied
    //     refactor). Otherwise fall *down* to the rung already selected above, recorded, never silent.
    let (plan, rung) = if matches!(turn.op, AgentOp::ReplaceFunction { .. }) {
        (plan, rung)
    } else {
        match lsp {
            Some(driver) => {
                let mut lsp_plan: Vec<FileEdit> = Vec::with_capacity(plan.len());
                let mut all_applied = true;
                for e in &plan {
                    let src = turn
                        .files
                        .iter()
                        .find(|f| f.path == e.path)
                        .map(|f| f.source.as_str())
                        .unwrap_or("");
                    let target = turn.op.lsp_target(&e.path);
                    match driver.apply(primary_lang, sop, src, &target) {
                        LspOutcome::Applied(edited) => lsp_plan.push(FileEdit {
                            path: e.path.clone(),
                            new_content: edited,
                            base_version: e.base_version,
                        }),
                        LspOutcome::Unavailable(_) | LspOutcome::Failed(_) => {
                            all_applied = false;
                            break;
                        }
                    }
                }
                if all_applied && !lsp_plan.is_empty() {
                    (lsp_plan, Rung::Lsp)
                } else {
                    (plan, rung)
                }
            }
            None => (plan, rung),
        }
    };

    // 3. Materialize the applied tree = the original set with the planned edits overlaid by path.
    let original_files: Vec<(String, String)> = turn
        .files
        .iter()
        .map(|f| (f.path.clone(), f.source.clone()))
        .collect();
    let mut applied_files = original_files.clone();
    for e in &plan {
        if let Some(slot) = applied_files.iter_mut().find(|(p, _)| p == &e.path) {
            slot.1 = e.new_content.clone();
        } else {
            applied_files.push((e.path.clone(), e.new_content.clone()));
        }
    }

    // 4. Gate it. The selected rung sets the honest confidence penalty for this turn's pass.
    let mut config = turn.config;
    config.rung = rung;
    let edit_turn = EditTurn {
        edit_id: turn.edit_id,
        original_files,
        applied_files,
        config,
    };
    // R15: a planned AST-precise structural op legitimately makes an old symbol name disappear (that
    // IS the rename/extract) — never treat it as the method-preservation guard's "silently dropped"
    // finding. `guard_methods = false`; the import-restore half of the guard still runs.
    let outcome = run_edit_turn_full_guarded(
        edit_turn, coder, tools, scanner, None, review, None, false, sink, journal,
    );

    Ok(SemanticTurnOutcome {
        rung,
        plan,
        turn: outcome,
    })
}
