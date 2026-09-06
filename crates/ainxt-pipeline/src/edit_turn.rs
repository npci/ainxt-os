// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! The **edit-turn gate** (`docs/architecture/CODE_REVIEW_PIPELINE.md` §1/§2) — the clean public
//! entrypoint that binds a code-editing turn to a typed [`PipelineOutcome`]. This is the composition
//! the gap flagged as missing: `run_pipeline`/`PipelineOutcome`/`commit_approval` had no callers
//! outside this crate, so nothing bound a code-edit turn to a `Complete`. The invariant lived only in
//! the type system (the [`CommitApproval`] seal); here it becomes an executable pipeline.
//!
//! Contract for the reserved renderer/surface/runtime (which must NOT reimplement any of this):
//! call [`run_edit_turn`] with the applied edit set. The durable write to the [`WorkspaceSink`] is
//! reachable **only** through a [`CommitApproval`], which is obtainable **only** from a `Complete`
//! outcome. `Capped`/`Blocked` return [`TurnOutcome::HandedToHuman`] and the sink is never touched —
//! there is no code path to a "done" affordance for an edit turn without a real `Complete`.
//!
//! The pipeline fires on **every** write the edit engine would commit (§2): the applied edit set is
//! staged, verified through the full self-heal pipeline, and persisted only if the gate clears.

use crate::journal::Journal;
use crate::ladder_driver::guarded_full_file_apply;
use crate::outcome::{CommitApproval, PipelineOutcome};
use crate::perf::{BenchmarkHarness, PerfAdvisor, PerfBudget, PerfConfig};
use crate::review::SemanticGateConfig;
use crate::sast::SastScanner;
use crate::selfheal::{
    run_selfheal_reclassified, Coder, PerfSeams, ReclassifySeams, ReviewSeams, SelfHealConfig,
    SemanticGateSeams,
};
use crate::semantic_turn::{run_semantic_turn_full, AgentOp, SemanticTurn};
use crate::stage::Stage;
use crate::stages::StageTools;
use crate::wire_seal::{seal_wire_config, DeploymentEditPolicy, WireSealReport};
use ainxt_judge::{JudgeCriteria, JudgePanel, Reviewer};
use ainxt_semantic::arch::LayerContract;
use ainxt_semantic::graph::SourceFile;
use ainxt_semantic::ladder::{CodeLanguage, LspRefactor, Rung};
use ainxt_semantic::ops::lang_from_path;
use ainxt_semantic::regression::CochangeGraph;
use ainxt_semantic::workspace::{FileEdit, Workspace, WorkspaceSink};
use ainxt_types::Principal;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;

/// One code-editing turn: the pre-edit tree and the edit engine's applied edit set (post-edit
/// contents), plus the self-heal/risk configuration for the pipeline pass.
#[derive(Debug, Clone)]
pub struct EditTurn {
    pub edit_id: String,
    /// The working tree before the edit (seeds the staging workspace + the sink baseline).
    pub original_files: Vec<(String, String)>,
    /// The edit engine's applied edit set (what would be written) — the pipeline verifies THIS.
    pub applied_files: Vec<(String, String)>,
    pub config: SelfHealConfig,
}

/// The result of an edit turn. `Committed` is the *only* variant that ever wrote to the sink, and it
/// can only be constructed from a [`CommitApproval`].
#[derive(Debug, Clone)]
pub enum TurnOutcome {
    /// The gate cleared, the healed edit set was committed to the sink, and a commit affordance issued.
    Committed {
        approval: CommitApproval,
        /// The committed paths with their new versions.
        versions: BTreeMap<String, u64>,
        rounds: u8,
    },
    /// The gate did not clear (Capped/Blocked) — an honest human hand-off; the sink is untouched.
    HandedToHuman {
        outcome: PipelineOutcome,
        rounds: u8,
    },
}

/// The **renderer-facing "done" affordance** (`CODE_REVIEW_PIPELINE.md` §1) — the anti-sycophancy
/// invariant carried one level up, from the pipeline commit gate to the surface/renderer.
///
/// A renderer may display a "done"/commit message for an edit turn **only** by holding one of these.
/// It has no public constructor; [`TurnOutcome::commit_receipt`] returns `Some` **iff** the turn is
/// [`TurnOutcome::Committed`]. So a `HandedToHuman` turn (`Capped`/`Blocked`) has no code path to a
/// rendered "done" — a boolean `committed()` a renderer could ignore is not the whole story; the sealed
/// receipt is the *only* token that unlocks the done view, and it exists only for a real commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitReceipt {
    approval: CommitApproval,
    versions: BTreeMap<String, u64>,
    rounds: u8,
    seal: (),
}

impl CommitReceipt {
    /// The Confidence Score the commit gate cleared with.
    #[must_use]
    pub fn confidence(&self) -> u8 {
        self.approval.confidence()
    }
    /// Whether the commit is flagged for sampled post-commit human spot-audit.
    #[must_use]
    pub fn spot_audit(&self) -> bool {
        self.approval.spot_audit()
    }
    /// The paths durably written, with their post-commit versions — what a renderer shows as "done".
    #[must_use]
    pub fn committed_versions(&self) -> &BTreeMap<String, u64> {
        &self.versions
    }
    /// How many self-heal rounds the turn spent before clearing the gate.
    #[must_use]
    pub fn rounds(&self) -> u8 {
        self.rounds
    }
}

impl TurnOutcome {
    #[must_use]
    pub fn committed(&self) -> bool {
        matches!(self, TurnOutcome::Committed { .. })
    }

    /// The renderer's **only** path to a "done"/commit affordance — `Some` iff this turn actually
    /// committed. `HandedToHuman` yields `None`, so a renderer that gates its done view on a
    /// [`CommitReceipt`] structurally cannot render "done" for a capped/blocked turn.
    #[must_use]
    pub fn commit_receipt(&self) -> Option<CommitReceipt> {
        match self {
            TurnOutcome::Committed {
                approval,
                versions,
                rounds,
            } => Some(CommitReceipt {
                approval: approval.clone(),
                versions: versions.clone(),
                rounds: *rounds,
                seal: (),
            }),
            TurnOutcome::HandedToHuman { .. } => None,
        }
    }
}

/// A deterministic commit identifier for a committed file set: SHA-256 over the sorted
/// `path\x1fcontent` pairs. Stable across replays (forensic reproducibility, §9), independent of any
/// git backend.
fn commit_sha_of(files: &[(String, String)]) -> String {
    use sha2::{Digest, Sha256};
    let mut sorted: Vec<&(String, String)> = files.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let mut h = Sha256::new();
    for (p, c) in sorted {
        h.update(p.as_bytes());
        h.update(b"\x1f");
        h.update(c.as_bytes());
        h.update(b"\x1e");
    }
    let digest = h.finalize();
    let mut s = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Best-effort [`CodeLanguage`] from a file's extension, for the add/replace-method guards
/// ([`guarded_full_file_apply`]). `Other` degrades to the import-restore guard only (no AST language),
/// which the guard itself already handles honestly (`ast: None` disables method-preservation, never
/// fakes it).
fn code_language_of(path: &str) -> CodeLanguage {
    match path.rsplit('.').next() {
        Some("rs") => CodeLanguage::Rust,
        Some("py") => CodeLanguage::Python,
        Some("go") => CodeLanguage::Go,
        Some("js" | "jsx" | "mjs" | "cjs") => CodeLanguage::JavaScript,
        Some("ts" | "tsx") => CodeLanguage::TypeScript,
        Some("java") => CodeLanguage::Java,
        Some("cbl" | "cob" | "cobol") => CodeLanguage::Cobol,
        _ => CodeLanguage::Other,
    }
}

/// Run the **add/replace-method guards** (`SEMANTIC_EDITING.md` §4: import-restore + method-
/// preservation) over the healed file set against the pre-edit baseline, as part of the atomic apply —
/// the guard function existed ([`guarded_full_file_apply`]) but no apply path ever called it. Runs on
/// every file the healed set shares with the baseline (skips brand-new files, nothing to preserve).
///
/// Import restore always runs (it is strictly beneficial — re-injecting a dropped import never harms
/// a legitimate edit). The method-preservation *check* is gated by `check_methods`: it is correct for
/// an unplanned full-file regeneration (a Coder silently dropping a method is always a bug), but a
/// *planned* AST-precise structural op (rename / change-signature / extract) legitimately makes an old
/// symbol name disappear **by design** — that is not a drop, it is the op — so
/// [`crate::semantic_turn::run_semantic_turn_full`] calls this with `check_methods = false`.
///
/// Returns the guarded file set (imports re-injected) and, if any file dropped a method the baseline
/// defined (only populated when `check_methods`), the per-file drop list — the caller must treat a
/// non-empty drop list as a blocking finding, never a silent commit (mirrors the design's "if clean:
/// write ... else: fall down / self-correct").
type GuardedFiles = Vec<(String, String)>;
type DroppedMethods = Vec<(String, Vec<String>)>;

fn run_method_preservation_guards(
    baseline: &BTreeMap<String, String>,
    final_files: &[(String, String)],
    check_methods: bool,
) -> (GuardedFiles, DroppedMethods) {
    let mut guarded = Vec::with_capacity(final_files.len());
    let mut dropped = Vec::new();
    for (path, content) in final_files {
        match baseline.get(path) {
            Some(orig) if orig != content => {
                let ast = if check_methods {
                    lang_from_path(path)
                } else {
                    None
                };
                let g = guarded_full_file_apply(orig, content, code_language_of(path), ast);
                if g.dropped_any_method() {
                    dropped.push((path.clone(), g.dropped_methods.clone()));
                }
                guarded.push((path.clone(), g.content));
            }
            _ => guarded.push((path.clone(), content.clone())),
        }
    }
    (guarded, dropped)
}

/// Run one edit turn end-to-end. Persists to `sink` **iff** the pipeline reaches `Complete`.
///
/// The sink is seeded with `original_files` (so post-write verification + rollback have a baseline);
/// on `Complete` the healed set is applied atomically (all-files-or-none, parse-verified). Any failure
/// of the atomic apply after approval degrades to a `HandedToHuman(Blocked)` — an approval is a
/// necessary, never a sufficient-alone, condition for a durable write.
#[must_use]
pub fn run_edit_turn(
    turn: EditTurn,
    coder: &dyn Coder,
    tools: &dyn StageTools,
    scanner: &dyn SastScanner,
    sink: &mut dyn WorkspaceSink,
    journal: &mut Journal,
) -> TurnOutcome {
    run_edit_turn_with_perf(turn, coder, tools, scanner, None, sink, journal)
}

/// Run one edit turn end-to-end **with Performance Analysis (stage 6) enabled**. Identical to
/// [`run_edit_turn`] except that, when `perf` is `Some`, each self-heal round runs the benchmark-diff +
/// AST-complexity + model-advisory stage over the turn's pre-edit baseline vs the healed set and folds
/// the resulting penalty into the Confidence Score. The perf stage is non-gating, so it never turns a
/// clean commit into a hand-off on its own — it only adjusts the score (and can cap a Tier-scaled edit).
#[must_use]
pub fn run_edit_turn_with_perf(
    turn: EditTurn,
    coder: &dyn Coder,
    tools: &dyn StageTools,
    scanner: &dyn SastScanner,
    perf: Option<PerfConfig<'_>>,
    sink: &mut dyn WorkspaceSink,
    journal: &mut Journal,
) -> TurnOutcome {
    run_edit_turn_full(turn, coder, tools, scanner, perf, None, None, sink, journal)
}

/// Run one edit turn end-to-end with the **Performance Analysis (stage 6)** and **LLM Review
/// (stage 9) with an independent Judge panel (§5)** seam. Identical to [`run_edit_turn_with_perf`] except that, when
/// `review` is `Some`, every green self-heal round runs the finder + the context-isolated judge panel:
/// actionable review findings fold into the Confidence Score and the panel's strict-majority consensus
/// becomes the Commit Gate's `judge_approved`. The durable-write invariant is unchanged — a commit is
/// still reachable ONLY through a `CommitApproval` from a pipeline `Complete`.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn run_edit_turn_full(
    turn: EditTurn,
    coder: &dyn Coder,
    tools: &dyn StageTools,
    scanner: &dyn SastScanner,
    perf: Option<PerfConfig<'_>>,
    review: Option<&ReviewSeams>,
    semantic: Option<SemanticGateConfig<'_>>,
    sink: &mut dyn WorkspaceSink,
    journal: &mut Journal,
) -> TurnOutcome {
    run_edit_turn_full_guarded(
        turn, coder, tools, scanner, perf, review, semantic, true, sink, journal,
    )
}

/// [`run_edit_turn_full`] with the method-preservation guard's enforcement made explicit via
/// `guard_methods`. Every *unplanned* full-file regeneration path (the plain [`EditTurn`] a Coder
/// produced from raw content, which [`run_edit_turn_full`] always guards — `guard_methods = true`)
/// risks silently dropping a method the pre-edit baseline defined. A *planned* AST-precise structural
/// op ([`crate::semantic_turn::run_semantic_turn_full`]'s rename / change-signature / extract — R15's
/// LSP-rung entrypoint) legitimately makes an old symbol name disappear **by design** (that IS the
/// op), so it calls this with `guard_methods = false`: the import-restore guard still runs (always
/// beneficial), but a renamed-away symbol is never mistaken for an accidental drop.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_edit_turn_full_guarded(
    mut turn: EditTurn,
    coder: &dyn Coder,
    tools: &dyn StageTools,
    scanner: &dyn SastScanner,
    perf: Option<PerfConfig<'_>>,
    review: Option<&ReviewSeams>,
    semantic: Option<SemanticGateConfig<'_>>,
    guard_methods: bool,
    sink: &mut dyn WorkspaceSink,
    journal: &mut Journal,
) -> TurnOutcome {
    // ── Pre-stage-1 deterministic risk classification (drives the gate) ──────────────────────────
    // Before ANY stage runs, classify the edit from the code itself (AST diff + symbol-graph blast
    // radius) and fold the result into the turn's tier with the escalate-only combinator. A caller
    // may declare a floor tier, but classification can only raise it — a client that under-declares a
    // settlement-path edit as `Local` is still forced to Tier 3, and the blast radius the tier was
    // sized on is carried into the journal. This is the one place the gate's tier is decided; every
    // downstream stage/gate consumes the escalated tier.
    let assessment = crate::classify::classify_edit(
        &turn.original_files,
        &turn.applied_files,
        turn.config.lang,
        turn.config.tier,
        turn.config.rung,
        false,
    );
    turn.config.tier = assessment.tier;
    turn.config.blast_fan_out = assessment.blast_fan_out;

    // Seed the staging workspace + sink baseline with the pre-edit tree. Keep the baseline vec so the
    // perf stage can diff the healed set against it.
    let mut ws = Workspace::new();
    let mut baseline = BTreeMap::new();
    for (p, c) in &turn.original_files {
        ws.insert(p.clone(), c.clone());
        baseline.insert(p.clone(), c.clone());
    }
    // The sink starts from the baseline so rollback/post-verify are faithful.
    let _ = sink.commit(&baseline);

    let original = turn.original_files;
    let perf_seams = perf.map(|pc| PerfSeams {
        baseline: &original,
        bench: pc.bench,
        advisor: pc.advisor,
        budget: pc.budget,
    });
    // Stage 7 + Stage 8 seams: bind the deployment's layering contract + co-change graph to THIS turn's
    // pre-edit baseline. The self-heal loop re-computes both against the current healed set each round.
    let semantic_seams = semantic.map(|sc| SemanticGateSeams {
        baseline: &original,
        contract: sc.contract,
        cochange: sc.cochange,
        coupling_threshold: sc.coupling_threshold,
    });

    // §3 mid-run re-classification: bind the pre-edit baseline so every self-heal round re-derives
    // the tier from the CURRENT healed set (escalate-only). Without this the tier is frozen at the
    // pre-stage-1 value and a fix that lands in a settlement-path module is still gated as Tier 1.
    let reclass = ReclassifySeams {
        baseline: &original,
    };

    let heal = run_selfheal_reclassified(
        turn.applied_files,
        coder,
        tools,
        scanner,
        &turn.config,
        perf_seams.as_ref(),
        review,
        semantic_seams.as_ref(),
        Some(&reclass),
        journal,
    );

    // THE gate: a durable write is reachable only through a CommitApproval, only from Complete.
    match heal.outcome.commit_approval() {
        Some(approval) => {
            // R15: the add/replace-method guards (import-restore + method-preservation,
            // `SEMANTIC_EDITING.md` §4) run HERE, as part of the atomic apply — before the healed set
            // is ever durably written. A method the pre-edit baseline defined that silently vanished
            // from the regeneration is a blocking finding, never a silent commit; an import the
            // regeneration dropped is transparently re-injected into the committed content.
            let (guarded_files, dropped) =
                run_method_preservation_guards(&baseline, &heal.final_files, guard_methods);
            if !dropped.is_empty() {
                let total: usize = dropped.iter().map(|(_, m)| m.len()).sum();
                let detail = dropped
                    .iter()
                    .map(|(p, ms)| format!("{p}: {}", ms.join(", ")))
                    .collect::<Vec<_>>()
                    .join("; ");
                return TurnOutcome::HandedToHuman {
                    outcome: PipelineOutcome::Blocked {
                        stage: Stage::CommitGate,
                        deterministic_failure: format!(
                            "method-preservation guard: the regeneration silently dropped {total} \
                             method(s) present in the pre-edit baseline ({detail}) — never committed"
                        ),
                    },
                    rounds: heal.rounds,
                };
            }

            let edits: Vec<FileEdit> = guarded_files
                .iter()
                .map(|(p, c)| FileEdit {
                    path: p.clone(),
                    new_content: c.clone(),
                    base_version: ws.version(p),
                })
                .collect();
            match ws.apply_atomic(&edits, lang_from_path, sink) {
                Ok(applied) => {
                    // Bind a deterministic commit SHA (content hash of the committed file set) onto the
                    // journal so `JournalStore::pipeline_history(commit_sha)` (§9) can later reconstruct
                    // this edit's full hash-chained trail from a commit id alone — the forensic-replay
                    // key a regulator has two years on. Pure runtime (no git): the SHA is the content
                    // hash of the sorted committed `(path, content)` pairs.
                    journal.set_commit_sha(commit_sha_of(&guarded_files));
                    TurnOutcome::Committed {
                        approval,
                        versions: applied.committed,
                        rounds: heal.rounds,
                    }
                }
                Err(e) => TurnOutcome::HandedToHuman {
                    outcome: PipelineOutcome::Blocked {
                        stage: Stage::CommitGate,
                        deterministic_failure: format!("atomic apply failed post-approval: {e}"),
                    },
                    rounds: heal.rounds,
                },
            }
        }
        None => TurnOutcome::HandedToHuman {
            outcome: heal.outcome,
            rounds: heal.rounds,
        },
    }
}

/// The long-lived **edit engine** a surface assembles once at startup and routes every
/// code-editing turn through. It **owns** the three pipeline seams a deployment wires in once — the
/// [`Coder`] (LLM fix loop), the deterministic [`StageTools`] (compiler/test/lint/type-check), and
/// the [`SastScanner`] — behind [`Arc`]s, so a renderer holds *one* cheaply-cloneable, `Send + Sync`
/// handle and makes *one* call ([`EditEngine::run_turn`]) per turn. That shape is what the served
/// daemon needs: one engine assembled at startup and shared across many concurrent turns (2,000-user
/// target) without re-borrowing the concrete seams on every call.
///
/// This mirrors the surface layer's single-`ArtifactRuntime`-at-startup pattern and is the clean seam
/// the reserved runtime/surface crate binds to (**`needs_hot_wiring`** — the surface crates
/// `ainxt-runtimed` / `ainxt-surface` are not owned here). The surface owns the concrete seams + the
/// per-turn [`WorkspaceSink`] + [`Journal`]; this crate owns the gate.
///
/// The invariant is preserved verbatim: `run_turn` delegates to [`run_edit_turn`], so the durable
/// write is reachable **only** through a [`CommitApproval`] issued **only** from a `Complete`. There
/// is no method on this facade that reaches a "done"/commit affordance for an edit turn without a
/// real `Complete` in hand.
#[derive(Clone)]
pub struct EditEngine {
    coder: Arc<dyn Coder>,
    tools: Arc<dyn StageTools>,
    scanner: Arc<dyn SastScanner + Send + Sync>,
    perf: Option<OwnedPerf>,
    review: Option<OwnedReview>,
    semantic: Option<OwnedSemantic>,
    breaker: Option<Arc<dyn crate::breaker::DifferentialOracle>>,
    /// The edit ladder's rung-1 language-server driver ([`EditEngine::with_lsp`]). `None` (the
    /// air-gapped default) means every semantic op planned through
    /// [`run_semantic_op_for`](Self::run_semantic_op_for) resolves at the AST rung — recorded, never
    /// silently claimed as LSP-grade.
    lsp: Option<Arc<dyn LspRefactor + Send + Sync>>,
    /// The **deployment's** gate policy + wire-seal ceilings ([`EditEngine::with_edit_policy`]).
    /// Applied to every route-ready (`*_for`) entrypoint, replacing whatever the wire declared.
    edit_policy: DeploymentEditPolicy,
}

/// The deployment-level LLM-Review + Judge seams an [`EditEngine`] owns (behind `Arc`s so the engine
/// stays `'static`, `Send + Sync`, `Clone`). Assembled once via [`EditEngine::with_review`].
#[derive(Clone)]
struct OwnedReview {
    reviewer: Arc<dyn Reviewer>,
    judges: Arc<JudgePanel>,
    criteria: JudgeCriteria,
    task: String,
}

/// The deployment-level perf seams an [`EditEngine`] owns (behind `Arc`s so the engine stays
/// `'static`, `Send + Sync`, `Clone`). Assembled once via [`EditEngine::with_perf`]; the per-turn
/// baseline is the turn's `original_files`.
#[derive(Clone)]
struct OwnedPerf {
    bench: Arc<dyn BenchmarkHarness>,
    advisor: Arc<dyn PerfAdvisor>,
    budget: PerfBudget,
}

/// The deployment-level Architecture Review (stage 7) + Regression Detection (stage 8) seams an
/// [`EditEngine`] owns (behind `Arc`s so the engine stays `'static`, `Send + Sync`, `Clone`). Assembled
/// once via [`EditEngine::with_semantic_review`]; the per-turn baseline is the turn's `original_files`.
#[derive(Clone)]
struct OwnedSemantic {
    contract: Option<Arc<LayerContract>>,
    cochange: Arc<CochangeGraph>,
    coupling_threshold: usize,
}

impl EditEngine {
    /// Assemble the engine from the deployment's pipeline seams (once, at surface startup). The seams
    /// are owned (`Arc`), so the returned engine is `'static`, `Send + Sync`, and `Clone` — a surface
    /// can store it in shared state and hand a clone to every worker turn.
    #[must_use]
    pub fn new(
        coder: Arc<dyn Coder>,
        tools: Arc<dyn StageTools>,
        scanner: Arc<dyn SastScanner + Send + Sync>,
    ) -> Self {
        Self {
            coder,
            tools,
            scanner,
            perf: None,
            review: None,
            semantic: None,
            breaker: None,
            lsp: None,
            edit_policy: DeploymentEditPolicy::default(),
        }
    }

    /// Set the **deployment's** edit policy — the Commit-Gate thresholds plus the wire-seal ceilings
    /// (`CODE_REVIEW_PIPELINE.md` §8). This is what makes the gate *the runtime's decision, not the
    /// requester's*: [`SelfHealConfig::policy`] arrives on the wire (it is a plain `Deserialize`
    /// field of the `POST /v1/edit` body), so a caller holding [`CAP_EDIT_APPLY`] could post
    /// `auto_complete_threshold: 0` and auto-complete any Tier-0/1 edit at Confidence 0. Every
    /// route-ready entrypoint ([`run_turn_for`](Self::run_turn_for),
    /// [`classify_and_run_turn_for`](Self::classify_and_run_turn_for),
    /// [`run_semantic_op_for`](Self::run_semantic_op_for)) **discards** the wire value and substitutes
    /// this one via [`seal_wire_config`], so the forged threshold never reaches [`crate::gate::decide`].
    ///
    /// Not calling this leaves the safe default ([`GatePolicy::default`] — 90/70/60, round cap 5).
    #[must_use]
    pub fn with_edit_policy(mut self, policy: DeploymentEditPolicy) -> Self {
        self.edit_policy = policy;
        self
    }

    /// The deployment edit policy this engine gates with (never the wire's).
    #[must_use]
    pub fn edit_policy(&self) -> DeploymentEditPolicy {
        self.edit_policy
    }

    /// **The wire-seal derivation entrypoint** a transport calls where it parses the `POST /v1/edit`
    /// body (**`needs_hot_wiring`** — the route mount lives in the reserved `ainxt-server` /
    /// `ainxt-runtimed` crates, not owned here), when it wants the override list *visible* on the wire
    /// or in its own audit log. It is pure and side-effect-free.
    ///
    /// Calling it is **optional for safety**: the same seal is applied unconditionally inside every
    /// `*_for` entrypoint, so a transport that just forwards the deserialized body is already
    /// protected. This entrypoint exists so the transport can *report* what was overridden.
    #[must_use]
    pub fn seal_wire_request(&self, req: &EditRequest) -> WireSealReport {
        let (_, report) = seal_wire_config(
            req.config.clone(),
            &req.original_files,
            &req.applied_files,
            &self.edit_policy,
        );
        report
    }

    /// Apply the deployment seal to a wire body, returning the sealed request. Internal to the
    /// route-ready entrypoints; exposed so a transport can pre-seal a body it wants to log.
    #[must_use]
    pub fn sealed_request(&self, mut req: EditRequest) -> (EditRequest, WireSealReport) {
        let (cfg, report) = seal_wire_config(
            req.config,
            &req.original_files,
            &req.applied_files,
            &self.edit_policy,
        );
        req.config = cfg;
        (req, report)
    }

    /// Enable the **edit ladder's rung-1 language-server driver** (`SEMANTIC_EDITING.md` §2, the
    /// design's highest-fidelity rung) for every semantic op run through
    /// [`run_semantic_op_for`](Self::run_semantic_op_for). Before this seam is wired, [`EditEngine`]
    /// (the served `/v1/edit` engine) had no path to rung 1 at all — only [`run_turn`](Self::run_turn)'s
    /// already-resolved [`EditTurn::applied_files`], which never consults a language server. With a
    /// driver wired, a structural op (rename / change-signature / extract) is planned via the AST rung
    /// first and then handed to the driver; if it resolves the refactor for every touched file, that
    /// toolchain-grade result is adopted and the turn records [`Rung::Lsp`] (zero Confidence-Score
    /// penalty) — otherwise the ladder falls to the AST rung, recorded, never silently claimed.
    ///
    /// The real driver is **infra** (a live rust-analyzer/gopls/pyright/… process + warm index); offline,
    /// wire [`ainxt_semantic::ladder::ScriptedLspRefactor`].
    #[must_use]
    pub fn with_lsp(mut self, lsp: Arc<dyn LspRefactor + Send + Sync>) -> Self {
        self.lsp = Some(lsp);
        self
    }

    /// Enable the **optional Tier-3 Breaker differential/invariant run** (`CODE_REVIEW_PIPELINE.md`
    /// §3/§8) on every turn this engine runs. The oracle is consulted **only** for Tier-3
    /// (critical-path / high-risk) edits — the escalated tier decided by classification, never the
    /// wire-declared one — and its findings are journaled onto the tamper-evident Event Log so the
    /// mandatory human hand-off for a Tier-3 edit sees the differential result. The real oracle is
    /// infra (executes candidate + reference impl in a sandbox); offline, wire a [`ScriptedBreaker`].
    #[must_use]
    pub fn with_breaker(mut self, oracle: Arc<dyn crate::breaker::DifferentialOracle>) -> Self {
        self.breaker = Some(oracle);
        self
    }

    /// Enable **Architecture Review (stage 7)** + **Regression Detection (stage 8)** on every turn this
    /// engine runs, wiring the deployment's module-boundary [`LayerContract`] and git-history
    /// [`CochangeGraph`] in once (behind `Arc`s, so the engine remains `'static`, `Send + Sync`,
    /// `Clone`). The per-turn baseline is the turn's `original_files`; both stages are re-computed
    /// against the current healed set each self-heal round.
    ///
    /// Stage 7 is a deterministic hard-gate: an edit that introduces a forbidden boundary edge is
    /// blocked at [`Stage::Architecture`] regardless of its Confidence Score. Stage 8 is scored: the
    /// blast-radius test coverage folds into the Confidence Score (low coverage lowers it) and is never
    /// a hard gate. `contract == None` leaves the arch gate inert (no boundary is asserted the
    /// deployment never declared) while still computing regression coverage.
    #[must_use]
    pub fn with_semantic_review(
        mut self,
        contract: Option<Arc<LayerContract>>,
        cochange: Arc<CochangeGraph>,
        coupling_threshold: usize,
    ) -> Self {
        self.semantic = Some(OwnedSemantic {
            contract,
            cochange,
            coupling_threshold,
        });
        self
    }

    /// Enable **LLM Review (stage 9) + the independent Judge panel (§5)** on every turn this engine
    /// runs, wiring the deployment's reviewer (finder) + judge panel (adjudicator) in once (behind
    /// `Arc`s, so the engine remains `'static`, `Send + Sync`, `Clone`). Panel consensus becomes the
    /// Commit Gate's `judge_approved`; the coder's per-turn self-summary is not carried on this
    /// engine-level path (the finder simply sees none — the panel never sees one either, by design).
    #[must_use]
    pub fn with_review(
        mut self,
        reviewer: Arc<dyn Reviewer>,
        judges: Arc<JudgePanel>,
        criteria: JudgeCriteria,
        task: impl Into<String>,
    ) -> Self {
        self.review = Some(OwnedReview {
            reviewer,
            judges,
            criteria,
            task: task.into(),
        });
        self
    }

    /// Enable **Performance Analysis (stage 6)** on every turn this engine runs, wiring the deployment's
    /// benchmark harness, model advisor, and perf budget in once (behind `Arc`s, so the engine remains
    /// `'static`, `Send + Sync`, `Clone`). The per-turn baseline is the turn's `original_files`.
    #[must_use]
    pub fn with_perf(
        mut self,
        bench: Arc<dyn BenchmarkHarness>,
        advisor: Arc<dyn PerfAdvisor>,
        budget: PerfBudget,
    ) -> Self {
        self.perf = Some(OwnedPerf {
            bench,
            advisor,
            budget,
        });
        self
    }

    /// Run one code-editing turn through the full pipeline, persisting to `sink` **iff** the gate
    /// reaches `Complete`. This is the single call a surface makes per turn.
    #[must_use]
    pub fn run_turn(
        &self,
        turn: EditTurn,
        sink: &mut dyn WorkspaceSink,
        journal: &mut Journal,
    ) -> TurnOutcome {
        let perf = self.perf.as_ref().map(|p| PerfConfig {
            bench: p.bench.as_ref(),
            advisor: p.advisor.as_ref(),
            budget: p.budget,
        });
        let review = self.review.as_ref().map(|r| ReviewSeams {
            reviewer: r.reviewer.as_ref(),
            judges: r.judges.as_ref(),
            criteria: r.criteria.clone(),
            task: r.task.clone(),
            self_summary: String::new(),
        });
        let semantic = self.semantic.as_ref().map(|s| SemanticGateConfig {
            contract: s.contract.as_deref(),
            cochange: s.cochange.as_ref(),
            coupling_threshold: s.coupling_threshold,
        });

        // Optional Tier-3 Breaker differential run. Consulted ONLY when the edit classifies to Tier 3
        // (the same escalate-only classification the gate runs on, never the wire-declared tier), so a
        // trivial edit never pays for it. Its findings are journaled — a Tier-3 edit is a mandatory
        // human hand-off, and the reviewer sees the differential result on the tamper-evident log. The
        // breaker inputs are captured here because `turn` is consumed by the pipeline below.
        let breaker_run = self.breaker.as_ref().map(|oracle| {
            let assessment = crate::classify::classify_edit(
                &turn.original_files,
                &turn.applied_files,
                turn.config.lang,
                turn.config.tier,
                turn.config.rung,
                false,
            );
            crate::breaker::run_if_tier3(
                assessment.tier,
                &turn.original_files,
                &turn.applied_files,
                oracle.as_ref(),
            )
        });

        let outcome = run_edit_turn_full(
            turn,
            self.coder.as_ref(),
            self.tools.as_ref(),
            self.scanner.as_ref(),
            perf,
            review.as_ref(),
            semantic,
            sink,
            journal,
        );

        // Journal the Tier-3 differential result (after the pipeline trail, so PipelineStarted stays
        // first). `Some(None)` = a breaker is configured but the edit was below Tier 3 (not consulted).
        if let Some(Some(report)) = breaker_run {
            let divergences = report
                .findings
                .iter()
                .filter(|f| f.kind == crate::breaker::BreakerKind::Divergence)
                .count();
            let invariant_violations = report.findings.len() - divergences;
            journal.append(
                journal.len() as u64 + 1,
                crate::journal::PipelineEvent::BreakerDifferential {
                    divergences,
                    invariant_violations,
                    gating: report.has_gating_finding(),
                },
            );
        }

        outcome
    }
}

// ===========================================================================
// The RBAC-scoped, route-ready edit entrypoint (`POST /v1/edit`) — R7
// ===========================================================================

/// Capability that admits the **code-edit apply** surface (`POST /v1/edit`). Checked **before**
/// anything else in [`EditEngine::run_turn_for`] — before the turn is even assembled — so a caller
/// without it learns nothing about the pipeline (it never runs) and cannot cause a durable write.
/// This mirrors [`ainxt_artifact::CAP_ARTIFACT_GENERATE`] / the ledger + graph surfaces: one
/// capability-based [`Principal`] drives every non-chat route. `role == Admin` implies it
/// (per [`Principal::has_cap`]).
pub const CAP_EDIT_APPLY: &str = "code.edit.apply";

/// The **route-ready request body** a transport (`POST /v1/edit`) deserializes straight from the wire:
/// the pre-edit tree, the edit engine's applied edit set, and the risk/self-heal config the pass runs
/// under. `deny_unknown_fields` rejects a smuggled extra key. This is the serde-faithful mirror of
/// [`EditTurn`] (which carries the same three fields), so a server maps the wire body to a turn with a
/// single `From`. The seams (Coder / StageTools / SAST / perf / review) are NOT on the wire — they are
/// owned by the long-lived [`EditEngine`] the server assembled once at startup.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EditRequest {
    pub edit_id: String,
    /// The working tree before the edit.
    pub original_files: Vec<(String, String)>,
    /// The edit engine's applied edit set (what would be written) — the pipeline verifies THIS.
    pub applied_files: Vec<(String, String)>,
    /// Risk tier + language + rung + self-heal budget + gate policy for this pass.
    pub config: SelfHealConfig,
}

impl From<EditRequest> for EditTurn {
    fn from(r: EditRequest) -> Self {
        EditTurn {
            edit_id: r.edit_id,
            original_files: r.original_files,
            applied_files: r.applied_files,
            config: r.config,
        }
    }
}

/// Why a route-ready [`EditEngine::run_turn_for`] was refused **before** the pipeline ran. The only
/// reason an edit turn is *refused* (vs. honestly *handed to a human*) is authorization: a
/// `Capped`/`Blocked` outcome is NOT an error — it rides back as [`EditResponse::HandedToHuman`]
/// (mirroring compliance findings, which are audit-and-proceed, never a hard error). A transport maps
/// [`EditRefused::NotAuthorized`] → `403`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum EditRefused {
    /// The caller does not hold [`CAP_EDIT_APPLY`]. Raised before the turn is assembled, so a caller
    /// without the capability never triggers the pipeline and learns nothing about it (→ 403).
    NotAuthorized,
}

impl std::fmt::Display for EditRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EditRefused::NotAuthorized => write!(f, "not authorized to apply code edits"),
        }
    }
}

impl std::error::Error for EditRefused {}

/// The **route-ready, serializable** result of an edit turn — the anti-sycophancy invariant carried
/// all the way to the wire. A transport renders a "done" / commit view **only** for the
/// [`EditResponse::Committed`] variant; a `HandedToHuman` response has no committed fields at all
/// (no versions, no confidence-that-cleared-the-gate), so a renderer that pattern-matches the tagged
/// variant structurally cannot show "done" for a capped/blocked turn.
///
/// `Committed` is produced **only** from a [`TurnOutcome::Committed`] (via the private
/// [`EditResponse::from_outcome`]), which the pipeline yields **only** through a [`CommitApproval`]
/// from a `Complete` and a successful atomic write to the sink. So the guarantee that started in the
/// type system ([`CommitApproval`]'s private seal) survives serialization: the wire shape has no
/// `Committed` inhabitant that did not correspond to a real durable write.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum EditResponse {
    /// The gate cleared and the healed edit set was durably committed. This is the ONLY variant a
    /// transport renders as "done".
    Committed {
        /// The Confidence Score the commit gate cleared with.
        confidence: u8,
        /// Whether the commit is flagged for sampled post-commit human spot-audit.
        spot_audit: bool,
        /// The paths durably written, with their post-commit versions.
        versions: BTreeMap<String, u64>,
        /// How many self-heal rounds the turn spent before clearing the gate.
        rounds: u8,
    },
    /// The gate did not clear (Capped/Blocked) — an honest human hand-off carrying the typed
    /// [`PipelineOutcome`] gap report. The sink was NOT written. NEVER rendered as "done".
    HandedToHuman {
        outcome: PipelineOutcome,
        rounds: u8,
    },
}

impl EditResponse {
    /// Private: the only path from a [`TurnOutcome`] to this wire type. Keeps the mapping in one place
    /// so the `Committed` wire variant is emitted iff the turn actually committed.
    fn from_outcome(out: TurnOutcome) -> Self {
        match out {
            TurnOutcome::Committed {
                approval,
                versions,
                rounds,
            } => EditResponse::Committed {
                confidence: approval.confidence(),
                spot_audit: approval.spot_audit(),
                versions,
                rounds,
            },
            TurnOutcome::HandedToHuman { outcome, rounds } => {
                EditResponse::HandedToHuman { outcome, rounds }
            }
        }
    }

    /// Whether this response represents a real durable commit — the single predicate a transport gates
    /// its "done" affordance on.
    #[must_use]
    pub fn committed(&self) -> bool {
        matches!(self, EditResponse::Committed { .. })
    }
}

impl EditEngine {
    /// **The RBAC-scoped, route-ready edit entrypoint** a server mounts at `POST /v1/edit`
    /// (**`needs_hot_wiring`** — the route mount lives in the reserved `ainxt-server` /
    /// `ainxt-runtimed` transport crates, not owned here).
    ///
    /// It is the authorized counterpart to [`run_turn`](Self::run_turn): the caller's [`Principal`]
    /// gates the whole surface on [`CAP_EDIT_APPLY`] (fail-closed, checked **before** the turn is
    /// even assembled, so the refusal shape is no capability oracle and an unauthorized caller can
    /// never trigger a durable write), then it delegates to `run_turn` and maps the [`TurnOutcome`]
    /// to the serializable [`EditResponse`].
    ///
    /// Request, refusal, and response are all `Serialize`/`Deserialize`, so a transport round-trips
    /// the wire body and renders a refusal verbatim (mapping [`EditRefused::NotAuthorized`] → 403).
    /// The durable-write invariant is unchanged and now reaches the wire: [`EditResponse::Committed`]
    /// exists **iff** the pipeline reached `Complete` and the atomic sink write succeeded, so a
    /// renderer may show "done" **only** on that variant.
    pub fn run_turn_for(
        &self,
        principal: &Principal,
        req: EditRequest,
        sink: &mut dyn WorkspaceSink,
        journal: &mut Journal,
    ) -> Result<EditResponse, EditRefused> {
        if !principal.has_cap(CAP_EDIT_APPLY) {
            return Err(EditRefused::NotAuthorized);
        }
        // SEAL THE WIRE BEFORE ANYTHING ELSE. `EditRequest.config` is a plain `Deserialize` body: the
        // Commit-Gate thresholds, the ladder rung, a Judge verdict and the round budget all arrive
        // from the caller. Policy is the runtime's; the rung is derived from the diff. See
        // [`crate::wire_seal`].
        let (req, seal) = self.sealed_request(req);
        let turn: EditTurn = req.into();
        let out = EditResponse::from_outcome(self.run_turn(turn, sink, journal));
        // Journal the seal AFTER the pipeline trail (so `PipelineStarted` stays the first record),
        // exactly like the breaker's differential result. A regulator sees every field the runtime
        // took away from the requester.
        journal_seal(journal, &seal);
        Ok(out)
    }

    /// **The classification-surfacing, RBAC-scoped, route-ready edit entrypoint** a server mounts at
    /// `POST /v1/edit` when the surface wants the risk decision made *visible* on the wire
    /// (**`needs_hot_wiring`** — the route mount lives in the reserved `ainxt-server` /
    /// `ainxt-runtimed` transport crates, not owned here).
    ///
    /// It is [`run_turn_for`](Self::run_turn_for) plus the deterministic pre-stage-1
    /// [`EditRiskAssessment`]: the server classifies the edit from the code itself (never trusting
    /// the wire-declared tier), so the returned [`ClassifiedEditResponse`] carries both the effective
    /// tier that drove the gate **and the graph rationale that forced it** — a reviewer sees not just
    /// "Tier 3" but "settlement/x.rs is on the critical path". The assessment is computed with the
    /// **same** inputs (and thus the same result) as the escalation inside [`run_turn`](Self::run_turn),
    /// so the surfaced tier is exactly the one the Commit Gate ran under.
    ///
    /// Fail-closed and checked BEFORE the turn is assembled, identical to `run_turn_for`: an
    /// unauthorized caller never triggers classification or the pipeline and can never cause a write.
    pub fn classify_and_run_turn_for(
        &self,
        principal: &Principal,
        req: EditRequest,
        sink: &mut dyn WorkspaceSink,
        journal: &mut Journal,
    ) -> Result<ClassifiedEditResponse, EditRefused> {
        if !principal.has_cap(CAP_EDIT_APPLY) {
            return Err(EditRefused::NotAuthorized);
        }
        // Seal first: classify the edit against the DERIVED rung, not the declared one (a wire-declared
        // `lsp` would otherwise erase the `TextPatch ⇒ Moderate` escalation in the surfaced assessment
        // too, so the tier the reviewer reads would not be the tier the gate ran under).
        let (req, seal) = self.sealed_request(req);
        let assessment = crate::classify::classify_edit(
            &req.original_files,
            &req.applied_files,
            req.config.lang,
            req.config.tier,
            req.config.rung,
            false,
        );
        let turn: EditTurn = req.into();
        let response = EditResponse::from_outcome(self.run_turn(turn, sink, journal));
        journal_seal(journal, &seal);
        Ok(ClassifiedEditResponse {
            assessment,
            response,
        })
    }

    /// **The RBAC-scoped, route-ready SEMANTIC-OP edit entrypoint** a server mounts at
    /// `POST /v1/edit/semantic` (**`needs_hot_wiring`** — the route mount lives in the reserved
    /// `ainxt-server` / `ainxt-runtimed` transport crates, not owned here). This is the entrypoint that
    /// makes the edit ladder's **rung 1 (LSP semantic refactor)** reachable on the served path: unlike
    /// [`run_turn_for`](Self::run_turn_for), which only ever verifies an *already-resolved*
    /// `applied_files` set, this plans an [`AgentOp`] (rename / change-signature / extract) through the
    /// ladder — consulting [`EditEngine::with_lsp`]'s driver first, when wired — before gating and
    /// committing the result through the exact same [`run_edit_turn_full`] path (so the R15
    /// method-preservation/import-restore guards and every stage still apply).
    ///
    /// Fail-closed and checked BEFORE the op is planned, identical to `run_turn_for`: an unauthorized
    /// caller never triggers planning and can never cause a write. A [`PlanError`] (the op could not be
    /// planned — bad identifier, missing file, …) is reported as [`SemanticEditResponse::PlanRejected`];
    /// nothing is written on that path either.
    pub fn run_semantic_op_for(
        &self,
        principal: &Principal,
        req: SemanticEditRequest,
        sink: &mut dyn WorkspaceSink,
        journal: &mut Journal,
    ) -> Result<SemanticEditResponse, EditRefused> {
        if !principal.has_cap(CAP_EDIT_APPLY) {
            return Err(EditRefused::NotAuthorized);
        }
        // Seal the wire-supplied policy fields here too (thresholds / Judge verdict / round budget).
        // The rung is NOT sealed from the diff on this path — the ladder *resolves* it downstream and
        // overwrites `config.rung` with what it actually achieved, which is the honest evidence.
        let mut req = req;
        let (cfg, seal) = seal_wire_config(req.config, &[], &[], &self.edit_policy);
        req.config = cfg;
        let turn: SemanticTurn = req.into();
        let review = self.review.as_ref().map(|r| ReviewSeams {
            reviewer: r.reviewer.as_ref(),
            judges: r.judges.as_ref(),
            criteria: r.criteria.clone(),
            task: r.task.clone(),
            self_summary: String::new(),
        });
        // Drop the `Send + Sync` tail from the stored trait object: `run_semantic_turn_full` takes a
        // bare `&dyn LspRefactor` (the marker bounds are only needed to own it behind the engine's Arc).
        let lsp: Option<&dyn LspRefactor> = self.lsp.as_deref().map(|d| d as &dyn LspRefactor);
        let outcome = run_semantic_turn_full(
            turn,
            lsp,
            review.as_ref(),
            self.coder.as_ref(),
            self.tools.as_ref(),
            self.scanner.as_ref(),
            sink,
            journal,
        );
        journal_seal(journal, &seal);
        Ok(match outcome {
            Ok(o) => SemanticEditResponse::Resolved {
                rung: o.rung,
                response: EditResponse::from_outcome(o.turn),
            },
            Err(e) => SemanticEditResponse::PlanRejected {
                reason: e.to_string(),
            },
        })
    }

    /// GAP-FIX semantic-editing-codereview — **the RBAC-scoped, route-ready REVIEW-ONLY entrypoint**
    /// [`crate::surface::run_review`] documents as one of the crate's two public surface calls
    /// ("a product surface... calls exactly one of two functions") but which no transport ever mounted:
    /// unlike [`run_turn_for`](Self::run_turn_for) / [`run_semantic_op_for`](Self::run_semantic_op_for),
    /// this NEVER writes — no sink, no self-heal, no commit affordance — it runs the SAME deterministic
    /// stages + SAST + LLM Review finder + independent Judge panel over a candidate and returns the
    /// findings + panel verdict + typed [`PipelineOutcome`], so a code-review/PR-bot surface can
    /// adjudicate a change without applying it.
    ///
    /// Fail-closed on [`CAP_EDIT_APPLY`], checked before the review runs (no capability oracle) — same
    /// boundary every other route-ready entrypoint enforces. Refused with
    /// [`ReviewRefused::ReviewNotConfigured`] when this engine has no
    /// [`with_review`](Self::with_review) seam (the air-gapped default): a review-only turn cannot
    /// honestly run without an independent Judge, so this never silently degrades to a scoreless "pass".
    ///
    /// The wire-supplied `req.config`'s deployment-owned fields (gate policy / self-asserted Judge
    /// verdict / round cap / declared coverage) are sealed against `self.edit_policy` exactly as every
    /// other `*_for` entrypoint does — a caller holding [`CAP_EDIT_APPLY`] cannot forge a zero threshold
    /// to make a bad candidate's advisory verdict read "would complete". The rung is intentionally NOT
    /// re-derived from a diff here (mirrors [`run_semantic_op_for`](Self::run_semantic_op_for)'s empty-
    /// slice call): a review has no before/after edit to diff against — it grades one candidate
    /// snapshot — so `seal_wire_config` is called with empty original/applied slices, sealing
    /// policy/judge/rounds/coverage while leaving the caller-declared `rung` as the review parameter
    /// [`crate::surface::review_config`] documents it as.
    pub fn run_review_for(
        &self,
        principal: &Principal,
        req: crate::surface::ReviewRequest,
        journal: &mut Journal,
    ) -> Result<crate::surface::ReviewOutcome, ReviewRefused> {
        if !principal.has_cap(CAP_EDIT_APPLY) {
            return Err(ReviewRefused::NotAuthorized);
        }
        let owned = self
            .review
            .as_ref()
            .ok_or(ReviewRefused::ReviewNotConfigured)?;
        let mut req = req;
        let (cfg, seal) = seal_wire_config(req.config, &[], &[], &self.edit_policy);
        req.config = cfg;
        let seams = ReviewSeams {
            reviewer: owned.reviewer.as_ref(),
            judges: owned.judges.as_ref(),
            criteria: owned.criteria.clone(),
            task: owned.task.clone(),
            self_summary: String::new(),
        };
        let outcome = crate::surface::run_review(
            req,
            self.tools.as_ref(),
            self.scanner.as_ref(),
            &seams,
            journal,
        );
        journal_seal(journal, &seal);
        Ok(outcome)
    }
}

/// Why a route-ready [`EditEngine::run_review_for`] was refused **before** the review ran.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum ReviewRefused {
    /// The caller does not hold [`CAP_EDIT_APPLY`]. Raised before the review is assembled, so a caller
    /// without the capability never triggers it and learns nothing about it (→ 403).
    NotAuthorized,
    /// This engine has no [`EditEngine::with_review`] seam configured (the air-gapped default: no
    /// model-backed Reviewer/Judge panel wired). A review-only turn cannot honestly adjudicate a
    /// candidate without an independent Judge, so it is refused rather than silently short-circuited to
    /// an unscored "pass" (→ 503: the capability exists but this deployment has not wired a model).
    ReviewNotConfigured,
}

impl std::fmt::Display for ReviewRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReviewRefused::NotAuthorized => write!(f, "not authorized to request a code review"),
            ReviewRefused::ReviewNotConfigured => {
                write!(
                    f,
                    "no LLM Review + independent Judge panel seam is configured on this engine"
                )
            }
        }
    }
}

impl std::error::Error for ReviewRefused {}

/// Journal every field the deployment seal took away from the requester. Appended **after** the
/// pipeline trail (so `PipelineStarted` stays the first record), on the same hash chain — a regulator
/// reading the trail two years later sees both the forged value and the policy that replaced it.
fn journal_seal(journal: &mut Journal, seal: &WireSealReport) {
    for line in &seal.overrides {
        journal.append(
            journal.len() as u64 + 1,
            crate::journal::PipelineEvent::WirePolicySealed {
                field: line.clone(),
            },
        );
    }
}

/// The **route-ready request body** a transport (`POST /v1/edit/semantic`) deserializes straight from
/// the wire: the AST-parseable working tree, the [`AgentOp`] to plan, and the risk/self-heal config.
/// `deny_unknown_fields` rejects a smuggled extra key. The seams (Coder / StageTools / SAST / LSP
/// driver / review) are NOT on the wire — they are owned by the long-lived [`EditEngine`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticEditRequest {
    pub edit_id: String,
    pub files: Vec<SourceFile>,
    pub op: AgentOp,
    pub config: SelfHealConfig,
}

impl From<SemanticEditRequest> for SemanticTurn {
    fn from(r: SemanticEditRequest) -> Self {
        SemanticTurn {
            edit_id: r.edit_id,
            files: r.files,
            op: r.op,
            config: r.config,
        }
    }
}

/// The **route-ready, serializable** result of a semantic-op edit turn. `Resolved` carries the
/// [`Rung`] the ladder actually resolved at (`Lsp` only when a driver was wired AND it computed the
/// refactor for every touched file) alongside the same [`EditResponse`] `run_turn_for` returns, so a
/// renderer shows "done" under the identical rule: only on `response == EditResponse::Committed`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SemanticEditResponse {
    /// The op was planned (at `rung`) and run through the full gated commit path.
    Resolved { rung: Rung, response: EditResponse },
    /// The op could not even be planned (bad identifier / symbol not found / missing file). Nothing
    /// was ever written — this is a pre-pipeline refusal, not a gate outcome.
    PlanRejected { reason: String },
}

/// The **route-ready, serializable** result of a classified edit turn: the pre-stage-1
/// [`EditRiskAssessment`] (the effective tier + why) alongside the [`EditResponse`] the gate
/// produced. A transport renders "done" **only** on `response == EditResponse::Committed`, exactly as
/// for [`EditResponse`]; the assessment is advisory metadata a surface shows next to the outcome
/// (e.g. "held for human approval — settlement critical path"). The durable-write invariant is
/// unchanged: a `Committed` response still exists iff the pipeline reached `Complete`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassifiedEditResponse {
    /// The deterministic pre-stage-1 risk assessment that drove the gate.
    pub assessment: crate::classify::EditRiskAssessment,
    /// The typed edit-turn outcome (the ONLY `Committed` inhabitant corresponds to a real write).
    pub response: EditResponse,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::Language;
    use crate::risk::RiskTier;
    use crate::sast::BuiltinScanner;
    use crate::selfheal::Observation;
    use crate::stages::{ScriptedTools, StageContext, StageTools, ToolResult};
    use ainxt_semantic::workspace::MemorySink;

    struct NoOpCoder;
    impl Coder for NoOpCoder {
        fn fix(
            &self,
            _r: u8,
            files: &[(String, String)],
            _o: &Observation,
        ) -> Vec<(String, String)> {
            files.to_vec()
        }
    }

    /// Tools whose compile fails while the source contains "broken".
    struct CompileGate;
    impl StageTools for CompileGate {
        fn compile(&self, ctx: &StageContext) -> ToolResult {
            if ctx.files.iter().any(|(_, c)| c.contains("broken")) {
                ToolResult::fail(vec!["E: broken".into()])
            } else {
                ToolResult::pass()
            }
        }
        fn test(&self, _c: &StageContext) -> ToolResult {
            ToolResult::pass()
        }
        fn lint(&self, _c: &StageContext) -> ToolResult {
            ToolResult::pass()
        }
        fn type_check(&self, _c: &StageContext) -> ToolResult {
            ToolResult::pass()
        }
    }

    fn cfg(tier: RiskTier) -> SelfHealConfig {
        SelfHealConfig {
            lang: Language::Rust,
            tier,
            max_rounds: 3,
            stuck: None,
            ..Default::default()
        }
    }

    #[test]
    fn gap_ainxt_pipeline_edit_01_clean_turn_commits_via_the_pipeline_only() {
        // A clean edit passes the gate → the healed set is committed and a CommitApproval issued.
        let turn = EditTurn {
            edit_id: "t-clean".into(),
            original_files: vec![("a.rs".into(), "fn f() -> i32 { 1 }\n".into())],
            applied_files: vec![("a.rs".into(), "fn f() -> i32 { 2 }\n".into())],
            config: cfg(RiskTier::Local),
        };
        let mut sink = MemorySink::new();
        let mut j = Journal::new("t-clean");
        let out = run_edit_turn(
            turn,
            &NoOpCoder,
            &ScriptedTools::default(),
            &BuiltinScanner,
            &mut sink,
            &mut j,
        );
        match out {
            TurnOutcome::Committed {
                approval, versions, ..
            } => {
                assert!(approval.confidence() >= 90);
                assert_eq!(versions["a.rs"], 1);
                // The durable write actually happened, and only through the pipeline.
                assert!(sink.files["a.rs"].contains('2'));
            }
            other => panic!("expected Committed, got {other:?}"),
        }
        assert_eq!(j.verify(), Ok(()));
    }

    #[test]
    fn gap_ainxt_pipeline_edit_01_tier3_critical_path_hands_to_human_no_commit() {
        // Even a perfectly-scoring settlement-path edit must not auto-commit (Tier-3 forced HITL).
        let turn = EditTurn {
            edit_id: "t-settle".into(),
            original_files: vec![("settlement/x.rs".into(), "fn f() -> i32 { 1 }\n".into())],
            applied_files: vec![("settlement/x.rs".into(), "fn f() -> i32 { 2 }\n".into())],
            config: cfg(RiskTier::HighRisk),
        };
        let mut sink = MemorySink::new();
        let mut j = Journal::new("t-settle");
        let out = run_edit_turn(
            turn,
            &NoOpCoder,
            &ScriptedTools::default(),
            &BuiltinScanner,
            &mut sink,
            &mut j,
        );
        assert!(!out.committed());
        // Not written despite a clean edit — the human gate is unbypassable.
        assert_eq!(sink.files["settlement/x.rs"], "fn f() -> i32 { 1 }\n");
    }

    #[test]
    fn edit_turn_self_heals_a_compile_failure_then_commits() {
        // The applied edit is broken; a Coder that removes "broken" heals it, then it commits.
        struct HealCoder;
        impl Coder for HealCoder {
            fn fix(
                &self,
                _r: u8,
                files: &[(String, String)],
                _o: &Observation,
            ) -> Vec<(String, String)> {
                files
                    .iter()
                    .map(|(p, c)| (p.clone(), c.replace("// broken", "")))
                    .collect()
            }
        }
        let turn = EditTurn {
            edit_id: "t-heal".into(),
            original_files: vec![("a.rs".into(), "fn f() -> i32 { 1 }\n".into())],
            applied_files: vec![("a.rs".into(), "fn f() -> i32 { 2 } // broken\n".into())],
            config: cfg(RiskTier::Local),
        };
        let mut sink = MemorySink::new();
        let mut j = Journal::new("t-heal");
        let out = run_edit_turn(
            turn,
            &HealCoder,
            &CompileGate,
            &BuiltinScanner,
            &mut sink,
            &mut j,
        );
        assert!(out.committed(), "expected commit after heal, got {out:?}");
        assert!(sink.files["a.rs"].contains('2'));
        assert!(!sink.files["a.rs"].contains("broken"));
    }
}
