// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! The **self-heal feedback loop** (`docs/architecture/CODE_REVIEW_PIPELINE.md` §6) — the composition
//! that turns the pipeline's single pass into a bounded fix-and-reverify loop. The pieces existed but
//! were uncomposed: [`crate::pipeline::run_pipeline`] was a single pass with `rounds_exhausted`
//! hard-coded to `0`, there was no Coder seam, no round counter, and `SelfHealTriggered`/`RoundCapped`
//! were emitted only in journal tests. This module wires:
//!
//! ```text
//! run stages → run_pipeline → outcome
//!   Complete            → return (unlocks the commit affordance)
//!   Blocked/Capped      → Observation{stage, exact tool output}
//!       → Coder.fix(round, files, observation) → re-apply
//!       → RE-ENTER at the earliest invalidated stage (content-hash StageCache; Phase-A always re-runs)
//!   bounded by:  a round-cap  AND  a stuck/thrash detector (ainxt-judge)
//!       → RoundCapped → honest Capped with the REAL rounds_exhausted (never a false Complete)
//! ```
//!
//! The stuck detector matters as much as the cap: it cuts a thrashing loop (fix for stage A reopens
//! stage B) with a diagnosis rather than burning the whole budget. Deterministic control flow; the
//! Coder/tools/SAST are seams, so the honest-`Capped` invariant is exhaustively testable.

use crate::confidence::ConfidenceInputs;
use crate::gate::GatePolicy;
use crate::journal::{Journal, PipelineEvent};
use crate::outcome::PipelineOutcome;
use crate::perf::{analyze_perf, BenchmarkHarness, PerfAdvisor, PerfBudget, PerfReport};
use crate::pipeline::{content_hash, run_pipeline, PipelineInputs, StageCache};
use crate::review::{analyze_semantic_gate, repo_layer_contract};
use crate::risk::RiskTier;
use crate::sast::SastScanner;
use crate::stage::{Stage, StageReport, StageVerdict};
use crate::stages::{run_deterministic_stages, StageContext, StageTools};
use ainxt_judge::{
    actionable_review, CoderSubmission, JudgeCriteria, JudgePanel, PanelVerdict, ReviewFinding,
    Reviewer, StuckDetector, StuckDiagnosis,
};
use ainxt_semantic::arch::LayerContract;
use ainxt_semantic::ladder::Rung;
use ainxt_semantic::regression::CochangeGraph;
use std::collections::BTreeMap;

/// A structured observation fed back to the Coder — the stage that rejected the edit plus the exact,
/// un-paraphrased tool output (§6's `Observation{stage, tool_output, exact_location}`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    pub stage: Stage,
    pub diagnostics: Vec<String>,
}

/// The Coder seam: given the current files and the observation, produce a fixed file set. A real impl
/// calls the model + the wired edit ladder ([`crate::ladder_driver`]); the offline impl is scripted.
pub trait Coder: Send + Sync {
    fn fix(
        &self,
        round: u8,
        files: &[(String, String)],
        observation: &Observation,
    ) -> Vec<(String, String)>;
}

/// The **offline / air-gapped** [`Coder`]: it returns the file set unchanged on every self-heal round.
///
/// A real deployment wires a model-backed coder (the edit ladder + LLM). With no model configured (the
/// air-gapped default the shipped daemon runs), this is the honest seam: a first-pass edit that already
/// clears the gate still commits (the coder is never consulted — self-heal only runs on a REJECTED
/// pass), while an edit that fails a stage cannot be improved and is capped to a truthful human hand-off
/// ([`crate::PipelineOutcome::Capped`]) rather than a fabricated fix. It never invents code, so it can
/// never turn a failing edit into a false "done".
#[derive(Debug, Clone, Copy, Default)]
pub struct IdentityCoder;

impl Coder for IdentityCoder {
    fn fix(
        &self,
        _round: u8,
        files: &[(String, String)],
        _observation: &Observation,
    ) -> Vec<(String, String)> {
        files.to_vec()
    }
}

/// Self-heal loop budget + the risk/language context each round's pipeline pass needs.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SelfHealConfig {
    pub lang: crate::capability::Language,
    pub tier: RiskTier,
    pub rung: Rung,
    pub max_rounds: u8,
    /// `Some((window, threshold))` enables the thrash detector; `None` = pure round-cap.
    pub stuck: Option<(usize, f64)>,
    /// Fraction `[0,1]` of the blast radius covered by tests (regression term of the score).
    pub blast_radius_test_coverage: f64,
    /// Unremediated architecture boundary violations (hard-block if > 0).
    pub architecture_violations: u32,
    /// Judge approval, if a Judge ran (`None` = did not run — allowed only below Tier 2).
    pub judge_approved: Option<bool>,
    pub policy: GatePolicy,
    /// Direct 1-hop blast fan-out of the edit (from the pre-stage-1 classifier). Journaled on the
    /// `PipelineStarted` event so the tamper-evident regulator record shows the real blast radius the
    /// tier was sized on. `#[serde(default)]` so an older wire body (no field) still deserializes.
    #[serde(default)]
    pub blast_fan_out: usize,
}

impl Default for SelfHealConfig {
    fn default() -> Self {
        SelfHealConfig {
            lang: crate::capability::Language::Rust,
            tier: RiskTier::Local,
            rung: Rung::Ast,
            max_rounds: 5,
            stuck: Some((3, 0.9)),
            blast_radius_test_coverage: 1.0,
            architecture_violations: 0,
            judge_approved: None,
            policy: GatePolicy::default(),
            blast_fan_out: 0,
        }
    }
}

/// The full result of a self-heal run: the typed outcome plus loop observability.
#[derive(Debug, Clone)]
pub struct SelfHealOutcome {
    /// The typed pipeline outcome. `Complete` unlocks the commit; `Capped` is an honest hand-off.
    pub outcome: PipelineOutcome,
    /// How many self-heal rounds were actually spent (never a hard-coded 0).
    pub rounds: u8,
    /// The stuck/thrash diagnosis, if the loop was cut early by the detector.
    pub stuck: Option<StuckDiagnosis>,
    /// Per-round: which stages re-ran (the earliest-invalidated re-entry, from the content-hash cache).
    pub rerun_log: Vec<Vec<Stage>>,
    /// The file set as it stands at the outcome (the healed set on `Complete`) — what the turn gate
    /// commits, and only when a commit affordance is in hand.
    pub final_files: Vec<(String, String)>,
    /// The actionable LLM Review (stage 9) findings from the final round the review seam ran, if any.
    pub last_review: Vec<ReviewFinding>,
    /// The independent Judge panel's verdict from the final round it ran (context-isolated), if any.
    pub last_judge: Option<PanelVerdict>,
}

impl SelfHealOutcome {
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.outcome.is_complete()
    }
}

fn joined(files: &[(String, String)]) -> String {
    let mut s = String::new();
    for (p, c) in files {
        s.push_str(p);
        s.push('\n');
        s.push_str(c);
        s.push('\n');
    }
    s
}

fn file_map(files: &[(String, String)]) -> BTreeMap<String, String> {
    files.iter().cloned().collect()
}

/// The stage-6 Performance Analysis seams a caller wires into the self-heal loop. Held by borrow (the
/// loop runs synchronously), grouping the pre-edit **baseline** the benchmark/complexity diff is taken
/// against with the deployment's benchmark harness, model advisor, and perf budget. When `None`, the
/// perf stage does not run and `perf_regression_penalty` stays `0` (the historical behaviour — every
/// existing caller/test is unaffected).
pub struct PerfSeams<'a> {
    /// The pre-edit file set the post-edit set is diffed against (complexity + benchmark).
    pub baseline: &'a [(String, String)],
    pub bench: &'a dyn BenchmarkHarness,
    pub advisor: &'a dyn PerfAdvisor,
    pub budget: PerfBudget,
}

/// The model seams for **LLM Review (stage 9)** + the **independent Judge panel (§5)**, wired into the
/// self-heal loop by borrow. Both are behind trait objects from `ainxt-judge`, so a deployment plugs in
/// a real model-backed reviewer/panel while the offline tests plug in deterministic ones.
///
/// The two roles are architecturally distinct (`CODE_REVIEW_PIPELINE.md` §5):
/// - The [`Reviewer`] is a **finder** (stage 9): it lists actionable findings against the candidate +
///   task; it MAY see the coder's `self_summary`. Its findings feed the Confidence Score, never a
///   gate by themselves.
/// - The [`JudgePanel`] is the **adjudicator**: each judge scores the candidate INDEPENDENTLY and
///   context-isolated (never sees `self_summary`, never sees a peer's verdict). Its strict-majority
///   consensus becomes the pipeline's `judge_approved` — a gate the Confidence Score cannot buy back.
///
/// A candidate that fails a deterministic stage this round never reaches either (guarantee #1: you do
/// not ask a model whether code that does not compile is good) — the seam runs only on a green round.
pub struct ReviewSeams<'a> {
    /// Stage-9 LLM Review (finder). Findings are filtered to actionable-only before scoring.
    pub reviewer: &'a dyn Reviewer,
    /// The independent Judge panel (adjudicator). Consensus → `judge_approved`.
    pub judges: &'a JudgePanel,
    /// What the panel adjudicates against (goal + per-judge pass threshold).
    pub criteria: JudgeCriteria,
    /// The task the finder reviews against (e.g. the ticket).
    pub task: String,
    /// The coder's own completion claim. The finder may read it; the Judge panel structurally never
    /// does (context isolation is enforced by [`JudgePanel::evaluate_submission`]).
    pub self_summary: String,
}

/// The **Architecture Review (stage 7)** + **Regression Detection (stage 8)** seams, wired into the
/// self-heal loop by borrow and re-computed each round from the pre-edit **baseline** vs the current
/// healed set (deterministic AST/graph — no model, no I/O). This is the wiring the round-10 gap
/// flagged: `architecture_violations` / `blast_radius_test_coverage` were caller-supplied scalars the
/// loop trusted; with this seam a live edit turn *computes* them from the code itself.
///
/// - Stage 7 (hard gate): import edges the edit introduces that the [`LayerContract`] forbids are
///   counted as unremediated boundary violations; a count `> 0` hard-blocks at [`Stage::Architecture`]
///   in [`crate::gate::decide`] (a boundary-violating edit never reaches `Complete`, whatever its
///   score). A coder that removes the offending import on a later round clears it — the count is
///   re-computed against the *current* healed set every round.
/// - Stage 8 (scored, non-gating): the blast-radius test coverage from the test call-graph replaces
///   the invented `blast_radius_test_coverage`; low coverage lowers the Confidence Score. Change-
///   coupling partners are surfaced as advisories, never gating.
///
/// When `None`, both stages are inert and the loop falls back to the caller-supplied
/// `config.architecture_violations` / `config.blast_radius_test_coverage` (every existing caller/test
/// is byte-identical).
pub struct SemanticGateSeams<'a> {
    /// The pre-edit file set the arch-edge diff + regression coverage are computed against.
    pub baseline: &'a [(String, String)],
    /// Stage 7: the declared module-boundary contract. `None` = no contract wired (arch gate inert).
    pub contract: Option<&'a LayerContract>,
    /// Stage 8: the git-history co-change graph for change-coupling advisories.
    pub cochange: &'a CochangeGraph,
    /// Minimum historical co-change count for a coupling advisory.
    pub coupling_threshold: usize,
}

/// The **mid-run escalate-only re-classification** seam (`CODE_REVIEW_PIPELINE.md` §3:
/// "Re-classification, not a one-shot decision: if a self-heal round touches a file outside the
/// original blast radius, or a fix lands in a critical-path module the original edit didn't touch,
/// the tier is recomputed upward before the next pipeline pass").
///
/// Before round 0 the tier was classified once from the *submitted* edit set. A self-heal round
/// rewrites that set: the Coder may add a file, pull in a settlement-path module, widen the blast
/// radius, or introduce a signature change. Without this seam the frozen `config.tier` is reused for
/// every subsequent round's gate and `RiskInputs::prior_finding` — the only escalator input — is the
/// literal `false`, so a Tier-1 edit that heals into a critical-path change still commits as Tier 1.
///
/// With the baseline bound, each round re-runs [`crate::classify::classify_edit`] against the
/// **current healed set** and folds the result in with [`RiskTier::escalate`] (`max`) — so the tier
/// can only move *up*, never down. That direction is load-bearing: a de-escalation would be the
/// self-graded relief the anti-sycophancy design forbids (a coder could delete the risky file from
/// the set, drop to Tier 1, and auto-complete).
///
/// It also supplies the current-round escalators §3's Tier-3 trigger list names but nothing fed
/// before: **any SAST finding at any severity**, and any unremediated architecture violation, force
/// the tier to [`RiskTier::HighRisk`] for this round's gate and set `prior_finding` for every later
/// round. `HighRisk` forces a human hand-off; it never blocks the user — the outcome is the honest
/// `RequiresHitl`/`Capped` shape the surface already renders.
pub struct ReclassifySeams<'a> {
    /// The pre-edit file set every round's classification is diffed against.
    pub baseline: &'a [(String, String)],
}

/// The effective, escalate-only tier state carried across self-heal rounds.
struct TierState {
    tier: RiskTier,
    prior_finding: bool,
}

impl TierState {
    fn escalate_to(&mut self, to: RiskTier, round: u8, reason: &str, journal: &mut Journal) {
        if to <= self.tier {
            return;
        }
        let from = self.tier;
        self.tier = to;
        journal.append(
            journal.len() as u64 + 1,
            PipelineEvent::RiskReclassified {
                round,
                from: format!("{from:?}"),
                to: format!("{to:?}"),
                reason: reason.to_string(),
            },
        );
    }
}

/// Run the self-heal loop. Returns as soon as the pipeline reaches `Complete`, or an honest `Capped`
/// when the round-cap is hit or the stuck detector fires — with the real round count and the gap
/// report either way. Every round journals `SelfHealTriggered`; a give-up journals `RoundCapped`.
///
/// This is the perf-disabled entrypoint (equivalent to [`run_selfheal_with_perf`] with `perf = None`)
/// — preserved verbatim for every existing caller.
#[must_use]
pub fn run_selfheal(
    initial_files: Vec<(String, String)>,
    coder: &dyn Coder,
    tools: &dyn StageTools,
    scanner: &dyn SastScanner,
    config: &SelfHealConfig,
    journal: &mut Journal,
) -> SelfHealOutcome {
    run_selfheal_with_perf(initial_files, coder, tools, scanner, config, None, journal)
}

/// Run the self-heal loop with an optional **Performance Analysis (stage 6)** pass. When `perf` is
/// `Some`, each round — after the deterministic Phase-A stages pass — runs [`analyze_perf`] over the
/// baseline vs the current healed set, folds the resulting `0..=25` penalty into the Confidence Score's
/// `perf_regression_penalty`, and appends the honest `Stage::Perf` report (Pass / Advisory / Skipped,
/// never gating) to the pipeline's report set so it is journaled and visible in the gap report.
#[must_use]
pub fn run_selfheal_with_perf(
    initial_files: Vec<(String, String)>,
    coder: &dyn Coder,
    tools: &dyn StageTools,
    scanner: &dyn SastScanner,
    config: &SelfHealConfig,
    perf: Option<&PerfSeams>,
    journal: &mut Journal,
) -> SelfHealOutcome {
    run_selfheal_full(
        initial_files,
        coder,
        tools,
        scanner,
        config,
        perf,
        None,
        None,
        journal,
    )
}

/// Run the self-heal loop with the optional **Performance Analysis (stage 6)** pass AND the optional
/// **LLM Review (stage 9) + independent Judge panel (§5)** seam. This is the fully-composed loop the
/// surface entrypoints ([`crate::surface`]) drive.
///
/// When `review` is `Some`, each round that reaches a green build runs the finder + the context-isolated
/// judge panel: the finder's actionable findings fold into the Confidence Score's review term (and are
/// fed back to the Coder as part of the next round's observation), and the panel's strict-majority
/// consensus becomes `judge_approved` for the Commit Gate. When `None`, behaviour is byte-identical to
/// [`run_selfheal_with_perf`] (every existing caller/test is unaffected — `judge_approved` falls back to
/// the static `config.judge_approved`).
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn run_selfheal_full(
    initial_files: Vec<(String, String)>,
    coder: &dyn Coder,
    tools: &dyn StageTools,
    scanner: &dyn SastScanner,
    config: &SelfHealConfig,
    perf: Option<&PerfSeams>,
    review: Option<&ReviewSeams>,
    semantic: Option<&SemanticGateSeams>,
    journal: &mut Journal,
) -> SelfHealOutcome {
    run_selfheal_reclassified(
        initial_files,
        coder,
        tools,
        scanner,
        config,
        perf,
        review,
        semantic,
        None,
        journal,
    )
}

/// [`run_selfheal_full`] **plus the mid-run escalate-only risk re-classification** (§3). This is the
/// fully-composed loop the live edit turn ([`crate::edit_turn::run_edit_turn_full`]) drives: it binds
/// the pre-edit baseline via [`ReclassifySeams`] so every round re-derives the tier from the *current
/// healed set* and folds it in with `max`. When `reclass` is `None` the behaviour is byte-identical
/// to [`run_selfheal_full`] (the frozen `config.tier` is used for every round) — every existing
/// caller/test is unaffected.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn run_selfheal_reclassified(
    initial_files: Vec<(String, String)>,
    coder: &dyn Coder,
    tools: &dyn StageTools,
    scanner: &dyn SastScanner,
    config: &SelfHealConfig,
    perf: Option<&PerfSeams>,
    review: Option<&ReviewSeams>,
    semantic: Option<&SemanticGateSeams>,
    reclass: Option<&ReclassifySeams>,
    journal: &mut Journal,
) -> SelfHealOutcome {
    let max = config.max_rounds.max(1);
    let mut files = initial_files;
    let mut detector = config.stuck.map(|(w, t)| StuckDetector::new(w, t));
    let mut cache = StageCache::new();
    let mut rerun_log: Vec<Vec<Stage>> = Vec::new();
    let mut last_report: Vec<StageReport> = Vec::new();
    let mut last_blocking = Stage::CommitGate;
    let mut last_review: Vec<ReviewFinding> = Vec::new();
    let mut last_judge: Option<PanelVerdict> = None;
    // The effective tier for this run. Starts at whatever the pre-stage-1 classifier produced and is
    // only ever raised — never lowered — by [`ReclassifySeams`] and the per-round escalators below.
    let mut tier_state = TierState {
        tier: config.tier,
        prior_finding: false,
    };

    for round in 0..max {
        // §3 mid-run re-classification (escalate-only). Re-derive the tier from the CURRENT healed
        // set against the pre-edit baseline: a fix that pulled in a settlement-path module, added a
        // file, or widened the blast radius moves the tier up before this round's gate runs. The
        // `prior_finding` escalator carries any earlier round's SAST/architecture finding.
        if let Some(rc) = reclass {
            let a = crate::classify::classify_edit(
                rc.baseline,
                &files,
                config.lang,
                tier_state.tier,
                config.rung,
                tier_state.prior_finding,
            );
            let reason = format!(
                "round {round} re-classification: {}",
                a.rationale.join("; ")
            );
            tier_state.escalate_to(a.tier, round, &reason, journal);
        }

        // Re-entry planning: which stages must re-run against the current file set's hash. Phase-A
        // stages always re-run; expensive stages cached across rounds when the file set is unchanged.
        let hash = content_hash(&file_map(&files));
        let planned = [
            Stage::Compile,
            Stage::Lint,
            Stage::TypeCheck,
            Stage::Test,
            Stage::Sast,
        ];
        let to_rerun = cache.stages_to_rerun(&planned, &hash);
        for s in &to_rerun {
            cache.record(*s, &hash);
        }
        rerun_log.push(to_rerun);

        // Run the deterministic stages, then the full gate.
        let ctx = StageContext {
            lang: config.lang,
            files: files.clone(),
        };
        let run = run_deterministic_stages(&ctx, tools, scanner);

        // Stage 6 — Performance Analysis. Only meaningful on a build that compiled (a non-compiling
        // edit fails Phase-A and blocks before scoring), so it runs only when the deterministic stages
        // produced no gating failure this round.
        let perf_report: Option<PerfReport> = match perf {
            Some(p) if run.failure_observation.is_none() => Some(analyze_perf(
                config.lang,
                p.baseline,
                &files,
                p.bench,
                p.advisor,
                &p.budget,
            )),
            _ => None,
        };
        let perf_penalty = perf_report.as_ref().map_or(0, |r| r.regression_penalty);

        // Fold the perf stage report into the report set so it is journaled + visible in the gap report.
        let mut reports = run.reports.clone();
        if let Some(r) = &perf_report {
            reports.push(r.stage_report());
        }

        // Stage 7 (Architecture Review) + Stage 8 (Regression Detection) — computed from the pre-edit
        // baseline vs the current healed set, overriding the caller-supplied scalars. Stage 7's count
        // hard-blocks in the gate; stage 8's coverage folds into the Confidence Score. Re-computed each
        // round so a coder that heals a forbidden import (or adds a covering test) clears the finding.
        let mut arch_violations = config.architecture_violations;
        let mut coverage = config.blast_radius_test_coverage;
        if let Some(sg) = semantic {
            // GAP-FIX gap6-semantic-lsp-signature-layermanifest item 3 — a `.arch.json` `LayerManifest`
            // checked into THIS turn's own healed file set is loaded and takes precedence over the
            // engine's statically-configured contract (`sg.contract`, `None` on the shipped default).
            // Re-resolved every round: a coder that adds/edits the manifest changes the boundary the
            // very next round evaluates, exactly like every other stage-7/8 input here.
            let resolved_contract = repo_layer_contract(&files, sg.contract);
            let sgr = analyze_semantic_gate(
                config.lang,
                sg.baseline,
                &files,
                resolved_contract.as_ref(),
                sg.cochange,
                sg.coupling_threshold,
            );
            arch_violations = sgr.architecture_violations;
            coverage = sgr.coverage;
            reports.push(sgr.arch_report);
            reports.push(sgr.regression_report);
        }

        // Stage 9 — LLM Review (finder) + the independent Judge panel (adjudicator). Runs only on a
        // green round (a candidate that failed a deterministic stage never reaches a model judge —
        // §5 guarantee #1). Findings fold into the Confidence Score; panel consensus drives the gate.
        let mut review_findings: Vec<ReviewFinding> = Vec::new();
        let mut judge_approved = config.judge_approved;
        // A static `config.judge_approved` is a self-asserted verdict with no panel behind it — it is
        // NOT an independent adjudication (§5). Only a real context-isolated panel run below sets this.
        let mut judge_independent = false;
        if let (Some(rev), true) = (review, run.failure_observation.is_none()) {
            let submission = CoderSubmission {
                candidate: joined(&files),
                self_summary: rev.self_summary.clone(),
            };
            review_findings = actionable_review(rev.reviewer, &submission, &rev.task);
            reports.push(StageReport {
                stage: Stage::LlmReview,
                verdict: if review_findings.is_empty() {
                    StageVerdict::Pass
                } else {
                    StageVerdict::Advisory {
                        detail: format!(
                            "{} actionable review finding(s) fed to the Confidence Score",
                            review_findings.len()
                        ),
                    }
                },
                // A model finding is not a deterministic verdict.
                deterministic: false,
            });
            // Context isolation is structural: the panel sees only `.candidate`, never `.self_summary`.
            let panel = rev.judges.evaluate_submission(&submission, &rev.criteria);
            judge_approved = Some(panel.consensus_pass);
            // The panel ran via `evaluate_submission`, which structurally withholds the self-summary
            // (`context_isolation_confirmed == true`) — the genuine independent adjudication §5 requires.
            judge_independent = panel.context_isolation_confirmed;
            last_judge = Some(panel);
            last_review = review_findings.clone();
        }

        last_report = reports.clone();

        // §3 Tier-3 trigger list — the current-round escalators. "any SAST finding at any severity"
        // and any unremediated architecture boundary violation force Tier 3 for THIS round's gate and
        // latch `prior_finding` for every later round. Only wired when the re-classification seam is
        // bound (the live edit turn always binds it); a bare `run_selfheal_full` is byte-identical to
        // before. Tier 3 is a mandatory human hand-off, never a hard user-facing block.
        if reclass.is_some() {
            if !run.sast_findings.is_empty() {
                let reason = format!(
                    "round {round}: {} SAST finding(s) — any SAST finding at any severity is a Tier-3 \
                     trigger (§3)",
                    run.sast_findings.len()
                );
                tier_state.prior_finding = true;
                tier_state.escalate_to(RiskTier::HighRisk, round, &reason, journal);
            }
            if arch_violations > 0 {
                let reason = format!(
                    "round {round}: {arch_violations} unremediated architecture boundary violation(s) \
                     — Tier-3 escalator (§3)"
                );
                tier_state.prior_finding = true;
                tier_state.escalate_to(RiskTier::HighRisk, round, &reason, journal);
            }
        }

        let confidence = ConfidenceInputs {
            sast: &run.sast_findings,
            perf_regression_penalty: perf_penalty,
            architecture_violations: arch_violations,
            blast_radius_test_coverage: coverage,
            review_findings: &review_findings,
            skipped_stages: 0, // folded from reports inside run_pipeline
            rung: config.rung,
        };
        let inputs = PipelineInputs {
            edit_id: journal_edit_id(journal),
            // The ESCALATED tier, never the frozen one the turn started with.
            tier: tier_state.tier,
            rung: config.rung,
            blast_fan_out: config.blast_fan_out,
            stage_reports: reports.clone(),
            sast: &run.sast_findings,
            confidence,
            architecture_violations: arch_violations,
            judge_approved,
            judge_independent,
            policy: config.policy,
        };
        let outcome = run_pipeline(inputs, journal);

        if let PipelineOutcome::Complete { .. } = &outcome {
            return SelfHealOutcome {
                outcome,
                rounds: round + 1,
                stuck: None,
                rerun_log,
                final_files: files,
                last_review,
                last_judge,
            };
        }

        // Not complete — capture the blocking stage + build the self-heal observation.
        last_blocking = outcome.stage();
        let observation = match &run.failure_observation {
            Some((stage, diags)) => Observation {
                stage: *stage,
                diagnostics: diags.clone(),
            },
            None => {
                // A green build that the gate still capped/blocked: the reason plus every actionable
                // LLM Review finding (with its cited lines), so the next round's Coder can address them.
                let mut diagnostics = vec![match &outcome {
                    PipelineOutcome::Capped { reason, .. } => reason.clone(),
                    PipelineOutcome::Blocked {
                        deterministic_failure,
                        ..
                    } => deterministic_failure.clone(),
                    PipelineOutcome::Complete { .. } => unreachable!(),
                }];
                for f in &review_findings {
                    diagnostics.push(format!(
                        "review[{:?}] lines {:?}: {}",
                        f.severity, f.lines, f.message
                    ));
                }
                Observation {
                    stage: last_blocking,
                    diagnostics,
                }
            }
        };

        // If this was the last permitted round, do not attempt another fix — cap honestly.
        if round + 1 >= max {
            journal.append(
                journal.len() as u64 + 1,
                PipelineEvent::RoundCapped {
                    rounds_exhausted: max,
                    stuck_detector_fired: false,
                    diagnosis: format!(
                        "round-cap reached at stage {:?} without clearing the gate",
                        last_blocking
                    ),
                },
            );
            return SelfHealOutcome {
                outcome: PipelineOutcome::Capped {
                    blocking_stage: last_blocking,
                    reason: format!(
                        "round-cap ({max}) exhausted at {last_blocking:?} without clearing the gate"
                    ),
                    rounds_exhausted: max,
                    gap_report: last_report,
                },
                rounds: max,
                stuck: None,
                rerun_log,
                final_files: files,
                last_review,
                last_judge,
            };
        }

        // Journal the self-heal trigger and ask the Coder to fix.
        journal.append(
            journal.len() as u64 + 1,
            PipelineEvent::SelfHealTriggered {
                stage: observation.stage,
                round: round + 1,
                observation: observation.diagnostics.join("; "),
            },
        );
        let fixed = coder.fix(round + 1, &files, &observation);

        // Stuck / thrash detection on the produced candidate — cut early with a diagnosis.
        if let Some(det) = detector.as_mut() {
            if let Some(diag) = det.observe(&joined(&fixed)) {
                journal.append(
                    journal.len() as u64 + 1,
                    PipelineEvent::RoundCapped {
                        rounds_exhausted: round + 1,
                        stuck_detector_fired: true,
                        diagnosis: diag.reason.clone(),
                    },
                );
                return SelfHealOutcome {
                    outcome: PipelineOutcome::Capped {
                        blocking_stage: last_blocking,
                        reason: format!(
                            "stuck: {} (thrash detected before round-cap)",
                            diag.reason
                        ),
                        rounds_exhausted: round + 1,
                        gap_report: last_report,
                    },
                    rounds: round + 1,
                    stuck: Some(diag),
                    rerun_log,
                    final_files: files,
                    last_review,
                    last_judge,
                };
            }
        }

        files = fixed;
    }

    // Unreachable in practice (the round+1>=max branch returns), but keep the honest-Capped invariant.
    SelfHealOutcome {
        outcome: PipelineOutcome::Capped {
            blocking_stage: last_blocking,
            reason: "round-cap exhausted".into(),
            rounds_exhausted: max,
            gap_report: last_report,
        },
        rounds: max,
        stuck: None,
        rerun_log,
        final_files: files,
        last_review,
        last_judge,
    }
}

/// The journal's edit id, echoed into each round's pipeline pass (best-effort from the first record).
fn journal_edit_id(journal: &Journal) -> String {
    journal
        .records()
        .iter()
        .find_map(|r| match &r.event {
            PipelineEvent::PipelineStarted { edit_id, .. } => Some(edit_id.clone()),
            _ => None,
        })
        .unwrap_or_else(|| "edit".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::Language;
    use crate::sast::BuiltinScanner;

    /// A Coder that flips a marker from "broken" to "fixed" once, converging.
    struct FixOnceCoder;
    impl Coder for FixOnceCoder {
        fn fix(
            &self,
            _round: u8,
            files: &[(String, String)],
            _o: &Observation,
        ) -> Vec<(String, String)> {
            files
                .iter()
                .map(|(p, c)| (p.clone(), c.replace("broken", "fixed")))
                .collect()
        }
    }

    /// A Coder that never changes anything (no progress).
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

    /// A Coder that oscillates A→B→A→B (thrash).
    struct ThrashCoder;
    impl Coder for ThrashCoder {
        fn fix(
            &self,
            round: u8,
            _files: &[(String, String)],
            _o: &Observation,
        ) -> Vec<(String, String)> {
            // Both candidates still fail compile ("broken") but differ → genuine oscillation, never
            // converging: the fix for one round re-breaks the previous state.
            let body = if round % 2 == 1 { "state A" } else { "state B" };
            vec![("a.rs".into(), format!("fn f() {{ /* {body} broken */ }}\n"))]
        }
    }

    /// Tools whose compile fails while the source still contains "broken".
    struct CompileGate;
    impl StageTools for CompileGate {
        fn compile(&self, ctx: &StageContext) -> crate::stages::ToolResult {
            if ctx.files.iter().any(|(_, c)| c.contains("broken")) {
                crate::stages::ToolResult::fail(vec!["E0999: still broken".into()])
            } else {
                crate::stages::ToolResult::pass()
            }
        }
        fn test(&self, _c: &StageContext) -> crate::stages::ToolResult {
            crate::stages::ToolResult::pass()
        }
        fn lint(&self, _c: &StageContext) -> crate::stages::ToolResult {
            crate::stages::ToolResult::pass()
        }
        fn type_check(&self, _c: &StageContext) -> crate::stages::ToolResult {
            crate::stages::ToolResult::pass()
        }
    }

    fn cfg() -> SelfHealConfig {
        SelfHealConfig {
            lang: Language::Rust,
            max_rounds: 5,
            stuck: Some((3, 0.9)),
            ..Default::default()
        }
    }

    #[test]
    fn gap_ainxt_pipeline_edit_04_self_heal_re_enters_and_converges_to_complete() {
        let files = vec![("a.rs".to_string(), "fn f() { /* broken */ }\n".to_string())];
        let mut j = Journal::new("edit-heal");
        let out = run_selfheal(
            files,
            &FixOnceCoder,
            &CompileGate,
            &BuiltinScanner,
            &cfg(),
            &mut j,
        );
        // Round 1 compile-fails (broken); the Coder fixes; round 2 completes.
        assert!(
            out.is_complete(),
            "expected Complete, got {:?}",
            out.outcome
        );
        assert_eq!(out.rounds, 2);
        // A SelfHealTriggered event was journaled (previously only ever in tests).
        assert!(j
            .records()
            .iter()
            .any(|r| matches!(r.event, PipelineEvent::SelfHealTriggered { .. })));
        assert_eq!(j.verify(), Ok(()));
        // The commit affordance is only obtainable from the Complete outcome.
        assert!(out.outcome.commit_approval().is_some());
    }

    #[test]
    fn gap_ainxt_pipeline_edit_04_round_cap_yields_real_rounds_exhausted_not_zero() {
        // The Coder never fixes → the loop caps honestly with the REAL round count (was hard-coded 0).
        let files = vec![("a.rs".to_string(), "fn f() { /* broken */ }\n".to_string())];
        let mut cfg = cfg();
        cfg.stuck = None; // isolate the round-cap path
        cfg.max_rounds = 4;
        let mut j = Journal::new("edit-cap");
        let out = run_selfheal(
            files,
            &NoOpCoder,
            &CompileGate,
            &BuiltinScanner,
            &cfg,
            &mut j,
        );
        match &out.outcome {
            PipelineOutcome::Capped {
                rounds_exhausted, ..
            } => assert_eq!(*rounds_exhausted, 4),
            other => panic!("expected Capped, got {other:?}"),
        }
        assert_eq!(out.rounds, 4);
        assert!(!out.is_complete());
        // A RoundCapped event was journaled.
        assert!(j.records().iter().any(|r| matches!(
            r.event,
            PipelineEvent::RoundCapped {
                stuck_detector_fired: false,
                ..
            }
        )));
    }

    #[test]
    fn gap_ainxt_pipeline_edit_04_stuck_detector_cuts_thrash_before_the_cap() {
        // The Coder oscillates; with a big cap the round-cap alone would burn all rounds, but the
        // stuck detector fires early with a diagnosis.
        let files = vec![("a.rs".to_string(), "fn f() { /* broken */ }\n".to_string())];
        let mut cfg = cfg();
        cfg.max_rounds = 20;
        cfg.stuck = Some((3, 0.9));
        let mut j = Journal::new("edit-thrash");
        let out = run_selfheal(
            files,
            &ThrashCoder,
            &CompileGate,
            &BuiltinScanner,
            &cfg,
            &mut j,
        );
        assert!(!out.is_complete());
        assert!(out.stuck.is_some(), "stuck detector should have fired");
        // Cut well before the 20-round cap.
        assert!(out.rounds < 20);
        match &out.outcome {
            PipelineOutcome::Capped { reason, .. } => assert!(reason.contains("stuck")),
            other => panic!("expected Capped, got {other:?}"),
        }
        assert!(j.records().iter().any(|r| matches!(
            r.event,
            PipelineEvent::RoundCapped {
                stuck_detector_fired: true,
                ..
            }
        )));
    }

    #[test]
    fn re_entry_log_shows_phase_a_always_reruns() {
        let files = vec![("a.rs".to_string(), "fn f() { /* broken */ }\n".to_string())];
        let mut j = Journal::new("edit-reentry");
        let out = run_selfheal(
            files,
            &FixOnceCoder,
            &CompileGate,
            &BuiltinScanner,
            &cfg(),
            &mut j,
        );
        // Each round re-ran the Phase-A basics (never trusts a "small" fix to skip them).
        for round_stages in &out.rerun_log {
            assert!(round_stages.contains(&Stage::Compile));
            assert!(round_stages.contains(&Stage::Test));
        }
    }
}
