// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! The **one clean surface entrypoint** onto the Code-Review Pipeline + the semantic-edit engine
//! (`docs/architecture/CODE_REVIEW_PIPELINE.md` §1). A product surface (SDLC pipeline, Code profile,
//! an MR/PR review bot, the CLI) never reaches into the pipeline's internals; it calls exactly one of
//! two functions and consumes a typed outcome:
//!
//! - [`run_edit`] — an **editing** turn. Verify → self-heal → LLM Review (stage 9) → independent Judge
//!   panel (§5) → Commit Gate, and — iff the gate reaches `Complete` — an atomic durable write to the
//!   [`WorkspaceSink`]. The commit affordance is reachable ONLY through a `CommitApproval`, so a
//!   surface has no code path to "done" without a real `Complete`. This is the semantic-edit engine's
//!   public face (an [`EditTurn`] can be materialized from a raw edit set or a planned semantic op via
//!   [`crate::run_semantic_turn`]).
//!
//! - [`run_review`] — a **review-only** turn (no write, no sink). It runs the SAME pipeline core over a
//!   candidate — deterministic Phase-A stages, SAST, the LLM Review finder, and the context-isolated
//!   Judge panel — and returns the findings + panel verdict + the typed [`PipelineOutcome`]. This is
//!   what a code-review surface calls to adjudicate a proposed change WITHOUT applying it.
//!
//! Both include the LLM Review + Judge behind the `ainxt-judge` model seams ([`Reviewer`] finder +
//! [`JudgePanel`] adjudicator); a deployment wires a model-backed pair, the offline tests wire a
//! deterministic pair. The anti-sycophancy split is preserved: the finder may see the coder's
//! self-summary, the Judge panel structurally never does.

use crate::confidence::{compute, ConfidenceInputs, ConfidenceScore};
use crate::edit_turn::{run_edit_turn_full, EditTurn, TurnOutcome};
use crate::gate::GatePolicy;
use crate::journal::Journal;
use crate::outcome::PipelineOutcome;
use crate::perf::PerfConfig;
use crate::pipeline::{run_pipeline, PipelineInputs};
use crate::risk::RiskTier;
use crate::sast::SastScanner;
use crate::selfheal::{Coder, ReviewSeams, SelfHealConfig};
use crate::stage::{Stage, StageReport, StageVerdict};
use crate::stages::{run_deterministic_stages, StageContext, StageTools};
use ainxt_judge::{actionable_review, CoderSubmission, PanelVerdict, ReviewFinding};
use ainxt_semantic::ladder::Rung;
use serde::{Deserialize, Serialize};

/// Run one **editing** turn through the fully-composed pipeline (self-heal + perf + LLM Review + Judge)
/// and commit iff the gate clears. The single call a surface makes to *change* code.
///
/// `perf` enables Performance Analysis (stage 6) when `Some`; `review` enables the LLM Review
/// (stage 9) with a Judge panel (§5) when `Some`. The durable-write invariant is unchanged — a commit is reachable
/// only through a `CommitApproval` from a pipeline `Complete`.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn run_edit(
    turn: EditTurn,
    coder: &dyn Coder,
    tools: &dyn StageTools,
    scanner: &dyn SastScanner,
    perf: Option<PerfConfig<'_>>,
    review: Option<&ReviewSeams>,
    sink: &mut dyn ainxt_semantic::workspace::WorkspaceSink,
    journal: &mut Journal,
) -> TurnOutcome {
    // `run_edit` keeps its public signature; the stage-7/8 semantic seam is opted into via the
    // long-lived `EditEngine::with_semantic_review` path (or `run_edit_turn_full` directly).
    run_edit_turn_full(
        turn, coder, tools, scanner, perf, review, None, sink, journal,
    )
}

/// A review-only request: the candidate file set under review + the risk/language config. No coder and
/// no sink — a review never self-heals and never writes.
///
/// The **route-ready wire shape** [`crate::edit_turn::EditEngine::run_review_for`] deserializes at
/// `POST /v1/edit/review` (`deny_unknown_fields` rejects a smuggled extra key, mirroring
/// [`crate::edit_turn::EditRequest`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewRequest {
    pub edit_id: String,
    /// `(path, source)` for every file in the candidate under review.
    pub files: Vec<(String, String)>,
    /// The risk tier + language + rung + gate policy the review is scored under. `max_rounds`/`stuck`
    /// are ignored (a review is a single pass). The gate-policy/judge/round-cap/coverage fields are
    /// sealed against the deployment's policy at the `*_for` wire boundary exactly like every other
    /// route-ready request — see [`crate::edit_turn::EditEngine::run_review_for`].
    pub config: SelfHealConfig,
}

/// The typed, **route-ready serializable** result of a review-only turn.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewOutcome {
    /// The typed pipeline verdict (`Complete` = the change would clear the gate; `Capped`/`Blocked` =
    /// an honest gap report). A review NEVER produces a commit affordance — even a `Complete` here is
    /// advisory (there is no sink to write to).
    pub outcome: PipelineOutcome,
    /// The actionable LLM Review (stage 9) findings.
    pub findings: Vec<ReviewFinding>,
    /// The independent Judge panel's verdict — `None` iff the candidate failed a deterministic stage
    /// (a broken build never reaches the panel — §5 guarantee #1).
    pub verdict: Option<PanelVerdict>,
    /// The full, auditable Confidence Score the gate consumed.
    pub confidence: ConfidenceScore,
}

impl ReviewOutcome {
    /// Whether the reviewed change would clear the Commit Gate. Advisory only — a review writes nothing.
    #[must_use]
    pub fn would_complete(&self) -> bool {
        self.outcome.is_complete()
    }
}

/// Run one **review-only** turn: the SAME pipeline core over a candidate — deterministic Phase-A
/// stages + SAST, then (on a green build) the LLM Review finder + the context-isolated Judge panel —
/// producing the findings, the panel verdict, and the typed [`PipelineOutcome`]. Nothing is written;
/// there is no sink and no self-heal. Every step is journaled to the hash-chained [`Journal`].
///
/// A candidate that fails a deterministic stage is `Blocked` before scoring and NEVER reaches the
/// panel (`verdict = None`) — you do not ask a model whether code that does not compile is good.
#[must_use]
pub fn run_review(
    req: ReviewRequest,
    tools: &dyn StageTools,
    scanner: &dyn SastScanner,
    seams: &ReviewSeams,
    journal: &mut Journal,
) -> ReviewOutcome {
    let ctx = StageContext {
        lang: req.config.lang,
        files: req.files.clone(),
    };
    let run = run_deterministic_stages(&ctx, tools, scanner);

    // The LLM Review finder + the Judge panel run ONLY on a green build (a candidate that failed a
    // deterministic stage never reaches a model judge — §5 guarantee #1).
    let mut reports = run.reports.clone();
    let mut findings: Vec<ReviewFinding> = Vec::new();
    let mut verdict: Option<PanelVerdict> = None;
    let mut judge_approved: Option<bool> = req.config.judge_approved;
    // A static `config.judge_approved` is self-asserted (no panel) → not an independent adjudication.
    let mut judge_independent = false;

    if run.failure_observation.is_none() {
        let submission = CoderSubmission {
            candidate: joined(&req.files),
            self_summary: seams.self_summary.clone(),
        };
        findings = actionable_review(seams.reviewer, &submission, &seams.task);
        reports.push(StageReport {
            stage: Stage::LlmReview,
            verdict: if findings.is_empty() {
                StageVerdict::Pass
            } else {
                StageVerdict::Advisory {
                    detail: format!("{} actionable review finding(s)", findings.len()),
                }
            },
            deterministic: false,
        });
        // Context isolation is structural: the panel sees only `.candidate`, never `.self_summary`.
        let panel = seams
            .judges
            .evaluate_submission(&submission, &seams.criteria);
        judge_approved = Some(panel.consensus_pass);
        judge_independent = panel.context_isolation_confirmed;
        verdict = Some(panel);
    }

    // A skip is a penalty, never free — count what the reports show so the returned Confidence Score
    // matches exactly the one the gate consumed inside `run_pipeline`.
    let skipped_stages = reports.iter().filter(|r| r.verdict.is_skipped()).count() as u32;
    let ci = ConfidenceInputs {
        sast: &run.sast_findings,
        perf_regression_penalty: 0,
        architecture_violations: req.config.architecture_violations,
        blast_radius_test_coverage: req.config.blast_radius_test_coverage,
        review_findings: &findings,
        skipped_stages,
        rung: req.config.rung,
    };
    let confidence = compute(&ci);

    let inputs = PipelineInputs {
        edit_id: req.edit_id,
        tier: req.config.tier,
        rung: req.config.rung,
        blast_fan_out: 0,
        stage_reports: reports,
        sast: &run.sast_findings,
        confidence: ci,
        architecture_violations: req.config.architecture_violations,
        judge_approved,
        judge_independent,
        policy: req.config.policy,
    };
    let outcome = run_pipeline(inputs, journal);

    ReviewOutcome {
        outcome,
        findings,
        verdict,
        confidence,
    }
}

/// Convenience: a default review config for a given tier/language, single-pass (no self-heal budget).
#[must_use]
pub fn review_config(
    lang: crate::capability::Language,
    tier: RiskTier,
    rung: Rung,
) -> SelfHealConfig {
    SelfHealConfig {
        lang,
        tier,
        rung,
        max_rounds: 1,
        stuck: None,
        blast_radius_test_coverage: 1.0,
        architecture_violations: 0,
        judge_approved: None,
        policy: GatePolicy::default(),
        blast_fan_out: 0,
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
