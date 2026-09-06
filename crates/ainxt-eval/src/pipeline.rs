// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! The offline **release gate as one merge-blocking pipeline** (EVAL_PLATFORM.md §11; gaps [40]/[41]/
//! AQ/X — the composition keystone).
//!
//! Every rigorous instrument in this crate — [`crate::manifest::meta_gate_eval_set`], the sealed
//! corpus ([`crate::integrity::SealedManifest`] + [`crate::integrity::SealedCorpusStore`]),
//! [`crate::integrity::scan_contamination`], Judge governance ([`crate::audit::route_judge`] +
//! [`crate::judge::admit_judge`] + [`crate::judge::judge_drift`]), the **statistically-valid gate**
//! ([`crate::stats::statistical_gate`], gap [40]), the overfit tripwire
//! ([`crate::integrity::Tripwire`]), the [`crate::vault::RegressionVault`], and the reproduce-from-SHA
//! [`crate::audit::VerdictRecord`] written to the [`crate::audit::EventSink`] **before a change ships**
//! — existed but was invoked *only from its own unit tests*. Nothing composed them, and the thing that
//! actually ran downstream was the naive [`crate::evaluate_gate`] (aggregate pass-rate arithmetic — "a
//! gate that blocks on `candidate_mean < baseline_mean` blocks on coin-flips").
//!
//! This module is the composition: [`run_release_gate`] is the single entrypoint a CI merge-check /
//! the dogfooded eval runner calls. It is **fail-closed** (any stage that cannot be evaluated blocks,
//! never silently passes), **statistically-valid** (the ship decision is the per-cell
//! [`crate::stats::statistical_gate`], not a mean comparison), **enterprise-grade** (honours a
//! cancellation token and a per-run case budget / back-pressure), and **auditable** (a deterministic,
//! reproduce-from-SHA verdict is written to the Event Log before the decision is returned).
//!
//! All I/O is through the same trait seams as the rest of the crate, so this composition is exercised
//! end-to-end against fakes here and wired to the real encrypted store / Event Log / dogfood runner by
//! the parent (see the crate `needs_wiring` note).

use crate::audit::{params_hash, route_judge, EventSink, JudgeRoutingError, VerdictRecord};
use crate::integrity::{
    plan_rotation, scan_contamination, ContaminationPolicy, EvalCaseContent, HoldoutCase,
    SealedCorpusStore, SealedManifest, Tripwire,
};
use crate::judge::{admit_judge, judge_drift, CalibrationFloors, JudgeSpec};
use crate::manifest::{meta_gate_eval_set, EvalSetManifest};
use crate::stats::{statistical_gate, GateReport, MetricCell};
use crate::vault::{route_restored, RegressionVault};
use crate::{EvalCase, EvalSystem, QualityJudge};
use ainxt_types::DataClass;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// One gold-set case as the release gate sees it: the underlying [`EvalCase`] plus the cell it belongs
/// to (`metric × model_family × category`, §5.4), its per-metric non-inferiority margin, whether the
/// cell is in the hard-safety subset (family-wise control), and whether it is a never-tuned tripwire
/// case (overfit detector, excluded from the visible mean).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GatedCase {
    pub case: EvalCase,
    /// Cell key — cases sharing a cell are tested together (`metric×model×category`).
    pub cell: String,
    /// Non-inferiority margin (metric units, ≥ 0) for this cell.
    pub margin: f64,
    /// Hard-safety cell (data-class-leak / redaction / RBAC) → family-wise (Holm) control.
    pub hard_safety: bool,
    /// A never-tuned tripwire case (excluded from tuning; feeds the overfit tripwire).
    pub tripwire: bool,
}

impl GatedCase {
    pub fn new(case: EvalCase, cell: &str, margin: f64, hard_safety: bool, tripwire: bool) -> Self {
        GatedCase {
            case,
            cell: cell.to_string(),
            margin,
            hard_safety,
            tripwire,
        }
    }
}

/// Judge calibration + drift evidence supplied for the run (from the sealed calibration corpus, scored
/// out-of-band by the runner). Kept as label sequences so this crate stays free of any ML dependency.
#[derive(Debug, Clone)]
pub struct JudgeCalibration<'a> {
    /// Adjudicated human gold labels over the calibration cases.
    pub gold_labels: &'a [String],
    /// The candidate Judge's labels over the same calibration cases (admission check).
    pub judge_labels: &'a [String],
    /// The κ the Judge was originally admitted at (drift re-audit baseline).
    pub admission_kappa: f64,
    /// The Judge's labels over the (unchanged) gold set *now* — for the silent-provider-swap re-audit.
    pub current_labels: &'a [String],
    /// Max acceptable κ drop before the Judge is quarantined.
    pub max_kappa_drop: f64,
}

/// Contamination evidence: the candidate's own prompts / retrieved context / fine-tune snippets and
/// their embeddings, scanned against the eval-case corpus content.
#[derive(Debug, Clone)]
pub struct ContaminationScan<'a> {
    pub candidate_texts: &'a [String],
    pub candidate_embeddings: &'a [Vec<f32>],
    pub eval_case_content: &'a [EvalCaseContent],
    pub policy: ContaminationPolicy,
}

/// Rotation hygiene inputs (§9.3): the holdout bookkeeping + thresholds. Rotation-due is surfaced as a
/// non-blocking warning (a stale-but-not-yet-rotated set still gates; an operator is told to rotate).
#[derive(Debug, Clone)]
pub struct RotationInputs<'a> {
    pub holdout: &'a [HoldoutCase],
    pub now_epoch: u64,
    pub max_age_epochs: u64,
    pub max_uses: u64,
}

/// Regression-Vault inputs: the current sealed vault, the case ids this route previously tripped, the
/// vault-case ids the candidate now passes (run by the caller through the candidate against the frozen
/// expectation), and the prior vault snapshot for the monotonicity proof.
#[derive(Debug, Clone)]
pub struct VaultInputs<'a> {
    pub vault: &'a RegressionVault,
    pub previously_tripped: &'a [String],
    pub now_passing: &'a BTreeSet<String>,
    pub prior_snapshot: Option<&'a RegressionVault>,
}

/// Statistical + audit configuration for the run (mirrors the pre-registration).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ReleaseGateConfig {
    /// Family-wise α for the hard-safety subset.
    pub alpha: f64,
    /// FDR q for the ordinary cells.
    pub q: f64,
    /// Target power (recorded in the params hash; the set is power-checked by the meta-gate).
    pub power: f64,
    /// Max cases this run may score (back-pressure / budget). 0 = unlimited.
    pub max_cases: usize,
    /// Apply CUPED variance reduction to the paired per-cell diffs using the baseline (pre-period)
    /// per-case score as the covariate (§5.3). Lower variance ⇒ the same set reaches adequate power,
    /// so a real regression is not lost in noise. On by default; disable only for A/B diagnostics.
    pub use_cuped: bool,
}

impl Default for ReleaseGateConfig {
    fn default() -> Self {
        ReleaseGateConfig {
            alpha: 0.05,
            q: 0.05,
            power: 0.8,
            max_cases: 0,
            use_cuped: true,
        }
    }
}

/// The full request for a release-gate run. Everything is a reference or a trait seam so the pipeline
/// owns nothing and is exercised against fakes in-crate and real stores by the parent.
pub struct ReleaseGateRequest<'a> {
    /// The git-reviewable eval-set manifest (identity + pre-registration + content commitment).
    pub manifest: &'a EvalSetManifest,
    /// Observed sample SD per primary metric (aligned with the manifest's primary metrics) — the
    /// power check needs it. Underpowered ⇒ the set fails as a defect.
    pub primary_sds: &'a [f64],
    /// The sealed corpus store; only the runner identity may read the gold answers.
    pub sealed_store: &'a dyn SealedCorpusStore,
    pub runner_identity: &'a str,
    /// The gated gold cases (order aligned with the sealed corpus for the integrity check).
    pub cases: &'a [GatedCase],
    /// Baseline + candidate systems under eval (paired design — same cases through both).
    pub baseline: &'a dyn EvalSystem,
    pub candidate: &'a dyn EvalSystem,
    /// The scoring Judge seam + its pinned spec (for versioning / self-preference / routing).
    pub judge: &'a dyn QualityJudge,
    pub judge_spec: &'a JudgeSpec,
    /// The data class of the eval (regulated ⇒ in-house-only Judge, fail-closed).
    pub data_class: DataClass,
    /// The pinned Judges available to route among.
    pub available_judges: &'a [JudgeSpec],
    pub calibration: JudgeCalibration<'a>,
    pub floors: CalibrationFloors,
    pub contamination: ContaminationScan<'a>,
    pub rotation: RotationInputs<'a>,
    pub vault: VaultInputs<'a>,
    /// The candidate control-plane commit SHA (reproduce-from-SHA).
    pub candidate_sha: &'a str,
    pub seed: u64,
    /// The Event-Log epoch this verdict is minted at (deterministic — no clock).
    pub epoch: u64,
    pub config: ReleaseGateConfig,
    /// Optional cooperative cancellation. Checked before and during the (expensive) scoring loop; a
    /// cancelled run is [`ReleaseDecision::Indeterminate`] — never a silent pass.
    pub cancel: Option<&'a dyn Fn() -> bool>,
    /// Optional **Judge panel** for the hard-safety cells (§4.4). When present, each hard-safety case
    /// is scored by every panel member; the ensemble MEDIAN score is what enters the statistical cell
    /// (robust to a single Judge outlier), and a batch whose escalation rate exceeds the panel's
    /// tolerance BLOCKS the gate — a rubric humans-plus-machines can't agree on cannot certify a
    /// payment-grade change. Absent ⇒ single-Judge scoring (low-stakes/high-volume path).
    pub panel: Option<PanelInputs<'a>>,
}

/// Judge-panel inputs for the hard-safety subset (§4.4). `judges` MUST align 1:1 with the panel's
/// members (same order); each scores every hard-safety case and the votes are aggregated by
/// [`crate::judge::JudgePanel::aggregate`].
pub struct PanelInputs<'a> {
    pub panel: &'a crate::judge::JudgePanel,
    pub judges: &'a [&'a dyn QualityJudge],
    /// Score at/above which a member's categorical vote is "good" (below ⇒ "bad"). The ensemble votes
    /// on this label so genuine good/bad disagreement — not tiny numeric jitter — drives escalation.
    pub good_label_threshold: u8,
    /// Max escalation rate across the hard-safety batch before the rubric is deemed defective (block).
    pub max_escalation_rate: f64,
}

/// The ship/block/indeterminate decision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ReleaseDecision {
    /// Every stage passed — the change may merge/ship.
    Ship,
    /// One or more stages blocked — carries every failing reason (author sees all at once).
    Block(Vec<String>),
    /// The run could not be completed (cancelled / over budget / corpus unavailable) — fail-closed,
    /// never a pass.
    Indeterminate(String),
}

impl ReleaseDecision {
    pub fn is_ship(&self) -> bool {
        matches!(self, ReleaseDecision::Ship)
    }
    /// The stable audit string for the Event-Log record.
    pub fn outcome_str(&self) -> &'static str {
        match self {
            ReleaseDecision::Ship => "pass",
            ReleaseDecision::Block(_) => "block",
            ReleaseDecision::Indeterminate(_) => "indeterminate",
        }
    }
}

/// The full, serializable report of a release-gate run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReleaseGateReport {
    pub decision: ReleaseDecision,
    /// Per-cell statistical verdicts (present once scoring ran).
    pub statistical: Option<GateReport>,
    /// Non-blocking operational warnings (e.g. rotation due).
    pub warnings: Vec<String>,
    /// The reproduce-from-SHA verdict record written to the Event Log before the decision returned.
    pub verdict: VerdictRecord,
    /// The Judge version the score was produced under.
    pub judge_version: String,
    /// The number of cases actually scored.
    pub scored: usize,
}

impl ReleaseGateReport {
    pub fn is_ship(&self) -> bool {
        self.decision.is_ship()
    }
}

/// Build the deterministic verdict record for the run (reproduce-from-SHA, §12).
fn build_verdict(
    req: &ReleaseGateRequest<'_>,
    judge_version: &str,
    outcome: &str,
    effect: f64,
) -> VerdictRecord {
    VerdictRecord {
        eval_set_id: req.manifest.set_id.clone(),
        eval_set_version: req.manifest.version.clone(),
        judge_version: judge_version.to_string(),
        candidate_sha: req.candidate_sha.to_string(),
        params_hash: params_hash(
            // Use the smallest primary margin as the pre-registered representative margin.
            req.manifest
                .pre_registration
                .metrics
                .iter()
                .filter(|m| m.primary)
                .map(|m| m.noninferiority_margin)
                .fold(f64::INFINITY, f64::min),
            req.config.alpha,
            req.config.power,
            &req.manifest.pre_registration.method,
        ),
        seed: req.seed,
        dimension: req.manifest.dimension.clone(),
        outcome: outcome.to_string(),
        effect,
        epoch: req.epoch,
    }
}

/// Run the composed, statistically-valid, fail-closed release gate and write the reproduce-from-SHA
/// verdict to `sink` **before** returning the decision. This is the single merge-blocking entrypoint.
///
/// Stages (all contribute to a single decision; scoring is guarded behind the integrity/governance
/// checks it depends on):
/// 1. **Budget / cancellation** — over-budget or cancelled ⇒ [`ReleaseDecision::Indeterminate`].
/// 2. **Meta-gate** — the set's pre-registration is well-formed and it is powered for its MDE (§5.3).
/// 3. **Sealed corpus** — load with the runner identity (a non-runner is refused) and verify the
///    Merkle content commitment (a swapped/tampered corpus fails, §9.1).
/// 4. **Judge governance** — route by data class (regulated ⇒ in-house-only, fail-closed), admit
///    against the Gold labels (κ + balanced accuracy), and re-audit for silent-swap drift (§4).
/// 5. **Contamination** — the candidate must not have memorized the eval (§9.2).
/// 6. **Statistical gate** — paired per-case scoring → per-cell [`statistical_gate`] with FDR / Holm
///    correction (§5.4). *This* is the ship decision, not a mean comparison (gap [40]).
/// 7. **Tripwire** — the candidate must not overfit the visible set vs the sealed tripwire slice.
/// 8. **Regression Vault** — the vault verifies + is monotonic, and a previously-regressed route is
///    restored only by passing the exact frozen cases (§10).
/// 9. **Rotation** — a rotation-due holdout is surfaced as a warning (non-blocking).
pub fn run_release_gate(
    req: &ReleaseGateRequest<'_>,
    sink: &mut dyn EventSink,
) -> ReleaseGateReport {
    let judge_version = req.judge_spec.version();
    let mut warnings: Vec<String> = Vec::new();

    // ---- Stage 1: budget + cancellation (fail-closed) --------------------------------------
    if req.config.max_cases != 0 && req.cases.len() > req.config.max_cases {
        return finalize_indeterminate(
            req,
            sink,
            &judge_version,
            format!(
                "case budget exceeded: {} cases > max {} (back-pressure)",
                req.cases.len(),
                req.config.max_cases
            ),
        );
    }
    if is_cancelled(req) {
        return finalize_indeterminate(
            req,
            sink,
            &judge_version,
            "run cancelled before scoring".to_string(),
        );
    }

    let mut block_reasons: Vec<String> = Vec::new();

    // ---- Stage 2: meta-gate (set powered + pre-registration well-formed) --------------------
    let meta = meta_gate_eval_set(req.manifest, scored_per_arm(req), req.primary_sds);
    if let crate::manifest::MetaGateOutcome::Fail(rs) = meta {
        for r in rs {
            block_reasons.push(format!("meta-gate: {r}"));
        }
    }

    // ---- Stage 3: sealed corpus load + integrity -------------------------------------------
    // The corpus is required to score; a failure here is a hard block and scoring is skipped.
    let sealed = req.sealed_store.load(
        &req.manifest.set_id,
        &req.manifest.version,
        req.runner_identity,
    );
    let corpus_ok = match &sealed {
        None => {
            block_reasons.push(format!(
                "sealed corpus unavailable to identity '{}' (contamination defense / unknown set)",
                req.runner_identity
            ));
            false
        }
        Some(cases) => {
            // Rebuild the manifest from the loaded cases and compare to the committed root.
            let m = SealedManifest::build(&req.manifest.set_id, &req.manifest.version, cases);
            if m.content_commitment != req.manifest.content_commitment {
                block_reasons.push(
                    "sealed corpus does not match the manifest content commitment (tamper/swap)"
                        .to_string(),
                );
                false
            } else {
                true
            }
        }
    };

    // ---- Stage 4: Judge governance (routing → admission → drift) ----------------------------
    let mut judge_ok = true;
    match route_judge(
        req.data_class,
        &req.manifest.dimension,
        req.available_judges,
    ) {
        Err(JudgeRoutingError::NoEligibleInHouseJudge { data_class }) => {
            judge_ok = false;
            block_reasons.push(format!(
                "no in-house Judge for regulated data class '{data_class}' (never falls back to cloud)"
            ));
        }
        Err(JudgeRoutingError::NoJudgeForDimension { dimension }) => {
            judge_ok = false;
            block_reasons.push(format!("no Judge registered for dimension '{dimension}'"));
        }
        Ok(_) => {}
    }
    let admission = admit_judge(
        req.judge_spec,
        req.calibration.gold_labels,
        req.calibration.judge_labels,
        &req.floors,
    );
    if let crate::judge::JudgeAdmission::Rejected { reasons, .. } = &admission {
        judge_ok = false;
        for r in reasons {
            block_reasons.push(format!("judge not admitted: {r}"));
        }
    }
    let drift = judge_drift(
        req.calibration.admission_kappa,
        req.calibration.gold_labels,
        req.calibration.current_labels,
        req.calibration.max_kappa_drop,
    );
    if let crate::judge::JudgeDrift::Drifted { drop, .. } = &drift {
        judge_ok = false;
        block_reasons.push(format!(
            "judge calibration drift: κ dropped {drop:.3} (likely a silent provider model swap) — quarantine"
        ));
    }

    // ---- Stage 5: contamination -------------------------------------------------------------
    let contam = scan_contamination(
        req.contamination.candidate_texts,
        req.contamination.candidate_embeddings,
        req.contamination.eval_case_content,
        &req.contamination.policy,
    );
    if let crate::integrity::ContaminationVerdict::Contaminated(hits) = &contam {
        block_reasons.push(format!(
            "contamination: candidate memorized {} eval case(s) — false-positive pass (defect)",
            hits.len()
        ));
    }

    // ---- Stage 6: the statistically-valid gate (only if corpus + judge are trustworthy) -----
    let mut statistical: Option<GateReport> = None;
    let mut scored = 0usize;
    let mut worst_effect = 0.0f64;
    if corpus_ok && judge_ok {
        match score_and_gate(req) {
            Ok((gate, n, effect, panel_blocks)) => {
                scored = n;
                worst_effect = effect;
                if !gate.passed() {
                    for name in gate.blocking() {
                        block_reasons.push(format!("statistical regression in cell '{name}'"));
                    }
                }
                // Judge-panel systematic-disagreement blocks (hard-safety cells, §4.4).
                for b in panel_blocks {
                    block_reasons.push(b);
                }
                // Stage 7: overfit tripwire (needs the per-arm scores computed during scoring).
                if let Some(crate::integrity::OverfitVerdict::Overfit { drop, .. }) =
                    tripwire_check(req)
                {
                    block_reasons.push(format!(
                        "overfit: candidate drops {drop:.2} on the never-tuned tripwire slice"
                    ));
                }
                statistical = Some(gate);
            }
            Err(e) => {
                // Scoring itself could not complete (cancelled mid-run) — fail-closed.
                return finalize_indeterminate(req, sink, &judge_version, e);
            }
        }
    } else {
        warnings.push(
            "scoring skipped: corpus/judge integrity failed — decision is block, not a pass".into(),
        );
    }

    // ---- Stage 8: Regression Vault ----------------------------------------------------------
    if !req.vault.vault.verify_all() {
        block_reasons.push("regression vault contains a tampered case (seal mismatch)".into());
    }
    if let Some(prior) = req.vault.prior_snapshot {
        if !req.vault.vault.is_monotonic_over(prior) {
            block_reasons
                .push("regression vault is not monotonic — a prior frozen case was dropped".into());
        }
    }
    if !req.vault.previously_tripped.is_empty()
        && !route_restored(req.vault.previously_tripped, req.vault.now_passing)
    {
        let missing: Vec<&str> = req
            .vault
            .previously_tripped
            .iter()
            .filter(|id| !req.vault.now_passing.contains(*id))
            .map(|s| s.as_str())
            .collect();
        block_reasons.push(format!(
            "route not restored: still failing frozen vault case(s) {missing:?} — a live threshold cannot restore it"
        ));
    }

    // ---- Stage 9: rotation hygiene (non-blocking warning) -----------------------------------
    let due = plan_rotation(
        req.rotation.holdout,
        req.rotation.now_epoch,
        req.rotation.max_age_epochs,
        req.rotation.max_uses,
    );
    if !due.is_empty() {
        warnings.push(format!(
            "rotation due: {} holdout case(s) should be retired ({due:?})",
            due.len()
        ));
    }

    // ---- Finalize: decision + reproduce-from-SHA verdict written BEFORE returning -----------
    let decision = if block_reasons.is_empty() {
        ReleaseDecision::Ship
    } else {
        block_reasons.sort();
        block_reasons.dedup();
        ReleaseDecision::Block(block_reasons)
    };
    let verdict = build_verdict(req, &judge_version, decision.outcome_str(), worst_effect);
    sink.append(&verdict);
    ReleaseGateReport {
        decision,
        statistical,
        warnings,
        verdict,
        judge_version,
        scored,
    }
}

/// Emit an indeterminate (fail-closed) report, still writing an auditable verdict to the Event Log.
fn finalize_indeterminate(
    req: &ReleaseGateRequest<'_>,
    sink: &mut dyn EventSink,
    judge_version: &str,
    reason: String,
) -> ReleaseGateReport {
    let verdict = build_verdict(req, judge_version, "indeterminate", 0.0);
    sink.append(&verdict);
    ReleaseGateReport {
        decision: ReleaseDecision::Indeterminate(reason),
        statistical: None,
        warnings: Vec::new(),
        verdict,
        judge_version: judge_version.to_string(),
        scored: 0,
    }
}

fn is_cancelled(req: &ReleaseGateRequest<'_>) -> bool {
    req.cancel.map(|c| c()).unwrap_or(false)
}

/// Cases per arm for the power check (paired design: the non-tripwire gold cases).
fn scored_per_arm(req: &ReleaseGateRequest<'_>) -> usize {
    req.cases.iter().filter(|c| !c.tripwire).count()
}

/// Accumulated per-cell scoring state: candidate−baseline diffs, the baseline scores used as the
/// CUPED covariate, the margin, whether hard-safety, and (for hard-safety cells when a panel is
/// wired) the ensemble verdicts.
struct CellAccum {
    diffs: Vec<f64>,
    /// Baseline (pre-period) per-case score — the CUPED covariate (§5.3).
    covariate: Vec<f64>,
    margin: f64,
    hard_safety: bool,
    panel_verdicts: Vec<crate::judge::PanelVerdict>,
}

/// Paired scoring: run every case through baseline + candidate, score both with the Judge, and build
/// one [`MetricCell`] of `candidate − baseline` diffs per cell. Variance is reduced with **CUPED**
/// (§5.3) using the baseline score as the per-case covariate, and hard-safety cells are additionally
/// scored by the **Judge panel** (§4.4) whose median score enters the cell and whose batch escalation
/// rate can block. Then apply the statistical gate. The scoring loop is cancellation-aware. Tripwire
/// cases are excluded from the statistical cells (they feed the overfit check separately).
///
/// Returns `(gate report, cases scored, worst effect, panel block reasons)`.
fn score_and_gate(
    req: &ReleaseGateRequest<'_>,
) -> Result<(GateReport, usize, f64, Vec<String>), String> {
    let mut per_cell: BTreeMap<String, CellAccum> = BTreeMap::new();
    let mut scored = 0usize;
    for (i, gc) in req.cases.iter().enumerate() {
        if gc.tripwire {
            continue;
        }
        // Check cancellation periodically so a large corpus can be stopped promptly.
        if i % 64 == 0 && is_cancelled(req) {
            return Err(format!("run cancelled after scoring {scored} cases"));
        }
        let base_out = req.baseline.respond(&gc.case.input);
        let cand_out = req.candidate.respond(&gc.case.input);
        let base_score = req
            .judge
            .score(&gc.case.input, &base_out, &gc.case.criteria)
            .score as f64;
        let mut cand_score = req
            .judge
            .score(&gc.case.input, &cand_out, &gc.case.criteria)
            .score as f64;
        let entry = per_cell
            .entry(gc.cell.clone())
            .or_insert_with(|| CellAccum {
                diffs: Vec::new(),
                covariate: Vec::new(),
                margin: gc.margin,
                hard_safety: gc.hard_safety,
                panel_verdicts: Vec::new(),
            });
        // Judge-panel ensemble on the hard-safety subset: the median panel score REPLACES the single
        // Judge's candidate score in the statistical cell (robust), and the verdict is recorded so a
        // systematic split can block after the batch.
        if gc.hard_safety {
            if let Some(p) = &req.panel {
                let votes: Vec<(String, u8)> = p
                    .judges
                    .iter()
                    .map(|j| {
                        let s = j.score(&gc.case.input, &cand_out, &gc.case.criteria).score;
                        let label = if s >= p.good_label_threshold {
                            "good"
                        } else {
                            "bad"
                        };
                        (label.to_string(), s)
                    })
                    .collect();
                let verdict = p.panel.aggregate(&votes);
                cand_score = match &verdict {
                    crate::judge::PanelVerdict::Consensus { score, .. } => *score as f64,
                    crate::judge::PanelVerdict::Escalate { median_score, .. } => {
                        *median_score as f64
                    }
                };
                entry.panel_verdicts.push(verdict);
            }
        }
        entry.diffs.push(cand_score - base_score);
        entry.covariate.push(base_score);
        scored += 1;
    }

    let mut panel_blocks = Vec::new();
    let mut cells: Vec<MetricCell> = Vec::new();
    for (name, acc) in per_cell.into_iter() {
        // CUPED variance reduction on the paired diffs (identity when the covariate has no signal).
        let diffs = if req.config.use_cuped && acc.covariate.len() == acc.diffs.len() {
            crate::stats::cuped_adjust(&acc.diffs, &acc.covariate)
        } else {
            acc.diffs
        };
        // Judge-panel systematic-disagreement (defective rubric ⇒ block, §4.4).
        if let Some(p) = &req.panel {
            if acc.hard_safety && !acc.panel_verdicts.is_empty() {
                let (defective, rate) = crate::judge::systematic_disagreement(
                    &acc.panel_verdicts,
                    p.max_escalation_rate,
                );
                if defective {
                    panel_blocks.push(format!(
                        "judge panel systematic disagreement in hard-safety cell '{name}': \
                         escalation rate {rate:.2} > {:.2} — the rubric cannot certify this change",
                        p.max_escalation_rate
                    ));
                }
            }
        }
        cells.push(MetricCell {
            name,
            diffs,
            margin: acc.margin,
            hard_safety: acc.hard_safety,
        });
    }
    let report = statistical_gate(&cells, req.config.alpha, req.config.q);
    // The worst (most negative) mean effect across cells, for the audit record.
    let worst = report.cells.iter().map(|c| c.effect).fold(0.0f64, f64::min);
    Ok((report, scored, worst, panel_blocks))
}

/// The overfit tripwire: candidate mean on the visible (non-tripwire) cases vs the sealed tripwire
/// slice. Returns `None` if there are no tripwire cases.
fn tripwire_check(req: &ReleaseGateRequest<'_>) -> Option<crate::integrity::OverfitVerdict> {
    let mut visible = Vec::new();
    let mut trip = Vec::new();
    for gc in req.cases {
        let out = req.candidate.respond(&gc.case.input);
        let s = req
            .judge
            .score(&gc.case.input, &out, &gc.case.criteria)
            .score as f64;
        if gc.tripwire {
            trip.push(s);
        } else {
            visible.push(s);
        }
    }
    if trip.is_empty() || visible.is_empty() {
        return None;
    }
    let vmean = visible.iter().sum::<f64>() / visible.len() as f64;
    let tmean = trip.iter().sum::<f64>() / trip.len() as f64;
    Some(Tripwire::default().evaluate(vmean, tmean))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::replay_matches;
    use crate::integrity::ContaminationPolicy;
    use crate::judge::JudgeSpec;
    use crate::manifest::{Direction, MetricSpec, PreRegistration};
    use crate::vault::{VaultCase, VaultOrigin};
    use crate::{EvalCase, EvalCriteria, QualityScore};

    // ---- fakes ------------------------------------------------------------------------------

    /// A system whose score is controlled per-case-input by a lookup (so we can craft regressions).
    struct ScriptedSystem {
        prefix: String,
    }
    impl EvalSystem for ScriptedSystem {
        fn respond(&self, input: &str) -> String {
            format!("{}:{input}", self.prefix)
        }
    }

    /// A judge that reads the desired score from the output prefix map. Output "b:<id>" or "c:<id>";
    /// the score comes from a per-arm table keyed by case id, so a test can dial exact diffs.
    struct TableJudge {
        base: BTreeMap<String, u8>,
        cand: BTreeMap<String, u8>,
    }
    impl QualityJudge for TableJudge {
        fn score(&self, _input: &str, output: &str, _c: &EvalCriteria) -> QualityScore {
            // output = "<arm>:<id>"
            let mut it = output.splitn(2, ':');
            let arm = it.next().unwrap_or("");
            let id = it.next().unwrap_or("");
            let table = if arm == "c" { &self.cand } else { &self.base };
            let score = *table.get(id).unwrap_or(&0);
            QualityScore {
                score,
                rationale: "table".into(),
            }
        }
    }

    struct AllowStore {
        cases: Vec<(String, String, String)>,
        identity: String,
    }
    impl SealedCorpusStore for AllowStore {
        fn load(
            &self,
            _set_id: &str,
            _v: &str,
            identity: &str,
        ) -> Option<Vec<(String, String, String)>> {
            if identity == self.identity {
                Some(self.cases.clone())
            } else {
                None
            }
        }
    }

    struct MemSink(Vec<VerdictRecord>);
    impl EventSink for MemSink {
        fn append(&mut self, record: &VerdictRecord) {
            self.0.push(record.clone());
        }
    }

    fn judge_spec() -> JudgeSpec {
        JudgeSpec {
            judge_id: "correctness-v1".into(),
            base_model: "glm-4".into(),
            model_version: "glm-4-2026-05".into(),
            family: "glm".into(),
            temperature: 0.0,
            seed: 7,
            rubric: "score correctness".into(),
            scoring_scale: "0-100".into(),
            dimension: "correctness".into(),
            in_house_only: true,
        }
    }

    fn prereg() -> PreRegistration {
        PreRegistration {
            metrics: vec![MetricSpec {
                name: "correctness".into(),
                direction: Direction::HigherIsBetter,
                noninferiority_margin: 2.0,
                mde: 3.0,
                primary: true,
            }],
            power: 0.8,
            alpha: 0.05,
            method: "paired-noninferiority-bh".into(),
        }
    }

    /// Build N gated cases in a single cell; `base`/`cand` fill the judge tables. Returns the cases,
    /// the judge, and the sealed-corpus triples for the manifest.
    fn build(
        n: usize,
        base_fn: impl Fn(usize) -> u8,
        cand_fn: impl Fn(usize) -> u8,
    ) -> (Vec<GatedCase>, TableJudge, Vec<(String, String, String)>) {
        let mut cases = Vec::new();
        let mut base = BTreeMap::new();
        let mut cand = BTreeMap::new();
        let mut triples = Vec::new();
        for i in 0..n {
            let id = format!("c{i}");
            cases.push(GatedCase::new(
                EvalCase::new(&id, &id, "must be correct", 60),
                "correctness×glm×qa",
                2.0,
                false,
                false,
            ));
            base.insert(id.clone(), base_fn(i));
            cand.insert(id.clone(), cand_fn(i));
            triples.push((id.clone(), id.clone(), "gold".to_string()));
        }
        (cases, TableJudge { base, cand }, triples)
    }

    fn good_labels() -> (Vec<String>, Vec<String>) {
        // near-perfect, balanced judge agreement (admitted, no drift).
        let mut gold = vec!["good".to_string(); 8];
        gold.extend(vec!["bad".to_string(); 8]);
        let mut judge = gold.clone();
        judge[0] = "bad".into(); // one mistake — still admitted
        (gold, judge)
    }

    /// Assemble a request that SHIPS on a null (non-regressing) candidate, then let each test perturb
    /// one input to prove the corresponding stage blocks.
    struct Fixture {
        cases: Vec<GatedCase>,
        judge: TableJudge,
        triples: Vec<(String, String, String)>,
        spec: JudgeSpec,
        available: Vec<JudgeSpec>,
        gold: Vec<String>,
        jlabels: Vec<String>,
        current: Vec<String>,
        content: Vec<EvalCaseContent>,
        cand_texts: Vec<String>,
        cand_emb: Vec<Vec<f32>>,
        holdout: Vec<HoldoutCase>,
        vault: RegressionVault,
    }

    fn fixture_null() -> Fixture {
        // 120 paired cases, candidate == baseline (score 80) → a true null change.
        let (cases, judge, triples) = build(120, |_| 80, |_| 80);
        let (gold, jlabels) = good_labels();
        let current = gold.clone(); // no drift
        Fixture {
            cases,
            judge,
            triples,
            spec: judge_spec(),
            available: vec![judge_spec()],
            gold,
            jlabels,
            current,
            content: vec![EvalCaseContent {
                id: "c0".into(),
                text: "some sealed gold answer about settlement cycles".into(),
                embedding: Some(vec![0.0, 1.0, 0.0]),
            }],
            cand_texts: vec!["you are a helpful payments assistant, be concise".into()],
            cand_emb: vec![vec![1.0, 0.0, 0.0]],
            holdout: vec![HoldoutCase {
                id: "h1".into(),
                minted_epoch: 100,
                use_count: 1,
                tripwire: false,
            }],
            vault: RegressionVault::new(),
        }
    }

    fn manifest_for(f: &Fixture) -> EvalSetManifest {
        let m = SealedManifest::build("correctness-set", "v1", &f.triples);
        EvalSetManifest {
            set_id: "correctness-set".into(),
            version: "v1".into(),
            dimension: "correctness".into(),
            content_commitment: m.content_commitment,
            pre_registration: prereg(),
        }
    }

    fn request<'a>(
        f: &'a Fixture,
        manifest: &'a EvalSetManifest,
        store: &'a AllowStore,
        base: &'a ScriptedSystem,
        cand: &'a ScriptedSystem,
        now_passing: &'a BTreeSet<String>,
    ) -> ReleaseGateRequest<'a> {
        ReleaseGateRequest {
            manifest,
            primary_sds: &[1.0], // tiny SD → well-powered at n=120
            sealed_store: store,
            runner_identity: "eval-runner",
            cases: &f.cases,
            baseline: base,
            candidate: cand,
            judge: &f.judge,
            judge_spec: &f.spec,
            data_class: DataClass::RegulatedPayment,
            available_judges: &f.available,
            calibration: JudgeCalibration {
                gold_labels: &f.gold,
                judge_labels: &f.jlabels,
                admission_kappa: 1.0,
                current_labels: &f.current,
                max_kappa_drop: 0.2,
            },
            floors: CalibrationFloors::default(),
            contamination: ContaminationScan {
                candidate_texts: &f.cand_texts,
                candidate_embeddings: &f.cand_emb,
                eval_case_content: &f.content,
                policy: ContaminationPolicy::default(),
            },
            rotation: RotationInputs {
                holdout: &f.holdout,
                now_epoch: 101,
                max_age_epochs: 50,
                max_uses: 100,
            },
            vault: VaultInputs {
                vault: &f.vault,
                previously_tripped: &[],
                now_passing,
                prior_snapshot: None,
            },
            candidate_sha: "deadbeef",
            seed: 42,
            epoch: 1000,
            config: ReleaseGateConfig::default(),
            cancel: None,
            panel: None,
        }
    }

    #[test]
    fn gap_ainxt_eval_02_pipeline_ships_a_null_change_and_writes_a_verdict() {
        let f = fixture_null();
        let manifest = manifest_for(&f);
        let store = AllowStore {
            cases: f.triples.clone(),
            identity: "eval-runner".into(),
        };
        let base = ScriptedSystem { prefix: "b".into() };
        let cand = ScriptedSystem { prefix: "c".into() };
        let passing = BTreeSet::new();
        let req = request(&f, &manifest, &store, &base, &cand, &passing);
        let mut sink = MemSink(Vec::new());
        let report = run_release_gate(&req, &mut sink);
        assert!(
            report.is_ship(),
            "a fully-composed null run must ship: {:?}",
            report.decision
        );
        // The verdict was written to the Event Log BEFORE the decision returned.
        assert_eq!(sink.0.len(), 1, "exactly one verdict recorded");
        assert_eq!(sink.0[0].outcome, "pass");
        assert_eq!(report.scored, 120);
        assert!(report.statistical.is_some());
    }

    #[test]
    fn gap_ainxt_eval_01_gate_uses_significance_not_arithmetic() {
        // A candidate that is EQUAL in true quality but with per-case sampling noise whose aggregate
        // pass-rate dips just enough that the NAIVE evaluate_gate blocks it as a "regression".
        // The statistically-valid pipeline must NOT block — the diff is not significant.
        // baseline: alternating 80/62 ; candidate: alternating 62/80 (same distribution, shuffled),
        // threshold 60 → both "pass" every case, but let's make a few candidate cases dip below 60.
        let base_fn = |i: usize| if i % 20 == 0 { 61u8 } else { 80 };
        let cand_fn = |i: usize| if i % 20 == 0 { 59u8 } else { 80 }; // 6 of 120 dip below threshold
        let (cases, judge, triples) = build(120, base_fn, cand_fn);
        let (gold, jlabels) = good_labels();

        // Naive aggregate gate: baseline passes all (>=60), candidate fails the 6 dipped → pass-rate
        // 0.95 vs 1.0, margin 0.02 → NAIVE GATE BLOCKS (this is the coin-flip bug).
        let base_report = crate::run_eval(
            &cases.iter().map(|g| g.case.clone()).collect::<Vec<_>>(),
            &ScriptedSystem { prefix: "b".into() },
            &judge_as_arm(&judge, "b"),
        );
        let cand_report = crate::run_eval(
            &cases.iter().map(|g| g.case.clone()).collect::<Vec<_>>(),
            &ScriptedSystem { prefix: "c".into() },
            &judge_as_arm(&judge, "c"),
        );
        let naive = crate::evaluate_gate(
            &cand_report,
            &crate::GatePolicy {
                min_pass_rate: 0.0,
                min_mean: 0,
                noninferiority_margin: 0.02,
            },
            Some(&base_report),
        );
        assert!(
            !naive.is_pass(),
            "the NAIVE gate blocks this tiny non-significant dip (the coin-flip bug it must not have)"
        );

        // Now the composed statistically-valid pipeline on the SAME data must NOT block statistically.
        let f = Fixture {
            cases,
            judge,
            triples: triples.clone(),
            spec: judge_spec(),
            available: vec![judge_spec()],
            gold,
            jlabels,
            current: good_labels().0,
            content: vec![EvalCaseContent {
                id: "c0".into(),
                text: "sealed gold".into(),
                embedding: None,
            }],
            cand_texts: vec!["clean prompt".into()],
            cand_emb: vec![],
            holdout: vec![],
            vault: RegressionVault::new(),
        };
        let manifest = manifest_for(&f);
        let store = AllowStore {
            cases: f.triples.clone(),
            identity: "eval-runner".into(),
        };
        let base = ScriptedSystem { prefix: "b".into() };
        let cand = ScriptedSystem { prefix: "c".into() };
        let passing = BTreeSet::new();
        let req = request(&f, &manifest, &store, &base, &cand, &passing);
        let mut sink = MemSink(Vec::new());
        let report = run_release_gate(&req, &mut sink);
        assert!(
            report.is_ship(),
            "a non-significant sampling dip must NOT block the statistical gate: {:?}",
            report.decision
        );
    }

    #[test]
    fn gap_ainxt_eval_01_pipeline_blocks_a_real_statistical_regression() {
        // Every case drops ~8 points, tight variance, margin 2 → a genuine, significant regression.
        let (cases, judge, triples) = build(120, |_| 80, |_| 72);
        let (gold, jlabels) = good_labels();
        let f = Fixture {
            cases,
            judge,
            triples: triples.clone(),
            spec: judge_spec(),
            available: vec![judge_spec()],
            gold,
            jlabels,
            current: good_labels().0,
            content: vec![EvalCaseContent {
                id: "c0".into(),
                text: "sealed gold".into(),
                embedding: None,
            }],
            cand_texts: vec!["clean".into()],
            cand_emb: vec![],
            holdout: vec![],
            vault: RegressionVault::new(),
        };
        let manifest = manifest_for(&f);
        let store = AllowStore {
            cases: f.triples.clone(),
            identity: "eval-runner".into(),
        };
        let base = ScriptedSystem { prefix: "b".into() };
        let cand = ScriptedSystem { prefix: "c".into() };
        let passing = BTreeSet::new();
        let req = request(&f, &manifest, &store, &base, &cand, &passing);
        let mut sink = MemSink(Vec::new());
        let report = run_release_gate(&req, &mut sink);
        match &report.decision {
            ReleaseDecision::Block(rs) => {
                assert!(
                    rs.iter().any(|r| r.contains("statistical regression")),
                    "{rs:?}"
                )
            }
            other => panic!("a real 8-point regression must block: {other:?}"),
        }
        assert_eq!(sink.0[0].outcome, "block");
    }

    #[test]
    fn gap_ainxt_eval_02_fail_closed_on_every_integrity_stage() {
        // Each perturbation flips exactly one stage to blocking.
        let base = ScriptedSystem { prefix: "b".into() };
        let cand = ScriptedSystem { prefix: "c".into() };
        let passing = BTreeSet::new();

        // (a) sealed corpus: wrong runner identity → corpus refused.
        {
            let f = fixture_null();
            let manifest = manifest_for(&f);
            let store = AllowStore {
                cases: f.triples.clone(),
                identity: "eval-runner".into(),
            };
            let mut req = request(&f, &manifest, &store, &base, &cand, &passing);
            req.runner_identity = "pr-author";
            let mut sink = MemSink(Vec::new());
            let r = run_release_gate(&req, &mut sink);
            assert!(
                matches!(r.decision, ReleaseDecision::Block(ref rs) if rs.iter().any(|x| x.contains("sealed corpus unavailable"))),
                "{:?}",
                r.decision
            );
        }
        // (b) tampered corpus: store returns a swapped gold answer → commitment mismatch.
        {
            let f = fixture_null();
            let manifest = manifest_for(&f);
            let mut tampered = f.triples.clone();
            tampered[0].2 = "SWAPPED".into();
            let store = AllowStore {
                cases: tampered,
                identity: "eval-runner".into(),
            };
            let req = request(&f, &manifest, &store, &base, &cand, &passing);
            let mut sink = MemSink(Vec::new());
            let r = run_release_gate(&req, &mut sink);
            assert!(
                matches!(r.decision, ReleaseDecision::Block(ref rs) if rs.iter().any(|x| x.contains("content commitment"))),
                "{:?}",
                r.decision
            );
        }
        // (c) contamination: candidate lifted a sealed case verbatim.
        {
            let mut f = fixture_null();
            f.content = vec![EvalCaseContent {
                id: "c0".into(),
                text: "the settlement runs on a t plus one net settlement cycle for member banks daily".into(),
                embedding: None,
            }];
            f.cand_texts = vec!["system: the settlement runs on a t plus one net settlement cycle for member banks daily".into()];
            let manifest = manifest_for(&f);
            let store = AllowStore {
                cases: f.triples.clone(),
                identity: "eval-runner".into(),
            };
            let req = request(&f, &manifest, &store, &base, &cand, &passing);
            let mut sink = MemSink(Vec::new());
            let r = run_release_gate(&req, &mut sink);
            assert!(
                matches!(r.decision, ReleaseDecision::Block(ref rs) if rs.iter().any(|x| x.contains("contamination"))),
                "{:?}",
                r.decision
            );
        }
        // (d) regulated data class with only a cloud judge → routing fails closed.
        {
            let mut f = fixture_null();
            let mut cloud = judge_spec();
            cloud.in_house_only = false;
            f.available = vec![cloud];
            let manifest = manifest_for(&f);
            let store = AllowStore {
                cases: f.triples.clone(),
                identity: "eval-runner".into(),
            };
            let req = request(&f, &manifest, &store, &base, &cand, &passing);
            let mut sink = MemSink(Vec::new());
            let r = run_release_gate(&req, &mut sink);
            assert!(
                matches!(r.decision, ReleaseDecision::Block(ref rs) if rs.iter().any(|x| x.contains("in-house Judge"))),
                "{:?}",
                r.decision
            );
        }
        // (e) judge drift: current labels diverge from gold beyond max drop.
        {
            let mut f = fixture_null();
            f.current = {
                let mut c = f.gold.clone();
                for (i, v) in c.iter_mut().enumerate() {
                    if i % 2 == 0 {
                        *v = if v == "good" {
                            "bad".into()
                        } else {
                            "good".into()
                        };
                    }
                }
                c
            };
            let manifest = manifest_for(&f);
            let store = AllowStore {
                cases: f.triples.clone(),
                identity: "eval-runner".into(),
            };
            let req = request(&f, &manifest, &store, &base, &cand, &passing);
            let mut sink = MemSink(Vec::new());
            let r = run_release_gate(&req, &mut sink);
            assert!(
                matches!(r.decision, ReleaseDecision::Block(ref rs) if rs.iter().any(|x| x.contains("drift"))),
                "{:?}",
                r.decision
            );
        }
        // (f) underpowered set: huge SD, few cases.
        {
            let f = fixture_null();
            let manifest = manifest_for(&f);
            let store = AllowStore {
                cases: f.triples.clone(),
                identity: "eval-runner".into(),
            };
            let mut req = request(&f, &manifest, &store, &base, &cand, &passing);
            req.primary_sds = &[40.0]; // MDE 3, sd 40, n 120 → underpowered
            let mut sink = MemSink(Vec::new());
            let r = run_release_gate(&req, &mut sink);
            assert!(
                matches!(r.decision, ReleaseDecision::Block(ref rs) if rs.iter().any(|x| x.contains("underpowered"))),
                "{:?}",
                r.decision
            );
        }
    }

    #[test]
    fn gap_ainxt_eval_02_vault_route_not_restored_blocks() {
        let mut f = fixture_null();
        let case = VaultCase::mint(
            "INJ-001",
            VaultOrigin::Breaker,
            "evt-1",
            "sha-1",
            "tainted settle",
            "settle must not fire",
            10,
        );
        f.vault.mint(case);
        let manifest = manifest_for(&f);
        let store = AllowStore {
            cases: f.triples.clone(),
            identity: "eval-runner".into(),
        };
        let base = ScriptedSystem { prefix: "b".into() };
        let cand = ScriptedSystem { prefix: "c".into() };
        let passing = BTreeSet::new(); // candidate passes NONE of the tripped cases
        let mut req = request(&f, &manifest, &store, &base, &cand, &passing);
        let tripped = vec!["INJ-001".to_string()];
        req.vault.previously_tripped = &tripped;
        let mut sink = MemSink(Vec::new());
        let r = run_release_gate(&req, &mut sink);
        assert!(
            matches!(r.decision, ReleaseDecision::Block(ref rs) if rs.iter().any(|x| x.contains("route not restored"))),
            "{:?}",
            r.decision
        );
    }

    #[test]
    fn gap_ainxt_eval_02_cancellation_and_budget_are_indeterminate_not_pass() {
        let f = fixture_null();
        let manifest = manifest_for(&f);
        let store = AllowStore {
            cases: f.triples.clone(),
            identity: "eval-runner".into(),
        };
        let base = ScriptedSystem { prefix: "b".into() };
        let cand = ScriptedSystem { prefix: "c".into() };
        let passing = BTreeSet::new();

        // Cancellation.
        {
            let req = {
                let mut r = request(&f, &manifest, &store, &base, &cand, &passing);
                r.cancel = Some(&always_cancel);
                r
            };
            let mut sink = MemSink(Vec::new());
            let rep = run_release_gate(&req, &mut sink);
            assert!(matches!(rep.decision, ReleaseDecision::Indeterminate(_)));
            assert_eq!(
                sink.0[0].outcome, "indeterminate",
                "even a cancelled run is audited"
            );
        }
        // Budget (back-pressure): max_cases below corpus size.
        {
            let mut req = request(&f, &manifest, &store, &base, &cand, &passing);
            req.config = ReleaseGateConfig {
                max_cases: 10,
                ..ReleaseGateConfig::default()
            };
            let mut sink = MemSink(Vec::new());
            let rep = run_release_gate(&req, &mut sink);
            assert!(
                matches!(rep.decision, ReleaseDecision::Indeterminate(ref s) if s.contains("budget"))
            );
        }
    }

    #[test]
    fn gap_ainxt_eval_02_verdict_is_reproducible_from_sha() {
        let f = fixture_null();
        let manifest = manifest_for(&f);
        let store = AllowStore {
            cases: f.triples.clone(),
            identity: "eval-runner".into(),
        };
        let base = ScriptedSystem { prefix: "b".into() };
        let cand = ScriptedSystem { prefix: "c".into() };
        let passing = BTreeSet::new();
        let req = request(&f, &manifest, &store, &base, &cand, &passing);
        let mut s1 = MemSink(Vec::new());
        let r1 = run_release_gate(&req, &mut s1);
        let mut s2 = MemSink(Vec::new());
        let r2 = run_release_gate(&req, &mut s2);
        assert!(
            replay_matches(&r1.verdict, &r2.verdict),
            "the same inputs must replay to the same verdict (reproduce-from-SHA)"
        );
        // A different candidate SHA is a different reproduction key.
        let mut req2 = request(&f, &manifest, &store, &base, &cand, &passing);
        req2.candidate_sha = "cafef00d";
        let mut s3 = MemSink(Vec::new());
        let r3 = run_release_gate(&req2, &mut s3);
        assert_ne!(r1.verdict.repro_key(), r3.verdict.repro_key());
    }

    #[test]
    fn gap_ainxt_eval_02_report_serializes() {
        let f = fixture_null();
        let manifest = manifest_for(&f);
        let store = AllowStore {
            cases: f.triples.clone(),
            identity: "eval-runner".into(),
        };
        let base = ScriptedSystem { prefix: "b".into() };
        let cand = ScriptedSystem { prefix: "c".into() };
        let passing = BTreeSet::new();
        let req = request(&f, &manifest, &store, &base, &cand, &passing);
        let mut sink = MemSink(Vec::new());
        let report = run_release_gate(&req, &mut sink);
        let j = serde_json::to_string(&report).unwrap();
        let back: ReleaseGateReport = serde_json::from_str(&j).unwrap();
        assert_eq!(back, report);
    }

    fn always_cancel() -> bool {
        true
    }

    /// Wrap a `TableJudge` as a single-arm judge (for the naive-gate demonstration where run_eval
    /// drives one arm at a time).
    fn judge_as_arm(t: &TableJudge, arm: &str) -> ArmJudge {
        ArmJudge {
            table: if arm == "c" {
                t.cand.clone()
            } else {
                t.base.clone()
            },
        }
    }
    struct ArmJudge {
        table: BTreeMap<String, u8>,
    }
    impl QualityJudge for ArmJudge {
        fn score(&self, input: &str, _output: &str, _c: &EvalCriteria) -> QualityScore {
            QualityScore {
                score: *self.table.get(input).unwrap_or(&0),
                rationale: "arm".into(),
            }
        }
    }

    // ---- R11: CUPED + Judge-panel wired into the release gate (§5.3 / §4.4) -----------------

    /// A constant-score judge (a pinned panel member for the ensemble tests).
    struct FixedJudge(u8);
    impl QualityJudge for FixedJudge {
        fn score(&self, _i: &str, _o: &str, _c: &EvalCriteria) -> QualityScore {
            QualityScore {
                score: self.0,
                rationale: "fixed".into(),
            }
        }
    }

    fn panel_spec(id: &str, family: &str) -> JudgeSpec {
        JudgeSpec {
            judge_id: id.into(),
            base_model: family.into(),
            model_version: format!("{family}-2026"),
            family: family.into(),
            temperature: 0.0,
            seed: 1,
            rubric: "hard-safety".into(),
            scoring_scale: "0-100".into(),
            dimension: "correctness".into(),
            in_house_only: true,
        }
    }

    /// Turn the null fixture's cell into a hard-safety cell (so the panel governs it).
    fn hard_safety_fixture() -> Fixture {
        let mut f = fixture_null();
        for c in &mut f.cases {
            c.hard_safety = true;
        }
        f
    }

    #[test]
    fn r11_cuped_default_on_and_panel_consensus_ships() {
        use crate::judge::JudgePanel;
        // CUPED is on by default — the wiring reads it.
        assert!(
            ReleaseGateConfig::default().use_cuped,
            "CUPED default must be on"
        );

        let f = hard_safety_fixture();
        let manifest = manifest_for(&f);
        let store = AllowStore {
            cases: f.triples.clone(),
            identity: "eval-runner".into(),
        };
        let base = ScriptedSystem { prefix: "b".into() };
        let cand = ScriptedSystem { prefix: "c".into() };
        let passing = BTreeSet::new();
        let mut req = request(&f, &manifest, &store, &base, &cand, &passing);

        // A model-diverse panel that AGREES (both 80 → "good") → consensus, and the candidate is a
        // true null vs the baseline (80) → the gate ships (panel wired, CUPED applied, no regression).
        let panel = JudgePanel::new(vec![
            panel_spec("j-glm", "glm"),
            panel_spec("j-qwen", "qwen"),
        ]);
        assert!(panel.validate().is_ok());
        let j1 = FixedJudge(80);
        let j2 = FixedJudge(80);
        let judges: Vec<&dyn QualityJudge> = vec![&j1, &j2];
        req.panel = Some(PanelInputs {
            panel: &panel,
            judges: &judges,
            good_label_threshold: 70,
            max_escalation_rate: 0.1,
        });

        let mut sink = MemSink(Vec::new());
        let rep = run_release_gate(&req, &mut sink);
        assert!(
            rep.decision.is_ship(),
            "panel-consensus null change must ship: {:?}",
            rep.decision
        );
    }

    #[test]
    fn r11_panel_systematic_disagreement_blocks() {
        use crate::judge::JudgePanel;
        let f = hard_safety_fixture();
        let manifest = manifest_for(&f);
        let store = AllowStore {
            cases: f.triples.clone(),
            identity: "eval-runner".into(),
        };
        let base = ScriptedSystem { prefix: "b".into() };
        let cand = ScriptedSystem { prefix: "c".into() };
        let passing = BTreeSet::new();
        let mut req = request(&f, &manifest, &store, &base, &cand, &passing);

        // The panel SPLITS on every case (one "good"=95, one "bad"=40) → escalation rate 1.0 > 0.1
        // → the rubric cannot certify the change → BLOCK (only reachable because the panel is wired).
        let panel = JudgePanel::new(vec![
            panel_spec("j-glm", "glm"),
            panel_spec("j-qwen", "qwen"),
        ]);
        let j1 = FixedJudge(95);
        let j2 = FixedJudge(40);
        let judges: Vec<&dyn QualityJudge> = vec![&j1, &j2];
        req.panel = Some(PanelInputs {
            panel: &panel,
            judges: &judges,
            good_label_threshold: 70,
            max_escalation_rate: 0.1,
        });

        let mut sink = MemSink(Vec::new());
        let rep = run_release_gate(&req, &mut sink);
        match &rep.decision {
            ReleaseDecision::Block(rs) => assert!(
                rs.iter()
                    .any(|r| r.contains("judge panel systematic disagreement")),
                "block must name the panel disagreement: {rs:?}"
            ),
            d => panic!("expected a panel-disagreement block, got {d:?}"),
        }
    }

    // ---- R11: merge-blocking CI status check wiring (§11 + SCENARIO_MATRIX §5) --------------

    #[test]
    fn r11_merge_blocking_status_check_needs_both_gates() {
        use crate::ci::{merge_status_check, run_release_gate_ci, CheckState, RequiredCheck};

        let f = fixture_null();
        let manifest = manifest_for(&f);
        let store = AllowStore {
            cases: f.triples.clone(),
            identity: "eval-runner".into(),
        };
        let base = ScriptedSystem { prefix: "b".into() };
        let cand = ScriptedSystem { prefix: "c".into() };
        let passing = BTreeSet::new();
        let req = request(&f, &manifest, &store, &base, &cand, &passing);

        let mut sink = MemSink(Vec::new());
        let outcome = run_release_gate_ci(&req, &mut sink);
        assert!(
            outcome.is_mergeable(),
            "the null change ships the eval gate"
        );

        // Both DoD gates green → the composite required check is Success (mergeable).
        let matrix_green = RequiredCheck::new("ainxt/scenario-matrix", true, "1300 green");
        let ok = merge_status_check(&outcome, std::slice::from_ref(&matrix_green));
        assert_eq!(ok.state, CheckState::Success);
        assert!(ok.allows_merge());

        // The scenario matrix (safety half) RED → the composite is Failure even though eval shipped:
        // a PR that regresses EITHER half cannot merge, by rule.
        let matrix_red = RequiredCheck::new("ainxt/scenario-matrix", false, "3 invariant failures");
        let blocked = merge_status_check(&outcome, std::slice::from_ref(&matrix_red));
        assert_eq!(blocked.state, CheckState::Failure);
        assert!(!blocked.allows_merge());
        assert!(blocked.description.contains("ainxt/scenario-matrix"));

        // Pending required check is fail-closed (blocks).
        assert!(!CheckState::Pending.allows_merge());
    }
}
