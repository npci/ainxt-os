// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! The Judge as a **calibrated, pinned, versioned, bias-controlled instrument** (EVAL_PLATFORM.md §4,
//! gap [41]).
//!
//! "The Judge" is never "whatever model we called that day". A [`JudgeSpec`] is a content-addressed
//! definition — `{base_model, model_version, params(temp,seed), rubric, scoring_scale, dimension,
//! family}` — with a deterministic [`JudgeSpec::version`] SHA over its fields, so a score is
//! reproducible from SHA and a silent rubric/param edit is a *different* judge.
//!
//! Trustworthiness is engineered, not asserted:
//!
//! * **Human Gold-Set fitness** ([`GoldSetFitness`]): you cannot calibrate a machine against a
//!   reference humans themselves don't agree on. The calibration panel's inter-rater reliability is
//!   quantified with [`cohens_kappa`] / [`fleiss_kappa`] / [`krippendorff_alpha`]; a set below the κ
//!   floor is unfit and triggers rubric refinement *before* any Judge is calibrated.
//! * **Judge admission** ([`admit_judge`]): a candidate Judge is admitted only if its agreement with
//!   the adjudicated Gold labels clears a documented κ floor **and** a balanced-accuracy floor
//!   ([`balanced_accuracy`], which κ-alone class imbalance can hide) **and** the confusion matrix is
//!   inspected.
//! * **Structural bias controls**: position bias ([`position_bias_flip_rate`], order-averaged),
//!   self-preference ([`self_preference_conflict`] — a Judge never scores its own base-model family),
//!   and drift re-audit ([`judge_drift`]) that catches a provider silently swapping the model behind a
//!   cloud Judge before its drift is mistaken for product drift.
//!
//! The *scoring call itself* is the [`crate::QualityJudge`] seam (an LLM behind it). This module owns
//! the calibration math and governance around that seam; it is pure, deterministic, and std-only save
//! for the `sha2` content digest.

use crate::{EvalCriteria, QualityJudge, QualityScore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

// ===========================================================================================
// The Judge definition — pinned + versioned + content-addressed
// ===========================================================================================

/// A pinned Judge definition (a control-plane kind, ADR-026). Its [`JudgeSpec::version`] is a SHA-256
/// over every field, so any change to the model, params, or rubric yields a new, reproducible version.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JudgeSpec {
    pub judge_id: String,
    /// The base model that scores (e.g. "glm-4", "claude-sonnet-4-6").
    pub base_model: String,
    /// The exact pinned model version/snapshot (never "latest").
    pub model_version: String,
    /// The model family — used for the self-preference control.
    pub family: String,
    /// Sampling temperature; 0.0 for a deterministic judge.
    pub temperature: f64,
    /// Seed for reproducibility.
    pub seed: u64,
    /// The full rubric text (content-hashed into the version).
    pub rubric: String,
    /// e.g. "0-100" or "1-5".
    pub scoring_scale: String,
    /// The dimension this judge scores.
    pub dimension: String,
    /// Whether this judge is only permitted on in-house (non-cloud) data (regulated routing).
    pub in_house_only: bool,
}

/// Length-prefixed hasher feed so distinct field boundaries can't collide.
fn feed(h: &mut Sha256, bytes: &[u8]) {
    h.update((bytes.len() as u64).to_le_bytes());
    h.update(bytes);
}

impl JudgeSpec {
    /// A deterministic SHA-256 content commitment over every field → the reproducible version tag.
    pub fn version(&self) -> String {
        let mut h = Sha256::new();
        feed(&mut h, self.judge_id.as_bytes());
        feed(&mut h, self.base_model.as_bytes());
        feed(&mut h, self.model_version.as_bytes());
        feed(&mut h, self.family.as_bytes());
        feed(&mut h, &self.temperature.to_le_bytes());
        feed(&mut h, &self.seed.to_le_bytes());
        feed(&mut h, self.rubric.as_bytes());
        feed(&mut h, self.scoring_scale.as_bytes());
        feed(&mut h, self.dimension.as_bytes());
        feed(&mut h, &[self.in_house_only as u8]);
        h.finalize().iter().map(|b| format!("{b:02x}")).collect::<String>()
    }
}

// ===========================================================================================
// Confusion matrix + balanced accuracy
// ===========================================================================================

/// A categorical confusion matrix keyed by (truth_label, predicted_label) → count. Labels are
/// arbitrary strings so it works for binary ("good"/"bad") or multi-class rubrics.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ConfusionMatrix {
    cells: BTreeMap<(String, String), usize>,
    labels: Vec<String>,
}

impl ConfusionMatrix {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build from paired (truth, prediction) label sequences. Mismatched lengths use the shorter.
    pub fn from_pairs(truth: &[String], pred: &[String]) -> Self {
        let mut m = ConfusionMatrix::new();
        for (t, p) in truth.iter().zip(pred.iter()) {
            m.record(t, p);
        }
        m
    }

    pub fn record(&mut self, truth: &str, pred: &str) {
        for l in [truth, pred] {
            if !self.labels.iter().any(|x| x == l) {
                self.labels.push(l.to_string());
            }
        }
        self.labels.sort();
        *self
            .cells
            .entry((truth.to_string(), pred.to_string()))
            .or_insert(0) += 1;
    }

    pub fn count(&self, truth: &str, pred: &str) -> usize {
        *self
            .cells
            .get(&(truth.to_string(), pred.to_string()))
            .unwrap_or(&0)
    }

    pub fn labels(&self) -> &[String] {
        &self.labels
    }

    pub fn total(&self) -> usize {
        self.cells.values().sum()
    }

    /// Overall (raw) accuracy — diagonal / total.
    pub fn accuracy(&self) -> f64 {
        let total = self.total();
        if total == 0 {
            return 0.0;
        }
        let diag: usize = self.labels.iter().map(|l| self.count(l, l)).sum();
        diag as f64 / total as f64
    }
}

/// Balanced accuracy = mean per-class recall. Unlike raw accuracy, a Judge that is great at the
/// majority class ("good") and blind to the minority ("bad") is caught by a low value here.
pub fn balanced_accuracy(cm: &ConfusionMatrix) -> f64 {
    let labels = cm.labels();
    if labels.is_empty() {
        return 0.0;
    }
    let mut recalls = Vec::new();
    for truth in labels {
        let row_total: usize = labels.iter().map(|p| cm.count(truth, p)).sum();
        if row_total == 0 {
            continue; // class absent in the gold set — excluded, not counted as perfect
        }
        let tp = cm.count(truth, truth);
        recalls.push(tp as f64 / row_total as f64);
    }
    if recalls.is_empty() {
        0.0
    } else {
        recalls.iter().sum::<f64>() / recalls.len() as f64
    }
}

// ===========================================================================================
// Inter-rater reliability
// ===========================================================================================

/// Cohen's κ between two raters over paired categorical labels. Corrects raw agreement for
/// chance agreement: κ = (p_o − p_e) / (1 − p_e).
pub fn cohens_kappa(a: &[String], b: &[String]) -> Option<f64> {
    let n = a.len().min(b.len());
    if n == 0 {
        return None;
    }
    let cm = ConfusionMatrix::from_pairs(&a[..n], &b[..n]);
    let labels = cm.labels();
    let total = cm.total() as f64;
    let p_o = cm.accuracy();
    // Expected agreement from the marginals.
    let mut p_e = 0.0;
    for l in labels {
        let row: usize = labels.iter().map(|p| cm.count(l, p)).sum();
        let col: usize = labels.iter().map(|t| cm.count(t, l)).sum();
        p_e += (row as f64 / total) * (col as f64 / total);
    }
    if (1.0 - p_e).abs() < 1e-12 {
        // Perfect chance-agreement expectation (single label): κ undefined → treat perfect obs as 1.
        return Some(if (p_o - 1.0).abs() < 1e-12 { 1.0 } else { 0.0 });
    }
    Some((p_o - p_e) / (1.0 - p_e))
}

/// Fleiss' κ for `n` raters over categorical labels. `ratings[i]` is the label each rater gave item
/// `i` (all rows must have the same number of raters ≥ 2).
pub fn fleiss_kappa(ratings: &[Vec<String>]) -> Option<f64> {
    let n_items = ratings.len();
    if n_items == 0 {
        return None;
    }
    let n_raters = ratings[0].len();
    if n_raters < 2 || ratings.iter().any(|r| r.len() != n_raters) {
        return None;
    }
    // Collect the category set.
    let mut categories: Vec<String> = Vec::new();
    for r in ratings {
        for l in r {
            if !categories.iter().any(|c| c == l) {
                categories.push(l.clone());
            }
        }
    }
    categories.sort();
    let k = categories.len();
    if k == 0 {
        return None;
    }
    // n_ij: count of raters that assigned category j to item i.
    let mut p_j = vec![0.0f64; k]; // category marginals
    let mut agree_sum = 0.0; // sum of P_i (item agreement)
    for r in ratings {
        let mut counts = vec![0usize; k];
        for l in r {
            let idx = categories.iter().position(|c| c == l).unwrap();
            counts[idx] += 1;
        }
        for (j, &c) in counts.iter().enumerate() {
            p_j[j] += c as f64;
        }
        // P_i = (sum n_ij^2 - n) / (n(n-1))
        let sum_sq: f64 = counts.iter().map(|&c| (c * c) as f64).sum();
        let nr = n_raters as f64;
        agree_sum += (sum_sq - nr) / (nr * (nr - 1.0));
    }
    let p_bar = agree_sum / n_items as f64;
    for v in p_j.iter_mut() {
        *v /= (n_items * n_raters) as f64;
    }
    let p_e: f64 = p_j.iter().map(|p| p * p).sum();
    if (1.0 - p_e).abs() < 1e-12 {
        return Some(if (p_bar - 1.0).abs() < 1e-12 {
            1.0
        } else {
            0.0
        });
    }
    Some((p_bar - p_e) / (1.0 - p_e))
}

/// Krippendorff's α (interval-metric variant) for ordinal/interval score reliability across raters.
/// `ratings[i]` are the scores item `i` received (raters may vary per item; missing = don't include).
/// α = 1 − D_o / D_e, using squared-difference (interval) distance. Handles the reliability of a
/// numeric scoring scale where Cohen/Fleiss (nominal) would ignore "how far apart" two scores are.
pub fn krippendorff_alpha(ratings: &[Vec<f64>]) -> Option<f64> {
    // Flatten to the list of all values (for expected disagreement) and compute observed within-item.
    let all: Vec<f64> = ratings.iter().flatten().copied().collect();
    let n_total = all.len();
    if n_total < 2 {
        return None;
    }
    // Observed disagreement: mean over items of the mean pairwise squared diff (weighted by pairs).
    let mut obs_num = 0.0;
    let mut obs_pairs = 0.0;
    for item in ratings {
        let m = item.len();
        if m < 2 {
            continue;
        }
        for i in 0..m {
            for j in (i + 1)..m {
                obs_num += (item[i] - item[j]).powi(2);
                obs_pairs += 1.0;
            }
        }
    }
    if obs_pairs == 0.0 {
        return None;
    }
    let d_o = obs_num / obs_pairs;
    // Expected disagreement: mean pairwise squared diff over ALL values.
    let mut exp_num = 0.0;
    let mut exp_pairs = 0.0;
    for i in 0..n_total {
        for j in (i + 1)..n_total {
            exp_num += (all[i] - all[j]).powi(2);
            exp_pairs += 1.0;
        }
    }
    let d_e = exp_num / exp_pairs;
    if d_e == 0.0 {
        // No variance at all → perfect reliability.
        return Some(1.0);
    }
    Some(1.0 - d_o / d_e)
}

// ===========================================================================================
// Gold-set fitness + Judge admission
// ===========================================================================================

/// Documented reliability floors (EVAL_PLATFORM.md §4.2).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct CalibrationFloors {
    /// Minimum human inter-rater κ for a Gold Set to be fit to calibrate against (default 0.6).
    pub gold_kappa_floor: f64,
    /// Minimum Judge-vs-Gold κ for a Judge to be admitted (default 0.6).
    pub judge_kappa_floor: f64,
    /// Minimum Judge balanced accuracy for admission (default 0.7).
    pub balanced_accuracy_floor: f64,
}

impl Default for CalibrationFloors {
    fn default() -> Self {
        CalibrationFloors {
            gold_kappa_floor: 0.6,
            judge_kappa_floor: 0.6,
            balanced_accuracy_floor: 0.7,
        }
    }
}

/// Whether the human Gold Set itself is fit to calibrate against.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum GoldSetFitness {
    /// Human κ clears the floor — usable as a calibration reference.
    Fit { human_kappa: f64 },
    /// Human κ below floor — the RUBRIC is defective; refine + re-adjudicate before calibrating.
    NeedsRubricRefinement { human_kappa: f64, floor: f64 },
}

impl GoldSetFitness {
    pub fn is_fit(&self) -> bool {
        matches!(self, GoldSetFitness::Fit { .. })
    }
}

/// Assess a Gold Set's fitness from the panel's n-rater categorical labels (Fleiss' κ).
pub fn assess_gold_set(
    panel_ratings: &[Vec<String>],
    floors: &CalibrationFloors,
) -> GoldSetFitness {
    let k = fleiss_kappa(panel_ratings).unwrap_or(0.0);
    if k >= floors.gold_kappa_floor {
        GoldSetFitness::Fit { human_kappa: k }
    } else {
        GoldSetFitness::NeedsRubricRefinement {
            human_kappa: k,
            floor: floors.gold_kappa_floor,
        }
    }
}

/// The outcome of a Judge admission decision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum JudgeAdmission {
    Admitted {
        judge_version: String,
        kappa: f64,
        balanced_accuracy: f64,
    },
    Rejected {
        judge_version: String,
        reasons: Vec<String>,
    },
}

impl JudgeAdmission {
    pub fn is_admitted(&self) -> bool {
        matches!(self, JudgeAdmission::Admitted { .. })
    }
}

/// Admit a candidate Judge only if its agreement with the adjudicated Gold labels clears BOTH the κ
/// floor and the balanced-accuracy floor. `gold` and `judge` are the label sequences over the same
/// calibration cases. Reports every failing reason.
pub fn admit_judge(
    spec: &JudgeSpec,
    gold: &[String],
    judge: &[String],
    floors: &CalibrationFloors,
) -> JudgeAdmission {
    let version = spec.version();
    let mut reasons = Vec::new();
    if gold.len() != judge.len() || gold.is_empty() {
        return JudgeAdmission::Rejected {
            judge_version: version,
            reasons: vec![format!(
                "calibration mismatch: {} gold vs {} judge labels",
                gold.len(),
                judge.len()
            )],
        };
    }
    let kappa = cohens_kappa(gold, judge).unwrap_or(0.0);
    let cm = ConfusionMatrix::from_pairs(gold, judge);
    let ba = balanced_accuracy(&cm);
    if kappa < floors.judge_kappa_floor {
        reasons.push(format!(
            "Judge-vs-Gold κ {kappa:.3} below floor {:.3}",
            floors.judge_kappa_floor
        ));
    }
    if ba < floors.balanced_accuracy_floor {
        reasons.push(format!(
            "balanced accuracy {ba:.3} below floor {:.3} (class-imbalance blind spot)",
            floors.balanced_accuracy_floor
        ));
    }
    if reasons.is_empty() {
        JudgeAdmission::Admitted {
            judge_version: version,
            kappa,
            balanced_accuracy: ba,
        }
    } else {
        JudgeAdmission::Rejected {
            judge_version: version,
            reasons,
        }
    }
}

// ===========================================================================================
// Structural bias controls
// ===========================================================================================

/// Fraction of cases where a Judge's A/B verdict flips when the presentation order is swapped
/// (position bias). `order_ab[i]` and `order_ba[i]` are the winner the Judge picked for case `i`
/// under each order; a stable Judge picks the same underlying answer regardless of order. Callers
/// pass the *resolved* winner (e.g. "candidate"/"baseline") so a flip is a genuine order artifact.
pub fn position_bias_flip_rate(order_ab: &[String], order_ba: &[String]) -> Option<f64> {
    let n = order_ab.len().min(order_ba.len());
    if n == 0 {
        return None;
    }
    let flips = (0..n).filter(|&i| order_ab[i] != order_ba[i]).count();
    Some(flips as f64 / n as f64)
}

/// A Judge must never score output from its own base-model family (self-preference, ADR-010 D2).
/// Returns `true` when the pairing is a conflict and must be refused.
pub fn self_preference_conflict(judge_family: &str, producer_family: &str) -> bool {
    judge_family.eq_ignore_ascii_case(producer_family)
}

/// Drift verdict from a periodic Judge-vs-Gold re-audit.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum JudgeDrift {
    /// Agreement held within tolerance of the admission baseline.
    Stable { current_kappa: f64 },
    /// Agreement dropped materially — quarantine the Judge (likely a silent provider model swap).
    Drifted {
        admission_kappa: f64,
        current_kappa: f64,
        drop: f64,
    },
}

impl JudgeDrift {
    pub fn is_drifted(&self) -> bool {
        matches!(self, JudgeDrift::Drifted { .. })
    }
}

/// Re-audit a pinned Judge against the (unchanged) Gold Set. If its agreement dropped by more than
/// `max_drop` from the κ it was admitted at — with no control-plane change on record — the provider
/// likely swapped the model under us; quarantine before its drift is mistaken for product drift.
pub fn judge_drift(
    admission_kappa: f64,
    gold: &[String],
    judge: &[String],
    max_drop: f64,
) -> JudgeDrift {
    let current = cohens_kappa(gold, judge).unwrap_or(0.0);
    let drop = admission_kappa - current;
    if drop > max_drop {
        JudgeDrift::Drifted {
            admission_kappa,
            current_kappa: current,
            drop,
        }
    } else {
        JudgeDrift::Stable {
            current_kappa: current,
        }
    }
}

// ===========================================================================================
// Judge panels + ensemble voting + disagreement escalation (EVAL_PLATFORM.md §4.4, gap [41])
// ===========================================================================================

/// A panel of N pinned, model-diverse Judges for a high-stakes dimension. Voting is only trustworthy
/// if the members are genuinely diverse — a panel of three Judges from the same base-model family votes
/// like one Judge with extra latency. [`JudgePanel::validate`] enforces both size and family diversity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JudgePanel {
    /// The pinned member specs (each contributes one vote).
    pub members: Vec<JudgeSpec>,
    /// Max fraction of the panel that may disagree with the ensemble before the case is escalated to a
    /// human instead of being counted as a confident pass/fail (default 1/3).
    pub max_disagreement: f64,
    /// Minimum distinct model families required for the panel to be admissible (default 2).
    pub min_families: usize,
}

/// One case's ensemble outcome.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PanelVerdict {
    /// The panel reached consensus within tolerance: this is a confident score.
    Consensus {
        /// The median score (robust to a single outlier Judge).
        score: u8,
        /// Fraction of members whose label matched the ensemble label.
        agreement: f64,
    },
    /// The panel split beyond tolerance — NOT counted as a confident pass/fail; routed to a human and,
    /// if the disagreement is systematic across cases, promoted into the Gold Set.
    Escalate {
        median_score: u8,
        disagreement: f64,
        /// The distinct member labels observed (for the human adjudicator).
        member_labels: Vec<String>,
    },
}

impl PanelVerdict {
    pub fn is_consensus(&self) -> bool {
        matches!(self, PanelVerdict::Consensus { .. })
    }
    pub fn needs_human(&self) -> bool {
        matches!(self, PanelVerdict::Escalate { .. })
    }
}

impl JudgePanel {
    pub fn new(members: Vec<JudgeSpec>) -> Self {
        JudgePanel {
            members,
            max_disagreement: 1.0 / 3.0,
            min_families: 2,
        }
    }

    /// A panel is admissible iff it has ≥2 members AND ≥`min_families` distinct model families (real
    /// model-diversity — the whole point of an ensemble) AND no two members share a `judge_id`.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errs = Vec::new();
        if self.members.len() < 2 {
            errs.push("a panel needs at least 2 members".into());
        }
        let families: BTreeMap<&str, ()> = self
            .members
            .iter()
            .map(|m| (m.family.as_str(), ()))
            .collect();
        if families.len() < self.min_families {
            errs.push(format!(
                "panel has only {} model family/families; needs {} for real diversity",
                families.len(),
                self.min_families
            ));
        }
        let ids: BTreeMap<&str, usize> = self.members.iter().fold(BTreeMap::new(), |mut m, j| {
            *m.entry(j.judge_id.as_str()).or_insert(0) += 1;
            m
        });
        if ids.values().any(|&c| c > 1) {
            errs.push("duplicate judge_id in the panel (not independent votes)".into());
        }
        if errs.is_empty() {
            Ok(())
        } else {
            Err(errs)
        }
    }

    /// The distinct member families (diversity introspection).
    pub fn family_count(&self) -> usize {
        self.members
            .iter()
            .map(|m| (m.family.as_str(), ()))
            .collect::<BTreeMap<_, ()>>()
            .len()
    }

    /// Aggregate one case's per-member `(label, score)` votes into a [`PanelVerdict`]. A member is
    /// counted as *agreeing* if its categorical label equals the modal (most common) ensemble label;
    /// disagreement = 1 − agreement. Consensus reports the **median** score (robust); an escalation
    /// carries the split for a human adjudicator. `votes` must align with `self.members`.
    pub fn aggregate(&self, votes: &[(String, u8)]) -> PanelVerdict {
        let median = median_score(&votes.iter().map(|(_, s)| *s).collect::<Vec<_>>());
        // Modal label.
        let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
        for (l, _) in votes {
            *counts.entry(l.as_str()).or_insert(0) += 1;
        }
        let modal = counts
            .iter()
            .max_by(|a, b| a.1.cmp(b.1).then(b.0.cmp(a.0)))
            .map(|(l, _)| l.to_string())
            .unwrap_or_default();
        let n = votes.len().max(1) as f64;
        let agree = counts.get(modal.as_str()).copied().unwrap_or(0) as f64 / n;
        let disagreement = 1.0 - agree;
        if disagreement > self.max_disagreement + 1e-9 {
            let mut member_labels: Vec<String> = counts.keys().map(|s| s.to_string()).collect();
            member_labels.sort();
            PanelVerdict::Escalate {
                median_score: median,
                disagreement,
                member_labels,
            }
        } else {
            PanelVerdict::Consensus {
                score: median,
                agreement: agree,
            }
        }
    }
}

/// Median of a score slice (lower-middle for even counts — deterministic). 0 for an empty slice.
fn median_score(scores: &[u8]) -> u8 {
    if scores.is_empty() {
        return 0;
    }
    let mut s = scores.to_vec();
    s.sort_unstable();
    s[(s.len() - 1) / 2]
}

/// Systematic-disagreement detector: across a batch of panel verdicts, if the escalation *rate*
/// exceeds `max_rate` the disagreement is not case-noise but a rubric/dimension defect — those cases
/// are promoted into the Gold Set for re-adjudication (§4.4). Returns whether promotion is warranted
/// plus the observed rate.
pub fn systematic_disagreement(verdicts: &[PanelVerdict], max_rate: f64) -> (bool, f64) {
    if verdicts.is_empty() {
        return (false, 0.0);
    }
    let escalations = verdicts.iter().filter(|v| v.needs_human()).count();
    let rate = escalations as f64 / verdicts.len() as f64;
    (rate > max_rate, rate)
}

// ===========================================================================================
// The Calibrated Judge — the pinned instrument itself (EVAL_PLATFORM.md §4, gap [41])
// ===========================================================================================

/// Why a [`CalibratedJudge`] refused to score a case. A refusal is NEVER a silent low score — a
/// governance violation must be visible to the caller, which fails the gate closed rather than
/// letting a compromised measurement through.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScoreRefusal {
    /// The producer's model family matches the Judge's family — self-preference (ADR-010 D2). A Judge
    /// may never score output from its own base-model family.
    SelfPreference {
        judge_family: String,
        producer_family: String,
    },
    /// The Judge is pinned `in_house_only` (regulated routing, ADR-012) but the data it was asked to
    /// score is cloud-eligible — using a cloud Judge on it would exfiltrate regulated content.
    InHouseOnlyViolation { judge_version: String },
    /// A pairwise comparison's verdict FLIPPED when the presentation order was swapped — a structural
    /// position-bias artifact, not a genuine preference (§ below, round-15 gap: "structural
    /// position-bias control applied in scoring"). The instrument refuses to emit a single-call
    /// verdict; the case must be escalated to a human/panel rather than a biased pick standing in for
    /// one.
    PositionBiasDetected {
        forward: PairwiseVerdict,
        swapped: PairwiseVerdict,
    },
}

impl std::fmt::Display for ScoreRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScoreRefusal::SelfPreference {
                judge_family,
                producer_family,
            } => write!(
                f,
                "judge refused: self-preference (judge family '{judge_family}' == producer family '{producer_family}')"
            ),
            ScoreRefusal::InHouseOnlyViolation { judge_version } => write!(
                f,
                "judge refused: in-house-only judge '{judge_version}' may not score cloud-eligible data"
            ),
            ScoreRefusal::PositionBiasDetected { forward, swapped } => write!(
                f,
                "judge refused: position-bias detected (forward verdict {forward:?}, order-swapped \
                 verdict {swapped:?} disagree) — escalate to a human/panel"
            ),
        }
    }
}

// ===========================================================================================
// Pairwise (A/B) comparison + structural position-bias control APPLIED AT SCORING (EVAL_PLATFORM.md
// §4.3 structural bias controls; round-15 gap: [`position_bias_flip_rate`] previously existed only as
// a bare statistic the CALLER had to already have both order-swapped results for — nothing made the
// swapped call itself, so no comparison a live pipeline actually ran was ever bias-checked. The types
// below make the double-order call PART OF scoring, not an optional post-hoc audit.
// ===========================================================================================

/// A head-to-head pairwise verdict: which of the two presented outputs is better, in the FRAME of the
/// call that produced it — `A` means "the first argument passed to [`PairwiseJudge::compare`]", `B`
/// means "the second". [`bias_controlled_compare`] canonicalizes a swapped-order call's verdict back
/// into the original frame before comparing, so callers of [`bias_controlled_compare`] itself never
/// have to reason about call-order framing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PairwiseVerdict {
    A,
    B,
    Tie,
}

impl PairwiseVerdict {
    /// Swap A/B (Tie is its own inverse) — used to canonicalize an order-swapped call's raw verdict
    /// back into the original argument frame.
    fn flip(self) -> Self {
        match self {
            PairwiseVerdict::A => PairwiseVerdict::B,
            PairwiseVerdict::B => PairwiseVerdict::A,
            PairwiseVerdict::Tie => PairwiseVerdict::Tie,
        }
    }
}

/// A judge that compares two candidate outputs head-to-head for the same input/criteria and returns
/// which is better. Production backend = a pinned LLM behind the Provider Gateway reached with both
/// orderings (infra-gated, same discipline as [`crate::live::LiveProviderJudge`]); a deterministic
/// offline stand-in is [`crate::semantic::SemanticOverlapPairwiseJudge`].
///
/// Implementations MUST be a pure function of `(input, a, b, criteria)` — no hidden state that varies
/// with call order — so [`bias_controlled_compare`] can swap the presentation order and attribute any
/// verdict change to a genuine structural bias in the JUDGE, not to noise in the implementation.
pub trait PairwiseJudge: Send + Sync {
    fn compare(&self, input: &str, a: &str, b: &str, criteria: &EvalCriteria) -> PairwiseVerdict;
}

/// The reconciled outcome of comparing `a` vs `b` under BOTH presentation orders.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BiasControlledVerdict {
    /// Both orders agree (after canonicalizing the swap) — a genuine, order-independent verdict.
    Consistent(PairwiseVerdict),
    /// The verdict flipped when the presentation order was swapped. Never silently resolved (e.g. by
    /// keeping "whichever order was called first," or by majority) — the instrument surfaces this as
    /// a structural artifact so the caller escalates instead of trusting a biased single call.
    PositionBiased {
        forward: PairwiseVerdict,
        swapped: PairwiseVerdict,
    },
}

impl BiasControlledVerdict {
    pub fn is_biased(&self) -> bool {
        matches!(self, BiasControlledVerdict::PositionBiased { .. })
    }
    /// The resolved verdict, only when the two orders agreed.
    pub fn resolved(&self) -> Option<PairwiseVerdict> {
        match self {
            BiasControlledVerdict::Consistent(v) => Some(*v),
            BiasControlledVerdict::PositionBiased { .. } => None,
        }
    }
}

/// Compare `a` vs `b` under BOTH presentation orders and reconcile — [`position_bias_flip_rate`]'s
/// control APPLIED at the moment of scoring a single case, rather than measured afterward from a
/// pre-collected `order_ab`/`order_ba` pair the caller had to assemble itself. This is the function
/// [`CalibratedPairwiseJudge::compare_governed`] calls on every comparison.
pub fn bias_controlled_compare(
    judge: &dyn PairwiseJudge,
    input: &str,
    a: &str,
    b: &str,
    criteria: &EvalCriteria,
) -> BiasControlledVerdict {
    let forward = judge.compare(input, a, b, criteria);
    // Swap presentation order; canonicalize the swapped call's raw verdict back into the ORIGINAL
    // (a, b) frame by flipping A<->B so `forward` and `swapped` are directly comparable.
    let swapped = judge.compare(input, b, a, criteria).flip();
    if forward == swapped {
        BiasControlledVerdict::Consistent(forward)
    } else {
        BiasControlledVerdict::PositionBiased { forward, swapped }
    }
}

/// **The calibrated pairwise instrument** — [`CalibratedJudge`]'s sibling for head-to-head A/B
/// comparison. Carries the same admission discipline (pinned [`JudgeSpec`], admitted only via
/// [`CalibratedPairwiseJudge::admit`] against the human Gold Set) PLUS the structural position-bias
/// control applied to every comparison it makes: [`CalibratedPairwiseJudge::compare_governed`] scores
/// under both presentation orders via [`bias_controlled_compare`] and REFUSES
/// ([`ScoreRefusal::PositionBiasDetected`]) rather than silently returning whichever order happened to
/// be called, on top of the existing self-preference / in-house-only refusals.
pub struct CalibratedPairwiseJudge {
    spec: JudgeSpec,
    admission: JudgeAdmission,
    backend: Box<dyn PairwiseJudge>,
}

impl CalibratedPairwiseJudge {
    /// Admit and assemble the instrument — identical admission discipline to [`CalibratedJudge::admit`]
    /// (κ + balanced-accuracy floors against the adjudicated Gold labels); constructed only if admitted.
    pub fn admit(
        spec: JudgeSpec,
        backend: Box<dyn PairwiseJudge>,
        gold: &[String],
        judge_labels: &[String],
        floors: &CalibrationFloors,
    ) -> Result<Self, JudgeAdmission> {
        let admission = admit_judge(&spec, gold, judge_labels, floors);
        if admission.is_admitted() {
            Ok(CalibratedPairwiseJudge {
                spec,
                admission,
                backend,
            })
        } else {
            Err(admission)
        }
    }

    pub fn version(&self) -> String {
        self.spec.version()
    }
    pub fn spec(&self) -> &JudgeSpec {
        &self.spec
    }
    pub fn admission(&self) -> &JudgeAdmission {
        &self.admission
    }

    /// Compare `a` vs `b` under this instrument's full governance: self-preference refusal (checked
    /// against BOTH producers, since either side of a pairwise comparison could be the Judge's own
    /// family), the in-house-only routing refusal, and — the round-15 gap this closes — the
    /// **structural position-bias control applied at scoring time**: the comparison is made under both
    /// presentation orders via [`bias_controlled_compare`], and a detected flip refuses rather than
    /// silently returning whichever order happened to be called.
    #[allow(clippy::too_many_arguments)] // pairwise governed compare needs both producers + both families + criteria
    pub fn compare_governed(
        &self,
        input: &str,
        a: &str,
        b: &str,
        criteria: &EvalCriteria,
        producer_family_a: &str,
        producer_family_b: &str,
        data_cloud_eligible: bool,
    ) -> Result<PairwiseVerdict, ScoreRefusal> {
        for producer_family in [producer_family_a, producer_family_b] {
            if self_preference_conflict(&self.spec.family, producer_family) {
                return Err(ScoreRefusal::SelfPreference {
                    judge_family: self.spec.family.clone(),
                    producer_family: producer_family.to_string(),
                });
            }
        }
        if self.spec.in_house_only && data_cloud_eligible {
            return Err(ScoreRefusal::InHouseOnlyViolation {
                judge_version: self.version(),
            });
        }
        match bias_controlled_compare(self.backend.as_ref(), input, a, b, criteria) {
            BiasControlledVerdict::Consistent(v) => Ok(v),
            BiasControlledVerdict::PositionBiased { forward, swapped } => {
                Err(ScoreRefusal::PositionBiasDetected { forward, swapped })
            }
        }
    }
}

impl std::fmt::Debug for CalibratedPairwiseJudge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CalibratedPairwiseJudge")
            .field("version", &self.version())
            .field("admission", &self.admission)
            .finish_non_exhaustive()
    }
}

/// **The pinned, calibrated instrument** — the object the design means by "the Judge", assembled from
/// its three inseparable parts:
///
/// 1. a pinned, versioned [`JudgeSpec`] (content-addressed — a silent rubric/param edit is a *different*
///    instrument);
/// 2. an [`JudgeAdmission`] proving it cleared the κ + balanced-accuracy floors against the human Gold
///    Set — **a candidate that was never admitted cannot be constructed** ([`CalibratedJudge::admit`]
///    is the only public constructor and returns `Err` on a rejected candidate); and
/// 3. the scoring backend behind the [`QualityJudge`] seam — in production the pinned LLM reached over
///    the Provider Gateway (a live model call, infra-gated); offline the deterministic
///    [`crate::semantic::SemanticOverlapJudge`] stands in unchanged.
///
/// The instrument enforces its own governance at *scoring* time, not just at admission: it refuses
/// (never silently mis-scores) on a self-preference conflict or an `in_house_only` routing violation,
/// and every score it emits is stamped with its immutable version so a verdict is reproducible from
/// the SHA. Because the LLM lives behind the seam, swapping the offline stand-in for the pinned cloud
/// Judge is a one-line backend change; nothing else about the instrument moves.
pub struct CalibratedJudge {
    spec: JudgeSpec,
    admission: JudgeAdmission,
    backend: Box<dyn QualityJudge>,
}

impl CalibratedJudge {
    /// Admit and assemble the instrument. The candidate is calibrated against the adjudicated Gold
    /// labels ([`admit_judge`]); it is constructed **only if admitted** (both the κ floor and the
    /// balanced-accuracy floor clear). On rejection the failing [`JudgeAdmission`] is returned — an
    /// un-calibrated Judge can never become a usable instrument.
    pub fn admit(
        spec: JudgeSpec,
        backend: Box<dyn QualityJudge>,
        gold: &[String],
        judge_labels: &[String],
        floors: &CalibrationFloors,
    ) -> Result<Self, JudgeAdmission> {
        let admission = admit_judge(&spec, gold, judge_labels, floors);
        if admission.is_admitted() {
            Ok(CalibratedJudge {
                spec,
                admission,
                backend,
            })
        } else {
            Err(admission)
        }
    }

    /// The pinned, reproducible version tag (the content SHA of the spec).
    pub fn version(&self) -> String {
        self.spec.version()
    }

    pub fn spec(&self) -> &JudgeSpec {
        &self.spec
    }

    /// The admission record that authorized this instrument (κ + balanced accuracy on the Gold Set).
    pub fn admission(&self) -> &JudgeAdmission {
        &self.admission
    }

    /// Score a case under the instrument's governance. `producer_family` is the model family that
    /// produced `output` (for the self-preference control); `data_cloud_eligible` is whether the data
    /// being scored may leave the in-house boundary (for the `in_house_only` routing control). Refuses
    /// — visibly — on either violation; otherwise delegates to the calibrated backend and stamps the
    /// verdict with the pinned judge version.
    pub fn score_governed(
        &self,
        input: &str,
        output: &str,
        criteria: &EvalCriteria,
        producer_family: &str,
        data_cloud_eligible: bool,
    ) -> Result<QualityScore, ScoreRefusal> {
        if self_preference_conflict(&self.spec.family, producer_family) {
            return Err(ScoreRefusal::SelfPreference {
                judge_family: self.spec.family.clone(),
                producer_family: producer_family.to_string(),
            });
        }
        if self.spec.in_house_only && data_cloud_eligible {
            return Err(ScoreRefusal::InHouseOnlyViolation {
                judge_version: self.version(),
            });
        }
        let mut verdict = self.backend.score(input, output, criteria);
        verdict.rationale = format!("[judge {}] {}", self.version(), verdict.rationale);
        Ok(verdict)
    }
}

impl std::fmt::Debug for CalibratedJudge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CalibratedJudge")
            .field("version", &self.version())
            .field("admission", &self.admission)
            .finish_non_exhaustive()
    }
}

/// The instrument plugs into [`crate::run_eval`] unchanged. This impl performs no per-call routing
/// controls (they need the producer family + data class, which the bare seam does not carry) — it is
/// the "admitted instrument, in-boundary data, non-conflicting producer" fast path. Use
/// [`CalibratedJudge::score_governed`] when the producer family / data class are known so the
/// self-preference and in-house-only refusals are enforced.
impl QualityJudge for CalibratedJudge {
    fn score(&self, input: &str, output: &str, criteria: &EvalCriteria) -> QualityScore {
        let mut verdict = self.backend.score(input, output, criteria);
        verdict.rationale = format!("[judge {}] {}", self.version(), verdict.rationale);
        verdict
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn spec() -> JudgeSpec {
        JudgeSpec {
            judge_id: "groundedness-v1".into(),
            base_model: "glm-4".into(),
            model_version: "glm-4-2026-05".into(),
            family: "glm".into(),
            temperature: 0.0,
            seed: 42,
            rubric: "Score 0-100 how supported the answer is by the sources.".into(),
            scoring_scale: "0-100".into(),
            dimension: "groundedness".into(),
            in_house_only: true,
        }
    }

    #[test]
    fn judge_version_is_stable_and_content_sensitive() {
        let a = spec();
        let mut b = spec();
        assert_eq!(a.version(), b.version(), "same fields → same version");
        assert_eq!(a.version().len(), 64, "SHA-256 hex is 64 chars");
        b.rubric.push_str(" Be strict.");
        assert_ne!(
            a.version(),
            b.version(),
            "a rubric edit is a new judge version"
        );
        let mut c = spec();
        c.seed = 43;
        assert_ne!(
            a.version(),
            c.version(),
            "a param edit is a new judge version"
        );
    }

    #[test]
    fn cohens_kappa_perfect_and_chance() {
        let a = labels(&["good", "bad", "good", "bad", "good"]);
        assert_eq!(cohens_kappa(&a, &a), Some(1.0));
        // Systematic disagreement (always opposite) → κ negative.
        let flip = labels(&["bad", "good", "bad", "good", "bad"]);
        let k = cohens_kappa(&a, &flip).unwrap();
        assert!(k < 0.0, "always-opposite raters give κ<0: {k}");
    }

    #[test]
    fn cohens_kappa_corrects_for_chance() {
        // Two raters mostly labeling "good" agree a lot by raw %, but κ discounts chance.
        let a = labels(&[
            "good", "good", "good", "good", "bad", "good", "good", "good",
        ]);
        let b = labels(&[
            "good", "good", "good", "bad", "good", "good", "good", "good",
        ]);
        let raw = ConfusionMatrix::from_pairs(&a, &b).accuracy();
        let k = cohens_kappa(&a, &b).unwrap();
        assert!(raw > 0.7, "raw agreement is high: {raw}");
        assert!(
            k < raw,
            "κ must be below raw agreement (chance correction): κ={k}, raw={raw}"
        );
    }

    #[test]
    fn fleiss_kappa_three_raters() {
        // Three raters in strong agreement.
        let ratings = vec![
            labels(&["good", "good", "good"]),
            labels(&["bad", "bad", "bad"]),
            labels(&["good", "good", "good"]),
            labels(&["bad", "bad", "good"]),
            labels(&["good", "good", "good"]),
        ];
        let k = fleiss_kappa(&ratings).unwrap();
        assert!(k > 0.5, "strong 3-rater agreement gives high κ: {k}");
        // Random disagreement → low κ.
        let noisy = vec![
            labels(&["good", "bad", "good"]),
            labels(&["bad", "good", "bad"]),
            labels(&["good", "bad", "good"]),
            labels(&["bad", "good", "bad"]),
        ];
        let kn = fleiss_kappa(&noisy).unwrap();
        assert!(kn < k, "noisy panel gives lower κ: {kn} < {k}");
    }

    #[test]
    fn krippendorff_alpha_ordinal_scale() {
        // Raters within 1-2 points of each other on a 0-100 scale → high α.
        let close = vec![
            vec![90.0, 91.0, 89.0],
            vec![60.0, 61.0, 59.0],
            vec![75.0, 74.0, 76.0],
            vec![40.0, 41.0, 42.0],
        ];
        let a = krippendorff_alpha(&close).unwrap();
        assert!(a > 0.9, "tight ordinal agreement → high α: {a}");
        // Wildly divergent scores → low/negative α.
        let far = vec![
            vec![90.0, 10.0, 50.0],
            vec![20.0, 80.0, 40.0],
            vec![70.0, 5.0, 95.0],
        ];
        let a2 = krippendorff_alpha(&far).unwrap();
        assert!(a2 < a, "divergent ordinal ratings → lower α: {a2} < {a}");
    }

    #[test]
    fn balanced_accuracy_catches_minority_blindness() {
        // Judge says "good" to everything. 90 good, 10 bad in gold.
        let mut gold = vec!["good".to_string(); 90];
        gold.extend(vec!["bad".to_string(); 10]);
        let judge = vec!["good".to_string(); 100];
        let cm = ConfusionMatrix::from_pairs(&gold, &judge);
        assert!(cm.accuracy() > 0.85, "raw accuracy looks great");
        let ba = balanced_accuracy(&cm);
        assert!(ba < 0.6, "balanced accuracy exposes the blind spot: {ba}");
    }

    #[test]
    fn gold_set_below_floor_needs_rubric_refinement() {
        // A panel that disagrees a lot.
        let noisy = vec![
            labels(&["good", "bad", "good"]),
            labels(&["bad", "good", "bad"]),
            labels(&["good", "bad", "good"]),
            labels(&["bad", "good", "bad"]),
        ];
        let f = assess_gold_set(&noisy, &CalibrationFloors::default());
        assert!(!f.is_fit(), "a low-κ panel is unfit: {f:?}");
        assert!(matches!(f, GoldSetFitness::NeedsRubricRefinement { .. }));
    }

    #[test]
    fn judge_admission_requires_both_floors() {
        let s = spec();
        // High agreement AND balanced → admitted.
        let mut gold = labels(&["good", "bad", "good", "bad", "good", "bad", "good", "bad"]);
        let mut judge = gold.clone();
        // one mistake
        judge[0] = "bad".into();
        let adm = admit_judge(&s, &gold, &judge, &CalibrationFloors::default());
        assert!(
            adm.is_admitted(),
            "near-perfect balanced judge admitted: {adm:?}"
        );

        // Now a judge that only ever says "good": κ and balanced-accuracy both collapse → rejected.
        gold = vec!["good".to_string(); 8];
        gold.extend(vec!["bad".to_string(); 8]);
        let all_good = vec!["good".to_string(); 16];
        let adm2 = admit_judge(&s, &gold, &all_good, &CalibrationFloors::default());
        assert!(
            !adm2.is_admitted(),
            "a class-blind judge must be rejected: {adm2:?}"
        );
    }

    #[test]
    fn position_bias_is_detected() {
        // Stable judge: same winner in both orders → flip rate 0.
        let ab = labels(&["candidate", "baseline", "candidate", "baseline"]);
        let ba = ab.clone();
        assert_eq!(position_bias_flip_rate(&ab, &ba), Some(0.0));
        // Order-biased judge: always picks whatever was shown first → flips on every case.
        let ab2 = labels(&["candidate", "candidate", "candidate"]);
        let ba2 = labels(&["baseline", "baseline", "baseline"]);
        assert_eq!(position_bias_flip_rate(&ab2, &ba2), Some(1.0));
    }

    #[test]
    fn self_preference_is_refused() {
        assert!(
            self_preference_conflict("claude", "Claude"),
            "same family refused (case-insensitive)"
        );
        assert!(
            !self_preference_conflict("glm", "qwen"),
            "cross-family allowed"
        );
    }

    #[test]
    fn judge_drift_catches_a_silent_swap() {
        let gold = labels(&["good", "bad", "good", "bad", "good", "bad"]);
        // At admission the judge agreed perfectly (κ=1).
        // After a silent provider swap it now disagrees on half.
        let after = labels(&["good", "good", "bad", "bad", "good", "good"]);
        let d = judge_drift(1.0, &gold, &after, 0.2);
        assert!(
            d.is_drifted(),
            "a large agreement drop must trip drift: {d:?}"
        );
        // Stable case.
        let same = gold.clone();
        assert!(!judge_drift(1.0, &gold, &same, 0.2).is_drifted());
    }

    #[test]
    fn spec_serializes_round_trip() {
        let s = spec();
        let j = serde_json::to_string(&s).unwrap();
        let back: JudgeSpec = serde_json::from_str(&j).unwrap();
        assert_eq!(back, s);
        assert_eq!(back.version(), s.version());
    }

    fn member(id: &str, family: &str) -> JudgeSpec {
        JudgeSpec {
            judge_id: id.into(),
            base_model: format!("{family}-model"),
            model_version: format!("{family}-2026"),
            family: family.into(),
            temperature: 0.0,
            seed: 1,
            rubric: "score groundedness".into(),
            scoring_scale: "0-100".into(),
            dimension: "groundedness".into(),
            in_house_only: true,
        }
    }

    #[test]
    fn gap_ainxt_eval_04_panel_requires_real_model_diversity() {
        // A "panel" of three same-family judges is NOT diverse — must be rejected.
        let mono = JudgePanel::new(vec![
            member("a", "glm"),
            member("b", "glm"),
            member("c", "glm"),
        ]);
        let e = mono.validate().unwrap_err();
        assert!(e.iter().any(|s| s.contains("model family")), "{e:?}");
        // A genuinely diverse panel is admissible.
        let diverse = JudgePanel::new(vec![
            member("a", "glm"),
            member("b", "qwen"),
            member("c", "claude"),
        ]);
        assert!(diverse.validate().is_ok());
        assert_eq!(diverse.family_count(), 3);
        // Duplicate judge_id → not independent votes.
        let dup = JudgePanel::new(vec![member("a", "glm"), member("a", "qwen")]);
        assert!(dup.validate().is_err());
    }

    #[test]
    fn gap_ainxt_eval_04_disagreement_escalates_to_a_human_not_a_majority_vote() {
        let panel = JudgePanel::new(vec![
            member("a", "glm"),
            member("b", "qwen"),
            member("c", "claude"),
        ]);
        // Consensus: all three say "good" → confident, median score reported.
        let consensus = panel.aggregate(&[
            ("good".into(), 90),
            ("good".into(), 84),
            ("good".into(), 88),
        ]);
        assert!(consensus.is_consensus());
        if let PanelVerdict::Consensus { score, agreement } = consensus {
            assert_eq!(score, 88, "median of {{84,88,90}}");
            assert!((agreement - 1.0).abs() < 1e-9);
        }
        // Split 2/1 across a 3-judge panel → disagreement 1/3, within tolerance (still consensus).
        let split_21 =
            panel.aggregate(&[("good".into(), 80), ("good".into(), 78), ("bad".into(), 30)]);
        assert!(split_21.is_consensus(), "a lone dissenter is tolerated");
        // A real 3-way split (each judge a different label) → disagreement 2/3 → ESCALATE, not a
        // silent majority pick. This is the gap: disagreement is a first-class signal.
        let three_way = panel.aggregate(&[
            ("good".into(), 90),
            ("mediocre".into(), 55),
            ("bad".into(), 20),
        ]);
        assert!(
            three_way.needs_human(),
            "a genuine split must route to a human, not be hidden behind a vote: {three_way:?}"
        );
        if let PanelVerdict::Escalate { member_labels, .. } = &three_way {
            assert_eq!(
                member_labels.len(),
                3,
                "the human sees every distinct label"
            );
        }
    }

    #[test]
    fn gap_ainxt_eval_04_systematic_disagreement_feeds_the_gold_set() {
        let panel = JudgePanel::new(vec![member("a", "glm"), member("b", "qwen")]);
        // A batch where the panel keeps splitting → the rubric is defective, promote to Gold Set.
        let mut verdicts = Vec::new();
        for _ in 0..10 {
            verdicts.push(panel.aggregate(&[("good".into(), 90), ("bad".into(), 20)]));
        }
        let (promote, rate) = systematic_disagreement(&verdicts, 0.2);
        assert!(
            promote,
            "a high escalation rate ({rate}) is a rubric defect → Gold Set"
        );
        // A mostly-consensual batch does not warrant promotion.
        let calm: Vec<PanelVerdict> = (0..10)
            .map(|_| panel.aggregate(&[("good".into(), 88), ("good".into(), 90)]))
            .collect();
        assert!(!systematic_disagreement(&calm, 0.2).0);
    }

    #[test]
    fn gap_ainxt_eval_04_panel_verdict_serializes() {
        let panel = JudgePanel::new(vec![member("a", "glm"), member("b", "qwen")]);
        let v = panel.aggregate(&[("good".into(), 80), ("good".into(), 82)]);
        let j = serde_json::to_string(&v).unwrap();
        let back: PanelVerdict = serde_json::from_str(&j).unwrap();
        assert_eq!(back, v);
    }
}
