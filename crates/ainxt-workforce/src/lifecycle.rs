// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! **Citizen-authored artifact lifecycle** (WORKFORCE_AND_OS §6).
//!
//! "Anyone can build up the ladder" opens the risk that a citizen-authored skill/agent/role outlives
//! its author's attention (or employment) and keeps running on stale assumptions, unowned. ADR-026
//! §5 only fires *when someone touches the file*; §6 adds the *continuous* half. All five controls are
//! pure functions over data-plane telemetry + control-plane metadata — they compute *signals* and the
//! *actions* to take, but (per §6.1) they never mutate the git definition itself.
//!
//! Time is modelled as an integer "day number" the caller supplies (no clock in the crate), so every
//! sweep is deterministic and testable.

use std::collections::{BTreeMap, BTreeSet};

// ============================ §6.1 Decay sweep ============================

/// Data-plane telemetry for one definition, read by the nightly decay sweep. All already collected
/// for other purposes; the sweep only *reads* them.
#[derive(Debug, Clone, PartialEq)]
pub struct DefinitionTelemetry {
    pub definition_id: String,
    pub owner: String,
    /// 90-day KPI/eval trend: the recent-vs-baseline delta (negative = declining quality).
    pub kpi_trend_90d: f64,
    /// Invocation-count trend (negative = falling usage).
    pub invocation_trend: f64,
    /// Age in days of the definition's last signed commit (control-plane metadata, read-only).
    pub days_since_last_commit: u64,
    /// Invocations in the trailing 30 days (drives §6.5 deprecation floor).
    pub invocations_30d: u64,
}

/// Thresholds + weights for the decay sweep. §6.1 requires the decay *score* to be composed from
/// **all three** designed signals — the KPI/eval trend, the invocation-count trend, and the age of
/// the last signed commit — so each has its own adverse-threshold and its own weight, and the flag
/// fires on the composite score, not on any single signal. Weights are normalized by their sum, so
/// the score is always in `[0.0, 1.0]` regardless of how they are set.
#[derive(Debug, Clone, PartialEq)]
pub struct DecayThresholds {
    pub max_days_since_commit: u64,
    /// A KPI trend at/below this is "declining".
    pub declining_kpi_below: f64,
    /// An invocation-count trend below this is "falling usage".
    pub declining_invocation_below: f64,
    /// Weight of the commit-age signal in the composite decay score.
    pub weight_commit_age: f64,
    /// Weight of the KPI/eval-trend signal.
    pub weight_kpi_trend: f64,
    /// Weight of the invocation-count-trend signal.
    pub weight_invocation_trend: f64,
    /// Composite score (normalized `[0,1]`) at/above which the definition is flagged amber.
    pub flag_threshold: f64,
}

impl Default for DecayThresholds {
    fn default() -> Self {
        DecayThresholds {
            max_days_since_commit: 180,
            declining_kpi_below: 0.0,
            declining_invocation_below: 0.0,
            weight_commit_age: 0.4,
            weight_kpi_trend: 0.3,
            weight_invocation_trend: 0.3,
            // Commit-staleness alone (0.4) is below threshold; staleness plus either declining trend
            // (0.7), or both trends declining (0.6), crosses it — a healthy, well-used definition is
            // never flagged just for age.
            flag_threshold: 0.6,
        }
    }
}

/// An amber decay flag (data-plane), surfaced to the owner as a single digest — never a git mutation.
#[derive(Debug, Clone, PartialEq)]
pub struct DecayFlag {
    pub definition_id: String,
    pub owner: String,
    /// The composite decay score in `[0,1]` (weighted mix of the three adverse signals).
    pub decay_score: f64,
    pub reasons: Vec<String>,
}

/// The nightly decay sweep. Computes a composite decay **score** from all three designed signals
/// (commit age + KPI/eval trend + invocation-count trend), each weighted, and flags amber when the
/// score crosses `flag_threshold`. Returns exactly one flag per breaching definition (deduped by id)
/// — no notification storm (§6.1 acceptance test).
pub fn decay_sweep(defs: &[DefinitionTelemetry], th: &DecayThresholds) -> Vec<DecayFlag> {
    let mut out: Vec<DecayFlag> = Vec::new();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for d in defs {
        if seen.contains(d.definition_id.as_str()) {
            continue;
        }
        let (score, reasons) = decay_score(d, th);
        if score >= th.flag_threshold {
            seen.insert(d.definition_id.as_str());
            out.push(DecayFlag {
                definition_id: d.definition_id.clone(),
                owner: d.owner.clone(),
                decay_score: score,
                reasons,
            });
        }
    }
    out
}

/// Compute the composite decay score (normalized `[0,1]`) for one definition, plus a human-readable
/// reason per adverse signal. Exposed so the Studio badge + owner digest can show the exact score and
/// which of the three signals contributed (§6.1). Signals that are healthy contribute `0`.
pub fn decay_score(d: &DefinitionTelemetry, th: &DecayThresholds) -> (f64, Vec<String>) {
    let total_weight = th.weight_commit_age + th.weight_kpi_trend + th.weight_invocation_trend;
    if total_weight <= 0.0 {
        return (0.0, Vec::new());
    }
    let mut adverse_weight = 0.0;
    let mut reasons = Vec::new();

    if d.days_since_last_commit > th.max_days_since_commit {
        adverse_weight += th.weight_commit_age;
        reasons.push(format!(
            "no signed commit in {} days",
            d.days_since_last_commit
        ));
    }
    if d.kpi_trend_90d <= th.declining_kpi_below {
        adverse_weight += th.weight_kpi_trend;
        reasons.push(format!("KPI/eval trend {} at/below floor", d.kpi_trend_90d));
    }
    if d.invocation_trend < th.declining_invocation_below {
        adverse_weight += th.weight_invocation_trend;
        reasons.push(format!(
            "invocation-count trend {} falling",
            d.invocation_trend
        ));
    }

    (adverse_weight / total_weight, reasons)
}

// ============================ §6.2 Re-certification nudge ============================

/// True once `now_day - last_signed_commit_day > recert_after_days` — one nudge to the owning group.
/// Recertifying is opening a (possibly no-op) signed PR, which resets the clock (verified by the caller
/// against git history).
pub fn needs_recert(now_day: u64, last_signed_commit_day: u64, recert_after_days: u64) -> bool {
    now_day.saturating_sub(last_signed_commit_day) > recert_after_days
}

/// [`needs_recert`] restated over the age already carried on [`DefinitionTelemetry`]
/// (`days_since_last_commit` IS `now_day - last_signed_commit_day`) — the shape the nightly sweep's
/// telemetry slice actually has, so [`crate::controls::NightlyControls::run_nightly`] can wire the
/// §6.2 nudge without the caller re-deriving two absolute day numbers from one relative age.
pub fn needs_recert_for(d: &DefinitionTelemetry, recert_after_days: u64) -> bool {
    d.days_since_last_commit > recert_after_days
}

/// One §6.2 re-certification nudge (data-plane), analogous to [`DecayFlag`]/[`OrphanFlag`] — surfaced
/// to the owning group as a single digest, never a git mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecertNudge {
    pub definition_id: String,
    pub owner: String,
    pub days_since_last_commit: u64,
}

/// The continuous §6.2 re-certification sweep: one nudge per definition whose last signed commit is
/// older than `recert_after_days`. Requires no new git push to trigger, mirroring §6.3's orphan sweep.
pub fn recert_sweep(defs: &[DefinitionTelemetry], recert_after_days: u64) -> Vec<RecertNudge> {
    defs.iter()
        .filter(|d| needs_recert_for(d, recert_after_days))
        .map(|d| RecertNudge {
            definition_id: d.definition_id.clone(),
            owner: d.owner.clone(),
            days_since_last_commit: d.days_since_last_commit,
        })
        .collect()
}

// ============================ §6.3 Orphan-detection sweep ============================

/// The AD org-tree slice the orphan sweep needs (CLAUDE.md Auth): who is active + each person's
/// manager (org-tree parent) for routing a reassignment.
#[derive(Debug, Clone, Default)]
pub struct OrgTree {
    pub active: BTreeMap<String, bool>,
    pub manager: BTreeMap<String, String>,
}

impl OrgTree {
    pub fn is_active(&self, user: &str) -> bool {
        *self.active.get(user).unwrap_or(&false)
    }
    pub fn manager_of(&self, user: &str) -> Option<&String> {
        self.manager.get(user)
    }
}

/// An orphaned-definition flag (data-plane). The definition is flagged + routed to a manager for
/// reassignment — never auto-disabled (disabling a live production role by a background sweep is its
/// own incident, §6.3).
#[derive(Debug, Clone, PartialEq)]
pub struct OrphanFlag {
    pub definition_id: String,
    pub owner: String,
    /// Manager one level up to route reassignment to; `None` if the org tree can't resolve one.
    pub notify_manager: Option<String>,
    pub reason: String,
}

/// The continuous orphan sweep over already-merged definitions. A definition is orphaned if its
/// `owner` is missing from CODEOWNERS *or* is inactive in the org-tree. Requires no new git push to
/// trigger (§6.3 acceptance test).
pub fn orphan_sweep(
    defs: &[DefinitionTelemetry],
    codeowners: &BTreeSet<String>,
    org: &OrgTree,
) -> Vec<OrphanFlag> {
    let mut out = Vec::new();
    for d in defs {
        let not_in_codeowners = !codeowners.contains(&d.owner);
        let inactive = !org.is_active(&d.owner);
        if not_in_codeowners || inactive {
            let reason = if inactive {
                "owner deactivated in org-tree".to_string()
            } else {
                "owner absent from CODEOWNERS".to_string()
            };
            out.push(OrphanFlag {
                definition_id: d.definition_id.clone(),
                owner: d.owner.clone(),
                notify_manager: org.manager_of(&d.owner).cloned(),
                reason,
            });
        }
    }
    out
}

// ============================ §6.4 Ownership succession ============================

/// The fields a succession PR changed. Succession must touch *only* `owner`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SuccessionDiff {
    pub changes_owner: bool,
    pub changes_body: bool,
}

/// Why a succession PR was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuccessionError {
    /// The PR did not change the owner — it is not a succession.
    NotAnOwnershipChange,
    /// The PR changed the owner AND the SOP/logic body — must be split into two reviewable diffs.
    ConflatesBodyChange,
}

impl std::fmt::Display for SuccessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SuccessionError::NotAnOwnershipChange => write!(f, "not an ownership change"),
            SuccessionError::ConflatesBodyChange => {
                write!(
                    f,
                    "ownership change conflated with a body change; split into two PRs"
                )
            }
        }
    }
}
impl std::error::Error for SuccessionError {}

/// Validate an ownership-succession PR (§6.4): an ownership change and a behaviour change must be two
/// reviewable diffs, never one.
pub fn validate_succession(diff: SuccessionDiff) -> Result<(), SuccessionError> {
    if !diff.changes_owner {
        return Err(SuccessionError::NotAnOwnershipChange);
    }
    if diff.changes_body {
        return Err(SuccessionError::ConflatesBodyChange);
    }
    Ok(())
}

// ============================ §6.5 Forced review before deprecation ============================

/// A request to move a definition to `deprecated/`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeprecationRequest {
    pub invocations_30d: u64,
    pub breaker_dry_run_passed: bool,
    pub manager_approval: bool,
}

/// Why a deprecation was blocked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeprecationBlock {
    /// Actively-used artifact deprecated without a Breaker dry-run.
    NeedsBreakerDryRun,
    /// Actively-used artifact deprecated without the manager sign-off.
    NeedsManagerApproval,
}

/// Gate a deprecation (§6.5). A definition with live invocation volume above `floor` cannot be
/// deprecated on owner say-so — it needs a Breaker dry-run *and* the owning group's manager sign-off.
/// Below the floor, ordinary CODEOWNERS approval suffices (empty result = allowed).
pub fn can_deprecate(req: DeprecationRequest, floor: u64) -> Result<(), Vec<DeprecationBlock>> {
    if req.invocations_30d <= floor {
        return Ok(());
    }
    let mut blocks = Vec::new();
    if !req.breaker_dry_run_passed {
        blocks.push(DeprecationBlock::NeedsBreakerDryRun);
    }
    if !req.manager_approval {
        blocks.push(DeprecationBlock::NeedsManagerApproval);
    }
    if blocks.is_empty() {
        Ok(())
    } else {
        Err(blocks)
    }
}
