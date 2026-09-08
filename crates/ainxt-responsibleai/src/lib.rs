// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! ainxt-responsibleai — Responsible-AI governance (gap D; ADR-011).
//!
//! An RBI-regulated payment switch (and EU-AI-Act-style regimes) makes AI-specific governance
//! **mandatory, not optional**: model cards, system cards, bias/fairness testing, and an auditable
//! human-approval record before anything ships. The DRAFT→…→PRODUCTION lifecycle itself is already
//! git-native (ADR-026); this crate adds the AI-specific *artifacts* that ride that lifecycle and the
//! **fail-closed deploy gate** that consumes them.
//!
//! Four pure, deterministic pieces:
//!
//! 1. [`ModelCard`] — intended use, out-of-scope uses, limitations, training-data + eval summaries,
//!    and an EU-AI-Act-style [`RiskClass`]. [`ModelCard::validate`] rejects empty required fields
//!    **field-by-field** (structural validity), so an author sees every gap at once.
//! 2. [`SystemCard`] — the components (model ids), data flows, and human-oversight description of a
//!    composed system, with a [`SystemCard::completeness`] check.
//! 3. [`assess_bias`] — given per-group favorable-outcome rates, computes a [`BiasReport`] with an
//!    exact disparity ([`FairnessMetric::RateRatio`] max/min, or [`FairnessMetric::RateDifference`]
//!    max−min), names the worst-off / best-off **group pair**, and flags when disparity exceeds a
//!    configured threshold.
//! 4. [`GovernanceRecord`] + [`deploy_gate`] — a record binds a card, an optional system card, a bias
//!    report, and an **approver** ([`ainxt_types::Principal`]). The gate **refuses** (fail-closed) if
//!    the card is invalid, the risk is [`RiskClass::Unacceptable`], the system card is incomplete,
//!    bias exceeds threshold, or the approver lacks approval authority — collecting *all* reasons.
//!
//! Nothing here reads a clock, an RNG, or the filesystem: the audit tick is a caller-supplied `u64`.
//! Clean-room throughout.

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt;

use ainxt_types::{DataClass, Principal};

pub mod dpia;
pub mod exit_plan;
pub mod outsourcing;
pub mod promotion;
pub mod routes;

// ============================ Risk classification ============================

/// EU-AI-Act-style risk classification of a model/system. `Ord` runs least → most severe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RiskClass {
    /// Negligible risk (e.g. spam filtering).
    Minimal,
    /// Transparency obligations apply (e.g. a chat assistant).
    Limited,
    /// Regulated high-risk use — deployable, but only with conformity evidence + human oversight.
    High,
    /// Prohibited. Never deployable.
    Unacceptable,
}

impl RiskClass {
    /// `false` only for [`RiskClass::Unacceptable`] — a prohibited system can never ship.
    pub fn deployable(&self) -> bool {
        !matches!(self, RiskClass::Unacceptable)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            RiskClass::Minimal => "minimal",
            RiskClass::Limited => "limited",
            RiskClass::High => "high",
            RiskClass::Unacceptable => "unacceptable",
        }
    }
}

// ============================ Model card ============================

/// A structural defect in a [`ModelCard`] — one per missing/blank required field, so validation is
/// reported field-by-field rather than as a single opaque failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CardDefect {
    MissingModelId,
    MissingIntendedUse,
    /// `out_of_scope_uses` has no non-blank entry — an unbounded scope is itself a risk.
    NoOutOfScopeUses,
    /// `limitations` has no non-blank entry — a card claiming zero limitations is not credible.
    NoLimitations,
    MissingTrainingDataSummary,
    MissingEvalSummary,
}

impl CardDefect {
    /// The card field this defect refers to.
    pub fn field(&self) -> &'static str {
        match self {
            CardDefect::MissingModelId => "model_id",
            CardDefect::MissingIntendedUse => "intended_use",
            CardDefect::NoOutOfScopeUses => "out_of_scope_uses",
            CardDefect::NoLimitations => "limitations",
            CardDefect::MissingTrainingDataSummary => "training_data_summary",
            CardDefect::MissingEvalSummary => "eval_summary",
        }
    }
}

impl fmt::Display for CardDefect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "model card: required field `{}` is missing or empty",
            self.field()
        )
    }
}

/// A model card: what a model is for, what it must not be used for, its limits, and its risk class.
///
/// [`validate`](ModelCard::validate) checks **structural** validity (required fields present). A card
/// can be structurally valid yet still non-deployable — e.g. an [`RiskClass::Unacceptable`] card is a
/// perfectly valid *description* of a prohibited system; refusing its deployment is the job of
/// [`deploy_gate`], not `validate`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelCard {
    pub model_id: String,
    pub intended_use: String,
    pub out_of_scope_uses: Vec<String>,
    pub limitations: Vec<String>,
    pub training_data_summary: String,
    pub eval_summary: String,
    pub risk_class: RiskClass,
}

/// A string is "blank" if it is empty or only whitespace.
fn blank(s: &str) -> bool {
    s.trim().is_empty()
}

/// A list is "empty of content" if it has no non-blank entry.
fn no_content(list: &[String]) -> bool {
    list.iter().all(|s| blank(s))
}

impl ModelCard {
    /// Validate required fields. Returns `Ok(())` when the card is structurally complete, else the
    /// full list of [`CardDefect`]s in a stable field order (so callers can assert field-by-field and
    /// authors see every gap in one pass). Does **not** consider the risk class — see the type doc.
    pub fn validate(&self) -> Result<(), Vec<CardDefect>> {
        let mut defects = Vec::new();
        if blank(&self.model_id) {
            defects.push(CardDefect::MissingModelId);
        }
        if blank(&self.intended_use) {
            defects.push(CardDefect::MissingIntendedUse);
        }
        if no_content(&self.out_of_scope_uses) {
            defects.push(CardDefect::NoOutOfScopeUses);
        }
        if no_content(&self.limitations) {
            defects.push(CardDefect::NoLimitations);
        }
        if blank(&self.training_data_summary) {
            defects.push(CardDefect::MissingTrainingDataSummary);
        }
        if blank(&self.eval_summary) {
            defects.push(CardDefect::MissingEvalSummary);
        }
        if defects.is_empty() {
            Ok(())
        } else {
            Err(defects)
        }
    }

    /// `true` if [`validate`](ModelCard::validate) has no defects.
    pub fn is_valid(&self) -> bool {
        self.validate().is_ok()
    }
}

// ============================ System card ============================

/// A structural defect in a [`SystemCard`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SystemCardDefect {
    MissingSystemId,
    /// No component model ids listed — a system of nothing cannot be governed.
    NoComponents,
    /// A component entry is blank.
    BlankComponent,
    /// No data flows described — undocumented data movement is a compliance blind spot.
    NoDataFlows,
    /// No human-oversight description — mandatory for high-risk systems.
    MissingHumanOversight,
}

impl SystemCardDefect {
    pub fn field(&self) -> &'static str {
        match self {
            SystemCardDefect::MissingSystemId => "system_id",
            SystemCardDefect::NoComponents => "components",
            SystemCardDefect::BlankComponent => "components[entry]",
            SystemCardDefect::NoDataFlows => "data_flows",
            SystemCardDefect::MissingHumanOversight => "human_oversight",
        }
    }
}

impl fmt::Display for SystemCardDefect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "system card: `{}` is missing or empty", self.field())
    }
}

/// A system card: the composed system's components (model ids), data flows, and human-oversight
/// description. Governs a *system* built from one or more model-carded components.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemCard {
    pub system_id: String,
    /// The model ids this system composes.
    pub components: Vec<String>,
    /// Human-readable descriptions of how data moves through the system.
    pub data_flows: Vec<String>,
    /// How humans stay in/over the loop (the human-oversight record).
    pub human_oversight: String,
}

impl SystemCard {
    /// Check completeness. Returns `Ok(())` when complete, else every defect in a stable order.
    pub fn completeness(&self) -> Result<(), Vec<SystemCardDefect>> {
        let mut defects = Vec::new();
        if blank(&self.system_id) {
            defects.push(SystemCardDefect::MissingSystemId);
        }
        if self.components.is_empty() {
            defects.push(SystemCardDefect::NoComponents);
        } else if self.components.iter().any(|c| blank(c)) {
            defects.push(SystemCardDefect::BlankComponent);
        }
        if no_content(&self.data_flows) {
            defects.push(SystemCardDefect::NoDataFlows);
        }
        if blank(&self.human_oversight) {
            defects.push(SystemCardDefect::MissingHumanOversight);
        }
        if defects.is_empty() {
            Ok(())
        } else {
            Err(defects)
        }
    }

    pub fn is_complete(&self) -> bool {
        self.completeness().is_ok()
    }
}

// ============================ Bias / fairness ============================

/// A group's favorable-outcome rate. `favorable_rate` is the fraction (0.0–1.0) of the group that
/// received the favorable outcome (e.g. loan approved, transaction not flagged).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GroupRate {
    pub group: String,
    pub favorable_rate: f64,
}

impl GroupRate {
    pub fn new(group: &str, favorable_rate: f64) -> Self {
        GroupRate {
            group: group.to_string(),
            favorable_rate,
        }
    }

    /// Build from counts. A group with `total == 0` has an undefined rate; we record it as `0.0`
    /// (guarding the division) — an empty group cannot be favored.
    pub fn from_counts(group: &str, favorable: u64, total: u64) -> Self {
        let rate = if total == 0 {
            0.0
        } else {
            favorable as f64 / total as f64
        };
        GroupRate {
            group: group.to_string(),
            favorable_rate: rate,
        }
    }
}

/// How disparity between the best- and worst-off groups is measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FairnessMetric {
    /// `max_rate / min_rate` (a four-fifths-rule style impact ratio, ≥ 1.0; `1.0` = parity).
    /// If the min rate is 0 while the max is positive, the ratio is `+∞` (maximal disparity).
    RateRatio,
    /// `max_rate − min_rate` (0.0 = parity).
    RateDifference,
}

/// The fairness policy applied to a bias assessment.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct FairnessPolicy {
    pub metric: FairnessMetric,
    /// Disparity strictly above this flags the assessment. For [`FairnessMetric::RateRatio`] a common
    /// value is `1.25` (the four-fifths rule); for [`FairnessMetric::RateDifference`], an absolute
    /// rate gap such as `0.1`.
    pub threshold: f64,
}

impl FairnessPolicy {
    pub fn ratio(threshold: f64) -> Self {
        FairnessPolicy {
            metric: FairnessMetric::RateRatio,
            threshold,
        }
    }
    pub fn difference(threshold: f64) -> Self {
        FairnessPolicy {
            metric: FairnessMetric::RateDifference,
            threshold,
        }
    }
}

/// The result of a bias assessment. `disparity` is measured by `metric`; `flagged` is
/// `disparity > threshold`. When at least two groups are present, `disadvantaged`/`advantaged` name
/// the worst-off/best-off group pair (the pair that produces the widest gap).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BiasReport {
    pub metric: FairnessMetric,
    pub threshold: f64,
    pub disparity: f64,
    pub min_rate: f64,
    pub max_rate: f64,
    /// Worst-off group (lowest favorable rate; ties broken by group name for determinism).
    pub disadvantaged: Option<String>,
    /// Best-off group (highest favorable rate; ties broken by group name for determinism).
    pub advantaged: Option<String>,
    pub n_groups: usize,
    pub flagged: bool,
}

impl BiasReport {
    /// The worst-off/best-off pair, if both are known.
    pub fn worst_pair(&self) -> Option<(&str, &str)> {
        match (&self.disadvantaged, &self.advantaged) {
            (Some(d), Some(a)) => Some((d.as_str(), a.as_str())),
            _ => None,
        }
    }
}

/// Compute a [`BiasReport`] from per-group favorable-outcome rates under `policy`.
///
/// Deterministic: the disadvantaged group is the minimum rate (ties broken by the lexicographically
/// smallest group name), the advantaged group the maximum (same tie-break). With fewer than two
/// groups there is no pair to compare, so disparity is parity (`1.0` for a ratio, `0.0` for a
/// difference) and the assessment is never flagged.
pub fn assess_bias(groups: &[GroupRate], policy: &FairnessPolicy) -> BiasReport {
    // Parity baseline for the degenerate (< 2 groups) case.
    let parity = match policy.metric {
        FairnessMetric::RateRatio => 1.0,
        FairnessMetric::RateDifference => 0.0,
    };

    if groups.len() < 2 {
        // With 0 or 1 group there is no comparison; still surface the single rate if present.
        let single = groups.first();
        let rate = single.map(|g| g.favorable_rate).unwrap_or(0.0);
        return BiasReport {
            metric: policy.metric,
            threshold: policy.threshold,
            disparity: parity,
            min_rate: rate,
            max_rate: rate,
            disadvantaged: None,
            advantaged: None,
            n_groups: groups.len(),
            flagged: false,
        };
    }

    // Find min/max groups. total_cmp gives a total order without float `==`; ties break on name.
    let mut min_g = &groups[0];
    let mut max_g = &groups[0];
    for g in &groups[1..] {
        match g.favorable_rate.total_cmp(&min_g.favorable_rate) {
            Ordering::Less => min_g = g,
            Ordering::Equal if g.group < min_g.group => min_g = g,
            _ => {}
        }
        match g.favorable_rate.total_cmp(&max_g.favorable_rate) {
            Ordering::Greater => max_g = g,
            Ordering::Equal if g.group < max_g.group => max_g = g,
            _ => {}
        }
    }

    let min_rate = min_g.favorable_rate;
    let max_rate = max_g.favorable_rate;

    let disparity = match policy.metric {
        FairnessMetric::RateRatio => {
            if min_rate <= 0.0 {
                // Division guarded: 0/0 → parity; positive/0 → maximal (infinite) disparity.
                if max_rate <= 0.0 {
                    1.0
                } else {
                    f64::INFINITY
                }
            } else {
                max_rate / min_rate
            }
        }
        FairnessMetric::RateDifference => max_rate - min_rate,
    };

    BiasReport {
        metric: policy.metric,
        threshold: policy.threshold,
        disparity,
        min_rate,
        max_rate,
        disadvantaged: Some(min_g.group.clone()),
        advantaged: Some(max_g.group.clone()),
        n_groups: groups.len(),
        flagged: disparity > policy.threshold,
    }
}

// ============================ Governance record + deploy gate ============================

/// The capability that authorizes a deployment sign-off.
pub const APPROVE_CAP: &str = "governance:approve";

/// `true` if a principal may sign off a deployment: an admin (implies all caps), or a user holding
/// the [`APPROVE_CAP`] capability. Fail-closed — an unknown/under-privileged approver cannot ship.
pub fn can_approve(principal: &Principal) -> bool {
    principal.has_cap(APPROVE_CAP)
}

/// A reason the [`deploy_gate`] refused a deployment.
#[derive(Debug, Clone, PartialEq)]
pub enum RefusalReason {
    /// The model card is structurally invalid (carries the defects).
    InvalidCard(Vec<CardDefect>),
    /// The system card, if present, is incomplete (carries the defects).
    IncompleteSystemCard(Vec<SystemCardDefect>),
    /// The risk class is [`RiskClass::Unacceptable`] — prohibited.
    UnacceptableRisk,
    /// Bias exceeds the fairness threshold; names the worst-off/best-off pair.
    BiasExceedsThreshold {
        disparity: f64,
        threshold: f64,
        disadvantaged: Option<String>,
        advantaged: Option<String>,
    },
    /// The named approver lacks approval authority.
    ApproverLacksAuthority(String),
}

impl fmt::Display for RefusalReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RefusalReason::InvalidCard(d) => {
                let fields: Vec<&str> = d.iter().map(|x| x.field()).collect();
                write!(f, "model card invalid (missing: {})", fields.join(", "))
            }
            RefusalReason::IncompleteSystemCard(d) => {
                let fields: Vec<&str> = d.iter().map(|x| x.field()).collect();
                write!(f, "system card incomplete (missing: {})", fields.join(", "))
            }
            RefusalReason::UnacceptableRisk => {
                write!(f, "risk class is Unacceptable — deployment is prohibited")
            }
            RefusalReason::BiasExceedsThreshold {
                disparity,
                threshold,
                disadvantaged,
                advantaged,
            } => {
                write!(
                    f,
                    "bias disparity {:.4} exceeds threshold {:.4} (worst pair: {} vs {})",
                    disparity,
                    threshold,
                    disadvantaged.as_deref().unwrap_or("?"),
                    advantaged.as_deref().unwrap_or("?"),
                )
            }
            RefusalReason::ApproverLacksAuthority(u) => {
                write!(f, "approver `{u}` lacks approval authority")
            }
        }
    }
}

/// The deploy gate's decision.
#[derive(Debug, Clone, PartialEq)]
pub enum DeployDecision {
    Approved,
    /// Refused, carrying *every* failing reason (so an author fixes them all at once).
    Refused(Vec<RefusalReason>),
}

impl DeployDecision {
    pub fn is_approved(&self) -> bool {
        matches!(self, DeployDecision::Approved)
    }
}

/// A governance record binding the AI-specific artifacts to a human approver at a point in time.
/// This is control-plane definition content (versioned under ADR-026 git governance). The audit
/// `recorded_tick` is caller-supplied — the crate never reads a clock.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceRecord {
    pub model_card: ModelCard,
    /// The composed-system card, when the deployment is a system rather than a bare model.
    pub system_card: Option<SystemCard>,
    pub bias_report: BiasReport,
    pub approver: Principal,
    pub approval_note: String,
    /// A caller-supplied monotonic tick for the audit trail (no wall clock in the logic).
    pub recorded_tick: u64,
}

impl GovernanceRecord {
    pub fn new(
        model_card: ModelCard,
        system_card: Option<SystemCard>,
        bias_report: BiasReport,
        approver: Principal,
        approval_note: &str,
        recorded_tick: u64,
    ) -> Self {
        GovernanceRecord {
            model_card,
            system_card,
            bias_report,
            approver,
            approval_note: approval_note.to_string(),
            recorded_tick,
        }
    }
}

/// The fail-closed deploy gate.
///
/// Refuses deployment if **any** of these hold, collecting every reason:
/// - the model card is structurally invalid,
/// - a present system card is incomplete,
/// - the risk class is [`RiskClass::Unacceptable`],
/// - bias exceeds the fairness threshold ([`BiasReport::flagged`]),
/// - the approver lacks approval authority.
///
/// Only a clean record with an authorized approver returns [`DeployDecision::Approved`].
pub fn deploy_gate(record: &GovernanceRecord) -> DeployDecision {
    let mut reasons = Vec::new();

    if let Err(defects) = record.model_card.validate() {
        reasons.push(RefusalReason::InvalidCard(defects));
    }

    if let Some(sys) = &record.system_card {
        if let Err(defects) = sys.completeness() {
            reasons.push(RefusalReason::IncompleteSystemCard(defects));
        }
    }

    if !record.model_card.risk_class.deployable() {
        reasons.push(RefusalReason::UnacceptableRisk);
    }

    if record.bias_report.flagged {
        reasons.push(RefusalReason::BiasExceedsThreshold {
            disparity: record.bias_report.disparity,
            threshold: record.bias_report.threshold,
            disadvantaged: record.bias_report.disadvantaged.clone(),
            advantaged: record.bias_report.advantaged.clone(),
        });
    }

    if !can_approve(&record.approver) {
        reasons.push(RefusalReason::ApproverLacksAuthority(
            record.approver.user_id.clone(),
        ));
    }

    if reasons.is_empty() {
        DeployDecision::Approved
    } else {
        DeployDecision::Refused(reasons)
    }
}

// ============================ Model-Risk Record / SR-11-7 (§4.2, gap P) ============================
//
// DPDP §10 algorithmic due diligence + SR-11-7 model risk management: a model route is not
// "certified once", it is *inventoried, independently validated, challenger-benchmarked, and
// continuously monitored*. The [`ModelRiskRecord`] is the control-plane inventory entry; the live
// scoreboard that backs it is data-plane. [`due_diligence_gate`] is the fail-closed promotion check
// — a route whose monitoring drops below the bar (or whose validation/challenger is missing) is
// refused, and in production that same signal trips the quality circuit-breaker (§2.1).

/// Where a model's weights/serving come from — the provenance an SR-11-7 inventory and the data
/// sovereignty gate (ADR-006-ext / ADR-012) both need.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum ModelProvenance {
    /// Hosted in-house on owned infrastructure (eligible for regulated/PII data).
    InHouse,
    /// A third-party cloud API (IT outsourcing per RBI §3; never eligible for regulated data).
    CloudApi { vendor: String },
    /// Open-weights model self-hosted; `origin` records the weights' source for supply-chain audit.
    OpenWeights { origin: String },
}

impl ModelProvenance {
    /// Whether this provenance may ever carry regulated/PII data. Only in-house or self-hosted
    /// open-weights are on-premise; a cloud API categorically may not (data-localisation, §3/ADR-012).
    pub fn allows_regulated(&self) -> bool {
        matches!(
            self,
            ModelProvenance::InHouse | ModelProvenance::OpenWeights { .. }
        )
    }
}

/// SR-11-7 independent-validation status of a model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum ValidationStatus {
    /// Not yet independently validated — a model in this state must not promote.
    NotValidated,
    /// Independently validated (by a party distinct from the developer) at the given logical tick.
    IndependentlyValidated { at_tick: u64 },
}

impl ValidationStatus {
    pub fn is_validated(&self) -> bool {
        matches!(self, ValidationStatus::IndependentlyValidated { .. })
    }
}

/// A reference to the challenger model benchmarked against the champion (SR-11-7 ongoing benchmarking).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengerRef {
    pub model_id: String,
    pub note: String,
}

/// The live monitoring scoreboard backing a model-risk record (data-plane). `latest_score` is the
/// continuously-evaluated quality/performance signal (0.0–1.0); `last_update_tick` anchors staleness.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct MonitoringScoreboard {
    pub latest_score: f64,
    pub samples: u64,
    pub last_update_tick: u64,
}

impl MonitoringScoreboard {
    pub fn new(latest_score: f64, samples: u64, last_update_tick: u64) -> Self {
        Self {
            latest_score,
            samples,
            last_update_tick,
        }
    }

    /// Whether the latest score is at or above `bar`.
    pub fn meets(&self, bar: f64) -> bool {
        self.latest_score >= bar
    }

    /// The age of the scoreboard at `now` (saturating; a `last_update_tick` in the future = age 0).
    pub fn age_at(&self, now: u64) -> u64 {
        now.saturating_sub(self.last_update_tick)
    }
}

/// A model-risk record — the control-plane SR-11-7 inventory entry for one model route / Role.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelRiskRecord {
    pub model_id: String,
    pub provenance: ModelProvenance,
    /// The maximum data class this model may carry — the router's eligibility ceiling (ADR-012/§3).
    pub permitted_data_class: DataClass,
    pub intended_use: String,
    pub risk_class: RiskClass,
    pub validation: ValidationStatus,
    /// The challenger benchmarked against this model, if any.
    pub challenger: Option<ChallengerRef>,
    /// The live monitoring scoreboard, if monitoring is wired up.
    pub monitoring: Option<MonitoringScoreboard>,
    pub limitations: Vec<String>,
}

impl ModelRiskRecord {
    /// Whether this model may carry data of `class` — `class <= permitted_data_class` **and**, for a
    /// regulated class, a provenance that allows regulated data (a cloud API can never, even if the
    /// permitted ceiling was mis-set — defense in depth on the sovereignty invariant).
    pub fn may_carry(&self, class: DataClass) -> bool {
        if class.sensitivity() > self.permitted_data_class.sensitivity() {
            return false;
        }
        if class.is_regulated() && !self.provenance.allows_regulated() {
            return false;
        }
        true
    }
}

/// The due-diligence bar a model-risk record must clear to promote (control-plane, DPO-reviewed).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct DueDiligenceConfig {
    /// Minimum acceptable monitoring score.
    pub min_score: f64,
    /// Risk class at or above which a challenger model is mandatory.
    pub require_challenger_at_or_above: RiskClass,
    /// Maximum monitoring staleness (ticks) tolerated at check time — older ⇒ stale ⇒ fail.
    pub max_monitoring_staleness: u64,
}

impl Default for DueDiligenceConfig {
    fn default() -> Self {
        Self {
            min_score: 0.8,
            require_challenger_at_or_above: RiskClass::High,
            max_monitoring_staleness: 1_000,
        }
    }
}

/// A way the [`due_diligence_gate`] found a model-risk record wanting.
#[derive(Debug, Clone, PartialEq)]
pub enum DueDiligenceDefect {
    /// Not independently validated (SR-11-7).
    NotIndependentlyValidated,
    /// Risk class requires a challenger but none is recorded.
    MissingChallenger { risk_class: RiskClass },
    /// No monitoring scoreboard at all — "monitored, not certified-once" is violated.
    NoMonitoring,
    /// The latest monitoring score is below the bar (the circuit-breaker trigger).
    ScoreBelowBar { score: f64, bar: f64 },
    /// The monitoring scoreboard is stale at check time.
    MonitoringStale { age: u64, max: u64 },
}

impl fmt::Display for DueDiligenceDefect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DueDiligenceDefect::NotIndependentlyValidated => {
                write!(f, "model-risk: not independently validated (SR-11-7)")
            }
            DueDiligenceDefect::MissingChallenger { risk_class } => write!(
                f,
                "model-risk: risk class {} requires a challenger model, none recorded",
                risk_class.as_str()
            ),
            DueDiligenceDefect::NoMonitoring => {
                write!(
                    f,
                    "model-risk: no monitoring scoreboard (must be continuously monitored)"
                )
            }
            DueDiligenceDefect::ScoreBelowBar { score, bar } => write!(
                f,
                "model-risk: monitoring score {score:.4} is below the due-diligence bar {bar:.4}"
            ),
            DueDiligenceDefect::MonitoringStale { age, max } => {
                write!(f, "model-risk: monitoring is stale (age {age} > max {max})")
            }
        }
    }
}

/// The due-diligence gate's decision (§4.2).
#[derive(Debug, Clone, PartialEq)]
pub enum DueDiligenceOutcome {
    Passed,
    /// Refused, carrying every failing reason (fix them all at once). Fail-closed.
    Failed(Vec<DueDiligenceDefect>),
}

impl DueDiligenceOutcome {
    pub fn is_passed(&self) -> bool {
        matches!(self, DueDiligenceOutcome::Passed)
    }
}

/// The fail-closed algorithmic-due-diligence gate (§4.2, SR-11-7). Refuses promotion of a model-risk
/// record at logical time `now` if **any** hold, collecting every reason:
/// - the model is not independently validated,
/// - its risk class requires a challenger and none is recorded,
/// - it has no monitoring scoreboard,
/// - the latest score is below `cfg.min_score`,
/// - the monitoring is staler than `cfg.max_monitoring_staleness` at `now`.
///
/// Deterministic in the injected `now`; no clock/rng. Only a clean, monitored, validated,
/// (challenger-backed where required), fresh, above-bar record [`Passes`](DueDiligenceOutcome::Passed).
pub fn due_diligence_gate(
    record: &ModelRiskRecord,
    cfg: &DueDiligenceConfig,
    now: u64,
) -> DueDiligenceOutcome {
    let mut defects = Vec::new();

    if !record.validation.is_validated() {
        defects.push(DueDiligenceDefect::NotIndependentlyValidated);
    }

    if record.risk_class >= cfg.require_challenger_at_or_above && record.challenger.is_none() {
        defects.push(DueDiligenceDefect::MissingChallenger {
            risk_class: record.risk_class,
        });
    }

    match &record.monitoring {
        None => defects.push(DueDiligenceDefect::NoMonitoring),
        Some(board) => {
            if !board.meets(cfg.min_score) {
                defects.push(DueDiligenceDefect::ScoreBelowBar {
                    score: board.latest_score,
                    bar: cfg.min_score,
                });
            }
            let age = board.age_at(now);
            if age > cfg.max_monitoring_staleness {
                defects.push(DueDiligenceDefect::MonitoringStale {
                    age,
                    max: cfg.max_monitoring_staleness,
                });
            }
        }
    }

    if defects.is_empty() {
        DueDiligenceOutcome::Passed
    } else {
        DueDiligenceOutcome::Failed(defects)
    }
}

// ============================ Quality circuit-breaker + promotion (FI-07, §2.1/§4.2) ============================
//
// SR-11-7 says a route is "monitored, not certified-once". Two seams make that live:
//   1. [`route_promotable`] — the promotion/router check: a route may promote only if its model-risk
//      record passes [`due_diligence_gate`] at `now`. This is the clean entrypoint a promotion path
//      or the model router calls before admitting a route (FI-07 wiring target).
//   2. [`QualityCircuitBreaker`] — the *runtime* half: when a live scoreboard on a regulated route
//      drops below the bar, the breaker **trips**, producing a [`BreakerTrip`] the parent maps to an
//      incident candidate (§2.1). The runtime crate stays decoupled from ainxt-incident by returning
//      the typed facts; the parent calls `IncidentCandidate::from_quality_breaker(..)`.

/// The facts of a circuit-breaker trip — enough for the parent to (a) contain the route and (b) open
/// a §2 operational-risk incident (`CandidateSource::QualityCircuitBreaker`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BreakerTrip {
    pub route_id: String,
    pub score: f64,
    pub bar: f64,
    /// Whether the route carries a regulated class (a degraded regulated route is RBI-reportable).
    pub regulated_route: bool,
}

/// The breaker's state for a route at a point in time.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum BreakerState {
    /// The route is healthy (scoreboard present and at/above the bar).
    Closed,
    /// The route is contained: the scoreboard is missing or below the bar.
    Open(BreakerTrip),
}

impl BreakerState {
    pub fn is_open(&self) -> bool {
        matches!(self, BreakerState::Open(_))
    }
    pub fn trip(&self) -> Option<&BreakerTrip> {
        match self {
            BreakerState::Open(t) => Some(t),
            BreakerState::Closed => None,
        }
    }
}

/// The runtime quality circuit-breaker (§2.1). Configured with the minimum acceptable live score; a
/// route whose monitoring scoreboard drops below it (or is absent) trips the breaker.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct QualityCircuitBreaker {
    pub bar: f64,
}

impl QualityCircuitBreaker {
    pub fn new(bar: f64) -> Self {
        Self { bar }
    }

    /// Evaluate a model-risk record's live scoreboard. Opens (trips) when there is no monitoring or
    /// the latest score is below the bar; otherwise stays closed. A regulated route (permitted class
    /// is regulated) is flagged so the parent arms the RBI operational-risk clock.
    pub fn evaluate(&self, record: &ModelRiskRecord) -> BreakerState {
        let regulated = record.permitted_data_class.is_regulated();
        match &record.monitoring {
            Some(board) if board.meets(self.bar) => BreakerState::Closed,
            Some(board) => BreakerState::Open(BreakerTrip {
                route_id: record.model_id.clone(),
                score: board.latest_score,
                bar: self.bar,
                regulated_route: regulated,
            }),
            None => BreakerState::Open(BreakerTrip {
                route_id: record.model_id.clone(),
                score: 0.0,
                bar: self.bar,
                regulated_route: regulated,
            }),
        }
    }
}

/// FI-07: the promotion/router admission check — a route may promote only if its model-risk record
/// passes algorithmic due diligence at `now`. This is the clean, non-overridable entrypoint the
/// promotion path (or the model router, before admitting an external route) calls; it wraps
/// [`due_diligence_gate`] so "monitored, not certified-once" is enforced at the exact seam a route
/// enters service.
pub fn route_promotable(
    record: &ModelRiskRecord,
    cfg: &DueDiligenceConfig,
    now: u64,
) -> DueDiligenceOutcome {
    due_diligence_gate(record, cfg, now)
}

// ============================ Tests ============================

#[cfg(test)]
mod tests {
    use super::*;
    use ainxt_types::DataClass;

    fn full_card(risk: RiskClass) -> ModelCard {
        ModelCard {
            model_id: "txn-fraud-scorer-v3".into(),
            intended_use: "Score transactions for fraud likelihood on a payment switch.".into(),
            out_of_scope_uses: vec![
                "Credit-worthiness decisions".into(),
                "Employment screening".into(),
            ],
            limitations: vec!["Degrades on merchant categories unseen in training".into()],
            training_data_summary: "18 months of labelled switch transactions, PII-stripped."
                .into(),
            eval_summary: "AUC 0.94 on holdout; fairness audit attached.".into(),
            risk_class: risk,
        }
    }

    fn approver() -> Principal {
        Principal::admin("gov-officer")
    }

    fn clean_bias() -> BiasReport {
        // Two groups, near-parity, ratio metric — not flagged.
        assess_bias(
            &[GroupRate::new("a", 0.80), GroupRate::new("b", 0.78)],
            &FairnessPolicy::ratio(1.25),
        )
    }

    fn regulated_record(score: f64, last_update: u64) -> ModelRiskRecord {
        ModelRiskRecord {
            model_id: "inhouse-payment-scorer".into(),
            provenance: ModelProvenance::InHouse,
            permitted_data_class: DataClass::RegulatedPayment,
            intended_use: "payment routing".into(),
            risk_class: RiskClass::High,
            validation: ValidationStatus::IndependentlyValidated { at_tick: 1 },
            challenger: Some(ChallengerRef {
                model_id: "challenger-x".into(),
                note: "benchmark".into(),
            }),
            monitoring: Some(MonitoringScoreboard::new(score, 10_000, last_update)),
            limitations: vec![],
        }
    }

    #[test]
    fn gap_ainxt_responsibleai_fi07_scoreboard_drop_fails_promotion_and_trips_breaker() {
        // §4.5 test 3: a model route's scoreboard drops below the due-diligence bar → the promotion
        // check fails AND the quality circuit-breaker trips, carrying the facts the parent needs to
        // open a §2 operational-risk incident. This is the "monitored, not certified-once" wiring.
        let cfg = DueDiligenceConfig::default(); // min_score 0.8
        let breaker = QualityCircuitBreaker::new(cfg.min_score);

        // Healthy route: promotable + breaker closed.
        let healthy = regulated_record(0.92, 100);
        assert!(route_promotable(&healthy, &cfg, 200).is_passed());
        assert!(!breaker.evaluate(&healthy).is_open());

        // Degraded route: promotion refused with ScoreBelowBar AND breaker opens.
        let degraded = regulated_record(0.55, 100);
        let outcome = route_promotable(&degraded, &cfg, 200);
        assert!(!outcome.is_passed());
        match outcome {
            DueDiligenceOutcome::Failed(defects) => assert!(defects
                .iter()
                .any(|d| matches!(d, DueDiligenceDefect::ScoreBelowBar { .. }))),
            _ => panic!("expected failure"),
        }
        let state = breaker.evaluate(&degraded);
        let trip = state.trip().expect("breaker must trip on a score drop");
        assert_eq!(trip.route_id, "inhouse-payment-scorer");
        assert!(
            trip.regulated_route,
            "a regulated route trip is RBI-reportable"
        );
        assert!((trip.score - 0.55).abs() < 1e-9);
    }

    #[test]
    fn gap_ainxt_responsibleai_fi07_stale_monitoring_blocks_promotion() {
        // A route whose monitoring is stale at check time cannot promote (SR-11-7 ongoing monitoring).
        let cfg = DueDiligenceConfig::default(); // max staleness 1000
        let stale = regulated_record(0.95, 100);
        assert!(!route_promotable(&stale, &cfg, 5_000).is_passed());
    }

    #[test]
    fn complete_card_validates() {
        assert!(full_card(RiskClass::Limited).validate().is_ok());
        assert!(full_card(RiskClass::High).is_valid());
    }

    #[test]
    fn incomplete_card_rejected_field_by_field() {
        // Every required field blanked → every defect, in stable order.
        let empty = ModelCard {
            model_id: "  ".into(),
            intended_use: "".into(),
            out_of_scope_uses: vec![],
            limitations: vec!["   ".into()], // present but blank → still no content
            training_data_summary: "".into(),
            eval_summary: "\t".into(),
            risk_class: RiskClass::Limited,
        };
        let defects = empty.validate().unwrap_err();
        assert_eq!(
            defects,
            vec![
                CardDefect::MissingModelId,
                CardDefect::MissingIntendedUse,
                CardDefect::NoOutOfScopeUses,
                CardDefect::NoLimitations,
                CardDefect::MissingTrainingDataSummary,
                CardDefect::MissingEvalSummary,
            ]
        );

        // A single missing field is reported alone (nothing else spuriously flagged).
        let mut one = full_card(RiskClass::Limited);
        one.eval_summary = "   ".into();
        assert_eq!(
            one.validate().unwrap_err(),
            vec![CardDefect::MissingEvalSummary]
        );

        let mut two = full_card(RiskClass::Limited);
        two.out_of_scope_uses = vec![];
        two.model_id = "".into();
        assert_eq!(
            two.validate().unwrap_err(),
            vec![CardDefect::MissingModelId, CardDefect::NoOutOfScopeUses]
        );
    }

    #[test]
    fn unacceptable_risk_is_not_deployable_but_card_still_structurally_valid() {
        let card = full_card(RiskClass::Unacceptable);
        // The card DESCRIBES a prohibited system — it is structurally valid...
        assert!(card.validate().is_ok());
        // ...but the risk class itself is not deployable.
        assert!(!card.risk_class.deployable());
        assert!(RiskClass::High.deployable());
        assert!(RiskClass::Minimal.deployable());
    }

    #[test]
    fn system_card_completeness_field_by_field() {
        let good = SystemCard {
            system_id: "settlement-copilot".into(),
            components: vec!["txn-fraud-scorer-v3".into(), "reconciler-v1".into()],
            data_flows: vec!["Ledger → scorer → reviewer queue".into()],
            human_oversight: "A settlement officer confirms every auto-flag before action.".into(),
        };
        assert!(good.completeness().is_ok());

        let bad = SystemCard {
            system_id: "".into(),
            components: vec![],
            data_flows: vec!["   ".into()],
            human_oversight: "".into(),
        };
        assert_eq!(
            bad.completeness().unwrap_err(),
            vec![
                SystemCardDefect::MissingSystemId,
                SystemCardDefect::NoComponents,
                SystemCardDefect::NoDataFlows,
                SystemCardDefect::MissingHumanOversight,
            ]
        );

        // A blank component (list non-empty) is caught distinctly from an empty list.
        let blank_comp = SystemCard {
            system_id: "s".into(),
            components: vec!["ok".into(), "  ".into()],
            data_flows: vec!["flow".into()],
            human_oversight: "human".into(),
        };
        assert_eq!(
            blank_comp.completeness().unwrap_err(),
            vec![SystemCardDefect::BlankComponent]
        );
    }

    #[test]
    fn disparity_ratio_computed_exactly_and_names_worst_pair() {
        // Rates: hi=0.90 (best), mid=0.75, lo=0.60 (worst). ratio = 0.90/0.60 = 1.5 > 1.25 → flagged.
        let groups = [
            GroupRate::new("mid", 0.75),
            GroupRate::new("hi", 0.90),
            GroupRate::new("lo", 0.60),
        ];
        let report = assess_bias(&groups, &FairnessPolicy::ratio(1.25));
        assert!(
            (report.disparity - 1.5).abs() < 1e-12,
            "disparity was {}",
            report.disparity
        );
        assert!(report.flagged);
        assert_eq!(report.worst_pair(), Some(("lo", "hi")));
        assert!((report.min_rate - 0.60).abs() < 1e-12);
        assert!((report.max_rate - 0.90).abs() < 1e-12);
        assert_eq!(report.n_groups, 3);
    }

    #[test]
    fn disparity_difference_metric_computed_exactly() {
        let groups = [GroupRate::new("women", 0.55), GroupRate::new("men", 0.80)];
        let report = assess_bias(&groups, &FairnessPolicy::difference(0.10));
        // 0.80 - 0.55 = 0.25 > 0.10 → flagged, worst pair (women, men).
        assert!(
            (report.disparity - 0.25).abs() < 1e-12,
            "disparity was {}",
            report.disparity
        );
        assert!(report.flagged);
        assert_eq!(report.worst_pair(), Some(("women", "men")));
    }

    #[test]
    fn zero_rate_group_yields_infinite_ratio_and_flags() {
        let groups = [
            GroupRate::from_counts("north", 0, 50),
            GroupRate::new("south", 0.7),
        ];
        let report = assess_bias(&groups, &FairnessPolicy::ratio(1.25));
        assert!(report.disparity.is_infinite());
        assert!(report.flagged);
        assert_eq!(report.worst_pair(), Some(("north", "south")));
    }

    #[test]
    fn equal_rates_do_not_flag() {
        let groups = [
            GroupRate::new("a", 0.70),
            GroupRate::new("b", 0.70),
            GroupRate::new("c", 0.70),
        ];
        let ratio = assess_bias(&groups, &FairnessPolicy::ratio(1.25));
        assert!((ratio.disparity - 1.0).abs() < 1e-12);
        assert!(!ratio.flagged);

        let diff = assess_bias(&groups, &FairnessPolicy::difference(0.10));
        assert!((diff.disparity - 0.0).abs() < 1e-12);
        assert!(!diff.flagged);
    }

    #[test]
    fn all_zero_rates_are_parity_not_infinite() {
        let groups = [GroupRate::new("a", 0.0), GroupRate::new("b", 0.0)];
        let report = assess_bias(&groups, &FairnessPolicy::ratio(1.25));
        assert!((report.disparity - 1.0).abs() < 1e-12);
        assert!(!report.flagged);
    }

    #[test]
    fn tie_break_is_deterministic_by_name() {
        // Two groups share the min rate; the lexicographically smaller name is chosen.
        let groups = [
            GroupRate::new("zeta", 0.5),
            GroupRate::new("alpha", 0.5),
            GroupRate::new("top", 0.9),
        ];
        let report = assess_bias(&groups, &FairnessPolicy::ratio(1.0));
        assert_eq!(report.disadvantaged.as_deref(), Some("alpha"));
        assert_eq!(report.advantaged.as_deref(), Some("top"));
    }

    #[test]
    fn single_group_has_no_pair_and_does_not_flag() {
        let report = assess_bias(&[GroupRate::new("solo", 0.3)], &FairnessPolicy::ratio(1.25));
        assert!(!report.flagged);
        assert_eq!(report.worst_pair(), None);
        assert!((report.disparity - 1.0).abs() < 1e-12);
        assert_eq!(report.n_groups, 1);
    }

    #[test]
    fn deploy_gate_passes_clean_record() {
        let record = GovernanceRecord::new(
            full_card(RiskClass::Limited),
            None,
            clean_bias(),
            approver(),
            "Reviewed; conforms.",
            42,
        );
        assert_eq!(deploy_gate(&record), DeployDecision::Approved);
        assert!(deploy_gate(&record).is_approved());
    }

    #[test]
    fn deploy_gate_passes_high_risk_when_otherwise_clean() {
        // High risk is deployable (with oversight); only Unacceptable is prohibited.
        let record = GovernanceRecord::new(
            full_card(RiskClass::High),
            Some(SystemCard {
                system_id: "s".into(),
                components: vec!["txn-fraud-scorer-v3".into()],
                data_flows: vec!["in → score → human review".into()],
                human_oversight: "Officer reviews all high-risk flags.".into(),
            }),
            clean_bias(),
            approver(),
            "High-risk, oversight documented.",
            7,
        );
        assert!(deploy_gate(&record).is_approved());
    }

    #[test]
    fn deploy_gate_fails_closed_on_unacceptable_risk() {
        let record = GovernanceRecord::new(
            full_card(RiskClass::Unacceptable),
            None,
            clean_bias(),
            approver(),
            "",
            1,
        );
        match deploy_gate(&record) {
            DeployDecision::Refused(reasons) => {
                assert!(reasons.contains(&RefusalReason::UnacceptableRisk));
            }
            DeployDecision::Approved => panic!("unacceptable risk must be refused"),
        }
    }

    #[test]
    fn deploy_gate_fails_closed_on_invalid_card() {
        let mut card = full_card(RiskClass::Limited);
        card.eval_summary = "".into();
        let record = GovernanceRecord::new(card, None, clean_bias(), approver(), "", 1);
        match deploy_gate(&record) {
            DeployDecision::Refused(reasons) => {
                assert!(reasons
                    .iter()
                    .any(|r| matches!(r, RefusalReason::InvalidCard(d) if d == &vec![CardDefect::MissingEvalSummary])));
            }
            DeployDecision::Approved => panic!("invalid card must be refused"),
        }
    }

    #[test]
    fn deploy_gate_fails_closed_on_biased_model() {
        let biased = assess_bias(
            &[GroupRate::new("lo", 0.5), GroupRate::new("hi", 0.95)],
            &FairnessPolicy::ratio(1.25),
        );
        assert!(biased.flagged);
        let record = GovernanceRecord::new(
            full_card(RiskClass::Limited),
            None,
            biased,
            approver(),
            "",
            1,
        );
        match deploy_gate(&record) {
            DeployDecision::Refused(reasons) => {
                assert!(reasons.iter().any(|r| matches!(
                    r,
                    RefusalReason::BiasExceedsThreshold { disadvantaged, advantaged, .. }
                        if disadvantaged.as_deref() == Some("lo") && advantaged.as_deref() == Some("hi")
                )));
            }
            DeployDecision::Approved => panic!("biased model must be refused"),
        }
    }

    #[test]
    fn deploy_gate_fails_closed_on_unauthorized_approver() {
        let nobody = Principal::user("intern", &["chat:use"]);
        assert!(!can_approve(&nobody));
        let record = GovernanceRecord::new(
            full_card(RiskClass::Limited),
            None,
            clean_bias(),
            nobody,
            "",
            1,
        );
        match deploy_gate(&record) {
            DeployDecision::Refused(reasons) => {
                assert!(reasons.contains(&RefusalReason::ApproverLacksAuthority("intern".into())));
            }
            DeployDecision::Approved => panic!("unauthorized approver must be refused"),
        }
    }

    #[test]
    fn cap_holder_can_approve() {
        let officer = Principal::user("risk-officer", &["governance:approve"])
            .with_clearance(DataClass::Confidential);
        assert!(can_approve(&officer));
        let record = GovernanceRecord::new(
            full_card(RiskClass::Limited),
            None,
            clean_bias(),
            officer,
            "ok",
            9,
        );
        assert!(deploy_gate(&record).is_approved());
    }

    #[test]
    fn deploy_gate_collects_every_reason_at_once() {
        // Invalid card + incomplete system card + unacceptable risk + biased + bad approver.
        let mut card = full_card(RiskClass::Unacceptable);
        card.intended_use = "".into();
        let sys = SystemCard {
            system_id: "".into(),
            components: vec![],
            data_flows: vec![],
            human_oversight: "".into(),
        };
        let biased = assess_bias(
            &[GroupRate::new("lo", 0.4), GroupRate::new("hi", 0.9)],
            &FairnessPolicy::ratio(1.25),
        );
        let record = GovernanceRecord::new(
            card,
            Some(sys),
            biased,
            Principal::user("intern", &[]),
            "",
            1,
        );
        let reasons = match deploy_gate(&record) {
            DeployDecision::Refused(r) => r,
            DeployDecision::Approved => panic!("must be refused"),
        };
        assert_eq!(
            reasons.len(),
            5,
            "expected all five failure classes, got {reasons:?}"
        );
        assert!(reasons
            .iter()
            .any(|r| matches!(r, RefusalReason::InvalidCard(_))));
        assert!(reasons
            .iter()
            .any(|r| matches!(r, RefusalReason::IncompleteSystemCard(_))));
        assert!(reasons.contains(&RefusalReason::UnacceptableRisk));
        assert!(reasons
            .iter()
            .any(|r| matches!(r, RefusalReason::BiasExceedsThreshold { .. })));
        assert!(reasons
            .iter()
            .any(|r| matches!(r, RefusalReason::ApproverLacksAuthority(_))));
    }

    #[test]
    fn risk_class_orders_least_to_most_severe() {
        assert!(RiskClass::Minimal < RiskClass::Limited);
        assert!(RiskClass::Limited < RiskClass::High);
        assert!(RiskClass::High < RiskClass::Unacceptable);
    }

    #[test]
    fn record_serde_round_trips() {
        let record = GovernanceRecord::new(
            full_card(RiskClass::High),
            None,
            clean_bias(),
            approver(),
            "note",
            123,
        );
        let json = serde_json::to_string(&record).unwrap();
        let back: GovernanceRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.model_card, record.model_card);
        assert_eq!(back.recorded_tick, 123);
        assert_eq!(back.bias_report.flagged, record.bias_report.flagged);
    }

    // ==================== Model-Risk Record / SR-11-7 (§4.2) ====================

    fn healthy_risk_record() -> ModelRiskRecord {
        ModelRiskRecord {
            model_id: "in-house-fraud-v3".into(),
            provenance: ModelProvenance::InHouse,
            permitted_data_class: DataClass::RegulatedPayment,
            intended_use: "Fraud scoring on the switch".into(),
            risk_class: RiskClass::High,
            validation: ValidationStatus::IndependentlyValidated { at_tick: 10 },
            challenger: Some(ChallengerRef {
                model_id: "challenger-v1".into(),
                note: "monthly benchmark".into(),
            }),
            monitoring: Some(MonitoringScoreboard::new(0.92, 5000, 100)),
            limitations: vec!["degrades on unseen merchants".into()],
        }
    }

    #[test]
    fn may_carry_enforces_ceiling_and_regulated_provenance() {
        let rec = healthy_risk_record();
        // In-house, permitted up to regulated-payment → may carry regulated + lower.
        assert!(rec.may_carry(DataClass::RegulatedPayment));
        assert!(rec.may_carry(DataClass::Internal));

        // A cloud route can NEVER carry regulated data even if the ceiling is mis-set high.
        let mut cloud = healthy_risk_record();
        cloud.provenance = ModelProvenance::CloudApi {
            vendor: "acme-llm".into(),
        };
        cloud.permitted_data_class = DataClass::Pii; // deliberately mis-set high
        assert!(!cloud.may_carry(DataClass::RegulatedPayment));
        assert!(!cloud.may_carry(DataClass::Pii));
        // ...but it may still carry non-regulated up to its ceiling.
        assert!(cloud.may_carry(DataClass::Confidential));

        // Ceiling below the requested class → refused.
        let mut low = healthy_risk_record();
        low.permitted_data_class = DataClass::Internal;
        assert!(!low.may_carry(DataClass::Confidential));
    }

    #[test]
    fn due_diligence_passes_a_healthy_record() {
        let cfg = DueDiligenceConfig::default();
        assert_eq!(
            due_diligence_gate(&healthy_risk_record(), &cfg, 200),
            DueDiligenceOutcome::Passed
        );
    }

    #[test]
    fn due_diligence_fails_closed_when_not_validated() {
        let cfg = DueDiligenceConfig::default();
        let mut rec = healthy_risk_record();
        rec.validation = ValidationStatus::NotValidated;
        match due_diligence_gate(&rec, &cfg, 200) {
            DueDiligenceOutcome::Failed(d) => {
                assert!(d.contains(&DueDiligenceDefect::NotIndependentlyValidated))
            }
            DueDiligenceOutcome::Passed => panic!("unvalidated model must fail"),
        }
    }

    #[test]
    fn due_diligence_requires_challenger_for_high_risk() {
        let cfg = DueDiligenceConfig::default();
        let mut rec = healthy_risk_record();
        rec.challenger = None; // High risk with no challenger
        match due_diligence_gate(&rec, &cfg, 200) {
            DueDiligenceOutcome::Failed(d) => assert!(d
                .iter()
                .any(|x| matches!(x, DueDiligenceDefect::MissingChallenger { .. }))),
            DueDiligenceOutcome::Passed => panic!("high-risk without challenger must fail"),
        }
        // A limited-risk model does NOT require a challenger.
        let mut limited = healthy_risk_record();
        limited.risk_class = RiskClass::Limited;
        limited.challenger = None;
        assert!(due_diligence_gate(&limited, &cfg, 200).is_passed());
    }

    #[test]
    fn due_diligence_fails_on_low_score_the_circuit_breaker_trigger() {
        let cfg = DueDiligenceConfig::default(); // min 0.8
        let mut rec = healthy_risk_record();
        rec.monitoring = Some(MonitoringScoreboard::new(0.55, 100, 100));
        match due_diligence_gate(&rec, &cfg, 200) {
            DueDiligenceOutcome::Failed(d) => assert!(d.iter().any(|x| matches!(
                x,
                DueDiligenceDefect::ScoreBelowBar { score, bar } if *score == 0.55 && *bar == 0.8
            ))),
            DueDiligenceOutcome::Passed => panic!("below-bar score must fail"),
        }
    }

    #[test]
    fn due_diligence_fails_on_stale_or_absent_monitoring() {
        let cfg = DueDiligenceConfig::default(); // max staleness 1000
                                                 // Stale: last update at 100, checked at 2000 → age 1900 > 1000.
        let mut stale = healthy_risk_record();
        stale.monitoring = Some(MonitoringScoreboard::new(0.95, 100, 100));
        match due_diligence_gate(&stale, &cfg, 2000) {
            DueDiligenceOutcome::Failed(d) => assert!(d
                .iter()
                .any(|x| matches!(x, DueDiligenceDefect::MonitoringStale { .. }))),
            DueDiligenceOutcome::Passed => panic!("stale monitoring must fail"),
        }
        // Absent monitoring.
        let mut none = healthy_risk_record();
        none.monitoring = None;
        match due_diligence_gate(&none, &cfg, 200) {
            DueDiligenceOutcome::Failed(d) => {
                assert!(d.contains(&DueDiligenceDefect::NoMonitoring))
            }
            DueDiligenceOutcome::Passed => panic!("no monitoring must fail"),
        }
    }

    #[test]
    fn due_diligence_collects_every_defect() {
        let cfg = DueDiligenceConfig::default();
        let bad = ModelRiskRecord {
            model_id: "x".into(),
            provenance: ModelProvenance::CloudApi { vendor: "v".into() },
            permitted_data_class: DataClass::Internal,
            intended_use: "u".into(),
            risk_class: RiskClass::High,
            validation: ValidationStatus::NotValidated,
            challenger: None,
            monitoring: Some(MonitoringScoreboard::new(0.1, 1, 0)),
            limitations: vec![],
        };
        match due_diligence_gate(&bad, &cfg, 5000) {
            DueDiligenceOutcome::Failed(d) => {
                // not-validated + missing-challenger + below-bar + stale = 4.
                assert_eq!(d.len(), 4, "got {d:?}");
            }
            DueDiligenceOutcome::Passed => panic!("must fail"),
        }
    }

    #[test]
    fn model_risk_record_serde_round_trips() {
        let rec = healthy_risk_record();
        let json = serde_json::to_string(&rec).unwrap();
        let back: ModelRiskRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back, rec);
    }
}
