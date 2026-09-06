// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! ainxt-incident — the statutory AI-incident breach-notification engine
//! (`REGULATED_FI_COMPLIANCE_OPS.md` §2; ADR-011 extended into a *statutory* breach engine by
//! ADR-017; Pass-5 gap **[3]**).
//!
//! # The problem this closes
//!
//! India's payment switch is subject, the moment it processes a query, to hard statutory clocks:
//! **CERT-In gives 6 hours** from *noticing* a cyber incident to file; DPDP imposes breach-notice
//! windows; RBI imposes outsourcing/operational-risk reporting. A runbook has no clock and no teeth.
//! The design principle: **every statutory deadline is an SLO with a durable countdown, and missing
//! one is structurally impossible to hide.**
//!
//! # What this crate is
//!
//! A pure, deterministic, durable **state machine**:
//!
//! - [`IncidentCandidate`] — a typed notice from a detection source (the compliance gate, the
//!   write-path sink-guard, the quality circuit-breaker, the payment boundary, serving-ops, the
//!   store-sweep, an operator, or an inbound advisory). Its `noticed_tick` is the legally operative
//!   **t0**.
//! - [`ArmingPolicy`] — the **control-plane** table (git-native, Q2): *incident class ⇒ which
//!   statutory clocks fire, with what budget*. The model classifies; the **policy** arms — so a
//!   confused model cannot disarm a clock. Fail-safe: arm early ([`StatutoryClock::provisional`]),
//!   disarm only on an authenticated, reason-coded [`downgrade`](IncidentRegister::downgrade).
//! - [`StatutoryClock`] — a durable countdown from an **immutable t0** with a config budget, a
//!   50 / 75 / 90 %→owner/DPO/CISO + breach→board-delegate escalation ladder, and a
//!   **crash-survival** property: the clock lives in the (serde) register, never in a process, so a
//!   restart re-projects it and continues counting from real elapsed wall-clock — t0 is never reset.
//! - [`IncidentRegister`] — the append-only, **SHA-256 hash-chained** register (evidentiary,
//!   [`verify`](IncidentRegister::verify)) that opens incidents, arms clocks, and — on
//!   [`tick`](IncidentRegister::tick) — pages the ladder and **auto-raises a P1 compliance
//!   meta-incident** the instant a clock crosses its budget without a recorded filing. A missed
//!   deadline is therefore itself a first-class, un-hideable event.
//!
//! # Determinism
//!
//! No wall clock, no RNG, no I/O. Logical time is the injected `now` [`Tick`]; the control-plane SHA
//! and NTP particulars are injected strings. The same register advanced to the same `now` always
//! produces the same pages, meta-incidents, and hash chain — so every property below is unit-testable.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use ainxt_cryptoagility::{AlgorithmRegistry, GovernedHasher, Purpose};
use ainxt_types::{DataClass, Principal};

pub mod cadence;
pub mod durable;
pub mod evidence;
pub mod ops;
pub mod report;

/// Logical time. A larger tick is "later". Clocks count from an injected `t0` against an injected
/// `now`; there is no wall-clock read anywhere in non-test code.
pub type Tick = u64;

// ============================ the tick unit (the one that must be consistent) ============================
//
// The register is deterministic on *logical* [`Tick`]s, but a live deployment drives it from a wall
// clock — and the arming budgets, the `t0`, and the `now` fed to [`IncidentRegister::tick`] MUST all be
// the SAME unit or a clock breaches at the wrong time. The [`ArmingPolicy::india_regulatory_default`] budgets are
// **minute-scaled** (CERT-In 6h = 360, DPDP-board 72h = 4320, …). A driver that fed the register raw
// wall-clock *seconds* (`SystemTime::now().as_secs()`) against those minute budgets would make every
// statutory clock breach **60× early** — a 72h DPDP clock would breach after 72 *minutes*, not 72
// *hours*. This is a real, load-bearing footgun (Round-10 fix), so the canonical unit and the sole
// wall-clock→tick projection live here, next to the budgets, and the live driver funnels through it.

/// Wall-clock seconds per one logical [`Tick`] on the [`india_regulatory_default`](ArmingPolicy::india_regulatory_default)
/// statutory register: **60** — i.e. one tick is one minute, the unit the default budgets are scaled in
/// (`CERT-In 6h = 360 ticks`). A live breach-clock driver reading Unix-epoch seconds MUST project them
/// onto the tick axis with [`ticks_from_unix_secs`] rather than feeding raw seconds, or clocks breach
/// 60× early.
pub const SECONDS_PER_TICK: u64 = 60;

/// Project a wall-clock instant (Unix-epoch **seconds**) onto the register's logical [`Tick`] axis at
/// the [`SECONDS_PER_TICK`] resolution the [`india_regulatory_default`](ArmingPolicy::india_regulatory_default) budgets assume.
/// This is the **single** conversion the live breach-clock ticker and every wall-clock incident-open
/// site must funnel through, so `t0`, `now`, and `budget_ticks` are one consistent unit (minutes).
/// Truncating (floor) division: a clock is never made to breach earlier than the real elapsed minute.
#[inline]
pub const fn ticks_from_unix_secs(unix_secs: u64) -> Tick {
    unix_secs / SECONDS_PER_TICK
}

/// Budget helper: `hours` expressed in [`SECONDS_PER_TICK`]-scaled ticks (`h * 60`, saturating). Lets a
/// policy author write `budget_ticks_from_hours(72)` for a 72h clock instead of hand-computing `4320`
/// and risking the very unit slip this module exists to prevent.
#[inline]
pub const fn budget_ticks_from_hours(hours: u64) -> u64 {
    hours.saturating_mul(60)
}

/// The capability a principal must hold to downgrade (disarm) a provisionally-armed clock. Fail-safe:
/// arming needs no authority; *disarming* does (§2.2).
pub const DOWNGRADE_CAP: &str = "compliance:downgrade-clock";

// ============================ classification + sources ============================

/// The classified incident class (§2.2). The model *proposes* this; the [`ArmingPolicy`] then arms
/// deterministically from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IncidentClass {
    /// A data principal's personal data was exposed.
    PersonalDataBreach,
    /// A CERT-In-category cyber security incident (unauthorized access, data breach, …).
    CyberSecurityIncident,
    /// A material outsourced-service disruption / provider failure.
    OutsourcedServiceDisruption,
    /// An attempted or actual agent-initiated settlement-class action (the hardest class, ADR-016).
    AgentSettlementAction,
    /// Quality degradation on a regulated route (operational-risk log; no data exposure).
    QualityDegradationRegulatedRoute,
    /// The engine-raised meta-incident: "we may have missed a statutory deadline" (§2.3).
    ComplianceDeadlineMissed,
}

impl IncidentClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            IncidentClass::PersonalDataBreach => "personal-data-breach",
            IncidentClass::CyberSecurityIncident => "cyber-security-incident",
            IncidentClass::OutsourcedServiceDisruption => "outsourced-service-disruption",
            IncidentClass::AgentSettlementAction => "agent-settlement-action",
            IncidentClass::QualityDegradationRegulatedRoute => {
                "quality-degradation-regulated-route"
            }
            IncidentClass::ComplianceDeadlineMissed => "compliance-deadline-missed",
        }
    }

    /// The **protective severity rank** of a class (higher = more statutory exposure). This is the axis
    /// the triage floor turns on (§2.2): a triage Role may *escalate* a candidate to a more-protective
    /// class, but a proposal *below* the source's fail-safe floor never lowers the armed class — a
    /// confused/adversarial model cannot talk the runtime into arming *less*. Payment-settlement and
    /// personal-data exposure sit at the top; a pure quality-degradation operational-risk log at the
    /// bottom. `ComplianceDeadlineMissed` is engine-raised, not a triage target, and ranks with cyber.
    pub fn severity_rank(&self) -> u8 {
        match self {
            IncidentClass::AgentSettlementAction => 5,
            IncidentClass::PersonalDataBreach => 4,
            IncidentClass::CyberSecurityIncident => 3,
            IncidentClass::ComplianceDeadlineMissed => 3,
            IncidentClass::OutsourcedServiceDisruption => 2,
            IncidentClass::QualityDegradationRegulatedRoute => 1,
        }
    }
}

/// A **triage Role's proposal** (§2.2, agentic incident taxonomy): the model classifies, the policy
/// arms. This is the model's *advisory* output — a proposed class with a confidence and a PII-free
/// rationale. It is recorded verbatim on the evidentiary chain and can only *escalate* the armed class
/// above the source's fail-safe floor via [`IncidentRegister::open_from_triage`]; it can never disarm
/// or de-escalate a clock (that needs an authenticated, capability-gated [`downgrade`]). So a wrong or
/// hijacked triage model degrades gracefully to "arm at least the fail-safe class", never to silence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TriageProposal {
    /// The class the triage Role proposes.
    pub proposed_class: IncidentClass,
    /// The model's self-reported confidence, 0..=100 (integer so the value hashes deterministically —
    /// no float formatting drift on the evidentiary chain). Clamped to 100 on construction.
    pub confidence_pct: u8,
    /// The identifier of the triage Role/model that produced the proposal (audit — "who classified").
    pub model: String,
    /// A short, PII-free rationale for the classification (audit; not load-bearing on arming).
    pub rationale: String,
}

impl TriageProposal {
    /// A proposal from `model` for `proposed_class` at `confidence_pct` (clamped to 100).
    pub fn new(model: &str, proposed_class: IncidentClass, confidence_pct: u8) -> Self {
        Self {
            proposed_class,
            confidence_pct: confidence_pct.min(100),
            model: model.to_string(),
            rationale: String::new(),
        }
    }

    /// Attach a PII-free rationale (chainable).
    pub fn with_rationale(mut self, rationale: &str) -> Self {
        self.rationale = rationale.to_string();
        self
    }
}

/// Where an [`IncidentCandidate`] came from (§2.1). Each is a real runtime detector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CandidateSource {
    /// The compliance gate saw a regulated class egress where policy forbids it.
    ComplianceGateEgress,
    /// The write-path sink-guard caught CHD reaching a durable store.
    WritePathSinkGuard,
    /// The quality circuit-breaker saw a judge-score collapse on a regulated route.
    QualityCircuitBreaker,
    /// The payment boundary saw an anomalous/attempted settlement action.
    PaymentBoundary,
    /// Serving-ops reported a material disruption of a critical route.
    ServingOps,
    /// The defense-in-depth store sweep found CHD in a store.
    StoreSweep,
    /// The NTP clock-skew monitor alarmed.
    NtpSkew,
    /// A human operator declared an incident.
    OperatorDeclaration,
    /// An inbound CERT-In / RBI advisory.
    InboundAdvisory,
    /// The India-residency verifier found a log/data store resolving outside Indian jurisdiction
    /// (§8.1 — a mis-located store is a §2 incident).
    ResidencyViolation,
    /// The engine itself, raising a meta-incident.
    EngineMetaIncident,
}

impl CandidateSource {
    /// The **fail-safe default incident class** for a source (§2.2). A live triage Role may *propose*
    /// a more specific class, but until an accountable owner confirms, the runtime arms from this
    /// deterministic mapping so a detector always arms *something* — a confused/absent model can never
    /// leave a reportable event unclassified. Chosen conservatively (arm early, disarm on authority).
    pub fn default_class(&self) -> IncidentClass {
        match self {
            // A regulated class leaving where it must not = personal-data breach + cyber.
            CandidateSource::ComplianceGateEgress => IncidentClass::PersonalDataBreach,
            // CHD reaching a durable store / found in one = a control failure, treated as cyber.
            CandidateSource::WritePathSinkGuard | CandidateSource::StoreSweep => {
                IncidentClass::CyberSecurityIncident
            }
            // A degraded model on a regulated route = RBI operational-risk.
            CandidateSource::QualityCircuitBreaker => {
                IncidentClass::QualityDegradationRegulatedRoute
            }
            CandidateSource::PaymentBoundary => IncidentClass::AgentSettlementAction,
            CandidateSource::ServingOps => IncidentClass::OutsourcedServiceDisruption,
            // Skew undermines evidentiary timestamps + can double-execute sagas = cyber.
            CandidateSource::NtpSkew => IncidentClass::CyberSecurityIncident,
            CandidateSource::ResidencyViolation => IncidentClass::CyberSecurityIncident,
            CandidateSource::OperatorDeclaration | CandidateSource::InboundAdvisory => {
                IncidentClass::CyberSecurityIncident
            }
            CandidateSource::EngineMetaIncident => IncidentClass::ComplianceDeadlineMissed,
        }
    }
}

// ============================ statutory clocks ============================

/// A statutory clock kind — the deadline family a countdown belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StatutoryClockKind {
    /// CERT-In (IT Act §70B; 2022 Directions) — 6 hours by default.
    CertIn,
    /// DPDP notice to the affected data principal ("without undue delay").
    DpdpDataPrincipal,
    /// DPDP detailed report to the Board (72h per the settling Rules).
    DpdpBoard,
    /// RBI outsourcing / operational-risk report (per contract/direction).
    RbiOutsourcing,
    /// Payment-boundary hard-class escalation (ADR-016).
    PaymentBoundaryEscalation,
}

impl StatutoryClockKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            StatutoryClockKind::CertIn => "cert-in",
            StatutoryClockKind::DpdpDataPrincipal => "dpdp-data-principal",
            StatutoryClockKind::DpdpBoard => "dpdp-board",
            StatutoryClockKind::RbiOutsourcing => "rbi-outsourcing",
            StatutoryClockKind::PaymentBoundaryEscalation => "payment-boundary-escalation",
        }
    }
}

/// An escalation tier on the paging ladder (§2.3), least → most senior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EscalationTier {
    IncidentOwner,
    Dpo,
    Ciso,
    BoardDelegate,
}

/// The paging ladder: `(percent-of-budget-elapsed, tier)`. Crossing a threshold pages that tier
/// once. `BoardDelegate` at 100 % (deadline reached) is the last rung before the breach meta-incident.
const ESCALATION_LADDER: &[(u64, EscalationTier)] = &[
    (50, EscalationTier::IncidentOwner),
    (75, EscalationTier::Dpo),
    (90, EscalationTier::Ciso),
    (100, EscalationTier::BoardDelegate),
];

/// A filed statutory report — the act that stops a clock's breach (§2.4). The filing is the legal
/// act (a human files it); the engine only records it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Filing {
    /// The control-plane version of the report template used (a control-plane SHA / version string).
    pub template_version: String,
    /// Logical tick the filing was submitted.
    pub submitted_tick: Tick,
    /// The regulator's acknowledgement reference.
    pub ack_ref: String,
}

/// An authenticated, reason-coded downgrade of a provisionally-armed clock (§2.2). Disarming is the
/// only way to stop a clock without filing, and it requires authority — you can never *drift* into a
/// missed deadline, only *decide, on the record,* that a clock does not apply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Downgrade {
    /// The accountable owner who downgraded (their user id).
    pub actor: String,
    /// The reason code.
    pub reason: String,
    /// Logical tick of the downgrade.
    pub tick: Tick,
}

/// A durable statutory countdown (§2.3). Lives in the register (serde), not a process — a restart
/// re-projects it from the immutable `t0` and continues from real elapsed time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatutoryClock {
    pub kind: StatutoryClockKind,
    /// The legally operative instant (time of first notice). **Immutable** — never reset, even by a
    /// restart or a pause.
    pub t0: Tick,
    /// The statutory budget in ticks (config-driven — DPDP timelines are still settling).
    pub budget_ticks: u64,
    /// `true` until an accountable owner confirms the classification (fail-safe: armed early).
    pub provisional: bool,
    /// The filing that stopped this clock, if any.
    pub filing: Option<Filing>,
    /// The authenticated downgrade that disarmed this clock, if any.
    pub downgrade: Option<Downgrade>,
    /// Escalation tiers already paged (so each is paged at most once).
    pub paged: BTreeSet<EscalationTier>,
    /// Whether the breach meta-incident has already been raised for this clock (idempotency).
    pub meta_raised: bool,
}

impl StatutoryClock {
    /// Arm a new provisional clock at `t0` with `budget_ticks`.
    pub fn arm(kind: StatutoryClockKind, t0: Tick, budget_ticks: u64) -> Self {
        Self {
            kind,
            t0,
            budget_ticks,
            provisional: true,
            filing: None,
            downgrade: None,
            paged: BTreeSet::new(),
            meta_raised: false,
        }
    }

    /// The deadline tick (`t0 + budget`, saturating).
    pub fn deadline(&self) -> Tick {
        self.t0.saturating_add(self.budget_ticks)
    }

    /// Elapsed ticks at `now` (saturating; a `now` before `t0` is 0 elapsed).
    pub fn elapsed(&self, now: Tick) -> u64 {
        now.saturating_sub(self.t0)
    }

    /// Remaining budget at `now` (0 once the deadline is reached/passed).
    pub fn remaining(&self, now: Tick) -> u64 {
        self.deadline().saturating_sub(now)
    }

    /// `true` while the clock is neither filed nor downgraded — i.e. still running.
    pub fn is_active(&self) -> bool {
        self.filing.is_none() && self.downgrade.is_none()
    }

    /// The tick at which `percent` of the budget has elapsed (`t0 + budget*percent/100`, saturating).
    fn threshold_tick(&self, percent: u64) -> Tick {
        self.t0
            .saturating_add(self.budget_ticks.saturating_mul(percent) / 100)
    }

    /// `true` when the clock is active and `now` is strictly past the deadline (budget exceeded
    /// without a filing/downgrade) — the condition that auto-raises the meta-incident (§2.3).
    pub fn is_breached(&self, now: Tick) -> bool {
        self.is_active() && now > self.deadline()
    }

    /// Every ladder tier whose threshold has been crossed at `now` (an active clock only). A
    /// threshold is crossed when `now >= threshold_tick(percent)`.
    fn crossed_tiers(&self, now: Tick) -> Vec<EscalationTier> {
        if !self.is_active() {
            return Vec::new();
        }
        ESCALATION_LADDER
            .iter()
            .filter(|(pct, _)| now >= self.threshold_tick(*pct))
            .map(|(_, tier)| *tier)
            .collect()
    }
}

// ============================ arming policy (control plane) ============================

/// One clock the policy arms for a class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClockSpec {
    pub kind: StatutoryClockKind,
    /// Budget in **logical ticks**. Config-driven per the design (DPDP Rule values still settling);
    /// interpret the tick unit per deployment (the defaults below assume 1 tick = 1 minute).
    pub budget_ticks: u64,
}

impl ClockSpec {
    pub fn new(kind: StatutoryClockKind, budget_ticks: u64) -> Self {
        Self { kind, budget_ticks }
    }
}

/// The control-plane arming table (§2.2): incident class ⇒ ordered clocks to arm. This is a git
/// artifact in production; here it is a deterministic, serde-serializable value.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArmingPolicy {
    table: BTreeMap<IncidentClass, Vec<ClockSpec>>,
}

impl ArmingPolicy {
    /// An empty policy — no class arms anything.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a clock spec to a class's arming list (chainable; insertion order = clock order).
    pub fn arm(&mut self, class: IncidentClass, spec: ClockSpec) -> &mut Self {
        self.table.entry(class).or_default().push(spec);
        self
    }

    /// The clocks a class arms (empty slice if the class arms nothing).
    pub fn clocks_for(&self, class: IncidentClass) -> &[ClockSpec] {
        self.table.get(&class).map_or(&[], Vec::as_slice)
    }

    /// Generic default arming policy — no pre-armed statutory clocks.
    /// Use this as the OSS baseline; add clocks for your jurisdiction via `arm()`.
    pub fn generic_default() -> Self {
        Self::new()
    }

    /// India regulatory default (§2.2 table): CERT-In, DPDP, and RBI clocks pre-armed.
    /// Budgets are logical ticks assuming 1 tick ≈ 1 minute:
    /// CERT-In = 6h = 360, DPDP-board = 72h = 4320, DPDP-data-principal ≈ 24h = 1440,
    /// RBI = 24h = 1440, payment-boundary = 1h = 60. These are **config** — re-pin when the DPDP
    /// Rules finalize. `ComplianceDeadlineMissed` arms nothing (it is an internal escalation).
    pub fn india_regulatory_default() -> Self {
        let mut p = Self::new();
        p.arm(
            IncidentClass::PersonalDataBreach,
            ClockSpec::new(StatutoryClockKind::DpdpDataPrincipal, 1_440),
        )
        .arm(
            IncidentClass::PersonalDataBreach,
            ClockSpec::new(StatutoryClockKind::DpdpBoard, 4_320),
        );
        p.arm(
            IncidentClass::CyberSecurityIncident,
            ClockSpec::new(StatutoryClockKind::CertIn, 360),
        );
        p.arm(
            IncidentClass::OutsourcedServiceDisruption,
            ClockSpec::new(StatutoryClockKind::RbiOutsourcing, 1_440),
        );
        p.arm(
            IncidentClass::AgentSettlementAction,
            ClockSpec::new(StatutoryClockKind::CertIn, 360),
        )
        .arm(
            IncidentClass::AgentSettlementAction,
            ClockSpec::new(StatutoryClockKind::RbiOutsourcing, 1_440),
        )
        .arm(
            IncidentClass::AgentSettlementAction,
            ClockSpec::new(StatutoryClockKind::PaymentBoundaryEscalation, 60),
        );
        p.arm(
            IncidentClass::QualityDegradationRegulatedRoute,
            ClockSpec::new(StatutoryClockKind::RbiOutsourcing, 1_440),
        );
        p
    }

    /// Deprecated alias for [`india_regulatory_default`](ArmingPolicy::india_regulatory_default).
    /// Use `india_regulatory_default()` in new code.
    #[deprecated(since = "1.0.0", note = "use `india_regulatory_default()` instead")]
    pub fn india_default() -> Self {
        Self::india_regulatory_default()
    }
}

// ============================ candidate + incident ============================

/// A typed incident candidate (§2.1). `noticed_tick` is the legally operative **t0**.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentCandidate {
    pub source: CandidateSource,
    /// Time of first notice — becomes the incident's immutable t0.
    pub noticed_tick: Tick,
    /// Regulated data classes implicated.
    pub affected_data_classes: BTreeSet<DataClass>,
    /// Best estimate of affected data principals.
    pub affected_principal_estimate: u64,
    /// Systems implicated.
    pub systems_involved: Vec<String>,
    /// The control-plane commit SHA live at t0 (evidentiary — "which definitions produced this").
    pub control_plane_sha: String,
    /// A short, PII-free description.
    pub description: String,
}

impl IncidentCandidate {
    pub fn new(source: CandidateSource, noticed_tick: Tick, control_plane_sha: &str) -> Self {
        Self {
            source,
            noticed_tick,
            affected_data_classes: BTreeSet::new(),
            affected_principal_estimate: 0,
            systems_involved: Vec::new(),
            control_plane_sha: control_plane_sha.to_string(),
            description: String::new(),
        }
    }

    pub fn with_data_class(mut self, class: DataClass) -> Self {
        self.affected_data_classes.insert(class);
        self
    }
    pub fn with_principal_estimate(mut self, n: u64) -> Self {
        self.affected_principal_estimate = n;
        self
    }
    pub fn with_system(mut self, system: &str) -> Self {
        self.systems_involved.push(system.to_string());
        self
    }
    /// The fail-safe class this candidate arms if a triage Role does not override it (§2.2).
    /// Convenience over [`CandidateSource::default_class`].
    pub fn default_class(&self) -> IncidentClass {
        self.source.default_class()
    }

    // ---- FI-02: typed detection-source adapters ----
    //
    // Each real runtime detector (§2.1) has a clean, named constructor here, so wiring a detector to
    // the breach engine is one call — the detector supplies only its own facts, and the candidate is
    // pre-shaped with the right source. The parent then calls
    // [`IncidentRegister::open_from`] (or `open` with a triage class). These make "an
    // `IncidentCandidate` is raised by typed sources each already present in the runtime" a real,
    // one-line integration rather than hand-rolling the struct at every call site.

    /// A candidate from the compliance gate seeing a regulated class egress where policy forbids it —
    /// the AI-specific breach class (§2.1). `class` is the regulated data class that leaked.
    pub fn from_compliance_egress(
        noticed_tick: Tick,
        control_plane_sha: &str,
        class: DataClass,
        principal_estimate: u64,
    ) -> Self {
        Self::new(
            CandidateSource::ComplianceGateEgress,
            noticed_tick,
            control_plane_sha,
        )
        .with_data_class(class)
        .with_principal_estimate(principal_estimate)
        .with_description("regulated class egressed past policy")
    }

    /// A candidate from the write-path sink-guard catching CHD reaching a durable store (§5 / §2.1) —
    /// a redaction that *should not have been needed* is itself a signal.
    pub fn from_sink_guard(noticed_tick: Tick, control_plane_sha: &str, sink: &str) -> Self {
        Self::new(
            CandidateSource::WritePathSinkGuard,
            noticed_tick,
            control_plane_sha,
        )
        .with_data_class(DataClass::RegulatedPayment)
        .with_system(sink)
        .with_description("CHD reached a durable sink write-path")
    }

    /// A candidate from the defense-in-depth store sweep finding CHD already in a store (§5.4).
    pub fn from_store_sweep(noticed_tick: Tick, control_plane_sha: &str, store: &str) -> Self {
        Self::new(CandidateSource::StoreSweep, noticed_tick, control_plane_sha)
            .with_data_class(DataClass::RegulatedPayment)
            .with_system(store)
            .with_description("store sweep found CHD in a durable store")
    }

    /// A candidate from the quality circuit-breaker tripping on a regulated route (§2.1) — a degraded
    /// model on payment queries is a reportable operational-risk event under RBI.
    pub fn from_quality_breaker(noticed_tick: Tick, control_plane_sha: &str, route: &str) -> Self {
        Self::new(
            CandidateSource::QualityCircuitBreaker,
            noticed_tick,
            control_plane_sha,
        )
        .with_system(route)
        .with_description("judge-score collapse on a regulated route")
    }

    /// A candidate from the payment boundary (ADR-013/016) seeing an anomalous/attempted settlement.
    pub fn from_payment_boundary(
        noticed_tick: Tick,
        control_plane_sha: &str,
        action: &str,
    ) -> Self {
        Self::new(
            CandidateSource::PaymentBoundary,
            noticed_tick,
            control_plane_sha,
        )
        .with_system(action)
        .with_description("anomalous or attempted settlement-class action")
    }

    /// A candidate from serving-ops (ADR-020) reporting a material disruption of a critical route.
    pub fn from_serving_ops(noticed_tick: Tick, control_plane_sha: &str, route: &str) -> Self {
        Self::new(CandidateSource::ServingOps, noticed_tick, control_plane_sha)
            .with_system(route)
            .with_description("material disruption of a critical route")
    }

    pub fn with_description(mut self, d: &str) -> Self {
        self.description = d.to_string();
        self
    }
}

/// The operational status of an incident.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IncidentStatus {
    Open,
    Closed,
}

/// The incident register record (§2.5) — the mutable operational projection. The *evidentiary* spine
/// is the hash-chained event log ([`IncidentRegister::events`]); this aggregate projects it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Incident {
    pub id: String,
    pub class: IncidentClass,
    /// Immutable time of first notice (evidentiary, NTP-sourced upstream).
    pub t0: Tick,
    pub source: CandidateSource,
    pub clocks: Vec<StatutoryClock>,
    pub affected_data_classes: BTreeSet<DataClass>,
    pub affected_principal_estimate: u64,
    pub systems_involved: Vec<String>,
    pub control_plane_sha: String,
    pub status: IncidentStatus,
    /// For a meta-incident, the source incident it was raised from.
    pub meta_incident_of: Option<String>,
}

impl Incident {
    /// The active clock of a given kind, if any.
    pub fn clock(&self, kind: StatutoryClockKind) -> Option<&StatutoryClock> {
        self.clocks.iter().find(|c| c.kind == kind)
    }

    /// `true` when every armed clock has been filed or downgraded (no active clock remains).
    pub fn all_clocks_resolved(&self) -> bool {
        self.clocks.iter().all(|c| !c.is_active())
    }
}

// ============================ hash-chained event log ============================

/// The payload of one hash-chained register event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum IncidentEventKind {
    Opened {
        class: IncidentClass,
        source: CandidateSource,
    },
    /// §2.2 — a triage Role proposed a classification. Recorded verbatim for audit ("who classified,
    /// with what confidence") **regardless of** whether the policy adopted it: a proposal below the
    /// fail-safe floor is logged here but did not lower the armed class.
    TriageProposed {
        proposed_class: IncidentClass,
        armed_class: IncidentClass,
        model: String,
        confidence_pct: u8,
    },
    ClockArmed {
        clock: StatutoryClockKind,
        budget_ticks: u64,
    },
    Escalated {
        clock: StatutoryClockKind,
        tier: EscalationTier,
    },
    Filed {
        clock: StatutoryClockKind,
        template_version: String,
    },
    Downgraded {
        clock: StatutoryClockKind,
        actor: String,
        reason: String,
    },
    MetaIncidentRaised {
        clock: StatutoryClockKind,
        meta_id: String,
    },
    Closed,
}

impl IncidentEventKind {
    /// A stable, canonical label for the hash-chain input (not the Debug format).
    fn tag(&self) -> String {
        match self {
            IncidentEventKind::Opened { class, source } => {
                format!("opened:{}:{source:?}", class.as_str())
            }
            IncidentEventKind::TriageProposed {
                proposed_class,
                armed_class,
                model,
                confidence_pct,
            } => format!(
                "triage-proposed:{}:{}:{model}:{confidence_pct}",
                proposed_class.as_str(),
                armed_class.as_str()
            ),
            IncidentEventKind::ClockArmed {
                clock,
                budget_ticks,
            } => format!("clock-armed:{}:{budget_ticks}", clock.as_str()),
            IncidentEventKind::Escalated { clock, tier } => {
                format!("escalated:{}:{tier:?}", clock.as_str())
            }
            IncidentEventKind::Filed {
                clock,
                template_version,
            } => format!("filed:{}:{template_version}", clock.as_str()),
            IncidentEventKind::Downgraded {
                clock,
                actor,
                reason,
            } => format!("downgraded:{}:{actor}:{reason}", clock.as_str()),
            IncidentEventKind::MetaIncidentRaised { clock, meta_id } => {
                format!("meta-raised:{}:{meta_id}", clock.as_str())
            }
            IncidentEventKind::Closed => "closed".into(),
        }
    }
}

/// One hash-chained register event. `hash` chains `prev_hash` + canonical fields, so any edit,
/// reorder, or deletion breaks the chain (detected by [`IncidentRegister::verify`]). `hash_alg` is the
/// crypto-agility policy label of the primitive that actually sealed this link (ADR-023 §7 evidentiary
/// particular — "manner of production"); [`verify`](IncidentRegister::verify) recomputes each link with
/// the primitive that sealed it, so an event sealed under a since-deprecated algorithm still verifies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentEvent {
    pub seq: u64,
    pub incident_id: String,
    pub event: IncidentEventKind,
    pub tick: Tick,
    pub prev_hash: String,
    pub hash: String,
    /// The crypto-agility policy label of the hash primitive that sealed this link (e.g. `"sha-256"`).
    /// Defaulted for backward-compatible deserialization of pre-ADR-023 snapshots.
    #[serde(default = "default_hash_alg")]
    pub hash_alg: String,
}

const GENESIS: &str = "GENESIS";

/// The default evidentiary-hash primitive label — SHA-256, the primitive the register chained with
/// before ADR-023 made the choice policy-governed. Used for `#[serde(default)]` back-compat.
fn default_hash_alg() -> String {
    "sha-256".to_string()
}

/// The default crypto-agility [`AlgorithmRegistry`] governing the register's evidentiary hash-chain
/// (ADR-023). Re-exported from `ainxt_cryptoagility` (the canonical definition, shared with the
/// Event Log's `GovernedChainHasher`) so a policy rotation is a single edit, not a per-crate hunt.
/// A deployment overrides this via [`IncidentRegister::with_hash_policy`] to deprecate/forbid a
/// primitive or stage a PQC migration — a data edit, never a code change.
pub use ainxt_cryptoagility::default_hash_policy;

/// The canonical, length-prefixed byte layout of one chain link (a value boundary cannot be forged by
/// shifting bytes between adjacent fields). The digest primitive is chosen by policy at hash time; this
/// only fixes *what bytes* are hashed. Deterministic — no wall clock, no RNG.
fn chain_link_bytes(
    prev: &str,
    seq: u64,
    incident_id: &str,
    event_tag: &str,
    tick: Tick,
) -> Vec<u8> {
    let mut buf = Vec::new();
    for field in [prev, incident_id, event_tag] {
        buf.extend_from_slice(&(field.len() as u64).to_le_bytes());
        buf.extend_from_slice(field.as_bytes());
    }
    buf.extend_from_slice(&seq.to_le_bytes());
    buf.extend_from_slice(&tick.to_le_bytes());
    buf
}

/// Recompute a chain link's hex digest with a *specific* policy label (the one recorded on the event),
/// for evidentiary re-verification: an event sealed under a since-deprecated primitive must still be
/// checkable with the primitive that sealed it, independent of the live policy's current status.
/// Supported labels mirror [`GovernedHasher`]: `sha-256`/`sha256`, `sha-512`/`sha512`. An unsupported
/// label yields `None` (→ [`TamperError::CryptoUnavailable`]).
fn digest_with_label(label: &str, data: &[u8]) -> Option<String> {
    match label.to_ascii_lowercase().as_str() {
        "sha-256" | "sha256" => {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(data);
            Some(h.finalize().iter().map(|b| format!("{b:02x}")).collect::<String>())
        }
        "sha-512" | "sha512" => {
            use sha2::{Digest, Sha512};
            let mut h = Sha512::new();
            h.update(data);
            Some(h.finalize().iter().map(|b| format!("{b:02x}")).collect::<String>())
        }
        _ => None,
    }
}

/// A detected break in the register's append-only hash chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TamperError {
    SeqGap {
        expected: u64,
        found: u64,
    },
    BrokenChain {
        seq: u64,
    },
    HashMismatch {
        seq: u64,
    },
    /// The crypto-agility policy fenced off every hash primitive at this link's tick (or the recorded
    /// primitive has no implementation here) — the link could not be, or cannot be re-, sealed
    /// tamper-evidently. Fail-closed: an unsealed link is a broken chain, never silently accepted.
    CryptoUnavailable {
        seq: u64,
    },
}

/// An error from a register operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IncidentError {
    UnknownIncident(String),
    UnknownClock {
        incident_id: String,
        clock: StatutoryClockKind,
    },
    /// A downgrade was attempted by a principal without [`DOWNGRADE_CAP`] (fail-closed, §2.2).
    Unauthorized(String),
    /// A filing/downgrade targeted a clock that is already resolved.
    ClockAlreadyResolved {
        incident_id: String,
        clock: StatutoryClockKind,
    },
}

impl fmt::Display for IncidentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IncidentError::UnknownIncident(id) => write!(f, "unknown incident `{id}`"),
            IncidentError::UnknownClock { incident_id, clock } => {
                write!(
                    f,
                    "incident `{incident_id}` has no {} clock",
                    clock.as_str()
                )
            }
            IncidentError::Unauthorized(user) => {
                write!(f, "principal `{user}` may not downgrade a statutory clock")
            }
            IncidentError::ClockAlreadyResolved { incident_id, clock } => write!(
                f,
                "incident `{incident_id}` {} clock is already filed/downgraded",
                clock.as_str()
            ),
        }
    }
}

impl std::error::Error for IncidentError {}

/// An event surfaced from an engine [`tick`](IncidentRegister::tick) — what a live pager/dashboard
/// would consume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineEvent {
    /// A ladder tier was paged for a clock.
    Paged {
        incident_id: String,
        clock: StatutoryClockKind,
        tier: EscalationTier,
        tick: Tick,
    },
    /// A P1 compliance meta-incident was auto-raised (a statutory deadline was missed).
    MetaIncidentRaised {
        source_incident: String,
        meta_incident_id: String,
        clock: StatutoryClockKind,
        tick: Tick,
    },
}

// ============================ the register ============================

/// The durable, hash-chained statutory-incident register + breach engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentRegister {
    arming: ArmingPolicy,
    incidents: BTreeMap<String, Incident>,
    events: Vec<IncidentEvent>,
    /// ADR-023 — the crypto-agility policy governing the evidentiary hash-chain's digest primitive.
    /// The register is "the substrate every register lives on": its tamper-evidence primitive is not a
    /// hard-coded sha2 call but the algorithm the policy resolves for [`Purpose::Hashing`] at each
    /// link's tick. Defaulted (SHA-256) for backward-compatible deserialization.
    #[serde(default = "default_hash_policy")]
    hash_policy: AlgorithmRegistry,
}

impl IncidentRegister {
    /// A register governed by `arming`, sealing its evidentiary chain under the
    /// [`default_hash_policy`] (SHA-256 approved) per ADR-023.
    pub fn new(arming: ArmingPolicy) -> Self {
        Self {
            arming,
            incidents: BTreeMap::new(),
            events: Vec::new(),
            hash_policy: default_hash_policy(),
        }
    }

    /// A register whose evidentiary hash-chain is governed by a caller-supplied crypto-agility
    /// `hash_policy` (ADR-023). Fails closed at construction if the policy resolves **no** usable
    /// [`Purpose::Hashing`] primitive at tick `0` — a register that cannot seal its first link
    /// tamper-evidently must never come into being (better to refuse than to log un-sealably).
    pub fn with_hash_policy(
        arming: ArmingPolicy,
        hash_policy: AlgorithmRegistry,
    ) -> Result<Self, ainxt_cryptoagility::CryptoAgilityError> {
        // Validate that some primitive is resolvable now (fail-closed) AND that it is one this build
        // can actually compute (no silently-unsupported label sealing the register).
        let alg = hash_policy.resolve(Purpose::Hashing, 0)?;
        if digest_with_label(&alg.name, b"").is_none() {
            return Err(
                ainxt_cryptoagility::CryptoAgilityError::UnsupportedAlgorithm {
                    name: alg.name.clone(),
                },
            );
        }
        Ok(Self {
            arming,
            incidents: BTreeMap::new(),
            events: Vec::new(),
            hash_policy,
        })
    }

    /// The crypto-agility policy label that governs a chain link sealed at logical time `now`
    /// (ADR-023 inspection/audit), or the fail-closed error when the policy fences off every primitive.
    pub fn hash_alg_at(
        &self,
        now: Tick,
    ) -> Result<String, ainxt_cryptoagility::CryptoAgilityError> {
        Ok(self
            .hash_policy
            .resolve(Purpose::Hashing, now)?
            .name
            .clone())
    }

    /// The arming policy in force.
    pub fn arming(&self) -> &ArmingPolicy {
        &self.arming
    }

    /// A read-only incident view.
    pub fn incident(&self, id: &str) -> Option<&Incident> {
        self.incidents.get(id)
    }

    /// All incidents, id-sorted.
    pub fn incidents(&self) -> impl Iterator<Item = &Incident> {
        self.incidents.values()
    }

    /// The append-only, hash-chained event log (the evidentiary spine).
    pub fn events(&self) -> &[IncidentEvent] {
        &self.events
    }

    /// Append a hash-chained event (internal). The digest primitive is resolved from the crypto-agility
    /// policy at this link's `tick` (ADR-023) and the resolved label is recorded on the event. If the
    /// policy fences off every primitive (or resolves to one this build cannot compute), the link is
    /// sealed with a fail-closed sentinel and labelled `"unavailable"` — [`verify`](Self::verify) then
    /// reports [`TamperError::CryptoUnavailable`] rather than silently accepting an unsealed link.
    fn append(&mut self, incident_id: &str, event: IncidentEventKind, tick: Tick) {
        let seq = self.events.len() as u64;
        let prev = self
            .events
            .last()
            .map_or_else(|| GENESIS.to_string(), |e| e.hash.clone());
        let tag = event.tag();
        let buf = chain_link_bytes(&prev, seq, incident_id, &tag, tick);
        let hasher = GovernedHasher::new(self.hash_policy.clone());
        let (hash_alg, hash) = match hasher.digest(&buf, tick) {
            Ok(d) => (d.algorithm, d.hex),
            // Fail-closed: no policy-usable/implemented primitive at this tick. Seal with a sentinel so
            // the event still exists (a missed obligation must never be dropped) but verify() flags it.
            Err(_) => (
                "unavailable".to_string(),
                format!("CRYPTO-UNAVAILABLE-{seq}"),
            ),
        };
        self.events.push(IncidentEvent {
            seq,
            incident_id: incident_id.to_string(),
            event,
            tick,
            prev_hash: prev,
            hash,
            hash_alg,
        });
    }

    /// Open an incident from a `candidate` classified as `class`, at the current `now` (§2.1–2.3).
    /// Clocks are armed **from the policy** for that class (deterministic; the model's classification
    /// does not choose the clocks). t0 = `candidate.noticed_tick` (the legally operative instant).
    /// Returns the new incident id. Ids are deterministic: `incident-{source}-{t0}`.
    pub fn open(
        &mut self,
        candidate: IncidentCandidate,
        class: IncidentClass,
        now: Tick,
    ) -> String {
        let id = format!(
            "incident-{}-{}",
            candidate.source_slug(),
            candidate.noticed_tick
        );
        let specs = self.arming.clocks_for(class).to_vec();
        let clocks: Vec<StatutoryClock> = specs
            .iter()
            .map(|s| StatutoryClock::arm(s.kind, candidate.noticed_tick, s.budget_ticks))
            .collect();
        let incident = Incident {
            id: id.clone(),
            class,
            t0: candidate.noticed_tick,
            source: candidate.source,
            clocks,
            affected_data_classes: candidate.affected_data_classes.clone(),
            affected_principal_estimate: candidate.affected_principal_estimate,
            systems_involved: candidate.systems_involved.clone(),
            control_plane_sha: candidate.control_plane_sha.clone(),
            status: IncidentStatus::Open,
            meta_incident_of: None,
        };
        self.incidents.insert(id.clone(), incident);
        self.append(
            &id,
            IncidentEventKind::Opened {
                class,
                source: candidate.source,
            },
            now,
        );
        for s in &specs {
            self.append(
                &id,
                IncidentEventKind::ClockArmed {
                    clock: s.kind,
                    budget_ticks: s.budget_ticks,
                },
                now,
            );
        }
        id
    }

    /// FI-02: open an incident directly from a detector-supplied candidate, using the candidate's
    /// **fail-safe default class** ([`IncidentCandidate::default_class`]). This is the one-call
    /// integration point a detector (compliance gate, sink-guard, quality breaker, payment boundary,
    /// serving-ops, store-sweep, NTP-skew, residency verifier) uses to *arm a clock the instant it
    /// notices a reportable event* — no manual classification required at the detector. A triage Role
    /// may later re-open under a more specific class; the fail-safe posture is "arm early".
    pub fn open_from(&mut self, candidate: IncidentCandidate, now: Tick) -> String {
        let class = candidate.default_class();
        self.open(candidate, class, now)
    }

    /// §2.2 **agentic incident taxonomy** — open an incident where a triage Role (a model) *proposes* a
    /// classification and the **policy arms**. The armed class is the more-protective of the source's
    /// deterministic fail-safe floor ([`IncidentCandidate::default_class`]) and the model's
    /// `proposal.proposed_class`: a proposal can only *escalate* coverage, never lower it, so a
    /// confused or hijacked triage model cannot disarm a statutory clock (disarming needs an
    /// authenticated [`downgrade`](Self::downgrade)). The proposal is recorded verbatim on the
    /// evidentiary chain (a [`IncidentEventKind::TriageProposed`] event) whether or not it was adopted —
    /// so "the model proposed X but policy floored to Y" is itself un-hideable. Returns the incident id.
    ///
    /// GAP-AUDIT misc-decisions: investigated and confirmed a genuine, infra-gated non-gap for today.
    /// Every served detector integration point (`ainxt-runtimed`'s `arm_incident`/`maybe_arm_incident`,
    /// `ainxt-server`'s serving-ops fences) calls [`Self::open_from`] only — there is no composition-root
    /// call site that makes a live triage-model call to CLASSIFY an incident candidate at all (unlike,
    /// e.g., `ainxt-runtimed::workforce_surface::ModelRoutedExecutor`, which does call a model, but for
    /// Role-task execution, not incident triage). No `/v1/regfi/*` route accepts an externally-submitted
    /// [`TriageProposal`] either. This is not "the seam is dead code" so much as "the upstream capability
    /// (a real triage-Role model call feeding an incident candidate) does not exist yet in this daemon" —
    /// wiring `open_from_triage` in today would mean fabricating a fake proposal source, which would be
    /// theater, not a fix. The fail-safe `open_from` path this crate's `IncidentClass::default_class`
    /// backs is what actually protects every regulated detector right now. Wire this the moment a real
    /// triage-Role/model call site is added (a natural fit: a `ModelRoutedExecutor`-shaped role scoped to
    /// incident classification, feeding its output straight into this method).
    pub fn open_from_triage(
        &mut self,
        candidate: IncidentCandidate,
        proposal: TriageProposal,
        now: Tick,
    ) -> String {
        let floor = candidate.default_class();
        let armed = if proposal.proposed_class.severity_rank() > floor.severity_rank() {
            proposal.proposed_class
        } else {
            floor
        };
        let id = self.open(candidate, armed, now);
        // Record what the model actually proposed (audit), alongside what the policy armed.
        self.append(
            &id,
            IncidentEventKind::TriageProposed {
                proposed_class: proposal.proposed_class,
                armed_class: armed,
                model: proposal.model,
                confidence_pct: proposal.confidence_pct,
            },
            now,
        );
        id
    }

    /// Record a filing against a clock (§2.4) — stops that clock's breach. The filing is the human
    /// legal act; this only records it. Errors on an unknown incident/clock or an already-resolved
    /// clock.
    pub fn record_filing(
        &mut self,
        incident_id: &str,
        clock: StatutoryClockKind,
        filing: Filing,
    ) -> Result<(), IncidentError> {
        let template_version = filing.template_version.clone();
        let submitted_tick = filing.submitted_tick;
        {
            let inc = self
                .incidents
                .get_mut(incident_id)
                .ok_or_else(|| IncidentError::UnknownIncident(incident_id.to_string()))?;
            let c = inc
                .clocks
                .iter_mut()
                .find(|c| c.kind == clock)
                .ok_or_else(|| IncidentError::UnknownClock {
                    incident_id: incident_id.to_string(),
                    clock,
                })?;
            if !c.is_active() {
                return Err(IncidentError::ClockAlreadyResolved {
                    incident_id: incident_id.to_string(),
                    clock,
                });
            }
            c.filing = Some(filing);
            c.provisional = false;
        }
        self.append(
            incident_id,
            IncidentEventKind::Filed {
                clock,
                template_version,
            },
            submitted_tick,
        );
        Ok(())
    }

    /// Downgrade (disarm) a provisionally-armed clock (§2.2) — an authenticated, reason-coded action
    /// by an accountable owner. Fails closed if `actor` lacks [`DOWNGRADE_CAP`]. Does **not** move
    /// t0 or rewind the wall-clock; it only stops paging/breach for a clock that has been decided
    /// (on the record) not to apply.
    pub fn downgrade(
        &mut self,
        incident_id: &str,
        clock: StatutoryClockKind,
        actor: &Principal,
        reason: &str,
        now: Tick,
    ) -> Result<(), IncidentError> {
        if !actor.has_cap(DOWNGRADE_CAP) {
            return Err(IncidentError::Unauthorized(actor.user_id.clone()));
        }
        {
            let inc = self
                .incidents
                .get_mut(incident_id)
                .ok_or_else(|| IncidentError::UnknownIncident(incident_id.to_string()))?;
            let c = inc
                .clocks
                .iter_mut()
                .find(|c| c.kind == clock)
                .ok_or_else(|| IncidentError::UnknownClock {
                    incident_id: incident_id.to_string(),
                    clock,
                })?;
            if !c.is_active() {
                return Err(IncidentError::ClockAlreadyResolved {
                    incident_id: incident_id.to_string(),
                    clock,
                });
            }
            c.downgrade = Some(Downgrade {
                actor: actor.user_id.clone(),
                reason: reason.to_string(),
                tick: now,
            });
        }
        self.append(
            incident_id,
            IncidentEventKind::Downgraded {
                clock,
                actor: actor.user_id.clone(),
                reason: reason.to_string(),
            },
            now,
        );
        Ok(())
    }

    /// Close an incident (all its statutory obligations discharged).
    pub fn close(&mut self, incident_id: &str, now: Tick) -> Result<(), IncidentError> {
        {
            let inc = self
                .incidents
                .get_mut(incident_id)
                .ok_or_else(|| IncidentError::UnknownIncident(incident_id.to_string()))?;
            inc.status = IncidentStatus::Closed;
        }
        self.append(incident_id, IncidentEventKind::Closed, now);
        Ok(())
    }

    /// The engine's durable advance to logical time `now` (§2.3) — the crux. For every active clock
    /// of every incident, in a deterministic (id-sorted) order:
    /// - page each newly-crossed ladder tier (50/75/90 %→owner/DPO/CISO, 100 %→board-delegate) once;
    /// - if the clock is breached (budget exceeded with no filing/downgrade) and no meta-incident has
    ///   yet been raised for it, **auto-raise a P1 `ComplianceDeadlineMissed` meta-incident** and
    ///   page the board-delegate — a missed deadline is itself a first-class, un-hideable event.
    ///
    /// Idempotent: re-running at the same (or a smaller) `now` produces no duplicate pages or
    /// meta-incidents. Returns the events produced, in deterministic order.
    pub fn tick(&mut self, now: Tick) -> Vec<EngineEvent> {
        // Phase 1: DECIDE over an immutable snapshot (id-sorted; clocks in vec order).
        struct Decision {
            incident_id: String,
            clock_index: usize,
            clock_kind: StatutoryClockKind,
            page_tiers: Vec<EscalationTier>,
            raise_meta: bool,
        }
        let mut decisions: Vec<Decision> = Vec::new();
        for inc in self.incidents.values() {
            for (idx, clk) in inc.clocks.iter().enumerate() {
                if !clk.is_active() {
                    continue;
                }
                let page_tiers: Vec<EscalationTier> = clk
                    .crossed_tiers(now)
                    .into_iter()
                    .filter(|t| !clk.paged.contains(t))
                    .collect();
                let raise_meta = clk.is_breached(now) && !clk.meta_raised;
                if !page_tiers.is_empty() || raise_meta {
                    decisions.push(Decision {
                        incident_id: inc.id.clone(),
                        clock_index: idx,
                        clock_kind: clk.kind,
                        page_tiers,
                        raise_meta,
                    });
                }
            }
        }

        // Phase 2: APPLY (mutations + event appends + meta-incident creation).
        let mut out: Vec<EngineEvent> = Vec::new();
        for d in decisions {
            // Mutate the clock in a tight scope so the &mut borrow ends before self.append.
            {
                if let Some(inc) = self.incidents.get_mut(&d.incident_id) {
                    let clk = &mut inc.clocks[d.clock_index];
                    for t in &d.page_tiers {
                        clk.paged.insert(*t);
                    }
                    if d.raise_meta {
                        clk.meta_raised = true;
                    }
                }
            }
            for t in &d.page_tiers {
                self.append(
                    &d.incident_id,
                    IncidentEventKind::Escalated {
                        clock: d.clock_kind,
                        tier: *t,
                    },
                    now,
                );
                out.push(EngineEvent::Paged {
                    incident_id: d.incident_id.clone(),
                    clock: d.clock_kind,
                    tier: *t,
                    tick: now,
                });
            }
            if d.raise_meta {
                let meta_id = self.raise_meta_incident(&d.incident_id, d.clock_kind, now);
                out.push(EngineEvent::MetaIncidentRaised {
                    source_incident: d.incident_id.clone(),
                    meta_incident_id: meta_id,
                    clock: d.clock_kind,
                    tick: now,
                });
            }
        }
        out
    }

    /// Create (idempotently) the meta-incident for a breached clock and log the linkage. The meta-id
    /// is deterministic per (source, clock), so a repeat call does not duplicate it.
    fn raise_meta_incident(
        &mut self,
        source_id: &str,
        clock: StatutoryClockKind,
        now: Tick,
    ) -> String {
        let meta_id = format!("{source_id}::meta::{}", clock.as_str());
        if !self.incidents.contains_key(&meta_id) {
            let control_plane_sha = self
                .incidents
                .get(source_id)
                .map(|i| i.control_plane_sha.clone())
                .unwrap_or_default();
            let meta = Incident {
                id: meta_id.clone(),
                class: IncidentClass::ComplianceDeadlineMissed,
                t0: now,
                source: CandidateSource::EngineMetaIncident,
                clocks: Vec::new(),
                affected_data_classes: BTreeSet::new(),
                affected_principal_estimate: 0,
                systems_involved: vec![source_id.to_string()],
                control_plane_sha,
                status: IncidentStatus::Open,
                meta_incident_of: Some(source_id.to_string()),
            };
            self.incidents.insert(meta_id.clone(), meta);
            self.append(
                &meta_id,
                IncidentEventKind::Opened {
                    class: IncidentClass::ComplianceDeadlineMissed,
                    source: CandidateSource::EngineMetaIncident,
                },
                now,
            );
        }
        // Always log the raise linkage on the SOURCE incident (idempotency is on the clock flag).
        self.append(
            source_id,
            IncidentEventKind::MetaIncidentRaised {
                clock,
                meta_id: meta_id.clone(),
            },
            now,
        );
        meta_id
    }

    // -------- dashboard / query projections (§9) --------

    /// Every currently-armed (active) clock across all incidents, as
    /// `(incident_id, kind, remaining_at_now)`, id-sorted.
    pub fn armed_clocks(&self, now: Tick) -> Vec<(String, StatutoryClockKind, u64)> {
        let mut v = Vec::new();
        for inc in self.incidents.values() {
            for c in &inc.clocks {
                if c.is_active() {
                    v.push((inc.id.clone(), c.kind, c.remaining(now)));
                }
            }
        }
        v
    }

    /// Every clock currently breached without a filing (the go-live-blocking view), id-sorted.
    pub fn breached_without_filing(&self, now: Tick) -> Vec<(String, StatutoryClockKind)> {
        let mut v = Vec::new();
        for inc in self.incidents.values() {
            for c in &inc.clocks {
                if c.is_breached(now) {
                    v.push((inc.id.clone(), c.kind));
                }
            }
        }
        v
    }

    /// Recompute the hash chain end-to-end; returns the verified event count or the first break.
    pub fn verify(&self) -> Result<usize, TamperError> {
        let mut prev = GENESIS.to_string();
        for (i, e) in self.events.iter().enumerate() {
            let expected = i as u64;
            if e.seq != expected {
                return Err(TamperError::SeqGap {
                    expected,
                    found: e.seq,
                });
            }
            if e.prev_hash != prev {
                return Err(TamperError::BrokenChain { seq: e.seq });
            }
            // Recompute with the SAME crypto-agility primitive that sealed this link (ADR-023): an event
            // sealed under a since-deprecated algorithm must still re-verify with the algorithm of
            // record, not the live policy's current pick. An unrecognised label (incl. the fail-closed
            // `"unavailable"` sentinel) is a broken chain, never silently accepted.
            let buf = chain_link_bytes(&prev, e.seq, &e.incident_id, &e.event.tag(), e.tick);
            let recomputed = match digest_with_label(&e.hash_alg, &buf) {
                Some(hex) => hex,
                None => return Err(TamperError::CryptoUnavailable { seq: e.seq }),
            };
            if recomputed != e.hash {
                return Err(TamperError::HashMismatch { seq: e.seq });
            }
            prev = e.hash.clone();
        }
        Ok(self.events.len())
    }
}

impl IncidentCandidate {
    /// A stable slug for the source, used to build a deterministic incident id.
    fn source_slug(&self) -> &'static str {
        match self.source {
            CandidateSource::ComplianceGateEgress => "gate-egress",
            CandidateSource::WritePathSinkGuard => "sink-guard",
            CandidateSource::QualityCircuitBreaker => "quality-cb",
            CandidateSource::PaymentBoundary => "payment",
            CandidateSource::ServingOps => "serving",
            CandidateSource::StoreSweep => "store-sweep",
            CandidateSource::NtpSkew => "ntp-skew",
            CandidateSource::OperatorDeclaration => "operator",
            CandidateSource::InboundAdvisory => "advisory",
            CandidateSource::ResidencyViolation => "residency",
            CandidateSource::EngineMetaIncident => "meta",
        }
    }
}

#[cfg(test)]
mod fi02_detection_wiring_tests {
    use super::*;

    #[test]
    fn gap_ainxt_incident_fi02_typed_detectors_arm_clocks_via_open_from() {
        // FI-02: every typed detection source (§2.1) has a one-call adapter that produces a candidate
        // which `open_from` classifies (fail-safe) and arms the correct statutory clock(s). This is
        // the wiring that makes "a detector actually arms a clock in the live system" true — proven
        // here against the register itself, not just the standalone library.
        let mut reg = IncidentRegister::new(ArmingPolicy::india_regulatory_default());

        // Compliance-gate egress → personal-data breach → DPDP clocks armed.
        let id = reg.open_from(
            IncidentCandidate::from_compliance_egress(10, "cp", DataClass::Pii, 5),
            10,
        );
        let inc = reg.incident(&id).unwrap();
        assert_eq!(inc.class, IncidentClass::PersonalDataBreach);
        assert!(inc.clock(StatutoryClockKind::DpdpBoard).is_some());

        // Write-path sink-guard → cyber incident → CERT-In armed.
        let id = reg.open_from(
            IncidentCandidate::from_sink_guard(20, "cp", "event-log"),
            20,
        );
        assert!(reg
            .incident(&id)
            .unwrap()
            .clock(StatutoryClockKind::CertIn)
            .is_some());

        // Quality circuit-breaker → operational-risk (RBI) clock armed.
        let id = reg.open_from(
            IncidentCandidate::from_quality_breaker(30, "cp", "route-r"),
            30,
        );
        assert_eq!(
            reg.incident(&id).unwrap().class,
            IncidentClass::QualityDegradationRegulatedRoute
        );

        // Payment boundary → agent-settlement (hardest) class → CERT-In + RBI + payment escalation.
        let id = reg.open_from(
            IncidentCandidate::from_payment_boundary(40, "cp", "settle-x"),
            40,
        );
        let inc = reg.incident(&id).unwrap();
        assert_eq!(inc.class, IncidentClass::AgentSettlementAction);
        assert!(inc
            .clock(StatutoryClockKind::PaymentBoundaryEscalation)
            .is_some());

        // Serving-ops → outsourced-service disruption → RBI clock.
        let id = reg.open_from(
            IncidentCandidate::from_serving_ops(50, "cp", "route-crit"),
            50,
        );
        assert!(reg
            .incident(&id)
            .unwrap()
            .clock(StatutoryClockKind::RbiOutsourcing)
            .is_some());

        // The register remains hash-chained/tamper-evident after all this wiring.
        assert!(reg.verify().is_ok());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pan_egress_candidate(t0: Tick) -> IncidentCandidate {
        IncidentCandidate::new(CandidateSource::ComplianceGateEgress, t0, "cp-sha-abc")
            .with_data_class(DataClass::Pii)
            .with_principal_estimate(3)
            .with_system("chat-surface")
            .with_description("PAN reached a cloud route")
    }

    fn register() -> IncidentRegister {
        IncidentRegister::new(ArmingPolicy::india_regulatory_default())
    }

    #[test]
    fn open_arms_the_policy_clocks_from_t0() {
        // §2.6 test 1: a cyber incident arms CERT-In(6h=360) at the NTP-sourced t0.
        let mut reg = register();
        let id = reg.open(
            pan_egress_candidate(1_000),
            IncidentClass::CyberSecurityIncident,
            1_005,
        );
        let inc = reg.incident(&id).unwrap();
        assert_eq!(inc.t0, 1_000, "t0 is the time of first notice, not `now`");
        let clk = inc.clock(StatutoryClockKind::CertIn).unwrap();
        assert_eq!(clk.budget_ticks, 360);
        assert_eq!(clk.deadline(), 1_360);
        assert!(clk.provisional);
        assert!(clk.is_active());
        // A draft would be generated off this record; the register is chain-valid.
        assert!(reg.verify().is_ok());
    }

    #[test]
    fn escalation_ladder_pages_each_tier_once_in_order() {
        // §2.6 test 2: advancing the clock pages owner → DPO → CISO.
        let mut reg = register();
        let id = reg.open(
            pan_egress_candidate(0),
            IncidentClass::CyberSecurityIncident,
            0,
        ); // CERT-In budget 360
           // 50% = 180 → owner.
        let ev = reg.tick(180);
        assert_eq!(
            ev,
            vec![EngineEvent::Paged {
                incident_id: id.clone(),
                clock: StatutoryClockKind::CertIn,
                tier: EscalationTier::IncidentOwner,
                tick: 180,
            }]
        );
        // Re-ticking at 180 pages nothing new (idempotent).
        assert!(reg.tick(180).is_empty());
        // 75% = 270 → DPO.
        let ev = reg.tick(270);
        assert_eq!(ev.len(), 1);
        assert!(matches!(
            ev[0],
            EngineEvent::Paged {
                tier: EscalationTier::Dpo,
                ..
            }
        ));
        // 90% = 324 → CISO.
        let ev = reg.tick(324);
        assert!(matches!(
            ev[0],
            EngineEvent::Paged {
                tier: EscalationTier::Ciso,
                ..
            }
        ));
    }

    #[test]
    fn breach_without_filing_auto_raises_meta_incident() {
        // §2.6 test 2 (tail): at breach a P1 meta-incident is auto-raised + board-delegate paged.
        let mut reg = register();
        let src = reg.open(
            pan_egress_candidate(0),
            IncidentClass::CyberSecurityIncident,
            0,
        ); // deadline 360
           // Advance past the deadline with no filing.
        let ev = reg.tick(400);
        // Board-delegate paged (100% crossed) AND meta-incident raised.
        assert!(ev.iter().any(|e| matches!(
            e,
            EngineEvent::Paged {
                tier: EscalationTier::BoardDelegate,
                ..
            }
        )));
        let meta = ev.iter().find_map(|e| match e {
            EngineEvent::MetaIncidentRaised {
                meta_incident_id, ..
            } => Some(meta_incident_id.clone()),
            _ => None,
        });
        let meta_id = meta.expect("a meta-incident must be raised on breach");
        let meta_inc = reg.incident(&meta_id).unwrap();
        assert_eq!(meta_inc.class, IncidentClass::ComplianceDeadlineMissed);
        assert_eq!(meta_inc.meta_incident_of.as_deref(), Some(src.as_str()));
        // Idempotent: re-ticking past the deadline does not raise a second meta-incident.
        let again = reg.tick(500);
        assert!(!again
            .iter()
            .any(|e| matches!(e, EngineEvent::MetaIncidentRaised { .. })));
    }

    #[test]
    fn a_filed_clock_never_breaches_or_pages() {
        let mut reg = register();
        let id = reg.open(
            pan_egress_candidate(0),
            IncidentClass::CyberSecurityIncident,
            0,
        );
        reg.record_filing(
            &id,
            StatutoryClockKind::CertIn,
            Filing {
                template_version: "cert-in-v3".into(),
                submitted_tick: 100,
                ack_ref: "ACK-42".into(),
            },
        )
        .unwrap();
        // Well past the (now-moot) deadline: no pages, no meta-incident.
        let ev = reg.tick(10_000);
        assert!(ev.is_empty(), "a filed clock must not page/breach: {ev:?}");
        assert!(reg.breached_without_filing(10_000).is_empty());
        assert!(reg.incident(&id).unwrap().all_clocks_resolved());
    }

    #[test]
    fn durable_clock_survives_restart_and_continues_from_real_elapsed() {
        // §2.6 test 3: kill -9 mid-clock → on restart the clock re-projects and continues; t0 fixed.
        let mut reg = register();
        let id = reg.open(
            pan_egress_candidate(0),
            IncidentClass::CyberSecurityIncident,
            0,
        );
        reg.tick(180); // owner paged at 50%
                       // "kill -9": serialize the whole register, drop it, deserialize a fresh one.
        let snapshot = serde_json::to_string(&reg).unwrap();
        drop(reg);
        let mut restored: IncidentRegister = serde_json::from_str(&snapshot).unwrap();
        // t0 is unchanged; elapsed reflects real wall-clock, not a reset.
        let clk = restored
            .incident(&id)
            .unwrap()
            .clock(StatutoryClockKind::CertIn)
            .unwrap();
        assert_eq!(clk.t0, 0);
        assert_eq!(clk.elapsed(200), 200);
        // The owner page already fired (persisted); resuming does not re-page it, but the next tier does.
        let ev = restored.tick(270);
        assert_eq!(ev.len(), 1);
        assert!(matches!(
            ev[0],
            EngineEvent::Paged {
                tier: EscalationTier::Dpo,
                ..
            }
        ));
        // And the resumed register still hash-verifies end-to-end.
        assert!(restored.verify().is_ok());
    }

    #[test]
    fn downgrade_requires_authority_and_stops_the_clock() {
        // §2.6 test 4: a provisionally-armed clock can be downgraded only by an authorized owner.
        let mut reg = register();
        let id = reg.open(
            pan_egress_candidate(0),
            IncidentClass::CyberSecurityIncident,
            0,
        );
        // An intern cannot downgrade (fail-closed).
        let intern = Principal::user("intern", &["chat:use"]);
        assert_eq!(
            reg.downgrade(
                &id,
                StatutoryClockKind::CertIn,
                &intern,
                "not reportable",
                10
            )
            .unwrap_err(),
            IncidentError::Unauthorized("intern".into())
        );
        // The DPO (with the cap) can, on the record.
        let dpo = Principal::user("dpo", &[DOWNGRADE_CAP]);
        reg.downgrade(
            &id,
            StatutoryClockKind::CertIn,
            &dpo,
            "duplicate advisory",
            10,
        )
        .unwrap();
        // Downgraded clock never breaches/pages afterwards.
        assert!(reg.tick(10_000).is_empty());
        let clk = reg
            .incident(&id)
            .unwrap()
            .clock(StatutoryClockKind::CertIn)
            .unwrap();
        assert!(!clk.is_active());
        assert_eq!(clk.downgrade.as_ref().unwrap().actor, "dpo");
        // t0 is not moved by a downgrade.
        assert_eq!(clk.t0, 0);
    }

    #[test]
    fn multi_clock_class_arms_all_and_breaches_independently() {
        // AgentSettlementAction arms CERT-In(360), RBI(1440), payment(60).
        let mut reg = register();
        let id = reg.open(
            IncidentCandidate::new(CandidateSource::PaymentBoundary, 0, "cp")
                .with_data_class(DataClass::RegulatedPayment),
            IncidentClass::AgentSettlementAction,
            0,
        );
        assert_eq!(reg.incident(&id).unwrap().clocks.len(), 3);
        // At tick 61 only the 60-budget payment clock has breached.
        let breached = reg.breached_without_filing(61);
        assert_eq!(
            breached,
            vec![(id.clone(), StatutoryClockKind::PaymentBoundaryEscalation)]
        );
        // Ticking raises exactly one meta-incident (for the payment clock).
        let ev = reg.tick(61);
        let metas: Vec<_> = ev
            .iter()
            .filter(|e| matches!(e, EngineEvent::MetaIncidentRaised { .. }))
            .collect();
        assert_eq!(metas.len(), 1);
    }

    #[test]
    fn filing_on_unknown_incident_or_clock_errs() {
        let mut reg = register();
        let id = reg.open(
            pan_egress_candidate(0),
            IncidentClass::CyberSecurityIncident,
            0,
        );
        assert_eq!(
            reg.record_filing("nope", StatutoryClockKind::CertIn, dummy_filing())
                .unwrap_err(),
            IncidentError::UnknownIncident("nope".into())
        );
        // CERT-In incident has no DPDP clock.
        assert_eq!(
            reg.record_filing(&id, StatutoryClockKind::DpdpBoard, dummy_filing())
                .unwrap_err(),
            IncidentError::UnknownClock {
                incident_id: id.clone(),
                clock: StatutoryClockKind::DpdpBoard
            }
        );
        // Double-filing the same clock errs.
        reg.record_filing(&id, StatutoryClockKind::CertIn, dummy_filing())
            .unwrap();
        assert!(matches!(
            reg.record_filing(&id, StatutoryClockKind::CertIn, dummy_filing()),
            Err(IncidentError::ClockAlreadyResolved { .. })
        ));
    }

    fn dummy_filing() -> Filing {
        Filing {
            template_version: "v1".into(),
            submitted_tick: 1,
            ack_ref: "A".into(),
        }
    }

    #[test]
    fn register_is_hash_chained_and_tamper_evident() {
        let mut reg = register();
        let id = reg.open(
            pan_egress_candidate(0),
            IncidentClass::CyberSecurityIncident,
            0,
        );
        reg.tick(400); // pages + meta events
        let n = reg.verify().unwrap();
        assert!(n >= 2);
        // Tamper: flip an event's incident_id after the fact → chain breaks.
        reg.events[0].incident_id = format!("{id}-tampered");
        assert!(matches!(
            reg.verify(),
            Err(TamperError::HashMismatch { seq: 0 })
        ));
    }

    #[test]
    fn armed_clocks_projection_reports_remaining() {
        let mut reg = register();
        let id = reg.open(
            pan_egress_candidate(0),
            IncidentClass::CyberSecurityIncident,
            0,
        );
        let armed = reg.armed_clocks(100);
        assert_eq!(
            armed,
            vec![(id, StatutoryClockKind::CertIn, 260)] // 360 - 100
        );
    }

    #[test]
    fn r10_statutory_clock_breach_boundary_is_unit_consistent() {
        // Round-10 REAL BUG pin: the arming budget, elapsed, and the breach comparison are ONE unit,
        // and the wall-clock→tick projection lands a 72h DPDP clock's breach at 72 HOURS, never 72
        // minutes. This is the boundary a seconds-fed driver got wrong (breaching 60× early).
        let mut reg = register();
        // Personal-data breach arms DPDP-board = 72h = 4320 ticks (minute-scaled) from t0 = 0.
        let id = reg.open(
            pan_egress_candidate(0),
            IncidentClass::PersonalDataBreach,
            0,
        );
        let clk = reg
            .incident(&id)
            .unwrap()
            .clock(StatutoryClockKind::DpdpBoard)
            .unwrap();
        assert_eq!(clk.budget_ticks, budget_ticks_from_hours(72));
        assert_eq!(
            clk.budget_ticks, 4_320,
            "72h must be 4320 minute-ticks, not 72"
        );
        assert_eq!(clk.deadline(), 4_320);

        // elapsed + breach agree on the unit: not breached AT the deadline, breached one tick past it.
        // (Asserted on the DPDP-BOARD clock specifically — the class also arms a tighter 24h clock.)
        let board_breached = |reg: &IncidentRegister, now: Tick| {
            reg.breached_without_filing(now)
                .iter()
                .any(|(_, k)| *k == StatutoryClockKind::DpdpBoard)
        };
        assert_eq!(clk.elapsed(4_320), 4_320);
        assert!(
            !clk.is_breached(4_320),
            "not breached at exactly the deadline"
        );
        assert!(
            !board_breached(&reg, 4_320),
            "72h clock not breached AT 4320"
        );
        assert!(
            board_breached(&reg, 4_321),
            "the 72h clock breaches one tick past 4320, i.e. at 72h — never at 72min"
        );

        // The wall-clock projection is what makes a live driver correct: 72 wall-MINUTES maps to 72
        // ticks (nowhere near the 4320 budget → NOT breached), while 72 wall-HOURS maps to exactly the
        // 4320-tick budget. A driver feeding raw as_secs() would instead treat 72min (4320s) as 4320
        // ticks and breach 60× early — the bug this pins shut.
        assert_eq!(ticks_from_unix_secs(72 * 60), 72);
        assert_eq!(ticks_from_unix_secs(72 * 3600), 4_320);
        assert!(
            !board_breached(&reg, ticks_from_unix_secs(72 * 60)),
            "after 72 wall-minutes the 72h clock must NOT be breached"
        );
        assert!(
            board_breached(&reg, ticks_from_unix_secs(72 * 3600) + 1),
            "just past 72 wall-hours the 72h clock breaches"
        );
    }

    #[test]
    fn deterministic_ids_and_no_meta_before_deadline() {
        let mut reg = register();
        let id = reg.open(
            pan_egress_candidate(500),
            IncidentClass::CyberSecurityIncident,
            500,
        );
        assert_eq!(id, "incident-gate-egress-500");
        // Just before the deadline (t0 500 + 360 = 860): board-delegate not yet paged, no meta.
        let ev = reg.tick(859);
        assert!(!ev
            .iter()
            .any(|e| matches!(e, EngineEvent::MetaIncidentRaised { .. })));
    }
}
