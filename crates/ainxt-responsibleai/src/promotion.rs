// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! The composed **governance promotion gate** — the single fail-closed decision a CI promotion job or
//! the release controller runs before a feature/route reaches `env/prod` (`REGULATED_FI_COMPLIANCE_OPS.md`
//! §4). It unifies the two promotion-time governance controls that previously each existed as a library
//! with no single caller:
//!
//! * **FI-06 — DPDP DPIA-per-feature** ([`crate::dpia::DpiaCiGate`]): a personal-data feature may not
//!   promote to `env/prod` without an approved, content-current DPIA.
//! * **FI-07 — SR-11-7 model-risk / quality** ([`crate::route_promotable`] + [`crate::QualityCircuitBreaker`]):
//!   the serving model-route must clear algorithmic due-diligence AND its live quality circuit-breaker
//!   must be closed ("monitored, not certified-once").
//!
//! Before this composition FI-06 was a gate object with **zero callers** — its `check` was never run on
//! any promotion path, so a personal-data feature could reach prod with a clean model-risk record and no
//! DPIA. [`GovernancePromotionGate::admit`] is the caller: it runs BOTH controls, fail-closed, and
//! collects **every** reason so an operator fixes all blockers at once. Pure/deterministic — `now` is
//! injected; no clock/RNG/I/O.
//!
//! **The served daemon's promotion/routing admission path is `ainxt_runtimed::AssembledFull::
//! admit_promotion`** — it originally reimplemented this SAME three-check sequence inline (plus its own
//! served side effects: event-log audit, `ainxt-eval` regression-vault case minting, and §2 incident
//! opening on a regulated-route breaker trip, none of which belong in this crate's pure gate). GAP-FIX
//! gap6-responsibleai-cleanup item 2 removed that duplication: `admit_promotion` now calls
//! [`GovernancePromotionGate::evaluate`] (the borrowed-parts core also backing [`GovernancePromotionGate::
//! admit`]) for the decision, and layers its own side effects on top of the returned
//! [`PromotionOutcome`] — so there is exactly ONE implementation of the gate logic itself. Unit tests
//! here prove the composition blocks on either control; `ainxt-runtimed`'s own tests prove
//! `admit_promotion` reaches this same logic on the real served path.

use crate::dpia::{DpiaCiGate, DpiaGateDecision, PromotionTarget};
use crate::{
    route_promotable, DueDiligenceConfig, DueDiligenceOutcome, ModelRiskRecord,
    QualityCircuitBreaker,
};

/// A single blocking reason from the composed gate — kept typed (not stringly) so a caller can route
/// FI-06 blocks (DPO re-assessment) differently from FI-07 blocks (model-risk remediation).
#[derive(Debug, Clone, PartialEq)]
pub enum PromotionBlock {
    /// FI-06: the feature's DPIA gate refused (missing / not-approved / stale / unknown feature).
    Dpia(crate::dpia::DpiaGateRefusal),
    /// FI-07: the model-risk record failed algorithmic due-diligence (each defect rendered).
    ModelRiskDueDiligence(Vec<String>),
    /// FI-07: the live quality circuit-breaker is OPEN for the route (score below bar / absent).
    QualityBreakerOpen {
        route_id: String,
        score: f64,
        bar: f64,
        regulated_route: bool,
    },
}

impl std::fmt::Display for PromotionBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PromotionBlock::Dpia(r) => write!(f, "FI-06 DPIA: {r}"),
            PromotionBlock::ModelRiskDueDiligence(defects) => {
                write!(f, "FI-07 due-diligence: {}", defects.join("; "))
            }
            PromotionBlock::QualityBreakerOpen {
                route_id,
                score,
                bar,
                ..
            } => write!(
                f,
                "FI-07 quality circuit-breaker OPEN for route '{route_id}': live score {score:.2} < bar {bar:.2}"
            ),
        }
    }
}

/// The composed gate's decision. `Admitted` only when EVERY applicable control passes; otherwise every
/// blocking reason is returned together (fail-closed, fix-all-at-once).
#[derive(Debug, Clone, PartialEq)]
pub enum PromotionOutcome {
    Admitted,
    Blocked(Vec<PromotionBlock>),
}

impl PromotionOutcome {
    pub fn is_admitted(&self) -> bool {
        matches!(self, PromotionOutcome::Admitted)
    }
    /// The blocking reasons (empty when admitted).
    pub fn blocks(&self) -> &[PromotionBlock] {
        match self {
            PromotionOutcome::Blocked(b) => b,
            PromotionOutcome::Admitted => &[],
        }
    }
}

/// The composed governance promotion gate (§4). Owns the FI-06 DPIA CI gate, the FI-07 due-diligence
/// config, and the live FI-07 quality circuit-breaker. One [`admit`](Self::admit) call is the whole
/// promotion-time governance decision.
#[derive(Debug, Clone)]
pub struct GovernancePromotionGate {
    dpia: DpiaCiGate,
    dd_cfg: DueDiligenceConfig,
    breaker: QualityCircuitBreaker,
}

impl GovernancePromotionGate {
    /// Build the composed gate from its two sub-controls.
    pub fn new(
        dpia: DpiaCiGate,
        dd_cfg: DueDiligenceConfig,
        breaker: QualityCircuitBreaker,
    ) -> Self {
        Self {
            dpia,
            dd_cfg,
            breaker,
        }
    }

    /// Borrow the FI-06 DPIA gate (e.g. to hydrate feature/DPIA inventory at bootstrap).
    pub fn dpia_gate(&self) -> &DpiaCiGate {
        &self.dpia
    }

    /// Mutable access to the FI-06 DPIA gate (register features / record DPIAs).
    pub fn dpia_gate_mut(&mut self) -> &mut DpiaCiGate {
        &mut self.dpia
    }

    /// **The composed promotion decision** for promoting `feature_id` (served by model-route `record`)
    /// to `target`, at logical time `now`.
    ///
    /// Runs, fail-closed and collecting every reason:
    /// 1. **FI-06** — the DPIA CI gate for `(feature_id, target)`. A `dev` target is DPIA-free; an
    ///    `env`/`prod` target of a personal-data feature requires an approved, current DPIA.
    /// 2. **FI-07** — algorithmic due-diligence ([`route_promotable`]) on the serving model-route's
    ///    risk record.
    /// 3. **FI-07** — the live quality circuit-breaker on the route's monitoring scoreboard.
    ///
    /// `Admitted` iff all three pass. This is the caller FI-06 lacked: a personal-data feature with a
    /// pristine model-risk record but no DPIA is now BLOCKED (previously it would have promoted).
    pub fn admit(
        &self,
        feature_id: &str,
        target: PromotionTarget,
        record: &ModelRiskRecord,
        now: u64,
    ) -> PromotionOutcome {
        Self::evaluate(
            &self.dpia,
            &self.dd_cfg,
            &self.breaker,
            feature_id,
            target,
            record,
            now,
        )
    }

    /// The composed gate's **borrowed-parts core** — the exact same fail-closed, collect-every-reason
    /// logic [`Self::admit`] runs, but over caller-borrowed `dpia`/`dd_cfg`/`breaker` instead of an
    /// owned `GovernancePromotionGate`. This is the single source of truth for the promotion-gate
    /// decision: a caller that already holds its own live state behind its own synchronization (e.g.
    /// the served daemon's `AssembledFull`, which keeps `dpia_gate` behind a `Mutex` and
    /// `quality_breaker` behind an `Arc` so OTHER code paths can also read/mutate them directly) can
    /// call this without needing to clone that state into a freshly-constructed `GovernancePromotionGate`
    /// on every call. `admit` above is the convenience form for a caller that owns the gate outright
    /// (e.g. a standalone CI promotion job).
    pub fn evaluate(
        dpia: &DpiaCiGate,
        dd_cfg: &DueDiligenceConfig,
        breaker: &QualityCircuitBreaker,
        feature_id: &str,
        target: PromotionTarget,
        record: &ModelRiskRecord,
        now: u64,
    ) -> PromotionOutcome {
        let mut blocks: Vec<PromotionBlock> = Vec::new();

        // (1) FI-06 DPIA CI gate.
        if let DpiaGateDecision::Blocked(refusal) = dpia.check(feature_id, target) {
            blocks.push(PromotionBlock::Dpia(refusal));
        }

        // (2) FI-07 algorithmic due-diligence.
        if let DueDiligenceOutcome::Failed(defects) = route_promotable(record, dd_cfg, now) {
            blocks.push(PromotionBlock::ModelRiskDueDiligence(
                defects.iter().map(|d| d.to_string()).collect(),
            ));
        }

        // (3) FI-07 live quality circuit-breaker.
        if let crate::BreakerState::Open(trip) = breaker.evaluate(record) {
            blocks.push(PromotionBlock::QualityBreakerOpen {
                route_id: trip.route_id,
                score: trip.score,
                bar: trip.bar,
                regulated_route: trip.regulated_route,
            });
        }

        if blocks.is_empty() {
            PromotionOutcome::Admitted
        } else {
            PromotionOutcome::Blocked(blocks)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dpia::{Dpia, FeatureProfile};
    use crate::{
        ChallengerRef, ModelProvenance, MonitoringScoreboard, RiskClass, ValidationStatus,
    };
    use ainxt_types::DataClass;

    const PDC: &[&str] = &["outlook", "graph", "crm"];

    fn clean_record() -> ModelRiskRecord {
        ModelRiskRecord {
            model_id: "inhouse-scorer".into(),
            provenance: ModelProvenance::InHouse,
            permitted_data_class: DataClass::RegulatedPayment,
            intended_use: "payment routing".into(),
            risk_class: RiskClass::High,
            validation: ValidationStatus::IndependentlyValidated { at_tick: 1 },
            challenger: Some(ChallengerRef {
                model_id: "challenger-x".into(),
                note: "benchmark".into(),
            }),
            monitoring: Some(MonitoringScoreboard::new(0.95, 10_000, 5_000)),
            limitations: vec![],
        }
    }

    fn gate_with(dpia: DpiaCiGate) -> GovernancePromotionGate {
        GovernancePromotionGate::new(
            dpia,
            DueDiligenceConfig::default(),
            QualityCircuitBreaker::new(0.8),
        )
    }

    #[test]
    fn personal_data_feature_without_dpia_is_blocked_even_with_a_clean_model_risk_record() {
        // The load-bearing composition proof: FI-07 alone would ADMIT (record is pristine), but the
        // composed gate BLOCKS on the missing FI-06 DPIA — the caller FI-06 previously lacked.
        let record = clean_record();

        // FI-07 in isolation passes.
        assert!(route_promotable(&record, &DueDiligenceConfig::default(), 5_000).is_passed());

        let mut dpia_gate = DpiaCiGate::new(PDC);
        dpia_gate.register_feature(
            FeatureProfile::new("summarizer", DataClass::Internal, "summarize inbox")
                .with_capability("connector.outlook.read"),
        );
        // No DPIA recorded for the personal-data feature.
        let gate = gate_with(dpia_gate);

        let out = gate.admit("summarizer", PromotionTarget::Prod, &record, 5_000);
        assert!(
            !out.is_admitted(),
            "composed gate must block on missing DPIA"
        );
        assert!(matches!(out.blocks()[0], PromotionBlock::Dpia(_)));
    }

    #[test]
    fn both_controls_passing_admits() {
        let record = clean_record();
        let mut dpia_gate = DpiaCiGate::new(PDC);
        let profile = FeatureProfile::new("summarizer", DataClass::Pii, "summarize inbox");
        dpia_gate.register_feature(profile.clone());
        let mut dpia = Dpia::draft("summarizer", "risks + mitigations");
        dpia.approve_for(&profile, "dpo-anita");
        dpia_gate.record_dpia(dpia);

        let gate = gate_with(dpia_gate);
        assert_eq!(
            gate.admit("summarizer", PromotionTarget::Prod, &record, 5_000),
            PromotionOutcome::Admitted
        );
    }

    #[test]
    fn dev_target_is_dpia_free_but_still_model_risk_gated() {
        // A dev promotion needs no DPIA, but a degraded model-route still fails FI-07 (breaker open).
        let mut record = clean_record();
        record.monitoring = Some(MonitoringScoreboard::new(0.10, 10_000, 5_000)); // below bar
        let dpia_gate = DpiaCiGate::new(PDC); // no features registered
        let gate = gate_with(dpia_gate);

        let out = gate.admit("anything", PromotionTarget::Dev, &record, 5_000);
        assert!(!out.is_admitted());
        // No DPIA block (dev is DPIA-free); the block(s) are FI-07 only.
        assert!(out
            .blocks()
            .iter()
            .all(|b| !matches!(b, PromotionBlock::Dpia(_))));
        assert!(out
            .blocks()
            .iter()
            .any(|b| matches!(b, PromotionBlock::QualityBreakerOpen { .. })));
    }

    #[test]
    fn both_failing_collects_every_reason() {
        // A personal-data feature with no DPIA AND a stale/degraded model-route: BOTH FI-06 and FI-07
        // reasons come back together (fix-all-at-once).
        let mut record = clean_record();
        record.validation = ValidationStatus::NotValidated; // FI-07 due-diligence fails
        record.monitoring = Some(MonitoringScoreboard::new(0.10, 10_000, 5_000)); // breaker opens
        let mut dpia_gate = DpiaCiGate::new(PDC);
        dpia_gate.register_feature(
            FeatureProfile::new("scorer", DataClass::Pii, "score").with_capability("crm.read"),
        );
        let gate = gate_with(dpia_gate);

        let out = gate.admit("scorer", PromotionTarget::Env, &record, 5_000);
        let blocks = out.blocks();
        assert!(blocks.iter().any(|b| matches!(b, PromotionBlock::Dpia(_))));
        assert!(blocks
            .iter()
            .any(|b| matches!(b, PromotionBlock::ModelRiskDueDiligence(_))));
        assert!(blocks
            .iter()
            .any(|b| matches!(b, PromotionBlock::QualityBreakerOpen { .. })));
    }
}
