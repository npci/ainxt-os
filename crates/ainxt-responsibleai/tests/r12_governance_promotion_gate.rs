// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R12 gap (medium): "DPIA-per-feature CI promotion gate (FI-06) is a library with zero runtime/CI
//! callers."
//!
//! Closure: [`GovernancePromotionGate`] is the single promotion-time governance decision a CI job /
//! release controller runs — it is the caller FI-06 lacked, composing FI-06 (DPIA) with FI-07
//! (model-risk due-diligence + live quality circuit-breaker). This integration test drives that public
//! entrypoint from OUTSIDE the crate (exactly as the served release/router-admission path will), and
//! proves the composition BLOCKS on the DPIA control that was previously never evaluated on any
//! promotion path.

use ainxt_responsibleai::dpia::{Dpia, DpiaCiGate, FeatureProfile, PromotionTarget};
use ainxt_responsibleai::promotion::{GovernancePromotionGate, PromotionBlock};
use ainxt_responsibleai::{
    route_promotable, ChallengerRef, DueDiligenceConfig, ModelProvenance, ModelRiskRecord,
    MonitoringScoreboard, QualityCircuitBreaker, RiskClass, ValidationStatus,
};
use ainxt_types::DataClass;

const PDC: &[&str] = &["outlook", "graph", "crm"];

fn pristine_route() -> ModelRiskRecord {
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
        monitoring: Some(MonitoringScoreboard::new(0.95, 10_000, 5_000)),
        limitations: vec![],
    }
}

#[test]
fn r12_promotion_gate_is_the_fi06_caller_and_blocks_a_dpia_less_personal_data_feature() {
    let record = pristine_route();

    // FAIL-BEFORE (the "library with zero callers" world): only FI-07 was evaluated on promotion, and
    // FI-07 passes for this pristine route → the personal-data feature would have promoted with NO DPIA.
    assert!(
        route_promotable(&record, &DueDiligenceConfig::default(), 5_000).is_passed(),
        "FI-07 alone admits — so nothing would have caught the missing DPIA"
    );

    // PASS-AFTER: the composed gate now RUNS FI-06 on the promotion path and blocks.
    let mut dpia = DpiaCiGate::new(PDC);
    dpia.register_feature(
        FeatureProfile::new("inbox-summarizer", DataClass::Internal, "summarize inbox")
            .with_capability("connector.outlook.read"),
    );
    let gate = GovernancePromotionGate::new(
        dpia,
        DueDiligenceConfig::default(),
        QualityCircuitBreaker::new(0.8),
    );

    let out = gate.admit("inbox-summarizer", PromotionTarget::Prod, &record, 5_000);
    assert!(
        !out.is_admitted(),
        "must block on the missing DPIA: {out:?}"
    );
    assert!(
        out.blocks()
            .iter()
            .any(|b| matches!(b, PromotionBlock::Dpia(_))),
        "the block must be the FI-06 DPIA control"
    );

    // Recording an approved, current DPIA unblocks — the whole promotion decision is one call.
    let mut dpia2 = DpiaCiGate::new(PDC);
    let profile = FeatureProfile::new("inbox-summarizer", DataClass::Internal, "summarize inbox")
        .with_capability("connector.outlook.read");
    dpia2.register_feature(profile.clone());
    let mut art = Dpia::draft("inbox-summarizer", "risks + mitigations");
    art.approve_for(&profile, "dpo-anita");
    dpia2.record_dpia(art);
    let gate2 = GovernancePromotionGate::new(
        dpia2,
        DueDiligenceConfig::default(),
        QualityCircuitBreaker::new(0.8),
    );
    assert!(gate2
        .admit("inbox-summarizer", PromotionTarget::Prod, &record, 5_000)
        .is_admitted());
}
