// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R7 — the SHIPPED daemon INVOKES the built organs (closing the recurring "wired-but-not-invoked"
//! gap). Round 6 instantiated + held the control organs on `AssembledFull` but several were never
//! actually driven on any served decision. These tests assert on the REAL composition objects that the
//! organs are now LIVE **and evaluated**:
//!
//! * `r7_promotion_gate_evaluates_quality_breaker_and_arms_incident` — the FI-07 promotion/routing
//!   admission gate (`AssembledFull::admit_promotion`) actually EVALUATES the SR-11-7 quality
//!   circuit-breaker + due-diligence gate: a regulated route with no monitoring is REFUSED and arms an
//!   operational-risk incident on the LIVE served register; a healthy route is ADMITTED.
//! * `r7_retention_legal_hold_organ_live` — the data-lifecycle organ (retention TTL / legal-hold /
//!   DSAR right-to-erasure over the durable record tier) is held LIVE and enforces the legal-hold
//!   freeze (a held record's erasure is deferred, never silently dropped).
//! * `r7_connector_use_path_fails_closed_offline` — the connector USE path (`ConnectorInvoker`) is LIVE
//!   on the served surface and fails CLOSED on the air-gapped default (no fabricated success).
//! * `r7_unified_capability_registry_populated_on_served_engine` — the ONE unified Capability registry
//!   the served engine dispatches through is POPULATED with the built-in native `query_ledger`
//!   capability (not empty dead code).
//!
//! Fail-before/pass-after: before R7 `admit_promotion`, the retention organ, the `ConnectorInvoker`, and
//! the populated registry did not exist — these tests would not compile/pass. Deterministic: the offline
//! provider backs the engine; the organs are the REAL production types.

use std::time::{SystemTime, UNIX_EPOCH};

use ainxt_runtimed::{
    assemble_full, assemble_surface, build_unified_capability_registry, load_layered,
    PromotionAdmission,
};

fn loaded_with_unique_log() -> ainxt_runtimed::LoadedConfig {
    // R16 critical: the daemon now refuses the header-trusting default authenticator unless the
    // deployment states the assumption (see r10_breach_clock_unit.rs) — state it here.
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("ainxt-r7-{nanos}"));
    let src = format!(
        "version = 1\n[server]\nevent_log_dir = {:?}\n",
        dir.to_string_lossy()
    );
    load_layered(&[("r7", &src)]).expect("load offline config")
}

fn assembled_full() -> ainxt_runtimed::AssembledFull {
    let loaded = loaded_with_unique_log();
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat surface");
    assemble_full(&loaded, assembled).expect("assemble fully-wired surface")
}

#[tokio::test(flavor = "multi_thread")]
async fn r7_promotion_gate_evaluates_quality_breaker_and_arms_incident() {
    use ainxt_responsibleai::dpia::PromotionTarget;
    use ainxt_responsibleai::{
        DueDiligenceConfig, ModelProvenance, ModelRiskRecord, MonitoringScoreboard, RiskClass,
        ValidationStatus,
    };
    use ainxt_types::DataClass;

    let full = assembled_full();
    let dd = DueDiligenceConfig::default();
    let now = 10_000u64;

    // A REGULATED route with NO live monitoring scoreboard — "monitored, not certified-once" is
    // violated, so both the due-diligence gate AND the quality breaker refuse it, and (regulated) an
    // operational-risk incident is armed on the LIVE served register.
    let unmonitored = ModelRiskRecord {
        model_id: "txn-scorer-cloud".into(),
        provenance: ModelProvenance::InHouse,
        permitted_data_class: DataClass::RegulatedPayment,
        intended_use: "score settlement anomalies".into(),
        risk_class: RiskClass::High,
        validation: ValidationStatus::IndependentlyValidated { at_tick: 0 },
        challenger: None,
        monitoring: None,
        limitations: vec![],
    };
    let incidents_before = full.incidents.lock().unwrap().incidents().count();
    // GAP-AUDIT regulated-fi #8 — this test is specifically about the FI-07 quality-breaker behavior,
    // not FI-06 DPIA; `PromotionTarget::Dev` is unconditionally DPIA-free so it stays scoped to that.
    let decision = full.admit_promotion("test-route", PromotionTarget::Dev, &unmonitored, &dd, now);
    match &decision {
        PromotionAdmission::Refused {
            reasons,
            incident_opened,
        } => {
            assert!(
                reasons.iter().any(|r| r.contains("quality circuit-breaker OPEN")),
                "the quality breaker must be EVALUATED and trip on a missing scoreboard: {reasons:?}"
            );
            assert!(
                incident_opened.is_some(),
                "a regulated route's breaker trip must ARM an incident on the served register"
            );
        }
        PromotionAdmission::Admitted => panic!("an unmonitored regulated route must be refused"),
    }
    assert!(
        full.incidents.lock().unwrap().incidents().count() > incidents_before,
        "the served incident register must have opened the operational-risk incident"
    );

    // A HEALTHY route: independently validated, live scoreboard above the bar, fresh, low-risk (no
    // challenger required) — the gate ADMITS it (proving the refusal above is a real evaluation, not a
    // blanket deny).
    let healthy = ModelRiskRecord {
        model_id: "in-house-8k".into(),
        provenance: ModelProvenance::InHouse,
        permitted_data_class: DataClass::Internal,
        intended_use: "general assistance".into(),
        risk_class: RiskClass::Limited,
        validation: ValidationStatus::IndependentlyValidated { at_tick: 0 },
        challenger: None,
        monitoring: Some(MonitoringScoreboard::new(0.95, 500, now)),
        limitations: vec![],
    };
    assert!(
        full.admit_promotion("test-route", PromotionTarget::Dev, &healthy, &dd, now)
            .is_admitted(),
        "a validated, monitored, above-bar route must be ADMITTED to promote"
    );
}

/// GAP-FIX regulated-fi-responsible-lifecycle — `model_risk_breaker_status`/`model_risk_promotable_status`
/// (a cap-gated, read-only preview of the SAME quality-breaker/due-diligence checks `admit_promotion`
/// already runs, over the SAME `quality_breaker`) were previously unreachable: a caller could only ever
/// learn a route's state by driving a full (side-effecting) promotion. Proves both are fail-closed on
/// authority and agree with `admit_promotion`'s own verdict for the SAME record.
#[tokio::test(flavor = "multi_thread")]
async fn r_model_risk_status_previews_agree_with_admit_promotion_and_are_cap_gated() {
    use ainxt_responsibleai::routes::ModelRiskRouteError;
    use ainxt_responsibleai::{
        DueDiligenceConfig, ModelProvenance, ModelRiskRecord, RiskClass, ValidationStatus,
    };
    use ainxt_types::{DataClass, Principal};

    let full = assembled_full();
    let dd = DueDiligenceConfig::default();
    let now = 10_000u64;

    let unmonitored = ModelRiskRecord {
        model_id: "txn-scorer-cloud".into(),
        provenance: ModelProvenance::InHouse,
        permitted_data_class: DataClass::RegulatedPayment,
        intended_use: "score settlement anomalies".into(),
        risk_class: RiskClass::High,
        validation: ValidationStatus::IndependentlyValidated { at_tick: 0 },
        challenger: None,
        monitoring: None,
        limitations: vec![],
    };

    // Fail-closed: a caller lacking `model-risk.read` is refused BEFORE any breaker/due-diligence
    // evaluation, for both preview methods.
    let no_cap = Principal::user("mallory", &[]);
    assert_eq!(
        full.model_risk_breaker_status(&no_cap, &unmonitored),
        Err(ModelRiskRouteError::NotAuthorized)
    );
    assert_eq!(
        full.model_risk_promotable_status(&no_cap, &unmonitored, &dd, now),
        Err(ModelRiskRouteError::NotAuthorized)
    );

    // Authorized: the preview agrees with `admit_promotion`'s own live verdict for the SAME record —
    // an unmonitored regulated route trips the breaker and fails due diligence either way.
    let reader = Principal::user("auditor", &["model-risk.read"]);
    let breaker = full
        .model_risk_breaker_status(&reader, &unmonitored)
        .expect("authorized caller reaches the breaker");
    assert!(
        matches!(breaker, ainxt_responsibleai::BreakerState::Open(_)),
        "must agree: breaker trips"
    );

    let promotable = full
        .model_risk_promotable_status(&reader, &unmonitored, &dd, now)
        .expect("authorized caller reaches due diligence");
    assert!(
        !promotable.promotable,
        "must agree: an unmonitored regulated route is not promotable"
    );
    assert!(!promotable.defects.is_empty());

    // The preview is READ-ONLY: it must never arm an incident (unlike `admit_promotion` itself).
    let incidents_before = full.incidents.lock().unwrap().incidents().count();
    let _ = full.model_risk_breaker_status(&reader, &unmonitored);
    let _ = full.model_risk_promotable_status(&reader, &unmonitored, &dd, now);
    assert_eq!(
        full.incidents.lock().unwrap().incidents().count(),
        incidents_before,
        "a read-only preview must never open an incident as a side effect"
    );
}

/// GAP-AUDIT regulated-fi #8 — FI-06 (the DPIA-per-feature CI gate) was a fully implemented, tested
/// gate object with ZERO callers on the served promotion path: `admit_promotion` independently
/// re-implemented only the FI-07 half, so a personal-data feature with a pristine model-risk record
/// could reach prod with no DPIA at all. Proves the composed check now genuinely runs.
#[tokio::test(flavor = "multi_thread")]
async fn r8_admit_promotion_blocks_a_personal_data_feature_with_no_dpia_even_with_a_clean_record() {
    use ainxt_responsibleai::dpia::{Dpia, FeatureProfile, PromotionTarget};
    use ainxt_responsibleai::{
        DueDiligenceConfig, ModelProvenance, ModelRiskRecord, MonitoringScoreboard, RiskClass,
        ValidationStatus,
    };
    use ainxt_types::DataClass;

    let full = assembled_full();
    let dd = DueDiligenceConfig::default();
    let now = 10_000u64;

    // A pristine model-risk record — FI-07 alone would ADMIT.
    let clean_record = ModelRiskRecord {
        model_id: "inhouse-scorer".into(),
        provenance: ModelProvenance::InHouse,
        permitted_data_class: DataClass::Pii,
        intended_use: "summarize inbox".into(),
        risk_class: RiskClass::Limited,
        validation: ValidationStatus::IndependentlyValidated { at_tick: 0 },
        challenger: None,
        monitoring: Some(MonitoringScoreboard::new(0.95, 500, now)),
        limitations: vec![],
    };

    // Register a personal-data feature (uses the daemon's own default connector fragment "outlook")
    // with NO DPIA recorded.
    full.dpia_gate.lock().unwrap().register_feature(
        FeatureProfile::new("summarizer", DataClass::Internal, "summarize inbox")
            .with_capability("connector.outlook.read"),
    );

    let refused =
        full.admit_promotion("summarizer", PromotionTarget::Prod, &clean_record, &dd, now);
    match refused {
        PromotionAdmission::Refused { reasons, .. } => {
            assert!(
                reasons.iter().any(|r| r.contains("FI-06 DPIA")),
                "a personal-data feature with a clean model-risk record but no DPIA must still be \
                 blocked on promotion to prod: {reasons:?}"
            );
        }
        PromotionAdmission::Admitted => {
            panic!("a personal-data feature with no DPIA must never be admitted to prod")
        }
    }

    // Record an approved, current DPIA for the SAME feature — now it must admit (FI-07 was already
    // clean; this proves the block above was a real DPIA evaluation, not an unconditional refusal).
    let profile = FeatureProfile::new("summarizer", DataClass::Internal, "summarize inbox")
        .with_capability("connector.outlook.read");
    let mut dpia = Dpia::draft("summarizer", "risks + mitigations");
    dpia.approve_for(&profile, "dpo-anita");
    full.dpia_gate.lock().unwrap().record_dpia(dpia);

    assert!(
        full.admit_promotion("summarizer", PromotionTarget::Prod, &clean_record, &dd, now)
            .is_admitted(),
        "the same feature with an approved, current DPIA must now be admitted"
    );

    // A `dev` target stays DPIA-free even for an un-inventoried feature.
    assert!(
        full.admit_promotion(
            "never-registered",
            PromotionTarget::Dev,
            &clean_record,
            &dd,
            now
        )
        .is_admitted(),
        "dev promotion must remain DPIA-free even for a feature the gate has never seen"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn r7_retention_legal_hold_organ_live() {
    use ainxt_lifecycle::{Record, RetentionPolicy};
    use ainxt_types::DataClass;

    let full = assembled_full();
    let mut store = full.retention.lock().unwrap();

    // Put a legal-hold on the PII class, then request erasure of the subject's PII record: the hold
    // FREEZES it — the erasure is DEFERRED + recorded, never silently dropped (the regulator's freeze
    // wins over the DPDP right-to-erasure).
    store.set_policy(RetentionPolicy::new(DataClass::Pii, 1_000).with_legal_hold(true));
    store.put(Record::new("rec-pii", "subject-1", DataClass::Pii, 0));
    // A non-held Internal record is erased normally.
    store.put(Record::new("rec-int", "subject-1", DataClass::Internal, 0));

    let outcome = store.erase_subject("subject-1");
    assert!(
        outcome.refused.iter().any(|r| r.record_id == "rec-pii"),
        "a legal-held record's erasure must be DEFERRED/refused, not honored: {outcome:?}"
    );
    assert!(
        outcome.erased.contains(&"rec-int".to_string()),
        "a non-held record must still be erased on a DSAR request: {outcome:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn r7_connector_use_path_fails_closed_offline() {
    use ainxt_connector_http::Graph;
    use ainxt_types::{DataClass, Principal};

    let full = assembled_full();
    let principal = Principal::user("alice", &["connector.graph"]);
    let prepared = Graph::new().get_me();

    // The USE path is LIVE (admission + egress + audit run), but the air-gapped default has no
    // registered connector / no sealed token / an offline transport — so the call fails CLOSED, never
    // fabricating a success.
    let result = full
        .connector_invoker
        .invoke(&principal, 1_000, DataClass::Internal, prepared);
    assert!(
        result.is_err(),
        "the connector USE path must fail closed on the air-gapped default, never a fabricated success"
    );
}

#[test]
fn r7_unified_capability_registry_populated_on_served_engine() {
    // The ONE unified Capability registry the served engine dispatches through is POPULATED with the
    // built-in native `query_ledger` capability (is_side_effecting returns Some ⇒ registered), not an
    // empty registry.
    let mut report = Vec::new();
    let registry = build_unified_capability_registry(&mut report);
    assert!(
        registry.is_side_effecting("query_ledger").is_some(),
        "the unified registry must be POPULATED with the built-in native query_ledger capability"
    );
    assert!(
        report
            .iter()
            .any(|r| r.contains("ONE unified Capability registry")),
        "the assembly report must announce the unified registry wire: {report:?}"
    );

    // And the assembled surface's report announces the served ledger/answer numeric HARD GATE (gap 2)
    // and the promotion-path breaker evaluation (gap 1).
    let full = assembled_full_sync();
    assert!(
        full.report
            .iter()
            .any(|r| r.contains("numeric re-derivation HARD GATE")),
        "the served chat path must announce the numeric re-derivation hard gate"
    );
    assert!(
        full.report
            .iter()
            .any(|r| r.contains("EVALUATED on the served promotion/routing path")),
        "the quality breaker must announce it is evaluated on the promotion path"
    );
    assert!(
        full.report.iter().any(|r| r.contains("connector USE path")),
        "the connector USE path organ must be announced"
    );
    assert!(
        full.report
            .iter()
            .any(|r| r.contains("data-retention / legal-hold")),
        "the retention/legal-hold organ must be announced"
    );
}

fn assembled_full_sync() -> ainxt_runtimed::AssembledFull {
    let loaded = loaded_with_unique_log();
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat surface");
    assemble_full(&loaded, assembled).expect("assemble fully-wired surface")
}

/// GAP-AUDIT connectors #4 — both served connector organs (`ConnectorGateway`'s OWN OAuth audit AND
/// `ConnectorInvoker`'s wrapped `ConnectorRuntime` audit) used the plain, non-chained
/// `InMemoryConnectorAudit` — the daemon's own doc comment at the composition site named this exact
/// gap (`needs_hot_wiring`) and named the fix. Proves the USE-path organ now uses the tamper-evident
/// `HashChainedConnectorAudit`: driving one admission decision against the empty air-gapped catalog
/// (fails closed on `UnknownConnector`, but `ConnectorRuntime::authorize_use` audits the denial
/// itself before returning) leaves a real hash-chain head — `InMemoryConnectorAudit::head_hash`
/// always returns `None`, so a non-`None` head is only possible with the chained sink.
#[test]
fn r4_connector_use_path_organ_uses_tamper_evident_audit_not_in_memory() {
    use ainxt_connector_http::{HttpMethod, HttpRequest, PreparedCall};
    use ainxt_types::{DataClass, Principal};

    let full = assembled_full_sync();
    // `InMemoryConnectorAudit::head_hash` (the default trait impl) ALWAYS returns `None` — a chained
    // sink always returns `Some(genesis-derived-hash)`, even with zero events. So `is_some()` alone
    // already distinguishes the two; the real proof this is a genuine hash CHAIN (not a constant) is
    // that the head changes once a real event is recorded.
    let genesis_head = full.connector_invoker.audit_head().expect(
        "the USE-path organ's audit sink must be the tamper-evident HashChainedConnectorAudit \
                 (InMemoryConnectorAudit's head_hash is always None, even before any event)",
    );

    let principal = Principal::user("u1", &[]);
    let prepared = PreparedCall {
        connector: "no-such-connector".into(),
        op: "read".to_string(),
        resource: None,
        request: HttpRequest::new(HttpMethod::Get, "https://example.invalid/x"),
        egress_body: false,
    };
    // The air-gapped default registers no connectors, so this fails closed at admission — but
    // `ConnectorRuntime::authorize_use` audits an `UnknownConnector` denial before returning it.
    let _ = full
        .connector_invoker
        .invoke(&principal, 1_000, DataClass::Public, prepared);

    let head_after = full.connector_invoker.audit_head().expect("still chained");
    assert_ne!(
        genesis_head, head_after,
        "the head must advance after a real audit event — proving this is a real hash chain, not a \
         static placeholder"
    );
}

/// GAP-FIX connectors — `HashChainedConnectorAudit::verify`/`verify_chain` were fully implemented and
/// unit-tested but had zero callers outside `ainxt-connector`'s own tests: the composition root could
/// read the chain's head anchor (`audit_head`, GAP-AUDIT connectors #4 above) but never actually WALK
/// the chain to confirm it is intact. Proves the served USE-path organ's chain verifies clean both
/// before and after a real audit event.
#[test]
fn r_connector_use_path_organ_audit_chain_verifies_intact() {
    use ainxt_connector_http::{HttpMethod, HttpRequest, PreparedCall};
    use ainxt_types::{DataClass, Principal};

    let full = assembled_full_sync();
    assert_eq!(
        full.connector_invoker.audit_verify(),
        Ok(()),
        "an empty chain verifies clean"
    );

    let principal = Principal::user("u1", &[]);
    let prepared = PreparedCall {
        connector: "no-such-connector".into(),
        op: "read".to_string(),
        resource: None,
        request: HttpRequest::new(HttpMethod::Get, "https://example.invalid/x"),
        egress_body: false,
    };
    let _ = full
        .connector_invoker
        .invoke(&principal, 1_000, DataClass::Public, prepared);

    assert_eq!(
        full.connector_invoker.audit_verify(),
        Ok(()),
        "a real audit event must still verify clean — the reachable check confirms intact links, not \
         just that a head anchor exists"
    );
}
