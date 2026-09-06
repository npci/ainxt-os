// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX tooling-mcp-plugins-routing (round 2) — "a quality-breaker trip is never also filed as a
//! permanent eval regression scenario".
//!
//! `AssembledFull::admit_promotion` (`ainxt-runtimed`) already correctly maps a real
//! [`ainxt_responsibleai::BreakerTrip`] onto the §2 incident-escalation channel for a REGULATED route
//! (`ainxt_incident::IncidentCandidate::from_quality_breaker`) — that part is pre-existing and
//! untouched by this fix. What was missing: the SAME trip was never ALSO filed into
//! `ainxt_eval::vault::RegressionVault` — meaning "this exact quality regression that tripped the
//! breaker in production" never automatically became a permanent test case a later CI/eval run picks
//! up. `ainxt_eval::vault::VaultOrigin::CircuitBreaker` existed specifically for this ("a live
//! quality-circuit-breaker trip (TOOLING §4.6)") but had ZERO callers anywhere in the workspace before
//! this fix — confirmed by `grep -rn "VaultOrigin::CircuitBreaker" crates/` returning only its own
//! enum-variant definition and doc comment.
//!
//! `admit_promotion` now mints a `VaultCase` into `AssembledFull::vault` on EVERY real trip (not only
//! a regulated one — a non-regulated route's quality regression is still a genuine regression worth
//! guarding against, even though it is not independently RBI-reportable). These tests drive the REAL
//! composition-root `assemble_full`/`admit_promotion` path and prove:
//!   1. A regulated route's trip arms BOTH the pre-existing incident AND a new, sealed vault case.
//!   2. A non-regulated route's trip ALSO mints a vault case, even though NO incident is armed for it
//!      — proving vault-filing is not accidentally scoped to regulated routes only.
//!   3. Re-tripping the IDENTICAL route on the SAME build is idempotent (the vault never grows from a
//!      repeat of a case it already has — `RegressionVault::mint`'s append-only contract).
//!   4. The read-only preview (`model_risk_breaker_status`) never mints a vault case, mirroring its
//!      pre-existing "never arms an incident" guarantee.
//!   5. A healthy (non-tripping) route mints nothing.

use ainxt_eval::vault::VaultOrigin;
use ainxt_responsibleai::dpia::PromotionTarget;
use ainxt_responsibleai::{
    DueDiligenceConfig, ModelProvenance, ModelRiskRecord, MonitoringScoreboard, RiskClass,
    ValidationStatus,
};
use ainxt_runtimed::{assemble_full, assemble_surface, load_layered, PromotionAdmission};
use ainxt_types::{DataClass, Principal};
use std::time::{SystemTime, UNIX_EPOCH};

fn loaded_with_unique_log() -> ainxt_runtimed::LoadedConfig {
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("ainxt-gap5-qcb-vault-{nanos}"));
    let src = format!(
        "version = 1\n[server]\nevent_log_dir = {:?}\n",
        dir.to_string_lossy()
    );
    load_layered(&[("gap5qcbvault", &src)]).expect("load offline config")
}

fn assembled_full() -> ainxt_runtimed::AssembledFull {
    let loaded = loaded_with_unique_log();
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat surface");
    assemble_full(&loaded, assembled).expect("assemble fully-wired surface")
}

fn unmonitored_record(model_id: &str, data_class: DataClass) -> ModelRiskRecord {
    ModelRiskRecord {
        model_id: model_id.to_string(),
        provenance: ModelProvenance::InHouse,
        permitted_data_class: data_class,
        intended_use: "score settlement anomalies".into(),
        risk_class: RiskClass::High,
        validation: ValidationStatus::IndependentlyValidated { at_tick: 0 },
        challenger: None,
        monitoring: None,
        limitations: vec![],
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_regulated_routes_trip_mints_a_sealed_vault_case_alongside_the_pre_existing_incident() {
    let full = assembled_full();
    let dd = DueDiligenceConfig::default();
    let now = 10_000u64;

    let unmonitored = unmonitored_record("txn-scorer-cloud", DataClass::RegulatedPayment);

    let vault_len_before = full.vault.lock().unwrap().len();
    let incidents_before = full.incidents.lock().unwrap().incidents().count();

    let decision = full.admit_promotion("test-route", PromotionTarget::Dev, &unmonitored, &dd, now);
    let PromotionAdmission::Refused {
        incident_opened, ..
    } = &decision
    else {
        panic!("an unmonitored regulated route must be refused: {decision:?}");
    };
    assert!(
        incident_opened.is_some(),
        "the pre-existing incident-arming behavior must be unaffected"
    );

    assert_eq!(
        full.incidents.lock().unwrap().incidents().count(),
        incidents_before + 1,
        "the incident register must still open exactly one new incident (unchanged pre-existing behavior)"
    );
    assert_eq!(
        full.vault.lock().unwrap().len(),
        vault_len_before + 1,
        "a real BreakerTrip on a regulated route must ALSO mint exactly one new regression case into \
         the served RegressionVault — this is the gap being closed: before this fix the vault never \
         grew no matter how many times the breaker tripped"
    );

    let vault = full.vault.lock().unwrap();
    let minted = vault
        .cases()
        .iter()
        .find(|c| c.input.contains("txn-scorer-cloud"))
        .expect("a vault case referencing the tripped route must exist");
    assert_eq!(
        minted.origin,
        VaultOrigin::CircuitBreaker,
        "must be tagged as a circuit-breaker origin"
    );
    assert_eq!(
        minted.control_plane_sha, full.control_plane_sha,
        "the case must be pinned to the SAME control-plane SHA the served surface is running"
    );
    assert!(
        !minted.event_log_id.is_empty(),
        "the case must be reproduce-from-SHA: a real Event-Log id"
    );
    assert!(
        minted.verify_seal(),
        "a freshly-minted case must verify its own tamper-evident seal"
    );
    assert!(
        minted.expectation.contains("txn-scorer-cloud"),
        "the expectation must name the route that regressed: {}",
        minted.expectation
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_non_regulated_routes_trip_also_mints_a_vault_case_even_though_no_incident_arms() {
    let full = assembled_full();
    let dd = DueDiligenceConfig::default();
    let now = 10_000u64;

    // Internal (non-regulated) data class, still unmonitored — trips the breaker (which cares about
    // the live scoreboard, not regulatory status) but must NOT arm an incident (regulated-only).
    let unmonitored = unmonitored_record("internal-scorer", DataClass::Internal);

    let vault_len_before = full.vault.lock().unwrap().len();
    let incidents_before = full.incidents.lock().unwrap().incidents().count();

    let decision =
        full.admit_promotion("test-route-2", PromotionTarget::Dev, &unmonitored, &dd, now);
    let PromotionAdmission::Refused {
        incident_opened,
        reasons,
    } = &decision
    else {
        panic!(
            "an unmonitored route must be refused regardless of regulatory status: {decision:?}"
        );
    };
    assert!(
        reasons
            .iter()
            .any(|r| r.contains("quality circuit-breaker OPEN")),
        "the breaker must genuinely trip for a non-regulated route too: {reasons:?}"
    );
    assert!(
        incident_opened.is_none(),
        "a NON-regulated route's trip must never arm an incident (pre-existing, unchanged behavior)"
    );
    assert_eq!(
        full.incidents.lock().unwrap().incidents().count(),
        incidents_before,
        "no incident must have been opened for the non-regulated trip"
    );
    assert_eq!(
        full.vault.lock().unwrap().len(),
        vault_len_before + 1,
        "vault-filing must NOT be scoped to regulated routes only — a non-regulated quality \
         regression is still a genuine regression worth a permanent eval case"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn retripping_the_identical_route_on_the_same_build_is_idempotent() {
    let full = assembled_full();
    let dd = DueDiligenceConfig::default();
    let now = 10_000u64;
    let unmonitored = unmonitored_record("repeat-offender", DataClass::RegulatedPayment);

    let _ = full.admit_promotion("test-route-3", PromotionTarget::Dev, &unmonitored, &dd, now);
    let vault_len_after_first = full.vault.lock().unwrap().len();

    // Trip the SAME route again, same build (SAME control_plane_sha) — the vault must not grow: this
    // is the SAME regression, already frozen, not a fresh one.
    let _ = full.admit_promotion(
        "test-route-3",
        PromotionTarget::Dev,
        &unmonitored,
        &dd,
        now + 1,
    );
    assert_eq!(
        full.vault.lock().unwrap().len(),
        vault_len_after_first,
        "re-tripping the identical route on an unchanged build must be idempotent — \
         RegressionVault::mint never overwrites/duplicates an existing case id"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_read_only_breaker_status_preview_never_mints_a_vault_case() {
    let full = assembled_full();
    let unmonitored = unmonitored_record("preview-only-route", DataClass::RegulatedPayment);
    let reader = Principal::user("auditor", &["model-risk.read"]);

    let vault_len_before = full.vault.lock().unwrap().len();
    let _ = full
        .model_risk_breaker_status(&reader, &unmonitored)
        .expect("authorized caller reaches the breaker");
    assert_eq!(
        full.vault.lock().unwrap().len(),
        vault_len_before,
        "the READ-ONLY breaker-status preview must never mint a vault case as a side effect, \
         mirroring its pre-existing 'never arms an incident' guarantee"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_healthy_route_that_never_trips_mints_nothing() {
    let full = assembled_full();
    let dd = DueDiligenceConfig::default();
    let now = 10_000u64;

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

    let vault_len_before = full.vault.lock().unwrap().len();
    assert!(
        full.admit_promotion("test-route-4", PromotionTarget::Dev, &healthy, &dd, now)
            .is_admitted(),
        "a validated, monitored, above-bar route must be admitted"
    );
    assert_eq!(
        full.vault.lock().unwrap().len(),
        vault_len_before,
        "an admitted (non-tripping) route must never mint a vault case"
    );
}
