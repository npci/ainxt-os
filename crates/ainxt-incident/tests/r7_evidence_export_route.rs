// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R7 — route-ready BSA §63 evidentiary-export + read-only Auditor evidence-access entrypoint
//! (§7.2 / §8.3). Exercises [`IncidentRegister::evidentiary_export_for`] end-to-end, offline.
//! Fail-before: the `evidentiary_export_for` entrypoint + its request/error types did not exist.
//! Pass-after: the entrypoint is capability-gated (explicit AUDITOR_CAP, admin NOT implied),
//! existence-hiding on scope, custody-threaded, and refuses over a broken chain — all serde.

use ainxt_incident::evidence::{
    AuditorScope, EvidenceExportRequest, EvidenceRouteError, NtpAttestation, AUDITOR_CAP,
};
use ainxt_incident::{ArmingPolicy, IncidentCandidate, IncidentClass, IncidentRegister};

use ainxt_types::{DataClass, Principal};

fn ntp() -> NtpAttestation {
    NtpAttestation {
        source: "nic-ntp-pool".into(),
        last_sync_offset_ms: 8,
        within_threshold: true,
    }
}

fn req(incident_id: &str) -> EvidenceExportRequest {
    EvidenceExportRequest {
        incident_id: incident_id.to_string(),
        runtime_version: "ainxt-runtime/7.0.0".into(),
        production_method: "append-only SHA-256 hash-chained Event Log".into(),
        ntp: ntp(),
        export_tick: 500,
    }
}

fn seeded() -> (IncidentRegister, String, String) {
    let mut reg = IncidentRegister::new(ArmingPolicy::india_regulatory_default());
    let pii = reg.open_from(
        IncidentCandidate::from_compliance_egress(100, "sha-live-001", DataClass::Pii, 3),
        100,
    );
    let ops = reg.open_from(
        IncidentCandidate::from_serving_ops(200, "sha-b", "route-x"),
        200,
    );
    (reg, pii, ops)
}

#[test]
fn r7_bsa63_evidence_export_route_ready() {
    let (reg, pii_id, ops_id) = seeded();

    // An admin WITHOUT the explicit AUDITOR_CAP is refused (least-privilege, §8.3).
    let admin = Principal::admin("root");
    assert_eq!(
        reg.evidentiary_export_for(&admin, &AuditorScope::All, &req(&pii_id))
            .unwrap_err(),
        EvidenceRouteError::NotAuthorized
    );

    // An empanelled examiner scoped ONLY to personal-data-breach incidents.
    let examiner = Principal::user("rbi-examiner", &[AUDITOR_CAP]);
    let scope = AuditorScope::Classes(vec![IncidentClass::PersonalDataBreach]);

    // In-scope export succeeds and yields a §63 certificate draft with particulars auto-filled and
    // both human signatures deliberately blank; the exporter is the first custody hop.
    let export = reg
        .evidentiary_export_for(&examiner, &scope, &req(&pii_id))
        .unwrap();
    let cert = &export.certificate;
    assert_eq!(cert.record_set_id, pii_id);
    assert_eq!(cert.runtime_version, "ainxt-runtime/7.0.0");
    assert_eq!(cert.control_plane_sha, "sha-live-001");
    assert_eq!(cert.ntp.source, "nic-ntp-pool");
    assert!(cert.integrity_verified);
    assert!(!cert.is_signed());
    assert!(export.reverify());
    assert_eq!(export.custody.hops[0].actor, "rbi-examiner");

    // Out-of-scope incident is indistinguishable from not-found (existence-hiding).
    assert_eq!(
        reg.evidentiary_export_for(&examiner, &scope, &req(&ops_id))
            .unwrap_err(),
        EvidenceRouteError::OutOfScopeOrUnknown
    );
    // A genuinely unknown id collapses into the same 404.
    assert_eq!(
        reg.evidentiary_export_for(&examiner, &AuditorScope::All, &req("no-such-incident"))
            .unwrap_err(),
        EvidenceRouteError::OutOfScopeOrUnknown
    );

    // The request + error round-trip serde (wire body ↔ struct, verbatim refusal render).
    let j = serde_json::to_string(&req(&pii_id)).unwrap();
    let back: EvidenceExportRequest = serde_json::from_str(&j).unwrap();
    assert_eq!(back.incident_id, pii_id);
    let ej = serde_json::to_string(&EvidenceRouteError::OutOfScopeOrUnknown).unwrap();
    assert!(ej.contains("out_of_scope_or_unknown"));
}

#[test]
fn r7_evidence_export_refused_over_broken_chain() {
    // §7.3: the entrypoint must never dress up an unverifiable chain with a §63 certificate.
    let (mut reg, pii_id, _ops) = seeded();
    // Corrupt the register's own chain via a serde round-trip field flip.
    let mut json: serde_json::Value = serde_json::to_value(&reg).unwrap();
    json["events"][0]["tick"] = serde_json::json!(123_456);
    reg = serde_json::from_value(json).unwrap();

    let examiner = Principal::user("rbi-examiner", &[AUDITOR_CAP]);
    assert_eq!(
        reg.evidentiary_export_for(&examiner, &AuditorScope::All, &req(&pii_id))
            .unwrap_err(),
        EvidenceRouteError::ChainBroken
    );
}
