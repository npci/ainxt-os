// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R9 — the SHIPPED daemon HOT-WIRES the route-ready regulated-FI seams over its LIVE served organs.
//!
//! Round 7 mounted the route-ready seams (`RecordStore::request_erasure_attested`,
//! `IncidentRegister::evidentiary_export_for` + `AuditorSession`, the typed `IncidentCandidate`
//! adapters) but the SHIPPED daemon held the LIVE organs (`retention`, `incidents`) with NO entrypoint
//! that drove those seams over them: an erasure DSAR on the served path used the legacy hard-block, no
//! served entrypoint produced a §63 export/auditor listing over the live register, and only the quality
//! circuit-breaker fed the register. These tests assert on the REAL composition object
//! (`assemble_full` → `AssembledFull`) that all three are now driven over the shared, tamper-evident
//! organs:
//!
//! * `r9_served_erasure_redact_with_attestation` (gap 1, §6) — `AssembledFull::erase_subject_attested`
//!   runs a DPDP erasure through the LIVE retention `RecordStore` under §6 precedence: a legal-held and
//!   a floor-bound record are PRESERVED (never hard-deleted under hold) + attested as deferred-with-
//!   record; a free record is hard-erased; the attestation is tamper-evident; fail-closed on
//!   `CAP_RETENTION_ADMIN`.
//! * `r9_served_evidence_export_and_auditor_mode` (gap 2, §7.2/§8.3) —
//!   `AssembledFull::export_incident_evidence` + `auditor_list_incidents` over the LIVE register:
//!   explicit `AUDITOR_CAP` (admin NOT implied), existence-hiding scope, §63 certificate particulars
//!   auto-filled + signatures blank.
//! * `r9_more_than_quality_breaker_feeds_register` (gap 3, §2.1) — the compliance-egress, sink-guard,
//!   payment-boundary and serving-ops detectors each arm a statutory clock on the LIVE register via the
//!   typed `IncidentCandidate` adapters (distinct incident classes), and the hash chain still verifies.
//!
//! Fail-before/pass-after: before R9 `erase_subject_attested`, `ErasureAttestation`,
//! `export_incident_evidence`, `auditor_list_incidents`, and the `arm_*` seams did not exist — these
//! tests would not compile. Deterministic + offline: the air-gapped default assembles with no infra.

use std::time::{SystemTime, UNIX_EPOCH};

use ainxt_runtimed::{assemble_full, assemble_surface, load_layered, AssembledFull};

fn loaded_with_unique_log() -> ainxt_runtimed::LoadedConfig {
    // R16 critical: the daemon now refuses the header-trusting default authenticator unless the
    // deployment states the assumption (see r10_breach_clock_unit.rs) — state it here.
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("ainxt-r9-{nanos}"));
    let src = format!(
        "version = 1\n[server]\nevent_log_dir = {:?}\n",
        dir.to_string_lossy()
    );
    load_layered(&[("r9", &src)]).expect("load offline config")
}

fn assembled_full() -> AssembledFull {
    let loaded = loaded_with_unique_log();
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat surface");
    assemble_full(&loaded, assembled).expect("assemble fully-wired surface")
}

#[tokio::test(flavor = "multi_thread")]
async fn r9_served_erasure_redact_with_attestation() {
    use ainxt_lifecycle::routes::CAP_RETENTION_ADMIN;
    use ainxt_lifecycle::{HoldScope, LegalHold, Record};
    use ainxt_types::{DataClass, Principal};

    let full = assembled_full();

    // Seed the LIVE served retention store: one legal-HELD record (covered by an open matter), one
    // FLOOR-bound record, one FREE record — all for the same subject. (Pii ships with a non-zero
    // statutory retention floor by default, so a fresh Pii record is floor-bound; the Confidential
    // record is frozen by an explicit legal-hold matter scoped to it.)
    {
        let mut store = full.retention.lock().unwrap();
        store.put(Record::new(
            "held-conf",
            "subject-1",
            DataClass::Confidential,
            0,
        ));
        store.put(Record::new("floor-pii", "subject-1", DataClass::Pii, 0));
        store.put(Record::new("free-int", "subject-1", DataClass::Internal, 0));
        // A litigation-hold matter covering only the subject's Confidential records (§6.2).
        store.add_hold(LegalHold::open(
            "matter-9",
            "legal",
            HoldScope::any()
                .with_subject("subject-1")
                .with_data_class(DataClass::Confidential),
            0,
        ));
    }

    let now = 1_000u64; // well inside the Pii statutory floor and the open Confidential hold

    // Fail-closed: a caller without CAP_RETENTION_ADMIN is refused BEFORE any store lookup (no oracle),
    // and nothing is erased.
    let nobody = Principal::user("intern", &[]);
    assert_eq!(
        full.erase_subject_attested(&nobody, "subject-1", now)
            .unwrap_err(),
        ainxt_lifecycle::routes::RetentionRouteError::NotAuthorized
    );
    assert!(full.retention.lock().unwrap().get("held-conf").is_some());

    // The authorized DPO runs the erasure THROUGH §6 precedence and receives a redact-with-attestation.
    let dpo = Principal::user("dpo", &[CAP_RETENTION_ADMIN]);
    let att = full.erase_subject_attested(&dpo, "subject-1", now).unwrap();

    // The FREE record is hard-erased; the held + floored records are PRESERVED (never hard-deleted
    // under hold) and attested as deferred-with-record.
    assert_eq!(att.hard_erased(), &["free-int".to_string()]);
    let preserved: Vec<&str> = att
        .preserved_under_hold()
        .iter()
        .map(|d| d.record_id.as_str())
        .collect();
    assert!(
        preserved.contains(&"held-conf"),
        "a legal-held record must be preserved, not deleted: {preserved:?}"
    );
    assert!(
        preserved.contains(&"floor-pii"),
        "a floor-bound record must be preserved, not deleted: {preserved:?}"
    );
    assert!(
        att.preserved_under_hold().iter().all(|d| d
            .notice
            .contains("honored to the extent legally permissible")),
        "each deferral carries the DPDP 'honored to the extent legally permissible' notice"
    );

    // The held/floored records SURVIVE in the LIVE store; the free one is gone (never-hard-delete-under-hold).
    {
        let store = full.retention.lock().unwrap();
        assert!(
            store.get("held-conf").is_some(),
            "legal-held record must NOT be hard-deleted under hold"
        );
        assert!(
            store.get("floor-pii").is_some(),
            "floor-bound record must NOT be hard-deleted"
        );
        assert!(
            store.get("free-int").is_none(),
            "the free record must be hard-erased"
        );
    }

    // The attestation is tamper-evident: it self-verifies, but altering any field breaks the digest.
    assert!(att.verify(), "a freshly issued attestation must verify");
    let mut tampered = att.clone();
    tampered.tick = 999_999;
    assert!(
        !tampered.verify(),
        "tampering with the attestation must break its content hash"
    );

    // The attestation round-trips serde (the wire artifact the regulator/DPO receives).
    let json = serde_json::to_string(&att).unwrap();
    let back: ainxt_lifecycle::ErasureAttestation = serde_json::from_str(&json).unwrap();
    assert!(back.verify());
    assert_eq!(back, att);
}

#[tokio::test(flavor = "multi_thread")]
async fn r9_served_evidence_export_and_auditor_mode() {
    use ainxt_incident::evidence::{
        AuditorScope, EvidenceExportRequest, EvidenceRouteError, NtpAttestation,
    };
    use ainxt_incident::IncidentClass;
    use ainxt_types::{DataClass, Principal};

    let full = assembled_full();

    // Open two incidents on the LIVE served register via the typed detector seams (gap 3 feeds gap 2):
    // one personal-data-breach (compliance-egress) and one outsourced-service-disruption (serving-ops).
    let pii_id = full.arm_compliance_egress_incident(100, DataClass::Pii, 3);
    let ops_id = full.arm_serving_ops_incident(200, "route-x");

    let req = |incident_id: &str| EvidenceExportRequest {
        incident_id: incident_id.to_string(),
        runtime_version: "ainxt-runtime/9.0.0".into(),
        production_method: "append-only SHA-256 hash-chained Event Log".into(),
        ntp: NtpAttestation {
            source: "nic-ntp-pool".into(),
            last_sync_offset_ms: 8,
            within_threshold: true,
        },
        export_tick: 500,
    };

    // An admin WITHOUT the explicit AUDITOR_CAP is refused (least-privilege, §8.3) on BOTH surfaces.
    let admin = Principal::admin("root");
    assert_eq!(
        full.export_incident_evidence(&admin, &AuditorScope::All, &req(&pii_id))
            .unwrap_err(),
        EvidenceRouteError::NotAuthorized
    );
    assert!(matches!(
        full.auditor_list_incidents(&admin, AuditorScope::All, 300),
        Err(ainxt_incident::evidence::AuditorError::Unauthorized(_))
    ));

    // An empanelled examiner scoped ONLY to personal-data-breach incidents.
    let examiner = Principal::user("rbi-examiner", &["incident:supervisory-auditor"]);
    let scope = AuditorScope::Classes(vec![IncidentClass::PersonalDataBreach]);

    // In-scope §63 export succeeds: certificate particulars auto-filled, signatures blank, self-verifies,
    // and the examiner is the first custody hop.
    let export = full
        .export_incident_evidence(&examiner, &scope, &req(&pii_id))
        .unwrap();
    let cert = &export.certificate;
    assert_eq!(cert.record_set_id, pii_id);
    assert_eq!(cert.runtime_version, "ainxt-runtime/9.0.0");
    assert!(cert.integrity_verified);
    assert!(
        !cert.is_signed(),
        "the §63 draft leaves both human signatures blank"
    );
    assert!(export.reverify());
    // GAP-FIX regulated-fi-responsible-lifecycle — `EvidentiaryExport::reverify` had zero callers
    // outside its own crate's tests; a recipient who received this export earlier has a served way to
    // re-check it wasn't tampered with in transit/storage.
    assert!(
        full.reverify_evidence_export(&export),
        "the served passthrough must agree: intact"
    );
    // Tamper by inserting an extra event not covered by the certificate's record-hash list — a
    // length mismatch `reverify` must catch (a real tamper: a record added/removed post-export).
    let mut tampered_export = export.clone();
    if let Some(extra) = tampered_export.events.first().cloned() {
        tampered_export.events.push(extra);
    }
    assert!(
        !full.reverify_evidence_export(&tampered_export),
        "the served passthrough must catch a tampered export"
    );
    assert_eq!(export.custody.hops[0].actor, "rbi-examiner");

    // Out-of-scope incident is indistinguishable from not-found (existence-hiding).
    assert_eq!(
        full.export_incident_evidence(&examiner, &scope, &req(&ops_id))
            .unwrap_err(),
        EvidenceRouteError::OutOfScopeOrUnknown
    );

    // The read-only auditor listing is scoped + existence-hiding: the in-scope incident appears, the
    // out-of-scope one never does.
    let ids = full.auditor_list_incidents(&examiner, scope, 300).unwrap();
    assert!(
        ids.contains(&pii_id),
        "in-scope incident must be visible to the auditor"
    );
    assert!(
        !ids.contains(&ops_id),
        "out-of-scope incident must NOT leak in the auditor listing"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn r9_more_than_quality_breaker_feeds_register() {
    use ainxt_incident::IncidentClass;
    use ainxt_types::DataClass;

    let full = assembled_full();
    let before = full.incidents.lock().unwrap().incidents().count();

    // FOUR distinct detection sources — none of them the quality circuit-breaker — each arm a clock on
    // the LIVE served register via its typed IncidentCandidate adapter.
    let egress = full.arm_compliance_egress_incident(100, DataClass::Pii, 42);
    let sink = full.arm_sink_guard_incident(110, "durable-event-log");
    let pay = full.arm_payment_boundary_incident(120, "initiate-settlement-x");
    let serving = full.arm_serving_ops_incident(130, "route-critical");

    let reg = full.incidents.lock().unwrap();
    assert_eq!(
        reg.incidents().count(),
        before + 4,
        "all four typed detectors must open an incident on the served register"
    );

    // The typed adapters map to the correct fail-safe incident classes (proves these are the REAL typed
    // sources, not one generic candidate) — MORE than the quality breaker feeds the register.
    assert_eq!(
        reg.incident(&egress).unwrap().class,
        IncidentClass::PersonalDataBreach
    );
    assert_eq!(
        reg.incident(&sink).unwrap().class,
        IncidentClass::CyberSecurityIncident
    );
    assert_eq!(
        reg.incident(&pay).unwrap().class,
        IncidentClass::AgentSettlementAction
    );
    assert_eq!(
        reg.incident(&serving).unwrap().class,
        IncidentClass::OutsourcedServiceDisruption
    );

    // A personal-data-breach arms statutory clocks (DPDP), and the tamper-evident chain still verifies.
    assert!(
        !reg.armed_clocks(130).is_empty(),
        "the compliance-egress breach must arm statutory clocks"
    );
    assert!(
        reg.verify().is_ok(),
        "the served register's hash chain verifies after four arms"
    );
}
