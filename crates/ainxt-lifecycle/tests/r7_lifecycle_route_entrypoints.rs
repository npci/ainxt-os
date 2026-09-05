// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R7 — route-ready entrypoints for the data-lifecycle surface: the §4.4 DSAR workflow
//! ([`DsarWorkflow`]) and the §6 retention / legal-hold / deferred-erasure precedence store
//! ([`RetentionService`]). These integration tests exercise the *route-ready* seam (cap gate + serde
//! request/outcome + shared store) end-to-end, offline. Fail-before: the `routes` module did not
//! exist. Pass-after: the entrypoints dispatch, enforce RBAC, and thread §6 precedence through DSAR
//! erasure — all serde-round-trippable.

use ainxt_lifecycle::routes::{
    can_approve_dsar_access, DsarCommand, DsarOutcome, DsarRouteError, DsarWorkflow,
    RetentionCommand, RetentionOutcome, RetentionService, CAP_DSAR_OPERATE, CAP_RETENTION_ADMIN,
};
use ainxt_lifecycle::{HoldScope, LegalHold, RetentionPolicy};

use ainxt_types::{DataClass, Principal};

fn dpo() -> Principal {
    Principal::user("dpo", &[CAP_DSAR_OPERATE, CAP_RETENTION_ADMIN])
}

#[test]
fn r7_dsar_workflow_route_ready_dispatch_and_rbac() {
    // A caller lacking the DSAR capability is refused BEFORE any state is touched (no oracle).
    let mut wf = DsarWorkflow::new();
    let mut retention = RetentionService::new();
    let nobody = Principal::user("intern", &[]);
    let open = DsarCommand::Open {
        id: "d1".into(),
        subject_id: "alice".into(),
        kind: ainxt_lifecycle::dsar::DsarKind::Erasure,
        sla_ticks: 100,
    };
    assert_eq!(
        wf.handle(&nobody, &open, retention.store_mut(), None, 0)
            .unwrap_err(),
        DsarRouteError::NotAuthorized
    );
    // Nothing was opened.
    assert!(wf.register().request("d1").is_none());

    // The authorized DPO drives the full workflow: open → authenticate → erase.
    let p = dpo();
    // Seed the shared retention store: one held record, one erasable record for the subject.
    retention
        .handle(
            &p,
            &RetentionCommand::SetPolicy {
                policy: RetentionPolicy::new(DataClass::Internal, 10_000),
            },
            0,
        )
        .unwrap();
    {
        let store = retention.store_mut();
        store.put(ainxt_lifecycle::Record::new(
            "r_free",
            "alice",
            DataClass::Internal,
            5,
        ));
        store.put(ainxt_lifecycle::Record::new(
            "r_held",
            "alice",
            DataClass::Internal,
            0,
        ));
    }
    // A legal-hold matter covers only r_held (created at tick 0).
    retention
        .handle(
            &p,
            &RetentionCommand::OpenHold {
                hold: LegalHold::open(
                    "matter-7",
                    "legal",
                    HoldScope::any()
                        .with_subject("alice")
                        .with_created_range(Some(0), Some(0)),
                    0,
                ),
            },
            0,
        )
        .unwrap();

    // open + authenticate return a Receipt carrying the request snapshot.
    let out = wf
        .handle(&p, &open, retention.store_mut(), None, 0)
        .unwrap();
    assert!(matches!(out, DsarOutcome::Receipt { .. }));
    wf.handle(
        &p,
        &DsarCommand::Authenticate {
            id: "d1".into(),
            proof_ok: true,
        },
        retention.store_mut(),
        None,
        1,
    )
    .unwrap();

    // Erasure runs THROUGH §6 precedence: the held record is deferred-with-record, the free one erased.
    let out = wf
        .handle(
            &p,
            &DsarCommand::Erase { id: "d1".into() },
            retention.store_mut(),
            None,
            5,
        )
        .unwrap();
    match out {
        DsarOutcome::Erasure {
            request,
            resolution,
        } => {
            assert_eq!(resolution.erased, vec!["r_free".to_string()]);
            assert_eq!(resolution.deferred.len(), 1);
            assert_eq!(resolution.deferred[0].record_id, "r_held");
            assert!(resolution.deferred[0]
                .notice
                .contains("honored to the extent legally permissible"));
            // The DSAR is recorded fulfilled (answered with deferral).
            assert_eq!(request.status, ainxt_lifecycle::dsar::DsarStatus::Fulfilled);
        }
        other => panic!("expected Erasure outcome, got {other:?}"),
    }

    // The held record survives the "forget everything"; the free one is gone.
    assert!(retention.store().get("r_held").is_some());
    assert!(retention.store().get("r_free").is_none());
    // The DSAR register's hash chain still verifies after route-driven fulfilment.
    assert!(wf.register().verify().is_ok());

    // The command + outcome round-trip serde (wire body ↔ struct).
    let json = serde_json::to_string(&open).unwrap();
    let back: DsarCommand = serde_json::from_str(&json).unwrap();
    assert_eq!(back, open);
}

#[test]
fn r7_retention_precedence_route_ready_release_fires_deferred() {
    // The §6 precedence store as a route-ready service: request-erasure inside a hold defers; a later
    // release + run-deferred fires it — all through the dispatch entrypoint, RBAC-gated.
    let p = dpo();
    let mut svc = RetentionService::new();

    // Unauthorized principal is refused.
    let nobody = Principal::user("intern", &[]);
    assert_eq!(
        svc.handle(&nobody, &RetentionCommand::Purge, 0)
            .unwrap_err(),
        ainxt_lifecycle::routes::RetentionRouteError::NotAuthorized
    );

    svc.handle(
        &p,
        &RetentionCommand::SetPolicy {
            policy: RetentionPolicy::new(DataClass::Confidential, 10_000),
        },
        0,
    )
    .unwrap();
    svc.store_mut().put(ainxt_lifecycle::Record::new(
        "doc",
        "dave",
        DataClass::Confidential,
        0,
    ));
    svc.handle(
        &p,
        &RetentionCommand::OpenHold {
            hold: LegalHold::open("m", "legal", HoldScope::any().with_subject("dave"), 0),
        },
        0,
    )
    .unwrap();

    // Erasure while held → deferred, not erased.
    match svc
        .handle(
            &p,
            &RetentionCommand::RequestErasure {
                subject_id: "dave".into(),
            },
            10,
        )
        .unwrap()
    {
        RetentionOutcome::Erasure { resolution } => {
            assert!(resolution.erased.is_empty());
            assert_eq!(resolution.deferred.len(), 1);
        }
        other => panic!("expected Erasure, got {other:?}"),
    }
    assert!(svc.store().get("doc").is_some());

    // Running the queue while held fires nothing.
    match svc.handle(&p, &RetentionCommand::RunDeferred, 11).unwrap() {
        RetentionOutcome::Fired { ids } => assert!(ids.is_empty()),
        other => panic!("expected Fired, got {other:?}"),
    }

    // Release the matter, then run the queue → the deferred erasure fires.
    match svc
        .handle(
            &p,
            &RetentionCommand::ReleaseHold {
                matter_id: "m".into(),
            },
            12,
        )
        .unwrap()
    {
        RetentionOutcome::Released { released } => assert!(released),
        other => panic!("expected Released, got {other:?}"),
    }
    match svc.handle(&p, &RetentionCommand::RunDeferred, 13).unwrap() {
        RetentionOutcome::Fired { ids } => assert_eq!(ids, vec!["doc".to_string()]),
        other => panic!("expected Fired, got {other:?}"),
    }
    assert!(svc.store().get("doc").is_none());

    // The service serializes for durable persistence and reloads intact.
    let json = serde_json::to_string(&svc).unwrap();
    let back: RetentionService = serde_json::from_str(&json).unwrap();
    assert!(back.store().get("doc").is_none());
}

// GAP-FIX regulated-fi-responsible-lifecycle (FI-09) — the missing `DsarCommand::Access` variant, its
// extra `can_approve_dsar_access` RBAC gate (on top of `CAP_DSAR_OPERATE`), and dispatch through a REAL
// cross-tier lineage assembled by `ainxt_lifecycle::dsar_tiers::hydrate_default_lineage` (the same pure
// function the served `ainxt-server`/`ainxt-runtimed` callers use) — proven end-to-end offline.
#[test]
fn r7_dsar_access_variant_enforces_can_approve_and_resolves_real_tiers() {
    use ainxt_incident::{ArmingPolicy, IncidentRegister};
    use ainxt_lifecycle::dsar::DsarKind;
    use ainxt_lifecycle::dsar_tiers::hydrate_default_lineage;
    use ainxt_lifecycle::Record;
    use ainxt_memory::access::AccessScope;
    use ainxt_memory::store::InMemoryStore;
    use ainxt_memory::{MemoryItem, MemoryKind, Provenance};

    // A REAL memory-fabric export for the subject (not a stand-in) — written through the real store
    // and pulled back via its DPDP `export_subject`, so the four memory-derived tiers resolve actual
    // records rather than being left unregistered.
    let mut mem_store = InMemoryStore::new();
    mem_store
        .write_as(
            MemoryItem::new(
                "e1",
                MemoryKind::Episodic,
                ainxt_memory::Scope::User("alice".into()),
                "run outcome",
                "resolved a ticket",
                Provenance::flywheel(0.9),
            ),
            &AccessScope::from_principal(Principal::user("alice", &[])),
        )
        .unwrap();
    let memory_export = mem_store
        .export_subject(
            "alice",
            &AccessScope::from_principal(Principal::admin("dpo-2"))
                .with_break_glass("DSAR access d1"),
        )
        .unwrap();

    // A junior clerk: CAP_DSAR_OPERATE (so has_cap passes handle's top-level gate) but no `ad_level`
    // claim and not Admin — fails `can_approve_dsar_access`.
    let junior_clerk = Principal::user("clerk-1", &[CAP_DSAR_OPERATE]);
    assert!(!can_approve_dsar_access(&junior_clerk));
    // A senior DPO: CAP_DSAR_OPERATE + ad_level 2 (<= 3) — passes.
    let senior_dpo = Principal::user("dpo-2", &[CAP_DSAR_OPERATE]).with_ad_level(2);
    assert!(can_approve_dsar_access(&senior_dpo));
    // A junior-ad_level but Admin-role principal still passes (Role::Admin bypass, same as has_cap).
    assert!(can_approve_dsar_access(&Principal::admin("root")));
    // ad_level exactly at the boundary (3) passes; one past it (4) does not.
    assert!(can_approve_dsar_access(
        &Principal::user("boundary", &[]).with_ad_level(3)
    ));
    assert!(!can_approve_dsar_access(
        &Principal::user("over-boundary", &[]).with_ad_level(4)
    ));

    let mut wf = DsarWorkflow::new();
    let mut retention = ainxt_lifecycle::RecordStore::new();
    retention.put(Record::new("r1", "alice", DataClass::Internal, 0));

    wf.handle(
        &senior_dpo,
        &DsarCommand::Open {
            id: "d1".into(),
            subject_id: "alice".into(),
            kind: DsarKind::Access,
            sla_ticks: 1_000,
        },
        &mut retention,
        None,
        0,
    )
    .unwrap();
    wf.handle(
        &senior_dpo,
        &DsarCommand::Authenticate {
            id: "d1".into(),
            proof_ok: true,
        },
        &mut retention,
        None,
        1,
    )
    .unwrap();

    // Assemble a REAL, complete cross-tier lineage (no test doubles standing in for tiers) via the
    // SAME pure function the served daemon uses.
    let incidents = IncidentRegister::new(ArmingPolicy::new());
    let lineage = hydrate_default_lineage(
        &retention,
        wf.register(),
        &incidents,
        &[],
        "alice",
        Vec::new(),
        Some(memory_export),
    );

    // The junior clerk (CAP_DSAR_OPERATE but not can_approve) is REFUSED — the RBAC decision under
    // test: CAP_DSAR_OPERATE alone does not authorize Access.
    let refused = wf
        .handle(
            &junior_clerk,
            &DsarCommand::Access {
                id: "d1".into(),
                require_complete: true,
            },
            &mut retention,
            Some(&lineage),
            2,
        )
        .unwrap_err();
    assert_eq!(refused, DsarRouteError::NotAuthorized);
    // Nothing was mutated by the refused attempt.
    assert_ne!(
        wf.register().request("d1").unwrap().status,
        ainxt_lifecycle::dsar::DsarStatus::Fulfilled
    );

    // Dispatching Access with NO lineage fails closed with LineageUnavailable, not a panic — even for
    // an otherwise-authorized senior DPO.
    let no_lineage = wf
        .handle(
            &senior_dpo,
            &DsarCommand::Access {
                id: "d1".into(),
                require_complete: true,
            },
            &mut retention,
            None,
            2,
        )
        .unwrap_err();
    assert_eq!(no_lineage, DsarRouteError::LineageUnavailable);

    // The senior DPO's Access dispatch, WITH the real hydrated lineage, succeeds and resolves the
    // subject's lifecycle-store + dsar-register + real episodic-memory record (incident-register is
    // registered but empty in this offline test — no case-file linkage source — still counts toward
    // completeness, since every mandated tier has a resolver).
    let out = wf
        .handle(
            &senior_dpo,
            &DsarCommand::Access {
                id: "d1".into(),
                require_complete: true,
            },
            &mut retention,
            Some(&lineage),
            3,
        )
        .unwrap();
    match out {
        DsarOutcome::AccessExport { request, export } => {
            assert!(
                export.is_complete(),
                "missing tiers: {:?}",
                export.missing_tiers
            );
            assert!(export
                .records
                .iter()
                .any(|r| r.tier == "lifecycle-store" && r.record_id == "r1"));
            assert!(export
                .records
                .iter()
                .any(|r| r.tier == "dsar-register" && r.record_id == "d1"));
            assert!(
                export.records.iter().any(|r| r.tier == "postgres-episodic"),
                "the real episodic memory record must be surfaced: {:?}",
                export.records
            );
            assert_eq!(request.status, ainxt_lifecycle::dsar::DsarStatus::Fulfilled);
        }
        other => panic!("expected AccessExport outcome, got {other:?}"),
    }
    // The hash-chained DSAR register audit trail records the fulfilment and still verifies.
    assert!(wf.register().verify().is_ok());

    // A second Access dispatch is refused — the request is already terminal (Fulfilled).
    let again = wf
        .handle(
            &senior_dpo,
            &DsarCommand::Access {
                id: "d1".into(),
                require_complete: true,
            },
            &mut retention,
            Some(&lineage),
            4,
        )
        .unwrap_err();
    assert_eq!(again, DsarRouteError::AlreadyTerminal("d1".to_string()));

    // The command round-trips serde, including the new variant's default `require_complete`.
    let cmd = DsarCommand::Access {
        id: "d2".into(),
        require_complete: true,
    };
    let json = serde_json::to_string(&cmd).unwrap();
    let back: DsarCommand = serde_json::from_str(&json).unwrap();
    assert_eq!(back, cmd);
    let defaulted: DsarCommand = serde_json::from_str(r#"{"op":"access","id":"d3"}"#).unwrap();
    assert_eq!(
        defaulted,
        DsarCommand::Access {
            id: "d3".into(),
            require_complete: true
        }
    );
}
