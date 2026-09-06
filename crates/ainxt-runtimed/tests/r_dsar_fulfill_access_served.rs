// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX regulated-fi-responsible-lifecycle (§4.4 access/portability, FI-09) —
//! `DsarWorkflow::fulfill_access` (and the completeness-checked `DsarRegister::fulfill_access_complete`
//! it delegates to) had ZERO callers anywhere in the served daemon: `AssembledFull::dsar_command`
//! dispatches `Open`/`Authenticate`/`Correct`/`Grievance`/`Erase`, but `DsarCommand` has no variant
//! that can ever FULFIL an `Access`-kind request — a Right-to-Access DSAR could be opened and
//! authenticated on the served `/v1/regfi/dsar` route and then never actually exported. This proves
//! the new `AssembledFull::dsar_fulfill_access` passthrough dispatches through the SAME shared,
//! served DSAR register `dsar_command` writes to, enforces identity-proofing, and enforces FI-09
//! completeness (refusing when a mandated tier has no registered resolver).

use std::time::{SystemTime, UNIX_EPOCH};

use ainxt_lifecycle::dsar::{CompleteLineage, DsarKind};
use ainxt_lifecycle::routes::{DsarCommand, DsarRouteError, CAP_DSAR_OPERATE};
use ainxt_lifecycle::Record;
use ainxt_runtimed::{assemble_full, assemble_surface, load_layered, AssembledFull};
use ainxt_types::{DataClass, Principal};

fn assembled_full() -> AssembledFull {
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("ainxt-r-dsar-access-{nanos}"));
    let src = format!(
        "version = 1\n[server]\nevent_log_dir = {:?}\n",
        dir.to_string_lossy()
    );
    let loaded = load_layered(&[("r", &src)]).expect("load offline config");
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat surface");
    assemble_full(&loaded, assembled).expect("assemble fully-wired surface")
}

#[tokio::test(flavor = "multi_thread")]
async fn r_dsar_fulfill_access_dispatches_through_the_same_served_register() {
    let full = assembled_full();
    // GAP-FIX regulated-fi-responsible-lifecycle (FI-09 RBAC decision) — Access additionally requires
    // `can_approve_dsar_access` (senior/approving actor, `ad_level <= 3` — mirroring the platform's
    // `can_approve` JWT claim) ON TOP OF `CAP_DSAR_OPERATE`; `with_ad_level(2)` makes this DPO qualify.
    let dpo = Principal::user("dpo", &[CAP_DSAR_OPERATE]).with_ad_level(2);

    // A CAP_DSAR_OPERATE-only clerk with no `ad_level` claim (this offline harness has no live claim
    // transport, mirroring the served header/JWT authenticators) is REFUSED — the RBAC decision under
    // test: CAP_DSAR_OPERATE alone is not commensurate with a full cross-tier PII export.
    let junior_clerk = Principal::user("clerk", &[CAP_DSAR_OPERATE]);
    let refused = full.dsar_fulfill_access(
        &junior_clerk,
        "d-access-1",
        &CompleteLineage::with_default_required(),
        true,
        0,
    );
    assert!(
        matches!(refused, Err(DsarRouteError::NotAuthorized)),
        "CAP_DSAR_OPERATE alone must not authorize Access: {refused:?}"
    );

    // A subject with one record in the daemon's SAME shared retention store (`full.retention`) —
    // the exact store the served `/v1/regfi/erasure`/`Erase` path also writes to.
    full.retention
        .lock()
        .unwrap()
        .put(Record::new("rec-1", "alice", DataClass::Internal, 0));

    // Open + authenticate an Access-kind DSAR on the SAME served register `dsar_command` writes to.
    full.dsar_command(
        &dpo,
        &DsarCommand::Open {
            id: "d-access-1".into(),
            subject_id: "alice".into(),
            kind: DsarKind::Access,
            sla_ticks: 100,
        },
        0,
    )
    .expect("open DSAR");
    full.dsar_command(
        &dpo,
        &DsarCommand::Authenticate {
            id: "d-access-1".into(),
            proof_ok: true,
        },
        1,
    )
    .expect("authenticate DSAR");

    // GAP proof 1 — FI-09 fail-closed: a lineage missing a mandated tier REFUSES the fulfilment
    // rather than certifying a best-effort export, and the request stays un-fulfilled.
    let incomplete = CompleteLineage::new(&["lifecycle-store", "dsar-register"]);
    let err = full
        .dsar_fulfill_access(&dpo, "d-access-1", &incomplete, true, 5)
        .expect_err("a lineage missing a mandated tier must be refused");
    assert!(
        matches!(err, DsarRouteError::IncompleteLineage { .. }),
        "got {err:?}"
    );

    // GAP proof 2 — the real entrypoint: register the SAME shared retention store (cloned out from
    // behind its lock) as the `lifecycle-store` tier, satisfying the (custom, smaller) manifest.
    let store_snapshot = full.retention.lock().unwrap().clone();
    let complete = CompleteLineage::new(&["lifecycle-store"])
        .with_named_tier("lifecycle-store", Box::new(store_snapshot));
    let export = full
        .dsar_fulfill_access(&dpo, "d-access-1", &complete, true, 5)
        .expect("a complete lineage must fulfil the access request");
    assert!(export.is_complete(), "every mandated tier was registered");
    assert!(
        export
            .records
            .iter()
            .any(|r| r.tier == "lifecycle-store" && r.record_id == "rec-1"),
        "the subject's real retention-store record must appear in the export: {:?}",
        export.records
    );

    // The fulfilment landed on the SAME shared register `dsar_command` reads: a second fulfilment
    // attempt is refused because the request is already terminal (Fulfilled).
    let again = full.dsar_fulfill_access(&dpo, "d-access-1", &complete, true, 6);
    assert!(matches!(again, Err(DsarRouteError::AlreadyTerminal(_))));

    // Fail-closed on authorization: a principal without CAP_DSAR_OPERATE is refused before any lookup.
    let outsider = Principal::user("nobody", &[]);
    let denied = full.dsar_fulfill_access(&outsider, "d-access-1", &complete, true, 7);
    assert!(matches!(denied, Err(DsarRouteError::NotAuthorized)));
}

// GAP-FIX regulated-fi-responsible-lifecycle (FI-09) — the REAL, hydrated counterpart above:
// `AssembledFull::dsar_fulfill_access_live` had ZERO callers (the whole point of this file's original
// gap), and unlike the test above, requires NO caller-assembled `CompleteLineage` — it hydrates one
// from the daemon's OWN live organs (`full.retention`, `full.dsar`'s own register, `full.incidents`,
// `full.event_log`), proving the daemon can genuinely serve a Right-to-Access DSAR end-to-end without
// a caller having to know about `ainxt_lifecycle::dsar_tiers` at all.
#[tokio::test(flavor = "multi_thread")]
async fn r_dsar_fulfill_access_live_hydrates_the_daemons_own_organs() {
    let full = assembled_full();
    // A full cross-tier export inherently reads the subject's personal memory under break-glass
    // (`ainxt_memory::access::AccessScope::can_see` requires `Role::Admin` for that), so this uses an
    // admin operator — `Role::Admin` also satisfies `can_approve_dsar_access` and `CAP_DSAR_OPERATE` by
    // the same admin-bypass every other cap check in this codebase grants.
    let dpo = Principal::admin("dpo-live");

    // A real record in the daemon's SAME shared retention store.
    full.retention
        .lock()
        .unwrap()
        .put(Record::new("rec-live-1", "alice", DataClass::Internal, 0));

    // A real trace record on the SAME live Event Log this daemon serves `/v1/replay` from.
    full.event_log
        .append("sess-live", "alice", "ask", "hello")
        .expect("append trace");

    full.dsar_command(
        &dpo,
        &DsarCommand::Open {
            id: "d-live-1".into(),
            subject_id: "alice".into(),
            kind: DsarKind::Access,
            sla_ticks: 100,
        },
        0,
    )
    .expect("open DSAR");
    full.dsar_command(
        &dpo,
        &DsarCommand::Authenticate {
            id: "d-live-1".into(),
            proof_ok: true,
        },
        1,
    )
    .expect("authenticate DSAR");

    // RBAC decision applies here too: a CAP_DSAR_OPERATE-only clerk is refused even via the live path.
    let junior_clerk = Principal::user("clerk-2", &[CAP_DSAR_OPERATE]);
    let refused = full.dsar_fulfill_access_live(&junior_clerk, "d-live-1", true, 2);
    assert!(
        matches!(refused, Err(DsarRouteError::NotAuthorized)),
        "got {refused:?}"
    );

    // An unknown request id is refused with UnknownRequest, before any hydration is attempted.
    let unknown = full.dsar_fulfill_access_live(&dpo, "no-such-request", true, 2);
    assert!(
        matches!(unknown, Err(DsarRouteError::UnknownRequest(_))),
        "got {unknown:?}"
    );

    // The REAL, hydrated fulfilment: no caller-supplied lineage, just the daemon's own live organs.
    let export = full
        .dsar_fulfill_access_live(&dpo, "d-live-1", true, 3)
        .expect("live access fulfilment over the daemon's own organs must succeed");
    assert!(
        export.is_complete(),
        "missing tiers: {:?}",
        export.missing_tiers
    );
    assert!(
        export
            .records
            .iter()
            .any(|r| r.tier == "lifecycle-store" && r.record_id == "rec-live-1"),
        "the real retention-store record must appear: {:?}",
        export.records
    );
    assert!(
        export
            .records
            .iter()
            .any(|r| r.tier == "dsar-register" && r.record_id == "d-live-1"),
        "the subject's own DSAR history must appear: {:?}",
        export.records
    );
    assert!(
        export.records.iter().any(|r| r.tier == "traces"),
        "the real event-log trace must appear: {:?}",
        export.records
    );

    // A daemon-level, tamper-evident audit record was appended to the SAME live event log ON TOP OF
    // the hash-chained `DsarAction::AccessExported` event inside the register itself.
    let audit = full.event_log.records("dsar:d-live-1");
    assert!(
        audit
            .iter()
            .any(|r| r.kind == "dsar.access.fulfilled" && r.actor == "dpo-live"),
        "expected a dsar.access.fulfilled audit record: {audit:?}"
    );

    // A second live fulfilment attempt is refused — the request is already terminal (Fulfilled).
    let again = full.dsar_fulfill_access_live(&dpo, "d-live-1", true, 4);
    assert!(
        matches!(again, Err(DsarRouteError::AlreadyTerminal(_))),
        "got {again:?}"
    );

    // Two INDEPENDENT fail-closed layers, proven together: a `can_approve_dsar_access`-qualifying
    // operator who is nonetheless NOT `Role::Admin` (so `ainxt_memory::access::AccessScope::can_see`
    // refuses them break-glass into another subject's personal memory) gets an honestly INCOMPLETE
    // hydration — the memory-derived tiers are correctly left unregistered rather than the daemon
    // fabricating an empty stand-in — so `require_complete=true` REFUSES rather than under-reporting,
    // while `require_complete=false` still returns everything that WAS resolvable.
    let senior_non_admin = Principal::user("dpo-senior-2", &[CAP_DSAR_OPERATE]).with_ad_level(1);
    full.dsar_command(
        &dpo,
        &DsarCommand::Open {
            id: "d-live-2".into(),
            subject_id: "alice".into(),
            kind: DsarKind::Access,
            sla_ticks: 100,
        },
        5,
    )
    .expect("open second DSAR");
    full.dsar_command(
        &dpo,
        &DsarCommand::Authenticate {
            id: "d-live-2".into(),
            proof_ok: true,
        },
        6,
    )
    .expect("authenticate second DSAR");

    let incomplete = full.dsar_fulfill_access_live(&senior_non_admin, "d-live-2", true, 7);
    assert!(
        matches!(incomplete, Err(DsarRouteError::IncompleteLineage { .. })),
        "a can_approve-but-non-admin operator must not silently under-report a full export: {incomplete:?}"
    );

    let partial = full
        .dsar_fulfill_access_live(&senior_non_admin, "d-live-2", false, 7)
        .expect("require_complete=false still returns what WAS resolvable");
    assert!(!partial.is_complete());
    assert!(
        partial
            .records
            .iter()
            .any(|r| r.tier == "lifecycle-store" && r.record_id == "rec-live-1"),
        "non-memory tiers still resolve for a can_approve (non-admin) operator: {:?}",
        partial.records
    );
}
