// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX regulated-fi-responsible-lifecycle — `DsarRegister::overdue`/`refresh_overdue` (the
//! SLA-breach sweep: mark every non-terminal DSAR request past its DPDP response deadline) had zero
//! callers outside `ainxt-lifecycle`'s own tests: `AssembledFull::dsar_command` dispatches every
//! per-request DSAR command, but nothing ever swept the SAME served register for requests that
//! crossed their SLA line. Proves the new `AssembledFull::dsar_overdue`/`refresh_overdue_dsars`
//! passthroughs read/mutate the SAME register `dsar_command` writes to.

use std::time::{SystemTime, UNIX_EPOCH};

use ainxt_lifecycle::dsar::DsarKind;
use ainxt_lifecycle::routes::{DsarCommand, CAP_DSAR_OPERATE};
use ainxt_runtimed::{assemble_full, assemble_surface, load_layered, AssembledFull};
use ainxt_types::Principal;

fn assembled_full() -> AssembledFull {
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("ainxt-r-dsar-{nanos}"));
    let src = format!(
        "version = 1\n[server]\nevent_log_dir = {:?}\n",
        dir.to_string_lossy()
    );
    let loaded = load_layered(&[("r", &src)]).expect("load offline config");
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat surface");
    assemble_full(&loaded, assembled).expect("assemble fully-wired surface")
}

#[tokio::test(flavor = "multi_thread")]
async fn r_dsar_overdue_sweep_reflects_the_same_register_dsar_command_writes_to() {
    let full = assembled_full();
    let dpo = Principal::user("dpo", &[CAP_DSAR_OPERATE]);

    full.dsar_command(
        &dpo,
        &DsarCommand::Open {
            id: "d1".into(),
            subject_id: "alice".into(),
            kind: DsarKind::Access,
            sla_ticks: 10,
        },
        0,
    )
    .expect("open DSAR");

    // Well within the SLA window — not overdue yet.
    assert!(full.dsar_overdue(5).is_empty());

    // Past the SLA deadline — `overdue` is a live, read-only view (no mutation needed to see it).
    let overdue_now = full.dsar_overdue(50);
    assert_eq!(overdue_now, vec!["d1".to_string()]);

    // `refresh_overdue_dsars` actually marks it AND reports it was newly marked.
    let newly_marked = full.refresh_overdue_dsars(50);
    assert_eq!(newly_marked, vec!["d1".to_string()]);

    // Idempotent: a second refresh at the same or later tick reports nothing NEWLY overdue.
    assert!(full.refresh_overdue_dsars(60).is_empty());
    // But the request remains in the overdue view either way.
    assert_eq!(full.dsar_overdue(60), vec!["d1".to_string()]);
}
