// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R10 — the LIVE breach-clock driver advances the statutory register in the SAME unit as the
//! `india_default` arming budgets.
//!
//! REAL BUG (round-10): `spawn_breach_clock` read `SystemTime::now().as_secs()` and fed those raw
//! Unix-epoch SECONDS straight into `IncidentRegister::tick`. But the `india_default` budgets are
//! MINUTE-scaled (CERT-In 6h = 360 ticks, DPDP-board 72h = 4320). Raw seconds against minute budgets
//! breached every statutory clock 60× early — a 72h DPDP clock at 72 MINUTES. The fix routes the live
//! driver through `ainxt_incident::ticks_from_unix_secs`, and this test pins the boundary end-to-end on
//! the SHIPPED surface: a 72h clock does NOT breach after 72 wall-minutes and DOES after 72 wall-hours.
//!
//! Fail-before / pass-after: with the pre-fix raw-seconds driver, advancing by 90 wall-minutes (5400s)
//! yields tick 5400 > 4320 → the 72h clock is (wrongly) breached and the first assertion fails. With the
//! projection, 90 wall-minutes → tick 90 ≪ 4320 → not breached, and the test passes.

use std::time::{SystemTime, UNIX_EPOCH};

use ainxt_incident::StatutoryClockKind;
use ainxt_runtimed::{assemble_full, assemble_surface, load_layered};
use ainxt_types::DataClass;

fn loaded_with_unique_log() -> ainxt_runtimed::LoadedConfig {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("ainxt-r10-{nanos}"));
    let src = format!(
        "version = 1\n[server]\nevent_log_dir = {:?}\n",
        dir.to_string_lossy()
    );
    load_layered(&[("r10", &src)]).expect("load offline config")
}

#[tokio::test(flavor = "multi_thread")]
async fn r10_breach_clock_unit_matches_arming_budget() {
    // This test exercises the breach clock, not the auth policy. The daemon now REFUSES to assemble
    // on the header-trusting default authenticator unless the deployment states that assumption
    // (R16 critical: "shipped default trusts client-controlled headers"), so state it here.
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let loaded = loaded_with_unique_log();
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat surface");
    let full = assemble_full(&loaded, assembled).expect("assemble fully-wired surface");

    // Open a real regulated-egress (personal-data-breach) incident at wall-clock t0 = 0 on the LIVE
    // served register. The India arming policy arms the DPDP-board (72h = 4320 minute-ticks) clock.
    let id = full.arm_compliance_egress_incident(0, DataClass::Pii, 100);
    {
        let reg = full.incidents.lock().unwrap();
        let clk = reg
            .incident(&id)
            .unwrap()
            .clock(StatutoryClockKind::DpdpBoard)
            .unwrap();
        assert_eq!(
            clk.budget_ticks, 4_320,
            "72h DPDP-board budget is 4320 minute-ticks"
        );
    }

    let board_breached = |now_secs: u64| -> bool {
        // Advance the LIVE breach clock exactly as the background ticker now does (wall-clock seconds
        // projected onto the tick axis), then read the breach view at the SAME projected instant.
        full.advance_breach_clock_at_unix_secs(now_secs);
        let reg = full.incidents.lock().unwrap();
        reg.breached_without_filing(ainxt_incident::ticks_from_unix_secs(now_secs))
            .iter()
            .any(|(_, k)| *k == StatutoryClockKind::DpdpBoard)
    };

    // 90 wall-MINUTES after t0: the 72h clock must NOT be breached. (Pre-fix raw-seconds driver: 5400s
    // → 5400 ticks > 4320 → wrongly breached; this assertion is the fail-before.)
    assert!(
        !board_breached(90 * 60),
        "a 72h DPDP clock must NOT breach after 90 wall-minutes (unit slip = 60× early breach)"
    );

    // 71 wall-HOURS: still under the 72h budget → not breached.
    assert!(
        !board_breached(71 * 3600),
        "a 72h DPDP clock must NOT breach at 71 wall-hours"
    );

    // Just past 72 wall-HOURS: NOW the 72h clock breaches — the correct statutory boundary.
    assert!(
        board_breached(72 * 3600 + 60),
        "a 72h DPDP clock MUST breach just past 72 wall-hours"
    );

    // The evidentiary hash chain still verifies after arming + ticking (tamper-evident).
    assert!(full.incidents.lock().unwrap().verify().is_ok());
}
