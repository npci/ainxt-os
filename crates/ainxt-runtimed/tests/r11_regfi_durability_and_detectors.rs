// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R11 — regulated-FI served-surface gap closures on the assembled daemon, fail-before / pass-after:
//!
//! 1. `r11_served_statutory_clock_survives_kill9_and_continues` (§2.3 HIGH; acceptance test 3) — the
//!    shipped daemon exposes durable crash-survival ENTRYPOINTS for the LIVE served statutory register:
//!    an armed clock paged mid-flight is snapshotted through the durable `SnapshotStore` seam, and after
//!    a simulated `kill -9` (a fresh assembled surface) it is RESTORED and CONTINUES from the immutable
//!    `t0` — the already-paged tier is not re-paged, the next tier pages, and the clock still breaches at
//!    the correct boundary (not early). The live crash-atomic backend behind the seam is infra_gated.
//!    Fail-before: `AssembledFull` had no `{snapshot,restore}_incident_register` entrypoint — the served
//!    register was rebuilt cold on every boot.
//!
//! 2. `r11_served_ntp_skew_and_residency_arm_live_register` (§8.1/§8.2; acceptance tests 21,22) — the
//!    daemon exposes served NTP-skew + India-residency intake ENTRYPOINTS that arm a §2 incident on the
//!    LIVE served register: a measured skew beyond threshold and a store resolving outside India each
//!    open a live incident (an in-threshold skew / in-India store does not). The live NTP measurement +
//!    region resolution are infra_gated; the served register intake is wired.
//!    Fail-before: `check_served_ntp_skew` / `verify_served_store_residency` did not exist — the
//!    detectors could not reach the served register.

use ainxt_incident::durable::InMemorySnapshotStore;
use ainxt_incident::ops::{NtpSkewMonitor, ResidencyVerifier};
use ainxt_incident::{EngineEvent, EscalationTier, IncidentRegister, StatutoryClockKind};
use ainxt_runtimed::{assemble_full, assemble_surface, load_layered, AssembledFull, LoadedConfig};
use ainxt_types::DataClass;

fn offline() -> LoadedConfig {
    load_layered(&[("t", "version = 1")]).unwrap()
}

fn full() -> AssembledFull {
    // R16 critical: the daemon now refuses the header-trusting default authenticator unless the
    // deployment states the assumption (see r10_breach_clock_unit.rs) — state it here.
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let assembled = assemble_surface(&offline(), "chat").expect("assemble chat surface");
    assemble_full(&offline(), assembled).expect("assemble fully-wired surface")
}

#[tokio::test(flavor = "multi_thread")]
async fn r11_served_statutory_clock_survives_kill9_and_continues() {
    // A personal-data breach arms the DPDP clocks on the LIVE served register (t0 = tick 0).
    let full1 = full();
    let id = full1.arm_compliance_egress_incident(0, DataClass::Pii, 3);

    // Advance the LIVE breach clock to 50% of the 1440-tick DPDP-data-principal budget (tick 720 =
    // 43_200 wall-clock seconds) — the incident owner is paged.
    let pre = full1.advance_breach_clock_at_unix_secs(720 * 60);
    assert!(
        pre.iter().any(|e| matches!(
            e,
            EngineEvent::Paged {
                tier: EscalationTier::IncidentOwner,
                ..
            }
        )),
        "owner paged at 50% before the crash: {pre:?}"
    );

    // Snapshot the mid-flight register through the durable seam.
    let mut store = InMemorySnapshotStore::new();
    full1
        .snapshot_incident_register(&mut store, serde_json::to_vec)
        .expect("snapshot the served register");

    // "kill -9": a brand-new assembled daemon surface with a COLD register …
    let full2 = full();
    assert!(
        full2.incidents.lock().unwrap().incidents().next().is_none(),
        "a fresh surface starts with no incidents"
    );
    // … restore the served register from the durable store.
    assert!(
        full2
            .restore_incident_register(&store, |b| serde_json::from_slice(b))
            .expect("restore the served register"),
        "a persisted snapshot restores on boot"
    );

    // t0 survived the restart unchanged (the clock did not reset).
    {
        let reg = full2.incidents.lock().unwrap();
        let clk = reg
            .incident(&id)
            .unwrap()
            .clock(StatutoryClockKind::DpdpDataPrincipal)
            .unwrap();
        assert_eq!(clk.t0, 0, "t0 immutable across the crash");
    }

    // Resuming does NOT re-page the owner; the next tier (75% → DPO) pages — the clock continued.
    let resumed = full2.advance_breach_clock_at_unix_secs(1_080 * 60);
    assert!(
        resumed.iter().any(|e| matches!(
            e,
            EngineEvent::Paged {
                tier: EscalationTier::Dpo,
                ..
            }
        )),
        "DPO paged at 75% post-restart: {resumed:?}"
    );
    assert!(
        !resumed.iter().any(|e| matches!(
            e,
            EngineEvent::Paged {
                tier: EscalationTier::IncidentOwner,
                ..
            }
        )),
        "the owner page from before the crash is NOT repeated"
    );

    // Boundary precision preserved: not breached AT the deadline (1440), breached one tick past it.
    {
        let reg = full2.incidents.lock().unwrap();
        assert!(reg.breached_without_filing(1_440).is_empty());
        assert!(reg
            .breached_without_filing(1_441)
            .iter()
            .any(|(_, k)| *k == StatutoryClockKind::DpdpDataPrincipal));
        assert!(
            reg.verify().is_ok(),
            "the restored register still hash-verifies"
        );
    }

    // A cold start (empty durable store) is a no-op, not an error — a first boot does not crash-loop.
    let empty = InMemorySnapshotStore::new();
    assert!(!full2
        .restore_incident_register(&empty, |b| serde_json::from_slice::<IncidentRegister>(b))
        .unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn r11_served_ntp_skew_and_residency_arm_live_register() {
    let full = full();

    let mon = NtpSkewMonitor::new("nic-ntp.gov.in", 100);
    // In-threshold: attestation recorded, NO incident armed.
    let (att_ok, none) = full.check_served_ntp_skew(&mon, 40, 10);
    assert!(att_ok.within_threshold);
    assert_eq!(att_ok.source, "nic-ntp.gov.in");
    assert!(none.is_none());

    // Beyond threshold: a §2 incident is armed on the LIVE served register.
    let (att_bad, some) = full.check_served_ntp_skew(&mon, -350, 20);
    assert!(!att_bad.within_threshold);
    let ntp_id = some.expect("a skew beyond threshold arms a served incident");

    // India-residency: a mis-located store arms; an in-India store does not.
    let verifier = ResidencyVerifier::india();
    let ids = full.verify_served_store_residency(
        &verifier,
        [("eventlog", "ap-south-1"), ("trace-store", "us-east-1")],
        30,
    );
    assert_eq!(ids.len(), 1, "only the non-India store arms an incident");

    // Both detectors landed real incidents on the served register, and it stays tamper-evident.
    let reg = full.incidents.lock().unwrap();
    assert!(
        reg.incident(&ntp_id).is_some(),
        "NTP-skew incident is live on the served register"
    );
    assert!(
        reg.incident(&ids[0]).is_some(),
        "residency incident is live on the served register"
    );
    assert!(reg.verify().is_ok());
}
