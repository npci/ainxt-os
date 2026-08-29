// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX eval-durable-stores — "the eval `durable` module is fully built but the real vault stays
//! in-memory".
//!
//! `ainxt-eval/src/durable.rs`'s `FileVaultStore` (a durable, file-backed, tamper-evident
//! [`ainxt_eval::vault::VaultStore`]) was fully implemented and unit-tested in its OWN crate
//! (`ainxt-eval/tests/r12_durable_data_plane_stores.rs`), but had zero callers anywhere in the
//! workspace outside that test before this fix — `AssembledFull::vault`
//! (`ainxt_eval::vault::RegressionVault`, constructed at `assemble_full_with_control_plane`) stayed
//! purely in-memory no matter how the daemon was configured, despite `admit_promotion` minting a real
//! permanent regression case into it on every live quality-circuit-breaker trip (the SAME mechanism the
//! sibling test `gap5_quality_breaker_trip_files_eval_regression_scenario.rs` proves). A daemon restart
//! silently lost every regression case a trip ever minted.
//!
//! This test drives the REAL composition root (`assemble_surface` → `assemble_full`, `main.rs`'s own
//! composition path) with `[server] eval_durable_dir` CONFIGURED, mints a real `VaultCase` by tripping
//! the SAME quality circuit-breaker `admit_promotion` gates on (an unmonitored `RegulatedPayment`
//! route — identical fixture shape to the sibling proving test), then throws the ENTIRE assembled
//! daemon away and re-assembles a brand-new one against the SAME durable path — proving the case
//! survives an actual "restart" through the real composed path, not merely `FileVaultStore`'s own
//! isolated load/persist round-trip (already proven in its crate test).

use ainxt_eval::vault::VaultOrigin;
use ainxt_responsibleai::dpia::PromotionTarget;
use ainxt_responsibleai::{
    DueDiligenceConfig, ModelProvenance, ModelRiskRecord, RiskClass, ValidationStatus,
};
use ainxt_runtimed::{assemble_full, assemble_surface, load_layered, PromotionAdmission};
use ainxt_types::DataClass;
use std::time::{SystemTime, UNIX_EPOCH};

/// A fresh, unique durable directory per test run (never shared across tests / accidental reruns).
fn unique_durable_dir(tag: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "ainxt-gap6-eval-durable-vault-{tag}-{}-{nanos}",
        std::process::id()
    ))
}

/// Assemble the REAL, fully-wired composition root (`assemble_surface` → `assemble_full`, the exact
/// path `main.rs` drives) against a config that sets BOTH `event_log_dir` (required — see the sibling
/// test's fixture) and `eval_durable_dir` (the durable Vault path under test) to the SAME parent
/// directory's sub-paths, so re-invoking this with the SAME `dir` reopens the SAME durable state.
fn assembled_full_at(dir: &std::path::Path) -> ainxt_runtimed::AssembledFull {
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let event_log_dir = dir.join("eventlog");
    let vault_dir = dir.join("vault");
    let src = format!(
        "version = 1\n[server]\nevent_log_dir = {:?}\neval_durable_dir = {:?}\n",
        event_log_dir.to_string_lossy(),
        vault_dir.to_string_lossy(),
    );
    let loaded = load_layered(&[("gap6evaldurablevault", &src)]).expect("load offline config");
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat surface");
    assemble_full(&loaded, assembled).expect("assemble fully-wired surface")
}

fn unmonitored_regulated_record(model_id: &str) -> ModelRiskRecord {
    ModelRiskRecord {
        model_id: model_id.to_string(),
        provenance: ModelProvenance::InHouse,
        permitted_data_class: DataClass::RegulatedPayment,
        intended_use: "score settlement anomalies".into(),
        risk_class: RiskClass::High,
        validation: ValidationStatus::IndependentlyValidated { at_tick: 0 },
        challenger: None,
        monitoring: None, // no scoreboard ⇒ the FI-07 quality circuit-breaker trips
        limitations: vec![],
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_regression_case_minted_by_a_real_breaker_trip_survives_a_real_daemon_restart() {
    let dir = unique_durable_dir("basic");

    // ---- "Boot 1": assemble the real daemon with a durable vault path configured, trip the breaker
    // through the REAL `admit_promotion` gate (the same production call path a live promotion request
    // drives), and confirm the case landed in the in-memory vault of THIS instance.
    let route_id = "txn-scorer-cloud-gap6";
    {
        let full = assembled_full_at(&dir);
        let dd = DueDiligenceConfig::default();
        let now = 10_000u64;
        let unmonitored = unmonitored_regulated_record(route_id);

        assert_eq!(
            full.vault.lock().unwrap().len(),
            0,
            "a fresh durable path starts with an empty vault"
        );

        let decision = full.admit_promotion(
            "gap6-restart-route",
            PromotionTarget::Dev,
            &unmonitored,
            &dd,
            now,
        );
        let PromotionAdmission::Refused { .. } = &decision else {
            panic!("an unmonitored regulated route must be refused: {decision:?}");
        };
        assert_eq!(
            full.vault.lock().unwrap().len(),
            1,
            "the real BreakerTrip must mint exactly one vault case on this (first) boot"
        );

        // Sanity: the on-disk durable file now actually exists and holds the record — this is the
        // OBSERVABLE durable side effect `admit_promotion` must have produced via `vault_store`.
        let vault_file = dir.join("vault").join("vault.jsonl");
        assert!(
            vault_file.exists(),
            "admit_promotion must have durably persisted the minted case to disk"
        );
        let contents = std::fs::read_to_string(&vault_file).expect("read durable vault file");
        assert_eq!(
            contents.lines().count(),
            1,
            "exactly one durable record for the one mint"
        );
        assert!(
            contents.contains(route_id),
            "the durable record must reference the tripped route"
        );
    } // `full` (and its whole assembled daemon) is dropped here — simulating a process exit.

    // ---- "Boot 2": assemble an ENTIRELY NEW daemon instance against the SAME durable path (no shared
    // state whatsoever with boot 1's `full` other than the filesystem) — proving restart durability
    // through the REAL composed path, not merely `FileVaultStore`'s own isolated round-trip.
    let full2 = assembled_full_at(&dir);
    assert_eq!(
        full2.vault.lock().unwrap().len(),
        1,
        "a brand-new composition-root instance opened against the SAME durable path must REPLAY the \
         prior boot's minted case back into its live vault — this is the actual gap being closed: \
         before this fix a restart always started at exactly zero, no matter what was configured"
    );
    let survived = full2
        .vault
        .lock()
        .unwrap()
        .cases()
        .iter()
        .find(|c| c.input.contains(route_id))
        .cloned()
        .expect("the case minted before the simulated restart must be present after it");
    assert_eq!(survived.origin, VaultOrigin::CircuitBreaker);
    assert!(
        survived.verify_seal(),
        "the reloaded case must still verify its tamper-evident seal"
    );

    // ---- Boot 2 keeps minting durably too: a SECOND, genuinely new trip (different route) on the
    // reopened instance must both grow the live vault AND append to the SAME durable file — proving
    // `vault_store` was correctly rehydrated (not merely the one-shot in-memory snapshot) on reassembly.
    let dd = DueDiligenceConfig::default();
    let second_route = "txn-scorer-cloud-gap6-second";
    let decision2 = full2.admit_promotion(
        "gap6-restart-route-2",
        PromotionTarget::Dev,
        &unmonitored_regulated_record(second_route),
        &dd,
        10_001,
    );
    assert!(matches!(decision2, PromotionAdmission::Refused { .. }));
    assert_eq!(
        full2.vault.lock().unwrap().len(),
        2,
        "boot 2's own new trip must also mint"
    );
    let contents_after_boot2 =
        std::fs::read_to_string(dir.join("vault").join("vault.jsonl")).unwrap();
    assert_eq!(
        contents_after_boot2.lines().count(),
        2,
        "boot 2's new mint must be durably appended onto the SAME file boot 1 wrote, not a fresh one"
    );

    // ---- "Boot 3": one more fresh assembly proves BOTH cases (minted across two different process
    // lifetimes) survive together — the vault is monotonic across restarts, not just single-shot.
    let full3 = assembled_full_at(&dir);
    assert_eq!(
        full3.vault.lock().unwrap().len(),
        2,
        "a second restart must still see BOTH previously-minted cases"
    );
    assert!(full3.vault.lock().unwrap().contains(&survived.case_id));

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unconfigured_daemon_keeps_the_pre_existing_in_memory_only_behavior() {
    // GAP-FIX eval-durable-stores must be a strictly additive, config-gated wire: a daemon with NO
    // `[server] eval_durable_dir` set must behave EXACTLY as before this fix — in-memory only, no
    // `vault_store`, no file ever created.
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let event_log_dir = std::env::temp_dir().join(format!("ainxt-gap6-eval-nodurable-{nanos}"));
    let src = format!(
        "version = 1\n[server]\nevent_log_dir = {:?}\n",
        event_log_dir.to_string_lossy()
    );
    let loaded = load_layered(&[("gap6evalnodurable", &src)]).expect("load offline config");
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat surface");
    let full = assemble_full(&loaded, assembled).expect("assemble fully-wired surface");

    assert!(
        full.vault_store.is_none(),
        "no eval_durable_dir configured ⇒ no durable store handle"
    );

    let dd = DueDiligenceConfig::default();
    let decision = full.admit_promotion(
        "gap6-no-durable-route",
        PromotionTarget::Dev,
        &unmonitored_regulated_record("no-durable-route"),
        &dd,
        10_000,
    );
    assert!(matches!(decision, PromotionAdmission::Refused { .. }));
    assert_eq!(
        full.vault.lock().unwrap().len(),
        1,
        "in-memory minting still works unchanged"
    );
}
