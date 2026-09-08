// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX serving-ops (SERVING_OPS.md §5, gap 38) — the zero-downtime signed weight-rollout
//! controller (`ainxt_serving::rollout::WeightRollout`) is now wired onto the composition root,
//! mirroring how `r_placement_actuator_wired.rs`/`r_chunked_prefill_wired.rs` close the analogous
//! serving-ops gaps.
//!
//! `WeightRollout` (the fail-closed signature+content-hash+attestation load fence, the staged
//! P2Shadow→P2Canary→P1Canary→P0 promotion ladder, and `observe_live_window`'s real-traffic-driven
//! advance/rollback) was fully implemented and exhaustively unit-tested but had ZERO references in
//! `ainxt-runtimed`/`ainxt-server` — no `ServingConfig` field, no daemon caller — so a deployment had
//! no way to actually enforce a staged rollout on the shipped daemon; the mechanism was library-only.
//! This test proves the fix through the actual composition root:
//!   1. a declared `[serving.rollout]` builds a live `RolloutSurface` that
//!      `AssembledFull::run_rollout_observe_window` drives for real.
//!   2. the fail-closed load fence genuinely refuses a forged signature — nothing is staged.
//!   3. a clean real-traffic window walks the SAME persistent per-model ladder to `Promoted`, and a
//!      regression window auto-rolls-back — reflected in `AssembledFull::rollout_state`.
//!
//! Fail-before: `ServingConfig` had no `rollout` field and `AssembledFull` had no `rollout` field /
//! `run_rollout_observe_window` / `rollout_state` — this file would not compile.

use std::time::{SystemTime, UNIX_EPOCH};

use ainxt_runtimed::{assemble_full, assemble_surface, load_layered, LoadedConfig};
use ainxt_serving::rollout::{
    AdvanceOutcome, LoadError, RolloutState, TrafficWindow, WeightArtifact,
};

fn unique_log_dir(tag: &str) -> String {
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir()
        .join(format!("ainxt-r-rollout-{tag}-{nanos}"))
        .to_string_lossy()
        .into_owned()
}

fn config_with_rollout() -> LoadedConfig {
    let dir = unique_log_dir("on");
    let src = format!(
        "version = 1\n\
         [server]\n\
         event_log_dir = {dir:?}\n\
         [serving]\n\
         [serving.rollout]\n\
         accepted_signatures = [\"sig-good\"]\n\
         regression_threshold = 0.1\n\
         p0_breach_threshold = 0.3\n\
         [[serving.rollout.incumbents]]\n\
         model_id = \"qwen-32b\"\n\
         version = \"v1\"\n"
    );
    load_layered(&[("r-rollout-on", &src)]).expect("load config with rollout")
}

fn default_config() -> LoadedConfig {
    let dir = unique_log_dir("default");
    let src = format!("version = 1\n[server]\nevent_log_dir = {dir:?}\n");
    load_layered(&[("r-rollout-default", &src)]).expect("load default config")
}

fn artifact(signature: &str) -> WeightArtifact {
    WeightArtifact {
        model_id: "qwen-32b".to_string(),
        version: "v2".to_string(),
        content_hash: 0xABCDEF,
        signature: signature.to_string(),
        regulated: false,
    }
}

fn clean_window() -> TrafficWindow {
    TrafficWindow {
        sampled_requests: 1000,
        regression_rate: 0.0,
        soak_elapsed: 100,
        soak_required: 10,
    }
}

fn regressed_window() -> TrafficWindow {
    TrafficWindow {
        sampled_requests: 1000,
        regression_rate: 0.5,
        soak_elapsed: 100,
        soak_required: 10,
    }
}

#[test]
fn r_rollout_config_parses_signatures_thresholds_and_incumbents() {
    let loaded = config_with_rollout();
    let r = loaded
        .serving
        .rollout
        .as_ref()
        .expect("rollout section parsed");
    assert_eq!(r.accepted_signatures, vec!["sig-good".to_string()]);
    assert_eq!(r.regression_threshold, 0.1);
    assert_eq!(r.p0_breach_threshold, 0.3);
    assert_eq!(r.incumbents.len(), 1);
    assert_eq!(r.incumbents[0].model_id, "qwen-32b");
}

#[test]
fn r_rollout_air_gapped_default_wires_no_surface() {
    let loaded = default_config();
    assert!(loaded.serving.rollout.is_none());
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat surface");
    let full = assemble_full(&loaded, assembled).expect("assemble fully-wired surface");
    assert!(
        full.rollout.is_none(),
        "no declared [serving.rollout] ⇒ no surface"
    );
    assert!(full
        .run_rollout_observe_window(&artifact("sig-good"), true, clean_window())
        .is_none());
    assert!(full.rollout_state("qwen-32b").is_none());
}

#[test]
fn r_rollout_wired_fail_closed_fence_refuses_a_forged_signature() {
    let loaded = config_with_rollout();
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat surface");
    let full = assemble_full(&loaded, assembled).expect("assemble fully-wired surface");
    assert!(
        full.rollout.is_some(),
        "declared [serving.rollout] ⇒ surface wired"
    );

    // A signature the deployment never accepted must be refused AT LOAD — nothing staged, state
    // unchanged (still unobserved).
    let forged = artifact("sig-forged");
    let outcome = full
        .run_rollout_observe_window(&forged, true, clean_window())
        .expect("rollout declared ⇒ a call runs");
    assert_eq!(
        outcome,
        Err(LoadError::SignatureInvalid),
        "the REAL load fence ran, not a stub"
    );
    // The model's rollout is auto-registered at the starting stage on first observation, but a
    // refused load must never ADVANCE it past P2Shadow — the fence runs strictly before any state
    // transition, matching `WeightRollout::advance_with_loader`'s own fail-closed-first ordering.
    assert_eq!(
        full.rollout_state("qwen-32b"),
        Some(RolloutState::P2Shadow),
        "a refused load must never advance the staged-promotion ladder"
    );
}

#[test]
fn r_rollout_wired_walks_the_real_ladder_and_auto_rolls_back_on_regression() {
    let loaded = config_with_rollout();
    let assembled = assemble_surface(&loaded, "chat").expect("assemble chat surface");
    let full = assemble_full(&loaded, assembled).expect("assemble fully-wired surface");

    let good = artifact("sig-good");

    // Three clean real-traffic windows walk the SAME persistent per-model ladder to P0.
    let a1 = full
        .run_rollout_observe_window(&good, true, clean_window())
        .unwrap()
        .unwrap();
    assert_eq!(
        a1,
        AdvanceOutcome::Advanced {
            to: RolloutState::P2Canary
        }
    );
    let a2 = full
        .run_rollout_observe_window(&good, true, clean_window())
        .unwrap()
        .unwrap();
    assert_eq!(
        a2,
        AdvanceOutcome::Advanced {
            to: RolloutState::P1Canary
        }
    );
    let a3 = full
        .run_rollout_observe_window(&good, true, clean_window())
        .unwrap()
        .unwrap();
    assert_eq!(
        a3,
        AdvanceOutcome::Advanced {
            to: RolloutState::Promoted
        }
    );

    // The SAME shared surface's state read confirms it — proving `rollout_state` reads the SAME
    // persistent WeightRollout `run_rollout_observe_window` advanced, not a disjoint copy.
    assert_eq!(full.rollout_state("qwen-32b"), Some(RolloutState::Promoted));
    assert_eq!(
        full.rollout_live_version("qwen-32b"),
        Some("v2".to_string()),
        "traffic shifted to v2"
    );

    // A P0-stage regression AT/ABOVE the breach threshold (0.3) auto-rolls-back — real traffic
    // reverts to the declared incumbent (v1), over the SAME shared InMemoryWeightLoader.
    let a4 = full
        .run_rollout_observe_window(&good, true, regressed_window())
        .unwrap()
        .unwrap();
    assert_eq!(
        a4,
        AdvanceOutcome::AutoRolledBack {
            from: RolloutState::Promoted
        }
    );
    assert_eq!(
        full.rollout_state("qwen-32b"),
        Some(RolloutState::RolledBack)
    );
    assert_eq!(
        full.rollout_live_version("qwen-32b"),
        Some("v1".to_string()),
        "a real rollback reverted live traffic to the declared incumbent version"
    );
}
