// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-10 Serving-Ops — the three INFRA-GATED physical-GPU-binding seams for SERVING_OPS.md
//! §3/§4/§5, each proven end-to-end against its deterministic offline reference implementation. The
//! scheduling/placement/health/rollout ALGORITHMS are the pure, already-unit-tested cores; these
//! tests exercise the *seam boundary* (the part that, in production, binds to a live GPU fleet /
//! load-balancer / weight store) through the in-memory offline impls so the sequencing logic is
//! deterministically verifiable with no GPU, no clock, no network.
//!
//! Fail-before: none of `PlacementBinder`/`PlacementReconciler`, `FleetRouter`/`drain_and_replace`,
//! `WeightLoader`/`advance_with_loader` existed — this file would not compile. Pass-after: each seam
//! + its driver converges/actuates/fails-closed exactly as §3/§4/§5 specify.

use ainxt_serving::attestation::TrustTier;
use ainxt_serving::health::{
    CanaryProbe, FleetRouter, HealthConfig, HealthEvent, HealthState, InMemoryFleetRouter,
    ShardGroupId, ShardHealthMonitor,
};
use ainxt_serving::placement::{
    Bin, BinPool, InMemoryPlacementBinder, ModelItem, PlacementBinder, PlacementController,
    PlacementReconciler, ReconcileAction,
};
use ainxt_serving::rollout::{
    AdvanceOutcome, AllowListArtifactVerifier, ArtifactVerifier, InMemoryWeightLoader, LoadError,
    RolloutState, SoakSignal, WeightArtifact, WeightLoader, WeightRollout,
};

// ---------------------------------------------------------------------------
// §3 — GPU bin-packing placement bound onto the fleet via the incremental reconciler
// ---------------------------------------------------------------------------
#[test]
fn r10_placement_reconciler_binds_plan_incrementally_and_idempotently() {
    // Two bins; three models that best-fit-decreasing packs deterministically.
    let pool = BinPool::new(vec![
        Bin::new("gpuA", 100, TrustTier::CcEnclave, "fab0"),
        Bin::new("gpuB", 100, TrustTier::CcEnclave, "fab0"),
    ]);
    let items = vec![
        ModelItem::new("m-large", 70, false),
        ModelItem::new("m-mid", 40, false),
        ModelItem::new("m-small", 20, false),
    ];
    let plan = PlacementController::plan(&pool, &items);
    assert!(
        plan.unplaced.is_empty(),
        "all three must fit across the two bins"
    );

    // The physical binder starts empty (nothing resident on the fleet yet).
    let mut binder = InMemoryPlacementBinder::from_bins(pool.bins());
    assert!(binder.bound_set().is_empty());

    // Rate-limited reconcile: at most ONE move per step. The fleet converges over several steps —
    // never a big-bang re-place (SERVING_OPS.md §3 rate-limited reconciler).
    let mut steps = 0;
    loop {
        let actions = PlacementReconciler::reconcile_step(&mut binder, &plan, &items, 1);
        if actions.is_empty() {
            break;
        }
        assert!(actions.len() <= 1, "rate budget of 1 move must be honored");
        assert!(
            !matches!(actions[0], ReconcileAction::Failed { .. }),
            "a valid plan must never fail to bind: {actions:?}"
        );
        steps += 1;
        assert!(steps <= 8, "must converge, not loop forever");
    }
    assert_eq!(steps, 3, "exactly three binds to converge (one per model)");

    // The fleet now matches the plan exactly: every assigned model bound to its planned bin.
    for a in &plan.assignments {
        assert_eq!(
            binder.bound_bin(&a.model_id).as_deref(),
            Some(a.bin_id.as_str()),
            "{} must be resident on {}",
            a.model_id,
            a.bin_id
        );
    }
    // VRAM accounting is real (not tautological): no bin over its 100u ceiling.
    assert!(binder.used_vram("gpuA") <= 100 && binder.used_vram("gpuB") <= 100);
    assert_eq!(
        binder.used_vram("gpuA") + binder.used_vram("gpuB"),
        70 + 40 + 20
    );

    // Re-driving a converged plan is a pure no-op (idempotent — safe to run on a timer).
    assert!(PlacementReconciler::reconcile_step(&mut binder, &plan, &items, 8).is_empty());

    // Scale-DOWN: drop m-small from the desired set → the reconciler UNBINDS it (frees its VRAM),
    // and does not touch the survivors.
    let shrunk_items = vec![
        ModelItem::new("m-large", 70, false),
        ModelItem::new("m-mid", 40, false),
    ];
    let shrunk = PlacementController::plan(&pool, &shrunk_items);
    let actions = PlacementReconciler::reconcile_step(&mut binder, &shrunk, &shrunk_items, 8);
    assert_eq!(
        actions,
        vec![ReconcileAction::Unbound {
            model: "m-small".into()
        }]
    );
    assert_eq!(binder.bound_bin("m-small"), None);
    assert_eq!(binder.used_vram("gpuA") + binder.used_vram("gpuB"), 70 + 40);
}

// ---------------------------------------------------------------------------
// §4 — multi-GPU shard health drains the live route + promotes an N+1 standby
// ---------------------------------------------------------------------------
struct CorruptProbe;
impl CanaryProbe for CorruptProbe {
    fn probe(&self, _g: &ShardGroupId) -> u64 {
        0xBAD // never matches the golden hash → silent-corruption signal
    }
}

#[test]
fn r10_shard_health_drains_route_and_promotes_standby() {
    let mut mon = ShardHealthMonitor::new(HealthConfig {
        collective_timeout: 100,
        consecutive_miss_threshold: 3,
    });
    let primary = ShardGroupId::new("tp0");
    let standby = ShardGroupId::new("tp0-standby");
    mon.register_group(primary.clone(), 0xC0FFEE);
    mon.add_standby(standby.clone(), 0xC0FFEE);

    // The live balancer routes only the primary to start.
    let mut router = InMemoryFleetRouter::new().with_routed([primary.clone()]);
    assert!(router.is_routed(&primary));
    assert_eq!(router.routed_count(), 1);

    // Liveness is green, but the deterministic canary returns a wrong hash → SuspectCorrupt (the
    // failure invisible to process liveness).
    assert_eq!(mon.record_collective(&primary, 10), HealthEvent::Ok);
    let ev = mon.run_probe(&primary, &CorruptProbe);
    assert_eq!(
        ev,
        HealthEvent::PulledFromPool {
            state: HealthState::SuspectCorrupt
        }
    );

    // Actuate the physical drain-the-group recovery through the FleetRouter seam.
    let out = mon.drain_and_replace(&primary, &mut router);
    assert_eq!(out.drained, primary);
    assert_eq!(out.promoted, Some(standby.clone()));

    // The corrupt group is physically pulled from the balancer; the standby is physically routed —
    // capacity restored, and the corrupt group stays known (for forensics) but non-routable.
    assert!(
        !router.is_routed(&primary),
        "corrupt group pulled from the live route"
    );
    assert!(router.is_routed(&standby), "standby brought online");
    assert_eq!(router.routed_count(), 1);
    assert_eq!(mon.state_of(&primary), Some(HealthState::SuspectCorrupt));
    assert!(mon.routable_groups().contains(&standby));

    // No standby left: a second drain reports the shortfall HONESTLY (promoted: None), never faking
    // recovered capacity.
    let ev2 = mon.run_probe(&standby, &CorruptProbe);
    assert_eq!(
        ev2,
        HealthEvent::PulledFromPool {
            state: HealthState::SuspectCorrupt
        }
    );
    let out2 = mon.drain_and_replace(&standby, &mut router);
    assert_eq!(out2.promoted, None);
    assert!(!router.is_routed(&standby));
    assert_eq!(
        router.routed_count(),
        0,
        "honest zero-capacity, not a hidden shortfall"
    );
}

// ---------------------------------------------------------------------------
// §5 — signed + staged + integrity-verified weight rollout physically bound via WeightLoader
// ---------------------------------------------------------------------------
fn artifact(regulated: bool) -> WeightArtifact {
    WeightArtifact {
        model_id: "qwen-32b".into(),
        version: "v2".into(),
        content_hash: 0xABCDEF,
        signature: "sig-good".into(),
        regulated,
    }
}

#[test]
fn r10_weight_rollout_stages_via_loader_and_fails_closed_on_bad_blob() {
    let verifier: AllowListArtifactVerifier =
        AllowListArtifactVerifier::new().accept_signature("sig-good");
    let mut loader = InMemoryWeightLoader::new().with_incumbent("qwen-32b", "v1");
    let clean = SoakSignal {
        no_regression: true,
        soak_met: true,
        p0_breach_threshold: false,
    };

    // (1) FAIL-CLOSED: a forged signature is refused at the load fence — nothing is staged, no
    //     traffic shifts, the state machine does not advance.
    let mut r = WeightRollout::new();
    let mut forged = artifact(false);
    forged.signature = "sig-forged".into();
    assert_eq!(
        r.advance_with_loader(&forged, &verifier, true, clean, &mut loader),
        Err(LoadError::SignatureInvalid)
    );
    assert_eq!(
        r.state(),
        RolloutState::P2Shadow,
        "state unchanged on a refused load"
    );
    assert_eq!(
        loader.staged_count(),
        0,
        "a forged blob is NEVER staged onto the fleet"
    );
    assert_eq!(
        loader.live_version("qwen-32b").as_deref(),
        Some("v1"),
        "incumbent still live"
    );

    // (2) A verified candidate walks the full ladder; each advance physically stages the version and
    //     shifts that stage's traffic slice onto it.
    let good = artifact(false);
    assert_eq!(
        r.advance_with_loader(&good, &verifier, true, clean, &mut loader),
        Ok(AdvanceOutcome::Advanced {
            to: RolloutState::P2Canary
        })
    );
    assert!(loader.was_staged("qwen-32b", "v2", RolloutState::P2Canary));
    assert_eq!(
        loader.live_version("qwen-32b").as_deref(),
        Some("v2"),
        "candidate now taking traffic"
    );
    assert_eq!(
        r.advance_with_loader(&good, &verifier, true, clean, &mut loader),
        Ok(AdvanceOutcome::Advanced {
            to: RolloutState::P1Canary
        })
    );
    assert_eq!(
        r.advance_with_loader(&good, &verifier, true, clean, &mut loader),
        Ok(AdvanceOutcome::Advanced {
            to: RolloutState::Promoted
        })
    );
    assert!(loader.was_staged("qwen-32b", "v2", RolloutState::Promoted));
    assert_eq!(loader.staged_count(), 3, "staged once per ladder rung");

    // (3) ROLLBACK reverts traffic to the incumbent through the same seam. Restart the rollout and
    //     hit a canary regression → auto-rollback → live traffic returns to v1.
    let mut r2 = WeightRollout::new();
    let regress = SoakSignal {
        no_regression: false,
        soak_met: true,
        p0_breach_threshold: false,
    };
    assert_eq!(
        r2.advance_with_loader(&good, &verifier, true, regress, &mut loader),
        Ok(AdvanceOutcome::AutoRolledBack {
            from: RolloutState::P2Shadow
        })
    );
    assert_eq!(r2.state(), RolloutState::RolledBack);
    assert_eq!(
        loader.live_version("qwen-32b").as_deref(),
        Some("v1"),
        "rollback reverts live traffic to the incumbent via the loader seam"
    );

    // (4) A regulated blob on a NON-attested node is refused at the fence (attestation-bound key) —
    //     fail-closed, nothing staged.
    let mut r3 = WeightRollout::new();
    let before = loader.staged_count();
    assert_eq!(
        r3.advance_with_loader(&artifact(true), &verifier, false, clean, &mut loader),
        Err(LoadError::AttestationKeyUnavailable)
    );
    assert_eq!(
        loader.staged_count(),
        before,
        "no stage without a valid attestation quote"
    );
}

// Keep the shared ArtifactVerifier trait object in the type graph (documents the crypto seam reuse).
#[test]
fn r10_artifact_verifier_is_a_trait_object_seam() {
    let v = AllowListArtifactVerifier::new().accept_signature("s");
    let dynv: &dyn ArtifactVerifier = &v;
    let a = WeightArtifact {
        model_id: "m".into(),
        version: "v".into(),
        content_hash: 1,
        signature: "s".into(),
        regulated: false,
    };
    assert!(dynv.verify_signature(&a));
}
