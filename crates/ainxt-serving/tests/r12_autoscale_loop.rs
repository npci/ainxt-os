// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-12 Serving-Ops gap-7 (LOW) — the §3 demand-autoscale DECISION LOOP: demand EWMA + target
//! replicas + model-parking are composed into a per-tick controller, not just standalone primitives.
//!
//! The audit found bin-packing, the demand EWMA, and the parking registry all existed but nothing
//! composed them into the loop §3 describes (observe demand → recompute target → scale out, or PARK
//! WARM a family whose demand fell — never cold-evict a warm model onto a P0 path). This closes the
//! decision loop ([`AutoscaleController::tick`]); the physical replica provisioning it feeds is the
//! [`PlacementBinder`] infra seam (proven separately in r10).
//!
//! Fail-before: `AutoscaleController`/`ScaleAction` did not exist. Pass-after: sustained demand scales
//! a family out proportionally, a demand collapse parks it WARM (still P0-admissible, not cold), and a
//! P0-floor family never scales to zero.

use ainxt_serving::placement::{AutoscaleController, ParkTier, ScaleAction};

fn scale_to(actions: &[ScaleAction], model: &str) -> Option<u32> {
    actions.iter().find_map(|a| match a {
        ScaleAction::ScaleTo { model_id, replicas } if model_id == model => Some(*replicas),
        _ => None,
    })
}

#[test]
fn r12_autoscale_scales_out_on_demand_and_holds_the_p0_floor() {
    // alpha 0.5, 100 rps/replica, P0 floor of 1 replica.
    let mut ac = AutoscaleController::new(0.5, 100.0, 1);

    // A brand-new family with no demand still gets its P0 floor (never scaled to zero).
    let a = ac.tick(&[("chat-30b".into(), 0.0)]);
    assert_eq!(
        scale_to(&a, "chat-30b"),
        Some(1),
        "P0-floor family holds >= 1 replica"
    );

    // Sustained ~450 rps → 5 replicas at 100 rps each. Feed the EWMA to convergence.
    let mut last = Vec::new();
    for _ in 0..20 {
        last = ac.tick(&[("chat-30b".into(), 450.0)]);
    }
    assert!((ac.demand("chat-30b") - 450.0).abs() < 1.0);
    assert_eq!(
        scale_to(&last, "chat-30b"),
        Some(5),
        "scaled out proportional to demand"
    );
    // The scaled-out family is resident (servable now).
    assert_eq!(ac.parking().tier_of("chat-30b"), ParkTier::Resident);
}

#[test]
fn r12_autoscale_parks_warm_not_cold_when_demand_collapses() {
    // No P0 floor (min_replicas = 0) so an idle family is eligible to be parked.
    let mut ac = AutoscaleController::new(0.9, 100.0, 0);

    // Warm it up under load first.
    for _ in 0..10 {
        ac.tick(&[("batch-embed".into(), 300.0)]);
    }
    assert_eq!(ac.parking().tier_of("batch-embed"), ParkTier::Resident);

    // Demand collapses to zero for many windows → the EWMA decays to ~0 → the family is PARKED WARM.
    let mut acts = Vec::new();
    for _ in 0..20 {
        acts = ac.tick(&[("batch-embed".into(), 0.0)]);
    }
    assert!(
        acts.contains(&ScaleAction::ParkWarm {
            model_id: "batch-embed".into()
        }),
        "collapsed-demand family is parked: {acts:?}"
    );
    // THE PROOF: it is parked WARM (a minutes-scale local re-warm), NOT cold-evicted — so a demand
    // rebound never lands a P0 on a tens-of-minutes cold object-store pull (§3 / gap W).
    assert_eq!(ac.parking().tier_of("batch-embed"), ParkTier::Warm);
    assert!(
        ac.parking().is_p0_admissible("batch-embed"),
        "warm is still fast enough for P0"
    );
}
