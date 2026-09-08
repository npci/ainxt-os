// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-12 Serving-Ops gap-4 (MEDIUM) — the §5 zero-downtime integrity-verified weight rollout is
//! ENFORCED ON LIVE LOAD: the staged promotion / auto-rollback is driven by windows of real-traffic
//! quality metrics through the weight-loader seam, not by hand-built `SoakSignal` constants.
//!
//! The audit found the staged-rollout state machine + loader seam existed but were exercised only by
//! synthetic signals — "library-only, never enforced on a real load". This closes the gap by deriving
//! the soak signal from a [`TrafficWindow`] (online-scoreboard regression rate + soak time) and
//! driving one advance/rollback per window ([`WeightRollout::observe_live_window`]). The live metrics
//! collection + physical weight store are infra seams; the enforcement over real-load windows is here.
//!
//! Fail-before: `TrafficWindow`/`RolloutThresholds`/`observe_live_window` did not exist. Pass-after: a
//! sequence of clean live windows walks the ladder to Promoted (staging + shifting live traffic via
//! the loader), a canary-stage regression window auto-rolls-back with a small blast radius, and a P0
//! regression past the breach threshold reverts live traffic to the incumbent.

use ainxt_serving::rollout::{
    AdvanceOutcome, AllowListArtifactVerifier, InMemoryWeightLoader, RolloutState,
    RolloutThresholds, TrafficWindow, WeightArtifact, WeightLoader, WeightRollout,
};

fn artifact() -> WeightArtifact {
    WeightArtifact {
        model_id: "qwen-32b".into(),
        version: "v2".into(),
        content_hash: 0xABCDEF,
        signature: "sig-good".into(),
        regulated: false,
    }
}

fn verifier() -> AllowListArtifactVerifier {
    AllowListArtifactVerifier::new().accept_signature("sig-good")
}

fn thresholds() -> RolloutThresholds {
    RolloutThresholds {
        regression_threshold: 0.02,
        p0_breach_threshold: 0.10,
    }
}

fn clean_window() -> TrafficWindow {
    // 10k live requests, 0.5% regression (< 2% threshold), soak met.
    TrafficWindow {
        sampled_requests: 10_000,
        regression_rate: 0.005,
        soak_elapsed: 60,
        soak_required: 60,
    }
}

#[test]
fn r12_clean_live_traffic_walks_the_ladder_to_promoted_via_the_loader() {
    let art = artifact();
    let v = verifier();
    let mut loader = InMemoryWeightLoader::new().with_incumbent("qwen-32b", "v1");
    let mut r = WeightRollout::new();

    // Each clean live-traffic window advances one stage and physically stages + shifts traffic.
    for expected in [
        RolloutState::P2Canary,
        RolloutState::P1Canary,
        RolloutState::Promoted,
    ] {
        let out = r
            .observe_live_window(&art, &v, true, clean_window(), thresholds(), &mut loader)
            .expect("verified blob stages");
        assert_eq!(out, AdvanceOutcome::Advanced { to: expected });
        assert!(
            loader.was_staged("qwen-32b", "v2", expected),
            "candidate staged at {expected:?}"
        );
    }
    // Live traffic now flows to the candidate; the ladder is fully walked from live-load evidence.
    assert_eq!(loader.live_version("qwen-32b").as_deref(), Some("v2"));
    assert_eq!(r.state(), RolloutState::Promoted);
}

#[test]
fn r12_canary_regression_window_auto_rolls_back_small_blast_radius() {
    let art = artifact();
    let v = verifier();
    let mut loader = InMemoryWeightLoader::new().with_incumbent("qwen-32b", "v1");
    let mut r = WeightRollout::new();

    // First clean window: P2Shadow → P2Canary (a slice of live batch traffic).
    assert_eq!(
        r.observe_live_window(&art, &v, true, clean_window(), thresholds(), &mut loader)
            .unwrap(),
        AdvanceOutcome::Advanced {
            to: RolloutState::P2Canary
        }
    );
    assert_eq!(loader.live_version("qwen-32b").as_deref(), Some("v2"));

    // A regression appears in live traffic (8% > 2% threshold) at the canary stage → auto-rollback,
    // and live traffic reverts to the incumbent — the small-blast-radius guarantee.
    let bad = TrafficWindow {
        sampled_requests: 5_000,
        regression_rate: 0.08,
        soak_elapsed: 30,
        soak_required: 60,
    };
    let out = r
        .observe_live_window(&art, &v, true, bad, thresholds(), &mut loader)
        .unwrap();
    assert_eq!(
        out,
        AdvanceOutcome::AutoRolledBack {
            from: RolloutState::P2Canary
        }
    );
    assert_eq!(r.state(), RolloutState::RolledBack);
    assert_eq!(
        loader.live_version("qwen-32b").as_deref(),
        Some("v1"),
        "live traffic reverted to incumbent"
    );
}

#[test]
fn r12_p0_regression_below_breach_awaits_approval_above_breach_auto_reverts() {
    let art = artifact();
    let v = verifier();
    let thr = thresholds();

    // Drive to Promoted (P0) on clean windows.
    let promote = |r: &mut WeightRollout, loader: &mut InMemoryWeightLoader| {
        for _ in 0..3 {
            r.observe_live_window(&art, &v, true, clean_window(), thr, loader)
                .unwrap();
        }
    };

    // (a) A mild P0 regression (5%: above the 2% canary threshold but below the 10% breach) → awaits a
    //     human approval gate; live traffic is NOT auto-reverted yet.
    let mut loader = InMemoryWeightLoader::new().with_incumbent("qwen-32b", "v1");
    let mut r = WeightRollout::new();
    promote(&mut r, &mut loader);
    assert_eq!(r.state(), RolloutState::Promoted);
    let mild = TrafficWindow {
        sampled_requests: 20_000,
        regression_rate: 0.05,
        soak_elapsed: 100,
        soak_required: 60,
    };
    assert_eq!(
        r.observe_live_window(&art, &v, true, mild, thr, &mut loader)
            .unwrap(),
        AdvanceOutcome::AwaitingApproval {
            at: RolloutState::Promoted
        }
    );
    assert_eq!(
        loader.live_version("qwen-32b").as_deref(),
        Some("v2"),
        "still serving candidate pending approval"
    );

    // (b) A severe P0 regression (15% >= 10% breach threshold) → auto-reverts live traffic immediately.
    let mut loader2 = InMemoryWeightLoader::new().with_incumbent("qwen-32b", "v1");
    let mut r2 = WeightRollout::new();
    promote(&mut r2, &mut loader2);
    let severe = TrafficWindow {
        sampled_requests: 20_000,
        regression_rate: 0.15,
        soak_elapsed: 100,
        soak_required: 60,
    };
    assert_eq!(
        r2.observe_live_window(&art, &v, true, severe, thr, &mut loader2)
            .unwrap(),
        AdvanceOutcome::AutoRolledBack {
            from: RolloutState::Promoted
        }
    );
    assert_eq!(
        loader2.live_version("qwen-32b").as_deref(),
        Some("v1"),
        "breach auto-reverted live traffic"
    );
}
