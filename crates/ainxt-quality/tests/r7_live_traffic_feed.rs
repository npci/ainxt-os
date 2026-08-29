// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-7 gap-closing test (eval-tester-scenarios, gap AS) — the **live-traffic-feed seam**.
//!
//! R5 exposed [`OnlineReleaseController`] but a caller still had to hand-roll a per-turn loop and
//! invent the `(served_ref, quality)` stream inline. Nothing named the *source* of that stream, so the
//! controller sitting live in `AppState` (ainxt-runtimed) had no seam a served hook could push into —
//! it was instantiated but never fed. R7 closes that: [`ainxt_quality::feed::LiveTurnFeed`] is the
//! feed seam, [`ReplayFeed`] its deterministic offline implementation, and
//! [`OnlineReleaseController::drive_from_feed`] the single entry point a served hook drives.
//!
//! The production feed is fed by a running served daemon (a hook scores each completed turn and pushes
//! it) → **infra-gated**. This test stands that in with a recorded / pushed stream through the real
//! seams, so the whole online release loop (canary → auto-rollback → drift) is exercised end-to-end
//! offline and replays identically (no clock, no RNG).
//!
//! Fail-before: `ainxt_quality::feed` and `drive_from_feed` did not exist. Pass-after: driving the
//! controller off the feed rolls back a worse candidate during canarying, promotes an established
//! non-inferior candidate, and — post-promotion — rolls it back on a drift change-point.

use ainxt_canary::alwaysvalid::{AlwaysValidCanary, AlwaysValidConfig};
use ainxt_canary::experiment::{Notifier, PointerController};
use ainxt_quality::controller::{OnlineReleaseController, Phase};
use ainxt_quality::feed::{LiveTurnFeed, ObservedTurn, ReplayFeed};
use ainxt_quality::monitor::{Cusum, DriftAction, DriftResponder, SampledDriftMonitor};

// ---- in-memory production-seam doubles (the daemon supplies real git-ref/ticket impls) ----------

struct MemPointer {
    current: String,
    flips: Vec<String>,
}
impl PointerController for MemPointer {
    fn current(&self) -> String {
        self.current.clone()
    }
    fn flip(&mut self, to_ref: &str) -> String {
        let prev = self.current.clone();
        self.current = to_ref.to_string();
        self.flips.push(to_ref.to_string());
        prev
    }
}

#[derive(Default)]
struct MemNotifier(Vec<String>);
impl Notifier for MemNotifier {
    fn notify(&mut self, m: &str) {
        self.0.push(m.to_string());
    }
}

#[derive(Default)]
struct MemResponder {
    tickets: Vec<String>,
    rollbacks: u32,
}
impl DriftResponder for MemResponder {
    fn open_ticket(&mut self, s: &str) {
        self.tickets.push(s.to_string());
    }
    fn rollback_last_good(&mut self) -> bool {
        self.rollbacks += 1;
        true
    }
}

fn controller() -> OnlineReleaseController {
    // Champion baseline 90, non-inferiority margin 2 → floor 88.
    let canary = AlwaysValidCanary::new(AlwaysValidConfig::tuned(90.0, 2.0, 0.05, 100, 500));
    let drift =
        SampledDriftMonitor::new(Cusum::from_sigma(90.0, 3.0, 0.5, 4.0), 1, true, "role@v7");
    OnlineReleaseController::new(canary, drift, "canary", "env/prod-canary", "env/prod")
}

#[test]
fn r7_live_traffic_feed() {
    // ---- (A) a worse candidate, driven ENTIRELY off the feed seam, rolls back during canarying ----
    {
        let mut ctrl = controller();
        let mut ptr = MemPointer {
            current: "env/prod-canary".into(), // canary carried some traffic
            flips: vec![],
        };
        let mut notif = MemNotifier::default();
        let mut resp = MemResponder::default();

        // A RECORDED stream (the offline stand-in for the infra-gated live feed): champion turns
        // (fine) interleaved with candidate turns steady ~78 (clearly below the floor).
        let recorded: Vec<ObservedTurn> = (0..1000)
            .map(|i| {
                if i % 5 < 2 {
                    ObservedTurn::new(
                        "env/prod-canary",
                        78.0 + if i % 2 == 0 { 0.5 } else { -0.5 },
                    )
                } else {
                    ObservedTurn::new("env/prod", 90.0)
                }
            })
            .collect();
        let mut feed = ReplayFeed::new(recorded);

        // ONE call drives the whole loop off the feed until the rollout terminates.
        let steps = ctrl.drive_from_feed(&mut feed, &mut ptr, &mut notif, &mut resp);

        assert!(
            steps.last().map(|s| s.rolled_back()).unwrap_or(false),
            "the driver's final step must be the rollback"
        );
        assert_eq!(ctrl.phase(), Phase::RolledBack);
        assert_eq!(ptr.current(), "env/prod", "pointer returned to champion");
        assert_eq!(notif.0.len(), 1, "a human was notified, not paged");
        assert!(
            feed.remaining() > 0,
            "driver stopped at the terminal decision, not by draining the whole recording"
        );
        // Exactly one terminal step; everything before it is a Hold/Continue.
        assert_eq!(
            steps.iter().filter(|s| s.rolled_back()).count(),
            1,
            "the rollback fires exactly once"
        );
    }

    // ---- (B) a good candidate promotes, then post-promotion drift flips it back — feed-driven -----
    {
        let mut ctrl = controller();
        let mut ptr = MemPointer {
            current: "env/prod".into(),
            flips: vec![],
        };
        let mut notif = MemNotifier::default();
        let mut resp = MemResponder::default();

        // Phase 1 stream: candidate steady ~91 (above floor 88) → establishes non-inferiority.
        let phase1: Vec<ObservedTurn> = (0..900)
            .map(|i| {
                ObservedTurn::new(
                    "env/prod-canary",
                    91.0 + if i % 2 == 0 { 0.3 } else { -0.3 },
                )
            })
            .collect();
        let mut feed = ReplayFeed::new(phase1);
        let steps1 = ctrl.drive_from_feed(&mut feed, &mut ptr, &mut notif, &mut resp);
        // Promotion happens mid-stream; the driver then keeps draining, drift-watching the promoted
        // candidate (Promoted is not terminal) — so a promote step occurred and the phase advanced.
        assert!(
            steps1.iter().any(|s| s.promoted()),
            "an established non-inferior candidate promotes"
        );
        assert_eq!(
            steps1.iter().filter(|s| s.promoted()).count(),
            1,
            "exactly one promotion across the driven stream"
        );
        assert_eq!(ctrl.phase(), Phase::Promoted);
        assert_eq!(
            ptr.current(),
            "env/prod-canary",
            "candidate ref is now live prod"
        );
        assert_eq!(ptr.flips.len(), 1, "exactly one promotion flip so far");

        // Phase 2 stream: quality erodes on the promoted candidate (90 → 72). Model the SERVED HOOK
        // PUSH path — turns are pushed into the feed as they complete, then drained by the driver.
        let mut feed = ReplayFeed::empty();
        for i in 0..300 {
            let q = if i < 20 {
                90.0 + if i % 2 == 0 { 1.0 } else { -1.0 }
            } else {
                72.0 + if i % 2 == 0 { 1.0 } else { -1.0 }
            };
            feed.push_observation("env/prod-canary", q);
        }
        let steps2 = ctrl.drive_from_feed(&mut feed, &mut ptr, &mut notif, &mut resp);

        let last = steps2.last().expect("drift stream produced steps");
        assert!(
            last.rolled_back(),
            "post-promotion drift must roll the candidate back"
        );
        assert!(
            matches!(last.drift_action, DriftAction::TicketedAndRolledBack { .. }),
            "the rollback was drift-driven, not canary-driven: {:?}",
            last.drift_action
        );
        assert_eq!(ctrl.phase(), Phase::RolledBack);
        assert_eq!(
            ptr.current(),
            "env/prod",
            "pointer flipped back to champion after drift"
        );
        assert_eq!(resp.tickets.len(), 1, "a drift ticket was opened");
        assert!(resp.rollbacks >= 1);

        // ---- (C) terminal: re-driving the feed after rollback is a clean no-op --------------------
        let mut after = ReplayFeed::new(vec![ObservedTurn::new("env/prod-canary", 95.0)]);
        let steps3 = ctrl.drive_from_feed(&mut after, &mut ptr, &mut notif, &mut resp);
        assert!(
            steps3.is_empty(),
            "a terminal controller pulls nothing further from the feed"
        );
        assert_eq!(
            after.remaining(),
            1,
            "the untouched turn is left in the feed (no phantom consumption)"
        );
        assert_eq!(ctrl.phase(), Phase::RolledBack);
    }

    // ---- (D) an empty feed is a clean stop (a served hook with nothing buffered yet) --------------
    {
        let mut ctrl = controller();
        let mut ptr = MemPointer {
            current: "env/prod".into(),
            flips: vec![],
        };
        let mut notif = MemNotifier::default();
        let mut resp = MemResponder::default();
        let mut empty = ReplayFeed::empty();
        let steps = ctrl.drive_from_feed(&mut empty, &mut ptr, &mut notif, &mut resp);
        assert!(steps.is_empty(), "no turns → no steps, no panic");
        assert_eq!(
            ctrl.phase(),
            Phase::Canarying,
            "phase unchanged with no feed"
        );
        assert!(ptr.flips.is_empty());
        // The seam is a trait object: confirm dyn dispatch compiles/works through &mut dyn.
        let dynfeed: &mut dyn LiveTurnFeed = &mut empty;
        assert!(dynfeed.next_turn().is_none());
    }
}
