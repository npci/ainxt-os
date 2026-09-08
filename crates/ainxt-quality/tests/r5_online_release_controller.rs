// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-5 gap-closing integration test (eval-tester-scenarios):
//!
//! * `r5_online_release_controller` — the online canary + auto-rollback + drift monitor are now
//!   exposed as ONE live-drivable [`ainxt_quality::controller::OnlineReleaseController`]. Before this,
//!   `AlwaysValidCanary`, `drive_pointer`, and `SampledDriftMonitor` were reachable only piecemeal in
//!   their own crate tests — nothing composed them onto a per-turn feed. This test drives the
//!   controller by REPLAYING a recorded stream of live turns (`(served_ref, quality)`), the offline
//!   stand-in for the infra-gated live-traffic feed, through the real seams.
//!
//! Fail-before: `ainxt_quality::controller` did not exist. Pass-after: a worse candidate rolls back
//! during canarying; a good candidate promotes and then, when its quality erodes post-promotion, the
//! drift monitor tickets and the deploy pointer is flipped back to the champion.

use ainxt_canary::alwaysvalid::{AlwaysValidCanary, AlwaysValidConfig};
use ainxt_canary::experiment::{ControllerAction, Notifier, PointerController};
use ainxt_quality::controller::{OnlineReleaseController, Phase};
use ainxt_quality::monitor::{Cusum, DriftAction, DriftResponder, SampledDriftMonitor};

// ---- in-memory production-seam doubles (the parent supplies real git-ref/ticket impls) ----------

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

/// One recorded live turn: which git-ref served it, and its measured quality.
struct Turn {
    served_ref: &'static str,
    quality: f64,
}

fn controller() -> OnlineReleaseController {
    let canary = AlwaysValidCanary::new(AlwaysValidConfig::tuned(90.0, 2.0, 0.05, 100, 500));
    let drift =
        SampledDriftMonitor::new(Cusum::from_sigma(90.0, 3.0, 0.5, 4.0), 1, true, "role@v7");
    OnlineReleaseController::new(canary, drift, "canary", "env/prod-canary", "env/prod")
}

#[test]
fn r5_online_release_controller() {
    // ---- (A) a worse candidate rolls back during canarying -------------------------------------
    {
        let mut ctrl = controller();
        let mut ptr = MemPointer {
            current: "env/prod-canary".into(),
            flips: vec![],
        };
        let mut notif = MemNotifier::default();
        let mut resp = MemResponder::default();

        // Replay: 60% champion turns (fine) interleaved with candidate turns steady ~78 (bad).
        let stream: Vec<Turn> = (0..1000)
            .map(|i| {
                if i % 5 < 2 {
                    Turn {
                        served_ref: "env/prod-canary",
                        quality: 78.0 + if i % 2 == 0 { 0.5 } else { -0.5 },
                    }
                } else {
                    Turn {
                        served_ref: "env/prod",
                        quality: 90.0,
                    }
                }
            })
            .collect();

        let mut rolled = false;
        for t in &stream {
            let step = ctrl.ingest(t.served_ref, t.quality, &mut ptr, &mut notif, &mut resp);
            if step.rolled_back() {
                rolled = true;
                break;
            }
        }
        assert!(rolled, "a clearly-worse candidate must be rolled back");
        assert_eq!(ctrl.phase(), Phase::RolledBack);
        assert_eq!(ptr.current(), "env/prod", "pointer returned to champion");
        assert_eq!(notif.0.len(), 1, "a human was notified, not paged");
    }

    // ---- (B) a good candidate promotes, then post-promotion drift flips it back ----------------
    {
        let mut ctrl = controller();
        let mut ptr = MemPointer {
            current: "env/prod".into(),
            flips: vec![],
        };
        let mut notif = MemNotifier::default();
        let mut resp = MemResponder::default();

        // Phase 1: candidate steady ~91 (above floor 88) → establishes non-inferiority.
        let mut promoted = false;
        for i in 0..900 {
            let q = 91.0 + if i % 2 == 0 { 0.3 } else { -0.3 };
            let step = ctrl.ingest("env/prod-canary", q, &mut ptr, &mut notif, &mut resp);
            if step.promoted() {
                promoted = true;
                break;
            }
        }
        assert!(promoted, "an established non-inferior candidate promotes");
        assert_eq!(ctrl.phase(), Phase::Promoted);
        assert_eq!(
            ptr.current(),
            "env/prod-canary",
            "candidate ref is now live prod"
        );
        assert_eq!(ptr.flips.len(), 1, "exactly one promotion flip so far");

        // Phase 2: quality erodes on the promoted candidate (90 → 72) → drift ticket + rollback flip.
        let mut rolled = false;
        for i in 0..300 {
            let q = if i < 20 {
                90.0 + if i % 2 == 0 { 1.0 } else { -1.0 }
            } else {
                72.0 + if i % 2 == 0 { 1.0 } else { -1.0 }
            };
            let step = ctrl.ingest("env/prod-canary", q, &mut ptr, &mut notif, &mut resp);
            if step.rolled_back() {
                assert!(
                    matches!(step.drift_action, DriftAction::TicketedAndRolledBack { .. }),
                    "the rollback was drift-driven"
                );
                rolled = true;
                break;
            }
        }
        assert!(rolled, "post-promotion drift must roll the candidate back");
        assert_eq!(ctrl.phase(), Phase::RolledBack);
        assert_eq!(
            ptr.current(),
            "env/prod",
            "pointer flipped back to champion after drift"
        );
        assert_eq!(resp.tickets.len(), 1, "a drift ticket was opened");
        assert!(resp.rollbacks >= 1);
        // Terminal: a further turn is a no-op hold.
        let after = ctrl.ingest("env/prod-canary", 95.0, &mut ptr, &mut notif, &mut resp);
        assert_eq!(after.pointer_action, ControllerAction::Hold);
        assert_eq!(after.phase, Phase::RolledBack);
    }
}
