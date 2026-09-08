// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! The live-drivable **online release controller** (EVAL_PLATFORM.md §7, gap AS) — one seam that
//! drives the whole post-release safety loop off a stream of live turns.
//!
//! The pieces existed but nothing composed them onto a running feed:
//!
//! * [`ainxt_canary::alwaysvalid::AlwaysValidCanary`] — the anytime-valid (safe-to-peek) decision on
//!   whether a candidate is non-inferior to the established champion;
//! * [`ainxt_canary::experiment::drive_pointer`] — the instant, byte-for-byte git-ref pointer flip that
//!   promotes a winner or rolls a regression back, notifying a human (never paging one);
//! * [`crate::monitor::SampledDriftMonitor`] — the cost-bounded CUSUM that catches quality *eroding
//!   after* a promotion (a silent provider swap, a retrieval-mix shift).
//!
//! [`OnlineReleaseController`] wires them into a single per-turn [`OnlineReleaseController::ingest`]
//! call with a small state machine:
//!
//! 1. **Canarying** — candidate turns accrue into the anytime-valid canary; each turn drives the
//!    pointer. An established regression rolls back immediately (safety-first); an established win
//!    promotes and arms the drift watch.
//! 2. **Promoted** — the candidate is now `env/prod`; every turn feeds the drift monitor. A sustained
//!    downward change-point opens a ticket and (per policy) flips the pointer back to the champion.
//! 3. **RolledBack** — terminal: the candidate is off, further turns are no-ops.
//!
//! The **live-traffic feed** that produces the per-turn `(served_ref, quality)` observations needs a
//! running served daemon (infra-gated); this controller is the seam it drives, and is exercised here
//! end-to-end by *replaying* a recorded stream against in-memory pointer/notifier/responder doubles —
//! deterministic, no RNG/clock, so a rollout replays identically offline.

use crate::feed::LiveTurnFeed;
use crate::monitor::{DriftAction, DriftResponder, SampledDriftMonitor};
use ainxt_canary::alwaysvalid::{AlwaysValidCanary, AvDecision, GateMode};
use ainxt_canary::experiment::{drive_pointer, ControllerAction, Notifier, PointerController};
use serde::{Deserialize, Serialize};

/// The lifecycle phase of a candidate rollout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Phase {
    /// Split live: candidate turns accrue into the anytime-valid canary.
    Canarying,
    /// Candidate promoted to `env/prod`; the drift monitor watches for post-promotion erosion.
    Promoted,
    /// Candidate rolled back to the champion ref — terminal.
    RolledBack,
}

impl Phase {
    pub fn is_terminal(&self) -> bool {
        matches!(self, Phase::RolledBack)
    }
}

/// What the controller did on one live turn.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ControllerStep {
    /// The phase *after* this turn was processed.
    pub phase: Phase,
    /// The deploy-pointer action taken (Hold / Promoted / RolledBack).
    pub pointer_action: ControllerAction,
    /// The drift-monitor action taken (None until Promoted; then per sampled turn).
    pub drift_action: DriftAction,
    /// The canary's cold-start / enforced [`GateMode`] AFTER this turn (EVAL_PLATFORM.md §275) — loud,
    /// structural labeling so a `Hold` during `Canarying` is never mistaken for "the gate is
    /// protecting you" while the candidate is still underpowered. `Enforced` once promoted/rolled-back
    /// (both are themselves established, powered decisions).
    pub gate_mode: GateMode,
}

impl ControllerStep {
    pub fn rolled_back(&self) -> bool {
        self.pointer_action.is_rollback()
    }
    pub fn promoted(&self) -> bool {
        self.pointer_action.is_promote()
    }
    /// A loud advisory warning when the canary is still cold-start/underpowered — `None` once enforced.
    pub fn advisory_warning(&self) -> Option<String> {
        self.gate_mode.warning()
    }
}

/// Drives the online canary → auto-rollback → drift-watch loop off a live-traffic stream.
#[derive(Debug, Clone)]
pub struct OnlineReleaseController {
    canary: AlwaysValidCanary,
    drift: SampledDriftMonitor,
    candidate_arm: String,
    candidate_ref: String,
    champion_ref: String,
    phase: Phase,
}

impl OnlineReleaseController {
    /// Build a controller for one candidate rollout. `canary` decides pre-promotion non-inferiority;
    /// `drift` watches the promoted candidate. `candidate_arm` is a human label for notifications;
    /// `candidate_ref` / `champion_ref` are the git-refs the pointer flips between.
    pub fn new(
        canary: AlwaysValidCanary,
        drift: SampledDriftMonitor,
        candidate_arm: &str,
        candidate_ref: &str,
        champion_ref: &str,
    ) -> Self {
        OnlineReleaseController {
            canary,
            drift,
            candidate_arm: candidate_arm.to_string(),
            candidate_ref: candidate_ref.to_string(),
            champion_ref: champion_ref.to_string(),
            phase: Phase::Canarying,
        }
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// Candidate samples accrued into the anytime-valid canary so far.
    pub fn candidate_samples(&self) -> u64 {
        self.canary.samples()
    }

    /// Ingest one live turn. `served_ref` is the git-ref that actually served it (from the upstream
    /// traffic split); `quality` is its measured 0–100 quality. The pointer/notifier/responder are the
    /// production side-effect seams (git-ref flip, human notification, ticket + rollback).
    ///
    /// * **Canarying**: only *candidate* turns move the decision — they accrue into the canary and
    ///   drive the pointer. A rollback or promote transitions the phase.
    /// * **Promoted**: every turn feeds the drift monitor. A downward change-point tickets and (if the
    ///   monitor is configured to auto-roll-back) flips the pointer back to the champion.
    /// * **RolledBack**: terminal — a no-op that holds the pointer.
    pub fn ingest(
        &mut self,
        served_ref: &str,
        quality: f64,
        pointer: &mut dyn PointerController,
        notifier: &mut dyn Notifier,
        responder: &mut dyn DriftResponder,
    ) -> ControllerStep {
        match self.phase {
            Phase::Canarying => self.step_canarying(served_ref, quality, pointer, notifier),
            Phase::Promoted => self.step_promoted(quality, pointer, notifier, responder),
            Phase::RolledBack => ControllerStep {
                phase: Phase::RolledBack,
                pointer_action: ControllerAction::Hold,
                drift_action: DriftAction::None,
                gate_mode: self.canary.gate_mode(),
            },
        }
    }

    /// Drive the controller off a [`LiveTurnFeed`] until the feed is exhausted OR the rollout reaches
    /// a terminal (RolledBack) phase — whichever comes first. Each pulled turn is applied through the
    /// same per-turn [`ingest`](Self::ingest) path (canary → pointer-flip → drift), using the supplied
    /// production side-effect seams. Returns the steps taken, in order.
    ///
    /// This is the entry point a served hook calls: the daemon pushes each completed, quality-scored
    /// turn into the feed and drains it here (the feed's `next_turn` returning `None` is a clean stop,
    /// so it can be re-driven as more turns arrive). The controller owns no I/O — the feed seam and
    /// the pointer/notifier/responder seams are its only contact with the outside world, so the whole
    /// loop replays identically offline. Wiring the *production* feed onto the served turn handler is
    /// the runtime daemon's concern; this method is the drivable seam it targets.
    pub fn drive_from_feed(
        &mut self,
        feed: &mut dyn LiveTurnFeed,
        pointer: &mut dyn PointerController,
        notifier: &mut dyn Notifier,
        responder: &mut dyn DriftResponder,
    ) -> Vec<ControllerStep> {
        let mut steps = Vec::new();
        while !self.phase.is_terminal() {
            let Some(turn) = feed.next_turn() else { break };
            let step = self.ingest(&turn.served_ref, turn.quality, pointer, notifier, responder);
            let terminal = step.phase.is_terminal();
            steps.push(step);
            if terminal {
                break;
            }
        }
        steps
    }

    fn step_canarying(
        &mut self,
        served_ref: &str,
        quality: f64,
        pointer: &mut dyn PointerController,
        notifier: &mut dyn Notifier,
    ) -> ControllerStep {
        // Champion turns don't move the candidate's confidence sequence — hold.
        if served_ref != self.candidate_ref {
            return ControllerStep {
                phase: Phase::Canarying,
                pointer_action: ControllerAction::Hold,
                drift_action: DriftAction::None,
                gate_mode: self.canary.gate_mode(),
            };
        }
        self.canary.record(quality);
        let decision = self.canary.decide();
        let action = drive_pointer(
            &self.candidate_arm,
            &self.candidate_ref,
            &self.champion_ref,
            &decision,
            pointer,
            notifier,
        );
        // A promote arms the drift watch; a rollback is terminal.
        match &decision {
            AvDecision::Promote { .. } => self.phase = Phase::Promoted,
            AvDecision::Rollback { .. } => self.phase = Phase::RolledBack,
            AvDecision::Continue { .. } => {}
        }
        ControllerStep {
            phase: self.phase,
            pointer_action: action,
            drift_action: DriftAction::None,
            gate_mode: self.canary.gate_mode(),
        }
    }

    fn step_promoted(
        &mut self,
        quality: f64,
        pointer: &mut dyn PointerController,
        notifier: &mut dyn Notifier,
        responder: &mut dyn DriftResponder,
    ) -> ControllerStep {
        let drift_action = self.drift.observe_and_respond(quality, responder);
        // A confirmed downward drift on the promoted candidate: flip the deploy pointer back to the
        // champion using the SAME instant, notify-a-human flip discipline as the pre-promotion path.
        let pointer_action = if let DriftAction::TicketedAndRolledBack { change_point, .. } =
            &drift_action
        {
            self.phase = Phase::RolledBack;
            let rollback = AvDecision::Rollback {
                lower: f64::NEG_INFINITY,
                upper: change_point.statistic,
                reason: format!(
                    "post-promotion quality drift: downward change-point at sampled index {} (stat {:.2})",
                    change_point.at_index, change_point.statistic
                ),
            };
            drive_pointer(
                &self.candidate_arm,
                &self.candidate_ref,
                &self.champion_ref,
                &rollback,
                pointer,
                notifier,
            )
        } else {
            ControllerAction::Hold
        };
        ControllerStep {
            phase: self.phase,
            pointer_action,
            drift_action,
            gate_mode: self.canary.gate_mode(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitor::Cusum;
    use ainxt_canary::alwaysvalid::AlwaysValidConfig;

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
        // Champion baseline 90, margin 2 → floor 88.
        let canary = AlwaysValidCanary::new(AlwaysValidConfig::tuned(90.0, 2.0, 0.05, 100, 500));
        // Drift monitor: sample every promoted turn, auto-rollback, CUSUM around 90.
        let drift =
            SampledDriftMonitor::new(Cusum::from_sigma(90.0, 3.0, 0.5, 4.0), 1, true, "role@v7");
        OnlineReleaseController::new(canary, drift, "canary", "env/prod-canary", "env/prod")
    }

    #[test]
    fn worse_candidate_rolls_back_during_canarying() {
        let mut c = controller();
        let mut ptr = MemPointer {
            current: "env/prod-canary".into(), // canary was live at some traffic
            flips: vec![],
        };
        let mut notif = MemNotifier::default();
        let mut resp = MemResponder::default();
        let mut rolled = false;
        for i in 0..600 {
            let q = 78.0 + if i % 2 == 0 { 0.5 } else { -0.5 };
            let step = c.ingest("env/prod-canary", q, &mut ptr, &mut notif, &mut resp);
            if step.rolled_back() {
                rolled = true;
                break;
            }
        }
        assert!(rolled, "a clearly-worse candidate must roll back");
        assert_eq!(c.phase(), Phase::RolledBack);
        assert_eq!(
            ptr.current(),
            "env/prod",
            "pointer flipped back to champion"
        );
    }

    #[test]
    fn champion_turns_do_not_move_the_decision() {
        let mut c = controller();
        let mut ptr = MemPointer {
            current: "env/prod".into(),
            flips: vec![],
        };
        let mut notif = MemNotifier::default();
        let mut resp = MemResponder::default();
        for _ in 0..1000 {
            let step = c.ingest("env/prod", 10.0, &mut ptr, &mut notif, &mut resp);
            assert_eq!(step.pointer_action, ControllerAction::Hold);
        }
        assert_eq!(c.candidate_samples(), 0, "champion turns are not recorded");
        assert_eq!(c.phase(), Phase::Canarying);
    }

    #[test]
    fn good_candidate_promotes_then_drift_rolls_back() {
        let mut c = controller();
        let mut ptr = MemPointer {
            current: "env/prod".into(),
            flips: vec![],
        };
        let mut notif = MemNotifier::default();
        let mut resp = MemResponder::default();

        // Phase 1: a strong candidate (~91, floor 88) establishes non-inferiority → promote.
        let mut promoted = false;
        for i in 0..900 {
            let q = 91.0 + if i % 2 == 0 { 0.3 } else { -0.3 };
            let step = c.ingest("env/prod-canary", q, &mut ptr, &mut notif, &mut resp);
            if step.promoted() {
                promoted = true;
                break;
            }
        }
        assert!(promoted, "an established non-inferior candidate promotes");
        assert_eq!(c.phase(), Phase::Promoted);
        assert_eq!(
            ptr.current(),
            "env/prod-canary",
            "candidate ref is now live"
        );

        // Phase 2: post-promotion, quality erodes (90 → 72) → drift ticket + pointer flip back.
        let mut rolled = false;
        for i in 0..300 {
            let q = if i < 20 {
                90.0 + if i % 2 == 0 { 1.0 } else { -1.0 }
            } else {
                72.0 + if i % 2 == 0 { 1.0 } else { -1.0 }
            };
            let step = c.ingest("env/prod-canary", q, &mut ptr, &mut notif, &mut resp);
            if step.rolled_back() {
                assert!(matches!(
                    step.drift_action,
                    DriftAction::TicketedAndRolledBack { .. }
                ));
                rolled = true;
                break;
            }
        }
        assert!(rolled, "post-promotion drift must roll back");
        assert_eq!(c.phase(), Phase::RolledBack);
        assert_eq!(
            ptr.current(),
            "env/prod",
            "pointer flipped back to champion after drift"
        );
        assert_eq!(
            resp.tickets.len(),
            1,
            "a ticket was opened, a human notified"
        );
        assert!(resp.rollbacks >= 1);
    }

    #[test]
    fn rolled_back_is_terminal() {
        let mut c = controller();
        c.phase = Phase::RolledBack;
        let mut ptr = MemPointer {
            current: "env/prod".into(),
            flips: vec![],
        };
        let mut notif = MemNotifier::default();
        let mut resp = MemResponder::default();
        let step = c.ingest("env/prod-canary", 10.0, &mut ptr, &mut notif, &mut resp);
        assert_eq!(step.phase, Phase::RolledBack);
        assert_eq!(step.pointer_action, ControllerAction::Hold);
        assert!(ptr.flips.is_empty());
    }

    #[test]
    fn step_serializes() {
        let step = ControllerStep {
            phase: Phase::Promoted,
            pointer_action: ControllerAction::Hold,
            drift_action: DriftAction::None,
            gate_mode: GateMode::Enforced,
        };
        let j = serde_json::to_string(&step).unwrap();
        assert_eq!(serde_json::from_str::<ControllerStep>(&j).unwrap(), step);
    }

    #[test]
    fn r15_controller_step_surfaces_the_cold_start_advisory_label_during_canarying() {
        let mut c = controller();
        // Champion is live at the start (candidate not yet promoted) — the correct pointer setup for
        // exercising an eventual PROMOTE (drive_pointer's `from == candidate_ref` short-circuit would
        // otherwise mask every promote as a no-op `Hold`, as it correctly does once truly promoted).
        let mut ptr = MemPointer {
            current: "env/prod".into(),
            flips: vec![],
        };
        let mut notif = MemNotifier::default();
        let mut resp = MemResponder::default();

        // The very first candidate turn: the canary has essentially no evidence yet — advisory.
        let step = c.ingest("env/prod-canary", 98.0, &mut ptr, &mut notif, &mut resp);
        assert!(
            step.gate_mode.is_advisory(),
            "a brand-new rollout's first turn must be advisory, not silently enforced: {:?}",
            step.gate_mode
        );
        assert!(step.advisory_warning().unwrap().contains("ADVISORY-ONLY"));
        assert_eq!(
            step.phase,
            Phase::Canarying,
            "still holding, correctly — Continue"
        );

        // Drive enough turns to establish non-inferiority and promote (floor is baseline 90 − margin 2
        // = 88; a candidate steady around 98 is a wide, fast-to-establish margin). Once promoted the
        // canary has, by construction, cleared min_samples — gate_mode must read Enforced from then on.
        let mut promoted_step = None;
        for i in 0..500 {
            let q = 98.0 + if i % 2 == 0 { 0.3 } else { -0.3 };
            let s = c.ingest("env/prod-canary", q, &mut ptr, &mut notif, &mut resp);
            if s.promoted() {
                promoted_step = Some(s);
                break;
            }
        }
        let promoted_step = promoted_step.expect("an established non-inferior candidate promotes");
        assert!(
            promoted_step.gate_mode.is_enforced(),
            "once enough evidence accrued to promote, the gate is no longer advisory: {:?}",
            promoted_step.gate_mode
        );
        assert!(promoted_step.advisory_warning().is_none());
    }

    #[test]
    fn r15_champion_turns_report_the_canarys_unchanged_gate_mode() {
        // Champion-served turns don't move the candidate's evidence, so gate_mode must reflect
        // whatever the canary already has accrued — still advisory before any candidate turn at all.
        let mut c = controller();
        let mut ptr = MemPointer {
            current: "env/prod".into(),
            flips: vec![],
        };
        let mut notif = MemNotifier::default();
        let mut resp = MemResponder::default();
        let step = c.ingest("env/prod", 10.0, &mut ptr, &mut notif, &mut resp);
        assert!(
            step.gate_mode.is_advisory(),
            "zero candidate evidence is cold-start"
        );
    }
}
