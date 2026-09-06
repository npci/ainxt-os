// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! The **live-traffic-feed seam** for the online release controller (EVAL_PLATFORM.md §7, gap AS).
//!
//! [`OnlineReleaseController`](crate::controller::OnlineReleaseController) decides
//! promote / rollback / drift off a *per-turn* stream of `(served_ref, quality)` observations. In
//! production that stream comes from the served path: every completed turn (`/v1/chat`, an agent
//! step, an SDLC action) knows which git-ref served it — from the upstream traffic split — and, once
//! the quality assessor scores its answer, a 0–100 quality. The **feed** is the seam that surfaces
//! those observations to the controller.
//!
//! The *production* feed is driven by a running served daemon: a hook on the served path pushes each
//! scored turn as it completes. That requires a live daemon carrying live traffic → **infra-gated**.
//! This module builds the seam ([`LiveTurnFeed`]) plus a deterministic **offline** implementation
//! ([`ReplayFeed`]) that either replays a recorded stream or accepts pushes from a hook stand-in — so
//! the whole online release loop is exhaustively testable without a live system, and a recorded
//! rollout replays identically (no clock, no RNG).
//!
//! The controller consumes this seam via
//! [`OnlineReleaseController::drive_from_feed`](crate::controller::OnlineReleaseController::drive_from_feed).
//! Wiring the *production* hook (a served-path callback that scores each turn and pushes it) lives in
//! the runtime daemon (`ainxt-runtimed`) and is left to that crate to hot-wire onto the served turn
//! handler; this crate ships the drivable seam so that wiring is a thin push, not a rebuild.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// One observed live turn: the git-ref that actually served it (from the upstream traffic split) and
/// its measured 0–100 quality (from the quality assessor). This is the unit the controller ingests.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObservedTurn {
    /// The git-ref that served this turn (e.g. `env/prod`, `env/prod-canary`).
    pub served_ref: String,
    /// The turn's measured quality, 0–100.
    pub quality: f64,
}

impl ObservedTurn {
    pub fn new(served_ref: impl Into<String>, quality: f64) -> Self {
        ObservedTurn {
            served_ref: served_ref.into(),
            quality,
        }
    }
}

/// The live-traffic-feed seam: a source of served turns for the online release controller.
///
/// The production implementation is driven by the served daemon (a hook pushes each completed,
/// quality-scored turn); that path is **infra-gated** (needs a running daemon + live traffic). The
/// offline [`ReplayFeed`] fulfils the same seam from a recorded / pushed stream for deterministic
/// testing.
///
/// `next_turn` returns `None` when the feed is currently exhausted or closed — the driver stops
/// cleanly and can be re-driven later when more turns have arrived.
pub trait LiveTurnFeed {
    fn next_turn(&mut self) -> Option<ObservedTurn>;
}

/// A FIFO buffer feed. Preload a recorded stream with [`ReplayFeed::new`] for offline replay, or let a
/// served hook [`push`](ReplayFeed::push) turns as they complete — the same seam serves both the
/// deterministic replay and the live-hook push model. Draining is strictly FIFO and deterministic.
#[derive(Debug, Clone, Default)]
pub struct ReplayFeed {
    turns: VecDeque<ObservedTurn>,
}

impl ReplayFeed {
    /// A feed preloaded with a recorded stream (replayed in order).
    pub fn new(turns: Vec<ObservedTurn>) -> Self {
        ReplayFeed {
            turns: turns.into(),
        }
    }

    /// An empty feed — a served hook pushes into it as turns complete.
    pub fn empty() -> Self {
        ReplayFeed {
            turns: VecDeque::new(),
        }
    }

    /// Push one completed, quality-scored turn (the served-hook entry point).
    pub fn push(&mut self, turn: ObservedTurn) {
        self.turns.push_back(turn);
    }

    /// Push a `(served_ref, quality)` observation directly (convenience over [`ObservedTurn`]).
    pub fn push_observation(&mut self, served_ref: impl Into<String>, quality: f64) {
        self.turns.push_back(ObservedTurn::new(served_ref, quality));
    }

    /// Turns still buffered (not yet drained).
    pub fn remaining(&self) -> usize {
        self.turns.len()
    }

    pub fn is_empty(&self) -> bool {
        self.turns.is_empty()
    }
}

impl LiveTurnFeed for ReplayFeed {
    fn next_turn(&mut self) -> Option<ObservedTurn> {
        self.turns.pop_front()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_feed_drains_fifo_then_stops() {
        let mut f = ReplayFeed::new(vec![
            ObservedTurn::new("env/prod", 90.0),
            ObservedTurn::new("env/prod-canary", 88.0),
        ]);
        assert_eq!(f.remaining(), 2);
        assert_eq!(f.next_turn(), Some(ObservedTurn::new("env/prod", 90.0)));
        assert_eq!(
            f.next_turn(),
            Some(ObservedTurn::new("env/prod-canary", 88.0))
        );
        assert_eq!(f.next_turn(), None, "exhausted feed yields None");
        assert!(f.is_empty());
    }

    #[test]
    fn push_model_matches_the_served_hook_shape() {
        // A served hook pushes turns as they complete; the driver drains what has arrived, then stops
        // cleanly on None and can be re-driven when more arrive.
        let mut f = ReplayFeed::empty();
        assert_eq!(
            f.next_turn(),
            None,
            "empty feed is a clean stop, not a panic"
        );
        f.push_observation("env/prod-canary", 91.0);
        f.push(ObservedTurn::new("env/prod", 90.0));
        assert_eq!(f.remaining(), 2);
        assert_eq!(
            f.next_turn(),
            Some(ObservedTurn::new("env/prod-canary", 91.0))
        );
        assert_eq!(f.next_turn(), Some(ObservedTurn::new("env/prod", 90.0)));
        assert_eq!(f.next_turn(), None);
    }

    #[test]
    fn observed_turn_serializes() {
        let t = ObservedTurn::new("env/prod-canary", 87.5);
        let j = serde_json::to_string(&t).unwrap();
        assert_eq!(serde_json::from_str::<ObservedTurn>(&j).unwrap(), t);
    }
}
