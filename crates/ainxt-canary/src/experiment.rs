// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Git-ref traffic split, multi-arm A/B, and live pointer-flip auto-rollback (EVAL_PLATFORM.md §7,
//! gap AS).
//!
//! The canary is a **git-ref-pinned split**, not a DB flag: `canary.weight_pct` of turns route to
//! `env/prod-canary`, the rest to `env/prod` (ADR-026). Two candidate tags can run concurrently
//! (multi-arm). On an established regression the controller **flips the pointer back** — instant,
//! exact, byte-for-byte — and **notifies a human, doesn't page one** (gap AS). A winner's tag becomes
//! the new `env/prod`; a loser's ref resets.
//!
//! The deploy pointer and the notifier are production seams ([`PointerController`], [`Notifier`]); the
//! split/assignment/decision logic is deterministic (stable hash, no RNG) and fully testable offline.

use crate::alwaysvalid::AvDecision;
use serde::{Deserialize, Serialize};

/// Stable FNV-1a-64 hash of a request key → deterministic, uniform-ish assignment (no RNG).
fn fnv1a64(key: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in key.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// One arm of the experiment: a name bound to a pinned git-ref, plus its traffic weight in basis
/// points (0–10000). The champion is just the arm whose ref is the live `env/prod`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitArm {
    pub name: String,
    /// The pinned git-ref this arm serves (e.g. "env/prod", "env/prod-canary", "env/prod-canary-2").
    pub git_ref: String,
    /// Traffic weight in basis points (10000 = 100%).
    pub weight_bps: u32,
}

/// A weighted, git-ref-pinned traffic split across N arms (multi-arm A/B).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrafficSplit {
    arms: Vec<SplitArm>,
}

impl TrafficSplit {
    /// Build a split; arms with a non-positive weight are dropped. The remaining weights need not sum
    /// to 10000 — assignment normalizes over the total.
    pub fn new(arms: Vec<SplitArm>) -> Self {
        TrafficSplit {
            arms: arms.into_iter().filter(|a| a.weight_bps > 0).collect(),
        }
    }

    pub fn arms(&self) -> &[SplitArm] {
        &self.arms
    }

    /// The total weight across arms.
    pub fn total_weight(&self) -> u64 {
        self.arms.iter().map(|a| a.weight_bps as u64).sum()
    }

    /// Deterministically assign a request key to an arm (stable git-ref). Returns `None` only if the
    /// split has no arms. The same key always maps to the same arm; the share of each arm
    /// approximates its weight over many distinct keys.
    pub fn assign(&self, request_key: &str) -> Option<&SplitArm> {
        let total = self.total_weight();
        if total == 0 {
            return None;
        }
        let bucket = fnv1a64(request_key) % total;
        let mut acc = 0u64;
        for arm in &self.arms {
            acc += arm.weight_bps as u64;
            if bucket < acc {
                return Some(arm);
            }
        }
        self.arms.last()
    }

    /// The git-ref a request routes to (convenience over [`TrafficSplit::assign`]).
    pub fn route(&self, request_key: &str) -> Option<&str> {
        self.assign(request_key).map(|a| a.git_ref.as_str())
    }
}

/// The live deploy pointer (which git-ref `env/prod` currently points at). Flipping it is instant,
/// exact, and byte-for-byte — the same discipline as hot-reload. Production impl updates the signed
/// env-ref; this trait keeps the controller testable.
pub trait PointerController {
    /// The git-ref `env/prod` currently points at.
    fn current(&self) -> String;
    /// Flip `env/prod` to `to_ref` (promotion or rollback). Returns the previous ref.
    fn flip(&mut self, to_ref: &str) -> String;
}

/// Notify a human — never page one (gap AS). The production impl posts to a channel / opens a ticket.
pub trait Notifier {
    fn notify(&mut self, message: &str);
}

/// What the controller did this step.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ControllerAction {
    /// Nothing established yet — keep the split running.
    Hold,
    /// A candidate arm was promoted: `env/prod` now points at its ref.
    Promoted {
        arm: String,
        from_ref: String,
        to_ref: String,
    },
    /// A candidate arm regressed: `env/prod` was flipped back to the champion ref.
    RolledBack {
        arm: String,
        from_ref: String,
        to_ref: String,
        reason: String,
    },
}

impl ControllerAction {
    pub fn is_rollback(&self) -> bool {
        matches!(self, ControllerAction::RolledBack { .. })
    }
    pub fn is_promote(&self) -> bool {
        matches!(self, ControllerAction::Promoted { .. })
    }
}

/// Drives one candidate arm's anytime-valid decision onto the live pointer. `champion_ref` is where a
/// rollback returns to (the established `env/prod`). On an established regression it flips the pointer
/// back to the champion and notifies; on an established win it flips the pointer to the candidate.
///
/// Rollback is prioritized over promotion (safety first). Returns the action taken; a no-op is `Hold`.
pub fn drive_pointer(
    candidate_arm: &str,
    candidate_ref: &str,
    champion_ref: &str,
    decision: &AvDecision,
    pointer: &mut dyn PointerController,
    notifier: &mut dyn Notifier,
) -> ControllerAction {
    match decision {
        AvDecision::Rollback { reason, .. } => {
            // Only flip if the candidate is (or could be) live; always return to the champion ref.
            let from = pointer.current();
            if from != champion_ref {
                let prev = pointer.flip(champion_ref);
                notifier.notify(&format!(
                    "canary '{candidate_arm}' rolled back to {champion_ref} (was {prev}): {reason}"
                ));
                ControllerAction::RolledBack {
                    arm: candidate_arm.to_string(),
                    from_ref: prev,
                    to_ref: champion_ref.to_string(),
                    reason: reason.clone(),
                }
            } else {
                // Already on champion; still record the safety signal.
                notifier.notify(&format!(
                    "canary '{candidate_arm}' regressed but champion already live: {reason}"
                ));
                ControllerAction::RolledBack {
                    arm: candidate_arm.to_string(),
                    from_ref: from.clone(),
                    to_ref: champion_ref.to_string(),
                    reason: reason.clone(),
                }
            }
        }
        AvDecision::Promote { .. } => {
            let from = pointer.current();
            if from == candidate_ref {
                ControllerAction::Hold // already promoted
            } else {
                let prev = pointer.flip(candidate_ref);
                notifier.notify(&format!(
                    "canary '{candidate_arm}' promoted: env/prod {prev} → {candidate_ref}"
                ));
                ControllerAction::Promoted {
                    arm: candidate_arm.to_string(),
                    from_ref: prev,
                    to_ref: candidate_ref.to_string(),
                }
            }
        }
        AvDecision::Continue { .. } => ControllerAction::Hold,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

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

    fn split() -> TrafficSplit {
        TrafficSplit::new(vec![
            SplitArm {
                name: "champion".into(),
                git_ref: "env/prod".into(),
                weight_bps: 9000,
            },
            SplitArm {
                name: "canary".into(),
                git_ref: "env/prod-canary".into(),
                weight_bps: 1000,
            },
        ])
    }

    #[test]
    fn assignment_is_deterministic_and_git_ref_pinned() {
        let s = split();
        let a = s.route("req-1").map(|r| r.to_string());
        let b = s.route("req-1").map(|r| r.to_string());
        assert_eq!(a, b, "same key → same git-ref");
        assert!(a == Some("env/prod".into()) || a == Some("env/prod-canary".into()));
    }

    #[test]
    fn traffic_shares_approximate_weights() {
        let s = split();
        let mut counts: HashMap<&str, u32> = HashMap::new();
        let n = 20_000;
        for i in 0..n {
            let arm = s.assign(&format!("user-{i}-sess")).unwrap();
            *counts.entry(arm.name.as_str()).or_insert(0) += 1;
        }
        let canary_share = *counts.get("canary").unwrap_or(&0) as f64 / n as f64;
        assert!(
            (canary_share - 0.10).abs() < 0.03,
            "canary weight ~10%: got {canary_share}"
        );
    }

    #[test]
    fn multi_arm_split_covers_three_refs() {
        let s = TrafficSplit::new(vec![
            SplitArm {
                name: "champ".into(),
                git_ref: "env/prod".into(),
                weight_bps: 8000,
            },
            SplitArm {
                name: "a".into(),
                git_ref: "env/prod-canary".into(),
                weight_bps: 1000,
            },
            SplitArm {
                name: "b".into(),
                git_ref: "env/prod-canary-2".into(),
                weight_bps: 1000,
            },
        ]);
        let mut seen = std::collections::HashSet::new();
        for i in 0..5000 {
            seen.insert(s.route(&format!("k{i}")).unwrap().to_string());
        }
        assert_eq!(
            seen.len(),
            3,
            "all three git-refs must receive traffic: {seen:?}"
        );
    }

    #[test]
    fn established_regression_flips_pointer_back_and_notifies() {
        // Canary was promoted (live = canary ref); a regression must flip back to champion.
        let mut ptr = MemPointer {
            current: "env/prod-canary".into(),
            flips: vec![],
        };
        let mut notif = MemNotifier::default();
        let decision = AvDecision::Rollback {
            lower: 70.0,
            upper: 80.0,
            reason: "CI upper below floor".into(),
        };
        let action = drive_pointer(
            "canary",
            "env/prod-canary",
            "env/prod",
            &decision,
            &mut ptr,
            &mut notif,
        );
        assert!(action.is_rollback());
        assert_eq!(
            ptr.current(),
            "env/prod",
            "pointer flipped back to champion"
        );
        assert_eq!(notif.0.len(), 1, "a human is notified, not paged");
    }

    #[test]
    fn established_win_promotes_the_candidate_ref() {
        let mut ptr = MemPointer {
            current: "env/prod".into(),
            flips: vec![],
        };
        let mut notif = MemNotifier::default();
        let decision = AvDecision::Promote {
            lower: 91.0,
            upper: 93.0,
        };
        let action = drive_pointer(
            "canary",
            "env/prod-canary",
            "env/prod",
            &decision,
            &mut ptr,
            &mut notif,
        );
        assert!(action.is_promote());
        assert_eq!(ptr.current(), "env/prod-canary");
        // A second promote decision is a no-op (already live).
        let again = drive_pointer(
            "canary",
            "env/prod-canary",
            "env/prod",
            &decision,
            &mut ptr,
            &mut notif,
        );
        assert_eq!(again, ControllerAction::Hold);
    }

    #[test]
    fn continue_holds_the_pointer() {
        let mut ptr = MemPointer {
            current: "env/prod".into(),
            flips: vec![],
        };
        let mut notif = MemNotifier::default();
        let action = drive_pointer(
            "canary",
            "env/prod-canary",
            "env/prod",
            &AvDecision::Continue {
                lower: 80.0,
                upper: 95.0,
            },
            &mut ptr,
            &mut notif,
        );
        assert_eq!(action, ControllerAction::Hold);
        assert_eq!(ptr.current(), "env/prod", "no flip while uncertain");
        assert!(notif.0.is_empty());
    }

    #[test]
    fn split_serializes() {
        let s = split();
        let j = serde_json::to_string(&s).unwrap();
        assert_eq!(serde_json::from_str::<TrafficSplit>(&j).unwrap(), s);
    }
}
