// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! ainxt-canary — online canary + auto-rollback (gap AS).
//!
//! The eval gate ([`ainxt_eval`]) catches regressions BEFORE a change ships. This crate catches the
//! ones that only show up in production: it routes a configurable slice of live traffic to a
//! **candidate** (model/prompt/retrieval change) alongside the **champion**, accumulates per-arm
//! outcomes, and makes a **promote / rollback / continue** decision guarded by a minimum-sample
//! floor and a regression margin — so a candidate that is worse on real traffic is rolled back
//! automatically rather than silently degrading answers.
//!
//! Deterministic by construction: arm assignment is a stable hash of the request key (no RNG), and
//! all decisions are pure functions of the accumulated counters — so a canary run replays identically
//! and is exhaustively testable without a live system.

use serde::{Deserialize, Serialize};

pub mod alwaysvalid;
pub mod experiment;

/// Which deployment arm a request is served by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Arm {
    Champion,
    Candidate,
}

/// Accumulated outcomes for one arm.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArmMetrics {
    pub samples: u64,
    pub successes: u64,
    /// Sum of quality scores (0–100) — mean is derived, avoiding float accumulation drift.
    pub quality_sum: u64,
}

impl ArmMetrics {
    /// Record one served request.
    pub fn record(&mut self, success: bool, quality_0_100: u8) {
        self.samples += 1;
        if success {
            self.successes += 1;
        }
        self.quality_sum += quality_0_100 as u64;
    }

    /// Success fraction (0.0 when no samples).
    pub fn success_rate(&self) -> f64 {
        if self.samples == 0 {
            0.0
        } else {
            self.successes as f64 / self.samples as f64
        }
    }

    /// Mean quality 0–100 (0.0 when no samples).
    pub fn mean_quality(&self) -> f64 {
        if self.samples == 0 {
            0.0
        } else {
            self.quality_sum as f64 / self.samples as f64
        }
    }
}

/// Canary configuration (config-first).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct CanaryConfig {
    /// Fraction of traffic routed to the candidate, in `[0.0, 1.0]`.
    pub candidate_traffic: f64,
    /// Minimum candidate samples before any promote/rollback decision is made.
    pub min_samples: u64,
    /// Success-rate regression margin: the candidate is rolled back if its success rate is more than
    /// this below the champion's (0.0–1.0).
    pub success_margin: f64,
    /// Quality regression margin in points (0–100): rolled back if mean quality is more than this
    /// below the champion's.
    pub quality_margin: f64,
}

impl Default for CanaryConfig {
    fn default() -> Self {
        CanaryConfig {
            candidate_traffic: 0.05,
            min_samples: 100,
            success_margin: 0.02,
            quality_margin: 3.0,
        }
    }
}

/// The canary controller's decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CanaryDecision {
    /// Not enough candidate samples yet — keep serving the split.
    Continue,
    /// Candidate is at least as good (within margins) — promote it to champion.
    Promote,
    /// Candidate regressed beyond a margin — roll back to champion. Carries the reasons.
    Rollback(Vec<String>),
}

impl CanaryDecision {
    pub fn is_rollback(&self) -> bool {
        matches!(self, CanaryDecision::Rollback(_))
    }
}

/// Stable FNV-1a hash of a request key → deterministic, uniform-ish assignment (no RNG).
fn hash_key(key: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in key.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// Deterministically assign a request to an arm. The same key always maps to the same arm, and the
/// candidate share approximates `candidate_traffic` over many distinct keys. A `candidate_traffic`
/// of 0.0 never assigns Candidate; 1.0 always does.
pub fn assign(request_key: &str, cfg: &CanaryConfig) -> Arm {
    let frac = cfg.candidate_traffic.clamp(0.0, 1.0);
    if frac <= 0.0 {
        return Arm::Champion;
    }
    if frac >= 1.0 {
        return Arm::Candidate;
    }
    // Map the hash into [0, 10000) and compare against the fraction's basis-point threshold.
    let bucket = hash_key(request_key) % 10_000;
    let threshold = (frac * 10_000.0) as u64;
    if bucket < threshold {
        Arm::Candidate
    } else {
        Arm::Champion
    }
}

/// The promote/rollback/continue decision, a pure function of the accumulated arm metrics.
///
/// * `Continue` while the candidate has fewer than `min_samples` — never decide on thin data.
/// * `Rollback` if the candidate's success rate is more than `success_margin` below the champion's,
///   OR its mean quality is more than `quality_margin` below — collecting every failing reason.
/// * `Promote` otherwise (candidate is within, or above, both margins on enough samples).
pub fn decide(champion: &ArmMetrics, candidate: &ArmMetrics, cfg: &CanaryConfig) -> CanaryDecision {
    if candidate.samples < cfg.min_samples {
        return CanaryDecision::Continue;
    }
    let mut reasons = Vec::new();
    if candidate.success_rate() + cfg.success_margin < champion.success_rate() {
        reasons.push(format!(
            "success rate {:.3} is more than {:.3} below champion {:.3}",
            candidate.success_rate(),
            cfg.success_margin,
            champion.success_rate()
        ));
    }
    if candidate.mean_quality() + cfg.quality_margin < champion.mean_quality() {
        reasons.push(format!(
            "mean quality {:.1} is more than {:.1} below champion {:.1}",
            candidate.mean_quality(),
            cfg.quality_margin,
            champion.mean_quality()
        ));
    }
    if reasons.is_empty() {
        CanaryDecision::Promote
    } else {
        CanaryDecision::Rollback(reasons)
    }
}

// GAP-AUDIT misc-decisions (gap6, item 4) — investigated whether this crate's own base `Canary` /
// `assign` / `decide` / `CanaryConfig` / `CanaryDecision` / `ArmMetrics` engine (this whole file,
// above and below) is a real gap (an A/B decision path with no real caller) or fully superseded.
// It is fully superseded, by TWO independently-wired real consumers in the composition root,
// neither of which uses this engine:
//
// 1. `ainxt_quality::OnlineReleaseController` (wired at the composition root via
//    `ainxt_runtimed::governed::build_release_controller`) composes this crate's OWN
//    `alwaysvalid::AlwaysValidCanary` — anytime-valid, safe-to-peek confidence-sequence
//    decisioning, strictly stronger than this module's fixed-sample `decide()` — with
//    `experiment::{TrafficSplit, drive_pointer, PointerController, Notifier}` — weighted
//    multi-arm, git-ref-pinned assignment and an instant pointer-flip, strictly more capable
//    than this module's two-arm hash `assign()` — plus a CUSUM drift watch, for exactly the
//    online-canary-plus-auto-rollback gap ("gap AS") this crate's module doc says it exists for.
// 2. `ainxt_prompt::canary::{CanaryController, ArmMetrics, CanaryDecision}` — a separate,
//    independently-implemented crate — is wired at the composition root via
//    `ainxt_runtimed::governed::run_prompt_canary_sweep_tick` / `spawn_prompt_canary_tick` for
//    the served-prompt-deployment's own pointer-flip canary: a different decision surface with
//    its own metrics shape, unrelated to this crate.
//
// So the real composition root already has TWO closed A/B decision paths, each strictly stronger
// for its own purpose than this base engine — forcing this module into a THIRD, redundant path
// would not close a gap, it would add one more inconsistent implementation of the same idea.
// `Canary` / `assign` / `decide` remain correct, exhaustively tested, self-contained library
// primitives — genuine value for an external embedder of `ainxt-canary` who wants a simple,
// dependency-free two-arm fixed-sample A/B and does not want to pull in the anytime-valid
// statistics machinery `alwaysvalid` requires or wire a `PointerController`/`Notifier`. Not
// removed, and deliberately not forced into a redundant third production A/B decision path.

/// A running canary experiment: config + both arms + assignment/decision.
#[derive(Debug, Clone)]
pub struct Canary {
    cfg: CanaryConfig,
    champion: ArmMetrics,
    candidate: ArmMetrics,
}

impl Canary {
    pub fn new(cfg: CanaryConfig) -> Self {
        Canary {
            cfg,
            champion: ArmMetrics::default(),
            candidate: ArmMetrics::default(),
        }
    }

    /// Assign a request to an arm (deterministic by key).
    pub fn assign(&self, request_key: &str) -> Arm {
        assign(request_key, &self.cfg)
    }

    /// Record an outcome against the arm that served it.
    pub fn record(&mut self, arm: Arm, success: bool, quality_0_100: u8) {
        match arm {
            Arm::Champion => self.champion.record(success, quality_0_100),
            Arm::Candidate => self.candidate.record(success, quality_0_100),
        }
    }

    /// The current promote/rollback/continue decision.
    pub fn decision(&self) -> CanaryDecision {
        decide(&self.champion, &self.candidate, &self.cfg)
    }

    pub fn champion(&self) -> ArmMetrics {
        self.champion
    }
    pub fn candidate(&self) -> ArmMetrics {
        self.candidate
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> CanaryConfig {
        CanaryConfig {
            candidate_traffic: 0.1,
            min_samples: 50,
            success_margin: 0.02,
            quality_margin: 3.0,
        }
    }

    #[test]
    fn assignment_is_deterministic_and_stable() {
        let c = cfg();
        let a = assign("req-123", &c);
        let b = assign("req-123", &c);
        assert_eq!(a, b, "same key must map to the same arm");
    }

    #[test]
    fn traffic_fraction_is_approximately_honored() {
        let c = CanaryConfig {
            candidate_traffic: 0.2,
            ..cfg()
        };
        let mut candidate = 0;
        let n = 10_000;
        for i in 0..n {
            if assign(&format!("user-{i}-session"), &c) == Arm::Candidate {
                candidate += 1;
            }
        }
        let share = candidate as f64 / n as f64;
        assert!(
            (share - 0.2).abs() < 0.03,
            "candidate share {share} should be ~0.2"
        );
    }

    #[test]
    fn zero_and_full_traffic_are_absolute() {
        let none = CanaryConfig {
            candidate_traffic: 0.0,
            ..cfg()
        };
        let all = CanaryConfig {
            candidate_traffic: 1.0,
            ..cfg()
        };
        for i in 0..100 {
            assert_eq!(assign(&format!("k{i}"), &none), Arm::Champion);
            assert_eq!(assign(&format!("k{i}"), &all), Arm::Candidate);
        }
    }

    #[test]
    fn continue_until_min_samples() {
        let c = cfg();
        let mut champ = ArmMetrics::default();
        let mut cand = ArmMetrics::default();
        for _ in 0..100 {
            champ.record(true, 90);
        }
        for _ in 0..49 {
            cand.record(true, 90);
        }
        assert_eq!(
            decide(&champ, &cand, &c),
            CanaryDecision::Continue,
            "49 < 50 min_samples"
        );
    }

    #[test]
    fn rollback_on_success_rate_regression() {
        let c = cfg();
        let mut champ = ArmMetrics::default();
        let mut cand = ArmMetrics::default();
        for _ in 0..100 {
            champ.record(true, 90); // 100% success
        }
        for i in 0..100 {
            cand.record(i % 10 != 0, 90); // 90% success → 10 points below, > 2% margin
        }
        match decide(&champ, &cand, &c) {
            CanaryDecision::Rollback(rs) => assert!(rs.iter().any(|r| r.contains("success rate"))),
            d => panic!("expected rollback, got {d:?}"),
        }
    }

    #[test]
    fn rollback_on_quality_regression_even_if_success_ok() {
        let c = cfg();
        let mut champ = ArmMetrics::default();
        let mut cand = ArmMetrics::default();
        for _ in 0..100 {
            champ.record(true, 90);
        }
        for _ in 0..100 {
            cand.record(true, 80); // same success, 10 quality points below (> 3.0 margin)
        }
        match decide(&champ, &cand, &c) {
            CanaryDecision::Rollback(rs) => assert!(rs.iter().any(|r| r.contains("mean quality"))),
            d => panic!("expected rollback, got {d:?}"),
        }
    }

    #[test]
    fn promote_when_candidate_is_as_good() {
        let c = cfg();
        let mut champ = ArmMetrics::default();
        let mut cand = ArmMetrics::default();
        for _ in 0..100 {
            champ.record(true, 88);
            cand.record(true, 90); // slightly better
        }
        assert_eq!(decide(&champ, &cand, &c), CanaryDecision::Promote);
    }

    #[test]
    fn within_margin_is_not_a_rollback() {
        let c = cfg();
        let mut champ = ArmMetrics::default();
        let mut cand = ArmMetrics::default();
        for _ in 0..100 {
            champ.record(true, 90);
        }
        for i in 0..100 {
            cand.record(i % 100 != 0, 89); // 99% success (1% below, within 2%), 89 quality (within 3)
        }
        assert_eq!(
            decide(&champ, &cand, &c),
            CanaryDecision::Promote,
            "within both margins → promote"
        );
    }

    #[test]
    fn canary_end_to_end_flow() {
        let mut canary = Canary::new(CanaryConfig {
            candidate_traffic: 0.5,
            min_samples: 20,
            ..cfg()
        });
        for i in 0..200 {
            let key = format!("session-{i}");
            let arm = canary.assign(&key);
            // Candidate is worse: it fails 1 in 4.
            let (success, q) = match arm {
                Arm::Champion => (true, 92),
                Arm::Candidate => (i % 4 != 0, 92),
            };
            canary.record(arm, success, q);
        }
        assert!(canary.candidate().samples >= 20);
        assert!(
            canary.decision().is_rollback(),
            "a clearly-worse candidate must be rolled back"
        );
    }

    #[test]
    fn config_serializes() {
        let c = cfg();
        let j = serde_json::to_string(&c).unwrap();
        assert_eq!(serde_json::from_str::<CanaryConfig>(&j).unwrap(), c);
    }
}
