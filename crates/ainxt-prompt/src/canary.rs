// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! **Active progressive delivery** for prompts (`PROMPT_ENGINEERING.md` §3, §8, `GAP_ANALYSIS` AS):
//! watch a live canary artifact against the last-known-good PRODUCTION and either **promote** it or
//! **auto-roll-back** — where rollback is an *instant pointer flip* (§3), not a rewrite, because the
//! compiled variant bodies are immutable + content-addressed.
//!
//! The [`crate::registry::Deployment`] already models the `prod` / `prod-canary` refs and the
//! pointer-flip primitives (`promote_canary` / `rollback_canary`). What was missing is the ACTIVE
//! controller that decides between them from the online canary metrics and applies the flip in one
//! step — so "canary + auto-rollback" is a wired control loop, not two disconnected primitives.
//!
//! A regression on ANY watched signal (quality mean OR guardrail-trigger rate) rolls back; a human is
//! **notified**, not paged to manually revert (§8). Deterministic; no clock/rng/I-O — the live metric
//! computation is the injected seam (the daemon computes the online numbers and calls in).

use crate::registry::Deployment;
use serde::{Deserialize, Serialize};

/// The online metrics watched for one deployment arm (`prod` or the canary), computed on LIVE traffic
/// (§8 — the SAME quality metric the offline gate uses, plus the guardrail-trigger rate). Higher
/// `quality_mean` is better; higher `guardrail_trigger_rate` is worse.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ArmMetrics {
    /// Mean quality score (0–100) over the arm's sampled live turns.
    pub quality_mean: f64,
    /// Number of scored samples backing `quality_mean` (evidence sufficiency).
    pub n: usize,
    /// Fraction of turns that tripped a guardrail (0.0–1.0) — lower is better.
    pub guardrail_trigger_rate: f64,
}

impl ArmMetrics {
    pub fn new(quality_mean: f64, n: usize, guardrail_trigger_rate: f64) -> Self {
        ArmMetrics {
            quality_mean,
            n,
            guardrail_trigger_rate,
        }
    }
}

/// Tuning for the promote/rollback decision.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct CanaryPolicy {
    /// Minimum canary samples before any promote/rollback decision (soak requirement — below this the
    /// controller HOLDs, never acting on thin evidence).
    pub min_samples: usize,
    /// The canary's quality may not regress below prod by more than this many points.
    pub max_quality_regression: f64,
    /// The canary's guardrail-trigger rate may not exceed prod's by more than this (absolute fraction).
    pub max_guardrail_increase: f64,
}

impl Default for CanaryPolicy {
    fn default() -> Self {
        CanaryPolicy {
            min_samples: 50,
            max_quality_regression: 2.0,
            max_guardrail_increase: 0.02,
        }
    }
}

/// The controller's decision for a canary soak.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CanaryDecision {
    /// Not enough evidence yet — keep soaking (no pointer flip).
    Hold,
    /// Healthy — promote the canary onto `prod` (fast-forward pointer flip).
    Promote,
    /// Regressed on a watched signal — auto-rollback (collapse the canary onto `prod`); a human is
    /// notified, not paged.
    Rollback,
}

/// The active canary controller.
#[derive(Debug, Clone, Copy, Default)]
pub struct CanaryController {
    pub policy: CanaryPolicy,
}

impl CanaryController {
    pub fn new(policy: CanaryPolicy) -> Self {
        CanaryController { policy }
    }

    /// Decide from the two arms' online metrics, WITHOUT touching the deployment (pure).
    pub fn decide(&self, prod: &ArmMetrics, canary: &ArmMetrics) -> CanaryDecision {
        if canary.n < self.policy.min_samples {
            return CanaryDecision::Hold;
        }
        let quality_regression = prod.quality_mean - canary.quality_mean;
        let guardrail_increase = canary.guardrail_trigger_rate - prod.guardrail_trigger_rate;
        if quality_regression > self.policy.max_quality_regression
            || guardrail_increase > self.policy.max_guardrail_increase
        {
            return CanaryDecision::Rollback;
        }
        CanaryDecision::Promote
    }

    /// Decide AND apply the resulting **pointer flip** to `deployment` (§3): `Promote` fast-forwards
    /// `prod` onto the canary tag; `Rollback` collapses `prod-canary` back onto `prod`; `Hold` is a
    /// no-op. Returns the decision taken. A deployment with no active canary always yields `Hold`.
    pub fn evaluate_and_apply(
        &self,
        deployment: &mut Deployment,
        prod: &ArmMetrics,
        canary: &ArmMetrics,
    ) -> CanaryDecision {
        if deployment.canary.is_none() {
            return CanaryDecision::Hold;
        }
        let decision = self.decide(prod, canary);
        match decision {
            CanaryDecision::Promote => deployment.promote_canary(),
            CanaryDecision::Rollback => deployment.rollback_canary(),
            CanaryDecision::Hold => {}
        }
        decision
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn controller() -> CanaryController {
        CanaryController::new(CanaryPolicy::default())
    }

    #[test]
    fn thin_evidence_holds() {
        let c = controller();
        let prod = ArmMetrics::new(88.0, 500, 0.01);
        let canary = ArmMetrics::new(60.0, 10, 0.5); // terrible, but only 10 samples
        assert_eq!(c.decide(&prod, &canary), CanaryDecision::Hold);
    }

    #[test]
    fn healthy_canary_promotes() {
        let c = controller();
        let prod = ArmMetrics::new(88.0, 500, 0.02);
        let canary = ArmMetrics::new(89.0, 200, 0.02);
        assert_eq!(c.decide(&prod, &canary), CanaryDecision::Promote);
    }

    #[test]
    fn quality_regression_rolls_back() {
        let c = controller();
        let prod = ArmMetrics::new(88.0, 500, 0.02);
        let canary = ArmMetrics::new(80.0, 200, 0.02); // −8 pts > 2.0 margin
        assert_eq!(c.decide(&prod, &canary), CanaryDecision::Rollback);
    }

    #[test]
    fn guardrail_spike_rolls_back_even_if_quality_holds() {
        let c = controller();
        let prod = ArmMetrics::new(88.0, 500, 0.02);
        let canary = ArmMetrics::new(88.5, 200, 0.20); // quality fine, guardrails spiked
        assert_eq!(c.decide(&prod, &canary), CanaryDecision::Rollback);
    }
}
