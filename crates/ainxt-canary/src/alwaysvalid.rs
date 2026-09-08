// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Always-valid (anytime-valid) inference for the online canary (EVAL_PLATFORM.md §5.6, gap AS).
//!
//! The offline gate is fixed-sample (analyzed once, no peeking). The *online* canary cannot tell
//! operators not to watch a live rollout — so peeking at a fixed-sample p-value inflates the
//! false-positive rate and flaps the gate. The correct engineering answer is a **confidence
//! sequence**: a time-uniform CI under which continuous monitoring and early stopping do **not**
//! inflate the false-positive rate. Operators may watch and stop the moment the sequence crosses,
//! safely.
//!
//! This module implements the asymptotic confidence sequence (AsympCS, Waudby-Smith et al. 2021):
//! at every step `n` the running mean is bracketed by
//! `μ̂ ± σ̂ · sqrt( 2(nρ²+1)/(n²ρ²) · ln( sqrt(nρ²+1)/α ) )`, whose width shrinks like ~1/√n with an
//! iterated-log inflation that makes the coverage hold *uniformly over time*. The champion is
//! production (a well-established metric), so the canary watches the *candidate* stream against a
//! fixed baseline — a clean one-sample confidence sequence, safe to peek.
//!
//! Deterministic: variance is tracked with Welford's online algorithm (no RNG/clock); every decision
//! is a pure function of the accumulated counters.

use serde::{Deserialize, Serialize};

/// Welford's online mean/variance accumulator — numerically stable, exact-replay deterministic.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct RunningStats {
    n: u64,
    mean: f64,
    /// Sum of squared deviations from the running mean.
    m2: f64,
}

impl RunningStats {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold one observation in.
    pub fn push(&mut self, x: f64) {
        self.n += 1;
        let delta = x - self.mean;
        self.mean += delta / self.n as f64;
        let delta2 = x - self.mean;
        self.m2 += delta * delta2;
    }

    pub fn count(&self) -> u64 {
        self.n
    }

    pub fn mean(&self) -> f64 {
        self.mean
    }

    /// Unbiased sample variance (n − 1); 0 for n < 2.
    pub fn variance(&self) -> f64 {
        if self.n < 2 {
            0.0
        } else {
            self.m2 / (self.n as f64 - 1.0)
        }
    }

    pub fn std_dev(&self) -> f64 {
        self.variance().sqrt()
    }
}

/// Tuning parameter ρ optimizing the AsympCS width around a target sample size `n_star`
/// (Waudby-Smith et al.): `ρ = sqrt( (−2 ln α + ln(−2 ln α + 1)) / n_star )`.
pub fn rho_for_target(n_star: u64, alpha: f64) -> f64 {
    let n = n_star.max(1) as f64;
    let l = -2.0 * alpha.ln();
    ((l + (l + 1.0).ln()) / n).sqrt()
}

/// The AsympCS half-width for a running mean with `n` samples, sample variance `var`, tuning `rho`,
/// and error level `alpha`. Returns `f64::INFINITY` before two samples exist (no variance estimate).
pub fn asymp_cs_halfwidth(n: u64, var: f64, rho: f64, alpha: f64) -> f64 {
    if n < 2 || rho <= 0.0 {
        return f64::INFINITY;
    }
    let nf = n as f64;
    let sigma = var.sqrt();
    let inner = (nf * rho * rho + 1.0) / (nf * nf * rho * rho);
    let log_term = ((nf * rho * rho + 1.0).sqrt() / alpha).ln();
    if log_term <= 0.0 {
        return f64::INFINITY;
    }
    sigma * (2.0 * inner * log_term).sqrt()
}

/// Config for the anytime-valid canary monitor.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct AlwaysValidConfig {
    /// The established champion (production) metric the candidate is judged against (0–100).
    pub baseline: f64,
    /// Non-inferiority margin in metric points: the candidate is a regression only if its mean is
    /// established to be more than this below `baseline`.
    pub margin: f64,
    /// Error level for the confidence sequence (time-uniform coverage 1 − α).
    pub alpha: f64,
    /// Minimum candidate samples before a Promote decision (a Rollback can fire earlier — safety).
    pub min_samples: u64,
    /// AsympCS tuning parameter ρ (see [`rho_for_target`]).
    pub rho: f64,
}

impl AlwaysValidConfig {
    /// A config whose ρ is tuned for `target_n` candidate samples.
    pub fn tuned(baseline: f64, margin: f64, alpha: f64, min_samples: u64, target_n: u64) -> Self {
        AlwaysValidConfig {
            baseline,
            margin,
            alpha,
            min_samples,
            rho: rho_for_target(target_n, alpha),
        }
    }
}

/// The anytime-valid decision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AvDecision {
    /// The sequence has not established either verdict yet — keep serving the split (safe to peek).
    Continue { lower: f64, upper: f64 },
    /// The confidence sequence's UPPER bound is below `baseline − margin`: the candidate is
    /// established to be materially worse → roll back now (anytime-valid; no peeking penalty).
    Rollback {
        lower: f64,
        upper: f64,
        reason: String,
    },
    /// The confidence sequence's LOWER bound is above `baseline − margin` with enough samples: the
    /// candidate is established non-inferior → promote.
    Promote { lower: f64, upper: f64 },
}

impl AvDecision {
    pub fn is_rollback(&self) -> bool {
        matches!(self, AvDecision::Rollback { .. })
    }
    pub fn is_promote(&self) -> bool {
        matches!(self, AvDecision::Promote { .. })
    }
}

/// Provenance of one candidate observation fed into the canary — LIVE traffic vs. Breaker/synthetic
/// seeding (the cold-start mitigation, EVAL_PLATFORM.md §275: *"Mitigation: Breaker + synthetic
/// seeding, and loud 'advisory-only' labeling so an advisory gate is never mistaken for enforced."*).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObservationSource {
    /// A real, served production turn.
    Live,
    /// A Breaker-verified repro or other synthetic case, seeded to narrow the cold-start window before
    /// enough live traffic has accrued. Counts toward statistical power exactly like a live sample —
    /// it is real signal, just not yet validated on the live distribution.
    Synthetic,
}

/// Whether a brand-new capability's canary has accrued enough evidence to be **enforced**, or is still
/// in its **cold-start / underpowered** window (EVAL_PLATFORM.md §275, ADR-010-evaluation-platform.md
/// §187: *"A brand-new capability has too little data to power a gate; until it does, its gate is
/// honestly 'advisory' — a window in which a regression could ship."*).
///
/// This is a LOUD, structural label — never inferred by the caller from a bare sample count — so an
/// [`AvDecision::Continue`] returned while [`GateMode::Advisory`] is never mistaken for "the gate is
/// protecting you": it means the confidence sequence has not yet had enough data to establish EITHER
/// verdict, and a real regression could still be silently shipping in this window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GateMode {
    /// Enough total evidence (live + synthetic) has accrued to reach `min_samples` — the confidence
    /// sequence's guarantee is live: a [`AvDecision::Continue`] here genuinely means "no regression
    /// established yet," not "no data yet."
    Enforced,
    /// Cold start / underpowered: fewer than `min_samples` observations total. ANY decision in this
    /// window — even one seeded with synthetic cases — is advisory-only. Must be surfaced loudly
    /// (`GateMode::warning`) to an operator/dashboard, never silently treated as protection.
    Advisory {
        samples: u64,
        min_samples: u64,
        synthetic_samples: u64,
    },
}

impl GateMode {
    pub fn is_advisory(&self) -> bool {
        matches!(self, GateMode::Advisory { .. })
    }
    pub fn is_enforced(&self) -> bool {
        matches!(self, GateMode::Enforced)
    }
    /// A loud, human-readable warning when advisory — `None` once enforced. Callers (dashboards,
    /// notifiers, the online release controller) surface this directly rather than re-deriving it, so
    /// the "advisory-only" label can never silently drop out of a log line.
    pub fn warning(&self) -> Option<String> {
        match self {
            GateMode::Enforced => None,
            GateMode::Advisory {
                samples,
                min_samples,
                synthetic_samples,
            } => Some(format!(
                "ADVISORY-ONLY GATE: only {samples}/{min_samples} samples accrued \
                 ({synthetic_samples} synthetic-seeded) — a regression could ship undetected in this \
                 cold-start window (EVAL_PLATFORM.md §275)"
            )),
        }
    }
}

/// An anytime-valid canary: accumulate the candidate stream and decide at any point without a peeking
/// penalty.
#[derive(Debug, Clone)]
pub struct AlwaysValidCanary {
    cfg: AlwaysValidConfig,
    candidate: RunningStats,
    synthetic_samples: u64,
}

impl AlwaysValidCanary {
    pub fn new(cfg: AlwaysValidConfig) -> Self {
        AlwaysValidCanary {
            cfg,
            candidate: RunningStats::new(),
            synthetic_samples: 0,
        }
    }

    /// Record one candidate quality observation (0–100) from LIVE traffic.
    pub fn record(&mut self, quality: f64) {
        self.record_with_source(quality, ObservationSource::Live);
    }

    /// Seed a Breaker-verified / synthetic observation — the cold-start MITIGATION named alongside the
    /// advisory label (EVAL_PLATFORM.md §275): narrows the window in which the gate is merely advisory
    /// by contributing real statistical power before live traffic alone would clear `min_samples`.
    pub fn seed_synthetic(&mut self, quality: f64) {
        self.record_with_source(quality, ObservationSource::Synthetic);
    }

    /// Record one observation with explicit provenance.
    pub fn record_with_source(&mut self, quality: f64, source: ObservationSource) {
        self.candidate.push(quality);
        if source == ObservationSource::Synthetic {
            self.synthetic_samples += 1;
        }
    }

    pub fn samples(&self) -> u64 {
        self.candidate.count()
    }

    /// Samples seeded synthetically (a subset of [`Self::samples`]) — disclosed so the advisory label
    /// can say exactly how much of the evidence is live vs. seeded.
    pub fn synthetic_samples(&self) -> u64 {
        self.synthetic_samples
    }

    /// The current cold-start / enforced [`GateMode`] — computed off total accrued evidence (live +
    /// synthetic), the same denominator [`Self::decide`] uses for its `min_samples` floor, so
    /// `GateMode::Enforced` and a `Promote`-eligible decision agree on when the gate has real teeth.
    pub fn gate_mode(&self) -> GateMode {
        let samples = self.candidate.count();
        if samples >= self.cfg.min_samples {
            GateMode::Enforced
        } else {
            GateMode::Advisory {
                samples,
                min_samples: self.cfg.min_samples,
                synthetic_samples: self.synthetic_samples,
            }
        }
    }

    /// The current time-uniform confidence interval for the candidate mean.
    pub fn confidence_interval(&self) -> (f64, f64) {
        let w = asymp_cs_halfwidth(
            self.candidate.count(),
            self.candidate.variance(),
            self.cfg.rho,
            self.cfg.alpha,
        );
        if w.is_infinite() {
            return (f64::NEG_INFINITY, f64::INFINITY);
        }
        (self.candidate.mean() - w, self.candidate.mean() + w)
    }

    /// The anytime-valid promote/rollback/continue decision.
    pub fn decide(&self) -> AvDecision {
        let (lower, upper) = self.confidence_interval();
        let floor = self.cfg.baseline - self.cfg.margin;
        // Rollback the moment the whole sequence is below the floor — safe to peek.
        if upper < floor {
            return AvDecision::Rollback {
                lower,
                upper,
                reason: format!(
                    "candidate CI upper {upper:.2} below non-inferiority floor {floor:.2} \
                     (baseline {:.2} − margin {:.2})",
                    self.cfg.baseline, self.cfg.margin
                ),
            };
        }
        // Promote once the whole sequence is above the floor AND we have enough samples.
        if lower > floor && self.candidate.count() >= self.cfg.min_samples {
            return AvDecision::Promote { lower, upper };
        }
        AvDecision::Continue { lower, upper }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx(a: f64, b: f64, tol: f64) -> bool {
        (a - b).abs() <= tol
    }

    #[test]
    fn welford_matches_batch_mean_and_variance() {
        let xs = [4.0, 8.0, 15.0, 16.0, 23.0, 42.0];
        let mut r = RunningStats::new();
        for &x in &xs {
            r.push(x);
        }
        let mean = xs.iter().sum::<f64>() / xs.len() as f64;
        let var = xs.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (xs.len() as f64 - 1.0);
        assert!(approx(r.mean(), mean, 1e-9));
        assert!(approx(r.variance(), var, 1e-9));
    }

    #[test]
    fn cs_width_shrinks_with_more_samples() {
        let rho = rho_for_target(200, 0.05);
        let w_small = asymp_cs_halfwidth(20, 25.0, rho, 0.05);
        let w_large = asymp_cs_halfwidth(2000, 25.0, rho, 0.05);
        assert!(
            w_large < w_small,
            "more samples → tighter CS: {w_large} < {w_small}"
        );
        assert!(w_small.is_finite() && w_large > 0.0);
        // Before two samples the width is infinite (no verdict possible).
        assert!(asymp_cs_halfwidth(1, 0.0, rho, 0.05).is_infinite());
    }

    #[test]
    fn rollback_fires_when_candidate_is_clearly_worse() {
        // baseline 90, margin 2 → floor 88. Candidate steady around 78 → must roll back.
        let cfg = AlwaysValidConfig::tuned(90.0, 2.0, 0.05, 100, 500);
        let mut c = AlwaysValidCanary::new(cfg);
        for i in 0..500 {
            // small deterministic wobble around 78
            let q = 78.0 + if i % 2 == 0 { 0.5 } else { -0.5 };
            c.record(q);
        }
        let d = c.decide();
        assert!(
            d.is_rollback(),
            "a clearly-worse candidate must roll back: {d:?}"
        );
    }

    #[test]
    fn promote_when_candidate_is_established_non_inferior() {
        // baseline 90, margin 3 → floor 87. Candidate steady ~91 → established non-inferior.
        let cfg = AlwaysValidConfig::tuned(90.0, 3.0, 0.05, 100, 500);
        let mut c = AlwaysValidCanary::new(cfg);
        for i in 0..800 {
            let q = 91.0 + if i % 2 == 0 { 0.3 } else { -0.3 };
            c.record(q);
        }
        let d = c.decide();
        assert!(
            d.is_promote(),
            "an established non-inferior candidate promotes: {d:?}"
        );
    }

    #[test]
    fn continue_while_uncertain_and_no_peeking_penalty() {
        // baseline 90, margin 5 → floor 85. Candidate hovers right at the floor with wide variance:
        // the sequence should NOT prematurely decide — it holds Continue while genuinely uncertain.
        let cfg = AlwaysValidConfig::tuned(90.0, 5.0, 0.05, 100, 500);
        let mut c = AlwaysValidCanary::new(cfg);
        // Only a handful of noisy samples → cannot establish a verdict yet.
        for i in 0..15 {
            let q = 85.0 + if i % 2 == 0 { 20.0 } else { -20.0 };
            c.record(q);
        }
        let d = c.decide();
        assert!(
            matches!(d, AvDecision::Continue { .. }),
            "thin, noisy data must not trigger an early verdict: {d:?}"
        );
    }

    #[test]
    fn null_stream_at_baseline_does_not_falsely_rollback() {
        // A candidate exactly at baseline with noise must NOT be rolled back even under heavy peeking.
        let cfg = AlwaysValidConfig::tuned(90.0, 2.0, 0.05, 100, 500);
        let mut c = AlwaysValidCanary::new(cfg);
        let mut rolled_back = false;
        for i in 0..1000 {
            let q = 90.0 + if i % 2 == 0 { 1.0 } else { -1.0 };
            c.record(q);
            if c.decide().is_rollback() {
                rolled_back = true;
                break;
            }
        }
        assert!(
            !rolled_back,
            "an at-baseline candidate must never be rolled back despite continuous peeking"
        );
    }

    #[test]
    fn config_serializes() {
        let cfg = AlwaysValidConfig::tuned(90.0, 2.0, 0.05, 100, 500);
        let j = serde_json::to_string(&cfg).unwrap();
        assert_eq!(serde_json::from_str::<AlwaysValidConfig>(&j).unwrap(), cfg);
    }

    #[test]
    fn r15_gate_mode_is_advisory_during_cold_start_and_enforced_once_powered() {
        let cfg = AlwaysValidConfig::tuned(90.0, 2.0, 0.05, 100, 500);
        let mut c = AlwaysValidCanary::new(cfg);
        // Brand new: zero samples — a fresh capability's cold start.
        match c.gate_mode() {
            GateMode::Advisory {
                samples,
                min_samples,
                synthetic_samples,
            } => {
                assert_eq!(samples, 0);
                assert_eq!(min_samples, 100);
                assert_eq!(synthetic_samples, 0);
            }
            GateMode::Enforced => panic!("zero samples must never be Enforced"),
        }
        assert!(c.gate_mode().is_advisory());
        assert!(
            c.gate_mode().warning().unwrap().contains("ADVISORY-ONLY"),
            "the label must be LOUD, not a bare enum variant"
        );

        // Accrue live samples up to (but not past) min_samples: still advisory.
        for _ in 0..99 {
            c.record(91.0);
        }
        assert!(
            c.gate_mode().is_advisory(),
            "99 < 100 min_samples is still cold-start"
        );

        // Cross the floor: now enforced, and the warning disappears.
        c.record(91.0);
        assert_eq!(c.samples(), 100);
        assert!(c.gate_mode().is_enforced());
        assert!(c.gate_mode().warning().is_none());
    }

    #[test]
    fn r15_synthetic_seeding_narrows_the_cold_start_window_and_is_disclosed() {
        let cfg = AlwaysValidConfig::tuned(90.0, 2.0, 0.05, 100, 500);
        let mut c = AlwaysValidCanary::new(cfg);
        // Seed 60 Breaker/synthetic cases before ANY live traffic exists.
        for _ in 0..60 {
            c.seed_synthetic(90.0);
        }
        assert_eq!(c.synthetic_samples(), 60);
        assert_eq!(
            c.samples(),
            60,
            "synthetic seeds count toward total evidence"
        );
        match c.gate_mode() {
            GateMode::Advisory {
                samples,
                synthetic_samples,
                ..
            } => {
                assert_eq!(samples, 60);
                assert_eq!(
                    synthetic_samples, 60,
                    "the advisory label discloses the seeded composition"
                );
            }
            GateMode::Enforced => panic!("60 < 100 must still be advisory"),
        }
        // 40 more LIVE samples clear the floor — seeding genuinely narrowed the live-only window from
        // 100 down to 40.
        for _ in 0..40 {
            c.record(91.0);
        }
        assert!(c.gate_mode().is_enforced());
        assert_eq!(
            c.synthetic_samples(),
            60,
            "the synthetic count is preserved, not reset"
        );
    }

    #[test]
    fn r15_gate_mode_serializes() {
        let advisory = GateMode::Advisory {
            samples: 10,
            min_samples: 100,
            synthetic_samples: 2,
        };
        let j = serde_json::to_string(&advisory).unwrap();
        assert_eq!(serde_json::from_str::<GateMode>(&j).unwrap(), advisory);
        let enforced = GateMode::Enforced;
        let j2 = serde_json::to_string(&enforced).unwrap();
        assert_eq!(serde_json::from_str::<GateMode>(&j2).unwrap(), enforced);
    }
}
