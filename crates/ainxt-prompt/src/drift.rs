// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Continuous **quality-drift detection** in production (`PROMPT_ENGINEERING.md` §8, `GAP_ANALYSIS`
//! X). Even a prompt that passed its deploy gate can drift as the provider silently updates the model,
//! the retrieval mix shifts, or usage moves into territory the eval set didn't cover. The point-in-time
//! canary gate does not catch this; a continuous monitor does.
//!
//! The monitor:
//! * **Samples** live turns (bounded cost — never full-traffic) via a deterministic [`SamplingPolicy`].
//! * **Scores** each sampled turn against the same quality dimensions via an injected LLM-judge
//!   ([`ainxt_eval::QualityJudge`]) — the same judge the eval gate uses, so drift and gate can't drift
//!   apart.
//! * **Tracks** the score distribution over a rolling window per `(role, model_family, version)`.
//! * **Alerts** only on *statistically significant* degradation vs the deploy-time baseline
//!   distribution — a one-sample t-test with a minimum sample size AND a minimum effect size, so a
//!   single bad turn (noise) never trips it, and a trivially-significant micro-shift is ignored.
//! * A confirmed drift event recommends **auto-open a ticket + roll back** (the same instant
//!   pointer-flip as a canary regression, just triggered by a slower signal).
//!
//! Deterministic; no clock/rng/I/O (the judge + the sample decision are seams / pure functions).

use crate::registry::content_fingerprint;
use ainxt_eval::{EvalCriteria, QualityJudge};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The distribution key: one tracked stream per Role × model family × deployed artifact version.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DriftKey {
    pub role: String,
    pub model_family: String,
    pub artifact_version: String,
}

impl DriftKey {
    pub fn new(role: &str, model_family: &str, artifact_version: &str) -> Self {
        DriftKey {
            role: role.into(),
            model_family: model_family.into(),
            artifact_version: artifact_version.into(),
        }
    }
}

/// Deterministic, cost-bounding sampling: sample `rate_pct` of turns by hashing the turn's routing key
/// (so a turn's sample decision is reproducible in replay, and the rate is stable across the fleet).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SamplingPolicy {
    /// 0–100. 0 disables sampling; 100 samples every turn.
    pub rate_pct: u8,
}

impl SamplingPolicy {
    pub fn new(rate_pct: u8) -> Self {
        SamplingPolicy {
            rate_pct: rate_pct.min(100),
        }
    }
    /// Should this turn be sampled? Deterministic bucket of the routing key.
    pub fn should_sample(&self, routing_key: &str) -> bool {
        if self.rate_pct == 0 {
            return false;
        }
        let fp = content_fingerprint(routing_key);
        let n = u32::from_str_radix(&fp[..8], 16).unwrap_or(0);
        (n % 100) < self.rate_pct as u32
    }
}

/// The deploy-time baseline the live distribution is compared against.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Baseline {
    /// The baseline mean score (0–100), from the artifact's passing eval run.
    pub mean: f64,
}

impl Baseline {
    pub fn new(mean: f64) -> Self {
        Baseline { mean }
    }
    /// Derive the baseline mean from the artifact's eval report (§8 — the deploy-gate distribution).
    pub fn from_report(report: &ainxt_eval::EvalReport) -> Self {
        Baseline {
            mean: report.mean as f64,
        }
    }
}

/// Tuning for how sensitive/robust the detector is.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct DriftPolicy {
    /// Minimum samples in the window before any alert can fire (kills single-turn noise).
    pub min_samples: usize,
    /// Rolling window capacity (older samples drop out — drift is about the *recent* distribution).
    pub window: usize,
    /// t-statistic threshold for "statistically significant" degradation (one-sided).
    pub t_threshold: f64,
    /// Minimum mean drop (points) required in addition to significance — ignores trivial shifts.
    pub min_effect: f64,
}

impl Default for DriftPolicy {
    fn default() -> Self {
        DriftPolicy {
            min_samples: 30,
            window: 200,
            t_threshold: 2.5,
            min_effect: 3.0,
        }
    }
}

/// What the runtime should do about a confirmed drift (§8 — same mechanism as a canary regression).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DriftAction {
    /// Auto-open a Registry ticket and roll the deployment back to the last known-good version.
    OpenTicketAndRollback,
}

/// A confirmed drift event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DriftEvent {
    pub key: DriftKey,
    pub baseline_mean: f64,
    pub window_mean: f64,
    pub window_n: usize,
    /// The computed t-statistic (higher = more significant degradation).
    pub t_stat: f64,
    pub action: DriftAction,
}

/// One tracked stream's rolling state.
#[derive(Debug, Clone)]
struct Stream {
    baseline: Baseline,
    scores: Vec<f64>,
    alerted: bool,
}

/// The drift monitor: many streams keyed by `(role, family, version)`.
#[derive(Debug, Clone, Default)]
pub struct DriftMonitor {
    policy: DriftPolicy,
    streams: BTreeMap<DriftKey, Stream>,
}

impl DriftMonitor {
    pub fn new(policy: DriftPolicy) -> Self {
        DriftMonitor {
            policy,
            streams: BTreeMap::new(),
        }
    }

    /// Register (or reset) a stream's baseline — call this at deploy time for each `(role, family,
    /// version)`. Resets any accumulated window (a new version starts fresh).
    pub fn set_baseline(&mut self, key: DriftKey, baseline: Baseline) {
        self.streams.insert(
            key,
            Stream {
                baseline,
                scores: Vec::new(),
                alerted: false,
            },
        );
    }

    /// Observe a sampled, already-scored live turn. Returns a [`DriftEvent`] the first time the stream
    /// crosses into confirmed degradation (it does not re-alert every turn afterward — one ticket, not
    /// a paging storm). A turn for an unknown key (no baseline) is ignored.
    pub fn observe_score(&mut self, key: &DriftKey, score: u8) -> Option<DriftEvent> {
        let policy = self.policy;
        let stream = self.streams.get_mut(key)?;
        stream.scores.push(score as f64);
        if stream.scores.len() > policy.window {
            let overflow = stream.scores.len() - policy.window;
            stream.scores.drain(0..overflow);
        }
        if stream.alerted {
            return None;
        }
        let event = detect(key, stream, &policy)?;
        stream.alerted = true;
        Some(event)
    }

    /// Convenience: score a sampled turn with the injected judge, then observe it. Use when the caller
    /// hands the monitor the raw turn; use [`observe_score`](Self::observe_score) when scoring is done
    /// asynchronously elsewhere.
    pub fn observe_turn(
        &mut self,
        key: &DriftKey,
        input: &str,
        output: &str,
        criteria: &EvalCriteria,
        judge: &dyn QualityJudge,
    ) -> Option<DriftEvent> {
        let score = judge.score(input, output, criteria).score;
        self.observe_score(key, score)
    }

    /// Current window mean for a key (for dashboards / tests). `None` if unknown/empty.
    pub fn window_mean(&self, key: &DriftKey) -> Option<f64> {
        let s = self.streams.get(key)?;
        if s.scores.is_empty() {
            None
        } else {
            Some(mean(&s.scores))
        }
    }
}

/// The **active** continuous-drift controller (§8) — the single per-turn entrypoint the served path
/// calls so drift detection is *wired*, not just implemented. It composes the three pieces that were
/// otherwise the caller's to assemble by hand: the cost-bounding [`SamplingPolicy`] (only a fraction of
/// live turns are scored), the injected [`QualityJudge`] (the same instrument the eval gate uses), and
/// the [`DriftMonitor`] (rolling per-`(role,family,version)` distribution + significance test). One
/// call — [`DriftController::on_live_turn`] — samples, scores, observes, and returns a [`DriftEvent`]
/// (which recommends [`DriftAction::OpenTicketAndRollback`]) exactly once per confirmed degradation.
///
/// The daemon feeds this every served turn; the *live traffic + live judge model* are the injected
/// seams (infra). Deterministic given deterministic seams.
pub struct DriftController {
    sampling: SamplingPolicy,
    monitor: DriftMonitor,
    criteria: EvalCriteria,
}

impl DriftController {
    /// Build a controller. `criteria` is the quality rubric the judge scores each sampled turn against
    /// (the same rubric the deploy gate used, so drift and gate cannot diverge).
    pub fn new(sampling: SamplingPolicy, monitor: DriftMonitor, criteria: EvalCriteria) -> Self {
        DriftController {
            sampling,
            monitor,
            criteria,
        }
    }

    /// Seed a served `(role, family, version)` stream's deploy-time baseline (call once at deploy).
    pub fn set_baseline(&mut self, key: DriftKey, baseline: Baseline) {
        self.monitor.set_baseline(key, baseline);
    }

    /// Process one live served turn. `routing_key` drives the deterministic sample decision; a turn
    /// that is NOT sampled is skipped entirely (bounded cost — no judge call). A sampled turn is scored
    /// by the injected `judge` and observed into the rolling window; the first crossing into confirmed
    /// degradation returns a [`DriftEvent`] whose [`DriftAction::OpenTicketAndRollback`] the runtime
    /// then applies (the same instant pointer-flip as a canary regression).
    pub fn on_live_turn(
        &mut self,
        key: &DriftKey,
        routing_key: &str,
        input: &str,
        output: &str,
        judge: &dyn QualityJudge,
    ) -> Option<DriftEvent> {
        if !self.sampling.should_sample(routing_key) {
            return None;
        }
        self.monitor
            .observe_turn(key, input, output, &self.criteria, judge)
    }

    /// The current rolling window mean for a stream (dashboards / tests).
    pub fn window_mean(&self, key: &DriftKey) -> Option<f64> {
        self.monitor.window_mean(key)
    }
}

/// The one-sample degradation test against the baseline mean.
fn detect(key: &DriftKey, stream: &Stream, policy: &DriftPolicy) -> Option<DriftEvent> {
    let n = stream.scores.len();
    if n < policy.min_samples {
        return None;
    }
    let m = mean(&stream.scores);
    let drop = stream.baseline.mean - m;
    // Must be a degradation of at least the minimum effect size.
    if drop < policy.min_effect {
        return None;
    }
    // One-sample t-statistic: (baseline_mean − window_mean) / (s / sqrt(n)).
    let sd = sample_std(&stream.scores, m);
    let t = if sd <= f64::EPSILON {
        // Zero variance + a real drop = unambiguous degradation.
        f64::INFINITY
    } else {
        drop / (sd / (n as f64).sqrt())
    };
    if t < policy.t_threshold {
        return None;
    }
    Some(DriftEvent {
        key: key.clone(),
        baseline_mean: stream.baseline.mean,
        window_mean: m,
        window_n: n,
        t_stat: t,
        action: DriftAction::OpenTicketAndRollback,
    })
}

fn mean(xs: &[f64]) -> f64 {
    if xs.is_empty() {
        return 0.0;
    }
    xs.iter().sum::<f64>() / xs.len() as f64
}

fn sample_std(xs: &[f64], m: f64) -> f64 {
    if xs.len() < 2 {
        return 0.0;
    }
    let var = xs.iter().map(|x| (x - m).powi(2)).sum::<f64>() / (xs.len() as f64 - 1.0);
    var.sqrt()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ainxt_eval::{EvalCriteria, QualityScore};

    fn key() -> DriftKey {
        DriftKey::new("role.l1_support", "qwen", "3.1.0")
    }

    // --- sampling bounds cost ----------------------------------------------------------------

    #[test]
    fn sampling_is_deterministic_and_bounded() {
        let p = SamplingPolicy::new(10);
        // Deterministic: same key → same decision.
        assert_eq!(p.should_sample("turn-7"), p.should_sample("turn-7"));
        // ~10% of a spread of keys are sampled (cost-bounded, not full-traffic).
        let hits = (0..1000)
            .filter(|i| p.should_sample(&format!("turn-{i}")))
            .count();
        assert!((50..170).contains(&hits), "≈10% sampled, got {hits}");
        // 0% disables entirely.
        assert!(!SamplingPolicy::new(0).should_sample("turn-1"));
    }

    // --- PRMT-08: degradation detected; noise does not alert ---------------------------------

    #[test]
    fn gap_ainxt_prompt_prmt_08_significant_degradation_is_detected_and_recommends_rollback() {
        let mut mon = DriftMonitor::new(DriftPolicy::default());
        mon.set_baseline(key(), Baseline::new(90.0));

        // Feed a steady stream well below baseline (model silently got worse).
        let mut event = None;
        for i in 0..60 {
            // Scores hover around 70 with a little deterministic variation.
            let s = if i % 2 == 0 { 68 } else { 72 };
            if let Some(e) = mon.observe_score(&key(), s) {
                event = Some(e);
                break;
            }
        }
        let e = event.expect("a sustained ~20-point drop must be flagged as drift");
        assert_eq!(e.action, DriftAction::OpenTicketAndRollback);
        assert!(e.window_mean < e.baseline_mean);
        assert!(e.window_n >= DriftPolicy::default().min_samples);
    }

    #[test]
    fn gap_ainxt_prompt_prmt_08_single_bad_turn_is_noise_not_drift() {
        let mut mon = DriftMonitor::new(DriftPolicy::default());
        mon.set_baseline(key(), Baseline::new(90.0));
        // Healthy stream at ~90 with ONE terrible turn — must not alert.
        for i in 0..80 {
            let s = if i == 40 { 5 } else { 90 };
            assert!(
                mon.observe_score(&key(), s).is_none(),
                "one bad turn in a healthy stream is noise, not drift"
            );
        }
    }

    #[test]
    fn gap_ainxt_prompt_prmt_08_below_min_samples_never_alerts() {
        let mut mon = DriftMonitor::new(DriftPolicy::default());
        mon.set_baseline(key(), Baseline::new(90.0));
        // Even a catastrophic drop with too few samples must wait for evidence.
        for _ in 0..10 {
            assert!(mon.observe_score(&key(), 10).is_none());
        }
    }

    #[test]
    fn gap_ainxt_prompt_prmt_08_trivial_shift_within_effect_size_is_ignored() {
        let mut mon = DriftMonitor::new(DriftPolicy::default());
        mon.set_baseline(key(), Baseline::new(90.0));
        // A ~1-point drop is statistically detectable at high n but below the min effect size — ignore.
        for i in 0..120 {
            let s = if i % 2 == 0 { 88 } else { 90 };
            assert!(
                mon.observe_score(&key(), s).is_none(),
                "a 1-point shift must not alert"
            );
        }
    }

    #[test]
    fn gap_ainxt_prompt_prmt_08_alerts_once_not_every_turn() {
        let mut mon = DriftMonitor::new(DriftPolicy::default());
        mon.set_baseline(key(), Baseline::new(90.0));
        let mut alerts = 0;
        for _ in 0..200 {
            if mon.observe_score(&key(), 60).is_some() {
                alerts += 1;
            }
        }
        assert_eq!(alerts, 1, "one ticket per drift event, not a paging storm");
    }

    #[test]
    fn observe_turn_uses_the_injected_judge() {
        struct FixedJudge(u8);
        impl QualityJudge for FixedJudge {
            fn score(&self, _i: &str, _o: &str, _c: &EvalCriteria) -> QualityScore {
                QualityScore {
                    score: self.0,
                    rationale: String::new(),
                }
            }
        }
        let mut mon = DriftMonitor::new(DriftPolicy::default());
        mon.set_baseline(key(), Baseline::new(90.0));
        let crit = EvalCriteria {
            rubric: "r".into(),
            threshold: 60,
        };
        let mut fired = false;
        for _ in 0..60 {
            if mon
                .observe_turn(&key(), "in", "out", &crit, &FixedJudge(60))
                .is_some()
            {
                fired = true;
                break;
            }
        }
        assert!(
            fired,
            "the judge-scored stream at 60 vs baseline 90 must drift"
        );
    }

    #[test]
    fn unknown_key_is_ignored() {
        let mut mon = DriftMonitor::new(DriftPolicy::default());
        // No baseline set → observations are dropped, never panic.
        assert!(mon.observe_score(&key(), 10).is_none());
        assert!(mon.window_mean(&key()).is_none());
    }
}
