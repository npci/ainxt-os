// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Continuous production quality-drift monitor (EVAL_PLATFORM.md §8; gaps BF/BT/X, 8).
//!
//! A change that passed its release gate can still degrade later: a provider silently updates a cloud
//! model, the retrieval mix shifts, or usage moves off-distribution. The two-sample change-point test
//! in [`crate::detect_drift`] compares caller-supplied windows; this module adds the *production
//! wiring* the audit flagged as missing:
//!
//! * **CUSUM sequential change-point** ([`Cusum`]): a streaming tabular CUSUM that flags a sustained
//!   downward shift in quality (not single-turn noise), tuned to the sampling volume so it neither
//!   flaps nor sleeps.
//! * **Sampled, cost-bounded ingestion** ([`SampledDriftMonitor`], [`should_sample`]): a sampled
//!   stream of live turns feeds the detector — deterministic every-Nth sampling, no RNG.
//! * **Provider-silent-update tripwire** ([`provider_silent_update`]): a frozen tripwire set is
//!   re-scored; a shift with *no control-plane change on record* isolates "the provider changed the
//!   model under us" from "we changed something".
//! * **Auto-ticket / auto-rollback seam** ([`DriftResponder`]): on confirmed drift, open a ticket and
//!   (per policy) roll back to last-known-good — the production side effects behind a trait.
//!
//! Deterministic; reuses [`ainxt_eval::stats`] for the tripwire significance test.

use ainxt_eval::stats::{welch_t_test, SampleStats};
use serde::{Deserialize, Serialize};

// ===========================================================================================
// CUSUM sequential change-point
// ===========================================================================================

/// A detected change-point.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ChangePoint {
    /// The stream index (0-based) at which the alarm fired.
    pub at_index: u64,
    /// The accumulated CUSUM statistic at the alarm (how far past the decision interval).
    pub statistic: f64,
    /// True = a downward (quality-drop) shift; false = an upward shift.
    pub downward: bool,
}

/// A streaming tabular CUSUM detector for a shift in the mean of a quality stream. Tuned by a
/// reference slack `k` (half the smallest shift worth detecting) and a decision interval `h`
/// (larger = fewer false alarms, slower detection). The downward side is the quality-regression
/// signal a payments platform cares about; the upward side is reported too (a suspicious *jump* can
/// signal a scoring/judge change).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Cusum {
    /// In-control (known-good baseline) mean.
    pub mean0: f64,
    /// Reference slack in metric units.
    pub k: f64,
    /// Decision interval (alarm threshold) in metric units.
    pub h: f64,
    // running state
    s_low: f64,
    s_high: f64,
    index: u64,
}

impl Cusum {
    /// A CUSUM around `mean0` with explicit slack `k` and decision interval `h`.
    pub fn new(mean0: f64, k: f64, h: f64) -> Self {
        Cusum {
            mean0,
            k,
            h,
            s_low: 0.0,
            s_high: 0.0,
            index: 0,
        }
    }

    /// Tune from the baseline SD: detect a shift of `k_sigma` SDs with a decision interval of
    /// `h_sigma` SDs (classic defaults k_sigma=0.5, h_sigma=5.0).
    pub fn from_sigma(mean0: f64, sigma: f64, k_sigma: f64, h_sigma: f64) -> Self {
        Cusum::new(mean0, k_sigma * sigma, h_sigma * sigma)
    }

    /// Fold one observation in; returns a [`ChangePoint`] the moment either side crosses `h`. On an
    /// alarm the crossing side resets so the monitor keeps watching for the next shift.
    pub fn observe(&mut self, x: f64) -> Option<ChangePoint> {
        let i = self.index;
        self.index += 1;
        // Downward accumulator: grows when x falls below (mean0 − k).
        self.s_low = (self.s_low + (self.mean0 - self.k) - x).max(0.0);
        // Upward accumulator: grows when x rises above (mean0 + k).
        self.s_high = (self.s_high + x - (self.mean0 + self.k)).max(0.0);
        if self.s_low > self.h {
            let stat = self.s_low;
            self.s_low = 0.0;
            return Some(ChangePoint {
                at_index: i,
                statistic: stat,
                downward: true,
            });
        }
        if self.s_high > self.h {
            let stat = self.s_high;
            self.s_high = 0.0;
            return Some(ChangePoint {
                at_index: i,
                statistic: stat,
                downward: false,
            });
        }
        None
    }

    /// Current downward statistic (for observability dashboards).
    pub fn downward_statistic(&self) -> f64 {
        self.s_low
    }
    pub fn upward_statistic(&self) -> f64 {
        self.s_high
    }
}

// ===========================================================================================
// Cost-bounded sampling + wired monitor
// ===========================================================================================

/// Deterministic every-Nth sampling decision (no RNG): sample when `seq_index` is a multiple of
/// `rate_denom`. `rate_denom == 0` samples nothing.
pub fn should_sample(seq_index: u64, rate_denom: u64) -> bool {
    rate_denom != 0 && seq_index % rate_denom == 0
}

/// The production side effects of a confirmed drift, behind a trait (auto-ticket + auto-rollback).
pub trait DriftResponder {
    /// Open a ticket against the current artifact.
    fn open_ticket(&mut self, summary: &str);
    /// Roll back to the last-known-good artifact (per policy). Returns whether a rollback occurred.
    fn rollback_last_good(&mut self) -> bool;
}

/// A drift monitor wired to a sampled live-traffic stream: it samples turns, feeds the CUSUM, and on a
/// downward change-point invokes the responder (auto-ticket, and auto-rollback if `auto_rollback`).
#[derive(Debug, Clone)]
pub struct SampledDriftMonitor {
    cusum: Cusum,
    sample_rate: u64,
    seq: u64,
    /// Whether a downward change-point triggers an auto-rollback (vs ticket-only).
    pub auto_rollback: bool,
    /// A label for the artifact under watch (goes into the ticket).
    pub artifact: String,
}

impl SampledDriftMonitor {
    pub fn new(cusum: Cusum, sample_rate: u64, auto_rollback: bool, artifact: &str) -> Self {
        SampledDriftMonitor {
            cusum,
            sample_rate,
            seq: 0,
            auto_rollback,
            artifact: artifact.to_string(),
        }
    }

    /// Observe one live turn's quality. Only sampled turns feed the detector (cost-bounded). Returns
    /// the change-point if one fired on this (sampled) turn.
    pub fn observe(&mut self, quality: f64) -> Option<ChangePoint> {
        let idx = self.seq;
        self.seq += 1;
        if !should_sample(idx, self.sample_rate) {
            return None;
        }
        self.cusum.observe(quality)
    }

    /// Observe a turn and, on a downward change-point, drive the responder (auto-ticket + optional
    /// auto-rollback). Returns the action taken.
    pub fn observe_and_respond(
        &mut self,
        quality: f64,
        responder: &mut dyn DriftResponder,
    ) -> DriftAction {
        match self.observe(quality) {
            Some(cp) if cp.downward => {
                responder.open_ticket(&format!(
                    "quality drift on '{}': downward change-point at sampled index {} (stat {:.2})",
                    self.artifact, cp.at_index, cp.statistic
                ));
                if self.auto_rollback {
                    let rolled = responder.rollback_last_good();
                    DriftAction::TicketedAndRolledBack {
                        change_point: cp,
                        rolled,
                    }
                } else {
                    DriftAction::Ticketed { change_point: cp }
                }
            }
            Some(cp) => DriftAction::UpwardAnomaly { change_point: cp },
            None => DriftAction::None,
        }
    }
}

/// What the wired monitor did on a turn.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DriftAction {
    None,
    /// A downward drift opened a ticket (rollback not enabled).
    Ticketed {
        change_point: ChangePoint,
    },
    /// A downward drift opened a ticket and rolled back.
    TicketedAndRolledBack {
        change_point: ChangePoint,
        rolled: bool,
    },
    /// An upward jump was flagged (possible judge/scoring change) — reported, not rolled back.
    UpwardAnomaly {
        change_point: ChangePoint,
    },
}

// ===========================================================================================
// Provider-silent-update tripwire
// ===========================================================================================

/// The provider-silent-update verdict.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ProviderVerdict {
    /// The frozen tripwire scores held — no shift.
    Stable { p_value: f64 },
    /// A significant shift AND no control-plane change on record → the provider changed the model.
    SilentProviderUpdate {
        p_value: f64,
        baseline_mean: f64,
        current_mean: f64,
    },
    /// A significant shift explained by a recorded control-plane change (expected, not a provider issue).
    ExplainedByChange { p_value: f64 },
    /// Not enough tripwire data to decide.
    Indeterminate(String),
}

impl ProviderVerdict {
    pub fn is_silent_update(&self) -> bool {
        matches!(self, ProviderVerdict::SilentProviderUpdate { .. })
    }
}

/// Re-run a frozen tripwire set against a (cloud) model and test whether its scores shifted. A shift
/// with `control_plane_changed == false` isolates a silent provider model-swap from our own changes.
pub fn provider_silent_update(
    baseline_scores: &[f64],
    current_scores: &[f64],
    control_plane_changed: bool,
    alpha: f64,
) -> ProviderVerdict {
    let b = SampleStats::from_slice(baseline_scores);
    let c = SampleStats::from_slice(current_scores);
    let test = match welch_t_test(&b, &c) {
        Some(t) => t,
        None => {
            return ProviderVerdict::Indeterminate(format!(
                "tripwire too small / no variance: baseline n={}, current n={}",
                b.n, c.n
            ))
        }
    };
    if test.p_value >= alpha {
        return ProviderVerdict::Stable {
            p_value: test.p_value,
        };
    }
    if control_plane_changed {
        ProviderVerdict::ExplainedByChange {
            p_value: test.p_value,
        }
    } else {
        ProviderVerdict::SilentProviderUpdate {
            p_value: test.p_value,
            baseline_mean: b.mean,
            current_mean: c.mean,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cusum_flags_a_sustained_drop_not_single_noise() {
        // Baseline ~90 with noise, then a sustained drop to ~75.
        let mut c = Cusum::from_sigma(90.0, 3.0, 0.5, 5.0);
        let mut alarms = Vec::new();
        // 40 in-control samples.
        for i in 0..40 {
            let x = 90.0 + if i % 2 == 0 { 1.0 } else { -1.0 };
            if let Some(cp) = c.observe(x) {
                alarms.push(cp);
            }
        }
        assert!(
            alarms.is_empty(),
            "in-control noise must not alarm: {alarms:?}"
        );
        // Sustained regression.
        let mut fired = None;
        for i in 40..120 {
            let x = 75.0 + if i % 2 == 0 { 1.0 } else { -1.0 };
            if let Some(cp) = c.observe(x) {
                fired = Some(cp);
                break;
            }
        }
        let cp = fired.expect("a sustained 15-point drop must alarm");
        assert!(cp.downward, "the alarm must be a downward shift");
        assert!(
            cp.at_index >= 40,
            "change-point after the shift began: {}",
            cp.at_index
        );
    }

    #[test]
    fn cusum_does_not_flap_on_a_single_spike() {
        let mut c = Cusum::from_sigma(90.0, 3.0, 0.5, 5.0);
        let mut alarms = 0;
        for i in 0..100 {
            // one lone below-par turn (~3σ) every 25, otherwise fine: a transient dip, not a
            // sustained shift — the accumulator rises then decays back below the decision interval.
            let x = if i % 25 == 0 { 80.0 } else { 90.0 };
            if c.observe(x).is_some() {
                alarms += 1;
            }
        }
        assert_eq!(
            alarms, 0,
            "isolated transient dips must not trip the sequential detector"
        );
    }

    #[test]
    fn sampling_is_deterministic_and_cost_bounded() {
        assert!(should_sample(0, 10));
        assert!(should_sample(10, 10));
        assert!(!should_sample(5, 10));
        assert!(!should_sample(3, 0), "rate 0 samples nothing");
        // Over 100 turns at rate 10, exactly 10 are sampled.
        let sampled = (0..100u64).filter(|&i| should_sample(i, 10)).count();
        assert_eq!(sampled, 10);
    }

    #[test]
    fn wired_monitor_tickets_and_rolls_back_on_downward_drift() {
        #[derive(Default)]
        struct Resp {
            tickets: Vec<String>,
            rollbacks: u32,
        }
        impl DriftResponder for Resp {
            fn open_ticket(&mut self, s: &str) {
                self.tickets.push(s.to_string());
            }
            fn rollback_last_good(&mut self) -> bool {
                self.rollbacks += 1;
                true
            }
        }
        // Sample every turn (rate 1) so the drift is fed promptly.
        let cusum = Cusum::from_sigma(90.0, 3.0, 0.5, 4.0);
        let mut mon = SampledDriftMonitor::new(cusum, 1, true, "role-analyst@v7");
        let mut resp = Resp::default();
        let mut acted = false;
        for i in 0..200 {
            let q = if i < 30 {
                90.0 + if i % 2 == 0 { 1.0 } else { -1.0 }
            } else {
                72.0 + if i % 2 == 0 { 1.0 } else { -1.0 }
            };
            if let DriftAction::TicketedAndRolledBack { rolled, .. } =
                mon.observe_and_respond(q, &mut resp)
            {
                assert!(rolled);
                acted = true;
                break;
            }
        }
        assert!(acted, "a sustained drift must ticket + roll back");
        assert_eq!(resp.tickets.len(), 1);
        assert_eq!(resp.rollbacks, 1);
    }

    #[test]
    fn provider_silent_update_isolated_from_our_changes() {
        let baseline = [90.0, 91.0, 89.0, 92.0, 90.0, 91.0, 88.0, 90.0];
        let shifted = [80.0, 81.0, 79.0, 82.0, 80.0, 81.0, 78.0, 80.0];
        // Shift with NO control-plane change → silent provider update.
        let v = provider_silent_update(&baseline, &shifted, false, 0.05);
        assert!(
            v.is_silent_update(),
            "an unexplained shift is a silent provider update: {v:?}"
        );
        // Same shift WITH a recorded control-plane change → explained (not the provider's fault).
        let v2 = provider_silent_update(&baseline, &shifted, true, 0.05);
        assert!(
            matches!(v2, ProviderVerdict::ExplainedByChange { .. }),
            "{v2:?}"
        );
        // No shift → stable.
        let v3 = provider_silent_update(&baseline, &baseline, false, 0.05);
        assert!(matches!(v3, ProviderVerdict::Stable { .. }), "{v3:?}");
    }

    #[test]
    fn change_point_serializes() {
        let cp = ChangePoint {
            at_index: 7,
            statistic: 12.5,
            downward: true,
        };
        let j = serde_json::to_string(&cp).unwrap();
        assert_eq!(serde_json::from_str::<ChangePoint>(&j).unwrap(), cp);
    }
}
