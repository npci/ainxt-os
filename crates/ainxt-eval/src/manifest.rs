// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Git-native eval-set manifests + recursive gating of the eval sets and Judge themselves
//! (EVAL_PLATFORM.md §2/§11, ADR-026/2).
//!
//! Eval sets and Judges are **definitions** (ADR-026), so they are gated like any other change — the
//! instrument evaluates *itself*, and cannot silently drift or rot without a reviewable, measured
//! change. This module provides:
//!
//! * [`PreRegistration`] — the metrics, direction, non-inferiority margins, primary/secondary split,
//!   power/α, and analysis method, declared **before** the run (anti-p-hacking, §5.1). Content-hashed
//!   into the manifest so metric-shopping is structurally impossible.
//! * [`EvalSetManifest`] — the PII-free, git-reviewable definition binding a set's identity/version to
//!   its pre-registration and its sealed `content_commitment`.
//! * [`meta_gate_eval_set`] — the recursive gate on the *set itself*: pre-registration is well-formed
//!   and the set is **powered** to detect its own pre-registered MDE (an underpowered set fails as a
//!   defect, never a falsely-confident pass).
//!
//! Deterministic; digest via `sha2`; power via [`crate::stats`].

use crate::stats::is_powered;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Whether a higher or lower value of a metric is better (governs the non-inferiority direction).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Direction {
    HigherIsBetter,
    LowerIsBetter,
}

/// One pre-registered metric.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricSpec {
    pub name: String,
    pub direction: Direction,
    /// Non-inferiority margin in the metric's own units (how much worse is "not a regression"). ≥ 0.
    pub noninferiority_margin: f64,
    /// The minimum detectable effect the set must be powered to see (metric units). > 0.
    pub mde: f64,
    /// Primary metrics gate; secondary metrics are reported but do not block on their own.
    pub primary: bool,
}

/// The pre-registration declared before a run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PreRegistration {
    pub metrics: Vec<MetricSpec>,
    /// Target statistical power (default 0.8).
    pub power: f64,
    /// Significance level α (default 0.05).
    pub alpha: f64,
    /// The analysis method (e.g. "paired-noninferiority-bh").
    pub method: String,
}

impl PreRegistration {
    /// Is the pre-registration well-formed? (≥1 metric, ≥1 primary, valid power/α, non-negative
    /// margins, positive MDEs.)
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errs = Vec::new();
        if self.metrics.is_empty() {
            errs.push("no metrics declared".into());
        }
        if !self.metrics.iter().any(|m| m.primary) {
            errs.push("no primary metric declared".into());
        }
        if !(0.0..1.0).contains(&self.alpha) || self.alpha <= 0.0 {
            errs.push(format!("alpha {} must be in (0,1)", self.alpha));
        }
        if !(0.0..1.0).contains(&self.power) || self.power <= 0.5 {
            errs.push(format!("power {} must be in (0.5,1)", self.power));
        }
        for m in &self.metrics {
            if m.noninferiority_margin < 0.0 {
                errs.push(format!("metric {} has a negative margin", m.name));
            }
            if m.mde <= 0.0 {
                errs.push(format!("metric {} has a non-positive MDE", m.name));
            }
        }
        if errs.is_empty() {
            Ok(())
        } else {
            Err(errs)
        }
    }

    /// A deterministic content hash of the pre-registration (so the analysis is fixed before data).
    pub fn digest(&self) -> String {
        let mut h = Sha256::new();
        h.update(b"ainxt-eval-prereg\0");
        h.update(self.power.to_le_bytes());
        h.update(self.alpha.to_le_bytes());
        h.update((self.method.len() as u64).to_le_bytes());
        h.update(self.method.as_bytes());
        for m in &self.metrics {
            h.update((m.name.len() as u64).to_le_bytes());
            h.update(m.name.as_bytes());
            h.update([matches!(m.direction, Direction::HigherIsBetter) as u8]);
            h.update(m.noninferiority_margin.to_le_bytes());
            h.update(m.mde.to_le_bytes());
            h.update([m.primary as u8]);
        }
        let digest = h.finalize();
        let mut out = String::with_capacity(64);
        for b in digest {
            out.push_str(&format!("{b:02x}"));
        }
        out
    }
}

/// The git-reviewable eval-set manifest (a definition, ADR-026).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvalSetManifest {
    pub set_id: String,
    pub version: String,
    pub dimension: String,
    /// The Merkle content commitment over the sealed corpus (see [`crate::integrity`]).
    pub content_commitment: String,
    pub pre_registration: PreRegistration,
}

impl EvalSetManifest {
    /// The manifest's own content digest (identity + commitment + pre-registration).
    pub fn digest(&self) -> String {
        let mut h = Sha256::new();
        h.update(b"ainxt-eval-manifest\0");
        for p in [
            self.set_id.as_str(),
            self.version.as_str(),
            self.dimension.as_str(),
            self.content_commitment.as_str(),
        ] {
            h.update((p.len() as u64).to_le_bytes());
            h.update(p.as_bytes());
        }
        h.update(self.pre_registration.digest().as_bytes());
        let digest = h.finalize();
        let mut out = String::with_capacity(64);
        for b in digest {
            out.push_str(&format!("{b:02x}"));
        }
        out
    }
}

/// The recursive gate's verdict on the eval SET itself.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum MetaGateOutcome {
    Pass,
    Fail(Vec<String>),
}

impl MetaGateOutcome {
    pub fn is_pass(&self) -> bool {
        matches!(self, MetaGateOutcome::Pass)
    }
}

/// Recursively gate the eval SET: its pre-registration must be well-formed AND it must be powered to
/// detect every primary metric's pre-registered MDE at the declared power, given `n_per_arm` cases and
/// the observed per-metric sample SD (`primary_sds`, aligned to the primary metrics in order). An
/// underpowered set is a defect (ADR-010 test #4), not a pass.
pub fn meta_gate_eval_set(
    manifest: &EvalSetManifest,
    n_per_arm: usize,
    primary_sds: &[f64],
) -> MetaGateOutcome {
    let mut reasons = Vec::new();
    if let Err(mut e) = manifest.pre_registration.validate() {
        reasons.append(&mut e);
    }
    let primaries: Vec<&MetricSpec> = manifest
        .pre_registration
        .metrics
        .iter()
        .filter(|m| m.primary)
        .collect();
    if !primaries.is_empty() && primary_sds.len() == primaries.len() {
        for (m, &sd) in primaries.iter().zip(primary_sds.iter()) {
            if !is_powered(
                n_per_arm,
                sd,
                m.mde,
                manifest.pre_registration.alpha,
                manifest.pre_registration.power,
            ) {
                reasons.push(format!(
                    "underpowered: metric '{}' cannot detect its MDE {} at n={}/arm, sd={}",
                    m.name, m.mde, n_per_arm, sd
                ));
            }
        }
    } else if !primaries.is_empty() {
        reasons.push(format!(
            "power check needs one SD per primary metric ({} metrics, {} sds)",
            primaries.len(),
            primary_sds.len()
        ));
    }
    if reasons.is_empty() {
        MetaGateOutcome::Pass
    } else {
        MetaGateOutcome::Fail(reasons)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prereg() -> PreRegistration {
        PreRegistration {
            metrics: vec![
                MetricSpec {
                    name: "correctness".into(),
                    direction: Direction::HigherIsBetter,
                    noninferiority_margin: 2.0,
                    mde: 3.0,
                    primary: true,
                },
                MetricSpec {
                    name: "verbosity".into(),
                    direction: Direction::LowerIsBetter,
                    noninferiority_margin: 5.0,
                    mde: 5.0,
                    primary: false,
                },
            ],
            power: 0.8,
            alpha: 0.05,
            method: "paired-noninferiority-bh".into(),
        }
    }

    fn manifest() -> EvalSetManifest {
        EvalSetManifest {
            set_id: "role-analyst-correctness".into(),
            version: "v7".into(),
            dimension: "correctness".into(),
            content_commitment: "abc123".into(),
            pre_registration: prereg(),
        }
    }

    #[test]
    fn prereg_validation_catches_defects() {
        assert!(prereg().validate().is_ok());
        let mut bad = prereg();
        bad.metrics.iter_mut().for_each(|m| m.primary = false);
        let e = bad.validate().unwrap_err();
        assert!(e.iter().any(|s| s.contains("primary")), "{e:?}");
        let mut bad2 = prereg();
        bad2.alpha = 1.5;
        assert!(bad2.validate().is_err());
    }

    #[test]
    fn prereg_digest_is_content_sensitive() {
        let a = prereg().digest();
        let mut b = prereg();
        b.metrics[0].noninferiority_margin = 3.0;
        assert_ne!(
            a,
            b.digest(),
            "changing a margin changes the pre-registration digest"
        );
        assert_eq!(a, prereg().digest(), "stable for identical content");
    }

    #[test]
    fn manifest_digest_binds_commitment_and_prereg() {
        let a = manifest().digest();
        let mut b = manifest();
        b.content_commitment = "different".into();
        assert_ne!(
            a,
            b.digest(),
            "a swapped corpus commitment changes the manifest digest"
        );
    }

    #[test]
    fn meta_gate_fails_an_underpowered_set() {
        let m = manifest();
        // sd=15, MDE=3, only 10 cases/arm → underpowered.
        let out = meta_gate_eval_set(&m, 10, &[15.0]);
        assert!(
            !out.is_pass(),
            "underpowered set must fail as a defect: {out:?}"
        );
        if let MetaGateOutcome::Fail(r) = out {
            assert!(r.iter().any(|s| s.contains("underpowered")));
        }
        // With plenty of cases it is powered → pass.
        let out2 = meta_gate_eval_set(&m, 1000, &[15.0]);
        assert!(
            out2.is_pass(),
            "a well-powered, well-formed set passes: {out2:?}"
        );
    }

    #[test]
    fn meta_gate_fails_a_malformed_prereg() {
        let mut m = manifest();
        m.pre_registration.power = 0.3; // below the 0.5 floor
        let out = meta_gate_eval_set(&m, 1000, &[15.0]);
        assert!(!out.is_pass());
    }

    #[test]
    fn manifest_serializes_round_trip() {
        let m = manifest();
        let j = serde_json::to_string(&m).unwrap();
        let back: EvalSetManifest = serde_json::from_str(&j).unwrap();
        assert_eq!(back, m);
    }
}
