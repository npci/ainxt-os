// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! The **optional Tier-3 Breaker differential / invariant run** (`CODE_REVIEW_PIPELINE.md` §3 Tier 3
//! §4 stage 8's "high-risk escalation": *"Tier 3 edits may trigger a scoped Breaker differential
//! run — comparing behavior against a reference implementation … as an additional regression oracle"*).
//!
//! This is a **scoped, Tier-3-only** oracle: for the highest-risk edits (critical-path modules,
//! public-API breaks) the pipeline may compare the edited code's behavior against a reference
//! implementation (the Rust-migration shadow-mode comparator is the concrete existing use of this
//! pattern) and check invariants the standalone regression stage cannot. It never runs below Tier 3 —
//! spending a differential run on a docstring typo is exactly the waste §3 forbids.
//!
//! The **real** oracle is infra: it executes both implementations on generated / recorded inputs and
//! diffs the outputs (needs a sandbox + a reference impl + input corpus). Offline, [`ScriptedBreaker`]
//! is a deterministic stand-in that returns only the divergences it was given — it never manufactures
//! a "behaviorally identical" verdict it did not actually establish, so a missing oracle is honestly
//! "not run", never a false clean.

use crate::risk::RiskTier;
use serde::{Deserialize, Serialize};

/// The class of a Breaker finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BreakerKind {
    /// The edited code produced a different output than the reference implementation for some input.
    Divergence,
    /// A stated invariant (metamorphic / algebraic relation) failed to hold on the edited code.
    InvariantViolation,
}

/// One finding from a differential / invariant run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BreakerFinding {
    pub kind: BreakerKind,
    /// The concrete, un-paraphrased failure ("input `amount=-1` → edited returns 0, reference panics").
    pub detail: String,
    /// A divergence on a Tier-3 (critical-path) edit is gating; an invariant advisory may not be.
    pub gating: bool,
}

/// A Breaker run's report over one candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BreakerReport {
    pub findings: Vec<BreakerFinding>,
}

impl BreakerReport {
    /// Whether any gating divergence/invariant failure was found (the human hand-off must surface it).
    #[must_use]
    pub fn has_gating_finding(&self) -> bool {
        self.findings.iter().any(|f| f.gating)
    }
}

/// The seam a real differential / invariant oracle (the Breaker) implements. **Infra**: executes the
/// candidate + a reference implementation on inputs and diffs behavior. Offline, use
/// [`ScriptedBreaker`].
pub trait DifferentialOracle: Send + Sync {
    /// Compare the `candidate` file set against the deployment's reference behavior, returning any
    /// divergences / invariant violations.
    fn differential_check(
        &self,
        baseline: &[(String, String)],
        candidate: &[(String, String)],
    ) -> Vec<BreakerFinding>;
}

/// A deterministic offline [`DifferentialOracle`]: it reports a gating [`BreakerKind::Divergence`] for
/// each `marker` that appears in the candidate but not the baseline (a stand-in for "this changed
/// behavior in a way the reference disagrees with"). With no markers it finds nothing — but a
/// *no-finding* result is only meaningful because the scripted oracle was actually consulted; a
/// *missing* oracle is reported as "not run", never as clean (see [`run_if_tier3`]).
#[derive(Debug, Clone, Default)]
pub struct ScriptedBreaker {
    divergence_markers: Vec<String>,
    invariant_markers: Vec<String>,
}

impl ScriptedBreaker {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A gating divergence is reported when `marker` is newly present in the candidate.
    #[must_use]
    pub fn with_divergence_marker(mut self, marker: impl Into<String>) -> Self {
        self.divergence_markers.push(marker.into());
        self
    }

    /// A (non-gating advisory) invariant violation is reported when `marker` is newly present.
    #[must_use]
    pub fn with_invariant_marker(mut self, marker: impl Into<String>) -> Self {
        self.invariant_markers.push(marker.into());
        self
    }
}

impl DifferentialOracle for ScriptedBreaker {
    fn differential_check(
        &self,
        baseline: &[(String, String)],
        candidate: &[(String, String)],
    ) -> Vec<BreakerFinding> {
        let base: String = baseline
            .iter()
            .map(|(_, c)| c.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        let cand: String = candidate
            .iter()
            .map(|(_, c)| c.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        let mut out = Vec::new();
        for m in &self.divergence_markers {
            if cand.contains(m.as_str()) && !base.contains(m.as_str()) {
                out.push(BreakerFinding {
                    kind: BreakerKind::Divergence,
                    detail: format!("candidate diverges from the reference at `{m}`"),
                    gating: true,
                });
            }
        }
        for m in &self.invariant_markers {
            if cand.contains(m.as_str()) && !base.contains(m.as_str()) {
                out.push(BreakerFinding {
                    kind: BreakerKind::InvariantViolation,
                    detail: format!("invariant `{m}` no longer holds on the candidate"),
                    gating: false,
                });
            }
        }
        out
    }
}

/// Run the Breaker **only for Tier-3 edits** (`§3` — scoped to the highest risk). Returns:
/// - `None` when `tier` is below [`RiskTier::HighRisk`] — the oracle is *not consulted* (and the
///   caller must not present that as "differentially clean");
/// - `Some(report)` at Tier 3, carrying whatever the oracle found (possibly empty).
#[must_use]
pub fn run_if_tier3(
    tier: RiskTier,
    baseline: &[(String, String)],
    candidate: &[(String, String)],
    oracle: &dyn DifferentialOracle,
) -> Option<BreakerReport> {
    if tier != RiskTier::HighRisk {
        return None;
    }
    Some(BreakerReport {
        findings: oracle.differential_check(baseline, candidate),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files(marker: &str) -> Vec<(String, String)> {
        vec![(
            "settlement/x.rs".into(),
            format!("fn settle() {{ {marker} }}\n"),
        )]
    }

    #[test]
    fn not_consulted_below_tier3() {
        let oracle = ScriptedBreaker::new().with_divergence_marker("BAD");
        for tier in [RiskTier::Trivial, RiskTier::Local, RiskTier::Moderate] {
            assert!(run_if_tier3(tier, &files("ok"), &files("BAD"), &oracle).is_none());
        }
    }

    #[test]
    fn tier3_divergence_is_a_gating_finding() {
        let oracle = ScriptedBreaker::new().with_divergence_marker("BAD");
        let report =
            run_if_tier3(RiskTier::HighRisk, &files("ok"), &files("BAD"), &oracle).unwrap();
        assert!(report.has_gating_finding());
        assert_eq!(report.findings[0].kind, BreakerKind::Divergence);
    }

    #[test]
    fn tier3_no_marker_is_consulted_but_finds_nothing() {
        let oracle = ScriptedBreaker::new().with_divergence_marker("BAD");
        let report = run_if_tier3(RiskTier::HighRisk, &files("ok"), &files("ok"), &oracle).unwrap();
        assert!(report.findings.is_empty());
        assert!(!report.has_gating_finding());
    }
}
