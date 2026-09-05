// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! **Risk classification & stage selection** (`docs/architecture/CODE_REVIEW_PIPELINE.md` §3).
//!
//! Running twelve stages on a docstring typo trains users to distrust the gate and burns spend; a
//! settlement-path change must be forced through the full gate plus a human. A deterministic
//! classifier (no LLM call to decide *whether* to run stages) computes a [`RiskTier`] from graph-
//! derived signals before stage 1 runs.
//!
//! Two invariants are load-bearing:
//! - **Re-classification only escalates.** Within one pipeline run, a self-heal round that touches a
//!   critical-path module or trips a SAST finding can move risk *up*, never *down* — a de-escalation
//!   would be exactly the self-graded relief the anti-sycophancy design forbids ([`RiskTier::escalate`]).
//! - **Tier 3 forces autonomy down to `assisted`** — a human approves even at Confidence 100
//!   ([`RiskTier::forces_hitl`]).

use ainxt_semantic::ladder::Rung;
use serde::{Deserialize, Serialize};

/// The four risk tiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskTier {
    /// Doc/comment/formatting only — compile-sanity + lint.
    Trivial,
    /// Single function/file, no signature/API change, small blast radius, non-critical.
    Local,
    /// Multi-file, signature change, or a shared module.
    Moderate,
    /// Critical-path, cross-service blast radius, public-API break, or any SAST finding.
    HighRisk,
}

impl RiskTier {
    /// Tier 3 forces a human approval regardless of score (autonomy down to `assisted`).
    #[must_use]
    pub fn forces_hitl(self) -> bool {
        self == RiskTier::HighRisk
    }

    /// The escalate-only combinator: the higher of two tiers. Used for mid-run re-classification.
    #[must_use]
    pub fn escalate(self, other: RiskTier) -> RiskTier {
        self.max(other)
    }
}

/// The AST-diff class of the edit — its executable-semantics weight.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffClass {
    /// Comment/doc/formatting only — no executable-semantics change.
    DocOnly,
    /// Local logic change inside one function.
    LocalLogic,
    /// A signature or public-API change.
    SignatureApi,
    /// A new external dependency introduced.
    NewDependency,
}

/// The deterministic inputs to classification — all computed from the Context Fabric graphs.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RiskInputs {
    pub diff_class: DiffClass,
    /// Direct fan-out from the touched symbols (blast radius).
    pub blast_fan_out: usize,
    /// Number of files touched by the edit.
    pub files_touched: usize,
    /// The touched module carries a critical-path tag (`payments`/`settlement`/`ledger`/`compliance`).
    pub critical_path: bool,
    /// Fraction `[0,1]` of the blast radius covered by tests.
    pub coverage_overlap: f64,
    /// The lowest (least-trusted) edit-engine rung used across the edit set.
    pub rung: Rung,
    /// A prior round on this edit already tripped a SAST/architecture finding (escalator only).
    pub prior_finding: bool,
}

/// Classify an edit into a risk tier. Deterministic; no LLM.
#[must_use]
pub fn classify(inp: &RiskInputs) -> RiskTier {
    // Tier 3: the non-negotiable escalators.
    if inp.critical_path || inp.prior_finding {
        return RiskTier::HighRisk;
    }
    // A large blast radius / public-API break is Tier 3.
    if inp.blast_fan_out >= 20 {
        return RiskTier::HighRisk;
    }

    // Tier 0: doc-only with no semantics change and a trivially-local footprint.
    if inp.diff_class == DiffClass::DocOnly && inp.files_touched <= 1 && inp.blast_fan_out == 0 {
        return RiskTier::Trivial;
    }

    // Tier 2: multi-file, a signature/API change, a new dependency, or a text-patch-rung edit
    // (lower fidelity ⇒ more scrutiny), or a non-trivial blast radius.
    let moderate = inp.files_touched > 1
        || matches!(
            inp.diff_class,
            DiffClass::SignatureApi | DiffClass::NewDependency
        )
        || inp.rung == Rung::TextPatch
        || inp.blast_fan_out >= 5;
    if moderate {
        return RiskTier::Moderate;
    }

    RiskTier::Local
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> RiskInputs {
        RiskInputs {
            diff_class: DiffClass::LocalLogic,
            blast_fan_out: 0,
            files_touched: 1,
            critical_path: false,
            coverage_overlap: 1.0,
            rung: Rung::Ast,
            prior_finding: false,
        }
    }

    #[test]
    fn doc_only_local_edit_is_trivial() {
        let mut i = base();
        i.diff_class = DiffClass::DocOnly;
        assert_eq!(classify(&i), RiskTier::Trivial);
    }

    #[test]
    fn plain_local_logic_is_tier_1() {
        assert_eq!(classify(&base()), RiskTier::Local);
    }

    #[test]
    fn signature_change_is_moderate() {
        let mut i = base();
        i.diff_class = DiffClass::SignatureApi;
        assert_eq!(classify(&i), RiskTier::Moderate);
    }

    #[test]
    fn multi_file_is_moderate() {
        let mut i = base();
        i.files_touched = 3;
        assert_eq!(classify(&i), RiskTier::Moderate);
    }

    #[test]
    fn critical_path_forces_high_risk_even_when_tiny() {
        let mut i = base();
        i.diff_class = DiffClass::DocOnly; // even a doc edit...
        i.critical_path = true; // ...on a settlement module is Tier 3.
        assert_eq!(classify(&i), RiskTier::HighRisk);
        assert!(classify(&i).forces_hitl());
    }

    #[test]
    fn prior_finding_only_escalates() {
        let mut i = base();
        i.prior_finding = true;
        assert_eq!(classify(&i), RiskTier::HighRisk);
    }

    #[test]
    fn large_blast_radius_is_high_risk() {
        let mut i = base();
        i.blast_fan_out = 25;
        assert_eq!(classify(&i), RiskTier::HighRisk);
    }

    #[test]
    fn text_patch_rung_bumps_to_moderate() {
        let mut i = base();
        i.rung = Rung::TextPatch;
        assert_eq!(classify(&i), RiskTier::Moderate);
    }

    #[test]
    fn escalate_never_decreases() {
        assert_eq!(
            RiskTier::Local.escalate(RiskTier::HighRisk),
            RiskTier::HighRisk
        );
        // Re-classification cannot de-escalate.
        assert_eq!(
            RiskTier::HighRisk.escalate(RiskTier::Trivial),
            RiskTier::HighRisk
        );
    }
}
