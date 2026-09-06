// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! DPDP DPIA-per-feature promotion gate (FI-06; `REGULATED_FI_COMPLIANCE_OPS.md` §4.1).
//!
//! Under DPDP §10 an SDF-class fiduciary must complete a Data Protection Impact Assessment *before* a
//! personal-data feature reaches production. This is not a form filed once: it is a **precondition of
//! promotion**, enforced as a gate. A feature whose `data_class_ceiling` reaches personal data (or
//! whose capabilities touch a personal-data connector) **must reference an `approved`, current DPIA**
//! — no reference, or a DPIA whose approval predates a material data-processing change, blocks the
//! promotion to `env/prod`.
//!
//! "Current" is enforced by **content hash**: the DPIA is approved against a hash of the feature's
//! `data_class_ceiling` + `capabilities` + `purpose`; if any of those change, the recomputed hash no
//! longer matches and the approval is **invalidated** (the same diff-and-re-approve discipline used
//! for the marketplace). A feature cannot silently expand its data processing beyond what the DPO
//! assessed. Pure/deterministic — the DPIA is a control-plane definition (Q2, git), here a serde value.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use ainxt_types::DataClass;

/// A feature's data-processing profile — the inputs that determine whether a DPIA is required and what
/// the DPIA must be current against. This mirrors the definition fields (Role/agent/skill/workflow)
/// that the promotion machinery already versions (ADR-026).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeatureProfile {
    pub feature_id: String,
    /// The highest data class this feature may process.
    pub data_class_ceiling: DataClass,
    /// Capabilities the feature holds (e.g. connector ids). A capability naming a personal-data
    /// connector triggers the DPIA requirement even if the ceiling were mis-set.
    pub capabilities: Vec<String>,
    /// The declared processing purpose (part of the content hash — a purpose change re-triggers DPIA).
    pub purpose: String,
}

impl FeatureProfile {
    pub fn new(feature_id: &str, data_class_ceiling: DataClass, purpose: &str) -> Self {
        Self {
            feature_id: feature_id.to_string(),
            data_class_ceiling,
            capabilities: Vec::new(),
            purpose: purpose.to_string(),
        }
    }

    pub fn with_capability(mut self, cap: &str) -> Self {
        self.capabilities.push(cap.to_string());
        self
    }

    /// Whether this feature processes personal data — the trigger for the DPIA requirement. True if
    /// the ceiling is a regulated class (PII/regulated-payment) or any capability names a personal-data
    /// connector (a substring match against `personal_data_connectors`).
    pub fn processes_personal_data(&self, personal_data_connectors: &[&str]) -> bool {
        if self.data_class_ceiling.is_regulated() {
            return true;
        }
        self.capabilities
            .iter()
            .any(|c| personal_data_connectors.iter().any(|pdc| c.contains(pdc)))
    }

    /// The content hash the DPIA is bound to: SHA-256 over ceiling + sorted capabilities + purpose.
    /// A change to any of these three invalidates a DPIA approved against the old hash.
    pub fn content_hash(&self) -> String {
        let mut caps = self.capabilities.clone();
        caps.sort();
        let mut h = Sha256::new();
        let ceiling = self.data_class_ceiling.as_str();
        h.update((ceiling.len() as u64).to_le_bytes());
        h.update(ceiling.as_bytes());
        h.update((caps.len() as u64).to_le_bytes());
        for c in &caps {
            h.update((c.len() as u64).to_le_bytes());
            h.update(c.as_bytes());
        }
        h.update((self.purpose.len() as u64).to_le_bytes());
        h.update(self.purpose.as_bytes());
        h.finalize().iter().map(|b| format!("{b:02x}")).collect::<String>()
    }
}

/// The approval status of a DPIA assessment (DPO CODEOWNERS review outcome).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DpiaStatus {
    Draft,
    Approved,
    Rejected,
}

/// A DPIA artifact (control-plane definition, PII-free — it describes *data classes*, *purposes*,
/// *risks*, *mitigations*, not actual data). Bound to a feature content hash via `approved_for_hash`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dpia {
    pub feature_id: String,
    pub status: DpiaStatus,
    /// The feature content hash this DPIA was approved against. `None` until approved.
    pub approved_for_hash: Option<String>,
    /// The DPO/reviewer who approved (audit).
    pub approver: String,
    /// Free-text risk/mitigation summary (PII-free).
    pub summary: String,
}

impl Dpia {
    /// A fresh draft DPIA for a feature.
    pub fn draft(feature_id: &str, summary: &str) -> Self {
        Self {
            feature_id: feature_id.to_string(),
            status: DpiaStatus::Draft,
            approved_for_hash: None,
            approver: String::new(),
            summary: summary.to_string(),
        }
    }

    /// Approve this DPIA against a specific feature profile (binds the content hash).
    pub fn approve_for(&mut self, profile: &FeatureProfile, approver: &str) {
        self.status = DpiaStatus::Approved;
        self.approved_for_hash = Some(profile.content_hash());
        self.approver = approver.to_string();
    }

    /// Whether this DPIA is approved AND current for `profile` (its bound hash matches).
    pub fn is_current_for(&self, profile: &FeatureProfile) -> bool {
        self.status == DpiaStatus::Approved
            && self.approved_for_hash.as_deref() == Some(profile.content_hash().as_str())
    }
}

/// Why the DPIA promotion gate refused (§4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DpiaGateRefusal {
    /// The feature processes personal data but references no DPIA at all.
    MissingDpia { feature_id: String },
    /// A DPIA is referenced but has not been approved.
    NotApproved { feature_id: String },
    /// The referenced DPIA belongs to a different feature.
    FeatureMismatch { expected: String, got: String },
    /// The DPIA's approval predates a material change (content-hash mismatch) — must re-assess.
    Stale { feature_id: String },
    /// The promotion job named a feature the gate has no registered profile for — fail-safe: an
    /// un-inventoried feature cannot be assessed for personal-data processing, so it must not reach
    /// `env/prod` (§4.1 "a precondition of promotion", not an afterthought).
    UnknownFeature { feature_id: String },
}

impl std::fmt::Display for DpiaGateRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DpiaGateRefusal::MissingDpia { feature_id } => {
                write!(
                    f,
                    "feature `{feature_id}` processes personal data with no DPIA"
                )
            }
            DpiaGateRefusal::NotApproved { feature_id } => {
                write!(f, "feature `{feature_id}` DPIA is not approved")
            }
            DpiaGateRefusal::FeatureMismatch { expected, got } => {
                write!(f, "DPIA is for `{got}`, expected `{expected}`")
            }
            DpiaGateRefusal::Stale { feature_id } => write!(
                f,
                "feature `{feature_id}` DPIA approval predates a material change (re-assess)"
            ),
            DpiaGateRefusal::UnknownFeature { feature_id } => {
                write!(
                    f,
                    "feature `{feature_id}` is not inventoried in the DPIA gate"
                )
            }
        }
    }
}

/// The gate's decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DpiaGateDecision {
    /// Promotion allowed: either the feature does not process personal data, or a current approved
    /// DPIA is present.
    Allowed,
    Blocked(DpiaGateRefusal),
}

impl DpiaGateDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, DpiaGateDecision::Allowed)
    }
}

/// FI-06: the DPIA-per-feature promotion gate. If `profile` does not process personal data, promotion
/// is allowed (no DPIA needed). Otherwise a `dpia` must be present, for this feature, approved, and
/// current (content-hash match) — else promotion to `env/prod` is blocked. `personal_data_connectors`
/// is the deployment's list of connector-id fragments that imply personal data.
pub fn dpia_promotion_gate(
    profile: &FeatureProfile,
    dpia: Option<&Dpia>,
    personal_data_connectors: &[&str],
) -> DpiaGateDecision {
    if !profile.processes_personal_data(personal_data_connectors) {
        return DpiaGateDecision::Allowed;
    }
    let Some(dpia) = dpia else {
        return DpiaGateDecision::Blocked(DpiaGateRefusal::MissingDpia {
            feature_id: profile.feature_id.clone(),
        });
    };
    if dpia.feature_id != profile.feature_id {
        return DpiaGateDecision::Blocked(DpiaGateRefusal::FeatureMismatch {
            expected: profile.feature_id.clone(),
            got: dpia.feature_id.clone(),
        });
    }
    if dpia.status != DpiaStatus::Approved {
        return DpiaGateDecision::Blocked(DpiaGateRefusal::NotApproved {
            feature_id: profile.feature_id.clone(),
        });
    }
    if !dpia.is_current_for(profile) {
        return DpiaGateDecision::Blocked(DpiaGateRefusal::Stale {
            feature_id: profile.feature_id.clone(),
        });
    }
    DpiaGateDecision::Allowed
}

/// The promotion target of a CI promotion job (§4.1). DPIA is a **precondition of promotion to
/// env/prod**, not of a dev push — a personal-data feature may iterate in dev without an approved DPIA,
/// but the promotion job that would put it in front of real data principals is blocked until the DPIA
/// is approved and current.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PromotionTarget {
    /// A dev/sandbox deploy — no real data principals; DPIA not yet required.
    Dev,
    /// A staging/UAT environment carrying real personal data — DPIA required.
    Env,
    /// Production — DPIA required.
    Prod,
}

impl PromotionTarget {
    /// Whether reaching this target requires a current, approved DPIA for a personal-data feature.
    pub fn requires_dpia(&self) -> bool {
        matches!(self, PromotionTarget::Env | PromotionTarget::Prod)
    }
}

/// FI-06 — the **DPIA-per-feature CI promotion gate** (§4.1), the seam a promotion job calls before it
/// lets a feature reach `env/prod`. It inventories the features under governance and their DPIA
/// artifacts (control-plane definitions, ADR-026); [`check`](Self::check) is the fail-closed decision
/// the promotion job gates on. Dev promotions are free; env/prod promotions of a personal-data feature
/// are **blocked** unless an approved, current (content-hash-bound) DPIA is on record. An
/// un-inventoried feature fails closed for env/prod. Pure/deterministic — no clock/rng/I/O.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DpiaCiGate {
    /// Connector-id fragments that imply personal-data processing (deployment policy).
    personal_data_connectors: Vec<String>,
    /// The features under governance, keyed by `feature_id`.
    features: BTreeMap<String, FeatureProfile>,
    /// The DPIA artifacts on record, keyed by `feature_id`.
    dpias: BTreeMap<String, Dpia>,
}

impl DpiaCiGate {
    /// A gate whose personal-data-connector policy is `personal_data_connectors`.
    pub fn new(personal_data_connectors: &[&str]) -> Self {
        Self {
            personal_data_connectors: personal_data_connectors
                .iter()
                .map(|s| s.to_string())
                .collect(),
            features: BTreeMap::new(),
            dpias: BTreeMap::new(),
        }
    }

    /// Register/replace a feature profile under governance (chainable-by-value not needed; the CI job
    /// hydrates the inventory from the control-plane store).
    pub fn register_feature(&mut self, profile: FeatureProfile) {
        self.features.insert(profile.feature_id.clone(), profile);
    }

    /// Record/replace a DPIA artifact for a feature.
    pub fn record_dpia(&mut self, dpia: Dpia) {
        self.dpias.insert(dpia.feature_id.clone(), dpia);
    }

    /// **The CI promotion-gate decision** for promoting `feature_id` to `target`. Dev → always
    /// [`DpiaGateDecision::Allowed`]. Env/Prod → fail-closed on an un-inventoried feature, else the
    /// FI-06 [`dpia_promotion_gate`] over the feature's registered profile and its DPIA of record.
    pub fn check(&self, feature_id: &str, target: PromotionTarget) -> DpiaGateDecision {
        if !target.requires_dpia() {
            return DpiaGateDecision::Allowed;
        }
        let Some(profile) = self.features.get(feature_id) else {
            return DpiaGateDecision::Blocked(DpiaGateRefusal::UnknownFeature {
                feature_id: feature_id.to_string(),
            });
        };
        let pdc: Vec<&str> = self
            .personal_data_connectors
            .iter()
            .map(String::as_str)
            .collect();
        dpia_promotion_gate(profile, self.dpias.get(feature_id), &pdc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PDC: &[&str] = &["outlook", "graph", "crm"];

    #[test]
    fn gap_ainxt_responsibleai_fi06_personal_data_feature_without_dpia_is_blocked() {
        // §4.5 test 1: a Role gains a personal-data connector with no approved DPIA → promotion blocked.
        let profile = FeatureProfile::new("summarizer", DataClass::Internal, "summarize inbox")
            .with_capability("connector.outlook.read");
        assert!(profile.processes_personal_data(PDC));
        let decision = dpia_promotion_gate(&profile, None, PDC);
        assert_eq!(
            decision,
            DpiaGateDecision::Blocked(DpiaGateRefusal::MissingDpia {
                feature_id: "summarizer".into()
            })
        );

        // With an approved, current DPIA → allowed.
        let mut dpia = Dpia::draft("summarizer", "risks + mitigations");
        dpia.approve_for(&profile, "dpo-anita");
        assert!(dpia_promotion_gate(&profile, Some(&dpia), PDC).is_allowed());
    }

    #[test]
    fn gap_ainxt_responsibleai_fi06_data_class_change_invalidates_dpia_approval() {
        // §4.5 test 2: an approved DPIA'd feature changes its data_class_ceiling → DPIA invalidated
        // (content-hash mismatch); re-promotion blocked until re-assessed.
        let profile = FeatureProfile::new("scorer", DataClass::Pii, "score applicants");
        let mut dpia = Dpia::draft("scorer", "assessed at pii");
        dpia.approve_for(&profile, "dpo-anita");
        assert!(dpia_promotion_gate(&profile, Some(&dpia), PDC).is_allowed());

        // The feature materially expands its processing (ceiling PII → regulated-payment).
        let expanded =
            FeatureProfile::new("scorer", DataClass::RegulatedPayment, "score applicants");
        let decision = dpia_promotion_gate(&expanded, Some(&dpia), PDC);
        assert_eq!(
            decision,
            DpiaGateDecision::Blocked(DpiaGateRefusal::Stale {
                feature_id: "scorer".into()
            })
        );

        // Re-assessing (re-approving against the new profile) unblocks it.
        dpia.approve_for(&expanded, "dpo-anita");
        assert!(dpia_promotion_gate(&expanded, Some(&dpia), PDC).is_allowed());
    }

    #[test]
    fn gap_ainxt_responsibleai_fi06_non_personal_feature_needs_no_dpia() {
        let profile = FeatureProfile::new("docs-search", DataClass::Public, "search public docs");
        assert!(!profile.processes_personal_data(PDC));
        assert!(dpia_promotion_gate(&profile, None, PDC).is_allowed());
    }

    #[test]
    fn gap_ainxt_responsibleai_fi06_purpose_change_invalidates_and_wrong_feature_rejected() {
        let profile = FeatureProfile::new("f", DataClass::Pii, "original purpose");
        let mut dpia = Dpia::draft("f", "s");
        dpia.approve_for(&profile, "dpo");
        // Purpose drift invalidates.
        let repurposed = FeatureProfile::new("f", DataClass::Pii, "NEW purpose");
        assert!(!dpia_promotion_gate(&repurposed, Some(&dpia), PDC).is_allowed());
        // A DPIA for the wrong feature is rejected.
        let other = FeatureProfile::new("g", DataClass::Pii, "p");
        assert_eq!(
            dpia_promotion_gate(&other, Some(&dpia), PDC),
            DpiaGateDecision::Blocked(DpiaGateRefusal::FeatureMismatch {
                expected: "g".into(),
                got: "f".into()
            })
        );
    }
}
