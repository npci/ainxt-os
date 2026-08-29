// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Reproduce-from-SHA, audit, and data-class Judge routing (EVAL_PLATFORM.md §12; gaps X, ADR-012/
//! 014/025).
//!
//! Every gate verdict, canary decision, and Vault-case origin records the **eval-set version, Judge
//! version, candidate SHA, params, and seed** on the Event Log — a verdict from two years ago replays
//! to the same result. This is the ADR-014 model-validation record and the ADR-025 admissible
//! evidence.
//!
//! * [`VerdictRecord`] captures the full reproduction key; [`EventSink`] is the append-only Event-Log
//!   seam it is written to *before* the change ships.
//! * [`repro_key`] / [`replay_matches`] enforce determinism: two records with the same reproduction
//!   inputs must carry the same outcome, else the verdict is not reproducible and the audit fails.
//! * [`route_judge`] enforces **data-class Judge routing**: a `regulated-payment`/PII eval is scored
//!   only by an in-house Judge — a cloud Judge is never attempted (fail-closed).
//!
//! Deterministic; the epoch is always passed in (no clock); the digest uses `sha2`.

use crate::judge::JudgeSpec;
use ainxt_types::DataClass;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The outcome recorded for a verdict (kept as a stable string so the audit format is provider- and
/// enum-evolution-stable).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerdictRecord {
    pub eval_set_id: String,
    pub eval_set_version: String,
    pub judge_version: String,
    /// The candidate control-plane commit SHA the change under test was built from.
    pub candidate_sha: String,
    /// Content hash of the analysis parameters (pre-registration: margins, α, power, method).
    pub params_hash: String,
    pub seed: u64,
    pub dimension: String,
    /// "pass" | "block" | "indeterminate" — stable strings.
    pub outcome: String,
    /// The measured effect (metric units) for the record.
    pub effect: f64,
    /// The Event-Log epoch this verdict was minted at (passed in — deterministic).
    pub epoch: u64,
}

impl VerdictRecord {
    /// The reproduction key: everything that must be identical for the verdict to replay. Two runs
    /// sharing this key MUST produce the same `outcome` (see [`replay_matches`]).
    pub fn repro_key(&self) -> String {
        repro_key(
            &self.eval_set_id,
            &self.eval_set_version,
            &self.judge_version,
            &self.candidate_sha,
            &self.params_hash,
            self.seed,
            &self.dimension,
        )
    }
}

/// The append-only Event-Log seam for verdict records (ADR-025 admissible evidence). The production
/// impl is the tamper-evident event log; this trait keeps the eval core decoupled and testable.
pub trait EventSink {
    fn append(&mut self, record: &VerdictRecord);
}

/// Length-prefixed hasher feed so distinct field boundaries can't collide.
fn feed(h: &mut Sha256, b: &[u8]) {
    h.update((b.len() as u64).to_le_bytes());
    h.update(b);
}

/// Compute a SHA-256 reproduction key over the identifying inputs of a verdict.
#[allow(clippy::too_many_arguments)]
pub fn repro_key(
    eval_set_id: &str,
    eval_set_version: &str,
    judge_version: &str,
    candidate_sha: &str,
    params_hash: &str,
    seed: u64,
    dimension: &str,
) -> String {
    let mut h = Sha256::new();
    h.update(b"ainxt-eval-repro\0");
    feed(&mut h, eval_set_id.as_bytes());
    feed(&mut h, eval_set_version.as_bytes());
    feed(&mut h, judge_version.as_bytes());
    feed(&mut h, candidate_sha.as_bytes());
    feed(&mut h, params_hash.as_bytes());
    feed(&mut h, &seed.to_le_bytes());
    feed(&mut h, dimension.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect::<String>()
}

/// A deterministic content hash of the pre-registration params (so a param change is a new key).
pub fn params_hash(margin: f64, alpha: f64, power: f64, method: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"ainxt-eval-params\0");
    h.update(margin.to_le_bytes());
    h.update(alpha.to_le_bytes());
    h.update(power.to_le_bytes());
    h.update((method.len() as u64).to_le_bytes());
    h.update(method.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect::<String>()
}

/// A replay is faithful iff the two records share a reproduction key AND the same outcome. A same-key
/// pair with different outcomes means the verdict is not reproducible — a defect the audit must catch.
pub fn replay_matches(original: &VerdictRecord, replay: &VerdictRecord) -> bool {
    original.repro_key() == replay.repro_key() && original.outcome == replay.outcome
}

// ===========================================================================================
// Data-class Judge routing (ADR-012)
// ===========================================================================================

/// Why a Judge could not be routed for a data class.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum JudgeRoutingError {
    /// No in-house Judge is available for a regulated/PII eval; a cloud Judge is never attempted.
    NoEligibleInHouseJudge { data_class: String },
    /// No judge at all for the dimension.
    NoJudgeForDimension { dimension: String },
}

/// Select an eligible Judge for scoring an eval of `data_class` on `dimension` from the available
/// pinned Judges. **Fail-closed:** a regulated/PII eval selects only an `in_house_only` Judge; if none
/// exists it errors rather than falling back to a cloud Judge. Non-regulated data may use any Judge
/// for the dimension. Selection is deterministic (first match by sorted judge_version).
pub fn route_judge<'a>(
    data_class: DataClass,
    dimension: &str,
    available: &'a [JudgeSpec],
) -> Result<&'a JudgeSpec, JudgeRoutingError> {
    let mut candidates: Vec<&JudgeSpec> = available
        .iter()
        .filter(|j| j.dimension == dimension)
        .collect();
    if candidates.is_empty() {
        return Err(JudgeRoutingError::NoJudgeForDimension {
            dimension: dimension.to_string(),
        });
    }
    if data_class.is_regulated() {
        candidates.retain(|j| j.in_house_only);
        if candidates.is_empty() {
            return Err(JudgeRoutingError::NoEligibleInHouseJudge {
                data_class: data_class.as_str().to_string(),
            });
        }
    }
    // Deterministic pick: lowest judge version hash.
    candidates.sort_by_key(|a| a.version());
    Ok(candidates[0])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec() -> VerdictRecord {
        VerdictRecord {
            eval_set_id: "rag-groundedness".into(),
            eval_set_version: "v3".into(),
            judge_version: "abc123".into(),
            candidate_sha: "deadbeef".into(),
            params_hash: params_hash(2.0, 0.05, 0.8, "paired-noninferiority"),
            seed: 42,
            dimension: "groundedness".into(),
            outcome: "pass".into(),
            effect: 0.5,
            epoch: 1000,
        }
    }

    fn judge(id: &str, dim: &str, family: &str, in_house: bool) -> JudgeSpec {
        JudgeSpec {
            judge_id: id.into(),
            base_model: format!("{family}-model"),
            model_version: format!("{family}-2026"),
            family: family.into(),
            temperature: 0.0,
            seed: 1,
            rubric: "rubric".into(),
            scoring_scale: "0-100".into(),
            dimension: dim.into(),
            in_house_only: in_house,
        }
    }

    #[test]
    fn repro_key_is_stable_and_input_sensitive() {
        let a = rec();
        let b = rec();
        assert_eq!(a.repro_key(), b.repro_key(), "same inputs → same key");
        let mut c = rec();
        c.candidate_sha = "cafef00d".into();
        assert_ne!(
            a.repro_key(),
            c.repro_key(),
            "a different candidate is a different key"
        );
        let mut d = rec();
        d.seed = 43;
        assert_ne!(
            a.repro_key(),
            d.repro_key(),
            "a different seed is a different key"
        );
    }

    #[test]
    fn replay_detects_a_nondeterministic_verdict() {
        let orig = rec();
        // Faithful replay: same key + same outcome.
        let good = rec();
        assert!(replay_matches(&orig, &good));
        // Same key, DIFFERENT outcome → not reproducible (a defect).
        let mut bad = rec();
        bad.outcome = "block".into();
        assert!(
            !replay_matches(&orig, &bad),
            "same inputs must yield the same verdict"
        );
    }

    #[test]
    fn event_sink_captures_the_full_record() {
        struct MemSink(Vec<VerdictRecord>);
        impl EventSink for MemSink {
            fn append(&mut self, record: &VerdictRecord) {
                self.0.push(record.clone());
            }
        }
        let mut sink = MemSink(Vec::new());
        sink.append(&rec());
        assert_eq!(sink.0.len(), 1);
        // The record carries everything needed to reproduce.
        let r = &sink.0[0];
        assert!(
            !r.judge_version.is_empty() && !r.candidate_sha.is_empty() && !r.params_hash.is_empty()
        );
    }

    #[test]
    fn regulated_eval_never_routes_to_a_cloud_judge() {
        let judges = vec![
            judge("cloud", "groundedness", "claude", false),
            judge("inhouse", "groundedness", "glm", true),
        ];
        // Regulated → must pick the in-house one.
        let sel = route_judge(DataClass::RegulatedPayment, "groundedness", &judges).unwrap();
        assert!(
            sel.in_house_only,
            "regulated eval must use the in-house judge"
        );

        // Only a cloud judge available for a regulated eval → fail closed, never fall back.
        let only_cloud = vec![judge("cloud", "groundedness", "claude", false)];
        let err = route_judge(DataClass::Pii, "groundedness", &only_cloud).unwrap_err();
        assert!(
            matches!(err, JudgeRoutingError::NoEligibleInHouseJudge { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn non_regulated_eval_may_use_any_judge() {
        let judges = vec![judge("cloud", "tone", "claude", false)];
        let sel = route_judge(DataClass::Internal, "tone", &judges).unwrap();
        assert_eq!(sel.judge_id, "cloud");
        // Unknown dimension → explicit error.
        let err = route_judge(DataClass::Internal, "nonexistent", &judges).unwrap_err();
        assert!(matches!(err, JudgeRoutingError::NoJudgeForDimension { .. }));
    }

    #[test]
    fn record_serializes_round_trip() {
        let r = rec();
        let j = serde_json::to_string(&r).unwrap();
        let back: VerdictRecord = serde_json::from_str(&j).unwrap();
        assert_eq!(back, r);
    }
}
