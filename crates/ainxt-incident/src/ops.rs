// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Supervisory infra monitors that *arm the breach engine* (§8.1, §8.2; FI-05):
//! the NIC/NPL **NTP clock-skew monitor** and the **India-residency verifier**. Both are pure,
//! deterministic detectors: given an injected measurement they decide, by policy, whether the
//! measurement is a §2 reportable incident, and if so they emit a ready-to-open [`IncidentCandidate`]
//! (source [`CandidateSource::NtpSkew`] / [`CandidateSource::ResidencyViolation`]).
//!
//! Skew is doubly dangerous — it can fire premature saga compensation (double-execution) *and* it
//! undermines evidentiary timestamps — so skew beyond threshold is an incident, not a warning
//! (Pass-5 gap [32]). A log/data store that resolves outside Indian jurisdiction breaks the CERT-In
//! 180-day-in-India retention floor (§8.1), so a mis-located store is likewise an incident.
//!
//! The runtime cannot itself provision the NTP source or the storage region (residual 7) — it
//! *monitors and alarms*. These types are the alarm; the parent wires the real measurement in.

use crate::evidence::NtpAttestation;
use crate::{CandidateSource, IncidentCandidate, Tick};

/// The NIC/NPL NTP clock-skew monitor (§8.2). Configured with the statutory source and a skew
/// threshold; [`check`](NtpSkewMonitor::check) turns a measured offset into an [`NtpAttestation`]
/// (always — every evidentiary timestamp records its source + offset) and, when the offset exceeds
/// the threshold, an [`IncidentCandidate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtpSkewMonitor {
    /// The configured NIC/NPL source (or a server traceable to them).
    pub source: String,
    /// The maximum tolerated absolute skew, in milliseconds.
    pub threshold_ms: i64,
}

impl NtpSkewMonitor {
    pub fn new(source: &str, threshold_ms: i64) -> Self {
        Self {
            source: source.to_string(),
            threshold_ms: threshold_ms.max(0),
        }
    }

    /// `true` if `offset_ms` is within the tolerated skew.
    pub fn within_threshold(&self, offset_ms: i64) -> bool {
        offset_ms.abs() <= self.threshold_ms
    }

    /// The attestation for the current offset — recorded on every evidentiary timestamp regardless of
    /// whether it is in-threshold (§8.2: "every evidentiary timestamp records its source + offset").
    pub fn attest(&self, offset_ms: i64) -> NtpAttestation {
        NtpAttestation {
            source: self.source.clone(),
            last_sync_offset_ms: offset_ms,
            within_threshold: self.within_threshold(offset_ms),
        }
    }

    /// Check a measured offset. Returns the always-present attestation plus, when the skew exceeds the
    /// threshold, an [`IncidentCandidate`] the parent opens with
    /// [`IncidentRegister::open_from`](crate::IncidentRegister::open_from) (fail-safe class = cyber).
    pub fn check(
        &self,
        offset_ms: i64,
        noticed_tick: Tick,
        control_plane_sha: &str,
    ) -> (NtpAttestation, Option<IncidentCandidate>) {
        let attestation = self.attest(offset_ms);
        let candidate = if attestation.within_threshold {
            None
        } else {
            Some(
                IncidentCandidate::new(CandidateSource::NtpSkew, noticed_tick, control_plane_sha)
                    .with_system(&self.source)
                    .with_description(&format!(
                        "clock skew {offset_ms}ms exceeds {}ms threshold",
                        self.threshold_ms
                    )),
            )
        };
        (attestation, candidate)
    }
}

/// The India-residency verifier (§8.1). A store carries a data-residency label (its resolved region);
/// the verifier asserts every log/data store resolves within Indian jurisdiction. A mis-located store
/// is a §2 incident.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResidencyVerifier {
    /// The set of region labels considered inside Indian jurisdiction (lowercased on insert).
    in_country_regions: Vec<String>,
}

impl Default for ResidencyVerifier {
    fn default() -> Self {
        Self::india()
    }
}

impl ResidencyVerifier {
    /// A verifier that accepts common India-region labels. Extend with deployment-specific labels.
    pub fn india() -> Self {
        Self {
            in_country_regions: [
                "in",
                "india",
                "ap-south-1",
                "ap-south-2",
                "in-central",
                "in-west",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        }
    }

    /// Add an accepted in-country region label (chainable).
    pub fn allow_region(mut self, region: &str) -> Self {
        self.in_country_regions.push(region.to_ascii_lowercase());
        self
    }

    /// `true` if `region` resolves inside Indian jurisdiction.
    pub fn is_in_country(&self, region: &str) -> bool {
        let r = region.to_ascii_lowercase();
        self.in_country_regions.iter().any(|c| c == &r)
    }

    /// Verify one store's residency. A store resolving outside India returns an [`IncidentCandidate`]
    /// (source [`CandidateSource::ResidencyViolation`]); an in-country store returns `None`.
    pub fn verify_store(
        &self,
        store_id: &str,
        region: &str,
        noticed_tick: Tick,
        control_plane_sha: &str,
    ) -> Option<IncidentCandidate> {
        if self.is_in_country(region) {
            return None;
        }
        Some(
            IncidentCandidate::new(
                CandidateSource::ResidencyViolation,
                noticed_tick,
                control_plane_sha,
            )
            .with_system(store_id)
            .with_description(&format!(
                "store `{store_id}` resolves to non-India region `{region}` (breaks 180-day in-India floor)"
            )),
        )
    }

    /// Sweep a set of `(store_id, region)` pairs; returns a candidate per mis-located store, in input
    /// order (deterministic; no I/O — the caller supplies the resolved regions).
    pub fn verify_all<'a, I>(
        &self,
        stores: I,
        noticed_tick: Tick,
        control_plane_sha: &str,
    ) -> Vec<IncidentCandidate>
    where
        I: IntoIterator<Item = (&'a str, &'a str)>,
    {
        stores
            .into_iter()
            .filter_map(|(id, region)| {
                self.verify_store(id, region, noticed_tick, control_plane_sha)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ArmingPolicy, IncidentClass, IncidentRegister, StatutoryClockKind};

    #[test]
    fn gap_ainxt_incident_fi05_ntp_skew_beyond_threshold_raises_a_2_incident() {
        // §8.4 test 2: NTP skew beyond threshold fires a §2 incident; the attestation still records
        // its source + offset either way.
        let mon = NtpSkewMonitor::new("nic-ntp.gov.in", 100);

        // In-threshold: attestation recorded, NO candidate.
        let (att_ok, cand_ok) = mon.check(42, 500, "sha-x");
        assert!(att_ok.within_threshold);
        assert_eq!(att_ok.source, "nic-ntp.gov.in");
        assert_eq!(att_ok.last_sync_offset_ms, 42);
        assert!(cand_ok.is_none());

        // Beyond threshold (either sign): a candidate is raised.
        let (att_bad, cand_bad) = mon.check(-350, 600, "sha-x");
        assert!(!att_bad.within_threshold);
        assert_eq!(att_bad.last_sync_offset_ms, -350);
        let cand = cand_bad.expect("skew beyond threshold must raise a candidate");
        assert_eq!(cand.source, CandidateSource::NtpSkew);
        assert_eq!(cand.default_class(), IncidentClass::CyberSecurityIncident);

        // Opening it arms a real clock — the engine is actually fed.
        let mut reg = IncidentRegister::new(ArmingPolicy::india_regulatory_default());
        let id = reg.open_from(cand, 600);
        let inc = reg.incident(&id).unwrap();
        assert!(inc.clock(StatutoryClockKind::CertIn).is_some());
    }

    #[test]
    fn gap_ainxt_incident_fi05_mislocated_store_raises_a_residency_incident() {
        // §8.4 test 1: a deliberately mis-located store raises a §2 incident; India stores do not.
        let v = ResidencyVerifier::india();
        assert!(v
            .verify_store("eventlog", "ap-south-1", 10, "sha")
            .is_none());

        let cand = v
            .verify_store("trace-store", "us-east-1", 10, "sha")
            .expect("non-India store must raise a candidate");
        assert_eq!(cand.source, CandidateSource::ResidencyViolation);
        assert!(cand.systems_involved.contains(&"trace-store".to_string()));

        // Sweep: only the mis-located store is flagged.
        let hits = v.verify_all(
            [("a", "india"), ("b", "eu-west-1"), ("c", "ap-south-2")],
            10,
            "sha",
        );
        assert_eq!(hits.len(), 1);
        assert!(hits[0].systems_involved.contains(&"b".to_string()));
    }
}
