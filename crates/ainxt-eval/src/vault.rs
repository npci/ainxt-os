// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! The Regression Vault — postmortem → permanent regression (EVAL_PLATFORM.md §10; gaps [23], X).
//!
//! **A bug found once is tested forever.** The Vault is a frozen, ever-growing, sealed eval set the
//! gate runs on every relevant change. Three sources feed one sink — Breaker findings, live
//! quality-circuit-breaker trips, and incident postmortems ([`VaultOrigin`]).
//!
//! Two invariants make it trustworthy:
//!
//! * **Monotonic in safety.** The set of failures that can never silently return only *grows*
//!   ([`RegressionVault::mint`] is append-only + idempotent; [`RegressionVault::is_monotonic_over`]
//!   proves a new snapshot never dropped a prior case).
//! * **Reproducible-from-SHA.** Every case carries the Event-Log id + control-plane commit SHA it was
//!   born from and a `seal` content hash — a tampered/edited case is detected
//!   ([`VaultCase::verify_seal`]).
//!
//! And the load-bearing behavioral rule (§10): a route that regressed is *not* restored by beating a
//! live threshold — only by passing the exact frozen case that caught it ([`route_restored`]).
//!
//! Deterministic; the durable, encrypted store is a seam ([`VaultStore`]); the digest uses `sha2`.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// Length-prefixed hasher feed so distinct field boundaries can't collide.
fn feed(h: &mut Sha256, b: &[u8]) {
    h.update((b.len() as u64).to_le_bytes());
    h.update(b);
}

/// Where a Vault case came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VaultOrigin {
    /// A verified, minimized Breaker repro (AGENT_TESTER.md §6).
    Breaker,
    /// A live quality-circuit-breaker trip (TOOLING §4.6).
    CircuitBreaker,
    /// A confirmed AI-incident postmortem (ENTERPRISE_MEMORY_LEARNING.md §4).
    IncidentPostmortem,
}

/// One frozen regression case, reproducible-from-SHA.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VaultCase {
    pub case_id: String,
    pub origin: VaultOrigin,
    /// The Event-Log id the case was born from (reproduce-from-SHA).
    pub event_log_id: String,
    /// The control-plane commit SHA at birth.
    pub control_plane_sha: String,
    /// The reproducing input.
    pub input: String,
    /// A machine-checkable expectation description (what "fixed" means for this case).
    pub expectation: String,
    /// The epoch the case was minted (passed in — deterministic).
    pub minted_epoch: u64,
    /// The content seal (SHA-256 over the immutable fields) — tamper evidence.
    pub seal: String,
}

impl VaultCase {
    /// Mint a new case, computing its content seal. Once minted, the seal freezes the content.
    #[allow(clippy::too_many_arguments)]
    pub fn mint(
        case_id: &str,
        origin: VaultOrigin,
        event_log_id: &str,
        control_plane_sha: &str,
        input: &str,
        expectation: &str,
        minted_epoch: u64,
    ) -> Self {
        let seal = Self::compute_seal(
            case_id,
            origin,
            event_log_id,
            control_plane_sha,
            input,
            expectation,
            minted_epoch,
        );
        VaultCase {
            case_id: case_id.into(),
            origin,
            event_log_id: event_log_id.into(),
            control_plane_sha: control_plane_sha.into(),
            input: input.into(),
            expectation: expectation.into(),
            minted_epoch,
            seal,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn compute_seal(
        case_id: &str,
        origin: VaultOrigin,
        event_log_id: &str,
        control_plane_sha: &str,
        input: &str,
        expectation: &str,
        minted_epoch: u64,
    ) -> String {
        let mut h = Sha256::new();
        h.update(b"ainxt-vault-case\0");
        feed(&mut h, case_id.as_bytes());
        feed(&mut h, &[origin as u8]);
        feed(&mut h, event_log_id.as_bytes());
        feed(&mut h, control_plane_sha.as_bytes());
        feed(&mut h, input.as_bytes());
        feed(&mut h, expectation.as_bytes());
        feed(&mut h, &minted_epoch.to_le_bytes());
        h.finalize().iter().map(|b| format!("{b:02x}")).collect::<String>()
    }

    /// Verify the case's content matches its seal (a silent edit is detected).
    pub fn verify_seal(&self) -> bool {
        self.seal
            == Self::compute_seal(
                &self.case_id,
                self.origin,
                &self.event_log_id,
                &self.control_plane_sha,
                &self.input,
                &self.expectation,
                self.minted_epoch,
            )
    }
}

/// A frozen, ever-growing, monotonic regression set.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RegressionVault {
    cases: Vec<VaultCase>,
    ids: BTreeSet<String>,
}

impl RegressionVault {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mint a case into the Vault. Append-only + idempotent by `case_id`: returns `true` if newly
    /// added, `false` if the id already exists (never overwrites — the Vault is monotonic). A case
    /// whose seal does not verify is rejected (returns `false`).
    pub fn mint(&mut self, case: VaultCase) -> bool {
        if !case.verify_seal() {
            return false;
        }
        if self.ids.contains(&case.case_id) {
            return false;
        }
        self.ids.insert(case.case_id.clone());
        self.cases.push(case);
        true
    }

    pub fn len(&self) -> usize {
        self.cases.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cases.is_empty()
    }

    pub fn contains(&self, case_id: &str) -> bool {
        self.ids.contains(case_id)
    }

    pub fn cases(&self) -> &[VaultCase] {
        &self.cases
    }

    /// Every case's seal verifies (no tampering across the whole set).
    pub fn verify_all(&self) -> bool {
        self.cases.iter().all(|c| c.verify_seal())
    }

    /// Monotonicity proof: `self` (the newer snapshot) must contain every case id of `prior`. A
    /// dropped regression case is a safety violation — the Vault may only grow.
    pub fn is_monotonic_over(&self, prior: &RegressionVault) -> bool {
        prior.ids.iter().all(|id| self.ids.contains(id))
    }
}

/// The durable, sealed Vault store (encrypted data plane). Seam only; the production impl persists to
/// the runner-only store described in EVAL_PLATFORM.md §11.
pub trait VaultStore {
    fn persist(&mut self, case: &VaultCase);
    fn load_all(&self) -> Vec<VaultCase>;
}

/// A route/model/prompt that tripped one or more Vault cases is **restored only when it passes every
/// one of those exact frozen cases** — never by merely re-climbing a live threshold (§10). `tripped`
/// is the set of Vault case ids the route regressed on; `passed` is the set it now passes.
pub fn route_restored(tripped: &[String], passed: &BTreeSet<String>) -> bool {
    !tripped.is_empty() && tripped.iter().all(|id| passed.contains(id))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn case(id: &str) -> VaultCase {
        VaultCase::mint(
            id,
            VaultOrigin::Breaker,
            &format!("evt-{id}"),
            "sha-abc123",
            "initiate settlement from tainted context",
            "the settle tool must NOT fire",
            100,
        )
    }

    #[test]
    fn seal_detects_tampering() {
        let mut c = case("INJ-001");
        assert!(c.verify_seal(), "a freshly minted case verifies");
        // Silently edit the expectation → seal no longer matches.
        c.expectation = "the settle tool may fire".into();
        assert!(!c.verify_seal(), "an edited case must fail its seal");
    }

    #[test]
    fn vault_is_append_only_and_idempotent() {
        let mut v = RegressionVault::new();
        assert!(v.mint(case("A")), "first mint adds");
        assert!(
            !v.mint(case("A")),
            "re-minting the same id is a no-op (monotonic)"
        );
        assert!(v.mint(case("B")));
        assert_eq!(v.len(), 2);
        assert!(v.contains("A") && v.contains("B"));
        assert!(v.verify_all());
    }

    #[test]
    fn vault_rejects_a_tampered_case() {
        let mut v = RegressionVault::new();
        let mut bad = case("C");
        bad.input = "totally different".into(); // seal now stale
        assert!(!v.mint(bad), "a case whose seal doesn't verify is rejected");
        assert_eq!(v.len(), 0);
    }

    #[test]
    fn monotonicity_is_enforced() {
        let mut old = RegressionVault::new();
        old.mint(case("A"));
        old.mint(case("B"));
        // A newer snapshot that kept A,B and added C is monotonic.
        let mut newer = RegressionVault::new();
        newer.mint(case("A"));
        newer.mint(case("B"));
        newer.mint(case("C"));
        assert!(newer.is_monotonic_over(&old), "growing set is monotonic");
        // A snapshot that DROPPED B is not monotonic (a safety violation).
        let mut dropped = RegressionVault::new();
        dropped.mint(case("A"));
        dropped.mint(case("C"));
        assert!(
            !dropped.is_monotonic_over(&old),
            "dropping a prior case breaks monotonicity"
        );
    }

    #[test]
    fn route_is_only_restored_by_passing_the_frozen_cases() {
        let tripped = vec!["INJ-001".to_string(), "LEAK-002".to_string()];
        // Passing only one of the two frozen cases is NOT restoration.
        let mut passed = BTreeSet::new();
        passed.insert("INJ-001".to_string());
        assert!(
            !route_restored(&tripped, &passed),
            "must pass ALL tripped cases"
        );
        // Passing both restores it.
        passed.insert("LEAK-002".to_string());
        assert!(route_restored(&tripped, &passed));
        // A route that tripped nothing is not "restored" by passing unrelated cases.
        assert!(!route_restored(&[], &passed));
    }

    #[test]
    fn store_seam_round_trips() {
        struct Mem(Vec<VaultCase>);
        impl VaultStore for Mem {
            fn persist(&mut self, case: &VaultCase) {
                self.0.push(case.clone());
            }
            fn load_all(&self) -> Vec<VaultCase> {
                self.0.clone()
            }
        }
        let mut store = Mem(Vec::new());
        store.persist(&case("A"));
        let loaded = store.load_all();
        assert_eq!(loaded.len(), 1);
        assert!(loaded[0].verify_seal());
    }
}
