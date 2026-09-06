// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! ainxt-cryptoagility — crypto-agility / PQC-readiness policy core.
//!
//! Design: ADR-023 (crypto-agility), Pass-5 gap 42 (PQC readiness). This crate is the pure,
//! deterministic heart of the machinery that lets the platform *swap* cryptographic primitives by
//! policy and *refuse* deprecated ones by policy — so a primitive that is discovered broken, or
//! the post-quantum transition, is enacted by editing data, never by shipping new selection code.
//!
//! # Why this crate exists
//!
//! In a payments switch the whole country runs through, a cryptographic primitive is a liability
//! the moment it is weakened. The classic failure mode is *silent stickiness*: a service keeps
//! signing with SHA-1 or exchanging keys with a classical-only algorithm long after the org
//! "deprecated" it, because the deprecation lived in a wiki and the code still returned the old
//! name. This crate makes the policy the single source of truth for "what may I use right now":
//!
//! 1. **Swappability.** [`AlgorithmRegistry`] holds, per [`Purpose`], an *ordered* list of
//!    candidate [`Algorithm`]s (index `0` = most preferred). Migrating to a PQC primitive is a
//!    matter of putting it at the front and marking the old one [`AlgStatus::Deprecated`] or
//!    [`AlgStatus::Forbidden`] — no call site changes.
//! 2. **Refusal.** [`AlgorithmRegistry::resolve`] walks candidates in preference order and returns
//!    the first that is *usable at the injected logical time* — [`AlgStatus::Approved`], or
//!    [`AlgStatus::Deprecated`] whose `not_after` tick has not yet passed. A
//!    [`AlgStatus::Forbidden`] algorithm is **never** returned, *even if it is the top preference*
//!    — that is the anti-downgrade invariant. When nothing is usable, resolution fails loudly with
//!    [`CryptoAgilityError::NoApprovedAlgorithm`] rather than falling back to a broken primitive.
//! 3. **PQC readiness.** [`AlgorithmRegistry::is_pqc_ready`] reports whether the algorithm that
//!    *would actually be used* is post-quantum safe — a live health signal for the transition, not
//!    a static claim about the registry.
//! 4. **Rotation.** [`Algorithm::must_rotate`] answers, for an algorithm already in use, whether it
//!    has become [`AlgStatus::Forbidden`] or has passed its `not_after` and therefore must be
//!    rotated away from.
//!
//! # The adversarial case, designed first
//!
//! The threat is a **downgrade / stale-policy attack**: an attacker (or a careless config edit)
//! that leaves a broken primitive at the top of the preference list, or that lets a deprecated
//! primitive quietly outlive its sunset. The design refuses both:
//!
//! * A `Forbidden` candidate is skipped *unconditionally*, regardless of preference rank — there
//!   is no code path that returns it, so pinning a broken algorithm at rank 0 does not weaken the
//!   resolved answer; resolution simply moves to the next usable candidate.
//! * A `Deprecated` candidate is skipped once `now > not_after`. Expiry is enforced against the
//!   injected clock, not against wall time or operator memory, so a sunset that has passed cannot
//!   be honoured by accident.
//! * When every candidate is forbidden or expired, `resolve` returns an error. It never returns
//!   `Ok` with a degraded algorithm — "fail closed" is the only outcome. `is_pqc_ready` and any
//!   caller that unwraps the resolution inherit that failure instead of a false green.
//!
//! # Determinism (why the guarantees are testable)
//!
//! This crate reads no clock, draws no randomness, and does no I/O. Logical time is the injected
//! [`Tick`] parameter `now`. The same registry queried at the same tick always yields the same
//! resolution, the same PQC verdict, and the same rotation decision — so every property below is
//! something a unit test can *assert*, not hope for. The `#[cfg(test)]` module exercises the top
//! pick, the deprecated-but-live pick, the expired skip (including the exact boundary tick), the
//! forbidden-top skip, the fail-closed error, PQC reflection of the resolved choice, and rotation
//! firing for forbidden/expired while staying quiet for a healthy approved algorithm.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

/// Logical time. The whole crate is deterministic in this injected clock — there is no wall-clock
/// read anywhere in non-test code. A larger `Tick` is "later"; `not_after` sunsets compare against
/// it directly.
pub type Tick = u64;

/// The cryptographic job an algorithm is being selected for. Selection is always scoped to a
/// purpose: the signing preference list is independent of the key-exchange one, so a PQC migration
/// can proceed purpose-by-purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Purpose {
    /// Digital signatures (e.g. message / artifact / token signing).
    Signing,
    /// Key establishment / key agreement.
    KeyExchange,
    /// Cryptographic hashing / digests.
    Hashing,
    /// Symmetric bulk encryption.
    SymmetricEncryption,
}

/// The policy status of a candidate algorithm.
///
/// This is the axis the whole crate turns on. `Deprecated` deliberately carries its own sunset so
/// that "usable until tick N" is data, not a side table the resolver has to join against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlgStatus {
    /// Fully allowed. Usable at any `now`.
    Approved,
    /// On the way out: still usable, but only up to and including `not_after`. Once `now` passes
    /// `not_after` the algorithm is treated exactly like [`AlgStatus::Forbidden`] for the purposes
    /// of both resolution and rotation.
    Deprecated {
        /// The last [`Tick`] at which this algorithm may still be selected/used (inclusive).
        not_after: Tick,
    },
    /// Refused outright — a broken or banned primitive. Never selectable, at any `now`, at any
    /// preference rank. Always triggers rotation.
    Forbidden,
}

/// A candidate cryptographic algorithm within a [`Purpose`]'s preference list.
///
/// `name` is an opaque policy label (e.g. `"ed25519"`, `"ml-dsa-65"`) — this crate never
/// interprets it, it only selects and reports it. `pqc_safe` is the operator's assertion that the
/// algorithm is believed resistant to a cryptographically-relevant quantum computer; it drives
/// [`AlgorithmRegistry::is_pqc_ready`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Algorithm {
    /// Opaque policy label for the algorithm.
    pub name: String,
    /// Current policy status (with sunset for `Deprecated`).
    pub status: AlgStatus,
    /// Whether this algorithm is considered post-quantum safe.
    pub pqc_safe: bool,
}

impl Algorithm {
    /// Construct an [`AlgStatus::Approved`] candidate.
    pub fn approved(name: impl Into<String>, pqc_safe: bool) -> Self {
        Self {
            name: name.into(),
            status: AlgStatus::Approved,
            pqc_safe,
        }
    }

    /// Construct an [`AlgStatus::Deprecated`] candidate that is usable up to and including
    /// `not_after`.
    pub fn deprecated(name: impl Into<String>, not_after: Tick, pqc_safe: bool) -> Self {
        Self {
            name: name.into(),
            status: AlgStatus::Deprecated { not_after },
            pqc_safe,
        }
    }

    /// Construct an [`AlgStatus::Forbidden`] candidate — never selectable.
    pub fn forbidden(name: impl Into<String>, pqc_safe: bool) -> Self {
        Self {
            name: name.into(),
            status: AlgStatus::Forbidden,
            pqc_safe,
        }
    }

    /// Whether this algorithm may be *selected* at logical time `now`.
    ///
    /// `Approved` is always usable; `Deprecated { not_after }` is usable while `now <= not_after`;
    /// `Forbidden` is never usable.
    pub fn is_usable_at(&self, now: Tick) -> bool {
        match self.status {
            AlgStatus::Approved => true,
            AlgStatus::Deprecated { not_after } => now <= not_after,
            AlgStatus::Forbidden => false,
        }
    }

    /// Whether an algorithm already *in use* must be rotated away from at logical time `now`.
    ///
    /// Fires for [`AlgStatus::Forbidden`] (always) and for [`AlgStatus::Deprecated`] once
    /// `now > not_after`. A healthy [`AlgStatus::Approved`] algorithm never triggers rotation.
    /// This is the exact complement of [`Algorithm::is_usable_at`] for a non-approved status, so a
    /// deprecated algorithm is usable and non-rotating at exactly `not_after`, then flips both at
    /// `not_after + 1`.
    pub fn must_rotate(&self, now: Tick) -> bool {
        match self.status {
            AlgStatus::Approved => false,
            AlgStatus::Deprecated { not_after } => now > not_after,
            AlgStatus::Forbidden => true,
        }
    }
}

/// The crypto-agility policy: per-[`Purpose`] ordered preference lists of candidate algorithms.
///
/// Order is preference: the algorithm at index `0` of a purpose's list is tried first. Migrating a
/// purpose to a new primitive is a data edit — reorder the list and/or change statuses.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlgorithmRegistry {
    /// Preference lists keyed by purpose. A `BTreeMap` keeps iteration deterministic.
    candidates: BTreeMap<Purpose, Vec<Algorithm>>,
}

impl AlgorithmRegistry {
    /// An empty registry — no purpose has any candidate yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append `algorithm` to `purpose`'s preference list (lowest preference so far). Chainable.
    ///
    /// The insertion order *is* the preference order, so callers register most-preferred first.
    pub fn register(&mut self, purpose: Purpose, algorithm: Algorithm) -> &mut Self {
        self.candidates.entry(purpose).or_default().push(algorithm);
        self
    }

    /// The full ordered candidate list for a purpose (empty slice if the purpose is unknown).
    /// Exposed for policy inspection/audit; it is not the selection path.
    pub fn candidates(&self, purpose: Purpose) -> &[Algorithm] {
        self.candidates.get(&purpose).map_or(&[], Vec::as_slice)
    }

    /// Resolve the algorithm to use for `purpose` at logical time `now`.
    ///
    /// Returns the highest-preference candidate that [`Algorithm::is_usable_at`] `now` — i.e. the
    /// first `Approved`, or `Deprecated` still within its `not_after`, in list order. A `Forbidden`
    /// or expired candidate is skipped no matter its rank. If no candidate is usable (or the
    /// purpose is unknown), returns [`CryptoAgilityError::NoApprovedAlgorithm`] — never a degraded
    /// fallback.
    pub fn resolve(&self, purpose: Purpose, now: Tick) -> Result<&Algorithm, CryptoAgilityError> {
        self.candidates
            .get(&purpose)
            .into_iter()
            .flatten()
            .find(|alg| alg.is_usable_at(now))
            .ok_or(CryptoAgilityError::NoApprovedAlgorithm { purpose })
    }

    /// Whether the algorithm that *would actually be resolved* for `purpose` at `now` is
    /// post-quantum safe.
    ///
    /// Propagates [`CryptoAgilityError::NoApprovedAlgorithm`] when nothing is usable — a caller
    /// cannot mistake "no algorithm at all" for "not PQC ready".
    pub fn is_pqc_ready(&self, purpose: Purpose, now: Tick) -> Result<bool, CryptoAgilityError> {
        Ok(self.resolve(purpose, now)?.pqc_safe)
    }
}

/// The default crypto-agility policy for [`Purpose::Hashing`] (ADR-023): SHA-256 approved. The
/// canonical starting point for every hash-chained durable structure this workspace governs (the
/// Event Log, the incident register, and any future chain) — a deployment overrides it (e.g. via
/// `IncidentRegister::with_hash_policy`) to deprecate/forbid a primitive or stage a PQC migration,
/// a data edit, never a code change. Defined once here so every governed chain shares ONE default,
/// instead of each caller re-deriving its own (which would make a policy rotation a multi-crate
/// hunt instead of a single edit).
pub fn default_hash_policy() -> AlgorithmRegistry {
    let mut r = AlgorithmRegistry::new();
    r.register(Purpose::Hashing, Algorithm::approved("sha-256", false));
    r
}

/// Failure to select any usable algorithm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CryptoAgilityError {
    /// No candidate for `purpose` was approved (or deprecated-but-unexpired) at the queried tick —
    /// the policy has fenced off every option, so the caller must fail closed rather than proceed.
    NoApprovedAlgorithm {
        /// The purpose for which resolution failed.
        purpose: Purpose,
    },
    /// The policy resolved to an algorithm this build has no implementation for. The operation is
    /// refused (fail-closed) rather than silently falling back to a hard-coded primitive — this is the
    /// exact hole [`GovernedHasher`] closes: code never keeps hashing with something the policy did not
    /// select. A deployment adds the impl (or re-orders the policy) rather than the code choosing.
    UnsupportedAlgorithm {
        /// The policy label that has no implementation here.
        name: String,
    },
}

impl fmt::Display for CryptoAgilityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoAgilityError::NoApprovedAlgorithm { purpose } => {
                write!(f, "no approved algorithm available for {purpose:?}")
            }
            CryptoAgilityError::UnsupportedAlgorithm { name } => {
                write!(f, "policy resolved to unsupported algorithm `{name}`")
            }
        }
    }
}

impl std::error::Error for CryptoAgilityError {}

// ============================ governed hashing (FI-10; ADR-023) ============================
//
// The registry above *selects*; the rest of the runtime historically hashed with `sha2` directly, so
// the policy governed nothing real. `GovernedHasher` closes that: it is the single hashing entrypoint
// that resolves [`Purpose::Hashing`] from the policy at `now` and only then computes the digest — so a
// Forbidden/expired hash primitive is un-usable by construction, and a PQC transition is a policy edit,
// not a code change. Pure + deterministic (logical `now` injected); permissive `sha2` only.

/// The result of a governed hash: the digest and the policy label of the algorithm that produced it,
/// so a caller/audit records *which policy-selected primitive* hashed the bytes (§7 evidentiary
/// particular — "manner of production").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernedDigest {
    /// The algorithm label the policy resolved to (e.g. `"sha-256"`).
    pub algorithm: String,
    /// The lowercase hex digest.
    pub hex: String,
}

/// Hex-encode digest bytes without depending on `sha2`'s output type implementing `LowerHex`
/// (it does not, across the `digest`/`sha2` 0.10 → 0.11 transition) or on an extra `hex` crate.
fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(s, "{:02x}", b).expect("writing to a String never fails");
    }
    s
}

/// The single, policy-governed hashing entrypoint. Holds a snapshot of the crypto-agility policy; a
/// digest is only ever produced through the algorithm the policy resolves for [`Purpose::Hashing`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernedHasher {
    registry: AlgorithmRegistry,
}

impl GovernedHasher {
    /// Wrap a policy. The hasher exposes no way to hash outside the policy — [`digest`](Self::digest)
    /// is the only method and it consults the registry first.
    pub fn new(registry: AlgorithmRegistry) -> Self {
        Self { registry }
    }

    /// Which algorithm would govern a hash at `now` (for audit/inspection), or the fail-closed error.
    pub fn resolved_algorithm(&self, now: Tick) -> Result<&Algorithm, CryptoAgilityError> {
        self.registry.resolve(Purpose::Hashing, now)
    }

    /// Compute a governed digest of `data` at logical time `now`. Resolves the Hashing purpose from
    /// the policy; if nothing is usable → [`CryptoAgilityError::NoApprovedAlgorithm`]; if the resolved
    /// label has no implementation here → [`CryptoAgilityError::UnsupportedAlgorithm`] (never a silent
    /// fallback). Supported labels: `sha-256`/`sha256`, `sha-512`/`sha512` (case-insensitive).
    pub fn digest(&self, data: &[u8], now: Tick) -> Result<GovernedDigest, CryptoAgilityError> {
        let alg = self.registry.resolve(Purpose::Hashing, now)?;
        let label = alg.name.to_ascii_lowercase();
        let hex = match label.as_str() {
            "sha-256" | "sha256" => {
                use sha2::{Digest, Sha256};
                let mut h = Sha256::new();
                h.update(data);
                to_hex(&h.finalize())
            }
            "sha-512" | "sha512" => {
                use sha2::{Digest, Sha512};
                let mut h = Sha512::new();
                h.update(data);
                to_hex(&h.finalize())
            }
            _ => {
                return Err(CryptoAgilityError::UnsupportedAlgorithm {
                    name: alg.name.clone(),
                })
            }
        };
        Ok(GovernedDigest {
            algorithm: alg.name.clone(),
            hex,
        })
    }
}

#[cfg(test)]
mod governed_hasher_tests {
    use super::*;

    #[test]
    fn gap_ainxt_cryptoagility_fi10_governed_hash_uses_policy_selected_algorithm() {
        // FI-10: a real cryptographic operation (hashing) is actually GOVERNED by the agility policy —
        // the digest is produced through the algorithm the policy resolves, not a hard-coded sha2 call.
        let mut r = AlgorithmRegistry::new();
        // Policy prefers sha-256 while approved.
        r.register(Purpose::Hashing, Algorithm::approved("sha-256", false));
        let hasher = GovernedHasher::new(r);

        let out = hasher.digest(b"settlement-record", 10).unwrap();
        assert_eq!(out.algorithm, "sha-256");
        // Matches a direct sha-256 of the same bytes (the governed op really hashed).
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"settlement-record");
        assert_eq!(out.hex, to_hex(&h.finalize()));
    }

    #[test]
    fn gap_ainxt_cryptoagility_fi10_deprecated_then_forbidden_hash_is_enacted_by_policy_alone() {
        // The PQC/rotation transition is enacted by policy: once sha-256 is deprecated-and-expired the
        // hasher stops using it and resolves the next usable candidate — no code change, no silent
        // fallback to the deprecated primitive.
        let mut r = AlgorithmRegistry::new();
        r.register(
            Purpose::Hashing,
            Algorithm::deprecated("sha-256", 100, false),
        );
        r.register(Purpose::Hashing, Algorithm::approved("sha-512", false));
        let hasher = GovernedHasher::new(r);

        // Before sunset: sha-256 governs.
        assert_eq!(hasher.digest(b"x", 100).unwrap().algorithm, "sha-256");
        // After sunset: policy resolves to sha-512 — the deprecated primitive is un-usable by policy.
        assert_eq!(hasher.digest(b"x", 101).unwrap().algorithm, "sha-512");
    }

    #[test]
    fn gap_ainxt_cryptoagility_fi10_forbidden_and_unimplemented_fail_closed() {
        // A policy that forbids every hash primitive → the hasher REFUSES (fail-closed), never hashes.
        let mut r = AlgorithmRegistry::new();
        r.register(Purpose::Hashing, Algorithm::forbidden("md5", false));
        let hasher = GovernedHasher::new(r);
        assert_eq!(
            hasher.digest(b"x", 0),
            Err(CryptoAgilityError::NoApprovedAlgorithm {
                purpose: Purpose::Hashing
            })
        );

        // A policy resolving to a label with no impl here → refused, not a silent fallback.
        let mut r2 = AlgorithmRegistry::new();
        r2.register(Purpose::Hashing, Algorithm::approved("blake3", true));
        let hasher2 = GovernedHasher::new(r2);
        assert_eq!(
            hasher2.digest(b"x", 0),
            Err(CryptoAgilityError::UnsupportedAlgorithm {
                name: "blake3".into()
            })
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a registry with a realistic multi-candidate signing list plus other purposes.
    fn registry() -> AlgorithmRegistry {
        let mut r = AlgorithmRegistry::new();
        // Signing: PQC primary (approved), classical secondary (deprecated, sunset at 100),
        // legacy tertiary (forbidden — a broken primitive still listed but banned).
        r.register(Purpose::Signing, Algorithm::approved("ml-dsa-65", true))
            .register(
                Purpose::Signing,
                Algorithm::deprecated("ed25519", 100, false),
            )
            .register(
                Purpose::Signing,
                Algorithm::forbidden("rsa-1024-sha1", false),
            );
        // Hashing: a forbidden primitive pinned at TOP preference (downgrade attempt) followed by
        // a healthy approved one.
        r.register(Purpose::Hashing, Algorithm::forbidden("sha1", false))
            .register(Purpose::Hashing, Algorithm::approved("sha3-256", false));
        r
    }

    #[test]
    fn resolve_returns_top_approved() {
        let r = registry();
        let a = r.resolve(Purpose::Signing, 0).unwrap();
        assert_eq!(a.name, "ml-dsa-65");
        assert!(a.pqc_safe);
    }

    #[test]
    fn deprecated_but_unexpired_is_usable_when_it_is_the_best_candidate() {
        // A signing list whose only non-forbidden option is a deprecated one still within sunset.
        let mut r = AlgorithmRegistry::new();
        r.register(Purpose::Signing, Algorithm::forbidden("rsa-1024", false))
            .register(
                Purpose::Signing,
                Algorithm::deprecated("ed25519", 100, false),
            );
        // Well before sunset, and exactly at the sunset boundary (inclusive), it resolves.
        assert_eq!(r.resolve(Purpose::Signing, 50).unwrap().name, "ed25519");
        assert_eq!(r.resolve(Purpose::Signing, 100).unwrap().name, "ed25519");
    }

    #[test]
    fn expired_deprecated_is_skipped_in_favor_of_next_usable() {
        // Top is deprecated with sunset 100; second is approved. One tick past sunset the
        // deprecated one must be skipped and the approved fallback returned.
        let mut r = AlgorithmRegistry::new();
        r.register(
            Purpose::Signing,
            Algorithm::deprecated("ed25519", 100, false),
        )
        .register(Purpose::Signing, Algorithm::approved("ml-dsa-65", true));
        // At the boundary the deprecated top still wins…
        assert_eq!(r.resolve(Purpose::Signing, 100).unwrap().name, "ed25519");
        // …one tick later it is expired and skipped.
        assert_eq!(r.resolve(Purpose::Signing, 101).unwrap().name, "ml-dsa-65");
    }

    #[test]
    fn forbidden_is_never_returned_even_at_top_preference() {
        let r = registry();
        // Hashing lists forbidden "sha1" first; the downgrade must be refused for the approved
        // "sha3-256" at every tick.
        for now in [0, 1, 1_000, Tick::MAX] {
            assert_eq!(r.resolve(Purpose::Hashing, now).unwrap().name, "sha3-256");
        }
    }

    #[test]
    fn resolve_errors_when_nothing_is_usable() {
        let mut r = AlgorithmRegistry::new();
        r.register(Purpose::KeyExchange, Algorithm::forbidden("dh-1024", false))
            .register(
                Purpose::KeyExchange,
                Algorithm::deprecated("x25519", 10, true),
            );
        // Past the only sunset, every candidate is fenced off -> fail closed.
        let err = r.resolve(Purpose::KeyExchange, 11).unwrap_err();
        assert_eq!(
            err,
            CryptoAgilityError::NoApprovedAlgorithm {
                purpose: Purpose::KeyExchange
            }
        );
    }

    #[test]
    fn resolve_errors_for_unknown_purpose() {
        let r = AlgorithmRegistry::new();
        assert_eq!(
            r.resolve(Purpose::SymmetricEncryption, 0).unwrap_err(),
            CryptoAgilityError::NoApprovedAlgorithm {
                purpose: Purpose::SymmetricEncryption
            }
        );
    }

    #[test]
    fn is_pqc_ready_reflects_the_resolved_algorithm_not_the_registry() {
        // Signing resolves to the PQC-safe primary -> ready.
        let r = registry();
        assert!(r.is_pqc_ready(Purpose::Signing, 0).unwrap());
        // Hashing resolves to sha3-256 which is (per this policy) not marked pqc_safe -> not ready,
        // even though the registry contains no better option.
        assert!(!r.is_pqc_ready(Purpose::Hashing, 0).unwrap());
    }

    #[test]
    fn is_pqc_ready_tracks_the_fallback_when_the_pqc_pick_expires() {
        // Primary is a PQC-safe but DEPRECATED alg; fallback is a classical approved one.
        let mut r = AlgorithmRegistry::new();
        r.register(
            Purpose::KeyExchange,
            Algorithm::deprecated("ml-kem-768", 100, true),
        )
        .register(Purpose::KeyExchange, Algorithm::approved("x25519", false));
        // While the PQC pick is live, ready.
        assert!(r.is_pqc_ready(Purpose::KeyExchange, 100).unwrap());
        // After it expires we fall back to the classical alg -> no longer PQC ready.
        assert!(!r.is_pqc_ready(Purpose::KeyExchange, 101).unwrap());
    }

    #[test]
    fn is_pqc_ready_propagates_no_algorithm_error() {
        let r = AlgorithmRegistry::new();
        assert!(r.is_pqc_ready(Purpose::Signing, 0).is_err());
    }

    #[test]
    fn must_rotate_fires_for_forbidden_and_past_sunset_only() {
        let forbidden = Algorithm::forbidden("rsa-1024", false);
        let deprecated = Algorithm::deprecated("ed25519", 100, false);
        let approved = Algorithm::approved("ml-dsa-65", true);

        // Forbidden: rotate now, always.
        assert!(forbidden.must_rotate(0));
        assert!(forbidden.must_rotate(Tick::MAX));

        // Deprecated: healthy up to and including sunset, must rotate strictly after.
        assert!(!deprecated.must_rotate(99));
        assert!(!deprecated.must_rotate(100));
        assert!(deprecated.must_rotate(101));

        // Approved: never rotate.
        assert!(!approved.must_rotate(0));
        assert!(!approved.must_rotate(Tick::MAX));
    }

    #[test]
    fn usable_and_rotate_are_complementary_for_deprecated() {
        // The two decisions must not disagree: a deprecated alg is usable iff it need not rotate.
        let dep = Algorithm::deprecated("x25519", 50, true);
        for now in [0, 49, 50, 51, 1_000] {
            assert_ne!(dep.is_usable_at(now), dep.must_rotate(now), "now={now}");
        }
    }

    #[test]
    fn candidates_preserves_registration_order() {
        let r = registry();
        let names: Vec<&str> = r
            .candidates(Purpose::Signing)
            .iter()
            .map(|a| a.name.as_str())
            .collect();
        assert_eq!(names, ["ml-dsa-65", "ed25519", "rsa-1024-sha1"]);
        assert!(r.candidates(Purpose::SymmetricEncryption).is_empty());
    }
}
