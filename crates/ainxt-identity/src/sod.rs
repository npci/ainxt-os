// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Producer ≠ approver Separation of Duties + signed handoffs (ADR-022 §18) — the identity-layer
//! close of Pass-5 **[17]** (a compromised agent forges a peer's approval).
//!
//! Design: `docs/architecture/AGENT_IDENTITY_AND_PAYMENT_BOUNDARY.md` §18.
//!
//! # The two structural guarantees
//!
//! 1. **Producer ≠ approver, keyed on identity.** The [`AgentWorkloadCredential`](crate::authority::AgentWorkloadCredential)
//!    that *produced* an artifact is recorded on it. [`SodPolicy::evaluate_approval`] **refuses** an
//!    approval whose approver is the same Run as the producer. Because two Runs of the same role
//!    have distinct `run_id`s ([`WorkloadRef`] keys on `run_id`), this is *stronger* than a
//!    cross-model producer≠judge rule: even the identical model running as two Runs cannot
//!    self-approve, and even the identical Run cannot re-approve its own work.
//! 2. **Signed handoffs.** A handoff artifact is signed by the producer's AWC ([`HandoffSigner`]);
//!    the receiver [`verifies the signature`](SodPolicy::accept_handoff) **and** re-checks SoD
//!    before acting. A compromised Coder cannot forge a Judge's "approved" handoff because it
//!    cannot produce the Judge's AWC signature, and the SoD check rejects a self-produced approval
//!    even if the signature somehow verified.
//!
//! # Why the crypto is real (GAP-FIX identity-payments — SoD signed-handoffs, was a fake signature)
//!
//! Signing/verification is delegated to injected [`HandoffSigner`]/[`HandoffVerifier`] traits so a
//! deployment can swap in its PKI/HSM-backed ADR-023 signer with no call-site change. **Before this
//! fix, [`FakeSigner`]/[`AwcKeySigner`] were not cryptography at all**: the "signature" was a
//! `format!()` string that concatenated the raw shared secret *in cleartext* into the returned tag,
//! and verification was `signature == expected` — a non-constant-time string compare. That is worse
//! than no crypto: any party who ever observed a "signature" (a log line, a stored handoff, a network
//! capture) read the signing key itself, and the byte-by-byte `==` compare leaks timing information
//! about how many leading bytes matched. Both [`FakeSigner`] and [`AwcKeySigner`] now compute a real
//! **HMAC-SHA256** (RFC 2104, built from the `sha2` primitive already vetted for this crate's §13
//! transparency-log Merkle/STH work — no new dependency) over the handoff's signing material, keyed
//! by the (never-transmitted) secret; verification recomputes the tag and compares it in constant
//! time ([`ct_eq`]). The tag reveals nothing about the key, and a forged/altered handoff or a
//! guessed/wrong key produces a non-matching tag with cryptographic (not string-luck) probability.
//! The real deployment swaps the shared-secret HMAC key for the AWC's ADR-023 asymmetric key material
//! behind the identical [`HandoffSigner`]/[`HandoffVerifier`] seam — no call site changes.
//!
//! The **SoD decision** — producer≠approver by identity, and the approver-role allow-list — is pure,
//! deterministic, and needs no crypto, so it is exhaustively unit-testable here. A forged signature
//! and a self-approval are *both* rejected, and the tests prove each independently and in
//! combination.

use crate::authority::AgentWorkloadCredential;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

// ===========================================================================
// WorkloadRef — the identity an artifact/approval is attributed to
// ===========================================================================

/// A stable reference to the acting Run identity (a projection of an AWC, §18). SoD keys on
/// `run_id` — globally unique per Run — so two Runs of the same `def_ref` are distinct actors and
/// one may legitimately approve the other's work, but a Run can never approve its own.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct WorkloadRef {
    /// The versioned definition, `def:<kind>/<id>@<version>` — used for approver-role policy.
    pub def_ref: String,
    /// The per-Run instance id — the SoD identity key.
    pub run_id: String,
}

impl WorkloadRef {
    pub fn new(def_ref: impl Into<String>, run_id: impl Into<String>) -> Self {
        WorkloadRef {
            def_ref: def_ref.into(),
            run_id: run_id.into(),
        }
    }
}

impl From<&AgentWorkloadCredential> for WorkloadRef {
    fn from(awc: &AgentWorkloadCredential) -> Self {
        WorkloadRef {
            def_ref: awc.def_ref(),
            run_id: awc.run_id.clone(),
        }
    }
}

impl fmt::Display for WorkloadRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}#{}", self.def_ref, self.run_id)
    }
}

// ===========================================================================
// The produced artifact
// ===========================================================================

/// An artifact produced by a Run, carrying the producer's identity (§18 "the AWC that produced an
/// artifact is recorded on it"). The `content_digest` binds the artifact bytes to the identity so a
/// later approval/handoff is provably *about this artifact*, not a swapped one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProducedArtifact {
    pub artifact_id: String,
    pub producer: WorkloadRef,
    /// A digest of the artifact content (an injected digest — the crate does not hash bytes).
    pub content_digest: String,
}

impl ProducedArtifact {
    pub fn new(
        artifact_id: impl Into<String>,
        producer: WorkloadRef,
        content_digest: impl Into<String>,
    ) -> Self {
        ProducedArtifact {
            artifact_id: artifact_id.into(),
            producer,
            content_digest: content_digest.into(),
        }
    }
}

// ===========================================================================
// SoD policy + decision
// ===========================================================================

/// Why an approval was refused (§18). Every arm names the actors so audit sees exactly what was
/// blocked and why — never a bare boolean.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum SodError {
    /// The approver is the same Run that produced the artifact — self-approval (the core SoD rule).
    SelfApproval {
        producer: WorkloadRef,
        approver: WorkloadRef,
    },
    /// The approver's definition is not in the git-controlled approver-role allow-list for this
    /// action (§18 "which roles may approve which").
    ApproverRoleNotPermitted {
        approver_def_ref: String,
        permitted: BTreeSet<String>,
    },
    /// A signed handoff's signature did not verify — the claimed producer did not sign it (the
    /// forged-approval attack).
    SignatureInvalid { claimed_producer: WorkloadRef },
    /// The handoff's artifact digest does not match the artifact it claims to approve (a swap).
    ArtifactDigestMismatch { expected: String, presented: String },
}

impl fmt::Display for SodError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SodError::SelfApproval { producer, approver } => write!(
                f,
                "separation-of-duties violation: approver {approver} is the producer {producer} (self-approval)"
            ),
            SodError::ApproverRoleNotPermitted {
                approver_def_ref,
                permitted,
            } => write!(
                f,
                "approver role {approver_def_ref:?} is not permitted to approve; permitted: {permitted:?}"
            ),
            SodError::SignatureInvalid { claimed_producer } => write!(
                f,
                "handoff signature does not verify for claimed producer {claimed_producer} (forgery)"
            ),
            SodError::ArtifactDigestMismatch {
                expected,
                presented,
            } => write!(
                f,
                "handoff artifact digest {presented:?} does not match expected {expected:?}"
            ),
        }
    }
}

impl std::error::Error for SodError {}

/// The verdict carried by a *granted* approval (§18) — the audit-ready record of who produced and
/// who approved. Only ever constructed by [`SodPolicy::evaluate_approval`] / [`SodPolicy::accept_handoff`]
/// after the SoD (and, for handoffs, signature) checks pass, so its existence *is* the proof that
/// producer ≠ approver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalDecision {
    pub artifact_id: String,
    pub producer: WorkloadRef,
    pub approver: WorkloadRef,
    pub content_digest: String,
}

/// The git-controlled Separation-of-Duties policy (§18 "SoD policy is git-controlled"): which
/// definitions may approve. An empty allow-list means *any distinct Run* may approve (the producer≠
/// approver rule still always applies); a non-empty list additionally restricts approvers by role.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SodPolicy {
    /// `def_ref`s permitted to approve. Empty = no role restriction (identity SoD still enforced).
    permitted_approver_defs: BTreeSet<String>,
}

impl SodPolicy {
    /// A policy that enforces only the producer≠approver identity rule (no role restriction).
    pub fn identity_only() -> Self {
        Self::default()
    }

    /// Restrict approvers to the given definitions (in addition to the always-on identity rule).
    pub fn with_permitted_approvers<I, S>(defs: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        SodPolicy {
            permitted_approver_defs: defs.into_iter().map(Into::into).collect(),
        }
    }

    fn role_permitted(&self, approver_def_ref: &str) -> bool {
        self.permitted_approver_defs.is_empty()
            || self.permitted_approver_defs.contains(approver_def_ref)
    }

    /// Evaluate an approval of `artifact` by `approver` (§18). **Rejects** when the approver is the
    /// same Run that produced the artifact ([`SodError::SelfApproval`]) or when the approver's role
    /// is not permitted. On success returns the audit-ready [`ApprovalDecision`].
    pub fn evaluate_approval(
        &self,
        artifact: &ProducedArtifact,
        approver: &WorkloadRef,
    ) -> Result<ApprovalDecision, SodError> {
        // The core SoD rule: producer ≠ approver, keyed on the per-Run identity.
        if artifact.producer.run_id == approver.run_id {
            return Err(SodError::SelfApproval {
                producer: artifact.producer.clone(),
                approver: approver.clone(),
            });
        }
        if !self.role_permitted(&approver.def_ref) {
            return Err(SodError::ApproverRoleNotPermitted {
                approver_def_ref: approver.def_ref.clone(),
                permitted: self.permitted_approver_defs.clone(),
            });
        }
        Ok(ApprovalDecision {
            artifact_id: artifact.artifact_id.clone(),
            producer: artifact.producer.clone(),
            approver: approver.clone(),
            content_digest: artifact.content_digest.clone(),
        })
    }

    /// Accept a signed handoff and evaluate it as an approval (§18): the receiver **verifies the
    /// producer's signature** (a forgery is rejected), checks the artifact digest matches, then
    /// applies the SoD rule. All three must pass. This is the full close of Pass-5 [17]: a
    /// compromised Coder cannot present a Judge-signed approval it did not have the Judge's key to
    /// sign, and cannot approve its own output even with a valid signature.
    pub fn accept_handoff<V: HandoffVerifier>(
        &self,
        signed: &SignedHandoff,
        expected: &ProducedArtifact,
        verifier: &V,
    ) -> Result<ApprovalDecision, SodError> {
        // 1. The signature must be the claimed producer's, over this exact handoff.
        if !verifier.verify(&signed.handoff, &signed.signature) {
            return Err(SodError::SignatureInvalid {
                claimed_producer: signed.handoff.producer.clone(),
            });
        }
        // 2. The handoff must be about the artifact the receiver expects (no swap).
        if signed.handoff.content_digest != expected.content_digest {
            return Err(SodError::ArtifactDigestMismatch {
                expected: expected.content_digest.clone(),
                presented: signed.handoff.content_digest.clone(),
            });
        }
        // 3. SoD: the handoff's producer (the signer) must not be the approver/receiver's own Run.
        //    We evaluate the *receiver* approving the *signer-produced* artifact.
        let produced = ProducedArtifact {
            artifact_id: signed.handoff.artifact_id.clone(),
            producer: signed.handoff.producer.clone(),
            content_digest: signed.handoff.content_digest.clone(),
        };
        self.evaluate_approval(&produced, &signed.handoff.receiver)
    }
}

// ===========================================================================
// SodVerifyGate — the credential-facing verify-gate entrypoint the LIVE program
// verifier calls (ADR-022 §18 hot-wire)
// ===========================================================================

/// The Separation-of-Duties **verify gate** the live program verifier calls before it may treat a
/// produced artifact as approved / committable. It is a thin, credential-facing façade over
/// [`SodPolicy`]: the composition already holds the two [`AgentWorkloadCredential`]s in play — the
/// Run that PRODUCED the module output and the Run that would APPROVE (verify) it — so this gate
/// projects their identities via [`WorkloadRef::from`] and applies the SoD rule, rather than forcing
/// each caller to hand-build `WorkloadRef`s and re-implement the check. It exists so the wire is a
/// single, named entrypoint (`authorize_approval`) the program-verification loop drives at each
/// commit, and so the same gate handles both the direct-approval and signed-handoff paths.
///
/// The guarantee is unchanged and load-bearing: an approval whose approver Run is the producing Run
/// is **refused** ([`SodError::SelfApproval`]) — a Run can never approve its own work, even the same
/// role/model running as a distinct Run may (distinct `run_id`), and a forged or swapped signed
/// handoff is rejected before the SoD rule is even reached.
#[derive(Debug, Clone, Default)]
pub struct SodVerifyGate {
    policy: SodPolicy,
}

impl SodVerifyGate {
    /// A gate over an explicit git-controlled [`SodPolicy`] (approver-role allow-list + always-on
    /// identity rule).
    pub fn new(policy: SodPolicy) -> Self {
        SodVerifyGate { policy }
    }

    /// A gate that enforces ONLY the always-on producer≠approver identity rule (no role restriction).
    pub fn identity_only() -> Self {
        SodVerifyGate {
            policy: SodPolicy::identity_only(),
        }
    }

    /// The git-controlled policy behind this gate (for audit / introspection).
    pub fn policy(&self) -> &SodPolicy {
        &self.policy
    }

    /// **The entrypoint the program verifier calls.** Authorize `approver` (a verifier / judge Run's
    /// credential) to approve the artifact `artifact_id`/`content_digest` produced by `producer` (the
    /// Run that generated it). Both are the credentials the composition already minted; the gate keys
    /// SoD on their per-Run `run_id`s. Returns the audit-ready [`ApprovalDecision`] on grant, or
    /// [`SodError::SelfApproval`] when producer Run == approver Run (self-approval refused), or
    /// [`SodError::ApproverRoleNotPermitted`] when the approver's definition is out of policy.
    pub fn authorize_approval(
        &self,
        producer: &AgentWorkloadCredential,
        approver: &AgentWorkloadCredential,
        artifact_id: impl Into<String>,
        content_digest: impl Into<String>,
    ) -> Result<ApprovalDecision, SodError> {
        let artifact =
            ProducedArtifact::new(artifact_id, WorkloadRef::from(producer), content_digest);
        self.policy
            .evaluate_approval(&artifact, &WorkloadRef::from(approver))
    }

    /// The signed-handoff variant of the entrypoint: the receiver verifies the producer's signature
    /// (a forgery is rejected) and the artifact digest (a swap is rejected), then applies the SoD
    /// rule. All three must pass — the full close of Pass-5 [17].
    pub fn accept_handoff<V: HandoffVerifier>(
        &self,
        signed: &SignedHandoff,
        expected: &ProducedArtifact,
        verifier: &V,
    ) -> Result<ApprovalDecision, SodError> {
        self.policy.accept_handoff(signed, expected, verifier)
    }
}

// ===========================================================================
// Signed handoffs — ADR-022 §18
// ===========================================================================

/// A handoff of produced work from one Run to another (LOOP handoff contract, §18). Signed by the
/// producer's AWC; the receiver verifies before acting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Handoff {
    pub artifact_id: String,
    /// The Run that produced the work and signs the handoff.
    pub producer: WorkloadRef,
    /// The Run receiving the handoff (the prospective approver/next actor).
    pub receiver: WorkloadRef,
    pub content_digest: String,
}

impl Handoff {
    pub fn new(
        artifact_id: impl Into<String>,
        producer: WorkloadRef,
        receiver: WorkloadRef,
        content_digest: impl Into<String>,
    ) -> Self {
        Handoff {
            artifact_id: artifact_id.into(),
            producer,
            receiver,
            content_digest: content_digest.into(),
        }
    }

    /// The canonical bytes a signer signs / a verifier checks — deterministic and injection-safe
    /// (field-separated with a delimiter that cannot appear in the ids by construction convention).
    pub fn signing_material(&self) -> String {
        format!(
            "handoff\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}",
            self.artifact_id, self.producer, self.receiver, self.content_digest
        )
    }
}

/// A [`Handoff`] plus the producer's signature over it (§18).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedHandoff {
    pub handoff: Handoff,
    pub signature: String,
}

// ===========================================================================
// Real cryptographic primitive — HMAC-SHA256 (RFC 2104) over the `sha2` primitive already vetted
// for this crate (§13 transparency-log Merkle/STH). GAP-FIX identity-payments: this replaces the
// prior `format!()`-based "signature" that leaked the raw secret in cleartext.
// ===========================================================================

const HMAC_BLOCK_SIZE: usize = 64; // SHA-256's block size.

/// HMAC-SHA256(`key`, `message`) per RFC 2104, returning the raw 32-byte tag.
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    // The key is block-sized: hashed down if longer than the block, zero-padded if shorter.
    let mut key_block = [0u8; HMAC_BLOCK_SIZE];
    if key.len() > HMAC_BLOCK_SIZE {
        let hashed = Sha256::digest(key);
        key_block[..hashed.len()].copy_from_slice(&hashed);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; HMAC_BLOCK_SIZE];
    let mut opad = [0x5cu8; HMAC_BLOCK_SIZE];
    for i in 0..HMAC_BLOCK_SIZE {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }

    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(message);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    let result = outer.finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Lower-hex encode raw bytes (no external hex crate — a handful of bytes, trivial to hand-roll).
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Lower-hex decode; `Err` on odd length or a non-hex digit (a malformed/tampered signature string
/// fails closed here rather than panicking).
fn hex_decode(s: &str) -> Result<Vec<u8>, ()> {
    if s.len() % 2 != 0 {
        return Err(());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16).ok_or(())?;
        let lo = (bytes[i + 1] as char).to_digit(16).ok_or(())?;
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    Ok(out)
}

/// Constant-time byte-slice comparison — verification must NOT branch on the first mismatched byte
/// (a variable-time `==` on a MAC leaks how many leading bytes are correct, letting an attacker forge
/// the tag one byte at a time). Unequal lengths short-circuit to `false` (length is not secret here:
/// both sides always produce a fixed 32-byte tag).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Produces a signature over a handoff with the producer's AWC key material (§18/ADR-023). A seam:
/// the real impl uses the AWC's `key_id` crypto; [`FakeSigner`] is a deterministic offline stand-in.
pub trait HandoffSigner {
    fn sign(&self, handoff: &Handoff) -> String;
}

/// Verifies a producer's signature over a handoff (§18). The receiver holds only a *verifier* (the
/// producer's public key material in the real deployment), never the signer — it can check but not
/// forge.
pub trait HandoffVerifier {
    fn verify(&self, handoff: &Handoff, signature: &str) -> bool;
}

/// A real HMAC-SHA256 signer keyed by a per-identity shared secret — the offline seam impl (real
/// deployments swap this for the AWC's asymmetric ADR-023 key behind the identical trait, no call-site
/// change). GAP-FIX identity-payments: this used to be a `format!()` stub that put the raw `secret`
/// into the returned "signature" string; it now returns `hex(HMAC-SHA256(secret, run_id \x1f
/// signing_material))` — a real keyed MAC that reveals nothing about `secret` and is unforgeable
/// without it (cryptographic, not string-luck, unforgeability).
#[derive(Debug, Clone, Default)]
pub struct FakeSigner {
    /// The signing identity and its secret (the producer's private key stand-in).
    run_id: String,
    secret: String,
}

impl FakeSigner {
    pub fn new(run_id: impl Into<String>, secret: impl Into<String>) -> Self {
        FakeSigner {
            run_id: run_id.into(),
            secret: secret.into(),
        }
    }
}

impl HandoffSigner for FakeSigner {
    fn sign(&self, handoff: &Handoff) -> String {
        let message = format!("{}\u{1f}{}", self.run_id, handoff.signing_material());
        hex_encode(&hmac_sha256(self.secret.as_bytes(), message.as_bytes()))
    }
}

/// The public-side verifier for a [`FakeSigner`]: it holds the producer's `run_id` and the *expected
/// secret* (the shared HMAC key — a real asymmetric deployment holds only a public key here) and
/// recomputes the expected tag. A forger who does not know the secret cannot produce a matching tag
/// (cryptographic HMAC unforgeability, not a string-luck guess), and the comparison is constant-time.
#[derive(Debug, Clone, Default)]
pub struct FakeVerifier {
    expected_run_id: String,
    expected_secret: String,
}

impl FakeVerifier {
    pub fn new(expected_run_id: impl Into<String>, expected_secret: impl Into<String>) -> Self {
        FakeVerifier {
            expected_run_id: expected_run_id.into(),
            expected_secret: expected_secret.into(),
        }
    }
}

impl HandoffVerifier for FakeVerifier {
    fn verify(&self, handoff: &Handoff, signature: &str) -> bool {
        // The signature must be the producer's (by run_id) AND over this exact handoff material.
        if handoff.producer.run_id != self.expected_run_id {
            return false;
        }
        let message = format!(
            "{}\u{1f}{}",
            self.expected_run_id,
            handoff.signing_material()
        );
        let expected = hmac_sha256(self.expected_secret.as_bytes(), message.as_bytes());
        let Ok(given) = hex_decode(signature) else {
            return false;
        };
        ct_eq(&expected, &given)
    }
}

// ===========================================================================
// AWC-key-bound handoff signing — ADR-022 §18 (the AWC's real ADR-023 key material)
// ===========================================================================

/// A handoff signer bound to a **specific AWC's key material** (§18 / ADR-023): the signature is
/// produced under the credential's versioned `key_id` (the ADR-023 signing key, §16) and tied to its
/// per-Run `run_id`, and it carries a `trust_domain` — the attestation/PKI root the key chains to. A
/// signer for one credential cannot produce a signature that a verifier bound to a *different* trust
/// domain will accept, so a handoff is **unforgeable across the trust domain**: a compromised Run in
/// domain A cannot mint a signature that domain B's verifier trusts, even for its own `run_id`.
///
/// This is the offline seam over the real ADR-023 crypto: it models the exact unforgeability property
/// the design requires (only the holder of *this AWC's* key material, chaining to *this* trust root,
/// can sign) so the SoD/handoff guarantee is testable without a crypto dependency. The real
/// deployment swaps the deterministic tag for an ADR-023 signature over the same
/// [`Handoff::signing_material`] with no algorithm change.
#[derive(Debug, Clone, Default)]
pub struct AwcKeySigner {
    run_id: String,
    key_id: String,
    trust_domain: String,
    /// The private key material stand-in held only by the signer (never by a verifier).
    secret: String,
}

impl AwcKeySigner {
    /// Build a signer from the producing credential + its held key secret and trust-domain root. The
    /// `run_id`/`key_id` are read from the AWC so the signature is provably that credential's.
    pub fn for_credential(
        awc: &AgentWorkloadCredential,
        trust_domain: impl Into<String>,
        secret: impl Into<String>,
    ) -> Self {
        AwcKeySigner {
            run_id: awc.run_id.clone(),
            key_id: awc.key_id.clone(),
            trust_domain: trust_domain.into(),
            secret: secret.into(),
        }
    }

    /// The message the tag is computed over: everything that must be bound into the signature EXCEPT
    /// the key itself (`trust_domain`/`run_id`/`key_id`/`signing_material`) — a mismatch on any of
    /// these produces a different HMAC input and therefore a non-matching tag, so cross-domain or
    /// wrong-key forgery fails on the MAC itself, not on a separate string-equality side-check.
    fn message(&self, handoff: &Handoff) -> String {
        format!(
            "awcsig\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}",
            self.trust_domain,
            self.run_id,
            self.key_id,
            handoff.signing_material()
        )
    }
}

impl HandoffSigner for AwcKeySigner {
    fn sign(&self, handoff: &Handoff) -> String {
        hex_encode(&hmac_sha256(
            self.secret.as_bytes(),
            self.message(handoff).as_bytes(),
        ))
    }
}

/// The public-side verifier for an [`AwcKeySigner`] (§18): it holds the producer AWC's `run_id`/
/// `key_id`, the trust-domain root, and the public key material (the `secret` stand-in) and recomputes
/// the expected signature. It rejects a signature that (a) is not over this exact handoff, (b) does not
/// name the producer's `run_id`, (c) was minted under a different `key_id` (an old/rotated or wrong
/// key), or (d) chains to a **different trust domain** — the cross-domain unforgeability check.
#[derive(Debug, Clone, Default)]
pub struct AwcKeyVerifier {
    run_id: String,
    key_id: String,
    trust_domain: String,
    secret: String,
}

impl AwcKeyVerifier {
    pub fn for_credential(
        awc: &AgentWorkloadCredential,
        trust_domain: impl Into<String>,
        secret: impl Into<String>,
    ) -> Self {
        AwcKeyVerifier {
            run_id: awc.run_id.clone(),
            key_id: awc.key_id.clone(),
            trust_domain: trust_domain.into(),
            secret: secret.into(),
        }
    }
}

impl HandoffVerifier for AwcKeyVerifier {
    fn verify(&self, handoff: &Handoff, signature: &str) -> bool {
        // The handoff's claimed producer Run must be the credential this verifier is bound to.
        if handoff.producer.run_id != self.run_id {
            return false;
        }
        let message = format!(
            "awcsig\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}",
            self.trust_domain,
            self.run_id,
            self.key_id,
            handoff.signing_material()
        );
        let expected = hmac_sha256(self.secret.as_bytes(), message.as_bytes());
        let Ok(given) = hex_decode(signature) else {
            return false;
        };
        ct_eq(&expected, &given)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn coder() -> WorkloadRef {
        WorkloadRef::new("def:role/coder@v3", "run-coder-1")
    }
    fn judge() -> WorkloadRef {
        WorkloadRef::new("def:role/judge@v2", "run-judge-1")
    }
    fn artifact(producer: WorkloadRef) -> ProducedArtifact {
        ProducedArtifact::new("mr-42", producer, "digest-abc")
    }

    // ---- IDN-02: producer != approver, keyed on identity ------------------

    #[test]
    fn gap_idn_02_self_approval_is_rejected_same_run() {
        let policy = SodPolicy::identity_only();
        let art = artifact(coder());
        // The producing Run tries to approve its own artifact -> rejected.
        let err = policy.evaluate_approval(&art, &coder()).unwrap_err();
        assert_eq!(
            err,
            SodError::SelfApproval {
                producer: coder(),
                approver: coder(),
            }
        );
    }

    #[test]
    fn gap_idn_02_same_model_two_runs_still_cannot_self_approve() {
        // The SAME role/model running as two Runs: producer run-a, "approver" run-a is self; but a
        // DISTINCT run of the same role CAN approve (distinct identity). Proves keying on run_id.
        let policy = SodPolicy::identity_only();
        let prod = WorkloadRef::new("def:role/coder@v3", "run-a");
        let art = ProducedArtifact::new("mr-1", prod.clone(), "d1");

        // Same Run -> rejected.
        assert!(matches!(
            policy.evaluate_approval(&art, &prod),
            Err(SodError::SelfApproval { .. })
        ));
        // Same role, DIFFERENT Run -> permitted (a peer reviewer, distinct AWC).
        let peer = WorkloadRef::new("def:role/coder@v3", "run-b");
        let decision = policy.evaluate_approval(&art, &peer).unwrap();
        assert_eq!(decision.producer, prod);
        assert_eq!(decision.approver, peer);
        assert_eq!(decision.artifact_id, "mr-1");
    }

    #[test]
    fn gap_idn_02_distinct_approver_is_granted_and_recorded() {
        let policy = SodPolicy::identity_only();
        let art = artifact(coder());
        let decision = policy.evaluate_approval(&art, &judge()).unwrap();
        assert_eq!(decision.producer, coder());
        assert_eq!(decision.approver, judge());
        assert_eq!(decision.content_digest, "digest-abc");
    }

    #[test]
    fn gap_idn_02_approver_role_allow_list_is_enforced() {
        // Only the judge role may approve. A distinct-but-wrong role is rejected even though it
        // passes the identity rule.
        let policy = SodPolicy::with_permitted_approvers(["def:role/judge@v2"]);
        let art = artifact(coder());
        // A linter Run (distinct identity, wrong role) is refused.
        let linter = WorkloadRef::new("def:role/linter@v1", "run-linter-1");
        assert!(matches!(
            policy.evaluate_approval(&art, &linter),
            Err(SodError::ApproverRoleNotPermitted { .. })
        ));
        // The judge role is permitted.
        assert!(policy.evaluate_approval(&art, &judge()).is_ok());
    }

    // ---- IDN-02: signed handoffs (the forged-approval fix) ----------------

    #[test]
    fn gap_idn_02_forged_handoff_signature_is_rejected() {
        // A compromised Coder tries to present a handoff claiming the Judge produced/approved it,
        // but it cannot produce the Judge's signature (it lacks the Judge's secret).
        let policy = SodPolicy::identity_only();
        let judge_verifier = FakeVerifier::new("run-judge-1", "judge-secret");

        // The Coder forges a handoff *claiming* the judge is the producer, signing with its OWN key.
        let coder_signer = FakeSigner::new("run-coder-1", "coder-secret");
        let handoff = Handoff::new("mr-42", judge(), coder(), "digest-abc");
        let forged = SignedHandoff {
            signature: coder_signer.sign(&handoff), // wrong key for the claimed judge producer
            handoff,
        };
        let expected = artifact(judge());
        let err = policy
            .accept_handoff(&forged, &expected, &judge_verifier)
            .unwrap_err();
        assert_eq!(
            err,
            SodError::SignatureInvalid {
                claimed_producer: judge()
            }
        );
    }

    #[test]
    fn gap_idn_02_valid_judge_handoff_to_distinct_receiver_is_accepted() {
        // The Judge legitimately signs a handoff to a distinct deployer Run; signature verifies and
        // SoD passes (receiver != producer).
        let policy = SodPolicy::identity_only();
        let judge_signer = FakeSigner::new("run-judge-1", "judge-secret");
        let judge_verifier = FakeVerifier::new("run-judge-1", "judge-secret");
        let deployer = WorkloadRef::new("def:role/deployer@v1", "run-deployer-1");
        let handoff = Handoff::new("mr-42", judge(), deployer.clone(), "digest-abc");
        let signed = SignedHandoff {
            signature: judge_signer.sign(&handoff),
            handoff,
        };
        let expected = artifact(judge());
        let decision = policy
            .accept_handoff(&signed, &expected, &judge_verifier)
            .unwrap();
        assert_eq!(decision.producer, judge());
        assert_eq!(decision.approver, deployer);
    }

    #[test]
    fn gap_idn_02_validly_signed_but_self_approval_still_rejected() {
        // Even with a perfectly valid signature, a Run cannot approve its OWN handoff: the
        // signature proves authorship, the SoD rule still blocks self-approval.
        let policy = SodPolicy::identity_only();
        let coder_signer = FakeSigner::new("run-coder-1", "coder-secret");
        let coder_verifier = FakeVerifier::new("run-coder-1", "coder-secret");
        // producer == receiver == the coder Run.
        let handoff = Handoff::new("mr-42", coder(), coder(), "digest-abc");
        let signed = SignedHandoff {
            signature: coder_signer.sign(&handoff),
            handoff,
        };
        let expected = artifact(coder());
        let err = policy
            .accept_handoff(&signed, &expected, &coder_verifier)
            .unwrap_err();
        assert!(matches!(err, SodError::SelfApproval { .. }));
    }

    #[test]
    fn gap_idn_02_artifact_swap_is_rejected() {
        // A valid signature over a DIFFERENT artifact digest than the receiver expects is rejected.
        let policy = SodPolicy::identity_only();
        let judge_signer = FakeSigner::new("run-judge-1", "judge-secret");
        let judge_verifier = FakeVerifier::new("run-judge-1", "judge-secret");
        let deployer = WorkloadRef::new("def:role/deployer@v1", "run-deployer-1");
        let handoff = Handoff::new("mr-42", judge(), deployer, "digest-EVIL");
        let signed = SignedHandoff {
            signature: judge_signer.sign(&handoff),
            handoff,
        };
        let expected = artifact(judge()); // expects digest-abc
        let err = policy
            .accept_handoff(&signed, &expected, &judge_verifier)
            .unwrap_err();
        assert_eq!(
            err,
            SodError::ArtifactDigestMismatch {
                expected: "digest-abc".to_string(),
                presented: "digest-EVIL".to_string(),
            }
        );
    }

    #[test]
    fn workload_ref_from_awc_keys_on_run() {
        use crate::authority::{
            AttestationQuote, ControlPlaneProjection, IdentityAuthority, IssueRequest,
            ReferenceValueVerifier,
        };
        use crate::LogicalTime;
        use ainxt_types::DataClass;
        let mut aia = IdentityAuthority::new(
            ReferenceValueVerifier::new().with_measurement("m"),
            ControlPlaneProjection::new(["def:role/coder@v3".to_string()], LogicalTime(0), "c"),
            5,
            50,
            "k",
        );
        let q = AttestationQuote {
            def_content_hash: "h".to_string(),
            control_commit_sha: "c".to_string(),
            measurement: "m".to_string(),
            tee_quote: None,
        };
        let req = IssueRequest {
            def_kind: "role".to_string(),
            def_id: "coder".to_string(),
            def_version: "v3".to_string(),
            run_id: "run-xyz".to_string(),
            data_class: DataClass::Internal,
            requires_tee: false,
            obo_user_id: "u".to_string(),
            obo_department: None,
            obo_ad_level: None,
            obo_can_approve: false,
        };
        let awc = aia.issue(&req, &q, LogicalTime(1)).unwrap();
        let wref = WorkloadRef::from(&awc);
        assert_eq!(wref.def_ref, "def:role/coder@v3");
        assert_eq!(wref.run_id, "run-xyz");
    }

    // =======================================================================
    // GAP-FIX identity-payments — SoD signed-handoffs: real HMAC-SHA256, not a fake stub signature.
    // =======================================================================

    #[test]
    fn gap_idn_sod_hmac_is_deterministic_and_unforgeable_without_the_key() {
        let handoff = Handoff::new(
            "mr-1",
            WorkloadRef::new("def:role/coder@v3", "run-c1"),
            WorkloadRef::new("def:role/judge@v2", "run-j1"),
            "digest-1",
        );
        let signer = FakeSigner::new("run-c1", "the-real-secret");
        let verifier = FakeVerifier::new("run-c1", "the-real-secret");

        // Same key + same message ⇒ same tag (deterministic MAC), and it verifies.
        let sig1 = HandoffSigner::sign(&signer, &handoff);
        let sig2 = HandoffSigner::sign(&signer, &handoff);
        assert_eq!(sig1, sig2);
        assert!(HandoffVerifier::verify(&verifier, &handoff, &sig1));

        // A verifier holding the WRONG key rejects a genuinely-produced tag (no lucky string match).
        let wrong_key_verifier = FakeVerifier::new("run-c1", "a-guessed-secret");
        assert!(!HandoffVerifier::verify(
            &wrong_key_verifier,
            &handoff,
            &sig1
        ));

        // Flipping a single hex character (a bit-level tamper of the tag) must not verify — proves
        // the check is a real MAC recomputation, not a prefix/substring/length heuristic.
        let mut tampered = sig1.clone();
        let last = tampered.pop().unwrap();
        let flipped = if last == '0' { '1' } else { '0' };
        tampered.push(flipped);
        assert!(!HandoffVerifier::verify(&verifier, &handoff, &tampered));

        // A non-hex / malformed signature string fails closed rather than panicking.
        assert!(!HandoffVerifier::verify(
            &verifier,
            &handoff,
            "not-a-hex-signature!!"
        ));
    }

    #[test]
    fn gap_idn_sod_hmac_binds_the_full_message_not_just_a_prefix() {
        // Two handoffs differing only in content_digest must produce DIFFERENT tags under the same
        // key — proves the whole signing_material (not a truncated/partial view) is authenticated.
        let signer = FakeSigner::new("run-c1", "k");
        let h1 = Handoff::new(
            "mr-1",
            WorkloadRef::new("def:role/coder@v3", "run-c1"),
            WorkloadRef::new("def:role/judge@v2", "run-j1"),
            "digest-A",
        );
        let h2 = Handoff::new(
            "mr-1",
            WorkloadRef::new("def:role/coder@v3", "run-c1"),
            WorkloadRef::new("def:role/judge@v2", "run-j1"),
            "digest-B",
        );
        assert_ne!(
            HandoffSigner::sign(&signer, &h1),
            HandoffSigner::sign(&signer, &h2)
        );
    }

    #[test]
    fn gap_idn_sod_hmac_helper_matches_known_answer() {
        // A hand-computable known-answer sanity check on the raw primitive (independent of the
        // Handoff plumbing): HMAC-SHA256("key", "The quick brown fox jumps over the lazy dog") is a
        // published RFC/test-vector-style value used widely to sanity-check HMAC-SHA256 impls.
        let tag = hmac_sha256(b"key", b"The quick brown fox jumps over the lazy dog");
        assert_eq!(
            hex_encode(&tag),
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
    }

    #[test]
    fn gap_idn_sod_constant_time_eq_is_correct() {
        assert!(ct_eq(b"abcd", b"abcd"));
        assert!(!ct_eq(b"abcd", b"abce"));
        assert!(!ct_eq(b"abc", b"abcd")); // length mismatch
        assert!(!ct_eq(b"", b"a"));
        assert!(ct_eq(b"", b""));
    }
}
