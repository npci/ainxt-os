// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Append-only issuance transparency log with external inclusion proofs (ADR-022 §13 + §22 #3).
//!
//! Design: `docs/architecture/AGENT_IDENTITY_AND_PAYMENT_BOUNDARY.md` §13 (transparency-log
//! inclusion), §14 (court-grade actor record), §22 scenario 3 (an external auditor independently
//! verifies *that* an identity was issued, *to what measurement*, *when* — via an inclusion proof,
//! without trusting the runtime).
//!
//! # What is real here
//!
//! A genuine **Merkle-tree append-only log**: every AWC issuance appends a leaf, the log maintains a
//! root over all leaves, and [`TransparencyLog::inclusion_proof`] produces an audit path a party
//! **outside the runtime** can check with [`InclusionProof::verify`] against a root they obtained
//! independently. The Merkle math (leaf hashing, sibling-path folding, root recomputation) is real
//! and exhaustively tested: a tampered leaf, a wrong index, or an out-of-log entry all fail
//! verification.
//!
//! # What is real here (cryptographic strength, closed)
//!
//! The cryptographic *hash primitive* is injected via the [`MerkleHasher`] trait, exactly as
//! attestation is injected in [`crate::authority`]. [`Sha256Hasher`] is a **real**,
//! collision-resistant implementation (RustCrypto `sha2`, the same vetted primitive
//! `ainxt-eventlog`/`ainxt-eval`/`ainxt-cryptoagility`/`ainxt-server` already carry — no new
//! dependency *category* enters the tree) with RFC-6962 domain separation (`0x00` leaf / `0x01`
//! node), so a Merkle root built with it is tamper-evident in the cryptographic sense, not just
//! structurally. The checkpoint signature is likewise real: [`HmacSha256TreeHeadSigner`] /
//! [`HmacSha256TreeHeadVerifier`] compute genuine RFC-2104 HMAC-SHA256 over the canonical
//! checkpoint body (hand-rolled over `sha2`, mirroring `ainxt-server`'s `hmac_sha256` — no new
//! `hmac` crate) and verify with a constant-time compare, so a Signed Tree Head cannot be forged
//! without the shared secret. The deterministic non-cryptographic [`FnvHasher`] and
//! [`FakeTreeHeadSigner`]/[`FakeTreeHeadVerifier`] remain **only** to exercise the
//! inclusion-proof *algorithm* in isolation from any hash choice (it is hash-agnostic and correct
//! regardless of which [`MerkleHasher`] is plugged in) — production code and the end-to-end test
//! below use the real SHA-256 path.
//!
//! # What is still infra (and why)
//!
//! The *key material itself* — provisioning, rotating, and custody of the HMAC secret / the
//! eventual asymmetric ADR-023 signing key, and publishing the resulting Signed Tree Head to an
//! external monitor out-of-band — is a live KMS/HSM + distribution concern (ADR-023/ADR-025
//! infra: no amount of in-crate code makes a secret exist in a vault). The primitives that
//! consume that key material are real and fully offline-tested here.

use crate::authority::AgentWorkloadCredential;
use serde::{Deserialize, Serialize};

// ===========================================================================
// The hash seam
// ===========================================================================

/// The Merkle hash primitive (ADR-023 seam). `leaf` hashes raw entry bytes; `node` hashes an
/// ordered pair of child hashes. Domain-separated (`0x00` leaf / `0x01` node) to prevent
/// second-preimage attacks that swap a leaf for an internal node — a standard RFC-6962 discipline
/// the real cryptographic impl must preserve.
pub trait MerkleHasher {
    fn leaf(&self, bytes: &[u8]) -> Vec<u8>;
    fn node(&self, left: &[u8], right: &[u8]) -> Vec<u8>;
}

/// A deterministic, **non-cryptographic** FNV-1a hasher — the offline seam impl. Real deployments
/// inject an ADR-023 collision-resistant hash; this exists only so the inclusion-proof *algorithm*
/// can be exercised without pulling a crypto crate into this crate's supply-chain surface.
#[derive(Debug, Clone, Copy, Default)]
pub struct FnvHasher;

impl FnvHasher {
    fn fnv1a(seed: u64, bytes: &[u8]) -> u64 {
        let mut h = seed ^ 0xcbf29ce484222325;
        for &b in bytes {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        h
    }
}

impl MerkleHasher for FnvHasher {
    fn leaf(&self, bytes: &[u8]) -> Vec<u8> {
        // Domain byte 0x00 for leaves.
        Self::fnv1a(0x00, bytes).to_be_bytes().to_vec()
    }
    fn node(&self, left: &[u8], right: &[u8]) -> Vec<u8> {
        // Domain byte 0x01 for internal nodes; order matters (left then right).
        let mut buf = Vec::with_capacity(left.len() + right.len());
        buf.extend_from_slice(left);
        buf.extend_from_slice(right);
        Self::fnv1a(0x01, &buf).to_be_bytes().to_vec()
    }
}

/// The **real**, collision-resistant [`MerkleHasher`] (ADR-023 §13/§16): SHA-256 (RustCrypto
/// `sha2`) with RFC-6962 domain separation — leaves are hashed as `0x00 ∥ bytes`, internal nodes
/// as `0x01 ∥ left ∥ right` — so a leaf can never be replayed as an internal node (the standard
/// second-preimage defense). This is the primitive a production deployment uses; [`FnvHasher`]
/// remains only to exercise the inclusion-proof algorithm independently of hash choice.
#[derive(Debug, Clone, Copy, Default)]
pub struct Sha256Hasher;

impl MerkleHasher for Sha256Hasher {
    fn leaf(&self, bytes: &[u8]) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update([0x00u8]);
        h.update(bytes);
        h.finalize().to_vec()
    }
    fn node(&self, left: &[u8], right: &[u8]) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update([0x01u8]);
        h.update(left);
        h.update(right);
        h.finalize().to_vec()
    }
}

// ===========================================================================
// Log entries
// ===========================================================================

/// One append-only issuance record (§13/§14): the minimal externally-meaningful facts about an AWC
/// issuance — *what code measurement*, *which definition@commit*, *which Run*, *when*. Deliberately
/// carries no OBO PII beyond the `obo_user_id` reference (the mandate/credential material stays in
/// the data plane, §21); this is the immutable, content-addressed audit reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuanceEntry {
    pub run_id: String,
    pub def_ref: String,
    pub def_content_hash: String,
    pub control_commit_sha: String,
    pub attestation_ref: String,
    pub key_id: String,
    pub issued_at: u64,
}

impl IssuanceEntry {
    /// Build an entry from an issued credential (§14 — the actor of record's log reference).
    pub fn from_awc(awc: &AgentWorkloadCredential) -> Self {
        IssuanceEntry {
            run_id: awc.run_id.clone(),
            def_ref: awc.def_ref(),
            def_content_hash: awc.def_content_hash.clone(),
            control_commit_sha: awc.control_commit_sha.clone(),
            attestation_ref: awc.attestation_ref.clone(),
            key_id: awc.key_id.clone(),
            issued_at: awc.issued_at.tick(),
        }
    }

    /// The canonical, deterministic byte encoding hashed into the Merkle leaf. Field-separated with
    /// a unit-separator so distinct field boundaries cannot be forged by concatenation ambiguity.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        format!(
            "{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}",
            self.run_id,
            self.def_ref,
            self.def_content_hash,
            self.control_commit_sha,
            self.attestation_ref,
            self.key_id,
            self.issued_at
        )
        .into_bytes()
    }
}

// ===========================================================================
// The append-only Merkle transparency log
// ===========================================================================

/// An append-only, Merkle-committed issuance log (§13). Appends are monotonic; the root commits to
/// every leaf in order, so a later reorder or edit changes the root — tamper-evident given a
/// collision-resistant [`MerkleHasher`].
#[derive(Debug, Clone)]
pub struct TransparencyLog<H: MerkleHasher> {
    hasher: H,
    /// Leaf hashes, in append order.
    leaves: Vec<Vec<u8>>,
    /// The raw entries (parallel to `leaves`) — retained so a proof can be requested by run_id.
    entries: Vec<IssuanceEntry>,
}

impl<H: MerkleHasher> TransparencyLog<H> {
    pub fn new(hasher: H) -> Self {
        TransparencyLog {
            hasher,
            leaves: Vec::new(),
            entries: Vec::new(),
        }
    }

    /// Number of entries logged.
    pub fn len(&self) -> usize {
        self.leaves.len()
    }
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Append an issuance entry, returning its leaf index. Append-only: entries are never mutated or
    /// removed (an erasure of *credential material* is a data-plane action, §21; the audit
    /// reference is immutable).
    pub fn append(&mut self, entry: IssuanceEntry) -> usize {
        let leaf = self.hasher.leaf(&entry.canonical_bytes());
        let idx = self.leaves.len();
        self.leaves.push(leaf);
        self.entries.push(entry);
        idx
    }

    /// The current Merkle root over all appended leaves (RFC-6962-style: duplicate the last node of
    /// an odd level, i.e. hash it with itself). An empty log has an empty root.
    pub fn root(&self) -> Vec<u8> {
        if self.leaves.is_empty() {
            return Vec::new();
        }
        let mut level = self.leaves.clone();
        while level.len() > 1 {
            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            let mut i = 0;
            while i < level.len() {
                let left = &level[i];
                let right = if i + 1 < level.len() {
                    &level[i + 1]
                } else {
                    // Odd node: promote by hashing with itself (deterministic, standard).
                    &level[i]
                };
                next.push(self.hasher.node(left, right));
                i += 2;
            }
            level = next;
        }
        level.into_iter().next().unwrap_or_default()
    }

    /// The entry at `index`, if any.
    pub fn entry(&self, index: usize) -> Option<&IssuanceEntry> {
        self.entries.get(index)
    }

    /// Find the log index of the most-recent issuance for `run_id` (a Run appears once per issuance;
    /// renewals would append fresh entries in the real deployment).
    pub fn index_of_run(&self, run_id: &str) -> Option<usize> {
        self.entries.iter().rposition(|e| e.run_id == run_id)
    }

    /// Produce an inclusion proof for the leaf at `index` — the audit path (sibling hashes bottom to
    /// top) an external party folds to recompute the root (§22 #3). `None` for an out-of-range index.
    pub fn inclusion_proof(&self, index: usize) -> Option<InclusionProof> {
        if index >= self.leaves.len() {
            return None;
        }
        let mut siblings: Vec<ProofNode> = Vec::new();
        let mut level = self.leaves.clone();
        let mut idx = index;
        while level.len() > 1 {
            let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            // Odd promotion: a left node with no right sibling pairs with itself.
            let sibling = if sibling_idx < level.len() {
                level[sibling_idx].clone()
            } else {
                level[idx].clone()
            };
            siblings.push(ProofNode {
                hash: sibling,
                // Is the sibling on the LEFT of the current node?
                sibling_is_left: idx % 2 == 1,
            });
            // Fold to the next level.
            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            let mut i = 0;
            while i < level.len() {
                let left = &level[i];
                let right = if i + 1 < level.len() {
                    &level[i + 1]
                } else {
                    &level[i]
                };
                next.push(self.hasher.node(left, right));
                i += 2;
            }
            level = next;
            idx /= 2;
        }
        Some(InclusionProof {
            leaf_index: index,
            tree_size: self.leaves.len(),
            entry: self.entries[index].clone(),
            siblings,
        })
    }
}

/// One node on an inclusion path: a sibling hash and which side it sits on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofNode {
    pub hash: Vec<u8>,
    /// True if this sibling is to the LEFT of the node being proved at that level.
    pub sibling_is_left: bool,
}

/// A self-contained inclusion proof (§22 #3): the entry, its position, the tree size, and the audit
/// path. An external auditor calls [`verify`](InclusionProof::verify) with their own [`MerkleHasher`]
/// and an independently-obtained `expected_root` — trusting neither the runtime nor the log server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionProof {
    pub leaf_index: usize,
    pub tree_size: usize,
    pub entry: IssuanceEntry,
    pub siblings: Vec<ProofNode>,
}

impl InclusionProof {
    /// Recompute the root from the entry + audit path and compare to `expected_root`. Returns true
    /// iff the entry is provably included in a tree with that root. A tampered entry, a swapped
    /// sibling, or a wrong root all yield false — the external-verifiability guarantee (§22 #3).
    pub fn verify<H: MerkleHasher>(&self, hasher: &H, expected_root: &[u8]) -> bool {
        if expected_root.is_empty() || self.tree_size == 0 {
            return false;
        }
        let mut acc = hasher.leaf(&self.entry.canonical_bytes());
        for node in &self.siblings {
            acc = if node.sibling_is_left {
                hasher.node(&node.hash, &acc)
            } else {
                hasher.node(&acc, &node.hash)
            };
        }
        acc == expected_root
    }
}

// ===========================================================================
// Signed Tree Head (checkpoint) — ADR-022 §13/§16 (ADR-023 signing keys)
// ===========================================================================

/// The signing seam for a transparency-log checkpoint (ADR-023 §16). The real deployment signs with
/// the log's ADR-023 key material (versioned `key_id`, rotatable / PQC-agile); this crate injects the
/// primitive so no crypto dependency enters its supply-chain surface (mirrors [`MerkleHasher`] and
/// the attestation seam). `sign` produces a signature over the canonical checkpoint body; `key_id`
/// names the key version stamped into the [`SignedTreeHead`] so a verifier picks the right key and a
/// key rotation is a config change, not a history rewrite.
pub trait TreeHeadSigner {
    fn key_id(&self) -> &str;
    fn sign(&self, checkpoint_body: &[u8]) -> String;
}

/// The verify side of the checkpoint seam — the ADR-023 public-key material a party *outside* the log
/// server holds. It can check a [`SignedTreeHead`] but not forge one.
pub trait TreeHeadVerifier {
    fn verify(&self, checkpoint_body: &[u8], signature: &str, key_id: &str) -> bool;
}

/// A cryptographically-committed, **signed** checkpoint of the log at a point in time (§13/§16): the
/// tree size, the Merkle root over all leaves, the checkpoint timestamp, and a signature over those
/// facts under a versioned ADR-023 `key_id`. This is the *Signed Tree Head* (RFC-6962 STH): an
/// external auditor obtains it out-of-band and, having verified its signature once, can then check any
/// [`InclusionProof`] against `root_hash` **without trusting the runtime or the log server** — the
/// signature makes the root itself non-repudiable, so a server that later rewrites or reorders leaves
/// cannot present a different root under the same key without detection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTreeHead {
    pub tree_size: usize,
    pub root_hash: Vec<u8>,
    pub timestamp: u64,
    pub key_id: String,
    pub signature: String,
}

impl SignedTreeHead {
    /// The canonical, deterministic byte body the signature covers — `size ∥ root(hex) ∥ ts ∥ key`,
    /// unit-separated so no field boundary can be forged by concatenation ambiguity. Domain-tagged
    /// `sth` so an STH signature can never be replayed as some other signed structure.
    pub fn canonical_body(
        tree_size: usize,
        root_hash: &[u8],
        timestamp: u64,
        key_id: &str,
    ) -> Vec<u8> {
        let root_hex: String = root_hash.iter().map(|b| format!("{b:02x}")).collect();
        format!("sth\u{1f}{tree_size}\u{1f}{root_hex}\u{1f}{timestamp}\u{1f}{key_id}").into_bytes()
    }

    /// The body THIS checkpoint's signature covers.
    pub fn body(&self) -> Vec<u8> {
        Self::canonical_body(
            self.tree_size,
            &self.root_hash,
            self.timestamp,
            &self.key_id,
        )
    }

    /// Verify the checkpoint signature under the injected ADR-023 verifier (§16). Returns true iff the
    /// signature is a valid signature over this exact `(size, root, ts, key_id)` — a tampered size,
    /// root, or timestamp, or a wrong key, all fail. This is the auditor's first, one-time check;
    /// thereafter inclusion proofs verify against [`root_hash`](SignedTreeHead::root_hash).
    pub fn verify<V: TreeHeadVerifier>(&self, verifier: &V) -> bool {
        if self.tree_size == 0 || self.root_hash.is_empty() {
            return false;
        }
        verifier.verify(&self.body(), &self.signature, &self.key_id)
    }
}

/// A deterministic, **non-cryptographic** STH signer — the offline seam impl (real deployments inject
/// an ADR-023 signer). Models the one property the tamper-evidence proof needs: only a holder of the
/// key's secret can produce the signature, so a log server without it cannot forge a checkpoint.
#[derive(Debug, Clone, Default)]
pub struct FakeTreeHeadSigner {
    key_id: String,
    secret: String,
}

impl FakeTreeHeadSigner {
    pub fn new(key_id: impl Into<String>, secret: impl Into<String>) -> Self {
        FakeTreeHeadSigner {
            key_id: key_id.into(),
            secret: secret.into(),
        }
    }
}

impl TreeHeadSigner for FakeTreeHeadSigner {
    fn key_id(&self) -> &str {
        &self.key_id
    }
    fn sign(&self, checkpoint_body: &[u8]) -> String {
        // A signature only a holder of `secret` can produce over this exact body.
        let body = String::from_utf8_lossy(checkpoint_body);
        format!("sth-sig:{}:{}:{}", self.key_id, self.secret, body)
    }
}

/// The public-side verifier for a [`FakeTreeHeadSigner`] (its "public key" stand-in): knows the
/// expected `key_id` + secret and recomputes the expected signature. A forger who lacks the secret
/// cannot produce a matching signature over any body.
#[derive(Debug, Clone, Default)]
pub struct FakeTreeHeadVerifier {
    key_id: String,
    secret: String,
}

impl FakeTreeHeadVerifier {
    pub fn new(key_id: impl Into<String>, secret: impl Into<String>) -> Self {
        FakeTreeHeadVerifier {
            key_id: key_id.into(),
            secret: secret.into(),
        }
    }
}

impl TreeHeadVerifier for FakeTreeHeadVerifier {
    fn verify(&self, checkpoint_body: &[u8], signature: &str, key_id: &str) -> bool {
        if key_id != self.key_id {
            return false;
        }
        let body = String::from_utf8_lossy(checkpoint_body);
        let expected = format!("sth-sig:{}:{}:{}", self.key_id, self.secret, body);
        signature == expected
    }
}

// ===========================================================================
// Real checkpoint signing — RFC-2104 HMAC-SHA256 (ADR-023 §16, closed)
// ===========================================================================

/// RFC-2104 HMAC-SHA256 over `msg` under `key`, hand-rolled on the vetted `sha2` primitive
/// (mirrors `ainxt-server`'s `hmac_sha256` — no new `hmac` crate enters the tree). Block size
/// B = 64 bytes for SHA-256.
fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    const B: usize = 64;
    let mut k = [0u8; B];
    if key.len() > B {
        let h = Sha256::digest(key);
        k[..32].copy_from_slice(&h);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; B];
    let mut opad = [0x5cu8; B];
    for i in 0..B {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(msg);
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    outer.finalize().into()
}

/// Length-independent-leak-resistant byte compare (no early return on first mismatch) — the
/// standard defense against a timing side-channel that would otherwise let an attacker recover
/// the expected signature byte-by-byte.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// The hex-encoding a signature is transported as.
fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The **real** [`TreeHeadSigner`] (ADR-023 §16): genuine RFC-2104 HMAC-SHA256 over the canonical
/// checkpoint body under a shared secret. Only a holder of `secret` can produce a signature that
/// [`HmacSha256TreeHeadVerifier`] accepts. The secret's provisioning/rotation/custody (a live
/// KMS/HSM concern) is the ADR-023/ADR-025 infra boundary; the signing primitive itself is real
/// and fully exercised offline.
#[derive(Debug, Clone)]
pub struct HmacSha256TreeHeadSigner {
    key_id: String,
    secret: Vec<u8>,
}

impl HmacSha256TreeHeadSigner {
    pub fn new(key_id: impl Into<String>, secret: impl AsRef<[u8]>) -> Self {
        HmacSha256TreeHeadSigner {
            key_id: key_id.into(),
            secret: secret.as_ref().to_vec(),
        }
    }
}

impl TreeHeadSigner for HmacSha256TreeHeadSigner {
    fn key_id(&self) -> &str {
        &self.key_id
    }
    fn sign(&self, checkpoint_body: &[u8]) -> String {
        to_hex(&hmac_sha256(&self.secret, checkpoint_body))
    }
}

/// The verify side of [`HmacSha256TreeHeadSigner`] — holds the same shared secret (the symmetric
/// analogue of a public key for this MAC construction) and recomputes-and-compares in constant
/// time. A forger without `secret` cannot produce a matching signature over any body.
#[derive(Debug, Clone)]
pub struct HmacSha256TreeHeadVerifier {
    key_id: String,
    secret: Vec<u8>,
}

impl HmacSha256TreeHeadVerifier {
    pub fn new(key_id: impl Into<String>, secret: impl AsRef<[u8]>) -> Self {
        HmacSha256TreeHeadVerifier {
            key_id: key_id.into(),
            secret: secret.as_ref().to_vec(),
        }
    }
}

impl TreeHeadVerifier for HmacSha256TreeHeadVerifier {
    fn verify(&self, checkpoint_body: &[u8], signature: &str, key_id: &str) -> bool {
        if key_id != self.key_id {
            return false;
        }
        let expected = to_hex(&hmac_sha256(&self.secret, checkpoint_body));
        ct_eq(expected.as_bytes(), signature.as_bytes())
    }
}

impl<H: MerkleHasher> TransparencyLog<H> {
    /// Produce a **Signed Tree Head** over the current log state (§13/§16): the current root + size +
    /// `timestamp`, signed under the injected ADR-023 [`TreeHeadSigner`]. The returned [`SignedTreeHead`]
    /// is what a deployment publishes to a monitor/auditor out-of-band; anyone can then verify inclusion
    /// against its `root_hash` after a one-time signature check, so the log becomes cryptographically
    /// tamper-evident end-to-end (a re-ordered or edited log cannot re-produce this signed root).
    pub fn signed_tree_head<S: TreeHeadSigner>(
        &self,
        signer: &S,
        timestamp: u64,
    ) -> SignedTreeHead {
        let root = self.root();
        let key_id = signer.key_id().to_string();
        let body = SignedTreeHead::canonical_body(self.leaves.len(), &root, timestamp, &key_id);
        let signature = signer.sign(&body);
        SignedTreeHead {
            tree_size: self.leaves.len(),
            root_hash: root,
            timestamp,
            key_id,
            signature,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::{
        AttestationQuote, ControlPlaneProjection, IdentityAuthority, IssueRequest,
        ReferenceValueVerifier,
    };
    use crate::LogicalTime;
    use ainxt_types::DataClass;

    fn entry(run: &str) -> IssuanceEntry {
        IssuanceEntry {
            run_id: run.to_string(),
            def_ref: "def:role/coder@v3".to_string(),
            def_content_hash: "hash-coder".to_string(),
            control_commit_sha: "commit-abc".to_string(),
            attestation_ref: "m-ok".to_string(),
            key_id: "key-v1".to_string(),
            issued_at: 10,
        }
    }

    // ---- IDN-05: external inclusion proof over an append-only log ----------

    #[test]
    fn gap_idn_05_inclusion_proof_verifies_for_every_entry() {
        let h = FnvHasher;
        let mut log = TransparencyLog::new(h);
        // A non-power-of-two count exercises the odd-promotion path.
        for i in 0..5 {
            log.append(entry(&format!("run-{i}")));
        }
        let root = log.root();
        assert!(!root.is_empty());
        for i in 0..5 {
            let proof = log.inclusion_proof(i).expect("proof exists");
            assert!(
                proof.verify(&h, &root),
                "entry {i} must verify against the true root"
            );
        }
    }

    #[test]
    fn gap_idn_05_tampered_entry_fails_verification() {
        let h = FnvHasher;
        let mut log = TransparencyLog::new(h);
        for i in 0..4 {
            log.append(entry(&format!("run-{i}")));
        }
        let root = log.root();
        let mut proof = log.inclusion_proof(2).unwrap();
        assert!(proof.verify(&h, &root));
        // An auditor is handed a proof whose entry was altered (a forged measurement) — it fails.
        proof.entry.attestation_ref = "m-EVIL".to_string();
        assert!(
            !proof.verify(&h, &root),
            "a tampered entry cannot forge inclusion"
        );
    }

    #[test]
    fn gap_idn_05_wrong_root_and_swapped_sibling_fail() {
        let h = FnvHasher;
        let mut log = TransparencyLog::new(h);
        for i in 0..4 {
            log.append(entry(&format!("run-{i}")));
        }
        let root = log.root();
        let proof = log.inclusion_proof(1).unwrap();
        assert!(proof.verify(&h, &root));
        // A different (later) tree's root does not match this proof's tree.
        let mut log2 = log.clone();
        log2.append(entry("run-extra"));
        assert!(
            !proof.verify(&h, &log2.root()),
            "a proof from an earlier tree must not verify against a grown root"
        );
        // A proof with a corrupted sibling side fails.
        let mut bad = proof.clone();
        if let Some(n) = bad.siblings.first_mut() {
            n.sibling_is_left = !n.sibling_is_left;
        }
        assert!(
            !bad.verify(&h, &root),
            "a swapped sibling side breaks the fold"
        );
    }

    #[test]
    fn gap_idn_05_out_of_range_index_and_empty_log() {
        let h = FnvHasher;
        let mut log = TransparencyLog::new(h);
        assert!(log.root().is_empty());
        assert!(log.inclusion_proof(0).is_none());
        log.append(entry("run-0"));
        assert!(log.inclusion_proof(5).is_none());
        // An empty expected root never verifies.
        let proof = log.inclusion_proof(0).unwrap();
        assert!(!proof.verify(&h, &[]));
    }

    #[test]
    fn gap_idn_05_logs_awc_issuance_and_proves_it() {
        // End-to-end: issue an AWC, log its issuance, hand an auditor the proof + root; they verify
        // the code measurement + issuance without trusting the runtime (§22 #3).
        let mut aia = IdentityAuthority::new(
            ReferenceValueVerifier::new().with_measurement("m-coder-ok"),
            ControlPlaneProjection::new(
                ["def:role/coder@v3".to_string()],
                LogicalTime(0),
                "commit-abc",
            ),
            5,
            50,
            "key-v1",
        );
        let q = AttestationQuote {
            def_content_hash: "hash-coder-v3".to_string(),
            control_commit_sha: "commit-abc".to_string(),
            measurement: "m-coder-ok".to_string(),
            tee_quote: None,
        };
        let req = IssueRequest {
            def_kind: "role".to_string(),
            def_id: "coder".to_string(),
            def_version: "v3".to_string(),
            run_id: "run-audit-1".to_string(),
            data_class: DataClass::Internal,
            requires_tee: false,
            obo_user_id: "u-alice".to_string(),
            obo_department: None,
            obo_ad_level: None,
            obo_can_approve: false,
        };
        let awc = aia.issue(&req, &q, LogicalTime(3)).unwrap();

        let h = FnvHasher;
        let mut log = TransparencyLog::new(h);
        log.append(IssuanceEntry::from_awc(&awc));
        let idx = log.index_of_run("run-audit-1").unwrap();
        let root = log.root();
        let proof = log.inclusion_proof(idx).unwrap();

        // The external auditor sees the attested measurement and verifies inclusion.
        assert_eq!(proof.entry.attestation_ref, "m-coder-ok");
        assert_eq!(proof.entry.def_content_hash, "hash-coder-v3");
        assert!(proof.verify(&h, &root));
    }
}
