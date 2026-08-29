// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! ainxt-governance — git-native governance + marketplace (Phase 5, ADR-026).
//!
//! Definitions (harnesses, skills, agents, policies) are governed by **git primitives**, not a DB
//! status column. The lifecycle is a small state machine mapped onto git events:
//!
//! ```text
//! DRAFT (a branch) --open PR--> PENDING_APPROVAL (PR + CI) --CODEOWNERS-approved signed merge-->
//!   APPROVED (on main) --signed semver tag on env/prod--> PRODUCTION --deprecate--> DEPRECATED
//! ```
//!
//! Two invariants matter:
//! - **`publish` emits a Pull Request, never a DB row** ([`publish`]). The artifact of publishing is
//!   a PR descriptor to open on the control repo — governance is the PR review, CI, and signed merge,
//!   so nothing becomes authoritative without clearing them.
//! - **The pre-receive gate BLOCKS, it does not redact** ([`PrereceiveGate`]). Unlike the
//!   redact-and-proceed rule at runtime, a push carrying PII/secrets is *rejected* — git history is
//!   non-erasable, so a leaked secret must never land in it (ADR-026 §10).
//!
//! The marketplace ([`Marketplace`]) is a federation of **pinned git repos** with trust-on-first-use
//! hash pinning: the first sight of a source pins its hash; a later hash or URL mismatch is rejected
//! (a repointed or tampered dependency cannot slip in).
//!
//! Pure and testable; clean-room throughout.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ============================ Lifecycle ============================

/// The governance state of a definition — each backed by a git primitive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GovernanceState {
    /// A working branch.
    Draft,
    /// An open PR with CI running.
    PendingApproval,
    /// Merged to main (CODEOWNERS-approved, signed).
    Approved,
    /// A signed semver tag promoted onto the env/prod ref.
    Production,
    /// Retired.
    Deprecated,
}

/// A git event that drives a state transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitEvent {
    /// Open a working branch → [`Draft`](GovernanceState::Draft).
    OpenBranch,
    /// Open a PR from the draft branch.
    OpenPr,
    /// Close/reject the PR, back to the branch.
    ClosePr,
    /// CODEOWNERS-approved, signed merge to main.
    MergeApproved,
    /// Promote a signed semver tag onto the env/prod ref.
    PromoteSignedTag,
    /// Retire a production definition.
    Deprecate,
}

/// An invalid lifecycle transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionError {
    pub from: GovernanceState,
    pub event: GitEvent,
}

impl fmt::Display for TransitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid transition {:?} on {:?}", self.event, self.from)
    }
}
impl std::error::Error for TransitionError {}

/// Advance the lifecycle. Only the git-native transitions are valid; anything else is refused (you
/// cannot, e.g., jump a draft straight to production, or reopen a PR on a shipped definition).
pub fn advance(
    state: GovernanceState,
    event: GitEvent,
) -> Result<GovernanceState, TransitionError> {
    use GitEvent::*;
    use GovernanceState::*;
    let next = match (state, event) {
        (Draft, OpenPr) => PendingApproval,
        (PendingApproval, ClosePr) => Draft,
        (PendingApproval, MergeApproved) => Approved,
        (Approved, PromoteSignedTag) => Production,
        (Production, Deprecate) => Deprecated,
        // OpenBranch is only valid as the very first step (handled by `start`), not a transition.
        _ => return Err(TransitionError { from: state, event }),
    };
    Ok(next)
}

/// The initial state when a definition is first branched.
pub fn start() -> GovernanceState {
    GovernanceState::Draft
}

// ============================ Enforced transitions (CODEOWNERS + signatures) ============================

/// A CODEOWNERS approval on a PR: who approved and the CODEOWNERS groups they belong to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeownersApproval {
    pub approver: String,
    pub groups: Vec<String>,
}

/// The CODEOWNERS policy for the control repo: which owner (a user id or a group) must approve a
/// change to `path`. A real impl reads `.gitlab/CODEOWNERS`; the check is mandatory, only the policy
/// source is configurable.
pub trait CodeownersPolicy: Send + Sync {
    /// The owners (user ids and/or group names) any one of which must approve `path`.
    fn required_owners(&self, path: &str) -> Vec<String>;
}

/// A deterministic policy that maps a single owner to every path (the manifest's `owner` field).
pub struct SingleOwnerPolicy {
    pub owner: String,
}
impl CodeownersPolicy for SingleOwnerPolicy {
    fn required_owners(&self, _path: &str) -> Vec<String> {
        vec![self.owner.clone()]
    }
}

/// A cryptographic signature over a git object (a merge commit or a tag).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    pub key_id: String,
    pub signature: String,
}

/// Verifies a signature over a payload. A real impl checks a detached GPG/SSH/sigstore signature
/// against a trusted-key set; this seam keeps the lifecycle logic crypto-agnostic. The check is
/// mandatory (a promotion is never label-only) — only the verifier behind it is configurable.
pub trait SignatureVerifier: Send + Sync {
    fn verify(&self, payload: &str, sig: &Signature) -> bool;
}

/// OSS deterministic placeholder verifier (no crypto dependency): a signature is valid iff its
/// `key_id` is trusted and its `signature` equals the documented deterministic scheme
/// `"{key_id}:{payload}"`. This is NOT real cryptography — the enterprise plugin swaps in a real
/// GPG/sigstore verifier behind this same trait — but it is a genuine, non-tautological check: a
/// forged signature or an untrusted key is rejected.
pub struct TrustedKeyVerifier {
    trusted: BTreeMap<String, ()>,
}
impl TrustedKeyVerifier {
    pub fn new<S: Into<String>>(keys: impl IntoIterator<Item = S>) -> Self {
        TrustedKeyVerifier {
            trusted: keys.into_iter().map(|k| (k.into(), ())).collect(),
        }
    }
    /// The signature this verifier expects for `payload` under `key_id` (helper for signers/tests).
    pub fn expected_signature(key_id: &str, payload: &str) -> String {
        format!("{key_id}:{payload}")
    }
}
impl SignatureVerifier for TrustedKeyVerifier {
    fn verify(&self, payload: &str, sig: &Signature) -> bool {
        self.trusted.contains_key(&sig.key_id)
            && sig.signature == Self::expected_signature(&sig.key_id, payload)
    }
}

/// A **real cryptographic** [`SignatureVerifier`]: HMAC-SHA256 over the payload, keyed per `key_id`
/// (RustCrypto `sha2`, MIT/Apache-2.0 — the same permissive primitive already vetted elsewhere in the
/// workspace, e.g. `ainxt-server`'s HS256 JWT verifier). Unlike [`TrustedKeyVerifier`] (a deterministic
/// `"{key_id}:{payload}"` string-equality placeholder — NOT cryptography, just a non-tautological
/// stand-in), this is genuine keyed-MAC authentication: forging a valid signature for an untrusted or
/// wrong key requires breaking HMAC-SHA256, not guessing a string format. Every key comparison and the
/// final tag comparison are constant-time, so verification time never leaks which byte first
/// mismatched (a timing side-channel on a signature check is itself a forgery primitive).
///
/// This is still deliberately the OSS-tier answer, not the enterprise one: the design's eventual real
/// impl is a detached GPG/SSH/sigstore signature against an asymmetric trusted-key set (so the signer
/// need not share a long-lived secret with the verifier) — that upgrade drops in behind this same
/// [`SignatureVerifier`] trait without touching the lifecycle logic. HMAC is the correct STOPGAP
/// because it is real, cheap, dependency-light (no new crate — `sha2` is already in the tree), and
/// strictly stronger than a placeholder: a forged signature or an untrusted/wrong key is rejected by
/// actual cryptographic hardness, not by string luck.
pub struct HmacSha256Verifier {
    /// `key_id` -> shared HMAC secret. Held only in memory; a real deployment resolves this from a
    /// vault/KMS, never a literal in source.
    keys: BTreeMap<String, Vec<u8>>,
}

impl HmacSha256Verifier {
    pub fn new<S: Into<String>, K: Into<Vec<u8>>>(keys: impl IntoIterator<Item = (S, K)>) -> Self {
        HmacSha256Verifier {
            keys: keys
                .into_iter()
                .map(|(id, secret)| (id.into(), secret.into()))
                .collect(),
        }
    }

    /// Sign `payload` under `key_id`'s secret (helper for signers/tests — a real signer holds the
    /// secret out-of-band; this just makes the construction concrete and testable here).
    pub fn sign(&self, key_id: &str, payload: &str) -> Option<Signature> {
        let secret = self.keys.get(key_id)?;
        Some(Signature {
            key_id: key_id.to_string(),
            signature: hex_encode(&hmac_sha256(secret, payload.as_bytes())),
        })
    }
}

impl SignatureVerifier for HmacSha256Verifier {
    fn verify(&self, payload: &str, sig: &Signature) -> bool {
        let Some(secret) = self.keys.get(&sig.key_id) else {
            return false; // untrusted key id — never computed against, never accepted
        };
        let Ok(given) = hex_decode(&sig.signature) else {
            return false; // malformed tag — a genuine HMAC never fails to hex-decode a good signature
        };
        let expected = hmac_sha256(secret, payload.as_bytes());
        ct_eq(&expected, &given)
    }
}

/// Hand-rolled HMAC-SHA256 (RFC 2104) over `sha2::Sha256` directly — the identical construction
/// `ainxt-server`'s HS256 JWT verifier already uses, so no new crate (`hmac`) enters the dependency
/// tree; `sha2` is already vetted permissive (MIT/Apache-2.0) in the workspace. Block size B = 64 for
/// SHA-256.
fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    const BLOCK: usize = 64;
    let mut key_block = [0u8; BLOCK];
    if key.len() > BLOCK {
        let hashed = Sha256::digest(key);
        key_block[..hashed.len()].copy_from_slice(&hashed);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(msg);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    let out = outer.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(&out);
    result
}

/// Lowercase hex encoding (no external crate needed for this tiny, allocation-light helper).
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Decode a lowercase (or mixed-case) hex string into bytes. `Err` on odd length or a non-hex digit —
/// a malformed tag is treated as a verification failure, never a panic.
fn hex_decode(s: &str) -> Result<Vec<u8>, ()> {
    if s.len() % 2 != 0 {
        return Err(());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for chunk in bytes.chunks(2) {
        let hi = (chunk[0] as char).to_digit(16).ok_or(())?;
        let lo = (chunk[1] as char).to_digit(16).ok_or(())?;
        out.push(((hi << 4) | lo) as u8);
    }
    Ok(out)
}

/// Constant-time byte-slice equality (same discipline as any secret/signature comparison elsewhere in
/// the tree) — an early-return `==` would leak the length of the common prefix via timing.
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

/// Evidence accompanying a lifecycle transition.
pub enum GovEvidence<'a> {
    /// No extra evidence (for label-only transitions like OpenPr/ClosePr/Deprecate).
    None,
    /// A CODEOWNERS-approved, signed merge to main.
    Merge {
        /// The manifest path being merged (drives CODEOWNERS lookup).
        path: &'a str,
        approval: &'a CodeownersApproval,
        /// The signed merge-commit payload + its signature.
        payload: &'a str,
        signature: &'a Signature,
    },
    /// A signed semver tag promoted onto the env/prod ref.
    Tag {
        payload: &'a str,
        signature: &'a Signature,
    },
}

/// Why an enforced transition was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovError {
    /// The state/event pair is not a valid transition.
    InvalidTransition(TransitionError),
    /// The transition requires evidence that was not supplied.
    MissingEvidence { event: GitEvent },
    /// No CODEOWNERS-approved reviewer approved the merge.
    MissingCodeownersApproval { path: String, required: Vec<String> },
    /// The merge/tag signature failed verification (forged or untrusted key).
    BadSignature { key_id: String },
}

impl fmt::Display for GovError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GovError::InvalidTransition(t) => write!(f, "{t}"),
            GovError::MissingEvidence { event } => {
                write!(f, "transition {event:?} requires evidence")
            }
            GovError::MissingCodeownersApproval { path, required } => write!(
                f,
                "merge of '{path}' needs approval from one of {required:?}"
            ),
            GovError::BadSignature { key_id } => {
                write!(f, "signature by key '{key_id}' failed verification")
            }
        }
    }
}
impl std::error::Error for GovError {}

fn approval_satisfies(approval: &CodeownersApproval, required: &[String]) -> bool {
    required
        .iter()
        .any(|r| &approval.approver == r || approval.groups.iter().any(|g| g == r))
}

/// Advance the lifecycle **with enforcement**: [`GitEvent::MergeApproved`] requires a CODEOWNERS
/// approval that satisfies the path's required owners AND a verified merge signature;
/// [`GitEvent::PromoteSignedTag`] requires a verified tag signature. Every other transition is the
/// pure label transition (evidence may be [`GovEvidence::None`]). This is the difference between a
/// label-only state machine and a git-native one that actually gates on review + signing.
pub fn advance_with_evidence(
    state: GovernanceState,
    event: GitEvent,
    evidence: GovEvidence<'_>,
    codeowners: &dyn CodeownersPolicy,
    verifier: &dyn SignatureVerifier,
) -> Result<GovernanceState, GovError> {
    // The label transition must be valid first.
    let next = advance(state, event).map_err(GovError::InvalidTransition)?;

    match event {
        GitEvent::MergeApproved => match evidence {
            GovEvidence::Merge {
                path,
                approval,
                payload,
                signature,
            } => {
                let required = codeowners.required_owners(path);
                if !approval_satisfies(approval, &required) {
                    return Err(GovError::MissingCodeownersApproval {
                        path: path.to_string(),
                        required,
                    });
                }
                if !verifier.verify(payload, signature) {
                    return Err(GovError::BadSignature {
                        key_id: signature.key_id.clone(),
                    });
                }
                Ok(next)
            }
            _ => Err(GovError::MissingEvidence { event }),
        },
        GitEvent::PromoteSignedTag => match evidence {
            GovEvidence::Tag { payload, signature } => {
                if !verifier.verify(payload, signature) {
                    return Err(GovError::BadSignature {
                        key_id: signature.key_id.clone(),
                    });
                }
                Ok(next)
            }
            _ => Err(GovError::MissingEvidence { event }),
        },
        // Label-only transitions carry no signing/approval requirement.
        _ => Ok(next),
    }
}

// ============================ Publish = emit a PR (not a DB row) ============================

/// A request to publish a definition: its id, the branch it lives on, the file path in the control
/// repo, and its content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishRequest {
    pub definition_id: String,
    pub branch: String,
    pub path: String,
    pub content: String,
}

/// A pull request descriptor — the artifact of publishing. Opening this on the control repo starts
/// the PENDING_APPROVAL phase (CI + CODEOWNERS review). Publishing writes NO database row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PullRequest {
    pub branch: String,
    pub target: String,
    pub title: String,
    pub body: String,
    /// The files (path, content) the PR stages.
    pub files: Vec<(String, String)>,
}

/// Publish a definition by emitting a [`PullRequest`] to the control repo — never a DB write. The
/// returned PR, once opened, is in [`GovernanceState::PendingApproval`].
pub fn publish(req: PublishRequest) -> PullRequest {
    PullRequest {
        branch: req.branch,
        target: "main".to_string(),
        title: format!("publish definition '{}'", req.definition_id),
        body: format!(
            "Automated publish of '{}'. Governance = this PR: CI + CODEOWNERS review + signed merge.",
            req.definition_id
        ),
        files: vec![(req.path, req.content)],
    }
}

// ============================ Pre-receive gate (blocks, never redacts) ============================

/// Scans pushed files and BLOCKS the push if any carry PII/secrets. Unlike the runtime's
/// redact-and-proceed, this refuses — git history is permanent (ADR-026 §10).
pub trait PrereceiveGate: Send + Sync {
    /// `Ok(())` to accept the push; `Err(findings)` to reject it.
    fn check(&self, files: &[(String, String)]) -> Result<(), Vec<String>>;
}

/// Deterministic gate: rejects a push whose files contain a PAN-like digit run (≥12) or a secret
/// marker. Production plugs in the full PCI/DSS detector behind this seam.
pub struct MarkerPrereceiveGate;

impl PrereceiveGate for MarkerPrereceiveGate {
    fn check(&self, files: &[(String, String)]) -> Result<(), Vec<String>> {
        let mut findings = Vec::new();
        for (path, content) in files {
            let mut run = 0usize;
            for c in content.chars() {
                if c.is_ascii_digit() {
                    run += 1;
                } else {
                    if run >= 12 {
                        findings.push(format!("{path}: PAN-like digit run"));
                    }
                    run = 0;
                }
            }
            if run >= 12 {
                findings.push(format!("{path}: PAN-like digit run"));
            }
            for marker in ["PAN=", "SECRET=", "API_KEY=", "TOKEN=", "PRIVATE KEY"] {
                if content.contains(marker) {
                    findings.push(format!("{path}: secret marker '{marker}'"));
                }
            }
        }
        if findings.is_empty() {
            Ok(())
        } else {
            Err(findings)
        }
    }
}

/// Run the pre-receive gate over a PR's staged files.
pub fn gate_push(pr: &PullRequest, gate: &dyn PrereceiveGate) -> Result<(), Vec<String>> {
    gate.check(&pr.files)
}

// ============ Payment-boundary front-matter CI gate (IDN-07, ADR-026 §5) ============

// The payment-boundary *policy core* lives in `ainxt-payments`; the CI runner / pre-receive hook
// lives here (the governance control plane) and calls it (see `ainxt_payments::front_matter`).
pub use ainxt_payments::front_matter::{
    authorize_authoring, evaluate_changeset, AuthoringContext, BlockedDefinition,
    ChangedDefinition, FrontMatterError, PaymentBoundaryClass, PAYMENT_AUTHOR_MAX_AD_LEVEL,
};

/// Extract the `payment_boundary` front-matter value from a control-plane definition body.
///
/// Recognises the YAML (`payment_boundary: x`), TOML (`payment_boundary = "x"`) and JSON
/// (`"payment_boundary": "x"`) spellings, tolerant of surrounding quotes and a trailing comma.
/// Returns `None` when the field is absent — [`PaymentBoundaryClass::parse`] treats the empty
/// value as the safe [`PaymentBoundaryClass::None`] default.
fn extract_payment_boundary(content: &str) -> Option<String> {
    const KEY: &str = "payment_boundary";
    for raw in content.lines() {
        let line = raw.trim();
        // Match the bare, JSON-quoted, or single-quoted key form.
        let after_key = if let Some(r) = line.strip_prefix(KEY) {
            r
        } else if let Some(r) = line.strip_prefix(&format!("\"{KEY}\"")) {
            r
        } else if let Some(r) = line.strip_prefix(&format!("'{KEY}'")) {
            r
        } else {
            continue;
        };
        // The next non-space char must be a `:` or `=` separator — otherwise this was a longer
        // identifier that merely starts with the key (e.g. `payment_boundary_note`).
        let after_key = after_key.trim_start();
        let after_sep = match after_key
            .strip_prefix(':')
            .or_else(|| after_key.strip_prefix('='))
        {
            Some(v) => v,
            None => continue,
        };
        let val = after_sep
            .trim()
            .trim_end_matches(',')
            .trim()
            .trim_matches('"')
            .trim_matches('\'')
            .trim();
        return Some(val.to_string());
    }
    None
}

/// Why the control-plane CI / pre-receive gate refused a push.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CiGateError {
    /// A definition's `payment_boundary` front-matter value or its authoring was refused — the
    /// reserved `payment-initiating` value, an unknown value, or unauthorized payment-adjacent
    /// authoring (missing payments-council CODEOWNERS / unsigned / too-junior). Fail-closed.
    FrontMatter {
        path: String,
        error: FrontMatterError,
        /// GAP-FIX payments-governance: any OTHER offending files in the SAME push, beyond
        /// `path`/`error` — the whole-push property [`evaluate_changeset`] provides (name EVERY
        /// offender in one pass) that a per-file `?`-early-return loop cannot express. Empty for the
        /// common single-bad-file case, so every pre-existing single-file caller is unaffected.
        also_blocked: Vec<BlockedDefinition>,
    },
    /// The pre-receive PII/secret gate blocked the push (blocks, never redacts — history is
    /// permanent, ADR-026 §10).
    Prereceive { findings: Vec<String> },
}

impl fmt::Display for CiGateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CiGateError::FrontMatter {
                path,
                error,
                also_blocked,
            } => {
                if also_blocked.is_empty() {
                    write!(f, "{path}: payment_boundary front-matter refused: {error}")
                } else {
                    write!(
                        f,
                        "{path}: payment_boundary front-matter refused: {error} (+ {} more \
                         offending file(s) in this push: {also_blocked:?})",
                        also_blocked.len()
                    )
                }
            }
            CiGateError::Prereceive { findings } => {
                write!(f, "pre-receive gate blocked push: {findings:?}")
            }
        }
    }
}
impl std::error::Error for CiGateError {}

/// The control-plane CI / pre-receive gate (IDN-07 + the pre-receive block).
///
/// For the whole push it:
/// 1. delegates to [`evaluate_changeset`] (`ainxt_payments::front_matter`) — the single whole-push
///    front-matter/authoring decision the crate documents as "the single call the git pre-receive
///    hook and CI job both make". It parses each definition's `payment_boundary` front-matter via
///    [`PaymentBoundaryClass::parse`] (the reserved `payment-initiating` value, and any unknown
///    value, is **rejected** so it can never merge, ADR-026 §5), runs [`authorize_authoring`] with
///    the commit's `authoring` evidence (a `payment-adjacent` definition requires payments-council
///    CODEOWNERS + a signed `ad_level <= 3` `can_approve` commit), and — unlike a per-file
///    `?`-early-return loop — names EVERY offending file in the push in one pass, not just the
///    first (a genuine whole-push property; see [`CiGateError::FrontMatter`]'s `also_blocked`);
/// 2. runs the [`PrereceiveGate`] over the whole push — a PII/secret finding **blocks** it.
///
/// Every check is fail-closed. On success it returns the parsed class of each file (for audit).
/// The `gate` is any [`PrereceiveGate`] — the OSS [`MarkerPrereceiveGate`] or the enterprise
/// compliance-backed gate (`ainxt_admission::ComplianceBackedPrereceiveGate`) injected by the CI
/// composition root. `authoring` is applied uniformly to every file in `pr` — the single commit's
/// evidence a real git pre-receive hook has for the whole push it is screening.
pub fn gate_control_plane_push(
    pr: &PullRequest,
    gate: &dyn PrereceiveGate,
    authoring: &AuthoringContext,
) -> Result<Vec<(String, PaymentBoundaryClass)>, CiGateError> {
    let changes: Vec<ChangedDefinition> = pr
        .files
        .iter()
        .map(|(path, content)| ChangedDefinition {
            path: path.clone(),
            raw_payment_boundary: extract_payment_boundary(content).unwrap_or_default(),
            authoring: authoring.clone(),
        })
        .collect();
    if let Err(mut blocked) = evaluate_changeset(&changes) {
        // `evaluate_changeset` only errs with a non-empty Vec — the first entry becomes the
        // primary `path`/`error` (preserving the pre-existing single-offender error shape), any
        // remaining offenders ride along in `also_blocked` so none are silently dropped.
        let first = blocked.remove(0);
        return Err(CiGateError::FrontMatter {
            path: first.path,
            error: first.error,
            also_blocked: blocked,
        });
    }
    let classes = changes
        .iter()
        .map(|c| {
            // Safe: `evaluate_changeset` above already proved every entry parses and authorizes
            // cleanly, so re-parsing here (to recover the typed class for the caller) cannot fail.
            let class = PaymentBoundaryClass::parse(&c.raw_payment_boundary)
                .expect("evaluate_changeset already validated this parses");
            (c.path.clone(), class)
        })
        .collect();
    gate.check(&pr.files)
        .map_err(|findings| CiGateError::Prereceive { findings })?;
    Ok(classes)
}

// ============================ Marketplace (TOFU hash-pin) ============================

/// A pinned marketplace source: a git repo pinned to a specific content hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedSource {
    pub name: String,
    pub repo_url: String,
    pub pinned_hash: String,
}

/// A supply-chain integrity failure resolving a marketplace source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MarketError {
    /// The source's hash differs from its pin (tampered / unexpected content).
    HashMismatch {
        name: String,
        expected: String,
        actual: String,
    },
    /// The source's URL differs from its pin (repointed dependency).
    UrlMismatch {
        name: String,
        expected: String,
        actual: String,
    },
}

impl fmt::Display for MarketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MarketError::HashMismatch {
                name,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "source '{name}': hash mismatch (pinned {expected}, got {actual})"
                )
            }
            MarketError::UrlMismatch {
                name,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "source '{name}': url mismatch (pinned {expected}, got {actual})"
                )
            }
        }
    }
}
impl std::error::Error for MarketError {}

/// A federation of pinned git repos. Trust-on-first-use: the first resolution of a name pins it; any
/// later resolution must match the pin exactly.
#[derive(Debug, Default, Clone)]
pub struct Marketplace {
    sources: BTreeMap<String, PinnedSource>,
}

impl Marketplace {
    pub fn new() -> Self {
        Marketplace {
            sources: BTreeMap::new(),
        }
    }

    /// Resolve a source under TOFU. First sight pins it (returns `Ok`); afterwards the URL + hash
    /// must match the pin, else the source is rejected.
    pub fn resolve(&mut self, candidate: PinnedSource) -> Result<(), MarketError> {
        match self.sources.get(&candidate.name) {
            None => {
                self.sources.insert(candidate.name.clone(), candidate);
                Ok(())
            }
            Some(pinned) => {
                if pinned.repo_url != candidate.repo_url {
                    return Err(MarketError::UrlMismatch {
                        name: candidate.name,
                        expected: pinned.repo_url.clone(),
                        actual: candidate.repo_url,
                    });
                }
                if pinned.pinned_hash != candidate.pinned_hash {
                    return Err(MarketError::HashMismatch {
                        name: candidate.name,
                        expected: pinned.pinned_hash.clone(),
                        actual: candidate.pinned_hash,
                    });
                }
                Ok(())
            }
        }
    }

    pub fn pin_of(&self, name: &str) -> Option<&PinnedSource> {
        self.sources.get(name)
    }
    pub fn len(&self) -> usize {
        self.sources.len()
    }
    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn happy_path_lifecycle() {
        let mut s = start();
        assert_eq!(s, GovernanceState::Draft);
        s = advance(s, GitEvent::OpenPr).unwrap();
        assert_eq!(s, GovernanceState::PendingApproval);
        s = advance(s, GitEvent::MergeApproved).unwrap();
        assert_eq!(s, GovernanceState::Approved);
        s = advance(s, GitEvent::PromoteSignedTag).unwrap();
        assert_eq!(s, GovernanceState::Production);
        s = advance(s, GitEvent::Deprecate).unwrap();
        assert_eq!(s, GovernanceState::Deprecated);
    }

    #[test]
    fn pr_can_be_rejected_back_to_draft() {
        let s = advance(GovernanceState::Draft, GitEvent::OpenPr).unwrap();
        assert_eq!(
            advance(s, GitEvent::ClosePr).unwrap(),
            GovernanceState::Draft
        );
    }

    #[test]
    fn invalid_transitions_are_refused() {
        // Cannot jump a draft straight to production.
        assert!(advance(GovernanceState::Draft, GitEvent::PromoteSignedTag).is_err());
        // Cannot merge without a PR.
        assert!(advance(GovernanceState::Draft, GitEvent::MergeApproved).is_err());
        // Cannot reopen a PR on a shipped definition.
        assert!(advance(GovernanceState::Production, GitEvent::OpenPr).is_err());
        // OpenBranch is not a transition (it's the start).
        assert!(advance(GovernanceState::Draft, GitEvent::OpenBranch).is_err());
    }

    #[test]
    fn publish_emits_a_pr_not_a_db_row() {
        let pr = publish(PublishRequest {
            definition_id: "harness.rca".into(),
            branch: "publish/harness.rca".into(),
            path: "harnesses/rca.md".into(),
            content: "id = \"rca\"".into(),
        });
        assert_eq!(pr.target, "main");
        assert_eq!(pr.branch, "publish/harness.rca");
        assert_eq!(
            pr.files,
            vec![("harnesses/rca.md".to_string(), "id = \"rca\"".to_string())]
        );
        assert!(pr.title.contains("harness.rca"));
        // Opening this PR is the PENDING_APPROVAL phase.
        assert_eq!(
            advance(start(), GitEvent::OpenPr).unwrap(),
            GovernanceState::PendingApproval
        );
    }

    #[test]
    fn prereceive_gate_blocks_pii_but_not_clean_pushes() {
        let dirty = publish(PublishRequest {
            definition_id: "x".into(),
            branch: "b".into(),
            path: "x.md".into(),
            content: "token PAN=4111111111111111".into(),
        });
        let findings = gate_push(&dirty, &MarkerPrereceiveGate).unwrap_err();
        assert!(!findings.is_empty(), "a push with a PAN must be blocked");

        let clean = publish(PublishRequest {
            definition_id: "y".into(),
            branch: "b".into(),
            path: "y.md".into(),
            content: "id = \"y\"\ndescription = \"safe\"".into(),
        });
        assert!(gate_push(&clean, &MarkerPrereceiveGate).is_ok());
    }

    #[test]
    fn marketplace_tofu_pins_then_enforces() {
        let mut m = Marketplace::new();
        let src = |h: &str, u: &str| PinnedSource {
            name: "acme-harnesses".into(),
            repo_url: u.into(),
            pinned_hash: h.into(),
        };
        // First use pins.
        assert!(m.resolve(src("hash-abc", "https://git/acme")).is_ok());
        assert_eq!(m.len(), 1);
        // Same hash + url → ok.
        assert!(m.resolve(src("hash-abc", "https://git/acme")).is_ok());
        // Different hash → rejected (tampered content).
        assert!(matches!(
            m.resolve(src("hash-XYZ", "https://git/acme")),
            Err(MarketError::HashMismatch { .. })
        ));
        // Different url → rejected (repointed dependency).
        assert!(matches!(
            m.resolve(src("hash-abc", "https://evil/acme")),
            Err(MarketError::UrlMismatch { .. })
        ));
    }

    // ---- enforced (git-native) transitions ----

    fn merge_sig(payload: &str) -> Signature {
        Signature {
            key_id: "release-key".into(),
            signature: TrustedKeyVerifier::expected_signature("release-key", payload),
        }
    }

    #[test]
    fn merge_requires_codeowners_approval_and_a_valid_signature() {
        let codeowners = SingleOwnerPolicy {
            owner: "settlement-ops".into(),
        };
        let verifier = TrustedKeyVerifier::new(["release-key"]);
        let payload = "merge harness.rca -> main";
        let good = CodeownersApproval {
            approver: "alice".into(),
            groups: vec!["settlement-ops".into()],
        };

        // Happy path: owner-group approval + valid signature → Approved.
        let ok = advance_with_evidence(
            GovernanceState::PendingApproval,
            GitEvent::MergeApproved,
            GovEvidence::Merge {
                path: "harnesses/rca.md",
                approval: &good,
                payload,
                signature: &merge_sig(payload),
            },
            &codeowners,
            &verifier,
        );
        assert_eq!(ok.unwrap(), GovernanceState::Approved);

        // A reviewer outside CODEOWNERS cannot approve the merge.
        let outsider = CodeownersApproval {
            approver: "mallory".into(),
            groups: vec!["retail".into()],
        };
        assert!(matches!(
            advance_with_evidence(
                GovernanceState::PendingApproval,
                GitEvent::MergeApproved,
                GovEvidence::Merge {
                    path: "harnesses/rca.md",
                    approval: &outsider,
                    payload,
                    signature: &merge_sig(payload),
                },
                &codeowners,
                &verifier,
            ),
            Err(GovError::MissingCodeownersApproval { .. })
        ));

        // A forged signature (right approval) is rejected.
        let forged = Signature {
            key_id: "release-key".into(),
            signature: "not-the-real-sig".into(),
        };
        assert!(matches!(
            advance_with_evidence(
                GovernanceState::PendingApproval,
                GitEvent::MergeApproved,
                GovEvidence::Merge {
                    path: "harnesses/rca.md",
                    approval: &good,
                    payload,
                    signature: &forged,
                },
                &codeowners,
                &verifier,
            ),
            Err(GovError::BadSignature { .. })
        ));

        // A signature over a DIFFERENT payload (tamper) is rejected.
        assert!(matches!(
            advance_with_evidence(
                GovernanceState::PendingApproval,
                GitEvent::MergeApproved,
                GovEvidence::Merge {
                    path: "harnesses/rca.md",
                    approval: &good,
                    payload,
                    signature: &merge_sig("merge SOMETHING ELSE -> main"),
                },
                &codeowners,
                &verifier,
            ),
            Err(GovError::BadSignature { .. })
        ));

        // Merge with no evidence is refused (not a label-only transition).
        assert!(matches!(
            advance_with_evidence(
                GovernanceState::PendingApproval,
                GitEvent::MergeApproved,
                GovEvidence::None,
                &codeowners,
                &verifier,
            ),
            Err(GovError::MissingEvidence { .. })
        ));
    }

    #[test]
    fn promote_requires_a_signed_tag_by_a_trusted_key() {
        let codeowners = SingleOwnerPolicy { owner: "x".into() };
        let verifier = TrustedKeyVerifier::new(["release-key"]);
        let payload = "tag v1.0.0 on prod";
        let sig = Signature {
            key_id: "release-key".into(),
            signature: TrustedKeyVerifier::expected_signature("release-key", payload),
        };
        assert_eq!(
            advance_with_evidence(
                GovernanceState::Approved,
                GitEvent::PromoteSignedTag,
                GovEvidence::Tag {
                    payload,
                    signature: &sig
                },
                &codeowners,
                &verifier,
            )
            .unwrap(),
            GovernanceState::Production
        );

        // An untrusted key cannot promote.
        let untrusted = Signature {
            key_id: "attacker-key".into(),
            signature: TrustedKeyVerifier::expected_signature("attacker-key", payload),
        };
        assert!(matches!(
            advance_with_evidence(
                GovernanceState::Approved,
                GitEvent::PromoteSignedTag,
                GovEvidence::Tag {
                    payload,
                    signature: &untrusted
                },
                &codeowners,
                &verifier,
            ),
            Err(GovError::BadSignature { .. })
        ));
    }

    // ---- r15: real cryptographic (HMAC-SHA256) signature verification ----

    #[test]
    fn r15_hmac_verifier_accepts_a_genuine_signature_and_rejects_forgeries() {
        let verifier = HmacSha256Verifier::new([("release-key", b"super-secret-key".to_vec())]);
        let payload = "merge harness.rca -> main";
        let sig = verifier
            .sign("release-key", payload)
            .expect("known key signs");

        assert!(
            verifier.verify(payload, &sig),
            "a genuine signature must verify"
        );

        // Tamper with the payload after signing — the SAME tag must now fail (this is what makes it
        // real crypto: a placeholder string-equality scheme can't distinguish "signed X" from "signed
        // Y" unless it re-derives the expected string, but a keyed MAC is payload-bound by construction).
        assert!(
            !verifier.verify("merge SOMETHING ELSE -> main", &sig),
            "a tampered payload must invalidate the signature"
        );

        // An untrusted key id is never accepted, even with a well-formed hex tag.
        let untrusted = Signature {
            key_id: "attacker-key".into(),
            signature: sig.signature.clone(),
        };
        assert!(!verifier.verify(payload, &untrusted));

        // A signature keyed under the WRONG (but trusted) secret is rejected — proves verification is
        // keyed on the actual secret bytes, not just "any hex string for a known key_id passes".
        let other =
            HmacSha256Verifier::new([("release-key", b"a-totally-different-secret".to_vec())]);
        let wrong_secret_sig = other.sign("release-key", payload).unwrap();
        assert!(
            !verifier.verify(payload, &wrong_secret_sig),
            "a signature made under a different secret must not verify against this verifier's key"
        );

        // A bit-flipped tag (still valid hex, same length) must not verify — proves the comparison is
        // over the actual MAC bytes, not a length/format check.
        let mut flipped = sig.signature.clone();
        let last = flipped.pop().unwrap();
        flipped.push(if last == '0' { '1' } else { '0' });
        let bitflipped = Signature {
            key_id: "release-key".into(),
            signature: flipped,
        };
        assert!(!verifier.verify(payload, &bitflipped));

        // Malformed (non-hex / odd-length) signature text fails closed, never panics.
        let malformed = Signature {
            key_id: "release-key".into(),
            signature: "not-hex-at-all".into(),
        };
        assert!(!verifier.verify(payload, &malformed));
    }

    #[test]
    fn r15_hmac_verifier_drives_the_real_lifecycle_transition() {
        // The SAME `advance_with_evidence` enforcement path, now backed by real crypto instead of the
        // deterministic placeholder — proves `HmacSha256Verifier` drops in behind `SignatureVerifier`
        // with zero change to the lifecycle logic (design intent: "the enterprise plugin swaps in a
        // real verifier behind this same trait").
        let codeowners = SingleOwnerPolicy {
            owner: "settlement-ops".into(),
        };
        let verifier = HmacSha256Verifier::new([("release-key", b"prod-signing-secret".to_vec())]);
        let payload = "tag v1.0.0 on prod";
        let sig = verifier.sign("release-key", payload).unwrap();

        assert_eq!(
            advance_with_evidence(
                GovernanceState::Approved,
                GitEvent::PromoteSignedTag,
                GovEvidence::Tag {
                    payload,
                    signature: &sig
                },
                &codeowners,
                &verifier,
            )
            .unwrap(),
            GovernanceState::Production
        );

        // A forged tag (right key id, wrong bytes) cannot promote.
        let forged = Signature {
            key_id: "release-key".into(),
            signature: "00".repeat(32), // well-formed hex, wrong MAC
        };
        assert!(matches!(
            advance_with_evidence(
                GovernanceState::Approved,
                GitEvent::PromoteSignedTag,
                GovEvidence::Tag {
                    payload,
                    signature: &forged
                },
                &codeowners,
                &verifier,
            ),
            Err(GovError::BadSignature { .. })
        ));
    }

    #[test]
    fn r15_hmac_produces_a_64_char_lowercase_hex_sha256_tag() {
        // Sanity on the wire shape: HMAC-SHA256 is a 32-byte MAC, hex-encoded to 64 lowercase chars.
        let verifier = HmacSha256Verifier::new([("k", b"secret".to_vec())]);
        let sig = verifier.sign("k", "payload").unwrap();
        assert_eq!(sig.signature.len(), 64);
        assert!(sig
            .signature
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));

        // Deterministic: signing the same payload twice yields the identical tag (no nonce/salt) —
        // required so a verifier can recompute and compare, the whole point of a MAC.
        let sig2 = verifier.sign("k", "payload").unwrap();
        assert_eq!(sig.signature, sig2.signature);

        // A different payload yields a different tag (no accidental collisions in this construction).
        let sig3 = verifier.sign("k", "different payload").unwrap();
        assert_ne!(sig.signature, sig3.signature);
    }

    #[test]
    fn enforced_transition_still_rejects_an_invalid_label_transition() {
        let codeowners = SingleOwnerPolicy { owner: "x".into() };
        let verifier = TrustedKeyVerifier::new(["k"]);
        // Cannot promote straight from Draft even with a valid-looking tag.
        assert!(matches!(
            advance_with_evidence(
                GovernanceState::Draft,
                GitEvent::PromoteSignedTag,
                GovEvidence::None,
                &codeowners,
                &verifier,
            ),
            Err(GovError::InvalidTransition(_))
        ));
    }

    #[test]
    fn descriptors_serde_round_trip() {
        let pr = PullRequest {
            branch: "b".into(),
            target: "main".into(),
            title: "t".into(),
            body: "x".into(),
            files: vec![("a".into(), "b".into())],
        };
        assert_eq!(
            serde_json::from_str::<PullRequest>(&serde_json::to_string(&pr).unwrap()).unwrap(),
            pr
        );
        let src = PinnedSource {
            name: "n".into(),
            repo_url: "u".into(),
            pinned_hash: "h".into(),
        };
        assert_eq!(
            serde_json::from_str::<PinnedSource>(&serde_json::to_string(&src).unwrap()).unwrap(),
            src
        );
    }
}
