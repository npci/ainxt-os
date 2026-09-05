// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! The reference in-memory [`MemoryStore`] plus the enterprise operations layered on it:
//! edit-free versioning + forensic replay (§7.5), retention/decay/right-to-erasure (§5), a
//! tamper-evident audit chain (`AK`), retroactive re-redaction and data-class-routed re-embedding
//! (§8.5/§8.6), and the "what do you remember about me" consent surface (§5).
//!
//! Deterministic: a logical clock (no wall time) assigns write ticks (`seq`); a hash chain
//! (FNV-1a here — a real deployment wires the runtime's SHA-256 Event-Log hasher behind the same
//! shape) makes governance/erasure events tamper-evident. Nothing here uses rng or the wall clock.

use std::collections::HashMap;

use crate::{
    embedder_allowed, precedence_class, relevance, required_embedder_kind, AccessScope, Author,
    EdgeKind, EmbedderKind, Embedding, GovernanceState, MemoryError, MemoryHit, MemoryItem,
    MemoryKind, MemoryQuery, MemoryStore, Principal, RankOrder, Redactor, SchemaRegistry, Scope,
    CAP_APPROVE,
};

// ============================ Built-in compliance redactor ============================

/// The always-on default compliance redactor installed by [`InMemoryStore::new`] so the
/// compliance-on-write gate is **never off by omission** (design §8.4 / the A1 invariant:
/// "configurable provider, never configurable off"). A deployment swaps in its own richer provider
/// via [`InMemoryStore::with_redactor`] (adapting the runtime's full compliance engine into the
/// [`Redactor`] seam), but no store ever exists *without a gate*: the seam is mandatory, only the
/// provider is configurable.
///
/// This built-in is a conservative, dependency-free floor — **not** the full platform engine:
/// Luhn-valid card numbers (PAN, incl. space/dash-grouped), Verhoeff-valid 12-digit Aadhaar, and
/// high-signal secret tokens (known key prefixes + long high-entropy strings). It errs toward
/// catching obvious leaks without mangling ordinary prose.
#[derive(Debug, Default, Clone, Copy)]
pub struct BuiltinRedactor;

/// A no-op redactor used **only** as a transient placeholder while the real provider is borrowed
/// during a re-redaction pass — it is never the installed gate. Kept private on purpose so no
/// caller can construct a store whose gate is a no-op.
#[derive(Debug, Default, Clone, Copy)]
struct PlaceholderRedactor;
impl Redactor for PlaceholderRedactor {
    fn redact(&self, text: &str) -> String {
        text.to_string()
    }
}

fn luhn_ok(digits: &[u8]) -> bool {
    if digits.len() < 12 {
        return false;
    }
    let mut sum = 0u32;
    let mut alt = false;
    for &d in digits.iter().rev() {
        let mut v = d as u32;
        if alt {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
        alt = !alt;
    }
    sum % 10 == 0
}

// Verhoeff dihedral-group tables (public-domain algorithm) for Aadhaar checksum validation.
const VERHOEFF_D: [[u8; 10]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];
const VERHOEFF_P: [[u8; 10]; 8] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];
fn verhoeff_ok(digits: &[u8]) -> bool {
    if digits.len() != 12 {
        return false;
    }
    let mut c = 0u8;
    for (i, &d) in digits.iter().rev().enumerate() {
        c = VERHOEFF_D[c as usize][VERHOEFF_P[i % 8][d as usize] as usize];
    }
    c == 0
}

/// Shannon entropy (bits/char) of a token — used to distinguish a random secret from a word.
fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    let mut n = 0usize;
    for b in s.bytes() {
        counts[b as usize] += 1;
        n += 1;
    }
    let n = n as f64;
    let mut h = 0.0;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f64 / n;
            h -= p * p.log2();
        }
    }
    h
}

/// Whether a whitespace-delimited token looks like a leaked secret/credential.
fn looks_like_secret(token: &str) -> bool {
    let t = token_core(token);
    const PREFIXES: &[&str] = &[
        "sk-", "sk_", "AKIA", "ghp_", "gho_", "xoxb-", "xoxp-", "AIza",
    ];
    if PREFIXES.iter().any(|p| t.starts_with(p)) && t.len() >= 12 {
        return true;
    }
    if t.len() >= 32
        && t.chars().all(|c| {
            c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '+' || c == '/' || c == '='
        })
        && t.chars().any(|c| c.is_ascii_digit())
        && t.chars().any(|c| c.is_ascii_alphabetic())
        && shannon_entropy(t) >= 3.5
    {
        return true;
    }
    false
}

/// Chars kept as part of a token "core" (surrounding punctuation is affix, stripped for matching
/// and re-attached after redaction so ordinary prose punctuation survives).
fn is_core_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@' | '+' | '/' | '=')
}

/// Trim leading/trailing non-core punctuation from a token.
fn token_core(token: &str) -> &str {
    token.trim_matches(|c: char| !is_core_char(c))
}

/// Split a whitespace token into `(prefix_punct, core, suffix_punct)` so a redaction of the core
/// preserves the surrounding punctuation (e.g. `(user@bank.com)` → `([REDACTED-EMAIL])`).
fn split_affix(token: &str) -> (&str, &str, &str) {
    let core = token_core(token);
    match token.find(core) {
        Some(off) if !core.is_empty() => (&token[..off], core, &token[off + core.len()..]),
        _ => ("", token, ""),
    }
}

/// An Indian PAN (Permanent Account Number): 5 uppercase letters, 4 digits, 1 uppercase letter.
fn is_india_pan(core: &str) -> bool {
    let b = core.as_bytes();
    b.len() == 10
        && b[0..5].iter().all(u8::is_ascii_uppercase)
        && b[5..9].iter().all(u8::is_ascii_digit)
        && b[9].is_ascii_uppercase()
}

/// An IFSC code: 4 uppercase letters, a `0`, then 6 alphanumerics (11 chars).
fn is_ifsc(core: &str) -> bool {
    let b = core.as_bytes();
    b.len() == 11
        && b[0..4].iter().all(u8::is_ascii_uppercase)
        && b[4] == b'0'
        && b[5..11].iter().all(u8::is_ascii_alphanumeric)
}

/// Classify an `@`-bearing token: an RFC-shaped address with a dotted TLD is an email; an
/// `user@handle` with no dotted TLD is treated as a UPI VPA (India virtual payment address).
fn email_or_upi(core: &str) -> Option<&'static str> {
    let at = core.find('@')?;
    if at == 0 || at + 1 >= core.len() || core[at + 1..].contains('@') {
        return None;
    }
    let (local, domain) = (&core[..at], &core[at + 1..]);
    let local_ok = local
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '%' | '+' | '-'));
    let domain_ok = !domain.is_empty()
        && domain
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'));
    if !local_ok || !domain_ok {
        return None;
    }
    let dotted_tld = domain
        .rsplit_once('.')
        .is_some_and(|(_, tld)| tld.len() >= 2 && tld.chars().all(|c| c.is_ascii_alphabetic()));
    Some(if dotted_tld {
        "[REDACTED-EMAIL]"
    } else {
        "[REDACTED-UPI]"
    })
}

/// A 3–4 digit group (a CVV/CVC candidate — only redacted under a preceding marker).
fn is_cvv_digits(core: &str) -> bool {
    (3..=4).contains(&core.len()) && core.bytes().all(|b| b.is_ascii_digit())
}

/// A `MM/YY`, `MM/YYYY` or `MM-YY(YY)` card-expiry group (only redacted under a preceding marker,
/// so a plain calendar date is never mistaken for an expiry — see `feedback_compliance_expiry_context`).
fn is_expiry_group(core: &str) -> bool {
    let parts: Vec<&str> = core.split(['/', '-']).collect();
    if parts.len() != 2 {
        return false;
    }
    let (mm, yy) = (parts[0], parts[1]);
    let month_ok = mm.len() == 2
        && mm.bytes().all(|b| b.is_ascii_digit())
        && matches!(mm.parse::<u8>(), Ok(1..=12));
    let year_ok = (yy.len() == 2 || yy.len() == 4) && yy.bytes().all(|b| b.is_ascii_digit());
    month_ok && year_ok
}

/// Context marker that gates CVV / expiry redaction on the *next* token.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Marker {
    Cvv,
    Expiry,
}

fn marker_of(core: &str) -> Option<Marker> {
    let lc = core
        .trim_matches(|c: char| !c.is_ascii_alphanumeric())
        .to_ascii_lowercase();
    match lc.as_str() {
        "cvv" | "cvc" | "cvv2" | "cid" | "csc" => Some(Marker::Cvv),
        "exp" | "expiry" | "expires" | "expiration" | "expire" | "valid" | "thru" | "till"
        | "until" | "validthru" | "validuntil" => Some(Marker::Expiry),
        _ => None,
    }
}

/// Non-numeric single-token classification (email/UPI, IFSC, India-PAN, secret credential).
fn classify_token(core: &str) -> Option<&'static str> {
    if core.contains('@') {
        if let Some(label) = email_or_upi(core) {
            return Some(label);
        }
    }
    if is_ifsc(core) {
        return Some("[REDACTED-IFSC]");
    }
    if is_india_pan(core) {
        return Some("[REDACTED-INDIA-PAN]");
    }
    if looks_like_secret(core) {
        return Some("[REDACTED-SECRET]");
    }
    None
}

impl Redactor for BuiltinRedactor {
    fn redact(&self, text: &str) -> String {
        // Pass 1: grouped numeric identifiers — PAN (Luhn), Aadhaar (Verhoeff), Indian mobile
        // (10 digits, leading 6–9), and a long-digit-run safety net (12–18 → account/PAN-like).
        let bytes = text.as_bytes();
        let mut out = String::with_capacity(text.len());
        let mut i = 0usize;
        while i < bytes.len() {
            if bytes[i].is_ascii_digit() {
                let start = i;
                let mut digits: Vec<u8> = Vec::new();
                let mut end = i;
                let mut j = i;
                while j < bytes.len() {
                    let b = bytes[j];
                    if b.is_ascii_digit() {
                        digits.push(b - b'0');
                        end = j + 1;
                        j += 1;
                    } else if (b == b' ' || b == b'-')
                        && j + 1 < bytes.len()
                        && bytes[j + 1].is_ascii_digit()
                    {
                        j += 1; // single separator between digit groups
                    } else {
                        break;
                    }
                }
                let n = digits.len();
                let replacement = if (13..=19).contains(&n) && luhn_ok(&digits) {
                    Some("[REDACTED-PAN]")
                } else if n == 12 && verhoeff_ok(&digits) {
                    Some("[REDACTED-AADHAAR]")
                } else if n == 10 && (6..=9).contains(&digits[0]) {
                    Some("[REDACTED-MOBILE]")
                } else if (12..=18).contains(&n) {
                    Some("[REDACTED-ACCOUNT]")
                } else {
                    None
                };
                match replacement {
                    Some(r) => out.push_str(r),
                    None => out.push_str(&text[start..end]),
                }
                i = end.max(start + 1);
            } else {
                // copy this byte (UTF-8 safe: non-digit lead bytes copied whole via char boundary)
                let ch_len = utf8_len(bytes[i]);
                out.push_str(&text[i..(i + ch_len).min(text.len())]);
                i += ch_len;
            }
        }

        // Pass 2: token-level PII/secret classification + marker-gated CVV/expiry. Whitespace is
        // normalized to single spaces only when a redaction actually fires (matches prior behavior).
        let mut rebuilt = String::with_capacity(out.len());
        let mut changed = false;
        let mut prev_marker: Option<Marker> = None;
        for (k, tok) in out.split_whitespace().enumerate() {
            if k > 0 {
                rebuilt.push(' ');
            }
            let (pre, core, suf) = split_affix(tok);
            let mut label: Option<&'static str> = None;
            if let Some(m) = prev_marker {
                if m == Marker::Cvv && is_cvv_digits(core) {
                    label = Some("[REDACTED-CVV]");
                } else if m == Marker::Expiry && is_expiry_group(core) {
                    label = Some("[REDACTED-EXPIRY]");
                }
            }
            if label.is_none() {
                label = classify_token(core);
            }
            match label {
                Some(l) => {
                    rebuilt.push_str(pre);
                    rebuilt.push_str(l);
                    rebuilt.push_str(suf);
                    changed = true;
                }
                None => rebuilt.push_str(tok),
            }
            // Marker for the NEXT token (a redacted core cannot itself be a marker).
            prev_marker = if label.is_some() {
                None
            } else {
                marker_of(core)
            };
        }
        if changed {
            rebuilt
        } else {
            out
        }
    }
}

fn utf8_len(lead: u8) -> usize {
    if lead < 0x80 {
        1
    } else if lead >> 5 == 0b110 {
        2
    } else if lead >> 4 == 0b1110 {
        3
    } else if lead >> 3 == 0b11110 {
        4
    } else {
        1
    }
}

// ============================ Tamper-evident audit ============================

/// One hash-chained audit entry. `digest = H(seq | action | subject | detail | prev_digest)`, so
/// tampering with an earlier entry breaks every subsequent `digest` and
/// [`InMemoryStore::verify_audit_chain`] detects it (design `AK`: erasure/governance must be
/// *provable*, not merely performed).
///
/// The authoritative chain value is the full-width [`digest`](AuditEntry::digest). `hash`/`prev_hash`
/// are a 64-bit fold of it, retained as a cheap index and for the `bigint` columns of the durable
/// seam — **a 64-bit fold is not a regulator-grade integrity value on its own** (its birthday bound
/// is only ~2^32), so verification is defined over `digest` and the fold is checked as a
/// consistency cross-check, never as the sole evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    /// Monotonic audit index.
    pub seq: u64,
    /// What happened (e.g. `promote`, `erase-subject`, `break-glass-read`).
    pub action: String,
    /// The subject (item id / user id).
    pub subject: String,
    /// Free detail.
    pub detail: String,
    /// 64-bit fold of the previous entry's `digest` (0 for the first).
    pub prev_hash: u64,
    /// 64-bit fold of this entry's `digest`.
    pub hash: u64,
    /// The previous entry's full-width digest (empty for the first entry).
    pub prev_digest: String,
    /// This entry's full-width digest — the authoritative chain value.
    pub digest: String,
    /// [`AuditHasher::name`] of the function that produced `digest`, so a verifier (or an auditor
    /// years later, after a crypto-agility rotation) knows which function to re-run.
    pub hasher: String,
}

/// The audit chain's hash function, as a **seam**: a deployment injects its own (the runtime's
/// Event-Log hasher, an HSM-backed keyed MAC, a PQC digest) via
/// [`InMemoryStore::with_audit_hasher`] without the store knowing which. The default is
/// [`Sha256AuditHasher`].
///
/// Implementations must be deterministic and must bind *every* field plus the previous digest —
/// a hasher that ignores `prev` produces an unchained log that cannot detect reordering or deletion.
pub trait AuditHasher: std::fmt::Debug + Send + Sync {
    /// Stable name recorded on each entry (e.g. `sha256`, `hmac-sha256`, `fnv1a`).
    fn name(&self) -> &'static str;
    /// Full-width hex digest binding this entry to `prev` (the previous entry's digest, `""` first).
    fn digest(&self, seq: u64, action: &str, subject: &str, detail: &str, prev: &str) -> String;
}

fn audit_preimage(seq: u64, action: &str, subject: &str, detail: &str, prev: &str) -> String {
    // Length-prefix every variable field so no two distinct entries can share a preimage by
    // shifting a `|` into a value (e.g. action="a|b", subject="c" vs action="a", subject="b|c").
    format!(
        "{seq}|{}:{action}|{}:{subject}|{}:{detail}|{}:{prev}",
        action.len(),
        subject.len(),
        detail.len(),
        prev.len()
    )
}

fn fold64(digest: &str) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for b in digest.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Default audit hasher: SHA-256 over a length-prefixed preimage. Collision/preimage resistant, so
/// an attacker who can rewrite history cannot produce a colliding entry — but note that an attacker
/// who can rewrite the *whole* chain can recompute it; use [`HmacSha256AuditHasher`] (or an external
/// WORM sink) when the threat model includes a writer with full store access.
#[derive(Debug, Clone, Copy, Default)]
pub struct Sha256AuditHasher;

impl AuditHasher for Sha256AuditHasher {
    fn name(&self) -> &'static str {
        "sha256"
    }
    fn digest(&self, seq: u64, action: &str, subject: &str, detail: &str, prev: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(audit_preimage(seq, action, subject, detail, prev).as_bytes());
        h.finalize().iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// Keyed audit hasher (HMAC-SHA-256). Unlike [`Sha256AuditHasher`], a party who can rewrite the
/// store but does **not** hold the key cannot forge a valid chain — this is what makes the log
/// un-forgeable by its own writer, which is the property a regulator actually asks for.
///
/// The key is a secret: it belongs in the deployment's vault, never in the tree. It is deliberately
/// not exposed by any accessor, and [`Debug`] prints a redacted placeholder instead of the key.
#[derive(Clone)]
pub struct HmacSha256AuditHasher {
    key: Vec<u8>,
}

impl HmacSha256AuditHasher {
    /// Build a keyed hasher. `key` should be at least 32 bytes of vault-held entropy.
    pub fn new(key: impl Into<Vec<u8>>) -> Self {
        HmacSha256AuditHasher { key: key.into() }
    }
}

impl std::fmt::Debug for HmacSha256AuditHasher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the key — a Debug-logged audit hasher would hand over forgery capability.
        f.debug_struct("HmacSha256AuditHasher")
            .field("key", &"<redacted>")
            .finish()
    }
}

impl AuditHasher for HmacSha256AuditHasher {
    fn name(&self) -> &'static str {
        "hmac-sha256"
    }
    fn digest(&self, seq: u64, action: &str, subject: &str, detail: &str, prev: &str) -> String {
        use hmac::{Hmac, KeyInit, Mac};
        use sha2::Sha256;
        // HMAC accepts a key of any length, so this cannot fail for our inputs; map rather than
        // unwrap so a future key source can never panic the audit path.
        let mut mac = match Hmac::<Sha256>::new_from_slice(&self.key) {
            Ok(m) => m,
            Err(_) => return String::new(),
        };
        mac.update(audit_preimage(seq, action, subject, detail, prev).as_bytes());
        mac.finalize()
            .into_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}

/// Non-cryptographic FNV-1a hasher. **Test/offline use only** — it is trivially collidable, so it
/// detects accidental corruption but proves nothing against a motivated adversary. Kept so offline
/// suites and fixtures need no crypto, and so the legacy chain remains reproducible.
#[derive(Debug, Clone, Copy, Default)]
pub struct Fnv1aAuditHasher;

impl AuditHasher for Fnv1aAuditHasher {
    fn name(&self) -> &'static str {
        "fnv1a"
    }
    fn digest(&self, seq: u64, action: &str, subject: &str, detail: &str, prev: &str) -> String {
        format!(
            "{:016x}",
            fold64(&audit_preimage(seq, action, subject, detail, prev))
        )
    }
}

// ============================ Retention / erasure / embedding types ============================

/// Config-driven retention (design §5 table). Raw session/episodic/feedback age out; promoted
/// derivatives (`Semantic`/`OrgKnowledge`/…) never age on a timer — they are superseded/deprecated
/// through governance. Windows are in **logical ticks** (the caller maps ticks→days). `0` disables
/// purging for that tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionPolicy {
    /// Max age (ticks since write) of a raw `Episodic` item before it is purged (design §5: 90d).
    pub episodic_ttl: u64,
    /// Max age (ticks since last activity) of a `Session` working-memory item (design §5: session
    /// lifetime — short, per-conversation). `0` disables.
    pub session_ttl: u64,
    /// Max age (ticks) of a raw captured `FeedbackEvent` in the Improvement Engine before it is
    /// purged (design §5: 180d) — curated derivatives (prompts/evals/OKIs) outlive the raw event.
    /// Consumed by [`crate::flywheel::ImprovementEngine::purge_expired_feedback`].
    pub feedback_ttl: u64,
}

impl RetentionPolicy {
    /// A policy with the given episodic TTL (session/feedback TTL disabled — set via the builders).
    pub fn new(episodic_ttl: u64) -> Self {
        RetentionPolicy {
            episodic_ttl,
            session_ttl: 0,
            feedback_ttl: 0,
        }
    }
    /// Set the `Session` working-memory TTL.
    pub fn with_session_ttl(mut self, ttl: u64) -> Self {
        self.session_ttl = ttl;
        self
    }
    /// Set the raw-feedback TTL (consumed by the Improvement Engine).
    pub fn with_feedback_ttl(mut self, ttl: u64) -> Self {
        self.feedback_ttl = ttl;
        self
    }
}

/// Receipt from a right-to-erasure cascade — the *provable* record (design §5, acceptance test).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ErasureReceipt {
    /// The erased subject (user id).
    pub subject: String,
    /// Ids hard-deleted across the store.
    pub removed_ids: Vec<String>,
    /// Ids whose provenance traces to the subject — flagged so a future fine-tune run excludes
    /// them (a past fine-tune isn't un-trained, but the lineage is what proves exclusion, §5).
    pub fine_tune_lineage_flagged: Vec<String>,
    /// The audit-chain seq of the signed erasure entry.
    pub audit_seq: u64,
    /// Per-tier cascade results (design §5 "Redis (immediate)" + captured feedback). Empty when the
    /// erasure touched only the durable item store — i.e. when it was **not** run through
    /// [`cascade_erasure`], which is the difference between "we deleted the rows we own" and "the
    /// subject's data is gone from every tier".
    #[serde(default)]
    pub cascaded: Vec<TierErasure>,
}

/// What one tier reported during a [`cascade_erasure`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TierErasure {
    /// The tier's name, as it appears in the audit chain (e.g. `session`, `feedback`).
    pub tier: String,
    /// How many records the tier removed.
    pub removed: usize,
    /// The audit-chain seq of this tier's entry — each tier is proved separately, so a partially
    /// completed cascade is visible in the log rather than hidden behind one aggregate ack.
    pub audit_seq: u64,
}

/// A data tier that a right-to-erasure request must reach beyond the durable item store: the session
/// (Redis) cache, captured feedback, the answer cache, an embedding index.
///
/// Erasure that stops at the item store is the failure the audit called out — a DPDP acknowledgement
/// is only truthful if every tier holding the subject's data was asked to erase it and *said how
/// much it removed*.
pub trait ErasureTier: std::fmt::Debug {
    /// Tier name recorded in the audit chain.
    fn tier(&self) -> &str;
    /// Erase everything belonging to `subject`; returns the number of records removed.
    fn erase_subject(&mut self, subject: &str) -> usize;
}

/// Cascade a right-to-erasure across the item store **and** every other tier holding the subject's
/// data, producing one receipt that proves each tier individually (design §5, gap "erasure cascade
/// does not reach the Session tier or captured feedback").
///
/// Each tier gets its own audit entry, so a tier that removed nothing — or a cascade that died
/// halfway — is evident in the chain instead of being papered over by a single success ack.
pub fn cascade_erasure(
    store: &mut InMemoryStore,
    subject: &str,
    tiers: &mut [&mut dyn ErasureTier],
) -> ErasureReceipt {
    let mut receipt = store.erase_subject(subject);
    for t in tiers.iter_mut() {
        let removed = t.erase_subject(subject);
        let name = t.tier().to_string();
        let audit_seq = store.audit(
            "erase-cascade",
            subject,
            &format!("tier={name} removed={removed}"),
        );
        receipt.cascaded.push(TierErasure {
            tier: name,
            removed,
            audit_seq,
        });
    }
    receipt
}

/// An embedding model seam. Regulated/PII content must be embedded only by an [`EmbedderKind::InHouse`]
/// model (design §8.5); the store enforces the routing, the concrete model is infra. `Debug + Send +
/// Sync` so a configured embedder can live inside the (thread-shareable) store for embed-on-write.
pub trait Embedder: std::fmt::Debug + Send + Sync {
    /// The model id recorded on the embedding.
    fn model_id(&self) -> &str;
    /// The tier of this model.
    fn kind(&self) -> EmbedderKind;
    /// Embed `text` into a dense vector.
    fn embed(&self, text: &str) -> Vec<f32>;
}

/// A tier-grouped "what do you remember about me" view (design §5 consent surface).
#[derive(Debug, Clone, PartialEq)]
pub struct ConsentView {
    /// The subject user id.
    pub subject: String,
    /// Current items scoped to the subject, grouped by kind (with provenance intact).
    pub by_kind: Vec<(MemoryKind, Vec<MemoryItem>)>,
}

/// A machine-readable export of everything remembered about a subject (DPDP portability, §5).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SubjectExport {
    /// The subject user id.
    pub subject: String,
    /// Every version of every item scoped to the subject (full history for portability + audit).
    pub items: Vec<MemoryItem>,
}

// ============================ In-memory store ============================

/// Reference in-memory [`MemoryStore`]. Versions are append-only per id (edit-free versioning);
/// the last version is "current". Deterministic (logical clock). Suitable as the test target and
/// for single-process/ephemeral use.
#[derive(Debug)]
pub struct InMemoryStore {
    /// id → append-only version history (oldest first; last = current).
    items: HashMap<String, Vec<MemoryItem>>,
    clock: u64,
    /// The compliance gate applied to **every** write before persistence. This is a *mandatory*
    /// seam (design §8.4 / A1 invariant "configurable provider, never configurable off"): there is
    /// no store without a gate — [`InMemoryStore::new`] installs [`BuiltinRedactor`], and
    /// [`with_redactor`](InMemoryStore::with_redactor) only *swaps the provider*, never removes it.
    redactor: Box<dyn Redactor>,
    audit: Vec<AuditEntry>,
    /// Optional in-house embedder for **embed-on-write** (design §8.5 data-class routing): the tier
    /// permitted for regulated/PII content. `None` = embed-on-write disabled (embeddings only via the
    /// batch [`reembed_all`](InMemoryStore::reembed_all) path).
    inhouse_embedder: Option<Box<dyn Embedder>>,
    /// Optional cloud embedder for embed-on-write of non-regulated content.
    cloud_embedder: Option<Box<dyn Embedder>>,
    /// OKI-extraction guard cap (design §8.8 / gap AM): the max number of extraction-sensitive OKIs
    /// (`SecurityRule`/`ApprovedLibrary`) an **unscoped recon-shaped** query may return before the
    /// guard fails closed and drops them. `0` = guard disabled (default; the guard is opt-in, wired by
    /// the surface — the runtime does not rebuild the guardrails classifier, it exposes the seam).
    extraction_cap: usize,
    /// The **versioned, per-type JSON-schema registry** enforced on every OKI write (design §2
    /// `type_payload`). Every org-knowledge write is validated through this registry (not an
    /// ungoverned inline `validate()` call) and the in-force schema version is stamped on the
    /// persisted item ([`MemoryItem::schema_version`](crate::MemoryItem)). Default =
    /// [`SchemaRegistry::new`] (all types at v1); a deployment swaps in a registry whose types have
    /// been governably bumped via [`with_schema_registry`](InMemoryStore::with_schema_registry).
    schema_registry: SchemaRegistry,
    /// The audit chain's hash function (design `AK`). A *seam*, like the redactor: never removable,
    /// only swappable — default [`Sha256AuditHasher`], swapped via
    /// [`with_audit_hasher`](InMemoryStore::with_audit_hasher) for a keyed/HSM/PQC hasher.
    hasher: Box<dyn AuditHasher>,
}

impl Default for InMemoryStore {
    fn default() -> Self {
        InMemoryStore {
            items: HashMap::new(),
            clock: 0,
            redactor: Box::new(BuiltinRedactor),
            audit: Vec::new(),
            inhouse_embedder: None,
            cloud_embedder: None,
            extraction_cap: 0,
            schema_registry: SchemaRegistry::new(),
            hasher: Box::new(Sha256AuditHasher),
        }
    }
}

impl InMemoryStore {
    /// A fresh, empty store with the mandatory compliance gate installed ([`BuiltinRedactor`]).
    pub fn new() -> Self {
        InMemoryStore::default()
    }

    /// Swap the compliance-gate *provider* (e.g. an adapter over the runtime's full compliance
    /// engine). The gate itself is never removable — this only changes which redactor runs.
    pub fn with_redactor(mut self, redactor: Box<dyn Redactor>) -> Self {
        self.redactor = redactor;
        self
    }

    /// Swap the audit chain's hash function (design `AK`, crypto-agility). Like the redactor this
    /// only changes the *provider*: there is no store without a hash-chained audit log.
    ///
    /// Entries already in the chain keep the hasher they were written with (each entry records its
    /// [`hasher`](AuditEntry::hasher)), so rotating forward does not invalidate history — see
    /// [`verify_audit_chain`](InMemoryStore::verify_audit_chain).
    pub fn with_audit_hasher(mut self, hasher: Box<dyn AuditHasher>) -> Self {
        self.hasher = hasher;
        self
    }

    /// Configure **embed-on-write** with a data-class-routed embedder pair (design §2 `embedding`
    /// "computed under the same data-class rules as any other embedding"; §8.5). Every subsequent
    /// write whose item has no embedding gets one computed over its (already-redacted) body, routed
    /// by [`required_embedder_kind`](crate::required_embedder_kind): regulated/PII → the in-house
    /// model, everything else → the cloud model. The tiers are validated (a cloud model passed as the
    /// in-house one is rejected) so a mis-configured pair can never leak regulated content to a cloud
    /// embedder. `inhouse` must report [`EmbedderKind::InHouse`] and `cloud` [`EmbedderKind::Cloud`].
    ///
    /// # Panics
    /// If either embedder reports the wrong tier — a deployment configuration error, caught at wiring
    /// time (fail-fast), never silently serving mis-tiered embeddings.
    pub fn with_embedders(mut self, inhouse: Box<dyn Embedder>, cloud: Box<dyn Embedder>) -> Self {
        assert_eq!(
            inhouse.kind(),
            EmbedderKind::InHouse,
            "in-house embedder must report EmbedderKind::InHouse"
        );
        assert_eq!(
            cloud.kind(),
            EmbedderKind::Cloud,
            "cloud embedder must report EmbedderKind::Cloud"
        );
        self.inhouse_embedder = Some(inhouse);
        self.cloud_embedder = Some(cloud);
        self
    }

    /// Enable the OKI-extraction guard (design §8.8 / gap AM) with a disclosure cap. An unscoped,
    /// recon-shaped query ([`MemoryQuery::is_unscoped_safety_recon`]) that would return **more than
    /// `cap`** extraction-sensitive OKIs (`SecurityRule`/`ApprovedLibrary`) is treated as an
    /// extraction attempt: those OKIs are dropped from the result (fail-closed — the full set is never
    /// dumped verbatim) and the audited read path records an `oki-extraction-guard` entry. `cap == 0`
    /// disables the guard (the default). Scoped reads (the Context-Fabric planner always scopes by
    /// repo) are never affected.
    pub fn with_extraction_guard(mut self, cap: usize) -> Self {
        self.extraction_cap = cap;
        self
    }

    /// Install a governed, versioned [`SchemaRegistry`] enforced on every OKI write (design §2
    /// `type_payload`: "validated against a per-type JSON-schema registry (versioned)"). Use this to
    /// carry a registry whose per-type versions have been governably bumped
    /// ([`SchemaRegistry::bump`]); each subsequent OKI write is validated through it and records the
    /// in-force version on [`MemoryItem::schema_version`](crate::MemoryItem). Default (unset) = a
    /// fresh registry with every type at [`OKI_SCHEMA_VERSION`](crate::oki::OKI_SCHEMA_VERSION).
    pub fn with_schema_registry(mut self, registry: SchemaRegistry) -> Self {
        self.schema_registry = registry;
        self
    }

    /// The versioned OKI schema registry currently enforced on writes.
    pub fn schema_registry(&self) -> &SchemaRegistry {
        &self.schema_registry
    }

    /// Every stored version across all ids (oldest-first within an id), as owned snapshots. This is
    /// the write-through source for the durable [`SqlLike`](crate::durable::SqlLike) seam — a
    /// [`DurableMemoryStore`](crate::durable::DurableMemoryStore) diffs this against what the backend
    /// already holds and upserts only what changed. Ids are visited in unspecified order; callers
    /// that need determinism sort by `(id, version)`.
    pub(crate) fn export_versions(&self) -> Vec<MemoryItem> {
        self.items
            .values()
            .flat_map(|v| v.iter().cloned())
            .collect()
    }

    /// The current audit chain (used to persist newly-appended entries through the durable seam).
    pub(crate) fn audit_log(&self) -> &[AuditEntry] {
        &self.audit
    }

    /// Rebuild a store from durably-persisted state (hydration on daemon restart). `versions` may be
    /// in any order; they are grouped by id and sorted by `version` so "last = current" holds. The
    /// logical clock is restored to the max persisted `seq` so new writes keep monotonic ticks, and
    /// the audit chain is restored verbatim (its integrity is re-checkable via
    /// [`verify_audit_chain`](InMemoryStore::verify_audit_chain)). The mandatory compliance gate is
    /// installed as usual (the provider is swapped by the durable store if configured).
    pub(crate) fn from_persisted(versions: Vec<MemoryItem>, audit: Vec<AuditEntry>) -> Self {
        let mut items: HashMap<String, Vec<MemoryItem>> = HashMap::new();
        let mut clock = 0u64;
        for it in versions {
            clock = clock.max(it.seq);
            items.entry(it.id.clone()).or_default().push(it);
        }
        for v in items.values_mut() {
            v.sort_by_key(|it| it.version);
        }
        InMemoryStore {
            items,
            clock,
            redactor: Box::new(BuiltinRedactor),
            audit,
            inhouse_embedder: None,
            cloud_embedder: None,
            extraction_cap: 0,
            schema_registry: SchemaRegistry::new(),
            hasher: Box::new(Sha256AuditHasher),
        }
    }

    /// Number of live items (by id, any governance state).
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    fn tick(&mut self) -> u64 {
        self.clock += 1;
        self.clock
    }

    fn current(&self, id: &str) -> Option<&MemoryItem> {
        self.items.get(id).and_then(|v| v.last())
    }

    fn current_mut(&mut self, id: &str) -> Option<&mut MemoryItem> {
        self.items.get_mut(id).and_then(|v| v.last_mut())
    }

    fn audit(&mut self, action: &str, subject: &str, detail: &str) -> u64 {
        let seq = self.audit.len() as u64;
        let prev_digest = self
            .audit
            .last()
            .map(|e| e.digest.clone())
            .unwrap_or_default();
        let prev_hash = self.audit.last().map(|e| e.hash).unwrap_or(0);
        let digest = self
            .hasher
            .digest(seq, action, subject, detail, &prev_digest);
        let hash = fold64(&digest);
        self.audit.push(AuditEntry {
            seq,
            action: action.to_string(),
            subject: subject.to_string(),
            detail: detail.to_string(),
            prev_hash,
            hash,
            prev_digest,
            digest,
            hasher: self.hasher.name().to_string(),
        });
        seq
    }

    /// The tamper-evident audit log (governance transitions, erasures, break-glass reads).
    pub fn audit_entries(&self) -> &[AuditEntry] {
        &self.audit
    }

    /// Recompute the chain and confirm no entry was tampered with, reordered, or removed. Returns
    /// the index of the first broken entry, or `None` if the chain is intact.
    ///
    /// Verification is defined over the full-width [`digest`](AuditEntry::digest); `hash` is checked
    /// only as a fold-consistency cross-check. An entry whose `hasher` differs from the store's
    /// current one is re-verified with the hasher **named on the entry** where that hasher is
    /// key-free — this is what lets a crypto-agility rotation happen without invalidating history.
    /// A keyed entry (e.g. `hmac-sha256`) can only be re-verified by a store holding that key, so
    /// when the names disagree and the entry is keyed, the fold-consistency check is applied and the
    /// linkage (`prev_digest`) is still enforced.
    pub fn verify_audit_chain(&self) -> Option<usize> {
        let mut prev_digest = String::new();
        let mut prev_hash = 0u64;
        for (i, e) in self.audit.iter().enumerate() {
            if e.seq != i as u64 || e.prev_hash != prev_hash || e.prev_digest != prev_digest {
                return Some(i);
            }
            if e.hash != fold64(&e.digest) {
                return Some(i);
            }
            let recomputable: Option<&dyn AuditHasher> = if e.hasher == self.hasher.name() {
                Some(self.hasher.as_ref())
            } else {
                match e.hasher.as_str() {
                    "sha256" => Some(&Sha256AuditHasher),
                    "fnv1a" => Some(&Fnv1aAuditHasher),
                    // Keyed hashers cannot be recomputed without the key: linkage + fold above are
                    // the checks available here. Say so rather than pretend to verify.
                    _ => None,
                }
            };
            if let Some(h) = recomputable {
                let expect = h.digest(e.seq, &e.action, &e.subject, &e.detail, &e.prev_digest);
                if e.digest != expect {
                    return Some(i);
                }
            }
            prev_digest = e.digest.clone();
            prev_hash = e.hash;
        }
        None
    }

    fn redact_item(&self, item: &mut MemoryItem) {
        let r = self.redactor.as_ref();
        item.title = r.redact(&item.title);
        item.body = r.redact(&item.body);
        for tag in &mut item.tags {
            *tag = r.redact(tag);
        }
        // The substance of an OKI is in its typed payload, not free text — scrub it too (MEM-02).
        if let Some(p) = &mut item.payload {
            p.redact_in_place(r);
        }
    }

    /// Embed-on-write (design §2 `embedding`; §8.5 data-class routing). When embed-on-write is
    /// configured ([`with_embedders`](InMemoryStore::with_embedders)) and the item has no embedding
    /// yet, compute one over the (already-redacted) body using the tier its data-class requires:
    /// regulated/PII content is embedded **only** by the in-house model, everything else by the cloud
    /// model. If the required tier's embedder is absent the item is left unembedded rather than routed
    /// to the wrong tier (fail-closed on the data-class rule, never leak regulated content to cloud).
    fn embed_on_write(&self, item: &mut MemoryItem) {
        if item.embedding.is_some() {
            return; // caller supplied one (e.g. a re-embed pipeline); don't overwrite.
        }
        let needed = required_embedder_kind(item.data_class);
        let chosen = match needed {
            EmbedderKind::InHouse => self.inhouse_embedder.as_ref(),
            EmbedderKind::Cloud => self.cloud_embedder.as_ref(),
        };
        let Some(embedder) = chosen else {
            return; // embed-on-write not configured for this tier.
        };
        debug_assert!(embedder_allowed(item.data_class, embedder.kind()));
        let vector = embedder.embed(&item.body);
        item.embedding = Some(Embedding {
            model_id: embedder.model_id().to_string(),
            kind: embedder.kind(),
            vector,
        });
    }

    // -------- version access / forensic replay --------

    /// Fetch a specific historical version of an item (forensic replay, design §7.5).
    pub fn get_version(&self, id: &str, version: u32) -> Option<&MemoryItem> {
        self.items.get(id)?.iter().find(|v| v.version == version)
    }

    /// All versions of an item (oldest first).
    pub fn versions(&self, id: &str) -> &[MemoryItem] {
        self.items.get(id).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Resolve a set of `(id, version)` references to their exact content snapshots — the operation
    /// that lets an auditor reconstruct exactly what the runtime knew when it answered a turn, even
    /// after those items were edited/superseded (design §7.5 forensic replay).
    pub fn resolve(&self, refs: &[(String, u32)]) -> Vec<Option<MemoryItem>> {
        refs.iter()
            .map(|(id, v)| self.get_version(id, *v).cloned())
            .collect()
    }

    // -------- extra governance transitions --------

    /// Promote an `Approved` org item to `Production`. Requires [`CAP_APPROVE`]/admin.
    pub fn productionize(&mut self, id: &str, actor: &Principal) -> Result<(), MemoryError> {
        if !actor.has_cap(CAP_APPROVE) {
            return Err(MemoryError::NotAuthorized(format!(
                "principal '{}' lacks '{}'",
                actor.user_id, CAP_APPROVE
            )));
        }
        let item = self
            .current_mut(id)
            .ok_or_else(|| MemoryError::NotFound(id.to_string()))?;
        if item.kind != MemoryKind::OrgKnowledge || item.governance != GovernanceState::Approved {
            return Err(MemoryError::InvalidTransition(format!(
                "cannot productionize '{id}': must be an Approved org item"
            )));
        }
        item.governance = GovernanceState::Production;
        self.audit("productionize", id, actor.user_id.as_str());
        Ok(())
    }

    /// Human arbitration of a conflict (design §6): the human owner picks the `winner` (→ Approved)
    /// and the `loser` (→ Superseded). Both must be OKIs sharing a conflict subject; requires
    /// [`CAP_APPROVE`]/admin. This is the only way a `Conflicted` item becomes authoritative.
    pub fn arbitrate(
        &mut self,
        winner_id: &str,
        loser_id: &str,
        actor: &Principal,
    ) -> Result<(), MemoryError> {
        if !actor.has_cap(CAP_APPROVE) {
            return Err(MemoryError::NotAuthorized(format!(
                "principal '{}' lacks '{}'",
                actor.user_id, CAP_APPROVE
            )));
        }
        if winner_id == loser_id {
            return Err(MemoryError::InvalidTransition(
                "winner and loser must differ".into(),
            ));
        }
        let wk = self
            .current(winner_id)
            .ok_or_else(|| MemoryError::NotFound(winner_id.to_string()))?
            .conflict_key();
        let lk = self
            .current(loser_id)
            .ok_or_else(|| MemoryError::NotFound(loser_id.to_string()))?
            .conflict_key();
        match (wk, lk) {
            (Some(a), Some(b)) if a == b => {}
            _ => {
                return Err(MemoryError::InvalidTransition(
                    "arbitrate requires two OKIs sharing a conflict subject".into(),
                ))
            }
        }
        let verified_by = actor.user_id.clone();
        let tick = self.tick();
        if let Some(w) = self.current_mut(winner_id) {
            w.governance = GovernanceState::Approved;
            w.provenance.last_verified_by = Some(verified_by);
            w.provenance.last_verified_at = Some(tick);
        }
        if let Some(l) = self.current_mut(loser_id) {
            l.governance = GovernanceState::Superseded;
        }
        self.audit("arbitrate", winner_id, &format!("supersedes {loser_id}"));
        Ok(())
    }

    // -------- retention / decay / erasure --------

    /// Purge raw, time-bounded tiers older than their policy TTL at logical time `now`: raw
    /// `Episodic` (by write tick) and `Session` working memory (by last-activity tick). Promoted
    /// derivatives (Semantic/OrgKnowledge/...) are untouched — they age out only through governance,
    /// never on a timer (§5). Returns the number of ids purged; emits one audit entry per tier that
    /// purged anything. (Raw *feedback* retention lives in the Improvement Engine —
    /// [`crate::flywheel::ImprovementEngine::purge_expired_feedback`] — since feedback is not stored
    /// as memory items.)
    pub fn purge_expired(&mut self, now: u64, policy: RetentionPolicy) -> usize {
        let mut total = 0usize;
        // Raw episodic (aged by write tick).
        if policy.episodic_ttl > 0 {
            total += self.purge_tier(
                now,
                MemoryKind::Episodic,
                policy.episodic_ttl,
                false,
                "purge-episodic",
            );
        }
        // Session working memory (aged by last activity, since it is touched every turn).
        if policy.session_ttl > 0 {
            total += self.purge_tier(
                now,
                MemoryKind::Session,
                policy.session_ttl,
                true,
                "purge-session",
            );
        }
        total
    }

    fn purge_tier(
        &mut self,
        now: u64,
        kind: MemoryKind,
        ttl: u64,
        by_activity: bool,
        action: &str,
    ) -> usize {
        let doomed: Vec<String> = self
            .items
            .iter()
            .filter_map(|(id, versions)| {
                let cur = versions.last()?;
                let age_base = if by_activity {
                    cur.last_active()
                } else {
                    cur.seq
                };
                if cur.kind == kind && age_base.saturating_add(ttl) <= now {
                    Some(id.clone())
                } else {
                    None
                }
            })
            .collect();
        for id in &doomed {
            self.items.remove(id);
        }
        if !doomed.is_empty() {
            self.audit(
                action,
                "retention",
                &format!("purged {} at tick {now}", doomed.len()),
            );
        }
        doomed.len()
    }

    /// **Confidence-decay expiry** (design §6): "a fact unconfirmed **and unused** past N months
    /// drops priority, *eventually expires* — decay is a ranking signal, not a silent deletion."
    /// This is the "eventually expires" half: a durable **personal-fact** tier item
    /// (`Semantic`/`Procedural`/`UserPreference`) whose usage-based [`decay_factor`](crate::MemoryItem::decay_factor)
    /// has fallen **below `floor`** at logical time `now` (given `half_life`) is transitioned to
    /// [`Deprecated`](crate::GovernanceState::Deprecated) — retained for audit/forensic replay
    /// (never hard-deleted here; that is only the explicit erasure path, §5) but excluded from
    /// authoritative retrieval. A freshly *used* or *confirmed* item resets its decay clock (via
    /// [`last_active`](crate::MemoryItem::last_active)) and is therefore never expired.
    ///
    /// Org-knowledge (OKI) is deliberately **exempt**: per §5 it "doesn't expire on a timer — it's
    /// superseded/deprecated through governance," so a decay sweep never touches it. Already-retired
    /// (`Deprecated`/`Superseded`) items and `Session`/`Episodic` raw tiers (which age out by TTL via
    /// [`purge_expired`](InMemoryStore::purge_expired)) are likewise skipped. Returns the number of
    /// items expired; emits one audit entry when any expired. `half_life == 0` or `floor <= 0.0`
    /// disables the sweep (returns 0).
    pub fn expire_decayed(&mut self, now: u64, half_life: u64, floor: f64) -> usize {
        if half_life == 0 || floor <= 0.0 {
            return 0;
        }
        let doomed: Vec<String> = self
            .items
            .iter()
            .filter_map(|(id, versions)| {
                let cur = versions.last()?;
                let eligible = matches!(
                    cur.kind,
                    MemoryKind::Semantic | MemoryKind::Procedural | MemoryKind::UserPreference
                );
                let retired = matches!(
                    cur.governance,
                    GovernanceState::Deprecated | GovernanceState::Superseded
                );
                if eligible && !retired && cur.is_decayed(now, half_life, floor) {
                    Some(id.clone())
                } else {
                    None
                }
            })
            .collect();
        for id in &doomed {
            if let Some(it) = self.current_mut(id) {
                it.governance = GovernanceState::Deprecated;
            }
        }
        if !doomed.is_empty() {
            self.audit(
                "decay-expire",
                "retention",
                &format!(
                    "expired {} long-unused facts below decay floor at tick {now}",
                    doomed.len()
                ),
            );
        }
        doomed.len()
    }

    /// Right-to-erasure cascade (design §5): hard-delete every item scoped to `subject` across the
    /// store, flag any item whose provenance traces to them for fine-tune exclusion, and record one
    /// signed (hash-chained) audit entry. A post-erasure query returns zero live records for them.
    pub fn erase_subject(&mut self, subject: &str) -> ErasureReceipt {
        let target = Scope::User(subject.to_string());
        let removed_ids: Vec<String> = self
            .items
            .iter()
            .filter_map(|(id, versions)| {
                let cur = versions.last()?;
                if cur.scope == target {
                    Some(id.clone())
                } else {
                    None
                }
            })
            .collect();
        // Fine-tune lineage: any surviving item authored by this human (e.g. an org OKI they wrote)
        // is flagged so a future fine-tune corpus excludes their data going forward.
        let lineage: Vec<String> = self
            .items
            .iter()
            .filter_map(|(id, versions)| {
                let cur = versions.last()?;
                let by_subject = matches!(&cur.provenance.author, Author::Human { user_id } if user_id == subject);
                if by_subject && cur.scope != target {
                    Some(id.clone())
                } else {
                    None
                }
            })
            .collect();
        for id in &removed_ids {
            self.items.remove(id);
        }
        let audit_seq = self.audit(
            "erase-subject",
            subject,
            &format!(
                "removed {} items, flagged {} lineage",
                removed_ids.len(),
                lineage.len()
            ),
        );
        ErasureReceipt {
            subject: subject.to_string(),
            removed_ids,
            fine_tune_lineage_flagged: lineage,
            audit_seq,
            cascaded: Vec::new(),
        }
    }

    // -------- defense-in-depth store sweep (FI-01 §5.4) --------

    /// GAP-FIX regulated-fi-responsible-lifecycle (FI-01 §5.4) — a **read-only** snapshot of every
    /// stored version's free text, keyed by a stable per-version record id (`"{item.id}@v{version}"`).
    /// Covers exactly the fields [`Self::re_redact`] scrubs (title/body/tags/typed OKI payload,
    /// flattened to its canonical JSON so no per-variant field list has to be kept in sync here), but
    /// — unlike `re_redact` — this NEVER mutates the store: it exists so a caller can re-scan already-
    /// persisted content through [`ainxt_compliance::SinkGuard::sweep`] and treat a hit as a §2
    /// incident candidate (the write-path guard was bypassed for that record), mirroring the SAME
    /// defense-in-depth proof `ainxt_runtimed::AssembledFull::sweep_event_log` already runs over the
    /// Event Log. Deterministic order (`items` iterated by id, versions oldest-first).
    pub fn all_content(&self) -> Vec<(String, String)> {
        let mut ids: Vec<&String> = self.items.keys().collect();
        ids.sort();
        let mut out = Vec::new();
        for id in ids {
            for item in &self.items[id] {
                let mut content = format!("{} {} {}", item.title, item.body, item.tags.join(" "));
                if let Some(payload) = &item.payload {
                    content.push(' ');
                    content.push_str(&serde_json::to_string(payload).unwrap_or_default());
                }
                out.push((format!("{}@v{}", item.id, item.version), content));
            }
        }
        out
    }

    // -------- retroactive re-redaction / re-embedding --------

    /// Retroactively re-apply the compliance redactor to **every stored version** across all items
    /// (design §8.6: when compliance rules change, previously-stored memory is re-scanned and
    /// re-redacted — leakage defense isn't only at write-time). Covers title/body/tags **and** the
    /// typed OKI payload. Returns the number of versions whose content changed.
    pub fn re_redact(&mut self) -> usize {
        // Borrow the mandatory provider out transiently (placeholder is never the installed gate).
        let r = std::mem::replace(&mut self.redactor, Box::new(PlaceholderRedactor));
        let mut changed = 0usize;
        for versions in self.items.values_mut() {
            for item in versions.iter_mut() {
                let before = item.clone();
                item.title = r.redact(&item.title);
                item.body = r.redact(&item.body);
                for tag in &mut item.tags {
                    *tag = r.redact(tag);
                }
                if let Some(p) = &mut item.payload {
                    p.redact_in_place(r.as_ref());
                }
                if item.title != before.title
                    || item.body != before.body
                    || item.tags != before.tags
                    || item.payload != before.payload
                {
                    changed += 1;
                }
            }
        }
        self.redactor = r;
        if changed > 0 {
            self.audit(
                "re-redact",
                "compliance",
                &format!("re-redacted {changed} versions"),
            );
        }
        changed
    }

    /// Re-embed every current item, routing by data-class: regulated/PII content is embedded only
    /// via the in-house model, everything else may use the cloud model (design §8.5). Returns the
    /// number of items embedded, or an error if the supplied models are mis-tiered.
    pub fn reembed_all(
        &mut self,
        inhouse: &dyn Embedder,
        cloud: &dyn Embedder,
    ) -> Result<usize, MemoryError> {
        if inhouse.kind() != EmbedderKind::InHouse {
            return Err(MemoryError::InvalidWrite(
                "in-house embedder must report EmbedderKind::InHouse".into(),
            ));
        }
        if cloud.kind() != EmbedderKind::Cloud {
            return Err(MemoryError::InvalidWrite(
                "cloud embedder must report EmbedderKind::Cloud".into(),
            ));
        }
        let mut count = 0usize;
        for versions in self.items.values_mut() {
            let Some(item) = versions.last_mut() else {
                continue;
            };
            let needed = required_embedder_kind(item.data_class);
            // Defense-in-depth: never route regulated/PII to the cloud model even if asked to.
            let chosen: &dyn Embedder = match needed {
                EmbedderKind::InHouse => inhouse,
                EmbedderKind::Cloud => cloud,
            };
            debug_assert!(embedder_allowed(item.data_class, chosen.kind()));
            let vector = chosen.embed(&item.body);
            item.embedding = Some(Embedding {
                model_id: chosen.model_id().to_string(),
                kind: chosen.kind(),
                vector,
            });
            count += 1;
        }
        Ok(count)
    }

    // -------- consent surface --------

    /// The "what do you remember about me" view (design §5). Requires the caller to be the subject,
    /// or an admin exercising break-glass — which emits an audited `break-glass-read` entry.
    pub fn remembered_about(
        &mut self,
        subject: &str,
        access: &AccessScope,
    ) -> Result<ConsentView, MemoryError> {
        let (visible, break_glass) = access.can_see(&Scope::User(subject.to_string()));
        if !visible {
            return Err(MemoryError::NotAuthorized(format!(
                "principal '{}' may not view '{}' personal memory",
                access.principal().user_id,
                subject
            )));
        }
        if break_glass {
            let reason = access.break_glass_justification().unwrap_or("(none)");
            self.audit(
                "break-glass-read",
                subject,
                &format!("by {}: {reason}", access.principal().user_id),
            );
        }
        let target = Scope::User(subject.to_string());
        let mut buckets: Vec<(MemoryKind, Vec<MemoryItem>)> = Vec::new();
        // Deterministic ordering of kinds.
        for kind in [
            MemoryKind::Session,
            MemoryKind::Episodic,
            MemoryKind::Semantic,
            MemoryKind::Procedural,
            MemoryKind::UserPreference,
            MemoryKind::OrgKnowledge,
        ] {
            let mut items: Vec<MemoryItem> = self
                .items
                .values()
                .filter_map(|v| v.last())
                .filter(|it| it.scope == target && it.kind == kind)
                .cloned()
                .collect();
            items.sort_by(|a, b| a.id.cmp(&b.id));
            if !items.is_empty() {
                buckets.push((kind, items));
            }
        }
        Ok(ConsentView {
            subject: subject.to_string(),
            by_kind: buckets,
        })
    }

    /// Machine-readable export of everything (all versions) scoped to a subject (DPDP portability,
    /// §5). Requires the same authorization as [`remembered_about`](InMemoryStore::remembered_about).
    pub fn export_subject(
        &mut self,
        subject: &str,
        access: &AccessScope,
    ) -> Result<SubjectExport, MemoryError> {
        let (visible, break_glass) = access.can_see(&Scope::User(subject.to_string()));
        if !visible {
            return Err(MemoryError::NotAuthorized(format!(
                "principal '{}' may not export '{}' data",
                access.principal().user_id,
                subject
            )));
        }
        if break_glass {
            let reason = access.break_glass_justification().unwrap_or("(none)");
            self.audit(
                "break-glass-export",
                subject,
                &format!("by {}: {reason}", access.principal().user_id),
            );
        }
        let target = Scope::User(subject.to_string());
        let mut items: Vec<MemoryItem> = self
            .items
            .values()
            .filter(|v| v.last().map(|c| c.scope == target).unwrap_or(false))
            .flat_map(|v| v.iter().cloned())
            .collect();
        items.sort_by(|a, b| a.id.cmp(&b.id).then(a.version.cmp(&b.version)));
        Ok(SubjectExport {
            subject: subject.to_string(),
            items,
        })
    }

    // -------- query internals --------

    fn candidate(versions: &[MemoryItem], as_of: Option<u64>) -> Option<&MemoryItem> {
        match as_of {
            None => versions.last(),
            Some(t) => versions.iter().filter(|v| v.seq <= t).max_by_key(|v| v.seq),
        }
    }

    /// Core query. Returns `(hits, break_glass_subjects, extraction_blocked)`:
    /// - `break_glass_subjects` — the user subjects an admin saw via break-glass, so
    ///   [`query_audited`](InMemoryStore::query_audited) can audit them.
    /// - `extraction_blocked` — the OKI-extraction guard fired (design §8.8): a recon-shaped unscoped
    ///   sweep was truncated of its extraction-sensitive OKIs.
    ///
    /// `audit_capable` reflects whether the *caller* can record an audit entry. Break-glass reads of
    /// another user's personal memory are only served when `audit_capable` is true — the immutable
    /// [`query`](MemoryStore::query) path passes `false` and therefore **fails closed** on break-glass
    /// (it cannot prove the access, so it does not grant it); [`query_audited`] passes `true`. This is
    /// what makes "break-glass is provably audited on *every* read path" hold: no read path serves a
    /// break-glass item without also auditing it.
    fn query_core(
        &self,
        q: &MemoryQuery,
        access: &AccessScope,
        audit_capable: bool,
    ) -> (Vec<MemoryHit>, Vec<String>, bool) {
        let clearance = access.principal().clearance.sensitivity();
        let mut break_glass_subjects: Vec<String> = Vec::new();
        let mut hits: Vec<MemoryHit> = Vec::new();
        // Does the query carry any non-empty keyword? (An all-empty keyword list is "match all".)
        let kw_present = q.keywords.iter().any(|k| !k.is_empty());

        for versions in self.items.values() {
            let Some(item) = Self::candidate(versions, q.as_of) else {
                continue;
            };
            // 1. Identity-derived scope isolation (pre-rank). An item outside the caller's reach is
            //    never ranked — existence is not leaked via omission from a ranked list.
            let (visible, used_bg) = access.can_see(&item.scope);
            if !visible {
                continue;
            }
            // 1b. Break-glass fail-closed: an admin's break-glass view of another user's personal
            //     memory is only served on an audit-capable path (so the access is always provable).
            //     The immutable `query` path cannot audit → it does not disclose the item.
            if used_bg && !audit_capable {
                continue;
            }
            // 2. Per-item RBAC grant (pre-rank, §2 `rbac_scope`): even within a reachable scope, an
            //    item may be granted only to specific roles/departments. Filtered before ranking so
            //    its existence is never leaked via omission from a ranked list.
            if let Some(rb) = &item.rbac_scope {
                if !rb.allows(access.principal()) {
                    continue;
                }
            }
            // 3. Data-class clearance (pre-rank, independent of scope). Exception (design §5): a
            //    caller reading their OWN personal (`User`) fact is never blocked by the read-
            //    clearance ceiling — "a user's own PII-classed facts about themselves are visible to
            //    themselves." Every other caller (and a break-glass admin, who holds full clearance)
            //    stays subject to the ceiling; the waiver cannot widen shared-scope visibility.
            if item.data_class.sensitivity() > clearance && !access.is_own_personal(&item.scope) {
                continue;
            }
            // 3. Governance/authority.
            if q.authoritative_only && !item.is_authoritative() {
                continue;
            }
            // 4. Kind / org-type / exact-scope filters.
            if let Some(k) = q.kind {
                if item.kind != k {
                    continue;
                }
            }
            if let Some(t) = q.org_type {
                if item.org_type != Some(t) {
                    continue;
                }
            }
            if let Some(scope) = &q.scope {
                if &item.scope != scope {
                    continue;
                }
            }
            // 5. Valid-time (bi-temporal) filter.
            if let Some(t) = q.valid_as_of {
                if !item.valid_at(t) {
                    continue;
                }
            }
            // 6. Relevance: keyword, semantic (cosine), or hybrid — then optional decay.
            //    `SEM_SCALE` weights the cosine contribution so it re-orders WITHIN a keyword-weight
            //    tier without ever outranking a strictly-more-keyword-relevant hit; a semantic-only
            //    hit in a hybrid query ranks below every keyword hit (base 0 + scaled cosine).
            const SEM_SCALE: f64 = 1_000.0;
            let sem = q
                .semantic
                .as_ref()
                .and_then(|qv| crate::semantic_score(item, qv));
            let mut score = match (&q.semantic, kw_present) {
                // Pure keyword / recency (unchanged default behaviour).
                (None, _) => match relevance(item, &q.keywords) {
                    Some(s) => s,
                    None => continue,
                },
                // Pure semantic recall: rank by cosine; an item with no (compatible) embedding — or a
                // non-positive similarity (orthogonal/opposite) — is not a semantic hit.
                (Some(_), false) => match sem {
                    Some(s) if s > 0.0 => s * SEM_SCALE,
                    _ => continue,
                },
                // Hybrid: a keyword hit dominates; semantic augments/boosts it, and a positive
                // semantic-only match is still admissible (ranked below keyword hits).
                (Some(_), true) => match (relevance(item, &q.keywords), sem) {
                    (Some(k), Some(s)) => k + s.max(0.0) * SEM_SCALE,
                    (Some(k), None) => k,
                    (None, Some(s)) if s > 0.0 => s * SEM_SCALE,
                    _ => continue,
                },
            };
            if let Some(d) = q.decay {
                score *= item.decay_factor(d.now, d.half_life);
            }
            if used_bg {
                if let Scope::User(u) = &item.scope {
                    if !break_glass_subjects.contains(u) {
                        break_glass_subjects.push(u.clone());
                    }
                }
            }
            hits.push(MemoryHit {
                precedence: precedence_class(item),
                item: item.clone(),
                score,
            });
        }

        match q.order {
            RankOrder::Relevance => {
                hits.sort_by(|a, b| {
                    b.score
                        .partial_cmp(&a.score)
                        .unwrap_or(std::cmp::Ordering::Equal)
                        .then_with(|| a.item.id.cmp(&b.item.id))
                });
            }
            RankOrder::Precedence => {
                hits.sort_by(|a, b| {
                    a.precedence
                        .cmp(&b.precedence)
                        .then_with(|| {
                            b.score
                                .partial_cmp(&a.score)
                                .unwrap_or(std::cmp::Ordering::Equal)
                        })
                        .then_with(|| a.item.id.cmp(&b.item.id))
                });
            }
        }
        // OKI-extraction guard (design §8.8 / gap AM): a recon-shaped unscoped sweep that would return
        // more than `extraction_cap` extraction-sensitive OKIs (SecurityRule/ApprovedLibrary) is
        // treated as an extraction attempt — the sensitive OKIs are dropped (fail-closed; the full set
        // is never dumped verbatim). Scoped reads (the Context-Fabric planner) never trip this.
        let mut extraction_blocked = false;
        if self.extraction_cap > 0 && q.is_unscoped_safety_recon() {
            let sensitive =
                |h: &MemoryHit| h.item.org_type.is_some_and(|t| t.is_extraction_sensitive());
            let sensitive_count = hits.iter().filter(|h| sensitive(h)).count();
            if sensitive_count > self.extraction_cap {
                hits.retain(|h| !sensitive(h));
                extraction_blocked = true;
            }
        }
        if q.limit > 0 && hits.len() > q.limit {
            hits.truncate(q.limit);
        }
        (hits, break_glass_subjects, extraction_blocked)
    }

    /// Like [`query`](MemoryStore::query) but emits an audited `break-glass-read` entry for any
    /// personal item an admin saw via break-glass. Use this on the enterprise read path so
    /// privileged access to another user's memory is always provable.
    pub fn query_audited(&mut self, q: &MemoryQuery, access: &AccessScope) -> Vec<MemoryHit> {
        let (hits, subjects, extraction_blocked) = self.query_core(q, access, true);
        if !subjects.is_empty() {
            let reason = access.break_glass_justification().unwrap_or("(none)");
            for s in subjects {
                self.audit(
                    "break-glass-read",
                    &s,
                    &format!("query by {}: {reason}", access.principal().user_id),
                );
            }
        }
        if extraction_blocked {
            // Provably record the recon attempt (guardrail violation, §8.8) — same category as a
            // system-prompt extraction attempt.
            self.audit(
                "oki-extraction-guard",
                access.principal().user_id.as_str(),
                "unscoped bulk sweep of SecurityRule/ApprovedLibrary refused (fail-closed)",
            );
        }
        hits
    }

    // -------- unified Knowledge-Graph retrieval (design §2: OKIs are KG nodes) --------

    /// Whether `item` may be disclosed to `access` on a **non-audit-capable** read (KG traversal /
    /// immutable query): reachable scope (break-glass fails closed — never disclosed without audit),
    /// per-item RBAC grant, data-class clearance, and (when `authoritative_only`) governance authority.
    fn can_disclose(
        &self,
        item: &MemoryItem,
        access: &AccessScope,
        authoritative_only: bool,
    ) -> bool {
        let (visible, used_bg) = access.can_see(&item.scope);
        if !visible || used_bg {
            return false;
        }
        if let Some(rb) = &item.rbac_scope {
            if !rb.allows(access.principal()) {
                return false;
            }
        }
        if item.data_class.sensitivity() > access.principal().clearance.sensitivity()
            && !access.is_own_personal(&item.scope)
        {
            return false;
        }
        if authoritative_only && !item.is_authoritative() {
            return false;
        }
        true
    }

    /// Outgoing knowledge-graph neighbors of item `id` (design §2: OKIs are **nodes in the Context
    /// Fabric Knowledge Graph**, `links` are typed edges). For each [`Link`](crate::Link) whose target
    /// resolves to another stored item the caller may see (same pre-rank RBAC/data-class/governance
    /// discipline as [`query`](MemoryStore::query) — break-glass fails closed), returns
    /// `(edge_kind, item)`. Links to non-item targets (ADR refs, repo names, incident ids with no
    /// stored OKI) are skipped. Deterministic order: by `(edge, target id)`.
    pub fn neighbors(
        &self,
        id: &str,
        access: &AccessScope,
        authoritative_only: bool,
    ) -> Vec<(crate::EdgeKind, MemoryItem)> {
        let Some(node) = self.current(id) else {
            return Vec::new();
        };
        let mut out: Vec<(crate::EdgeKind, MemoryItem)> = Vec::new();
        let mut links: Vec<&crate::Link> = node.links.iter().collect();
        links.sort_by(|a, b| (a.edge as u8, &a.target).cmp(&(b.edge as u8, &b.target)));
        for link in links {
            if let Some(target) = self.current(&link.target) {
                if self.can_disclose(target, access, authoritative_only) {
                    out.push((link.edge, target.clone()));
                }
            }
        }
        out
    }

    /// Breadth-first traversal of the OKI knowledge graph from `start_id`, following outgoing typed
    /// edges up to `max_depth` hops (design §2: "one RBAC/data-class-aware graph, one query surface").
    /// Every visited node is pre-rank filtered by [`can_disclose`](InMemoryStore::can_disclose) — a
    /// node the caller cannot see is neither returned nor traversed *through* (existence not leaked,
    /// and it cannot be a bridge to nodes past it). `edges` restricts which [`EdgeKind`](crate::EdgeKind)s
    /// to follow (empty = all). Returns the connected items (excluding `start_id`) in BFS visitation
    /// order, de-duplicated. `max_depth == 0` returns empty.
    pub fn traverse(
        &self,
        start_id: &str,
        max_depth: usize,
        edges: &[crate::EdgeKind],
        access: &AccessScope,
        authoritative_only: bool,
    ) -> Vec<MemoryItem> {
        use std::collections::VecDeque;
        let mut visited: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        visited.insert(start_id.to_string());
        let mut out: Vec<MemoryItem> = Vec::new();
        // Only traverse FROM a start node the caller may see (fail-closed: no bridging through a
        // node you cannot read).
        match self.current(start_id) {
            Some(s) if self.can_disclose(s, access, authoritative_only) => {}
            _ => return out,
        }
        let mut frontier: VecDeque<(String, usize)> = VecDeque::new();
        frontier.push_back((start_id.to_string(), 0));
        while let Some((node_id, depth)) = frontier.pop_front() {
            if depth >= max_depth {
                continue;
            }
            for (edge, item) in self.neighbors(&node_id, access, authoritative_only) {
                if !edges.is_empty() && !edges.contains(&edge) {
                    continue;
                }
                if visited.insert(item.id.clone()) {
                    frontier.push_back((item.id.clone(), depth + 1));
                    out.push(item);
                }
            }
        }
        out
    }

    // -------- write path (attribution / scope-write isolation) --------

    /// Attributed, identity-checked write — the enterprise write path (design §8.2 write isolation).
    /// Enforces that `writer` may author into the item's [`Scope`] ([`AccessScope::can_write`]:
    /// membership for shared scopes, ownership for personal scope — break-glass never grants a
    /// write), and that **shared-scope non-OKI authority requires the approve capability**. Without
    /// it the item is queued as `Draft` (governance queue) rather than hard-rejected — redact/
    /// queue-and-proceed, not block. OKI writes remain human-gated regardless of `writer`.
    pub fn write_as(&mut self, item: MemoryItem, writer: &AccessScope) -> Result<(), MemoryError> {
        if !writer.can_write(&item.scope) {
            // Checkmarx CX-FP: user_id excluded from error message — caller already knows their
            // own identity; the error is returned to the caller, never logged to an external sink.
            return Err(MemoryError::NotAuthorized(
                "principal is not authorised to write into the target scope".to_string(),
            ));
        }
        let authorized_shared = writer.principal().has_cap(CAP_APPROVE);
        self.write_inner(item, authorized_shared)
    }

    /// Mark an item *used* (retrieved/injected) at logical tick `now` — feeds usage-based confidence
    /// decay (design §6: unused facts decay, freshly-used ones do not). Returns `false` if unknown.
    pub fn touch(&mut self, id: &str, now: u64) -> bool {
        if let Some(it) = self.current_mut(id) {
            it.last_used = Some(it.last_used.map_or(now, |p| p.max(now)));
            true
        } else {
            false
        }
    }

    /// Mark an item *confirmed* (re-verified still true) at `now` by `actor` — audited; resets its
    /// decay clock (design §6). Returns `false` if the id is unknown.
    pub fn confirm(&mut self, id: &str, now: u64, actor: &Principal) -> bool {
        let ok = if let Some(it) = self.current_mut(id) {
            it.last_confirmed = Some(now);
            true
        } else {
            false
        };
        if ok {
            let uid = actor.user_id.clone();
            self.audit("confirm", id, &uid);
        }
        ok
    }

    /// The **automatic** account-offboarding erasure job (design §5: "offboarding = automatic
    /// erasure job, not a manual step someone forgets"). Records an offboarding-initiated audit
    /// entry, then runs the full right-to-erasure cascade for `subject`. Returns the receipt.
    pub fn offboard_subject(&mut self, subject: &str) -> ErasureReceipt {
        self.audit(
            "offboard-initiated",
            subject,
            "automatic account-offboarding erasure job",
        );
        self.erase_subject(subject)
    }

    /// Internal write. `authorized_shared` = the caller holds approve authority for shared-scope
    /// authoring (set by [`write_as`](InMemoryStore::write_as)). The unattributed trait
    /// [`write`](MemoryStore::write) passes `false`, so no unattributed path can mint shared-scope
    /// authority. Enforces every write invariant (typed-payload schema, human-gate, approved-org
    /// immutability, shared-scope governance-queue, author/scope consistency, compliance redaction).
    fn write_inner(
        &mut self,
        mut item: MemoryItem,
        authorized_shared: bool,
    ) -> Result<(), MemoryError> {
        if item.id.trim().is_empty() {
            return Err(MemoryError::InvalidWrite("empty id".into()));
        }
        if !(0.0..=1.0).contains(&item.provenance.confidence) {
            return Err(MemoryError::InvalidWrite(
                "confidence must be within [0.0, 1.0]".into(),
            ));
        }

        // Author/scope consistency (design §8.2): a human-authored personal fact must be about its
        // own subject — no writing a fact into another user's personal scope.
        if item.kind != MemoryKind::OrgKnowledge {
            if let (Scope::User(subject), Author::Human { user_id }) =
                (&item.scope, &item.provenance.author)
            {
                if subject != user_id {
                    return Err(MemoryError::InvalidWrite(format!(
                        "human-authored personal fact must be about its own subject: author '{user_id}' != scope 'user:{subject}'"
                    )));
                }
            }
        }

        if item.kind == MemoryKind::OrgKnowledge {
            // Typed-payload schema gate — an invalid payload is rejected, never persisted as text.
            let ot = item.org_type.ok_or_else(|| {
                MemoryError::InvalidWrite("org-knowledge requires org_type".into())
            })?;
            let payload = item.payload.as_ref().ok_or_else(|| {
                MemoryError::InvalidWrite("org-knowledge requires a typed payload".into())
            })?;
            if payload.oki_type() != ot {
                return Err(MemoryError::SchemaViolation(
                    "payload type does not match org_type".into(),
                ));
            }
            // Enforce the versioned per-type JSON-schema registry on the write (design §2
            // `type_payload`): validate through the registry (not an ungoverned inline validate) and
            // stamp the in-force schema version on the persisted item — so "which schema version was
            // in force when this OKI was written" is answerable per item. An invalid payload is
            // rejected, never persisted "as text".
            let enforced_version = self
                .schema_registry
                .validate_write(payload)
                .map_err(|errs| MemoryError::SchemaViolation(format!("{errs:?}")))?;
            item.schema_version = enforced_version;
            // Human-gate: org-knowledge may only ENTER as Draft. No path from a write to authority.
            if item.governance != GovernanceState::Draft {
                return Err(MemoryError::InvalidWrite(
                    "org-knowledge must be written as Draft; approval only via promote()".into(),
                ));
            }
            // A system author can never mint authority (redundant with the Draft gate; explicit).
            if matches!(
                item.provenance.author,
                Author::SystemFlywheel | Author::SystemIngest
            ) && item.governance.is_authoritative_state()
            {
                return Err(MemoryError::InvalidWrite(
                    "a system author cannot mint authoritative org-knowledge".into(),
                ));
            }
        } else {
            if item.org_type.is_some() || item.payload.is_some() {
                return Err(MemoryError::InvalidWrite(
                    "non-org items must not carry org_type/payload".into(),
                ));
            }
            // Shared-scope (org/dept/team/repo) NON-OKI memory must never become org-wide authority
            // from an unattributed or unauthorized write (design §8.2: no path from "a user said so"
            // to org-scope authority). It enters the governance queue (Draft) unless the writer
            // holds approve authority (via `write_as`). Personal (User) scope is low-blast-radius
            // and remains immediately usable. This closes the "single caller injects an org-wide
            // authoritative fact" hole for every kind, not just OrgKnowledge.
            if !matches!(item.scope, Scope::User(_))
                && item.governance.is_authoritative_state()
                && !authorized_shared
            {
                item.governance = GovernanceState::Draft;
            }
        }

        // Approved/Production/Superseded org items are immutable to `write` — protect authority from
        // silent overwrite (edits go through a new Draft; conflicts through arbitrate()).
        if let Some(existing) = self.current(&item.id) {
            if existing.kind == MemoryKind::OrgKnowledge
                && !matches!(
                    existing.governance,
                    GovernanceState::Draft | GovernanceState::Conflicted
                )
            {
                return Err(MemoryError::InvalidWrite(format!(
                    "org-knowledge '{}' is {:?}; not editable via write (create a new Draft)",
                    existing.id, existing.governance
                )));
            }
            item.version = existing.version + 1;
        } else {
            item.version = 1;
        }

        // Compliance gate: redact BEFORE persistence so a leak never enters durable memory.
        self.redact_item(&mut item);
        // Embed-on-write (design §2 `embedding` / §8.5): compute the semantic vector over the
        // already-redacted body, routed by data-class (regulated/PII → in-house model only). Runs
        // AFTER redaction so a vector is never derived from unredacted content.
        self.embed_on_write(&mut item);
        item.seq = self.tick();

        // Collect SUPERSEDES targets (before the mutable insert, to satisfy the borrow checker).
        let supersede_targets: Vec<String> = item
            .links
            .iter()
            .filter(|l| l.edge == EdgeKind::Supersedes)
            .map(|l| l.target.clone())
            .collect();

        // Personal-fact conflict resolution (design §6): "most-recent + highest-confidence auto-wins
        // for ranking purposes" — a compound rule, not recency alone. On a same-subject conflict, the
        // candidate with the **higher provenance confidence** wins; only when confidences tie does
        // the most-recent write win (this item always is the most recent, since `seq` is monotonic).
        // The loser is superseded (versioned, tombstoned) but retained for audit — never deleted. This
        // means a low-confidence new assertion no longer silently retires a higher-confidence existing
        // fact just because it was written later.
        let subject_matches: Vec<(String, f32)> =
            if matches!(item.kind, MemoryKind::Semantic | MemoryKind::UserPreference)
                && matches!(item.scope, Scope::User(_))
            {
                let subject = item.personal_subject();
                self.items
                    .iter()
                    .filter_map(|(id, versions)| {
                        if id == &item.id {
                            return None;
                        }
                        let cur = versions.last()?;
                        if cur.kind == item.kind
                            && cur.scope == item.scope
                            && cur.personal_subject() == subject
                            && cur.is_authoritative()
                        {
                            Some((id.clone(), cur.provenance.confidence))
                        } else {
                            None
                        }
                    })
                    .collect()
            } else {
                Vec::new()
            };

        let new_confidence = item.provenance.confidence;
        // Partition by the confidence comparison: the new item wins over a candidate whose confidence
        // it meets or exceeds (ties broken by recency, which the new item always holds); it loses to a
        // strictly-more-confident existing fact instead.
        let personal_losers: Vec<String> = subject_matches
            .iter()
            .filter(|(_, conf)| new_confidence >= *conf)
            .map(|(id, _)| id.clone())
            .collect();
        let new_item_loses = subject_matches
            .iter()
            .any(|(_, conf)| new_confidence < *conf);

        let id = item.id.clone();
        if new_item_loses {
            // A less-confident new assertion never displaces a more-confident standing fact; the new
            // write is itself the one tombstoned (still persisted — the user's own edit history stays
            // auditable and undoable, per §5).
            item.governance = GovernanceState::Superseded;
        }
        self.items.entry(id.clone()).or_default().push(item);

        for target in supersede_targets {
            if target != id {
                if let Some(t) = self.current_mut(&target) {
                    if !matches!(t.governance, GovernanceState::Deprecated) {
                        t.governance = GovernanceState::Superseded;
                    }
                }
                self.audit("supersede-link", &target, &format!("by {id}"));
            }
        }
        if new_item_loses {
            self.audit(
                "personal-supersede",
                &id,
                "new write has lower confidence than the standing fact; new write superseded",
            );
        } else {
            for loser in personal_losers {
                if let Some(l) = self.current_mut(&loser) {
                    l.governance = GovernanceState::Superseded;
                }
                self.audit("personal-supersede", &loser, &format!("by {id}"));
            }
        }
        Ok(())
    }
}

impl MemoryStore for InMemoryStore {
    /// Unattributed write (system ingest / trait surface). Delegates to
    /// [`write_inner`](InMemoryStore::write_inner) with `authorized_shared = false`, so this path can
    /// never mint shared-scope authority — a shared-scope non-OKI item lands in the governance queue.
    /// Use [`write_as`](InMemoryStore::write_as) to author with an identity + approve capability.
    fn write(&mut self, item: MemoryItem) -> Result<(), MemoryError> {
        self.write_inner(item, false)
    }

    fn get_unchecked(&self, id: &str) -> Option<&MemoryItem> {
        self.current(id)
    }

    fn promote(&mut self, id: &str, approver: &Principal) -> Result<GovernanceState, MemoryError> {
        if !approver.has_cap(CAP_APPROVE) {
            return Err(MemoryError::NotAuthorized(format!(
                "principal '{}' lacks '{}' — promotion to authority is human-gated",
                approver.user_id, CAP_APPROVE
            )));
        }
        // Read state + conflict key before mutating (borrow discipline).
        let (_kind, state, conflict_key) = {
            let it = self
                .current(id)
                .ok_or_else(|| MemoryError::NotFound(id.to_string()))?;
            (it.kind, it.governance, it.conflict_key())
        };
        // Promotion applies to any governance-queued item: an OKI, or a shared-scope non-OKI fact
        // that `write` parked as Draft (design §8.2). Conflict arbitration below is OKI-only (only
        // OKIs carry a conflict_key). A named CAP_APPROVE human is always the one flipping to
        // authority — the flywheel/volume attack can never reach here.
        if state != GovernanceState::Draft {
            return Err(MemoryError::InvalidTransition(format!(
                "cannot promote '{id}': state is {state:?}, expected Draft"
            )));
        }
        // Conflict detection (design §6): if an authoritative OKI already owns this subject, park
        // the new one Conflicted for human arbitration — never silently create two authorities.
        let conflicts_with = conflict_key.as_ref().and_then(|key| {
            self.items.iter().find_map(|(other_id, versions)| {
                if other_id == id {
                    return None;
                }
                let cur = versions.last()?;
                if cur.kind == MemoryKind::OrgKnowledge
                    && cur.governance.is_authoritative_state()
                    && cur.conflict_key().as_ref() == Some(key)
                {
                    Some(other_id.clone())
                } else {
                    None
                }
            })
        });

        let tick = self.tick();
        let verified_by = approver.user_id.clone();
        let item = self
            .current_mut(id)
            .ok_or_else(|| MemoryError::NotFound(id.to_string()))?;
        if let Some(other) = conflicts_with {
            item.governance = GovernanceState::Conflicted;
            self.audit("promote-conflict", id, &format!("conflicts with {other}"));
            Ok(GovernanceState::Conflicted)
        } else {
            item.governance = GovernanceState::Approved;
            item.provenance.last_verified_by = Some(verified_by.clone());
            item.provenance.last_verified_at = Some(tick);
            self.audit("promote", id, &verified_by);
            Ok(GovernanceState::Approved)
        }
    }

    fn deprecate(&mut self, id: &str, actor: &Principal) -> Result<(), MemoryError> {
        if !actor.has_cap(CAP_APPROVE) {
            return Err(MemoryError::NotAuthorized(format!(
                "principal '{}' lacks '{}'",
                actor.user_id, CAP_APPROVE
            )));
        }
        let item = self
            .current_mut(id)
            .ok_or_else(|| MemoryError::NotFound(id.to_string()))?;
        if item.governance == GovernanceState::Deprecated {
            return Err(MemoryError::InvalidTransition(format!(
                "'{id}' is already Deprecated"
            )));
        }
        item.governance = GovernanceState::Deprecated;
        self.audit("deprecate", id, actor.user_id.as_str());
        Ok(())
    }

    fn delete_as(&mut self, id: &str, actor: &AccessScope) -> Result<bool, MemoryError> {
        // Read the governance facts first, then decide. An item the caller cannot see must be
        // indistinguishable from a missing one, so both return Ok(false) — a NotAuthorized error
        // here would confirm the id exists (an existence oracle over other users' memory).
        let Some(item) = self.current(id) else {
            return Ok(false);
        };
        let scope = item.scope.clone();
        let governance = item.governance;
        let (visible, used_break_glass) = actor.can_see(&scope);
        if !visible {
            return Ok(false);
        }

        let actor_id = actor.principal().user_id.clone();
        match &scope {
            // Personal memory: the owner's own right-to-erasure. An admin may erase another user's
            // personal item only under an audited break-glass justification (DPO/DSAR handling).
            Scope::User(owner) => {
                if *owner != actor_id && !used_break_glass {
                    return Ok(false);
                }
            }
            // Shared scope: anything that reached authority or was retired is audit evidence and is
            // never hard-deletable (design §6) — deprecate() is the supported path.
            _ => {
                if governance.is_authoritative_state()
                    || matches!(
                        governance,
                        GovernanceState::Deprecated | GovernanceState::Superseded
                    )
                {
                    return Err(MemoryError::NotAuthorized(format!(
                        "'{id}' is shared-scope and {governance:?}: retained for audit — deprecate it, \
                         hard-delete is not permitted"
                    )));
                }
                // Still queued (Draft/Conflicted): discarding it is the same human gate as promoting.
                if !actor.principal().has_cap(CAP_APPROVE) {
                    return Err(MemoryError::NotAuthorized(format!(
                        "principal '{actor_id}' lacks '{CAP_APPROVE}' to discard shared-scope '{id}'"
                    )));
                }
            }
        }

        let removed = self.items.remove(id).is_some();
        if removed {
            // Attribution is the point: the actor, the scope and any break-glass justification go
            // into the tamper-evident chain, so an erasure is provable after the fact.
            let mut detail = format!("by={actor_id} scope={} state={governance:?}", scope.key());
            if let Some(j) = actor.break_glass_justification() {
                detail.push_str(&format!(" break-glass={j}"));
            }
            self.audit("delete", id, &detail);
        }
        Ok(removed)
    }

    fn query(&self, q: &MemoryQuery, access: &AccessScope) -> Vec<MemoryHit> {
        // Immutable path: not audit-capable, so it fails closed on break-glass (a break-glass read
        // is only ever served on the audited path). The extraction guard still truncates fail-closed.
        self.query_core(q, access, false).0
    }
}

// ============================ Tests ============================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Enforcement, OrgPayload, Provenance, Severity};
    use ainxt_types::{DataClass, Principal};

    fn approver() -> Principal {
        Principal::user("owner-1", &[CAP_APPROVE])
    }

    fn access(p: Principal) -> AccessScope {
        AccessScope::from_principal(p)
    }

    fn lib_oki(id: &str, name: &str, language: &str) -> MemoryItem {
        MemoryItem::org(
            id,
            Scope::Repo("payments-core".into()),
            &format!("approved {name}"),
            OrgPayload::ApprovedLibrary {
                name: name.into(),
                version_range: ">=1".into(),
                language: language.into(),
                reason: "audited".into(),
                disallowed_alternatives: vec![],
                security_review_ref: None,
            },
            Provenance::flywheel(0.8),
        )
    }

    fn repo_access(repo: &str) -> AccessScope {
        AccessScope::from_principal(approver()).with_repos(&[repo])
    }

    #[derive(Debug)]
    struct StubRedactor;
    impl Redactor for StubRedactor {
        fn redact(&self, text: &str) -> String {
            text.replace("4111111111111111", "[REDACTED-PAN]")
        }
    }

    #[test]
    fn write_redacts_sensitive_content_before_persistence() {
        let mut store = InMemoryStore::new().with_redactor(Box::new(StubRedactor));
        let it = MemoryItem::new(
            "m1",
            MemoryKind::Episodic,
            Scope::User("u".into()),
            "card note",
            "customer card 4111111111111111 is on file",
            Provenance::flywheel(0.9),
        )
        .with_tags(&["4111111111111111"]);
        store.write(it).unwrap();
        let stored = store.get_unchecked("m1").unwrap();
        assert!(
            !stored.body.contains("4111111111111111"),
            "PAN must not persist: {}",
            stored.body
        );
        assert!(stored.body.contains("[REDACTED-PAN]"));
        assert!(!stored.tags.iter().any(|t| t.contains("4111111111111111")));
    }

    #[derive(Debug)]
    struct WeakRedactor; // an OLD rule-set that misses the PAN pattern
    impl Redactor for WeakRedactor {
        fn redact(&self, text: &str) -> String {
            text.to_string()
        }
    }

    #[test]
    fn re_redaction_scrubs_previously_stored_items() {
        // Item stored under an OLD (weak) rule-set that did not catch this PAN. The gate is always
        // present (never off) — it just missed the pattern before the rules were upgraded.
        let mut store = InMemoryStore::new().with_redactor(Box::new(WeakRedactor));
        store
            .write(MemoryItem::new(
                "m1",
                MemoryKind::Episodic,
                Scope::User("u".into()),
                "note",
                "leak 4111111111111111 here",
                Provenance::human("u", 1.0),
            ))
            .unwrap();
        assert!(store.get_unchecked("m1").unwrap().body.contains("4111111111111111"));
        // A rules update swaps in the stronger provider and re-scans retroactively.
        store = store.with_redactor(Box::new(StubRedactor));
        let changed = store.re_redact();
        assert_eq!(changed, 1);
        assert!(!store.get_unchecked("m1").unwrap().body.contains("4111111111111111"));
        // The re-redaction is itself audited and the chain verifies.
        assert!(store
            .audit_entries()
            .iter()
            .any(|e| e.action == "re-redact"));
        assert_eq!(store.verify_audit_chain(), None);
    }

    #[test]
    fn org_knowledge_not_authoritative_until_approved() {
        let mut store = InMemoryStore::new();
        store.write(lib_oki("c1", "reqwest", "rust")).unwrap();
        let acc = repo_access("payments-core");

        let auth = store.query(&MemoryQuery::keywords(&["reqwest"]), &acc);
        assert!(auth.is_empty(), "draft org-knowledge is not authoritative");

        let review = store.query(
            &MemoryQuery::keywords(&["reqwest"]).including_non_authoritative(),
            &acc,
        );
        assert_eq!(review.len(), 1);
        assert_eq!(review[0].item.governance, GovernanceState::Draft);

        assert_eq!(
            store.promote("c1", &approver()).unwrap(),
            GovernanceState::Approved
        );
        let after = store.query(&MemoryQuery::keywords(&["reqwest"]), &acc);
        assert_eq!(after.len(), 1);
        assert!(after[0].item.is_authoritative());
    }

    #[test]
    fn promote_requires_explicit_authorized_approval() {
        let mut store = InMemoryStore::new();
        store.write(lib_oki("c1", "reqwest", "rust")).unwrap();

        let unauth = Principal::user("dev-9", &[]);
        assert!(matches!(
            store.promote("c1", &unauth).unwrap_err(),
            MemoryError::NotAuthorized(_)
        ));
        assert_eq!(store.get_unchecked("c1").unwrap().governance, GovernanceState::Draft);

        let admin = Principal::admin("boss");
        assert_eq!(
            store.promote("c1", &admin).unwrap(),
            GovernanceState::Approved
        );
        let it = store.get_unchecked("c1").unwrap();
        assert_eq!(it.provenance.last_verified_by.as_deref(), Some("boss"));
        assert!(it.provenance.last_verified_at.is_some());

        assert!(matches!(
            store.promote("c1", &admin).unwrap_err(),
            MemoryError::InvalidTransition(_)
        ));
        assert!(matches!(
            store.promote("nope", &admin).unwrap_err(),
            MemoryError::NotFound(_)
        ));
        assert_eq!(store.verify_audit_chain(), None);
    }

    #[test]
    fn write_cannot_mint_authoritative_org_knowledge() {
        let mut store = InMemoryStore::new();
        let mut poison = lib_oki("p1", "evil", "rust");
        poison.governance = GovernanceState::Approved; // attacker forges authority
        assert!(matches!(
            store.write(poison).unwrap_err(),
            MemoryError::InvalidWrite(_)
        ));
        assert!(store.get_unchecked("p1").is_none(), "forged item must not persist");

        store.write(lib_oki("p2", "reqwest", "rust")).unwrap();
        store.promote("p2", &approver()).unwrap();
        let mut overwrite = lib_oki("p2", "hijacked", "rust");
        overwrite.governance = GovernanceState::Draft;
        assert!(matches!(
            store.write(overwrite).unwrap_err(),
            MemoryError::InvalidWrite(_)
        ));
    }

    #[test]
    fn invalid_typed_payload_is_rejected_not_stored_as_text() {
        let mut store = InMemoryStore::new();
        let bad = MemoryItem::org(
            "s1",
            Scope::Org,
            "blank rule",
            OrgPayload::SecurityRule {
                rule: "   ".into(), // blank → schema violation
                applicable_action: "".into(),
                applicable_data_class: DataClass::RegulatedPayment,
                severity: Severity::Critical,
                enforcement: Enforcement::Blocking,
                exception_process: None,
            },
            Provenance::ingest(0.9),
        );
        assert!(matches!(
            store.write(bad).unwrap_err(),
            MemoryError::SchemaViolation(_)
        ));
        assert!(store.get_unchecked("s1").is_none(), "invalid payload never persisted");
    }

    #[test]
    fn conflicting_okis_both_persist_and_need_human_arbitration() {
        let mut store = InMemoryStore::new();
        // First approved http client for rust.
        store.write(lib_oki("a", "reqwest", "rust")).unwrap();
        store.promote("a", &approver()).unwrap();
        // A second http client for the SAME language/scope → conflict on promote.
        store.write(lib_oki("b", "ureq", "rust")).unwrap();
        let state = store.promote("b", &approver()).unwrap();
        assert_eq!(state, GovernanceState::Conflicted);
        // Neither served as authoritative-ambiguously: 'a' still authoritative, 'b' conflicted.
        assert!(store.get_unchecked("a").unwrap().is_authoritative());
        assert!(!store.get_unchecked("b").unwrap().is_authoritative());

        // A human arbitrates: 'b' wins, 'a' is superseded.
        store.arbitrate("b", "a", &approver()).unwrap();
        assert_eq!(
            store.get_unchecked("b").unwrap().governance,
            GovernanceState::Approved
        );
        assert_eq!(
            store.get_unchecked("a").unwrap().governance,
            GovernanceState::Superseded
        );
        // 'a' retained (recoverable) but not served.
        let acc = repo_access("payments-core");
        let hits = store.query(&MemoryQuery::keywords(&["approved"]), &acc);
        let ids: Vec<&str> = hits.iter().map(|h| h.item.id.as_str()).collect();
        assert_eq!(ids, vec!["b"]);
    }

    /// R15 (low): **personal-fact conflict resolution is "most-recent + highest-confidence," not
    /// recency alone** (design §6). A later, LOW-confidence write on the same subject must NOT
    /// silently retire a standing HIGH-confidence fact; the low-confidence write is itself the one
    /// tombstoned. Only when the new write meets or beats the standing confidence does it win — and a
    /// same-confidence write still wins on recency (unchanged prior behaviour).
    #[test]
    fn r15_personal_fact_conflict_resolves_by_confidence_not_recency_alone() {
        let mut store = InMemoryStore::new();
        let mk = |id: &str, body: &str, confidence: f32| {
            MemoryItem::new(
                id,
                MemoryKind::UserPreference,
                Scope::User("alice".into()),
                "answer length preference",
                body,
                Provenance::human("alice", confidence),
            )
        };
        // A high-confidence, explicit human assertion.
        store.write(mk("hi", "prefers verbose", 0.95)).unwrap();
        assert_eq!(
            store.get_unchecked("hi").unwrap().governance,
            GovernanceState::Approved
        );

        // A LATER but LOW-confidence write on the same subject (e.g. a shaky system-side guess) must
        // not displace the higher-confidence standing fact, despite being more recent.
        store
            .write(mk("lo", "prefers terse (unsure)", 0.2))
            .unwrap();
        assert_eq!(
            store.get_unchecked("hi").unwrap().governance,
            GovernanceState::Approved,
            "higher-confidence standing fact must survive a lower-confidence later write"
        );
        assert_eq!(
            store.get_unchecked("lo").unwrap().governance,
            GovernanceState::Superseded,
            "the low-confidence write is itself tombstoned, not the high-confidence one"
        );
        let acc = access(Principal::user("alice", &[]));
        let hits = store.query(&MemoryQuery::keywords(&["preference"]), &acc);
        let ids: Vec<&str> = hits.iter().map(|h| h.item.id.as_str()).collect();
        assert_eq!(ids, vec!["hi"], "only the higher-confidence fact is served");
        assert!(
            store.get_unchecked("lo").is_some(),
            "loser retained (recoverable) for audit"
        );

        // A subsequent write that meets/beats the standing confidence DOES win (auto-wins), and the
        // prior high-confidence fact is superseded (retained, recoverable).
        store
            .write(mk("hi2", "prefers terse, confirmed", 0.95))
            .unwrap();
        assert_eq!(
            store.get_unchecked("hi").unwrap().governance,
            GovernanceState::Superseded
        );
        assert_eq!(
            store.get_unchecked("hi2").unwrap().governance,
            GovernanceState::Approved
        );
        let hits2 = store.query(&MemoryQuery::keywords(&["preference"]), &acc);
        let ids2: Vec<&str> = hits2.iter().map(|h| h.item.id.as_str()).collect();
        assert_eq!(ids2, vec!["hi2"]);
    }

    #[test]
    fn personal_facts_auto_resolve_by_recency_loser_recoverable() {
        let mut store = InMemoryStore::new();
        let mk = |id: &str, body: &str| {
            MemoryItem::new(
                id,
                MemoryKind::UserPreference,
                Scope::User("alice".into()),
                "answer length preference",
                body,
                Provenance::human("alice", 1.0),
            )
        };
        store.write(mk("old", "prefers verbose")).unwrap();
        store.write(mk("new", "prefers terse")).unwrap();
        // Auto-resolution: newer wins, older superseded (not deleted).
        assert_eq!(
            store.get_unchecked("old").unwrap().governance,
            GovernanceState::Superseded
        );
        assert_eq!(
            store.get_unchecked("new").unwrap().governance,
            GovernanceState::Approved
        );
        let acc = access(Principal::user("alice", &[]));
        let hits = store.query(&MemoryQuery::keywords(&["preference"]), &acc);
        let ids: Vec<&str> = hits.iter().map(|h| h.item.id.as_str()).collect();
        assert_eq!(ids, vec!["new"], "only the current fact is served");
        assert!(store.get_unchecked("old").is_some(), "loser recoverable for audit");
    }

    #[test]
    fn edit_free_versioning_enables_forensic_replay() {
        let mut store = InMemoryStore::new();
        store
            .write(MemoryItem::new(
                "f1",
                MemoryKind::Semantic,
                Scope::User("alice".into()),
                "role",
                "works on billing",
                Provenance::human("alice", 1.0),
            ))
            .unwrap();
        let v1_seq = store.get_unchecked("f1").unwrap().seq;
        assert_eq!(store.get_unchecked("f1").unwrap().version, 1);
        // Edit → new version, old retained.
        store
            .write(MemoryItem::new(
                "f1",
                MemoryKind::Semantic,
                Scope::User("alice".into()),
                "role",
                "works on payments-core",
                Provenance::human("alice", 1.0),
            ))
            .unwrap();
        assert_eq!(store.get_unchecked("f1").unwrap().version, 2);
        assert_eq!(store.versions("f1").len(), 2);
        // Forensic replay: resolve the exact (id, version) injected earlier → original content.
        let resolved = store.resolve(&[("f1".into(), 1)]);
        assert_eq!(resolved[0].as_ref().unwrap().body, "works on billing");
        // Transaction-time as_of query returns the v1 snapshot as of that tick.
        let acc = access(Principal::user("alice", &[]));
        let historical = store.query(&MemoryQuery::keywords(&["billing"]).as_of(v1_seq), &acc);
        assert_eq!(historical.len(), 1);
        assert_eq!(historical[0].item.version, 1);
        // Current query no longer matches the old body.
        assert!(store
            .query(&MemoryQuery::keywords(&["billing"]), &acc)
            .is_empty());
    }

    #[test]
    fn bitemporal_valid_time_query() {
        let mut store = InMemoryStore::new();
        // A rule valid only during [10, 20).
        store
            .write(
                MemoryItem::new(
                    "r",
                    MemoryKind::Semantic,
                    Scope::Org,
                    "deploy freeze",
                    "no deploys during freeze",
                    Provenance::ingest(1.0),
                )
                .with_validity(Some(10), Some(20)),
            )
            .unwrap();
        // Org-scope non-OKI enters the governance queue; a human approves it into authority.
        store.promote("r", &approver()).unwrap();
        let acc = access(Principal::user("u", &[]));
        // At valid-time 15 it applies.
        assert_eq!(
            store
                .query(&MemoryQuery::keywords(&["deploy"]).valid_as_of(15), &acc)
                .len(),
            1
        );
        // At valid-time 5 (before) and 25 (after) it does not.
        assert!(store
            .query(&MemoryQuery::keywords(&["deploy"]).valid_as_of(5), &acc)
            .is_empty());
        assert!(store
            .query(&MemoryQuery::keywords(&["deploy"]).valid_as_of(25), &acc)
            .is_empty());
    }

    #[test]
    fn precedence_orders_safety_rule_above_style_preference() {
        let mut store = InMemoryStore::new();
        // A style preference with a STRONG keyword match (title + body).
        store
            .write(MemoryItem::new(
                "pref",
                MemoryKind::UserPreference,
                Scope::User("alice".into()),
                "payment payment style",
                "prefers payment payment terse payment",
                Provenance::human("alice", 1.0),
            ))
            .unwrap();
        // A safety-classed org rule with a WEAKER keyword match.
        store
            .write(MemoryItem::org(
                "rule",
                Scope::Org,
                "payment approval rule",
                OrgPayload::SecurityRule {
                    rule: "dual-control over 1L".into(),
                    applicable_action: "approve".into(),
                    applicable_data_class: DataClass::RegulatedPayment,
                    severity: Severity::Critical,
                    enforcement: Enforcement::Blocking,
                    exception_process: None,
                },
                Provenance::ingest(1.0),
            ))
            .unwrap();
        store.promote("rule", &approver()).unwrap();

        let acc = AccessScope::from_principal(Principal::user("alice", &[]));
        // Pure relevance: the preference (stronger keyword match) ranks first.
        let by_rel = store.query(&MemoryQuery::keywords(&["payment"]), &acc);
        assert_eq!(by_rel[0].item.id, "pref");
        // Injection precedence: the SecurityRule wins despite weaker relevance.
        let by_prec = store.query(&MemoryQuery::keywords(&["payment"]).by_precedence(), &acc);
        assert_eq!(
            by_prec[0].item.id, "rule",
            "safety rule must outrank style at injection"
        );
    }

    #[test]
    fn identity_scope_isolation_is_not_caller_optional() {
        let mut store = InMemoryStore::new();
        // Two repo-scoped items in different repos, plus another user's personal fact. Shared-scope
        // facts enter the governance queue; a human approves them into authority.
        store.write(lib_oki_semantic("a", "repo-a")).unwrap();
        store.promote("a", &approver()).unwrap();
        store.write(lib_oki_semantic("b", "repo-b")).unwrap();
        store.promote("b", &approver()).unwrap();
        store
            .write(MemoryItem::new(
                "alice-pref",
                MemoryKind::UserPreference,
                Scope::User("alice".into()),
                "build config",
                "personal build config note",
                Provenance::human("alice", 1.0),
            ))
            .unwrap();

        // Bob is a member of repo-a only, and is NOT alice.
        let bob = AccessScope::from_principal(Principal::user("bob", &[])).with_repos(&["repo-a"]);
        let hits = store.query(&MemoryQuery::keywords(&["build"]), &bob);
        let ids: Vec<&str> = hits.iter().map(|h| h.item.id.as_str()).collect();
        // Even with scope=None on the query, bob sees ONLY repo-a — never repo-b or alice's fact.
        assert_eq!(
            ids,
            vec!["a"],
            "identity scope must filter without an explicit q.scope"
        );
    }

    fn lib_oki_semantic(id: &str, repo: &str) -> MemoryItem {
        MemoryItem::new(
            id,
            MemoryKind::Semantic,
            Scope::Repo(repo.into()),
            "build config",
            "build config detail",
            Provenance::human("u", 1.0),
        )
    }

    #[test]
    fn admin_break_glass_read_of_personal_pii_is_audited() {
        let mut store = InMemoryStore::new();
        store
            .write(
                MemoryItem::new(
                    "alice-pii",
                    MemoryKind::Semantic,
                    Scope::User("alice".into()),
                    "contact",
                    "personal contact detail",
                    Provenance::human("alice", 1.0),
                )
                .with_data_class(DataClass::Pii),
            )
            .unwrap();

        // Admin without break-glass: cannot see alice's personal item at all.
        let admin_noglass = AccessScope::from_principal(Principal::admin("root"));
        assert!(store
            .query(&MemoryQuery::keywords(&["contact"]), &admin_noglass)
            .is_empty());

        // Admin WITH break-glass via the audited read path: sees it AND an audit entry is written.
        let admin_glass =
            AccessScope::from_principal(Principal::admin("root")).with_break_glass("DPO ticket 7");
        let hits = store.query_audited(&MemoryQuery::keywords(&["contact"]), &admin_glass);
        assert_eq!(hits.len(), 1);
        assert!(store
            .audit_entries()
            .iter()
            .any(|e| e.action == "break-glass-read" && e.subject == "alice"));
        assert_eq!(store.verify_audit_chain(), None);
    }

    #[test]
    fn rbac_data_class_filters_pre_rank() {
        let mut store = InMemoryStore::new();
        store
            .write(
                MemoryItem::new(
                    "secret",
                    MemoryKind::Semantic,
                    Scope::Org,
                    "cardholder note",
                    "sensitive payment detail",
                    Provenance::human("u", 1.0),
                )
                .with_data_class(DataClass::RegulatedPayment),
            )
            .unwrap();
        // Org-scope non-OKI enters the governance queue; approve it into authority.
        store.promote("secret", &approver()).unwrap();
        let low = access(Principal::user("dev", &[]).with_clearance(DataClass::Internal));
        assert!(store
            .query(&MemoryQuery::keywords(&["payment"]), &low)
            .is_empty());
        let high = access(Principal::user("auditor", &[]).with_clearance(DataClass::Pii));
        assert_eq!(
            store
                .query(&MemoryQuery::keywords(&["payment"]), &high)
                .len(),
            1
        );
    }

    #[test]
    fn right_to_erasure_cascade_and_provable_audit() {
        let mut store = InMemoryStore::new();
        // Alice's personal facts across kinds.
        for (id, kind) in [
            ("a1", MemoryKind::Semantic),
            ("a2", MemoryKind::UserPreference),
            ("a3", MemoryKind::Episodic),
        ] {
            store
                .write(MemoryItem::new(
                    id,
                    kind,
                    Scope::User("alice".into()),
                    "alice thing",
                    "alice body",
                    Provenance::human("alice", 1.0),
                ))
                .unwrap();
        }
        // An org OKI alice authored (survives erasure, but is lineage-flagged).
        let mut oki = lib_oki("org1", "reqwest", "rust");
        oki.provenance = Provenance::human("alice", 0.9);
        store.write(oki).unwrap();

        let receipt = store.erase_subject("alice");
        assert_eq!(receipt.removed_ids.len(), 3);
        assert_eq!(receipt.fine_tune_lineage_flagged, vec!["org1".to_string()]);
        // Post-erasure: zero live personal records for alice.
        let acc = access(Principal::user("alice", &[]));
        assert!(store
            .query(
                &MemoryQuery::default().with_scope(Scope::User("alice".into())),
                &acc
            )
            .is_empty());
        assert!(store.get_unchecked("a1").is_none());
        // Org OKI retained.
        assert!(store.get_unchecked("org1").is_some());
        // One signed, chain-verified erasure audit entry.
        assert!(store
            .audit_entries()
            .iter()
            .any(|e| e.action == "erase-subject" && e.subject == "alice"));
        assert_eq!(store.verify_audit_chain(), None);
    }

    #[test]
    fn retention_purges_raw_episodic_but_keeps_promoted_derivatives() {
        let mut store = InMemoryStore::new();
        store
            .write(MemoryItem::new(
                "ep",
                MemoryKind::Episodic,
                Scope::User("u".into()),
                "run",
                "did a thing",
                Provenance::ingest(0.5),
            ))
            .unwrap(); // seq = 1
        store
            .write(MemoryItem::new(
                "fact",
                MemoryKind::Semantic,
                Scope::User("u".into()),
                "learned",
                "durable fact",
                Provenance::ingest(0.9),
            ))
            .unwrap(); // seq = 2
                       // Purge with now well past the episodic TTL.
        let purged = store.purge_expired(100, RetentionPolicy::new(5));
        assert_eq!(purged, 1);
        assert!(store.get_unchecked("ep").is_none(), "raw episodic aged out");
        assert!(store.get_unchecked("fact").is_some(), "promoted derivative survives");
    }

    #[test]
    fn reembed_routes_regulated_to_inhouse_only() {
        #[derive(Debug)]
        struct FakeInHouse;
        impl Embedder for FakeInHouse {
            fn model_id(&self) -> &str {
                "inhouse-v1"
            }
            fn kind(&self) -> EmbedderKind {
                EmbedderKind::InHouse
            }
            fn embed(&self, text: &str) -> Vec<f32> {
                vec![text.len() as f32]
            }
        }
        #[derive(Debug)]
        struct FakeCloud;
        impl Embedder for FakeCloud {
            fn model_id(&self) -> &str {
                "cloud-v1"
            }
            fn kind(&self) -> EmbedderKind {
                EmbedderKind::Cloud
            }
            fn embed(&self, text: &str) -> Vec<f32> {
                vec![text.len() as f32]
            }
        }

        let mut store = InMemoryStore::new();
        store
            .write(
                MemoryItem::new(
                    "reg",
                    MemoryKind::Semantic,
                    Scope::Org,
                    "regulated",
                    "regulated body",
                    Provenance::ingest(1.0),
                )
                .with_data_class(DataClass::RegulatedPayment),
            )
            .unwrap();
        store
            .write(
                MemoryItem::new(
                    "pub",
                    MemoryKind::Semantic,
                    Scope::Org,
                    "public",
                    "public body",
                    Provenance::ingest(1.0),
                )
                .with_data_class(DataClass::Public),
            )
            .unwrap();

        let n = store.reembed_all(&FakeInHouse, &FakeCloud).unwrap();
        assert_eq!(n, 2);
        // Regulated → in-house model ONLY (never cloud).
        assert_eq!(
            store.get_unchecked("reg").unwrap().embedding.as_ref().unwrap().kind,
            EmbedderKind::InHouse
        );
        // Public → cloud model.
        assert_eq!(
            store.get_unchecked("pub").unwrap().embedding.as_ref().unwrap().kind,
            EmbedderKind::Cloud
        );

        // A mis-tiered embedder is rejected (can't pass a cloud model as the in-house one).
        assert!(store.reembed_all(&FakeCloud, &FakeCloud).is_err());
    }

    #[test]
    fn consent_view_and_export_round_trip() {
        let mut store = InMemoryStore::new();
        store
            .write(MemoryItem::new(
                "p1",
                MemoryKind::UserPreference,
                Scope::User("alice".into()),
                "terse",
                "prefers terse",
                Provenance::human("alice", 1.0),
            ))
            .unwrap();
        store
            .write(MemoryItem::new(
                "s1",
                MemoryKind::Semantic,
                Scope::User("alice".into()),
                "role",
                "payments engineer",
                Provenance::human("alice", 1.0),
            ))
            .unwrap();

        let alice = AccessScope::from_principal(Principal::user("alice", &[]));
        let view = store.remembered_about("alice", &alice).unwrap();
        assert_eq!(view.subject, "alice");
        let kinds: Vec<MemoryKind> = view.by_kind.iter().map(|(k, _)| *k).collect();
        assert!(kinds.contains(&MemoryKind::UserPreference));
        assert!(kinds.contains(&MemoryKind::Semantic));

        // Another user cannot view or export alice's memory.
        let bob = AccessScope::from_principal(Principal::user("bob", &[]));
        assert!(store.remembered_about("alice", &bob).is_err());

        // Export is machine-readable (serde round-trips).
        let export = store.export_subject("alice", &alice).unwrap();
        let json = serde_json::to_string(&export).unwrap();
        let back: SubjectExport = serde_json::from_str(&json).unwrap();
        assert_eq!(back, export);
        assert_eq!(back.items.len(), 2);
    }

    #[test]
    fn supersedes_link_retires_target() {
        let mut store = InMemoryStore::new();
        store.write(lib_oki("old", "reqwest", "rust")).unwrap();
        store.promote("old", &approver()).unwrap();
        // A new item that SUPERSEDES the old one retires it on write.
        let newer = MemoryItem::new(
            "new",
            MemoryKind::Semantic,
            Scope::Repo("payments-core".into()),
            "replacement",
            "replacement note",
            Provenance::human("u", 1.0),
        )
        .with_link(EdgeKind::Supersedes, "old");
        store.write(newer).unwrap();
        assert_eq!(
            store.get_unchecked("old").unwrap().governance,
            GovernanceState::Superseded
        );
        assert!(!store.get_unchecked("old").unwrap().is_authoritative());
    }

    #[test]
    fn audit_chain_detects_tampering() {
        let mut store = InMemoryStore::new();
        store.write(lib_oki("c1", "reqwest", "rust")).unwrap();
        store.promote("c1", &approver()).unwrap();
        store.deprecate("c1", &approver()).unwrap();
        assert!(store.audit_entries().len() >= 2);
        assert_eq!(store.verify_audit_chain(), None);
        // Tamper with a middle entry's detail without recomputing hashes.
        store.audit[0].detail = "forged".to_string();
        assert_eq!(store.verify_audit_chain(), Some(0));
    }

    #[test]
    fn decay_factor_penalizes_older_items() {
        let mut store = InMemoryStore::new();
        let mk = |id: &str| {
            MemoryItem::new(
                id,
                MemoryKind::Semantic,
                Scope::Org,
                "cache tip",
                "cache tip",
                Provenance::human("u", 1.0),
            )
        };
        store.write(mk("old")).unwrap(); // seq 1
        store.write(mk("new")).unwrap(); // seq 2
        let old = store.get_unchecked("old").unwrap();
        let new = store.get_unchecked("new").unwrap();
        // At now=100, half-life 1, the older item's factor is strictly smaller.
        assert!(old.decay_factor(100, 1) < new.decay_factor(100, 1));
        assert!(old.is_decayed(100, 1, 0.5));
        // Decay is a ranking signal, not deletion: both still present.
        assert!(store.get_unchecked("old").is_some());
    }

    #[test]
    fn typed_non_org_rejects_stray_payload() {
        let mut store = InMemoryStore::new();
        let mut it = MemoryItem::new(
            "x",
            MemoryKind::Semantic,
            Scope::Org,
            "t",
            "b",
            Provenance::human("u", 1.0),
        );
        it.org_type = Some(crate::OrgKnowledgeType::CommonFix); // illegal on a non-org item
        assert!(matches!(
            store.write(it).unwrap_err(),
            MemoryError::InvalidWrite(_)
        ));
    }

    #[test]
    fn write_rejects_empty_id_and_bad_confidence() {
        let mut store = InMemoryStore::new();
        let bad_id = MemoryItem::new(
            "  ",
            MemoryKind::Semantic,
            Scope::Org,
            "t",
            "b",
            Provenance::human("u", 1.0),
        );
        assert!(matches!(
            store.write(bad_id).unwrap_err(),
            MemoryError::InvalidWrite(_)
        ));
        let mut bad_conf = MemoryItem::new(
            "x",
            MemoryKind::Semantic,
            Scope::Org,
            "t",
            "b",
            Provenance::human("u", 1.0),
        );
        bad_conf.provenance.confidence = 2.5;
        assert!(matches!(
            store.write(bad_conf).unwrap_err(),
            MemoryError::InvalidWrite(_)
        ));
    }

    #[test]
    fn deprecate_removes_from_authoritative_retrieval() {
        let mut store = InMemoryStore::new();
        store.write(lib_oki("d1", "reqwest", "rust")).unwrap();
        store.promote("d1", &approver()).unwrap();
        let acc = repo_access("payments-core");
        assert_eq!(
            store
                .query(&MemoryQuery::keywords(&["approved"]), &acc)
                .len(),
            1
        );
        store.deprecate("d1", &approver()).unwrap();
        assert!(store
            .query(&MemoryQuery::keywords(&["approved"]), &acc)
            .is_empty());
        assert_eq!(
            store.get_unchecked("d1").unwrap().governance,
            GovernanceState::Deprecated
        );
        store.write(lib_oki("d2", "ureq", "rust")).unwrap();
        assert!(matches!(
            store
                .deprecate("d2", &Principal::user("nobody", &[]))
                .unwrap_err(),
            MemoryError::NotAuthorized(_)
        ));
    }

    #[test]
    fn delete_erases_and_is_audited() {
        let mut store = InMemoryStore::new();
        store
            .write(MemoryItem::new(
                "u-pref",
                MemoryKind::UserPreference,
                Scope::User("u1".into()),
                "terse answers",
                "prefers terse answers",
                Provenance::human("u1", 1.0),
            ))
            .unwrap();
        // The owner exercising their own right-to-erasure.
        let owner = AccessScope::from_principal(Principal::user("u1", &[]));
        assert!(store.delete_as("u-pref", &owner).unwrap());
        assert!(store.get_unchecked("u-pref").is_none());
        assert!(!store.delete_as("u-pref", &owner).unwrap());
        // The audit entry is attributed — an unattributed "hard-delete" is exactly what was wrong.
        let e = store
            .audit_entries()
            .iter()
            .find(|e| e.action == "delete")
            .expect("delete audited");
        assert!(
            e.detail.contains("by=u1"),
            "unattributed delete: {}",
            e.detail
        );
    }

    // ==================== gap closures ====================

    #[test]
    fn gap_ainxt_memory_mem_01_default_store_gate_is_never_off_by_omission() {
        // MEM-01: a store built via the plain constructor (no explicit redactor) must NOT silently
        // persist a PAN — the compliance-on-write gate is mandatory (A1 invariant), only the
        // provider is configurable. Before the fix, `new()` had no redactor and this PAN persisted.
        let mut store = InMemoryStore::new();
        store
            .write(
                MemoryItem::new(
                    "m",
                    MemoryKind::Episodic,
                    Scope::User("u".into()),
                    "card note 4111111111111111",
                    "customer card 4111 1111 1111 1111 on file",
                    Provenance::human("u", 1.0),
                )
                .with_tags(&["4111111111111111"]),
            )
            .unwrap();
        let it = store.get_unchecked("m").unwrap();
        assert!(
            !it.body.contains("4111"),
            "PAN (grouped) must be redacted: {}",
            it.body
        );
        assert!(it.body.contains("[REDACTED-PAN]"));
        assert!(!it.title.contains("4111111111111111"), "title PAN redacted");
        assert!(
            !it.tags.iter().any(|t| t.contains("4111")),
            "tag PAN redacted"
        );
        // A secret token is caught too.
        store
            .write(MemoryItem::new(
                "s",
                MemoryKind::Episodic,
                Scope::User("u".into()),
                "leak",
                "token AKIAIOSFODNN7EXAMPLE9 committed",
                Provenance::human("u", 1.0),
            ))
            .unwrap();
        assert!(store.get_unchecked("s").unwrap().body.contains("[REDACTED-SECRET]"));
        // Ordinary prose with short numbers is untouched (no over-redaction).
        store
            .write(MemoryItem::new(
                "p",
                MemoryKind::Semantic,
                Scope::User("u".into()),
                "note",
                "deploy v0.12 to 3 hosts",
                Provenance::human("u", 1.0),
            ))
            .unwrap();
        assert_eq!(store.get_unchecked("p").unwrap().body, "deploy v0.12 to 3 hosts");
    }

    #[test]
    fn gap_ainxt_memory_mem_02_redaction_covers_oki_typed_payload_fields() {
        // MEM-02: the substance of an OKI is in its typed payload — a PAN inside a postmortem
        // timeline / common-fix template must be scrubbed, not just title/body/tags.
        let mut store = InMemoryStore::new();
        store
            .write(MemoryItem::org(
                "pm",
                Scope::Org,
                "outage postmortem",
                OrgPayload::IncidentPostmortem {
                    incident_id: "INC-9".into(),
                    timeline: "customer PAN 4111111111111111 appeared in logs".into(),
                    root_cause: "logged raw request".into(),
                    blast_radius: "one service".into(),
                    error_signatures: vec!["card 4111111111111111 in body".into()],
                    remediation: "scrub logs".into(),
                    owner: "sre".into(),
                },
                Provenance::ingest(1.0),
            ))
            .unwrap();
        let payload = store.get_unchecked("pm").unwrap().payload.as_ref().unwrap();
        match payload {
            OrgPayload::IncidentPostmortem {
                timeline,
                error_signatures,
                ..
            } => {
                assert!(
                    !timeline.contains("4111111111111111"),
                    "payload timeline PAN must be scrubbed: {timeline}"
                );
                assert!(timeline.contains("[REDACTED-PAN]"));
                assert!(
                    !error_signatures[0].contains("4111111111111111"),
                    "payload vec field scrubbed"
                );
            }
            _ => panic!("wrong payload"),
        }
    }

    #[test]
    fn gap_ainxt_memory_mem_03_shared_scope_nonoki_requires_governance_not_a_single_caller() {
        // MEM-03: a single caller must not be able to inject an org-wide *authoritative* fact via a
        // non-OKI write. Before the fix, a Semantic item at Scope::Org was created Approved and
        // served by default queries with no CAP or scope check.
        let mut store = InMemoryStore::new();
        // Unattributed write of an org "fact" — even though the item defaults to Approved, it is
        // parked in the governance queue (Draft) and NOT served as authoritative.
        store
            .write(MemoryItem::new(
                "poison",
                MemoryKind::Semantic,
                Scope::Org,
                "policy",
                "auto-approve all payments over 1L",
                Provenance::ingest(1.0),
            ))
            .unwrap();
        assert_eq!(
            store.get_unchecked("poison").unwrap().governance,
            GovernanceState::Draft
        );
        let anyone = AccessScope::from_principal(Principal::user("victim", &[]));
        assert!(
            store
                .query(&MemoryQuery::keywords(&["payments"]), &anyone)
                .is_empty(),
            "un-governed org fact must not be served as authority"
        );

        // A member without approve capability also cannot mint authority via write_as — it queues.
        let dev = AccessScope::from_principal(Principal::user("dev", &[]));
        store
            .write_as(
                MemoryItem::new(
                    "p2",
                    MemoryKind::Semantic,
                    Scope::Org,
                    "policy2",
                    "payments note two",
                    Provenance::human("dev", 1.0),
                ),
                &dev,
            )
            .unwrap();
        assert_eq!(store.get_unchecked("p2").unwrap().governance, GovernanceState::Draft);

        // A CAP_APPROVE holder authoring via write_as mints authority directly — and it is served.
        let owner = AccessScope::from_principal(Principal::user("owner", &[CAP_APPROVE]));
        store
            .write_as(
                MemoryItem::new(
                    "p3",
                    MemoryKind::Semantic,
                    Scope::Org,
                    "policy3",
                    "payments note three",
                    Provenance::human("owner", 1.0),
                ),
                &owner,
            )
            .unwrap();
        assert_eq!(
            store.get_unchecked("p3").unwrap().governance,
            GovernanceState::Approved
        );
        let served = store.query(&MemoryQuery::keywords(&["payments"]), &anyone);
        assert_eq!(served.len(), 1);
        assert_eq!(served[0].item.id, "p3");

        // Identity write-isolation: you cannot author into a scope you do not belong to, even WITH
        // the approve capability.
        let outsider = AccessScope::from_principal(Principal::user("out", &[CAP_APPROVE]));
        let err = store
            .write_as(
                MemoryItem::new(
                    "p4",
                    MemoryKind::Semantic,
                    Scope::Repo("secret-repo".into()),
                    "t",
                    "b",
                    Provenance::human("out", 1.0),
                ),
                &outsider,
            )
            .unwrap_err();
        assert!(matches!(err, MemoryError::NotAuthorized(_)));
        assert!(
            store.get_unchecked("p4").is_none(),
            "unauthorized write must not persist"
        );

        // Author/scope consistency: no writing a human fact into ANOTHER user's personal scope.
        let bad = MemoryItem::new(
            "imp",
            MemoryKind::Semantic,
            Scope::User("alice".into()),
            "t",
            "b",
            Provenance::human("mallory", 1.0),
        );
        assert!(matches!(
            store.write(bad).unwrap_err(),
            MemoryError::InvalidWrite(_)
        ));
    }

    #[test]
    fn gap_ainxt_memory_mem_06_session_tier_ages_out_by_last_activity() {
        // MEM-06: a Session working-memory tier exists and ages out on a short per-conversation TTL
        // (by last activity), while durable derivatives never age on a timer.
        let mut store = InMemoryStore::new();
        store
            .write(MemoryItem::new(
                "sess",
                MemoryKind::Session,
                Scope::User("u".into()),
                "scratch",
                "pending tool result",
                Provenance::ingest(0.5),
            ))
            .unwrap(); // seq = 1
        store
            .write(MemoryItem::new(
                "fact",
                MemoryKind::Semantic,
                Scope::User("u".into()),
                "durable",
                "durable fact",
                Provenance::ingest(0.9),
            ))
            .unwrap();
        // Touch the session item recently — last activity keeps it alive past its write tick.
        store.touch("sess", 40);
        let policy = RetentionPolicy::new(0).with_session_ttl(5);
        assert_eq!(
            store.purge_expired(43, policy),
            0,
            "recently-used session survives"
        );
        // Well past last activity → purged; durable derivative untouched.
        assert_eq!(store.purge_expired(100, policy), 1);
        assert!(store.get_unchecked("sess").is_none());
        assert!(store.get_unchecked("fact").is_some());
    }

    #[test]
    fn gap_ainxt_memory_mem_07_offboarding_auto_erasure_cascades_and_is_audited() {
        // MEM-07: account offboarding is an *automatic* erasure job (not a manual delete), running
        // the full right-to-erasure cascade and leaving a provable audit trail.
        let mut store = InMemoryStore::new();
        for (id, kind) in [
            ("a1", MemoryKind::Semantic),
            ("a2", MemoryKind::Session),
            ("a3", MemoryKind::Episodic),
        ] {
            store
                .write(MemoryItem::new(
                    id,
                    kind,
                    Scope::User("bob".into()),
                    "bob thing",
                    "bob body",
                    Provenance::human("bob", 1.0),
                ))
                .unwrap();
        }
        let receipt = store.offboard_subject("bob");
        assert_eq!(receipt.removed_ids.len(), 3);
        assert!(
            store.get_unchecked("a1").is_none() && store.get_unchecked("a2").is_none() && store.get_unchecked("a3").is_none()
        );
        // Both the offboarding trigger and the erasure are audited, and the chain verifies.
        assert!(store
            .audit_entries()
            .iter()
            .any(|e| e.action == "offboard-initiated" && e.subject == "bob"));
        assert!(store
            .audit_entries()
            .iter()
            .any(|e| e.action == "erase-subject" && e.subject == "bob"));
        assert_eq!(store.verify_audit_chain(), None);
    }

    #[test]
    fn gap_ainxt_memory_mem_08_decay_is_usage_based_not_write_recency() {
        // MEM-08: decay must penalize *unused* facts, not merely old writes — a freshly-used old
        // fact should out-rank a never-used newer one. Before the fix, decay used the write tick.
        let mut store = InMemoryStore::new();
        let mk = |id: &str| {
            MemoryItem::new(
                id,
                MemoryKind::Semantic,
                Scope::User("u".into()),
                "tip",
                "cache tip",
                Provenance::human("u", 1.0),
            )
        };
        store.write(mk("old")).unwrap(); // seq 1
        store.write(mk("new")).unwrap(); // seq 2
                                         // The OLD fact is used again at tick 100; the NEW one is never touched.
        assert!(store.touch("old", 100));
        let old = store.get_unchecked("old").unwrap();
        let new = store.get_unchecked("new").unwrap();
        assert!(
            old.decay_factor(100, 1) > new.decay_factor(100, 1),
            "a freshly-used old fact must decay less than a never-used newer fact"
        );
        // Confirmation also refreshes the decay clock and is audited.
        assert!(store.confirm("new", 100, &approver()));
        assert!(store.audit_entries().iter().any(|e| e.action == "confirm"));
    }

    #[test]
    fn gap_ainxt_memory_mem_11_rbac_scope_enforced_pre_rank() {
        // MEM-11: an item may be granted only to specific roles/departments, enforced pre-rank —
        // independent of its Scope. A department outside the grant sees nothing (existence hidden).
        let mut store = InMemoryStore::new();
        store
            .write(
                MemoryItem::new(
                    "g",
                    MemoryKind::Semantic,
                    Scope::Org, // org-visible by scope...
                    "policy",
                    "org wide payments note",
                    Provenance::ingest(1.0),
                )
                .with_rbac_scope(crate::RbacScope::departments(&["payments"])), // ...but granted only to payments
            )
            .unwrap();
        store.promote("g", &approver()).unwrap();

        // A user in a different department reaches Org scope but is NOT granted → filtered pre-rank.
        let hr = AccessScope::from_principal(Principal::user("h", &[]).with_department("hr"));
        assert!(store
            .query(&MemoryQuery::keywords(&["payments"]), &hr)
            .is_empty());
        // A user in the granted department sees it.
        let pay =
            AccessScope::from_principal(Principal::user("p", &[]).with_department("payments"));
        assert_eq!(
            store
                .query(&MemoryQuery::keywords(&["payments"]), &pay)
                .len(),
            1
        );
        // An admin bypasses the per-item grant.
        let admin = AccessScope::from_principal(Principal::admin("root"));
        assert_eq!(
            store
                .query(&MemoryQuery::keywords(&["payments"]), &admin)
                .len(),
            1
        );
    }
}
