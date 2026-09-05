// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! ainxt-compliance — a strong, **generic** DLP/redaction [`ComplianceGate`] default (ADR-003).
//!
//! The runtime ships a deliberately-weak placeholder ([`ainxt_runtime::compliance::RedactAndProceed`])
//! that only collapses *contiguous* 12+ digit runs. That placeholder has a real recall hole this
//! crate closes: a spaced card number like `4111 1111 1111 1111` is **not** a contiguous run, so the
//! placeholder leaks it in full. [`StrongRedactor`] validates payment cards with the Luhn checksum
//! across single space/hyphen separators, redacts secrets by marker/prefix/bearer, catches
//! high-entropy credentials, and redacts emails.
//!
//! ## Design invariants
//! * **Redact-and-proceed, never hard-block** — every detector produces a replacement span; the text
//!   flows on. (Blocking = day-1 abandonment; the project mandate.)
//! * **Never ship the secret value** — marker detectors redact the *value*, not just the marker. (A
//!   prior sibling bug shipped `SECRET=` while leaking the value; the tests here assert the value is
//!   gone.)
//! * **Generic + international** — Luhn (ISO/IEC 7812), RFC-shaped emails, and publicly-documented
//!   token prefixes only. Region-specific rules (e.g. Aadhaar / UPI VPA / IFSC / India-PAN) are the PRIVATE
//!   enterprise plugin behind this same seam and are intentionally **absent** from this OSS tree
//!   (core/enterprise split, ADR-028).
//! * **Config-first** — every detector and threshold is toggleable via [`RedactorConfig`]; the gate
//!   itself (that *some* redaction runs) is not removable — that is the engine's mandatory seam.
//! * **Std-only** — zero new dependency/license surface; hand-rolled scanners, exhaustively tested.
//!
//! Precision note: compliance is redact-and-proceed and over-redaction is safer than a leak in a
//! payments context, so a few detectors (long digit runs, context-gated CVV) deliberately err toward
//! recall. Where a false positive would be costly (entropy on ordinary prose), the detector is gated.

use ainxt_runtime::compliance::{ComplianceGate, Direction, Redacted};

/// A replacement span: `[start, end)` byte range in the source, and the label to substitute.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Span {
    start: usize,
    end: usize,
    label: &'static str,
}

/// Which detectors run, and their thresholds. All default **on**; disable individually for a surface
/// that provably does not need one (config-first). The *gate* is never removable — only its policy.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RedactorConfig {
    /// Luhn-validated payment cards (separator-tolerant). ISO/IEC 7812.
    pub cards: bool,
    /// Contiguous long digit runs (recall safety net for account/PAN-like numbers).
    pub long_digit_runs: bool,
    /// Minimum contiguous digit-run length treated as sensitive (safety net). Default 12.
    pub long_digit_run_min: usize,
    /// `marker=value` / `marker: value` secret redaction (password, token, api_key, …).
    pub marked_secrets: bool,
    /// Publicly-documented credential prefixes (AKIA…, ghp_…, sk-…, xox…, AIza…).
    pub prefixed_tokens: bool,
    /// `Authorization: Bearer <token>` redaction.
    pub bearer_tokens: bool,
    /// RFC-shaped email addresses.
    pub emails: bool,
    /// Context-gated CVV/CVC (only when a cvv/cvc marker precedes 3–4 digits).
    pub cvv: bool,
    /// Standalone high-entropy tokens (Shannon bits/char over threshold, length-gated).
    pub high_entropy: bool,
    /// Minimum token length considered for entropy scanning. Default 20.
    pub entropy_min_len: usize,
    /// Shannon-entropy threshold (bits per char) above which a length-gated token is redacted.
    /// Default 3.5 — high enough to skip ordinary words/URLs, low enough to catch base64/hex secrets.
    pub entropy_bits_per_char: f64,
    /// Value-based credential redaction: password-shaped tokens near a
    /// credential-root context word. Complements `marked_secrets` for typos.
    pub credential_shaped_values: bool,
}

impl Default for RedactorConfig {
    fn default() -> Self {
        RedactorConfig {
            cards: true,
            long_digit_runs: true,
            long_digit_run_min: 12,
            marked_secrets: true,
            prefixed_tokens: true,
            bearer_tokens: true,
            emails: true,
            cvv: true,
            high_entropy: true,
            // 32 chars: real API keys are usually 32+; below that, filenames
            // and camelCase identifiers dominate false positives.
            entropy_min_len: 32,
            // 4.0 bits/char: above mixed-case prose, still catches base64/hex secrets.
            entropy_bits_per_char: 4.0,
            credential_shaped_values: true,
        }
    }
}

/// A strong generic redactor implementing the mandatory [`ComplianceGate`] seam.
#[derive(Debug, Clone, Copy, Default)]
pub struct StrongRedactor {
    cfg: RedactorConfig,
}

impl StrongRedactor {
    /// A redactor with all detectors enabled (the recommended default).
    pub fn new() -> Self {
        StrongRedactor {
            cfg: RedactorConfig::default(),
        }
    }

    /// A redactor with an explicit configuration.
    pub fn with_config(cfg: RedactorConfig) -> Self {
        StrongRedactor { cfg }
    }

    /// Scan `text`, returning the redacted string and the number of redactions applied. Exposed
    /// directly (not just via the trait) so callers/tests can use it without a [`Direction`].
    pub fn redact(&self, text: &str) -> (String, usize) {
        let mut spans: Vec<Span> = Vec::new();
        if self.cfg.cards {
            detect_cards(text, &mut spans);
        }
        if self.cfg.long_digit_runs {
            detect_long_digit_runs(text, self.cfg.long_digit_run_min, &mut spans);
        }
        if self.cfg.marked_secrets {
            detect_marked_secrets(text, &mut spans);
        }
        if self.cfg.credential_shaped_values {
            detect_credential_shaped_values(text, &mut spans);
        }
        if self.cfg.bearer_tokens {
            detect_bearer(text, &mut spans);
        }
        if self.cfg.prefixed_tokens {
            detect_prefixed_tokens(text, &mut spans);
        }
        if self.cfg.cvv {
            detect_cvv(text, &mut spans);
        }
        if self.cfg.emails {
            detect_emails(text, &mut spans);
        }
        if self.cfg.high_entropy {
            detect_high_entropy(
                text,
                self.cfg.entropy_min_len,
                self.cfg.entropy_bits_per_char,
                &mut spans,
            );
        }
        apply_spans(text, spans)
    }
}

impl ComplianceGate for StrongRedactor {
    fn scan(&self, text: &str, _dir: Direction) -> Redacted {
        let (text, redactions) = self.redact(text);
        Redacted { text, redactions }
    }
}

// ============================ composable detector chain (core/enterprise split seam) ============================
//
// The OSS tree carries a strong *generic*, international detector set ([`StrongRedactor`]). The design's
// core/enterprise split (ADR-028) keeps region-specific CHD/PII detectors — Aadhaar, UPI VPA, IFSC,
// India-PAN — in the PRIVATE enterprise plugin, NOT here (an India-region pattern in the OSS tree is an
// IP/legal liability, and the mandate is: no region-specific rule ships in OSS). But "the detector set is fixed to
// the generic ones" was itself a gap: a deployment could not *extend* the set behind the same seam. The
// closure is a composition primitive, not the patterns. [`CompositeGate`] chains any number of
// [`ComplianceGate`]s — each scans the *redacted output* of the previous — so the private plugin plugs
// its detector gate in AFTER the generic redactor, the enforcement seam stays one `dyn ComplianceGate`,
// and no region-specific pattern ever lives in this repo. Redact-and-proceed composes cleanly: every
// gate only removes, so chaining can only redact *more*, never resurrect a redacted span.

/// A chain of [`ComplianceGate`]s applied in order — each gate scans the redacted output of the one
/// before it, and the total redaction count is the sum. This is the composition seam that lets a
/// deployment (or the PRIVATE enterprise plugin — Aadhaar / UPI VPA / IFSC / India-PAN, kept out
/// of this OSS tree by the core/enterprise split, ADR-028) extend the generic [`StrongRedactor`] with
/// additional detector sets **behind the same single `dyn ComplianceGate` seam** the engine enforces —
/// without any region-specific pattern living in the OSS repo. An empty chain is a no-op (redacts
/// nothing); order is preserved and deterministic.
///
/// GAP-AUDIT misc-decisions: investigated and confirmed a genuine, legitimate not-yet-needed
/// extension point, not a gap. Composition-root wiring (`ainxt-runtimed`) uses `StrongRedactor`
/// directly, and grepping this whole workspace for `impl ComplianceGate for` turns up no SECOND
/// production detector this OSS tree could chain today — the only other impls are test doubles
/// (`ainxt-conformance::LeakyGate`, assorted `Spaced*Detector` test fixtures) and `RedactAndProceed`
/// (the placeholder `StrongRedactor` already supersedes). The private enterprise plugin this seam
/// exists for, by design (ADR-028), lives outside this repo — there is nothing to fabricate a second
/// gate out of without inventing exactly the kind of region-specific pattern the split forbids here.
/// Re-investigate if/when a real second `ComplianceGate` impl (private-plugin or otherwise) appears.
pub struct CompositeGate {
    gates: Vec<Box<dyn ComplianceGate>>,
}

impl Default for CompositeGate {
    fn default() -> Self {
        Self::new()
    }
}

impl CompositeGate {
    /// An empty chain (no detectors). Build it up with [`then`](Self::then).
    pub fn new() -> Self {
        CompositeGate { gates: Vec::new() }
    }

    /// A chain whose first (base) detector is the generic [`StrongRedactor`] — the recommended base for
    /// a deployment that then chains its enterprise/region detectors after it.
    pub fn with_strong() -> Self {
        CompositeGate::new().then(Box::new(StrongRedactor::new()))
    }

    /// Append a gate to the chain (runs after all previously-added gates). Chainable.
    pub fn then(mut self, gate: Box<dyn ComplianceGate>) -> Self {
        self.gates.push(gate);
        self
    }

    /// Append a gate in place (for building a chain without move semantics).
    pub fn push(&mut self, gate: Box<dyn ComplianceGate>) {
        self.gates.push(gate);
    }

    /// Number of gates in the chain.
    pub fn len(&self) -> usize {
        self.gates.len()
    }

    /// Whether the chain is empty (a no-op gate).
    pub fn is_empty(&self) -> bool {
        self.gates.is_empty()
    }
}

impl ComplianceGate for CompositeGate {
    fn scan(&self, text: &str, dir: Direction) -> Redacted {
        let mut current = text.to_string();
        let mut total = 0usize;
        for gate in &self.gates {
            let Redacted { text, redactions } = gate.scan(&current, dir);
            current = text;
            total += redactions;
        }
        Redacted {
            text: current,
            redactions: total,
        }
    }
}

// ============================ span merge + apply ============================

/// Merge (dropping overlaps, earliest-start-wins, longer-wins on ties) and rebuild the string.
/// Deterministic and byte-safe: spans are byte offsets on char boundaries by construction.
fn apply_spans(text: &str, mut spans: Vec<Span>) -> (String, usize) {
    if spans.is_empty() {
        return (text.to_string(), 0);
    }
    // Earliest start first; on equal start prefer the longer span (more coverage).
    spans.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0usize;
    let mut count = 0usize;
    for s in spans {
        if s.start < cursor {
            continue; // overlaps an already-applied span; skip
        }
        if s.start > text.len() || s.end > text.len() || s.start >= s.end {
            continue; // defensive: never index out of bounds
        }
        out.push_str(&text[cursor..s.start]);
        out.push_str(s.label);
        cursor = s.end;
        count += 1;
    }
    out.push_str(&text[cursor..]);
    (out, count)
}

// ============================ detectors ============================

const CARD_LABEL: &str = "[REDACTED-PAN]";
const SECRET_LABEL: &str = "[REDACTED-SECRET]";
const EMAIL_LABEL: &str = "[REDACTED-EMAIL]";
const CVV_LABEL: &str = "[REDACTED-CVV]";

/// Luhn checksum over a slice of decimal digit values (0–9).
fn luhn_valid(digits: &[u8]) -> bool {
    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }
    let mut sum = 0u32;
    // Double every second digit from the right.
    for (i, &d) in digits.iter().rev().enumerate() {
        let mut v = d as u32;
        if i % 2 == 1 {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        // Checkmarx G3: use saturating_add to silence the integer-overflow lint; the
        // maximum possible sum for a 19-digit card is 9×19 = 171, well within u32, but
        // saturating_add makes the intent explicit and safe under any future refactor.
        sum = sum.saturating_add(v);
    }
    sum % 10 == 0
}

/// Cards: a maximal run of ASCII digits interleaved with single space/hyphen separators, whose
/// digits Luhn-validate at length 13–19. Catches spaced/hyphenated cards the placeholder leaks.
fn detect_cards(text: &str, out: &mut Vec<Span>) {
    let bytes = text.as_bytes();
    let n = bytes.len();
    let mut i = 0usize;
    while i < n {
        if !bytes[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        // Extend a run of digits and single internal separators.
        let start = i;
        let mut j = i;
        let mut digits: Vec<u8> = Vec::new();
        while j < n {
            let b = bytes[j];
            if b.is_ascii_digit() {
                digits.push(b - b'0');
                j += 1;
            } else if (b == b' ' || b == b'-') && j + 1 < n && bytes[j + 1].is_ascii_digit() {
                // single separator between digits — consume it and continue
                j += 1;
            } else {
                break;
            }
        }
        // Trim a trailing separator if any slipped in (shouldn't, given the look-ahead).
        let mut end = j;
        while end > start && (bytes[end - 1] == b' ' || bytes[end - 1] == b'-') {
            end -= 1;
        }
        if luhn_valid(&digits)
            && !is_followed_by_file_extension(bytes, end)
            && !is_preceded_by_path_separator(bytes, start)
        {
            out.push(Span {
                start,
                end,
                label: CARD_LABEL,
            });
        }
        i = j.max(i + 1);
    }
}

/// Contiguous digit runs of at least `min` — recall safety net for account/PAN-like numbers.
/// Skipped inside filenames/path segments (timestamps in filenames aren't sensitive).
fn detect_long_digit_runs(text: &str, min: usize, out: &mut Vec<Span>) {
    let bytes = text.as_bytes();
    let n = bytes.len();
    let mut i = 0usize;
    while i < n {
        if !bytes[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let start = i;
        while i < n && bytes[i].is_ascii_digit() {
            i += 1;
        }
        if i - start < min {
            continue;
        }
        // Skip path segments (leading / or \), bare filenames (202604281514.sql),
        // and digit runs embedded in filename-shaped identifiers (bankmaster_202604281514.sql).
        if is_preceded_by_path_separator(bytes, start)
            || is_followed_by_file_extension(bytes, i)
            || is_inside_filename_identifier(bytes, i)
            || is_after_identifier_and_before_extension(bytes, start, i)
        {
            continue;
        }
        out.push(Span {
            start,
            end: i,
            label: CARD_LABEL,
        });
    }
}

/// True if walking forward past word chars from `end` reaches a known file extension.
fn is_inside_filename_identifier(bytes: &[u8], end: usize) -> bool {
    let mut k = end;
    let n = bytes.len();
    while k < n {
        let b = bytes[k];
        if b.is_ascii_alphanumeric() || b == b'_' || b == b'-' {
            k += 1;
        } else {
            break;
        }
    }
    is_followed_by_file_extension(bytes, k)
}

/// True if `start..end` sits in a filename-shaped token: identifier-like prefix
/// (letter/`_`/`-`) AND the token as a whole is followed by a known extension.
fn is_after_identifier_and_before_extension(bytes: &[u8], start: usize, end: usize) -> bool {
    if start == 0 {
        return false;
    }
    let prev = bytes[start - 1];
    let has_identifier_prefix = prev.is_ascii_alphabetic()
        || prev == b'_'
        || prev == b'-';
    if !has_identifier_prefix {
        return false;
    }
    is_inside_filename_identifier(bytes, end)
}

/// Secret markers (case-insensitive) followed by `=`/`:` and a value → redact the VALUE.
/// True if the value token has secret-shape (digit OR special OR mixed-case).
/// Used to keep prose out of natural-language matches ("password is important").
fn has_secret_complexity(value: &str) -> bool {
    let mut has_digit = false;
    let mut has_upper = false;
    let mut has_lower = false;
    let mut has_special = false;
    for b in value.as_bytes() {
        if b.is_ascii_digit() {
            has_digit = true;
        } else if b.is_ascii_uppercase() {
            has_upper = true;
        } else if b.is_ascii_lowercase() {
            has_lower = true;
        } else if !b.is_ascii_whitespace() {
            has_special = true;
        }
    }
    has_digit || has_special || (has_upper && has_lower)
}

/// Separator matched after a secret-marker keyword.
enum SecretSeparator {
    /// `=` / `:` — permissive: accept any value token.
    Assignment,
    /// `is` / `->` / `→` — strict: require secret-shape + NL_MIN_VALUE_LEN.
    NaturalLanguage,
}

fn detect_marked_secrets(text: &str, out: &mut Vec<Span>) {
    // Common typos (paaawd/passwrd/passwoord) are also covered by
    // detect_credential_shaped_values via the shared "pass" root.
    const MARKERS: &[&str] = &[
        "password", "passwd", "passphrase", "passkey", "pwd",
        "paaawd", "passwrd", "passwoord",
        "secret", "credential", "credentials",
        "api_key", "apikey", "api-key",
        "access_token", "accesstoken",
        "client_secret", "clientsecret",
        "token", "auth_token",
        "private_key", "privatekey",
        "pin", "login",
    ];
    /// Natural-language min value length — below this, prose dominates.
    const NL_MIN_VALUE_LEN: usize = 6;

    let lower = text.to_ascii_lowercase();
    let bytes = text.as_bytes();
    let n = bytes.len();
    for marker in MARKERS {
        let mut from = 0usize;
        while let Some(rel) = lower[from..].find(marker) {
            let mstart = from + rel;
            let mend = mstart + marker.len();
            from = mend; // advance regardless
                         // marker must be a whole token (not a substring like "tokenizer")
            if mstart > 0 {
                let prev = bytes[mstart - 1];
                if prev.is_ascii_alphanumeric() || prev == b'_' {
                    continue;
                }
            }
            // Skip whitespace, then match a separator: `=`/`:` (permissive)
            // or ` is `/` -> `/`→` (natural-language, strict value guard).
            let mut k = mend;
            while k < n && (bytes[k] == b' ' || bytes[k] == b'\t') {
                k += 1;
            }
            if k >= n {
                continue;
            }
            let sep_kind: SecretSeparator;
            if bytes[k] == b'=' || bytes[k] == b':' {
                sep_kind = SecretSeparator::Assignment;
                k += 1;
            } else if lower[k..].starts_with("is ") || lower[k..].starts_with("is\t") {
                // Trailing space rules "is" as a standalone word (not `isabelle`).
                sep_kind = SecretSeparator::NaturalLanguage;
                k += 3; // skip "is "
            } else if bytes[k] == b'-'
                && k + 1 < n
                && bytes[k + 1] == b'>'
            {
                sep_kind = SecretSeparator::NaturalLanguage;
                k += 2; // skip "->"
            } else if k + 2 < n
                && bytes[k] == 0xE2
                && bytes[k + 1] == 0x86
                && bytes[k + 2] == 0x92
            {
                // '→' (U+2192)
                sep_kind = SecretSeparator::NaturalLanguage;
                k += 3;
            } else {
                continue;
            }
            // skip whitespace and an optional opening quote
            while k < n && (bytes[k] == b' ' || bytes[k] == b'\t') {
                k += 1;
            }
            let quoted = k < n && (bytes[k] == b'"' || bytes[k] == b'\'');
            let quote = if quoted { bytes[k] } else { 0 };
            if quoted {
                k += 1;
            }
            let vstart = k;
            // Value ends at a closing quote, ASCII whitespace/punctuation, or the
            // first non-ASCII byte — keeps `k` on a UTF-8 boundary so slicing never panics.
            while k < n {
                let b = bytes[k];
                if !b.is_ascii() {
                    break;
                }
                if quoted {
                    if b == quote {
                        break;
                    }
                } else if b == b' '
                    || b == b'\t'
                    || b == b'\n'
                    || b == b'\r'
                    || b == b','
                    || b == b';'
                    || b == b'&'
                    // Trim trailing sentence terminators on NL matches.
                    || (matches!(sep_kind, SecretSeparator::NaturalLanguage)
                        && (b == b'.' || b == b'!' || b == b'?'))
                {
                    break;
                }
                k += 1;
            }
            if k <= vstart {
                continue;
            }
            // Defensive: `vstart`/`k` are ASCII boundaries by construction; `get`
            // keeps that invariant safe against future refactors.
            let value = match text.get(vstart..k) {
                Some(v) => v,
                None => continue,
            };
            // NL form requires complexity + NL_MIN_VALUE_LEN; Assignment is permissive.
            if matches!(sep_kind, SecretSeparator::NaturalLanguage) {
                if value.len() < NL_MIN_VALUE_LEN {
                    continue;
                }
                if !has_secret_complexity(value) {
                    continue;
                }
            }
            out.push(Span {
                start: vstart,
                end: k,
                label: SECRET_LABEL,
            });
        }
    }
}

/// Credential-context root prefixes — a value near ANY word starting with
/// one of these is treated as a credential (catches typos and unenumerated
/// markers via the shared root, e.g. `passkey`, `keystore-pw`).
const CREDENTIAL_ROOTS: &[&str] = &[
    "pass", "pwd", "pw", "key", "secret", "token", "cred", "pin", "login", "auth",
];

/// Allowlist of credential-shaped words that are legitimate prose. Empty by
/// default — populate if production shows benign matches.
const CREDENTIAL_VALUE_ALLOWLIST: &[&str] = &[];

/// True if `token` could plausibly be a password/secret value:
/// length >= 6, ≥3-of-4 char classes (lower/upper/digit/special), not allowlisted.
fn looks_like_credential_value(token: &str) -> bool {
    if token.len() < 6 {
        return false;
    }
    let mut has_lower = false;
    let mut has_upper = false;
    let mut has_digit = false;
    let mut has_special = false;
    for b in token.as_bytes() {
        if b.is_ascii_lowercase() {
            has_lower = true;
        } else if b.is_ascii_uppercase() {
            has_upper = true;
        } else if b.is_ascii_digit() {
            has_digit = true;
        } else if matches!(b, b'@' | b'#' | b'!' | b'$' | b'%' | b'^' | b'&' | b'*' | b'(' | b')' | b'-' | b'_' | b'+' | b'=') {
            has_special = true;
        }
    }
    let classes = [has_lower, has_upper, has_digit, has_special]
        .iter()
        .filter(|x| **x)
        .count();
    if classes < 3 {
        return false;
    }
    let lower = token.to_ascii_lowercase();
    for allow in CREDENTIAL_VALUE_ALLOWLIST {
        if lower == *allow {
            return false;
        }
    }
    true
}

/// True if any word inside `text[window_start..window_end]` starts with a
/// CREDENTIAL_ROOTS prefix — the context signal for `detect_credential_shaped_values`.
fn has_credential_context(text: &str, window_start: usize, window_end: usize) -> bool {
    let lower = text.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let start = window_start.min(bytes.len());
    let end = window_end.min(bytes.len());
    if start >= end {
        return false;
    }
    // Char-boundary-safe: if the byte offsets land inside a multi-byte
    // character (e.g. `→`, Devanagari), `str::get` returns None and we
    // fall through to "no context" — the safe default.
    let window = match lower.get(start..end) {
        Some(w) => w,
        None => return false,
    };
    let win_bytes = window.as_bytes();
    let mut i = 0usize;
    let n = win_bytes.len();
    while i < n {
        while i < n && !win_bytes[i].is_ascii_alphabetic() {
            i += 1;
        }
        let word_start = i;
        while i < n && (win_bytes[i].is_ascii_alphabetic() || win_bytes[i] == b'_') {
            i += 1;
        }
        if word_start == i {
            continue;
        }
        // `word_start..i` walks only ASCII-alphabetic bytes, so the slice
        // is always a char boundary; the `get` is defensive belt+braces.
        let word = match window.get(word_start..i) {
            Some(w) => w,
            None => continue,
        };
        for root in CREDENTIAL_ROOTS {
            if word.starts_with(root) {
                return true;
            }
        }
    }
    false
}

/// Detect password/secret VALUES by shape + nearby credential context.
/// Complements `detect_marked_secrets` for typos and unenumerated synonyms
/// (`passkey`, `keystore-pw`, …). Fires when a credential-shaped token appears
/// within CONTEXT_WINDOW chars of a `CREDENTIAL_ROOTS` word.
fn detect_credential_shaped_values(text: &str, out: &mut Vec<Span>) {
    let bytes = text.as_bytes();
    let n = bytes.len();
    // Token delimiter set excludes `=`/`:` so a key=value pair such as
    // `api_key=<value>` splits into two tokens (letting detect_marked_secrets
    // redact the value token cleanly without consuming the key name).
    let is_tok = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'@' | b'#' | b'!' | b'$' | b'%' | b'^' | b'&' | b'*' | b'+');
    const CONTEXT_WINDOW: usize = 40;
    let mut i = 0usize;
    while i < n {
        if !is_tok(bytes[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < n && is_tok(bytes[i]) {
            i += 1;
        }
        let end = i;
        let tok = &text[start..end];
        if !looks_like_credential_value(tok) {
            continue;
        }
        let ctx_start = start.saturating_sub(CONTEXT_WINDOW);
        let ctx_end = (end + CONTEXT_WINDOW).min(n);
        if !has_credential_context(text, ctx_start, ctx_end) {
            continue;
        }
        // Skip filename-shaped tokens (followed by a common file extension
        // or preceded by a path separator) — directory listings are not secrets.
        if is_followed_by_file_extension(bytes, end)
            || is_preceded_by_path_separator(bytes, start)
        {
            continue;
        }
        // Overlaps with earlier detectors are resolved by apply_spans.
        out.push(Span {
            start,
            end,
            label: SECRET_LABEL,
        });
    }
}

/// `Authorization: Bearer <token>` (case-insensitive scheme) → redact the token.
fn detect_bearer(text: &str, out: &mut Vec<Span>) {
    let lower = text.to_ascii_lowercase();
    let bytes = text.as_bytes();
    let n = bytes.len();
    let needle = "bearer ";
    let mut from = 0usize;
    while let Some(rel) = lower[from..].find(needle) {
        let bstart = from + rel;
        let mut k = bstart + needle.len();
        from = k;
        while k < n && (bytes[k] == b' ' || bytes[k] == b'\t') {
            k += 1;
        }
        let vstart = k;
        while k < n && !bytes[k].is_ascii_whitespace() && bytes[k] != b',' {
            k += 1;
        }
        if k > vstart {
            out.push(Span {
                start: vstart,
                end: k,
                label: SECRET_LABEL,
            });
        }
    }
}

/// Publicly-documented credential prefixes. Only well-known, unambiguous shapes.
fn detect_prefixed_tokens(text: &str, out: &mut Vec<Span>) {
    // (prefix, min_suffix_len, suffix predicate)
    let bytes = text.as_bytes();
    let n = bytes.len();
    let is_tok = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'-';
    let prefixes: &[(&str, usize)] = &[
        ("AKIA", 16), // AWS access key id
        ("ASIA", 16), // AWS temporary access key id
        ("ghp_", 36), // GitHub personal token
        ("gho_", 36), // GitHub oauth token
        ("ghs_", 36), // GitHub app token
        ("github_pat_", 40),
        ("sk-", 20),   // OpenAI-style secret key
        ("xoxb-", 10), // Slack bot token
        ("xoxp-", 10), // Slack user token
        ("AIza", 20),  // Google API key
    ];
    for (prefix, min_suffix) in prefixes {
        let mut from = 0usize;
        while let Some(rel) = text[from..].find(prefix) {
            let start = from + rel;
            // require a token boundary before the prefix
            let ok_before = start == 0 || !is_tok(bytes[start - 1]);
            let mut k = start + prefix.len();
            while k < n && is_tok(bytes[k]) {
                k += 1;
            }
            let suffix_len = k - (start + prefix.len());
            if ok_before && suffix_len >= *min_suffix {
                out.push(Span {
                    start,
                    end: k,
                    label: SECRET_LABEL,
                });
            }
            from = start + prefix.len();
        }
    }
}

/// Context-gated CVV/CVC: a cvv/cvc/cvv2 marker followed by `=`/`:`/space and 3–4 digits.
fn detect_cvv(text: &str, out: &mut Vec<Span>) {
    const MARKERS: &[&str] = &["cvv2", "cvv", "cvc", "cid"];
    let lower = text.to_ascii_lowercase();
    let bytes = text.as_bytes();
    let n = bytes.len();
    for marker in MARKERS {
        let mut from = 0usize;
        while let Some(rel) = lower[from..].find(marker) {
            let mstart = from + rel;
            let mend = mstart + marker.len();
            from = mend;
            if mstart > 0
                && (bytes[mstart - 1].is_ascii_alphanumeric() || bytes[mstart - 1] == b'_')
            {
                continue;
            }
            let mut k = mend;
            while k < n
                && (bytes[k] == b' ' || bytes[k] == b'\t' || bytes[k] == b'=' || bytes[k] == b':')
            {
                k += 1;
            }
            let vstart = k;
            while k < n && bytes[k].is_ascii_digit() {
                k += 1;
            }
            let len = k - vstart;
            if (3..=4).contains(&len) {
                out.push(Span {
                    start: vstart,
                    end: k,
                    label: CVV_LABEL,
                });
            }
        }
    }
}

/// RFC-shaped email addresses: `local@domain.tld`. Conservative local/domain charsets.
fn detect_emails(text: &str, out: &mut Vec<Span>) {
    let bytes = text.as_bytes();
    let n = bytes.len();
    let is_local =
        |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'%' | b'+' | b'-');
    let is_domain = |b: u8| b.is_ascii_alphanumeric() || b == b'-';
    let mut i = 0usize;
    while i < n {
        if bytes[i] != b'@' {
            i += 1;
            continue;
        }
        // walk left over the local part
        let mut ls = i;
        while ls > 0 && is_local(bytes[ls - 1]) {
            ls -= 1;
        }
        // walk right over domain labels separated by dots, requiring a final TLD of ≥2 alpha
        let mut k = i + 1;
        let mut last_dot: Option<usize> = None;
        while k < n {
            let b = bytes[k];
            if is_domain(b) {
                k += 1;
            } else if b == b'.' && k + 1 < n && is_domain(bytes[k + 1]) {
                last_dot = Some(k);
                k += 1;
            } else {
                break;
            }
        }
        let local_ok = ls < i && bytes[ls] != b'.' && bytes[i - 1] != b'.';
        let tld_ok = match last_dot {
            Some(d) => {
                let tld = &bytes[d + 1..k];
                tld.len() >= 2 && tld.iter().all(|c| c.is_ascii_alphabetic())
            }
            None => false,
        };
        if local_ok && tld_ok {
            out.push(Span {
                start: ls,
                end: k,
                label: EMAIL_LABEL,
            });
            i = k;
        } else {
            i += 1;
        }
    }
}

/// Extensions treated as filename endings. When a candidate token is followed
/// by `.<ext>`, skip the entropy check — directory listings shouldn't be
/// redacted. Ordered by likelihood of appearing in tool output.
const FILENAME_EXTENSIONS: &[&str] = &[
    // Executables & packages
    "exe", "msi", "msu", "dll", "cab", "class", "jar", "so", "dylib", "deb", "rpm", "apk", "app",
    // Archives
    "zip", "tar", "gz", "tgz", "bz2", "7z", "rar", "xz",
    // Documents
    "pdf", "docx", "doc", "xlsx", "xls", "pptx", "ppt", "txt", "rtf", "odt", "ods",
    // Images / media
    "png", "jpg", "jpeg", "gif", "bmp", "svg", "ico", "webp", "mp4", "mov", "avi", "mkv", "mp3", "wav",
    // Source code
    "py", "rs", "js", "ts", "jsx", "tsx", "java", "kt", "go", "c", "cpp", "h", "hpp", "cs", "rb",
    "php", "swift", "scala", "sh", "bash", "zsh", "ps1", "bat", "cmd",
    // Config / data
    "json", "yaml", "yml", "toml", "xml", "ini", "conf", "cfg", "properties", "env", "csv", "tsv",
    // Web
    "html", "htm", "css", "scss", "less",
    // Logs & misc
    "log", "md", "mdx", "sql", "db", "sqlite", "crt", "cer", "pem", "key", "lock",
    // Office 2016 style
    "opal", "opax", "chm",
];

/// True if `bytes[end..]` starts with `.<ext>` for any known extension —
/// marks a high-entropy token as a filename base rather than a secret.
fn is_followed_by_file_extension(bytes: &[u8], end: usize) -> bool {
    if end >= bytes.len() || bytes[end] != b'.' {
        return false;
    }
    // Extract at most 6 chars after the '.'
    let ext_start = end + 1;
    let mut ext_end = ext_start;
    while ext_end < bytes.len() && ext_end - ext_start < 8 {
        let b = bytes[ext_end];
        if b.is_ascii_alphanumeric() {
            ext_end += 1;
        } else {
            break;
        }
    }
    if ext_end == ext_start {
        return false;
    }
    let ext_bytes = &bytes[ext_start..ext_end];
    // Case-insensitive compare against the known list.
    FILENAME_EXTENSIONS.iter().any(|known| {
        let k = known.as_bytes();
        k.len() == ext_bytes.len()
            && k.iter().zip(ext_bytes.iter()).all(|(a, b)| a.eq_ignore_ascii_case(b))
    })
}

/// True if `start` is preceded by `/` or `\` — the token is a path segment
/// (e.g. camelCase folder names) and not a secret.
fn is_preceded_by_path_separator(bytes: &[u8], start: usize) -> bool {
    start > 0 && matches!(bytes[start - 1], b'/' | b'\\')
}

/// Standalone high-entropy tokens: length-gated, Shannon bits/char over threshold, and "mixed" enough
/// (contains at least two of lower/upper/digit) to skip ordinary long words and hex-only IDs.
///
/// Excludes filename-shaped tokens (`.ext` suffix) and path segments
/// (preceded by `/` or `\`) to keep directory listings intact.
fn detect_high_entropy(text: &str, min_len: usize, bits_per_char: f64, out: &mut Vec<Span>) {
    let bytes = text.as_bytes();
    let n = bytes.len();
    let is_tok = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'+' | b'/' | b'=');
    let mut i = 0usize;
    while i < n {
        if !is_tok(bytes[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < n && is_tok(bytes[i]) {
            i += 1;
        }
        let end = i;
        let tok = &text[start..end];
        if tok.len() < min_len {
            continue;
        }
        // Skip filename base names (followed by a common file extension).
        if is_followed_by_file_extension(bytes, end) {
            continue;
        }
        // Skip path segments (preceded by / or \).
        if is_preceded_by_path_separator(bytes, start) {
            continue;
        }
        // require character-class mix (skip all-lower prose and all-hex ids)
        let has_lower = tok.bytes().any(|b| b.is_ascii_lowercase());
        let has_upper = tok.bytes().any(|b| b.is_ascii_uppercase());
        let has_digit = tok.bytes().any(|b| b.is_ascii_digit());
        let classes = [has_lower, has_upper, has_digit]
            .iter()
            .filter(|x| **x)
            .count();
        if classes < 2 {
            continue;
        }
        if shannon_bits_per_char(tok) >= bits_per_char {
            out.push(Span {
                start,
                end,
                label: SECRET_LABEL,
            });
        }
    }
}

/// Shannon entropy in bits per character over the token's byte distribution.
fn shannon_bits_per_char(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &b in s.as_bytes() {
        freq[b as usize] += 1;
    }
    let len = s.len() as f64;
    let mut h = 0.0f64;
    for &f in freq.iter() {
        if f == 0 {
            continue;
        }
        let p = f as f64 / len;
        h -= p * p.log2();
    }
    h
}

// ============================ PCI no-CDE-persistence sink-guard (§5) ============================
//
// The runtime I/O gate (redact-and-proceed) protects the *user-facing* surface. The design's
// §1.3 durable-store regime is different: cardholder data (PAN/SAD) and secrets must be redacted
// **before the bytes land in any durable sink** — Event Log, memory, vector index, traces, DSAR
// exports — so the store is *structurally* CHD-free and falls out of PCI "stores CHD" scope by
// construction (§5.1), not by audit luck. The same detector set drives it; only the seam differs:
// this is a write-path guard, plus a defense-in-depth store sweep (§5.4) that proves the guard held.

/// A durable sink the runtime persists to. The write-path [`SinkGuard`] sits in front of it, so a
/// sink only ever receives already-redacted bytes. Implementors are the real stores (Event Log /
/// Postgres / object-store); [`InMemorySink`] is the reference/test double.
pub trait DurableSink {
    /// The sink's write error.
    type Error;
    /// Append one **already-guarded** record.
    fn append(&mut self, guarded: &str) -> Result<(), Self::Error>;
}

/// An in-memory sink — a reference impl and a test double. Never fails.
#[derive(Debug, Default, Clone)]
pub struct InMemorySink {
    records: Vec<String>,
}

impl InMemorySink {
    pub fn new() -> Self {
        Self::default()
    }
    /// The records as stored (already guarded when written through a [`SinkGuard`]).
    pub fn records(&self) -> &[String] {
        &self.records
    }
    /// Append a record **without** guarding it — used only to simulate a bypass in a sweep test.
    pub fn append_raw(&mut self, raw: &str) {
        self.records.push(raw.to_string());
    }
}

impl DurableSink for InMemorySink {
    type Error = std::convert::Infallible;
    fn append(&mut self, guarded: &str) -> Result<(), Self::Error> {
        self.records.push(guarded.to_string());
        Ok(())
    }
}

/// The outcome of a guarded persist: exactly what landed in the sink, and how many redactions the
/// guard applied on the way in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistOutcome {
    /// The redacted bytes that were written (safe to echo/log — CHD already removed).
    pub stored: String,
    /// Number of redactions applied before the write.
    pub redactions: usize,
}

/// A CHD/secret hit found by the defense-in-depth store sweep (§5.4). Its presence means the
/// write-path guard was bypassed for that record — each hit is a §2 incident candidate. `sample`
/// is the **redacted** rendering (never the raw CHD), so surfacing a hit does not itself leak.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SweepHit {
    pub record_id: String,
    pub redactions: usize,
    pub sample: String,
}

/// The write-path CHD sink-guard (§5.1) — redact-before-persist over any [`ComplianceGate`].
///
/// Wrapping the generic [`StrongRedactor`] guards every durable sink with the same detector set the
/// I/O gate uses, but with the durable-store *action* (redact before the write). Because every path
/// to a sink goes through [`persist`](SinkGuard::persist), the sink is CHD-free by construction; the
/// [`sweep`](SinkGuard::sweep) then continuously *proves* it.
#[derive(Debug, Clone, Copy)]
pub struct SinkGuard<G: ComplianceGate> {
    gate: G,
}

impl SinkGuard<StrongRedactor> {
    /// A sink-guard backed by the full [`StrongRedactor`] (all detectors on). For a durable store,
    /// over-redaction is safer than a leak, so the strong default is the recommended write-path guard.
    pub fn strong() -> Self {
        SinkGuard {
            gate: StrongRedactor::new(),
        }
    }

    /// A sink-guard tuned to **cardholder data only** (PAN via Luhn + long digit runs + context-gated
    /// CVV). Use when a store must stay CHD-free but should retain non-CHD text (e.g. an audit log
    /// that keeps redacted-but-present records — the §6.4 retain-record/minimize-PII posture).
    pub fn cde() -> Self {
        let cfg = RedactorConfig {
            cards: true,
            long_digit_runs: true,
            cvv: true,
            marked_secrets: false,
            prefixed_tokens: false,
            bearer_tokens: false,
            emails: false,
            high_entropy: false,
            ..RedactorConfig::default()
        };
        SinkGuard {
            gate: StrongRedactor::with_config(cfg),
        }
    }
}

impl<G: ComplianceGate> SinkGuard<G> {
    /// Build a sink-guard over an explicit gate.
    pub fn new(gate: G) -> Self {
        SinkGuard { gate }
    }

    /// Redact `text` and append the redacted bytes to `sink`. The sink never sees the raw input.
    /// Propagates the sink's own write error unchanged.
    pub fn persist<S: DurableSink>(
        &self,
        sink: &mut S,
        text: &str,
    ) -> Result<PersistOutcome, S::Error> {
        let Redacted {
            text: stored,
            redactions,
        } = self.gate.scan(text, Direction::Output);
        sink.append(&stored)?;
        Ok(PersistOutcome { stored, redactions })
    }

    /// Whether `text` still carries CHD/secret/PII under this guard's detectors — i.e. persisting it
    /// raw would leave the store non-clean.
    pub fn would_redact(&self, text: &str) -> bool {
        self.gate.scan(text, Direction::Output).redactions > 0
    }

    /// Defense-in-depth store sweep (§5.4): scan already-stored `(record_id, content)` pairs; any
    /// record the guard would still redact is a [`SweepHit`] (the write-path guard was bypassed).
    /// Returns hits in input order. Deterministic; no I/O — the caller supplies the records.
    pub fn sweep<'a, I>(&self, records: I) -> Vec<SweepHit>
    where
        I: IntoIterator<Item = (&'a str, &'a str)>,
    {
        records
            .into_iter()
            .filter_map(|(id, content)| {
                let r = self.gate.scan(content, Direction::Output);
                if r.redactions > 0 {
                    Some(SweepHit {
                        record_id: id.to_string(),
                        redactions: r.redactions,
                        sample: r.text,
                    })
                } else {
                    None
                }
            })
            .collect()
    }
}

/// The **enforced** write path (FI-01): a sink wrapped so that the *only* way to write is through
/// the CHD sink-guard. [`SinkGuard::persist`] is correct but *advisory* — a caller still holds the
/// raw sink and could call [`DurableSink::append`] directly, bypassing redaction. `GuardedSink`
/// closes that hole structurally: it **owns** the sink privately, exposes **no** raw-append path,
/// and its only constructors bind a guard. Once a real store is wrapped, "every path to the sink
/// goes through `persist()`" (§5.1) is a *type-level* guarantee, not a review convention.
///
/// This is the wrapper the runtime's durable sinks (Event Log, memory, vector index, traces, DSAR
/// exports, incident register) must be constructed behind so the no-CDE-persistence guarantee holds
/// mechanically. The inner sink is unreachable except by consuming the wrapper ([`into_inner`]),
/// after which it can no longer be written through — so no live write can skip the guard.
///
/// [`into_inner`]: GuardedSink::into_inner
#[derive(Debug, Clone)]
pub struct GuardedSink<S: DurableSink, G: ComplianceGate = StrongRedactor> {
    sink: S,
    guard: SinkGuard<G>,
    writes: u64,
    redactions: u64,
}

impl<S: DurableSink> GuardedSink<S, StrongRedactor> {
    /// Wrap `sink` behind the full [`StrongRedactor`] guard (all detectors on). The recommended
    /// default for a durable store: over-redaction is safer than a leak.
    pub fn strong(sink: S) -> Self {
        Self::with_guard(sink, SinkGuard::strong())
    }

    /// Wrap `sink` behind the cardholder-data-only guard (PAN/long-run/CVV; keeps other text) — the
    /// §6.4 retain-record/minimize-CHD posture for an evidentiary/audit log.
    pub fn cde(sink: S) -> Self {
        Self::with_guard(sink, SinkGuard::cde())
    }
}

impl<S: DurableSink, G: ComplianceGate> GuardedSink<S, G> {
    /// Wrap `sink` behind an explicit [`SinkGuard`]. This (and the `strong`/`cde` shortcuts) are the
    /// **only** ways to construct a `GuardedSink` — there is no constructor that leaves the sink
    /// writable without a guard, and no field is public.
    pub fn with_guard(sink: S, guard: SinkGuard<G>) -> Self {
        GuardedSink {
            sink,
            guard,
            writes: 0,
            redactions: 0,
        }
    }

    /// The one and only write path. Redacts through the guard, then appends the **already-redacted**
    /// bytes to the owned sink. A cancel/failure in the underlying sink surfaces as `Err` *after*
    /// redaction, so a failed write never leaves raw CHD anywhere — the redaction happened first and
    /// the raw bytes are dropped. Returns what landed plus the redaction count.
    pub fn write(&mut self, text: &str) -> Result<PersistOutcome, S::Error> {
        let outcome = self.guard.persist(&mut self.sink, text)?;
        self.writes += 1;
        self.redactions += outcome.redactions as u64;
        Ok(outcome)
    }

    /// Total writes that succeeded through the guard.
    pub fn write_count(&self) -> u64 {
        self.writes
    }

    /// Total redactions the guard applied across all writes (a live "how much CHD did we stop landing"
    /// metric — a nonzero value on a store that should be clean is a §5.4 signal).
    pub fn redaction_count(&self) -> u64 {
        self.redactions
    }

    /// Borrow the guard (e.g. to run a defense-in-depth [`sweep`](SinkGuard::sweep) with the same
    /// detector policy the writes used).
    pub fn guard(&self) -> &SinkGuard<G> {
        &self.guard
    }

    /// Read-only borrow of the wrapped sink (for a sweep/inspection). There is deliberately **no**
    /// `&mut` accessor: a mutable borrow would re-open the raw-append bypass this type exists to close.
    pub fn sink(&self) -> &S {
        &self.sink
    }

    /// Consume the wrapper and return the inner sink. After this the sink is no longer behind the
    /// guard — this is the explicit, visible escape hatch (e.g. teardown), never a silent bypass.
    pub fn into_inner(self) -> S {
        self.sink
    }
}

#[cfg(test)]
mod sink_guard_tests {
    use super::*;

    #[test]
    fn pan_is_redacted_before_it_reaches_the_sink() {
        // §5.5 test 1: a Luhn-valid PAN is redacted BEFORE the durable write.
        let guard = SinkGuard::strong();
        let mut sink = InMemorySink::new();
        let out = guard
            .persist(&mut sink, "charge 4111 1111 1111 1111 now")
            .unwrap();
        assert!(out.redactions >= 1);
        assert!(!out.stored.contains("4111"));
        // The sink bytes are structurally CHD-free.
        assert_eq!(sink.records().len(), 1);
        assert!(!sink.records()[0].contains("4111"));
        assert!(sink.records()[0].contains("[REDACTED-PAN]"));
    }

    #[test]
    fn sink_is_chd_free_after_guarded_writes_sweep_finds_nothing() {
        // §5.5 test 1 (continued): a post-write sweep of the store returns zero CHD.
        let guard = SinkGuard::strong();
        let mut sink = InMemorySink::new();
        guard.persist(&mut sink, "pan 4111111111111111").unwrap();
        guard.persist(&mut sink, "cvv: 123 for the card").unwrap();
        guard
            .persist(&mut sink, "an ordinary settlement note")
            .unwrap();
        let ids: Vec<(String, String)> = sink
            .records()
            .iter()
            .enumerate()
            .map(|(i, r)| (format!("rec-{i}"), r.clone()))
            .collect();
        let hits = guard.sweep(ids.iter().map(|(a, b)| (a.as_str(), b.as_str())));
        assert!(
            hits.is_empty(),
            "guarded store must sweep clean, got {hits:?}"
        );
    }

    #[test]
    fn store_sweep_detects_a_bypassed_write() {
        // §5.5 test 4: a PAN injected into a durable store out-of-band is caught by the sweep.
        let guard = SinkGuard::strong();
        let mut sink = InMemorySink::new();
        guard.persist(&mut sink, "clean note").unwrap();
        sink.append_raw("leaked 4111111111111111 slipped past the guard"); // bypass
        let ids: Vec<(String, String)> = sink
            .records()
            .iter()
            .enumerate()
            .map(|(i, r)| (format!("rec-{i}"), r.clone()))
            .collect();
        let hits = guard.sweep(ids.iter().map(|(a, b)| (a.as_str(), b.as_str())));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].record_id, "rec-1");
        // The reported sample is redacted — surfacing a hit does not re-leak the PAN.
        assert!(!hits[0].sample.contains("4111"));
        assert!(hits[0].sample.contains("[REDACTED-PAN]"));
    }

    #[test]
    fn clean_text_is_stored_verbatim() {
        let guard = SinkGuard::strong();
        let mut sink = InMemorySink::new();
        let text = "The quarterly settlement report is due Friday.";
        let out = guard.persist(&mut sink, text).unwrap();
        assert_eq!(out.redactions, 0);
        assert_eq!(out.stored, text);
        assert_eq!(sink.records()[0], text);
    }

    #[test]
    fn cde_guard_keeps_non_chd_but_strips_cards() {
        // The CHD-only guard redacts the PAN but leaves an email/secret in place (retain-record,
        // minimize-CHD — §6.4). Contrast with the strong guard which would strip both.
        let guard = SinkGuard::cde();
        let mut sink = InMemorySink::new();
        let out = guard
            .persist(&mut sink, "card 4111111111111111 mailed to a@b.com")
            .unwrap();
        assert!(!out.stored.contains("4111"));
        assert!(
            out.stored.contains("a@b.com"),
            "cde guard must not touch email"
        );
        assert_eq!(out.redactions, 1);
    }

    #[test]
    fn would_redact_reflects_chd_presence() {
        let guard = SinkGuard::cde();
        assert!(guard.would_redact("pan 4111111111111111"));
        assert!(!guard.would_redact("just a note"));
    }

    // ---- FI-01: GuardedSink is the ENFORCED path ----

    /// A sink that records the *exact* bytes it was handed, so a test can prove the raw CHD never
    /// reached it. It has NO public raw-append; the only way to feed it is via `DurableSink::append`,
    /// which `GuardedSink` calls only after redaction.
    #[derive(Default)]
    struct SpySink {
        seen: Vec<String>,
    }
    impl DurableSink for SpySink {
        type Error = std::convert::Infallible;
        fn append(&mut self, guarded: &str) -> Result<(), Self::Error> {
            self.seen.push(guarded.to_string());
            Ok(())
        }
    }

    #[test]
    fn gap_ainxt_compliance_fi01_raw_chd_write_is_redacted_before_the_sink_sees_it() {
        // The load-bearing FI-01 proof: wrap ANY DurableSink in GuardedSink; the ONLY write path is
        // GuardedSink::write, which redacts BEFORE the wrapped sink's append() is ever called. The spy
        // sink captures precisely what bytes it received — asserting the raw PAN was never among them.
        let mut sink = GuardedSink::strong(SpySink::default());

        // Two Luhn-valid PANs (spaced + contiguous) plus a marked secret and a bare account run.
        let raw =
            "settle 4111 1111 1111 1111 and 5500005555555559 password=hunter2 acct 123456789012";
        let out = sink.write(raw).unwrap();

        // The guard redacted on the way in.
        assert!(
            out.redactions >= 3,
            "expected multiple redactions, got {out:?}"
        );
        assert!(!out.stored.contains("4111"));
        assert!(!out.stored.contains("5500005555555559"));
        assert!(!out.stored.contains("hunter2"));

        // The sink itself NEVER saw the raw CHD — this is the structural guarantee.
        let seen = &sink.sink().seen;
        assert_eq!(seen.len(), 1);
        assert!(
            !seen[0].contains("4111"),
            "raw PAN reached the sink: {}",
            seen[0]
        );
        assert!(
            !seen[0].contains("5500005555555559"),
            "raw PAN reached the sink"
        );
        assert!(!seen[0].contains("hunter2"), "raw secret reached the sink");
        assert!(seen[0].contains("[REDACTED-PAN]"));
        assert_eq!(sink.write_count(), 1);
        assert!(sink.redaction_count() >= 3);
    }

    #[test]
    fn gap_ainxt_compliance_fi01_guarded_sink_has_no_raw_append_bypass() {
        // Structural: everything written through the wrapper is guarded, and a post-hoc sweep of the
        // wrapped store finds zero CHD — because there is no constructor or method that appends raw.
        let mut sink = GuardedSink::strong(InMemorySink::new());
        sink.write("charge 4111111111111111 now").unwrap();
        sink.write("an ordinary settlement note").unwrap();
        let stored: Vec<String> = sink.sink().records().to_vec();
        let ids: Vec<(String, String)> = stored
            .iter()
            .enumerate()
            .map(|(i, r)| (format!("rec-{i}"), r.clone()))
            .collect();
        let hits = sink
            .guard()
            .sweep(ids.iter().map(|(a, b)| (a.as_str(), b.as_str())));
        assert!(
            hits.is_empty(),
            "guarded store must sweep clean, got {hits:?}"
        );
    }

    #[test]
    fn gap_ainxt_compliance_fi01_write_failure_does_not_leak_raw_bytes() {
        // A sink whose append always fails (simulating a full disk / cancelled write). Redaction runs
        // FIRST, so even a failed durable write never handled raw CHD — the error propagates and the
        // raw bytes are dropped, never persisted.
        struct FailingSink;
        #[derive(Debug, PartialEq)]
        struct WriteFull;
        impl DurableSink for FailingSink {
            type Error = WriteFull;
            fn append(&mut self, _guarded: &str) -> Result<(), Self::Error> {
                Err(WriteFull)
            }
        }
        let mut sink = GuardedSink::strong(FailingSink);
        let err = sink.write("pan 4111111111111111").unwrap_err();
        assert_eq!(err, WriteFull);
        assert_eq!(
            sink.write_count(),
            0,
            "a failed write is not counted as a success"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn red(text: &str) -> (String, usize) {
        StrongRedactor::new().redact(text)
    }

    // ---- the headline placeholder recall bug this crate fixes ----

    #[test]
    fn spaced_card_that_placeholder_leaks_is_redacted() {
        // 4111 1111 1111 1111 is a valid Visa test PAN; spaced, so NOT a contiguous 12+ run.
        let (out, count) = red("charge card 4111 1111 1111 1111 today");
        assert!(!out.contains("4111"), "spaced card leaked: {out}");
        assert!(out.contains("[REDACTED-PAN]"));
        assert_eq!(count, 1);
    }

    #[test]
    fn hyphenated_card_is_redacted() {
        let (out, _) = red("PAN 4111-1111-1111-1111 end");
        assert!(!out.contains("4111"), "hyphenated card leaked: {out}");
        assert!(out.contains("[REDACTED-PAN]"));
    }

    #[test]
    fn contiguous_card_is_redacted() {
        let (out, _) = red("4111111111111111");
        assert_eq!(out, "[REDACTED-PAN]");
    }

    #[test]
    fn luhn_invalid_16_digits_still_caught_by_safety_net() {
        // Not a valid Luhn number, but a 16-digit contiguous run — the safety net still redacts it.
        let (out, _) = red("1234567890123456");
        assert_eq!(out, "[REDACTED-PAN]");
    }

    #[test]
    fn short_number_is_not_a_card() {
        let (out, count) = red("order 12345 shipped");
        assert_eq!(out, "order 12345 shipped");
        assert_eq!(count, 0);
    }

    #[test]
    fn phone_like_10_digits_is_left_alone_by_default_min() {
        // default long_digit_run_min = 12, so a 10-digit number is not redacted as a run
        // (and is not Luhn-valid at len 10). Prevents over-redaction of ordinary numbers.
        let (out, count) = red("ref 1234567890 ok");
        assert_eq!(out, "ref 1234567890 ok");
        assert_eq!(count, 0);
    }

    // ---- secrets: never ship the value (the sibling DLP bug) ----

    #[test]
    fn marked_secret_value_is_redacted_not_the_marker() {
        let (out, _) = red("password=hunter2");
        assert!(!out.contains("hunter2"), "secret value leaked: {out}");
        assert!(
            out.contains("password="),
            "marker should remain for context"
        );
        assert!(out.contains("[REDACTED-SECRET]"));
    }

    #[test]
    fn quoted_secret_value_is_redacted() {
        let (out, _) = red("api_key = \"s3cr3t-v4lue-xyz\"");
        assert!(
            !out.contains("s3cr3t-v4lue-xyz"),
            "quoted secret leaked: {out}"
        );
        assert!(out.contains("[REDACTED-SECRET]"));
    }

    #[test]
    fn tokenizer_is_not_mistaken_for_token_marker() {
        // "tokenizer" contains "token" but must not be treated as a secret marker.
        let (out, count) = red("the tokenizer runs fast");
        assert_eq!(out, "the tokenizer runs fast");
        assert_eq!(count, 0);
    }

    // ---- prefixed tokens ----

    #[test]
    fn aws_access_key_id_is_redacted() {
        let (out, _) = red("key AKIAIOSFODNN7EXAMPLE here");
        assert!(
            !out.contains("AKIAIOSFODNN7EXAMPLE"),
            "AWS key leaked: {out}"
        );
        assert!(out.contains("[REDACTED-SECRET]"));
    }

    #[test]
    fn openai_style_key_is_redacted() {
        let tok = "sk-abcdef1234567890ABCDEFghij";
        let (out, _) = red(&format!("OPENAI={tok}"));
        assert!(!out.contains(tok), "openai key leaked: {out}");
    }

    #[test]
    fn short_sk_dash_word_is_not_a_false_positive() {
        // "sk-" needs a >=20 char suffix; a short one must not trip.
        let (out, count) = red("sk-1 lift");
        assert_eq!(out, "sk-1 lift");
        assert_eq!(count, 0);
    }

    // ---- cvv ----

    #[test]
    fn cvv_is_context_gated_and_redacted() {
        let (out, _) = red("cvv: 123");
        assert!(out.contains("[REDACTED-CVV]"));
        assert!(!out.contains("123"));
    }

    #[test]
    fn bare_three_digits_without_cvv_context_is_kept() {
        let (out, count) = red("page 123 of the doc");
        assert_eq!(out, "page 123 of the doc");
        assert_eq!(count, 0);
    }

    // ---- emails ----

    #[test]
    fn email_is_redacted() {
        let (out, _) = red("contact alice.smith+tag@example.co.uk please");
        assert!(
            !out.contains("alice.smith+tag@example.co.uk"),
            "email leaked: {out}"
        );
        assert!(out.contains("[REDACTED-EMAIL]"));
    }

    #[test]
    fn at_handle_without_domain_is_not_an_email() {
        let (out, count) = red("ping @alice on chat");
        assert_eq!(out, "ping @alice on chat");
        assert_eq!(count, 0);
    }

    // ---- high entropy ----

    #[test]
    fn high_entropy_token_is_redacted() {
        // A long mixed-class base64-ish blob (not after a marker) — entropy catches it.
        // Length 40 (above the 32-char default min_len) with high mixed entropy —
        // representative of a real opaque credential (e.g. a 40-char API secret).
        let tok = "aB3xK9pQ7mZ2wL5vN8rT4yU6cD8eF1gH2jI4kM7";
        let (out, _) = red(&format!("blob {tok} end"));
        assert!(!out.contains(tok), "high-entropy token leaked: {out}");
    }

    #[test]
    fn filename_with_high_entropy_base_is_not_redacted() {
        // camelCase base >= 32 chars + `.exe`: entropy detector would fire without
        // the extension guard — must NOT be redacted.
        let text = "installer SecureNxtAgentSetupDeploymentTool.exe ready";
        let (out, count) = red(text);
        assert_eq!(out, text, "filename should not be redacted: {out}");
        assert_eq!(count, 0);
    }

    #[test]
    fn path_segment_is_not_redacted() {
        // A long mixed-case token that is a directory segment inside a path (preceded
        // by ``/``) must NOT be redacted even though it satisfies the entropy rule.
        let text = "path=/opt/SecureNxtAgentSetupDeploymentTool/config.json";
        let (out, count) = red(text);
        assert!(
            out.contains("SecureNxtAgentSetupDeploymentTool"),
            "path segment should not be redacted: {out}"
        );
        assert_eq!(count, 0);
    }

    #[test]
    fn ordinary_long_word_is_not_high_entropy() {
        let (out, count) = red("internationalization documentation");
        assert_eq!(out, "internationalization documentation");
        assert_eq!(count, 0);
    }

    // ---- long digit run in filenames (real bug from prod log) ----

    #[test]
    fn timestamp_in_filename_is_not_redacted() {
        let (out, count) = red("- bankmaster_202604281514.sql");
        assert!(out.contains("202604281514"), "timestamp in filename got redacted: {out}");
        assert_eq!(count, 0);
    }

    #[test]
    fn bare_timestamp_filename_is_not_redacted() {
        let (out, count) = red("- 202604281514.sql");
        assert!(out.contains("202604281514"), "bare timestamp filename redacted: {out}");
        assert_eq!(count, 0);
    }

    #[test]
    fn timestamp_in_path_segment_is_not_redacted() {
        let (out, count) = red("path=/logs/202604281514/access.log");
        assert!(out.contains("202604281514"));
        assert_eq!(count, 0);
    }

    #[test]
    fn long_digit_run_in_prose_is_still_redacted() {
        let (out, _) = red("Account number 202604281514 was flagged");
        assert!(!out.contains("202604281514"), "prose digit run leaked: {out}");
    }

    #[test]
    fn ordinary_prose_is_untouched() {
        let text = "The quarterly settlement report is due on Friday afternoon.";
        let (out, count) = red(text);
        assert_eq!(out, text);
        assert_eq!(count, 0);
    }

    // ---- natural-language secret disclosure ----

    #[test]
    fn natural_language_password_disclosure_is_redacted() {
        let (out, _) = red("My password is Test@12345");
        assert!(!out.contains("Test@12345"), "password value leaked: {out}");
        assert!(out.contains("[REDACTED-SECRET]"), "expected redaction: {out}");
    }

    #[test]
    fn natural_language_password_with_trailing_period_is_redacted() {
        let (out, _) = red("My password is Test@12345.");
        assert!(!out.contains("Test@12345"));
        assert!(out.ends_with("."));
    }

    #[test]
    fn natural_language_password_prose_is_not_redacted() {
        let (out, count) = red("a strong password is important for security");
        assert_eq!(out, "a strong password is important for security", "prose was mangled: {out}");
        assert_eq!(count, 0);
    }

    #[test]
    fn natural_language_token_disclosure_is_redacted() {
        let (out, _) = red("my token is Test@12345");
        assert!(!out.contains("Test@12345"));
        assert!(out.contains("[REDACTED-SECRET]"));
    }

    // ---- passkey / passphrase / PIN / credential (extended MARKERS) ----

    #[test]
    fn passkey_disclosure_is_redacted() {
        let (out, _) = red("My passkey is Test@12345");
        assert!(!out.contains("Test@12345"), "passkey value leaked: {out}");
    }

    #[test]
    fn passphrase_disclosure_is_redacted() {
        let (out, _) = red("My passphrase is Test@12345");
        assert!(!out.contains("Test@12345"), "passphrase value leaked: {out}");
    }

    #[test]
    fn credential_disclosure_is_redacted() {
        let (out, _) = red("my credential = Test@12345");
        assert!(!out.contains("Test@12345"));
    }

    // ---- value-based detector (typos + unenumerated synonyms) ----

    #[test]
    fn typo_paaawd_value_is_redacted_via_context() {
        let (out, _) = red("My paaawd is Test@12345");
        assert!(!out.contains("Test@12345"), "paaawd typo leaked value: {out}");
    }

    #[test]
    fn credential_shaped_value_near_key_word_is_redacted() {
        // `keystore` starts with root `key` → credential context signal fires
        // even without `=`/`:`/`is`.
        let (out, _) = red("keystore-pw Test@12345 today");
        assert!(!out.contains("Test@12345"), "credential-context leak: {out}");
    }

    #[test]
    fn credential_shaped_value_without_context_is_not_redacted() {
        // "tag" doesn't start with any credential root → V1.2@rc1 stays.
        let (out, count) = red("The version tag is V1.2@rc1");
        assert!(out.contains("V1.2@rc1"), "false positive: {out}");
        assert_eq!(count, 0);
    }

    #[test]
    fn credential_shaped_short_value_is_not_redacted() {
        let (out, count) = red("password Ab1@2");
        assert!(out.contains("Ab1@2"));
        assert_eq!(count, 0);
    }

    #[test]
    fn credential_shaped_two_class_value_is_not_redacted() {
        let (out, count) = red("password Something");
        assert!(out.contains("Something"), "prose Word blocked: {out}");
        assert_eq!(count, 0);
    }

    #[test]
    fn natural_language_arrow_separator_is_redacted() {
        let (out, _) = red("password -> Test@12345");
        assert!(!out.contains("Test@12345"));
    }

    #[test]
    fn natural_language_short_value_is_not_redacted() {
        let (out, count) = red("password is short");
        assert_eq!(out, "password is short");
        assert_eq!(count, 0);
    }

    #[test]
    fn assignment_form_still_accepts_short_values() {
        let (out, _) = red("password=abc");
        assert!(!out.contains("abc"));
    }

    // ---- utf-8 char-boundary regression tests ----

    #[test]
    fn utf8_arrow_in_context_window_does_not_panic() {
        // `→` is 3-byte U+2192. Prior code panicked when the 40-char
        // context window landed inside it.
        let (_out, _) = red("bytes=100→200 password Test@12345");
    }

    #[test]
    fn utf8_devanagari_in_input_does_not_panic() {
        // Hindi text uses 3-byte codepoints throughout.
        let (_out, _) = red("क ख ग password Test@12345 घ ङ");
    }

    #[test]
    fn utf8_tamil_in_input_does_not_panic() {
        // Tamil text uses 3-byte codepoints.
        let (_out, _) = red("எழுத்து password Test@12345 வாய்");
    }

    #[test]
    fn utf8_emoji_in_input_does_not_panic() {
        // 4-byte codepoints (astral plane).
        let (_out, _) = red("🔑 password Test@12345 🔐");
    }

    #[test]
    fn utf8_value_terminated_by_multibyte_char_does_not_panic() {
        // Prior loop stepped past `→` when scanning the value.
        let (_out, _) = red("My password is Test@12345→continuation");
    }

    #[test]
    fn utf8_secret_disclosure_still_redacts_across_multibyte_prose() {
        // Multibyte chars around the marker must not defeat detection.
        let (out, _) = red("नमस्ते — My password is Test@12345.");
        assert!(!out.contains("Test@12345"), "utf-8 prose broke redaction: {out}");
    }

    // ---- overlap / integrity ----

    #[test]
    fn overlapping_detectors_do_not_double_count_or_corrupt() {
        // A card that is also caught by the long-run safety net — must yield exactly one span,
        // and the output must be valid (no interleaved/duplicated labels).
        let (out, count) = red("4111111111111111");
        assert_eq!(out, "[REDACTED-PAN]");
        assert_eq!(count, 1);
    }

    #[test]
    fn multiple_secrets_in_one_line_all_redacted() {
        let (out, count) = red("password=hunter2 and cvv: 999 and 4111 1111 1111 1111");
        assert!(!out.contains("hunter2"));
        assert!(!out.contains("999"));
        assert!(!out.contains("4111"));
        assert!(count >= 3, "expected >=3 redactions, got {count}: {out}");
    }

    #[test]
    fn config_can_disable_a_detector() {
        let cfg = RedactorConfig {
            emails: false,
            ..RedactorConfig::default()
        };
        let (out, count) = StrongRedactor::with_config(cfg).redact("mail a@b.com");
        assert_eq!(out, "mail a@b.com");
        assert_eq!(count, 0);
    }

    #[test]
    fn unicode_text_is_byte_safe() {
        // multibyte chars around a secret must not panic or split a char boundary
        let (out, _) = red("café password=münchen123 déjà");
        assert!(out.starts_with("café "));
        assert!(out.contains("déjà"));
        assert!(!out.contains("münchen123"));
    }

    #[test]
    fn trait_object_scan_works_in_all_directions() {
        let g: &dyn ComplianceGate = &StrongRedactor::new();
        for dir in [
            Direction::Input,
            Direction::ToolArgs,
            Direction::ToolResult,
            Direction::Output,
        ] {
            let r = g.scan("password=hunter2", dir);
            assert!(!r.text.contains("hunter2"));
            assert_eq!(r.redactions, 1);
        }
    }

    #[test]
    fn empty_and_all_redacted_edge_cases() {
        assert_eq!(red(""), (String::new(), 0));
        let (out, count) = red("4111111111111111");
        assert_eq!(count, 1);
        assert_eq!(out, "[REDACTED-PAN]");
    }

    #[test]
    fn luhn_matches_known_vectors() {
        // Valid test PANs (Luhn-valid); values are industry-published test numbers.
        for pan in ["4111111111111111", "5500005555555559", "340000000000009"] {
            let digits: Vec<u8> = pan.bytes().map(|b| b - b'0').collect();
            assert!(luhn_valid(&digits), "{pan} should be Luhn-valid");
        }
        // Corrupt one digit → invalid.
        let bad: Vec<u8> = "4111111111111112".bytes().map(|b| b - b'0').collect();
        assert!(!luhn_valid(&bad));
    }
}
