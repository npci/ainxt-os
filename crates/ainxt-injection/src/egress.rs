// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Egress control / outbound DLP (ADR-009, gap T).
//!
//! Injection defense stops malicious instructions *entering*; egress DLP is the mirror — it stops
//! secrets/credentials *leaving* on outbound tool arguments / connector payloads, and enforces a
//! destination allow-list so a tainted or coaxed agent cannot exfiltrate to an attacker endpoint.
//! (The always-on PCI/DSS compliance gate covers PAN/PII; this helper focuses on *secrets* and
//! *destinations*, the exfiltration surface the compliance gate does not own.)
//!
//! Deterministic: entropy is computed from byte frequencies, no clock/rng. Redaction returns a copy
//! with secret spans replaced by `[REDACTED:{category}]`; the original is never mutated in place.

/// A single outbound finding.
#[derive(Debug, Clone, PartialEq)]
pub struct EgressFinding {
    /// Taxonomy label, e.g. `"private-key"`, `"aws-access-key"`, `"disallowed-destination"`.
    pub category: &'static str,
    /// The offending fragment (already truncated for a secret so the finding log stays clean).
    pub evidence: String,
}

/// Policy for outbound scanning. Fully **serde-deserializable** so a deployment configures egress
/// control from its config layer (the `[injection.egress]` table via
/// [`InjectionDefenseConfig`](crate::InjectionDefenseConfig)) rather than a hardcoded default.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct EgressPolicy {
    /// Destination domain allow-list (suffix match, e.g. `"example.org"`). When non-empty, any
    /// destination to a domain NOT on the list is a `disallowed-destination` finding.
    pub allowed_domains: Vec<String>,
    /// Explicit destination deny-list (suffix match). Always a `disallowed-destination` finding,
    /// even when the allow-list is empty — the opt-in half of destination control that does not
    /// require enumerating every legitimate domain first.
    pub denied_domains: Vec<String>,
    /// Treat any detected secret as blocking (vs. audit+redact).
    pub block_on_secret: bool,
    /// Minimum Shannon entropy (bits/char) for a long alnum token to be a `high-entropy-secret`.
    pub min_entropy_bits: f32,
    /// Minimum length for the generic high-entropy heuristic.
    pub min_secret_len: usize,
    /// Destination-risk score at/above which a destination is reported as `risky-destination`
    /// **even with an empty allow-list**. This is what makes egress destination control effective
    /// out of the box: a deployment that has not enumerated its allow-list is still protected
    /// against the known exfiltration-sink classes (webhook catchers, paste bins, onion services,
    /// punycode look-alikes, …). Default `0.5`.
    pub destination_risk_threshold: f32,
    /// Whether a `risky-destination` finding blocks (fail-closed) or is audit-only. Default `true`:
    /// posting data to an exfiltration sink is never a legitimate agent action.
    pub block_on_risky_destination: bool,
    /// Deployment-supplied additional high-risk destination suffixes (weight `0.6`), e.g. sinks the
    /// deployment's own threat intel knows about. Keeps the sink taxonomy config-extensible instead
    /// of a frozen in-source list.
    pub risky_domains: Vec<String>,
    /// Deployment-supplied JSON/argument keys whose value is a destination (in addition to the
    /// built-in `url`/`host`/`endpoint`/… set), e.g. `"sftp_target"`.
    pub destination_keys: Vec<String>,
}

impl Default for EgressPolicy {
    fn default() -> Self {
        EgressPolicy {
            allowed_domains: Vec::new(),
            denied_domains: Vec::new(),
            block_on_secret: true,
            min_entropy_bits: 3.5,
            min_secret_len: 24,
            destination_risk_threshold: 0.5,
            block_on_risky_destination: true,
            risky_domains: Vec::new(),
            destination_keys: Vec::new(),
        }
    }
}

impl EgressPolicy {
    /// Batteries-included preset: the deployment's own domains allow-listed, everything else
    /// reported, and exfiltration sinks blocked. One call instead of hand-assembling the policy.
    pub fn recommended(allowed_domains: impl IntoIterator<Item = String>) -> Self {
        EgressPolicy {
            allowed_domains: allowed_domains.into_iter().collect(),
            ..Default::default()
        }
    }

    /// Builder: allow-list these destination domains (suffix match).
    pub fn with_allowed_domains(mut self, domains: impl IntoIterator<Item = String>) -> Self {
        self.allowed_domains = domains.into_iter().collect();
        self
    }

    /// Builder: deny-list these destination domains (suffix match), independent of the allow-list.
    pub fn with_denied_domains(mut self, domains: impl IntoIterator<Item = String>) -> Self {
        self.denied_domains = domains.into_iter().collect();
        self
    }
}

/// Categories that describe a DESTINATION rather than a secret.
const DESTINATION_CATEGORIES: &[&str] = &["disallowed-destination", "risky-destination"];

fn is_destination_category(cat: &str) -> bool {
    DESTINATION_CATEGORIES.contains(&cat)
}

/// Result of scanning one outbound payload.
#[derive(Debug, Clone, PartialEq)]
pub struct EgressAssessment {
    /// Every finding, in scan order.
    pub findings: Vec<EgressFinding>,
    /// The payload with secret spans redacted (destinations are NOT redacted, only reported).
    pub redacted: String,
}

impl EgressAssessment {
    /// Any secret category present (destination findings are not secrets).
    pub fn has_secret(&self) -> bool {
        self.findings
            .iter()
            .any(|f| !is_destination_category(f.category))
    }
    /// Any allow-list / deny-list destination violation present.
    pub fn has_disallowed_destination(&self) -> bool {
        self.findings
            .iter()
            .any(|f| f.category == "disallowed-destination")
    }
    /// Any destination whose intrinsic RISK score crossed the policy threshold (exfiltration sink,
    /// onion service, punycode look-alike, …) — independent of the allow-list.
    pub fn has_risky_destination(&self) -> bool {
        self.findings
            .iter()
            .any(|f| f.category == "risky-destination")
    }
    /// Whether this payload should be blocked under `policy`.
    pub fn is_blocked(&self, policy: &EgressPolicy) -> bool {
        self.has_disallowed_destination()
            || (policy.block_on_risky_destination && self.has_risky_destination())
            || (policy.block_on_secret && self.has_secret())
    }
}

/// The enforcement decision for one outbound payload — the clean seam the runtime egress guard
/// calls at its outbound tool-argument / connector-payload point (fail-closed by construction).
#[derive(Debug, Clone, PartialEq)]
pub enum EgressDecision {
    /// Nothing found — forward the payload unchanged.
    Allow,
    /// Secrets found but the policy is audit-mode (`block_on_secret = false`) and there is no
    /// disallowed destination: forward the REDACTED payload; `findings` is kept for the audit log.
    Redact {
        sanitized: String,
        findings: Vec<EgressFinding>,
    },
    /// Fail-closed: a disallowed destination, or a secret under `block_on_secret`. Do NOT send.
    Block {
        reason: String,
        findings: Vec<EgressFinding>,
    },
}

impl EgressDecision {
    /// Whether egress must be refused.
    pub fn is_blocked(&self) -> bool {
        matches!(self, EgressDecision::Block { .. })
    }
    /// The payload to actually send when not blocked (redacted copy in audit mode, else unchanged).
    /// Returns `None` when blocked.
    pub fn payload_to_send<'a>(&'a self, original: &'a str) -> Option<&'a str> {
        match self {
            EgressDecision::Allow => Some(original),
            EgressDecision::Redact { sanitized, .. } => Some(sanitized),
            EgressDecision::Block { .. } => None,
        }
    }
    /// Findings recorded for the audit log regardless of decision.
    pub fn findings(&self) -> &[EgressFinding] {
        match self {
            EgressDecision::Allow => &[],
            EgressDecision::Redact { findings, .. } | EgressDecision::Block { findings, .. } => {
                findings
            }
        }
    }
}

fn block_reason(findings: &[EgressFinding]) -> String {
    let mut cats: Vec<&str> = findings.iter().map(|f| f.category).collect();
    cats.sort_unstable();
    cats.dedup();
    format!("outbound blocked: {}", cats.join(", "))
}

/// Enforcement entrypoint: scan `payload` under `policy` and return the action to take. This is the
/// single call the runtime egress guard should make on every outbound tool argument / connector
/// payload (destination allow-listing + provider-secret taxonomy in one fail-closed decision) — it
/// covers exfiltration surfaces the always-on PCI/DSS compliance gate does not own (arbitrary
/// destinations, non-PII secrets like private keys / JWTs / provider API keys).
pub fn guard_egress(payload: &str, policy: &EgressPolicy) -> EgressDecision {
    let a = scan_egress(payload, policy);
    if a.findings.is_empty() {
        return EgressDecision::Allow;
    }
    if a.is_blocked(policy) {
        return EgressDecision::Block {
            reason: block_reason(&a.findings),
            findings: a.findings,
        };
    }
    // Secrets present but audit-mode and no disallowed destination → forward redacted.
    EgressDecision::Redact {
        sanitized: a.redacted,
        findings: a.findings,
    }
}

/// Taint-aware enforcement for the injection→exfiltration attack chain. When the turn is `tainted`
/// (untrusted content tripped the injection detector this turn), egress is treated fail-closed: ANY
/// finding — a secret even under audit mode, or any destination when an allow-list is set — blocks,
/// because a tainted turn attempting outbound traffic is the exfiltration half of the attack. On a
/// non-tainted turn it behaves exactly like [`guard_egress`].
pub fn guard_egress_for_turn(
    payload: &str,
    policy: &EgressPolicy,
    tainted: bool,
) -> EgressDecision {
    if !tainted {
        return guard_egress(payload, policy);
    }
    let a = scan_egress(payload, policy);
    if a.findings.is_empty() {
        return EgressDecision::Allow;
    }
    EgressDecision::Block {
        reason: format!("{} (tainted turn — fail-closed)", block_reason(&a.findings)),
        findings: a.findings,
    }
}

/// Fail-closed taint gate for tool dispatch (ADR-009). On a turn TAINTED by suspected injection in
/// untrusted content, a tool is safe to run only when it is **known** to be neither side-effecting
/// nor egress-capable — i.e. `side_effecting == Some(false) && egress == Some(false)`. Any other
/// combination gates (blocks) the tool. The critical property is the treatment of **unknown**
/// classification (`None`): an unclassified tool is gated, so injection-defense coverage no longer
/// silently depends on the registry having classified every tool (a tool nobody remembered to tag
/// would otherwise slip an exfiltration/side-effect through on a poisoned turn). Returns `true` when
/// the tool must be blocked.
///
/// Callers pass the registry's classification for the tool being dispatched; the two-argument shape
/// mirrors the runtime's `tools.is_side_effecting(name)` / `tools.egress_of(name)` accessors so it is
/// a drop-in replacement for the inline `== Some(true)` check (which under-covered unknown tools).
pub fn gate_tool_on_taint(side_effecting: Option<bool>, egress: Option<bool>) -> bool {
    !(side_effecting == Some(false) && egress == Some(false))
}

/// Turn-aware drop-in for the runtime's inline taint check. On a NON-tainted turn nothing is gated
/// (`false`); on a TAINTED turn it defers to [`gate_tool_on_taint`] — so an UNCLASSIFIED (`None`)
/// tool is fail-closed (blocked) instead of slipping through the old
/// `is_side_effecting(name) == Some(true) || egress_of(name) == Some(true)` check, which only gated
/// tools KNOWN to be dangerous and silently let an untagged tool run on a poisoned turn. This is the
/// exact three-argument shape the reserved runtime call-site should adopt. Returns `true` = block.
pub fn gate_tool_on_taint_for_turn(
    tainted: bool,
    side_effecting: Option<bool>,
    egress: Option<bool>,
) -> bool {
    tainted && gate_tool_on_taint(side_effecting, egress)
}

/// Byte-range of a detected secret (for redaction) plus its category.
struct SecretSpan {
    start: usize,
    end: usize,
    category: &'static str,
}

/// Scan `text` for outbound secrets and disallowed destinations under `policy`.
pub fn scan_egress(text: &str, policy: &EgressPolicy) -> EgressAssessment {
    let mut spans: Vec<SecretSpan> = Vec::new();
    detect_private_key_block(text, &mut spans);
    detect_prefixed_secrets(text, &mut spans);
    detect_jwt(text, &mut spans);
    detect_high_entropy(text, policy, &mut spans);

    // Sort + merge overlapping spans so redaction is well-formed. When spans overlap, keep the
    // MOST SPECIFIC category (a JWT/PEM/provider-key label wins over the generic high-entropy one).
    spans.sort_by_key(|s| (s.start, s.end));
    let mut merged: Vec<SecretSpan> = Vec::new();
    for s in spans {
        match merged.last_mut() {
            Some(prev) if s.start < prev.end => {
                if s.end > prev.end {
                    prev.end = s.end;
                }
                if category_priority(s.category) > category_priority(prev.category) {
                    prev.category = s.category;
                }
            }
            _ => merged.push(s),
        }
    }

    let mut findings: Vec<EgressFinding> = merged
        .iter()
        .map(|s| EgressFinding {
            category: s.category,
            evidence: truncate_secret(&text[s.start..s.end]),
        })
        .collect();

    // Redact secret spans (build once, back-to-front so byte offsets stay valid).
    let mut redacted = text.to_string();
    for s in merged.iter().rev() {
        redacted.replace_range(s.start..s.end, &format!("[REDACTED:{}]", s.category));
    }

    // Destinations (reported, not redacted). Two independent controls:
    //   * ALLOW/DENY-LIST — configured domain policy (`disallowed-destination`);
    //   * INTRINSIC RISK  — a scored classification of the destination itself, effective even when
    //     no allow-list is configured (`risky-destination`), so destination control is not dead in a
    //     deployment that has not enumerated every legitimate domain.
    let mut seen: Vec<String> = Vec::new();
    for dest in extract_destinations(text, policy) {
        if seen.contains(&dest.raw) {
            continue;
        }
        seen.push(dest.raw.clone());
        let denied = domain_allowed(&dest.domain, &policy.denied_domains);
        let unlisted = !policy.allowed_domains.is_empty()
            && !domain_allowed(&dest.domain, &policy.allowed_domains);
        if denied || unlisted {
            findings.push(EgressFinding {
                category: "disallowed-destination",
                evidence: dest.raw.clone(),
            });
            continue;
        }
        let risk = destination_risk(&dest, policy);
        if risk.score >= policy.destination_risk_threshold {
            findings.push(EgressFinding {
                category: "risky-destination",
                evidence: format!("{} [{}]", dest.raw, risk.reasons.join("+")),
            });
        }
    }

    EgressAssessment { findings, redacted }
}

/// The scored risk of one outbound destination (design T). Deterministic: a weighted taxonomy of
/// exfiltration-sink classes, per-category max summed and clamped — the same scoring shape the
/// injection detector uses, not a fixed substring verdict.
#[derive(Debug, Clone, PartialEq)]
pub struct DestinationRisk {
    pub score: f32,
    pub reasons: Vec<String>,
}

/// Known exfiltration-sink suffixes by class. Deliberately *classes* (webhook catchers, paste bins,
/// tunnels, shorteners, dynamic DNS) rather than a blocklist of individual attacker domains, which
/// would be obsolete on arrival; `EgressPolicy::risky_domains` extends this from config.
const WEBHOOK_CATCHERS: &[&str] = &[
    "webhook.site",
    "requestbin.com",
    "requestbin.net",
    "pipedream.net",
    "beeceptor.com",
    "requestcatcher.com",
    "hookb.in",
    "typedwebhook.tools",
    "interact.sh",
    "oastify.com",
    "burpcollaborator.net",
    "dnslog.cn",
    "canarytokens.com",
    "mockbin.io",
];
const PASTE_SINKS: &[&str] = &[
    "pastebin.com",
    "paste.ee",
    "hastebin.com",
    "ghostbin.com",
    "termbin.com",
    "transfer.sh",
    "file.io",
    "0x0.st",
    "anonfiles.com",
    "gofile.io",
    "controlc.com",
    "dpaste.org",
];
const TUNNELS_AND_DDNS: &[&str] = &[
    "ngrok.io",
    "ngrok-free.app",
    "trycloudflare.com",
    "loca.lt",
    "localtunnel.me",
    "serveo.net",
    "duckdns.org",
    "no-ip.com",
    "hopto.org",
    "ddns.net",
    "zapto.org",
];
const SHORTENERS: &[&str] = &[
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "cutt.ly",
    "rb.gy",
    "shorturl.at",
    "rebrand.ly",
];

fn suffix_hit(domain: &str, list: &[&str]) -> bool {
    let d = domain.trim_end_matches('.').to_lowercase();
    list.iter()
        .any(|s| d == *s || d.ends_with(&format!(".{s}")))
}

fn is_ip_literal(host: &str) -> bool {
    let h = host.trim_start_matches('[').trim_end_matches(']');
    if h.contains(':') && h.chars().all(|c| c.is_ascii_hexdigit() || c == ':') {
        return true; // IPv6 literal
    }
    let parts: Vec<&str> = h.split('.').collect();
    parts.len() == 4
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.len() <= 3 && p.bytes().all(|b| b.is_ascii_digit()))
}

/// Score a destination's intrinsic exfiltration risk.
pub fn destination_risk(dest: &Destination, policy: &EgressPolicy) -> DestinationRisk {
    let mut signals: Vec<(&'static str, f32, String)> = Vec::new();
    let d = dest.domain.to_lowercase();

    if suffix_hit(&d, WEBHOOK_CATCHERS) {
        signals.push(("sink", 0.7, "webhook-catcher".into()));
    }
    if suffix_hit(&d, PASTE_SINKS) {
        signals.push(("sink", 0.6, "paste-sink".into()));
    }
    if d.ends_with(".onion") {
        signals.push(("anonymity", 0.7, "onion-service".into()));
    }
    if suffix_hit(&d, TUNNELS_AND_DDNS) {
        signals.push(("infrastructure", 0.4, "tunnel-or-dynamic-dns".into()));
    }
    if suffix_hit(&d, SHORTENERS) {
        signals.push(("obfuscation", 0.45, "url-shortener".into()));
    }
    if d.split('.').any(|l| l.starts_with("xn--")) {
        signals.push(("obfuscation", 0.5, "punycode-idn-host".into()));
    }
    if is_ip_literal(&d) {
        signals.push(("infrastructure", 0.35, "ip-literal-endpoint".into()));
    }
    if dest.has_userinfo {
        signals.push(("obfuscation", 0.5, "userinfo-obfuscated-url".into()));
    }
    if let Some(scheme) = &dest.scheme {
        if !matches!(scheme.as_str(), "http" | "https" | "mailto") {
            signals.push(("scheme", 0.4, format!("non-web-scheme:{scheme}")));
        }
    }
    if !policy.risky_domains.is_empty() && domain_allowed(&d, &policy.risky_domains) {
        signals.push(("policy", 0.6, "deployment-flagged-destination".into()));
    }

    let mut per: std::collections::BTreeMap<&'static str, f32> = std::collections::BTreeMap::new();
    for (cat, w, _) in &signals {
        let e = per.entry(*cat).or_insert(0.0);
        if *w > *e {
            *e = *w;
        }
    }
    DestinationRisk {
        score: per.values().sum::<f32>().min(1.0),
        reasons: signals.into_iter().map(|(_, _, r)| r).collect(),
    }
}

/// Specificity ranking: a concrete secret format outranks the generic high-entropy heuristic.
fn category_priority(cat: &str) -> u8 {
    match cat {
        "private-key" => 9,
        "jwt" => 8,
        "aws-access-key" => 7,
        "api-key" => 6,
        "github-token" | "slack-token" | "google-api-key" => 5,
        "bearer-token" => 4,
        "high-entropy-secret" => 1,
        _ => 0,
    }
}

fn truncate_secret(s: &str) -> String {
    let head: String = s.chars().take(6).collect();
    format!("{head}… ({} chars)", s.chars().count())
}

// ---------------- secret detectors ----------------

fn detect_private_key_block(text: &str, out: &mut Vec<SecretSpan>) {
    // PEM: from "-----BEGIN" through the trailing dashes of the "-----END ...-----" footer.
    let mut search = 0;
    while let Some(rel) = text[search..].find("-----BEGIN") {
        let start = search + rel;
        // Locate the END header, then the closing "-----" that terminates the footer line.
        let end = text[start..]
            .find("-----END")
            .and_then(|erel| {
                let footer = start + erel + "-----END".len();
                text[footer..].find("-----").map(|c| footer + c + 5)
            })
            .unwrap_or(text.len());
        out.push(SecretSpan {
            start,
            end,
            category: "private-key",
        });
        if end <= start {
            break;
        }
        search = end;
    }
}

/// Prefixed provider secrets: AWS access keys, OpenAI-style `sk-…`, GitHub `ghp_…`, Slack `xoxb-…`,
/// and `Bearer <token>` / Fernet-style keys.
fn detect_prefixed_secrets(text: &str, out: &mut Vec<SecretSpan>) {
    // (prefix, min_token_len_after_prefix, category)
    const PREFIXES: &[(&str, usize, &str)] = &[
        ("AKIA", 16, "aws-access-key"),
        ("ASIA", 16, "aws-access-key"),
        ("sk-", 20, "api-key"),
        ("ghp_", 20, "github-token"),
        ("gho_", 20, "github-token"),
        ("xoxb-", 10, "slack-token"),
        ("xoxp-", 10, "slack-token"),
        ("AIza", 30, "google-api-key"),
    ];
    let bytes = text.as_bytes();
    for &(prefix, min_after, cat) in PREFIXES {
        let mut from = 0;
        while let Some(rel) = text[from..].find(prefix) {
            let start = from + rel;
            let mut end = start + prefix.len();
            while end < bytes.len() && is_secret_char(bytes[end]) {
                end += 1;
            }
            if end - (start + prefix.len()) >= min_after {
                out.push(SecretSpan {
                    start,
                    end,
                    category: cat,
                });
            }
            from = start + prefix.len();
        }
    }
    // Bearer tokens
    let lower = text.to_lowercase();
    let mut from = 0;
    while let Some(rel) = lower[from..].find("bearer ") {
        let tok_start = from + rel + "bearer ".len();
        let mut end = tok_start;
        while end < bytes.len() && is_secret_char(bytes[end]) {
            end += 1;
        }
        if end - tok_start >= 16 {
            out.push(SecretSpan {
                start: tok_start,
                end,
                category: "bearer-token",
            });
        }
        from = tok_start;
    }
}

/// JWT: three base64url segments separated by dots, each reasonably long.
fn detect_jwt(text: &str, out: &mut Vec<SecretSpan>) {
    for (start, tok) in token_spans(text, |c| {
        (c.is_ascii() && is_secret_char(c as u8)) || c == '.'
    }) {
        let parts: Vec<&str> = tok.split('.').collect();
        if parts.len() == 3
            && parts[0].len() >= 10
            && parts[1].len() >= 10
            && parts[2].len() >= 10
            && parts.iter().all(|p| p.bytes().all(is_base64url_char))
        {
            out.push(SecretSpan {
                start,
                end: start + tok.len(),
                category: "jwt",
            });
        }
    }
}

/// Generic high-entropy alnum blob (catches unknown-format keys).
fn detect_high_entropy(text: &str, policy: &EgressPolicy, out: &mut Vec<SecretSpan>) {
    for (start, tok) in token_spans(text, |c| c.is_ascii() && is_secret_char(c as u8)) {
        if tok.len() < policy.min_secret_len {
            continue;
        }
        let has_lower = tok.bytes().any(|b| b.is_ascii_lowercase());
        let has_upper = tok.bytes().any(|b| b.is_ascii_uppercase());
        let has_digit = tok.bytes().any(|b| b.is_ascii_digit());
        // Require character-class mix so we don't flag long lowercase words as secrets.
        if !(has_digit && (has_lower || has_upper)) {
            continue;
        }
        // Character-class filter: a pure-hexadecimal token (only [0-9a-fA-F]) is a hash / content
        // digest / UUID-without-dashes / commit-sha / hex id — NOT a credential — even at high
        // entropy. Requiring at least one alphabetic char OUTSIDE the hex alphabet (g-z / G-Z)
        // suppresses that dominant false-positive class. Real credentials in an unknown format still
        // carry non-hex letters; formatted provider secrets (sk-/AKIA/ghp_/JWT/PEM) are caught by
        // their specific detectors regardless of this generic heuristic.
        let has_non_hex_alpha = tok
            .bytes()
            .any(|b| b.is_ascii_alphabetic() && !b.is_ascii_hexdigit());
        if !has_non_hex_alpha {
            continue;
        }
        if shannon_bits_per_char(tok) >= policy.min_entropy_bits {
            out.push(SecretSpan {
                start,
                end: start + tok.len(),
                category: "high-entropy-secret",
            });
        }
    }
}

fn is_secret_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'+' || b == b'/' || b == b'='
}

fn is_base64url_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

/// Maximal token spans (byte offset + slice) whose chars satisfy `pred`.
fn token_spans(s: &str, pred: impl Fn(char) -> bool) -> Vec<(usize, &str)> {
    let mut spans = Vec::new();
    let mut start: Option<usize> = None;
    for (i, ch) in s.char_indices() {
        if pred(ch) {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(st) = start.take() {
            spans.push((st, &s[st..i]));
        }
    }
    if let Some(st) = start {
        spans.push((st, &s[st..]));
    }
    spans
}

fn shannon_bits_per_char(s: &str) -> f32 {
    let mut freq = [0usize; 256];
    let mut n = 0usize;
    for b in s.bytes() {
        freq[b as usize] += 1;
        n += 1;
    }
    if n == 0 {
        return 0.0;
    }
    let nf = n as f32;
    let mut h = 0.0f32;
    for &c in freq.iter() {
        if c > 0 {
            let p = c as f32 / nf;
            h -= p * p.log2();
        }
    }
    h
}

// ---------------- destinations ----------------

/// One outbound destination found in a payload.
#[derive(Debug, Clone, PartialEq)]
pub struct Destination {
    /// The raw fragment as it appeared (for the finding evidence).
    pub raw: String,
    /// The host / email domain, lower-cased, without port or userinfo.
    pub domain: String,
    /// URI scheme when the destination was written as `scheme://…` (`None` for emails and bare
    /// hosts).
    pub scheme: Option<String>,
    /// The URL carried `user@` userinfo — the classic `https://example.org@evil.com` disguise.
    pub has_userinfo: bool,
}

/// JSON / argument keys whose value is an outbound destination. A tool argument such as
/// `{"host":"attacker.com","port":443}` carries no scheme and no `@`, so scheme-only extraction
/// missed it entirely and the allow-list never applied.
const DESTINATION_KEYS: &[&str] = &[
    "url",
    "uri",
    "href",
    "host",
    "hostname",
    "endpoint",
    "server",
    "domain",
    "target",
    "dest",
    "destination",
    "recipient",
    "webhook",
    "webhook_url",
    "callback",
    "callback_url",
    "addr",
    "address",
    "sink",
    "upload_url",
    "remote",
    "to",
    "forward_to",
    "post_to",
    "base_url",
];

/// File extensions that look like a TLD in a bare token but are not destinations.
const NON_TLD_SUFFIXES: &[&str] = &[
    "pdf", "txt", "json", "csv", "md", "png", "jpg", "jpeg", "gif", "svg", "html", "htm", "xml",
    "yaml", "yml", "log", "zip", "gz", "tar", "docx", "xlsx", "pptx", "rs", "py", "js", "ts",
    "tsx", "jsx", "sh", "sql", "toml", "conf", "ini", "exe", "dll", "so", "class", "jar", "java",
    "go", "rb", "php", "css", "lock", "bak", "tmp",
];

fn strip_port(host: &str) -> &str {
    if host.starts_with('[') {
        // IPv6 literal `[::1]:8080`
        return host
            .split(']')
            .next()
            .unwrap_or(host)
            .trim_start_matches('[');
    }
    match host.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => host,
    }
}

/// A token that plausibly names a host: `label(.label)+` with an alphabetic TLD that is not a file
/// extension, or an IP literal.
fn plausible_host(tok: &str) -> bool {
    let h = strip_port(tok.trim_matches(|c: char| !c.is_alphanumeric() && c != '[' && c != ']'));
    if h.is_empty() {
        return false;
    }
    if is_ip_literal(h) {
        return true;
    }
    let labels: Vec<&str> = h.split('.').collect();
    if labels.len() < 2 || labels.iter().any(|l| l.is_empty()) {
        return false;
    }
    let tld = labels[labels.len() - 1].to_lowercase();
    if tld.len() < 2 || !tld.chars().all(|c| c.is_ascii_alphabetic()) {
        return false;
    }
    if NON_TLD_SUFFIXES.contains(&tld.as_str()) {
        return false;
    }
    labels.iter().all(|l| {
        l.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    })
}

fn push_host_destination(
    raw: &str,
    host: &str,
    scheme: Option<String>,
    out: &mut Vec<Destination>,
) {
    let (userinfo, hostpart) = match host.rsplit_once('@') {
        Some((_, h)) => (true, h),
        None => (false, host),
    };
    let domain = strip_port(hostpart).trim_end_matches('.').to_lowercase();
    if domain.is_empty() {
        return;
    }
    out.push(Destination {
        raw: raw.to_string(),
        domain,
        scheme,
        has_userinfo: userinfo,
    });
}

fn is_url_terminator(c: char) -> bool {
    matches!(
        c,
        '/' | ' '
            | '\n'
            | '\t'
            | '\r'
            | '"'
            | '\''
            | ')'
            | '>'
            | ','
            | '\\'
            | '{'
            | '}'
            | '|'
            | '^'
    )
}

/// Extract every outbound destination from `text`: `scheme://host` for ANY scheme (not just
/// http/https), `user@domain` emails, IP-literal endpoints, and bare hosts appearing as the value of
/// a destination-ish key (`{"host":"attacker.com"}`, `endpoint=attacker.com`). Bare hosts are only
/// taken from key context so ordinary prose (`report.pdf`, `v1.2.3`) is not mistaken for a
/// destination.
pub fn extract_destinations(text: &str, policy: &EgressPolicy) -> Vec<Destination> {
    let mut out = Vec::new();
    let lower = text.to_lowercase();

    // 1. `scheme://host` for any ASCII scheme.
    let bytes = lower.as_bytes();
    let mut i = 0;
    while let Some(rel) = lower[i..].find("://") {
        let sep = i + rel;
        // Walk back over the scheme letters.
        let mut s = sep;
        while s > 0 {
            let c = bytes[s - 1];
            if c.is_ascii_alphanumeric() || c == b'+' || c == b'-' || c == b'.' {
                s -= 1;
            } else {
                break;
            }
        }
        let scheme = lower[s..sep].to_string();
        let rest = &text[sep + 3..];
        let host: String = rest
            .chars()
            .take_while(|c| !is_url_terminator(*c))
            .collect();
        if !scheme.is_empty() && !host.is_empty() {
            let raw = format!("{scheme}://{host}");
            push_host_destination(&raw, &host, Some(scheme), &mut out);
        }
        i = sep + 3;
    }

    // 2. `mailto:` and bare emails.
    for (_, tok) in token_spans(text, |c| {
        c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '%' | '+' | '-' | '@')
    }) {
        if let Some(at) = tok.find('@') {
            let local = &tok[..at];
            let domain = &tok[at + 1..];
            if !local.is_empty() && domain.contains('.') && !domain.starts_with('.') {
                out.push(Destination {
                    raw: tok.to_string(),
                    domain: domain.trim_end_matches('.').to_lowercase(),
                    scheme: None,
                    has_userinfo: false,
                });
            }
        }
    }

    // 3. Bare hosts as the value of a destination-ish key: `"host": "attacker.com"`,
    //    `endpoint=1.2.3.4:9000`, `--target attacker.com`.
    let mut keys: Vec<String> = DESTINATION_KEYS.iter().map(|k| k.to_string()).collect();
    keys.extend(policy.destination_keys.iter().map(|k| k.to_lowercase()));
    for key in &keys {
        let mut from = 0;
        while let Some(rel) = lower[from..].find(key.as_str()) {
            let at = from + rel;
            from = at + key.len();
            // Key must be a standalone token (avoid "authority" matching "to").
            let prev_ok = lower[..at]
                .chars()
                .next_back()
                .map(|c| !c.is_ascii_alphanumeric() && c != '_')
                .unwrap_or(true);
            let after = &text[at + key.len()..];
            let mut it = after.chars();
            let next_ok = it
                .next()
                .map(|c| !c.is_ascii_alphanumeric() && c != '_')
                .unwrap_or(false);
            if !prev_ok || !next_ok {
                continue;
            }
            // Skip the separator run (`":  "`, `= `, ` `).
            let value_start = after
                .char_indices()
                .find(|(_, c)| c.is_ascii_alphanumeric() || *c == '[')
                .map(|(idx, _)| idx);
            let Some(vs) = value_start else { continue };
            // Only accept a short separator run — otherwise we are matching an unrelated later word.
            if after[..vs].chars().count() > 6 {
                continue;
            }
            // `:` is NOT a terminator here so an explicit port survives into `strip_port`.
            let value: String = after[vs..]
                .chars()
                .take_while(|c| !is_url_terminator(*c))
                .collect();
            let v = value.trim_matches('"').trim_end_matches(['.', ';']);
            if v.contains("://") || v.contains('@') {
                continue; // already covered by (1)/(2)
            }
            if plausible_host(v) {
                push_host_destination(v, v, None, &mut out);
            }
        }
    }
    out
}

fn domain_allowed(domain: &str, allowed: &[String]) -> bool {
    let d = domain.trim_end_matches('.').to_lowercase();
    allowed.iter().any(|a| {
        let a = a.trim().to_lowercase();
        !a.is_empty() && (d == a || d.ends_with(&format!(".{a}")))
    })
}
