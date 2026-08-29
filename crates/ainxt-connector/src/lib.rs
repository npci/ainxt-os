// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! ainxt-connector — the **Connector Runtime** policy spine (Phase 2, increment #1).
//!
//! A connector lets the runtime act on an external system (GitLab, Jira, Microsoft Graph) **on
//! behalf of a user**. Before any outbound call is made, and before any bytes leave the perimeter,
//! the request flows through this crate's admission pipeline. The pipeline is built from FOUR
//! mandatory safety seams — they are **required constructor arguments** of [`ConnectorRuntime`], so
//! there is no way to build a connector runtime without them (config-first, safety-invariant, the
//! same discipline as the engine's compliance/authz/audit gates):
//!
//! 1. [`ConnectorPolicy`]  — org/dept **allow-deny** (declarative, least-privilege default).
//! 2. [`ConnectorAuthorizer`] — **on-behalf-of** fine-grained authz (may THIS principal use THIS
//!    connector for THIS op on THIS resource, using the *user's* authority — confused-deputy
//!    defense, gap AI).
//! 3. [`EgressGuard`] — outbound **DLP** (redact secrets/PANs before they leave, gap T) plus a
//!    hard **data-class ceiling** (regulated data never egresses to a cloud connector, ADR-012 /
//!    gap O). The ceiling is enforced by [`ConnectorRuntime`] itself, not delegated.
//! 4. [`ConnectorAudit`] — every admission outcome is recorded (no resource values leak into it).
//!
//! This increment is the *spine only*: the OAuth2/PKCE engine (#3), the encrypted token store (#2),
//! the refresh coordinator (#4) and the concrete GitLab/Jira/Graph transports (#5) plug into this
//! same runtime object in later increments. Keeping the safety seams here means every one of those
//! later paths inherits admission control by construction rather than re-implementing it.
//!
//! Clean-room: all terminology, types and the pipeline shape are original to AiNxt.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, Mutex};

use ainxt_injection::Provenance;
use ainxt_types::{DataClass, Principal, Role};
use serde::{Deserialize, Serialize};

// ============================ Core identity + catalog ============================

/// Stable identifier for a connector (e.g. `"gitlab"`, `"jira"`, `"graph"`). A newtype so a
/// connector id can never be confused with an arbitrary string at a call site.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ConnectorId(String);

impl ConnectorId {
    pub fn new(id: impl Into<String>) -> Self {
        ConnectorId(id.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for ConnectorId {
    fn from(s: &str) -> Self {
        ConnectorId(s.to_string())
    }
}

impl fmt::Display for ConnectorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// How a connector authenticates on behalf of the user. The concrete flows land in #2/#3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthKind {
    /// OAuth2 authorization-code + PKCE (e.g. Microsoft Entra / Graph). Tokens live encrypted.
    OAuth2AuthCode,
    /// A long-lived per-user API / personal-access token (e.g. GitLab PAT, Jira API token).
    ApiToken,
    /// Unauthenticated (discovery/health only).
    None,
}

/// The **declarative** definition of a connector — loadable from config. It carries no secrets and
/// no per-user state; it is the static catalog entry the policy pipeline reasons about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorDef {
    pub id: ConnectorId,
    pub display_name: String,
    pub auth: AuthKind,
    /// OAuth scopes this connector's operations require (empty for `ApiToken`/`None`).
    #[serde(default)]
    pub scopes: Vec<String>,
    /// The **highest** data class permitted to LEAVE the perimeter through this connector
    /// (ADR-012 / gap O). A request whose data class exceeds this ceiling is hard-refused —
    /// regulated/PII data never egresses to a cloud connector. Conservative default: `Internal`.
    #[serde(default = "default_egress_ceiling")]
    pub max_egress_class: DataClass,
    /// Base URL / endpoint hint consumed by the transport (#5). Opaque to the policy spine.
    #[serde(default)]
    pub base_url: String,
}

fn default_egress_ceiling() -> DataClass {
    DataClass::Internal
}

impl ConnectorDef {
    /// A minimal definition; refine with the builder methods. Egress ceiling defaults to `Internal`.
    pub fn new(
        id: impl Into<ConnectorId>,
        display_name: impl Into<String>,
        auth: AuthKind,
    ) -> Self {
        ConnectorDef {
            id: id.into(),
            display_name: display_name.into(),
            auth,
            scopes: Vec::new(),
            max_egress_class: DataClass::Internal,
            base_url: String::new(),
        }
    }
    pub fn with_scopes<S: Into<String>>(mut self, scopes: impl IntoIterator<Item = S>) -> Self {
        self.scopes = scopes.into_iter().map(Into::into).collect();
        self
    }
    pub fn with_max_egress_class(mut self, class: DataClass) -> Self {
        self.max_egress_class = class;
        self
    }
    pub fn with_base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = url.into();
        self
    }
}

/// The connector catalog. Sorted (BTreeMap) so enumeration is deterministic.
#[derive(Debug, Default, Clone)]
pub struct ConnectorRegistry {
    defs: BTreeMap<String, ConnectorDef>,
}

impl ConnectorRegistry {
    pub fn new() -> Self {
        ConnectorRegistry {
            defs: BTreeMap::new(),
        }
    }
    /// Register a connector. Last-writer-wins on a duplicate id (the config loader dedups upstream);
    /// returns the definition that was replaced, if any.
    pub fn register(&mut self, def: ConnectorDef) -> Option<ConnectorDef> {
        self.defs.insert(def.id.as_str().to_string(), def)
    }
    pub fn get(&self, id: &ConnectorId) -> Option<&ConnectorDef> {
        self.defs.get(id.as_str())
    }
    pub fn contains(&self, id: &ConnectorId) -> bool {
        self.defs.contains_key(id.as_str())
    }
    /// All registered connector ids, sorted.
    pub fn ids(&self) -> Vec<&str> {
        self.defs.keys().map(String::as_str).collect()
    }
    pub fn len(&self) -> usize {
        self.defs.len()
    }
    pub fn is_empty(&self) -> bool {
        self.defs.is_empty()
    }
}

// ============================ Errors ============================

/// A connector admission / egress failure. `Display` messages never echo a resource value (which
/// may be a sensitive id such as an account number) — the model already knows what it requested.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectorError {
    /// No such connector is registered.
    UnknownConnector(String),
    /// Blocked by org/dept policy (allow-deny).
    PolicyDenied(String),
    /// Blocked by on-behalf-of authz (principal lacks the capability).
    NotAuthorized(String),
    /// The turn's data class exceeds the connector's egress ceiling — regulated data must not leave.
    EgressRefused {
        connector: String,
        data_class: DataClass,
        ceiling: DataClass,
    },
    /// A secret/PAN was detected in the request **URL** (path or query). A URL cannot be safely
    /// redacted mid-flight (redaction would corrupt the request and the secret is already in a
    /// non-body position), so egress is hard-refused fail-closed — a PAN/secret in a URL is an
    /// exfiltration signal, not user prose. The count is reported; the value never is.
    UrlEgressBlocked {
        connector: String,
        redactions: usize,
    },
}

impl fmt::Display for ConnectorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectorError::UnknownConnector(id) => write!(f, "unknown connector '{id}'"),
            ConnectorError::PolicyDenied(m) => write!(f, "connector policy denied: {m}"),
            ConnectorError::NotAuthorized(m) => write!(f, "not authorized: {m}"),
            ConnectorError::EgressRefused {
                connector,
                data_class,
                ceiling,
            } => write!(
                f,
                "egress refused for connector '{connector}': data class '{}' exceeds ceiling '{}'",
                data_class.as_str(),
                ceiling.as_str()
            ),
            ConnectorError::UrlEgressBlocked {
                connector,
                redactions,
            } => write!(
                f,
                "egress refused for connector '{connector}': {redactions} secret(s)/PAN(s) detected in the request URL"
            ),
        }
    }
}

impl std::error::Error for ConnectorError {}

// ============================ Seam 1: org/dept policy ============================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    Permit,
    Deny(String),
}

/// Org/dept allow-deny over connectors. MANDATORY seam; the *policy* is configurable, the *check*
/// is not (it always runs).
pub trait ConnectorPolicy: Send + Sync {
    fn permits(&self, principal: &Principal, connector: &ConnectorId) -> PolicyDecision;
}

/// Dev/OSS-only pass-through policy. Explicitly opt-in — never a hidden default — so choosing to
/// disable org/dept scoping is a visible decision in the composition layer.
pub struct AllowAllPolicy;
impl ConnectorPolicy for AllowAllPolicy {
    fn permits(&self, _p: &Principal, _c: &ConnectorId) -> PolicyDecision {
        PolicyDecision::Permit
    }
}

/// Declarative department allow-list policy. **Least-privilege by default** (`default_permit =
/// false`): a connector with no matching rule is denied. Admins bypass (role implies all grants).
#[derive(Debug, Clone, Default)]
pub struct DeptRuleTable {
    /// connector id → set of departments explicitly permitted to use it.
    allow: BTreeMap<String, BTreeSet<String>>,
    /// departments permitted to use ANY connector (e.g. a platform team).
    global_allow: BTreeSet<String>,
    /// outcome when no rule matches. `false` = default-deny (least privilege).
    default_permit: bool,
}

impl DeptRuleTable {
    pub fn new() -> Self {
        DeptRuleTable::default()
    }
    /// Permit `dept` to use connector `connector`.
    pub fn allow_dept(mut self, connector: &str, dept: &str) -> Self {
        self.allow
            .entry(connector.to_string())
            .or_default()
            .insert(dept.to_string());
        self
    }
    /// Permit `dept` to use every connector.
    pub fn allow_dept_global(mut self, dept: &str) -> Self {
        self.global_allow.insert(dept.to_string());
        self
    }
    /// Set the no-rule-matches outcome (default `false` = deny).
    pub fn default_permit(mut self, yes: bool) -> Self {
        self.default_permit = yes;
        self
    }
}

impl ConnectorPolicy for DeptRuleTable {
    fn permits(&self, principal: &Principal, connector: &ConnectorId) -> PolicyDecision {
        if principal.role == Role::Admin {
            return PolicyDecision::Permit;
        }
        let dept = principal.department.as_deref();
        if let Some(d) = dept {
            if self.global_allow.contains(d) {
                return PolicyDecision::Permit;
            }
        }
        if let Some(allowed) = self.allow.get(connector.as_str()) {
            // An explicit rule exists for this connector: the dept must be in it, else denied.
            if dept.is_some_and(|d| allowed.contains(d)) {
                return PolicyDecision::Permit;
            }
            // Do not echo the department value.
            return PolicyDecision::Deny(format!(
                "department is not permitted to use connector '{}'",
                connector.as_str()
            ));
        }
        if self.default_permit {
            PolicyDecision::Permit
        } else {
            PolicyDecision::Deny(format!(
                "no policy grants connector '{}' to this principal",
                connector.as_str()
            ))
        }
    }
}

/// **Clean served-daemon entrypoint (round-15 gap: "served connector policy default is
/// `AllowAllPolicy`, not least-privilege org/dept scoping").** Builds a [`DeptRuleTable`] from a
/// declarative env-var format: comma-separated `connector:dept` pairs (e.g.
/// `"gitlab:payments-eng,jira:hr-ops"`), where `connector` may be `*` to grant `dept` every
/// connector. **The offline default is genuinely least-privilege even with no configuration**: an
/// unset or empty env var returns a bare [`DeptRuleTable::new`] (`default_permit = false`,
/// default-deny), never [`AllowAllPolicy`] — so there is no "forgot to set the env var ⇒ everyone
/// gets everything" footgun. A malformed entry (missing `:`, an empty connector or dept) is skipped
/// rather than panicking, so one bad rule cannot take down the daemon or silently widen access.
///
/// `needs_hot_wiring`: the reserved daemon composition root
/// (`ainxt-runtimed::mounts::build_connector_gateway` / `build_connector_invoker`) passes
/// `Box::new(AllowAllPolicy)` to `ConnectorRuntime::new` today; calling
/// `dept_policy_from_env("AINXT_CONNECTOR_DEPT_RULES")` there (feeding it from the real org-tree /
/// `dept_product_mappings` source once available) replaces the permissive default with a real
/// least-privilege policy with zero required config. `DeptRuleTable`'s own least-privilege-by-default
/// semantics are proven offline by `policy_denies_wrong_department` and
/// `default_deny_when_no_rule_matches` (below); this function's env parsing is proven by the
/// `r15_dept_policy_from_env_*` tests below.
pub fn dept_policy_from_env(var: &str) -> DeptRuleTable {
    let mut table = DeptRuleTable::new(); // default_permit = false (least privilege)
    let Ok(raw) = std::env::var(var) else {
        return table;
    };
    for entry in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let Some((connector, dept)) = entry.split_once(':') else {
            continue; // malformed entry — skip, never widen access silently
        };
        let (connector, dept) = (connector.trim(), dept.trim());
        if connector.is_empty() || dept.is_empty() {
            continue;
        }
        table = if connector == "*" {
            table.allow_dept_global(dept)
        } else {
            table.allow_dept(connector, dept)
        };
    }
    table
}

// ============================ Seam 2: on-behalf-of authz ============================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectorDecision {
    Allow,
    Deny(String),
}

/// Fine-grained, on-behalf-of authorization: may THIS principal use THIS connector for THIS
/// operation on THIS resource — using the *user's* authority, never the runtime's own broad creds
/// (confused-deputy defense, gap AI). MANDATORY seam.
pub trait ConnectorAuthorizer: Send + Sync {
    fn authorize(
        &self,
        principal: &Principal,
        connector: &ConnectorId,
        op: &str,
        resource: Option<&str>,
    ) -> ConnectorDecision;
}

/// Capability-based OBO authorizer. Grants (most→least broad), any of which authorizes:
/// - `connector.<id>`            — the whole connector, every op/resource;
/// - `connector.<id>.<op>`       — one op, any resource;
/// - `connector.<id>:<res>`      — one resource, any op;
/// - `connector.<id>.<op>:<res>` — one op on one resource (least privilege).
///
/// `Role::Admin` implies all capabilities (see [`Principal::has_cap`]). Deny messages never echo
/// the resource value.
pub struct CapabilityConnectorAuthorizer;

impl ConnectorAuthorizer for CapabilityConnectorAuthorizer {
    fn authorize(
        &self,
        p: &Principal,
        connector: &ConnectorId,
        op: &str,
        resource: Option<&str>,
    ) -> ConnectorDecision {
        let id = connector.as_str();
        if p.has_cap(&format!("connector.{id}")) || p.has_cap(&format!("connector.{id}.{op}")) {
            return ConnectorDecision::Allow;
        }
        if let Some(res) = resource {
            if p.has_cap(&format!("connector.{id}:{res}"))
                || p.has_cap(&format!("connector.{id}.{op}:{res}"))
            {
                return ConnectorDecision::Allow;
            }
            return ConnectorDecision::Deny(format!(
                "principal '{}' is not authorized for connector '{id}' op '{op}' on the requested resource",
                p.user_id
            ));
        }
        ConnectorDecision::Deny(format!(
            "principal '{}' lacks capability for connector '{id}' op '{op}'",
            p.user_id
        ))
    }
}

// ============================ Seam 3: egress DLP ============================

/// The result of scanning an outbound payload: the (possibly redacted) bytes plus a redaction count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressFiltered {
    pub payload: String,
    pub redactions: usize,
}

/// Outbound data-loss-prevention (gap T): scan+redact a payload before it leaves the perimeter.
/// Redact-and-proceed (never blocks the call). MANDATORY seam — the enterprise DLP engine plugs in
/// here; the OSS default is [`MarkerEgressGuard`].
pub trait EgressGuard: Send + Sync {
    fn filter_egress(&self, connector: &ConnectorId, payload: &str) -> EgressFiltered;
}

/// Luhn (mod-10) check over an all-digits string — the checksum every real PAN satisfies. Used to
/// decide whether a *separator-formatted* digit group is a card number (so `4111 1111 1111 1111`
/// redacts) without over-redacting arbitrary spaced number groups. `digits` must contain only ASCII
/// digits (the caller guarantees this), so the byte→value conversion cannot overflow.
fn luhn_valid(digits: &str) -> bool {
    if digits.is_empty() {
        return false;
    }
    let mut sum = 0u32;
    let mut double = false;
    for b in digits.bytes().rev() {
        let mut d = (b - b'0') as u32; // digits-only input ⇒ 0..=9
        if double {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
        double = !double;
    }
    sum % 10 == 0
}

/// The secret markers the OSS default DLP neutralizes together with their VALUE (the non-whitespace
/// run after the marker). Relabeling the prefix while shipping the value in full is worse than
/// nothing (the secret still egresses AND a downstream marker-scanner is blinded), so the value is
/// redacted too. Both `KEY=value` assignment markers and the `Bearer <token>` HTTP auth form.
const SECRET_MARKERS: &[&str] = &[
    "PAN=",
    "SECRET=",
    "API_KEY=",
    "APIKEY=",
    "TOKEN=",
    "token=",
    "PASSWORD=",
    "PASSWD=",
    "PWD=",
    "AUTH=",
    "AUTHORIZATION=",
    "Bearer ",
    "bearer ",
];

/// High-value credential-token PREFIXES a payments platform must not egress by accident: provider
/// personal-access / API tokens whose format is unambiguous (these prefixes never occur in prose).
/// A word starting with one of these AND at least [`CRED_MIN_LEN`] chars long is redacted whole.
const CRED_PREFIXES: &[&str] = &[
    "glpat-", // GitLab personal access token
    "gldt-",  // GitLab deploy token
    "xoxb-",  // Slack bot token
    "xoxp-",  // Slack user token
    "ghp_",   // GitHub personal access token
    "gho_",   // GitHub OAuth token
    "ghs_",   // GitHub server-to-server token
    "AKIA",   // AWS access key id
    "ASIA",   // AWS temporary access key id
];

/// Minimum length of a credential word for the prefix pass to redact it (AWS access-key ids are
/// exactly 20 chars; provider PATs are longer). Below this a prefix match is not a credential.
const CRED_MIN_LEN: usize = 20;

/// OSS default DLP (a deterministic floor — the enterprise entropy/ML detector replaces it via the
/// trait). It redacts, before any bytes leave the perimeter:
/// - **PAN-like numbers** — contiguous digit runs (≥12) and separator-formatted card numbers (13–19
///   digits split by single spaces/hyphens passing the Luhn checksum) → `[REDACTED-PAN]`;
/// - **credential tokens** — words with an unambiguous provider prefix ([`CRED_PREFIXES`], e.g.
///   `glpat-…`, `ghp_…`, `AKIA…`) → `[REDACTED-SECRET]`;
/// - **secret markers + their values** — [`SECRET_MARKERS`] incl. `Bearer <token>` → `[REDACTED]`;
/// - **private-key PEM blocks** — a `-----BEGIN … PRIVATE KEY-----` … block → `[REDACTED-PRIVATE-KEY]`.
pub struct MarkerEgressGuard;

impl MarkerEgressGuard {
    fn redact(text: &str) -> (String, usize) {
        let chars: Vec<char> = text.chars().collect();
        let mut out = String::with_capacity(text.len());
        let mut count = 0usize;
        let mut i = 0;
        while i < chars.len() {
            if !chars[i].is_ascii_digit() {
                out.push(chars[i]);
                i += 1;
                continue;
            }
            // Extend a PAN candidate: digits, plus single interior ' '/'-' separators that are
            // immediately followed by another digit (so trailing/double separators end the span).
            let start = i;
            let mut j = i + 1;
            while j < chars.len() {
                let is_digit = chars[j].is_ascii_digit();
                // A single interior ' '/'-' separator immediately followed by another digit.
                let is_interior_sep = (chars[j] == ' ' || chars[j] == '-')
                    && chars.get(j + 1).is_some_and(char::is_ascii_digit);
                if is_digit || is_interior_sep {
                    j += 1;
                } else {
                    break;
                }
            }
            let candidate: String = chars[start..j].iter().collect();
            let digits: String = candidate.chars().filter(char::is_ascii_digit).collect();
            let has_sep = candidate.len() != digits.len();
            // Contiguous run ≥12 (unformatted PAN / long secret number), OR a separator-formatted
            // 13–19 digit group that satisfies Luhn (a real card number, not a spaced id/date).
            let redact_it = if has_sep {
                (13..=19).contains(&digits.len()) && luhn_valid(&digits)
            } else {
                digits.len() >= 12
            };
            if redact_it {
                out.push_str("[REDACTED-PAN]");
                count += 1;
            } else {
                out.push_str(&candidate);
            }
            i = j;
        }
        // Credential-token prefix pass: redact whole words that are unmistakably provider tokens.
        out = Self::redact_credential_words(&out, &mut count);
        // Redact each secret MARKER together with its VALUE (up to the next whitespace) — not just
        // the label. Relabeling the prefix while shipping the value in full is worse than nothing:
        // the secret still egresses AND a downstream marker-scanner is blinded to it.
        for marker in SECRET_MARKERS {
            out = Self::redact_marker_value(&out, marker, &mut count);
        }
        // Private-key PEM block pass (a leaked private key is critical — redact the whole block).
        out = Self::redact_pem_private_keys(&out, &mut count);
        (out, count)
    }

    /// Redact whole words that begin with an unambiguous credential prefix ([`CRED_PREFIXES`]) and are
    /// at least [`CRED_MIN_LEN`] chars long. A "word" is a maximal run of `[A-Za-z0-9_-]`; a prefix is
    /// only honored at a word boundary (preceding char is not a word char), so a prefix appearing as a
    /// substring of ordinary prose (e.g. `task-force` containing `sk-`) can never trigger.
    fn redact_credential_words(text: &str, count: &mut usize) -> String {
        let bytes = text.as_bytes();
        let is_word = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'-';
        let mut out = String::with_capacity(text.len());
        let mut i = 0;
        while i < bytes.len() {
            // Only ASCII bytes participate in word runs; multi-byte UTF-8 is copied verbatim.
            let at_boundary = i == 0 || !is_word(bytes[i - 1]);
            if at_boundary && is_word(bytes[i]) && bytes[i].is_ascii() {
                let start = i;
                while i < bytes.len() && is_word(bytes[i]) {
                    i += 1;
                }
                let word = &text[start..i];
                let is_cred =
                    word.len() >= CRED_MIN_LEN && CRED_PREFIXES.iter().any(|p| word.starts_with(p));
                if is_cred {
                    out.push_str("[REDACTED-SECRET]");
                    *count += 1;
                } else {
                    out.push_str(word);
                }
            } else {
                // Copy one full UTF-8 char so we never split a multi-byte sequence.
                let ch = text[i..].chars().next().unwrap();
                out.push(ch);
                i += ch.len_utf8();
            }
        }
        out
    }

    /// Redact each `-----BEGIN … PRIVATE KEY-----` … `-----END … PRIVATE KEY-----` block (including the
    /// markers) to `[REDACTED-PRIVATE-KEY]`. Triggers only when a private-key PEM header is actually
    /// present, so ordinary text is never touched.
    fn redact_pem_private_keys(text: &str, count: &mut usize) -> String {
        const BEGIN: &str = "-----BEGIN";
        const KEY_TAIL: &str = "PRIVATE KEY-----";
        let mut out = String::with_capacity(text.len());
        let mut rest = text;
        loop {
            let Some(begin_rel) = rest.find(BEGIN) else {
                out.push_str(rest);
                break;
            };
            let after_begin = &rest[begin_rel..];
            // The block is a private key only if its BEGIN HEADER LINE says so (`… PRIVATE KEY-----`);
            // a certificate/public-key BEGIN is left untouched.
            let header_end = after_begin.find('\n').unwrap_or(after_begin.len());
            if after_begin[..header_end].contains(KEY_TAIL) {
                // The END line's tail is the LAST `PRIVATE KEY-----` in the block.
                let tail_rel = after_begin.rfind(KEY_TAIL).expect("header contained it");
                let block_end = begin_rel + tail_rel + KEY_TAIL.len();
                out.push_str(&rest[..begin_rel]);
                out.push_str("[REDACTED-PRIVATE-KEY]");
                *count += 1;
                rest = &rest[block_end..];
            } else {
                // A `-----BEGIN` that is not a private key (e.g. a certificate) — leave it, and
                // advance past this marker so we don't loop forever.
                let adv = begin_rel + BEGIN.len();
                out.push_str(&rest[..adv]);
                rest = &rest[adv..];
            }
        }
        out
    }

    /// Replace every `marker`+value occurrence (value = the non-whitespace run after the marker)
    /// with `[REDACTED]`, so the secret value never survives.
    fn redact_marker_value(text: &str, marker: &str, count: &mut usize) -> String {
        if !text.contains(marker) {
            return text.to_string();
        }
        let mut out = String::with_capacity(text.len());
        let mut rest = text;
        while let Some(pos) = rest.find(marker) {
            out.push_str(&rest[..pos]);
            out.push_str("[REDACTED]");
            *count += 1;
            let after = &rest[pos + marker.len()..];
            let value_end = after.find(char::is_whitespace).unwrap_or(after.len());
            rest = &after[value_end..];
        }
        out.push_str(rest);
        out
    }
}

impl EgressGuard for MarkerEgressGuard {
    fn filter_egress(&self, _connector: &ConnectorId, payload: &str) -> EgressFiltered {
        let (payload, redactions) = Self::redact(payload);
        EgressFiltered {
            payload,
            redactions,
        }
    }
}

// ============================ Seam 4: audit ============================

/// One connector admission/egress audit event. Carries `resource_present` (a bool), never the
/// resource value, so a sensitive id is never persisted into the audit trail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorAuditEvent {
    pub actor: String,
    pub connector: String,
    pub op: String,
    pub resource_present: bool,
    pub outcome: String,
}

/// Audit seam. MANDATORY. Production plugs in the tamper-evident/WORM sink (gap AK).
pub trait ConnectorAudit: Send + Sync {
    fn record(&self, event: ConnectorAuditEvent);

    /// The tamper-evidence anchor, if this sink is chained (`None` for a plain sink like
    /// [`InMemoryConnectorAudit`]). Lets a caller — or [`ConnectorRuntime::audit_head`] — distinguish
    /// "this runtime's audit is tamper-evident" from "it is not" through the trait object alone,
    /// without needing a concrete-type handle into the runtime's private `audit` field.
    fn head_hash(&self) -> Option<String> {
        None
    }

    /// GAP-FIX connectors — verify this sink's own tamper-evidence chain, if it has one. `Ok(())` for
    /// a non-chained sink (nothing to verify, `head_hash` is also `None`) or an intact chain; `Err(i)`
    /// names the first tampered/reordered/inserted link. [`HashChainedConnectorAudit::verify`]/
    /// `verify_chain` were fully implemented and unit-tested but had zero callers outside their own
    /// crate's tests — this default plus [`HashChainedConnectorAudit`]'s override make the check
    /// reachable through the SAME trait-object seam [`ConnectorRuntime::audit_head`] already uses,
    /// without needing a concrete-type handle into the runtime's private `audit` field.
    fn verify(&self) -> Result<(), usize> {
        Ok(())
    }
}

/// In-memory audit sink (tests/dev). Cheap to clone — clones share the same backing store, so a
/// test can hold a handle and inspect what the runtime recorded.
#[derive(Debug, Clone, Default)]
pub struct InMemoryConnectorAudit {
    records: Arc<Mutex<Vec<ConnectorAuditEvent>>>,
}

impl InMemoryConnectorAudit {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn events(&self) -> Vec<ConnectorAuditEvent> {
        self.records.lock().expect("audit lock").clone()
    }
    pub fn len(&self) -> usize {
        self.records.lock().expect("audit lock").len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl ConnectorAudit for InMemoryConnectorAudit {
    fn record(&self, event: ConnectorAuditEvent) {
        self.records.lock().expect("audit lock").push(event);
    }
}

/// Genesis hash for an empty chain (no previous entry).
const AUDIT_GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// One link in the tamper-evident audit chain: the event, the hash of the previous link, and this
/// link's hash = `SHA-256(prev_hash || canonical(event))`. Any in-place edit, reorder, or insertion
/// breaks every subsequent hash, so tampering is detectable by re-walking the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainedAuditEntry {
    pub event: ConnectorAuditEvent,
    pub prev_hash: String,
    pub hash: String,
}

/// A **tamper-evident** connector audit sink (gap AK): a SHA-256 **hash chain** over every admission/
/// egress outcome. This is the in-tree, dependency-light realization of the design's tamper-evident
/// audit — each record is bound to the entire prior history, so any silent mutation/reordering/
/// insertion is detectable via [`verify`](Self::verify). It is NOT durable on its own: production
/// binds this in front of (or feeds its links into) a WORM object-store with a retention lock for the
/// append-only + durability half; the [`head`](Self::head) hash is the anchor an external witness
/// publishes so even tail-truncation is detectable. Cheap to clone — clones share the chain.
#[derive(Clone, Default)]
pub struct HashChainedConnectorAudit {
    entries: Arc<Mutex<Vec<ChainedAuditEntry>>>,
}

impl HashChainedConnectorAudit {
    pub fn new() -> Self {
        Self::default()
    }

    /// Canonical, unambiguous byte encoding of an event (length-prefixed fields so no field value can
    /// forge a boundary). Feeds the hash.
    fn canonical(event: &ConnectorAuditEvent) -> Vec<u8> {
        let mut out = Vec::new();
        for field in [
            event.actor.as_str(),
            event.connector.as_str(),
            event.op.as_str(),
            if event.resource_present { "1" } else { "0" },
            event.outcome.as_str(),
        ] {
            out.extend_from_slice(&(field.len() as u64).to_le_bytes());
            out.extend_from_slice(field.as_bytes());
        }
        out
    }

    /// `hex(SHA-256(prev_hash_bytes || canonical(event)))`.
    fn link_hash(prev_hash: &str, event: &ConnectorAuditEvent) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(prev_hash.as_bytes());
        h.update(Self::canonical(event));
        let digest = h.finalize();
        let mut s = String::with_capacity(64);
        for b in digest {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    /// A snapshot of the chain (for inspection / feeding a durable WORM sink).
    pub fn snapshot(&self) -> Vec<ChainedAuditEntry> {
        self.entries.lock().expect("audit lock").clone()
    }

    /// The head (latest) hash — the anchor to publish to an external witness so tail-truncation is
    /// detectable. [`AUDIT_GENESIS`] when the chain is empty.
    pub fn head(&self) -> String {
        self.entries
            .lock()
            .expect("audit lock")
            .last()
            .map(|e| e.hash.clone())
            .unwrap_or_else(|| AUDIT_GENESIS.to_string())
    }

    pub fn len(&self) -> usize {
        self.entries.lock().expect("audit lock").len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Verify the live chain. `Ok(())` if intact; `Err(index)` of the FIRST link whose stored hash or
    /// `prev_hash` linkage does not recompute — i.e. the first tampered/reordered/inserted link.
    pub fn verify(&self) -> Result<(), usize> {
        Self::verify_chain(&self.snapshot())
    }

    /// Verify an arbitrary chain snapshot (associated fn so callers/tests can validate exported links).
    pub fn verify_chain(entries: &[ChainedAuditEntry]) -> Result<(), usize> {
        let mut prev = AUDIT_GENESIS.to_string();
        for (i, e) in entries.iter().enumerate() {
            if e.prev_hash != prev {
                return Err(i);
            }
            let expect = Self::link_hash(&e.prev_hash, &e.event);
            if e.hash != expect {
                return Err(i);
            }
            prev = e.hash.clone();
        }
        Ok(())
    }
}

impl ConnectorAudit for HashChainedConnectorAudit {
    fn record(&self, event: ConnectorAuditEvent) {
        let mut entries = self.entries.lock().expect("audit lock");
        let prev_hash = entries
            .last()
            .map(|e| e.hash.clone())
            .unwrap_or_else(|| AUDIT_GENESIS.to_string());
        let hash = Self::link_hash(&prev_hash, &event);
        entries.push(ChainedAuditEntry {
            event,
            prev_hash,
            hash,
        });
    }

    fn head_hash(&self) -> Option<String> {
        Some(self.head())
    }

    fn verify(&self) -> Result<(), usize> {
        Self::verify_chain(&self.snapshot())
    }
}

// ============================ The runtime (policy spine) ============================

/// The Connector Runtime. Every outbound connector action is admitted through
/// [`authorize_use`](ConnectorRuntime::authorize_use) and every outbound payload through
/// [`guard_egress`](ConnectorRuntime::guard_egress). The four safety seams are required
/// constructor arguments — a `ConnectorRuntime` cannot exist without them.
pub struct ConnectorRuntime {
    registry: ConnectorRegistry,
    policy: Box<dyn ConnectorPolicy>,
    authorizer: Box<dyn ConnectorAuthorizer>,
    egress: Box<dyn EgressGuard>,
    audit: Box<dyn ConnectorAudit>,
}

impl ConnectorRuntime {
    /// Construct the runtime. All four seams are mandatory (safety-invariant): you configure *which*
    /// policy/authorizer/DLP/audit, never *whether* they run.
    pub fn new(
        registry: ConnectorRegistry,
        policy: Box<dyn ConnectorPolicy>,
        authorizer: Box<dyn ConnectorAuthorizer>,
        egress: Box<dyn EgressGuard>,
        audit: Box<dyn ConnectorAudit>,
    ) -> Self {
        ConnectorRuntime {
            registry,
            policy,
            authorizer,
            egress,
            audit,
        }
    }

    /// Construct with the **OSS-default safety seams pre-wired** so a composition can never
    /// accidentally ship a connector runtime WITHOUT egress DLP + audit + OBO authz. Egress defaults
    /// to [`MarkerEgressGuard`] (the deterministic PAN/credential/PEM DLP floor), authz to
    /// [`CapabilityConnectorAuthorizer`], audit to the tamper-evident [`HashChainedConnectorAudit`].
    /// The caller supplies only the org/dept `policy` (the one genuinely deployment-specific seam) and
    /// the `registry`. A deployment that wants a stronger DLP/audit backend uses [`new`](Self::new) and
    /// injects it — this helper guarantees the *floor*, never a weaker one.
    ///
    /// `needs_hot_wiring` (round-15 gaps: "tamper-evident/WORM connector audit not wired on the served
    /// path" + "served connector policy default is `AllowAllPolicy`"): the reserved daemon composition
    /// root (`ainxt-runtimed::mounts::build_connector_gateway` / `build_connector_invoker`) calls
    /// `ConnectorRuntime::new(.., Box::new(AllowAllPolicy), .., Box::new(InMemoryConnectorAudit::new()))`
    /// directly today, bypassing this helper — so the served daemon gets neither the tamper-evident
    /// audit chain nor least-privilege org/dept scoping. Calling
    /// `ConnectorRuntime::with_oss_defaults(registry, dept_policy_from_env("AINXT_CONNECTOR_DEPT_RULES"))`
    /// there closes both at once with no weaker floor ever possible. The tamper-evident chain being
    /// active end-to-end on the real connector-invoke call-site is proven by
    /// `r11_dept_policy_enforced_and_every_outcome_chained_on_use_path` /
    /// `r11_tamper_evident_audit_detects_silent_mutation` (`ainxt-connector-http` tests); this
    /// constructor specifically selecting the tamper-evident sink (not `InMemoryConnectorAudit`) is
    /// pinned by `r15_with_oss_defaults_audit_is_tamper_evident_not_in_memory` below.
    pub fn with_oss_defaults(
        registry: ConnectorRegistry,
        policy: Box<dyn ConnectorPolicy>,
    ) -> Self {
        ConnectorRuntime::new(
            registry,
            policy,
            Box::new(CapabilityConnectorAuthorizer),
            Box::new(MarkerEgressGuard),
            Box::new(HashChainedConnectorAudit::new()),
        )
    }

    /// The tamper-evidence anchor of this runtime's audit sink, if it is chained — `None` if the
    /// composition used a plain (non-tamper-evident) sink like [`InMemoryConnectorAudit`]. Lets a
    /// caller (or a test) verify WHICH kind of audit sink a runtime was built with, from the outside,
    /// without a concrete-type handle into the private `audit` field.
    pub fn audit_head(&self) -> Option<String> {
        self.audit.head_hash()
    }

    /// GAP-FIX connectors — the served counterpart to [`Self::audit_head`]: actually verify the
    /// tamper-evidence chain (not just read its anchor) through the same trait-object seam.
    pub fn audit_verify(&self) -> Result<(), usize> {
        self.audit.verify()
    }

    pub fn registry(&self) -> &ConnectorRegistry {
        &self.registry
    }

    fn audit(
        &self,
        principal: &Principal,
        connector: &ConnectorId,
        op: &str,
        resource: Option<&str>,
        outcome: &str,
    ) {
        self.audit.record(ConnectorAuditEvent {
            actor: principal.user_id.clone(),
            connector: connector.as_str().to_string(),
            op: op.to_string(),
            resource_present: resource.is_some(),
            outcome: outcome.to_string(),
        });
    }

    /// Admit (or refuse) USING a connector on behalf of a principal. Fail-closed, in order:
    /// 1. the connector must be registered;
    /// 2. org/dept policy must permit it;
    /// 3. on-behalf-of authz must allow this op on this resource.
    ///
    /// Every outcome (allow or any deny) is audited. On success the caller may proceed to obtain a
    /// token (#2/#3) and make the call (#5).
    pub fn authorize_use(
        &self,
        principal: &Principal,
        connector: &ConnectorId,
        op: &str,
        resource: Option<&str>,
    ) -> Result<(), ConnectorError> {
        if !self.registry.contains(connector) {
            self.audit(principal, connector, op, resource, "unknown-connector");
            return Err(ConnectorError::UnknownConnector(
                connector.as_str().to_string(),
            ));
        }
        if let PolicyDecision::Deny(reason) = self.policy.permits(principal, connector) {
            self.audit(principal, connector, op, resource, "policy-denied");
            return Err(ConnectorError::PolicyDenied(reason));
        }
        if let ConnectorDecision::Deny(reason) = self
            .authorizer
            .authorize(principal, connector, op, resource)
        {
            self.audit(principal, connector, op, resource, "authz-denied");
            return Err(ConnectorError::NotAuthorized(reason));
        }
        self.audit(principal, connector, op, resource, "authorized");
        Ok(())
    }

    /// Guard an OUTBOUND payload before it leaves the perimeter. Fail-closed, in order:
    /// 1. the connector must be registered;
    /// 2. **data-class ceiling** — if `data_class` exceeds the connector's `max_egress_class`, the
    ///    call is hard-refused (regulated/PII data never egresses to a cloud connector, ADR-012);
    /// 3. **DLP** — the payload is scanned and secrets/PANs are redacted (redact-and-proceed).
    ///
    /// Returns the payload actually safe to send. The data-class check is enforced here by the
    /// runtime itself, so no [`EgressGuard`] impl can weaken it.
    pub fn guard_egress(
        &self,
        principal: &Principal,
        connector: &ConnectorId,
        op: &str,
        data_class: DataClass,
        payload: &str,
    ) -> Result<EgressFiltered, ConnectorError> {
        let def = match self.registry.get(connector) {
            Some(d) => d,
            None => {
                self.audit(principal, connector, op, None, "unknown-connector");
                return Err(ConnectorError::UnknownConnector(
                    connector.as_str().to_string(),
                ));
            }
        };
        if data_class.sensitivity() > def.max_egress_class.sensitivity() {
            self.audit(principal, connector, op, None, "egress-refused-dataclass");
            return Err(ConnectorError::EgressRefused {
                connector: connector.as_str().to_string(),
                data_class,
                ceiling: def.max_egress_class,
            });
        }
        let filtered = self.egress.filter_egress(connector, payload);
        let outcome = if filtered.redactions > 0 {
            "egress-redacted"
        } else {
            "egress-clean"
        };
        self.audit(principal, connector, op, None, outcome);
        Ok(filtered)
    }

    /// Screen an OUTBOUND request **URL** (path + query) for secrets/PANs before dispatch (gap T,
    /// URL coverage). Read requests carry no body, but their URLs embed user-controlled data (a repo
    /// path, a file path, a `ref`, query params), so a PAN/secret placed there would egress
    /// unredacted if only the body were scanned. A URL cannot be redacted in flight without breaking
    /// the request, so detection is **fail-closed**: if the DLP guard would redact anything in the
    /// URL, the call is refused ([`ConnectorError::UrlEgressBlocked`]) and audited. Returns `Ok(())`
    /// when the URL is clean.
    pub fn screen_url(
        &self,
        principal: &Principal,
        connector: &ConnectorId,
        op: &str,
        url: &str,
    ) -> Result<(), ConnectorError> {
        if !self.registry.contains(connector) {
            self.audit(principal, connector, op, None, "unknown-connector");
            return Err(ConnectorError::UnknownConnector(
                connector.as_str().to_string(),
            ));
        }
        let scanned = self.egress.filter_egress(connector, url);
        if scanned.redactions > 0 {
            self.audit(principal, connector, op, None, "egress-url-blocked");
            return Err(ConnectorError::UrlEgressBlocked {
                connector: connector.as_str().to_string(),
                redactions: scanned.redactions,
            });
        }
        Ok(())
    }

    /// The provenance to tag a connector RESPONSE with: [`Provenance::Connector`] — untrusted, so
    /// the runtime's injection stage fences + scans it (connector data can carry indirect prompt
    /// injection, ADR-009). Connector data is never treated as instructions.
    pub fn ingress_provenance(&self) -> Provenance {
        Provenance::Connector
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gitlab() -> ConnectorDef {
        ConnectorDef::new("gitlab", "GitLab", AuthKind::ApiToken)
            .with_max_egress_class(DataClass::Internal)
            .with_base_url("https://gitlab.example.invalid")
    }

    fn registry() -> ConnectorRegistry {
        let mut r = ConnectorRegistry::new();
        r.register(gitlab());
        r
    }

    /// A runtime with default gates + a caller-supplied policy, returning the audit handle too.
    fn runtime_with(
        policy: Box<dyn ConnectorPolicy>,
    ) -> (ConnectorRuntime, InMemoryConnectorAudit) {
        let audit = InMemoryConnectorAudit::new();
        let rt = ConnectorRuntime::new(
            registry(),
            policy,
            Box::new(CapabilityConnectorAuthorizer),
            Box::new(MarkerEgressGuard),
            Box::new(audit.clone()),
        );
        (rt, audit)
    }

    #[test]
    fn registry_is_sorted_and_queryable() {
        let mut r = ConnectorRegistry::new();
        r.register(ConnectorDef::new("jira", "Jira", AuthKind::ApiToken));
        r.register(ConnectorDef::new(
            "graph",
            "Graph",
            AuthKind::OAuth2AuthCode,
        ));
        r.register(gitlab());
        assert_eq!(r.ids(), vec!["gitlab", "graph", "jira"]); // deterministic, sorted
        assert_eq!(r.len(), 3);
        assert!(r.contains(&ConnectorId::from("gitlab")));
        assert!(r.get(&ConnectorId::from("graph")).is_some());
    }

    #[test]
    fn duplicate_registration_replaces_and_returns_prior() {
        let mut r = ConnectorRegistry::new();
        assert!(r.register(gitlab()).is_none());
        let prev = r.register(ConnectorDef::new("gitlab", "GitLab v2", AuthKind::ApiToken));
        assert_eq!(prev.unwrap().display_name, "GitLab");
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn connector_def_serde_round_trips() {
        let def = gitlab().with_scopes(["api", "read_repository"]);
        let json = serde_json::to_string(&def).unwrap();
        let back: ConnectorDef = serde_json::from_str(&json).unwrap();
        assert_eq!(def, back);
    }

    #[test]
    fn unknown_connector_is_refused_and_audited() {
        let (rt, audit) = runtime_with(Box::new(AllowAllPolicy));
        let p = Principal::user("u", &["connector.gitlab"]);
        let err = rt
            .authorize_use(&p, &ConnectorId::from("bitbucket"), "read", None)
            .unwrap_err();
        assert_eq!(err, ConnectorError::UnknownConnector("bitbucket".into()));
        assert_eq!(audit.events()[0].outcome, "unknown-connector");
    }

    #[test]
    fn policy_denies_wrong_department() {
        let policy = DeptRuleTable::new().allow_dept("gitlab", "payments-eng");
        let (rt, audit) = runtime_with(Box::new(policy));
        let p = Principal::user("u", &["connector.gitlab"]).with_department("hr");
        let err = rt
            .authorize_use(&p, &ConnectorId::from("gitlab"), "read", None)
            .unwrap_err();
        assert!(matches!(err, ConnectorError::PolicyDenied(_)));
        assert_eq!(audit.events()[0].outcome, "policy-denied");
    }

    #[test]
    fn policy_permits_allowed_department_then_authz_runs() {
        let policy = DeptRuleTable::new().allow_dept("gitlab", "payments-eng");
        let (rt, _audit) = runtime_with(Box::new(policy));
        let p = Principal::user("u", &["connector.gitlab"]).with_department("payments-eng");
        assert!(rt
            .authorize_use(&p, &ConnectorId::from("gitlab"), "read", None)
            .is_ok());
    }

    #[test]
    fn default_deny_when_no_rule_matches() {
        let policy = DeptRuleTable::new(); // least privilege: nothing allowed
        let (rt, _audit) = runtime_with(Box::new(policy));
        let p = Principal::user("u", &["connector.gitlab"]).with_department("payments-eng");
        assert!(matches!(
            rt.authorize_use(&p, &ConnectorId::from("gitlab"), "read", None),
            Err(ConnectorError::PolicyDenied(_))
        ));
    }

    #[test]
    fn admin_bypasses_dept_policy() {
        let policy = DeptRuleTable::new(); // default-deny for everyone else
        let (rt, _audit) = runtime_with(Box::new(policy));
        let admin = Principal::admin("root");
        assert!(rt
            .authorize_use(&admin, &ConnectorId::from("gitlab"), "read", None)
            .is_ok());
    }

    #[test]
    fn obo_authz_denies_without_capability() {
        let (rt, audit) = runtime_with(Box::new(AllowAllPolicy));
        let p = Principal::user("u", &[]); // no connector cap
        let err = rt
            .authorize_use(&p, &ConnectorId::from("gitlab"), "write", None)
            .unwrap_err();
        assert!(matches!(err, ConnectorError::NotAuthorized(_)));
        assert_eq!(audit.events()[0].outcome, "authz-denied");
    }

    #[test]
    fn obo_authz_grants_by_scope_ladder() {
        let (rt, _a) = runtime_with(Box::new(AllowAllPolicy));
        // broad
        let broad = Principal::user("a", &["connector.gitlab"]);
        assert!(rt
            .authorize_use(
                &broad,
                &ConnectorId::from("gitlab"),
                "write",
                Some("repo/x")
            )
            .is_ok());
        // op-scoped
        let op = Principal::user("b", &["connector.gitlab.read"]);
        assert!(rt
            .authorize_use(&op, &ConnectorId::from("gitlab"), "read", Some("repo/x"))
            .is_ok());
        assert!(rt
            .authorize_use(&op, &ConnectorId::from("gitlab"), "write", Some("repo/x"))
            .is_err());
        // resource-scoped
        let res = Principal::user("c", &["connector.gitlab:repo/x"]);
        assert!(rt
            .authorize_use(&res, &ConnectorId::from("gitlab"), "read", Some("repo/x"))
            .is_ok());
        assert!(rt
            .authorize_use(&res, &ConnectorId::from("gitlab"), "read", Some("repo/y"))
            .is_err());
        // op+resource-scoped
        let both = Principal::user("d", &["connector.gitlab.read:repo/x"]);
        assert!(rt
            .authorize_use(&both, &ConnectorId::from("gitlab"), "read", Some("repo/x"))
            .is_ok());
        assert!(rt
            .authorize_use(&both, &ConnectorId::from("gitlab"), "write", Some("repo/x"))
            .is_err());
    }

    #[test]
    fn deny_messages_do_not_leak_the_resource() {
        let (rt, _a) = runtime_with(Box::new(AllowAllPolicy));
        let p = Principal::user("u", &["connector.gitlab.read"]);
        let secret_resource = "account-9988776655";
        let err = rt
            .authorize_use(
                &p,
                &ConnectorId::from("gitlab"),
                "write",
                Some(secret_resource),
            )
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            !msg.contains("9988776655"),
            "resource value leaked into error: {msg}"
        );
    }

    #[test]
    fn egress_refused_when_data_class_exceeds_ceiling() {
        let (rt, audit) = runtime_with(Box::new(AllowAllPolicy));
        let p = Principal::admin("root");
        // gitlab ceiling = Internal; a RegulatedPayment payload must be refused (never egress).
        let err = rt
            .guard_egress(
                &p,
                &ConnectorId::from("gitlab"),
                "write",
                DataClass::RegulatedPayment,
                "settlement file",
            )
            .unwrap_err();
        assert!(matches!(err, ConnectorError::EgressRefused { .. }));
        assert_eq!(audit.events()[0].outcome, "egress-refused-dataclass");
    }

    #[test]
    fn egress_allowed_at_or_below_ceiling_and_dlp_redacts() {
        let (rt, _a) = runtime_with(Box::new(AllowAllPolicy));
        let p = Principal::admin("root");
        let payload = "note card 4111111111111111 and SECRET=hunter2 to the ticket";
        let out = rt
            .guard_egress(
                &p,
                &ConnectorId::from("gitlab"),
                "write",
                DataClass::Internal,
                payload,
            )
            .unwrap();
        assert!(
            out.redactions >= 2,
            "PAN + secret marker should both redact: {out:?}"
        );
        assert!(
            !out.payload.contains("4111111111111111"),
            "PAN leaked: {}",
            out.payload
        );
        // The secret VALUE must be gone, not just the marker label (the old relabel-only bug shipped
        // the value in full). This assertion fails on that bug.
        assert!(
            !out.payload.contains("hunter2"),
            "secret VALUE leaked: {}",
            out.payload
        );
        assert!(
            !out.payload.contains("SECRET="),
            "secret marker leaked: {}",
            out.payload
        );
        // Surrounding non-secret text is preserved.
        assert!(
            out.payload.contains("to the ticket"),
            "over-redacted: {}",
            out.payload
        );
    }

    #[test]
    fn egress_dlp_redacts_separator_formatted_pans() {
        // THE adversarial bypass the audit named: a PAN split by spaces/hyphens escaped the
        // contiguous-run redactor. These must now redact (Luhn-validated card numbers).
        let g = MarkerEgressGuard;
        let cid = ConnectorId::from("gitlab");
        for pan in [
            "4111 1111 1111 1111", // Visa, space-grouped
            "4111-1111-1111-1111", // Visa, hyphen-grouped
            "3782 822463 10005",   // Amex (15-digit), mixed grouping
        ] {
            let text = format!("please charge {pan} today");
            let out = g.filter_egress(&cid, &text);
            assert_eq!(
                out.redactions, 1,
                "exactly one PAN span redacted in {text:?}"
            );
            assert!(
                out.payload.contains("[REDACTED-PAN]"),
                "PAN not redacted: {}",
                out.payload
            );
            // Not one raw digit-group of the card survives.
            assert!(
                !out.payload.contains("4111") && !out.payload.contains("822463"),
                "formatted PAN leaked: {}",
                out.payload
            );
            assert!(out.payload.contains("please charge") && out.payload.contains("today"));
        }
    }

    #[test]
    fn egress_dlp_luhn_gates_separator_path_no_over_redaction() {
        let g = MarkerEgressGuard;
        let cid = ConnectorId::from("gitlab");
        // A spaced 16-digit group that FAILS Luhn is not a real card → must NOT be redacted.
        let out = g.filter_egress(&cid, "ref 1111 1111 1111 1111 end");
        assert_eq!(
            out.redactions, 0,
            "non-Luhn spaced group over-redacted: {}",
            out.payload
        );
        assert!(out.payload.contains("1111 1111 1111 1111"));
        // A short spaced number (phone-like, <13 digits) is untouched.
        let phone = g.filter_egress(&cid, "call 98765 43210 now");
        assert_eq!(phone.redactions, 0);
        assert!(phone.payload.contains("98765 43210"));
        // But a CONTIGUOUS ≥12-digit run is still redacted regardless of Luhn (unformatted floor).
        let contig = g.filter_egress(&cid, "num 123456789012 x");
        assert_eq!(contig.redactions, 1);
        assert!(contig.payload.contains("[REDACTED-PAN]"));
    }

    #[test]
    fn gap_ainxt_connector_conn_05_url_dlp_blocks_secret_in_url() {
        // A PAN embedded in a request URL (path or query) must be caught fail-closed — the body-only
        // scan missed it. Before screen_url this URL egressed unredacted.
        let (rt, audit) = runtime_with(Box::new(AllowAllPolicy));
        let p = Principal::user("u", &["connector.gitlab"]);
        let cid = ConnectorId::from("gitlab");
        // PAN in a path segment.
        let err = rt
            .screen_url(
                &p,
                &cid,
                "read",
                "https://gl/api/v4/projects/g%2Fr/repository/files/4111111111111111",
            )
            .unwrap_err();
        assert!(
            matches!(err, ConnectorError::UrlEgressBlocked { redactions, .. } if redactions >= 1),
            "PAN in URL path must be blocked, got {err:?}"
        );
        // PAN in a query parameter value.
        let err2 = rt
            .screen_url(&p, &cid, "read", "https://gl/x?ref=SECRET=hunter2")
            .unwrap_err();
        assert!(matches!(err2, ConnectorError::UrlEgressBlocked { .. }));
        // The audit records the block without echoing the value.
        assert!(audit
            .events()
            .iter()
            .any(|e| e.outcome == "egress-url-blocked"));
        assert!(!err.to_string().contains("4111111111111111"));
    }

    #[test]
    fn gap_ainxt_connector_conn_05_clean_url_passes() {
        let (rt, _a) = runtime_with(Box::new(AllowAllPolicy));
        let p = Principal::user("u", &["connector.gitlab"]);
        let cid = ConnectorId::from("gitlab");
        // A normal GitLab URL (small numeric ids, encoded path) must NOT be over-blocked.
        assert!(rt
            .screen_url(
                &p,
                &cid,
                "read",
                "https://gl/api/v4/projects/g%2Fr/merge_requests/7/notes"
            )
            .is_ok());
    }

    #[test]
    fn gap_ainxt_connector_conn_08_hash_chain_detects_tamper() {
        let audit = HashChainedConnectorAudit::new();
        let mk = |actor: &str, outcome: &str| ConnectorAuditEvent {
            actor: actor.into(),
            connector: "gitlab".into(),
            op: "read".into(),
            resource_present: false,
            outcome: outcome.into(),
        };
        audit.record(mk("u1", "authorized"));
        audit.record(mk("u2", "authz-denied"));
        audit.record(mk("u3", "authorized"));
        // Intact chain verifies, and head advances.
        assert_eq!(audit.verify(), Ok(()));
        assert_ne!(audit.head(), AUDIT_GENESIS);
        assert_eq!(audit.len(), 3);

        // Tamper: silently flip a middle record's outcome (simulating an attacker with store access).
        let mut forged = audit.snapshot();
        forged[1].event.outcome = "authorized".into();
        // The forged link's own hash no longer matches → detected at index 1.
        assert_eq!(HashChainedConnectorAudit::verify_chain(&forged), Err(1));

        // Even if the attacker re-hashes the forged link, its new hash breaks the NEXT link's
        // prev_hash linkage → detected at index 2.
        forged[1].hash =
            HashChainedConnectorAudit::link_hash(&forged[1].prev_hash, &forged[1].event);
        assert_eq!(HashChainedConnectorAudit::verify_chain(&forged), Err(2));
    }

    #[test]
    fn gap_ainxt_connector_conn_08_runtime_audits_through_the_worm_sink() {
        // The tamper-evident sink is a drop-in ConnectorAudit — every admission outcome chains into it.
        let audit = HashChainedConnectorAudit::new();
        let rt = ConnectorRuntime::new(
            registry(),
            Box::new(AllowAllPolicy),
            Box::new(CapabilityConnectorAuthorizer),
            Box::new(MarkerEgressGuard),
            Box::new(audit.clone()),
        );
        let ok = Principal::user("u", &["connector.gitlab"]);
        assert!(rt
            .authorize_use(&ok, &ConnectorId::from("gitlab"), "read", None)
            .is_ok());
        let no = Principal::user("v", &[]);
        assert!(rt
            .authorize_use(&no, &ConnectorId::from("gitlab"), "read", None)
            .is_err());
        assert_eq!(audit.len(), 2);
        assert_eq!(audit.verify(), Ok(()), "runtime-produced chain is intact");
    }

    #[test]
    fn connector_ingress_is_untrusted() {
        let (rt, _a) = runtime_with(Box::new(AllowAllPolicy));
        assert_eq!(rt.ingress_provenance(), Provenance::Connector);
        assert!(
            !rt.ingress_provenance().is_trusted(),
            "connector data must never be trusted"
        );
    }

    // ---- r12: broaden OSS-default egress DLP coverage + guaranteed-defaults constructor ----

    #[test]
    fn r12_egress_dlp_no_over_redaction_of_prose() {
        // The broadened coverage must NOT redact ordinary text: a credential prefix appearing as a
        // substring of a word, a short AKIA-like token, and a certificate PEM are all left intact.
        let g = MarkerEgressGuard;
        let cid = ConnectorId::from("gitlab");
        let out = g.filter_egress(
            &cid,
            "the task-force reviewed ghp_short and a CERTIFICATE block below\n\
             -----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\nok",
        );
        assert_eq!(out.redactions, 0, "prose over-redacted: {}", out.payload);
        assert!(out.payload.contains("task-force"));
        assert!(out.payload.contains("ghp_short")); // too short to be a credential
        assert!(out.payload.contains("-----BEGIN CERTIFICATE-----")); // a cert is not a private key
    }

    #[test]
    fn r12_with_oss_defaults_guarantees_the_dlp_floor_on_the_runtime() {
        // The guaranteed-defaults constructor pre-wires MarkerEgressGuard so a runtime cannot be built
        // without the DLP floor. Egress through it redacts a PAN + a credential; admission still runs.
        let rt = ConnectorRuntime::with_oss_defaults(registry(), Box::new(AllowAllPolicy));
        let p = Principal::user("u", &["connector.gitlab"]);
        let out = rt
            .guard_egress(
                &p,
                &ConnectorId::from("gitlab"),
                "write",
                DataClass::Internal,
                // 4111111111111111 is the reserved Visa test PAN (Luhn-valid, never
                // issued). The PAT keeps the `glpat-` shape the DLP floor matches and
                // says in the value that it is synthetic.
                "pay 4111111111111111 with glpat-example-fake-not-real",
            )
            .unwrap();
        assert!(
            out.redactions >= 2,
            "default DLP floor must redact PAN + credential: {out:?}"
        );
        assert!(!out.payload.contains("4111111111111111"));
        assert!(!out.payload.contains("glpat-example-fake-not-real"));
    }

    #[test]
    fn every_admission_outcome_is_audited() {
        let (rt, audit) = runtime_with(Box::new(AllowAllPolicy));
        let ok = Principal::user("u", &["connector.gitlab"]);
        assert!(rt
            .authorize_use(&ok, &ConnectorId::from("gitlab"), "read", None)
            .is_ok());
        let no = Principal::user("v", &[]);
        assert!(rt
            .authorize_use(&no, &ConnectorId::from("gitlab"), "read", None)
            .is_err());
        let ev = audit.events();
        assert_eq!(ev.len(), 2);
        assert_eq!(ev[0].outcome, "authorized");
        assert_eq!(ev[0].actor, "u");
        assert_eq!(ev[1].outcome, "authz-denied");
        assert!(!ev[0].resource_present);
    }

    // ---- r15: served-daemon entrypoints (dept-policy-from-env, tamper-evident-by-default) ----

    #[test]
    fn r15_dept_policy_from_env_defaults_to_least_privilege_when_unset() {
        let var = "AINXT_TEST_DEPT_RULES_R15_UNSET";
        std::env::remove_var(var);
        let policy = dept_policy_from_env(var);
        // No config at all must NEVER behave like AllowAllPolicy: an ordinary department is denied.
        let p = Principal::user("u", &["connector.gitlab"]).with_department("payments-eng");
        assert_eq!(
            policy.permits(&p, &ConnectorId::from("gitlab")),
            PolicyDecision::Deny(
                "no policy grants connector 'gitlab' to this principal".to_string()
            )
        );
    }

    #[test]
    fn r15_dept_policy_from_env_parses_rules_and_global_allow_and_skips_malformed() {
        let var = "AINXT_TEST_DEPT_RULES_R15_PARSE";
        // A per-connector rule, a global-allow rule, and one malformed entry (no colon) that must be
        // skipped rather than panicking or silently granting anything.
        std::env::set_var(
            var,
            "gitlab:payments-eng, *:platform-team ,not-a-rule,jira: ",
        );
        let policy = dept_policy_from_env(var);
        std::env::remove_var(var);

        let payments = Principal::user("u", &["connector.gitlab"]).with_department("payments-eng");
        assert_eq!(
            policy.permits(&payments, &ConnectorId::from("gitlab")),
            PolicyDecision::Permit
        );
        let platform = Principal::user("v", &["connector.jira"]).with_department("platform-team");
        assert_eq!(
            policy.permits(&platform, &ConnectorId::from("jira")),
            PolicyDecision::Permit,
            "global-allow (*) rule must grant every connector"
        );
        let hr = Principal::user("w", &["connector.gitlab"]).with_department("hr");
        assert!(matches!(
            policy.permits(&hr, &ConnectorId::from("gitlab")),
            PolicyDecision::Deny(_)
        ));
        // The malformed "not-a-rule" and empty-dept "jira: " entries must not have created any grant.
        let nobody = Principal::user("x", &["connector.gitlab"]).with_department("not-a-rule");
        assert!(matches!(
            policy.permits(&nobody, &ConnectorId::from("gitlab")),
            PolicyDecision::Deny(_)
        ));
    }

    #[test]
    fn r15_dept_policy_from_env_empty_string_is_also_least_privilege() {
        let var = "AINXT_TEST_DEPT_RULES_R15_EMPTY";
        std::env::set_var(var, "");
        let policy = dept_policy_from_env(var);
        std::env::remove_var(var);
        let p = Principal::user("u", &["connector.gitlab"]).with_department("payments-eng");
        assert!(matches!(
            policy.permits(&p, &ConnectorId::from("gitlab")),
            PolicyDecision::Deny(_)
        ));
    }

    #[test]
    fn r15_with_oss_defaults_audit_is_tamper_evident_not_in_memory() {
        // The served-daemon entrypoint must select the CHAINED audit sink: `audit_head()` returns
        // `Some` only for a tamper-evident sink (HashChainedConnectorAudit overrides `head_hash`);
        // InMemoryConnectorAudit (what the reserved daemon currently wires directly) would give `None`.
        let rt = ConnectorRuntime::with_oss_defaults(registry(), Box::new(AllowAllPolicy));
        let before = rt.audit_head();
        assert!(
            before.is_some(),
            "with_oss_defaults must wire a tamper-evident audit sink, got a non-chained one"
        );
        let p = Principal::user("u", &["connector.gitlab"]);
        rt.authorize_use(&p, &ConnectorId::from("gitlab"), "read", None)
            .unwrap();
        let after = rt.audit_head();
        assert!(after.is_some());
        assert_ne!(
            before, after,
            "recording an event must advance the tamper-evident chain head"
        );
    }

    #[test]
    fn r15_plain_in_memory_audit_has_no_tamper_evidence_anchor() {
        // Contrast case: a runtime built with the CURRENT served-daemon composition (`::new` +
        // `InMemoryConnectorAudit`) has no chain head at all — proving `with_oss_defaults` is a real,
        // observable behavioral upgrade, not just a doc-comment claim.
        let (rt, _audit) = runtime_with(Box::new(AllowAllPolicy)); // runtime_with uses InMemoryConnectorAudit
        assert_eq!(
            rt.audit_head(),
            None,
            "InMemoryConnectorAudit is not tamper-evident and must report no chain head"
        );
    }
}
