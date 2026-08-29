// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! ainxt-tools — the Tool Runtime + the Side-Effect Ledger (ADR-002/013).
//!
//! The payment-critical guarantee: a side-effecting tool (create-MR, send-email,
//! **initiate-settlement**) executes **at most once** per idempotency key. A retried
//! dispatch with the same key returns the stored result instead of re-executing — no double
//! debit, no double MR. Multi-step actions run as **sagas** with compensation; a lost-ack
//! ("in-doubt") claim is resolved by a **reconciler**, never silently re-run.
//!
//! Invariants enforced here:
//! * A side-effecting tool MUST supply a **purely semantic** idempotency key (a timestamp or
//!   random component would silently reopen the double-execution hole — ADR-013). Missing key
//!   ⇒ the dispatch is blocked, not guessed.
//! * The ledger can be **durable** ([`EventLogLedger`]) so exactly-once holds across restarts.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ainxt_eventlog::EventLog;
use ainxt_types::DataClass;

// GAP-FIX tooling-mcp-plugins-routing — `hooks.rs` (the deterministic pre/post-hook "guardrails"
// box of the reference Tool-Calling Layer architecture — see its module doc) existed as a fully
// implemented, unit-tested file on disk but was never declared as a module anywhere in this crate
// (no `mod hooks;`/`pub mod hooks;` and no `#[path]` alternate reference): it was not compiled into
// `ainxt-tools` at all, so it had ZERO callers by construction, not merely zero *served* callers.
// Declaring it here makes `HookRegistry`/`PreHook`/`PostHook` part of the crate's public surface;
// `ToolRuntime::execute_dispatch` below is what actually wires the registry into the live dispatch
// path so a registered hook runs on every capability call regardless of origin (native/MCP/plugin).
pub mod hooks;

/// The Tool Runtime's effect classification is the **canonical four-value enum** defined once in the
/// payment-domain crate (ADR-016 §3.1): `Pure | Idempotent | SideEffecting | PaymentInitiating`.
/// IDN-11 wired: rather than re-declare a divergent 3-value copy that folded `Idempotent` into
/// `SideEffecting`, the runtime **adopts** [`ainxt_payments::boundary::PaymentEffectClass`] directly,
/// so the payment boundary has a single source of truth. Its methods drive the live dispatch path:
/// * [`is_dispatchable`](ainxt_payments::boundary::PaymentEffectClass::is_dispatchable) — `false` only
///   for `PaymentInitiating`, the APEX class with **no dispatch arm** ([`ToolRuntime::dispatch`]
///   refuses it unconditionally; [`ToolRuntime::register`] refuses to admit it). An agent therefore
///   *structurally cannot* initiate a payment through a tool call — a non-configurable invariant.
/// * [`requires_ledger`](ainxt_payments::boundary::PaymentEffectClass::requires_ledger) — `true` only
///   for `SideEffecting`; `Idempotent` is world-changing but naturally safe to retry, so it executes
///   WITHOUT a ledger dedup, while `SideEffecting` takes the exactly-once ledger path.
pub use ainxt_payments::boundary::PaymentEffectClass as EffectClass;

/// Strong, conservative payment-initiation name signatures (ADR-016 Layer-6 tripwire, defense in
/// depth). Deliberately NARROW — explicit money-movement verbs only — so it never trips a legitimate
/// side-effecting tool (e.g. a `settle`/`pay` *test* stand-in that only exercises the ledger). The
/// AUTHORITATIVE control is the [`EffectClass::PaymentInitiating`] declaration + the non-dispatchable
/// dispatch arm; this heuristic only catches a tool that *lies* about its effect class.
fn is_payment_signature(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    const SIGS: &[&str] = &[
        "initiate_payment",
        "payment_initiation",
        "wire_transfer",
        "fund_transfer",
        "credit_transfer",
        "disburse",
        "remittance",
        "settlement_instruction",
        "move_money",
    ];
    SIGS.iter().any(|s| n.contains(s))
}

/// How dangerous a capability is — the risk ladder the design (§1.1) uses to drive both the
/// approval gate and the two-phase-commit requirement (§1.4).
///
/// * `Low` — no gate.
/// * `Elevated` — requires the approval gate (a human/policy must clear it) but is a single-phase
///   action.
/// * `High` — the legacy approval-gate tier the engine already gates on
///   (`ainxt-runtime` compares `risk_tier(..) == Some(RiskTier::High)`); retained verbatim so that
///   established call-site is untouched. Treated as approval-requiring, single-phase.
/// * `HighRisk` — settlement-adjacent, bulk-write, or irreversible. Requires **both** the approval
///   gate **and** two-phase commit: it is structurally non-dispatchable in one shot
///   ([`ToolRuntime::dispatch`] refuses it) and can only fire via [`ToolRuntime::dry_run`] →
///   [`ToolRuntime::commit`] (§1.4). An agent cannot skip the preview step for the actions that
///   most need one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskTier {
    Low,
    Elevated,
    High,
    HighRisk,
}

impl RiskTier {
    /// Whether an approval gate must clear this call before it can execute. Everything above `Low`
    /// requires approval; the engine's own gate keys on `High` specifically, but `Elevated` and
    /// `HighRisk` are approval-requiring too.
    pub fn requires_approval(self) -> bool {
        !matches!(self, RiskTier::Low)
    }

    /// Whether this tier requires the §1.4 two-phase (`dry_run` → `commit`) contract. Only the apex
    /// `HighRisk` tier does — direct [`ToolRuntime::dispatch`] of such a tool is refused.
    pub fn requires_two_phase(self) -> bool {
        matches!(self, RiskTier::HighRisk)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolError {
    Execution(String),
}

// ============ §4.2 tri-signal data-class classification of a tool call (ADR-012) ============
//
// The data-class of a tool call is NOT read off a single field — a tool that lies (or omits) its
// declared class, args that smuggle a PAN into a "read-only" tool, and an off-box destination each
// tell part of the story. §4.2 fuses THREE independent signals and takes the **most sensitive**:
//
//   1. declared capability class  — what the tool/registry *claims* ([`Tool::declared_data_class`])
//   2. compliance scan of the ARGS — what the args actually *contain* ([`ArgClassScanner`])
//   3. destination / egress class  — where the data is *going* ([`Tool::destination_data_class`])
//
// Disagreement never averages and never trusts the lowest: it **escalates to the most sensitive**
// signal. This is the data-class that then gates model ROUTING (a regulated/PII class must stay on
// in-house models, ADR-012) and whether an extra APPROVAL step is warranted. It is a *classification*
// — it never DENIES the turn (clearance is a retrieval read-filter, not an admission gate).

/// Which of the three §4.2 signals a classification attributes a class to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassSignal {
    /// Signal 1 — the tool's own declared class ([`Tool::declared_data_class`]).
    Declared,
    /// Signal 2 — the compliance scan of the call's args ([`ArgClassScanner`]).
    ArgScan,
    /// Signal 3 — the destination/egress class ([`Tool::destination_data_class`]).
    Destination,
}

/// The three raw signal readings for one tool call, retained for audit alongside the fused verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataClassSignals {
    /// Signal 1: always present (the trait method has a default).
    pub declared: DataClass,
    /// Signal 2: `None` when the arg scan finds nothing sensitive.
    pub scanned: Option<DataClass>,
    /// Signal 3: `None` when the call has no off-box destination floor.
    pub destination: Option<DataClass>,
}

/// The fused §4.2 verdict: the effective data-class of a tool call plus the provenance a reviewer /
/// the router needs. `class` is the **maximum** (most sensitive) of the present signals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveDataClass {
    /// The effective (most-sensitive) class — the one that gates routing/approval.
    pub class: DataClass,
    /// `true` iff the present signals did NOT all agree — i.e. the effective class was reached by
    /// escalating above at least one lower signal. This is the auditable "we escalated" flag.
    pub escalated: bool,
    /// Every signal that reads at the effective class (the driver(s) of the verdict). Sorted in
    /// `Declared, ArgScan, Destination` order for determinism.
    pub drivers: Vec<ClassSignal>,
    /// The raw signal readings, for the audit record.
    pub signals: DataClassSignals,
}

impl EffectiveDataClass {
    /// Fuse the three signals: the effective class is the most sensitive present reading; on any
    /// disagreement we escalate to it (never average, never trust the lowest). `declared` is always
    /// present; `scanned`/`destination` are `None` when their signal found nothing.
    pub fn fuse(
        declared: DataClass,
        scanned: Option<DataClass>,
        destination: Option<DataClass>,
    ) -> Self {
        // Candidate (signal, class) pairs actually present this call — declared always is.
        let candidates: [(ClassSignal, Option<DataClass>); 3] = [
            (ClassSignal::Declared, Some(declared)),
            (ClassSignal::ArgScan, scanned),
            (ClassSignal::Destination, destination),
        ];
        // Most sensitive present class = the effective class (DataClass is Ord, higher = more
        // sensitive). Declared guarantees at least one present, so `class` is always defined.
        let class = candidates
            .iter()
            .filter_map(|(_, c)| *c)
            .max()
            .unwrap_or(declared);
        // Disagreement = the present readings are not all identical. If any present signal differs
        // from the effective class, we escalated above it.
        let escalated = candidates
            .iter()
            .filter_map(|(_, c)| *c)
            .any(|c| c != class);
        let drivers = candidates
            .iter()
            .filter_map(|(sig, c)| c.filter(|c| *c == class).map(|_| *sig))
            .collect();
        EffectiveDataClass {
            class,
            escalated,
            drivers,
            signals: DataClassSignals {
                declared,
                scanned,
                destination,
            },
        }
    }

    /// Routing consequence (ADR-012): a regulated/PII effective class must be served by an in-house
    /// model — it may never be routed to a cloud provider. This is a routing eligibility hint the
    /// Model Router consumes; it is NOT a turn denial.
    pub fn must_stay_in_house(&self) -> bool {
        self.class.is_regulated()
    }
}

/// §4.2 **signal 2 — compliance scan of the args**. Given a tool call's raw args, returns the
/// *highest* data-class the scan detects present, or `None` if the args carry nothing sensitive.
///
/// This is the ADR-012 data-CLASSIFIER seam — distinct from the compliance *redactor* (which rewrites
/// text): here we only need to know the sensitivity class the args imply, to fuse it with the other
/// two signals. Production plugs a PCI/DSS classifier in behind this trait; the OSS default
/// ([`MarkerArgScanner`]) is a std-only, deterministic detector of a few unmistakable markers so the
/// tri-signal pipeline is real and testable offline. The scanner NEVER blocks — it classifies.
pub trait ArgClassScanner: Send + Sync {
    fn classify_args(&self, args: &str) -> Option<DataClass>;
}

/// The std-only default [`ArgClassScanner`]: deterministic detection of a few unmistakable markers,
/// returning the most sensitive class found. Intentionally NARROW (high precision over recall) — the
/// a production classifier replaces it behind the same trait. Never blocks; only classifies.
///
/// * a Luhn-valid 13–19 digit card number, or any run of 12+ digits (PAN / account-like) ⇒
///   [`DataClass::RegulatedPayment`];
/// * an email address, an Aadhaar-like 12-digit group, or an explicit PII marker ⇒ [`DataClass::Pii`];
/// * a marked secret (`credential=`, `api_key:`, `token=`) ⇒ [`DataClass::Confidential`].
///
/// The verdict is the maximum over everything detected.
#[derive(Debug, Clone, Copy, Default)]
pub struct MarkerArgScanner;

impl MarkerArgScanner {
    /// Luhn checksum over the ASCII-digit subsequence of `s`, valid only at PAN length 13–19.
    fn is_luhn_card(digits: &[u8]) -> bool {
        if digits.len() < 13 || digits.len() > 19 {
            return false;
        }
        let mut sum = 0u32;
        for (i, &d) in digits.iter().rev().enumerate() {
            let mut v = d as u32;
            if i % 2 == 1 {
                v *= 2;
                if v > 9 {
                    v -= 9;
                }
            }
            // Checkmarx G3: use saturating_add to silence the integer-overflow lint; the
            // maximum possible sum for a 19-digit card is 9×19 = 171, well within u32.
            sum = sum.saturating_add(v);
        }
        sum % 10 == 0
    }

    /// Scans for card/account-like numbers. Returns `(longest_contiguous_run, some_luhn_card)`.
    /// A "card" run may interleave SINGLE space/hyphen separators between digits (matching the
    /// compliance redactor's `detect_cards`), so a spaced/hyphenated PAN (`4111 1111 1111 1111`) is
    /// caught — an attacker cannot launder a card down by inserting the separators the wire uses.
    /// `longest_contiguous_run` counts only unbroken digit runs (the account-number heuristic).
    fn digit_scan(s: &str) -> (usize, bool) {
        let bytes = s.as_bytes();
        let n = bytes.len();
        let mut longest = 0usize;
        let mut luhn = false;
        let mut i = 0usize;
        while i < n {
            if !bytes[i].is_ascii_digit() {
                i += 1;
                continue;
            }
            // Longest contiguous run starting here.
            let mut c = i;
            while c < n && bytes[c].is_ascii_digit() {
                c += 1;
            }
            longest = longest.max(c - i);
            // Card run: digits interleaved with single separators.
            let mut ds: Vec<u8> = Vec::new();
            let mut j = i;
            while j < n {
                let b = bytes[j];
                if b.is_ascii_digit() {
                    ds.push(b - b'0');
                    j += 1;
                } else if (b == b' ' || b == b'-') && j + 1 < n && bytes[j + 1].is_ascii_digit() {
                    j += 1; // single internal separator
                } else {
                    break;
                }
            }
            if Self::is_luhn_card(&ds) {
                luhn = true;
            }
            i = j.max(i + 1);
        }
        (longest, luhn)
    }

    /// A cheap `local@domain.tld` email presence check (no full RFC parse — precision over recall).
    fn has_email(s: &str) -> bool {
        for (idx, _) in s.match_indices('@') {
            let (left, right) = (&s[..idx], &s[idx + 1..]);
            let local_ok = left
                .rsplit(|c: char| c.is_whitespace() || c == '<' || c == ',')
                .next()
                .map(|l| !l.is_empty() && l.chars().all(|c| !c.is_whitespace()))
                .unwrap_or(false);
            let domain = right
                .split(|c: char| c.is_whitespace() || c == '>' || c == ',')
                .next()
                .unwrap_or("");
            if local_ok && domain.contains('.') && !domain.starts_with('.') {
                let tld = domain.rsplit('.').next().unwrap_or("");
                if tld.len() >= 2 && tld.chars().all(|c| c.is_ascii_alphabetic()) {
                    return true;
                }
            }
        }
        false
    }
}

impl ArgClassScanner for MarkerArgScanner {
    fn classify_args(&self, args: &str) -> Option<DataClass> {
        let lower = args.to_ascii_lowercase();
        let mut class: Option<DataClass> = None;
        let raise = |c: DataClass, cur: &mut Option<DataClass>| {
            *cur = Some(cur.map_or(c, |e| e.max(c)));
        };

        // Confidential: an explicitly marked secret. The exact-substring marker list below is fast
        // but brittle: it misses `credential : abc123` (whitespace before the separator) and
        // `api-key=...` / `client-secret=...` (hyphenated key spellings) — a payload that reads as
        // an obvious secret assignment to a human reviewer but slips past every literal substring
        // here. GAP-FIX tooling-mcp-plugins-routing — `re2_detectors::is_secret_assignment` (the
        // §1.9 canonical, CI-guaranteed-linear-time pattern set) had zero callers from any live
        // detector; its `\s*[:=]\s*` + `[_-]?` pattern is exactly whitespace/hyphen-tolerant where
        // this substring list is not, so wiring it in HERE — the served engine's default
        // `ArgClassScanner` ([`default_hardened_scanner`], installed by `Engine::new` at
        // `ainxt-runtime`'s composition root) — closes a real detection gap rather than adding a
        // redundant duplicate check. `re2_detectors::is_email`/`is_pan_like`/`is_aadhaar_like` stay
        // unwired deliberately: `has_email`/`digit_scan` below already cover that same ground at
        // least as precisely (this is the "genuinely superseded, don't force it" half of the call).
        const SECRET_MARKERS: &[&str] = &[
            "password=",
            "password:",
            "passwd=",
            "secret=",
            "secret:",
            "api_key=",
            "api_key:",
            "apikey=",
            "access_token=",
            "client_secret=",
            "token=",
        ];
        if SECRET_MARKERS.iter().any(|m| lower.contains(m))
            || crate::re2_detectors::is_secret_assignment(args)
        {
            raise(DataClass::Confidential, &mut class);
        }

        // RegulatedPayment: a card/account-like number.
        let (longest_run, luhn) = Self::digit_scan(args);
        if luhn || longest_run >= 12 {
            raise(DataClass::RegulatedPayment, &mut class);
        }

        // Pii: an email, an explicit PII marker, or an Aadhaar-like 12-digit group.
        const PII_MARKERS: &[&str] = &["aadhaar", "aadhar", "pii", "date_of_birth", "passport"];
        if Self::has_email(args)
            || PII_MARKERS.iter().any(|m| lower.contains(m))
            || longest_run == 12
        {
            raise(DataClass::Pii, &mut class);
        }

        class
    }
}

// ============================ Detector DoS hardening (§1.9, gap [20]) ============================
//
// The arg-class scanner (§4.2 signal 2) runs over attacker-influenceable text — args a poisoned
// document or a remote MCP tool result steered the model into producing. An unbounded input or a
// catastrophically-backtracking pattern would turn the *defensive* layer into the outage (ReDoS,
// pinned worker). This wrapper hardens ANY [`ArgClassScanner`] as an AVAILABILITY boundary, per §1.9:
//   * INPUT BOUNDED before any pass — the payload is chunked (with overlap so a token straddling a
//     boundary is still caught) and each chunk is scanned in O(chunk), never O(whole payload);
//   * PER-CALL WALL-CLOCK BUDGET — the scan runs under a budget on a worker thread;
//   * FAIL-CLOSED — a scan that exceeds its budget does NOT wave the payload through: it returns the
//     most-sensitive class, so an un-scannable payload is treated as un-sendable / must-stay-in-house.
//
// The default [`MarkerArgScanner`] is itself regex-free (linear byte scans by construction), so it
// already satisfies the §1.9 "guaranteed-linear-time engine" mandate for THIS detector — there is no
// backtracking regex to weaponize here. The platform-wide RE2 CI mandate over the full PII/PAN/secret
// rule-set lives with the compliance detector crate; this wrapper is the availability half applied at
// the tool-runtime boundary.

/// A DoS-hardened [`ArgClassScanner`] decorator (§1.9): input-bounded chunking + a per-call wall-clock
/// budget + fail-closed on timeout. Wraps any inner scanner (including a production classifier)
/// with no change to the classification contract — only its availability posture.
pub struct BoundedArgScanner<S: ArgClassScanner + 'static> {
    inner: Arc<S>,
    /// Max characters scanned per chunk (input is chunked to this, so per-chunk work is bounded).
    max_chunk: usize,
    /// Characters of overlap between consecutive chunks, so a sensitive token split across a chunk
    /// boundary is still seen whole by at least one chunk.
    overlap: usize,
    /// Per-call wall-clock budget; a scan exceeding it fails closed.
    budget: std::time::Duration,
    /// The class returned when the scan cannot complete in budget (fail-closed). The MOST sensitive
    /// class, so an un-scannable payload routes in-house / blocks egress rather than being waved
    /// through.
    fail_closed_class: DataClass,
}

impl<S: ArgClassScanner + 'static> BoundedArgScanner<S> {
    /// Sensible defaults: 16 KiB chunks, 64-char overlap, 250 ms budget, fail-closed to
    /// `RegulatedPayment` (the most sensitive class).
    pub fn new(inner: S) -> Self {
        BoundedArgScanner {
            inner: Arc::new(inner),
            max_chunk: 16 * 1024,
            overlap: 64,
            budget: std::time::Duration::from_millis(250),
            fail_closed_class: DataClass::RegulatedPayment,
        }
    }
    pub fn with_max_chunk(mut self, max_chunk: usize) -> Self {
        self.max_chunk = max_chunk.max(1);
        self
    }
    pub fn with_overlap(mut self, overlap: usize) -> Self {
        self.overlap = overlap;
        self
    }
    pub fn with_budget(mut self, budget: std::time::Duration) -> Self {
        self.budget = budget;
        self
    }
    pub fn with_fail_closed_class(mut self, class: DataClass) -> Self {
        self.fail_closed_class = class;
        self
    }

    /// Split into overlapping char-boundary chunks so per-chunk work is bounded and no chunk slices a
    /// multi-byte char. The overlap keeps a token straddling a boundary intact in at least one chunk.
    fn chunks(&self, args: &str) -> Vec<String> {
        let chars: Vec<char> = args.chars().collect();
        if chars.len() <= self.max_chunk {
            return vec![args.to_string()];
        }
        let step = self.max_chunk.saturating_sub(self.overlap).max(1);
        let mut out = Vec::new();
        let mut start = 0usize;
        while start < chars.len() {
            let end = (start + self.max_chunk).min(chars.len());
            out.push(chars[start..end].iter().collect());
            if end == chars.len() {
                break;
            }
            start += step;
        }
        out
    }
}

/// The clean, discoverable §1.9 entrypoint the served engine installs by default: the std-only
/// [`MarkerArgScanner`] wrapped in the DoS-hardening [`BoundedArgScanner`] decorator (input bounding
/// + per-call wall-clock budget + fail-closed). Because `MarkerArgScanner` is itself regex-free —
/// pure linear byte scans, no backtracking engine — the pair satisfies the §1.9 "guaranteed
/// linear-time" mandate for this detector *by construction of the scanner*, not by hand-auditing a
/// regex, and adds the availability boundary on top. Classification of normal (in-budget) input is
/// identical to the bare scanner (see the r11/r12 detector tests), so wiring this as the live-path
/// default hardens availability without changing detection behavior. A deployment plugs a region-specific
/// PCI/DSS classifier in as the inner `S` and inherits the same hardening unchanged.
#[allow(clippy::doc_lazy_continuation)]
pub fn default_hardened_scanner() -> BoundedArgScanner<MarkerArgScanner> {
    BoundedArgScanner::new(MarkerArgScanner)
}

impl<S: ArgClassScanner + 'static> ArgClassScanner for BoundedArgScanner<S> {
    fn classify_args(&self, args: &str) -> Option<DataClass> {
        let chunks = self.chunks(args);
        let inner = Arc::clone(&self.inner);
        let (tx, rx) = std::sync::mpsc::channel();
        // Run the bounded chunk scan under the wall-clock budget on a worker thread. A well-behaved
        // scanner returns far within budget; a pathological one cannot pin the calling turn.
        std::thread::spawn(move || {
            let mut cls: Option<DataClass> = None;
            for chunk in &chunks {
                if let Some(c) = inner.classify_args(chunk) {
                    cls = Some(cls.map_or(c, |e| e.max(c)));
                }
            }
            let _ = tx.send(cls);
        });
        match rx.recv_timeout(self.budget) {
            Ok(cls) => cls,
            // Fail closed: the payload could not be scanned in budget → treat it as the most sensitive
            // class (un-scannable ⇒ un-sendable / must-stay-in-house), never waved through as `None`.
            Err(_) => Some(self.fail_closed_class),
        }
    }
}

// ============================ Guaranteed-linear-time detector engine mandate (§1.9) ============================
//
// §1.9 mandates: "All PII/PAN/secret patterns compile on a RE2 / guaranteed-linear-time engine — no
// backtracking constructs, so catastrophic patterns are impossible BY CONSTRUCTION OF THE ENGINE, not
// by hand-auditing each regex. A pattern that will not compile under RE2 is a rejected pattern,
// enforced in CI over the detector rule-set, so a well-meaning contributor cannot land a backtracking
// regex that reopens the hole." `MarkerArgScanner` above already satisfies this by being regex-free
// entirely (pure linear byte scans — no engine to weaponize). This module is the complementary case:
// a canonical, reusable set of PII/PAN/secret patterns for detectors that DO want regex expressiveness,
// compiled EXCLUSIVELY on Rust's `regex` crate.
//
// Why `regex` structurally satisfies "RE2-class, enforced in CI, not by hand-auditing": Rust's `regex`
// crate compiles every pattern to a finite automaton (Thompson NFA / DFA), never a backtracking VM —
// backreferences and lookaround (the constructs a backtracking engine needs to exhibit catastrophic
// blowup) are **not expressible in its grammar at all**. A pattern requiring them is therefore a
// **compile-time rejection** (`Regex::new` returns `Err`), not a runtime latency bug waiting to be
// discovered under adversarial load. Combined with the eager, panic-on-failure compilation below, a
// contributor who edits a canonical pattern into something the engine can't express fails the very
// first `cargo build`/`cargo test` that exercises it — CI enforcement that is structural, not a linter
// someone can silence.
pub mod re2_detectors {
    use std::sync::OnceLock;

    /// Compile a pattern exactly once and panic loudly if it doesn't compile under the
    /// guaranteed-linear-time engine — the concrete form of "a pattern that will not compile under
    /// RE2 is a rejected pattern" (§1.9). This can only ever be reached from the canonical patterns
    /// below, each covered by [`all_pattern_sources`] and the CI-mandate test that iterates it.
    fn compiled(
        cell: &'static OnceLock<regex::Regex>,
        pattern: &'static str,
    ) -> &'static regex::Regex {
        cell.get_or_init(|| {
            regex::Regex::new(pattern).unwrap_or_else(|e| {
                panic!(
                    "§1.9 CI mandate violation: pattern `{pattern}` does not compile on the \
                     guaranteed-linear-time engine: {e}"
                )
            })
        })
    }

    static EMAIL: OnceLock<regex::Regex> = OnceLock::new();
    const EMAIL_PATTERN: &str = r"[[:alnum:].+_-]+@[[:alnum:].-]+\.[[:alpha:]]{2,}";
    /// An email address — linear-time by construction of the engine, not by hand review.
    pub fn is_email(s: &str) -> bool {
        compiled(&EMAIL, EMAIL_PATTERN).is_match(s)
    }

    static PAN_LIKE: OnceLock<regex::Regex> = OnceLock::new();
    const PAN_LIKE_PATTERN: &str = r"(?:\d[ -]?){13,19}";
    /// A 13-19 digit run, optionally space/hyphen separated (card/account-number shape) — the
    /// regex-engine-backed equivalent of [`MarkerArgScanner::digit_scan`] for a detector that wants a
    /// single expressive pattern rather than hand-rolled byte scanning.
    pub fn is_pan_like(s: &str) -> bool {
        compiled(&PAN_LIKE, PAN_LIKE_PATTERN).is_match(s)
    }

    static SECRET_ASSIGNMENT: OnceLock<regex::Regex> = OnceLock::new();
    const SECRET_ASSIGNMENT_PATTERN: &str = r"(?i)\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|client[_-]?secret|token)\s*[:=]\s*\S+";
    /// `key = value` / `key: value` style secret assignment (password, api_key, token, ...).
    pub fn is_secret_assignment(s: &str) -> bool {
        compiled(&SECRET_ASSIGNMENT, SECRET_ASSIGNMENT_PATTERN).is_match(s)
    }

    static AADHAAR_LIKE: OnceLock<regex::Regex> = OnceLock::new();
    const AADHAAR_LIKE_PATTERN: &str = r"\b\d{4}[ -]?\d{4}[ -]?\d{4}\b";
    /// A 12-digit group, optionally space/hyphen-separated in 4-4-4 blocks (Aadhaar shape).
    pub fn is_aadhaar_like(s: &str) -> bool {
        compiled(&AADHAAR_LIKE, AADHAAR_LIKE_PATTERN).is_match(s)
    }

    /// Every canonical pattern's name and source string, for the CI-mandate test to iterate. A new
    /// canonical pattern that is added without being listed here is a review-time nit, not a hidden
    /// gap — but it also means the mandate test cannot cover it, so keep this list current.
    pub fn all_pattern_sources() -> Vec<(&'static str, &'static str)> {
        vec![
            ("email", EMAIL_PATTERN),
            ("pan_like", PAN_LIKE_PATTERN),
            ("secret_assignment", SECRET_ASSIGNMENT_PATTERN),
            ("aadhaar_like", AADHAAR_LIKE_PATTERN),
        ]
    }
}

// ============================ Tool argument schema (ADR-002) ============================

/// A scalar argument type (the minimal, dependency-light schema vocabulary).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldType {
    String,
    Integer,
    Number,
    Boolean,
}

/// One field of a structured (object) argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub name: String,
    pub ty: FieldType,
    pub required: bool,
}

impl Field {
    pub fn required(name: &str, ty: FieldType) -> Self {
        Field {
            name: name.into(),
            ty,
            required: true,
        }
    }
    pub fn optional(name: &str, ty: FieldType) -> Self {
        Field {
            name: name.into(),
            ty,
            required: false,
        }
    }
}

/// The shape of a tool's arguments. `Text` = a free-form string (no structured validation);
/// `Object` = a JSON object with typed fields (validated before dispatch). This is the seam a
/// proc-macro "derive from struct" would target later; the vocabulary is intentionally small so
/// it maps cleanly onto every provider's function-calling schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParamSpec {
    Text,
    Object {
        fields: Vec<Field>,
        additional: bool,
    },
}

/// A tool's self-description: the manifest entry a model's function-calling list is built from,
/// identical whether the tool is native or an MCP adapter (ADR-002: MCP == native).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolSchema {
    pub name: String,
    pub description: String,
    pub parameters: ParamSpec,
}

/// Validate raw `args` against a [`ParamSpec`]. `Text` accepts anything; `Object` requires the
/// args to be a JSON object with all required fields present and each present field of the
/// declared type — so malformed / partial tool-call JSON is rejected cleanly (fed back to the
/// model to retry) rather than reaching the tool.
pub fn validate_args(spec: &ParamSpec, args: &str) -> Result<(), String> {
    let ParamSpec::Object { fields, additional } = spec else {
        return Ok(());
    };
    let value: serde_json::Value =
        serde_json::from_str(args).map_err(|e| format!("arguments are not valid JSON: {e}"))?;
    let obj = value
        .as_object()
        .ok_or_else(|| "arguments must be a JSON object".to_string())?;
    for f in fields {
        match obj.get(&f.name) {
            // An explicit JSON `null` is treated as absent (models routinely emit optional params
            // as null) — accepted for optional fields, "missing" for required ones.
            None | Some(serde_json::Value::Null) => {
                if f.required {
                    return Err(format!("missing required field '{}'", f.name));
                }
            }
            Some(v) => {
                let ok = match f.ty {
                    FieldType::String => v.is_string(),
                    FieldType::Integer => v.is_i64() || v.is_u64(),
                    FieldType::Number => v.is_number(),
                    FieldType::Boolean => v.is_boolean(),
                };
                if !ok {
                    return Err(format!(
                        "field '{}' has the wrong type (expected {:?})",
                        f.name, f.ty
                    ));
                }
            }
        }
    }
    if !additional {
        for k in obj.keys() {
            if !fields.iter().any(|f| &f.name == k) {
                return Err(format!("unexpected field '{k}'"));
            }
        }
    }
    Ok(())
}

/// Canonicalize a `(name, args)` pair into a **retry-stable** exactly-once / dedup key.
///
/// JSON args are normalized — object keys sorted (recursively) and whitespace stripped — so a
/// semantically-identical retry that reorders fields or reformats whitespace maps to the SAME key
/// (a lost-ack retry must be deduped, not double-executed — ADR-013). Non-JSON args fall back to
/// the raw string. NOTE: numeric *format* is not normalized (`100` and `100.0` are distinct JSON);
/// prefer a stable business identifier for the strongest guarantee where one exists.
pub fn canonical_key(name: &str, args: &str) -> String {
    let canon = match serde_json::from_str::<serde_json::Value>(args) {
        Ok(v) => canonicalize_json(&v),
        Err(_) => args.to_string(),
    };
    format!("{name}|{canon}")
}

fn canonicalize_json(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            let inner: Vec<String> = keys
                .iter()
                .map(|k| {
                    let key = serde_json::Value::String((*k).clone()).to_string();
                    format!("{key}:{}", canonicalize_json(&m[*k]))
                })
                .collect();
            format!("{{{}}}", inner.join(","))
        }
        serde_json::Value::Array(a) => {
            let inner: Vec<String> = a.iter().map(canonicalize_json).collect();
            format!("[{}]", inner.join(","))
        }
        other => other.to_string(),
    }
}

/// §0 one-registry vocabulary. The design speaks of **one `Capability` trait** and **one
/// `CapabilityRegistry`**; in this crate those are the established [`Tool`] trait and [`ToolRuntime`]
/// registry. `Capability`/`CapabilityRegistry` are re-export aliases for the *same* items — not a
/// second, parallel abstraction — so a native Rust fn, an MCP-discovered tool (adapted via
/// [`mcp_bridge::McpCapability`]), and a WASM/native plugin export (via
/// [`plugin_bridge::PluginCapability`]) all implement one trait and register into one registry, and
/// nothing downstream branches on origin.
pub use self::Tool as Capability;
pub use self::ToolRuntime as CapabilityRegistry;

/// A capability the agent can invoke. (Sync in this slice; async execute wires in with the
/// agent loop later — the ledger semantics are the point here.)
pub trait Tool: Send + Sync {
    fn name(&self) -> &str;
    fn effect_class(&self) -> EffectClass;
    /// Risk tier — `High` means an approval gate must clear it before dispatch. Default `Low`.
    fn risk_tier(&self) -> RiskTier {
        RiskTier::Low
    }
    /// Side-effecting tools MUST return `Some(key)` derived **purely from the semantic args**
    /// (no timestamp/random). Pure tools return `None`.
    fn idempotency_key(&self, _args: &str) -> Option<String> {
        None
    }
    /// The resource this call targets (e.g. an account id, a repo), parsed from the args, for
    /// fine-grained *resource*-level authorization. Default `None` = no resource-level authz
    /// (tool-level only). Resource-scoped tools override this.
    fn resource(&self, _args: &str) -> Option<String> {
        None
    }
    /// The tool's argument schema + description — the manifest entry used to build a model's
    /// function-calling list, and to VALIDATE args before dispatch. Default: a free-form `Text`
    /// argument (no structured validation). Structured tools override.
    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: self.name().into(),
            description: String::new(),
            parameters: ParamSpec::Text,
        }
    }
    /// Whether this tool sends data OFF-box / to an external system (network egress). Default
    /// `false`. Egress-capable tools are gated alongside side-effecting ones on an
    /// injection-tainted turn (ADR-009) — a poisoned document must not be able to exfiltrate via
    /// a "read-only" tool. MCP/HTTP adapters set this `true`.
    fn egress(&self) -> bool {
        false
    }
    /// §4.2 **signal 1 — declared capability class**: the data-sensitivity class this capability
    /// *claims* it handles. This is the tool author's / registry's own assertion and is therefore
    /// never trusted alone — it is fused with the arg-scan (signal 2) and destination (signal 3)
    /// signals by [`ToolRuntime::classify_data_class`], which escalates to the most sensitive of the
    /// three. Default `Internal` (an ordinary internal capability); a PII/payment-touching tool
    /// overrides upward. An MCP tool surfaces the server's manifest-declared class here (via the
    /// [`mcp_bridge`] adapter), a plugin surfaces its grant's declared class.
    fn declared_data_class(&self) -> DataClass {
        DataClass::Internal
    }
    /// §4.2 **signal 3 — destination / egress class**: the data-class implied by WHERE this call
    /// sends data. The default derives from [`Tool::egress`]: a call that leaves the box
    /// (`egress() == true`) is floored at `Confidential`, because handing data to an off-box
    /// destination must be treated as at least confidential regardless of what the tool *declared*;
    /// an on-box call contributes `None` (no destination floor). A tool with a KNOWN-regulated sink
    /// (a payments rail, a PII export endpoint) overrides this upward to `RegulatedPayment`/`Pii`.
    /// Args are provided so a destination parsed from the call (a URL, a queue name) can refine the
    /// class; the default ignores them.
    fn destination_data_class(&self, _args: &str) -> Option<DataClass> {
        if self.egress() {
            Some(DataClass::Confidential)
        } else {
            None
        }
    }
    /// §1.7: the destination this call's egress reaches (a URL, host, or connector target), if this
    /// call has one and the tool can name it from `args`/its own identity. Default `None` — a tool
    /// that doesn't override this is unaffected by [`ToolRuntime::with_egress_allowlist`] (the check
    /// only fires when a destination IS available, deliberately additive rather than a retrofit onto
    /// every capability at once). An egressing tool that CAN name its destination (an MCP capability
    /// via its server URL, a connector tool via its configured host) should override this so §1.7's
    /// per-capability/per-data-class allow-list can actually gate it.
    fn destination(&self, _args: &str) -> Option<String> {
        None
    }
    /// The **preview** half of two-phase commit (§1.4): compute and return a human-reviewable
    /// description of what a subsequent `commit` WOULD do, **without performing any side effect**.
    /// This runs inside [`ToolRuntime::dry_run`]; it must never call [`Tool::execute`] or otherwise
    /// mutate the world. The default renders a generic preview from the args; a real `HighRisk`
    /// capability (e.g. a settlement or bulk-write) overrides it to render the concrete plan
    /// (amounts, counterparties, affected rows) the approver needs to see. An `Err` aborts the
    /// dry-run before any commit token is issued.
    fn dry_run_preview(&self, args: &str) -> Result<String, ToolError> {
        Ok(format!(
            "dry-run: '{}' would execute with args {} (no side effect performed)",
            self.name(),
            args
        ))
    }
    /// §1.8: whether this capability exposes a downstream reconcile PROBE — a
    /// `reconcile(idempotency_key) -> {Committed|NotFound|Ambiguous}` the active
    /// [`ReconcilerSweeper`] can call to resolve a lost-ack row stuck `PENDING` by querying the
    /// downstream's actual state, rather than escalating on a guess. Default `false` (no probe
    /// declared). **Mandatory** (enforced at registration by [`ToolRuntime::try_register`], not
    /// merely a runtime nicety) for any `SideEffecting` capability at `risk_tier:
    /// `[`RiskTier::HighRisk`]` — the reconciler's own graceful degrade of a probe-less row to
    /// `MANUAL_RECONCILIATION` is the LAST-RESORT path for a capability that legitimately cannot be
    /// probed, never a substitute for building the probe in the first place for the tier that most
    /// needs one. The actual probe logic lives in the [`Reconciler`] impl passed to the sweeper (the
    /// registry only enforces that the capability's manifest CLAIMS to be probed); this is the
    /// governance-time check that a HighRisk SideEffecting tool cannot be registered while silently
    /// declaring it has no way to ever resolve its own lost acks.
    fn has_reconcile_probe(&self) -> bool {
        false
    }
    /// §1.1/§1.3: this capability's manifest-declared `compensate: Option<fn(receipt) -> Action>` —
    /// the undo action for a saga step that already committed, needed when a LATER step in the same
    /// composite action fails. `receipt` is the exact result [`Tool::execute`] returned for the
    /// original call. Default `None`: most capabilities are not compensable (an email already sent
    /// cannot be unsent), which is the honest, correct default — [`ToolRuntime::dispatch_saga`]
    /// reports a step with no declared compensate as `uncompensated` in
    /// [`SagaOutcome::FailedPartial`] rather than silently claiming a rollback that cannot happen. A
    /// genuinely reversible capability (e.g. "create a draft" whose compensate is "delete the draft
    /// by the id `receipt` contains") overrides this.
    fn compensate(&self, _receipt: &str) -> Option<Compensate> {
        None
    }
    fn execute(&self, args: &str) -> Result<String, ToolError>;

    /// Execute this capability **attributed to** `caller` — the per-request acting principal's
    /// `user_id`, exactly as [`ToolRuntime::dispatch_for`]/[`ToolRuntime::dispatch_obo`] already
    /// resolve it for the exactly-once ledger key (§1.2), extended past the ledger to the tool body
    /// itself (GAP-FIX guardrails-injection "connector-provenance lost"). A `Box<dyn Tool>`
    /// registered ONCE into the process-wide, `Arc`-shared [`ToolRuntime`] cannot answer "who is
    /// calling *this time*?" from `&self` alone when many different users' requests dispatch it
    /// concurrently — this method is the seam that lets the ONE registered instance still act
    /// correctly per call, mirroring how [`obo::OboContext`] already gives the dispatch call site
    /// (not the shared registry) the caller's identity.
    ///
    /// Default: ignore `caller` and delegate to [`Tool::execute`] — the overwhelming majority of
    /// tools (native fns, the MCP bridge, WASM/native plugins) have no per-caller downstream
    /// identity and are unaffected by this seam. A connector capability
    /// (`ainxt_connector_http::capability::ConnectorCapability`) overrides this to resolve the REAL
    /// per-request `Principal` and refuses the identity-less [`Tool::execute`] outright, so a
    /// connector call can never be silently attributed to the wrong — or a shared/baked-at-
    /// construction — identity.
    fn execute_as(&self, args: &str, caller: Option<&str>) -> Result<String, ToolError> {
        let _ = caller;
        self.execute(args)
    }

    /// GAP-FIX identity-payments (ADR-016 §6) — whether this call is payment-*adjacent* (more than a
    /// pure read but structurally incapable of moving value — e.g. simulate a settlement, draft a
    /// dispute response) and, if so, the exact `(action_verb, resource)` a
    /// [`ainxt_payments::mandate::PaymentAdjacentMandate`] must authorize before dispatch. Default
    /// `None` — the overwhelming majority of tools are unaffected. A payment-adjacent capability
    /// overrides this so [`ToolRuntime::dispatch_obo_with_pam`]/[`ToolRuntime::dispatch_obo_audited_with_pam`]
    /// enforce the fourth gate automatically (§6: "verified at dispatch, alongside OBO") — this is
    /// checked in ADDITION to, never instead of, the three-layer OBO check the same call already runs.
    fn payment_adjacent_action(&self, _args: &str) -> Option<(String, String)> {
        None
    }

    /// GAP-FIX guardrails-injection "connector-provenance lost" — the [`ainxt_injection::Provenance`]
    /// this capability's RESULT carries when it re-enters the turn. The served engine's post-dispatch
    /// injection scan/quarantine (`ainxt-runtime`) previously tagged EVERY dispatch result
    /// `Provenance::ToolResult` regardless of origin, so a connector-sourced response (email/ticket/
    /// chat/repo content — the textbook indirect-injection vector) was scanned/quarantined/audited
    /// under the generic tag instead of the specifically untrusted-external-data tag the design names.
    /// Default `ToolResult` (a native fn / MCP-bridged / plugin capability is unaffected — byte-
    /// identical to before this method existed); [`ainxt_connector_http::capability::ConnectorCapability`]
    /// overrides this to `Connector`, since every one of its outcomes originates off-box through the
    /// connector USE path. [`ToolRuntime::provenance_of`] is the lookup the engine's dispatch loop
    /// consults per named tool.
    fn tool_provenance(&self) -> ainxt_injection::Provenance {
        ainxt_injection::Provenance::ToolResult
    }
}

/// What the ledger knows about a key when a dispatch claims it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Claim {
    /// Never seen — the claim reserved it (PENDING); the caller may execute.
    Fresh,
    /// Already executed — here is the stored result; DO NOT re-execute.
    Committed(String),
    /// A prior claim reserved it but never committed (crash / lost ack) — must be reconciled.
    InDoubt,
}

/// A `PENDING` ledger row the reconciler sweep (§1.8) may resolve. Carries the probe metadata —
/// the tool and the exact args (the "same idempotency key that was sent") — so the reconciler can
/// query the downstream's *actual* state, plus the logical claim time used for the timeout scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRow {
    /// The idempotency key that identifies this side effect end-to-end.
    pub key: String,
    /// The capability that claimed the slot (for the reconcile probe + incident report).
    pub tool: String,
    /// The exact args of the claimed call (the request the downstream saw).
    pub args: String,
    /// The ledger's logical clock value at claim time — `now() - claimed_at` is the row's age.
    pub claimed_at: u64,
}

/// The exactly-once ledger seam.
///
/// The three core methods ([`claim`](Ledger::claim)/[`commit`](Ledger::commit)/[`fail`](Ledger::fail))
/// own the exactly-once guarantee across retries. The remaining methods are the **active
/// reconciliation** seam (§1.8): they let a background [`ReconcilerSweeper`] find rows stuck
/// `PENDING` past a timeout, take a short lease on each, and — for the durable case — persist the
/// probe metadata and a `MANUAL_RECONCILIATION` escalation. They all carry a default so an existing
/// or minimal [`Ledger`] impl (e.g. a durable one that does not yet support scanning) keeps
/// compiling; [`InMemoryLedger`] implements every one. `now()` returning `0` and `pending_beyond`
/// returning empty means "not scan-capable" — the sweep then finds nothing rather than misbehaving.
pub trait Ledger: Send + Sync {
    fn claim(&self, key: &str) -> Claim;
    fn commit(&self, key: &str, result: &str);
    fn fail(&self, key: &str, reason: &str);

    // ---------------- Active reconciliation seam (§1.8) ----------------

    /// Attach the reconcile-probe metadata (tool + exact args) to a freshly-claimed `PENDING` row.
    /// Called by the dispatch path immediately after a `Fresh` claim and **before** the capability
    /// fires, so that if the process dies mid-flight the stuck row still carries what the reconciler
    /// needs to probe the downstream. Default: no-op (a non-scan-capable ledger keeps no metadata).
    fn record_pending_meta(&self, _key: &str, _tool: &str, _args: &str) {}

    /// The ledger's current logical clock (monotonic; ticks are caller-advanced for determinism, or
    /// wall-clock in a durable impl). Row age is `now() - claimed_at`. Default `0` (no aging).
    fn now(&self) -> u64 {
        0
    }

    /// Every `PENDING` row whose age (`now() - claimed_at`) is **at least** `min_age` and that is not
    /// currently under a live lease — the timed-out lost-ack rows the sweep must resolve. Default
    /// empty (not scan-capable).
    fn pending_beyond(&self, _min_age: u64) -> Vec<PendingRow> {
        Vec::new()
    }

    /// Try to take a short exclusive lease on a `PENDING` row so exactly one node reconciles it.
    /// Returns `true` iff the lease was granted (the row is still `PENDING` and has no live lease).
    /// The lease auto-expires after `lease_ttl` logical ticks, so a crashed reconciler cannot pin a
    /// row forever. Default `false` — a ledger that cannot lease is never swept (the sweep skips it),
    /// which is the safe degradation. This is what makes the sweep idempotent and safe on every node.
    fn try_lease(&self, _key: &str, _owner: &str, _lease_ttl: u64) -> bool {
        false
    }

    /// Move a `PENDING` row to `MANUAL_RECONCILIATION` — the honest terminal state for a row the
    /// reconciler could not resolve automatically (probe `Ambiguous`, or no probe). The row is no
    /// longer swept (no duplicate incidents) and a future retry will not silently re-execute it.
    /// Default: no-op.
    fn escalate_manual(&self, _key: &str, _reason: &str) {}
}

#[derive(Debug, Clone)]
enum Entry {
    Pending,
    Committed(String),
    // The reason is persisted for audit but not read in the claim path (a failed key is retryable).
    Failed(#[allow(dead_code)] String),
}

/// A short exclusive lease on a `PENDING` row (§1.8) — the owning node and its expiry tick.
#[derive(Debug, Clone)]
struct Lease {
    /// Node that holds the lease (retained for audit / debugging of a contended sweep).
    #[allow(dead_code)]
    owner: String,
    expires_at: u64,
}

/// In-memory ledger row. Unlike the durable [`Entry`] (used by [`EventLogLedger`]), the `Pending`
/// variant carries the reconcile-probe metadata + claim time + optional lease that the active
/// reconciler sweep needs, and there is a terminal `Manual` state.
#[derive(Debug, Clone)]
enum MemEntry {
    Pending {
        tool: String,
        args: String,
        claimed_at: u64,
        lease: Option<Lease>,
    },
    Committed(String),
    Failed(#[allow(dead_code)] String),
    /// Escalated to MANUAL_RECONCILIATION — never re-swept, never silently re-executed.
    Manual(#[allow(dead_code)] String),
}

/// In-memory ledger (ephemeral / tests). Also the reference implementation of the §1.8 active
/// reconciliation seam: it records probe metadata at claim, carries a caller-advanced logical clock
/// for the timeout scan, and supports short leases so the sweep is safe to run on every node.
#[derive(Default)]
pub struct InMemoryLedger {
    map: Mutex<HashMap<String, MemEntry>>,
    /// Monotonic logical clock. Advanced explicitly via [`InMemoryLedger::advance`] (deterministic
    /// tests) or overridden by a wall-clock-backed durable ledger; a row claimed at `t` has age
    /// `now() - t`.
    clock: std::sync::atomic::AtomicU64,
}

impl InMemoryLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Advance the logical clock by `ticks` — how a test ages `PENDING` rows past a sweep timeout,
    /// and how a durable deployment would fold in elapsed wall-clock time. Monotonic.
    pub fn advance(&self, ticks: u64) {
        self.clock
            .fetch_add(ticks, std::sync::atomic::Ordering::SeqCst);
    }

    fn lease_is_live(lease: &Option<Lease>, now: u64) -> bool {
        matches!(lease, Some(l) if l.expires_at > now)
    }
}

impl Ledger for InMemoryLedger {
    fn claim(&self, key: &str) -> Claim {
        let now = self.now();
        let mut m = self.map.lock().unwrap();
        match m.get(key) {
            Some(MemEntry::Committed(r)) => Claim::Committed(r.clone()),
            // A row still PENDING (crash/lost ack) or already escalated to MANUAL is in-doubt — never
            // blind-re-executed. A cleanly FAILED row (or an absent one) is safe to (re-)claim.
            Some(MemEntry::Pending { .. }) | Some(MemEntry::Manual(_)) => Claim::InDoubt,
            _ => {
                m.insert(
                    key.to_string(),
                    MemEntry::Pending {
                        tool: String::new(),
                        args: String::new(),
                        claimed_at: now,
                        lease: None,
                    },
                );
                Claim::Fresh
            }
        }
    }
    fn commit(&self, key: &str, result: &str) {
        self.map
            .lock()
            .unwrap()
            .insert(key.to_string(), MemEntry::Committed(result.to_string()));
    }
    fn fail(&self, key: &str, reason: &str) {
        self.map
            .lock()
            .unwrap()
            .insert(key.to_string(), MemEntry::Failed(reason.to_string()));
    }

    fn record_pending_meta(&self, key: &str, tool: &str, args: &str) {
        if let Some(MemEntry::Pending {
            tool: t, args: a, ..
        }) = self.map.lock().unwrap().get_mut(key)
        {
            *t = tool.to_string();
            *a = args.to_string();
        }
    }

    fn now(&self) -> u64 {
        self.clock.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn pending_beyond(&self, min_age: u64) -> Vec<PendingRow> {
        let now = self.now();
        let m = self.map.lock().unwrap();
        // Return ALL timed-out PENDING rows (regardless of lease); `try_lease` is the single
        // exclusivity gate a sweeper passes through before touching a row. A row a peer node already
        // holds a live lease on is still listed here, but this node's `try_lease` will fail and the
        // sweep records it as `skipped_leased` — no double-probe.
        m.iter()
            .filter_map(|(key, entry)| match entry {
                MemEntry::Pending {
                    tool,
                    args,
                    claimed_at,
                    ..
                } if now.saturating_sub(*claimed_at) >= min_age => Some(PendingRow {
                    key: key.clone(),
                    tool: tool.clone(),
                    args: args.clone(),
                    claimed_at: *claimed_at,
                }),
                _ => None,
            })
            .collect()
    }

    fn try_lease(&self, key: &str, owner: &str, lease_ttl: u64) -> bool {
        let now = self.now();
        let mut m = self.map.lock().unwrap();
        match m.get_mut(key) {
            Some(MemEntry::Pending { lease, .. }) => {
                if Self::lease_is_live(lease, now) {
                    return false; // someone else holds a live lease
                }
                *lease = Some(Lease {
                    owner: owner.to_string(),
                    expires_at: now + lease_ttl,
                });
                true
            }
            _ => false,
        }
    }

    fn escalate_manual(&self, key: &str, reason: &str) {
        // Only a still-PENDING row escalates (idempotent: a row already resolved is left alone).
        let mut m = self.map.lock().unwrap();
        if let Some(MemEntry::Pending { .. }) = m.get(key) {
            m.insert(key.to_string(), MemEntry::Manual(reason.to_string()));
        }
    }
}

/// Durable ledger backed by the tamper-evident event log — exactly-once survives restarts.
/// State is reconstructed by replaying the ledger session's records for the key.
pub struct EventLogLedger<L: EventLog> {
    log: L,
    session: String,
    /// Serializes `claim` so its check-then-append is atomic within this process. Without it, two
    /// concurrent claims on the same key both read "not present" and both append "pending",
    /// returning `Fresh` twice → a double-executed side effect (a double debit).
    claim_lock: Mutex<()>,
}

impl<L: EventLog> EventLogLedger<L> {
    pub fn new(log: L) -> Self {
        EventLogLedger {
            log,
            session: "__ledger__".to_string(),
            claim_lock: Mutex::new(()),
        }
    }
    fn current(&self, key: &str) -> Option<Entry> {
        // Last record whose actor == key is the current state.
        self.log
            .records(&self.session)
            .into_iter()
            .rfind(|r| r.actor == key)
            .map(|r| {
                if let Some(rest) = r.text.strip_prefix("committed:") {
                    Entry::Committed(rest.to_string())
                } else if let Some(rest) = r.text.strip_prefix("failed:") {
                    Entry::Failed(rest.to_string())
                } else {
                    Entry::Pending
                }
            })
    }
}

impl<L: EventLog> Ledger for EventLogLedger<L> {
    fn claim(&self, key: &str) -> Claim {
        // Hold the claim lock across the whole check-then-append so two concurrent claims on the
        // same key cannot both read "not present" and both append "pending". Single-process
        // exactly-once; cross-process durability (multiple daemons over one log) needs OS file
        // locking or a DB unique-constraint ledger — the enterprise durable impl.
        let _guard = self.claim_lock.lock().expect("ledger claim lock");
        match self.current(key) {
            Some(Entry::Committed(r)) => Claim::Committed(r),
            Some(Entry::Pending) => Claim::InDoubt,
            _ => {
                let _ = self.log.append(&self.session, key, "ledger", "pending");
                Claim::Fresh
            }
        }
    }
    fn commit(&self, key: &str, result: &str) {
        let _ = self
            .log
            .append(&self.session, key, "ledger", &format!("committed:{result}"));
    }
    fn fail(&self, key: &str, reason: &str) {
        let _ = self
            .log
            .append(&self.session, key, "ledger", &format!("failed:{reason}"));
    }
}

// ============ Durable cross-process exactly-once ledger — the SQL seam (§1.2, gap R+S) ============
//
// [`EventLogLedger`] gives exactly-once WITHIN one process: its check-then-append is made atomic by
// an in-process `claim_lock`. That lock is invisible to a *second* daemon over the same log — two
// nodes both read "key absent" and both append "pending", returning `Fresh` twice → a double debit.
// Payments run N replicas, so exactly-once must be arbitrated by a store the whole cluster shares.
//
// The durable ledger moves that arbitration into the database: the idempotency key is a UNIQUE /
// PRIMARY KEY, and the claim is an atomic **unique-key upsert** — `INSERT ... ON CONFLICT (key) DO
// NOTHING`. The database, not any node's lock, decides who wins the race: exactly one INSERT lands,
// every concurrent duplicate is a no-op that then reads the winner's row. No per-process claim lock
// exists on this path at all — that is the whole point, and what makes it correct across processes.
//
// [`SqlLedger`] is that path, generic over a [`SqlLedgerDriver`] (the atomic-upsert seam). The real
// Postgres driver ([`PostgresSqlLedgerDriver`] over a live [`SqlExecutor`]) needs a running database
// and so is infra-gated; [`InMemorySqlStore`] is the offline reference driver — a *shared* store
// (cheap `Arc` clone) that proves cross-process dedup and drives the §1.8 reconciler sweep offline.

/// The outcome of an atomic unique-key claim against the durable ledger.
///
/// This is what the database's `INSERT ... ON CONFLICT DO NOTHING` (plus a `FAILED`→`PENDING`
/// re-claim) collapses to: either this caller's row landed, or a row for the key already existed and
/// we read its state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SqlClaim {
    /// This caller's INSERT landed (or it re-claimed a cleanly-`FAILED` row) — it owns the slot and
    /// must execute. Exactly one concurrent caller across the whole cluster gets this.
    Won,
    /// A row for the key is already `COMMITTED` — the effect happened once; return the stored result
    /// and DO NOT re-execute (retry / cross-process dedup).
    AlreadyCommitted(String),
    /// A row exists in `PENDING` (another node in-flight or crashed) or `MANUAL` — in-doubt; never
    /// blind-re-execute. The reconciler (§1.8) resolves it.
    InDoubt,
}

/// The durable exactly-once ledger seam (§1.2): a small, database-shaped set of operations whose
/// correctness rests on a UNIQUE constraint on the idempotency key.
///
/// A driver is trusted to make [`claim_upsert`](SqlLedgerDriver::claim_upsert) **atomic** against
/// concurrent callers in *other processes* (a real DB does this with the unique index; the offline
/// [`InMemorySqlStore`] does it under a shared mutex that stands in for that index). Everything else
/// ([`SqlLedger`], the reconciler sweep) is built on top and is driver-agnostic.
pub trait SqlLedgerDriver: Send + Sync {
    /// Atomic unique-key claim. Maps to `INSERT INTO ledger(key,state,claimed_at) VALUES(?, 'PENDING',
    /// ?) ON CONFLICT(key) DO NOTHING`, then — only on conflict — a read and a conditional
    /// `FAILED`→`PENDING` re-claim. Returns [`SqlClaim::Won`] iff THIS call took the slot.
    fn claim_upsert(&self, key: &str, claimed_at: u64) -> SqlClaim;
    /// Attach reconcile-probe metadata to the (own) `PENDING` row: `UPDATE ... SET tool=?, args=?
    /// WHERE key=? AND state='PENDING'`.
    fn set_meta(&self, key: &str, tool: &str, args: &str);
    /// `UPDATE ... SET state='COMMITTED', result=? WHERE key=?` — the terminal success write.
    fn set_committed(&self, key: &str, result: &str);
    /// `UPDATE ... SET state='FAILED', reason=? WHERE key=?` — cleanly failed, re-claimable.
    fn set_failed(&self, key: &str, reason: &str);
    /// `UPDATE ... SET state='MANUAL', reason=? WHERE key=? AND state='PENDING'` — §1.8 escalation.
    fn set_manual(&self, key: &str, reason: &str);
    /// The ledger's current logical clock (a durable driver returns wall-clock epoch seconds; the
    /// offline store returns a caller-advanced tick). Row age is `now() - claimed_at`.
    fn now(&self) -> u64;
    /// Every `PENDING` row aged `>= min_age`: `SELECT key,tool,args,claimed_at FROM ledger WHERE
    /// state='PENDING' AND (now - claimed_at) >= ?`.
    fn pending_beyond(&self, min_age: u64) -> Vec<PendingRow>;
    /// Atomic conditional lease: `UPDATE ... SET lease_owner=?, lease_expires=? WHERE key=? AND
    /// state='PENDING' AND (lease_expires IS NULL OR lease_expires <= now)` — returns rows-affected
    /// `> 0`. Exactly one node's UPDATE lands, so exactly one node reconciles the row.
    fn try_lease(&self, key: &str, owner: &str, lease_ttl: u64) -> bool;
}

/// Durable, cross-process exactly-once ledger over a [`SqlLedgerDriver`].
///
/// It holds **no per-process lock** — unlike [`EventLogLedger`], the exactly-once guarantee is the
/// driver's atomic unique-key upsert, so it holds across processes. Sharing is via the driver: with
/// [`InMemorySqlStore`] every `SqlLedger` built over a clone of the same store sees the same rows,
/// exactly as N daemons see one database.
pub struct SqlLedger<D: SqlLedgerDriver> {
    driver: D,
}

impl<D: SqlLedgerDriver> SqlLedger<D> {
    pub fn new(driver: D) -> Self {
        SqlLedger { driver }
    }
    /// Borrow the backing driver (e.g. to advance the offline clock in a test).
    pub fn driver(&self) -> &D {
        &self.driver
    }
}

impl<D: SqlLedgerDriver> Ledger for SqlLedger<D> {
    fn claim(&self, key: &str) -> Claim {
        match self.driver.claim_upsert(key, self.driver.now()) {
            SqlClaim::Won => Claim::Fresh,
            SqlClaim::AlreadyCommitted(r) => Claim::Committed(r),
            SqlClaim::InDoubt => Claim::InDoubt,
        }
    }
    fn commit(&self, key: &str, result: &str) {
        self.driver.set_committed(key, result);
    }
    fn fail(&self, key: &str, reason: &str) {
        self.driver.set_failed(key, reason);
    }
    fn record_pending_meta(&self, key: &str, tool: &str, args: &str) {
        self.driver.set_meta(key, tool, args);
    }
    fn now(&self) -> u64 {
        self.driver.now()
    }
    fn pending_beyond(&self, min_age: u64) -> Vec<PendingRow> {
        self.driver.pending_beyond(min_age)
    }
    fn try_lease(&self, key: &str, owner: &str, lease_ttl: u64) -> bool {
        self.driver.try_lease(key, owner, lease_ttl)
    }
    fn escalate_manual(&self, key: &str, reason: &str) {
        self.driver.set_manual(key, reason);
    }
}

/// A durable ledger row as the offline store holds it. The `PENDING` variant carries the reconcile
/// metadata + claim tick + optional `(owner, expires)` lease the §1.8 sweep needs.
#[derive(Debug, Clone)]
enum SqlRow {
    Pending {
        tool: String,
        args: String,
        claimed_at: u64,
        lease: Option<(String, u64)>,
    },
    Committed(String),
    Failed(#[allow(dead_code)] String),
    Manual(#[allow(dead_code)] String),
}

#[derive(Default)]
struct SqlStoreState {
    rows: HashMap<String, SqlRow>,
    clock: u64,
}

/// Offline reference driver for [`SqlLedgerDriver`] — an in-memory stand-in for the durable ledger
/// table. It is **shareable**: `clone()` shares one `Arc<Mutex<..>>`, so several [`SqlLedger`]
/// instances built over clones model several processes over ONE database. The mutex stands in for
/// the DB's unique index: `claim_upsert` reads-and-inserts under it, so exactly one of any number of
/// concurrent claims (from any process) wins — cross-process exactly-once, no per-process lock.
#[derive(Clone, Default)]
pub struct InMemorySqlStore {
    inner: Arc<Mutex<SqlStoreState>>,
}

impl InMemorySqlStore {
    pub fn new() -> Self {
        Self::default()
    }
    /// Advance the shared logical clock (ages `PENDING` rows toward the sweep timeout). A durable
    /// driver folds in elapsed wall-clock instead. Monotonic; visible to every process sharing this
    /// store.
    pub fn advance(&self, ticks: u64) {
        self.inner.lock().unwrap().clock += ticks;
    }
    /// Rows currently persisted — the offline analogue of `SELECT count(*)`.
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().rows.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn lease_live(lease: &Option<(String, u64)>, now: u64) -> bool {
        matches!(lease, Some((_, exp)) if *exp > now)
    }
}

impl SqlLedgerDriver for InMemorySqlStore {
    fn claim_upsert(&self, key: &str, claimed_at: u64) -> SqlClaim {
        // The whole read-then-insert runs under one lock — this IS the DB's atomic unique-key
        // upsert. Two processes racing the same key serialize here; exactly one inserts (Won), the
        // rest observe the existing row.
        let mut s = self.inner.lock().unwrap();
        match s.rows.get(key) {
            Some(SqlRow::Committed(r)) => SqlClaim::AlreadyCommitted(r.clone()),
            Some(SqlRow::Pending { .. }) | Some(SqlRow::Manual(_)) => SqlClaim::InDoubt,
            // Absent, or a cleanly-FAILED row → (re-)claim it as PENDING. This is the `ON CONFLICT
            // DO NOTHING` insert plus the conditional FAILED→PENDING re-claim.
            Some(SqlRow::Failed(_)) | None => {
                s.rows.insert(
                    key.to_string(),
                    SqlRow::Pending {
                        tool: String::new(),
                        args: String::new(),
                        claimed_at,
                        lease: None,
                    },
                );
                SqlClaim::Won
            }
        }
    }
    fn set_meta(&self, key: &str, tool: &str, args: &str) {
        if let Some(SqlRow::Pending {
            tool: t, args: a, ..
        }) = self.inner.lock().unwrap().rows.get_mut(key)
        {
            *t = tool.to_string();
            *a = args.to_string();
        }
    }
    fn set_committed(&self, key: &str, result: &str) {
        self.inner
            .lock()
            .unwrap()
            .rows
            .insert(key.to_string(), SqlRow::Committed(result.to_string()));
    }
    fn set_failed(&self, key: &str, reason: &str) {
        self.inner
            .lock()
            .unwrap()
            .rows
            .insert(key.to_string(), SqlRow::Failed(reason.to_string()));
    }
    fn set_manual(&self, key: &str, reason: &str) {
        let mut s = self.inner.lock().unwrap();
        if let Some(SqlRow::Pending { .. }) = s.rows.get(key) {
            s.rows
                .insert(key.to_string(), SqlRow::Manual(reason.to_string()));
        }
    }
    fn now(&self) -> u64 {
        self.inner.lock().unwrap().clock
    }
    fn pending_beyond(&self, min_age: u64) -> Vec<PendingRow> {
        let s = self.inner.lock().unwrap();
        let now = s.clock;
        s.rows
            .iter()
            .filter_map(|(key, row)| match row {
                SqlRow::Pending {
                    tool,
                    args,
                    claimed_at,
                    ..
                } if now.saturating_sub(*claimed_at) >= min_age => Some(PendingRow {
                    key: key.clone(),
                    tool: tool.clone(),
                    args: args.clone(),
                    claimed_at: *claimed_at,
                }),
                _ => None,
            })
            .collect()
    }
    fn try_lease(&self, key: &str, owner: &str, lease_ttl: u64) -> bool {
        let mut s = self.inner.lock().unwrap();
        let now = s.clock;
        match s.rows.get_mut(key) {
            Some(SqlRow::Pending { lease, .. }) => {
                if Self::lease_live(lease, now) {
                    return false;
                }
                *lease = Some((owner.to_string(), now + lease_ttl));
                true
            }
            _ => false,
        }
    }
}

// ---------------- The real Postgres driver (infra-gated) ----------------
//
// The offline store proves the SEAM; the production ledger is a real Postgres table. To keep the
// crate buildable and testable offline (no live DB, no pg client crate vendored), the DB round-trip
// is itself a thin seam — [`SqlExecutor`] — and [`PostgresSqlLedgerDriver`] issues the exact SQL
// through it. Binding a live `tokio-postgres`/`postgres` connection to `SqlExecutor` is the only
// piece that needs running infra; that binding, and the real cross-process dedup it provides, is
// infra-gated. An offline test drives the driver against a recording mock executor to prove it
// emits the load-bearing `ON CONFLICT DO NOTHING` claim and the conditional lease UPDATE.

/// A value bound into a parameterized statement. Deliberately tiny — the ledger only needs text and
/// 64-bit integer params.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SqlValue {
    Text(String),
    Int(i64),
    Null,
}

/// A database error surfaced by a [`SqlExecutor`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqlError(pub String);

impl std::fmt::Display for SqlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "sql error: {}", self.0)
    }
}
impl std::error::Error for SqlError {}

/// The DB round-trip seam a live Postgres connection implements (infra-gated). Kept minimal so the
/// ledger driver is fully testable against a mock offline.
pub trait SqlExecutor: Send + Sync {
    /// Run a parameterized DML statement; return rows affected. This is how the driver learns whether
    /// its `ON CONFLICT DO NOTHING` insert / conditional lease UPDATE actually landed.
    fn execute(&self, sql: &str, params: &[SqlValue]) -> Result<u64, SqlError>;
    /// Run a query returning at most one row of nullable text columns.
    fn query_opt(
        &self,
        sql: &str,
        params: &[SqlValue],
    ) -> Result<Option<Vec<Option<String>>>, SqlError>;
    /// Run a query returning many rows of nullable text columns.
    fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Vec<Option<String>>>, SqlError>;
}

/// The real durable ledger driver over Postgres (infra-gated). Owns a live [`SqlExecutor`] and the
/// canonical SQL; the unique constraint is the `PRIMARY KEY (idempotency_key)`.
pub struct PostgresSqlLedgerDriver<E: SqlExecutor> {
    exec: E,
    table: String,
}

impl<E: SqlExecutor> PostgresSqlLedgerDriver<E> {
    /// Canonical DDL — run once at startup. The PRIMARY KEY is the cross-process exactly-once
    /// arbiter; the CHECK keeps the state machine honest.
    pub const DDL: &'static str = "CREATE TABLE IF NOT EXISTS exactly_once_ledger (\
        idempotency_key TEXT PRIMARY KEY, \
        state TEXT NOT NULL CHECK (state IN ('PENDING','COMMITTED','FAILED','MANUAL')), \
        tool TEXT NOT NULL DEFAULT '', args TEXT NOT NULL DEFAULT '', \
        result TEXT, reason TEXT, claimed_at BIGINT NOT NULL, \
        lease_owner TEXT, lease_expires BIGINT)";

    pub fn new(exec: E) -> Self {
        PostgresSqlLedgerDriver {
            exec,
            table: "exactly_once_ledger".to_string(),
        }
    }

    /// Borrow the backing executor — the seam a live-Postgres binding replaces, and the handle an
    /// offline test uses to inspect the SQL the driver issued.
    pub fn executor(&self) -> &E {
        &self.exec
    }

    /// The atomic claim insert — `ON CONFLICT DO NOTHING` is what makes the DB, not the process,
    /// arbitrate the race.
    fn claim_sql(&self) -> String {
        format!(
            "INSERT INTO {t} (idempotency_key, state, claimed_at) VALUES ($1, 'PENDING', $2) \
             ON CONFLICT (idempotency_key) DO NOTHING",
            t = self.table
        )
    }
    fn reclaim_failed_sql(&self) -> String {
        format!(
            "UPDATE {t} SET state='PENDING', claimed_at=$2, result=NULL, reason=NULL, \
             lease_owner=NULL, lease_expires=NULL WHERE idempotency_key=$1 AND state='FAILED'",
            t = self.table
        )
    }
    fn lease_sql(&self) -> String {
        format!(
            "UPDATE {t} SET lease_owner=$2, lease_expires=$3 WHERE idempotency_key=$1 \
             AND state='PENDING' AND (lease_expires IS NULL OR lease_expires <= $4)",
            t = self.table
        )
    }

    /// Run the DDL. Infra-gated: needs a live connection.
    pub fn ensure_schema(&self) -> Result<(), SqlError> {
        self.exec.execute(Self::DDL, &[]).map(|_| ())
    }
}

impl<E: SqlExecutor> SqlLedgerDriver for PostgresSqlLedgerDriver<E> {
    fn claim_upsert(&self, key: &str, claimed_at: u64) -> SqlClaim {
        // 1) Try to take the slot with the atomic ON CONFLICT DO NOTHING insert.
        let inserted = self
            .exec
            .execute(
                &self.claim_sql(),
                &[SqlValue::Text(key.into()), SqlValue::Int(claimed_at as i64)],
            )
            .unwrap_or(0);
        if inserted == 1 {
            return SqlClaim::Won;
        }
        // 2) Conflict — a row exists. Read its state.
        let row = self
            .exec
            .query_opt(
                &format!(
                    "SELECT state, result FROM {} WHERE idempotency_key=$1",
                    self.table
                ),
                &[SqlValue::Text(key.into())],
            )
            .ok()
            .flatten();
        match row.as_deref() {
            Some([Some(state), result]) => match state.as_str() {
                "COMMITTED" => SqlClaim::AlreadyCommitted(result.clone().unwrap_or_default()),
                // A cleanly-FAILED row is re-claimable: conditionally flip it back to PENDING.
                "FAILED" => {
                    let re = self
                        .exec
                        .execute(
                            &self.reclaim_failed_sql(),
                            &[SqlValue::Text(key.into()), SqlValue::Int(claimed_at as i64)],
                        )
                        .unwrap_or(0);
                    if re == 1 {
                        SqlClaim::Won
                    } else {
                        // Lost the re-claim race to a peer — treat as in-doubt, never double-run.
                        SqlClaim::InDoubt
                    }
                }
                // PENDING / MANUAL → in-doubt.
                _ => SqlClaim::InDoubt,
            },
            // Row vanished between insert and select (concurrent resolve) — safest is in-doubt.
            _ => SqlClaim::InDoubt,
        }
    }
    fn set_meta(&self, key: &str, tool: &str, args: &str) {
        let _ = self.exec.execute(
            &format!(
                "UPDATE {} SET tool=$2, args=$3 WHERE idempotency_key=$1 AND state='PENDING'",
                self.table
            ),
            &[
                SqlValue::Text(key.into()),
                SqlValue::Text(tool.into()),
                SqlValue::Text(args.into()),
            ],
        );
    }
    fn set_committed(&self, key: &str, result: &str) {
        let _ = self.exec.execute(
            &format!(
                "UPDATE {} SET state='COMMITTED', result=$2 WHERE idempotency_key=$1",
                self.table
            ),
            &[SqlValue::Text(key.into()), SqlValue::Text(result.into())],
        );
    }
    fn set_failed(&self, key: &str, reason: &str) {
        let _ = self.exec.execute(
            &format!(
                "UPDATE {} SET state='FAILED', reason=$2 WHERE idempotency_key=$1",
                self.table
            ),
            &[SqlValue::Text(key.into()), SqlValue::Text(reason.into())],
        );
    }
    fn set_manual(&self, key: &str, reason: &str) {
        let _ = self.exec.execute(
            &format!(
                "UPDATE {} SET state='MANUAL', reason=$2 WHERE idempotency_key=$1 AND state='PENDING'",
                self.table
            ),
            &[SqlValue::Text(key.into()), SqlValue::Text(reason.into())],
        );
    }
    fn now(&self) -> u64 {
        // A durable driver reads the DB clock; here we surface epoch seconds so row-age math holds
        // against a wall-clock `claimed_at`. (Offline mock executors are driven with fixed rows, so
        // this value is not asserted in the seam test.)
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
    fn pending_beyond(&self, min_age: u64) -> Vec<PendingRow> {
        let now = self.now();
        let rows = self
            .exec
            .query(
                &format!(
                    "SELECT idempotency_key, tool, args, claimed_at FROM {} \
                     WHERE state='PENDING' AND ($1 - claimed_at) >= $2",
                    self.table
                ),
                &[SqlValue::Int(now as i64), SqlValue::Int(min_age as i64)],
            )
            .unwrap_or_default();
        rows.into_iter()
            .filter_map(|r| match r.as_slice() {
                [Some(key), tool, args, Some(claimed)] => Some(PendingRow {
                    key: key.clone(),
                    tool: tool.clone().unwrap_or_default(),
                    args: args.clone().unwrap_or_default(),
                    claimed_at: claimed.parse().unwrap_or(0),
                }),
                _ => None,
            })
            .collect()
    }
    fn try_lease(&self, key: &str, owner: &str, lease_ttl: u64) -> bool {
        let now = self.now();
        self.exec
            .execute(
                &self.lease_sql(),
                &[
                    SqlValue::Text(key.into()),
                    SqlValue::Text(owner.into()),
                    SqlValue::Int((now + lease_ttl) as i64),
                    SqlValue::Int(now as i64),
                ],
            )
            .map(|n| n > 0)
            .unwrap_or(false)
    }
}

/// How an in-doubt (lost-ack) claim resolves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// The downstream actually did complete — adopt this result.
    Committed(String),
    /// The downstream did not complete.
    Failed(String),
    /// Cannot determine automatically — escalate to a human.
    Manual,
}

/// Resolves in-doubt claims by querying the downstream's real state. Default escalates.
pub trait Reconciler: Send + Sync {
    fn reconcile(&self, key: &str, tool: &str, args: &str) -> Resolution;
}

/// Safe default: never guess — escalate an in-doubt claim to manual reconciliation.
pub struct ManualReconciler;
impl Reconciler for ManualReconciler {
    fn reconcile(&self, _key: &str, _tool: &str, _args: &str) -> Resolution {
        Resolution::Manual
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchResult {
    /// Executed now.
    Ok(String),
    /// Not executed — the stored result was returned (exactly-once dedup).
    Deduped(String),
    /// Execution failed.
    Failed(String),
    /// In-doubt and the reconciler could not resolve it — a human must reconcile.
    NeedsReconciliation,
    /// Refused before any effect (e.g. unknown tool, missing idempotency key).
    Blocked(String),
}

/// A prepared (dry-run) commit awaiting its matching [`ToolRuntime::commit`] within a TTL (§1.4).
#[derive(Debug, Clone)]
struct PreparedCommit {
    /// The idempotency key computed at dry-run time; `commit` must present the exact same key.
    /// (Retained beyond the map-key suffix for audit/debug of the prepared-commit table.)
    #[allow(dead_code)]
    commit_key: String,
    /// Logical tick after which the preview is stale and the commit is refused.
    expires_at: u64,
}

/// GAP-FIX identity-payments (ADR-016 §6) — the caller-presented PAM + its binding context, threaded
/// internally from [`ToolRuntime::dispatch_obo_with_pam`]/[`ToolRuntime::dispatch_obo_audited_with_pam`]
/// down to [`ToolRuntime::execute_dispatch_core`] (the shared choke point every dispatch path funnels
/// through). `pam` is `Option` (not `&PaymentAdjacentMandate` directly) because a caller may reach the
/// PAM-aware entrypoint without actually holding a mandate for THIS particular call (e.g. a batch of
/// mixed payment-adjacent and ordinary tool names) — `execute_dispatch_core` treats a `None` exactly
/// like the plain (non-PAM-aware) entrypoints: a hard refusal for any tool that declares itself
/// payment-adjacent.
struct PamDispatchContext<'a> {
    pam: Option<&'a ainxt_payments::mandate::PaymentAdjacentMandate>,
    run_id: &'a str,
    now: u64,
}

/// One capability registry + ledger + reconciler.
///
/// This is the **single** [`CapabilityRegistry`] of §0: a native tool, an MCP-discovered tool
/// (adapted via [`mcp_bridge::McpCapability`]), and a plugin export (via
/// [`plugin_bridge::PluginCapability`]) all register here as `Box<dyn Tool>` and dispatch through
/// the identical path — nothing downstream branches on origin.
pub struct ToolRuntime {
    tools: HashMap<String, Box<dyn Tool>>,
    ledger: Arc<dyn Ledger>,
    reconciler: Arc<dyn Reconciler>,
    /// Issued-but-not-yet-committed dry-runs (§1.4 two-phase commit), keyed by
    /// `"{tool}\u{0}{commit_key}"`. A `HighRisk` `commit` must find a live entry here or is refused.
    two_phase: Mutex<HashMap<String, PreparedCommit>>,
    /// Per-resource serialization table (§1.5). Each distinct `resource_key` a tool call resolves
    /// maps to its own `Mutex`; concurrent calls sharing a key serialize on it, while calls on
    /// disjoint resources take *different* mutexes and run fully in parallel. This is the
    /// *concurrent* axis of double-execution prevention — the ledger (§1.2) covers the *retry /
    /// restart* axis; together they cover both. Kept as `Arc<Mutex<()>>` values so the guard can be
    /// held across the ledger-claim + execute window without holding the outer table lock.
    resource_locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
    /// Per-idempotency-KEY serialization table (§1.2, scenario 2). This is the *concurrent-duplicate*
    /// axis the resource lock does not cover: two retries of the SAME logical side-effecting action
    /// (identical idempotency key) — e.g. a UI double-click plus an internal retry — that a tool with
    /// no `resource_key` would otherwise both claim in parallel. Holding this key lock across the
    /// claim+execute+commit window makes the second caller **block briefly** on the first's in-flight
    /// claim and then observe the committed row (returned as [`DispatchResult::Deduped`]) — the
    /// underlying capability runs exactly once, never twice in parallel. Distinct from the ledger's
    /// *cross-process / restart* dedup: a `PENDING` row left by a DIFFERENT process (a crash) holds no
    /// live lock here, so it still takes the in-doubt → reconcile path, never a spurious block.
    key_locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
    /// GAP-FIX tooling-mcp-plugins-routing — the deterministic pre/post guardrail box (§hooks): empty
    /// (`HookRegistry::default()`) by default, which is a pure passthrough, so every existing caller
    /// that never touches [`ToolRuntime::hooks_mut`] is byte-identical to before this field existed.
    /// A deployment installs hooks (e.g. a [`hooks::HashVerifyHook`] on a specific fetch capability,
    /// or a global [`hooks::TruncateOutputHook`]) after construction; they then run for EVERY
    /// dispatch through [`ToolRuntime::execute_dispatch`] regardless of whether the capability is
    /// native, MCP-discovered, or plugin-provided — one guardrail box, not a per-origin bolt-on.
    hooks: hooks::HookRegistry,
    /// §1.7 per-capability egress destination allow-list. `None` by default (a pure passthrough — no
    /// existing caller that never reaches for [`ToolRuntime::with_egress_allowlist`] is affected).
    /// When set, every egressing (`Tool::egress() == true`) dispatch that also declares a
    /// [`Tool::destination`] is checked against it BEFORE the ledger claim / execute — an unlisted
    /// destination is refused, never a silent send. A tool that declares no destination (the default
    /// for every existing `Tool` impl) is unaffected either way; this is deliberately additive, not a
    /// retrofit onto every capability at once.
    egress_allowlist: Option<egress_allowlist::EgressAllowList>,
    /// GAP-FIX identity-payments (ADR-016 §6) — the SHARED fourth-gate registry for payment-*adjacent*
    /// dispatch. `None` by default (a pure passthrough — no existing caller that never reaches for
    /// [`ToolRuntime::with_mandate_registry`] is affected). When set, every call whose
    /// [`Tool::payment_adjacent_action`] returns `Some(..)` MUST go through
    /// [`ToolRuntime::dispatch_obo_with_pam`]/[`ToolRuntime::dispatch_obo_audited_with_pam`] with a
    /// presented PAM — the plain [`ToolRuntime::dispatch_obo`]/[`ToolRuntime::dispatch_obo_audited`]
    /// (no PAM parameter) now fail closed for such a capability rather than silently skipping the
    /// fourth gate. An `Arc<Mutex<..>>` so a composition root can hand the SAME registry here AND to
    /// e.g. `AssembledFull::authorize_payment_adjacent_dispatch` (never a second, disjoint registry).
    mandate_registry: Option<Arc<Mutex<ainxt_payments::mandate::MandateRegistry>>>,
}

/// Soft cap on the number of retained per-resource lock entries before idle ones are pruned. Bounds
/// memory for a long-lived process that touches an unbounded universe of resource keys (e.g. every
/// file path in a monorepo) without pruning on the hot path for typical working sets.
const RESOURCE_LOCK_SOFT_CAP: usize = 4096;

impl ToolRuntime {
    pub fn new(ledger: Box<dyn Ledger>, reconciler: Box<dyn Reconciler>) -> Self {
        Self::with_shared_ledger(Arc::from(ledger), Arc::from(reconciler))
    }

    /// Build a runtime over a **shared** ledger + reconciler. This is the clean entrypoint the
    /// daemon uses so the very same ledger instance backs BOTH the dispatch path and a background
    /// [`ReconcilerSweeper`] (§1.8): construct one `Arc<dyn Ledger>`, hand a clone here and a clone
    /// to the sweeper via [`ToolRuntime::shared_ledger`]. Sharing is what lets the sweep resolve the
    /// exact rows dispatch left `PENDING`.
    pub fn with_shared_ledger(ledger: Arc<dyn Ledger>, reconciler: Arc<dyn Reconciler>) -> Self {
        ToolRuntime {
            tools: HashMap::new(),
            ledger,
            reconciler,
            two_phase: Mutex::new(HashMap::new()),
            resource_locks: Mutex::new(HashMap::new()),
            key_locks: Mutex::new(HashMap::new()),
            hooks: hooks::HookRegistry::new(),
            egress_allowlist: None,
            mandate_registry: None,
        }
    }

    /// Install the §1.7 per-capability egress allow-list (builder-style, after construction — a
    /// composition root that never calls this gets byte-identical behavior to before this field
    /// existed). See [`egress_allowlist::EgressAllowList`] and the `egress_allowlist` field doc.
    pub fn with_egress_allowlist(mut self, allowlist: egress_allowlist::EgressAllowList) -> Self {
        self.egress_allowlist = Some(allowlist);
        self
    }

    /// Install the ADR-016 §6 payment-adjacent fourth-gate [`ainxt_payments::mandate::MandateRegistry`]
    /// (builder-style, after construction — a composition root that never calls this gets
    /// byte-identical behavior to before this field existed). See the `mandate_registry` field doc.
    pub fn with_mandate_registry(
        mut self,
        registry: Arc<Mutex<ainxt_payments::mandate::MandateRegistry>>,
    ) -> Self {
        self.mandate_registry = Some(registry);
        self
    }

    /// Mutable access to the deterministic pre/post guardrail box (§hooks) so a composition root can
    /// install hooks after construction — e.g. a [`hooks::HashVerifyHook`] on a specific capability's
    /// post path, or a global [`hooks::TruncateOutputHook`]/[`hooks::DenyArgsHook`]. Empty by default
    /// (a pure passthrough), so a caller that never reaches for this is unaffected.
    pub fn hooks_mut(&mut self) -> &mut hooks::HookRegistry {
        &mut self.hooks
    }

    /// Read-only access to the guardrail box (e.g. for a status/introspection route to report how
    /// many hooks are installed via [`hooks::HookRegistry::counts`]).
    pub fn hooks(&self) -> &hooks::HookRegistry {
        &self.hooks
    }

    /// A clone of the shared ledger handle — hand this to a [`ReconcilerSweeper`] so it sweeps the
    /// same rows dispatch writes.
    pub fn shared_ledger(&self) -> Arc<dyn Ledger> {
        Arc::clone(&self.ledger)
    }

    /// A clone of the shared reconciler handle — the probe seam a sweeper reuses.
    pub fn shared_reconciler(&self) -> Arc<dyn Reconciler> {
        Arc::clone(&self.reconciler)
    }

    /// Get-or-create the lock for `resource_key`. Two callers resolving the same key get the *same*
    /// `Arc<Mutex<()>>`, so they serialize; distinct keys get distinct mutexes and never block each
    /// other. A tool panic while holding a resource lock poisons only that resource's mutex — we
    /// recover it (the guarded value is `()`, so there is no torn state) rather than letting one bad
    /// call permanently deadlock every future call on that resource.
    fn resource_lock(&self, resource_key: &str) -> Arc<Mutex<()>> {
        Self::get_or_create_lock(&self.resource_locks, resource_key)
    }

    /// Get-or-create the per-idempotency-key lock (§1.2, scenario 2). Same discipline as
    /// [`resource_lock`](Self::resource_lock): concurrent callers on the same key get the same mutex
    /// and serialize; idle entries are pruned past the soft cap.
    fn key_lock(&self, key: &str) -> Arc<Mutex<()>> {
        Self::get_or_create_lock(&self.key_locks, key)
    }

    /// The shared get-or-create-with-pruning used by both the resource-lock and key-lock tables. Two
    /// callers resolving the same key get the *same* `Arc<Mutex<()>>`, so they serialize; distinct
    /// keys get distinct mutexes and never block each other. A poisoned mutex is recovered (the
    /// guarded value is `()`, so there is no torn state) rather than deadlocking every future call.
    fn get_or_create_lock(
        table: &Mutex<HashMap<String, Arc<Mutex<()>>>>,
        key: &str,
    ) -> Arc<Mutex<()>> {
        let mut table = table.lock().unwrap_or_else(|e| e.into_inner());
        // Bound memory: an idle lock (only the table itself still references it — `strong_count == 1`)
        // has no in-flight holder, so dropping it cannot break serialization; the next call on that
        // key simply recreates it. Only sweep when the table has grown past the soft cap so the
        // common path stays O(1).
        if table.len() > RESOURCE_LOCK_SOFT_CAP {
            table.retain(|_, l| Arc::strong_count(l) > 1);
        }
        table
            .entry(key.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }
    /// Register a tool — UNLESS it is payment-initiating, in which case it is **refused** (never
    /// admitted): a tool that declares [`EffectClass::PaymentInitiating`], or whose name matches a
    /// payment-initiation signature ([`is_payment_signature`]) while being side-effecting, is dropped
    /// (fail-closed, ADR-016 Layer 2). Use [`ToolRuntime::try_register`] if you need to observe the
    /// refusal. Even if one somehow slipped in, [`ToolRuntime::dispatch`] refuses it too (Layer 1).
    pub fn register(&mut self, tool: Box<dyn Tool>) {
        let _ = self.try_register(tool);
    }

    /// Fallible register: `Err` names why a tool was refused (payment boundary, ADR-016 Layer 2).
    pub fn try_register(&mut self, tool: Box<dyn Tool>) -> Result<(), ToolError> {
        let name = tool.name().to_string();
        if tool.effect_class() == EffectClass::PaymentInitiating {
            return Err(ToolError::Execution(format!(
                "refused to register payment-initiating tool '{name}': money movement is not \
                 dispatchable by an agent (ADR-016)"
            )));
        }
        // Layer-6 tripwire: a world-changing tool (SideEffecting OR the canonical Idempotent) whose
        // name screams money movement is refused — adding the Idempotent variant must NOT open a hole
        // where a payment tool relabels itself Idempotent to skip the tripwire.
        if matches!(
            tool.effect_class(),
            EffectClass::SideEffecting | EffectClass::Idempotent
        ) && is_payment_signature(&name)
        {
            return Err(ToolError::Execution(format!(
                "refused to register tool '{name}': its name matches a payment-initiation signature \
                 but it is not declared PaymentInitiating (ADR-016 Layer-6 tripwire)"
            )));
        }
        self.tools.insert(name, tool);
        Ok(())
    }

    /// GAP-FIX guardrails-injection — the registered tool NAMES, for wiring into
    /// `ainxt_injection::InjectionDetector::with_tools` (the "an external document should never
    /// reference your private tool registry" strong signal, ADR-009). Before this the served
    /// composition root always built its scanners with `InjectionDetector::default()` (empty
    /// `known_tool_names`), so this detection category could never fire in production no matter how
    /// real the rest of the scored detector was — every caller of this method's own detector/scanner
    /// tests supplied the names by hand. Order is unspecified (backed by a `HashMap`); callers only
    /// need membership, never order.
    pub fn tool_names(&self) -> Vec<String> {
        self.tools.keys().cloned().collect()
    }

    /// §1.8 STRICT registration gate: everything [`ToolRuntime::try_register`] already enforces,
    /// PLUS the mandatory-reconcile-probe rule for HighRisk SideEffecting capabilities — "for a
    /// capability that exposes a `reconcile(idempotency_key) -> {Committed|NotFound|Ambiguous}`
    /// probe — **mandatory** for any `SideEffecting` capability at `risk_tier: HighRisk`". Left
    /// unenforced, every lost-ack row for the settlement-adjacent tier that needs active resolution
    /// MOST would silently degrade to `MANUAL_RECONCILIATION` by default — a real availability/ops
    /// hole hiding behind the reconciler's own honest "never guess" behavior.
    ///
    /// Kept as a SEPARATE method from `try_register`/`register` (rather than folded into them) so
    /// every existing caller and test — which predates the per-tool [`Tool::has_reconcile_probe`]
    /// declaration and would otherwise be silently refused — is completely unaffected; a deployment
    /// that wants the §1.8 mandate enforced calls this instead. This is the concrete "clean
    /// entrypoint" a served capability-bootstrap path should route through (needs hot-wiring into
    /// the served registration path in the reserved runtime crate).
    pub fn try_register_governed(&mut self, tool: Box<dyn Tool>) -> Result<(), ToolError> {
        if tool.risk_tier() == RiskTier::HighRisk
            && tool.effect_class() == EffectClass::SideEffecting
            && !tool.has_reconcile_probe()
        {
            let name = tool.name().to_string();
            return Err(ToolError::Execution(format!(
                "refused to register HighRisk SideEffecting tool '{name}': §1.8 requires a declared \
                 reconcile probe (Tool::has_reconcile_probe) for this risk tier — a lost-ack PENDING \
                 row for a settlement-adjacent capability must be actively resolvable against the \
                 downstream's real state, not merely escalated to manual reconciliation by default"
            )));
        }
        self.try_register(tool)
    }

    /// GAP-AUDIT tooling-mcp-plugins-routing — "Native-tools supply-chain parity": a WASM/native
    /// PLUGIN ([`ainxt_plugin::supply_chain`]) gets a mandatory content-hash pin + publisher
    /// allow-list check, re-verified on EVERY load (§3.4), before its capability is ever registered.
    /// A NATIVE Rust capability — full host privilege, no sandbox, and frequently
    /// `RiskTier::HighRisk`/`SideEffecting` (e.g. a ledger/payment-adjacent tool) — got NO equivalent
    /// integrity check at all: [`try_register`]/[`try_register_governed`] only ever ran business-logic
    /// gates (the payment boundary, the §1.8 reconcile-probe mandate). A `HighRisk` native tool's
    /// declared admission-governing posture (effect class, risk tier, egress, declared data class)
    /// could silently drift with no reviewed record catching it — exactly the asymmetry §3.4 exists
    /// to prevent for plugins.
    ///
    /// This closes it at the SAME scope §1.8 already uses (`RiskTier::HighRisk` — the tier with the
    /// biggest blast radius, not every capability): [`native_supply_chain::verify_native_for_registration`]
    /// must pass (a reviewed [`native_supply_chain::NativeControlLock`] entry's hash must match the
    /// tool's live [`native_supply_chain::native_manifest_hash`]) in addition to everything
    /// [`try_register_governed`] already enforces. A capability below `HighRisk` is unaffected —
    /// this is additive parity for the highest-risk tier, not a new gate for every native tool.
    pub fn try_register_governed_pinned(
        &mut self,
        tool: Box<dyn Tool>,
        lock: &native_supply_chain::NativeControlLock,
    ) -> Result<(), ToolError> {
        if let Err(e) = native_supply_chain::verify_native_for_registration(tool.as_ref(), lock) {
            let name = tool.name().to_string();
            return Err(ToolError::Execution(format!(
                "refused to register HighRisk native tool '{name}': supply-chain parity check \
                 failed ({e}) — a HighRisk native capability's declared manifest must match a \
                 reviewed control.lock pin, the same discipline a WASM/native plugin gets (§3.4)"
            )));
        }
        self.try_register_governed(tool)
    }

    /// The risk tier of a registered tool (for the engine's approval decision), or None if unknown.
    pub fn risk_tier(&self, name: &str) -> Option<RiskTier> {
        self.tools.get(name).map(|t| t.risk_tier())
    }

    /// Whether a registered tool is side-effecting (for injection capability-gating), or None if
    /// unknown. Side-effecting tools are the ones a prompt-injection would try to weaponize.
    pub fn is_side_effecting(&self, name: &str) -> Option<bool> {
        // Anything that is not Pure is world-changing for gating purposes (PaymentInitiating too,
        // though it can never be registered/dispatched).
        self.tools
            .get(name)
            .map(|t| t.effect_class() != EffectClass::Pure)
    }

    /// The resource a tool call targets (for fine-grained resource authz), or None.
    pub fn resource_of(&self, name: &str, args: &str) -> Option<String> {
        self.tools.get(name).and_then(|t| t.resource(args))
    }

    /// Whether a registered tool does network egress (for injection gating), or None if unknown.
    pub fn egress_of(&self, name: &str) -> Option<bool> {
        self.tools.get(name).map(|t| t.egress())
    }

    /// GAP-FIX guardrails-injection "connector-provenance lost" — the [`ainxt_injection::Provenance`]
    /// a NAMED registered tool's results carry ([`Tool::tool_provenance`]), or `None` if `name` is not
    /// registered. The served engine's post-dispatch injection scan/quarantine (`ainxt-runtime`) looks
    /// this up per dispatched tool instead of hardcoding `Provenance::ToolResult` for every result —
    /// so a connector capability's result is tagged `Provenance::Connector` on the SAME real dispatch
    /// path, not a parallel/bespoke one.
    pub fn provenance_of(&self, name: &str) -> Option<ainxt_injection::Provenance> {
        self.tools.get(name).map(|t| t.tool_provenance())
    }

    /// §4.2: classify the effective data-class of a tool call by fusing the three signals — the
    /// tool's declared class, a compliance scan of `args` (via `scanner`), and the destination/egress
    /// class — and escalating to the **most sensitive**. `None` iff the tool is unknown here. The
    /// returned [`EffectiveDataClass`] carries the fused class (for routing/approval), an `escalated`
    /// flag set when the signals disagreed, the driving signal(s), and the raw readings for audit.
    ///
    /// This is a *classification*, never an admission gate: a high class routes the call to an
    /// in-house model and may warrant an approval step, but it does not deny the turn.
    pub fn classify_data_class(
        &self,
        name: &str,
        args: &str,
        scanner: &dyn ArgClassScanner,
    ) -> Option<EffectiveDataClass> {
        let tool = self.tools.get(name)?;
        Some(EffectiveDataClass::fuse(
            tool.declared_data_class(),
            scanner.classify_args(args),
            tool.destination_data_class(args),
        ))
    }

    /// Validate a tool call's args against the tool's declared schema. `Ok(())` when the tool is
    /// unknown here (dispatch will surface the unknown-tool error) or its args are free-form.
    pub fn validate(&self, name: &str, args: &str) -> Result<(), String> {
        match self.tools.get(name) {
            Some(t) => validate_args(&t.schema().parameters, args),
            None => Ok(()),
        }
    }

    /// The manifest of every registered tool's schema — the model's function-calling list. Native
    /// and MCP tools appear identically (ADR-002). Order is unspecified (HashMap).
    pub fn schemas(&self) -> Vec<ToolSchema> {
        self.tools.values().map(|t| t.schema()).collect()
    }

    /// Dispatch a capability call through the single, origin-agnostic path (§0).
    ///
    /// A `HighRisk` capability is **refused here** — it is structurally non-dispatchable in one shot
    /// and must go through [`ToolRuntime::dry_run`] → [`ToolRuntime::commit`] (§1.4). Everything
    /// below `HighRisk` runs the normal effect-class + exactly-once path.
    pub fn dispatch(&self, name: &str, args: &str) -> DispatchResult {
        self.dispatch_inner(None, name, args, None)
    }

    /// Dispatch a capability call **on behalf of** a specific principal (§1.2). The exactly-once
    /// idempotency key is derived from `f(user_id, capability, resource_key, semantic-args)` — the
    /// `user_id` is folded in so two *different* users issuing the byte-identical call get two
    /// distinct ledger rows (their side effects are independent and must not dedup against each
    /// other), while the *same* user retrying dedups exactly as before. Plain [`ToolRuntime::dispatch`]
    /// is the legacy / unattributed entrypoint (no OBO context) and keeps the raw, unscoped key.
    pub fn dispatch_for(&self, user_id: &str, name: &str, args: &str) -> DispatchResult {
        self.dispatch_inner(Some(user_id), name, args, None)
    }

    /// Dispatch a capability call **authorized as the requesting user** (§1.6). BEFORE any effect, the
    /// three-layer OBO policy is consulted — declared grant ∧ issued scope ∧ resource ABAC — with the
    /// resource resolved from the tool's own [`Tool::resource`]. A denial is a HARD, structured
    /// [`DispatchResult::Blocked`]; the agent's broader ambient credential is NEVER substituted (the
    /// confused-deputy fix). On allow, the call runs the identical exactly-once path as
    /// [`ToolRuntime::dispatch_for`], scoped to `ctx.user_id`. `action` names the operation for the
    /// grant check (e.g. `"read"`, `"write"`, or `"execute"` when the tool has no finer action).
    ///
    /// A sub-agent passes a [`OboContext::delegate`]/[`OboContext::inherit`] child here: because a
    /// child can only narrow the parent, a delegated call can never exercise a grant broader than the
    /// human who started the turn holds (scenario 6).
    pub fn dispatch_obo(
        &self,
        ctx: &obo::OboContext,
        policy: &dyn obo::OboPolicy,
        name: &str,
        args: &str,
        action: &str,
    ) -> DispatchResult {
        self.dispatch_obo_inner(ctx, policy, &obo::NoOboAudit, name, args, action, None)
    }

    /// [`dispatch_obo`](Self::dispatch_obo) that additionally writes the OBO decision — GRANTED **or**
    /// DENIED — to `sink` before it dispatches or hard-blocks (§1.6: "Every OBO decision … is written
    /// to the Event Log beside the tool call"). This is the clean entrypoint the served daemon
    /// (`ainxt-runtime`, reserved) hot-wires in its agent loop: construct the [`obo::OboContext`] from
    /// the turn's JWT (user_id + granted permissions + issued connector scope + clearance), pass the
    /// engine's Event-Log-backed [`obo::OboDecisionSink`], and call this instead of the coarse
    /// `authorize_tool` + `dispatch_for` pair — so the confused-deputy denial is BOTH enforced and
    /// audited on the live path, and a sub-agent's [`obo::OboContext::delegate`] child flows through
    /// the identical audited gate (its narrowed authority recorded at `depth > 0`).
    pub fn dispatch_obo_audited(
        &self,
        ctx: &obo::OboContext,
        policy: &dyn obo::OboPolicy,
        sink: &dyn obo::OboDecisionSink,
        name: &str,
        args: &str,
        action: &str,
    ) -> DispatchResult {
        self.dispatch_obo_inner(ctx, policy, sink, name, args, action, None)
    }

    /// [`dispatch_obo`](Self::dispatch_obo) extended with the ADR-016 §6 payment-*adjacent* fourth
    /// gate: "verified at dispatch, alongside OBO". `pam`/`run_id`/`now` are consulted ONLY when the
    /// target tool's [`Tool::payment_adjacent_action`] declares an `(action_verb, resource)` pair —
    /// an ordinary tool is completely unaffected (byte-identical to [`dispatch_obo`]). For a
    /// payment-adjacent tool the three-layer OBO verdict is checked FIRST, exactly as for any other
    /// call — an OBO denial short-circuits here and the PAM is never even consulted (no self-DoS of a
    /// single-use PAM on an OBO failure, mirroring
    /// [`ainxt_payments::mandate::authorize_adjacent_dispatch`]'s own ordering guarantee). On an OBO
    /// pass, [`ToolRuntime::execute_dispatch_core`] enforces that `pam` is `Some` and authorizes the
    /// EXACT `(action_verb, resource, run_id)` the tool declared against the SAME shared
    /// [`ainxt_payments::mandate::MandateRegistry`] installed via [`ToolRuntime::with_mandate_registry`]
    /// — a missing PAM, an unconfigured registry, or a PAM failure is a hard
    /// [`DispatchResult::Blocked`], never a silent skip.
    pub fn dispatch_obo_with_pam(
        &self,
        ctx: &obo::OboContext,
        policy: &dyn obo::OboPolicy,
        name: &str,
        args: &str,
        action: &str,
        pam: Option<&ainxt_payments::mandate::PaymentAdjacentMandate>,
        run_id: &str,
        now: u64,
    ) -> DispatchResult {
        self.dispatch_obo_inner(
            ctx,
            policy,
            &obo::NoOboAudit,
            name,
            args,
            action,
            Some((pam, run_id, now)),
        )
    }

    /// [`dispatch_obo_with_pam`](Self::dispatch_obo_with_pam) that additionally writes the OBO
    /// decision to `sink` (mirrors [`dispatch_obo_audited`](Self::dispatch_obo_audited)).
    pub fn dispatch_obo_audited_with_pam(
        &self,
        ctx: &obo::OboContext,
        policy: &dyn obo::OboPolicy,
        sink: &dyn obo::OboDecisionSink,
        name: &str,
        args: &str,
        action: &str,
        pam: Option<&ainxt_payments::mandate::PaymentAdjacentMandate>,
        run_id: &str,
        now: u64,
    ) -> DispatchResult {
        self.dispatch_obo_inner(
            ctx,
            policy,
            sink,
            name,
            args,
            action,
            Some((pam, run_id, now)),
        )
    }

    fn dispatch_obo_inner(
        &self,
        ctx: &obo::OboContext,
        policy: &dyn obo::OboPolicy,
        sink: &dyn obo::OboDecisionSink,
        name: &str,
        args: &str,
        action: &str,
        pam_ctx: Option<(
            Option<&ainxt_payments::mandate::PaymentAdjacentMandate>,
            &str,
            u64,
        )>,
    ) -> DispatchResult {
        // Resolve the resource the call targets (for resource-level grant + ABAC) from the tool
        // itself, so authz sees exactly what dispatch will lock/execute against. An unknown tool is
        // surfaced by the normal dispatch path below.
        let resource = self.tools.get(name).and_then(|t| t.resource(args));
        let verdict = policy.authorize(ctx, name, resource.as_deref(), action);
        // Record the decision (granted or denied) BEFORE acting on it — the denied case is exactly
        // the confused-deputy attempt the audit trail must retain.
        sink.record(&obo::OboDecision {
            user_id: ctx.user_id.clone(),
            capability: name.to_string(),
            resource: resource.clone(),
            action: action.to_string(),
            depth: ctx.depth,
            verdict: verdict.clone(),
        });
        if let Err(denial) = verdict {
            // Structured denial — no ambient fallback. This is the confused-deputy guarantee. A
            // payment-adjacent tool's PAM is NEVER even consulted here — the three OBO layers are the
            // gate that must pass first (ADR-016 §6, no self-DoS of a single-use PAM on an OBO
            // failure).
            return DispatchResult::Blocked(denial.to_string());
        }
        // The three-layer OBO gate has just passed — fold that into the PAM context's OboOutcome
        // (only consulted by `execute_dispatch_core` if the tool actually declares itself
        // payment-adjacent; an ordinary tool ignores this entirely).
        let pam_dispatch_ctx =
            pam_ctx.map(|(pam, run_id, now)| PamDispatchContext { pam, run_id, now });
        self.dispatch_inner(Some(&ctx.user_id), name, args, pam_dispatch_ctx)
    }

    fn dispatch_inner(
        &self,
        user_id: Option<&str>,
        name: &str,
        args: &str,
        pam_ctx: Option<PamDispatchContext<'_>>,
    ) -> DispatchResult {
        let Some(tool) = self.tools.get(name) else {
            return DispatchResult::Blocked(format!("unknown tool: {name}"));
        };
        // §1.4: the apex risk tier cannot fire in a single shot. An agent must first `dry_run`
        // (preview + compute the key) and then `commit` with that key — it cannot skip the preview
        // step for the actions that most need one.
        if tool.risk_tier().requires_two_phase() {
            return DispatchResult::Blocked(format!(
                "HighRisk capability '{name}' requires two-phase commit: call dry_run then commit; \
                 direct dispatch is refused (§1.4)"
            ));
        }
        self.execute_dispatch(tool.as_ref(), user_id, name, args, pam_ctx)
    }

    /// Run a composite, multi-step action against REGISTERED capabilities (§1.3): "update the Jira
    /// ticket, then create the GitLab MR, then notify the channel" as one saga. `run_saga`/
    /// `run_saga_ledgered` (below) are the real, tested primitives for this, but they take raw
    /// `Action`/`Compensate` closures the caller must hand-wire — nothing bridged a NAMED, registered
    /// [`Tool`] into that shape, so a saga could never be driven against the actual capability
    /// registry a turn dispatches through. This closes that: each step is dispatched through
    /// [`ToolRuntime::dispatch_inner`] — the SAME path [`ToolRuntime::dispatch_for`] uses, so a saga
    /// step gets the identical exactly-once ledger claim, the §1.4 two-phase refusal, the §1.7 egress
    /// check, and pre/post hooks as any other call, with no separate/weaker code path for saga
    /// participation. On a step failure, completed steps are compensated in reverse via
    /// [`Tool::compensate`] (passed that step's own recorded result as the receipt); a step with no
    /// declared compensate is honestly reported `uncompensated` in [`SagaOutcome::FailedPartial`],
    /// never a false "rolled back" claim (the same discipline as [`run_saga_ledgered`]).
    pub fn dispatch_saga(
        &self,
        user_id: Option<&str>,
        steps: &[SagaStepRequest<'_>],
    ) -> SagaOutcome {
        // (tool name, receipt) for every step that has completed so far, oldest first — compensated
        // in reverse on a later failure.
        let mut done: Vec<(&str, String)> = Vec::new();
        let mut results: Vec<String> = Vec::new();
        for step in steps {
            let outcome = match self.dispatch_inner(user_id, step.tool, step.args, None) {
                DispatchResult::Ok(r) | DispatchResult::Deduped(r) => Ok(r),
                DispatchResult::Blocked(reason) | DispatchResult::Failed(reason) => Err(reason),
                DispatchResult::NeedsReconciliation => Err(format!(
                    "step '{}' is in-doubt (needs reconciliation) — refusing to proceed the saga \
                     past an unresolved lost ack",
                    step.tool
                )),
            };
            match outcome {
                Ok(receipt) => {
                    results.push(receipt.clone());
                    done.push((step.tool, receipt));
                }
                Err(reason) => {
                    let mut uncompensated = Vec::new();
                    for (name, receipt) in done.iter().rev() {
                        match self.tools.get(*name).and_then(|t| t.compensate(receipt)) {
                            Some(compensate) => {
                                if let Err(ce) = compensate() {
                                    uncompensated.push(format!("{name}: compensate failed: {ce}"));
                                }
                            }
                            None => uncompensated.push(format!(
                                "{name}: no compensate declared for this capability"
                            )),
                        }
                    }
                    return if uncompensated.is_empty() {
                        SagaOutcome::Compensated {
                            failed_step: step.tool.to_string(),
                            reason,
                        }
                    } else {
                        SagaOutcome::FailedPartial {
                            failed_step: step.tool.to_string(),
                            reason,
                            uncompensated,
                        }
                    };
                }
            }
        }
        SagaOutcome::Completed(results)
    }

    /// The origin-agnostic execution core shared by [`ToolRuntime::dispatch`] (single-phase) and
    /// [`ToolRuntime::commit`] (the second phase of a `HighRisk` action). Runs the deterministic
    /// pre/post guardrail box (§hooks, GAP-FIX tooling-mcp-plugins-routing) around per-resource
    /// locking, the payment boundary, and the exactly-once ledger — identically regardless of how it
    /// was reached or where the capability came from. A pre-hook may rewrite the arguments actually
    /// dispatched (so resource resolution, the idempotency key, and the ledger record all key off the
    /// REWRITTEN args, not the raw caller-supplied ones) or refuse the call outright, structurally
    /// before any effect (`Blocked`). A post-hook runs on the content about to be released — on both
    /// a fresh `Ok` and a `Deduped` replay, so a redaction/verification guardrail cannot be bypassed
    /// by retrying a call that already committed — and its refusal surfaces as `Failed` (the ledger's
    /// record of what happened is never altered; only what is handed back to the caller is gated).
    fn execute_dispatch(
        &self,
        tool: &dyn Tool,
        user_id: Option<&str>,
        name: &str,
        args: &str,
        pam_ctx: Option<PamDispatchContext<'_>>,
    ) -> DispatchResult {
        let args_owned = match self.hooks.run_pre(name, args, user_id) {
            Ok(rewritten) => rewritten,
            Err(refusal) => return DispatchResult::Blocked(refusal.to_string()),
        };
        let result = self.execute_dispatch_core(tool, user_id, name, &args_owned, pam_ctx);
        self.apply_post_hooks(name, user_id, result)
    }

    /// Run the post-hook chain over a result about to be released to the caller. `Failed` /
    /// `Blocked` / `NeedsReconciliation` carry no deliverable content and pass through unchanged.
    fn apply_post_hooks(
        &self,
        name: &str,
        user_id: Option<&str>,
        result: DispatchResult,
    ) -> DispatchResult {
        match result {
            DispatchResult::Ok(r) => match self.hooks.run_post(name, &r, user_id) {
                Ok(rewritten) => DispatchResult::Ok(rewritten),
                Err(refusal) => DispatchResult::Failed(refusal.to_string()),
            },
            DispatchResult::Deduped(r) => match self.hooks.run_post(name, &r, user_id) {
                Ok(rewritten) => DispatchResult::Deduped(rewritten),
                Err(refusal) => DispatchResult::Failed(refusal.to_string()),
            },
            other => other,
        }
    }

    /// The pre-hooks/post-hooks-free exactly-once core: per-resource locking, the payment boundary,
    /// and the ledger dedup path. Kept separate from [`ToolRuntime::execute_dispatch`] purely so the
    /// hook wrapping above has one clean call site; behaviorally this is exactly what
    /// `execute_dispatch` used to be before hooks existed.
    fn execute_dispatch_core(
        &self,
        tool: &dyn Tool,
        user_id: Option<&str>,
        name: &str,
        args: &str,
        pam_ctx: Option<PamDispatchContext<'_>>,
    ) -> DispatchResult {
        // §1.7 egress allow-list: the cheapest possible check, run BEFORE any lock is taken or any
        // ledger slot claimed — a destination refusal costs nothing and leaves no PENDING row. Only
        // fires when (a) a deployment has installed an allow-list at all and (b) the tool actually
        // egresses AND can name its destination; a tool with no fixed destination is unaffected. The
        // data-class used here fuses declared + destination-floor (both known without a scanner); the
        // arg-scan signal is not threaded through `dispatch` today, so this is a real but partial
        // fusion — a caller wanting the full tri-signal verdict pre-flight already has
        // `ToolRuntime::classify_data_class` for that.
        if let Some(allowlist) = &self.egress_allowlist {
            if tool.egress() {
                if let Some(destination) = tool.destination(args) {
                    let class = EffectiveDataClass::fuse(
                        tool.declared_data_class(),
                        None,
                        tool.destination_data_class(args),
                    )
                    .class;
                    if let egress_allowlist::EgressDecision::PendingApproval { .. } =
                        allowlist.check(name, &destination, class)
                    {
                        return DispatchResult::Blocked(format!(
                            "egress refused (§1.7): capability '{name}' has no allow-list entry for \
                             destination '{destination}' at data-class {class:?} — soft-blocked \
                             pending approval, never a silent send to an unlisted destination"
                        ));
                    }
                }
            }
        }
        // Per-resource serialization (§1.5, scenario 8): if this call resolves a `resource_key`,
        // hold that resource's lock across the ledger-claim + execute window so two concurrent
        // calls touching the SAME resource cannot interleave their writes. Calls on disjoint
        // resources take different locks and are unaffected. `res_lock` (the owned `Arc`) is bound
        // first so it outlives `_res_guard`, which borrows from it; drop order (reverse of
        // declaration) releases the guard, then the Arc. A stalled downstream call therefore only
        // ever holds up other calls on the *same* resource — never unrelated turns — which is the
        // deliberate scope of the lock.
        let res_lock = tool.resource(args).map(|rk| self.resource_lock(&rk));
        let _res_guard = res_lock
            .as_ref()
            .map(|l| l.lock().unwrap_or_else(|e| e.into_inner()));
        // IDN-11: the canonical PaymentEffectClass methods are the live dispatch decision.
        let effect = tool.effect_class();
        // APEX payment boundary (ADR-016 §3.1): a non-dispatchable class (PaymentInitiating) has NO
        // dispatch arm. Even a registered payment-initiating tool cannot execute — it is refused,
        // unconditionally, before any ledger/approval logic. `is_dispatchable()` is the type-level
        // source of truth for this structural "an agent cannot move money" guarantee; there is no
        // configuration that enables it.
        if !effect.is_dispatchable() {
            return DispatchResult::Blocked(format!(
                "payment-initiating tool '{name}' is structurally non-dispatchable: money movement \
                 goes through the out-of-band settlement perimeter, never an agent tool (ADR-016)"
            ));
        }
        // GAP-FIX identity-payments (ADR-016 §6) — the FOURTH gate for payment-*adjacent* writes,
        // checked here so EVERY dispatch path funnels through it (this core is the shared choke
        // point `dispatch`/`dispatch_for`/`dispatch_obo(_audited)`/`dispatch_saga`/`commit` all
        // reach) — never a substitute for, always in ADDITION to, the three-layer OBO gate above (the
        // ordering is enforced by construction: `dispatch_obo_inner` only reaches this core AFTER its
        // own OBO verdict has already passed). A tool that does not declare
        // [`Tool::payment_adjacent_action`] is completely unaffected (the overwhelming majority).
        if let Some((action_verb, pam_resource)) = tool.payment_adjacent_action(args) {
            let Some(registry) = self.mandate_registry.as_ref() else {
                return DispatchResult::Blocked(format!(
                    "payment-adjacent capability '{name}' requires a PAM (ADR-016 §6 fourth gate) but \
                     no MandateRegistry is configured on this dispatch path \
                     (ToolRuntime::with_mandate_registry)"
                ));
            };
            let Some(PamDispatchContext {
                pam: Some(pam),
                run_id,
                now,
            }) = pam_ctx
            else {
                return DispatchResult::Blocked(format!(
                    "payment-adjacent capability '{name}' requires a presented \
                     PaymentAdjacentMandate (ADR-016 §6 fourth gate) — dispatch it through \
                     ToolRuntime::dispatch_obo_with_pam/dispatch_obo_audited_with_pam, never the \
                     plain dispatch/dispatch_for/dispatch_obo entrypoints"
                ));
            };
            // By construction, reaching this core via `dispatch_obo_inner` means the three-layer OBO
            // verdict already passed (an OBO denial returns `Blocked` before `dispatch_inner` is ever
            // called) — so the OBO half of the composed four-gate check is exactly this already-
            // enforced pass, never a second, weaker re-derivation of it.
            let obo_outcome = ainxt_payments::mandate::OboOutcome {
                identity_ok: true,
                delegation_ok: true,
                authz_ok: true,
            };
            let mut mandate_reg = registry.lock().unwrap_or_else(|e| e.into_inner());
            if let Err(denied) = ainxt_payments::mandate::authorize_adjacent_dispatch(
                &mut mandate_reg,
                obo_outcome,
                pam,
                &action_verb,
                &pam_resource,
                run_id,
                now,
            ) {
                return DispatchResult::Blocked(format!(
                    "payment-adjacent dispatch refused (ADR-016 §6 fourth gate): {denied}"
                ));
            }
        }
        // Pure OR Idempotent: no exactly-once ledger record required. Pure has no effect; Idempotent
        // is world-changing but naturally safe to retry under its own key, so it executes every time
        // without a ledger dedup (ADR-016 §3.1 — requires_ledger() is false for both).
        if !effect.requires_ledger() {
            return match tool.execute_as(args, user_id) {
                Ok(r) => DispatchResult::Ok(r),
                Err(ToolError::Execution(e)) => DispatchResult::Failed(e),
            };
        }
        // requires_ledger() == true ⇒ SideEffecting: the exactly-once ledger path.
        let key = match tool.idempotency_key(args) {
            // §1.2: the ledger key is f(user_id, capability, resource_key, semantic-args). The tool
            // supplies the (capability, resource_key, semantic-args) portion; the runtime folds in
            // the acting principal so two DIFFERENT users' identical calls get DISTINCT ledger rows
            // (independent side effects must not cross-dedup), while the SAME user's retry collapses
            // to one row (lost-ack safety). Without the user_id segment, user B's first call would
            // be silently deduped against user A's committed result — a cross-user leak/no-op. The
            // unattributed legacy path (`user_id == None`) keeps the raw key unchanged.
            Some(k) if !k.is_empty() => match user_id {
                Some(u) => Self::scope_key(u, &k),
                None => k,
            },
            _ => {
                return DispatchResult::Blocked(
                    "side-effecting tool must supply a semantic idempotency key".into(),
                )
            }
        };
        // §1.2 scenario 2: serialize concurrent duplicates of the SAME key in this process. The second
        // caller blocks here until the first releases (after commit), then its `claim` observes the
        // committed row and returns `Deduped` — the capability runs exactly once, never in parallel
        // with itself. A `PENDING` row from a DIFFERENT process (a crash) holds no lock here, so the
        // in-doubt → reconcile path below is unaffected. The owned `Arc` is bound first so it outlives
        // the guard that borrows from it.
        let key_lock = self.key_lock(&key);
        let _key_guard = key_lock.lock().unwrap_or_else(|e| e.into_inner());
        match self.ledger.claim(&key) {
            // Already done — return stored result, DO NOT re-execute (no double debit).
            Claim::Committed(r) => DispatchResult::Deduped(r),
            // Lost-ack: query the downstream; never blind-retry a payment-adjacent action.
            Claim::InDoubt => match self.reconciler.reconcile(&key, name, args) {
                Resolution::Committed(r) => {
                    self.ledger.commit(&key, &r);
                    DispatchResult::Deduped(r)
                }
                Resolution::Failed(reason) => {
                    self.ledger.fail(&key, &reason);
                    DispatchResult::Failed(reason)
                }
                Resolution::Manual => DispatchResult::NeedsReconciliation,
            },
            // First time — record probe metadata on the PENDING row BEFORE firing (so a lost ack
            // leaves a row the §1.8 sweep can reconcile), then execute and commit under the key.
            Claim::Fresh => {
                self.ledger.record_pending_meta(&key, name, args);
                match tool.execute_as(args, user_id) {
                    Ok(r) => {
                        self.ledger.commit(&key, &r);
                        DispatchResult::Ok(r)
                    }
                    Err(ToolError::Execution(e)) => {
                        self.ledger.fail(&key, &e);
                        DispatchResult::Failed(e)
                    }
                }
            }
        }
    }

    // ---------------- Two-phase commit for HighRisk actions (§1.4) ----------------

    fn two_phase_key(user_id: Option<&str>, name: &str, commit_key: &str) -> String {
        // The prepared-preview table is scoped to the principal too, so one user's dry_run cannot
        // authorize another user's commit. The unattributed path uses the empty segment.
        format!("{}\u{0}{name}\u{0}{commit_key}", user_id.unwrap_or(""))
    }

    /// Fold the acting principal into a ledger key: `f(user_id, capability, resource_key,
    /// semantic-args)` (§1.2). `base` is the tool-supplied `(capability, resource_key,
    /// semantic-args)` portion; prefixing the `user_id` under a NUL separator (which cannot appear
    /// in a JSON-canonical key) keeps the principal segment unambiguous and makes cross-user
    /// dedup structurally impossible.
    fn scope_key(user_id: &str, base: &str) -> String {
        format!("{user_id}\u{0}{base}")
    }

    /// **Phase one** of a `HighRisk` action: produce a human-reviewable preview and compute (but do
    /// NOT execute) the idempotency key that a later [`ToolRuntime::commit`] must present. No side
    /// effect occurs. `now`/`ttl` are logical ticks (deterministic — the caller supplies the clock,
    /// consistent with the rest of the crate): the issued preview is valid only until `now + ttl`.
    ///
    /// The tool must supply a semantic idempotency key (a `HighRisk` action is by definition
    /// side-effect-bearing); a missing key is a hard [`DispatchResult::Blocked`], never a guess.
    pub fn dry_run(
        &self,
        name: &str,
        args: &str,
        now: u64,
        ttl: u64,
    ) -> Result<DryRunOutcome, DispatchResult> {
        self.dry_run_inner(None, name, args, now, ttl)
    }

    /// [`ToolRuntime::dry_run`] on behalf of a specific principal — the prepared preview is scoped
    /// to `user_id` so one user's preview cannot authorize another user's commit (§1.2 + §1.4).
    pub fn dry_run_for(
        &self,
        user_id: &str,
        name: &str,
        args: &str,
        now: u64,
        ttl: u64,
    ) -> Result<DryRunOutcome, DispatchResult> {
        self.dry_run_inner(Some(user_id), name, args, now, ttl)
    }

    fn dry_run_inner(
        &self,
        user_id: Option<&str>,
        name: &str,
        args: &str,
        now: u64,
        ttl: u64,
    ) -> Result<DryRunOutcome, DispatchResult> {
        let Some(tool) = self.tools.get(name) else {
            return Err(DispatchResult::Blocked(format!("unknown tool: {name}")));
        };
        // Even the preview must respect the payment boundary — a payment-initiating tool has no
        // dispatch arm at all, and no dry_run either.
        if !tool.effect_class().is_dispatchable() {
            return Err(DispatchResult::Blocked(format!(
                "payment-initiating tool '{name}' is structurally non-dispatchable (ADR-016)"
            )));
        }
        let commit_key = match tool.idempotency_key(args) {
            Some(k) if !k.is_empty() => k,
            _ => {
                return Err(DispatchResult::Blocked(
                    "HighRisk two-phase action must supply a semantic idempotency key".into(),
                ))
            }
        };
        let preview = match tool.dry_run_preview(args) {
            Ok(p) => p,
            Err(ToolError::Execution(e)) => {
                return Err(DispatchResult::Failed(format!(
                    "dry-run preview failed: {e}"
                )))
            }
        };
        let expires_at = now.saturating_add(ttl);
        self.two_phase.lock().unwrap().insert(
            Self::two_phase_key(user_id, name, &commit_key),
            PreparedCommit {
                commit_key: commit_key.clone(),
                expires_at,
            },
        );
        Ok(DryRunOutcome {
            preview,
            commit_key,
            expires_at,
        })
    }

    /// **Phase two** of a `HighRisk` action: execute it, but ONLY if a matching, unexpired
    /// [`ToolRuntime::dry_run`] preview exists for this exact `(tool, commit_key)` and the current
    /// args still hash to that same `commit_key`. The dispatcher **rejects a commit with no matching
    /// prior dry_run** (or an expired one, or one whose args changed after the preview) — the
    /// "propose, then act" contract for the highest-severity class. On success the call runs the
    /// identical exactly-once executor as any other dispatch; the prepared entry is consumed so a
    /// single preview cannot authorize two commits.
    pub fn commit(&self, name: &str, args: &str, commit_key: &str, now: u64) -> DispatchResult {
        self.commit_inner(None, name, args, commit_key, now)
    }

    /// [`ToolRuntime::commit`] on behalf of a specific principal — matches only a prepared preview
    /// issued for the SAME `user_id`, and executes under a `user_id`-scoped ledger key (§1.2).
    pub fn commit_for(
        &self,
        user_id: &str,
        name: &str,
        args: &str,
        commit_key: &str,
        now: u64,
    ) -> DispatchResult {
        self.commit_inner(Some(user_id), name, args, commit_key, now)
    }

    fn commit_inner(
        &self,
        user_id: Option<&str>,
        name: &str,
        args: &str,
        commit_key: &str,
        now: u64,
    ) -> DispatchResult {
        let Some(tool) = self.tools.get(name) else {
            return DispatchResult::Blocked(format!("unknown tool: {name}"));
        };
        // The presented key must actually match the args being committed — otherwise an agent could
        // preview a benign payload and commit a different one under its token.
        match tool.idempotency_key(args) {
            Some(k) if k == commit_key => {}
            _ => {
                return DispatchResult::Blocked(
                    "commit args do not match the previewed idempotency key (§1.4)".into(),
                )
            }
        }
        let prepared = self
            .two_phase
            .lock()
            .unwrap()
            .remove(&Self::two_phase_key(user_id, name, commit_key));
        match prepared {
            None => DispatchResult::Blocked(format!(
                "commit of HighRisk capability '{name}' refused: no matching prior dry_run (§1.4)"
            )),
            Some(p) if now > p.expires_at => DispatchResult::Blocked(format!(
                "commit of HighRisk capability '{name}' refused: the dry_run preview expired (§1.4)"
            )),
            // Matching, unexpired preview (p.commit_key == commit_key by construction): run the
            // identical exactly-once executor as any other dispatch, under the same principal.
            // No PAM-aware two-phase commit entrypoint exists yet — a HighRisk payment-adjacent
            // capability's `commit` therefore fails closed at the fourth gate (§6) exactly as the
            // plain single-phase `dispatch`/`dispatch_for` do, rather than silently skipping it.
            Some(_p) => self.execute_dispatch(tool.as_ref(), user_id, name, args, None),
        }
    }
}

// ==================== Turnkey default installers (§1.2 + §1.6) =====================================
//
// The building blocks above ([`SqlLedger`] durable exactly-once, [`ToolRuntime::dispatch_obo_audited`]
// three-layer OBO) are complete and proven, but WIRING them into the served daemon still required the
// caller to hand-assemble the durable driver + shared handles, or to re-construct the OBO policy +
// audit sink on every call. That hand-assembly is exactly where a "the DEFAULT is still the ephemeral
// in-memory ledger" or "the served path uses the coarse authorize+dispatch pair, not the audited
// three-layer entrypoint" regression slips in. The two entrypoints below make both TURNKEY: one call
// installs the durable ledger as a `ToolRuntime`'s default backing (returning the shared handle the
// background `ReconcilerSweeper` needs), and one holder object turns three-layer OBO + audit + sub-agent
// propagation into a single `dispatch`/`dispatch_sub_agent` call the daemon installs once.
//
// The offline default driver ([`InMemorySqlStore`]) gives cross-PROCESS exactly-once (N handles over one
// shared store = N daemons over one DB) and is proven offline; genuine cross-RESTART durability is the
// real database's job — a deployment passes [`install_durable_ledger`] a [`PostgresSqlLedgerDriver`] over
// a live connection (infra-gated). Nothing here defaults to the ephemeral [`InMemoryLedger`].

/// A [`ToolRuntime`] built over the DURABLE cross-process exactly-once ledger, plus the SHARED ledger +
/// reconciler handles the daemon hands to a background [`ReconcilerSweeper`] (§1.8). The turnkey result
/// of [`install_durable_ledger`] and friends: the daemon registers its capabilities into `runtime`,
/// dispatches through it, and sweeps the SAME rows via a clone of `ledger`.
pub struct DurableToolRuntime {
    /// The capability registry to register into and dispatch through. Its ledger IS `ledger` below.
    pub runtime: ToolRuntime,
    /// The SAME durable ledger instance backing `runtime`'s dispatch path — hand a clone to a
    /// [`ReconcilerSweeper`] so the sweep resolves the exact rows dispatch leaves `PENDING`.
    pub ledger: Arc<dyn Ledger>,
    /// The shared reconciler probe seam (also reused by the sweeper).
    pub reconciler: Arc<dyn Reconciler>,
}

/// Install the DURABLE cross-process exactly-once ledger as the DEFAULT backing of a fresh
/// [`ToolRuntime`], over any [`SqlLedgerDriver`], with the safe [`ManualReconciler`]. This is the
/// clean entrypoint the served daemon calls instead of `ToolRuntime::with_shared_ledger(Arc::new(
/// InMemoryLedger::new()), ..)` — so the shipped default is the durable ledger, never the ephemeral
/// one. Production hands this a [`PostgresSqlLedgerDriver`] over a live connection (infra-gated);
/// the OSS/air-gapped default driver is [`install_durable_ledger_default`].
pub fn install_durable_ledger<D: SqlLedgerDriver + 'static>(driver: D) -> DurableToolRuntime {
    install_durable_ledger_with(driver, Arc::new(ManualReconciler))
}

/// [`install_durable_ledger`] with a caller-chosen [`Reconciler`] (e.g. a real downstream-probing
/// reconciler bound to the settlement rail) instead of the escalate-only [`ManualReconciler`].
pub fn install_durable_ledger_with<D: SqlLedgerDriver + 'static>(
    driver: D,
    reconciler: Arc<dyn Reconciler>,
) -> DurableToolRuntime {
    let ledger: Arc<dyn Ledger> = Arc::new(SqlLedger::new(driver));
    let runtime = ToolRuntime::with_shared_ledger(Arc::clone(&ledger), Arc::clone(&reconciler));
    DurableToolRuntime {
        runtime,
        ledger,
        reconciler,
    }
}

/// The OSS / air-gapped turnkey default: the durable ledger over the offline [`InMemorySqlStore`]
/// driver. It is genuinely cross-PROCESS exactly-once (every [`SqlLedger`] built over a clone of the
/// returned `store`... — but note the store is owned inside; use [`install_durable_ledger`] with a
/// shared [`InMemorySqlStore`] when you need to attach a second handle) and never falls back to the
/// ephemeral [`InMemoryLedger`]. Cross-RESTART durability is the live database's job — a deployment
/// passes [`install_durable_ledger`] a [`PostgresSqlLedgerDriver`] (infra-gated).
pub fn install_durable_ledger_default() -> DurableToolRuntime {
    install_durable_ledger(InMemorySqlStore::new())
}

/// The turnkey OBO dispatch surface the served daemon installs by DEFAULT (§1.6). Holds the ONE shared
/// [`ToolRuntime`], the three-layer [`OboPolicy`](obo::OboPolicy) (declared grant ∧ issued scope ∧
/// resource ABAC), and the [`OboDecisionSink`](obo::OboDecisionSink) — so the agent loop calls ONE
/// method per tool call ([`dispatch`](OboDispatcher::dispatch) for a human turn, or
/// [`dispatch_sub_agent`](OboDispatcher::dispatch_sub_agent) for a delegated child) instead of
/// re-assembling policy + sink on every call. Every dispatch runs
/// [`ToolRuntime::dispatch_obo_audited`]: the decision (GRANTED **or** DENIED) is written to the sink
/// BEFORE any effect, a denial hard-blocks with the agent's ambient credential NEVER substituted, and a
/// sub-agent child (which can only NARROW the parent) flows through the identical enforced+audited path.
pub struct OboDispatcher {
    runtime: Arc<ToolRuntime>,
    policy: Box<dyn obo::OboPolicy>,
    sink: Arc<dyn obo::OboDecisionSink>,
}

impl OboDispatcher {
    /// Build the dispatcher over an explicit policy + audit sink. The daemon constructs this once,
    /// from the shared runtime, and reuses it for every OBO tool call.
    pub fn new(
        runtime: Arc<ToolRuntime>,
        policy: Box<dyn obo::OboPolicy>,
        sink: Arc<dyn obo::OboDecisionSink>,
    ) -> Self {
        OboDispatcher {
            runtime,
            policy,
            sink,
        }
    }

    /// Turnkey default: the reference [`ThreeLayerPolicy`](obo::ThreeLayerPolicy) over a caller-supplied
    /// resource-ABAC map, auditing to the durable Event Log via
    /// [`EventLogOboAudit`](obo::EventLogOboAudit). This is the exact stack the served daemon installs
    /// (production hands it the same tamper-evident `EventLog` the engine already uses).
    pub fn with_event_log<A, L>(runtime: Arc<ToolRuntime>, abac: A, log: L) -> Self
    where
        A: obo::ResourceAbac + 'static,
        L: ainxt_eventlog::EventLog + 'static,
    {
        OboDispatcher::new(
            runtime,
            Box::new(obo::ThreeLayerPolicy::new(abac)),
            Arc::new(obo::EventLogOboAudit::new(log)),
        )
    }

    /// A clone of the shared runtime handle (e.g. to register a capability or hand to a sweeper).
    pub fn runtime(&self) -> Arc<ToolRuntime> {
        Arc::clone(&self.runtime)
    }

    /// A clone of the shared audit-sink handle (e.g. an offline test reads back the recorded decisions).
    pub fn audit(&self) -> Arc<dyn obo::OboDecisionSink> {
        Arc::clone(&self.sink)
    }

    /// Dispatch a capability call authorized AS `ctx` (a human turn), through the audited three-layer
    /// path. `action` names the operation for the grant + audit record.
    pub fn dispatch(
        &self,
        ctx: &obo::OboContext,
        name: &str,
        args: &str,
        action: &str,
    ) -> DispatchResult {
        self.runtime.dispatch_obo_audited(
            ctx,
            self.policy.as_ref(),
            self.sink.as_ref(),
            name,
            args,
            action,
        )
    }

    /// Dispatch a capability call for a SUB-AGENT that narrows `parent` — the turnkey sub-agent OBO
    /// propagation entrypoint (§1.6, scenario 6). The child keeps only the grants + issued scope whose
    /// capability is in `keep_capabilities`, a clearance clamped to `min(parent, requested_clearance)`,
    /// and `depth + 1`; there is no path to WIDEN. The narrowed context flows through the same
    /// audited three-layer dispatch, so a sub-agent hop that tries to exceed the parent's authority is
    /// both hard-blocked and recorded (at `depth > 0`) — the confused-deputy fix propagates.
    pub fn dispatch_sub_agent(
        &self,
        parent: &obo::OboContext,
        keep_capabilities: &[&str],
        requested_clearance: ainxt_types::DataClass,
        name: &str,
        args: &str,
        action: &str,
    ) -> DispatchResult {
        let child = parent.delegate(keep_capabilities, requested_clearance);
        self.dispatch(&child, name, args, action)
    }
}

/// The outcome of a [`ToolRuntime::dry_run`] — the preview to show a human/approver plus the
/// idempotency key and expiry a subsequent [`ToolRuntime::commit`] must present (§1.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DryRunOutcome {
    /// Human-reviewable description of what committing would do — no side effect has occurred.
    pub preview: String,
    /// The idempotency key computed from the previewed args; feed it back to `commit`.
    pub commit_key: String,
    /// Logical tick after which the preview is stale and `commit` is refused.
    pub expires_at: u64,
}

// ============ Active reconciliation of lost acknowledgements (§1.8, gap [21]) ============
//
// The exactly-once ledger (§1.2) makes a *retried* call safe, but a row stuck `PENDING` — the
// runtime claimed the slot, the capability fired against the downstream, then the process died
// before the row moved to `COMMITTED`/`FAILED` — is a permanently ambiguous settlement-adjacent
// record. Passive expiry is unacceptable for payments. A background [`ReconcilerSweeper`] finds
// each timed-out `PENDING` row, leases it, and resolves it *actively, not by guessing*: it probes
// the downstream's real state via the [`Reconciler`] seam and moves the row to `COMMITTED`/`FAILED`,
// or — on `Ambiguous`/no-probe — escalates to `MANUAL_RECONCILIATION`, files an incident, and pages
// on-call. A settlement-adjacent row is never left indefinitely ambiguous and never auto-resolved.

/// The incident payload filed when a lost-ack row cannot be resolved automatically and must go to a
/// human (§1.8) — carries the request identity (key + tool + exact args) and the receipt/reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconIncident {
    pub key: String,
    pub tool: String,
    /// The exact args the downstream saw — the "full request hash and receipt" the design requires.
    pub args: String,
    /// Logical time the row was originally claimed (how long it had been ambiguous).
    pub claimed_at: u64,
    pub reason: String,
}

/// Where a `MANUAL_RECONCILIATION` escalation goes: file an incident and page the settlement
/// on-call (§1.8). The concrete impl wires the incident/pager systems; this seam keeps that out of
/// the ledger core. Escalation must be honest and loud — never swallowed.
pub trait EscalationSink: Send + Sync {
    fn escalate(&self, incident: &ReconIncident);
}

/// A [`EscalationSink`] that records every escalation in memory — the deterministic default for
/// tests and a base for an audit mirror. A production sink additionally files the incident and
/// pages on-call.
#[derive(Default)]
pub struct RecordingEscalationSink {
    incidents: Mutex<Vec<ReconIncident>>,
}

impl RecordingEscalationSink {
    pub fn new() -> Self {
        Self::default()
    }
    /// Every escalation recorded so far, in order.
    pub fn incidents(&self) -> Vec<ReconIncident> {
        self.incidents.lock().unwrap().clone()
    }
    pub fn len(&self) -> usize {
        self.incidents.lock().unwrap().len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl EscalationSink for RecordingEscalationSink {
    fn escalate(&self, incident: &ReconIncident) {
        self.incidents.lock().unwrap().push(incident.clone());
    }
}

/// What one sweep pass did — every row it touched, classified. All lists are the row keys.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SweepReport {
    /// Rows the probe confirmed the effect for → moved to `COMMITTED`, result back-filled.
    pub committed: Vec<String>,
    /// Rows the probe found no downstream record for → moved to `FAILED` (safe to re-attempt).
    pub failed: Vec<String>,
    /// Rows the probe could not resolve (`Ambiguous`/no probe) → escalated to MANUAL_RECONCILIATION
    /// with an incident + page.
    pub escalated: Vec<String>,
    /// Rows another node already holds a live lease on → skipped this pass (idempotent, no
    /// double-probe).
    pub skipped_leased: Vec<String>,
}

impl SweepReport {
    /// Total rows the sweep resolved or escalated this pass (excludes lease-skips).
    pub fn resolved(&self) -> usize {
        self.committed.len() + self.failed.len() + self.escalated.len()
    }
}

/// The active lost-ack reconciler (§1.8). Owns a shared handle to the same ledger the dispatch path
/// writes, the [`Reconciler`] probe seam, and an [`EscalationSink`]. Safe to run on every node: it
/// leases each row before touching it, so two nodes never double-probe the same settlement record.
pub struct ReconcilerSweeper {
    ledger: Arc<dyn Ledger>,
    reconciler: Arc<dyn Reconciler>,
    escalation: Arc<dyn EscalationSink>,
    /// This node's identity — stamped into the lease so a contended sweep is auditable.
    node_id: String,
    /// A row must be `PENDING` for at least this many logical ticks before it is swept (the
    /// per-deployment lost-ack timeout). Prevents racing a still-in-flight legitimate call.
    min_age: u64,
    /// How long a taken lease lives (logical ticks) — long enough to probe, short enough that a
    /// crashed reconciler's rows are re-eligible soon.
    lease_ttl: u64,
}

impl ReconcilerSweeper {
    pub fn new(
        ledger: Arc<dyn Ledger>,
        reconciler: Arc<dyn Reconciler>,
        escalation: Arc<dyn EscalationSink>,
        node_id: impl Into<String>,
        min_age: u64,
        lease_ttl: u64,
    ) -> Self {
        ReconcilerSweeper {
            ledger,
            reconciler,
            escalation,
            node_id: node_id.into(),
            min_age,
            lease_ttl,
        }
    }

    /// Run ONE sweep pass: find every timed-out `PENDING` row, lease it, probe the downstream, and
    /// resolve or escalate. Deterministic and side-effect-honest — this is the unit the background
    /// loop repeats and the unit a test drives directly.
    pub fn sweep_once(&self) -> SweepReport {
        let mut report = SweepReport::default();
        for row in self.ledger.pending_beyond(self.min_age) {
            // Lease first: if another node already owns this row, skip it — never double-probe.
            if !self
                .ledger
                .try_lease(&row.key, &self.node_id, self.lease_ttl)
            {
                report.skipped_leased.push(row.key);
                continue;
            }
            match self.reconciler.reconcile(&row.key, &row.tool, &row.args) {
                // Downstream confirms the effect happened → adopt it, no re-execution.
                Resolution::Committed(result) => {
                    self.ledger.commit(&row.key, &result);
                    report.committed.push(row.key);
                }
                // Downstream has no record → the effect never landed, safe to re-attempt later.
                Resolution::Failed(reason) => {
                    self.ledger.fail(&row.key, &reason);
                    report.failed.push(row.key);
                }
                // Ambiguous / no probe → never fabricate a verdict: escalate loudly.
                Resolution::Manual => {
                    let reason =
                        "reconcile probe returned Ambiguous or the capability declares no probe"
                            .to_string();
                    self.ledger.escalate_manual(&row.key, &reason);
                    self.escalation.escalate(&ReconIncident {
                        key: row.key.clone(),
                        tool: row.tool,
                        args: row.args,
                        claimed_at: row.claimed_at,
                        reason,
                    });
                    report.escalated.push(row.key);
                }
            }
        }
        report
    }

    /// Start the **active background sweep**: spawn a thread that runs one [`sweep_once`] pass, then
    /// waits up to `interval` before the next — returning a [`SweepHandle`] whose `stop()` cleanly
    /// joins the loop. This is the daemon-facing entrypoint (the daemon owns the interval +
    /// lifecycle; wiring it into the daemon supervisor is the runtime's job — this is the clean,
    /// self-contained handle it drives).
    ///
    /// Shutdown is **responsive, not interval-bound**: the inter-pass wait is a condvar timed-wait,
    /// so `stop()` interrupts a sleeping loop *immediately* and joins — a daemon with a 30s sweep
    /// interval does not block 30s on shutdown. A `std::thread::sleep(interval)` (the naive form)
    /// would pin shutdown latency to a full interval, which is unacceptable for a supervised daemon.
    /// One pass always runs before the first wait, so a lost-ack row present at spawn is reconciled
    /// promptly regardless of `interval`.
    pub fn spawn(self: Arc<Self>, interval: std::time::Duration) -> SweepHandle {
        let shared = Arc::new(SweepShared {
            state: Mutex::new(false),
            wake: std::sync::Condvar::new(),
            passes: std::sync::atomic::AtomicU64::new(0),
        });
        let loop_shared = Arc::clone(&shared);
        let join = std::thread::spawn(move || loop {
            let _ = self.sweep_once();
            loop_shared
                .passes
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            // Wait up to `interval`, but wake instantly if `stop` was signalled — either already
            // (checked before the wait, closing the signal-during-sweep race) or during the wait.
            let mut stop = loop_shared.state.lock().unwrap();
            if *stop {
                break;
            }
            let (guard, _timed_out) = loop_shared.wake.wait_timeout(stop, interval).unwrap();
            stop = guard;
            if *stop {
                break;
            }
        });
        SweepHandle {
            shared,
            join: Some(join),
        }
    }
}

/// Shared state between a [`SweepHandle`] and its background loop: the stop flag (guarded so a
/// signal + condvar-notify is race-free), the wakeup condvar, and a pass counter for observability.
struct SweepShared {
    state: Mutex<bool>,
    wake: std::sync::Condvar,
    passes: std::sync::atomic::AtomicU64,
}

/// Handle to a running background sweep ([`ReconcilerSweeper::spawn`]). Dropping it signals stop and
/// joins; call [`SweepHandle::stop`] to do so explicitly. Shutdown wakes the loop immediately rather
/// than waiting out the current sweep interval.
pub struct SweepHandle {
    shared: Arc<SweepShared>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl SweepHandle {
    /// Signal the loop to stop and wait for the thread to finish its current pass. Returns promptly:
    /// a loop asleep between passes is woken at once, not after the remaining interval.
    pub fn stop(mut self) {
        self.signal_and_join();
    }

    /// How many full sweep passes the background loop has completed so far — monitoring/liveness
    /// signal for the daemon supervisor (a stalled sweep stops advancing this).
    pub fn passes_completed(&self) -> u64 {
        self.shared.passes.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn signal_and_join(&mut self) {
        // Set the flag UNDER the lock, then notify — so a loop about to enter `wait_timeout` cannot
        // miss the signal (the classic lost-wakeup): it either sees `*stop == true` before waiting,
        // or is woken by the notify.
        {
            let mut stop = self.shared.state.lock().unwrap();
            *stop = true;
        }
        self.shared.wake.notify_all();
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

impl Drop for SweepHandle {
    fn drop(&mut self) {
        self.signal_and_join();
    }
}

// ---------------- Saga (multi-step with compensation) ----------------

pub type Action = Box<dyn Fn() -> Result<String, String> + Send + Sync>;
pub type Compensate = Box<dyn Fn() -> Result<(), String> + Send + Sync>;

/// One step of a [`ToolRuntime::dispatch_saga`] run: a named, registered capability plus the raw
/// args to invoke it with — the bridge from a saga's `(tool, args)` shape into the same dispatch
/// path every other call uses (see `dispatch_saga`'s own doc for why this exists as a distinct type
/// from [`SagaStep`], which carries caller-supplied closures rather than a registry lookup).
pub struct SagaStepRequest<'a> {
    pub tool: &'a str,
    pub args: &'a str,
}

/// One saga step: an action and its compensating action (run on later failure).
pub struct SagaStep {
    pub name: String,
    pub action: Action,
    pub compensate: Compensate,
}

impl SagaStep {
    pub fn new(name: &str, action: Action, compensate: Compensate) -> Self {
        SagaStep {
            name: name.to_string(),
            action,
            compensate,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SagaOutcome {
    Completed(Vec<String>),
    /// A step failed; all completed steps were compensated (world restored).
    Compensated {
        failed_step: String,
        reason: String,
    },
    /// A step failed AND some compensations also failed — the world is half-changed (honest).
    FailedPartial {
        failed_step: String,
        reason: String,
        uncompensated: Vec<String>,
    },
}

/// Run a saga: on a step failure, compensate the completed steps in reverse.
pub fn run_saga(steps: Vec<SagaStep>) -> SagaOutcome {
    let mut done: Vec<&SagaStep> = Vec::new();
    let mut results: Vec<String> = Vec::new();
    for step in &steps {
        match (step.action)() {
            Ok(r) => {
                results.push(r);
                done.push(step);
            }
            Err(reason) => {
                let mut uncompensated = Vec::new();
                for s in done.iter().rev() {
                    if let Err(ce) = (s.compensate)() {
                        uncompensated.push(format!("{}: {ce}", s.name));
                    }
                }
                return if uncompensated.is_empty() {
                    SagaOutcome::Compensated {
                        failed_step: step.name.clone(),
                        reason,
                    }
                } else {
                    SagaOutcome::FailedPartial {
                        failed_step: step.name.clone(),
                        reason,
                        uncompensated,
                    }
                };
            }
        }
    }
    SagaOutcome::Completed(results)
}

/// One saga step whose action is tracked by the **exactly-once ledger** (§1.3): the step carries its
/// own semantic idempotency `key`, so a saga replayed after a mid-way crash re-adopts the results of
/// steps that already committed instead of re-executing them.
pub struct LedgerSagaStep {
    pub name: String,
    /// The semantic idempotency key for THIS step (§1.2 discipline, per step). Must be derived from
    /// the step's semantic args, never a timestamp/nonce.
    pub key: String,
    pub action: Action,
    pub compensate: Compensate,
}

impl LedgerSagaStep {
    pub fn new(name: &str, key: &str, action: Action, compensate: Compensate) -> Self {
        LedgerSagaStep {
            name: name.to_string(),
            key: key.to_string(),
            action,
            compensate,
        }
    }
}

/// Run a saga whose every step is **ledger-tracked** (§1.3): before executing a step the runner
/// claims its idempotency slot; a step already `COMMITTED` on a prior saga attempt is **not
/// re-executed** (its stored result is adopted), a `Fresh` step executes and commits, and a step left
/// `InDoubt` by a crashed prior attempt is treated as a failure that triggers compensation — never a
/// blind re-run of a possibly-completed side effect. On a step failure the completed steps are
/// compensated in reverse; a non-compensable step surfaces as [`SagaOutcome::FailedPartial`] (honest,
/// never a claimed clean rollback). This is the exactly-once ledger of §1.2 applied to each step of a
/// composite action, so "update Jira, then create the MR, then notify" is safe to retry as a whole.
pub fn run_saga_ledgered(ledger: &dyn Ledger, steps: Vec<LedgerSagaStep>) -> SagaOutcome {
    let mut done: Vec<&LedgerSagaStep> = Vec::new();
    let mut results: Vec<String> = Vec::new();
    for step in &steps {
        let step_result: Result<String, String> = match ledger.claim(&step.key) {
            // Already committed on a prior attempt — adopt, do NOT re-execute (exactly-once).
            Claim::Committed(r) => Ok(r),
            // A prior attempt left this step ambiguous — do not guess; fail into compensation.
            Claim::InDoubt => Err(format!(
                "step '{}' is in-doubt from a prior attempt (reconcile before retrying the saga)",
                step.name
            )),
            // First time — record probe metadata, execute, commit/fail under the key.
            Claim::Fresh => {
                ledger.record_pending_meta(&step.key, &step.name, "");
                match (step.action)() {
                    Ok(r) => {
                        ledger.commit(&step.key, &r);
                        Ok(r)
                    }
                    Err(e) => {
                        ledger.fail(&step.key, &e);
                        Err(e)
                    }
                }
            }
        };
        match step_result {
            Ok(r) => {
                results.push(r);
                done.push(step);
            }
            Err(reason) => {
                let mut uncompensated = Vec::new();
                for s in done.iter().rev() {
                    if let Err(ce) = (s.compensate)() {
                        uncompensated.push(format!("{}: {ce}", s.name));
                    }
                }
                return if uncompensated.is_empty() {
                    SagaOutcome::Compensated {
                        failed_step: step.name.clone(),
                        reason,
                    }
                } else {
                    SagaOutcome::FailedPartial {
                        failed_step: step.name.clone(),
                        reason,
                        uncompensated,
                    }
                };
            }
        }
    }
    SagaOutcome::Completed(results)
}

// ==================== On-behalf-of authorization + least-privilege (§1.6) ====================
//
// The agent NEVER executes under its own ambient identity. Every dispatch that carries an
// [`OboContext`] is authorized as the requesting user against THREE independent layers, ALL of which
// must pass (§1.6): (1) a scoped DECLARED GRANT on the harness/role, (2) the ISSUED connector scope
// the user's own credential actually covers, (3) RESOURCE-level ABAC — the resource's data-class must
// be within the user's clearance. A missing grant is a HARD, structured denial; the runtime never
// substitutes the agent's broader ambient credential to "help" the call succeed — that substitution
// IS the confused-deputy failure mode, and refusing it is the fix. A sub-agent inherits the parent's
// context and can only NARROW it — it can never present broader credentials than the human who
// started the turn holds (delegation across sub-agents, not just single-hop).
//
// KNOWN SERVED-PATH GAP (named honestly, not hidden): `Grant::covers`'s resource-pattern scoping in
// this module is fully real and proven offline —
// `r11_obo_three_layer.rs::scenario5_scoped_grant_allows_only_the_named_resource` exercises the exact
// design scenario 5 (a grant scoped to `settlement_batches` succeeds on that resource and is denied on
// `ledger_accounts` in the same turn). The reserved served-path crate (`ainxt-runtime`, live agent
// loop §7c) currently constructs every principal's OBO grants as `Grant::new(capability, "*", "*")` —
// a blanket wildcard on resource AND action, which collapses layer 1's scoping to a no-op on the LIVE
// path even though the mechanism itself is real. Closing this for real requires threading real
// per-capability `resource_pattern` declarations from the harness/role manifest through to that call
// site (a `Principal`/JWT-claims shape change) — out of this crate's boundary and inside a crate under
// heavy concurrent edit this round. The clean entrypoint (`Grant::new`) already exists and is already
// proven correct; only the served caller needs to stop discarding the pattern.
pub mod obo {
    use ainxt_types::DataClass;
    use std::collections::BTreeSet;
    use std::fmt;

    /// A scoped declared grant (§1.6 layer 1): `{capability, resource_pattern, action}`. Never a
    /// blanket `connector.postgres.*` — the pattern scopes WHICH resources and WHICH action. A grant
    /// `covers` a call iff the capability matches (exact, or a `foo.*` prefix wildcard), the resource
    /// matches the pattern (exact, `*` = any, or a `prefix*` glob), and the action matches (exact or
    /// `*`).
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Grant {
        pub capability: String,
        pub resource_pattern: String,
        pub action: String,
    }

    impl Grant {
        pub fn new(capability: &str, resource_pattern: &str, action: &str) -> Self {
            Grant {
                capability: capability.to_string(),
                resource_pattern: resource_pattern.to_string(),
                action: action.to_string(),
            }
        }
        fn cap_matches(&self, capability: &str) -> bool {
            match self.capability.strip_suffix('*') {
                Some(prefix) => capability.starts_with(prefix),
                None => self.capability == capability,
            }
        }
        fn action_matches(&self, action: &str) -> bool {
            self.action == "*" || self.action == action
        }
        fn resource_matches(&self, resource: Option<&str>) -> bool {
            match resource {
                None => true, // a call with no resource is only resource-unscoped; the pattern is moot
                Some(r) => match self.resource_pattern.as_str() {
                    "*" => true,
                    pat => match pat.strip_suffix('*') {
                        Some(prefix) => r.starts_with(prefix),
                        None => pat == r,
                    },
                },
            }
        }
        /// Whether this grant authorizes `(capability, resource, action)`.
        pub fn covers(&self, capability: &str, resource: Option<&str>, action: &str) -> bool {
            self.cap_matches(capability)
                && self.action_matches(action)
                && self.resource_matches(resource)
        }
    }

    /// The resource-level ABAC seam (§1.6 layer 3): the data-class of a named resource, so the runtime
    /// can require it be within the caller's clearance. A resource unknown to the policy is treated
    /// conservatively (its class is supplied by the impl; the reference impl returns `Internal` for
    /// unmapped resources, and a stricter deployment can fail-closed to a higher floor).
    pub trait ResourceAbac: Send + Sync {
        fn data_class(&self, resource: &str) -> DataClass;
    }

    /// A [`ResourceAbac`] backed by an explicit `resource -> class` map; unmapped resources default to
    /// `Internal` (the ordinary internal floor). Deterministic reference impl.
    #[derive(Default)]
    pub struct MapAbac {
        classes: std::collections::BTreeMap<String, DataClass>,
        default_class: Option<DataClass>,
    }
    impl MapAbac {
        pub fn new() -> Self {
            Self::default()
        }
        pub fn with(mut self, resource: &str, class: DataClass) -> Self {
            self.classes.insert(resource.to_string(), class);
            self
        }
        /// Set the class returned for an UNMAPPED resource (defaults to `Internal`). A stricter
        /// deployment sets this to a higher floor to fail-closed on unknown resources.
        pub fn with_default(mut self, class: DataClass) -> Self {
            self.default_class = Some(class);
            self
        }
    }
    impl ResourceAbac for MapAbac {
        fn data_class(&self, resource: &str) -> DataClass {
            self.classes
                .get(resource)
                .copied()
                .unwrap_or(self.default_class.unwrap_or(DataClass::Internal))
        }
    }

    /// The resolved on-behalf-of context threaded from the turn's JWT (§1.6). Production builds this
    /// from the request principal / [`ainxt_identity`](https://docs.rs) delegation chain; the fields
    /// here are the three layers the policy needs. A sub-agent gets a [`OboContext::delegate`] child.
    #[derive(Debug, Clone)]
    pub struct OboContext {
        pub user_id: String,
        /// Layer 1: the scoped declared grants on the harness/role.
        pub grants: Vec<Grant>,
        /// Layer 2: the capabilities the user's OWN issued credential actually covers (GitLab token
        /// scopes, Graph consent). A harness grant cannot exceed this.
        pub issued_scope: BTreeSet<String>,
        /// Layer 3: the max data-class this user may touch (clearance).
        pub clearance: DataClass,
        /// Delegation depth — 0 for the human turn, +1 per sub-agent hop (audit / loop-guard).
        pub depth: u32,
    }

    impl OboContext {
        pub fn new(
            user_id: impl Into<String>,
            grants: Vec<Grant>,
            issued_scope: impl IntoIterator<Item = String>,
            clearance: DataClass,
        ) -> Self {
            OboContext {
                user_id: user_id.into(),
                grants,
                issued_scope: issued_scope.into_iter().collect(),
                clearance,
                depth: 0,
            }
        }

        /// Produce a sub-agent context that can only NARROW this one (§1.6, scenario 6): the child
        /// keeps only grants whose capability is in `keep_capabilities`, only the intersection of the
        /// issued scope, a clearance clamped to `min(parent, requested)`, and `depth + 1`. There is no
        /// API to ADD a grant, scope, or clearance the parent lacks — a sub-agent structurally cannot
        /// present broader credentials than the human who started the turn.
        pub fn delegate(
            &self,
            keep_capabilities: &[&str],
            requested_clearance: DataClass,
        ) -> OboContext {
            let keep: BTreeSet<&str> = keep_capabilities.iter().copied().collect();
            let grants = self
                .grants
                .iter()
                .filter(|g| keep.contains(g.capability.as_str()))
                .cloned()
                .collect();
            let issued_scope = self
                .issued_scope
                .iter()
                .filter(|c| keep.contains(c.as_str()))
                .cloned()
                .collect();
            OboContext {
                user_id: self.user_id.clone(),
                grants,
                issued_scope,
                // Clamp DOWN only — a child can never widen clearance.
                clearance: self.clearance.min(requested_clearance),
                depth: self.depth + 1,
            }
        }

        /// A verbatim sub-agent inheritance (§1.6, scenario 6): the child evaluates under the SAME
        /// context (all grants/scope/clearance carried through), depth + 1. Used when a sub-agent is
        /// trusted with the parent's full authority but still cannot exceed it.
        pub fn inherit(&self) -> OboContext {
            OboContext {
                depth: self.depth + 1,
                ..self.clone()
            }
        }

        fn issued_covers(&self, capability: &str) -> bool {
            // Exact, or a held `foo.*` scope, or a held scope that is a dotted prefix of the capability.
            self.issued_scope.iter().any(|s| {
                s == capability
                    || s.strip_suffix('*')
                        .is_some_and(|p| capability.starts_with(p))
                    || capability
                        .strip_prefix(s)
                        .is_some_and(|rest| rest.starts_with('.'))
            })
        }
    }

    /// Why an OBO authorization failed (§1.6) — always a HARD, structured denial. Never falls back to
    /// the agent's ambient credential.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum OboDenial {
        /// GAP-FIX identity-payments (ADR-016 §3.3/§4 Layer 3) — the grant vocabulary has no word for
        /// `PaymentInitiating`: a capability whose name matches the payment-initiation signature is
        /// refused BEFORE any grant, issued-scope, or clearance check runs, so no OBO context — no
        /// matter how privileged, even a bare `Grant::new("*", "*", "*")` — can carry the authority.
        /// This is independent of, and does not rely on, Layer 2's registry refusal: even if a
        /// payment-signature capability somehow reached this policy (a different admission path, a
        /// future registry bug), the grant vocabulary itself is structurally incapable of authorizing
        /// it. Confused-deputy (Pass-5 [AI]) is closed here for this class specifically.
        PaymentInitiatingNotRepresentable(String),
        /// Layer 1: no declared grant covers this `(capability, resource, action)`.
        NoGrant {
            capability: String,
            resource: Option<String>,
            action: String,
        },
        /// Layer 2: the user's OWN issued credential does not cover this capability (a harness grant
        /// cannot grant what the user's credential lacks).
        OutOfIssuedScope(String),
        /// Layer 3: the resource's data-class exceeds the user's clearance.
        ResourceAboveClearance {
            resource: String,
            class: DataClass,
            clearance: DataClass,
        },
    }

    impl fmt::Display for OboDenial {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                OboDenial::PaymentInitiatingNotRepresentable(capability) => write!(
                    f,
                    "OBO denied: '{capability}' matches a payment-initiation signature; no OBO grant \
                     can represent this authority (ADR-016 §3.3 — the grant vocabulary has no word \
                     for PaymentInitiating)"
                ),
                OboDenial::NoGrant {
                    capability,
                    resource,
                    action,
                } => write!(
                    f,
                    "OBO denied: no grant for capability '{capability}' action '{action}' on \
                     resource {resource:?} (agent's ambient credential is never substituted)"
                ),
                OboDenial::OutOfIssuedScope(c) => write!(
                    f,
                    "OBO denied: capability '{c}' is outside the user's own issued credential scope"
                ),
                OboDenial::ResourceAboveClearance {
                    resource,
                    class,
                    clearance,
                } => write!(
                    f,
                    "OBO denied: resource '{resource}' is classified {} but the user's clearance is \
                     only {}",
                    class.as_str(),
                    clearance.as_str()
                ),
            }
        }
    }

    /// The OBO policy seam (§1.6). `authorize` answers the one question: *can THIS user, via this
    /// capability, do this action on this resource?* — evaluated against all three layers.
    pub trait OboPolicy: Send + Sync {
        fn authorize(
            &self,
            ctx: &OboContext,
            capability: &str,
            resource: Option<&str>,
            action: &str,
        ) -> Result<(), OboDenial>;
    }

    /// One resolved OBO authorization decision (§1.6: "Every OBO decision (granted **or** denied) is
    /// written to the Event Log beside the tool call, reconstructable for audit two years later").
    /// This is the record [`ToolRuntime::dispatch_obo_audited`](crate::ToolRuntime::dispatch_obo_audited)
    /// emits before it either dispatches (granted) or hard-blocks (denied) — so the audit trail exists
    /// for the DENIED case too, which is exactly the confused-deputy attempt a regulator will ask
    /// about.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct OboDecision {
        /// The user the call was authorized *as* — never the agent's ambient identity.
        pub user_id: String,
        pub capability: String,
        /// The resource the call targets (for the audit record). A display/UI layer must NOT echo a
        /// sensitive id outward — the model-facing denial already omits it — but the tamper-evident
        /// audit sink retains it so the decision is fully reconstructable.
        pub resource: Option<String>,
        pub action: String,
        /// Delegation depth: 0 = the human turn, +1 per sub-agent hop. A denied sub-agent call
        /// records the hop that attempted to exceed the parent's authority.
        pub depth: u32,
        /// `Ok(())` = granted; `Err(denial)` = the structured hard denial. There is no third
        /// "fell back to ambient" state — that path does not exist (the confused-deputy fix).
        pub verdict: Result<(), OboDenial>,
    }

    impl OboDecision {
        /// Whether the call was authorized.
        pub fn granted(&self) -> bool {
            self.verdict.is_ok()
        }
    }

    /// The audit seam every OBO decision is written to (§1.6). Production plugs the tamper-evident
    /// Event Log behind this; [`VecOboAudit`] is the deterministic offline reference used by tests.
    /// Keeping it a distinct, small trait (rather than reusing a bulky engine audit type) is what lets
    /// the reserved served engine hot-wire the audited dispatch entrypoint without dragging a
    /// dependency cycle back into this leaf crate.
    pub trait OboDecisionSink: Send + Sync {
        fn record(&self, decision: &OboDecision);
    }

    /// A no-op [`OboDecisionSink`] — the default behind the un-audited [`ToolRuntime::dispatch_obo`]
    /// (crate::ToolRuntime::dispatch_obo) so the plain entrypoint keeps its exact prior behavior.
    pub struct NoOboAudit;
    impl OboDecisionSink for NoOboAudit {
        fn record(&self, _decision: &OboDecision) {}
    }

    /// A deterministic in-memory [`OboDecisionSink`] (tests / dev): every decision is appended in
    /// order. The production tamper-evident Event Log implements the same trait.
    #[derive(Default)]
    pub struct VecOboAudit {
        decisions: std::sync::Mutex<Vec<OboDecision>>,
    }
    impl VecOboAudit {
        pub fn new() -> Self {
            Self::default()
        }
        /// A snapshot of every recorded decision, in order.
        pub fn decisions(&self) -> Vec<OboDecision> {
            self.decisions
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        }
        /// How many decisions have been recorded.
        pub fn len(&self) -> usize {
            self.decisions
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .len()
        }
        pub fn is_empty(&self) -> bool {
            self.len() == 0
        }
    }
    impl OboDecisionSink for VecOboAudit {
        fn record(&self, decision: &OboDecision) {
            self.decisions
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(decision.clone());
        }
    }

    /// The turnkey DEFAULT [`OboDecisionSink`] the served daemon installs (§1.6: "Every OBO decision
    /// (granted **or** denied) is written to the Event Log beside the tool call, reconstructable for
    /// audit two years later"). Writes each decision — including a DENIED confused-deputy attempt and a
    /// sub-agent hop at `depth > 0` — as one record on the tamper-evident [`EventLog`]. Production hands
    /// it the same durable `EventLog` the engine already uses (a file-backed / DB-backed impl survives
    /// restarts); offline tests hand it an in-memory or `JsonlEventLog`. Keeping the audit on the
    /// hash-chained log is what makes a regulator able to reconstruct the decision two years later.
    pub struct EventLogOboAudit<L: ainxt_eventlog::EventLog> {
        log: L,
        session: String,
    }

    impl<L: ainxt_eventlog::EventLog> EventLogOboAudit<L> {
        /// The default OBO audit session (`__obo__`). Use [`with_session`](Self::with_session) to
        /// co-locate the OBO decisions with a specific turn/session's records.
        pub fn new(log: L) -> Self {
            EventLogOboAudit {
                log,
                session: "__obo__".to_string(),
            }
        }
        pub fn with_session(log: L, session: impl Into<String>) -> Self {
            EventLogOboAudit {
                log,
                session: session.into(),
            }
        }
        /// Borrow the backing log (e.g. an offline test reads/verifies the recorded decisions).
        pub fn log(&self) -> &L {
            &self.log
        }
        pub fn session(&self) -> &str {
            &self.session
        }
    }

    impl<L: ainxt_eventlog::EventLog> OboDecisionSink for EventLogOboAudit<L> {
        fn record(&self, decision: &OboDecision) {
            let verdict = match &decision.verdict {
                Ok(()) => "GRANTED".to_string(),
                Err(denial) => format!("DENIED:{denial}"),
            };
            let text = format!(
                "cap={} action={} resource={:?} depth={} verdict={}",
                decision.capability, decision.action, decision.resource, decision.depth, verdict
            );
            // The audit write must never crash the dispatch path (redact-and-proceed spirit); a log
            // append failure is swallowed here — a durable log's own error path handles persistence.
            let _ = self
                .log
                .append(&self.session, &decision.user_id, "obo_decision", &text);
        }
    }

    /// The reference three-layer policy (§1.6): declared grant ∧ issued scope ∧ resource ABAC, ALL
    /// required. Production plugs the platform's real ABAC behind [`ResourceAbac`]; the layers and the
    /// no-ambient-substitution rule are the same.
    pub struct ThreeLayerPolicy<A: ResourceAbac> {
        abac: A,
    }

    impl<A: ResourceAbac> ThreeLayerPolicy<A> {
        pub fn new(abac: A) -> Self {
            ThreeLayerPolicy { abac }
        }
    }

    impl<A: ResourceAbac> OboPolicy for ThreeLayerPolicy<A> {
        fn authorize(
            &self,
            ctx: &OboContext,
            capability: &str,
            resource: Option<&str>,
            action: &str,
        ) -> Result<(), OboDenial> {
            // GAP-FIX identity-payments (ADR-016 §4 Layer 3) — the payment-initiation signature check
            // runs BEFORE layer 1, so it does not matter what grant the caller holds: a capability
            // that matches the deterministic payment-initiation signature is refused before any grant
            // is even consulted. This is what makes the denial independent of Layer 2's registry
            // refusal (§4's "five independent structural denials" — this is layer 3's).
            if super::is_payment_signature(capability) {
                return Err(OboDenial::PaymentInitiatingNotRepresentable(
                    capability.to_string(),
                ));
            }
            // Layer 1 — a declared grant must cover the call.
            if !ctx
                .grants
                .iter()
                .any(|g| g.covers(capability, resource, action))
            {
                return Err(OboDenial::NoGrant {
                    capability: capability.to_string(),
                    resource: resource.map(str::to_string),
                    action: action.to_string(),
                });
            }
            // Layer 2 — the user's own issued credential must cover the capability.
            if !ctx.issued_covers(capability) {
                return Err(OboDenial::OutOfIssuedScope(capability.to_string()));
            }
            // Layer 3 — the resource's data-class must be within the user's clearance.
            if let Some(r) = resource {
                let class = self.abac.data_class(r);
                if class > ctx.clearance {
                    return Err(OboDenial::ResourceAboveClearance {
                        resource: r.to_string(),
                        class,
                        clearance: ctx.clearance,
                    });
                }
            }
            Ok(())
        }
    }
}

// ============================ MCP adapter (ADR-002: MCP == native) ============================
pub mod mcp {
    //! An MCP tool is just a [`Tool`] whose `execute` delegates to a remote MCP server through an
    //! [`McpTransport`]. Because it implements the same trait, an MCP tool is registered in the
    //! same [`ToolRuntime`] and flows through the identical pipeline — schema validation, on-behalf-of
    //! authorization, the injection taint-gate, the approval gate, and the exactly-once ledger all
    //! apply uniformly. "MCP is an adapter," not a parallel code path.

    use super::{canonical_key, EffectClass, RiskTier, Tool, ToolError, ToolSchema};

    /// The transport to a remote MCP server. The real client (JSON-RPC over stdio/HTTP, async) is
    /// a later increment; this seam keeps the adapter testable with a mock and network-free here.
    pub trait McpTransport: Send + Sync {
        /// List the tools the server exposes (their schemas).
        fn list(&self) -> Vec<ToolSchema>;
        /// Invoke a remote tool. The result string re-enters the runtime as an UNTRUSTED tool
        /// result (the injection scanner treats it as such).
        fn call(&self, tool: &str, args: &str) -> Result<String, ToolError>;
    }

    /// Adapts ONE remote MCP tool to the native [`Tool`] trait.
    pub struct McpTool<T: McpTransport> {
        transport: std::sync::Arc<T>,
        schema: ToolSchema,
        /// Remote effects are opaque, so default to the conservative, safe classification.
        effect: EffectClass,
        risk: RiskTier,
    }

    impl<T: McpTransport> McpTool<T> {
        /// Conservative defaults for an OPAQUE remote tool: SIDE-EFFECTING (ledgered, gated),
        /// egressing, and **High-risk** (requires the approval gate) — the safe assumptions when
        /// the server's true behavior is unknown. A read-only remote tool should be relaxed
        /// explicitly via `.with_effect(Pure).with_risk_tier(Low)`.
        pub fn new(transport: std::sync::Arc<T>, schema: ToolSchema) -> Self {
            McpTool {
                transport,
                schema,
                effect: EffectClass::SideEffecting,
                risk: RiskTier::High,
            }
        }
        /// Override the effect class when the server declares a tool is genuinely read-only/pure.
        pub fn with_effect(mut self, effect: EffectClass) -> Self {
            self.effect = effect;
            self
        }
        /// Override the risk tier (e.g. lower a trusted read-only remote tool to `Low`, or keep
        /// `High` so the engine's approval gate must clear a destructive remote action).
        pub fn with_risk_tier(mut self, risk: RiskTier) -> Self {
            self.risk = risk;
            self
        }
    }

    impl<T: McpTransport + 'static> Tool for McpTool<T> {
        fn name(&self) -> &str {
            &self.schema.name
        }
        fn effect_class(&self) -> EffectClass {
            self.effect
        }
        fn risk_tier(&self) -> RiskTier {
            self.risk
        }
        fn idempotency_key(&self, args: &str) -> Option<String> {
            // Side-effecting remote tools need an exactly-once key; canonicalize the (tool, args)
            // so a retried MCP call that reorders/reformats the JSON args cannot double-execute.
            match self.effect {
                EffectClass::SideEffecting => Some(canonical_key(&self.schema.name, args)),
                // Pure/Idempotent need no exactly-once key; a remote tool can never be
                // PaymentInitiating (register/dispatch refuse it) — no key either.
                EffectClass::Pure | EffectClass::Idempotent | EffectClass::PaymentInitiating => {
                    None
                }
            }
        }
        fn schema(&self) -> ToolSchema {
            self.schema.clone()
        }
        fn egress(&self) -> bool {
            true // an MCP call always leaves the box
        }
        fn execute(&self, args: &str) -> Result<String, ToolError> {
            self.transport.call(&self.schema.name, args)
        }
    }
}

// ==================== query_ledger: the safe NL-to-SQL capability (SURF-09) ====================
pub mod ledger_query {
    //! Wires the safe NL-to-SQL boundary ([`ainxt_nl2sql`]) onto the live tool path as a
    //! `query_ledger` capability (SURF-09). The model **never** emits raw SQL: it proposes a
    //! structured [`QueryIntent`] as JSON, which [`LedgerQueryTool::compile`] deserializes (a raw-SQL
    //! smuggle attempt as an extra JSON field is rejected by the intent's `deny_unknown_fields`) and
    //! [`validate_and_compile`]s against a startup [`Schema`] allowlist and the caller's [`Principal`]
    //! into a bounded, parameterized [`SafeQuery`] — over-clearance columns are hidden without leaking
    //! their existence (ADR-012), values become `$n` placeholders (SQL injection is structurally
    //! impossible), and native-DB RLS settings carry the caller identity out-of-band.
    //!
    //! The tool is also a native [`Tool`], so it appears in the model's function-calling manifest and
    //! registers into a [`ToolRuntime`] like any other capability. Its `execute` fails **closed**: a
    //! ledger read cannot run without a caller clearance for RLS, so the principal-scoped
    //! [`compile`](LedgerQueryTool::compile) is the only path that produces a runnable query.

    use super::{EffectClass, ParamSpec, Tool, ToolError, ToolSchema};
    use ainxt_nl2sql::{
        validate_and_compile, Column, DataClass, Principal, QueryError, QueryIntent, SafeQuery,
        Schema, Table,
    };
    use std::fmt;

    /// The canonical capability name exposed to the model's function-calling manifest.
    pub const QUERY_LEDGER: &str = "query_ledger";

    /// Why a `query_ledger` invocation was refused before any SQL could run.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum LedgerQueryError {
        /// The model's proposal was not a well-formed [`QueryIntent`] — INCLUDING an attempt to
        /// smuggle a raw SQL fragment (or any other unexpected key) into the JSON, which the intent's
        /// `deny_unknown_fields` rejects at deserialization. Carries the parser message.
        MalformedProposal(String),
        /// The proposal parsed but was refused by the NL-to-SQL boundary (unknown table,
        /// unknown/over-clearance column, empty projection, empty `IN` list, or a missing RLS
        /// attribute). Wraps the boundary's [`QueryError`] — note that "unknown" and "over-clearance"
        /// columns collapse to the same variant on purpose (no existence oracle, ADR-012).
        Rejected(QueryError),
    }

    impl fmt::Display for LedgerQueryError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                LedgerQueryError::MalformedProposal(m) => {
                    write!(f, "query_ledger proposal is not a valid QueryIntent: {m}")
                }
                LedgerQueryError::Rejected(e) => write!(f, "query_ledger proposal rejected: {e}"),
            }
        }
    }

    impl std::error::Error for LedgerQueryError {}

    /// The `query_ledger` capability: a startup-fixed [`Schema`] allowlist plus the principal-scoped
    /// compile boundary. One instance is built once at startup (the allowlist is a git-controlled
    /// policy) and shared; the caller's [`Principal`] is supplied per request.
    pub struct LedgerQueryTool {
        schema: Schema,
    }

    impl LedgerQueryTool {
        /// Build over an explicit allowlist (custom deployments / tests).
        pub fn new(schema: Schema) -> Self {
            LedgerQueryTool { schema }
        }

        /// The default ledger allowlist, built once at startup. Columns span the clearance
        /// ladder so ADR-012 hiding is exercised: `entry_id` (Internal), `amount_minor`
        /// (Confidential), `counterparty_acct` (RegulatedPayment), `holder_pan` (Pii). A malformed
        /// static allowlist is a programmer error, so construction `expect`s at startup.
        /// Configurable: use `LedgerQueryTool { schema }` directly to supply a custom schema.
        pub fn default_ledger() -> Self {
            let table = Table::new(
                "ledger_entries",
                vec![
                    Column::new("entry_id", DataClass::Internal).expect("valid ident"),
                    Column::new("amount_minor", DataClass::Confidential).expect("valid ident"),
                    Column::new("counterparty_acct", DataClass::RegulatedPayment)
                        .expect("valid ident"),
                    Column::new("holder_pan", DataClass::Pii).expect("valid ident"),
                ],
            )
            .expect("valid ledger table");
            let schema = Schema::new(vec![table])
                .expect("valid schema")
                .with_max_limit(500)
                .expect("valid max limit");
            LedgerQueryTool { schema }
        }

        /// The allowlist this capability compiles against.
        pub fn schema(&self) -> &Schema {
            &self.schema
        }

        /// THE live handler: deserialize the model's JSON `proposal` into a [`QueryIntent`] (a raw-SQL
        /// smuggle is rejected here by `deny_unknown_fields`), then [`validate_and_compile`] it against
        /// the allowlist and `principal` into a runnable [`SafeQuery`]. The returned query's `sql` is
        /// parameterized (`$1`, `$2`, …), carries no caller value and no `;`, and its `settings` bind
        /// the caller identity for native-DB RLS — the driver runs `sql` with `params` after applying
        /// `settings`. Fail-closed: any parse or authorization problem is an `Err`, never a broad scan.
        pub fn compile(
            &self,
            proposal: &str,
            principal: &Principal,
        ) -> Result<SafeQuery, LedgerQueryError> {
            let intent: QueryIntent = serde_json::from_str(proposal)
                .map_err(|e| LedgerQueryError::MalformedProposal(e.to_string()))?;
            validate_and_compile(&intent, &self.schema, principal)
                .map_err(LedgerQueryError::Rejected)
        }
    }

    impl Tool for LedgerQueryTool {
        fn name(&self) -> &str {
            QUERY_LEDGER
        }
        /// Compiling a `SELECT`-only query has no side effect (the produced [`SafeQuery`] is executed
        /// by the read-only DB layer downstream), so the capability is [`EffectClass::Pure`].
        fn effect_class(&self) -> EffectClass {
            EffectClass::Pure
        }
        fn schema(&self) -> ToolSchema {
            ToolSchema {
                name: QUERY_LEDGER.into(),
                description: "Query the ledger/reporting store by proposing a structured, SELECT-only \
                              QueryIntent as JSON (columns, table, filters, order_by, limit). Raw SQL \
                              is not accepted; results are clearance-scoped to you."
                    .into(),
                // The proposal is a whole QueryIntent JSON object which this tool parses and validates
                // itself (strictly, via deny_unknown_fields) — richer than the scalar ParamSpec fields.
                parameters: ParamSpec::Text,
            }
        }
        /// Fail-closed: a ledger read is clearance-scoped (ADR-012 RLS), and the sync [`Tool::execute`]
        /// signature carries no [`Principal`], so a query cannot be safely run here. The runtime resolves
        /// the JWT into a `Principal` and calls [`LedgerQueryTool::compile`] instead — the ONLY path
        /// that produces a runnable [`SafeQuery`]. Never emit an unscoped query.
        fn execute(&self, _args: &str) -> Result<String, ToolError> {
            Err(ToolError::Execution(
                "query_ledger must be invoked through the principal-scoped boundary \
                 (LedgerQueryTool::compile): a ledger query cannot run without a caller clearance for \
                 row/column-level security (ADR-012)"
                    .into(),
            ))
        }
    }
}

// ============ §0 one-registry adapters: MCP + plugin register as native capabilities ============

pub mod mcp_bridge {
    //! Adapts an MCP-discovered tool (the real [`ainxt_mcp`] registry) into the native [`Tool`]
    //! trait so it registers into the SAME [`ToolRuntime`]/[`CapabilityRegistry`] and dispatches
    //! through the identical path (§0). This is the concrete "MCP is an adapter that registers
    //! wrapped capabilities" bridge: once wrapped, an MCP tool is — to the dispatcher — indis-
    //! tinguishable from a native one, so the approval gate, injection taint-gate, exactly-once
    //! ledger, and egress DLP all apply uniformly, with no origin branch downstream.
    //!
    //! Distinct from the crate's earlier [`super::mcp`] module: that adapts a single tool over the
    //! crate-local `McpTransport` seam; THIS bridges the full `ainxt_mcp::McpRegistry` (lazy/parallel
    //! discovery, per-`(user,url)` auth, namespace routing, TOFU pinning) — the gap was precisely
    //! that `McpRegistry`/`QualifiedTool` were referenced by nothing in the tool runtime.

    use super::{
        canonical_key, DataClass, EffectClass, ParamSpec, RiskTier, Tool, ToolError, ToolSchema,
    };
    use ainxt_mcp::{
        rank_session, AuthProvider, CoreSet, McpRegistry, PinStore, QualifiedTool, RankConfig,
    };
    use std::sync::Arc;

    /// Register an MCP runtime's already-plannable tools into the ONE unified
    /// [`CapabilityRegistry`](super::CapabilityRegistry) (§0), so each dispatches through the
    /// identical path as a native capability — no origin branch anywhere downstream.
    ///
    /// This is the clean crate-level entrypoint the served engine hot-wires: after
    /// [`ainxt_mcp::McpRegistry::discover_pinned`], hand its `.plannable()` set here. Only
    /// pinned-and-unchanged tools should be passed — a first-use / added / reworded tool is
    /// quarantined by the TOFU pin and must never reach the model's plannable set, so this function
    /// deliberately takes the *already-vetted* list rather than re-discovering (the vetting decision
    /// stays with the caller that holds the [`ainxt_mcp::PinStore`]).
    ///
    /// Each tool is adapted via [`McpCapability`] over the shared `registry`/`auth`, keyed to
    /// `user_id` (so the exactly-once ledger key is folded per acting principal). Conservative
    /// opaque-remote defaults apply (side-effecting, egressing, approval-gated). A tool the payment
    /// boundary refuses (ADR-016 Layer-2 — e.g. a remote tool whose name screams money movement) is
    /// skipped and omitted from the returned list, which names exactly what was admitted.
    ///
    /// Registers via [`super::CapabilityRegistry::try_register_governed`], not the bare
    /// `try_register` — §1.8's mandatory-reconcile-probe gate must apply to an MCP-discovered
    /// capability exactly as it does to a native one. `McpCapability`'s own default risk tier
    /// (`RiskTier::High`, the legacy single-phase approval tier — see its doc) sits below the gate's
    /// `HighRisk` trigger, so an unremarkable MCP tool is unaffected; the gate only bites the moment
    /// a deployment explicitly escalates a specific MCP tool to `RiskTier::HighRisk` (settlement-
    /// adjacent, irreversible) via [`McpCapability::with_risk_tier`] — exactly the case §1.8 exists
    /// for — and at that point it is refused unless [`McpCapability::with_reconcile_probe_declared`]
    /// has also been set, proving an out-of-band [`super::Reconciler`] genuinely covers it.
    pub fn register_plannable_mcp_tools(
        reg: &mut super::CapabilityRegistry,
        registry: Arc<McpRegistry>,
        auth: Arc<dyn AuthProvider>,
        user_id: &str,
        plannable: &[QualifiedTool],
    ) -> Vec<String> {
        let mut admitted = Vec::new();
        for qualified in plannable {
            let name = qualified.qualified_name.clone();
            let cap = McpCapability::new(
                Arc::clone(&registry),
                Arc::clone(&auth),
                user_id,
                qualified.clone(),
            );
            if reg.try_register_governed(Box::new(cap)).is_ok() {
                admitted.push(name);
            }
        }
        admitted
    }

    /// GAP-AUDIT tooling-mcp-plugins-routing — "MCP retrieval-ranking has zero callers":
    /// [`ainxt_mcp::rank_session`]/[`ainxt_mcp::CoreSet`]/[`ainxt_mcp::capability_search`] (§2.4's
    /// retrieval-based tool ranking at scale — BM25 relevance + an always-visible core set + session
    /// stickiness, the concrete answer to "hundreds of tools degrade tool-choice") were fully
    /// implemented and unit-tested in `ainxt-mcp` with ZERO callers outside that crate's own tests.
    /// [`register_plannable_mcp_tools`] (above) — the ONE real production entrypoint that puts a
    /// discovered MCP tool in front of the model — registered every TOFU-pinned tool unconditionally,
    /// with no top-K bound at all: the ranking subsystem existed and was correct, but nothing on the
    /// served path ever asked it a question.
    ///
    /// This is [`register_plannable_mcp_tools`] with a ranking gate in front of it: `plannable` is
    /// ranked via [`rank_session`] against `query` (the always-visible `core` set first, then the
    /// BM25-ranked, session-stickiness-boosted remainder truncated to `config.k`), and ONLY the
    /// resulting bounded set is registered — never the raw unranked discovery output. A tool outside
    /// the top-K is simply not registered THIS call; it remains discoverable via
    /// [`ainxt_mcp::capability_search`] (the §2.4 escape valve) run separately against the FULL
    /// `plannable` set, which a caller wires to a `capability.search` capability the same way any
    /// other tool is registered.
    ///
    /// Honest scope: true per-turn semantic relevance needs the turn's own text as `query`, which
    /// requires a live per-turn caller — today's one production call site
    /// (`ainxt-runtimed::register_served_mcp_runtime`) runs once at daemon composition, before any
    /// turn exists, so it passes an empty query (ranking still bounds cardinality to the core set +
    /// `config.k`, deterministically, even with no relevance signal). A future per-turn caller gets
    /// full semantic ranking for free by passing the turn's actual text through this SAME parameter —
    /// that per-turn wiring is a separate gap (no per-turn tool-schema assembly path exists yet at
    /// all; `ToolRuntime::schemas()` itself has no served caller either), not something this function
    /// can manufacture a live turn context for.
    pub fn register_plannable_mcp_tools_ranked(
        reg: &mut super::CapabilityRegistry,
        registry: Arc<McpRegistry>,
        auth: Arc<dyn AuthProvider>,
        user_id: &str,
        plannable: &[QualifiedTool],
        query: &str,
        core: &CoreSet,
        recently_used: &[String],
        config: RankConfig,
    ) -> Vec<String> {
        let ranked: Vec<QualifiedTool> =
            rank_session(query, plannable, core, recently_used, config)
                .into_iter()
                .map(|r| r.tool)
                .collect();
        register_plannable_mcp_tools(reg, registry, auth, user_id, &ranked)
    }

    /// One MCP-discovered (and, in production, TOFU-pinned) tool, adapted to [`Tool`]. Conservative
    /// opaque-remote defaults per the design: SIDE-EFFECTING (ledgered), egressing, and approval-
    /// gated (`RiskTier::High`). A server that declares a tool genuinely read-only relaxes these
    /// explicitly via [`McpCapability::with_effect`] / [`McpCapability::with_risk_tier`].
    pub struct McpCapability {
        registry: Arc<McpRegistry>,
        auth: Arc<dyn AuthProvider>,
        user_id: String,
        qualified: QualifiedTool,
        effect: EffectClass,
        risk: RiskTier,
        reconcile_probe_declared: bool,
    }

    impl McpCapability {
        pub fn new(
            registry: Arc<McpRegistry>,
            auth: Arc<dyn AuthProvider>,
            user_id: impl Into<String>,
            qualified: QualifiedTool,
        ) -> Self {
            McpCapability {
                registry,
                auth,
                user_id: user_id.into(),
                qualified,
                effect: EffectClass::SideEffecting,
                risk: RiskTier::High,
                reconcile_probe_declared: false,
            }
        }
        pub fn with_effect(mut self, effect: EffectClass) -> Self {
            self.effect = effect;
            self
        }
        pub fn with_risk_tier(mut self, risk: RiskTier) -> Self {
            self.risk = risk;
            self
        }
        /// Declare that an out-of-band [`super::Reconciler`] genuinely covers this specific
        /// MCP-discovered tool's downstream state (e.g. a deployment-specific probe that queries the
        /// remote system this MCP server fronts). §1.8/[`super::Tool::has_reconcile_probe`] is a
        /// registration-time CLAIM, not the probe logic itself — the actual reconcile behavior still
        /// lives in the `Reconciler` wired into the `ReconcilerSweeper`. Required (and otherwise
        /// unsatisfiable — an opaque remote MCP tool has no protocol-standard reconcile verb of its
        /// own) before [`RiskTier::HighRisk`] can be used with this capability: without it,
        /// [`super::CapabilityRegistry::try_register_governed`] — what
        /// [`register_plannable_mcp_tools`] uses — refuses registration rather than silently
        /// accepting a settlement-adjacent capability with no way to ever resolve a lost ack.
        pub fn with_reconcile_probe_declared(mut self, declared: bool) -> Self {
            self.reconcile_probe_declared = declared;
            self
        }
    }

    impl Tool for McpCapability {
        fn name(&self) -> &str {
            &self.qualified.qualified_name
        }
        fn effect_class(&self) -> EffectClass {
            self.effect
        }
        fn risk_tier(&self) -> RiskTier {
            self.risk
        }
        fn has_reconcile_probe(&self) -> bool {
            self.reconcile_probe_declared
        }
        fn idempotency_key(&self, args: &str) -> Option<String> {
            match self.effect {
                // A side-effecting remote call needs an exactly-once key; canonicalize (name, args)
                // so a reordered/reformatted retry cannot double-execute.
                EffectClass::SideEffecting => {
                    Some(canonical_key(&self.qualified.qualified_name, args))
                }
                EffectClass::Pure | EffectClass::Idempotent | EffectClass::PaymentInitiating => {
                    None
                }
            }
        }
        fn schema(&self) -> ToolSchema {
            ToolSchema {
                name: self.qualified.qualified_name.clone(),
                description: self.qualified.manifest.description.clone(),
                parameters: super::ParamSpec::Text,
            }
        }
        fn egress(&self) -> bool {
            true // an MCP call always leaves the box
        }
        fn destination(&self, _args: &str) -> Option<String> {
            // §1.7: the server URL is the trust boundary (§2.2) AND the egress destination — an MCP
            // capability always knows exactly where its call goes, so it can always be gated by
            // ToolRuntime::with_egress_allowlist, unlike a tool with no fixed destination. Reduced to
            // the bare host (scheme and path stripped) to match the allow-list's domain-glob
            // convention (`*.internal.example.com`-style patterns, per `egress_allowlist`'s own
            // tests) rather than requiring every entry to spell out an exact path.
            let url = &self.qualified.server_url;
            let after_scheme = url
                .split_once("://")
                .map(|(_, rest)| rest)
                .unwrap_or(url.as_str());
            let host = after_scheme.split('/').next().unwrap_or(after_scheme);
            Some(host.to_string())
        }
        fn declared_data_class(&self) -> DataClass {
            // §4.2 signal 1 for a remote tool: the class the SERVER declared in its (TOFU-pinned)
            // manifest. Untrusted — the arg-scan and the egress destination (signal 3, always
            // Confidential+ since an MCP call leaves the box) can only escalate above it.
            self.qualified.manifest.declared_data_class
        }
        fn execute(&self, args: &str) -> Result<String, ToolError> {
            match self.registry.call(
                &self.user_id,
                self.auth.as_ref(),
                &self.qualified.qualified_name,
                args,
            ) {
                Ok(res) if res.is_error => Err(ToolError::Execution(res.content)),
                Ok(res) => Ok(res.content),
                Err(e) => Err(ToolError::Execution(e.to_string())),
            }
        }
    }

    /// GAP-AUDIT tooling-mcp-plugins-routing — "Ranking escape valve capability.search never
    /// registered": [`ainxt_mcp::capability_search`]/[`ainxt_mcp::CAPABILITY_SEARCH`] (§2.4 — a BM25
    /// search over the FULL TOFU-approved MCP tool universe, for when the model's bounded top-K
    /// candidate set doesn't include a tool it needs) existed and was unit-tested, but was never
    /// registered as a dispatchable [`Tool`] anywhere on the served path — the model had a name for
    /// the escape valve (`CAPABILITY_SEARCH`) and no way to actually call it. This adapts it into the
    /// native [`Tool`] trait exactly like [`McpCapability`] above, so it registers into the SAME
    /// unified registry and appears in the model's function-calling manifest like any other
    /// capability.
    ///
    /// Read-only (`Pure`, never egresses, never touches the ledger): searches the caller's OWN
    /// TOFU-pinned-and-unchanged `plannable()` set — the identical vetted universe
    /// [`register_plannable_mcp_tools_ranked`] admits into the top-K — never a quarantined
    /// first-use/added/reworded tool, so the escape valve cannot surface (or let the model dispatch)
    /// anything the TOFU gate above has not already cleared.
    pub struct CapabilitySearchTool {
        mcp: Arc<McpRegistry>,
        auth: Arc<dyn AuthProvider>,
        pins: Arc<dyn PinStore>,
        /// Top-K matches to return; the escape valve's own budget, independent of
        /// [`RankConfig::k`] (the bounded per-turn candidate set) since this call is explicitly the
        /// "search past that bound" path.
        k: usize,
    }

    impl CapabilitySearchTool {
        /// `mcp`/`auth`/`pins` are the SAME shared handles the served composition root passes to
        /// [`register_served_mcp_runtime`](crate) — never a second, independently-built registry —
        /// so a search result is always drawn from (and gated by) the identical TOFU/pin state a
        /// dispatch of that same tool name would be. `k` defaults to 10.
        pub fn new(
            mcp: Arc<McpRegistry>,
            auth: Arc<dyn AuthProvider>,
            pins: Arc<dyn PinStore>,
        ) -> Self {
            CapabilitySearchTool {
                mcp,
                auth,
                pins,
                k: 10,
            }
        }
        pub fn with_k(mut self, k: usize) -> Self {
            self.k = k;
            self
        }
    }

    impl Tool for CapabilitySearchTool {
        fn name(&self) -> &str {
            ainxt_mcp::CAPABILITY_SEARCH
        }
        fn effect_class(&self) -> EffectClass {
            EffectClass::Pure
        }
        fn schema(&self) -> ToolSchema {
            ToolSchema {
                name: ainxt_mcp::CAPABILITY_SEARCH.into(),
                description: "Search the FULL tool registry by keyword for a capability outside your \
                              current visible tool list (the escape valve for when the tool you need \
                              wasn't in your planned top-K). Args: the raw search query text."
                    .into(),
                parameters: ParamSpec::Text,
            }
        }
        /// Fail-closed like [`super::super::ledger_query::LedgerQueryTool::execute`]: which tools are
        /// even VISIBLE to search depends on the CALLING principal's own TOFU-approval state
        /// (`discover_pinned(user_id, ..)`), so a caller-less invocation cannot be answered correctly
        /// — the runtime always dispatches through [`Tool::execute_as`] instead, which every
        /// `ToolRuntime::dispatch_*` entrypoint threads the acting principal through.
        fn execute(&self, _args: &str) -> Result<String, ToolError> {
            Err(ToolError::Execution(
                "capability.search must be invoked through the caller-attributed dispatch path \
                 (execute_as): the searchable tool set is scoped to the calling principal's own \
                 TOFU-approved servers, never resolved caller-less"
                    .into(),
            ))
        }
        fn execute_as(&self, args: &str, caller: Option<&str>) -> Result<String, ToolError> {
            let Some(user_id) = caller else {
                return self.execute(args);
            };
            let query = args.trim();
            if query.is_empty() {
                return Err(ToolError::Execution(
                    "capability.search requires a non-empty query".into(),
                ));
            }
            // The SAME TOFU-pinned-and-unchanged discovery `register_served_mcp_runtime` runs before
            // every turn's registration — never the raw, unvetted `discover()` — so a quarantined
            // (first-use/added/reworded) tool can never be surfaced or dispatched through this escape
            // valve either.
            let discovered =
                self.mcp
                    .discover_pinned(user_id, self.auth.as_ref(), self.pins.as_ref());
            let all_tools = discovered.plannable();
            let matches = ainxt_mcp::capability_search(query, &all_tools, self.k);
            let results: Vec<serde_json::Value> = matches
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "tool": r.tool.qualified_name,
                        "server": r.tool.server_name,
                        "description": r.tool.manifest.description,
                        "score": r.score,
                    })
                })
                .collect();
            serde_json::to_string(&serde_json::json!({ "matches": results }))
                .map_err(|e| ToolError::Execution(format!("capability.search: {e}")))
        }
    }
}

/// GAP-AUDIT tooling-mcp-plugins-routing — "Native-tools supply-chain parity". See
/// [`ToolRuntime::try_register_governed_pinned`] for how this is consulted.
pub mod native_supply_chain {
    //! A native-capability analogue of [`ainxt_plugin::supply_chain`]'s content-hash pin, scoped to
    //! `RiskTier::HighRisk` (the same tier §1.8's reconcile-probe mandate already targets). A plugin
    //! artifact is bytes fetched over the network and loaded dynamically, so its supply chain pins
    //! the compiled bytes; a native capability is first-party code compiled into the same binary as
    //! everything else, so there is no analogous "bytes fetched at load time" to hash. What CAN and
    //! should be pinned is the tool's DECLARED MANIFEST — everything that governs its admission and
    //! dispatch behavior (name, effect class, risk tier, egress, declared data class) — so a reviewer
    //! who approved "capability X is HighRisk + SideEffecting + non-egressing" catches it if a later
    //! code change silently relabels X as, say, Elevated risk or non-side-effecting, exactly the kind
    //! of drift a plugin's manifest-hash re-verification-on-every-load exists to catch (§3.4).

    use super::{RiskTier, Tool};
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;

    /// A content hash over everything that governs a native capability's admission + dispatch
    /// behavior. Length-prefixed fields — the same canonical discipline as
    /// [`ainxt_plugin::supply_chain::artifact_hash`] and the MCP TOFU pin — so a field boundary
    /// cannot be forged by shifting bytes. Two tools with the same name but a different effect
    /// class, risk tier, egress flag, or declared data class hash differently.
    pub fn native_manifest_hash(tool: &dyn Tool) -> String {
        let mut h = Sha256::new();
        let name = tool.name();
        h.update((name.len() as u64).to_le_bytes());
        h.update(name.as_bytes());
        h.update([tool.effect_class() as u8]);
        h.update([tool.risk_tier() as u8]);
        h.update([tool.egress() as u8]);
        h.update([tool.declared_data_class() as u8]);
        h.finalize().iter().map(|b| format!("{b:02x}")).collect::<String>()
    }

    /// One `native.lock` entry: the exact `{capability_name, manifest_hash, reviewer}` approved to
    /// register in an environment — the native-capability case of ADR-026's `control.lock`,
    /// structurally mirroring [`ainxt_plugin::supply_chain::LockEntry`].
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct NativeLockEntry {
        pub capability_name: String,
        pub manifest_hash: String,
        pub reviewer: String,
    }

    /// The per-environment native-capability lock — `capability_name -> NativeLockEntry`. What is
    /// approved to register here is a reviewed, git-trackable fact, not implicit "it compiled so
    /// it's trusted."
    #[derive(Debug, Clone, Default)]
    pub struct NativeControlLock {
        entries: BTreeMap<String, NativeLockEntry>,
    }
    impl NativeControlLock {
        pub fn new() -> Self {
            Self::default()
        }
        pub fn pin(&mut self, entry: NativeLockEntry) {
            self.entries.insert(entry.capability_name.clone(), entry);
        }
        pub fn get(&self, name: &str) -> Option<&NativeLockEntry> {
            self.entries.get(name)
        }
    }

    /// Why a HighRisk native capability was refused registration.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum NativeLoadError {
        /// No `native.lock` entry pins this capability name in this environment.
        NotInLock(String),
        /// The tool's live manifest hash does not match the reviewed pin (declared posture drifted
        /// since the pin was reviewed, or the capability was never reviewed under this name).
        HashMismatch { pinned: String, actual: String },
    }
    impl std::fmt::Display for NativeLoadError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                NativeLoadError::NotInLock(name) => {
                    write!(f, "native capability '{name}' is not pinned in native.lock")
                }
                NativeLoadError::HashMismatch { pinned, actual } => {
                    write!(
                        f,
                        "manifest hash {actual} does not match the pinned {pinned}"
                    )
                }
            }
        }
    }
    impl std::error::Error for NativeLoadError {}

    /// The load-time gate for a `HighRisk` native capability (parity with §3.4's plugin gate): the
    /// tool's live manifest hash must match a REVIEWED pin in `lock`. Any other risk tier is
    /// unaffected and returns `Ok` unconditionally — HighRisk already carries the biggest blast
    /// radius and is where the §1.8 reconcile-probe mandate already applies, so this closes the SAME
    /// tier's remaining gap rather than gating every capability (which would make every
    /// Low/Elevated/High-tier registration — the overwhelming majority — require a pin, a much
    /// bigger and unrequested behavior change).
    pub fn verify_native_for_registration(
        tool: &dyn Tool,
        lock: &NativeControlLock,
    ) -> Result<(), NativeLoadError> {
        if tool.risk_tier() != RiskTier::HighRisk {
            return Ok(());
        }
        let actual = native_manifest_hash(tool);
        let entry = lock
            .get(tool.name())
            .ok_or_else(|| NativeLoadError::NotInLock(tool.name().to_string()))?;
        if entry.manifest_hash != actual {
            return Err(NativeLoadError::HashMismatch {
                pinned: entry.manifest_hash.clone(),
                actual,
            });
        }
        Ok(())
    }
}

pub mod plugin_bridge {
    //! Adapts a WASM/native plugin export (the [`ainxt_plugin`] host) into the native [`Tool`] trait
    //! so a plugin-provided capability registers into the SAME [`ToolRuntime`]/[`CapabilityRegistry`]
    //! and dispatches through the identical path (§0/§3): approval, idempotency, locking, and egress
    //! DLP apply to a plugin capability with no plugin-specific work. The plugin sandbox is the
    //! *inner* boundary; this is the outer one — both are enforced.

    use super::{canonical_key, EffectClass, RiskTier, Tool, ToolError, ToolSchema};
    use ainxt_plugin::{PluginGrant, PluginHost, PluginManifest};
    use std::sync::Arc;

    /// One plugin export, adapted to [`Tool`]. The capability name defaults to the plugin id; the
    /// effect class / risk / egress are declared by whoever registers it (the governance-reviewed
    /// grant), defaulting to the conservative SIDE-EFFECTING + approval-gated + egressing posture
    /// for untrusted third-party code.
    pub struct PluginCapability {
        host: Arc<dyn PluginHost + Send + Sync>,
        manifest: PluginManifest,
        grant: PluginGrant,
        name: String,
        effect: EffectClass,
        risk: RiskTier,
        egress: bool,
    }

    impl PluginCapability {
        pub fn new(
            host: Arc<dyn PluginHost + Send + Sync>,
            manifest: PluginManifest,
            grant: PluginGrant,
        ) -> Self {
            let name = manifest.id.clone();
            PluginCapability {
                host,
                manifest,
                grant,
                name,
                effect: EffectClass::SideEffecting,
                risk: RiskTier::High,
                egress: true,
            }
        }
        /// Override the model-facing capability name (defaults to the plugin id).
        pub fn with_name(mut self, name: impl Into<String>) -> Self {
            self.name = name.into();
            self
        }
        pub fn with_effect(mut self, effect: EffectClass) -> Self {
            self.effect = effect;
            self
        }
        pub fn with_risk_tier(mut self, risk: RiskTier) -> Self {
            self.risk = risk;
            self
        }
        pub fn with_egress(mut self, egress: bool) -> Self {
            self.egress = egress;
            self
        }
    }

    impl Tool for PluginCapability {
        fn name(&self) -> &str {
            &self.name
        }
        fn effect_class(&self) -> EffectClass {
            self.effect
        }
        fn risk_tier(&self) -> RiskTier {
            self.risk
        }
        fn idempotency_key(&self, args: &str) -> Option<String> {
            match self.effect {
                EffectClass::SideEffecting => Some(canonical_key(&self.name, args)),
                EffectClass::Pure | EffectClass::Idempotent | EffectClass::PaymentInitiating => {
                    None
                }
            }
        }
        fn schema(&self) -> ToolSchema {
            ToolSchema {
                name: self.name.clone(),
                description: String::new(),
                parameters: super::ParamSpec::Text,
            }
        }
        fn egress(&self) -> bool {
            self.egress
        }
        fn execute(&self, args: &str) -> Result<String, ToolError> {
            // Runs under the plugin's capability sandbox (least-privilege, output-limited, panic-
            // isolated); a sandbox denial/trap surfaces as a tool execution error, never a host crash.
            //
            // GAP-AUDIT plugin-sandbox-registry: this calls `host.invoke()` directly, never through
            // `ainxt_plugin::PluginRegistry`/`CapabilityDispatch` (the §3.2 bounded inter-plugin call
            // switchboard). Investigated and confirmed intentional, not a gap: `self.host` here is
            // always `NativeHost` or `ainxt_wasm::WasmPluginHost`, and neither gives the invoked
            // plugin any way to call back into ANOTHER plugin (see the audit note in
            // `ainxt_plugin::lib` above `CapabilityDispatch`) — there is no inter-plugin call path in
            // the served system today for `PluginRegistry` to bound. It is the right seam to route
            // through if/when one is ever added; wiring it here now would fabricate a call path that
            // does not exist rather than close a real one.
            match self.host.invoke(&self.manifest, &self.grant, args) {
                Ok(out) => Ok(out.output),
                Err(e) => Err(ToolError::Execution(e.to_string())),
            }
        }
    }
}

// ============================ Structural prompt caching (§4.5) ============================

/// Structural, provider-native prompt caching over the STABLE PREFIX of an assembled prompt —
/// persona, behavioral skills, guard prompts, large static context — as distinct from the coarser
/// full-turn semantic answer cache (`ainxt-cache`, gap I): this is the ALWAYS-ON layer under every
/// call, keyed on the prefix content, not the full turn.
///
/// What is real and offline here: the stable-prefix content-hash cache key, the per-session
/// warm/cold/INVALIDATED state machine (scenario 19 — a hot-updated skill must never serve against a
/// stale cached prefix), the cost/latency ranking bonus §4.1 step 4 consumes, and the KV
/// session-affinity hint for self-hosted models (cleared automatically on invalidation, since a
/// changed prefix means the old KV state is stale too). What is infra-gated: the provider-native
/// cache write/hit itself (an actual `cache_control`/prefix-cache API call to a live model endpoint)
/// and the inference-serving layer that actually pins a session to a GPU node by the affinity hint —
/// both need a live provider/serving deployment; this module is the deterministic decision layer they
/// sit behind, fully exercised without either.
pub mod prompt_cache {
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;

    /// Content hash of a stable prefix. Content-sensitive: ANY change to the assembled prefix — a
    /// skill hot-update, a prompt-engineering edit, a persona swap — changes the hash and therefore
    /// correctly invalidates the cache; an unrelated reordering upstream of assembly is not this
    /// module's concern (the Context Engine's deliberate stable-prefix-first ordering is what makes
    /// this hash meaningful in the first place).
    fn prefix_hash(stable_prefix: &str) -> String {
        let mut h = Sha256::new();
        h.update(stable_prefix.as_bytes());
        h.finalize().iter().map(|b| format!("{b:02x}")).collect::<String>()
    }

    /// One session's cache state.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct SessionState {
        prefix_hash: String,
        /// The self-hosted KV session-affinity pin, if one has been set while warm.
        affinity: Option<String>,
        /// Consecutive turns served against the SAME prefix hash — an observable "how warm" signal.
        warm_streak: u32,
    }

    /// What happened to a session's cache when its stable prefix was presented this turn.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum CacheOutcome {
        /// First turn for this session — nothing to compare against; cold by construction.
        FirstUse,
        /// The prefix hash matches the session's last-known state — the provider-native cache for
        /// this session is expected to be warm. Carries the consecutive-warm-turn streak.
        Warm { warm_streak: u32 },
        /// The prefix hash CHANGED since the last turn (e.g. a skill was hot-updated mid-session,
        /// scenario 19) — the cache is explicitly invalidated, and any KV session-affinity pin is
        /// cleared with it. The caller must never serve the next model call against the stale prefix.
        Invalidated,
    }

    /// The stable-prefix cache + invalidation state machine (§4.5, scenario 19). One instance is
    /// shared across a session's turns.
    #[derive(Default)]
    pub struct PromptCache {
        sessions: BTreeMap<String, SessionState>,
    }

    impl PromptCache {
        pub fn new() -> Self {
            Self::default()
        }

        /// Present this turn's assembled stable prefix for `session_id`. This IS the §4.5 correctness
        /// gate — a caller must never treat a prior turn's cache as valid without going through this
        /// first, because it is the only place a prefix change is detected and invalidated.
        pub fn observe(&mut self, session_id: &str, stable_prefix: &str) -> CacheOutcome {
            let hash = prefix_hash(stable_prefix);
            match self.sessions.get_mut(session_id) {
                None => {
                    self.sessions.insert(
                        session_id.to_string(),
                        SessionState {
                            prefix_hash: hash,
                            affinity: None,
                            warm_streak: 1,
                        },
                    );
                    CacheOutcome::FirstUse
                }
                Some(state) if state.prefix_hash == hash => {
                    state.warm_streak += 1;
                    CacheOutcome::Warm {
                        warm_streak: state.warm_streak,
                    }
                }
                Some(state) => {
                    // Invalidate: adopt the new prefix, reset warmth, and clear the KV affinity pin —
                    // a changed prefix means the self-hosted model's KV state for the OLD prefix is
                    // stale too, so the hint must never be blindly carried forward.
                    state.prefix_hash = hash;
                    state.warm_streak = 1;
                    state.affinity = None;
                    CacheOutcome::Invalidated
                }
            }
        }

        /// Whether `session_id`'s cache is currently warm for `stable_prefix`, WITHOUT mutating state
        /// — a read-only check the router's ranking step (§4.1 step 4) can use ahead of `observe`.
        pub fn is_warm(&self, session_id: &str, stable_prefix: &str) -> bool {
            let hash = prefix_hash(stable_prefix);
            self.sessions
                .get(session_id)
                .is_some_and(|s| s.prefix_hash == hash && s.warm_streak >= 2)
        }

        /// Set the self-hosted KV session-affinity pin for `session_id` (§4.5's "session-pinned
        /// KV-cache reuse across turns, coordinated by a router-emitted session-affinity hint"). Only
        /// takes effect while the session is warm for `stable_prefix` — pinning affinity against an
        /// already-stale prefix would just resurrect the exact bug `observe`'s invalidation exists to
        /// prevent. Returns whether the pin was actually set.
        pub fn set_affinity(
            &mut self,
            session_id: &str,
            stable_prefix: &str,
            node: impl Into<String>,
        ) -> bool {
            let hash = prefix_hash(stable_prefix);
            match self.sessions.get_mut(session_id) {
                Some(state) if state.prefix_hash == hash && state.warm_streak >= 2 => {
                    state.affinity = Some(node.into());
                    true
                }
                _ => false,
            }
        }

        /// The current KV session-affinity hint for `session_id`, if a live pin exists.
        pub fn affinity_hint(&self, session_id: &str) -> Option<&str> {
            self.sessions
                .get(session_id)
                .and_then(|s| s.affinity.as_deref())
        }

        /// §4.1 step-4 ranking input: a cost/latency preference bonus for a candidate that is
        /// cache-warm for this session versus the same candidate cold — the concrete form of "the
        /// router prefers cache-warm candidates among otherwise-tied options" (§4.5). `0.0` when cold,
        /// so it is a pure additive nudge that never overrides a genuinely better-ranked candidate.
        pub fn warm_preference_bonus(&self, session_id: &str, stable_prefix: &str) -> f64 {
            if self.is_warm(session_id, stable_prefix) {
                0.15
            } else {
                0.0
            }
        }
    }
}

// ============================ Per-capability / per-data-class egress allow-list (§1.7) ============================

/// Per-capability / per-data-class egress allow-list (§1.7): "An explicit egress allow-list per
/// capability and per data-class governs destinations (e.g. `connector.email` defaults to internal
/// domains; anything else soft-blocks pending approval) — unknown destinations never get a silent
/// send." This complements the Compliance-Gate egress DLP (which inspects *payload content*): this
/// module decides *destination + data-class* eligibility before the payload is even assembled, and
/// deny-by-omission is the default — a capability with no allow-list entry has EVERY destination
/// soft-blocked, never silently permitted.
pub mod egress_allowlist {
    use ainxt_types::DataClass;
    use std::collections::BTreeMap;

    /// The decision for one attempted egress call. Never a silent send: an unmatched destination is
    /// always `PendingApproval`, an explicit, auditable state a human can clear — never a hard fail
    /// that blocks the user, and never a fail-open that waves an unknown destination through.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum EgressDecision {
        /// The destination is allow-listed for this capability (or a platform default) at or below
        /// the entry's data-class ceiling.
        Allowed,
        /// Not allow-listed (unknown destination, or the data-class exceeds every matching entry's
        /// ceiling) — soft-blocked pending human approval.
        PendingApproval {
            capability: String,
            destination: String,
            data_class: DataClass,
        },
    }
    impl EgressDecision {
        pub fn is_allowed(&self) -> bool {
            matches!(self, EgressDecision::Allowed)
        }
    }

    /// One allow-list entry: a destination pattern (exact, or a `prefix*` glob — the same pattern
    /// discipline as [`obo::Grant`]) permitted up to a data-class ceiling.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct AllowEntry {
        destination_pattern: String,
        max_class: DataClass,
    }
    impl AllowEntry {
        fn matches(&self, destination: &str, class: DataClass) -> bool {
            if class > self.max_class {
                return false;
            }
            if let Some(suffix) = self.destination_pattern.strip_prefix('*') {
                return destination.ends_with(suffix);
            }
            match self.destination_pattern.strip_suffix('*') {
                Some(prefix) => destination.starts_with(prefix),
                None => self.destination_pattern == destination,
            }
        }
    }

    /// The per-capability + platform-default egress allow-list (§1.7).
    #[derive(Debug, Clone, Default)]
    pub struct EgressAllowList {
        by_capability: BTreeMap<String, Vec<AllowEntry>>,
        /// Capability-agnostic defaults (e.g. "any capability may reach internal domains at
        /// Confidential or below") — the design's "`connector.email` defaults to internal domains"
        /// example, generalized to apply per-capability OR platform-wide.
        defaults: Vec<AllowEntry>,
    }

    impl EgressAllowList {
        pub fn new() -> Self {
            Self::default()
        }

        /// Allow `destination_pattern` for `capability`, up to `max_class`. A call classified ABOVE
        /// `max_class` still soft-blocks even to an otherwise-matching destination.
        pub fn allow(
            mut self,
            capability: &str,
            destination_pattern: &str,
            max_class: DataClass,
        ) -> Self {
            self.by_capability
                .entry(capability.to_string())
                .or_default()
                .push(AllowEntry {
                    destination_pattern: destination_pattern.to_string(),
                    max_class,
                });
            self
        }

        /// Allow `destination_pattern` for EVERY capability, up to `max_class` (a platform-wide
        /// default rather than a per-capability grant).
        pub fn allow_default(mut self, destination_pattern: &str, max_class: DataClass) -> Self {
            self.defaults.push(AllowEntry {
                destination_pattern: destination_pattern.to_string(),
                max_class,
            });
            self
        }

        /// Decide one egress attempt: `capability` is about to send data classified `class` to
        /// `destination`. `Allowed` iff a per-capability OR default entry matches both the
        /// destination pattern and the class ceiling; otherwise `PendingApproval` — deny-by-omission,
        /// never a silent send to an unknown destination.
        pub fn check(
            &self,
            capability: &str,
            destination: &str,
            class: DataClass,
        ) -> EgressDecision {
            let matched = self
                .by_capability
                .get(capability)
                .into_iter()
                .flatten()
                .chain(self.defaults.iter())
                .any(|e| e.matches(destination, class));
            if matched {
                EgressDecision::Allowed
            } else {
                EgressDecision::PendingApproval {
                    capability: capability.to_string(),
                    destination: destination.to_string(),
                    data_class: class,
                }
            }
        }
    }
}
