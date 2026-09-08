// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Numeric-claim contract + server-side re-derivation gate.
//!
//! Design: `docs/architecture/STRUCTURED_FEDERATED_RETRIEVAL.md` §5 ("Answer re-derivation &
//! verification — never trust model arithmetic"), gap **BH**. This is the payments-critical
//! half of synthesis: retrieval says *which chunks*, [`crate`]'s top level says *was material
//! used faithfully*, and this module answers the sharpest question of all —
//! **is a stated number the one the deterministic path actually computed?**
//!
//! A confidently-wrong sum on ledger/settlement data is a payment incident, not a bad answer,
//! so the design makes this a **hard gate**, not a best practice. Two mechanisms:
//!
//! 1. **Numeric-claim contract (§5.1).** Any number an answer states that is derived from
//!    structured retrieval MUST be emitted as a typed [`NumericClaim`] carrying a
//!    [`ClaimSource`] (a `metric` id + `query_hash`, or a deterministic-tool `call_id`).
//!    [`lint_numeric_claims`] flags two violations: a declared claim with no source
//!    ([`NumericLintFinding::UnsourcedClaim`]), and a number appearing in the prose answer that
//!    is not backed by any sourced claim ([`NumericLintFinding::UnbackedProseNumber`]) — the
//!    exact analogue of a citation-less factual claim, blocked before it ships.
//! 2. **Server-side re-derivation (§5.2).** For every sourced claim, the runtime *independently
//!    re-executes* the same `query_hash`'s compiled query (or re-runs the recorded tool) and
//!    **diffs** the re-derived value against what the model stated. Match → ship, with the
//!    re-derivation hash attached to lineage. Mismatch (or a value the deterministic path
//!    refuses to reproduce) → **BLOCK**, emit an incident-adjacent signal, regenerate. Counts
//!    and exact aggregates use `epsilon = 0`; currency/rate fields use a configured tolerance.
//!
//! The actual query execution / tool invocation is a **trait seam** ([`Rederiver`]) — a real
//! deployment plugs in a read-replica SQL executor (`STRUCTURED_FEDERATED_RETRIEVAL.md` §3–§4)
//! or the sandbox `code.exec` capability. Everything in this module is pure, deterministic, and
//! offline: the contract, the prose-number extraction, the diff-or-block decision, and the
//! fail-closed semantics are all real logic with real tests; only the live re-execution is
//! deferred to the seam, exactly as the design places it.

use serde::{Deserialize, Serialize};

use crate::{parse_number, split_sentences};

/// Floating-point tolerance below which two values are considered identical when a claim's
/// tolerance is nominally zero (guards against representation noise in exact aggregates).
const EXACT_EPSILON: f64 = 1e-9;

/// The provenance of a stated number. A number with no source (free-text arithmetic the model
/// did itself) is a contract violation — modelled as [`ClaimSource::Unsourced`] so it is a
/// representable, lintable state rather than an absent field that silently passes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum ClaimSource {
    /// A value read from a governed catalog metric, identified by metric id + the hash of the
    /// exact compiled query that produced it (`STRUCTURED_FEDERATED_RETRIEVAL.md` §5.1).
    Metric { id: String, query_hash: String },
    /// A value produced by a deterministic compute tool (sandbox `code.exec` / decimal-safe
    /// evaluator), identified by the recorded tool-call id (§5.2).
    Tool { call_id: String },
    /// The model stated a number with no provenance — a contract violation.
    Unsourced,
}

impl ClaimSource {
    /// A stable key for this source, used to ask the [`Rederiver`] to reproduce it and to
    /// record the re-derivation in lineage. `Unsourced` has no re-derivable key.
    pub fn rederive_key(&self) -> Option<String> {
        match self {
            ClaimSource::Metric { id, query_hash } => Some(format!("metric:{id}:{query_hash}")),
            ClaimSource::Tool { call_id } => Some(format!("tool:{call_id}")),
            ClaimSource::Unsourced => None,
        }
    }

    fn is_sourced(&self) -> bool {
        !matches!(self, ClaimSource::Unsourced)
    }
}

/// The precision regime a claim's value must be re-derived under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ValueClass {
    /// Counts / exact aggregates — must match to the bit (`epsilon = 0`).
    Exact,
    /// Currency amounts — matched within a configured rounding tolerance.
    Currency,
    /// Rates / percentages — matched within a configured rounding tolerance.
    Rate,
}

/// One number the model's answer states, in the typed contract form (§5.1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NumericClaim {
    /// The value the model stated.
    pub value: f64,
    /// A unit label for display / lineage (e.g. `"count"`, `"INR"`, `"%"`).
    pub unit: String,
    /// Precision regime for the diff.
    pub value_class: ValueClass,
    /// Where the number came from.
    pub source: ClaimSource,
}

impl NumericClaim {
    /// A properly-sourced metric claim.
    pub fn metric(
        value: f64,
        unit: &str,
        value_class: ValueClass,
        id: &str,
        query_hash: &str,
    ) -> Self {
        NumericClaim {
            value,
            unit: unit.to_string(),
            value_class,
            source: ClaimSource::Metric {
                id: id.to_string(),
                query_hash: query_hash.to_string(),
            },
        }
    }

    /// A properly-sourced deterministic-tool claim.
    pub fn tool(value: f64, unit: &str, value_class: ValueClass, call_id: &str) -> Self {
        NumericClaim {
            value,
            unit: unit.to_string(),
            value_class,
            source: ClaimSource::Tool {
                call_id: call_id.to_string(),
            },
        }
    }
}

/// Diff tolerances per [`ValueClass`]. `Exact` is always compared at [`EXACT_EPSILON`]; the
/// currency/rate absolute tolerances are configurable per deployment (a judgment call, §5.2).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Tolerance {
    pub currency_abs: f64,
    pub rate_abs: f64,
}

impl Default for Tolerance {
    fn default() -> Self {
        // Sensible payments defaults: currency to the paisa, rate to a basis-point.
        Tolerance {
            currency_abs: 0.01,
            rate_abs: 0.0001,
        }
    }
}

impl Tolerance {
    fn epsilon_for(&self, class: ValueClass) -> f64 {
        match class {
            ValueClass::Exact => EXACT_EPSILON,
            ValueClass::Currency => self.currency_abs.max(EXACT_EPSILON),
            ValueClass::Rate => self.rate_abs.max(EXACT_EPSILON),
        }
    }
}

// ---------------------------------------------------------------------------------------
// Numeric-claim lint (§5.1)
// ---------------------------------------------------------------------------------------

/// A number found in the prose answer, with the value and the sentence it appeared in.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProseNumber {
    pub value: f64,
    pub sentence: String,
}

/// A numeric-claim contract violation (§5.1) — each blocks the answer from shipping.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NumericLintFinding {
    /// A declared [`NumericClaim`] carries [`ClaimSource::Unsourced`] — the model stated a number
    /// it did not attribute to a metric or a deterministic tool.
    UnsourcedClaim { index: usize, value: f64 },
    /// A number in the prose answer is not backed by any *sourced* claim — free-text arithmetic
    /// the model appears to have done itself.
    UnbackedProseNumber { value: f64, sentence: String },
}

/// Report of the numeric-claim lint over a candidate answer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NumericLintReport {
    pub findings: Vec<NumericLintFinding>,
}

impl NumericLintReport {
    /// True iff the answer is clean and may ship (subject still to re-derivation, §5.2).
    pub fn passed(&self) -> bool {
        self.findings.is_empty()
    }
}

/// Extract candidate numbers from the prose answer, one entry per number occurrence, tagged
/// with its sentence. Reuses the crate's hand-written [`parse_number`] (no regex/NLP dep) after
/// trimming surrounding punctuation, so an ISO date (`2024-01-15`) or a plain word never parses
/// as a number, but `47`, `1,000`, `10.50`, and `5%` do.
pub fn extract_prose_numbers(answer: &str) -> Vec<ProseNumber> {
    let mut out = Vec::new();
    for sentence in split_sentences(answer) {
        for raw in sentence.split_whitespace() {
            // Trim leading/trailing chars that are neither digits nor number-internal
            // ('.', ',', '%', currency/sign), so sentence punctuation does not defeat parsing.
            let trimmed = raw.trim_matches(|c: char| {
                !c.is_ascii_digit() && !matches!(c, '.' | ',' | '%' | '-' | '$' | '₹')
            });
            if let Some(v) = parse_number(trimmed) {
                out.push(ProseNumber {
                    value: v,
                    sentence: sentence.clone(),
                });
            }
        }
    }
    out
}

/// Lint a candidate answer against its declared numeric claims (§5.1).
///
/// A prose number is "backed" iff some *sourced* claim states the same value within the
/// [`ValueClass::Exact`] epsilon (the answer's prose and its structured claims must agree on
/// the literal figure). An `Unsourced` claim never backs a prose number — it is itself a
/// finding. This is deliberately conservative: for payments data, an unaccounted number in
/// prose is flagged rather than assumed benign.
pub fn lint_numeric_claims(answer: &str, claims: &[NumericClaim]) -> NumericLintReport {
    let mut findings = Vec::new();

    for (i, c) in claims.iter().enumerate() {
        if !c.source.is_sourced() {
            findings.push(NumericLintFinding::UnsourcedClaim {
                index: i,
                value: c.value,
            });
        }
    }

    let backed: Vec<f64> = claims
        .iter()
        .filter(|c| c.source.is_sourced())
        .map(|c| c.value)
        .collect();

    for pn in extract_prose_numbers(answer) {
        let is_backed = backed.iter().any(|b| (b - pn.value).abs() <= EXACT_EPSILON);
        if !is_backed {
            findings.push(NumericLintFinding::UnbackedProseNumber {
                value: pn.value,
                sentence: pn.sentence,
            });
        }
    }

    NumericLintReport { findings }
}

// ---------------------------------------------------------------------------------------
// Server-side re-derivation (§5.2)
// ---------------------------------------------------------------------------------------

/// The re-execution seam. A real deployment implements this with a read-replica SQL executor
/// (re-running the compiled query behind a `query_hash`, `STRUCTURED_FEDERATED_RETRIEVAL.md`
/// §3–§4) and/or the sandbox deterministic-compute capability (re-running a recorded tool call).
///
/// Returning `None` means the deterministic path **could not reproduce** the value (unknown
/// hash, tool call not found, replica error). The gate treats that as fail-closed — a value the
/// server cannot independently reproduce is never shipped as "verified".
pub trait Rederiver {
    /// Re-execute the source behind a claim and return the independently-computed value, or
    /// `None` if it cannot be reproduced.
    fn rederive(&self, source: &ClaimSource) -> Option<f64>;
}

/// Any shared reference to a [`Rederiver`] is itself a [`Rederiver`] — so a `&dyn Rederiver` (the
/// seam a surface passes around) satisfies a generic `R: Rederiver` bound without boxing/cloning.
impl<T: Rederiver + ?Sized> Rederiver for &T {
    fn rederive(&self, source: &ClaimSource) -> Option<f64> {
        (**self).rederive(source)
    }
}

/// Why a single claim failed re-derivation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RederiveFailure {
    /// The claim had no re-derivable source (`Unsourced`).
    Unsourced { index: usize, claimed: f64 },
    /// The deterministic path could not reproduce the value at all (fail-closed).
    NotReproducible { index: usize, claimed: f64 },
    /// The re-derived value differed from the claimed value beyond tolerance — the payment
    /// incident the whole gate exists to catch.
    Mismatch {
        index: usize,
        claimed: f64,
        rederived: f64,
        tolerance: f64,
    },
}

/// A claim that passed re-derivation, with the hash key attached for the lineage record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerifiedClaim {
    pub index: usize,
    pub value: f64,
    /// The `rederive_key` of the source — the re-derivation hash attached to lineage (§5.2).
    pub rederive_key: String,
}

/// The verdict of the re-derivation gate over all of an answer's numeric claims.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RederivationReport {
    pub verified: Vec<VerifiedClaim>,
    pub failures: Vec<RederiveFailure>,
}

impl RederivationReport {
    /// True iff EVERY claim was independently re-derived and matched — the only state in which
    /// the answer may ship. Any failure blocks (§5.2: "mismatch → answer is BLOCKED").
    pub fn passed(&self) -> bool {
        self.failures.is_empty()
    }

    /// True iff at least one failure is a value mismatch (as opposed to unsourced /
    /// not-reproducible) — the incident-adjacent signal fed to the eval platform (§5.2).
    pub fn has_mismatch(&self) -> bool {
        self.failures
            .iter()
            .any(|f| matches!(f, RederiveFailure::Mismatch { .. }))
    }
}

/// Server-side re-derivation gate (§5.2): for every numeric claim, ask the [`Rederiver`] to
/// independently reproduce the value and diff it against what the model stated.
///
/// Fail-closed on every non-match: an `Unsourced` claim, a value the server cannot reproduce,
/// and a value that differs beyond tolerance all become [`RederiveFailure`]s that block the
/// answer. Only a claim that is sourced, reproducible, AND within tolerance is [`VerifiedClaim`].
pub fn rederive_and_verify(
    claims: &[NumericClaim],
    rederiver: &dyn Rederiver,
    tolerance: &Tolerance,
) -> RederivationReport {
    let mut verified = Vec::new();
    let mut failures = Vec::new();

    for (i, c) in claims.iter().enumerate() {
        let key = match c.source.rederive_key() {
            Some(k) => k,
            None => {
                failures.push(RederiveFailure::Unsourced {
                    index: i,
                    claimed: c.value,
                });
                continue;
            }
        };
        match rederiver.rederive(&c.source) {
            None => failures.push(RederiveFailure::NotReproducible {
                index: i,
                claimed: c.value,
            }),
            Some(actual) => {
                let eps = tolerance.epsilon_for(c.value_class);
                if (actual - c.value).abs() <= eps {
                    verified.push(VerifiedClaim {
                        index: i,
                        value: c.value,
                        rederive_key: key,
                    });
                } else {
                    failures.push(RederiveFailure::Mismatch {
                        index: i,
                        claimed: c.value,
                        rederived: actual,
                        tolerance: eps,
                    });
                }
            }
        }
    }

    RederivationReport { verified, failures }
}

/// The combined ship/block decision for an answer's numbers: lint (§5.1) THEN re-derive (§5.2).
/// The answer may ship iff both pass. Lint runs first because a number that isn't even in the
/// contract can't be re-derived.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NumericGateOutcome {
    pub lint: NumericLintReport,
    pub rederivation: RederivationReport,
}

impl NumericGateOutcome {
    /// True iff the answer clears both the contract lint and server-side re-derivation.
    pub fn ships(&self) -> bool {
        self.lint.passed() && self.rederivation.passed()
    }
}

/// Run the full numeric gate: contract lint over the prose + claims, then server-side
/// re-derivation of every claim.
pub fn numeric_gate(
    answer: &str,
    claims: &[NumericClaim],
    rederiver: &dyn Rederiver,
    tolerance: &Tolerance,
) -> NumericGateOutcome {
    NumericGateOutcome {
        lint: lint_numeric_claims(answer, claims),
        rederivation: rederive_and_verify(claims, rederiver, tolerance),
    }
}

// ---------------------------------------------------------------------------------------
// Numeric-claim SYNTHESIS (generation) — the counterpart to the verify-only gate above.
// ---------------------------------------------------------------------------------------
//
// Everything above this point (the contract lint, `rederive_and_verify`, `numeric_gate`) only
// VERIFIES a number the model has already written into its prose answer: it takes `answer: &str`
// and/or a `NumericClaim.value` the model asserted, and diffs it against the `Rederiver`'s
// independently-computed truth. There is no path above that hands back a number a turn could use
// as the answer — only a ship/block verdict on one the model already produced.
//
// `synthesize_numeric_claim` closes that gap: given a `ClaimSource` (a metric/tool the turn wants
// to answer with) and the SAME `Rederiver` seam, it asks for the ground-truth value UP FRONT and
// returns it as a `NumericClaim` — the model never does the arithmetic, so a served turn can splice
// the rendered value straight into its prose. The synthesized claim is still a first-class
// `NumericClaim`, so it composes with everything above (e.g. `numeric_gate`) for defense-in-depth
// if the model also restates the figure in its own words.

/// Errors from GENERATING a numeric answer directly from structured/tool data, as opposed to
/// [`numeric_gate`]/[`rederive_and_verify`], which only VERIFY a number the model already stated in
/// prose. A served turn that needs to answer with a number computed from a metric/tool source calls
/// [`synthesize_numeric_claim`] to get the ground-truth value itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NumericSynthesisError {
    /// The [`Rederiver`] has no ground-truth value for this source (unknown metric/query_hash, or
    /// the tool call hasn't run this turn) — fail-closed, exactly like
    /// [`RederiveFailure::NotReproducible`]: a served turn must never fabricate a number it cannot
    /// independently compute.
    SourceUnavailable(ClaimSource),
}

/// Computes ONE [`NumericClaim`] directly from structured/tool data via the [`Rederiver`] seam — the
/// GENERATION counterpart to this module's verify-only functions. A served turn that needs to answer
/// a numeric question calls this BEFORE producing prose: the returned claim's `value` is the number
/// to splice into the answer (via [`render_numeric_claim`]), and the claim is already in the typed
/// contract form so it can still be run back through [`numeric_gate`]/[`lint_numeric_claims`] for
/// defense-in-depth if the model also restates the figure in its own words.
///
/// Fail-closed: if the source cannot be reproduced, this returns an error rather than a value — a
/// served turn must fall back to a qualitative answer, never guess a number it could not compute.
pub fn synthesize_numeric_claim(
    unit: &str,
    value_class: ValueClass,
    source: ClaimSource,
    rederiver: &dyn Rederiver,
) -> Result<NumericClaim, NumericSynthesisError> {
    match rederiver.rederive(&source) {
        Some(value) => Ok(NumericClaim {
            value,
            unit: unit.to_string(),
            value_class,
            source,
        }),
        None => Err(NumericSynthesisError::SourceUnavailable(source)),
    }
}

/// Batch form of [`synthesize_numeric_claim`]: computes every requested `(unit, value_class,
/// source)` triple, short-circuiting on the first source the [`Rederiver`] cannot reproduce, so a
/// turn never ships an answer built from a partially-computed set of figures.
pub fn synthesize_numeric_claims(
    requests: Vec<(String, ValueClass, ClaimSource)>,
    rederiver: &dyn Rederiver,
) -> Result<Vec<NumericClaim>, NumericSynthesisError> {
    requests
        .into_iter()
        .map(|(unit, value_class, source)| {
            synthesize_numeric_claim(&unit, value_class, source, rederiver)
        })
        .collect()
}

/// Renders a [`NumericClaim`] (typically a synthesized one) into answer-ready text per its
/// [`ValueClass`], so a served turn can splice a COMPUTED number straight into prose without ad hoc
/// formatting at the call site. `Currency` renders 2dp with the claim's unit as a prefix (e.g.
/// `unit="₹"` → `"₹1234.50"`); `Rate` renders 2dp with a trailing `%`; `Exact` renders the bare value
/// (trailing `.0` trimmed) with the unit suffixed when non-empty (e.g. `"47 count"`).
pub fn render_numeric_claim(claim: &NumericClaim) -> String {
    match claim.value_class {
        ValueClass::Currency => format!("{}{:.2}", claim.unit, claim.value),
        ValueClass::Rate => format!("{:.2}%", claim.value),
        ValueClass::Exact => {
            let v = trim_trailing_zero(claim.value);
            if claim.unit.is_empty() {
                v
            } else {
                format!("{v} {}", claim.unit)
            }
        }
    }
}

fn trim_trailing_zero(value: f64) -> String {
    if value.fract() == 0.0 {
        format!("{value:.0}")
    } else {
        format!("{value}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// A stub re-executor: keyed by `rederive_key`, returns the recorded server-truth value, or
    /// `None` for an unknown key (models "cannot reproduce").
    struct MapRederiver {
        truth: HashMap<String, f64>,
    }

    impl MapRederiver {
        fn new(pairs: &[(&str, f64)]) -> Self {
            MapRederiver {
                truth: pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect(),
            }
        }
    }

    impl Rederiver for MapRederiver {
        fn rederive(&self, source: &ClaimSource) -> Option<f64> {
            self.truth.get(&source.rederive_key()?).copied()
        }
    }

    // --- prose extraction ----------------------------------------------------------

    #[test]
    fn extract_prose_numbers_finds_figures_not_dates_or_words() {
        let nums = extract_prose_numbers(
            "There were 47 failed settlements on 2024-01-15, a rate of 3.5% over 1,000 attempts.",
        );
        let vals: Vec<f64> = nums.iter().map(|n| n.value).collect();
        assert!(vals.contains(&47.0), "count parsed");
        assert!(vals.contains(&3.5), "percentage parsed");
        assert!(vals.contains(&1000.0), "thousands-separated parsed");
        assert!(
            !vals.iter().any(|v| (*v - 2024.0).abs() < 1e-9),
            "an ISO date must not parse as a number"
        );
    }

    // --- contract lint (§5.1) ------------------------------------------------------

    #[test]
    fn lint_flags_unbacked_prose_number() {
        // The model states a percentage in prose it never put under the contract → blocked.
        let answer = "The failure rate was 12%.";
        let report = lint_numeric_claims(answer, &[]);
        assert!(!report.passed());
        assert!(report.findings.iter().any(|f| matches!(
            f,
            NumericLintFinding::UnbackedProseNumber { value, .. } if (*value - 12.0).abs() < 1e-9
        )));
    }

    #[test]
    fn lint_flags_unsourced_claim() {
        let claims = vec![NumericClaim {
            value: 47.0,
            unit: "count".into(),
            value_class: ValueClass::Exact,
            source: ClaimSource::Unsourced,
        }];
        // Prose repeats the same figure; it is NOT backed because the only claim is unsourced.
        let report = lint_numeric_claims("There were 47 failures.", &claims);
        assert!(report
            .findings
            .iter()
            .any(|f| matches!(f, NumericLintFinding::UnsourcedClaim { value, .. } if (*value - 47.0).abs() < 1e-9)));
        assert!(report
            .findings
            .iter()
            .any(|f| matches!(f, NumericLintFinding::UnbackedProseNumber { .. })));
    }

    #[test]
    fn lint_passes_when_prose_number_is_backed_by_sourced_claim() {
        let claims = vec![NumericClaim::metric(
            47.0,
            "count",
            ValueClass::Exact,
            "failed_settlement_count",
            "abc123",
        )];
        let report = lint_numeric_claims("There were 47 failed settlements.", &claims);
        assert!(
            report.passed(),
            "a sourced, matching claim backs the prose number"
        );
    }

    // --- re-derivation (§5.2) ------------------------------------------------------

    #[test]
    fn rederive_verifies_matching_value() {
        let claims = vec![NumericClaim::metric(
            47.0,
            "count",
            ValueClass::Exact,
            "failed_settlement_count",
            "h1",
        )];
        let rd = MapRederiver::new(&[("metric:failed_settlement_count:h1", 47.0)]);
        let report = rederive_and_verify(&claims, &rd, &Tolerance::default());
        assert!(report.passed());
        assert_eq!(report.verified.len(), 1);
        assert_eq!(
            report.verified[0].rederive_key,
            "metric:failed_settlement_count:h1"
        );
    }

    #[test]
    fn rederive_blocks_on_mismatch_and_flags_incident() {
        // The model claimed 47; the server recomputes 52 → BLOCK, and it is a mismatch signal.
        let claims = vec![NumericClaim::metric(
            47.0,
            "count",
            ValueClass::Exact,
            "failed_settlement_count",
            "h1",
        )];
        let rd = MapRederiver::new(&[("metric:failed_settlement_count:h1", 52.0)]);
        let report = rederive_and_verify(&claims, &rd, &Tolerance::default());
        assert!(!report.passed(), "a mismatch must block the answer");
        assert!(report.has_mismatch());
        assert!(matches!(
            report.failures[0],
            RederiveFailure::Mismatch { claimed, rederived, .. }
                if (claimed - 47.0).abs() < 1e-9 && (rederived - 52.0).abs() < 1e-9
        ));
    }

    #[test]
    fn rederive_is_fail_closed_when_not_reproducible() {
        // The server has no record of this query_hash → cannot verify → block (never ship as
        // "verified" a number the deterministic path can't reproduce).
        let claims = vec![NumericClaim::metric(
            47.0,
            "count",
            ValueClass::Exact,
            "failed_settlement_count",
            "unknown_hash",
        )];
        let rd = MapRederiver::new(&[]);
        let report = rederive_and_verify(&claims, &rd, &Tolerance::default());
        assert!(!report.passed());
        assert!(matches!(
            report.failures[0],
            RederiveFailure::NotReproducible { .. }
        ));
        assert!(
            !report.has_mismatch(),
            "not-reproducible is not a value mismatch"
        );
    }

    #[test]
    fn rederive_currency_tolerance_admits_rounding_but_not_drift() {
        // Currency claim of 100.00; server computes 100.004 → within 0.01 → OK.
        let ok = vec![NumericClaim::metric(
            100.00,
            "INR",
            ValueClass::Currency,
            "recon_break_amount",
            "h",
        )];
        let rd_ok = MapRederiver::new(&[("metric:recon_break_amount:h", 100.004)]);
        assert!(rederive_and_verify(&ok, &rd_ok, &Tolerance::default()).passed());

        // Same claim; server computes 100.5 → beyond 0.01 → BLOCK.
        let rd_bad = MapRederiver::new(&[("metric:recon_break_amount:h", 100.5)]);
        assert!(!rederive_and_verify(&ok, &rd_bad, &Tolerance::default()).passed());
    }

    #[test]
    fn rederive_exact_class_rejects_off_by_one() {
        // Counts must match to the bit — no tolerance saves an off-by-one on a settlement count.
        let claims = vec![NumericClaim::metric(
            47.0,
            "count",
            ValueClass::Exact,
            "m",
            "h",
        )];
        let rd = MapRederiver::new(&[("metric:m:h", 48.0)]);
        assert!(!rederive_and_verify(&claims, &rd, &Tolerance::default()).passed());
    }

    #[test]
    fn rederive_unsourced_claim_cannot_be_verified() {
        let claims = vec![NumericClaim {
            value: 47.0,
            unit: "count".into(),
            value_class: ValueClass::Exact,
            source: ClaimSource::Unsourced,
        }];
        let rd = MapRederiver::new(&[]);
        let report = rederive_and_verify(&claims, &rd, &Tolerance::default());
        assert!(matches!(
            report.failures[0],
            RederiveFailure::Unsourced { .. }
        ));
    }

    #[test]
    fn tool_sourced_claim_is_rederived_via_key() {
        let claims = vec![NumericClaim::tool(
            0.125,
            "ratio",
            ValueClass::Rate,
            "call_9",
        )];
        let rd = MapRederiver::new(&[("tool:call_9", 0.125)]);
        assert!(rederive_and_verify(&claims, &rd, &Tolerance::default()).passed());
    }

    // --- combined gate -------------------------------------------------------------

    #[test]
    fn numeric_gate_ships_only_when_lint_and_rederivation_both_pass() {
        let answer = "There were 47 failed settlements.";
        let claims = vec![NumericClaim::metric(
            47.0,
            "count",
            ValueClass::Exact,
            "failed_settlement_count",
            "h1",
        )];
        let good = MapRederiver::new(&[("metric:failed_settlement_count:h1", 47.0)]);
        assert!(numeric_gate(answer, &claims, &good, &Tolerance::default()).ships());

        // A stray computed number in prose (the 75% ratio the model did itself) blocks even
        // though the metric claim re-derives fine.
        let answer2 = "There were 47 failed settlements, about 75% of the batch.";
        let outcome = numeric_gate(answer2, &claims, &good, &Tolerance::default());
        assert!(!outcome.ships(), "an unbacked computed ratio must block");
        assert!(!outcome.lint.passed());
        assert!(
            outcome.rederivation.passed(),
            "the metric claim still re-derives"
        );
    }

    #[test]
    fn gate_report_serializes_with_values() {
        let claims = vec![NumericClaim::metric(
            5.0,
            "count",
            ValueClass::Exact,
            "m",
            "h",
        )];
        let rd = MapRederiver::new(&[("metric:m:h", 9.0)]);
        let outcome = numeric_gate("The count is 5.", &claims, &rd, &Tolerance::default());
        let json = serde_json::to_string(&outcome).expect("serialize");
        assert!(json.contains("\"rederived\":9"));
        let back: NumericGateOutcome = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, outcome);
        assert!(!back.ships());
    }
}
