// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Numeric-via-tools **enforcement** (BH, `PROMPT_ENGINEERING.md`; audit: "instructs but does not
//! enforce"). Under [`crate::NumericPolicy::ToolsOnly`], a directive alone is not enough for a
//! payments platform — a wrong figure moves money. This module turns the directive into an
//! enforced post-condition: after the model answers, every *amount-like* number in the output must be
//! attributable to a tool result; any number the model produced from its own head is flagged.
//!
//! Deterministic; no clock/rng. The set of tool-produced numbers is passed in (the tool-loop knows
//! exactly which numbers came back from calculators/queries).

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// A single number the model emitted that is NOT attributable to a tool result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsourcedNumber {
    /// The number as it appeared in the output (original spelling).
    pub literal: String,
    /// The normalized numeric form used for the tool-set comparison.
    pub normalized: String,
}

/// The enforcement verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NumericFinding {
    /// True if any amount-like number in the output is unsourced (a policy violation).
    pub violated: bool,
    pub unsourced: Vec<UnsourcedNumber>,
}

impl NumericFinding {
    fn ok() -> Self {
        NumericFinding {
            violated: false,
            unsourced: Vec::new(),
        }
    }
}

/// Configuration for what counts as an "amount-like" number worth enforcing on. Small bare integers
/// (list ordinals, "3 bullets", years) are ignored to avoid false positives; anything with a decimal,
/// a thousands separator, a currency marker, or `min_bare_digits`+ digits is enforced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NumericPolicyConfig {
    /// A bare integer with at least this many digits is treated as amount-like. Default 4
    /// (so "2024" or a 4-digit code is caught, but "3 steps" is not).
    pub min_bare_digits: usize,
}

impl Default for NumericPolicyConfig {
    fn default() -> Self {
        NumericPolicyConfig { min_bare_digits: 4 }
    }
}

/// Enforce ToolsOnly on `output`: flag every amount-like number not present in `tool_numbers`.
///
/// `tool_numbers` are the numbers returned by tools this turn (any spelling — they are normalized the
/// same way). A number is sourced iff its normalized form is in that set.
pub fn enforce(output: &str, tool_numbers: &[&str], cfg: NumericPolicyConfig) -> NumericFinding {
    let sourced: BTreeSet<String> = tool_numbers.iter().filter_map(|s| normalize(s)).collect();

    let mut unsourced = Vec::new();
    let mut seen = BTreeSet::new();
    for (literal, currency_marked) in number_tokens(output) {
        let Some(norm) = normalize(&literal) else {
            continue;
        };
        if !is_amount_like(&literal, currency_marked, cfg) {
            continue;
        }
        if sourced.contains(&norm) {
            continue;
        }
        if seen.insert(norm.clone()) {
            unsourced.push(UnsourcedNumber {
                literal,
                normalized: norm,
            });
        }
    }
    if unsourced.is_empty() {
        NumericFinding::ok()
    } else {
        NumericFinding {
            violated: true,
            unsourced,
        }
    }
}

/// Normalize a numeric literal to a canonical form: strip currency/grouping, keep sign + digits +
/// one decimal point, drop trailing-zero noise. Returns `None` if there is no digit.
fn normalize(s: &str) -> Option<String> {
    let mut sign = "";
    let mut digits = String::new();
    let mut dot = false;
    for c in s.chars() {
        match c {
            '-' if digits.is_empty() && sign.is_empty() => sign = "-",
            '0'..='9' => digits.push(c),
            '.' if !dot => {
                dot = true;
                digits.push('.');
            }
            ',' | '_' | ' ' | '₹' | '$' | '€' | '£' => {}
            _ => {}
        }
    }
    if !digits.chars().any(|c| c.is_ascii_digit()) {
        return None;
    }
    // Canonicalize numeric value so "1000.0" == "1000" and "1,000" == "1000".
    let normalized = if dot {
        let parsed: f64 = digits.parse().ok()?;
        // Deterministic canonical form; trim trailing zeros.
        let mut out = format!("{parsed}");
        if out.contains('.') {
            while out.ends_with('0') {
                out.pop();
            }
            if out.ends_with('.') {
                out.pop();
            }
        }
        out
    } else {
        // Strip leading zeros but keep at least one digit.
        let trimmed = digits.trim_start_matches('0');
        if trimmed.is_empty() {
            "0".to_string()
        } else {
            trimmed.to_string()
        }
    };
    Some(format!("{sign}{normalized}"))
}

/// Decide if a literal is "amount-like" (worth enforcing): currency-marked, has a decimal, has a
/// grouping separator, or has ≥ `min_bare_digits` digits.
fn is_amount_like(literal: &str, currency_marked: bool, cfg: NumericPolicyConfig) -> bool {
    if currency_marked {
        return true;
    }
    if literal.contains('.') || literal.contains(',') {
        return true;
    }
    let digit_count = literal.chars().filter(|c| c.is_ascii_digit()).count();
    digit_count >= cfg.min_bare_digits
}

/// GAP-AUDIT prompt #1 — extract every number-like literal from a TOOL RESULT's raw text, for the
/// caller to pass as [`enforce`]'s `tool_numbers`. This is the missing half of `ToolsOnly`
/// enforcement on the served path: `enforce()` was always called with `tool_numbers = &[]`
/// (hardcoded), so a genuinely tool-sourced figure could never be recognized as sourced and every
/// amount-like number in a payments-surface answer was unconditionally flagged. `enforce()`
/// normalizes each provided number independently, so the caller must first split a tool's raw
/// output text into its individual number tokens (never pass the whole raw text as one
/// `tool_numbers` entry — `normalize()` would concatenate every digit in the string into one
/// garbled value).
pub fn tool_output_numbers(text: &str) -> Vec<String> {
    number_tokens(text)
        .into_iter()
        .map(|(literal, _)| literal)
        .collect()
}

/// Extract number tokens from text along with whether a currency marker was adjacent. Yields
/// `(literal, currency_marked)`. A token is a maximal run of `[0-9.,_]` optionally preceded by a
/// sign; currency markers (`₹ $ € £`, or `Rs`/`INR` immediately before) set the flag.
fn number_tokens(text: &str) -> Vec<(String, bool)> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_ascii_digit() {
            // Walk back over a sign.
            let start = i;
            let mut lit = String::new();
            // include a leading '-' if directly attached
            if start > 0 && chars[start - 1] == '-' {
                lit.push('-');
            }
            let mut j = i;
            while j < chars.len()
                && (chars[j].is_ascii_digit() || matches!(chars[j], '.' | ',' | '_'))
            {
                lit.push(chars[j]);
                j += 1;
            }
            // Trim a trailing '.' or ',' (sentence punctuation, not part of the number).
            while lit.ends_with('.') || lit.ends_with(',') {
                lit.pop();
            }
            let currency = currency_before(&chars, start);
            out.push((lit, currency));
            i = j;
        } else {
            i += 1;
        }
    }
    out
}

/// Is there a currency marker immediately before position `start` (skipping one optional space/sign)?
fn currency_before(chars: &[char], start: usize) -> bool {
    let mut k = start;
    // skip an attached sign
    if k > 0 && chars[k - 1] == '-' {
        k -= 1;
    }
    // skip one space
    if k > 0 && chars[k - 1] == ' ' {
        k -= 1;
    }
    if k == 0 {
        return false;
    }
    let prev = chars[k - 1];
    if matches!(prev, '₹' | '$' | '€' | '£') {
        return true;
    }
    // "Rs" / "INR" word immediately before
    let upto: String = chars[..k].iter().collect();
    let tail = upto.trim_end().to_lowercase();
    tail.ends_with("rs") || tail.ends_with("inr")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_invented_amount_is_flagged() {
        // The model states a settlement figure with no tool behind it.
        let out = "The total settlement is ₹12,45,600 across all banks.";
        let finding = enforce(out, &[], NumericPolicyConfig::default());
        assert!(finding.violated);
        assert_eq!(finding.unsourced.len(), 1);
        assert_eq!(finding.unsourced[0].normalized, "1245600");
    }

    #[test]
    fn tool_sourced_amount_passes() {
        // Same figure, but a tool returned it → sourced → OK.
        let out = "The total settlement is ₹12,45,600 across all banks.";
        let finding = enforce(out, &["1245600"], NumericPolicyConfig::default());
        assert!(
            !finding.violated,
            "a tool-sourced number must not be flagged"
        );
    }

    #[test]
    fn different_spellings_normalize_equal() {
        let out = "Balance: 1000.00";
        // Tool returned "1,000" — different spelling, same value.
        let finding = enforce(out, &["1,000"], NumericPolicyConfig::default());
        assert!(!finding.violated);
    }

    #[test]
    fn small_ordinals_are_ignored() {
        // "3 steps", "in 2 bullets" — steerability numbers, not amounts. No false positive.
        let out = "Here are the 3 steps in 2 sections. Point 1 and point 2 follow.";
        let finding = enforce(out, &[], NumericPolicyConfig::default());
        assert!(!finding.violated, "small bare integers must not be flagged");
    }

    #[test]
    fn decimal_and_grouped_are_amount_like_even_if_small() {
        // A decimal amount with few digits is still money.
        let out = "Charge is $3.50 per transaction.";
        let finding = enforce(out, &[], NumericPolicyConfig::default());
        assert!(finding.violated);
        assert_eq!(finding.unsourced[0].normalized, "3.5");
    }

    #[test]
    fn multiple_unsourced_are_all_flagged_once_each() {
        let out = "Fees were ₹1,200 and the balance ₹4,500.99, then again ₹1,200.";
        let finding = enforce(out, &[], NumericPolicyConfig::default());
        assert!(finding.violated);
        // 1200 appears twice but is reported once; plus 4500.99 → 2 distinct.
        assert_eq!(finding.unsourced.len(), 2);
    }

    #[test]
    fn partially_sourced_flags_only_the_invented_one() {
        let out = "Sent ₹1,000 (from ledger) but also invented ₹9,999 in fees.";
        let finding = enforce(out, &["1000"], NumericPolicyConfig::default());
        assert!(finding.violated);
        assert_eq!(finding.unsourced.len(), 1);
        assert_eq!(finding.unsourced[0].normalized, "9999");
    }

    #[test]
    fn no_numbers_is_clean() {
        let finding = enforce(
            "No figures here at all.",
            &[],
            NumericPolicyConfig::default(),
        );
        assert!(!finding.violated);
    }

    #[test]
    fn year_like_bare_four_digits_is_caught_by_default_threshold() {
        // With min_bare_digits=4, a 4-digit bare number is enforced (could be an account/code/amount).
        let finding = enforce("Reference 2024 batch.", &[], NumericPolicyConfig::default());
        assert!(finding.violated);
        // Raising the threshold makes it pass (config-first).
        let relaxed = enforce(
            "Reference 2024 batch.",
            &[],
            NumericPolicyConfig { min_bare_digits: 5 },
        );
        assert!(!relaxed.violated);
    }
}
