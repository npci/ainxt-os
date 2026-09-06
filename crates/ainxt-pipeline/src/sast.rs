// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! The **SAST stage** (`docs/architecture/CODE_REVIEW_PIPELINE.md` §4 stage 5) — the one place the
//! design deliberately overrides "the score decides the commit": a `critical`/`high` finding
//! **hard-blocks** regardless of every other stage's outcome or the Confidence Score.
//!
//! A matched rule is a finding, full stop — the model may propose a fix, it cannot argue a finding
//! away. This is a deterministic scanner (a [`SastScanner`] trait so a real Semgrep/`cargo audit`
//! engine plugs in) plus a [`BuiltinScanner`] that catches the payments-critical classes offline:
//! - **accidental PAN logging** — a 13–19 digit run that passes the Luhn check on a `log`/`print`
//!   line (`critical`), the exact compliance-adjacent class §5 calls out;
//! - **hard-coded secrets** — `secret`/`api_key`/`token`/`credential = "…"` assignments and private-key
//!   / AWS-key headers (`critical`/`high`);
//! - **high-entropy string literals** — Shannon entropy over a bits/char threshold (`high`),
//!   a possible embedded credential.

use serde::{Deserialize, Serialize};

/// Finding severity. `critical`/`high` hard-block; `medium`/`low` are scored but non-blocking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Whether a finding at this severity hard-blocks the commit regardless of score.
    #[must_use]
    pub fn hard_blocks(self) -> bool {
        matches!(self, Severity::Critical | Severity::High)
    }
    /// The Confidence-Score penalty for a non-blocking finding (`CODE_REVIEW_PIPELINE.md` §7).
    /// Critical/high never reach the score (they hard-block), so their penalty is not used there.
    #[must_use]
    pub fn score_penalty(self) -> u32 {
        match self {
            Severity::Critical => 100,
            Severity::High => 20,
            Severity::Medium => 8,
            Severity::Low => 2,
        }
    }
}

/// One SAST finding — a typed, located, rule-attributed result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SastFinding {
    pub rule: String,
    pub severity: Severity,
    pub file: String,
    /// 1-based line.
    pub line: usize,
    /// The exact matched evidence (never a paraphrase).
    pub evidence: String,
}

/// A SAST engine. The builtin scans text deterministically; a real engine (Semgrep, `cargo audit`,
/// bandit, gosec) implements the same trait and its findings flow into the same hard-block logic.
pub trait SastScanner {
    fn scan(&self, file: &str, source: &str) -> Vec<SastFinding>;
}

/// Return the first hard-blocking (critical/high) finding, if any — the gate consults this before it
/// ever computes a Confidence Score.
#[must_use]
pub fn hard_block(findings: &[SastFinding]) -> Option<&SastFinding> {
    findings
        .iter()
        .filter(|f| f.severity.hard_blocks())
        .max_by_key(|f| f.severity)
}

/// The offline deterministic scanner.
#[derive(Debug, Clone, Default)]
pub struct BuiltinScanner;

impl SastScanner for BuiltinScanner {
    fn scan(&self, file: &str, source: &str) -> Vec<SastFinding> {
        let mut out = Vec::new();
        for (i, line) in source.lines().enumerate() {
            let ln = i + 1;
            let lower = line.to_ascii_lowercase();

            // 1. Accidental PAN logging: a Luhn-valid 13–19 digit run on a logging line.
            let logging = lower.contains("log")
                || lower.contains("print")
                || lower.contains("println")
                || lower.contains("eprintln")
                || lower.contains("console.");
            if logging {
                for run in digit_runs(line) {
                    let digits: String = run.chars().filter(|c| c.is_ascii_digit()).collect();
                    if (13..=19).contains(&digits.len()) && luhn_ok(&digits) {
                        out.push(SastFinding {
                            rule: "pan-in-log".into(),
                            severity: Severity::Critical,
                            file: file.to_string(),
                            line: ln,
                            evidence: mask_pan(&digits),
                        });
                    }
                }
            }

            // 2. Private-key / AWS-key headers.
            if line.contains("-----BEGIN") && line.contains("PRIVATE KEY") {
                out.push(SastFinding {
                    rule: "private-key-literal".into(),
                    severity: Severity::Critical,
                    file: file.to_string(),
                    line: ln,
                    evidence: "-----BEGIN … PRIVATE KEY-----".into(),
                });
            }
            if let Some(m) = find_aws_key(line) {
                out.push(SastFinding {
                    rule: "aws-access-key".into(),
                    severity: Severity::High,
                    file: file.to_string(),
                    line: ln,
                    evidence: m,
                });
            }

            // 3. Hard-coded secret assignments: `<secretish> = "<nontrivial>"`.
            if let Some((key, val)) = secret_assignment(line) {
                // A short/obvious placeholder is low; a real-looking value is high.
                let sev = if val.len() >= 12 || shannon_bits_per_char(&val) >= 3.5 {
                    Severity::High
                } else {
                    Severity::Medium
                };
                out.push(SastFinding {
                    rule: "hardcoded-secret".into(),
                    severity: sev,
                    file: file.to_string(),
                    line: ln,
                    evidence: format!("{key} = \"…\""),
                });
            } else if let Some(val) = high_entropy_literal(line) {
                // 4. A high-entropy string literal not already flagged as a keyed secret.
                out.push(SastFinding {
                    rule: "high-entropy-literal".into(),
                    severity: Severity::High,
                    file: file.to_string(),
                    line: ln,
                    evidence: format!("entropy≈{:.1} bits/char", shannon_bits_per_char(&val)),
                });
            }
        }
        out
    }
}

/// Contiguous runs of digits (with optional separators) that could be a PAN.
fn digit_runs(line: &str) -> Vec<String> {
    let mut runs = Vec::new();
    let mut cur = String::new();
    for c in line.chars() {
        if c.is_ascii_digit() || ((c == ' ' || c == '-') && !cur.is_empty()) {
            cur.push(c);
        } else {
            if cur.chars().filter(|c| c.is_ascii_digit()).count() >= 13 {
                runs.push(cur.trim().to_string());
            }
            cur.clear();
        }
    }
    if cur.chars().filter(|c| c.is_ascii_digit()).count() >= 13 {
        runs.push(cur.trim().to_string());
    }
    runs
}

/// Luhn checksum (mod-10) validation — the deterministic PAN discriminator.
fn luhn_ok(digits: &str) -> bool {
    let ds: Vec<u32> = digits.chars().filter_map(|c| c.to_digit(10)).collect();
    if ds.len() < 13 {
        return false;
    }
    let mut sum = 0u32;
    let mut double = false;
    for &d in ds.iter().rev() {
        let mut v = d;
        if double {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
        double = !double;
    }
    sum % 10 == 0
}

fn mask_pan(digits: &str) -> String {
    let n = digits.len();
    if n <= 4 {
        return "*".repeat(n);
    }
    format!("{}{}", "*".repeat(n - 4), &digits[n - 4..])
}

/// A `<keyish> = "<value>"` assignment where the key looks secret-bearing.
fn secret_assignment(line: &str) -> Option<(String, String)> {
    let eq = line.find('=')?;
    let (lhs, rhs) = line.split_at(eq);
    let key_raw = lhs
        .trim()
        .trim_end_matches(':')
        .rsplit([' ', '\t', '.'])
        .next()
        .unwrap_or("")
        .trim();
    let key_l = key_raw.to_ascii_lowercase();
    let keyish = [
        "secret",
        "api_key",
        "apikey",
        "token",
        "password",
        "passwd",
        "private_key",
    ]
    .iter()
    .any(|k| key_l.contains(k));
    if !keyish {
        return None;
    }
    let val = string_literal(&rhs[1..])?;
    if val.is_empty() {
        return None;
    }
    Some((key_raw.to_string(), val))
}

/// The first double-quoted string literal in `s`.
fn string_literal(s: &str) -> Option<String> {
    let start = s.find('"')?;
    let rest = &s[start + 1..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// A high-entropy quoted string literal (possible embedded credential), if present.
fn high_entropy_literal(line: &str) -> Option<String> {
    let val = string_literal(line)?;
    if val.len() >= 20 && shannon_bits_per_char(&val) >= 4.0 {
        Some(val)
    } else {
        None
    }
}

/// AWS-access-key-shaped token `AKIA` + 16 uppercase/digit chars.
fn find_aws_key(line: &str) -> Option<String> {
    let bytes = line.as_bytes();
    let needle = b"AKIA";
    for i in 0..bytes.len().saturating_sub(needle.len()) {
        if &bytes[i..i + 4] == needle {
            let tail = &line[i + 4..];
            let run: String = tail
                .chars()
                .take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
                .collect();
            if run.len() >= 16 {
                return Some(format!("AKIA{}…", &run[..4]));
            }
        }
    }
    None
}

/// Shannon entropy in bits per character.
fn shannon_bits_per_char(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = std::collections::BTreeMap::new();
    for c in s.chars() {
        *counts.entry(c).or_insert(0u32) += 1;
    }
    let len = s.chars().count() as f64;
    let mut h = 0.0;
    for &c in counts.values() {
        let p = c as f64 / len;
        h -= p * p.log2();
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn luhn_valid_pan_in_a_log_line_is_critical() {
        // 4111 1111 1111 1111 is the canonical Luhn-valid test PAN.
        let src = "fn f() { log::info!(\"charging card 4111 1111 1111 1111\"); }\n";
        let f = BuiltinScanner.scan("pay.rs", src);
        let pan = f
            .iter()
            .find(|x| x.rule == "pan-in-log")
            .expect("PAN flagged");
        assert_eq!(pan.severity, Severity::Critical);
        assert_eq!(pan.line, 1);
        // Evidence is masked, never the raw PAN.
        assert!(pan.evidence.ends_with("1111"));
        assert!(pan.evidence.contains('*'));
        assert!(hard_block(&f).is_some());
    }

    #[test]
    fn luhn_invalid_number_in_log_is_not_flagged() {
        // 4111 1111 1111 1112 fails Luhn → not a PAN.
        let src = "print(\"order id 4111111111111112\")\n";
        let f = BuiltinScanner.scan("a.py", src);
        assert!(f.iter().all(|x| x.rule != "pan-in-log"));
    }

    #[test]
    fn pan_not_on_a_logging_line_is_ignored() {
        // A PAN in a non-logging context is out of THIS stage's scope (I/O gate handles that).
        let src = "let test_card = \"4111111111111111\";\n";
        let f = BuiltinScanner.scan("a.rs", src);
        assert!(f.iter().all(|x| x.rule != "pan-in-log"));
    }

    #[test]
    fn hardcoded_secret_assignment_is_flagged() {
        let src = "let api_key = \"sk_live_9aB3xQ7ZplMnO2\";\n";
        let f = BuiltinScanner.scan("a.rs", src);
        let s = f.iter().find(|x| x.rule == "hardcoded-secret").unwrap();
        assert_eq!(s.severity, Severity::High);
        // Evidence never leaks the value.
        assert!(!s.evidence.contains("sk_live"));
        assert!(hard_block(&f).is_some());
    }

    #[test]
    fn aws_access_key_is_high() {
        let src = "aws = \"AKIAIOSFODNN7EXAMPLE\"\n";
        let f = BuiltinScanner.scan("c.py", src);
        assert!(f
            .iter()
            .any(|x| x.rule == "aws-access-key" && x.severity == Severity::High));
    }

    #[test]
    fn clean_code_yields_no_findings_and_no_hard_block() {
        let src = "fn add(a: i32, b: i32) -> i32 {\n    a + b\n}\n";
        let f = BuiltinScanner.scan("clean.rs", src);
        assert!(f.is_empty());
        assert!(hard_block(&f).is_none());
    }

    #[test]
    fn hard_block_prefers_the_most_severe_finding() {
        let findings = vec![
            SastFinding {
                rule: "a".into(),
                severity: Severity::High,
                file: "x".into(),
                line: 1,
                evidence: "".into(),
            },
            SastFinding {
                rule: "b".into(),
                severity: Severity::Critical,
                file: "x".into(),
                line: 2,
                evidence: "".into(),
            },
        ];
        assert_eq!(hard_block(&findings).unwrap().severity, Severity::Critical);
    }

    #[test]
    fn entropy_is_higher_for_random_than_repetitive() {
        assert!(shannon_bits_per_char("aaaaaaaa") < 1.0);
        assert!(shannon_bits_per_char("aB3xQ7ZplMnO2kR9") > 3.5);
    }
}
