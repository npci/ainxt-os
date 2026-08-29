// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Steerability / instruction-following as an OWN, mechanically-scored dimension (`GAP_ANALYSIS` BG,
//! `PROMPT_ENGINEERING.md` §9, PE7). A product that ignores explicit instructions "feels like it
//! doesn't listen" regardless of correctness. Steerability failures are usually *objectively
//! checkable* — so scoring is **mechanical** (count bullets, regex-free term checks, length bounds,
//! structure), which is cheap at scale and immune to judge-model drift.
//!
//! Tracked per `(Role, model_family, artifact_version)` ([`SteerabilityScore`]); a model family whose
//! best-achievable score is below the Role's bar is **not eligible** for that Role ([`is_eligible`]) —
//! steerability gates model eligibility the same way data-class does.
//!
//! Deterministic; no clock/rng.

use serde::{Deserialize, Serialize};

/// One machine-checkable constraint attached to a steerability case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum Constraint {
    /// The answer must contain exactly `n` bullet lines.
    ExactBullets { n: usize },
    /// Every listed term (case-insensitive) must appear.
    RequiredTerms { terms: Vec<String> },
    /// None of the listed terms (case-insensitive) may appear.
    ForbiddenTerms { terms: Vec<String> },
    /// The answer must contain a section header line whose text matches `title` (case-insensitive).
    RequiredSection { title: String },
    /// Word count must be ≤ `max`.
    MaxWords { max: usize },
    /// Word count must be ≥ `min`.
    MinWords { min: usize },
    /// The whole answer must be a single JSON object (starts `{`, ends `}`, braces balanced).
    JsonObject,
}

impl Constraint {
    /// Check this constraint against `output`. Returns `(passed, detail)`.
    pub fn check(&self, output: &str) -> (bool, String) {
        match self {
            Constraint::ExactBullets { n } => {
                let got = count_bullets(output);
                (got == *n, format!("bullets: wanted {n}, got {got}"))
            }
            Constraint::RequiredTerms { terms } => {
                let lower = output.to_lowercase();
                let missing: Vec<&String> = terms
                    .iter()
                    .filter(|t| !lower.contains(&t.to_lowercase()))
                    .collect();
                (
                    missing.is_empty(),
                    format!("missing required terms: {missing:?}"),
                )
            }
            Constraint::ForbiddenTerms { terms } => {
                let lower = output.to_lowercase();
                let present: Vec<&String> = terms
                    .iter()
                    .filter(|t| lower.contains(&t.to_lowercase()))
                    .collect();
                (
                    present.is_empty(),
                    format!("forbidden terms present: {present:?}"),
                )
            }
            Constraint::RequiredSection { title } => {
                let want = title.to_lowercase();
                let found = output.lines().any(|l| {
                    let t = l.trim().trim_start_matches('#').trim().to_lowercase();
                    t == want || t == format!("{want}:") || t.starts_with(&format!("{want}:"))
                });
                (
                    found,
                    format!("required section '{title}' present: {found}"),
                )
            }
            Constraint::MaxWords { max } => {
                let n = output.split_whitespace().count();
                (n <= *max, format!("words: {n} (max {max})"))
            }
            Constraint::MinWords { min } => {
                let n = output.split_whitespace().count();
                (n >= *min, format!("words: {n} (min {min})"))
            }
            Constraint::JsonObject => {
                let ok = is_json_object(output);
                (ok, format!("single JSON object: {ok}"))
            }
        }
    }
}

/// One graded steerability case: an output judged against a set of constraints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaseVerdict {
    pub id: String,
    /// Per-constraint pass flags (index-aligned to the case's constraints).
    pub passed: Vec<bool>,
    pub details: Vec<String>,
    /// True iff EVERY constraint passed (a steerability case is all-or-nothing).
    pub all_passed: bool,
}

/// Grade one output against its constraints.
pub fn grade_case(id: &str, output: &str, constraints: &[Constraint]) -> CaseVerdict {
    let mut passed = Vec::with_capacity(constraints.len());
    let mut details = Vec::with_capacity(constraints.len());
    for c in constraints {
        let (ok, detail) = c.check(output);
        passed.push(ok);
        details.push(detail);
    }
    let all_passed = !passed.is_empty() && passed.iter().all(|p| *p);
    CaseVerdict {
        id: id.to_string(),
        passed,
        details,
        all_passed,
    }
}

/// The aggregate steerability score for a `(Role, model_family, artifact_version)`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SteerabilityScore {
    pub model_family: String,
    pub artifact_version: String,
    pub n: usize,
    pub passed: usize,
    /// Fraction of cases where every constraint held (0.0–1.0).
    pub pass_rate: f64,
    pub verdicts: Vec<CaseVerdict>,
}

/// Aggregate a set of graded cases into a per-model score.
pub fn score(
    model_family: &str,
    artifact_version: &str,
    verdicts: Vec<CaseVerdict>,
) -> SteerabilityScore {
    let n = verdicts.len();
    let passed = verdicts.iter().filter(|v| v.all_passed).count();
    let pass_rate = if n == 0 {
        0.0
    } else {
        passed as f64 / n as f64
    };
    SteerabilityScore {
        model_family: model_family.to_string(),
        artifact_version: artifact_version.to_string(),
        n,
        passed,
        pass_rate,
        verdicts,
    }
}

/// Model-eligibility gate: a model family is eligible for the Role only if its steerability pass-rate
/// meets the Role's minimum bar (`PROMPT_ENGINEERING.md` §9). An empty score is never eligible (no
/// evidence is not a pass).
pub fn is_eligible(score: &SteerabilityScore, min_bar: f64) -> bool {
    score.n > 0 && score.pass_rate >= min_bar
}

/// **Gap closure (prompt-governance #3) — config-sourcing for the steerability gate, mirroring how
/// [`crate::policy::PolicyEngineConfig`] sources the L2 policy body.** Before this, the only caller of
/// [`crate::served::steerability_gated_served_chat_prompts`] was this crate's own `#[cfg(test)]` —
/// there was no way for a deployment to actually SUPPLY measured scores to the served build.
///
/// A deployment/tenant TOML `[steerability]` layer supplies the measured per-family
/// [`SteerabilityScore`]s (from the offline steerability harness, §9) and the Role's minimum pass-rate
/// bar, resolved through the SAME layered TOML merge as every other config domain
/// (`ainxt_config::Loader`).
///
/// `scores` empty (the default — no `[steerability]` layer configured) means the gate is **inactive**:
/// the served family list stays unfiltered, byte-for-byte the pre-existing behavior. A deployment that
/// configures at least one score opts into the gate; [`crate::served::steerability_eligible_families`]
/// then drops any candidate family absent from `scores` or below `min_bar`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SteerabilityConfig {
    /// Measured per-family steerability scores from the offline harness. Empty ⇒ gate inactive.
    #[serde(default)]
    pub scores: Vec<SteerabilityScore>,
    /// The minimum instruction-following pass-rate (0.0–1.0) a family must meet to stay served. Only
    /// consulted when `scores` is non-empty.
    #[serde(default)]
    pub min_bar: f64,
}

impl Default for SteerabilityConfig {
    fn default() -> Self {
        SteerabilityConfig {
            scores: Vec::new(),
            min_bar: 0.0,
        }
    }
}

impl SteerabilityConfig {
    /// Whether a deployment has opted into the gate (supplied at least one measured score).
    pub fn is_configured(&self) -> bool {
        !self.scores.is_empty()
    }
}

/// Non-regression check for a new artifact version's steerability vs the previous version: no
/// individual case that previously passed may now fail (§9). Returns the ids that regressed.
pub fn regressed_cases(previous: &SteerabilityScore, candidate: &SteerabilityScore) -> Vec<String> {
    use std::collections::BTreeMap;
    let cand: BTreeMap<&str, bool> = candidate
        .verdicts
        .iter()
        .map(|v| (v.id.as_str(), v.all_passed))
        .collect();
    previous
        .verdicts
        .iter()
        .filter(|p| p.all_passed && !cand.get(p.id.as_str()).copied().unwrap_or(false))
        .map(|p| p.id.clone())
        .collect()
}

// ---------------------------------------------------------------------------------------------
// Mechanical checkers
// ---------------------------------------------------------------------------------------------

/// Count bullet lines: lines whose first non-space content is `- `, `* `, `+ `, or `N.`/`N)`.
fn count_bullets(output: &str) -> usize {
    output
        .lines()
        .filter(|l| {
            let t = l.trim_start();
            t.starts_with("- ")
                || t.starts_with("* ")
                || t.starts_with("+ ")
                || is_ordered_bullet(t)
        })
        .count()
}

/// `1.` / `1)` / `12.` style ordered-list markers.
fn is_ordered_bullet(t: &str) -> bool {
    let digits: String = t.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return false;
    }
    let rest = &t[digits.len()..];
    rest.starts_with(". ") || rest.starts_with(") ") || rest == "." || rest == ")"
}

/// A minimal structural JSON-object check (no serde in the lib path): trimmed text starts with `{`,
/// ends with `}`, and braces balance without going negative (ignoring braces inside strings).
fn is_json_object(output: &str) -> bool {
    let t = output.trim();
    if !(t.starts_with('{') && t.ends_with('}')) {
        return false;
    }
    let mut depth = 0i32;
    let mut in_str = false;
    let mut escaped = false;
    for c in t.chars() {
        if in_str {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_str = false;
            }
            continue;
        }
        match c {
            '"' => in_str = true,
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            _ => {}
        }
    }
    depth == 0 && !in_str
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_bullet_count_is_enforced() {
        let three = "- a\n- b\n- c";
        assert!(Constraint::ExactBullets { n: 3 }.check(three).0);
        assert!(!Constraint::ExactBullets { n: 2 }.check(three).0);
        // Ordered lists count too.
        let ordered = "1. first\n2. second";
        assert!(Constraint::ExactBullets { n: 2 }.check(ordered).0);
    }

    #[test]
    fn required_and_forbidden_terms() {
        let out = "The settlement uses RTGS for high value.";
        assert!(
            Constraint::RequiredTerms {
                terms: vec!["rtgs".into()]
            }
            .check(out)
            .0
        );
        assert!(
            !Constraint::RequiredTerms {
                terms: vec!["neft".into()]
            }
            .check(out)
            .0
        );
        // Negative constraint: must NOT mention the helpdesk number.
        assert!(
            Constraint::ForbiddenTerms {
                terms: vec!["helpdesk".into()]
            }
            .check(out)
            .0
        );
        assert!(
            !Constraint::ForbiddenTerms {
                terms: vec!["settlement".into()]
            }
            .check(out)
            .0
        );
    }

    #[test]
    fn required_section_and_word_bounds() {
        let out = "Summary here.\n## Risks\nThere is a settlement risk.";
        assert!(
            Constraint::RequiredSection {
                title: "Risks".into()
            }
            .check(out)
            .0
        );
        assert!(
            !Constraint::RequiredSection {
                title: "Mitigations".into()
            }
            .check(out)
            .0
        );
        assert!(Constraint::MaxWords { max: 20 }.check(out).0);
        assert!(!Constraint::MaxWords { max: 3 }.check(out).0);
        assert!(Constraint::MinWords { min: 3 }.check(out).0);
    }

    #[test]
    fn json_object_structure_check() {
        assert!(Constraint::JsonObject.check(r#"{"a": 1, "b": {"c": 2}}"#).0);
        // Brace inside a string must not confuse the balancer.
        assert!(Constraint::JsonObject.check(r#"{"a": "has } brace"}"#).0);
        assert!(!Constraint::JsonObject.check("not json").0);
        assert!(!Constraint::JsonObject.check(r#"{"a": 1"#).0); // unbalanced
        assert!(!Constraint::JsonObject.check(r#"[1,2,3]"#).0); // array, not object
    }

    #[test]
    fn case_is_all_or_nothing_and_aggregates() {
        let constraints = vec![
            Constraint::ExactBullets { n: 2 },
            Constraint::ForbiddenTerms {
                terms: vec!["phone".into()],
            },
        ];
        let good = grade_case("c1", "- one\n- two", &constraints);
        assert!(good.all_passed);
        let bad = grade_case("c2", "- one\n- two\ncall the phone", &constraints);
        assert!(!bad.all_passed);
        assert_eq!(bad.passed, vec![true, false]);

        let s = score("qwen", "role.support@7", vec![good, bad]);
        assert_eq!(s.n, 2);
        assert_eq!(s.passed, 1);
        assert!((s.pass_rate - 0.5).abs() < 1e-9);
    }

    #[test]
    fn eligibility_gates_on_the_bar_and_rejects_no_evidence() {
        let strong = score(
            "claude",
            "v1",
            vec![grade_case(
                "c",
                "- a\n- b",
                &[Constraint::ExactBullets { n: 2 }],
            )],
        );
        assert!(is_eligible(&strong, 0.9));
        let empty = score("weak", "v1", vec![]);
        assert!(!is_eligible(&empty, 0.0), "no evidence is never eligible");
    }

    #[test]
    fn steerability_regression_is_detected_case_by_case() {
        let c = vec![Constraint::ExactBullets { n: 2 }];
        let prev = score(
            "m",
            "v1",
            vec![
                grade_case("a", "- x\n- y", &c),
                grade_case("b", "- x\n- y", &c),
            ],
        );
        // Candidate breaks case "b" (now 3 bullets) that previously passed → regression on "b".
        let cand = score(
            "m",
            "v2",
            vec![
                grade_case("a", "- x\n- y", &c),
                grade_case("b", "- x\n- y\n- z", &c),
            ],
        );
        let regressed = regressed_cases(&prev, &cand);
        assert_eq!(regressed, vec!["b".to_string()]);
    }
}
