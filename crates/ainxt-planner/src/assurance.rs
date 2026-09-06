// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Real, **non-synthetic** offline backings for two of the three verification proofs (§6 / §10):
//! the **adversarial Breaker** and the **semantic rubric Judge**.
//!
//! Design: `docs/architecture/LONG_HORIZON_PROGRAMS.md` (ADR-027) §6 and
//! `docs/architecture/LOOP_AND_AGENT_TEAMS.md` §7.
//!
//! # The gap this closes
//!
//! [`crate::verify::three_way_gate`] combines three *independent* proofs — a deterministic gate, an
//! adversarial gate, and a semantic Judge. The pure combiner has always been real, but the served
//! program driver fabricated two of the three: it handed the gate an `AdversarialVerdict::green()` and
//! a fixed-score `JudgeVerdict::pass(95, …)` regardless of what the module produced. A green
//! adversarial + high judge score that do not actually *look at the artifact* are worthless — they can
//! never catch a bad module, so "three-way verification" collapses to the deterministic gate alone.
//!
//! This module supplies the two missing proofs as **deterministic content analysers** that genuinely
//! inspect the produced artifact and return a *computed* verdict:
//!
//! * [`AdversarialBreaker`] runs a battery of concrete attack probes (empty output, unfinished
//!   stub/placeholder markers, a card-number-shaped literal that would breach PCI-DSS, a claim of
//!   input handling with no validation, a claim of tests with no boundary/edge coverage) and returns
//!   an [`AdversarialVerdict`] whose `counterexamples` are the probes that *found something* — any
//!   surviving counterexample hard-blocks the commit.
//! * [`RubricJudge`] scores the artifact against a four-dimension rubric (substance, goal-relevance,
//!   completeness, safety hygiene), 0..=100, and returns a cross-model [`JudgeVerdict`] whose score
//!   *varies with the content* — a stubbed or off-goal artifact scores below threshold and blocks.
//!
//! Both are pure and deterministic (no clock/rng/I/O), so every rule is a unit-test property. They are
//! the OSS offline defaults the design's §10 model seams hot-wire: a deployment replaces the Breaker
//! with a real exploratory attack loop and the Judge with a cross-model LLM judge (both needing a live
//! model → `needs_hot_wiring`). The point closed here is that the *served default is no longer a
//! fabricated green* — it is a real analysis that can, and does, block a bad module.

use crate::program::EditRung;
use crate::verify::{AdversarialVerdict, JudgeVerdict};

/// The produced module artifact handed to the offline Breaker + Judge (§6). Deliberately carries only
/// what a fresh-context reviewer may see: the goal it was meant to satisfy, the produced text/diff, the
/// rung it was authored at, and whether the producer *claimed* to have handled input / written tests
/// (so the Breaker can check the claim against the artifact — the anti-sycophancy check).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleArtifact {
    /// The module goal the artifact must satisfy (its keywords drive the goal-relevance dimension).
    pub goal: String,
    /// The produced artifact text (code/diff/report). The analysers read this, never a self-narrative.
    pub text: String,
    /// The model that PRODUCED the artifact (threaded into the cross-model Judge as `producer_model`).
    pub producer_model: String,
    /// The Semantic-Editing rung the artifact was authored at (§10).
    pub edit_rung: EditRung,
    /// The producer claimed the artifact validates/handles its input — the Breaker checks the claim.
    pub claims_input_handling: bool,
    /// The producer claimed the artifact includes tests — the Breaker checks for boundary coverage.
    pub claims_tests: bool,
}

impl ModuleArtifact {
    /// A minimal artifact: just a goal + produced text + producer model, no producer claims.
    pub fn new(
        goal: impl Into<String>,
        text: impl Into<String>,
        producer_model: impl Into<String>,
    ) -> Self {
        ModuleArtifact {
            goal: goal.into(),
            text: text.into(),
            producer_model: producer_model.into(),
            edit_rung: EditRung::StructuredPatch,
            claims_input_handling: false,
            claims_tests: false,
        }
    }
    pub fn with_edit_rung(mut self, rung: EditRung) -> Self {
        self.edit_rung = rung;
        self
    }
    pub fn claiming_input_handling(mut self) -> Self {
        self.claims_input_handling = true;
        self
    }
    pub fn claiming_tests(mut self) -> Self {
        self.claims_tests = true;
        self
    }
}

/// Markers that betray an unfinished / placeholder artifact — a "completed" claim these words refute.
const STUB_MARKERS: &[&str] = &[
    "todo",
    "fixme",
    "unimplemented",
    "not implemented",
    "todo!",
    "unimplemented!",
    "panic!(\"todo",
    "placeholder",
    "your code here",
];

/// Split a string into lowercase alphanumeric word tokens (≥ 3 chars) — the keyword basis for the
/// goal-relevance dimension. Pure + allocation-light; no external tokenizer.
fn keywords(s: &str) -> Vec<String> {
    s.split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| w.len() >= 3)
        .map(|w| w.to_ascii_lowercase())
        .collect()
}

/// Whether `text` contains a **card-number-shaped** literal: a run of 13..=19 digits (spaces/dashes
/// tolerated) whose digits satisfy the Luhn checksum. This is the same shape the compliance gate
/// treats as a PAN — a generated module that embeds one is a hard adversarial counterexample (it would
/// breach PCI-DSS the moment it ran). Deterministic; no regex crate.
fn contains_pan_shaped(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if !bytes[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        // Collect a maximal digit run allowing single space/dash separators between digits.
        let mut digits: Vec<u8> = Vec::new();
        let mut j = i;
        while j < bytes.len() {
            let c = bytes[j];
            if c.is_ascii_digit() {
                digits.push(c - b'0');
                j += 1;
            } else if (c == b' ' || c == b'-')
                && j + 1 < bytes.len()
                && bytes[j + 1].is_ascii_digit()
            {
                j += 1; // skip a single separator inside the run
            } else {
                break;
            }
        }
        if (13..=19).contains(&digits.len()) && luhn_ok(&digits) {
            return true;
        }
        i = j.max(i + 1);
    }
    false
}

/// Luhn checksum over already-parsed decimal digits.
fn luhn_ok(digits: &[u8]) -> bool {
    let mut sum = 0u32;
    let mut double = false;
    for &d in digits.iter().rev() {
        let mut v = d as u32;
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

// ===========================================================================
// Adversarial Breaker (§6 gate 2) — real attack probes, not a fabricated green
// ===========================================================================

/// The offline adversarial Breaker (§6): a battery of deterministic attack probes over a produced
/// artifact. Each probe that *finds something* contributes a concrete counterexample; any surviving
/// counterexample hard-blocks the commit in [`crate::verify::three_way_gate`]. A deployment replaces
/// this with a real exploratory attack loop / property-fuzzer (needs a live executor → `needs_hot_wiring`),
/// but the offline default is already a genuine analysis — never a fabricated `green()`.
#[derive(Debug, Clone, Copy, Default)]
pub struct AdversarialBreaker;

impl AdversarialBreaker {
    pub fn new() -> Self {
        AdversarialBreaker
    }

    /// Run every probe against `artifact` and return the [`AdversarialVerdict`]. `attempts` is the
    /// number of probes run; `counterexamples` are the ones that found a defect (empty ⇒ green).
    pub fn attack(&self, artifact: &ModuleArtifact) -> AdversarialVerdict {
        let text = &artifact.text;
        let lower = text.to_ascii_lowercase();
        let mut counterexamples: Vec<String> = Vec::new();

        // Probe 1 — empty / whitespace-only output produces nothing committable.
        if text.trim().is_empty() {
            counterexamples
                .push("empty-output: the artifact produced no committable content".into());
        }

        // Probe 2 — unfinished stub / placeholder markers refute a "done" artifact.
        for marker in STUB_MARKERS {
            if lower.contains(marker) {
                counterexamples.push(format!(
                    "unfinished-stub: artifact contains placeholder marker '{marker}'"
                ));
                break;
            }
        }

        // Probe 3 — a card-number-shaped literal would breach PCI-DSS at runtime (compliance escapes
        // the model's own redaction because it is *baked into generated code*).
        if contains_pan_shaped(text) {
            counterexamples
                .push("pci-leak: artifact embeds a card-number-shaped (Luhn-valid) literal".into());
        }

        // Probe 4 — a claim of input handling with no validation/error path in the artifact.
        if artifact.claims_input_handling
            && !(lower.contains("error")
                || lower.contains("valid")
                || lower.contains("err(")
                || lower.contains("result<")
                || lower.contains("throw")
                || lower.contains("raise")
                || lower.contains("reject"))
        {
            counterexamples.push(
                "unhandled-input: claims input handling but shows no validation/error path".into(),
            );
        }

        // Probe 5 — a claim of tests with no boundary / edge-case coverage is a weak test.
        if artifact.claims_tests
            && !(lower.contains("boundary")
                || lower.contains("edge")
                || lower.contains("empty")
                || lower.contains("overflow")
                || lower.contains("negative")
                || lower.contains("max")
                || lower.contains("zero"))
        {
            counterexamples
                .push("shallow-tests: claims tests but none exercise a boundary/edge case".into());
        }

        AdversarialVerdict {
            attempts: PROBE_COUNT,
            counterexamples,
            completed: true,
        }
    }
}

/// The number of probes [`AdversarialBreaker::attack`] runs (reported as `attempts`).
const PROBE_COUNT: u32 = 5;

// ===========================================================================
// Rubric Judge (§6 gate 3 / §10) — a computed, content-varying score
// ===========================================================================

/// A four-dimension rubric score (each 0..=25) — the transparent basis for the Judge's 0..=100 score,
/// so a blocked artifact carries *why* it scored low, not just a number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RubricScore {
    /// The artifact is substantive (non-trivial length), not a one-liner stub.
    pub substance: u32,
    /// The artifact's tokens overlap the goal's keywords (it is on-goal, not off-topic).
    pub goal_relevance: u32,
    /// No unfinished / placeholder markers (it is complete).
    pub completeness: u32,
    /// No obvious safety-hygiene defect (no card-number-shaped literal).
    pub safety_hygiene: u32,
}

impl RubricScore {
    /// The total 0..=100 score.
    pub fn total(&self) -> u32 {
        (self.substance + self.goal_relevance + self.completeness + self.safety_hygiene).min(100)
    }
}

/// The offline semantic Judge (§6 gate 3): scores a produced artifact against a four-dimension rubric
/// and emits a **cross-model** [`JudgeVerdict`] (its `judge_model` differs from the producer, so a
/// same-model pairing is rejected structurally by [`crate::verify::three_way_gate`], §10). Unlike the
/// fabricated `pass(95, …)` the served path used, the score is *computed from the content* — a stubbed
/// or off-goal artifact scores below threshold and blocks. A deployment hot-wires a real cross-model
/// LLM judge behind the same shape (`needs_hot_wiring`).
#[derive(Debug, Clone)]
pub struct RubricJudge {
    /// The distinct judge model label (must differ from the artifact's producer model, §10).
    pub judge_model: String,
    /// Minimum acceptable total score.
    pub threshold: u32,
    /// Minimum substantive length (chars) for full `substance` credit.
    pub min_len: usize,
}

impl Default for RubricJudge {
    fn default() -> Self {
        RubricJudge {
            judge_model: "rubric-cross-judge".to_string(),
            threshold: 80,
            min_len: 40,
        }
    }
}

impl RubricJudge {
    /// A rubric judge with the given distinct judge-model label and threshold.
    pub fn new(judge_model: impl Into<String>, threshold: u32) -> Self {
        RubricJudge {
            judge_model: judge_model.into(),
            threshold,
            ..Default::default()
        }
    }

    /// Score `artifact` against the rubric (0..=25 per dimension).
    pub fn score(&self, artifact: &ModuleArtifact) -> RubricScore {
        let text = &artifact.text;
        let trimmed = text.trim();
        let lower = text.to_ascii_lowercase();

        // Substance — proportional to length up to `min_len`, 0 for empty.
        let substance = if trimmed.is_empty() {
            0
        } else {
            ((trimmed.len().min(self.min_len) as u32) * 25 / (self.min_len.max(1) as u32)).min(25)
        };

        // Goal-relevance — fraction of the goal's distinct keywords present in the artifact.
        let goal_kw = keywords(&artifact.goal);
        let goal_relevance = if goal_kw.is_empty() {
            25
        } else {
            let art_lower = lower.clone();
            let present = {
                let mut seen = std::collections::BTreeSet::new();
                for k in &goal_kw {
                    if art_lower.contains(k.as_str()) {
                        seen.insert(k.clone());
                    }
                }
                seen.len()
            };
            let distinct: std::collections::BTreeSet<&String> = goal_kw.iter().collect();
            (present as u32 * 25 / distinct.len().max(1) as u32).min(25)
        };

        // Completeness — full credit unless a stub/placeholder marker is present.
        let completeness = if STUB_MARKERS.iter().any(|m| lower.contains(m)) {
            0
        } else {
            25
        };

        // Safety hygiene — full credit unless a card-number-shaped literal is embedded.
        let safety_hygiene = if contains_pan_shaped(text) { 0 } else { 25 };

        RubricScore {
            substance,
            goal_relevance,
            completeness,
            safety_hygiene,
        }
    }

    /// Judge `artifact` and return the cross-model [`JudgeVerdict`] the three-way gate consumes.
    pub fn judge(&self, artifact: &ModuleArtifact) -> JudgeVerdict {
        let total = self.score(artifact).total();
        JudgeVerdict {
            score: total,
            threshold: self.threshold,
            producer_model: artifact.producer_model.clone(),
            judge_model: self.judge_model.clone(),
            completed: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::{three_way_gate, DeterministicVerdict, GateOutcome};

    fn good_artifact() -> ModuleArtifact {
        ModuleArtifact::new(
            "validate the settlement amount and reject negative values",
            "fn validate(amount: i64) -> Result<(), Error> { if amount < 0 { return Err(Error::Negative); } Ok(()) }\n#[test] fn rejects_negative_and_zero_boundary() { assert!(validate(-1).is_err()); assert!(validate(0).is_ok()); }",
            "qwen-coder",
        )
        .claiming_input_handling()
        .claiming_tests()
    }

    #[test]
    fn breaker_passes_a_real_substantive_artifact() {
        let adv = AdversarialBreaker::new().attack(&good_artifact());
        assert!(
            adv.counterexamples.is_empty(),
            "unexpected: {:?}",
            adv.counterexamples
        );
        assert_eq!(adv.attempts, PROBE_COUNT);
        assert!(adv.completed);
    }

    #[test]
    fn breaker_flags_empty_stub_and_pan() {
        let empty = AdversarialBreaker::new().attack(&ModuleArtifact::new("g", "   ", "m"));
        assert!(empty
            .counterexamples
            .iter()
            .any(|c| c.contains("empty-output")));

        let stub =
            AdversarialBreaker::new().attack(&ModuleArtifact::new("g", "fn f() { todo!() }", "m"));
        assert!(stub
            .counterexamples
            .iter()
            .any(|c| c.contains("unfinished-stub")));

        // A Luhn-valid 16-digit literal baked into code.
        let pan = AdversarialBreaker::new().attack(&ModuleArtifact::new(
            "g",
            "let card = \"4111 1111 1111 1111\";",
            "m",
        ));
        assert!(pan.counterexamples.iter().any(|c| c.contains("pci-leak")));
    }

    #[test]
    fn breaker_checks_producer_claims_against_the_artifact() {
        // Claims input handling but shows no validation/error path.
        let a = ModuleArtifact::new(
            "parse the file",
            "fn parse(s: &str) { println!(\"{s}\"); }",
            "m",
        )
        .claiming_input_handling();
        let v = AdversarialBreaker::new().attack(&a);
        assert!(v
            .counterexamples
            .iter()
            .any(|c| c.contains("unhandled-input")));

        // Claims tests but no boundary/edge coverage.
        let b = ModuleArtifact::new("add feature", "#[test] fn works() { assert!(run()); }", "m")
            .claiming_tests();
        let v = AdversarialBreaker::new().attack(&b);
        assert!(v
            .counterexamples
            .iter()
            .any(|c| c.contains("shallow-tests")));
    }

    #[test]
    fn judge_score_varies_with_content_and_is_cross_model() {
        let j = RubricJudge::default();
        let good = j.judge(&good_artifact());
        assert!(good.score >= good.threshold, "good scored {}", good.score);
        assert_ne!(good.producer_model, good.judge_model, "must be cross-model");

        // An off-goal stub scores far below threshold — a real block, not a fabricated pass.
        let bad = j.judge(&ModuleArtifact::new(
            "validate the settlement amount and reject negatives",
            "// TODO",
            "qwen-coder",
        ));
        assert!(bad.score < bad.threshold, "bad scored {}", bad.score);
    }

    #[test]
    fn a_bad_artifact_blocks_the_full_three_way_gate() {
        // Even with a green deterministic gate, the real breaker + judge together block a stub.
        let stub = ModuleArtifact::new("do the thing", "fn f() { todo!() }", "qwen-coder");
        let adv = AdversarialBreaker::new().attack(&stub);
        let judge = RubricJudge::default().judge(&stub);
        let out = three_way_gate(&DeterministicVerdict::green(), &adv, &judge);
        assert!(matches!(out, GateOutcome::Blocked { .. }));

        // A good artifact with the same green deterministic gate is Complete.
        let good = good_artifact();
        let adv = AdversarialBreaker::new().attack(&good);
        let judge = RubricJudge::default().judge(&good);
        let out = three_way_gate(&DeterministicVerdict::green(), &adv, &judge);
        assert_eq!(out, GateOutcome::Complete);
    }
}
