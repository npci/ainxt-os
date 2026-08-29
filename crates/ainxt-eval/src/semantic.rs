// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Semantic LLM-judge — the OFFLINE, deterministic stand-in behind the [`crate::QualityJudge`] seam
//! (EVAL_PLATFORM.md §4; gap "semantic LLM-judge + durable production backends behind the trait
//! seams").
//!
//! The production Judge is a pinned, calibrated LLM (§4.1) reached over the Provider Gateway — a
//! **live** model call, and therefore infra-gated (real weights / GPU or a cloud endpoint + keys).
//! What lives here in the open-source core is (a) the seam ([`crate::QualityJudge`]) the LLM judge
//! plugs into unchanged, and (b) a **deterministic semantic scorer** that stands in for it offline so
//! the gate's own logic is exercised end-to-end without a model:
//!
//! * [`SemanticOverlapJudge`] scores **groundedness** — how much of the answer is supported by the
//!   reference/rubric and how much of the rubric the answer covers — as a token-overlap F1. It is a
//!   genuine, if lexical, semantic signal: a grounded answer scores high, an off-topic/hallucinated
//!   answer scores low, deterministically and with no dependency surface. Swapping it for the pinned
//!   LLM judge is a config change behind the same trait; nothing else in the gate moves.
//!
//! The durable production backends the design also names (the encrypted `SealedCorpusStore`, the
//! tamper-evident `EventSink`/WORM Event Log, the drift-score stream) are, likewise, **trait seams**
//! in this crate ([`crate::integrity::SealedCorpusStore`], [`crate::audit::EventSink`]); their
//! Postgres/Redis/object-store implementations are infra-gated and live in the reserved daemon crates.
//! This module's job is to prove the seam is real and drivable, not to embed a database.

use crate::{EvalCriteria, QualityJudge, QualityScore};
use std::collections::BTreeSet;

/// Lowercase alphanumeric word tokens (a stable, dependency-free tokenizer).
fn tokens(s: &str) -> BTreeSet<String> {
    s.split(|c: char| !c.is_alphanumeric())
        .filter(|t| t.len() >= 3) // drop stopword-ish fragments deterministically
        .map(|t| t.to_lowercase())
        .collect()
}

/// A deterministic groundedness/relevance judge: the offline stand-in for the pinned LLM judge behind
/// the [`QualityJudge`] seam. The score is the token-overlap **F1** between the answer and the
/// grounding set (the case rubric plus, optionally, the input), scaled to 0–100 — precision guards
/// against hallucination (answer tokens unsupported by the grounding), recall against incompleteness
/// (grounding not covered by the answer).
#[derive(Debug, Clone, Default)]
pub struct SemanticOverlapJudge {
    /// Also treat the case input as part of the grounding set (relevance-to-question, not just rubric).
    pub ground_on_input: bool,
}

impl SemanticOverlapJudge {
    pub fn new() -> Self {
        Self::default()
    }

    /// F1 of two token sets, 0–100. Empty grounding ⇒ 50 (no signal, neither pass nor fail).
    fn f1(answer: &BTreeSet<String>, grounding: &BTreeSet<String>) -> u8 {
        if grounding.is_empty() {
            return 50;
        }
        if answer.is_empty() {
            return 0;
        }
        let overlap = answer.intersection(grounding).count() as f64;
        let precision = overlap / answer.len() as f64;
        let recall = overlap / grounding.len() as f64;
        if precision + recall == 0.0 {
            return 0;
        }
        let f1 = 2.0 * precision * recall / (precision + recall);
        (f1 * 100.0).round().clamp(0.0, 100.0) as u8
    }
}

impl QualityJudge for SemanticOverlapJudge {
    fn score(&self, input: &str, output: &str, criteria: &EvalCriteria) -> QualityScore {
        let answer = tokens(output);
        let mut grounding = tokens(&criteria.rubric);
        if self.ground_on_input {
            grounding.extend(tokens(input));
        }
        let score = Self::f1(&answer, &grounding);
        QualityScore {
            score,
            rationale: format!(
                "semantic-overlap groundedness: {score}/100 ({} answer tokens vs {} grounding tokens)",
                answer.len(),
                grounding.len()
            ),
        }
    }
}

/// A deterministic, order-independent pairwise comparator built on [`SemanticOverlapJudge`]'s F1
/// score: scores each side's groundedness independently and picks the higher one (within
/// `tie_epsilon` points is reported as a [`crate::judge::PairwiseVerdict::Tie`], never an arbitrary
/// pick). Being a pure function of `(input, a, b, criteria)` it exhibits NO position bias by
/// construction — the offline reference implementation behind [`crate::judge::PairwiseJudge`], playing
/// the same role for pairwise comparison that [`SemanticOverlapJudge`] plays for single-output scoring.
#[derive(Debug, Clone)]
pub struct SemanticOverlapPairwiseJudge {
    pub inner: SemanticOverlapJudge,
    /// Score-point tolerance within which the two sides are reported as a tie rather than a
    /// razor-thin, noise-driven pick.
    pub tie_epsilon: u8,
}

impl Default for SemanticOverlapPairwiseJudge {
    fn default() -> Self {
        SemanticOverlapPairwiseJudge {
            inner: SemanticOverlapJudge::new(),
            tie_epsilon: 2,
        }
    }
}

impl crate::judge::PairwiseJudge for SemanticOverlapPairwiseJudge {
    fn compare(
        &self,
        input: &str,
        a: &str,
        b: &str,
        criteria: &EvalCriteria,
    ) -> crate::judge::PairwiseVerdict {
        let score_a = self.inner.score(input, a, criteria).score;
        let score_b = self.inner.score(input, b, criteria).score;
        if score_a.abs_diff(score_b) <= self.tie_epsilon {
            crate::judge::PairwiseVerdict::Tie
        } else if score_a > score_b {
            crate::judge::PairwiseVerdict::A
        } else {
            crate::judge::PairwiseVerdict::B
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EvalCriteria;

    fn crit(rubric: &str) -> EvalCriteria {
        EvalCriteria {
            rubric: rubric.into(),
            threshold: 60,
        }
    }

    #[test]
    fn r11_semantic_judge_separates_grounded_from_hallucinated() {
        let judge = SemanticOverlapJudge::new();
        let c = crit("settlement batches reconcile against the ledger before payout");
        // A grounded answer that covers the rubric scores well above threshold.
        let grounded = judge
            .score(
                "the settlement batches reconcile against the ledger prior to any payout",
                "the settlement batches reconcile against the ledger prior to any payout",
                &c,
            )
            .score;
        // An off-topic / hallucinated answer scores far below.
        let hallucinated = judge
            .score(
                "the weather in mumbai is pleasant during monsoon season",
                "",
                &c,
            )
            .score;
        assert!(
            grounded >= c.threshold,
            "a grounded answer must clear threshold, got {grounded}"
        );
        assert!(
            hallucinated < c.threshold,
            "an off-topic answer must fall below threshold, got {hallucinated}"
        );
        assert!(
            grounded > hallucinated + 30,
            "the judge must clearly separate the two"
        );
    }

    #[test]
    fn r11_semantic_judge_is_deterministic_and_object_safe() {
        // Behind the QualityJudge seam (dyn) — the exact slot the pinned LLM judge fills.
        let judge: Box<dyn QualityJudge> = Box::new(SemanticOverlapJudge::new());
        let c = crit("idempotency key prevents double execution of a payment");
        let a = judge
            .score("q", "the idempotency key prevents double execution", &c)
            .score;
        let b = judge
            .score("q", "the idempotency key prevents double execution", &c)
            .score;
        assert_eq!(
            a, b,
            "the offline judge must be deterministic (reproducible scores)"
        );
    }
}
