// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! RAG evals as a gate (EVAL_PLATFORM.md §6, gaps G/AN).
//!
//! "The answer got worse" is useless without "…because recall dropped" vs "…because the model stopped
//! citing". This module decomposes RAG quality so a regression is **localized** (retrieval vs
//! generation), and provides the load-bearing **embedding-migration gate** (gap AN — a half-migrated,
//! mixed-embedding-version index silently degrades retrieval).
//!
//! Retrieval metrics ([`context_recall`], [`context_precision`], [`recall_at_k`], [`mrr`],
//! [`average_precision`]) are deterministic against a labeled relevant-set. Generation metrics
//! ([`claim_groundedness`], [`citation_span_faithfulness`]) are claim-decomposed lexical scorers with
//! an explicit [`GroundednessJudge`] seam where a semantic LLM-judge plugs in behind the same shape.
//!
//! Pure, deterministic, std-only.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

// ===========================================================================================
// Retrieval-side metrics (deterministic, against a labeled relevant-set)
// ===========================================================================================

/// One retrieval observation for a case: the ranked chunk ids returned (best first) and the ids that
/// are actually relevant (the labeled gold set for the case).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RetrievalCase {
    pub retrieved: Vec<String>,
    pub relevant: Vec<String>,
}

/// Context recall: fraction of the labeled-relevant chunks that were retrieved at all. A drop here is
/// the classic "we stopped fetching the evidence" regression (and the embedding-migration symptom).
pub fn context_recall(case: &RetrievalCase) -> f64 {
    if case.relevant.is_empty() {
        return 1.0; // nothing to recall → vacuously complete
    }
    let ret: BTreeSet<&String> = case.retrieved.iter().collect();
    let hit = case.relevant.iter().filter(|r| ret.contains(r)).count();
    hit as f64 / case.relevant.len() as f64
}

/// Recall@k: fraction of relevant chunks present in the top-`k` retrieved.
pub fn recall_at_k(case: &RetrievalCase, k: usize) -> f64 {
    if case.relevant.is_empty() {
        return 1.0;
    }
    let topk: BTreeSet<&String> = case.retrieved.iter().take(k).collect();
    let hit = case.relevant.iter().filter(|r| topk.contains(r)).count();
    hit as f64 / case.relevant.len() as f64
}

/// Mean reciprocal rank contribution for one case: 1/(rank of the first relevant chunk), 0 if none.
pub fn mrr(case: &RetrievalCase) -> f64 {
    let rel: BTreeSet<&String> = case.relevant.iter().collect();
    for (i, id) in case.retrieved.iter().enumerate() {
        if rel.contains(id) {
            return 1.0 / (i as f64 + 1.0);
        }
    }
    0.0
}

/// Average precision (rank-aware) for one case — rewards putting relevant chunks high, not padding.
pub fn average_precision(case: &RetrievalCase) -> f64 {
    if case.relevant.is_empty() {
        return 1.0;
    }
    let rel: BTreeSet<&String> = case.relevant.iter().collect();
    let mut hits = 0usize;
    let mut sum_prec = 0.0;
    for (i, id) in case.retrieved.iter().enumerate() {
        if rel.contains(id) {
            hits += 1;
            sum_prec += hits as f64 / (i as f64 + 1.0);
        }
    }
    if hits == 0 {
        0.0
    } else {
        sum_prec / case.relevant.len() as f64
    }
}

/// Context precision: rank-aware precision that the top-ranked chunks are the relevant ones (mean of
/// average precision across cases). Aggregated over a suite via [`RagReport`].
pub fn context_precision(case: &RetrievalCase) -> f64 {
    average_precision(case)
}

// ===========================================================================================
// Generation-side metrics (claim-decomposed; lexical default + Judge seam)
// ===========================================================================================

const STOPWORDS: &[&str] = &[
    "the", "a", "an", "and", "or", "but", "of", "to", "in", "on", "for", "is", "are", "was",
    "were", "be", "by", "with", "as", "at", "it", "this", "that", "these", "those", "from", "into",
    "than", "then", "so", "not", "no", "if", "will", "can", "may", "each", "per", "its",
];

fn content_words(s: &str) -> BTreeSet<String> {
    s.split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
        .map(|t| t.to_lowercase())
        .filter(|t| t.len() >= 3 && !STOPWORDS.contains(&t.as_str()))
        .collect()
}

/// Split an answer into atomic claims (sentence-ish units on `.`/`!`/`?`/newline).
pub fn decompose_claims(answer: &str) -> Vec<String> {
    answer
        .split(['.', '!', '?', '\n'])
        .map(|s| s.trim())
        .filter(|s| !s.is_empty() && s.chars().any(|c| c.is_alphanumeric()))
        .map(|s| s.to_string())
        .collect()
}

/// A semantic groundedness judge seam (an LLM-judge implements this). The lexical default
/// [`LexicalGroundedness`] is used when no semantic judge is wired.
pub trait GroundednessJudge: Send + Sync {
    /// Is this claim supported by the given context passages? (0.0–1.0 support score.)
    fn support(&self, claim: &str, context: &[String]) -> f64;
}

/// The deterministic lexical fallback: a claim is supported to the degree its content words appear in
/// the union of the context passages.
pub struct LexicalGroundedness;

impl GroundednessJudge for LexicalGroundedness {
    fn support(&self, claim: &str, context: &[String]) -> f64 {
        let cw = content_words(claim);
        if cw.is_empty() {
            return 1.0;
        }
        let mut support: BTreeSet<String> = BTreeSet::new();
        for c in context {
            support.extend(content_words(c));
        }
        let supported = cw.iter().filter(|w| support.contains(*w)).count();
        supported as f64 / cw.len() as f64
    }
}

/// Claim-decomposed groundedness: the fraction of the answer's claims that clear `min_support` given
/// the retrieved context, scored by `judge`. This localizes hallucination to specific claims.
pub fn claim_groundedness(
    answer: &str,
    context: &[String],
    judge: &dyn GroundednessJudge,
    min_support: f64,
) -> f64 {
    let claims = decompose_claims(answer);
    if claims.is_empty() {
        return 1.0;
    }
    let supported = claims
        .iter()
        .filter(|c| judge.support(c, context) >= min_support)
        .count();
    supported as f64 / claims.len() as f64
}

/// One cited claim: the claim text and the source passage the citation points at.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CitedClaim {
    pub claim: String,
    pub cited_source: String,
}

/// Citation-span faithfulness (gap AA): does each cited source *actually support* the specific claim
/// attached to it? Scores the fraction of cited claims whose content words are covered by their own
/// cited span at/above `min_support`. Catches a real-but-wrong citation (source exists but doesn't say
/// what the claim says), which whole-context groundedness would miss.
pub fn citation_span_faithfulness(cited: &[CitedClaim], min_support: f64) -> f64 {
    if cited.is_empty() {
        return 1.0;
    }
    let judge = LexicalGroundedness;
    let faithful = cited
        .iter()
        .filter(|c| judge.support(&c.claim, std::slice::from_ref(&c.cited_source)) >= min_support)
        .count();
    faithful as f64 / cited.len() as f64
}

// ===========================================================================================
// Answer relevance (EVAL_PLATFORM.md §6 — "does the answer address the actual question?")
// ===========================================================================================

/// A semantic answer-relevance judge seam (an LLM-judge implements this — e.g. RAGAS-style
/// question-regeneration). The lexical default [`LexicalRelevance`] is used when none is wired.
pub trait RelevanceJudge: Send + Sync {
    /// How well does `answer` address `question`? 0.0–1.0. Independent of groundedness: a perfectly
    /// grounded answer to the *wrong* question scores low here.
    fn relevance(&self, question: &str, answer: &str) -> f64;
}

/// Deterministic lexical relevance: the fraction of the QUESTION's content words the answer engages,
/// down-weighted when the answer is padded with large amounts of off-question material (so a long
/// off-topic essay that happens to contain the question's words does not score a spurious 1.0).
pub struct LexicalRelevance;

/// Interrogatives / question function-words carry no topical signal — they should not count against
/// an answer that addresses the substance of the question.
const INTERROGATIVES: &[&str] = &[
    "what", "when", "where", "who", "whom", "whose", "why", "how", "which", "does", "did", "do",
    "should", "would", "could", "many", "much",
];

impl RelevanceJudge for LexicalRelevance {
    fn relevance(&self, question: &str, answer: &str) -> f64 {
        let q: BTreeSet<String> = content_words(question)
            .into_iter()
            .filter(|w| !INTERROGATIVES.contains(&w.as_str()))
            .collect();
        if q.is_empty() {
            return 1.0;
        }
        let a = content_words(answer);
        if a.is_empty() {
            return 0.0;
        }
        let addressed = q.iter().filter(|w| a.contains(*w)).count() as f64 / q.len() as f64;
        // Precision guard: of the answer's content words, how many are on-question? An answer that is
        // almost entirely off-topic is penalized even if it name-drops every question term.
        let on_topic = a.iter().filter(|w| q.contains(*w)).count() as f64 / a.len() as f64;
        // Harmonic-ish blend weighted toward coverage (F-measure with β favoring recall of the Q).
        if addressed == 0.0 {
            return 0.0;
        }
        let beta2 = 4.0; // recall (coverage of the question) weighted 2× over precision
        (1.0 + beta2) * addressed * on_topic / (beta2 * on_topic + addressed).max(1e-9)
    }
}

/// One question/answer pair for answer-relevance scoring.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QaCase {
    pub question: String,
    pub answer: String,
}

/// Mean answer-relevance over a suite of QA pairs, scored by `judge`.
pub fn answer_relevance_mean(cases: &[QaCase], judge: &dyn RelevanceJudge) -> f64 {
    if cases.is_empty() {
        return 1.0;
    }
    cases
        .iter()
        .map(|c| judge.relevance(&c.question, &c.answer))
        .sum::<f64>()
        / cases.len() as f64
}

// ===========================================================================================
// Aggregate RAG report + gate
// ===========================================================================================

/// Aggregate RAG metrics over a suite of cases (means).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RagReport {
    pub n: usize,
    pub context_recall: f64,
    pub context_precision: f64,
    pub recall_at_k: f64,
    pub mrr: f64,
    pub k: usize,
    /// Mean answer-relevance (§6) — `None` when no QA pairs / relevance judge were supplied. Retrieval
    /// can be perfect while the generator answers the wrong question; this dimension catches that.
    #[serde(default)]
    pub answer_relevance: Option<f64>,
}

/// Compute the aggregate report over retrieval cases at cutoff `k` (retrieval dimensions only).
pub fn rag_report(cases: &[RetrievalCase], k: usize) -> RagReport {
    let n = cases.len();
    if n == 0 {
        return RagReport {
            n: 0,
            context_recall: 0.0,
            context_precision: 0.0,
            recall_at_k: 0.0,
            mrr: 0.0,
            k,
            answer_relevance: None,
        };
    }
    let nf = n as f64;
    RagReport {
        n,
        context_recall: cases.iter().map(context_recall).sum::<f64>() / nf,
        context_precision: cases.iter().map(context_precision).sum::<f64>() / nf,
        recall_at_k: cases.iter().map(|c| recall_at_k(c, k)).sum::<f64>() / nf,
        mrr: cases.iter().map(mrr).sum::<f64>() / nf,
        k,
        answer_relevance: None,
    }
}

/// The full RAG report including the generation-side **answer-relevance** dimension (§6): retrieval
/// metrics over `cases` plus mean answer-relevance over the aligned QA pairs, scored by `judge`.
pub fn rag_report_with_relevance(
    cases: &[RetrievalCase],
    qa: &[QaCase],
    k: usize,
    judge: &dyn RelevanceJudge,
) -> RagReport {
    let mut r = rag_report(cases, k);
    r.answer_relevance = Some(answer_relevance_mean(qa, judge));
    r
}

// ===========================================================================================
// Embedding-migration gate (gap AN)
// ===========================================================================================

/// Verdict from the embedding-migration gate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum MigrationVerdict {
    /// Every chunk is on the target embedding version AND context recall did not regress.
    Complete,
    /// The index is partly migrated (mixed embedding versions) — a silent-degradation trap.
    MixedVersions {
        target: String,
        stale_count: usize,
        total: usize,
    },
    /// Fully migrated but context recall regressed beyond the margin — the new embedding is worse.
    RecallRegressed {
        baseline_recall: f64,
        candidate_recall: f64,
        margin: f64,
    },
}

impl MigrationVerdict {
    pub fn is_complete(&self) -> bool {
        matches!(self, MigrationVerdict::Complete)
    }
}

/// Gate an embedding-model migration. `chunk_versions` are the embedding-model-version tags of every
/// chunk in the index; `target` is the version being migrated to. A mixed-version index is caught
/// **before** production as a defect, not discovered as a recall drop later; a fully-migrated index
/// still must not regress context recall by more than `recall_margin`.
pub fn embedding_migration_gate(
    chunk_versions: &[String],
    target: &str,
    baseline_recall: f64,
    candidate_recall: f64,
    recall_margin: f64,
) -> MigrationVerdict {
    let total = chunk_versions.len();
    let stale = chunk_versions
        .iter()
        .filter(|v| v.as_str() != target)
        .count();
    if stale > 0 {
        return MigrationVerdict::MixedVersions {
            target: target.to_string(),
            stale_count: stale,
            total,
        };
    }
    if candidate_recall + recall_margin < baseline_recall {
        return MigrationVerdict::RecallRegressed {
            baseline_recall,
            candidate_recall,
            margin: recall_margin,
        };
    }
    MigrationVerdict::Complete
}

// ===========================================================================================
// Global / sensemaking (map-reduce) mode — its OWN eval set (EVAL_PLATFORM.md §6)
// ===========================================================================================
//
// Global/sensemaking queries ("what are the themes across all incident postmortems?") are answered by
// a map-reduce over community summaries, NOT by top-k retrieval — so recall@k/MRR do not apply. A
// sparse corpus can yield noisy/spurious communities, so this mode is gated by a DIFFERENT eval set
// with its own metrics: community coverage (did the answer represent the communities it should?),
// spurious-community rate (did map-reduce invent themes not supported by any real community?), and
// claim-attribution (is every synthesized theme traceable to a source community?).

/// One global/sensemaking case: the communities the corpus actually contains (`gold_communities`), the
/// communities the answer represented (`answer_communities`), and the answer's synthesized theme claims
/// each tagged with the community id it was attributed to (empty string = unattributed).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SensemakingCase {
    pub gold_communities: Vec<String>,
    pub answer_communities: Vec<String>,
    /// (theme_claim, attributed_community_id) — an id absent from `gold_communities` is spurious.
    pub attributed_claims: Vec<(String, String)>,
}

impl SensemakingCase {
    /// Community coverage: fraction of the real communities the answer represented (a global answer
    /// that misses whole themes is incomplete).
    pub fn community_coverage(&self) -> f64 {
        if self.gold_communities.is_empty() {
            return 1.0;
        }
        let ans: BTreeSet<&String> = self.answer_communities.iter().collect();
        let hit = self
            .gold_communities
            .iter()
            .filter(|c| ans.contains(c))
            .count();
        hit as f64 / self.gold_communities.len() as f64
    }

    /// Spurious-community rate: fraction of the answer's theme claims attributed to a community that
    /// does NOT exist in the corpus (map-reduce hallucinated a theme). Unattributed claims count as
    /// spurious (an unsourced global theme is exactly the sparse-corpus noise this set guards).
    pub fn spurious_rate(&self) -> f64 {
        if self.attributed_claims.is_empty() {
            return 0.0;
        }
        let gold: BTreeSet<&String> = self.gold_communities.iter().collect();
        let spurious = self
            .attributed_claims
            .iter()
            .filter(|(_, cid)| cid.is_empty() || !gold.contains(cid))
            .count();
        spurious as f64 / self.attributed_claims.len() as f64
    }
}

/// Aggregate global/sensemaking report — a distinct gate from [`RagReport`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SensemakingReport {
    pub n: usize,
    pub community_coverage: f64,
    pub spurious_rate: f64,
}

impl SensemakingReport {
    /// The sensemaking gate: coverage must clear `min_coverage` AND spurious-community rate must stay
    /// at/below `max_spurious`. A noisy-community regression on a sparse corpus blocks here even when
    /// ordinary retrieval evals are green.
    pub fn passes(&self, min_coverage: f64, max_spurious: f64) -> bool {
        self.community_coverage >= min_coverage && self.spurious_rate <= max_spurious
    }
}

/// Compute the aggregate sensemaking report over a suite of global-mode cases.
pub fn sensemaking_report(cases: &[SensemakingCase]) -> SensemakingReport {
    let n = cases.len();
    if n == 0 {
        return SensemakingReport {
            n: 0,
            community_coverage: 1.0,
            spurious_rate: 0.0,
        };
    }
    let nf = n as f64;
    SensemakingReport {
        n,
        community_coverage: cases.iter().map(|c| c.community_coverage()).sum::<f64>() / nf,
        spurious_rate: cases.iter().map(|c| c.spurious_rate()).sum::<f64>() / nf,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn recall_precision_mrr_ap_are_correct() {
        // relevant = {a, c}; retrieved = [a, x, c, y]
        let case = RetrievalCase {
            retrieved: ids(&["a", "x", "c", "y"]),
            relevant: ids(&["a", "c"]),
        };
        assert!(
            (context_recall(&case) - 1.0).abs() < 1e-9,
            "both relevant retrieved"
        );
        assert!(
            (recall_at_k(&case, 2) - 0.5).abs() < 1e-9,
            "only 'a' in top-2"
        );
        assert!((mrr(&case) - 1.0).abs() < 1e-9, "first item is relevant");
        // AP = (1/1 + 2/3)/2 = 0.8333
        assert!((average_precision(&case) - 0.833_333).abs() < 1e-4, "AP");
    }

    #[test]
    fn recall_drops_when_evidence_missing() {
        let good = RetrievalCase {
            retrieved: ids(&["a", "b", "c"]),
            relevant: ids(&["a", "c"]),
        };
        let bad = RetrievalCase {
            retrieved: ids(&["x", "y", "z"]),
            relevant: ids(&["a", "c"]),
        };
        assert!(context_recall(&good) > context_recall(&bad));
        assert!(
            (context_recall(&bad)).abs() < 1e-9,
            "no relevant retrieved → 0 recall"
        );
        assert!((mrr(&bad)).abs() < 1e-9);
    }

    #[test]
    fn claim_groundedness_localizes_hallucination() {
        let context = vec![
            "Payment settlement runs on a T+1 net settlement cycle for member banks.".to_string(),
        ];
        // Two claims: one grounded, one hallucinated.
        let answer = "Settlement runs on a T+1 net settlement cycle. Interplanetary teleportation \
                      schedules govern the flux capacitor.";
        let g = claim_groundedness(answer, &context, &LexicalGroundedness, 0.5);
        assert!(
            (g - 0.5).abs() < 1e-9,
            "exactly one of two claims grounded: {g}"
        );
        // Fully grounded answer.
        let grounded = "Settlement runs on a T+1 net settlement cycle for member banks.";
        assert!(
            (claim_groundedness(grounded, &context, &LexicalGroundedness, 0.5) - 1.0).abs() < 1e-9
        );
    }

    #[test]
    fn citation_span_faithfulness_catches_wrong_but_real_citation() {
        let cited = vec![
            // faithful: the cited span supports the claim.
            CitedClaim {
                claim: "settlement uses a T+1 cycle".into(),
                cited_source: "the settlement process uses a T+1 cycle for member banks".into(),
            },
            // unfaithful: real source, but it doesn't say what the claim says.
            CitedClaim {
                claim: "the CVV rotates every settlement window".into(),
                cited_source: "UPI is the unified payments interface for retail transfers".into(),
            },
        ];
        let f = citation_span_faithfulness(&cited, 0.5);
        assert!(
            (f - 0.5).abs() < 1e-9,
            "one of two citations is faithful: {f}"
        );
    }

    #[test]
    fn rag_report_aggregates() {
        let cases = vec![
            RetrievalCase {
                retrieved: ids(&["a", "b"]),
                relevant: ids(&["a"]),
            },
            RetrievalCase {
                retrieved: ids(&["x", "c"]),
                relevant: ids(&["c"]),
            },
        ];
        let r = rag_report(&cases, 2);
        assert_eq!(r.n, 2);
        assert!((r.context_recall - 1.0).abs() < 1e-9);
        // MRR: case1 rank1=1.0, case2 rank2=0.5 → mean 0.75
        assert!((r.mrr - 0.75).abs() < 1e-9);
    }

    #[test]
    fn gap_ainxt_eval_05_answer_relevance_scores_addressing_the_question() {
        let j = LexicalRelevance;
        let q = "when does payment settlement run for member banks";
        // On-topic answer → high relevance.
        let good = "Payment settlement runs on a T+1 cycle for member banks each day";
        // Perfectly-fluent but OFF-question answer (grounded elsewhere) → low relevance.
        let off = "The weather forecast predicts rain across the coastal districts tomorrow";
        let rg = j.relevance(q, good);
        let ro = j.relevance(q, off);
        assert!(rg > 0.6, "an on-question answer scores high: {rg}");
        assert!(ro < 0.2, "an off-question answer scores low: {ro}");
        assert!(rg > ro);
        // Wired into the RAG report as its own dimension.
        let cases = vec![RetrievalCase {
            retrieved: ids(&["a"]),
            relevant: ids(&["a"]),
        }];
        let qa = vec![
            QaCase {
                question: q.into(),
                answer: good.into(),
            },
            QaCase {
                question: q.into(),
                answer: off.into(),
            },
        ];
        let r = rag_report_with_relevance(&cases, &qa, 5, &j);
        assert!(r.answer_relevance.is_some());
        assert!(
            r.answer_relevance.unwrap() < rg,
            "the mean drags in the off-topic answer"
        );
        // The plain report leaves the dimension unset.
        assert!(rag_report(&cases, 5).answer_relevance.is_none());
    }

    #[test]
    fn gap_ainxt_eval_07_sensemaking_has_its_own_eval_set() {
        // A good global answer: covers every real community, no invented themes.
        let good = SensemakingCase {
            gold_communities: ids(&["fraud", "latency", "settlement"]),
            answer_communities: ids(&["fraud", "latency", "settlement"]),
            attributed_claims: vec![
                ("fraud rings rose".into(), "fraud".into()),
                ("latency spiked".into(), "latency".into()),
            ],
        };
        assert!((good.community_coverage() - 1.0).abs() < 1e-9);
        assert!(good.spurious_rate().abs() < 1e-9);

        // A noisy map-reduce on a sparse corpus: misses a theme AND invents one.
        let noisy = SensemakingCase {
            gold_communities: ids(&["fraud", "latency", "settlement"]),
            answer_communities: ids(&["fraud"]), // missed latency + settlement
            attributed_claims: vec![
                ("fraud rings rose".into(), "fraud".into()),
                ("aliens caused the outage".into(), "ufo".into()), // spurious community
                ("unsourced theme".into(), "".into()),             // unattributed
            ],
        };
        assert!(
            noisy.community_coverage() < 0.5,
            "missed themes lower coverage"
        );
        assert!(
            noisy.spurious_rate() > 0.5,
            "invented/unsourced themes are spurious"
        );

        let report = sensemaking_report(&[good.clone(), noisy.clone()]);
        assert_eq!(report.n, 2);
        // The all-good corpus passes; the mixed corpus (with the noisy case) fails the sensemaking
        // gate even though a top-k retrieval eval would say nothing about it.
        assert!(sensemaking_report(&[good]).passes(0.9, 0.1));
        assert!(
            !report.passes(0.9, 0.1),
            "noisy communities block the global-mode gate"
        );
        let j = serde_json::to_string(&report).unwrap();
        let back: SensemakingReport = serde_json::from_str(&j).unwrap();
        assert_eq!(back, report);
    }

    #[test]
    fn migration_gate_blocks_mixed_versions() {
        // Half-migrated index → MixedVersions.
        let mixed = ids(&["v2", "v2", "v1", "v2"]);
        let v = embedding_migration_gate(&mixed, "v2", 0.9, 0.9, 0.02);
        assert!(
            matches!(v, MigrationVerdict::MixedVersions { stale_count: 1, .. }),
            "{v:?}"
        );

        // Fully migrated but recall regressed → RecallRegressed.
        let full = ids(&["v2", "v2", "v2"]);
        let v2 = embedding_migration_gate(&full, "v2", 0.90, 0.80, 0.02);
        assert!(
            matches!(v2, MigrationVerdict::RecallRegressed { .. }),
            "{v2:?}"
        );

        // Fully migrated, recall held → Complete.
        let v3 = embedding_migration_gate(&full, "v2", 0.90, 0.895, 0.02);
        assert!(v3.is_complete(), "{v3:?}");
    }
}
