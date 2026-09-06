// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! ainxt-quality — answer **QUALITY** as a measured dimension (gaps **BF/BT**), plus online
//! quality-**DRIFT** detection.
//!
//! Correctness ("is the answer right?") and quality ("is it complete, well-formatted, right-sized,
//! grounded, cited, and on-tone?") are *different axes*. The eval keystone ([`ainxt_eval`]) gates
//! correctness at release; this crate measures the quality axis — both as an input to that gate and,
//! critically, as a **continuous production monitor** that catches quality *eroding after release*
//! (a provider silently swaps a model, the retrieval mix shifts, usage drifts off-distribution).
//! That online monitor is deliberately distinct from the release GATE in `ainxt-eval`.
//!
//! Four pieces, all pure and deterministic (no clock, no RNG — callers pass any ordering/sequence in):
//!
//! 1. **Dimensions** ([`QualityDimension`]). Each is a real heuristic over the answer text and its
//!    [`AnswerContext`], producing a 0–100 [`DimensionScore`] with a rationale — never a constant:
//!    - [`Completeness`] — coverage of the required points the answer had to address.
//!    - [`FormatValidity`] — does the text actually conform to the declared [`Format`]
//!      (balanced JSON, balanced code fences, real bullet/table structure, non-truncated prose).
//!    - [`VerbosityFit`] — is the length inside the target band; how far outside if not.
//!    - [`CitationPresence`] — are claims cited when sources exist, and are the citation markers
//!      *real* (in-range) rather than fabricated references to sources that don't exist.
//!    - [`Groundedness`] — what fraction of the answer's content words are supported by the sources
//!      (a lexical hallucination proxy; the semantic LLM-judge plugs in behind the same shape).
//!    - [`ToneConsistency`] — hedging / apology-fluff / shouting penalties, stricter on
//!      regulated-payment answers.
//!
//! 2. **Profile** ([`QualityProfile`] via [`QualityAssessor`]). Aggregates dimension scores into an
//!    overall using configurable [`QualityWeights`] (defaults are uniform; a deployment can weight
//!    Groundedness or CitationPresence higher for RAG surfaces).
//!
//! 3. **Drift** ([`detect_drift`]). Given an *ordered* series of profiles split into a baseline window
//!    and a recent window, it flags any dimension (and the overall) whose recent mean dropped below
//!    the baseline mean by more than a margin **and** by more than a two-sample standard-error
//!    threshold — a real change-point test, not a single-noisy-sample tripwire. It names every
//!    regressed dimension, and is honest ([`DriftVerdict::Inconclusive`]) when a window is too small
//!    to power the test.
//!
//! 4. **Eval bridge** ([`DimensionJudge`], [`ProfileJudge`]). Adapters implementing
//!    [`ainxt_eval::QualityJudge`] so a single quality dimension — or the aggregate profile — can be
//!    dropped in as the judge behind the `ainxt-eval` release gate.
//!
//! Clean-room; deterministic; every dimension is exercised on a passing and a failing input in the
//! test module so the heuristics cannot be silently gutted.

use ainxt_eval::{EvalCriteria, QualityJudge as EvalQualityJudge, QualityScore};
use ainxt_types::DataClass;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub mod controller;
pub mod feed;
pub mod monitor;

// ===========================================================================================
// Answer + context under evaluation
// ===========================================================================================

/// The declared shape an answer was asked to produce. [`FormatValidity`] checks conformance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Format {
    /// Plain prose. Valid = balanced code fences and a non-truncated ending.
    Prose,
    /// Markdown. Valid = balanced code fences and link brackets.
    Markdown,
    /// A bulleted list. Valid = the bulk of non-empty lines are bullet items.
    BulletList,
    /// A markdown table. Valid = a header separator row and multiple piped rows.
    Table,
    /// A JSON document. Valid = structurally balanced braces/brackets/strings.
    Json,
}

/// A target length band, in words, for [`VerbosityFit`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LengthBand {
    pub min_words: usize,
    pub max_words: usize,
}

impl LengthBand {
    pub fn new(min_words: usize, max_words: usize) -> Self {
        LengthBand {
            min_words,
            max_words,
        }
    }
    /// A one-liner / short factual answer.
    pub fn brief() -> Self {
        LengthBand {
            min_words: 8,
            max_words: 60,
        }
    }
    /// A normal explanatory answer.
    pub fn standard() -> Self {
        LengthBand {
            min_words: 40,
            max_words: 200,
        }
    }
    /// A long, detailed answer.
    pub fn detailed() -> Self {
        LengthBand {
            min_words: 150,
            max_words: 600,
        }
    }
}

/// Everything a dimension needs about an answer *besides the answer text itself*.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnswerContext {
    /// The user's question / instruction the answer responds to.
    pub question: String,
    /// Retrieved source passages the answer is expected to be grounded in. Empty = no context was
    /// available (an ungrounded, uncitable answer by construction).
    pub sources: Vec<String>,
    /// Key points/aspects the answer had to cover, each a phrase matched case-insensitively.
    pub required_points: Vec<String>,
    /// The format the answer was asked to produce.
    pub expected_format: Format,
    /// The target length band.
    pub target_len: LengthBand,
    /// Sensitivity of the answer. Regulated/PII answers are held to a stricter tone bar.
    pub data_class: DataClass,
}

impl AnswerContext {
    /// A minimal context: no sources, no required points, prose, standard length, internal class.
    pub fn plain(question: &str) -> Self {
        AnswerContext {
            question: question.to_string(),
            sources: Vec::new(),
            required_points: Vec::new(),
            expected_format: Format::Prose,
            target_len: LengthBand::standard(),
            data_class: DataClass::Internal,
        }
    }
}

/// An answer plus the context needed to score it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluableAnswer {
    pub answer: String,
    pub context: AnswerContext,
}

impl EvaluableAnswer {
    pub fn new(answer: &str, context: AnswerContext) -> Self {
        EvaluableAnswer {
            answer: answer.to_string(),
            context,
        }
    }
}

// ===========================================================================================
// Dimension trait + score
// ===========================================================================================

/// One dimension's verdict on one answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DimensionScore {
    pub dimension: String,
    /// 0–100. Higher is better.
    pub score: u8,
    pub rationale: String,
}

/// A quality dimension: a named, deterministic heuristic mapping an answer to a 0–100 score with a
/// rationale. The semantic LLM-judge for a dimension (e.g. holistic groundedness) implements the same
/// shape and swaps in without changing callers.
pub trait QualityDimension: Send + Sync {
    /// Stable identifier, used as the weight/drift key. Must be constant per dimension type.
    fn name(&self) -> &'static str;
    fn score(&self, answer: &EvaluableAnswer) -> DimensionScore;
}

// ===========================================================================================
// Text helpers (shared by dimensions)
// ===========================================================================================

const STOPWORDS: &[&str] = &[
    "the", "a", "an", "and", "or", "but", "of", "to", "in", "on", "for", "is", "are", "was",
    "were", "be", "by", "with", "as", "at", "it", "this", "that", "these", "those", "from", "into",
    "than", "then", "so", "such", "not", "no", "if", "we", "you", "i", "he", "she", "they", "its",
    "their", "our", "your", "will", "can", "may", "should", "would", "could", "which", "what",
    "when", "where", "who", "how", "about", "up", "out", "over", "under", "also", "there", "here",
    "have", "has", "had", "do", "does", "did", "been", "being",
];

/// Lowercased alphanumeric tokens.
fn tokens(s: &str) -> Vec<String> {
    s.split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
        .map(|t| t.to_lowercase())
        .collect()
}

/// Deduped content words (len >= 3, non-stopword).
fn content_words(s: &str) -> BTreeSet<String> {
    tokens(s)
        .into_iter()
        .filter(|t| t.len() >= 3 && !STOPWORDS.contains(&t.as_str()))
        .collect()
}

/// Word count (whitespace-separated tokens containing at least one alphanumeric char).
fn word_count(s: &str) -> usize {
    s.split_whitespace()
        .filter(|w| w.chars().any(|c| c.is_alphanumeric()))
        .count()
}

/// Distinct citation markers of the form `[<digits>]`, in ascending order.
fn citation_markers(s: &str) -> Vec<u32> {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'[' {
            let start = i + 1;
            let mut j = start;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                j += 1;
            }
            if j > start && j < bytes.len() && bytes[j] == b']' {
                if let Ok(n) = s[start..j].parse::<u32>() {
                    out.push(n);
                }
                i = j + 1;
                continue;
            }
        }
        i += 1;
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// Structural JSON balance: braces/brackets/strings balanced, string contents ignored.
fn json_balanced(s: &str) -> bool {
    let mut curly = 0i32;
    let mut square = 0i32;
    let mut in_str = false;
    let mut esc = false;
    let mut saw_any = false;
    for c in s.chars() {
        if in_str {
            if esc {
                esc = false;
            } else if c == '\\' {
                esc = true;
            } else if c == '"' {
                in_str = false;
            }
            continue;
        }
        match c {
            '"' => in_str = true,
            '{' => {
                curly += 1;
                saw_any = true;
            }
            '}' => {
                curly -= 1;
                if curly < 0 {
                    return false;
                }
            }
            '[' => {
                square += 1;
                saw_any = true;
            }
            ']' => {
                square -= 1;
                if square < 0 {
                    return false;
                }
            }
            _ => {}
        }
    }
    saw_any && !in_str && curly == 0 && square == 0
}

fn clamp_score(x: f64) -> u8 {
    if x <= 0.0 {
        0
    } else if x >= 100.0 {
        100
    } else {
        x.round() as u8
    }
}

fn non_empty_lines(s: &str) -> Vec<&str> {
    s.lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .collect()
}

fn is_bullet(line: &str) -> bool {
    let l = line.trim_start();
    l.starts_with("- ") || l.starts_with("* ") || l.starts_with("+ ") || l.starts_with("• ") || {
        // "1." / "12)" ordered markers
        let digits: String = l.chars().take_while(|c| c.is_ascii_digit()).collect();
        !digits.is_empty()
            && (l[digits.len()..].starts_with('.') || l[digits.len()..].starts_with(')'))
    }
}

// ===========================================================================================
// Concrete dimensions
// ===========================================================================================

/// Coverage of the required points the answer had to address.
#[derive(Debug, Clone, Copy, Default)]
pub struct Completeness;

impl QualityDimension for Completeness {
    fn name(&self) -> &'static str {
        "completeness"
    }
    fn score(&self, answer: &EvaluableAnswer) -> DimensionScore {
        let pts = &answer.context.required_points;
        if pts.is_empty() {
            return DimensionScore {
                dimension: self.name().into(),
                score: 100,
                rationale: "no required points declared; nothing to omit".into(),
            };
        }
        let hay = answer.answer.to_lowercase();
        let mut missing = Vec::new();
        let mut covered = 0usize;
        for p in pts {
            let needle = p.trim().to_lowercase();
            if !needle.is_empty() && hay.contains(&needle) {
                covered += 1;
            } else {
                missing.push(p.clone());
            }
        }
        let score = clamp_score(covered as f64 * 100.0 / pts.len() as f64);
        let rationale = if missing.is_empty() {
            format!("all {} required point(s) covered", pts.len())
        } else {
            format!(
                "covered {}/{}, missing: {}",
                covered,
                pts.len(),
                missing.join(", ")
            )
        };
        DimensionScore {
            dimension: self.name().into(),
            score,
            rationale,
        }
    }
}

/// Does the answer actually conform to the declared [`Format`]?
#[derive(Debug, Clone, Copy, Default)]
pub struct FormatValidity;

impl FormatValidity {
    fn score_prose(a: &str) -> (u8, String) {
        if a.trim().is_empty() {
            return (0, "empty prose".into());
        }
        let mut score = 100.0;
        let mut notes = Vec::new();
        if a.matches("```").count() % 2 == 1 {
            score -= 40.0;
            notes.push("unbalanced code fence");
        }
        let last = a.trim_end().chars().last().unwrap_or(' ');
        if !matches!(last, '.' | '!' | '?' | '"' | ')' | ']' | '”') {
            score -= 20.0;
            notes.push("truncated / no terminal punctuation");
        }
        let note = if notes.is_empty() {
            "well-formed prose".into()
        } else {
            notes.join("; ")
        };
        (clamp_score(score), note)
    }

    fn score_markdown(a: &str) -> (u8, String) {
        if a.trim().is_empty() {
            return (0, "empty markdown".into());
        }
        let mut score = 100.0;
        let mut notes = Vec::new();
        if a.matches("```").count() % 2 == 1 {
            score -= 60.0;
            notes.push("unbalanced code fence");
        }
        let open = a.matches('[').count();
        let close = a.matches(']').count();
        if open != close {
            score -= 20.0;
            notes.push("unbalanced link brackets");
        }
        let note = if notes.is_empty() {
            "well-formed markdown".into()
        } else {
            notes.join("; ")
        };
        (clamp_score(score), note)
    }

    fn score_bullets(a: &str) -> (u8, String) {
        let lines = non_empty_lines(a);
        if lines.is_empty() {
            return (0, "empty; no bullet items".into());
        }
        let bullets = lines.iter().filter(|&&l| is_bullet(l)).count();
        if bullets < 2 {
            return (
                clamp_score(bullets as f64 * 30.0),
                format!("only {bullets} bullet item(s); not a list"),
            );
        }
        let score = clamp_score(bullets as f64 * 100.0 / lines.len() as f64);
        (
            score,
            format!("{bullets}/{} lines are bullet items", lines.len()),
        )
    }

    fn score_table(a: &str) -> (u8, String) {
        let lines = non_empty_lines(a);
        let piped: Vec<&&str> = lines.iter().filter(|l| l.contains('|')).collect();
        let has_sep = lines.iter().any(|l| {
            l.contains('|')
                && l.contains('-')
                && l.chars().all(|c| matches!(c, '|' | '-' | ':' | ' '))
        });
        if has_sep && piped.len() >= 2 {
            (
                100,
                format!("header separator + {} piped row(s)", piped.len()),
            )
        } else if !piped.is_empty() {
            (40, "pipes present but no valid header separator row".into())
        } else {
            (0, "no table structure".into())
        }
    }

    fn score_json(a: &str) -> (u8, String) {
        if a.trim().is_empty() {
            return (0, "empty JSON".into());
        }
        if json_balanced(a) {
            (100, "structurally balanced JSON".into())
        } else {
            let has_json_chars = a.contains('{') || a.contains('[');
            if has_json_chars {
                (
                    35,
                    "JSON delimiters present but unbalanced/unterminated".into(),
                )
            } else {
                (0, "no JSON structure".into())
            }
        }
    }
}

impl QualityDimension for FormatValidity {
    fn name(&self) -> &'static str {
        "format_validity"
    }
    fn score(&self, answer: &EvaluableAnswer) -> DimensionScore {
        let (score, rationale) = match answer.context.expected_format {
            Format::Prose => Self::score_prose(&answer.answer),
            Format::Markdown => Self::score_markdown(&answer.answer),
            Format::BulletList => Self::score_bullets(&answer.answer),
            Format::Table => Self::score_table(&answer.answer),
            Format::Json => Self::score_json(&answer.answer),
        };
        DimensionScore {
            dimension: self.name().into(),
            score,
            rationale,
        }
    }
}

/// Is the answer's length inside the target band; how far outside if not?
#[derive(Debug, Clone, Copy, Default)]
pub struct VerbosityFit;

impl QualityDimension for VerbosityFit {
    fn name(&self) -> &'static str {
        "verbosity_fit"
    }
    fn score(&self, answer: &EvaluableAnswer) -> DimensionScore {
        let n = word_count(&answer.answer);
        let band = answer.context.target_len;
        let (score, rationale) = if n >= band.min_words && n <= band.max_words {
            (
                100u8,
                format!("{n} words within [{}, {}]", band.min_words, band.max_words),
            )
        } else if n < band.min_words {
            let s = if band.min_words == 0 {
                100.0
            } else {
                n as f64 * 100.0 / band.min_words as f64
            };
            (
                clamp_score(s),
                format!("{n} words below minimum {} (too terse)", band.min_words),
            )
        } else {
            let s = if n == 0 {
                0.0
            } else {
                band.max_words as f64 * 100.0 / n as f64
            };
            (
                clamp_score(s),
                format!("{n} words above maximum {} (too verbose)", band.max_words),
            )
        };
        DimensionScore {
            dimension: self.name().into(),
            score,
            rationale,
        }
    }
}

/// Are claims cited when sources exist, and are the citation markers real (in range)?
#[derive(Debug, Clone, Copy, Default)]
pub struct CitationPresence;

impl QualityDimension for CitationPresence {
    fn name(&self) -> &'static str {
        "citation_presence"
    }
    fn score(&self, answer: &EvaluableAnswer) -> DimensionScore {
        let markers = citation_markers(&answer.answer);
        let n_sources = answer.context.sources.len();

        if n_sources == 0 {
            // Nothing to cite. Correct behaviour = no markers; fabricated markers are penalised.
            return if markers.is_empty() {
                DimensionScore {
                    dimension: self.name().into(),
                    score: 100,
                    rationale: "no sources available; correctly uncited".into(),
                }
            } else {
                DimensionScore {
                    dimension: self.name().into(),
                    score: clamp_score(100.0 - markers.len() as f64 * 30.0),
                    rationale: format!(
                        "{} citation marker(s) but no sources — fabricated references",
                        markers.len()
                    ),
                }
            };
        }

        if markers.is_empty() {
            return DimensionScore {
                dimension: self.name().into(),
                score: 0,
                rationale: format!("{n_sources} source(s) available but answer is uncited"),
            };
        }

        let valid = markers
            .iter()
            .filter(|&&m| m >= 1 && (m as usize) <= n_sources)
            .count();
        let invalid = markers.len() - valid;
        let base = valid as f64 * 100.0 / n_sources as f64;
        let score = clamp_score(base - invalid as f64 * 20.0);
        let rationale = if invalid == 0 {
            format!("{valid}/{n_sources} source(s) cited")
        } else {
            format!("{valid} valid cite(s), {invalid} out-of-range (fabricated) marker(s)")
        };
        DimensionScore {
            dimension: self.name().into(),
            score,
            rationale,
        }
    }
}

/// What fraction of the answer's content words are supported by the sources? A lexical hallucination
/// proxy: an answer asserting content absent from every source is ungrounded. With no sources, an
/// answer that makes content claims is ungrounded by construction.
#[derive(Debug, Clone, Copy, Default)]
pub struct Groundedness;

impl QualityDimension for Groundedness {
    fn name(&self) -> &'static str {
        "groundedness"
    }
    fn score(&self, answer: &EvaluableAnswer) -> DimensionScore {
        let claim = content_words(&answer.answer);
        if claim.is_empty() {
            return DimensionScore {
                dimension: self.name().into(),
                score: 100,
                rationale: "no content-bearing claims to support".into(),
            };
        }
        let mut support: BTreeSet<String> = BTreeSet::new();
        for src in &answer.context.sources {
            support.extend(content_words(src));
        }
        let supported = claim.iter().filter(|w| support.contains(*w)).count();
        let unsupported: Vec<&String> = claim.iter().filter(|w| !support.contains(*w)).collect();
        let score = clamp_score(supported as f64 * 100.0 / claim.len() as f64);
        let sample: Vec<String> = unsupported.iter().take(5).map(|s| (*s).clone()).collect();
        let rationale = if unsupported.is_empty() {
            format!("all {} content term(s) supported by sources", claim.len())
        } else if answer.context.sources.is_empty() {
            format!("no sources; {} content term(s) unsupported", claim.len())
        } else {
            format!(
                "{}/{} content term(s) supported; unsupported e.g.: {}",
                supported,
                claim.len(),
                sample.join(", ")
            )
        };
        DimensionScore {
            dimension: self.name().into(),
            score,
            rationale,
        }
    }
}

/// Professional-tone penalties: hedging, apology fluff, shouting, filler. Stricter on
/// regulated-payment answers.
#[derive(Debug, Clone, Copy, Default)]
pub struct ToneConsistency;

const HEDGES: &[&str] = &[
    "maybe",
    "perhaps",
    "probably",
    "i think",
    "i guess",
    "i believe",
    "sort of",
    "kind of",
    "possibly",
    "not sure",
];
const APOLOGIES: &[&str] = &["sorry", "apolog", "unfortunately", "regret", "my bad"];
const FILLER: &[&str] = &["basically", "actually", "literally", "honestly"];

impl QualityDimension for ToneConsistency {
    fn name(&self) -> &'static str {
        "tone_consistency"
    }
    fn score(&self, answer: &EvaluableAnswer) -> DimensionScore {
        let lc = answer.answer.to_lowercase();
        let count =
            |phrases: &[&str]| -> usize { phrases.iter().map(|p| lc.matches(p).count()).sum() };
        let hedges = count(HEDGES);
        let apologies = count(APOLOGIES);
        let filler = count(FILLER);
        let exclaim = answer.answer.matches('!').count();
        let shouting = answer
            .answer
            .split_whitespace()
            .filter(|w| {
                let core: String = w.chars().filter(|c| c.is_alphabetic()).collect();
                core.len() >= 4 && core.chars().all(|c| c.is_uppercase())
            })
            .count();

        let mut penalty = hedges as f64 * 8.0
            + apologies as f64 * 10.0
            + filler as f64 * 3.0
            + exclaim as f64 * 5.0
            + shouting as f64 * 6.0;
        if answer.context.data_class.is_regulated() {
            penalty *= 1.5;
        }
        let score = clamp_score(100.0 - penalty);
        let rationale = if penalty == 0.0 {
            "professional tone; no hedging/apology/shouting".into()
        } else {
            format!(
                "penalised: {hedges} hedge(s), {apologies} apolog(y/ies), {filler} filler, {exclaim} '!', {shouting} shouted word(s){}",
                if answer.context.data_class.is_regulated() { " (regulated: 1.5x)" } else { "" }
            )
        };
        DimensionScore {
            dimension: self.name().into(),
            score,
            rationale,
        }
    }
}

// ===========================================================================================
// Weights + profile + assessor
// ===========================================================================================

/// Per-dimension weights for aggregating into an overall. Dimensions without an explicit entry use
/// `default_weight`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QualityWeights {
    weights: Vec<(String, f64)>,
    default_weight: f64,
}

impl QualityWeights {
    /// Uniform weighting: every dimension counts equally.
    pub fn uniform() -> Self {
        QualityWeights {
            weights: Vec::new(),
            default_weight: 1.0,
        }
    }

    /// Explicit weights (non-negative); unlisted dimensions get `default_weight`. Negative weights
    /// are clamped to 0 so a weight can never invert the aggregate.
    pub fn new(weights: &[(&str, f64)], default_weight: f64) -> Self {
        QualityWeights {
            weights: weights
                .iter()
                .map(|(k, w)| ((*k).to_string(), w.max(0.0)))
                .collect(),
            default_weight: default_weight.max(0.0),
        }
    }

    /// Weight for `name`, or `default_weight` if unlisted.
    pub fn weight_for(&self, name: &str) -> f64 {
        self.weights
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, w)| *w)
            .unwrap_or(self.default_weight)
    }

    /// Set/override one weight (builder style).
    pub fn with(mut self, name: &str, weight: f64) -> Self {
        let w = weight.max(0.0);
        if let Some(entry) = self.weights.iter_mut().find(|(k, _)| k == name) {
            entry.1 = w;
        } else {
            self.weights.push((name.to_string(), w));
        }
        self
    }
}

impl Default for QualityWeights {
    fn default() -> Self {
        Self::uniform()
    }
}

/// The scored quality of one answer across all dimensions, plus the weighted overall.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QualityProfile {
    pub dimensions: Vec<DimensionScore>,
    /// Weighted mean of the dimension scores (0–100).
    pub overall: u8,
}

impl QualityProfile {
    pub fn new(dimensions: Vec<DimensionScore>, overall: u8) -> Self {
        QualityProfile {
            dimensions,
            overall,
        }
    }
    /// The score for a named dimension, if present.
    pub fn dimension_score(&self, name: &str) -> Option<u8> {
        self.dimensions
            .iter()
            .find(|d| d.dimension == name)
            .map(|d| d.score)
    }
}

/// Runs a fixed set of dimensions with a fixed weighting to produce a [`QualityProfile`].
pub struct QualityAssessor {
    dimensions: Vec<Box<dyn QualityDimension>>,
    weights: QualityWeights,
}

impl QualityAssessor {
    pub fn new(dimensions: Vec<Box<dyn QualityDimension>>, weights: QualityWeights) -> Self {
        QualityAssessor {
            dimensions,
            weights,
        }
    }

    /// The standard six dimensions with the given weights.
    pub fn standard(weights: QualityWeights) -> Self {
        QualityAssessor {
            dimensions: vec![
                Box::new(Completeness),
                Box::new(FormatValidity),
                Box::new(VerbosityFit),
                Box::new(CitationPresence),
                Box::new(Groundedness),
                Box::new(ToneConsistency),
            ],
            weights,
        }
    }

    /// Assess one answer. If total weight is zero (all dimensions weighted out), the overall is 0 and
    /// the rationale on the profile reflects that no dimension counted.
    pub fn assess(&self, answer: &EvaluableAnswer) -> QualityProfile {
        let mut dims = Vec::with_capacity(self.dimensions.len());
        let mut wsum = 0.0f64;
        let mut acc = 0.0f64;
        for d in &self.dimensions {
            let ds = d.score(answer);
            let w = self.weights.weight_for(d.name());
            acc += w * ds.score as f64;
            wsum += w;
            dims.push(ds);
        }
        let overall = if wsum > 0.0 {
            clamp_score(acc / wsum)
        } else {
            0
        };
        QualityProfile {
            dimensions: dims,
            overall,
        }
    }
}

// ===========================================================================================
// Drift detection
// ===========================================================================================

/// Tuning for the drift monitor.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct DriftPolicy {
    /// Minimum samples required in *each* window; below this the result is [`DriftVerdict::Inconclusive`].
    pub min_window: usize,
    /// A drop (baseline mean − recent mean, in points) must exceed this to count at all.
    pub drop_margin: f64,
    /// …and must also exceed `z_threshold × standard-error-of-the-difference` — the change-point test
    /// that rejects noise. If both windows are perfectly stable (SE = 0), only `drop_margin` applies.
    pub z_threshold: f64,
}

impl Default for DriftPolicy {
    fn default() -> Self {
        DriftPolicy {
            min_window: 5,
            drop_margin: 5.0,
            z_threshold: 2.0,
        }
    }
}

/// One regressed dimension (or the overall).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DimensionDrift {
    pub dimension: String,
    pub baseline_mean: f64,
    pub recent_mean: f64,
    /// baseline_mean − recent_mean (positive = regression).
    pub drop: f64,
    /// Standard error of the difference of means.
    pub std_error: f64,
}

/// The drift monitor's verdict.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DriftVerdict {
    /// No dimension regressed meaningfully.
    Stable,
    /// One or more dimensions regressed, worst first.
    Regressed(Vec<DimensionDrift>),
    /// Not enough samples to power the test — carries the reason (honest cold-start).
    Inconclusive(String),
}

impl DriftVerdict {
    pub fn is_stable(&self) -> bool {
        matches!(self, DriftVerdict::Stable)
    }
    pub fn is_regressed(&self) -> bool {
        matches!(self, DriftVerdict::Regressed(_))
    }
    /// Names of the regressed dimensions, worst-first (empty unless [`DriftVerdict::Regressed`]).
    pub fn regressed_dimensions(&self) -> Vec<&str> {
        match self {
            DriftVerdict::Regressed(v) => v.iter().map(|d| d.dimension.as_str()).collect(),
            _ => Vec::new(),
        }
    }
}

/// Key used for the aggregate overall series in drift output.
pub const OVERALL_KEY: &str = "overall";

/// Sample mean and sample variance (n − 1). Requires `xs.len() >= 2`.
fn mean_and_var(xs: &[f64]) -> (f64, f64) {
    let n = xs.len() as f64;
    let mean = xs.iter().sum::<f64>() / n;
    let var = xs.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1.0);
    (mean, var)
}

fn series(profiles: &[QualityProfile], key: &str) -> Option<Vec<f64>> {
    let mut out = Vec::with_capacity(profiles.len());
    if key == OVERALL_KEY {
        for p in profiles {
            out.push(p.overall as f64);
        }
        return Some(out);
    }
    for p in profiles {
        // `?` returns None if the dimension is absent in any profile across the window.
        out.push(p.dimension_score(key)? as f64);
    }
    Some(out)
}

/// Detect a meaningful quality regression of `recent` vs `baseline`. Both are *ordered* windows of
/// profiles (baseline = earlier / known-good, recent = latest). Returns which dimension(s) regressed.
///
/// This is the ONLINE quality-drift monitor, distinct from `ainxt-eval`'s release GATE: the gate
/// blocks a *candidate* pre-release; this watches *production* quality erode over time.
pub fn detect_drift(
    baseline: &[QualityProfile],
    recent: &[QualityProfile],
    policy: &DriftPolicy,
) -> DriftVerdict {
    let min_w = policy.min_window.max(2); // need >= 2 for a sample variance
    if baseline.len() < min_w || recent.len() < min_w {
        return DriftVerdict::Inconclusive(format!(
            "windows too small: baseline={}, recent={}, need >= {} each",
            baseline.len(),
            recent.len(),
            min_w
        ));
    }

    // Candidate keys: the overall plus every dimension present in the first baseline profile.
    let mut keys: Vec<String> = vec![OVERALL_KEY.to_string()];
    if let Some(first) = baseline.first() {
        for d in &first.dimensions {
            keys.push(d.dimension.clone());
        }
    }

    let mut drifts = Vec::new();
    for key in &keys {
        let (base, rec) = match (series(baseline, key), series(recent, key)) {
            (Some(b), Some(r)) if b.len() >= 2 && r.len() >= 2 => (b, r),
            _ => continue,
        };
        let (bm, bv) = mean_and_var(&base);
        let (rm, rv) = mean_and_var(&rec);
        let drop = bm - rm;
        let se = (bv / base.len() as f64 + rv / rec.len() as f64).sqrt();
        let passes_margin = drop >= policy.drop_margin;
        let passes_significance = se == 0.0 || drop >= policy.z_threshold * se;
        if passes_margin && passes_significance {
            drifts.push(DimensionDrift {
                dimension: key.clone(),
                baseline_mean: bm,
                recent_mean: rm,
                drop,
                std_error: se,
            });
        }
    }

    if drifts.is_empty() {
        DriftVerdict::Stable
    } else {
        drifts.sort_by(|a, b| {
            b.drop
                .partial_cmp(&a.drop)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        DriftVerdict::Regressed(drifts)
    }
}

// ===========================================================================================
// Eval bridge — drive the ainxt-eval release GATE off a quality dimension / profile
// ===========================================================================================

/// Bridges a single [`QualityDimension`] into [`ainxt_eval::QualityJudge`], so the release gate can be
/// driven by that one dimension's score. `build` maps the eval seam (input, output, criteria) into an
/// [`EvaluableAnswer`] — supplying the context (sources, required points, format…) the dimension needs
/// but the eval signature doesn't carry.
pub struct DimensionJudge<F> {
    dimension: Box<dyn QualityDimension>,
    build: F,
}

impl<F> DimensionJudge<F>
where
    F: Fn(&str, &str, &EvalCriteria) -> EvaluableAnswer + Send + Sync,
{
    pub fn new(dimension: Box<dyn QualityDimension>, build: F) -> Self {
        DimensionJudge { dimension, build }
    }
}

impl<F> EvalQualityJudge for DimensionJudge<F>
where
    F: Fn(&str, &str, &EvalCriteria) -> EvaluableAnswer + Send + Sync,
{
    fn score(&self, input: &str, output: &str, criteria: &EvalCriteria) -> QualityScore {
        let answer = (self.build)(input, output, criteria);
        let ds = self.dimension.score(&answer);
        QualityScore {
            score: ds.score,
            rationale: format!("[{}] {}", ds.dimension, ds.rationale),
        }
    }
}

/// Bridges the aggregate [`QualityProfile`] `overall` into [`ainxt_eval::QualityJudge`], so the release
/// gate can be driven by the weighted quality profile as a whole.
pub struct ProfileJudge<F> {
    assessor: QualityAssessor,
    build: F,
}

impl<F> ProfileJudge<F>
where
    F: Fn(&str, &str, &EvalCriteria) -> EvaluableAnswer + Send + Sync,
{
    pub fn new(assessor: QualityAssessor, build: F) -> Self {
        ProfileJudge { assessor, build }
    }
}

impl<F> EvalQualityJudge for ProfileJudge<F>
where
    F: Fn(&str, &str, &EvalCriteria) -> EvaluableAnswer + Send + Sync,
{
    fn score(&self, input: &str, output: &str, criteria: &EvalCriteria) -> QualityScore {
        let answer = (self.build)(input, output, criteria);
        let profile = self.assessor.assess(&answer);
        let worst = profile
            .dimensions
            .iter()
            .min_by_key(|d| d.score)
            .map(|d| format!("{}={}", d.dimension, d.score))
            .unwrap_or_else(|| "no dimensions".into());
        QualityScore {
            score: profile.overall,
            rationale: format!("overall {} (weakest: {})", profile.overall, worst),
        }
    }
}

// ===========================================================================================
// Tests
// ===========================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ---- fixtures -------------------------------------------------------------------------

    fn rag_context() -> AnswerContext {
        AnswerContext {
            question: "When does payment settlement occur?".into(),
            sources: vec![
                "Payment settlement runs on a T+1 cycle. Net settlement posts to member banks."
                    .into(),
                "The settlement window closes at 18:00 IST each business day.".into(),
            ],
            required_points: vec!["settlement".into(), "T+1".into(), "18:00".into()],
            expected_format: Format::Prose,
            target_len: LengthBand::new(12, 60),
            data_class: DataClass::RegulatedPayment,
        }
    }

    /// A complete, well-formatted, cited, grounded, on-tone answer.
    fn good_answer() -> EvaluableAnswer {
        EvaluableAnswer::new(
            "Payment settlement occurs on a T+1 net settlement cycle. The settlement window closes at 18:00 each business day [1][2].",
            rag_context(),
        )
    }

    /// A terse, uncited, ungrounded stub.
    fn bad_answer() -> EvaluableAnswer {
        EvaluableAnswer::new("Dunno really.", rag_context())
    }

    // ---- per-dimension: passing + failing ------------------------------------------------

    #[test]
    fn completeness_covers_or_misses_required_points() {
        let hi = Completeness.score(&good_answer());
        assert_eq!(hi.score, 100, "all three points present");
        let lo = Completeness.score(&bad_answer());
        assert_eq!(lo.score, 0, "no points present");
        assert!(lo.rationale.contains("missing"));
    }

    #[test]
    fn format_validity_json_balance() {
        let mut ctx = AnswerContext::plain("x");
        ctx.expected_format = Format::Json;
        let ok = FormatValidity.score(&EvaluableAnswer::new(
            r#"{"a": [1, 2], "b": "]"}"#,
            ctx.clone(),
        ));
        assert_eq!(ok.score, 100);
        let bad = FormatValidity.score(&EvaluableAnswer::new(r#"{"a": [1, 2}"#, ctx));
        assert!(
            bad.score < 100 && bad.score > 0,
            "unbalanced but has json chars => partial: {}",
            bad.score
        );
    }

    #[test]
    fn format_validity_prose_truncation() {
        let mut ctx = AnswerContext::plain("x");
        ctx.expected_format = Format::Prose;
        let ok = FormatValidity.score(&EvaluableAnswer::new(
            "This is a complete sentence.",
            ctx.clone(),
        ));
        assert_eq!(ok.score, 100);
        let truncated =
            FormatValidity.score(&EvaluableAnswer::new("This sentence just stops and", ctx));
        assert_eq!(truncated.score, 80, "no terminal punctuation => -20");
    }

    #[test]
    fn format_validity_bullets_and_table() {
        let mut b = AnswerContext::plain("x");
        b.expected_format = Format::BulletList;
        let list = FormatValidity.score(&EvaluableAnswer::new("- one\n- two\n- three", b.clone()));
        assert_eq!(list.score, 100);
        let notlist = FormatValidity.score(&EvaluableAnswer::new("just a paragraph of prose", b));
        assert_eq!(notlist.score, 0);

        let mut t = AnswerContext::plain("x");
        t.expected_format = Format::Table;
        let table = FormatValidity.score(&EvaluableAnswer::new(
            "| a | b |\n| --- | --- |\n| 1 | 2 |",
            t.clone(),
        ));
        assert_eq!(table.score, 100);
        let notable = FormatValidity.score(&EvaluableAnswer::new("no columns here", t));
        assert_eq!(notable.score, 0);
    }

    #[test]
    fn verbosity_fit_band() {
        let mut ctx = AnswerContext::plain("x");
        ctx.target_len = LengthBand::new(10, 20);
        // 15 words: in band.
        let words15 = "one two three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen";
        assert_eq!(
            VerbosityFit
                .score(&EvaluableAnswer::new(words15, ctx.clone()))
                .score,
            100
        );
        // 5 words: below min 10 => 50.
        let s = VerbosityFit.score(&EvaluableAnswer::new(
            "one two three four five",
            ctx.clone(),
        ));
        assert_eq!(s.score, 50);
        // 40 words: max 20 => 50.
        let long = (0..40)
            .map(|i| format!("w{i}"))
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(
            VerbosityFit.score(&EvaluableAnswer::new(&long, ctx)).score,
            50
        );
    }

    #[test]
    fn citation_presence_all_paths() {
        // sources present + valid cites
        let hi = CitationPresence.score(&good_answer());
        assert_eq!(hi.score, 100, "both sources cited [1][2]");
        // sources present + no cites
        let lo = CitationPresence.score(&bad_answer());
        assert_eq!(lo.score, 0);
        // sources present + out-of-range (fabricated) marker
        let fab = EvaluableAnswer::new("Per the docs [9], it is so.", rag_context());
        let f = CitationPresence.score(&fab);
        assert_eq!(f.score, 0, "0 valid, 1 invalid => base 0 - 20 clamped to 0");
        assert!(f.rationale.contains("fabricated"));
        // no sources + no cites => correctly uncited
        let none = EvaluableAnswer::new("A general statement.", AnswerContext::plain("q"));
        assert_eq!(CitationPresence.score(&none).score, 100);
        // no sources + fabricated cites
        let fake = EvaluableAnswer::new("As shown [1][2].", AnswerContext::plain("q"));
        assert_eq!(CitationPresence.score(&fake).score, 40, "100 - 2*30");
    }

    #[test]
    fn groundedness_supported_vs_hallucinated() {
        let hi = Groundedness.score(&good_answer());
        assert!(
            hi.score >= 80,
            "answer terms drawn from sources: {}",
            hi.score
        );
        // Fully hallucinated content vs the same sources.
        let hallu = EvaluableAnswer::new(
            "Quantum reconciliation flux capacitors govern interplanetary teleportation schedules.",
            rag_context(),
        );
        let lo = Groundedness.score(&hallu);
        assert_eq!(lo.score, 0, "no content word appears in sources");
    }

    #[test]
    fn tone_consistency_professional_vs_sloppy() {
        let mut ctx = AnswerContext::plain("x");
        ctx.data_class = DataClass::Internal;
        let pro = ToneConsistency.score(&EvaluableAnswer::new(
            "Settlement posts on the T+1 cycle at 18:00 IST.",
            ctx.clone(),
        ));
        assert_eq!(pro.score, 100);
        let sloppy = ToneConsistency.score(&EvaluableAnswer::new(
            "Well, maybe, I think it's probably fine, sorry, unfortunately I'm not sure!!!",
            ctx,
        ));
        assert!(
            sloppy.score < 50,
            "hedges+apologies+bangs penalised: {}",
            sloppy.score
        );
    }

    #[test]
    fn tone_regulated_is_stricter() {
        let base = "I think this is probably right.";
        let mut internal = AnswerContext::plain("x");
        internal.data_class = DataClass::Internal;
        let mut regulated = AnswerContext::plain("x");
        regulated.data_class = DataClass::RegulatedPayment;
        let s_int = ToneConsistency
            .score(&EvaluableAnswer::new(base, internal))
            .score;
        let s_reg = ToneConsistency
            .score(&EvaluableAnswer::new(base, regulated))
            .score;
        assert!(
            s_reg < s_int,
            "regulated tone penalty must be stricter: {s_reg} < {s_int}"
        );
    }

    // ---- profile aggregation + weights ---------------------------------------------------

    #[test]
    fn good_answer_scores_high_bad_answer_scores_low() {
        let assessor = QualityAssessor::standard(QualityWeights::uniform());
        let good = assessor.assess(&good_answer());
        let bad = assessor.assess(&bad_answer());
        assert!(good.overall >= 85, "good overall {}", good.overall);
        // A terse uncited stub: well-formed prose + neutral tone prop it up, but completeness,
        // citation, verbosity, and groundedness all collapse — a clearly low aggregate.
        assert!(bad.overall <= 40, "bad overall {}", bad.overall);
        assert!(good.overall > bad.overall + 40);
    }

    #[test]
    fn weights_change_the_overall_predictably() {
        // An answer that is perfect except it is completely uncited (sources exist).
        let ans = EvaluableAnswer::new(
            "Payment settlement occurs on a T+1 net settlement cycle; the settlement window closes at 18:00.",
            rag_context(),
        );
        let uniform = QualityAssessor::standard(QualityWeights::uniform()).assess(&ans);
        // Now weight citation_presence heavily: overall must DROP because that dimension is 0.
        let cite_heavy =
            QualityAssessor::standard(QualityWeights::uniform().with("citation_presence", 10.0))
                .assess(&ans);
        assert_eq!(uniform.dimension_score("citation_presence"), Some(0));
        assert!(
            cite_heavy.overall < uniform.overall,
            "up-weighting the failing dimension must lower overall: {} !< {}",
            cite_heavy.overall,
            uniform.overall
        );
        // And zero-weighting the failing dimension must RAISE overall vs uniform.
        let cite_zero =
            QualityAssessor::standard(QualityWeights::uniform().with("citation_presence", 0.0))
                .assess(&ans);
        assert!(cite_zero.overall > uniform.overall);
    }

    // ---- drift ---------------------------------------------------------------------------

    fn prof(scores: &[(&str, u8)], overall: u8) -> QualityProfile {
        QualityProfile::new(
            scores
                .iter()
                .map(|(n, s)| DimensionScore {
                    dimension: (*n).into(),
                    score: *s,
                    rationale: String::new(),
                })
                .collect(),
            overall,
        )
    }

    #[test]
    fn drift_trips_and_names_the_regressed_dimension() {
        // Baseline: citation ~92, groundedness ~90, overall ~90.
        let baseline: Vec<QualityProfile> = [91u8, 92, 90, 93, 92, 91]
            .iter()
            .map(|&c| prof(&[("citation_presence", c), ("groundedness", 90)], 90))
            .collect();
        // Recent: citation collapses to ~55 (RAG citation regression), groundedness steady, overall dips.
        let recent: Vec<QualityProfile> = [56u8, 54, 55, 57, 55, 56]
            .iter()
            .map(|&c| prof(&[("citation_presence", c), ("groundedness", 90)], 78))
            .collect();
        let v = detect_drift(&baseline, &recent, &DriftPolicy::default());
        assert!(
            v.is_regressed(),
            "a 37-point citation drop must trip: {v:?}"
        );
        let regressed = v.regressed_dimensions();
        assert!(
            regressed.contains(&"citation_presence"),
            "must name citation: {regressed:?}"
        );
        assert!(
            regressed.contains(&OVERALL_KEY),
            "overall dropped 90->78 too"
        );
        assert!(
            !regressed.contains(&"groundedness"),
            "groundedness was steady"
        );
        // worst-first ordering: citation drop (~37) > overall drop (~12).
        if let DriftVerdict::Regressed(v) = v {
            assert_eq!(v[0].dimension, "citation_presence");
        }
    }

    #[test]
    fn drift_stable_series_does_not_trip() {
        let baseline: Vec<QualityProfile> = [88u8, 90, 89, 91, 90, 88]
            .iter()
            .map(|&c| prof(&[("citation_presence", c), ("groundedness", 87)], 88))
            .collect();
        let recent: Vec<QualityProfile> = [89u8, 90, 91, 88, 90, 89]
            .iter()
            .map(|&c| prof(&[("citation_presence", c), ("groundedness", 88)], 89))
            .collect();
        assert_eq!(
            detect_drift(&baseline, &recent, &DriftPolicy::default()),
            DriftVerdict::Stable
        );
    }

    #[test]
    fn drift_small_drop_within_noise_does_not_trip() {
        // A 3-point drop under noisy windows: below the 5-point margin AND not significant.
        let baseline: Vec<QualityProfile> = [80u8, 90, 70, 95, 85, 75]
            .iter()
            .map(|&o| prof(&[("x", o)], o))
            .collect();
        let recent: Vec<QualityProfile> = [77u8, 87, 67, 92, 82, 72]
            .iter()
            .map(|&o| prof(&[("x", o)], o))
            .collect();
        let v = detect_drift(&baseline, &recent, &DriftPolicy::default());
        assert!(v.is_stable(), "a within-margin drop must not trip: {v:?}");
    }

    #[test]
    fn drift_inconclusive_when_windows_too_small() {
        let baseline = vec![prof(&[("x", 90)], 90), prof(&[("x", 90)], 90)];
        let recent = vec![prof(&[("x", 50)], 50), prof(&[("x", 50)], 50)];
        match detect_drift(&baseline, &recent, &DriftPolicy::default()) {
            DriftVerdict::Inconclusive(msg) => assert!(msg.contains("too small")),
            other => panic!("expected inconclusive, got {other:?}"),
        }
    }

    // ---- eval bridge ---------------------------------------------------------------------

    #[test]
    fn quality_dimension_drives_the_release_gate() {
        use ainxt_eval::{evaluate_gate, run_eval, EvalCase, EvalSystem, GatePolicy};

        // A system that either cites its source or doesn't.
        struct Sys {
            cited: bool,
        }
        impl EvalSystem for Sys {
            fn respond(&self, _input: &str) -> String {
                if self.cited {
                    "Settlement is on a T+1 cycle [1].".into()
                } else {
                    "Settlement is on a T+1 cycle.".into()
                }
            }
        }

        // Build the context the CitationPresence dimension needs from the eval seam.
        let build = |_input: &str, output: &str, _c: &EvalCriteria| {
            let mut ctx = AnswerContext::plain("when is settlement");
            ctx.sources = vec!["settlement runs T+1".into()];
            EvaluableAnswer::new(output, ctx)
        };
        let judge = DimensionJudge::new(Box::new(CitationPresence), build);

        let cases = vec![EvalCase::new("q1", "when is settlement", "must cite", 60)];
        let good = run_eval(&cases, &Sys { cited: true }, &judge);
        let bad = run_eval(&cases, &Sys { cited: false }, &judge);

        assert_eq!(
            good.mean, 100,
            "cited answer scores full on citation dimension"
        );
        assert_eq!(
            bad.mean, 0,
            "uncited answer scores zero on citation dimension"
        );

        let policy = GatePolicy {
            min_pass_rate: 1.0,
            min_mean: 60,
            noninferiority_margin: 0.02,
        };
        assert!(
            evaluate_gate(&good, &policy, None).is_pass(),
            "quality gate passes cited"
        );
        assert!(
            !evaluate_gate(&bad, &policy, None).is_pass(),
            "quality gate blocks uncited via the dimension judge"
        );
    }

    #[test]
    fn profile_judge_drives_the_gate_on_the_aggregate() {
        use ainxt_eval::{evaluate_gate, run_eval, EvalCase, EvalSystem, GatePolicy};

        struct Sys {
            good: bool,
        }
        impl EvalSystem for Sys {
            fn respond(&self, _input: &str) -> String {
                if self.good {
                    "Payment settlement occurs on a T+1 net settlement cycle; the window closes at 18:00 [1][2].".into()
                } else {
                    "Dunno really.".into()
                }
            }
        }
        let build =
            |_i: &str, output: &str, _c: &EvalCriteria| EvaluableAnswer::new(output, rag_context());
        let judge = ProfileJudge::new(QualityAssessor::standard(QualityWeights::uniform()), build);
        let cases = vec![EvalCase::new("q1", "settlement?", "high quality", 70)];
        let good = run_eval(&cases, &Sys { good: true }, &judge);
        let bad = run_eval(&cases, &Sys { good: false }, &judge);
        assert!(
            good.mean > bad.mean + 40,
            "profile separates good/bad: {} vs {}",
            good.mean,
            bad.mean
        );
        let policy = GatePolicy {
            min_pass_rate: 1.0,
            min_mean: 70,
            noninferiority_margin: 0.02,
        };
        assert!(evaluate_gate(&good, &policy, None).is_pass());
        assert!(!evaluate_gate(&bad, &policy, None).is_pass());
    }

    #[test]
    fn profile_serializes_round_trip() {
        let p = QualityAssessor::standard(QualityWeights::uniform()).assess(&good_answer());
        let json = serde_json::to_string(&p).unwrap();
        let back: QualityProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(back, p);
    }
}
