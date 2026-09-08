// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! ainxt-synthesis — the AiNxt cross-source synthesis + faithfulness core.
//!
//! Design: `docs/architecture/CONTEXT_FABRIC.md` (the "conflict-arbitrated, lineage-
//! recording" optimizer), `docs/architecture/STRUCTURED_FEDERATED_RETRIEVAL.md` (a
//! factual claim with no source is an output-lint failure, exactly analogous to a
//! citation-less number), and `docs/architecture/SUBSYSTEM_DEEP_DIVES.md`
//! (retrieve → generate → **cite**).
//!
//! Retrieval (`ainxt-retrieval`) answers *"which chunks are relevant?"*. This crate
//! answers the next, harder question — *"was the relevant material USED faithfully?"* —
//! the quality-of-RAG-use gate. It operates purely in-process over a set of [`Source`]s
//! and a candidate answer expressed as [`Claim`]s (sentences/statements), and produces a
//! [`SynthesisReport`] that a runtime output-lint seam can act on before an answer ships:
//!
//! 1. **Near-duplicate source dedup** ([`dedup_sources`]) — the same fact mirrored across
//!    three sources must count *once*, or conflict-arbitration and coverage both lie.
//!    Sources are clustered by token-set Jaccard against a threshold; each cluster keeps a
//!    single canonical representative and lists its duplicates. All downstream analysis
//!    runs over the canonical set.
//! 2. **Cross-source conflict detection** ([`detect_conflicts`]) — two *different* sources
//!    that make contradictory statements about the *same subject* are flagged with the
//!    subject and the conflicting pair. A "fact" is a sentence's subject (its content
//!    words) plus a typed value — a number, a date, or a negation polarity. Two facts
//!    conflict when their subjects overlap above a threshold and their same-kind values
//!    differ (`5` vs `10`, `2024-01-15` vs `2024-02-20`, affirmed vs negated). Same value
//!    on the same subject is NOT a conflict — that is agreement, which is why mirrors do
//!    not self-flag.
//! 3. **Claim → source attribution** ([`attribute`]) — each answer claim is matched to the
//!    source(s) that support it by lexical *containment* (`|claim ∩ source| / |claim|`)
//!    above a threshold, evaluated per source sentence so a claim buried in one sentence
//!    of a long source still attributes.
//! 4. **Faithfulness** — any claim with *no* supporting source is flagged as unsupported
//!    (a potential hallucination), and a groundedness ratio (`supported / total`) is
//!    computed exactly.
//! 5. **Coverage** — which canonical sources were actually used, which were ignored, and
//!    the highest [`DataClass`] among the used ones (so a downstream router knows the true
//!    sensitivity of the material the answer actually rests on, ADR-012).
//!
//! Everything is deterministic and dependency-light (`serde` + `ainxt-types`): the text
//! extractors — tokenizer, sentence splitter, number/date/negation scanners — are all
//! hand-written, so no regex/NLP/ML crate enters the legal or supply-chain surface. The
//! analysis is intentionally *lexical and conservative*: it is an output-lint safety net,
//! not a semantic entailment model, so it prefers to under-claim support (flag more) over
//! silently blessing an ungrounded answer — the correct bias for payments software.

use std::collections::BTreeSet;

use ainxt_types::DataClass;
use serde::{Deserialize, Serialize};

pub mod rederive;

/// Jaccard over content-token sets at/above which two sources are treated as near-duplicate
/// mirrors of the same material.
pub const DEFAULT_DEDUP_JACCARD: f64 = 0.8;
/// Jaccard over subject-token sets at/above which two facts are treated as being about the
/// same subject (a precondition for calling their differing values a *conflict*).
pub const DEFAULT_CONFLICT_SUBJECT_JACCARD: f64 = 0.5;
/// Containment (`|claim ∩ source| / |claim|`) at/above which a source is treated as
/// supporting a claim.
pub const DEFAULT_SUPPORT_CONTAINMENT: f64 = 0.6;

/// Floating-point tolerance for treating two extracted numbers as equal.
const NUM_EPSILON: f64 = 1e-9;

// ---------------------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------------------

/// A retrieved source the answer may draw on: an id, its text, and the data class that
/// classifies its sensitivity (mirrors `ainxt_retrieval::Chunk`'s labels so lineage and
/// routing read the same vocabulary).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Source {
    pub id: String,
    pub text: String,
    pub data_class: DataClass,
    /// Authority rank of the source (higher = more authoritative — e.g. a signed control-plane
    /// doc outranks a wiki page). `None` = unranked. Used by [`arbitrate`] to resolve a
    /// cross-source conflict *by authority before recency* (`CONTEXT_FABRIC.md` §3, "arbitrate
    /// conflicts by recency/authority"). Deterministic: no ambient default is assumed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<u32>,
    /// A monotonic freshness stamp (a caller-supplied logical tick — no wall clock enters this
    /// crate, `DETERMINISTIC` mandate). Higher = fresher. `None` = undated. Used by [`arbitrate`]
    /// as the recency tiebreak once authority is equal/absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<i64>,
}

impl Source {
    pub fn new(id: &str, text: &str, data_class: DataClass) -> Self {
        Source {
            id: id.to_string(),
            text: text.to_string(),
            data_class,
            authority: None,
            timestamp: None,
        }
    }

    /// Builder: attach an authority rank (higher = more authoritative).
    pub fn with_authority(mut self, authority: u32) -> Self {
        self.authority = Some(authority);
        self
    }

    /// Builder: attach a freshness stamp (higher = fresher; a caller-supplied logical tick).
    pub fn with_timestamp(mut self, timestamp: i64) -> Self {
        self.timestamp = Some(timestamp);
        self
    }
}

/// A single statement in the candidate answer. An answer is a sequence of these; splitting
/// a raw answer string into claims is available via [`claims_from_text`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Claim {
    pub text: String,
}

impl Claim {
    pub fn new(text: &str) -> Self {
        Claim {
            text: text.to_string(),
        }
    }
}

/// Split a raw candidate-answer string into [`Claim`]s on sentence boundaries. Empty /
/// whitespace-only fragments are dropped.
pub fn claims_from_text(answer: &str) -> Vec<Claim> {
    split_sentences(answer)
        .into_iter()
        .map(|s| Claim { text: s })
        .collect()
}

/// Tunable thresholds for a full [`synthesize`] pass.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct SynthesisConfig {
    pub dedup_jaccard: f64,
    pub conflict_subject_jaccard: f64,
    pub support_containment: f64,
}

impl Default for SynthesisConfig {
    fn default() -> Self {
        SynthesisConfig {
            dedup_jaccard: DEFAULT_DEDUP_JACCARD,
            conflict_subject_jaccard: DEFAULT_CONFLICT_SUBJECT_JACCARD,
            support_containment: DEFAULT_SUPPORT_CONTAINMENT,
        }
    }
}

// ---------------------------------------------------------------------------------------
// Outputs
// ---------------------------------------------------------------------------------------

/// One cluster of near-duplicate sources. `representative` is the canonical id kept for
/// downstream analysis; `duplicates` are the other ids that collapsed into it (may be
/// empty for a singleton cluster). All ids in a group are sorted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DuplicateGroup {
    pub representative: String,
    pub duplicates: Vec<String>,
}

/// Result of near-duplicate dedup. `canonical_ids` is the deduplicated source set (one id
/// per cluster) in first-seen order; `groups` records the full clustering for lineage.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DedupReport {
    pub groups: Vec<DuplicateGroup>,
    pub canonical_ids: Vec<String>,
}

/// The kind of contradiction two facts exhibit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConflictKind {
    /// Same subject, differing numbers.
    Numeric,
    /// Same subject, differing dates.
    Date,
    /// Same subject, one statement affirmed and the other negated.
    Negation,
}

/// A pointer to one side of a conflict: which source, the exact statement, and a display
/// of the extracted value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FactRef {
    pub source_id: String,
    pub statement: String,
    pub value: String,
}

/// A detected cross-source contradiction: two different sources asserting different values
/// for the same subject.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Conflict {
    /// The shared subject tokens (sorted), e.g. `["fee", "transaction", "upi"]`.
    pub subject: Vec<String>,
    pub kind: ConflictKind,
    pub a: FactRef,
    pub b: FactRef,
}

/// A source that supports a claim, with the containment score that earned it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SupportingSource {
    pub source_id: String,
    pub score: f64,
}

/// The attribution outcome for one answer claim.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Attribution {
    pub claim_index: usize,
    pub claim_text: String,
    /// `true` iff at least one source supports the claim (or the claim carries no content
    /// tokens, which is vacuously grounded — nothing can be hallucinated).
    pub supported: bool,
    /// Supporting sources, strongest first.
    pub sources: Vec<SupportingSource>,
}

/// The full synthesis + faithfulness verdict over a set of sources and a candidate answer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SynthesisReport {
    pub dedup: DedupReport,
    pub conflicts: Vec<Conflict>,
    pub attributions: Vec<Attribution>,
    /// Indices (into the claim list) of claims with no supporting source.
    pub unsupported_claims: Vec<usize>,
    /// `supported_claims / total_claims`. Exactly `1.0` for an empty answer (nothing to
    /// ground) — never `NaN`.
    pub groundedness: f64,
    /// Canonical source ids attributed to at least one claim, sorted.
    pub used_sources: Vec<String>,
    /// Canonical source ids attributed to no claim, sorted.
    pub unused_sources: Vec<String>,
    /// Highest data class among the *used* sources — the true sensitivity the answer rests
    /// on. `None` when no source was used.
    pub used_data_class: Option<DataClass>,
}

// ---------------------------------------------------------------------------------------
// Text extraction (hand-written, no regex/NLP dep)
// ---------------------------------------------------------------------------------------

/// Function words dropped from content/subject token sets so overlap reflects the
/// meaning-bearing words, not grammatical glue.
const STOPWORDS: &[&str] = &[
    "a", "an", "the", "is", "are", "was", "were", "be", "been", "being", "am", "of", "to", "in",
    "on", "at", "for", "and", "or", "but", "if", "then", "than", "as", "by", "with", "from",
    "this", "that", "these", "those", "it", "its", "into", "over", "under", "out", "up", "down",
    "so", "such", "each", "all", "any", "some", "will", "shall", "would", "should", "can", "could",
    "may", "might", "must", "do", "does", "did", "has", "have", "had", "he", "she", "they", "we",
    "you", "i", "his", "her", "their", "our", "your", "occurs", "occur",
];

fn is_stopword(tok: &str) -> bool {
    STOPWORDS.contains(&tok)
}

/// Words that flip a statement's polarity (qualitative negation).
const NEGATIONS: &[&str] = &[
    "not", "no", "never", "cannot", "none", "without", "nor", "neither", "nothing", "unable",
];

/// Lower-cased alphanumeric tokens carrying meaning: stopwords and pure-digit tokens (the
/// number/date payloads live in the typed value, not the subject) are removed.
fn content_tokens(text: &str) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    for raw in text.split(|c: char| !c.is_ascii_alphanumeric()) {
        if raw.is_empty() {
            continue;
        }
        let lower = raw.to_ascii_lowercase();
        if is_stopword(&lower) {
            continue;
        }
        // Negation words carry polarity, not subject identity — they live in the typed
        // value, so drop them here or "X does not Y" vs "X does Y" would look like
        // different subjects instead of the same subject with opposite polarity.
        if NEGATIONS.contains(&lower.as_str()) {
            continue;
        }
        // Drop pure-digit tokens — numeric meaning is captured as a typed value.
        if lower.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        set.insert(lower);
    }
    set
}

/// Split text into sentences. Boundaries: any newline, or `.`/`!`/`?` followed by
/// whitespace or end-of-text — so a decimal (`10.50`) or an `ISO` date (`2024-01-15`) is
/// never split mid-token. Fragments are trimmed; empties dropped.
pub(crate) fn split_sentences(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut start = 0usize;
    for i in 0..chars.len() {
        let c = chars[i];
        let is_terminal = matches!(c, '.' | '!' | '?')
            && chars.get(i + 1).map(|n| n.is_whitespace()).unwrap_or(true);
        if c == '\n' || is_terminal {
            let frag: String = chars[start..=i].iter().collect();
            let trimmed = frag
                .trim()
                .trim_matches(|c: char| matches!(c, '.' | '!' | '?'));
            let trimmed = trimmed.trim();
            if !trimmed.is_empty() {
                out.push(trimmed.to_string());
            }
            start = i + 1;
        }
    }
    if start < chars.len() {
        let frag: String = chars[start..].iter().collect();
        let trimmed = frag.trim();
        if !trimmed.is_empty() {
            out.push(trimmed.to_string());
        }
    }
    out
}

/// Parse a whitespace token as a normalized date (`YYYY-MM-DD`, `D/M/Y`, etc.). Returns a
/// canonical string that is identical for identical dates and distinct for distinct ones —
/// exact calendar interpretation is irrelevant to conflict detection, only equality is.
/// Rejects anything that is not three integer parts with one 4-digit year and the other
/// two within `1..=31`.
fn parse_date(tok: &str) -> Option<String> {
    let t = tok.trim_matches(|c: char| !c.is_ascii_digit());
    let sep = if t.contains('-') {
        '-'
    } else if t.contains('/') {
        '/'
    } else if t.contains('.') {
        '.'
    } else {
        return None;
    };
    let parts: Vec<&str> = t.split(sep).collect();
    if parts.len() != 3 {
        return None;
    }
    let mut nums = Vec::with_capacity(3);
    let mut has_year = false;
    for p in &parts {
        if p.is_empty() || !p.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        let n: u32 = p.parse().ok()?;
        if p.len() == 4 {
            has_year = true;
        }
        nums.push((p.len(), n));
    }
    if !has_year {
        return None;
    }
    // Non-year parts must be plausible day/month values.
    for (len, n) in &nums {
        if *len != 4 && (*n == 0 || *n > 31) {
            return None;
        }
    }
    Some(
        nums.iter()
            .map(|(_, n)| format!("{:02}", n))
            .collect::<Vec<_>>()
            .join("-"),
    )
}

/// Parse a whitespace token as a number, tolerating thousands separators, a leading
/// currency symbol, and a trailing `%`. Any ASCII letter, or an internal `-` (a range or a
/// date), disqualifies it.
pub(crate) fn parse_number(tok: &str) -> Option<f64> {
    if tok.chars().any(|c| c.is_ascii_alphabetic()) {
        return None;
    }
    // Reject a '-' that is not a leading sign (ranges / dates are not numbers here).
    if tok.char_indices().any(|(i, c)| c == '-' && i != 0) {
        return None;
    }
    let mut s = String::new();
    for c in tok.chars() {
        match c {
            '0'..='9' | '.' => s.push(c),
            '-' => s.push(c), // only reaches here as a leading sign
            ',' => {}         // thousands separator
            _ => {}           // currency / % / brackets
        }
    }
    if s.is_empty() || s == "-" || s == "." {
        return None;
    }
    s.parse::<f64>().ok()
}

/// Does a sentence contain a qualitative negation (`not`, `never`, an `n't` contraction …)?
fn has_negation(sentence: &str) -> bool {
    for raw in sentence.split_whitespace() {
        let w: String = raw
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '\'')
            .collect::<String>()
            .to_ascii_lowercase();
        if w.is_empty() {
            continue;
        }
        if NEGATIONS.contains(&w.as_str()) || w.ends_with("n't") {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------------------
// Facts
// ---------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum FactValue {
    Number(f64),
    Date(String),
    Polarity(bool), // true = negated
}

impl FactValue {
    fn kind(&self) -> ConflictKind {
        match self {
            FactValue::Number(_) => ConflictKind::Numeric,
            FactValue::Date(_) => ConflictKind::Date,
            FactValue::Polarity(_) => ConflictKind::Negation,
        }
    }

    /// Two same-kind values that disagree.
    fn differs_from(&self, other: &FactValue) -> bool {
        match (self, other) {
            (FactValue::Number(a), FactValue::Number(b)) => (a - b).abs() > NUM_EPSILON,
            (FactValue::Date(a), FactValue::Date(b)) => a != b,
            (FactValue::Polarity(a), FactValue::Polarity(b)) => a != b,
            _ => false,
        }
    }

    fn display(&self) -> String {
        match self {
            FactValue::Number(n) => fmt_num(*n),
            FactValue::Date(d) => d.clone(),
            FactValue::Polarity(true) => "negated".to_string(),
            FactValue::Polarity(false) => "affirmed".to_string(),
        }
    }
}

fn fmt_num(n: f64) -> String {
    if (n.fract()).abs() < NUM_EPSILON {
        format!("{}", n as i64)
    } else {
        format!("{}", n)
    }
}

struct Fact {
    source_id: String,
    statement: String,
    subject: BTreeSet<String>,
    value: FactValue,
}

/// Extract one fact per sentence (those with a non-empty subject). Value precedence:
/// date → number → polarity. A sentence with no content words yields no fact.
fn extract_facts(source: &Source) -> Vec<Fact> {
    let mut facts = Vec::new();
    for sentence in split_sentences(&source.text) {
        let subject = content_tokens(&sentence);
        if subject.is_empty() {
            continue;
        }
        let mut date_val: Option<String> = None;
        let mut num_val: Option<f64> = None;
        for raw in sentence.split_whitespace() {
            if date_val.is_none() {
                if let Some(d) = parse_date(raw) {
                    date_val = Some(d);
                    continue;
                }
            }
            if num_val.is_none() {
                if let Some(n) = parse_number(raw) {
                    num_val = Some(n);
                }
            }
        }
        let value = if let Some(d) = date_val {
            FactValue::Date(d)
        } else if let Some(n) = num_val {
            FactValue::Number(n)
        } else {
            FactValue::Polarity(has_negation(&sentence))
        };
        facts.push(Fact {
            source_id: source.id.clone(),
            statement: sentence,
            subject,
            value,
        });
    }
    facts
}

// ---------------------------------------------------------------------------------------
// Set metrics
// ---------------------------------------------------------------------------------------

/// Jaccard `|a ∩ b| / |a ∪ b|`. Two empty sets are treated as identical (`1.0`); an empty
/// vs non-empty pair is `0.0`.
fn jaccard(a: &BTreeSet<String>, b: &BTreeSet<String>) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    let inter = a.intersection(b).count();
    let union = a.len() + b.len() - inter;
    if union == 0 {
        return 0.0;
    }
    inter as f64 / union as f64
}

/// Containment `|a ∩ b| / |a|` — how much of `a` is covered by `b`. `0.0` when `a` is
/// empty (nothing to contain, cannot support).
fn containment(a: &BTreeSet<String>, b: &BTreeSet<String>) -> f64 {
    if a.is_empty() {
        return 0.0;
    }
    let inter = a.intersection(b).count();
    inter as f64 / a.len() as f64
}

// ---------------------------------------------------------------------------------------
// Public algorithms
// ---------------------------------------------------------------------------------------

/// Cluster near-duplicate sources by content-token Jaccard `>= threshold`. Deterministic:
/// sources are processed in input order and each joins the first existing cluster whose
/// representative it matches, else starts a new one. The representative is the first
/// (input-order) member of each cluster.
pub fn dedup_sources(sources: &[Source], threshold: f64) -> DedupReport {
    let toks: Vec<BTreeSet<String>> = sources.iter().map(|s| content_tokens(&s.text)).collect();
    let mut reps: Vec<usize> = Vec::new();
    let mut cluster_of: Vec<usize> = vec![0; sources.len()];
    for i in 0..sources.len() {
        let mut assigned: Option<usize> = None;
        for &r in &reps {
            if jaccard(&toks[i], &toks[r]) >= threshold {
                assigned = Some(r);
                break;
            }
        }
        match assigned {
            Some(r) => cluster_of[i] = r,
            None => {
                cluster_of[i] = i;
                reps.push(i);
            }
        }
    }
    let mut groups = Vec::with_capacity(reps.len());
    for &r in &reps {
        let mut members: Vec<String> = (0..sources.len())
            .filter(|&i| cluster_of[i] == r)
            .map(|i| sources[i].id.clone())
            .collect();
        members.sort();
        let representative = sources[r].id.clone();
        let duplicates: Vec<String> = members
            .into_iter()
            .filter(|id| id != &representative)
            .collect();
        groups.push(DuplicateGroup {
            representative,
            duplicates,
        });
    }
    let canonical_ids = reps.iter().map(|&r| sources[r].id.clone()).collect();
    DedupReport {
        groups,
        canonical_ids,
    }
}

/// Detect cross-source contradictions. For every pair of facts drawn from *different*
/// sources whose subjects overlap (`jaccard >= subject_threshold`) and whose same-kind
/// values differ, emit a [`Conflict`]. Facts within one source are never compared to each
/// other. Pass an already-deduped source set to avoid mirror noise (see [`synthesize`]).
pub fn detect_conflicts(sources: &[Source], subject_threshold: f64) -> Vec<Conflict> {
    let facts: Vec<Fact> = sources.iter().flat_map(extract_facts).collect();
    let mut conflicts = Vec::new();
    for i in 0..facts.len() {
        for j in (i + 1)..facts.len() {
            let (fa, fb) = (&facts[i], &facts[j]);
            if fa.source_id == fb.source_id {
                continue;
            }
            if fa.value.kind() != fb.value.kind() {
                continue;
            }
            if !fa.value.differs_from(&fb.value) {
                continue;
            }
            if jaccard(&fa.subject, &fb.subject) < subject_threshold {
                continue;
            }
            let subject: Vec<String> = fa.subject.intersection(&fb.subject).cloned().collect();
            conflicts.push(Conflict {
                subject,
                kind: fa.value.kind(),
                a: FactRef {
                    source_id: fa.source_id.clone(),
                    statement: fa.statement.clone(),
                    value: fa.value.display(),
                },
                b: FactRef {
                    source_id: fb.source_id.clone(),
                    statement: fb.statement.clone(),
                    value: fb.value.display(),
                },
            });
        }
    }
    conflicts
}

/// How a conflict was resolved (which signal decided the winner).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResolutionBasis {
    /// One side's source had strictly higher authority.
    Authority,
    /// Authority tied/absent; one side's source was strictly fresher.
    Recency,
    /// Neither authority nor recency could separate the two sides — a human must arbitrate.
    /// (`CONTEXT_FABRIC.md` §3 arbitrates "by recency/authority"; when both are silent the
    /// safe outcome for payments data is to escalate, never to silently pick one.)
    Unresolved,
}

/// The outcome of arbitrating one [`Conflict`]: which side wins, which loses, on what basis,
/// with a human-readable provenance line for the lineage record / Event Log.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConflictResolution {
    pub subject: Vec<String>,
    pub kind: ConflictKind,
    /// The surviving fact — `None` iff `basis == Unresolved`.
    pub winner: Option<FactRef>,
    /// The superseded fact — `None` iff `basis == Unresolved`.
    pub loser: Option<FactRef>,
    pub basis: ResolutionBasis,
    /// Provenance: e.g. `"authority: src=policy(3) > src=wiki(1)"` — recorded so an auditor can
    /// see *why* one number was preferred over another.
    pub provenance: String,
}

/// Look up a source's (authority, timestamp) by id. A missing source is treated as fully
/// unranked/undated — never as a zero authority, which would be a silent implicit ranking.
fn rank_of(sources: &[Source], id: &str) -> (Option<u32>, Option<i64>) {
    sources
        .iter()
        .find(|s| s.id == id)
        .map(|s| (s.authority, s.timestamp))
        .unwrap_or((None, None))
}

/// Arbitrate a single [`Conflict`] by **authority first, then recency**, attaching provenance.
///
/// Deterministic and fail-safe for payments data: if neither authority nor recency can
/// separate the two contradicting sources, the result is [`ResolutionBasis::Unresolved`] with
/// no winner — the caller must escalate to a human rather than ship an arbitrarily-picked
/// number. Authority strictly dominates recency (a fresher-but-lower-authority source never
/// overrides an authoritative one).
pub fn arbitrate(conflict: &Conflict, sources: &[Source]) -> ConflictResolution {
    let (auth_a, ts_a) = rank_of(sources, &conflict.a.source_id);
    let (auth_b, ts_b) = rank_of(sources, &conflict.b.source_id);

    // 1) Authority: only decides when BOTH are known and they differ.
    if let (Some(a), Some(b)) = (auth_a, auth_b) {
        if a != b {
            let (winner, loser, wa, la) = if a > b {
                (&conflict.a, &conflict.b, a, b)
            } else {
                (&conflict.b, &conflict.a, b, a)
            };
            return ConflictResolution {
                subject: conflict.subject.clone(),
                kind: conflict.kind,
                winner: Some(winner.clone()),
                loser: Some(loser.clone()),
                basis: ResolutionBasis::Authority,
                provenance: format!(
                    "authority: src={}({}) > src={}({})",
                    winner.source_id, wa, loser.source_id, la
                ),
            };
        }
    }

    // 2) Recency: only decides when BOTH are dated and they differ.
    if let (Some(a), Some(b)) = (ts_a, ts_b) {
        if a != b {
            let (winner, loser, wt, lt) = if a > b {
                (&conflict.a, &conflict.b, a, b)
            } else {
                (&conflict.b, &conflict.a, b, a)
            };
            return ConflictResolution {
                subject: conflict.subject.clone(),
                kind: conflict.kind,
                winner: Some(winner.clone()),
                loser: Some(loser.clone()),
                basis: ResolutionBasis::Recency,
                provenance: format!(
                    "recency: src={}(t={}) fresher than src={}(t={})",
                    winner.source_id, wt, loser.source_id, lt
                ),
            };
        }
    }

    // 3) Neither signal separates them — escalate.
    ConflictResolution {
        subject: conflict.subject.clone(),
        kind: conflict.kind,
        winner: None,
        loser: None,
        basis: ResolutionBasis::Unresolved,
        provenance: format!(
            "unresolved: src={} vs src={} — authority and recency both indecisive",
            conflict.a.source_id, conflict.b.source_id
        ),
    }
}

/// Detect and arbitrate in one pass: every cross-source conflict, each paired with its
/// [`ConflictResolution`]. The order mirrors [`detect_conflicts`].
pub fn detect_and_arbitrate(
    sources: &[Source],
    subject_threshold: f64,
) -> Vec<(Conflict, ConflictResolution)> {
    detect_conflicts(sources, subject_threshold)
        .into_iter()
        .map(|c| {
            let r = arbitrate(&c, sources);
            (c, r)
        })
        .collect()
}

/// Attribute each claim to its supporting source(s) by lexical containment `>= threshold`,
/// scored per source sentence (max over sentences). A claim with no content tokens is
/// vacuously supported with no sources.
pub fn attribute(sources: &[Source], claims: &[Claim], threshold: f64) -> Vec<Attribution> {
    // Precompute each source's per-sentence content-token sets once.
    let source_sents: Vec<(String, Vec<BTreeSet<String>>)> = sources
        .iter()
        .map(|s| {
            let sents: Vec<BTreeSet<String>> = split_sentences(&s.text)
                .iter()
                .map(|sent| content_tokens(sent))
                .collect();
            // A source with no sentence-splitting still contributes its whole text.
            let sents = if sents.is_empty() {
                vec![content_tokens(&s.text)]
            } else {
                sents
            };
            (s.id.clone(), sents)
        })
        .collect();

    let mut out = Vec::with_capacity(claims.len());
    for (idx, claim) in claims.iter().enumerate() {
        let ctoks = content_tokens(&claim.text);
        if ctoks.is_empty() {
            out.push(Attribution {
                claim_index: idx,
                claim_text: claim.text.clone(),
                supported: true,
                sources: Vec::new(),
            });
            continue;
        }
        let mut supporting: Vec<SupportingSource> = Vec::new();
        for (sid, sents) in &source_sents {
            let mut best = 0.0f64;
            for stoks in sents {
                let c = containment(&ctoks, stoks);
                if c > best {
                    best = c;
                }
            }
            if best >= threshold {
                supporting.push(SupportingSource {
                    source_id: sid.clone(),
                    score: best,
                });
            }
        }
        // Strongest support first; ties broken by id for determinism.
        supporting.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.source_id.cmp(&b.source_id))
        });
        out.push(Attribution {
            claim_index: idx,
            claim_text: claim.text.clone(),
            supported: !supporting.is_empty(),
            sources: supporting,
        });
    }
    out
}

/// Full pass: dedup → conflict-detect → attribute → faithfulness → coverage, all over the
/// canonical (deduplicated) source set so mirrors count once everywhere.
pub fn synthesize(
    sources: &[Source],
    claims: &[Claim],
    config: &SynthesisConfig,
) -> SynthesisReport {
    let dedup = dedup_sources(sources, config.dedup_jaccard);

    // Canonical source objects, in canonical_ids order.
    let canonical: Vec<Source> = dedup
        .canonical_ids
        .iter()
        .filter_map(|id| sources.iter().find(|s| &s.id == id).cloned())
        .collect();

    let conflicts = detect_conflicts(&canonical, config.conflict_subject_jaccard);
    let attributions = attribute(&canonical, claims, config.support_containment);

    // Faithfulness.
    let unsupported_claims: Vec<usize> = attributions
        .iter()
        .filter(|a| !a.supported)
        .map(|a| a.claim_index)
        .collect();
    let total = attributions.len();
    let supported = total - unsupported_claims.len();
    let groundedness = if total == 0 {
        1.0
    } else {
        supported as f64 / total as f64
    };

    // Coverage.
    let mut used: BTreeSet<String> = BTreeSet::new();
    for a in &attributions {
        for s in &a.sources {
            used.insert(s.source_id.clone());
        }
    }
    let used_sources: Vec<String> = used.iter().cloned().collect();
    let unused_sources: Vec<String> = canonical
        .iter()
        .map(|s| s.id.clone())
        .filter(|id| !used.contains(id))
        .collect::<BTreeSet<String>>()
        .into_iter()
        .collect();
    let used_data_class = canonical
        .iter()
        .filter(|s| used.contains(&s.id))
        .map(|s| s.data_class)
        .max_by_key(|dc| dc.sensitivity());

    SynthesisReport {
        dedup,
        conflicts,
        attributions,
        unsupported_claims,
        groundedness,
        used_sources,
        unused_sources,
        used_data_class,
    }
}

// ---------------------------------------------------------------------------------------
// The composed answer-verification gate (the live output-lint seam)
// ---------------------------------------------------------------------------------------

use rederive::{numeric_gate, NumericClaim, NumericGateOutcome, Rederiver, Tolerance};

/// Why a candidate answer is blocked from shipping — the union of every failing gate. Each is a
/// hard block for payments data (`STRUCTURED_FEDERATED_RETRIEVAL.md` §5, `CONTEXT_FABRIC.md` §3).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BlockReason {
    /// A prose claim has no supporting source (a hallucination / ungrounded statement).
    UnsupportedClaim {
        claim_index: usize,
        claim_text: String,
    },
    /// Two sources contradict and neither authority nor recency could arbitrate — a human must
    /// decide; the answer must NOT ship an arbitrarily-picked value.
    UnresolvedConflict { subject: Vec<String> },
    /// A stated number failed the numeric contract or server-side re-derivation (§5).
    NumericGateFailed,
}

/// The full ship/block verdict for a candidate answer over its retrieved sources. Composes the
/// three previously-standalone gates — faithfulness ([`synthesize`]), cross-source conflict
/// arbitration ([`detect_and_arbitrate`]), and the numeric re-derivation gate
/// ([`rederive::numeric_gate`]) — into one decision a surface makes before an answer streams to a
/// user. This is the entrypoint the design's "output-lint seam" calls; the individual analyses
/// remain public for finer-grained callers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnswerVerification {
    pub synthesis: SynthesisReport,
    /// Every detected cross-source conflict with its arbitration outcome (winner/loser/basis).
    pub resolutions: Vec<(Conflict, ConflictResolution)>,
    pub numeric: NumericGateOutcome,
    /// Every reason the answer is blocked; empty ⇒ the answer may ship.
    pub blocked: Vec<BlockReason>,
}

impl AnswerVerification {
    /// True iff nothing blocks the answer.
    pub fn ships(&self) -> bool {
        self.blocked.is_empty()
    }
}

/// Policy knobs for [`verify_answer`] — what counts as a hard block for this surface.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct VerificationPolicy {
    /// Block if ANY claim is unsupported (strict groundedness). Payments surfaces set this.
    pub block_on_unsupported: bool,
    /// Block if any cross-source conflict is [`ResolutionBasis::Unresolved`].
    pub block_on_unresolved_conflict: bool,
    /// Block if the numeric gate (contract lint + re-derivation) does not pass.
    pub block_on_numeric_gate: bool,
    pub synthesis: SynthesisConfig,
    pub tolerance: Tolerance,
}

impl Default for VerificationPolicy {
    fn default() -> Self {
        // The payments-safe default: every gate hard-blocks.
        VerificationPolicy {
            block_on_unsupported: true,
            block_on_unresolved_conflict: true,
            block_on_numeric_gate: true,
            synthesis: SynthesisConfig::default(),
            tolerance: Tolerance::default(),
        }
    }
}

/// The single answer-path verification gate. Runs faithfulness + conflict arbitration + the
/// numeric re-derivation gate over `sources`, the candidate `answer` prose, and its declared
/// typed `numeric_claims`, and returns a combined [`AnswerVerification`] with every block reason.
///
/// Fail-closed by default (see [`VerificationPolicy`]): an ungrounded claim, an unresolved
/// contradiction, or a number that fails its contract / re-derivation all block. The `rederiver`
/// is the read-replica/tool re-execution seam (`rederive::Rederiver`) — a real deployment plugs in
/// the live executor; the gate itself is complete and tested here.
pub fn verify_answer(
    sources: &[Source],
    answer: &str,
    numeric_claims: &[NumericClaim],
    rederiver: &dyn Rederiver,
    policy: &VerificationPolicy,
) -> AnswerVerification {
    let claims = claims_from_text(answer);
    let synthesis = synthesize(sources, &claims, &policy.synthesis);
    // Arbitrate over the RAW sources, not the deduped set: two sources that differ ONLY in a
    // number (`fee is 5` vs `fee is 10`) have identical content tokens (numbers live in the typed
    // value, not the subject) and would collapse as "mirrors" under dedup — which would silently
    // hide a real numeric contradiction. Conflict detection must see every source; genuine
    // mirrors carry the SAME value and register as agreement, so they never false-positive.
    let resolutions = detect_and_arbitrate(sources, policy.synthesis.conflict_subject_jaccard);
    let numeric = numeric_gate(answer, numeric_claims, rederiver, &policy.tolerance);

    let mut blocked = Vec::new();
    if policy.block_on_unsupported {
        for a in &synthesis.attributions {
            if !a.supported {
                blocked.push(BlockReason::UnsupportedClaim {
                    claim_index: a.claim_index,
                    claim_text: a.claim_text.clone(),
                });
            }
        }
    }
    if policy.block_on_unresolved_conflict {
        for (_, r) in &resolutions {
            if r.basis == ResolutionBasis::Unresolved {
                blocked.push(BlockReason::UnresolvedConflict {
                    subject: r.subject.clone(),
                });
            }
        }
    }
    if policy.block_on_numeric_gate && !numeric.ships() {
        blocked.push(BlockReason::NumericGateFailed);
    }

    AnswerVerification {
        synthesis,
        resolutions,
        numeric,
        blocked,
    }
}

impl AnswerVerification {
    /// True iff at least one stated figure differed from the server's independent recomputation —
    /// the payment-incident signal the ledger gate exists to catch (fed to the eval/incident
    /// platform, `STRUCTURED_FEDERATED_RETRIEVAL.md` §5.2). Distinct from [`AnswerVerification::ships`]:
    /// an answer can be blocked for an unsourced/not-reproducible figure without a value *mismatch*.
    pub fn blocked_on_mismatch(&self) -> bool {
        self.numeric.rederivation.has_mismatch()
    }
}

// ---------------------------------------------------------------------------------------
// The ledger-class answer gate — the `from_engine_verified`-style numeric default (gap BH)
// ---------------------------------------------------------------------------------------

use std::collections::BTreeMap;

use rederive::ClaimSource;

/// The data-class floor at/above which an answer grounded on such a source is treated as
/// **ledger-class** — the payments tier (settlement / reconciliation / ledger data) where a
/// confidently-wrong figure is an *incident*, not merely a bad answer. At/above this floor the
/// server-side numeric re-derivation gate is armed as a HARD block by default; below it, ordinary
/// prose numbers are left to the normal path so the gate never over-blocks casual answers.
pub const LEDGER_CLASS_FLOOR: DataClass = DataClass::Confidential;

/// True iff any grounding source is at/above `floor` — i.e. the answer rests on ledger-class data
/// and its numbers MUST be re-derived server-side before it may ship.
pub fn is_ledger_class_at(sources: &[Source], floor: DataClass) -> bool {
    sources.iter().any(|s| s.data_class >= floor)
}

/// True iff any grounding source is at/above the default [`LEDGER_CLASS_FLOOR`].
pub fn is_ledger_class(sources: &[Source]) -> bool {
    is_ledger_class_at(sources, LEDGER_CLASS_FLOOR)
}

/// A production server-side re-deriver: it reproduces a claim's value from the governed
/// structured-retrieval result **the runtime itself computed** (server truth), never from anything
/// the model emitted. This is the concrete DEFAULT a verified ledger surface installs in place of a
/// fail-closed reproduce-nothing placeholder: a correctly-sourced figure re-derives and the answer
/// SHIPS, while a figure that differs from the server's own recomputation is BLOCKED
/// (blocked-on-mismatch). Deterministic + offline — it holds the values the deterministic path
/// already produced, keyed by each claim source's stable `rederive_key`, and re-runs the diff
/// independently of the model. A real deployment builds it from the read-replica query / sandbox
/// tool result that grounded the answer (`STRUCTURED_FEDERATED_RETRIEVAL.md` §5.2); the diff-or-block
/// contract is identical either way.
#[derive(Debug, Clone, Default)]
pub struct SourceRederiver {
    truth: BTreeMap<String, f64>,
}

impl SourceRederiver {
    /// An empty re-deriver — reproduces nothing until server-truth values are registered (so it
    /// fail-closes exactly like the reproduce-nothing placeholder until populated).
    pub fn new() -> Self {
        SourceRederiver::default()
    }

    /// Register the server-side value for a catalog-metric claim (its `metric:{id}:{query_hash}`
    /// key) — the value the deterministic path computed for that exact compiled query.
    pub fn with_metric(mut self, id: &str, query_hash: &str, value: f64) -> Self {
        self.truth
            .insert(format!("metric:{id}:{query_hash}"), value);
        self
    }

    /// Register the server-side value for a deterministic-tool claim (its `tool:{call_id}` key).
    pub fn with_tool(mut self, call_id: &str, value: f64) -> Self {
        self.truth.insert(format!("tool:{call_id}"), value);
        self
    }

    /// The number of registered server-truth values.
    pub fn len(&self) -> usize {
        self.truth.len()
    }

    /// True iff no server-truth value is registered.
    pub fn is_empty(&self) -> bool {
        self.truth.is_empty()
    }
}

impl Rederiver for SourceRederiver {
    fn rederive(&self, source: &ClaimSource) -> Option<f64> {
        self.truth.get(&source.rederive_key()?).copied()
    }
}

/// GAP-AUDIT gap6-synthesis-teams-scheduler — DECISION: `LedgerAnswerGate`/[`CompiledWindow::
/// verify_ledger_answer`](../ainxt_context/struct.CompiledWindow.html#method.verify_ledger_answer) is
/// NOT wired into the live `/v1/chat` served path (`ainxt-convo`'s `verify_answer_live_rederived` call
/// sites), and after investigation this is the CORRECT state, not an unclosed gap.
///
/// The two mechanisms are not interchangeable — they arm on different signals and require different
/// inputs:
///
/// * `LedgerAnswerGate` arms the CONTRACT numeric leg ([`rederive::numeric_gate`] /
///   [`rederive::lint_numeric_claims`]) by [`is_ledger_class`] — the grounding **source's**
///   `DataClass`. That lint requires a typed [`rederive::NumericClaim`] contract: a caller who already
///   knows the compiled query/metric behind each figure. Grep across `ainxt-convo`, `ainxt-runtimed`,
///   and `ainxt-server` finds **zero** `NumericClaim` construction anywhere outside tests — the served
///   chat surface has no such contract; the model emits prose, never typed claims.
/// * The live path's own numeric leg (`extract_ledger_figures` / `rederive_ledger_figures`, wired via
///   `verify_answer_live_rederived`) arms per-SENTENCE, on ledger/settlement/reconciliation vocabulary
///   ([`is_ledger_claim_subject`]), independent of the source's `DataClass`.
///
/// Naively substituting `LedgerAnswerGate::verify`/`verify_ledger_answer` into the live path (calling
/// it with an empty claims slice, since none exist there) does NOT add protection — it reintroduces,
/// and generalizes, the exact over-block regression round-14 fixed: `lint_numeric_claims` flags EVERY
/// prose number as `UnbackedProseNumber` when the contract is empty, so any answer grounded on so much
/// as one `Confidential`+ source would hard-block on ANY number in it, benign or not. This is not
/// hypothetical — `ainxt-synthesis/tests/r14_numeric_gate_live.rs`'s
/// `r14_numeric_gate_ships_benign_number_and_no_claim_answer` is a standing, deliberately-written test
/// that asserts a benign incidental number ("UPI was launched in 2016...") SHIPS even though its only
/// grounding source is `DataClass::Confidential` — i.e. the codebase already tested against and
/// rejected `DataClass`-armed blanket blocking on the prose path. Widening the live gate's arming to
/// "ledger-class source ⇒ every number is a claim" would break that test and, in production, would
/// hard-block most numeric answers on an internal engineering platform where many grounding documents
/// are tagged `Confidential` by default for reasons unrelated to payments figures.
///
/// `LedgerAnswerGate` is therefore scoped to a genuinely different, NOT-YET-BUILT caller: a served
/// surface that answers directly from a compiled structured query (`ainxt-runtimed::governed`'s
/// `served_structured_turn` / `StructuredQueryTool` produce a `CompiledStructuredQuery`, and
/// [`rederive::synthesize_numeric_claim`] can turn that into a typed `NumericClaim` — but nothing in the
/// composition root today splices that claim into a rendered answer and runs `LedgerAnswerGate` over
/// it). Building that structured-answer serving mode is a materially larger, separate feature than
/// "wire an existing call"; forcing the wire without it, using empty claims, is a regression, not a
/// fix. No code change: `LedgerAnswerGate`, `is_ledger_class`, `is_ledger_class_at`, and
/// `LEDGER_CLASS_FLOOR` stay as a complete, unit-tested primitive (exercised via
/// `ainxt-context/tests/r7_ledger_rederivation.rs`) ready for that future caller.
///
/// Separately confirmed non-gap: [`extract_ledger_figures`] and [`rederive_ledger_figures`] are a
/// legitimate parallel pair, not a missing-logic gap — both are thin callers of the shared private
/// `ledger_figures_inner`; `extract_ledger_figures` is simply the "no server re-derivation available"
/// degenerate case (`recomputed = &[]`, source-text re-reading only), used by [`verify_answer_live`]
/// and directly by the round-14 test suite, while `rederive_ledger_figures` is the §5.2 form the live
/// served path actually calls (`ainxt-convo`), supplying the turn's own re-executed
/// [`ClaimSource`]s. Neither is missing anything the other has; they share one implementation by
/// construction.
///
/// The **numeric `from_engine_verified` default** — the ledger-class answer gate a payments surface
/// installs by default. It composes the payments-safe [`VerificationPolicy`] (fail-closed; every
/// sub-gate hard-blocks) with a server-side [`Rederiver`] and answers the one question a surface
/// asks before an answer streams: *may this answer ship?*
///
/// * When the answer rests on **ledger-class** sources (any source at/above the configured floor),
///   the full fail-closed verification runs — faithfulness + cross-source conflict + numeric
///   re-derivation — and the numeric gate is a HARD block: the answer ships iff every stated figure
///   re-derives from the server's own data, and is BLOCKED on any mismatch (blocked-on-mismatch).
/// * Otherwise the numeric hard-block is disarmed (`block_on_numeric_gate = false`) so ordinary
///   prose numbers are never over-blocked; the non-numeric gates still run.
///
/// This is the default the surface uses; a deployment overrides only the [`Rederiver`] (to the live
/// read-replica / sandbox re-executor) and, if needed, the policy or the floor.
pub struct LedgerAnswerGate<R: Rederiver> {
    rederiver: R,
    policy: VerificationPolicy,
    floor: DataClass,
}

impl<R: Rederiver> LedgerAnswerGate<R> {
    /// The `from_engine_verified`-style default: payments-safe policy, the default
    /// [`LEDGER_CLASS_FLOOR`], and the given server-side re-deriver.
    pub fn from_engine_verified(rederiver: R) -> Self {
        LedgerAnswerGate {
            rederiver,
            policy: VerificationPolicy::default(),
            floor: LEDGER_CLASS_FLOOR,
        }
    }

    /// Override the verification policy (which sub-gates hard-block).
    pub fn with_policy(mut self, policy: VerificationPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Override the ledger-class data-class floor.
    pub fn with_floor(mut self, floor: DataClass) -> Self {
        self.floor = floor;
        self
    }

    /// Whether these sources arm the hard numeric gate (i.e. the answer is ledger-class).
    pub fn is_armed(&self, sources: &[Source]) -> bool {
        is_ledger_class_at(sources, self.floor)
    }

    /// Gate a candidate answer over its grounding `sources` and declared numeric `claims`. The
    /// numeric hard-block is armed only for ledger-class sources; everything else in the payments
    /// policy always runs. Returns the full [`AnswerVerification`] — `ships()` is the ship/block
    /// decision, `blocked_on_mismatch()` the incident signal.
    pub fn verify(
        &self,
        sources: &[Source],
        answer: &str,
        claims: &[NumericClaim],
    ) -> AnswerVerification {
        let mut policy = self.policy;
        if !self.is_armed(sources) {
            policy.block_on_numeric_gate = false;
        }
        verify_answer(sources, answer, claims, &self.rederiver, &policy)
    }
}

// ---------------------------------------------------------------------------------------
// Live-path (contract-free) ledger-number verification — the served /v1/chat default (gap BH)
// ---------------------------------------------------------------------------------------
//
// The typed numeric-claim contract ([`rederive::NumericClaim`]) + [`rederive::numeric_gate`] are the
// *contract* path: a caller (e.g. the structured-federated pipeline) that KNOWS the compiled query
// behind each figure supplies typed claims, and an unbacked prose number is a hard finding. But the
// live served /v1/chat surface has no such contract — the model returns prose, not typed claims — so
// running the contract lint there with an EMPTY claim set flags EVERY prose number as unbacked and
// blocks it. That is the over-block this path fixes: on the live path the gate must EXTRACT the
// genuine ledger claims itself and block ONLY on a real re-derivation failure, leaving benign numbers
// (a launch year, a step count, a latency) and no-claim answers to ship (redact-don't-block).

/// Domain terms that mark a numeric statement as a genuine **ledger / metric claim**: a figure
/// computed over payment/settlement data whose correctness is a payment *incident* concern. This is
/// the discriminator that makes the live gate functional rather than over-blocking: a number is
/// treated as a ledger claim (and therefore MUST re-derive) only when its own sentence carries
/// settlement/reconciliation vocabulary. An incidental number carries none of these terms and ships.
const LEDGER_LEXICON: &[&str] = &[
    "settlement",
    "settlements",
    "settle",
    "settled",
    "settling",
    "reconciliation",
    "reconciliations",
    "reconcile",
    "reconciled",
    "reconciling",
    "recon",
    "ledger",
    "ledgers",
    "netting",
    "clearing",
    "disbursement",
    "disbursements",
    "payout",
    "payouts",
    "chargeback",
    "chargebacks",
    "interchange",
    "remittance",
    "remittances",
    "debit",
    "debits",
    "credit",
    "credits",
    "refund",
    "refunds",
];

/// True iff a sentence's subject tokens carry a ledger/metric domain term — i.e. the number it
/// states is a genuine ledger claim that must be re-derived, not a benign incidental figure.
fn is_ledger_claim_subject(subject: &BTreeSet<String>) -> bool {
    subject.iter().any(|t| LEDGER_LEXICON.contains(&t.as_str()))
}

/// How a ledger figure stated in the answer classified against the grounding sources.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LedgerFigureVerdict {
    /// A grounding source quantifies the same subject with a matching value → the figure re-derives
    /// and ships, with the source it re-derived against recorded for lineage.
    Verified {
        source_id: String,
        source_value: f64,
    },
    /// A grounding source quantifies the same subject with a DIFFERENT value → BLOCK. This is the
    /// real re-derivation mismatch — the fabricated / mis-stated figure the gate exists to catch.
    Mismatch {
        source_id: String,
        source_value: f64,
        tolerance: f64,
    },
    /// No grounding source quantifies the subject, so the ledger figure cannot be re-derived → BLOCK
    /// (fail-closed: a payment figure the deterministic path can't independently reproduce is never
    /// shipped as verified — the same fail-closed semantics as [`rederive::RederiveFailure`]).
    Unreproducible,
}

/// One genuine ledger figure the answer stated, with its re-derivation verdict.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LedgerFigureFinding {
    /// The ledger-claim subject tokens (sorted).
    pub subject: Vec<String>,
    /// The number the answer stated.
    pub stated: f64,
    pub verdict: LedgerFigureVerdict,
}

impl LedgerFigureFinding {
    fn ships(&self) -> bool {
        matches!(self.verdict, LedgerFigureVerdict::Verified { .. })
    }
}

/// The verdict of the live-path (contract-free) ledger-number gate over a candidate answer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LiveNumericReport {
    /// One entry per genuine ledger figure found in the answer. Benign numbers and no-claim answers
    /// produce no entries, so their report is empty and ships.
    pub findings: Vec<LedgerFigureFinding>,
}

impl LiveNumericReport {
    /// True iff every extracted ledger figure re-derived — the only state in which the numbers ship.
    pub fn ships(&self) -> bool {
        self.findings.iter().all(LedgerFigureFinding::ships)
    }

    /// True iff at least one figure contradicted its grounding source — the incident-adjacent signal.
    pub fn has_mismatch(&self) -> bool {
        self.findings
            .iter()
            .any(|f| matches!(f.verdict, LedgerFigureVerdict::Mismatch { .. }))
    }
}

/// Extract genuine ledger/metric claims from a candidate `answer` WITHOUT a typed contract, and
/// re-derive each against the material that grounded the answer (`STRUCTURED_FEDERATED_RETRIEVAL.md`
/// §5.2, gap BH) — the served /v1/chat default.
///
/// For every sentence in the answer that states a number AND carries ledger vocabulary
/// ([`is_ledger_claim_subject`]), the runtime independently re-reads the figure the grounding
/// `sources` carry for the same subject (subject lexical containment `>= support_containment`,
/// mirroring the faithfulness attribution threshold) and diffs it:
///
/// * a source value matching within `tolerance` → [`LedgerFigureVerdict::Verified`] (ships);
/// * a source value that differs → [`LedgerFigureVerdict::Mismatch`] (BLOCK — the payment incident);
/// * no source quantifies the subject → [`LedgerFigureVerdict::Unreproducible`] (fail-closed BLOCK).
///
/// A number whose sentence carries NO ledger vocabulary is not a ledger claim: it is skipped
/// entirely, so a benign incidental figure and a no-claim answer both produce an empty, shipping
/// report. This is what makes the served gate functional instead of over-blocking every prose number.
pub fn extract_ledger_figures(
    answer: &str,
    sources: &[Source],
    support_containment: f64,
    tolerance: &Tolerance,
) -> LiveNumericReport {
    // No server re-derivation available on this call: fall back to source-text re-reading only.
    ledger_figures_inner(answer, sources, support_containment, tolerance, &[])
}

/// The **server-side re-derivation** form of the live gate (`STRUCTURED_FEDERATED_RETRIEVAL.md`
/// §5.2) — the one the design actually specifies, and the one the served path must use whenever the
/// turn read a structured source.
///
/// `turn_sources` are the [`ClaimSource`]s the RUNTIME itself recorded for this turn (e.g. the
/// `(metric_id, query_hash)` of every compiled structured query the turn executed) — never anything
/// the model asserted. For each one, `rederiver` **independently re-executes the same compiled
/// query server-side** and returns the freshly recomputed value. Every genuine ledger figure the
/// answer states is then diffed against those recomputations:
///
/// * a recomputation agreeing within tolerance → [`LedgerFigureVerdict::Verified`] (ships);
/// * recomputations exist but none agrees → [`LedgerFigureVerdict::Mismatch`] (BLOCK) — this is the
///   case the source-text-only gate CANNOT catch, because a retrieved chunk can carry the same
///   stale/wrong figure the model stated and "verify" it;
/// * the runtime recorded no re-derivable source (an ordinary RAG turn) → fall back to
///   [`extract_ledger_figures`]'s source-text re-reading, so a non-structured turn is unaffected.
///
/// The re-derivation identity is recorded on the verdict's `source_id` as `rederive:<key>` (the
/// [`ClaimSource::rederive_key`]), so lineage shows the answer was verified against a server
/// recomputation rather than against the text it was generated from.
pub fn rederive_ledger_figures(
    answer: &str,
    sources: &[Source],
    support_containment: f64,
    tolerance: &Tolerance,
    rederiver: &dyn Rederiver,
    turn_sources: &[ClaimSource],
) -> LiveNumericReport {
    // Independently re-execute EVERY source the runtime recorded for this turn, once.
    let recomputed: Vec<(String, f64)> = turn_sources
        .iter()
        .filter_map(|s| {
            let key = s.rederive_key()?;
            let value = rederiver.rederive(s)?;
            Some((format!("rederive:{key}"), value))
        })
        .collect();
    ledger_figures_inner(answer, sources, support_containment, tolerance, &recomputed)
}

/// Shared implementation of the live ledger-figure gate. `recomputed` carries any **server-side
/// re-derivations** for this turn; when non-empty it is AUTHORITATIVE (a server recomputation
/// outranks re-reading the same text the answer was generated from), and the source-text pass is
/// used only as the fallback for turns with nothing re-derivable.
fn ledger_figures_inner(
    answer: &str,
    sources: &[Source],
    support_containment: f64,
    tolerance: &Tolerance,
    recomputed: &[(String, f64)],
) -> LiveNumericReport {
    // Equal-value epsilon: the currency tolerance (paisa) is the general floor so representation
    // noise never registers as a mismatch, while any materially different figure does.
    let eps = tolerance.currency_abs.max(NUM_EPSILON);
    // Numeric facts the grounding sources independently quantify (the re-derivation ground truth).
    let src_facts: Vec<Fact> = sources.iter().flat_map(extract_facts).collect();
    // Treat the answer as a source so the SAME subject/number extraction applies to it.
    let answer_src = Source::new("__answer__", answer, DataClass::Public);

    let mut findings = Vec::new();
    for af in extract_facts(&answer_src) {
        let stated = match af.value {
            FactValue::Number(n) => n,
            _ => continue, // dates / polarity are not ledger figures
        };
        if !is_ledger_claim_subject(&af.subject) {
            continue; // benign incidental number — not a ledger claim, ships
        }
        // §5.2 FIRST: if the runtime independently re-executed this turn's structured query, that
        // recomputation — not the retrieved text — decides. A retrieved chunk can repeat the same
        // wrong figure the model stated; a fresh server-side execution cannot.
        if !recomputed.is_empty() {
            let agreeing = recomputed.iter().find(|(_, v)| (v - stated).abs() <= eps);
            let verdict = match agreeing {
                Some((key, v)) => LedgerFigureVerdict::Verified {
                    source_id: key.clone(),
                    source_value: *v,
                },
                None => {
                    let (key, v) = &recomputed[0];
                    LedgerFigureVerdict::Mismatch {
                        source_id: key.clone(),
                        source_value: *v,
                        tolerance: eps,
                    }
                }
            };
            findings.push(LedgerFigureFinding {
                subject: af.subject.into_iter().collect(),
                stated,
                verdict,
            });
            continue;
        }
        // Re-derive against the grounding source(s) that quantify this claim's subject.
        let mut verified: Option<(&Fact, f64)> = None;
        let mut differing: Option<(&Fact, f64)> = None;
        for sf in &src_facts {
            let sv = match sf.value {
                FactValue::Number(n) => n,
                _ => continue,
            };
            if containment(&af.subject, &sf.subject) < support_containment {
                continue;
            }
            if (sv - stated).abs() <= eps {
                verified = Some((sf, sv));
                break; // an agreeing source re-derives the figure — done
            }
            if differing.is_none() {
                differing = Some((sf, sv));
            }
        }
        let verdict = if let Some((sf, sv)) = verified {
            LedgerFigureVerdict::Verified {
                source_id: sf.source_id.clone(),
                source_value: sv,
            }
        } else if let Some((sf, sv)) = differing {
            LedgerFigureVerdict::Mismatch {
                source_id: sf.source_id.clone(),
                source_value: sv,
                tolerance: eps,
            }
        } else {
            LedgerFigureVerdict::Unreproducible
        };
        findings.push(LedgerFigureFinding {
            subject: af.subject.into_iter().collect(),
            stated,
            verdict,
        });
    }
    LiveNumericReport { findings }
}

/// The **live-path answer-verification gate** — the served /v1/chat default where the model does NOT
/// emit a typed numeric-claim contract. Runs the same faithfulness + cross-source conflict gates as
/// [`verify_answer`] (honoring `policy`), but replaces the contract numeric lint — which would
/// over-block every benign prose number when no contract is supplied — with contract-free
/// source-backed ledger verification ([`extract_ledger_figures`]): it appends
/// [`BlockReason::NumericGateFailed`] iff a genuine ledger figure fails to re-derive against its
/// grounding sources (a real mismatch, or a fail-closed unreproducible figure). Benign numbers and
/// no-claim answers therefore ship. The numeric block is applied only when `policy.block_on_numeric_gate`.
pub fn verify_answer_live(
    sources: &[Source],
    answer: &str,
    policy: &VerificationPolicy,
) -> AnswerVerification {
    // No re-derivation seam supplied → source-text re-reading only (the pre-§5.2 behaviour).
    let empty = SourceRederiver::new();
    verify_answer_live_rederived(sources, answer, policy, &empty, &[])
}

/// The live-path answer-verification gate **with independent server-side re-derivation**
/// (`STRUCTURED_FEDERATED_RETRIEVAL.md` §5.2) — the entrypoint a served turn should call whenever
/// it read a structured/metric source.
///
/// Identical to [`verify_answer_live`] (same faithfulness + cross-source conflict gates, same
/// redact-don't-block posture for benign numbers), except the numeric leg runs
/// [`rederive_ledger_figures`]: every ledger figure in the answer is diffed against a **fresh
/// server-side recomputation** of the turn's own compiled query (`turn_sources` = the
/// [`ClaimSource`]s the runtime recorded, `rederiver` = the executor that re-runs them), not against
/// the retrieved text the answer was generated from. A mismatch appends
/// [`BlockReason::NumericGateFailed`] exactly as before, and only when
/// `policy.block_on_numeric_gate` is set.
///
/// Passing an empty `turn_sources` (or a rederiver that reproduces nothing) degrades precisely to
/// [`verify_answer_live`], so an ordinary RAG turn is unaffected.
pub fn verify_answer_live_rederived(
    sources: &[Source],
    answer: &str,
    policy: &VerificationPolicy,
    rederiver: &dyn Rederiver,
    turn_sources: &[ClaimSource],
) -> AnswerVerification {
    // Base pass: faithfulness + cross-source conflict per policy, with the CONTRACT numeric lint
    // disarmed (there is no contract on the live path — an empty claim set would flag every prose
    // number). The CONTRACT gate is not the blocker on this path, so a reproduce-nothing
    // SourceRederiver suffices for it — the real re-derivation happens in the numeric leg below,
    // against `rederiver` + the runtime-recorded `turn_sources`.
    let mut base = *policy;
    base.block_on_numeric_gate = false;
    let no_claims: [NumericClaim; 0] = [];
    let empty = SourceRederiver::new();
    let mut verification = verify_answer(sources, answer, &no_claims, &empty, &base);

    if policy.block_on_numeric_gate {
        let live = rederive_ledger_figures(
            answer,
            sources,
            policy.synthesis.support_containment,
            &policy.tolerance,
            rederiver,
            turn_sources,
        );
        if !live.ships() {
            verification.blocked.push(BlockReason::NumericGateFailed);
        }
    }
    verification
}

// ---------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn src(id: &str, text: &str) -> Source {
        Source::new(id, text, DataClass::Internal)
    }

    // --- dedup ---------------------------------------------------------------------

    #[test]
    fn dedup_collapses_mirrors_and_keeps_distinct() {
        let sources = vec![
            src(
                "mirror_a",
                "UPI enables instant bank transfer between accounts",
            ),
            src(
                "mirror_b",
                "UPI enables instant bank transfer between accounts",
            ),
            // Same content words, different order/punctuation — still a mirror.
            src(
                "mirror_c",
                "Between accounts, UPI enables instant bank transfer.",
            ),
            src("distinct", "NEFT settles payments in half hourly batches"),
        ];
        let report = dedup_sources(&sources, DEFAULT_DEDUP_JACCARD);
        // Two clusters: the three UPI mirrors + the lone NEFT source.
        assert_eq!(report.canonical_ids.len(), 2);
        assert_eq!(report.canonical_ids, vec!["mirror_a", "distinct"]);
        let upi_group = report
            .groups
            .iter()
            .find(|g| g.representative == "mirror_a")
            .expect("upi cluster");
        assert_eq!(upi_group.duplicates, vec!["mirror_b", "mirror_c"]);
        let neft_group = report
            .groups
            .iter()
            .find(|g| g.representative == "distinct")
            .expect("neft cluster");
        assert!(neft_group.duplicates.is_empty());
    }

    // --- conflict detection --------------------------------------------------------

    #[test]
    fn numeric_conflict_flagged_with_subject() {
        let sources = vec![
            src("s1", "The UPI transaction fee is 5 rupees."),
            src("s2", "The UPI transaction fee is 10 rupees."),
        ];
        let conflicts = detect_conflicts(&sources, DEFAULT_CONFLICT_SUBJECT_JACCARD);
        assert_eq!(conflicts.len(), 1, "one numeric contradiction");
        let c = &conflicts[0];
        assert_eq!(c.kind, ConflictKind::Numeric);
        assert!(c.subject.contains(&"fee".to_string()));
        assert!(c.subject.contains(&"rupees".to_string()));
        // The two extracted numbers are surfaced.
        let vals: BTreeSet<&str> = [c.a.value.as_str(), c.b.value.as_str()]
            .into_iter()
            .collect();
        assert_eq!(vals, ["10", "5"].into_iter().collect());
        assert_ne!(c.a.source_id, c.b.source_id);
    }

    #[test]
    fn date_conflict_flagged() {
        let sources = vec![
            src("s1", "Settlement occurs on 2024-01-15."),
            src("s2", "Settlement occurs on 2024-02-20."),
        ];
        let conflicts = detect_conflicts(&sources, DEFAULT_CONFLICT_SUBJECT_JACCARD);
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].kind, ConflictKind::Date);
        assert!(conflicts[0].subject.contains(&"settlement".to_string()));
        let vals: BTreeSet<&str> = [conflicts[0].a.value.as_str(), conflicts[0].b.value.as_str()]
            .into_iter()
            .collect();
        assert_eq!(vals, ["2024-01-15", "2024-02-20"].into_iter().collect());
    }

    #[test]
    fn negation_conflict_flagged() {
        let sources = vec![
            src("s1", "UPI supports instant refunds"),
            src("s2", "UPI does not support instant refunds"),
        ];
        let conflicts = detect_conflicts(&sources, DEFAULT_CONFLICT_SUBJECT_JACCARD);
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].kind, ConflictKind::Negation);
        let vals: BTreeSet<&str> = [conflicts[0].a.value.as_str(), conflicts[0].b.value.as_str()]
            .into_iter()
            .collect();
        assert_eq!(vals, ["affirmed", "negated"].into_iter().collect());
    }

    #[test]
    fn agreeing_sources_do_not_conflict() {
        // Same subject, SAME number — agreement, not contradiction.
        let sources = vec![
            src("s1", "The UPI transaction fee is 5 rupees."),
            src("s2", "The UPI transaction fee is 5 rupees."),
        ];
        let conflicts = detect_conflicts(&sources, DEFAULT_CONFLICT_SUBJECT_JACCARD);
        assert!(conflicts.is_empty(), "identical facts are agreement");
    }

    #[test]
    fn unrelated_subjects_do_not_conflict() {
        // Different numbers but different subjects → not a conflict.
        let sources = vec![
            src("s1", "The UPI transaction fee is 5 rupees."),
            src("s2", "The NEFT settlement window is 30 minutes."),
        ];
        let conflicts = detect_conflicts(&sources, DEFAULT_CONFLICT_SUBJECT_JACCARD);
        assert!(conflicts.is_empty());
    }

    #[test]
    fn conflict_ignores_within_source_pairs() {
        // Two differing numbers on the same subject but in ONE source is not cross-source.
        let sources = vec![src("s1", "The fee is 5 rupees. The fee is 10 rupees.")];
        let conflicts = detect_conflicts(&sources, DEFAULT_CONFLICT_SUBJECT_JACCARD);
        assert!(conflicts.is_empty());
    }

    // --- conflict arbitration ------------------------------------------------------

    #[test]
    fn arbitrate_prefers_higher_authority_over_fresher() {
        // The wiki is FRESHER (t=100) but LOWER authority (1); the policy doc is older (t=1)
        // but authoritative (3). Authority must win — a fresh-but-unauthoritative number must
        // never override an authoritative one on payments data.
        let sources = vec![
            Source::new(
                "policy",
                "The UPI transaction fee is 5 rupees.",
                DataClass::Internal,
            )
            .with_authority(3)
            .with_timestamp(1),
            Source::new(
                "wiki",
                "The UPI transaction fee is 10 rupees.",
                DataClass::Internal,
            )
            .with_authority(1)
            .with_timestamp(100),
        ];
        let conflicts = detect_conflicts(&sources, DEFAULT_CONFLICT_SUBJECT_JACCARD);
        assert_eq!(conflicts.len(), 1);
        let res = arbitrate(&conflicts[0], &sources);
        assert_eq!(res.basis, ResolutionBasis::Authority);
        assert_eq!(res.winner.as_ref().unwrap().source_id, "policy");
        assert_eq!(res.winner.as_ref().unwrap().value, "5");
        assert_eq!(res.loser.as_ref().unwrap().source_id, "wiki");
        assert!(res.provenance.contains("authority"));
    }

    #[test]
    fn arbitrate_falls_back_to_recency_when_authority_ties() {
        // Equal authority → the fresher source wins.
        let sources = vec![
            Source::new(
                "old",
                "Settlement occurs on 2024-01-15.",
                DataClass::Internal,
            )
            .with_authority(2)
            .with_timestamp(10),
            Source::new(
                "new",
                "Settlement occurs on 2024-02-20.",
                DataClass::Internal,
            )
            .with_authority(2)
            .with_timestamp(20),
        ];
        let conflicts = detect_conflicts(&sources, DEFAULT_CONFLICT_SUBJECT_JACCARD);
        let res = arbitrate(&conflicts[0], &sources);
        assert_eq!(res.basis, ResolutionBasis::Recency);
        assert_eq!(res.winner.as_ref().unwrap().source_id, "new");
        assert_eq!(res.loser.as_ref().unwrap().source_id, "old");
    }

    #[test]
    fn arbitrate_escalates_when_both_signals_silent() {
        // No authority, no timestamps on either side — the safe outcome is Unresolved, NOT an
        // arbitrary pick.
        let sources = vec![
            Source::new(
                "a",
                "The UPI transaction fee is 5 rupees.",
                DataClass::Internal,
            ),
            Source::new(
                "b",
                "The UPI transaction fee is 10 rupees.",
                DataClass::Internal,
            ),
        ];
        let conflicts = detect_conflicts(&sources, DEFAULT_CONFLICT_SUBJECT_JACCARD);
        let res = arbitrate(&conflicts[0], &sources);
        assert_eq!(res.basis, ResolutionBasis::Unresolved);
        assert!(res.winner.is_none());
        assert!(res.loser.is_none());
        assert!(res.provenance.contains("unresolved"));
    }

    #[test]
    fn arbitrate_authority_dominates_even_reversed_order() {
        // Authority on the SECOND fact — the winner selection must not depend on argument order.
        let sources = vec![
            Source::new("low", "The fee is 5 rupees.", DataClass::Internal).with_authority(1),
            Source::new("high", "The fee is 10 rupees.", DataClass::Internal).with_authority(9),
        ];
        let conflicts = detect_conflicts(&sources, DEFAULT_CONFLICT_SUBJECT_JACCARD);
        let res = arbitrate(&conflicts[0], &sources);
        assert_eq!(res.basis, ResolutionBasis::Authority);
        assert_eq!(res.winner.as_ref().unwrap().source_id, "high");
    }

    #[test]
    fn detect_and_arbitrate_pairs_every_conflict() {
        let sources = vec![
            Source::new("p", "The fee is 5 rupees.", DataClass::Internal).with_authority(5),
            Source::new("w", "The fee is 10 rupees.", DataClass::Internal).with_authority(1),
        ];
        let pairs = detect_and_arbitrate(&sources, DEFAULT_CONFLICT_SUBJECT_JACCARD);
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].1.basis, ResolutionBasis::Authority);
        assert_eq!(pairs[0].0.kind, ConflictKind::Numeric);
    }

    // --- attribution + faithfulness ------------------------------------------------

    #[test]
    fn claim_attributes_to_supporting_source() {
        let sources = vec![
            src("upi", "UPI enables instant bank transfer between accounts"),
            src("neft", "NEFT settles payments in half hourly batches"),
        ];
        let claims = vec![Claim::new(
            "UPI enables instant bank transfer between accounts",
        )];
        let attrs = attribute(&sources, &claims, DEFAULT_SUPPORT_CONTAINMENT);
        assert!(attrs[0].supported);
        assert_eq!(attrs[0].sources.len(), 1);
        assert_eq!(attrs[0].sources[0].source_id, "upi");
        assert!(
            (attrs[0].sources[0].score - 1.0).abs() < 1e-9,
            "full containment"
        );
    }

    #[test]
    fn fabricated_claim_flagged_unsupported() {
        let sources = vec![src(
            "upi",
            "UPI enables instant bank transfer between accounts",
        )];
        let claims = vec![Claim::new(
            "Aadhaar biometric authentication is mandatory for every wire",
        )];
        let attrs = attribute(&sources, &claims, DEFAULT_SUPPORT_CONTAINMENT);
        assert!(!attrs[0].supported);
        assert!(attrs[0].sources.is_empty());
    }

    #[test]
    fn groundedness_ratio_exact_on_mixed_answer() {
        let sources = vec![
            src("upi", "UPI enables instant bank transfer between accounts"),
            src("neft", "NEFT settles payments in half hourly batches"),
        ];
        let claims = vec![
            Claim::new("UPI enables instant bank transfer between accounts"), // supported by upi
            Claim::new("NEFT settles payments in batches"),                   // supported by neft
            Claim::new("UPI transfer between accounts"),                      // supported by upi
            Claim::new("Aadhaar is required for all UPI transactions"),       // fabricated
        ];
        let report = synthesize(&sources, &claims, &SynthesisConfig::default());
        assert_eq!(report.attributions.len(), 4);
        assert_eq!(report.unsupported_claims, vec![3]);
        assert!(
            (report.groundedness - 0.75).abs() < 1e-9,
            "3 of 4 grounded, got {}",
            report.groundedness
        );
    }

    // --- coverage ------------------------------------------------------------------

    #[test]
    fn coverage_reports_used_and_unused_over_deduped_set() {
        let sources = vec![
            src(
                "upi_a",
                "UPI enables instant bank transfer between accounts",
            ),
            src(
                "upi_b",
                "UPI enables instant bank transfer between accounts",
            ), // mirror
            src("weather", "The monsoon brought heavy rain to the coast"),
        ];
        let claims = vec![Claim::new(
            "UPI enables instant bank transfer between accounts",
        )];
        let report = synthesize(&sources, &claims, &SynthesisConfig::default());
        // Mirror collapsed: only the canonical upi_a and weather remain.
        assert_eq!(report.dedup.canonical_ids, vec!["upi_a", "weather"]);
        assert_eq!(report.used_sources, vec!["upi_a"]);
        assert_eq!(report.unused_sources, vec!["weather"]);
        assert!(!report.used_sources.contains(&"upi_b".to_string()));
    }

    #[test]
    fn used_data_class_is_max_sensitivity_of_used_sources() {
        let sources = vec![
            Source::new(
                "pub",
                "UPI enables instant bank transfer between accounts",
                DataClass::Public,
            ),
            Source::new(
                "reg",
                "Card settlement ledger reconciliation runs nightly",
                DataClass::RegulatedPayment,
            ),
            Source::new(
                "pii",
                "Customer home address details on file",
                DataClass::Pii,
            ),
        ];
        let claims = vec![
            Claim::new("UPI enables instant bank transfer between accounts"),
            Claim::new("Card settlement ledger reconciliation runs nightly"),
        ];
        let report = synthesize(&sources, &claims, &SynthesisConfig::default());
        // pub + reg used; pii unused → max sensitivity among USED is RegulatedPayment.
        assert_eq!(report.used_sources, vec!["pub", "reg"]);
        assert_eq!(report.used_data_class, Some(DataClass::RegulatedPayment));
    }

    // --- edge cases ----------------------------------------------------------------

    #[test]
    fn empty_sources_and_empty_answer_are_safe() {
        let empty = synthesize(&[], &[], &SynthesisConfig::default());
        assert!(
            (empty.groundedness - 1.0).abs() < 1e-9,
            "no claims = vacuously grounded"
        );
        assert!(empty.conflicts.is_empty());
        assert!(empty.used_sources.is_empty());
        assert_eq!(empty.used_data_class, None);

        // Sources but no answer: still safe, nothing used.
        let sources = vec![src("s", "some content about payments")];
        let no_answer = synthesize(&sources, &[], &SynthesisConfig::default());
        assert!((no_answer.groundedness - 1.0).abs() < 1e-9);
        assert_eq!(no_answer.unused_sources, vec!["s"]);

        // Answer but no sources: every claim is unsupported, groundedness 0.
        let claims = vec![
            Claim::new("Some confident claim"),
            Claim::new("Another one"),
        ];
        let no_sources = synthesize(&[], &claims, &SynthesisConfig::default());
        assert!((no_sources.groundedness - 0.0).abs() < 1e-9);
        assert_eq!(no_sources.unsupported_claims, vec![0, 1]);
    }

    #[test]
    fn claims_from_text_splits_on_sentence_boundaries() {
        let claims = claims_from_text("UPI is instant. NEFT is batched. Is RTGS real-time?");
        assert_eq!(claims.len(), 3);
        assert_eq!(claims[0].text, "UPI is instant");
        assert_eq!(claims[2].text, "Is RTGS real-time");
    }

    #[test]
    fn number_and_date_parsers_reject_non_values() {
        assert_eq!(parse_number("half-hourly"), None);
        assert_eq!(parse_number("rs5"), None); // letters present
        assert_eq!(parse_number("2024-01-15"), None); // internal dash → not a number
        assert_eq!(parse_number("1,000"), Some(1000.0));
        assert_eq!(parse_number("10.50"), Some(10.50));
        assert_eq!(parse_number("5%"), Some(5.0));
        assert_eq!(parse_date("2024-01-15"), Some("2024-01-15".to_string()));
        assert_eq!(parse_date("not-a-date"), None);
        assert_eq!(parse_date("10.50"), None); // two parts, no 4-digit year
    }

    #[test]
    fn report_serializes_to_json() {
        let sources = vec![src("s1", "The UPI fee is 5 rupees.")];
        let claims = vec![Claim::new("The UPI fee is 5 rupees")];
        let report = synthesize(&sources, &claims, &SynthesisConfig::default());
        let json = serde_json::to_string(&report).expect("serialize");
        // Not a round-trip-only test: assert a computed field is present with its value.
        assert!(json.contains("\"groundedness\":1"));
        let back: SynthesisReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, report);
    }

    // --- composed answer-verification gate (CTX-06 + CTX-09) -----------------------

    use rederive::{ClaimSource, NumericClaim, Rederiver, ValueClass};
    use std::collections::HashMap;

    /// A stub re-executor keyed by `rederive_key`.
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

    #[test]
    fn gap_ctx_06_verify_answer_blocks_on_bad_number_ships_on_good() {
        // A grounded answer whose stated number re-derives correctly ships.
        let sources = vec![src("m", "There were 47 failed settlements in the batch")];
        let claims = vec![NumericClaim::metric(
            47.0,
            "count",
            ValueClass::Exact,
            "failed_settlement_count",
            "h1",
        )];
        let good = MapRederiver::new(&[("metric:failed_settlement_count:h1", 47.0)]);
        let v = verify_answer(
            &sources,
            "There were 47 failed settlements in the batch",
            &claims,
            &good,
            &VerificationPolicy::default(),
        );
        assert!(
            v.ships(),
            "grounded + re-derivable answer must ship, blocked={:?}",
            v.blocked
        );

        // Same answer, but the server recomputes 52 → the numeric gate blocks it.
        let bad = MapRederiver::new(&[("metric:failed_settlement_count:h1", 52.0)]);
        let v2 = verify_answer(
            &sources,
            "There were 47 failed settlements in the batch",
            &claims,
            &bad,
            &VerificationPolicy::default(),
        );
        assert!(!v2.ships());
        assert!(v2.blocked.contains(&BlockReason::NumericGateFailed));
    }

    #[test]
    fn gap_ctx_09_verify_answer_blocks_unsupported_claim_and_unresolved_conflict() {
        // Two undated, unranked sources contradict on the fee → Unresolved → block. And the answer
        // adds an ungrounded claim → also block. Would FAIL before: nothing composed arbitration +
        // faithfulness into a single live gate.
        let sources = vec![
            src("a", "The UPI transaction fee is 5 rupees"),
            src("b", "The UPI transaction fee is 10 rupees"),
        ];
        let rd = MapRederiver::new(&[]);
        let answer = "Aadhaar biometric authentication is mandatory for every wire";
        let v = verify_answer(&sources, answer, &[], &rd, &VerificationPolicy::default());
        assert!(!v.ships());
        assert!(v
            .blocked
            .iter()
            .any(|b| matches!(b, BlockReason::UnsupportedClaim { .. })));
        assert!(v
            .blocked
            .iter()
            .any(|b| matches!(b, BlockReason::UnresolvedConflict { .. })));
        // The arbitration outcome is surfaced for audit.
        assert!(v
            .resolutions
            .iter()
            .any(|(_, r)| r.basis == ResolutionBasis::Unresolved));

        // With authority on one source, the conflict is arbitrated (not a blocker). The answer
        // takes the authoritative figure and backs it with a sourced, re-derivable numeric claim,
        // so it ships.
        let ranked = vec![
            Source::new(
                "policy",
                "The UPI transaction fee is 5 rupees",
                DataClass::Internal,
            )
            .with_authority(3),
            Source::new(
                "wiki",
                "The UPI transaction fee is 10 rupees",
                DataClass::Internal,
            )
            .with_authority(1),
        ];
        let fee_claim = vec![NumericClaim::metric(
            5.0,
            "INR",
            ValueClass::Currency,
            "upi_fee",
            "hfee",
        )];
        let rd2 = MapRederiver::new(&[("metric:upi_fee:hfee", 5.0)]);
        let v2 = verify_answer(
            &ranked,
            "The UPI transaction fee is 5 rupees",
            &fee_claim,
            &rd2,
            &VerificationPolicy::default(),
        );
        assert!(
            v2.ships(),
            "arbitrated conflict + grounded, re-derivable answer ships, blocked={:?}",
            v2.blocked
        );
        assert!(v2
            .resolutions
            .iter()
            .any(|(_, r)| r.basis == ResolutionBasis::Authority));
    }
}
