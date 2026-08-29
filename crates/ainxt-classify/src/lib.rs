// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! ainxt-classify — the AiNxt constrained-decoding label extractor.
//!
//! Design: `docs/architecture/CONVERSATION_INTELLIGENCE.md` (§1 "the runtime owns
//! control-flow; the model does understanding under constrained output"; §2 Stage-2
//! "constrained classifier — any model"; §5 capability-aware decoding).
//!
//! # Why this crate exists
//!
//! Weak / self-hosted OSS models (Qwen, Gemma, Kimi, GLM, …) do not reliably obey
//! "answer with one word". Asked for an intent they emit `The intent here is clearly:
//! QA.` or `"qa"` or `qa (though it could be a task)`. Frontier models with native
//! grammar-constrained decoding can be pinned to a single token, but the runtime must
//! behave **identically** whether or not the transport supports GBNF / JSON-schema
//! enforcement (`CONVERSATION_INTELLIGENCE.md` §5, requirement T6 "model-agnostic").
//!
//! So label extraction is split in two:
//!
//! 1. **The constraint instruction** — [`build_prompt`] renders a fixed-vocabulary
//!    prompt (`Reply with EXACTLY one of: a | b | c`). Where the transport supports
//!    grammar-constrained decoding this doubles as the human-readable mirror of the
//!    grammar; where it does not, it is the only steering the model gets.
//! 2. **The tolerant parser** — [`parse_label`] recovers the intended label from
//!    whatever prose the model actually returned, and [`classify_with_fallback`]
//!    guarantees the caller always gets *a* label so a downstream state machine never
//!    stalls on a blank classification.
//!
//! This crate is the taxonomy + extraction logic those two steps share. It sits behind
//! every classification seam in the runtime — intent detection, query-complexity tiering
//! (`models/classifier.py`'s successor), and semantic tool selection.
//!
//! # Extraction contract (the adversarial cases, designed first)
//!
//! For enterprise payments the failure that matters is a *confident wrong label*, so the
//! parser is deliberately conservative and every relaxation is graded down in confidence:
//!
//! * **Case-insensitive.** `QA`, `qa`, `Qa` all resolve to the canonical `qa`.
//! * **Prose / quote / punctuation tolerant.** `The intent is: "QA".` → `qa`.
//! * **Whole-token only — never a substring.** `qa` is *not* found inside `aqua`,
//!   `encode` does not match the label `code`, and `qa_result` does not match `qa`
//!   (an underscore is treated as a word character, so snake_case identifiers never
//!   trip a false positive). This is the single most important rule: a substring match
//!   would silently misroute a payment-adjacent request.
//! * **First appearance wins.** If several distinct labels appear, the earliest-positioned
//!   one is chosen — deterministically, tie-broken by [`LabelSet`] declaration order.
//! * **Confidence is graded.** An exact standalone label scores highest; resolution via
//!   an alias, a match buried in prose, or the presence of *more than one* distinct label
//!   each lower the score, so the runtime's Stage-3 "clarify if ambiguous" gate
//!   (`CONVERSATION_INTELLIGENCE.md` §2) can trigger on a low-confidence read instead of
//!   acting on a guess.
//!
//! # Purity & determinism
//!
//! No clock, no RNG, no I/O, no ML runtime, no regex engine — the whole-token scanner is
//! a hand-written pure function. The same `(output, LabelSet)` pair always yields the same
//! [`Classified`], which is what makes the forensic replay / behavioral-diffing discipline
//! (`GAP_ANALYSIS` X) possible for the classification seam. The only dependency is `serde`,
//! so a Surface Profile can declare its label taxonomy as data (config-first) and the
//! result can travel over the protocol.

use std::collections::HashSet;
use std::fmt;

use serde::{Deserialize, Serialize};

/// Confidence for an exact standalone canonical label (the whole cleaned output *is* the
/// label, e.g. `"qa"` or `"QA."`).
pub const CONF_EXACT_CANONICAL: f32 = 1.0;
/// Confidence for an exact standalone *alias* that resolved to its canonical (e.g. the
/// whole cleaned output is `quality_assurance`, an alias of `qa`). Lower than a canonical
/// hit because the model used an indirect surface form.
pub const CONF_EXACT_ALIAS: f32 = 0.9;
/// Confidence for a canonical label found as a whole token embedded in prose
/// (e.g. `The intent is: qa.`).
pub const CONF_EMBEDDED_CANONICAL: f32 = 0.75;
/// Confidence for an alias found as a whole token embedded in prose. Lowest single-label
/// tier: both indirect *and* loose.
pub const CONF_EMBEDDED_ALIAS: f32 = 0.6;
/// Multiplicative penalty applied when more than one distinct label appears in the output.
/// The first-appearing label still wins, but the ambiguity is surfaced as a lower score so
/// the clarify gate can fire.
pub const AMBIGUITY_FACTOR: f32 = 0.6;

/// A word character for whole-token boundary purposes: an alphanumeric or an underscore.
/// Underscore is included on purpose so that `qa` never matches inside `qa_result` and the
/// like — snake_case identifiers are common in engineering prose and must not misroute.
fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Trim only the *surrounding* non-word characters (quotes, punctuation, whitespace,
/// brackets, colons) from both ends, leaving the interior untouched. `'"qa".'` → `qa`;
/// `(co-pilot)` → `co-pilot`; `"..."` → `` (empty).
fn strip_affixes(s: &str) -> &str {
    s.trim_matches(|c: char| !is_word_char(c))
}

/// Find the byte offset of the first occurrence of `needle` in `hay` that stands as a
/// **whole token** — i.e. the character immediately before and after the match (if any)
/// is not a word character. Both arguments are expected to already be lowercased by the
/// caller. Returns `None` if `needle` is empty or occurs only as a substring of a larger
/// token.
fn find_whole_token(hay: &str, needle: &str) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    let mut start = 0usize;
    while start <= hay.len() {
        let rel = hay[start..].find(needle)?;
        let pos = start + rel;
        let before_ok = match hay[..pos].chars().next_back() {
            Some(c) => !is_word_char(c),
            None => true,
        };
        let after = pos + needle.len();
        let after_ok = match hay[after..].chars().next() {
            Some(c) => !is_word_char(c),
            None => true,
        };
        if before_ok && after_ok {
            return Some(pos);
        }
        // Advance exactly one character past the rejected match so the search continues on
        // a valid UTF-8 boundary without looping forever.
        let step = hay[pos..].chars().next().map_or(1, char::len_utf8);
        start = pos + step;
    }
    None
}

/// One allowed classification outcome: a `canonical` label plus any `aliases` (alternative
/// surface forms a model might emit) that resolve to it.
///
/// Aliases let the taxonomy stay stable while tolerating model vocabulary drift — e.g. a
/// canonical `doc_generation` with aliases `document`, `pdf`, `generate document`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Label {
    /// The canonical value returned by the parser and emitted in the prompt vocabulary.
    pub canonical: String,
    /// Alternative surface forms that resolve to `canonical`. Never emitted in the prompt.
    #[serde(default)]
    pub aliases: Vec<String>,
}

impl Label {
    /// A label with a canonical form and no aliases. Surrounding whitespace is trimmed.
    pub fn new(canonical: &str) -> Self {
        Label {
            canonical: canonical.trim().to_string(),
            aliases: Vec::new(),
        }
    }

    /// Builder: add a single alias.
    pub fn with_alias(mut self, alias: &str) -> Self {
        self.aliases.push(alias.trim().to_string());
        self
    }

    /// Builder: add several aliases at once.
    pub fn with_aliases<I, S>(mut self, aliases: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for a in aliases {
            self.aliases.push(a.as_ref().trim().to_string());
        }
        self
    }
}

/// What went wrong while constructing a [`LabelSet`]. Returned instead of panicking so a
/// declaratively-loaded (config-first) taxonomy with a mistake fails closed and loud.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LabelSetError {
    /// The label list was empty — a classifier with no vocabulary cannot classify.
    Empty,
    /// A label's canonical form was empty (or whitespace-only).
    EmptyCanonical,
    /// An alias under the named canonical was empty (or whitespace-only).
    EmptyAlias(String),
    /// The named surface form (a canonical or an alias) appears more than once across the
    /// set. Ambiguous vocabularies are rejected because a duplicate surface could resolve
    /// to two different labels — a silent misroute risk.
    DuplicateSurface(String),
}

impl fmt::Display for LabelSetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LabelSetError::Empty => write!(f, "label set is empty"),
            LabelSetError::EmptyCanonical => write!(f, "a label has an empty canonical form"),
            LabelSetError::EmptyAlias(c) => {
                write!(f, "label '{c}' has an empty alias")
            }
            LabelSetError::DuplicateSurface(s) => {
                write!(f, "surface form '{s}' is declared more than once")
            }
        }
    }
}

impl std::error::Error for LabelSetError {}

/// An ordered, validated vocabulary of [`Label`]s. Order is significant: it fixes the
/// prompt's presentation order and is the deterministic tie-break when two labels appear at
/// the same position in model output.
///
/// The interior is private and the only constructors ([`LabelSet::new`],
/// [`LabelSet::from_canonicals`], and `serde` deserialization) all run the same validation,
/// so a `LabelSet` value is *always* non-empty with unique, non-empty surface forms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawLabelSet")]
pub struct LabelSet {
    labels: Vec<Label>,
}

/// Deserialization shim so JSON/YAML-declared taxonomies pass through [`LabelSet::new`]'s
/// validation rather than bypassing it via a derived `Deserialize`.
#[derive(Deserialize)]
struct RawLabelSet {
    labels: Vec<Label>,
}

impl TryFrom<RawLabelSet> for LabelSet {
    type Error = LabelSetError;
    fn try_from(raw: RawLabelSet) -> Result<Self, Self::Error> {
        LabelSet::new(raw.labels)
    }
}

impl LabelSet {
    /// Build and validate a label set. Every canonical and alias is trimmed; the set is
    /// rejected if it is empty, has an empty surface form, or reuses any surface form
    /// (case-insensitively) across labels.
    pub fn new(labels: Vec<Label>) -> Result<Self, LabelSetError> {
        if labels.is_empty() {
            return Err(LabelSetError::Empty);
        }
        let mut seen: HashSet<String> = HashSet::new();
        let mut clean: Vec<Label> = Vec::with_capacity(labels.len());
        for lab in labels {
            let canonical = lab.canonical.trim().to_string();
            if canonical.is_empty() {
                return Err(LabelSetError::EmptyCanonical);
            }
            if !seen.insert(canonical.to_lowercase()) {
                return Err(LabelSetError::DuplicateSurface(canonical));
            }
            let mut aliases = Vec::with_capacity(lab.aliases.len());
            for a in &lab.aliases {
                let alias = a.trim().to_string();
                if alias.is_empty() {
                    return Err(LabelSetError::EmptyAlias(canonical));
                }
                if !seen.insert(alias.to_lowercase()) {
                    return Err(LabelSetError::DuplicateSurface(alias));
                }
                aliases.push(alias);
            }
            clean.push(Label { canonical, aliases });
        }
        Ok(LabelSet { labels: clean })
    }

    /// Convenience constructor for an alias-free vocabulary.
    pub fn from_canonicals<I, S>(canonicals: I) -> Result<Self, LabelSetError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        LabelSet::new(
            canonicals
                .into_iter()
                .map(|c| Label::new(c.as_ref()))
                .collect(),
        )
    }

    /// The labels in declaration order.
    pub fn labels(&self) -> &[Label] {
        &self.labels
    }

    /// The canonical forms in declaration order — the prompt vocabulary.
    pub fn canonicals(&self) -> impl Iterator<Item = &str> {
        self.labels.iter().map(|l| l.canonical.as_str())
    }

    /// Number of labels.
    pub fn len(&self) -> usize {
        self.labels.len()
    }

    /// Always `false` — a valid `LabelSet` is never empty (kept for API completeness / to
    /// satisfy the `len`-without-`is_empty` lint).
    pub fn is_empty(&self) -> bool {
        self.labels.is_empty()
    }

    /// Resolve any surface form (canonical or alias, case-insensitively, exact — no token
    /// scanning) to its canonical label, if it is in the vocabulary.
    pub fn resolve(&self, surface: &str) -> Option<&str> {
        let key = surface.trim().to_lowercase();
        for lab in &self.labels {
            if lab.canonical.to_lowercase() == key
                || lab.aliases.iter().any(|a| a.to_lowercase() == key)
            {
                return Some(lab.canonical.as_str());
            }
        }
        None
    }
}

/// A successful classification: the resolved canonical `label` plus a graded `confidence`
/// and the provenance flags the clarify gate keys off.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Classified {
    /// The resolved canonical label.
    pub label: String,
    /// Graded confidence in `(0.0, 1.0]`. See the `CONF_*` constants and [`AMBIGUITY_FACTOR`].
    pub confidence: f32,
    /// `true` if the label was reached via an alias rather than its canonical surface form.
    pub matched_via_alias: bool,
    /// `true` if more than one distinct label appeared in the output (first-appearance won).
    pub ambiguous: bool,
}

/// The always-a-label result of [`classify_with_fallback`]: a parsed [`Classified`] flat­tened
/// with a `fallback_used` flag, or the fallback label with `confidence == 0.0`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Resolution {
    /// The resolved label — parsed if possible, otherwise the caller's fallback.
    pub label: String,
    /// Graded confidence of a parse, or exactly `0.0` when the fallback was used.
    pub confidence: f32,
    /// Whether the (parsed) label was reached via an alias. Always `false` for a fallback.
    pub matched_via_alias: bool,
    /// Whether multiple labels appeared. Always `false` for a fallback.
    pub ambiguous: bool,
    /// `true` when parsing failed and the fallback label was substituted.
    pub fallback_used: bool,
}

/// Render a constrained-decoding instruction for `set`, prefixed by `instruction`.
///
/// The vocabulary is presented in declaration order, joined by ` | `, as
/// `Reply with EXACTLY one of: a | b | c`. Where the transport supports grammar /
/// JSON-schema-constrained decoding this is the human-readable mirror of the grammar;
/// where it does not, it is the model's only steering. An empty `instruction` yields just
/// the constraint block.
pub fn build_prompt(instruction: &str, set: &LabelSet) -> String {
    let choices = set.canonicals().collect::<Vec<_>>().join(" | ");
    let instruction = instruction.trim();
    let constraint = format!(
        "Reply with EXACTLY one of: {choices}\n\
         Respond with only the single label — no explanation, no punctuation, no quotes."
    );
    if instruction.is_empty() {
        constraint
    } else {
        format!("{instruction}\n\n{constraint}")
    }
}

/// Extract the single intended label from raw (possibly messy) model `output`.
///
/// Returns `None` only when no label or alias from `set` appears as a whole token. See the
/// crate-level docs for the full extraction contract; in brief: case-insensitive, prose /
/// quote / punctuation tolerant, whole-token only, first-appearance wins, confidence graded
/// down for alias / embedded / ambiguous matches.
pub fn parse_label(output: &str, set: &LabelSet) -> Option<Classified> {
    // Fast path: after stripping surrounding punctuation/quotes/whitespace the entire output
    // *is* a single label or alias. This is the clean, high-confidence case and, because the
    // interior is untouched, it can only ever be one label — no ambiguity is possible.
    let core = strip_affixes(output).to_lowercase();
    if !core.is_empty() {
        for lab in &set.labels {
            if core == lab.canonical.to_lowercase() {
                return Some(Classified {
                    label: lab.canonical.clone(),
                    confidence: CONF_EXACT_CANONICAL,
                    matched_via_alias: false,
                    ambiguous: false,
                });
            }
            if lab.aliases.iter().any(|a| a.to_lowercase() == core) {
                return Some(Classified {
                    label: lab.canonical.clone(),
                    confidence: CONF_EXACT_ALIAS,
                    matched_via_alias: true,
                    ambiguous: false,
                });
            }
        }
    }

    // Slow path: scan for labels/aliases embedded in surrounding prose, as whole tokens.
    let hay = output.to_lowercase();

    /// Per-label best whole-token hit: earliest byte position + whether it came via an alias.
    struct Hit {
        order: usize,
        pos: usize,
        via_alias: bool,
    }

    let mut hits: Vec<Hit> = Vec::new();
    for (order, lab) in set.labels.iter().enumerate() {
        let canonical_pos = find_whole_token(&hay, &lab.canonical.to_lowercase());
        let mut alias_pos: Option<usize> = None;
        for a in &lab.aliases {
            if let Some(p) = find_whole_token(&hay, &a.to_lowercase()) {
                alias_pos = Some(match alias_pos {
                    Some(cur) => cur.min(p),
                    None => p,
                });
            }
        }
        // Prefer the canonical surface when it appears no later than the earliest alias, so
        // `qa (aka q)` is reported as a canonical match, not an alias one.
        let best = match (canonical_pos, alias_pos) {
            (Some(c), Some(a)) => {
                if c <= a {
                    (c, false)
                } else {
                    (a, true)
                }
            }
            (Some(c), None) => (c, false),
            (None, Some(a)) => (a, true),
            (None, None) => continue,
        };
        hits.push(Hit {
            order,
            pos: best.0,
            via_alias: best.1,
        });
    }

    if hits.is_empty() {
        return None;
    }

    let distinct = hits.len();
    // First appearance wins; ties (impossible for distinct whole tokens, but guarded anyway)
    // break by declaration order for determinism.
    let winner = hits
        .iter()
        .min_by(|a, b| a.pos.cmp(&b.pos).then(a.order.cmp(&b.order)))
        .expect("hits is non-empty");

    let base = if winner.via_alias {
        CONF_EMBEDDED_ALIAS
    } else {
        CONF_EMBEDDED_CANONICAL
    };
    let ambiguous = distinct > 1;
    let confidence = if ambiguous {
        base * AMBIGUITY_FACTOR
    } else {
        base
    };

    Some(Classified {
        label: set.labels[winner.order].canonical.clone(),
        confidence,
        matched_via_alias: winner.via_alias,
        ambiguous,
    })
}

// GAP-AUDIT misc-decisions (gap6, item 3) — investigated whether the real production path
// (`ainxt_convo::ModelIntentClassifier::classify_with_commands`, which calls
// `classify_constrained` directly rather than this function) can return with NO label at all in
// some edge case this function would have caught. It cannot: `classify_constrained`'s Stage-2/
// Stage-3 cascade (below) already guarantees an outcome on every call —
// `Stage2Outcome::Act(Classified)` on a confident parse, or `Stage2Outcome::Clarify { reason,
// best }` otherwise (unparseable, low-confidence, ambiguous, or model-unavailable — see
// `ClarifyReason`) — and `ModelIntentClassifier::classify_with_commands` maps `Clarify` to
// `IntentResult::clarify(reason, guess, conf)`, defaulting `guess` to `Intent::Qa` when no
// sub-threshold parse exists at all. So every call resolves to something actionable: dispatch on
// a label, or ask with a concrete best-guess default — the caller can never "stall on a blank
// classification" the way this function's own doc below worries about. This is a STRONGER
// contract than this function's silent substitution, not a weaker one with a gap in it (see the
// crate-level "Stage-2 constrained classifier seam" section doc: "the Stage-2 entry point never
// silently substitutes a fallback label the way `classify_with_fallback` does"; §0.3 "ask third —
// never a silent wrong guess"). `classify_with_fallback`/`Resolution` remain correct, tested
// library primitives for a caller that explicitly wants silent-fallback semantics instead of
// ask-first (e.g. a non-interactive batch classifier with no user to clarify with) — genuinely
// superseded for the interactive chat path, not dead code hiding a bug.
//
/// Classify `output`, guaranteeing a label. On a successful parse the [`Classified`] is
/// returned with `fallback_used == false`; otherwise `fallback_label` is returned verbatim
/// with `confidence == 0.0` and `fallback_used == true`, so a downstream state machine never
/// stalls on an unparseable classification (the runtime can instead route the zero-confidence
/// result to the Stage-3 clarify gate).
pub fn classify_with_fallback(output: &str, set: &LabelSet, fallback_label: &str) -> Resolution {
    match parse_label(output, set) {
        Some(c) => Resolution {
            label: c.label,
            confidence: c.confidence,
            matched_via_alias: c.matched_via_alias,
            ambiguous: c.ambiguous,
            fallback_used: false,
        },
        None => Resolution {
            label: fallback_label.trim().to_string(),
            confidence: 0.0,
            matched_via_alias: false,
            ambiguous: false,
            fallback_used: true,
        },
    }
}

// ============================================================================================
// Stage-2 constrained classifier seam + Stage-3 clarify-on-low-confidence policy
// (CONVERSATION_INTELLIGENCE.md §2 "Constrained classifier — any model", §3 "Clarify if
// ambiguous", §5 "Model-agnostic extraction").
//
// The extraction logic above (build_prompt / parse_label) is model-*less*. This section adds the
// two seams the design's cascade needs on top of it:
//
//   * a MODEL seam ([`LabelModel`]) — "one cheap call, any model" (§2). The real transport does
//     grammar / JSON-schema-constrained decoding where the model supports it and plain prompting
//     where it does not (§5); either way it hands back raw text and this crate parses it. The seam
//     keeps the ML runtime out of the classifier core, so the whole cascade stays pure + testable
//     with a deterministic double.
//   * a POLICY ([`ClarifyPolicy`]) that reads the graded confidence the parser already produces and
//     decides ACT vs CLARIFY — Stage-3. This is the gap the audit flags: a confidence field that is
//     computed and then never read before dispatch. Here it is load-bearing.
//
// Governing principle (§0.3): "deterministic first, model second, ASK third — never a silent wrong
// guess." So the Stage-2 entry point never silently substitutes a fallback label the way
// [`classify_with_fallback`] does; an unparseable / low-confidence / ambiguous read routes to
// [`Stage2Outcome::Clarify`] instead.
// ============================================================================================

/// A transport-level failure from the model seam (the model call itself failed — timeout, provider
/// error, empty completion). Distinct from a *parse* failure, which is not an error but a signal to
/// repair or clarify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelError(pub String);

impl fmt::Display for ModelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "label model error: {}", self.0)
    }
}

impl std::error::Error for ModelError {}

/// The Stage-2 model seam: "one cheap model call, any model" (§2). An implementation renders the
/// prompt to the model — under grammar / JSON-schema-constrained decoding where the transport
/// supports it (§5) — and returns the raw completion text. The runtime, not the model, owns
/// control-flow (§0.1): this seam only *classifies*, it never decides what to do next.
///
/// Kept object-safe (`&dyn LabelModel`) so a Surface Profile can select the model at runtime, and
/// deliberately synchronous + text-in/text-out so the classifier core takes on no async/ML deps.
pub trait LabelModel {
    /// Run one classification call for `prompt` (produced by [`build_prompt`]). `Ok` carries the
    /// raw, possibly-messy completion; `Err` is a transport failure, not an unparseable answer.
    fn classify(&self, prompt: &str) -> Result<String, ModelError>;
}

/// Stage-3 policy: the confidence floor (and ambiguity switch) that decides ACT vs CLARIFY, plus the
/// bounded repair budget (§5 "bounded repair loop as backstop"). Declarative so a deployment/profile
/// can tune it as config (config-first) rather than in code.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ClarifyPolicy {
    /// A parsed label scoring strictly below this confidence routes to CLARIFY rather than ACT.
    pub min_confidence: f32,
    /// When `true`, a read that saw more than one distinct label (`ambiguous`) always clarifies —
    /// even if its (already penalized) confidence happens to clear `min_confidence`.
    pub clarify_on_ambiguous: bool,
    /// How many times to call the model before giving up on an *unparseable* stream (§5). `1` = no
    /// repair. Clamped to at least 1 internally, so `0` cannot silently skip the only call.
    pub max_attempts: u32,
    /// When `true`, a parse failure (`Unparseable` / `ModelUnavailable`) does NOT clarify — instead
    /// the classifier returns a default label (`fallback_label`) so the caller can answer rather
    /// than ask. This is the chat-surface contract: "never clarify — always answer." A genuine
    /// low-confidence or ambiguous read still clarifies (governed by the fields above); this only
    /// covers the case where the model never produced a parseable label at all.
    pub fallback_on_parse_failure: bool,
    /// The label to return when `fallback_on_parse_failure` is `true` and the model never parsed.
    /// Defaults to `"qa"` — the neutral "answer the question" intent.
    pub fallback_label: &'static str,
}

impl Default for ClarifyPolicy {
    /// A floor of `0.7` sits between [`CONF_EMBEDDED_ALIAS`] (0.6) and [`CONF_EMBEDDED_CANONICAL`]
    /// (0.75): a clean canonical read acts, while an alias-only / prose-buried / ambiguous read asks.
    /// Ambiguity always clarifies, and one repair retry backstops a weak model's first bad stream.
    fn default() -> Self {
        ClarifyPolicy {
            min_confidence: 0.7,
            clarify_on_ambiguous: true,
            max_attempts: 2,
            fallback_on_parse_failure: false,
            fallback_label: "qa",
        }
    }
}

impl ClarifyPolicy {
    /// Apply the policy to a successfully parsed label: ACT, or CLARIFY with a typed reason.
    fn gate(&self, c: Classified) -> Stage2Outcome {
        if self.clarify_on_ambiguous && c.ambiguous {
            return Stage2Outcome::Clarify {
                reason: ClarifyReason::Ambiguous,
                best: Some(c),
            };
        }
        if c.confidence < self.min_confidence {
            return Stage2Outcome::Clarify {
                reason: ClarifyReason::LowConfidence {
                    confidence: c.confidence,
                    threshold: self.min_confidence,
                },
                best: Some(c),
            };
        }
        Stage2Outcome::Act(c)
    }
}

/// Why Stage-3 chose to clarify rather than act. Typed so the caller can render the *right* question
/// (a low-confidence prompt differs from an ambiguity prompt) and so it can be logged for the
/// forensic-replay discipline.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum ClarifyReason {
    /// The best parse scored below the policy floor.
    LowConfidence { confidence: f32, threshold: f32 },
    /// More than one distinct label appeared and the policy clarifies on ambiguity.
    Ambiguous,
    /// The model never produced a parseable label within the repair budget.
    Unparseable,
    /// Every model call failed at the transport layer (the seam erred, no completion arrived).
    ModelUnavailable { detail: String },
}

/// The outcome of the Stage-2 → Stage-3 pipeline: either a decision to ACT on a resolved label, or a
/// decision to CLARIFY (carrying the reason and, where one exists, the best low-confidence guess so
/// the caller can offer it as the default option in a clarifying prompt).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum Stage2Outcome {
    /// Confident enough to proceed — dispatch on `label`.
    Act(Classified),
    /// Ask the user; do not guess. `best` is the strongest sub-threshold parse, if any.
    Clarify {
        reason: ClarifyReason,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        best: Option<Classified>,
    },
}

impl Stage2Outcome {
    /// The resolved label iff the outcome is [`Stage2Outcome::Act`] — the only case a state machine
    /// may dispatch on. `None` for any CLARIFY, so a caller cannot accidentally act on a guess.
    pub fn acted_label(&self) -> Option<&str> {
        match self {
            Stage2Outcome::Act(c) => Some(c.label.as_str()),
            Stage2Outcome::Clarify { .. } => None,
        }
    }

    /// `true` if the pipeline decided to clarify rather than act.
    pub fn is_clarify(&self) -> bool {
        matches!(self, Stage2Outcome::Clarify { .. })
    }
}

/// Run the full Stage-2 (constrained model classification) + Stage-3 (clarify-on-low-confidence)
/// cascade for one turn.
///
/// 1. [`build_prompt`] renders the fixed-vocabulary constraint instruction for `set`.
/// 2. The [`LabelModel`] is called; its raw output is parsed by [`parse_label`]. An *unparseable*
///    stream is retried up to `policy.max_attempts` times (§5 bounded repair) — repair targets a
///    blank/garbled stream, never a low confidence (a confident-enough parse stops the loop).
/// 3. The first parseable read is graded by [`ClarifyPolicy::gate`]: ACT if it clears the floor and
///    (optionally) is unambiguous, otherwise CLARIFY with a typed reason.
/// 4. If no attempt ever parses, the result is CLARIFY — [`ClarifyReason::Unparseable`] if the model
///    answered but unintelligibly, or [`ClarifyReason::ModelUnavailable`] if every call erred.
///
/// Deterministic given the seam: no clock, no RNG. The same sequence of model outputs always yields
/// the same [`Stage2Outcome`].
pub fn classify_constrained(
    model: &dyn LabelModel,
    instruction: &str,
    set: &LabelSet,
    policy: &ClarifyPolicy,
) -> Stage2Outcome {
    let prompt = build_prompt(instruction, set);
    let attempts = policy.max_attempts.max(1);

    let mut got_response = false;
    let mut last_error: Option<String> = None;

    for _ in 0..attempts {
        match model.classify(&prompt) {
            Ok(raw) => {
                got_response = true;
                if let Some(c) = parse_label(&raw, set) {
                    return policy.gate(c);
                }
                // Parseable-nothing: fall through and repair (retry) if the budget allows.
            }
            Err(ModelError(detail)) => last_error = Some(detail),
        }
    }

    // Budget exhausted with no parseable label.
    let reason = if got_response {
        ClarifyReason::Unparseable
    } else {
        ClarifyReason::ModelUnavailable {
            detail: last_error.unwrap_or_else(|| "no model response".to_string()),
        }
    };
    // Chat-surface contract: when fallback_on_parse_failure is set, a parse failure returns the
    // fallback label as a confident ACT instead of a Clarify — so the turn reaches the LLM and gets
    // answered rather than bouncing back with "I didn't quite catch that." The label must exist in
    // the set; if it doesn't, fall through to Clarify (safe default).
    if policy.fallback_on_parse_failure {
        if let Some(c) = parse_label(policy.fallback_label, set) {
            return Stage2Outcome::Act(c);
        }
    }
    Stage2Outcome::Clarify { reason, best: None }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The canonical intent vocabulary from CONVERSATION_INTELLIGENCE.md §2, trimmed for tests.
    fn intent_set() -> LabelSet {
        LabelSet::new(vec![
            Label::new("chitchat"),
            Label::new("qa"),
            Label::new("code"),
            Label::new("doc_generation").with_aliases(["document", "pdf"]),
        ])
        .expect("valid set")
    }

    #[test]
    fn exact_single_label_scores_full_confidence() {
        let set = intent_set();
        let c = parse_label("qa", &set).expect("parsed");
        assert_eq!(c.label, "qa");
        assert_eq!(c.confidence, CONF_EXACT_CANONICAL);
        assert!(!c.ambiguous);
        assert!(!c.matched_via_alias);
    }

    #[test]
    fn messy_prefix_is_embedded_match() {
        let set = intent_set();
        let c = parse_label("Answer: qa", &set).expect("parsed");
        assert_eq!(c.label, "qa");
        assert_eq!(c.confidence, CONF_EMBEDDED_CANONICAL);
        assert!(!c.ambiguous);
        // Prose sentence form from the spec example.
        let c2 = parse_label("The intent is: QA.", &set).expect("parsed");
        assert_eq!(c2.label, "qa");
        assert_eq!(c2.confidence, CONF_EMBEDDED_CANONICAL);
    }

    #[test]
    fn matching_is_case_insensitive() {
        let set = intent_set();
        assert_eq!(parse_label("QA", &set).unwrap().label, "qa");
        assert_eq!(parse_label("Qa", &set).unwrap().label, "qa");
        assert_eq!(parse_label("Intent: CODE", &set).unwrap().label, "code");
        // Case-insensitive exact still scores as exact.
        assert_eq!(
            parse_label("QA", &set).unwrap().confidence,
            CONF_EXACT_CANONICAL
        );
    }

    #[test]
    fn surrounding_punctuation_and_quotes_are_stripped_to_exact() {
        let set = intent_set();
        // Quotes + trailing period → still the exact standalone label.
        let c = parse_label("\"qa\".", &set).expect("parsed");
        assert_eq!(c.label, "qa");
        assert_eq!(c.confidence, CONF_EXACT_CANONICAL);
        assert_eq!(parse_label("'code'", &set).unwrap().label, "code");
        assert_eq!(
            parse_label("  [code]  ", &set).unwrap().confidence,
            CONF_EXACT_CANONICAL
        );
    }

    #[test]
    fn whole_token_only_no_substring_false_positive() {
        let set = intent_set();
        // "qa" must not be found inside "aqua".
        assert!(parse_label("aqua", &set).is_none());
        // "code" must not be found inside "encode" / "decoded".
        assert!(parse_label("please encode this", &set).is_none());
        assert!(parse_label("it decoded fine", &set).is_none());
        // Underscore is a word boundary char: snake_case must not trip "qa".
        assert!(parse_label("see qa_result for details", &set).is_none());
    }

    #[test]
    fn two_labels_first_wins_with_lower_confidence() {
        let set = intent_set();
        let c = parse_label("maybe qa or code", &set).expect("parsed");
        assert_eq!(c.label, "qa"); // first appearance
        assert!(c.ambiguous);
        // Ambiguous must score strictly below the single-label embedded tier, but stay positive.
        assert!(c.confidence < CONF_EMBEDDED_CANONICAL);
        assert!(c.confidence > 0.0);
        assert_eq!(c.confidence, CONF_EMBEDDED_CANONICAL * AMBIGUITY_FACTOR);

        // Reverse the order in the text: the other label now wins.
        let c2 = parse_label("try code then qa", &set).expect("parsed");
        assert_eq!(c2.label, "code");
        assert!(c2.ambiguous);
    }

    #[test]
    fn repeated_single_label_is_not_ambiguous() {
        let set = intent_set();
        let c = parse_label("qa and qa again", &set).expect("parsed");
        assert_eq!(c.label, "qa");
        assert!(!c.ambiguous);
        assert_eq!(c.confidence, CONF_EMBEDDED_CANONICAL);
    }

    #[test]
    fn no_match_returns_none_then_fallback_is_used() {
        let set = intent_set();
        assert!(parse_label("hello there world", &set).is_none());

        let r = classify_with_fallback("hello there world", &set, "chitchat");
        assert_eq!(r.label, "chitchat");
        assert!(r.fallback_used);
        assert_eq!(r.confidence, 0.0);
        assert!(!r.ambiguous);
    }

    #[test]
    fn fallback_not_used_when_parse_succeeds() {
        let set = intent_set();
        let r = classify_with_fallback("Answer: code", &set, "chitchat");
        assert_eq!(r.label, "code");
        assert!(!r.fallback_used);
        assert_eq!(r.confidence, CONF_EMBEDDED_CANONICAL);
    }

    #[test]
    fn alias_resolves_to_canonical_at_graded_confidence() {
        let set = intent_set();
        // Exact standalone alias → canonical label, exact-alias confidence.
        let c = parse_label("pdf", &set).expect("parsed");
        assert_eq!(c.label, "doc_generation");
        assert!(c.matched_via_alias);
        assert_eq!(c.confidence, CONF_EXACT_ALIAS);

        // Alias embedded in prose → embedded-alias confidence, still canonical label.
        let c2 = parse_label("please produce a document for me", &set).expect("parsed");
        assert_eq!(c2.label, "doc_generation");
        assert!(c2.matched_via_alias);
        assert_eq!(c2.confidence, CONF_EMBEDDED_ALIAS);
    }

    #[test]
    fn canonical_preferred_over_alias_of_same_label() {
        // A label whose canonical appears earlier than its own alias is reported as canonical
        // and is NOT ambiguous (one distinct label).
        let set =
            LabelSet::new(vec![Label::new("qa").with_alias("q"), Label::new("code")]).unwrap();
        let c = parse_label("qa (aka q)", &set).expect("parsed");
        assert_eq!(c.label, "qa");
        assert!(!c.matched_via_alias);
        assert!(!c.ambiguous);
        assert_eq!(c.confidence, CONF_EMBEDDED_CANONICAL);
    }

    #[test]
    fn build_prompt_lists_canonicals_in_order() {
        let set = intent_set();
        let bare = build_prompt("", &set);
        assert!(bare.contains("Reply with EXACTLY one of: chitchat | qa | code | doc_generation"));
        // Aliases are never leaked into the vocabulary.
        assert!(!bare.contains("pdf"));
        assert!(!bare.contains("document"));

        let with_instr = build_prompt("Classify the user intent.", &set);
        assert!(with_instr.starts_with("Classify the user intent."));
        assert!(with_instr.contains("EXACTLY one of"));
    }

    #[test]
    fn labelset_validation_rejects_bad_vocabularies() {
        assert_eq!(LabelSet::new(vec![]), Err(LabelSetError::Empty));
        assert_eq!(
            LabelSet::new(vec![Label::new("   ")]),
            Err(LabelSetError::EmptyCanonical)
        );
        // Duplicate canonical (case-insensitive).
        assert_eq!(
            LabelSet::new(vec![Label::new("qa"), Label::new("QA")]),
            Err(LabelSetError::DuplicateSurface("QA".to_string()))
        );
        // Alias collides with another label's canonical.
        assert_eq!(
            LabelSet::new(vec![
                Label::new("qa").with_alias("code"),
                Label::new("code")
            ]),
            Err(LabelSetError::DuplicateSurface("code".to_string()))
        );
        // Empty alias.
        assert_eq!(
            LabelSet::new(vec![Label::new("qa").with_alias("  ")]),
            Err(LabelSetError::EmptyAlias("qa".to_string()))
        );
    }

    #[test]
    fn resolve_maps_surface_forms_to_canonical() {
        let set = intent_set();
        assert_eq!(set.resolve("PDF"), Some("doc_generation"));
        assert_eq!(set.resolve(" document "), Some("doc_generation"));
        assert_eq!(set.resolve("qa"), Some("qa"));
        assert_eq!(set.resolve("nonexistent"), None);
    }

    #[test]
    fn empty_or_punctuation_only_output_is_none() {
        let set = intent_set();
        assert!(parse_label("", &set).is_none());
        assert!(parse_label("   ", &set).is_none());
        assert!(parse_label("...!?", &set).is_none());
    }

    #[test]
    fn slash_separated_labels_are_ambiguous_first_wins() {
        let set = intent_set();
        // No spaces, punctuation separator — whole-token boundaries still hold on both sides.
        let c = parse_label("qa/code", &set).expect("parsed");
        assert_eq!(c.label, "qa");
        assert!(c.ambiguous);
    }

    #[test]
    fn labelset_deserialization_validates() {
        // Valid taxonomy round-trips through serde and is usable.
        let json = r#"{"labels":[{"canonical":"qa"},{"canonical":"code","aliases":["coding"]}]}"#;
        let set: LabelSet = serde_json::from_str(json).expect("valid");
        assert_eq!(set.len(), 2);
        assert_eq!(parse_label("coding", &set).unwrap().label, "code");

        // Invalid taxonomy (duplicate surface) is rejected at deserialization time.
        let bad = r#"{"labels":[{"canonical":"qa","aliases":["code"]},{"canonical":"code"}]}"#;
        assert!(serde_json::from_str::<LabelSet>(bad).is_err());
    }

    #[test]
    fn classified_confidence_ordering_is_monotonic() {
        // The four single-label tiers are strictly ordered, and any ambiguity sits below its
        // single-label tier — the property the clarify gate depends on. These are invariants on the
        // confidence CONSTANTS, so enforce them at COMPILE time (a reorder becomes a build error).
        const _: () = {
            assert!(CONF_EXACT_CANONICAL > CONF_EXACT_ALIAS);
            assert!(CONF_EXACT_ALIAS > CONF_EMBEDDED_CANONICAL);
            assert!(CONF_EMBEDDED_CANONICAL > CONF_EMBEDDED_ALIAS);
            assert!(CONF_EMBEDDED_CANONICAL * AMBIGUITY_FACTOR < CONF_EMBEDDED_CANONICAL);
            assert!(CONF_EMBEDDED_ALIAS * AMBIGUITY_FACTOR > 0.0);
        };
    }

    // ---- Stage-2 constrained classifier + Stage-3 clarify policy ----

    use std::cell::Cell;

    /// A deterministic [`LabelModel`] double: returns each scripted output in turn (repeating the
    /// last once exhausted), counting calls so tests can assert the repair loop's exact budget use.
    struct ScriptedModel {
        outputs: Vec<Result<String, ModelError>>,
        calls: Cell<usize>,
        last_prompt: std::cell::RefCell<String>,
    }
    impl ScriptedModel {
        fn ok(outputs: &[&str]) -> Self {
            ScriptedModel {
                outputs: outputs.iter().map(|s| Ok(s.to_string())).collect(),
                calls: Cell::new(0),
                last_prompt: std::cell::RefCell::new(String::new()),
            }
        }
        fn from(outputs: Vec<Result<String, ModelError>>) -> Self {
            ScriptedModel {
                outputs,
                calls: Cell::new(0),
                last_prompt: std::cell::RefCell::new(String::new()),
            }
        }
    }
    impl LabelModel for ScriptedModel {
        fn classify(&self, prompt: &str) -> Result<String, ModelError> {
            *self.last_prompt.borrow_mut() = prompt.to_string();
            let i = self.calls.get();
            self.calls.set(i + 1);
            let idx = i.min(self.outputs.len() - 1);
            self.outputs[idx].clone()
        }
    }

    #[test]
    fn stage2_acts_on_a_confident_clean_label() {
        let set = intent_set();
        let model = ScriptedModel::ok(&["qa"]);
        let out = classify_constrained(
            &model,
            "Classify the intent.",
            &set,
            &ClarifyPolicy::default(),
        );
        match out {
            Stage2Outcome::Act(c) => {
                assert_eq!(c.label, "qa");
                assert_eq!(c.confidence, CONF_EXACT_CANONICAL);
            }
            other => panic!("expected Act, got {other:?}"),
        }
        // Exactly one model call for a first-try clean parse — no wasteful repair.
        assert_eq!(model.calls.get(), 1);
        // The seam actually received the constraint prompt (Stage-2 wiring, not a bypass).
        assert!(model.last_prompt.borrow().contains("EXACTLY one of"));
        assert!(model
            .last_prompt
            .borrow()
            .starts_with("Classify the intent."));
    }

    #[test]
    fn stage3_clarifies_on_ambiguous_read() {
        let set = intent_set();
        // Two distinct labels → ambiguous; policy clarifies on ambiguity regardless of the score.
        let model = ScriptedModel::ok(&["maybe qa or code"]);
        let out = classify_constrained(&model, "", &set, &ClarifyPolicy::default());
        match out {
            Stage2Outcome::Clarify { reason, best } => {
                assert_eq!(reason, ClarifyReason::Ambiguous);
                // The best guess is carried through so the caller can offer it as the default.
                assert_eq!(best.unwrap().label, "qa");
            }
            other => panic!("expected Clarify(Ambiguous), got {other:?}"),
        }
    }

    #[test]
    fn stage3_clarifies_on_low_confidence_alias_in_prose() {
        let set = intent_set();
        // Embedded alias → CONF_EMBEDDED_ALIAS (0.6) < default floor 0.7 → clarify, not a silent act.
        let model = ScriptedModel::ok(&["please produce a document for me"]);
        let out = classify_constrained(&model, "", &set, &ClarifyPolicy::default());
        // A CLARIFY must never expose an acted label — no accidental dispatch on a guess.
        assert_eq!(out.acted_label(), None);
        match out {
            Stage2Outcome::Clarify {
                reason:
                    ClarifyReason::LowConfidence {
                        confidence,
                        threshold,
                    },
                best,
            } => {
                assert_eq!(confidence, CONF_EMBEDDED_ALIAS);
                assert_eq!(threshold, 0.7);
                assert_eq!(best.unwrap().label, "doc_generation");
            }
            other => panic!("expected Clarify(LowConfidence), got {other:?}"),
        }
    }

    #[test]
    fn repair_loop_retries_unparseable_then_succeeds() {
        let set = intent_set();
        // First stream is garbage, second is a clean label → the bounded repair loop recovers.
        let model = ScriptedModel::ok(&["I'm not sure what you mean", "qa"]);
        let policy = ClarifyPolicy {
            max_attempts: 3,
            ..ClarifyPolicy::default()
        };
        let out = classify_constrained(&model, "", &set, &policy);
        assert_eq!(out.acted_label(), Some("qa"));
        assert_eq!(
            model.calls.get(),
            2,
            "recovered on the second attempt, no third call"
        );
    }

    #[test]
    fn repair_loop_exhausts_then_clarifies_unparseable() {
        let set = intent_set();
        let model = ScriptedModel::ok(&["no label here at all"]);
        let policy = ClarifyPolicy {
            max_attempts: 3,
            ..ClarifyPolicy::default()
        };
        let out = classify_constrained(&model, "", &set, &policy);
        assert!(matches!(
            out,
            Stage2Outcome::Clarify {
                reason: ClarifyReason::Unparseable,
                best: None
            }
        ));
        // Every attempt in the budget was spent trying to repair the unparseable stream.
        assert_eq!(model.calls.get(), 3);
    }

    #[test]
    fn max_attempts_zero_is_clamped_to_one_call() {
        let set = intent_set();
        let model = ScriptedModel::ok(&["garbage"]);
        let policy = ClarifyPolicy {
            max_attempts: 0,
            ..ClarifyPolicy::default()
        };
        let _ = classify_constrained(&model, "", &set, &policy);
        assert_eq!(model.calls.get(), 1, "0 must not skip the only call");
    }

    #[test]
    fn transport_error_becomes_model_unavailable_not_a_guess() {
        let set = intent_set();
        let model = ScriptedModel::from(vec![
            Err(ModelError("connection reset".to_string())),
            Err(ModelError("connection reset".to_string())),
        ]);
        let policy = ClarifyPolicy {
            max_attempts: 2,
            ..ClarifyPolicy::default()
        };
        let out = classify_constrained(&model, "", &set, &policy);
        match out {
            Stage2Outcome::Clarify {
                reason: ClarifyReason::ModelUnavailable { detail },
                best: None,
            } => assert_eq!(detail, "connection reset"),
            other => panic!("expected ModelUnavailable, got {other:?}"),
        }
        assert_eq!(model.calls.get(), 2);
    }

    #[test]
    fn a_response_after_errors_is_unparseable_not_unavailable() {
        // If any attempt returned text (even if garbage), the failure is Unparseable, not
        // ModelUnavailable — the model WAS reachable, it just didn't answer intelligibly.
        let set = intent_set();
        let model = ScriptedModel::from(vec![
            Err(ModelError("timeout".to_string())),
            Ok("still nothing useful".to_string()),
        ]);
        let policy = ClarifyPolicy {
            max_attempts: 2,
            ..ClarifyPolicy::default()
        };
        let out = classify_constrained(&model, "", &set, &policy);
        assert!(matches!(
            out,
            Stage2Outcome::Clarify {
                reason: ClarifyReason::Unparseable,
                ..
            }
        ));
    }

    #[test]
    fn a_stricter_floor_pushes_even_a_canonical_prose_hit_to_clarify() {
        let set = intent_set();
        // Embedded canonical scores 0.75; a floor above it must clarify.
        let model = ScriptedModel::ok(&["the intent is qa"]);
        let policy = ClarifyPolicy {
            min_confidence: 0.9,
            ..ClarifyPolicy::default()
        };
        let out = classify_constrained(&model, "", &set, &policy);
        assert!(out.is_clarify());
        // And a floor below it lets the same read act — the floor is load-bearing, not decorative.
        let model2 = ScriptedModel::ok(&["the intent is qa"]);
        let lax = ClarifyPolicy {
            min_confidence: 0.5,
            ..ClarifyPolicy::default()
        };
        assert_eq!(
            classify_constrained(&model2, "", &set, &lax).acted_label(),
            Some("qa")
        );
    }

    #[test]
    fn stage2_outcome_serde_round_trips_both_arms() {
        let set = intent_set();
        for output in ["qa", "maybe qa or code"] {
            let model = ScriptedModel::ok(&[output]);
            let out = classify_constrained(&model, "", &set, &ClarifyPolicy::default());
            let json = serde_json::to_string(&out).unwrap();
            let back: Stage2Outcome = serde_json::from_str(&json).unwrap();
            assert_eq!(back, out);
        }
    }
}
