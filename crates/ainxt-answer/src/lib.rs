// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! ainxt-answer — the **answer-composition + presentation core** for AiNxt chat.
//!
//! This is the direct fix for three quality gaps the scorecard flags as "messy output":
//!
//! * **BK — formatting / rich rendering.** An answer is a *typed model* ([`Answer`]) — a lead
//!   (tl;dr), ordered [`Section`]s, and inline [`Segment`]s (text / code / table / citation) — not a
//!   blob of model text hopefully-shaped by a prompt. Rendering to Markdown or plain text is a pure,
//!   deterministic function of that model.
//! * **BM — verbosity calibration ("right-sizing").** A [`Verbosity`] bound, derived from a
//!   reasoning-depth hint ([`ainxt_types::Tier`]), *caps* lead length and section count. A trivial
//!   follow-up (Terse) is not answered with an essay; a deep analysis (Detailed) is not truncated to
//!   a sentence. Truncation is recorded as a [`CompositionWarning`], never silent.
//! * **BN — citation UX.** Repeated sources are de-duplicated; references are numbered `[n]` in
//!   **first-appearance reading order** (lead-then-sections); a references list is rendered; and two
//!   integrity failures are detected — a **dangling** inline ref with no matching source, and a
//!   **source that is never cited**.
//!
//! Distinct from its neighbours: `ainxt-artifact` renders *generated documents* (docx/pptx/pdf),
//! `ainxt-prompt` assembles the *model input*. This crate shapes the *chat output* only.
//!
//! ## Design for the adversarial / empty case
//!
//! This is enterprise payments software, so composition is defined for the hostile input, not the
//! happy path: an empty answer renders to an empty string (never a panic), a lead of multi-byte
//! characters truncates on a `char` boundary, a citation to a missing source is surfaced rather than
//! swallowed, and every truncation is reported. Composition is total — [`Answer::compose`] cannot
//! fail — because a runtime seam that can panic on a caller's answer is not shippable.
//!
//! Clean-room; pure; no I/O; deterministic. Every ordering and bound below is exhaustively tested.

use serde::{Deserialize, Serialize};

pub use ainxt_types::Tier;

// ---------------------------------------------------------------------------------------------
// Verbosity calibration (gap BM)
// ---------------------------------------------------------------------------------------------

/// How much answer the caller has earned. Derived from a reasoning-depth / intent hint, it *bounds*
/// the composed answer so the size matches the question. This is the "right-sizing" lever.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verbosity {
    /// A quick answer — one section at most, a short lead. For trivial / follow-up turns.
    Terse,
    /// The default shape — a handful of sections, a paragraph-scale lead.
    Normal,
    /// A thorough treatment — many sections, a long lead. For deep analysis.
    Detailed,
}

/// The concrete bounds a [`Verbosity`] imposes. Split out so the numbers are testable in isolation
/// and a deployment can reason about them without composing an answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerbosityBounds {
    /// Maximum number of sections kept; the rest are dropped (and a warning is raised).
    pub max_sections: usize,
    /// Maximum lead length in Unicode scalar values (`char`s), not bytes.
    pub max_lead_chars: usize,
}

impl Verbosity {
    /// The bounds for this level. Monotone: Terse ⊆ Normal ⊆ Detailed on both axes.
    pub fn bounds(self) -> VerbosityBounds {
        match self {
            Verbosity::Terse => VerbosityBounds {
                max_sections: 1,
                max_lead_chars: 160,
            },
            Verbosity::Normal => VerbosityBounds {
                max_sections: 4,
                max_lead_chars: 400,
            },
            Verbosity::Detailed => VerbosityBounds {
                max_sections: 12,
                max_lead_chars: 800,
            },
        }
    }

    /// Derive verbosity from the runtime's reasoning-depth hint. A `Simple` classification (greeting,
    /// trivial Q&A) earns a Terse answer; `Complex` (deep analysis / SDLC) earns Detailed. This is
    /// the seam that ties answer size to the classifier/router decision (gap BM, ADR-006 input).
    pub fn for_tier(tier: Tier) -> Self {
        match tier {
            Tier::Simple => Verbosity::Terse,
            Tier::Medium => Verbosity::Normal,
            Tier::Complex => Verbosity::Detailed,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The typed answer model (gap BK)
// ---------------------------------------------------------------------------------------------

/// A source that a claim can cite. `key` is a *stable identity* used by [`Segment::Cite`] — de-dup
/// and numbering are keyed on it, so the same source cited five times is one reference. `locator` is
/// the human-facing pointer (a URL, a repo path, a doc span); `None` renders as title-only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Citation {
    pub key: String,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locator: Option<String>,
}

impl Citation {
    pub fn new(key: &str, title: &str) -> Self {
        Citation {
            key: key.into(),
            title: title.into(),
            locator: None,
        }
    }
    /// Attach a human-facing locator (URL / path / span).
    pub fn with_locator(mut self, locator: &str) -> Self {
        self.locator = Some(locator.into());
        self
    }
}

/// A simple tabular block. Kept minimal on purpose — rich layout belongs to `ainxt-artifact`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Table {
    pub headers: Vec<String>,
    pub rows: Vec<Vec<String>>,
}

impl Table {
    pub fn new(headers: &[&str], rows: Vec<Vec<String>>) -> Self {
        Table {
            headers: headers.iter().map(|h| h.to_string()).collect(),
            rows,
        }
    }
}

/// One inline piece of a section body, in reading order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Segment {
    /// Prose. Rendered inline.
    Text { text: String },
    /// An inline citation to a source by its [`Citation::key`]. Rendered as `[n]`.
    Cite { key: String },
    /// A fenced code block. `language` is the fence info-string (e.g. `"rust"`).
    Code {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        language: Option<String>,
        source: String,
    },
    /// A table block.
    Table { table: Table },
}

impl Segment {
    pub fn text(s: &str) -> Self {
        Segment::Text { text: s.into() }
    }
    pub fn cite(key: &str) -> Self {
        Segment::Cite { key: key.into() }
    }
    pub fn code(language: Option<&str>, source: &str) -> Self {
        Segment::Code {
            language: language.map(|l| l.to_string()),
            source: source.into(),
        }
    }
    pub fn table(table: Table) -> Self {
        Segment::Table { table }
    }
}

/// A titled section of the answer body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Section {
    pub heading: String,
    pub body: Vec<Segment>,
}

impl Section {
    pub fn new(heading: &str, body: Vec<Segment>) -> Self {
        Section {
            heading: heading.into(),
            body,
        }
    }
}

/// The typed chat answer. `lead` is the tl;dr shown first; `sections` are the ordered body;
/// `sources` is the *pool* of citable sources (inline [`Segment::Cite`]s reference them by key).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Answer {
    pub lead: String,
    #[serde(default)]
    pub sections: Vec<Section>,
    #[serde(default)]
    pub sources: Vec<Citation>,
}

impl Answer {
    /// An answer with a lead and nothing else.
    pub fn new(lead: &str) -> Self {
        Answer {
            lead: lead.into(),
            sections: Vec::new(),
            sources: Vec::new(),
        }
    }
    /// The empty answer. Composes and renders safely (to an empty string).
    pub fn empty() -> Self {
        Answer::default()
    }
    /// Append a section (builder-style).
    pub fn section(mut self, section: Section) -> Self {
        self.sections.push(section);
        self
    }
    /// Register a citable source (builder-style).
    pub fn source(mut self, citation: Citation) -> Self {
        self.sources.push(citation);
        self
    }

    /// Compose this answer under a verbosity bound: enforce right-sizing, then resolve citations in
    /// first-appearance order over the *bounded* body. Total — never fails, never panics.
    pub fn compose(&self, verbosity: Verbosity) -> ComposedAnswer {
        let bounds = verbosity.bounds();
        let mut warnings: Vec<CompositionWarning> = Vec::new();

        // ---- BM: right-size the lead (char-boundary safe) ----
        let (lead, lead_warn) = truncate_lead(&self.lead, bounds.max_lead_chars);
        if let Some(w) = lead_warn {
            warnings.push(w);
        }

        // ---- BM: right-size the section count ----
        let mut sections: Vec<Section> = self.sections.clone();
        if sections.len() > bounds.max_sections {
            let dropped = sections.len() - bounds.max_sections;
            sections.truncate(bounds.max_sections);
            warnings.push(CompositionWarning::SectionsTruncated { dropped });
        }

        // ---- BN: resolve citations over the bounded body, first-appearance order ----
        let mut references: Vec<Reference> = Vec::new();
        let mut numbered: Vec<String> = Vec::new(); // keys already assigned a number
        let mut dangling_seen: Vec<String> = Vec::new(); // dangling keys already warned

        for section in &sections {
            for seg in &section.body {
                if let Segment::Cite { key } = seg {
                    if numbered.iter().any(|k| k == key) {
                        continue; // de-dup: same source, same [n]
                    }
                    match self.sources.iter().find(|c| &c.key == key) {
                        Some(citation) => {
                            numbered.push(key.clone());
                            references.push(Reference {
                                number: references.len() + 1,
                                citation: citation.clone(),
                            });
                        }
                        None => {
                            if !dangling_seen.iter().any(|k| k == key) {
                                dangling_seen.push(key.clone());
                                warnings.push(CompositionWarning::DanglingCitation {
                                    key: key.clone(),
                                });
                            }
                        }
                    }
                }
            }
        }

        // ---- BN: sources present in the pool but never cited (in pool order) ----
        for source in &self.sources {
            if !numbered.iter().any(|k| k == &source.key) {
                warnings.push(CompositionWarning::UncitedSource {
                    key: source.key.clone(),
                });
            }
        }

        ComposedAnswer {
            verbosity,
            lead,
            sections,
            references,
            warnings,
        }
    }
}

/// Truncate a lead to at most `max_chars` Unicode scalar values, appending an ellipsis when cut.
/// Returns the (possibly truncated) lead and a warning describing the cut, if any. `char`-based so
/// it can never slice a multi-byte UTF-8 sequence.
fn truncate_lead(lead: &str, max_chars: usize) -> (String, Option<CompositionWarning>) {
    let total = lead.chars().count();
    if total <= max_chars {
        return (lead.to_string(), None);
    }
    // Reserve one slot for the ellipsis so the result still honours the bound exactly.
    let keep = max_chars.saturating_sub(1);
    let mut out: String = lead.chars().take(keep).collect();
    out.push('\u{2026}'); // …
    let kept_chars = out.chars().count();
    (
        out,
        Some(CompositionWarning::LeadTruncated {
            original_chars: total,
            kept_chars,
        }),
    )
}

// ---------------------------------------------------------------------------------------------
// Composition result
// ---------------------------------------------------------------------------------------------

/// A numbered reference in the composed answer's references list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reference {
    /// The `[n]` shown inline and in the list. 1-based, first-appearance order.
    pub number: usize,
    pub citation: Citation,
}

/// A non-fatal issue found during composition. Surfaced, never swallowed — a payments answer that
/// silently drops a citation or an essay's worth of sections is a defect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CompositionWarning {
    /// An inline `Cite { key }` had no matching source in the pool. Rendered as `[?]`.
    DanglingCitation { key: String },
    /// A source in the pool was never cited by any kept segment.
    UncitedSource { key: String },
    /// Verbosity dropped `dropped` trailing sections.
    SectionsTruncated { dropped: usize },
    /// Verbosity shortened the lead from `original_chars` to `kept_chars`.
    LeadTruncated {
        original_chars: usize,
        kept_chars: usize,
    },
}

/// The result of [`Answer::compose`]: a bounded, citation-resolved answer ready to render. Renderers
/// are pure functions of this — the same `ComposedAnswer` always yields byte-identical output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComposedAnswer {
    pub verbosity: Verbosity,
    pub lead: String,
    pub sections: Vec<Section>,
    /// De-duplicated, first-appearance-numbered references. Only *cited* sources appear.
    pub references: Vec<Reference>,
    pub warnings: Vec<CompositionWarning>,
}

impl ComposedAnswer {
    /// The `[n]` assigned to a source key, if it was cited (and thus numbered).
    pub fn number_for(&self, key: &str) -> Option<usize> {
        self.references
            .iter()
            .find(|r| r.citation.key == key)
            .map(|r| r.number)
    }

    /// True if composition raised any warning.
    pub fn has_warnings(&self) -> bool {
        !self.warnings.is_empty()
    }

    /// Render to clean Markdown: lead first, then `## heading` sections (with fenced code and pipe
    /// tables and inline `[n]`), then a `## References` list **last**. An empty answer → `""`.
    pub fn to_markdown(&self) -> String {
        let mut blocks: Vec<String> = Vec::new();

        if !self.lead.is_empty() {
            blocks.push(self.lead.clone());
        }

        for section in &self.sections {
            let mut sec = String::new();
            if !section.heading.is_empty() {
                sec.push_str("## ");
                // A raw newline in a heading would split the `## ` line and inject structure below
                // it (a heading is a single logical line) — flatten it.
                sec.push_str(&one_line(&section.heading));
            }
            let body = self.render_body_markdown(&section.body);
            if !body.is_empty() {
                if !sec.is_empty() {
                    sec.push_str("\n\n");
                }
                sec.push_str(&body);
            }
            if !sec.is_empty() {
                blocks.push(sec);
            }
        }

        if !self.references.is_empty() {
            let mut refs = String::from("## References\n");
            for r in &self.references {
                refs.push('\n');
                refs.push_str(&format!("{}. {}", r.number, r.citation.title));
                if let Some(loc) = &r.citation.locator {
                    refs.push_str(" \u{2014} "); // em dash
                    refs.push_str(loc);
                }
            }
            blocks.push(refs);
        }

        blocks.join("\n\n")
    }

    // GAP-AUDIT misc-decisions (gap6, item 2) — investigated whether the served `/v1/chat` path
    // has ANY format-negotiation mechanism (an `Accept` header, a request field, a client-
    // capability flag) that would call for this method over `to_markdown` for a plain-text-only
    // client (SMS/voice/legacy integration). It does not: `ainxt-server::ChatRequest` carries no
    // such field — only `forced_provider`, `caps`, `priority`, and the unrelated
    // `generate_document`/`OutputFormat` sentinel, which selects a DOCUMENT-GENERATION format
    // (pdf/docx/pptx/xlsx), not a chat-text rendering mode. No `Accept` header is read anywhere
    // on the chat path (`header_str` is only ever called for `last-event-id`, SSE resume). And
    // the one production renderer, `ainxt_convo::compose_chat_answer`, unconditionally calls
    // `.to_markdown()`. So this is not a case of an existing negotiation signal being ignored —
    // no real caller need exists yet. `to_plain_text` and `compose_chat_answer_typed` (which
    // returns the typed `ComposedAnswer` this method hangs off) remain the ready seam for
    // whenever a plain-text surface is added; wiring a call to this method in ahead of an actual
    // negotiation mechanism would be dead branching with nothing to select it.
    //
    /// Render to plain text with **no Markdown syntax** — no `#`, no fences, no `|` tables, no `*`.
    /// Headings are bare lines, code is indented, tables are space-aligned, `[n]` markers stay (they
    /// are not Markdown), and a `References` list is appended. An empty answer → `""`.
    pub fn to_plain_text(&self) -> String {
        let mut blocks: Vec<String> = Vec::new();

        if !self.lead.is_empty() {
            blocks.push(self.lead.clone());
        }

        for section in &self.sections {
            let mut sec = String::new();
            if !section.heading.is_empty() {
                sec.push_str(&one_line(&section.heading));
            }
            let body = self.render_body_plain(&section.body);
            if !body.is_empty() {
                if !sec.is_empty() {
                    sec.push('\n');
                }
                sec.push_str(&body);
            }
            if !sec.is_empty() {
                blocks.push(sec);
            }
        }

        if !self.references.is_empty() {
            let mut refs = String::from("References\n");
            for r in &self.references {
                refs.push_str(&format!("[{}] {}", r.number, r.citation.title));
                if let Some(loc) = &r.citation.locator {
                    refs.push_str(" - ");
                    refs.push_str(loc);
                }
                refs.push('\n');
            }
            blocks.push(refs.trim_end().to_string());
        }

        blocks.join("\n\n")
    }

    /// Inline-marker for a cite key: `[n]` if numbered, `[?]` if dangling. Shared by both renderers
    /// so a dangling ref never renders as a broken number.
    fn cite_marker(&self, key: &str) -> String {
        match self.number_for(key) {
            Some(n) => format!("[{}]", n),
            None => "[?]".to_string(),
        }
    }

    fn render_body_markdown(&self, body: &[Segment]) -> String {
        let mut inline = String::new(); // accumulates text + cite runs
        let mut blocks: Vec<String> = Vec::new();
        let flush = |inline: &mut String, blocks: &mut Vec<String>| {
            let t = inline.trim();
            if !t.is_empty() {
                blocks.push(t.to_string());
            }
            inline.clear();
        };
        for seg in body {
            match seg {
                Segment::Text { text } => inline.push_str(text),
                Segment::Cite { key } => inline.push_str(&self.cite_marker(key)),
                Segment::Code { language, source } => {
                    flush(&mut inline, &mut blocks);
                    // Adaptive fence: longer than any backtick run inside `source`, so code that
                    // itself contains a ``` fence cannot break out of the block (CommonMark rule).
                    // The info-string is flattened so a newline in `language` can't inject content.
                    let fence = code_fence(source);
                    let lang = language
                        .as_deref()
                        .map(sanitize_info_string)
                        .unwrap_or_default();
                    blocks.push(format!("{fence}{lang}\n{source}\n{fence}"));
                }
                Segment::Table { table } => {
                    flush(&mut inline, &mut blocks);
                    blocks.push(render_table_markdown(table));
                }
            }
        }
        flush(&mut inline, &mut blocks);
        blocks.join("\n\n")
    }

    fn render_body_plain(&self, body: &[Segment]) -> String {
        let mut inline = String::new();
        let mut blocks: Vec<String> = Vec::new();
        let flush = |inline: &mut String, blocks: &mut Vec<String>| {
            let t = inline.trim();
            if !t.is_empty() {
                blocks.push(t.to_string());
            }
            inline.clear();
        };
        for seg in body {
            match seg {
                Segment::Text { text } => inline.push_str(text),
                Segment::Cite { key } => inline.push_str(&self.cite_marker(key)),
                Segment::Code { source, .. } => {
                    flush(&mut inline, &mut blocks);
                    // Indent each line by four spaces — no fences, still visually a block.
                    let indented: Vec<String> =
                        source.lines().map(|l| format!("    {}", l)).collect();
                    blocks.push(indented.join("\n"));
                }
                Segment::Table { table } => {
                    flush(&mut inline, &mut blocks);
                    blocks.push(render_table_plain(table));
                }
            }
        }
        flush(&mut inline, &mut blocks);
        blocks.join("\n\n")
    }
}

/// Collapse any line breaks in `s` to single spaces — for contexts (a Markdown heading, a table
/// cell) where a raw newline would break the surrounding structure.
fn one_line(s: &str) -> String {
    s.replace(['\r', '\n'], " ")
}

/// Escape a value for a GitHub-flavoured Markdown table cell. A literal `|` starts a new column, so
/// it is backslash-escaped; line breaks (which would end the row) are flattened. Prevents an
/// adversarial or simply pipe-containing data value from desyncing the table's columns.
fn escape_md_cell(s: &str) -> String {
    one_line(s).replace('|', "\\|")
}

/// The fence for a Markdown code block whose body is `source`: at least three backticks, and always
/// one more than the longest run of backticks *inside* `source`, so code containing a ``` fence
/// cannot terminate the block early (CommonMark fenced-code rule).
fn code_fence(source: &str) -> String {
    let mut longest = 0usize;
    let mut run = 0usize;
    for c in source.chars() {
        if c == '`' {
            run += 1;
            longest = longest.max(run);
        } else {
            run = 0;
        }
    }
    "`".repeat(longest.max(2) + 1)
}

/// Sanitize a fenced-code info-string (the language tag): a single line, no backticks — either would
/// corrupt the opening fence.
fn sanitize_info_string(lang: &str) -> String {
    one_line(lang).replace('`', "").trim().to_string()
}

/// Render a table as GitHub-flavoured Markdown (`| a | b |` + `| --- | --- |`).
fn render_table_markdown(table: &Table) -> String {
    let mut lines: Vec<String> = Vec::new();
    let width = table.headers.len();
    let header: Vec<String> = table.headers.iter().map(|h| escape_md_cell(h)).collect();
    lines.push(format!("| {} |", header.join(" | ")));
    lines.push(format!("| {} |", vec!["---"; width.max(1)].join(" | ")));
    for row in &table.rows {
        // Pad / truncate defensively so a ragged row can never desync the columns, and escape each
        // cell so a `|` inside a value cannot either.
        let cells: Vec<String> = (0..width)
            .map(|i| escape_md_cell(row.get(i).map(String::as_str).unwrap_or_default()))
            .collect();
        lines.push(format!("| {} |", cells.join(" | ")));
    }
    lines.join("\n")
}

/// Render a table as space-aligned plain text — columns padded to the widest cell, no `|`.
fn render_table_plain(table: &Table) -> String {
    let width = table.headers.len();
    // Compute the max display width (in chars) per column across header + rows. Cells are flattened
    // to a single line first so an embedded newline cannot desync the space-aligned columns.
    let mut col_w = vec![0usize; width];
    for (i, h) in table.headers.iter().enumerate() {
        col_w[i] = col_w[i].max(one_line(h).chars().count());
    }
    for row in &table.rows {
        for (i, cw) in col_w.iter_mut().enumerate() {
            let cell = row.get(i).map(|c| one_line(c).chars().count()).unwrap_or(0);
            *cw = (*cw).max(cell);
        }
    }
    let fmt_row = |cells: &[String]| -> String {
        (0..width)
            .map(|i| {
                let val = cells.get(i).map(|c| one_line(c)).unwrap_or_default();
                let pad = col_w[i].saturating_sub(val.chars().count());
                format!("{}{}", val, " ".repeat(pad))
            })
            .collect::<Vec<_>>()
            .join("  ")
            .trim_end()
            .to_string()
    };
    let mut lines: Vec<String> = Vec::new();
    lines.push(fmt_row(&table.headers));
    for row in &table.rows {
        lines.push(fmt_row(row));
    }
    lines.join("\n")
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sec(heading: &str, body: Vec<Segment>) -> Section {
        Section::new(heading, body)
    }

    fn multi_section_answer() -> Answer {
        Answer::new("This is a fairly long lead sentence used to exercise the length bound.")
            .section(sec("One", vec![Segment::text("first")]))
            .section(sec("Two", vec![Segment::text("second")]))
            .section(sec("Three", vec![Segment::text("third")]))
            .section(sec("Four", vec![Segment::text("fourth")]))
            .section(sec("Five", vec![Segment::text("fifth")]))
    }

    #[test]
    fn terse_caps_sections_and_lead() {
        let long_lead = "x".repeat(500);
        let ans = Answer::new(&long_lead)
            .section(sec("A", vec![Segment::text("a")]))
            .section(sec("B", vec![Segment::text("b")]))
            .section(sec("C", vec![Segment::text("c")]));
        let c = ans.compose(Verbosity::Terse);

        // Section cap = 1, two dropped.
        assert_eq!(c.sections.len(), 1);
        assert_eq!(c.sections[0].heading, "A");
        assert!(c
            .warnings
            .iter()
            .any(|w| matches!(w, CompositionWarning::SectionsTruncated { dropped: 2 })));

        // Lead cap = 160 chars exactly (ellipsis included).
        assert_eq!(c.lead.chars().count(), 160);
        assert!(c.lead.ends_with('\u{2026}'));
        assert!(c.warnings.iter().any(|w| matches!(
            w,
            CompositionWarning::LeadTruncated {
                original_chars: 500,
                kept_chars: 160
            }
        )));
    }

    #[test]
    fn detailed_allows_more_sections_than_terse() {
        let terse = multi_section_answer().compose(Verbosity::Terse);
        let detailed = multi_section_answer().compose(Verbosity::Detailed);

        assert_eq!(terse.sections.len(), 1, "terse caps at one");
        assert_eq!(
            detailed.sections.len(),
            5,
            "detailed (cap 12) keeps all five"
        );
        assert!(!detailed
            .warnings
            .iter()
            .any(|w| matches!(w, CompositionWarning::SectionsTruncated { .. })));
        // The un-truncated lead survives verbatim at Detailed.
        assert!(!detailed.lead.ends_with('\u{2026}'));
    }

    #[test]
    fn verbosity_for_tier_mapping_and_monotone_bounds() {
        assert_eq!(Verbosity::for_tier(Tier::Simple), Verbosity::Terse);
        assert_eq!(Verbosity::for_tier(Tier::Medium), Verbosity::Normal);
        assert_eq!(Verbosity::for_tier(Tier::Complex), Verbosity::Detailed);

        let t = Verbosity::Terse.bounds();
        let n = Verbosity::Normal.bounds();
        let d = Verbosity::Detailed.bounds();
        assert!(t.max_sections < n.max_sections && n.max_sections < d.max_sections);
        assert!(t.max_lead_chars < n.max_lead_chars && n.max_lead_chars < d.max_lead_chars);
    }

    #[test]
    fn citations_dedup_and_number_in_first_appearance_order() {
        // Source "b" is cited first (section 1), then "a" (section 2), then "b" again.
        let ans = Answer::new("lead")
            .source(Citation::new("a", "Alpha Doc"))
            .source(Citation::new("b", "Bravo Doc"))
            .section(sec("S1", vec![Segment::text("claim "), Segment::cite("b")]))
            .section(sec(
                "S2",
                vec![
                    Segment::cite("a"),
                    Segment::text(" and "),
                    Segment::cite("b"),
                ],
            ));
        let c = ans.compose(Verbosity::Detailed);

        // First appearance is "b", so it is [1]; "a" is [2]. Repeated "b" does not add a reference.
        assert_eq!(c.references.len(), 2);
        assert_eq!(c.number_for("b"), Some(1));
        assert_eq!(c.number_for("a"), Some(2));
        assert_eq!(c.references[0].citation.title, "Bravo Doc");
        assert_eq!(c.references[1].citation.title, "Alpha Doc");
        // No integrity warnings: both sources cited, none dangling.
        assert!(!c.has_warnings());
    }

    #[test]
    fn dangling_citation_is_detected_and_marked() {
        let ans = Answer::new("lead")
            .source(Citation::new("real", "Real Source"))
            .section(sec(
                "S",
                vec![
                    Segment::cite("real"),
                    Segment::text(" vs "),
                    Segment::cite("ghost"),
                ],
            ));
        let c = ans.compose(Verbosity::Normal);

        assert_eq!(c.number_for("ghost"), None, "dangling gets no number");
        assert_eq!(c.number_for("real"), Some(1));
        assert!(c
            .warnings
            .iter()
            .any(|w| matches!(w, CompositionWarning::DanglingCitation { key } if key == "ghost")));
        // The dangling ref renders as [?], the real one as [1].
        let md = c.to_markdown();
        assert!(md.contains("[1]"));
        assert!(md.contains("[?]"));
    }

    #[test]
    fn dangling_warning_is_deduped_per_key() {
        let ans = Answer::new("lead").section(sec(
            "S",
            vec![Segment::cite("ghost"), Segment::cite("ghost")],
        ));
        let c = ans.compose(Verbosity::Normal);
        let count = c
            .warnings
            .iter()
            .filter(|w| matches!(w, CompositionWarning::DanglingCitation { key } if key == "ghost"))
            .count();
        assert_eq!(count, 1, "one dangling warning per key, not per occurrence");
    }

    #[test]
    fn uncited_source_is_detected() {
        let ans = Answer::new("lead")
            .source(Citation::new("used", "Used"))
            .source(Citation::new("unused", "Never Cited"))
            .section(sec("S", vec![Segment::cite("used")]));
        let c = ans.compose(Verbosity::Normal);

        assert!(c
            .warnings
            .iter()
            .any(|w| matches!(w, CompositionWarning::UncitedSource { key } if key == "unused")));
        // The unused source does not appear in the numbered references.
        assert!(c.references.iter().all(|r| r.citation.key != "unused"));
    }

    #[test]
    fn citations_only_counted_over_bounded_body() {
        // "deep" is cited only in section 2, which Terse drops -> it must become uncited, not [1].
        let ans = Answer::new("lead")
            .source(Citation::new("shallow", "Shallow"))
            .source(Citation::new("deep", "Deep"))
            .section(sec("S1", vec![Segment::cite("shallow")]))
            .section(sec("S2", vec![Segment::cite("deep")]));
        let c = ans.compose(Verbosity::Terse);

        assert_eq!(c.number_for("shallow"), Some(1));
        assert_eq!(
            c.number_for("deep"),
            None,
            "dropped-section cite is not numbered"
        );
        assert!(c
            .warnings
            .iter()
            .any(|w| matches!(w, CompositionWarning::UncitedSource { key } if key == "deep")));
    }

    #[test]
    fn markdown_places_lead_first_and_references_last() {
        let ans = Answer::new("LEAD_MARKER")
            .source(Citation::new("s", "Some Source").with_locator("https://example.test/x"))
            .section(sec("Body", vec![Segment::text("see "), Segment::cite("s")]));
        let md = ans.compose(Verbosity::Normal).to_markdown();

        let lead_at = md.find("LEAD_MARKER").expect("lead present");
        let heading_at = md.find("## Body").expect("section heading present");
        let refs_at = md.find("## References").expect("references present");
        assert!(lead_at < heading_at, "lead precedes body");
        assert!(heading_at < refs_at, "references come last");
        // References render the number, title and locator.
        assert!(md.contains("1. Some Source"));
        assert!(md.contains("https://example.test/x"));
        assert!(
            md.trim_start().starts_with("LEAD_MARKER"),
            "answer opens with the lead"
        );
    }

    #[test]
    fn markdown_renders_code_and_table_syntax() {
        let table = Table::new(
            &["Metric", "Value"],
            vec![vec!["p99".into(), "40ms".into()]],
        );
        let ans = Answer::new("lead").section(sec(
            "Detail",
            vec![
                Segment::code(Some("rust"), "let x = 1;"),
                Segment::table(table),
            ],
        ));
        let md = ans.compose(Verbosity::Detailed).to_markdown();
        assert!(md.contains("```rust\nlet x = 1;\n```"), "fenced code block");
        assert!(md.contains("| Metric | Value |"), "table header row");
        assert!(md.contains("| --- | --- |"), "table separator row");
        assert!(md.contains("| p99 | 40ms |"), "table data row");
    }

    #[test]
    fn plain_text_has_no_markdown_syntax() {
        let table = Table::new(
            &["Metric", "Value"],
            vec![vec!["p99".into(), "40ms".into()]],
        );
        let ans = Answer::new("A plain lead.")
            .source(Citation::new("s", "Src").with_locator("path/to/x"))
            .section(sec(
                "Heading",
                vec![
                    Segment::text("prose "),
                    Segment::cite("s"),
                    Segment::code(Some("rust"), "fn main() {}"),
                    Segment::table(table),
                ],
            ));
        let text = ans.compose(Verbosity::Detailed).to_plain_text();

        assert!(!text.contains('#'), "no ATX headings");
        assert!(!text.contains("```"), "no code fences");
        assert!(!text.contains('|'), "no pipe tables");
        assert!(!text.contains('*'), "no emphasis/bullets");
        // But the substance survives: heading text, prose, the [n] marker, code, table cells, refs.
        assert!(text.contains("Heading"));
        assert!(text.contains("prose [1]"));
        assert!(text.contains("fn main() {}"));
        assert!(text.contains("Metric"));
        assert!(text.contains("40ms"));
        assert!(text.contains("[1] Src - path/to/x"));
    }

    #[test]
    fn empty_answer_is_safe() {
        let c = Answer::empty().compose(Verbosity::Normal);
        assert_eq!(c.sections.len(), 0);
        assert_eq!(c.references.len(), 0);
        assert!(!c.has_warnings());
        assert_eq!(c.to_markdown(), "");
        assert_eq!(c.to_plain_text(), "");
        // Composing at every verbosity is total.
        for v in [Verbosity::Terse, Verbosity::Normal, Verbosity::Detailed] {
            let _ = Answer::empty().compose(v);
        }
    }

    #[test]
    fn lead_truncation_is_char_boundary_safe() {
        // 300 multi-byte characters; Normal caps at 400 (no cut) — build one that DOES cut.
        let lead: String = "é".repeat(500); // each 'é' is 2 bytes
        let c = Answer::new(&lead).compose(Verbosity::Terse);
        assert_eq!(c.lead.chars().count(), 160, "counted in chars, not bytes");
        assert!(c.lead.ends_with('\u{2026}'));
        // Round-trips as valid UTF-8 (would have panicked on a byte-slice mid-codepoint).
        assert!(c.lead.chars().all(|ch| ch == 'é' || ch == '\u{2026}'));
    }

    #[test]
    fn ragged_table_row_cannot_desync_columns() {
        // A row shorter than the header must not panic or misalign in either renderer.
        let table = Table::new(&["A", "B", "C"], vec![vec!["only-one".into()]]);
        let ans = Answer::new("lead").section(sec("T", vec![Segment::table(table)]));
        let c = ans.compose(Verbosity::Normal);
        let md = c.to_markdown();
        assert!(
            md.contains("| only-one |  |  |"),
            "missing cells padded empty in md"
        );
        let _ = c.to_plain_text(); // must not panic
    }

    #[test]
    fn composed_answer_serde_round_trips() {
        let ans = Answer::new("lead")
            .source(Citation::new("s", "Src"))
            .section(sec("H", vec![Segment::text("x "), Segment::cite("s")]));
        let c = ans.compose(Verbosity::Normal);
        let json = serde_json::to_string(&c).unwrap();
        let back: ComposedAnswer = serde_json::from_str(&json).unwrap();
        assert_eq!(back, c);
        // And the rebuilt value renders identically (renderers are pure over the model).
        assert_eq!(back.to_markdown(), c.to_markdown());
    }

    // ---- Formatting robustness against adversarial / real-world content ----

    #[test]
    fn table_cell_with_pipe_cannot_desync_markdown_columns() {
        // A data value containing '|' (common in real payment descriptions / regexes) must not
        // start a phantom column — it is escaped as '\|', keeping the row two cells wide.
        let table = Table::new(
            &["Field", "Value"],
            vec![vec!["rule".into(), "a|b|c".into()]],
        );
        let ans = Answer::new("lead").section(sec("T", vec![Segment::table(table)]));
        let md = ans.compose(Verbosity::Normal).to_markdown();
        assert!(
            md.contains(r"| rule | a\|b\|c |"),
            "pipe escaped, columns intact: {md}"
        );
        // Both interior pipes were backslash-escaped (so a renderer reads one 2-cell row, not four).
        let data_line = md.lines().find(|l| l.contains("rule")).unwrap();
        assert_eq!(
            data_line.matches(r"\|").count(),
            2,
            "both data pipes escaped"
        );
    }

    #[test]
    fn table_cell_with_newline_is_flattened_in_both_renderers() {
        let table = Table::new(&["K", "V"], vec![vec!["k".into(), "line1\nline2".into()]]);
        let ans = Answer::new("lead").section(sec("T", vec![Segment::table(table)]));
        let composed = ans.compose(Verbosity::Normal);

        let md = composed.to_markdown();
        // The table's data row is a single physical line (a raw newline would have split the row).
        let data_line = md.lines().find(|l| l.contains("line1")).unwrap();
        assert!(
            data_line.contains("line1 line2"),
            "newline flattened to a space in md"
        );

        let plain = composed.to_plain_text();
        assert!(
            plain.contains("line1 line2"),
            "newline flattened in plain too"
        );
    }

    #[test]
    fn code_containing_a_triple_backtick_fence_cannot_break_out() {
        // Generated code / a markdown snippet may itself contain ``` — the outer fence must be
        // LONGER so the inner backticks stay inside the block rather than closing it early.
        let inner = "before\n```\ninner fence\n```\nafter";
        let ans = Answer::new("lead").section(sec("Code", vec![Segment::code(Some("md"), inner)]));
        let md = ans.compose(Verbosity::Detailed).to_markdown();
        // Fence is four backticks (one more than the inner run of three).
        assert!(
            md.contains("````md\n"),
            "opening fence longer than inner run: {md}"
        );
        assert!(md.contains("\n````"), "closing fence matches");
        // The inner ``` survives verbatim inside the block.
        assert!(md.contains("inner fence"));
        // A plain 3-backtick fence would have appeared TWICE more (the inner pair) — assert the
        // opening/closing 4-backtick fence bounds it exactly once each.
        assert_eq!(
            md.matches("````").count(),
            2,
            "exactly one open + one close 4-fence"
        );
    }

    #[test]
    fn code_fence_scales_to_the_longest_inner_backtick_run() {
        // Five backticks inside → a six-backtick fence.
        let inner = "x ````` y";
        assert_eq!(code_fence(inner), "``````");
        // No backticks inside → the standard three.
        assert_eq!(code_fence("let x = 1;"), "```");
    }

    #[test]
    fn heading_newline_is_flattened_so_it_stays_one_line() {
        let ans =
            Answer::new("lead").section(sec("Title\n## Injected", vec![Segment::text("body")]));
        let md = ans.compose(Verbosity::Normal).to_markdown();
        // The heading is a single '## ' line; the '\n## Injected' must not become a second heading.
        let heading_lines: Vec<&str> = md.lines().filter(|l| l.starts_with("## ")).collect();
        assert_eq!(
            heading_lines.len(),
            1,
            "one heading, no injected second one: {md}"
        );
        assert_eq!(heading_lines[0], "## Title ## Injected");
    }

    #[test]
    fn info_string_with_backtick_or_newline_is_sanitized() {
        // A language tag carrying a backtick/newline would corrupt the opening fence line.
        let ans =
            Answer::new("lead").section(sec("C", vec![Segment::code(Some("ru`st\nevil"), "code")]));
        let md = ans.compose(Verbosity::Detailed).to_markdown();
        let fence_line = md.lines().find(|l| l.starts_with("```")).unwrap();
        // Strip the leading fence backticks; nothing after them may be a backtick (which would
        // prematurely close the fence) and the whole thing is a single physical line.
        let info = fence_line.trim_start_matches('`');
        assert!(
            !info.contains('`'),
            "backtick leaked into info string: {info:?}"
        );
        assert!(info.starts_with("rust"), "language preserved: {info:?}");
        // The newline in the tag was flattened, so "evil" stayed on the fence line rather than
        // being pushed onto a line of its own (which would corrupt the block).
        assert!(
            !md.lines().any(|l| l.trim() == "evil"),
            "injected newline split the info string: {md:?}"
        );
        assert!(
            info.contains("evil"),
            "the rest of the flattened tag stays on the fence line"
        );
    }
}
