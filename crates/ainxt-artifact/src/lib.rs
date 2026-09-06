// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! ainxt-artifact — the document-generation (artifact) runtime (Phase 3).
//!
//! Document generation is done from a **structured intermediate representation**, not by asking the
//! model for raw docx/markdown. The model (or the runtime) produces a [`Document`] — a typed tree of
//! blocks (headings, paragraphs, lists, tables, code, page breaks) — and a [`Renderer`] turns that IR
//! into a concrete format. Built-in renderers cover Markdown and plain text; docx/pptx/pdf/xlsx are
//! skill renderers behind the same trait. Separating IR from rendering means the same content renders
//! faithfully to every format, and the structure is validated once.
//!
//! **Compliance is audit-and-proceed, never redact.** Redacting *inside* a generated document —
//! especially a code block or a table cell — corrupts it (a half-redacted code sample won't compile,
//! a mangled table breaks layout). So [`audit_document`] scans the content and records findings, and
//! the renderer emits the content **intact**. Blocking or mutating the artifact is not done here.
//!
//! Pure and string-based; clean-room throughout.

use ainxt_types::Principal;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

mod binary;
pub use binary::{crc32, DocxRenderer, PdfRenderer, PptxRenderer, StoredZip, XlsxRenderer};

/// A block of document content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Block {
    /// A heading at `level` (1–6).
    Heading {
        level: u8,
        text: String,
    },
    Paragraph {
        text: String,
    },
    BulletList {
        items: Vec<String>,
    },
    NumberedList {
        items: Vec<String>,
    },
    /// A table with a header row and body rows.
    Table {
        headers: Vec<String>,
        rows: Vec<Vec<String>>,
    },
    /// A fenced code block — rendered verbatim, never redacted.
    Code {
        language: String,
        code: String,
    },
    PageBreak,
}

/// A structured document: a title and an ordered list of blocks.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Document {
    pub title: String,
    pub blocks: Vec<Block>,
}

impl Document {
    pub fn new(title: impl Into<String>) -> Self {
        Document {
            title: title.into(),
            blocks: Vec::new(),
        }
    }
    pub fn push(&mut self, block: Block) -> &mut Self {
        self.blocks.push(block);
        self
    }

    /// All human-readable text in the document, block by block (used by the compliance audit).
    pub fn text_segments(&self) -> Vec<String> {
        let mut out = Vec::new();
        if !self.title.is_empty() {
            out.push(self.title.clone());
        }
        for block in &self.blocks {
            match block {
                Block::Heading { text, .. } | Block::Paragraph { text } => out.push(text.clone()),
                Block::BulletList { items } | Block::NumberedList { items } => {
                    out.extend(items.iter().cloned())
                }
                Block::Table { headers, rows } => {
                    out.extend(headers.iter().cloned());
                    for row in rows {
                        out.extend(row.iter().cloned());
                    }
                }
                Block::Code { code, .. } => out.push(code.clone()),
                Block::PageBreak => {}
            }
        }
        out
    }

    /// Build a [`Document`] IR from plain/lightly-marked-up text (R16 fix, gap "doc_generation
    /// dead-ends"): the conversation surface resolves a doc-generation turn down to a `title` +
    /// resolved `body` string (the referent content — never the instruction, `CONVERSATION_
    /// INTELLIGENCE.md`), but nothing ever turned that into the structured IR
    /// [`ArtifactRuntime::generate`] / `POST /v1/artifact` require. This is the missing conversion:
    /// a real (if simple) block-structuring pass, not a single opaque paragraph, so a resolved
    /// answer with headings/lists renders as an actual heading/list in every format instead of one
    /// undifferentiated text blob.
    ///
    /// Rules, applied per blank-line-separated paragraph of `body`:
    /// * A line starting with `#`..`######` (Markdown ATX syntax) becomes a [`Block::Heading`] at
    ///   that level (text after the hashes, trimmed).
    /// * A paragraph whose lines ALL start with `-`, `*`, or `N.`/`N)` becomes a
    ///   [`Block::BulletList`] (or [`Block::NumberedList`] for the digit-prefixed form), one item
    ///   per line with its marker stripped.
    /// * Anything else becomes a [`Block::Paragraph`] with internal newlines joined by a space
    ///   (paragraphs are the unit of structure here, not raw lines).
    /// * Blank paragraphs are dropped, so leading/trailing/doubled blank lines never emit an empty
    ///   block.
    pub fn from_text(title: impl Into<String>, body: &str) -> Self {
        let mut doc = Document::new(title);
        for para in body.split("\n\n") {
            let para = para.trim();
            if para.is_empty() {
                continue;
            }
            let lines: Vec<&str> = para
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .collect();
            if lines.is_empty() {
                continue;
            }
            if lines.len() == 1 {
                if let Some(stripped) = lines[0].strip_prefix('#') {
                    let mut level: u8 = 1;
                    let mut rest = stripped;
                    while let Some(s) = rest.strip_prefix('#') {
                        level += 1;
                        rest = s;
                    }
                    if level <= 6 && rest.starts_with(' ') {
                        doc.push(Block::Heading {
                            level,
                            text: rest.trim().to_string(),
                        });
                        continue;
                    }
                }
            }
            let bulleted: Vec<&str> = lines
                .iter()
                .filter_map(|l| l.strip_prefix("- ").or_else(|| l.strip_prefix("* ")))
                .collect();
            if bulleted.len() == lines.len() {
                doc.push(Block::BulletList {
                    items: bulleted.into_iter().map(str::to_string).collect(),
                });
                continue;
            }
            let numbered: Vec<&str> = lines
                .iter()
                .filter_map(|l| {
                    let rest = l.trim_start_matches(|c: char| c.is_ascii_digit());
                    if rest.len() == l.len() {
                        return None; // no leading digits at all
                    }
                    rest.strip_prefix(". ").or_else(|| rest.strip_prefix(") "))
                })
                .collect();
            if numbered.len() == lines.len() {
                doc.push(Block::NumberedList {
                    items: numbered.into_iter().map(str::to_string).collect(),
                });
                continue;
            }
            doc.push(Block::Paragraph {
                text: lines.join(" "),
            });
        }
        doc
    }
}

/// Renders a [`Document`] to a concrete format.
///
/// Text formats implement [`render`](Renderer::render). Binary formats (docx/pptx/pdf/xlsx) are
/// skill renderers behind this *same* trait: they override [`render_bytes`](Renderer::render_bytes)
/// to emit the packaged bytes directly (an OOXML zip, a PDF byte stream, …) and set
/// [`is_binary`](Renderer::is_binary) so a surface knows to serve the payload with a binary
/// content-type instead of inlining it as text. `Send + Sync` so a single [`ArtifactRuntime`] can be
/// shared across worker threads (the platform runs many concurrent generations).
pub trait Renderer: Send + Sync {
    /// A short format id, e.g. `"markdown"`, `"docx"`.
    fn format(&self) -> &str;

    /// Render to a textual representation. Binary renderers may return an empty string and instead
    /// override [`render_bytes`](Renderer::render_bytes).
    fn render(&self, doc: &Document) -> String;

    /// Render to raw bytes. Text renderers inherit the default (`render(...).into_bytes()`); binary
    /// renderers (docx/pptx/pdf/xlsx) override this to produce the packaged artifact. The default is
    /// deliberately UTF-8 of [`render`](Renderer::render) so every text renderer is also a valid
    /// byte source without extra code.
    fn render_bytes(&self, doc: &Document) -> Vec<u8> {
        self.render(doc).into_bytes()
    }

    /// True for formats whose [`render_bytes`](Renderer::render_bytes) output is not human-readable
    /// text (docx/pdf/…). Surfaces use this to choose an attachment vs. inline rendering and a
    /// binary content-type. Defaults to `false` (text formats).
    fn is_binary(&self) -> bool {
        false
    }
}

/// Renders to GitHub-flavored Markdown.
pub struct MarkdownRenderer;

impl Renderer for MarkdownRenderer {
    fn format(&self) -> &str {
        "markdown"
    }
    fn render(&self, doc: &Document) -> String {
        let mut out = String::new();
        if !doc.title.is_empty() {
            out.push_str(&format!("# {}\n\n", doc.title));
        }
        for block in &doc.blocks {
            match block {
                Block::Heading { level, text } => {
                    let hashes = "#".repeat((*level).clamp(1, 6) as usize);
                    out.push_str(&format!("{hashes} {text}\n\n"));
                }
                Block::Paragraph { text } => out.push_str(&format!("{text}\n\n")),
                Block::BulletList { items } => {
                    for item in items {
                        out.push_str(&format!("- {item}\n"));
                    }
                    out.push('\n');
                }
                Block::NumberedList { items } => {
                    for (i, item) in items.iter().enumerate() {
                        out.push_str(&format!("{}. {item}\n", i + 1));
                    }
                    out.push('\n');
                }
                Block::Table { headers, rows } => {
                    out.push_str(&format!("| {} |\n", headers.join(" | ")));
                    out.push_str(&format!(
                        "|{}|\n",
                        headers.iter().map(|_| "---").collect::<Vec<_>>().join("|")
                    ));
                    for row in rows {
                        out.push_str(&format!("| {} |\n", row.join(" | ")));
                    }
                    out.push('\n');
                }
                Block::Code { language, code } => {
                    out.push_str(&format!("```{language}\n{code}\n```\n\n"));
                }
                Block::PageBreak => out.push_str("---\n\n"),
            }
        }
        out.trim_end().to_string()
    }
}

/// Renders to plain text (no markup) — for surfaces that need unformatted output.
pub struct PlainTextRenderer;

impl Renderer for PlainTextRenderer {
    fn format(&self) -> &str {
        "text"
    }
    fn render(&self, doc: &Document) -> String {
        let mut lines = doc.text_segments();
        lines.retain(|s| !s.is_empty());
        lines.join("\n")
    }
}

/// Scans text for compliance-sensitive content, returning finding labels (never mutating). A real
/// deployment plugs in the enterprise PCI/DSS detector (the enterprise engine lives in a private plugin
/// repo per the core/enterprise split); the in-tree [`LuhnEntropyScanner`] is a real-but-generic
/// default (Luhn + Shannon entropy), and [`MarkerScanner`] is the minimal deterministic floor.
/// `Send + Sync` so it can back a shared [`ArtifactRuntime`].
pub trait ContentScanner: Send + Sync {
    fn scan(&self, text: &str) -> Vec<String>;
}

/// Deterministic scanner: long digit runs (PAN-like, ≥12) and common secret markers.
pub struct MarkerScanner;

impl ContentScanner for MarkerScanner {
    fn scan(&self, text: &str) -> Vec<String> {
        let mut findings = Vec::new();
        let mut run = 0usize;
        for c in text.chars() {
            if c.is_ascii_digit() {
                run += 1;
            } else {
                if run >= 12 {
                    findings.push("PAN-like digit run".to_string());
                }
                run = 0;
            }
        }
        if run >= 12 {
            findings.push("PAN-like digit run".to_string());
        }
        for marker in ["PAN=", "SECRET=", "API_KEY=", "TOKEN=", "token="] {
            if text.contains(marker) {
                findings.push(format!("secret marker '{marker}'"));
            }
        }
        findings
    }
}

/// A real-but-generic content scanner: Luhn-validated card numbers + Shannon-entropy secret
/// detection, mirroring the platform's "regex + Luhn + entropy" discipline without embedding any
/// enterprise-specific (private) rules. It is a genuine detector, not a marker floor:
///
/// - **PAN:** a digit run of 13–19 digits (allowing spaces/hyphens as separators) that passes the
///   Luhn checksum is flagged `"PAN (Luhn-valid)"`. A same-length run that fails Luhn is NOT a
///   false positive — this is the whole point of Luhn over a bare digit-run heuristic.
/// - **High-entropy secret:** a token of ≥20 chars mixing letter+digit (typical API-key/JWT shape)
///   whose Shannon entropy per char ≥ 3.5 bits is flagged `"high-entropy secret"`.
///
/// Deterministic, allocation-light, no regex/rng/clock. The enterprise deployment replaces this via
/// the [`ContentScanner`] seam with the full PCI/DSS engine (Aadhaar/UPI/IFSC/PIN-block/etc.).
pub struct LuhnEntropyScanner;

impl LuhnEntropyScanner {
    /// Luhn checksum over an already-extracted digit string. Empty/short input is not valid.
    fn luhn_ok(digits: &[u8]) -> bool {
        if !(13..=19).contains(&digits.len()) {
            return false;
        }
        let mut sum = 0u32;
        // Double every second digit from the right.
        for (i, &d) in digits.iter().rev().enumerate() {
            let mut v = d as u32;
            if i % 2 == 1 {
                v *= 2;
                if v > 9 {
                    v -= 9;
                }
            }
            sum += v;
        }
        sum % 10 == 0
    }

    /// Shannon entropy (bits per character) of a token.
    fn shannon_bits_per_char(token: &str) -> f64 {
        let n = token.chars().count();
        if n == 0 {
            return 0.0;
        }
        let mut counts: BTreeMap<char, u32> = BTreeMap::new();
        for c in token.chars() {
            *counts.entry(c).or_insert(0) += 1;
        }
        let n_f = n as f64;
        let mut h = 0.0f64;
        for &c in counts.values() {
            let p = c as f64 / n_f;
            h -= p * p.log2();
        }
        h
    }
}

impl ContentScanner for LuhnEntropyScanner {
    fn scan(&self, text: &str) -> Vec<String> {
        let mut findings = Vec::new();

        // --- PAN: scan maximal runs of digits with optional single space/hyphen separators. -----
        // We walk the text collecting digit sequences where digits may be split by a lone ' ' or
        // '-' (card formatting). A separator only continues a run if it sits between two digits.
        let chars: Vec<char> = text.chars().collect();
        let mut i = 0usize;
        let mut pan_found = false;
        while i < chars.len() {
            if chars[i].is_ascii_digit() {
                let mut digits: Vec<u8> = Vec::new();
                let mut j = i;
                while j < chars.len() {
                    if chars[j].is_ascii_digit() {
                        digits.push(chars[j] as u8 - b'0');
                        j += 1;
                    } else if (chars[j] == ' ' || chars[j] == '-')
                        && j + 1 < chars.len()
                        && chars[j + 1].is_ascii_digit()
                    {
                        // separator between two digits — keep going but don't record it.
                        j += 1;
                    } else {
                        break;
                    }
                }
                if Self::luhn_ok(&digits) {
                    pan_found = true;
                }
                i = j;
            } else {
                i += 1;
            }
        }
        if pan_found {
            findings.push("PAN (Luhn-valid)".to_string());
        }

        // --- High-entropy secret: whitespace-delimited tokens of a key-ish shape. ----------------
        let mut secret_found = false;
        for token in text.split(|c: char| c.is_whitespace()) {
            let len = token.chars().count();
            if len < 20 {
                continue;
            }
            let has_alpha = token.chars().any(|c| c.is_ascii_alphabetic());
            let has_digit = token.chars().any(|c| c.is_ascii_digit());
            if !(has_alpha && has_digit) {
                continue;
            }
            if Self::shannon_bits_per_char(token) >= 3.5 {
                secret_found = true;
            }
        }
        if secret_found {
            findings.push("high-entropy secret".to_string());
        }

        findings
    }
}

/// One audit finding: which block (index; `None` = the title) and what was flagged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditFinding {
    pub block_index: Option<usize>,
    pub label: String,
}

/// **Audit-and-proceed:** scan every text segment of the document and return findings. The document
/// is NOT modified — callers record the findings (for the audit trail) and render the content intact.
pub fn audit_document(doc: &Document, scanner: &dyn ContentScanner) -> Vec<AuditFinding> {
    let mut findings = Vec::new();
    for label in scanner.scan(&doc.title) {
        findings.push(AuditFinding {
            block_index: None,
            label,
        });
    }
    for (i, block) in doc.blocks.iter().enumerate() {
        let text = match block {
            Block::Heading { text, .. } | Block::Paragraph { text } => text.clone(),
            Block::BulletList { items } | Block::NumberedList { items } => items.join("\n"),
            Block::Table { headers, rows } => {
                let mut t = headers.join("\n");
                for row in rows {
                    t.push('\n');
                    t.push_str(&row.join("\n"));
                }
                t
            }
            Block::Code { code, .. } => code.clone(),
            Block::PageBreak => String::new(),
        };
        for label in scanner.scan(&text) {
            findings.push(AuditFinding {
                block_index: Some(i),
                label,
            });
        }
    }
    findings
}

// ===========================================================================
// ArtifactRuntime — the one-shot wiring seam for a live surface (Phase-3)
// ===========================================================================

/// Resource caps for a single generation, so a hostile/broken document cannot exhaust a worker.
/// Enforced *before* audit or rendering. Defaults are generous but bounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArtifactLimits {
    /// Maximum number of blocks in the document.
    pub max_blocks: usize,
    /// Maximum total UTF-8 bytes across every text segment (title + block text).
    pub max_total_bytes: usize,
}

impl Default for ArtifactLimits {
    fn default() -> Self {
        ArtifactLimits {
            max_blocks: 10_000,
            max_total_bytes: 8 * 1024 * 1024, // 8 MiB of source text
        }
    }
}

/// The result of a generation: the rendered bytes, the format id, the (non-blocking) audit findings,
/// and the invariant `redacted == false` (artifact compliance is **audit-and-proceed**, never redact).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactOutput {
    pub format: String,
    /// Rendered payload. For text formats this is UTF-8; for binary formats (docx/pdf) it is the
    /// packaged bytes. Use [`is_binary`](ArtifactOutput::is_binary) to decide how to serve it.
    pub bytes: Vec<u8>,
    pub is_binary: bool,
    /// Compliance findings recorded for the audit trail. **Never** empties the output — the content
    /// is emitted intact regardless (audit-and-proceed).
    pub findings: Vec<AuditFinding>,
    /// Always `false`: this runtime records findings, it does not redact the artifact.
    pub redacted: bool,
}

impl ArtifactOutput {
    pub fn is_binary(&self) -> bool {
        self.is_binary
    }
    /// Best-effort text view (lossy for true binary formats); handy for text surfaces/tests.
    pub fn text_lossy(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.bytes)
    }
}

/// Why a generation could not be produced. Note: a compliance finding is **not** an error — findings
/// ride along on a successful [`ArtifactOutput`]. Errors are structural only (unknown format, too big).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactError {
    /// No renderer is registered for the requested format id.
    UnknownFormat(String),
    /// The document exceeds a configured [`ArtifactLimits`] bound.
    TooLarge {
        limit: usize,
        actual: usize,
        what: &'static str,
    },
}

impl std::fmt::Display for ArtifactError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArtifactError::UnknownFormat(fmt) => {
                write!(f, "no renderer registered for format {fmt:?}")
            }
            ArtifactError::TooLarge {
                limit,
                actual,
                what,
            } => {
                write!(
                    f,
                    "document too large: {what} {actual} exceeds limit {limit}"
                )
            }
        }
    }
}

impl std::error::Error for ArtifactError {}

/// The live artifact runtime: a registry of [`Renderer`]s + an injected [`ContentScanner`] + resource
/// limits, exposing a single [`generate`](ArtifactRuntime::generate) call for a surface (Chat / Buddy
/// / SDLC) to turn a [`Document`] IR into a rendered artifact with its audit trail in one shot.
///
/// This is the clean wiring entrypoint the parent (`ainxt-surface`) constructs once at startup:
/// register the built-in renderers, inject the deployment's PCI scanner, then call `generate` per
/// output. `Send + Sync` (renderer/scanner bounds guarantee it) so it can be shared across workers.
pub struct ArtifactRuntime {
    renderers: BTreeMap<String, Box<dyn Renderer>>,
    scanner: Box<dyn ContentScanner>,
    limits: ArtifactLimits,
}

impl ArtifactRuntime {
    /// A runtime with the injected scanner and default limits, no renderers yet.
    pub fn new(scanner: Box<dyn ContentScanner>) -> Self {
        ArtifactRuntime {
            renderers: BTreeMap::new(),
            scanner,
            limits: ArtifactLimits::default(),
        }
    }

    /// The batteries-included default: Markdown + plain-text renderers and the injected scanner.
    /// Binary (docx/pptx/pdf/xlsx) renderers are registered on top via [`register`](Self::register).
    pub fn with_builtin_renderers(scanner: Box<dyn ContentScanner>) -> Self {
        let mut rt = Self::new(scanner);
        rt.register(Box::new(MarkdownRenderer));
        rt.register(Box::new(PlainTextRenderer));
        rt
    }

    /// The full batteries-included set: the text renderers PLUS the dependency-free binary
    /// renderers (`pdf`, `docx`, `xlsx`, `pptx`) — gap DATA "binary artifact renderers". `pptx`
    /// packages the full PresentationML slide master → layout → theme chain in-tree (round-12: the
    /// previously-deferred skill seam is now a real renderer behind the same trait).
    pub fn with_all_renderers(scanner: Box<dyn ContentScanner>) -> Self {
        let mut rt = Self::with_builtin_renderers(scanner);
        rt.register(Box::new(PdfRenderer));
        rt.register(Box::new(DocxRenderer));
        rt.register(Box::new(XlsxRenderer));
        rt.register(Box::new(PptxRenderer));
        rt
    }

    pub fn with_limits(mut self, limits: ArtifactLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Register (or replace) a renderer, keyed by its [`Renderer::format`] id.
    pub fn register(&mut self, renderer: Box<dyn Renderer>) -> &mut Self {
        self.renderers
            .insert(renderer.format().to_string(), renderer);
        self
    }

    /// Format ids currently registered, sorted.
    pub fn formats(&self) -> Vec<&str> {
        self.renderers.keys().map(String::as_str).collect()
    }

    fn check_limits(&self, doc: &Document) -> Result<(), ArtifactError> {
        if doc.blocks.len() > self.limits.max_blocks {
            return Err(ArtifactError::TooLarge {
                limit: self.limits.max_blocks,
                actual: doc.blocks.len(),
                what: "blocks",
            });
        }
        let total: usize = doc.text_segments().iter().map(|s| s.len()).sum();
        if total > self.limits.max_total_bytes {
            return Err(ArtifactError::TooLarge {
                limit: self.limits.max_total_bytes,
                actual: total,
                what: "text bytes",
            });
        }
        Ok(())
    }

    /// **One-shot generate:** enforce limits → audit (record, never block) → render. Returns the
    /// rendered bytes plus the findings. Structural failures (unknown format, oversized document)
    /// are the only `Err`; a compliance finding never blocks and rides along on `Ok`.
    pub fn generate(&self, doc: &Document, format: &str) -> Result<ArtifactOutput, ArtifactError> {
        self.check_limits(doc)?;
        let renderer = self
            .renderers
            .get(format)
            .ok_or_else(|| ArtifactError::UnknownFormat(format.to_string()))?;
        // Audit-and-proceed: findings are recorded, the content is emitted intact.
        let mut findings = audit_document(doc, self.scanner.as_ref());
        // GAP-AUDIT data-surfaces-artifacts #6 (remainder): the PDF renderer's WinAnsi font cannot
        // represent CJK/Devanagari/emoji/etc. and silently drops them to a blank space. A font asset
        // to fix the rendering itself is out of scope for this runtime, but the loss must not also be
        // invisible to the audit trail — record it as a finding (audit-and-proceed, never blocking)
        // exactly like a compliance hit, so an India-market document with a Devanagari name or similar
        // leaves a trace instead of silently vanishing.
        if format == "pdf" {
            let dropped = PdfRenderer::unrepresentable_chars(doc);
            if !dropped.is_empty() {
                findings.push(AuditFinding {
                    block_index: None,
                    label: format!(
                        "PDF_UNREPRESENTABLE_CHARS: {} distinct character(s) not representable in the \
                         built-in WinAnsi font and rendered as blank spaces: {:?}",
                        dropped.len(),
                        dropped
                    ),
                });
            }
        }
        let bytes = renderer.render_bytes(doc);
        Ok(ArtifactOutput {
            format: format.to_string(),
            bytes,
            is_binary: renderer.is_binary(),
            findings,
            redacted: false,
        })
    }
}

// ===========================================================================
// The RBAC-scoped, route-ready generate entrypoint (R6 DATA)
// ===========================================================================

/// Capability that admits the document-generation (artifact) surface. Checked **before** anything
/// else in [`ArtifactRuntime::generate_for`], so a caller without it learns nothing — not even which
/// formats are registered or what the size limits are (mirrors [`ainxt_nl2sql::CAP_QUERY_LEDGER`] and
/// the graph surface: one capability-based Principal drives every non-chat route). `role == Admin`
/// implies it, per [`Principal::has_cap`].
pub const CAP_ARTIFACT_GENERATE: &str = "artifact.generate";

/// The route-ready request body a transport (`POST /v1/artifact`) deserializes straight from the
/// wire: the structured [`Document`] IR the model/runtime produced, plus the target `format` id. The
/// document is a validated IR — the model never emits raw docx/markdown — so there is no injection
/// surface here (contrast the nl2sql boundary). `deny_unknown_fields` rejects a smuggled extra key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRequest {
    pub document: Document,
    pub format: String,
}

/// Why a route-ready [`ArtifactRuntime::generate_for`] was refused — the serializable superset of
/// [`ArtifactError`] with an authorization variant, so a transport renders the refusal verbatim and
/// maps [`ArtifactGenError::NotAuthorized`] to `403` while the structural variants map to `404`/`413`.
///
/// A compliance **finding is never an error** and never appears here: findings ride along on a
/// successful [`ArtifactOutput`] (audit-and-proceed). Only authorization and structural problems fail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum ArtifactGenError {
    /// The caller does not hold [`CAP_ARTIFACT_GENERATE`]. Raised before any format/limit is
    /// consulted, so a caller without the capability learns nothing about the surface (→ 403).
    NotAuthorized,
    /// No renderer is registered for the requested format id (→ 404).
    UnknownFormat(String),
    /// The document exceeds a configured [`ArtifactLimits`] bound (→ 413).
    TooLarge {
        limit: usize,
        actual: usize,
        what: String,
    },
}

impl std::fmt::Display for ArtifactGenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArtifactGenError::NotAuthorized => write!(f, "not authorized to generate artifacts"),
            ArtifactGenError::UnknownFormat(fmt) => {
                write!(f, "no renderer registered for format {fmt:?}")
            }
            ArtifactGenError::TooLarge {
                limit,
                actual,
                what,
            } => {
                write!(
                    f,
                    "document too large: {what} {actual} exceeds limit {limit}"
                )
            }
        }
    }
}

impl std::error::Error for ArtifactGenError {}

impl From<ArtifactError> for ArtifactGenError {
    fn from(e: ArtifactError) -> Self {
        match e {
            ArtifactError::UnknownFormat(fmt) => ArtifactGenError::UnknownFormat(fmt),
            ArtifactError::TooLarge {
                limit,
                actual,
                what,
            } => ArtifactGenError::TooLarge {
                limit,
                actual,
                what: what.to_string(),
            },
        }
    }
}

impl ArtifactRuntime {
    /// **The RBAC-scoped, route-ready generate entrypoint** a server mounts at `POST /v1/artifact`.
    ///
    /// It is the authorized counterpart to [`generate`](Self::generate): the caller's [`Principal`]
    /// gates the whole surface on [`CAP_ARTIFACT_GENERATE`] (fail-closed, checked **before** any
    /// format lookup or limit check, so the error shape is no capability oracle), then it delegates
    /// to `generate`. Compliance stays **audit-and-proceed** — findings are recorded on the returned
    /// [`ArtifactOutput`] and the content is emitted intact; a finding never fails the call and never
    /// redacts (redacting a code block or table cell would corrupt the artifact).
    ///
    /// Request and error are `Serialize`/`Deserialize`, so a transport can round-trip the wire body
    /// and render a refusal verbatim (mapping [`ArtifactGenError::NotAuthorized`] → 403).
    pub fn generate_for(
        &self,
        principal: &Principal,
        req: &ArtifactRequest,
    ) -> Result<ArtifactOutput, ArtifactGenError> {
        if !principal.has_cap(CAP_ARTIFACT_GENERATE) {
            return Err(ArtifactGenError::NotAuthorized);
        }
        Ok(self.generate(&req.document, &req.format)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Document {
        let mut d = Document::new("Quarterly Report");
        d.push(Block::Heading {
            level: 2,
            text: "Overview".into(),
        })
        .push(Block::Paragraph {
            text: "UPI volumes grew.".into(),
        })
        .push(Block::BulletList {
            items: vec!["point one".into(), "point two".into()],
        })
        .push(Block::NumberedList {
            items: vec!["first".into(), "second".into()],
        })
        .push(Block::Table {
            headers: vec!["Month".into(), "Txns".into()],
            rows: vec![vec!["Jan".into(), "100".into()]],
        })
        .push(Block::Code {
            language: "python".into(),
            code: "print('hi')".into(),
        })
        .push(Block::PageBreak);
        d
    }

    // -- Document::from_text (R16 fix: doc_generation → real ainxt_artifact::Document) ----------

    #[test]
    fn from_text_structures_headings_lists_and_paragraphs() {
        let body = "# Settlement Summary\n\n\
                     Total settlements ran clean this cycle.\n\n\
                     - failed: 0\n\
                     - pending: 2\n\n\
                     1. verify ledger\n\
                     2. notify ops\n\n\
                     A closing paragraph\nwrapped across two lines.";
        let doc = Document::from_text("Report", body);
        assert_eq!(doc.title, "Report");
        assert_eq!(
            doc.blocks,
            vec![
                Block::Heading {
                    level: 1,
                    text: "Settlement Summary".into(),
                },
                Block::Paragraph {
                    text: "Total settlements ran clean this cycle.".into(),
                },
                Block::BulletList {
                    items: vec!["failed: 0".into(), "pending: 2".into()],
                },
                Block::NumberedList {
                    items: vec!["verify ledger".into(), "notify ops".into()],
                },
                Block::Paragraph {
                    text: "A closing paragraph wrapped across two lines.".into(),
                },
            ]
        );
    }

    #[test]
    fn from_text_drops_blank_paragraphs_and_handles_plain_prose() {
        let doc = Document::from_text("T", "\n\nJust one plain paragraph.\n\n\n");
        assert_eq!(
            doc.blocks,
            vec![Block::Paragraph {
                text: "Just one plain paragraph.".into(),
            }]
        );
    }

    /// The built `Document` is not a dead-end IR: it renders and it audits, exactly like a
    /// hand-built one — proving this is a real construction path into the existing artifact
    /// runtime (`ArtifactRuntime::generate`), not a parallel/inert type.
    #[test]
    fn from_text_output_is_a_real_renderable_document() {
        let doc = Document::from_text("Weekly Digest", "# Digest\n\n- item one\n- item two");
        let rt = ArtifactRuntime::with_builtin_renderers(Box::new(MarkerScanner));
        let out = rt.generate(&doc, "markdown").expect("renders");
        assert!(out.text_lossy().contains("# Weekly Digest"));
        assert!(out.text_lossy().contains("# Digest"));
        assert!(out.text_lossy().contains("- item one"));
    }

    #[test]
    fn markdown_renders_all_block_types() {
        let md = MarkdownRenderer.render(&sample());
        assert!(md.starts_with("# Quarterly Report"));
        assert!(md.contains("## Overview"));
        assert!(md.contains("- point one"));
        assert!(md.contains("1. first"));
        assert!(md.contains("| Month | Txns |"));
        assert!(md.contains("|---|---|"));
        assert!(md.contains("| Jan | 100 |"));
        assert!(md.contains("```python\nprint('hi')\n```"));
        assert!(md.contains("---"));
    }

    #[test]
    fn heading_level_is_clamped() {
        let mut d = Document::new("");
        d.push(Block::Heading {
            level: 9,
            text: "x".into(),
        });
        assert!(MarkdownRenderer.render(&d).starts_with("###### x")); // clamped to 6
    }

    #[test]
    fn plain_text_strips_markup() {
        let txt = PlainTextRenderer.render(&sample());
        assert!(txt.contains("Quarterly Report"));
        assert!(txt.contains("print('hi')"));
        assert!(!txt.contains("##"));
        assert!(!txt.contains("```"));
    }

    #[test]
    fn document_serde_round_trips() {
        let d = sample();
        let json = serde_json::to_string(&d).unwrap();
        let back: Document = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }

    #[test]
    fn audit_finds_but_never_redacts() {
        let mut d = Document::new("Statement");
        d.push(Block::Paragraph {
            text: "Card 4111111111111111 on file.".into(),
        });
        let findings = audit_document(&d, &MarkerScanner);
        assert!(!findings.is_empty(), "the PAN must be flagged");
        assert_eq!(findings[0].block_index, Some(0));
        // AUDIT-and-proceed: the rendered document still contains the original content intact.
        let md = MarkdownRenderer.render(&d);
        assert!(
            md.contains("4111111111111111"),
            "content must NOT be redacted (audit-and-proceed)"
        );
    }

    #[test]
    fn code_block_is_never_corrupted_by_compliance() {
        // A secret marker inside code is flagged but the code stays byte-for-byte intact (redacting
        // it would break the code).
        let mut d = Document::new("");
        d.push(Block::Code {
            language: "sh".into(),
            code: "export TOKEN=abc123 && run".into(),
        });
        let findings = audit_document(&d, &MarkerScanner);
        assert!(findings.iter().any(|f| f.label.contains("TOKEN=")));
        let md = MarkdownRenderer.render(&d);
        assert!(
            md.contains("export TOKEN=abc123 && run"),
            "code must be emitted verbatim"
        );
    }

    #[test]
    fn clean_document_has_no_findings() {
        assert!(audit_document(&sample(), &MarkerScanner).is_empty());
    }

    #[test]
    fn text_segments_cover_every_block() {
        let segs = sample().text_segments();
        assert!(segs.contains(&"Quarterly Report".to_string()));
        assert!(segs.contains(&"point two".to_string()));
        assert!(segs.contains(&"100".to_string()));
        assert!(segs.contains(&"print('hi')".to_string()));
    }

    // =======================================================================
    // SURF-13 — Artifact IR runtime as a one-shot live-surface entrypoint
    // =======================================================================

    /// A fake surface-side scanner injected into the runtime, proving the ContentScanner seam is
    /// wired through `generate` exactly as `ainxt-surface` would inject its PCI engine.
    struct FakeInjectedScanner;
    impl ContentScanner for FakeInjectedScanner {
        fn scan(&self, text: &str) -> Vec<String> {
            if text.contains("LEDGER-SECRET") {
                vec!["injected-detector-hit".to_string()]
            } else {
                Vec::new()
            }
        }
    }

    #[test]
    fn gap_ainxt_artifact_surf13_runtime_generate_audits_and_renders() {
        // The parent constructs ONE runtime with built-ins + an injected scanner, then calls
        // generate() per output — the clean wiring seam that was previously missing.
        let rt = ArtifactRuntime::with_builtin_renderers(Box::new(FakeInjectedScanner));
        assert!(rt.formats().contains(&"markdown"));
        assert!(rt.formats().contains(&"text"));

        let mut d = Document::new("Report");
        d.push(Block::Paragraph {
            text: "value LEDGER-SECRET present".into(),
        })
        .push(Block::Code {
            language: "sql".into(),
            code: "select 1".into(),
        });

        let out = rt.generate(&d, "markdown").expect("markdown is registered");
        // Audit-and-proceed: the injected finding is recorded...
        assert!(
            out.findings
                .iter()
                .any(|f| f.label == "injected-detector-hit"),
            "the injected scanner must be consulted through generate()"
        );
        // ...but the content is emitted INTACT and never redacted.
        assert!(!out.redacted);
        assert!(out.text_lossy().contains("LEDGER-SECRET present"));
        assert!(!out.is_binary());

        // Unknown format is a structural error (not a panic, not a silent empty).
        assert_eq!(
            rt.generate(&d, "docx"),
            Err(ArtifactError::UnknownFormat("docx".to_string()))
        );
    }

    #[test]
    fn gap_ainxt_artifact_surf13_runtime_enforces_limits() {
        let rt = ArtifactRuntime::with_builtin_renderers(Box::new(MarkerScanner)).with_limits(
            ArtifactLimits {
                max_blocks: 2,
                max_total_bytes: 1024,
            },
        );
        let mut d = Document::new("");
        for _ in 0..5 {
            d.push(Block::Paragraph { text: "x".into() });
        }
        match rt.generate(&d, "markdown") {
            Err(ArtifactError::TooLarge {
                what: "blocks",
                actual: 5,
                limit: 2,
            }) => {}
            other => panic!("expected TooLarge(blocks), got {other:?}"),
        }
    }

    // =======================================================================
    // SURF-14 — binary renderers (docx/pptx/pdf/xlsx) behind the same trait
    // =======================================================================

    /// A stand-in binary renderer (as a docx/pdf skill renderer would be): it overrides
    /// `render_bytes` to emit a non-UTF-8 packaged payload and marks itself binary. Proves the
    /// Renderer trait now carries a byte path so real OOXML/PDF skill renderers plug straight in.
    struct FakeZipRenderer;
    impl Renderer for FakeZipRenderer {
        fn format(&self) -> &str {
            "docx"
        }
        fn render(&self, _doc: &Document) -> String {
            String::new() // binary format has no meaningful text rendering
        }
        fn render_bytes(&self, doc: &Document) -> Vec<u8> {
            // A fake OOXML zip: PK magic header + a non-UTF-8 byte + the title bytes.
            let mut b = vec![0x50, 0x4B, 0x03, 0x04, 0xFF];
            b.extend_from_slice(doc.title.as_bytes());
            b
        }
        fn is_binary(&self) -> bool {
            true
        }
    }

    #[test]
    fn gap_ainxt_artifact_surf14_binary_renderer_seam() {
        let mut rt = ArtifactRuntime::with_builtin_renderers(Box::new(MarkerScanner));
        rt.register(Box::new(FakeZipRenderer));
        assert!(rt.formats().contains(&"docx"));

        let d = Document::new("Q3");
        let out = rt.generate(&d, "docx").expect("docx renderer registered");
        assert!(out.is_binary(), "binary format must be flagged binary");
        // The PK zip magic and the non-UTF-8 byte survive — proving a true byte path, not String.
        assert_eq!(&out.bytes[..4], &[0x50, 0x4B, 0x03, 0x04]);
        assert!(
            out.bytes.contains(&0xFF),
            "non-UTF-8 byte must pass through intact"
        );
        assert!(out.bytes.ends_with(b"Q3"));
    }

    // =======================================================================
    // SURF-15 — real PCI-style detector (Luhn + entropy) behind the seam
    // =======================================================================

    #[test]
    fn gap_ainxt_artifact_surf15_luhn_entropy_scanner() {
        let s = LuhnEntropyScanner;

        // A valid-Luhn 16-digit PAN is flagged...
        assert!(
            s.scan("card 4111111111111111 on file")
                .iter()
                .any(|f| f == "PAN (Luhn-valid)"),
            "a Luhn-valid PAN must be flagged"
        );
        // ...formatted with spaces too (real card formatting).
        assert!(s
            .scan("4111 1111 1111 1111")
            .iter()
            .any(|f| f == "PAN (Luhn-valid)"));

        // A 16-digit run that FAILS Luhn is NOT a PAN false-positive — the key advance over the
        // digit-run floor. (MarkerScanner would wrongly flag this.)
        assert!(
            !s.scan("order 1234567890123456 shipped")
                .iter()
                .any(|f| f == "PAN (Luhn-valid)"),
            "a non-Luhn digit run must NOT be reported as a PAN"
        );
        assert!(
            MarkerScanner
                .scan("order 1234567890123456 shipped")
                .iter()
                .any(|f| f.contains("PAN-like")),
            "the floor scanner over-flags — this is exactly what Luhn fixes"
        );

        // A high-entropy API-key-shaped token is flagged...
        assert!(
            s.scan("key sk9aZ3xQ7bW2pL8mN4tR6vY0uH1cE5d")
                .iter()
                .any(|f| f == "high-entropy secret"),
            "a high-entropy key token must be flagged"
        );
        // ...but ordinary low-entropy prose is not.
        assert!(s
            .scan("the quick brown fox jumps over the lazy dog again")
            .is_empty());
    }

    #[test]
    fn gap_ainxt_artifact_surf15_scanner_is_injectable_and_never_redacts() {
        // Wired through the runtime, the stronger scanner still audits-and-proceeds.
        let rt = ArtifactRuntime::with_builtin_renderers(Box::new(LuhnEntropyScanner));
        let mut d = Document::new("Statement");
        d.push(Block::Paragraph {
            text: "PAN 4111111111111111 recorded".into(),
        });
        let out = rt.generate(&d, "markdown").unwrap();
        assert!(out.findings.iter().any(|f| f.label == "PAN (Luhn-valid)"));
        assert!(!out.redacted);
        assert!(out.text_lossy().contains("4111111111111111"));
    }
}
