// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Binary artifact renderers (gap DATA: "binary artifact renderers docx/pptx/pdf/xlsx").
//!
//! These are the `render_bytes`-overriding [`Renderer`](crate::Renderer)s the module docs promised
//! "behind the same seam". They are **real, dependency-free** emitters — no `printpdf`/`docx-rs`/zip
//! crate enters the supply-chain surface (the crate forbids `unsafe` and vendors nothing copyleft):
//!
//! * [`PdfRenderer`] hand-emits a valid PDF byte stream (catalog → pages → per-page content streams
//!   with a WinAnsi Helvetica font) with a correct `xref` table and `startxref` offset;
//! * [`DocxRenderer`] and [`XlsxRenderer`] package structurally-valid OOXML (`[Content_Types].xml`
//!   `_rels` + the main part) into a STORED (uncompressed) ZIP written by [`StoredZip`], so the
//!   output opens in Word/Excel without any external library.
//!
//! Compliance stays AUDIT-and-proceed: like the text renderers, these emit content INTACT (a redact
//! inside a docx run or a pdf text object would corrupt the container). The audit runs in
//! [`ArtifactRuntime::generate`](crate::ArtifactRuntime) before rendering, exactly as for text.
//!
//! [`PptxRenderer`] closes the round-11 residual: it now packages structurally-valid **PresentationML**
//! (`ppt/presentation.xml` + the slide **master → layout → theme** chain PowerPoint requires, plus one
//! `ppt/slides/slideN.xml` per page) into the same STORED ZIP — dependency-free, no external OOXML
//! library. A `PageBreak` starts a new slide; each slide carries a title placeholder + a body text box.

use crate::{Block, Document, Renderer};

// ===========================================================================
// CRC-32 (IEEE 802.3) — the checksum every ZIP local/central header carries.
// ===========================================================================

/// IEEE CRC-32 of `data`. Table-free (bit-at-a-time) — small, pure, and exact; a document artifact
/// is not a hot path, so the table's memory is not worth it.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

// ===========================================================================
// STORED-method ZIP writer (the OOXML container).
// ===========================================================================

/// A minimal, deterministic ZIP writer using the STORED (no-compression) method. Deterministic
/// because it writes zeroed mod-time/date and no extra fields — the same document always yields the
/// same bytes (replayable). Sufficient for OOXML: Office reads STORED entries.
#[derive(Default)]
pub struct StoredZip {
    entries: Vec<ZipEntry>,
}

struct ZipEntry {
    name: String,
    data: Vec<u8>,
    crc: u32,
    offset: u32,
}

impl StoredZip {
    pub fn new() -> Self {
        StoredZip::default()
    }

    /// Add a file at archive path `name` with raw `data`.
    pub fn add(&mut self, name: &str, data: impl Into<Vec<u8>>) -> &mut Self {
        let data = data.into();
        let crc = crc32(&data);
        self.entries.push(ZipEntry {
            name: name.to_string(),
            data,
            crc,
            offset: 0,
        });
        self
    }

    /// Serialize the archive to bytes.
    pub fn finish(mut self) -> Vec<u8> {
        let mut out = Vec::new();
        // Local file headers + data.
        for e in &mut self.entries {
            e.offset = out.len() as u32;
            out.extend_from_slice(&0x0403_4b50u32.to_le_bytes()); // local header sig
            out.extend_from_slice(&20u16.to_le_bytes()); // version needed
            out.extend_from_slice(&0u16.to_le_bytes()); // flags
            out.extend_from_slice(&0u16.to_le_bytes()); // method: stored
            out.extend_from_slice(&0u16.to_le_bytes()); // mod time
            out.extend_from_slice(&0u16.to_le_bytes()); // mod date
            out.extend_from_slice(&e.crc.to_le_bytes());
            out.extend_from_slice(&(e.data.len() as u32).to_le_bytes()); // compressed size
            out.extend_from_slice(&(e.data.len() as u32).to_le_bytes()); // uncompressed size
            out.extend_from_slice(&(e.name.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes()); // extra len
            out.extend_from_slice(e.name.as_bytes());
            out.extend_from_slice(&e.data);
        }
        // Central directory.
        let cd_start = out.len() as u32;
        for e in &self.entries {
            out.extend_from_slice(&0x0201_4b50u32.to_le_bytes()); // central dir sig
            out.extend_from_slice(&20u16.to_le_bytes()); // version made by
            out.extend_from_slice(&20u16.to_le_bytes()); // version needed
            out.extend_from_slice(&0u16.to_le_bytes()); // flags
            out.extend_from_slice(&0u16.to_le_bytes()); // method
            out.extend_from_slice(&0u16.to_le_bytes()); // mod time
            out.extend_from_slice(&0u16.to_le_bytes()); // mod date
            out.extend_from_slice(&e.crc.to_le_bytes());
            out.extend_from_slice(&(e.data.len() as u32).to_le_bytes());
            out.extend_from_slice(&(e.data.len() as u32).to_le_bytes());
            out.extend_from_slice(&(e.name.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes()); // extra len
            out.extend_from_slice(&0u16.to_le_bytes()); // comment len
            out.extend_from_slice(&0u16.to_le_bytes()); // disk number start
            out.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
            out.extend_from_slice(&0u32.to_le_bytes()); // external attrs
            out.extend_from_slice(&e.offset.to_le_bytes());
            out.extend_from_slice(e.name.as_bytes());
        }
        let cd_size = out.len() as u32 - cd_start;
        // End of central directory.
        out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // disk number
        out.extend_from_slice(&0u16.to_le_bytes()); // disk with cd
        out.extend_from_slice(&(self.entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(self.entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&cd_size.to_le_bytes());
        out.extend_from_slice(&cd_start.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // comment len
        out
    }
}

// ===========================================================================
// Document flattening — the shared block→line projection the binary emitters use.
// ===========================================================================

/// A flattened line with a coarse style, so each emitter can decorate consistently.
///
/// `level` is the heading level (1-6) when `heading` is true, clamped to the OOXML-representable
/// range; it is meaningless (0) for non-heading lines. Kept alongside `heading` (rather than folded
/// into it) because `heading` alone is what the PDF/PPTX emitters use for their coarse "is this a
/// title-sized line" decision, while `level` is only consumed where the target format actually has
/// discrete heading styles (DOCX's `HeadingN` paragraph styles).
struct Line {
    text: String,
    heading: bool,
    level: u8,
}

enum FlatItem {
    Line(Line),
    PageBreak,
}

/// Flatten a [`Document`] to styled lines + explicit page breaks (the emitters' shared front-end).
fn flatten(doc: &Document) -> Vec<FlatItem> {
    let mut out = Vec::new();
    if !doc.title.is_empty() {
        out.push(FlatItem::Line(Line {
            text: doc.title.clone(),
            heading: true,
            level: 1,
        }));
    }
    for block in &doc.blocks {
        match block {
            Block::Heading { level, text } => out.push(FlatItem::Line(Line {
                text: text.clone(),
                heading: true,
                level: (*level).clamp(1, 6),
            })),
            Block::Paragraph { text } => out.push(FlatItem::Line(Line {
                text: text.clone(),
                heading: false,
                level: 0,
            })),
            Block::BulletList { items } => {
                for it in items {
                    out.push(FlatItem::Line(Line {
                        text: format!("• {it}"),
                        heading: false,
                        level: 0,
                    }));
                }
            }
            Block::NumberedList { items } => {
                for (i, it) in items.iter().enumerate() {
                    out.push(FlatItem::Line(Line {
                        text: format!("{}. {it}", i + 1),
                        heading: false,
                        level: 0,
                    }));
                }
            }
            Block::Table { headers, rows } => {
                out.push(FlatItem::Line(Line {
                    text: headers.join("\t"),
                    heading: false,
                    level: 0,
                }));
                for r in rows {
                    out.push(FlatItem::Line(Line {
                        text: r.join("\t"),
                        heading: false,
                        level: 0,
                    }));
                }
            }
            Block::Code { code, .. } => {
                for l in code.lines() {
                    out.push(FlatItem::Line(Line {
                        text: l.to_string(),
                        heading: false,
                        level: 0,
                    }));
                }
            }
            Block::PageBreak => out.push(FlatItem::PageBreak),
        }
    }
    out
}

// ===========================================================================
// PDF
// ===========================================================================

/// Renders a [`Document`] to a valid, dependency-free PDF (US-Letter pages, Helvetica).
pub struct PdfRenderer;

impl PdfRenderer {
    /// True if `c` survives [`PdfRenderer::esc`] as its own WinAnsi byte (escaped literal parens/
    /// backslash count as representable — they round-trip, just re-encoded). `false` means `esc` falls
    /// back to a dropped space for it. The single source of truth shared by the escaper and
    /// [`PdfRenderer::unrepresentable_chars`], so the two can never drift apart.
    fn is_representable(c: char) -> bool {
        matches!(c, '(' | ')' | '\\')
            || (c.is_ascii() && !c.is_control())
            || ('\u{A0}'..='\u{FF}').contains(&c)
    }

    /// Escape a string into a PDF literal string's raw bytes (`WinAnsiEncoding`, i.e. Windows-1252).
    ///
    /// GAP-AUDIT data-surfaces-artifacts #6: PDF literal strings are byte-oriented, not UTF-8, so this
    /// previously dropped EVERY non-ASCII character to a space — silently corrupting any accented
    /// Western-European text (café, naïve, Zürich…). Windows-1252 is byte-identical to Latin-1
    /// (ISO-8859-1) across U+00A0-U+00FF (the two encodings only diverge in the U+0080-U+009F control
    /// range, which the WinAnsi font never needs), so those codepoints now encode directly to their
    /// single WinAnsi byte instead of being dropped. Only genuinely unrepresentable codepoints
    /// (CJK, Devanagari, emoji, …) still fall back to a space — real information loss there is
    /// unavoidable without embedding a different font program (see
    /// [`PdfRenderer::unrepresentable_chars`] for making that loss non-silent).
    fn esc(s: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(s.len());
        for c in s.chars() {
            match c {
                '(' => out.extend_from_slice(b"\\("),
                ')' => out.extend_from_slice(b"\\)"),
                '\\' => out.extend_from_slice(b"\\\\"),
                c if Self::is_representable(c) => out.push(c as u8),
                _ => out.push(b' '),
            }
        }
        out
    }

    /// GAP-AUDIT data-surfaces-artifacts #6 (remainder): the built-in WinAnsi/Helvetica font cannot
    /// represent CJK, Devanagari, emoji, or any codepoint outside Latin-1 — `esc` silently drops those
    /// to a blank space with **no error and no audit finding**, on an India-market platform where
    /// Devanagari names/₹-adjacent scripts in a generated PDF are an ordinary, expected input.
    /// Embedding a Unicode font program is out of scope here (needs a font asset the runtime does not
    /// ship), but the loss no longer has to be silent: this scans every text segment of `doc` for
    /// codepoints [`esc`](Self::esc) will drop and returns the distinct set (sorted, de-duplicated), so
    /// a caller (e.g. [`crate::ArtifactRuntime::generate`]) can raise a compliance finding — audit and
    /// proceed, same discipline as [`crate::audit_document`] — instead of shipping a PDF with vanished
    /// content and no trace.
    pub fn unrepresentable_chars(doc: &Document) -> Vec<char> {
        let mut found: Vec<char> = doc
            .text_segments()
            .iter()
            .flat_map(|seg| seg.chars())
            .filter(|c| !Self::is_representable(*c))
            .collect();
        found.sort_unstable();
        found.dedup();
        found
    }

    /// Build one page's content stream from its lines.
    fn content_stream(lines: &[&Line]) -> Vec<u8> {
        let mut s: Vec<u8> = Vec::new();
        s.extend_from_slice(b"BT\n");
        s.extend_from_slice(b"/F1 12 Tf\n");
        s.extend_from_slice(b"14 TL\n");
        s.extend_from_slice(b"54 738 Td\n"); // top-left text origin (1 inch margins-ish)
        for line in lines {
            let size = if line.heading { 16 } else { 12 };
            s.extend_from_slice(format!("/F1 {size} Tf\n").as_bytes());
            s.push(b'(');
            s.extend_from_slice(&Self::esc(&line.text));
            s.extend_from_slice(b") Tj\n");
            s.extend_from_slice(b"T*\n");
        }
        s.extend_from_slice(b"ET\n");
        s
    }
}

const PDF_LINES_PER_PAGE: usize = 48;

impl Renderer for PdfRenderer {
    fn format(&self) -> &str {
        "pdf"
    }
    fn render(&self, _doc: &Document) -> String {
        // Binary format: the textual form is empty; callers use render_bytes.
        String::new()
    }
    fn is_binary(&self) -> bool {
        true
    }
    fn render_bytes(&self, doc: &Document) -> Vec<u8> {
        // Paginate the flattened lines: explicit page breaks + a max-lines-per-page cap.
        let flat = flatten(doc);
        let mut pages: Vec<Vec<&Line>> = vec![Vec::new()];
        for item in &flat {
            match item {
                FlatItem::PageBreak => pages.push(Vec::new()),
                FlatItem::Line(l) => {
                    if pages.last().unwrap().len() >= PDF_LINES_PER_PAGE {
                        pages.push(Vec::new());
                    }
                    pages.last_mut().unwrap().push(l);
                }
            }
        }
        if pages.iter().all(|p| p.is_empty()) {
            pages = vec![Vec::new()]; // always at least one (blank) page
        }

        // Object layout: 1=Catalog, 2=Pages, then per page a Page obj + a Content obj, then Font.
        let n_pages = pages.len();
        let font_obj = 3 + n_pages * 2; // page objs: 3,5,7…; content objs: 4,6,8…
        let mut objects: Vec<(usize, Vec<u8>)> = Vec::new();

        objects.push((1, b"<< /Type /Catalog /Pages 2 0 R >>".to_vec()));

        let kids: Vec<String> = (0..n_pages).map(|i| format!("{} 0 R", 3 + i * 2)).collect();
        objects.push((
            2,
            format!(
                "<< /Type /Pages /Kids [{}] /Count {} >>",
                kids.join(" "),
                n_pages
            )
            .into_bytes(),
        ));

        for (i, page) in pages.iter().enumerate() {
            let page_obj = 3 + i * 2;
            let content_obj = page_obj + 1;
            objects.push((
                page_obj,
                format!(
                    "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
                     /Resources << /Font << /F1 {font_obj} 0 R >> >> /Contents {content_obj} 0 R >>"
                )
                .into_bytes(),
            ));
            let stream = Self::content_stream(page);
            let mut body = format!("<< /Length {} >>\nstream\n", stream.len()).into_bytes();
            body.extend_from_slice(&stream);
            body.extend_from_slice(b"\nendstream");
            objects.push((content_obj, body));
        }
        objects.push((
            font_obj,
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"
                .to_vec(),
        ));

        objects.sort_by_key(|(n, _)| *n);
        let max_obj = font_obj;

        // Serialize with byte-offset tracking for the xref.
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\n");
        let mut offsets = vec![0usize; max_obj + 1];
        for (num, body) in &objects {
            offsets[*num] = out.len();
            out.extend_from_slice(format!("{num} 0 obj\n").as_bytes());
            out.extend_from_slice(body);
            out.extend_from_slice(b"\nendobj\n");
        }
        let xref_start = out.len();
        out.extend_from_slice(format!("xref\n0 {}\n", max_obj + 1).as_bytes());
        out.extend_from_slice(b"0000000000 65535 f \n");
        for offset in &offsets[1..=max_obj] {
            out.extend_from_slice(format!("{:010} 00000 n \n", offset).as_bytes());
        }
        out.extend_from_slice(
            format!(
                "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{}\n%%EOF\n",
                max_obj + 1,
                xref_start
            )
            .as_bytes(),
        );
        out
    }
}

// ===========================================================================
// OOXML helpers
// ===========================================================================

/// Escape text for XML content.
fn xml_esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

// ===========================================================================
// DOCX (WordprocessingML)
// ===========================================================================

/// Renders a [`Document`] to a structurally-valid `.docx` (OOXML WordprocessingML) package.
pub struct DocxRenderer;

impl Renderer for DocxRenderer {
    fn format(&self) -> &str {
        "docx"
    }
    fn render(&self, _doc: &Document) -> String {
        String::new()
    }
    fn is_binary(&self) -> bool {
        true
    }
    fn render_bytes(&self, doc: &Document) -> Vec<u8> {
        let mut body = String::new();
        body.push_str(
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
             <w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\">\
             <w:body>",
        );
        // GAP-AUDIT data-surfaces-artifacts (DocxRenderer heading fidelity): `flatten()` used to
        // discard `Block::Heading`'s `level`, so every heading (H1..H6) rendered as `Heading1` — a
        // level-3 heading in the source `Document` was indistinguishable from a level-1 heading in
        // the emitted OOXML. `level` is now threaded through `Line` and mapped to the matching
        // `HeadingN` paragraph style (Word's built-in styles only go to Heading9, but the IR caps at
        // 6 anyway per `Block::Heading`'s doc comment).
        let para = |text: &str, heading: bool, level: u8| -> String {
            let ppr = if heading {
                format!(
                    "<w:pPr><w:pStyle w:val=\"Heading{}\"/></w:pPr>",
                    level.clamp(1, 6)
                )
            } else {
                String::new()
            };
            format!(
                "<w:p>{ppr}<w:r><w:t xml:space=\"preserve\">{}</w:t></w:r></w:p>",
                xml_esc(text)
            )
        };
        for item in flatten(doc) {
            match item {
                FlatItem::Line(l) => body.push_str(&para(&l.text, l.heading, l.level)),
                FlatItem::PageBreak => {
                    body.push_str("<w:p><w:r><w:br w:type=\"page\"/></w:r></w:p>")
                }
            }
        }
        body.push_str("<w:sectPr/></w:body></w:document>");

        let content_types = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
            <Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">\
            <Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>\
            <Default Extension=\"xml\" ContentType=\"application/xml\"/>\
            <Override PartName=\"/word/document.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/>\
            </Types>";
        let rels = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
            <Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\
            <Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"word/document.xml\"/>\
            </Relationships>";

        let mut zip = StoredZip::new();
        zip.add("[Content_Types].xml", content_types)
            .add("_rels/.rels", rels)
            .add("word/document.xml", body);
        zip.finish()
    }
}

// ===========================================================================
// XLSX (SpreadsheetML)
// ===========================================================================

/// Renders a [`Document`] to a structurally-valid `.xlsx` package. Tables become rows of cells;
/// every other block becomes a single-cell row in column A, so the artifact is always a real sheet.
pub struct XlsxRenderer;

impl XlsxRenderer {
    fn col_letter(mut idx: usize) -> String {
        // 0 -> A, 25 -> Z, 26 -> AA …
        let mut s = Vec::new();
        loop {
            s.push(b'A' + (idx % 26) as u8);
            if idx < 26 {
                break;
            }
            idx = idx / 26 - 1;
        }
        s.reverse();
        String::from_utf8(s).unwrap()
    }

    fn rows(doc: &Document) -> Vec<Vec<String>> {
        let mut rows = Vec::new();
        if !doc.title.is_empty() {
            rows.push(vec![doc.title.clone()]);
        }
        for block in &doc.blocks {
            match block {
                Block::Heading { text, .. } | Block::Paragraph { text } => {
                    rows.push(vec![text.clone()])
                }
                Block::BulletList { items } | Block::NumberedList { items } => {
                    for it in items {
                        rows.push(vec![it.clone()]);
                    }
                }
                Block::Table {
                    headers,
                    rows: trows,
                } => {
                    rows.push(headers.clone());
                    for r in trows {
                        rows.push(r.clone());
                    }
                }
                Block::Code { code, .. } => {
                    for l in code.lines() {
                        rows.push(vec![l.to_string()]);
                    }
                }
                Block::PageBreak => {}
            }
        }
        rows
    }
}

impl Renderer for XlsxRenderer {
    fn format(&self) -> &str {
        "xlsx"
    }
    fn render(&self, _doc: &Document) -> String {
        String::new()
    }
    fn is_binary(&self) -> bool {
        true
    }
    fn render_bytes(&self, doc: &Document) -> Vec<u8> {
        let mut sheet = String::new();
        sheet.push_str(
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
             <worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"><sheetData>",
        );
        for (r, row) in Self::rows(doc).iter().enumerate() {
            let rownum = r + 1;
            sheet.push_str(&format!("<row r=\"{rownum}\">"));
            for (c, cell) in row.iter().enumerate() {
                let refc = format!("{}{}", Self::col_letter(c), rownum);
                // inlineStr keeps the package to a single part (no sharedStrings dependency).
                sheet.push_str(&format!(
                    "<c r=\"{refc}\" t=\"inlineStr\"><is><t xml:space=\"preserve\">{}</t></is></c>",
                    xml_esc(cell)
                ));
            }
            sheet.push_str("</row>");
        }
        sheet.push_str("</sheetData></worksheet>");

        let content_types = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
            <Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">\
            <Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>\
            <Default Extension=\"xml\" ContentType=\"application/xml\"/>\
            <Override PartName=\"/xl/workbook.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml\"/>\
            <Override PartName=\"/xl/worksheets/sheet1.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml\"/>\
            </Types>";
        let rels = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
            <Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\
            <Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"xl/workbook.xml\"/>\
            </Relationships>";
        let workbook = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
            <workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\" \
            xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\">\
            <sheets><sheet name=\"Sheet1\" sheetId=\"1\" r:id=\"rId1\"/></sheets></workbook>";
        let wb_rels = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
            <Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\
            <Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet\" Target=\"worksheets/sheet1.xml\"/>\
            </Relationships>";

        let mut zip = StoredZip::new();
        zip.add("[Content_Types].xml", content_types)
            .add("_rels/.rels", rels)
            .add("xl/workbook.xml", workbook)
            .add("xl/_rels/workbook.xml.rels", wb_rels)
            .add("xl/worksheets/sheet1.xml", sheet);
        zip.finish()
    }
}

// ===========================================================================
// PPTX (PresentationML)
// ===========================================================================

/// Renders a [`Document`] to a structurally-valid `.pptx` (OOXML PresentationML) package, packaging the
/// full **slide master → slide layout → theme** chain PowerPoint requires (the round-11 residual that
/// was previously deferred to a skill service). One slide is emitted per `PageBreak`-delimited group;
/// each slide gets a title placeholder (the group's first heading, or the document title on slide 1)
/// and a body text box holding the remaining lines. Dependency-free — no external OOXML library.
pub struct PptxRenderer;

/// EMU (English Metric Units) for a 4:3 slide (9144000 × 6858000 = 10in × 7.5in).
const PPTX_SLIDE_CX: u32 = 9_144_000;
const PPTX_SLIDE_CY: u32 = 6_858_000;

impl PptxRenderer {
    /// Group the flattened document into slides split on `PageBreak`. Each slide is `(title, body)`
    /// where `title` is the group's first heading line (falling back to the document title on the
    /// first slide, else an empty title) and `body` is the remaining lines.
    fn slides(doc: &Document) -> Vec<(String, Vec<String>)> {
        // Split flattened items into page groups (a PageBreak starts a new group).
        let mut groups: Vec<Vec<Line>> = vec![Vec::new()];
        for item in flatten(doc) {
            match item {
                FlatItem::PageBreak => groups.push(Vec::new()),
                FlatItem::Line(l) => groups.last_mut().unwrap().push(l),
            }
        }
        groups.retain(|g| !g.is_empty());
        if groups.is_empty() {
            groups.push(Vec::new()); // always at least one (blank) slide
        }

        let mut out = Vec::new();
        for (i, group) in groups.iter().enumerate() {
            // The first heading line in the group is the slide title; the rest is the body.
            let heading_pos = group.iter().position(|l| l.heading);
            let (title, body): (String, Vec<String>) = match heading_pos {
                Some(pos) => {
                    let title = group[pos].text.clone();
                    let body = group
                        .iter()
                        .enumerate()
                        .filter(|(j, _)| *j != pos)
                        .map(|(_, l)| l.text.clone())
                        .collect();
                    (title, body)
                }
                None => {
                    // No heading in this group: use the doc title on the first slide only.
                    let title = if i == 0 {
                        doc.title.clone()
                    } else {
                        String::new()
                    };
                    let body = group.iter().map(|l| l.text.clone()).collect();
                    (title, body)
                }
            };
            out.push((title, body));
        }
        out
    }

    /// Build one slide part (`ppt/slides/slideN.xml`) with a title placeholder + a body text box.
    fn slide_xml(title: &str, body: &[String]) -> String {
        // Body paragraphs — one <a:p> per line; an empty body still yields a single empty paragraph so
        // the shape's text body is always well-formed.
        let mut body_paras = String::new();
        if body.is_empty() {
            body_paras.push_str("<a:p/>");
        } else {
            for line in body {
                body_paras.push_str(&format!(
                    "<a:p><a:r><a:t>{}</a:t></a:r></a:p>",
                    xml_esc(line)
                ));
            }
        }
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
             <p:sld xmlns:a=\"http://schemas.openxmlformats.org/drawingml/2006/main\" \
             xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\" \
             xmlns:p=\"http://schemas.openxmlformats.org/presentationml/2006/main\">\
             <p:cSld><p:spTree>\
             <p:nvGrpSpPr><p:cNvPr id=\"1\" name=\"\"/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>\
             <p:grpSpPr/>\
             <p:sp><p:nvSpPr><p:cNvPr id=\"2\" name=\"Title 1\"/><p:cNvSpPr>\
             <a:spLocks noGrp=\"1\"/></p:cNvSpPr><p:nvPr><p:ph type=\"title\"/></p:nvPr></p:nvSpPr>\
             <p:spPr/><p:txBody><a:bodyPr/><a:lstStyle/>\
             <a:p><a:r><a:t>{title}</a:t></a:r></a:p></p:txBody></p:sp>\
             <p:sp><p:nvSpPr><p:cNvPr id=\"3\" name=\"Content 2\"/><p:cNvSpPr>\
             <a:spLocks noGrp=\"1\"/></p:cNvSpPr><p:nvPr><p:ph idx=\"1\"/></p:nvPr></p:nvSpPr>\
             <p:spPr/><p:txBody><a:bodyPr/><a:lstStyle/>{body_paras}</p:txBody></p:sp>\
             </p:spTree></p:cSld><p:clrMapOvr><a:overrideClrMapping \
             bg1=\"lt1\" tx1=\"dk1\" bg2=\"lt2\" tx2=\"dk2\" accent1=\"accent1\" accent2=\"accent2\" \
             accent3=\"accent3\" accent4=\"accent4\" accent5=\"accent5\" accent6=\"accent6\" \
             hlink=\"hlink\" folHlink=\"folHlink\"/></p:clrMapOvr></p:sld>",
            title = xml_esc(title),
        )
    }

    /// The single slide layout (blank/title+content). References the master via its own rels.
    fn layout_xml() -> &'static str {
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
         <p:sldLayout xmlns:a=\"http://schemas.openxmlformats.org/drawingml/2006/main\" \
         xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\" \
         xmlns:p=\"http://schemas.openxmlformats.org/presentationml/2006/main\" \
         type=\"obj\" preserve=\"1\">\
         <p:cSld name=\"Title and Content\"><p:spTree>\
         <p:nvGrpSpPr><p:cNvPr id=\"1\" name=\"\"/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>\
         <p:grpSpPr/></p:spTree></p:cSld><p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sldLayout>"
    }

    /// The single slide master. References the layout (rId1) + theme (rId2) via its own rels.
    fn master_xml() -> &'static str {
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
         <p:sldMaster xmlns:a=\"http://schemas.openxmlformats.org/drawingml/2006/main\" \
         xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\" \
         xmlns:p=\"http://schemas.openxmlformats.org/presentationml/2006/main\">\
         <p:cSld><p:spTree>\
         <p:nvGrpSpPr><p:cNvPr id=\"1\" name=\"\"/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>\
         <p:grpSpPr/></p:spTree></p:cSld>\
         <p:clrMap bg1=\"lt1\" tx1=\"dk1\" bg2=\"lt2\" tx2=\"dk2\" accent1=\"accent1\" \
         accent2=\"accent2\" accent3=\"accent3\" accent4=\"accent4\" accent5=\"accent5\" \
         accent6=\"accent6\" hlink=\"hlink\" folHlink=\"folHlink\"/>\
         <p:sldLayoutIdLst><p:sldLayoutId id=\"2147483649\" r:id=\"rId1\"/></p:sldLayoutIdLst>\
         </p:sldMaster>"
    }

    /// A minimal but complete DrawingML theme (clrScheme + fontScheme + fmtScheme) — the theme the
    /// master's rels point at (rId2). PresentationML requires a theme in the master chain.
    fn theme_xml() -> &'static str {
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
         <a:theme xmlns:a=\"http://schemas.openxmlformats.org/drawingml/2006/main\" name=\"Office\">\
         <a:themeElements>\
         <a:clrScheme name=\"Office\">\
         <a:dk1><a:sysClr val=\"windowText\" lastClr=\"000000\"/></a:dk1>\
         <a:lt1><a:sysClr val=\"window\" lastClr=\"FFFFFF\"/></a:lt1>\
         <a:dk2><a:srgbClr val=\"44546A\"/></a:dk2><a:lt2><a:srgbClr val=\"E7E6E6\"/></a:lt2>\
         <a:accent1><a:srgbClr val=\"4472C4\"/></a:accent1><a:accent2><a:srgbClr val=\"ED7D31\"/></a:accent2>\
         <a:accent3><a:srgbClr val=\"A5A5A5\"/></a:accent3><a:accent4><a:srgbClr val=\"FFC000\"/></a:accent4>\
         <a:accent5><a:srgbClr val=\"5B9BD5\"/></a:accent5><a:accent6><a:srgbClr val=\"70AD47\"/></a:accent6>\
         <a:hlink><a:srgbClr val=\"0563C1\"/></a:hlink><a:folHlink><a:srgbClr val=\"954F72\"/></a:folHlink>\
         </a:clrScheme>\
         <a:fontScheme name=\"Office\">\
         <a:majorFont><a:latin typeface=\"Calibri Light\"/><a:ea typeface=\"\"/><a:cs typeface=\"\"/></a:majorFont>\
         <a:minorFont><a:latin typeface=\"Calibri\"/><a:ea typeface=\"\"/><a:cs typeface=\"\"/></a:minorFont>\
         </a:fontScheme>\
         <a:fmtScheme name=\"Office\">\
         <a:fillStyleLst>\
         <a:solidFill><a:schemeClr val=\"phClr\"/></a:solidFill>\
         <a:solidFill><a:schemeClr val=\"phClr\"/></a:solidFill>\
         <a:solidFill><a:schemeClr val=\"phClr\"/></a:solidFill></a:fillStyleLst>\
         <a:lnStyleLst>\
         <a:ln w=\"6350\"><a:solidFill><a:schemeClr val=\"phClr\"/></a:solidFill></a:ln>\
         <a:ln w=\"12700\"><a:solidFill><a:schemeClr val=\"phClr\"/></a:solidFill></a:ln>\
         <a:ln w=\"19050\"><a:solidFill><a:schemeClr val=\"phClr\"/></a:solidFill></a:ln></a:lnStyleLst>\
         <a:effectStyleLst>\
         <a:effectStyle><a:effectLst/></a:effectStyle>\
         <a:effectStyle><a:effectLst/></a:effectStyle>\
         <a:effectStyle><a:effectLst/></a:effectStyle></a:effectStyleLst>\
         <a:bgFillStyleLst>\
         <a:solidFill><a:schemeClr val=\"phClr\"/></a:solidFill>\
         <a:solidFill><a:schemeClr val=\"phClr\"/></a:solidFill>\
         <a:solidFill><a:schemeClr val=\"phClr\"/></a:solidFill></a:bgFillStyleLst>\
         </a:fmtScheme></a:themeElements></a:theme>"
    }
}

impl Renderer for PptxRenderer {
    fn format(&self) -> &str {
        "pptx"
    }
    fn render(&self, _doc: &Document) -> String {
        String::new()
    }
    fn is_binary(&self) -> bool {
        true
    }
    fn render_bytes(&self, doc: &Document) -> Vec<u8> {
        let slides = Self::slides(doc);
        let n = slides.len();

        // presentation.xml: master id + one slide id per slide + slide size.
        let sld_ids: String = (0..n)
            .map(|i| format!("<p:sldId id=\"{}\" r:id=\"rId{}\"/>", 256 + i, i + 2))
            .collect();
        let presentation = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
             <p:presentation xmlns:a=\"http://schemas.openxmlformats.org/drawingml/2006/main\" \
             xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\" \
             xmlns:p=\"http://schemas.openxmlformats.org/presentationml/2006/main\">\
             <p:sldMasterIdLst><p:sldMasterId id=\"2147483648\" r:id=\"rId1\"/></p:sldMasterIdLst>\
             <p:sldIdLst>{sld_ids}</p:sldIdLst>\
             <p:sldSz cx=\"{PPTX_SLIDE_CX}\" cy=\"{PPTX_SLIDE_CY}\"/>\
             <p:notesSz cx=\"{PPTX_SLIDE_CY}\" cy=\"{PPTX_SLIDE_CX}\"/></p:presentation>"
        );

        // presentation rels: rId1 -> master, rId2.. -> slides.
        let mut pres_rels = String::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
             <Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\
             <Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster\" Target=\"slideMasters/slideMaster1.xml\"/>",
        );
        for i in 0..n {
            pres_rels.push_str(&format!(
                "<Relationship Id=\"rId{}\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide\" Target=\"slides/slide{}.xml\"/>",
                i + 2,
                i + 1
            ));
        }
        pres_rels.push_str("</Relationships>");

        // master rels: rId1 -> layout, rId2 -> theme.
        let master_rels = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
            <Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\
            <Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout\" Target=\"../slideLayouts/slideLayout1.xml\"/>\
            <Relationship Id=\"rId2\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/theme\" Target=\"../theme/theme1.xml\"/>\
            </Relationships>";
        // layout rels: rId1 -> master.
        let layout_rels = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
            <Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\
            <Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster\" Target=\"../slideMasters/slideMaster1.xml\"/>\
            </Relationships>";
        // each slide's rels: rId1 -> layout.
        let slide_rels = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
            <Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\
            <Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout\" Target=\"../slideLayouts/slideLayout1.xml\"/>\
            </Relationships>";
        let root_rels = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
            <Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\
            <Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"ppt/presentation.xml\"/>\
            </Relationships>";

        // [Content_Types].xml: defaults + one override per part (incl. one per slide).
        let mut content_types = String::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
             <Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">\
             <Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>\
             <Default Extension=\"xml\" ContentType=\"application/xml\"/>\
             <Override PartName=\"/ppt/presentation.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml\"/>\
             <Override PartName=\"/ppt/slideMasters/slideMaster1.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.presentationml.slideMaster+xml\"/>\
             <Override PartName=\"/ppt/slideLayouts/slideLayout1.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.presentationml.slideLayout+xml\"/>\
             <Override PartName=\"/ppt/theme/theme1.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.theme+xml\"/>",
        );
        for i in 0..n {
            content_types.push_str(&format!(
                "<Override PartName=\"/ppt/slides/slide{}.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.presentationml.slide+xml\"/>",
                i + 1
            ));
        }
        content_types.push_str("</Types>");

        let mut zip = StoredZip::new();
        zip.add("[Content_Types].xml", content_types)
            .add("_rels/.rels", root_rels)
            .add("ppt/presentation.xml", presentation)
            .add("ppt/_rels/presentation.xml.rels", pres_rels)
            .add("ppt/slideMasters/slideMaster1.xml", Self::master_xml())
            .add("ppt/slideMasters/_rels/slideMaster1.xml.rels", master_rels)
            .add("ppt/slideLayouts/slideLayout1.xml", Self::layout_xml())
            .add("ppt/slideLayouts/_rels/slideLayout1.xml.rels", layout_rels)
            .add("ppt/theme/theme1.xml", Self::theme_xml());
        for (i, (title, body)) in slides.iter().enumerate() {
            zip.add(
                &format!("ppt/slides/slide{}.xml", i + 1),
                Self::slide_xml(title, body),
            )
            .add(
                &format!("ppt/slides/_rels/slide{}.xml.rels", i + 1),
                slide_rels,
            );
        }
        zip.finish()
    }
}
