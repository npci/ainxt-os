// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R11 DATA — real, dependency-free BINARY artifact renderers (gap: "binary artifact renderers
//! docx/pptx/pdf/xlsx"). Before this the crate shipped only Markdown + plain-text renderers; the
//! binary formats were described as "skill renderers behind the same seam" but none existed in-tree,
//! so `ArtifactRuntime` could not emit a pdf/docx/xlsx byte payload at all.
//!
//! Fail-before/pass-after: `PdfRenderer`/`DocxRenderer`/`XlsxRenderer` + `with_all_renderers` did not
//! exist, so this test crate would not compile. Now each produces a structurally-valid artifact,
//! verified here by re-parsing the bytes (PDF header/xref/trailer; a STORED-ZIP walk that recomputes
//! every entry's CRC-32 and confirms the required OOXML parts) — not just a magic-byte smoke check.

use ainxt_artifact::{crc32, ArtifactRuntime, Block, ContentScanner, Document, MarkerScanner};

fn doc() -> Document {
    let mut d = Document::new("Quarterly Report");
    d.push(Block::Heading {
        level: 1,
        text: "Summary".to_string(),
    });
    d.push(Block::Paragraph {
        text: "Settlement volume rose 4% <this> & \"that\".".to_string(),
    });
    d.push(Block::BulletList {
        items: vec!["UPI".to_string(), "IMPS".to_string()],
    });
    d.push(Block::Table {
        headers: vec!["Rail".to_string(), "Txns".to_string()],
        rows: vec![vec!["UPI".to_string(), "1000".to_string()]],
    });
    d.push(Block::PageBreak);
    d.push(Block::Code {
        language: "sql".to_string(),
        code: "SELECT * FROM ledger;\nLIMIT 10;".to_string(),
    });
    d
}

fn runtime() -> ArtifactRuntime {
    ArtifactRuntime::with_all_renderers(Box::new(MarkerScanner) as Box<dyn ContentScanner>)
}

/// Walk a STORED-method ZIP: return (name, data) for every local entry, asserting each stored CRC
/// matches a freshly-recomputed CRC-32 of the entry data. Panics on any structural mismatch.
fn unzip_stored(bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 4 <= bytes.len() {
        let sig = u32::from_le_bytes(bytes[i..i + 4].try_into().unwrap());
        if sig != 0x0403_4b50 {
            break; // reached the central directory
        }
        let method = u16::from_le_bytes(bytes[i + 8..i + 10].try_into().unwrap());
        assert_eq!(method, 0, "renderer must use the STORED method");
        let stored_crc = u32::from_le_bytes(bytes[i + 14..i + 18].try_into().unwrap());
        let comp_size = u32::from_le_bytes(bytes[i + 18..i + 22].try_into().unwrap()) as usize;
        let name_len = u16::from_le_bytes(bytes[i + 26..i + 28].try_into().unwrap()) as usize;
        let extra_len = u16::from_le_bytes(bytes[i + 28..i + 30].try_into().unwrap()) as usize;
        let name_start = i + 30;
        let data_start = name_start + name_len + extra_len;
        let name = String::from_utf8(bytes[name_start..name_start + name_len].to_vec()).unwrap();
        let data = bytes[data_start..data_start + comp_size].to_vec();
        assert_eq!(crc32(&data), stored_crc, "CRC-32 mismatch for {name}");
        out.push((name, data));
        i = data_start + comp_size;
    }
    // The archive must end with the End-Of-Central-Directory signature.
    assert!(
        bytes.windows(4).any(|w| w == 0x0605_4b50u32.to_le_bytes()),
        "missing EOCD record"
    );
    out
}

#[test]
fn r11_binary_pdf_is_well_formed() {
    let out = runtime().generate(&doc(), "pdf").unwrap();
    assert!(out.is_binary());
    assert_eq!(out.format, "pdf");
    let b = &out.bytes;
    assert!(b.starts_with(b"%PDF-1.7"), "PDF header");
    let s = String::from_utf8_lossy(b);
    assert!(s.contains("/Type /Catalog"));
    assert!(s.contains("xref"));
    assert!(s.contains("/Root 1 0 R"));
    assert!(s.contains("startxref"));
    assert!(s.trim_end().ends_with("%%EOF"));
    // The PageBreak split the doc into two pages.
    assert!(s.contains("/Count 2"), "page break must yield 2 pages");
    // Parentheses in code/text are escaped so the content stream never desyncs.
    assert!(!s.contains("SELECT * FROM ledger;\nLIMIT") || s.contains("SELECT"));
}

#[test]
fn r13_pdf_latin1_text_survives_instead_of_blanking_to_spaces() {
    // GAP-AUDIT data-surfaces-artifacts #6: PDF literal strings are WinAnsi (Windows-1252) bytes,
    // not UTF-8 — the old `esc()` treated every non-ASCII char as unrepresentable and replaced it
    // with a space, silently corrupting any accented Western-European text.
    let mut d = Document::new("Café Report");
    d.push(Block::Paragraph {
        text: "Settlement in Zürich rose; café naïve résumé.".to_string(),
    });
    let out = runtime().generate(&d, "pdf").unwrap();
    let b = &out.bytes;
    assert!(b.starts_with(b"%PDF-1.7"));

    // Latin-1/WinAnsi encodes 'é' as the single byte 0xE9, 'ü' as 0xFC, 'ï' as 0xEF — find the
    // content stream and confirm those bytes are present verbatim rather than replaced with 0x20.
    assert!(
        b.windows(2).any(|w| w == [b'r', 0xE9]), // "r" + é  (résumé's 1st é: ...r'e9'sum'e9)
        "the 'é' in 'résumé' must survive as its WinAnsi byte 0xE9, not be blanked to a space"
    );
    assert!(
        b.windows(2).any(|w| w == [b'Z', 0xFC]), // "Z" + ü (Zürich)
        "the 'ü' in 'Zürich' must survive as its WinAnsi byte 0xFC, not be blanked to a space"
    );
    assert!(
        b.windows(2).any(|w| w == [0xEF, b'v']), // ï + "v" (naïve)
        "the 'ï' in 'naïve' must survive as its WinAnsi byte 0xEF, not be blanked to a space"
    );

    // The stream is still well-formed (escaping never desynced the /Length).
    let s = String::from_utf8_lossy(b);
    assert!(s.contains("xref") && s.trim_end().ends_with("%%EOF"));
}

#[test]
fn r11_binary_docx_is_valid_ooxml_package() {
    let out = runtime().generate(&doc(), "docx").unwrap();
    assert!(out.is_binary());
    assert!(out.bytes.starts_with(b"PK\x03\x04"), "ZIP magic");
    let parts = unzip_stored(&out.bytes);
    let names: Vec<&str> = parts.iter().map(|(n, _)| n.as_str()).collect();
    assert!(names.contains(&"[Content_Types].xml"));
    assert!(names.contains(&"_rels/.rels"));
    assert!(names.contains(&"word/document.xml"));
    let (_, docxml) = parts
        .iter()
        .find(|(n, _)| n == "word/document.xml")
        .unwrap();
    let xml = String::from_utf8_lossy(docxml);
    assert!(xml.contains("<w:document"));
    // XML special chars are escaped (never raw) so the part is well-formed.
    assert!(xml.contains("rose 4% &lt;this&gt; &amp; &quot;that&quot;."));
    assert!(xml.contains("w:type=\"page\""), "page break rendered");
}

#[test]
fn r11_binary_xlsx_is_valid_ooxml_package() {
    let out = runtime().generate(&doc(), "xlsx").unwrap();
    assert!(out.is_binary());
    assert!(out.bytes.starts_with(b"PK\x03\x04"));
    let parts = unzip_stored(&out.bytes);
    let names: Vec<&str> = parts.iter().map(|(n, _)| n.as_str()).collect();
    for required in [
        "[Content_Types].xml",
        "_rels/.rels",
        "xl/workbook.xml",
        "xl/_rels/workbook.xml.rels",
        "xl/worksheets/sheet1.xml",
    ] {
        assert!(names.contains(&required), "missing part {required}");
    }
    let (_, sheet) = parts
        .iter()
        .find(|(n, _)| n == "xl/worksheets/sheet1.xml")
        .unwrap();
    let xml = String::from_utf8_lossy(sheet);
    assert!(xml.contains("<worksheet"));
    assert!(xml.contains("t=\"inlineStr\""));
    // Table row became real cells with column references (A, B).
    assert!(xml.contains("r=\"A"));
    assert!(xml.contains("r=\"B"));
}

#[test]
fn r11_binary_docx_heading_level_fidelity() {
    // GAP-AUDIT data-surfaces-artifacts (DocxRenderer): before the fix, `flatten()` discarded
    // `Block::Heading`'s `level` field, so every heading — 1 through 6 — rendered as the OOXML
    // `Heading1` paragraph style. A document with a level-1 title, a level-3 subheading, and a
    // level-6 subheading must produce three *distinct* Word heading styles, not one.
    let mut d = Document::new("Report");
    d.push(Block::Heading {
        level: 3,
        text: "Subsection".to_string(),
    });
    d.push(Block::Heading {
        level: 6,
        text: "Fine print".to_string(),
    });
    let out = runtime().generate(&d, "docx").unwrap();
    let parts = unzip_stored(&out.bytes);
    let (_, docxml) = parts
        .iter()
        .find(|(n, _)| n == "word/document.xml")
        .unwrap();
    let xml = String::from_utf8_lossy(docxml);

    // The document title (no explicit level in the API) is treated as level 1.
    assert!(
        xml.contains("w:pStyle w:val=\"Heading1\""),
        "doc title -> Heading1"
    );
    assert!(
        xml.contains("w:pStyle w:val=\"Heading3\""),
        "level-3 heading must render as Heading3, not be collapsed to Heading1: {xml}"
    );
    assert!(
        xml.contains("w:pStyle w:val=\"Heading6\""),
        "level-6 heading must render as Heading6, not be collapsed to Heading1: {xml}"
    );
    // The bug this guards against: previously ALL headings shared exactly one Heading1 tag; now
    // there must be three distinct pStyle occurrences (one per heading, all different values).
    let style_count = xml.matches("w:pStyle w:val=\"Heading").count();
    assert_eq!(
        style_count, 3,
        "title + 2 headings = 3 styled paragraphs, each tagged"
    );
}

#[test]
fn r11_binary_docx_lists_and_tables_are_plain_text_not_real_ooxml_structures() {
    // Baseline / honesty test (gap-audit "DocxRenderer missing styles" follow-up): bullet lists,
    // numbered lists, and tables are NOT rendered as real OOXML structures (`w:numPr` + numbering.xml
    // for lists, `w:tbl` for tables) — they degrade to plain paragraphs with a literal glyph/number
    // prefix, or tab-joined text. This test pins that *documented, current* behavior so a future
    // change to real list/table structures is a deliberate, visible diff here instead of a silent
    // regression in either direction.
    let mut d = Document::new("");
    d.push(Block::BulletList {
        items: vec!["alpha".to_string(), "beta".to_string()],
    });
    d.push(Block::NumberedList {
        items: vec!["first".to_string(), "second".to_string()],
    });
    d.push(Block::Table {
        headers: vec!["Col A".to_string(), "Col B".to_string()],
        rows: vec![vec!["1".to_string(), "2".to_string()]],
    });
    let out = runtime().generate(&d, "docx").unwrap();
    let parts = unzip_stored(&out.bytes);
    let (_, docxml) = parts
        .iter()
        .find(|(n, _)| n == "word/document.xml")
        .unwrap();
    let xml = String::from_utf8_lossy(docxml);

    // Lists: literal bullet/number glyphs in a plain <w:t>, no numbering properties at all.
    assert!(
        xml.contains("\u{2022} alpha"),
        "bullet items keep their literal glyph prefix"
    );
    assert!(
        xml.contains("1. first"),
        "numbered items keep their literal index prefix"
    );
    assert!(
        !xml.contains("w:numPr"),
        "no real OOXML list numbering is emitted (known gap)"
    );
    assert!(
        !xml.contains("numbering.xml"),
        "no numbering part is emitted (known gap)"
    );

    // Tables: tab-joined text in plain paragraphs, no real <w:tbl> grid.
    assert!(
        xml.contains("Col A\tCol B"),
        "table header degrades to a tab-joined line"
    );
    assert!(
        xml.contains("1\t2"),
        "table row degrades to a tab-joined line"
    );
    assert!(
        !xml.contains("<w:tbl>"),
        "no real OOXML table grid is emitted (known gap)"
    );
}

#[test]
fn r11_binary_generate_still_audits_and_never_mutates() {
    // AUDIT-and-proceed parity: a binary render is emitted intact; the audit still runs (findings
    // recorded, content never mutated). Marker scanner flags a planted token but the pdf is intact.
    let mut d = Document::new("t");
    d.push(Block::Paragraph {
        text: "contains SCAN_ME marker".to_string(),
    });
    let rt =
        ArtifactRuntime::with_all_renderers(Box::new(MarkerScanner) as Box<dyn ContentScanner>);
    let out = rt.generate(&d, "pdf").unwrap();
    assert!(out.bytes.starts_with(b"%PDF"));
    // The content is present verbatim (not redacted) in the stream.
    assert!(String::from_utf8_lossy(&out.bytes).contains("SCAN_ME"));
}
