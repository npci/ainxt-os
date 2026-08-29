// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-AUDIT data-surfaces-artifacts #6 (remainder) — the PDF renderer's built-in WinAnsi font
//! silently drops any codepoint outside Latin-1 (CJK, Devanagari, emoji, …) to a blank space, with
//! no error and no audit finding — a real, silent information-loss bug on an India-market platform
//! where Devanagari names are ordinary input. `PdfRenderer::unrepresentable_chars` now lets
//! `ArtifactRuntime::generate` raise a non-blocking compliance finding for exactly this case.

use ainxt_artifact::{ArtifactRuntime, Block, Document, LuhnEntropyScanner, PdfRenderer};

#[test]
fn devanagari_content_raises_a_pdf_unrepresentable_chars_finding_and_still_renders() {
    let mut doc = Document::new("Report");
    doc.push(Block::Paragraph {
        text: "ग्राहक का नाम: राज".to_string(),
    });

    let dropped = PdfRenderer::unrepresentable_chars(&doc);
    assert!(
        !dropped.is_empty(),
        "Devanagari codepoints must be detected as unrepresentable"
    );

    let runtime = ArtifactRuntime::with_all_renderers(Box::new(LuhnEntropyScanner));
    let out = runtime
        .generate(&doc, "pdf")
        .expect("pdf generation must still succeed");
    assert!(
        !out.bytes.is_empty(),
        "audit-and-proceed: content is still emitted, never blocked"
    );
    assert!(
        out.findings
            .iter()
            .any(|f| f.label.contains("PDF_UNREPRESENTABLE_CHARS")),
        "a non-blocking finding must record the silent drop: {:?}",
        out.findings
    );
}

#[test]
fn ascii_and_latin1_content_raises_no_finding() {
    let mut doc = Document::new("Report");
    doc.push(Block::Paragraph {
        text: "Cafe resume - plain ASCII, fully representable, cliche naive.".to_string(),
    });
    doc.push(Block::Paragraph {
        text: "Café résumé, plain Latin-1 (no em-dash), fully representable.".to_string(),
    });

    assert!(
        PdfRenderer::unrepresentable_chars(&doc).is_empty(),
        "Latin-1 content must not be flagged"
    );

    let runtime = ArtifactRuntime::with_all_renderers(Box::new(LuhnEntropyScanner));
    let out = runtime
        .generate(&doc, "pdf")
        .expect("pdf generation must succeed");
    assert!(
        !out.findings
            .iter()
            .any(|f| f.label.contains("PDF_UNREPRESENTABLE_CHARS")),
        "no finding must be raised for fully-representable content: {:?}",
        out.findings
    );
}

#[test]
fn the_finding_is_pdf_only_never_raised_for_other_formats() {
    let mut doc = Document::new("Report");
    doc.push(Block::Paragraph {
        text: "日本語のテキスト".to_string(),
    });
    let runtime = ArtifactRuntime::with_all_renderers(Box::new(LuhnEntropyScanner));
    let out = runtime
        .generate(&doc, "markdown")
        .expect("markdown generation must succeed");
    assert!(
        !out.findings
            .iter()
            .any(|f| f.label.contains("PDF_UNREPRESENTABLE_CHARS")),
        "the PDF-specific finding must never fire for a non-PDF format: {:?}",
        out.findings
    );
}
