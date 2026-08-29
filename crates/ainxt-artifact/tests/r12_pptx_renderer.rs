// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R12 DATA — the PPTX artifact renderer (gap data-surfaces-artifacts, low: "PPTX artifact
//! renderer"). Round-11 shipped pdf/docx/xlsx but explicitly DEFERRED pptx to a skill service
//! ("the slide master/layout/theme chain is a skill seam, not shipped in-tree"). This closes that
//! residual: `PptxRenderer` now packages structurally-valid PresentationML — `ppt/presentation.xml`
//! plus the full slide **master → layout → theme** chain and one `ppt/slides/slideN.xml` per page —
//! into the same dependency-free STORED ZIP, behind the SAME `Renderer` trait as the other binaries.
//!
//! Fail-before/pass-after: `PptxRenderer` + the `pptx` format in `with_all_renderers` did not exist,
//! so this test crate would not compile and `generate(_, "pptx")` returned `UnknownFormat`. Now it
//! emits a real package, verified here by re-walking the STORED ZIP (recomputing every entry CRC-32)
//! and asserting the required PresentationML parts + one slide part per `PageBreak`-delimited group.

use ainxt_artifact::{
    crc32, ArtifactRequest, ArtifactRuntime, Block, ContentScanner, Document, MarkerScanner,
    CAP_ARTIFACT_GENERATE,
};
use ainxt_types::Principal;

fn doc() -> Document {
    let mut d = Document::new("Board Deck");
    d.push(Block::Heading {
        level: 1,
        text: "Agenda".to_string(),
    });
    d.push(Block::Paragraph {
        text: "Settlement volume rose 4% <this> & \"that\".".to_string(),
    });
    d.push(Block::BulletList {
        items: vec!["UPI".to_string(), "IMPS".to_string()],
    });
    d.push(Block::PageBreak); // -> second slide
    d.push(Block::Heading {
        level: 1,
        text: "Risks".to_string(),
    });
    d.push(Block::Paragraph {
        text: "Concentration risk on a single rail.".to_string(),
    });
    d
}

/// Walk a STORED-method ZIP, verifying each entry's CRC-32; returns (name, data) pairs. (Same walk
/// shape as `r11_binary_renderers`, kept local so the two test files stay independent.)
fn unzip_stored(bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 4 <= bytes.len() {
        let sig = u32::from_le_bytes(bytes[i..i + 4].try_into().unwrap());
        if sig != 0x0403_4b50 {
            break;
        }
        let method = u16::from_le_bytes(bytes[i + 8..i + 10].try_into().unwrap());
        assert_eq!(method, 0, "pptx must use the STORED method");
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
    assert!(
        bytes.windows(4).any(|w| w == 0x0605_4b50u32.to_le_bytes()),
        "missing EOCD record"
    );
    out
}

fn runtime() -> ArtifactRuntime {
    ArtifactRuntime::with_all_renderers(Box::new(MarkerScanner) as Box<dyn ContentScanner>)
}

#[test]
fn r12_pptx_format_is_registered_by_with_all_renderers() {
    // FAIL-BEFORE: pptx was not a registered format (UnknownFormat). PASS-AFTER: it is.
    let rt = runtime();
    assert!(
        rt.formats().contains(&"pptx"),
        "pptx must be a registered format"
    );
    // And every other binary format is still present (no regression).
    for f in ["markdown", "text", "pdf", "docx", "xlsx", "pptx"] {
        assert!(rt.formats().contains(&f), "format {f} must be registered");
    }
}

#[test]
fn r12_pptx_is_valid_presentationml_package_with_master_layout_theme_chain() {
    let out = runtime().generate(&doc(), "pptx").unwrap();
    assert!(out.is_binary(), "pptx is a binary format");
    assert_eq!(out.format, "pptx");
    assert!(out.bytes.starts_with(b"PK\x03\x04"), "ZIP magic");

    let parts = unzip_stored(&out.bytes);
    let names: Vec<&str> = parts.iter().map(|(n, _)| n.as_str()).collect();

    // The master -> layout -> theme chain PowerPoint requires, plus the presentation part + rels.
    for required in [
        "[Content_Types].xml",
        "_rels/.rels",
        "ppt/presentation.xml",
        "ppt/_rels/presentation.xml.rels",
        "ppt/slideMasters/slideMaster1.xml",
        "ppt/slideMasters/_rels/slideMaster1.xml.rels",
        "ppt/slideLayouts/slideLayout1.xml",
        "ppt/slideLayouts/_rels/slideLayout1.xml.rels",
        "ppt/theme/theme1.xml",
    ] {
        assert!(
            names.contains(&required),
            "missing required part {required}"
        );
    }

    // One slide part per PageBreak-delimited group (the doc has exactly one PageBreak => 2 slides).
    assert!(names.contains(&"ppt/slides/slide1.xml"));
    assert!(names.contains(&"ppt/slides/slide2.xml"));
    assert!(names.contains(&"ppt/slides/_rels/slide1.xml.rels"));
    assert!(!names.contains(&"ppt/slides/slide3.xml"), "no third slide");

    // presentation.xml wires the master + exactly two slide ids and a 4:3 slide size.
    let (_, pres) = parts
        .iter()
        .find(|(n, _)| n == "ppt/presentation.xml")
        .unwrap();
    let pres = String::from_utf8_lossy(pres);
    assert!(pres.contains("<p:sldMasterId"));
    assert_eq!(pres.matches("<p:sldId ").count(), 2, "two slide ids");
    assert!(pres.contains("cx=\"9144000\""));

    // The theme carries the full clr/font/fmt scheme triple (a bare stub would be rejected by Office).
    let (_, theme) = parts
        .iter()
        .find(|(n, _)| n == "ppt/theme/theme1.xml")
        .unwrap();
    let theme = String::from_utf8_lossy(theme);
    assert!(theme.contains("<a:clrScheme"));
    assert!(theme.contains("<a:fontScheme"));
    assert!(theme.contains("<a:fmtScheme"));

    // Slide 1 title = the first heading ("Agenda"); XML special chars are escaped (never raw).
    let (_, s1) = parts
        .iter()
        .find(|(n, _)| n == "ppt/slides/slide1.xml")
        .unwrap();
    let s1 = String::from_utf8_lossy(s1);
    assert!(s1.contains("<p:ph type=\"title\"/>"));
    assert!(s1.contains("<a:t>Agenda</a:t>"));
    assert!(
        s1.contains("rose 4% &lt;this&gt; &amp; &quot;that&quot;."),
        "content must be XML-escaped so the part stays well-formed"
    );
    // Slide 2 title = "Risks".
    let (_, s2) = parts
        .iter()
        .find(|(n, _)| n == "ppt/slides/slide2.xml")
        .unwrap();
    assert!(String::from_utf8_lossy(s2).contains("<a:t>Risks</a:t>"));
}

#[test]
fn r12_pptx_empty_doc_still_yields_one_slide() {
    // A degenerate (blank) document must still produce a structurally-valid single-slide deck.
    let out = runtime().generate(&Document::new(""), "pptx").unwrap();
    let parts = unzip_stored(&out.bytes);
    let names: Vec<&str> = parts.iter().map(|(n, _)| n.as_str()).collect();
    assert!(names.contains(&"ppt/slides/slide1.xml"));
    assert!(!names.contains(&"ppt/slides/slide2.xml"));
}

#[test]
fn r12_pptx_audit_and_proceed_content_intact_never_redacted() {
    // Parity with the other binary renderers: the audit runs but the slide content is emitted intact.
    let mut d = Document::new("Deck");
    d.push(Block::Paragraph {
        text: "contains SCAN_ME marker".to_string(),
    });
    let out = runtime().generate(&d, "pptx").unwrap();
    assert!(
        !out.redacted,
        "artifact compliance is audit-and-proceed, never redact"
    );
    let parts = unzip_stored(&out.bytes);
    let (_, s1) = parts
        .iter()
        .find(|(n, _)| n == "ppt/slides/slide1.xml")
        .unwrap();
    assert!(
        String::from_utf8_lossy(s1).contains("contains SCAN_ME marker"),
        "content must be emitted verbatim inside the slide"
    );
}

#[test]
fn r12_pptx_is_rbac_scoped_through_generate_for() {
    // The pptx format rides the SAME capability-gated route entrypoint as every other format:
    // a caller without CAP_ARTIFACT_GENERATE is refused before any renderer runs.
    let rt = runtime();
    let req = ArtifactRequest {
        document: doc(),
        format: "pptx".to_string(),
    };
    let holder = Principal::user("priya", &[CAP_ARTIFACT_GENERATE]);
    let out = rt
        .generate_for(&holder, &req)
        .expect("authorized caller renders pptx");
    assert_eq!(out.format, "pptx");
    assert!(out.is_binary());

    let stranger = Principal::user("mallory", &[]);
    assert!(
        rt.generate_for(&stranger, &req).is_err(),
        "no cap => refused"
    );
}
