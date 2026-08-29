// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Surface artifact generation — the surface layer's **one shared** document-generation runtime
//! (gap SURF-13/14).
//!
//! Document output (a report, a design doc, a spreadsheet) is a *surface output path*: Chat, Buddy and
//! SDLC all turn a structured [`Document`] IR into a rendered artifact. Previously the Phase-3
//! [`ArtifactRuntime`] existed and passed its own unit tests but was reachable from **no** assembled
//! surface — it was pulled in only by a dev-test. This module is the live wiring seam: the surface
//! layer constructs **exactly one** [`SurfaceArtifacts`] at startup — built-in renderers plus the
//! deployment's injected [`ContentScanner`] (the enterprise PCI engine in prod; a real-but-generic
//! Luhn+entropy default otherwise) — and every surface routes its document-output through
//! [`generate`](SurfaceArtifacts::generate).
//!
//! It mirrors [`crate::SurfaceCatalog`]: keeping the assembly here (rather than hardcoded inside the
//! daemon binary) makes the profile → artifact path a real, testable library surface. A single
//! instance is shared across worker threads — [`SurfaceArtifacts`] is `Send + Sync` because both the
//! renderer registry and the scanner are `Send + Sync`.
//!
//! **Compliance is audit-and-proceed, never redact** ([`ArtifactOutput::redacted`] is always `false`):
//! findings are recorded on the audit trail and ride along on a successful output; the content is
//! emitted intact (redacting inside a code block or table cell would corrupt the artifact).
//!
//! Clean-room: the surface-side assembly and its API are original to AiNxt.

// Re-exported so the composition daemon can build documents and read outputs through `ainxt-surface`
// alone, without also depending on `ainxt-artifact` directly.
pub use ainxt_artifact::{
    ArtifactError, ArtifactLimits, ArtifactOutput, AuditFinding, Block, ContentScanner, Document,
    LuhnEntropyScanner, MarkerScanner, Renderer,
};

use ainxt_artifact::ArtifactRuntime;

/// The surface layer's single, shared artifact-generation runtime.
///
/// Constructed **once** at startup with the deployment's PCI scanner injected (SURF-13), optionally
/// extended with binary skill renderers (docx/pptx/pdf/xlsx) via [`register`](Self::register)
/// (SURF-14), then shared across workers. Every Chat/Buddy/SDLC document-output calls
/// [`generate`](Self::generate).
///
/// `Send + Sync` (guaranteed by the inner renderer/scanner bounds) so one instance backs all workers.
pub struct SurfaceArtifacts {
    runtime: ArtifactRuntime,
}

impl SurfaceArtifacts {
    /// Assemble the surface artifact runtime with the built-in text renderers (Markdown + plain text)
    /// and the injected deployment scanner. In production this is `Box::new(<enterprise PCI engine>)`
    /// (a PCI/DSS detector supplied as a private plugin); in OSS/dev builds pass
    /// [`LuhnEntropyScanner`] or use [`with_default_scanner`](Self::with_default_scanner).
    pub fn new(scanner: Box<dyn ContentScanner>) -> Self {
        SurfaceArtifacts {
            runtime: ArtifactRuntime::with_builtin_renderers(scanner),
        }
    }

    /// Assemble with the in-tree real-but-generic [`LuhnEntropyScanner`] (Luhn-validated PANs +
    /// Shannon-entropy secrets) — the batteries-included default when no enterprise engine is
    /// injected. Still audit-and-proceed; still swappable for the PCI engine via [`new`](Self::new).
    pub fn with_default_scanner() -> Self {
        Self::new(Box::new(LuhnEntropyScanner))
    }

    /// Override the per-generation resource caps (block count / total source bytes) so a hostile or
    /// broken document cannot exhaust a worker. Builder-style.
    pub fn with_limits(mut self, limits: ArtifactLimits) -> Self {
        self.runtime = self.runtime.with_limits(limits);
        self
    }

    /// Register (or replace) a renderer — this is the binary skill-renderer seam (SURF-14): a
    /// docx/pptx/pdf/xlsx renderer overrides [`Renderer::render_bytes`] to emit packaged bytes and
    /// sets [`Renderer::is_binary`], and plugs in here alongside the built-in text renderers.
    /// Builder-style so the whole runtime is assembled before it is sealed and shared.
    pub fn register(mut self, renderer: Box<dyn Renderer>) -> Self {
        self.runtime.register(renderer);
        self
    }

    /// The registered format ids (sorted) this surface can emit.
    pub fn formats(&self) -> Vec<&str> {
        self.runtime.formats()
    }

    /// **The live surface output path.** Turn a [`Document`] IR into a rendered artifact for the
    /// requested `format`: enforce limits → audit (record findings, never block) → render (text or
    /// binary byte path). Structural failures (unknown format / oversized document) are the only
    /// `Err`; a compliance finding never blocks and rides along on the returned [`ArtifactOutput`]
    /// (audit-and-proceed, `redacted == false`).
    pub fn generate(&self, doc: &Document, format: &str) -> Result<ArtifactOutput, ArtifactError> {
        self.runtime.generate(doc, format)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `SurfaceArtifacts` must be shareable across the platform's worker threads: one instance,
    /// many concurrent generations.
    #[test]
    fn surface_artifacts_is_send_sync_for_worker_sharing() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SurfaceArtifacts>();
    }

    // =======================================================================
    // wire_surf_13 — the artifact runtime is LIVE on the surface output path
    // =======================================================================

    /// Stands in for the deployment's injected PCI engine, proving the [`ContentScanner`] seam runs
    /// through the assembled surface runtime exactly as the enterprise detector would.
    struct DeploymentScanner;
    impl ContentScanner for DeploymentScanner {
        fn scan(&self, text: &str) -> Vec<String> {
            if text.contains("LEDGER-SECRET") {
                vec!["deployment-detector-hit".to_string()]
            } else {
                Vec::new()
            }
        }
    }

    #[test]
    fn wire_surf_13() {
        // The REAL assembled surface object: one runtime, built-in renderers + injected scanner.
        let art = SurfaceArtifacts::new(Box::new(DeploymentScanner));
        assert!(art.formats().contains(&"markdown"));
        assert!(art.formats().contains(&"text"));

        // A surface (Chat/Buddy/SDLC) hands its document-output to the shared runtime.
        let mut doc = Document::new("Ops Report");
        doc.push(Block::Paragraph {
            text: "value LEDGER-SECRET present".into(),
        })
        .push(Block::Code {
            language: "sql".into(),
            code: "select 1".into(),
        });

        let out = art
            .generate(&doc, "markdown")
            .expect("markdown is registered by the surface runtime");

        // Audit-and-proceed: the injected scanner is consulted on the live output path...
        assert!(
            out.findings
                .iter()
                .any(|f| f.label == "deployment-detector-hit"),
            "the injected scanner must run when a surface generates an artifact"
        );
        // ...but the content is emitted INTACT and never redacted.
        assert!(
            !out.redacted,
            "artifact compliance is audit-and-proceed, never redact"
        );
        assert!(
            out.text_lossy().contains("LEDGER-SECRET present"),
            "content must be emitted intact"
        );
        assert!(!out.is_binary());

        // An unknown format is a structural error — not a panic, not a silent empty.
        assert_eq!(
            art.generate(&doc, "docx"),
            Err(ArtifactError::UnknownFormat("docx".to_string()))
        );
    }

    // =======================================================================
    // wire_surf_14 — binary skill renderers plug into the same surface seam
    // =======================================================================

    /// A stand-in binary (docx/pptx/pdf/xlsx) skill renderer: overrides `render_bytes` to emit a
    /// non-UTF-8 packaged payload and marks itself binary. The real OOXML/PDF encoders are the
    /// design-acknowledged deferred skill implementation (need a permissive zip/pdf crate); this
    /// proves the byte path is wired through the assembled surface.
    struct FakeOoxmlRenderer;
    impl Renderer for FakeOoxmlRenderer {
        fn format(&self) -> &str {
            "docx"
        }
        fn render(&self, _doc: &Document) -> String {
            String::new()
        }
        fn render_bytes(&self, doc: &Document) -> Vec<u8> {
            // PK zip magic + a non-UTF-8 byte + the title bytes.
            let mut b = vec![0x50, 0x4B, 0x03, 0x04, 0xFF];
            b.extend_from_slice(doc.title.as_bytes());
            b
        }
        fn is_binary(&self) -> bool {
            true
        }
    }

    #[test]
    fn wire_surf_14() {
        // The REAL assembled surface object, extended with a binary renderer through the seam.
        let art = SurfaceArtifacts::with_default_scanner().register(Box::new(FakeOoxmlRenderer));
        assert!(art.formats().contains(&"docx"));

        let out = art
            .generate(&Document::new("Q3"), "docx")
            .expect("the docx renderer is registered on the surface");

        assert!(
            out.is_binary(),
            "a binary format must be flagged binary by the surface"
        );
        // The PK zip magic and the non-UTF-8 byte survive — a true byte path, not a String round-trip.
        assert_eq!(&out.bytes[..4], &[0x50, 0x4B, 0x03, 0x04]);
        assert!(
            out.bytes.contains(&0xFF),
            "the non-UTF-8 byte must pass through the surface byte path intact"
        );
        assert!(out.bytes.ends_with(b"Q3"));
        assert!(
            !out.redacted,
            "still audit-and-proceed for binary artifacts"
        );
    }

    #[test]
    fn default_scanner_is_the_real_luhn_entropy_detector() {
        // The batteries-included surface default is a genuine detector, not a marker floor: a
        // Luhn-valid PAN in a generated artifact is flagged (audit-and-proceed).
        let art = SurfaceArtifacts::with_default_scanner();
        let mut doc = Document::new("Statement");
        doc.push(Block::Paragraph {
            text: "PAN 4111111111111111 recorded".into(),
        });
        let out = art.generate(&doc, "markdown").unwrap();
        assert!(out.findings.iter().any(|f| f.label == "PAN (Luhn-valid)"));
        assert!(!out.redacted);
        assert!(out.text_lossy().contains("4111111111111111"));
    }

    #[test]
    fn limits_are_enforced_before_render() {
        let art = SurfaceArtifacts::with_default_scanner().with_limits(ArtifactLimits {
            max_blocks: 2,
            max_total_bytes: 1024,
        });
        let mut doc = Document::new("");
        for _ in 0..5 {
            doc.push(Block::Paragraph { text: "x".into() });
        }
        match art.generate(&doc, "markdown") {
            Err(ArtifactError::TooLarge {
                what: "blocks",
                actual: 5,
                limit: 2,
            }) => {}
            other => panic!("expected TooLarge(blocks), got {other:?}"),
        }
    }
}
