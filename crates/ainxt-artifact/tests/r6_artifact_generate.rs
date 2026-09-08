// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R6 DATA — integration coverage for the mount-ready, RBAC-scoped artifact `generate_for`.
//!
//! Gap: the Phase-3 [`ArtifactRuntime`] had a `generate` that took no [`Principal`], no capability
//! gate, and returned a non-`Deserialize` error — so a server could not mount document generation as
//! an authenticated route (the ledger/graph surfaces already were capability-gated; artifact was
//! not). `generate_for` + `ArtifactRequest` + `ArtifactGenError` + `CAP_ARTIFACT_GENERATE` provide
//! the single RBAC-scoped, serializable entrypoint `POST /v1/artifact` mounts.
//!
//! Fail-before/pass-after: these symbols did not exist, so this test crate would not compile before
//! the change, and its assertions (authorization precedes format lookup; audit-and-proceed never
//! redacts through the gate; the wire request/error round-trip) hold only after it.

use ainxt_artifact::{
    ArtifactGenError, ArtifactRequest, ArtifactRuntime, Block, ContentScanner, Document,
    LuhnEntropyScanner, CAP_ARTIFACT_GENERATE,
};
use ainxt_types::{DataClass, Principal};

/// A holder of the artifact capability.
fn author() -> Principal {
    Principal::user("priya", &[CAP_ARTIFACT_GENERATE]).with_clearance(DataClass::Confidential)
}

/// A caller who lacks the capability entirely.
fn stranger() -> Principal {
    Principal::user("mallory", &[]).with_clearance(DataClass::Pii)
}

fn report_with_pan() -> Document {
    let mut d = Document::new("Settlement Statement");
    d.push(Block::Paragraph {
        text: "Card 4111111111111111 recorded on file.".into(),
    })
    .push(Block::Code {
        language: "sql".into(),
        code: "select amount from ledger where id = $1".into(),
    });
    d
}

#[test]
fn r6_artifact_generate_for_is_capability_gated_before_any_format_lookup() {
    let rt = ArtifactRuntime::with_builtin_renderers(Box::new(LuhnEntropyScanner));

    // A caller WITHOUT the capability is refused — even for an UNKNOWN format. Authorization runs
    // first, so the error is NotAuthorized (never UnknownFormat): the surface is no capability or
    // format oracle to an unauthorized caller.
    let bogus = ArtifactRequest {
        document: Document::new("x"),
        format: "no-such-format".into(),
    };
    assert_eq!(
        rt.generate_for(&stranger(), &bogus),
        Err(ArtifactGenError::NotAuthorized)
    );

    // Even a well-formed, registered-format request is refused without the capability.
    let ok_shape = ArtifactRequest {
        document: report_with_pan(),
        format: "markdown".into(),
    };
    assert_eq!(
        rt.generate_for(&stranger(), &ok_shape),
        Err(ArtifactGenError::NotAuthorized)
    );
}

#[test]
fn r6_artifact_generate_for_audits_and_proceeds_never_redacts() {
    let rt = ArtifactRuntime::with_builtin_renderers(Box::new(LuhnEntropyScanner));
    let req = ArtifactRequest {
        document: report_with_pan(),
        format: "markdown".into(),
    };

    let out = rt
        .generate_for(&author(), &req)
        .expect("authorized generate");

    // The PAN is flagged for the audit trail...
    assert!(
        out.findings.iter().any(|f| f.label == "PAN (Luhn-valid)"),
        "the injected scanner must be consulted through generate_for"
    );
    // ...but audit-and-proceed: the content is emitted intact, never redacted (a half-redacted PAN
    // inside prose — or worse, a code block — would corrupt the artifact).
    assert!(
        !out.redacted,
        "artifact compliance is audit-and-proceed, never redact"
    );
    let text = out.text_lossy();
    assert!(
        text.contains("4111111111111111"),
        "content must survive intact"
    );
    assert!(
        text.contains("select amount from ledger where id = $1"),
        "the code block must be emitted verbatim"
    );
    assert!(!out.is_binary());
    assert_eq!(out.format, "markdown");
}

#[test]
fn r6_artifact_generate_for_admin_bypass_and_unknown_format_after_authz() {
    let rt = ArtifactRuntime::with_builtin_renderers(Box::new(LuhnEntropyScanner));

    // An Admin principal carries no explicit caps but `has_cap` implies all — the surface is open.
    let admin = Principal::admin("root");
    let ok = rt
        .generate_for(
            &admin,
            &ArtifactRequest {
                document: Document::new("Ops Runbook"),
                format: "text".into(),
            },
        )
        .expect("admin is authorized");
    assert!(ok.text_lossy().contains("Ops Runbook"));

    // For an AUTHORIZED caller, an unregistered format is now a structural error (past the gate).
    assert_eq!(
        rt.generate_for(
            &admin,
            &ArtifactRequest {
                document: Document::new("x"),
                format: "docx".into(),
            }
        ),
        Err(ArtifactGenError::UnknownFormat("docx".into()))
    );
}

#[test]
fn r6_artifact_request_and_error_round_trip_on_the_wire() {
    // The request DTO deserializes straight from a transport body...
    let json = r#"{"document":{"title":"Q3","blocks":[{"kind":"paragraph","text":"hello"}]},"format":"markdown"}"#;
    let req: ArtifactRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.format, "markdown");
    assert_eq!(req.document.title, "Q3");

    let rt = ArtifactRuntime::with_builtin_renderers(Box::new(NoopScanner));
    let out = rt.generate_for(&author(), &req).unwrap();
    // ...and the successful output serializes back for the response body.
    let out_json = serde_json::to_string(&out).unwrap();
    let back: ainxt_artifact::ArtifactOutput = serde_json::from_str(&out_json).unwrap();
    assert_eq!(back, out);

    // A refusal renders verbatim as a tagged body (the transport maps it to 403).
    let refusal = serde_json::to_string(&ArtifactGenError::NotAuthorized).unwrap();
    assert_eq!(refusal, r#"{"error":"not_authorized"}"#);
    let parsed: ArtifactGenError = serde_json::from_str(&refusal).unwrap();
    assert_eq!(parsed, ArtifactGenError::NotAuthorized);
}

/// A scanner that flags nothing — keeps the wire round-trip test focused on the DTOs.
struct NoopScanner;
impl ContentScanner for NoopScanner {
    fn scan(&self, _text: &str) -> Vec<String> {
        Vec::new()
    }
}
