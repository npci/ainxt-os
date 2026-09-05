// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-9 offline seam tests for the edit ladder's top rung (LSP rename/refs) and the
//! deterministic-verify (compile/test) gate. Both real drivers are infra (live language server /
//! compiler); these prove the *seams* behave correctly offline and — critically — that the offline
//! stand-ins never manufacture a green.

use ainxt_edit::toolchain::{
    CannedLspClient, CannedVerifyToolchain, Diagnostic, FileEdit, LspClient, LspError,
    OfflineVerifyToolchain, Position, RenameRequest, Severity, StepResult, StepStatus, SymbolQuery,
    SymbolRef, VerifyOutcome, VerifyReport, VerifyRequest, VerifyStep, VerifyToolchain,
    WorkspaceEdit,
};

fn query(path: &str, line: usize, col: usize, symbol: &str) -> SymbolQuery {
    SymbolQuery {
        path: path.to_string(),
        position: Position::new(line, col),
        symbol: symbol.to_string(),
    }
}

// -------------------------------- LSP client seam --------------------------------

#[test]
fn r9_lsp_client_seam_canned_rename_and_refs() {
    let q = query("src/pay.rs", 12, 9, "amount");
    let refs = vec![
        SymbolRef {
            path: "src/pay.rs".into(),
            position: Position::new(12, 9),
        },
        SymbolRef {
            path: "src/pay.rs".into(),
            position: Position::new(40, 17),
        },
        SymbolRef {
            path: "src/settle.rs".into(),
            position: Position::new(7, 22),
        },
    ];
    let edit = WorkspaceEdit {
        files: vec![
            FileEdit {
                path: "src/pay.rs".into(),
                new_content: "// renamed amount -> gross_amount\n".into(),
                changed_lines: vec![12, 40],
            },
            FileEdit {
                path: "src/settle.rs".into(),
                new_content: "// renamed amount -> gross_amount\n".into(),
                changed_lines: vec![7],
            },
        ],
    };
    let rename_req = RenameRequest {
        query: q.clone(),
        new_name: "gross_amount".into(),
    };

    let client = CannedLspClient::new()
        .with_references(q.clone(), refs.clone())
        .with_rename(rename_req.clone(), edit.clone());

    // Scripted references come back exactly — the toolchain-guaranteed cross-file set (rung 1).
    let got = client.references(&q).expect("scripted refs");
    assert_eq!(got, refs);
    assert_eq!(got.len(), 3, "rename must touch all three real references");

    // Scripted rename returns the server-computed workspace edit verbatim (engine applies, never
    // re-derives).
    let got_edit = client.rename(&rename_req).expect("scripted rename");
    assert_eq!(got_edit, edit);
    assert_eq!(got_edit.files.len(), 2);

    // HONESTY: anything not scripted is Unavailable, so the ladder falls DOWN to AST/patch — the
    // offline stand-in never guesses a rename it wasn't given.
    let unknown = query("src/pay.rs", 99, 1, "unknown_sym");
    match client.references(&unknown) {
        Err(LspError::Unavailable(_)) => {}
        other => panic!("unscripted query must be Unavailable, got {other:?}"),
    }
    let unknown_rename = RenameRequest {
        query: q.clone(),
        new_name: "different_name".into(),
    };
    assert!(matches!(
        client.rename(&unknown_rename),
        Err(LspError::Unavailable(_))
    ));
}

// -------------------------------- Deterministic-verify seam --------------------------------

#[test]
fn r9_verify_toolchain_seam_offline_is_never_green() {
    let req = VerifyRequest {
        workspace_root: "/ws".into(),
        changed_files: vec!["src/pay.rs".into()],
        steps: vec![VerifyStep::Compile, VerifyStep::Test],
    };

    // Offline: no compiler present. Every step is ToolchainUnavailable and the verdict is
    // Inconclusive — absence of a toolchain is UNKNOWN, never PASSED. This is the anti-fake invariant.
    let offline = OfflineVerifyToolchain;
    let report = offline.verify(&req);
    assert_eq!(report.outcome, VerifyOutcome::Inconclusive);
    assert!(!report.is_verified(), "offline must never report verified");
    assert!(report
        .steps
        .iter()
        .all(|s| s.status == StepStatus::ToolchainUnavailable));

    // A scripted "all passed" toolchain drives the gate's happy path.
    let passed = CannedVerifyToolchain::new(VerifyReport::from_steps(vec![
        StepResult {
            step: VerifyStep::Compile,
            status: StepStatus::Passed,
            diagnostics: vec![],
        },
        StepResult {
            step: VerifyStep::Test,
            status: StepStatus::Passed,
            diagnostics: vec![],
        },
    ]));
    assert!(passed.verify(&req).is_verified());

    // A scripted compile failure ⇒ Rejected, tests skipped, diagnostics preserved.
    let failed = CannedVerifyToolchain::new(VerifyReport::from_steps(vec![
        StepResult {
            step: VerifyStep::Compile,
            status: StepStatus::Failed,
            diagnostics: vec![Diagnostic {
                path: "src/pay.rs".into(),
                line: 12,
                severity: Severity::Error,
                message: "cannot find value `amount` in this scope".into(),
            }],
        },
        StepResult {
            step: VerifyStep::Test,
            status: StepStatus::Skipped,
            diagnostics: vec![],
        },
    ]));
    let rep = failed.verify(&req);
    assert_eq!(rep.outcome, VerifyOutcome::Rejected);
    assert!(!rep.is_verified());
    assert_eq!(rep.steps[0].diagnostics.len(), 1);
    assert_eq!(rep.steps[0].diagnostics[0].severity, Severity::Error);

    // Empty step set proves nothing → Inconclusive (not a vacuous pass).
    assert_eq!(
        VerifyReport::from_steps(vec![]).outcome,
        VerifyOutcome::Inconclusive
    );
}
