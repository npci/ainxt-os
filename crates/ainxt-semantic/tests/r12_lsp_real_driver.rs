// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-12 — **the LSP rung (rung 1, highest fidelity) is a REAL driver, not just a seam**
//! (`SEMANTIC_EDITING.md` §2). Before this round the highest rung of the edit ladder had only a
//! scripted stand-in ([`ainxt_semantic::ladder::ScriptedLspRefactor`]) behind it — no code spoke the
//! Language Server Protocol, so a `RenameSymbol` could never *actually* resolve at rung 1; the ladder
//! always fell to the AST rung.
//!
//! Round-12 adds a real JSON-RPC/LSP client ([`ainxt_semantic::lsp`]): `Content-Length`-framed base
//! protocol, the `initialize`/`initialized` handshake, `textDocument/didOpen` + `textDocument/rename`,
//! and byte-precise application of the returned `WorkspaceEdit`. The single genuinely-infra concern —
//! a live server *process* — is isolated behind [`LspTransport`]: the live [`StdioLspTransport`] spawns
//! rust-analyzer/gopls/…; this test injects a [`ScriptedLspTransport`] that replays the exact framed
//! JSON-RPC a server would emit, proving the whole client end-to-end with no live process.
//!
//! `gap3-semantic-editing` item 1 (post round-12 follow-up): `ServerLspRefactor` no longer bakes a
//! single [`RenamePlan`] in at construction — the trait's `apply(lang, op, source, target)` now carries
//! an [`ainxt_semantic::ladder::LspEditTarget`] per call, and the driver resolves the symbol's position
//! itself via [`ainxt_semantic::lsp::resolve_rename_plan`]. This file's driver is now built with just
//! `(open, root_uri)` and the rename identity flows through `apply()`'s `target` argument instead.
//!
//! Fail-before / pass-after, in one file:
//!  * with the real driver wired, a Rust `RenameSymbol` resolves at [`Rung::Lsp`] with the server's
//!    edit applied to *both* occurrences (the def and its call site) — a result the AST closure below
//!    would NOT have produced, proving rung 1 truly won;
//!  * with the transport unavailable (no live server — the air-gapped/CI default), the identical run
//!    degrades honestly: the LSP attempt is recorded `Unavailable` and the ladder falls to the AST
//!    rung — the missing server never masquerades as a completed refactor.

use ainxt_semantic::ladder::{
    CodeLanguage, EditLadder, LspEditTarget, LspRefactor, Rung, SemanticOp,
};
use ainxt_semantic::lsp::{scripted_transport_factory, LspError, LspTransport, ServerLspRefactor};
use serde_json::json;

const URI: &str = "file:///repo/src/a.rs";
const SRC: &str = "fn caller() {\n    old_name();\n}\n\nfn old_name() {}\n";

/// The framed JSON-RPC a real language server would emit for the initialize + rename sequence:
/// an `initialize` result, then a `WorkspaceEdit` renaming `old_name` → `renamed` at BOTH occurrences.
fn server_script() -> Vec<serde_json::Value> {
    vec![
        json!({"jsonrpc":"2.0","id":1,"result":{"capabilities":{"renameProvider":true}}}),
        json!({
            "jsonrpc":"2.0","id":2,
            "result":{
                "changes":{
                    URI:[
                        // the call site on line 1
                        {"range":{"start":{"line":1,"character":4},"end":{"line":1,"character":12}},"newText":"renamed"},
                        // the definition on line 4
                        {"range":{"start":{"line":4,"character":3},"end":{"line":4,"character":11}},"newText":"renamed"}
                    ]
                }
            }
        }),
    ]
}

/// The target the trait now carries per call: which symbol, at which URI, renamed to what. The
/// driver resolves the exact `(line, character)` itself (a whole-word text search over `SRC`), so no
/// position is hardcoded by the caller here — unlike round-12's original `plan()` helper.
fn target() -> LspEditTarget {
    LspEditTarget::rename(URI, "old_name", "renamed")
}

/// Run a RenameSymbol through the real ladder with `lsp` as the rung-1 driver. The AST closure below
/// produces a deliberately-WRONG marker so we can prove which rung actually won.
fn run_rename(lsp: &dyn LspRefactor) -> ainxt_semantic::ladder::FallTrail {
    let ladder = EditLadder::new(Some(lsp));
    ladder.run(
        CodeLanguage::Rust,
        SemanticOp::RenameSymbol,
        SRC,
        &target(),
        // AST rung — would resolve, but with a marker so an accidental AST win is detectable.
        |src| Ok(src.replace("old_name", "AST_RUNG_WON")),
        // structured rung
        |_src| Err("no anchored edits".to_string()),
        // text rung
        |src| Ok(src.replace("old_name", "TEXT_RUNG_WON")),
    )
}

#[test]
fn r12_lsp_rung_resolves_a_real_rename_via_the_json_rpc_driver() {
    let driver =
        ServerLspRefactor::new(scripted_transport_factory(server_script()), "file:///repo");
    let trail = run_rename(&driver);

    // Rung 1 truly won — highest fidelity, zero confidence penalty.
    assert_eq!(
        trail.applied_rung,
        Some(Rung::Lsp),
        "the real LSP driver must resolve rung 1, not fall to AST"
    );
    assert_eq!(trail.confidence_penalty(), 0);

    let out = trail.result.expect("a result");
    // The server's WorkspaceEdit was applied byte-precisely to BOTH occurrences...
    assert_eq!(out, "fn caller() {\n    renamed();\n}\n\nfn renamed() {}\n");
    // ...and it was the SERVER, not the AST/text closures, that produced it.
    assert!(!out.contains("AST_RUNG_WON"));
    assert!(!out.contains("TEXT_RUNG_WON"));
    assert!(!out.contains("old_name"));
}

/// A transport factory that always fails to open — the air-gapped/CI default with no server binary.
fn dead_transport_factory() -> impl Fn() -> Result<Box<dyn LspTransport>, LspError> {
    || {
        Err(LspError::Transport(
            "no language server on PATH".to_string(),
        ))
    }
}

#[test]
fn r12_no_live_server_degrades_honestly_to_the_ast_rung() {
    let driver = ServerLspRefactor::new(dead_transport_factory(), "file:///repo");
    let trail = run_rename(&driver);

    // The LSP rung was ATTEMPTED and recorded unavailable — never silently skipped.
    let lsp_attempt = trail
        .attempts
        .iter()
        .find(|a| a.rung == Rung::Lsp)
        .expect("the LSP rung must be attempted before it falls");
    assert!(!lsp_attempt.succeeded);
    assert!(
        lsp_attempt.reason.contains("live server") || lsp_attempt.reason.contains("unavailable"),
        "the fall reason names the missing server: {:?}",
        lsp_attempt.reason
    );

    // ...and the ladder fell to the AST rung, which resolved.
    assert_eq!(trail.applied_rung, Some(Rung::Ast));
    assert_eq!(
        trail.result.as_deref(),
        Some("fn caller() {\n    AST_RUNG_WON();\n}\n\nfn AST_RUNG_WON() {}\n")
    );
}

#[test]
fn r12_unsupported_op_is_unavailable_and_falls_without_a_false_rung1() {
    // The driver wires only RenameSymbol; a ReplaceFunction must fall to AST, never claim rung 1.
    let driver =
        ServerLspRefactor::new(scripted_transport_factory(server_script()), "file:///repo");
    let ladder = EditLadder::new(Some(&driver as &dyn LspRefactor));
    let trail = ladder.run(
        CodeLanguage::Rust,
        SemanticOp::ReplaceFunction,
        SRC,
        &target(),
        |src| Ok(src.replace("old_name", "AST_REPLACED")),
        |_s| Err("n/a".to_string()),
        |s| Ok(s.to_string()),
    );
    // ReplaceFunction does not even offer the LSP rung in the matrix, so AST wins cleanly.
    assert_eq!(trail.applied_rung, Some(Rung::Ast));
    assert!(trail.result.unwrap().contains("AST_REPLACED"));
}
