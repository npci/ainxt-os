// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R14 — close the HIGH "deterministic verify is parse-only on the shipped default (Stage 1/2/4 do
//! not run)".
//!
//! Before: the offline deterministic-verify seam had exactly two stand-ins — `OfflineVerifyToolchain`
//! (every step `ToolchainUnavailable`, i.e. the tool stages never run) and `CannedVerifyToolchain`
//! (a fixed scripted report). There was no offline impl that actually *ran* the checks it honestly
//! could, and no way to prove the Compile / Lint / Test stages (the pipeline's deterministic
//! Stage 1 / Stage 2 / Stage 3-4 tool stages) execute through the seam when a toolchain is provided.
//!
//! After: [`LocalVerifyToolchain`] runs a **real tree-sitter parse** as the Compile gate and runs the
//! Lint / Test stages through pluggable [`CheckHook`]s. This test proves:
//!
//!  1. **Stage 1 (Compile) actually runs** — a syntactically broken edit is `Failed` with a real
//!     `path:line` parse diagnostic (not a fabricated pass, not `ToolchainUnavailable`). The old
//!     `OfflineVerifyToolchain` on the same input reports `ToolchainUnavailable` — proving the stage
//!     genuinely runs now.
//!  2. **Stage 1/2/4 all run through the seam when a toolchain is provided** — Compile (real parse) +
//!     a provided Lint hook + a provided Test hook execute and produce real verdicts; a clean edit is
//!     `Verified` and a lint-flagged edit is `Rejected`.
//!  3. **The anti-fake invariant survives pluggability** — with no lint/test hook those stages are
//!     `ToolchainUnavailable` (never a fabricated pass); the enhanced impl is honest, not green-washing.
//!
//! The real `cargo build`/`clippy`/`cargo test` binding behind the same seam is infra (a live compiler
//! plus a test-runner in the serving-ops sandbox), exercised via `with_compile`/`with_lint`/`with_test`
//! by a deployment; here the hooks are deterministic offline stand-ins.

use ainxt_edit::toolchain::{
    CheckHook, Diagnostic, LocalVerifyToolchain, OfflineVerifyToolchain, Severity, StepResult,
    StepStatus, VerifyOutcome, VerifyRequest, VerifySource, VerifyStep, VerifyToolchain,
};
use ainxt_edit::Language;

fn req(steps: Vec<VerifyStep>) -> VerifyRequest {
    VerifyRequest {
        workspace_root: "/ws".into(),
        changed_files: vec!["src/pay.rs".into()],
        steps,
    }
}

fn step(report: &ainxt_edit::toolchain::VerifyReport, s: VerifyStep) -> &StepResult {
    report
        .steps
        .iter()
        .find(|r| r.step == s)
        .unwrap_or_else(|| panic!("missing step {s:?}"))
}

/// A deterministic offline lint stand-in: any line containing `TODO` is a gating lint error. Stands in
/// for a real `clippy`/`eslint` binding wired behind the same `CheckHook` seam.
fn todo_lint_hook() -> CheckHook {
    Box::new(|sources: &[VerifySource]| {
        let mut diagnostics = Vec::new();
        for s in sources {
            for (i, line) in s.content.lines().enumerate() {
                if line.contains("TODO") {
                    diagnostics.push(Diagnostic {
                        path: s.path.clone(),
                        line: i + 1,
                        severity: Severity::Error,
                        message: "lint: unresolved TODO on a gated path".into(),
                    });
                }
            }
        }
        StepResult {
            step: VerifyStep::Lint,
            status: if diagnostics.is_empty() {
                StepStatus::Passed
            } else {
                StepStatus::Failed
            },
            diagnostics,
        }
    })
}

/// A deterministic offline test stand-in that always passes (stands in for a real `cargo test` hook).
fn passing_test_hook() -> CheckHook {
    Box::new(|_: &[VerifySource]| StepResult {
        step: VerifyStep::Test,
        status: StepStatus::Passed,
        diagnostics: Vec::new(),
    })
}

#[test]
fn r14_deterministic_verify_stages_run() {
    // ---- (1) Stage 1 (Compile) actually RUNS a real parse — broken syntax ⇒ Failed ----------------
    let broken = VerifySource::new(
        "src/pay.rs",
        Language::Rust,
        "fn settle(amount: u64) -> u64 {\n    amount +\n}\n", // dangling `+` — real parse error
    );
    let local = LocalVerifyToolchain::new(vec![broken.clone()]);
    let rep = local.verify(&req(vec![VerifyStep::Compile]));
    let compile = step(&rep, VerifyStep::Compile);
    assert_eq!(
        compile.status,
        StepStatus::Failed,
        "the Compile stage must actually run the parse and FAIL a broken edit"
    );
    assert!(
        !compile.diagnostics.is_empty(),
        "a real parse failure carries an exact path:line diagnostic"
    );
    assert_eq!(compile.diagnostics[0].path, "src/pay.rs");
    assert_eq!(rep.outcome, VerifyOutcome::Rejected);

    // Contrast: the OLD shipped stand-in never runs the check — it is ToolchainUnavailable, which is
    // exactly the "parse-only / stages do not run" gap this round closes.
    let old = OfflineVerifyToolchain;
    let old_rep = old.verify(&req(vec![VerifyStep::Compile]));
    assert_eq!(
        step(&old_rep, VerifyStep::Compile).status,
        StepStatus::ToolchainUnavailable,
        "the pre-change offline stand-in does NOT run the compile stage"
    );

    // ---- (2) Stage 1/2/4 all RUN through the seam when a toolchain is provided --------------------
    // Clean edit + provided lint + provided test hooks → every deterministic stage runs → Verified.
    let clean = VerifySource::new(
        "src/pay.rs",
        Language::Rust,
        "fn settle(amount: u64) -> u64 {\n    amount + 1\n}\n",
    );
    let toolchain = LocalVerifyToolchain::new(vec![clean.clone()])
        .with_lint(todo_lint_hook())
        .with_test(passing_test_hook());
    let rep = toolchain.verify(&req(vec![
        VerifyStep::Compile,
        VerifyStep::Lint,
        VerifyStep::Test,
    ]));
    assert_eq!(
        step(&rep, VerifyStep::Compile).status,
        StepStatus::Passed,
        "Stage 1 Compile runs a real parse and passes a clean edit"
    );
    assert_eq!(
        step(&rep, VerifyStep::Lint).status,
        StepStatus::Passed,
        "Stage (3/4) Lint runs through the provided hook"
    );
    assert_eq!(
        step(&rep, VerifyStep::Test).status,
        StepStatus::Passed,
        "Stage 2 Test runs through the provided hook"
    );
    assert_eq!(
        rep.outcome,
        VerifyOutcome::Verified,
        "all three deterministic stages ran and passed ⇒ Verified"
    );
    assert!(rep.is_verified());

    // A real lint finding gates the commit (Stage 3/4 owns a deterministic Fail through the seam).
    let flagged = VerifySource::new(
        "src/pay.rs",
        Language::Rust,
        "fn settle(a: u64) -> u64 {\n    // TODO: verify overflow\n    a + 1\n}\n",
    );
    let toolchain = LocalVerifyToolchain::new(vec![flagged])
        .with_lint(todo_lint_hook())
        .with_test(passing_test_hook());
    let rep = toolchain.verify(&req(vec![
        VerifyStep::Compile,
        VerifyStep::Lint,
        VerifyStep::Test,
    ]));
    assert_eq!(step(&rep, VerifyStep::Lint).status, StepStatus::Failed);
    assert_eq!(step(&rep, VerifyStep::Lint).diagnostics[0].line, 2);
    assert_eq!(
        rep.outcome,
        VerifyOutcome::Rejected,
        "a lint failure that ran through the seam Rejects the edit"
    );

    // ---- (3) Anti-fake invariant survives pluggability: no hook ⇒ Unavailable, never a fake pass --
    let clean_only = LocalVerifyToolchain::new(vec![clean]);
    let rep = clean_only.verify(&req(vec![
        VerifyStep::Compile,
        VerifyStep::Lint,
        VerifyStep::Test,
    ]));
    assert_eq!(
        step(&rep, VerifyStep::Compile).status,
        StepStatus::Passed,
        "Compile still runs the built-in parse"
    );
    assert_eq!(
        step(&rep, VerifyStep::Lint).status,
        StepStatus::ToolchainUnavailable,
        "no lint hook ⇒ Unavailable, NOT a fabricated pass"
    );
    assert_eq!(
        step(&rep, VerifyStep::Test).status,
        StepStatus::ToolchainUnavailable,
        "no test hook ⇒ Unavailable, NOT a fabricated pass"
    );
    assert_eq!(
        rep.outcome,
        VerifyOutcome::Inconclusive,
        "an un-proven edit is Inconclusive, never green"
    );
    assert!(!rep.is_verified());

    // ---- Honesty on grammar-less sources: parse cannot verify ⇒ Unavailable, never a fake pass ----
    let opaque = VerifySource::new("data.bin", Language::Other, "\u{0}\u{1}garbage");
    let rep = LocalVerifyToolchain::new(vec![opaque]).verify(&req(vec![VerifyStep::Compile]));
    assert_eq!(
        step(&rep, VerifyStep::Compile).status,
        StepStatus::ToolchainUnavailable,
        "a grammar-less file cannot be parse-verified ⇒ Unavailable, never Passed"
    );
}
