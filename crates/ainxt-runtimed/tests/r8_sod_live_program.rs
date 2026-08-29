// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-8 — the Separation-of-Duties verify-gate is WIRED into the LIVE program-verification path
//! (ADR-022 §18). Before this, `run_program_verified` reached `commit_node` on any three-way-green
//! node with NO producer≠approver check — the SoD gate (`ainxt_identity::sod`) existed but nothing on
//! the served program path called it. Now every node commit is authorized by
//! [`ainxt_identity::sod::SodVerifyGate`] against a DISTINCT verifier/approver Run.
//!
//! These tests drive the REAL program driver over the offline [`ainxt_runtime::Engine`] the daemon
//! assembles (`assemble_program`), through `run_program_verified_sod`:
//!
//!   * fail-before/pass-after — a self-approving misconfiguration (the approver Run == the producing
//!     Run) is REFUSED at every commit: no node commits, `sod_approvals == 0`, and the program cannot
//!     reach `Completed`. Without the wire this program would have committed and completed.
//!   * the composition default (a distinct approver Run) authorizes each commit and the program
//!     completes, with one SoD authorization per committed node.

use ainxt_planner::program::{NodeClass, NodeDecl, ProgramOutcome};
use ainxt_protocol::Event;
use ainxt_runtime::engine_with_defaults;
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_runtimed::{
    assemble_program, load_layered, run_program_verified_sod, LoadedConfig, RunIdentitySpec,
    SodApprover,
};
use ainxt_types::DataClass;
use std::sync::Arc;
use tokio::sync::mpsc;

fn offline_config() -> LoadedConfig {
    load_layered(&[("x", "version = 1")]).unwrap()
}

/// GAP-FIX planner-assurance-revision (item 1) — a fixed-text model [`Provider`]: the served Program
/// driver's semantic Judge is now a REAL, content-varying `RubricJudge`, never a fabricated fixed pass,
/// so the air-gapped `OfflineProvider`'s prompt-invariant "offline mode: no model configured." text can
/// no longer stand in for "the module genuinely committed" — it carries none of a real goal's keywords.
struct FixedTextProvider {
    text: String,
}
impl Provider for FixedTextProvider {
    fn id(&self) -> &str {
        "r8-test-producer"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, _prompt: &str) -> mpsc::Receiver<Event> {
        let (tx, rx) = mpsc::channel(8);
        let text = self.text.clone();
        tokio::spawn(async move {
            let _ = tx.send(Event::TextDelta(text)).await;
            let _ = tx.send(Event::Done).await;
        });
        rx
    }
}

fn engine_with_fixed_text(text: &str) -> Arc<ainxt_runtime::Engine> {
    let mut router = ModelRouter::new();
    router.register(Box::new(FixedTextProvider {
        text: text.to_string(),
    }));
    Arc::new(engine_with_defaults(router))
}

/// A 2-node dependency chain the program driver executes through real engine turns.
fn nodes() -> Vec<NodeDecl> {
    vec![
        NodeDecl::new("mod-a", NodeClass::MigrationRun),
        NodeDecl::new("mod-b", NodeClass::MigrationRun).depends_on("mod-a"),
    ]
}

fn identity(run_id: &str) -> RunIdentitySpec {
    RunIdentitySpec::new(
        "agent",
        "r8-sod-prog",
        run_id,
        DataClass::Internal,
        "u-alice",
    )
}

// R8 — self-approval is REFUSED on the live program-verification path: forcing the approver Run to be
// the producing Run makes every commit a self-approval, which the SoD gate refuses, so nothing commits.
#[tokio::test(flavor = "multi_thread")]
async fn r8_sod_live_program_refuses_self_approval() {
    let pr = assemble_program(&offline_config()).unwrap();

    // The producing Run acts as its own approver (producer == approver) — a self-approving
    // misconfiguration the SoD gate refuses at every commit.
    let run = run_program_verified_sod(
        pr.engine(),
        identity("prog-self-approve"),
        "migrate the module",
        nodes(),
        None,
        None,
        SodApprover::SameAsProducer,
        ainxt_runtime::CancelToken::new(),
    )
    .await
    .expect(
        "the run drives to a terminal outcome (self-approval is a refused commit, not a crash)",
    );

    let committed = run.program.state().committed_node_ids().len();
    assert_eq!(committed, 0, "a self-approving Run must commit NOTHING");
    assert_eq!(
        run.sod_approvals, 0,
        "no commit may be SoD-authorized under self-approval"
    );
    assert_ne!(
        run.outcome,
        ProgramOutcome::Completed,
        "a program whose every commit is self-approval-refused cannot complete: {:?}",
        run.outcome
    );
}

// R8 — the composition default (a DISTINCT approver Run) authorizes each commit; the program completes
// with exactly one SoD authorization per committed node. Proves the gate is on the path AND grants for
// a legitimate producer≠approver pairing (never a blanket refusal).
#[tokio::test(flavor = "multi_thread")]
async fn r8_sod_live_program_distinct_approver_completes() {
    // GAP-FIX planner-assurance-revision (item 1) — a genuinely substantive, on-goal artifact is
    // required for the REAL RubricJudge to pass; see `FixedTextProvider`'s doc comment.
    let engine = engine_with_fixed_text(
        "migrated the module: assessed dependencies and executed the migration successfully, with \
         boundary tests covering empty and negative edge cases.",
    );

    let run = run_program_verified_sod(
        engine,
        identity("prog-distinct"),
        "migrate the module",
        nodes(),
        None,
        None,
        SodApprover::Distinct, // a distinct `<producer>::verifier` approver Run
        ainxt_runtime::CancelToken::new(),
    )
    .await
    .expect("distinct approver -> the program runs");

    let committed = run.program.state().committed_node_ids().len();
    assert_eq!(committed, 2, "both nodes commit under a distinct approver");
    assert_eq!(
        run.sod_approvals, 2,
        "one SoD authorization per committed node"
    );
    assert_eq!(run.outcome, ProgramOutcome::Completed);
    assert!(run.program.state().committed_nodes_are_all_proven());
}
