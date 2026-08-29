// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R14 (served-composition, HIGH) — the served Program driver ENFORCES the §7 per-Run token budget and
//! the §8 human-checkpoint gate (no critical-path forced-commit). Before this round the served path
//! built a `SupervisorConfig` and immediately discarded it (`let _ = config`), and the verified driver
//! committed every proven node — so a critical-path (settlement/ledger) node was FORCE-committed with
//! no human gate, and a runaway Run had no budget. `drive_served_program_governed` +
//! `ServedProgramGovernance` close both, and `ProgramSurface` now drives the governed path.
//!
//! FAIL-BEFORE: `drive_served_program_governed`/`ServedProgramGovernance` did not exist; the served
//! driver force-committed critical-path nodes and ignored the budget.
//! PASS-AFTER: green, offline, deterministic.

use ainxt_planner::program::{CheckpointClass, NodeClass, NodeDecl, ProgramOutcome};
use ainxt_protocol::Event;
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_runtime::{engine_with_defaults, CancelToken};
use ainxt_runtimed::{
    assemble_program, drive_served_program_governed, load_layered, LoadedConfig, ProgramProofSeams,
    RunIdentitySpec, ServedProgramGovernance, SodApprover,
};
use ainxt_types::DataClass;
use std::sync::Arc;
use tokio::sync::mpsc;

fn offline() -> LoadedConfig {
    load_layered(&[("x", "version = 1")]).unwrap()
}

fn identity(run: &str) -> RunIdentitySpec {
    RunIdentitySpec::new("agent", "r14-gov", run, DataClass::Internal, "u-alice")
}

/// GAP-FIX planner-assurance-revision (item 1) — a fixed-text model [`Provider`], the same
/// substitution `r21_program_rubric_judge_real_verdict.rs` uses: `assemble_program`'s `OfflineProvider`
/// always streams the SAME prompt-invariant "offline mode: no model configured." text, which the served
/// Program driver's Judge is now a REAL, content-varying `RubricJudge` (no longer a fabricated fixed
/// pass) — that canned text carries none of a real goal's keywords, so it genuinely (and correctly)
/// fails the Judge and can no longer stand in for "the checkpoint-approved Run completes". This
/// provider lets the test supply a genuinely substantive, on-goal, safe artifact instead.
struct FixedTextProvider {
    text: String,
}
impl Provider for FixedTextProvider {
    fn id(&self) -> &str {
        "r14-test-producer"
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

// ============================ §7 budget bites on the served path ============================

#[tokio::test(flavor = "multi_thread")]
async fn r14_served_program_budget_caps_the_run() {
    let pr = assemble_program(&offline()).expect("assemble program runtime");
    let nodes = vec![
        NodeDecl::new("assess", NodeClass::MigrationRun),
        NodeDecl::new("migrate", NodeClass::MigrationRun).depends_on("assess"),
    ];
    // A 1-token ceiling: the first real module turn's output already blows it, so the driver halts at
    // the next module boundary — an honest CappedPartial, never a forced completion.
    let run = drive_served_program_governed(
        pr.engine(),
        identity("budget"),
        "migrate the settlement module",
        nodes,
        None,
        None,
        None,
        SodApprover::Distinct,
        CancelToken::new(),
        ProgramProofSeams::offline_default(),
        ServedProgramGovernance {
            budget_tokens: 1,
            critical_path_approved: true,
            fleet_slots: None,
        },
    )
    .await
    .expect("a budget-capped run still drives to a terminal outcome");

    assert_eq!(
        run.outcome,
        ProgramOutcome::CappedPartial,
        "the §7 token budget must cap the served Run, never force it Completed"
    );
    assert!(
        run.program.state().committed_node_ids().len() < 2,
        "the budget cap must stop the Run before every node commits"
    );
}

// ============================ §8 human checkpoint: no critical-path forced-commit ============

fn critical_path_nodes() -> Vec<NodeDecl> {
    vec![
        NodeDecl::new("assess", NodeClass::MigrationRun),
        // The settlement cutover is a CRITICAL-PATH human checkpoint.
        NodeDecl::new("migrate", NodeClass::MigrationRun)
            .depends_on("assess")
            .checkpoint(CheckpointClass::CriticalPath),
    ]
}

#[tokio::test(flavor = "multi_thread")]
async fn r14_critical_path_node_is_held_without_human_approval() {
    let pr = assemble_program(&offline()).expect("assemble program runtime");
    let run = drive_served_program_governed(
        pr.engine(),
        identity("checkpoint-held"),
        "migrate the settlement module",
        critical_path_nodes(),
        None,
        None,
        None,
        SodApprover::Distinct,
        CancelToken::new(),
        ProgramProofSeams::offline_default(),
        // The served default: NO human approval present.
        ServedProgramGovernance {
            budget_tokens: 0,
            critical_path_approved: false,
            fleet_slots: None,
        },
    )
    .await
    .expect("the run drives to a terminal outcome");

    assert_eq!(
        run.outcome,
        ProgramOutcome::CappedPartial,
        "a critical-path node with no human checkpoint must NOT force the Run Completed"
    );
    let committed: Vec<String> = run
        .program
        .state()
        .committed_node_ids()
        .iter()
        .map(|n| n.as_str().to_string())
        .collect();
    assert!(
        !committed.contains(&"migrate".to_string()),
        "the critical-path 'migrate' node must NOT be force-committed without a human checkpoint: {committed:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn r14_critical_path_node_commits_once_human_approves() {
    // GAP-FIX planner-assurance-revision (item 1) — a genuinely substantive, on-goal, tested, safe
    // artifact (not the OfflineProvider's fixed prompt-invariant text) is required for this run to
    // reach Completed now that the served Judge is a real, content-varying `RubricJudge`.
    let engine = engine_with_fixed_text(
        "migrated the settlement module: assessed dependencies and executed the settlement cutover \
         successfully, with boundary tests covering empty and negative edge cases.",
    );
    let run = drive_served_program_governed(
        engine,
        identity("checkpoint-approved"),
        "migrate the settlement module",
        critical_path_nodes(),
        None,
        None,
        None,
        SodApprover::Distinct,
        CancelToken::new(),
        ProgramProofSeams::offline_default(),
        // Contrast: the human checkpoint is approved → the critical-path node proceeds and commits.
        ServedProgramGovernance {
            budget_tokens: 0,
            critical_path_approved: true,
            fleet_slots: None,
        },
    )
    .await
    .expect("the approved run drives to a terminal outcome");

    assert_eq!(
        run.outcome,
        ProgramOutcome::Completed,
        "with the human checkpoint approved the critical-path Run completes"
    );
    let committed: Vec<String> = run
        .program
        .state()
        .committed_node_ids()
        .iter()
        .map(|n| n.as_str().to_string())
        .collect();
    assert!(
        committed.contains(&"migrate".to_string()),
        "the approved critical-path node commits: {committed:?}"
    );
}

// A no-op to keep the offline `Arc<Engine>` import honest on all toolchains.
#[allow(dead_code)]
fn _touch(_e: Arc<ainxt_runtime::Engine>) {}
