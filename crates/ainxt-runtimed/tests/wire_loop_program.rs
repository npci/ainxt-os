// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! WIRE-2 proofs: the long-horizon **Program Supervisor** (`ainxt-planner`) and the hierarchical
//! **3-tier Team** loop (`ainxt-teams`) are now REACHABLE from the composition root and driven by a
//! REAL [`ainxt_runtime::Engine`], not a test fake. Each test constructs the real object the daemon
//! assembles (`assemble_program` → `ProgramRuntime` over the offline engine) and drives the subsystem
//! end-to-end.
//!
//! Before this wire the subsystems were built + unit-tested but UNREACHABLE — no live crate depended
//! on them, so their `RunExecutor` / `TaskExecutor` seams had only fake backings and these tests could
//! not be written. After the wire they pass through a live engine turn per module / task.
//!
//!   * `wire2_loop_01_program_runs_through_real_engine` — a 2-node Program runs end-to-end through
//!     real engine turns; BOTH nodes execute and the program completes (LOOP-01/LOOP-15 driver).
//!   * `wire2_loop_15_team_runs_through_real_engine` — a 2-task Team run drives real engine turns to a
//!     confirmed completion (LOOP-15).
//!   * `wire2_idn_03_per_run_credential_minted_and_used` — a per-Run AgentWorkloadCredential is minted
//!     at run start and threaded as the policy principal for every executor turn (IDN-03).
//!   * `wire2_fi_02_regulated_egress_arms_incident_clock` — a regulated turn on which the compliance
//!     gate acts arms a statutory incident clock via the typed detector adapter (FI-02).
//!   * `wire2_loop_13_team_learning_record_routed_to_sink` — a terminal team run's Learning Record is
//!     routed to an injected sink (LOOP-13).

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use ainxt_identity::LogicalTime;
use ainxt_incident::{ArmingPolicy, IncidentClass, IncidentRegister, StatutoryClockKind};
use ainxt_planner::program::{ChildOutcome, NodeClass, NodeDecl, ProgramEvent, ProgramOutcome};
use ainxt_planner::supervisor::SupervisorConfig;
use ainxt_protocol::Event;
use ainxt_runtime::engine_with_defaults;
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_runtimed::{
    assemble_program, load_layered, run_program, InMemoryLearningSink, LearningSink, LoadedConfig,
    RunIdentitySpec,
};
use ainxt_teams::tiers::{TeamOutcome, ThreeTierConfig};
use ainxt_teams::{ModelTier, Role, Task, TaskGraph, TaskId, Team};
use ainxt_types::DataClass;

/// The daemon's default offline config (no keys ⇒ deterministic offline provider, independent of env).
fn offline_config() -> LoadedConfig {
    load_layered(&[("x", "version = 1")]).unwrap()
}

/// GAP-FIX planner-assurance-revision (item 1) — a fixed-text model [`Provider`]: the bundled
/// (`EngineRunExecutor::execute_module`) semantic Judge is now a REAL, content-varying `RubricJudge`,
/// never a fabricated fixed pass, so the air-gapped `OfflineProvider`'s prompt-invariant "offline mode:
/// no model configured." text can no longer stand in for "the program genuinely completes" — it
/// carries none of a real goal's keywords. Used in place of `pr.engine()` (still built via
/// `assemble_program`, whose OTHER mandatory gates this keeps exercising) wherever a test needs the
/// REAL RubricJudge to pass, calling the free [`run_program`] function `ProgramRuntime::run_program`
/// itself delegates to (never a bespoke driver).
struct FixedTextProvider {
    text: String,
}
impl Provider for FixedTextProvider {
    fn id(&self) -> &str {
        "wire-test-producer"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, _prompt: &str) -> tokio::sync::mpsc::Receiver<Event> {
        let (tx, rx) = tokio::sync::mpsc::channel(8);
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

/// A 2-task chain: coder → reviewer, matching the team roles below.
fn chain_graph() -> TaskGraph {
    let mut g = TaskGraph::new();
    g.add_task(
        Task::new("impl", "coder")
            .produces("diff")
            .accepts("compiles"),
    )
    .unwrap();
    g.add_task(
        Task::new("review", "reviewer")
            .depends_on("impl")
            .accepts("reviewed"),
    )
    .unwrap();
    g
}

fn team() -> Team {
    let mut t = Team::new();
    t.add_role(Role::new("coder", ModelTier::Medium, ["edit_code"]));
    t.add_role(Role::new("reviewer", ModelTier::Simple, ["review"]));
    t
}

// ============================ LOOP-01 — Program through the real engine ============================

#[tokio::test(flavor = "multi_thread")]
async fn wire2_loop_01_program_runs_through_real_engine() {
    // The REAL program runtime the daemon assembles (offline engine behind the mandatory gates).
    let pr = assemble_program(&offline_config()).unwrap();
    assert!(
        pr.report.iter().any(|r| r.contains("Program Supervisor")),
        "assembly report must record the reachable program subsystem: {:?}",
        pr.report
    );

    // A 2-node dependency chain: mod-a → mod-b.
    let nodes = vec![
        NodeDecl::new("mod-a", NodeClass::MigrationRun),
        NodeDecl::new("mod-b", NodeClass::MigrationRun).depends_on("mod-a"),
    ];
    let identity = RunIdentitySpec::new(
        "agent",
        "loop01-prog",
        "prog-loop01",
        DataClass::Internal,
        "u-loop01",
    );

    // GAP-FIX planner-assurance-revision (item 1) — a genuinely substantive, on-goal artifact is
    // required for the bundled RubricJudge to pass; see `FixedTextProvider`'s doc comment. The free
    // `run_program` function is the EXACT function `pr.run_program(..)` delegates to.
    let engine = engine_with_fixed_text(
        "migrated the settlement switch: assessed dependencies and executed the cutover successfully, \
         with boundary tests covering empty and negative edge cases.",
    );
    let run = run_program(
        engine,
        identity,
        "migrate the settlement switch",
        nodes,
        SupervisorConfig::default(),
        None,
    )
    .await
    .expect("program run");

    // The program completed through the terminal COMPLETED gate — never a self-report.
    assert_eq!(run.report.outcome, ProgramOutcome::Completed);
    assert!(run.report.gate.is_complete());

    // BOTH nodes executed and committed, in dependency order.
    let committed: Vec<String> = run
        .report
        .final_state
        .committed_node_ids()
        .iter()
        .map(|n| n.as_str().to_string())
        .collect();
    assert_eq!(committed.len(), 2, "both nodes committed: {committed:?}");
    assert!(committed.contains(&"mod-a".to_string()));
    assert!(committed.contains(&"mod-b".to_string()));
    assert!(run.report.final_state.committed_is_dependency_closed());

    // Each node was executed by a REAL engine turn.
    let module_turns: Vec<_> = run
        .turns
        .iter()
        .filter(|t| t.label.starts_with("module:"))
        .collect();
    assert_eq!(
        module_turns.len(),
        2,
        "one real engine turn per module: {:?}",
        run.turns
    );
    assert!(module_turns
        .iter()
        .all(|t| t.ok && t.provider == "wire-test-producer"));
    assert!(
        module_turns
            .iter()
            .all(|t| t.text.contains("migrated the settlement switch")),
        "modules must be driven by a live engine turn: {module_turns:?}"
    );
}

// ==================== gap loop-teams-longhorizon item 3 — child-program composition ====================

/// gap loop-teams-longhorizon (item 3, child-program composition): before this wire, a
/// `NodeClass::ChildProgram` node fell straight into the ordinary `drive_turn` engine-turn path in
/// `EngineRunExecutor::execute_module` — the REAL executor never special-cased it, so a served/durable
/// program could never actually recurse into a nested Program (`ChildProgramSpawned`/
/// `ChildProgramOutcomeMapped` would never be emitted on a real run, only in tests against fakes). This
/// proves the real wire: a `ChildProgram`-class node spawns an ACTUAL nested Program (its own
/// single-node MTG), drives it through a REAL engine turn, and maps its terminal outcome back onto the
/// parent node — which then itself runs (and commits) through a second real engine turn.
#[tokio::test(flavor = "multi_thread")]
async fn wire2_loop_teams_longhorizon_child_program_spawns_and_completes_through_real_engine() {
    let nodes = vec![NodeDecl::new("decouple-legacy", NodeClass::ChildProgram)];
    let identity = RunIdentitySpec::new(
        "agent",
        "loop01-child",
        "prog-child-program",
        DataClass::Internal,
        "u-child",
    );

    // GAP-FIX planner-assurance-revision (item 1) — a genuinely substantive, on-goal artifact is
    // required for the bundled RubricJudge to pass, for BOTH the parent node's own turn and the child
    // program's own module turn (its goal is the parent goal plus a suffix — see
    // `EngineRunExecutor::execute_child_program`'s `child_goal`, still a superstring of this text's
    // matched keywords). See `FixedTextProvider`'s doc comment.
    let engine = engine_with_fixed_text(
        "migrated the settlement switch: assessed dependencies and executed the cutover successfully, \
         with boundary tests covering empty and negative edge cases.",
    );
    let run = run_program(
        engine,
        identity,
        "migrate the settlement switch",
        nodes,
        SupervisorConfig::default(),
        None,
    )
    .await
    .expect("program run");

    // The parent program reaches COMPLETED for real: the nested child program's own node committed
    // through a real engine turn, mapped Completed back onto the parent's ChildProgram node, which
    // then itself ran to completion.
    assert_eq!(run.report.outcome, ProgramOutcome::Completed);
    assert!(run.report.gate.is_complete());

    // The durable parent log actually recorded the child-program spawn + terminal mapping (ADR-027
    // §4) — never silently flattened into an ordinary module turn.
    assert!(
        run.events
            .iter()
            .any(|e| matches!(e, ProgramEvent::ChildProgramSpawned { .. })),
        "a ChildProgramSpawned event must be durably appended: {:?}",
        run.events
    );
    assert!(
        run.events.iter().any(|e| matches!(
            e,
            ProgramEvent::ChildProgramOutcomeMapped { outcome, .. } if *outcome == ChildOutcome::Completed
        )),
        "the child's REAL terminal outcome must be mapped back, never fabricated: {:?}",
        run.events
    );

    // The parent's own node committed (Completed re-opened it to Ready and it then ran for real).
    let committed: Vec<String> = run
        .report
        .final_state
        .committed_node_ids()
        .iter()
        .map(|n| n.as_str().to_string())
        .collect();
    assert!(
        committed.contains(&"decouple-legacy".to_string()),
        "the parent node must commit after its child resolves: {committed:?}"
    );

    // A REAL nested engine turn ran for the child's own work module — not a fabricated result.
    assert!(
        run.turns
            .iter()
            .any(|t| t.label == "module:decouple-legacy::work"
                && t.ok
                && t.provider == "wire-test-producer"),
        "the child program's own node must be driven by a real engine turn: {:?}",
        run.turns
    );
    // AND the parent node itself got its own (post-child) real engine turn.
    assert!(
        run.turns
            .iter()
            .any(|t| t.label == "module:decouple-legacy" && t.ok),
        "the parent node must run its own turn once its child resolves: {:?}",
        run.turns
    );
}

// ============================ LOOP-15 — Team through the real engine ============================

#[tokio::test(flavor = "multi_thread")]
async fn wire2_loop_15_team_runs_through_real_engine() {
    let pr = assemble_program(&offline_config()).unwrap();

    let identity = RunIdentitySpec::new(
        "agent",
        "loop15-team",
        "team-loop15",
        DataClass::Internal,
        "u-loop15",
    );

    let run = pr
        .run_team(
            identity,
            chain_graph(),
            team(),
            "ship the feature",
            BTreeSet::new(),
            ThreeTierConfig::default(),
            None,
            None,
        )
        .await
        .expect("team run");

    // The 3-tier loop confirmed the deliverable and every task ran.
    assert_eq!(run.report.outcome, TeamOutcome::Complete);
    assert!(run.report.last_run.all_succeeded());

    // Each task was executed by a REAL engine turn.
    let task_turns: Vec<_> = run
        .turns
        .iter()
        .filter(|t| t.label.starts_with("task:"))
        .collect();
    assert_eq!(
        task_turns.len(),
        2,
        "one real engine turn per task: {:?}",
        run.turns
    );
    assert!(task_turns.iter().all(|t| t.ok && t.provider == "offline"));
    assert!(task_turns.iter().all(|t| t.text.contains("offline mode")));
}

// ============================ IDN-03 — per-Run workload credential ============================

#[tokio::test(flavor = "multi_thread")]
async fn wire2_idn_03_per_run_credential_minted_and_used() {
    let identity = RunIdentitySpec::new(
        "agent",
        "idn-prog",
        "prog-idn",
        DataClass::Internal,
        "u-alice",
    )
    .with_department("payments-eng");

    // GAP-FIX planner-assurance-revision (item 1) — a genuinely substantive, on-goal artifact is
    // required for the bundled RubricJudge to pass; see `FixedTextProvider`'s doc comment.
    let engine = engine_with_fixed_text(
        "completed the single module program successfully: assessed dependencies and executed the \
         work, with boundary tests covering empty and negative edge cases.",
    );
    let run = run_program(
        engine,
        identity,
        "a single-module program",
        vec![NodeDecl::new("mod-only", NodeClass::MigrationRun)],
        SupervisorConfig::default(),
        None,
    )
    .await
    .expect("program run");

    // A real per-Run credential was minted (not a bare role name / service account).
    let cred = &run.credential;
    assert_eq!(cred.run_id, "prog-idn");
    assert_eq!(cred.def_ref(), "def:agent/idn-prog@v1");
    assert_eq!(cred.obo_user_id, "u-alice");
    assert_eq!(cred.key_id, "runtimed-key-v1");
    assert!(
        cred.uri().contains("prog-idn"),
        "AWC uri carries the run: {}",
        cred.uri()
    );
    assert!(
        cred.is_valid_at(LogicalTime(1)),
        "the minted credential is valid at mint time"
    );

    // ...and it was USED: every executor turn ran under a policy principal derived from the
    // credential's OBO identity (IDN-03 threading), and the §14 actor of record recorded for the
    // turn is the credential's FULL COMPOSITE label — never the bare OBO user id a service-account
    // attribution would use (GAP-FIX identity-payments: `TurnObservation.actor` previously stamped
    // the bare `principal.user_id`; a regulator's "who did this?" must be answerable from this one
    // field alone — see `ainxt-identity/tests/r12_actor_of_record_served.rs`).
    assert!(
        !run.turns.is_empty(),
        "at least one module turn must have run"
    );
    let expected_actor = cred.actor_label();
    assert!(
        run.turns.iter().all(|t| t.actor == expected_actor),
        "every turn's actor of record must be the credential's full composite label {:?}, got: {:?}",
        expected_actor,
        run.turns
    );
    assert!(
        run.turns.iter().all(|t| t.actor.contains("obo=u-alice")),
        "the composite actor must still carry the OBO human: {:?}",
        run.turns
    );
    assert!(
        run.turns.iter().all(|t| t.actor != "u-alice"),
        "the actor of record must never collapse to the bare OBO user id: {:?}",
        run.turns
    );
    assert_eq!(run.report.outcome, ProgramOutcome::Completed);
}

// ============================ FI-02 — detector signal arms a statutory clock ============================

#[tokio::test(flavor = "multi_thread")]
async fn wire2_fi_02_regulated_egress_arms_incident_clock() {
    let pr = assemble_program(&offline_config()).unwrap();
    let register = Arc::new(Mutex::new(IncidentRegister::new(
        ArmingPolicy::india_regulatory_default(),
    )));

    // A REGULATED-payment run whose module goal carries a PAN-like digit run: the always-on
    // compliance gate redacts it (a real detector signal), which must arm a statutory clock.
    let identity = RunIdentitySpec::new(
        "agent",
        "fi02-prog",
        "prog-fi02",
        DataClass::RegulatedPayment,
        "u-fi02",
    );

    let run = pr
        .run_program(
            identity,
            "reconcile settlement for PAN 4111111111111111 today",
            vec![NodeDecl::new("mod-settle", NodeClass::MigrationRun)],
            SupervisorConfig::default(),
            Some(register.clone()),
        )
        .await
        .expect("program run");

    // The turn genuinely triggered a compliance redaction (the detector signal).
    assert!(
        run.turns.iter().any(|t| t.redactions > 0),
        "the regulated turn must have produced a compliance redaction: {:?}",
        run.turns
    );

    // FI-02: the typed compliance-egress detector adapter armed a statutory incident.
    let reg = register.lock().unwrap();
    assert!(
        reg.incidents().count() >= 1,
        "a statutory incident must be opened"
    );
    let incident = reg
        .incidents()
        .find(|i| i.class == IncidentClass::PersonalDataBreach)
        .expect("a compliance-egress signal opens a personal-data-breach incident");
    // Its DPDP statutory clocks are armed from the control-plane arming policy.
    assert!(
        incident.clock(StatutoryClockKind::DpdpBoard).is_some(),
        "the incident must arm its DPDP board clock"
    );
    // The tamper-evident register stays hash-chain valid after arming.
    assert!(reg.verify().is_ok());
}

// ============================ LOOP-13 — learning record routed to a sink ============================

#[tokio::test(flavor = "multi_thread")]
async fn wire2_loop_13_team_learning_record_routed_to_sink() {
    let pr = assemble_program(&offline_config()).unwrap();
    let sink = Arc::new(InMemoryLearningSink::new());

    let identity = RunIdentitySpec::new(
        "agent",
        "loop13-team",
        "team-loop13",
        DataClass::Internal,
        "u-loop13",
    );

    let run = pr
        .run_team(
            identity,
            chain_graph(),
            team(),
            "ship it",
            BTreeSet::new(),
            ThreeTierConfig::default(),
            Some(sink.clone() as Arc<dyn LearningSink>),
            None,
        )
        .await
        .expect("team run");
    assert_eq!(run.report.outcome, TeamOutcome::Complete);

    // LOOP-13: exactly one terminal Learning Record was routed to the sink, carrying the run outcome.
    assert_eq!(sink.len(), 1, "one terminal learning record must be routed");
    let records = sink.records();
    let learning = &records[0];
    assert!(learning.all_succeeded, "the happy-path run succeeded");
    assert!(learning.succeeded.contains(&TaskId::from("impl")));
    assert!(learning.succeeded.contains(&TaskId::from("review")));
}
