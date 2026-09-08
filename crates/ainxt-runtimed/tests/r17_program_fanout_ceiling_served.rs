// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! r17 (loop-teams-longhorizon, gap 5) — `ainxt_planner::driver::drive_program_verified_fanout` and
//! `ainxt_planner::qos::{ElasticFanoutPolicy, FleetCapacity, WorkloadClass}` were fully built and
//! unit-tested (`ainxt-planner/tests/r11_longhorizon_verified_path.rs`,
//! `ainxt-planner/tests/r12_gpu_qos_elastic_fanout.rs`) but had ZERO callers from the served
//! composition root: `drive_served_program_blocking` always called the SEQUENTIAL
//! `drive_program_verified` (wave ceiling 1), so independent branches of a served long-horizon
//! Program's module graph serialized regardless of how many were mutually independent — exactly the
//! "parallel tracks do not serialize" claim `LONG_HORIZON_PROGRAMS.md` §7 makes but the served path
//! never delivered.
//!
//! This proves the wiring through the REAL served entrypoint (`drive_served_program_governed`, the
//! function `ProgramSurface::handle_turn` itself calls): three mutually INDEPENDENT nodes, every
//! attempt forced non-Complete via the existing `ProgramProofSeams::with_failing_module_judge` seam
//! (deterministic — no engine-content trickery needed), so each node retries up to
//! `VERIFY_ATTEMPT_CAP` (2) times before being durably quarantined. `Program::actionable_wave` admits
//! nodes in DECLARATION order (deterministic), so:
//!
//! * `fleet_slots: None` (today's default, sequential / wave ceiling 1) — the first-declared node
//!   monopolizes every wave until it exhausts its attempts and is quarantined; ONLY THEN do its
//!   independent siblings get a turn. The turn sequence GROUPS by node: n1,n1,n2,n2,n3,n3.
//! * `fleet_slots: Some(10)` (fan-out enabled, plenty of fleet capacity for 3 nodes) — all three nodes
//!   are admitted into the SAME wave every round, so their turns INTERLEAVE: n1,n2,n3,n1,n2,n3.
//!
//! Both runs produce the identical terminal outcome (every node quarantined, `CappedPartial`) — the
//! wiring changes *scheduling fairness across independent branches*, never correctness. The live GPU
//! fleet (real concurrent dispatch) stays infra-gated (`needs_hot_wiring`); what is proven reachable
//! here is the real, computed *admission-width decision* `ElasticFanoutPolicy` makes.

use ainxt_planner::program::{NodeClass, NodeDecl, ProgramOutcome};
use ainxt_runtime::CancelToken;
use ainxt_runtimed::{
    assemble_program, assemble_program_surface, drive_served_program_governed, load_layered,
    LoadedConfig, ProgramProofSeams, RunIdentitySpec, ServedProgramGovernance, SodApprover,
};
use ainxt_types::DataClass;

fn offline() -> LoadedConfig {
    load_layered(&[("x", "version = 1")]).unwrap()
}

fn identity(run: &str) -> RunIdentitySpec {
    RunIdentitySpec::new("agent", "r17-fanout", run, DataClass::Internal, "u-alice")
}

/// Three mutually independent nodes — no `depends_on` between any of them.
fn independent_nodes() -> Vec<NodeDecl> {
    vec![
        NodeDecl::new("n1", NodeClass::MigrationRun),
        NodeDecl::new("n2", NodeClass::MigrationRun),
        NodeDecl::new("n3", NodeClass::MigrationRun),
    ]
}

/// The `module:<id>` labels off a run's turns, in order.
fn turn_labels(turns: &[ainxt_runtimed::TurnObservation]) -> Vec<String> {
    turns.iter().map(|t| t.label.clone()).collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn r17_sequential_default_starves_siblings_until_the_first_node_is_quarantined() {
    let pr = assemble_program(&offline()).expect("assemble program runtime");
    let run = drive_served_program_governed(
        pr.engine(),
        identity("sequential"),
        "migrate three independent shards",
        independent_nodes(),
        None,
        None,
        None,
        SodApprover::Distinct,
        CancelToken::new(),
        ProgramProofSeams::with_failing_module_judge(),
        // fleet_slots: None (the default) -> drive_served_program_blocking computes fan_out_ceiling=1.
        ServedProgramGovernance::served_default(),
    )
    .await
    .expect("every-node-quarantined is a clean terminal outcome, never an error");

    assert_eq!(
        run.outcome,
        ProgramOutcome::CappedPartial,
        "a permanently-failing judge must quarantine every node, never fabricate Completed"
    );
    assert_eq!(
        run.program.state().committed_node_ids().len(),
        0,
        "nothing ever passes the forced-failing judge, so nothing commits"
    );

    let labels = turn_labels(&run.turns);
    assert_eq!(
        labels,
        vec![
            "module:n1",
            "module:n1",
            "module:n2",
            "module:n2",
            "module:n3",
            "module:n3",
        ],
        "sequential (wave ceiling 1): n1 monopolizes both its attempts before n2 gets a single \
         turn, and n2 before n3 — independent siblings are STARVED, not run together: {labels:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn r17_configured_fleet_slots_admits_independent_siblings_in_the_same_wave() {
    let pr = assemble_program(&offline()).expect("assemble program runtime");
    let run = drive_served_program_governed(
        pr.engine(),
        identity("fanout"),
        "migrate three independent shards",
        independent_nodes(),
        None,
        None,
        None,
        SodApprover::Distinct,
        CancelToken::new(),
        ProgramProofSeams::with_failing_module_judge(),
        // fleet_slots: Some(10) -> ElasticFanoutPolicy(Batch, 10 free slots) admits all 3 at once.
        ServedProgramGovernance::served_default().with_fleet_slots(Some(10)),
    )
    .await
    .expect("every-node-quarantined is a clean terminal outcome, never an error");

    // Same terminal correctness as the sequential run above — the fix changes fairness, not outcome.
    assert_eq!(run.outcome, ProgramOutcome::CappedPartial);
    assert_eq!(run.program.state().committed_node_ids().len(), 0);

    let labels = turn_labels(&run.turns);
    assert_eq!(
        labels,
        vec![
            "module:n1", "module:n2", "module:n3", "module:n1", "module:n2", "module:n3",
        ],
        "fan-out enabled (wave ceiling >= 3): all three independent nodes are admitted into the SAME \
         wave every round, so their turns INTERLEAVE round-by-round, not grouped per node: {labels:?}"
    );
}

/// `assemble_program_surface` (the daemon's `--surface program` composition) must actually thread the
/// deployment's `[limits] program_fan_out_fleet_slots` into the served governance, not silently ignore
/// it — mirrors the existing `loop_12_13_team_surface_wires_cost_ceiling_and_learning_sink_from_config`
/// pattern for the analogous Team-surface config wire.
#[test]
fn r17_program_surface_wires_fleet_slots_from_config() {
    let configured = load_layered(&[(
        "t",
        "version = 1\n[limits]\nprogram_fan_out_fleet_slots = 6\n",
    )])
    .unwrap();
    assert_eq!(
        configured.runtime.limits.program_fan_out_fleet_slots,
        Some(6),
        "sanity: the config layer must parse the new [limits] field"
    );
    let assembled = assemble_program_surface(&configured, "program").unwrap();
    let joined = assembled.report.join("\n");
    assert!(
        joined.contains("fleet_slots=6"),
        "the served program surface must report the config-driven fleet capacity it actually \
         installed (gap 5), not silently ignore it: {joined}"
    );

    // Regression guard: no fleet slots configured -> sequential, exactly the pre-fix default.
    let unconfigured = load_layered(&[("u", "version = 1")]).unwrap();
    let assembled_unconfigured = assemble_program_surface(&unconfigured, "program").unwrap();
    assert!(
        assembled_unconfigured
            .report
            .iter()
            .any(|r| r.contains("fleet_slots=None")),
        "an unconfigured deployment must stay sequential (no accidental default fan-out): {:?}",
        assembled_unconfigured.report
    );
}
