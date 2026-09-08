// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R21 — GAP-AUDIT loop-teams-longhorizon (gap 2), independent re-audit.
//!
//! `ainxt_teams::flywheel::generate_eval_cases` / `plan_template_priors` / `role_spec_tuning` (LOOP §10's
//! flywheel DOWNSTREAM consumers) were fully implemented and unit-tested, and
//! `InMemoryLearningSink::flywheel_eval_cases`/`flywheel_template_priors`/`flywheel_role_tuning` already
//! passed accumulated records straight through to them — but `assemble_team_surface_with_transparency`
//! (the function `assemble_selected("team", ..)` and therefore the daemon's `--surface team` dispatch
//! actually calls, via `assemble_team_surface`) wired only the PRODUCER side
//! (`LearningRecord -> InMemoryLearningSink`). Nothing on any served or daemon path ever called the
//! three curators: the passthroughs' own proving test (`r_flywheel_sink_accessors.rs`) demonstrated the
//! curation only by hand-building an `InMemoryLearningSink` and calling `.record()` on it directly,
//! never through a real served Team run.
//!
//! This drives the REAL composition root (`assemble_team_surface_with_flywheel`, which delegates to the
//! SAME `build_team_surface_parts` `assemble_team_surface` — and therefore `assemble_selected("team",
//! ..)` — uses) over TWO real served Team turns via `Client::in_process`, then calls
//! `FlywheelCurationSweep::tick` — the exact pure entrypoint the daemon's cadence
//! (`spawn_flywheel_sweep`) calls — and proves the curated output is derived from the REAL
//! `LearningRecord`s the served turns actually produced (real task/role ids from the served graph, a
//! record count matching the number of turns driven), not a fabricated or hand-seeded batch.
//!
//! A second, focused test proves `spawn_flywheel_sweep` itself is a genuine recurring cadence (not a
//! single callable pass with an unwired timer): a short period ticks a bare `FlywheelCurationSweep`
//! multiple times with no caller polling it.

use std::collections::BTreeMap;
use std::sync::Arc;

use ainxt_client::{Client, ClientConfig};
use ainxt_runtimed::{
    assemble_team_surface_with_flywheel, load_layered, spawn_flywheel_sweep, FlywheelCurationSweep,
    InMemoryLearningSink,
};
use ainxt_teams::{ModelTier, RoleId, TaskId};
use ainxt_types::Principal;

fn offline() -> ainxt_runtimed::LoadedConfig {
    load_layered(&[("x", "version = 1")]).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn r21_composition_root_flywheel_sweep_curates_real_served_team_records() {
    // The EXACT composition-root function `assemble_selected("team", ..)` reaches (via
    // `assemble_team_surface` -> `build_team_surface_parts`) — not a hand-built `TeamSurface` /
    // `InMemoryLearningSink`.
    let (assembled, _transparency_log, flywheel) =
        assemble_team_surface_with_flywheel(&offline(), "team").expect("composition succeeds");

    // Before any served turn, the sweep has curated zero records — never a fabricated non-empty
    // default (the concrete count of prior ticks is not asserted here: `build_team_surface_parts`
    // spawns the real cadence in the background, and `tokio::time::interval` fires its first tick
    // immediately, so a background tick may race with this check on a multi-thread runtime; that
    // recurring-cadence behavior is proven deterministically and in isolation by
    // `r21_spawn_flywheel_sweep_is_a_real_recurring_cadence` below).
    assert_eq!(flywheel.latest().records_curated, 0);

    let client = Client::in_process(
        assembled.manager,
        Principal::user("dev", &["chat.send"]),
        ClientConfig::default(),
    );

    // Drive TWO real served Team turns — each terminal run's LearningRecord lands in the SAME sink
    // `flywheel` reads.
    let out1 = client
        .chat(
            "s-r21-a",
            "t-r21-a",
            "review the payment reconciliation report",
        )
        .unwrap()
        .collect()
        .await;
    assert!(out1.completed, "the first served team turn must complete");
    let out2 = client
        .chat("s-r21-b", "t-r21-b", "review the settlement ledger export")
        .unwrap()
        .collect()
        .await;
    assert!(out2.completed, "the second served team turn must complete");

    // The composition-root entrypoint a daemon cadence calls (`spawn_flywheel_sweep` invokes the SAME
    // method on the SAME schedule).
    let result = flywheel.tick();
    assert!(
        flywheel.sweeps_run() >= 1,
        "tick() must advance the sweep counter"
    );
    assert_eq!(
        result.records_curated, 2,
        "the sweep must have curated exactly the two real served turns' LearningRecords, not a \
         fabricated or hand-seeded count: {result:?}"
    );

    // The served graph's REAL task/role ids (compose_served_team's canonical hierarchy) must appear in
    // the curated template priors / role tuning — proving the curators ran over genuine served-run
    // data, not an empty or synthetic batch.
    for task in ["architect", "code", "review", "test"] {
        let tid = TaskId::from(task);
        assert!(
            result.template_priors.contains_key(&tid),
            "template_priors must include the real served task '{task}' curated from the actual \
             LearningRecords: {:?}",
            result.template_priors.keys().collect::<Vec<_>>()
        );
        let prior = &result.template_priors[&tid];
        assert_eq!(
            prior.runs, 2,
            "task '{task}' ran in both served turns: {prior:?}"
        );
    }
    for role in ["architect", "coder", "reviewer", "tester"] {
        let rid = RoleId::from(role);
        assert!(
            result.role_tuning.contains_key(&rid),
            "role_tuning must include the real served role '{role}' curated from the actual \
             LearningRecords: {:?}",
            result.role_tuning.keys().collect::<Vec<_>>()
        );
        assert_eq!(result.role_tuning[&rid].runs, 2);
    }

    // `latest()` reflects the same tick just run (read-model consistency).
    assert_eq!(flywheel.latest().records_curated, 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn r21_spawn_flywheel_sweep_is_a_real_recurring_cadence() {
    // A bare sink + empty maps is enough to prove the CADENCE mechanics (interval -> repeated tick),
    // independent of the served composition root proven above.
    let sink = Arc::new(InMemoryLearningSink::new());
    let sweep = Arc::new(FlywheelCurationSweep::new(
        sink,
        BTreeMap::<TaskId, RoleId>::new(),
        BTreeMap::<RoleId, ModelTier>::new(),
    ));
    assert_eq!(sweep.sweeps_run(), 0);

    let handle = spawn_flywheel_sweep(sweep.clone(), std::time::Duration::from_millis(20));

    // No caller ever calls `.tick()` directly here — only the spawned cadence does. Poll briefly for at
    // least 3 ticks to have landed on their own, proving a genuine recurring loop, not a single pass.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while sweep.sweeps_run() < 3 && std::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(
        sweep.sweeps_run() >= 3,
        "spawn_flywheel_sweep must actually tick repeatedly on its own cadence, not once: sweeps_run={}",
        sweep.sweeps_run()
    );

    handle.abort();
}
