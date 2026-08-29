// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-12 (loop-teams-longhorizon gap 2): the hierarchical **3-tier Team loop**
//! (roles / structured handoff / bulkhead isolation / bounded self-heal / fresh-context judge) is now
//! reachable from the LIVE SERVED path — not only from the library API + tests. A served turn over the
//! SessionManager spine (`POST /v1/chat` → `TeamSurface`) drives the real 3-tier loop over the real
//! Engine and returns a terminal team outcome.
//!
//! Fail-before: there was a `ProgramSurface` but no `TeamSurface` and no `--surface team` assembly, so
//! the team loop had no served/daemon reach. Pass-after: `assemble_team_surface` mounts a served
//! `TeamSurface` and a served turn drives the hierarchy (architect → coder → reviewer + independent
//! tester) end-to-end. (The daemon CLI `--surface team` selector → `assemble_team_surface` is the
//! remaining one-line `needs_hot_wiring` in `main`.)

use ainxt_client::{Client, ClientConfig};
use ainxt_runtimed::{assemble_team_surface, compose_served_team, load_layered};
use ainxt_types::{DataClass, Principal};

#[tokio::test(flavor = "multi_thread")]
async fn r12_team_served_reachable() {
    // The canonical served team is a genuine hierarchy + an independent branch (not one task).
    let (graph, team, _seed) = compose_served_team("ship the feature").unwrap();
    assert_eq!(team.len(), 4, "architect/coder/reviewer/tester");
    let order = graph.topological_order().unwrap();
    assert_eq!(order.len(), 4, "four tasks in the served team graph");

    // Assemble the served team surface over the offline engine (the daemon's `--surface team`).
    let loaded = load_layered(&[("t", "version = 1")]).unwrap();
    let assembled = assemble_team_surface(&loaded, "team").unwrap();
    assert!(
        assembled
            .report
            .iter()
            .any(|r| r.contains("Team loop served over the protocol")),
        "the team surface must announce it is served: {:?}",
        assembled.report
    );

    // Drive a served turn through the SAME SessionManager spine chat uses.
    let client = Client::in_process(
        assembled.manager,
        Principal::user("dev", &["chat.send"]).with_clearance(DataClass::Public),
        ClientConfig::default(),
    );
    let out = client
        .chat(
            "team-sess",
            "t1",
            "add input validation to the settlement module",
        )
        .unwrap()
        .collect()
        .await;

    assert!(
        out.completed,
        "the served team turn must complete: {}",
        out.text
    );
    // The served body reports the 3-tier team outcome and shows real per-task engine turns for the
    // hierarchy + the independent branch (proving the loop, not a single call, ran on the served path).
    assert!(
        out.text.contains("team team-sess:t1"),
        "served body must be the team-run projection: {}",
        out.text
    );
    assert!(
        out.text.contains("task:architect")
            && out.text.contains("task:code")
            && out.text.contains("task:review")
            && out.text.contains("task:test"),
        "the served path must run the hierarchical multi-branch team: {}",
        out.text
    );
}

/// LOOP-12/LOOP-13: `assemble_team_surface` — the daemon's `--surface team` composition — must
/// actually thread a deployment's configured cost ceiling and a real terminal-run Learning Record
/// sink onto the served `TeamSurface`, not silently build every served run with
/// `ThreeTierConfig::default()` (unbounded) and no learning sink at all (the audited gap: the
/// underlying mechanisms were implemented and unit-tested in `ainxt-teams`/`program_exec.rs`, but
/// nothing in the composition root ever called `TeamSurface::with_config`/`with_learning_sink`).
#[tokio::test(flavor = "multi_thread")]
async fn loop_12_13_team_surface_wires_cost_ceiling_and_learning_sink_from_config() {
    let loaded = load_layered(&[(
        "t",
        "version = 1\n[limits]\nteam_run_cost_ceiling_dollars_micros = 500000\n",
    )])
    .unwrap();
    assert_eq!(
        loaded.runtime.limits.team_run_cost_ceiling_dollars_micros,
        Some(500_000),
        "sanity: the config layer must parse the new [limits] field"
    );
    let assembled = assemble_team_surface(&loaded, "team").unwrap();
    let joined = assembled.report.join("\n");
    assert!(
        joined.contains("cost ceiling=Some(") && joined.contains("dollars_micros: 500000"),
        "the served team surface must report the config-driven cost ceiling it actually \
         installed (LOOP-12), not silently ignore it: {joined}"
    );
    assert!(
        joined.contains("terminal Learning Records routed to a live sink (LOOP-13)"),
        "the served team surface must report a real Learning Record sink is wired: {joined}"
    );

    // Regression guard: no ceiling configured -> unbounded, exactly the pre-fix default.
    let unbounded = load_layered(&[("u", "version = 1")]).unwrap();
    let assembled_unbounded = assemble_team_surface(&unbounded, "team").unwrap();
    assert!(
        assembled_unbounded
            .report
            .iter()
            .any(|r| r.contains("cost ceiling=None")),
        "an unconfigured deployment must stay unbounded (no accidental default cap): {:?}",
        assembled_unbounded.report
    );
}
