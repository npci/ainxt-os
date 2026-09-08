// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX identity-payments (ADR-022 §13/§22 #3 — "transparency-log orphaned").
//!
//! `r13_program_transparency_log.rs` / `r13_team_transparency_log.rs` proved the transparency-log
//! *mechanism* end-to-end, but did so by hand-building a `ProgramSurface`/`TeamSurface` and calling
//! `.with_transparency_log(...)` directly — NOT by exercising `assemble_program_surface` /
//! `assemble_team_surface`, the actual composition roots `assemble_selected("program"|"team", ..)`
//! calls on the served daemon's `--surface program`/`--surface team` path. Before this fix, neither
//! composition function ever called `.with_transparency_log(...)`, so a REAL served daemon's Program/
//! Team Runs never appended to any transparency log at all — the mechanism was fully built, fully
//! tested, and completely unreached from the one path that matters (the "orphaned" gap).
//!
//! This test drives the SAME composition functions the daemon uses
//! (`assemble_program_surface_with_transparency` / `assemble_team_surface_with_transparency` — the
//! exact internals `assemble_program_surface`/`assemble_team_surface` now delegate to) end-to-end over
//! a real chat turn, and proves the Run's credential issuance lands in the SAME log the composition
//! root wires into the surface, with an externally-verifiable inclusion proof (§22 #3).

use ainxt_client::{Client, ClientConfig};
use ainxt_identity::transparency::Sha256Hasher;
use ainxt_runtimed::{
    assemble_program_surface_with_transparency, assemble_team_surface_with_transparency,
    load_layered,
};
use ainxt_types::Principal;

#[tokio::test(flavor = "multi_thread")]
async fn gap_idn_program_composition_root_wires_a_live_transparency_log() {
    let loaded = load_layered(&[("x", "version = 1")]).unwrap();
    let (assembled, log) = assemble_program_surface_with_transparency(&loaded, "program")
        .expect("composition succeeds");

    // The composition root's own report documents the wiring (an operator/auditor reading the boot
    // report sees this is live, not silent).
    assert!(
        assembled
            .report
            .iter()
            .any(|line| line
                .contains("issuance transparency log LIVE on the served program surface")),
        "boot report must document the live transparency-log wiring: {:?}",
        assembled.report
    );
    assert!(
        log.lock().unwrap().is_empty(),
        "sanity: the log starts empty"
    );

    let client = Client::in_process(
        assembled.manager,
        Principal::user("dev", &["chat.send"]),
        ClientConfig::default(),
    );
    let out = client
        .chat("s-idn16", "t-idn16", "migrate the legacy settlement module")
        .unwrap()
        .collect()
        .await;
    assert!(out.completed, "the program turn must complete");

    // The Run's credential issuance landed in the SAME log object the composition root wired in —
    // proving `assemble_program_surface_with_transparency` (and therefore the daemon's real
    // `--surface program` path) is a live caller, not just the hand-built test surface.
    let log = log.lock().unwrap();
    assert_eq!(
        log.len(),
        1,
        "exactly one issuance must be logged for one Run"
    );
    let idx = log
        .index_of_run("s-idn16:t-idn16")
        .expect("the Run's own run_id must be findable in the log");
    let root = log.root();
    let proof = log
        .inclusion_proof(idx)
        .expect("an inclusion proof must exist for a logged entry");
    assert!(
        proof.verify(&Sha256Hasher, &root),
        "the inclusion proof must verify against the log's current root (external-auditor scenario)"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn gap_idn_team_composition_root_wires_a_live_transparency_log() {
    let loaded = load_layered(&[("x", "version = 1")]).unwrap();
    let (assembled, log) =
        assemble_team_surface_with_transparency(&loaded, "team").expect("composition succeeds");

    assert!(
        assembled
            .report
            .iter()
            .any(|line| line.contains("issuance transparency log LIVE on the served team surface")),
        "boot report must document the live transparency-log wiring: {:?}",
        assembled.report
    );
    assert!(
        log.lock().unwrap().is_empty(),
        "sanity: the log starts empty"
    );

    let client = Client::in_process(
        assembled.manager,
        Principal::user("dev", &["chat.send"]),
        ClientConfig::default(),
    );
    let out = client
        .chat(
            "s-idn16-team",
            "t-idn16-team",
            "review the payment reconciliation report",
        )
        .unwrap()
        .collect()
        .await;
    assert!(out.completed, "the team turn must complete");

    let log = log.lock().unwrap();
    assert!(
        !log.is_empty(),
        "at least one Run's issuance must be logged for the team turn"
    );
}
