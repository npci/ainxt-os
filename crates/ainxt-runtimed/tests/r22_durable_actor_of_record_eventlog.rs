// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R22 — GAP-FIX identity-payments (ADR-022 §14, gap6 audit item 3): the real turn-completion path
//! now durably writes the composite §14 [`ActorRecord`] to the Event Log, not just the flattened
//! `actor_label()` string.
//!
//! `ainxt_identity::authority::AgentWorkloadCredential::actor_of_record` was fully implemented and
//! unit-tested (`ainxt-identity/tests/r11_actor_of_record_eventlog.rs`,
//! `tests/r12_actor_of_record_served.rs`) but the REAL production call site —
//! `ainxt-runtimed/src/program_exec.rs`'s durable turn-completion path
//! (`run_program_durable`/`run_program_durable_blocking`) — used only the simpler
//! `credential.actor_label()` string, and that value never reached durable storage at all (it lived
//! only on the in-memory `TurnObservation.actor`, projected into streamed text, never appended to
//! any `ainxt_eventlog::JsonlEventLog`). The durable `ProgramEventSink` stream itself stamped every
//! record with a single hardcoded per-session literal actor (`"runtimed-program-supervisor"`),
//! carrying no per-Run identity information whatsoever.
//!
//! This proves the fix end-to-end through the REAL composition-root entrypoint
//! (`run_program_durable` — the exact function `ProgramSurface`'s `with_durable_dir` branch calls,
//! see `r20_program_durable_composition_root_and_real_verification.rs`): every module turn this Run
//! serves now durably appends the credential's full structured [`ActorRecord`] (JSON-encoded — the
//! Event Log's `actor` field is a plain `&str`, hash-chained into the tamper-evident record) to a
//! DEDICATED `{run_id}::actor_of_record` session, independently readable back and deserializable into
//! the exact same structured type — never re-derived or approximated from the flattened label.

use ainxt_identity::authority::ActorRecord;
use ainxt_planner::program::{NodeClass, NodeDecl};
use ainxt_planner::supervisor::SupervisorConfig;
use ainxt_runtimed::{
    assemble_program, load_layered, run_program_durable, LoadedConfig, RunIdentitySpec,
};
use ainxt_types::DataClass;

fn offline() -> LoadedConfig {
    load_layered(&[("x", "version = 1")]).unwrap()
}

fn tmp_dir(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "ainxt-r22-{tag}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

fn nodes() -> Vec<NodeDecl> {
    vec![
        NodeDecl::new("assess", NodeClass::MigrationRun),
        NodeDecl::new("migrate", NodeClass::MigrationRun).depends_on("assess"),
    ]
}

#[tokio::test(flavor = "multi_thread")]
async fn r22_durable_turn_completion_writes_structured_actor_of_record() {
    let pr = assemble_program(&offline()).expect("assemble program runtime");
    let dir = tmp_dir("actor");
    let run_id = "r22-durable-actor-run";

    // `run_program_durable` is the EXACT function the served composition root's `with_durable_dir`
    // branch calls (program_exec.rs) — not a bespoke test-only driver.
    let run = run_program_durable(
        pr.engine(),
        RunIdentitySpec::new(
            "agent",
            "r22-durable",
            run_id,
            DataClass::Internal,
            "u-alice",
        ),
        "migrate the settlement module",
        nodes(),
        SupervisorConfig::default(),
        None,
        dir.clone(),
    )
    .await
    .expect("the durable run drives to a terminal outcome");

    assert!(
        !run.turns.is_empty(),
        "at least one module turn must have run to prove anything about turn-level actor records"
    );

    // Read back the DEDICATED actor-of-record stream through the real, durable `JsonlEventLog` —
    // never the in-memory `run.turns` the driver already returned (that would only prove the value
    // exists in memory, not that it was durably WRITTEN, the audit's exact complaint).
    use ainxt_eventlog::{EventLog, JsonlEventLog};
    let log = JsonlEventLog::open(&dir).expect("reopen the durable log the run just wrote");
    let actor_session = format!("{run_id}::actor_of_record");
    let records = log.records(&actor_session);

    assert_eq!(
        records.len(),
        run.turns.len(),
        "exactly one durable actor-of-record entry per served module turn: {records:?}"
    );

    let expected: ActorRecord = run.credential.actor_of_record();
    for rec in &records {
        assert_eq!(
            rec.kind, "turn_actor_of_record",
            "the dedicated stream must never be mistaken for the ProgramEvent session"
        );
        let decoded: ActorRecord = serde_json::from_str(&rec.actor)
            .expect("the durable `actor` field must deserialize into the structured ActorRecord");
        assert_eq!(
            decoded, expected,
            "the durably-recorded actor of record must be the credential's REAL composite record, \
             not a re-derived or partial projection"
        );
        // The composite must be genuinely richer than the flattened label: it must never itself
        // collapse to the bare OBO user id.
        assert_ne!(decoded.obo_user_id, decoded.actor_uri);
        assert_eq!(decoded.obo_user_id, "u-alice");
        assert!(decoded.actor_uri.contains(run_id));
    }

    // The chain is tamper-evident like every other session in this log.
    log.verify(&actor_session)
        .expect("the actor-of-record stream is itself a real, verifiable hash chain");

    let _ = std::fs::remove_dir_all(&dir);
}
