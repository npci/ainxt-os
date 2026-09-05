// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-12 — **the signed Event-Log store is DURABLE** (`CODE_REVIEW_PIPELINE.md` §9: the Event Log
//! is "durable, incrementally-projected"). The gap: the only [`JournalStore`] was
//! [`ainxt_pipeline::InMemoryJournalStore`] — process memory, lost on exit, so a regulator's
//! `pipelineHistory(commit_sha)` two years later would find nothing. Round-12 adds the crash-atomic
//! [`FsJournalStore`]: a sealed, hash-chained trail persists to disk and survives a process restart,
//! and its signature still verifies (tamper-evidence survives cold storage).
//!
//! Fail-before: `FsJournalStore` did not exist — there was no durable journal store at all. Real
//! Postgres/WORM behind the same trait is infra_gated; this proves the durability + signature-survival
//! contract offline through the real seam.

use ainxt_pipeline::journal::PipelineEvent;
use ainxt_pipeline::stage::StageVerdict;
use ainxt_pipeline::{FsJournalStore, HmacSigner, Journal, JournalStore, Stage};

fn scratch(tag: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("ainxt-r12-{tag}-{}-{nanos}", std::process::id()))
}

fn seeded(edit_id: &str) -> Journal {
    let mut j = Journal::new(edit_id);
    j.append(
        1,
        PipelineEvent::PipelineStarted {
            edit_id: edit_id.into(),
            risk_tier: "moderate".into(),
            blast_radius: 3,
            edit_engine_rung: "ast".into(),
        },
    );
    j.append(
        2,
        PipelineEvent::StageResult {
            stage: Stage::Compile,
            verdict: StageVerdict::Pass,
            deterministic: true,
        },
    );
    j.append(
        3,
        PipelineEvent::PipelineOutcome {
            outcome: "complete".into(),
            confidence_score: 92,
        },
    );
    j.set_commit_sha("commit-sha-r12");
    j
}

#[test]
fn r12_signed_journal_survives_a_process_restart_via_fs_store() {
    let root = scratch("journal");
    let signer = HmacSigner::new(b"r12-key".to_vec());

    // ── "Process instance 1": seal + persist a journal, then drop everything (a restart). ──
    let seal = {
        let journal = seeded("edit-r12");
        let seal = journal.seal(&signer);
        let mut store = FsJournalStore::open(&root).expect("open durable store");
        store.put(&journal, seal.clone());
        seal
        // store + journal dropped here — nothing left in memory.
    };
    // It is really on disk.
    assert!(
        std::fs::read_dir(&root).unwrap().count() >= 1,
        "the sealed journal must be persisted to disk"
    );

    // ── "Process instance 2": a fresh store at the same root answers the regulator's forensic query. ──
    let reopened = FsJournalStore::open(&root).expect("reopen durable store");

    // pipelineHistory(commit_sha) reconstructs the full hash-chained trail + its seal from cold storage.
    let (records, back_seal) = reopened
        .pipeline_history("commit-sha-r12")
        .expect("committed edit must be queryable by its commit SHA after restart");
    assert_eq!(records.len(), 3, "the whole trail survived");
    assert_eq!(
        records[0].prev_hash,
        "0".repeat(64),
        "genesis prev_hash survived"
    );

    // The signature survives the round-trip, and a rebuilt Journal still verifies against it — so
    // tamper-evidence is intact after the restart.
    let rebuilt = Journal::from_records(
        "edit-r12",
        Some("commit-sha-r12".to_string()),
        records.clone(),
    );
    assert!(
        rebuilt.verify_seal(&signer, &back_seal),
        "the durable, restored journal must still verify against its signed seal"
    );
    assert_eq!(
        back_seal, seal,
        "the persisted seal is byte-identical after restart"
    );

    // by_edit_id reaches the same trail directly.
    let (by_id, _) = reopened
        .by_edit_id("edit-r12")
        .expect("edit id is queryable");
    assert_eq!(by_id, records);

    // A tampered restore is caught: flip a verdict and the seal no longer verifies.
    let mut tampered = records;
    tampered[1].event = PipelineEvent::StageResult {
        stage: Stage::Compile,
        verdict: StageVerdict::Fail {
            detail: "hidden".into(),
        },
        deterministic: true,
    };
    let tampered_journal =
        Journal::from_records("edit-r12", Some("commit-sha-r12".to_string()), tampered);
    assert!(
        !tampered_journal.verify_seal(&signer, &back_seal),
        "a post-restart tamper must break the signature"
    );

    let _ = std::fs::remove_dir_all(&root);
}
