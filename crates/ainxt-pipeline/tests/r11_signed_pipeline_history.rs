// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-11 — the Event Log's three §9 properties the round-10 audit flagged as incomplete:
//! **signed**, **durable**, and queryable by **`pipelineHistory(commit_sha)`**.
//!
//! Before this round the journal was hash-chained (tamper-*evident*) and verifiable, but: it carried
//! no signature (nothing *sealed* the trail), it was not addressable by the commit SHA a regulator
//! actually holds two years on (only by `edit_id`), and there was no durable store seam. This proves:
//! 1. a served edit turn binds a deterministic commit SHA onto its journal on commit;
//! 2. the journal seals under a signer and the seal verifies — and fails if a record is tampered;
//! 3. `JournalStore::pipeline_history(commit_sha)` reconstructs the full ordered trail + its seal.
//!
//! Fail-before: `seal` / `SignedSeal` / `JournalStore` / `pipeline_history` / commit-sha binding did
//! not exist before round-11, so this test would not compile against the prior crate.

use ainxt_pipeline::journal::PipelineEvent;
use ainxt_pipeline::sast::BuiltinScanner;
use ainxt_pipeline::stages::ScriptedTools;
use ainxt_pipeline::{
    Coder, EditEngine, EditRequest, EditResponse, HmacSigner, InMemoryJournalStore, Journal,
    JournalStore, Observation, RiskTier, SelfHealConfig, CAP_EDIT_APPLY,
};
use ainxt_semantic::workspace::MemorySink;
use ainxt_types::Principal;
use std::sync::Arc;

struct NoOpCoder;
impl Coder for NoOpCoder {
    fn fix(&self, _r: u8, files: &[(String, String)], _o: &Observation) -> Vec<(String, String)> {
        files.to_vec()
    }
}

#[test]
fn r11_served_commit_is_signed_durable_and_queryable_by_commit_sha() {
    let eng = EditEngine::new(
        Arc::new(NoOpCoder),
        Arc::new(ScriptedTools::default()),
        Arc::new(BuiltinScanner),
    );
    let req = EditRequest {
        edit_id: "edit-777".into(),
        original_files: vec![("pay.rs".into(), "fn f() -> i32 { 1 }\n".into())],
        applied_files: vec![("pay.rs".into(), "fn f() -> i32 { 2 }\n".into())],
        config: SelfHealConfig {
            tier: RiskTier::Local,
            max_rounds: 3,
            ..Default::default()
        },
    };
    let dev = Principal::user("dev", &[CAP_EDIT_APPLY]);
    let mut sink = MemorySink::new();
    let mut journal = Journal::new("edit-777");

    let res = eng
        .run_turn_for(&dev, req, &mut sink, &mut journal)
        .expect("authorized");
    assert!(matches!(res, EditResponse::Committed { .. }));

    // (1) The commit bound a deterministic commit SHA onto the journal.
    let sha = journal
        .commit_sha()
        .expect("a committed turn must bind a commit sha")
        .to_string();
    assert_eq!(sha.len(), 64, "commit sha is a SHA-256 hex digest");
    // The journal actually recorded the pipeline outcome (the trail is non-trivial).
    assert!(journal
        .records()
        .iter()
        .any(|r| matches!(&r.event, PipelineEvent::PipelineOutcome { .. })));

    // (2) Seal it under a signer; the seal verifies against the intact journal.
    let signer = HmacSigner::new(b"example-evidentiary-key".to_vec());
    let seal = journal.seal(&signer);
    assert!(journal.verify_seal(&signer, &seal));
    assert_eq!(seal.commit_sha.as_deref(), Some(sha.as_str()));

    // (3) Persist to the durable store and query by COMMIT SHA — the regulator's forensic key.
    let mut store = InMemoryJournalStore::new();
    store.put(&journal, seal.clone());

    let (records, stored_seal) = store
        .pipeline_history(&sha)
        .expect("pipeline_history(commit_sha) must find the committed edit");
    assert_eq!(records, journal.records());
    assert_eq!(stored_seal, seal);

    // A regulator rebuilds the trail from the stored records alone and re-verifies chain + signature.
    let reconstructed = Journal::from_records("edit-777", Some(sha.clone()), records);
    assert_eq!(reconstructed.verify(), Ok(()));
    assert!(reconstructed.verify_seal(&signer, &stored_seal));

    // An unknown commit sha has no history (no false positives).
    assert!(store.pipeline_history("deadbeef").is_none());
}

#[test]
fn r11_tampering_a_sealed_record_fails_verification() {
    let signer = HmacSigner::new(b"k".to_vec());
    let mut j = Journal::new("edit-x");
    j.append(
        1,
        PipelineEvent::PipelineStarted {
            edit_id: "edit-x".into(),
            risk_tier: "high_risk".into(),
            blast_radius: 3,
            edit_engine_rung: "ast".into(),
        },
    );
    j.append(
        2,
        PipelineEvent::PipelineOutcome {
            outcome: "complete".into(),
            confidence_score: 95,
        },
    );
    j.set_commit_sha("abc123");
    let seal = j.seal(&signer);
    assert!(j.verify_seal(&signer, &seal));

    // Silently rewrite the outcome to a higher score — the classic after-the-fact forgery. The seal
    // (over the chain head) no longer verifies: the hash chain broke and the head drifted.
    let mut tampered = j.records().to_vec();
    tampered[1].event = PipelineEvent::PipelineOutcome {
        outcome: "complete".into(),
        confidence_score: 100,
    };
    let forged = Journal::from_records("edit-x", Some("abc123".into()), tampered);
    assert!(
        !forged.verify_seal(&signer, &seal),
        "a tampered record must fail the signed-seal check"
    );

    // A wrong key also fails — the signature is genuinely key-dependent, not a bare hash.
    let wrong = HmacSigner::new(b"not-the-key".to_vec());
    assert!(!j.verify_seal(&wrong, &seal));
}
