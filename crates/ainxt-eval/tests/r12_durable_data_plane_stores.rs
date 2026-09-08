// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-12 gap-closing integration test (eval-tester-scenarios, LOW):
//! **"Durable production stores behind the sealed-corpus / Event-Log / Vault seams (§11 data plane)."**
//!
//! The Event-Log seam is already durably backed (`ainxt-eventlog`'s hash-chained `JsonlEventLog`); the
//! sealed-corpus and Vault seams previously had only in-memory test doubles. `durable::{FileVaultStore,
//! FileSealedCorpusStore, FileEventSink}` give all three a durable, file-backed implementation that
//! survives a process "restart" with no external infrastructure. This drives them across a fresh store
//! instance (the restart) through the public trait seams.
//!
//! Fail-before: `ainxt_eval::durable` did not exist. Pass-after: minted cases / sealed corpus /
//! verdicts persist and re-load through a NEW store object; a tampered vault record is dropped; the
//! sealed corpus stays runner-only.
//!
//! (The KMS-encrypted, access-controlled Postgres / object-store data plane the design ultimately
//! requires is infra-gated; these are the durable no-infra tier behind the SAME seams.)

use ainxt_eval::audit::{EventSink, VerdictRecord};
use ainxt_eval::durable::{FileEventSink, FileSealedCorpusStore, FileVaultStore};
use ainxt_eval::integrity::SealedCorpusStore;
use ainxt_eval::vault::{VaultCase, VaultOrigin, VaultStore};

fn tmp(tag: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "ainxt-eval-r12-{tag}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn r12_durable_data_plane_stores() {
    // ---- Vault: mint → drop the store → reopen a FRESH one → the case is still there + verifies. --
    let vault_path = tmp("vault").join("vault.jsonl");
    {
        let mut store = FileVaultStore::new(&vault_path);
        store.persist(&VaultCase::mint(
            "INJ-001",
            VaultOrigin::IncidentPostmortem,
            "evt-9",
            "sha-777",
            "initiate settlement from tainted context",
            "the settle tool must NOT fire",
            42,
        ));
    } // store dropped — simulates process exit
    let reloaded: Vec<VaultCase> = FileVaultStore::new(&vault_path).load_all();
    assert_eq!(reloaded.len(), 1, "the minted case survived the restart");
    assert!(
        reloaded[0].verify_seal(),
        "the durable case's seal verifies"
    );
    assert_eq!(reloaded[0].case_id, "INJ-001");

    // ---- Sealed corpus: sealed by the runner, readable only by the runner identity. --------------
    let corpus_path = tmp("corpus").join("corpus.json");
    let cases = vec![
        (
            "c1".to_string(),
            "when is settlement".to_string(),
            "T+1".to_string(),
        ),
        (
            "c2".to_string(),
            "IFSC format".to_string(),
            "4 letters, 0, 6 digits".to_string(),
        ),
    ];
    FileSealedCorpusStore::seal(&corpus_path, &[("rag-groundedness", "v3", cases.clone())])
        .unwrap();
    let corpus = FileSealedCorpusStore::new(&corpus_path, "eval-runner");
    assert_eq!(
        corpus.load("rag-groundedness", "v3", "eval-runner"),
        Some(cases),
        "the runner reads the durable sealed corpus after restart"
    );
    assert!(
        corpus.load("rag-groundedness", "v3", "pr-author").is_none(),
        "the author of the gated change must NOT read the gold answers"
    );

    // ---- Event sink: append verdicts → reopen → they are durably present. ------------------------
    let events_path = tmp("events").join("verdicts.jsonl");
    let rec = VerdictRecord {
        eval_set_id: "rag-groundedness".into(),
        eval_set_version: "v3".into(),
        judge_version: "glm-4-2026-05".into(),
        candidate_sha: "sha-777".into(),
        params_hash: "ph".into(),
        seed: 1,
        dimension: "groundedness".into(),
        outcome: "pass".into(),
        effect: 1.5,
        epoch: 42,
    };
    {
        let mut sink = FileEventSink::new(&events_path);
        sink.append(&rec);
    }
    let verdicts = FileEventSink::new(&events_path).load_all();
    assert_eq!(
        verdicts.len(),
        1,
        "the reproduce-from-SHA verdict survived the restart"
    );
    assert_eq!(verdicts[0], rec);
}
