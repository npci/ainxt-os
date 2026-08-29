// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Durable, file-backed stores behind the §11 data-plane seams (EVAL_PLATFORM.md §11).
//!
//! The design's §11 data plane names three durable stores: the tamper-evident **Event Log** (already
//! durably backed by `ainxt-eventlog`'s hash-chained `JsonlEventLog`), the encrypted **sealed-corpus**
//! store, and the sealed **Regression Vault** store. The last two previously had only in-memory test
//! doubles. This module gives them a **durable, file-backed** implementation that survives a process
//! restart with no external infrastructure — the same discipline `ainxt-eventlog` uses (one durable
//! append-only file, JSON records) — so the seams are backed by a real store offline, not a mock.
//!
//! * [`FileVaultStore`] persists [`VaultCase`]s as append-only JSONL and re-loads them across restarts,
//!   dropping any record whose content seal does not verify (tamper evidence survives the round-trip).
//! * [`FileSealedCorpusStore`] reads a sealed corpus file and enforces the runner-only read identity
//!   ([`SealedCorpusStore`]), so the authors of a gated change still cannot read the gold answers.
//! * [`FileEventSink`] appends [`VerdictRecord`]s to a durable JSONL log (the reproduce-from-SHA
//!   verdicts the release gate writes).
//!
//! The *production* variants the design ultimately requires — a KMS-encrypted, access-controlled
//! Postgres / object-store data plane replicated for DR — are infra-gated (they need the live database
//! / object store / KMS). These file-backed stores are the durable, no-infra tier behind the SAME
//! trait seams; swapping in the encrypted DB-backed store is a config change, nothing else moves.

use crate::audit::{EventSink, VerdictRecord};
use crate::integrity::SealedCorpusStore;
use crate::vault::{VaultCase, VaultStore};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

/// A durable, append-only, file-backed [`VaultStore`]: each minted case is one JSON line in
/// `{path}`; [`load_all`](FileVaultStore::load_all) re-reads and re-verifies every case's seal, so a
/// case whose file record was silently edited is dropped on load (tamper evidence is durable).
#[derive(Debug, Clone)]
pub struct FileVaultStore {
    path: PathBuf,
}

impl FileVaultStore {
    /// Open (creating on first write) a durable Vault store at `path`.
    pub fn new(path: impl AsRef<Path>) -> Self {
        FileVaultStore {
            path: path.as_ref().to_path_buf(),
        }
    }
}

impl VaultStore for FileVaultStore {
    fn persist(&mut self, case: &VaultCase) {
        // Append-only durable write. A serialization failure would be a programmer error (VaultCase is
        // always serializable), so we surface it rather than silently dropping the case.
        let line = serde_json::to_string(case).expect("VaultCase serializes");
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .expect("open durable vault file for append");
        writeln!(f, "{line}").expect("append vault case");
        f.flush().expect("flush vault append");
    }

    fn load_all(&self) -> Vec<VaultCase> {
        let Ok(file) = File::open(&self.path) else {
            return Vec::new(); // no file yet ⇒ empty vault
        };
        let mut out = Vec::new();
        for line in BufReader::new(file).lines() {
            let Ok(line) = line else { continue };
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(case) = serde_json::from_str::<VaultCase>(&line) {
                // Only surface cases whose durable record still matches its seal — a tampered on-disk
                // record is dropped, never served as if authentic.
                if case.verify_seal() {
                    out.push(case);
                }
            }
        }
        out
    }
}

/// The on-disk shape of a sealed corpus file: `set_id -> version -> [(case_id, input, gold)]`.
type SealedCorpusFile = BTreeMap<String, BTreeMap<String, Vec<(String, String, String)>>>;

/// A durable, file-backed [`SealedCorpusStore`] readable only by the eval-runner machine identity. The
/// corpus lives in a JSON file the runner controls; the authors of the definitions the set gates never
/// hold the runner identity, so they cannot read the gold answers even with the file path.
#[derive(Debug, Clone)]
pub struct FileSealedCorpusStore {
    path: PathBuf,
    runner_identity: String,
}

impl FileSealedCorpusStore {
    /// Open a sealed corpus store at `path`, authorizing only `runner_identity` to read it.
    pub fn new(path: impl AsRef<Path>, runner_identity: &str) -> Self {
        FileSealedCorpusStore {
            path: path.as_ref().to_path_buf(),
            runner_identity: runner_identity.to_string(),
        }
    }

    /// Write (seal) a corpus file from `entries` (`set_id`, `version`, cases). This is the producer
    /// side — a runner-controlled operation — kept here so a durable store can be stood up in one call.
    #[allow(clippy::type_complexity)]
    pub fn seal(
        path: impl AsRef<Path>,
        entries: &[(&str, &str, Vec<(String, String, String)>)],
    ) -> std::io::Result<()> {
        let mut file: SealedCorpusFile = BTreeMap::new();
        for (set_id, version, cases) in entries {
            file.entry((*set_id).to_string())
                .or_default()
                .insert((*version).to_string(), cases.clone());
        }
        let json = serde_json::to_string_pretty(&file).expect("sealed corpus serializes");
        // Checkmarx G2: set explicit owner-only permissions (0600) so the sealed corpus
        // (which contains gold evaluation answers) is not world-readable on Unix systems.
        #[cfg(unix)]
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        #[cfg(not(unix))]
        let mut f = File::create(path)?;
        f.write_all(json.as_bytes())?;
        f.flush()
    }
}

impl SealedCorpusStore for FileSealedCorpusStore {
    fn load(
        &self,
        set_id: &str,
        version: &str,
        identity: &str,
    ) -> Option<Vec<(String, String, String)>> {
        // Runner-only read: the author of a gated change must never read the gold answers.
        if identity != self.runner_identity {
            return None;
        }
        // Checkmarx CX-FP: use std::fs::read (opens, reads, closes atomically) instead of an
        // explicit File handle — eliminates the "Improper Resource Shutdown" pattern match.
        let bytes = std::fs::read(&self.path).ok()?;
        let parsed: SealedCorpusFile = serde_json::from_slice(&bytes).ok()?;
        parsed.get(set_id)?.get(version).cloned()
    }
}

/// A durable, append-only, file-backed [`EventSink`]: each release-gate [`VerdictRecord`] is one JSON
/// line, so the reproduce-from-SHA verdicts survive a restart. (The tamper-evident, hash-chained
/// production Event Log is `ainxt-eventlog`; this is the plain durable sink behind the same seam.)
#[derive(Debug, Clone)]
pub struct FileEventSink {
    path: PathBuf,
}

impl FileEventSink {
    pub fn new(path: impl AsRef<Path>) -> Self {
        FileEventSink {
            path: path.as_ref().to_path_buf(),
        }
    }

    /// Re-read every persisted verdict (for audit / verification).
    pub fn load_all(&self) -> Vec<VerdictRecord> {
        let Ok(file) = File::open(&self.path) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for line in BufReader::new(file).lines() {
            let Ok(line) = line else { continue };
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(rec) = serde_json::from_str::<VerdictRecord>(&line) {
                out.push(rec);
            }
        }
        out
    }
}

impl EventSink for FileEventSink {
    fn append(&mut self, record: &VerdictRecord) {
        let line = serde_json::to_string(record).expect("VerdictRecord serializes");
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .expect("open durable event sink for append");
        writeln!(f, "{line}").expect("append verdict record");
        f.flush().expect("flush verdict append");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::VaultOrigin;

    fn unique_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "ainxt-eval-durable-{tag}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn vault_store_is_durable_across_reopen_and_drops_tampered_records() {
        let dir = unique_dir("vault");
        let path = dir.join("vault.jsonl");
        {
            let mut store = FileVaultStore::new(&path);
            store.persist(&VaultCase::mint(
                "INJ-1",
                VaultOrigin::Breaker,
                "evt-1",
                "sha-1",
                "tainted context",
                "settle tool must NOT fire",
                1,
            ));
        }
        // Reopen a FRESH store instance — durability across "restart".
        let reloaded = FileVaultStore::new(&path).load_all();
        assert_eq!(reloaded.len(), 1);
        assert!(reloaded[0].verify_seal());

        // Append a tampered line by hand → it must be dropped on load (seal fails).
        {
            let mut bad = VaultCase::mint("BAD", VaultOrigin::Breaker, "e", "s", "x", "y", 2);
            bad.expectation = "silently weakened".into(); // seal now stale
            let line = serde_json::to_string(&bad).unwrap();
            let mut f = OpenOptions::new().append(true).open(&path).unwrap();
            writeln!(f, "{line}").unwrap();
        }
        let after = FileVaultStore::new(&path).load_all();
        assert_eq!(after.len(), 1, "a tampered record must not survive load");
    }

    #[test]
    fn sealed_corpus_is_durable_and_runner_only() {
        let dir = unique_dir("corpus");
        let path = dir.join("corpus.json");
        let cases = vec![
            (
                "c1".to_string(),
                "when is settlement".to_string(),
                "T+1".to_string(),
            ),
            (
                "c2".to_string(),
                "what is UPI".to_string(),
                "unified payments".to_string(),
            ),
        ];
        FileSealedCorpusStore::seal(&path, &[("s1", "v1", cases.clone())]).unwrap();

        let store = FileSealedCorpusStore::new(&path, "eval-runner");
        assert_eq!(
            store.load("s1", "v1", "eval-runner"),
            Some(cases),
            "the runner reads the durable corpus"
        );
        assert!(
            store.load("s1", "v1", "pr-author").is_none(),
            "the author of the gated change must NOT read the gold answers"
        );
        assert!(
            store.load("s1", "v9", "eval-runner").is_none(),
            "unknown version"
        );
    }

    #[test]
    fn event_sink_is_durable_across_reopen() {
        let dir = unique_dir("events");
        let path = dir.join("verdicts.jsonl");
        let rec = VerdictRecord {
            eval_set_id: "s1".into(),
            eval_set_version: "v1".into(),
            judge_version: "j1".into(),
            candidate_sha: "sha".into(),
            params_hash: "ph".into(),
            seed: 7,
            dimension: "correctness".into(),
            outcome: "pass".into(),
            effect: 0.0,
            epoch: 1,
        };
        {
            let mut sink = FileEventSink::new(&path);
            sink.append(&rec);
            sink.append(&rec);
        }
        let loaded = FileEventSink::new(&path).load_all();
        assert_eq!(loaded.len(), 2, "verdicts survive a restart");
        assert_eq!(loaded[0], rec);
    }
}
