// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! **Event-Log journaling** of every pipeline stage, hash-chained for tamper-evident regulator
//! replay (`docs/architecture/CODE_REVIEW_PIPELINE.md` §9).
//!
//! Every stage transition is an event appended with a SHA-256 hash chained to its predecessor for
//! this edit: a regulator reconstructing a settlement-path commit two years later gets a signed,
//! ordered, un-editable trail from "patch generated" to "commit", including every self-heal round
//! and the exact evidence behind every verdict. `pipelineHistory(edit_id)` is then a structured
//! query, the same shape as the rest of the runtime's Event Log.
//!
//! Deterministic: the caller supplies a monotonic tick per event (no wall clock in this crate), so a
//! replay reproduces byte-identical hashes. Verification ([`Journal::verify`]) recomputes the whole
//! chain and reports the first break.

use crate::stage::{Stage, StageVerdict};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// One journaled pipeline event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum PipelineEvent {
    PipelineStarted {
        edit_id: String,
        risk_tier: String,
        blast_radius: usize,
        edit_engine_rung: String,
    },
    StageStarted {
        stage: Stage,
    },
    StageResult {
        stage: Stage,
        verdict: StageVerdict,
        deterministic: bool,
    },
    SelfHealTriggered {
        stage: Stage,
        round: u8,
        observation: String,
    },
    RoundCapped {
        rounds_exhausted: u8,
        stuck_detector_fired: bool,
        diagnosis: String,
    },
    /// **Mid-run escalate-only risk re-classification** (`CODE_REVIEW_PIPELINE.md` §3: "Re-classification,
    /// not a one-shot decision"). Emitted whenever a self-heal round moves the effective tier *up* —
    /// because the healed set now touches a file outside the original blast radius / a critical-path
    /// module, or because a stage tripped a finding. The tier can never move down, so this event is
    /// always an escalation and the regulator trail shows exactly which round forced it.
    RiskReclassified {
        round: u8,
        from: String,
        to: String,
        reason: String,
    },
    /// A wire-supplied policy field the runtime **discarded and replaced** at the request boundary
    /// (`crate::wire_seal`): a forged Commit-Gate threshold, an unevidenced ladder rung, a
    /// self-asserted Judge verdict, an over-budget round count. Recorded so the override is auditable
    /// rather than silent.
    WirePolicySealed {
        field: String,
    },
    JudgeVerdict {
        approved: bool,
        judge_model: String,
        context_isolation_confirmed: bool,
    },
    /// The optional Tier-3 Breaker differential/invariant run (`CODE_REVIEW_PIPELINE.md` §3/§8).
    BreakerDifferential {
        divergences: usize,
        invariant_violations: usize,
        gating: bool,
    },
    PipelineOutcome {
        outcome: String,
        confidence_score: u8,
    },
}

/// A hash-chained record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalRecord {
    pub seq: u64,
    pub tick: u64,
    pub event: PipelineEvent,
    pub prev_hash: String,
    pub hash: String,
}

/// The append-only, hash-chained journal for one edit.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Journal {
    edit_id: String,
    /// The commit SHA this edit produced, once the turn commits. `None` until then. This is the key
    /// `pipeline_history(commit_sha)` (`CODE_REVIEW_PIPELINE.md` §9) indexes by — a regulator with
    /// only a commit SHA reconstructs the full stage-by-stage trail.
    #[serde(default)]
    commit_sha: Option<String>,
    records: Vec<JournalRecord>,
}

/// SHA-256 chain link. Swap this one function to rotate the hash (crypto-agility, ADR-023).
fn chain_hash(prev: &str, seq: u64, tick: u64, edit_id: &str, event_json: &str) -> String {
    let mut h = Sha256::new();
    h.update(prev.as_bytes());
    h.update(b"\x1f");
    h.update(seq.to_le_bytes());
    h.update(tick.to_le_bytes());
    h.update(edit_id.as_bytes());
    h.update(b"\x1f");
    h.update(event_json.as_bytes());
    let digest = h.finalize();
    let mut s = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// The genesis previous-hash for the first record.
const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

impl Journal {
    #[must_use]
    pub fn new(edit_id: impl Into<String>) -> Self {
        Journal {
            edit_id: edit_id.into(),
            commit_sha: None,
            records: Vec::new(),
        }
    }

    #[must_use]
    pub fn edit_id(&self) -> &str {
        &self.edit_id
    }

    /// Reconstruct a journal from stored records — what a regulator does with a `pipeline_history`
    /// result: rebuild the trail, then [`verify`](Self::verify) the chain and
    /// [`verify_seal`](Self::verify_seal) the signature against it. No `append` is possible after this;
    /// it is a read model of an already-sealed trail.
    #[must_use]
    pub fn from_records(
        edit_id: impl Into<String>,
        commit_sha: Option<String>,
        records: Vec<JournalRecord>,
    ) -> Self {
        Journal {
            edit_id: edit_id.into(),
            commit_sha,
            records,
        }
    }

    /// Bind the commit SHA this edit produced (called once the turn commits). This is what
    /// [`JournalStore::pipeline_history`] later indexes by.
    pub fn set_commit_sha(&mut self, sha: impl Into<String>) {
        self.commit_sha = Some(sha.into());
    }

    #[must_use]
    pub fn commit_sha(&self) -> Option<&str> {
        self.commit_sha.as_deref()
    }

    /// The current chain head hash (the last record's hash, or [`GENESIS`] if empty). This is the
    /// single value a [`JournalSigner`] signs to seal the whole ordered trail: because each record's
    /// hash chains its predecessor, a signature over the head transitively authenticates every record.
    #[must_use]
    pub fn head_hash(&self) -> String {
        self.records
            .last()
            .map(|r| r.hash.clone())
            .unwrap_or_else(|| GENESIS.to_string())
    }

    /// Produce a **signed seal** over this journal's chain head with `signer`, binding the edit id +
    /// commit sha + record count + head hash. The signature makes the trail not merely tamper-*evident*
    /// (the hash chain) but tamper-*proof* against an attacker who could recompute the chain: without
    /// the signer's key the head cannot be re-signed. The real signer is an HSM/KMS seam (**infra**);
    /// offline, [`HmacSigner`] is a deterministic keyed stand-in.
    #[must_use]
    pub fn seal(&self, signer: &dyn JournalSigner) -> SignedSeal {
        let head = self.head_hash();
        let payload = format!(
            "{}\x1f{}\x1f{}\x1f{}",
            self.edit_id,
            self.commit_sha.as_deref().unwrap_or(""),
            self.records.len(),
            head
        );
        SignedSeal {
            edit_id: self.edit_id.clone(),
            commit_sha: self.commit_sha.clone(),
            record_count: self.records.len(),
            head_hash: head,
            signature: signer.sign(payload.as_bytes()),
        }
    }

    /// Verify a [`SignedSeal`] against this journal's *current* state with `signer`. Returns `false` if
    /// the chain is broken, the head/edit/commit/count drifted from the seal, or the signature does not
    /// verify — any post-seal tampering is caught.
    #[must_use]
    pub fn verify_seal(&self, signer: &dyn JournalSigner, seal: &SignedSeal) -> bool {
        if self.verify().is_err() {
            return false;
        }
        let recomputed = self.seal(signer);
        recomputed == *seal
            && signer.verify(
                format!(
                    "{}\x1f{}\x1f{}\x1f{}",
                    seal.edit_id,
                    seal.commit_sha.as_deref().unwrap_or(""),
                    seal.record_count,
                    seal.head_hash
                )
                .as_bytes(),
                &seal.signature,
            )
    }

    /// Append an event with a caller-supplied monotonic `tick`. Returns the new record's hash.
    ///
    /// # Panics
    /// Never in practice: `serde_json::to_string` of these plain enums cannot fail; a defensive
    /// `unwrap_or_default` keeps the chain honest even in the impossible case.
    pub fn append(&mut self, tick: u64, event: PipelineEvent) -> String {
        let seq = self.records.len() as u64;
        let prev = self
            .records
            .last()
            .map(|r| r.hash.clone())
            .unwrap_or_else(|| GENESIS.to_string());
        let event_json = serde_json::to_string(&event).unwrap_or_default();
        let hash = chain_hash(&prev, seq, tick, &self.edit_id, &event_json);
        self.records.push(JournalRecord {
            seq,
            tick,
            event,
            prev_hash: prev,
            hash: hash.clone(),
        });
        hash
    }

    #[must_use]
    pub fn records(&self) -> &[JournalRecord] {
        &self.records
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Verify the whole chain. `Ok(())` if intact; `Err(seq)` at the first tampered record.
    pub fn verify(&self) -> Result<(), u64> {
        let mut prev = GENESIS.to_string();
        for (i, r) in self.records.iter().enumerate() {
            if r.seq != i as u64 || r.prev_hash != prev {
                return Err(r.seq);
            }
            let event_json = serde_json::to_string(&r.event).unwrap_or_default();
            let expect = chain_hash(&prev, r.seq, r.tick, &self.edit_id, &event_json);
            if expect != r.hash {
                return Err(r.seq);
            }
            prev = r.hash.clone();
        }
        Ok(())
    }
}

// ===========================================================================
// Signing seam (§9 "signed") + durable store seam + pipelineHistory(commit_sha)
// ===========================================================================

/// A cryptographic **signature over a journal's sealed chain head** (`CODE_REVIEW_PIPELINE.md` §9 —
/// "a *signed*, ordered, un-editable trail"). Carries the identifiers it authenticates so a verifier
/// (a regulator, the Breaker) can check it standalone against a re-read journal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedSeal {
    pub edit_id: String,
    pub commit_sha: Option<String>,
    pub record_count: usize,
    pub head_hash: String,
    /// Hex signature over `edit_id ⧉ commit_sha ⧉ record_count ⧉ head_hash`.
    pub signature: String,
}

/// The seam a real evidentiary signer (HSM / KMS / cloud signing service) implements — **infra**: it
/// holds a private key in hardware and its `verify` may call out to a key service. Offline, use
/// [`HmacSigner`]. Swapping the concrete signer is the crypto-agility knob (ADR-023) the durable
/// registers ride on: the hash-chain link (`chain_hash`) and this signature are the two rotatable
/// primitives, and nothing above this trait hard-codes the algorithm.
pub trait JournalSigner {
    /// Sign `payload`, returning a hex signature.
    fn sign(&self, payload: &[u8]) -> String;
    /// Verify a hex `signature` over `payload`.
    fn verify(&self, payload: &[u8], signature: &str) -> bool;
}

/// A deterministic offline [`JournalSigner`]: keyed SHA-256 (HMAC-style), so tests and air-gapped
/// runs get a real, verifiable, key-dependent signature without an HSM. It is honest about being a
/// stand-in — the key lives in process, so it authenticates against accidental/after-the-fact
/// tampering, not a key-compromising attacker (that is the real HSM seam's job).
#[derive(Debug, Clone)]
pub struct HmacSigner {
    key: Vec<u8>,
}

impl HmacSigner {
    #[must_use]
    pub fn new(key: impl Into<Vec<u8>>) -> Self {
        HmacSigner { key: key.into() }
    }

    fn mac(&self, payload: &[u8]) -> String {
        // HMAC-SHA256 construction (block size 64). Deterministic, no external crate beyond sha2.
        const BLOCK: usize = 64;
        let mut key = self.key.clone();
        if key.len() > BLOCK {
            let mut h = Sha256::new();
            h.update(&key);
            key = h.finalize().to_vec();
        }
        key.resize(BLOCK, 0);
        let ipad: Vec<u8> = key.iter().map(|b| b ^ 0x36).collect();
        let opad: Vec<u8> = key.iter().map(|b| b ^ 0x5c).collect();
        let mut inner = Sha256::new();
        inner.update(&ipad);
        inner.update(payload);
        let inner = inner.finalize();
        let mut outer = Sha256::new();
        outer.update(&opad);
        outer.update(inner);
        let digest = outer.finalize();
        let mut s = String::with_capacity(64);
        for b in digest {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
        }
        s
    }
}

impl JournalSigner for HmacSigner {
    fn sign(&self, payload: &[u8]) -> String {
        self.mac(payload)
    }
    fn verify(&self, payload: &[u8], signature: &str) -> bool {
        // Constant-ish comparison is unnecessary here (offline, no timing channel), but compare the
        // full recomputed MAC so a truncated signature never passes.
        self.mac(payload) == signature
    }
}

/// The seam a **durable** journal store implements (`CODE_REVIEW_PIPELINE.md` §9 — the Event Log is
/// "durable, incrementally-projected"). The real backend is Postgres/WORM object storage (**infra**);
/// [`InMemoryJournalStore`] is the offline impl the query + signing logic is proven against.
pub trait JournalStore {
    /// Persist a sealed journal (its records + the signed seal). Overwrites by `edit_id`.
    fn put(&mut self, journal: &Journal, seal: SignedSeal);
    /// **`pipelineHistory(commit_sha)`** — the full hash-chained record trail for the edit that
    /// produced `commit_sha`, plus its signed seal. `None` if no committed edit maps to that SHA.
    fn pipeline_history(&self, commit_sha: &str) -> Option<(Vec<JournalRecord>, SignedSeal)>;
    /// The trail for a specific `edit_id` (whether or not it committed).
    fn by_edit_id(&self, edit_id: &str) -> Option<(Vec<JournalRecord>, SignedSeal)>;
}

/// Offline, deterministic [`JournalStore`]: two indexes (by edit id, by commit sha) over cloned
/// records + seals. Faithful to the durable contract so the query behaves identically when a real
/// Postgres/WORM backend is slotted behind the same trait.
#[derive(Debug, Clone, Default)]
pub struct InMemoryJournalStore {
    by_edit: std::collections::BTreeMap<String, (Vec<JournalRecord>, SignedSeal)>,
    commit_to_edit: std::collections::BTreeMap<String, String>,
}

impl InMemoryJournalStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl JournalStore for InMemoryJournalStore {
    fn put(&mut self, journal: &Journal, seal: SignedSeal) {
        if let Some(sha) = journal.commit_sha() {
            self.commit_to_edit
                .insert(sha.to_string(), journal.edit_id().to_string());
        }
        self.by_edit.insert(
            journal.edit_id().to_string(),
            (journal.records().to_vec(), seal),
        );
    }

    fn pipeline_history(&self, commit_sha: &str) -> Option<(Vec<JournalRecord>, SignedSeal)> {
        let edit_id = self.commit_to_edit.get(commit_sha)?;
        self.by_edit.get(edit_id).cloned()
    }

    fn by_edit_id(&self, edit_id: &str) -> Option<(Vec<JournalRecord>, SignedSeal)> {
        self.by_edit.get(edit_id).cloned()
    }
}

/// The on-disk shape of one persisted, sealed journal (records + seal + the commit SHA it produced).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredJournal {
    edit_id: String,
    commit_sha: Option<String>,
    records: Vec<JournalRecord>,
    seal: SignedSeal,
}

/// A **durable, crash-atomic** [`JournalStore`] backed by the filesystem — the offline-real store that
/// makes the tamper-evident Event Log survive a process restart (`CODE_REVIEW_PIPELINE.md` §9: the
/// Event Log is "durable, incrementally-projected"). Prior to this, the only [`JournalStore`] was
/// [`InMemoryJournalStore`], lost on exit — a regulator two years later would find nothing.
///
/// Each sealed journal is written as one JSON file `<root>/<edit_id>.jnl.json`, published via
/// write-temp-then-`rename` so a crash mid-write never leaves a torn record (the rename is atomic on
/// POSIX). Reopening a store at the same root re-reads every persisted journal, so
/// [`pipeline_history`](JournalStore::pipeline_history) / [`by_edit_id`](JournalStore::by_edit_id)
/// answer a regulator's forensic-replay query from cold storage. The signed seal round-trips intact,
/// so [`Journal::verify_seal`] still detects any post-hoc tampering after the restart.
///
/// **Honest scope (`infra_gated`):** the production backend is Postgres + WORM object storage (append-
/// only, retention-locked) behind this same [`JournalStore`] trait — that is infra. This FS store is
/// the durable offline impl the durability + signature-survival contract is proven against; the crypto
/// signer is already swappable ([`JournalSigner`], ADR-023).
#[derive(Debug, Clone)]
pub struct FsJournalStore {
    root: std::path::PathBuf,
}

impl FsJournalStore {
    /// Open (creating if absent) a durable journal store rooted at `root`.
    ///
    /// # Errors
    /// Returns the underlying [`std::io::Error`] if the root directory cannot be created.
    pub fn open(root: impl Into<std::path::PathBuf>) -> std::io::Result<Self> {
        let root = root.into();
        std::fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    /// A filesystem-safe file name for an edit id (path separators / oddities collapsed to `_`).
    fn file_for(&self, edit_id: &str) -> std::path::PathBuf {
        let safe: String = edit_id
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '.' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        self.root.join(format!("{safe}.jnl.json"))
    }

    /// Read + deserialize every persisted journal in the root (skips non-journal / unreadable files).
    fn load_all(&self) -> Vec<StoredJournal> {
        let mut out = Vec::new();
        let Ok(entries) = std::fs::read_dir(&self.root) else {
            return out;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            if let Ok(bytes) = std::fs::read(&path) {
                if let Ok(stored) = serde_json::from_slice::<StoredJournal>(&bytes) {
                    out.push(stored);
                }
            }
        }
        out
    }
}

impl JournalStore for FsJournalStore {
    fn put(&mut self, journal: &Journal, seal: SignedSeal) {
        let stored = StoredJournal {
            edit_id: journal.edit_id().to_string(),
            commit_sha: journal.commit_sha().map(str::to_string),
            records: journal.records().to_vec(),
            seal,
        };
        let Ok(bytes) = serde_json::to_vec_pretty(&stored) else {
            return;
        };
        let final_path = self.file_for(journal.edit_id());
        // Crash-atomic publish: write to a unique temp sibling, fsync-free rename over the target.
        let tmp = final_path.with_extension(format!(
            "json.tmp.{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        if std::fs::write(&tmp, &bytes).is_ok() {
            let _ = std::fs::rename(&tmp, &final_path);
        }
    }

    fn pipeline_history(&self, commit_sha: &str) -> Option<(Vec<JournalRecord>, SignedSeal)> {
        self.load_all()
            .into_iter()
            .find(|s| s.commit_sha.as_deref() == Some(commit_sha))
            .map(|s| (s.records, s.seal))
    }

    fn by_edit_id(&self, edit_id: &str) -> Option<(Vec<JournalRecord>, SignedSeal)> {
        let path = self.file_for(edit_id);
        let bytes = std::fs::read(&path).ok()?;
        let stored: StoredJournal = serde_json::from_slice(&bytes).ok()?;
        Some((stored.records, stored.seal))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seeded() -> Journal {
        let mut j = Journal::new("edit-42");
        j.append(
            1,
            PipelineEvent::PipelineStarted {
                edit_id: "edit-42".into(),
                risk_tier: "high_risk".into(),
                blast_radius: 7,
                edit_engine_rung: "ast".into(),
            },
        );
        j.append(
            2,
            PipelineEvent::StageResult {
                stage: Stage::Sast,
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
        j
    }

    #[test]
    fn appends_and_chains() {
        let j = seeded();
        assert_eq!(j.len(), 3);
        assert_eq!(j.records()[0].prev_hash, GENESIS);
        // Each record's prev_hash is the previous record's hash.
        assert_eq!(j.records()[1].prev_hash, j.records()[0].hash);
        assert_eq!(j.records()[2].prev_hash, j.records()[1].hash);
    }

    #[test]
    fn intact_chain_verifies() {
        assert_eq!(seeded().verify(), Ok(()));
    }

    #[test]
    fn tampering_with_an_event_is_detected() {
        let mut j = seeded();
        // Silently rewrite the middle event's verdict — a regulator's worst case.
        j.records[1].event = PipelineEvent::StageResult {
            stage: Stage::Sast,
            verdict: StageVerdict::Fail {
                detail: "hidden".into(),
            },
            deterministic: true,
        };
        assert_eq!(j.verify(), Err(1));
    }

    #[test]
    fn reordering_is_detected() {
        let mut j = seeded();
        j.records.swap(0, 1);
        assert!(j.verify().is_err());
    }

    #[test]
    fn hashes_are_deterministic_across_rebuilds() {
        // Same edit_id + same ticks + same events ⇒ byte-identical hashes (forensic replay).
        assert_eq!(seeded().records()[2].hash, seeded().records()[2].hash);
    }

    #[test]
    fn different_edit_id_yields_different_hash() {
        let mut a = Journal::new("edit-A");
        let mut b = Journal::new("edit-B");
        let ev = || PipelineEvent::StageStarted {
            stage: Stage::Compile,
        };
        let ha = a.append(1, ev());
        let hb = b.append(1, ev());
        assert_ne!(ha, hb);
    }
}
