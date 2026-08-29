// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Gap-closure tests for the transport-daemon event log (subsystem `transport-daemon`).
//!
//! Each test is named after the gap it closes and is written to FAIL before the corresponding
//! change (the API/behaviour did not exist) and PASS after:
//!   * `gap_ainxt_eventlog_replay_tail_from_cursor` — replay backbone (PROTOCOL §7.2).
//!   * `gap_ainxt_eventlog_replay_verified_rejects_tampered_tail` — audit-grade replay (I4).
//!   * `gap_ainxt_eventlog_crypto_hash_is_sha256_not_fnv` — real crypto hash seam.
//!   * `gap_ainxt_eventlog_crypto_agility_rotation_seam` — ADR-023 pluggable/rotatable hasher.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ainxt_eventlog::{ChainHasher, EventLog, JsonlEventLog, Sha256Hasher, TamperError};

fn temp_dir(tag: &str) -> PathBuf {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("ax-elog-gap-{tag}-{}-{n}", std::process::id()))
}

/// PROTOCOL.md §7.2: `session.resume{from_event}` replays "every event with seq > from_event".
/// Before this change there was no cursor-based replay — only `records()` (full history).
#[test]
fn gap_ainxt_eventlog_replay_tail_from_cursor() {
    let dir = temp_dir("replay");
    let log = JsonlEventLog::open(&dir).unwrap();
    for i in 1..=5 {
        log.append("s", "user", "message", &format!("m{i}"))
            .unwrap();
    }

    // Reconnect at cursor 2 → only seq 3,4,5 in order (nothing lost, nothing re-sent).
    let tail = log.replay("s", 2);
    let seqs: Vec<u64> = tail.iter().map(|r| r.seq).collect();
    assert_eq!(
        seqs,
        vec![3, 4, 5],
        "tail must be strictly seq > from_seq, in order"
    );
    assert_eq!(tail[0].text, "m3");

    // from_seq == 0 → full replay; cursor at head → empty; cursor past head → empty (no panic).
    assert_eq!(log.replay("s", 0).len(), 5);
    assert!(log.replay("s", 5).is_empty());
    assert!(log.replay("s", 99).is_empty());

    // Replay survives a process restart (cold-start-safe resume, PROTOCOL §7.2 last para).
    drop(log);
    let log2 = JsonlEventLog::open(&dir).unwrap();
    assert_eq!(
        log2.replay("s", 3)
            .iter()
            .map(|r| r.seq)
            .collect::<Vec<_>>(),
        vec![4, 5]
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// I4 / ADR-025: audit-grade replay must NOT hand back a tampered chain. `replay_verified`
/// verifies the whole chain first; a tamper *anywhere* (even before the cursor) blocks the tail.
#[test]
fn gap_ainxt_eventlog_replay_verified_rejects_tampered_tail() {
    let dir = temp_dir("replay-verified");
    let log = JsonlEventLog::open(&dir).unwrap();
    log.append("s", "user", "message", "one").unwrap();
    log.append("s", "assistant", "message", "two").unwrap();
    log.append("s", "user", "message", "three").unwrap();

    // Clean log: verified replay returns the tail.
    assert_eq!(
        log.replay_verified("s", 1)
            .unwrap()
            .iter()
            .map(|r| r.seq)
            .collect::<Vec<_>>(),
        vec![2, 3]
    );

    // Tamper record seq 1 (which is BEFORE the cursor=1 tail). A naive replay would still ship
    // seq 2,3; verified replay refuses the whole session because the chain is compromised.
    let path = dir.join("s.jsonl");
    let content = std::fs::read_to_string(&path)
        .unwrap()
        .replace("one", "ONE");
    std::fs::write(&path, content).unwrap();

    let log2 = JsonlEventLog::open(&dir).unwrap();
    assert_eq!(
        log2.replay_verified("s", 1),
        Err(TamperError::HashMismatch { seq: 1 }),
        "a tampered chain must never be replayed, even the untampered tail"
    );
    // Fast (unverified) replay still returns rows — this is why the verified variant exists.
    assert_eq!(log2.replay("s", 1).len(), 2);

    std::fs::remove_dir_all(&dir).ok();
}

/// The chain hash must be a real cryptographic hash (SHA-256), not SipHash/FNV. SHA-256 emits
/// 32 bytes = 64 lowercase hex chars and is deterministic; SipHash/FNV (`DefaultHasher`) emit a
/// u64 (≤16 hex). This pins the seam to genuine crypto.
#[test]
fn gap_ainxt_eventlog_crypto_hash_is_sha256_not_fnv() {
    let h = Sha256Hasher;
    assert_eq!(h.algorithm(), "sha256");
    let a = h.hash("GENESIS", "s", 1, 42, "user", "message", "hello");
    let b = h.hash("GENESIS", "s", 1, 42, "user", "message", "hello");
    assert_eq!(a, b, "hash must be deterministic across builds/calls");
    assert_eq!(
        a.len(),
        64,
        "SHA-256 = 64 hex chars (a u64 SipHash/FNV would be ≤16)"
    );
    assert!(a
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    // Any field change flips the digest (length-prefixing prevents boundary-shift forgery).
    assert_ne!(a, h.hash("GENESIS", "s", 1, 42, "user", "message", "hellp"));
    // Persisted records carry their algorithm id for crypto-agility audits.
    let dir = temp_dir("alg-tag");
    let log = JsonlEventLog::open(&dir).unwrap();
    let r = log.append("s", "user", "message", "x").unwrap();
    assert_eq!(r.hash_alg, "sha256");
    assert_eq!(log.records("s")[0].hash_alg, "sha256");
    std::fs::remove_dir_all(&dir).ok();
}

/// ADR-023 crypto-agility: the hasher is a pluggable seam and a log may be *rotated* to a new
/// algorithm mid-life. A mixed-algorithm chain still verifies when both hashers are registered,
/// and an unregistered/forged algorithm is caught (`UnknownAlgorithm`) rather than silently
/// passing. Proven here with an injected second hasher (no extra crate dep needed).
#[test]
fn gap_ainxt_eventlog_crypto_agility_rotation_seam() {
    // A second, distinct hasher standing in for a rotated-in algorithm (e.g. blake3).
    #[derive(Clone, Copy)]
    struct DoubleSha;
    impl ChainHasher for DoubleSha {
        fn algorithm(&self) -> &'static str {
            "sha256x2"
        }
        fn hash(
            &self,
            prev: &str,
            session: &str,
            seq: u64,
            ts: u128,
            actor: &str,
            kind: &str,
            text: &str,
        ) -> String {
            // A genuinely different construction from Sha256Hasher: hash the sha256 digest again.
            let once = Sha256Hasher.hash(prev, session, seq, ts, actor, kind, text);
            Sha256Hasher.hash(&once, session, seq, ts, actor, kind, text)
        }
    }

    let dir = temp_dir("rotate");

    // Phase 1: write two records under the default SHA-256.
    {
        let log = JsonlEventLog::open(&dir).unwrap();
        log.append("s", "user", "message", "pre-rotation-1")
            .unwrap();
        log.append("s", "user", "message", "pre-rotation-2")
            .unwrap();
        assert_eq!(log.primary_algorithm(), "sha256");
        assert_eq!(log.verify("s"), Ok(2));
    }

    // Phase 2: ROTATE — reopen with the new primary hasher and append more records. The chain
    // links across the boundary (record 3's prev_hash = record 2's sha256 hash string).
    {
        let log = JsonlEventLog::open_with_hasher(&dir, Arc::new(DoubleSha));
        let log = log.unwrap();
        assert_eq!(log.primary_algorithm(), "sha256x2");
        let r3 = log
            .append("s", "user", "message", "post-rotation-3")
            .unwrap();
        assert_eq!(r3.hash_alg, "sha256x2");

        // With ONLY the new hasher registered, the old sha256 records cannot be attested.
        assert_eq!(
            log.verify("s"),
            Err(TamperError::UnknownAlgorithm {
                seq: 1,
                algorithm: "sha256".to_string()
            }),
            "a rotated-out algorithm without its verifier must not silently pass"
        );
    }

    // Phase 3: register BOTH hashers → the mixed-algorithm chain verifies end to end.
    {
        let log = JsonlEventLog::open_with_hasher(&dir, Arc::new(DoubleSha))
            .unwrap()
            .with_verifier(Arc::new(Sha256Hasher));
        assert_eq!(
            log.verify("s"),
            Ok(3),
            "mixed sha256 + sha256x2 chain must verify"
        );

        // And tampering a rotated (new-algo) record is still caught under the new hasher.
        let path = dir.join("s.jsonl");
        let content = std::fs::read_to_string(&path)
            .unwrap()
            .replace("post-rotation-3", "post-rotation-HACKED");
        std::fs::write(&path, content).unwrap();
        let log2 = JsonlEventLog::open_with_hasher(&dir, Arc::new(DoubleSha))
            .unwrap()
            .with_verifier(Arc::new(Sha256Hasher));
        assert_eq!(log2.verify("s"), Err(TamperError::HashMismatch { seq: 3 }));
    }

    std::fs::remove_dir_all(&dir).ok();
}
