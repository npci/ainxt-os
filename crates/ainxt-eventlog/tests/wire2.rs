// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Wire-2 integration tests: each gap's capability exercised on the REAL assembled object
//! (a `JsonlEventLog` on a real temp directory), not a mock.
//!
//! * `wire2_fi10`  — FI-10: the tamper-evident chain hash is produced through the crypto-agility
//!   policy ([`GovernedChainHasher`] over `ainxt_cryptoagility::GovernedHasher`), not a direct sha2
//!   call, and construction is fail-closed when the policy forbids/omits a usable primitive.
//! * `wire2_loop06` — LOOP-06: a Program's `ProgramEvent`s persist durably through
//!   [`ProgramEventSink`] (the planner's `EventSink` seam) and survive a simulated restart, with the
//!   hash chain intact and the stream re-projectable by the planner.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ainxt_cryptoagility::{
    Algorithm, AlgorithmRegistry, CryptoAgilityError, GovernedHasher, Purpose,
};
use ainxt_eventlog::{EventLog, GovernedChainHasher, JsonlEventLog, ProgramEventSink, TamperError};
use ainxt_planner::program::{project, NodeClass, NodeDecl, ProgramEvent, ProgramId};
use ainxt_planner::supervisor::EventSink;

/// A unique, isolated temp directory for one test run (no external test-dir crate).
fn temp_dir(tag: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "ainxt-eventlog-wire2-{tag}-{}-{nanos}-{n}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn hashing_policy(alg: Algorithm) -> GovernedHasher {
    let mut r = AlgorithmRegistry::new();
    r.register(Purpose::Hashing, alg);
    GovernedHasher::new(r)
}

#[test]
fn wire2_fi10() {
    // --- The live chain hash is governed by policy (not a hard-coded sha2 call). ---
    let dir = temp_dir("fi10");
    let governed = hashing_policy(Algorithm::approved("sha-256", false));
    let hasher = GovernedChainHasher::try_new(governed, 10)
        .expect("sha-256 policy must yield a governed hasher");
    let log = JsonlEventLog::open_with_hasher(&dir, Arc::new(hasher)).unwrap();

    let rec = log
        .append("settlement", "supervisor", "commit", "node A committed")
        .unwrap();
    // The record records the POLICY-selected algorithm, and the chain verifies with it.
    assert_eq!(rec.hash_alg, "sha256");
    assert_eq!(log.verify("settlement").unwrap(), 1);
    // A governed digest is a real SHA-256 output (64 lowercase hex chars).
    assert_eq!(rec.hash.len(), 64);
    assert!(rec.hash.chars().all(|c| c.is_ascii_hexdigit()));

    // --- Fail-closed: a policy that forbids every hash primitive yields NO hasher. ---
    let forbidden = hashing_policy(Algorithm::forbidden("md5", false));
    assert_eq!(
        GovernedChainHasher::try_new(forbidden, 0).unwrap_err(),
        CryptoAgilityError::NoApprovedAlgorithm {
            purpose: Purpose::Hashing
        }
    );
    // A policy resolving to an unimplemented label is refused (no silent fallback to a hard-coded alg).
    let unsupported = hashing_policy(Algorithm::approved("blake3", true));
    assert_eq!(
        GovernedChainHasher::try_new(unsupported, 0).unwrap_err(),
        CryptoAgilityError::UnsupportedAlgorithm {
            name: "blake3".into()
        }
    );

    // --- Rotation is enacted by POLICY alone: the chain-hash algorithm changes with the clock,
    // with zero code change. sha-256 is deprecated (sunset 100), sha-512 approved behind it. ---
    let rotating = || {
        let mut r = AlgorithmRegistry::new();
        r.register(
            Purpose::Hashing,
            Algorithm::deprecated("sha-256", 100, false),
        )
        .register(Purpose::Hashing, Algorithm::approved("sha-512", false));
        GovernedHasher::new(r)
    };
    // Before sunset: the log hashes with sha-256.
    let before = JsonlEventLog::open_with_hasher(
        temp_dir("fi10-before"),
        Arc::new(GovernedChainHasher::try_new(rotating(), 50).unwrap()),
    )
    .unwrap();
    let r_before = before.append("s", "a", "k", "t").unwrap();
    assert_eq!(r_before.hash_alg, "sha256");
    assert_eq!(before.verify("s").unwrap(), 1);
    // After sunset: the SAME policy now governs the log to sha-512 — no code change.
    let after = JsonlEventLog::open_with_hasher(
        temp_dir("fi10-after"),
        Arc::new(GovernedChainHasher::try_new(rotating(), 200).unwrap()),
    )
    .unwrap();
    let r_after = after.append("s", "a", "k", "t").unwrap();
    assert_eq!(r_after.hash_alg, "sha512");
    assert_eq!(r_after.hash.len(), 128); // sha-512 = 128 hex chars
    assert_eq!(after.verify("s").unwrap(), 1);

    // Tamper evidence still holds on a governed log: a forged payload breaks the chain.
    let path = dir.join("settlement.jsonl");
    let tampered = std::fs::read_to_string(&path)
        .unwrap()
        .replace("node A committed", "node A NOT committed");
    std::fs::write(&path, tampered).unwrap();
    assert!(matches!(
        log.verify("settlement"),
        Err(TamperError::HashMismatch { seq: 1 })
    ));
}

#[test]
fn wire2_loop06() {
    // A Program's events persist durably through the planner's EventSink seam, survive a restart,
    // and remain a verifiable, re-projectable stream.
    let dir = temp_dir("loop06");
    let goal = "decouple settlement module";
    let events = vec![
        ProgramEvent::Created {
            program_id: ProgramId::new("prog-1"),
            goal: goal.to_string(),
        },
        ProgramEvent::Decomposed {
            nodes: vec![
                NodeDecl::new("characterize", NodeClass::CharacterizationTest),
                NodeDecl::new("shim", NodeClass::Shim),
            ],
        },
    ];

    // --- First process: append through the durable sink. Offsets are the log's monotonic seq. ---
    let log = JsonlEventLog::open(&dir).unwrap();
    let mut sink = ProgramEventSink::new(log, "prog-1", "supervisor");
    for (i, ev) in events.iter().enumerate() {
        let offset = sink.append(ev).expect("durable append must succeed");
        assert_eq!(offset, (i + 1) as u64);
    }
    // The chain is intact.
    assert_eq!(sink.verify().unwrap(), events.len());
    drop(sink); // simulate process exit

    // --- Second process (restart / model-swap): re-open the SAME dir+session and resume. ---
    let reopened = JsonlEventLog::open(&dir).unwrap();
    let resumed = ProgramEventSink::new(reopened, "prog-1", "supervisor");
    let loaded = resumed.load().expect("durable load must succeed");
    // The full, in-order stream survived the restart, byte-for-byte.
    assert_eq!(loaded, events);
    // And it still projects to a valid Program state — resume = replay of the durable log (ADR-027 §4).
    let state = project(&loaded).expect("durable stream must project");
    assert_eq!(state.goal, goal);
    // Continuing to append after resume keeps offsets monotonic across the restart boundary.
    let mut resumed = resumed;
    let next = resumed
        .append(&ProgramEvent::Approved {
            approver: "lead".to_string(),
        })
        .unwrap();
    assert_eq!(next, (events.len() + 1) as u64);
    assert_eq!(resumed.verify().unwrap(), events.len() + 1);
}
