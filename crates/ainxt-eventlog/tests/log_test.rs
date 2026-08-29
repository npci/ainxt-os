// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Event-log tests: append/read, chain verification, resume-after-reopen (durability), and
//! tamper detection.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use ainxt_eventlog::{EventLog, JsonlEventLog, TamperError};

fn temp_dir(tag: &str) -> PathBuf {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("ax-elog-{tag}-{}-{n}", std::process::id()))
}

#[test]
fn append_read_and_verify() {
    let dir = temp_dir("basic");
    let log = JsonlEventLog::open(&dir).unwrap();
    log.append("s", "user", "message", "hello").unwrap();
    log.append("s", "assistant", "message", "hi there").unwrap();
    log.append("s", "user", "message", "thanks").unwrap();

    let recs = log.records("s");
    assert_eq!(recs.len(), 3);
    assert_eq!(recs[0].seq, 1);
    assert_eq!(recs[2].seq, 3);
    assert_eq!(recs[1].text, "hi there");
    assert_eq!(log.verify("s"), Ok(3));

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn survives_reopen_and_chain_continues() {
    let dir = temp_dir("resume");
    {
        let log = JsonlEventLog::open(&dir).unwrap();
        log.append("sess", "user", "message", "UPI growth?")
            .unwrap();
        log.append("sess", "assistant", "message", "UPI grew ~45% YoY")
            .unwrap();
    } // dropped — simulate a process restart

    // A fresh log instance on the SAME dir reads the persisted history...
    let log2 = JsonlEventLog::open(&dir).unwrap();
    let recs = log2.records("sess");
    assert_eq!(recs.len(), 2, "history must survive a restart");
    assert_eq!(recs[1].text, "UPI grew ~45% YoY");

    // ...and appends continue the chain (seq 3, prev_hash = record 2's hash).
    let r3 = log2
        .append("sess", "user", "message", "generate this as pdf")
        .unwrap();
    assert_eq!(r3.seq, 3);
    assert_eq!(r3.prev_hash, recs[1].hash);
    assert_eq!(log2.verify("sess"), Ok(3));

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn tampering_is_detected() {
    let dir = temp_dir("tamper");
    let log = JsonlEventLog::open(&dir).unwrap();
    log.append("s", "user", "message", "original").unwrap();
    log.append("s", "assistant", "message", "answer").unwrap();
    assert_eq!(log.verify("s"), Ok(2));

    // Tamper: edit a record's text on disk (its stored hash no longer matches).
    let path = dir.join("s.jsonl");
    let content = std::fs::read_to_string(&path)
        .unwrap()
        .replace("original", "HACKED");
    std::fs::write(&path, content).unwrap();

    let log2 = JsonlEventLog::open(&dir).unwrap();
    assert_eq!(
        log2.verify("s"),
        Err(TamperError::HashMismatch { seq: 1 }),
        "edit must break the chain"
    );

    std::fs::remove_dir_all(&dir).ok();
}
