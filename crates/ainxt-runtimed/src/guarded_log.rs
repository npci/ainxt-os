// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! FI-01 — the durable event-log CHD sink-guard, applied at the composition layer.
//!
//! `ainxt-eventlog` cannot itself depend on `ainxt-compliance`: that would close a dependency
//! cycle (`compliance → runtime → tools → eventlog → compliance`). So the cardholder-data
//! sink-guard is applied *here*, in the composition root, where the durable [`EventLog`] and the
//! [`StrongRedactor`] legitimately coexist. [`GuardedEventLog`] wraps ANY [`EventLog`] and redacts
//! every `text` through the strong redactor BEFORE delegating the append — so the record that is
//! hash-chained and written to disk commits only redacted bytes, and a raw PAN/secret can never be
//! persisted to the durable log. This is the same guarantee as [`ainxt_compliance::GuardedSink`],
//! applied to the event-log seam (design §5.1: "no CDE persistence, by construction not by luck").

use std::sync::atomic::{AtomicBool, Ordering};

use ainxt_compliance::StrongRedactor;
use ainxt_eventlog::{EventLog, LogRecord, SinkStatus, TamperError};

/// A CHD sink-guard decorator over any [`EventLog`]: it redacts before the durable write. The only
/// constructor wraps an inner log, so there is no path to the durable sink that skips redaction.
pub struct GuardedEventLog<L: EventLog> {
    inner: L,
    redactor: StrongRedactor,
    /// Outcome of the most recent real append, for [`EventLog::sink_status`].
    ///
    /// This is the readiness signal the daemon exposes at `/readyz`. It is tracked *here* because
    /// this decorator is the single chokepoint every durable write already passes through — so the
    /// signal costs one atomic store per append and needs no synthetic probe write, which would
    /// otherwise append junk to the tamper-evident chain on every load-balancer poll.
    ///
    /// Starts `true`: a log that has not been written to yet is not failing.
    write_ok: AtomicBool,
}

impl<L: EventLog> GuardedEventLog<L> {
    /// Wrap `inner` so every append is redacted first (FI-01). This is the ONLY way to obtain a
    /// guarded log; the inner log is never handed out un-guarded.
    pub fn new(inner: L) -> Self {
        GuardedEventLog {
            inner,
            redactor: StrongRedactor::new(),
            write_ok: AtomicBool::new(true),
        }
    }
}

impl<L: EventLog> EventLog for GuardedEventLog<L> {
    fn append(
        &self,
        session: &str,
        actor: &str,
        kind: &str,
        text: &str,
    ) -> std::io::Result<LogRecord> {
        // FI-01: redact CHD/PII/secrets BEFORE the durable append. The redacted text is what the
        // inner log hash-chains AND writes, so both the on-disk record and the tamper-evident chain
        // are CHD-free by construction.
        let (redacted, _n) = self.redactor.redact(text);
        let result = self.inner.append(session, actor, kind, &redacted);
        // Record the outcome for `sink_status`. `Relaxed` is right: a readiness probe is inherently
        // a sample of a moving value, and no other state is ordered against this flag.
        self.write_ok.store(result.is_ok(), Ordering::Relaxed);
        result
    }

    fn records(&self, session: &str) -> Vec<LogRecord> {
        self.inner.records(session)
    }

    // GAP-AUDIT regulated-fi #4 — forward to the inner log. Without this override the trait's
    // `Vec::new()` default silently wins, and `AssembledFull::sweep_all_sessions` (which drives the
    // served daemon's cadence-scheduled sweep) would enumerate ZERO sessions on every real deployment
    // (the served `event_log` is always a `GuardedEventLog`, never a bare `JsonlEventLog`).
    fn sessions(&self) -> Vec<String> {
        self.inner.sessions()
    }

    fn verify(&self, session: &str) -> Result<usize, TamperError> {
        self.inner.verify(session)
    }

    /// The served daemon's real readiness signal: did the last durable append succeed?
    ///
    /// Reported as a bare [`SinkStatus`] with no detail, because `/readyz` is unauthenticated and
    /// the underlying `io::Error` names a filesystem path. The detail stays in the daemon's log.
    fn sink_status(&self) -> SinkStatus {
        if self.write_ok.load(Ordering::Relaxed) {
            SinkStatus::Ok
        } else {
            SinkStatus::Failing
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ainxt_eventlog::JsonlEventLog;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    /// A log whose durable append always fails, standing in for a full disk.
    struct AlwaysFailing;
    impl EventLog for AlwaysFailing {
        fn append(&self, _: &str, _: &str, _: &str, _: &str) -> std::io::Result<LogRecord> {
            Err(std::io::Error::new(
                std::io::ErrorKind::StorageFull,
                "no space left on device",
            ))
        }
        fn records(&self, _: &str) -> Vec<LogRecord> {
            Vec::new()
        }
        fn verify(&self, _: &str) -> Result<usize, TamperError> {
            Ok(0)
        }
    }

    /// The readiness signal behind `/readyz`: a healthy guarded log reports `Ok`, and one whose
    /// durable write failed reports `Failing` — derived from a REAL append, never a probe write,
    /// so a load-balancer poll can never append junk to the tamper-evident chain.
    #[test]
    fn sink_status_tracks_the_outcome_of_real_appends() {
        // A fresh log has not failed, so it must not report itself as failing.
        let dir = tmp("sink-status-ok");
        let ok = GuardedEventLog::new(JsonlEventLog::open(&dir).expect("open"));
        assert_eq!(
            ok.sink_status(),
            SinkStatus::Ok,
            "an unwritten log is not a failing log"
        );
        ok.append("s1", "alice", "ask", "hello").expect("append");
        assert_eq!(ok.sink_status(), SinkStatus::Ok, "a successful write stays Ok");
        std::fs::remove_dir_all(&dir).ok();

        // A failing durable write must flip the signal.
        let bad = GuardedEventLog::new(AlwaysFailing);
        assert_eq!(
            bad.sink_status(),
            SinkStatus::Ok,
            "the flag starts optimistic — nothing has failed yet"
        );
        assert!(bad.append("s1", "alice", "ask", "hello").is_err());
        assert_eq!(
            bad.sink_status(),
            SinkStatus::Failing,
            "a failed durable append is exactly what /readyz must surface"
        );
    }

    /// Redaction still happens on the failing path: the signal is recorded, but the guard is not
    /// bypassed. A regression here would leak CHD to whatever the inner sink does with the text.
    #[test]
    fn health_tracking_does_not_bypass_redaction() {
        let dir = tmp("sink-status-redact");
        let log = GuardedEventLog::new(JsonlEventLog::open(&dir).expect("open"));
        log.append("s1", "alice", "ask", "card 4111111111111111")
            .expect("append");
        let persisted = log.records("s1");
        assert_eq!(persisted.len(), 1);
        assert!(
            !persisted[0].text.contains("4111111111111111"),
            "the PAN must not reach the durable record: {}",
            persisted[0].text
        );
        assert_eq!(log.sink_status(), SinkStatus::Ok);
        std::fs::remove_dir_all(&dir).ok();
    }

    fn tmp(tag: &str) -> std::path::PathBuf {
        static C: AtomicU64 = AtomicU64::new(0);
        let n = C.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let d = std::env::temp_dir().join(format!(
            "ainxt-guarded-log-{tag}-{}-{nanos}-{n}",
            std::process::id()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn wire2_fi01_guarded_eventlog_redacts_chd_before_durable_write() {
        // The critical: a raw PAN handed to the durable sink must be redacted before it is chained
        // and written — the guard, not audit luck, keeps the log CHD-free.
        let log = GuardedEventLog::new(JsonlEventLog::open(tmp("fi01")).unwrap());
        let rec = log
            .append(
                "settlement",
                "auditor",
                "note",
                "refund to card 4111111111111111 done",
            )
            .unwrap();
        assert!(
            !rec.text.contains("4111111111111111"),
            "raw PAN must not survive into the durable record: {}",
            rec.text
        );
        let on_disk = &log.records("settlement")[0];
        assert!(
            !on_disk.text.contains("4111111111111111"),
            "raw PAN must not be on disk: {}",
            on_disk.text
        );
        // The chain verifies — the hash committed the redacted bytes, not the raw ones.
        assert_eq!(log.verify("settlement").unwrap(), 1);
        // Redaction is targeted: a benign line is stored verbatim.
        let plain = log
            .append("settlement", "auditor", "note", "batch closed ok")
            .unwrap();
        assert_eq!(plain.text, "batch closed ok");
    }
}
