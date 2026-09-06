// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! ainxt-eventlog — durable, append-only, tamper-evident event log (the data plane).
//!
//! Design: `docs/architecture/SUBSYSTEM_DEEP_DIVES.md` (event log) + ADR-001 (two-tier
//! persistence) + ADR-023 (hash-chain crypto-agility) + `PROTOCOL.md` §7.2 (resume/replay).
//! Each session is an append-only JSONL file; every record carries a hash chained to its
//! predecessor, so any after-the-fact edit, reorder, or deletion breaks the chain and is
//! detected by [`EventLog::verify`].
//!
//! Three capabilities the runtime spine relies on:
//! * **append** — single-writer, crash-safe (`O_APPEND` + `flush`), monotonic `seq`.
//! * **verify** — recompute the whole chain and locate the first tamper (audit-grade).
//! * **replay** — [`EventLog::replay`] returns the tail after a cursor (`seq > from_seq`),
//!   the resume backbone from `PROTOCOL.md` §7.2 (`session.resume{from_event}`);
//!   [`EventLog::replay_verified`] verifies the chain *before* handing back the tail so a
//!   tampered log is never replayed to a client or an auditor (I4 / ADR-025).
//!
//! This is the file-backed slice — durable and verifiable with no external infra. The
//! production sink (Postgres/object-store) implements the SAME [`EventLog`] trait; nothing
//! above it changes, and `replay`/`replay_verified` are inherited as trait defaults.
//!
//! **Crypto-agility (ADR-023):** the chain hash is a real cryptographic hash (SHA-256 via the
//! RustCrypto `sha2` crate — collision-resistant and stable across builds, *not* SipHash/FNV),
//! behind the pluggable [`ChainHasher`] seam. Each record records the `hash_alg` that produced
//! it, so an algorithm can be rotated over the life of a log and a mixed-algorithm chain still
//! verifies: [`verify`](EventLog::verify) selects the hasher per record by its recorded
//! algorithm. Register additional (e.g. rotated-out) hashers with
//! [`JsonlEventLog::with_verifier`].

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

const GENESIS: &str = "GENESIS";

/// Default chain-hash algorithm identifier (see [`Sha256Hasher`]).
pub const DEFAULT_ALG: &str = "sha256";

fn default_alg() -> String {
    DEFAULT_ALG.to_string()
}

/// One persisted, hash-chained log record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogRecord {
    pub session: String,
    pub seq: u64,
    pub ts_millis: u128,
    pub actor: String,
    pub kind: String,
    pub text: String,
    pub prev_hash: String,
    pub hash: String,
    /// Which [`ChainHasher`] algorithm produced `hash` (crypto-agility / rotation, ADR-023).
    /// `#[serde(default)]` keeps pre-agility records (no field) readable as `"sha256"`.
    #[serde(default = "default_alg")]
    pub hash_alg: String,
}

/// A detected break in the append-only chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TamperError {
    SeqGap {
        expected: u64,
        found: u64,
    },
    BrokenChain {
        seq: u64,
    },
    HashMismatch {
        seq: u64,
    },
    /// A record was hashed with an algorithm no registered [`ChainHasher`] can verify — the
    /// chain cannot be attested (e.g. a rotated-out algorithm whose verifier wasn't registered,
    /// or a forged `hash_alg`). Register it with [`JsonlEventLog::with_verifier`].
    UnknownAlgorithm {
        seq: u64,
        algorithm: String,
    },
}

// ============================ crypto-agility seam (ADR-023) ============================

/// Pluggable chain-hash function. The default is [`Sha256Hasher`]; production may register a
/// stronger/rotated hasher without touching any code above this seam. The implementation MUST
/// bind its own [`algorithm`](ChainHasher::algorithm) into the digest so a downgrade of the
/// recorded `hash_alg` cannot pass verification.
pub trait ChainHasher: Send + Sync {
    /// Stable, wire-recorded identifier (e.g. `"sha256"`, `"blake3"`). Stored per record.
    fn algorithm(&self) -> &'static str;

    /// Compute the chain link over the canonical, length-prefixed encoding of every field
    /// (so a value boundary cannot be forged by shifting bytes between adjacent fields). The
    /// arguments ARE the canonical hash preimage — grouping them into a struct would only add
    /// indirection over the exact bytes being committed.
    #[allow(clippy::too_many_arguments)]
    fn hash(
        &self,
        prev: &str,
        session: &str,
        seq: u64,
        ts: u128,
        actor: &str,
        kind: &str,
        text: &str,
    ) -> String;
}

/// SHA-256 chain hash (RustCrypto `sha2`; MIT/Apache). Cryptographic and stable across builds —
/// genuinely tamper-evident, unlike `DefaultHasher`/SipHash/FNV. Output is 64 lowercase hex chars.
#[derive(Debug, Clone, Copy, Default)]
pub struct Sha256Hasher;

impl ChainHasher for Sha256Hasher {
    fn algorithm(&self) -> &'static str {
        "sha256"
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
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        // Bind the algorithm id so a forged `hash_alg` downgrade cannot verify.
        let alg = self.algorithm();
        h.update((alg.len() as u64).to_le_bytes());
        h.update(alg.as_bytes());
        for field in [prev, session, actor, kind, text] {
            h.update((field.len() as u64).to_le_bytes());
            h.update(field.as_bytes());
        }
        h.update(seq.to_le_bytes());
        h.update(ts.to_le_bytes());
        h.finalize().iter().map(|b| format!("{b:02x}")).collect::<String>()
    }
}

// ==================== FI-10: policy-GOVERNED chain hasher (ADR-023) ====================
//
// `Sha256Hasher` above is a *direct* sha2 call: the algorithm is hard-coded, so the crypto-agility
// policy governs nothing here. `GovernedChainHasher` closes that (FI-10): it is a [`ChainHasher`]
// whose digest is produced through [`ainxt_cryptoagility::GovernedHasher`], i.e. the chain-hash
// algorithm is *selected by policy* at a fixed governance tick. A Forbidden/expired hash primitive
// is then un-usable by construction, and a PQC transition is a policy edit, not a code change —
// exactly the guarantee ADR-023 asks for, now enacted on a live cryptographic operation (the
// tamper-evident chain), not just in the registry's own tests.

use ainxt_cryptoagility::{CryptoAgilityError, GovernedHasher, Tick};

/// A [`ChainHasher`] that computes the tamper-evident chain link through the crypto-agility policy.
///
/// The primitive is whatever the policy resolves for [`ainxt_cryptoagility::Purpose::Hashing`] at
/// the injected governance `tick` — never a hard-coded call. Construction is **fail-closed**
/// ([`try_new`](GovernedChainHasher::try_new)): if the policy has no usable hash primitive, or
/// resolves to a label this build cannot compute, no hasher is produced, so an event log can never
/// be opened that would hash with a forbidden/unimplemented algorithm.
///
/// The resolved algorithm is pinned into the stable `hash_alg` recorded per record (`"sha256"` /
/// `"sha512"`), so [`EventLog::verify`] selects the matching verifier and a mixed-algorithm chain
/// (produced across a policy rotation) still verifies.
#[derive(Debug, Clone)]
pub struct GovernedChainHasher {
    governed: GovernedHasher,
    tick: Tick,
    /// The stable, wire-recorded algorithm id resolved from the policy at `tick`.
    algorithm: &'static str,
}

impl GovernedChainHasher {
    /// Resolve the hash primitive from `governed`'s policy at governance time `tick` and bind it.
    ///
    /// Fail-closed: returns [`CryptoAgilityError::NoApprovedAlgorithm`] if the policy fences off
    /// every hash candidate, or [`CryptoAgilityError::UnsupportedAlgorithm`] if it resolves to a
    /// label with no implementation here — never a silent fallback to a hard-coded primitive.
    /// Supported labels: `sha-256`/`sha256`, `sha-512`/`sha512` (matching the governed hasher).
    pub fn try_new(governed: GovernedHasher, tick: Tick) -> Result<Self, CryptoAgilityError> {
        let name = governed.resolved_algorithm(tick)?.name.clone();
        let algorithm = match name.to_ascii_lowercase().as_str() {
            "sha-256" | "sha256" => "sha256",
            "sha-512" | "sha512" => "sha512",
            _ => return Err(CryptoAgilityError::UnsupportedAlgorithm { name }),
        };
        // Prove the resolved primitive is actually computable here, at construction — so
        // `hash()` (which must be infallible) can never hit an unimplemented policy label.
        governed.digest(b"", tick)?;
        Ok(GovernedChainHasher {
            governed,
            tick,
            algorithm,
        })
    }
}

impl ChainHasher for GovernedChainHasher {
    fn algorithm(&self) -> &'static str {
        self.algorithm
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
        // Canonical, length-prefixed encoding (same field-boundary discipline as `Sha256Hasher`),
        // then hashed through the POLICY-selected primitive rather than a direct sha2 call.
        let mut buf: Vec<u8> = Vec::new();
        let alg = self.algorithm;
        buf.extend_from_slice(&(alg.len() as u64).to_le_bytes());
        buf.extend_from_slice(alg.as_bytes());
        for field in [prev, session, actor, kind, text] {
            buf.extend_from_slice(&(field.len() as u64).to_le_bytes());
            buf.extend_from_slice(field.as_bytes());
        }
        buf.extend_from_slice(&seq.to_le_bytes());
        buf.extend_from_slice(&ts.to_le_bytes());
        // Infallible by construction: `try_new` already resolved a usable, implemented primitive,
        // and the policy snapshot + fixed `tick` cannot change, so resolution here cannot fail.
        self.governed
            .digest(&buf, self.tick)
            .expect("governed chain hasher validated at construction; policy + tick are immutable")
            .hex
    }
}

/// The persistence seam. Production (Postgres/object-store) implements this same trait; the
/// `replay*` methods are inherited as defaults, so a new backend only wires storage.
/// The health of a durable audit sink, as observed by its own *real* writes.
///
/// This exists so a readiness probe can answer "should this instance receive traffic?" without
/// writing a synthetic record. Audit is a **mandatory, fail-closed** gate: if the durable sink
/// cannot accept a write, every governed turn will be refused, so an instance in that state should
/// be taken out of a load balancer's rotation — while staying *alive*, because restarting it cannot
/// fix a full disk or a revoked permission.
///
/// Deliberately carries no detail. A readiness endpoint is unauthenticated (a load balancer cannot
/// present a token), and the underlying `io::Error` routinely names a filesystem path, which is not
/// something to hand an anonymous caller. The reason a sink is failing belongs in the daemon's own
/// log, where an authenticated operator reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SinkStatus {
    /// The most recent real append succeeded.
    Ok,
    /// The most recent real append failed. Every governed turn will now fail closed.
    Failing,
    /// This log does not track write outcomes (an in-memory or test double). Never treated as a
    /// readiness failure — absence of evidence is not evidence of a fault.
    Unknown,
}

pub trait EventLog: Send + Sync {
    fn append(
        &self,
        session: &str,
        actor: &str,
        kind: &str,
        text: &str,
    ) -> std::io::Result<LogRecord>;

    fn records(&self, session: &str) -> Vec<LogRecord>;

    /// GAP-AUDIT regulated-fi #4 — every session id this log currently holds records for, so a
    /// cadence-driven sweep (`ainxt_compliance::SinkGuard::sweep`) can cover the WHOLE log rather than
    /// one hardcoded session. Default `Vec::new()` (an in-memory/test double need not support
    /// enumeration); [`JsonlEventLog`] overrides this by listing its backing directory.
    fn sessions(&self) -> Vec<String> {
        Vec::new()
    }

    /// Recompute the chain; returns the verified record count or the first break.
    fn verify(&self, session: &str) -> Result<usize, TamperError>;

    /// Replay the tail: every record with `seq > from_seq`, in order. This is the
    /// resume backbone (`PROTOCOL.md` §7.2: `session.resume{from_event}` → "replay every event
    /// with `seq > from_event`"). `from_seq == 0` replays the full history.
    ///
    /// This is *unverified* replay (a fast reconnect path). For audit-grade replay that refuses
    /// to hand back a tampered chain, use [`replay_verified`](EventLog::replay_verified).
    fn replay(&self, session: &str, from_seq: u64) -> Vec<LogRecord> {
        self.records(session)
            .into_iter()
            .filter(|r| r.seq > from_seq)
            .collect()
    }

    /// Verify the *entire* chain first, then return the tail (`seq > from_seq`). If the log is
    /// tampered anywhere — even before the cursor — this returns the [`TamperError`] instead of
    /// replaying, so a client/auditor never receives events that differ from what was persisted
    /// (I4 / ADR-025: "replay and audit see exactly what the user saw").
    fn replay_verified(&self, session: &str, from_seq: u64) -> Result<Vec<LogRecord>, TamperError> {
        self.verify(session)?;
        Ok(self.replay(session, from_seq))
    }

    /// Cheap health view of this sink, derived from the outcome of the last real
    /// [`append`](EventLog::append) — never from a synthetic probe write, which would pollute the
    /// tamper-evident chain that is the whole point of this log.
    ///
    /// Default [`SinkStatus::Unknown`], so an implementation that does not track write outcomes
    /// (an in-memory double) is never reported as unhealthy. The composition root's
    /// `GuardedEventLog` overrides this, which is why the served daemon reports a real value.
    fn sink_status(&self) -> SinkStatus {
        SinkStatus::Unknown
    }
}

fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn safe_name(session: &str) -> String {
    session
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn read_file(dir: &Path, session: &str) -> Vec<LogRecord> {
    let path = dir.join(format!("{}.jsonl", safe_name(session)));
    let Ok(content) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<LogRecord>(l).ok())
        .collect()
}

/// File-backed event log: one append-only `{dir}/{session}.jsonl` per session. Cheaply
/// cloneable (shares the in-memory chain index + hasher config) so sessions + audit can share
/// one log. Appends use the primary [`ChainHasher`]; [`verify`](EventLog::verify) selects a
/// hasher per record by its recorded `hash_alg` from the registered verifier set.
#[derive(Clone)]
pub struct JsonlEventLog {
    dir: PathBuf,
    /// session → (last seq, last hash), loaded lazily from disk on first touch.
    index: Arc<Mutex<HashMap<String, (u64, String)>>>,
    /// The hasher used for new appends.
    primary: Arc<dyn ChainHasher>,
    /// algorithm id → hasher, used by `verify`/`replay_verified`. Always contains `primary`.
    verifiers: HashMap<String, Arc<dyn ChainHasher>>,
}

impl JsonlEventLog {
    /// Open (creating the dir if needed) with the default SHA-256 hasher.
    pub fn open(dir: impl Into<PathBuf>) -> std::io::Result<Self> {
        Self::open_with_hasher(dir, Arc::new(Sha256Hasher))
    }

    /// Open with an explicit primary [`ChainHasher`] (crypto-agility / rotation, ADR-023). The
    /// primary is automatically registered as a verifier for its own algorithm.
    pub fn open_with_hasher(
        dir: impl Into<PathBuf>,
        hasher: Arc<dyn ChainHasher>,
    ) -> std::io::Result<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        let mut verifiers: HashMap<String, Arc<dyn ChainHasher>> = HashMap::new();
        verifiers.insert(hasher.algorithm().to_string(), hasher.clone());
        Ok(JsonlEventLog {
            dir,
            index: Arc::new(Mutex::new(HashMap::new())),
            primary: hasher,
            verifiers,
        })
    }

    /// Register an additional hasher used only for *verification* — e.g. a rotated-out algorithm
    /// still present in old records. Appends continue to use the primary. Builder-style.
    ///
    /// GAP-AUDIT misc-decisions: confirmed non-gap for the shipped daemon today — see
    /// `ainxt_runtimed::open_guarded_event_log`'s doc for why (its `default_hash_policy()` is a
    /// hard-coded single-candidate registry with no runtime rotation path yet, so there is currently
    /// no old algorithm this needs to register).
    pub fn with_verifier(mut self, hasher: Arc<dyn ChainHasher>) -> Self {
        self.verifiers
            .insert(hasher.algorithm().to_string(), hasher);
        self
    }

    /// The primary algorithm id used for new appends.
    pub fn primary_algorithm(&self) -> &str {
        self.primary.algorithm()
    }
}

impl EventLog for JsonlEventLog {
    fn append(
        &self,
        session: &str,
        actor: &str,
        kind: &str,
        text: &str,
    ) -> std::io::Result<LogRecord> {
        let mut idx = self.index.lock().expect("eventlog index lock");
        if !idx.contains_key(session) {
            // Lazy load: rebuild the chain head from disk (survives process restart).
            let recs = read_file(&self.dir, session);
            let seed = recs
                .last()
                .map(|r| (r.seq, r.hash.clone()))
                .unwrap_or((0, GENESIS.to_string()));
            idx.insert(session.to_string(), seed);
        }
        let (prev_seq, prev_hash) = idx.get(session).cloned().unwrap();
        let seq = prev_seq + 1;
        let ts = now_millis();
        let hash = self
            .primary
            .hash(&prev_hash, session, seq, ts, actor, kind, text);
        let rec = LogRecord {
            session: session.to_string(),
            seq,
            ts_millis: ts,
            actor: actor.to_string(),
            kind: kind.to_string(),
            text: text.to_string(),
            prev_hash: prev_hash.clone(),
            hash: hash.clone(),
            hash_alg: self.primary.algorithm().to_string(),
        };

        let path = self.dir.join(format!("{}.jsonl", safe_name(session)));
        let mut f = OpenOptions::new().create(true).append(true).open(&path)?;
        let line = serde_json::to_string(&rec).expect("serialize record");
        f.write_all(line.as_bytes())?;
        f.write_all(b"\n")?;
        f.flush()?;

        // Only advance the in-memory head after the durable write succeeded, so a failed append
        // does not corrupt the chain seed for the next writer.
        idx.insert(session.to_string(), (seq, hash));
        Ok(rec)
    }

    fn records(&self, session: &str) -> Vec<LogRecord> {
        read_file(&self.dir, session)
    }

    /// GAP-AUDIT regulated-fi #4 — list every `{session}.jsonl` file's stem in the backing directory.
    /// Session ids that collide after [`safe_name`] sanitization are indistinguishable here (a known,
    /// documented limitation shared with `append`'s own on-disk naming) — acceptable for a defense-in-
    /// depth sweep, since `records(&stem)` reopens the SAME file this listing found.
    fn sessions(&self) -> Vec<String> {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return Vec::new();
        };
        let mut out: Vec<String> = entries
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                let path = e.path();
                if path.extension().and_then(|s| s.to_str()) == Some("jsonl") {
                    path.file_stem()
                        .and_then(|s| s.to_str())
                        .map(|s| s.to_string())
                } else {
                    None
                }
            })
            .collect();
        out.sort();
        out
    }

    fn verify(&self, session: &str) -> Result<usize, TamperError> {
        let recs = read_file(&self.dir, session);
        let mut prev = GENESIS.to_string();
        for (i, r) in recs.iter().enumerate() {
            let expect_seq = i as u64 + 1;
            if r.seq != expect_seq {
                return Err(TamperError::SeqGap {
                    expected: expect_seq,
                    found: r.seq,
                });
            }
            if r.prev_hash != prev {
                return Err(TamperError::BrokenChain { seq: r.seq });
            }
            // Crypto-agility: verify each record with the hasher that produced it.
            let Some(hasher) = self.verifiers.get(&r.hash_alg) else {
                return Err(TamperError::UnknownAlgorithm {
                    seq: r.seq,
                    algorithm: r.hash_alg.clone(),
                });
            };
            let h = hasher.hash(
                &r.prev_hash,
                &r.session,
                r.seq,
                r.ts_millis,
                &r.actor,
                &r.kind,
                &r.text,
            );
            if h != r.hash {
                return Err(TamperError::HashMismatch { seq: r.seq });
            }
            prev = r.hash.clone();
        }
        Ok(recs.len())
    }
}

// ==================== LOOP-06: durable EventSink backing for the planner ====================
//
// `ainxt-planner`'s Supervisor persists a Program's state through its [`ainxt_planner::supervisor::
// EventSink`] seam, but the only impl shipped there (`VecEventSink`) is in-memory — restart /
// model-swap / multi-week wall-clock survival was proven only as an in-memory unit test, never
// end-to-end (LOOP-06). `ProgramEventSink` closes that: it implements the planner seam on top of
// this append-only, hash-chained event log, so every `ProgramEvent` is durably persisted and a
// resume is a replay of the log (ADR-027 §4). One [`EventSink::append`] → one guarded, chained
// [`LogRecord`]; [`EventSink::load`] reloads + deserializes the whole stream from disk, so a fresh
// process (or a swapped model) resumes from exactly where the last one stopped.

use ainxt_planner::program::ProgramEvent;
use ainxt_planner::supervisor::EventSink;

/// Durable [`EventSink`] for a single Program, backed by a hash-chained [`JsonlEventLog`] session.
///
/// This is the wiring the planner's §4 durability guarantee needs: `ProgramEvent`s are serialized
/// into chained log records under one session id, so they survive process restarts and the chain
/// itself is tamper-evident. Cheaply cloneable (the log is). Re-opening a `ProgramEventSink` on the
/// same directory + session id after a restart returns the full, in-order stream via [`load`].
///
/// [`load`]: EventSink::load
#[derive(Clone)]
pub struct ProgramEventSink {
    log: JsonlEventLog,
    session: String,
    actor: String,
}

impl ProgramEventSink {
    /// Bind a Program's event stream to `session` inside `log`. `actor` is stamped on every record
    /// for the audit trail (e.g. the supervisor/program identifier).
    pub fn new(log: JsonlEventLog, session: impl Into<String>, actor: impl Into<String>) -> Self {
        ProgramEventSink {
            log,
            session: session.into(),
            actor: actor.into(),
        }
    }

    /// The session id this sink appends under.
    pub fn session(&self) -> &str {
        &self.session
    }

    /// Verify the durable chain for this Program's session (audit-grade tamper detection).
    pub fn verify(&self) -> Result<usize, TamperError> {
        EventLog::verify(&self.log, &self.session)
    }
}

impl EventSink for ProgramEventSink {
    fn append(&mut self, ev: &ProgramEvent) -> Result<u64, String> {
        // Serialize the event as the record payload; the log adds seq + hash chaining + durability.
        let text = serde_json::to_string(ev).map_err(|e| e.to_string())?;
        let rec = self
            .log
            .append(&self.session, &self.actor, "program_event", &text)
            .map_err(|e| e.to_string())?;
        // The record's monotonic seq IS the planner's event offset.
        Ok(rec.seq)
    }

    fn load(&self) -> Result<Vec<ProgramEvent>, String> {
        self.log
            .records(&self.session)
            .into_iter()
            .map(|r| serde_json::from_str::<ProgramEvent>(&r.text).map_err(|e| e.to_string()))
            .collect()
    }
}
