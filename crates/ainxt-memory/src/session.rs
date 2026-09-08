// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! The Session (Redis) working-memory tier — design §3: "Session (Redis) ... scope: this
//! conversation ... TTL: conversation length ... write: every turn ... read: this turn's history +
//! working state". Unlike the durable OKI/episodic/semantic tiers (Postgres, see [`crate::durable`]),
//! session scratch state is explicitly **never durable** (design §5 retention table: "Session
//! (Redis) | session lifetime | never durable") — it belongs behind a key-value TTL store, not a
//! relational one. This module is that seam:
//!
//! - [`SessionSeam`] — a narrow key-value port (put/get/all/evict-expired/delete-session) any
//!   Redis-shaped backend can implement (`SET key val EX ttl`, `GET key`, `SCAN`, `DEL`).
//! - [`InMemorySessionSeam`] — an offline, cloneable in-memory backend that models exactly that
//!   contract (a table with per-key expiry) so the tier's lifecycle logic is proven without a live
//!   Redis; a deployment backs [`SessionSeam`] with a real Redis client (this crate pulls no Redis
//!   dependency, mirroring how [`crate::durable::SqlLike`] pulls no database crate).
//! - [`SessionCache`] — composes the seam with the store's compliance-on-write discipline: every
//!   write still runs through redaction before it ever reaches the seam (design §8.4 "every memory
//!   write ... session, episodic, semantic, OKI"), and the right-to-erasure cascade (§5) reaches this
//!   tier too (`erase_session`).
//!
//! **Served-path wiring:** this is the clean entrypoint ([`SessionCache::write`] /
//! [`SessionCache::read_all`]) a live turn pipeline calls to persist/read scratch state (a pending
//! tool-call result, the condenser's window) for the duration of a conversation, without
//! re-implementing redaction or TTL bookkeeping. Actually calling it from the served turn loop is
//! `needs_hot_wiring` in the reserved runtime crate; the seam, its governed write discipline, and the
//! TTL/erasure lifecycle are proven here, fully offline.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::{MemoryItem, Redactor};

/// A narrow, Redis-shaped key-value port for the Session working-memory tier (design §3). Every
/// method maps 1:1 onto a single Redis command; a production backend wraps a real Redis client
/// behind this trait so the tier's lifecycle logic never depends on one.
pub trait SessionSeam: std::fmt::Debug + Send + Sync {
    /// `SET session:{session_id}:{item.id} <json> EX ttl_ticks` — write/overwrite one scratch item
    /// with an absolute expiry at `now + ttl_ticks` (logical ticks here stand in for wall-clock
    /// seconds).
    fn put(&self, session_id: &str, item: &MemoryItem, now: u64, ttl_ticks: u64);
    /// `GET session:{session_id}:{item_id}` — fetch one live (non-expired-as-of-`now`) item.
    fn get(&self, session_id: &str, item_id: &str, now: u64) -> Option<MemoryItem>;
    /// `SCAN session:{session_id}:*` — every live item in the session, in write order.
    fn all(&self, session_id: &str, now: u64) -> Vec<MemoryItem>;
    /// A periodic sweep of every key past its expiry, across all sessions — Redis does this
    /// automatically in production via per-key TTL; exposed here as an explicit, deterministic call
    /// for offline testing. Returns the count purged.
    fn evict_expired(&self, now: u64) -> usize;
    /// `DEL session:{session_id}:*` — right-to-erasure cascade reaches Redis too (design §5: "Redis
    /// (immediate)"). Returns the count removed.
    fn delete_session(&self, session_id: &str) -> usize;
}

#[derive(Debug)]
struct Entry {
    item: MemoryItem,
    expires_at: u64,
}

/// The offline, in-RAM [`SessionSeam`] test double — a behavioural model of a Redis
/// string-with-TTL store keyed by `(session_id, item_id)`. **Cheap to clone — clones share state**
/// (mirrors [`MemorySqlBackend`](crate::durable::MemorySqlBackend)'s cross-process modelling).
#[derive(Debug, Clone, Default)]
pub struct InMemorySessionSeam {
    table: Arc<Mutex<HashMap<(String, String), Entry>>>,
}

impl InMemorySessionSeam {
    /// A fresh, empty seam (models an empty Redis keyspace under this prefix).
    pub fn new() -> Self {
        Self::default()
    }
}

impl SessionSeam for InMemorySessionSeam {
    fn put(&self, session_id: &str, item: &MemoryItem, now: u64, ttl_ticks: u64) {
        let mut t = self.table.lock().expect("session seam mutex poisoned");
        t.insert(
            (session_id.to_string(), item.id.clone()),
            Entry {
                item: item.clone(),
                expires_at: now.saturating_add(ttl_ticks),
            },
        );
    }

    fn get(&self, session_id: &str, item_id: &str, now: u64) -> Option<MemoryItem> {
        let t = self.table.lock().expect("session seam mutex poisoned");
        t.get(&(session_id.to_string(), item_id.to_string()))
            .filter(|e| e.expires_at > now)
            .map(|e| e.item.clone())
    }

    fn all(&self, session_id: &str, now: u64) -> Vec<MemoryItem> {
        let t = self.table.lock().expect("session seam mutex poisoned");
        let mut out: Vec<(u64, MemoryItem)> = t
            .iter()
            .filter(|((sid, _), e)| sid == session_id && e.expires_at > now)
            .map(|(_, e)| (e.item.seq, e.item.clone()))
            .collect();
        out.sort_by_key(|(seq, _)| *seq);
        out.into_iter().map(|(_, item)| item).collect()
    }

    fn evict_expired(&self, now: u64) -> usize {
        let mut t = self.table.lock().expect("session seam mutex poisoned");
        let before = t.len();
        t.retain(|_, e| e.expires_at > now);
        before - t.len()
    }

    fn delete_session(&self, session_id: &str) -> usize {
        let mut t = self.table.lock().expect("session seam mutex poisoned");
        let before = t.len();
        t.retain(|(sid, _), _| sid != session_id);
        before - t.len()
    }
}

/// The tier's write path, composed with the mandatory compliance gate (design §8.4): every write to
/// the Session tier is redacted **before** it reaches the seam, exactly like every other tier — a
/// PAN/PII/secret in a scratch tool-call result never sits even briefly unredacted in Redis.
#[derive(Debug)]
pub struct SessionCache<S: SessionSeam> {
    seam: S,
    redactor: Box<dyn Redactor>,
}

impl<S: SessionSeam> SessionCache<S> {
    /// Compose a seam with the mandatory compliance-on-write gate (design §8.4 — session writes are
    /// never exempt from redaction just because the tier itself is ephemeral).
    pub fn new(seam: S, redactor: Box<dyn Redactor>) -> Self {
        SessionCache { seam, redactor }
    }

    /// Write one scratch item, redacted first, with a per-conversation TTL (design §3 "write: every
    /// turn"). Only [`MemoryKind::Session`](crate::MemoryKind::Session) items belong here.
    pub fn write(&self, session_id: &str, mut item: MemoryItem, now: u64, ttl_ticks: u64) {
        debug_assert_eq!(
            item.kind,
            crate::MemoryKind::Session,
            "SessionCache is for MemoryKind::Session scratch state only"
        );
        item.title = self.redactor.redact(&item.title);
        item.body = self.redactor.redact(&item.body);
        for t in item.tags.iter_mut() {
            *t = self.redactor.redact(t);
        }
        // Scratch state orders by write time (the seam's own clock), not the durable store's logical
        // clock — the two tiers are independent (design §3: session is not "layer 0 of episodic").
        item.seq = now;
        self.seam.put(session_id, &item, now, ttl_ticks);
    }

    /// Read this turn's working state (design §3 "read: this turn's history + working state").
    pub fn read_all(&self, session_id: &str, now: u64) -> Vec<MemoryItem> {
        self.seam.all(session_id, now)
    }

    /// One scratch item by id, if still live.
    pub fn get(&self, session_id: &str, item_id: &str, now: u64) -> Option<MemoryItem> {
        self.seam.get(session_id, item_id, now)
    }

    /// Right-to-erasure cascade reaches this tier too (design §5: "Redis (immediate)"). Returns the
    /// count removed.
    pub fn erase_session(&self, session_id: &str) -> usize {
        self.seam.delete_session(session_id)
    }

    /// The periodic sweep a production deployment gets for free from Redis key TTLs; exposed here so
    /// the offline test double's aging is deterministic and callable on the same cadence.
    pub fn evict_expired(&self, now: u64) -> usize {
        self.seam.evict_expired(now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MemoryKind, Provenance, Scope};

    #[derive(Debug)]
    struct StubRedactor;
    impl Redactor for StubRedactor {
        fn redact(&self, text: &str) -> String {
            text.replace("4111111111111111", "[REDACTED-PAN]")
        }
    }

    fn scratch(id: &str, body: &str) -> MemoryItem {
        MemoryItem::new(
            id,
            MemoryKind::Session,
            Scope::User("alice".into()),
            "scratch",
            body,
            Provenance::ingest(0.5),
        )
    }

    /// R15 (low, infra_gated): the Session (Redis) tier's seam — TTL expiry, compliance-on-write, and
    /// the right-to-erasure cascade — proven fully offline against [`InMemorySessionSeam`]. The live
    /// Redis backend and the served-path call site are infra/hot-wiring; this is the honest, testable
    /// slice that lives in-crate.
    #[test]
    fn r15_session_seam_ttl_expiry_and_redaction_offline() {
        let cache = SessionCache::new(InMemorySessionSeam::new(), Box::new(StubRedactor));
        // Write under compliance: PAN in body must never reach the seam.
        cache.write("sess-1", scratch("tool-1", "card 4111111111111111"), 0, 10);
        let got = cache.get("sess-1", "tool-1", 5).unwrap();
        assert!(
            !got.body.contains("4111111111111111"),
            "session write must be redacted first"
        );
        assert!(got.body.contains("[REDACTED-PAN]"));

        // TTL expiry: alive before, gone after.
        assert!(
            cache.get("sess-1", "tool-1", 9).is_some(),
            "alive before ttl elapses"
        );
        assert!(
            cache.get("sess-1", "tool-1", 10).is_none(),
            "expired at/after now+ttl"
        );

        // A second, still-live item in the same session.
        cache.write("sess-1", scratch("tool-2", "pending result"), 8, 10);
        let all_live = cache.read_all("sess-1", 10);
        assert_eq!(
            all_live.len(),
            1,
            "tool-1 already expired by tick 10; only tool-2 is live"
        );
        assert_eq!(all_live[0].id, "tool-2");

        // evict_expired sweeps expired rows out of the table entirely (production: Redis TTL does
        // this automatically; the offline seam exposes it for deterministic testing).
        assert_eq!(
            cache.evict_expired(100),
            2,
            "both rows are past expiry by tick 100"
        );

        // Right-to-erasure cascade reaches the session tier immediately (design §5).
        cache.write("sess-2", scratch("x", "y"), 0, 1000);
        assert_eq!(cache.erase_session("sess-2"), 1);
        assert!(cache.get("sess-2", "x", 0).is_none());
    }

    #[test]
    fn r15_session_seam_scoped_per_session_isolation() {
        let cache = SessionCache::new(InMemorySessionSeam::new(), Box::new(StubRedactor));
        cache.write("sess-a", scratch("k", "a-value"), 0, 100);
        cache.write("sess-b", scratch("k", "b-value"), 0, 100);
        assert_eq!(cache.get("sess-a", "k", 1).unwrap().body, "a-value");
        assert_eq!(cache.get("sess-b", "k", 1).unwrap().body, "b-value");
        cache.erase_session("sess-a");
        assert!(cache.get("sess-a", "k", 1).is_none());
        assert!(
            cache.get("sess-b", "k", 1).is_some(),
            "erasing one session must not affect another"
        );
    }
}

/// Adapts a [`SessionSeam`] to the memory crate's [`ErasureTier`](crate::ErasureTier) so a
/// right-to-erasure cascade reaches the session (Redis) tier — design §5 "Redis (immediate)".
///
/// The subject→sessions mapping is deliberately an input, not a guess: sessions are keyed by session
/// id, and only the caller (the runtime's session store) knows which belong to a data subject.
/// Passing an empty list is therefore *not* an error — it truthfully reports `removed = 0` rather
/// than silently implying the tier was clean.
#[derive(Debug)]
pub struct SessionErasureTier<'a> {
    seam: &'a dyn SessionSeam,
    sessions: Vec<String>,
}

impl<'a> SessionErasureTier<'a> {
    /// Bind a seam to the session ids owned by the subject being erased.
    pub fn new(seam: &'a dyn SessionSeam, sessions: &[&str]) -> Self {
        SessionErasureTier {
            seam,
            sessions: sessions.iter().map(|s| s.to_string()).collect(),
        }
    }
}

impl crate::ErasureTier for SessionErasureTier<'_> {
    fn tier(&self) -> &str {
        "session"
    }
    fn erase_subject(&mut self, _subject: &str) -> usize {
        self.sessions
            .iter()
            .map(|sid| self.seam.delete_session(sid))
            .sum()
    }
}
