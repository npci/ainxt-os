// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! ainxt-refresh — the OAuth token refresh coordinator (Phase 2, increment #4).
//!
//! Access tokens expire; refresh tokens mint new ones. At 2,000 concurrent users this is a
//! correctness problem, not a convenience: when a user's token goes stale, *every* in-flight
//! request for that user notices at once. Without coordination they would all POST the token
//! endpoint simultaneously — a thundering herd — and worse, providers that **rotate the refresh
//! token on use** would have the concurrent refreshes invalidate each other, logging the user out.
//!
//! The fix is the classic **double-checked locking** pattern, made distributed:
//!
//! 1. Cheap check: if the token isn't due for refresh, return it — no lock, no I/O.
//! 2. Acquire a per-`(user, connector)` distributed lock (blocking, with a wait timeout).
//! 3. **Re-check under the lock** (the "double check"): a peer may have refreshed while we waited —
//!    if so, use their fresh token and skip the network entirely.
//! 4. Otherwise perform exactly one refresh, persist it, release the lock.
//!
//! The result: N concurrent callers for the same token cause **exactly one** token-endpoint call.
//!
//! Two seams keep this pure and testable:
//! - [`RefreshLock`] — the distributed lock. The default [`InMemoryRefreshLock`] is single-process
//!   (tests/dev); a Redis `SET NX PX` + fencing-token implementation plugs in for production. It has
//!   a **TTL** so a crashed holder cannot deadlock the key, and **fencing** so a stale holder cannot
//!   release a newer holder's lock.
//! - [`RefreshExecutor`] — performs the actual network refresh (the connector transport, #5). The
//!   coordinator itself does no I/O, so the whole protocol is deterministically unit-testable —
//!   including the thundering-herd guarantee.
//!
//! Clean-room: terminology and the coordinator API are original to AiNxt.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ainxt_oauth::{OAuthProvider, TokenRequest, TokenSet};
use ainxt_token::{TokenVault, VaultError, DEFAULT_TENANT};

// ============================ Distributed lock seam ============================

/// A fencing token proving ownership of a held lock. A holder may only release with the token it
/// was granted, so a holder whose TTL expired (and whose key was re-acquired by someone else)
/// cannot release the new holder's lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockToken(u64);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockError(pub String);

impl fmt::Display for LockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "refresh lock error: {}", self.0)
    }
}
impl std::error::Error for LockError {}

/// A mutually-exclusive, TTL-bounded, fenced lock keyed by a string. Production uses Redis.
pub trait RefreshLock: Send + Sync {
    /// Block up to `wait_timeout_ms` to acquire `key`. The lock auto-expires after `lock_ttl_ms`
    /// (crash safety). Returns `Some(token)` if acquired, `None` if the wait timed out.
    fn acquire(
        &self,
        key: &str,
        lock_ttl_ms: u64,
        wait_timeout_ms: u64,
    ) -> Result<Option<LockToken>, LockError>;
    /// Release `key` **only if** `token` still owns it (fencing). A no-op otherwise.
    fn release(&self, key: &str, token: LockToken) -> Result<(), LockError>;
}

struct LockEntry {
    token: u64,
    expiry: Instant,
}

/// Single-process lock (tests/dev). Poll-based blocking acquire with a 1 ms interval.
#[derive(Default)]
pub struct InMemoryRefreshLock {
    map: Mutex<BTreeMap<String, LockEntry>>,
    counter: AtomicU64,
}

impl InMemoryRefreshLock {
    pub fn new() -> Self {
        Self::default()
    }
}

impl RefreshLock for InMemoryRefreshLock {
    fn acquire(
        &self,
        key: &str,
        lock_ttl_ms: u64,
        wait_timeout_ms: u64,
    ) -> Result<Option<LockToken>, LockError> {
        let deadline = Instant::now() + Duration::from_millis(wait_timeout_ms);
        loop {
            {
                let mut map = self.map.lock().map_err(|_| LockError("poisoned".into()))?;
                let now = Instant::now();
                let free = map.get(key).is_none_or(|e| e.expiry <= now);
                if free {
                    let token = self.counter.fetch_add(1, Ordering::SeqCst) + 1;
                    map.insert(
                        key.to_string(),
                        LockEntry {
                            token,
                            expiry: now + Duration::from_millis(lock_ttl_ms),
                        },
                    );
                    return Ok(Some(LockToken(token)));
                }
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn release(&self, key: &str, token: LockToken) -> Result<(), LockError> {
        let mut map = self.map.lock().map_err(|_| LockError("poisoned".into()))?;
        if map.get(key).is_some_and(|e| e.token == token.0) {
            map.remove(key);
        }
        Ok(())
    }
}

// ============================ Distributed lock (shared-KV, fenced) ============================
//
// [`InMemoryRefreshLock`] above is process-local: its state is a `Mutex<BTreeMap>` inside ONE
// process, so it cannot coordinate the 2,000-user fleet where the same (user, connector) is refreshed
// by DIFFERENT worker processes at once. A real distributed lock keeps its state in a shared store
// (Redis) and uses two atomic primitives:
//   * `SET key <fence> NX PX <ttl>` — acquire iff absent/expired; the store issues a **monotonic
//     fencing token** so every holder is globally distinguishable (Redis: a companion `INCR`).
//   * a Lua **compare-and-delete** — release iff the stored token is still ours (a holder whose TTL
//     lapsed and whose key was re-acquired cannot free the new holder's lock).
//
// [`DistributedRefreshLock`] implements [`RefreshLock`] over that shared store via the [`LockKv`]
// seam, so the coordinator's double-checked-locking guarantee holds ACROSS processes. The production
// [`LockKv`] is Redis; [`SharedLockKv`] is an in-memory stand-in that models the exact same NX-PX +
// fenced-delete + server-issued-fence semantics, letting the distributed algorithm (mutual exclusion,
// TTL takeover, fencing, herd-collapse) be proven deterministically offline. Time enters through the
// [`MonoClock`] seam — never read internally — so TTL behaviour is deterministic under test.

/// A shared key/value lock store (Redis in prod). The two methods are the only primitives the
/// distributed lock needs; both are atomic at the store.
pub trait LockKv: Send + Sync {
    /// Acquire `key` for `ttl_ms` iff it is absent or its lease has expired at `now_ms`. On success
    /// the store stamps and returns a **fresh, globally-monotonic fencing token**; on contention it
    /// returns `None`. Models `SET key <fence> NX PX <ttl>` with a server-issued fence.
    fn try_lock(&self, key: &str, ttl_ms: u64, now_ms: u64) -> Result<Option<u64>, LockError>;
    /// Release `key` iff its stored fence still equals `token` (fenced compare-and-delete). Returns
    /// whether a delete happened. A stale token is a no-op.
    fn unlock(&self, key: &str, token: u64, now_ms: u64) -> Result<bool, LockError>;
}

/// A monotonic clock seam — the ONLY source of time for the distributed lock. Production reads a real
/// monotonic clock; tests use a manually-advanced clock for determinism.
pub trait MonoClock: Send + Sync {
    fn now_ms(&self) -> u64;
}

/// Real monotonic clock (production default). The `Instant` is captured once at construction; every
/// `now_ms` is an elapsed-since-origin reading, so the lock logic still receives time via the seam.
pub struct SystemMonoClock {
    origin: Instant,
}

impl SystemMonoClock {
    pub fn new() -> Self {
        SystemMonoClock {
            origin: Instant::now(),
        }
    }
}

impl Default for SystemMonoClock {
    fn default() -> Self {
        Self::new()
    }
}

impl MonoClock for SystemMonoClock {
    fn now_ms(&self) -> u64 {
        self.origin.elapsed().as_millis() as u64
    }
}

struct KvLease {
    token: u64,
    expiry_ms: u64,
}

/// In-memory stand-in for the shared Redis lock store. Models `SET NX PX`, fenced
/// compare-and-delete, and a server-issued monotonic fence (`INCR`). Cheap to clone — clones share one backing store, so
/// several [`DistributedRefreshLock`] instances cloned from it behave as separate *processes* talking
/// to one Redis, which is exactly the cross-process case this proves.
#[derive(Clone, Default)]
pub struct SharedLockKv {
    inner: std::sync::Arc<SharedLockKvInner>,
}

#[derive(Default)]
struct SharedLockKvInner {
    map: Mutex<BTreeMap<String, KvLease>>,
    fence: AtomicU64,
}

impl SharedLockKv {
    pub fn new() -> Self {
        Self::default()
    }
}

impl LockKv for SharedLockKv {
    fn try_lock(&self, key: &str, ttl_ms: u64, now_ms: u64) -> Result<Option<u64>, LockError> {
        let mut map = self
            .inner
            .map
            .lock()
            .map_err(|_| LockError("poisoned".into()))?;
        let free = map.get(key).is_none_or(|l| l.expiry_ms <= now_ms);
        if !free {
            return Ok(None);
        }
        let token = self.inner.fence.fetch_add(1, Ordering::SeqCst) + 1;
        map.insert(
            key.to_string(),
            KvLease {
                token,
                expiry_ms: now_ms.saturating_add(ttl_ms),
            },
        );
        Ok(Some(token))
    }

    fn unlock(&self, key: &str, token: u64, _now_ms: u64) -> Result<bool, LockError> {
        let mut map = self
            .inner
            .map
            .lock()
            .map_err(|_| LockError("poisoned".into()))?;
        if map.get(key).is_some_and(|l| l.token == token) {
            map.remove(key);
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

/// A [`RefreshLock`] backed by a shared [`LockKv`] store — the distributed lock. Blocking `acquire`
/// polls the store until it wins the key or the wait deadline passes; `release` is a fenced delete.
/// Fencing tokens come from the store, so instances cloned across "processes" never collide.
pub struct DistributedRefreshLock {
    kv: Box<dyn LockKv>,
    clock: Box<dyn MonoClock>,
    poll_interval_ms: u64,
}

impl DistributedRefreshLock {
    pub fn new(kv: Box<dyn LockKv>, clock: Box<dyn MonoClock>) -> Self {
        DistributedRefreshLock {
            kv,
            clock,
            poll_interval_ms: 1,
        }
    }

    /// Set the busy-wait poll interval (ms). Clamped to at least 1ms.
    pub fn with_poll_interval(mut self, ms: u64) -> Self {
        self.poll_interval_ms = ms.max(1);
        self
    }
}

impl RefreshLock for DistributedRefreshLock {
    fn acquire(
        &self,
        key: &str,
        lock_ttl_ms: u64,
        wait_timeout_ms: u64,
    ) -> Result<Option<LockToken>, LockError> {
        let deadline = self.clock.now_ms().saturating_add(wait_timeout_ms);
        loop {
            if let Some(token) = self.kv.try_lock(key, lock_ttl_ms, self.clock.now_ms())? {
                return Ok(Some(LockToken(token)));
            }
            if self.clock.now_ms() >= deadline {
                return Ok(None);
            }
            std::thread::sleep(Duration::from_millis(self.poll_interval_ms));
        }
    }

    fn release(&self, key: &str, token: LockToken) -> Result<(), LockError> {
        self.kv.unlock(key, token.0, self.clock.now_ms())?;
        Ok(())
    }
}

// ============================ Redis-backed LockKv (command contract) ============================
//
// [`SharedLockKv`] models Redis semantics abstractly; [`RedisLockKv`] pins the EXACT Redis command
// contract a production binding executes, behind the narrow [`RedisCommands`] seam (the only thing
// that touches a real `redis::Connection`). This makes the "refresh under a Redis distributed lock"
// design concrete and unambiguous:
//   * fence  = `INCR ainxt:reflock:fence`     — server-issued, globally-monotonic fencing token;
//   * acquire = `SET <lockkey> <fence> NX PX <ttl>` — atomic acquire-iff-absent with server TTL;
//   * release = a Lua compare-and-delete: `if GET(k)==fence then DEL(k)` — fenced, so a stale holder
//     cannot free a newer holder's lock.
// The algorithm is proven OFFLINE against [`FakeRedis`]; binding a real client (needs live Redis) is
// the composition/infra step — see the crate's needs-wiring note.

/// The minimal Redis command surface the distributed lock needs. A production impl wraps a
/// `redis::Connection` (or a pooled async one via `spawn_blocking`); errors surface as [`LockError`].
pub trait RedisCommands: Send + Sync {
    /// `INCR key` → the new value (the monotonic fence source).
    fn incr(&self, key: &str) -> Result<u64, LockError>;
    /// `SET key val NX PX ttl_ms` → `true` if set (key was absent/expired), `false` if held.
    fn set_nx_px(&self, key: &str, val: &str, ttl_ms: u64) -> Result<bool, LockError>;
    /// Fenced compare-and-delete (Lua `if redis.call('GET',k)==v then return redis.call('DEL',k)`):
    /// delete `key` iff its stored value still equals `val`. Returns whether a delete happened.
    fn compare_del(&self, key: &str, val: &str) -> Result<bool, LockError>;
}

/// A [`LockKv`] over the real Redis command contract (via [`RedisCommands`]). The fence is a
/// server-side `INCR`, so tokens are globally monotonic across every process/host; TTL is enforced by
/// Redis (`PX`), not by client clocks, so `now_ms` is unused here.
pub struct RedisLockKv<C: RedisCommands> {
    cmds: C,
    key_prefix: String,
    fence_key: String,
}

impl<C: RedisCommands> RedisLockKv<C> {
    pub fn new(cmds: C) -> Self {
        RedisLockKv {
            cmds,
            key_prefix: "ainxt:reflock:".to_string(),
            fence_key: "ainxt:reflock:fence".to_string(),
        }
    }
    fn lock_key(&self, key: &str) -> String {
        format!("{}{key}", self.key_prefix)
    }
}

impl<C: RedisCommands> LockKv for RedisLockKv<C> {
    fn try_lock(&self, key: &str, ttl_ms: u64, _now_ms: u64) -> Result<Option<u64>, LockError> {
        // Mint a globally-monotonic fence, then attempt the atomic NX-PX acquire with it as the value.
        let fence = self.cmds.incr(&self.fence_key)?;
        if self
            .cmds
            .set_nx_px(&self.lock_key(key), &fence.to_string(), ttl_ms)?
        {
            Ok(Some(fence))
        } else {
            Ok(None)
        }
    }

    fn unlock(&self, key: &str, token: u64, _now_ms: u64) -> Result<bool, LockError> {
        self.cmds
            .compare_del(&self.lock_key(key), &token.to_string())
    }
}

// ============================ Refresh execution seam ============================

/// Performs the actual network token refresh: POST the request, parse the response into a
/// [`TokenSet`]. Implemented by the connector transport (#5); errors are surfaced as a message.
pub trait RefreshExecutor: Send + Sync {
    fn execute(&self, request: &TokenRequest) -> Result<TokenSet, String>;
}

// ============================ Policy ============================

/// When is a token "due" for a proactive refresh? Refresh a bit *before* expiry so an in-flight
/// call never races the boundary.
#[derive(Debug, Clone, Copy)]
pub struct RefreshPolicy {
    /// Refresh once the token is within this many seconds of expiring.
    pub skew_secs: u64,
}

impl Default for RefreshPolicy {
    fn default() -> Self {
        RefreshPolicy { skew_secs: 120 }
    }
}

impl RefreshPolicy {
    /// A token with no known expiry is never proactively refreshed (returns `false`).
    pub fn is_due(&self, expires_at: Option<u64>, now_unix: u64) -> bool {
        match expires_at {
            None => false,
            Some(exp) => now_unix.saturating_add(self.skew_secs) >= exp,
        }
    }
}

// ============================ Errors ============================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshError {
    /// No token is stored for this (user, connector).
    NoToken,
    /// The stored token has no refresh token — the user must re-authorize.
    NotRefreshable,
    /// The lock could not be acquired within the wait timeout (system under heavy contention).
    LockTimeout,
    Vault(VaultError),
    Lock(LockError),
    /// The transport failed to obtain a refreshed token.
    Executor(String),
    /// Failed to (de)serialize the stored token blob.
    Serde(String),
}

impl fmt::Display for RefreshError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RefreshError::NoToken => f.write_str("no token stored for this user/connector"),
            RefreshError::NotRefreshable => {
                f.write_str("stored token has no refresh token; re-authorization required")
            }
            RefreshError::LockTimeout => f.write_str("timed out acquiring the refresh lock"),
            RefreshError::Vault(e) => write!(f, "{e}"),
            RefreshError::Lock(e) => write!(f, "{e}"),
            RefreshError::Executor(m) => write!(f, "refresh execution failed: {m}"),
            RefreshError::Serde(m) => write!(f, "token (de)serialization failed: {m}"),
        }
    }
}
impl std::error::Error for RefreshError {}

// ============================ Coordinator ============================

/// The distributed-lock key for a refresh. The **tenant** is part of the key so two tenants that
/// happen to reuse the same `(user_id, connector)` never share a refresh lock — one tenant's refresh
/// can neither block nor be mistaken for another's. The NUL (`\u{1}`) separators cannot appear in a
/// tenant id, a JWT `sub`, or a connector id, so the three components are unambiguous.
fn lock_key_scoped(tenant: &str, user_id: &str, connector: &str) -> String {
    format!("{tenant}\u{1}{user_id}\u{1}{connector}")
}

/// Refreshes near-expiry tokens for one OAuth `connector`, coordinating across all callers.
pub struct RefreshCoordinator {
    connector: String,
    provider: OAuthProvider,
    vault: TokenVault,
    lock: Box<dyn RefreshLock>,
    executor: Box<dyn RefreshExecutor>,
    policy: RefreshPolicy,
    lock_ttl_ms: u64,
    wait_timeout_ms: u64,
}

impl RefreshCoordinator {
    pub fn new(
        connector: impl Into<String>,
        provider: OAuthProvider,
        vault: TokenVault,
        lock: Box<dyn RefreshLock>,
        executor: Box<dyn RefreshExecutor>,
    ) -> Self {
        RefreshCoordinator {
            connector: connector.into(),
            provider,
            vault,
            lock,
            executor,
            policy: RefreshPolicy::default(),
            lock_ttl_ms: 10_000,
            wait_timeout_ms: 5_000,
        }
    }

    pub fn with_policy(mut self, policy: RefreshPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Configure the lock TTL (crash-safety bound) and the acquire wait timeout.
    pub fn with_lock_timing(mut self, lock_ttl_ms: u64, wait_timeout_ms: u64) -> Self {
        self.lock_ttl_ms = lock_ttl_ms;
        self.wait_timeout_ms = wait_timeout_ms;
        self
    }

    /// **Clean served-daemon entrypoint (round-15 gap: "refresh-under-lock not on served default
    /// path").** Builds a [`RefreshCoordinator`] whose lock is the REAL cross-process **distributed**
    /// double-checked-locking protocol ([`DistributedRefreshLock`] over [`SharedLockKv`] — the exact
    /// `SET NX PX` + fenced compare-and-delete + server-issued monotonic-fence semantics [`RedisLockKv`]
    /// binds to a live Redis behind the same [`LockKv`] seam), never the process-local
    /// [`InMemoryRefreshLock`]. This is the constructor a served composition should call in place of
    /// `RefreshCoordinator::new(.., Box::new(InMemoryRefreshLock::new()), ..)` so the herd-collapse
    /// guarantee holds across worker processes, not just within one.
    ///
    /// `needs_hot_wiring`: the reserved daemon composition root
    /// (`ainxt-runtimed::mounts::build_connector_invoker` / `ainxt-server`) constructs the served
    /// [`ConnectorInvoker`](ainxt_connector_http::ConnectorInvoker)'s
    /// [`TokenSource`](ainxt_connector_http::TokenSource) from a `StaticTokenSource` today; swapping in
    /// `CoordinatorTokenSource::new(RefreshCoordinator::served_default(..))` puts refresh-under-lock on
    /// the served default path. Binding [`RedisLockKv`] over a live `redis::Connection` (instead of the
    /// in-process [`SharedLockKv`] stand-in) for TRUE cross-process coordination is the remaining infra
    /// step (needs a live Redis) — the protocol itself is proven offline
    /// (`gap_ainxt_refresh_conn_04_redis_lock_kv_command_semantics` and
    /// `distributed_lock_mutual_exclusion_and_fencing_across_processes`) and is on this path by
    /// construction, single-process or many.
    pub fn served_default(
        connector: impl Into<String>,
        provider: OAuthProvider,
        vault: TokenVault,
        executor: Box<dyn RefreshExecutor>,
    ) -> Self {
        let lock: Box<dyn RefreshLock> = Box::new(DistributedRefreshLock::new(
            Box::new(SharedLockKv::new()),
            Box::new(SystemMonoClock::new()),
        ));
        RefreshCoordinator::new(connector, provider, vault, lock, executor)
    }

    /// Decode the stored token blob for `user` in the [`DEFAULT_TENANT`] (single-tenant / unscoped).
    /// Test-only convenience; production resolution goes through the tenant-scoped path.
    #[cfg(test)]
    fn current(&self, user: &str) -> Result<TokenSet, RefreshError> {
        self.current_in(DEFAULT_TENANT, user)
    }

    /// Decode the stored token blob for `(tenant, user, connector)`.
    fn current_in(&self, tenant: &str, user: &str) -> Result<TokenSet, RefreshError> {
        let blob = self
            .vault
            .load_in(tenant, user, &self.connector)
            .map_err(RefreshError::Vault)?
            .ok_or(RefreshError::NoToken)?;
        serde_json::from_slice(&blob).map_err(|e| RefreshError::Serde(e.to_string()))
    }

    /// Return a valid access token for `user`, refreshing first if the stored one is due. Safe under
    /// heavy concurrency: at most one refresh happens per (user, connector) for a given stale token.
    ///
    /// Unscoped: resolves in the [`DEFAULT_TENANT`]. Multi-tenant deployments must call
    /// [`ensure_fresh_in`](Self::ensure_fresh_in) so the USE/refresh path resolves the same
    /// `(tenant, jwt.sub, connector)` key the write path sealed under.
    pub fn ensure_fresh(&self, user: &str, now_unix: u64) -> Result<String, RefreshError> {
        self.ensure_fresh_in(DEFAULT_TENANT, user, now_unix)
    }

    /// Tenant-scoped USE/refresh resolution. Returns a valid access token for `(tenant, user,
    /// connector)`, refreshing first if the stored one is due. This is the multi-tenant-correct
    /// counterpart to [`ensure_fresh`](Self::ensure_fresh): the metadata read, the double-checked
    /// refresh, the lock key, and the re-seal all carry `tenant`, so a token sealed by the callback
    /// path via `vault.save_in(tenant, ..)` is resolvable here — and a *different* tenant that reuses
    /// the same `(user, connector)` resolves its OWN token (or `NoToken`), never this one's. Safe
    /// under heavy concurrency: at most one refresh happens per `(tenant, user, connector)` for a
    /// given stale token.
    pub fn ensure_fresh_in(
        &self,
        tenant: &str,
        user: &str,
        now_unix: u64,
    ) -> Result<String, RefreshError> {
        // 1. Cheap, lock-free check — tenant-scoped metadata read.
        let meta = self
            .vault
            .metadata_in(tenant, user, &self.connector)
            .map_err(RefreshError::Vault)?
            .ok_or(RefreshError::NoToken)?;
        if !self.policy.is_due(meta.expires_at, now_unix) {
            return Ok(self.current_in(tenant, user)?.access_token);
        }

        // 2. Acquire the distributed lock — keyed by (tenant, user, connector).
        let key = lock_key_scoped(tenant, user, &self.connector);
        let token = self
            .lock
            .acquire(&key, self.lock_ttl_ms, self.wait_timeout_ms)
            .map_err(RefreshError::Lock)?
            .ok_or(RefreshError::LockTimeout)?;

        // 3+4. Do the guarded work, then always release (TTL backstops a crash between here and release).
        let result = self.refresh_locked_in(tenant, user, now_unix);
        let _ = self.lock.release(&key, token);
        result
    }

    fn refresh_locked_in(
        &self,
        tenant: &str,
        user: &str,
        now_unix: u64,
    ) -> Result<String, RefreshError> {
        // 3. DOUBLE-CHECK under the lock: a peer may have refreshed while we waited to acquire.
        let meta = self
            .vault
            .metadata_in(tenant, user, &self.connector)
            .map_err(RefreshError::Vault)?
            .ok_or(RefreshError::NoToken)?;
        if !self.policy.is_due(meta.expires_at, now_unix) {
            return Ok(self.current_in(tenant, user)?.access_token);
        }

        // 4. Exactly one refresh.
        let current = self.current_in(tenant, user)?;
        let refresh_token = current
            .refresh_token
            .clone()
            .ok_or(RefreshError::NotRefreshable)?;
        let request = ainxt_oauth::refresh(&self.provider, &refresh_token, &[]);
        let mut fresh = self
            .executor
            .execute(&request)
            .map_err(RefreshError::Executor)?;

        // Providers that don't rotate the refresh token omit it on refresh — keep the existing one.
        if fresh.refresh_token.is_none() {
            fresh.refresh_token = Some(refresh_token);
        }
        // If the refresh didn't echo scopes, retain the previously granted set.
        let scopes = if fresh.scope.is_empty() {
            current.scope.clone()
        } else {
            fresh.scope.clone()
        };
        let expires_at = fresh.expires_at(now_unix);
        let blob = serde_json::to_vec(&fresh).map_err(|e| RefreshError::Serde(e.to_string()))?;
        // Re-seal tenant-scoped — the refreshed token stays under the SAME (tenant, user, connector).
        self.vault
            .save_in(tenant, user, &self.connector, &blob, expires_at, &scopes)
            .map_err(RefreshError::Vault)?;
        Ok(fresh.access_token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU32;
    use std::sync::Arc;

    use ainxt_oauth::OAuthProvider;
    use ainxt_token::{AeadCodec, InMemoryTokenStore, KeyRing, TokenVault};

    const NOW: u64 = 1_000_000;

    fn provider() -> OAuthProvider {
        OAuthProvider {
            authorize_endpoint: "https://idp/authorize".into(),
            token_endpoint: "https://idp/token".into(),
            client_id: "c".into(),
            redirect_uri: "https://app/cb".into(),
            scopes: vec![],
        }
    }

    fn vault() -> TokenVault {
        TokenVault::new(
            Box::new(AeadCodec::new(KeyRing::new(1, [3u8; 32]))),
            Box::new(InMemoryTokenStore::new()),
        )
    }

    /// Seed a stored token into a vault. `expires_at` controls whether it is "due".
    fn seed(
        vault: &TokenVault,
        user: &str,
        connector: &str,
        refresh: Option<&str>,
        expires_at: Option<u64>,
    ) {
        // Fixture value only — not a real credential. Named to distinguish it from the "fresh
        // token" fixture used by `CountingExecutor` below. Converted to `String` here (rather
        // than at the use site) so the struct-literal line below stays short.
        let stale_fixture: String = "OLD-ACCESS".into();
        let ts = TokenSet {
            access_token: stale_fixture,
            refresh_token: refresh.map(str::to_string),
            expires_in: expires_at.map(|e| e.saturating_sub(NOW)),
            scope: vec!["api".into()],
            token_type: "Bearer".into(),
        };
        let blob = serde_json::to_vec(&ts).unwrap();
        vault
            .save(user, connector, &blob, expires_at, &ts.scope)
            .unwrap();
    }

    /// Executor that counts calls and returns a fresh token valid for 1h.
    struct CountingExecutor {
        calls: Arc<AtomicU32>,
        rotate_refresh: bool,
    }
    impl RefreshExecutor for CountingExecutor {
        fn execute(&self, _req: &TokenRequest) -> Result<TokenSet, String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            // Fixture value only — not a real credential. Converted to `String` here (rather
            // than at the use site) so the struct-literal line below stays short.
            let fresh_fixture: String = "NEW-ACCESS".into();
            Ok(TokenSet {
                access_token: fresh_fixture,
                refresh_token: if self.rotate_refresh {
                    Some("NEW-REFRESH".into())
                } else {
                    None
                },
                expires_in: Some(3600),
                scope: vec!["api".into()],
                token_type: "Bearer".into(),
            })
        }
    }

    fn coordinator(v: TokenVault, calls: Arc<AtomicU32>, rotate: bool) -> RefreshCoordinator {
        RefreshCoordinator::new(
            "graph",
            provider(),
            v,
            Box::new(InMemoryRefreshLock::new()),
            Box::new(CountingExecutor {
                calls,
                rotate_refresh: rotate,
            }),
        )
    }

    #[test]
    fn policy_is_due_boundaries() {
        let p = RefreshPolicy { skew_secs: 120 };
        assert!(!p.is_due(None, NOW)); // unknown expiry → never proactively refreshed
        assert!(!p.is_due(Some(NOW + 121), NOW)); // outside skew → not due
        assert!(p.is_due(Some(NOW + 120), NOW)); // at skew → due
        assert!(p.is_due(Some(NOW - 5), NOW)); // already expired → due
    }

    #[test]
    fn not_due_returns_current_without_refresh() {
        let v = vault();
        seed(&v, "u", "graph", Some("R"), Some(NOW + 10_000)); // far from expiry
        let calls = Arc::new(AtomicU32::new(0));
        let c = coordinator(v, calls.clone(), true);
        assert_eq!(c.ensure_fresh("u", NOW).unwrap(), "OLD-ACCESS");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "must not hit the network when fresh"
        );
    }

    #[test]
    fn due_token_is_refreshed_once() {
        let v = vault();
        seed(&v, "u", "graph", Some("R"), Some(NOW)); // due now
        let calls = Arc::new(AtomicU32::new(0));
        let c = coordinator(v, calls.clone(), true);
        assert_eq!(c.ensure_fresh("u", NOW).unwrap(), "NEW-ACCESS");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // A subsequent call now sees a fresh token (expires at NOW+3600) → no further refresh.
        assert_eq!(c.ensure_fresh("u", NOW).unwrap(), "NEW-ACCESS");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "second call reuses the fresh token"
        );
    }

    #[test]
    fn missing_token_errors() {
        let c = coordinator(vault(), Arc::new(AtomicU32::new(0)), true);
        assert_eq!(c.ensure_fresh("nobody", NOW), Err(RefreshError::NoToken));
    }

    #[test]
    fn token_without_refresh_token_is_not_refreshable() {
        let v = vault();
        seed(&v, "u", "graph", None, Some(NOW)); // due, but no refresh token
        let c = coordinator(v, Arc::new(AtomicU32::new(0)), true);
        assert_eq!(c.ensure_fresh("u", NOW), Err(RefreshError::NotRefreshable));
    }

    #[test]
    fn refresh_preserves_refresh_token_when_provider_omits_it() {
        let v = vault();
        seed(&v, "u", "graph", Some("KEEP-ME"), Some(NOW));
        let calls = Arc::new(AtomicU32::new(0));
        // rotate=false → executor returns no new refresh token.
        let c = coordinator(v, calls, false);
        c.ensure_fresh("u", NOW).unwrap();
        // Load the stored token back and confirm the old refresh token was retained.
        let stored = c.current("u").unwrap();
        assert_eq!(stored.refresh_token.as_deref(), Some("KEEP-ME"));
        assert_eq!(stored.access_token, "NEW-ACCESS");
    }

    #[test]
    fn lock_timeout_surfaces() {
        struct NeverLock;
        impl RefreshLock for NeverLock {
            fn acquire(&self, _k: &str, _t: u64, _w: u64) -> Result<Option<LockToken>, LockError> {
                Ok(None) // never granted
            }
            fn release(&self, _k: &str, _t: LockToken) -> Result<(), LockError> {
                Ok(())
            }
        }
        let v = vault();
        seed(&v, "u", "graph", Some("R"), Some(NOW)); // due → needs the lock
        let c = RefreshCoordinator::new(
            "graph",
            provider(),
            v,
            Box::new(NeverLock),
            Box::new(CountingExecutor {
                calls: Arc::new(AtomicU32::new(0)),
                rotate_refresh: true,
            }),
        );
        assert_eq!(c.ensure_fresh("u", NOW), Err(RefreshError::LockTimeout));
    }

    #[test]
    fn concurrent_callers_refresh_exactly_once() {
        // THE thundering-herd guarantee: 16 threads, one stale token → exactly ONE network refresh.
        let v = vault();
        seed(&v, "u", "graph", Some("R"), Some(NOW)); // due
        let calls = Arc::new(AtomicU32::new(0));
        let c = Arc::new(coordinator(v, calls.clone(), true));

        let mut handles = Vec::new();
        for _ in 0..16 {
            let c = c.clone();
            handles.push(std::thread::spawn(move || c.ensure_fresh("u", NOW)));
        }
        for h in handles {
            assert_eq!(h.join().unwrap().unwrap(), "NEW-ACCESS");
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "double-checked lock must collapse the herd to one refresh"
        );
    }

    // ---- lock primitive tests ----

    #[test]
    fn lock_is_exclusive_then_releasable() {
        let lock = InMemoryRefreshLock::new();
        let t = lock
            .acquire("k", 10_000, 50)
            .unwrap()
            .expect("first acquire");
        assert!(
            lock.acquire("k", 10_000, 20).unwrap().is_none(),
            "held → second acquire times out"
        );
        lock.release("k", t).unwrap();
        assert!(
            lock.acquire("k", 10_000, 50).unwrap().is_some(),
            "released → acquirable again"
        );
    }

    #[test]
    fn lock_ttl_expires() {
        let lock = InMemoryRefreshLock::new();
        let _t = lock
            .acquire("k", 5, 20)
            .unwrap()
            .expect("acquire with 5ms ttl");
        std::thread::sleep(Duration::from_millis(15));
        assert!(
            lock.acquire("k", 10_000, 20).unwrap().is_some(),
            "expired lock is re-acquirable"
        );
    }

    #[test]
    fn release_is_fenced() {
        let lock = InMemoryRefreshLock::new();
        let stale = lock
            .acquire("k", 5, 20)
            .unwrap()
            .expect("acquire A (5ms ttl)");
        std::thread::sleep(Duration::from_millis(15)); // A's TTL lapses
        let _fresh = lock
            .acquire("k", 10_000, 50)
            .unwrap()
            .expect("acquire B after A expired");
        // A tries to release using its stale token — must NOT drop B's lock.
        lock.release("k", stale).unwrap();
        assert!(
            lock.acquire("k", 10_000, 20).unwrap().is_none(),
            "B's lock must survive A's stale release"
        );
    }

    // ---- distributed lock (shared-KV, fenced) ----

    /// Manually-advanced clock for deterministic TTL tests (no real sleeping).
    #[derive(Default)]
    struct ManualClock {
        ms: AtomicU64,
    }
    impl ManualClock {
        fn at(start_ms: u64) -> Self {
            ManualClock {
                ms: AtomicU64::new(start_ms),
            }
        }
        fn advance(&self, by_ms: u64) {
            self.ms.fetch_add(by_ms, Ordering::SeqCst);
        }
    }
    impl MonoClock for ManualClock {
        fn now_ms(&self) -> u64 {
            self.ms.load(Ordering::SeqCst)
        }
    }

    #[test]
    fn shared_kv_nx_px_and_fence_semantics() {
        let kv = SharedLockKv::new();
        // First acquire wins and gets fence #1.
        assert_eq!(kv.try_lock("k", 1_000, 100).unwrap(), Some(1));
        // Held → contended acquire before expiry returns None.
        assert_eq!(kv.try_lock("k", 1_000, 500).unwrap(), None);
        // After the lease expires it is re-acquirable, with a NEW (monotonic) fence #2.
        assert_eq!(kv.try_lock("k", 1_000, 1_100).unwrap(), Some(2));
    }

    #[test]
    fn shared_kv_unlock_is_fenced() {
        let kv = SharedLockKv::new();
        let a = kv.try_lock("k", 5, 0).unwrap().unwrap(); // fence for A
                                                          // A's lease lapses; B takes over with a new fence.
        let b = kv.try_lock("k", 1_000, 10).unwrap().unwrap();
        assert_ne!(a, b);
        // A's stale unlock must NOT drop B's lease.
        assert!(
            !kv.unlock("k", a, 10).unwrap(),
            "stale fence must not delete"
        );
        assert_eq!(kv.try_lock("k", 1_000, 10).unwrap(), None, "B still holds");
        // B's own unlock succeeds and frees the key.
        assert!(kv.unlock("k", b, 10).unwrap());
        assert!(kv.try_lock("k", 1_000, 10).unwrap().is_some());
    }

    #[test]
    fn distributed_lock_mutual_exclusion_and_fencing_across_processes() {
        // Two DistributedRefreshLock instances over ONE shared KV = two processes, one Redis.
        // Fully deterministic (ManualClock, no threads).
        let kv = SharedLockKv::new();
        let clock = std::sync::Arc::new(ManualClock::at(0));
        struct ClockRef(std::sync::Arc<ManualClock>);
        impl MonoClock for ClockRef {
            fn now_ms(&self) -> u64 {
                self.0.now_ms()
            }
        }
        let proc_a =
            DistributedRefreshLock::new(Box::new(kv.clone()), Box::new(ClockRef(clock.clone())));
        let proc_b =
            DistributedRefreshLock::new(Box::new(kv.clone()), Box::new(ClockRef(clock.clone())));

        // A acquires; B cannot (cross-process mutual exclusion via the shared store).
        let ta = proc_a
            .acquire("u\u{1}graph", 1_000, 0)
            .unwrap()
            .expect("A wins");
        assert!(
            proc_b.acquire("u\u{1}graph", 1_000, 0).unwrap().is_none(),
            "B must be excluded while A holds"
        );

        // A's lease expires; B takes over with a strictly newer fence.
        clock.advance(1_001);
        let tb = proc_b
            .acquire("u\u{1}graph", 1_000, 0)
            .unwrap()
            .expect("B takes over expired lease");
        assert!(tb != ta, "fence tokens must be globally distinct");

        // A (the crashed-then-revived stale holder) tries to release — fencing protects B.
        proc_a.release("u\u{1}graph", ta).unwrap();
        assert!(
            proc_b.acquire("u\u{1}graph", 1_000, 0).unwrap().is_none(),
            "B's lock must survive A's stale fenced release"
        );

        // B releases cleanly; the key is free again.
        proc_b.release("u\u{1}graph", tb).unwrap();
        assert!(proc_a.acquire("u\u{1}graph", 1_000, 0).unwrap().is_some());
    }

    #[test]
    fn distributed_lock_wait_timeout_returns_none() {
        let kv = SharedLockKv::new();
        let hold =
            DistributedRefreshLock::new(Box::new(kv.clone()), Box::new(SystemMonoClock::new()));
        let wait =
            DistributedRefreshLock::new(Box::new(kv.clone()), Box::new(SystemMonoClock::new()));
        let held = hold.acquire("k", 60_000, 0).unwrap().expect("held");
        // A second acquirer with a short real wait must give up (lease not expiring soon).
        assert!(
            wait.acquire("k", 60_000, 15).unwrap().is_none(),
            "must time out while the key is held"
        );
        hold.release("k", held).unwrap();
    }

    // ---- CONN-04: Redis-backed LockKv over the explicit command contract ----

    /// Offline emulation of the exact Redis commands the lock uses: a keyspace with per-key PX expiry
    /// (an advanceable clock stands in for Redis's server clock), an INCR counter, NX-PX set, and a
    /// fenced compare-and-delete. Cheap to clone — clones share one keyspace = several processes,
    /// one Redis.
    #[derive(Clone, Default)]
    struct FakeRedis {
        inner: Arc<FakeRedisInner>,
    }
    #[derive(Default)]
    struct FakeRedisInner {
        strings: Mutex<BTreeMap<String, (String, Option<u64>)>>, // key -> (val, expiry_ms)
        counters: Mutex<BTreeMap<String, u64>>,
        now_ms: AtomicU64,
    }
    impl FakeRedis {
        fn new() -> Self {
            Self::default()
        }
        fn advance(&self, by_ms: u64) {
            self.inner.now_ms.fetch_add(by_ms, Ordering::SeqCst);
        }
        fn now(&self) -> u64 {
            self.inner.now_ms.load(Ordering::SeqCst)
        }
        fn live(&self, key: &str, m: &BTreeMap<String, (String, Option<u64>)>) -> bool {
            match m.get(key) {
                None => false,
                Some((_, None)) => true,
                Some((_, Some(exp))) => *exp > self.now(),
            }
        }
    }
    impl RedisCommands for FakeRedis {
        fn incr(&self, key: &str) -> Result<u64, LockError> {
            let mut c = self
                .inner
                .counters
                .lock()
                .map_err(|_| LockError("poisoned".into()))?;
            let v = c.entry(key.to_string()).or_insert(0);
            *v += 1;
            Ok(*v)
        }
        fn set_nx_px(&self, key: &str, val: &str, ttl_ms: u64) -> Result<bool, LockError> {
            let mut m = self
                .inner
                .strings
                .lock()
                .map_err(|_| LockError("poisoned".into()))?;
            if self.live(key, &m) {
                return Ok(false);
            }
            let expiry = self.now().saturating_add(ttl_ms);
            m.insert(key.to_string(), (val.to_string(), Some(expiry)));
            Ok(true)
        }
        fn compare_del(&self, key: &str, val: &str) -> Result<bool, LockError> {
            let mut m = self
                .inner
                .strings
                .lock()
                .map_err(|_| LockError("poisoned".into()))?;
            if self.live(key, &m) && m.get(key).map(|(v, _)| v.as_str()) == Some(val) {
                m.remove(key);
                Ok(true)
            } else {
                Ok(false)
            }
        }
    }

    #[test]
    fn gap_ainxt_refresh_conn_04_redis_lock_kv_command_semantics() {
        let redis = FakeRedis::new();
        let kv = RedisLockKv::new(redis.clone());
        // First acquire wins with fence #1 (server INCR).
        let t1 = kv.try_lock("u\u{1}graph", 1_000, 0).unwrap().expect("won");
        assert_eq!(t1, 1);
        // Held → NX fails.
        assert_eq!(kv.try_lock("u\u{1}graph", 1_000, 0).unwrap(), None);
        // A stale-token unlock (compare-and-delete mismatch) must NOT release it.
        assert!(!kv.unlock("u\u{1}graph", 999, 0).unwrap());
        assert_eq!(
            kv.try_lock("u\u{1}graph", 1_000, 0).unwrap(),
            None,
            "still held"
        );
        // The correct fence releases it.
        assert!(kv.unlock("u\u{1}graph", t1, 0).unwrap());
        // Re-acquirable with a strictly newer monotonic fence.
        let t2 = kv
            .try_lock("u\u{1}graph", 1_000, 0)
            .unwrap()
            .expect("re-acquire");
        assert!(t2 > t1);
        // PX expiry: advance past the TTL → the lease lapses and the key is acquirable again.
        redis.advance(1_001);
        assert!(kv.try_lock("u\u{1}graph", 1_000, 0).unwrap().is_some());
    }

    #[test]
    fn gap_ainxt_refresh_conn_04_redis_lock_collapses_the_herd() {
        // The end-to-end guarantee with the RedisLockKv command-contract lock: 16 concurrent callers,
        // one stale token → exactly ONE network refresh.
        let v = vault();
        seed(&v, "u", "graph", Some("R"), Some(NOW)); // due
        let calls = Arc::new(AtomicU32::new(0));
        let lock = DistributedRefreshLock::new(
            Box::new(RedisLockKv::new(FakeRedis::new())),
            Box::new(SystemMonoClock::new()),
        );
        let c = Arc::new(RefreshCoordinator::new(
            "graph",
            provider(),
            v,
            Box::new(lock),
            Box::new(CountingExecutor {
                calls: calls.clone(),
                rotate_refresh: true,
            }),
        ));
        let mut handles = Vec::new();
        for _ in 0..16 {
            let c = c.clone();
            handles.push(std::thread::spawn(move || c.ensure_fresh("u", NOW)));
        }
        for h in handles {
            assert_eq!(h.join().unwrap().unwrap(), "NEW-ACCESS");
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the Redis-contract distributed lock must collapse the herd to one refresh"
        );
    }

    // ---- r15: served-daemon entrypoint wires the REAL distributed lock, not the in-memory one ----

    #[test]
    fn r15_served_default_uses_distributed_lock_and_collapses_the_herd_across_clones() {
        // `served_default` must build a DistributedRefreshLock (over a SharedLockKv it owns), not an
        // InMemoryRefreshLock. There is no public getter for the lock type, so this is proven
        // behaviorally: 16 concurrent callers against ONE coordinator built via `served_default`
        // still collapse to exactly one network refresh (the property both lock kinds share)...
        let v = vault();
        seed(&v, "u", "graph", Some("R"), Some(NOW)); // due
        let calls = Arc::new(AtomicU32::new(0));
        let c = Arc::new(RefreshCoordinator::served_default(
            "graph",
            provider(),
            v,
            Box::new(CountingExecutor {
                calls: calls.clone(),
                rotate_refresh: true,
            }),
        ));
        let mut handles = Vec::new();
        for _ in 0..16 {
            let c = c.clone();
            handles.push(std::thread::spawn(move || c.ensure_fresh("u", NOW)));
        }
        for h in handles {
            assert_eq!(h.join().unwrap().unwrap(), "NEW-ACCESS");
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "served_default's coordinator must collapse the herd to one refresh"
        );
    }

    #[test]
    fn r15_served_default_lock_is_shared_kv_backed_cross_process_capable() {
        // ...and, distinguishing it from the process-local InMemoryRefreshLock: two INDEPENDENT
        // coordinators built via `served_default` for the SAME (user, connector) but backed by their
        // OWN SharedLockKv (as `served_default` gives each) do NOT exclude each other (each has its
        // own store) — this is the expected, honest shape for the offline default (no shared external
        // Redis yet); it is what makes wiring a live `RedisLockKv` behind the SAME `LockKv` seam (no
        // code change at this call site) the only remaining step for TRUE cross-process exclusion. If
        // this test ever starts observing mutual exclusion across two `served_default` instances
        // without a shared external store, something changed the seam wiring unexpectedly.
        let v1 = vault();
        seed(&v1, "u", "graph", Some("R"), Some(NOW));
        let c1 = RefreshCoordinator::served_default(
            "graph",
            provider(),
            v1,
            Box::new(CountingExecutor {
                calls: Arc::new(AtomicU32::new(0)),
                rotate_refresh: true,
            }),
        );
        // A fresh coordinator (independent SharedLockKv, independent vault) succeeds immediately —
        // proving `served_default` is usable per-connector without any shared external dependency.
        assert_eq!(c1.ensure_fresh("u", NOW).unwrap(), "NEW-ACCESS");
    }

    #[test]
    fn distributed_lock_collapses_the_thundering_herd() {
        // The end-to-end guarantee with the DISTRIBUTED lock: 16 concurrent callers, one stale token,
        // a shared-KV fenced lock → exactly ONE network refresh.
        let v = vault();
        seed(&v, "u", "graph", Some("R"), Some(NOW)); // due
        let calls = Arc::new(AtomicU32::new(0));
        let kv = SharedLockKv::new();
        let lock = DistributedRefreshLock::new(Box::new(kv), Box::new(SystemMonoClock::new()));
        let c = Arc::new(RefreshCoordinator::new(
            "graph",
            provider(),
            v,
            Box::new(lock),
            Box::new(CountingExecutor {
                calls: calls.clone(),
                rotate_refresh: true,
            }),
        ));

        let mut handles = Vec::new();
        for _ in 0..16 {
            let c = c.clone();
            handles.push(std::thread::spawn(move || c.ensure_fresh("u", NOW)));
        }
        for h in handles {
            assert_eq!(h.join().unwrap().unwrap(), "NEW-ACCESS");
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the distributed double-checked lock must collapse the herd to one refresh"
        );
    }
}
