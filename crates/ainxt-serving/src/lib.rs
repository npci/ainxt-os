// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! ainxt-serving — Serving-Ops **control-plane logic**: admission and flow control.
//!
//! Design: `docs/architecture/SERVING_OPS.md` (§2 SLO-aware QoS admission — priority
//! classes, per-tenant fairness; §0 the workload mix that makes one undifferentiated pool
//! fail) and ADR-020 (Serving-Ops as a first-class scheduled subsystem).
//!
//! This crate is the **pure, deterministic core** of the node-level admission gate that sits
//! *underneath* the Model Router (SERVING_OPS.md §7: the Router decides *which* model is
//! eligible; Serving-Ops decides *whether the fleet can take the call right now, and if not,
//! whose call yields*). It does **no I/O**, spawns no threads, calls no model, holds no GPU,
//! and reads no clock. Every notion of "time" is a **logical tick passed in by the caller**
//! ([`TokenBucket::tick`], [`Batcher::flush`]). That is what makes the whole control plane a
//! property a unit test can assert rather than a race a load test can only hope to catch: the
//! same inputs always produce the same decisions and the same state transition.
//!
//! # What is real here
//!
//! * [`AdmissionController`] — bounded concurrency + a **bounded** queue. `admit()` returns
//!   [`AdmissionDecision::Admit`] while there is in-flight headroom, [`AdmissionDecision::Enqueue`]
//!   while the queue has room, and [`AdmissionDecision::Shed`] (the 503-equivalent
//!   backpressure signal, extending `core/job_queue.py`'s `check_queue_pressure()` pattern,
//!   SERVING_OPS.md §2) the moment both are full. The queue is a **hard cap** — it can never
//!   grow without bound, which is the entire point of admission control. `complete()` frees a
//!   slot and promotes the head of the queue in one step.
//! * [`TokenBucket`] — a deterministic rate limiter. It starts **full** (a burst is allowed up
//!   to `capacity`), `try_take(k)` succeeds only within the current budget (throttles when
//!   drained), and `tick(n)` refills `refill_per_tick × n` up to `capacity`. All arithmetic is
//!   saturating, so a caller passing a huge tick count can never wrap the budget.
//! * [`Batcher`] — accumulates items and emits **whole batches**: `push` flushes automatically
//!   at `max_batch`, and an explicit `flush()` (the caller's periodic tick) drains the
//!   remainder. Items are never dropped and order is preserved — a batcher that silently lost
//!   the tail would corrupt exactly-once accounting downstream.
//! * [`LoadShedder`] — under pressure, sheds by **priority, lowest first** ([`PriorityClass`]:
//!   P2/batch before P1/standard before P0/interactive), so an incident query is protected
//!   from a batch flood. `offer()` additionally lets a higher-priority arrival **evict** a
//!   lower-priority incumbent when the shedder is full, and refuses an arrival that is itself
//!   the lowest priority present.
//! * [`FairnessLimiter`] — per-tenant (department, from the JWT `department` claim, §2)
//!   weighted quotas. A tenant is capped at its own share, so a single greedy department
//!   cannot starve a sibling. When configured quotas do not oversubscribe capacity
//!   ([`FairnessLimiter::is_starvation_proof`]) every under-quota tenant is *guaranteed*
//!   admission regardless of any other tenant's demand — the WFQ minimum-service property of
//!   SERVING_OPS.md §2.
//!
//! # Additional control-plane logic in this crate (submodules)
//!
//! Beyond the admission/flow-control primitives above, the load-bearing SERVING_OPS.md mechanisms
//! now live here as pure, deterministic cores:
//!
//! * [`attestation`] — the node-level hardware attestation gate (ADR-021 §8): trust tiers, the
//!   reference-value allow-list, firmware-provenance whole-node quarantine, and the bounded
//!   grace-TTL fail-closed-on-verifier-outage decision.
//! * [`preemption`] — chunk/step-granular preemption of already-running work (§2): an incident P0
//!   admitted within one boundary, never queued behind a 20-minute SDLC decode; committed work
//!   preserved via per-class checkpoint disposition.
//! * [`slo`] — the SLO-aware QoS **main admission path** (§2): the single pre-node decision the
//!   request path makes first — per-tenant fairness → priority-class preemptive scheduling →
//!   bounded-queue backpressure — so the live path carries a [`PriorityClass`] and invokes the
//!   scheduler instead of admitting priority-blind (the caller the audit found missing on §2).
//! * [`health`] — multi-GPU shard-level health (§4): interconnect watchdog + deterministic canary
//!   correctness probe (seam), drain-the-group, and N+1 standby promotion.
//! * [`cache_isolation`] — inference-cache isolation by `{data_class, principal_scope, harness_id}`
//!   (§6) + GPU-residue KV-page zeroization on DPDP erasure.
//! * [`gate`] — the **`model.infer` upward capability** (§7 / ADR-020): the single node-level
//!   admission gate that composes attestation + fairness + preemptive scheduling + node selection
//!   and dispatches through the [`gate::InferExecutor`] seam. This is the caller the audit found
//!   missing (`SRV-01`/`SRV-02`).
//! * [`idempotency`] — the inference-call idempotency ledger (ADR-013) and drain-the-group in-flight
//!   disposition by priority class (§4 step 2, `SRV-08`): exactly-once billing, a divergence guard,
//!   and retry-after-drop safety.
//! * [`kv_relay`] — the disaggregated prefill→decode **KV relay** (§1, `SRV-03`): credit-based flow
//!   control (bounds decode-pool pressure), GPU-to-GPU with host-buffer fallback, and
//!   idempotency-ledger-backed retry on a link drop.
//! * [`placement`] — **bin-packing placement** (best-fit-decreasing, locality- and attestation-aware),
//!   N+1 standby reservation, eviction/model-parking (warm vs cold re-warm), and demand-EWMA
//!   autoscale (§3, gaps 26/W, `SRV-04`).
//! * [`rollout`] — **signed, staged, integrity-verified weight rollout** (§5, `SRV-05`): re-verify at
//!   every load, attestation-bound regulated decryption, staged promotion with auto/approved
//!   rollback, blue-green vs staged cutover, and an honest numeric rollback SLA.
//! * [`wfq`] — **weighted fair queuing** (deficit round-robin, guarantees minimum service per tenant)
//!   and **chunked-prefill interleaving** (§2, `SRV-07`).
//! * [`disagg`] — the disaggregated prefill/decode **pool split** itself (§1, gap 7): two independent
//!   [`gate::ServingGate`]s joined only by the [`kv_relay`] fabric, so a decode admission is
//!   structurally never gated by prefill-pool saturation — the interference class removed, not
//!   scheduled around.
//!
//! # What is deliberately a seam (absent by design, not stubbed)
//!
//! The async request lifecycle and the actual hardware — GPU memory, the physical prefill/decode
//! pools and interconnect behind [`kv_relay`], the signature-verification crypto
//! ([`attestation::SignatureVerifier`], [`rollout::ArtifactVerifier`]), the canary's GPU inference
//! ([`health::CanaryProbe`]), and the model stream itself ([`gate::InferExecutor`]) — are seams
//! injected by the deployment. This crate owns the pure *policy* those layers stand on: what is
//! admitted, queued, shed, at what rate, in what batches, whose request yields first, which node a
//! regulated turn may run on, how KV pages move between pools under credit and retry safely on
//! failure, where a replica is placed, how a weight version is promoted or rolled back, and how a
//! principal's KV residue is zeroized.

pub mod attestation;
pub mod cache_isolation;
pub mod disagg;
pub mod erasure;
pub mod gate;
pub mod health;
pub mod idempotency;
pub mod kv_relay;
pub mod placement;
pub mod preemption;
pub mod rollout;
pub mod slo;
pub mod wfq;

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Configuration errors
// ---------------------------------------------------------------------------

/// A rejected constructor argument. Config values arrive from git-native manifests
/// (SERVING_OPS.md §2, ADR-026), so an invalid value is a *loading* error to surface, never a
/// silent clamp that would hide a bad policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfigError {
    /// A [`Batcher`] was asked for a `max_batch` of zero — a batcher that flushes at zero would
    /// emit empty or single-item batches forever, defeating batching.
    ZeroBatchSize,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::ZeroBatchSize => f.write_str("batcher max_batch must be >= 1"),
        }
    }
}

impl std::error::Error for ConfigError {}

// ---------------------------------------------------------------------------
// Priority classes (SERVING_OPS.md §2)
// ---------------------------------------------------------------------------

/// SLO priority class of a request (SERVING_OPS.md §2). Ordering is meaningful:
/// `Batch < Standard < Interactive`, so the *lowest* priority (the first thing a shedder
/// drops) is [`PriorityClass::Batch`] and the highest, never-shed-first class is
/// [`PriorityClass::Interactive`]. The `Ord` derive follows this declaration order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PriorityClass {
    /// P2 — Long-Horizon Program Runs, bulk indexing, eval sweeps, shadow traffic. Elastic,
    /// best-effort, preemptible; consumes only idle capacity and is shed first.
    Batch,
    /// P1 — standard agentic work: SDLC turns, coding-agent tool calls, code review.
    Standard,
    /// P0 — interactive chat, voice, incident RCA. TTFT-critical; protected, shed last.
    Interactive,
}

impl PriorityClass {
    /// All classes in ascending priority (lowest first) — the deterministic order a
    /// [`LoadShedder`] walks when choosing victims.
    pub const ASCENDING: [PriorityClass; 3] = [
        PriorityClass::Batch,
        PriorityClass::Standard,
        PriorityClass::Interactive,
    ];

    /// Priority rank; higher = more important (Batch=0, Standard=1, Interactive=2).
    pub fn rank(self) -> u8 {
        self as u8
    }

    /// The operational label used in dashboards/SLOs: P0 (Interactive) … P2 (Batch).
    pub fn label(self) -> &'static str {
        match self {
            PriorityClass::Interactive => "P0",
            PriorityClass::Standard => "P1",
            PriorityClass::Batch => "P2",
        }
    }
}

// ---------------------------------------------------------------------------
// Tenant identity
// ---------------------------------------------------------------------------

/// A fairness tenant — a department (from the JWT `department` claim, SERVING_OPS.md §2 /
/// `CLAUDE.md` Auth) or any other unit fairness is enforced across.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TenantId(pub String);

impl TenantId {
    pub fn new(s: impl Into<String>) -> Self {
        TenantId(s.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for TenantId {
    fn from(s: &str) -> Self {
        TenantId(s.to_string())
    }
}

impl From<String> for TenantId {
    fn from(s: String) -> Self {
        TenantId(s)
    }
}

impl fmt::Display for TenantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ---------------------------------------------------------------------------
// Admission controller (SERVING_OPS.md §2 — bounded queue, honest backpressure)
// ---------------------------------------------------------------------------

/// Why a request was shed rather than admitted or queued.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShedReason {
    /// In-flight slots are all taken **and** the bounded queue is full. This is the
    /// 503-equivalent honest backpressure signal — the alternative (an unbounded queue) is how
    /// a fleet dies under load instead of degrading.
    QueueFull {
        /// The configured queue ceiling, echoed for an honest `retry-after`-style signal.
        max_queue_depth: u32,
    },
}

/// The outcome of one [`AdmissionController::admit`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdmissionDecision {
    /// A slot was free; the request runs now. In-flight count incremented.
    Admit,
    /// No slot free but the queue had room; the request waits. Queue depth incremented.
    Enqueue,
    /// Both in-flight and queue are full — backpressure. Nothing was mutated.
    Shed(ShedReason),
}

impl AdmissionDecision {
    pub fn is_admit(self) -> bool {
        matches!(self, AdmissionDecision::Admit)
    }
    pub fn is_enqueue(self) -> bool {
        matches!(self, AdmissionDecision::Enqueue)
    }
    pub fn is_shed(self) -> bool {
        matches!(self, AdmissionDecision::Shed(_))
    }
}

/// A misuse of the [`AdmissionController`] state machine — returned rather than panicked so a
/// worker mis-accounting a completion degrades to an error, not a crash of the whole node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdmissionError {
    /// `complete()` was called with nothing in flight — a double-complete or accounting bug.
    NothingInFlight,
    /// `abandon_queued()` was called with an empty queue.
    NothingQueued,
}

impl fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdmissionError::NothingInFlight => f.write_str("complete() with nothing in flight"),
            AdmissionError::NothingQueued => f.write_str("abandon_queued() with an empty queue"),
        }
    }
}

impl std::error::Error for AdmissionError {}

/// Bounded-concurrency + bounded-queue admission (SERVING_OPS.md §2).
///
/// Tracks two counters against two ceilings. It never allocates and never blocks — it answers
/// "may this request run, wait, or must it be shed?" and maintains the counts. The actual
/// request objects, the async wait, and the wakeups belong to the caller; this is the *policy*.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionController {
    max_in_flight: u32,
    max_queue_depth: u32,
    in_flight: u32,
    queued: u32,
}

impl AdmissionController {
    /// `max_in_flight` concurrency slots; a queue bounded at `max_queue_depth`. For forward
    /// progress `max_in_flight` should be >= 1 (with zero, nothing can ever be promoted off the
    /// queue because no in-flight request can ever complete).
    pub fn new(max_in_flight: u32, max_queue_depth: u32) -> Self {
        AdmissionController {
            max_in_flight,
            max_queue_depth,
            in_flight: 0,
            queued: 0,
        }
    }

    /// Decide, and update state, for one arriving request.
    pub fn admit(&mut self) -> AdmissionDecision {
        if self.in_flight < self.max_in_flight {
            self.in_flight += 1;
            AdmissionDecision::Admit
        } else if self.queued < self.max_queue_depth {
            self.queued += 1;
            AdmissionDecision::Enqueue
        } else {
            AdmissionDecision::Shed(ShedReason::QueueFull {
                max_queue_depth: self.max_queue_depth,
            })
        }
    }

    /// An in-flight request finished. Frees its slot and, if the queue is non-empty and there
    /// is now headroom, promotes the head of the queue to in-flight in the same step.
    ///
    /// Returns `Ok(true)` if a queued request was promoted (net in-flight unchanged),
    /// `Ok(false)` if the slot simply freed, or [`AdmissionError::NothingInFlight`] if there
    /// was nothing to complete.
    pub fn complete(&mut self) -> Result<bool, AdmissionError> {
        if self.in_flight == 0 {
            return Err(AdmissionError::NothingInFlight);
        }
        self.in_flight -= 1;
        if self.queued > 0 && self.in_flight < self.max_in_flight {
            self.queued -= 1;
            self.in_flight += 1;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Drop a queued request that will never run (client disconnect / wait timeout). Keeps the
    /// queue depth honest so the ceiling is not permanently consumed by ghosts.
    pub fn abandon_queued(&mut self) -> Result<(), AdmissionError> {
        if self.queued == 0 {
            return Err(AdmissionError::NothingQueued);
        }
        self.queued -= 1;
        Ok(())
    }

    pub fn in_flight(&self) -> u32 {
        self.in_flight
    }
    pub fn queued(&self) -> u32 {
        self.queued
    }
    pub fn max_in_flight(&self) -> u32 {
        self.max_in_flight
    }
    pub fn max_queue_depth(&self) -> u32 {
        self.max_queue_depth
    }
    /// True when the next `admit()` would shed (both ceilings hit).
    pub fn is_saturated(&self) -> bool {
        self.in_flight >= self.max_in_flight && self.queued >= self.max_queue_depth
    }
}

// ---------------------------------------------------------------------------
// Token-bucket rate limiter (deterministic — tick time is a parameter)
// ---------------------------------------------------------------------------

/// A deterministic token-bucket rate limiter (SERVING_OPS.md §0/§2 — smoothing bursts against
/// a sustainable fleet rate). Starts **full**, so a burst up to `capacity` is allowed
/// immediately; drains on `try_take`; refills on `tick`. No wall clock — the caller drives
/// logical time, so behaviour is reproducible.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenBucket {
    capacity: u64,
    refill_per_tick: u64,
    tokens: u64,
}

impl TokenBucket {
    /// A bucket that holds at most `capacity` tokens and gains `refill_per_tick` per logical
    /// tick. Starts full to permit an initial burst.
    pub fn new(capacity: u64, refill_per_tick: u64) -> Self {
        TokenBucket {
            capacity,
            refill_per_tick,
            tokens: capacity,
        }
    }

    /// Like [`TokenBucket::new`] but starting empty (cold-start throttled until the first
    /// refill) — useful when a newly-placed replica must not absorb a burst before it is warm.
    pub fn new_empty(capacity: u64, refill_per_tick: u64) -> Self {
        TokenBucket {
            capacity,
            refill_per_tick,
            tokens: 0,
        }
    }

    /// Advance `ticks` logical ticks, refilling `refill_per_tick × ticks` tokens, clamped to
    /// `capacity`. Saturating throughout, so no tick count can wrap the budget.
    pub fn tick(&mut self, ticks: u64) {
        let added = self.refill_per_tick.saturating_mul(ticks);
        self.tokens = self.tokens.saturating_add(added).min(self.capacity);
    }

    /// Take `k` tokens if the current budget allows. Returns `true` and debits on success;
    /// returns `false` and leaves the budget untouched when throttled. Taking `0` always
    /// succeeds and is a no-op.
    pub fn try_take(&mut self, k: u64) -> bool {
        if self.tokens >= k {
            self.tokens -= k;
            true
        } else {
            false
        }
    }

    /// Tokens currently available.
    pub fn available(&self) -> u64 {
        self.tokens
    }
    pub fn capacity(&self) -> u64 {
        self.capacity
    }
    pub fn refill_per_tick(&self) -> u64 {
        self.refill_per_tick
    }
}

// ---------------------------------------------------------------------------
// Batcher (accumulate → flush at max or on a flush tick; never drops silently)
// ---------------------------------------------------------------------------

/// Accumulates items and emits **whole batches** (SERVING_OPS.md §0 — continuous batching is
/// how a decode pool stays efficient). It flushes automatically when it reaches `max_batch`,
/// and on an explicit [`Batcher::flush`] (the caller's periodic tick) for the remainder. It
/// never drops an item and never reorders — losing the tail would corrupt token accounting and
/// exactly-once semantics downstream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Batcher<T> {
    max_batch: usize,
    buffer: Vec<T>,
}

impl<T> Batcher<T> {
    /// A batcher that flushes at `max_batch` items. `max_batch` must be >= 1.
    pub fn new(max_batch: usize) -> Result<Self, ConfigError> {
        if max_batch == 0 {
            return Err(ConfigError::ZeroBatchSize);
        }
        Ok(Batcher {
            max_batch,
            buffer: Vec::new(),
        })
    }

    /// Add one item. Returns `Some(batch)` (draining the buffer) the moment the buffer reaches
    /// `max_batch`, otherwise `None`. With `max_batch == 1` every push flushes a singleton.
    pub fn push(&mut self, item: T) -> Option<Vec<T>> {
        self.buffer.push(item);
        if self.buffer.len() >= self.max_batch {
            Some(self.drain())
        } else {
            None
        }
    }

    /// Emit whatever has accumulated (the periodic flush tick). Returns `None` when the buffer
    /// is empty — an empty batch is never emitted.
    pub fn flush(&mut self) -> Option<Vec<T>> {
        if self.buffer.is_empty() {
            None
        } else {
            Some(self.drain())
        }
    }

    fn drain(&mut self) -> Vec<T> {
        std::mem::take(&mut self.buffer)
    }

    pub fn len(&self) -> usize {
        self.buffer.len()
    }
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }
    pub fn max_batch(&self) -> usize {
        self.max_batch
    }
}

// ---------------------------------------------------------------------------
// Load shedder (shed by priority, lowest first)
// ---------------------------------------------------------------------------

/// The outcome of offering a request to a [`LoadShedder`] at capacity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShedOutcome {
    /// The request was accepted. `evicted` names a lower-priority incumbent that was dropped to
    /// make room (only when the shedder was already full); `None` means there was free capacity.
    Accepted { evicted: Option<PriorityClass> },
    /// The request was refused: the shedder is full and nothing of *lower* priority was present
    /// to evict, so shedding the arrival itself protects the higher-priority incumbents.
    Rejected,
}

/// One line of a proactive [`LoadShedder::shed`] plan: how many of a class were dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShedLine {
    pub class: PriorityClass,
    pub count: u32,
}

/// The result of a proactive shed: the per-class drops in ascending-priority order, and the
/// total actually shed (which is `<= requested` when the shedder held fewer than requested).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShedPlan {
    pub lines: Vec<ShedLine>,
    pub total_shed: u32,
}

/// Sheds load by **priority, lowest first** (SERVING_OPS.md §2 — protect P0/incident traffic).
///
/// Holds a per-[`PriorityClass`] count of live load against a `capacity`. Two entry points:
/// [`LoadShedder::offer`] admits a single arrival, evicting a strictly-lower-priority incumbent
/// if full; [`LoadShedder::shed`] proactively drops a target amount, draining the lowest
/// priority class first, then the next, until the target is met or nothing lower remains.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoadShedder {
    capacity: u32,
    counts: BTreeMap<PriorityClass, u32>,
    total: u32,
}

impl LoadShedder {
    pub fn new(capacity: u32) -> Self {
        LoadShedder {
            capacity,
            counts: BTreeMap::new(),
            total: 0,
        }
    }

    /// Offer one arrival of `class`.
    ///
    /// * If there is free capacity, it is accepted with no eviction.
    /// * If full, the lowest-priority incumbent whose class is **strictly below** `class` is
    ///   evicted and the arrival takes its place (higher priority wins the scarce slot).
    /// * If full and nothing of lower priority is present, the arrival is [`ShedOutcome::Rejected`]
    ///   — dropping the newcomer rather than a same-or-higher-priority incumbent.
    pub fn offer(&mut self, class: PriorityClass) -> ShedOutcome {
        if self.total < self.capacity {
            self.increment(class);
            return ShedOutcome::Accepted { evicted: None };
        }
        // Full: look for a strictly-lower-priority victim, lowest first.
        for victim in PriorityClass::ASCENDING {
            if victim >= class {
                break; // ASCENDING is sorted; nothing from here up is lower priority.
            }
            if self.load(victim) > 0 {
                self.decrement(victim);
                self.increment(class);
                return ShedOutcome::Accepted {
                    evicted: Some(victim),
                };
            }
        }
        ShedOutcome::Rejected
    }

    /// Proactively shed up to `target` units of load, lowest priority first. Sheds fewer than
    /// `target` only when the shedder holds fewer than `target` in total.
    pub fn shed(&mut self, target: u32) -> ShedPlan {
        let mut remaining = target;
        let mut lines = Vec::new();
        for class in PriorityClass::ASCENDING {
            if remaining == 0 {
                break;
            }
            let have = self.load(class);
            if have == 0 {
                continue;
            }
            let take = have.min(remaining);
            self.decrement_by(class, take);
            remaining -= take;
            lines.push(ShedLine { class, count: take });
        }
        ShedPlan {
            total_shed: target - remaining,
            lines,
        }
    }

    /// Register live load of `class` (e.g. a request that was admitted elsewhere).
    pub fn register(&mut self, class: PriorityClass) {
        self.increment(class);
    }

    /// Release one unit of live load of `class` on normal completion. No-op if already zero.
    pub fn release(&mut self, class: PriorityClass) {
        if self.load(class) > 0 {
            self.decrement(class);
        }
    }

    pub fn load(&self, class: PriorityClass) -> u32 {
        self.counts.get(&class).copied().unwrap_or(0)
    }
    pub fn total(&self) -> u32 {
        self.total
    }
    pub fn capacity(&self) -> u32 {
        self.capacity
    }
    pub fn remaining_capacity(&self) -> u32 {
        self.capacity.saturating_sub(self.total)
    }

    fn increment(&mut self, class: PriorityClass) {
        *self.counts.entry(class).or_insert(0) += 1;
        self.total += 1;
    }
    fn decrement(&mut self, class: PriorityClass) {
        self.decrement_by(class, 1);
    }
    fn decrement_by(&mut self, class: PriorityClass, n: u32) {
        let slot = self.counts.entry(class).or_insert(0);
        let take = n.min(*slot);
        *slot -= take;
        self.total -= take;
    }
}

// ---------------------------------------------------------------------------
// Per-tenant fairness (weighted quotas — no tenant starves a sibling)
// ---------------------------------------------------------------------------

/// The outcome of a [`FairnessLimiter::try_admit`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FairnessDecision {
    /// Admitted within the tenant's quota and the global capacity.
    Admit,
    /// Refused because the tenant is already at its own quota — this is what caps a greedy
    /// tenant and protects everyone else's guaranteed share. `quota` is the tenant's ceiling.
    RejectOverQuota { quota: u32 },
    /// Refused because the global capacity is exhausted (only reachable when quotas are
    /// oversubscribed; see [`FairnessLimiter::is_starvation_proof`]).
    RejectAtCapacity,
}

impl FairnessDecision {
    pub fn is_admit(self) -> bool {
        matches!(self, FairnessDecision::Admit)
    }
}

/// Per-tenant weighted-fair admission (SERVING_OPS.md §2). Each tenant may hold up to its own
/// quota of concurrent slots; a greedy tenant is queued/refused at its ceiling and can never
/// consume a sibling's share.
///
/// **Starvation-proof invariant:** when the sum of configured quotas does not exceed capacity
/// ([`FairnessLimiter::is_starvation_proof`]), every under-quota tenant is *guaranteed*
/// admission — no other tenant's demand can push the global total to capacity before this
/// tenant reaches its own quota, because all tenants together cannot exceed the sum of quotas,
/// which is <= capacity. This is the WFQ minimum-service guarantee, made a checkable property.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FairnessLimiter {
    capacity: u32,
    default_quota: u32,
    quotas: BTreeMap<TenantId, u32>,
    usage: BTreeMap<TenantId, u32>,
    total: u32,
}

impl FairnessLimiter {
    /// A limiter with a global `capacity` and a `default_quota` applied to any tenant without an
    /// explicit quota.
    pub fn new(capacity: u32, default_quota: u32) -> Self {
        FairnessLimiter {
            capacity,
            default_quota,
            quotas: BTreeMap::new(),
            usage: BTreeMap::new(),
            total: 0,
        }
    }

    /// Build quotas from integer weights: each tenant's quota is `floor(capacity × wᵢ / Σw)`.
    /// Tenants not listed get `default_quota = 0` (must be given an explicit quota to run). The
    /// floor guarantees `Σ quotas <= capacity`, so the result is always starvation-proof.
    pub fn from_weights(capacity: u32, weights: &[(TenantId, u32)]) -> Self {
        let sum_w: u64 = weights.iter().map(|(_, w)| u64::from(*w)).sum();
        let mut quotas = BTreeMap::new();
        for (tenant, w) in weights {
            // `checked_div` yields None when Σw == 0 → no quota inserted (stays at default 0),
            // matching the "all-zero-weights ⇒ no quotas" contract without a manual guard.
            if let Some(q) = (u64::from(capacity) * u64::from(*w)).checked_div(sum_w) {
                quotas.insert(tenant.clone(), q as u32);
            }
        }
        FairnessLimiter {
            capacity,
            default_quota: 0,
            quotas,
            usage: BTreeMap::new(),
            total: 0,
        }
    }

    /// Set (or override) one tenant's quota.
    pub fn set_quota(&mut self, tenant: impl Into<TenantId>, quota: u32) {
        self.quotas.insert(tenant.into(), quota);
    }

    /// Try to admit one request for `tenant`. Over-quota is checked **before** capacity so a
    /// greedy tenant gets the honest [`FairnessDecision::RejectOverQuota`] reason even while
    /// global capacity is intact (that headroom is reserved for other tenants).
    pub fn try_admit(&mut self, tenant: &TenantId) -> FairnessDecision {
        let quota = self.quota_of(tenant);
        if self.usage_of(tenant) >= quota {
            return FairnessDecision::RejectOverQuota { quota };
        }
        if self.total >= self.capacity {
            return FairnessDecision::RejectAtCapacity;
        }
        *self.usage.entry(tenant.clone()).or_insert(0) += 1;
        self.total += 1;
        FairnessDecision::Admit
    }

    /// Release one in-use slot for `tenant` on completion. No-op if the tenant has none.
    pub fn release(&mut self, tenant: &TenantId) {
        if let Some(u) = self.usage.get_mut(tenant) {
            if *u > 0 {
                *u -= 1;
                self.total -= 1;
            }
        }
    }

    pub fn quota_of(&self, tenant: &TenantId) -> u32 {
        self.quotas
            .get(tenant)
            .copied()
            .unwrap_or(self.default_quota)
    }
    pub fn usage_of(&self, tenant: &TenantId) -> u32 {
        self.usage.get(tenant).copied().unwrap_or(0)
    }
    pub fn total(&self) -> u32 {
        self.total
    }
    pub fn capacity(&self) -> u32 {
        self.capacity
    }

    /// Sum of all explicitly configured quotas.
    pub fn total_configured_quota(&self) -> u64 {
        self.quotas.values().map(|q| u64::from(*q)).sum()
    }

    /// True when configured quotas do not oversubscribe capacity — the condition under which
    /// every under-quota tenant is guaranteed admission (no starvation possible).
    pub fn is_starvation_proof(&self) -> bool {
        self.total_configured_quota() <= u64::from(self.capacity)
    }
}

pub use ainxt_types::{DataClass, Tier};

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ---- AdmissionController ------------------------------------------------

    #[test]
    fn admits_up_to_capacity_then_enqueues_to_cap_then_sheds() {
        let mut ac = AdmissionController::new(2, 2);
        // Two admits fill the in-flight slots.
        assert_eq!(ac.admit(), AdmissionDecision::Admit);
        assert_eq!(ac.admit(), AdmissionDecision::Admit);
        assert_eq!(ac.in_flight(), 2);
        // Next two fill the bounded queue.
        assert_eq!(ac.admit(), AdmissionDecision::Enqueue);
        assert_eq!(ac.admit(), AdmissionDecision::Enqueue);
        assert_eq!(ac.queued(), 2);
        // Past both ceilings → shed, and nothing mutated.
        assert_eq!(
            ac.admit(),
            AdmissionDecision::Shed(ShedReason::QueueFull { max_queue_depth: 2 })
        );
        assert_eq!(ac.in_flight(), 2);
        assert_eq!(ac.queued(), 2);
        assert!(ac.is_saturated());
    }

    #[test]
    fn complete_promotes_head_of_queue() {
        let mut ac = AdmissionController::new(1, 3);
        assert!(ac.admit().is_admit()); // in_flight=1
        assert!(ac.admit().is_enqueue()); // queued=1
        assert!(ac.admit().is_enqueue()); // queued=2
        assert_eq!(ac.in_flight(), 1);
        assert_eq!(ac.queued(), 2);
        // Completing one promotes exactly one queued request; in-flight stays full at 1.
        assert_eq!(ac.complete(), Ok(true));
        assert_eq!(ac.in_flight(), 1);
        assert_eq!(ac.queued(), 1);
        assert_eq!(ac.complete(), Ok(true));
        assert_eq!(ac.queued(), 0);
        // Now the queue is empty; the next completion just frees the slot.
        assert_eq!(ac.complete(), Ok(false));
        assert_eq!(ac.in_flight(), 0);
    }

    #[test]
    fn complete_with_nothing_in_flight_is_an_error_not_a_panic() {
        let mut ac = AdmissionController::new(1, 1);
        assert_eq!(ac.complete(), Err(AdmissionError::NothingInFlight));
    }

    #[test]
    fn abandon_queued_frees_a_ghost_slot() {
        let mut ac = AdmissionController::new(1, 2);
        ac.admit();
        ac.admit(); // queued=1
        assert_eq!(ac.queued(), 1);
        assert_eq!(ac.abandon_queued(), Ok(()));
        assert_eq!(ac.queued(), 0);
        assert_eq!(ac.abandon_queued(), Err(AdmissionError::NothingQueued));
    }

    #[test]
    fn zero_in_flight_and_zero_queue_sheds_everything() {
        let mut ac = AdmissionController::new(0, 0);
        assert!(ac.admit().is_shed());
    }

    // ---- TokenBucket --------------------------------------------------------

    #[test]
    fn token_bucket_allows_burst_then_throttles_then_refills() {
        let mut tb = TokenBucket::new(10, 2);
        // Burst: the full capacity is available immediately.
        assert_eq!(tb.available(), 10);
        assert!(tb.try_take(10));
        assert_eq!(tb.available(), 0);
        // Throttled: empty bucket refuses and leaves the budget untouched.
        assert!(!tb.try_take(1));
        assert_eq!(tb.available(), 0);
        // Refill: 3 ticks × 2 = 6 tokens.
        tb.tick(3);
        assert_eq!(tb.available(), 6);
        assert!(tb.try_take(6));
        assert!(!tb.try_take(1));
    }

    #[test]
    fn token_bucket_refill_clamps_to_capacity() {
        let mut tb = TokenBucket::new(5, 4);
        assert!(tb.try_take(5));
        tb.tick(100); // 400 would overflow the cap
        assert_eq!(tb.available(), 5);
    }

    #[test]
    fn token_bucket_tick_is_saturating() {
        let mut tb = TokenBucket::new(u64::MAX, u64::MAX);
        assert!(tb.try_take(u64::MAX));
        tb.tick(u64::MAX); // MAX*MAX must saturate, never wrap
        assert_eq!(tb.available(), u64::MAX);
    }

    #[test]
    fn token_bucket_empty_start_throttles_until_first_refill() {
        let mut tb = TokenBucket::new_empty(4, 1);
        assert!(!tb.try_take(1));
        tb.tick(2);
        assert!(tb.try_take(2));
        assert!(!tb.try_take(1));
    }

    #[test]
    fn token_bucket_take_zero_is_noop_success() {
        let mut tb = TokenBucket::new_empty(4, 1);
        assert!(tb.try_take(0));
        assert_eq!(tb.available(), 0);
    }

    // ---- Batcher ------------------------------------------------------------

    #[test]
    fn batcher_flushes_at_max_and_on_flush_with_remainder() {
        let mut b: Batcher<i32> = Batcher::new(3).unwrap();
        assert_eq!(b.push(1), None);
        assert_eq!(b.push(2), None);
        // Third push hits max_batch → whole batch emitted in order, buffer cleared.
        assert_eq!(b.push(3), Some(vec![1, 2, 3]));
        assert!(b.is_empty());
        // Partial accumulation then an explicit flush tick returns the remainder.
        assert_eq!(b.push(4), None);
        assert_eq!(b.push(5), None);
        assert_eq!(b.flush(), Some(vec![4, 5]));
        // Nothing left → flush emits no empty batch.
        assert_eq!(b.flush(), None);
    }

    #[test]
    fn batcher_never_drops_across_many_batches() {
        let mut b: Batcher<usize> = Batcher::new(2).unwrap();
        let mut emitted = Vec::new();
        for i in 0..5 {
            if let Some(batch) = b.push(i) {
                emitted.extend(batch);
            }
        }
        if let Some(rem) = b.flush() {
            emitted.extend(rem);
        }
        // Every item accounted for, exactly once, in order.
        assert_eq!(emitted, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn batcher_max_batch_one_flushes_every_push() {
        let mut b: Batcher<char> = Batcher::new(1).unwrap();
        assert_eq!(b.push('a'), Some(vec!['a']));
        assert_eq!(b.push('b'), Some(vec!['b']));
        assert!(b.is_empty());
    }

    #[test]
    fn batcher_zero_max_batch_is_a_config_error() {
        let err = Batcher::<i32>::new(0).unwrap_err();
        assert_eq!(err, ConfigError::ZeroBatchSize);
    }

    // ---- LoadShedder --------------------------------------------------------

    #[test]
    fn shed_drops_lowest_priority_first() {
        let mut ls = LoadShedder::new(100);
        for _ in 0..3 {
            ls.register(PriorityClass::Batch);
        }
        for _ in 0..2 {
            ls.register(PriorityClass::Standard);
        }
        ls.register(PriorityClass::Interactive);
        assert_eq!(ls.total(), 6);

        // Shed 4: all 3 Batch first, then 1 Standard — Interactive is untouched.
        let plan = ls.shed(4);
        assert_eq!(plan.total_shed, 4);
        assert_eq!(
            plan.lines,
            vec![
                ShedLine {
                    class: PriorityClass::Batch,
                    count: 3
                },
                ShedLine {
                    class: PriorityClass::Standard,
                    count: 1
                },
            ]
        );
        assert_eq!(ls.load(PriorityClass::Batch), 0);
        assert_eq!(ls.load(PriorityClass::Standard), 1);
        assert_eq!(ls.load(PriorityClass::Interactive), 1);
    }

    #[test]
    fn shed_caps_at_available_when_target_exceeds_load() {
        let mut ls = LoadShedder::new(10);
        ls.register(PriorityClass::Batch);
        ls.register(PriorityClass::Interactive);
        let plan = ls.shed(100);
        assert_eq!(plan.total_shed, 2);
        assert_eq!(ls.total(), 0);
    }

    #[test]
    fn offer_accepts_with_free_capacity_no_eviction() {
        let mut ls = LoadShedder::new(2);
        assert_eq!(
            ls.offer(PriorityClass::Batch),
            ShedOutcome::Accepted { evicted: None }
        );
        assert_eq!(ls.total(), 1);
    }

    #[test]
    fn offer_high_priority_evicts_lower_when_full() {
        let mut ls = LoadShedder::new(2);
        ls.register(PriorityClass::Batch);
        ls.register(PriorityClass::Standard);
        assert_eq!(ls.total(), 2); // full
                                   // An incident (P0) arrives: the lowest-priority incumbent (Batch) is evicted for it.
        assert_eq!(
            ls.offer(PriorityClass::Interactive),
            ShedOutcome::Accepted {
                evicted: Some(PriorityClass::Batch)
            }
        );
        assert_eq!(ls.load(PriorityClass::Batch), 0);
        assert_eq!(ls.load(PriorityClass::Standard), 1);
        assert_eq!(ls.load(PriorityClass::Interactive), 1);
        assert_eq!(ls.total(), 2);
    }

    #[test]
    fn offer_rejects_arrival_that_is_lowest_priority_when_full() {
        let mut ls = LoadShedder::new(2);
        ls.register(PriorityClass::Interactive);
        ls.register(PriorityClass::Interactive);
        // A batch job arrives into a pool full of P0s: nothing lower to evict → refuse the batch.
        assert_eq!(ls.offer(PriorityClass::Batch), ShedOutcome::Rejected);
        assert_eq!(ls.load(PriorityClass::Interactive), 2);
        assert_eq!(ls.load(PriorityClass::Batch), 0);
    }

    #[test]
    fn offer_standard_evicts_batch_but_not_interactive() {
        let mut ls = LoadShedder::new(2);
        ls.register(PriorityClass::Interactive);
        ls.register(PriorityClass::Batch);
        // P1 arrives: it may evict the P2 batch, never the P0.
        assert_eq!(
            ls.offer(PriorityClass::Standard),
            ShedOutcome::Accepted {
                evicted: Some(PriorityClass::Batch)
            }
        );
        assert_eq!(ls.load(PriorityClass::Interactive), 1);
        assert_eq!(ls.load(PriorityClass::Standard), 1);
    }

    #[test]
    fn offer_equal_priority_full_is_rejected_not_self_evicting() {
        let mut ls = LoadShedder::new(1);
        ls.register(PriorityClass::Standard);
        // Same priority, full, nothing lower → reject the arrival (don't thrash equals).
        assert_eq!(ls.offer(PriorityClass::Standard), ShedOutcome::Rejected);
    }

    #[test]
    fn priority_ordering_and_labels() {
        assert!(PriorityClass::Interactive > PriorityClass::Standard);
        assert!(PriorityClass::Standard > PriorityClass::Batch);
        assert_eq!(PriorityClass::Interactive.label(), "P0");
        assert_eq!(PriorityClass::Standard.label(), "P1");
        assert_eq!(PriorityClass::Batch.label(), "P2");
        assert_eq!(PriorityClass::Interactive.rank(), 2);
        assert_eq!(PriorityClass::Batch.rank(), 0);
    }

    // ---- FairnessLimiter ----------------------------------------------------

    #[test]
    fn greedy_tenant_is_capped_while_others_still_served() {
        // Capacity 4, two tenants, quota 2 each (starvation-proof: 2+2 == 4).
        let mut fl = FairnessLimiter::new(4, 0);
        let a = TenantId::new("dept-a");
        let b = TenantId::new("dept-b");
        fl.set_quota(a.clone(), 2);
        fl.set_quota(b.clone(), 2);
        assert!(fl.is_starvation_proof());

        // Greedy A grabs its full quota...
        assert_eq!(fl.try_admit(&a), FairnessDecision::Admit);
        assert_eq!(fl.try_admit(&a), FairnessDecision::Admit);
        // ...then is capped at its own quota, NOT allowed to eat into B's reserved share,
        // even though the global total (2) is below capacity (4).
        assert_eq!(
            fl.try_admit(&a),
            FairnessDecision::RejectOverQuota { quota: 2 }
        );
        assert!(fl.total() < fl.capacity());

        // B is still guaranteed its full share regardless of A's greed.
        assert_eq!(fl.try_admit(&b), FairnessDecision::Admit);
        assert_eq!(fl.try_admit(&b), FairnessDecision::Admit);
        assert_eq!(
            fl.try_admit(&b),
            FairnessDecision::RejectOverQuota { quota: 2 }
        );
    }

    #[test]
    fn release_lets_a_capped_tenant_run_again() {
        let mut fl = FairnessLimiter::new(2, 1);
        let a = TenantId::new("a");
        assert!(fl.try_admit(&a).is_admit());
        assert_eq!(
            fl.try_admit(&a),
            FairnessDecision::RejectOverQuota { quota: 1 }
        );
        fl.release(&a);
        assert_eq!(fl.usage_of(&a), 0);
        assert!(fl.try_admit(&a).is_admit());
    }

    #[test]
    fn oversubscribed_quotas_can_hit_global_capacity() {
        // Quotas sum to 4 but capacity is only 2 → NOT starvation-proof; the second tenant can
        // be refused for capacity, not quota.
        let mut fl = FairnessLimiter::new(2, 0);
        let a = TenantId::new("a");
        let b = TenantId::new("b");
        fl.set_quota(a.clone(), 2);
        fl.set_quota(b.clone(), 2);
        assert!(!fl.is_starvation_proof());
        assert!(fl.try_admit(&a).is_admit());
        assert!(fl.try_admit(&a).is_admit());
        // A is within its quota-of-2 conceptually, but global capacity is spent.
        assert_eq!(fl.try_admit(&b), FairnessDecision::RejectAtCapacity);
    }

    #[test]
    fn from_weights_computes_floored_quotas_and_stays_starvation_proof() {
        let a = TenantId::new("a");
        let b = TenantId::new("b");
        // Weights 3:1 over capacity 10 → 7 and 2 (floors), sum 9 <= 10.
        let fl = FairnessLimiter::from_weights(10, &[(a.clone(), 3), (b.clone(), 1)]);
        assert_eq!(fl.quota_of(&a), 7);
        assert_eq!(fl.quota_of(&b), 2);
        assert!(fl.is_starvation_proof());
    }

    #[test]
    fn default_quota_applies_to_unconfigured_tenant() {
        let mut fl = FairnessLimiter::new(10, 1);
        let x = TenantId::new("unknown");
        assert_eq!(fl.quota_of(&x), 1);
        assert!(fl.try_admit(&x).is_admit());
        assert_eq!(
            fl.try_admit(&x),
            FairnessDecision::RejectOverQuota { quota: 1 }
        );
    }

    // ---- serde --------------------------------------------------------------

    #[test]
    fn decisions_serialize_stably() {
        let json = serde_json::to_string(&AdmissionDecision::Shed(ShedReason::QueueFull {
            max_queue_depth: 5,
        }))
        .unwrap();
        assert!(json.contains("QueueFull"));
        assert!(json.contains('5'));
        let pc = serde_json::to_string(&PriorityClass::Interactive).unwrap();
        assert_eq!(pc, "\"interactive\"");
    }

    #[test]
    fn ainxt_types_reexport_is_usable() {
        // The shared domain types are re-exported at the crate root and behave.
        assert!(DataClass::RegulatedPayment.is_regulated());
        assert!(DataClass::Confidential.sensitivity() < DataClass::Pii.sensitivity());
        let _t = Tier::Complex;
    }
}
