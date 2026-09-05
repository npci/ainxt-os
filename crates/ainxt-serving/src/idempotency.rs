// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Inference-call idempotency ledger + drain-the-group in-flight disposition
//! (SERVING_OPS.md §4 step 2, §1 relay-retry; ADR-013 reused verbatim for inference calls).
//!
//! The audit (gap **SRV-08**) found drain-the-group recovery was only a *comment* in
//! [`crate::health`]: "recover under the existing idempotency-ledger discipline (a seam here, not
//! reinvented)". That discipline did not actually exist in the crate, so a retry after a drain could
//! double-bill tokens or return two divergent answers to one logical request. This module makes it
//! real, as a pure deterministic core:
//!
//! * **Exactly-once billing.** A request is [`IdempotencyLedger::begin`]-ed under a caller-chosen
//!   key. Tokens are billed *only* at [`IdempotencyLedger::commit`], and commit is idempotent — a
//!   second commit of the same key never bills again. A retry of an already-committed key returns the
//!   recorded result without re-executing ([`BeginOutcome::AlreadyCommitted`]).
//! * **Divergence guard.** Committing the *same* key with a *different* result hash is rejected
//!   ([`CommitError::DivergentResult`]) — the concrete guard against "returns two divergent answers
//!   to one logical request" (SERVING_OPS.md §4 step 2). Same key + same hash is a safe no-op.
//! * **Retry after a drop is safe, not a double.** A key whose prior attempt is still in flight (the
//!   node was drained mid-generation, so the first attempt never committed) can be re-begun; it
//!   returns [`BeginOutcome::Retry`] with an incremented attempt counter, and because billing only
//!   happens at commit, the discarded partial is never charged.
//! * **Drain disposition by priority class** ([`dispose_on_drain`]) — the §4-step-2 policy: P0/P1
//!   in-flight generations fail back and retry against a healthy group under the ledger; P2 module
//!   Runs checkpoint to `PENDING` and re-queue at the Program Supervisor (ADR-027), never retried
//!   inline. No new recovery path is invented — the disposition just routes to the two existing ones.

use std::collections::BTreeMap;
use std::fmt;

use crate::PriorityClass;

/// State of one logical request in the ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Record {
    /// An attempt is executing; nothing billed yet. `attempt` counts (re)starts after drops.
    InFlight { attempt: u32 },
    /// The request finished; `tokens_billed` was charged exactly once, `result_hash` pins the answer.
    Committed {
        tokens_billed: u64,
        result_hash: u64,
    },
}

/// The outcome of [`IdempotencyLedger::begin`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BeginOutcome {
    /// First time this key is seen — proceed to execute and later `commit`.
    Fresh,
    /// A prior attempt is still in flight (e.g. a retry after a drain). Safe to re-execute; the
    /// prior partial is discarded and never billed. `attempt` is the new attempt number (>= 2).
    Retry { attempt: u32 },
    /// Already committed — do **not** re-execute or re-bill; return the recorded result.
    AlreadyCommitted {
        tokens_billed: u64,
        result_hash: u64,
    },
}

/// Why a [`IdempotencyLedger::commit`] was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitError {
    /// `commit` was called for a key that was never `begin`-ed.
    NotBegun,
    /// The key was already committed with a **different** result hash — the divergence guard
    /// (SERVING_OPS.md §4 step 2: "never returns two divergent answers to one logical request").
    DivergentResult {
        existing_hash: u64,
        attempted_hash: u64,
    },
}

impl fmt::Display for CommitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CommitError::NotBegun => f.write_str("commit() for a key that was never begun"),
            CommitError::DivergentResult { existing_hash, attempted_hash } => write!(
                f,
                "divergent result for idempotent key: committed {existing_hash:#x}, attempted {attempted_hash:#x}"
            ),
        }
    }
}

impl std::error::Error for CommitError {}

/// The result of a successful commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitOutcome {
    /// Tokens actually billed by *this* commit (0 when the commit was a duplicate — never a double).
    pub billed_now: u64,
    /// The pinned result hash for the key.
    pub result_hash: u64,
}

/// A deterministic idempotency ledger for inference calls (ADR-013, SERVING_OPS.md §1/§4).
///
/// Pure: no clock, no I/O. The key namespace is the caller's (a gateway request id); this crate only
/// guarantees exactly-once billing and answer-stability across retries.
#[derive(Debug, Clone, Default)]
pub struct IdempotencyLedger {
    records: BTreeMap<String, Record>,
}

impl IdempotencyLedger {
    pub fn new() -> Self {
        IdempotencyLedger::default()
    }

    /// Begin (or resume) a request under `key`. See [`BeginOutcome`].
    pub fn begin(&mut self, key: &str) -> BeginOutcome {
        match self.records.get(key) {
            Some(Record::Committed {
                tokens_billed,
                result_hash,
            }) => BeginOutcome::AlreadyCommitted {
                tokens_billed: *tokens_billed,
                result_hash: *result_hash,
            },
            Some(Record::InFlight { attempt }) => {
                let next = attempt.saturating_add(1);
                self.records
                    .insert(key.to_string(), Record::InFlight { attempt: next });
                BeginOutcome::Retry { attempt: next }
            }
            None => {
                self.records
                    .insert(key.to_string(), Record::InFlight { attempt: 1 });
                BeginOutcome::Fresh
            }
        }
    }

    /// Commit `key` with the tokens consumed and a hash pinning the answer. Bills exactly once; a
    /// duplicate commit of the same hash bills nothing; a commit of a divergent hash is rejected.
    pub fn commit(
        &mut self,
        key: &str,
        tokens: u64,
        result_hash: u64,
    ) -> Result<CommitOutcome, CommitError> {
        match self.records.get(key) {
            None => Err(CommitError::NotBegun),
            Some(Record::Committed {
                tokens_billed: _,
                result_hash: existing,
            }) => {
                if *existing == result_hash {
                    // Idempotent replay of the same answer — never bill twice.
                    Ok(CommitOutcome {
                        billed_now: 0,
                        result_hash: *existing,
                    })
                } else {
                    Err(CommitError::DivergentResult {
                        existing_hash: *existing,
                        attempted_hash: result_hash,
                    })
                }
            }
            Some(Record::InFlight { .. }) => {
                self.records.insert(
                    key.to_string(),
                    Record::Committed {
                        tokens_billed: tokens,
                        result_hash,
                    },
                );
                Ok(CommitOutcome {
                    billed_now: tokens,
                    result_hash,
                })
            }
        }
    }

    /// True once `key` has committed a final answer.
    pub fn is_committed(&self, key: &str) -> bool {
        matches!(self.records.get(key), Some(Record::Committed { .. }))
    }

    /// The current attempt number for an in-flight key (`None` if unknown or already committed).
    pub fn attempt(&self, key: &str) -> Option<u32> {
        match self.records.get(key) {
            Some(Record::InFlight { attempt }) => Some(*attempt),
            _ => None,
        }
    }

    /// Total tokens billed across all committed requests — the FinOps accounting signal.
    pub fn total_billed(&self) -> u64 {
        self.records
            .values()
            .filter_map(|r| match r {
                Record::Committed { tokens_billed, .. } => Some(*tokens_billed),
                _ => None,
            })
            .sum()
    }
}

// ---------------------------------------------------------------------------
// Drain-the-group in-flight disposition (SERVING_OPS.md §4 step 2)
// ---------------------------------------------------------------------------

/// An in-flight request on a shard group that is being drained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InFlightRequest {
    /// The idempotency key that makes the retry safe.
    pub key: String,
    pub priority: PriorityClass,
}

/// What Serving-Ops does with one in-flight request when its group drains (SERVING_OPS.md §4 step 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DrainDisposition {
    /// P0/P1: fail back to the gateway and retry against a healthy group under the idempotency
    /// ledger — a retry never double-bills (billing is at commit) nor diverges (the divergence guard).
    RetryOnHealthyGroup {
        key: String,
        priority: PriorityClass,
    },
    /// P2 (Program/Batch): checkpoint to `PENDING` and re-queue at the Program Supervisor level
    /// (ADR-027) — the same idempotent-resume contract, not inline retry.
    CheckpointToPending { key: String },
}

/// Route each in-flight request of a draining group to its recovery path by priority class
/// (SERVING_OPS.md §4 step 2). The ledger is consulted so an already-committed request needs no
/// recovery at all — its answer is final and must not be re-run.
pub fn dispose_on_drain(
    inflight: &[InFlightRequest],
    ledger: &IdempotencyLedger,
) -> Vec<DrainDisposition> {
    inflight
        .iter()
        .filter(|r| !ledger.is_committed(&r.key)) // a committed request is done — never re-run.
        .map(|r| match r.priority {
            PriorityClass::Batch => DrainDisposition::CheckpointToPending { key: r.key.clone() },
            _ => DrainDisposition::RetryOnHealthyGroup {
                key: r.key.clone(),
                priority: r.priority,
            },
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gap_ainxt_serving_srv_08_first_commit_bills_once_retry_returns_recorded_answer() {
        let mut l = IdempotencyLedger::new();
        assert_eq!(l.begin("req-1"), BeginOutcome::Fresh);
        // Execute, then commit 512 tokens with answer-hash 0xAA.
        let c = l.commit("req-1", 512, 0xAA).unwrap();
        assert_eq!(c.billed_now, 512);
        assert_eq!(l.total_billed(), 512);
        // A retry of a committed key returns the recorded result and bills NOTHING more.
        assert_eq!(
            l.begin("req-1"),
            BeginOutcome::AlreadyCommitted {
                tokens_billed: 512,
                result_hash: 0xAA
            }
        );
        // A duplicate commit of the same answer is a safe no-op (billed_now == 0).
        let dup = l.commit("req-1", 512, 0xAA).unwrap();
        assert_eq!(dup.billed_now, 0);
        assert_eq!(l.total_billed(), 512, "still billed exactly once");
    }

    #[test]
    fn gap_ainxt_serving_srv_08_retry_after_drop_does_not_double_bill() {
        // A node drained mid-generation: the first attempt never committed.
        let mut l = IdempotencyLedger::new();
        assert_eq!(l.begin("req-2"), BeginOutcome::Fresh); // attempt 1
                                                           // ... group drained before commit; the gateway retries the SAME key on a healthy group.
        assert_eq!(l.begin("req-2"), BeginOutcome::Retry { attempt: 2 });
        assert_eq!(l.attempt("req-2"), Some(2));
        // Only the successful retry commits → billed exactly once, not once per attempt.
        let c = l.commit("req-2", 300, 0xBEEF).unwrap();
        assert_eq!(c.billed_now, 300);
        assert_eq!(l.total_billed(), 300);
    }

    #[test]
    fn gap_ainxt_serving_srv_08_divergent_result_is_rejected() {
        let mut l = IdempotencyLedger::new();
        l.begin("req-3");
        l.commit("req-3", 100, 0x1111).unwrap();
        // A second commit with a DIFFERENT answer hash is the "two divergent answers" case → rejected.
        assert_eq!(
            l.commit("req-3", 100, 0x2222),
            Err(CommitError::DivergentResult {
                existing_hash: 0x1111,
                attempted_hash: 0x2222
            })
        );
    }

    #[test]
    fn commit_without_begin_is_an_error_not_a_panic() {
        let mut l = IdempotencyLedger::new();
        assert_eq!(l.commit("ghost", 1, 1), Err(CommitError::NotBegun));
    }

    #[test]
    fn gap_ainxt_serving_srv_08_drain_disposition_routes_by_priority_class() {
        let ledger = IdempotencyLedger::new();
        let inflight = vec![
            InFlightRequest {
                key: "p0".into(),
                priority: PriorityClass::Interactive,
            },
            InFlightRequest {
                key: "p1".into(),
                priority: PriorityClass::Standard,
            },
            InFlightRequest {
                key: "p2".into(),
                priority: PriorityClass::Batch,
            },
        ];
        let plan = dispose_on_drain(&inflight, &ledger);
        assert_eq!(
            plan,
            vec![
                DrainDisposition::RetryOnHealthyGroup {
                    key: "p0".into(),
                    priority: PriorityClass::Interactive
                },
                DrainDisposition::RetryOnHealthyGroup {
                    key: "p1".into(),
                    priority: PriorityClass::Standard
                },
                DrainDisposition::CheckpointToPending { key: "p2".into() },
            ]
        );
    }

    #[test]
    fn gap_ainxt_serving_srv_08_already_committed_request_is_not_recovered_on_drain() {
        // A request that already produced its final answer must NOT be re-run when its group drains.
        let mut ledger = IdempotencyLedger::new();
        ledger.begin("done");
        ledger.commit("done", 42, 0xC0DE).unwrap();
        let inflight = vec![
            InFlightRequest {
                key: "done".into(),
                priority: PriorityClass::Interactive,
            },
            InFlightRequest {
                key: "live".into(),
                priority: PriorityClass::Interactive,
            },
        ];
        let plan = dispose_on_drain(&inflight, &ledger);
        // Only the still-live request is scheduled for retry.
        assert_eq!(
            plan,
            vec![DrainDisposition::RetryOnHealthyGroup {
                key: "live".into(),
                priority: PriorityClass::Interactive
            }]
        );
    }
}
