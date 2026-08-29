// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Incremental index maintenance + per-node staleness tracking.
//!
//! Design: `docs/architecture/CONTEXT_FABRIC.md` §4 ("Incremental maintenance — so it never
//! rots"): graphs/indexes update on **file change / index / commit / runtime event**
//! (event-driven, not batch), with **staleness tracking per node** driving re-index/re-embed
//! triggers, and a `stale_as_of` freshness flag so stale data is never silently served as
//! current (`STRUCTURED_FEDERATED_RETRIEVAL.md` §3.1).
//!
//! The [`Corpus`](crate::Corpus) itself is an immutable snapshot (rebuilding it is what keeps
//! the BM25 df/avgdl statistics consistent — a live mutation mid-query would corrupt them).
//! This module is the *event-driven layer above* that snapshot: an [`IndexState`] tracks, per
//! node id, the content fingerprint last indexed and the logical tick it was indexed at.
//! Applying a batch of [`SourceEvent`]s (the file-change / commit / runtime events) returns the
//! exact set of [`ReindexTrigger`]s — which nodes were added, whose content actually changed
//! (fingerprint differs, so a re-embed is needed) and which were removed — so a rebuild
//! re-embeds only what changed, never the whole corpus, and never *misses* a change.
//!
//! Deterministic: the "now" tick is passed in (no wall clock — `DETERMINISTIC` mandate), and
//! the fingerprint is a fixed FNV-1a over the bytes (no rng, no hash-map iteration order in the
//! output — results are id-sorted).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// A stable, dependency-free content fingerprint (FNV-1a, 64-bit) over the UTF-8 bytes. Used to
/// tell "the same node was re-seen with identical content" (no re-embed needed) from "its
/// content actually changed" (re-embed needed) — the distinction that makes maintenance
/// incremental rather than a full rebuild.
pub fn content_fingerprint(text: &str) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;
    let mut hash = FNV_OFFSET;
    for b in text.as_bytes() {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// An incoming index event (a file save, a commit touching a file, a runtime signal that a
/// node's content is new). The unit of event-driven maintenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum SourceEvent {
    /// The node `id` now has this `text` (insert if new, replace if it changed).
    Upsert { id: String, text: String },
    /// The node `id` no longer exists and must leave the index (and cascade to its embedding).
    Remove { id: String },
}

/// What an applied event batch requires of the (re)builder for one node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReindexTrigger {
    /// A brand-new node — index it and generate its embedding.
    Added { id: String },
    /// An existing node whose content changed — re-index and **re-embed** (its old vector is now
    /// stale for the new text).
    Changed { id: String },
    /// A node removed — drop it from the index and cascade-delete its embedding row.
    Removed { id: String },
}

impl ReindexTrigger {
    /// The node id this trigger concerns.
    pub fn id(&self) -> &str {
        match self {
            ReindexTrigger::Added { id }
            | ReindexTrigger::Changed { id }
            | ReindexTrigger::Removed { id } => id,
        }
    }

    /// True iff this trigger requires (re)generating an embedding (Added or Changed).
    pub fn needs_embedding(&self) -> bool {
        matches!(
            self,
            ReindexTrigger::Added { .. } | ReindexTrigger::Changed { .. }
        )
    }
}

/// Per-node index bookkeeping: the content fingerprint last indexed and the logical tick it was
/// indexed at (for `stale_as_of` freshness).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct IndexEntry {
    fingerprint: u64,
    indexed_tick: i64,
}

/// The event-driven index-state tracker sitting above the immutable corpus snapshot.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexState {
    entries: BTreeMap<String, IndexEntry>,
}

impl IndexState {
    pub fn new() -> Self {
        IndexState::default()
    }

    /// Number of tracked nodes.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True iff nothing is tracked.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The logical tick a node was last indexed at, if tracked.
    pub fn indexed_tick(&self, id: &str) -> Option<i64> {
        self.entries.get(id).map(|e| e.indexed_tick)
    }

    /// Apply a batch of events at logical tick `now`, mutating the tracked state and returning
    /// the exact [`ReindexTrigger`]s needed — one per node that was added, genuinely changed, or
    /// removed. An `Upsert` whose content fingerprint is unchanged yields **no** trigger and does
    /// **not** bump `indexed_tick` (re-seeing identical content is not a re-index). Triggers are
    /// returned id-sorted for a deterministic sweep. Later events for the same id in one batch
    /// win (last-write-wins within the batch).
    pub fn apply(&mut self, events: &[SourceEvent], now: i64) -> Vec<ReindexTrigger> {
        // Collapse the batch to the final intended state per id (last-write-wins), so an
        // Upsert-then-Remove in one batch nets to a Remove, and a churned node triggers once.
        let mut final_op: BTreeMap<String, Option<String>> = BTreeMap::new();
        for ev in events {
            match ev {
                SourceEvent::Upsert { id, text } => {
                    final_op.insert(id.clone(), Some(text.clone()));
                }
                SourceEvent::Remove { id } => {
                    final_op.insert(id.clone(), None);
                }
            }
        }

        let mut triggers = Vec::new();
        for (id, op) in final_op {
            match op {
                None => {
                    if self.entries.remove(&id).is_some() {
                        triggers.push(ReindexTrigger::Removed { id });
                    }
                    // Removing an untracked id is a no-op (idempotent), no trigger.
                }
                Some(text) => {
                    let fp = content_fingerprint(&text);
                    // Copy the previous fingerprint out so the immutable borrow ends before the
                    // mutable insert below (no borrow overlap).
                    let prev_fp = self.entries.get(&id).map(|e| e.fingerprint);
                    match prev_fp {
                        Some(old) if old == fp => {
                            // Identical content re-seen — nothing to do, freshness unchanged.
                        }
                        Some(_) => {
                            self.entries.insert(
                                id.clone(),
                                IndexEntry {
                                    fingerprint: fp,
                                    indexed_tick: now,
                                },
                            );
                            triggers.push(ReindexTrigger::Changed { id });
                        }
                        None => {
                            self.entries.insert(
                                id.clone(),
                                IndexEntry {
                                    fingerprint: fp,
                                    indexed_tick: now,
                                },
                            );
                            triggers.push(ReindexTrigger::Added { id });
                        }
                    }
                }
            }
        }
        triggers
    }

    /// The ids whose last index is older than `max_age` ticks relative to `now` — the staleness
    /// worklist (`CONTEXT_FABRIC.md` §4, "re-index/re-embed triggers"). Id-sorted.
    pub fn stale(&self, now: i64, max_age: i64) -> Vec<String> {
        self.entries
            .iter()
            .filter(|(_, e)| now.saturating_sub(e.indexed_tick) > max_age)
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// The oldest `indexed_tick` across all tracked nodes — the `stale_as_of` watermark a
    /// response should carry so stale data is never presented as current
    /// (`STRUCTURED_FEDERATED_RETRIEVAL.md` §3.1). `None` for an empty index.
    pub fn stale_as_of(&self) -> Option<i64> {
        self.entries.values().map(|e| e.indexed_tick).min()
    }

    /// Given a freshness SLA (max acceptable age) and the current tick, decide whether a served
    /// result must be flagged stale, and as-of when. `Fresh` iff no tracked node exceeds the SLA.
    pub fn freshness(&self, now: i64, sla: i64) -> Freshness {
        let stale = self.stale(now, sla);
        if stale.is_empty() {
            Freshness::Fresh
        } else {
            Freshness::Stale {
                as_of: self.stale_as_of().unwrap_or(now),
                stale_ids: stale,
            }
        }
    }
}

/// The freshness verdict for a served result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Freshness {
    /// Every tracked node is within the SLA — serve without a staleness flag.
    Fresh,
    /// At least one node exceeds the SLA — the response MUST carry `as_of` rather than claim to
    /// be current.
    Stale { as_of: i64, stale_ids: Vec<String> },
}

impl Freshness {
    pub fn is_fresh(&self) -> bool {
        matches!(self, Freshness::Fresh)
    }
}

// ---------------------------------------------------------------------------------------
// Vector-index recall/latency monitoring (CONTEXT_FABRIC.md §4 "recall/latency tuned + monitored")
// ---------------------------------------------------------------------------------------

/// SLO thresholds for the vector index (`CONTEXT_FABRIC.md` §4). `min_recall_at_k` is the floor
/// recall@k the ANN index must sustain against an exact-search ground truth (an HNSW that has
/// silently degraded — bad `ef_search`, an unbuilt/mixed-version index — retrieves the wrong
/// neighbours and quietly kills answer quality); `max_p99_latency_ms` is the tail-latency ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct IndexSlo {
    pub min_recall_at_k: f64,
    pub max_p99_latency_ms: u64,
}

impl Default for IndexSlo {
    fn default() -> Self {
        // Conservative defaults: 0.95 recall@k, 150ms p99 — tunable per deployment.
        IndexSlo {
            min_recall_at_k: 0.95,
            max_p99_latency_ms: 150,
        }
    }
}

/// The monitored health of the vector index against its [`IndexSlo`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum IndexHealth {
    /// Recall and tail latency are both within SLO.
    Healthy {
        recall_at_k: f64,
        p99_latency_ms: u64,
    },
    /// Recall@k has dropped below the floor — retrieval quality is degraded; re-tune `ef_search` /
    /// rebuild the index. Carries the measured recall and the floor it breached.
    RecallDegraded { recall_at_k: f64, floor: f64 },
    /// Tail latency exceeds the ceiling — the index is a latency risk on the serving path.
    LatencyDegraded { p99_latency_ms: u64, ceiling: u64 },
    /// No samples recorded yet — status is unknown (never reported as healthy by default).
    NoData,
}

impl IndexHealth {
    pub fn is_healthy(&self) -> bool {
        matches!(self, IndexHealth::Healthy { .. })
    }
}

/// Rolling recall/latency monitor for the vector index (`CONTEXT_FABRIC.md` §4). Recall samples are
/// measured offline against an exact-search ground truth (fraction of true top-k neighbours the ANN
/// index also returned); latency samples are query wall-times in ms. [`status`] reports the current
/// [`IndexHealth`] against the [`IndexSlo`] — recall is judged on the mean, latency on the p99
/// (tail), the two dimensions the design names. Bounded memory: keeps the most recent `window`
/// samples of each.
///
/// [`status`]: RecallLatencyMonitor::status
#[derive(Debug, Clone)]
pub struct RecallLatencyMonitor {
    slo: IndexSlo,
    window: usize,
    recall_samples: Vec<f64>,
    latency_samples: Vec<u64>,
}

impl RecallLatencyMonitor {
    pub fn new(slo: IndexSlo, window: usize) -> Self {
        RecallLatencyMonitor {
            slo,
            window: window.max(1),
            recall_samples: Vec::new(),
            latency_samples: Vec::new(),
        }
    }

    /// Record one recall@k measurement (`[0,1]`, clamped) against exact-search ground truth.
    pub fn record_recall(&mut self, recall_at_k: f64) {
        self.recall_samples.push(recall_at_k.clamp(0.0, 1.0));
        if self.recall_samples.len() > self.window {
            self.recall_samples.remove(0);
        }
    }

    /// Record one query latency measurement (ms).
    pub fn record_latency(&mut self, latency_ms: u64) {
        self.latency_samples.push(latency_ms);
        if self.latency_samples.len() > self.window {
            self.latency_samples.remove(0);
        }
    }

    /// Mean recall@k over the window (`None` if no samples).
    pub fn mean_recall(&self) -> Option<f64> {
        if self.recall_samples.is_empty() {
            return None;
        }
        Some(self.recall_samples.iter().sum::<f64>() / self.recall_samples.len() as f64)
    }

    /// p99 latency over the window (`None` if no samples). Nearest-rank p99 on the sorted window.
    pub fn p99_latency(&self) -> Option<u64> {
        if self.latency_samples.is_empty() {
            return None;
        }
        let mut sorted = self.latency_samples.clone();
        sorted.sort_unstable();
        // Nearest-rank: ceil(0.99 * n) th value (1-based) → index (rank-1).
        let n = sorted.len();
        let rank = ((0.99 * n as f64).ceil() as usize).max(1);
        Some(sorted[rank - 1])
    }

    /// The current index health verdict against the SLO. Recall is checked first (a quality problem
    /// dominates a latency problem); then latency; else healthy.
    pub fn status(&self) -> IndexHealth {
        let recall = self.mean_recall();
        let p99 = self.p99_latency();
        match (recall, p99) {
            (None, None) => IndexHealth::NoData,
            _ => {
                if let Some(r) = recall {
                    if r < self.slo.min_recall_at_k {
                        return IndexHealth::RecallDegraded {
                            recall_at_k: r,
                            floor: self.slo.min_recall_at_k,
                        };
                    }
                }
                if let Some(l) = p99 {
                    if l > self.slo.max_p99_latency_ms {
                        return IndexHealth::LatencyDegraded {
                            p99_latency_ms: l,
                            ceiling: self.slo.max_p99_latency_ms,
                        };
                    }
                }
                IndexHealth::Healthy {
                    recall_at_k: recall.unwrap_or(1.0),
                    p99_latency_ms: p99.unwrap_or(0),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_stable_and_content_sensitive() {
        assert_eq!(content_fingerprint("abc"), content_fingerprint("abc"));
        assert_ne!(content_fingerprint("abc"), content_fingerprint("abd"));
        // Order matters (it's a real hash, not a set): "ab" != "ba".
        assert_ne!(content_fingerprint("ab"), content_fingerprint("ba"));
    }

    #[test]
    fn apply_classifies_add_change_remove() {
        let mut s = IndexState::new();
        let t = s.apply(
            &[
                SourceEvent::Upsert {
                    id: "a".into(),
                    text: "one".into(),
                },
                SourceEvent::Upsert {
                    id: "b".into(),
                    text: "two".into(),
                },
            ],
            10,
        );
        assert_eq!(t.len(), 2);
        assert!(t.iter().all(|x| matches!(x, ReindexTrigger::Added { .. })));
        assert_eq!(s.len(), 2);

        // Change a, leave b identical, add c.
        let t2 = s.apply(
            &[
                SourceEvent::Upsert {
                    id: "a".into(),
                    text: "ONE-CHANGED".into(),
                },
                SourceEvent::Upsert {
                    id: "b".into(),
                    text: "two".into(),
                }, // identical → no trigger
                SourceEvent::Upsert {
                    id: "c".into(),
                    text: "three".into(),
                },
            ],
            20,
        );
        // a changed, c added, b silent.
        assert_eq!(t2.len(), 2, "identical re-upsert of b must not trigger");
        assert!(t2
            .iter()
            .any(|x| matches!(x, ReindexTrigger::Changed { id } if id == "a")));
        assert!(t2
            .iter()
            .any(|x| matches!(x, ReindexTrigger::Added { id } if id == "c")));
        // b's indexed_tick stayed at 10 (identical content is not a re-index).
        assert_eq!(s.indexed_tick("b"), Some(10));
        assert_eq!(s.indexed_tick("a"), Some(20));
    }

    #[test]
    fn changed_node_needs_reembed_removed_does_not() {
        let mut s = IndexState::new();
        s.apply(
            &[SourceEvent::Upsert {
                id: "a".into(),
                text: "x".into(),
            }],
            1,
        );
        let changed = s.apply(
            &[SourceEvent::Upsert {
                id: "a".into(),
                text: "y".into(),
            }],
            2,
        );
        assert!(changed[0].needs_embedding(), "a changed node must re-embed");

        let removed = s.apply(&[SourceEvent::Remove { id: "a".into() }], 3);
        assert_eq!(removed.len(), 1);
        assert!(
            !removed[0].needs_embedding(),
            "a removal cascades delete, not re-embed"
        );
        assert!(s.is_empty());
    }

    #[test]
    fn removing_untracked_id_is_idempotent_noop() {
        let mut s = IndexState::new();
        let t = s.apply(&[SourceEvent::Remove { id: "ghost".into() }], 5);
        assert!(t.is_empty());
    }

    #[test]
    fn upsert_then_remove_in_one_batch_nets_to_removed_only() {
        let mut s = IndexState::new();
        s.apply(
            &[SourceEvent::Upsert {
                id: "a".into(),
                text: "x".into(),
            }],
            1,
        );
        // Within one batch: change then remove → net Removed, single trigger.
        let t = s.apply(
            &[
                SourceEvent::Upsert {
                    id: "a".into(),
                    text: "y".into(),
                },
                SourceEvent::Remove { id: "a".into() },
            ],
            2,
        );
        assert_eq!(t, vec![ReindexTrigger::Removed { id: "a".into() }]);
        assert!(s.is_empty());
    }

    #[test]
    fn staleness_and_freshness_flag() {
        let mut s = IndexState::new();
        s.apply(
            &[SourceEvent::Upsert {
                id: "old".into(),
                text: "x".into(),
            }],
            100,
        );
        s.apply(
            &[SourceEvent::Upsert {
                id: "new".into(),
                text: "y".into(),
            }],
            300,
        );

        // SLA = 150 ticks. At now=320: "old" (age 220) is stale, "new" (age 20) is fresh.
        assert_eq!(s.stale(320, 150), vec!["old".to_string()]);
        assert_eq!(s.stale_as_of(), Some(100));

        match s.freshness(320, 150) {
            Freshness::Stale { as_of, stale_ids } => {
                assert_eq!(as_of, 100, "as_of is the oldest indexed tick");
                assert_eq!(stale_ids, vec!["old".to_string()]);
            }
            Freshness::Fresh => panic!("expected a stale flag"),
        }

        // A generous SLA makes everything fresh.
        assert!(s.freshness(320, 10_000).is_fresh());
    }
}
