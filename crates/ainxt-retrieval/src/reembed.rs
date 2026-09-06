// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Embedding-model lifecycle → a live re-embed pipeline.
//!
//! Design: `CONTEXT_FABRIC.md` §4 ("version-tracked embeddings + a re-embed pipeline so
//! migrations never leave a mixed-version index; event-driven staleness triggers"). The building
//! blocks already exist: [`crate::maintenance::IndexState`] turns source events into
//! [`crate::maintenance::ReindexTrigger`]s, [`crate::EmbeddingVersion`] tags every vector, and
//! [`crate::Corpus::stale_embeddings`] enumerates what is not yet at the target version. What was
//! missing is the *pipeline that connects them to an embedder and drives the index to a single
//! version* — this module.
//!
//! The flow (all pure/deterministic; the only side-effecting step is a trait seam):
//!
//! 1. [`plan_reembed`] — turn a batch of [`ReindexTrigger`]s into a [`ReembedPlan`]: the ids whose
//!    content changed/added (need a fresh vector) and the ids removed (whose vector must be
//!    cascade-deleted, gap AN + ADR-015 erasure).
//! 2. [`run_reembed`] — for each to-embed id, call the [`Embedder`] seam (a real deployment plugs
//!    in `services/embed_svc`), tagging every produced vector with the embedder's
//!    [`EmbeddingVersion`]. An embedder failure for an id is recorded, **not** silently skipped —
//!    so a partial migration is visible, never mistaken for complete.
//! 3. [`migrate_to`] — the convenience driver: given the current corpus and a target version,
//!    re-embed exactly [`crate::Corpus::stale_embeddings`] and report whether the corpus reached
//!    [`crate::Corpus::is_embedding_uniform`]. This is the loop an index worker runs after the
//!    platform embedding model is bumped.
//!
//! The actual embedding computation (the ML model) is the seam — everything else, including the
//! fail-visible partial-migration accounting, is real logic with real tests.

use std::collections::BTreeMap;

use crate::maintenance::ReindexTrigger;
use crate::{Chunk, Corpus, EmbeddingVersion};

/// The embed-service seam. A real deployment implements this with `services/embed_svc` (Ollama
/// `nomic-embed-text`); the returned vector is tagged with [`Embedder::version`] so the corpus
/// never mixes embedding spaces. Returning `None` = the embed call failed for this text (service
/// down, too long, etc.) and MUST surface as a failure, not a silent drop.
pub trait Embedder {
    fn embed(&self, text: &str) -> Option<Vec<f32>>;
    /// The model + generation this embedder produces (stamped onto every vector).
    fn version(&self) -> EmbeddingVersion;
}

/// The work a batch of reindex triggers implies for the embedding index.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReembedPlan {
    /// Ids that need a (re)generated embedding — Added or Changed nodes.
    pub to_embed: Vec<String>,
    /// Ids whose embedding must be cascade-deleted — Removed nodes.
    pub to_delete: Vec<String>,
}

impl ReembedPlan {
    pub fn is_empty(&self) -> bool {
        self.to_embed.is_empty() && self.to_delete.is_empty()
    }
}

/// Turn reindex triggers into a re-embed plan. `Added`/`Changed` → re-embed; `Removed` → delete.
/// Ids are de-duplicated and sorted for a deterministic sweep.
pub fn plan_reembed(triggers: &[ReindexTrigger]) -> ReembedPlan {
    let mut to_embed = std::collections::BTreeSet::new();
    let mut to_delete = std::collections::BTreeSet::new();
    for t in triggers {
        match t {
            ReindexTrigger::Added { id } | ReindexTrigger::Changed { id } => {
                to_embed.insert(id.clone());
            }
            ReindexTrigger::Removed { id } => {
                to_delete.insert(id.clone());
            }
        }
    }
    ReembedPlan {
        to_embed: to_embed.into_iter().collect(),
        to_delete: to_delete.into_iter().collect(),
    }
}

/// A single re-embed result for one id.
#[derive(Debug, Clone, PartialEq)]
pub enum ReembedResult {
    /// The id was successfully re-embedded at `version`.
    Embedded {
        id: String,
        version: EmbeddingVersion,
    },
    /// The embedder could not produce a vector for the id (fail-visible, not silently skipped).
    Failed { id: String },
    /// The id's embedding was cascade-deleted (removed node).
    Deleted { id: String },
}

/// The outcome of running a [`ReembedPlan`] through an [`Embedder`].
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ReembedOutcome {
    /// Newly produced vectors, keyed by id, each tagged with the embedder version.
    pub embeddings: BTreeMap<String, (Vec<f32>, EmbeddingVersion)>,
    /// Per-id results (embedded / failed / deleted), id-sorted.
    pub results: Vec<ReembedResult>,
}

impl ReembedOutcome {
    /// Ids that failed to embed — a non-empty list means the migration is INCOMPLETE.
    pub fn failed_ids(&self) -> Vec<&str> {
        self.results
            .iter()
            .filter_map(|r| match r {
                ReembedResult::Failed { id } => Some(id.as_str()),
                _ => None,
            })
            .collect()
    }

    /// True iff every planned embed succeeded (no failures). Deletes never count as failures.
    pub fn complete(&self) -> bool {
        self.failed_ids().is_empty()
    }
}

/// Run a re-embed plan against an embedder. `texts` supplies the current content per id (the
/// caller has it — the corpus/source of truth); an id in `to_embed` with no text is treated as an
/// embed failure (its content vanished mid-migration — surface it, don't skip). Deterministic:
/// results are id-sorted.
pub fn run_reembed(
    plan: &ReembedPlan,
    texts: &BTreeMap<String, String>,
    embedder: &dyn Embedder,
) -> ReembedOutcome {
    let version = embedder.version();
    let mut embeddings = BTreeMap::new();
    let mut results = Vec::new();

    for id in &plan.to_embed {
        match texts.get(id).and_then(|t| embedder.embed(t)) {
            Some(vec) => {
                embeddings.insert(id.clone(), (vec, version.clone()));
                results.push(ReembedResult::Embedded {
                    id: id.clone(),
                    version: version.clone(),
                });
            }
            None => results.push(ReembedResult::Failed { id: id.clone() }),
        }
    }
    for id in &plan.to_delete {
        results.push(ReembedResult::Deleted { id: id.clone() });
    }
    results.sort_by(|a, b| result_id(a).cmp(result_id(b)));
    ReembedOutcome {
        embeddings,
        results,
    }
}

fn result_id(r: &ReembedResult) -> &str {
    match r {
        ReembedResult::Embedded { id, .. }
        | ReembedResult::Failed { id }
        | ReembedResult::Deleted { id } => id,
    }
}

/// The report of a full migration attempt toward `target`.
#[derive(Debug, Clone)]
pub struct MigrationReport {
    pub outcome: ReembedOutcome,
    /// The rebuilt corpus with newly-embedded chunks carrying `target`.
    pub corpus: Corpus,
    /// True iff EVERY chunk in the rebuilt corpus is now at `target` (no mixed-version index).
    pub uniform: bool,
}

/// The end-to-end migration driver an index worker runs after bumping the platform embedding
/// model: re-embed exactly the stale chunks ([`Corpus::stale_embeddings`]) to `target` and report
/// whether the corpus reached a single version. A chunk that fails to re-embed is left at its old
/// version (visible via `!uniform` and `outcome.failed_ids()`) — never falsely marked migrated.
pub fn migrate_to(
    corpus: &Corpus,
    target: &EmbeddingVersion,
    embedder: &dyn Embedder,
) -> MigrationReport {
    // The stale worklist = everything not already at target.
    let stale_idx = corpus.stale_embeddings(target);
    let mut texts = BTreeMap::new();
    let mut to_embed = Vec::new();
    for &i in &stale_idx {
        if let Some(c) = corpus.chunk(i) {
            texts.insert(c.id.clone(), c.text.clone());
            to_embed.push(c.id.clone());
        }
    }
    let plan = ReembedPlan {
        to_embed,
        to_delete: Vec::new(),
    };
    let outcome = run_reembed(&plan, &texts, embedder);

    // Rebuild the corpus, applying successful re-embeddings.
    let mut rebuilt: Vec<Chunk> = Vec::new();
    for i in 0..corpus.len() {
        let c = corpus.chunk(i).expect("index in range");
        let mut nc = c.clone();
        if let Some((vec, ver)) = outcome.embeddings.get(&c.id) {
            nc.embedding = Some(vec.clone());
            nc.embedding_model = Some(ver.clone());
        }
        rebuilt.push(nc);
    }
    let corpus = Corpus::new(rebuilt);
    let uniform = corpus.is_embedding_uniform(target);
    MigrationReport {
        outcome,
        corpus,
        uniform,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::maintenance::{IndexState, SourceEvent};

    /// A fake embedder producing a fixed-dim vector; refuses a sentinel text to model a failure.
    struct FakeEmbedder {
        version: EmbeddingVersion,
    }
    impl Embedder for FakeEmbedder {
        fn embed(&self, text: &str) -> Option<Vec<f32>> {
            if text == "<<unembeddable>>" {
                return None;
            }
            // Deterministic tiny "embedding": [len, first-byte].
            let first = text.bytes().next().unwrap_or(0) as f32;
            Some(vec![text.len() as f32, first])
        }
        fn version(&self) -> EmbeddingVersion {
            self.version.clone()
        }
    }

    #[test]
    fn plan_splits_triggers_into_embed_and_delete() {
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
            1,
        );
        let plan = plan_reembed(&t);
        assert_eq!(plan.to_embed, vec!["a", "b"]);
        assert!(plan.to_delete.is_empty());

        // Change a, remove b.
        let t2 = s.apply(
            &[
                SourceEvent::Upsert {
                    id: "a".into(),
                    text: "one-changed".into(),
                },
                SourceEvent::Remove { id: "b".into() },
            ],
            2,
        );
        let plan2 = plan_reembed(&t2);
        assert_eq!(plan2.to_embed, vec!["a"]);
        assert_eq!(plan2.to_delete, vec!["b"]);
    }

    #[test]
    fn run_reembed_records_failures_visibly() {
        let embedder = FakeEmbedder {
            version: EmbeddingVersion::new("nomic", 3),
        };
        let mut texts = BTreeMap::new();
        texts.insert("ok".to_string(), "real content".to_string());
        texts.insert("bad".to_string(), "<<unembeddable>>".to_string());
        let plan = ReembedPlan {
            to_embed: vec!["ok".into(), "bad".into()],
            to_delete: vec![],
        };
        let outcome = run_reembed(&plan, &texts, &embedder);
        assert!(outcome.embeddings.contains_key("ok"));
        assert!(!outcome.embeddings.contains_key("bad"));
        assert_eq!(outcome.failed_ids(), vec!["bad"]);
        assert!(
            !outcome.complete(),
            "a failed embed makes the batch incomplete"
        );
    }
}
