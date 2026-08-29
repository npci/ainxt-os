// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Eval integrity — sealed holdouts, contamination scanning, rotation, tripwires (EVAL_PLATFORM.md
//! §9, gap AQ).
//!
//! An eval you can pass by *memorization* is worse than no eval — it manufactures confidence. Evals
//! rot three ways; each gets a mechanism, not a hope:
//!
//! * **Sealed holdouts** ([`SealedCorpusStore`], [`SealedManifest`]): the manifest (id/version/
//!   `content_commitment` Merkle root) is a PII-free, reviewable definition; the case corpus + gold
//!   labels live behind a store readable only by the eval-runner identity — never by the authors of
//!   the definitions the set gates. A swapped corpus is caught by the Merkle mismatch exactly like an
//!   ADR-026 `control.lock` check.
//! * **Contamination scanning** ([`scan_contamination`]): before a candidate ships, its prompts /
//!   retrieved context / fine-tune corpus are scanned for n-gram ([`ngram_overlap`]) and
//!   embedding-similarity ([`max_embedding_similarity`]) overlap with eval-case content. A hit fails
//!   the gate as a platform defect.
//! * **Rotation + tripwires** ([`plan_rotation`], [`Tripwire`]): holdouts rotate on a schedule so a
//!   set can't become memorized-by-familiarity, and a small never-tuned slice detects overfitting —
//!   a candidate that aces the visible set but drops on the sealed slice is caught.
//!
//! Deterministic (rotation takes an explicit epoch, never a clock); the cryptographic commitment uses
//! `sha2`. The encrypted at-rest store and KMS are a production seam behind [`SealedCorpusStore`].

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ===========================================================================================
// Content commitment (Merkle root over the sealed corpus)
// ===========================================================================================

/// SHA-256 hex of a byte slice.
fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// A stable leaf hash for one eval case (id + input + gold answer), domain-separated.
pub fn case_leaf_hash(case_id: &str, input: &str, gold: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"ainxt-eval-case-leaf\0");
    for part in [case_id, input, gold] {
        h.update((part.len() as u64).to_le_bytes());
        h.update(part.as_bytes());
    }
    let digest = h.finalize();
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Compute a Merkle root over ordered leaf hashes (duplicate-last for odd levels — a standard,
/// deterministic binary-Merkle construction). Empty input → the hash of the empty string.
pub fn merkle_root(leaves: &[String]) -> String {
    if leaves.is_empty() {
        return sha256_hex(b"");
    }
    let mut level: Vec<String> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            let left = &level[i];
            let right = if i + 1 < level.len() {
                &level[i + 1]
            } else {
                left // duplicate the last node on an odd level
            };
            let mut h = Sha256::new();
            h.update(b"ainxt-merkle-node\0");
            h.update(left.as_bytes());
            h.update(right.as_bytes());
            let digest = h.finalize();
            let mut node = String::with_capacity(64);
            for b in digest {
                node.push_str(&format!("{b:02x}"));
            }
            next.push(node);
            i += 2;
        }
        level = next;
    }
    level.into_iter().next().unwrap()
}

// ===========================================================================================
// Sealed manifest + store seam
// ===========================================================================================

/// The PII-free, git-reviewable manifest binding an eval set's identity/version to its sealed corpus
/// by a content commitment. The manifest is readable by everyone; the corpus is not.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SealedManifest {
    pub set_id: String,
    pub version: String,
    /// Merkle root over the sealed case leaves — the tamper-evident content commitment.
    pub content_commitment: String,
    /// Number of sealed cases (a size check independent of the root).
    pub case_count: usize,
}

impl SealedManifest {
    /// Build a manifest from the sealed cases (id, input, gold-answer triples).
    pub fn build(set_id: &str, version: &str, cases: &[(String, String, String)]) -> Self {
        let leaves: Vec<String> = cases
            .iter()
            .map(|(id, input, gold)| case_leaf_hash(id, input, gold))
            .collect();
        SealedManifest {
            set_id: set_id.to_string(),
            version: version.to_string(),
            content_commitment: merkle_root(&leaves),
            case_count: cases.len(),
        }
    }

    /// Verify a set of cases matches this manifest's commitment (a swapped/tampered corpus fails).
    pub fn verify(&self, cases: &[(String, String, String)]) -> bool {
        if cases.len() != self.case_count {
            return false;
        }
        let leaves: Vec<String> = cases
            .iter()
            .map(|(id, input, gold)| case_leaf_hash(id, input, gold))
            .collect();
        merkle_root(&leaves) == self.content_commitment
    }
}

/// The sealed corpus store — readable only by the eval-runner machine identity (ADR-022) plus a
/// break-glass quorum, never by the authors of the definitions the set gates. This trait is the seam;
/// the production impl is an encrypted, access-controlled data-plane store.
pub trait SealedCorpusStore {
    /// Load the sealed cases for a set version, IF the caller identity is authorized. Returns `None`
    /// when the identity is not the runner (contamination defense) or the set is unknown.
    fn load(
        &self,
        set_id: &str,
        version: &str,
        identity: &str,
    ) -> Option<Vec<(String, String, String)>>;
}

// ===========================================================================================
// Contamination scanning
// ===========================================================================================

/// Word tokens (lowercased, alphanumeric runs).
fn tokens(s: &str) -> Vec<String> {
    s.split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
        .map(|t| t.to_lowercase())
        .collect()
}

/// Distinct n-gram shingles of the token stream.
fn shingles(s: &str, n: usize) -> Vec<String> {
    let toks = tokens(s);
    if n == 0 || toks.len() < n {
        // Fall back to the whole token bag as one shingle so short strings still compare.
        return if toks.is_empty() {
            Vec::new()
        } else {
            vec![toks.join(" ")]
        };
    }
    let mut out: Vec<String> = toks.windows(n).map(|w| w.join(" ")).collect();
    out.sort();
    out.dedup();
    out
}

/// Jaccard overlap of `n`-gram shingles between two texts (0.0–1.0). A high value means the candidate
/// text contains long verbatim runs from the eval case — a memorization signal.
pub fn ngram_overlap(a: &str, b: &str, n: usize) -> f64 {
    let sa = shingles(a, n);
    let sb = shingles(b, n);
    if sa.is_empty() || sb.is_empty() {
        return 0.0;
    }
    let mut inter = 0usize;
    for s in &sa {
        if sb.binary_search(s).is_ok() {
            inter += 1;
        }
    }
    let union = sa.len() + sb.len() - inter;
    if union == 0 {
        0.0
    } else {
        inter as f64 / union as f64
    }
}

/// Cosine similarity of two equal-length embedding vectors (None on mismatch/empty/zero-norm).
pub fn cosine_similarity(a: &[f32], b: &[f32]) -> Option<f64> {
    if a.is_empty() || a.len() != b.len() {
        return None;
    }
    let mut dot = 0.0f64;
    let mut na = 0.0f64;
    let mut nb = 0.0f64;
    for (&xa, &xb) in a.iter().zip(b.iter()) {
        let (xa, xb) = (xa as f64, xb as f64);
        dot += xa * xb;
        na += xa * xa;
        nb += xb * xb;
    }
    if na == 0.0 || nb == 0.0 {
        return None;
    }
    Some(dot / (na.sqrt() * nb.sqrt()))
}

/// The maximum embedding similarity between a candidate embedding and any eval-case embedding.
pub fn max_embedding_similarity(candidate: &[f32], eval_cases: &[Vec<f32>]) -> f64 {
    eval_cases
        .iter()
        .filter_map(|e| cosine_similarity(candidate, e))
        .fold(0.0f64, f64::max)
}

/// Contamination thresholds.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ContaminationPolicy {
    /// n for the n-gram shingles (default 8 — long enough that natural overlap is rare).
    pub ngram_n: usize,
    /// n-gram Jaccard at/above this is contamination (default 0.30).
    pub ngram_threshold: f64,
    /// embedding cosine at/above this is contamination (default 0.95 — near-duplicate paraphrase).
    pub embedding_threshold: f64,
}

impl Default for ContaminationPolicy {
    fn default() -> Self {
        ContaminationPolicy {
            ngram_n: 8,
            ngram_threshold: 0.30,
            embedding_threshold: 0.95,
        }
    }
}

/// One contamination hit.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContaminationHit {
    pub eval_case_id: String,
    pub kind: String,
    pub score: f64,
}

/// The scan result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ContaminationVerdict {
    Clean,
    /// One or more overlaps at/above threshold — the candidate memorized the eval; fail as a defect.
    Contaminated(Vec<ContaminationHit>),
}

impl ContaminationVerdict {
    pub fn is_clean(&self) -> bool {
        matches!(self, ContaminationVerdict::Clean)
    }
}

/// One eval case's content for contamination scanning: id + text (+ optional embedding).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvalCaseContent {
    pub id: String,
    pub text: String,
    pub embedding: Option<Vec<f32>>,
}

/// Scan candidate content (prompts / retrieved context / fine-tune corpus, concatenated) against the
/// eval-case corpus for n-gram and embedding overlap. Any hit at/above threshold is a platform defect.
pub fn scan_contamination(
    candidate_texts: &[String],
    candidate_embeddings: &[Vec<f32>],
    eval_cases: &[EvalCaseContent],
    policy: &ContaminationPolicy,
) -> ContaminationVerdict {
    let mut hits = Vec::new();
    for case in eval_cases {
        // n-gram overlap against each candidate text.
        let mut worst_ngram = 0.0f64;
        for ct in candidate_texts {
            worst_ngram = worst_ngram.max(ngram_overlap(ct, &case.text, policy.ngram_n));
        }
        if worst_ngram >= policy.ngram_threshold {
            hits.push(ContaminationHit {
                eval_case_id: case.id.clone(),
                kind: "ngram".into(),
                score: worst_ngram,
            });
        }
        // embedding overlap (if both sides carry embeddings).
        if let Some(case_emb) = &case.embedding {
            let sim = max_embedding_similarity(case_emb, candidate_embeddings);
            if sim >= policy.embedding_threshold {
                hits.push(ContaminationHit {
                    eval_case_id: case.id.clone(),
                    kind: "embedding".into(),
                    score: sim,
                });
            }
        }
    }
    if hits.is_empty() {
        ContaminationVerdict::Clean
    } else {
        ContaminationVerdict::Contaminated(hits)
    }
}

// ===========================================================================================
// Rotation + tripwires
// ===========================================================================================

/// A holdout case's rotation bookkeeping (deterministic — epochs are explicit, no clock).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HoldoutCase {
    pub id: String,
    /// The epoch this case was minted / last rotated in.
    pub minted_epoch: u64,
    /// How many times this case has been used to gate a change (familiarity risk).
    pub use_count: u64,
    /// A never-tuned tripwire case (excluded from tuning; overfitting detector).
    pub tripwire: bool,
}

/// Which holdout cases to rotate out at `now_epoch`: any whose age exceeds `max_age_epochs` OR whose
/// `use_count` exceeds `max_uses` — but tripwires are never rotated for age alone (they must persist
/// to detect overfitting) unless overused. Returns the ids to retire, sorted for determinism.
pub fn plan_rotation(
    cases: &[HoldoutCase],
    now_epoch: u64,
    max_age_epochs: u64,
    max_uses: u64,
) -> Vec<String> {
    let mut out: Vec<String> = cases
        .iter()
        .filter(|c| {
            let aged = now_epoch.saturating_sub(c.minted_epoch) > max_age_epochs;
            let overused = c.use_count > max_uses;
            if c.tripwire {
                overused
            } else {
                aged || overused
            }
        })
        .map(|c| c.id.clone())
        .collect();
    out.sort();
    out
}

/// A tripwire comparison: the candidate's score on the visible (tunable) set vs the sealed tripwire
/// slice. A candidate that aced the visible set but drops materially on the tripwire is overfitted.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Tripwire {
    /// Max acceptable drop (visible mean − tripwire mean) before overfit is declared.
    pub max_drop: f64,
}

impl Default for Tripwire {
    fn default() -> Self {
        Tripwire { max_drop: 5.0 }
    }
}

/// The tripwire verdict.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum OverfitVerdict {
    Ok {
        drop: f64,
    },
    Overfit {
        visible_mean: f64,
        tripwire_mean: f64,
        drop: f64,
    },
}

impl OverfitVerdict {
    pub fn is_overfit(&self) -> bool {
        matches!(self, OverfitVerdict::Overfit { .. })
    }
}

impl Tripwire {
    pub fn evaluate(&self, visible_mean: f64, tripwire_mean: f64) -> OverfitVerdict {
        let drop = visible_mean - tripwire_mean;
        if drop > self.max_drop {
            OverfitVerdict::Overfit {
                visible_mean,
                tripwire_mean,
                drop,
            }
        } else {
            OverfitVerdict::Ok { drop }
        }
    }
}

// ===========================================================================================
// Flywheel staging → human-gated promotion (EVAL_PLATFORM.md §3.3 / §9.3)
// ===========================================================================================
//
// Flywheel-derived candidates *propose* eval cases; they never *legislate* them into the gate. A
// candidate lands in a STAGING set, contamination-guarded, and only a human promotion moves it into
// the live/holdout set. Auto-adding a flywheel case would let production traffic silently rewrite the
// ruler it is measured by.

/// How a candidate eval case was authored (provenance, §3.3). A case's provenance governs how much
/// scrutiny it needs before it can gate — flywheel-derived cases are the least trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CaseProvenance {
    /// Hand-authored seed case (highest trust).
    Seed,
    /// A verified Breaker repro.
    Breaker,
    /// Derived from live production traffic by the data flywheel (lowest trust — never auto-added).
    Flywheel,
    /// A confirmed incident postmortem.
    Incident,
}

/// A candidate eval case awaiting promotion: identity/content + provenance + the human/contamination
/// gates it must clear. Kept as plain id/text/gold so this stays free of any cross-module coupling.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StagedCase {
    pub id: String,
    pub input: String,
    pub gold: String,
    pub provenance: CaseProvenance,
    /// Set true only by an explicit human review action (never by the flywheel itself).
    pub human_approved: bool,
    /// The contamination scan result recorded at staging time (must be clean to promote).
    pub contamination_clean: bool,
}

/// Why a staged case could not be promoted into the live/holdout set.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PromotionError {
    /// A flywheel/traffic-derived case with no explicit human approval on record.
    NeedsHumanApproval { id: String },
    /// The case overlaps existing eval content — promoting it would poison the gate.
    Contaminated { id: String },
    /// The id already exists in the live set (idempotent — never overwrite).
    AlreadyLive { id: String },
}

/// The flywheel staging area: candidates accumulate here and are promoted one-by-one, never in bulk,
/// never automatically.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct StagingSet {
    staged: Vec<StagedCase>,
    live_ids: std::collections::BTreeSet<String>,
}

impl StagingSet {
    /// Start from the ids already live (so promotion is idempotent against them).
    pub fn with_live_ids(live: impl IntoIterator<Item = String>) -> Self {
        StagingSet {
            staged: Vec::new(),
            live_ids: live.into_iter().collect(),
        }
    }

    /// Stage a flywheel/other candidate. Always allowed — staging is not gating.
    pub fn stage(&mut self, case: StagedCase) {
        self.staged.push(case);
    }

    pub fn staged(&self) -> &[StagedCase] {
        &self.staged
    }

    /// Attempt to promote a staged case into the live set. **Fail-closed:** a flywheel-derived case
    /// requires explicit human approval; any case must be contamination-clean; an already-live id is
    /// rejected. On success the id joins the live set and the promoted case is returned.
    pub fn promote(&mut self, id: &str) -> Result<StagedCase, PromotionError> {
        let idx = self
            .staged
            .iter()
            .position(|c| c.id == id)
            .ok_or_else(|| PromotionError::NeedsHumanApproval { id: id.to_string() })?;
        let case = &self.staged[idx];
        if self.live_ids.contains(&case.id) {
            return Err(PromotionError::AlreadyLive {
                id: case.id.clone(),
            });
        }
        // Flywheel/incident/traffic-derived cases MUST carry an explicit human approval; a seed case
        // authored by review is trusted, but the flywheel can never self-promote.
        if !case.human_approved {
            return Err(PromotionError::NeedsHumanApproval {
                id: case.id.clone(),
            });
        }
        if !case.contamination_clean {
            return Err(PromotionError::Contaminated {
                id: case.id.clone(),
            });
        }
        let promoted = self.staged.remove(idx);
        self.live_ids.insert(promoted.id.clone());
        Ok(promoted)
    }

    pub fn is_live(&self, id: &str) -> bool {
        self.live_ids.contains(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cases() -> Vec<(String, String, String)> {
        vec![
            (
                "c1".into(),
                "when does settlement occur".into(),
                "T+1 cycle".into(),
            ),
            (
                "c2".into(),
                "what is UPI".into(),
                "unified payments interface".into(),
            ),
            (
                "c3".into(),
                "IFSC format".into(),
                "4 letters then 0 then 6".into(),
            ),
        ]
    }

    #[test]
    fn merkle_root_is_stable_and_order_sensitive() {
        let a = merkle_root(&["h1".into(), "h2".into(), "h3".into()]);
        let b = merkle_root(&["h1".into(), "h2".into(), "h3".into()]);
        assert_eq!(a, b, "deterministic");
        let c = merkle_root(&["h2".into(), "h1".into(), "h3".into()]);
        assert_ne!(a, c, "order changes the root");
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn manifest_detects_a_swapped_corpus() {
        let m = SealedManifest::build("rag-groundedness", "v3", &cases());
        assert!(m.verify(&cases()), "the honest corpus verifies");
        // Swap one gold answer → verify fails (tamper-evident).
        let mut tampered = cases();
        tampered[1].2 = "a wrong answer key".into();
        assert!(
            !m.verify(&tampered),
            "a swapped gold label must fail the commitment"
        );
        // Drop a case → count + root mismatch.
        assert!(!m.verify(&cases()[..2]));
    }

    #[test]
    fn sealed_store_denies_non_runner_identity() {
        struct Store;
        impl SealedCorpusStore for Store {
            fn load(
                &self,
                set_id: &str,
                _v: &str,
                identity: &str,
            ) -> Option<Vec<(String, String, String)>> {
                if identity == "eval-runner" && set_id == "s1" {
                    Some(cases())
                } else {
                    None
                }
            }
        }
        let s = Store;
        assert!(
            s.load("s1", "v1", "eval-runner").is_some(),
            "runner may read"
        );
        assert!(
            s.load("s1", "v1", "pr-author").is_none(),
            "the author of the gated change must NOT read the gold answers"
        );
    }

    #[test]
    fn ngram_overlap_flags_verbatim_lift() {
        let eval =
            "the settlement runs on a t plus one net settlement cycle for member banks daily";
        let clean = "unified payments interface enables instant retail transfers between banks";
        let lifted = format!("here is my answer: {eval} and more");
        assert!(
            ngram_overlap(&lifted, eval, 8) > 0.3,
            "verbatim lift of a long span must show high overlap"
        );
        assert!(
            ngram_overlap(clean, eval, 8) < 0.1,
            "unrelated text must show near-zero overlap"
        );
    }

    #[test]
    fn cosine_and_embedding_overlap() {
        let a = vec![1.0f32, 0.0, 0.0];
        let b = vec![1.0f32, 0.0, 0.0];
        let c = vec![0.0f32, 1.0, 0.0];
        assert!((cosine_similarity(&a, &b).unwrap() - 1.0).abs() < 1e-9);
        assert!(cosine_similarity(&a, &c).unwrap().abs() < 1e-9);
        assert!(
            cosine_similarity(&a, &[1.0]).is_none(),
            "dim mismatch → None"
        );
        let sim = max_embedding_similarity(&a, &[c.clone(), b.clone()]);
        assert!((sim - 1.0).abs() < 1e-9, "picks the closest case");
    }

    #[test]
    fn scan_flags_contaminated_candidate_and_passes_clean() {
        let eval = vec![EvalCaseContent {
            id: "c1".into(),
            text: "the settlement runs on a t plus one net settlement cycle for member banks daily"
                .into(),
            embedding: Some(vec![1.0, 0.0, 0.0]),
        }];
        // Candidate prompt that lifted the eval case verbatim + a near-duplicate embedding.
        let dirty = vec![
            "system: the settlement runs on a t plus one net settlement cycle for member banks daily"
                .to_string(),
        ];
        let v = scan_contamination(
            &dirty,
            &[vec![1.0, 0.0, 0.0]],
            &eval,
            &ContaminationPolicy::default(),
        );
        assert!(
            !v.is_clean(),
            "verbatim + near-dup embedding is contamination: {v:?}"
        );

        // A clean candidate.
        let clean = vec!["you are a helpful payments assistant; be concise".to_string()];
        let v2 = scan_contamination(
            &clean,
            &[vec![0.0, 1.0, 0.0]],
            &eval,
            &ContaminationPolicy::default(),
        );
        assert!(v2.is_clean(), "an unrelated prompt is clean: {v2:?}");
    }

    #[test]
    fn rotation_retires_aged_and_overused_but_keeps_fresh_tripwires() {
        let cases = vec![
            HoldoutCase {
                id: "old".into(),
                minted_epoch: 0,
                use_count: 1,
                tripwire: false,
            },
            HoldoutCase {
                id: "fresh".into(),
                minted_epoch: 9,
                use_count: 1,
                tripwire: false,
            },
            HoldoutCase {
                id: "overused".into(),
                minted_epoch: 9,
                use_count: 100,
                tripwire: false,
            },
            HoldoutCase {
                id: "tripwire_old".into(),
                minted_epoch: 0,
                use_count: 1,
                tripwire: true,
            },
            HoldoutCase {
                id: "tripwire_overused".into(),
                minted_epoch: 9,
                use_count: 100,
                tripwire: true,
            },
        ];
        let retire = plan_rotation(&cases, 10, 5, 10);
        assert!(retire.contains(&"old".to_string()), "aged case rotates out");
        assert!(
            retire.contains(&"overused".to_string()),
            "overused case rotates out"
        );
        assert!(!retire.contains(&"fresh".to_string()), "fresh case stays");
        assert!(
            !retire.contains(&"tripwire_old".to_string()),
            "a merely-aged tripwire must persist to keep detecting overfit"
        );
        assert!(
            retire.contains(&"tripwire_overused".to_string()),
            "an OVERUSED tripwire is compromised and rotates"
        );
    }

    #[test]
    fn gap_ainxt_eval_06_flywheel_case_never_auto_promotes() {
        let mut staging = StagingSet::with_live_ids(vec!["LIVE-1".to_string()]);
        // A flywheel candidate with NO human approval must not promote.
        staging.stage(StagedCase {
            id: "FLY-1".into(),
            input: "a traffic-derived question".into(),
            gold: "expected answer".into(),
            provenance: CaseProvenance::Flywheel,
            human_approved: false,
            contamination_clean: true,
        });
        assert!(
            matches!(
                staging.promote("FLY-1"),
                Err(PromotionError::NeedsHumanApproval { .. })
            ),
            "the flywheel can never legislate a case into the gate"
        );
        assert!(!staging.is_live("FLY-1"));

        // After a human approves it, it promotes — and only once (idempotent).
        staging.staged.iter_mut().for_each(|c| {
            if c.id == "FLY-1" {
                c.human_approved = true;
            }
        });
        let promoted = staging
            .promote("FLY-1")
            .expect("human-approved, clean → promotes");
        assert_eq!(promoted.id, "FLY-1");
        assert!(staging.is_live("FLY-1"));

        // A contaminated candidate is refused even with human approval.
        staging.stage(StagedCase {
            id: "FLY-2".into(),
            input: "overlaps an existing eval case".into(),
            gold: "leaked gold".into(),
            provenance: CaseProvenance::Flywheel,
            human_approved: true,
            contamination_clean: false,
        });
        assert!(matches!(
            staging.promote("FLY-2"),
            Err(PromotionError::Contaminated { .. })
        ));

        // An already-live id is rejected (no silent overwrite of the gate's ruler).
        staging.stage(StagedCase {
            id: "LIVE-1".into(),
            input: "dupe".into(),
            gold: "x".into(),
            provenance: CaseProvenance::Seed,
            human_approved: true,
            contamination_clean: true,
        });
        assert!(matches!(
            staging.promote("LIVE-1"),
            Err(PromotionError::AlreadyLive { .. })
        ));
    }

    #[test]
    fn tripwire_catches_overfitting() {
        let t = Tripwire::default();
        // Aced visible (95), collapsed on sealed tripwire (70) → overfit.
        assert!(t.evaluate(95.0, 70.0).is_overfit());
        // Consistent across both → ok.
        assert!(!t.evaluate(92.0, 90.0).is_overfit());
    }
}
