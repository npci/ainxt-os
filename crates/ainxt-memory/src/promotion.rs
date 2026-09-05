// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Episodic → semantic **promotion pipeline** + **durability heuristic** (design §3 "Promotion, not
//! duplication" and §6 "what qualifies to be remembered").
//!
//! Semantic memory is not an ever-growing transcript archive. Raw [`Episodic`](crate::MemoryKind::Episodic)
//! records (one structured row per run) are the flywheel's raw material and age out on a TTL (§5).
//! A session-end / condensation checkpoint runs this pipeline to **propose** distilled, typed
//! durable [`MemoryFact`](crate::MemoryKind::Semantic)/[`UserPreference`](crate::MemoryKind::UserPreference)
//! candidates from that episodic material — it never *copies* an episodic row verbatim into semantic
//! memory. Every candidate must clear the **durability heuristic** (design §6) before it is even
//! proposed:
//!
//! 1. **Durable, not transient** — a value that is "today's date" / "right now" / a session-local
//!    token is disqualified (ties gap `AU`: never remember transient state as if it were a stable
//!    fact).
//! 2. **Confident enough to be worth remembering** — below a configurable confidence floor, the
//!    record stays in episodic and ages out.
//! 3. **Not already contradicted by a more-authoritative / higher-confidence existing record** —
//!    the pipeline never proposes a fact that would fight an authoritative OKI or a higher-confidence
//!    existing personal fact on the same subject.
//! 4. **Not a duplicate** — promotion, not duplication (§3): if an equal durable record already
//!    exists, nothing new is proposed.
//!
//! A record that fails the heuristic is **never force-promoted** — it simply stays in episodic/
//! session and ages out naturally, and the pipeline returns an explained rejection (honest, not
//! silent). What the pipeline *proposes* is written through the ordinary [`MemoryStore`] write path,
//! so the store's invariants still apply: a personal (`user:{id}`) fact is low-blast-radius and
//! immediately usable, while **anything above user-personal scope lands in the governance queue as
//! `Draft`** (the store forces it — §6: "for anything above user-personal scope → passes through
//! governance"). The flywheel proposes; a human legislates.
//!
//! Deterministic: no clock / rng. The logical `now` and candidate-id generation are caller-supplied.

use crate::{Author, MemoryError, MemoryItem, MemoryKind, MemoryStore, Provenance, Scope};

/// Why an episodic record failed the durability heuristic. A rejection is always explained: the
/// source stays in episodic/session and ages out naturally — it is never force-promoted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NonDurable {
    /// Carries transient state (a date/time/"today"/session-local value) — not durable across turns
    /// (design §6 / gap `AU`). Holds the offending marker.
    Transient(String),
    /// Below the confidence floor to be worth promoting.
    LowConfidence,
    /// A more-authoritative or higher-confidence existing record already covers this subject with a
    /// different value — promoting would create a conflict. Holds the winning record's id.
    ContradictedByAuthority(String),
    /// An equal durable record already exists — promotion, not duplication (§3). Holds its id.
    Duplicate(String),
    /// Not a promotable input (not an `Episodic` record, or empty substance).
    NotPromotable,
}

impl std::fmt::Display for NonDurable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NonDurable::Transient(m) => write!(f, "transient (marker '{m}')"),
            NonDurable::LowConfidence => write!(f, "below confidence floor"),
            NonDurable::ContradictedByAuthority(id) => {
                write!(f, "contradicted by more-authoritative record '{id}'")
            }
            NonDurable::Duplicate(id) => write!(f, "duplicate of existing record '{id}'"),
            NonDurable::NotPromotable => write!(f, "not a promotable episodic record"),
        }
    }
}

/// The tunable durability heuristic (design §6). Deterministic — no clock/rng, no external deps.
#[derive(Debug, Clone)]
pub struct DurabilityHeuristic {
    /// Minimum authoring confidence for an episodic fact to be worth promoting.
    pub min_confidence: f32,
    /// Lowercased substrings that mark a value as transient (a "today"/"right now"/session-local
    /// token). Their presence disqualifies promotion. A bare ISO date (`YYYY-MM-DD`) or clock time
    /// (`HH:MM`) token is *also* detected structurally, so callers need not enumerate every date.
    pub transient_markers: Vec<String>,
}

impl Default for DurabilityHeuristic {
    fn default() -> Self {
        DurabilityHeuristic {
            min_confidence: 0.6,
            transient_markers: [
                "today",
                "tomorrow",
                "yesterday",
                "right now",
                "current time",
                "current date",
                "as of now",
                "this session",
                "o'clock",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        }
    }
}

impl DurabilityHeuristic {
    /// A heuristic with the given confidence floor and the default transient-marker set.
    pub fn new(min_confidence: f32) -> Self {
        DurabilityHeuristic {
            min_confidence,
            ..Default::default()
        }
    }

    /// Add a transient marker (lowercased) that disqualifies promotion.
    pub fn with_transient_marker(mut self, marker: &str) -> Self {
        self.transient_markers.push(marker.to_lowercase());
        self
    }

    /// The transient marker present in `text`, if any (a configured marker, or a structural
    /// date/clock token). `None` = no transient signal detected.
    pub fn transient_marker(&self, text: &str) -> Option<String> {
        let lower = text.to_lowercase();
        for m in &self.transient_markers {
            if !m.is_empty() && lower.contains(m.as_str()) {
                return Some(m.clone());
            }
        }
        if let Some(tok) = detect_date_or_clock(&lower) {
            return Some(tok);
        }
        None
    }

    /// Judge a single episodic item against the heuristic given the current durable records that
    /// share its subject (same scope + normalized title). `Ok(())` = qualifies to be promoted.
    pub fn judge(
        &self,
        episodic: &MemoryItem,
        existing_same_subject: &[&MemoryItem],
    ) -> Result<(), NonDurable> {
        if episodic.kind != MemoryKind::Episodic || episodic.title.trim().is_empty() {
            return Err(NonDurable::NotPromotable);
        }
        // 1. Durable, not transient (§6 / AU).
        let combined = format!("{} {}", episodic.title, episodic.body);
        if let Some(marker) = self.transient_marker(&combined) {
            return Err(NonDurable::Transient(marker));
        }
        // 2. Confident enough.
        if episodic.provenance.confidence < self.min_confidence {
            return Err(NonDurable::LowConfidence);
        }
        // 3/4. Duplicate / contradicted-by-authority.
        let cand_body = norm(&distill_body(&episodic.body));
        for existing in existing_same_subject {
            if !existing.is_authoritative() {
                continue; // a retired/draft record neither blocks nor duplicates.
            }
            let ex_body = norm(&existing.body);
            if ex_body == cand_body {
                return Err(NonDurable::Duplicate(existing.id.clone()));
            }
            // Different value on the same subject → only a *more-authoritative* or *at-least-as-
            // confident* existing record blocks it. A lower-confidence personal record does not
            // (recency/higher-confidence wins; the store auto-supersedes it on write).
            let more_authoritative = existing.kind == MemoryKind::OrgKnowledge
                || existing.provenance.confidence >= episodic.provenance.confidence;
            if more_authoritative {
                return Err(NonDurable::ContradictedByAuthority(existing.id.clone()));
            }
        }
        Ok(())
    }
}

/// A distilled durable candidate proposed from one episodic record. `proposed` is a **new** typed
/// [`MemoryFact`](crate::MemoryKind::Semantic) (never a verbatim copy of the episodic row); writing
/// it through a store applies the usual governance (personal = usable, shared = `Draft`).
#[derive(Debug, Clone, PartialEq)]
pub struct PromotionCandidate {
    /// The id of the episodic record this was distilled from (lineage / provenance).
    pub source_episodic_id: String,
    /// The ready-to-write durable MemoryFact.
    pub proposed: MemoryItem,
    /// A short human rationale.
    pub rationale: String,
}

/// The outcome of one condensation checkpoint: qualified candidates + explained rejections.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PromotionOutcome {
    /// Candidates that cleared the durability heuristic (proposed, not yet written).
    pub candidates: Vec<PromotionCandidate>,
    /// Episodic records that failed the heuristic — `(episodic id, reason)`. They stay in episodic
    /// and age out; they are never force-promoted.
    pub rejected: Vec<(String, NonDurable)>,
}

/// The episodic → semantic promotion pipeline (design §3/§6). Runs at a session-end / condensation
/// checkpoint: distills qualifying episodic records into typed durable MemoryFact candidates.
#[derive(Debug, Clone)]
pub struct PromotionPipeline {
    /// The durability heuristic every candidate must clear.
    pub heuristic: DurabilityHeuristic,
    /// Deterministic id prefix for generated candidate ids (no rng).
    id_prefix: String,
}

impl PromotionPipeline {
    /// A pipeline with the given heuristic and candidate-id prefix.
    pub fn new(heuristic: DurabilityHeuristic, id_prefix: &str) -> Self {
        PromotionPipeline {
            heuristic,
            id_prefix: id_prefix.to_string(),
        }
    }

    /// Run the condensation checkpoint. `episodics` are the raw `Episodic` records from the just-
    /// ended session; `existing_durable` are the current durable records the promotion must neither
    /// duplicate nor contradict (the caller fetches them, already scope-filtered). `now` stamps
    /// provenance deterministically. Nothing is written here — promotion, not duplication: this
    /// *proposes*; [`write_candidates`](PromotionPipeline::write_candidates) persists.
    pub fn condense(
        &self,
        episodics: &[MemoryItem],
        existing_durable: &[MemoryItem],
        now: u64,
    ) -> PromotionOutcome {
        let mut out = PromotionOutcome::default();
        for (idx, ep) in episodics.iter().enumerate() {
            let subject = subject_key(&ep.scope, &ep.title);
            let same_subject: Vec<&MemoryItem> = existing_durable
                .iter()
                .filter(|e| subject_key(&e.scope, &e.title) == subject)
                .collect();
            match self.heuristic.judge(ep, &same_subject) {
                Ok(()) => {
                    out.candidates.push(self.build_candidate(ep, idx, now));
                }
                Err(reason) => out.rejected.push((ep.id.clone(), reason)),
            }
        }
        out
    }

    /// Build one distilled candidate MemoryFact from a qualifying episodic record. The candidate is a
    /// **new** typed item — its body is the *distilled* statement (run-local detail stripped), never
    /// the raw episodic transcript. An episodic record tagged `preference` becomes a
    /// [`UserPreference`](crate::MemoryKind::UserPreference); everything else a
    /// [`Semantic`](crate::MemoryKind::Semantic) fact. Data-class is carried over from the source so
    /// a regulated/PII episodic promotes to a regulated/PII durable fact (embedding-tier routing and
    /// clearance filtering then still apply).
    fn build_candidate(&self, ep: &MemoryItem, idx: usize, now: u64) -> PromotionCandidate {
        let kind = if ep.tags.iter().any(|t| t.eq_ignore_ascii_case("preference")) {
            MemoryKind::UserPreference
        } else {
            MemoryKind::Semantic
        };
        let body = distill_body(&ep.body);
        let mut prov = Provenance::ingest(ep.provenance.confidence);
        prov.author = Author::SystemIngest;
        // Lineage: point the durable fact back at the source turn / episodic row.
        prov.source_turn = ep
            .provenance
            .source_turn
            .clone()
            .or_else(|| Some(ep.id.clone()));
        let mut proposed = MemoryItem::new(
            &format!("{}-{}", self.id_prefix, idx),
            kind,
            ep.scope.clone(),
            ep.title.trim(),
            &body,
            prov,
        )
        .with_data_class(ep.data_class);
        proposed.effective_from = Some(now);
        PromotionCandidate {
            source_episodic_id: ep.id.clone(),
            proposed,
            rationale: format!(
                "distilled durable {} fact from episodic '{}' (confidence {:.2})",
                kind.as_str(),
                ep.id,
                ep.provenance.confidence
            ),
        }
    }

    /// Write every proposed candidate through `store`. Personal (`user:{id}`) facts are immediately
    /// usable; anything above user-personal scope lands `Draft` (the store forces it — §6). Returns
    /// the number written. A single write error aborts and is returned (fail-closed).
    pub fn write_candidates<S: MemoryStore>(
        &self,
        store: &mut S,
        outcome: &PromotionOutcome,
    ) -> Result<usize, MemoryError> {
        let mut n = 0;
        for c in &outcome.candidates {
            store.write(c.proposed.clone())?;
            n += 1;
        }
        Ok(n)
    }
}

/// Normalize a string for equality comparison: trimmed, lowercased, internal whitespace collapsed.
fn norm(s: &str) -> String {
    s.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

/// The subject axis a promotion is keyed on: scope + normalized title. Two records with the same
/// subject are "about the same thing" for duplicate/contradiction purposes.
fn subject_key(scope: &Scope, title: &str) -> String {
    format!("{}|{}", scope.key(), norm(title))
}

/// Distill an episodic body into a durable statement: drop run-local suffixes (anything after a
/// `; run:` / `; turn:` / `; session:` marker) and trim. Deliberately conservative — it removes the
/// most common run-scoped tails so the promoted fact is not a verbatim transcript, without inventing
/// content (no summarization model in this deterministic core).
fn distill_body(body: &str) -> String {
    let lower = body.to_lowercase();
    let mut cut = body.len();
    for marker in ["; run:", "; turn:", "; session:", " (run ", " (turn "] {
        if let Some(pos) = lower.find(marker) {
            cut = cut.min(pos);
        }
    }
    body[..cut].trim().to_string()
}

/// Detect a bare ISO date (`YYYY-MM-DD`) or 24h clock (`HH:MM`) token in `text` — a structural
/// transient signal the heuristic rejects even without a configured marker. Returns the token found.
fn detect_date_or_clock(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let is_d = |b: u8| b.is_ascii_digit();
    // YYYY-MM-DD
    for w in bytes.windows(10) {
        if is_d(w[0])
            && is_d(w[1])
            && is_d(w[2])
            && is_d(w[3])
            && w[4] == b'-'
            && is_d(w[5])
            && is_d(w[6])
            && w[7] == b'-'
            && is_d(w[8])
            && is_d(w[9])
        {
            return Some(String::from_utf8_lossy(w).to_string());
        }
    }
    // HH:MM  (digit digit colon digit digit, not part of a longer number run)
    for i in 0..bytes.len().saturating_sub(4) {
        let w = &bytes[i..i + 5];
        if is_d(w[0]) && is_d(w[1]) && w[2] == b':' && is_d(w[3]) && is_d(w[4]) {
            let prev_ok = i == 0 || !is_d(bytes[i - 1]);
            if prev_ok {
                return Some(String::from_utf8_lossy(w).to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::InMemoryStore;
    use crate::{DataClass, GovernanceState, MemoryQuery, Scope};

    fn episodic(id: &str, scope: Scope, title: &str, body: &str, conf: f32) -> MemoryItem {
        MemoryItem::new(
            id,
            MemoryKind::Episodic,
            scope,
            title,
            body,
            Provenance::ingest(conf),
        )
    }

    #[test]
    fn transient_episodic_is_not_promoted() {
        let pipe = PromotionPipeline::new(DurabilityHeuristic::new(0.5), "cand");
        let eps = vec![
            episodic(
                "e1",
                Scope::User("alice".into()),
                "meeting time",
                "the standup is today at 09:30",
                1.0,
            ),
            episodic(
                "e2",
                Scope::User("alice".into()),
                "as-of date",
                "balance as of 2026-07-24",
                1.0,
            ),
        ];
        let out = pipe.condense(&eps, &[], 100);
        assert!(
            out.candidates.is_empty(),
            "transient facts must never be promoted"
        );
        assert_eq!(out.rejected.len(), 2);
        assert!(out
            .rejected
            .iter()
            .all(|(_, r)| matches!(r, NonDurable::Transient(_))));
    }

    #[test]
    fn low_confidence_stays_in_episodic() {
        let pipe = PromotionPipeline::new(DurabilityHeuristic::new(0.7), "c");
        let eps = vec![episodic(
            "e1",
            Scope::User("bob".into()),
            "works in payments",
            "bob works in the payments-core team",
            0.4,
        )];
        let out = pipe.condense(&eps, &[], 10);
        assert!(out.candidates.is_empty());
        assert_eq!(out.rejected[0].1, NonDurable::LowConfidence);
    }

    #[test]
    fn qualifying_fact_promotes_to_usable_semantic() {
        let pipe = PromotionPipeline::new(DurabilityHeuristic::new(0.6), "c");
        let eps = vec![episodic(
            "e1",
            Scope::User("carol".into()),
            "primary repo",
            "carol primarily works in payments-core; run: r-42",
            0.95,
        )];
        let out = pipe.condense(&eps, &[], 5);
        assert_eq!(out.candidates.len(), 1);
        let cand = &out.candidates[0];
        assert_eq!(cand.proposed.kind, MemoryKind::Semantic);
        // Promotion, not duplication: the run-local tail is stripped, not copied verbatim.
        assert!(!cand.proposed.body.to_lowercase().contains("run: r-42"));
        assert_eq!(cand.source_episodic_id, "e1");
        // Written to a store, a personal fact is immediately authoritative/usable.
        let mut store = InMemoryStore::new();
        assert_eq!(pipe.write_candidates(&mut store, &out).unwrap(), 1);
        assert!(store.get_unchecked("c-0").unwrap().is_authoritative());
    }

    #[test]
    fn preference_tag_promotes_to_user_preference() {
        let pipe = PromotionPipeline::new(DurabilityHeuristic::new(0.5), "c");
        let mut ep = episodic(
            "e1",
            Scope::User("d".into()),
            "answer style",
            "prefers terse answers",
            0.9,
        );
        ep.tags = vec!["preference".into()];
        let out = pipe.condense(&[ep], &[], 1);
        assert_eq!(out.candidates[0].proposed.kind, MemoryKind::UserPreference);
    }

    #[test]
    fn duplicate_and_contradiction_are_not_promoted() {
        let pipe = PromotionPipeline::new(DurabilityHeuristic::new(0.5), "c");
        // Existing authoritative durable fact on the same subject.
        let mut existing = MemoryItem::new(
            "s1",
            MemoryKind::Semantic,
            Scope::User("e".into()),
            "primary repo",
            "works in payments-core",
            Provenance::ingest(0.9),
        );
        existing.governance = GovernanceState::Approved;
        // Duplicate (same body) → not promoted.
        let dup = episodic(
            "e-dup",
            Scope::User("e".into()),
            "primary repo",
            "works in payments-core",
            0.95,
        );
        // Contradiction against an equally/more-confident record → not promoted.
        let contra = episodic(
            "e-con",
            Scope::User("e".into()),
            "primary repo",
            "works in fraud-team",
            0.8,
        );
        let out = pipe.condense(&[dup, contra], std::slice::from_ref(&existing), 10);
        assert!(out.candidates.is_empty());
        assert!(out
            .rejected
            .iter()
            .any(|(id, r)| id == "e-dup" && matches!(r, NonDurable::Duplicate(_))));
        assert!(out
            .rejected
            .iter()
            .any(|(id, r)| id == "e-con" && matches!(r, NonDurable::ContradictedByAuthority(_))));
    }

    #[test]
    fn above_user_scope_lands_in_governance_queue() {
        // Design §6: anything above user-personal scope passes through governance — the store forces
        // a shared-scope non-OKI promotion to Draft (never instant org/team authority).
        let pipe = PromotionPipeline::new(DurabilityHeuristic::new(0.5), "c");
        let ep = episodic(
            "e1",
            Scope::Team("payments".into()),
            "deploy window",
            "team deploys on tuesdays",
            0.95,
        );
        let out = pipe.condense(&[ep], &[], 1);
        assert_eq!(out.candidates.len(), 1);
        let mut store = InMemoryStore::new();
        pipe.write_candidates(&mut store, &out).unwrap();
        assert_eq!(store.get_unchecked("c-0").unwrap().governance, GovernanceState::Draft);
        assert!(!store.get_unchecked("c-0").unwrap().is_authoritative());
    }

    #[test]
    fn regulated_data_class_is_carried_to_the_promoted_fact() {
        let pipe = PromotionPipeline::new(DurabilityHeuristic::new(0.5), "c");
        let ep = episodic(
            "e1",
            Scope::User("f".into()),
            "role",
            "senior settlement engineer",
            0.9,
        )
        .with_data_class(DataClass::Pii);
        let out = pipe.condense(&[ep], &[], 1);
        assert_eq!(out.candidates[0].proposed.data_class, DataClass::Pii);
    }

    #[test]
    fn non_episodic_input_is_rejected() {
        let pipe = PromotionPipeline::new(DurabilityHeuristic::default(), "c");
        let sem = MemoryItem::new(
            "s",
            MemoryKind::Semantic,
            Scope::User("g".into()),
            "x",
            "y",
            Provenance::ingest(1.0),
        );
        let out = pipe.condense(&[sem], &[], 1);
        assert_eq!(out.rejected[0].1, NonDurable::NotPromotable);
    }

    #[test]
    fn promoted_fact_is_queryable_and_source_episodic_is_untouched() {
        let pipe = PromotionPipeline::new(DurabilityHeuristic::new(0.6), "c");
        let ep = episodic(
            "e1",
            Scope::User("h".into()),
            "primary repo",
            "works in payments-core",
            0.9,
        );
        let mut store = InMemoryStore::new();
        // The raw episodic itself is written (it lives in episodic until it ages out).
        store.write(ep.clone()).unwrap();
        let out = pipe.condense(std::slice::from_ref(&ep), &[], 5);
        pipe.write_candidates(&mut store, &out).unwrap();
        // The source episodic is NOT mutated into semantic — it is still Episodic.
        assert_eq!(store.get_unchecked("e1").unwrap().kind, MemoryKind::Episodic);
        // The distilled semantic fact is retrievable.
        let access = crate::AccessScope::from_principal(crate::Principal::user("h", &[]));
        let hits = store.query(
            &MemoryQuery::keywords(&["payments-core"]).with_kind(MemoryKind::Semantic),
            &access,
        );
        assert!(hits.iter().any(|hit| hit.item.id == "c-0"));
    }
}
