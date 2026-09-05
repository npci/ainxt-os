// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-12 all-severities gap closure for the Enterprise Memory & Continuous-Learning core
//! (design: `docs/architecture/ENTERPRISE_MEMORY_LEARNING.md`). Each test drives the REAL objects
//! (the concrete store / flywheel / promotion pipeline — no mocks of them) end-to-end at the crate's
//! public API and asserts a design invariant:
//!
//! - `r12_episodic_to_semantic_promotion_pipeline` — §3 "Promotion, not duplication" / §6
//!   durability heuristic (the medium gap: episodic → semantic promotion did not exist).
//! - `r12_flywheel_four_separately_gated_destinations` — §4 four destinations, each independently
//!   gated (the per-destination router did not exist).
//! - `r12_versioned_per_type_schema_registry_enforced_on_write` — §2 `type_payload`.
//! - `r12_confidence_decay_eventually_expires_unused_fact` — §6 "eventually expires".
//! - `r12_own_pii_personal_fact_visible_to_self` — §5 own PII visible to self.

use ainxt_memory::flywheel::{
    Candidate, CandidateDest, CandidateSink, DestinationGates, ImprovementEngine,
};
use ainxt_memory::{
    AccessScope, DataClass, DurabilityHeuristic, Enforcement, GovernanceState, InMemoryStore,
    MemoryItem, MemoryKind, MemoryQuery, MemoryStore, NonDurable, OrgKnowledgeType, OrgPayload,
    Principal, PromotionPipeline, Provenance, SchemaRegistry, Scope, Severity, CAP_APPROVE,
};

fn approver() -> Principal {
    Principal::user("owner", &[CAP_APPROVE])
}

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

// ============================================================================================
// GAP 1 (medium): Episodic → semantic promotion pipeline + durability heuristic (§3 / §6).
// ============================================================================================
#[test]
fn r12_episodic_to_semantic_promotion_pipeline() {
    let pipe = PromotionPipeline::new(DurabilityHeuristic::new(0.6), "prom");

    // A session's worth of raw episodic records — a mix of durable, transient, weak, and
    // shared-scope material, plus one that duplicates an existing durable fact.
    let existing = {
        let mut it = MemoryItem::new(
            "sem-existing",
            MemoryKind::Semantic,
            Scope::User("alice".into()),
            "known role",
            "alice is a settlement engineer",
            Provenance::ingest(0.9),
        );
        it.governance = GovernanceState::Approved;
        it
    };
    let eps = vec![
        // durable, high-confidence, personal → promotes (Semantic)
        episodic(
            "e1",
            Scope::User("alice".into()),
            "primary repo",
            "alice primarily works in payments-core; run: r-9",
            0.95,
        ),
        // transient (a clock time) → rejected, stays episodic
        episodic(
            "e2",
            Scope::User("alice".into()),
            "standup",
            "standup happens at 09:30 today",
            1.0,
        ),
        // below the confidence floor → rejected
        episodic(
            "e3",
            Scope::User("alice".into()),
            "guess",
            "alice maybe likes graphql",
            0.3,
        ),
        // duplicate of an existing durable fact → not re-promoted
        episodic(
            "e4",
            Scope::User("alice".into()),
            "known role",
            "alice is a settlement engineer",
            0.99,
        ),
        // shared (team) scope, durable → promotes but must land in the governance queue
        episodic(
            "e5",
            Scope::Team("payments".into()),
            "deploy cadence",
            "team ships on tuesdays",
            0.9,
        ),
    ];

    let out = pipe.condense(&eps, std::slice::from_ref(&existing), 500);

    // Exactly the two durable ones become candidates; the other three are explained rejections.
    let sources: Vec<&str> = out
        .candidates
        .iter()
        .map(|c| c.source_episodic_id.as_str())
        .collect();
    assert!(
        sources.contains(&"e1"),
        "durable personal fact must promote"
    );
    assert!(
        sources.contains(&"e5"),
        "durable team fact must promote (into governance queue)"
    );
    assert_eq!(
        out.candidates.len(),
        2,
        "only durable, non-dup, confident facts promote"
    );

    assert!(out
        .rejected
        .iter()
        .any(|(id, r)| id == "e2" && matches!(r, NonDurable::Transient(_))));
    assert!(out
        .rejected
        .iter()
        .any(|(id, r)| id == "e3" && *r == NonDurable::LowConfidence));
    assert!(out
        .rejected
        .iter()
        .any(|(id, r)| id == "e4" && matches!(r, NonDurable::Duplicate(_))));

    // Promotion, not duplication: the candidate is a NEW distilled fact, run-local tail stripped.
    let e1_cand = out
        .candidates
        .iter()
        .find(|c| c.source_episodic_id == "e1")
        .unwrap();
    assert_eq!(e1_cand.proposed.kind, MemoryKind::Semantic);
    assert!(!e1_cand.proposed.body.to_lowercase().contains("run: r-9"));

    // Persist through the ordinary store write path and prove the governance split:
    let mut store = InMemoryStore::new();
    // (the raw episodics also live in the store until they age out)
    for ep in &eps {
        let _ = store.write(ep.clone());
    }
    let written = pipe.write_candidates(&mut store, &out).unwrap();
    assert_eq!(written, 2);

    // Personal fact is immediately usable/authoritative; the team fact is queued Draft (governance).
    assert!(
        store.get_unchecked("prom-0").unwrap().is_authoritative(),
        "personal promotion usable at once"
    );
    assert_eq!(
        store.get_unchecked("prom-4").unwrap().governance,
        GovernanceState::Draft,
        "above-user-scope promotion must pass through governance"
    );

    // The source episodics are NOT mutated into semantic memory (promotion, not duplication).
    assert_eq!(store.get_unchecked("e1").unwrap().kind, MemoryKind::Episodic);

    // The distilled personal fact is retrievable by its owner.
    let alice = AccessScope::from_principal(Principal::user("alice", &[]));
    let hits = store.query(
        &MemoryQuery::keywords(&["payments-core"]).with_kind(MemoryKind::Semantic),
        &alice,
    );
    assert!(hits.iter().any(|h| h.item.id == "prom-0"));
}

// ============================================================================================
// GAP 2 (low): Flywheel — four separately-gated destinations, each with its own gate (§4).
// ============================================================================================
#[test]
fn r12_flywheel_four_separately_gated_destinations() {
    // A distinct gate per destination. Each records what it saw and applies its OWN accept/reject
    // criterion — proving destinations are gated independently, not through one funnel.
    #[derive(Default)]
    struct RecordingGate {
        seen: Vec<CandidateDest>,
        reject_all: bool,
    }
    impl CandidateSink for RecordingGate {
        fn accept(&mut self, c: &Candidate) -> Result<(), String> {
            self.seen.push(c.dest);
            if self.reject_all {
                Err("gate rejected".into())
            } else {
                Ok(())
            }
        }
    }

    // Build candidates across every destination via the real engine.
    let mut eng = ImprovementEngine::new();
    for t in ["t1", "t2", "t3"] {
        eng.capture(
            &ainxt_memory::flywheel::FeedbackEvent::correction(t, "npe", "x", "guard null"),
            0.9,
            None,
        );
    }
    for i in 0..3 {
        eng.capture(
            &ainxt_memory::flywheel::FeedbackEvent::thumbs(&format!("d{i}"), false),
            1.0,
            None,
        );
    }
    for i in 0..3 {
        eng.capture(
            &ainxt_memory::flywheel::FeedbackEvent {
                turn_id: format!("edit{i}"),
                signal: ainxt_memory::flywheel::FeedbackSignal::EditBeforeSend {
                    draft: "a".into(),
                    final_text: "b".into(),
                },
                origin: ainxt_memory::flywheel::FeedbackOrigin::UserExplicit,
                error_signature: None,
            },
            1.0,
            None,
        );
    }
    let cands = eng.propose(3, 0.5, &Scope::Org, "c", 1);
    assert!(cands.iter().any(|c| c.dest == CandidateDest::OrgKnowledge));
    assert!(cands.iter().any(|c| c.dest == CandidateDest::Prompt));
    assert!(cands.iter().any(|c| c.dest == CandidateDest::Retrieval));

    let mut prompt_gate = RecordingGate::default();
    let mut retrieval_gate = RecordingGate {
        reject_all: true,
        ..Default::default()
    }; // its own gate says no
    let mut oki_gate = RecordingGate::default();
    // EvalCase gate deliberately NOT wired → those candidates are unrouted (never silently admitted).

    let report = {
        let mut gates = DestinationGates::new()
            .with_prompt(&mut prompt_gate)
            .with_retrieval(&mut retrieval_gate)
            .with_org_knowledge(&mut oki_gate);
        eng.dispatch_gated(&cands, &mut gates)
    };

    // Each gate only ever saw candidates for its OWN destination (independent routing).
    assert!(prompt_gate.seen.iter().all(|d| *d == CandidateDest::Prompt));
    assert!(retrieval_gate
        .seen
        .iter()
        .all(|d| *d == CandidateDest::Retrieval));
    assert!(oki_gate
        .seen
        .iter()
        .all(|d| *d == CandidateDest::OrgKnowledge));

    // The retrieval gate rejected on its own criterion; the others accepted — independent gating.
    assert_eq!(
        report
            .per_dest
            .get(&CandidateDest::Retrieval)
            .map(|(_, r)| *r > 0),
        Some(true)
    );
    assert_eq!(
        report
            .per_dest
            .get(&CandidateDest::Prompt)
            .map(|(a, _)| *a > 0),
        Some(true)
    );
    assert_eq!(
        report
            .per_dest
            .get(&CandidateDest::OrgKnowledge)
            .map(|(a, _)| *a > 0),
        Some(true)
    );

    // Eval-case candidates had no gate wired → unrouted, never silently accepted (fail-safe).
    if cands.iter().any(|c| c.dest == CandidateDest::EvalCase) {
        assert!(report.unrouted.contains(&CandidateDest::EvalCase));
    }
    assert_eq!(
        report.accepted,
        prompt_gate.seen.len() + oki_gate.seen.len()
    );
}

// ============================================================================================
// GAP 3 (low): Versioned per-type JSON-schema registry ENFORCED ON WRITE (§2 type_payload).
// ============================================================================================
#[test]
fn r12_versioned_per_type_schema_registry_enforced_on_write() {
    // Govern a schema bump: SecurityRule → v3, ApprovedLibrary stays v1.
    let mut reg = SchemaRegistry::new();
    reg.bump(
        OrgKnowledgeType::SecurityRule,
        2,
        &approver(),
        "add exception_ref",
    )
    .unwrap();
    reg.bump(
        OrgKnowledgeType::SecurityRule,
        3,
        &approver(),
        "tighten action",
    )
    .unwrap();

    let mut store = InMemoryStore::new().with_schema_registry(reg);

    // A valid SecurityRule write is validated THROUGH the registry and stamped with the in-force
    // version (3) on the persisted item.
    let sec = MemoryItem::org(
        "sec-1",
        Scope::Org,
        "no plaintext PAN",
        OrgPayload::SecurityRule {
            rule: "never log a PAN".into(),
            applicable_action: "log".into(),
            applicable_data_class: DataClass::RegulatedPayment,
            severity: Severity::Critical,
            enforcement: Enforcement::Blocking,
            exception_process: None,
        },
        Provenance::ingest(1.0),
    );
    store.write(sec).unwrap();
    assert_eq!(
        store.get_unchecked("sec-1").unwrap().schema_version,
        3,
        "in-force SecurityRule version stamped"
    );

    // A different type retains its own independent version (1).
    let lib = MemoryItem::org(
        "lib-1",
        Scope::Org,
        "approved http client",
        OrgPayload::ApprovedLibrary {
            name: "reqwest".into(),
            version_range: ">=0.12".into(),
            language: "rust".into(),
            reason: "audited".into(),
            disallowed_alternatives: vec![],
            security_review_ref: None,
        },
        Provenance::ingest(1.0),
    );
    store.write(lib).unwrap();
    assert_eq!(
        store.get_unchecked("lib-1").unwrap().schema_version,
        1,
        "per-type version independence"
    );

    // An invalid payload is REJECTED through the registry on write — never persisted "as text".
    let bad = MemoryItem::org(
        "sec-bad",
        Scope::Org,
        "blank rule",
        OrgPayload::SecurityRule {
            rule: "   ".into(),           // required, blank
            applicable_action: "".into(), // required, blank
            applicable_data_class: DataClass::Confidential,
            severity: Severity::Low,
            enforcement: Enforcement::Advisory,
            exception_process: None,
        },
        Provenance::ingest(1.0),
    );
    let err = store.write(bad).unwrap_err();
    assert!(matches!(err, ainxt_memory::MemoryError::SchemaViolation(_)));
    assert!(
        store.get_unchecked("sec-bad").is_none(),
        "invalid OKI never persisted"
    );
}

// ============================================================================================
// GAP 4 (low): Confidence decay "eventually expires" a long-unused fact (§6).
// ============================================================================================
#[test]
fn r12_confidence_decay_eventually_expires_unused_fact() {
    let mut store = InMemoryStore::new();

    // Two durable personal facts + one governed OKI.
    for id in ["f-stale", "f-fresh"] {
        store
            .write(MemoryItem::new(
                id,
                MemoryKind::Semantic,
                Scope::User("u".into()),
                id,
                "durable fact body",
                Provenance::ingest(0.9),
            ))
            .unwrap();
    }
    store
        .write(MemoryItem::org(
            "oki-1",
            Scope::Org,
            "convention",
            OrgPayload::CodingConvention {
                rule: "use Result".into(),
                language: "rust".into(),
                example_do: "Ok(x)".into(),
                example_dont: "panic!()".into(),
                enforcement: Enforcement::Advisory,
            },
            Provenance::ingest(1.0),
        ))
        .unwrap();
    store.promote("oki-1", &approver()).unwrap();

    // f-fresh is USED recently → its decay clock resets and it must survive the sweep.
    assert!(store.touch("f-fresh", 1000));

    // Sweep at a far-future tick: long-unused facts below the decay floor "eventually expire"
    // (→ Deprecated, retained for audit — NOT a silent delete).
    let expired = store.expire_decayed(1000, 1, 0.5);
    assert_eq!(expired, 1, "only the long-unused fact expires");

    assert_eq!(
        store.get_unchecked("f-stale").unwrap().governance,
        GovernanceState::Deprecated
    );
    assert!(
        !store.get_unchecked("f-stale").unwrap().is_authoritative(),
        "expired fact excluded from authority"
    );
    assert!(
        store.get_unchecked("f-stale").is_some(),
        "expiry is not a hard delete — retained for audit"
    );

    assert!(
        store.get_unchecked("f-fresh").unwrap().is_authoritative(),
        "freshly-used fact is not expired"
    );
    // OKI is exempt from timer-based decay (§5: governance-only lifecycle).
    assert!(
        store.get_unchecked("oki-1").unwrap().is_authoritative(),
        "OKI never decay-expires on a timer"
    );

    // The expired fact drops out of authoritative retrieval.
    let access = AccessScope::from_principal(Principal::user("u", &[]));
    let hits = store.query(&MemoryQuery::keywords(&["durable"]), &access);
    assert!(hits.iter().all(|h| h.item.id != "f-stale"));
    assert!(hits.iter().any(|h| h.item.id == "f-fresh"));
}

// ============================================================================================
// GAP 5 (low): A user's own PII-classed personal fact is visible to themselves (§5).
// ============================================================================================
#[test]
fn r12_own_pii_personal_fact_visible_to_self() {
    let mut store = InMemoryStore::new();

    // Alice records a PII-classed fact ABOUT HERSELF (low blast radius, personal scope).
    store
        .write(
            MemoryItem::new(
                "alice-pii",
                MemoryKind::Semantic,
                Scope::User("alice".into()),
                "home city",
                "alice lives in Mumbai",
                Provenance::human("alice", 1.0),
            )
            .with_data_class(DataClass::Pii),
        )
        .unwrap();

    // An org-wide PII OKI (authoritative) — used to prove the clearance ceiling still bites for
    // facts that are NOT the caller's own personal facts.
    store
        .write(
            MemoryItem::org(
                "org-pii",
                Scope::Org,
                "pii handling",
                OrgPayload::SecurityRule {
                    rule: "mask customer PII in logs".into(),
                    applicable_action: "log".into(),
                    applicable_data_class: DataClass::Pii,
                    severity: Severity::High,
                    enforcement: Enforcement::Blocking,
                    exception_process: None,
                },
                Provenance::ingest(1.0),
            )
            .with_data_class(DataClass::Pii),
        )
        .unwrap();
    store.promote("org-pii", &approver()).unwrap();

    // Alice with only INTERNAL clearance (below PII) still sees her OWN PII fact...
    let alice = AccessScope::from_principal(
        Principal::user("alice", &[]).with_clearance(DataClass::Internal),
    );
    let own = store.query(&MemoryQuery::keywords(&["mumbai"]), &alice);
    assert!(
        own.iter().any(|h| h.item.id == "alice-pii"),
        "own PII visible to self despite low clearance"
    );

    // ...but the same low clearance does NOT let her read a NON-own PII org fact (ceiling intact).
    let org_hits = store.query(&MemoryQuery::keywords(&["mask"]), &alice);
    assert!(
        org_hits.iter().all(|h| h.item.id != "org-pii"),
        "clearance ceiling still applies to non-own PII"
    );

    // Another plain user cannot see Alice's personal PII at all (scope isolation, existence hidden).
    let bob =
        AccessScope::from_principal(Principal::user("bob", &[]).with_clearance(DataClass::Pii));
    let bob_hits = store.query(&MemoryQuery::keywords(&["mumbai"]), &bob);
    assert!(
        bob_hits.is_empty(),
        "another user cannot see alice's personal PII"
    );
}
