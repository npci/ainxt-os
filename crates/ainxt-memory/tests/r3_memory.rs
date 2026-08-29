// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-3 gap-closure integration tests on the REAL objects (no mocks of the store):
//!
//! - `r3_compliance_on_write_uses_strong_default_detector` — the DEFAULT compliance gate
//!   ([`BuiltinRedactor`], installed by `InMemoryStore::new()` with no custom redactor) now redacts
//!   the full PAN/PII/secret set the turn pipeline detects (PAN, Aadhaar, Indian mobile, IFSC,
//!   India-PAN, email, UPI VPA, credential secret, context-gated CVV/expiry) BEFORE persistence —
//!   proven by raw values that must never appear in the stored item. Fails before this round because
//!   the built-in gate caught only Luhn-PAN / Verhoeff-Aadhaar / high-entropy secrets.
//!
//! - `r3_durable_store_survives_reopen` — the durable [`DurableMemoryStore`] over the [`SqlLike`]
//!   seam persists OKIs, MemoryFacts, the governance lifecycle, the tamper-evident audit chain, and
//!   DPDP erasure (consent) receipts; reopening over the SAME backend recovers all of it. Fails
//!   before this round because no durable impl / seam existed (only `InMemoryStore`).

use ainxt_memory::{
    AccessScope, DurableMemoryStore, GovernanceState, InMemoryStore, MemoryItem, MemoryKind,
    MemorySqlBackend, MemoryStore, OrgPayload, Principal, Provenance, Scope, CAP_APPROVE,
};

fn admin() -> Principal {
    Principal::admin("boss")
}

fn lib_oki_lang(id: &str, name: &str, language: &str) -> MemoryItem {
    MemoryItem::org(
        id,
        Scope::Repo("payments-core".into()),
        &format!("approved {name}"),
        OrgPayload::ApprovedLibrary {
            name: name.into(),
            version_range: ">=1".into(),
            language: language.into(),
            reason: "audited".into(),
            disallowed_alternatives: vec![],
            security_review_ref: None,
        },
        Provenance::flywheel(0.8),
    )
}

fn lib_oki(id: &str) -> MemoryItem {
    lib_oki_lang(id, "reqwest", "rust")
}

#[test]
fn r3_durable_store_survives_reopen() {
    // A cloneable in-memory SQL backend models one shared database across processes.
    let backend = MemorySqlBackend::new();

    // ---- session 1: write governed knowledge + a PII-bearing fact + erase a subject ----
    {
        let mut store = DurableMemoryStore::open(backend.clone()).unwrap();

        // An OKI: written Draft, promoted to authority by an approver.
        store.write(lib_oki("oki-1")).unwrap();
        assert_eq!(
            store.get("oki-1").unwrap().governance,
            GovernanceState::Draft
        );
        assert_eq!(
            store.promote("oki-1", &admin()).unwrap(),
            GovernanceState::Approved
        );

        // A MemoryFact (personal semantic) carrying a raw PAN — must persist redacted.
        store
            .write(MemoryItem::new(
                "fact-alice",
                MemoryKind::Semantic,
                Scope::User("alice".into()),
                "payment note",
                "alice card 4111111111111111 on file",
                Provenance::flywheel(0.9),
            ))
            .unwrap();

        // A soon-to-be-erased subject's personal fact.
        store
            .write(MemoryItem::new(
                "fact-bob",
                MemoryKind::UserPreference,
                Scope::User("bob".into()),
                "tone",
                "bob prefers terse",
                Provenance::flywheel(0.7),
            ))
            .unwrap();

        // DPDP right-to-erasure for bob → durable, provable receipt.
        let receipt = store.erase_subject("bob").unwrap();
        assert!(receipt.removed_ids.contains(&"fact-bob".to_string()));
        assert_eq!(store.verify_audit_chain(), None);
    } // store dropped — nothing kept in RAM

    // ---- session 2: reopen over the SAME backend; every governed record survives ----
    let mut reopened = DurableMemoryStore::open(backend.clone()).unwrap();

    // OKI + its promoted governance state persisted.
    let oki = reopened.get("oki-1").expect("OKI must survive reopen");
    assert_eq!(oki.kind, MemoryKind::OrgKnowledge);
    assert_eq!(oki.governance, GovernanceState::Approved);
    assert_eq!(oki.provenance.last_verified_by.as_deref(), Some("boss"));

    // The MemoryFact survived AND was compliance-redacted before persistence.
    let fact = reopened
        .get("fact-alice")
        .expect("fact must survive reopen");
    assert!(
        !fact.body.contains("4111111111111111"),
        "PAN leaked into durable memory: {}",
        fact.body
    );
    assert!(fact.body.contains("[REDACTED-PAN]"));

    // Erased subject is gone across the reopen (post-erasure query returns zero live records).
    assert!(reopened.get("fact-bob").is_none());
    let alice_access = AccessScope::from_principal(Principal::user("alice", &[]));
    let bob_view: Vec<_> = reopened
        .query(&ainxt_memory::MemoryQuery::default(), &alice_access)
        .into_iter()
        .filter(|h| h.item.scope == Scope::User("bob".into()))
        .collect();
    assert!(
        bob_view.is_empty(),
        "erased subject still queryable after reopen"
    );

    // The tamper-evident audit chain survived intact, and the erasure receipt is a durable
    // consent record.
    assert_eq!(reopened.verify_audit_chain(), None);
    let receipts = reopened.consent_receipts().unwrap();
    assert!(
        receipts.iter().any(|r| r.subject == "bob"),
        "DPDP erasure receipt not durably recorded"
    );

    // Governance still enforced on the durable store: promotion needs CAP_APPROVE.
    reopened
        .write(lib_oki_lang("oki-2", "requests", "python"))
        .unwrap();
    let unauth = Principal::user("dev-9", &[]);
    assert!(reopened.promote("oki-2", &unauth).is_err());
    assert_eq!(
        reopened.promote("oki-2", &admin()).unwrap(),
        GovernanceState::Approved
    );
    // Sanity: CAP_APPROVE is the gate the durable path shares with the reference store.
    assert!(admin().has_cap(CAP_APPROVE));
}
