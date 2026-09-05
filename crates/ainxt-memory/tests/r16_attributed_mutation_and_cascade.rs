// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-16 criticals for `ainxt-memory`:
//!
//! 1. **Unauthorized, unattributed hard-delete of governed items.** The store used to expose
//!    `delete(&mut self, id) -> bool`: no principal, no authorization, and an audit line that read
//!    literally `"hard-delete"`. Anything holding `&mut dyn MemoryStore` could erase an approved
//!    org-knowledge item — audit evidence in a payments platform — and the log could not say who.
//! 2. **Cross-user personal-memory poisoning via the unattributed write path.** `write()` carries no
//!    identity, so nothing stopped user B writing into `Scope::User("A")`.
//! 3. **Erasure cascade never reached the Session tier or captured feedback** — a DPDP ack that was
//!    only true of the item store.
//!
//! Each test below fails against that older behaviour: 1 and 2 do not compile against it (the
//! attributed methods did not exist), and the cascade test asserts per-tier proof that was absent.

use ainxt_memory::{
    cascade_erasure, AccessScope, AuditHasher, Enforcement, ErasureTier, Fnv1aAuditHasher,
    GovernanceState, HmacSha256AuditHasher, InMemorySessionSeam, InMemoryStore, MemoryItem,
    MemoryKind, MemoryStore, OrgPayload, Provenance, Scope, SessionErasureTier, SessionSeam,
    CAP_APPROVE,
};
use ainxt_types::Principal;

fn item(id: &str, scope: Scope, author: &str) -> MemoryItem {
    MemoryItem::new(
        id,
        MemoryKind::UserPreference,
        scope,
        "body",
        "summary",
        Provenance::human(author, 1.0),
    )
}

// ============================ 1. attributed, authorized delete ============================

#[test]
fn r16_shared_scope_authoritative_item_is_never_hard_deletable() {
    let mut store = InMemoryStore::new();
    let approver = Principal::user("lead-1", &[CAP_APPROVE]);
    store
        .write_as(
            MemoryItem::org(
                "oki-1",
                Scope::Org,
                "settlement cutoff",
                OrgPayload::CodingConvention {
                    rule: "settlement cutoff is 17:30 IST".into(),
                    language: "n/a".into(),
                    example_do: "cutoff 17:30".into(),
                    example_dont: "cutoff 23:00".into(),
                    enforcement: Enforcement::Blocking,
                },
                Provenance::human("lead-1", 1.0),
            ),
            &AccessScope::from_principal(approver.clone()),
        )
        .expect("org write accepted into the governance queue");
    let state = store.promote("oki-1", &approver).expect("promoted");
    assert!(
        matches!(state, GovernanceState::Approved),
        "expected Approved, got {state:?}"
    );

    // Even the approver cannot hard-delete authoritative shared knowledge: it is audit evidence.
    let admin = AccessScope::from_principal(Principal::admin("root"));
    let err = store
        .delete_as("oki-1", &admin)
        .expect_err("authoritative shared item must refuse hard-delete");
    assert!(
        format!("{err:?}").contains("retained for audit"),
        "wrong refusal reason: {err:?}"
    );
    assert!(store.get_unchecked("oki-1").is_some(), "item was destroyed anyway");
}

#[test]
fn r16_queued_shared_item_needs_the_same_human_gate_as_promotion() {
    let mut store = InMemoryStore::new();
    let lead = AccessScope::from_principal(Principal::user("lead-1", &[CAP_APPROVE]));
    // Org-knowledge is the human-gated kind, so this sits in the governance queue as a Draft — the
    // only shared-scope state that is still discardable.
    store
        .write_as(
            MemoryItem::org(
                "draft-1",
                Scope::Org,
                "proposed convention",
                OrgPayload::CodingConvention {
                    rule: "prefer thiserror".into(),
                    language: "rust".into(),
                    example_do: "?".into(),
                    example_dont: "unwrap".into(),
                    enforcement: Enforcement::Advisory,
                },
                Provenance::human("lead-1", 1.0),
            ),
            &lead,
        )
        .expect("draft accepted");
    assert_eq!(
        store.get_unchecked("draft-1").map(|i| i.governance),
        Some(GovernanceState::Draft),
        "org write should be queued, not authoritative"
    );

    // A member without CAP_APPROVE may see the org draft but may not discard it.
    let member = AccessScope::from_principal(Principal::user("dev-9", &[]));
    let err = store
        .delete_as("draft-1", &member)
        .expect_err("discarding a shared draft requires the approve capability");
    assert!(format!("{err:?}").contains(CAP_APPROVE), "{err:?}");

    // The approve holder may.
    assert!(store.delete_as("draft-1", &lead).unwrap());
    assert!(store.get_unchecked("draft-1").is_none());
}

#[test]
fn r16_other_users_personal_item_is_invisible_not_an_error() {
    let mut store = InMemoryStore::new();
    let a = AccessScope::from_principal(Principal::user("user-a", &[]));
    store
        .write_as(item("a-pref", Scope::User("user-a".into()), "user-a"), &a)
        .unwrap();

    // B must not be able to delete it — and must not learn that it exists. Ok(false), never Err:
    // an error would be an existence oracle over another user's personal memory.
    let b = AccessScope::from_principal(Principal::user("user-b", &[]));
    assert_eq!(
        store.delete_as("a-pref", &b),
        Ok(false),
        "B either erased A's memory or was told the id exists"
    );
    assert_eq!(
        store.delete_as("does-not-exist", &b),
        Ok(false),
        "a missing id must be indistinguishable from an invisible one"
    );
    assert!(store.get_unchecked("a-pref").is_some());
}

#[test]
fn r16_admin_break_glass_delete_is_permitted_but_recorded_with_its_justification() {
    let mut store = InMemoryStore::new();
    let a = AccessScope::from_principal(Principal::user("user-a", &[]));
    store
        .write_as(item("a-pref", Scope::User("user-a".into()), "user-a"), &a)
        .unwrap();

    let dpo = AccessScope::from_principal(Principal::admin("dpo-1"))
        .with_break_glass("DSAR erasure request TICKET-4211");
    assert!(store.delete_as("a-pref", &dpo).unwrap());

    let e = store
        .audit_entries()
        .iter()
        .find(|e| e.action == "delete")
        .expect("delete audited");
    assert!(e.detail.contains("by=dpo-1"), "{}", e.detail);
    assert!(
        e.detail
            .contains("break-glass=DSAR erasure request TICKET-4211"),
        "break-glass justification missing from the audit line: {}",
        e.detail
    );
}

// ============================ 2. no cross-user poisoning ============================

#[test]
fn r16_cross_user_personal_write_is_refused() {
    let mut store = InMemoryStore::new();
    let b = AccessScope::from_principal(Principal::user("user-b", &[]));
    let err = store
        .write_as(item("poison", Scope::User("user-a".into()), "user-b"), &b)
        .expect_err("B must not author into A's personal scope");
    assert!(
        format!("{err:?}").to_lowercase().contains("author")
            || format!("{err:?}").to_lowercase().contains("scope"),
        "unexpected refusal: {err:?}"
    );
    assert!(store.get_unchecked("poison").is_none());
}

// ============================ 3. erasure cascade with per-tier proof ============================

#[derive(Debug, Default)]
struct FeedbackTier {
    captured: Vec<String>,
}

impl ErasureTier for FeedbackTier {
    fn tier(&self) -> &str {
        "feedback"
    }
    fn erase_subject(&mut self, subject: &str) -> usize {
        let before = self.captured.len();
        self.captured.retain(|s| s != subject);
        before - self.captured.len()
    }
}

#[test]
fn r16_erasure_cascades_to_session_and_feedback_with_per_tier_audit() {
    let mut store = InMemoryStore::new();
    let a = AccessScope::from_principal(Principal::user("user-a", &[]));
    store
        .write_as(item("a-1", Scope::User("user-a".into()), "user-a"), &a)
        .unwrap();

    // Session tier holds live scratch for the subject's session.
    let seam = InMemorySessionSeam::default();
    seam.put(
        "sess-a",
        &item("scratch-1", Scope::User("user-a".into()), "user-a"),
        0,
        1_000,
    );
    assert_eq!(seam.all("sess-a", 1).len(), 1);

    let mut feedback = FeedbackTier {
        captured: vec!["user-a".into(), "user-b".into()],
    };
    let mut session_tier = SessionErasureTier::new(&seam, &["sess-a"]);

    let receipt = {
        let mut tiers: Vec<&mut dyn ErasureTier> = vec![&mut session_tier, &mut feedback];
        cascade_erasure(&mut store, "user-a", &mut tiers)
    };

    assert_eq!(receipt.removed_ids, vec!["a-1".to_string()]);
    assert_eq!(
        seam.all("sess-a", 1).len(),
        0,
        "session tier still holds the erased subject's scratch"
    );
    assert_eq!(feedback.captured, vec!["user-b".to_string()]);

    // Each tier is proved separately, so a half-completed cascade is visible in the log.
    let tiers: Vec<&str> = receipt.cascaded.iter().map(|t| t.tier.as_str()).collect();
    assert_eq!(tiers, vec!["session", "feedback"]);
    assert!(receipt.cascaded.iter().all(|t| t.removed == 1));
    for t in &receipt.cascaded {
        let e = &store.audit_entries()[t.audit_seq as usize];
        assert_eq!(e.action, "erase-cascade");
        assert!(
            e.detail.contains(&format!("tier={}", t.tier)),
            "{}",
            e.detail
        );
    }
    assert_eq!(store.verify_audit_chain(), None, "chain broken by cascade");
}

// ============================ audit chain: crypto + seam ============================

#[test]
fn r16_audit_chain_default_is_sha256_and_detects_tampering() {
    let mut store = InMemoryStore::new();
    let a = AccessScope::from_principal(Principal::user("user-a", &[]));
    store
        .write_as(item("a-1", Scope::User("user-a".into()), "user-a"), &a)
        .unwrap();
    store.delete_as("a-1", &a).unwrap();

    let entries = store.audit_entries();
    assert!(!entries.is_empty());
    for e in entries {
        assert_eq!(e.hasher, "sha256", "default hasher must be cryptographic");
        assert_eq!(
            e.digest.len(),
            64,
            "expected a full-width SHA-256 hex digest"
        );
    }
    assert_eq!(store.verify_audit_chain(), None);
}

#[test]
fn r16_audit_hasher_is_a_seam_and_keyed_variant_is_unforgeable_without_the_key() {
    let key = b"vault-held-audit-key-not-in-tree".to_vec();
    let mut store =
        InMemoryStore::new().with_audit_hasher(Box::new(HmacSha256AuditHasher::new(key.clone())));
    let a = AccessScope::from_principal(Principal::user("user-a", &[]));
    store
        .write_as(item("a-1", Scope::User("user-a".into()), "user-a"), &a)
        .unwrap();
    store.delete_as("a-1", &a).unwrap();

    let entries: Vec<_> = store.audit_entries().to_vec();
    assert!(entries.iter().all(|e| e.hasher == "hmac-sha256"));
    assert_eq!(store.verify_audit_chain(), None);

    // A party who can rewrite the log but lacks the key cannot produce a matching digest: recomputing
    // with the un-keyed default over the same fields yields a different value.
    let e = &entries[0];
    let forged = ainxt_memory::Sha256AuditHasher.digest(
        e.seq,
        &e.action,
        &e.subject,
        &e.detail,
        &e.prev_digest,
    );
    assert_ne!(
        forged, e.digest,
        "keyed chain was reproducible without the key"
    );

    // The Debug impl must not leak the key — a debug-logged hasher would hand over forgery power.
    let dbg = format!("{:?}", HmacSha256AuditHasher::new(key));
    assert!(dbg.contains("redacted"), "key leaked via Debug: {dbg}");
    assert!(!dbg.contains("vault-held"), "key leaked via Debug: {dbg}");
}

#[test]
fn r16_non_cryptographic_hasher_is_available_but_labelled() {
    let mut store = InMemoryStore::new().with_audit_hasher(Box::new(Fnv1aAuditHasher));
    let a = AccessScope::from_principal(Principal::user("user-a", &[]));
    store
        .write_as(item("a-1", Scope::User("user-a".into()), "user-a"), &a)
        .unwrap();
    assert!(store.audit_entries().iter().all(|e| e.hasher == "fnv1a"));
    assert_eq!(store.verify_audit_chain(), None);
}

#[test]
fn r16_audit_preimage_is_length_prefixed_so_fields_cannot_be_shifted() {
    // Two different entries that would share a naive "a|b|c"-style preimage must not collide.
    let h = ainxt_memory::Sha256AuditHasher;
    let one = h.digest(1, "act|x", "subj", "detail", "");
    let two = h.digest(1, "act", "x|subj", "detail", "");
    assert_ne!(
        one, two,
        "delimiter-shifting collision in the audit preimage"
    );
}
