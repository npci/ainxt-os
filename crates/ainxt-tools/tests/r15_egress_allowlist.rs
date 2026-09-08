// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R15 §1.7 — per-capability / per-data-class egress allow-list, unknown destination soft-blocks
//! pending approval. Fail-before: `Tool::egress()` was a bare boolean ("does this call leave the
//! box at all") with no destination- or data-class-aware allow-list anywhere in the crate — every
//! egressing call was either always allowed or the decision lived entirely outside this crate.
//! Pass-after: `EgressAllowList` is deny-by-omission (an unmapped destination is `PendingApproval`,
//! never a silent send), scoped per capability AND per data-class ceiling, with platform-wide
//! defaults for the design's "`connector.email` defaults to internal domains" example.

use ainxt_tools::egress_allowlist::{EgressAllowList, EgressDecision};
use ainxt_types::DataClass;

#[test]
fn an_allow_listed_destination_within_its_class_ceiling_is_allowed() {
    let list = EgressAllowList::new().allow(
        "connector.postgres.query",
        "warehouse.internal.example.com*",
        DataClass::Confidential,
    );
    let decision = list.check(
        "connector.postgres.query",
        "warehouse.internal.example.com/reports",
        DataClass::Internal,
    );
    assert_eq!(decision, EgressDecision::Allowed);
}

#[test]
fn an_unknown_destination_soft_blocks_pending_approval_never_a_silent_send() {
    let list = EgressAllowList::new().allow(
        "connector.email",
        "*@company.example.com",
        DataClass::Confidential,
    );
    let decision = list.check(
        "connector.email",
        "attacker@evil.example.net",
        DataClass::Internal,
    );
    match decision {
        EgressDecision::PendingApproval {
            capability,
            destination,
            data_class,
        } => {
            assert_eq!(capability, "connector.email");
            assert_eq!(destination, "attacker@evil.example.net");
            assert_eq!(data_class, DataClass::Internal);
        }
        other => panic!("expected PendingApproval, got {other:?}"),
    }
}

#[test]
fn a_capability_with_no_allow_list_entry_at_all_soft_blocks_every_destination() {
    // Deny-by-omission: a capability the operator never configured has NOTHING allowed by default.
    let list = EgressAllowList::new();
    let decision = list.check("connector.slack.post", "general-channel", DataClass::Public);
    assert!(!decision.is_allowed());
}

#[test]
fn data_class_ceiling_is_enforced_even_for_an_otherwise_matching_destination() {
    // §1.7's PER-DATA-CLASS dimension: the same destination that is fine for Internal data is soft-
    // blocked for a more sensitive class the entry was never trusted for.
    let list = EgressAllowList::new().allow(
        "connector.email",
        "*@company.example.com",
        DataClass::Internal, // trusted for Internal only
    );
    assert!(list
        .check(
            "connector.email",
            "alice@company.example.com",
            DataClass::Internal
        )
        .is_allowed());
    let blocked = list.check(
        "connector.email",
        "alice@company.example.com",
        DataClass::RegulatedPayment, // exceeds the entry's ceiling
    );
    assert!(
        !blocked.is_allowed(),
        "a regulated-class payload must not ride an Internal-ceiling entry"
    );
}

#[test]
fn platform_default_applies_across_capabilities_the_design_example() {
    // The design's literal example: "connector.email defaults to internal domains". A default entry
    // (not tied to one capability) covers every capability that egresses to that pattern.
    let list =
        EgressAllowList::new().allow_default("*.internal.example.com", DataClass::Confidential);
    assert!(list
        .check(
            "connector.email",
            "mail.internal.example.com",
            DataClass::Internal
        )
        .is_allowed());
    assert!(list
        .check(
            "connector.slack.post",
            "hooks.internal.example.com",
            DataClass::Internal
        )
        .is_allowed());
    // An external destination is still soft-blocked despite the default existing.
    assert!(!list
        .check(
            "connector.email",
            "external.example.net",
            DataClass::Internal
        )
        .is_allowed());
}

#[test]
fn per_capability_and_default_entries_compose() {
    let list = EgressAllowList::new()
        .allow(
            "connector.jira",
            "jira.company.example.com",
            DataClass::Confidential,
        )
        .allow_default("*.internal.example.com", DataClass::Internal);

    // The capability-specific entry applies to its own capability...
    assert!(list
        .check(
            "connector.jira",
            "jira.company.example.com",
            DataClass::Confidential
        )
        .is_allowed());
    // ...but NOT to a different capability (no cross-capability leakage of a scoped grant).
    assert!(!list
        .check(
            "connector.email",
            "jira.company.example.com",
            DataClass::Confidential
        )
        .is_allowed());
    // The default entry applies to any capability.
    assert!(list
        .check(
            "connector.email",
            "mail.internal.example.com",
            DataClass::Internal
        )
        .is_allowed());
}
