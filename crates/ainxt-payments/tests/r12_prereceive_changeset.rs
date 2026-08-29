// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-12 closure of the §4 Layer-4 (LOW) gap — **the `payment_boundary` front-matter is enforced
//! by CI + the git pre-receive hook so a payment-initiating definition cannot merge.**
//!
//! The pure per-definition decision (`enforce`) already existed. This adds `evaluate_changeset` — the
//! whole-push decision the git `pre-receive` hook and the CI job both call: run `enforce` on every
//! changed control-plane definition and, git-style, **reject the entire push if ANY definition
//! fails** — so a `payment-initiating` def cannot merge and cannot be smuggled in alongside good
//! changes.
//!
//! The git transport itself (the `pre-receive` hook process + CI runner) is infra this crate cannot
//! host; this is the versioned, tested policy artifact those hooks invoke, so the boundary is enforced
//! identically at both gates from one place.
//!
//! Fail-before/pass-after: `evaluate_changeset` / `ChangedDefinition` / `BlockedDefinition` are new.

use ainxt_payments::front_matter::{
    evaluate_changeset, AuthoringContext, ChangedDefinition, FrontMatterError,
};

fn senior_ctx() -> AuthoringContext {
    AuthoringContext {
        payments_council_approved: true,
        commit_signed: true,
        author_can_approve: true,
        author_ad_level: 3,
    }
}

fn changed(path: &str, raw: &str, ctx: AuthoringContext) -> ChangedDefinition {
    ChangedDefinition {
        path: path.into(),
        raw_payment_boundary: raw.into(),
        authoring: ctx,
    }
}

#[test]
fn r12_prereceive_blocks_push_with_a_payment_initiating_definition() {
    // A push mixing benign changes with one payment-initiating definition.
    let push = vec![
        changed("roles/coder.md", "none", senior_ctx()),
        changed("roles/reconciler.md", "payment-adjacent", senior_ctx()),
        changed("roles/settler.md", "payment-initiating", senior_ctx()), // the poison
    ];
    let blocked = evaluate_changeset(&push).expect_err("the whole push must be rejected");
    // The offending definition is named with the reserved-value reason.
    assert_eq!(blocked.len(), 1);
    assert_eq!(blocked[0].path, "roles/settler.md");
    assert!(matches!(
        blocked[0].error,
        FrontMatterError::ReservedValue(_)
    ));
}

#[test]
fn r12_prereceive_accepts_a_fully_authorized_clean_push() {
    let push = vec![
        changed("roles/coder.md", "none", senior_ctx()),
        changed("roles/reconciler.md", "payment-adjacent", senior_ctx()),
        changed("roles/greeter.md", "", senior_ctx()), // empty defaults to none
    ];
    assert!(
        evaluate_changeset(&push).is_ok(),
        "only none/payment-adjacent, properly authored"
    );
}

#[test]
fn r12_prereceive_reports_every_offender_and_underauthorized_adjacent() {
    // Two failures in one push: a smuggled payment-initiating def AND a payment-adjacent def authored
    // without payments-council approval. The hook reports BOTH so the author fixes it in one pass.
    let no_council = AuthoringContext {
        payments_council_approved: false,
        ..senior_ctx()
    };
    let push = vec![
        changed("roles/settler.md", "payment-initiating", senior_ctx()),
        changed("roles/mover.md", "payment-adjacent", no_council),
        changed("roles/coder.md", "none", senior_ctx()),
    ];
    let mut blocked = evaluate_changeset(&push).unwrap_err();
    blocked.sort_by(|a, b| a.path.cmp(&b.path));
    assert_eq!(blocked.len(), 2);
    assert_eq!(blocked[0].path, "roles/mover.md");
    assert_eq!(
        blocked[0].error,
        FrontMatterError::MissingPaymentsCouncilApproval
    );
    assert_eq!(blocked[1].path, "roles/settler.md");
    assert!(matches!(
        blocked[1].error,
        FrontMatterError::ReservedValue(_)
    ));
}

#[test]
fn r12_prereceive_empty_changeset_passes() {
    assert!(evaluate_changeset(&[]).is_ok());
}
