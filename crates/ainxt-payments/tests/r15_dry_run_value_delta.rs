// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-15 closure of the §4.5 LOW gap — **`ValueDeltaCommit`: a two-phase commit whose
//! `dry_run` preview showed a value delta.**
//!
//! Before this round, `PayloadSignal::ValueDeltaCommit` and `InitiationReason::ValueDeltaCommit`
//! existed only as enum variants a *test* constructed by hand — nothing in the crate ever
//! *derived* the signal from an actual §1.4 two-phase commit's `dry_run` preview numbers, so the
//! link the doc comment describes ("a two-phase `commit` whose `dry_run` preview showed a value
//! delta") was purely conceptual. This round adds [`DryRunValueSnapshot`] (the real before/after
//! preview-amount detector) and [`OutboundCall::from_dry_run`] (the constructor that derives the
//! payload signal from it, rather than letting a call site declare `ValueDeltaCommit` directly),
//! and proves end-to-end that a capability whose `dry_run` preview shows a changed amount is
//! caught by the classifier even though nothing about its destination or resource key looks
//! payment-shaped.
//!
//! Fail-before/pass-after: `DryRunValueSnapshot` and `OutboundCall::from_dry_run` did not exist
//! before this round.

use ainxt_payments::boundary::{
    DryRunValueSnapshot, InitiationReason, OutboundCall, PayloadSignal, PaymentBoundary,
};

#[test]
fn r15_dry_run_preview_with_value_delta_is_initiating_even_on_a_benign_destination() {
    let b = PaymentBoundary::payment_default();

    // A capability whose declared destination/resource are entirely benign — no settlement
    // perimeter hit, no settlement resource-key prefix — but whose §1.4 `dry_run` preview shows
    // the committed balance would move from 10_000 to 9_500 minor units (a debit-shaped delta).
    let snapshot = DryRunValueSnapshot {
        before_minor_units: 10_000,
        after_minor_units: 9_500,
    };
    assert!(snapshot.has_value_delta());
    assert_eq!(snapshot.delta_minor_units(), -500);
    assert_eq!(snapshot.payload_signal(), PayloadSignal::ValueDeltaCommit);

    let call = OutboundCall::from_dry_run(
        "https://internal.svc/generic-2pc",
        "generic-op:commit-42",
        snapshot,
    );
    let verdict = b.classify(&call);
    assert!(
        verdict.is_initiating(),
        "a dry_run preview showing a value delta must be caught regardless of destination/resource"
    );
    if let ainxt_payments::boundary::PaymentInitiationVerdict::Initiating { reasons } = verdict {
        assert!(reasons.contains(&InitiationReason::ValueDeltaCommit));
        // And ONLY that reason — this call carries no other payment-shaped signal.
        assert_eq!(reasons.len(), 1);
    } else {
        unreachable!();
    }

    // The pre-dispatch tripwire (§4.6) refuses it too.
    assert!(b.screen(&call).is_err());
}

#[test]
fn r15_dry_run_preview_with_no_delta_is_benign_and_adjacent() {
    let b = PaymentBoundary::payment_default();

    // A metadata-only dry_run (e.g. a config toggle) previews no amount change at all.
    let snapshot = DryRunValueSnapshot::unchanged(500);
    assert!(!snapshot.has_value_delta());
    assert_eq!(snapshot.delta_minor_units(), 0);
    assert_eq!(snapshot.payload_signal(), PayloadSignal::Benign);

    let call = OutboundCall::from_dry_run(
        "https://internal.svc/generic-2pc",
        "generic-op:commit-1",
        snapshot,
    );
    assert!(
        !b.classify(&call).is_initiating(),
        "an unchanged preview must not trip the value-delta signature"
    );
    assert!(b.screen(&call).is_ok());
}

#[test]
fn r15_credit_shaped_delta_initiates_just_as_much_as_a_debit_shaped_one() {
    let b = PaymentBoundary::payment_default();

    // An INCREASE (credit-shaped) preview must be caught exactly like a decrease — both move
    // value; the classifier does not privilege one sign over the other.
    let credit = DryRunValueSnapshot {
        before_minor_units: 1_000,
        after_minor_units: 1_200,
    };
    assert_eq!(credit.delta_minor_units(), 200);
    let call = OutboundCall::from_dry_run("https://internal.svc/2pc", "op:commit-credit", credit);
    assert!(b.classify(&call).is_initiating());
}
