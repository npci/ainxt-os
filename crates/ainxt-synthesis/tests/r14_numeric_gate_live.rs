// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-14 HIGH closure (context-fabric): the numeric re-derivation gate was **non-functional and
//! over-blocked on the live /v1/chat path** (gap BH, `STRUCTURED_FEDERATED_RETRIEVAL.md` §5).
//!
//! Root cause: the served surface has no typed numeric-claim contract (the model returns prose, not
//! typed [`NumericClaim`]s), so running the contract lint with an EMPTY claim set flagged EVERY prose
//! number as "unbacked" and blocked it — a benign year, a step count, or a truthful figure alike.
//!
//! Fix under test: [`verify_answer_live`] / [`extract_ledger_figures`] — the live path now EXTRACTS
//! genuine ledger/metric claims (numbers whose sentence carries settlement/reconciliation vocabulary)
//! and re-derives each against the material that grounded the answer, blocking ONLY on a real
//! re-derivation failure (a value that contradicts the source, or a ledger figure no source can
//! reproduce), while a benign incidental number and a no-claim answer ship untouched.
//!
//! Fail-before / pass-after: `verify_answer_live` and `extract_ledger_figures` did not exist before
//! this round, so this file fails to COMPILE before the fix and passes after. The policy used here is
//! byte-for-byte the served /v1/chat default (`AnswerVerifier::numeric_gate_only`): faithfulness and
//! cross-source conflict are NON-blocking, the numeric gate is the only hard block — the exact
//! configuration under which the over-block manifested.

use ainxt_synthesis::rederive::Tolerance;
use ainxt_synthesis::{
    extract_ledger_figures, verify_answer_live, LedgerFigureVerdict, Source, VerificationPolicy,
};
use ainxt_types::DataClass;

/// The served /v1/chat numeric-only policy: only the numeric gate hard-blocks (faithfulness and
/// cross-source conflict are handled as redact-don't-block presentation caveats there).
fn numeric_only_policy() -> VerificationPolicy {
    VerificationPolicy {
        block_on_unsupported: false,
        block_on_unresolved_conflict: false,
        block_on_numeric_gate: true,
        ..VerificationPolicy::default()
    }
}

/// A ledger source that quantifies the reconciliation failure rate as 3% (the server truth).
fn ledger_sources() -> Vec<Source> {
    vec![Source::new(
        "recon-metric",
        "The reconciliation failure rate was 3% in the nightly batch.",
        DataClass::Confidential,
    )]
}

#[test]
fn r14_numeric_gate_blocks_fabricated_ledger_figure_on_mismatch() {
    let sources = ledger_sources();
    // The model states a DIFFERENT reconciliation failure rate than the grounding source carries —
    // a genuine re-derivation MISMATCH (the payment-incident signal), so it MUST block.
    let fabricated = "The reconciliation failure rate was 12% overnight.";
    let v = verify_answer_live(&sources, fabricated, &numeric_only_policy());
    assert!(
        !v.ships(),
        "a fabricated ledger figure that contradicts the source must BLOCK: {:?}",
        v.blocked
    );

    // And it is classified as a genuine re-derivation mismatch (not merely unbacked prose).
    let report = extract_ledger_figures(
        fabricated,
        &sources,
        VerificationPolicy::default().synthesis.support_containment,
        &Tolerance::default(),
    );
    assert!(
        report.has_mismatch(),
        "the block is a real re-derivation mismatch: {report:?}"
    );
    assert!(matches!(
        report.findings.first().map(|f| &f.verdict),
        Some(LedgerFigureVerdict::Mismatch { source_value, .. }) if (*source_value - 3.0).abs() < 1e-9
    ));
}

#[test]
fn r14_numeric_gate_ships_benign_number_and_no_claim_answer() {
    let sources = ledger_sources();

    // (a) A BENIGN numeric answer — a launch year, no ledger/metric vocabulary in its sentence — is
    //     NOT a ledger claim and must ship (the over-block this fix removes).
    let benign = "UPI was launched in 2016 and now serves millions of users daily.";
    let v_benign = verify_answer_live(&sources, benign, &numeric_only_policy());
    assert!(
        v_benign.ships(),
        "a benign incidental number must ship, not be over-blocked: {:?}",
        v_benign.blocked
    );
    assert!(
        extract_ledger_figures(
            benign,
            &sources,
            VerificationPolicy::default().synthesis.support_containment,
            &Tolerance::default(),
        )
        .findings
        .is_empty(),
        "a benign number is not extracted as a ledger claim at all"
    );

    // (b) A NO-CLAIM answer — no numbers — must ship untouched.
    let no_claim = "UPI is a real-time payments rail operated across member banks.";
    let v_none = verify_answer_live(&sources, no_claim, &numeric_only_policy());
    assert!(
        v_none.ships(),
        "a no-claim answer must ship untouched: {:?}",
        v_none.blocked
    );
}

#[test]
fn r14_numeric_gate_ships_truthful_ledger_figure_that_rederives() {
    let sources = ledger_sources();
    // The model states the SAME reconciliation failure rate the grounding source carries — it
    // re-derives, so a truthful ledger figure ships (the gate must not block a correct number).
    let truthful = "The reconciliation failure rate was 3% overnight.";
    let v = verify_answer_live(&sources, truthful, &numeric_only_policy());
    assert!(
        v.ships(),
        "a truthful ledger figure that re-derives against the source must ship: {:?}",
        v.blocked
    );

    let report = extract_ledger_figures(
        truthful,
        &sources,
        VerificationPolicy::default().synthesis.support_containment,
        &Tolerance::default(),
    );
    assert!(!report.has_mismatch());
    assert!(matches!(
        report.findings.first().map(|f| &f.verdict),
        Some(LedgerFigureVerdict::Verified { source_value, .. }) if (*source_value - 3.0).abs() < 1e-9
    ));
}

#[test]
fn r14_numeric_gate_fail_closed_on_unreproducible_ledger_figure() {
    // A ledger figure that NO grounding source can reproduce (empty corpus) is fail-closed BLOCKED —
    // never shipped as verified. This preserves the served-path r6/r10 behavior: an unbacked ledger
    // figure is escalated, not shipped. (Distinct from the benign case: this sentence IS a ledger
    // claim by vocabulary — "settlement" — so it must re-derive and, lacking any source, blocks.)
    let no_sources: Vec<Source> = Vec::new();
    let ledger_claim = "The settlement total was 987654 rupees.";
    let v = verify_answer_live(&no_sources, ledger_claim, &numeric_only_policy());
    assert!(
        !v.ships(),
        "an unreproducible ledger figure must be fail-closed blocked: {:?}",
        v.blocked
    );

    let report = extract_ledger_figures(
        ledger_claim,
        &no_sources,
        VerificationPolicy::default().synthesis.support_containment,
        &Tolerance::default(),
    );
    assert!(
        !report.has_mismatch(),
        "not-reproducible is a block but not a value mismatch"
    );
    assert!(matches!(
        report.findings.first().map(|f| &f.verdict),
        Some(LedgerFigureVerdict::Unreproducible)
    ));
}
