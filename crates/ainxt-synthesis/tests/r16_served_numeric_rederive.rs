// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-16 CRITICAL (`context-fabric`): **the served numeric gate must independently RE-DERIVE.**
//!
//! `STRUCTURED_FEDERATED_RETRIEVAL.md` §5.2: the runtime independently re-executes the same
//! `query_hash`'s compiled query server-side — a fresh deterministic recomputation, not a re-ask and
//! not a re-read — and diffs it against the model's stated value.
//!
//! What shipped instead: the served live gate ([`verify_answer_live`]) took no re-deriver at all. It
//! re-read the figure out of the RETRIEVED CHUNK TEXT the answer was generated from. That is not an
//! independent check: if the retrieved material carries a stale or wrong figure (a cached dashboard
//! snapshot, a superseded postmortem) the model repeats it and the gate confirms it — the exact
//! confidently-wrong payments answer §5.2 exists to stop.
//!
//! Fail-before / pass-after: in `r16_server_rederivation_catches_what_source_text_cannot` the
//! grounding source says 9 and the server recomputation says 7. `verify_answer_live` ships the 9
//! (its source text agrees with it); [`verify_answer_live_rederived`] blocks it.

use ainxt_synthesis::rederive::{ClaimSource, Rederiver, Tolerance};
use ainxt_synthesis::{
    rederive_ledger_figures, verify_answer_live, verify_answer_live_rederived, BlockReason,
    LedgerFigureVerdict, Source, VerificationPolicy,
};
use ainxt_types::DataClass;

/// A re-deriver standing in for the read-replica executor: it reproduces the value the SERVER
/// recomputes for a given compiled-query identity, independent of any retrieved text.
struct ServerExec {
    query_hash: &'static str,
    value: f64,
}

impl Rederiver for ServerExec {
    fn rederive(&self, source: &ClaimSource) -> Option<f64> {
        match source {
            ClaimSource::Metric { query_hash, .. } if query_hash == self.query_hash => {
                Some(self.value)
            }
            _ => None,
        }
    }
}

/// A re-deriver that can reproduce nothing (a replica error / unknown hash) — fail-closed.
struct Unavailable;
impl Rederiver for Unavailable {
    fn rederive(&self, _s: &ClaimSource) -> Option<f64> {
        None
    }
}

fn numeric_only_policy() -> VerificationPolicy {
    VerificationPolicy {
        block_on_numeric_gate: true,
        block_on_unsupported: false,
        block_on_unresolved_conflict: false,
        ..Default::default()
    }
}

fn turn_source() -> Vec<ClaimSource> {
    vec![ClaimSource::Metric {
        id: "failed_settlement_count".to_string(),
        query_hash: "qh-settlement-tuesday".to_string(),
    }]
}

#[test]
fn r16_server_rederivation_catches_what_source_text_cannot() {
    // The retrieved material carries a STALE figure (9) — and the model faithfully repeats it.
    let sources = vec![Source::new(
        "dashboard-snapshot",
        "There were 9 failed settlements for bank X on Tuesday.",
        DataClass::Confidential,
    )];
    let answer = "There were 9 failed settlements for bank X on Tuesday.";

    // BEFORE (source-text re-reading only): the stale figure "verifies" against the stale text and
    // ships. This is the served default today, asserted here so the regression is visible.
    let text_only = verify_answer_live(&sources, answer, &numeric_only_policy());
    assert!(
        !text_only.blocked.contains(&BlockReason::NumericGateFailed),
        "the source-text gate cannot catch a figure its own sources repeat"
    );

    // AFTER (§5.2): the server independently re-executes the turn's compiled query and gets 7.
    let server = ServerExec {
        query_hash: "qh-settlement-tuesday",
        value: 7.0,
    };
    let v = verify_answer_live_rederived(
        &sources,
        answer,
        &numeric_only_policy(),
        &server,
        &turn_source(),
    );
    assert!(
        v.blocked.contains(&BlockReason::NumericGateFailed),
        "a figure the server recomputation contradicts must BLOCK: {:?}",
        v.blocked
    );

    // The verdict names the re-derivation identity, so lineage records WHAT it was checked against.
    let report = rederive_ledger_figures(
        answer,
        &sources,
        numeric_only_policy().synthesis.support_containment,
        &Tolerance::default(),
        &server,
        &turn_source(),
    );
    assert!(report.has_mismatch());
    let f = report.findings.first().expect("one ledger figure");
    assert_eq!(f.stated, 9.0);
    match &f.verdict {
        LedgerFigureVerdict::Mismatch {
            source_id,
            source_value,
            ..
        } => {
            assert_eq!(
                source_id,
                "rederive:metric:failed_settlement_count:qh-settlement-tuesday"
            );
            assert_eq!(*source_value, 7.0);
        }
        other => panic!("expected a re-derivation mismatch, got {other:?}"),
    }
}

#[test]
fn r16_server_rederivation_ships_the_recomputed_figure() {
    // The model states the figure the server independently recomputes → ships, and the lineage
    // records that it was verified against the SERVER, not against the retrieved text.
    let sources = vec![Source::new(
        "replica-note",
        "Settlement failures are tracked per bank.",
        DataClass::Confidential,
    )];
    let answer = "There were 7 failed settlements for bank X on Tuesday.";
    let server = ServerExec {
        query_hash: "qh-settlement-tuesday",
        value: 7.0,
    };

    let v = verify_answer_live_rederived(
        &sources,
        answer,
        &numeric_only_policy(),
        &server,
        &turn_source(),
    );
    assert!(
        !v.blocked.contains(&BlockReason::NumericGateFailed),
        "an independently re-derived figure ships: {:?}",
        v.blocked
    );

    let report = rederive_ledger_figures(
        answer,
        &sources,
        numeric_only_policy().synthesis.support_containment,
        &Tolerance::default(),
        &server,
        &turn_source(),
    );
    assert!(report.ships());
    assert!(matches!(
        report.findings.first().map(|f| &f.verdict),
        Some(LedgerFigureVerdict::Verified { source_value, .. }) if (*source_value - 7.0).abs() < 1e-9
    ));
}

#[test]
fn r16_rederivation_is_fail_closed_and_does_not_over_block() {
    let sources = vec![Source::new(
        "replica-note",
        "Settlement failures are tracked per bank.",
        DataClass::Confidential,
    )];

    // (a) Fail-closed: the runtime recorded a structured source but the server cannot reproduce it
    // (replica error). The figure is NOT presented as verified — it falls back to the source-text
    // pass, which cannot reproduce it either → blocked, never silently shipped.
    let v = verify_answer_live_rederived(
        &sources,
        "There were 7 failed settlements for bank X.",
        &numeric_only_policy(),
        &Unavailable,
        &turn_source(),
    );
    assert!(v.blocked.contains(&BlockReason::NumericGateFailed));

    // (b) No over-block: a BENIGN number on a turn that did re-derive a ledger figure still ships —
    // the gate only adjudicates genuine ledger claims (redact-don't-block posture preserved).
    let server = ServerExec {
        query_hash: "qh-settlement-tuesday",
        value: 7.0,
    };
    let benign = "The dashboard was launched in 2021 and has 4 tabs.";
    let v = verify_answer_live_rederived(
        &sources,
        benign,
        &numeric_only_policy(),
        &server,
        &turn_source(),
    );
    assert!(
        !v.blocked.contains(&BlockReason::NumericGateFailed),
        "benign incidental numbers must never be blocked: {:?}",
        v.blocked
    );

    // (c) An ordinary RAG turn (no structured source recorded) is byte-for-byte the old behaviour.
    let grounded = vec![Source::new(
        "postmortem",
        "There were 3 failed settlements in the window.",
        DataClass::Confidential,
    )];
    let answer = "There were 3 failed settlements in the window.";
    let before = verify_answer_live(&grounded, answer, &numeric_only_policy());
    let after =
        verify_answer_live_rederived(&grounded, answer, &numeric_only_policy(), &server, &[]);
    assert_eq!(before.blocked, after.blocked);
    assert!(after.blocked.is_empty());
}
