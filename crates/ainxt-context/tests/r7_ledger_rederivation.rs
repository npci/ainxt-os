// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-7 gap closure: **server-side numeric re-derivation is the DEFAULT hard gate on
//! ledger-class answers**, exposed via a `from_engine_verified`-style default the surface uses
//! ([`ainxt_context::CompiledWindow::verify_ledger_answer`] / [`ainxt_context::LedgerAnswerGate`]).
//!
//! The design (`STRUCTURED_FEDERATED_RETRIEVAL.md` §5.2, gap BH): a confidently-wrong figure on
//! ledger/settlement data is a payment *incident*, so for a ledger-class answer every stated number
//! must be independently re-derived from the server's own data and diffed against what the model
//! stated — ship on match, BLOCK on mismatch. This runs over the SAME [`CompiledWindow`] that
//! grounded the answer, so the material that grounded it also verifies its numbers, and it is armed
//! by DEFAULT precisely when the window's sources are ledger-class (Confidential+). Below that floor
//! the numeric hard-block is disarmed so ordinary prose numbers are never over-blocked.
//!
//! Fail-before / pass-after: `verify_ledger_answer`, `LedgerAnswerGate`, `SourceRederiver`, and
//! `is_ledger_class` did not exist before this round, so the file fails to COMPILE before it and
//! passes after — on the real production objects (`compile_window` over `HybridRetriever`). Every
//! filter remains a retrieval read-filter / answer-correctness gate, never a turn-admission denial.

use std::collections::BTreeMap;

use ainxt_context::{
    compile_window, is_ledger_class, AccessContext, CompileRequest, HybridRetriever,
    LedgerAnswerGate, NumericClaim, OptimizerConfig, RowFilter, Source, SourceRederiver,
    ValueClass,
};
use ainxt_retrieval::{Chunk as RChunk, Corpus as RCorpus, EligibleModel, WordTokenCounter};
use ainxt_types::{DataClass, Principal};

const LEDGER_TEXT: &str = "There were 47 failed settlements in the nightly reconciliation batch";
const PUBLIC_TEXT: &str = "The standard UPI per transaction limit is 5 lakh rupees";

/// A settlement-eng ledger source at the ledger tier (Confidential).
fn ledger_corpus() -> RCorpus {
    RCorpus::new(vec![RChunk::new(
        "ledger-row",
        LEDGER_TEXT,
        DataClass::Confidential,
    )
    .with_attribute("department", "settlement-eng")])
}

/// A public knowledge source (below the ledger floor).
fn public_corpus() -> RCorpus {
    RCorpus::new(vec![RChunk::new("kb-row", PUBLIC_TEXT, DataClass::Public)
        .with_attribute("department", "settlement-eng")])
}

fn cfg() -> OptimizerConfig {
    OptimizerConfig {
        eligible: vec![EligibleModel::new("wide", 8000)],
        prefer_fresh: false,
        graph_weight: 0.0,
        ..OptimizerConfig::default()
    }
}

fn ledger_window(
    corpus: RCorpus,
    clearance: DataClass,
    query: &str,
) -> ainxt_context::CompiledWindow {
    let hybrid = HybridRetriever::from_retrieval_corpus(corpus);
    let principal = Principal::user("analyst", &[]).with_department("settlement-eng");
    let row_filter = RowFilter::department_isolation(&principal);
    let access = AccessContext::new(clearance, Some("settlement-eng"), Some(3), &[]);
    let seeds = BTreeMap::new();
    let req = CompileRequest {
        access: &access,
        row_filter: Some(&row_filter),
        graph: None,
        seeds: &seeds,
    };
    compile_window(query, &hybrid, &cfg(), &WordTokenCounter, &req)
}

#[test]
fn r7_ledger_rederivation_default_ships_on_match_blocks_on_mismatch() {
    // The window grounds on a Confidential ledger source → the answer is ledger-class, so the
    // numeric hard gate is armed by DEFAULT.
    let window = ledger_window(ledger_corpus(), DataClass::Confidential, LEDGER_TEXT);
    assert!(
        window.context.chunks.iter().any(|c| c.id == "ledger-row"),
        "the cleared caller grounds the ledger source"
    );

    // The model states a figure and declares it as a sourced metric claim.
    let answer = format!("{LEDGER_TEXT}.");
    let claims = vec![NumericClaim::metric(
        47.0,
        "count",
        ValueClass::Exact,
        "failed_settlement_count",
        "qh1",
    )];

    // Server-side re-derivation reproduces the SAME value → the answer ships.
    let matching = SourceRederiver::new().with_metric("failed_settlement_count", "qh1", 47.0);
    let ok = window.verify_ledger_answer(&answer, &claims, &matching);
    assert!(
        ok.ships(),
        "a server-re-derived matching ledger figure ships: {:?}",
        ok.blocked
    );
    assert!(!ok.blocked_on_mismatch());

    // Server-side re-derivation reproduces a DIFFERENT value → BLOCKED on mismatch (the incident
    // signal), never shipped as an arbitrarily-picked number.
    let drifted = SourceRederiver::new().with_metric("failed_settlement_count", "qh1", 52.0);
    let blocked = window.verify_ledger_answer(&answer, &claims, &drifted);
    assert!(
        !blocked.ships(),
        "a ledger figure the server recomputes differently must BLOCK"
    );
    assert!(
        blocked.blocked_on_mismatch(),
        "the mismatch is the payments-incident signal fed to escalation"
    );

    // Fail-closed: the server cannot reproduce the figure at all (unknown query hash) → still BLOCK
    // (never ship a ledger number the deterministic path can't independently reproduce).
    let cannot = SourceRederiver::new();
    let fc = window.verify_ledger_answer(&answer, &claims, &cannot);
    assert!(
        !fc.ships(),
        "an unreproducible ledger figure is fail-closed"
    );
    assert!(
        !fc.blocked_on_mismatch(),
        "not-reproducible is a block but not a value mismatch"
    );
}

#[test]
fn r7_numeric_hard_gate_is_disarmed_below_the_ledger_floor() {
    // The same default gate over a window grounded on a PUBLIC source: not ledger-class, so the
    // numeric hard-block is disarmed and an unbacked prose figure does NOT block a grounded answer.
    let window = ledger_window(public_corpus(), DataClass::Confidential, PUBLIC_TEXT);
    assert!(
        window.context.chunks.iter().any(|c| c.id == "kb-row"),
        "grounds the public source"
    );

    let sources: Vec<Source> = window
        .context
        .chunks
        .iter()
        .map(|c| Source::new(&c.id, &c.text, c.data_class))
        .collect();
    assert!(
        !is_ledger_class(&sources),
        "a public-only window is not ledger-class"
    );

    // Answer is fully grounded prose that contains a number, but declares NO sourced claim.
    let answer = format!("{PUBLIC_TEXT}.");
    let no_claims: [NumericClaim; 0] = [];
    let out = window.verify_ledger_answer(&answer, &no_claims, &SourceRederiver::new());
    assert!(
        out.ships(),
        "a grounded non-ledger answer ships despite an unbacked prose number: {:?}",
        out.blocked
    );

    // Control: the SAME answer + no claims IS blocked when the sources are ledger-class (the gate is
    // armed), proving it is the ledger-class floor — not something else — that arms the hard block.
    let ledger = ledger_window(ledger_corpus(), DataClass::Confidential, LEDGER_TEXT);
    let ledger_answer = format!("{LEDGER_TEXT}.");
    let armed = ledger.verify_ledger_answer(&ledger_answer, &no_claims, &SourceRederiver::new());
    assert!(
        !armed.ships(),
        "an unbacked figure on a ledger-class answer MUST block (the armed default)"
    );
}

#[test]
fn r7_ledger_answer_gate_default_is_payments_safe() {
    // The `from_engine_verified`-style default the surface installs: payments-safe policy + the
    // default ledger floor, armed only for ledger-class sources.
    let ledger = vec![Source::new("s", LEDGER_TEXT, DataClass::Confidential)];
    let public = vec![Source::new("s", PUBLIC_TEXT, DataClass::Public)];

    let rd = SourceRederiver::new().with_metric("failed_settlement_count", "qh1", 47.0);
    let gate = LedgerAnswerGate::from_engine_verified(&rd);

    assert!(
        gate.is_armed(&ledger),
        "Confidential+ sources arm the numeric hard gate"
    );
    assert!(
        !gate.is_armed(&public),
        "below the floor the numeric hard gate is disarmed"
    );

    // Armed + matching re-derivation → ships.
    let claims = vec![NumericClaim::metric(
        47.0,
        "count",
        ValueClass::Exact,
        "failed_settlement_count",
        "qh1",
    )];
    let answer = format!("{LEDGER_TEXT}.");
    assert!(gate.verify(&ledger, &answer, &claims).ships());

    // Armed + mismatched re-derivation → blocked-on-mismatch.
    let rd_bad = SourceRederiver::new().with_metric("failed_settlement_count", "qh1", 9.0);
    let gate_bad = LedgerAnswerGate::from_engine_verified(&rd_bad);
    let v = gate_bad.verify(&ledger, &answer, &claims);
    assert!(!v.ships() && v.blocked_on_mismatch());
}
