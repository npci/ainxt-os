// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX turn-pipeline #1 — `numeric_synthesis`/`NumericSynthesis` did not exist anywhere in the
//! workspace. What existed (`ainxt-convo::AnswerVerifier::numeric_gate_only`, and every function in
//! `ainxt_synthesis::rederive` — `numeric_gate`, `rederive_and_verify`, `lint_numeric_claims`) only
//! VERIFIES a number the model has ALREADY written into its prose answer: each takes `answer: &str`
//! and/or an already-populated `NumericClaim.value` and diffs it against the `Rederiver`'s
//! independently-computed truth. There was no path that GENERATES a numeric answer from structured/
//! tool data — only a ship/block verdict on one the model already produced.
//!
//! This proves `synthesize_numeric_claim` / `synthesize_numeric_claims` / `render_numeric_claim`
//! (added to `ainxt-synthesis::rederive` — extending the existing verify-only crate rather than
//! standing up a new one, since it already owns `ClaimSource`/`Rederiver`/`NumericClaim`, the exact
//! vocabulary a generation path needs): a served turn asks the SAME `Rederiver` seam for the
//! ground-truth value UP FRONT (no model arithmetic involved at all — there is no `answer: &str`
//! parameter anywhere in the generation path) and gets back a ready-to-splice `NumericClaim`, which
//! still composes with the pre-existing verify-only gate for defense-in-depth.

use ainxt_synthesis::rederive::{
    numeric_gate, render_numeric_claim, synthesize_numeric_claim, synthesize_numeric_claims,
    ClaimSource, NumericClaim, NumericSynthesisError, Rederiver, Tolerance, ValueClass,
};

/// A minimal structured/tool-data stand-in: keyed ground truth a real deployment would serve from a
/// read-replica SQL executor (metric queries) or a recorded deterministic tool call.
struct FixedRederiver(std::collections::HashMap<String, f64>);

impl Rederiver for FixedRederiver {
    fn rederive(&self, source: &ClaimSource) -> Option<f64> {
        self.0.get(&source.rederive_key()?).copied()
    }
}

fn rederiver(pairs: &[(&str, f64)]) -> FixedRederiver {
    FixedRederiver(pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect())
}

#[test]
fn r17_synthesize_numeric_claim_computes_value_from_structured_source_not_from_prose() {
    let rd = rederiver(&[("metric:total_settlement_amount:h9", 128450.75)]);
    let source = ClaimSource::Metric {
        id: "total_settlement_amount".into(),
        query_hash: "h9".into(),
    };

    // Note: no `answer: &str` is passed anywhere — the value comes purely from the structured
    // source, unlike every verify-direction function in this crate.
    let claim = synthesize_numeric_claim("INR", ValueClass::Currency, source, &rd)
        .expect("the rederiver has this metric ⇒ synthesis must succeed");

    assert_eq!(claim.value, 128450.75);
    assert_eq!(claim.unit, "INR");
    assert_eq!(claim.value_class, ValueClass::Currency);
    assert_eq!(
        claim.source,
        ClaimSource::Metric {
            id: "total_settlement_amount".into(),
            query_hash: "h9".into(),
        }
    );
}

#[test]
fn r17_synthesize_numeric_claim_fails_closed_when_source_not_reproducible() {
    let rd = rederiver(&[]); // no ground truth registered anywhere
    let source = ClaimSource::Tool {
        call_id: "call_missing".into(),
    };

    let err = synthesize_numeric_claim("count", ValueClass::Exact, source.clone(), &rd)
        .expect_err("an unreproducible source must never synthesize a fabricated number");

    assert_eq!(err, NumericSynthesisError::SourceUnavailable(source));
}

#[test]
fn r17_synthesize_numeric_claims_batch_short_circuits_on_first_unavailable_source() {
    let rd = rederiver(&[("metric:a:h", 1.0)]); // "b" is deliberately missing
    let requests = vec![
        (
            "count".to_string(),
            ValueClass::Exact,
            ClaimSource::Metric {
                id: "a".into(),
                query_hash: "h".into(),
            },
        ),
        (
            "count".to_string(),
            ValueClass::Exact,
            ClaimSource::Metric {
                id: "b".into(),
                query_hash: "h".into(),
            },
        ),
    ];

    let err = synthesize_numeric_claims(requests, &rd).expect_err(
        "a turn must never ship an answer built from a partially-computed set of figures",
    );
    assert!(matches!(
        err,
        NumericSynthesisError::SourceUnavailable(ClaimSource::Metric { id, .. }) if id == "b"
    ));
}

#[test]
fn r17_render_numeric_claim_formats_by_value_class() {
    let currency = NumericClaim::metric(1234.5, "₹", ValueClass::Currency, "m", "h");
    assert_eq!(render_numeric_claim(&currency), "₹1234.50");

    let rate = NumericClaim::metric(3.256, "", ValueClass::Rate, "m", "h");
    assert_eq!(render_numeric_claim(&rate), "3.26%");

    let exact = NumericClaim::metric(47.0, "count", ValueClass::Exact, "m", "h");
    assert_eq!(render_numeric_claim(&exact), "47 count");
}

#[test]
fn r17_synthesized_claim_still_clears_the_existing_verify_gate_for_defense_in_depth() {
    // The GENERATED claim composes with the EXISTING verify-only machinery: a served turn
    // synthesizes the number, splices it into prose, and can still run the whole answer back
    // through `numeric_gate` — proving this is additive, not a parallel/competing numeric path.
    let rd = rederiver(&[("metric:failed_settlement_count:h1", 47.0)]);
    let source = ClaimSource::Metric {
        id: "failed_settlement_count".into(),
        query_hash: "h1".into(),
    };
    let claim =
        synthesize_numeric_claim("count", ValueClass::Exact, source, &rd).expect("synthesizes");
    let answer = format!(
        "There were {} failed settlements.",
        render_numeric_claim(&claim)
    );

    let outcome = numeric_gate(&answer, &[claim], &rd, &Tolerance::default());
    assert!(
        outcome.ships(),
        "a synthesized (not model-authored) claim must clear the same gate: {outcome:?}"
    );
}
