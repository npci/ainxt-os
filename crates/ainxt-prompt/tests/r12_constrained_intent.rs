// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R12 (Prompt Engineering, §4 / PE3) — constrained decoding is GENERALIZED to EVERY structured-output
//! prompt, now including the original **intent-classification** call site (§4 "not just intent
//! classification"). Intent goes through the same grammar-attach + validate + bounded-repair guarantee
//! as tool-args / Role Spec / judge verdict / doc-gen payload.
//!
//! FAIL-BEFORE: `StructuredOutputKind::IntentClassification` did not exist (won't compile). PASS-AFTER:
//! green. Offline + deterministic.

use ainxt_prompt::constrained::{
    ConstrainedDecoder, DecodeError, DecodeMethod, JsonSchema, NeverCancel, StructuredOutputEngine,
    StructuredOutputKind,
};

struct WeakIntentModel;
impl ConstrainedDecoder for WeakIntentModel {
    fn grammar_native(&self) -> bool {
        false
    }
    fn decode(&self, prompt: &str, _g: Option<&str>) -> Result<String, DecodeError> {
        if prompt.contains("was invalid") {
            Ok(r#"{"intent":"qa","confidence":0.8}"#.to_string())
        } else {
            Ok("It's probably a question? {intent: qa}".to_string())
        }
    }
}

#[test]
fn r12_intent_classification_is_in_the_catalog_and_100pct_valid() {
    assert!(
        StructuredOutputKind::all().contains(&StructuredOutputKind::IntentClassification),
        "intent classification must be a catalog call site"
    );
    let schema: JsonSchema = StructuredOutputKind::IntentClassification.schema();
    let engine = StructuredOutputEngine::default();
    // 100 consecutive weak-model calls → 100 schema-valid intent verdicts via the bounded repair loop.
    for _ in 0..100 {
        let out = engine
            .generate(&WeakIntentModel, &schema, "classify the turn", &NeverCancel)
            .expect("intent must repair to a valid object");
        assert_eq!(out.method, DecodeMethod::Repaired { repairs: 1 });
        assert!(schema.validate(&out.raw).is_ok());
    }
    // The intent enum is a CLOSED set: an off-vocabulary intent is rejected, never passed downstream.
    assert!(schema
        .validate(r#"{"intent":"delete-everything","confidence":1.0}"#)
        .is_err());
}
