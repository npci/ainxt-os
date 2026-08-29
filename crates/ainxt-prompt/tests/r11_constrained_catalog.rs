// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R11 (Prompt Engineering, §4 / PE3) — constrained/grammar decoding is GENERALIZED to EVERY
//! structured-output call site (tool-call args, Role Spec, judge verdict, doc-gen payload), not just
//! intent classification. Every kind in the catalog:
//!   * compiles to a deterministic GBNF grammar that mentions each of its fields (replayable), and
//!   * yields a schema-valid object 100% of the time on a WEAK model via the bounded repair loop.
//!
//! FAIL-BEFORE: `StructuredOutputKind` / the catalog did not exist (won't compile). PASS-AFTER: green.
//! Offline + deterministic (no infra).

use ainxt_prompt::constrained::{
    ConstrainedDecoder, DecodeError, DecodeMethod, FieldType, JsonSchema, NeverCancel,
    StructuredOutputEngine, StructuredOutputKind,
};

/// Build a schema-valid JSON object for `schema` (required fields, typed placeholders). Used by the
/// weak-model fake to prove the repair loop can always land a valid object once told the exact error.
fn valid_json_for(schema: &JsonSchema) -> String {
    let mut parts: Vec<String> = Vec::new();
    for name in &schema.required {
        let spec = &schema.fields[name];
        let value = match &spec.ty {
            FieldType::String => "\"x\"".to_string(),
            FieldType::Integer => "72".to_string(),
            FieldType::Number => "0.9".to_string(),
            FieldType::Boolean => "true".to_string(),
            FieldType::Enum(vals) => format!("\"{}\"", vals[0]),
        };
        parts.push(format!("\"{name}\":{value}"));
    }
    format!("{{{}}}", parts.join(","))
}

/// A weak self-hosted model: emits prose on the first (no-error) prompt, then a schema-valid object
/// once the prompt carries a repair error ("was invalid"). Holds the target schema so it can build a
/// valid object generically for any catalog kind.
struct WeakModel {
    schema: JsonSchema,
}
impl ConstrainedDecoder for WeakModel {
    fn grammar_native(&self) -> bool {
        false
    }
    fn decode(&self, prompt: &str, _g: Option<&str>) -> Result<String, DecodeError> {
        if prompt.contains("was invalid") {
            Ok(valid_json_for(&self.schema))
        } else {
            Ok("Sure, here you go: not-json".to_string())
        }
    }
}

#[test]
fn r11_catalog_grammar_is_deterministic_and_covers_every_field() {
    for kind in StructuredOutputKind::all() {
        let schema = kind.schema();
        let g1 = schema.to_gbnf();
        let g2 = schema.to_gbnf();
        assert_eq!(g1, g2, "{kind:?} grammar must be deterministic for replay");
        assert!(g1.contains("root ::="));
        for field in schema.fields.keys() {
            assert!(
                g1.contains(field.as_str()),
                "{kind:?} grammar must constrain field {field}"
            );
        }
    }
}

#[test]
fn r11_catalog_schemas_validate_good_and_reject_off_schema() {
    for kind in StructuredOutputKind::all() {
        let schema = kind.schema();
        // A generated valid object passes.
        let good = valid_json_for(&schema);
        assert!(
            schema.validate(&good).is_ok(),
            "{kind:?} must accept a well-formed object, got err on {good}"
        );
        // An empty object misses required fields → rejected (fail-closed, never passed downstream).
        assert!(
            schema.validate("{}").is_err(),
            "{kind:?} must reject an object missing required fields"
        );
        // A blatantly non-JSON blob is rejected.
        assert!(schema.validate("sorry i cannot").is_err());
    }
}

#[test]
fn r11_every_structured_output_kind_is_100pct_valid_on_a_weak_model() {
    let engine = StructuredOutputEngine::default();
    for kind in StructuredOutputKind::all() {
        let schema = kind.schema();
        let model = WeakModel {
            schema: schema.clone(),
        };
        // 50 consecutive weak-model calls → 50 schema-valid objects for EACH call site, zero failures.
        for _ in 0..50 {
            let out = engine
                .generate(&model, &schema, "produce the object", &NeverCancel)
                .unwrap_or_else(|e| panic!("{kind:?} must repair to a valid object: {e}"));
            assert_eq!(out.method, DecodeMethod::Repaired { repairs: 1 });
            assert!(
                schema.validate(&out.raw).is_ok(),
                "{kind:?}: every structured output must be schema-valid"
            );
        }
    }
}
