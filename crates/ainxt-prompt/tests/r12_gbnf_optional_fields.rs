// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R12 (Prompt Engineering, §4) — the GBNF grammar FAITHFULLY represents optional fields. The earlier
//! grammar chained every field as required and so forced an absent optional field to appear (a grammar
//! the schema itself rejects). Now required fields form the mandatory core and each optional field is
//! an omittable `( "," ws kv )?` group.
//!
//! FAIL-BEFORE: the grammar chained ALL fields comma-separated as required (the omittable-group asserts
//! fail). PASS-AFTER: green. Offline + deterministic.

use ainxt_prompt::constrained::{FieldType, JsonSchema, StructuredOutputKind};

#[test]
fn r12_optional_field_is_an_omittable_group_required_is_mandatory() {
    // BTreeMap orders keys: id (idx 0, required), note (idx 1, optional).
    let s = JsonSchema::object([
        ("id", FieldType::String, true),
        ("note", FieldType::String, false),
    ]);
    let g = s.to_gbnf();
    // The root's mandatory core is exactly the required field; the optional is an omittable group.
    assert!(
        g.contains(r#"root ::= "{" ws kv-0 ( "," ws kv-1 )? ws "}""#),
        "optional field must be omittable; got:\n{g}"
    );
    // Deterministic (replay) + every field still constrained.
    assert_eq!(g, s.to_gbnf());
    assert!(g.contains("kv-0 ::=") && g.contains("kv-1 ::="));
    for f in ["id", "note"] {
        assert!(g.contains(f));
    }
}

#[test]
fn r12_all_optional_schema_makes_the_whole_member_list_omittable() {
    let s = JsonSchema::object([
        ("a", FieldType::String, false),
        ("b", FieldType::Integer, false),
    ]);
    let g = s.to_gbnf();
    // With NO required fields, the entire member list is optional (an empty object is valid).
    assert!(
        g.contains(r#"root ::= "{" ws members? ws "}""#),
        "got:\n{g}"
    );
    assert!(g.contains("members ::= member"));
    assert!(g.contains("member ::= kv-0 | kv-1"));
}

#[test]
fn r12_catalog_intent_optional_clarify_is_represented_faithfully() {
    // The catalog's IntentClassification carries a genuinely optional `clarify` field.
    let s = StructuredOutputKind::IntentClassification.schema();
    let g = s.to_gbnf();
    // ordered: clarify(0, optional), confidence(1, required), intent(2, required).
    // Required core = confidence, intent; clarify is the omittable group.
    assert!(
        g.contains("( \",\" ws kv-0 )?"),
        "optional clarify must be omittable; got:\n{g}"
    );
    // A valid object WITHOUT the optional field passes validation (proves it is truly optional).
    assert!(s.validate(r#"{"intent":"qa","confidence":0.9}"#).is_ok());
    assert!(s
        .validate(r#"{"intent":"clarify","confidence":0.4,"clarify":"which repo?"}"#)
        .is_ok());
}
