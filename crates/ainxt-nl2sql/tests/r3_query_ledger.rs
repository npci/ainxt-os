// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R3 DATA — integration coverage for the mount-ready `query_ledger` entrypoint.
//!
//! Gap: "Safe NL-to-SQL (query_ledger) not reachable in the running runtime." The pure compiler
//! (`validate_and_compile`) existed but had no single RBAC-scoped, serializable entrypoint a
//! transport route could mount. These tests drive the REAL `query_ledger` function end-to-end:
//! capability gate → clearance/structural validation → serializable `SafeQuery`.
//!
//! Fail-before/pass-after: `query_ledger` / `CAP_QUERY_LEDGER` / `QueryError::NotAuthorized` /
//! `SafeQuery: Serialize` did not exist before this change, so this test crate would not compile.

use ainxt_nl2sql::{
    query_ledger, Column, DataClass, Filter, Predicate, Principal, QueryError, QueryIntent, Schema,
    Table, Value, CAP_QUERY_LEDGER,
};

/// A ledger table spanning the clearance ladder — mirrors the design's payments-ledger surface.
fn ledger_schema() -> Schema {
    let table = Table::new(
        "ledger_entries",
        vec![
            Column::new("entry_id", DataClass::Internal).unwrap(),
            Column::new("amount_minor", DataClass::Confidential).unwrap(),
            Column::new("holder_pan", DataClass::Pii).unwrap(),
        ],
    )
    .unwrap();
    Schema::new(vec![table])
        .unwrap()
        .with_max_limit(100)
        .unwrap()
}

/// A principal cleared to see the sensitive column and holding the ledger capability.
fn cleared_analyst() -> Principal {
    Principal::user("analyst", &[CAP_QUERY_LEDGER]).with_clearance(DataClass::Pii)
}

#[test]
fn r3_query_ledger_denies_caller_without_capability() {
    let schema = ledger_schema();
    let intent = QueryIntent {
        select: vec!["entry_id".to_string()],
        from: "ledger_entries".to_string(),
        filters: vec![],
        order_by: vec![],
        limit: Some(10),
    };

    // No CAP_QUERY_LEDGER → refused BEFORE any schema/column is consulted.
    let unprivileged = Principal::user("intern", &[]).with_clearance(DataClass::Pii);
    assert_eq!(
        query_ledger(&intent, &schema, &unprivileged),
        Err(QueryError::NotAuthorized),
        "a caller without CAP_QUERY_LEDGER must be refused at the capability gate"
    );

    // The refusal discloses nothing about the schema: querying a non-existent table yields the SAME
    // NotAuthorized, not UnknownTable — the capability gate runs first.
    let bogus = QueryIntent {
        from: "does_not_exist".to_string(),
        ..intent.clone()
    };
    assert_eq!(
        query_ledger(&bogus, &schema, &unprivileged),
        Err(QueryError::NotAuthorized),
        "capability gate must precede schema resolution (no existence oracle over tables)"
    );

    // Admin holds every capability implicitly and passes the gate.
    let admin = Principal::admin("root");
    assert!(query_ledger(&intent, &schema, &admin).is_ok());
}

#[test]
fn r3_query_ledger_over_clearance_column_is_indistinguishable_from_unknown() {
    let schema = ledger_schema();
    // Authorized to reach the surface, but cleared only to Internal — cannot read the Pii column.
    let low = Principal::user("teller", &[CAP_QUERY_LEDGER]).with_clearance(DataClass::Internal);

    let over_clearance = QueryIntent {
        select: vec!["holder_pan".to_string()], // exists, but above clearance
        from: "ledger_entries".to_string(),
        filters: vec![],
        order_by: vec![],
        limit: None,
    };
    let unknown = QueryIntent {
        select: vec!["ssn_that_does_not_exist".to_string()], // truly absent
        from: "ledger_entries".to_string(),
        filters: vec![],
        order_by: vec![],
        limit: None,
    };

    let e_over = query_ledger(&over_clearance, &schema, &low).unwrap_err();
    let e_unknown = query_ledger(&unknown, &schema, &low).unwrap_err();

    // ADR-012: both collapse to the SAME variant — an under-cleared caller cannot tell "exists but
    // above my clearance" from "does not exist". The variant carries NO payload at all: the column
    // name is deliberately excluded from the error, so the refusal is byte-identical in both cases
    // and cannot be differenced by a caller probing for a column's existence.
    match (&e_over, &e_unknown) {
        (QueryError::ColumnNotAvailable, QueryError::ColumnNotAvailable) => {}
        other => panic!("both must be ColumnNotAvailable (no existence oracle), got {other:?}"),
    }
    // The strongest form of the property: the two rendered refusals are indistinguishable, and
    // neither one names the column that was probed.
    assert_eq!(
        e_over.to_string(),
        e_unknown.to_string(),
        "an over-clearance and an unknown column must render identically"
    );
    for e in [&e_over, &e_unknown] {
        let rendered = e.to_string();
        assert!(
            !rendered.contains("holder_pan") && !rendered.contains("ssn_that_does_not_exist"),
            "the refusal must not name the probed column: {rendered}"
        );
    }
    // Discriminant equality is the load-bearing property: same variant, no distinguishing signal.
    assert_eq!(
        std::mem::discriminant(&e_over),
        std::mem::discriminant(&e_unknown)
    );
}

#[test]
fn r3_query_ledger_compiles_parameterized_bounded_and_serializes() {
    let schema = ledger_schema();
    let analyst = cleared_analyst();

    let intent = QueryIntent {
        select: vec!["entry_id".to_string(), "amount_minor".to_string()],
        from: "ledger_entries".to_string(),
        filters: vec![Filter {
            column: "amount_minor".to_string(),
            predicate: Predicate::Gt(Value::Int(500)),
        }],
        order_by: vec![],
        limit: Some(9999), // above the ceiling → must clamp
    };

    let q = query_ledger(&intent, &schema, &analyst).expect("valid query must compile");

    // Structurally injection-proof: SELECT-only, value carried as a $n placeholder, no `;`.
    assert!(q.sql.starts_with("SELECT "), "sql = {}", q.sql);
    assert!(
        q.sql.contains("$1"),
        "filter value must be a placeholder: {}",
        q.sql
    );
    assert!(
        !q.sql.contains(';'),
        "statement stacking impossible: {}",
        q.sql
    );
    assert_eq!(q.params, vec![Value::Int(500)]);

    // Forced bounded LIMIT — the oversized request was clamped to the schema ceiling.
    assert_eq!(q.limit_applied, 100);
    assert!(q.limit_was_clamped);
    assert!(q.sql.ends_with("LIMIT 100"));

    // Mount-readiness: the SafeQuery serializes so a transport can return it verbatim.
    let json = serde_json::to_value(&q).expect("SafeQuery must be Serialize for the wire");
    assert_eq!(json["limit_applied"], serde_json::json!(100));
    assert_eq!(json["sql"], serde_json::Value::String(q.sql.clone()));
}
