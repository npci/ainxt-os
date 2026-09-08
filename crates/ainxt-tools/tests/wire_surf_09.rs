// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! SURF-09 wiring test: the safe NL-to-SQL boundary (`ainxt_nl2sql`) is reachable on the live tool
//! path as the `query_ledger` capability. This test constructs the REAL [`LedgerQueryTool`] (a real
//! startup [`ainxt_nl2sql::Schema`] allowlist) and a REAL [`ainxt_nl2sql::Principal`], and asserts the
//! full model→JSON→QueryIntent→validate_and_compile flow end-to-end:
//!   * a valid proposal compiles to bounded, parameterized SQL scoped to the caller;
//!   * a raw-SQL smuggle (an extra JSON field) is rejected by `deny_unknown_fields`;
//!   * an over-clearance column is hidden without leaking its existence (ADR-012);
//!   * the capability registers into a real [`ToolRuntime`] and appears in the function-calling
//!     manifest, and its `execute` fails CLOSED (a ledger query cannot run without a principal).
//!
//! Before the wire, `ainxt_tools::ledger_query` did not exist and `ainxt-nl2sql` was not a dependency,
//! so this file would not compile — it fails before the wire and passes after.

use ainxt_nl2sql::{DataClass, Principal, Value};
use ainxt_tools::ledger_query::{LedgerQueryError, LedgerQueryTool, QUERY_LEDGER};
use ainxt_tools::{DispatchResult, InMemoryLedger, ManualReconciler, ToolRuntime};

fn analyst() -> Principal {
    // Confidential clearance: may read entry_id (Internal) + amount_minor (Confidential); NOT the
    // RegulatedPayment / Pii columns. Department carried for native-DB RLS settings.
    Principal::user("analyst-1", &[])
        .with_clearance(DataClass::Confidential)
        .with_department("settlement-ops")
}

#[test]
fn wire_surf_09() {
    let tool = LedgerQueryTool::default_ledger();
    let analyst = analyst();

    // --- (1) a valid proposal compiles + scopes ---------------------------------------------
    let proposal = r#"{
        "select": ["entry_id", "amount_minor"],
        "from": "ledger_entries",
        "filters": [{"column": "amount_minor", "predicate": {"ge": {"int": 1000}}}],
        "order_by": [{"column": "amount_minor", "direction": "desc"}],
        "limit": 50
    }"#;
    let q = tool
        .compile(proposal, &analyst)
        .expect("valid proposal must compile");
    assert!(q.sql.starts_with("SELECT "), "sql: {}", q.sql);
    // Structurally injection-proof: no caller value interpolated, no statement stacking.
    assert!(!q.sql.contains(';'), "no statement separator: {}", q.sql);
    assert!(
        !q.sql.contains("1000"),
        "value must be a placeholder, not interpolated: {}",
        q.sql
    );
    assert!(q.sql.contains("$1"), "parameterized: {}", q.sql);
    assert_eq!(q.params, vec![Value::Int(1000)]);
    // Bounded by the schema ceiling.
    assert!(q.limit_applied <= 500 && q.limit_applied >= 1);
    // Native-DB RLS carries the caller identity out-of-band (never in SQL text).
    assert!(
        q.settings
            .iter()
            .any(|s| matches!(&s.value, Value::Text(v) if v == "analyst-1")),
        "settings must carry the caller user_id for RLS: {:?}",
        q.settings
    );

    // --- (2) raw-SQL smuggle is rejected by deny_unknown_fields ------------------------------
    let smuggle = r#"{
        "select": ["entry_id"],
        "from": "ledger_entries",
        "raw_sql": "DROP TABLE ledger_entries"
    }"#;
    match tool.compile(smuggle, &analyst) {
        Err(LedgerQueryError::MalformedProposal(_)) => {}
        other => panic!("a raw-SQL smuggle must be rejected at deserialization, got {other:?}"),
    }

    // --- (3) an over-clearance column is hidden (no existence oracle, ADR-012) ---------------
    let over = r#"{
        "select": ["counterparty_acct"],
        "from": "ledger_entries"
    }"#;
    let err = tool
        .compile(over, &analyst)
        .expect_err("a RegulatedPayment column is above a Confidential analyst's clearance");
    // Same variant an UNKNOWN column would yield — the two are indistinguishable on purpose.
    // `ColumnNotAvailable` is a UNIT variant: the column name is deliberately excluded from the
    // error payload entirely (see the variant's own note in `ainxt-nl2sql`), so there is nothing
    // to unpack here and nothing that could leak downstream into a 403 body or a log line.
    match err {
        LedgerQueryError::Rejected(ainxt_nl2sql::QueryError::ColumnNotAvailable) => {}
        other => panic!("expected ColumnNotAvailable (no leak), got {other:?}"),
    }
    // The rendered refusal must not name the column the caller probed for.
    assert!(
        !err.to_string().contains("counterparty_acct"),
        "the refusal must not echo the probed column name: {err}"
    );
    // Proof of no existence oracle: a genuinely NON-EXISTENT column yields the SAME error variant.
    let ghost = r#"{"select": ["does_not_exist"], "from": "ledger_entries"}"#;
    assert!(matches!(
        tool.compile(ghost, &analyst),
        Err(LedgerQueryError::Rejected(
            ainxt_nl2sql::QueryError::ColumnNotAvailable
        ))
    ));

    // --- (4) registers into the real runtime + appears in the manifest; execute fails closed --
    let mut rt = ToolRuntime::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler));
    rt.register(Box::new(LedgerQueryTool::default_ledger()));
    assert!(
        rt.schemas().iter().any(|s| s.name == QUERY_LEDGER),
        "query_ledger must appear in the function-calling manifest"
    );
    // A principal-less dispatch cannot enforce clearance → fail closed, never an unscoped query.
    match rt.dispatch(QUERY_LEDGER, proposal) {
        DispatchResult::Failed(m) => assert!(
            m.contains("principal-scoped") || m.contains("clearance"),
            "unexpected failure reason: {m}"
        ),
        other => panic!("execute must fail closed without a principal, got {other:?}"),
    }
}
