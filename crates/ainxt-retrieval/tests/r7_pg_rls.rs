// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-7: the **DB-native Postgres RLS seam** (`STRUCTURED_FEDERATED_RETRIEVAL.md` §3) — bind the
//! OBO-derived `SET LOCAL` session vars to a read-replica transaction and let native ROW LEVEL
//! SECURITY filter rows. INFRA-GATED: the live path needs a Postgres replica with the policies
//! installed, so it is exercised here against an in-memory [`RlsConnection`] that MIRRORS Postgres
//! RLS semantics (parse `SET LOCAL`, filter by the bound scope var). This proves the binding
//! contract + fail-closed refusal WITHOUT a live DB; the production `RlsConnection` impl wraps a
//! `tokio-postgres` replica connection (deferred to infra).
//!
//! Fail-before / pass-after: `PostgresRlsExecutor` / `RlsConnection` did not exist before this
//! round. The seam is a retrieval read-filter (shapes which rows a turn reads), never an admission
//! gate.

use ainxt_retrieval::acl::AccessContext;
use ainxt_retrieval::structured::{
    build_session_context, MetricCatalog, MetricDef, PostgresRlsExecutor, RlsConnection, RlsError,
    RlsExecutor, RlsPolicy, Row, SessionVarSource, StructuredPlan,
};
use ainxt_types::DataClass;
use std::collections::BTreeSet;

/// An in-memory connection that mirrors Postgres ROW LEVEL SECURITY: it holds the curated view's
/// rows and the RLS predicate (`scope_column = current_setting(scope_var)`), parses the `SET LOCAL`
/// statements the executor issues, and returns only the rows the bound var admits — exactly what a
/// real replica's RLS would do. `fail_conn` models a replica/connection error.
struct FakeReplica {
    rows: Vec<Row>,
    scope_column: String,
    scope_var: String,
    fail_conn: bool,
}

impl RlsConnection for FakeReplica {
    fn set_local_and_query(
        &self,
        set_local: &[String],
        _plan: &StructuredPlan,
    ) -> Option<Vec<Row>> {
        if self.fail_conn {
            return None; // replica error → fail-closed at the executor
        }
        // Parse `SET LOCAL <var> = '<value>'` to recover the bound scope var (as Postgres would read
        // it via current_setting). No binding for the scope var → RLS hides everything.
        let bound = set_local.iter().find_map(|stmt| {
            let rest = stmt.strip_prefix("SET LOCAL ")?;
            let (var, val) = rest.split_once(" = ")?;
            if var.trim() == self.scope_var {
                Some(val.trim().trim_matches('\'').to_string())
            } else {
                None
            }
        });
        let scope_value = match bound {
            Some(v) => v,
            None => return Some(Vec::new()),
        };
        let visible = self
            .rows
            .iter()
            .filter(|r| {
                r.iter()
                    .any(|(c, v)| c == &self.scope_column && v == &scope_value)
            })
            .cloned()
            .collect();
        Some(visible)
    }
}

fn settlement_catalog() -> MetricCatalog {
    let metric = MetricDef::new(
        "failed_settlement_count",
        "v_settlement_failures_curated",
        DataClass::Confidential,
    )
    .dimension("bank_id", DataClass::Internal)
    .rls("rls_settlement_by_dept");
    let mut policies = BTreeSet::new();
    policies.insert("rls_settlement_by_dept".to_string());
    MetricCatalog::load(vec![metric], &policies).unwrap()
}

fn rows() -> Vec<Row> {
    vec![
        vec![
            ("dept".into(), "settlement-eng".into()),
            ("count".into(), "12".into()),
        ],
        vec![
            ("dept".into(), "settlement-eng".into()),
            ("count".into(), "7".into()),
        ],
        vec![("dept".into(), "hr".into()), ("count".into(), "99".into())],
    ]
}

#[test]
fn r7_postgres_rls_executor_binds_set_local_and_row_filters() {
    let cat = settlement_catalog();
    let plan = cat.plan("failed_settlement_count", &["bank_id"]).unwrap();
    let policy =
        RlsPolicy::new("rls_settlement_by_dept").var("app.dept", SessionVarSource::Department);

    let replica = FakeReplica {
        rows: rows(),
        scope_column: "dept".into(),
        scope_var: "app.dept".into(),
        fail_conn: false,
    };
    let executor = PostgresRlsExecutor::new(replica);

    // A settlement-eng caller → SET LOCAL app.dept='settlement-eng' bound from the OBO context → only
    // that department's rows come back; the hr row never leaves the database.
    let ctx = AccessContext::new(DataClass::Confidential, Some("settlement-eng"), None, &[]);
    let session = build_session_context(&policy, &ctx, Some(500)).unwrap();
    let visible = executor.execute(&plan, &session).expect("rows");
    assert_eq!(
        visible.len(),
        2,
        "native RLS must hide the hr department's row"
    );
    assert!(visible
        .iter()
        .all(|r| r.iter().any(|(c, v)| c == "dept" && v == "settlement-eng")));
}

#[test]
fn r7_postgres_rls_executor_is_fail_closed() {
    let cat = settlement_catalog();
    let plan = cat.plan("failed_settlement_count", &["bank_id"]).unwrap();
    let policy =
        RlsPolicy::new("rls_settlement_by_dept").var("app.dept", SessionVarSource::Department);

    // (a) A caller with no department cannot source the SET LOCAL var → the query MUST abort before
    // any row is touched (never run RLS with an unset session var).
    let no_dept = AccessContext::new(DataClass::Confidential, None, None, &[]);
    assert!(matches!(
        build_session_context(&policy, &no_dept, None),
        Err(RlsError::MissingClaim { .. })
    ));

    // (b) A replica/connection error → the executor returns None (fail-closed), never a partial or
    // unscoped read.
    let broken = PostgresRlsExecutor::new(FakeReplica {
        rows: rows(),
        scope_column: "dept".into(),
        scope_var: "app.dept".into(),
        fail_conn: true,
    });
    let ctx = AccessContext::new(DataClass::Confidential, Some("settlement-eng"), None, &[]);
    let session = build_session_context(&policy, &ctx, None).unwrap();
    assert!(
        broken.execute(&plan, &session).is_none(),
        "a replica error fail-closes"
    );
}
