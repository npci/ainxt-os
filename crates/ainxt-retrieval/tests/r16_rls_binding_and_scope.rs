// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-16 CRITICALs for `context-fabric` / structured retrieval.
//!
//! **C1 — the RLS `SET LOCAL` binding is not forgeable.** `STRUCTURED_FEDERATED_RETRIEVAL.md` §3.2:
//! the runtime issues `SET LOCAL app.scoped_* = <from OBO context>` inside the same transaction and
//! the *database* refuses out-of-scope rows. That binding statement was previously built with
//! `format!("SET LOCAL {k} = '{v}'")` — the OBO department/ad_level interpolated with **no quoting
//! or escaping**, and consumed verbatim by the production `RlsConnection` seam. A department value
//! carrying a single quote could therefore terminate the literal and append arbitrary SQL to the
//! very statement whose whole job is to make the row scope un-forgeable.
//!
//! Fail-before: with the old renderer,
//! `department = "ops'; SET LOCAL app.dept = 'finance"` renders
//! `SET LOCAL app.dept = 'ops'; SET LOCAL app.dept = 'finance'` — two statements, the second of
//! which rebinds the scope to a department the caller does not belong to. Pass-after: it renders as
//! ONE statement whose value is a correctly-quoted literal, and the parameterized
//! `SELECT set_config($1,$2,true)` form carries the value as a bound parameter with zero SQL-text
//! interpolation.
//!
//! **C2 — a metric cannot silently widen its own row scope.** §2.2.2 ("a metric with no enforceable
//! row-level security cannot load") + §3.2. `compile_structured_query` never read
//! `plan.rls_predicate_ref`: row scoping came only from the `Schema` the caller supplied
//! independently, so a metric declaring `rls_settlement_by_dept` could compile a completely
//! unscoped `SELECT` over settlement data. Now the metric declares the row scope its policy
//! enforces, the compiler cross-checks that declaration against the row scope it actually emits,
//! and any disagreement (absent scope, different column, different principal attribute) refuses the
//! compile before any DB access.
//!
//! Both are retrieval READ-FILTER concerns (which rows a turn may read), never turn admission.

use ainxt_nl2sql::{Column, PrincipalAttr, RowScope, Schema, Table};
use ainxt_retrieval::acl::AccessContext;
use ainxt_retrieval::structured::{
    build_session_context, is_valid_session_var_name, quote_pg_literal, CatalogFile,
    CatalogLoadError, MetricCatalog, MetricDef, PostgresRlsExecutor, RlsConnection, RlsExecutor,
    RlsPolicy, RlsScopeBinding, Row, ScopeAttr, SessionContext, SessionVarSource, SetConfigBinding,
    StructuredPlan,
};
use ainxt_retrieval::structured_pipeline::{
    compile_structured_query, Aggregation, PipelineError, RlsScopeAttestation, ServerSideRederiver,
};
use ainxt_synthesis::rederive::{ClaimSource, Rederiver};
use ainxt_types::{DataClass, Principal};
use std::cell::RefCell;
use std::collections::BTreeSet;

// ---------------------------------------------------------------------------------------
// C1 — un-forgeable SET LOCAL binding
// ---------------------------------------------------------------------------------------

/// Adversarial OBO values. Each is a *legitimate string* as far as the runtime knows (it comes from
/// the AD department claim), so the binding must ESCAPE it — refusing would be a hard block on a
/// legitimately-punctuated org unit, which the redact-and-proceed posture forbids.
fn injection_payloads() -> Vec<(&'static str, &'static str)> {
    vec![
        ("statement-append", "ops'; SET LOCAL app.dept = 'finance"),
        ("drop-table", "x'; DROP TABLE settlements; --"),
        ("quote-only", "O'Brien"),
        ("double-quote-escape", "a''b"),
        ("backslash", "dept\\'; SET LOCAL app.dept = 'all"),
        ("backslash-only", "back\\slash"),
        ("newline", "ops'\nSET LOCAL app.dept = 'finance"),
        ("crlf", "ops'\r\nSET LOCAL app.dept = 'finance"),
        ("comment", "ops' /* */ OR '1'='1"),
        ("unicode", "settlement-\u{00e9}ng\u{200b}"),
        (
            "unicode-fullwidth-quote",
            "ops\u{ff07}; SET LOCAL app.dept = 'x",
        ),
        ("dollar-quote", "$$ops$$"),
        ("semicolon", "ops;finance"),
    ]
}

/// A `SET LOCAL <name> = <literal>` statement is well-formed iff the literal is balanced: outside
/// the literal there is exactly one statement and nothing after the closing quote. This is a
/// deliberately independent parser (not the crate's own renderer) so it can catch a forged
/// statement the renderer thinks is fine.
fn parse_single_set_local(stmt: &str) -> Option<(String, String)> {
    let rest = stmt.strip_prefix("SET LOCAL ")?;
    let (name, value_part) = rest.split_once(" = ")?;
    let (body, e_string) = match value_part.strip_prefix("E'") {
        Some(b) => (b, true),
        None => (value_part.strip_prefix('\'')?, false),
    };
    let mut out = String::new();
    let mut chars = body.chars().peekable();
    let mut closed = false;
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                if chars.peek() == Some(&'\'') {
                    chars.next();
                    out.push('\'');
                } else {
                    closed = true;
                    break;
                }
            }
            '\\' if e_string => {
                // In an E-string a backslash escapes the next character.
                let n = chars.next()?;
                out.push(n);
            }
            c => out.push(c),
        }
    }
    if !closed {
        return None; // unterminated literal
    }
    if chars.next().is_some() {
        return None; // trailing text AFTER the literal — a forged/appended statement
    }
    Some((name.to_string(), out))
}

#[test]
fn r16_rls_set_local_binding_is_not_forgeable() {
    for (label, payload) in injection_payloads() {
        let policy =
            RlsPolicy::new("rls_settlement_by_dept").var("app.dept", SessionVarSource::Department);
        let ctx = AccessContext::new(DataClass::Confidential, Some(payload), None, &[]);
        let session = build_session_context(&policy, &ctx, None).unwrap_or_else(|e| {
            panic!("{label}: a punctuated department must bind, not block: {e:?}")
        });

        let statements = session.set_local_statements_checked().expect("binds");
        assert_eq!(
            statements.len(),
            1,
            "{label}: exactly one statement per session var"
        );

        // The rendered statement must parse as ONE well-formed `SET LOCAL` whose value round-trips
        // to the ORIGINAL payload — no escape, no appended statement, no truncation.
        let (name, value) = parse_single_set_local(&statements[0])
            .unwrap_or_else(|| panic!("{label}: forged/unbalanced statement: {}", statements[0]));
        assert_eq!(name, "app.dept", "{label}");
        assert_eq!(
            value, payload,
            "{label}: the literal must round-trip verbatim"
        );

        // NOTE: do *not* "belt and braces" this by counting `';` substrings. A correctly escaped
        // literal doubles an embedded quote, so the payload `ops'; DROP ...` renders as
        // `'ops''; DROP ...'` — which legitimately contains `';` as the second half of the escaped
        // pair followed by the payload's own semicolon. Counting substrings flags that as an
        // injection when it is the *correct* output. `parse_single_set_local` above is the strictly
        // stronger check: it walks the literal, treats `''` as one escaped quote, and returns None
        // on an unterminated literal or ANY trailing text after it — i.e. it fails precisely when a
        // second statement really was appended.

        // The PARAMETERIZED form carries the value as a bound parameter — constant SQL text, so
        // there is nothing for the payload to escape from at all.
        let bindings = session.bindings().expect("binds");
        assert_eq!(bindings.len(), 1);
        assert_eq!(
            SetConfigBinding::SET_CONFIG_SQL,
            "SELECT set_config($1, $2, true)",
            "{label}: the statement text must be constant"
        );
        assert_eq!(bindings[0].params(), ["app.dept", payload], "{label}");
        assert!(
            !SetConfigBinding::SET_CONFIG_SQL.contains(payload),
            "{label}: no caller value may appear in the SQL text"
        );
    }
}

#[test]
fn r16_rls_session_var_names_are_allowlisted_and_bad_bindings_fail_closed() {
    // Legal, safe custom-GUC names.
    for good in ["app.dept", "app.scoped_bank_id", "_ns.k1"] {
        assert!(is_valid_session_var_name(good), "{good} must be accepted");
    }
    // Anything that could break out of `SET LOCAL <name> = ...` (a GUC name cannot be a bound
    // parameter, so it is allow-listed by shape, not escaped).
    for bad in [
        "app.dept; DROP TABLE settlements",
        "app.dept = 'x'; SET LOCAL y",
        "app dept",
        "dept",            // un-namespaced: Postgres rejects an unknown bare parameter
        "app.dept.extra",  // more than one dot
        "APP.DEPT",        // case-folding trick
        "app.\u{0435}ept", // Cyrillic homoglyph
        "app.'dept'",
        "",
        "app.",
        ".dept",
    ] {
        assert!(!is_valid_session_var_name(bad), "{bad:?} must be refused");
        assert!(
            SetConfigBinding::new(bad, "ops").is_err(),
            "{bad:?} must not produce a binding"
        );
    }

    // A NUL byte cannot be a Postgres text value at all → fail-closed, never a truncated literal.
    assert!(quote_pg_literal("ops\0finance").is_err());

    // An unbindable session context refuses the QUERY (fail-closed), rather than running it
    // unscoped or emitting a forged statement.
    struct Spy(RefCell<Vec<String>>);
    impl RlsConnection for Spy {
        fn set_local_and_query(
            &self,
            set_local: &[String],
            _p: &StructuredPlan,
        ) -> Option<Vec<Row>> {
            self.0.borrow_mut().extend(set_local.iter().cloned());
            Some(Vec::new())
        }
    }
    let plan = StructuredPlan {
        metric_id: "failed_settlement_count".into(),
        source_view: "v_settlement_failures_curated".into(),
        group_by: vec![],
        data_class_ceiling: DataClass::Confidential,
        rls_predicate_ref: Some("rls_settlement_by_dept".into()),
        rls_scope: vec![RlsScopeBinding::new("owner_dept", ScopeAttr::Department)],
        freshness_sla_seconds: 300,
    };
    let exec = PostgresRlsExecutor::new(Spy(RefCell::new(Vec::new())));
    let forged = SessionContext {
        settings: vec![("app.dept; SET LOCAL app.role = 'admin".into(), "ops".into())],
        stale_as_of: None,
    };
    assert!(
        exec.execute(&plan, &forged).is_none(),
        "an illegal session-var name must refuse the query, never be interpolated"
    );
    assert!(
        forged.set_local_statements().is_empty(),
        "an unbindable context renders NO statements (never a partial binding)"
    );
}

#[test]
fn r16_rls_executor_binds_the_escaped_value_the_database_sees() {
    // End-to-end through the production seam: a department carrying a quote must still scope rows
    // to EXACTLY that department — the escaped literal is what the database compares against.
    struct Replica {
        rows: Vec<Row>,
    }
    impl RlsConnection for Replica {
        fn set_local_and_query(
            &self,
            set_local: &[String],
            _p: &StructuredPlan,
        ) -> Option<Vec<Row>> {
            // Mirror Postgres: parse the literal the way the server would, then apply the policy.
            let bound = set_local
                .iter()
                .find_map(|s| parse_single_set_local(s).filter(|(n, _)| n == "app.dept"))
                .map(|(_, v)| v)?;
            Some(
                self.rows
                    .iter()
                    .filter(|r| r.iter().any(|(c, v)| c == "dept" && *v == bound))
                    .cloned()
                    .collect(),
            )
        }
    }
    let rows = vec![
        vec![
            ("dept".to_string(), "O'Brien-ops".to_string()),
            ("n".to_string(), "1".to_string()),
        ],
        vec![
            ("dept".to_string(), "finance".to_string()),
            ("n".to_string(), "2".to_string()),
        ],
        vec![
            ("dept".to_string(), "O'Brien-ops".to_string()),
            ("n".to_string(), "3".to_string()),
        ],
    ];
    let plan = StructuredPlan {
        metric_id: "failed_settlement_count".into(),
        source_view: "v_settlement_failures_curated".into(),
        group_by: vec![],
        data_class_ceiling: DataClass::Confidential,
        rls_predicate_ref: Some("rls_settlement_by_dept".into()),
        rls_scope: vec![RlsScopeBinding::new("owner_dept", ScopeAttr::Department)],
        freshness_sla_seconds: 300,
    };
    let policy =
        RlsPolicy::new("rls_settlement_by_dept").var("app.dept", SessionVarSource::Department);
    let ctx = AccessContext::new(DataClass::Confidential, Some("O'Brien-ops"), None, &[]);
    let session = build_session_context(&policy, &ctx, None).unwrap();
    let exec = PostgresRlsExecutor::new(Replica { rows });
    let visible = exec.execute(&plan, &session).expect("rows");
    assert_eq!(
        visible.len(),
        2,
        "only the caller's own (quoted) department's rows"
    );
    assert!(visible
        .iter()
        .all(|r| r.iter().any(|(c, v)| c == "dept" && v == "O'Brien-ops")));
}

// ---------------------------------------------------------------------------------------
// C2 — metric-declared RLS policy vs the compiled query's row scope
// ---------------------------------------------------------------------------------------

fn rls_set() -> BTreeSet<String> {
    ["rls_settlement_by_dept".to_string()].into_iter().collect()
}

/// The correct, git-reviewed shape: the metric declares BOTH the policy and the row scope it
/// enforces.
fn declared_metric() -> MetricDef {
    MetricDef::new(
        "failed_settlement_count",
        "v_settlement_failures_curated",
        DataClass::Confidential,
    )
    .dimension("bank_id", DataClass::Internal)
    .rls("rls_settlement_by_dept")
    .rls_scope("owner_dept", ScopeAttr::Department)
}

fn catalog_of(m: MetricDef) -> MetricCatalog {
    MetricCatalog::load(vec![m], &rls_set()).unwrap()
}

/// A schema for the curated view with the caller-chosen row scopes.
fn view_schema(scopes: Vec<RowScope>) -> Schema {
    let table = Table::new_scoped(
        "v_settlement_failures_curated",
        vec![
            Column::new("bank_id", DataClass::Internal).unwrap(),
            Column::new("owner_dept", DataClass::Internal).unwrap(),
            Column::new("owner_user", DataClass::Internal).unwrap(),
        ],
        scopes,
    )
    .unwrap();
    Schema::new(vec![table]).unwrap()
}

fn analyst() -> Principal {
    Principal::user("analyst", &[])
        .with_clearance(DataClass::Confidential)
        .with_department("settlement-eng")
}

fn compile_with(
    schema: &Schema,
) -> Result<ainxt_retrieval::structured_pipeline::CompiledStructuredQuery, PipelineError> {
    compile_structured_query(
        &catalog_of(declared_metric()),
        "failed_settlement_count",
        &["bank_id"],
        &[],
        Aggregation::Count,
        schema,
        &analyst(),
    )
}

#[test]
fn r16_metric_rls_policy_must_match_compiled_row_scope() {
    // (a) THE CRITICAL: the metric declares a dept-scoped RLS policy, but the schema it is compiled
    // against declares NO row scope — the emitted SELECT would be unscoped over settlement data.
    // Fails before this round (it compiled happily); refused now, before any DB access.
    let err = compile_with(&view_schema(vec![])).unwrap_err();
    match &err {
        PipelineError::RlsScopeMismatch {
            metric,
            policy,
            declared,
            compiled,
        } => {
            assert_eq!(metric, "failed_settlement_count");
            assert_eq!(policy, "rls_settlement_by_dept");
            assert_eq!(
                declared,
                &vec![RlsScopeBinding::new("owner_dept", ScopeAttr::Department)]
            );
            assert!(
                compiled.is_empty(),
                "the compiled query carried no row scope at all"
            );
        }
        other => panic!("expected an RLS scope mismatch, got {other:?}"),
    }

    // (b) Widened scope: scoped on a DIFFERENT column than the policy enforces (every row of the
    // caller's own bank rather than of the caller's own department).
    let widened = view_schema(vec![RowScope::new("bank_id", PrincipalAttr::Department)]);
    assert!(matches!(
        compile_with(&widened).unwrap_err(),
        PipelineError::RlsScopeMismatch { .. }
    ));

    // (c) Same column, DIFFERENT principal attribute — the policy says "the caller's department",
    // the compiled query says "the caller's user id".
    let wrong_attr = view_schema(vec![RowScope::new("owner_dept", PrincipalAttr::UserId)]);
    assert!(matches!(
        compile_with(&wrong_attr).unwrap_err(),
        PipelineError::RlsScopeMismatch { .. }
    ));

    // (d) An EXTRA scope beyond the declaration is also a disagreement — the declaration is the
    // reviewed contract, and drift in either direction must be visible at review time.
    let extra = view_schema(vec![
        RowScope::new("owner_dept", PrincipalAttr::Department),
        RowScope::new("owner_user", PrincipalAttr::UserId),
    ]);
    assert!(matches!(
        compile_with(&extra).unwrap_err(),
        PipelineError::RlsScopeMismatch { .. }
    ));

    // (e) Agreement: the compiled query really is row-scoped the way the policy promises, the SQL
    // carries the injected predicate, and the compiled query is stamped Verified.
    let ok = compile_with(&view_schema(vec![RowScope::new(
        "owner_dept",
        PrincipalAttr::Department,
    )]))
    .expect("a correctly-scoped metric compiles");
    assert!(ok.query.sql.starts_with("SELECT "));
    assert!(
        ok.query.sql.contains("\"owner_dept\" = $1"),
        "the row-scope predicate must be in the compiled SQL: {}",
        ok.query.sql
    );
    assert_eq!(
        ok.rls_scope,
        RlsScopeAttestation::Verified {
            policy: "rls_settlement_by_dept".to_string(),
            scopes: vec![RlsScopeBinding::new("owner_dept", ScopeAttr::Department)],
        }
    );
}

#[test]
fn r16_control_plane_refuses_a_metric_whose_rls_is_not_enforceable() {
    let mut views = BTreeSet::new();
    views.insert("v_settlement_failures_curated".to_string());

    // A definition naming an RLS policy but declaring NO row scope: nothing could cross-check the
    // compiled query against it, so §2.2.2 refuses the WHOLE load (all-or-nothing).
    let policy_only = serde_json::to_string(
        &MetricDef::new(
            "failed_settlement_count",
            "v_settlement_failures_curated",
            DataClass::Confidential,
        )
        .dimension("bank_id", DataClass::Internal)
        .rls("rls_settlement_by_dept"),
    )
    .unwrap();
    let files = vec![CatalogFile {
        dir_id: "failed_settlement_count",
        json: &policy_only,
    }];
    assert!(matches!(
        ainxt_retrieval::structured::load_metrics_from_files(&files, None, &rls_set(), &views)
            .unwrap_err(),
        CatalogLoadError::RlsPolicyWithoutScope { .. }
    ));

    // The mirror-image drift: a row scope with no policy to enforce it is an unenforced comment.
    let mut scope_only: MetricDef = serde_json::from_str(&policy_only).unwrap();
    scope_only.rls_predicate_ref = None;
    scope_only.rls_scope = vec![RlsScopeBinding::new("owner_dept", ScopeAttr::Department)];
    let scope_only_json = serde_json::to_string(&scope_only).unwrap();
    let files = vec![CatalogFile {
        dir_id: "failed_settlement_count",
        json: &scope_only_json,
    }];
    assert!(matches!(
        ainxt_retrieval::structured::load_metrics_from_files(&files, None, &rls_set(), &views)
            .unwrap_err(),
        CatalogLoadError::RlsScopeWithoutPolicy { .. }
    ));

    // The correct shape loads.
    let good = serde_json::to_string(&declared_metric()).unwrap();
    let files = vec![CatalogFile {
        dir_id: "failed_settlement_count",
        json: &good,
    }];
    let (catalog, _lock) =
        ainxt_retrieval::structured::load_metrics_from_files(&files, None, &rls_set(), &views)
            .expect("a metric with enforceable RLS loads");
    assert_eq!(catalog.len(), 1);
}

#[test]
fn r16_rederivation_refuses_an_unbound_rls_session() {
    // A legacy, code-built metric (policy declared, scope not) compiles with a DbNativeRequired
    // attestation: the SQL is not provably scoped, so DB-native RLS is the only thing standing
    // between the query and every department's rows. Re-executing it with an EMPTY session context
    // would drop that scope entirely — refuse (the numeric gate then fails closed).
    let legacy = MetricDef::new(
        "failed_settlement_count",
        "v_settlement_failures_curated",
        DataClass::Confidential,
    )
    .dimension("bank_id", DataClass::Internal)
    .rls("rls_settlement_by_dept");
    let compiled = compile_structured_query(
        &catalog_of(legacy),
        "failed_settlement_count",
        &["bank_id"],
        &[],
        Aggregation::Count,
        &view_schema(vec![]),
        &analyst(),
    )
    .expect("the legacy shape still compiles (the control-plane loader refuses it at load time)");
    assert_eq!(
        compiled.rls_scope,
        RlsScopeAttestation::DbNativeRequired {
            policy: "rls_settlement_by_dept".to_string()
        }
    );

    // An executor that would happily return EVERY row if it were ever reached.
    struct AllRows;
    impl RlsExecutor for AllRows {
        fn execute(&self, _p: &StructuredPlan, _s: &SessionContext) -> Option<Vec<Row>> {
            Some(vec![vec![("bank_id".to_string(), "BANKX".to_string())]; 42])
        }
    }
    let exec = AllRows;

    let mut unbound = ServerSideRederiver::new(&exec);
    unbound.register(
        &compiled,
        SessionContext {
            settings: vec![],
            stale_as_of: None,
        },
    );
    let source = ClaimSource::Metric {
        id: "failed_settlement_count".to_string(),
        query_hash: compiled.query_hash.clone(),
    };
    assert_eq!(
        unbound.rederive(&source),
        None,
        "an unscoped re-execution must fail closed, never silently verify against all rows"
    );

    // With the RLS session bound, the same target re-derives normally.
    let mut bound = ServerSideRederiver::new(&exec);
    bound.register(
        &compiled,
        SessionContext {
            settings: vec![("app.dept".to_string(), "settlement-eng".to_string())],
            stale_as_of: None,
        },
    );
    assert_eq!(bound.rederive(&source), Some(42.0));
}
