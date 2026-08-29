// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-12 Context-Fabric / structured-retrieval gap closures on the real objects.
//!
//! * **Catalog → NL2SQL Stage-A/Stage-B integrated into one pipeline** (`STRUCTURED_FEDERATED_
//!   RETRIEVAL.md` §4): [`compile_structured_query`] runs catalog resolution then the deterministic
//!   SQL compiler in one call, refusing an undeclared-dimension filter before the DB. Fails before:
//!   the two stages lived in separate crates with no bridge.
//! * **§5.2 independent server-side re-derivation for metric claims**: [`ServerSideRederiver`]
//!   re-executes the compiled query through the read-replica seam and re-applies the metric's
//!   aggregation, wired into the existing numeric gate — a fabricated count is blocked, a truthful
//!   one ships. Fails before: the only `Rederiver` was a truth-keyed stub; nothing re-executed the
//!   compiled query.
//! * **§3.1 `stale_as_of` computed from monitored replica lag vs `freshness_sla_seconds`** and **§4
//!   vector-index recall/latency monitoring**: [`stale_as_of_from_lag`] /
//!   [`build_session_context_monitored`] and [`RecallLatencyMonitor`]. Fails before: `stale_as_of`
//!   was a hand-passed parameter and there was no recall/latency monitor.

use std::collections::BTreeSet;

use ainxt_nl2sql::{Column, Schema, Table};
use ainxt_retrieval::acl::AccessContext;
use ainxt_retrieval::maintenance::{IndexHealth, IndexSlo, RecallLatencyMonitor};
use ainxt_retrieval::structured::{
    build_session_context_monitored, stale_as_of_from_lag, MetricCatalog, MetricDef, ReplicaLag,
    RlsPolicy, RowFilter, SessionVarSource,
};
use ainxt_retrieval::structured_pipeline::{
    compile_structured_query, query_hash, Aggregation, CompiledStructuredQuery, DimensionFilter,
    PipelineError, ServerSideRederiver,
};
use ainxt_synthesis::rederive::{numeric_gate, ClaimSource, NumericClaim, Tolerance, ValueClass};
use ainxt_types::{DataClass, Principal};

fn rls_set(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|s| s.to_string()).collect()
}

fn catalog() -> MetricCatalog {
    MetricCatalog::load(
        vec![MetricDef::new(
            "failed_settlement_count",
            "v_settlement_failures_curated",
            DataClass::Confidential,
        )
        .dimension("bank_id", DataClass::Internal)
        .rls("rls_settlement_by_dept")
        .freshness_sla(300)],
        &rls_set(&["rls_settlement_by_dept"]),
    )
    .unwrap()
}

fn view_schema() -> Schema {
    Schema::new(vec![Table::new(
        "v_settlement_failures_curated",
        vec![Column::new("bank_id", DataClass::Internal).unwrap()],
    )
    .unwrap()])
    .unwrap()
}

fn analyst() -> Principal {
    Principal::user("analyst", &[]).with_clearance(DataClass::Confidential)
}

fn compile() -> CompiledStructuredQuery {
    compile_structured_query(
        &catalog(),
        "failed_settlement_count",
        &["bank_id"],
        &[DimensionFilter::eq_text("bank_id", "BANKX")],
        Aggregation::Count,
        &view_schema(),
        &analyst(),
    )
    .unwrap()
}

// ============================ gap 4: Stage-A/Stage-B integrated pipeline ======================

#[test]
fn r12_pipeline_integrates_catalog_and_nl2sql_never_raw_sql() {
    let compiled = compile();
    // Stage A named only the curated view; Stage B produced a parameterized SELECT with a bound $1.
    assert!(compiled.query.sql.starts_with("SELECT "));
    assert!(compiled.query.sql.contains("v_settlement_failures_curated"));
    assert!(
        compiled.query.sql.contains("$1"),
        "filter value is a bound placeholder, not interpolated"
    );
    assert!(
        !compiled.query.sql.contains("BANKX"),
        "no caller value is ever rendered into SQL"
    );
    assert_eq!(compiled.plan.data_class_ceiling, DataClass::Confidential);
    assert!(!compiled.query_hash.is_empty());

    // A metric outside the catalog does not exist to the compiler (closed vocabulary).
    let unknown = compile_structured_query(
        &catalog(),
        "drop_all_tables",
        &[],
        &[],
        Aggregation::Count,
        &view_schema(),
        &analyst(),
    );
    assert!(matches!(unknown, Err(PipelineError::Catalog(_))));

    // A filter on an undeclared dimension is refused BEFORE the DB.
    let bad = compile_structured_query(
        &catalog(),
        "failed_settlement_count",
        &[],
        &[DimensionFilter::eq_text("ssn", "x")],
        Aggregation::Count,
        &view_schema(),
        &analyst(),
    );
    assert!(matches!(
        bad,
        Err(PipelineError::UndeclaredFilterDimension { .. })
    ));
}

#[test]
fn r12_query_hash_is_stable_and_sensitive() {
    let a = compile();
    let b = compile();
    assert_eq!(
        a.query_hash, b.query_hash,
        "same compiled query → same hash (durable identity)"
    );
    // A different aggregation changes the hash.
    let sum_hash = query_hash(
        &a.query,
        &Aggregation::SumColumn {
            column: "bank_id".into(),
        },
    );
    assert_ne!(a.query_hash, sum_hash);
}

// ============================ gap 1: server-side re-derivation ================================

fn rows(bankx_count: usize) -> Vec<Vec<(String, String)>> {
    // Rows the RLS-scoped read returns for dept "settle" — the server truth the model must match.
    (0..bankx_count)
        .map(|_| {
            vec![
                ("dept".to_string(), "settle".to_string()),
                ("bank_id".to_string(), "BANKX".to_string()),
            ]
        })
        .collect()
}

fn scoped_session() -> ainxt_retrieval::structured::SessionContext {
    let policy =
        RlsPolicy::new("rls_settlement_by_dept").var("app.dept", SessionVarSource::Department);
    let ctx = AccessContext::new(DataClass::Confidential, Some("settle"), None, &[]);
    build_session_context_monitored(&policy, &ctx, &compile().plan, ReplicaLag::new(0, 1000))
        .unwrap()
}

#[test]
fn r12_server_side_rederivation_blocks_fabricated_count_ships_truthful() {
    // The read replica truthfully returns 3 rows for this scope.
    let executor = RowFilter {
        rows: rows(3),
        scope_column: "dept".into(),
        scope_var: "app.dept".into(),
    };
    let compiled = compile();
    let mut rd = ServerSideRederiver::new(&executor);
    rd.register(&compiled, scoped_session());

    // The re-deriver independently re-executes the compiled query and recomputes COUNT = 3.
    let key = ClaimSource::Metric {
        id: "failed_settlement_count".into(),
        query_hash: compiled.query_hash.clone(),
    };
    assert_eq!(
        ainxt_synthesis::rederive::Rederiver::rederive(&rd, &key),
        Some(3.0),
        "re-execution recomputes the true aggregate from the data path"
    );

    // Truthful claim (3) ships through the numeric gate.
    let truthful = vec![NumericClaim::metric(
        3.0,
        "count",
        ValueClass::Exact,
        "failed_settlement_count",
        &compiled.query_hash,
    )];
    let ok = numeric_gate(
        "There were 3 failed settlements.",
        &truthful,
        &rd,
        &Tolerance::default(),
    );
    assert!(ok.ships(), "a claim matching the re-derived value ships");

    // Fabricated claim (47) is BLOCKED by the gate on mismatch.
    let fabricated = vec![NumericClaim::metric(
        47.0,
        "count",
        ValueClass::Exact,
        "failed_settlement_count",
        &compiled.query_hash,
    )];
    let blocked = numeric_gate(
        "There were 47 failed settlements.",
        &fabricated,
        &rd,
        &Tolerance::default(),
    );
    assert!(
        !blocked.ships(),
        "a fabricated number that fails re-derivation is blocked"
    );
    assert!(blocked.rederivation.has_mismatch());
}

#[test]
fn r12_rederiver_fails_closed_on_unknown_query_hash() {
    let executor = RowFilter {
        rows: rows(1),
        scope_column: "dept".into(),
        scope_var: "app.dept".into(),
    };
    let rd = ServerSideRederiver::new(&executor); // nothing registered
    let key = ClaimSource::Metric {
        id: "m".into(),
        query_hash: "deadbeef".into(),
    };
    assert_eq!(
        ainxt_synthesis::rederive::Rederiver::rederive(&rd, &key),
        None,
        "unknown hash → cannot verify"
    );
}

// ============================ gap 5: replica-lag staleness + recall/latency ===================

#[test]
fn r12_stale_as_of_from_monitored_replica_lag() {
    // Lag within SLA → fresh (no flag).
    assert_eq!(stale_as_of_from_lag(ReplicaLag::new(120, 1000), 300), None);
    // Lag == SLA → still within budget.
    assert_eq!(stale_as_of_from_lag(ReplicaLag::new(300, 1000), 300), None);
    // Lag exceeds SLA → flagged with the replica watermark (now - lag).
    assert_eq!(
        stale_as_of_from_lag(ReplicaLag::new(450, 1000), 300),
        Some(550)
    );

    // Threaded through the plan's freshness SLA on session-context build.
    let policy =
        RlsPolicy::new("rls_settlement_by_dept").var("app.dept", SessionVarSource::Department);
    let ctx = AccessContext::new(DataClass::Confidential, Some("settle"), None, &[]);
    let plan = compile().plan; // freshness_sla_seconds = 300
    let fresh =
        build_session_context_monitored(&policy, &ctx, &plan, ReplicaLag::new(10, 1000)).unwrap();
    assert_eq!(fresh.stale_as_of, None);
    let stale =
        build_session_context_monitored(&policy, &ctx, &plan, ReplicaLag::new(900, 1000)).unwrap();
    assert_eq!(stale.stale_as_of, Some(100));
}

#[test]
fn r12_recall_latency_monitor_flags_degradation() {
    let slo = IndexSlo {
        min_recall_at_k: 0.95,
        max_p99_latency_ms: 150,
    };

    // No data → unknown, never defaulted-healthy.
    let empty = RecallLatencyMonitor::new(slo, 100);
    assert_eq!(empty.status(), IndexHealth::NoData);

    // Healthy recall + latency.
    let mut healthy = RecallLatencyMonitor::new(slo, 100);
    for _ in 0..50 {
        healthy.record_recall(0.99);
        healthy.record_latency(40);
    }
    assert!(healthy.status().is_healthy());

    // Recall degraded below the floor.
    let mut low_recall = RecallLatencyMonitor::new(slo, 100);
    for _ in 0..50 {
        low_recall.record_recall(0.80);
        low_recall.record_latency(40);
    }
    assert!(matches!(
        low_recall.status(),
        IndexHealth::RecallDegraded { .. }
    ));

    // Tail latency over the ceiling: recall healthy, but the p99 latency window breaches the ceiling.
    let mut slow = RecallLatencyMonitor::new(slo, 100);
    for _ in 0..100 {
        slow.record_recall(0.99);
        slow.record_latency(220); // sustained tail above the 150ms ceiling
    }
    assert!(matches!(slow.status(), IndexHealth::LatencyDegraded { .. }));
}
