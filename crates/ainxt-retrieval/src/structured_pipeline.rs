// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! The single structured-retrieval pipeline: **Catalog (Stage A) → NL-to-SQL (Stage B) → server-side
//! re-derivation**, integrated end to end.
//!
//! Design: `STRUCTURED_FEDERATED_RETRIEVAL.md` §4 (the two-stage "never raw SQL" compiler) and §5.2
//! (independent server-side re-derivation of any metric-sourced numeric claim).
//!
//! Until now the two halves lived in separate crates with no wire between them:
//! * **Stage A** — [`crate::structured::MetricCatalog::plan`] resolves an intent against the
//!   closed-vocabulary catalog and emits a [`StructuredPlan`] naming only a curated `source_view`.
//! * **Stage B** — `ainxt_nl2sql::validate_and_compile` turns a structured, `SELECT`-only
//!   [`QueryIntent`] into a parameterized [`SafeQuery`] (every value a bound `$n`, RLS injected,
//!   bounded `LIMIT`).
//!
//! [`compile_structured_query`] is the missing bridge: it runs Stage A, projects the resulting plan
//! into a Stage-B [`QueryIntent`] over the plan's `source_view` (dimensions become the projection;
//! caller filters are validated against the metric's declared dimensions — a filter on an
//! undeclared dimension is refused *before* the compiler, exactly as §4 mandates), compiles it, and
//! returns a [`CompiledStructuredQuery`] carrying a stable `query_hash`. **The LLM never emits SQL:**
//! its only structured output is the closed-vocabulary intent; a deterministic compiler is the only
//! thing that ever produces a SQL string, and only against a catalog `source_view`.
//!
//! The `query_hash` is exactly the identity `ainxt_synthesis`'s numeric-claim contract
//! (`ClaimSource::Metric { id, query_hash }`) carries, so §5.2 re-derivation can find and re-run the
//! same compiled query. [`ServerSideRederiver`] implements `ainxt_synthesis::rederive::Rederiver` by
//! **independently re-executing the compiled query server-side** (through the read-replica
//! [`RlsExecutor`] seam) and applying the metric's [`Aggregation`] — a fresh recomputation from the
//! data path, never a re-ask of the model. Offline it is proven against the in-memory
//! [`crate::structured::RowFilter`] oracle; the live path runs the SQL on a Postgres read replica
//! (the sole infra-gated piece, behind the existing [`crate::structured::RlsConnection`] seam).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use ainxt_nl2sql::{
    validate_and_compile, Filter, Predicate, PrincipalAttr, QueryError, QueryIntent, SafeQuery,
    Schema, Value,
};
use ainxt_synthesis::rederive::{ClaimSource, Rederiver};
use ainxt_types::Principal;

use crate::structured::{
    CatalogError, MetricCatalog, RlsExecutor, RlsScopeBinding, Row, ScopeAttr, SessionContext,
    StructuredPlan,
};

/// How a metric's scalar value is computed from the rows the compiled query returns
/// (`STRUCTURED_FEDERATED_RETRIEVAL.md` §5.2 — the deterministic recomputation). The model never
/// performs this arithmetic; the runtime does, both when first answering and again at re-derivation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Aggregation {
    /// Count of rows the (RLS-scoped) query returns — the `failed_settlement_count` shape.
    Count,
    /// Sum of an integer-minor-unit column across the returned rows (currency-safe: parsed as i64,
    /// summed as i128, returned as the exact integer). A row missing/непarseable in that column is a
    /// re-derivation failure (returns `None`), never a silent zero.
    SumColumn { column: String },
}

impl Aggregation {
    /// Apply this aggregation to the returned rows, deterministically. `None` on a data shape the
    /// aggregation cannot honestly compute (so re-derivation fails closed rather than inventing 0).
    pub fn apply(&self, rows: &[Row]) -> Option<f64> {
        match self {
            Aggregation::Count => Some(rows.len() as f64),
            Aggregation::SumColumn { column } => {
                let mut acc: i128 = 0;
                for row in rows {
                    let cell = row.iter().find(|(c, _)| c == column)?;
                    let v: i64 = cell.1.trim().parse().ok()?;
                    acc += v as i128;
                }
                Some(acc as f64)
            }
        }
    }
}

/// The fully-compiled structured query: the Stage-A [`StructuredPlan`], the Stage-B [`SafeQuery`],
/// the [`Aggregation`] to apply to its rows, and a stable `query_hash` (over the compiled SQL +
/// params + aggregation) that is the re-derivation identity (§5.2).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CompiledStructuredQuery {
    pub plan: StructuredPlan,
    pub query: SafeQuery,
    pub aggregation: Aggregation,
    pub query_hash: String,
    /// What the compiler could actually *prove* about this query's row scope versus the row scope
    /// the metric's declared RLS policy promises (§2.2.2 / §3.2). Carried on the compiled query so
    /// every downstream execution/re-derivation can honor it rather than re-deriving trust.
    pub rls_scope: RlsScopeAttestation,
}

/// The compiler's attestation about a compiled query's row scope — the record that closes
/// "a metric can silently widen its own row scope".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RlsScopeAttestation {
    /// The metric declares no RLS policy and the compiled query carries no row scope — an
    /// explicitly unscoped, reviewed metric (§2.1 "rare; must be a deliberate choice").
    Unscoped,
    /// The metric declares an RLS policy AND its declared row scope was verified, element for
    /// element, against the row scope the compiler actually injected into the SQL. This is the only
    /// state in which the SQL text itself is known to be row-scoped.
    Verified {
        policy: String,
        scopes: Vec<RlsScopeBinding>,
    },
    /// The metric declares an RLS policy but carries no declared scope (a legacy, code-built
    /// catalog — the git-native control-plane loader refuses this shape at load time). The compiled
    /// SQL is therefore NOT proven row-scoped, so enforcement falls entirely to database-native RLS:
    /// execution MUST bind the policy's `SET LOCAL` session vars, and every executor here refuses to
    /// run with an empty session context.
    DbNativeRequired { policy: String },
}

impl RlsScopeAttestation {
    /// Does executing this query require a non-empty `SET LOCAL` session context to be safe?
    pub fn requires_session_binding(&self) -> bool {
        !matches!(self, RlsScopeAttestation::Unscoped)
    }
}

/// Why the integrated pipeline refused to compile a structured query.
#[derive(Debug, Clone, PartialEq)]
pub enum PipelineError {
    /// Stage A rejected the intent against the catalog (unknown/deprecated metric, unknown grouping
    /// dimension).
    Catalog(CatalogError),
    /// A caller filter referenced a dimension the metric does not declare — refused *before* the
    /// compiler touches the database (§4: "a structural 400, never a passed-through SQL error").
    /// Checkmarx CX-FP: unit variant — metric/dimension names excluded from error payload.
    UndeclaredFilterDimension,
    /// Stage B (the NL-to-SQL compiler) refused the projected intent (unknown/over-clearance column,
    /// unsatisfiable RLS, …).
    Compile(QueryError),
    /// **The row scope the metric's RLS policy declares does not match the row scope the query
    /// would actually compile with** (§2.2.2 / §3.2). Either the schema's table declares no row
    /// scope at all (the compiled SELECT would be unscoped over, e.g., settlement data), or it
    /// scopes on a different column/principal attribute than the policy promises — i.e. the metric
    /// would silently widen (or otherwise change) its own row scope. Refused before any DB access.
    RlsScopeMismatch {
        metric: String,
        policy: String,
        /// What the metric's control-plane definition declares its policy enforces.
        declared: Vec<RlsScopeBinding>,
        /// What the supplied `Schema` would actually compile into the SQL.
        compiled: Vec<RlsScopeBinding>,
    },
}

impl std::fmt::Display for PipelineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PipelineError::Catalog(e) => write!(f, "catalog stage refused: {e:?}"),
            PipelineError::UndeclaredFilterDimension => write!(
                f,
                "a filter references a dimension not declared on the requested metric"
            ),
            PipelineError::Compile(e) => write!(f, "compile stage refused: {e}"),
            PipelineError::RlsScopeMismatch {
                metric,
                policy,
                declared,
                compiled,
            } => write!(
                f,
                "metric {metric:?} declares RLS policy {policy:?} enforcing {declared:?} but the \
                 compiled query's row scope is {compiled:?}"
            ),
        }
    }
}

/// Project an `ainxt_nl2sql` compiled row scope into the catalog's declaration vocabulary, so the
/// two halves are compared in ONE representation (never by hand at each call site).
fn compiled_row_scope(table: &ainxt_nl2sql::Table) -> Vec<RlsScopeBinding> {
    let mut scopes: Vec<RlsScopeBinding> = table
        .row_scopes()
        .iter()
        .map(|s| {
            RlsScopeBinding::new(
                &s.column,
                match s.attr {
                    PrincipalAttr::Department => ScopeAttr::Department,
                    PrincipalAttr::UserId => ScopeAttr::UserId,
                },
            )
        })
        .collect();
    scopes.sort();
    scopes
}

/// Cross-check the metric-declared RLS policy against the row scope the query will actually compile
/// with (`STRUCTURED_FEDERATED_RETRIEVAL.md` §2.2.2 + §3.2) and return the attestation to stamp on
/// the compiled query.
///
/// This is the check whose absence let a metric declare `rls_settlement_by_dept` and still compile
/// an *unscoped* SELECT over settlement rows, because row scoping came only from a `Schema` the
/// caller supplied independently of the catalog. Now the catalog's declaration is authoritative and
/// any disagreement — missing scope, extra scope, different column, different principal attribute —
/// refuses the compile.
fn attest_rls_scope(
    plan: &StructuredPlan,
    schema: &Schema,
) -> Result<RlsScopeAttestation, PipelineError> {
    let compiled = schema.table(&plan.source_view).map(compiled_row_scope);
    let mut declared = plan.rls_scope.clone();
    declared.sort();

    match (&plan.rls_predicate_ref, declared.is_empty()) {
        // No policy, no declaration: an explicitly unscoped metric. Any row scope the schema adds on
        // top is strictly narrowing (defense in depth) and never a widening, so it is allowed.
        (None, _) => Ok(RlsScopeAttestation::Unscoped),
        // A policy with no declared scope — the legacy, code-built shape the git-native loader now
        // refuses. The SQL is not provably scoped, so execution must bind DB-native RLS session vars.
        (Some(policy), true) => Ok(RlsScopeAttestation::DbNativeRequired {
            policy: policy.clone(),
        }),
        // A policy WITH a declared scope: the compiled scope must match it exactly.
        (Some(policy), false) => {
            let compiled = compiled.unwrap_or_default();
            if compiled != declared {
                return Err(PipelineError::RlsScopeMismatch {
                    metric: plan.metric_id.clone(),
                    policy: policy.clone(),
                    declared,
                    compiled,
                });
            }
            Ok(RlsScopeAttestation::Verified {
                policy: policy.clone(),
                scopes: declared,
            })
        }
    }
}

impl std::error::Error for PipelineError {}

/// A caller-supplied dimension equality filter (the closed-vocabulary analogue of a `WHERE dim = v`).
/// The dimension must be one the metric declares; the value is bound as a parameter downstream.
#[derive(Debug, Clone, PartialEq)]
pub struct DimensionFilter {
    pub dimension: String,
    pub value: Value,
}

impl DimensionFilter {
    pub fn eq_text(dimension: &str, value: &str) -> Self {
        DimensionFilter {
            dimension: dimension.to_string(),
            value: Value::Text(value.to_string()),
        }
    }
    pub fn eq_int(dimension: &str, value: i64) -> Self {
        DimensionFilter {
            dimension: dimension.to_string(),
            value: Value::Int(value),
        }
    }
}

/// A stable FNV-1a-64 hash over bytes, rendered as lowercase hex. Deterministic across runs/hosts
/// (no `DefaultHasher` randomization), which is required because the `query_hash` is a durable
/// re-derivation identity that must reproduce.
fn stable_hash_hex(parts: &[&[u8]]) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for p in parts {
        for &b in *p {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        // Domain separator between parts.
        h ^= 0xff;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{h:016x}")
}

/// Compute the re-derivation identity of a compiled query: a stable hash over the SQL text, each
/// bound parameter, and the aggregation. Two intents that compile to the same query share a hash;
/// any change to filters/projection/limit/aggregation changes it.
pub fn query_hash(query: &SafeQuery, aggregation: &Aggregation) -> String {
    let params = serde_json::to_vec(&query.params).unwrap_or_default();
    let agg = serde_json::to_vec(aggregation).unwrap_or_default();
    stable_hash_hex(&[query.sql.as_bytes(), &params, &agg])
}

/// The integrated structural pipeline (`STRUCTURED_FEDERATED_RETRIEVAL.md` §4): Stage A (catalog) →
/// Stage B (NL-to-SQL), in one call. Fail-closed at each boundary. The model's contribution is only
/// `(metric_id, group_by, filters, aggregation)` — a closed-vocabulary intent; every SQL string is
/// produced by the deterministic compiler against the catalog's `source_view`.
///
/// Steps:
/// 1. **Stage A** — `catalog.plan(metric_id, group_by)` validates the metric + grouping dimensions
///    (unknown/deprecated → [`PipelineError::Catalog`]).
/// 2. **Filter validation** — each caller [`DimensionFilter`] must name a dimension the metric
///    declares, else [`PipelineError::UndeclaredFilterDimension`] (before any DB access).
/// 3. **Projection** — build a `SELECT`-only [`QueryIntent`] over the plan's `source_view`: project
///    the grouping dimensions (or the first declared dimension when none, so the projection is never
///    empty), attach the validated filters as equality predicates.
/// 4. **Stage B** — `validate_and_compile` compiles it against `schema` under the caller's clearance,
///    injecting RLS and a bounded `LIMIT`.
pub fn compile_structured_query(
    catalog: &MetricCatalog,
    metric_id: &str,
    group_by: &[&str],
    filters: &[DimensionFilter],
    aggregation: Aggregation,
    schema: &Schema,
    principal: &Principal,
) -> Result<CompiledStructuredQuery, PipelineError> {
    // Stage A: closed-vocabulary catalog resolution.
    let plan = catalog
        .plan(metric_id, group_by)
        .map_err(PipelineError::Catalog)?;

    // Cross-check the metric's DECLARED RLS policy against the row scope this compile would
    // actually carry (§2.2.2) — a metric may never silently widen its own row scope. Refused here,
    // before Stage B and before any DB access.
    let rls_scope = attest_rls_scope(&plan, schema)?;

    // Validate every filter dimension is declared on the metric (structural, pre-DB).
    let metric = catalog.resolve(metric_id).map_err(PipelineError::Catalog)?;
    for f in filters {
        if !metric.dimensions.iter().any(|d| d.name == f.dimension) {
            return Err(PipelineError::UndeclaredFilterDimension);
        }
    }

    // Projection: the grouping dimensions, or the first declared dimension so SELECT is never empty.
    let mut select: Vec<String> = plan.group_by.clone();
    if select.is_empty() {
        if let Some(first) = metric.dimensions.first() {
            select.push(first.name.clone());
        }
    }

    let intent = QueryIntent {
        select,
        from: plan.source_view.clone(),
        filters: filters
            .iter()
            .map(|f| Filter {
                column: f.dimension.clone(),
                predicate: Predicate::Eq(f.value.clone()),
            })
            .collect(),
        order_by: Vec::new(),
        limit: None,
    };

    // Stage B: deterministic, parameterized compilation under RLS + clearance.
    let query = validate_and_compile(&intent, schema, principal).map_err(PipelineError::Compile)?;
    let hash = query_hash(&query, &aggregation);

    Ok(CompiledStructuredQuery {
        plan,
        query,
        aggregation,
        query_hash: hash,
        rls_scope,
    })
}

// ---------------------------------------------------------------------------------------
// §5.2 server-side re-derivation: re-execute the compiled query, recompute the aggregate
// ---------------------------------------------------------------------------------------

/// One registered re-derivation target: the plan + session to re-execute and the aggregation to
/// re-apply, keyed (in [`ServerSideRederiver`]) by the compiled query's `query_hash`.
struct RederiveTarget {
    plan: StructuredPlan,
    session: SessionContext,
    aggregation: Aggregation,
    /// The compiler's row-scope attestation for this query — re-checked at execution so a query
    /// whose row scoping depends on DB-native RLS can never be re-executed without its session
    /// binding (which would be a broader read than the original answer's).
    rls_scope: RlsScopeAttestation,
}

/// The server-side re-derivation instrument (`STRUCTURED_FEDERATED_RETRIEVAL.md` §5.2): given a
/// numeric claim tagged `ClaimSource::Metric { query_hash, .. }`, it **independently re-executes the
/// same compiled query** through the read-replica [`RlsExecutor`] seam and re-applies the metric's
/// [`Aggregation`] — a fresh recomputation from the data path, not a re-ask of the model. Wire it
/// into `ainxt_synthesis::rederive::rederive_and_verify` / `numeric_gate`, which diffs the re-derived
/// value against the model's claim and blocks on mismatch.
///
/// It implements the crate's [`Rederiver`] trait, so it is a drop-in for the existing numeric gate.
/// Offline it is driven by the in-memory [`crate::structured::RowFilter`] oracle; live, by
/// [`crate::structured::PostgresRlsExecutor`] against a read replica (the only infra-gated piece).
pub struct ServerSideRederiver<'a> {
    executor: &'a dyn RlsExecutor,
    targets: BTreeMap<String, RederiveTarget>,
}

impl<'a> ServerSideRederiver<'a> {
    /// Build a re-deriver over a read-replica [`RlsExecutor`] (the [`RowFilter`] oracle offline, a
    /// Postgres replica executor live).
    ///
    /// [`RowFilter`]: crate::structured::RowFilter
    pub fn new(executor: &'a dyn RlsExecutor) -> Self {
        ServerSideRederiver {
            executor,
            targets: BTreeMap::new(),
        }
    }

    /// Register a compiled query so a claim carrying its `query_hash` can be re-derived. The
    /// `session` is the RLS `SET LOCAL` context to re-apply (same OBO scoping as the original read),
    /// so re-derivation runs under the *same* row scope — never a broader one.
    pub fn register(&mut self, compiled: &CompiledStructuredQuery, session: SessionContext) {
        self.targets.insert(
            compiled.query_hash.clone(),
            RederiveTarget {
                plan: compiled.plan.clone(),
                session,
                aggregation: compiled.aggregation.clone(),
                rls_scope: compiled.rls_scope.clone(),
            },
        );
    }

    /// Number of registered re-derivation targets.
    pub fn len(&self) -> usize {
        self.targets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.targets.is_empty()
    }
}

impl Rederiver for ServerSideRederiver<'_> {
    fn rederive(&self, source: &ClaimSource) -> Option<f64> {
        // Only metric-sourced claims are re-executed here; tool-sourced claims re-run elsewhere.
        let query_hash = match source {
            ClaimSource::Metric { query_hash, .. } => query_hash,
            _ => return None,
        };
        let target = self.targets.get(query_hash)?;
        // Row-scope invariant, re-checked at execution: a query whose scoping is not proven in the
        // SQL text (or which is policy-scoped at all) may only be re-executed with its RLS session
        // binding present. An empty session would re-derive over a BROADER row set than the answer
        // was built from — refuse (fail-closed → the numeric gate blocks, never silently verifies).
        if target.rls_scope.requires_session_binding() && target.session.settings.is_empty() {
            return None;
        }
        // A binding that cannot be safely rendered (illegal GUC name / unrepresentable value) is
        // likewise a refusal, never a forged statement.
        target.session.bindings().ok()?;
        // Independently re-execute the compiled query server-side (the read-replica seam), under the
        // same RLS session, then recompute the aggregate deterministically. `None` (executor error /
        // un-aggregatable rows) propagates as "cannot verify" → the numeric gate fails closed.
        let rows = self.executor.execute(&target.plan, &target.session)?;
        target.aggregation.apply(&rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::structured::MetricDef;
    use ainxt_nl2sql::{Column, Table};
    use ainxt_types::DataClass;
    use std::collections::BTreeSet;

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
            .rls("rls_settlement_by_dept")],
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

    #[test]
    fn pipeline_compiles_and_rejects_undeclared_filter() {
        let compiled = compile_structured_query(
            &catalog(),
            "failed_settlement_count",
            &["bank_id"],
            &[DimensionFilter::eq_text("bank_id", "BANKX")],
            Aggregation::Count,
            &view_schema(),
            &analyst(),
        )
        .unwrap();
        assert!(compiled.query.sql.starts_with("SELECT "));
        assert!(compiled.query.sql.contains("v_settlement_failures_curated"));
        assert!(!compiled.query_hash.is_empty());

        // A filter on an undeclared dimension is refused before the DB.
        let err = compile_structured_query(
            &catalog(),
            "failed_settlement_count",
            &[],
            &[DimensionFilter::eq_text("ssn", "x")],
            Aggregation::Count,
            &view_schema(),
            &analyst(),
        )
        .unwrap_err();
        assert!(matches!(err, PipelineError::UndeclaredFilterDimension));
    }
}
