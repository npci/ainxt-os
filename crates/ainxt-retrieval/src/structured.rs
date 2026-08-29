// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Structured retrieval control-plane: the semantic metric catalog + row-level-security context.
//!
//! Design: `STRUCTURED_FEDERATED_RETRIEVAL.md` §2 (the metric/dimension catalog as an
//! ADR-026 git-native control-plane definition kind), §4 (a deterministic closed-vocabulary
//! compiler — the model NEVER emits SQL), and §3 (native Postgres ROW LEVEL SECURITY keyed off
//! `SET LOCAL` session vars sourced from the OBO context, on read replicas with a `stale_as_of`
//! flag).
//!
//! What lives here (pure, deterministic, offline):
//!
//! - [`MetricCatalog`] — the *entire vocabulary* structured retrieval may reference. A metric or
//!   dimension not in the catalog does not exist to the compiler; this is the structural form of
//!   "never raw free-form SQL", not a prompt instruction the model could be talked out of.
//! - [`MetricCatalog::validate`] — load-time **all-or-nothing** validation (§2.2, extends ADR-026
//!   §6): one malformed metric rejects the whole catalog, so a half-valid control plane never
//!   loads.
//! - [`MetricCatalog::plan`] — the closed-vocabulary compile *front half*: it resolves an intent
//!   (metric + dimensions + filters) against the catalog and emits a validated [`StructuredPlan`]
//!   naming only the catalog `source_view`, the `data_class_ceiling` (feeds the Model Router), and
//!   the RLS policy ref. The actual SQL *text* generation is a downstream compiler seam
//!   (`ainxt-nl2sql`); this half proves the vocabulary is closed and the target is a curated view.
//! - [`RlsPolicy`] / [`build_session_context`] — derive the exact `SET LOCAL` session variables an
//!   RLS predicate reads, **from the OBO [`AccessContext`]**, fail-closed (a required var the
//!   caller can't source aborts the query — never emit a predicate that would return all rows).
//! - [`RowFilter`] / [`RlsExecutor`] — the read-replica seam and an offline reference row-filter
//!   proving the derived session context actually excludes out-of-scope rows. The live enforcement
//!   is Postgres RLS on a replica (deferred to infra); the contract + fail-closed derivation is
//!   real here.

use std::collections::{BTreeMap, BTreeSet};

use ainxt_types::DataClass;
use serde::{Deserialize, Serialize};

use crate::acl::AccessContext;

// ---------------------------------------------------------------------------------------
// The semantic metric + dimension catalog (§2)
// ---------------------------------------------------------------------------------------

/// One dimension a metric may be grouped/filtered by. `data_class` labels the dimension's own
/// sensitivity (a `bank_id` is internal, a `customer_id` is PII) so grouping can't silently
/// down-class a result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dimension {
    pub name: String,
    pub data_class: DataClass,
}

impl Dimension {
    pub fn new(name: &str, data_class: DataClass) -> Self {
        Dimension {
            name: name.to_string(),
            data_class,
        }
    }
}

/// Which authenticated-principal attribute supplies the value a row-scope column is filtered
/// against. The catalog-side mirror of `ainxt_nl2sql::PrincipalAttr` — declared here so a metric
/// definition (a git-reviewed control-plane file) states the row scope its RLS policy enforces,
/// independently of whatever `Schema` a caller later hands the compiler.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeAttr {
    /// The caller's AD department / org unit.
    Department,
    /// The caller's user id (owner-scoped, "only my rows").
    UserId,
}

/// One row-scope rule the metric's declared RLS policy enforces: `column = <principal attribute>`.
///
/// This is the **declaration half** of §2.2.2's "a metric with no enforceable row-level security
/// cannot load". The *compiled* half lives in `ainxt_nl2sql::Table::row_scopes`; the two are
/// cross-checked at compile time by
/// [`compile_structured_query`](crate::structured_pipeline::compile_structured_query), so a metric
/// can never silently widen its own row scope by being compiled against a schema whose table
/// declares a different (or no) scope.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RlsScopeBinding {
    pub column: String,
    pub attr: ScopeAttr,
}

impl RlsScopeBinding {
    pub fn new(column: &str, attr: ScopeAttr) -> Self {
        RlsScopeBinding {
            column: column.to_string(),
            attr,
        }
    }
}

/// A single catalog metric definition (`STRUCTURED_FEDERATED_RETRIEVAL.md` §2.1 front-matter).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetricDef {
    pub id: String,
    /// A read-only DB VIEW, never a base table (§2.1). The compiler targets only this.
    pub source_view: String,
    /// The dimensions this metric may be grouped/filtered by.
    pub dimensions: Vec<Dimension>,
    /// Sensitivity ceiling of the metric's output — feeds the Model Router (§2.1, §4.2).
    pub data_class_ceiling: DataClass,
    /// The named Postgres RLS policy that must be active when querying the source view. `None`
    /// means the view is not row-scoped (rare; must be a deliberate, reviewed choice).
    pub rls_predicate_ref: Option<String>,
    /// The row scope `rls_predicate_ref` enforces, declared explicitly (§2.2.2). Cross-checked
    /// against the compiled query's actual row scoping at compile time — a disagreement refuses the
    /// query rather than silently serving a wider row set than the metric's policy allows. Additive
    /// and serde-defaulted so an older serialized [`MetricDef`] still deserializes (the git-native
    /// loader then refuses it at load time when a policy is declared without its scope).
    #[serde(default)]
    pub rls_scope: Vec<RlsScopeBinding>,
    /// Whether the metric is on the federated whitelist (§6). Cross-checked by federation.
    pub federated: bool,
    /// A deprecated metric still loads (for lineage) but cannot be planned.
    pub deprecated: bool,
    /// The read-replica freshness SLA in logical seconds (`STRUCTURED_FEDERATED_RETRIEVAL.md` §2.1
    /// `freshness_sla_seconds`, default 300). If the replica's lag exceeds this, a served result
    /// MUST carry a `stale_as_of` flag rather than be presented as current (§3.1). Additive +
    /// serde-defaulted so an older serialized [`MetricDef`] loads with the design default.
    #[serde(default = "default_freshness_sla")]
    pub freshness_sla_seconds: i64,
}

/// The design's default replica freshness SLA (`STRUCTURED_FEDERATED_RETRIEVAL.md` §2.1).
pub const DEFAULT_FRESHNESS_SLA_SECONDS: i64 = 300;

fn default_freshness_sla() -> i64 {
    DEFAULT_FRESHNESS_SLA_SECONDS
}

impl MetricDef {
    pub fn new(id: &str, source_view: &str, data_class_ceiling: DataClass) -> Self {
        MetricDef {
            id: id.to_string(),
            source_view: source_view.to_string(),
            dimensions: Vec::new(),
            data_class_ceiling,
            rls_predicate_ref: None,
            rls_scope: Vec::new(),
            federated: false,
            deprecated: false,
            freshness_sla_seconds: DEFAULT_FRESHNESS_SLA_SECONDS,
        }
    }

    /// Override the read-replica freshness SLA (logical seconds) for this metric (§2.1).
    pub fn freshness_sla(mut self, seconds: i64) -> Self {
        self.freshness_sla_seconds = seconds;
        self
    }

    pub fn dimension(mut self, name: &str, data_class: DataClass) -> Self {
        self.dimensions.push(Dimension::new(name, data_class));
        self
    }

    pub fn rls(mut self, predicate_ref: &str) -> Self {
        self.rls_predicate_ref = Some(predicate_ref.to_string());
        self
    }

    /// Declare one row-scope rule the metric's RLS policy enforces (§2.2.2). Chainable; the set is
    /// what the compiler cross-checks the compiled query's actual row scope against.
    pub fn rls_scope(mut self, column: &str, attr: ScopeAttr) -> Self {
        self.rls_scope.push(RlsScopeBinding::new(column, attr));
        self
    }

    pub fn federated(mut self, yes: bool) -> Self {
        self.federated = yes;
        self
    }

    pub fn deprecated(mut self, yes: bool) -> Self {
        self.deprecated = yes;
        self
    }

    fn dimension_names(&self) -> BTreeSet<&str> {
        self.dimensions.iter().map(|d| d.name.as_str()).collect()
    }
}

/// Why a catalog failed to load, or a query failed to compile against it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CatalogError {
    /// Two metric definitions share an id — the control plane is ambiguous.
    DuplicateMetric { id: String },
    /// A metric's `source_view` is empty or not a curated `v_*` view (must be a read-only view).
    InvalidSourceView { id: String, source_view: String },
    /// A metric declares no dimensions — a grain-less metric can't be safely grouped/scoped.
    NoDimensions { id: String },
    /// A metric has an RLS ref that is not in the provided registered-policy set (a dangling RLS
    /// reference would silently disable row scoping at query time).
    UnknownRlsPolicy { id: String, policy: String },
    /// The requested metric is not in the catalog — it does not exist to the compiler.
    UnknownMetric { id: String },
    /// The requested metric exists but is deprecated.
    DeprecatedMetric { id: String },
    /// A requested dimension is not declared on the metric.
    UnknownDimension { metric: String, dimension: String },
}

/// The metric catalog — the closed vocabulary for structured retrieval.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetricCatalog {
    metrics: BTreeMap<String, MetricDef>,
}

impl MetricCatalog {
    pub fn new() -> Self {
        MetricCatalog::default()
    }

    /// Load a catalog from a set of metric definitions with **all-or-nothing** validation (§2.2):
    /// every metric is checked and the *first* violation rejects the whole load, so a half-valid
    /// control plane never becomes active. `registered_rls` is the set of RLS policy names known to
    /// exist in the database (Postgres side, §3); a metric referencing one outside this set is
    /// rejected rather than silently querying an unscoped view.
    pub fn load(
        metrics: Vec<MetricDef>,
        registered_rls: &BTreeSet<String>,
    ) -> Result<Self, CatalogError> {
        let mut map: BTreeMap<String, MetricDef> = BTreeMap::new();
        for m in metrics {
            if map.contains_key(&m.id) {
                return Err(CatalogError::DuplicateMetric { id: m.id });
            }
            // A curated read-only view, by convention, is a `v_*` view — never a base table.
            if m.source_view.is_empty() || !m.source_view.starts_with("v_") {
                return Err(CatalogError::InvalidSourceView {
                    id: m.id.clone(),
                    source_view: m.source_view.clone(),
                });
            }
            if m.dimensions.is_empty() {
                return Err(CatalogError::NoDimensions { id: m.id });
            }
            if let Some(policy) = &m.rls_predicate_ref {
                if !registered_rls.contains(policy) {
                    return Err(CatalogError::UnknownRlsPolicy {
                        id: m.id.clone(),
                        policy: policy.clone(),
                    });
                }
            }
            map.insert(m.id.clone(), m);
        }
        Ok(MetricCatalog { metrics: map })
    }

    /// Number of loaded metrics.
    pub fn len(&self) -> usize {
        self.metrics.len()
    }

    pub fn is_empty(&self) -> bool {
        self.metrics.is_empty()
    }

    /// Look up a metric by id (closed-vocabulary resolution). A metric absent from the catalog
    /// does not exist to the compiler — the structural "never free-form SQL" guarantee.
    pub fn resolve(&self, metric_id: &str) -> Result<&MetricDef, CatalogError> {
        match self.metrics.get(metric_id) {
            None => Err(CatalogError::UnknownMetric {
                id: metric_id.to_string(),
            }),
            Some(m) if m.deprecated => Err(CatalogError::DeprecatedMetric {
                id: metric_id.to_string(),
            }),
            Some(m) => Ok(m),
        }
    }

    /// Compile the *front half* of a structured query: resolve the metric + requested grouping
    /// dimensions against the catalog and emit a validated [`StructuredPlan`]. Fails closed on any
    /// unknown metric or dimension — the model can only ever reference the catalog vocabulary.
    pub fn plan(&self, metric_id: &str, group_by: &[&str]) -> Result<StructuredPlan, CatalogError> {
        let m = self.resolve(metric_id)?;
        let declared = m.dimension_names();
        let mut dims = Vec::new();
        for g in group_by {
            if !declared.contains(g) {
                return Err(CatalogError::UnknownDimension {
                    metric: metric_id.to_string(),
                    dimension: g.to_string(),
                });
            }
            dims.push(g.to_string());
        }
        Ok(StructuredPlan {
            metric_id: m.id.clone(),
            source_view: m.source_view.clone(),
            group_by: dims,
            data_class_ceiling: m.data_class_ceiling,
            rls_predicate_ref: m.rls_predicate_ref.clone(),
            rls_scope: m.rls_scope.clone(),
            freshness_sla_seconds: m.freshness_sla_seconds,
        })
    }

    /// The catalog's **closed vocabulary** of plannable metric ids — every non-deprecated metric,
    /// sorted. This is the exact vocabulary a Stage-A proposal may ever reference (round-15
    /// `context-fabric` gap: "Stage-A constrained decoding from the catalog") — a deprecated metric
    /// is loaded (for lineage) but structurally cannot be proposed, so it is excluded here too.
    pub fn metric_ids(&self) -> Vec<String> {
        self.metrics
            .values()
            .filter(|m| !m.deprecated)
            .map(|m| m.id.clone())
            .collect()
    }

    /// Build the **grammar-constrained-decoding schema** (`ainxt_prompt::constrained::JsonSchema`,
    /// PE3/§4) for a Stage-A metric proposal: a `metric_id` field whose native decoder grammar is a
    /// **closed enum** over exactly [`metric_ids`](Self::metric_ids) — the model cannot even emit a
    /// token for a metric id outside the catalog, on a decoder that honors GBNF/native constrained
    /// decoding. Optional `group_by`/`filter_dimension` fields are left as free strings (their closed
    /// vocabulary is PER-metric, resolved after `metric_id` is known — [`MetricCatalog::plan`] is the
    /// second, metric-scoped validation gate); this schema closes the outer, always-closed half.
    pub fn constrained_intent_schema(&self) -> ainxt_prompt::constrained::JsonSchema {
        use ainxt_prompt::constrained::{FieldType, JsonSchema};
        JsonSchema::object([
            ("metric_id", FieldType::Enum(self.metric_ids()), true),
            ("group_by", FieldType::String, false),
            ("filter_dimension", FieldType::String, false),
            ("filter_value", FieldType::String, false),
        ])
    }
}

// ---------------------------------------------------------------------------------------
// Git-native control-plane loader (ADR-026) — round-15 `context-fabric` gap: "metric catalog as a
// git-native ADR-026 control-plane definition kind (files, CODEOWNERS, content-addressed,
// hot-reload) + load-time source_view introspection".
//
// This crate is deliberately pure/synchronous (no I/O — see the crate doc): `std::fs` is the
// CALLER's job (the served composition root walking `metrics/<id>/definition.json` on disk, exactly
// as `ainxt-prompt::control` does for prompts). What belongs HERE, pure and fully tested offline, is
// the definition KIND itself: parse each already-read file into a [`MetricDef`], content-address it
// (FNV-1a over the raw bytes) against a `control.lock`-shaped [`CatalogLock`] so a swapped/drifted
// definition fails closed before it ever reaches [`MetricCatalog::load`], cross-check the metric id
// against its own file's declared id (a directory/id mismatch is exactly the kind of git-review-time
// drift a lock cannot itself catch), and check `source_view` against a REGISTERED-views set (§2.1
// load-time introspection — extends the existing `v_*` naming check with "does this view actually
// exist", the same discipline `registered_rls` already applies to RLS policy refs). CODEOWNERS
// review/branch-protection/signed-tag enforcement remain git-host + CI concerns (infra), exactly as
// `ainxt-prompt::control`'s own doc states for prompts — this loader is the runtime end that
// consumes their output. "Hot-reload": every call is pure and returns a FRESH [`MetricCatalog`]; the
// caller atomically swaps it in — there is no in-place mutation of a live catalog to get wrong.
// -------------------------------------------------------------------------------------------------

/// One `definition.json` file the caller has already read from disk — `(directory name, raw
/// content)`. The directory name is the metric's expected id (ADR-026 §4: one directory = one
/// definition), checked against the parsed definition's own `id` field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogFile<'a> {
    pub dir_id: &'a str,
    pub json: &'a str,
}

/// `control.lock`'s in-memory form: metric id → the content fingerprint of its `definition.json`
/// (ADR-026 §6, content-addressed). Computed once at release time and committed to git; every
/// subsequent load re-derives the same fingerprints and must match, or the load fails closed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogLock {
    pub fingerprints: BTreeMap<String, String>,
}

impl CatalogLock {
    /// Compute the lock for a set of files — what a release job runs to (re)write `control.lock`.
    pub fn of(files: &[CatalogFile<'_>]) -> Self {
        let fingerprints = files
            .iter()
            .map(|f| (f.dir_id.to_string(), catalog_content_fingerprint(f.json)))
            .collect();
        CatalogLock { fingerprints }
    }
}

/// A stable FNV-1a-64 fingerprint over raw file bytes, rendered as lowercase hex — dependency-free
/// and deterministic across hosts/runs (unlike `DefaultHasher`), so a `control.lock` entry is a
/// durable content address.
fn catalog_content_fingerprint(content: &str) -> String {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;
    let mut h = FNV_OFFSET;
    for b in content.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    format!("{h:016x}")
}

/// Why the git-native control-plane load failed closed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CatalogLoadError {
    /// A `definition.json` did not parse as a [`MetricDef`].
    Parse { dir_id: String, error: String },
    /// The definition's own declared `id` does not match the directory it lives in — a
    /// git-review-time drift a content lock alone cannot catch.
    IdMismatch { dir_id: String, declared_id: String },
    /// A `source_view` the definition names is not in the registered-views set — §2.1 load-time
    /// introspection: the view must actually exist, not merely look like one by naming convention.
    UnregisteredSourceView { id: String, source_view: String },
    /// The definition declares an RLS policy but does NOT declare the row scope that policy
    /// enforces (§2.2.2 "a metric with no enforceable row-level security cannot load"). Without the
    /// declaration there is nothing to cross-check the compiled query's row scope against, so the
    /// metric could be compiled unscoped — the whole load fails closed instead.
    RlsPolicyWithoutScope { id: String, policy: String },
    /// The definition declares a row scope but names no RLS policy — the scope would be an
    /// unenforced comment. Refused so the two halves can never drift apart.
    RlsScopeWithoutPolicy { id: String },
    /// A declared row-scope column duplicates another, or is empty — an ambiguous scope declaration.
    InvalidRlsScope { id: String, column: String },
    /// A file on disk is not represented in the pinned `control.lock` — an undeclared addition.
    Unlocked { dir_id: String },
    /// A file's content fingerprint does not match its pinned lock entry — tamper/drift, never
    /// silently loaded.
    LockMismatch { dir_id: String },
    /// The definitions parsed and content-addressed cleanly, but [`MetricCatalog::load`]'s own
    /// all-or-nothing validation rejected the set (duplicate id, dangling RLS ref, etc.).
    Catalog(CatalogError),
}

/// The git-native control-plane loader (ADR-026): parse + content-address-verify + all-or-nothing
/// validate a set of already-read `definition.json` files into a hot-reloadable [`MetricCatalog`].
///
/// `lock`: `None` = bootstrap (no `control.lock` exists yet — every file is trusted as-is; the
/// caller commits the returned [`CatalogLock`] as the new `control.lock`). `Some` = every file MUST
/// appear in the lock with a matching fingerprint, or the WHOLE load fails closed (never a
/// half-loaded, silently-drifted catalog) — the same all-or-nothing discipline
/// [`MetricCatalog::load`] already applies to metric validity, extended to content integrity.
///
/// `registered_views`: the load-time `source_view` introspection set (§2.1) — a metric naming a view
/// outside this set is rejected before [`MetricCatalog::load`] even runs its own naming-convention
/// check, so "the view doesn't exist" and "the view isn't `v_*`-shaped" are BOTH caught at load time.
pub fn load_metrics_from_files(
    files: &[CatalogFile<'_>],
    lock: Option<&CatalogLock>,
    registered_rls: &BTreeSet<String>,
    registered_views: &BTreeSet<String>,
) -> Result<(MetricCatalog, CatalogLock), CatalogLoadError> {
    let mut metrics = Vec::with_capacity(files.len());
    for f in files {
        // Content-address verify BEFORE parsing even runs any further, so a tampered/drifted file
        // is caught by the cheapest possible check first.
        if let Some(lock) = lock {
            let actual = catalog_content_fingerprint(f.json);
            match lock.fingerprints.get(f.dir_id) {
                None => {
                    return Err(CatalogLoadError::Unlocked {
                        dir_id: f.dir_id.to_string(),
                    })
                }
                Some(expected) if *expected != actual => {
                    return Err(CatalogLoadError::LockMismatch {
                        dir_id: f.dir_id.to_string(),
                    })
                }
                Some(_) => {}
            }
        }
        let def: MetricDef = serde_json::from_str(f.json).map_err(|e| CatalogLoadError::Parse {
            dir_id: f.dir_id.to_string(),
            error: e.to_string(),
        })?;
        if def.id != f.dir_id {
            return Err(CatalogLoadError::IdMismatch {
                dir_id: f.dir_id.to_string(),
                declared_id: def.id.clone(),
            });
        }
        if !registered_views.contains(&def.source_view) {
            return Err(CatalogLoadError::UnregisteredSourceView {
                id: def.id.clone(),
                source_view: def.source_view.clone(),
            });
        }
        // §2.2.2 — "a metric with no ENFORCEABLE row-level security cannot load". A policy name
        // alone is not enforceable: nothing could then cross-check the compiled query's row scope
        // against it, so the metric could be compiled over an unscoped SELECT. Both halves, or the
        // whole load fails closed.
        match (&def.rls_predicate_ref, def.rls_scope.is_empty()) {
            (Some(policy), true) => {
                return Err(CatalogLoadError::RlsPolicyWithoutScope {
                    id: def.id.clone(),
                    policy: policy.clone(),
                })
            }
            (None, false) => {
                return Err(CatalogLoadError::RlsScopeWithoutPolicy { id: def.id.clone() })
            }
            _ => {}
        }
        let mut seen_scope_columns: BTreeSet<String> = BTreeSet::new();
        for s in &def.rls_scope {
            if s.column.trim().is_empty() || !seen_scope_columns.insert(s.column.clone()) {
                return Err(CatalogLoadError::InvalidRlsScope {
                    id: def.id.clone(),
                    column: s.column.clone(),
                });
            }
        }
        metrics.push(def);
    }
    let new_lock = CatalogLock::of(files);
    let catalog =
        MetricCatalog::load(metrics, registered_rls).map_err(CatalogLoadError::Catalog)?;
    Ok((catalog, new_lock))
}

/// A validated structured-query plan — the compiler's closed-vocabulary output. Names only a
/// curated view and only catalog dimensions; carries the data-class ceiling (for the Model Router)
/// and the RLS policy to activate. A downstream SQL compiler (`ainxt-nl2sql`) turns this into text;
/// no free-form SQL is ever produced from an intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuredPlan {
    pub metric_id: String,
    pub source_view: String,
    pub group_by: Vec<String>,
    pub data_class_ceiling: DataClass,
    pub rls_predicate_ref: Option<String>,
    /// The row scope the metric's declared RLS policy enforces (§2.2.2), carried onto the plan so
    /// the SQL compiler can cross-check it against the row scope it actually compiles in — the
    /// check that stops a metric silently widening its own row scope.
    #[serde(default)]
    pub rls_scope: Vec<RlsScopeBinding>,
    /// The metric's read-replica freshness SLA in logical seconds (§2.1) — carried onto the plan so
    /// the executor can decide, from monitored replica lag, whether to flag the result `stale_as_of`
    /// (§3.1) without re-reading the catalog.
    #[serde(default = "default_freshness_sla")]
    pub freshness_sla_seconds: i64,
}

// ---------------------------------------------------------------------------------------
// Row-level security: SET LOCAL session context from the OBO principal (§3)
// ---------------------------------------------------------------------------------------

/// Where a `SET LOCAL` session variable's value is sourced from — always the OBO caller context,
/// never a literal the model chose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "from", rename_all = "snake_case")]
pub enum SessionVarSource {
    /// The caller's department (`ctx.department`).
    Department,
    /// The caller's AD seniority level (`ctx.ad_level`).
    AdLevel,
}

/// A named Postgres RLS policy and the session variables its predicate reads. The policy itself
/// lives in the database (validated to exist at catalog load); this binds each `SET LOCAL` var
/// name to the OBO source that fills it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RlsPolicy {
    pub predicate_ref: String,
    /// `(session_var_name, source)` — e.g. `("app.dept", Department)`.
    pub vars: Vec<(String, SessionVarSource)>,
}

impl RlsPolicy {
    pub fn new(predicate_ref: &str) -> Self {
        RlsPolicy {
            predicate_ref: predicate_ref.to_string(),
            vars: Vec::new(),
        }
    }

    pub fn var(mut self, name: &str, source: SessionVarSource) -> Self {
        self.vars.push((name.to_string(), source));
        self
    }
}

/// Why RLS session-context derivation aborted — always fail-closed (never run without the vars).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RlsError {
    /// A required session variable could not be sourced from the OBO context — the query must NOT
    /// run, because Postgres RLS with an unset `current_setting` would return no rows or (worse, if
    /// the policy defaults permissively) all rows. Abort instead.
    MissingClaim { var: String },
}

/// The `SET LOCAL` session context to apply on the RLS-enabled connection before the query, plus
/// the read-replica freshness watermark (§3.1) so a stale replica read is never presented as
/// current.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionContext {
    /// `(name, value)` pairs, sorted by name — the `SET LOCAL name = value` statements.
    pub settings: Vec<(String, String)>,
    /// The replica's `stale_as_of` logical tick (`None` when reading the primary / fresh).
    pub stale_as_of: Option<i64>,
}

impl SessionContext {
    /// Render as the literal `SET LOCAL` statements a connection would execute (for audit/debug).
    ///
    /// **Every value is quoted through [`quote_pg_literal`] and every variable name is validated
    /// through [`is_valid_session_var_name`]** — the RLS binding is the one statement in the system
    /// that must not be forgeable, so a value carrying `'`, `\`, a newline or a statement separator
    /// can never terminate the literal and append SQL. If ANY name/value is unbindable the whole
    /// vector comes back **empty** (never a partially-bound context), which every executor here
    /// treats as "refuse to run" for a policied plan. Use
    /// [`set_local_statements_checked`](Self::set_local_statements_checked) when you need the reason.
    pub fn set_local_statements(&self) -> Vec<String> {
        self.set_local_statements_checked().unwrap_or_default()
    }

    /// The fail-closed form of [`set_local_statements`](Self::set_local_statements): returns the
    /// exact [`RlsBindingError`] instead of collapsing to an empty vector.
    pub fn set_local_statements_checked(&self) -> Result<Vec<String>, RlsBindingError> {
        self.bindings().map(|bs| {
            bs.iter()
                .map(SetConfigBinding::set_local_statement)
                .collect()
        })
    }

    /// The **parameterized** form of the RLS binding (the production path): one
    /// `SELECT set_config($1, $2, true)` per session variable, with the variable name and its
    /// OBO-sourced value carried as *bound parameters*, never interpolated into SQL text. This is
    /// what makes the binding structurally un-forgeable: there is no string concatenation for an
    /// attacker-influenced value to escape from. The name is still validated (a GUC name is not a
    /// bindable parameter of the `SET LOCAL` grammar, so the two forms must agree on legality).
    pub fn bindings(&self) -> Result<Vec<SetConfigBinding>, RlsBindingError> {
        self.settings
            .iter()
            .map(|(k, v)| SetConfigBinding::new(k, v))
            .collect()
    }
}

// ---------------------------------------------------------------------------------------
// Un-forgeable RLS session binding (§3) — no interpolation of an OBO-sourced value into SQL
// ---------------------------------------------------------------------------------------

/// Why binding the RLS session context onto a connection was refused. Fail-closed: a refusal means
/// the query does NOT run (an unbound `current_setting` under a permissive policy default would be
/// an unscoped read), it never means "run without the scope".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RlsBindingError {
    /// The session variable name is not a legal, safe GUC name (`namespace.name`, ASCII
    /// lowercase/digits/underscore). A GUC name cannot be a bound parameter of `SET LOCAL`, so it is
    /// allow-listed by shape rather than escaped.
    InvalidVarName { var: String },
    /// The value cannot be represented as a Postgres string literal at all (it carries a NUL byte,
    /// which no Postgres text value may contain). Everything else — quotes, backslashes, newlines,
    /// semicolons, unicode — is legal data and is *escaped*, never rejected: the binding must not
    /// become a hard block on a legitimately-punctuated department name.
    InvalidValue { var: String, reason: String },
}

impl std::fmt::Display for RlsBindingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RlsBindingError::InvalidVarName { var } => {
                write!(f, "illegal RLS session variable name {var:?}")
            }
            RlsBindingError::InvalidValue { var, reason } => {
                write!(f, "unbindable RLS session value for {var:?}: {reason}")
            }
        }
    }
}

impl std::error::Error for RlsBindingError {}

/// Maximum length of one dot-separated segment of a GUC name (Postgres `NAMEDATALEN - 1`).
const MAX_GUC_SEGMENT: usize = 63;

/// Is `name` a legal, safe RLS session-variable (custom GUC) name? A custom GUC MUST be
/// `namespace.name` (Postgres refuses an un-namespaced unknown parameter), and we additionally
/// restrict both segments to ASCII `[a-z_][a-z0-9_]*` so the name can be inlined into `SET LOCAL`
/// with zero escaping ambiguity. Anything else — an embedded quote, space, semicolon, comment
/// marker, uppercase-folding trick or non-ASCII homoglyph — is refused.
pub fn is_valid_session_var_name(name: &str) -> bool {
    let mut segments = name.split('.');
    let (Some(ns), Some(key)) = (segments.next(), segments.next()) else {
        return false;
    };
    if segments.next().is_some() {
        return false; // exactly one dot: `app.dept`, never `app.dept.extra`
    }
    let ok_segment = |s: &str| {
        !s.is_empty()
            && s.len() <= MAX_GUC_SEGMENT
            && s.starts_with(|c: char| c.is_ascii_lowercase() || c == '_')
            && s.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    };
    ok_segment(ns) && ok_segment(key)
}

/// Quote an arbitrary value as a Postgres string literal, the way `libpq`'s `PQescapeLiteral` does.
///
/// * `'` is doubled (`''`) — the only way to end a literal, so it can never be produced by data.
/// * A value containing `\` is emitted as an **E-string** (`E'...'`) with backslashes doubled, so
///   the quoting is correct under BOTH `standard_conforming_strings=on` (the default) and `off` — a
///   deployment that flips that GUC must not silently re-open the injection.
/// * Newlines, semicolons, comment markers (`--`, `/*`) and any unicode are *data* inside the
///   literal and are preserved verbatim; they cannot escape it.
/// * A NUL byte is the one value Postgres text cannot carry at all → refused (fail-closed).
pub fn quote_pg_literal(value: &str) -> Result<String, &'static str> {
    if value.contains('\0') {
        return Err("value contains a NUL byte");
    }
    let needs_e = value.contains('\\');
    let mut out = String::with_capacity(value.len() + 4);
    if needs_e {
        out.push('E');
    }
    out.push('\'');
    for ch in value.chars() {
        match ch {
            '\'' => out.push_str("''"),
            '\\' if needs_e => out.push_str("\\\\"),
            c => out.push(c),
        }
    }
    out.push('\'');
    Ok(out)
}

/// One validated RLS session-variable binding. Constructing it is the *only* way to get a rendered
/// binding out of this crate, so validation/escaping cannot be skipped by a caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetConfigBinding {
    var: String,
    value: String,
    /// The value pre-rendered as a Postgres string literal (computed once, at validation time).
    escaped: String,
}

impl SetConfigBinding {
    /// The constant, parameterized statement text — identical for every binding, with NO caller
    /// data in it. `$1` = the GUC name, `$2` = its value, `true` = transaction-local (`SET LOCAL`).
    pub const SET_CONFIG_SQL: &'static str = "SELECT set_config($1, $2, true)";

    /// Validate a `(name, value)` pair and pre-render its literal. Fail-closed on an illegal name or
    /// an unrepresentable value.
    pub fn new(var: &str, value: &str) -> Result<Self, RlsBindingError> {
        if !is_valid_session_var_name(var) {
            return Err(RlsBindingError::InvalidVarName {
                var: var.to_string(),
            });
        }
        let escaped = quote_pg_literal(value).map_err(|reason| RlsBindingError::InvalidValue {
            var: var.to_string(),
            reason: reason.to_string(),
        })?;
        Ok(SetConfigBinding {
            var: var.to_string(),
            value: value.to_string(),
            escaped,
        })
    }

    pub fn var(&self) -> &str {
        &self.var
    }

    /// The RAW, un-escaped value — this is what a parameterized driver binds to `$2`.
    pub fn value(&self) -> &str {
        &self.value
    }

    /// The parameters for [`SET_CONFIG_SQL`](Self::SET_CONFIG_SQL), in order.
    pub fn params(&self) -> [&str; 2] {
        [&self.var, &self.value]
    }

    /// The escaped `SET LOCAL` statement, for drivers/audit paths that cannot bind parameters to a
    /// `SET LOCAL`. The value is a correctly-quoted literal, so this is safe — but the parameterized
    /// [`SET_CONFIG_SQL`](Self::SET_CONFIG_SQL) form is preferred wherever the driver allows it.
    pub fn set_local_statement(&self) -> String {
        format!("SET LOCAL {} = {}", self.var, self.escaped)
    }
}

/// Derive the `SET LOCAL` session context an RLS predicate needs, from the OBO [`AccessContext`].
/// Fail-closed: if any required variable cannot be sourced (e.g. the policy needs a department but
/// the caller has none), returns [`RlsError::MissingClaim`] and the caller MUST abort — the query
/// never runs against RLS with a missing session var.
pub fn build_session_context(
    policy: &RlsPolicy,
    ctx: &AccessContext,
    stale_as_of: Option<i64>,
) -> Result<SessionContext, RlsError> {
    let mut settings: Vec<(String, String)> = Vec::new();
    for (name, source) in &policy.vars {
        let value = match source {
            SessionVarSource::Department => ctx
                .department
                .clone()
                .ok_or_else(|| RlsError::MissingClaim { var: name.clone() })?,
            SessionVarSource::AdLevel => ctx
                .ad_level
                .map(|l| l.to_string())
                .ok_or_else(|| RlsError::MissingClaim { var: name.clone() })?,
        };
        settings.push((name.clone(), value));
    }
    settings.sort();
    Ok(SessionContext {
        settings,
        stale_as_of,
    })
}

/// A monitored read-replica lag reading (`STRUCTURED_FEDERATED_RETRIEVAL.md` §3.1): how far behind
/// the primary the replica the query will run on currently is, in logical seconds, plus the logical
/// `now` tick. In production `replica_lag_seconds` comes from the replica-lag metric the connection
/// pool monitors per view (e.g. `pg_last_wal_replay_lsn` / streaming-replication delay); here it is a
/// plain input so the freshness decision is a pure, testable function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicaLag {
    /// Seconds the replica trails the primary. Negative readings are clamped to 0 (never "fresher
    /// than now").
    pub replica_lag_seconds: i64,
    /// The current logical tick (seconds) the freshness watermark is computed against.
    pub now: i64,
}

impl ReplicaLag {
    pub fn new(replica_lag_seconds: i64, now: i64) -> Self {
        ReplicaLag {
            replica_lag_seconds: replica_lag_seconds.max(0),
            now,
        }
    }
}

/// Compute the `stale_as_of` watermark for a metric from the **monitored replica lag** vs the
/// metric's `freshness_sla_seconds` (`STRUCTURED_FEDERATED_RETRIEVAL.md` §3.1). This is the design's
/// "never silently serve stale settlement data as current" rule made concrete: if the replica's lag
/// is within the SLA, the read is fresh (`None`); if it exceeds the SLA, the result MUST carry the
/// replica's watermark (`now - lag`) so the answer is presented as "as of <ts>", not as current.
///
/// The comparison is strict-greater (`lag > sla`): a lag exactly at the SLA is still within budget.
pub fn stale_as_of_from_lag(lag: ReplicaLag, freshness_sla_seconds: i64) -> Option<i64> {
    if lag.replica_lag_seconds > freshness_sla_seconds {
        Some(lag.now - lag.replica_lag_seconds)
    } else {
        None
    }
}

/// Derive the RLS session context AND its freshness watermark in one step (§3 + §3.1): build the
/// `SET LOCAL` context from the OBO [`AccessContext`] (fail-closed on a missing claim, exactly like
/// [`build_session_context`]) and compute `stale_as_of` from the **monitored replica lag** vs the
/// plan's `freshness_sla_seconds` — so a stale replica read is flagged, never presented as current.
pub fn build_session_context_monitored(
    policy: &RlsPolicy,
    ctx: &AccessContext,
    plan: &StructuredPlan,
    lag: ReplicaLag,
) -> Result<SessionContext, RlsError> {
    let stale_as_of = stale_as_of_from_lag(lag, plan.freshness_sla_seconds);
    build_session_context(policy, ctx, stale_as_of)
}

/// The read-replica execution seam (`STRUCTURED_FEDERATED_RETRIEVAL.md` §3): a real deployment
/// implements this against a Postgres read replica with the derived [`SessionContext`] applied via
/// `SET LOCAL` and native ROW LEVEL SECURITY doing the filtering. The runtime never sees a row RLS
/// would hide. Returning rows is the ONLY thing infra does; the derivation + fail-closed contract
/// above is enforced here.
pub trait RlsExecutor {
    /// Execute the plan on an RLS-enabled connection carrying `session` and return the visible
    /// rows (already row-filtered by Postgres). `None` = replica/connection error (fail-closed).
    fn execute(&self, plan: &StructuredPlan, session: &SessionContext) -> Option<Vec<Row>>;
}

/// One returned row — an ordered list of `(column, value)` pairs (kept simple + serializable;
/// the structured surface projects these into the answer).
pub type Row = Vec<(String, String)>;

/// A reference, offline row-filter that applies an RLS predicate the same way Postgres would —
/// used to *prove* the derived session context actually excludes out-of-scope rows without a live
/// database. It filters an in-memory table to rows whose `scope_column` equals the session var the
/// policy binds it to. This is a fixture/oracle for the seam, not the production path.
#[derive(Debug, Clone)]
pub struct RowFilter {
    /// The table rows (each a `Row`).
    pub rows: Vec<Row>,
    /// The column the RLS predicate scopes on and the session var it must equal.
    pub scope_column: String,
    pub scope_var: String,
}

impl RlsExecutor for RowFilter {
    fn execute(&self, _plan: &StructuredPlan, session: &SessionContext) -> Option<Vec<Row>> {
        // The RLS predicate compares `scope_column` to the SET LOCAL `scope_var`. If the var is
        // absent from the session context, RLS would hide everything — return an empty set
        // (fail-closed), never the full table.
        let scope_value = session
            .settings
            .iter()
            .find(|(k, _)| k == &self.scope_var)
            .map(|(_, v)| v.clone());
        let scope_value = scope_value?; // no scope var → no rows
        let visible = self
            .rows
            .iter()
            .filter(|row| {
                row.iter()
                    .any(|(c, v)| c == &self.scope_column && v == &scope_value)
            })
            .cloned()
            .collect();
        Some(visible)
    }
}

// ---------------------------------------------------------------------------------------
// DB-native Postgres RLS seam (§3) — INFRA-GATED (live read replica) with an offline oracle
// ---------------------------------------------------------------------------------------

/// The live-Postgres connection seam a real deployment implements against a **read replica**: apply
/// the derived `SET LOCAL` session settings on the connection's current transaction, then run the
/// plan's query so native ROW LEVEL SECURITY does the filtering, and return only the rows RLS lets
/// through. `None` = a connection/replica error — the caller fail-closes (never falls back to an
/// unscoped read).
///
/// This is the ONLY piece that needs live infrastructure. A production impl wraps a
/// `tokio-postgres` / `deadpool-postgres` connection to a replica whose curated views carry the
/// RLS policies named by [`StructuredPlan::rls_predicate_ref`]; it is deliberately kept out of this
/// (permissive-only, DB-free) crate so no Postgres client dep enters the supply-chain surface here.
pub trait RlsConnection {
    /// Run `SET LOCAL <k> = <quoted v>` for each statement, then the plan's query, on one
    /// RLS-enabled transaction. Returns the RLS-filtered rows, or `None` on any connection/replica
    /// error. Every statement handed here has already been rendered through
    /// [`SetConfigBinding::set_local_statement`], so its value is a correctly-escaped literal.
    fn set_local_and_query(&self, set_local: &[String], plan: &StructuredPlan) -> Option<Vec<Row>>;

    /// The **preferred, parameterized** binding path: execute
    /// [`SetConfigBinding::SET_CONFIG_SQL`] once per binding with `params()` bound by the driver
    /// (zero SQL-text interpolation of an OBO-sourced value), then the plan's query, on one
    /// RLS-enabled transaction.
    ///
    /// The default implementation renders the escaped `SET LOCAL` statements and delegates to
    /// [`set_local_and_query`](Self::set_local_and_query), so an existing connection impl keeps
    /// working unchanged; a production `tokio-postgres` impl should override this and bind `$1`/`$2`.
    fn set_config_and_query(
        &self,
        bindings: &[SetConfigBinding],
        plan: &StructuredPlan,
    ) -> Option<Vec<Row>> {
        let statements: Vec<String> = bindings
            .iter()
            .map(SetConfigBinding::set_local_statement)
            .collect();
        self.set_local_and_query(&statements, plan)
    }
}

/// The DB-native RLS executor (`STRUCTURED_FEDERATED_RETRIEVAL.md` §3): binds the derived
/// [`SessionContext`] to a Postgres read replica via `SET LOCAL` and lets native ROW LEVEL SECURITY
/// filter every row — the runtime never sees a row RLS would hide. It is the production complement
/// to the offline reference [`RowFilter`]: same [`RlsExecutor`] contract, but the filtering happens
/// in the database, not in-process.
///
/// **INFRA-GATED.** The live path requires a Postgres read replica with the RLS policies installed
/// (deferred to infra). The *binding contract* — never query without the `SET LOCAL` vars the RLS
/// predicate reads, fail-closed otherwise — is enforced here and proven offline against an in-memory
/// [`RlsConnection`] that mirrors Postgres RLS semantics, so the seam is exercised without a live DB.
pub struct PostgresRlsExecutor<C: RlsConnection> {
    conn: C,
}

impl<C: RlsConnection> PostgresRlsExecutor<C> {
    pub fn new(conn: C) -> Self {
        PostgresRlsExecutor { conn }
    }
}

impl<C: RlsConnection> RlsExecutor for PostgresRlsExecutor<C> {
    fn execute(&self, plan: &StructuredPlan, session: &SessionContext) -> Option<Vec<Row>> {
        // Fail-closed binding invariant: if the plan activates an RLS policy, the query must NOT run
        // without the `SET LOCAL` session vars that policy reads — an unset `current_setting` would
        // let a permissive policy default return all rows. No vars for a policied plan → refuse.
        if plan.rls_predicate_ref.is_some() && session.settings.is_empty() {
            return None;
        }
        // Un-forgeable binding: build validated, parameterized bindings. An illegal GUC name or an
        // unrepresentable value refuses the query outright rather than emitting a forged statement.
        let bindings = session.bindings().ok()?;
        self.conn.set_config_and_query(&bindings, plan)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rls_set(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    fn settlement_metric() -> MetricDef {
        MetricDef::new(
            "failed_settlement_count",
            "v_settlement_failures_curated",
            DataClass::Confidential,
        )
        .dimension("bank_id", DataClass::Internal)
        .dimension("failure_reason_class", DataClass::Internal)
        .rls("rls_settlement_by_dept")
        // §2.2.2: an RLS policy is only ENFORCEABLE if the metric also declares the row scope
        // that policy applies, so the compiler can cross-check it against the SQL it emits.
        .rls_scope("owner_dept", ScopeAttr::Department)
    }

    #[test]
    fn catalog_load_is_all_or_nothing() {
        let good = MetricCatalog::load(
            vec![settlement_metric()],
            &rls_set(&["rls_settlement_by_dept"]),
        );
        assert!(good.is_ok());

        // A base table (not a v_* view) rejects the WHOLE load.
        let bad_view = MetricDef::new("x", "settlements_base", DataClass::Internal)
            .dimension("bank_id", DataClass::Internal);
        let res = MetricCatalog::load(
            vec![settlement_metric(), bad_view],
            &rls_set(&["rls_settlement_by_dept"]),
        );
        assert!(matches!(res, Err(CatalogError::InvalidSourceView { .. })));

        // A dangling RLS ref rejects the whole load (no silent unscoped view).
        let dangling = MetricCatalog::load(vec![settlement_metric()], &rls_set(&[]));
        assert!(matches!(
            dangling,
            Err(CatalogError::UnknownRlsPolicy { .. })
        ));
    }

    #[test]
    fn plan_is_closed_vocabulary() {
        let cat = MetricCatalog::load(
            vec![settlement_metric()],
            &rls_set(&["rls_settlement_by_dept"]),
        )
        .unwrap();
        // A catalog metric + declared dimension compiles.
        let plan = cat.plan("failed_settlement_count", &["bank_id"]).unwrap();
        assert_eq!(plan.source_view, "v_settlement_failures_curated");
        assert_eq!(plan.data_class_ceiling, DataClass::Confidential);
        // A metric NOT in the catalog does not exist to the compiler.
        assert!(matches!(
            cat.plan("drop_table_users", &[]),
            Err(CatalogError::UnknownMetric { .. })
        ));
        // A dimension not declared on the metric is refused.
        assert!(matches!(
            cat.plan("failed_settlement_count", &["customer_pan"]),
            Err(CatalogError::UnknownDimension { .. })
        ));
    }

    #[test]
    fn deprecated_metric_cannot_be_planned() {
        let cat = MetricCatalog::load(
            vec![settlement_metric().deprecated(true)],
            &rls_set(&["rls_settlement_by_dept"]),
        )
        .unwrap();
        assert!(matches!(
            cat.plan("failed_settlement_count", &[]),
            Err(CatalogError::DeprecatedMetric { .. })
        ));
    }

    #[test]
    fn rls_session_context_is_fail_closed_on_missing_claim() {
        let policy =
            RlsPolicy::new("rls_settlement_by_dept").var("app.dept", SessionVarSource::Department);
        // With a department the SET LOCAL var is derived.
        let ok_ctx = AccessContext::new(DataClass::Confidential, Some("settlement-eng"), None, &[]);
        let session = build_session_context(&policy, &ok_ctx, Some(42)).unwrap();
        assert_eq!(
            session.settings,
            vec![("app.dept".to_string(), "settlement-eng".to_string())]
        );
        assert_eq!(session.stale_as_of, Some(42));
        assert_eq!(
            session.set_local_statements(),
            vec!["SET LOCAL app.dept = 'settlement-eng'"]
        );

        // Without a department the query MUST abort — never run RLS with an unset session var.
        let no_dept = AccessContext::new(DataClass::Confidential, None, None, &[]);
        assert_eq!(
            build_session_context(&policy, &no_dept, None),
            Err(RlsError::MissingClaim {
                var: "app.dept".to_string()
            })
        );
    }

    #[test]
    fn gap_ctx_07_metric_catalog_is_the_closed_vocabulary() {
        // Would FAIL before this change: no catalog / closed-vocab compiler existed in the crate.
        let cat = MetricCatalog::load(
            vec![settlement_metric()],
            &rls_set(&["rls_settlement_by_dept"]),
        )
        .unwrap();
        // A catalog metric compiles to a curated view with its data-class ceiling + RLS ref.
        let plan = cat
            .plan(
                "failed_settlement_count",
                &["bank_id", "failure_reason_class"],
            )
            .unwrap();
        assert_eq!(plan.source_view, "v_settlement_failures_curated");
        assert_eq!(
            plan.rls_predicate_ref.as_deref(),
            Some("rls_settlement_by_dept")
        );
        // Anything outside the vocabulary structurally does not exist — no free-form SQL possible.
        assert!(cat.plan("arbitrary_metric", &[]).is_err());
        assert!(cat.plan("failed_settlement_count", &["ssn"]).is_err());
    }

    #[test]
    fn gap_ctx_05_rls_row_filter_scopes_rows_by_obo_session_context() {
        // Would FAIL before this change: no RLS / SET LOCAL / row-filter logic existed.
        let cat = MetricCatalog::load(
            vec![settlement_metric()],
            &rls_set(&["rls_settlement_by_dept"]),
        )
        .unwrap();
        let plan = cat.plan("failed_settlement_count", &["bank_id"]).unwrap();
        let policy =
            RlsPolicy::new("rls_settlement_by_dept").var("app.dept", SessionVarSource::Department);

        // An in-memory "curated view" with rows owned by two departments.
        let rows: Vec<Row> = vec![
            vec![
                ("dept".into(), "settlement-eng".into()),
                ("count".into(), "12".into()),
            ],
            vec![
                ("dept".into(), "settlement-eng".into()),
                ("count".into(), "7".into()),
            ],
            vec![("dept".into(), "hr".into()), ("count".into(), "99".into())],
        ];
        let executor = RowFilter {
            rows,
            scope_column: "dept".into(),
            scope_var: "app.dept".into(),
        };

        // A settlement-eng caller: SET LOCAL app.dept='settlement-eng' → only their 2 rows.
        let ctx = AccessContext::new(DataClass::Confidential, Some("settlement-eng"), None, &[]);
        let session = build_session_context(&policy, &ctx, Some(500)).unwrap();
        let visible = executor.execute(&plan, &session).expect("rows");
        assert_eq!(visible.len(), 2, "RLS must hide the hr department's row");
        assert!(visible
            .iter()
            .all(|r| r.iter().any(|(c, v)| c == "dept" && v == "settlement-eng")));

        // A caller with no department is aborted before any row is touched (fail-closed).
        let no_dept = AccessContext::new(DataClass::Confidential, None, None, &[]);
        assert!(matches!(
            build_session_context(&policy, &no_dept, None),
            Err(RlsError::MissingClaim { .. })
        ));
    }

    #[test]
    fn r15_metric_ids_are_the_closed_vocabulary_excluding_deprecated() {
        let deprecated = MetricDef::new("old_metric", "v_old", DataClass::Internal)
            .dimension("bank_id", DataClass::Internal)
            .deprecated(true);
        let cat = MetricCatalog::load(
            vec![settlement_metric(), deprecated],
            &rls_set(&["rls_settlement_by_dept"]),
        )
        .unwrap();
        // Loaded (for lineage) but excluded from the plannable/proposable vocabulary.
        assert_eq!(
            cat.metric_ids(),
            vec!["failed_settlement_count".to_string()]
        );
    }

    #[test]
    fn r15_constrained_intent_schema_locks_metric_id_to_the_catalog_enum() {
        use ainxt_prompt::constrained::FieldType;
        let cat = MetricCatalog::load(
            vec![settlement_metric()],
            &rls_set(&["rls_settlement_by_dept"]),
        )
        .unwrap();
        let schema = cat.constrained_intent_schema();
        let metric_field = schema
            .fields
            .get("metric_id")
            .expect("metric_id field present");
        assert_eq!(
            metric_field.ty,
            FieldType::Enum(vec!["failed_settlement_count".to_string()])
        );
        assert!(schema.required.contains(&"metric_id".to_string()));

        // A proposal naming a metric OUTSIDE the catalog fails validation — the model cannot even
        // reach the catalog/compiler stages with a made-up id (defense-in-depth ahead of `plan()`).
        let bad = r#"{"metric_id":"not_a_real_metric"}"#;
        assert!(schema.validate(bad).is_err());
        let good = r#"{"metric_id":"failed_settlement_count"}"#;
        assert!(schema.validate(good).is_ok());
    }

    fn settlement_definition_json() -> String {
        serde_json::to_string(&settlement_metric()).unwrap()
    }

    #[test]
    fn r15_git_native_loader_bootstraps_a_lock_and_hot_reloads_identically() {
        let json = settlement_definition_json();
        let files = vec![CatalogFile {
            dir_id: "failed_settlement_count",
            json: &json,
        }];
        let rls = rls_set(&["rls_settlement_by_dept"]);
        let mut views = BTreeSet::new();
        views.insert("v_settlement_failures_curated".to_string());

        // Bootstrap: no lock yet — the load trusts the files and MINTS the lock a release job
        // would commit as `control.lock`.
        let (catalog, lock) = load_metrics_from_files(&files, None, &rls, &views).unwrap();
        assert_eq!(
            catalog.metric_ids(),
            vec!["failed_settlement_count".to_string()]
        );
        assert!(lock.fingerprints.contains_key("failed_settlement_count"));

        // "Hot-reload": calling again with the SAME files + the now-pinned lock produces an
        // identical, freshly-built catalog — a pure function, never an in-place mutation.
        let (catalog2, lock2) = load_metrics_from_files(&files, Some(&lock), &rls, &views).unwrap();
        assert_eq!(catalog, catalog2);
        assert_eq!(lock, lock2);
    }

    #[test]
    fn r15_git_native_loader_fails_closed_on_drift_id_mismatch_and_unregistered_view() {
        let json = settlement_definition_json();
        let rls = rls_set(&["rls_settlement_by_dept"]);
        let mut views = BTreeSet::new();
        views.insert("v_settlement_failures_curated".to_string());

        // A file whose directory name does NOT match its declared `id` — a git-review-time drift a
        // content lock alone would never catch (the content itself is perfectly valid).
        let mismatched = vec![CatalogFile {
            dir_id: "wrong_directory_name",
            json: &json,
        }];
        let err = load_metrics_from_files(&mismatched, None, &rls, &views).unwrap_err();
        assert!(matches!(err, CatalogLoadError::IdMismatch { .. }));

        // A `source_view` NOT in the registered-views set — load-time introspection catches a view
        // that merely LOOKS curated (passes the `v_*` naming check) but does not actually exist.
        let files = vec![CatalogFile {
            dir_id: "failed_settlement_count",
            json: &json,
        }];
        let empty_views: BTreeSet<String> = BTreeSet::new();
        let err2 = load_metrics_from_files(&files, None, &rls, &empty_views).unwrap_err();
        assert!(matches!(
            err2,
            CatalogLoadError::UnregisteredSourceView { .. }
        ));

        // Tamper/drift: the pinned lock was minted over the ORIGINAL content; a byte-changed file
        // (even a cosmetic whitespace change) must fail closed, never silently reload the new bytes.
        let (_, lock) = load_metrics_from_files(&files, None, &rls, &views).unwrap();
        let tampered_json = format!("{json} ");
        let tampered = vec![CatalogFile {
            dir_id: "failed_settlement_count",
            json: &tampered_json,
        }];
        let err3 = load_metrics_from_files(&tampered, Some(&lock), &rls, &views).unwrap_err();
        assert!(matches!(err3, CatalogLoadError::LockMismatch { .. }));

        // A file present on disk but ABSENT from the pinned lock (an undeclared addition) also
        // fails closed.
        let other_json = serde_json::to_string(
            &MetricDef::new("other_metric", "v_other", DataClass::Internal)
                .dimension("x", DataClass::Internal),
        )
        .unwrap();
        let mut with_extra = files.clone();
        with_extra.push(CatalogFile {
            dir_id: "other_metric",
            json: &other_json,
        });
        let err4 = load_metrics_from_files(&with_extra, Some(&lock), &rls, &views).unwrap_err();
        assert!(matches!(err4, CatalogLoadError::Unlocked { .. }));
    }
}
