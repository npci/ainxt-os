// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! ainxt-nl2sql — the safe natural-language-to-SQL boundary.
//!
//! Design lineage: the data-class → clearance model of ADR-012 (residency / read-authorization)
//! applied to a *query surface* rather than a routing surface.
//!
//! # The threat this crate exists to kill
//!
//! An agent that can turn a user's words into a database query is a mission-differentiating
//! capability over structured ledger / reporting data — and a catastrophic one if done naively.
//! The moment a model is allowed to emit **raw SQL**, three attacks become live on a payments
//! platform:
//!
//! 1. **Exfiltration / mutation** — a crafted (or prompt-injected) query reads far more than the
//!    question needs, or worse mutates the ledger (`UPDATE`, `DELETE`, `DROP`), or stacks a second
//!    statement after a `;`.
//! 2. **Injection** — a filter value the user controls (`'; DROP TABLE settlements; --`) breaks
//!    out of its string literal and becomes code.
//! 3. **Over-privilege read** — the query touches a column above the caller's clearance (a PAN, an
//!    account number), leaking regulated data the principal was never authorized to see.
//!
//! This crate's answer is to **never let a model emit SQL at all**. The model proposes a
//! [`QueryIntent`] — a structured, `SELECT`-only description of what it wants. There is no field in
//! which a verb, a raw fragment, or a second statement can be expressed; mutation is *unrepresentable*
//! in the type system (see the module note "Why mutation is impossible" below). This crate then
//! [`validate_and_compile`]s that intent against a [`Schema`] allowlist and a [`Principal`], and only
//! then produces a [`SafeQuery`] — bounded, parameterized SQL plus its out-of-band params.
//!
//! # The four structural guarantees
//!
//! * **Allowlist identifiers.** Every table and column named in an intent must exist in the
//!   [`Schema`]. Identifiers are validated at *schema-build* time to a strict `[A-Za-z_][A-Za-z0-9_]*`
//!   grammar, so even a mis-configured allowlist cannot smuggle a quote, a space, or a `;` into the
//!   emitted SQL. Free text from the user is **never** used as an identifier.
//! * **Parameterized values.** Filter values are carried out-of-band in [`SafeQuery::params`] and
//!   referenced in the SQL only as `$1`, `$2`, … placeholders. A [`Value`] has *no* method that
//!   renders it into SQL — so a value physically cannot be interpolated. Injection is therefore
//!   structural, not stylistic: there is no code path that concatenates a user value into the query.
//! * **Pre-authorization without existence leak.** A column that is unknown *or* above the
//!   principal's clearance yields the **same** [`QueryError::ColumnNotAvailable`]. An under-cleared
//!   caller cannot use error shape as an oracle to enumerate which sensitive columns exist (ADR-012).
//!   Clearance is checked on `SELECT`, `WHERE` **and** `ORDER BY` columns — ordering by a hidden
//!   column leaks its values just as surely as selecting it.
//! * **Bounded results.** Every compiled query carries a `LIMIT`. A missing or oversized limit is
//!   clamped down to the schema's configured maximum; there is no way to ask for an unbounded scan.
//!
//! # Row-level security (principal-scoped rows)
//!
//! Column clearance ([`DataClass`]) governs *which columns* a caller may read. It says nothing about
//! *which rows*. A settlement-ops analyst cleared to read `amount_minor` must still see only **their
//! own department's** rows, never every bank's. That is [row-level security](RowScope): a table
//! declares one or more [`RowScope`] rules binding a column (e.g. `owner_dept`) to a
//! [`PrincipalAttr`] (the caller's `department` or `user_id`). At compile time this crate injects the
//! matching predicate (`"owner_dept" = $n`, value taken from the *principal*, never the model) as an
//! extra `AND` conjunct on **every** query over that table. The row filter is therefore:
//!
//! * **Un-bypassable** — the model's [`QueryIntent`] has no field that can drop, weaken, or overwrite
//!   it; it is added by the compiler after the model's filters, always.
//! * **Fail-closed** — if the policy needs an attribute the principal does not carry (a caller with
//!   no `department` over a department-scoped table), compilation is *refused*
//!   ([`QueryError::RowScopeUnavailable`]) rather than emitting an unscoped full-table scan.
//! * **No admin bypass** — row scope is applied uniformly; there is deliberately no clearance/role
//!   that turns it off, because "see all rows" is exactly the cross-tenant leak this exists to stop.
//!
//! As defense-in-depth for a database that *also* enforces native Postgres RLS policies, every
//! [`SafeQuery`] additionally carries [`SafeQuery::settings`] — the principal's identity bound
//! out-of-band (via `set_config`, never string-interpolated) so a `current_setting()`-based DB policy
//! fires even if a future caller forgets to apply the injected predicate.
//!
//! # Why mutation is impossible
//!
//! [`QueryIntent`] has exactly four shapes of field — a `select` list, a `from` table, `filters`,
//! `order_by`, and a `limit`. None of them can hold a statement verb. The compiler always begins the
//! output with `SELECT ` and never emits a `;`, so statement stacking is impossible too. Deserializing
//! an intent uses `#[serde(deny_unknown_fields)]`, so a JSON payload that tries to smuggle a
//! `"raw_sql"` (or any extra) field is *rejected by the parser* before it ever reaches this crate.
//! There is no `Insert`, `Update`, `Delete`, or `Ddl` type in this crate to construct.
//!
//! # Determinism
//!
//! No clock, no randomness, no I/O. Placeholder numbering is assigned strictly in field order, so the
//! same intent + schema + principal always compiles to byte-identical SQL and an identically-ordered
//! param vector. Every guarantee above is a property a unit test can *assert*, and the tests below do.

use serde::{Deserialize, Serialize};
use std::fmt;

pub use ainxt_types::{DataClass, Principal};

// ===========================================================================
// Schema registry — the identifier ALLOWLIST
// ===========================================================================

/// Maximum SQL identifier length accepted for a table or column name (PostgreSQL's `NAMEDATALEN`
/// default is 63). Anything longer is rejected at schema-build time.
pub const MAX_IDENT_LEN: usize = 63;

/// Default row ceiling injected when a [`Schema`] does not override it. Every compiled query is
/// bounded; this is the cap a missing/oversized [`QueryIntent::limit`] is clamped to.
pub const DEFAULT_MAX_LIMIT: u64 = 1000;

/// A single allow-listed column and the sensitivity class required to read it.
///
/// The `data_class` is the *minimum clearance* a [`Principal`] must hold to `SELECT`, filter on, or
/// order by this column. Construct via [`Column::new`], which validates the identifier grammar so a
/// column name can never carry an injection into the emitted SQL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ColumnWire")]
pub struct Column {
    name: String,
    data_class: DataClass,
}

/// Deserialization shadow for [`Column`]. Config-loaded columns route through [`Column::try_from`]
/// so identifier validation applies to declarative schemas too — deserialization cannot bypass it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ColumnWire {
    name: String,
    data_class: DataClass,
}

impl TryFrom<ColumnWire> for Column {
    type Error = SchemaError;
    fn try_from(w: ColumnWire) -> Result<Self, Self::Error> {
        Column::new(&w.name, w.data_class)
    }
}

impl Column {
    /// Build a column, validating that `name` is a safe SQL identifier.
    pub fn new(name: &str, data_class: DataClass) -> Result<Self, SchemaError> {
        if !is_valid_ident(name) {
            return Err(SchemaError::InvalidIdentifier(name.to_string()));
        }
        Ok(Column {
            name: name.to_string(),
            data_class,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn data_class(&self) -> DataClass {
        self.data_class
    }
}

/// A principal attribute that supplies the value for a [`RowScope`] row filter. The value is taken
/// from the authenticated [`Principal`] at compile time — never from the model or the user's text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalAttr {
    /// The caller's AD department / org unit ([`Principal::department`]). A department-scoped table
    /// filtered by this attribute shows only the caller's own department's rows. If the principal
    /// carries no department, compilation fails closed ([`QueryError::RowScopeUnavailable`]).
    Department,
    /// The caller's user id ([`Principal::user_id`]) — an owner-scoped ("only my rows") filter.
    UserId,
}

/// A row-level-security rule: bind a table column to a [`PrincipalAttr`], so every compiled query
/// over the table is filtered to the caller's own rows. The `column` must exist in the table (checked
/// at schema-build time). See the crate-level "Row-level security" note for the guarantees.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RowScope {
    /// The table column carrying the scoping value (e.g. `owner_dept`). Must be an allow-listed
    /// column of the table this scope is attached to.
    pub column: String,
    /// Which principal attribute supplies the value the column is filtered against.
    pub attr: PrincipalAttr,
}

impl RowScope {
    /// Build a row-scope rule. The column's *existence* is validated when the scope is attached to a
    /// [`Table`]; here we only capture the pair.
    pub fn new(column: &str, attr: PrincipalAttr) -> Self {
        RowScope {
            column: column.to_string(),
            attr,
        }
    }
}

/// An allow-listed table: a name, its readable columns, and any [`RowScope`] row-level-security
/// rules. A table with zero columns is rejected — there would be nothing safe to select.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "TableWire")]
pub struct Table {
    name: String,
    columns: Vec<Column>,
    row_scopes: Vec<RowScope>,
}

/// Deserialization shadow for [`Table`] — routes through [`Table::try_from`] so a config-loaded
/// table is validated (identifier, non-empty, no duplicate columns, scope columns exist) exactly
/// like a code-built one.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TableWire {
    name: String,
    columns: Vec<Column>,
    #[serde(default)]
    row_scopes: Vec<RowScope>,
}

impl TryFrom<TableWire> for Table {
    type Error = SchemaError;
    fn try_from(w: TableWire) -> Result<Self, Self::Error> {
        Table::new_scoped(&w.name, w.columns, w.row_scopes)
    }
}

impl Table {
    /// Build a table from validated columns, with no row-level-security rules. Rejects an invalid
    /// table identifier, an empty column set, and duplicate column names.
    pub fn new(name: &str, columns: Vec<Column>) -> Result<Self, SchemaError> {
        Table::new_scoped(name, columns, Vec::new())
    }

    /// Build a table with [`RowScope`] row-level-security rules. In addition to the [`Table::new`]
    /// checks, every scope's `column` must be an allow-listed column of this table — a scope over a
    /// non-existent column is a configuration error ([`SchemaError::UnknownScopeColumn`]) rather
    /// than a silently-ignored (and therefore *absent*) row filter.
    pub fn new_scoped(
        name: &str,
        columns: Vec<Column>,
        row_scopes: Vec<RowScope>,
    ) -> Result<Self, SchemaError> {
        if !is_valid_ident(name) {
            return Err(SchemaError::InvalidIdentifier(name.to_string()));
        }
        if columns.is_empty() {
            return Err(SchemaError::EmptyTable(name.to_string()));
        }
        for (i, col) in columns.iter().enumerate() {
            if columns[..i].iter().any(|c| c.name == col.name) {
                return Err(SchemaError::DuplicateColumn(col.name.clone()));
            }
        }
        for scope in &row_scopes {
            if !columns.iter().any(|c| c.name == scope.column) {
                return Err(SchemaError::UnknownScopeColumn(scope.column.clone()));
            }
        }
        Ok(Table {
            name: name.to_string(),
            columns,
            row_scopes,
        })
    }

    /// Attach an additional [`RowScope`] rule, validating the column exists. Chainable builder over
    /// [`Table::new`].
    pub fn with_row_scope(mut self, scope: RowScope) -> Result<Self, SchemaError> {
        if !self.columns.iter().any(|c| c.name == scope.column) {
            return Err(SchemaError::UnknownScopeColumn(scope.column));
        }
        self.row_scopes.push(scope);
        Ok(self)
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn columns(&self) -> &[Column] {
        &self.columns
    }

    /// The row-level-security rules applied to every query over this table.
    pub fn row_scopes(&self) -> &[RowScope] {
        &self.row_scopes
    }

    /// Resolve a column by exact name. Returns `None` if it is not in the allowlist.
    pub fn column(&self, name: &str) -> Option<&Column> {
        self.columns.iter().find(|c| c.name == name)
    }
}

/// The schema allowlist: the complete set of tables (and, transitively, columns) a [`QueryIntent`]
/// may reference, plus the row ceiling enforced on every compiled query. Anything not present here
/// is rejected — there is no wildcard, no reflection, no "trust the model" escape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "SchemaWire")]
pub struct Schema {
    tables: Vec<Table>,
    max_limit: u64,
}

/// Deserialization shadow for [`Schema`] — routes through [`Schema::try_from`] so a config-loaded
/// schema is validated (no duplicate tables, strictly-positive ceiling) exactly like a built one.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SchemaWire {
    tables: Vec<Table>,
    #[serde(default = "default_max_limit")]
    max_limit: u64,
}

impl TryFrom<SchemaWire> for Schema {
    type Error = SchemaError;
    fn try_from(w: SchemaWire) -> Result<Self, Self::Error> {
        Schema::new(w.tables)?.with_max_limit(w.max_limit)
    }
}

fn default_max_limit() -> u64 {
    DEFAULT_MAX_LIMIT
}

impl Schema {
    /// Build a schema from validated tables. Rejects duplicate table names. The row ceiling defaults
    /// to [`DEFAULT_MAX_LIMIT`]; override with [`Schema::with_max_limit`].
    pub fn new(tables: Vec<Table>) -> Result<Self, SchemaError> {
        for (i, t) in tables.iter().enumerate() {
            if tables[..i].iter().any(|o| o.name == t.name) {
                return Err(SchemaError::DuplicateTable(t.name.clone()));
            }
        }
        Ok(Schema {
            tables,
            max_limit: DEFAULT_MAX_LIMIT,
        })
    }

    /// Set the row ceiling forced onto every compiled query. A ceiling of zero is meaningless (no
    /// query could return a row) and is rejected.
    pub fn with_max_limit(mut self, max_limit: u64) -> Result<Self, SchemaError> {
        if max_limit == 0 {
            return Err(SchemaError::ZeroMaxLimit);
        }
        self.max_limit = max_limit;
        Ok(self)
    }

    pub fn max_limit(&self) -> u64 {
        self.max_limit
    }

    /// Resolve a table by exact name. Returns `None` if it is not in the allowlist.
    pub fn table(&self, name: &str) -> Option<&Table> {
        self.tables.iter().find(|t| t.name == name)
    }
}

/// Why a [`Schema`], [`Table`], or [`Column`] cannot be constructed. These are *build-time*
/// configuration errors, kept separate from [`QueryError`] (a runtime request rejection).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaError {
    /// An identifier did not match `[A-Za-z_][A-Za-z0-9_]*` within [`MAX_IDENT_LEN`].
    InvalidIdentifier(String),
    /// A table was declared with no columns.
    EmptyTable(String),
    /// Two columns in one table share a name.
    DuplicateColumn(String),
    /// Two tables in the schema share a name.
    DuplicateTable(String),
    /// The row ceiling was set to zero.
    ZeroMaxLimit,
    /// A [`RowScope`] referenced a column that is not in the table's allowlist.
    UnknownScopeColumn(String),
}

impl fmt::Display for SchemaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SchemaError::InvalidIdentifier(s) => {
                write!(f, "invalid SQL identifier {s:?} (need [A-Za-z_][A-Za-z0-9_]* up to {MAX_IDENT_LEN} chars)")
            }
            SchemaError::EmptyTable(s) => write!(f, "table {s:?} has no columns"),
            SchemaError::DuplicateColumn(s) => write!(f, "duplicate column {s:?} in table"),
            SchemaError::DuplicateTable(s) => write!(f, "duplicate table {s:?} in schema"),
            SchemaError::ZeroMaxLimit => write!(f, "max_limit must be strictly positive"),
            SchemaError::UnknownScopeColumn(s) => {
                write!(f, "row scope references unknown column {s:?}")
            }
        }
    }
}

impl std::error::Error for SchemaError {}

/// Validate an SQL identifier: non-empty, ASCII, starts with a letter or `_`, remainder alphanumeric
/// or `_`, no longer than [`MAX_IDENT_LEN`]. This is deliberately far stricter than PostgreSQL's own
/// quoted-identifier rules — the point is that a compiled identifier physically cannot contain a
/// quote, a space, a comment marker, or a statement separator.
fn is_valid_ident(name: &str) -> bool {
    if name.is_empty() || name.len() > MAX_IDENT_LEN {
        return false;
    }
    let mut chars = name.chars();
    let first = chars.next().expect("non-empty checked above");
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

// ===========================================================================
// QueryIntent — the SELECT-only, structured proposal a model emits (as JSON)
// ===========================================================================

/// A scalar value supplied by the caller for a filter. Carried out-of-band as a parameter and
/// **never** rendered into SQL — there is intentionally no `to_sql`/`Display` that would let a value
/// be interpolated. Note the deliberate absence of a floating-point variant: money is an integer
/// count of minor units on this platform, never a lossy `f64`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Value {
    Int(i64),
    Text(String),
    Bool(bool),
}

/// A comparison predicate applied to one column. Modeling the operator and its operand(s) together
/// (rather than a loose `op` + optional `param`) makes illegal states unrepresentable: `IsNull`
/// cannot carry a value, `Eq` cannot lack one, and `In` cannot be a scalar.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Predicate {
    Eq(Value),
    Ne(Value),
    Lt(Value),
    Le(Value),
    Gt(Value),
    Ge(Value),
    /// Membership test. The value list must be non-empty (`IN ()` is not valid SQL).
    In(Vec<Value>),
    IsNull,
    IsNotNull,
}

/// A single `WHERE` conjunct: a column plus the predicate to apply. All filters are AND-combined.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Filter {
    pub column: String,
    pub predicate: Predicate,
}

/// Sort direction. An enum, not free text — so `ORDER BY` can never carry an injected fragment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Asc,
    Desc,
}

/// One `ORDER BY` term. The column is authorized against the principal's clearance just like a
/// selected column — sorting by a hidden column would leak its ordering.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrderBy {
    pub column: String,
    pub direction: Direction,
}

/// The structured, `SELECT`-only query a model proposes. This is the *entire* expressive surface a
/// model has over the database: a projection, a source table, AND-combined filters, an ordering, and
/// an optional row limit. There is no verb, no raw fragment, no join, no subquery, and — enforced by
/// `deny_unknown_fields` — no way to smuggle an extra field past the deserializer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryIntent {
    /// Columns to project. Must be non-empty — there is no `SELECT *`, which would risk pulling
    /// columns above the caller's clearance.
    pub select: Vec<String>,
    /// The single source table.
    pub from: String,
    #[serde(default)]
    pub filters: Vec<Filter>,
    #[serde(default)]
    pub order_by: Vec<OrderBy>,
    /// Requested row cap. `None` or a value above the schema ceiling is clamped down to the ceiling.
    #[serde(default)]
    pub limit: Option<u64>,
}

// ===========================================================================
// SafeQuery — the compiled, parameterized output
// ===========================================================================

/// A session-scoped setting the driver must apply *before* running the query, carrying the caller's
/// identity out-of-band for native-DB (`current_setting()`) row-level-security policies. The value
/// is bound as a parameter (e.g. `SELECT set_config($key, $1, true)`) and is **never** interpolated
/// into SQL text — the same anti-injection discipline as [`SafeQuery::params`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionSetting {
    pub key: String,
    pub value: Value,
}

/// The result of a successful compilation: parameterized SQL plus its out-of-band parameter vector.
/// `sql` references parameters only as `$1`, `$2`, … placeholders and never contains a caller value
/// or a `;`. `params[i]` is the value for placeholder `$(i+1)`.
///
/// `Serialize` so a transport (e.g. the `/v1/query_ledger` route) can hand the compiled, safe query
/// straight back over the wire — the safe-compilation boundary IS the serializable response.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SafeQuery {
    pub sql: String,
    pub params: Vec<Value>,
    /// The row limit actually applied (always `<= schema.max_limit()` and `>= 1`).
    pub limit_applied: u64,
    /// True if the caller's requested limit was missing or exceeded the ceiling and was clamped.
    pub limit_was_clamped: bool,
    /// Session settings the driver applies before executing (defense-in-depth for native-DB RLS).
    /// Always carries the caller's `user_id`, and their `department` when present.
    pub settings: Vec<SessionSetting>,
}

/// Why a [`QueryIntent`] was refused at compile time. Note that an unknown column and an
/// over-clearance column collapse to the **same** [`QueryError::ColumnNotAvailable`] variant on
/// purpose — distinguishing them would hand an under-cleared caller an existence oracle over
/// sensitive columns (ADR-012).
///
/// `Serialize` (externally tagged) so a transport can render the refusal verbatim as a `403` body.
/// The tag never distinguishes unknown-vs-over-clearance — that collapse is the whole point of
/// [`QueryError::ColumnNotAvailable`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum QueryError {
    /// The `from` table is not in the schema allowlist.
    UnknownTable(String),
    /// A referenced column is either not in the allowlist **or** above the principal's clearance.
    /// The two cases are intentionally indistinguishable (ADR-012: no existence oracle).
    /// Checkmarx CX-FP: unit variant — column name deliberately excluded from error payload.
    ColumnNotAvailable,
    /// The projection was empty (`SELECT *` is not permitted).
    NoColumnsSelected,
    /// An `In` predicate carried an empty value list (`IN ()` is invalid SQL).
    EmptyInList(String),
    /// A [`RowScope`] on the table requires a principal attribute the caller does not carry (e.g. a
    /// department-scoped table queried by a principal with no `department`). Compilation fails
    /// **closed** — an unscoped full-table scan is never emitted. Carries the scope column name.
    RowScopeUnavailable(String),
    /// The caller does not hold [`CAP_QUERY_LEDGER`], so the ledger query surface is closed to them.
    /// Raised by [`query_ledger`] *before* any schema/column is consulted, so a caller without the
    /// capability learns nothing about the schema (not even whether a table exists).
    NotAuthorized,
}

impl fmt::Display for QueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QueryError::UnknownTable(t) => write!(f, "unknown table {t:?}"),
            QueryError::ColumnNotAvailable => write!(f, "a requested column is not available"),
            QueryError::NoColumnsSelected => write!(f, "at least one column must be selected"),
            QueryError::EmptyInList(c) => {
                write!(f, "IN filter on column {c:?} has an empty value list")
            }
            QueryError::RowScopeUnavailable(c) => write!(
                f,
                "row-level security on column {c:?} requires a principal attribute the caller lacks"
            ),
            QueryError::NotAuthorized => {
                write!(f, "not authorized to query the ledger")
            }
        }
    }
}

impl std::error::Error for QueryError {}

// ===========================================================================
// The boundary: validate_and_compile
// ===========================================================================

/// Compile a model-proposed [`QueryIntent`] into a [`SafeQuery`], or reject it.
///
/// Deterministic and side-effect-free. The steps, in order:
/// 1. Resolve `from` against the allowlist (else [`QueryError::UnknownTable`]).
/// 2. Require a non-empty projection (else [`QueryError::NoColumnsSelected`]).
/// 3. Resolve **and authorize** every `select`, `filter`, and `order_by` column: unknown or
///    over-clearance columns both yield [`QueryError::ColumnNotAvailable`] (no existence leak).
/// 4. Emit each filter value as a `$n` placeholder, appending the value to `params` in order.
/// 5. Inject the table's [`RowScope`] row-level-security predicates (principal-derived, un-bypassable),
///    or fail closed with [`QueryError::RowScopeUnavailable`] if a required attribute is absent.
/// 6. Force a bounded `LIMIT`, clamping a missing/oversized request down to `schema.max_limit()`.
///
/// The returned `sql` always begins with `SELECT `, contains no caller value, and contains no `;`.
/// [`SafeQuery::settings`] additionally carries the caller's identity for native-DB RLS.
pub fn validate_and_compile(
    intent: &QueryIntent,
    schema: &Schema,
    principal: &Principal,
) -> Result<SafeQuery, QueryError> {
    let table = schema
        .table(&intent.from)
        .ok_or_else(|| QueryError::UnknownTable(intent.from.clone()))?;

    if intent.select.is_empty() {
        return Err(QueryError::NoColumnsSelected);
    }

    // --- projection -------------------------------------------------------
    let mut select_sql = Vec::with_capacity(intent.select.len());
    for name in &intent.select {
        let col = resolve_readable(table, principal, name)?;
        select_sql.push(quote_ident(col.name()));
    }

    // --- filters (parameterized) -----------------------------------------
    let mut where_sql: Vec<String> = Vec::with_capacity(intent.filters.len());
    let mut params: Vec<Value> = Vec::new();
    let mut next_placeholder: usize = 1;
    for filter in &intent.filters {
        let col = resolve_readable(table, principal, &filter.column)?;
        let id = quote_ident(col.name());
        let clause = compile_predicate(
            &id,
            &filter.column,
            &filter.predicate,
            &mut params,
            &mut next_placeholder,
        )?;
        where_sql.push(clause);
    }

    // --- row-level security (principal-derived, un-bypassable) ------------
    // Injected AFTER the model's own filters, always ANDed in. The value comes from the
    // authenticated principal, never the model — so a query over a row-scoped table can only ever
    // see the caller's own rows, and there is no field in the intent that can remove this.
    for scope in table.row_scopes() {
        // Existence was validated at schema-build time; a scope column is always resolvable.
        let col = table
            .column(&scope.column)
            .expect("row-scope column validated at schema-build time");
        let value = match scope.attr {
            PrincipalAttr::Department => match &principal.department {
                Some(dept) => Value::Text(dept.clone()),
                // Fail closed: never emit an unscoped scan for a caller that cannot be scoped.
                None => return Err(QueryError::RowScopeUnavailable(scope.column.clone())),
            },
            PrincipalAttr::UserId => Value::Text(principal.user_id.clone()),
        };
        params.push(value);
        where_sql.push(format!("{} = ${next_placeholder}", quote_ident(col.name())));
        next_placeholder += 1;
    }

    // --- ordering (authorized like a projection) --------------------------
    let mut order_sql = Vec::with_capacity(intent.order_by.len());
    for ob in &intent.order_by {
        let col = resolve_readable(table, principal, &ob.column)?;
        let dir = match ob.direction {
            Direction::Asc => "ASC",
            Direction::Desc => "DESC",
        };
        order_sql.push(format!("{} {}", quote_ident(col.name()), dir));
    }

    // --- forced bounded limit --------------------------------------------
    let max = schema.max_limit();
    let (limit_applied, limit_was_clamped) = match intent.limit {
        Some(requested) if (1..=max).contains(&requested) => (requested, false),
        _ => (max, true),
    };

    // --- assemble ---------------------------------------------------------
    let mut sql = String::from("SELECT ");
    sql.push_str(&select_sql.join(", "));
    sql.push_str(" FROM ");
    sql.push_str(&quote_ident(table.name()));
    if !where_sql.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&where_sql.join(" AND "));
    }
    if !order_sql.is_empty() {
        sql.push_str(" ORDER BY ");
        sql.push_str(&order_sql.join(", "));
    }
    // `limit_applied` is a u64 we computed and bounded; formatting it can only produce digits, so
    // this is safe to inline (it is not, and can never be, caller free-text).
    sql.push_str(" LIMIT ");
    sql.push_str(&limit_applied.to_string());

    // Defense-in-depth: bind the caller's identity for a native-DB (current_setting) RLS policy.
    let mut settings = vec![SessionSetting {
        key: "app.principal_user_id".to_string(),
        value: Value::Text(principal.user_id.clone()),
    }];
    if let Some(dept) = &principal.department {
        settings.push(SessionSetting {
            key: "app.principal_department".to_string(),
            value: Value::Text(dept.clone()),
        });
    }

    Ok(SafeQuery {
        sql,
        params,
        limit_applied,
        limit_was_clamped,
        settings,
    })
}

// ===========================================================================
// query_ledger — the RBAC-scoped, mount-ready entrypoint (R3 DATA)
// ===========================================================================

/// Capability a principal must hold to reach the ledger query surface at all. This is the coarse
/// RBAC gate that precedes the fine-grained, per-column clearance check inside
/// [`validate_and_compile`]; a caller lacking it never reaches compilation. `Admin` holds every
/// capability (see [`Principal::has_cap`]).
pub const CAP_QUERY_LEDGER: &str = "data.query_ledger";

/// The single entrypoint a transport route (`POST /v1/query_ledger`) mounts to reach safe NL→SQL.
///
/// Two-stage RBAC, fail-closed at each stage:
/// 1. **Capability gate** — the principal must hold [`CAP_QUERY_LEDGER`] (or be `Admin`); otherwise
///    [`QueryError::NotAuthorized`] with no schema/column information disclosed.
/// 2. **Clearance + structural validation** — delegated to [`validate_and_compile`]: unknown table,
///    unknown/over-clearance column (indistinguishable — no existence oracle), empty projection,
///    empty `IN`, and un-satisfiable row-level-security all refuse; a bounded `LIMIT` is forced and
///    every caller value is emitted as a `$n` placeholder.
///
/// The returned [`SafeQuery`] is `Serialize`, so the transport hands it straight back over the wire.
/// This crate never executes SQL — it is the *safe-compilation boundary*; the deployment's driver
/// runs the compiled, parameterized query.
pub fn query_ledger(
    intent: &QueryIntent,
    schema: &Schema,
    principal: &Principal,
) -> Result<SafeQuery, QueryError> {
    if !principal.has_cap(CAP_QUERY_LEDGER) {
        return Err(QueryError::NotAuthorized);
    }
    validate_and_compile(intent, schema, principal)
}

/// Resolve a column and authorize the principal to read it in one step. An unknown column and an
/// over-clearance column are collapsed to the same error so existence is never leaked.
fn resolve_readable<'a>(
    table: &'a Table,
    principal: &Principal,
    name: &str,
) -> Result<&'a Column, QueryError> {
    match table.column(name) {
        Some(col) if can_read(principal, col) => Ok(col),
        _ => Err(QueryError::ColumnNotAvailable),
    }
}

/// Clearance check (ADR-012): a principal may read a column iff the column's sensitivity does not
/// exceed the principal's clearance. Authorization is clearance-based and independent of role/caps —
/// clearance is the single authority for what data a caller may see.
fn can_read(principal: &Principal, column: &Column) -> bool {
    column.data_class().sensitivity() <= principal.clearance.sensitivity()
}

/// Compile one predicate into a WHERE clause fragment, appending any values to `params` and
/// advancing the placeholder counter. Values are emitted only as `$n` placeholders.
fn compile_predicate(
    id: &str,
    column: &str,
    predicate: &Predicate,
    params: &mut Vec<Value>,
    next_placeholder: &mut usize,
) -> Result<String, QueryError> {
    // Append `value` to the param vector and return its `$n` placeholder, advancing the counter.
    // Values only ever reach the SQL as placeholders — never as interpolated text.
    let bind = |value: &Value, store: &mut Vec<Value>, counter: &mut usize| -> String {
        store.push(value.clone());
        let ph = format!("${counter}");
        *counter += 1;
        ph
    };
    let clause = match predicate {
        Predicate::Eq(v) => format!("{id} = {}", bind(v, params, next_placeholder)),
        Predicate::Ne(v) => format!("{id} <> {}", bind(v, params, next_placeholder)),
        Predicate::Lt(v) => format!("{id} < {}", bind(v, params, next_placeholder)),
        Predicate::Le(v) => format!("{id} <= {}", bind(v, params, next_placeholder)),
        Predicate::Gt(v) => format!("{id} > {}", bind(v, params, next_placeholder)),
        Predicate::Ge(v) => format!("{id} >= {}", bind(v, params, next_placeholder)),
        Predicate::In(values) => {
            if values.is_empty() {
                return Err(QueryError::EmptyInList(column.to_string()));
            }
            let placeholders: Vec<String> = values
                .iter()
                .map(|v| bind(v, params, next_placeholder))
                .collect();
            format!("{id} IN ({})", placeholders.join(", "))
        }
        Predicate::IsNull => format!("{id} IS NULL"),
        Predicate::IsNotNull => format!("{id} IS NOT NULL"),
    };
    Ok(clause)
}

/// Double-quote a validated identifier. `name` has already passed [`is_valid_ident`], so it contains
/// no quote character and quoting cannot be broken out of.
fn quote_ident(name: &str) -> String {
    format!("\"{name}\"")
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // A ledger table spanning the clearance ladder:
    //   entry_id           Internal
    //   amount_minor       Confidential
    //   counterparty_acct  RegulatedPayment
    //   holder_pan         Pii
    fn ledger_schema() -> Schema {
        let table = Table::new(
            "ledger_entries",
            vec![
                Column::new("entry_id", DataClass::Internal).unwrap(),
                Column::new("amount_minor", DataClass::Confidential).unwrap(),
                Column::new("counterparty_acct", DataClass::RegulatedPayment).unwrap(),
                Column::new("holder_pan", DataClass::Pii).unwrap(),
            ],
        )
        .unwrap();
        Schema::new(vec![table])
            .unwrap()
            .with_max_limit(500)
            .unwrap()
    }

    // A Confidential-cleared analyst: may read entry_id + amount_minor, not the two regulated cols.
    fn analyst() -> Principal {
        Principal::user("analyst-1", &[]).with_clearance(DataClass::Confidential)
    }

    #[test]
    fn valid_intent_compiles_to_parameterized_sql() {
        let intent = QueryIntent {
            select: vec!["entry_id".into(), "amount_minor".into()],
            from: "ledger_entries".into(),
            filters: vec![
                Filter {
                    column: "amount_minor".into(),
                    predicate: Predicate::Ge(Value::Int(1000)),
                },
                Filter {
                    column: "entry_id".into(),
                    predicate: Predicate::Eq(Value::Text("E-42".into())),
                },
            ],
            order_by: vec![OrderBy {
                column: "amount_minor".into(),
                direction: Direction::Desc,
            }],
            limit: Some(50),
        };
        let q = validate_and_compile(&intent, &ledger_schema(), &analyst()).unwrap();

        assert_eq!(
            q.sql,
            "SELECT \"entry_id\", \"amount_minor\" FROM \"ledger_entries\" \
             WHERE \"amount_minor\" >= $1 AND \"entry_id\" = $2 \
             ORDER BY \"amount_minor\" DESC LIMIT 50"
        );
        // Values live in params, in field order — not in the SQL text.
        assert_eq!(q.params, vec![Value::Int(1000), Value::Text("E-42".into())]);
        assert!(!q.sql.contains("E-42"), "raw string value leaked into SQL");
        assert!(!q.sql.contains("1000"), "raw int value leaked into SQL");
        assert_eq!(q.limit_applied, 50);
        assert!(!q.limit_was_clamped);
        assert!(q.sql.starts_with("SELECT "));
    }

    #[test]
    fn unknown_table_is_rejected() {
        let intent = QueryIntent {
            select: vec!["entry_id".into()],
            from: "shadow_ledger".into(),
            filters: vec![],
            order_by: vec![],
            limit: None,
        };
        let err = validate_and_compile(&intent, &ledger_schema(), &analyst()).unwrap_err();
        assert_eq!(err, QueryError::UnknownTable("shadow_ledger".into()));
    }

    #[test]
    fn unknown_column_is_rejected() {
        let intent = QueryIntent {
            select: vec!["entry_id".into(), "secret_backdoor".into()],
            from: "ledger_entries".into(),
            filters: vec![],
            order_by: vec![],
            limit: None,
        };
        let err = validate_and_compile(&intent, &ledger_schema(), &analyst()).unwrap_err();
        assert_eq!(err, QueryError::ColumnNotAvailable);
    }

    #[test]
    fn over_clearance_column_is_refused_but_reads_at_higher_clearance() {
        // The Confidential analyst cannot select the Pii column...
        let intent = QueryIntent {
            select: vec!["holder_pan".into()],
            from: "ledger_entries".into(),
            filters: vec![],
            order_by: vec![],
            limit: Some(10),
        };
        let err = validate_and_compile(&intent, &ledger_schema(), &analyst()).unwrap_err();
        assert_eq!(err, QueryError::ColumnNotAvailable);

        // ...but a Pii-cleared principal (e.g. admin) can.
        let privileged = Principal::admin("dpo-1"); // admin() clearance == Pii
        let ok = validate_and_compile(&intent, &ledger_schema(), &privileged).unwrap();
        assert_eq!(
            ok.sql,
            "SELECT \"holder_pan\" FROM \"ledger_entries\" LIMIT 10"
        );
    }

    #[test]
    fn unknown_and_over_clearance_columns_are_indistinguishable() {
        // Existence-not-leaked: probing a non-existent column and a real-but-hidden column must
        // return the SAME error variant, so error shape is not an existence oracle.
        let schema = ledger_schema();
        let p = analyst();
        let hidden = QueryIntent {
            select: vec!["holder_pan".into()], // exists, above clearance
            from: "ledger_entries".into(),
            filters: vec![],
            order_by: vec![],
            limit: None,
        };
        let ghost = QueryIntent {
            select: vec!["does_not_exist".into()], // does not exist
            from: "ledger_entries".into(),
            filters: vec![],
            order_by: vec![],
            limit: None,
        };
        let e_hidden = validate_and_compile(&hidden, &schema, &p).unwrap_err();
        let e_ghost = validate_and_compile(&ghost, &schema, &p).unwrap_err();
        assert!(matches!(e_hidden, QueryError::ColumnNotAvailable));
        assert!(matches!(e_ghost, QueryError::ColumnNotAvailable));
        // Same variant either way — the discriminant carries no existence signal.
        assert_eq!(
            std::mem::discriminant(&e_hidden),
            std::mem::discriminant(&e_ghost)
        );
    }

    #[test]
    fn over_clearance_filter_column_is_refused() {
        // The value we can see is fine, but filtering on a hidden column would leak it via the WHERE.
        let intent = QueryIntent {
            select: vec!["entry_id".into()],
            from: "ledger_entries".into(),
            filters: vec![Filter {
                column: "counterparty_acct".into(), // RegulatedPayment > Confidential
                predicate: Predicate::Eq(Value::Text("acct-9".into())),
            }],
            order_by: vec![],
            limit: None,
        };
        let err = validate_and_compile(&intent, &ledger_schema(), &analyst()).unwrap_err();
        assert_eq!(err, QueryError::ColumnNotAvailable);
    }

    #[test]
    fn over_clearance_order_by_column_is_refused() {
        // Ordering by a hidden column leaks its ordering — must be authorized like a projection.
        let intent = QueryIntent {
            select: vec!["entry_id".into()],
            from: "ledger_entries".into(),
            filters: vec![],
            order_by: vec![OrderBy {
                column: "holder_pan".into(),
                direction: Direction::Asc,
            }],
            limit: None,
        };
        let err = validate_and_compile(&intent, &ledger_schema(), &analyst()).unwrap_err();
        assert_eq!(err, QueryError::ColumnNotAvailable);
    }

    #[test]
    fn missing_limit_is_clamped_to_max() {
        let intent = QueryIntent {
            select: vec!["entry_id".into()],
            from: "ledger_entries".into(),
            filters: vec![],
            order_by: vec![],
            limit: None,
        };
        let q = validate_and_compile(&intent, &ledger_schema(), &analyst()).unwrap();
        assert_eq!(q.limit_applied, 500);
        assert!(q.limit_was_clamped);
        assert!(q.sql.ends_with(" LIMIT 500"));
    }

    #[test]
    fn oversized_limit_is_clamped_to_max() {
        let intent = QueryIntent {
            select: vec!["entry_id".into()],
            from: "ledger_entries".into(),
            filters: vec![],
            order_by: vec![],
            limit: Some(1_000_000),
        };
        let q = validate_and_compile(&intent, &ledger_schema(), &analyst()).unwrap();
        assert_eq!(q.limit_applied, 500);
        assert!(q.limit_was_clamped);
    }

    #[test]
    fn within_bounds_limit_is_preserved() {
        let intent = QueryIntent {
            select: vec!["entry_id".into()],
            from: "ledger_entries".into(),
            filters: vec![],
            order_by: vec![],
            limit: Some(123),
        };
        let q = validate_and_compile(&intent, &ledger_schema(), &analyst()).unwrap();
        assert_eq!(q.limit_applied, 123);
        assert!(!q.limit_was_clamped);
    }

    #[test]
    fn zero_limit_is_clamped_up_to_max() {
        // A zero limit (return nothing) is treated as "unset" and forced to the ceiling.
        let intent = QueryIntent {
            select: vec!["entry_id".into()],
            from: "ledger_entries".into(),
            filters: vec![],
            order_by: vec![],
            limit: Some(0),
        };
        let q = validate_and_compile(&intent, &ledger_schema(), &analyst()).unwrap();
        assert_eq!(q.limit_applied, 500);
        assert!(q.limit_was_clamped);
    }

    #[test]
    fn sql_metacharacter_value_is_carried_as_a_param_not_interpolated() {
        let attack = "1; DROP TABLE ledger_entries; --";
        let intent = QueryIntent {
            select: vec!["entry_id".into()],
            from: "ledger_entries".into(),
            filters: vec![Filter {
                column: "entry_id".into(),
                predicate: Predicate::Eq(Value::Text(attack.into())),
            }],
            order_by: vec![],
            limit: Some(5),
        };
        let q = validate_and_compile(&intent, &ledger_schema(), &analyst()).unwrap();
        // The payload rides in params, verbatim...
        assert_eq!(q.params, vec![Value::Text(attack.into())]);
        // ...and NONE of it appears in the SQL, which references it only as $1.
        assert!(!q.sql.contains("DROP"));
        assert!(!q.sql.contains("--"));
        assert!(!q.sql.contains(attack));
        assert!(q.sql.contains("\"entry_id\" = $1"));
        // Statement stacking is structurally impossible: never a semicolon in the output.
        assert!(!q.sql.contains(';'));
    }

    #[test]
    fn compiled_sql_is_always_a_single_select_no_mutation() {
        // Every compiled query begins with SELECT, has no `;`, and contains no mutation/DDL verb.
        let intent = QueryIntent {
            select: vec!["entry_id".into(), "amount_minor".into()],
            from: "ledger_entries".into(),
            filters: vec![Filter {
                column: "amount_minor".into(),
                predicate: Predicate::In(vec![Value::Int(1), Value::Int(2), Value::Int(3)]),
            }],
            order_by: vec![OrderBy {
                column: "entry_id".into(),
                direction: Direction::Asc,
            }],
            limit: Some(9),
        };
        let q = validate_and_compile(&intent, &ledger_schema(), &analyst()).unwrap();
        assert!(q.sql.starts_with("SELECT "));
        assert!(!q.sql.contains(';'));
        let upper = q.sql.to_uppercase();
        for verb in [
            "INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "TRUNCATE", "MERGE",
        ] {
            assert!(
                !upper.contains(verb),
                "mutation verb {verb} present in compiled SQL"
            );
        }
    }

    #[test]
    fn empty_selection_is_rejected_no_select_star() {
        let intent = QueryIntent {
            select: vec![],
            from: "ledger_entries".into(),
            filters: vec![],
            order_by: vec![],
            limit: None,
        };
        let err = validate_and_compile(&intent, &ledger_schema(), &analyst()).unwrap_err();
        assert_eq!(err, QueryError::NoColumnsSelected);
    }

    #[test]
    fn in_predicate_emits_sequential_placeholders() {
        let intent = QueryIntent {
            select: vec!["entry_id".into()],
            from: "ledger_entries".into(),
            filters: vec![
                Filter {
                    column: "entry_id".into(),
                    predicate: Predicate::In(vec![
                        Value::Text("a".into()),
                        Value::Text("b".into()),
                    ]),
                },
                Filter {
                    column: "amount_minor".into(),
                    predicate: Predicate::Gt(Value::Int(7)),
                },
            ],
            order_by: vec![],
            limit: Some(3),
        };
        let q = validate_and_compile(&intent, &ledger_schema(), &analyst()).unwrap();
        assert!(q.sql.contains("\"entry_id\" IN ($1, $2)"));
        assert!(q.sql.contains("\"amount_minor\" > $3"));
        assert_eq!(
            q.params,
            vec![
                Value::Text("a".into()),
                Value::Text("b".into()),
                Value::Int(7)
            ]
        );
    }

    #[test]
    fn empty_in_list_is_rejected() {
        let intent = QueryIntent {
            select: vec!["entry_id".into()],
            from: "ledger_entries".into(),
            filters: vec![Filter {
                column: "entry_id".into(),
                predicate: Predicate::In(vec![]),
            }],
            order_by: vec![],
            limit: None,
        };
        let err = validate_and_compile(&intent, &ledger_schema(), &analyst()).unwrap_err();
        assert_eq!(err, QueryError::EmptyInList("entry_id".into()));
    }

    #[test]
    fn null_predicates_bind_no_params() {
        let intent = QueryIntent {
            select: vec!["entry_id".into()],
            from: "ledger_entries".into(),
            filters: vec![
                Filter {
                    column: "amount_minor".into(),
                    predicate: Predicate::IsNull,
                },
                Filter {
                    column: "entry_id".into(),
                    predicate: Predicate::IsNotNull,
                },
            ],
            order_by: vec![],
            limit: Some(2),
        };
        let q = validate_and_compile(&intent, &ledger_schema(), &analyst()).unwrap();
        assert!(q
            .sql
            .contains("\"amount_minor\" IS NULL AND \"entry_id\" IS NOT NULL"));
        assert!(q.params.is_empty());
    }

    #[test]
    fn schema_rejects_injection_bearing_identifier() {
        // Even the allowlist cannot carry an injection: identifiers are grammar-validated at build.
        for bad in [
            "amount; DROP TABLE x",
            "col name",
            "\"quoted\"",
            "1col",
            "",
            "a-b",
        ] {
            assert!(
                matches!(
                    Column::new(bad, DataClass::Internal),
                    Err(SchemaError::InvalidIdentifier(_))
                ),
                "identifier {bad:?} should have been rejected"
            );
        }
        // A legitimate identifier is accepted.
        assert!(Column::new("amount_minor", DataClass::Internal).is_ok());
    }

    #[test]
    fn schema_rejects_duplicate_and_empty_definitions() {
        let dup_cols = Table::new(
            "t",
            vec![
                Column::new("a", DataClass::Internal).unwrap(),
                Column::new("a", DataClass::Internal).unwrap(),
            ],
        );
        assert_eq!(
            dup_cols.unwrap_err(),
            SchemaError::DuplicateColumn("a".into())
        );

        let empty = Table::new("t", vec![]);
        assert_eq!(empty.unwrap_err(), SchemaError::EmptyTable("t".into()));

        let t = Table::new("t", vec![Column::new("a", DataClass::Internal).unwrap()]).unwrap();
        let dup_tables = Schema::new(vec![t.clone(), t]);
        assert_eq!(
            dup_tables.unwrap_err(),
            SchemaError::DuplicateTable("t".into())
        );

        assert_eq!(
            Schema::new(vec![]).unwrap().with_max_limit(0).unwrap_err(),
            SchemaError::ZeroMaxLimit
        );
    }

    #[test]
    fn intent_deserializes_from_model_json_and_compiles() {
        // The real flow: a model proposes JSON, which parses into a QueryIntent and compiles.
        let json = r#"{
            "select": ["entry_id", "amount_minor"],
            "from": "ledger_entries",
            "filters": [{"column": "amount_minor", "predicate": {"ge": {"int": 500}}}],
            "order_by": [{"column": "entry_id", "direction": "asc"}],
            "limit": 20
        }"#;
        let intent: QueryIntent = serde_json::from_str(json).unwrap();
        let q = validate_and_compile(&intent, &ledger_schema(), &analyst()).unwrap();
        assert_eq!(
            q.sql,
            "SELECT \"entry_id\", \"amount_minor\" FROM \"ledger_entries\" \
             WHERE \"amount_minor\" >= $1 ORDER BY \"entry_id\" ASC LIMIT 20"
        );
        assert_eq!(q.params, vec![Value::Int(500)]);
    }

    #[test]
    fn model_json_smuggling_a_raw_sql_field_is_rejected_by_the_parser() {
        // deny_unknown_fields: a payload trying to carry raw SQL never becomes a QueryIntent.
        let json = r#"{
            "select": ["entry_id"],
            "from": "ledger_entries",
            "raw_sql": "DROP TABLE ledger_entries"
        }"#;
        assert!(serde_json::from_str::<QueryIntent>(json).is_err());
    }

    #[test]
    fn config_loaded_schema_is_validated_and_usable() {
        let json = r#"{
            "tables": [{
                "name": "reports",
                "columns": [
                    {"name": "report_id", "data_class": "internal"},
                    {"name": "net_amount_minor", "data_class": "confidential"}
                ]
            }],
            "max_limit": 250
        }"#;
        let schema: Schema = serde_json::from_str(json).unwrap();
        assert_eq!(schema.max_limit(), 250);
        let intent = QueryIntent {
            select: vec!["report_id".into()],
            from: "reports".into(),
            filters: vec![],
            order_by: vec![],
            limit: None,
        };
        let q = validate_and_compile(&intent, &schema, &analyst()).unwrap();
        assert_eq!(q.sql, "SELECT \"report_id\" FROM \"reports\" LIMIT 250");
    }

    #[test]
    fn config_loaded_schema_with_injection_identifier_is_rejected() {
        // Deserialization cannot bypass identifier validation — the try_from seam enforces it.
        let bad_col = r#"{"tables":[{"name":"t","columns":[{"name":"a; DROP TABLE t","data_class":"internal"}]}],"max_limit":10}"#;
        assert!(serde_json::from_str::<Schema>(bad_col).is_err());

        let bad_table = r#"{"tables":[{"name":"t space","columns":[{"name":"a","data_class":"internal"}]}],"max_limit":10}"#;
        assert!(serde_json::from_str::<Schema>(bad_table).is_err());

        let zero_limit = r#"{"tables":[{"name":"t","columns":[{"name":"a","data_class":"internal"}]}],"max_limit":0}"#;
        assert!(serde_json::from_str::<Schema>(zero_limit).is_err());
    }

    // === Row-level security ================================================

    // A department-scoped ledger: `owner_dept` (Internal) carries the row's owning department; a
    // RowScope binds it to the caller's `department`, so a query sees only that department's rows.
    fn scoped_schema() -> Schema {
        let table = Table::new_scoped(
            "ledger_entries",
            vec![
                Column::new("entry_id", DataClass::Internal).unwrap(),
                Column::new("amount_minor", DataClass::Confidential).unwrap(),
                Column::new("owner_dept", DataClass::Internal).unwrap(),
                Column::new("owner_user", DataClass::Internal).unwrap(),
            ],
            vec![RowScope::new("owner_dept", PrincipalAttr::Department)],
        )
        .unwrap();
        Schema::new(vec![table])
            .unwrap()
            .with_max_limit(500)
            .unwrap()
    }

    fn scoped_analyst() -> Principal {
        Principal::user("analyst-1", &[])
            .with_clearance(DataClass::Confidential)
            .with_department("settlement-ops")
    }

    #[test]
    fn row_scope_injects_principal_department_predicate() {
        let intent = QueryIntent {
            select: vec!["entry_id".into()],
            from: "ledger_entries".into(),
            filters: vec![],
            order_by: vec![],
            limit: Some(10),
        };
        let q = validate_and_compile(&intent, &scoped_schema(), &scoped_analyst()).unwrap();
        // The row filter is present even though the model asked for none, and its value is the
        // caller's OWN department — carried as a param, never interpolated.
        assert_eq!(
            q.sql,
            "SELECT \"entry_id\" FROM \"ledger_entries\" WHERE \"owner_dept\" = $1 LIMIT 10"
        );
        assert_eq!(q.params, vec![Value::Text("settlement-ops".into())]);
        assert!(
            !q.sql.contains("settlement-ops"),
            "dept value leaked into SQL"
        );
    }

    #[test]
    fn row_scope_combines_with_user_filters_and_numbers_placeholders_after() {
        let intent = QueryIntent {
            select: vec!["entry_id".into()],
            from: "ledger_entries".into(),
            filters: vec![Filter {
                column: "amount_minor".into(),
                predicate: Predicate::Ge(Value::Int(1000)),
            }],
            order_by: vec![],
            limit: Some(5),
        };
        let q = validate_and_compile(&intent, &scoped_schema(), &scoped_analyst()).unwrap();
        // Model filter takes $1; the injected row-scope predicate is ANDed after it as $2.
        assert_eq!(
            q.sql,
            "SELECT \"entry_id\" FROM \"ledger_entries\" \
             WHERE \"amount_minor\" >= $1 AND \"owner_dept\" = $2 LIMIT 5"
        );
        assert_eq!(
            q.params,
            vec![Value::Int(1000), Value::Text("settlement-ops".into())]
        );
    }

    #[test]
    fn row_scope_without_required_attribute_fails_closed() {
        // A principal with NO department must not receive an unscoped full-table scan — compilation
        // is refused rather than leaking every department's rows.
        let no_dept = Principal::user("ghost", &[]).with_clearance(DataClass::Confidential);
        let intent = QueryIntent {
            select: vec!["entry_id".into()],
            from: "ledger_entries".into(),
            filters: vec![],
            order_by: vec![],
            limit: None,
        };
        let err = validate_and_compile(&intent, &scoped_schema(), &no_dept).unwrap_err();
        assert_eq!(err, QueryError::RowScopeUnavailable("owner_dept".into()));
    }

    #[test]
    fn row_scope_is_not_bypassed_by_admin_or_high_clearance() {
        // Row scope is uniform: even an admin (Pii clearance) querying is filtered to their own
        // rows. Clearance widens which COLUMNS are readable, never which ROWS are visible.
        let admin = Principal::admin("root").with_department("audit");
        let intent = QueryIntent {
            select: vec!["entry_id".into()],
            from: "ledger_entries".into(),
            filters: vec![],
            order_by: vec![],
            limit: Some(3),
        };
        let q = validate_and_compile(&intent, &scoped_schema(), &admin).unwrap();
        assert!(q.sql.contains("WHERE \"owner_dept\" = $1"));
        assert_eq!(q.params, vec![Value::Text("audit".into())]);
    }

    #[test]
    fn user_id_row_scope_filters_to_the_caller() {
        let table = Table::new_scoped(
            "my_notes",
            vec![
                Column::new("note_id", DataClass::Internal).unwrap(),
                Column::new("owner_user", DataClass::Internal).unwrap(),
            ],
            vec![RowScope::new("owner_user", PrincipalAttr::UserId)],
        )
        .unwrap();
        let schema = Schema::new(vec![table]).unwrap();
        let intent = QueryIntent {
            select: vec!["note_id".into()],
            from: "my_notes".into(),
            filters: vec![],
            order_by: vec![],
            limit: Some(20),
        };
        let p = Principal::user("kannan", &[]);
        let q = validate_and_compile(&intent, &schema, &p).unwrap();
        assert!(q.sql.contains("WHERE \"owner_user\" = $1"));
        assert_eq!(q.params, vec![Value::Text("kannan".into())]);
    }

    #[test]
    fn multiple_row_scopes_are_all_injected_in_order() {
        let table = Table::new_scoped(
            "ledger_entries",
            vec![
                Column::new("entry_id", DataClass::Internal).unwrap(),
                Column::new("owner_dept", DataClass::Internal).unwrap(),
                Column::new("owner_user", DataClass::Internal).unwrap(),
            ],
            vec![
                RowScope::new("owner_dept", PrincipalAttr::Department),
                RowScope::new("owner_user", PrincipalAttr::UserId),
            ],
        )
        .unwrap();
        let schema = Schema::new(vec![table]).unwrap();
        let intent = QueryIntent {
            select: vec!["entry_id".into()],
            from: "ledger_entries".into(),
            filters: vec![],
            order_by: vec![],
            limit: Some(7),
        };
        let q = validate_and_compile(&intent, &schema, &scoped_analyst()).unwrap();
        assert_eq!(
            q.sql,
            "SELECT \"entry_id\" FROM \"ledger_entries\" \
             WHERE \"owner_dept\" = $1 AND \"owner_user\" = $2 LIMIT 7"
        );
        assert_eq!(
            q.params,
            vec![
                Value::Text("settlement-ops".into()),
                Value::Text("analyst-1".into()),
            ]
        );
    }

    #[test]
    fn safequery_settings_carry_principal_identity_for_native_db_rls() {
        let q = validate_and_compile(
            &QueryIntent {
                select: vec!["entry_id".into()],
                from: "ledger_entries".into(),
                filters: vec![],
                order_by: vec![],
                limit: Some(1),
            },
            &scoped_schema(),
            &scoped_analyst(),
        )
        .unwrap();
        assert_eq!(
            q.settings,
            vec![
                SessionSetting {
                    key: "app.principal_user_id".into(),
                    value: Value::Text("analyst-1".into()),
                },
                SessionSetting {
                    key: "app.principal_department".into(),
                    value: Value::Text("settlement-ops".into()),
                },
            ]
        );
        // A principal with no department omits the department binding (not an empty string).
        let no_dept = Principal::user("ghost", &[]);
        let q2 = validate_and_compile(
            &QueryIntent {
                select: vec!["entry_id".into()],
                from: "ledger_entries".into(),
                filters: vec![],
                order_by: vec![],
                limit: Some(1),
            },
            &ledger_schema(),
            &no_dept,
        )
        .unwrap();
        assert_eq!(
            q2.settings,
            vec![SessionSetting {
                key: "app.principal_user_id".into(),
                value: Value::Text("ghost".into()),
            }]
        );
    }

    #[test]
    fn unscoped_table_injects_no_row_predicate() {
        // Backward-compat: a table with no RowScope compiles exactly as before (no WHERE injected).
        let intent = QueryIntent {
            select: vec!["entry_id".into()],
            from: "ledger_entries".into(),
            filters: vec![],
            order_by: vec![],
            limit: Some(10),
        };
        let q = validate_and_compile(&intent, &ledger_schema(), &analyst()).unwrap();
        assert_eq!(
            q.sql,
            "SELECT \"entry_id\" FROM \"ledger_entries\" LIMIT 10"
        );
        assert!(q.params.is_empty());
    }

    #[test]
    fn row_scope_over_unknown_column_is_rejected_at_build() {
        let err = Table::new_scoped(
            "t",
            vec![Column::new("a", DataClass::Internal).unwrap()],
            vec![RowScope::new("nonexistent", PrincipalAttr::Department)],
        )
        .unwrap_err();
        assert_eq!(err, SchemaError::UnknownScopeColumn("nonexistent".into()));
        // The chainable builder rejects it too.
        let t = Table::new("t", vec![Column::new("a", DataClass::Internal).unwrap()]).unwrap();
        assert_eq!(
            t.with_row_scope(RowScope::new("nope", PrincipalAttr::UserId))
                .unwrap_err(),
            SchemaError::UnknownScopeColumn("nope".into())
        );
    }

    #[test]
    fn config_loaded_schema_with_row_scopes_deserializes_and_applies() {
        let json = r#"{
            "tables": [{
                "name": "ledger_entries",
                "columns": [
                    {"name": "entry_id", "data_class": "internal"},
                    {"name": "owner_dept", "data_class": "internal"}
                ],
                "row_scopes": [{"column": "owner_dept", "attr": "department"}]
            }],
            "max_limit": 100
        }"#;
        let schema: Schema = serde_json::from_str(json).unwrap();
        let q = validate_and_compile(
            &QueryIntent {
                select: vec!["entry_id".into()],
                from: "ledger_entries".into(),
                filters: vec![],
                order_by: vec![],
                limit: None,
            },
            &schema,
            &scoped_analyst(),
        )
        .unwrap();
        assert_eq!(
            q.sql,
            "SELECT \"entry_id\" FROM \"ledger_entries\" WHERE \"owner_dept\" = $1 LIMIT 100"
        );
        assert_eq!(q.params, vec![Value::Text("settlement-ops".into())]);
    }

    #[test]
    fn config_loaded_row_scope_over_unknown_column_is_rejected() {
        let json = r#"{
            "tables": [{
                "name": "t",
                "columns": [{"name": "a", "data_class": "internal"}],
                "row_scopes": [{"column": "ghost", "attr": "user_id"}]
            }],
            "max_limit": 10
        }"#;
        assert!(serde_json::from_str::<Schema>(json).is_err());
    }

    #[test]
    fn minimal_intent_defaults_filters_order_and_limit() {
        // Only select + from provided; filters/order_by default empty, limit defaults to clamp.
        let json = r#"{"select": ["entry_id"], "from": "ledger_entries"}"#;
        let intent: QueryIntent = serde_json::from_str(json).unwrap();
        assert!(intent.filters.is_empty());
        assert!(intent.order_by.is_empty());
        assert_eq!(intent.limit, None);
        let q = validate_and_compile(&intent, &ledger_schema(), &analyst()).unwrap();
        assert_eq!(
            q.sql,
            "SELECT \"entry_id\" FROM \"ledger_entries\" LIMIT 500"
        );
        assert!(q.limit_was_clamped);
    }

    // =======================================================================
    // SURF-09 — the live tool-boundary the parent (ainxt-tools/ainxt-mcp) wires:
    //   model-emitted JSON  →  QueryIntent (deny_unknown_fields)  →  validate_and_compile
    // This is the exact call sequence a `query_ledger` capability performs; the model NEVER
    // reaches SQL. Exercised end-to-end here against an injected Schema + Principal.
    // =======================================================================

    /// The single function a tool handler invokes. Mirrors what the parent will implement in a
    /// RESERVED crate: deserialize the model's JSON proposal, then compile under the caller's
    /// identity. Kept in-test to prove the seam is closed and callable with only public API.
    fn tool_boundary(
        model_json: &str,
        schema: &Schema,
        principal: &Principal,
    ) -> Result<SafeQuery, String> {
        let intent: QueryIntent =
            serde_json::from_str(model_json).map_err(|e| format!("rejected intent JSON: {e}"))?;
        validate_and_compile(&intent, schema, principal).map_err(|e| e.to_string())
    }

    #[test]
    fn gap_ainxt_nl2sql_surf09_tool_boundary_compiles_and_scopes() {
        // A well-formed model proposal compiles to bounded, parameterized, RLS-safe SQL.
        let model_json = r#"{
            "select": ["entry_id", "amount_minor"],
            "from": "ledger_entries",
            "filters": [{"column": "amount_minor", "predicate": {"ge": {"int": 1000}}}],
            "limit": 999999
        }"#;
        let q = tool_boundary(model_json, &ledger_schema(), &analyst()).unwrap();
        assert!(q.sql.starts_with("SELECT "));
        assert!(
            !q.sql.contains(';'),
            "statement stacking must be structurally impossible"
        );
        assert!(
            !q.sql.contains("1000"),
            "values must be parameterized, never inlined"
        );
        assert_eq!(q.params, vec![Value::Int(1000)]);
        // Oversized limit clamped to the schema ceiling (bounded result).
        assert_eq!(q.limit_applied, 500);
        assert!(q.limit_was_clamped);
        // Defense-in-depth: the caller identity rides out-of-band for native-DB RLS.
        assert!(q.settings.iter().any(|s| s.key == "app.principal_user_id"));
    }

    #[test]
    fn gap_ainxt_nl2sql_surf09_tool_boundary_blocks_raw_sql_smuggle() {
        // The model tries to smuggle a raw SQL fragment as an extra JSON field — deny_unknown_fields
        // rejects it at the boundary, before compilation. No injection surface reaches the DB.
        let malicious = r#"{
            "select": ["entry_id"],
            "from": "ledger_entries",
            "raw_sql": "; DROP TABLE ledger_entries; --"
        }"#;
        let err = tool_boundary(malicious, &ledger_schema(), &analyst()).unwrap_err();
        assert!(
            err.starts_with("rejected intent JSON"),
            "smuggled field must be refused: {err}"
        );
    }

    #[test]
    fn gap_ainxt_nl2sql_surf09_tool_boundary_hides_over_clearance_existence() {
        // An under-cleared caller asking for a Pii column gets ColumnNotAvailable — indistinguishable
        // from a nonexistent column, so no existence oracle leaks through the tool.
        let json = r#"{"select": ["holder_pan"], "from": "ledger_entries"}"#;
        let err = tool_boundary(json, &ledger_schema(), &analyst()).unwrap_err();
        assert_eq!(err, QueryError::ColumnNotAvailable.to_string());
        // `ColumnNotAvailable` is a unit variant precisely so the column name cannot ride along
        // into the rendered refusal — assert the hiding this test is named for.
        assert!(
            !err.contains("holder_pan"),
            "the tool boundary must not name the probed column: {err}"
        );
    }
}
