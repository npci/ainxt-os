// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Row-level-security row-filter contract — a SET LOCAL-style predicate bound from the OBO
//! principal and applied pre-rank on the retrieval query.
//!
//! Design: `CONTEXT_FABRIC.md` §8.3 ("department / `ad_level` pre-rank existence filtering") and
//! gap AJ ("retrieval-time CHUNK-level ACL applied PRE-rank — a post-filter leaks existence").
//! [`acl::NodeAcl`](crate::acl::NodeAcl) gates on labels *baked into the node* (its owning
//! department, a seniority ceiling, allow/deny groups). This module closes the orthogonal half:
//! a **per-request** row policy whose required value is **bound from the caller's OBO principal at
//! query start** — the retrieval analogue of Postgres row-level security, where
//! `SET LOCAL app.tenant = '<principal.department>'` binds a session setting and a table policy
//! `USING (tenant = current_setting('app.tenant'))` filters every row against it.
//!
//! Two invariants make this safe for payments data:
//!
//! 1. **Pre-rank, existence-never-leaks.** [`RowFilter::permits`] is evaluated in
//!    [`Corpus::hybrid_rls`](crate::Corpus::hybrid_rls)'s pre-rank pass, alongside the class/node
//!    ACL, so a row the caller may not read is never scored, fused, reranked, or counted.
//! 2. **Fail-closed.** A policy is satisfied only when the bound session setting is present AND the
//!    row carries the referenced attribute AND the two are equal. A missing binding, a missing row
//!    attribute, or a mismatch all **deny** the row — never permit by omission.
//!
//! This is a **read-filter, not an admission gate**: it shapes which rows a turn may read, never
//! whether the turn proceeds (the runtime never denies a turn on a clearance/row-scope basis).
//! Pure and deterministic: sorted [`BTreeMap`] settings, no clock/rng.

use std::collections::BTreeMap;

use ainxt_types::Principal;
use serde::{Deserialize, Serialize};

use crate::Chunk;

/// The standard OBO session setting name for the caller's department/org unit — the value
/// [`RlsSession::bind`] captures from [`Principal::department`].
pub const SETTING_DEPARTMENT: &str = "department";
/// The standard OBO session setting name for the caller's user id — captured from
/// [`Principal::user_id`].
pub const SETTING_USER_ID: &str = "user_id";

/// The bound OBO session: values captured from the principal at query start (the `SET LOCAL`
/// half of RLS). Policies reference these by name; a name with no bound value fail-closes any
/// policy that references it. A principal claim that is `None` (e.g. an unknown department) is
/// simply *not bound*, so a department-isolation policy correctly denies rather than matching
/// against an empty string.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RlsSession {
    settings: BTreeMap<String, String>,
}

impl RlsSession {
    /// An empty session (no bound settings) — every policy referencing a setting fail-closes.
    pub fn new() -> Self {
        RlsSession::default()
    }

    /// Bind the standard OBO settings from a principal — the retrieval analogue of issuing
    /// `SET LOCAL app.department = '<dept>'` / `app.user_id = '<id>'` from the JWT/OBO token at
    /// the start of the request. `department` is only bound when the principal actually carries it
    /// (a `None` department stays unbound, so department isolation fail-closes).
    pub fn bind(principal: &Principal) -> Self {
        let mut settings = BTreeMap::new();
        settings.insert(SETTING_USER_ID.to_string(), principal.user_id.clone());
        if let Some(dept) = &principal.department {
            settings.insert(SETTING_DEPARTMENT.to_string(), dept.clone());
        }
        RlsSession { settings }
    }

    /// Bind an additional/custom setting (e.g. a tenant id the surface resolves separately).
    pub fn set(mut self, name: &str, value: &str) -> Self {
        self.settings.insert(name.to_string(), value.to_string());
        self
    }

    /// The bound value for `name`, if any.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.settings.get(name).map(|s| s.as_str())
    }
}

/// One row-security policy: the row attribute `attribute` must equal the value bound to session
/// setting `setting` (`USING (<attribute> = current_setting('<setting>'))`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RlsPolicy {
    /// The row attribute key compared (looked up in [`Chunk::attributes`]).
    pub attribute: String,
    /// The bound session setting name whose value the attribute must equal.
    pub setting: String,
}

/// The row-filter contract applied pre-rank on the retrieval query: a bound [`RlsSession`] plus
/// the policies every readable row must satisfy. A row passes iff EVERY policy holds; an empty
/// policy set permits all rows (RLS disabled). Fail-closed on any missing binding or attribute.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RowFilter {
    session: RlsSession,
    policies: Vec<RlsPolicy>,
}

impl RowFilter {
    /// A filter over a bound session with no policies yet (permits everything until a policy is
    /// added via [`RowFilter::require`]).
    pub fn new(session: RlsSession) -> Self {
        RowFilter {
            session,
            policies: Vec::new(),
        }
    }

    /// Require that the row's `attribute` equal the value bound to session `setting`.
    pub fn require(mut self, attribute: &str, setting: &str) -> Self {
        self.policies.push(RlsPolicy {
            attribute: attribute.to_string(),
            setting: setting.to_string(),
        });
        self
    }

    /// The common case: **department isolation** bound from the principal — a row is readable only
    /// when its `department` attribute equals the caller's own department. A principal with no
    /// department produces an unbound setting, so this fail-closes (reads nothing) rather than
    /// leaking cross-department rows.
    pub fn department_isolation(principal: &Principal) -> Self {
        RowFilter::new(RlsSession::bind(principal)).require(SETTING_DEPARTMENT, SETTING_DEPARTMENT)
    }

    /// Whether `chunk` satisfies every policy. Fail-closed: an unbound setting, a row missing the
    /// referenced attribute, or a value mismatch each deny the row.
    pub fn permits(&self, chunk: &Chunk) -> bool {
        self.policies.iter().all(|p| {
            let want = match self.session.get(&p.setting) {
                Some(v) => v,
                None => return false,
            };
            match chunk.attributes.get(&p.attribute) {
                Some(have) => have == want,
                None => false,
            }
        })
    }

    /// Whether any policy is in force (an empty filter is a no-op that permits all rows).
    pub fn is_empty(&self) -> bool {
        self.policies.is_empty()
    }
}

// ---------------------------------------------------------------------------------------
// Break-glass audited RLS override (round-15 `context-fabric` LOW gap)
// ---------------------------------------------------------------------------------------
//
// `ainxt-nl2sql`'s row-scope is deliberately un-bypassable ("no admin bypass... because 'see all
// rows' is exactly the cross-tenant leak this exists to stop"). A senior/auditor cross-scope READ
// for a genuine, reviewed reason (an RBI audit, an incident investigation) is a real, narrower need
// — distinct from a silent admin bypass — so it must be its OWN explicit, capability-gated,
// reason-coded, fully-AUDITED mechanism, never a role/clearance flag that quietly turns RLS off.
// The shape mirrors `ainxt-lifecycle::breakglass` (explicit granted capability, reason-coded, no
// standing grant): a caller without [`RLS_BREAK_GLASS_CAP`] is refused; a caller with it gets the
// override PLUS the mandatory [`BreakGlassAudit`] record in the SAME return value, so it is
// structurally impossible to obtain the override without also obtaining what must be logged for it.

/// The explicit capability a principal must be GRANTED (checked against the JWT/OBO's granted caps
/// — never the admin/role shortcut) to open a break-glass RLS override. Least-privilege: this is a
/// capability a senior/auditor identity carries, not a role level.
pub const RLS_BREAK_GLASS_CAP: &str = "retrieval:break-glass-cross-scope-read";

/// Why a break-glass override was refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BreakGlassDenied {
    /// The principal's granted capabilities do not include [`RLS_BREAK_GLASS_CAP`].
    NotGranted,
}

/// A single-query, explicitly granted, reason-coded exception to a caller's own row scope. Never a
/// standing grant — the caller constructs a fresh one per read, so the reason travels with the exact
/// query it justifies. Every field is PII-free (ids/reason codes, never row contents), so this is a
/// safe payload to write straight into the audit trail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BreakGlassGrant {
    /// The approving senior/auditor identity's principal id (never a role name — a real approver).
    pub granted_by: String,
    /// A PII-free, reviewable reason code (e.g. `"RBI_AUDIT_2026_Q3"`, `"INC-4471-investigation"`).
    pub reason_code: String,
    /// The row-scope value the caller is temporarily reading AS (e.g. a department outside their
    /// own) — bound the SAME way an ordinary [`RowFilter::department_isolation`] would bind it, so
    /// the override is scoped to exactly one cross-scope value, never "all rows".
    pub scope: String,
}

impl BreakGlassGrant {
    pub fn new(granted_by: &str, reason_code: &str, scope: &str) -> Self {
        BreakGlassGrant {
            granted_by: granted_by.to_string(),
            reason_code: reason_code.to_string(),
            scope: scope.to_string(),
        }
    }
}

/// The mandatory audit record produced alongside every break-glass override — WHO exercised it, WHO
/// approved it, WHY, and WHAT SCOPE it reached, at what logical tick. This is the payload the
/// composition root MUST append to the one Event Log before serving any row through the override;
/// an override exercised with no corresponding audit entry never happened, for compliance purposes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BreakGlassAudit {
    pub principal_id: String,
    pub granted_by: String,
    pub reason_code: String,
    pub scope: String,
    pub tick: u64,
}

impl RowFilter {
    /// Open an audited break-glass override of `principal`'s OWN row scope, permitting rows scoped
    /// to `grant.scope` instead (a senior/auditor cross-scope read). Fail-closed on the capability
    /// check: `caps` must contain [`RLS_BREAK_GLASS_CAP]`, checked structurally here rather than
    /// trusted from a docstring. On success, returns the overridden [`RowFilter`] **together with**
    /// the [`BreakGlassAudit`] the caller must log — never the filter alone, so an override cannot
    /// silently go unaudited by omission at the call site.
    pub fn break_glass_override(
        principal: &Principal,
        caps: &[&str],
        grant: BreakGlassGrant,
        tick: u64,
    ) -> Result<(RowFilter, BreakGlassAudit), BreakGlassDenied> {
        if !caps.contains(&RLS_BREAK_GLASS_CAP) {
            return Err(BreakGlassDenied::NotGranted);
        }
        let session = RlsSession::new().set(SETTING_DEPARTMENT, &grant.scope);
        let filter = RowFilter::new(session).require(SETTING_DEPARTMENT, SETTING_DEPARTMENT);
        let audit = BreakGlassAudit {
            principal_id: principal.user_id.clone(),
            granted_by: grant.granted_by.clone(),
            reason_code: grant.reason_code.clone(),
            scope: grant.scope.clone(),
            tick,
        };
        Ok((filter, audit))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ainxt_types::DataClass;

    fn chunk_with_dept(id: &str, dept: &str) -> Chunk {
        Chunk::new(id, "settlement report", DataClass::Internal).with_attribute("department", dept)
    }

    #[test]
    fn department_isolation_permits_same_dept_only() {
        let p = Principal::user("u", &[]).with_department("settlement-eng");
        let f = RowFilter::department_isolation(&p);
        assert!(f.permits(&chunk_with_dept("a", "settlement-eng")));
        assert!(!f.permits(&chunk_with_dept("b", "hr")));
    }

    #[test]
    fn fail_closed_on_missing_binding_and_missing_attribute() {
        // No department on the principal → setting unbound → deny even a matching-looking row.
        let no_dept = Principal::user("u", &[]);
        let f = RowFilter::department_isolation(&no_dept);
        assert!(!f.permits(&chunk_with_dept("a", "settlement-eng")));

        // Bound principal, but the row carries no department attribute → deny.
        let p = Principal::user("u", &[]).with_department("settlement-eng");
        let f = RowFilter::department_isolation(&p);
        let no_attr = Chunk::new("x", "settlement report", DataClass::Internal);
        assert!(!f.permits(&no_attr));
    }

    #[test]
    fn empty_filter_permits_all() {
        let p = Principal::user("u", &[]);
        let f = RowFilter::new(RlsSession::bind(&p));
        assert!(f.is_empty());
        assert!(f.permits(&chunk_with_dept("a", "anything")));
        assert!(f.permits(&Chunk::new("x", "no attrs", DataClass::Public)));
    }

    #[test]
    fn custom_setting_binding() {
        let session = RlsSession::new().set("tenant", "acme");
        let f = RowFilter::new(session).require("tenant", "tenant");
        assert!(
            f.permits(&Chunk::new("a", "t", DataClass::Public).with_attribute("tenant", "acme"))
        );
        assert!(
            !f.permits(&Chunk::new("b", "t", DataClass::Public).with_attribute("tenant", "globex"))
        );
    }

    #[test]
    fn r15_break_glass_denied_without_the_explicit_capability() {
        // An ordinary caller — including one with an unrelated capability, and including a caller
        // whose OWN department already matches the requested scope — is refused: the capability
        // check is structural, never inferred from "the request looks legitimate".
        let auditor = Principal::user("auditor-1", &[]).with_department("beta");
        let grant = BreakGlassGrant::new("cco-1", "RBI_AUDIT_2026_Q3", "beta");
        let err =
            RowFilter::break_glass_override(&auditor, &["chat.send"], grant, 100).unwrap_err();
        assert_eq!(err, BreakGlassDenied::NotGranted);
    }

    #[test]
    fn r15_break_glass_grants_audited_cross_scope_read() {
        // A caller whose OWN department is "alpha" is granted a reason-coded exception to read
        // "beta"-scoped rows — the exact cross-department leak `department_isolation` otherwise
        // forbids — ONLY because they carry the explicit capability.
        let auditor = Principal::user("auditor-1", &[]).with_department("alpha");
        let grant = BreakGlassGrant::new("cco-1", "RBI_AUDIT_2026_Q3", "beta");
        let (filter, audit) =
            RowFilter::break_glass_override(&auditor, &[RLS_BREAK_GLASS_CAP], grant, 42).unwrap();

        // The override reaches the cross-department row the caller's OWN scope would have denied.
        assert!(filter.permits(&chunk_with_dept("beta-row", "beta")));
        assert!(
            !filter.permits(&chunk_with_dept("alpha-row", "alpha")),
            "scoped to beta ONLY, not alpha too"
        );

        // The mandatory audit record carries WHO/WHO-APPROVED/WHY/WHAT-SCOPE — the payload the
        // composition root logs to the one Event Log before serving any row through the override.
        assert_eq!(audit.principal_id, "auditor-1");
        assert_eq!(audit.granted_by, "cco-1");
        assert_eq!(audit.reason_code, "RBI_AUDIT_2026_Q3");
        assert_eq!(audit.scope, "beta");
        assert_eq!(audit.tick, 42);
    }
}
