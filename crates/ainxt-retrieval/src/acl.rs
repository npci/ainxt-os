// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Node/edge-level RBAC beyond the data-class scalar.
//!
//! Design: `CONTEXT_FABRIC.md` §2 ("node/edge-level RBAC + data-class labels") and §8.3
//! (department / `ad_level` **pre-rank existence filtering**). The base retrieval ACL
//! ([`crate::Corpus::is_visible`]) gates on the [`DataClass`] scalar alone; real deployment data also
//! carries *who* may see a node along orthogonal axes: which **department** owns it, a minimum
//! AD **seniority** (`ad_level`, 0 = most senior exec … 6 = junior), and explicit **allow/deny
//! groups**. A settlement postmortem may be `Internal` by class yet visible only to
//! `settlement-eng` at `ad_level <= 3`.
//!
//! Two rules make this safe for payments data:
//!
//! 1. **Pre-rank, existence-never-leaks.** A [`NodeAcl`] is evaluated in the same pre-rank pass as
//!    the class filter (`crate::Corpus::allowed_ctx`), so a node the caller may not see is never
//!    scored, fused, reranked, or counted — a post-filter would leak existence via result counts
//!    or score gaps (`CONTEXT_FABRIC.md` §3 / gap AJ).
//! 2. **Fail-closed on missing claims.** If an ACL *requires* a seniority ceiling or an allow-group
//!    but the [`AccessContext`] cannot prove the caller satisfies it (claim absent), the node is
//!    **denied**, never allowed by omission. A deny-group always wins.
//!
//! This is pure and deterministic (sorted `BTreeSet`s, no rng/clock). The context is built from an
//! `ainxt_types::Principal` plus the seniority/group claims the surface resolves from the JWT/OBO
//! token — those two live in `ainxt-types` / the session layer, so they are passed in here rather
//! than reached for.

use std::collections::BTreeSet;

use ainxt_types::{DataClass, Principal};
use serde::{Deserialize, Serialize};

/// The caller's access claims for a retrieval turn — the read side of the OBO/JWT context. Class
/// clearance plus the orthogonal RBAC axes a [`NodeAcl`] can gate on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessContext {
    /// Max data class the caller may read (the scalar gate; still enforced first).
    pub clearance: DataClass,
    /// The caller's AD department / org unit, if known.
    pub department: Option<String>,
    /// The caller's AD seniority level (0 = most senior exec … 6 = junior), if known. A node with
    /// a `max_ad_level` ceiling is visible only when `ad_level <= max_ad_level` (more senior).
    pub ad_level: Option<u8>,
    /// Group/role memberships (sorted). Used against a node's allow/deny groups.
    pub groups: BTreeSet<String>,
}

impl AccessContext {
    /// Build the caller's full node/edge-RBAC context from the OBO [`Principal`]: clearance +
    /// department + **`ad_level` seniority** + **group memberships** — every axis a [`NodeAcl`] can
    /// gate on, carried straight from the JWT/OBO claims the [`Principal`] holds.
    ///
    /// This is the LIVE served grounding path's context builder (`ainxt-convo`'s `assemble_grounding`
    /// calls it every turn). Before the `ad_level`/`groups` claims were added to [`Principal`] this
    /// dropped both axes to `None`/empty, so on the served path an `ad_level`- or group-gated node was
    /// unenforceable — a too-junior/wrong-group caller could not be distinguished from an entitled one
    /// (the entitled senior lost their grounding; the axes never bound). Now every axis the principal
    /// carries flows through. A claim the principal does not carry stays absent → the ACL fail-closes
    /// on it (an `ad_level`-gated node is denied to a principal with no `ad_level`), never allowed by
    /// omission.
    pub fn from_principal(p: &Principal) -> Self {
        AccessContext {
            clearance: p.clearance,
            department: p.department.clone(),
            ad_level: p.ad_level,
            groups: p.groups.iter().cloned().collect(),
        }
    }

    /// A full context with clearance + department + seniority + groups.
    pub fn new(
        clearance: DataClass,
        department: Option<&str>,
        ad_level: Option<u8>,
        groups: &[&str],
    ) -> Self {
        AccessContext {
            clearance,
            department: department.map(|d| d.to_string()),
            ad_level,
            groups: groups.iter().map(|g| g.to_string()).collect(),
        }
    }

    /// Builder: attach seniority to a principal-derived context.
    pub fn with_ad_level(mut self, ad_level: u8) -> Self {
        self.ad_level = Some(ad_level);
        self
    }

    /// Builder: attach group memberships.
    pub fn with_groups(mut self, groups: &[&str]) -> Self {
        self.groups = groups.iter().map(|g| g.to_string()).collect();
        self
    }
}

/// Per-node access control beyond the data-class scalar. Every axis is optional; an all-`None`
/// ACL permits everyone (equivalent to no ACL). Evaluated pre-rank and fail-closed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeAcl {
    /// If `Some`, only callers in one of these departments may see the node. An empty set here is
    /// treated the same as `Some(∅)` → nobody (a deliberately locked node), not everybody.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub departments: Option<BTreeSet<String>>,
    /// If `Some`, the caller's `ad_level` must be `<=` this (i.e. at least this senior). A caller
    /// with no known `ad_level` is denied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_ad_level: Option<u8>,
    /// If non-empty, the caller must be in at least one of these groups. Empty = no allow-list
    /// constraint.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub allow_groups: BTreeSet<String>,
    /// A caller in any deny-group is refused regardless of every other axis (deny always wins).
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub deny_groups: BTreeSet<String>,
}

impl NodeAcl {
    pub fn new() -> Self {
        NodeAcl::default()
    }

    /// Restrict to a set of departments.
    pub fn departments(mut self, depts: &[&str]) -> Self {
        self.departments = Some(depts.iter().map(|d| d.to_string()).collect());
        self
    }

    /// Require at least this seniority (`ad_level <= max`).
    pub fn max_ad_level(mut self, max: u8) -> Self {
        self.max_ad_level = Some(max);
        self
    }

    /// Require membership in at least one allow-group.
    pub fn allow_groups(mut self, groups: &[&str]) -> Self {
        self.allow_groups = groups.iter().map(|g| g.to_string()).collect();
        self
    }

    /// Deny any caller in one of these groups.
    pub fn deny_groups(mut self, groups: &[&str]) -> Self {
        self.deny_groups = groups.iter().map(|g| g.to_string()).collect();
        self
    }

    /// Whether `ctx` satisfies EVERY constraint on this ACL. Fail-closed: an unprovable required
    /// claim denies; a deny-group match denies unconditionally.
    pub fn permits(&self, ctx: &AccessContext) -> bool {
        // Deny-group wins first, always.
        if self.deny_groups.iter().any(|g| ctx.groups.contains(g)) {
            return false;
        }
        // Department gate.
        if let Some(depts) = &self.departments {
            match &ctx.department {
                Some(d) if depts.contains(d) => {}
                _ => return false,
            }
        }
        // Seniority gate — unknown ad_level cannot prove seniority → deny.
        if let Some(max) = self.max_ad_level {
            match ctx.ad_level {
                Some(level) if level <= max => {}
                _ => return false,
            }
        }
        // Allow-group gate.
        if !self.allow_groups.is_empty()
            && !self.allow_groups.iter().any(|g| ctx.groups.contains(g))
        {
            return false;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_acl_permits_everyone() {
        let acl = NodeAcl::new();
        assert!(acl.permits(&AccessContext::new(DataClass::Public, None, None, &[])));
    }

    #[test]
    fn department_gate_denies_other_departments_and_unknown() {
        let acl = NodeAcl::new().departments(&["settlement-eng"]);
        assert!(acl.permits(&AccessContext::new(
            DataClass::Internal,
            Some("settlement-eng"),
            None,
            &[]
        )));
        assert!(!acl.permits(&AccessContext::new(
            DataClass::Internal,
            Some("hr"),
            None,
            &[]
        )));
        // Fail-closed: unknown department cannot prove membership.
        assert!(!acl.permits(&AccessContext::new(DataClass::Internal, None, None, &[])));
    }

    #[test]
    fn seniority_gate_requires_known_level_at_or_above() {
        let acl = NodeAcl::new().max_ad_level(3);
        assert!(acl.permits(&AccessContext::new(DataClass::Internal, None, Some(2), &[])));
        assert!(acl.permits(&AccessContext::new(DataClass::Internal, None, Some(3), &[])));
        // A junior (higher number = less senior) is denied.
        assert!(!acl.permits(&AccessContext::new(DataClass::Internal, None, Some(4), &[])));
        // Unknown seniority cannot prove the ceiling → deny.
        assert!(!acl.permits(&AccessContext::new(DataClass::Internal, None, None, &[])));
    }

    #[test]
    fn allow_and_deny_groups() {
        let acl = NodeAcl::new()
            .allow_groups(&["oncall", "recon"])
            .deny_groups(&["contractor"]);
        assert!(acl.permits(&AccessContext::new(
            DataClass::Internal,
            None,
            None,
            &["oncall"]
        )));
        // No allow-group membership → deny.
        assert!(!acl.permits(&AccessContext::new(
            DataClass::Internal,
            None,
            None,
            &["random"]
        )));
        // Deny-group wins even with an allow-group present.
        assert!(!acl.permits(&AccessContext::new(
            DataClass::Internal,
            None,
            None,
            &["oncall", "contractor"]
        )));
    }

    #[test]
    fn from_principal_carries_department_and_seniority_and_groups() {
        // A principal WITHOUT the seniority/group claims: the ACL that requires them fail-closes.
        let p = Principal::user("u", &[]).with_department("settlement-eng");
        let ctx = AccessContext::from_principal(&p);
        assert_eq!(ctx.department.as_deref(), Some("settlement-eng"));
        assert_eq!(ctx.ad_level, None);
        assert!(ctx.groups.is_empty());
        let acl = NodeAcl::new().max_ad_level(3);
        assert!(
            !acl.permits(&ctx),
            "no ad_level claim → the seniority-gated node fail-closes"
        );

        // A principal WITH the OBO seniority + group claims: from_principal carries them, so the
        // grounding path can now enforce the ad_level + allow-group axes (the served gap).
        let senior = Principal::user("s", &[])
            .with_department("settlement-eng")
            .with_ad_level(2)
            .with_groups(&["oncall", "recon"]);
        let sctx = AccessContext::from_principal(&senior);
        assert_eq!(sctx.ad_level, Some(2));
        assert!(sctx.groups.contains("oncall"));
        // The entitled senior in an allowed group now PASSES a node gated on both axes — before, the
        // dropped claims denied them (over-restrictive) and the axes never bound.
        let gated = NodeAcl::new()
            .departments(&["settlement-eng"])
            .max_ad_level(3)
            .allow_groups(&["oncall"]);
        assert!(gated.permits(&sctx));
    }
}
