// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Identity-derived scope isolation (design §5, §7.2). Retrieval isolation is **not** an optional
//! query parameter the caller may forget to set — it is derived from the authenticated caller's
//! identity and memberships. An [`AccessScope`] wraps a [`Principal`] plus the set of teams /
//! repos / departments the caller belongs to (populated by the surface from the JWT + org tree),
//! and answers a single pre-rank question: *may this caller see an item in this [`Scope`]?*
//!
//! Rules:
//! - [`Scope::Org`] — visible to any authenticated caller.
//! - [`Scope::Department`] / [`Scope::Team`] / [`Scope::Repo`] — visible only if the caller is a
//!   member (or an admin).
//! - [`Scope::User`] — personal memory, visible only to its owner, or to an admin **under an
//!   audited break-glass justification** (design §5: "visible to admins only with a logged
//!   justification").
//!
//! Data-class clearance is enforced *in addition* to scope (both must pass), by the store.

use std::collections::BTreeSet;

use crate::Scope;
use ainxt_types::{Principal, Role};

/// The caller's reachable scope, derived from identity + memberships. Built by the surface layer;
/// the store consults it pre-rank so an item outside reach is never even ranked (existence not
/// leaked via omission from a ranked list).
#[derive(Debug, Clone)]
pub struct AccessScope {
    principal: Principal,
    teams: BTreeSet<String>,
    repos: BTreeSet<String>,
    departments: BTreeSet<String>,
    /// Present only when an admin is exercising break-glass to read another user's personal memory.
    /// The string is the mandatory justification (the audit reason).
    break_glass: Option<String>,
}

impl AccessScope {
    /// Build from a principal alone: reaches `Org`, the principal's own `User` scope, and — if the
    /// principal carries a department — that department. Team/repo memberships must be added
    /// explicitly with [`with_teams`](AccessScope::with_teams) / [`with_repos`](AccessScope::with_repos).
    pub fn from_principal(principal: Principal) -> Self {
        let mut departments = BTreeSet::new();
        if let Some(d) = &principal.department {
            departments.insert(d.clone());
        }
        AccessScope {
            principal,
            teams: BTreeSet::new(),
            repos: BTreeSet::new(),
            departments,
            break_glass: None,
        }
    }

    /// Add team memberships.
    pub fn with_teams(mut self, teams: &[&str]) -> Self {
        self.teams.extend(teams.iter().map(|t| t.to_string()));
        self
    }

    /// Add repo memberships.
    pub fn with_repos(mut self, repos: &[&str]) -> Self {
        self.repos.extend(repos.iter().map(|r| r.to_string()));
        self
    }

    /// Add department memberships (beyond the principal's primary department).
    pub fn with_departments(mut self, departments: &[&str]) -> Self {
        self.departments
            .extend(departments.iter().map(|d| d.to_string()));
        self
    }

    /// Admin-only: exercise break-glass to read another user's personal memory. The `justification`
    /// is mandatory and is what the store records to the (tamper-evident) audit log on such a read.
    pub fn with_break_glass(mut self, justification: &str) -> Self {
        self.break_glass = Some(justification.to_string());
        self
    }

    /// The underlying principal.
    pub fn principal(&self) -> &Principal {
        &self.principal
    }

    /// The break-glass justification, if this access is exercising it.
    pub fn break_glass_justification(&self) -> Option<&str> {
        self.break_glass.as_deref()
    }

    fn is_admin(&self) -> bool {
        self.principal.role == Role::Admin
    }

    /// Whether the caller may **author** memory into `scope` — identity-derived *write* isolation
    /// (design §8.2: "no code path from 'a user said so' directly to org-scope memory"). Distinct
    /// from [`can_see`](AccessScope::can_see): break-glass never grants a *write*, and personal
    /// (`User`) scope may be authored **only by its owner** (not by an admin impersonating them).
    /// Membership in a shared scope authorizes *proposing* to it; whether the write lands as
    /// authority additionally requires the approve capability, enforced by the store.
    pub fn can_write(&self, scope: &Scope) -> bool {
        match scope {
            Scope::Org => true,
            Scope::Department(d) => self.is_admin() || self.departments.contains(d),
            Scope::Team(t) => self.is_admin() || self.teams.contains(t),
            Scope::Repo(r) => self.is_admin() || self.repos.contains(r),
            Scope::User(u) => &self.principal.user_id == u,
        }
    }

    /// Whether `scope` is the caller's **own** personal (`User`) scope — i.e. the caller is the
    /// subject of this personal memory. Design §5: "a user's own PII-classed facts about themselves
    /// are visible to themselves." The store uses this to waive the data-class read-clearance ceiling
    /// for a caller reading their *own* personal fact (a low-clearance user can always see the PII
    /// they themselves told the system about themselves) — while every *other* caller (including a
    /// break-glass admin, who has full clearance anyway) remains subject to the ceiling. Never true
    /// for a non-`User` scope, so it cannot widen org/dept/team/repo visibility.
    pub fn is_own_personal(&self, scope: &Scope) -> bool {
        matches!(scope, Scope::User(u) if u == &self.principal.user_id)
    }

    /// Whether the caller may see an item in `scope`. Returns `(visible, used_break_glass)`:
    /// `used_break_glass` is `true` only when an admin saw another user's personal item via
    /// break-glass, so the store can emit the required audit entry.
    pub fn can_see(&self, scope: &Scope) -> (bool, bool) {
        match scope {
            Scope::Org => (true, false),
            Scope::Department(d) => (self.is_admin() || self.departments.contains(d), false),
            Scope::Team(t) => (self.is_admin() || self.teams.contains(t), false),
            Scope::Repo(r) => (self.is_admin() || self.repos.contains(r), false),
            Scope::User(u) => {
                if &self.principal.user_id == u {
                    (true, false)
                } else if self.is_admin() && self.break_glass.is_some() {
                    // Break-glass: an admin may read another user's personal memory ONLY with a
                    // logged justification. Flag it so the store audits the access.
                    (true, true)
                } else {
                    (false, false)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ainxt_types::Principal;

    #[test]
    fn org_visible_to_everyone() {
        let a = AccessScope::from_principal(Principal::user("u1", &[]));
        assert_eq!(a.can_see(&Scope::Org), (true, false));
    }

    #[test]
    fn team_repo_require_membership() {
        let a = AccessScope::from_principal(Principal::user("u1", &[]))
            .with_teams(&["infra"])
            .with_repos(&["payments-core"]);
        assert_eq!(a.can_see(&Scope::Team("infra".into())), (true, false));
        assert_eq!(a.can_see(&Scope::Team("growth".into())), (false, false));
        assert_eq!(
            a.can_see(&Scope::Repo("payments-core".into())),
            (true, false)
        );
        assert_eq!(
            a.can_see(&Scope::Repo("secret-repo".into())),
            (false, false)
        );
    }

    #[test]
    fn department_from_principal_is_reachable() {
        let a = AccessScope::from_principal(Principal::user("u1", &[]).with_department("payments"));
        assert_eq!(
            a.can_see(&Scope::Department("payments".into())),
            (true, false)
        );
        assert_eq!(a.can_see(&Scope::Department("hr".into())), (false, false));
    }

    #[test]
    fn personal_memory_only_owner_or_break_glass_admin() {
        // Owner sees own.
        let owner = AccessScope::from_principal(Principal::user("alice", &[]));
        assert_eq!(owner.can_see(&Scope::User("alice".into())), (true, false));
        // Another plain user cannot see it — not even by asking.
        let other = AccessScope::from_principal(Principal::user("bob", &[]));
        assert_eq!(other.can_see(&Scope::User("alice".into())), (false, false));
        // An admin WITHOUT break-glass cannot see another user's personal memory.
        let admin_noglass = AccessScope::from_principal(Principal::admin("root"));
        assert_eq!(
            admin_noglass.can_see(&Scope::User("alice".into())),
            (false, false)
        );
        // An admin WITH break-glass can — and the access is flagged for audit.
        let admin_glass = AccessScope::from_principal(Principal::admin("root"))
            .with_break_glass("DPO investigation TICKET-99");
        assert_eq!(
            admin_glass.can_see(&Scope::User("alice".into())),
            (true, true)
        );
    }
}
