// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! The **Digital Team** rung — a governed *department* of collaborating Roles (WORKFORCE_AND_OS §1).
//!
//! A team is the org-level composition: multiple [`PublishedRole`]s (each already Breaker-passed and
//! at Production) plus the declared [`Collaboration`] edges between them. Requiring *published* roles
//! is a governance-by-construction invariant — a department cannot be assembled out of ungoverned,
//! un-tested workers. [`DigitalTeam::assemble`] additionally rejects dangling collaboration edges
//! (an edge to/from a role not on the team) and self-collaboration, so the org chart is always
//! internally consistent.

use std::collections::BTreeSet;

use crate::role::PublishedRole;

/// A directed collaboration edge between two roles on the team (who hands work to whom, and why).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Collaboration {
    pub from_role: String,
    pub to_role: String,
    pub purpose: String,
}

impl Collaboration {
    pub fn new(from_role: &str, to_role: &str, purpose: &str) -> Self {
        Collaboration {
            from_role: from_role.to_string(),
            to_role: to_role.to_string(),
            purpose: purpose.to_string(),
        }
    }
}

/// A governed digital department.
#[derive(Debug, Clone)]
pub struct DigitalTeam {
    id: String,
    department: String,
    owner: String,
    roles: Vec<PublishedRole>,
    collaborations: Vec<Collaboration>,
}

/// Why a team failed to assemble.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TeamError {
    EmptyId,
    EmptyDepartment,
    EmptyOwner,
    NoRoles,
    DuplicateRole(String),
    /// A collaboration edge references a role that is not a member of the team.
    DanglingEdge {
        from: String,
        to: String,
        missing: String,
    },
    /// A role cannot collaborate with itself.
    SelfCollaboration(String),
}

impl std::fmt::Display for TeamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TeamError::EmptyId => write!(f, "team id is empty"),
            TeamError::EmptyDepartment => write!(f, "team department is empty"),
            TeamError::EmptyOwner => write!(f, "team owner is empty"),
            TeamError::NoRoles => write!(f, "team has no roles"),
            TeamError::DuplicateRole(id) => write!(f, "duplicate role '{id}' on team"),
            TeamError::DanglingEdge { from, to, missing } => {
                write!(
                    f,
                    "collaboration {from}->{to} references non-member role '{missing}'"
                )
            }
            TeamError::SelfCollaboration(id) => write!(f, "role '{id}' collaborates with itself"),
        }
    }
}
impl std::error::Error for TeamError {}

impl DigitalTeam {
    /// Assemble a department from published roles + collaboration edges, validating consistency.
    pub fn assemble(
        id: &str,
        department: &str,
        owner: &str,
        roles: Vec<PublishedRole>,
        collaborations: Vec<Collaboration>,
    ) -> Result<Self, TeamError> {
        if id.trim().is_empty() {
            return Err(TeamError::EmptyId);
        }
        if department.trim().is_empty() {
            return Err(TeamError::EmptyDepartment);
        }
        if owner.trim().is_empty() {
            return Err(TeamError::EmptyOwner);
        }
        if roles.is_empty() {
            return Err(TeamError::NoRoles);
        }

        let mut ids: BTreeSet<String> = BTreeSet::new();
        for r in &roles {
            if !ids.insert(r.id().to_string()) {
                return Err(TeamError::DuplicateRole(r.id().to_string()));
            }
        }

        for c in &collaborations {
            if c.from_role == c.to_role {
                return Err(TeamError::SelfCollaboration(c.from_role.clone()));
            }
            if !ids.contains(&c.from_role) {
                return Err(TeamError::DanglingEdge {
                    from: c.from_role.clone(),
                    to: c.to_role.clone(),
                    missing: c.from_role.clone(),
                });
            }
            if !ids.contains(&c.to_role) {
                return Err(TeamError::DanglingEdge {
                    from: c.from_role.clone(),
                    to: c.to_role.clone(),
                    missing: c.to_role.clone(),
                });
            }
        }

        Ok(DigitalTeam {
            id: id.to_string(),
            department: department.to_string(),
            owner: owner.to_string(),
            roles,
            collaborations,
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn department(&self) -> &str {
        &self.department
    }
    pub fn owner(&self) -> &str {
        &self.owner
    }
    pub fn roles(&self) -> &[PublishedRole] {
        &self.roles
    }
    pub fn collaborations(&self) -> &[Collaboration] {
        &self.collaborations
    }
    pub fn role_count(&self) -> usize {
        self.roles.len()
    }
}
