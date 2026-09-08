// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! ainxt-types — core domain types shared across the AiNxt runtime. Pure, no I/O.

use serde::{Deserialize, Serialize};

/// Data sensitivity class — drives model routing (ADR-012). Higher = more sensitive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DataClass {
    Public,
    Internal,
    Confidential,
    RegulatedPayment,
    Pii,
}

impl DataClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            DataClass::Public => "public",
            DataClass::Internal => "internal",
            DataClass::Confidential => "confidential",
            DataClass::RegulatedPayment => "regulated-payment",
            DataClass::Pii => "pii",
        }
    }
    /// Sensitivity level (0 = least). Regulated/PII are the "must stay in-house" tiers.
    pub fn sensitivity(&self) -> u8 {
        *self as u8
    }
    /// Regulated/PII must never leave in-house infrastructure (ADR-012).
    pub fn is_regulated(&self) -> bool {
        matches!(self, DataClass::RegulatedPayment | DataClass::Pii)
    }
}

/// Model complexity tier (ADR-006 routing input).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    Simple,
    Medium,
    Complex,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    User,
    Admin,
}

/// The authenticated caller. RBAC is capability-based; `role: Admin` implies all caps.
/// `clearance` is the max data class this principal may READ — it filters retrieval (ADR-012).
/// `department` is the AD org unit (from the JWT); it drives org/dept data scoping and
/// connector allow-deny policy (P2). `None` = unknown/unscoped.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Principal {
    pub user_id: String,
    pub role: Role,
    pub caps: Vec<String>,
    pub clearance: DataClass,
    /// AD department / org unit — additive, defaults to `None` for principals that predate it.
    #[serde(default)]
    pub department: Option<String>,
    /// AD **seniority** level from the org tree (0 = most senior exec … 6 = junior), as carried in
    /// the JWT `ad_level` claim. Drives node/edge RBAC on the Context-Fabric grounding path (a node
    /// with a `max_ad_level` ceiling is visible only when `ad_level <= max_ad_level`). Additive +
    /// serde-default (`None` = unknown/unscoped) so principals that predate it load unchanged; when
    /// `None`, an `ad_level`-gated node is (correctly) denied — fail-closed, never allowed by omission.
    #[serde(default)]
    pub ad_level: Option<u8>,
    /// AD group / role memberships from the JWT (e.g. `settlement-eng`, `oncall`). Drives the
    /// allow/deny-group axis of node/edge RBAC on grounding. Additive + serde-default (empty) so
    /// older principals load as group-less; a node requiring an allow-group is then denied.
    #[serde(default)]
    pub groups: Vec<String>,
    /// OAuth/connector scopes the user's own credential actually covers — GitLab token scopes,
    /// Graph consent, etc. This is OBO **layer 2** (ADR-003 §1.6): "a harness cannot grant what
    /// the user's own credential doesn't cover." Additive + serde-default (empty) so principals
    /// that predate it load unchanged; a connector-scope-gated tool is then (correctly) denied —
    /// fail-closed by omission, never allowed because the field was missing.
    #[serde(default)]
    pub connector_scopes: Vec<String>,
}

impl Principal {
    pub fn user(user_id: &str, caps: &[&str]) -> Self {
        Principal {
            user_id: user_id.to_string(),
            role: Role::User,
            caps: caps.iter().map(|s| s.to_string()).collect(),
            clearance: DataClass::Internal,
            department: None,
            ad_level: None,
            groups: Vec::new(),
            connector_scopes: Vec::new(),
        }
    }
    pub fn admin(user_id: &str) -> Self {
        Principal {
            user_id: user_id.to_string(),
            role: Role::Admin,
            caps: Vec::new(),
            clearance: DataClass::Pii,
            department: None,
            ad_level: None,
            groups: Vec::new(),
            connector_scopes: Vec::new(),
        }
    }
    /// Set the read clearance (max data class this principal may see).
    pub fn with_clearance(mut self, clearance: DataClass) -> Self {
        self.clearance = clearance;
        self
    }
    /// Set the AD department / org unit (drives org/dept connector policy in P2).
    pub fn with_department(mut self, department: &str) -> Self {
        self.department = Some(department.to_string());
        self
    }
    /// Set the AD **seniority** level (JWT `ad_level` claim; 0 = most senior … 6 = junior). Drives
    /// the seniority axis of node/edge RBAC on the Context-Fabric grounding path.
    pub fn with_ad_level(mut self, ad_level: u8) -> Self {
        self.ad_level = Some(ad_level);
        self
    }
    /// Set the AD group / role memberships (JWT groups claim). Drives the allow/deny-group axis of
    /// node/edge RBAC on grounding.
    pub fn with_groups(mut self, groups: &[&str]) -> Self {
        self.groups = groups.iter().map(|g| g.to_string()).collect();
        self
    }
    /// Set the OAuth/connector scopes the user's own credential actually covers (layer 2 of OBO
    /// three-layer authz).
    pub fn with_connector_scopes(mut self, scopes: &[&str]) -> Self {
        self.connector_scopes = scopes.iter().map(|s| s.to_string()).collect();
        self
    }
    pub fn has_cap(&self, cap: &str) -> bool {
        self.role == Role::Admin || self.caps.iter().any(|c| c == cap)
    }
}

pub type SessionId = String;
pub type TurnId = String;
