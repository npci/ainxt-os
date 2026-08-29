// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! The 7 canonical Org-Knowledge Item (OKI) types and their schema-validated typed payloads
//! (design §2). Every unit of organizational memory is one strongly-typed record — never a blob.
//! The type determines the structured payload; the payload is validated on write and an invalid
//! payload is **rejected**, never persisted "as text" as a fallback.
//!
//! Validation here is the typed, versioned schema registry the design calls for, done in Rust
//! (no external JSON-schema dep): each variant's [`OrgPayload::validate`] enforces its required
//! fields. [`OKI_SCHEMA_VERSION`] is the registry version — a schema bump is itself a governed
//! change (bump this constant + migrate).

use ainxt_types::DataClass;
use serde::{Deserialize, Serialize};

/// The typed-payload schema registry version. A schema change bumps this (governed).
pub const OKI_SCHEMA_VERSION: u32 = 1;

/// One governed schema-version bump: which type, from/to version, who authorized it, and why.
/// Retained as an append-only history so a schema change is itself auditable (design §2: "a schema
/// bump is itself governed").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaBump {
    /// The OKI type whose payload schema changed.
    pub oki_type: OrgKnowledgeType,
    /// The version before the bump.
    pub from: u32,
    /// The version after the bump.
    pub to: u32,
    /// The authorizing principal's user id (held [`CAP_APPROVE`](crate::CAP_APPROVE)).
    pub approved_by: String,
    /// A human note describing the migration.
    pub note: String,
}

/// A **versioned, per-type** JSON-schema registry (design §2 `type_payload`: "validated against a
/// per-type JSON-schema registry (versioned; a schema bump is itself governed)"). Each of the 7
/// [`OrgKnowledgeType`]s carries its own independent schema version (all start at
/// [`OKI_SCHEMA_VERSION`]); the *shape* validation itself lives in [`OrgPayload::validate`]. A schema
/// bump is a **governed** operation: it requires an approver holding
/// [`CAP_APPROVE`](crate::CAP_APPROVE), it only ever moves a version forward, and every bump is
/// recorded in an append-only [`history`](SchemaRegistry::history) — so "which schema version was in
/// force, changed by whom, when" is answerable (never a silent constant edit).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaRegistry {
    /// Per-type current schema version.
    versions: std::collections::BTreeMap<OrgKnowledgeType, u32>,
    /// Append-only bump history (oldest first).
    history: Vec<SchemaBump>,
}

impl Default for SchemaRegistry {
    fn default() -> Self {
        SchemaRegistry::new()
    }
}

impl SchemaRegistry {
    /// A fresh registry with every type at [`OKI_SCHEMA_VERSION`].
    pub fn new() -> Self {
        let mut versions = std::collections::BTreeMap::new();
        for t in [
            OrgKnowledgeType::CodingConvention,
            OrgKnowledgeType::ArchitectureDecision,
            OrgKnowledgeType::ApprovedLibrary,
            OrgKnowledgeType::SecurityRule,
            OrgKnowledgeType::IncidentPostmortem,
            OrgKnowledgeType::CommonFix,
            OrgKnowledgeType::TeamPattern,
        ] {
            versions.insert(t, OKI_SCHEMA_VERSION);
        }
        SchemaRegistry {
            versions,
            history: Vec::new(),
        }
    }

    /// The current schema version in force for `oki_type`.
    pub fn version(&self, oki_type: OrgKnowledgeType) -> u32 {
        self.versions
            .get(&oki_type)
            .copied()
            .unwrap_or(OKI_SCHEMA_VERSION)
    }

    /// The append-only bump history (oldest first).
    pub fn history(&self) -> &[SchemaBump] {
        &self.history
    }

    /// Enforce the registry on a write (design §2 `type_payload`: "validated against a per-type
    /// JSON-schema registry (versioned)"). Runs the type's shape [`validate`](OrgPayload::validate)
    /// and, on success, returns the **in-force schema version** for that type so the store can stamp
    /// it on the persisted item. An invalid payload is rejected (never persisted "as text"). This is
    /// what makes the registry *load-bearing on the write path* rather than a standalone object: the
    /// store validates every OKI write through here and records which version was in force.
    pub fn validate_write(&self, payload: &OrgPayload) -> Result<u32, Vec<SchemaError>> {
        payload.validate()?;
        Ok(self.version(payload.oki_type()))
    }

    /// Governed schema bump: move `oki_type` from its current version to `to`. Requires an approver
    /// holding [`CAP_APPROVE`](crate::CAP_APPROVE) (a schema change is a governed act, not a code
    /// constant edit), and `to` must be strictly greater than the current version (versions only move
    /// forward). Records the change in [`history`](SchemaRegistry::history). Returns the new version.
    pub fn bump(
        &mut self,
        oki_type: OrgKnowledgeType,
        to: u32,
        approver: &crate::Principal,
        note: &str,
    ) -> Result<u32, crate::MemoryError> {
        if !approver.has_cap(crate::CAP_APPROVE) {
            return Err(crate::MemoryError::NotAuthorized(format!(
                "principal '{}' lacks '{}' — a schema bump is human-gated",
                approver.user_id,
                crate::CAP_APPROVE
            )));
        }
        let from = self.version(oki_type);
        if to <= from {
            return Err(crate::MemoryError::InvalidTransition(format!(
                "schema version for {} must move forward: {from} -> {to}",
                oki_type.as_str()
            )));
        }
        self.versions.insert(oki_type, to);
        self.history.push(SchemaBump {
            oki_type,
            from,
            to,
            approved_by: approver.user_id.clone(),
            note: note.to_string(),
        });
        Ok(to)
    }
}

/// The 7 canonical organizational-knowledge types (design §2 table).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OrgKnowledgeType {
    /// A coding convention (rule + language + do/don't + enforcement level).
    CodingConvention,
    /// An architecture decision (mirrors an ADR).
    ArchitectureDecision,
    /// An approved library (name + version range + reason + disallowed alternatives).
    ApprovedLibrary,
    /// A security rule (mechanically checkable before a tool call).
    SecurityRule,
    /// An incident postmortem (timeline + root cause + error signatures + remediation).
    IncidentPostmortem,
    /// A common fix (error pattern → fix template, with verified/false-positive counts).
    CommonFix,
    /// A team pattern (when-to-use / when-not-to-use).
    TeamPattern,
}

impl OrgKnowledgeType {
    /// Human-readable slug.
    pub fn as_str(&self) -> &'static str {
        match self {
            OrgKnowledgeType::CodingConvention => "coding-convention",
            OrgKnowledgeType::ArchitectureDecision => "architecture-decision",
            OrgKnowledgeType::ApprovedLibrary => "approved-library",
            OrgKnowledgeType::SecurityRule => "security-rule",
            OrgKnowledgeType::IncidentPostmortem => "incident-postmortem",
            OrgKnowledgeType::CommonFix => "common-fix",
            OrgKnowledgeType::TeamPattern => "team-pattern",
        }
    }
    /// Whether this type is safety/compliance-classed — it wins injection precedence over
    /// conventions and personal preferences (design §6).
    pub fn is_safety_class(&self) -> bool {
        matches!(
            self,
            OrgKnowledgeType::SecurityRule | OrgKnowledgeType::ArchitectureDecision
        )
    }

    /// Whether a bulk verbatim dump of this type is recon-sensitive (design §8.8 / gap AM). The
    /// design names the `SecurityRule`/`ApprovedLibrary` set explicitly: enumerating every security
    /// rule or approved dependency is reconnaissance for a later attack, so an unscoped sweep of
    /// these is treated as an extraction attempt by the store's extraction guard.
    pub fn is_extraction_sensitive(&self) -> bool {
        matches!(
            self,
            OrgKnowledgeType::SecurityRule | OrgKnowledgeType::ApprovedLibrary
        )
    }
}

/// Enforcement level of a coding convention / security rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Enforcement {
    /// Advisory guidance.
    Advisory,
    /// Blocking — a violation stops a tool call / commit.
    Blocking,
}

/// Severity of a security rule / incident.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// A schema-validation failure (which field, why). Surfaced as
/// [`MemoryError::SchemaViolation`](crate::MemoryError::SchemaViolation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaError {
    /// The offending field.
    pub field: String,
    /// Why it is invalid.
    pub reason: String,
}

impl SchemaError {
    fn required(field: &str) -> Self {
        SchemaError {
            field: field.to_string(),
            reason: "required, must be non-empty".to_string(),
        }
    }
}

impl std::fmt::Display for SchemaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "field '{}': {}", self.field, self.reason)
    }
}

/// The typed, schema-validated payload for an OKI. Each variant maps to one
/// [`OrgKnowledgeType`]; the substance lives here (not in free text).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "type")]
pub enum OrgPayload {
    /// A coding convention.
    CodingConvention {
        rule: String,
        language: String,
        example_do: String,
        example_dont: String,
        enforcement: Enforcement,
    },
    /// An architecture decision (ADR shape).
    ArchitectureDecision {
        component: String,
        context: String,
        decision: String,
        consequences: String,
        #[serde(default)]
        alternatives: Vec<String>,
        #[serde(default)]
        adr_ref: Option<String>,
    },
    /// An approved library.
    ApprovedLibrary {
        name: String,
        version_range: String,
        language: String,
        reason: String,
        #[serde(default)]
        disallowed_alternatives: Vec<String>,
        #[serde(default)]
        security_review_ref: Option<String>,
    },
    /// A security rule (mechanically checkable).
    SecurityRule {
        rule: String,
        applicable_action: String,
        applicable_data_class: DataClass,
        severity: Severity,
        enforcement: Enforcement,
        #[serde(default)]
        exception_process: Option<String>,
    },
    /// An incident postmortem.
    IncidentPostmortem {
        incident_id: String,
        timeline: String,
        root_cause: String,
        blast_radius: String,
        #[serde(default)]
        error_signatures: Vec<String>,
        remediation: String,
        owner: String,
    },
    /// A common fix.
    CommonFix {
        error_pattern: String,
        fix_template: String,
        #[serde(default)]
        verified_count: u32,
        #[serde(default)]
        false_positive_count: u32,
    },
    /// A team pattern.
    TeamPattern {
        team: String,
        description: String,
        when_to_use: String,
        when_not_to_use: String,
    },
}

fn require(field: &str, value: &str, errs: &mut Vec<SchemaError>) {
    if value.trim().is_empty() {
        errs.push(SchemaError::required(field));
    }
}

impl OrgPayload {
    /// The [`OrgKnowledgeType`] this payload represents.
    pub fn oki_type(&self) -> OrgKnowledgeType {
        match self {
            OrgPayload::CodingConvention { .. } => OrgKnowledgeType::CodingConvention,
            OrgPayload::ArchitectureDecision { .. } => OrgKnowledgeType::ArchitectureDecision,
            OrgPayload::ApprovedLibrary { .. } => OrgKnowledgeType::ApprovedLibrary,
            OrgPayload::SecurityRule { .. } => OrgKnowledgeType::SecurityRule,
            OrgPayload::IncidentPostmortem { .. } => OrgKnowledgeType::IncidentPostmortem,
            OrgPayload::CommonFix { .. } => OrgKnowledgeType::CommonFix,
            OrgPayload::TeamPattern { .. } => OrgKnowledgeType::TeamPattern,
        }
    }

    /// Validate the payload against its type schema. Returns every failing field (not just the
    /// first) so a caller can surface a complete error. An invalid payload is never persisted.
    pub fn validate(&self) -> Result<(), Vec<SchemaError>> {
        let mut errs = Vec::new();
        match self {
            OrgPayload::CodingConvention {
                rule,
                language,
                example_do,
                example_dont,
                ..
            } => {
                require("rule", rule, &mut errs);
                require("language", language, &mut errs);
                require("example_do", example_do, &mut errs);
                require("example_dont", example_dont, &mut errs);
            }
            OrgPayload::ArchitectureDecision {
                component,
                context,
                decision,
                consequences,
                ..
            } => {
                require("component", component, &mut errs);
                require("context", context, &mut errs);
                require("decision", decision, &mut errs);
                require("consequences", consequences, &mut errs);
            }
            OrgPayload::ApprovedLibrary {
                name,
                version_range,
                language,
                reason,
                ..
            } => {
                require("name", name, &mut errs);
                require("version_range", version_range, &mut errs);
                require("language", language, &mut errs);
                require("reason", reason, &mut errs);
            }
            OrgPayload::SecurityRule {
                rule,
                applicable_action,
                ..
            } => {
                require("rule", rule, &mut errs);
                require("applicable_action", applicable_action, &mut errs);
            }
            OrgPayload::IncidentPostmortem {
                incident_id,
                timeline,
                root_cause,
                blast_radius,
                remediation,
                owner,
                ..
            } => {
                require("incident_id", incident_id, &mut errs);
                require("timeline", timeline, &mut errs);
                require("root_cause", root_cause, &mut errs);
                require("blast_radius", blast_radius, &mut errs);
                require("remediation", remediation, &mut errs);
                require("owner", owner, &mut errs);
            }
            OrgPayload::CommonFix {
                error_pattern,
                fix_template,
                ..
            } => {
                require("error_pattern", error_pattern, &mut errs);
                require("fix_template", fix_template, &mut errs);
            }
            OrgPayload::TeamPattern {
                team,
                description,
                when_to_use,
                when_not_to_use,
            } => {
                require("team", team, &mut errs);
                require("description", description, &mut errs);
                require("when_to_use", when_to_use, &mut errs);
                require("when_not_to_use", when_not_to_use, &mut errs);
            }
        }
        if errs.is_empty() {
            Ok(())
        } else {
            Err(errs)
        }
    }

    /// The conflict-subject discriminator (design §6): two OKIs of the same type + scope + subject
    /// that disagree cannot both be authoritative. Chosen per type to be the natural "same thing"
    /// axis (e.g. two `ApprovedLibrary` records for the same language, two `SecurityRule`s for the
    /// same action).
    pub fn subject_key(&self) -> String {
        let norm = |s: &str| s.trim().to_lowercase();
        match self {
            OrgPayload::CodingConvention { language, .. } => {
                format!("coding-convention:{}", norm(language))
            }
            OrgPayload::ArchitectureDecision { component, .. } => {
                format!("architecture-decision:{}", norm(component))
            }
            OrgPayload::ApprovedLibrary { language, .. } => {
                format!("approved-library:{}", norm(language))
            }
            OrgPayload::SecurityRule {
                applicable_action, ..
            } => format!("security-rule:{}", norm(applicable_action)),
            OrgPayload::IncidentPostmortem { incident_id, .. } => {
                format!("incident:{}", norm(incident_id))
            }
            OrgPayload::CommonFix { error_pattern, .. } => {
                format!("common-fix:{}", norm(error_pattern))
            }
            OrgPayload::TeamPattern { team, .. } => format!("team-pattern:{}", norm(team)),
        }
    }

    /// Re-run the compliance redactor over **every free-text field of the typed payload** — the
    /// substance of an OKI lives here, not in the item's free-text `body` (design §2), so a
    /// compliance-on-write gate that only scrubbed `title`/`body`/`tags` would let a PAN/PII/secret
    /// inside e.g. an [`IncidentPostmortem::timeline`](OrgPayload::IncidentPostmortem) or a
    /// [`CommonFix::fix_template`](OrgPayload::CommonFix) persist unredacted (design §8.4 — the gate
    /// scans *every* memory write before persistence). Structured non-text fields (severity,
    /// enforcement, data-class, counts) are left untouched. Called by the store at write time and by
    /// its retroactive re-redaction pass.
    pub fn redact_in_place(&mut self, redact: &dyn crate::Redactor) {
        let scrub = |s: &mut String| {
            *s = redact.redact(s);
        };
        let scrub_vec = |v: &mut Vec<String>| {
            for s in v.iter_mut() {
                *s = redact.redact(s);
            }
        };
        match self {
            OrgPayload::CodingConvention {
                rule,
                language,
                example_do,
                example_dont,
                ..
            } => {
                scrub(rule);
                scrub(language);
                scrub(example_do);
                scrub(example_dont);
            }
            OrgPayload::ArchitectureDecision {
                component,
                context,
                decision,
                consequences,
                alternatives,
                adr_ref,
            } => {
                scrub(component);
                scrub(context);
                scrub(decision);
                scrub(consequences);
                scrub_vec(alternatives);
                if let Some(r) = adr_ref {
                    scrub(r);
                }
            }
            OrgPayload::ApprovedLibrary {
                name,
                version_range,
                language,
                reason,
                disallowed_alternatives,
                security_review_ref,
            } => {
                scrub(name);
                scrub(version_range);
                scrub(language);
                scrub(reason);
                scrub_vec(disallowed_alternatives);
                if let Some(r) = security_review_ref {
                    scrub(r);
                }
            }
            OrgPayload::SecurityRule {
                rule,
                applicable_action,
                exception_process,
                ..
            } => {
                scrub(rule);
                scrub(applicable_action);
                if let Some(e) = exception_process {
                    scrub(e);
                }
            }
            OrgPayload::IncidentPostmortem {
                incident_id,
                timeline,
                root_cause,
                blast_radius,
                error_signatures,
                remediation,
                owner,
            } => {
                scrub(incident_id);
                scrub(timeline);
                scrub(root_cause);
                scrub(blast_radius);
                scrub_vec(error_signatures);
                scrub(remediation);
                scrub(owner);
            }
            OrgPayload::CommonFix {
                error_pattern,
                fix_template,
                ..
            } => {
                scrub(error_pattern);
                scrub(fix_template);
            }
            OrgPayload::TeamPattern {
                team,
                description,
                when_to_use,
                when_not_to_use,
            } => {
                scrub(team);
                scrub(description);
                scrub(when_to_use);
                scrub(when_not_to_use);
            }
        }
    }

    /// A short human summary used to fill the item body / for keyword recall.
    pub fn summary_text(&self) -> String {
        match self {
            OrgPayload::CodingConvention { rule, language, .. } => {
                format!("[{language}] convention: {rule}")
            }
            OrgPayload::ArchitectureDecision {
                component,
                decision,
                ..
            } => {
                format!("ADR for {component}: {decision}")
            }
            OrgPayload::ApprovedLibrary {
                name,
                language,
                reason,
                ..
            } => {
                format!("[{language}] approved library {name}: {reason}")
            }
            OrgPayload::SecurityRule {
                rule,
                applicable_action,
                ..
            } => {
                format!("security rule for {applicable_action}: {rule}")
            }
            OrgPayload::IncidentPostmortem { root_cause, .. } => {
                format!("postmortem root cause: {root_cause}")
            }
            OrgPayload::CommonFix {
                error_pattern,
                fix_template,
                ..
            } => {
                format!("fix for '{error_pattern}': {fix_template}")
            }
            OrgPayload::TeamPattern {
                team, description, ..
            } => {
                format!("[{team}] pattern: {description}")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_payload_passes_and_reports_type() {
        let p = OrgPayload::ApprovedLibrary {
            name: "reqwest".into(),
            version_range: ">=0.12".into(),
            language: "rust".into(),
            reason: "audited async http client".into(),
            disallowed_alternatives: vec!["curl-shellout".into()],
            security_review_ref: Some("SEC-42".into()),
        };
        assert!(p.validate().is_ok());
        assert_eq!(p.oki_type(), OrgKnowledgeType::ApprovedLibrary);
        assert_eq!(p.subject_key(), "approved-library:rust");
    }

    #[test]
    fn invalid_payload_reports_every_missing_field() {
        let p = OrgPayload::CodingConvention {
            rule: "  ".into(),
            language: "".into(),
            example_do: "x".into(),
            example_dont: "".into(),
            enforcement: Enforcement::Advisory,
        };
        let errs = p.validate().unwrap_err();
        let fields: Vec<&str> = errs.iter().map(|e| e.field.as_str()).collect();
        assert!(fields.contains(&"rule"), "blank rule must fail: {fields:?}");
        assert!(fields.contains(&"language"));
        assert!(fields.contains(&"example_dont"));
        assert!(
            !fields.contains(&"example_do"),
            "non-empty field must not fail"
        );
    }

    #[test]
    fn subject_keys_collide_for_same_axis_only() {
        let a = OrgPayload::ApprovedLibrary {
            name: "reqwest".into(),
            version_range: "1".into(),
            language: "rust".into(),
            reason: "r".into(),
            disallowed_alternatives: vec![],
            security_review_ref: None,
        };
        let b = OrgPayload::ApprovedLibrary {
            name: "ureq".into(),
            version_range: "1".into(),
            language: "rust".into(),
            reason: "r".into(),
            disallowed_alternatives: vec![],
            security_review_ref: None,
        };
        let c = OrgPayload::ApprovedLibrary {
            name: "aiohttp".into(),
            version_range: "1".into(),
            language: "python".into(),
            reason: "r".into(),
            disallowed_alternatives: vec![],
            security_review_ref: None,
        };
        assert_eq!(
            a.subject_key(),
            b.subject_key(),
            "same language → same subject"
        );
        assert_ne!(
            a.subject_key(),
            c.subject_key(),
            "different language → different subject"
        );
    }
}
