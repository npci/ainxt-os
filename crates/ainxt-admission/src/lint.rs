// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Manifest-lint (ADR-026) — the schema/consistency checks the control-repo CI runs on every
//! harness PR. This is the code the `manifest-lint` CI job and the `ainxt harness lint` command
//! share. It is deterministic and pure (no I/O): parse happened upstream, this validates semantics.
//!
//! A finding is a hard failure — a PR whose manifest lints RED cannot merge. The checks encode the
//! ADR-026 acceptance bars: `kind`/`id`/`version` present + well-formed, an `owner` (CODEOWNERS
//! entry), every step's capability declared in `requested_capabilities` (a step cannot silently use
//! an undeclared capability), `execute_rbac.permissions` scoped to declared capabilities, a
//! `Department`-visibility harness naming its department, and `depends_on` refs fully pinned.

use crate::{HarnessManifest, Visibility};

/// One lint failure: a stable machine code + a human message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LintFinding {
    pub code: &'static str,
    pub message: String,
}

impl LintFinding {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        LintFinding {
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for LintFinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

/// A `kind` must be exactly `harness` for this definition type.
fn is_slug(s: &str) -> bool {
    !s.is_empty()
        && s.chars().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.' || c == '_'
        })
}

/// A permissive semver check: `MAJOR.MINOR.PATCH` with numeric components (an optional `-pre` suffix
/// on patch is allowed). Enough to reject `latest`, empty, or a single number.
fn is_semver(s: &str) -> bool {
    let core = s.split('-').next().unwrap_or("");
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
}

/// Validate a manifest, returning every finding (empty = passes lint).
pub fn lint_manifest(m: &HarnessManifest) -> Result<(), Vec<LintFinding>> {
    let mut findings = Vec::new();

    if m.kind != "harness" {
        findings.push(LintFinding::new(
            "kind",
            format!("kind must be 'harness', got '{}'", m.kind),
        ));
    }
    if !is_slug(&m.id) {
        findings.push(LintFinding::new(
            "id",
            format!("id '{}' must be a non-empty lowercase slug", m.id),
        ));
    }
    if !is_semver(&m.version) {
        findings.push(LintFinding::new(
            "version",
            format!("version '{}' must be semver MAJOR.MINOR.PATCH", m.version),
        ));
    }
    if m.owner.trim().is_empty() {
        findings.push(LintFinding::new(
            "owner",
            "owner (CODEOWNERS entry) is required",
        ));
    }
    if m.steps.is_empty() {
        findings.push(LintFinding::new("steps", "a harness must declare >=1 step"));
    }

    // Every step's capability must be declared in requested_capabilities.
    for step in &m.steps {
        if !m
            .requested_capabilities
            .iter()
            .any(|c| c == &step.capability)
        {
            findings.push(LintFinding::new(
                "undeclared-capability",
                format!(
                    "step '{}' uses capability '{}' not in requested_capabilities",
                    step.id, step.capability
                ),
            ));
        }
    }

    // execute_rbac.permissions must be scoped to a declared capability (least-privilege hygiene): the
    // part before an optional ':scope' must be a requested capability.
    for perm in &m.execute_rbac.permissions {
        let base = perm.split(':').next().unwrap_or(perm);
        if !m.requested_capabilities.iter().any(|c| c == base) {
            findings.push(LintFinding::new(
                "orphan-permission",
                format!("execute_rbac permission '{perm}' names an undeclared capability '{base}'"),
            ));
        }
    }

    // Department visibility must name a department.
    if m.execute_rbac.visibility == Visibility::Department
        && m.execute_rbac
            .department
            .as_deref()
            .map(str::trim)
            .unwrap_or("")
            .is_empty()
    {
        findings.push(LintFinding::new(
            "missing-department",
            "execute_rbac.visibility=department requires a department",
        ));
    }

    // depends_on refs must be fully pinned.
    for dep in &m.depends_on {
        if dep.repo.trim().is_empty()
            || dep.tag.trim().is_empty()
            || dep.content_hash.trim().is_empty()
        {
            findings.push(LintFinding::new(
                "unpinned-dependency",
                format!("dependency '{}' must pin repo@tag@content_hash", dep.repo),
            ));
        }
    }

    if findings.is_empty() {
        Ok(())
    } else {
        Err(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ExecuteRbac, HarnessStep, PinnedDep, StepKind};

    fn step(id: &str, cap: &str) -> HarnessStep {
        HarnessStep {
            id: id.into(),
            kind: StepKind::Llm,
            capability: cap.into(),
            estimated_tokens: 0,
            input: None,
        }
    }

    fn valid() -> HarnessManifest {
        let mut m = HarnessManifest::new("settlement-investigator", vec![step("s1", "kb.search")])
            .with_capabilities(["kb.search"]);
        m.version = "1.0.0".into();
        m.owner = "settlement-ops".into();
        m
    }

    #[test]
    fn a_valid_manifest_passes() {
        assert!(lint_manifest(&valid()).is_ok());
    }

    #[test]
    fn missing_owner_and_bad_version_fail() {
        let mut m = valid();
        m.owner = "".into();
        m.version = "latest".into();
        let f = lint_manifest(&m).unwrap_err();
        assert!(f.iter().any(|x| x.code == "owner"));
        assert!(f.iter().any(|x| x.code == "version"));
    }

    #[test]
    fn wrong_kind_fails() {
        let mut m = valid();
        m.kind = "skill".into();
        assert!(lint_manifest(&m)
            .unwrap_err()
            .iter()
            .any(|x| x.code == "kind"));
    }

    #[test]
    fn a_step_using_an_undeclared_capability_is_caught() {
        let mut m = valid();
        m.steps.push(step("s2", "tool.delete")); // not in requested_capabilities
        let f = lint_manifest(&m).unwrap_err();
        assert!(f.iter().any(|x| x.code == "undeclared-capability"));
    }

    #[test]
    fn orphan_permission_is_caught() {
        let mut m = valid();
        m.execute_rbac = ExecuteRbac {
            permissions: vec!["connector.postgres.query:read-only".into()],
            ..Default::default()
        };
        assert!(lint_manifest(&m)
            .unwrap_err()
            .iter()
            .any(|x| x.code == "orphan-permission"));
    }

    #[test]
    fn department_visibility_needs_a_department() {
        let mut m = valid();
        m.execute_rbac = ExecuteRbac {
            visibility: Visibility::Department,
            department: None,
            permissions: vec![],
        };
        assert!(lint_manifest(&m)
            .unwrap_err()
            .iter()
            .any(|x| x.code == "missing-department"));
    }

    #[test]
    fn unpinned_dependency_is_caught() {
        let mut m = valid();
        m.depends_on = vec![PinnedDep {
            repo: "acme/kit".into(),
            tag: "v1".into(),
            content_hash: "".into(), // not pinned
        }];
        assert!(lint_manifest(&m)
            .unwrap_err()
            .iter()
            .any(|x| x.code == "unpinned-dependency"));
    }

    #[test]
    fn is_semver_accepts_and_rejects() {
        assert!(is_semver("1.0.0"));
        assert!(is_semver("2.13.4-rc1"));
        assert!(!is_semver("1.0"));
        assert!(!is_semver("v1.0.0"));
        assert!(!is_semver("latest"));
    }
}
