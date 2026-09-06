// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Round-15 closure: the built-in skill CATALOG carries real domain content — RCA, test-gen,
//! architecture review, compliance review, settlement investigation, release notes — not just the
//! two generic (citation-discipline / turn-header) skills the runtime shipped with before.
//!
//! Fails before these six behavioral SOPs existed in `builtin::manifests()` (only two built-ins, and
//! a profile referencing e.g. `"rca-procedure"` got `SkillError::NotFound`); passes after — every one
//! resolves, is behavioral (no code runs), and injects real, non-trivial SOP text into the system
//! prompt.

use ainxt_skill::{builtin, SkillRuntime};

const CATALOG_IDS: &[&str] = &[
    builtin::RCA,
    builtin::TEST_GEN,
    builtin::ARCHITECTURE_REVIEW,
    builtin::COMPLIANCE_REVIEW,
    builtin::SETTLEMENT_INVESTIGATION,
    builtin::RELEASE_NOTES,
];

#[test]
fn r15_all_six_domain_skills_are_registered_and_behavioral() {
    let rt = SkillRuntime::with_builtins();
    for id in CATALOG_IDS {
        let refs = vec![id.to_string()];
        let prepared = rt
            .prepare(&refs, "why did settlement batch 4471 fail?")
            .unwrap_or_else(|e| panic!("built-in skill '{id}' must resolve, got: {e}"));
        assert_eq!(
            prepared.behavioral.len(),
            1,
            "'{id}' must be a BEHAVIORAL skill (SOP text, no code)"
        );
        assert!(
            prepared.execution.is_empty(),
            "'{id}' must not run any execution skill"
        );
        let (got_id, body) = &prepared.behavioral[0];
        assert_eq!(got_id, id);
        // Substantive content, not a placeholder stub.
        assert!(
            body.len() > 120,
            "'{id}' SOP body should be a real procedure, not a stub: {} chars",
            body.len()
        );
    }
}

#[test]
fn r15_rca_procedure_distinguishes_proximate_from_root_cause() {
    let rt = SkillRuntime::with_builtins();
    let prepared = rt.prepare(&[builtin::RCA.to_string()], "x").unwrap();
    let sp = SkillRuntime::system_prompt("You are ops.", &prepared, &[]);
    assert!(sp.to_lowercase().contains("proximate"));
    assert!(sp.to_lowercase().contains("root"));
}

#[test]
fn r15_test_gen_procedure_requires_adversarial_and_boundary_cases() {
    let rt = SkillRuntime::with_builtins();
    let prepared = rt.prepare(&[builtin::TEST_GEN.to_string()], "x").unwrap();
    let sp = SkillRuntime::system_prompt("You are eng.", &prepared, &[]);
    let lower = sp.to_lowercase();
    assert!(lower.contains("adversarial"));
    assert!(lower.contains("boundary"));
    assert!(lower.contains("happy-path-only") || lower.contains("happy path"));
}

#[test]
fn r15_compliance_review_procedure_covers_pci_categories() {
    let rt = SkillRuntime::with_builtins();
    let prepared = rt
        .prepare(&[builtin::COMPLIANCE_REVIEW.to_string()], "x")
        .unwrap();
    let sp = SkillRuntime::system_prompt("You are compliance.", &prepared, &[]);
    let lower = sp.to_lowercase();
    assert!(lower.contains("pan"));
    assert!(lower.contains("redact"));
}

#[test]
fn r15_settlement_investigation_procedure_demands_traceable_arithmetic() {
    let rt = SkillRuntime::with_builtins();
    let prepared = rt
        .prepare(&[builtin::SETTLEMENT_INVESTIGATION.to_string()], "x")
        .unwrap();
    let sp = SkillRuntime::system_prompt("You are settlement ops.", &prepared, &[]);
    let lower = sp.to_lowercase();
    assert!(lower.contains("reconciliation"));
    assert!(lower.contains("traceable") || lower.contains("never asserted"));
}

#[test]
fn r15_a_profile_can_combine_a_domain_skill_with_the_original_built_ins() {
    // The new catalog content is additive: a profile can still combine an original built-in
    // (citation-discipline) with a new domain SOP (release-notes), preserving injection order.
    let rt = SkillRuntime::with_builtins();
    let refs = vec![
        builtin::CITATION_DISCIPLINE.to_string(),
        builtin::RELEASE_NOTES.to_string(),
    ];
    let prepared = rt.prepare(&refs, "draft v2.3 release notes").unwrap();
    assert_eq!(prepared.behavioral.len(), 2);
    let sp = SkillRuntime::system_prompt("You are docs.", &prepared, &[]);
    let cite_at = sp.find("Cite every factual claim").unwrap();
    let release_at = sp.find("release-notes procedure").unwrap();
    assert!(
        cite_at < release_at,
        "injection order must follow ref order"
    );
}
