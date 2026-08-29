// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX os-workforce — two more real, unit-tested pieces of `ainxt-workforce` had zero callers
//! anywhere outside its own crate's tests:
//!
//! 1. The Factory-driven conversational authoring flow (AINXT_OS §4 Steps 0–2:
//!    `JobDescription` → `Factory::describe` → `Factory::auto_assemble`, driven through the real
//!    `RoleStudio` state machine). `WorkforceSurface::open_studio` itself — the one method that hands
//!    back a driveable `RoleStudio` — had no caller at all, not even in `ainxt-runtimed`'s own test
//!    suite, so a creator's plain-language job description had no route to becoming a `RoleSpec`; every
//!    served path only ever consumed an already-fully-formed spec. `WorkforceSurface::draft_role_from_job`
//!    closes that.
//! 2. `ainxt_workforce::oversight::generate_decoy` (§7.2: a decoy attention-check must be minted from
//!    the role's OWN Breaker adversarial corpus, not a hand-invented `AttentionCheck` with an arbitrary
//!    label). `WorkforceSurface::generate_decoy_for_role` closes that.
//!
//! This test drives BOTH end to end through the real composition-root objects: a plain-language job
//! description becomes a governed, Breaker-passed, PRODUCTION role, and a decoy minted from THAT SAME
//! role's real adversarial corpus is proven to trace back to one of its actual generated cases.

use ainxt_governance::AuthoringContext;
use ainxt_runtimed::{assemble_workforce_surface, ShadowCase, WorkforceError};
use ainxt_workforce::author::{Factory, JobDescription};
use ainxt_workforce::breaker::{Breaker, GovernedPublishRequest, ResponseAction};
use ainxt_workforce::studio::Template;

/// GAP-CLOSE os-workforce (gap6-workforce-governance-gate) — see the identical helper's doc in
/// `r13_workforce_surface_reachable.rs`.
fn passing_shadow_cases() -> Vec<ShadowCase> {
    (0..20)
        .map(|i| ShadowCase {
            id: format!("shadow-{i}"),
            input: "A normal in-scope request for support.".into(),
            human_action: ResponseAction::Answered,
        })
        .collect()
}

fn gov_for(id: &str) -> GovernedPublishRequest {
    GovernedPublishRequest::release_signed(
        id,
        "support-leads",
        "release-key",
        AuthoringContext {
            payments_council_approved: true,
            commit_signed: true,
            author_can_approve: true,
            author_ad_level: 3,
        },
    )
}

/// The Factory-driven Steps 0–2 flow, reachable from the composition root, producing a real draft
/// that then clears the REST of the (already-wired) pipeline: the un-forgeable Breaker gate and a
/// governed, git-native publish to PRODUCTION.
#[test]
fn r_draft_role_from_job_reaches_governed_publish() {
    let surface = assemble_workforce_surface();

    let job = JobDescription::new(
        "l1-support-drafted",
        "L1 Support Engineer",
        "Triage L1 tickets from the ticketing queue, answer from the KB, \
         and escalate anything unrecognized to a human.",
        Template::Support,
    );
    // `Factory::default_governance` is itself reachable here for the first time from any reserved
    // crate (previously exercised only by `ainxt-workforce`'s own tests) — the Studio's own documented
    // Step-2 pre-fill, not a hand-rolled `Governance` literal.
    let governance = Factory::default().default_governance("alice", "support-leads");

    let mut draft = surface
        .draft_role_from_job(job, governance)
        .expect("Steps 1-2 (describe + auto_assemble) must succeed from a fresh Studio");

    // Step 1 (Factory::describe / KeywordIntentExtractor) actually parsed the free-form prose into a
    // structured charter — not a stub.
    assert!(
        !draft.charter.responsibilities.is_empty(),
        "charter: {:?}",
        draft.charter
    );
    assert!(
        draft
            .charter
            .escalation_rules
            .iter()
            .any(|r| r.to_lowercase().contains("escalate")),
        "the escalation clause must be detected: {:?}",
        draft.charter.escalation_rules
    );

    // Step 2 (Factory::auto_assemble) proposed the Support golden-path assembly.
    assert_eq!(draft.agents.len(), 1);
    assert!(draft
        .connectors
        .iter()
        .any(|c| c.name == "connector.ticketing"));
    assert!(draft.knowledge.iter().any(|k| k.namespace == "kb:support"));
    // Step 6 (Factory::auto_generate_kpis) pre-seeded the quality-eval set already, before Step 6 is
    // even separately "confirmed" by a caller.
    assert!(draft.kpis.iter().any(|k| k.name == "resolution-rate"));

    // The creator reviews the draft (Studio Step 5, retrieval-quality check) before it is gate-ready —
    // `draft_role_from_job` deliberately stops at the reviewable draft, exactly like the real Studio's
    // own Step 2, so this is the caller's own edit, not a bypass.
    for k in &mut draft.knowledge {
        k.retrieval_quality = Some(0.9);
    }

    // The already-wired second half of the pipeline: gate, then govern-publish. A citizen-authored
    // (Factory-drafted) role now reaches the exact same un-forgeable Breaker + governed-publish path
    // as a hand-built `RoleSpec`.
    let published = surface
        .publish_role(
            draft,
            &[],
            &passing_shadow_cases(),
            &gov_for("l1-support-drafted"),
        )
        .expect("the Factory-drafted role must clear the real Breaker gate and governed publish");
    assert_eq!(published.id(), "l1-support-drafted");
    assert_eq!(
        published.state(),
        ainxt_governance::GovernanceState::Production
    );
}

/// `WorkforceSurface::open_studio` (the method `draft_role_from_job` drives internally) is directly
/// reachable and produces a state machine at the documented Step-0 stage — proven directly, not just
/// as a side effect of the method above.
#[test]
fn r_open_studio_reachable_from_the_composition_root() {
    let surface = assemble_workforce_surface();
    let studio = surface.open_studio(Template::Developer);
    assert_eq!(studio.stage(), ainxt_workforce::studio::StudioStage::Start);
    assert_eq!(studio.template(), Template::Developer);
}

/// `generate_decoy_for_role` mints a §7.2 attention-check decoy from a PUBLISHED role's own real
/// Breaker adversarial corpus (not a hand-invented `AttentionCheck`), and refuses an id this surface
/// never actually published.
#[test]
fn r_generate_decoy_for_role_sourced_from_the_real_adversarial_corpus() {
    let surface = assemble_workforce_surface();

    let job = JobDescription::new(
        "l1-support-decoy",
        "L1 Support Engineer",
        "Triage L1 tickets from the ticketing queue, answer from the KB, \
         and escalate anything unrecognized to a human.",
        Template::Support,
    );
    let governance = Factory::default().default_governance("alice", "support-leads");
    let mut draft = surface.draft_role_from_job(job, governance).expect("draft");
    for k in &mut draft.knowledge {
        k.retrieval_quality = Some(0.9);
    }
    let published = surface
        .publish_role(
            draft,
            &[],
            &passing_shadow_cases(),
            &gov_for("l1-support-decoy"),
        )
        .expect("publish");

    let decoy = surface
        .generate_decoy_for_role("l1-support-decoy")
        .expect("a published role id must resolve")
        .expect(
            "a role with connectors ingesting external data has an injection probe to decoy with",
        );

    // The decoy is provably real Breaker material: its id is one of the role's OWN generated
    // adversarial cases, not an arbitrary label a caller invented.
    let corpus = Breaker::adversarial_corpus(published.role());
    assert!(
        corpus.iter().any(|c| c.id == decoy.check.decoy_id),
        "decoy id {} must trace back to the role's real adversarial corpus: {:?}",
        decoy.check.decoy_id,
        corpus.iter().map(|c| &c.id).collect::<Vec<_>>()
    );
    assert_eq!(decoy.check.role, "l1-support-decoy");
    assert_eq!(decoy.case.id, decoy.check.decoy_id);

    // A role id this surface never published is refused, not silently fabricated.
    match surface.generate_decoy_for_role("never-published") {
        Err(WorkforceError::UnknownRole(id)) => assert_eq!(id, "never-published"),
        other => panic!("expected UnknownRole for an id never published, got {other:?}"),
    }
}
