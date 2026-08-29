// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! P3 #4 — the four product surfaces expressed as DECLARATIVE profiles over the one runtime.
//! Each canonical profile is loaded, validated, and bound with a representative principal; the test
//! asserts the surface resolves to the intended policy (autonomy, retrieval scope, capabilities,
//! model policy, data-class ceiling). This is the concrete proof of "Chat/Buddy/Code/SDLC are just
//! profiles over the spine" — no per-surface code, only configuration.

use ainxt_profile::{Autonomy, RetrievalScope, SurfaceProfile};
use ainxt_prompt::{NumericPolicy, ReasoningDepth};
use ainxt_skill::{NoExecutor, SkillRegistry, SkillRuntime};
use ainxt_surface::{BindingError, SurfaceBinding};
use ainxt_types::{DataClass, Principal, Tier};

const CHAT: &str = include_str!("../profiles/chat.toml");
const CODE: &str = include_str!("../profiles/code.toml");
const SDLC: &str = include_str!("../profiles/sdlc.toml");
const BUDDY: &str = include_str!("../profiles/buddy.toml");

fn skills() -> SkillRuntime {
    SkillRuntime::new(SkillRegistry::new(), Box::new(NoExecutor))
}

/// A user with the baseline chat capability + the full code/connector tool-belt. All four canonical
/// surfaces are department-scoped, so a real principal carries a department.
fn power_user() -> Principal {
    Principal::user(
        "u",
        &[
            "chat.send",
            "tool.grep",
            "tool.read",
            "tool.edit",
            "tool.bash",
            "connector.gitlab",
            "connector.jira",
            "connector.graph",
        ],
    )
    .with_department("payments")
}

#[test]
fn all_canonical_profiles_are_valid() {
    for (name, src) in [
        ("chat", CHAT),
        ("code", CODE),
        ("sdlc", SDLC),
        ("buddy", BUDDY),
    ] {
        let p = SurfaceProfile::from_toml(src)
            .unwrap_or_else(|e| panic!("{name} profile invalid: {e}"));
        assert_eq!(p.id, name);
    }
}

#[test]
fn chat_is_read_only_platform_scoped() {
    let p = SurfaceProfile::from_toml(CHAT).unwrap();
    assert_eq!(p.autonomy, Autonomy::ReadOnly);
    assert!(!p.allows_side_effects());
    assert_eq!(p.context.retrieval, RetrievalScope::PlatformAndNamespace);
    assert!(p.connectors.is_empty());
    let sk = skills();
    let plan = SurfaceBinding::new(&p, &sk)
        .plan(&power_user(), "how did UPI grow?", DataClass::Public, &[])
        .unwrap();
    assert!(!plan.allow_side_effects);
    assert_eq!(plan.retrieval, RetrievalScope::PlatformAndNamespace);
}

#[test]
fn code_edits_need_approval_repo_scoped_tools_only() {
    let p = SurfaceProfile::from_toml(CODE).unwrap();
    assert_eq!(p.autonomy, Autonomy::ActWithApproval);
    assert!(p.offers_capability("tool.edit"));
    assert!(p.offers_connector("gitlab"));
    let sk = skills();
    let plan = SurfaceBinding::new(&p, &sk)
        .plan(
            &power_user(),
            "fix the bug in x.rs",
            DataClass::Internal,
            &[],
        )
        .unwrap();
    assert!(
        plan.allow_side_effects && plan.require_approval,
        "code edits must be HITL"
    );
    assert_eq!(
        plan.retrieval,
        RetrievalScope::RepoScoped,
        "code must not reach outside its repo"
    );
    assert_eq!(
        plan.numeric,
        NumericPolicy::ToolsOnly,
        "code must not do model arithmetic"
    );
    assert!(plan
        .effective_capabilities
        .contains(&"tool.edit".to_string()));
}

#[test]
fn sdlc_is_deep_model_agnostic_and_multi_connector() {
    let p = SurfaceProfile::from_toml(SDLC).unwrap();
    assert_eq!(p.autonomy, Autonomy::ActWithApproval);
    assert_eq!(p.connectors, vec!["gitlab".to_string(), "jira".to_string()]);
    // Model-agnostic: a set of allowed providers (Claude primary / GPT fallback), none forced.
    assert!(p.model_policy.forced_provider.is_none());
    assert_eq!(
        p.model_policy.allowed_providers,
        vec!["claude".to_string(), "gpt".to_string()]
    );
    let sk = skills();
    let plan = SurfaceBinding::new(&p, &sk)
        .plan(
            &power_user(),
            "implement the feature",
            DataClass::Internal,
            &[],
        )
        .unwrap();
    // Fixed deep reasoning → Complex tier regardless of the (short) input.
    assert_eq!(plan.reasoning_depth, ReasoningDepth::Deep);
    assert_eq!(plan.tier, Tier::Complex);
}

#[test]
fn buddy_suggests_only_with_graph_connector() {
    let p = SurfaceProfile::from_toml(BUDDY).unwrap();
    assert_eq!(p.autonomy, Autonomy::Suggest);
    assert!(
        !p.allows_side_effects(),
        "suggest must not execute without confirmation"
    );
    assert!(p.offers_connector("graph"));
    let sk = skills();
    let plan = SurfaceBinding::new(&p, &sk)
        .plan(
            &power_user(),
            "draft a reply to the email",
            DataClass::Internal,
            &[],
        )
        .unwrap();
    assert!(!plan.allow_side_effects);
}

#[test]
fn every_surface_requires_the_baseline_capability() {
    // A principal without `chat.send` is refused by every surface's RBAC floor.
    let no_cap = Principal::user("stranger", &[]);
    let sk = skills();
    for src in [CHAT, CODE, SDLC, BUDDY] {
        let p = SurfaceProfile::from_toml(src).unwrap();
        let err = SurfaceBinding::new(&p, &sk).admit(&no_cap).unwrap_err();
        assert_eq!(err, BindingError::MissingCap("chat.send".to_string()));
    }
}

#[test]
fn department_scoped_surface_refuses_an_unscoped_principal() {
    // Every canonical surface is department-scoped; a principal with the cap but NO department is
    // refused (fail-closed data scoping) — and the plan for a scoped principal carries the scope.
    let sk = skills();
    let no_dept = Principal::user("u", &["chat.send"]); // has the cap, but no department
    for src in [CHAT, CODE, SDLC, BUDDY] {
        let p = SurfaceProfile::from_toml(src).unwrap();
        let err = SurfaceBinding::new(&p, &sk).admit(&no_dept).unwrap_err();
        assert_eq!(
            err,
            BindingError::DepartmentRequired,
            "{} must refuse an unscoped principal",
            p.id
        );
    }
    // A scoped principal is admitted and the department flows into the plan.
    let chat = SurfaceProfile::from_toml(CHAT).unwrap();
    let plan = SurfaceBinding::new(&chat, &sk)
        .plan(&power_user(), "hi", DataClass::Public, &[])
        .unwrap();
    assert_eq!(plan.department_scope.as_deref(), Some("payments"));
}

#[test]
fn profile_model_policy_is_fully_carried_into_the_plan() {
    // The whole model policy (not just forced_provider) must reach the router via the plan.
    let sk = skills();
    let sdlc = SurfaceProfile::from_toml(SDLC).unwrap();
    let plan = SurfaceBinding::new(&sdlc, &sk)
        .plan(&power_user(), "implement", DataClass::Internal, &[])
        .unwrap();
    assert_eq!(
        plan.allowed_providers,
        vec!["claude".to_string(), "gpt".to_string()]
    );
    assert_eq!(plan.default_tier, Tier::Complex);
    assert_eq!(plan.max_data_class, DataClass::Confidential);
    // context strategy also carried
    assert_eq!(plan.history_budget_tokens, 24000);
    assert!(plan.condenser);
}

#[test]
fn surfaces_refuse_data_above_their_ceiling() {
    // All four are cleared only up to Confidential — regulated-payment data is refused (ADR-012).
    let sk = skills();
    for src in [CHAT, CODE, SDLC, BUDDY] {
        let p = SurfaceProfile::from_toml(src).unwrap();
        let err = SurfaceBinding::new(&p, &sk)
            .plan(
                &power_user(),
                "handle this",
                DataClass::RegulatedPayment,
                &[],
            )
            .unwrap_err();
        assert!(
            matches!(err, BindingError::DataClassExceeded { .. }),
            "{} must refuse regulated data",
            p.id
        );
    }
}
