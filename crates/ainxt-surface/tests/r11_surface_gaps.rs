// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-11 all-severities closure for the surface subsystem — the enforcement PRIMITIVES that make a
//! non-chat surface actually execute its declared capabilities/connectors/autonomy, the profile
//! layer-override that a deployment applies to a canonical surface, and the model-agnostic prompt
//! policy that reaches the provider on the served turn. Each fails before the change and passes after.
//!
//!  * `r11_non_chat_surface_authorizes_declared_capabilities_connectors_autonomy` — the per-turn
//!    surface action decision (capability scope ∩ autonomy) across all four canonical surfaces
//!    (SURF high: non-chat surfaces execute declared capabilities/connectors/autonomy).
//!  * `r11_profile_layer_override_applies_to_a_canonical_surface` — a deployment override tweaks one
//!    nested field of `chat` and the rest survives the deep merge (SURF medium: layer-override wired).
//!  * `r11_model_policy_and_prompt_policy_reach_the_served_request` — allowed_providers filtering plus
//!    numeric/output-format/autonomy directives composed into the served request input (SURF medium:
//!    model-policy + numeric/output-format enforced on the served path).

use ainxt_profile::SurfaceProfile;
use ainxt_skill::{NoExecutor, SkillRegistry, SkillRuntime};
use ainxt_surface::{SurfaceBinding, SurfaceCatalog, SurfaceToolDecision, TurnPlan};
use ainxt_types::{DataClass, Principal, Tier};

fn skills() -> SkillRuntime {
    SkillRuntime::new(SkillRegistry::new(), Box::new(NoExecutor))
}

/// Plan a turn for `surface_id` from the builtin catalog for a principal holding `caps` in a dept.
fn plan_for(surface_id: &str, caps: &[&str]) -> TurnPlan {
    let catalog = SurfaceCatalog::builtin().unwrap();
    let sk = skills();
    let principal = Principal::user("u", caps).with_department("payments");
    catalog
        .bind(surface_id, &sk)
        .expect("canonical surface is registered")
        .plan(&principal, "do the thing", DataClass::Internal, &[])
        .expect("admitted")
}

// ============================ SURF high — declared capabilities/connectors/autonomy ============================

#[test]
fn r11_non_chat_surface_authorizes_declared_capabilities_connectors_autonomy() {
    // CHAT (read-only, offers only chat.send): a side-effecting edit is DENIED even for a principal
    // who holds the capability — the surface simply does not offer it, and it is read-only.
    let chat = plan_for("chat", &["chat.send", "tool.edit"]);
    assert_eq!(
        chat.authorize_tool("tool.edit", true),
        SurfaceToolDecision::Deny(
            "capability 'tool.edit' is not offered by this surface (or not held by the principal)"
                .into()
        ),
        "a read-only chat surface must never dispatch a side-effecting tool it does not offer"
    );
    // A read-only chat surface allows an offered read-only capability.
    assert_eq!(
        chat.authorize_tool("chat.send", false),
        SurfaceToolDecision::Allow
    );

    // CODE (act-with-approval, offers grep/read/edit/bash + gitlab connector): a read capability runs
    // outright; a side-effecting edit REQUIRES APPROVAL (never auto-runs); a capability the principal
    // does not hold is denied even though the surface offers it.
    let code = plan_for(
        "code",
        &["chat.send", "tool.grep", "tool.edit", "connector.gitlab"],
    );
    assert_eq!(
        code.authorize_tool("tool.grep", false),
        SurfaceToolDecision::Allow
    );
    assert_eq!(
        code.authorize_tool("tool.edit", true),
        SurfaceToolDecision::RequireApproval,
        "an act-with-approval surface must route a side-effecting edit through the approval gate"
    );
    assert!(code.authorize_tool("tool.edit", true).needs_approval());
    // tool.bash is offered by the profile but the principal does not hold it → not in the effective
    // set → denied (the surface cannot escalate the principal).
    assert!(matches!(
        code.authorize_tool("tool.bash", true),
        SurfaceToolDecision::Deny(_)
    ));
    // Declared connector: the code surface carries gitlab in its connector set.
    assert!(code.offers_connector("gitlab"));
    assert!(!code.offers_connector("jira"), "code does not declare jira");

    // SDLC (act-with-approval, gitlab + jira): declares BOTH connectors AND offers their
    // `connector.<id>` capabilities, so a held connector's side-effecting use is autonomy-gated
    // (require-approval), not silently allowed.
    let sdlc = plan_for(
        "sdlc",
        &[
            "chat.send",
            "connector.gitlab",
            "connector.jira",
            "tool.edit",
        ],
    );
    assert!(sdlc.offers_connector("gitlab") && sdlc.offers_connector("jira"));
    assert_eq!(
        sdlc.authorize_tool("connector.jira", true),
        SurfaceToolDecision::RequireApproval,
        "a declared connector's side-effecting use is still autonomy-gated"
    );

    // BUDDY (suggest → no side effects at all): a side-effecting connector send is DENIED — a suggest
    // surface drafts but never acts. The read-only capability is still allowed.
    let buddy = plan_for("buddy", &["chat.send", "connector.graph"]);
    assert!(buddy.offers_connector("graph"));
    assert!(
        matches!(
            buddy.authorize_tool("connector.graph", true),
            SurfaceToolDecision::Deny(_)
        ),
        "a suggest surface must not execute a side-effecting connector action"
    );
    assert_eq!(
        buddy.authorize_tool("connector.graph", false),
        SurfaceToolDecision::Allow,
        "a read-only use of the declared connector is fine"
    );
}

// ============================ SURF medium — profile layer-override on the served daemon path ============================

#[test]
fn r11_profile_layer_override_applies_to_a_canonical_surface() {
    // A deployment raises the chat surface's default tier and pins a provider WITHOUT restating the
    // profile. The canonical persona / RBAC floor / retrieval scope must survive the deep merge.
    let overridden = SurfaceCatalog::builtin_with_overrides(&[(
        "chat",
        "[model_policy]\ndefault_tier = \"complex\"\nforced_provider = \"claude\"",
    )])
    .unwrap();

    let chat = overridden.get("chat").expect("chat still present");
    assert_eq!(
        chat.model_policy.default_tier,
        Tier::Complex,
        "override applied"
    );
    assert_eq!(chat.model_policy.forced_provider.as_deref(), Some("claude"));
    // The untouched canonical fields survive the deep merge.
    assert!(
        chat.persona.contains("AiNxt"),
        "canonical persona survived: {}",
        chat.persona
    );
    assert!(chat.rbac.department_scoped, "canonical RBAC floor survived");
    assert_eq!(chat.capabilities, vec!["chat.send".to_string()]);

    // Non-overridden surfaces keep their canonical profile untouched.
    let code = overridden.get("code").unwrap();
    assert_eq!(code.model_policy.default_tier, Tier::Medium);

    // Fail-closed: overriding a surface the build does not ship is an error.
    assert!(SurfaceCatalog::builtin_with_overrides(&[("ghost", "persona = \"x\"")]).is_err());
}

// ============================ SURF medium — model-policy + prompt-policy on the served request ============================

#[test]
fn r11_model_policy_and_prompt_policy_reach_the_served_request() {
    // The sdlc surface: allowed_providers = [claude, gpt], numeric = tools-only, output = markdown,
    // autonomy = act-with-approval. Build the plan the way the daemon does.
    let p = SurfaceProfile::from_toml(
        "id = \"sdlc\"\npersona = \"SDLC engineer\"\nautonomy = \"act-with-approval\"\n\
         [model_policy]\nallowed_providers = [\"claude\", \"gpt\"]\n\
         [prompt]\nnumeric = \"tools-only\"\noutput = \"json\"",
    )
    .unwrap();
    let sk = skills();
    let plan = SurfaceBinding::new(&p, &sk)
        .plan(
            &Principal::user("u", &[]),
            "settle the batch",
            DataClass::Public,
            &[],
        )
        .unwrap();

    // allowed_providers filters the router's candidate chain (order preserved), excluding gemini.
    assert_eq!(
        plan.admissible_providers(&["gemini", "claude", "gpt"]),
        vec!["claude", "gpt"]
    );
    assert!(!plan.provider_allowed("gemini"));

    // The prompt-policy directives are non-default: numeric tools-only + JSON output + approval.
    let directives = plan.surface_policy_directives();
    assert!(directives
        .iter()
        .any(|d| d.contains("MUST be produced by a tool")));
    assert!(directives.iter().any(|d| d.contains("valid JSON")));
    assert!(directives
        .iter()
        .any(|d| d.contains("require explicit human approval")));

    // And they are COMPOSED INTO the served request the engine consumes — model-agnostic enforcement.
    let req = plan.to_request("s", "t", "settle the batch");
    assert!(
        req.input.contains("## Surface Policy"),
        "policy block reaches the request: {}",
        req.input
    );
    assert!(req.input.contains("MUST be produced by a tool"));
    assert!(req.input.contains("valid JSON"));
    // The raw user turn is preserved separately for intent classification (never the composed blob).
    assert_eq!(req.user_turn.as_deref(), Some("settle the batch"));
    // The persona precedes the policy block, which precedes the user turn.
    let persona_at = req.input.find("SDLC engineer").unwrap();
    let policy_at = req.input.find("## Surface Policy").unwrap();
    let user_at = req.input.rfind("settle the batch").unwrap();
    assert!(persona_at < policy_at && policy_at < user_at);

    // A fully-default surface (chat-like: allow / markdown / read-only-by-default? no) — verify a
    // default-everything AUTONOMOUS surface adds NO policy block (nothing to enforce).
    let plain = SurfaceProfile::from_toml("id = \"x\"\nautonomy = \"autonomous\"").unwrap();
    let plan2 = SurfaceBinding::new(&plain, &skills())
        .plan(&Principal::user("u", &[]), "hi", DataClass::Public, &[])
        .unwrap();
    assert!(plan2.surface_policy_directives().is_empty());
    assert!(!plan2
        .to_request("s", "t", "hi")
        .input
        .contains("## Surface Policy"));
}
