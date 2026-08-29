// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! ainxt-profile — the **Surface Profile** schema + layered loader (Phase 3, increment #1).
//!
//! The runtime is one engine; a *product surface* (Chat, Buddy, Code, SDLC) is a **Renderer** plus a
//! **declarative Surface Profile** that configures the spine for that surface. This crate is the
//! profile: what persona to speak as, which capabilities/skills/connectors are offered, how to
//! route models, how much autonomy the surface has, the RBAC floor, the retrieval scope, and the
//! prompt policy. Every enterprise-hard concern (compliance, RBAC, budget, audit) still lives in
//! the spine — the profile only *declares*; the engine *enforces*.
//!
//! **Config-first.** A profile is resolved by a layered merge — `defaults → deployment → tenant →
//! profile → request`, most-specific last — reusing [`ainxt_config::Loader`]'s deep TOML merge, so a
//! deployment can override a single nested field without restating the rest.
//!
//! **Safety-invariant.** The profile's `capabilities`/`connectors` are what the surface *offers*;
//! the effective authority is always that set **intersected with the calling principal's RBAC**,
//! which the engine's authz gate enforces (a profile can never *escalate* a principal). Autonomy
//! defaults to the safest value ([`Autonomy::ReadOnly`]) so a misconfigured profile cannot act.
//!
//! Clean-room: the schema, its vocabulary, and the resolve/validate flow are original to AiNxt.

use ainxt_types::{DataClass, Role, Tier};
use serde::{Deserialize, Serialize};

// ============================ Enums (own vocabulary; mapped to engine types in #3) ============================

/// How much a surface may *act*. Ordered least→most capable. The runtime binding (#3) translates
/// this into the side-effecting-tool + approval policy; the spine enforces it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Autonomy {
    /// No side effects at all — read/answer only. The safe default.
    #[default]
    ReadOnly,
    /// May propose actions (diffs, drafts) but not execute them.
    Suggest,
    /// May execute side-effecting tools, but each requires the approval gate (HITL).
    ActWithApproval,
    /// May execute side-effecting tools without per-action approval (still RBAC-gated).
    Autonomous,
}

/// Retrieval scope — the RBAC scope-separation knob (a payment-org non-negotiable). Chat/Voice use
/// [`PlatformAndNamespace`]; Projects/Threads use [`RepoScoped`] (that repo only, RBAC-gated).
///
/// [`PlatformAndNamespace`]: RetrievalScope::PlatformAndNamespace
/// [`RepoScoped`]: RetrievalScope::RepoScoped
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RetrievalScope {
    /// No retrieval.
    None,
    /// Platform knowledge base + the surface's namespace only (no repo filter).
    #[default]
    PlatformAndNamespace,
    /// A single repository, RBAC-gated. No cross-repo/cross-tenant reach.
    RepoScoped,
}

/// Default reasoning depth for the surface. `Auto` = classify per query (BE adaptive depth).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReasoningPref {
    #[default]
    Auto,
    Shallow,
    Standard,
    Deep,
}

/// Numeric policy: whether arithmetic/tabular reasoning must go through tools (BH — never model
/// arithmetic for payment-critical work).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NumericPref {
    #[default]
    Allow,
    ToolsOnly,
}

/// Default output rendering preference for the surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OutputPref {
    Text,
    #[default]
    Markdown,
    Json,
}

// ============================ Nested policies ============================

/// Model routing policy for the surface (routing inputs; the router + data-class gate enforce it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ModelPolicy {
    /// Default complexity tier when the query isn't classified otherwise.
    pub default_tier: Tier,
    /// R15 COMPOSE (§4.1 step 1) — HARD-pin `default_tier` for this surface instead of treating it as
    /// a soft floor. `false` (the default, byte-identical pre-existing behavior): the surface's
    /// reasoning-depth classifier may still ESCALATE above `default_tier` per query (`ainxt-surface`'s
    /// `TurnPlan::tier` = `max(depth_tier, default_tier)`), and the engine derives/soft-prefers the
    /// tier on the unpinned routing path. `true`: the surface never escalates or falls through —
    /// every turn routes through the engine's HARD tier filter at exactly `default_tier`
    /// (`ainxt-runtime`'s `select_chain_graded`/`tier_eligible` via `ainxt_protocol::Request::pinned_tier`,
    /// populated from `ainxt-surface`'s `TurnPlan::pinned_tier`); if no eligible provider exists at
    /// that tier the turn fails CLOSED rather than silently serving a wrong-tier model. This is the
    /// genuine per-profile tier-pin policy source for a surface whose model policy is a hard
    /// requirement, not a preference (e.g. the `sdlc` surface — CLAUDE.md: "ALL SDLC LLM calls: Claude
    /// Sonnet 4.6 primary, GPT-5.4 fallback, zero Ollama" — a task-type hint that must never silently
    /// downgrade to a lesser-tier/local model).
    #[serde(default)]
    pub pin_tier: bool,
    /// A pinned provider for this surface (still subject to the data-class exclusion gate).
    pub forced_provider: Option<String>,
    /// The providers this surface may use; empty = any eligible provider.
    pub allowed_providers: Vec<String>,
    /// The highest data class this surface may handle — a routing/compliance ceiling (ADR-012).
    pub max_data_class: DataClass,
}

impl Default for ModelPolicy {
    fn default() -> Self {
        ModelPolicy {
            default_tier: Tier::Simple,
            pin_tier: false,
            forced_provider: None,
            allowed_providers: Vec::new(),
            max_data_class: DataClass::Internal,
        }
    }
}

/// The RBAC floor a principal must meet to use the surface (the engine authz gate enforces it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RbacPolicy {
    /// Minimum role required to use this surface.
    pub min_role: Role,
    /// Capabilities a principal must hold to use this surface at all.
    pub required_caps: Vec<String>,
    /// Whether data for this surface is scoped by the principal's department.
    pub department_scoped: bool,
    /// GAP-AUDIT surfaces-profiles-skills-config #3 — an AD **seniority ceiling** for the surface
    /// itself (0 = most senior … 6 = junior; mirrors the identical `max_ad_level` ceiling
    /// `ainxt_retrieval::acl::NodeAcl` already enforces per-node in the Context Fabric). `None` (the
    /// default) = no seniority floor beyond `min_role`. `Some(n)` admits only a principal whose
    /// `ad_level <= n`; a principal with no `ad_level` claim is fail-closed refused, never admitted
    /// by omission — the same posture `NodeAcl` and the kill-switch authority gate already take.
    #[serde(default)]
    pub max_ad_level: Option<u8>,
}

impl Default for RbacPolicy {
    fn default() -> Self {
        RbacPolicy {
            min_role: Role::User,
            required_caps: Vec::new(),
            department_scoped: false,
            max_ad_level: None,
        }
    }
}

/// How context is assembled for the surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ContextStrategy {
    pub retrieval: RetrievalScope,
    /// Token budget for the conversation-history tail.
    pub history_budget_tokens: u32,
    /// Whether the condenser may compress history when over budget.
    pub condenser: bool,
}

impl Default for ContextStrategy {
    fn default() -> Self {
        ContextStrategy {
            retrieval: RetrievalScope::PlatformAndNamespace,
            history_budget_tokens: 8_000,
            condenser: true,
        }
    }
}

/// Prompt policy for the surface (mapped to the Prompt Engine in #3).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PromptPolicy {
    pub reasoning: ReasoningPref,
    pub numeric: NumericPref,
    pub output: OutputPref,
}

// ============================ The profile ============================

/// A fully-resolved Surface Profile. Absent fields take safe defaults (autonomy = read-only,
/// retrieval = platform+namespace) via the derived `Default` (every field type is `Default`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SurfaceProfile {
    /// Stable surface id, e.g. `"chat"` / `"code"` / `"sdlc"` / `"buddy"`. Required (validated).
    pub id: String,
    /// System-prompt persona for the surface.
    pub persona: String,
    /// Capabilities the surface OFFERS (tool/connector capability names). Effective authority is
    /// this set ∩ the principal's RBAC — the profile never escalates a principal.
    pub capabilities: Vec<String>,
    /// Skill refs (ids) to inject for this surface.
    pub skills: Vec<String>,
    /// Connector ids the surface may use.
    pub connectors: Vec<String>,
    pub model_policy: ModelPolicy,
    pub autonomy: Autonomy,
    pub rbac: RbacPolicy,
    pub context: ContextStrategy,
    pub prompt: PromptPolicy,
}

/// A profile resolution/validation error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileError {
    /// A layer failed to parse or merge/deserialize.
    Load(String),
    /// A required field was missing after resolution.
    MissingField(&'static str),
    /// A resolved field was internally inconsistent.
    Invalid(String),
}

impl std::fmt::Display for ProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProfileError::Load(m) => write!(f, "profile load error: {m}"),
            ProfileError::MissingField(field) => {
                write!(f, "profile missing required field '{field}'")
            }
            ProfileError::Invalid(m) => write!(f, "invalid profile: {m}"),
        }
    }
}
impl std::error::Error for ProfileError {}

impl SurfaceProfile {
    /// Resolve a profile from ordered TOML `layers` (`(name, toml_src)`, most-specific last), then
    /// validate. Use the canonical order `defaults, deployment, tenant, profile, request`.
    pub fn resolve(layers: &[(&str, &str)]) -> Result<SurfaceProfile, ProfileError> {
        let mut loader = ainxt_config::Loader::new();
        for (name, src) in layers {
            loader = loader
                .layer(name, src)
                .map_err(|e| ProfileError::Load(e.to_string()))?;
        }
        let profile: SurfaceProfile = loader
            .resolve()
            .map_err(|e| ProfileError::Load(e.to_string()))?;
        profile.validate()?;
        Ok(profile)
    }

    /// Parse a single TOML document into a validated profile (the common single-layer case).
    pub fn from_toml(src: &str) -> Result<SurfaceProfile, ProfileError> {
        Self::resolve(&[("profile", src)])
    }

    /// Validate internal consistency: id present, and a forced provider (if any) must be in the
    /// allowed set (when the allowed set is non-empty).
    pub fn validate(&self) -> Result<(), ProfileError> {
        if self.id.trim().is_empty() {
            return Err(ProfileError::MissingField("id"));
        }
        if let Some(forced) = &self.model_policy.forced_provider {
            let allowed = &self.model_policy.allowed_providers;
            if !allowed.is_empty() && !allowed.iter().any(|p| p == forced) {
                return Err(ProfileError::Invalid(format!(
                    "forced_provider '{forced}' is not in allowed_providers"
                )));
            }
        }
        Ok(())
    }

    /// Whether the surface offers a capability (exact match; the engine applies the finer authz).
    pub fn offers_capability(&self, cap: &str) -> bool {
        self.capabilities.iter().any(|c| c == cap)
    }
    /// Whether the surface may use a connector.
    pub fn offers_connector(&self, id: &str) -> bool {
        self.connectors.iter().any(|c| c == id)
    }
    /// Whether the surface may execute side-effecting tools at all.
    pub fn allows_side_effects(&self) -> bool {
        !matches!(self.autonomy, Autonomy::ReadOnly | Autonomy::Suggest)
    }
    /// Whether side-effecting tools require the approval gate (HITL).
    pub fn requires_approval(&self) -> bool {
        matches!(self.autonomy, Autonomy::ActWithApproval)
    }
    /// Whether the surface may act without per-action approval.
    pub fn is_autonomous(&self) -> bool {
        matches!(self.autonomy, Autonomy::Autonomous)
    }

    /// Apply the final **`request`** rung of the `defaults → deployment → tenant → profile → request`
    /// chain (ADR-004) on top of this already-resolved profile — the layer a single TURN contributes,
    /// consumed at plan-time rather than at boot (gap: "per-request runtime-config override layer
    /// applied at turn time"). Deep-merges `request_toml` over `self` via
    /// [`ainxt_config::merge_toml`], deserializes, validates, then enforces a hard
    /// **SAFETY-INVARIANT**: a request layer may only ever *narrow or hold* the surface's authority,
    /// never widen it. Concretely it may adjust the reasoning-depth preference, the output-format
    /// preference, the routing tier, and (bounded by the already-resolved allow-list) which allowed
    /// provider to prefer this turn — and may only STRENGTHEN numeric discipline (`allow` →
    /// `tools-only`, never the reverse). It can never change the surface id, persona, skill refs,
    /// RBAC floor, offered capabilities/connectors, autonomy, context/retrieval strategy, the
    /// data-class ceiling, the allow-listed provider set, or a deployment-pinned `forced_provider`.
    /// Any attempt to do so is rejected — fail-closed, never silently dropped or silently honored.
    pub fn with_request_layer(&self, request_toml: &str) -> Result<SurfaceProfile, ProfileError> {
        let base_value = toml::Value::try_from(self)
            .map_err(|e| ProfileError::Load(format!("cannot serialize base profile: {e}")))?;
        let request_value: toml::Value = toml::from_str(request_toml)
            .map_err(|e| ProfileError::Load(format!("request: {e}")))?;
        let merged_value = ainxt_config::merge_toml(base_value, request_value);
        let merged: SurfaceProfile = merged_value
            .try_into()
            .map_err(|e: toml::de::Error| ProfileError::Load(e.to_string()))?;
        merged.validate()?;
        self.enforce_request_layer_invariants(&merged)?;
        Ok(merged)
    }

    /// The narrowing check backing [`with_request_layer`](Self::with_request_layer). Kept separate so
    /// the invariant is a single, auditable, testable decision point.
    fn enforce_request_layer_invariants(
        &self,
        merged: &SurfaceProfile,
    ) -> Result<(), ProfileError> {
        if merged.id != self.id {
            return Err(ProfileError::Invalid(
                "a request layer must not change the surface id".into(),
            ));
        }
        if merged.persona != self.persona {
            return Err(ProfileError::Invalid(
                "a request layer must not change the persona".into(),
            ));
        }
        if merged.skills != self.skills {
            return Err(ProfileError::Invalid(
                "a request layer must not change the injected skill refs".into(),
            ));
        }
        if merged.rbac != self.rbac {
            return Err(ProfileError::Invalid(
                "a request layer must not change the RBAC floor".into(),
            ));
        }
        if merged.capabilities != self.capabilities {
            return Err(ProfileError::Invalid(
                "a request layer must not change the offered capabilities".into(),
            ));
        }
        if merged.connectors != self.connectors {
            return Err(ProfileError::Invalid(
                "a request layer must not change the offered connectors".into(),
            ));
        }
        if merged.autonomy != self.autonomy {
            return Err(ProfileError::Invalid(
                "a request layer must not change the autonomy posture".into(),
            ));
        }
        if merged.context != self.context {
            return Err(ProfileError::Invalid(
                "a request layer must not change the context/retrieval strategy".into(),
            ));
        }
        if merged.model_policy.max_data_class != self.model_policy.max_data_class {
            return Err(ProfileError::Invalid(
                "a request layer must not change the data-class ceiling".into(),
            ));
        }
        if merged.model_policy.allowed_providers != self.model_policy.allowed_providers {
            return Err(ProfileError::Invalid(
                "a request layer must not change the allowed-provider allow-list".into(),
            ));
        }
        // R15 COMPOSE — a deployment-pinned HARD tier (§4.1 step 1) can never be turned OFF by a
        // request layer: that would be a widening (escaping the fail-closed hard filter back onto the
        // engine's soft, escalatable preference), which the safety invariant forbids. Turning a pin ON
        // is a narrowing (or a no-op preference tweak alongside the already-permitted `default_tier`
        // adjustment) and stays allowed.
        if self.model_policy.pin_tier && !merged.model_policy.pin_tier {
            return Err(ProfileError::Invalid(
                "a request layer must not remove a deployment-pinned hard tier".into(),
            ));
        }
        // A deployment-pinned forced_provider can never be overridden by a request. A request MAY
        // set forced_provider when the deployment left it unset, but only to a provider already
        // within the (unchanged, checked above) allow-list — never a way to reach an out-of-policy
        // provider.
        if let Some(base_forced) = &self.model_policy.forced_provider {
            if merged.model_policy.forced_provider.as_deref() != Some(base_forced.as_str()) {
                return Err(ProfileError::Invalid(
                    "a request layer must not override a deployment-pinned forced_provider".into(),
                ));
            }
        } else if let Some(req_forced) = &merged.model_policy.forced_provider {
            let allowed = &self.model_policy.allowed_providers;
            if !allowed.is_empty() && !allowed.iter().any(|p| p == req_forced) {
                return Err(ProfileError::Invalid(format!(
                    "request-selected provider '{req_forced}' is not in the surface's allowed_providers"
                )));
            }
        }
        // Numeric discipline may only be STRENGTHENED (allow -> tools-only), never loosened.
        if numeric_rank(merged.prompt.numeric) < numeric_rank(self.prompt.numeric) {
            return Err(ProfileError::Invalid(
                "a request layer must not loosen numeric discipline".into(),
            ));
        }
        Ok(())
    }
}

/// Strictness rank for [`NumericPref`] — higher is stricter. A request layer may only move up.
fn numeric_rank(p: NumericPref) -> u8 {
    match p {
        NumericPref::Allow => 0,
        NumericPref::ToolsOnly => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_a_minimal_profile_with_safe_defaults() {
        let p = SurfaceProfile::from_toml(r#"id = "chat""#).unwrap();
        assert_eq!(p.id, "chat");
        // Safe defaults: read-only, platform+namespace retrieval, Simple tier.
        assert_eq!(p.autonomy, Autonomy::ReadOnly);
        assert!(!p.allows_side_effects());
        assert_eq!(p.context.retrieval, RetrievalScope::PlatformAndNamespace);
        assert_eq!(p.model_policy.default_tier, Tier::Simple);
        assert_eq!(p.prompt.reasoning, ReasoningPref::Auto);
        assert_eq!(p.rbac.min_role, Role::User);
    }

    #[test]
    fn layered_merge_is_deep_and_most_specific_wins() {
        // defaults set a nested model field; profile sets id + another nested model field;
        // deployment overrides autonomy. Deep merge must combine all three.
        let defaults = r#"
            [model_policy]
            default_tier = "complex"
        "#;
        let deployment = r#"
            autonomy = "act-with-approval"
        "#;
        let profile = r#"
            id = "sdlc"
            persona = "SDLC engineer"
            [model_policy]
            forced_provider = "claude"
            allowed_providers = ["claude", "gpt"]
        "#;
        let p = SurfaceProfile::resolve(&[
            ("defaults", defaults),
            ("deployment", deployment),
            ("profile", profile),
        ])
        .unwrap();
        assert_eq!(p.id, "sdlc");
        assert_eq!(p.model_policy.default_tier, Tier::Complex); // from defaults, survived deep merge
        assert_eq!(p.model_policy.forced_provider.as_deref(), Some("claude")); // from profile
        assert_eq!(p.autonomy, Autonomy::ActWithApproval); // from deployment
        assert!(p.requires_approval());
    }

    #[test]
    fn most_specific_layer_overrides_scalar() {
        let base = r#"id = "code"
            autonomy = "autonomous""#;
        let request = r#"autonomy = "read-only""#;
        let p = SurfaceProfile::resolve(&[("profile", base), ("request", request)]).unwrap();
        assert_eq!(p.autonomy, Autonomy::ReadOnly, "request layer (last) wins");
    }

    #[test]
    fn arrays_replace_not_merge() {
        let defaults = r#"id = "x"
            capabilities = ["a", "b"]"#;
        let profile = r#"capabilities = ["c"]"#;
        let p = SurfaceProfile::resolve(&[("defaults", defaults), ("profile", profile)]).unwrap();
        assert_eq!(
            p.capabilities,
            vec!["c".to_string()],
            "a later array replaces the earlier one"
        );
    }

    #[test]
    fn missing_id_is_rejected() {
        assert_eq!(
            SurfaceProfile::from_toml(r#"persona = "x""#),
            Err(ProfileError::MissingField("id"))
        );
    }

    #[test]
    fn forced_provider_must_be_allowed() {
        let src = r#"
            id = "chat"
            [model_policy]
            forced_provider = "gemini"
            allowed_providers = ["claude", "gpt"]
        "#;
        assert!(matches!(
            SurfaceProfile::from_toml(src),
            Err(ProfileError::Invalid(_))
        ));
        // Empty allowed set → any forced provider is fine.
        let ok = r#"
            id = "chat"
            [model_policy]
            forced_provider = "gemini"
        "#;
        assert!(SurfaceProfile::from_toml(ok).is_ok());
    }

    #[test]
    fn unknown_field_is_rejected() {
        assert!(matches!(
            SurfaceProfile::from_toml("id = \"x\"\nbogus = 1"),
            Err(ProfileError::Load(_))
        ));
    }

    #[test]
    fn autonomy_helpers() {
        let mk =
            |a: &str| SurfaceProfile::from_toml(&format!("id=\"x\"\nautonomy=\"{a}\"")).unwrap();
        assert!(!mk("read-only").allows_side_effects());
        assert!(!mk("suggest").allows_side_effects());
        assert!(mk("act-with-approval").allows_side_effects());
        assert!(mk("act-with-approval").requires_approval());
        assert!(mk("autonomous").allows_side_effects());
        assert!(mk("autonomous").is_autonomous());
        assert!(!mk("autonomous").requires_approval());
    }

    #[test]
    fn capability_and_connector_queries() {
        let p = SurfaceProfile::from_toml(
            r#"id="code"
               capabilities = ["tool.grep", "tool.edit"]
               connectors = ["gitlab"]"#,
        )
        .unwrap();
        assert!(p.offers_capability("tool.grep"));
        assert!(!p.offers_capability("tool.delete"));
        assert!(p.offers_connector("gitlab"));
        assert!(!p.offers_connector("graph"));
    }

    #[test]
    fn resolved_profile_serde_round_trips() {
        let p = SurfaceProfile::from_toml(
            r#"id="chat"
               persona="helpful"
               capabilities=["chat.send"]
               [context]
               retrieval="repo-scoped"
               history_budget_tokens=4096
               condenser=false"#,
        )
        .unwrap();
        let json = serde_json::to_string(&p).unwrap();
        let back: SurfaceProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
        assert_eq!(back.context.retrieval, RetrievalScope::RepoScoped);
        assert_eq!(back.context.history_budget_tokens, 4096);
        assert!(!back.context.condenser);
    }

    // ==================== request-layer (turn-time) override (R15) ====================

    #[test]
    fn r15_request_layer_may_adjust_reasoning_output_and_tier() {
        let p = SurfaceProfile::from_toml(
            "id=\"chat\"\n[model_policy]\ndefault_tier=\"simple\"\n[prompt]\nreasoning=\"auto\"\noutput=\"markdown\"",
        )
        .unwrap();
        let adjusted = p
            .with_request_layer(
                "[model_policy]\ndefault_tier=\"complex\"\n[prompt]\nreasoning=\"deep\"\noutput=\"json\"",
            )
            .expect("a narrow prompt/tier preference tweak is a legitimate request layer");
        assert_eq!(adjusted.model_policy.default_tier, Tier::Complex);
        assert_eq!(adjusted.prompt.reasoning, ReasoningPref::Deep);
        assert_eq!(adjusted.prompt.output, OutputPref::Json);
        // Everything else is untouched.
        assert_eq!(adjusted.id, p.id);
        assert_eq!(adjusted.rbac, p.rbac);
    }

    #[test]
    fn r15_request_layer_cannot_escalate_rbac_capabilities_or_autonomy() {
        let p = SurfaceProfile::from_toml(
            "id=\"chat\"\ncapabilities=[\"tool.grep\"]\nconnectors=[\"gitlab\"]\nautonomy=\"read-only\"\n\
             [rbac]\nmin_role=\"user\"",
        )
        .unwrap();
        assert!(matches!(
            p.with_request_layer("[rbac]\nmin_role=\"admin\""),
            Err(ProfileError::Invalid(_))
        ));
        assert!(matches!(
            p.with_request_layer("capabilities=[\"tool.grep\",\"tool.delete\"]"),
            Err(ProfileError::Invalid(_))
        ));
        assert!(matches!(
            p.with_request_layer("connectors=[\"gitlab\",\"jira\"]"),
            Err(ProfileError::Invalid(_))
        ));
        assert!(matches!(
            p.with_request_layer("autonomy=\"autonomous\""),
            Err(ProfileError::Invalid(_))
        ));
    }

    #[test]
    fn r15_request_layer_cannot_widen_data_class_ceiling_or_retrieval_scope() {
        let p = SurfaceProfile::from_toml(
            "id=\"chat\"\n[model_policy]\nmax_data_class=\"internal\"\n[context]\nretrieval=\"repo-scoped\"",
        )
        .unwrap();
        assert!(matches!(
            p.with_request_layer("[model_policy]\nmax_data_class=\"regulated-payment\""),
            Err(ProfileError::Invalid(_))
        ));
        assert!(matches!(
            p.with_request_layer("[context]\nretrieval=\"platform-and-namespace\""),
            Err(ProfileError::Invalid(_))
        ));
    }

    #[test]
    fn r15_request_layer_cannot_override_a_pinned_provider_or_escape_the_allow_list() {
        let pinned = SurfaceProfile::from_toml(
            "id=\"pay\"\n[model_policy]\nforced_provider=\"claude\"\nallowed_providers=[\"claude\"]",
        )
        .unwrap();
        assert!(matches!(
            pinned.with_request_layer("[model_policy]\nforced_provider=\"gpt\""),
            Err(ProfileError::Invalid(_))
        ));

        let allow_listed = SurfaceProfile::from_toml(
            "id=\"pay\"\n[model_policy]\nallowed_providers=[\"claude\",\"gpt\"]",
        )
        .unwrap();
        // Selecting a provider already in the allow-list is a legitimate NARROWING request.
        let ok = allow_listed
            .with_request_layer("[model_policy]\nforced_provider=\"gpt\"")
            .unwrap();
        assert_eq!(ok.model_policy.forced_provider.as_deref(), Some("gpt"));
        // Selecting a provider outside the allow-list is refused.
        assert!(matches!(
            allow_listed.with_request_layer("[model_policy]\nforced_provider=\"gemini\""),
            Err(ProfileError::Invalid(_))
        ));
        // The allow-list itself can never be changed by a request.
        assert!(matches!(
            allow_listed.with_request_layer(
                "[model_policy]\nallowed_providers=[\"claude\",\"gpt\",\"gemini\"]"
            ),
            Err(ProfileError::Invalid(_))
        ));
    }

    #[test]
    fn r15_compose_pin_tier_defaults_off_and_survives_serde() {
        let p = SurfaceProfile::from_toml("id=\"chat\"\n[model_policy]\ndefault_tier=\"simple\"")
            .unwrap();
        assert!(
            !p.model_policy.pin_tier,
            "pin_tier must default to false (pre-wire behavior)"
        );
        let pinned = SurfaceProfile::from_toml(
            "id=\"sdlc\"\n[model_policy]\ndefault_tier=\"complex\"\npin_tier=true",
        )
        .unwrap();
        assert!(pinned.model_policy.pin_tier);
        let json = serde_json::to_string(&pinned).unwrap();
        let back: SurfaceProfile = serde_json::from_str(&json).unwrap();
        assert!(back.model_policy.pin_tier);
    }

    #[test]
    fn r15_compose_request_layer_cannot_remove_a_deployment_hard_pin() {
        let pinned = SurfaceProfile::from_toml(
            "id=\"sdlc\"\n[model_policy]\ndefault_tier=\"complex\"\npin_tier=true",
        )
        .unwrap();
        // Turning the pin OFF is a widening (escapes the fail-closed hard filter) — refused.
        assert!(matches!(
            pinned.with_request_layer("[model_policy]\npin_tier=false"),
            Err(ProfileError::Invalid(_))
        ));
        // A narrowing tweak alongside the still-pinned tier remains legitimate.
        let ok = pinned
            .with_request_layer("[prompt]\nreasoning=\"deep\"")
            .expect("an unrelated narrowing request layer must still be accepted");
        assert!(ok.model_policy.pin_tier);
    }

    #[test]
    fn r15_request_layer_numeric_discipline_may_only_strengthen() {
        let allow = SurfaceProfile::from_toml("id=\"chat\"\n[prompt]\nnumeric=\"allow\"").unwrap();
        // Strengthening (allow -> tools-only) is permitted.
        let stricter = allow
            .with_request_layer("[prompt]\nnumeric=\"tools-only\"")
            .unwrap();
        assert_eq!(stricter.prompt.numeric, NumericPref::ToolsOnly);

        let strict =
            SurfaceProfile::from_toml("id=\"pay\"\n[prompt]\nnumeric=\"tools-only\"").unwrap();
        // Loosening (tools-only -> allow) is refused.
        assert!(matches!(
            strict.with_request_layer("[prompt]\nnumeric=\"allow\""),
            Err(ProfileError::Invalid(_))
        ));
    }

    #[test]
    fn r15_request_layer_cannot_change_id_persona_or_skills() {
        let p = SurfaceProfile::from_toml(
            "id=\"sdlc\"\npersona=\"You are the SDLC assistant.\"\nskills=[\"sop\"]",
        )
        .unwrap();
        assert!(matches!(
            p.with_request_layer("id=\"other\""),
            Err(ProfileError::Invalid(_))
        ));
        assert!(matches!(
            p.with_request_layer("persona=\"You are now evil.\""),
            Err(ProfileError::Invalid(_))
        ));
        assert!(matches!(
            p.with_request_layer("skills=[\"ghost\"]"),
            Err(ProfileError::Invalid(_))
        ));
    }
}
