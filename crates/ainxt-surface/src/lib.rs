// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! ainxt-surface — the **profile → runtime binding** (Phase 3, increment #3).
//!
//! A [`SurfaceProfile`] *declares* how a surface behaves; the engine *enforces*. This crate is the
//! glue that turns a profile + a calling [`Principal`] + a user turn into a [`TurnPlan`] — the set of
//! concrete inputs the engine needs for one turn. It applies the profile's policies in a fail-closed
//! order:
//!
//! 1. **Admission** — the principal must meet the profile's RBAC floor (role + required caps).
//! 2. **Data-class ceiling** — a turn whose data is more sensitive than the surface is cleared for is
//!    refused (ADR-012: the surface can't be a leak path for regulated data it shouldn't touch).
//! 3. **Effective capabilities** = the profile's offered set **intersected** with the principal's —
//!    the profile can never *escalate* a principal (the engine still authorizes each tool call).
//! 4. **Autonomy → action policy** — read-only/suggest allow no side effects; act-with-approval
//!    routes side-effecting tools through the approval gate; autonomous allows them (still RBAC'd).
//! 5. **Prompt** — reasoning depth (adaptive per-query when `Auto`, else fixed) → routing tier (BE);
//!    numeric + format policy; and the assembled system prompt (persona → behavioral → guard) plus
//!    the `## Context` block, via the Skill Runtime.
//! 6. **Retrieval scope** — the RBAC scope-separation knob (no cross-repo/tenant reach).
//!
//! Pure and fully testable; the composition binary maps the [`TurnPlan`] onto the engine's Request +
//! prompt + authz + approval + router.
//!
//! Clean-room: the binding pipeline and the `TurnPlan` shape are original to AiNxt.

mod artifact;
mod catalog;
pub use artifact::{
    ArtifactError, ArtifactLimits, ArtifactOutput, AuditFinding, Block, ContentScanner, Document,
    LuhnEntropyScanner, MarkerScanner, Renderer, SurfaceArtifacts,
};
pub use catalog::{builtin_profiles, SurfaceCatalog};

use ainxt_profile::{
    NumericPref, OutputPref, ProfileError, ReasoningPref, RetrievalScope, SurfaceProfile,
};
use ainxt_prompt::{
    ComplexityClassifier, HeuristicComplexity, NumericPolicy, OutputFormat, ReasoningDepth,
};
use ainxt_skill::{SkillError, SkillRuntime};
use ainxt_types::{DataClass, Principal, Role, Tier};

/// Everything the engine needs to run one turn under a surface. Produced by [`SurfaceBinding::plan`].
///
/// This is the daemon-consumable contract: the composition binary maps every field onto the engine's
/// `Request` + router + prompt + authz + approval. The whole of the profile's model policy is
/// carried here (not just `forced_provider`) so the router has the full picture — allowed providers,
/// the surface's default/floor tier, and the data-class ceiling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnPlan {
    /// The system-prompt segment: persona → behavioral skills → guard prompts.
    pub system_prompt: String,
    /// The `## Context` block from execution-skill output (retrieval is merged in by the caller).
    pub context_block: String,
    /// The profile's offered capabilities intersected with the principal's — informational; the
    /// engine's authz gate is still the enforcement point.
    pub effective_capabilities: Vec<String>,
    /// The connector ids this surface DECLARES it may use (`code`→gitlab, `sdlc`→gitlab+jira,
    /// `buddy`→graph). A connector is only reachable if the surface offers it AND the principal holds
    /// its `connector.<id>` capability (the engine authz gate is still the enforcement point); this
    /// carries the surface's declared connector set onto the served turn so a non-chat surface can
    /// actually EXECUTE its declared connectors (gap SURF: non-chat surfaces execute declared
    /// capabilities/connectors/autonomy).
    pub connectors: Vec<String>,
    /// The resolved reasoning depth (classified per-query when the profile says `Auto`).
    pub reasoning_depth: ReasoningDepth,
    /// The EFFECTIVE routing tier: the higher of the reasoning-depth tier and the surface's declared
    /// `default_tier` (BE: route by depth, but never below the surface's declared floor) — UNLESS
    /// [`pinned_tier`](Self::pinned_tier) is `Some`, in which case this is exactly `default_tier`
    /// (depth escalation never applies to a hard-pinned surface).
    pub tier: Tier,
    /// The surface's declared default/floor tier (routing input, before depth escalation).
    pub default_tier: Tier,
    /// R15 COMPOSE (§4.1 step 1) — a HARD pin of the routing tier for this turn, populated from
    /// [`ainxt_profile::ModelPolicy::pin_tier`] (`Some(default_tier)` when the surface's profile
    /// hard-pins its tier; `None` — the default — when the surface leaves tier selection to the
    /// engine's soft preference / in-engine complexity classifier). [`to_request`](Self::to_request)
    /// carries this straight onto [`ainxt_protocol::Request::pinned_tier`], so a pinned surface (e.g.
    /// `sdlc`) routes through the engine's HARD tier filter and fails CLOSED rather than silently
    /// serving a wrong-tier model.
    pub pinned_tier: Option<Tier>,
    pub numeric: NumericPolicy,
    pub format: OutputFormat,
    /// A pinned provider for the surface (still subject to the engine's data-class exclusion gate).
    pub forced_provider: Option<String>,
    /// The providers this surface may use; empty = any eligible provider (router decides).
    pub allowed_providers: Vec<String>,
    /// The data class this turn runs at (already checked against the surface ceiling).
    pub data_class: DataClass,
    /// The surface's data-class ceiling (routing/compliance input; ADR-012).
    pub max_data_class: DataClass,
    /// Whether side-effecting tools may run at all this turn.
    pub allow_side_effects: bool,
    /// Whether side-effecting tools must clear the approval gate (HITL).
    pub require_approval: bool,
    /// The retrieval scope for context assembly (no cross-repo/tenant reach).
    pub retrieval: RetrievalScope,
    /// When the surface is department-scoped, the principal's department that retrieval MUST filter
    /// by (`Some(dept)`); `None` when the surface is not department-scoped. Admission guarantees a
    /// department-scoped surface never yields `None` (a principal with no department is refused).
    pub department_scope: Option<String>,
    /// Conversation-history token budget for context assembly.
    pub history_budget_tokens: u32,
    /// Whether the condenser may compress history when it exceeds the budget.
    pub condenser: bool,
}

impl TurnPlan {
    /// The **profile model-policy enforcement predicate** (gap SURF-06), as a pure function of just
    /// the two model-policy inputs rather than a fully-planned `TurnPlan`. Precedence:
    /// 1. a `forced_provider` pins the surface to exactly that provider (nothing else is allowed);
    /// 2. otherwise a non-empty `allowed_providers` acts as an allow-list;
    /// 3. otherwise (no forced, empty allow-list) any provider is permitted.
    ///
    /// This is *additive* to — never a replacement for — the engine's non-overridable data-class
    /// exclusion gate (ADR-012). The router still runs the data-class gate first; this narrows the
    /// eligible set to what the surface is configured to use.
    ///
    /// GAP-FIX surface-turnplan-policy — exposed as a `TurnPlan`-free associated function (rather than
    /// only an instance method) because the daemon's router-construction step
    /// (`ainxt_runtimed::filter_models_by_allowlist`) runs at BOOT time, once per surface, before any
    /// principal/turn exists to plan a `TurnPlan` from — there is no `TurnPlan` to call a method on
    /// yet. Before this, that boot-time step hand-rolled its own copy of just the `allowed_providers`
    /// arm and silently dropped the `forced_provider` arm entirely (a surface that pins
    /// `forced_provider` with an empty `allowed_providers` — e.g. a deployment override — got a router
    /// registering EVERY configured provider, not just the pinned one, contradicting this very module's
    /// documented promise that a disallowed provider is "never registered ... structural, not
    /// advisory"). Both `provider_allowed` below and the daemon's router-narrowing now call this ONE
    /// predicate, so there is exactly one enforcement decision, not two hand-maintained copies.
    pub fn is_provider_admissible(
        forced_provider: Option<&str>,
        allowed_providers: &[String],
        provider_id: &str,
    ) -> bool {
        if let Some(forced) = forced_provider {
            return provider_id == forced;
        }
        if allowed_providers.is_empty() {
            return true;
        }
        allowed_providers.iter().any(|p| p == provider_id)
    }

    /// Whether a candidate provider id is permitted by this surface's model policy. Thin wrapper over
    /// the pure [`is_provider_admissible`](Self::is_provider_admissible) predicate over this plan's own
    /// `forced_provider`/`allowed_providers` fields — see that function's doc for the full contract.
    pub fn provider_allowed(&self, provider_id: &str) -> bool {
        Self::is_provider_admissible(
            self.forced_provider.as_deref(),
            &self.allowed_providers,
            provider_id,
        )
    }

    /// Filter an ordered candidate provider list down to the surface's admissible set, preserving
    /// order. The composition binary applies this to the router's data-class-eligible chain so the
    /// profile's provider allow-list / forced pin is honored (gap SURF-06) — the engine's router has
    /// no allow-list of its own, so this is the enforcement seam until the router intersects it.
    pub fn admissible_providers<'b>(&self, candidates: &[&'b str]) -> Vec<&'b str> {
        candidates
            .iter()
            .copied()
            .filter(|id| self.provider_allowed(id))
            .collect()
    }

    /// The per-turn **surface action decision** for a candidate tool/connector capability (gap SURF:
    /// non-chat surfaces execute their declared capabilities/connectors/autonomy). This is the
    /// enforcement contract the served path applies to every proposed side-effecting action, composing
    /// the surface's two orthogonal controls:
    ///
    /// 1. **capability scope** — the capability must be in [`effective_capabilities`] (the surface's
    ///    offered set ∩ the principal's RBAC). A capability the surface does not offer — or that the
    ///    principal does not hold — is [`Deny`](SurfaceToolDecision::Deny), regardless of autonomy;
    /// 2. **autonomy** — a `side_effecting` action is [`Deny`](SurfaceToolDecision::Deny) when the
    ///    surface is read-only/suggest (`!allow_side_effects`), [`RequireApproval`] when the surface is
    ///    act-with-approval, and [`Allow`] when autonomous. A read-only action (`side_effecting=false`)
    ///    is allowed as long as it is in scope.
    ///
    /// Fail-closed and least-privilege: a surface can never escalate the principal, and autonomy can
    /// only ever *narrow* what an in-scope capability may do. The caller (engine tool dispatch / the
    /// approval gate) is the enforcement point; this method is the single source of truth for the
    /// decision.
    ///
    /// [`effective_capabilities`]: TurnPlan::effective_capabilities
    /// [`RequireApproval`]: SurfaceToolDecision::RequireApproval
    /// [`Allow`]: SurfaceToolDecision::Allow
    pub fn authorize_tool(&self, capability: &str, side_effecting: bool) -> SurfaceToolDecision {
        if !self.effective_capabilities.iter().any(|c| c == capability) {
            return SurfaceToolDecision::Deny(format!(
                "capability '{capability}' is not offered by this surface (or not held by the principal)"
            ));
        }
        if side_effecting {
            if !self.allow_side_effects {
                return SurfaceToolDecision::Deny(format!(
                    "capability '{capability}' is side-effecting but this surface is read-only"
                ));
            }
            if self.require_approval {
                return SurfaceToolDecision::RequireApproval;
            }
        }
        SurfaceToolDecision::Allow
    }

    /// Whether this surface DECLARES a connector id (its offered connector set). A connector is only
    /// reachable when the surface offers it AND the principal holds the matching `connector.<id>`
    /// capability — call [`authorize_tool`](Self::authorize_tool) with `connector.<id>` for the full
    /// decision. This is the offered-set predicate for the connector half of "execute declared
    /// capabilities/connectors".
    pub fn offers_connector(&self, connector_id: &str) -> bool {
        self.connectors.iter().any(|c| c == connector_id)
    }

    /// The active **prompt-policy directives** for this surface: the human-readable, model-agnostic
    /// statements of the profile's numeric discipline (BH), output format, and autonomy posture that
    /// [`to_request`](Self::to_request) composes into the `## Surface Policy` block. Empty when every
    /// policy is at its default (numeric=allow, format=markdown, autonomous) — so a fully-default
    /// surface adds nothing to the prompt. Exposed so a renderer/test can assert exactly which policy
    /// reaches the model.
    pub fn surface_policy_directives(&self) -> Vec<String> {
        let mut d = Vec::new();
        if self.numeric == NumericPolicy::ToolsOnly {
            d.push(
                "Every numeric or tabular figure MUST be produced by a tool; never estimate, \
                 round, or compute numbers yourself."
                    .to_string(),
            );
        }
        match self.format {
            OutputFormat::Json => {
                d.push("Respond with valid JSON only — no prose and no code fences.".to_string())
            }
            OutputFormat::Prose => {
                d.push("Respond in plain prose without Markdown formatting.".to_string())
            }
            OutputFormat::Markdown => {}
        }
        if !self.allow_side_effects {
            d.push(
                "This surface is read-only: do not perform any side-effecting action; answer only."
                    .to_string(),
            );
        } else if self.require_approval {
            d.push(
                "Side-effecting actions require explicit human approval before they may run."
                    .to_string(),
            );
        }
        d
    }

    /// Map this plan onto the engine's [`ainxt_protocol::Request`] — the concrete profile→runtime
    /// consumption adapter (gap SURF-01/08). The composition binary calls this to turn a bound plan
    /// into the engine's turn input, so the profile's routing policy is no longer dead at runtime:
    ///
    /// - `data_class` and `tier` (depth-vs-floor resolved) drive routing;
    /// - `forced_provider` pins the provider (still data-class gated by the engine);
    /// - the assembled system prompt + `## Context` block are prepended to the user turn so the
    ///   persona / behavioral skills / guard prompts / execution-skill output actually reach the
    ///   model (a bare [`ainxt_protocol::Request`] has no system-prompt field).
    ///
    /// `untrusted_tainted` is left `false`; a caller that runs retrieval sets it from the injection
    /// scan of the retrieved chunks (the convo layer already does this on the chat path).
    pub fn to_request(
        &self,
        session: &str,
        turn: &str,
        user_input: &str,
    ) -> ainxt_protocol::Request {
        let mut segments: Vec<String> = Vec::new();
        if !self.system_prompt.trim().is_empty() {
            segments.push(self.system_prompt.trim().to_string());
        }
        if !self.context_block.trim().is_empty() {
            segments.push(self.context_block.trim().to_string());
        }
        // Gap SURF: the profile's prompt policy (numeric discipline BH, output format, autonomy
        // posture) is enforced MODEL-AGNOSTICALLY on the served path by composing it into the prompt
        // as an explicit `## Surface Policy` block — so a non-chat surface actually carries its
        // declared numeric/output/autonomy policy to whatever provider the router picks (Claude / GPT
        // / local), not just as a dead field. This is additive to the engine's hard gates (the numeric
        // re-derivation verifier, the approval gate, the surface authorizer): a directive is defense-
        // in-depth, never the only enforcement. Omitted entirely when every policy is at its default
        // (the plain chat surface adds only the read-only line).
        let directives = self.surface_policy_directives();
        if !directives.is_empty() {
            let mut block = String::from("## Surface Policy");
            for d in &directives {
                block.push_str("\n- ");
                block.push_str(d);
            }
            segments.push(block);
        }
        segments.push(user_input.to_string());
        let input = segments.join("\n\n");

        let mut req = ainxt_protocol::Request::chat(session, turn, &input, self.data_class);
        req.tier = self.tier;
        req.forced_provider = self.forced_provider.clone();
        // R15 COMPOSE — hand the surface's hard tier pin (if any) straight to the engine's HARD tier
        // filter. `None` (the default) leaves the turn unpinned: the engine's in-engine complexity
        // classifier derives the tier and uses it only as a soft, escalatable preference.
        req.pinned_tier = self.pinned_tier;
        // GAP-FIX surfaces-profiles-skills-config — `history_budget_tokens` was computed on every
        // bound plan but never reached the engine: the conversation layer always assembled history
        // against its own hardcoded default budget, so a surface's declared context/history policy
        // was dead at runtime. Carry it onto the Request so `ainxt_convo::ConversationManager`'s
        // served turn handling can override its default `PromptDeployment::budget_tokens` per-turn.
        req.history_budget_tokens = Some(self.history_budget_tokens);
        // Carry the RAW user turn separately: `input` above is now a COMPOSED prompt (persona +
        // guard + context + user), and intent classification / referent resolution must run on the
        // user's own words, never on the composed blob (a guard line like "make a PDF …" must not
        // hijack the intent). The downstream conversation layer reads `Request::user_turn`.
        req.user_turn = Some(user_input.to_string());
        req
    }
}

/// The decision for one proposed tool/connector action under a surface (see
/// [`TurnPlan::authorize_tool`]). Ordered by increasing permissiveness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SurfaceToolDecision {
    /// The action is refused (out of the surface's offered scope, not held by the principal, or a
    /// side-effecting action on a read-only surface). Carries a non-sensitive reason.
    Deny(String),
    /// The action may run only after clearing the approval gate (HITL) — an act-with-approval surface.
    RequireApproval,
    /// The action may run without per-action approval (still subject to the engine's other gates).
    Allow,
}

impl SurfaceToolDecision {
    /// Whether the action may proceed at all (allowed outright OR after approval).
    pub fn is_permitted(&self) -> bool {
        !matches!(self, SurfaceToolDecision::Deny(_))
    }
    /// Whether the action must clear the approval gate first.
    pub fn needs_approval(&self) -> bool {
        matches!(self, SurfaceToolDecision::RequireApproval)
    }
}

/// Why a turn could not be planned under a surface. Fail-closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingError {
    /// The principal's role is below the surface's floor.
    RoleTooLow { required: Role, actual: Role },
    /// The principal lacks a capability the surface requires.
    MissingCap(String),
    /// The turn's data class exceeds the surface's ceiling (ADR-012).
    DataClassExceeded { data: DataClass, ceiling: DataClass },
    /// The surface is department-scoped but the principal has no department to scope by. Fail-closed:
    /// an unscoped principal must not silently see department-scoped data.
    DepartmentRequired,
    /// GAP-AUDIT surfaces-profiles-skills-config #3 — the surface has an AD seniority ceiling
    /// (`rbac.max_ad_level`) and the principal is either too junior (`ad_level > ceiling`) or
    /// carries no `ad_level` claim at all (fail-closed: never admitted by omission).
    SeniorityRequired {
        max_ad_level: u8,
        actual: Option<u8>,
    },
    /// A referenced skill failed to prepare.
    Skill(SkillError),
    /// A per-request config-override layer (`request` rung of the 5-layer chain) failed to resolve
    /// or attempted to widen the surface's authority — see
    /// [`SurfaceProfile::with_request_layer`](ainxt_profile::SurfaceProfile::with_request_layer).
    RequestOverride(ProfileError),
}

impl std::fmt::Display for BindingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BindingError::RoleTooLow { required, actual } => {
                write!(f, "role {actual:?} is below the surface floor {required:?}")
            }
            BindingError::MissingCap(c) => write!(f, "principal lacks required capability '{c}'"),
            BindingError::DataClassExceeded { data, ceiling } => write!(
                f,
                "data class '{}' exceeds the surface ceiling '{}'",
                data.as_str(),
                ceiling.as_str()
            ),
            BindingError::DepartmentRequired => write!(
                f,
                "surface is department-scoped but the principal has no department"
            ),
            BindingError::SeniorityRequired {
                max_ad_level,
                actual,
            } => write!(
                f,
                "surface requires ad_level <= {max_ad_level}, principal has {actual:?}"
            ),
            BindingError::Skill(e) => write!(f, "{e}"),
            BindingError::RequestOverride(e) => write!(f, "request config override: {e}"),
        }
    }
}
impl std::error::Error for BindingError {}

fn role_rank(role: Role) -> u8 {
    match role {
        Role::User => 0,
        Role::Admin => 1,
    }
}

/// Ordinal rank of a routing tier (Simple < Medium < Complex). `Tier` has no `Ord`, so the binding
/// keeps its own total order for the "never below the surface floor" rule.
fn tier_rank(t: Tier) -> u8 {
    match t {
        Tier::Simple => 0,
        Tier::Medium => 1,
        Tier::Complex => 2,
    }
}

/// The higher of two tiers.
fn max_tier(a: Tier, b: Tier) -> Tier {
    if tier_rank(a) >= tier_rank(b) {
        a
    } else {
        b
    }
}

fn map_numeric(p: NumericPref) -> NumericPolicy {
    match p {
        NumericPref::Allow => NumericPolicy::Allow,
        NumericPref::ToolsOnly => NumericPolicy::ToolsOnly,
    }
}

fn map_format(p: OutputPref) -> OutputFormat {
    match p {
        OutputPref::Text => OutputFormat::Prose,
        OutputPref::Markdown => OutputFormat::Markdown,
        OutputPref::Json => OutputFormat::Json,
    }
}

/// Binds a profile + skill runtime, and plans turns for principals.
pub struct SurfaceBinding<'a> {
    profile: &'a SurfaceProfile,
    skills: &'a SkillRuntime,
    classifier: Box<dyn ComplexityClassifier>,
}

impl<'a> SurfaceBinding<'a> {
    /// Bind with the default heuristic depth classifier (used when the profile's reasoning is `Auto`).
    pub fn new(profile: &'a SurfaceProfile, skills: &'a SkillRuntime) -> Self {
        SurfaceBinding {
            profile,
            skills,
            classifier: Box::new(HeuristicComplexity),
        }
    }

    /// Override the depth classifier (e.g. a model-backed one).
    pub fn with_classifier(mut self, classifier: Box<dyn ComplexityClassifier>) -> Self {
        self.classifier = classifier;
        self
    }

    /// Check the principal against the surface's RBAC floor (role + required caps). Fail-closed.
    ///
    /// Test-only convenience: the served path always calls [`plan`](Self::plan) /
    /// [`plan_with_request_override`](Self::plan_with_request_override), which run the identical check
    /// via [`admit_profile`](Self::admit_profile) (against the request-adjusted profile). Delegates to
    /// it here too so the RBAC-floor decision has exactly one implementation, not two hand-maintained
    /// copies that could silently drift apart.
    pub fn admit(&self, principal: &Principal) -> Result<(), BindingError> {
        Self::admit_profile(self.profile, principal)
    }

    /// Resolve the reasoning depth for `user_input` under `profile`'s preference.
    fn resolve_depth(&self, profile: &SurfaceProfile, user_input: &str) -> ReasoningDepth {
        match profile.prompt.reasoning {
            ReasoningPref::Auto => self.classifier.depth(user_input),
            ReasoningPref::Shallow => ReasoningDepth::Shallow,
            ReasoningPref::Standard => ReasoningDepth::Standard,
            ReasoningPref::Deep => ReasoningDepth::Deep,
        }
    }

    /// Plan one turn: admit, check the data-class ceiling, assemble prompt + context, and resolve the
    /// model/autonomy/retrieval policy into a [`TurnPlan`].
    pub fn plan(
        &self,
        principal: &Principal,
        user_input: &str,
        data_class: DataClass,
        guard_prompts: &[String],
    ) -> Result<TurnPlan, BindingError> {
        self.plan_with_request_override(principal, user_input, data_class, guard_prompts, None)
    }

    /// Like [`plan`](Self::plan), but additionally applies a per-turn **`request`** config-override
    /// layer (the final rung of the `defaults → deployment → tenant → profile → request` chain,
    /// ADR-004) before planning — the gap this closes: "per-request runtime-config override layer
    /// applied at turn time". `request_override` is raw TOML (`None`/empty = byte-identical to
    /// [`plan`](Self::plan)); it is resolved via
    /// [`SurfaceProfile::with_request_layer`](ainxt_profile::SurfaceProfile::with_request_layer),
    /// which enforces the SAFETY-INVARIANT that a request can only narrow the bound profile, never
    /// widen it (RBAC/capabilities/connectors/autonomy/retrieval/data-class ceiling/allow-list are all
    /// pinned; only prompt-policy preferences, the routing-tier floor, and an allow-listed provider
    /// choice may move). A merge/widening failure is [`BindingError::RequestOverride`] and the turn is
    /// refused BEFORE any admission check runs against the (rejected) override — fail-closed.
    pub fn plan_with_request_override(
        &self,
        principal: &Principal,
        user_input: &str,
        data_class: DataClass,
        guard_prompts: &[String],
        request_override: Option<&str>,
    ) -> Result<TurnPlan, BindingError> {
        let owned = match request_override {
            Some(src) if !src.trim().is_empty() => Some(
                self.profile
                    .with_request_layer(src)
                    .map_err(BindingError::RequestOverride)?,
            ),
            _ => None,
        };
        let profile: &SurfaceProfile = owned.as_ref().unwrap_or(self.profile);

        Self::admit_profile(profile, principal)?;

        let ceiling = profile.model_policy.max_data_class;
        if data_class.sensitivity() > ceiling.sensitivity() {
            return Err(BindingError::DataClassExceeded {
                data: data_class,
                ceiling,
            });
        }

        let effective_capabilities: Vec<String> = profile
            .capabilities
            .iter()
            .filter(|c| principal.has_cap(c))
            .cloned()
            .collect();

        let prepared = self
            .skills
            .prepare(&profile.skills, user_input)
            .map_err(BindingError::Skill)?;
        let system_prompt = SkillRuntime::system_prompt(&profile.persona, &prepared, guard_prompts);
        let context_block = prepared.context_block();

        let reasoning_depth = self.resolve_depth(profile, user_input);
        let default_tier = profile.model_policy.default_tier;
        // R15 COMPOSE (§4.1 step 1): a HARD-pinned surface never escalates OR falls through — it
        // always routes at exactly `default_tier`, through the engine's hard tier filter (fail-closed
        // if no eligible model exists at that tier). An unpinned surface keeps the pre-existing
        // soft-floor semantics: route by depth, but never below the surface's declared floor.
        let pin_tier = profile.model_policy.pin_tier;
        let tier = if pin_tier {
            default_tier
        } else {
            max_tier(reasoning_depth.tier(), default_tier)
        };
        let pinned_tier = if pin_tier { Some(default_tier) } else { None };

        // Admission guarantees a department-scoped surface has a department to scope by.
        let department_scope = if profile.rbac.department_scoped {
            principal.department.clone()
        } else {
            None
        };

        Ok(TurnPlan {
            system_prompt,
            context_block,
            effective_capabilities,
            connectors: profile.connectors.clone(),
            reasoning_depth,
            tier,
            default_tier,
            pinned_tier,
            numeric: map_numeric(profile.prompt.numeric),
            format: map_format(profile.prompt.output),
            forced_provider: profile.model_policy.forced_provider.clone(),
            allowed_providers: profile.model_policy.allowed_providers.clone(),
            data_class,
            max_data_class: profile.model_policy.max_data_class,
            allow_side_effects: profile.allows_side_effects(),
            require_approval: profile.requires_approval(),
            retrieval: profile.context.retrieval,
            department_scope,
            history_budget_tokens: profile.context.history_budget_tokens,
            condenser: profile.context.condenser,
        })
    }

    /// [`admit`](Self::admit) against an arbitrary profile reference (used by
    /// [`plan_with_request_override`](Self::plan_with_request_override) so admission is checked
    /// against the request-adjusted profile — though the safety invariant guarantees `rbac` is always
    /// identical to `self.profile.rbac`, so behavior is unchanged whichever one is passed).
    fn admit_profile(profile: &SurfaceProfile, principal: &Principal) -> Result<(), BindingError> {
        let required = profile.rbac.min_role;
        if role_rank(principal.role) < role_rank(required) {
            return Err(BindingError::RoleTooLow {
                required,
                actual: principal.role,
            });
        }
        for cap in &profile.rbac.required_caps {
            if !principal.has_cap(cap) {
                return Err(BindingError::MissingCap(cap.clone()));
            }
        }
        if profile.rbac.department_scoped && principal.department.is_none() {
            return Err(BindingError::DepartmentRequired);
        }
        if let Some(max) = profile.rbac.max_ad_level {
            if principal.ad_level.is_none_or(|lvl| lvl > max) {
                return Err(BindingError::SeniorityRequired {
                    max_ad_level: max,
                    actual: principal.ad_level,
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ainxt_skill::{NoExecutor, SkillManifest, SkillRegistry, SkillRuntime};

    fn skills() -> SkillRuntime {
        let mut r = SkillRegistry::new();
        r.register(SkillManifest::behavioral(
            "sop",
            "Follow the RCA procedure.",
        ));
        SkillRuntime::new(r, Box::new(NoExecutor))
    }

    fn profile(toml: &str) -> SurfaceProfile {
        SurfaceProfile::from_toml(toml).unwrap()
    }

    #[test]
    fn admit_enforces_role_floor() {
        let p = profile("id=\"admin-surface\"\n[rbac]\nmin_role=\"admin\"");
        let sk = skills();
        let b = SurfaceBinding::new(&p, &sk);
        assert!(b.admit(&Principal::admin("root")).is_ok());
        let err = b.admit(&Principal::user("u", &[])).unwrap_err();
        assert!(matches!(err, BindingError::RoleTooLow { .. }));
    }

    #[test]
    fn admit_enforces_required_caps() {
        let p = profile("id=\"s\"\n[rbac]\nrequired_caps=[\"chat.send\"]");
        let sk = skills();
        let b = SurfaceBinding::new(&p, &sk);
        assert!(b.admit(&Principal::user("u", &["chat.send"])).is_ok());
        assert_eq!(
            b.admit(&Principal::user("u", &[])).unwrap_err(),
            BindingError::MissingCap("chat.send".to_string())
        );
        // Admin implies all caps.
        assert!(b.admit(&Principal::admin("root")).is_ok());
    }

    #[test]
    fn data_class_ceiling_is_enforced() {
        let p = profile("id=\"chat\"\n[model_policy]\nmax_data_class=\"internal\"");
        let sk = skills();
        let b = SurfaceBinding::new(&p, &sk);
        let user = Principal::user("u", &[]);
        // At/below ceiling is fine.
        assert!(b.plan(&user, "hi", DataClass::Public, &[]).is_ok());
        // Above ceiling is refused.
        let err = b
            .plan(&user, "hi", DataClass::RegulatedPayment, &[])
            .unwrap_err();
        assert!(matches!(err, BindingError::DataClassExceeded { .. }));
    }

    #[test]
    fn effective_capabilities_intersect_principal() {
        let p = profile("id=\"code\"\ncapabilities=[\"tool.grep\",\"tool.edit\",\"tool.delete\"]");
        let sk = skills();
        let b = SurfaceBinding::new(&p, &sk);
        // A user with only two of the three offered caps.
        let user = Principal::user("u", &["tool.grep", "tool.edit"]);
        let plan = b.plan(&user, "find X", DataClass::Public, &[]).unwrap();
        assert_eq!(
            plan.effective_capabilities,
            vec!["tool.grep".to_string(), "tool.edit".to_string()]
        );
        // Admin gets the full offered set (has_cap always true).
        let plan_admin = b
            .plan(&Principal::admin("root"), "x", DataClass::Public, &[])
            .unwrap();
        assert_eq!(plan_admin.effective_capabilities.len(), 3);
    }

    #[test]
    fn autonomy_maps_to_action_policy() {
        let sk = skills();
        let ro = profile("id=\"chat\"\nautonomy=\"read-only\"");
        let plan = SurfaceBinding::new(&ro, &sk)
            .plan(&Principal::user("u", &[]), "x", DataClass::Public, &[])
            .unwrap();
        assert!(!plan.allow_side_effects && !plan.require_approval);

        let hitl = profile("id=\"sdlc\"\nautonomy=\"act-with-approval\"");
        let plan = SurfaceBinding::new(&hitl, &sk)
            .plan(&Principal::user("u", &[]), "x", DataClass::Public, &[])
            .unwrap();
        assert!(plan.allow_side_effects && plan.require_approval);

        let auto = profile("id=\"agent\"\nautonomy=\"autonomous\"");
        let plan = SurfaceBinding::new(&auto, &sk)
            .plan(&Principal::user("u", &[]), "x", DataClass::Public, &[])
            .unwrap();
        assert!(plan.allow_side_effects && !plan.require_approval);
    }

    #[test]
    fn reasoning_auto_classifies_but_fixed_is_honored() {
        let sk = skills();
        let auto = profile("id=\"chat\"\n[prompt]\nreasoning=\"auto\"");
        let b = SurfaceBinding::new(&auto, &sk);
        // A greeting classifies Shallow → Simple tier; a "why" query classifies Deep → Complex.
        assert_eq!(
            b.plan(&Principal::user("u", &[]), "hi", DataClass::Public, &[])
                .unwrap()
                .tier,
            Tier::Simple
        );
        let deep = b
            .plan(
                &Principal::user("u", &[]),
                "why did settlement fail?",
                DataClass::Public,
                &[],
            )
            .unwrap();
        assert_eq!(deep.reasoning_depth, ReasoningDepth::Deep);
        assert_eq!(deep.tier, Tier::Complex);

        // A fixed depth ignores the query.
        let fixed = profile("id=\"chat\"\n[prompt]\nreasoning=\"deep\"");
        let plan = SurfaceBinding::new(&fixed, &sk)
            .plan(&Principal::user("u", &[]), "hi", DataClass::Public, &[])
            .unwrap();
        assert_eq!(plan.reasoning_depth, ReasoningDepth::Deep);
    }

    #[test]
    fn prompt_prefs_and_provider_are_mapped() {
        let sk = skills();
        let p = profile(
            "id=\"pay\"\n[model_policy]\nforced_provider=\"claude\"\n[prompt]\nnumeric=\"tools-only\"\noutput=\"json\"",
        );
        let plan = SurfaceBinding::new(&p, &sk)
            .plan(&Principal::user("u", &[]), "x", DataClass::Public, &[])
            .unwrap();
        assert_eq!(plan.numeric, NumericPolicy::ToolsOnly);
        assert_eq!(plan.format, OutputFormat::Json);
        assert_eq!(plan.forced_provider.as_deref(), Some("claude"));
    }

    #[test]
    fn system_prompt_assembles_persona_behavioral_guard() {
        let sk = skills();
        let p = profile("id=\"sdlc\"\npersona=\"You are the SDLC assistant.\"\nskills=[\"sop\"]");
        let plan = SurfaceBinding::new(&p, &sk)
            .plan(
                &Principal::user("u", &[]),
                "x",
                DataClass::Public,
                &["Never leak secrets.".to_string()],
            )
            .unwrap();
        let persona_at = plan.system_prompt.find("SDLC assistant").unwrap();
        let behavioral_at = plan.system_prompt.find("RCA procedure").unwrap();
        let guard_at = plan.system_prompt.find("Never leak secrets").unwrap();
        assert!(persona_at < behavioral_at && behavioral_at < guard_at);
    }

    #[test]
    fn missing_skill_ref_surfaces_as_binding_error() {
        let sk = skills();
        let p = profile("id=\"x\"\nskills=[\"ghost\"]");
        let err = SurfaceBinding::new(&p, &sk)
            .plan(&Principal::user("u", &[]), "x", DataClass::Public, &[])
            .unwrap_err();
        assert!(matches!(err, BindingError::Skill(_)));
    }

    #[test]
    fn retrieval_scope_is_carried() {
        let sk = skills();
        let p = profile("id=\"proj\"\n[context]\nretrieval=\"repo-scoped\"");
        let plan = SurfaceBinding::new(&p, &sk)
            .plan(&Principal::user("u", &[]), "x", DataClass::Public, &[])
            .unwrap();
        assert_eq!(plan.retrieval, RetrievalScope::RepoScoped);
    }

    #[test]
    fn default_tier_is_a_floor_that_depth_can_raise_but_not_lower() {
        let sk = skills();
        // Surface floor = Complex, adaptive depth. A trivial "hi" would classify Shallow → Simple,
        // but the floor keeps it at Complex.
        let p = profile(
            "id=\"sdlc\"\n[model_policy]\ndefault_tier=\"complex\"\n[prompt]\nreasoning=\"auto\"",
        );
        let b = SurfaceBinding::new(&p, &sk);
        let plan = b
            .plan(&Principal::user("u", &[]), "hi", DataClass::Public, &[])
            .unwrap();
        assert_eq!(plan.reasoning_depth, ReasoningDepth::Shallow);
        assert_eq!(plan.default_tier, Tier::Complex);
        assert_eq!(plan.tier, Tier::Complex, "floor must not be undercut");

        // Surface floor = Simple; a hard query raises the effective tier above the floor.
        let p2 = profile(
            "id=\"chat\"\n[model_policy]\ndefault_tier=\"simple\"\n[prompt]\nreasoning=\"auto\"",
        );
        let plan2 = SurfaceBinding::new(&p2, &sk)
            .plan(
                &Principal::user("u", &[]),
                "why did the settlement batch fail?",
                DataClass::Public,
                &[],
            )
            .unwrap();
        assert_eq!(
            plan2.tier,
            Tier::Complex,
            "a hard query raises above the floor"
        );
    }

    #[test]
    fn department_scoped_admit_refuses_unscoped_and_plan_carries_scope() {
        let sk = skills();
        let p = profile("id=\"s\"\n[rbac]\ndepartment_scoped=true");
        let b = SurfaceBinding::new(&p, &sk);
        // No department → refused.
        assert_eq!(
            b.admit(&Principal::user("u", &[])).unwrap_err(),
            BindingError::DepartmentRequired
        );
        // With a department → admitted, and the scope reaches the plan.
        let scoped = Principal::user("u", &[]).with_department("cards");
        let plan = b.plan(&scoped, "x", DataClass::Public, &[]).unwrap();
        assert_eq!(plan.department_scope.as_deref(), Some("cards"));

        // A non-scoped surface never sets a department scope, even for a principal that has one.
        let open = profile("id=\"s\"");
        let plan2 = SurfaceBinding::new(&open, &sk)
            .plan(&scoped, "x", DataClass::Public, &[])
            .unwrap();
        assert_eq!(plan2.department_scope, None);
    }

    #[test]
    fn gap_surf_03_max_ad_level_ceiling_admits_only_senior_enough_principals() {
        // GAP-AUDIT surfaces-profiles-skills-config #3: a surface can be restricted by role and
        // department, but until now had no way to say "exec-only" — an AD seniority ceiling, the
        // same shape Context-Fabric's per-node `NodeAcl::max_ad_level` already enforces.
        let sk = skills();
        let p = profile("id=\"exec-briefing\"\n[rbac]\nmax_ad_level=2");
        let b = SurfaceBinding::new(&p, &sk);

        // No ad_level claim at all → fail-closed refused, never admitted by omission.
        let no_claim = Principal::user("u", &[]);
        assert_eq!(
            b.admit(&no_claim).unwrap_err(),
            BindingError::SeniorityRequired {
                max_ad_level: 2,
                actual: None
            }
        );

        // Too junior (ad_level=4 > ceiling=2) → refused.
        let junior = Principal::user("u", &[]).with_ad_level(4);
        assert_eq!(
            b.admit(&junior).unwrap_err(),
            BindingError::SeniorityRequired {
                max_ad_level: 2,
                actual: Some(4)
            }
        );

        // Senior enough (ad_level=2 == ceiling) → admitted.
        let exactly_at_ceiling = Principal::user("u", &[]).with_ad_level(2);
        assert!(b.admit(&exactly_at_ceiling).is_ok());

        // More senior than the ceiling (ad_level=0, most senior) → admitted.
        let very_senior = Principal::user("u", &[]).with_ad_level(0);
        assert!(b.admit(&very_senior).is_ok());

        // A surface with no ceiling admits any/no ad_level (byte-identical pre-existing behavior).
        let open = profile("id=\"s\"");
        assert!(SurfaceBinding::new(&open, &sk).admit(&no_claim).is_ok());
    }

    #[test]
    fn gap_ainxt_surface_surf_06_model_policy_provider_allow_list_is_enforced() {
        let sk = skills();

        // No forced provider, empty allow-list → any provider is admissible.
        let open = profile("id=\"chat\"");
        let plan = SurfaceBinding::new(&open, &sk)
            .plan(&Principal::user("u", &[]), "x", DataClass::Public, &[])
            .unwrap();
        assert!(plan.provider_allowed("claude") && plan.provider_allowed("gpt"));
        assert_eq!(
            plan.admissible_providers(&["claude", "gpt", "gemini"]),
            vec!["claude", "gpt", "gemini"]
        );

        // A non-empty allow-list filters the router's candidate chain, preserving order.
        let allow = profile("id=\"pay\"\n[model_policy]\nallowed_providers=[\"claude\",\"gpt\"]");
        let plan = SurfaceBinding::new(&allow, &sk)
            .plan(&Principal::user("u", &[]), "x", DataClass::Public, &[])
            .unwrap();
        assert!(plan.provider_allowed("claude"));
        assert!(!plan.provider_allowed("gemini"), "not in allow-list");
        assert_eq!(
            plan.admissible_providers(&["gemini", "gpt", "claude"]),
            vec!["gpt", "claude"],
            "disallowed providers are dropped from the candidate chain"
        );

        // A forced provider pins the surface to exactly that provider.
        let forced = profile(
            "id=\"pay\"\n[model_policy]\nforced_provider=\"claude\"\nallowed_providers=[\"claude\",\"gpt\"]",
        );
        let plan = SurfaceBinding::new(&forced, &sk)
            .plan(&Principal::user("u", &[]), "x", DataClass::Public, &[])
            .unwrap();
        assert!(plan.provider_allowed("claude"));
        assert!(
            !plan.provider_allowed("gpt"),
            "a forced provider excludes every other provider, even allow-listed ones"
        );
        assert_eq!(
            plan.admissible_providers(&["gpt", "claude"]),
            vec!["claude"]
        );
    }

    #[test]
    fn gap_ainxt_surface_surf_01_plan_maps_onto_engine_request() {
        // The profile→runtime consumption adapter: a bound plan becomes a concrete engine Request,
        // carrying the surface's routing policy (tier floor + forced provider + data class) and the
        // assembled system prompt / ## Context so profile-declared policy is LIVE at runtime.
        let sk = skills();
        let p = profile(
            "id=\"sdlc\"\npersona=\"You are the SDLC assistant.\"\nskills=[\"sop\"]\n\
             [model_policy]\nforced_provider=\"claude\"\ndefault_tier=\"complex\"",
        );
        let plan = SurfaceBinding::new(&p, &sk)
            .plan(
                &Principal::user("u", &[]),
                "fix the settlement bug",
                DataClass::Internal,
                &["Never leak secrets.".to_string()],
            )
            .unwrap();

        let req = plan.to_request("sess-1", "turn-1", "fix the settlement bug");
        assert_eq!(req.session, "sess-1");
        assert_eq!(req.turn, "turn-1");
        assert_eq!(req.data_class, DataClass::Internal);
        assert_eq!(
            req.tier,
            Tier::Complex,
            "the surface tier floor reaches the request"
        );
        assert_eq!(
            req.forced_provider.as_deref(),
            Some("claude"),
            "the profile's forced provider reaches the router via the request"
        );
        // The assembled system prompt (persona + behavioral skill + guard) precedes the user turn.
        let persona_at = req.input.find("SDLC assistant").expect("persona in prompt");
        let behavioral_at = req
            .input
            .find("RCA procedure")
            .expect("behavioral skill in prompt");
        let guard_at = req
            .input
            .find("Never leak secrets")
            .expect("guard in prompt");
        let user_at = req
            .input
            .find("fix the settlement bug")
            .expect("user turn in prompt");
        assert!(persona_at < behavioral_at && behavioral_at < guard_at && guard_at < user_at);
        assert!(!req.untrusted_tainted);
    }

    #[test]
    fn gap_ainxt_surface_surf_01_context_block_reaches_the_request_input() {
        use ainxt_skill::{NativeSkill, NativeSkillExecutor, SkillInvocation};
        use std::sync::Arc;

        struct MetricsSkill;
        impl NativeSkill for MetricsSkill {
            fn run(&self, inv: &SkillInvocation<'_>) -> Result<String, String> {
                Ok(format!("tps=1200 for: {}", inv.user_input))
            }
        }
        let mut reg = SkillRegistry::new();
        reg.register(SkillManifest::execution("live-metrics", ""));
        let exec = NativeSkillExecutor::new().with("live-metrics", Arc::new(MetricsSkill));
        let sk = SkillRuntime::new(reg, Box::new(exec));

        let p = profile("id=\"ops\"\nskills=[\"live-metrics\"]");
        let plan = SurfaceBinding::new(&p, &sk)
            .plan(&Principal::user("u", &[]), "load?", DataClass::Public, &[])
            .unwrap();
        let req = plan.to_request("s", "t", "load?");
        assert!(
            req.input.contains("## Context") && req.input.contains("tps=1200 for: load?"),
            "execution-skill output must reach the engine request input: {}",
            req.input
        );
    }

    #[test]
    fn execution_skill_output_flows_into_the_plan_context_block() {
        use ainxt_skill::{NativeSkill, NativeSkillExecutor, SkillInvocation};
        use std::sync::Arc;

        struct MetricsSkill;
        impl NativeSkill for MetricsSkill {
            fn run(&self, inv: &SkillInvocation<'_>) -> Result<String, String> {
                Ok(format!("tps=1200 for query: {}", inv.user_input))
            }
        }

        let mut reg = SkillRegistry::new();
        reg.register(SkillManifest::execution("live-metrics", ""));
        let exec = NativeSkillExecutor::new().with("live-metrics", Arc::new(MetricsSkill));
        let sk = SkillRuntime::new(reg, Box::new(exec));

        let p = profile("id=\"ops\"\nskills=[\"live-metrics\"]");
        let plan = SurfaceBinding::new(&p, &sk)
            .plan(
                &Principal::user("u", &[]),
                "current load?",
                DataClass::Public,
                &[],
            )
            .unwrap();
        assert!(plan.context_block.starts_with("## Context"));
        assert!(
            plan.context_block
                .contains("tps=1200 for query: current load?"),
            "real execution-skill output must reach the plan: {}",
            plan.context_block
        );
    }

    // ==================== per-request override at plan-time (R15) ====================

    #[test]
    fn r15_none_or_empty_request_override_is_byte_identical_to_plan() {
        let sk = skills();
        let p = profile("id=\"chat\"\n[model_policy]\ndefault_tier=\"simple\"");
        let b = SurfaceBinding::new(&p, &sk);
        let via_plan = b
            .plan(&Principal::user("u", &[]), "hi", DataClass::Public, &[])
            .unwrap();
        let via_none = b
            .plan_with_request_override(
                &Principal::user("u", &[]),
                "hi",
                DataClass::Public,
                &[],
                None,
            )
            .unwrap();
        let via_empty = b
            .plan_with_request_override(
                &Principal::user("u", &[]),
                "hi",
                DataClass::Public,
                &[],
                Some("   "),
            )
            .unwrap();
        assert_eq!(via_plan, via_none);
        assert_eq!(via_plan, via_empty);
    }

    #[test]
    fn r15_request_override_reaches_the_turn_plan_tier_and_format() {
        let sk = skills();
        let p = profile(
            "id=\"chat\"\n[model_policy]\ndefault_tier=\"simple\"\n[prompt]\noutput=\"markdown\"",
        );
        let b = SurfaceBinding::new(&p, &sk);
        let plan = b
            .plan_with_request_override(
                &Principal::user("u", &[]),
                "hi",
                DataClass::Public,
                &[],
                Some("[model_policy]\ndefault_tier=\"complex\"\n[prompt]\noutput=\"json\""),
            )
            .unwrap();
        assert_eq!(plan.default_tier, Tier::Complex);
        assert_eq!(plan.tier, Tier::Complex);
        assert_eq!(plan.format, OutputFormat::Json);
    }

    #[test]
    fn r15_request_override_cannot_escalate_capabilities_or_autonomy_and_is_denied_before_admission(
    ) {
        let sk = skills();
        let p = profile(
            "id=\"chat\"\ncapabilities=[\"tool.grep\"]\nautonomy=\"read-only\"\n[rbac]\nmin_role=\"user\"",
        );
        let b = SurfaceBinding::new(&p, &sk);
        // A request trying to grant itself admin RBAC is refused with RequestOverride, not silently
        // honored and not misreported as a plain RoleTooLow (the merge itself is rejected up front).
        let err = b
            .plan_with_request_override(
                &Principal::user("u", &[]),
                "x",
                DataClass::Public,
                &[],
                Some("[rbac]\nmin_role=\"admin\""),
            )
            .unwrap_err();
        assert!(matches!(err, BindingError::RequestOverride(_)));

        let err2 = b
            .plan_with_request_override(
                &Principal::user("u", &["tool.grep"]),
                "x",
                DataClass::Public,
                &[],
                Some("autonomy=\"autonomous\""),
            )
            .unwrap_err();
        assert!(matches!(err2, BindingError::RequestOverride(_)));
    }

    #[test]
    fn r15_request_override_provider_choice_is_bounded_by_the_surfaces_own_allow_list() {
        let sk = skills();
        let p = profile("id=\"pay\"\n[model_policy]\nallowed_providers=[\"claude\",\"gpt\"]");
        let b = SurfaceBinding::new(&p, &sk);
        // Within the allow-list: honored.
        let plan = b
            .plan_with_request_override(
                &Principal::user("u", &[]),
                "x",
                DataClass::Public,
                &[],
                Some("[model_policy]\nforced_provider=\"gpt\""),
            )
            .unwrap();
        assert_eq!(plan.forced_provider.as_deref(), Some("gpt"));
        // Outside the allow-list: refused.
        let err = b
            .plan_with_request_override(
                &Principal::user("u", &[]),
                "x",
                DataClass::Public,
                &[],
                Some("[model_policy]\nforced_provider=\"gemini\""),
            )
            .unwrap_err();
        assert!(matches!(err, BindingError::RequestOverride(_)));
    }

    #[test]
    fn r15_request_override_data_class_still_gated_against_the_unwidened_ceiling() {
        let sk = skills();
        let p = profile("id=\"chat\"\n[model_policy]\nmax_data_class=\"internal\"");
        let b = SurfaceBinding::new(&p, &sk);
        // The request cannot raise the ceiling, so a regulated-payment turn is still refused even
        // with an (otherwise legitimate) request layer attached.
        let err = b
            .plan_with_request_override(
                &Principal::user("u", &[]),
                "x",
                DataClass::RegulatedPayment,
                &[],
                Some("[prompt]\noutput=\"json\""),
            )
            .unwrap_err();
        assert!(matches!(err, BindingError::DataClassExceeded { .. }));
    }
}
