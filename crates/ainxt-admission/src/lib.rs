// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! ainxt-admission — the admission + capability-permission core (Phase 5).
//!
//! # Naming (ADR-030)
//!
//! This crate was `ainxt-harness`. It was renamed because "harness" now has ONE
//! org-wide meaning — **a team's deployable bundle** authored in the Harness Factory
//! (skills + tools + wikis + trigger + eval set). This crate is not that. Its job is
//! ADMISSION and BUDGET: it decides whether a declared, engineer-authored
//! orchestration may run at all, and bounds what it may spend. It never executes —
//! "admission owns the gate, the engine owns execution".
//!
//! The `Harness*` types below (`HarnessManifest`, `HarnessStep`, `HarnessBudget`, …)
//! still carry the old prefix. That is a KNOWN, deliberate follow-up rather than an
//! oversight: renaming them touches ~170 references, six of which sit in another
//! workstream's in-flight code, so it is a coordination step and not a mechanical
//! one. Read them as "the submitted orchestration's manifest/step/budget", not as
//! anything to do with a Factory harness.
//!
//! Extensibility is a ladder: consume the SDK, configure declarative agents/skills, extend with
//! plugins, or compose a **harness** — a declared, configured agent experience over the runtime. This
//! crate is the harness layer, and its whole job is to run untrusted, engineer-authored
//! orchestrations **safely**:
//!
//! - **Least privilege.** A harness's effective authority is `requested ∩ granted ∩ principal`. It
//!   can never use a capability it didn't request, wasn't granted by governance, or the invoking
//!   user doesn't hold. Every step's capability is checked; an ungranted/unauthorized step is
//!   refused, fail-closed.
//! - **Data-class ceiling (ADR-026 / ADR-012).** A manifest declares the maximum data classification
//!   it may process ([`HarnessManifest::data_class_ceiling`]). A run whose turn carries a *more*
//!   sensitive class than the ceiling is refused before any step executes — a harness scoped to
//!   `internal` can never be handed a `regulated-payment`/`pii` turn.
//! - **Payment boundary (ADR-016 / ADR-026).** A manifest declares its live payment-rail access
//!   ([`PaymentBoundary`]: `none`/`read-only`/`write`). A step whose capability is a payment-rail
//!   call is gated against this boundary; a `payment_boundary: none` harness cannot touch a rail.
//! - **RBAC-on-execute (ADR-026).** Beyond the role floor, [`ExecuteRbac`] scopes *who may invoke*
//!   the harness by visibility (`public`/`department`/`private`) — a caller outside the scope is
//!   refused before the loop starts.
//! - **Hard budget.** Steps, tokens, and tool-calls are capped; exceeding any is a refusal, not a
//!   best-effort overrun. The manifest cannot raise its own cap past the governance grant.
//! - **Safety lives in the spine, not the harness.** The [`HarnessManifest`] schema has **no field**
//!   to disable compliance, RBAC, or audit (and `deny_unknown_fields` means a manifest can't smuggle
//!   one in). The capability-authz + audit seams are **required** constructor arguments. Compliance
//!   runs where the steps execute (the engine); the [`ComplianceStepExecutor`] seam makes that
//!   explicit for callers that execute steps outside the engine.
//!
//! The admission decision is exposed as a two-phase seam ([`HarnessRuntime::admit`] then
//! [`HarnessRuntime::gate_step`]) so an async driver (the SDK / `ainxt-client`) can bridge each
//! admitted step to a **real engine turn** — the harness owns *admission + budget*, the engine owns
//! *execution + compliance*. Pure and executor-agnostic, so every safety invariant is exhaustively
//! testable. Clean-room throughout.

use std::collections::BTreeSet;
use std::fmt;

use ainxt_runtime::compliance::{ComplianceGate, Direction};
use ainxt_types::{DataClass, Principal, Role};
use serde::{Deserialize, Serialize};

pub mod lint;
pub use lint::{lint_manifest, LintFinding};

// ============================ Manifest (declarative, ADR-026) ============================

/// The kind of a step (informational + drives the tool-call budget).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StepKind {
    /// A model call.
    Llm,
    /// A tool/function call (counts against the tool-call budget).
    Tool,
    /// A skill invocation.
    Skill,
}

/// A single declared step. It names the one capability it needs and an estimated token cost (used
/// for the pre-execution budget check). `input` is the optional prompt/argument an SDK driver feeds
/// to the engine turn for this step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HarnessStep {
    pub id: String,
    pub kind: StepKind,
    /// The capability this step requires (e.g. `tool.grep`, `connector.gitlab`, `llm.call`).
    pub capability: String,
    #[serde(default)]
    pub estimated_tokens: u64,
    /// Optional prompt/argument for this step (used by the SDK engine-turn bridge).
    #[serde(default)]
    pub input: Option<String>,
}

/// The hard resource budget for a harness run. Enforced by the runtime; a manifest cannot exceed
/// what governance grants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HarnessBudget {
    pub max_steps: u32,
    pub max_tokens: u64,
    pub max_tool_calls: u32,
}

impl Default for HarnessBudget {
    fn default() -> Self {
        HarnessBudget {
            max_steps: 16,
            max_tokens: 100_000,
            max_tool_calls: 8,
        }
    }
}

/// The RBAC floor to run the harness (role rank + capabilities the principal must hold).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HarnessRbac {
    pub min_role: Role,
    pub required_caps: Vec<String>,
}

impl Default for HarnessRbac {
    fn default() -> Self {
        HarnessRbac {
            min_role: Role::User,
            required_caps: Vec::new(),
        }
    }
}

/// Autonomy level (ADR-026): how much a harness may act without a human in the loop. Informational
/// to admission — the spine's HITL approval gate enforces the actual behavior — but linted and
/// carried so a renderer/policy engine can honor it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Autonomy {
    /// No autonomous action (suggest-only).
    #[default]
    None,
    /// HITL approval required on any write/side-effect.
    Assisted,
    /// Autonomous, judge-audited.
    Autonomous,
}

/// The live payment-rail access a harness declares (ADR-016 / ADR-026). Ordered least→most.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PaymentBoundary {
    /// No payment-rail access at all.
    #[default]
    None,
    /// May read a payment rail/ledger, never write.
    ReadOnly,
    /// May initiate/write on a payment rail.
    Write,
}

/// The access a specific capability requires against a payment rail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PaymentAccess {
    ReadOnly,
    Write,
}

impl PaymentBoundary {
    /// Whether this declared boundary permits a call requiring `access`.
    pub fn permits(self, access: PaymentAccess) -> bool {
        match (self, access) {
            (PaymentBoundary::None, _) => false,
            (PaymentBoundary::ReadOnly, PaymentAccess::ReadOnly) => true,
            (PaymentBoundary::ReadOnly, PaymentAccess::Write) => false,
            (PaymentBoundary::Write, _) => true,
        }
    }
}

/// Classifies whether a capability is a payment-rail call and what access it needs. A seam so a
/// deployment can plug in its real rail registry; the OSS default is a token-marker classifier.
pub trait PaymentRailClassifier: Send + Sync {
    fn classify(&self, capability: &str) -> Option<PaymentAccess>;
}

/// Deterministic marker classifier: a capability whose dotted/slashed segments include a rail marker
/// (`payment`, `settlement`, `neft`, `rtgs`, `upi`, `imps`, `ledger`, `rail`) is a payment-rail call;
/// a write verb segment (`initiate`, `transfer`, `pay`, `post`, `create`, `write`, `execute`,
/// `send`, `debit`, `credit`, `settle`) makes it a `Write`, otherwise `ReadOnly`.
pub struct MarkerPaymentRailClassifier;

impl PaymentRailClassifier for MarkerPaymentRailClassifier {
    fn classify(&self, capability: &str) -> Option<PaymentAccess> {
        const RAIL: &[&str] = &[
            "payment",
            "payments",
            "settlement",
            "settle",
            "rail",
            "rails",
            "neft",
            "rtgs",
            "upi",
            "imps",
            "ledger",
        ];
        const WRITE: &[&str] = &[
            "initiate", "transfer", "pay", "post", "create", "write", "execute", "send", "debit",
            "credit", "settle",
        ];
        let lower = capability.to_ascii_lowercase();
        let segs: Vec<&str> = lower
            .split(|c: char| !c.is_ascii_alphanumeric())
            .filter(|s| !s.is_empty())
            .collect();
        if !segs.iter().any(|s| RAIL.contains(s)) {
            return None;
        }
        if segs.iter().any(|s| WRITE.contains(s)) {
            Some(PaymentAccess::Write)
        } else {
            Some(PaymentAccess::ReadOnly)
        }
    }
}

// ============================ Autonomy / HITL side-effect classification ============================

/// Whether a capability performs a **write / external side-effect** (drives autonomy + HITL). A seam
/// so a deployment can plug its real capability registry; the OSS default is a verb-marker classifier.
pub trait SideEffectClassifier: Send + Sync {
    /// `true` if invoking `capability` writes or causes an external side-effect (vs a pure read).
    fn is_side_effect(&self, capability: &str) -> bool;
}

/// Deterministic marker classifier: a capability whose dotted/slashed segments include a write verb
/// (`write`, `create`, `update`, `delete`, `remove`, `send`, `post`, `put`, `patch`, `insert`, `drop`,
/// `initiate`, `transfer`, `pay`, `debit`, `credit`, `settle`, `execute`, `merge`, `deploy`, `publish`,
/// `edit`, `apply`, `commit`, `push`) is a side-effect. Pure reads (`search`, `query`, `read`, `get`,
/// `list`, `fetch`, `grep`, `scan`) are not — matching the design's read-only `connector.postgres.query`.
pub struct MarkerSideEffectClassifier;
impl SideEffectClassifier for MarkerSideEffectClassifier {
    fn is_side_effect(&self, capability: &str) -> bool {
        const WRITE: &[&str] = &[
            "write", "create", "update", "delete", "remove", "send", "post", "put", "patch",
            "insert", "drop", "initiate", "transfer", "pay", "debit", "credit", "settle",
            "execute", "merge", "deploy", "publish", "edit", "apply", "commit", "push",
        ];
        let lower = capability.to_ascii_lowercase();
        lower
            .split(|c: char| !c.is_ascii_alphanumeric())
            .filter(|s| !s.is_empty())
            .any(|s| WRITE.contains(&s))
    }
}

/// The autonomy decision for a single step (given the manifest's declared [`Autonomy`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutonomyDecision {
    /// The step may run without a human: a pure read, or `autonomy=autonomous` (judge-audited).
    Proceed,
    /// A write/side-effect under `autonomy=assisted` — a human must approve before it runs.
    NeedsApproval { step: String, capability: String },
    /// A write/side-effect under `autonomy=none` (suggest-only) — refused (terminal outcome carried).
    Refused(HarnessOutcome),
}

/// A pending HITL approval a harness raised for a write/side-effect step under `assisted` autonomy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRequest {
    pub harness: String,
    pub step: String,
    pub capability: String,
}

/// A human/policy decision on a pending approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalDecision {
    Approve,
    Reject(String),
}

/// The HITL back-channel seam: a human (or a policy) decides a pending write approval. MANDATORY for
/// `assisted` autonomy. The OSS default [`DenyingApprovalResolver`] fails closed (rejects everything),
/// so a deployment MUST wire a real approver (UI / approval queue) before assisted writes can proceed.
pub trait ApprovalResolver: Send + Sync {
    fn resolve(&self, request: &ApprovalRequest) -> ApprovalDecision;
}

/// Fail-closed default: rejects every approval (no human wired). An assisted-mode write cannot run.
pub struct DenyingApprovalResolver;
impl ApprovalResolver for DenyingApprovalResolver {
    fn resolve(&self, _r: &ApprovalRequest) -> ApprovalDecision {
        ApprovalDecision::Reject("no approver configured (fail-closed)".into())
    }
}

/// Always-approve resolver (dev / autonomous-with-audit test fixtures only — NEVER production).
pub struct AllowingApprovalResolver;
impl ApprovalResolver for AllowingApprovalResolver {
    fn resolve(&self, _r: &ApprovalRequest) -> ApprovalDecision {
        ApprovalDecision::Approve
    }
}

/// GAP-FIX harness-sdk-governance #2 — adapts a REAL, LIVE [`ainxt_runtime::approval::ApprovalGate`]
/// (e.g. the served daemon's `ainxt_server::WireApprovalGate`, or this SDK's own
/// `ainxt_client::WireApprovalGate` — both block on a human's decision delivered over their own
/// coordinator) into this crate's [`ApprovalResolver`] (the harness invoke path's HITL seam,
/// `invoke_with_approvals`/`invoke_from_surface`). Before this adapter the two traits were differently
/// shaped with zero connection between them, so every harness call site was stuck choosing between the
/// fail-closed [`DenyingApprovalResolver`] (no assisted-autonomy write can ever run) or the unsafe
/// [`AllowingApprovalResolver`] (dev-only) — there was no way to route a harness's pending write
/// approval to the SAME live human/wire mechanism already gating the engine's own risky tool calls.
///
/// The two request shapes do not line up 1:1: [`ainxt_runtime::approval::ApprovalRequest`] is
/// session-scoped (`session`/`actor`/`tool`/`args`, correlated by an engine turn's session id), while
/// this crate's [`ApprovalRequest`] is harness-scoped (`harness`/`step`/`capability`, no session — a
/// harness invoke is not necessarily inside an engine turn at all). This adapter is constructed with
/// the `session`/`actor` that correlate a *particular harness run* on whatever wire the underlying
/// gate polls (e.g. the invoking principal's user id, or a synthetic per-run id), and projects the
/// harness fields onto the gate's `tool`/`args` so the SAME approval UI a human already watches for
/// risky tool calls also raises harness write approvals, one real "ask a human" backing both seams.
pub struct RuntimeApprovalGateResolver {
    gate: std::sync::Arc<dyn ainxt_runtime::approval::ApprovalGate>,
    session: String,
    actor: String,
}

impl RuntimeApprovalGateResolver {
    /// Adapt `gate` into an [`ApprovalResolver`], correlating every request through it under
    /// `session`/`actor` (the caller picks values meaningful to the underlying gate's own
    /// correlation — e.g. the harness run's session id and the invoking principal's user id).
    pub fn new(
        gate: std::sync::Arc<dyn ainxt_runtime::approval::ApprovalGate>,
        session: impl Into<String>,
        actor: impl Into<String>,
    ) -> Self {
        RuntimeApprovalGateResolver {
            gate,
            session: session.into(),
            actor: actor.into(),
        }
    }
}

impl ApprovalResolver for RuntimeApprovalGateResolver {
    fn resolve(&self, request: &ApprovalRequest) -> ApprovalDecision {
        let runtime_req = ainxt_runtime::approval::ApprovalRequest {
            session: self.session.clone(),
            actor: self.actor.clone(),
            tool: format!("harness:{}:{}", request.harness, request.step),
            args: request.capability.clone(),
        };
        match self.gate.decide(&runtime_req) {
            // `ApproveForSession` has no analog in this crate's tri-state decision (a harness run has
            // no notion of "for the rest of the session") — collapse it to a one-time `Approve` rather
            // than inventing a wider grant this call never asked for.
            ainxt_runtime::approval::ApprovalDecision::Approve
            | ainxt_runtime::approval::ApprovalDecision::ApproveForSession => {
                ApprovalDecision::Approve
            }
            ainxt_runtime::approval::ApprovalDecision::Reject(reason) => {
                ApprovalDecision::Reject(reason)
            }
        }
    }
}

/// Who may invoke a harness (ADR-026 RBAC-on-execute).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Visibility {
    /// Any caller meeting the role/capability floor.
    #[default]
    Public,
    /// Only callers whose AD department matches [`ExecuteRbac::department`].
    Department,
    /// Only the owner (or an admin).
    Private,
}

/// RBAC-on-execute front-matter (ADR-026): visibility scoping + the least-privilege capability
/// permissions the Policy Engine must have granted. `department` is required for `Department`
/// visibility.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ExecuteRbac {
    pub visibility: Visibility,
    pub department: Option<String>,
    /// Declared capability permissions (least-privilege). Linted against `requested_capabilities`.
    pub permissions: Vec<String>,
}

/// A pinned dependency (ADR-026 `depends_on`): a `repo@tag@content_hash` ref this harness requires,
/// TOFU-verified against the marketplace on install.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedDep {
    pub repo: String,
    pub tag: String,
    pub content_hash: String,
}

/// Retrieval/context configuration for the harness (namespace / repo scope).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HarnessContext {
    pub namespace: Option<String>,
}

// ============================ Renderer (ADR-026 / HARNESS_SDK.md §1) ============================

/// The renderer a harness presents through (`HARNESS_SDK.md` §1: `renderer # default = chat; custom
/// renderer is Phase 5`). "Agent vs harness": an agent is a harness with the default chat renderer; a
/// harness can additionally BUNDLE its own renderer. This crate stays render-agnostic — it declares
/// and gates *which* renderer id a run requires, never the rendering logic itself (that is
/// `ainxt_surface`'s [`Renderer`](../ainxt_surface/artifact/trait.Renderer.html) trait / registry) —
/// so [`RendererResolver`] is the seam a caller wires its concrete registry through.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum HarnessRenderer {
    /// The default: standard chat/text-delta rendering every surface already understands.
    #[default]
    Chat,
    /// A named renderer id the harness BUNDLES (Phase 5) — must be registered with the caller's
    /// [`RendererResolver`] or the run is refused before any step executes (fail-closed: a harness
    /// cannot silently fall back to `chat` when it declared a custom renderer it did not actually
    /// bundle).
    Custom(String),
}

impl HarnessRenderer {
    /// The renderer id this variant names (`"chat"` for the default).
    pub fn id(&self) -> &str {
        match self {
            HarnessRenderer::Chat => "chat",
            HarnessRenderer::Custom(id) => id.as_str(),
        }
    }
}

/// Whether a named (bundled) renderer is actually available to render a harness's output. The
/// built-in `chat` renderer is always available by definition — this seam is consulted only for a
/// [`HarnessRenderer::Custom`] declaration. A deployment wires its real `ainxt_surface` renderer
/// registry behind this trait; the OSS defaults below cover "anything goes" (dev) and "nothing extra
/// is registered" (fail-closed) without pulling `ainxt_surface` into this crate (would be a cycle:
/// `ainxt_surface` sits above the harness layer).
pub trait RendererResolver: Send + Sync {
    fn is_available(&self, renderer_id: &str) -> bool;
}

/// Dev/default resolver: every custom renderer id is considered available. Suitable when no
/// renderer registry is wired yet (matches today's behavior — declaring a renderer was a no-op).
pub struct AnyRendererResolver;
impl RendererResolver for AnyRendererResolver {
    fn is_available(&self, _renderer_id: &str) -> bool {
        true
    }
}

/// A resolver backed by an explicit allow-set of bundled renderer ids — the fail-closed choice for a
/// deployment that wants an unregistered custom renderer to refuse admission rather than silently
/// falling back to `chat`.
#[derive(Debug, Clone, Default)]
pub struct RegisteredRendererResolver {
    available: BTreeSet<String>,
}
impl RegisteredRendererResolver {
    pub fn new<S: Into<String>>(ids: impl IntoIterator<Item = S>) -> Self {
        RegisteredRendererResolver {
            available: ids.into_iter().map(Into::into).collect(),
        }
    }
}
impl RendererResolver for RegisteredRendererResolver {
    fn is_available(&self, renderer_id: &str) -> bool {
        self.available.contains(renderer_id)
    }
}

fn default_kind() -> String {
    "harness".to_string()
}
fn default_version() -> String {
    "0.0.0".to_string()
}
fn default_ceiling() -> DataClass {
    DataClass::Internal
}

/// A declared harness — a configured agent experience (ADR-026). **There is deliberately no field to
/// disable compliance/RBAC/audit** — those are spine invariants, not harness options.
/// `deny_unknown_fields` means a manifest cannot even *express* such a field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HarnessManifest {
    /// Definition kind — must be `harness` (ADR-026 manifest key).
    #[serde(default = "default_kind")]
    pub kind: String,
    pub id: String,
    /// Semver, bumped on every publish (ADR-026).
    #[serde(default = "default_version")]
    pub version: String,
    /// CODEOWNERS entry — authoring RBAC (ADR-026).
    #[serde(default)]
    pub owner: String,
    #[serde(default)]
    pub description: String,
    /// System prompt / role for the configured agent.
    #[serde(default)]
    pub persona: String,
    /// Model tier or explicit model id (resolved via the model registry upstream).
    #[serde(default)]
    pub model_policy: Option<String>,
    /// Retrieval namespace / repo scope.
    #[serde(default)]
    pub context: Option<HarnessContext>,
    /// Autonomy level (HITL policy).
    #[serde(default)]
    pub autonomy: Autonomy,
    /// The capabilities the harness asks for. Its effective set is this ∩ what governance granted ∩
    /// what the invoking principal holds.
    #[serde(default)]
    pub requested_capabilities: Vec<String>,
    #[serde(default)]
    pub budget: HarnessBudget,
    #[serde(default)]
    pub rbac: HarnessRbac,
    /// RBAC-on-execute (visibility + department + permissions).
    #[serde(default)]
    pub execute_rbac: ExecuteRbac,
    /// Max data classification this harness may process (never above this at run time).
    #[serde(default = "default_ceiling")]
    pub data_class_ceiling: DataClass,
    /// Declared live payment-rail access.
    #[serde(default)]
    pub payment_boundary: PaymentBoundary,
    /// Pinned `repo@tag@content_hash` refs required by this harness (marketplace-resolved).
    #[serde(default)]
    pub depends_on: Vec<PinnedDep>,
    /// The renderer this harness presents through (`HARNESS_SDK.md` §1: default = `chat`; a bundled
    /// custom renderer is Phase 5). Gated at admission via [`RendererResolver`] — a manifest cannot
    /// declare a custom renderer it did not actually register.
    #[serde(default)]
    pub renderer: HarnessRenderer,
    pub steps: Vec<HarnessStep>,
}

/// Resolve a manifest's `depends_on` refs against the marketplace under TOFU hash-pinning (ADR-026
/// §3 supply-chain integrity). Each pinned dep is resolved as a [`ainxt_governance::PinnedSource`]
/// keyed by its repo; a later resolution with a mutated `content_hash` (or a repointed repo) fails
/// closed with a [`ainxt_governance::MarketError`]. Idempotent for an unchanged pinned dep.
pub fn resolve_dependencies(
    manifest: &HarnessManifest,
    market: &mut ainxt_governance::Marketplace,
) -> Result<(), ainxt_governance::MarketError> {
    for dep in &manifest.depends_on {
        market.resolve(ainxt_governance::PinnedSource {
            name: format!("{}@{}", dep.repo, dep.tag),
            repo_url: dep.repo.clone(),
            pinned_hash: dep.content_hash.clone(),
        })?;
    }
    Ok(())
}

impl HarnessManifest {
    /// A minimal well-formed manifest (for tests / programmatic authoring).
    pub fn new(id: impl Into<String>, steps: Vec<HarnessStep>) -> Self {
        HarnessManifest {
            kind: default_kind(),
            id: id.into(),
            version: default_version(),
            owner: String::new(),
            description: String::new(),
            persona: String::new(),
            model_policy: None,
            context: None,
            autonomy: Autonomy::default(),
            requested_capabilities: Vec::new(),
            budget: HarnessBudget::default(),
            rbac: HarnessRbac::default(),
            execute_rbac: ExecuteRbac::default(),
            data_class_ceiling: default_ceiling(),
            payment_boundary: PaymentBoundary::default(),
            depends_on: Vec::new(),
            renderer: HarnessRenderer::default(),
            steps,
        }
    }

    /// Builder: set the requested capabilities.
    pub fn with_capabilities<S: Into<String>>(mut self, caps: impl IntoIterator<Item = S>) -> Self {
        self.requested_capabilities = caps.into_iter().map(Into::into).collect();
        self
    }

    /// The retrieval namespace this harness declares (`context.namespace`), if any. A thin accessor so
    /// a caller does not need to know [`HarnessContext`]'s shape to read the one field that matters for
    /// retrieval scoping.
    pub fn namespace(&self) -> Option<&str> {
        self.context.as_ref().and_then(|c| c.namespace.as_deref())
    }
}

/// Resolve a harness's declared `model_policy` string into an engine-routing [`Tier`] plus an optional
/// forced provider/model pin (design `HARNESS_SDK.md` §1: `model_policy` is "a model tier or explicit
/// model id, resolved via the model registry upstream"; this is that resolution, made concrete and
/// testable).
///
/// - A bare tier name (`simple`/`medium`/`complex`, case-insensitive, surrounding whitespace ignored)
///   resolves to that [`Tier`] with **no** forced provider — the harness only narrows the routing
///   floor, the router still picks the eligible provider.
/// - Anything else is treated as an **explicit model/provider id** (e.g. `claude-sonnet-4-6`): it
///   resolves to `Tier::Complex` (the safe floor for a named model — never under-tier a pinned model)
///   PLUS that id as the forced provider, mirroring exactly how a Chat turn's own `forced_provider`
///   already works. The caller applies the pair to an [`ainxt_types::Tier`]/`forced_provider` pair on
///   its own request type; this crate stays decoupled from the wire protocol.
///
/// Still subject to the engine's non-overridable data-class exclusion gate downstream — a harness can
/// never use this to force an ineligible provider onto regulated data (ADR-012).
pub fn resolve_model_policy(policy: &str) -> (ainxt_types::Tier, Option<String>) {
    use ainxt_types::Tier;
    match policy.trim().to_ascii_lowercase().as_str() {
        "simple" => (Tier::Simple, None),
        "medium" => (Tier::Medium, None),
        "complex" => (Tier::Complex, None),
        _ => (Tier::Complex, Some(policy.trim().to_string())),
    }
}

// A `HarnessManifest` is deserialized via serde from the caller's config format (JSON/TOML);
// `deny_unknown_fields` guarantees the schema cannot express a compliance/RBAC bypass.

// ============================ Grant + seams ============================

/// What governance granted this harness (the approved capability set). Least privilege intersects
/// this with the manifest's request and the invoking principal.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityGrant {
    pub granted: Vec<String>,
    /// The maximum budget governance permits. The effective budget is the field-wise MINIMUM of this
    /// ceiling and the manifest's self-declared budget, so an author can never raise its own cap past
    /// what was granted. `None` = governance set no ceiling (the manifest's budget stands).
    #[serde(default)]
    pub budget_ceiling: Option<HarnessBudget>,
    /// The maximum data classification governance permits this harness to process (ADR-012 / ADR-026
    /// §5). The **effective** ceiling is the LESS-sensitive of this grant cap and the manifest's
    /// self-declared [`HarnessManifest::data_class_ceiling`], so an engineer-authored harness can
    /// never raise its own reach past what governance granted — a manifest self-declaring `pii`
    /// under a grant capped at `internal` is admitted only for `internal`-or-lower turns, and a
    /// `regulated-payment`/`pii` turn is refused before any step runs. This is the data-class analogue
    /// of [`budget_ceiling`](Self::budget_ceiling): least-privilege on the sensitivity axis, not just
    /// the resource axis. `None` = governance set no data-class cap (the manifest's ceiling stands).
    #[serde(default)]
    pub data_class_ceiling: Option<DataClass>,
}

impl CapabilityGrant {
    pub fn new<S: Into<String>>(caps: impl IntoIterator<Item = S>) -> Self {
        CapabilityGrant {
            granted: caps.into_iter().map(Into::into).collect(),
            budget_ceiling: None,
            data_class_ceiling: None,
        }
    }
    /// Cap the harness budget at `ceiling` (the effective budget becomes the min with the manifest's).
    pub fn with_budget_ceiling(mut self, ceiling: HarnessBudget) -> Self {
        self.budget_ceiling = Some(ceiling);
        self
    }
    /// Cap the harness data-class reach at `ceiling` (the effective ceiling becomes the LESS-sensitive
    /// of this cap and the manifest's declared ceiling). Use this to hold a harness **below PAN/PCI**
    /// regardless of what its manifest self-declares — governance-side least privilege on data class.
    pub fn with_data_class_ceiling(mut self, ceiling: DataClass) -> Self {
        self.data_class_ceiling = Some(ceiling);
        self
    }
    /// The effective data-class ceiling for a manifest under this grant: the LESS-sensitive of the
    /// grant cap (if any) and the manifest's declared ceiling. A harness can never process a turn
    /// more sensitive than this.
    fn effective_data_class_ceiling(&self, declared: DataClass) -> DataClass {
        match self.data_class_ceiling {
            None => declared,
            Some(cap) if cap.sensitivity() < declared.sensitivity() => cap,
            Some(_) => declared,
        }
    }
    /// The effective budget for a manifest under this grant: field-wise min with the ceiling (if any).
    fn effective_budget(&self, declared: &HarnessBudget) -> HarnessBudget {
        match &self.budget_ceiling {
            None => *declared,
            Some(c) => HarnessBudget {
                max_steps: declared.max_steps.min(c.max_steps),
                max_tokens: declared.max_tokens.min(c.max_tokens),
                max_tool_calls: declared.max_tool_calls.min(c.max_tool_calls),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityDecision {
    Allow,
    Deny(String),
}

/// On-behalf-of capability authorization — the harness acts within the invoking principal's
/// authority. MANDATORY seam.
pub trait HarnessAuthorizer: Send + Sync {
    fn authorize(&self, principal: &Principal, capability: &str) -> CapabilityDecision;
}

/// Capability-based authorizer: the principal must hold the capability (Admin implies all).
pub struct CapabilityAuthorizer;
impl HarnessAuthorizer for CapabilityAuthorizer {
    fn authorize(&self, principal: &Principal, capability: &str) -> CapabilityDecision {
        if principal.has_cap(capability) {
            CapabilityDecision::Allow
        } else {
            CapabilityDecision::Deny(format!(
                "principal '{}' lacks '{capability}'",
                principal.user_id
            ))
        }
    }
}

/// One harness audit event (no sensitive values).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarnessAuditEvent {
    pub harness: String,
    pub actor: String,
    pub step: String,
    pub outcome: String,
}

/// Audit seam. MANDATORY.
pub trait HarnessAudit: Send + Sync {
    fn record(&self, event: HarnessAuditEvent);
}

/// In-memory audit sink (tests/dev). Clones share the backing store.
#[derive(Debug, Clone, Default)]
pub struct InMemoryHarnessAudit {
    records: std::sync::Arc<std::sync::Mutex<Vec<HarnessAuditEvent>>>,
}
impl InMemoryHarnessAudit {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn events(&self) -> Vec<HarnessAuditEvent> {
        self.records.lock().expect("audit lock").clone()
    }
}
impl HarnessAudit for InMemoryHarnessAudit {
    fn record(&self, event: HarnessAuditEvent) {
        self.records.lock().expect("audit lock").push(event);
    }
}

// ============================ Step execution seam ============================

/// The result of executing one step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepResult {
    pub tokens_used: u64,
    pub output: String,
    /// Compliance redactions applied to this step's output (0 for executors that don't scan).
    pub redactions: u64,
}

impl StepResult {
    /// A result with no redactions recorded.
    pub fn new(tokens_used: u64, output: impl Into<String>) -> Self {
        StepResult {
            tokens_used,
            output: output.into(),
            redactions: 0,
        }
    }
}

/// Executes a step (through the engine/tools, where compliance/RBAC apply). The harness runtime
/// never runs model/tool logic itself — it only *admits* and *budgets*.
pub trait StepExecutor: Send + Sync {
    fn execute(&self, step: &HarnessStep, principal: &Principal) -> StepResult;
}

/// A [`StepExecutor`] decorator that runs the mandatory [`ComplianceGate`] over each step's output
/// before it is returned — the concrete "compliance runs where the step executes" seam for callers
/// that execute steps outside the engine (the engine applies its own gate). Redact-and-proceed: the
/// output is redacted, the step still completes, and the count is recorded for audit.
pub struct ComplianceStepExecutor<'a> {
    inner: &'a dyn StepExecutor,
    gate: &'a dyn ComplianceGate,
}

impl<'a> ComplianceStepExecutor<'a> {
    pub fn new(inner: &'a dyn StepExecutor, gate: &'a dyn ComplianceGate) -> Self {
        ComplianceStepExecutor { inner, gate }
    }
}

impl StepExecutor for ComplianceStepExecutor<'_> {
    fn execute(&self, step: &HarnessStep, principal: &Principal) -> StepResult {
        let mut result = self.inner.execute(step, principal);
        let scanned = self.gate.scan(&result.output, Direction::Output);
        result.output = scanned.text;
        result.redactions = result.redactions.saturating_add(scanned.redactions as u64);
        result
    }
}

/// A step executor that can see the **prior (already compliance-redacted)** step results, so an
/// author can chain one step's output into the next. This is the seam that makes step-to-step data
/// flow explicit: the runtime only ever hands a step the *redacted* outputs of the steps before it,
/// never their raw form. A plain [`StepExecutor`] cannot see prior steps at all, so it is used where
/// no chaining is needed; chaining executors implement this trait directly.
pub trait ChainingStepExecutor: Send + Sync {
    /// Execute `step`, having visibility of every prior step's redacted [`StepResult`] (in order).
    fn execute_chained(
        &self,
        step: &HarnessStep,
        principal: &Principal,
        prior: &[StepResult],
    ) -> StepResult;
}

/// The result of a compliance-gated harness run: the terminal outcome plus each step's
/// **post-redaction** result (in order) and the total redactions the gate applied across the run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompliantRunReport {
    pub outcome: HarnessOutcome,
    /// Each executed step's result, **after** the mandatory step-output compliance pass.
    pub results: Vec<StepResult>,
    /// Total redactions the gate applied across all step outputs.
    pub total_redactions: u64,
}

impl CompliantRunReport {
    fn terminal(outcome: HarnessOutcome) -> Self {
        CompliantRunReport {
            outcome,
            results: Vec::new(),
            total_redactions: 0,
        }
    }
}

// ============================ Run context + tally ============================

/// The per-run context the caller supplies: the data class of the turn being run. Checked against
/// the manifest's `data_class_ceiling` before any step executes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunContext {
    pub data_class: DataClass,
}

impl RunContext {
    pub fn new(data_class: DataClass) -> Self {
        RunContext { data_class }
    }
    /// A context for an `internal`-class turn (the default).
    pub fn internal() -> Self {
        RunContext {
            data_class: DataClass::Internal,
        }
    }
}

/// Running tallies a driver maintains across steps.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RunTally {
    pub steps_run: u32,
    pub tokens_used: u64,
    pub tool_calls: u32,
}

// ============================ Outcome ============================

/// The outcome of a harness run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HarnessOutcome {
    /// All steps ran within policy.
    Completed {
        steps_run: u32,
        tokens_used: u64,
        tool_calls: u32,
    },
    /// The principal did not meet the harness RBAC floor.
    Rejected(String),
    /// The caller is outside the harness's execute-RBAC visibility scope (403 before the loop).
    VisibilityDenied(String),
    /// The turn's data class exceeds the harness's declared ceiling — refused before any step.
    DataClassExceeded {
        ceiling: DataClass,
        actual: DataClass,
    },
    /// A step needed a capability outside the effective (least-privilege) set.
    CapabilityDenied {
        step: String,
        capability: String,
        reason: String,
    },
    /// A step attempted a payment-rail call its declared boundary does not permit.
    PaymentBoundaryViolation {
        step: String,
        capability: String,
        needed: PaymentAccess,
        declared: PaymentBoundary,
    },
    /// A budget dimension was exhausted (`steps` / `tokens` / `tool_calls`).
    BudgetExceeded { limit: String, at_step: String },
    /// Autonomy is `none` (suggest-only) but a step attempted a write/side-effect — refused before it
    /// runs. A suggest-only harness may never mutate anything.
    SideEffectRefused { step: String, capability: String },
    /// An `assisted`-autonomy write/side-effect step was rejected by the human approver (HITL).
    ApprovalRejected {
        step: String,
        capability: String,
        reason: String,
    },
    /// The manifest declares a [`HarnessRenderer::Custom`] renderer that is not registered with the
    /// [`RendererResolver`] the runtime was constructed with — refused before any step, so a harness
    /// can never silently fall back to `chat` when it claimed to bundle its own renderer.
    RendererUnavailable(String),
}

impl HarnessOutcome {
    /// Whether this outcome is a successful completion.
    pub fn is_completed(&self) -> bool {
        matches!(self, HarnessOutcome::Completed { .. })
    }
}

impl fmt::Display for HarnessOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HarnessOutcome::Completed {
                steps_run,
                tokens_used,
                tool_calls,
            } => {
                write!(
                    f,
                    "completed: {steps_run} steps, {tokens_used} tokens, {tool_calls} tool-calls"
                )
            }
            HarnessOutcome::Rejected(r) => write!(f, "rejected: {r}"),
            HarnessOutcome::VisibilityDenied(r) => write!(f, "access denied: {r}"),
            HarnessOutcome::DataClassExceeded { ceiling, actual } => write!(
                f,
                "data class '{}' exceeds harness ceiling '{}'",
                actual.as_str(),
                ceiling.as_str()
            ),
            HarnessOutcome::CapabilityDenied {
                step,
                capability,
                reason,
            } => {
                write!(
                    f,
                    "capability denied at step '{step}' for '{capability}': {reason}"
                )
            }
            HarnessOutcome::PaymentBoundaryViolation {
                step,
                capability,
                needed,
                declared,
            } => write!(
                f,
                "payment boundary violation at step '{step}': '{capability}' needs {needed:?} but harness declares {declared:?}"
            ),
            HarnessOutcome::BudgetExceeded { limit, at_step } => {
                write!(f, "budget '{limit}' exceeded at step '{at_step}'")
            }
            HarnessOutcome::SideEffectRefused { step, capability } => write!(
                f,
                "suggest-only (autonomy=none): step '{step}' cannot perform the write '{capability}'"
            ),
            HarnessOutcome::ApprovalRejected {
                step,
                capability,
                reason,
            } => write!(
                f,
                "approval rejected at step '{step}' for write '{capability}': {reason}"
            ),
            HarnessOutcome::RendererUnavailable(id) => write!(
                f,
                "harness declares renderer '{id}' but it is not registered (bundle it or use 'chat')"
            ),
        }
    }
}

/// An admitted run: the pre-flight checks passed. Carries the effective (least-privilege) capability
/// set and the effective budget the driver enforces per step.
#[derive(Debug, Clone)]
pub struct AdmittedRun {
    effective: BTreeSet<String>,
    budget: HarnessBudget,
}

impl AdmittedRun {
    pub fn effective_capabilities(&self) -> &BTreeSet<String> {
        &self.effective
    }
    pub fn budget(&self) -> HarnessBudget {
        self.budget
    }
}

/// The decision for one step, given the running tally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepGate {
    /// The step is admitted; execute it.
    Admit,
    /// The step is refused; this terminal outcome must be returned.
    Reject(HarnessOutcome),
}

// ============================ Invoking surface (ADR-026 §2.1) ============================

/// The product surface an invocation originates from. A published harness is a **first-class agent
/// any surface can call by id** (ADR-026 §2.1) — the same registered manifest is reachable from the
/// REST route, a Chat turn ("run the settlement-investigator harness"), a connector trigger (an
/// inbound webhook/schedule firing a harness), or the CLI dev loop, with **no code written per
/// surface**. The surface is recorded on the audit at admission so every invocation is attributable
/// to its origin — a connector-triggered run is distinguishable from a human Chat invocation for the
/// §14 actor-of-record and the incident trail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvokingSurface {
    /// The HTTP `/v1/harness/{id}` route (a network SDK / IDE / desktop client).
    Rest,
    /// A Chat turn that resolved a "run harness X" intent to a registered harness id.
    Chat,
    /// A connector trigger — an inbound webhook, schedule, or event firing a harness by id.
    ConnectorTrigger,
    /// The headless CLI dev loop (`ainxt harness dev`).
    Cli,
}

impl InvokingSurface {
    /// A stable audit label for the surface.
    pub fn as_str(&self) -> &'static str {
        match self {
            InvokingSurface::Rest => "rest",
            InvokingSurface::Chat => "chat",
            InvokingSurface::ConnectorTrigger => "connector-trigger",
            InvokingSurface::Cli => "cli",
        }
    }
}

// ============================ The runtime ============================

/// Runs harnesses under least privilege. The authz + audit seams are required (safety-invariant);
/// the budget, data-class ceiling, payment boundary, and visibility are enforced by the runtime.
pub struct HarnessRuntime {
    authorizer: Box<dyn HarnessAuthorizer>,
    audit: Box<dyn HarnessAudit>,
    payment_classifier: Box<dyn PaymentRailClassifier>,
    side_effect_classifier: Box<dyn SideEffectClassifier>,
    renderer_resolver: Box<dyn RendererResolver>,
}

impl HarnessRuntime {
    /// Construct with the default marker payment-rail + side-effect classifiers, and the permissive
    /// [`AnyRendererResolver`] (unchanged behavior for a manifest that never declares a custom
    /// renderer; opt into fail-closed gating via [`with_renderer_resolver`](Self::with_renderer_resolver)).
    pub fn new(authorizer: Box<dyn HarnessAuthorizer>, audit: Box<dyn HarnessAudit>) -> Self {
        HarnessRuntime {
            authorizer,
            audit,
            payment_classifier: Box::new(MarkerPaymentRailClassifier),
            side_effect_classifier: Box::new(MarkerSideEffectClassifier),
            renderer_resolver: Box::new(AnyRendererResolver),
        }
    }

    /// Construct with an explicit payment-rail classifier (side-effect classifier + renderer resolver
    /// default).
    pub fn with_payment_classifier(
        authorizer: Box<dyn HarnessAuthorizer>,
        audit: Box<dyn HarnessAudit>,
        payment_classifier: Box<dyn PaymentRailClassifier>,
    ) -> Self {
        HarnessRuntime {
            authorizer,
            audit,
            payment_classifier,
            side_effect_classifier: Box::new(MarkerSideEffectClassifier),
            renderer_resolver: Box::new(AnyRendererResolver),
        }
    }

    /// Builder: override the side-effect classifier (drives autonomy/HITL).
    pub fn with_side_effect_classifier(
        mut self,
        classifier: Box<dyn SideEffectClassifier>,
    ) -> Self {
        self.side_effect_classifier = classifier;
        self
    }

    /// Builder: override the [`RendererResolver`] — a deployment with a real bundled-renderer
    /// registry wires it here so a manifest declaring an unregistered [`HarnessRenderer::Custom`] is
    /// refused at admission (fail-closed) instead of the permissive dev default.
    pub fn with_renderer_resolver(mut self, resolver: Box<dyn RendererResolver>) -> Self {
        self.renderer_resolver = resolver;
        self
    }

    fn audit(&self, manifest: &HarnessManifest, principal: &Principal, step: &str, outcome: &str) {
        self.audit.record(HarnessAuditEvent {
            harness: manifest.id.clone(),
            actor: principal.user_id.clone(),
            step: step.to_string(),
            outcome: outcome.to_string(),
        });
    }

    fn role_rank(role: Role) -> u8 {
        match role {
            Role::User => 0,
            Role::Admin => 1,
        }
    }

    /// Enforce execute-RBAC visibility. Admin bypasses department/private scoping (break-glass);
    /// every other caller must be within scope.
    fn check_visibility(
        manifest: &HarnessManifest,
        principal: &Principal,
    ) -> Option<HarnessOutcome> {
        if principal.role == Role::Admin {
            return None;
        }
        match manifest.execute_rbac.visibility {
            Visibility::Public => None,
            Visibility::Department => match &manifest.execute_rbac.department {
                Some(dept) if principal.department.as_deref() == Some(dept.as_str()) => None,
                Some(dept) => Some(HarnessOutcome::VisibilityDenied(format!(
                    "harness is scoped to department '{dept}'"
                ))),
                None => Some(HarnessOutcome::VisibilityDenied(
                    "harness declares department visibility but no department".into(),
                )),
            },
            Visibility::Private => {
                if !manifest.owner.is_empty() && principal.user_id == manifest.owner {
                    None
                } else {
                    Some(HarnessOutcome::VisibilityDenied(
                        "harness is private to its owner".into(),
                    ))
                }
            }
        }
    }

    /// Do all pre-flight checks; return an [`AdmittedRun`] the caller drives step-by-step, or a
    /// terminal [`HarnessOutcome`] if admission is refused. Fail-closed everywhere.
    pub fn admit(
        &self,
        manifest: &HarnessManifest,
        grant: &CapabilityGrant,
        principal: &Principal,
        ctx: &RunContext,
    ) -> Result<AdmittedRun, HarnessOutcome> {
        // RBAC role floor.
        if Self::role_rank(principal.role) < Self::role_rank(manifest.rbac.min_role) {
            self.audit(manifest, principal, "-", "rejected-role");
            return Err(HarnessOutcome::Rejected(format!(
                "role below floor {:?}",
                manifest.rbac.min_role
            )));
        }
        // Execute-RBAC visibility scope.
        if let Some(outcome) = Self::check_visibility(manifest, principal) {
            self.audit(manifest, principal, "-", "rejected-visibility");
            return Err(outcome);
        }
        // Required capabilities.
        for cap in &manifest.rbac.required_caps {
            if !principal.has_cap(cap) {
                self.audit(manifest, principal, "-", "rejected-cap");
                return Err(HarnessOutcome::Rejected(format!(
                    "missing required capability '{cap}'"
                )));
            }
        }
        // Renderer: a bundled CUSTOM renderer must actually be registered — a harness cannot declare
        // one it never shipped and silently fall back to `chat` (HARNESS_SDK.md §1).
        if let HarnessRenderer::Custom(id) = &manifest.renderer {
            if !self.renderer_resolver.is_available(id) {
                self.audit(manifest, principal, "-", "rejected-renderer");
                return Err(HarnessOutcome::RendererUnavailable(id.clone()));
            }
        }
        // Data-class ceiling: the turn cannot be more sensitive than the harness may process. The
        // EFFECTIVE ceiling is the LESS-sensitive of the manifest's declared ceiling and the
        // governance grant's cap — so governance can hold a harness below PAN/PCI (ADR-012/§5) even
        // when the manifest self-declares a higher ceiling. An author can never raise its own reach.
        let effective_ceiling = grant.effective_data_class_ceiling(manifest.data_class_ceiling);
        if ctx.data_class.sensitivity() > effective_ceiling.sensitivity() {
            self.audit(manifest, principal, "-", "rejected-dataclass");
            return Err(HarnessOutcome::DataClassExceeded {
                ceiling: effective_ceiling,
                actual: ctx.data_class,
            });
        }

        // Least privilege: effective = requested ∩ granted.
        let granted: BTreeSet<&str> = grant.granted.iter().map(String::as_str).collect();
        let effective: BTreeSet<String> = manifest
            .requested_capabilities
            .iter()
            .filter(|c| granted.contains(c.as_str()))
            .cloned()
            .collect();

        let budget = grant.effective_budget(&manifest.budget);
        Ok(AdmittedRun { effective, budget })
    }

    /// Gate one step against the effective capability set, on-behalf-of authz, the payment boundary,
    /// and the budget, given the running `tally`. Pure decision — the caller executes on [`StepGate::Admit`].
    pub fn gate_step(
        &self,
        run: &AdmittedRun,
        manifest: &HarnessManifest,
        step: &HarnessStep,
        principal: &Principal,
        tally: &RunTally,
    ) -> StepGate {
        // Budget: step count.
        if tally.steps_run >= run.budget.max_steps {
            return StepGate::Reject(HarnessOutcome::BudgetExceeded {
                limit: "steps".into(),
                at_step: step.id.clone(),
            });
        }
        // Capability must be in the effective (requested ∩ granted) set.
        if !run.effective.contains(step.capability.as_str()) {
            return StepGate::Reject(HarnessOutcome::CapabilityDenied {
                step: step.id.clone(),
                capability: step.capability.clone(),
                reason: "not in the granted+requested set".into(),
            });
        }
        // Capability must be authorized for the invoking principal (on-behalf-of).
        if let CapabilityDecision::Deny(reason) =
            self.authorizer.authorize(principal, &step.capability)
        {
            return StepGate::Reject(HarnessOutcome::CapabilityDenied {
                step: step.id.clone(),
                capability: step.capability.clone(),
                reason,
            });
        }
        // Payment boundary: a payment-rail call must be permitted by the declared boundary.
        if let Some(needed) = self.payment_classifier.classify(&step.capability) {
            if !manifest.payment_boundary.permits(needed) {
                return StepGate::Reject(HarnessOutcome::PaymentBoundaryViolation {
                    step: step.id.clone(),
                    capability: step.capability.clone(),
                    needed,
                    declared: manifest.payment_boundary,
                });
            }
        }
        // Budget: tokens (pre-check the estimate so we never start an over-budget step).
        if tally.tokens_used.saturating_add(step.estimated_tokens) > run.budget.max_tokens {
            return StepGate::Reject(HarnessOutcome::BudgetExceeded {
                limit: "tokens".into(),
                at_step: step.id.clone(),
            });
        }
        // Budget: tool-calls.
        if step.kind == StepKind::Tool && tally.tool_calls >= run.budget.max_tool_calls {
            return StepGate::Reject(HarnessOutcome::BudgetExceeded {
                limit: "tool_calls".into(),
                at_step: step.id.clone(),
            });
        }
        StepGate::Admit
    }

    /// A short audit label for a terminal step-gate outcome.
    fn reject_label(outcome: &HarnessOutcome) -> &'static str {
        match outcome {
            HarnessOutcome::CapabilityDenied { reason, .. } => {
                if reason.contains("granted+requested") {
                    "capability-denied-grant"
                } else {
                    "capability-denied-authz"
                }
            }
            HarnessOutcome::PaymentBoundaryViolation { .. } => "payment-boundary",
            HarnessOutcome::BudgetExceeded { limit, .. } => match limit.as_str() {
                "steps" => "budget-steps",
                "tokens" => "budget-tokens",
                _ => "budget-tool-calls",
            },
            _ => "rejected",
        }
    }

    /// Admit + run a harness synchronously with an in-process [`StepExecutor`], defaulting the turn
    /// to `internal` data class.
    pub fn run(
        &self,
        manifest: &HarnessManifest,
        grant: &CapabilityGrant,
        principal: &Principal,
        executor: &dyn StepExecutor,
    ) -> HarnessOutcome {
        self.run_with_context(
            manifest,
            grant,
            principal,
            &RunContext::internal(),
            executor,
        )
    }

    /// Admit + run a harness synchronously under a specific [`RunContext`]. Fail-closed everywhere.
    pub fn run_with_context(
        &self,
        manifest: &HarnessManifest,
        grant: &CapabilityGrant,
        principal: &Principal,
        ctx: &RunContext,
        executor: &dyn StepExecutor,
    ) -> HarnessOutcome {
        let run = match self.admit(manifest, grant, principal, ctx) {
            Ok(r) => r,
            Err(outcome) => return outcome,
        };

        let mut tally = RunTally::default();
        for step in &manifest.steps {
            match self.gate_step(&run, manifest, step, principal, &tally) {
                StepGate::Reject(outcome) => {
                    self.audit(manifest, principal, &step.id, Self::reject_label(&outcome));
                    return outcome;
                }
                StepGate::Admit => {}
            }
            // Admitted — execute (compliance/RBAC apply inside the executor/engine).
            let result = executor.execute(step, principal);
            tally.tokens_used = tally.tokens_used.saturating_add(result.tokens_used);
            tally.steps_run += 1;
            if step.kind == StepKind::Tool {
                tally.tool_calls += 1;
            }
            self.audit(manifest, principal, &step.id, "executed");
        }

        HarnessOutcome::Completed {
            steps_run: tally.steps_run,
            tokens_used: tally.tokens_used,
            tool_calls: tally.tool_calls,
        }
    }

    /// The autonomy decision for one step (pure). A pure-read step always proceeds; a write/side-effect
    /// proceeds only under `autonomous`, needs a human under `assisted`, and is refused under `none`
    /// (suggest-only). Exposed so an async driver (the SDK) can enforce HITL identically.
    pub fn autonomy_gate(
        &self,
        manifest: &HarnessManifest,
        step: &HarnessStep,
    ) -> AutonomyDecision {
        if !self.side_effect_classifier.is_side_effect(&step.capability) {
            return AutonomyDecision::Proceed;
        }
        match manifest.autonomy {
            Autonomy::Autonomous => AutonomyDecision::Proceed,
            Autonomy::Assisted => AutonomyDecision::NeedsApproval {
                step: step.id.clone(),
                capability: step.capability.clone(),
            },
            Autonomy::None => AutonomyDecision::Refused(HarnessOutcome::SideEffectRefused {
                step: step.id.clone(),
                capability: step.capability.clone(),
            }),
        }
    }

    /// Admit + run a harness synchronously **with autonomy + HITL enforcement**. Each admitted step is
    /// additionally passed through [`autonomy_gate`](Self::autonomy_gate): a `none`-autonomy harness
    /// refuses any write (suggest-only); an `assisted` harness raises an [`ApprovalRequest`] to
    /// `resolver` on every write and executes only if the human approves (rejection is terminal);
    /// `autonomous` proceeds (judge-audited upstream). This is the enforcement the plain [`run`] path
    /// leaves informational. Fail-closed everywhere.
    pub fn run_with_approvals(
        &self,
        manifest: &HarnessManifest,
        grant: &CapabilityGrant,
        principal: &Principal,
        ctx: &RunContext,
        executor: &dyn StepExecutor,
        resolver: &dyn ApprovalResolver,
    ) -> HarnessOutcome {
        let run = match self.admit(manifest, grant, principal, ctx) {
            Ok(r) => r,
            Err(outcome) => return outcome,
        };

        let mut tally = RunTally::default();
        for step in &manifest.steps {
            match self.gate_step(&run, manifest, step, principal, &tally) {
                StepGate::Reject(outcome) => {
                    self.audit(manifest, principal, &step.id, Self::reject_label(&outcome));
                    return outcome;
                }
                StepGate::Admit => {}
            }
            // Autonomy / HITL: enforce write-approval policy before the side-effect happens.
            match self.autonomy_gate(manifest, step) {
                AutonomyDecision::Proceed => {}
                AutonomyDecision::Refused(outcome) => {
                    self.audit(manifest, principal, &step.id, "side-effect-refused");
                    return outcome;
                }
                AutonomyDecision::NeedsApproval { .. } => {
                    self.audit(manifest, principal, &step.id, "approval-requested");
                    let req = ApprovalRequest {
                        harness: manifest.id.clone(),
                        step: step.id.clone(),
                        capability: step.capability.clone(),
                    };
                    match resolver.resolve(&req) {
                        ApprovalDecision::Approve => {
                            self.audit(manifest, principal, &step.id, "approval-granted");
                        }
                        ApprovalDecision::Reject(reason) => {
                            self.audit(manifest, principal, &step.id, "approval-rejected");
                            return HarnessOutcome::ApprovalRejected {
                                step: step.id.clone(),
                                capability: step.capability.clone(),
                                reason,
                            };
                        }
                    }
                }
            }

            let result = executor.execute(step, principal);
            tally.tokens_used = tally.tokens_used.saturating_add(result.tokens_used);
            tally.steps_run += 1;
            if step.kind == StepKind::Tool {
                tally.tool_calls += 1;
            }
            self.audit(manifest, principal, &step.id, "executed");
        }

        HarnessOutcome::Completed {
            steps_run: tally.steps_run,
            tokens_used: tally.tokens_used,
            tool_calls: tally.tool_calls,
        }
    }

    /// Admit + run a harness **from a named product surface**, with autonomy/HITL enforcement.
    ///
    /// This is the one surface-agnostic invoke entrypoint (ADR-026 §2.1): the REST route, a Chat
    /// "run harness X" intent, and a connector trigger all funnel through here, so the safety spine
    /// (RBAC / least-privilege / budget / data-class ceiling / payment boundary / autonomy) runs
    /// **identically** regardless of origin — no per-surface code path can weaken a gate. The
    /// originating [`InvokingSurface`] is recorded on the audit at admission (`invoked:{surface}`) so
    /// the run is attributable to where it came from. Autonomy is enforced exactly as in
    /// [`run_with_approvals`](Self::run_with_approvals): a `none` harness refuses writes, an
    /// `assisted` harness routes writes through `resolver`, `autonomous` proceeds. Fail-closed
    /// everywhere.
    #[allow(clippy::too_many_arguments)]
    pub fn run_from_surface(
        &self,
        surface: InvokingSurface,
        manifest: &HarnessManifest,
        grant: &CapabilityGrant,
        principal: &Principal,
        ctx: &RunContext,
        executor: &dyn StepExecutor,
        resolver: &dyn ApprovalResolver,
    ) -> HarnessOutcome {
        // Attribute the invocation to its origin surface before any step runs (§14 actor-of-record).
        self.audit(
            manifest,
            principal,
            "-",
            &format!("invoked:{}", surface.as_str()),
        );
        self.run_with_approvals(manifest, grant, principal, ctx, executor, resolver)
    }

    /// Admit + run a harness synchronously, applying the **mandatory** [`ComplianceGate`] to *every*
    /// step's output — not just the final answer (design §4: PCI/DSS on every step output). Each
    /// admitted step is executed through the [`ChainingStepExecutor`], and its result is
    /// **redact-and-proceed** scanned *before* it is recorded and *before* it can feed the next step:
    /// the executor only ever sees the redacted outputs of the steps before it, so a PAN a tool/skill/
    /// connector step emits can never reach the next step. Redaction never fails the turn — compliance
    /// redacts and the run proceeds. Least-privilege, budget, data-class and payment gating apply
    /// exactly as in [`run`](Self::run). Fail-closed on admission/gating; fail-open (redact) on
    /// compliance.
    pub fn run_with_compliance(
        &self,
        manifest: &HarnessManifest,
        grant: &CapabilityGrant,
        principal: &Principal,
        ctx: &RunContext,
        executor: &dyn ChainingStepExecutor,
        gate: &dyn ComplianceGate,
    ) -> CompliantRunReport {
        let run = match self.admit(manifest, grant, principal, ctx) {
            Ok(r) => r,
            Err(outcome) => return CompliantRunReport::terminal(outcome),
        };

        let mut tally = RunTally::default();
        let mut results: Vec<StepResult> = Vec::new();
        let mut total_redactions = 0u64;

        for step in &manifest.steps {
            match self.gate_step(&run, manifest, step, principal, &tally) {
                StepGate::Reject(outcome) => {
                    self.audit(manifest, principal, &step.id, Self::reject_label(&outcome));
                    return CompliantRunReport {
                        outcome,
                        results,
                        total_redactions,
                    };
                }
                StepGate::Admit => {}
            }

            // Execute with visibility of only the PRIOR, already-redacted results (chaining).
            let mut result = executor.execute_chained(step, principal, &results);

            // MANDATORY: scan THIS step's output before it is recorded or chained forward. The gate
            // is redact-and-proceed — the raw output is replaced with the redacted text, the step
            // still completes, and the count is carried for audit. This is the seam that guarantees a
            // sensitive value a step emits is removed before the next step (or the caller) sees it.
            let scanned = gate.scan(&result.output, Direction::Output);
            result.output = scanned.text;
            result.redactions = result.redactions.saturating_add(scanned.redactions as u64);
            total_redactions = total_redactions.saturating_add(scanned.redactions as u64);

            tally.tokens_used = tally.tokens_used.saturating_add(result.tokens_used);
            tally.steps_run += 1;
            if step.kind == StepKind::Tool {
                tally.tool_calls += 1;
            }
            self.audit(
                manifest,
                principal,
                &step.id,
                if scanned.redactions > 0 {
                    "executed-redacted"
                } else {
                    "executed"
                },
            );
            results.push(result);
        }

        CompliantRunReport {
            outcome: HarnessOutcome::Completed {
                steps_run: tally.steps_run,
                tokens_used: tally.tokens_used,
                tool_calls: tally.tool_calls,
            },
            results,
            total_redactions,
        }
    }
}

// ============================ Registry (invocable-from-a-surface, ADR-026 §2.1/§6) ============================

/// A registered, invocable harness: the manifest plus the governance capability grant it runs under.
/// This is the missing link between *authoring* a harness and *invoking* it — a published harness
/// becomes a first-class agent that any surface (Chat / REST / connector trigger) can call **by id**.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredHarness {
    pub manifest: HarnessManifest,
    pub grant: CapabilityGrant,
}

/// Why a registry operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryError {
    /// A harness with this id is already registered (ids are stable + unique, ADR-026).
    AlreadyRegistered(String),
    /// No harness is registered under this id.
    NotFound(String),
    /// The manifest failed lint — a harness cannot be registered until it lints clean (the same bar
    /// the control-repo CI enforces on publish).
    LintFailed(Vec<LintFinding>),
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegistryError::AlreadyRegistered(id) => {
                write!(f, "harness '{id}' is already registered")
            }
            RegistryError::NotFound(id) => write!(f, "no harness registered as '{id}'"),
            RegistryError::LintFailed(findings) => {
                write!(f, "manifest failed lint ({} finding(s))", findings.len())
            }
        }
    }
}
impl std::error::Error for RegistryError {}

/// An id-keyed registry of invocable harnesses. A surface resolves a harness by id and invokes it
/// through the [`HarnessRuntime`] — no code written per surface (ADR-026 §2.1). Only lint-clean
/// manifests may register. The registry owns *resolution*; the runtime still owns *every safety
/// invariant* on invoke (RBAC, least-privilege, budget, data-class, payment boundary, autonomy).
#[derive(Debug, Clone, Default)]
pub struct HarnessRegistry {
    by_id: std::collections::BTreeMap<String, RegisteredHarness>,
}

impl HarnessRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a harness under its manifest id. Fails if the manifest does not lint clean or the id
    /// is already taken.
    pub fn register(
        &mut self,
        manifest: HarnessManifest,
        grant: CapabilityGrant,
    ) -> Result<(), RegistryError> {
        if let Err(findings) = lint_manifest(&manifest) {
            return Err(RegistryError::LintFailed(findings));
        }
        if self.by_id.contains_key(&manifest.id) {
            return Err(RegistryError::AlreadyRegistered(manifest.id.clone()));
        }
        let id = manifest.id.clone();
        self.by_id.insert(id, RegisteredHarness { manifest, grant });
        Ok(())
    }

    /// Resolve a registered harness by id.
    pub fn get(&self, id: &str) -> Option<&RegisteredHarness> {
        self.by_id.get(id)
    }

    /// The ids of every registered harness (sorted — discoverable across departments).
    pub fn ids(&self) -> Vec<&str> {
        self.by_id.keys().map(String::as_str).collect()
    }

    pub fn len(&self) -> usize {
        self.by_id.len()
    }
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    /// The surface-facing entrypoint: invoke a registered harness **by id** under the invoking
    /// principal, synchronously, through `runtime` + `executor`. `NotFound` if the id is unknown; any
    /// policy refusal surfaces as the returned [`HarnessOutcome`] (never a panic). For autonomy/HITL
    /// enforcement use [`invoke_with_approvals`](Self::invoke_with_approvals).
    pub fn invoke(
        &self,
        id: &str,
        runtime: &HarnessRuntime,
        principal: &Principal,
        ctx: &RunContext,
        executor: &dyn StepExecutor,
    ) -> Result<HarnessOutcome, RegistryError> {
        let reg = self
            .get(id)
            .ok_or_else(|| RegistryError::NotFound(id.to_string()))?;
        Ok(runtime.run_with_context(&reg.manifest, &reg.grant, principal, ctx, executor))
    }

    /// The surface-agnostic entrypoint (ADR-026 §2.1): invoke a registered harness **by id** from a
    /// named [`InvokingSurface`] (REST / Chat / connector-trigger / CLI) with autonomy + HITL
    /// enforcement and the origin recorded on the audit. The SAME registered manifest is reachable
    /// from every surface with no per-surface code — Chat and a connector trigger call this exactly
    /// as the REST route does. `NotFound` if the id is unknown; any policy refusal surfaces as the
    /// returned [`HarnessOutcome`].
    #[allow(clippy::too_many_arguments)]
    pub fn invoke_from_surface(
        &self,
        surface: InvokingSurface,
        id: &str,
        runtime: &HarnessRuntime,
        principal: &Principal,
        ctx: &RunContext,
        executor: &dyn StepExecutor,
        resolver: &dyn ApprovalResolver,
    ) -> Result<HarnessOutcome, RegistryError> {
        let reg = self
            .get(id)
            .ok_or_else(|| RegistryError::NotFound(id.to_string()))?;
        Ok(runtime.run_from_surface(
            surface,
            &reg.manifest,
            &reg.grant,
            principal,
            ctx,
            executor,
            resolver,
        ))
    }

    // GAP-AUDIT misc-decisions (gap6, item 1) — investigated whether this method is a real
    // HITL-bypass gap: is there a served harness-invoke path with NO approval enforcement at
    // all? There is not. The one served route, `/v1/harness/:id`
    // (`ainxt-server::harness_invoke_handler` -> `invoke_harness_as` -> `invoke_from_surface`
    // above), already routes through `HarnessRuntime::run_from_surface`, which — after recording
    // the surface-attribution audit event — delegates straight into `run_with_approvals`
    // (`run_from_surface`'s own doc: "Autonomy is enforced exactly as in
    // `run_with_approvals`"). So `invoke_from_surface` IS this method plus surface attribution;
    // every registered-harness invocation the real composition root serves already gets full
    // autonomy/HITL enforcement. This method is a legitimately unused, strictly-subset
    // convenience entrypoint — left in place as a public library primitive for a caller with no
    // surface to attribute (e.g. an internal batch/cron re-run of a harness) that still wants
    // approval enforcement without the surface-audit bookkeeping. Not a bypass: nothing in the
    // real served path skips approvals by calling the plain, non-approval `invoke`/
    // `run_with_context` instead of this family.
    //
    /// Invoke a registered harness by id with autonomy + HITL enforcement (see
    /// [`HarnessRuntime::run_with_approvals`]).
    pub fn invoke_with_approvals(
        &self,
        id: &str,
        runtime: &HarnessRuntime,
        principal: &Principal,
        ctx: &RunContext,
        executor: &dyn StepExecutor,
        resolver: &dyn ApprovalResolver,
    ) -> Result<HarnessOutcome, RegistryError> {
        let reg = self
            .get(id)
            .ok_or_else(|| RegistryError::NotFound(id.to_string()))?;
        Ok(runtime.run_with_approvals(
            &reg.manifest,
            &reg.grant,
            principal,
            ctx,
            executor,
            resolver,
        ))
    }
}

// ============================ Compliance-backed pre-receive gate (ADR-026 §10) ============================

/// A [`ainxt_governance::PrereceiveGate`] backed by the runtime's real [`ComplianceGate`] (the PCI/DSS
/// engine in production, injected here). Unlike the OSS marker heuristic, this runs the **actual
/// detector**; because git history is permanent, any file the gate would *redact* at runtime is
/// instead **blocked** here — a spaced/entropy secret the marker heuristic misses is caught by the
/// real detector and the whole push is rejected, fail-closed. This is the seam that lets the private
/// enterprise detector guard the control repo without living in the OSS tree.
pub struct ComplianceBackedPrereceiveGate<'a> {
    gate: &'a dyn ComplianceGate,
}

impl<'a> ComplianceBackedPrereceiveGate<'a> {
    pub fn new(gate: &'a dyn ComplianceGate) -> Self {
        ComplianceBackedPrereceiveGate { gate }
    }
}

impl ainxt_governance::PrereceiveGate for ComplianceBackedPrereceiveGate<'_> {
    fn check(&self, files: &[(String, String)]) -> Result<(), Vec<String>> {
        let mut findings = Vec::new();
        for (path, content) in files {
            // Never surface the raw content — only the class/count (I4: the wire never carries PII).
            let scanned = self.gate.scan(content, Direction::Output);
            if scanned.redactions > 0 {
                findings.push(format!(
                    "{path}: compliance gate flagged {} sensitive item(s) — a push carrying PII/secrets is blocked (git history is permanent)",
                    scanned.redactions
                ));
            }
        }
        if findings.is_empty() {
            Ok(())
        } else {
            Err(findings)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Executor that charges a fixed token cost per step.
    struct FixedExecutor {
        tokens: u64,
    }
    impl StepExecutor for FixedExecutor {
        fn execute(&self, step: &HarnessStep, _p: &Principal) -> StepResult {
            StepResult::new(self.tokens, format!("ran {}", step.id))
        }
    }

    fn step(id: &str, cap: &str, kind: StepKind) -> HarnessStep {
        HarnessStep {
            id: id.into(),
            kind,
            capability: cap.into(),
            estimated_tokens: 10,
            input: None,
        }
    }

    fn manifest(caps: &[&str], steps: Vec<HarnessStep>) -> HarnessManifest {
        HarnessManifest::new("h", steps).with_capabilities(caps.iter().map(|s| s.to_string()))
    }

    fn runtime() -> (HarnessRuntime, InMemoryHarnessAudit) {
        let audit = InMemoryHarnessAudit::new();
        let rt = HarnessRuntime::new(Box::new(CapabilityAuthorizer), Box::new(audit.clone()));
        (rt, audit)
    }

    #[test]
    fn grant_budget_ceiling_caps_a_greedy_manifest() {
        let (rt, _a) = runtime();
        let mut m = manifest(
            &["c"],
            vec![
                step("s1", "c", StepKind::Llm),
                step("s2", "c", StepKind::Llm),
                step("s3", "c", StepKind::Llm),
            ],
        );
        m.budget = HarnessBudget {
            max_steps: u32::MAX,
            max_tokens: u64::MAX,
            max_tool_calls: u32::MAX,
        };
        let grant = CapabilityGrant::new(["c"]).with_budget_ceiling(HarnessBudget {
            max_steps: 2,
            max_tokens: u64::MAX,
            max_tool_calls: u32::MAX,
        });
        let p = Principal::user("u", &["c"]);
        match rt.run(&m, &grant, &p, &FixedExecutor { tokens: 1 }) {
            HarnessOutcome::BudgetExceeded { limit, .. } => assert_eq!(limit, "steps"),
            other => panic!("grant ceiling must cap the greedy manifest, got {other}"),
        }
        let no_ceiling = CapabilityGrant::new(["c"]);
        assert!(rt
            .run(&m, &no_ceiling, &p, &FixedExecutor { tokens: 1 })
            .is_completed());
    }

    #[test]
    fn happy_path_runs_all_steps() {
        let (rt, audit) = runtime();
        let m = manifest(
            &["tool.grep", "llm.call"],
            vec![
                step("s1", "llm.call", StepKind::Llm),
                step("s2", "tool.grep", StepKind::Tool),
            ],
        );
        let grant = CapabilityGrant::new(["tool.grep", "llm.call"]);
        let p = Principal::user("u", &["tool.grep", "llm.call"]);
        let out = rt.run(&m, &grant, &p, &FixedExecutor { tokens: 10 });
        assert_eq!(
            out,
            HarnessOutcome::Completed {
                steps_run: 2,
                tokens_used: 20,
                tool_calls: 1
            }
        );
        assert_eq!(
            audit
                .events()
                .iter()
                .filter(|e| e.outcome == "executed")
                .count(),
            2
        );
    }

    #[test]
    fn cannot_use_a_capability_not_granted() {
        let (rt, _a) = runtime();
        let m = manifest(
            &["tool.delete"],
            vec![step("s1", "tool.delete", StepKind::Tool)],
        );
        let grant = CapabilityGrant::new(["tool.grep"]);
        let p = Principal::user("u", &["tool.delete"]);
        let out = rt.run(&m, &grant, &p, &FixedExecutor { tokens: 1 });
        assert!(
            matches!(out, HarnessOutcome::CapabilityDenied { .. }),
            "ungranted capability must be refused"
        );
    }

    #[test]
    fn cannot_exceed_the_invoking_principal() {
        let (rt, _a) = runtime();
        let m = manifest(
            &["connector.gitlab"],
            vec![step("s1", "connector.gitlab", StepKind::Tool)],
        );
        let grant = CapabilityGrant::new(["connector.gitlab"]);
        let p = Principal::user("u", &[]);
        let out = rt.run(&m, &grant, &p, &FixedExecutor { tokens: 1 });
        assert!(
            matches!(out, HarnessOutcome::CapabilityDenied { .. }),
            "a harness cannot exceed its caller"
        );
    }

    #[test]
    fn cannot_use_a_capability_not_requested() {
        let (rt, _a) = runtime();
        let m = manifest(
            &["tool.grep"],
            vec![step("s1", "tool.write", StepKind::Tool)],
        );
        let grant = CapabilityGrant::new(["tool.grep", "tool.write"]);
        let p = Principal::user("u", &["tool.grep", "tool.write"]);
        let out = rt.run(&m, &grant, &p, &FixedExecutor { tokens: 1 });
        assert!(matches!(out, HarnessOutcome::CapabilityDenied { .. }));
    }

    #[test]
    fn budget_caps_steps_tokens_and_tool_calls() {
        let (rt, _a) = runtime();
        let p = Principal::user("u", &["c"]);
        let grant = CapabilityGrant::new(["c"]);

        let mut m = manifest(
            &["c"],
            vec![
                step("s1", "c", StepKind::Llm),
                step("s2", "c", StepKind::Llm),
                step("s3", "c", StepKind::Llm),
            ],
        );
        m.budget = HarnessBudget {
            max_steps: 2,
            max_tokens: 1_000_000,
            max_tool_calls: 100,
        };
        assert!(matches!(
            rt.run(&m, &grant, &p, &FixedExecutor { tokens: 1 }),
            HarnessOutcome::BudgetExceeded { .. }
        ));

        let mut m2 = manifest(
            &["c"],
            vec![
                step("s1", "c", StepKind::Llm),
                step("s2", "c", StepKind::Llm),
                step("s3", "c", StepKind::Llm),
            ],
        );
        m2.budget = HarnessBudget {
            max_steps: 100,
            max_tokens: 25,
            max_tool_calls: 100,
        };
        match rt.run(&m2, &grant, &p, &FixedExecutor { tokens: 10 }) {
            HarnessOutcome::BudgetExceeded { limit, .. } => assert_eq!(limit, "tokens"),
            other => panic!("expected token budget exceed, got {other}"),
        }

        let mut m3 = manifest(
            &["c"],
            vec![
                step("s1", "c", StepKind::Tool),
                step("s2", "c", StepKind::Tool),
            ],
        );
        m3.budget = HarnessBudget {
            max_steps: 100,
            max_tokens: 1_000_000,
            max_tool_calls: 1,
        };
        match rt.run(&m3, &grant, &p, &FixedExecutor { tokens: 1 }) {
            HarnessOutcome::BudgetExceeded { limit, .. } => assert_eq!(limit, "tool_calls"),
            other => panic!("expected tool-call budget exceed, got {other}"),
        }
    }

    #[test]
    fn rbac_floor_is_enforced() {
        let (rt, _a) = runtime();
        let mut m = manifest(&["c"], vec![step("s1", "c", StepKind::Llm)]);
        m.rbac = HarnessRbac {
            min_role: Role::Admin,
            required_caps: vec![],
        };
        let grant = CapabilityGrant::new(["c"]);
        let out = rt.run(
            &m,
            &grant,
            &Principal::user("u", &["c"]),
            &FixedExecutor { tokens: 1 },
        );
        assert!(matches!(out, HarnessOutcome::Rejected(_)));
        assert!(rt
            .run(
                &m,
                &grant,
                &Principal::admin("root"),
                &FixedExecutor { tokens: 1 }
            )
            .is_completed());
    }

    // ---- new: data-class ceiling ----

    #[test]
    fn data_class_ceiling_blocks_a_too_sensitive_turn() {
        let (rt, audit) = runtime();
        let mut m = manifest(&["c"], vec![step("s1", "c", StepKind::Llm)]);
        m.data_class_ceiling = DataClass::Internal;
        let grant = CapabilityGrant::new(["c"]);
        let p = Principal::user("u", &["c"]).with_clearance(DataClass::Pii);
        // A regulated-payment turn into an internal-ceiling harness is refused before any step.
        let out = rt.run_with_context(
            &m,
            &grant,
            &p,
            &RunContext::new(DataClass::RegulatedPayment),
            &FixedExecutor { tokens: 1 },
        );
        match out {
            HarnessOutcome::DataClassExceeded { ceiling, actual } => {
                assert_eq!(ceiling, DataClass::Internal);
                assert_eq!(actual, DataClass::RegulatedPayment);
            }
            other => panic!("expected data-class refusal, got {other}"),
        }
        // No step executed.
        assert!(audit.events().iter().all(|e| e.outcome != "executed"));
        // A within-ceiling turn runs.
        assert!(rt
            .run_with_context(
                &m,
                &grant,
                &p,
                &RunContext::new(DataClass::Public),
                &FixedExecutor { tokens: 1 }
            )
            .is_completed());
    }

    // ---- new: payment boundary ----

    #[test]
    fn payment_boundary_none_blocks_a_rail_step() {
        let (rt, _a) = runtime();
        let m = manifest(
            &["connector.upi.initiate"],
            vec![step("s1", "connector.upi.initiate", StepKind::Tool)],
        );
        // payment_boundary defaults to None.
        let grant = CapabilityGrant::new(["connector.upi.initiate"]);
        let p = Principal::user("u", &["connector.upi.initiate"]);
        match rt.run(&m, &grant, &p, &FixedExecutor { tokens: 1 }) {
            HarnessOutcome::PaymentBoundaryViolation {
                needed, declared, ..
            } => {
                assert_eq!(needed, PaymentAccess::Write);
                assert_eq!(declared, PaymentBoundary::None);
            }
            other => panic!("expected payment-boundary refusal, got {other}"),
        }
    }

    #[test]
    fn payment_boundary_readonly_permits_read_but_not_write() {
        let (rt, _a) = runtime();
        let mut read = manifest(
            &["connector.upi.query"],
            vec![step("s1", "connector.upi.query", StepKind::Tool)],
        );
        read.payment_boundary = PaymentBoundary::ReadOnly;
        let p = Principal::user("u", &["connector.upi.query", "connector.upi.transfer"]);
        assert!(rt
            .run(
                &read,
                &CapabilityGrant::new(["connector.upi.query"]),
                &p,
                &FixedExecutor { tokens: 1 }
            )
            .is_completed());

        let mut write = manifest(
            &["connector.upi.transfer"],
            vec![step("s1", "connector.upi.transfer", StepKind::Tool)],
        );
        write.payment_boundary = PaymentBoundary::ReadOnly;
        assert!(matches!(
            rt.run(
                &write,
                &CapabilityGrant::new(["connector.upi.transfer"]),
                &p,
                &FixedExecutor { tokens: 1 }
            ),
            HarnessOutcome::PaymentBoundaryViolation { .. }
        ));
    }

    #[test]
    fn non_rail_capability_is_never_payment_gated() {
        let c = MarkerPaymentRailClassifier;
        assert_eq!(c.classify("tool.grep"), None);
        assert_eq!(c.classify("kb.search"), None);
        assert_eq!(
            c.classify("connector.payment.query"),
            Some(PaymentAccess::ReadOnly)
        );
        assert_eq!(
            c.classify("connector.payment.initiate"),
            Some(PaymentAccess::Write)
        );
        assert_eq!(
            c.classify("connector.neft.settle"),
            Some(PaymentAccess::Write)
        );
    }

    // ---- new: execute-RBAC visibility ----

    #[test]
    fn department_visibility_scopes_the_caller() {
        let (rt, _a) = runtime();
        let mut m = manifest(&["c"], vec![step("s1", "c", StepKind::Llm)]);
        m.execute_rbac = ExecuteRbac {
            visibility: Visibility::Department,
            department: Some("settlement".into()),
            permissions: vec![],
        };
        let grant = CapabilityGrant::new(["c"]);
        // Wrong department → 403 before the loop.
        let outsider = Principal::user("u", &["c"]).with_department("retail");
        assert!(matches!(
            rt.run(&m, &grant, &outsider, &FixedExecutor { tokens: 1 }),
            HarnessOutcome::VisibilityDenied(_)
        ));
        // Right department → runs.
        let insider = Principal::user("v", &["c"]).with_department("settlement");
        assert!(rt
            .run(&m, &grant, &insider, &FixedExecutor { tokens: 1 })
            .is_completed());
        // Admin break-glass bypasses scoping.
        assert!(rt
            .run(
                &m,
                &grant,
                &Principal::admin("root"),
                &FixedExecutor { tokens: 1 }
            )
            .is_completed());
    }

    #[test]
    fn private_visibility_admits_only_the_owner() {
        let (rt, _a) = runtime();
        let mut m = manifest(&["c"], vec![step("s1", "c", StepKind::Llm)]);
        m.owner = "alice".into();
        m.execute_rbac = ExecuteRbac {
            visibility: Visibility::Private,
            department: None,
            permissions: vec![],
        };
        let grant = CapabilityGrant::new(["c"]);
        assert!(matches!(
            rt.run(
                &m,
                &grant,
                &Principal::user("bob", &["c"]),
                &FixedExecutor { tokens: 1 }
            ),
            HarnessOutcome::VisibilityDenied(_)
        ));
        assert!(rt
            .run(
                &m,
                &grant,
                &Principal::user("alice", &["c"]),
                &FixedExecutor { tokens: 1 }
            )
            .is_completed());
    }

    // ---- r15: bundled custom renderer (HARNESS_SDK.md §1) ----

    #[test]
    fn r15_default_chat_renderer_never_consults_the_resolver() {
        // A resolver that would deny EVERYTHING never even gets consulted for the default `chat`
        // renderer — the built-in renderer is always available by definition.
        let rt = HarnessRuntime::new(
            Box::new(CapabilityAuthorizer),
            Box::new(InMemoryHarnessAudit::new()),
        )
        .with_renderer_resolver(Box::new(RegisteredRendererResolver::default()));
        let m = manifest(&["c"], vec![step("s1", "c", StepKind::Llm)]);
        assert_eq!(
            m.renderer,
            HarnessRenderer::Chat,
            "manifest default renderer must be Chat"
        );
        let grant = CapabilityGrant::new(["c"]);
        assert!(rt
            .run(
                &m,
                &grant,
                &Principal::user("u", &["c"]),
                &FixedExecutor { tokens: 1 }
            )
            .is_completed());
    }

    #[test]
    fn r15_a_bundled_custom_renderer_must_be_registered_or_admission_is_refused() {
        let grant = CapabilityGrant::new(["c"]);
        let p = Principal::user("u", &["c"]);

        // Registered custom renderer → runs.
        let ok_audit = InMemoryHarnessAudit::new();
        let ok_rt = HarnessRuntime::new(Box::new(CapabilityAuthorizer), Box::new(ok_audit))
            .with_renderer_resolver(Box::new(RegisteredRendererResolver::new([
                "settlement-dashboard",
            ])));
        let mut ok = manifest(&["c"], vec![step("s1", "c", StepKind::Llm)]);
        ok.renderer = HarnessRenderer::Custom("settlement-dashboard".into());
        assert!(ok_rt
            .run(&ok, &grant, &p, &FixedExecutor { tokens: 1 })
            .is_completed());

        // An UNREGISTERED custom renderer is refused BEFORE any step runs — never a silent fallback
        // to `chat` (separate audit/runtime so the two cases can't be conflated).
        let bad_audit = InMemoryHarnessAudit::new();
        let bad_rt =
            HarnessRuntime::new(Box::new(CapabilityAuthorizer), Box::new(bad_audit.clone()))
                .with_renderer_resolver(Box::new(RegisteredRendererResolver::new([
                    "settlement-dashboard",
                ])));
        let mut bad = manifest(&["c"], vec![step("s1", "c", StepKind::Llm)]);
        bad.renderer = HarnessRenderer::Custom("not-bundled-anywhere".into());
        match bad_rt.run(&bad, &grant, &p, &FixedExecutor { tokens: 1 }) {
            HarnessOutcome::RendererUnavailable(id) => assert_eq!(id, "not-bundled-anywhere"),
            other => panic!("expected RendererUnavailable, got {other}"),
        }
        assert!(
            bad_audit.events().iter().all(|e| e.outcome != "executed"),
            "no step may execute when the bundled renderer is unavailable"
        );
        assert!(bad_audit
            .events()
            .iter()
            .any(|e| e.outcome == "rejected-renderer"));
    }

    #[test]
    fn r15_dev_default_runtime_permits_any_custom_renderer() {
        // `HarnessRuntime::new` defaults to `AnyRendererResolver` — unchanged behavior for a manifest
        // that declares a custom renderer with no registry wired yet.
        let (rt, _a) = runtime();
        let mut m = manifest(&["c"], vec![step("s1", "c", StepKind::Llm)]);
        m.renderer = HarnessRenderer::Custom("anything-goes".into());
        let grant = CapabilityGrant::new(["c"]);
        assert!(rt
            .run(
                &m,
                &grant,
                &Principal::user("u", &["c"]),
                &FixedExecutor { tokens: 1 }
            )
            .is_completed());
    }

    // ---- new: compliance-bridging executor ----

    #[test]
    fn compliance_step_executor_redacts_step_output() {
        use ainxt_runtime::compliance::RedactAndProceed;
        let (rt, _a) = runtime();
        // Inner executor leaks a 16-digit PAN in its output.
        struct LeakyExecutor;
        impl StepExecutor for LeakyExecutor {
            fn execute(&self, _s: &HarnessStep, _p: &Principal) -> StepResult {
                StepResult::new(5, "card 4111111111111111 on file")
            }
        }
        let gate = RedactAndProceed;
        let leaky = LeakyExecutor;
        let guarded = ComplianceStepExecutor::new(&leaky, &gate);
        let s = step("s1", "c", StepKind::Llm);
        let out = guarded.execute(&s, &Principal::user("u", &["c"]));
        assert!(
            out.output.contains("[REDACTED-PAN]"),
            "PAN must be redacted: {}",
            out.output
        );
        assert!(!out.output.contains("4111111111111111"));
        assert!(out.redactions >= 1);

        // And it composes into a full run.
        let m = manifest(&["c"], vec![step("s1", "c", StepKind::Llm)]);
        assert!(rt
            .run(
                &m,
                &CapabilityGrant::new(["c"]),
                &Principal::user("u", &["c"]),
                &guarded
            )
            .is_completed());
    }

    #[test]
    fn manifest_schema_cannot_express_a_gate_bypass() {
        let json = r#"{"id":"h","steps":[],"disable_compliance":true}"#;
        assert!(
            serde_json::from_str::<HarnessManifest>(json).is_err(),
            "schema must reject a bypass field"
        );
        let ok = r#"{"id":"h","steps":[{"id":"s1","kind":"llm","capability":"llm.call"}]}"#;
        let m: HarnessManifest = serde_json::from_str(ok).unwrap();
        assert_eq!(m.id, "h");
        assert_eq!(m.kind, "harness");
        assert_eq!(m.steps[0].capability, "llm.call");
        assert_eq!(m.data_class_ceiling, DataClass::Internal);
        assert_eq!(m.payment_boundary, PaymentBoundary::None);
    }

    #[test]
    fn manifest_serde_round_trips_with_all_keys() {
        let mut m = manifest(&["c"], vec![step("s1", "c", StepKind::Skill)]);
        m.version = "1.2.3".into();
        m.owner = "settlement-ops".into();
        m.persona = "you are an analyst".into();
        m.data_class_ceiling = DataClass::Confidential;
        m.payment_boundary = PaymentBoundary::ReadOnly;
        m.autonomy = Autonomy::Assisted;
        m.execute_rbac = ExecuteRbac {
            visibility: Visibility::Department,
            department: Some("settlement".into()),
            permissions: vec!["c:read-only".into()],
        };
        m.depends_on = vec![PinnedDep {
            repo: "acme/kit".into(),
            tag: "v1".into(),
            content_hash: "abc".into(),
        }];
        let json = serde_json::to_string(&m).unwrap();
        assert_eq!(serde_json::from_str::<HarnessManifest>(&json).unwrap(), m);
    }

    #[test]
    fn depends_on_pins_then_rejects_a_mutated_dependency() {
        use ainxt_governance::{MarketError, Marketplace};
        let mut m = manifest(&["c"], vec![step("s1", "c", StepKind::Llm)]);
        m.depends_on = vec![PinnedDep {
            repo: "acme/kit".into(),
            tag: "v1".into(),
            content_hash: "hash-1".into(),
        }];
        let mut market = Marketplace::new();
        // First install pins.
        assert!(resolve_dependencies(&m, &mut market).is_ok());
        // Re-install unchanged → idempotent.
        assert!(resolve_dependencies(&m, &mut market).is_ok());
        // Content mutated after first pin (same repo@tag, new hash) → fail closed.
        m.depends_on[0].content_hash = "hash-TAMPERED".into();
        assert!(matches!(
            resolve_dependencies(&m, &mut market),
            Err(MarketError::HashMismatch { .. })
        ));
    }

    // ---- HARN-01: a registered harness is invocable from a surface, by id ----

    #[test]
    fn gap_ainxt_admission_registry_resolves_and_invokes_by_id() {
        let (rt, _a) = runtime();
        let mut reg = HarnessRegistry::new();

        // A lint-clean, well-formed manifest (owner + semver + declared caps).
        let mut m = manifest(&["kb.search"], vec![step("s1", "kb.search", StepKind::Llm)]);
        m.owner = "settlement-ops".into();
        m.version = "1.0.0".into();
        let grant = CapabilityGrant::new(["kb.search"]);
        assert!(reg.register(m.clone(), grant.clone()).is_ok());
        assert_eq!(reg.ids(), vec!["h"]);
        assert!(reg.get("h").is_some());

        // A surface invokes it BY ID — no code written per surface.
        let p = Principal::user("u", &["kb.search"]);
        let out = reg
            .invoke(
                "h",
                &rt,
                &p,
                &RunContext::internal(),
                &FixedExecutor { tokens: 5 },
            )
            .expect("registered id must resolve");
        assert!(
            out.is_completed(),
            "invoke-by-id must run the harness: {out}"
        );

        // Unknown id → NotFound (never a panic).
        assert!(matches!(
            reg.invoke(
                "nope",
                &rt,
                &p,
                &RunContext::internal(),
                &FixedExecutor { tokens: 5 }
            ),
            Err(RegistryError::NotFound(_))
        ));
        // Duplicate id → rejected (stable, unique ids).
        assert!(matches!(
            reg.register(m, grant),
            Err(RegistryError::AlreadyRegistered(_))
        ));
        // A manifest that does not lint clean (no owner) cannot register.
        let dirty = manifest(&["c"], vec![step("s1", "c", StepKind::Llm)]); // owner empty, version 0.0.0
        assert!(matches!(
            HarnessRegistry::new().register(dirty, CapabilityGrant::new(["c"])),
            Err(RegistryError::LintFailed(_))
        ));
    }

    // ---- HARN-03: autonomy + HITL enforcement on writes ----

    #[test]
    fn gap_ainxt_admission_side_effect_classifier_reads_vs_writes() {
        let c = MarkerSideEffectClassifier;
        // Pure reads.
        assert!(!c.is_side_effect("kb.search"));
        assert!(!c.is_side_effect("connector.postgres.query"));
        assert!(!c.is_side_effect("tool.grep"));
        assert!(!c.is_side_effect("llm.call"));
        assert!(!c.is_side_effect("code.read"));
        // Writes / side-effects.
        assert!(c.is_side_effect("code.edit"));
        assert!(c.is_side_effect("connector.gitlab.create_mr"));
        assert!(c.is_side_effect("connector.email.send"));
        assert!(c.is_side_effect("connector.upi.transfer"));
    }

    #[test]
    fn gap_ainxt_admission_autonomy_hitl_enforced_on_writes() {
        let (rt, audit) = runtime();
        // A write step (code.edit) — its autonomy handling is what we exercise.
        let mk = |autonomy: Autonomy| {
            let mut m = manifest(
                &["code.edit"],
                vec![step("s1", "code.edit", StepKind::Tool)],
            );
            m.autonomy = autonomy;
            m
        };
        let grant = CapabilityGrant::new(["code.edit"]);
        let p = Principal::user("u", &["code.edit"]);

        // autonomy=none (suggest-only): a write is refused before it runs — nothing executes.
        let none = mk(Autonomy::None);
        let out = rt.run_with_approvals(
            &none,
            &grant,
            &p,
            &RunContext::internal(),
            &FixedExecutor { tokens: 1 },
            &DenyingApprovalResolver,
        );
        assert!(
            matches!(out, HarnessOutcome::SideEffectRefused { .. }),
            "suggest-only must refuse a write, got {out}"
        );
        assert!(audit.events().iter().all(|e| e.outcome != "executed"));

        // autonomy=assisted + no approver wired (fail-closed) → rejected.
        let assisted = mk(Autonomy::Assisted);
        let rejected = rt.run_with_approvals(
            &assisted,
            &grant,
            &p,
            &RunContext::internal(),
            &FixedExecutor { tokens: 1 },
            &DenyingApprovalResolver,
        );
        assert!(
            matches!(rejected, HarnessOutcome::ApprovalRejected { .. }),
            "assisted write without approval must be rejected, got {rejected}"
        );

        // autonomy=assisted + human approves → completes.
        assert!(rt
            .run_with_approvals(
                &assisted,
                &grant,
                &p,
                &RunContext::internal(),
                &FixedExecutor { tokens: 1 },
                &AllowingApprovalResolver,
            )
            .is_completed());

        // autonomy=autonomous → proceeds without approval (judge-audited upstream).
        assert!(rt
            .run_with_approvals(
                &mk(Autonomy::Autonomous),
                &grant,
                &p,
                &RunContext::internal(),
                &FixedExecutor { tokens: 1 },
                &DenyingApprovalResolver,
            )
            .is_completed());
    }

    #[test]
    fn gap_ainxt_admission_autonomy_read_step_never_needs_approval() {
        let (rt, _a) = runtime();
        // A read-only step under the strictest autonomy still runs — HITL is only for writes.
        let mut m = manifest(
            &["kb.search"],
            vec![step("s1", "kb.search", StepKind::Tool)],
        );
        m.autonomy = Autonomy::None;
        assert!(rt
            .run_with_approvals(
                &m,
                &CapabilityGrant::new(["kb.search"]),
                &Principal::user("u", &["kb.search"]),
                &RunContext::internal(),
                &FixedExecutor { tokens: 1 },
                &DenyingApprovalResolver,
            )
            .is_completed());
    }

    // ---- GAP-FIX harness-sdk-governance #2: ApprovalResolver <-> ApprovalGate adapter ----

    #[test]
    fn gap_harness_sdk_governance_runtime_approval_gate_resolver_adapts_decisions() {
        // A live human/wire `ApprovalGate` (the same trait `ainxt_server::WireApprovalGate` and
        // `ainxt_client::WireApprovalGate` implement) reaches the harness assisted-autonomy write
        // approval THROUGH the adapter — proving the two differently-shaped traits are now actually
        // connected, not merely similarly named. `AutoApprove`/`AutoReject` stand in for a real live
        // gate here; the adapter does not know or care which concrete `ApprovalGate` it wraps.
        let (rt, _audit) = runtime();
        let mut m = manifest(
            &["code.edit"],
            vec![step("s1", "code.edit", StepKind::Tool)],
        );
        m.autonomy = Autonomy::Assisted;
        let grant = CapabilityGrant::new(["code.edit"]);
        let p = Principal::user("u", &["code.edit"]);

        let approve_resolver = RuntimeApprovalGateResolver::new(
            std::sync::Arc::new(ainxt_runtime::approval::AutoApprove),
            "sess-1",
            "alice",
        );
        assert!(
            rt.run_with_approvals(
                &m,
                &grant,
                &p,
                &RunContext::internal(),
                &FixedExecutor { tokens: 1 },
                &approve_resolver,
            )
            .is_completed(),
            "a live-gate Approve delivered through the adapter must let the assisted write proceed"
        );

        let reject_resolver = RuntimeApprovalGateResolver::new(
            std::sync::Arc::new(ainxt_runtime::approval::AutoReject(
                "no live approver".to_string(),
            )),
            "sess-2",
            "alice",
        );
        let rejected = rt.run_with_approvals(
            &m,
            &grant,
            &p,
            &RunContext::internal(),
            &FixedExecutor { tokens: 1 },
            &reject_resolver,
        );
        assert!(
            matches!(rejected, HarnessOutcome::ApprovalRejected { .. }),
            "a live-gate Reject delivered through the adapter must refuse the write, got {rejected}"
        );

        // `ApproveForSession` has no session concept in this crate's tri-state decision — the adapter
        // collapses it to a one-time Approve rather than inventing a wider grant nothing asked for.
        struct SessionApprover;
        impl ainxt_runtime::approval::ApprovalGate for SessionApprover {
            fn decide(
                &self,
                _req: &ainxt_runtime::approval::ApprovalRequest,
            ) -> ainxt_runtime::approval::ApprovalDecision {
                ainxt_runtime::approval::ApprovalDecision::ApproveForSession
            }
            fn is_policy_auto(&self) -> bool {
                false
            }
        }
        let session_resolver = RuntimeApprovalGateResolver::new(
            std::sync::Arc::new(SessionApprover),
            "sess-3",
            "alice",
        );
        assert_eq!(
            session_resolver.resolve(&ApprovalRequest {
                harness: "h".into(),
                step: "s1".into(),
                capability: "code.edit".into(),
            }),
            ApprovalDecision::Approve,
            "ApproveForSession must collapse to a one-time Approve, not be dropped/rejected"
        );
    }

    // ---- HARN-05: pre-receive gate can use the REAL detector, blocking what the heuristic misses ----

    #[test]
    fn gap_ainxt_admission_compliance_backed_prereceive_blocks_spaced_secret() {
        use ainxt_governance::{gate_push, MarkerPrereceiveGate, PrereceiveGate, PublishRequest};

        // A "real" PCI detector that normalizes separators before scanning for a 16-digit PAN — the
        // enterprise plugin's job. (The OSS RedactAndProceed + MarkerPrereceiveGate both only see
        // short digit runs and miss this.)
        struct SpacedPanDetector;
        impl ComplianceGate for SpacedPanDetector {
            fn scan(&self, text: &str, _dir: Direction) -> ainxt_runtime::compliance::Redacted {
                // Normalize away spaces/dashes, then look for the PAN — what the real detector does.
                let compact: String = text.chars().filter(|c| c.is_ascii_digit()).collect();
                let redactions = usize::from(compact.contains("4111111111111111"));
                ainxt_runtime::compliance::Redacted {
                    text: text.to_string(),
                    redactions,
                }
            }
        }

        // A manifest whose description carries a SPACED PAN.
        let pr = ainxt_governance::publish(PublishRequest {
            definition_id: "rca".into(),
            branch: "b".into(),
            path: "rca.md".into(),
            content: "id = \"rca\"\ndescription = \"card 4111 1111 1111 1111 on file\"".into(),
        });

        // The OSS marker heuristic MISSES the spaced PAN (max contiguous run is 4 digits).
        assert!(
            gate_push(&pr, &MarkerPrereceiveGate).is_ok(),
            "the marker heuristic is expected to miss a spaced PAN"
        );

        // The compliance-backed gate, wired to the real detector, BLOCKS it (never redacts — history
        // is permanent).
        let detector = SpacedPanDetector;
        let gate = ComplianceBackedPrereceiveGate::new(&detector);
        let findings = gate
            .check(&pr.files)
            .expect_err("real detector must block a spaced PAN");
        assert!(!findings.is_empty());
        assert!(findings[0].contains("blocked"));

        // And a clean push still passes.
        let clean = ainxt_governance::publish(PublishRequest {
            definition_id: "y".into(),
            branch: "b".into(),
            path: "y.md".into(),
            content: "id = \"y\"\ndescription = \"safe\"".into(),
        });
        assert!(gate.check(&clean.files).is_ok());
    }

    // ---- R4: the compliance gate runs on EVERY step result, before it feeds the next step ----

    #[test]
    fn r4_step_result_compliance_gate() {
        use ainxt_runtime::compliance::RedactAndProceed;
        let (rt, audit) = runtime();

        // Step 1 (a tool) leaks a raw 16-digit PAN in its result. Step 2 echoes back verbatim
        // whatever prior output the runtime handed it — so the assertion on step 2 proves what the
        // NEXT step actually saw.
        struct ChainExec;
        impl ChainingStepExecutor for ChainExec {
            fn execute_chained(
                &self,
                step: &HarnessStep,
                _p: &Principal,
                prior: &[StepResult],
            ) -> StepResult {
                if step.id == "s1" {
                    StepResult::new(5, "settlement row: PAN 4111111111111111 flagged")
                } else {
                    let seen = prior.last().map(|r| r.output.clone()).unwrap_or_default();
                    StepResult::new(3, format!("next-step-saw: {seen}"))
                }
            }
        }

        let m = manifest(
            &["tool.read", "tool.summarize"],
            vec![
                step("s1", "tool.read", StepKind::Tool),
                step("s2", "tool.summarize", StepKind::Tool),
            ],
        );
        let grant = CapabilityGrant::new(["tool.read", "tool.summarize"]);
        let p = Principal::user("u", &["tool.read", "tool.summarize"]);

        let report = rt.run_with_compliance(
            &m,
            &grant,
            &p,
            &RunContext::internal(),
            &ChainExec,
            &RedactAndProceed,
        );

        assert!(
            report.outcome.is_completed(),
            "must complete: {}",
            report.outcome
        );
        assert_eq!(report.results.len(), 2);

        // Step 1's raw PAN was redacted AT THE STEP-RESULT BOUNDARY (redact-and-proceed).
        assert!(
            report.results[0].output.contains("[REDACTED-PAN]"),
            "step-1 PAN must be redacted: {}",
            report.results[0].output
        );
        assert!(!report.results[0].output.contains("4111111111111111"));
        assert!(report.results[0].redactions >= 1);

        // Step 2 — the NEXT step — only ever saw the redacted output, never the raw PAN. This is the
        // load-bearing proof: the fix redacts each step result BEFORE it feeds the next step.
        assert!(
            report.results[1].output.contains("[REDACTED-PAN]"),
            "next step must have seen the redacted form: {}",
            report.results[1].output
        );
        assert!(
            !report.results[1].output.contains("4111111111111111"),
            "the raw PAN must never reach the next step: {}",
            report.results[1].output
        );

        assert!(report.total_redactions >= 1);
        // The redaction is auditable.
        assert!(
            audit
                .events()
                .iter()
                .any(|e| e.outcome == "executed-redacted"),
            "a redacted step must be audited"
        );
    }
}
