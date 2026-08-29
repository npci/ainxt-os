// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! ainxt-runtime — the AiNxt runtime core (P1 vertical slice).
//!
//! Implements the canonical turn pipeline from `RUNTIME_FEATURE_FLOWS.md`:
//!   authz (ADR-003) → compliance-IN (ADR-003) → data-class routing (ADR-012/006)
//!   → provider stream (event-enum seam) → compliance-OUT → audit (ADR-003).
//!
//! Enterprise invariants realized here:
//! * The mandatory gates (compliance, authz, audit) are **required constructor args** of
//!   [`Engine`] — there is no way to build the engine without them (ADR-003/004).
//! * Data-class exclusion is **non-overridable** in the router — even a forced provider
//!   must be eligible for the request's data class (ADR-012).
//!
//! Scope of this slice: synchronous, mock provider, no network. The `Provider` trait is
//! the seam where async + real HTTP providers slot in next (P1 increment 2), and the
//! event-enum seam is already the normalization boundary. Zero external dependencies.

use ainxt_guardrails::{GuardrailOutcome, RailChain};
use ainxt_injection::{
    guard_egress_for_turn, wrap_untrusted, EgressDecision, EgressPolicy, HeuristicInjectionScanner,
    InjectionMode, InjectionScanner, InjectionVerdict, Provenance, QuarantineBroker,
};
use ainxt_protocol::{budget_gate, BudgetOutcome, Event, Request};
// §4 EventEnvelope + §6 WireEvent vocabulary — emitted on the LIVE wire sink alongside the legacy
// `Event` (see the `wire` module). The full typed contract lives in `ainxt-protocol`.
use ainxt_protocol::{
    ApprovalDecision as WireApprovalDecision, ApprovalRespond, ComplianceAction, ErrorCategory,
    EventEnvelope, ProtocolError, ResultBlock, ToolSource, TurnOutcome as WireTurnOutcome,
    WireEvent,
};
use ainxt_telemetry::{
    NullTelemetry, PriceTable, TelemetrySink, TurnMetrics, TurnOutcome as TurnOutcomeKind,
};
use ainxt_tools::{ArgClassScanner, DispatchResult, EffectiveDataClass, RiskTier, ToolRuntime};
use ainxt_types::Principal;

// Re-export the guardrails + injection config surface so callers configure them through the runtime crate.
pub use ainxt_guardrails::{GuardrailsConfig, RailMode};
pub use ainxt_injection::{
    EgressDecision as EgressDecisionKind, EgressPolicy as EgressPolicyConfig, InjectionConfig,
    InjectionScanner as InjectionScannerTrait,
};
pub use ainxt_protocol::{budget_gate as protocol_budget_gate, BudgetOutcome as BudgetGateOutcome};
// Re-export the payment-boundary vocabulary so callers declare a tool's boundary through the runtime
// crate (the runtime's payment-boundary resolver returns this; the §9/ADR-016 human-approve invariant
// is enforced on the approval path via `ApprovalRespond::is_valid`).
pub use ainxt_protocol::PaymentBoundary;
pub use ainxt_telemetry::{
    TelemetryConfig, TelemetrySink as TelemetrySinkTrait, TurnMetrics as TurnMetricsRecord,
};

// ============================ Compliance (ADR-003) ============================
pub mod compliance {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Direction {
        Input,
        ToolArgs,
        ToolResult,
        Output,
    }

    #[derive(Debug, Clone)]
    pub struct Redacted {
        pub text: String,
        pub redactions: usize,
    }

    /// Runs on all input/output. Policy is redact-and-proceed (never hard-block).
    /// The default impl is a PLACEHOLDER detector; production plugs in the NPCI PCI/DSS
    /// engine (private enterprise plugin) via this same trait.
    pub trait ComplianceGate: Send + Sync {
        fn scan(&self, text: &str, dir: Direction) -> Redacted;
    }

    /// Placeholder redactor: collapses long digit runs (PAN-like) and the `PAN=` marker.
    /// Std-only; NOT the real detector — real recall comes from the enterprise plugin.
    pub struct RedactAndProceed;

    impl RedactAndProceed {
        fn redact(text: &str) -> (String, usize) {
            let mut out = String::with_capacity(text.len());
            let mut run = String::new();
            let mut count = 0usize;
            for c in text.chars() {
                if c.is_ascii_digit() {
                    run.push(c);
                    continue;
                }
                if !run.is_empty() {
                    if run.len() >= 12 {
                        out.push_str("[REDACTED-PAN]");
                        count += 1;
                    } else {
                        out.push_str(&run);
                    }
                    run.clear();
                }
                out.push(c);
            }
            if !run.is_empty() {
                if run.len() >= 12 {
                    out.push_str("[REDACTED-PAN]");
                    count += 1;
                } else {
                    out.push_str(&run);
                }
            }
            if out.contains("PAN=") {
                out = out.replace("PAN=", "[REDACTED]");
                count += 1;
            }
            (out, count)
        }
    }

    impl ComplianceGate for RedactAndProceed {
        fn scan(&self, text: &str, _dir: Direction) -> Redacted {
            let (text, redactions) = Self::redact(text);
            Redacted { text, redactions }
        }
    }
}

// ============================ Authorization (ADR-003) ============================
pub mod authz {
    use ainxt_types::{DataClass, Principal};

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Decision {
        Allow,
        Deny(String),
    }

    pub trait Authorizer: Send + Sync {
        fn authorize(&self, principal: &Principal, capability: &str) -> Decision;

        /// OBO **layer 2** (ADR-003 §1.6): the actual OAuth/connector scope the *user's own*
        /// credential covers for this tool — "a harness cannot grant what the user's own
        /// credential doesn't cover." Returning `None` means this tool has no connector-scope
        /// requirement configured (e.g. a purely native, non-connector capability); returning
        /// `Some(scope)` means the principal's [`Principal::connector_scopes`] MUST contain that
        /// scope literal. Default: no requirement for any tool — back-compat for authorizers that
        /// don't model connector scopes. A real deployment overrides this to map connector-backed
        /// tools (`connector.gitlab.*`, `connector.graph.*`) to their required OAuth scope.
        fn required_connector_scope(&self, _tool: &str) -> Option<&str> {
            None
        }

        /// OBO **layer 3** (ADR-003 §1.6): resource-level ABAC — the resource's own data-class
        /// must be within the principal's [`Principal::clearance`]. Returning `None` means the
        /// resource's data-class is unknown/unclassified to this authorizer (no ABAC opinion, not
        /// evaluated). Default: no classification for any resource — back-compat. A real
        /// deployment overrides this with a lookup against the resource's stored data-class.
        fn resource_data_class(&self, _tool: &str, _resource: &str) -> Option<DataClass> {
            None
        }

        /// Fine-grained, **on-behalf-of** tool+resource authorization (ADR-003, confused-deputy
        /// defense). Before ANY tool dispatch the engine asks: may THIS principal invoke THIS tool
        /// on THIS resource? — using the *user's* authority, never the runtime's own broad creds.
        ///
        /// Evaluated against three INDEPENDENT layers, ALL of which must pass (§1.6): (1) the
        /// declared capability grant below, (2) [`Self::required_connector_scope`], and (3)
        /// [`Self::resource_data_class`] vs. `principal.clearance`. A capability grant alone
        /// (layer 1) is never sufficient on its own — a broad `tool.*` grant cannot substitute for
        /// a connector scope the user's own credential lacks, nor for clearance on a resource
        /// whose data-class exceeds it. The check is MANDATORY (always runs); only the *policy*
        /// (layers 2/3 overrides) is configurable.
        fn authorize_tool(
            &self,
            principal: &Principal,
            tool: &str,
            resource: Option<&str>,
        ) -> Decision {
            // Layer 1: declared capability grant (tool-wide, or resource-scoped least-privilege).
            let base = format!("tool.{tool}");
            let layer1 = if let Decision::Allow = self.authorize(principal, &base) {
                true // broad grant covers all resources / resource-less tools
            } else if let Some(res) = resource {
                let scoped = format!("tool.{tool}:{res}");
                matches!(self.authorize(principal, &scoped), Decision::Allow)
            } else {
                false
            };
            if !layer1 {
                // Do NOT echo the resource value — it may be a sensitive id (account/PAN). The
                // model already knows which resource it requested; the audit sink and the
                // model-facing message must not leak it.
                return match resource {
                    Some(_) => Decision::Deny(format!(
                        "principal '{}' not authorized for tool '{tool}' on the requested resource",
                        principal.user_id
                    )),
                    None => Decision::Deny(format!(
                        "principal '{}' lacks capability '{base}'",
                        principal.user_id
                    )),
                };
            }

            // Layer 2: issued connector scope — a grant cannot exceed what the user's own
            // credential was actually issued.
            if let Some(required_scope) = self.required_connector_scope(tool) {
                if !principal
                    .connector_scopes
                    .iter()
                    .any(|s| s == required_scope)
                {
                    return Decision::Deny(format!(
                        "principal '{}' has a grant for tool '{tool}' but the issued connector \
                         credential does not cover required scope '{required_scope}'",
                        principal.user_id
                    ));
                }
            }

            // Layer 3: resource-level ABAC — the resource's data-class must be within clearance.
            if let Some(res) = resource {
                if let Some(res_class) = self.resource_data_class(tool, res) {
                    if res_class > principal.clearance {
                        return Decision::Deny(format!(
                            "principal '{}' clearance is insufficient for the requested \
                             resource's data-class on tool '{tool}'",
                            principal.user_id
                        ));
                    }
                }
            }

            Decision::Allow
        }
    }

    /// Capability-based RBAC. Production plugs in AD-RBAC via this trait.
    pub struct RbacAuthorizer;

    impl Authorizer for RbacAuthorizer {
        fn authorize(&self, p: &Principal, capability: &str) -> Decision {
            if p.has_cap(capability) {
                Decision::Allow
            } else {
                Decision::Deny(format!(
                    "principal '{}' lacks capability '{capability}'",
                    p.user_id
                ))
            }
        }
    }
}

// ============================ Audit (ADR-003) ============================
pub mod audit {
    use std::sync::Mutex;

    #[derive(Debug, Clone)]
    pub struct AuditRecord {
        pub session: String,
        pub turn: String,
        pub actor: String,
        pub summary: String,
    }

    pub trait AuditSink: Send + Sync {
        fn record(&self, rec: AuditRecord);
    }

    /// In-memory audit sink (tests / dev). Production plugs in the tamper-evident sink.
    #[derive(Default)]
    pub struct InMemoryAudit {
        pub records: Mutex<Vec<AuditRecord>>,
    }

    impl InMemoryAudit {
        pub fn len(&self) -> usize {
            self.records.lock().expect("audit lock").len()
        }
        pub fn is_empty(&self) -> bool {
            self.len() == 0
        }
    }

    impl AuditSink for InMemoryAudit {
        fn record(&self, rec: AuditRecord) {
            self.records.lock().expect("audit lock").push(rec);
        }
    }
}

// ============================ Provider (event-enum seam, ADR-006) ============================
pub mod provider {
    use ainxt_protocol::Event;
    use ainxt_types::{DataClass, Tier};

    /// A model provider. `stream` returns the normalized event enum — the seam every
    /// vendor is adapted into. Sync in this slice; the async adapter lands next.
    pub trait Provider: Send + Sync {
        fn id(&self) -> &str;
        /// Whether this provider may serve the given data class (ADR-012).
        fn eligible(&self, data_class: DataClass) -> bool;
        /// The capability tier this provider serves (BE: route by reasoning depth). `None` = it
        /// serves any tier (the default; tier is then a non-factor in selection).
        fn tier(&self) -> Option<Tier> {
            None
        }
        /// The RBI outsourcing-register route id (`outsourcing.cloud.<provider>.<route>`) when this
        /// provider is an EXTERNAL / outsourced route subject to the register (FI-03). `None` (the
        /// default) = an on-prem / in-house route, which is not an outsourcing arrangement and is
        /// therefore not gated by the register. When `Some`, the router's non-overridable eligibility
        /// step consults [`OutsourcingRegister::eligibility`](ainxt_responsibleai::outsourcing::OutsourcingRegister::eligibility)
        /// and excludes the route BEFORE ranking if it is not registered/eligible for the request's
        /// data class + residency. It also keys the SR-11-7 model-risk lookup (FI-07).
        fn outsourcing_route(&self) -> Option<&str> {
            None
        }
        /// Start streaming: returns immediately with a bounded receiver of normalized events;
        /// the provider produces them on a spawned task (backpressure via the bounded channel).
        /// The sync signature keeps the trait object-safe for `dyn Provider`.
        fn stream(&self, prompt: &str) -> tokio::sync::mpsc::Receiver<Event>;
    }
}

// ============================ Model Router (ADR-006/012) ============================
pub mod router {
    use super::provider::Provider;
    use ainxt_responsibleai::outsourcing::{derive_route_id, OutsourcingRegister};
    use ainxt_responsibleai::{
        route_promotable, DueDiligenceConfig, ModelRiskRecord, QualityCircuitBreaker,
    };
    use ainxt_types::{DataClass, Tier};
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Arc;

    /// How the router decides whether a candidate is an EXTERNAL/outsourced route (subject to the FI-03
    /// register) or an in-house/on-prem route (exempt) — the §3.2 "no ungoverned outsourcing can ever
    /// route" invariant hinges on this classification being trustworthy.
    #[derive(Clone)]
    enum ExternalityClassifier {
        /// Legacy, fail-OPEN: trust the provider's own [`Provider::outsourcing_route`] self-declaration.
        /// A provider that returns `None` is taken at its word as in-house and is NOT gated. Retained
        /// only for back-compat / non-regulated deployments that opt into it via
        /// [`ModelRouter::with_outsourcing_register`]. The danger: a genuinely external cloud provider
        /// whose adapter forgot to declare a route id slips past the register as if it were in-house.
        SelfDeclared,
        /// Fail-CLOSED (FI-03 §3.2): externality is decided AUTHORITATIVELY at the composition edge, not
        /// on the adapter's say-so. Every provider is treated as an external/outsourced route — its
        /// register route id derived deterministically as [`derive_route_id`]`(provider_id)` — UNLESS its
        /// id is in `in_house`, the explicit, signed on-prem exemption set. Consequences:
        /// - a provider that self-declares in-house (`outsourcing_route() == None`) but is not on the
        ///   signed exemption list is STILL treated as external and refused until registered;
        /// - a route with no board-approved register entry is [`Eligibility::NoRegisterEntry`] ⇒ excluded.
        ///
        /// This is the posture the shipped daemon installs: cloud-kind providers are never exempt, so an
        /// unregistered/self-declared cloud route cannot route.
        Authoritative { in_house: BTreeSet<String> },
    }

    impl ExternalityClassifier {
        /// The register route id to gate this provider against, or `None` if the provider is an exempt
        /// in-house/on-prem route. Under [`Authoritative`](Self::Authoritative) the provider's own
        /// self-declaration is IGNORED — externality is by construction.
        fn route_id_for(&self, p: &dyn Provider) -> Option<String> {
            match self {
                ExternalityClassifier::SelfDeclared => p.outsourcing_route().map(|s| s.to_string()),
                ExternalityClassifier::Authoritative { in_house } => {
                    if in_house.contains(p.id()) {
                        None // an explicit, signed on-prem exemption — not an outsourcing arrangement.
                    } else {
                        Some(derive_route_id(p.id())) // external by construction; must be registered.
                    }
                }
            }
        }
    }

    /// A logical clock the governance guards read for time-dependent checks (exit-rehearsal staleness,
    /// FI-03; monitoring staleness, FI-07). Injectable so tests are deterministic; production passes a
    /// wall-clock closure.
    pub type RouterClock = Arc<dyn Fn() -> u64 + Send + Sync>;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum RouteError {
        /// No registered provider is eligible for this data class.
        NoEligible(DataClass),
        /// A provider was forced but is not eligible for this data class (gate is non-overridable).
        ForcedNotEligible(String, DataClass),
    }

    /// FI-03 — RBI IT/cloud-outsourcing register as the router's **non-overridable** eligibility
    /// input (§3). An EXTERNAL/outsourced route (one whose [`Provider::outsourcing_route`] is `Some`)
    /// is admissible ONLY if the register says it is eligible for the request's data class + residency
    /// at `now`: an unregistered route, a route below the request's class, a residency mismatch, an
    /// untested exit plan (regulated request), or a sub-processor drift is excluded BEFORE ranking and
    /// BEFORE failover — so no ungoverned outsourcing can ever route.
    struct OutsourcingGuard {
        // GAP-FIX regulated-fi-responsible-lifecycle — `Arc<RwLock<..>>`, NOT an owned value: the
        // register was previously ownership-trapped inside the router with no way for anything outside
        // it (an admin route) to ever mutate a live instance — `OutsourcingRegister::upsert` had ZERO
        // callers beyond this crate's own tests. Wrapping it here (still installed as a plain owned
        // value by every existing `with_outsourcing_register*` caller — see those methods) lets
        // [`ModelRouter::outsourcing_register_handle`] hand out a SHARED clone of the SAME Arc this
        // guard reads for every eligibility check, so a served admin route mutates the identical
        // instance the router's non-overridable FI-03 gate consults — never a second, disjoint copy.
        // Reads (the hot per-request eligibility path) take a brief `read()` lock; admin mutations
        // (`upsert`/`reapprove`, a rare "board-approved PR landed" event) take `write()`.
        register: Arc<std::sync::RwLock<OutsourcingRegister>>,
        residency: String,
        clock: RouterClock,
        /// How externality is decided (fail-OPEN self-declaration vs fail-CLOSED authoritative). The
        /// shipped daemon installs [`ExternalityClassifier::Authoritative`].
        classifier: ExternalityClassifier,
    }

    /// FI-07 — SR-11-7 model-risk / quality guard (§2.1/§4.2). A route with a model-risk record is
    /// excluded from selection when its live quality scoreboard has tripped the
    /// [`QualityCircuitBreaker`], or when [`route_promotable`] (algorithmic due-diligence) fails at
    /// `now` — so a degraded or un-certified route is never selected ("monitored, not certified-once"
    /// enforced live). Routes without a record are not gated (in-house defaults).
    struct QualityGuard {
        records: BTreeMap<String, ModelRiskRecord>,
        breaker: QualityCircuitBreaker,
        dd_cfg: DueDiligenceConfig,
        clock: RouterClock,
    }

    #[derive(Default)]
    pub struct ModelRouter {
        providers: Vec<Box<dyn Provider>>,
        /// FI-03 outsourcing-register guard (`None` = not configured → external routes are NOT gated,
        /// preserving pre-wire behavior for deployments without a register).
        outsourcing: Option<OutsourcingGuard>,
        /// FI-07 model-risk / quality guard (`None` = not configured → routes are not quality-gated).
        quality: Option<QualityGuard>,
        /// `PROMPT_ENGINEERING.md` §9 steerability guard (`None` = not configured → routes are not
        /// steerability-gated, preserving pre-wire behavior). See [`with_steerability_gate`](Self::with_steerability_gate).
        steerability_eligible: Option<BTreeSet<String>>,
        /// GAP-FIX misc-decisions (config's `ModelsConfig::auto_routable`/`user_selectable` — the
        /// platform's `core/model_registry.py` BLOCKED_MODELS/USER-SELECTABLE policy in config form) —
        /// the ids the complexity→tier AUTO-router may pick with no explicit selection. `None` (never
        /// installed) preserves pre-wire behavior: every route admissible under
        /// [`route_admissible`](Self::route_admissible) is
        /// auto-routable, exactly as before this gate existed. Once installed (see
        /// [`with_auto_routable`](Self::with_auto_routable)), a route absent from the set is excluded
        /// ONLY from the unforced/automatic path — a `forced` selection (a Role's `allowed_providers`,
        /// or an end-user's explicit model choice, i.e. `ModelsConfig::user_selectable`) still reaches
        /// it, mirroring the config's own auto_routable-vs-user_selectable split. This is layered ON TOP
        /// of — never a replacement for — the non-overridable data-class/governance/steerability gate:
        /// a route excluded by `route_admissible` is never reachable by ANY path, forced or not.
        auto_routable: Option<BTreeSet<String>>,
    }

    impl ModelRouter {
        pub fn new() -> Self {
            ModelRouter {
                providers: Vec::new(),
                outsourcing: None,
                quality: None,
                steerability_eligible: None,
                auto_routable: None,
            }
        }
        pub fn register(&mut self, p: Box<dyn Provider>) {
            self.providers.push(p);
        }

        /// Install the **steerability eligibility gate** (`PROMPT_ENGINEERING.md` §9: "a model family
        /// whose best-achievable steerability score is below the Role's minimum bar is not eligible for
        /// that Role regardless of raw capability — steerability gates model eligibility, same as
        /// data-class does"). `eligible_ids` is the set of provider ids the caller has ALREADY certified
        /// via `ainxt_prompt::steerability::is_eligible(score, role_min_bar)` for the Role/task currently
        /// being served.
        ///
        /// This crate deliberately never depends on `ainxt-prompt` (that edge would cycle back through
        /// `ainxt-prompt -> ainxt-eval -> ainxt-runtime`), so the gate is a plain `id -> eligible` set
        /// rather than a `SteerabilityScore` type — the caller (a crate that legitimately depends on both,
        /// e.g. `ainxt-chat`) computes the scoring and hands this router only the resulting boolean
        /// membership, exactly the same shape `with_outsourcing_register`/`with_quality_guard` already use
        /// for FI-03/FI-07 (inject the decision input, gate lives here in the non-overridable chain).
        ///
        /// `None` (never called) preserves pre-wire behavior: no route is excluded on steerability
        /// grounds. Once installed, a provider absent from `eligible_ids` is excluded — no recorded
        /// evidence is never treated as a pass, mirroring `is_eligible`'s own "no evidence is never
        /// eligible" rule.
        pub fn with_steerability_gate(
            mut self,
            eligible_ids: impl IntoIterator<Item = String>,
        ) -> Self {
            self.steerability_eligible = Some(eligible_ids.into_iter().collect());
            self
        }

        /// Install the config's auto-routable set (`ModelsConfig::auto_routable`) — the ids the
        /// complexity→tier AUTO-router may pick with no explicit selection. Restricts ONLY
        /// [`select`](Self::select)/[`select_chain`](Self::select_chain)/[`select_chain_graded`](Self::select_chain_graded)'s
        /// unforced path and [`eligible_ids`](Self::eligible_ids) (both describe what the router would
        /// pick on its own); a `forced` id is unaffected by this gate — it is still checked against the
        /// full [`route_admissible`](Self::route_admissible) set only, so an explicitly-selected
        /// user-selectable-only model (or a Role's configured `allowed_providers`) keeps working exactly
        /// as `ModelsConfig::user_selectable` describes. `ids` absent from the router's registered
        /// providers (e.g. a registry entry with no matching wired provider) are harmless no-ops.
        pub fn with_auto_routable(mut self, ids: impl IntoIterator<Item = String>) -> Self {
            self.auto_routable = Some(ids.into_iter().collect());
            self
        }

        /// Install the FI-03 RBI outsourcing register as the non-overridable router-eligibility input
        /// for external/outsourced routes, resolved for `residency` (the deployment's data-residency
        /// label) at the injected `clock`.
        pub fn with_outsourcing_register(
            mut self,
            register: OutsourcingRegister,
            residency: impl Into<String>,
            clock: RouterClock,
        ) -> Self {
            self.outsourcing = Some(OutsourcingGuard {
                register: Arc::new(std::sync::RwLock::new(register)),
                residency: residency.into().to_ascii_lowercase(),
                clock,
                classifier: ExternalityClassifier::SelfDeclared,
            });
            self
        }

        /// FI-03 §3.2 fail-CLOSED install: the RBI outsourcing register as the non-overridable
        /// eligibility input, with externality decided **authoritatively** — every provider is an
        /// external/outsourced route (register-gated by [`derive_route_id`]`(id)`) UNLESS its id is in
        /// `in_house`, the explicit signed on-prem exemption set. A provider's own `outsourcing_route()`
        /// self-declaration is IGNORED, so a cloud route that (accidentally or maliciously) declares
        /// itself in-house is still refused until a board-approved arrangement is registered. This is the
        /// posture the shipped daemon installs: no ungoverned outsourcing can ever route.
        pub fn with_outsourcing_register_authoritative(
            mut self,
            register: OutsourcingRegister,
            residency: impl Into<String>,
            clock: RouterClock,
            in_house: impl IntoIterator<Item = String>,
        ) -> Self {
            self.outsourcing = Some(OutsourcingGuard {
                register: Arc::new(std::sync::RwLock::new(register)),
                residency: residency.into().to_ascii_lowercase(),
                clock,
                classifier: ExternalityClassifier::Authoritative {
                    in_house: in_house.into_iter().collect(),
                },
            });
            self
        }

        /// GAP-FIX regulated-fi-responsible-lifecycle — a SHARED, mutable handle onto the SAME
        /// outsourcing register [`governance_admits`](Self::governance_admits) reads for every
        /// eligibility check, when one is installed. This is what makes a served admin route (register/
        /// replace/re-approve an arrangement after a board-approved PR lands) possible at all: before
        /// this accessor, the register was ownership-trapped inside the router with no external handle,
        /// so [`ainxt_responsibleai::outsourcing::OutsourcingRegister::upsert`] had zero callers outside
        /// this crate's own tests. `None` when no register is installed (unconfigured deployment).
        pub fn outsourcing_register_handle(
            &self,
        ) -> Option<Arc<std::sync::RwLock<OutsourcingRegister>>> {
            self.outsourcing.as_ref().map(|g| g.register.clone())
        }

        /// Install the FI-07 SR-11-7 model-risk guard: per-route model-risk records, the live quality
        /// circuit-breaker, and the due-diligence config, resolved at the injected `clock`.
        pub fn with_quality_guard(
            mut self,
            records: BTreeMap<String, ModelRiskRecord>,
            breaker: QualityCircuitBreaker,
            dd_cfg: DueDiligenceConfig,
            clock: RouterClock,
        ) -> Self {
            self.quality = Some(QualityGuard {
                records,
                breaker,
                dd_cfg,
                clock,
            });
            self
        }

        /// GAP-AUDIT tooling-mcp-plugins-routing — "Model-router ranking not fed a signal": the live
        /// FI-07 monitoring scoreboard ([`ModelRiskRecord::monitoring`]) was consulted ONLY for binary
        /// admission (§4.3's exclusion half, via [`Self::governance_admits`]) — its continuous
        /// `latest_score` never reached [`Self::select_chain_graded`]'s ranking step. The one real call
        /// site ([`Engine::run_turn`]'s pinned-tier path) passed a permanently-EMPTY `BTreeMap` as
        /// `metrics`, so every eligible candidate scored as the neutral default and the chain order was
        /// pure alphabetical tie-break — "ranking" that never actually looked at quality. This builds
        /// the graded-ranking metrics map from the SAME live scoreboard already used for admission (no
        /// new signal invented — the seam already existed and was already trustworthy), scaling
        /// `latest_score` (0.0..=1.0) to [`RouteMetrics::quality_score`] (0..=100). Keyed by
        /// [`Provider::id`] (what [`Self::select_chain_graded`]'s ranker looks up), resolved through the
        /// same `outsourcing_route().unwrap_or(id())` indirection [`Self::governance_admits`] uses to
        /// find each provider's record — a provider with a distinct outsourcing route id is still
        /// matched correctly. `cost`/`latency` are left at the neutral default (0) here: this closes
        /// the quality half of the signal; a harness-supplied cost/latency table composes on top via
        /// the same map without disturbing this.
        pub fn live_quality_metrics(&self) -> BTreeMap<String, RouteMetrics> {
            let mut out = BTreeMap::new();
            let Some(guard) = &self.quality else {
                return out;
            };
            for p in &self.providers {
                let key = p.outsourcing_route().unwrap_or_else(|| p.id());
                if let Some(record) = guard.records.get(key) {
                    if let Some(board) = &record.monitoring {
                        let score = (board.latest_score.clamp(0.0, 1.0) * 100.0).round() as u32;
                        out.insert(
                            p.id().to_string(),
                            RouteMetrics {
                                quality_score: score,
                                cost: 0,
                                latency: 0,
                            },
                        );
                    }
                }
            }
            out
        }

        /// The governance exclusion (FI-03 + FI-07), applied as part of the NON-overridable
        /// eligibility step — BEFORE ranking and BEFORE failover, and it gates a forced route too.
        /// Returns `true` if the route is admissible under both guards.
        fn governance_admits(&self, p: &dyn Provider, data_class: DataClass) -> bool {
            // FI-03: the RBI outsourcing register governs EXTERNAL/outsourced routes. Externality is
            // decided by the guard's classifier — under the fail-CLOSED (authoritative) posture the
            // provider's own self-declaration is ignored, so an ungoverned cloud route cannot slip past.
            if let Some(g) = &self.outsourcing {
                if let Some(route_id) = g.classifier.route_id_for(p) {
                    let now = (g.clock)();
                    // Fail-closed on a poisoned lock (an admin-route panic mid-write must never leave
                    // every subsequent eligibility check silently open) — same posture as every other
                    // guard in this function.
                    let eligible = g
                        .register
                        .read()
                        .map(|reg| {
                            reg.eligibility(&route_id, data_class, &g.residency, now)
                                .is_eligible()
                        })
                        .unwrap_or(false);
                    if !eligible {
                        return false;
                    }
                }
            }
            // FI-07: SR-11-7 model-risk record → quality circuit-breaker + promotion due-diligence.
            // Key by the outsourcing route id when present (the register/model-risk share a route id),
            // else by the provider id.
            if let Some(g) = &self.quality {
                let key = p.outsourcing_route().unwrap_or_else(|| p.id());
                if let Some(record) = g.records.get(key) {
                    if g.breaker.evaluate(record).is_open() {
                        return false; // tripped circuit-breaker — do not select a degraded route
                    }
                    let now = (g.clock)();
                    if !route_promotable(record, &g.dd_cfg, now).is_passed() {
                        return false; // failed algorithmic due-diligence — not certified to serve
                    }
                }
            }
            true
        }

        /// The steerability admission step (§9): `true` when no gate is installed (pre-wire behavior),
        /// else `true` only if `p.id()` is in the caller-certified eligible set.
        fn steerability_admits(&self, p: &dyn Provider) -> bool {
            match &self.steerability_eligible {
                None => true,
                Some(ids) => ids.contains(p.id()),
            }
        }

        /// The AUTO-routing admission step (config's `ModelsConfig::auto_routable`): `true` when no
        /// gate is installed (pre-wire behavior — every admissible route is auto-routable), else `true`
        /// only if `p.id()` is in the installed auto-routable set. This is deliberately NOT part of
        /// [`route_admissible`](Self::route_admissible) — it gates only the unforced path, never a
        /// `forced` selection, so a user-selectable-only model stays reachable by explicit choice.
        fn auto_routable_admits(&self, p: &dyn Provider) -> bool {
            match &self.auto_routable {
                None => true,
                Some(ids) => ids.contains(p.id()),
            }
        }

        /// The full NON-overridable admission test: data-class exclusion (ADR-012), governance
        /// (FI-03 outsourcing register + FI-07 model-risk/quality), AND — when installed — the §9
        /// steerability gate. No route that fails any of these is ever returned by
        /// [`select`](Self::select), [`select_chain`](Self::select_chain), or listed by
        /// [`eligible_ids`](Self::eligible_ids) — forced or not. (The separate
        /// [`auto_routable_admits`](Self::auto_routable_admits) gate narrows the UNFORCED path further;
        /// it is applied by each caller after this, never folded in here, so a `forced` id is only ever
        /// checked against this set.)
        fn route_admissible(&self, p: &dyn Provider, data_class: DataClass) -> bool {
            p.eligible(data_class)
                && self.governance_admits(p, data_class)
                && self.steerability_admits(p)
        }

        /// The ids of every provider admissible for `data_class` for **auto-routing** — data-class
        /// exclusion + governance (same non-overridable test as
        /// [`select`](Self::select)/[`select_chain`](Self::select_chain)), narrowed to the config's
        /// auto-routable set (`ModelsConfig::auto_routable` — excludes user-selectable-only and blocked
        /// models, same as `select`'s own unforced path), in registration order. Gap context-fabric
        /// (budget-fit fake eligible list): this is the seam a caller builds the served window's REAL
        /// `eligible: Vec<EligibleModel>` from, instead of a single hardcoded placeholder id — the
        /// two-phase budget fit then floors to whatever this router would actually AUTO-route to for
        /// the turn's data class, not an unrelated fake model or a model only reachable by explicit
        /// user selection.
        pub fn eligible_ids(&self, data_class: DataClass) -> Vec<String> {
            self.providers
                .iter()
                .filter(|p| self.route_admissible(p.as_ref(), data_class))
                .filter(|p| self.auto_routable_admits(p.as_ref()))
                .map(|p| p.id().to_string())
                .collect()
        }

        /// Select a provider. **Data-class exclusion + governance run FIRST and cannot be overridden**
        /// (ADR-012 / FI-03 / FI-07): the eligible set is computed before anything else, and even a
        /// forced provider must be inside it. There is no code path that reaches an inadmissible one.
        /// An UNFORCED selection is further narrowed to the config's auto-routable set (see
        /// [`with_auto_routable`](Self::with_auto_routable)) — a `forced` id (a Role's
        /// `allowed_providers`, or an end-user's explicit model choice) is exempt from that narrowing,
        /// exactly mirroring `ModelsConfig::auto_routable` vs. `ModelsConfig::user_selectable`.
        pub fn select(
            &self,
            data_class: DataClass,
            forced: Option<&str>,
        ) -> Result<&dyn Provider, RouteError> {
            let eligible: Vec<&Box<dyn Provider>> = self
                .providers
                .iter()
                .filter(|p| self.route_admissible(p.as_ref(), data_class))
                .collect();

            if let Some(id) = forced {
                return eligible
                    .into_iter()
                    .find(|p| p.id() == id)
                    .map(|p| p.as_ref())
                    .ok_or_else(|| RouteError::ForcedNotEligible(id.to_string(), data_class));
            }
            eligible
                .into_iter()
                .find(|p| self.auto_routable_admits(p.as_ref()))
                .map(|p| p.as_ref())
                .ok_or(RouteError::NoEligible(data_class))
        }

        /// The ORDERED failover chain of eligible providers for a data class (data-class exclusion +
        /// governance applied first, non-overridable). A forced provider yields a single-element chain
        /// (still gated, and exempt from the auto-routable narrowing below). `preferred` (BE
        /// reasoning-depth → tier) reorders the eligible set so providers matching that tier are tried
        /// FIRST — a graceful preference: if none match, order is unchanged, and neither the data-class
        /// gate nor governance is ever weakened. The engine tries the chain in order until one succeeds;
        /// no path reaches an inadmissible provider. An UNFORCED chain is further narrowed to the
        /// config's auto-routable set (see [`with_auto_routable`](Self::with_auto_routable)) — a
        /// user-selectable-only model never appears in an automatic failover chain, only in a `forced`
        /// one.
        pub fn select_chain(
            &self,
            data_class: DataClass,
            forced: Option<&str>,
            preferred: Option<Tier>,
        ) -> Result<Vec<&dyn Provider>, RouteError> {
            let mut eligible: Vec<&dyn Provider> = self
                .providers
                .iter()
                .filter(|p| self.route_admissible(p.as_ref(), data_class))
                .map(|p| p.as_ref())
                .collect();

            if let Some(id) = forced {
                let found = eligible
                    .into_iter()
                    .find(|p| p.id() == id)
                    .ok_or_else(|| RouteError::ForcedNotEligible(id.to_string(), data_class))?;
                return Ok(vec![found]);
            }
            eligible.retain(|p| self.auto_routable_admits(*p));
            if eligible.is_empty() {
                return Err(RouteError::NoEligible(data_class));
            }
            if let Some(t) = preferred {
                // Stable sort: tier-matching providers move to the front, others keep their order.
                eligible.sort_by_key(|p| if p.tier() == Some(t) { 0 } else { 1 });
            }
            Ok(eligible)
        }

        /// §4.1 step 1 — **tier eligibility as a HARD filter** (gap: "Router tier eligibility as hard
        /// filter"). Unlike [`select_chain`](Self::select_chain)'s `preferred`, which only *reorders*
        /// (a graceful preference), this EXCLUDES any provider whose tier does not match `tier` from
        /// the eligible set entirely — a task-type pinned to a policy tier can never fall through to
        /// an off-tier model. A provider that declares `tier() == None` ("serves any tier") stays
        /// eligible for every tier (it is not off-tier — it is un-tiered). The data-class + governance
        /// gate still runs FIRST and is never weakened; this narrows *within* the admissible set.
        fn tier_eligible(eligible: Vec<&dyn Provider>, tier: Option<Tier>) -> Vec<&dyn Provider> {
            match tier {
                None => eligible,
                // A provider matches if it is un-tiered (serves any tier) or its tier == t.
                Some(t) => eligible
                    .into_iter()
                    .filter(|p| p.tier().is_none() || p.tier() == Some(t))
                    .collect(),
            }
        }

        /// §4.1 step 4 + §4.3/§4.5 — **cost/latency/quality-graded ranking** over the eligible set,
        /// with **tier as a hard filter** (§4.1 step 1). This is the router's "exclude what is not
        /// allowed, THEN rank what remains" contract made concrete:
        ///
        /// 1. `eligible` = data-class + governance-admissible providers (non-overridable, computed
        ///    FIRST exactly as [`select_chain`](Self::select_chain) does — quality/cost preference can
        ///    never reach into the excluded set);
        /// 2. HARD tier filter to `require_tier` (§4.1 step 1, [`tier_eligible`](Self::tier_eligible));
        /// 3. rank the survivors by a weighted score of `metrics` — **quality up, cost down, latency
        ///    down** — with `weights` supplied per harness policy (§4.1 step 4). A candidate with a
        ///    warm prompt cache is modeled as a lower `latency`/`cost` in `metrics` (§4.5), so
        ///    cache-warm candidates naturally sort ahead of otherwise-tied ones. A provider absent
        ///    from `metrics` scores as the neutral default and sorts after any scored peer, ties
        ///    broken by id for determinism.
        ///
        /// A `forced` id must itself survive steps 1–2 (a forced off-tier or class-excluded provider
        /// is [`RouteError::ForcedNotEligible`]); it then yields a single-element chain. The returned
        /// chain is the ordered failover list, every element class-eligible (§4.4) — there is no code
        /// path by which a data-class-excluded or off-tier model can be reached by walking it.
        pub fn select_chain_graded(
            &self,
            data_class: DataClass,
            forced: Option<&str>,
            require_tier: Option<Tier>,
            metrics: &BTreeMap<String, RouteMetrics>,
            weights: &RankWeights,
        ) -> Result<Vec<&dyn Provider>, RouteError> {
            // Step 1: non-overridable data-class + governance admission, FIRST.
            let admissible: Vec<&dyn Provider> = self
                .providers
                .iter()
                .filter(|p| self.route_admissible(p.as_ref(), data_class))
                .map(|p| p.as_ref())
                .collect();
            // Step 2: hard tier filter.
            let mut eligible = Self::tier_eligible(admissible, require_tier);

            if let Some(id) = forced {
                let found = eligible
                    .into_iter()
                    .find(|p| p.id() == id)
                    .ok_or_else(|| RouteError::ForcedNotEligible(id.to_string(), data_class))?;
                return Ok(vec![found]);
            }
            // Unforced: narrow further to the config's auto-routable set (see
            // `with_auto_routable`) — a user-selectable-only model is never reached by graded
            // auto-ranking, only by an explicit `forced` selection above.
            eligible.retain(|p| self.auto_routable_admits(*p));
            if eligible.is_empty() {
                return Err(RouteError::NoEligible(data_class));
            }
            // Step 3: graded ranking. Best (highest score) first; deterministic tie-break by id.
            eligible.sort_by(|a, b| {
                let sa = weights.score(metrics.get(a.id()));
                let sb = weights.score(metrics.get(b.id()));
                sb.cmp(&sa).then_with(|| a.id().cmp(b.id()))
            });
            Ok(eligible)
        }
    }

    /// Per-route cost/latency/quality metrics the graded ranker consumes (§4.1 step 4). Sourced per
    /// harness policy + the live eval-quality scoreboard (§4.3); prompt-cache warmth (§4.5) is folded
    /// in by lowering `cost`/`latency` for a cache-warm candidate. All are relative units.
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub struct RouteMetrics {
        /// Higher is better (e.g. 0..=100 live judge score for the task type).
        pub quality_score: u32,
        /// Lower is better (relative money per call; a cache-warm candidate reports less).
        pub cost: u64,
        /// Lower is better (relative latency ms; a cache-warm candidate reports less).
        pub latency: u64,
    }

    /// Ranking weights, per harness policy (§4.1 step 4: "weights per harness policy"). The score is
    /// `quality*w_quality - cost*w_cost - latency*w_latency` — quality up, cost/latency down.
    #[derive(Debug, Clone, Copy)]
    pub struct RankWeights {
        pub quality: i64,
        pub cost: i64,
        pub latency: i64,
    }

    impl Default for RankWeights {
        /// A sensible default: quality dominates, then cost, then latency.
        fn default() -> Self {
            RankWeights {
                quality: 100,
                cost: 10,
                latency: 1,
            }
        }
    }

    impl RankWeights {
        /// The weighted score for a candidate's metrics (neutral default when it has none). Higher =
        /// preferred. Saturating arithmetic so extreme metrics cannot overflow the ordering key.
        fn score(&self, metrics: Option<&RouteMetrics>) -> i64 {
            let m = metrics.copied().unwrap_or_default();
            let q = self.quality.saturating_mul(m.quality_score as i64);
            let c = self.cost.saturating_mul(m.cost as i64);
            let l = self.latency.saturating_mul(m.latency as i64);
            q.saturating_sub(c).saturating_sub(l)
        }
    }
}

// ============================ Complexity classifier (BE, §4.1 tier derivation) ============================
pub mod complexity {
    //! In-engine, model-agnostic complexity classification (gap: "adaptive reasoning depth / route by
    //! depth not just tier", BE). When a turn does NOT hard-pin a tier ([`Request::pinned_tier`] is
    //! `None`), the runtime DERIVES the model-complexity tier before routing rather than blindly
    //! trusting a caller-declared default. The derivation is a pluggable seam:
    //!
    //! * the DEFAULT [`TierFromRequest`] echoes the request's soft [`Request::tier`] — byte-identical
    //!   pre-wire behavior, so every existing deployment routes exactly as before;
    //! * a deployment installs the deterministic, rule-based [`HeuristicComplexityClassifier`] (no
    //!   network model — unit-testable and reproducible) via [`Engine::with_complexity_classifier`],
    //!   or plugs an ML classifier behind the same trait.
    //!
    //! The derived tier is used only as the router's SOFT preference on the unpinned path (it never
    //! weakens the non-overridable data-class / governance gate). A hard tier PIN takes the separate
    //! hard-filter path and does not consult this classifier.
    use ainxt_protocol::Request;
    use ainxt_types::Tier;

    /// Derives a model-complexity tier for a turn. Must be deterministic (same input ⇒ same tier) so
    /// routing is reproducible and unit-testable.
    pub trait ComplexityClassifier: Send + Sync {
        fn classify(&self, req: &Request) -> Tier;
    }

    /// Default classifier: echo the request's soft [`Request::tier`]. This preserves the exact
    /// pre-existing routing behavior (the unpinned path used `req.tier` as the soft preference), so
    /// installing the classifier seam changes nothing until a real classifier is attached.
    pub struct TierFromRequest;
    impl ComplexityClassifier for TierFromRequest {
        fn classify(&self, req: &Request) -> Tier {
            req.tier
        }
    }

    /// A deterministic, rule-based complexity classifier — no network model, fully reproducible.
    /// Derives the tier from the SEMANTIC user turn ([`Request::classify_source`], never the composed
    /// prompt) using cheap, model-agnostic signals:
    ///
    /// * explicit deep-reasoning markers (e.g. "prove", "design", "architect", "why", "trade-off",
    ///   "step by step", "root cause") ⇒ [`Tier::Complex`];
    /// * multi-part / long / code-bearing turns ⇒ [`Tier::Medium`];
    /// * short, trivial turns (greetings, one-liners) ⇒ [`Tier::Simple`].
    ///
    /// Thresholds are conservative and documented so the mapping is auditable; a deployment may swap
    /// in an ML classifier behind [`ComplexityClassifier`] without touching the routing seam.
    pub struct HeuristicComplexityClassifier {
        /// Word count at/above which a turn is at least [`Tier::Medium`].
        pub medium_word_threshold: usize,
        /// Word count at/above which a turn is [`Tier::Complex`].
        pub complex_word_threshold: usize,
    }

    impl Default for HeuristicComplexityClassifier {
        fn default() -> Self {
            HeuristicComplexityClassifier {
                medium_word_threshold: 12,
                complex_word_threshold: 60,
            }
        }
    }

    impl HeuristicComplexityClassifier {
        pub fn new() -> Self {
            Self::default()
        }
    }

    /// Phrases that signal genuine multi-step reasoning depth regardless of length.
    const COMPLEX_MARKERS: &[&str] = &[
        "prove",
        "proof",
        "design",
        "architect",
        "trade-off",
        "tradeoff",
        "root cause",
        "step by step",
        "step-by-step",
        "derive",
        "optimize",
        "reconcile",
        "why does",
        "why is",
        "analy",
        "strategy",
        "refactor",
        "distributed",
        "concurren",
        "algorithm",
    ];

    impl ComplexityClassifier for HeuristicComplexityClassifier {
        fn classify(&self, req: &Request) -> Tier {
            let text = req.classify_source();
            let lower = text.to_ascii_lowercase();
            // Signal 1: explicit reasoning-depth markers ⇒ Complex.
            if COMPLEX_MARKERS.iter().any(|m| lower.contains(m)) {
                return Tier::Complex;
            }
            // Signal 2: code fences / multiple sentences also lift toward Complex.
            let words = text.split_whitespace().count();
            let has_code = text.contains("```") || text.contains("fn ") || text.contains("def ");
            let sentences = text.matches(['.', '?', '!']).count();
            if words >= self.complex_word_threshold
                || (has_code && words >= self.medium_word_threshold)
            {
                return Tier::Complex;
            }
            // Signal 3: length / multi-part ⇒ Medium.
            if words >= self.medium_word_threshold || sentences >= 3 || has_code {
                return Tier::Medium;
            }
            Tier::Simple
        }
    }
}

// ============================ Concurrent-dispatch observability ============================
pub mod dispatch {
    //! Observability for the concurrent tool-dispatch round (gap: parallel tool dispatch). When a
    //! provider round returns multiple tool calls the engine dispatches the admitted ones
    //! CONCURRENTLY (same-file edits serialized, one shared cancel token). This probe records the
    //! PEAK number of tool dispatches in flight at once and the total dispatched — a real
    //! serving-ops / FinOps signal AND the deterministic hook a test uses to prove that disjoint
    //! calls actually overlap while same-file calls serialize. `None` (the default) = no probe.
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    pub struct DispatchProbe {
        inflight: AtomicUsize,
        peak: AtomicUsize,
        total: AtomicUsize,
    }

    impl DispatchProbe {
        pub fn new() -> Self {
            Self::default()
        }
        /// Mark a dispatch entering the in-flight window; updates the peak. Called by the engine.
        pub(crate) fn enter(&self) {
            let n = self.inflight.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(n, Ordering::SeqCst);
            self.total.fetch_add(1, Ordering::SeqCst);
        }
        /// Mark a dispatch leaving the in-flight window.
        pub(crate) fn exit(&self) {
            self.inflight.fetch_sub(1, Ordering::SeqCst);
        }
        /// The maximum number of tool dispatches observed in flight simultaneously.
        pub fn peak_concurrency(&self) -> usize {
            self.peak.load(Ordering::SeqCst)
        }
        /// The total number of tool calls dispatched through the concurrent path.
        pub fn total_dispatched(&self) -> usize {
            self.total.load(Ordering::SeqCst)
        }
    }
}

// ============================ Cancellation (ADR-001) ============================
pub mod cancel {
    //! A cheap, clonable cancellation token. Cancelling a turn is cooperative but prompt: the
    //! engine races every stream `recv` against [`CancelToken::cancelled`], so a cancel stops
    //! streaming, halts further tool dispatch, drops the stream receiver, and ends the turn.
    //! (A provider task parked on a network read is bounded by the provider client's read
    //! timeout rather than aborted synchronously — see the provider adapters.)
    use std::sync::Arc;
    use tokio::sync::watch;

    #[derive(Clone)]
    pub struct CancelToken {
        tx: Arc<watch::Sender<bool>>,
        rx: watch::Receiver<bool>,
    }

    impl Default for CancelToken {
        fn default() -> Self {
            Self::new()
        }
    }

    impl CancelToken {
        pub fn new() -> Self {
            let (tx, rx) = watch::channel(false);
            CancelToken {
                tx: Arc::new(tx),
                rx,
            }
        }
        /// Request cancellation. Idempotent; wakes all `cancelled()` waiters.
        pub fn cancel(&self) {
            let _ = self.tx.send(true);
        }
        pub fn is_cancelled(&self) -> bool {
            *self.rx.borrow()
        }
        /// Resolves as soon as the token is cancelled (immediately if already cancelled). Uses a
        /// `watch` so there is no lost-wakeup race.
        pub async fn cancelled(&self) {
            let mut rx = self.rx.clone();
            if *rx.borrow() {
                return;
            }
            while rx.changed().await.is_ok() {
                if *rx.borrow() {
                    return;
                }
            }
        }
    }
}

// ============================ Error taxonomy (ADR-001) ============================
pub mod error {
    //! Classifies a provider error as retryable-transient vs terminal, driving retry/backoff and
    //! failover. The default is a heuristic PLACEHOLDER (string match); a production classifier
    //! (structured provider error codes) plugs in via the [`ErrorClassifier`] trait.

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ErrorClass {
        /// Transient — retry the same provider (with backoff), then fail over.
        Retryable,
        /// Permanent for this request — fail over immediately; do not retry the same provider.
        Terminal,
    }

    pub trait ErrorClassifier: Send + Sync {
        fn classify(&self, message: &str) -> ErrorClass;
    }

    pub struct HeuristicErrorClassifier;

    impl ErrorClassifier for HeuristicErrorClassifier {
        fn classify(&self, message: &str) -> ErrorClass {
            let m = message.to_lowercase();
            const RETRYABLE: &[&str] = &[
                "timeout",
                "timed out",
                "temporarily",
                "connection",
                "reset",
                "500",
                "502",
                "503",
                "504",
                "429",
                "rate limit",
                "overloaded",
                "unavailable",
            ];
            if RETRYABLE.iter().any(|k| m.contains(k)) {
                ErrorClass::Retryable
            } else {
                ErrorClass::Terminal
            }
        }
    }
}

// ============================ Approval Gate (ADR-003) ============================
pub mod approval {
    /// A request for a human/policy decision before a risky tool runs.
    #[derive(Debug, Clone)]
    pub struct ApprovalRequest {
        pub session: String,
        pub actor: String,
        pub tool: String,
        pub args: String,
    }

    /// Tri-state decision; `Reject` carries model-visible feedback.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum ApprovalDecision {
        Approve,
        ApproveForSession,
        Reject(String),
    }

    /// The blocking approval seam. The decider may be a UI dialog, an SDLC HITL gate, or an
    /// auto-policy — the engine doesn't know which. (Sync here; a production interactive gate
    /// blocks on a channel / runs async — see residual note.)
    pub trait ApprovalGate: Send + Sync {
        fn decide(&self, req: &ApprovalRequest) -> ApprovalDecision;

        /// Whether this gate's decisions are produced by a POLICY/auto default rather than a live
        /// human. This is the `is_policy_auto` input to the payment-boundary invariant (§9, ADR-016):
        /// a `payment_boundary != none` action can be cleared ONLY by an explicit **human** `approve`,
        /// so any policy-auto gate — no matter what it returns — can never clear a payment. Default is
        /// `true` (fail-closed for payments); an interactive human/HITL gate overrides this to `false`.
        fn is_policy_auto(&self) -> bool {
            true
        }
    }

    /// Approves everything — dev / low-stakes only, never for production risky tools. Policy-auto:
    /// it can never clear a `payment_boundary != none` action (only a human gate can).
    pub struct AutoApprove;
    impl ApprovalGate for AutoApprove {
        fn decide(&self, _req: &ApprovalRequest) -> ApprovalDecision {
            ApprovalDecision::Approve
        }
    }

    /// Rejects everything with a fixed reason.
    pub struct AutoReject(pub String);
    impl ApprovalGate for AutoReject {
        fn decide(&self, _req: &ApprovalRequest) -> ApprovalDecision {
            ApprovalDecision::Reject(self.0.clone())
        }
    }
}

// ============================ Budget gate (ADR-003 / gap TURN-01) ============================
pub mod budget {
    //! Pre-turn spend/quota enforcement (gap TURN-01). The runtime consults a [`BudgetStore`] in the
    //! Identity+Policy gate — BEFORE any provider call — so an over-ceiling turn is denied up front,
    //! not merely recorded post-hoc. The decision math lives in `ainxt_protocol::budget_gate`; this
    //! seam supplies the per-principal spend/limit the runtime feeds it.
    use ainxt_types::Principal;

    /// A per-principal spend snapshot in the runtime's budget unit (the same token/cost unit the
    /// engine's estimator produces). `limit == 0` means "no ceiling configured" (always allow).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct BudgetSnapshot {
        pub already_spent: u64,
        pub limit: u64,
    }

    impl BudgetSnapshot {
        pub fn new(already_spent: u64, limit: u64) -> Self {
            BudgetSnapshot {
                already_spent,
                limit,
            }
        }
    }

    /// The per-user budget store seam. Production plugs in the Redis/Postgres-backed budget
    /// middleware; the default [`NoBudgetLimit`] returns `limit == 0` (unlimited), which preserves
    /// the exact pre-wire behavior for deployments that do not configure a budget.
    pub trait BudgetStore: Send + Sync {
        fn snapshot(&self, principal: &Principal) -> BudgetSnapshot;
    }

    /// Default store: no ceiling for anyone (always allows).
    pub struct NoBudgetLimit;
    impl BudgetStore for NoBudgetLimit {
        fn snapshot(&self, _principal: &Principal) -> BudgetSnapshot {
            BudgetSnapshot::default()
        }
    }
}

// ============================ Memory (Context-Fabric layer 12, MEM-04) ============================
pub mod memory {
    //! Memory is NOT a separate retrieval path — it is *layer 12 of the Context Fabric* (design §7),
    //! read on the turn's context-assembly step under the SAME pre-rank identity/data-class discipline
    //! as every other source. This seam lets the engine call ainxt-memory's `read_for_turn` under the
    //! CALLER's identity scope and thread the returned hits + a forensic-replay [`TurnLineage`] into
    //! the prompt WITHOUT re-implementing retrieval. `None` (the default) = no memory (pre-wire
    //! behavior preserved).
    use ainxt_memory::fabric::{TaskKind, TurnLineage};
    use ainxt_memory::{AccessScope, MemoryHit};

    // Re-export so callers configure/derive tasks through the runtime crate.
    pub use ainxt_memory::fabric::{TaskKind as MemoryTaskKind, TurnLineage as MemoryTurnLineage};

    /// The Context-Fabric memory read seam. Implemented by an adapter over an ainxt-memory store; the
    /// engine calls it with the caller's [`AccessScope`], the turn's task class (query planning,
    /// §7.1), and a logical `now`. Returns the injected hits (highest-precedence first) and the
    /// per-turn lineage `(id, version)` for forensic replay (§7.4/§7.5).
    pub trait MemoryReader: Send + Sync {
        fn read_for_turn(
            &self,
            turn_id: &str,
            task: &TaskKind,
            access: &AccessScope,
            now: u64,
        ) -> (Vec<MemoryHit>, TurnLineage);
    }

    /// A concrete adapter wrapping a shared `InMemoryStore`. Interior-mutable (a `Mutex`) so the read
    /// can mark injected items *used* for usage-based decay (§6) behind the engine's `&self`.
    /// Production swaps in a durable-store adapter over this same trait.
    pub struct SharedMemoryStore {
        store: std::sync::Mutex<ainxt_memory::InMemoryStore>,
        /// Per-planned-query result cap (`0` = unlimited).
        per_query_limit: usize,
    }

    impl SharedMemoryStore {
        pub fn new(store: ainxt_memory::InMemoryStore) -> Self {
            Self {
                store: std::sync::Mutex::new(store),
                per_query_limit: 0,
            }
        }
        pub fn with_per_query_limit(mut self, limit: usize) -> Self {
            self.per_query_limit = limit;
            self
        }
    }

    impl MemoryReader for SharedMemoryStore {
        fn read_for_turn(
            &self,
            turn_id: &str,
            task: &TaskKind,
            access: &AccessScope,
            now: u64,
        ) -> (Vec<MemoryHit>, TurnLineage) {
            // Delegates to the REAL Context-Fabric read path: query planning + pre-rank identity/
            // data-class filter + usage-decay touch + lineage capture (never re-implemented here).
            self.store.lock().expect("memory store lock").read_for_turn(
                turn_id,
                task,
                access,
                now,
                self.per_query_limit,
            )
        }
    }
}

// ============================ Node attestation (ADR-021 §8.2, serving-ops SRV-02) ============================
pub mod serving {
    //! Node-level attestation as a PRE-DISPATCH admission hook (ADR-021 §8.2 / SERVING_OPS §8).
    //!
    //! For a regulated (`confidential`+) data class the runtime must not hand a turn to a model
    //! running on a node that is not currently attested — **even one sitting idle**. This is the seam
    //! the engine consults BEFORE any provider stream is opened, and it is **fail-closed**: when trust
    //! cannot be established the turn is refused, never served on an untrusted node.
    //!
    //! The default is no attestor attached (pre-wire behavior: attestation owned by the deployment).
    //! [`ServingGateAttestor`] is the concrete adapter that calls the Serving-Ops gate entrypoint
    //! ([`ainxt_serving::gate::ServingGate::pre_serve_check`]) — the single node-level admission check
    //! the fleet exposes upward (ADR-020). The LIVE fleet snapshot (candidate nodes, logical clock,
    //! verifier reachability) is owned by the daemon and injected via a closure, so the actual fleet
    //! wiring is a daemon concern (needs_hot_wiring) while the enforcement lands here in the engine.
    use ainxt_types::DataClass;

    /// The pre-dispatch node-attestation decision.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum AttestationOutcome {
        /// A node trusted enough to see this data class is available (or the class needs none).
        Admitted { node: Option<String> },
        /// Fail-closed: no attested/trusted node can serve this regulated turn — refuse it.
        FailClosed(String),
    }

    impl AttestationOutcome {
        pub fn is_admitted(&self) -> bool {
            matches!(self, AttestationOutcome::Admitted { .. })
        }
    }

    /// The node-attestation hook consulted before model dispatch. When configured it is MANDATORY:
    /// the engine calls it for every turn and fails the turn CLOSED on [`AttestationOutcome::FailClosed`]
    /// — a regulated turn never reaches a provider on an untrusted node.
    pub trait NodeAttestor: Send + Sync {
        fn admit(&self, data_class: DataClass) -> AttestationOutcome;
    }

    /// Adapter over the Serving-Ops gate (ADR-020/021). Wraps a SHARED
    /// `Arc<Mutex<ainxt_serving::gate::ServingGate>>` — GAP-FIX gap6-composition-root (Item 1): this
    /// used to hold an owned-by-value [`ainxt_serving::gate::ServingGate`], which meant a caller could
    /// only ever hand it a FROZEN snapshot taken at construction time — a background attestation
    /// refresh loop mutating a *different* `ServingGate` instance could never be seen here, so any real
    /// wiring would have left a regulated turn either permanently fail-closed (a fresh, never-attested
    /// gate) or attesting against stale state forever. Sharing the exact `Arc<Mutex<_>>` the daemon's
    /// attestation quote-refresh loop and its `/v1/chat` Stage-1 fence already lock is what makes this
    /// safe to wire into `Engine::with_node_attestor` for real. Also takes a fleet-state provider
    /// closure returning the currently-offered candidate nodes, the logical `now`, and whether the
    /// attestation verifier is reachable (drives the freshness/grace decision). `admit` locks the gate
    /// and calls [`pre_serve_check`](ainxt_serving::gate::ServingGate::pre_serve_check) — the exact
    /// node-level entrypoint the design specifies — and maps its verdict.
    pub struct ServingGateAttestor<F>
    where
        F: Fn() -> (Vec<ainxt_serving::gate::NodeCandidate>, u64, bool) + Send + Sync,
    {
        gate: std::sync::Arc<std::sync::Mutex<ainxt_serving::gate::ServingGate>>,
        fleet: F,
    }

    impl<F> ServingGateAttestor<F>
    where
        F: Fn() -> (Vec<ainxt_serving::gate::NodeCandidate>, u64, bool) + Send + Sync,
    {
        pub fn new(
            gate: std::sync::Arc<std::sync::Mutex<ainxt_serving::gate::ServingGate>>,
            fleet: F,
        ) -> Self {
            Self { gate, fleet }
        }
    }

    impl<F> NodeAttestor for ServingGateAttestor<F>
    where
        F: Fn() -> (Vec<ainxt_serving::gate::NodeCandidate>, u64, bool) + Send + Sync,
    {
        fn admit(&self, data_class: DataClass) -> AttestationOutcome {
            use ainxt_serving::gate::PreServeVerdict;
            let (candidates, now, verifier_reachable) = (self.fleet)();
            let gate = self.gate.lock().expect("serving gate lock poisoned");
            match gate.pre_serve_check(data_class, &candidates, now, verifier_reachable) {
                PreServeVerdict::Admit { node_id } => AttestationOutcome::Admitted {
                    node: Some(node_id),
                },
                PreServeVerdict::NoRoutableNode => AttestationOutcome::FailClosed(
                    "no health-routable node available to serve this turn".to_string(),
                ),
                PreServeVerdict::FailClosedNoAttestedCapacity => AttestationOutcome::FailClosed(
                    "regulated data class: no currently-attested node — fail-closed (ADR-021 §8.2)"
                        .to_string(),
                ),
            }
        }
    }
}

// ============================ §7.3 Backpressure admission (typed 503 Capacity) ============================
pub mod capacity {
    //! A bounded-inflight ADMISSION seam the SESSION layer drives BEFORE it starts a turn (§7.3
    //! backpressure). When the fleet is saturated a new turn is refused up front with a typed
    //! [`ErrorCategory::Capacity`] — the retryable "at capacity, retry shortly" 503 the protocol
    //! taxonomy defines — instead of piling onto an already-overloaded provider path.
    //!
    //! This is ADDITIVE and independent of the engine's own mandatory gates (compliance / authz /
    //! audit): those still run on every admitted turn, unchanged. A deployment that never
    //! constructs a gate has NO capacity ceiling (pre-wire behavior). The seam is a trait so a
    //! production transport can back it with a DISTRIBUTED limiter (e.g. a Redis token bucket
    //! shared across daemon replicas); the shipped default is the in-process [`InflightGate`].
    //!
    //! Usage (session layer):
    //! ```ignore
    //! let gate = InflightGate::new(max_concurrent);
    //! match gate.try_admit() {
    //!     Ok(permit) => { /* hold `permit` for the whole turn; drop frees the slot */ }
    //!     Err(err)   => { /* emit WireEvent::Error(err) — err.category == Capacity */ }
    //! }
    //! ```
    use ainxt_protocol::{ErrorCategory, ProtocolError};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// The backpressure admission seam. [`try_admit`](CapacityGate::try_admit) returns a RAII
    /// [`AdmissionPermit`] that MUST be held for the lifetime of the admitted turn — dropping it
    /// frees the slot (so the next queued turn can be admitted). On saturation it returns a typed
    /// [`ProtocolError`] whose category is [`ErrorCategory::Capacity`].
    pub trait CapacityGate: Send + Sync {
        /// Try to admit one more in-flight turn. `Ok(permit)` = admitted (hold the permit);
        /// `Err(ProtocolError{ category: Capacity, .. })` = refused, retry later.
        fn try_admit(&self) -> Result<AdmissionPermit, ProtocolError>;
        /// Current number of admitted-but-not-yet-released turns (observability / metrics).
        fn inflight(&self) -> usize;
        /// The configured ceiling (0 = unbounded).
        fn capacity(&self) -> usize;
    }

    /// A bounded in-process inflight limiter (the shipped default). Admits up to `max` concurrent
    /// turns; the `max + 1`-th is refused with [`ErrorCategory::Capacity`]. `max == 0` = unbounded
    /// (admits everything — the explicit "no ceiling" configuration, matching pre-wire behavior).
    ///
    /// Cheap to clone: all clones share one atomic counter, so a gate handed to N session tasks
    /// enforces ONE global ceiling across them.
    #[derive(Clone)]
    pub struct InflightGate {
        inflight: Arc<AtomicUsize>,
        max: usize,
    }

    impl InflightGate {
        /// Build a gate bounded at `max` concurrent turns (`0` = unbounded).
        pub fn new(max: usize) -> Self {
            Self {
                inflight: Arc::new(AtomicUsize::new(0)),
                max,
            }
        }
    }

    impl CapacityGate for InflightGate {
        fn try_admit(&self) -> Result<AdmissionPermit, ProtocolError> {
            if self.max == 0 {
                // Unbounded: still hand back a permit so the caller's RAII shape is uniform, but
                // the counter is only advisory (never a rejection source).
                self.inflight.fetch_add(1, Ordering::SeqCst);
                return Ok(AdmissionPermit {
                    inflight: Arc::clone(&self.inflight),
                });
            }
            // Reserve optimistically, then roll back if we crossed the ceiling — a lock-free
            // check-and-increment safe under concurrent admission from many session tasks.
            let prev = self.inflight.fetch_add(1, Ordering::SeqCst);
            if prev >= self.max {
                self.inflight.fetch_sub(1, Ordering::SeqCst);
                return Err(ProtocolError::new(
                    ErrorCategory::Capacity,
                    "at capacity — too many concurrent turns in flight",
                )
                .with_recovery("retry shortly"));
            }
            Ok(AdmissionPermit {
                inflight: Arc::clone(&self.inflight),
            })
        }

        fn inflight(&self) -> usize {
            self.inflight.load(Ordering::SeqCst)
        }

        fn capacity(&self) -> usize {
            self.max
        }
    }

    /// A held admission slot. Decrements the shared inflight counter on drop (RAII), so a turn that
    /// completes, cancels, fails, OR panics always frees its slot — there is no leak path.
    #[must_use = "hold the AdmissionPermit for the turn's lifetime; dropping it frees the slot"]
    pub struct AdmissionPermit {
        inflight: Arc<AtomicUsize>,
    }

    impl std::fmt::Debug for AdmissionPermit {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("AdmissionPermit")
                .field("inflight", &self.inflight.load(Ordering::SeqCst))
                .finish()
        }
    }

    impl Drop for AdmissionPermit {
        fn drop(&mut self) {
            // saturating: never underflow below zero even under an unexpected double-drop shape.
            let mut cur = self.inflight.load(Ordering::SeqCst);
            while cur > 0 {
                match self.inflight.compare_exchange_weak(
                    cur,
                    cur - 1,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                ) {
                    Ok(_) => break,
                    Err(observed) => cur = observed,
                }
            }
        }
    }
}

// ============================ Wire vocabulary (PROTOCOL §4 envelope + §6 events) ============================
pub mod wire {
    //! The §4 [`EventEnvelope`] + §6 [`WireEvent`] emission seam.
    //!
    //! The live turn pipeline streams the legacy [`ainxt_protocol::Event`] to its primary `sink`
    //! (the in-proc contract the server/client are wired to today). This module lets the engine ALSO
    //! emit the full typed §4/§6 vocabulary — strictly-monotonic `seq`, `ts`, `control_plane_sha`,
    //! `compliance.notice` on redaction, `turn.completed{outcome}` incl. `capped` — onto an OPTIONAL
    //! wire sink, WITHOUT changing the primary sink's type (which would ripple through every caller,
    //! the `TurnHandler` trait, and the server). The server/daemon consuming this envelope stream is
    //! the hot-wiring step (needs_hot_wiring: ainxt-server SSE serializes EventEnvelope).
    use super::{EventEnvelope, WireEvent};
    use std::sync::Mutex;

    /// The optional wire-event sink. A production transport implements this to serialize each
    /// envelope onto SSE/gRPC; a `None` sink (the default) makes emission a no-op.
    pub trait WireSink: Send + Sync {
        fn emit(&self, env: EventEnvelope);
    }

    /// A collecting sink (tests / dev): captures every emitted envelope in order.
    #[derive(Default)]
    pub struct VecWireSink {
        pub events: Mutex<Vec<EventEnvelope>>,
    }

    impl VecWireSink {
        pub fn snapshot(&self) -> Vec<EventEnvelope> {
            self.events.lock().expect("wire lock").clone()
        }
        pub fn len(&self) -> usize {
            self.events.lock().expect("wire lock").len()
        }
        pub fn is_empty(&self) -> bool {
            self.len() == 0
        }
    }

    impl WireSink for VecWireSink {
        fn emit(&self, env: EventEnvelope) {
            self.events.lock().expect("wire lock").push(env);
        }
    }

    /// Shared-ownership convenience: an `Arc<VecWireSink>` is itself a [`WireSink`], so the daemon
    /// (or a test) can retain a handle to inspect/replay the envelope stream while the engine holds
    /// its own `Box<dyn WireSink>` clone of the same buffer. `WireSink::emit` takes `&self`, so the
    /// `Arc` delegates directly with no extra locking.
    impl WireSink for std::sync::Arc<VecWireSink> {
        fn emit(&self, env: EventEnvelope) {
            (**self).emit(env);
        }
    }

    use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

    /// The **default wire projection** a served transport uses to receive the engine's typed §4/§6
    /// envelope stream directly — instead of re-deriving [`WireEvent`]s from the *lossy* legacy
    /// [`ainxt_protocol::Event`] stream. Re-derivation is exactly why a served daemon reports a
    /// judge-capped turn as `turn.completed{Complete}` (the legacy `Event::Done` carries no outcome)
    /// and NEVER emits `compliance.notice` (the legacy stream has no such event): the truthful
    /// `Capped` outcome and the redaction notices are emitted ONLY on this wire sink. This sink
    /// forwards every [`EventEnvelope`] the engine emits onto an unbounded channel the transport
    /// drains and serializes onto SSE/gRPC as-is (the envelope already carries `seq`/`ts`/
    /// `control_plane_sha`), so the on-wire outcome equals the engine's real outcome.
    ///
    /// Unbounded on purpose: the wire seam is emit-and-continue — a slow or disconnected consumer
    /// must never block or deadlock the turn pipeline (transport-level backpressure is the server's
    /// concern, applied where it drains this receiver, not inside the hot turn loop).
    pub struct ChannelWireSink {
        tx: UnboundedSender<EventEnvelope>,
    }

    impl ChannelWireSink {
        /// Build a sink plus the receiver the transport drains. Hand the sink to
        /// [`super::Engine::with_wire_sink`] (boxed) and read the receiver on the response task.
        pub fn new() -> (Self, UnboundedReceiver<EventEnvelope>) {
            let (tx, rx) = unbounded_channel();
            (ChannelWireSink { tx }, rx)
        }

        /// Build a sink over an existing sender (e.g. when the transport owns the channel and fans
        /// several sessions into one drain task).
        pub fn from_sender(tx: UnboundedSender<EventEnvelope>) -> Self {
            ChannelWireSink { tx }
        }
    }

    impl WireSink for ChannelWireSink {
        fn emit(&self, env: EventEnvelope) {
            // A closed receiver (client gone) is NOT fatal to the turn — the compliance/audit seams
            // still run; the projection is a transport concern. Drop silently on send error.
            let _ = self.tx.send(env);
        }
    }

    /// A per-turn emitter: assigns the strictly-monotonic per-session `seq`, stamps `ts` +
    /// `control_plane_sha`, and forwards to the sink. Holds a borrow of the sink for the turn's
    /// duration; when no sink is configured every call is a cheap no-op (seq is not advanced).
    pub struct TurnWire<'a> {
        sink: Option<&'a dyn WireSink>,
        session: String,
        turn: String,
        control_plane_sha: String,
        seq: u64,
    }

    impl<'a> TurnWire<'a> {
        pub fn new(
            sink: Option<&'a dyn WireSink>,
            session: &str,
            turn: &str,
            control_plane_sha: &str,
        ) -> Self {
            TurnWire {
                sink,
                session: session.to_string(),
                turn: turn.to_string(),
                control_plane_sha: control_plane_sha.to_string(),
                seq: 0,
            }
        }

        pub fn is_active(&self) -> bool {
            self.sink.is_some()
        }

        /// Epoch-millis timestamp as a string. NOTE: the production transport replaces this with a
        /// true RFC-3339 stamp (needs_hot_wiring); the seam + monotonic `seq` are what matter here.
        fn now_ts() -> String {
            let ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0);
            format!("{ms}")
        }

        /// Emit one typed event in a turn-scoped envelope, advancing `seq`. No-op without a sink.
        pub fn emit(&mut self, event: WireEvent) {
            let Some(sink) = self.sink else { return };
            self.seq += 1;
            sink.emit(EventEnvelope::turn(
                &self.session,
                &self.turn,
                self.seq,
                &Self::now_ts(),
                &self.control_plane_sha,
                event,
            ));
        }

        /// The last `seq` emitted (0 = none yet) — the resume cursor a client would checkpoint.
        pub fn last_seq(&self) -> u64 {
            self.seq
        }
    }
}

// ============================ Engine (the turn pipeline) ============================
use approval::{ApprovalDecision, ApprovalGate, ApprovalRequest};
use audit::{AuditRecord, AuditSink};
use authz::{Authorizer, Decision};
use budget::{BudgetSnapshot, BudgetStore, NoBudgetLimit};
use compliance::{ComplianceGate, Direction};
use router::{ModelRouter, RouteError};
use tokio::sync::mpsc;

/// The capability a chat turn requires.
pub const CAP_CHAT_SEND: &str = "chat.send";

/// GAP-AUDIT turn-pipeline #2 — the capability that gates `reasoning.delta` (§6.1): the model's
/// "thinking"/reasoning content is policy-sensitive (it can leak more about *how* an answer was
/// reached than the answer itself — chain-of-thought on a regulated turn, or a competitor-facing
/// surface that shouldn't show internal deliberation) and must be withheld from a caller the Policy
/// Engine hasn't explicitly cleared for it (ADR-003), even though the caller may otherwise be fully
/// authorized to chat at all (`CAP_CHAT_SEND`). Checked via the SAME `Authorizer::authorize` seam as
/// every other capability gate in this engine — `Role::Admin` always passes (via `Principal::has_cap`).
pub const CAP_REASONING_VIEW: &str = "chat.reasoning.view";

/// Upper bound (bytes) on the streaming output hold-back, so a pathologically long
/// separator-joined numeric run can never grow the carry without bound: anything older than this
/// window cannot be part of a single detectable token still in progress at the live boundary (a
/// real PAN/account number in spaced or hyphenated form is well under this), so its prefix is
/// released (re-scanned by compliance on the way out) while the last `window` bytes are retained.
const MAX_STREAM_CARRY_WINDOW: usize = 128;

/// Byte index up to which buffered output text is SAFE to emit now — everything except a trailing
/// region that a future delta could extend into a sensitive token, so a secret spanning a chunk
/// boundary is buffered whole and scanned before its prefix can leave.
///
/// Two shapes are held back:
///  1. a trailing contiguous alphanumeric/`=` run — an in-progress token (a PAN, a `PAN=`/key
///     marker) a future delta might extend (the original guarantee); and
///  2. a trailing SEPARATOR-JOINED NUMERIC sequence — digit groups joined by single spaces or
///     hyphens, optionally ending on a separator ("4111 1111 1111 1111", "4111-1111-…"), so a
///     spaced/hyphenated PAN or account number is buffered whole instead of flushed group-by-group
///     (each group alone is below the detector's digit threshold, so a flushed leading group would
///     escape un-redacted).
///
/// Crucially we do NOT hold back separators between NON-numeric words: a trailing space after an
/// ordinary word ("partial ") stays a flush boundary, so token-by-token prose streaming (and the
/// cancel-mid-stream contract) is unchanged. The hold-back is bounded to the last `window` bytes.
/// O(len of the trailing region).
fn safe_output_split(s: &str, window: usize) -> usize {
    let is_tok = |c: char| c.is_alphanumeric() || c == '=';
    let is_sep = |c: char| c == ' ' || c == '-';
    let chars: Vec<(usize, char)> = s.char_indices().collect();
    let n = chars.len();
    let has_digit = |lo: usize, hi: usize| chars[lo..hi].iter().any(|(_, c)| c.is_ascii_digit());

    // (1) Trailing contiguous alnum/`=` token run.
    let mut tok_lo = n;
    while tok_lo > 0 && is_tok(chars[tok_lo - 1].1) {
        tok_lo -= 1;
    }
    let tok_numeric = tok_lo < n && has_digit(tok_lo, n);

    // Held-region start (index into `chars`).
    let hb = if tok_lo < n && !tok_numeric {
        // A non-numeric in-progress token (a word / hex-less run): hold exactly it, as the original
        // trailing-alnum rule did. Do NOT extend across separators — that would buffer prose and
        // stall streaming.
        tok_lo
    } else {
        // (2) Walk backward over a numeric separator-joined sequence. Skip a trailing separator run
        // first (so a spaced PAN that currently ends on a space is still recognised), then require
        // alternating numeric groups joined by SINGLE separators.
        let mut cursor = n;
        while cursor > 0 && is_sep(chars[cursor - 1].1) {
            cursor -= 1;
        }
        let mut start = n;
        loop {
            let g_hi = cursor;
            let mut g_lo = g_hi;
            while g_lo > 0 && is_tok(chars[g_lo - 1].1) {
                g_lo -= 1;
            }
            if g_lo == g_hi || !has_digit(g_lo, g_hi) {
                break; // no group, or a non-numeric group ends the sequence
            }
            start = g_lo;
            if g_lo > 0 && is_sep(chars[g_lo - 1].1) {
                cursor = g_lo - 1; // step over exactly one separator to the previous group
            } else {
                break;
            }
        }
        // No numeric sequence found → fall back to holding the trailing token run (possibly empty).
        if start == n {
            tok_lo
        } else {
            start
        }
    };

    let mut cut = if hb < n { chars[hb].0 } else { s.len() };
    // Bound the hold-back to the last `window` bytes; align left to a char boundary.
    if s.len() - cut > window {
        cut = s.len() - window;
        while cut > 0 && !s.is_char_boundary(cut) {
            cut -= 1;
        }
    }
    cut
}

/// Default agent-loop iteration cap when config does not override it (see `ainxt-config`
/// `limits.max_agent_iters`, ceilinged at `MAX_AGENT_ITERS_CEILING`).
pub const DEFAULT_MAX_ITERS: usize = 4;

/// Default bounded-inflight ceiling for the backpressure admission seam ([`capacity::InflightGate`])
/// when a deployment does not override it. Deliberately GENEROUS: normal single-process operation
/// never trips it, so the seam is a safety ceiling rather than a routine limiter. A real deployment
/// sizes it to the fleet's provable concurrent-turn capacity (and can swap in a distributed limiter
/// via [`Engine::with_capacity_gate`]); a guard test sets a small explicit bound to exercise refusal.
pub const DEFAULT_MAX_INFLIGHT: usize = 4096;

/// Validity window (seconds) of a §1.4 two-phase `dry_run` preview when it is issued and committed
/// in-loop, back-to-back, on the agent path. The runtime issues the preview and the commit with the
/// SAME logical `now`, so any positive window keeps the commit inside the freshness bound; the value
/// only matters to a transport that later parks a preview for out-of-band human approval.
pub const TWO_PHASE_TTL_SECS: u64 = 300;

#[derive(Debug, Clone)]
pub struct TurnOutcome {
    pub events: Vec<Event>,
    pub final_text: String,
    pub redactions: usize,
    pub provider: String,
}

/// Summary of a streamed turn (events went to the caller's sink, not collected here).
///
/// GAP-FIX conversation-intelligence "doc-gen artifact IR + content-action delivery dead on the
/// streaming path": `ConversationManager::handle()` (the non-streaming path, itself unreachable from
/// the served daemon — see `ainxt_chat::ChatSurface::turn`'s own doc comment) builds a real
/// `ainxt_artifact::Document` IR for a doc-generation turn and carries the resolved `ActionKind` for a
/// content-consuming action ("summarize the above and email it"), but the SERVED streaming path
/// (`ConversationManager::run_turn_streaming`, which `TurnHandler::handle_turn` actually calls) dropped
/// BOTH signals and streamed only the resolved plain text — a served client had no way to tell "this
/// is a PDF" from an ordinary answer, or "this is an email delivery" from ordinary Q&A. `format` /
/// `document_json` / `action` are `None` for every pre-existing terminal (plain-text answers, cache
/// hits, clarifications) — byte-identical to the pre-fix shape via `..Default::default()` at every
/// existing construction site; only the doc-generation / content-action terminals populate them.
///
/// `format`/`action` are plain strings (not `ainxt_convo::OutputFormat`/`ActionKind`) and
/// `document_json` is the [`ainxt_artifact::Document`] IR pre-serialized to JSON, not the typed
/// struct — this crate is the foundational runtime layer `ainxt-convo`/`ainxt-artifact` themselves
/// depend on (`ConversationManager: TurnHandler`), so it cannot name either crate's types without a
/// dependency cycle. This is the SAME string-payload convention [`Event::Artifact`] already uses for
/// exactly this reason.
#[derive(Debug, Clone, Default)]
pub struct TurnSummary {
    pub final_text: String,
    pub redactions: usize,
    pub provider: String,
    /// `Some("pdf" | "docx" | "pptx" | "xlsx")` for a doc-generation terminal; `None` otherwise.
    pub format: Option<String>,
    /// The doc-generation terminal's [`ainxt_artifact::Document`] IR, pre-serialized to JSON
    /// (`serde_json`) — a caller that wants the typed struct back deserializes it; a caller that just
    /// wants to forward it to `POST /v1/artifact` can send the bytes as-is. `None` for every other
    /// terminal.
    pub document_json: Option<String>,
    /// `Some("email" | "summarize" | "translate" | "save")` for a resolved content-action terminal
    /// ("summarize the above and email it"); `None` otherwise. `final_text` already carries the
    /// resolved content for this terminal — this field is the missing WHAT-TO-DO-WITH-IT signal.
    pub action: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TurnError {
    Denied(String),
    Routing(RouteError),
    /// The turn was refused UP FRONT by the bounded-inflight admission seam (§7.3 backpressure) —
    /// the fleet is saturated. Carries the typed [`ErrorCategory::Capacity`] message; the refusal
    /// is retryable ("at capacity, retry shortly", the protocol's 503). No provider is contacted.
    Capacity(String),
    /// An internal failure surfaced by a supervising layer (e.g. a turn that timed out or
    /// panicked, isolated by the Session Manager) — never produced by `run_turn` itself.
    Internal(String),
}

/// The runtime engine. Constructing it REQUIRES the three mandatory gates — there is no
/// build of the pipeline without compliance, authz, and audit (ADR-003/004 invariant).
/// The three-layer On-Behalf-Of policy + audit sink the agent loop routes tool dispatch through (R14).
/// See [`Engine::with_obo`].
struct EngineObo {
    policy: Box<dyn ainxt_tools::obo::OboPolicy>,
    sink: std::sync::Arc<dyn ainxt_tools::obo::OboDecisionSink>,
}

pub struct Engine {
    compliance: Box<dyn ComplianceGate>,
    authz: Box<dyn Authorizer>,
    audit: Box<dyn AuditSink>,
    router: ModelRouter,
    /// R16 (§0/§1.2, CRITICAL) — held as a SHARED handle (not an owned value) so the SAME registry +
    /// exactly-once ledger this engine dispatches through can be handed to a second dispatcher (e.g.
    /// the harness `/run` capability bridge) via [`Engine::with_shared_tools`], instead of that second
    /// dispatcher building its own disjoint registry over a disjoint ledger (the bug: the same
    /// caller-supplied idempotency key — "retry settlement initiation" — could commit once on EACH of
    /// two independent ledgers, a double-execution path).
    tools: Option<std::sync::Arc<ToolRuntime>>,
    approval: Option<Box<dyn ApprovalGate>>,
    /// R14 (served-composition, HIGH) — the three-layer On-Behalf-Of policy + audit sink the agent
    /// loop routes EVERY single-phase tool dispatch through ([`ToolRuntime::dispatch_obo_audited`]):
    /// declared grant ∧ the user's own issued scope ∧ resource-ABAC clearance, with the decision
    /// (GRANTED **or** DENIED) written to the sink BEFORE any effect and the agent's ambient credential
    /// NEVER substituted on a denial. `None` (the default) keeps the prior `dispatch_for` behaviour
    /// (user-id-scoped exactly-once only); the composition daemon installs this so the SERVED agent
    /// loop is OBO-governed + audited.
    obo: Option<EngineObo>,
    /// Optional guardrails config (ADR-008). `None` = OFF (the default) — during coexistence
    /// the Python gateway owns these; the mandatory PCI compliance gate above is unaffected. Kept as
    /// the config (not a prebuilt chain) so the runtime can build BOTH the input chain
    /// ([`RailChain::for_input`]) and the per-turn OUTPUT chain ([`RailChain::for_output`], which
    /// needs the live system prompt for the leak rail — gap GUARD-06/07).
    guardrails: Option<GuardrailsConfig>,
    /// The profile/system prompt in force for this engine, supplied to the output-side
    /// system-prompt-leak rail (gap GUARD-06). `None` = no leak rail (the rail is skipped).
    system_prompt: Option<String>,
    /// Per-user spend/quota store consulted pre-turn (gap TURN-01). Default = no ceiling.
    budget: Box<dyn BudgetStore>,
    /// Outbound egress DLP policy (ADR-009, gap GUARD-04/05) — destination allow-list + secret
    /// taxonomy applied to every outbound tool argument. `None` = `EgressPolicy::default()`
    /// (secrets blocked, no destination restriction).
    egress_policy: Option<EgressPolicy>,
    /// Agent-loop hard iteration cap (config-driven via `ainxt-config`; defaults to
    /// [`DEFAULT_MAX_ITERS`]). A stuck-detector still applies within this bound.
    max_iters: usize,
    /// Classifies a provider error as retryable vs terminal (drives retry/failover).
    error_classifier: Box<dyn ErrorClassifier>,
    /// How many times to retry the SAME provider on a retryable error before failing over.
    max_provider_retries: usize,
    /// Exponential-backoff base (ms) between same-provider retries; 0 = no delay.
    retry_backoff_base_ms: u64,
    /// Prompt-injection defense (ADR-009). `None` = OFF (default). When on, untrusted tool
    /// results are scanned + fenced (instruction/data separation), and a tainted turn gates
    /// side-effecting tools.
    injection: Option<InjectionConfig>,
    /// The injection detector (default heuristic; production plugs an ML classifier).
    injection_scanner: Box<dyn InjectionScanner>,
    /// Observability sink — one `TurnMetrics` per turn (gap J/V). Default `NullTelemetry` (no-op).
    telemetry: Box<dyn TelemetrySink>,
    /// Per-provider token prices for cost attribution (config-driven; empty = cost 0/unknown).
    pricing: PriceTable,
    /// Context-Fabric memory reader (MEM-04). `None` = no memory injected (pre-wire behavior).
    memory: Option<Box<dyn memory::MemoryReader>>,
    /// Resolves the memory task class for a request (query planning by task, design §7.1). Default
    /// resolves every turn to `CasualChat` (personalization only); a surface with repo/incident
    /// context overrides it to pull the right org-knowledge sub-types.
    memory_task: Box<dyn Fn(&Request) -> ainxt_memory::fabric::TaskKind + Send + Sync>,
    /// Node-level attestation hook (ADR-021 §8.2, serving-ops SRV-02). `None` = not configured
    /// (pre-wire behavior). When set, it is consulted BEFORE any provider dispatch and a regulated
    /// turn is failed CLOSED if no attested node can serve it — never routed to an untrusted node.
    node_attestor: Option<Box<dyn serving::NodeAttestor>>,
    /// Optional §4/§6 wire sink. `None` (default) = only the legacy `Event` stream is produced. When
    /// set, the engine ALSO emits the typed [`EventEnvelope`]/[`WireEvent`] vocabulary (seq,
    /// control_plane_sha, compliance.notice, turn.completed{outcome}) for the transport to serialize.
    wire: Option<Box<dyn wire::WireSink>>,
    /// The control-repo commit the turn is pinned to (ADR-026 §6.2) — stamped on every wire
    /// envelope for reproducibility. Default `"unpinned"` until a deployment supplies the real sha.
    control_plane_sha: String,
    /// Resolves the [`PaymentBoundary`] of a pending tool action (name + raw args) on the approval
    /// path (§9, ADR-016). Default resolves every action to `PaymentBoundary::None` (pre-wire
    /// behavior). When it returns a `!= None` boundary, the action is ALWAYS routed through the
    /// approval gate and can be cleared ONLY by an explicit human `approve` — never
    /// `approve_for_session` and never a policy auto-decision (enforced via
    /// [`ApprovalRespond::is_valid`], mirroring the protocol invariant).
    payment_boundary: PaymentBoundaryResolver,
    /// §4.2 tri-signal data-class classifier — **signal 2** (compliance scan of args/input). Fused
    /// with the caller-declared class (signal 1) and a tool call's destination floor (signal 3), the
    /// most-sensitive reading is the EFFECTIVE data-class that gates model ROUTING before ranking
    /// (ADR-012): a request that under-declares, or an input/tool-result that smuggles a PAN, is
    /// routed as its TRUE class (a regulated class can never reach a cloud provider). Default is the
    /// std-only [`ainxt_tools::MarkerArgScanner`]; production plugs the NPCI PCI/DSS classifier behind the same
    /// trait. This is a CLASSIFICATION, never a turn denial — the turn proceeds redacted.
    arg_scanner: Box<dyn ArgClassScanner>,
    /// Bounded-inflight backpressure ADMISSION seam (§7.3, gap TURN "503 if over"). Consulted
    /// FIRST inside [`Engine::run_turn_cancellable`] — before authz/any provider — so a saturated
    /// fleet refuses a new turn UP FRONT with a typed [`ErrorCategory::Capacity`] retryable 503
    /// instead of piling onto an overloaded path. The returned [`capacity::AdmissionPermit`] is
    /// held for the whole turn (RAII on drop frees the slot on completion/cancel/failure/panic).
    /// The default is an in-process [`capacity::InflightGate`] with a GENEROUS ceiling
    /// ([`DEFAULT_MAX_INFLIGHT`]) so normal operation never trips it — a deployment (or a guard
    /// test) sets an explicit smaller bound via [`Engine::with_capacity_gate`], and a distributed
    /// transport can back the same trait with a Redis token bucket shared across daemon replicas.
    capacity: Box<dyn capacity::CapacityGate>,
    /// In-engine model-complexity classifier (BE, §4.1). Consulted ONLY on the UNPINNED routing path
    /// ([`Request::pinned_tier`] is `None`) to DERIVE the tier used as the router's soft preference.
    /// Default [`complexity::TierFromRequest`] echoes `req.tier` (byte-identical pre-wire behavior); a
    /// deployment installs [`complexity::HeuristicComplexityClassifier`] (or an ML one) via
    /// [`Engine::with_complexity_classifier`]. A hard tier PIN bypasses this and takes the hard filter.
    complexity: Box<dyn complexity::ComplexityClassifier>,
    /// Optional observability probe for the concurrent tool-dispatch round. `None` (default) = no
    /// instrumentation. When attached the engine records peak in-flight / total dispatches so ops (and
    /// tests) can observe that a multi-tool round dispatches concurrently while same-file edits serialize.
    dispatch_probe: Option<std::sync::Arc<dispatch::DispatchProbe>>,
    /// GAP-FIX tooling-mcp-plugins-routing (round 2) — `ainxt_tools::prompt_cache::PromptCache`
    /// (stable-prefix structural cache; §4.6-adjacent) previously had zero callers anywhere in the
    /// served turn pipeline, only its own crate's unit test (`r15_prompt_cache_stable_prefix.rs`).
    /// `None` (default) = no-op, byte-identical pre-wire behavior. When attached, EVERY served turn
    /// observes the session's stable prefix (the profile/system prompt) through it once, recording a
    /// hit ([`ainxt_tools::prompt_cache::CacheOutcome::Warm`]) or a cold/first-use/invalidated miss to
    /// the audit trail (the same testable seam the Context-Fabric memory read above uses), and a
    /// provider that actually served the turn is remembered as this session's warm-affinity hint —
    /// a real, observable USE of the cache, not merely a call that discards the outcome.
    prompt_cache: Option<std::sync::Arc<std::sync::Mutex<ainxt_tools::prompt_cache::PromptCache>>>,
}

/// Resolves the [`PaymentBoundary`] of a pending tool action from its `(name, raw_args)` on the
/// approval path (§9, ADR-016).
type PaymentBoundaryResolver = Box<dyn Fn(&str, &str) -> PaymentBoundary + Send + Sync>;

/// A tool call that cleared EVERY pre-dispatch gate (schema, OBO-authz, egress-DLP) and is queued
/// for CONCURRENT dispatch (gap: parallel tool dispatch, RUNTIME_FEATURE_FLOWS §1 step 7). Batching
/// is engaged only for the safe common case — injection defense OFF (no in-round result→gate taint
/// dependency), no approval/payment gate, single-phase — so the safety-critical serial paths
/// (approval, payment, injection taint propagation) are byte-identical to before. `file_lock`, when
/// set, is the shared async mutex for this call's edited file: two queued calls that edit the SAME
/// file share the lock and therefore serialize, while disjoint files dispatch concurrently.
struct PreparedCall {
    id: String,
    name: String,
    args: String,
    two_phase: bool,
    file_lock: Option<std::sync::Arc<tokio::sync::Mutex<()>>>,
}

/// Extract the string value of a top-level `"key": "value"` pair from a JSON-object args string,
/// dependency-free (the runtime slice avoids a JSON crate). Tolerant of whitespace; used only to
/// derive the same-file serialization key, so a miss simply means "no file lock" (less
/// serialization, never incorrect execution). Paths do not contain unescaped quotes, so the value is
/// read up to the next `"`. Slicing is on ASCII-quote boundaries, so it is UTF-8 safe.
fn json_string_field(s: &str, key: &str) -> Option<String> {
    let pat = format!("\"{key}\"");
    let after_key = &s[s.find(&pat)? + pat.len()..];
    let after_colon = after_key.trim_start();
    let after_colon = after_colon.strip_prefix(':')?.trim_start();
    let inner = after_colon.strip_prefix('"')?;
    let end = inner.find('"')?;
    Some(inner[..end].to_string())
}

/// GAP2 harness-sdk — a tool/capability whose name is in the `artifact.*` namespace (e.g.
/// `artifact.generate`) produces a result that a renderer/SDK consumer should treat as an artifact
/// reference, not opaque text. Returns the in-proc [`Event::Artifact`] to emit ALONGSIDE the legacy
/// [`Event::ToolResult`] for the same call id (never instead of it), so a consumer that understands
/// the richer vocabulary can route the result to artifact-aware handling (render/download/preview)
/// while an older consumer still sees the plain text.
fn artifact_event_for(name: &str, id: &str, output: &str) -> Option<Event> {
    if name.starts_with("artifact.") {
        Some(Event::Artifact {
            id: id.to_string(),
            capability: name.to_string(),
            output: output.to_string(),
        })
    } else {
        None
    }
}

impl Engine {
    pub fn new(
        compliance: Box<dyn ComplianceGate>,
        authz: Box<dyn Authorizer>,
        audit: Box<dyn AuditSink>,
        router: ModelRouter,
    ) -> Self {
        Engine {
            compliance,
            authz,
            audit,
            router,
            tools: None,
            approval: None,
            obo: None,
            guardrails: None,
            system_prompt: None,
            budget: Box::new(NoBudgetLimit),
            egress_policy: None,
            max_iters: DEFAULT_MAX_ITERS,
            error_classifier: Box::new(HeuristicErrorClassifier),
            max_provider_retries: 2,
            retry_backoff_base_ms: 20,
            injection: None,
            injection_scanner: Box::new(HeuristicInjectionScanner),
            telemetry: Box::new(NullTelemetry),
            pricing: PriceTable::new(),
            memory: None,
            memory_task: Box::new(|_req| ainxt_memory::fabric::TaskKind::CasualChat),
            node_attestor: None,
            wire: None,
            control_plane_sha: "unpinned".to_string(),
            payment_boundary: Box::new(|_name, _args| PaymentBoundary::None),
            // §1.9 detector DoS hardening on the LIVE path: the default arg-class scanner is the
            // std-only marker scanner wrapped in the DoS-hardening decorator (input bounding +
            // per-call wall-clock budget + fail-closed). Classification of in-budget input is
            // identical to the bare scanner, so this hardens availability without changing detection
            // behavior; a crafted super-linear/oversized payload can no longer pin the turn's worker.
            arg_scanner: Box::new(ainxt_tools::default_hardened_scanner()),
            // Backpressure admission seam ON by default at a GENEROUS ceiling — the seam is always
            // exercised (every turn acquires/releases a permit) so the code path is never dead, but
            // normal operation is never refused. A guard test / deployment installs an explicit
            // smaller bound via `with_capacity_gate`.
            capacity: Box::new(capacity::InflightGate::new(DEFAULT_MAX_INFLIGHT)),
            // Default: echo the request's soft tier (byte-identical pre-wire routing). A deployment
            // installs a real complexity classifier via `with_complexity_classifier`.
            complexity: Box::new(complexity::TierFromRequest),
            dispatch_probe: None,
            prompt_cache: None,
        }
    }

    /// Install the in-engine complexity classifier consulted on the UNPINNED routing path to DERIVE
    /// the model-complexity tier (BE, §4.1). Default echoes `req.tier`; a deployment installs
    /// [`complexity::HeuristicComplexityClassifier`] (deterministic, model-agnostic) or an ML one.
    /// A hard tier PIN ([`Request::pinned_tier`]) bypasses the classifier and takes the hard filter.
    pub fn with_complexity_classifier(
        mut self,
        classifier: Box<dyn complexity::ComplexityClassifier>,
    ) -> Self {
        self.complexity = classifier;
        self
    }

    /// Attach an observability probe for the concurrent tool-dispatch round (peak in-flight / total).
    /// Default is no probe. Additive; never changes dispatch behavior — only observes it.
    pub fn with_dispatch_probe(mut self, probe: std::sync::Arc<dispatch::DispatchProbe>) -> Self {
        self.dispatch_probe = Some(probe);
        self
    }

    /// Attach a [`ainxt_tools::prompt_cache::PromptCache`] to the served turn pipeline (GAP-FIX
    /// tooling-mcp-plugins-routing round 2). Default is no cache (byte-identical pre-wire behavior —
    /// the observe/affinity call sites in [`Engine::run_turn_cancellable`] are skipped entirely).
    /// Shared as an `Arc<Mutex<_>>` so a caller can hold the SAME handle to assert on cache state
    /// (hit/miss, affinity) after driving a turn through the real composition-root path.
    pub fn with_prompt_cache(
        mut self,
        cache: std::sync::Arc<std::sync::Mutex<ainxt_tools::prompt_cache::PromptCache>>,
    ) -> Self {
        self.prompt_cache = Some(cache);
        self
    }

    /// Install the bounded-inflight backpressure admission gate (§7.3). Consulted FIRST in
    /// [`Engine::run_turn_cancellable`]; when the fleet is at the ceiling a new turn is refused up
    /// front with a typed [`ErrorCategory::Capacity`] retryable 503 (no provider is contacted, all
    /// mandatory gates are bypassed only by never starting). Default is a generous in-process
    /// [`capacity::InflightGate`]; a distributed transport backs the same trait with a shared limiter.
    pub fn with_capacity_gate(mut self, gate: Box<dyn capacity::CapacityGate>) -> Self {
        self.capacity = gate;
        self
    }

    /// Override the §4.2 data-class classifier (signal 2). Default is the std-only
    /// [`ainxt_tools::MarkerArgScanner`]; a deployment installs the NPCI PCI/DSS classifier behind the same trait
    /// so the tri-signal routing verdict uses the production detector. Never blocks — only classifies.
    pub fn with_arg_scanner(mut self, scanner: Box<dyn ArgClassScanner>) -> Self {
        self.arg_scanner = scanner;
        self
    }

    /// Install the payment-boundary resolver (§9, ADR-016). When it returns a `!= None` boundary for
    /// a pending tool action, the action is always routed through the approval gate and can be cleared
    /// ONLY by an explicit human `approve` (never `approve_for_session`, never a policy auto-decision).
    /// Default resolves every action to `PaymentBoundary::None`.
    pub fn with_payment_boundary_resolver(mut self, f: PaymentBoundaryResolver) -> Self {
        self.payment_boundary = f;
        self
    }

    /// Read-only probe of the installed payment-boundary resolver (§9, ADR-016) — calls the exact
    /// closure the approval gate consults at dispatch time (`(self.payment_boundary)(&name, &args)`,
    /// the tri-state gate above), never a copy or a re-derivation of it. Exists so a composition
    /// root's own test suite can prove WHICH resolver a served engine was actually built with
    /// (the default `|_, _| PaymentBoundary::None` vs. a deployment's real classifier) without
    /// needing a live provider to drive a tool call through the full turn pipeline — the same
    /// reachability role [`Engine::has_obo`]/[`Engine::has_tools`] play for their own seams.
    pub fn probe_payment_boundary(&self, name: &str, args: &str) -> PaymentBoundary {
        (self.payment_boundary)(name, args)
    }

    /// Attach the node-level attestation hook (ADR-021 §8.2). When set, the engine consults it before
    /// any provider dispatch and refuses a regulated turn (fail-closed) if no attested node can serve
    /// it. Default is no attestor (attestation owned by the deployment / pre-wire behavior).
    pub fn with_node_attestor(mut self, attestor: Box<dyn serving::NodeAttestor>) -> Self {
        self.node_attestor = Some(attestor);
        self
    }

    /// Attach the optional §4/§6 wire sink. When set, the engine emits the typed
    /// [`EventEnvelope`]/[`WireEvent`] vocabulary alongside the legacy `Event` stream (additive; the
    /// primary sink is unchanged). Default is no wire sink.
    pub fn with_wire_sink(mut self, sink: Box<dyn wire::WireSink>) -> Self {
        self.wire = Some(sink);
        self
    }

    /// Set the control-repo commit sha stamped on every wire envelope (reproducibility, ADR-026).
    pub fn with_control_plane_sha(mut self, sha: impl Into<String>) -> Self {
        self.control_plane_sha = sha.into();
        self
    }

    /// Attach the Context-Fabric memory reader (MEM-04). When set, the engine reads governed memory
    /// under the caller's identity scope on the context-assembly step and threads the hits + a
    /// forensic-replay lineage into the prompt. Default is no memory.
    pub fn with_memory(mut self, reader: Box<dyn memory::MemoryReader>) -> Self {
        self.memory = Some(reader);
        self
    }

    /// Override how the memory task class is derived from a request (query planning by task, §7.1).
    /// Default resolves to `CasualChat`; a repo/incident surface supplies `CodeGen`/`IncidentTriage`.
    pub fn with_memory_task_resolver(
        mut self,
        f: Box<dyn Fn(&Request) -> ainxt_memory::fabric::TaskKind + Send + Sync>,
    ) -> Self {
        self.memory_task = f;
        self
    }

    /// Seconds since the Unix epoch — the logical `now` fed to the memory read (usage-decay/staleness).
    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Attach an observability sink (default is the no-op `NullTelemetry`). One `TurnMetrics` is
    /// emitted per turn — an OTLP/OTel exporter implements the same `TelemetrySink` seam.
    pub fn with_telemetry(mut self, sink: Box<dyn TelemetrySink>) -> Self {
        self.telemetry = sink;
        self
    }

    /// Set the per-provider price table used to attribute cost per turn (config-driven).
    pub fn with_pricing(mut self, pricing: PriceTable) -> Self {
        self.pricing = pricing;
        self
    }

    /// Turn on prompt-injection defense (ADR-009) from config. **OFF by default.** An `Off`-mode
    /// config is a no-op. When on, untrusted tool results are fenced (instruction/data separation)
    /// and scanned; in `Enforce`, suspicious untrusted content taints the turn and gates
    /// side-effecting tools.
    ///
    /// Also threads `cfg.egress` onto the engine's outbound DLP policy (gap GUARD-04/05) —
    /// independent of `mode`, since egress DLP and prompt-injection detection are separate
    /// concerns: a deployment gets its own destination allow-list / secret taxonomy even with
    /// injection detection `Off`. Without this call the engine's egress dispatch loop
    /// (`guard_egress_for_turn`) still runs on every `egress`-declared tool with
    /// `EgressPolicy::default()` — a real fail-closed floor — this just makes that policy
    /// deployment-configurable instead of hardcoded.
    pub fn with_injection(mut self, cfg: &InjectionConfig) -> Self {
        self.egress_policy = Some(cfg.egress.clone());
        self.injection = if cfg.is_off() {
            None
        } else {
            Some(cfg.clone())
        };
        self
    }

    /// Plug in a custom injection detector (default is the heuristic pattern scanner).
    pub fn with_injection_scanner(mut self, scanner: Box<dyn InjectionScanner>) -> Self {
        self.injection_scanner = scanner;
        self
    }

    /// Set the agent-loop iteration cap (config-driven). Clamped to at least 1; callers should
    /// pass `ainxt-config` `limits.max_agent_iters`, which is already ceilinged at parse time.
    pub fn with_max_iters(mut self, n: usize) -> Self {
        self.max_iters = n.max(1);
        self
    }

    /// Plug in a custom provider-error classifier (default is the heuristic string matcher).
    pub fn with_error_classifier(mut self, classifier: Box<dyn ErrorClassifier>) -> Self {
        self.error_classifier = classifier;
        self
    }

    /// Configure same-provider retry: how many retries on a retryable error, and the
    /// exponential-backoff base in ms (0 = retry with no delay). Config-driven via `ainxt-config`.
    pub fn with_retry(mut self, max_retries: usize, backoff_base_ms: u64) -> Self {
        self.max_provider_retries = max_retries;
        self.retry_backoff_base_ms = backoff_base_ms;
        self
    }

    /// Total (input, output, cost_micros) for a turn, pricing EACH provider's committed tokens at
    /// ITS OWN rate (a turn spread across a failover is billed correctly, gap V).
    fn sum_usage(
        &self,
        by_provider: &std::collections::HashMap<String, (u64, u64)>,
    ) -> (u64, u64, u64) {
        let mut inp = 0u64;
        let mut out = 0u64;
        let mut cost = 0u64;
        for (pid, (i, o)) in by_provider {
            inp = inp.saturating_add(*i);
            out = out.saturating_add(*o);
            cost = cost.saturating_add(self.pricing.cost_micros(pid, *i, *o));
        }
        (inp, out, cost)
    }

    /// Emit one observability + cost record for a turn (gap J/V). Cost is precomputed by the
    /// caller (per-provider); a no-op sink (the default) makes this cheap.
    #[allow(clippy::too_many_arguments)]
    fn emit_metrics(
        &self,
        req: &Request,
        actor: &str,
        provider: &str,
        input_tokens: u64,
        output_tokens: u64,
        cost_micros: u64,
        redactions: usize,
        tool_calls: usize,
        latency_ms: u64,
        outcome: TurnOutcomeKind,
    ) {
        self.telemetry.record_turn(&TurnMetrics {
            session: req.session.clone(),
            turn: req.turn.clone(),
            actor: actor.to_string(),
            provider: provider.to_string(),
            data_class: req.data_class,
            input_tokens,
            output_tokens,
            cost_micros,
            latency_ms,
            redactions,
            tool_calls,
            outcome,
        });
    }

    /// Exponential backoff between same-provider retries, RACED against cancellation. Returns
    /// `true` if the token was cancelled during the wait (so the caller must abort rather than
    /// re-invoke the provider). No-op (returns `false`) when the base is 0.
    async fn backoff(&self, attempt: usize, cancel: &CancelToken) -> bool {
        if self.retry_backoff_base_ms == 0 {
            return cancel.is_cancelled();
        }
        let ms = self
            .retry_backoff_base_ms
            .saturating_mul(1u64 << attempt.min(16));
        tokio::select! {
            biased;
            _ = cancel.cancelled() => true,
            _ = tokio::time::sleep(std::time::Duration::from_millis(ms)) => false,
        }
    }

    /// Attach a tool runtime, enabling the agent loop to dispatch tool calls. Takes ownership of a
    /// freshly-built [`ToolRuntime`] and wraps it as this engine's OWN, un-shared handle — the ordinary
    /// entrypoint for a single-dispatcher composition. Use [`Engine::with_shared_tools`] when a second
    /// dispatcher (e.g. a harness `/run` bridge) must dispatch through the SAME registry + exactly-once
    /// ledger as this engine (R16, §0/§1.2).
    pub fn with_tools(mut self, tools: ToolRuntime) -> Self {
        self.tools = Some(std::sync::Arc::new(tools));
        self
    }

    /// Install a PRE-BUILT, SHARED [`ToolRuntime`] handle (R16, §0/§1.2) — the seam that lets the
    /// composition root hand the served engine's exact registry + exactly-once ledger to a second
    /// dispatcher (the harness `/run` capability bridge) via a cloned `Arc`, instead of each side
    /// building its own disjoint instance. Collapsing to one shared instance is what makes the SAME
    /// caller-supplied idempotency key retried through either path dedupe against the SAME ledger row —
    /// a bare second [`ToolRuntime`] (even one registering the identical capabilities) would keep its
    /// own independent ledger and could commit the SAME semantic action twice.
    pub fn with_shared_tools(mut self, tools: std::sync::Arc<ToolRuntime>) -> Self {
        self.tools = Some(tools);
        self
    }

    /// Whether a tool runtime is assembled (so the tool-safety pipeline — OBO authz, injection
    /// taint-gate, exactly-once ledger, approval gate — is live, not dead code). A composition binary
    /// that forgets `with_tools`/`with_shared_tools` leaves this false, which is a shippable-but-inert
    /// safety bug.
    pub fn has_tools(&self) -> bool {
        self.tools.is_some()
    }

    /// The turn pipeline's **mandatory** compliance gate (step 3 in / step 8 out), exposed so a
    /// surface that legitimately answers WITHOUT running a provider round — a clarification
    /// question, a doc-generation echo, a cache hit — can still put its bytes through the same
    /// scan every engine-produced byte goes through.
    ///
    /// This exists because the alternative is worse. `run_turn` cannot be the only way to reach the
    /// gate: a surface that short-circuits then has *no* way to comply, and the observed result was
    /// a doc-generation turn echoing the user's own text — a PAN included — straight onto the wire
    /// and into session history, with no redaction and no audit record. Read-only by construction:
    /// a caller may run the gate, never replace or remove it.
    ///
    /// Using this is not a substitute for a full engine turn. It covers compliance-OUT only; a
    /// short-circuiting surface is still responsible for authorization and for writing its own
    /// audit record (see [`Engine::audit_short_circuit`]).
    pub fn compliance(&self) -> &dyn ComplianceGate {
        self.compliance.as_ref()
    }

    /// The [`ModelRouter`](router::ModelRouter) this engine dispatches through — read-only, so a
    /// surface layered on top (e.g. `ainxt-chat`'s served Context-Fabric window) can resolve the
    /// REAL tier-eligible provider set (gap context-fabric: budget-fit fake eligible list) instead
    /// of hardcoding a placeholder. A caller may read the router's admissible routes, never swap it.
    pub fn router(&self) -> &router::ModelRouter {
        &self.router
    }

    /// Run §1 step 2 (identity + policy) for a turn a surface intends to answer WITHOUT an engine
    /// round — the same `chat.send` check, against the same authorizer, writing the same audit
    /// record on denial.
    ///
    /// A surface that short-circuits must not become a way to skip authorization. The concrete case
    /// this closes: the chat answer cache is partitioned per-DEPARTMENT for internal/public classes,
    /// so a department peer who lacks `chat.send` — or whose access was revoked after the entry was
    /// written — was still served the cached answer, because the only `chat.send` check lived
    /// inside `run_turn` and a cache hit never reaches it.
    pub fn authorize_short_circuit(
        &self,
        principal: &Principal,
        session: &str,
        turn: &str,
    ) -> Result<(), TurnError> {
        if let Decision::Deny(reason) = self.authz.authorize(principal, CAP_CHAT_SEND) {
            // A refused turn is a governance event: it lands in the mandatory audit trail, exactly
            // as a denial inside the pipeline does.
            self.audit.record(AuditRecord {
                session: session.to_string(),
                turn: turn.to_string(),
                actor: principal.user_id.clone(),
                summary: format!("authz denied short-circuit turn (chat.send): {reason}"),
            });
            return Err(TurnError::Denied(reason));
        }
        Ok(())
    }

    /// Record an [`AuditRecord`] for a turn a surface answered WITHOUT an engine round.
    ///
    /// §1 step 10 says every turn produces an audit record. A short-circuited turn is still a turn:
    /// it consumed a user input and emitted an answer, so an auditor asking "what did this user see
    /// and when" must find it. `provider` names the surface that answered (`"chat-clarify"`,
    /// `"chat-cache"`, …) so a short-circuit is distinguishable from a model answer in the log.
    pub fn audit_short_circuit(
        &self,
        principal: &Principal,
        session: &str,
        turn: &str,
        provider: &str,
        redactions: usize,
    ) {
        self.audit.record(AuditRecord {
            session: session.to_string(),
            turn: turn.to_string(),
            actor: principal.user_id.clone(),
            summary: format!("short-circuit answer via {provider}; redactions={redactions}"),
        });
    }

    /// GAP-FIX guardrails-injection (ADR-009) — mirrors [`Engine::audit_short_circuit`]'s existing
    /// passthrough pattern. Before this, a RAG-retrieval injection scan's `Suspicious` reasons
    /// (`InjectionVerdict::Suspicious(Vec<String>)`) were collapsed to a bare `bool` at the served
    /// `ainxt-convo` call sites and thrown away — `req.untrusted_tainted` reached the tool-dispatch
    /// gate, but WHY a chunk was flagged never reached the audit trail, so a regulator/operator could
    /// see a turn ran tool-restricted but not the injection category that caused it. `self.audit` is
    /// private to this crate, so a served caller needs this thin passthrough to reach it.
    pub fn audit_injection_taint(
        &self,
        principal: &Principal,
        session: &str,
        turn: &str,
        reasons: &[String],
    ) {
        self.audit.record(AuditRecord {
            session: session.to_string(),
            turn: turn.to_string(),
            actor: principal.user_id.clone(),
            summary: format!("retrieval injection scan flagged: {}", reasons.join("; ")),
        });
    }

    /// Attach an approval gate. High-risk tools consult it before dispatch; without a gate a
    /// high-risk tool is refused (fail-closed).
    pub fn with_approval(mut self, gate: Box<dyn ApprovalGate>) -> Self {
        self.approval = Some(gate);
        self
    }

    /// R14 (served-composition, HIGH) — route the agent loop's single-phase tool dispatch through the
    /// audited THREE-LAYER On-Behalf-Of gate ([`ToolRuntime::dispatch_obo_audited`]) instead of the
    /// bare `dispatch_for`: for every tool call the loop builds an [`OboContext`](ainxt_tools::obo::OboContext)
    /// from the acting principal (its held capabilities are its declared grants AND its issued scope;
    /// its clearance is the resource-ABAC ceiling) and asks `policy` — declared grant ∧ issued scope ∧
    /// resource clearance — writing the decision to `sink` BEFORE any effect. A denial hard-blocks with
    /// the agent's ambient credential never substituted (the confused-deputy fix). Additive: absent
    /// this the loop keeps its prior `dispatch_for` behaviour.
    pub fn with_obo(
        mut self,
        policy: Box<dyn ainxt_tools::obo::OboPolicy>,
        sink: std::sync::Arc<dyn ainxt_tools::obo::OboDecisionSink>,
    ) -> Self {
        self.obo = Some(EngineObo { policy, sink });
        self
    }

    /// Whether the audited three-layer OBO gate is installed on the agent loop (R14). A composition
    /// binary that forgets `with_obo` leaves the loop on the un-audited user-id-scoped `dispatch_for`.
    pub fn has_obo(&self) -> bool {
        self.obo.is_some()
    }

    /// Turn on the optional guardrails layer (ADR-008) from config. **OFF by default** — call
    /// this only when a deployment opts in. An all-`Off` config yields an empty chain (no-op),
    /// so passing a default config is equivalent to leaving guardrails off.
    pub fn with_guardrails(mut self, cfg: &GuardrailsConfig) -> Self {
        // Keep the config (not a prebuilt chain) so both the input and per-turn output chains can be
        // built. `None` when every rail — including the output-only system-prompt-leak rail — is Off,
        // so a fully-off config stays a no-op on both paths.
        self.guardrails = if cfg.is_off() {
            None
        } else {
            Some(cfg.clone())
        };
        self
    }

    /// Supply the profile/system prompt used this turn. The output-side system-prompt-leak rail
    /// (gap GUARD-06) needs it to detect the model regurgitating its own instructions; without it the
    /// leak rail is skipped. Other output rails (toxicity/topic/groundedness) do not require it.
    pub fn with_system_prompt(mut self, system_prompt: impl Into<String>) -> Self {
        self.system_prompt = Some(system_prompt.into());
        self
    }

    /// Attach the per-user budget store consulted pre-turn (gap TURN-01). Default is no ceiling.
    pub fn with_budget_store(mut self, store: Box<dyn BudgetStore>) -> Self {
        self.budget = store;
        self
    }

    /// Set the outbound egress DLP policy (gap GUARD-04/05): destination allow-list + secret
    /// taxonomy enforced on every outbound tool argument. Without this the default policy applies
    /// (block on any detected secret; no destination restriction).
    pub fn with_egress_policy(mut self, policy: EgressPolicy) -> Self {
        self.egress_policy = Some(policy);
        self
    }

    /// Conservative pre-turn cost/token estimate from the input size (~4 chars/token), used ONLY to
    /// pre-check the spend ceiling (gap TURN-01). Deterministic and provider-agnostic; the
    /// authoritative committed cost is still attributed post-turn via telemetry.
    fn estimate_turn_cost(input: &str) -> u64 {
        ((input.len() as u64) / 4).max(1)
    }

    /// Compliance-OUT for a legacy provider [`Event`] before it may reach the transport — the I4
    /// invariant ("nothing text-bearing leaves the runtime unscanned") applied to EVERY outbound
    /// event, not just `TextDelta`/`ToolCallStart`/`Usage`. Every text-bearing field is scanned
    /// (redact-and-proceed, never blocking); text-free control events pass through unchanged.
    /// Returns the scanned event to forward, its redaction count, and the compliance-notice category
    /// (present only when something was redacted).
    ///
    /// The match is EXHAUSTIVE by construction: a future text-bearing `Event` variant added to the
    /// protocol enum will fail to COMPILE here until it is explicitly routed through compliance — a
    /// fail-CLOSED design, so no unknown text-bearing variant can ever be forwarded raw. This is the
    /// single choke point for the catch-all provider events (`ToolResult`, `ApprovalRequest`), which
    /// were previously forwarded verbatim.
    fn scan_outbound_event(&self, ev: Event) -> (Event, usize, Option<&'static str>) {
        let cat = |n: usize, c: &'static str| if n > 0 { Some(c) } else { None };
        match ev {
            Event::TextDelta(t) => {
                let r = self.compliance.scan(&t, Direction::Output);
                let c = cat(r.redactions, "output");
                (Event::TextDelta(r.text), r.redactions, c)
            }
            // GAP-AUDIT turn-pipeline #6 — reasoning content is model output too (I4): scanned
            // identically to `TextDelta`, never forwarded raw.
            Event::ReasoningDelta(t) => {
                let r = self.compliance.scan(&t, Direction::Output);
                let c = cat(r.redactions, "output");
                (Event::ReasoningDelta(r.text), r.redactions, c)
            }
            Event::ToolCallStart { id, name, args } => {
                let r = self.compliance.scan(&args, Direction::ToolArgs);
                let c = cat(r.redactions, "tool-args");
                (
                    Event::ToolCallStart {
                        id,
                        name,
                        args: r.text,
                    },
                    r.redactions,
                    c,
                )
            }
            Event::ToolResult { id, output } => {
                let r = self.compliance.scan(&output, Direction::ToolResult);
                let c = cat(r.redactions, "tool-result");
                (Event::ToolResult { id, output: r.text }, r.redactions, c)
            }
            Event::ApprovalRequest { id, summary } => {
                let r = self.compliance.scan(&summary, Direction::Output);
                let c = cat(r.redactions, "approval");
                (
                    Event::ApprovalRequest {
                        id,
                        summary: r.text,
                    },
                    r.redactions,
                    c,
                )
            }
            Event::Error(msg) => {
                // Provider-supplied error text can echo the prompt/args; scan it too.
                let r = self.compliance.scan(&msg, Direction::Output);
                let c = cat(r.redactions, "error");
                (Event::Error(r.text), r.redactions, c)
            }
            // GAP2 harness-sdk — `output` is the same untrusted capability-result text a
            // `ToolResult` carries (this event is emitted alongside it for the same call), so it
            // gets the identical scan; the fail-closed choke point is what caught this variant
            // being added without a scan arm at compile time.
            Event::Artifact {
                id,
                capability,
                output,
            } => {
                let r = self.compliance.scan(&output, Direction::ToolResult);
                let c = cat(r.redactions, "tool-result");
                (
                    Event::Artifact {
                        id,
                        capability,
                        output: r.text,
                    },
                    r.redactions,
                    c,
                )
            }
            // Text-free control events carry nothing to scan.
            ev @ (Event::Usage { .. } | Event::Done) => (ev, 0, None),
        }
    }

    /// The same-file serialization key for a queued tool call, or `None` if the call does not edit a
    /// file (so it never blocks a peer). A call "edits a file" when the tool is side-effecting AND its
    /// JSON args carry a `path`/`file`/`filename` string — two calls resolving the same path share one
    /// async mutex and therefore serialize; disjoint paths dispatch concurrently (gap: parallel tool
    /// dispatch, "serialize any two tool calls that edit the SAME file"). Deterministic + pure.
    fn edit_file_target(tools: &ToolRuntime, name: &str, args: &str) -> Option<String> {
        if tools.is_side_effecting(name) != Some(true) {
            return None;
        }
        for key in ["path", "file", "filename"] {
            if let Some(p) = json_string_field(args, key) {
                if !p.is_empty() {
                    return Some(p);
                }
            }
        }
        None
    }

    /// The raw single-phase / two-phase dispatch of ONE cleared tool call (7c), on behalf of the
    /// acting principal. Extracted so BOTH the serial path and the concurrent batch share one
    /// dispatch contract (exactly-once ledger keying, OBO audit, two-phase commit). Synchronous:
    /// `ToolRuntime` dispatch does not await; the concurrency is composed AROUND this call.
    fn dispatch_one(
        &self,
        tools: &ToolRuntime,
        principal: &Principal,
        name: &str,
        args: &str,
        two_phase: bool,
    ) -> String {
        let flat = |dr: DispatchResult| -> String {
            match dr {
                DispatchResult::Ok(r) | DispatchResult::Deduped(r) => r,
                DispatchResult::Failed(e) => format!("tool '{name}' failed: {e}"),
                DispatchResult::NeedsReconciliation => {
                    format!("tool '{name}' is in-doubt; manual reconciliation required")
                }
                DispatchResult::Blocked(b) => format!("tool '{name}' blocked: {b}"),
            }
        };
        let uid = principal.user_id.as_str();
        if two_phase {
            let now_tick = Self::now_secs();
            match tools.dry_run_for(uid, name, args, now_tick, TWO_PHASE_TTL_SECS) {
                Ok(dr) => flat(tools.commit_for(uid, name, args, &dr.commit_key, now_tick)),
                Err(refused) => flat(refused),
            }
        } else if let Some(obo) = &self.obo {
            let grants: Vec<ainxt_tools::obo::Grant> = principal
                .caps
                .iter()
                .map(|c| ainxt_tools::obo::Grant::new(c, "*", "*"))
                .collect();
            let ctx = ainxt_tools::obo::OboContext::new(
                principal.user_id.clone(),
                grants,
                principal.caps.iter().cloned(),
                principal.clearance,
            );
            flat(tools.dispatch_obo_audited(
                &ctx,
                obo.policy.as_ref(),
                obo.sink.as_ref(),
                name,
                args,
                "invoke",
            ))
        } else {
            flat(tools.dispatch_for(uid, name, args))
        }
    }

    /// Dispatch a batch of cleared tool calls CONCURRENTLY (gap: parallel tool dispatch). Every
    /// in-flight tool future shares the ONE round `cancel` token — a cancel/timeout aborts the whole
    /// round (a future that has not yet dispatched returns without touching the tool). Two calls that
    /// edit the SAME file share an async mutex and serialize; disjoint calls overlap. Results are
    /// returned in the SAME order as `batch` regardless of completion order, so the audit log / result
    /// stream stay deterministic. `dispatch_one` itself is synchronous (this slice's `ToolRuntime`),
    /// so real overlap materializes when async tool IO lands; the structure, the same-file lock, and
    /// the shared cancel are enforced now, and `dispatch_probe` observes the peak concurrency.
    async fn dispatch_prepared_concurrent(
        &self,
        tools: &ToolRuntime,
        principal: &Principal,
        batch: &[PreparedCall],
        cancel: &CancelToken,
    ) -> Vec<Option<String>> {
        use std::future::poll_fn;
        use std::pin::Pin;
        use std::task::Poll;

        // `None` output = the call was NOT dispatched (round-wide cancel took the slot); the caller
        // then emits nothing for it, matching the serial path's "no further dispatch after cancel".
        type DispatchFut<'f> =
            Pin<Box<dyn std::future::Future<Output = (usize, Option<String>)> + Send + 'f>>;
        let mut pending: Vec<DispatchFut<'_>> = Vec::with_capacity(batch.len());
        for (idx, p) in batch.iter().enumerate() {
            let probe = self.dispatch_probe.clone();
            let lock = p.file_lock.clone();
            let name = p.name.clone();
            let args = p.args.clone();
            let two_phase = p.two_phase;
            pending.push(Box::pin(async move {
                // Same-file serialization: hold the file's mutex across the dispatch. Disjoint files
                // take different mutexes and never block each other.
                let _guard = match lock {
                    Some(m) => Some(m.lock_owned().await),
                    None => None,
                };
                // Shared cancel: a round-wide cancel aborts a not-yet-dispatched call cleanly.
                if cancel.is_cancelled() {
                    return (idx, None);
                }
                // Mark in-flight BEFORE the interleave point so peak concurrency is observable: two
                // disjoint calls are both in flight across the yield; a same-file peer is still parked
                // on the mutex above and never enters concurrently.
                if let Some(pr) = probe.as_ref() {
                    pr.enter();
                }
                // Cooperative interleave point — where real async tool IO overlaps peers.
                tokio::task::yield_now().await;
                // Re-check AFTER the interleave point: a PEER tool (or a timeout) may have cancelled
                // the SHARED token while we were parked — the cancel aborts the whole round, so we
                // must NOT fire this side effect. This is the concurrent analogue of the serial loop's
                // per-call cancel checkpoint.
                let out = if cancel.is_cancelled() {
                    None
                } else {
                    Some(self.dispatch_one(tools, principal, &name, &args, two_phase))
                };
                if let Some(pr) = probe.as_ref() {
                    pr.exit();
                }
                (idx, out)
            }));
        }

        let mut results: Vec<Option<String>> = (0..batch.len()).map(|_| None).collect();
        poll_fn(|cx| {
            let mut i = 0;
            while i < pending.len() {
                match pending[i].as_mut().poll(cx) {
                    Poll::Ready((idx, out)) => {
                        results[idx] = out;
                        // The removed future is already resolved; drop it explicitly (it is `must_use`).
                        std::mem::drop(pending.remove(i));
                    }
                    Poll::Pending => i += 1,
                }
            }
            if pending.is_empty() {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
        results
    }

    /// Flush the concurrent-dispatch batch: dispatch every queued call concurrently
    /// ([`dispatch_prepared_concurrent`](Self::dispatch_prepared_concurrent)), then run the
    /// post-dispatch seams (7c-bis data-class escalation, 7d compliance-on-result + stream, feed-back)
    /// for each result IN QUEUE ORDER so the audit log / result stream are deterministic even though
    /// the dispatches completed concurrently. A no-op when the batch is empty, so on every serial /
    /// injection-on / approval path (where nothing is ever queued) behavior is byte-identical to
    /// before. Batching is only ever engaged with injection defense OFF, so 7e's taint scan does not
    /// apply here (there is no in-round result→gate dependency to preserve).
    #[allow(clippy::too_many_arguments)]
    async fn flush_dispatch_batch(
        &self,
        tools: &ToolRuntime,
        principal: &Principal,
        req: &Request,
        batch: &mut Vec<PreparedCall>,
        cancel: &CancelToken,
        route_class: &mut ainxt_types::DataClass,
        redactions: &mut usize,
        prompt: &mut String,
        wire: &mut wire::TurnWire<'_>,
        sink: &mpsc::Sender<Event>,
        rationale_sources: &mut Vec<String>,
    ) {
        if batch.is_empty() {
            return;
        }
        let results = self
            .dispatch_prepared_concurrent(tools, principal, batch, cancel)
            .await;
        for (p, result) in batch.iter().zip(results) {
            // A `None` result = the call was aborted by a round-wide cancel before its side effect;
            // emit nothing for it (exactly as the serial path's post-cancel calls produce nothing).
            let Some(result) = result else {
                continue;
            };
            // 7c-bis. §4.2 tri-signal classification feeding the router (raise route_class for the
            // NEXT round; never a turn denial).
            if let Some(eff) = tools.classify_data_class(&p.name, &p.args, &*self.arg_scanner) {
                if eff.class > *route_class {
                    self.audit.record(AuditRecord {
                        session: req.session.clone(),
                        turn: req.turn.clone(),
                        actor: principal.user_id.clone(),
                        summary: format!(
                            "data-class escalated {} -> {} (§4.2 tri-signal) by tool '{}'; \
                             subsequent rounds route at the tighter class",
                            route_class.as_str(),
                            eff.class.as_str(),
                            p.name
                        ),
                    });
                    *route_class = eff.class;
                }
            }
            // 7d. Compliance on the tool result before it re-enters context or streams out.
            let cr = self.compliance.scan(&result, Direction::ToolResult);
            *redactions += cr.redactions;
            if cr.redactions > 0 {
                wire.emit(WireEvent::ComplianceNotice {
                    categories: vec!["tool-result".to_string()],
                    action: ComplianceAction::Redacted,
                });
            }
            let _ = sink
                .send(Event::ToolResult {
                    id: p.id.clone(),
                    output: cr.text.clone(),
                })
                .await;
            // GAP2 harness-sdk — an `artifact.*` capability's result also gets the typed
            // Event::Artifact on the batched/concurrent dispatch path too.
            if let Some(artifact_event) = artifact_event_for(&p.name, &p.id, &cr.text) {
                let _ = sink.send(artifact_event).await;
            }
            wire.emit(WireEvent::ToolResult {
                call_id: p.id.clone(),
                blocks: vec![ResultBlock::Text {
                    text: cr.text.clone(),
                }],
                is_error: false,
            });
            // GAP-FIX rationale-sources — `turn.rationale`'s `sources` previously drew ONLY from
            // memory/Context-Fabric lineage (`{id}@v{version}`), so a turn grounded entirely on
            // tool-result/retrieval producers (a search/fetch tool, an MCP resource read, ...)
            // reported an empty "why this" panel even though real provenance existed. Every tool
            // call that actually completed (result observed by the model, whether success or a
            // surfaced tool-level error) is provenance for the turn's answer just as much as an
            // injected memory item is — record it in the same list, tagged so a renderer can tell
            // the two source KINDS apart (`mem:{id}@v{n}` vs `tool:{name}#{call_id}`).
            rationale_sources.push(format!("tool:{}#{}", p.name, p.id));
            // 7e reduces to identity here (injection OFF on the batched path): feed the observation
            // back for the next round in queue order.
            prompt.push_str(&format!("\n[tool {} result: {}]", p.name, cr.text));
        }
        batch.clear();
    }

    /// Run one chat turn, STREAMING each compliance-processed event to `sink` as it arrives.
    /// Order matches RUNTIME_FEATURE_FLOWS. Returns a summary once the stream completes.
    pub async fn run_turn(
        &self,
        principal: &Principal,
        req: &Request,
        sink: mpsc::Sender<Event>,
    ) -> Result<TurnSummary, TurnError> {
        self.run_turn_cancellable(principal, req, sink, &CancelToken::new())
            .await
    }

    /// Like [`Engine::run_turn`], but a [`CancelToken`] can abort the turn mid-flight: streaming
    /// stops, no further tool is dispatched, the stream receiver is dropped, and a terminal
    /// cancellation event is emitted. Cancellation is cooperative but prompt — checked at the
    /// turn boundary, each loop iteration, every stream `recv`, the retry backoff, and before
    /// each tool dispatch. (A read-parked provider task is bounded by the provider client's read
    /// timeout, not aborted synchronously.)
    pub async fn run_turn_cancellable(
        &self,
        principal: &Principal,
        req: &Request,
        sink: mpsc::Sender<Event>,
        cancel: &CancelToken,
    ) -> Result<TurnSummary, TurnError> {
        let started = std::time::Instant::now();
        // Token usage tallied PER PROVIDER (only committed/accepted attempts), so a turn spread
        // across a failover is priced at each provider's own rate — a failed attempt's tokens are
        // discarded, not billed to the serving provider (FinOps correctness, gap V).
        let mut usage_by_provider: std::collections::HashMap<String, (u64, u64)> =
            std::collections::HashMap::new();
        let mut tool_calls = 0usize;

        // §4/§6 wire emitter — additive to the legacy `Event` stream. No-op when no wire sink is
        // attached; when attached it stamps seq/ts/control_plane_sha on every typed event.
        let mut wire = wire::TurnWire::new(
            self.wire.as_deref(),
            &req.session,
            &req.turn,
            &self.control_plane_sha,
        );

        // GAP-AUDIT turn-pipeline #2 — `reasoning.delta` (§6.1) is documented as "Policy-gated —
        // only streamed to surfaces/roles the Policy Engine permits", but until now had ZERO
        // enforcement of that: it streamed unconditionally to every caller, on both the wire and
        // legacy transports, regardless of role/policy. Decided ONCE per turn (never mid-stream) via
        // the SAME `Authorizer::authorize` seam every other capability gate in this engine uses
        // (`Role::Admin` always passes via `Principal::has_cap`) — checked before either reasoning
        // emit site below ever buffers/streams a fragment.
        let reasoning_allowed = matches!(
            self.authz.authorize(principal, CAP_REASONING_VIEW),
            Decision::Allow
        );

        // 1. Cancellation pre-check — before any work.
        if cancel.is_cancelled() {
            let _ = sink.send(Event::Error("turn cancelled".into())).await;
            let _ = sink.send(Event::Done).await;
            wire.emit(WireEvent::TurnStopped {
                turn_id: req.turn.clone(),
            });
            self.emit_metrics(
                req,
                &principal.user_id,
                "cancelled",
                0,
                0,
                0,
                0,
                0,
                started.elapsed().as_millis() as u64,
                TurnOutcomeKind::Cancelled,
            );
            return Ok(TurnSummary {
                final_text: String::new(),
                redactions: 0,
                provider: "cancelled".into(),
                ..Default::default()
            });
        }

        // 1b. Backpressure ADMISSION (§7.3 "503 if over") — BEFORE authz and any provider work, so a
        //     saturated fleet sheds load up front rather than piling onto an overloaded path. On
        //     refusal the turn returns the typed retryable `ErrorCategory::Capacity` 503 and NEVER
        //     starts (no provider is contacted; the mandatory gates are bypassed only by never
        //     running). The permit is a RAII guard held for the whole turn: dropping it on ANY exit
        //     (success/cancel/failure/panic) frees the slot, so there is no leak path. The default
        //     gate's ceiling is generous, so this only fires under real saturation.
        let _admission = match self.capacity.try_admit() {
            Ok(permit) => permit,
            Err(err) => {
                let _ = sink.send(Event::Error(err.message.clone())).await;
                let _ = sink.send(Event::Done).await;
                wire.emit(WireEvent::TurnFailed {
                    turn_id: req.turn.clone(),
                    error: err.clone(),
                });
                self.audit.record(AuditRecord {
                    session: req.session.clone(),
                    turn: req.turn.clone(),
                    actor: principal.user_id.clone(),
                    summary: format!(
                        "backpressure admission refused turn (at capacity, {} in flight): {}",
                        self.capacity.inflight(),
                        err.message
                    ),
                });
                self.emit_metrics(
                    req,
                    &principal.user_id,
                    "capacity-refused",
                    0,
                    0,
                    0,
                    0,
                    0,
                    started.elapsed().as_millis() as u64,
                    TurnOutcomeKind::Rejected,
                );
                return Err(TurnError::Capacity(err.message));
            }
        };

        // 2. Identity + Policy (authz) — before anything touches a model.
        if let Decision::Deny(reason) = self.authz.authorize(principal, CAP_CHAT_SEND) {
            // Terminal events BEFORE returning, exactly as steps 1 / 2b / 2c and the routing error
            // below already do. This gate previously returned `Err` having emitted NOTHING: no
            // legacy `Event`, no `WireEvent`. The caller received `HTTP 200`,
            // `content-type: text/event-stream`, and a stream that closed with ZERO bytes — no
            // `turn.started`, no `error` frame, nothing in the log. A refusal indistinguishable
            // from success is the one outcome this runtime must never produce, and it defeated the
            // whole point of a fail-closed gate: the turn *was* correctly denied, but nobody could
            // tell. `capability_denied` (not retryable) is the right category — this is an
            // authorization decision, never a provider fault.
            let denied = format!("authz denied: {reason}");
            let _ = sink.send(Event::Error(denied.clone())).await;
            let _ = sink.send(Event::Done).await;
            wire.emit(WireEvent::TurnFailed {
                turn_id: req.turn.clone(),
                error: ProtocolError::new(ErrorCategory::CapabilityDenied, denied),
            });
            // An authz DENY at step 2 is written to the MANDATORY audit sink (not merely metered):
            // a refused turn is a governance/forensic event and must appear in the tamper-evident
            // trail alongside the emit_metrics record (gap: "authz denial not written to audit").
            self.audit.record(AuditRecord {
                session: req.session.clone(),
                turn: req.turn.clone(),
                actor: principal.user_id.clone(),
                summary: format!("authz denied turn at step 2 (chat.send): {reason}"),
            });
            self.emit_metrics(
                req,
                &principal.user_id,
                "none",
                0,
                0,
                0,
                0,
                0,
                started.elapsed().as_millis() as u64,
                TurnOutcomeKind::Rejected,
            );
            return Err(TurnError::Denied(reason));
        }

        // 2a. Clearance-vs-data-class is a RETRIEVAL read-FILTER, NOT a turn-admission gate. A turn
        //     whose input carries sensitive content (e.g. a PAN → `confidential`) MUST be redacted and
        //     PROCEED — never hard-denied — per the platform's compliance philosophy (redact-and-proceed).
        //     `principal.clearance` (the max data class this principal may READ) instead bounds what
        //     RETRIEVED context/memory a turn may surface: it is carried into the memory/retrieval read
        //     step below via `AccessScope::from_principal(principal)` and applied as a pre-rank chunk ACL,
        //     so a user cleared only to `internal` never has `confidential`+ documents RETURNED — while
        //     still being able to submit their own input and have it redacted. (A turn-level denial here
        //     would regress redact-and-proceed and the compliance-redaction conformance scenarios;
        //     clearance belongs on the read/retrieval path, not on turn admission.)

        // 2b. Budget/quota gate (gap TURN-01) — enforce the spend ceiling PRE-TURN, right after
        //     authz and BEFORE any provider call, so an over-ceiling turn is denied up front rather
        //     than merely recorded post-hoc. `limit == 0` = no ceiling. The decision math + typed
        //     error live in `ainxt_protocol::budget_gate`; the runtime supplies the spend/limit from
        //     its budget store and a conservative per-turn estimate.
        {
            let snap: BudgetSnapshot = self.budget.snapshot(principal);
            let estimated = Self::estimate_turn_cost(&req.input);
            if let BudgetOutcome::Deny(err) = budget_gate(snap.already_spent, snap.limit, estimated)
            {
                // Emit the typed protocol error as a session-level error event and end the turn
                // WITHOUT starting it (no provider is ever contacted).
                let _ = sink.send(Event::Error(err.message.clone())).await;
                let _ = sink.send(Event::Done).await;
                // ALSO on the typed wire, like every other terminal path. Without this the wire
                // stream depended on `ainxt_server::classify_legacy_error` recovering a category
                // from the message text — which works, but leaves the typed path with no
                // `turn.failed` for a turn that definitively ended.
                wire.emit(WireEvent::TurnFailed {
                    turn_id: req.turn.clone(),
                    error: err.clone(),
                });
                self.audit.record(AuditRecord {
                    session: req.session.clone(),
                    turn: req.turn.clone(),
                    actor: principal.user_id.clone(),
                    summary: format!("budget gate denied turn (pre-turn): {}", err.message),
                });
                self.emit_metrics(
                    req,
                    &principal.user_id,
                    "budget-denied",
                    0,
                    0,
                    0,
                    0,
                    0,
                    started.elapsed().as_millis() as u64,
                    TurnOutcomeKind::Rejected,
                );
                return Err(TurnError::Denied(err.message));
            }
        }

        // 2b-bis. §4.2 tri-signal data-class classification, BEFORE ranking (ADR-012). The caller
        //     supplies a *declared* class on the request (signal 1); a request that under-declares —
        //     or whose input smuggles a PAN/secret — must still be governed as its TRUE class. Fuse
        //     signal 1 with signal 2 (a compliance scan of the actual input) and escalate to the most
        //     sensitive (never average, never trust the lowest). The escalated `route_class` — not the
        //     raw `req.data_class` — is what gates BOTH the node-attestation admit (2c) and the model
        //     router's eligible-set (a regulated class can never reach a cloud provider). Later tool
        //     calls fold in signal 3 (destination) and can raise it further for subsequent rounds.
        //     This only ever TIGHTENS routing; it never denies the turn (which proceeds redacted).
        let mut route_class = {
            let scanned = self.arg_scanner.classify_args(&req.input);
            let eff = EffectiveDataClass::fuse(req.data_class, scanned, None);
            if eff.escalated {
                self.audit.record(AuditRecord {
                    session: req.session.clone(),
                    turn: req.turn.clone(),
                    actor: principal.user_id.clone(),
                    summary: format!(
                        "data-class escalated {} -> {} (§4.2 tri-signal, pre-rank) before routing",
                        req.data_class.as_str(),
                        eff.class.as_str()
                    ),
                });
            }
            eff.class
        };

        // 2c. Node-attestation gate (ADR-021 §8.2, serving-ops SRV-02) — before ANY model dispatch.
        //     For a regulated (`confidential`+) data class the fleet must offer a node currently
        //     attested to see this data; the runtime calls the Serving-Ops node-level entrypoint
        //     ([`serving::NodeAttestor::admit`], backed by `ServingGate::pre_serve_check`). On
        //     [`serving::AttestationOutcome::FailClosed`] the turn is refused here — it is NEVER routed
        //     to an untrusted node, even an idle one. Skipped entirely when no attestor is attached.
        //     Uses the ESCALATED `route_class`, so a smuggled PAN forces an attested-node requirement.
        if let Some(attestor) = self.node_attestor.as_ref() {
            if let serving::AttestationOutcome::FailClosed(reason) = attestor.admit(route_class) {
                let msg = format!("node attestation failed closed: {reason}");
                let _ = sink.send(Event::Error(msg.clone())).await;
                let _ = sink.send(Event::Done).await;
                wire.emit(WireEvent::TurnFailed {
                    turn_id: req.turn.clone(),
                    error: ProtocolError::new(ErrorCategory::CapabilityDenied, msg.clone()),
                });
                self.audit.record(AuditRecord {
                    session: req.session.clone(),
                    turn: req.turn.clone(),
                    actor: principal.user_id.clone(),
                    summary: format!(
                        "attestation gate denied turn (data_class {}): {reason}",
                        req.data_class.as_str()
                    ),
                });
                self.emit_metrics(
                    req,
                    &principal.user_id,
                    "attestation-denied",
                    0,
                    0,
                    0,
                    0,
                    0,
                    started.elapsed().as_millis() as u64,
                    TurnOutcomeKind::Rejected,
                );
                return Err(TurnError::Denied(msg));
            }
        }

        // §6.5 turn.started — all admission gates (cancel/authz/clearance/budget/attestation) passed;
        // the turn is now RUNNING. The envelope's control_plane_sha pins this turn's definitions.
        wire.emit(WireEvent::TurnStarted {
            turn_id: req.turn.clone(),
            parent_turn_id: None,
            participant_id: principal.user_id.clone(),
            model_hint: req.forced_provider.clone(),
        });

        // 3. Compliance IN — redact before the provider ever sees the input.
        let cin = self.compliance.scan(&req.input, Direction::Input);
        let mut redactions = cin.redactions;
        // §6.3 compliance.notice on the wire when the input scan redacted (category, never content).
        if cin.redactions > 0 {
            wire.emit(WireEvent::ComplianceNotice {
                categories: vec!["input".to_string()],
                action: ComplianceAction::Redacted,
            });
        }

        // 4. Guardrails IN (ADR-008) — OPT-IN only. Runs on the already-redacted input. In
        //    `Enforce`, a jailbreak/injection Block short-circuits the turn (fail-closed); in
        //    `Audit`, flags are recorded to the audit trail and the turn proceeds. Groundedness
        //    (output rail) passes here — there is no grounding context at input.
        let input_rails = self
            .guardrails
            .as_ref()
            .map(RailChain::for_input)
            .filter(|c| !c.is_empty());
        if let Some(rails) = input_rails.as_ref() {
            match rails.evaluate(&cin.text, &[]) {
                GuardrailOutcome::Allowed => {}
                GuardrailOutcome::Flagged(flags) => {
                    self.audit.record(AuditRecord {
                        session: req.session.clone(),
                        turn: req.turn.clone(),
                        actor: principal.user_id.clone(),
                        summary: format!(
                            "guardrails flagged (audit, proceeding): {}",
                            flags.join("; ")
                        ),
                    });
                }
                GuardrailOutcome::Blocked(reason) => {
                    let _ = sink
                        .send(Event::Error(format!("blocked by guardrails: {reason}")))
                        .await;
                    let _ = sink.send(Event::Done).await;
                    wire.emit(WireEvent::TurnFailed {
                        turn_id: req.turn.clone(),
                        error: ProtocolError::new(
                            ErrorCategory::CapabilityDenied,
                            format!("blocked by guardrails: {reason}"),
                        ),
                    });
                    self.audit.record(AuditRecord {
                        session: req.session.clone(),
                        turn: req.turn.clone(),
                        actor: principal.user_id.clone(),
                        summary: format!("guardrails blocked turn (enforce): {reason}"),
                    });
                    self.emit_metrics(
                        req,
                        &principal.user_id,
                        "guardrails-blocked",
                        0,
                        0,
                        0,
                        redactions,
                        0,
                        started.elapsed().as_millis() as u64,
                        TurnOutcomeKind::GuardrailsBlocked,
                    );
                    return Ok(TurnSummary {
                        final_text: String::new(),
                        redactions,
                        provider: "guardrails-blocked".to_string(),
                        ..Default::default()
                    });
                }
            }
        }

        // 5/6/7. Resilient need-driven agent loop. Each iteration streams a provider (with
        // retry + failover over the data-class-filtered chain), then dispatches any tool calls
        // through the ToolRuntime (compliance on args + result; exactly-once via the ledger),
        // feeds the observations back, and re-invokes — bounded by the iteration cap, a
        // repeat/stuck detector, and cooperative cancellation.
        let mut prompt = cin.text;

        // 4b. Context Fabric layer 12 (MEM-04): read governed memory under the CALLER's identity
        //     scope and thread the hits + a forensic-replay lineage into the prompt. This is NOT a
        //     separate retrieval path — it is the same pre-rank, identity/data-class-filtered read the
        //     Context Optimizer performs; query planning picks the right sub-types by task (§7.1). The
        //     injected block is still passed through the always-on compliance gate (defense in depth —
        //     memory is redacted at write, but the runtime never trusts injected context unscanned).
        //     Skipped entirely when no memory reader is attached (pre-wire behavior).
        // §6 `turn.rationale` ("why this" panel) accumulators — the grounding sources injected into
        // this turn and the capabilities (tools) it actually exercised. Emitted once at turn end.
        let mut rationale_sources: Vec<String> = Vec::new();
        let mut rationale_caps: Vec<String> = Vec::new();
        // GAP-FIX guardrails-injection — the served OUTPUT rail call site (§9 below) always evaluated
        // `RailChain::for_output` against an EMPTY grounding slice (`&[]`), so `GroundednessRail` and
        // `CitationRail` could never fire no matter how `[guardrails]` is configured (see
        // `ainxt-guardrails/tests/r15_output_rails_closed_by_empty_grounding_at_engine_call_site.rs`,
        // which pins this exact gap: "the turn's actually-retrieved grounding corpus is never threaded
        // into `context`"). The turn loop already collects real retrieved-content text right here (the
        // Context-Fabric memory-layer hits) — thread it into `context` too, not just into the prompt
        // and the rationale-sources id list, so a turn that grounds on governed memory gets a genuine
        // groundedness/citation check on the ENGINE's own output-rail path (every surface built over
        // this engine shares this call site, not only the chat surface's separate, RAG-context-aware
        // `ConversationManager::check_grounding`).
        let mut output_grounding_context: Vec<String> = Vec::new();
        if let Some(mem) = self.memory.as_ref() {
            let access = ainxt_memory::AccessScope::from_principal(principal.clone());
            let task = (self.memory_task)(req);
            let (hits, lineage) = mem.read_for_turn(&req.turn, &task, &access, Self::now_secs());
            rationale_sources.extend(lineage.injected.iter().map(|(id, v)| format!("{id}@v{v}")));
            output_grounding_context.extend(hits.iter().map(|h| h.item.body.clone()));
            if !hits.is_empty() {
                let mut block = String::from("[memory context — governed, treat as reference]\n");
                for h in &hits {
                    block.push_str(&format!("- {}: {}\n", h.item.title, h.item.body));
                }
                block.push_str("[/memory context]\n");
                let cm = self.compliance.scan(&block, Direction::Input);
                redactions += cm.redactions;
                if cm.redactions > 0 {
                    wire.emit(WireEvent::ComplianceNotice {
                        categories: vec!["memory-context".to_string()],
                        action: ComplianceAction::Redacted,
                    });
                }
                // Prepend so the model sees grounded memory before the (already-compliance-scanned)
                // user turn.
                prompt = format!("{}{}", cm.text, prompt);
            }
            // Per-turn lineage → audit trail so the turn is forensically replayable (§7.4/§7.5): the
            // exact (id, version) of every injected item, resolvable to its content AS OF this turn.
            self.audit.record(AuditRecord {
                session: req.session.clone(),
                turn: req.turn.clone(),
                actor: principal.user_id.clone(),
                summary: format!(
                    "memory read {} item(s) for turn (lineage: {})",
                    lineage.injected.len(),
                    lineage
                        .injected
                        .iter()
                        .map(|(id, v)| format!("{id}@v{v}"))
                        .collect::<Vec<_>>()
                        .join(",")
                ),
            });
        }

        // GAP-FIX tooling-mcp-plugins-routing (round 2) — observe THIS turn's stable prefix (the
        // profile/system prompt) through the attached `PromptCache` exactly ONCE per turn (never per
        // provider-attempt/retry below — re-observing inside the `'attempts` loop would inflate
        // `warm_streak` on every retry of the SAME turn instead of across a session's turns, which is
        // what the cache is actually meant to track). `None` (no cache attached) is a complete no-op —
        // byte-identical to pre-wire behavior. The stable prefix is captured once here so the
        // provider-success call site below (which sets session affinity) uses the IDENTICAL value.
        let prompt_cache_stable_prefix = self.system_prompt.clone().unwrap_or_default();
        if let Some(cache) = self.prompt_cache.as_ref() {
            let outcome = cache
                .lock()
                .expect("prompt cache lock")
                .observe(&req.session, &prompt_cache_stable_prefix);
            let summary = match outcome {
                ainxt_tools::prompt_cache::CacheOutcome::FirstUse => {
                    "prompt-cache first-use for this session's stable prefix".to_string()
                }
                ainxt_tools::prompt_cache::CacheOutcome::Warm { warm_streak } => {
                    format!("prompt-cache HIT (warm_streak={warm_streak}) for this session's stable prefix")
                }
                ainxt_tools::prompt_cache::CacheOutcome::Invalidated => {
                    "prompt-cache MISS: stable prefix changed since last turn, streak reset"
                        .to_string()
                }
            };
            self.audit.record(AuditRecord {
                session: req.session.clone(),
                turn: req.turn.clone(),
                actor: principal.user_id.clone(),
                summary,
            });
        }

        let mut final_text = String::new();
        // Output-side guardrails (ADR-008, gap GUARD-06/07): build the OUTPUT rail chain for THIS
        // turn (needs the live system prompt for the leak rail). When active, the model answer is
        // BUFFERED (deltas are accumulated into `final_text` but not streamed) so the whole answer is
        // evaluated by the rails BEFORE any of it reaches the user — a blocked answer is suppressed.
        let output_rails: Option<RailChain> = self
            .guardrails
            .as_ref()
            .map(|cfg| RailChain::for_output(cfg, self.system_prompt.as_deref()))
            .filter(|c| !c.is_empty());
        let buffer_output = output_rails.is_some();
        // Streaming-redaction carry: holds the trailing in-progress token across deltas so a
        // sensitive token split across chunk boundaries is redacted whole (see the TextDelta arm).
        let mut out_carry = String::new();
        // GAP-AUDIT turn-pipeline #6 — the same streaming-redaction carry as `out_carry`, but for
        // `Event::ReasoningDelta`/`WireEvent::ReasoningDelta` (§6.1) content, so a secret split
        // across reasoning-fragment boundaries is held back and redacted whole exactly like the
        // final-answer text stream, not skipped because it is "just thinking".
        let mut reasoning_carry = String::new();
        let mut seen_calls: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut approved_session: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        // PRMT-10: tools confirmed this session under the untrusted-influence confirmation gate
        // (ApproveForSession), so a repeatedly-called tool is not re-prompted every round.
        let mut prmt10_confirmed: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        let mut last_provider_id = String::new();
        let mut turn_cancelled = false;
        let mut providers_failed = false;
        // Loop verification (LOOP §7 / ADR §6, "never done until proven"): a turn is `Complete` ONLY
        // if the model reached a natural stop — it emitted a round with NO tool calls, i.e. it decided
        // it was done. If instead the loop is cut off by the iteration cap, or the stuck-detector fires
        // (the model only repeated tool calls it already made), the turn is `Capped` — a TRUTHFUL
        // completion, never reported as `Complete`. Enforced on the reachable path below.
        let mut completed_naturally = false;
        // Injection taint: seeded from the request (untrusted RAG/connector content already
        // flagged upstream), then set once a suspicious UNTRUSTED tool result is seen under
        // Enforce. Gates side-effecting tools for the rest of the turn (ADR-009).
        let mut tainted = req.untrusted_tainted && self.injection.is_some();
        // PRMT-10 provenance signal: has ANY untrusted content entered this turn? Seeded from the
        // request (untrusted RAG/connector content in the assembled input) and set once any tool
        // result — trusted-sourced or not, it is externally-sourced DATA — is folded back. Distinct
        // from `tainted` (which requires SUSPICION): untrusted content can be present without being
        // flagged, yet still steer a tool call, so a side-effecting tool whose ARGS carry injected
        // imperatives is confirmation-gated whenever untrusted content is in play.
        let mut untrusted_seen = req.untrusted_tainted && self.injection.is_some();
        // GAP-AUDIT guardrails-injection #2 — dual-LLM / privileged-quarantine broker (ADR-009,
        // `ainxt_injection::quarantine`, closed R12) for CONFIRMED-suspicious tool results. Scoped
        // per-turn (never shared across turns/requests) so quarantined symbols from one turn can
        // never resolve in another. See the call site below for why this is narrower than
        // quarantining every tool result.
        let mut quarantine = QuarantineBroker::new();

        // GAP-AUDIT turn-pipeline #7 — the previous stuck check (`!any_new` below) only fired when
        // a round introduced ZERO tool calls unseen in any prior round of THIS turn: a model that
        // pads each retry with a cosmetically-varying arg (a fresh nonce/timestamp) never repeats a
        // canonical key, so `any_new` stays true forever and the loop only ever exits via the
        // iteration cap. `ainxt_judge::StuckDetector` (already proven by the self-heal loop and the
        // LOOP teams tier-escalation path) catches that as `NoProgress` (near-identical candidates
        // across a window, Jaccard similarity — not just byte-identical) AND `Cycle` (the round's
        // call set re-equals a NON-adjacent earlier round, i.e. A→B→A thrash), neither of which the
        // exact-repeat check could see. Fed one "candidate" per round: the round's dispatched calls
        // as a canonical, order-independent string (sorted `name(args)` keys) — so two rounds are
        // "the same candidate" iff they dispatched the same tool calls, independent of call order.
        let mut stuck_detector = ainxt_judge::StuckDetector::new(3, 0.85);

        'agent: for _iter in 0..self.max_iters {
            if cancel.is_cancelled() {
                turn_cancelled = true;
                let _ = sink.send(Event::Error("turn cancelled".into())).await;
                break 'agent;
            }

            // --- provider invocation: retry the same provider on retryable errors, then fail
            //     over to the next eligible provider. Data-class exclusion is applied FIRST
            //     (non-overridable), so no path reaches an ineligible provider. Routes on the
            //     ESCALATED `route_class` (§4.2), which a prior round's tool call may have raised.
            //
            //     Tier routing (§4.1): a HARD PIN (`req.pinned_tier`) goes through the router's HARD
            //     tier filter (`select_chain_graded` with `require_tier`) — a pinned task can NEVER
            //     silently fall through to an off-tier model; if no eligible model exists for the
            //     pinned tier the turn fails CLOSED with a typed routing error. When NOT pinned, the
            //     in-engine complexity classifier DERIVES the tier and it is used only as the SOFT
            //     `select_chain` preference (graceful fallback preserved). Neither path weakens the
            //     non-overridable data-class / governance gate. ---
            let routed = match req.pinned_tier {
                Some(pinned) => {
                    // HARD tier filter — fail-closed. GAP-AUDIT tooling-mcp-plugins-routing —
                    // "Model-router ranking not fed a signal": this used to pass a permanently-EMPTY
                    // metrics map, so ranking among tier-survivors was pure alphabetical tie-break
                    // regardless of live quality. `live_quality_metrics()` feeds the SAME FI-07
                    // scoreboard already consulted for admission into the ranking step itself, so a
                    // higher-live-quality eligible route is genuinely preferred, not just admitted.
                    let metrics = self.router.live_quality_metrics();
                    self.router.select_chain_graded(
                        route_class,
                        req.forced_provider.as_deref(),
                        Some(pinned),
                        &metrics,
                        &router::RankWeights::default(),
                    )
                }
                None => {
                    // Unpinned: derive the tier via the complexity classifier, use it as the SOFT
                    // preference (the pre-existing graceful-fallback semantics).
                    let derived = self.complexity.classify(req);
                    self.router.select_chain(
                        route_class,
                        req.forced_provider.as_deref(),
                        Some(derived),
                    )
                }
            };
            let chain = match routed {
                Ok(c) => c,
                Err(e) => {
                    let (inp, out, cost) = self.sum_usage(&usage_by_provider);
                    self.emit_metrics(
                        req,
                        &principal.user_id,
                        "none",
                        inp,
                        out,
                        cost,
                        redactions,
                        tool_calls,
                        started.elapsed().as_millis() as u64,
                        TurnOutcomeKind::Rejected,
                    );
                    // Terminal events BEFORE returning, exactly as the cancellation
                    // pre-check above does. The `Err` goes to the caller, but a client
                    // is fed from `sink`/`wire` -- and it has already received
                    // `turn.started`. Without a terminal event the SSE stream stays
                    // open with no further bytes and the frontend waits forever.
                    //
                    // Observed: `POST /v1/chat` emitted `turn.started` and then nothing
                    // when the FI-03 outsourcing gate left no eligible route, hanging
                    // the caller indefinitely. `DOCKING.md` promises the opposite --
                    // "back-pressure, never a hang". `WireEvent::TurnFailed` was defined
                    // in the protocol and published in the SDK contract sample, but no
                    // code path had ever emitted it.
                    let _ = sink.send(Event::Error(format!("routing: {e:?}"))).await;
                    let _ = sink.send(Event::Done).await;
                    wire.emit(WireEvent::TurnFailed {
                        turn_id: req.turn.clone(),
                        error: ProtocolError::new(
                            ErrorCategory::ProviderUnavailable,
                            format!("no eligible route: {e:?}"),
                        ),
                    });
                    return Err(TurnError::Routing(e));
                }
            };

            let mut calls: Vec<(String, String, String)> = Vec::new(); // (id, name, args)
            let mut round_ok = false;
            let mut terminal_error: Option<(String, String)> = None; // (provider_id, msg)
            let mut last_error: Option<String> = None;
            let mut cancelled = false;

            'providers: for prov in &chain {
                'attempts: for attempt in 0..=self.max_provider_retries {
                    calls.clear();
                    let mut rx = prov.stream(&prompt);
                    let mut produced = false; // any output streamed to the caller this attempt
                    let mut attempt_error: Option<String> = None;
                    // Usage staged per attempt; committed (and forwarded) only if the attempt is
                    // accepted, so a failed attempt's tokens are never billed nor double-forwarded.
                    let mut att_in = 0u64;
                    let mut att_out = 0u64;

                    loop {
                        tokio::select! {
                            biased;
                            _ = cancel.cancelled() => { cancelled = true; break; }
                            maybe = rx.recv() => match maybe {
                                None => break, // provider round finished cleanly
                                Some(Event::Error(msg)) => { attempt_error = Some(msg); break; }
                                Some(Event::TextDelta(t)) => {
                                    produced = true;
                                    // 8. Compliance OUT — STREAMING-AWARE: append to a carry buffer
                                    // and only redact+emit up to the last token boundary, holding
                                    // back the trailing in-progress token. This closes the
                                    // split-secret hole: a PAN streamed digit-by-digit across
                                    // deltas is buffered whole and redacted before it can leave.
                                    out_carry.push_str(&t);
                                    let cut = safe_output_split(&out_carry, MAX_STREAM_CARRY_WINDOW);
                                    if cut > 0 {
                                        let emit_part: String = out_carry.drain(..cut).collect();
                                        let r = self.compliance.scan(&emit_part, Direction::Output);
                                        redactions += r.redactions;
                                        if r.redactions > 0 {
                                            wire.emit(WireEvent::ComplianceNotice {
                                                categories: vec!["output".to_string()],
                                                action: ComplianceAction::Redacted,
                                            });
                                        }
                                        final_text.push_str(&r.text);
                                        // When output rails are active the answer is buffered whole
                                        // and streamed only after it clears the rails (below).
                                        if !buffer_output {
                                            wire.emit(WireEvent::TextDelta {
                                                text: r.text.clone(),
                                            });
                                            let _ = sink.send(Event::TextDelta(r.text)).await;
                                        }
                                    }
                                }
                                // GAP-AUDIT turn-pipeline #6 — `reasoning.delta` was a defined wire
                                // event with zero emit sites (a stub): the engine never forwarded a
                                // provider's reasoning content. Mirrors the `TextDelta` arm's
                                // streaming-aware compliance carry (never buffered/gated by output
                                // rails — reasoning is not the judged final answer — but always
                                // scanned before it can reach the wire, I4).
                                Some(Event::ReasoningDelta(t)) => {
                                    produced = true;
                                    // GAP-AUDIT turn-pipeline #2 — withheld entirely (never even
                                    // buffered) for a caller the Policy Engine hasn't cleared for
                                    // `CAP_REASONING_VIEW`; the final answer below is unaffected.
                                    if reasoning_allowed {
                                        reasoning_carry.push_str(&t);
                                        let cut = safe_output_split(&reasoning_carry, MAX_STREAM_CARRY_WINDOW);
                                        if cut > 0 {
                                            let emit_part: String = reasoning_carry.drain(..cut).collect();
                                            let r = self.compliance.scan(&emit_part, Direction::Output);
                                            redactions += r.redactions;
                                            if r.redactions > 0 {
                                                wire.emit(WireEvent::ComplianceNotice {
                                                    categories: vec!["output".to_string()],
                                                    action: ComplianceAction::Redacted,
                                                });
                                            }
                                            wire.emit(WireEvent::ReasoningDelta { text: r.text.clone() });
                                            let _ = sink.send(Event::ReasoningDelta(r.text)).await;
                                        }
                                    }
                                }
                                Some(Event::ToolCallStart { id, name, args }) => {
                                    produced = true;
                                    // Redact the tool-call ARGS BEFORE they reach ANY transport — the
                                    // legacy `Event::ToolCallStart` and the §6.2 wire `tool.call.start`/
                                    // `tool.call.stop` events must never carry raw args (a PAN/secret the
                                    // model copied into a call) ahead of the 7a compliance seam. The
                                    // redaction COUNT is owned by the 7a seam below (scanned again on the
                                    // raw args) to avoid double-counting; here we only sanitize what is
                                    // emitted outward. The RAW args are retained in `calls` for dispatch,
                                    // idempotency, resource-authz, and injection scanning (which need the
                                    // true semantic values).
                                    let shown = self.compliance.scan(&args, Direction::ToolArgs);
                                    if shown.redactions > 0 {
                                        wire.emit(WireEvent::ComplianceNotice {
                                            categories: vec!["tool-args".to_string()],
                                            action: ComplianceAction::Redacted,
                                        });
                                    }
                                    let _ = sink
                                        .send(Event::ToolCallStart { id: id.clone(), name: name.clone(), args: shown.text.clone() })
                                        .await;
                                    // §6.2 tool-call lifecycle on the wire (always structured, never
                                    // model-text). Source is a display label only — dispatch is
                                    // source-agnostic (ADR-002); a model-emitted call is `Native`.
                                    wire.emit(WireEvent::ToolCallStart {
                                        call_id: id.clone(),
                                        name: name.clone(),
                                        source: ToolSource::Native,
                                    });
                                    wire.emit(WireEvent::ToolCallStop {
                                        call_id: id.clone(),
                                        args: shown.text.clone(),
                                    });
                                    calls.push((id, name, args));
                                }
                                Some(Event::Usage { input_tokens: it, output_tokens: ot }) => {
                                    // Stage this attempt's usage (do NOT forward/commit yet — only an
                                    // accepted attempt's tokens are real; a failed attempt is discarded).
                                    att_in = att_in.saturating_add(it);
                                    att_out = att_out.saturating_add(ot);
                                }
                                Some(Event::Done) => {}
                                // I4: EVERY other outbound provider event (ToolResult,
                                // ApprovalRequest, and any future text-bearing variant) is routed
                                // through compliance-OUT before it can reach the transport — never
                                // forwarded raw. `scan_outbound_event` is exhaustive, so a new
                                // text-bearing Event variant fails to compile until it is scanned
                                // here (fail-closed).
                                Some(other) => {
                                    let (scanned, n, cat) = self.scan_outbound_event(other);
                                    redactions += n;
                                    if let Some(c) = cat {
                                        wire.emit(WireEvent::ComplianceNotice {
                                            categories: vec![c.to_string()],
                                            action: ComplianceAction::Redacted,
                                        });
                                    }
                                    let _ = sink.send(scanned).await;
                                }
                            }
                        }
                    }

                    if cancelled {
                        // Attribute a partially-served cancelled turn to the provider that
                        // actually streamed output (audit fidelity) — not "none".
                        if produced {
                            last_provider_id = prov.id().to_string();
                        }
                        break 'providers;
                    }
                    // Commit an accepted attempt's staged usage to THIS provider's tally and forward
                    // the (single, combined) Usage event to the caller.
                    let mut commit_usage = || {
                        let e = usage_by_provider
                            .entry(prov.id().to_string())
                            .or_insert((0, 0));
                        e.0 = e.0.saturating_add(att_in);
                        e.1 = e.1.saturating_add(att_out);
                    };

                    match attempt_error {
                        None => {
                            commit_usage();
                            if att_in > 0 || att_out > 0 {
                                let _ = sink
                                    .send(Event::Usage {
                                        input_tokens: att_in,
                                        output_tokens: att_out,
                                    })
                                    .await;
                                // §6.4 usage accounting on the wire — `model` is the ACTUALLY-routed
                                // provider (never a placeholder), cost priced at that provider's rate.
                                wire.emit(WireEvent::Usage {
                                    model: prov.id().to_string(),
                                    input_tokens: att_in,
                                    output_tokens: att_out,
                                    cost: self.pricing.cost_micros(prov.id(), att_in, att_out)
                                        as f64
                                        / 1_000_000.0,
                                    cached: None,
                                });
                            }
                            last_provider_id = prov.id().to_string();
                            // GAP-FIX tooling-mcp-plugins-routing (round 2) — remember the provider
                            // that actually served this session's stable prefix as its warm-affinity
                            // hint (`PromptCache::set_affinity`); a future turn on this session can
                            // consult `affinity_hint`/`warm_preference_bonus` to prefer routing back to
                            // the SAME node/provider that (may) already hold this prefix warm.
                            if let Some(cache) = self.prompt_cache.as_ref() {
                                cache.lock().expect("prompt cache lock").set_affinity(
                                    &req.session,
                                    &prompt_cache_stable_prefix,
                                    prov.id(),
                                );
                            }
                            round_ok = true;
                            break 'providers; // success
                        }
                        Some(msg) => {
                            last_error = Some(msg.clone());
                            if produced {
                                // Partial output already streamed — cannot fail over/retry
                                // (can't un-emit). This provider DID produce, so its usage is real.
                                commit_usage();
                                if att_in > 0 || att_out > 0 {
                                    let _ = sink
                                        .send(Event::Usage {
                                            input_tokens: att_in,
                                            output_tokens: att_out,
                                        })
                                        .await;
                                    wire.emit(WireEvent::Usage {
                                        model: prov.id().to_string(),
                                        input_tokens: att_in,
                                        output_tokens: att_out,
                                        cost: self.pricing.cost_micros(prov.id(), att_in, att_out)
                                            as f64
                                            / 1_000_000.0,
                                        cached: None,
                                    });
                                }
                                terminal_error = Some((prov.id().to_string(), msg));
                                break 'providers;
                            }
                            match self.error_classifier.classify(&msg) {
                                ErrorClass::Retryable if attempt < self.max_provider_retries => {
                                    // Backoff is raced against cancel — a cancel during the
                                    // wait aborts the turn instead of re-invoking the provider.
                                    if self.backoff(attempt, cancel).await {
                                        cancelled = true;
                                        break 'providers;
                                    }
                                    continue 'attempts; // retry the SAME provider
                                }
                                _ => break 'attempts, // fail over to the next eligible provider
                            }
                        }
                    }
                }
            }

            if cancelled {
                turn_cancelled = true;
                let _ = sink.send(Event::Error("turn cancelled".into())).await;
                break 'agent;
            }
            if let Some((pid, msg)) = terminal_error {
                last_provider_id = pid;
                providers_failed = true;
                // Provider-supplied error TEXT can echo the prompt/args (a PAN/secret the model or
                // upstream copied into the error). Route it through compliance-OUT before it reaches
                // ANY transport — the same seam every other outbound event uses — so an error string
                // can never become an exfiltration channel. Redact-and-proceed: the (redacted) error
                // is still surfaced so the turn ends honestly.
                let (scanned, n, cat) = self.scan_outbound_event(Event::Error(msg));
                redactions += n;
                if let Some(c) = cat {
                    wire.emit(WireEvent::ComplianceNotice {
                        categories: vec![c.to_string()],
                        action: ComplianceAction::Redacted,
                    });
                }
                let _ = sink.send(scanned).await;
                break 'agent;
            }
            if !round_ok {
                providers_failed = true;
                let msg = last_error
                    .unwrap_or_else(|| "no eligible provider produced output".to_string());
                // Compliance-OUT on the composed error (the `{msg}` tail is provider-supplied text).
                let (scanned, n, cat) = self.scan_outbound_event(Event::Error(format!(
                    "all eligible providers failed: {msg}"
                )));
                redactions += n;
                if let Some(c) = cat {
                    wire.emit(WireEvent::ComplianceNotice {
                        categories: vec![c.to_string()],
                        action: ComplianceAction::Redacted,
                    });
                }
                let _ = sink.send(scanned).await;
                break 'agent;
            }

            if calls.is_empty() {
                // need-driven: no tool calls this round → the model reached a natural stop. This is
                // the ONLY path that PROVES completion (LOOP §7 / ADR §6); every other exit is capped.
                completed_naturally = true;
                break 'agent;
            }
            let Some(tools) = self.tools.as_ref() else {
                providers_failed = true;
                let _ = sink
                    .send(Event::Error(
                        "tool call requested but no tool runtime is configured".into(),
                    ))
                    .await;
                break 'agent;
            };

            let mut any_new = false;
            // GAP-AUDIT turn-pipeline #7 — this round's canonical call keys, fed to
            // `stuck_detector` as one candidate after dispatch (see the loop-exit check below).
            let mut round_keys: Vec<String> = Vec::new();
            // Concurrent-dispatch batch (gap: parallel tool dispatch). `pending` accumulates the
            // consecutive tool calls that cleared every pre-dispatch gate on the SAFE batchable path
            // (injection OFF, no approval/payment, single-phase); they are dispatched CONCURRENTLY at
            // the next flush point. `file_locks` maps an edited-file path to the shared async mutex
            // that serializes same-file edits within the batch. Any non-batchable / blocked call
            // flushes the batch FIRST, so the result stream + audit log stay in exact call order — and
            // when nothing is ever batched (every serial / injection-on / approval turn) the flushes
            // are no-ops and behavior is byte-identical to before.
            let mut pending: Vec<PreparedCall> = Vec::new();
            let mut file_locks: std::collections::HashMap<
                String,
                std::sync::Arc<tokio::sync::Mutex<()>>,
            > = std::collections::HashMap::new();
            for (id, name, mut args) in calls {
                // Record the tool as a capability this turn exercised (deduped) for `turn.rationale`.
                if !rationale_caps.iter().any(|c| c == &name) {
                    rationale_caps.push(name.clone());
                }
                if cancel.is_cancelled() {
                    turn_cancelled = true;
                    let _ = sink.send(Event::Error("turn cancelled".into())).await;
                    break 'agent;
                }
                let call_key = ainxt_tools::canonical_key(&name, &args);
                round_keys.push(call_key.clone());
                if seen_calls.insert(call_key) {
                    any_new = true;
                }
                // 7a. Compliance on tool arguments.
                let ca = self.compliance.scan(&args, Direction::ToolArgs);
                redactions += ca.redactions;

                // 7a0. Validate the tool-call args against the tool's declared schema (ADR-002).
                // Malformed / partial tool-call JSON is rejected cleanly — surfaced to the model to
                // retry — and never reaches the tool.
                if let Err(reason) = tools.validate(&name, &args) {
                    self.flush_dispatch_batch(
                        tools,
                        principal,
                        req,
                        &mut pending,
                        cancel,
                        &mut route_class,
                        &mut redactions,
                        &mut prompt,
                        &mut wire,
                        &sink,
                        &mut rationale_sources,
                    )
                    .await;
                    let _ = sink
                        .send(Event::ToolResult {
                            id,
                            output: format!("invalid arguments: {reason}"),
                        })
                        .await;
                    prompt.push_str(&format!("\n[tool {name} invalid arguments: {reason}]"));
                    continue;
                }

                // 7a1. On-behalf-of, fine-grained tool+resource authorization (ADR-003) — the
                // confused-deputy defense. MANDATORY: every tool call is authorized as THIS
                // principal against THIS tool + resource before dispatch; a denial is fail-closed
                // (the tool never runs; the model sees the denial and can adapt).
                //
                // The resource is extracted from the RAW args (not the redacted `ca.text`): a
                // resource id that looks like a PAN (a long digit run — e.g. a bank account) would
                // otherwise be collapsed to a single redaction token, making per-resource scoping
                // unenforceable. The raw value is used for the DECISION only; it is never echoed
                // outward (the Deny message omits it).
                let resource = tools.resource_of(&name, &args);
                if let Decision::Deny(reason) =
                    self.authz
                        .authorize_tool(principal, &name, resource.as_deref())
                {
                    self.flush_dispatch_batch(
                        tools,
                        principal,
                        req,
                        &mut pending,
                        cancel,
                        &mut route_class,
                        &mut redactions,
                        &mut prompt,
                        &mut wire,
                        &sink,
                        &mut rationale_sources,
                    )
                    .await;
                    let _ = sink
                        .send(Event::ToolResult {
                            id,
                            output: format!("unauthorized: {reason}"),
                        })
                        .await;
                    prompt.push_str(&format!("\n[tool {name} unauthorized: {reason}]"));
                    self.audit.record(AuditRecord {
                        session: req.session.clone(),
                        turn: req.turn.clone(),
                        actor: principal.user_id.clone(),
                        summary: format!("tool authz denied: '{name}' ({reason})"),
                    });
                    continue; // never dispatch a tool the principal isn't authorized for
                }

                // 7a2. Injection capability-gate (ADR-009): once the turn is tainted by suspicious
                // untrusted content, refuse SIDE-EFFECTING **or EGRESS** tools (fail-closed) — a
                // poisoned document/tool-result must neither drive a real-world action NOR
                // exfiltrate via a "read-only" tool that sends data off-box.
                //
                // GAP-AUDIT guardrails-injection #1 — this used to be the narrow
                // `is_side_effecting(name) == Some(true) || egress_of(name) == Some(true)` check,
                // which only gates a tool KNOWN to be dangerous: an UNCLASSIFIED tool (`None` for
                // both) evaluated the `||` to `false` and slipped through on a poisoned turn.
                // `ainxt_injection::gate_tool_on_taint_for_turn` is the fail-closed replacement named
                // for exactly this call site (per its own doc comment) — an unclassified tool is now
                // blocked, not silently admitted.
                if tainted {
                    if let Some(icfg) = self.injection.as_ref() {
                        if icfg.gate_side_effects_on_taint
                            && ainxt_injection::gate_tool_on_taint_for_turn(
                                tainted,
                                tools.is_side_effecting(&name),
                                tools.egress_of(&name),
                            )
                        {
                            let reason = "side-effecting/egress tool refused: turn tainted by \
                                          suspected prompt injection in untrusted content";
                            let _ = sink
                                .send(Event::ToolResult {
                                    id,
                                    output: format!("blocked: {reason}"),
                                })
                                .await;
                            prompt.push_str(&format!("\n[tool {name} blocked: {reason}]"));
                            self.audit.record(AuditRecord {
                                session: req.session.clone(),
                                turn: req.turn.clone(),
                                actor: principal.user_id.clone(),
                                summary: format!(
                                    "injection-gate blocked side-effecting tool '{name}'"
                                ),
                            });
                            continue; // do NOT dispatch
                        }
                    }
                }

                // 7a2b. PRMT-10 — untrusted-influence CONFIRMATION gate (indirect-injection defense,
                // PE6 §6.B). A side-effecting/egress tool whose ARGS are influenced by untrusted
                // content requires explicit confirmation before dispatch. "Influenced" = untrusted
                // content has entered this turn (`untrusted_seen`) AND the tool's own arguments carry
                // injected imperatives (the model copied untrusted instructions into the call — scanned
                // on the RAW args). This is distinct from, and complementary to, the hard taint-gate
                // above: it catches untrusted content that was NOT flagged strongly enough to hard-block
                // but still steered a real-world action. Fail-closed: no approval gate ⇒ refused.
                if self.injection.is_some()
                    && untrusted_seen
                    && !prmt10_confirmed.contains(&name)
                    && (tools.is_side_effecting(&name) == Some(true)
                        || tools.egress_of(&name) == Some(true))
                {
                    if let InjectionVerdict::Suspicious(reasons) =
                        self.injection_scanner.scan(&args, Provenance::ToolResult)
                    {
                        let _ = sink
                            .send(Event::ApprovalRequest {
                                id: id.clone(),
                                summary: format!(
                                    "confirm side-effecting tool '{name}': its arguments were \
                                     influenced by untrusted content ({})",
                                    reasons.join("; ")
                                ),
                            })
                            .await;
                        let decision = match self.approval.as_ref() {
                            Some(gate) => gate.decide(&ApprovalRequest {
                                session: req.session.clone(),
                                actor: principal.user_id.clone(),
                                tool: name.clone(),
                                args: ca.text.clone(),
                            }),
                            // Fail-closed: an untrusted-influenced side-effecting tool with no gate is refused.
                            None => ApprovalDecision::Reject(
                                "no approval gate configured to confirm an untrusted-influenced \
                                 side-effecting tool"
                                    .to_string(),
                            ),
                        };
                        match decision {
                            ApprovalDecision::Approve => {}
                            ApprovalDecision::ApproveForSession => {
                                prmt10_confirmed.insert(name.clone());
                            }
                            ApprovalDecision::Reject(reason) => {
                                let _ = sink
                                    .send(Event::ToolResult {
                                        id,
                                        output: format!("blocked: {reason}"),
                                    })
                                    .await;
                                prompt.push_str(&format!(
                                    "\n[tool {name} blocked (untrusted-influenced args, unconfirmed): {reason}]"
                                ));
                                self.audit.record(AuditRecord {
                                    session: req.session.clone(),
                                    turn: req.turn.clone(),
                                    actor: principal.user_id.clone(),
                                    summary: format!(
                                        "PRMT-10 blocked untrusted-influenced side-effecting tool '{name}': {reason}"
                                    ),
                                });
                                continue; // do NOT dispatch until a human/policy confirms
                            }
                        }
                        self.audit.record(AuditRecord {
                            session: req.session.clone(),
                            turn: req.turn.clone(),
                            actor: principal.user_id.clone(),
                            summary: format!(
                                "PRMT-10 confirmed untrusted-influenced side-effecting tool '{name}'"
                            ),
                        });
                    }
                }

                // 7a3. Egress DLP (exfiltration guard): a tool that leaves the box must not carry
                // sensitive content off-box, exfiltrate a secret, or ship data to a non-allowlisted
                // destination. Two layers, both fail-closed:
                if tools.egress_of(&name) == Some(true) {
                    // 7a3-i. PCI/PII exfil (the always-on compliance gate's domain): if the compliance
                    // scan of the args found ANY sensitive content, refuse — a PAN/PII must never be
                    // exfiltrated through an egressing tool, even on a non-tainted turn.
                    if ca.redactions > 0 {
                        let reason =
                            "egress DLP: outbound payload to an egress tool contains sensitive \
                             content; refused to prevent exfiltration";
                        self.flush_dispatch_batch(
                            tools,
                            principal,
                            req,
                            &mut pending,
                            cancel,
                            &mut route_class,
                            &mut redactions,
                            &mut prompt,
                            &mut wire,
                            &sink,
                            &mut rationale_sources,
                        )
                        .await;
                        let _ = sink
                            .send(Event::ToolResult {
                                id,
                                output: format!("blocked: {reason}"),
                            })
                            .await;
                        prompt.push_str(&format!("\n[tool {name} blocked: {reason}]"));
                        self.audit.record(AuditRecord {
                            session: req.session.clone(),
                            turn: req.turn.clone(),
                            actor: principal.user_id.clone(),
                            summary: format!("egress-DLP blocked '{name}'"),
                        });
                        continue; // do NOT dispatch
                    }

                    // 7a3-ii. Provider-secret taxonomy + destination allow-list (ADR-009, gap
                    // GUARD-04/05) — the exfiltration surface the PCI gate does NOT own: private
                    // keys / JWTs / provider API keys, and outbound traffic to a domain not on the
                    // allow-list. Taint-aware: a tainted turn treats ANY finding as fail-closed.
                    // Scans the RAW args (the true outbound payload); under audit policy a secret is
                    // redacted and the sanitized copy is what gets dispatched off-box.
                    let policy = self.egress_policy.clone().unwrap_or_default();
                    match guard_egress_for_turn(&args, &policy, tainted) {
                        EgressDecision::Allow => {}
                        EgressDecision::Redact {
                            sanitized,
                            findings,
                        } => {
                            self.audit.record(AuditRecord {
                                session: req.session.clone(),
                                turn: req.turn.clone(),
                                actor: principal.user_id.clone(),
                                summary: format!(
                                    "egress-DLP redacted outbound payload for '{name}' ({} finding(s))",
                                    findings.len()
                                ),
                            });
                            // Forward the sanitized payload off-box (audit-mode secret redaction).
                            args = sanitized;
                        }
                        EgressDecision::Block { reason, findings } => {
                            self.flush_dispatch_batch(
                                tools,
                                principal,
                                req,
                                &mut pending,
                                cancel,
                                &mut route_class,
                                &mut redactions,
                                &mut prompt,
                                &mut wire,
                                &sink,
                                &mut rationale_sources,
                            )
                            .await;
                            let _ = sink
                                .send(Event::ToolResult {
                                    id,
                                    output: format!("blocked: {reason}"),
                                })
                                .await;
                            prompt.push_str(&format!("\n[tool {name} blocked: {reason}]"));
                            self.audit.record(AuditRecord {
                                session: req.session.clone(),
                                turn: req.turn.clone(),
                                actor: principal.user_id.clone(),
                                summary: format!(
                                    "egress-DLP blocked '{name}' ({} finding(s)): {reason}",
                                    findings.len()
                                ),
                            });
                            continue; // fail-closed — do NOT dispatch
                        }
                    }
                }

                // 7b. Approval Gate — fail-closed, tri-state. Triggered for HIGH-risk tools AND for
                // ANY action that crosses a payment boundary (§9, ADR-016). A payment-boundary action
                // is ALWAYS gated (a prior session pre-approval does NOT clear it) and can be cleared
                // ONLY by an explicit human `approve` — never `approve_for_session`, never a policy
                // auto-decision. That invariant is enforced by mirroring `ApprovalRespond::is_valid`,
                // the exact protocol contract, so the runtime and the wire share one rule.
                let boundary = (self.payment_boundary)(&name, &args);
                let is_payment = boundary != PaymentBoundary::None;
                let tier = tools.risk_tier(&name);
                let high_risk = tier == Some(RiskTier::High);
                // The apex `HighRisk` tier (§1.4) is BOTH approval-gated AND two-phase: it can only
                // fire via dry_run → commit. It requires_approval() just like `High`, so it must clear
                // the gate here too (the legacy call-site keyed only on `High`, silently letting a
                // `HighRisk` tool skip the gate before hitting the non-dispatchable refusal at 7c).
                let two_phase = tier.map(RiskTier::requires_two_phase).unwrap_or(false);
                if is_payment || ((high_risk || two_phase) && !approved_session.contains(&name)) {
                    // A gated (approval / payment) call is on the SERIAL path — flush any queued
                    // concurrent batch FIRST so its results stream ahead of this call's approval
                    // request, preserving exact call order.
                    self.flush_dispatch_batch(
                        tools,
                        principal,
                        req,
                        &mut pending,
                        cancel,
                        &mut route_class,
                        &mut redactions,
                        &mut prompt,
                        &mut wire,
                        &sink,
                        &mut rationale_sources,
                    )
                    .await;
                    // §6.3 approval.request on the wire, carrying the payment_boundary so a renderer
                    // knows a human `approve` is mandatory. `scope`/`preview` are non-sensitive: the
                    // preview is the COMPLIANCE-REDACTED args, never the raw payload.
                    wire.emit(WireEvent::ApprovalRequest {
                        approval_id: id.clone(),
                        action: name.clone(),
                        scope: format!("tool={name}"),
                        risk_tier: format!("{:?}", tools.risk_tier(&name).unwrap_or(RiskTier::Low)),
                        preview: Some(ca.text.clone()),
                        payment_boundary: boundary,
                    });
                    let _ = sink
                        .send(Event::ApprovalRequest {
                            id: id.clone(),
                            summary: format!(
                                "approve {}tool '{name}' with args: {}",
                                if is_payment {
                                    "payment-boundary "
                                } else {
                                    "high-risk "
                                },
                                ca.text
                            ),
                        })
                        .await;
                    let (decision, is_policy_auto) = match self.approval.as_ref() {
                        Some(gate) => (
                            gate.decide(&ApprovalRequest {
                                session: req.session.clone(),
                                actor: principal.user_id.clone(),
                                tool: name.clone(),
                                args: ca.text.clone(),
                            }),
                            gate.is_policy_auto(),
                        ),
                        // Fail-closed: a gated tool with no approval gate is refused. Treated as a
                        // policy auto-decision so a payment can never slip through a missing gate.
                        None => (
                            ApprovalDecision::Reject(if is_payment {
                                "no approval gate configured for a payment-boundary tool"
                                    .to_string()
                            } else {
                                "no approval gate configured for a high-risk tool".to_string()
                            }),
                            true,
                        ),
                    };

                    // Mirror the protocol payment-boundary invariant (§9, ADR-016): map the runtime
                    // decision onto `ApprovalRespond` and validate it against the action's boundary.
                    // A `payment_boundary != none` action can be cleared ONLY by a human `approve`;
                    // `approve_for_session` and any policy auto-decision are refused here (fail-closed),
                    // so no auto-approval path can ever move value.
                    let (proto_decision, feedback) = match &decision {
                        ApprovalDecision::Approve => (WireApprovalDecision::Approve, None),
                        ApprovalDecision::ApproveForSession => {
                            (WireApprovalDecision::ApproveForSession, None)
                        }
                        ApprovalDecision::Reject(r) => {
                            (WireApprovalDecision::Reject, Some(r.clone()))
                        }
                    };
                    let respond = ApprovalRespond {
                        approval_id: id.clone(),
                        decision: proto_decision,
                        feedback,
                    };
                    if let Err(e) = respond.is_valid(boundary, is_policy_auto) {
                        // The decision is not a valid clearance for this boundary — e.g. an
                        // approve-for-session or a policy auto-approve on a payment action. Refuse
                        // (never auto-approve a payment), feed the reason back, and audit.
                        let reason = e.message.clone();
                        let _ = sink
                            .send(Event::ToolResult {
                                id,
                                output: format!("denied: {reason}"),
                            })
                            .await;
                        prompt.push_str(&format!(
                            "\n[tool {name} denied by approval gate: {reason}]"
                        ));
                        self.audit.record(AuditRecord {
                            session: req.session.clone(),
                            turn: req.turn.clone(),
                            actor: principal.user_id.clone(),
                            summary: format!(
                                "payment-boundary approval refused for '{name}' (boundary {boundary:?}): {reason}"
                            ),
                        });
                        continue; // do NOT dispatch — a payment requires an explicit human approve
                    }

                    match decision {
                        ApprovalDecision::Approve => {}
                        ApprovalDecision::ApproveForSession => {
                            // Unreachable for a payment boundary (is_valid refused it above); a
                            // session pre-approval only ever caches a non-payment high-risk tool.
                            approved_session.insert(name.clone());
                        }
                        ApprovalDecision::Reject(reason) => {
                            let _ = sink
                                .send(Event::ToolResult {
                                    id,
                                    output: format!("denied: {reason}"),
                                })
                                .await;
                            prompt.push_str(&format!(
                                "\n[tool {name} denied by approval gate: {reason}]"
                            ));
                            continue; // do NOT dispatch — the model sees the denial and can adapt
                        }
                    }
                }

                // 7c. Dispatch (exactly-once for side-effecting tools via the ledger). Uses the
                // RAW args: the (trusted, in-proc) tool needs the real values to act, and the
                // idempotency key must be derived from the true semantic args — redacting here
                // would corrupt execution and collapse distinct PAN-like resources to one key
                // (silent dedup). Outbound redaction happens on the RESULT (7d) and text deltas.
                //
                // Concurrent-dispatch fast path (gap: parallel tool dispatch, §1 step 7): a call that
                // cleared every gate on the SAFE batchable path (injection defense OFF ⇒ no in-round
                // result→gate taint dependency; no approval / payment gate; single-phase) is QUEUED
                // and dispatched CONCURRENTLY at the next flush, with same-file edits serialized on a
                // shared async mutex and one cancel token shared across the in-flight futures.
                // Everything else (approval/payment/two-phase, or injection ON) stays on the
                // byte-identical serial path below.
                if self.injection.is_none() && !is_payment && !high_risk && !two_phase {
                    tool_calls += 1;
                    let file_lock = Self::edit_file_target(tools, &name, &args).map(|path| {
                        file_locks
                            .entry(path)
                            .or_insert_with(|| std::sync::Arc::new(tokio::sync::Mutex::new(())))
                            .clone()
                    });
                    pending.push(PreparedCall {
                        id,
                        name,
                        args,
                        two_phase: false,
                        file_lock,
                    });
                    continue; // dispatch + post-dispatch seams run at flush, in queue order
                }
                // Non-batchable: flush any queued batch FIRST so its results precede this call, then
                // dispatch serially (the unchanged path below).
                self.flush_dispatch_batch(
                    tools,
                    principal,
                    req,
                    &mut pending,
                    cancel,
                    &mut route_class,
                    &mut redactions,
                    &mut prompt,
                    &mut wire,
                    &sink,
                    &mut rationale_sources,
                )
                .await;
                tool_calls += 1;
                // A `HighRisk` (`two_phase`) capability is structurally NON-dispatchable in one shot
                // (`ToolRuntime::dispatch` refuses it, §1.4). Now that the Approval Gate has cleared
                // it, fire the two-phase contract on the live agent path: PROPOSE (`dry_run` computes
                // the preview + idempotency key, NO side effect) then ACT (`commit` executes under
                // that exact key). dry_run and commit are issued back-to-back with the SAME logical
                // `now`, so the preview is always inside its freshness window; the mechanism still
                // enforces single-use (a preview authorizes exactly one commit) and key-match (the
                // committed args must hash to the previewed key). Everything below `HighRisk` takes
                // the normal single-phase dispatch.
                let flat = |dr: DispatchResult| -> String {
                    match dr {
                        DispatchResult::Ok(r) | DispatchResult::Deduped(r) => r,
                        DispatchResult::Failed(e) => format!("tool '{name}' failed: {e}"),
                        DispatchResult::NeedsReconciliation => {
                            format!("tool '{name}' is in-doubt; manual reconciliation required")
                        }
                        DispatchResult::Blocked(b) => format!("tool '{name}' blocked: {b}"),
                    }
                };
                // Dispatch ON BEHALF OF the acting principal (§1.2): the exactly-once ledger key is
                // f(user_id, capability, resource_key, semantic-args), so two DIFFERENT users
                // issuing the identical side-effecting call get two DISTINCT ledger rows (their
                // effects are independent and must never cross-dedup), while one user's retry still
                // collapses to one row. Passing `principal.user_id` here is what makes that real on
                // the live served path — a bare `dispatch` would fold every user onto a shared key.
                let uid = principal.user_id.as_str();
                let result = if two_phase {
                    let now_tick = Self::now_secs();
                    match tools.dry_run_for(uid, &name, &args, now_tick, TWO_PHASE_TTL_SECS) {
                        Ok(dr) => {
                            flat(tools.commit_for(uid, &name, &args, &dr.commit_key, now_tick))
                        }
                        Err(refused) => flat(refused),
                    }
                } else if let Some(obo) = &self.obo {
                    // R14: route the single-phase dispatch through the audited THREE-LAYER OBO gate.
                    // The acting principal's held capabilities are BOTH its declared grants (on any
                    // resource/action) and its issued scope; its clearance is the resource-ABAC ceiling.
                    // The decision (granted or denied) is written to the audit sink BEFORE any effect,
                    // and a denial hard-blocks with the ambient credential never substituted.
                    let grants: Vec<ainxt_tools::obo::Grant> = principal
                        .caps
                        .iter()
                        .map(|c| ainxt_tools::obo::Grant::new(c, "*", "*"))
                        .collect();
                    let ctx = ainxt_tools::obo::OboContext::new(
                        principal.user_id.clone(),
                        grants,
                        principal.caps.iter().cloned(),
                        principal.clearance,
                    );
                    flat(tools.dispatch_obo_audited(
                        &ctx,
                        obo.policy.as_ref(),
                        obo.sink.as_ref(),
                        &name,
                        &args,
                        "invoke",
                    ))
                } else {
                    flat(tools.dispatch_for(uid, &name, &args))
                };
                // 7c-bis. §4.2 tri-signal classification of THIS tool call feeding the router. Fuse
                // the tool's declared class (signal 1), a compliance scan of its args (signal 2), and
                // its destination/egress floor (signal 3); if the effective class is MORE sensitive
                // than the turn's current `route_class`, raise it so every SUBSEQUENT model round
                // routes at the true class (a call that pulls regulated data into context forces later
                // rounds onto in-house models, ADR-012). Classification only — never a turn denial.
                if let Some(eff) = tools.classify_data_class(&name, &args, &*self.arg_scanner) {
                    if eff.class > route_class {
                        self.audit.record(AuditRecord {
                            session: req.session.clone(),
                            turn: req.turn.clone(),
                            actor: principal.user_id.clone(),
                            summary: format!(
                                "data-class escalated {} -> {} (§4.2 tri-signal) by tool '{name}'; \
                                 subsequent rounds route at the tighter class",
                                route_class.as_str(),
                                eff.class.as_str()
                            ),
                        });
                        route_class = eff.class;
                    }
                }
                // 7d. Compliance on the tool result before it re-enters context or streams out.
                let cr = self.compliance.scan(&result, Direction::ToolResult);
                redactions += cr.redactions;
                if cr.redactions > 0 {
                    wire.emit(WireEvent::ComplianceNotice {
                        categories: vec!["tool-result".to_string()],
                        action: ComplianceAction::Redacted,
                    });
                }
                let _ = sink
                    .send(Event::ToolResult {
                        id: id.clone(),
                        output: cr.text.clone(),
                    })
                    .await;
                // GAP-FIX rationale-sources — mirrors the batched-path fix in
                // `flush_dispatch_batch`: this serial dispatch is the OTHER place a tool result is
                // produced (gated/two-phase/approval-cleared calls never enter the batch), so it
                // needs the identical provenance record or `turn.rationale.sources` would silently
                // miss every gated tool call while still catching the unremarkable ones.
                rationale_sources.push(format!("tool:{name}#{id}"));
                // GAP2 harness-sdk — an `artifact.*` capability's result also gets the typed
                // Event::Artifact, IN ADDITION TO the ToolResult above.
                if let Some(artifact_event) = artifact_event_for(&name, &id, &cr.text) {
                    let _ = sink.send(artifact_event).await;
                }
                // §6.2 tool.result on the wire — the observation fed back to the model, carried as a
                // structured text block (already compliance-redacted). A successful dispatch is not an
                // error; soft failures are surfaced to the model on the legacy stream as before.
                wire.emit(WireEvent::ToolResult {
                    call_id: id,
                    blocks: vec![ResultBlock::Text {
                        text: cr.text.clone(),
                    }],
                    is_error: false,
                });

                // 7e. Injection defense (ADR-009) on the UNTRUSTED tool result: scan for injected
                // instructions and, under Enforce, taint the turn; then feed the observation back
                // FENCED (instruction/data separation) so the model treats it as data, not commands.
                //
                // GAP-FIX guardrails-injection "connector-provenance lost" — the provenance tag this
                // SPECIFIC result carries is looked up per dispatched tool (`ToolRuntime::provenance_of`)
                // instead of being hardcoded `Provenance::ToolResult` for every dispatch regardless of
                // origin. A connector capability (`ConnectorCapability::tool_provenance` ==
                // `Provenance::Connector`) now reaches the quarantine/audit trail under the SAME tag
                // its own `ConnectorInvoker::invoke_in` outcome already carries; every other capability
                // (native/MCP/plugin) is unaffected — `provenance_of` defaults to `ToolResult`.
                let result_provenance =
                    tools.provenance_of(&name).unwrap_or(Provenance::ToolResult);
                let observation = if let Some(icfg) = self.injection.as_ref() {
                    let mut confirmed_suspicious = false;
                    if let InjectionVerdict::Suspicious(reasons) =
                        self.injection_scanner.scan(&cr.text, result_provenance)
                    {
                        self.audit.record(AuditRecord {
                            session: req.session.clone(),
                            turn: req.turn.clone(),
                            actor: principal.user_id.clone(),
                            summary: format!(
                                "injection suspected in tool '{name}' result ({}): {}",
                                icfg.mode_label(),
                                reasons.join("; ")
                            ),
                        });
                        if icfg.mode == InjectionMode::Enforce {
                            tainted = true;
                            confirmed_suspicious = true;
                        }
                    }
                    // A tool result is externally-sourced DATA — untrusted content is now in play for
                    // the rest of the turn (PRMT-10 provenance), even if it was not flagged suspicious.
                    untrusted_seen = true;
                    if confirmed_suspicious {
                        // GAP-AUDIT guardrails-injection #2 — a CONFIRMED-suspicious result under
                        // Enforce is exactly the case plain fencing (`wrap_untrusted`) does not fully
                        // cover: the raw bytes are known to likely carry an injected instruction, and
                        // a "treat as data" fence is a hint the privileged model can still be coaxed
                        // into ignoring. Route it through the dual-LLM/privileged-quarantine broker
                        // instead — the privileged prompt gets only an opaque symbol + provenance tag,
                        // never the raw bytes, so the buried instruction structurally cannot reach the
                        // tool-wielding model. Benign (non-flagged) tool results keep the existing
                        // fenced-but-legible behavior so ordinary tool use is unaffected.
                        let symbol = quarantine.quarantine(&cr.text, result_provenance);
                        quarantine
                            .privileged_reference(&symbol)
                            .unwrap_or_else(|| wrap_untrusted(&cr.text, result_provenance))
                    } else {
                        wrap_untrusted(&cr.text, result_provenance)
                    }
                } else {
                    cr.text.clone()
                };
                // Feed the observation back for the next round.
                prompt.push_str(&format!("\n[tool {name} result: {observation}]"));
            }
            // Flush the tail concurrent batch: any queued clean calls that ran off the end of the
            // round are dispatched concurrently now and their results fed back in queue order.
            self.flush_dispatch_batch(
                tools,
                principal,
                req,
                &mut pending,
                cancel,
                &mut route_class,
                &mut redactions,
                &mut prompt,
                &mut wire,
                &sink,
                &mut rationale_sources,
            )
            .await;
            if !any_new {
                break 'agent; // stuck: the model only repeated tool calls it already made
            }
            // GAP-AUDIT turn-pipeline #7 — the richer Cycle/NoProgress check `any_new` cannot see
            // (near-duplicate-but-technically-new calls; A/B oscillation). `round_keys` is sorted so
            // the candidate is order-independent (the SAME set of calls in a different order is
            // still "the same round" for stuck purposes).
            if !round_keys.is_empty() {
                round_keys.sort();
                if let Some(diagnosis) = stuck_detector.observe(&round_keys.join("\n")) {
                    self.audit.record(AuditRecord {
                        session: req.session.clone(),
                        turn: req.turn.clone(),
                        actor: principal.user_id.clone(),
                        summary: format!(
                            "turn stopped: tool-call loop diagnosed stuck ({:?}): {}",
                            diagnosis.kind, diagnosis.reason
                        ),
                    });
                    break 'agent;
                }
            }
        }

        // Flush any held-back trailing text through compliance before closing the stream, so no
        // tail escapes un-redacted. With the bounded secret-relevant hold-back, an entire
        // separator-joined answer (e.g. a spaced PAN, or prose with no hard punctuation) can be
        // buffered here rather than in the TextDelta arm, so this flush must mirror that arm's wire
        // emissions — the `compliance.notice{Redacted}` and the wire `text.delta` — or a redaction
        // that only lands on the flush would go un-announced on the §6 wire.
        if !out_carry.is_empty() {
            let r = self.compliance.scan(&out_carry, Direction::Output);
            redactions += r.redactions;
            if r.redactions > 0 {
                wire.emit(WireEvent::ComplianceNotice {
                    categories: vec!["output".to_string()],
                    action: ComplianceAction::Redacted,
                });
            }
            final_text.push_str(&r.text);
            if !buffer_output {
                wire.emit(WireEvent::TextDelta {
                    text: r.text.clone(),
                });
                let _ = sink.send(Event::TextDelta(r.text)).await;
            }
            out_carry.clear();
        }
        // GAP-AUDIT turn-pipeline #6 — flush any held-back trailing reasoning fragment, mirroring
        // `out_carry` above so a reasoning secret split across the last chunk boundary is still
        // redacted-and-emitted rather than silently dropped when the stream ends.
        if !reasoning_carry.is_empty() {
            let r = self.compliance.scan(&reasoning_carry, Direction::Output);
            redactions += r.redactions;
            if r.redactions > 0 {
                wire.emit(WireEvent::ComplianceNotice {
                    categories: vec!["output".to_string()],
                    action: ComplianceAction::Redacted,
                });
            }
            wire.emit(WireEvent::ReasoningDelta {
                text: r.text.clone(),
            });
            let _ = sink.send(Event::ReasoningDelta(r.text)).await;
            reasoning_carry.clear();
        }

        // 9. Guardrails OUT (ADR-008, gap GUARD-06/07) — run the OUTPUT rail chain (groundedness +
        //    toxicity + topic + system-prompt-leak) on the COMPLETE model answer BEFORE it streams.
        //    Only on a normally-completed turn (a cancelled/failed turn has no full answer to judge).
        //    Blocked => suppress the answer entirely; Flagged (Audit) => record and stream; Allowed
        //    => stream the buffered answer now. Skipped when no output rails are configured.
        if let Some(rails) = output_rails.as_ref() {
            if !turn_cancelled && !providers_failed {
                match rails.evaluate(&final_text, &output_grounding_context) {
                    GuardrailOutcome::Allowed => {
                        if !final_text.is_empty() {
                            // §6 wire: the buffered answer was NEVER emitted as `text.delta` during
                            // streaming (buffer_output suppressed the per-chunk wire emit at the
                            // TextDelta arm). Emit it now so a wire consumer receives the assistant
                            // text on the buffered-release path, mirroring the legacy sink send.
                            wire.emit(WireEvent::TextDelta {
                                text: final_text.clone(),
                            });
                            let _ = sink.send(Event::TextDelta(final_text.clone())).await;
                        }
                    }
                    GuardrailOutcome::Flagged(flags) => {
                        self.audit.record(AuditRecord {
                            session: req.session.clone(),
                            turn: req.turn.clone(),
                            actor: principal.user_id.clone(),
                            summary: format!(
                                "output guardrails flagged (audit, proceeding): {}",
                                flags.join("; ")
                            ),
                        });
                        if !final_text.is_empty() {
                            // §6 wire: same buffered-release emission as the Allowed arm — the
                            // flagged-but-proceeding answer must reach the wire consumer too.
                            wire.emit(WireEvent::TextDelta {
                                text: final_text.clone(),
                            });
                            let _ = sink.send(Event::TextDelta(final_text.clone())).await;
                        }
                    }
                    GuardrailOutcome::Blocked(reason) => {
                        let _ = sink
                            .send(Event::Error(format!(
                                "blocked by output guardrails: {reason}"
                            )))
                            .await;
                        let _ = sink.send(Event::Done).await;
                        self.audit.record(AuditRecord {
                            session: req.session.clone(),
                            turn: req.turn.clone(),
                            actor: principal.user_id.clone(),
                            summary: format!("output guardrails blocked turn (enforce): {reason}"),
                        });
                        let (input_tokens, output_tokens, cost_micros) =
                            self.sum_usage(&usage_by_provider);
                        let provider_id = if last_provider_id.is_empty() {
                            "none".to_string()
                        } else {
                            last_provider_id.clone()
                        };
                        self.emit_metrics(
                            req,
                            &principal.user_id,
                            &provider_id,
                            input_tokens,
                            output_tokens,
                            cost_micros,
                            redactions,
                            tool_calls,
                            started.elapsed().as_millis() as u64,
                            TurnOutcomeKind::GuardrailsBlocked,
                        );
                        return Ok(TurnSummary {
                            final_text: String::new(),
                            redactions,
                            provider: "guardrails-blocked-output".to_string(),
                            ..Default::default()
                        });
                    }
                }
            } else if buffer_output && !final_text.is_empty() {
                // Cancelled/failed turn: the buffered partial answer was withheld; flush it so a
                // cancel/failover path streams what it produced (rails are skipped — no full answer).
                // §6 wire: mirror the legacy flush so the wire consumer also receives the partial.
                wire.emit(WireEvent::TextDelta {
                    text: final_text.clone(),
                });
                let _ = sink.send(Event::TextDelta(final_text.clone())).await;
            }
        }

        // One terminal Done for the whole turn (per-round Done events are consumed by the loop).
        let _ = sink.send(Event::Done).await;

        // 10. Audit (always — mandatory sink). Attribution: the serving provider if one
        // produced output; "cancelled" for a turn cancelled before any provider produced;
        // "none" only when the failover chain was exhausted with no output.
        let provider_id = if !last_provider_id.is_empty() {
            last_provider_id
        } else if turn_cancelled {
            "cancelled".to_string()
        } else {
            "none".to_string()
        };
        self.audit.record(AuditRecord {
            session: req.session.clone(),
            turn: req.turn.clone(),
            actor: principal.user_id.clone(),
            summary: format!("chat turn served by '{provider_id}' ({redactions} redactions)"),
        });

        // 11. Telemetry (gap J/V) — one metrics record per turn, cost attributed to the actor.
        let outcome = if turn_cancelled {
            TurnOutcomeKind::Cancelled
        } else if providers_failed {
            TurnOutcomeKind::ProvidersFailed
        } else {
            TurnOutcomeKind::Completed
        };
        let (input_tokens, output_tokens, cost_micros) = self.sum_usage(&usage_by_provider);
        self.emit_metrics(
            req,
            &principal.user_id,
            &provider_id,
            input_tokens,
            output_tokens,
            cost_micros,
            redactions,
            tool_calls,
            started.elapsed().as_millis() as u64,
            outcome,
        );

        // §6.5 terminal turn event on the wire sink — this is where loop verification is ENFORCED on
        // the reachable path (LOOP §7 / ADR §6, "never done until proven"). A normally-ended turn is
        // reported `TurnOutcome::Complete` ONLY when the model reached a natural stop (it emitted a
        // round with no tool calls, i.e. it decided it was done → `completed_naturally`). A turn that
        // was cut off by the iteration cap OR by the stuck-detector (it only repeated tool calls it had
        // already made) is reported `TurnOutcome::Capped` — a TRUTHFUL completion, never `Complete`.
        // A cancelled/failed turn carries its own terminal event (`turn.stopped`/`turn.failed`).
        if turn_cancelled {
            wire.emit(WireEvent::TurnStopped {
                turn_id: req.turn.clone(),
            });
        } else if providers_failed {
            wire.emit(WireEvent::TurnFailed {
                turn_id: req.turn.clone(),
                error: ProtocolError::new(
                    ErrorCategory::ProviderUnavailable,
                    "all eligible providers failed",
                ),
            });
        } else {
            // §6 `turn.rationale` — the audit-grade "why this" panel, generated from THIS turn's own
            // trace (never model text): the actually-routed model, its tier, the capabilities the
            // turn exercised, and the grounding sources it read. Previously defined in the protocol
            // but never emitted by the turn engine (gap: "§6 wire events defined but never emitted").
            // Emitted only on a normally-ended turn (a cancelled/failed turn carries its own
            // terminal event) and only to the wire sink (a no-op when none is attached).
            let model_tier = match req.tier {
                ainxt_types::Tier::Simple => "simple",
                ainxt_types::Tier::Medium => "medium",
                ainxt_types::Tier::Complex => "complex",
            }
            .to_string();
            wire.emit(WireEvent::TurnRationale {
                turn_id: req.turn.clone(),
                model_tier,
                model: provider_id.clone(),
                capabilities: rationale_caps.clone(),
                sources: rationale_sources.clone(),
            });
            wire.emit(WireEvent::TurnCompleted {
                turn_id: req.turn.clone(),
                outcome: if completed_naturally {
                    WireTurnOutcome::Complete
                } else {
                    WireTurnOutcome::Capped
                },
            });
        }

        Ok(TurnSummary {
            final_text,
            redactions,
            provider: provider_id,
            ..Default::default()
        })
    }

    /// Convenience: run a turn and COLLECT all streamed events. Drains concurrently with the
    /// run so the bounded sink never deadlocks.
    pub async fn run_turn_collect(
        &self,
        principal: &Principal,
        req: &Request,
    ) -> Result<TurnOutcome, TurnError> {
        let (tx, mut rx) = mpsc::channel::<Event>(64);
        let run = self.run_turn(principal, req, tx);
        let collect = async move {
            let mut v = Vec::new();
            while let Some(e) = rx.recv().await {
                v.push(e);
            }
            v
        };
        let (res, events) = tokio::join!(run, collect);
        let summary = res?;
        Ok(TurnOutcome {
            events,
            final_text: summary.final_text,
            redactions: summary.redactions,
            provider: summary.provider,
        })
    }
}

// Re-exports for ergonomic construction.
// ============================ Turn-handler seam ============================

/// The per-turn seam the Session Manager drives. The bare [`Engine`] implements it (a raw model
/// turn); a richer handler — the Chat surface (intent cascade, referent resolution, grounded
/// retrieval, prompt assembly) — implements it to run the FULL pipeline while still streaming into
/// the same event `sink`. This is what lets ONE concurrency spine (`ainxt-session`) serve ANY
/// surface: the spine owns concurrency/backpressure/cancel/timeout; the handler owns intelligence.
///
/// Object-safe by manual future-boxing (no async-fn-in-trait), so it can be held as
/// `Arc<dyn TurnHandler>` and swapped by configuration.
pub trait TurnHandler: Send + Sync {
    fn handle_turn<'a>(
        &'a self,
        principal: &'a Principal,
        req: &'a Request,
        sink: tokio::sync::mpsc::Sender<Event>,
        cancel: &'a CancelToken,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<TurnSummary, TurnError>> + Send + 'a>,
    >;
}

impl TurnHandler for Engine {
    fn handle_turn<'a>(
        &'a self,
        principal: &'a Principal,
        req: &'a Request,
        sink: tokio::sync::mpsc::Sender<Event>,
        cancel: &'a CancelToken,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<TurnSummary, TurnError>> + Send + 'a>,
    > {
        Box::pin(self.run_turn_cancellable(principal, req, sink, cancel))
    }
}

pub use audit::InMemoryAudit;
pub use authz::RbacAuthorizer;
pub use budget::{
    BudgetSnapshot as BudgetSnapshotView, BudgetStore as BudgetStoreTrait,
    NoBudgetLimit as NoBudgetLimitStore,
};
pub use cancel::CancelToken;
pub use complexity::{ComplexityClassifier, HeuristicComplexityClassifier, TierFromRequest};
pub use compliance::RedactAndProceed;
pub use dispatch::DispatchProbe;
pub use error::{ErrorClass, ErrorClassifier, HeuristicErrorClassifier};
pub use memory::{MemoryReader, SharedMemoryStore};
pub use provider::Provider;

/// Convenience: an engine wired with the default OSS gate implementations.
pub fn engine_with_defaults(router: ModelRouter) -> Engine {
    Engine::new(
        Box::new(RedactAndProceed),
        Box::new(RbacAuthorizer),
        Box::new(InMemoryAudit::default()),
        router,
    )
}
