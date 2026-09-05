// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! The **Role** rung — a *digital worker* (WORKFORCE_AND_OS §1/§2, AINXT_OS §4).
//!
//! A Role is not one skill; it is a governed *composition* that maps to a whole job function:
//! a [`Charter`] (the job description as structured spec) + agent(s) + skills + [`ConnectorRef`]s +
//! [`KnowledgeScope`]s + [`Governance`] + [`Kpi`]s + a per-task [`AutonomyModel`]. It is authored as a
//! declarative [`RoleSpec`], then validated into a [`ValidatedRole`] (the only thing the Breaker will
//! run and the only thing that can be published). A [`PublishedRole`] can *only* be minted by the
//! Breaker publish gate (`crate::breaker::publish`) — its constructor is crate-private and never
//! called anywhere else — so outside this crate there is no path to a published role that skipped the
//! adversarial gate.

use ainxt_types::DataClass;
use serde::{Deserialize, Serialize};

use crate::autonomy::AutonomyModel;
use crate::ladder::{AgentRung, Capability, SkillRef};

/// Where a role sits relative to the money movement perimeter (ADR-016). Drives the strictest
/// oversight + attention-check controls (§7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PaymentBoundary {
    /// No contact with payment flows.
    None,
    /// Reads/derives from payment data but does not move money.
    Adjacent,
    /// Can initiate/authorize money movement.
    Direct,
}

impl PaymentBoundary {
    /// High-stakes = anything touching the payment perimeter (drives §7 decoys + attention checks).
    pub fn is_high_stakes(&self) -> bool {
        !matches!(self, PaymentBoundary::None)
    }
}

/// Model-risk classification (gap P / RBI SR-11-7). A `High` risk role may not run fully autonomous.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ModelRiskClass {
    Low,
    Medium,
    High,
}

/// Data-residency intent (gap N / RBI+DPDP). Regulated/PII must stay in-house.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Residency {
    InHouse,
    Cloud,
}

/// RBAC visibility of the role definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Visibility {
    Public,
    Private,
}

/// The job description as a structured spec (§2 element 1). This is what the Studio's own agent
/// produces from the plain-language description in Step 1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Charter {
    pub title: String,
    pub responsibilities: Vec<String>,
    pub inputs: Vec<String>,
    pub outputs: Vec<String>,
    /// When the role must hand off to a human. Non-empty is required — a worker with no defined
    /// escalation path is not shippable.
    pub escalation_rules: Vec<String>,
}

/// A connector the role may use (§2 element 2/5). `data_class` is the sensitivity of the data the
/// connector exposes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorRef {
    pub name: String,
    pub data_class: DataClass,
}

impl ConnectorRef {
    pub fn new(name: &str, data_class: DataClass) -> Self {
        ConnectorRef {
            name: name.to_string(),
            data_class,
        }
    }
}

/// A knowledge / RAG namespace attached to the role (§2 element 5). `retrieval_quality` is filled by
/// the Studio Step-5 retrieval-quality check (`None` until the check runs).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KnowledgeScope {
    pub namespace: String,
    pub data_class: DataClass,
    #[serde(default)]
    pub retrieval_quality: Option<f64>,
}

impl KnowledgeScope {
    pub fn new(namespace: &str, data_class: DataClass) -> Self {
        KnowledgeScope {
            namespace: namespace.to_string(),
            data_class,
            retrieval_quality: None,
        }
    }
}

/// The governance block (§2 element 6): the accountable human owner + the RBAC / OBO / model-risk /
/// residency / retention posture baked into every role by construction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Governance {
    /// The named accountable human (the CODEOWNERS owner; §5 — a digital worker cannot be legally
    /// accountable, a human must own its decisions).
    pub owner: String,
    /// The CODEOWNERS group on the manifest path (authoring RBAC).
    pub codeowners_group: String,
    pub rbac_visibility: Visibility,
    /// On-behalf-of authority (gap AI): the role acts *as* the user, not with its own broad creds.
    pub obo_authority: bool,
    pub model_risk_class: ModelRiskClass,
    pub residency: Residency,
    /// Data-lifecycle retention in days (gap Q / DPDP). `0` = undefined (invalid).
    pub retention_days: u32,
}

/// A role-specific KPI / eval target (§2 element 7).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Kpi {
    pub name: String,
    /// Target value (interpretation is metric-specific; presence is what the Breaker requires).
    pub target: f64,
}

impl Kpi {
    pub fn new(name: &str, target: f64) -> Self {
        Kpi {
            name: name.to_string(),
            target,
        }
    }
}

/// The declarative Role specification — the authored, not-yet-validated composition.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RoleSpec {
    pub id: String,
    pub charter: Charter,
    pub agents: Vec<AgentRung>,
    pub skills: Vec<SkillRef>,
    pub connectors: Vec<ConnectorRef>,
    pub knowledge: Vec<KnowledgeScope>,
    pub governance: Governance,
    pub kpis: Vec<Kpi>,
    pub autonomy: AutonomyModel,
    pub payment_boundary: PaymentBoundary,
}

impl RoleSpec {
    /// The most sensitive data class the whole role touches — over connectors, knowledge, every
    /// agent capability, AND every per-task data-class attestation. Drives the residency invariant
    /// and the autonomy cross-checks. Folding in the per-task attestation means a task that admits it
    /// touches regulated data cannot leave the role's derived class understated.
    pub fn max_data_class(&self) -> DataClass {
        let mut m = DataClass::Public;
        for c in &self.connectors {
            m = m.max(c.data_class);
        }
        for k in &self.knowledge {
            m = m.max(k.data_class);
        }
        for a in &self.agents {
            m = m.max(a.max_capability_class());
        }
        m = m.max(self.autonomy.max_task_data_class());
        m
    }

    /// Every capability across the role's agents (for over-privilege probing).
    pub fn all_capabilities(&self) -> Vec<&Capability> {
        self.agents
            .iter()
            .flat_map(|a| a.capabilities.iter())
            .collect()
    }

    /// Validate the composition into a [`ValidatedRole`]. Returns *all* violations on failure so the
    /// Studio can surface them at once. These invariants encode §5's responsible reality and the gap
    /// governance (N/P/Q/AI) structurally — you cannot assemble a role that bypasses them.
    pub fn validate(self) -> Result<ValidatedRole, Vec<String>> {
        let mut errs = Vec::new();

        if self.id.trim().is_empty() {
            errs.push("role id is empty".into());
        }
        if self.charter.title.trim().is_empty() {
            errs.push("charter title is empty".into());
        }
        if self.charter.responsibilities.is_empty() {
            errs.push("charter has no responsibilities".into());
        }
        if self.charter.escalation_rules.is_empty() {
            errs.push(
                "charter has no escalation rules (a worker must know when to hand off)".into(),
            );
        }
        if self.agents.is_empty() {
            errs.push("role has no agent(s) (nothing executes the job)".into());
        }
        if self.governance.owner.trim().is_empty() {
            errs.push("governance owner is empty (§5: a named human must be accountable)".into());
        }
        if self.governance.codeowners_group.trim().is_empty() {
            errs.push("governance codeowners_group is empty".into());
        }
        if self.governance.retention_days == 0 {
            errs.push("governance retention_days is 0 (gap Q: data lifecycle undefined)".into());
        }

        // Each agent must be a valid governed unit.
        for a in &self.agents {
            errs.extend(a.validate());
        }
        // The autonomy dial must be coherent (and no regulated task on Auto).
        errs.extend(self.autonomy.validate());

        // Gap N (residency): if the role touches regulated/PII data it MUST be served in-house.
        let max = self.max_data_class();
        if max.is_regulated() && self.governance.residency != Residency::InHouse {
            errs.push(format!(
                "role touches {} data but residency is Cloud (gap N: regulated/PII must stay in-house)",
                max.as_str()
            ));
        }

        // Regulated-data oversight invariant (gap AI + §5), DERIVED not self-declared. The
        // `payment_boundary` field is an author-supplied label and can be mis-declared as `None`; the
        // oversight requirement must instead key off the *actual* most-sensitive data class the role
        // touches (`max_data_class`, computed over connectors + knowledge + agent capabilities). If
        // the role handles regulated/PII data it MUST carry on-behalf-of authority, MUST NOT default
        // to fully-autonomous, and MUST retain a human-escalation path — fail-closed, so a role
        // cannot be dialed fully-autonomous with no OBO / no oversight by simply understating its
        // payment boundary.
        if max.is_regulated() {
            if !self.governance.obo_authority {
                errs.push(format!(
                    "role handles {} data and MUST carry on-behalf-of authority (gap AI; derived from data class, not the self-declared payment_boundary)",
                    max.as_str()
                ));
            }
            if self.autonomy.default == crate::autonomy::AutonomyLevel::Auto {
                errs.push(format!(
                    "role handles {} data and cannot default to Auto autonomy (§5 human-oversight; derived from data class, not the self-declared payment_boundary)",
                    max.as_str()
                ));
            }
            if !self.autonomy.has_escalation_path() {
                errs.push(format!(
                    "role handles {} data and must retain a human-escalation path (fail-closed oversight)",
                    max.as_str()
                ));
            }
            // DERIVED per-task cross-check (§5 + gap AI). The top-level rule above only gates the
            // `autonomy.default`; a *per-task* Auto override was previously gated ONLY by the task's
            // self-declared `regulated` bool (in `AutonomyModel::validate`). That let an author dial a
            // regulated-data task to Auto by leaving the bool false. Here — keyed off the role's
            // DERIVED data class (`max`), not the self-declared flag — any per-task Auto on a task
            // that TOUCHES regulated data (effective signal: flag OR attested regulated `data_class`)
            // is rejected fail-closed, exactly like the top-level default rule. Benign non-regulated
            // tasks (e.g. credential-reset) stay dialable to Auto by design (WORKFORCE §5: automate
            // task-by-task even inside a regulated-touching role).
            for t in &self.autonomy.per_task {
                if t.level == crate::autonomy::AutonomyLevel::Auto && t.touches_regulated() {
                    errs.push(format!(
                        "role handles {} data; per-task '{}' touches regulated data and cannot be dialed to Auto (§5 human-oversight; derived from data class, not only the self-declared regulated flag)",
                        max.as_str(),
                        t.task
                    ));
                }
            }
        }

        // Gap P (model risk): a High-risk role cannot default to fully-autonomous.
        if self.governance.model_risk_class == ModelRiskClass::High
            && self.autonomy.default == crate::autonomy::AutonomyLevel::Auto
        {
            errs.push(
                "High model-risk role cannot default to Auto autonomy (§5: high-judgment roles stay supervised)"
                    .into(),
            );
        }

        // Gap AI (OBO) + payment perimeter: a role at the payment boundary must act on-behalf-of a
        // user (never with its own broad creds) and must not default to fully-autonomous.
        if self.payment_boundary.is_high_stakes() {
            if !self.governance.obo_authority {
                errs.push(
                    "payment-boundary role must carry on-behalf-of authority (gap AI: no confused deputy)"
                        .into(),
                );
            }
            if self.autonomy.default == crate::autonomy::AutonomyLevel::Auto {
                errs.push(
                    "payment-boundary role cannot default to Auto autonomy (§5 human oversight)"
                        .into(),
                );
            }
        }

        if errs.is_empty() {
            Ok(ValidatedRole { spec: self })
        } else {
            Err(errs)
        }
    }
}

/// A role whose composition passed [`RoleSpec::validate`]. The Breaker runs on this, and only this
/// can be published. Construct exclusively via `RoleSpec::validate`.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidatedRole {
    spec: RoleSpec,
}

impl ValidatedRole {
    pub fn spec(&self) -> &RoleSpec {
        &self.spec
    }
    pub fn id(&self) -> &str {
        &self.spec.id
    }
    pub fn payment_boundary(&self) -> PaymentBoundary {
        self.spec.payment_boundary
    }
}

/// A **published** digital worker: a validated role that cleared the Breaker gate and is at
/// [`GovernanceState::Production`](ainxt_governance::GovernanceState). The only constructor is
/// crate-private and is called from exactly one place — `crate::breaker::publish` — so a role with a
/// failing (or absent) Breaker report can never become a `PublishedRole`. This is the type-level
/// enforcement of AINXT_OS §4 Step 7's "cannot skip".
#[derive(Debug, Clone, PartialEq)]
pub struct PublishedRole {
    role: ValidatedRole,
    state: ainxt_governance::GovernanceState,
}

impl PublishedRole {
    /// Crate-private mint point. Do NOT add any other caller — the Breaker gate is the sole path.
    pub(crate) fn mint(role: ValidatedRole) -> Self {
        PublishedRole {
            role,
            state: ainxt_governance::GovernanceState::Production,
        }
    }
    pub fn role(&self) -> &ValidatedRole {
        &self.role
    }
    pub fn id(&self) -> &str {
        self.role.id()
    }
    pub fn state(&self) -> ainxt_governance::GovernanceState {
        self.state
    }
    /// Retire the published role (git-native deprecate transition, ADR-026) — **§6.5 forced review
    /// enforced at the deprecate point**. [`crate::lifecycle::can_deprecate`] is the policy (an
    /// actively-used role needs a Breaker dry-run AND manager sign-off, not owner say-so); before this
    /// it existed as pure logic nobody called from the one place that actually retires a role, so a
    /// live, high-volume role could be deprecated on ordinary CODEOWNERS approval alone. Now the git
    /// lifecycle transition does not even run until `can_deprecate` clears.
    pub fn deprecate(
        &mut self,
        req: crate::lifecycle::DeprecationRequest,
        floor: u64,
    ) -> Result<(), DeprecateError> {
        crate::lifecycle::can_deprecate(req, floor)
            .map_err(DeprecateError::ForcedReviewRequired)?;
        self.state = ainxt_governance::advance(self.state, ainxt_governance::GitEvent::Deprecate)
            .map_err(DeprecateError::Governance)?;
        Ok(())
    }
}

/// Why a [`PublishedRole::deprecate`] was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeprecateError {
    /// §6.5: the role is actively used and needs a Breaker dry-run and/or manager sign-off first.
    ForcedReviewRequired(Vec<crate::lifecycle::DeprecationBlock>),
    /// The git-native lifecycle transition itself was refused.
    Governance(ainxt_governance::TransitionError),
}

impl std::fmt::Display for DeprecateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeprecateError::ForcedReviewRequired(blocks) => {
                write!(
                    f,
                    "§6.5 forced review required before deprecation: {blocks:?}"
                )
            }
            DeprecateError::Governance(e) => write!(f, "governance transition refused: {e}"),
        }
    }
}
impl std::error::Error for DeprecateError {}
