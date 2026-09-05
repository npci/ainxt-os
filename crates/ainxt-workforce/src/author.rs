// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! **Conversational authoring intelligence** — the Factory's own agent that turns a plain-language
//! job description into a governed [`RoleSpec`] (AINXT_OS §0 "creation-by-conversation", §4 Steps
//! 1/2/6).
//!
//! The design's moat is *intelligence, not configuration*: the creator **describes** a job
//! ("*Triage L1 tickets, answer from the KB, resolve password resets, escalate everything else*") and
//! the Factory (a) turns that into a **structured [`Charter`]** (Step 1 — intent detection applied to
//! role-building), (b) **auto-assembles** the draft — capabilities, skills, model policy, connectors,
//! knowledge, per-task autonomy — from a pre-vetted template (Step 2, review-don't-build), and (c)
//! **auto-generates a quality-eval [`Kpi`] set** for the role (Step 6, "this is how you'll know it's
//! good").
//!
//! The genuinely intelligent Step-1 parse of *free-form* prose is a model call, so it lives behind the
//! [`IntentExtractor`] seam (an LLM-backed extractor is a downstream, infra-gated implementation). The
//! crate ships a fully deterministic default, [`KeywordIntentExtractor`], so the whole authoring flow
//! is exhaustively testable offline with no model, clock, or RNG. Step 2 and Step 6 are template
//! golden paths — pure, deterministic data — because a template is exactly the pre-vetted assembly the
//! design uses to kill the blank-page problem (gap AZ).

use ainxt_types::DataClass;

use crate::autonomy::{AutonomyLevel, AutonomyModel, TaskAutonomy};
use crate::ladder::{AgentRung, Capability, ModelPolicy, SkillRef};
use crate::role::{
    Charter, ConnectorRef, Governance, KnowledgeScope, Kpi, ModelRiskClass, PaymentBoundary,
    Residency, RoleSpec, Visibility,
};
use crate::studio::Template;

/// A creator's plain-language request to build a digital worker (AINXT_OS §4 Step 0–1 input).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobDescription {
    /// The role id the published worker will carry.
    pub id: String,
    /// The human-facing title (e.g. "L1 Support Engineer").
    pub title: String,
    /// The free-form job description the creator typed.
    pub text: String,
    /// The golden-path template chosen at Step 0.
    pub template: Template,
}

impl JobDescription {
    pub fn new(id: &str, title: &str, text: &str, template: Template) -> Self {
        JobDescription {
            id: id.to_string(),
            title: title.to_string(),
            text: text.to_string(),
            template,
        }
    }
}

/// **Step-1 seam.** Turns free-form prose into a structured [`Charter`]. The genuinely intelligent
/// implementation is an LLM call (data-plane, infra-gated); the crate's default is deterministic.
pub trait IntentExtractor {
    fn extract_charter(&self, job: &JobDescription) -> Charter;
}

/// The deterministic default extractor: no model, no RNG. It clause-splits the description and
/// classifies each clause by domain cue words (escalation / input / output), so the same prose always
/// yields the same charter. A downstream LLM-backed [`IntentExtractor`] replaces it without touching
/// any other step.
#[derive(Debug, Clone, Copy, Default)]
pub struct KeywordIntentExtractor;

impl KeywordIntentExtractor {
    fn clauses(text: &str) -> Vec<String> {
        // Split on sentence/clause separators and the common enumerating conjunctions.
        text.split(['.', ',', ';', '\n'])
            .flat_map(|s| s.split(" and "))
            .flat_map(|s| s.split(" then "))
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect()
    }
}

impl IntentExtractor for KeywordIntentExtractor {
    fn extract_charter(&self, job: &JobDescription) -> Charter {
        let mut responsibilities = Vec::new();
        let mut inputs = Vec::new();
        let mut outputs = Vec::new();
        let mut escalation_rules = Vec::new();

        for clause in Self::clauses(&job.text) {
            let lc = clause.to_lowercase();
            let is_escalation = lc.contains("escalate")
                || lc.contains("hand off")
                || lc.contains("handoff")
                || lc.contains("everything else")
                || lc.contains("otherwise")
                || lc.contains("unrecognized")
                || lc.contains("unrecognised");
            if is_escalation {
                escalation_rules.push(clause.clone());
                // An escalation clause is still a responsibility (the worker must recognize the case).
                responsibilities.push(clause);
                continue;
            }
            if lc.contains("from ")
                || lc.contains("read ")
                || lc.contains("ingest")
                || lc.contains("receive")
                || lc.contains("input")
            {
                inputs.push(clause.clone());
            }
            if lc.contains("resolve")
                || lc.contains("answer")
                || lc.contains("produce")
                || lc.contains("generate")
                || lc.contains("draft")
                || lc.contains("output")
                || lc.contains("reply")
            {
                outputs.push(clause.clone());
            }
            responsibilities.push(clause);
        }

        // A worker with no explicitly stated escalation path still gets a safe default — the design's
        // "anything unrecognized escalates to a human" (§4 Step 4). The Breaker still requires it, so a
        // silent empty here would be caught, but the Factory should never hand back an unshippable
        // charter from a well-formed description.
        if escalation_rules.is_empty() {
            escalation_rules.push("escalate anything unrecognized to a human".to_string());
        }
        if responsibilities.is_empty() {
            responsibilities.push(job.title.clone());
        }

        Charter {
            title: job.title.clone(),
            responsibilities,
            inputs,
            outputs,
            escalation_rules,
        }
    }
}

/// Factory configuration — the deployment-level defaults the auto-assembler stamps onto a draft
/// (data-lifecycle retention, the in-house-first provider list). Declarative; overridable per deploy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactoryConfig {
    pub default_retention_days: u32,
    pub default_providers: Vec<String>,
    pub in_house_providers: Vec<String>,
}

impl Default for FactoryConfig {
    fn default() -> Self {
        FactoryConfig {
            default_retention_days: 365,
            default_providers: vec!["in-house".into(), "openai".into()],
            in_house_providers: vec!["in-house".into()],
        }
    }
}

/// The pre-vetted golden-path assembly a template expands into (Step 2). Pure data.
#[derive(Debug, Clone, PartialEq)]
pub struct TemplateBlueprint {
    pub persona: String,
    pub capabilities: Vec<Capability>,
    pub skills: Vec<SkillRef>,
    pub connectors: Vec<ConnectorRef>,
    pub knowledge_namespaces: Vec<(String, DataClass)>,
    pub autonomy: AutonomyModel,
    pub payment_boundary: PaymentBoundary,
    pub model_risk_class: ModelRiskClass,
    pub kpis: Vec<Kpi>,
}

/// The conversational Role Factory. Deterministic given its [`IntentExtractor`] and [`FactoryConfig`].
pub struct Factory<E: IntentExtractor = KeywordIntentExtractor> {
    extractor: E,
    config: FactoryConfig,
}

impl Default for Factory<KeywordIntentExtractor> {
    fn default() -> Self {
        Factory {
            extractor: KeywordIntentExtractor,
            config: FactoryConfig::default(),
        }
    }
}

impl<E: IntentExtractor> Factory<E> {
    pub fn new(extractor: E, config: FactoryConfig) -> Self {
        Factory { extractor, config }
    }

    pub fn config(&self) -> &FactoryConfig {
        &self.config
    }

    /// **Step 1** — plain-language description → structured [`Charter`] (via the intent seam).
    pub fn describe(&self, job: &JobDescription) -> Charter {
        self.extractor.extract_charter(job)
    }

    /// **Step 2** — auto-assemble a draft [`RoleSpec`] from the template golden path + the charter +
    /// the governance block set at Step 3. The autonomy dial, capabilities, skills, model policy,
    /// connectors and knowledge are all proposed here for the creator to *review*, not build.
    /// KPIs are left to Step 6 ([`Factory::auto_generate_kpis`]).
    pub fn auto_assemble(
        &self,
        job: &JobDescription,
        charter: Charter,
        governance: Governance,
    ) -> RoleSpec {
        let bp = self.blueprint(job.template);
        let max_class = bp
            .capabilities
            .iter()
            .map(|c| c.data_class_ceiling)
            .chain(bp.connectors.iter().map(|c| c.data_class))
            .chain(bp.knowledge_namespaces.iter().map(|(_, dc)| *dc))
            .max()
            .unwrap_or(DataClass::Public);
        // In-house-first when the assembly touches regulated/PII data (gap N); else the default list.
        let providers: Vec<&str> = if max_class.is_regulated() {
            self.config
                .in_house_providers
                .iter()
                .map(|s| s.as_str())
                .collect()
        } else {
            self.config
                .default_providers
                .iter()
                .map(|s| s.as_str())
                .collect()
        };
        let model_policy = ModelPolicy::new(&providers, max_class);

        let mut agent = AgentRung::new(&format!("{}-primary", job.id), &bp.persona, model_policy);
        for s in &bp.skills {
            agent = agent.with_skill(s.clone());
        }
        for c in &bp.capabilities {
            agent = agent.with_capability(c.clone());
        }

        let knowledge = bp
            .knowledge_namespaces
            .iter()
            .map(|(ns, dc)| KnowledgeScope::new(ns, *dc))
            .collect();

        RoleSpec {
            id: job.id.clone(),
            charter,
            agents: vec![agent],
            skills: bp.skills.clone(),
            connectors: bp.connectors.clone(),
            knowledge,
            governance,
            kpis: Vec::new(),
            autonomy: bp.autonomy.clone(),
            payment_boundary: bp.payment_boundary,
        }
    }

    /// **Step 6** — auto-generate the role's quality-eval [`Kpi`] set from the template. This is how
    /// the role's output quality becomes *measurable* (BF/BT) before the Breaker gate.
    pub fn auto_generate_kpis(&self, template: Template) -> Vec<Kpi> {
        self.blueprint(template).kpis
    }

    /// The template golden paths (Step 0 → the Step-2 draft). Deterministic, pre-vetted data.
    pub fn blueprint(&self, template: Template) -> TemplateBlueprint {
        match template {
            Template::Support => TemplateBlueprint {
                persona: "an L1 support engineer who triages tickets and answers from the KB"
                    .into(),
                capabilities: vec![
                    Capability::new("connector.ticketing", DataClass::Internal),
                    Capability::new("kb.search", DataClass::Internal),
                    Capability::new("connector.email", DataClass::Internal),
                ],
                skills: vec![
                    SkillRef::behavioral("triage-sop"),
                    SkillRef::behavioral("response-templates"),
                ],
                connectors: vec![
                    ConnectorRef::new("connector.ticketing", DataClass::Internal),
                    ConnectorRef::new("connector.email", DataClass::Internal),
                ],
                knowledge_namespaces: vec![("kb:support".into(), DataClass::Internal)],
                autonomy: AutonomyModel::new(AutonomyLevel::Assisted, 0.7)
                    .with_task(TaskAutonomy::new("password-reset", AutonomyLevel::Auto))
                    .with_task(TaskAutonomy::new("access-request", AutonomyLevel::Assisted))
                    .with_task(TaskAutonomy::new("unknown", AutonomyLevel::Escalate)),
                payment_boundary: PaymentBoundary::None,
                model_risk_class: ModelRiskClass::Low,
                kpis: vec![
                    Kpi::new("resolution-rate", 0.85),
                    Kpi::new("escalation-appropriateness", 0.9),
                    Kpi::new("csat", 0.8),
                ],
            },
            Template::Developer => TemplateBlueprint {
                persona: "a software developer who implements features and reviews merge requests"
                    .into(),
                capabilities: vec![
                    Capability::new("connector.gitlab", DataClass::Internal),
                    Capability::new("code.read", DataClass::Internal),
                    Capability::new("ci.trigger", DataClass::Internal),
                ],
                skills: vec![
                    SkillRef::behavioral("code-review-sop"),
                    SkillRef::execution("run-tests"),
                ],
                connectors: vec![
                    ConnectorRef::new("connector.gitlab", DataClass::Internal),
                    ConnectorRef::new("connector.ci", DataClass::Internal),
                ],
                knowledge_namespaces: vec![("kb:engineering".into(), DataClass::Internal)],
                autonomy: AutonomyModel::new(AutonomyLevel::Assisted, 0.7)
                    .with_task(TaskAutonomy::new("open-mr", AutonomyLevel::Assisted))
                    .with_task(TaskAutonomy::new("unknown", AutonomyLevel::Escalate)),
                payment_boundary: PaymentBoundary::None,
                model_risk_class: ModelRiskClass::Low,
                kpis: vec![
                    Kpi::new("mr-acceptance-rate", 0.8),
                    Kpi::new("ci-pass-rate", 0.95),
                ],
            },
            Template::Tester => TemplateBlueprint {
                persona: "an adversarial tester (the Breaker) who stress-tests other roles".into(),
                capabilities: vec![
                    Capability::new("sandbox.run", DataClass::Internal),
                    Capability::new("kb.search", DataClass::Internal),
                ],
                skills: vec![SkillRef::behavioral("adversarial-sop")],
                connectors: vec![],
                knowledge_namespaces: vec![("kb:eval".into(), DataClass::Internal)],
                autonomy: AutonomyModel::new(AutonomyLevel::Assisted, 0.7)
                    .with_task(TaskAutonomy::new("unknown", AutonomyLevel::Escalate)),
                payment_boundary: PaymentBoundary::None,
                model_risk_class: ModelRiskClass::Low,
                kpis: vec![Kpi::new("defect-detection-rate", 0.9)],
            },
            Template::Ops => TemplateBlueprint {
                persona: "an SRE who runs runbooks and remediates incidents".into(),
                capabilities: vec![
                    Capability::new("monitoring.read", DataClass::Internal),
                    Capability::new("service.restart", DataClass::Internal).requiring_approval(),
                ],
                skills: vec![SkillRef::behavioral("runbook-sop")],
                connectors: vec![ConnectorRef::new(
                    "connector.monitoring",
                    DataClass::Internal,
                )],
                knowledge_namespaces: vec![("kb:runbooks".into(), DataClass::Internal)],
                autonomy: AutonomyModel::new(AutonomyLevel::Assisted, 0.6)
                    .with_task(TaskAutonomy::new(
                        "restart-service",
                        AutonomyLevel::Assisted,
                    ))
                    .with_task(TaskAutonomy::new("unknown", AutonomyLevel::Escalate)),
                payment_boundary: PaymentBoundary::Adjacent,
                model_risk_class: ModelRiskClass::Medium,
                kpis: vec![
                    Kpi::new("mttr-minutes", 30.0),
                    Kpi::new("false-remediation-rate", 0.02),
                ],
            },
            Template::Analyst => TemplateBlueprint {
                persona:
                    "a risk analyst who produces heavily-overseen, model-risk-governed reports"
                        .into(),
                capabilities: vec![
                    Capability::new("data.read", DataClass::Confidential),
                    Capability::new("report.generate", DataClass::Confidential),
                ],
                skills: vec![SkillRef::behavioral("analysis-sop")],
                connectors: vec![ConnectorRef::new(
                    "connector.warehouse",
                    DataClass::Confidential,
                )],
                knowledge_namespaces: vec![("kb:analytics".into(), DataClass::Confidential)],
                autonomy: AutonomyModel::new(AutonomyLevel::Assisted, 0.5)
                    .with_task(TaskAutonomy::new("publish-report", AutonomyLevel::Assisted))
                    .with_task(TaskAutonomy::new("unknown", AutonomyLevel::Escalate)),
                payment_boundary: PaymentBoundary::None,
                model_risk_class: ModelRiskClass::High,
                kpis: vec![
                    Kpi::new("report-accuracy", 0.95),
                    Kpi::new("citation-faithfulness", 0.98),
                ],
            },
            Template::Blank => TemplateBlueprint {
                persona:
                    "a general-purpose worker (blank template — the creator fills the specifics)"
                        .into(),
                capabilities: vec![Capability::new("kb.search", DataClass::Internal)],
                skills: vec![SkillRef::behavioral("general-sop")],
                connectors: vec![],
                knowledge_namespaces: vec![],
                autonomy: AutonomyModel::new(AutonomyLevel::Assisted, 0.7)
                    .with_task(TaskAutonomy::new("unknown", AutonomyLevel::Escalate)),
                payment_boundary: PaymentBoundary::None,
                model_risk_class: ModelRiskClass::Low,
                kpis: vec![Kpi::new("task-success-rate", 0.8)],
            },
        }
    }

    /// A default governance block the Studio pre-fills at Step 2 for the creator to review/tighten at
    /// Step 3. In-house residency + bounded retention are stamped by construction (gaps N/Q).
    pub fn default_governance(&self, owner: &str, codeowners_group: &str) -> Governance {
        Governance {
            owner: owner.to_string(),
            codeowners_group: codeowners_group.to_string(),
            rbac_visibility: Visibility::Private,
            obo_authority: true,
            model_risk_class: ModelRiskClass::Low,
            residency: Residency::InHouse,
            retention_days: self.config.default_retention_days,
        }
    }
}
