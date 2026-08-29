// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! The lower rungs of the creation ladder (WORKFORCE_AND_OS §1): **Skill** and **Agent**.
//!
//! A [`SkillRef`] is a reference to one reusable capability — *behavioral* (an SOP / domain
//! instruction block) or *execution* (a sandboxed `run()`); the executable body lives in the Skill
//! Runtime, this crate only composes references. An [`AgentRung`] is the next rung up: a governed
//! composition of a persona + skills + least-privilege [`Capability`] grants + a [`ModelPolicy`].
//! "Governed ladder unit" means it is not a bag of fields — [`AgentRung::validate`] enforces real
//! coherence invariants (no capability may exceed the model policy's data-class ceiling, a policy
//! must name at least one provider, an agent must actually *do* something).

use ainxt_types::DataClass;
use serde::{Deserialize, Serialize};

/// A skill is behavioral (plain-text SOP injected into the system prompt) or execution (sandboxed
/// code run before the LLM, output injected as context) — the two `skill_type`s from CLAUDE.md.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SkillKind {
    /// Plain-text SOP / domain instructions injected directly into the system prompt.
    Behavioral,
    /// Sandboxed `run()` whose output is injected into `## Context`.
    Execution,
}

/// A reference to a skill in the Skill Runtime (the executable body is control-plane, git-native).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkillRef {
    pub id: String,
    pub kind: SkillKind,
}

impl SkillRef {
    pub fn behavioral(id: &str) -> Self {
        SkillRef {
            id: id.to_string(),
            kind: SkillKind::Behavioral,
        }
    }
    pub fn execution(id: &str) -> Self {
        SkillRef {
            id: id.to_string(),
            kind: SkillKind::Execution,
        }
    }
}

/// A least-privilege capability grant: a tool/connector/data-class the rung may touch (§2 element 2,
/// Policy-Engine grant). `data_class_ceiling` is the most sensitive data the capability is permitted
/// to handle; `requires_approval` marks a sensitive grant that needs a human sign-off at authoring.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capability {
    /// e.g. `connector.ticketing`, `kb.search`, `connector.email`.
    pub name: String,
    pub data_class_ceiling: DataClass,
    #[serde(default)]
    pub requires_approval: bool,
}

impl Capability {
    pub fn new(name: &str, ceiling: DataClass) -> Self {
        Capability {
            name: name.to_string(),
            data_class_ceiling: ceiling,
            requires_approval: false,
        }
    }
    pub fn requiring_approval(mut self) -> Self {
        self.requires_approval = true;
        self
    }
}

/// The model policy for a rung: which providers it may route to and the most sensitive data class it
/// is allowed to send to a model (ADR-012 data-class-aware routing). A regulated/PII ceiling forces
/// in-house serving upstream — captured here as the declarative intent the router enforces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelPolicy {
    pub allowed_providers: Vec<String>,
    pub max_data_class: DataClass,
}

impl ModelPolicy {
    pub fn new(providers: &[&str], max_data_class: DataClass) -> Self {
        ModelPolicy {
            allowed_providers: providers.iter().map(|p| p.to_string()).collect(),
            max_data_class,
        }
    }
}

/// The **Agent** rung: persona + skills + capabilities + model policy, as a governed ladder unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentRung {
    pub id: String,
    pub persona: String,
    pub skills: Vec<SkillRef>,
    pub capabilities: Vec<Capability>,
    pub model_policy: ModelPolicy,
}

impl AgentRung {
    pub fn new(id: &str, persona: &str, model_policy: ModelPolicy) -> Self {
        AgentRung {
            id: id.to_string(),
            persona: persona.to_string(),
            skills: Vec::new(),
            capabilities: Vec::new(),
            model_policy,
        }
    }
    pub fn with_skill(mut self, skill: SkillRef) -> Self {
        self.skills.push(skill);
        self
    }
    pub fn with_capability(mut self, cap: Capability) -> Self {
        self.capabilities.push(cap);
        self
    }

    /// The most sensitive data class any of this agent's capabilities may touch.
    pub fn max_capability_class(&self) -> DataClass {
        self.capabilities
            .iter()
            .map(|c| c.data_class_ceiling)
            .max()
            .unwrap_or(DataClass::Public)
    }

    /// Governed-ladder-unit validation. Returns every coherence violation (empty = valid), never
    /// panics. These are hard invariants, not lints: an agent that violates them cannot be assembled
    /// into a Role.
    pub fn validate(&self) -> Vec<String> {
        let mut errs = Vec::new();
        if self.id.trim().is_empty() {
            errs.push("agent id is empty".into());
        }
        if self.persona.trim().is_empty() {
            errs.push(format!("agent '{}' has an empty persona", self.id));
        }
        if self.skills.is_empty() && self.capabilities.is_empty() {
            errs.push(format!(
                "agent '{}' has neither skills nor capabilities (does nothing)",
                self.id
            ));
        }
        if self.model_policy.allowed_providers.is_empty() {
            errs.push(format!(
                "agent '{}' model policy names no allowed providers",
                self.id
            ));
        }
        // Least-privilege coherence: a capability may not out-rank what the model policy can route.
        for cap in &self.capabilities {
            if cap.data_class_ceiling > self.model_policy.max_data_class {
                errs.push(format!(
                    "agent '{}' capability '{}' ceiling {} exceeds model-policy max {} (over-privilege)",
                    self.id,
                    cap.name,
                    cap.data_class_ceiling.as_str(),
                    self.model_policy.max_data_class.as_str()
                ));
            }
        }
        errs
    }
}
