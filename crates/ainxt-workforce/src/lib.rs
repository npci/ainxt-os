// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! # ainxt-workforce — the AiNxt-OS digital-workforce ladder + Role Studio factory
//!
//! This crate implements, as real declarative + governed Rust objects, the "AiNxt OS" vision from
//! `docs/architecture/AINXT_OS.md` and `docs/architecture/WORKFORCE_AND_OS.md`: the runtime becomes
//! the operating system on which an organization runs a **hybrid human + digital workforce**, built
//! from a creation *ladder* and a conversational *factory*, governed by construction.
//!
//! ## The creation ladder (§1)
//!
//! ```text
//!   Skill  ──►  Agent  ──►  Role (digital worker)  ──►  Digital Team (department)
//! ```
//!
//! - [`ladder::SkillRef`] / [`ladder::AgentRung`] — a skill reference, and the **Agent** rung:
//!   persona + skills + least-privilege [`ladder::Capability`] grants + a [`ladder::ModelPolicy`], as
//!   a *governed* unit ([`ladder::AgentRung::validate`] enforces least-privilege coherence).
//! - [`role::RoleSpec`] → [`role::ValidatedRole`] → [`role::PublishedRole`] — the **Role** rung, a
//!   *digital worker*: a charter + agent(s) + skills + connectors + knowledge + governance + KPIs +
//!   a per-task autonomy dial. Validation bakes in §5's responsible reality and the gap governance
//!   (data-residency N, model-risk P, data-lifecycle Q, on-behalf-of AI) — you cannot assemble a role
//!   that bypasses them.
//! - [`team::DigitalTeam`] — the **Team** rung: a governed department of collaborating *published*
//!   roles (a department cannot be made of ungoverned, un-Breaker-tested workers).
//!
//! ## The Role Studio (AINXT_OS §4)
//!
//! [`studio::RoleStudio`] is the 10-step conversational factory as a typed state machine (Steps 0–10:
//! describe → auto-assemble → grant & govern → per-task autonomy → knowledge + retrieval-quality
//! check → KPI/eval → **Breaker gate** → shadow run → governed publish → monitor).
//!
//! ## The Breaker gate (non-skippable, §4 Step 7)
//!
//! [`breaker::Breaker`] is the adversarial Test Agent. [`breaker::publish`] is the **only**
//! constructor of a [`role::PublishedRole`], and it refuses any report that is not a `Pass` for that
//! exact role — so "cannot skip the Breaker" is a *type-level* guarantee, not a convention. The Studio
//! reinforces it: its state machine cannot reach `Published` without a passing Breaker report.
//!
//! ## Citizen lifecycle (§6) & oversight health (§7)
//!
//! [`lifecycle`] implements the continuous citizen-artifact controls (decay sweep, recert nudge,
//! standing orphan sweep, ownership succession, forced-review-before-deprecation). [`oversight`]
//! implements the automation-complacency controls (approve-latency + override-rate metrics,
//! Breaker-generated attention-check decoys, competency-status re-routing). Both are pure logic over
//! data-plane telemetry with an injected integer clock — no infra, no wall-clock, no RNG.
//!
//! Everything here is deterministic and exhaustively testable; the executable bodies (skill `run()`,
//! model calls, connectors, the live sweeps' schedulers) are downstream seams, not this crate's job.

pub mod author;
pub mod autonomy;
pub mod breaker;
pub mod controls;
pub mod kernel;
pub mod ladder;
pub mod lifecycle;
pub mod oversight;
pub mod role;
pub mod studio;
pub mod team;

// Curated re-exports — the ladder rungs and the factory, at the crate root.
pub use author::{
    Factory, FactoryConfig, IntentExtractor, JobDescription, KeywordIntentExtractor,
    TemplateBlueprint,
};
pub use autonomy::{AutonomyLevel, AutonomyModel, TaskAutonomy};
pub use breaker::{
    merge_payload, publish, tag_payload, AdversarialCase, AdversarialReport, Breaker, BreakerPass,
    BreakerReport, BreakerVerdict, CompliantExecutor, Expectation, GateError,
    GovernedPublishRequest, Probe, ProbeCategory, PublishError, ResponseAction, RoleExecutor,
    RoleOutput, ScriptedExecutor,
};
pub use controls::{
    DataPlaneStore, EventLog, InMemoryDataPlane, InMemoryEventLog, LoggedEvent, NightlyControls,
    Notifier, RecordingNotifier, SentDigest, SweepSummary, DEFAULT_RECERT_AFTER_DAYS,
};
pub use kernel::{Kernel, KernelError, Pid, ProcessState, RoleProcess};
pub use ladder::{AgentRung, Capability, ModelPolicy, SkillKind, SkillRef};
pub use lifecycle::decay_score;
pub use role::{
    Charter, ConnectorRef, DeprecateError, Governance, KnowledgeScope, Kpi, ModelRiskClass,
    PaymentBoundary, PublishedRole, Residency, RoleSpec, ValidatedRole, Visibility,
};
pub use studio::{
    MonitorDecision, RoleStudio, ShadowResult, StudioError, StudioStage, Template,
    MIN_SHADOW_AGREEMENT, MIN_SHADOW_OBSERVATIONS,
};
pub use team::{Collaboration, DigitalTeam, TeamError};
