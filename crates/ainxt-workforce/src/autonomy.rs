// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! The **per-task autonomy dial** (AINXT_OS §4 Step 4 / WORKFORCE_AND_OS §2 element 4).
//!
//! The innovation the design calls out: autonomy is **per-task, not per-role**. A Support role may
//! run a credential-reset fully automatically, an access-request only *assisted* (HITL), and anything
//! unrecognized *escalates* to a human. Escalation is wired to uncertainty/abstention (gap U) via an
//! [`AutonomyModel::escalation_threshold`]. §5's "responsible reality" is enforced structurally: a
//! task flagged `regulated` can never be dialed to fully-`Auto` — [`AutonomyModel::validate`] rejects
//! it, so the Factory cannot ship a role that flips a regulated payment task to autonomous.

use ainxt_types::DataClass;
use serde::{Deserialize, Serialize};

/// How much autonomy a task is granted. Ordered least-to-most human-involvement is *not* meaningful;
/// these are discrete modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AutonomyLevel {
    /// Fully automatic — the role acts without a human in the loop.
    Auto,
    /// Assisted — the role proposes, a human approves before it acts (HITL gate, ADR-003).
    Assisted,
    /// Supervised — a human drives, the role advises (highest oversight short of escalation).
    Supervised,
    /// Escalate — the role hands the task to a human; it does not act.
    Escalate,
}

/// One task's autonomy setting. `regulated` is the author's *self-declared* flag that a task touches
/// regulated-payment / high-risk work. `data_class` is the (optional) *attested* most-sensitive data
/// class the task itself touches; when regulated it is a stronger, auditable signal than the bare
/// bool and — unlike the bool — it folds into the role's DERIVED [`crate::role::RoleSpec::max_data_class`],
/// so it cannot be silently under-declared. A task whose *effective* data class is regulated (either
/// signal) constrains the dial (see [`AutonomyModel::validate`] and
/// [`crate::role::RoleSpec::validate`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskAutonomy {
    pub task: String,
    pub level: AutonomyLevel,
    #[serde(default)]
    pub regulated: bool,
    /// The most-sensitive data class this task touches, if attested. `None` = not attested (treated
    /// as non-regulated for this task's own signal; the role-level derived class still applies).
    #[serde(default)]
    pub data_class: Option<DataClass>,
}

impl TaskAutonomy {
    pub fn new(task: &str, level: AutonomyLevel) -> Self {
        TaskAutonomy {
            task: task.to_string(),
            level,
            regulated: false,
            data_class: None,
        }
    }
    pub fn regulated(mut self) -> Self {
        self.regulated = true;
        self
    }
    /// Attest the most-sensitive data class this task touches. A regulated class here makes the task
    /// count toward the role's derived data class and forbids `Auto` (fail-closed).
    pub fn touching(mut self, data_class: DataClass) -> Self {
        self.data_class = Some(data_class);
        self
    }
    /// True if the task touches regulated data by EITHER signal: the self-declared `regulated` flag
    /// OR an attested regulated `data_class`. This is what the dial constraints key off — a task
    /// cannot escape the constraint by leaving the bool false while attesting a regulated class.
    pub fn touches_regulated(&self) -> bool {
        self.regulated || self.data_class.map(|d| d.is_regulated()).unwrap_or(false)
    }
}

/// The per-task autonomy dial for a role.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AutonomyModel {
    /// The fallback level for a task not explicitly listed.
    pub default: AutonomyLevel,
    /// Per-task overrides — the actual dial.
    pub per_task: Vec<TaskAutonomy>,
    /// Uncertainty threshold in `[0.0, 1.0]`; a task whose uncertainty is at/above this escalates
    /// (gap U). `1.0` means "never auto-escalate on uncertainty alone".
    pub escalation_threshold: f64,
}

impl AutonomyModel {
    pub fn new(default: AutonomyLevel, escalation_threshold: f64) -> Self {
        AutonomyModel {
            default,
            per_task: Vec::new(),
            escalation_threshold,
        }
    }
    pub fn with_task(mut self, task: TaskAutonomy) -> Self {
        self.per_task.push(task);
        self
    }

    /// Resolve the autonomy level for a named task: its explicit override, else the default.
    pub fn resolve(&self, task: &str) -> AutonomyLevel {
        self.per_task
            .iter()
            .find(|t| t.task == task)
            .map(|t| t.level)
            .unwrap_or(self.default)
    }

    /// Does a task with this measured uncertainty escalate? (gap U / abstention.) Escalation always
    /// wins over the dialed level — "the role knows when it doesn't know".
    pub fn should_escalate(&self, uncertainty: f64) -> bool {
        uncertainty >= self.escalation_threshold
    }

    /// True if the role has *any* path to a human — an escalating task or a sub-`1.0` threshold. A
    /// role with no escalation path at all is a design smell the Breaker rejects.
    pub fn has_escalation_path(&self) -> bool {
        self.escalation_threshold < 1.0
            || self
                .per_task
                .iter()
                .any(|t| t.level == AutonomyLevel::Escalate)
    }

    /// Structural validation. Empty = valid.
    pub fn validate(&self) -> Vec<String> {
        let mut errs = Vec::new();
        if !(0.0..=1.0).contains(&self.escalation_threshold) || self.escalation_threshold.is_nan() {
            errs.push(format!(
                "escalation_threshold {} is outside [0.0, 1.0]",
                self.escalation_threshold
            ));
        }
        // §5 responsible reality: a regulated task can NEVER be fully autonomous. Keyed off the
        // EFFECTIVE signal (self-declared flag OR attested regulated data_class), so a task cannot
        // dodge the rule by attesting a regulated class while leaving the bool false.
        for t in &self.per_task {
            if t.touches_regulated() && t.level == AutonomyLevel::Auto {
                errs.push(format!(
                    "task '{}' is regulated and cannot be dialed to Auto (§5 human-oversight requirement)",
                    t.task
                ));
            }
        }
        errs
    }

    /// The most-sensitive data class attested across the per-task dial (for the role's derived
    /// data-class computation). `Public` if no task attests a class.
    pub fn max_task_data_class(&self) -> DataClass {
        self.per_task
            .iter()
            .filter_map(|t| t.data_class)
            .max()
            .unwrap_or(DataClass::Public)
    }
}
