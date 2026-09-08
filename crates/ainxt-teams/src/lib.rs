// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! ainxt-teams — hierarchical agent teams & long-horizon program scheduling.
//!
//! Design: `docs/architecture/LOOP_AND_AGENT_TEAMS.md` and
//! `docs/architecture/LONG_HORIZON_PROGRAMS.md` (ADR-027).
//!
//! This crate is the **pure, deterministic core** of the runtime's multi-agent
//! orchestration. It does no I/O, spawns no threads, and calls no model — every LLM
//! interaction is a *seam* the caller injects (`run_team`'s `step` closure). Keeping the
//! core pure is what makes the scheduler exhaustively testable: the same graph with the
//! same step behaviour always produces the same [`RunReport`], so the guarantees below are
//! properties a unit test can actually assert rather than hope for.
//!
//! # What is real here
//!
//! * [`Role`] — an identity with a set of capabilities and a [`ModelTier`] (re-exported
//!   from `ainxt-types`). A [`Team`] is the role registry a Run draws from.
//! * [`HandoffContract`] — roles never hand off free text (LOOP §4). A handoff carries the
//!   inputs it provides; [`HandoffContract::validate`] refuses the handoff if any input the
//!   receiving task *requires* is missing. This is the mechanism that stops the "silently
//!   guessed an ambiguity" bug class the SDLC judge-loop already guards against.
//! * [`TaskGraph`] — the transient, agent-authored plan (LOOP §3). [`TaskGraph::topological_order`]
//!   is a **deterministic Kahn** sort (ties broken by task-id order, so the schedule is
//!   reproducible) that also *rejects* cycles, self-dependencies, and dangling dependency
//!   references — a graph that cannot be scheduled never silently runs a partial subset.
//! * [`AgentInvocation`] — the sub-agent call tree. [`AgentInvocation::rolled_up_cost`] sums
//!   every descendant's cost into the parent (LOOP §4 cost roll-up), so budget is enforced on
//!   the *Run total*, closing the loophole where spawning five sub-agents would bypass a
//!   per-user ceiling five-fold. [`AgentInvocation::validate_depth`] enforces the hard
//!   hierarchy depth cap (LOOP §4 depth cap, default [`DEFAULT_MAX_DEPTH`]).
//! * [`run_team`] — the scheduler. It walks the topological order once and applies **bulkhead
//!   failure isolation** (LOOP §4): a failed or refused task marks only its *transitive*
//!   dependents [`TaskState::Blocked`]; independent branches keep running and complete. Cost
//!   is rolled up across every task that actually executed.
//!
//! # What this crate also owns (the pure decision logic)
//!
//! * [`TaskGraph::ready_wave`] — the deterministic **fan-out admission** decision (LOOP §3/§8): which
//!   runnable tasks to launch this wave, capped at a fan-out ceiling. The concurrency itself (the
//!   thread/task spawn) is the runtime's; the *decision of what may run, and how many*, is here.
//! * [`run_team_budgeted`] — cost roll-up **enforced** against a hard Run ceiling (LOOP §4), not
//!   merely accounted.
//! * [`run_team_cancellable`] — a **cancellation** seam (LOOP §8): one shared signal cancels the
//!   whole team; tasks reached after cancel never invoke their `step` seam.
//! * [`LearningRecord`] — the terminal-Run **Learning Record** (LOOP §10 / ADR-027 §13 flywheel).
//!
//! # What is deliberately a seam (not stubbed — absent by design)
//!
//! The Planner's LLM decomposition, the tier-2 critic, and the tier-3 judge live in other crates and
//! the live runtime; the durable, hash-chained Event-Log **Program** aggregate (ADR-027 §4) lives in
//! `ainxt-planner`'s `program` module. This crate owns exactly the *pure* invariants those layers
//! depend on: ordering, fan-out admission, handoff validity, cost accounting + enforcement,
//! cancellation, and failure blast-radius.

pub mod flywheel;
pub mod tiers;

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Model complexity tier a role runs at — re-exported from `ainxt-types` (ADR-006 routing).
pub use ainxt_types::Tier as ModelTier;

/// Hard default ceiling on agent-hierarchy depth (LOOP §4 depth cap). Architect → Planner →
/// Coder is depth 3; Reviewer/Tester are depth-2 siblings of Coder, not depth-4 descendants.
pub const DEFAULT_MAX_DEPTH: usize = 3;

// ---------------------------------------------------------------------------
// Identifiers
// ---------------------------------------------------------------------------

/// Stable identity of a role within a team (e.g. `"architect"`, `"coder"`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RoleId(pub String);

/// Stable identity of a task, stable across replans (LOOP §2 decomposition contract).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TaskId(pub String);

macro_rules! id_newtype {
    ($t:ident) => {
        impl $t {
            pub fn new(s: impl Into<String>) -> Self {
                $t(s.into())
            }
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
        impl From<&str> for $t {
            fn from(s: &str) -> Self {
                $t(s.to_string())
            }
        }
        impl From<String> for $t {
            fn from(s: String) -> Self {
                $t(s)
            }
        }
        impl fmt::Display for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}
id_newtype!(RoleId);
id_newtype!(TaskId);

// ---------------------------------------------------------------------------
// Cost & sub-agent roll-up
// ---------------------------------------------------------------------------

/// Resource cost of an agent invocation. Money is tracked in whole micro-dollars (integer,
/// not float) so roll-up and budget comparison are exact and reproducible across platforms.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cost {
    pub tokens: u64,
    pub tool_calls: u64,
    pub wall_time_ms: u64,
    /// Dollars in micro-units (1 USD = 1_000_000). Integer to keep roll-up exact.
    pub dollars_micros: u64,
}

impl Cost {
    /// The additive identity — a task that never ran costs this.
    pub const ZERO: Cost = Cost {
        tokens: 0,
        tool_calls: 0,
        wall_time_ms: 0,
        dollars_micros: 0,
    };

    pub fn new(tokens: u64, tool_calls: u64, wall_time_ms: u64, dollars_micros: u64) -> Self {
        Cost {
            tokens,
            tool_calls,
            wall_time_ms,
            dollars_micros,
        }
    }

    /// Overflow-safe addition. At program scale (thousands of Runs) a naive `+` could wrap;
    /// saturating is the enterprise-safe choice — the aggregate can never silently roll over
    /// to a tiny number and defeat the budget ceiling.
    pub fn saturating_add(self, other: Cost) -> Cost {
        Cost {
            tokens: self.tokens.saturating_add(other.tokens),
            tool_calls: self.tool_calls.saturating_add(other.tool_calls),
            wall_time_ms: self.wall_time_ms.saturating_add(other.wall_time_ms),
            dollars_micros: self.dollars_micros.saturating_add(other.dollars_micros),
        }
    }

    /// True when every field is within (`<=`) the given ceiling — the budget-gate check.
    pub fn within(self, ceiling: Cost) -> bool {
        self.tokens <= ceiling.tokens
            && self.tool_calls <= ceiling.tool_calls
            && self.wall_time_ms <= ceiling.wall_time_ms
            && self.dollars_micros <= ceiling.dollars_micros
    }
}

impl std::ops::Add for Cost {
    type Output = Cost;
    fn add(self, rhs: Cost) -> Cost {
        self.saturating_add(rhs)
    }
}

impl std::iter::Sum for Cost {
    fn sum<I: Iterator<Item = Cost>>(iter: I) -> Cost {
        iter.fold(Cost::ZERO, Cost::saturating_add)
    }
}

/// A single node in the sub-agent call tree (LOOP §4: "call another agent as a sub-agent").
///
/// Each invocation carries its **own** cost and the invocations it spawned. The parent Run
/// rolls the whole tree up into one aggregate ([`rolled_up_cost`](Self::rolled_up_cost)); the
/// budget middleware checks that aggregate, never a per-role slice — so spawning a team of
/// five to do one role's work cannot bypass a per-user ceiling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentInvocation {
    pub role: RoleId,
    pub own_cost: Cost,
    pub children: Vec<AgentInvocation>,
}

impl AgentInvocation {
    /// A leaf invocation (no sub-agents) that spent `own_cost`.
    pub fn leaf(role: impl Into<RoleId>, own_cost: Cost) -> Self {
        AgentInvocation {
            role: role.into(),
            own_cost,
            children: Vec::new(),
        }
    }

    /// Builder: attach a spawned sub-agent invocation.
    pub fn with_child(mut self, child: AgentInvocation) -> Self {
        self.children.push(child);
        self
    }

    /// Total cost of this invocation **and every descendant**, rolled up (LOOP §4).
    pub fn rolled_up_cost(&self) -> Cost {
        self.children
            .iter()
            .map(AgentInvocation::rolled_up_cost)
            .sum::<Cost>()
            .saturating_add(self.own_cost)
    }

    /// Depth of the deepest chain rooted here. A leaf is depth 1; Architect → Planner → Coder
    /// is depth 3.
    pub fn depth(&self) -> usize {
        1 + self
            .children
            .iter()
            .map(AgentInvocation::depth)
            .max()
            .unwrap_or(0)
    }

    /// Count of descendant invocations (not counting `self`).
    pub fn descendant_count(&self) -> usize {
        self.children.iter().map(|c| 1 + c.descendant_count()).sum()
    }

    /// Enforce the hard hierarchy depth cap (LOOP §4). An invocation tree deeper than `max`
    /// is a runaway agent-spawns-agent recursion and is rejected at the kernel boundary.
    pub fn validate_depth(&self, max: usize) -> Result<(), DepthCapExceeded> {
        let actual = self.depth();
        if actual > max {
            Err(DepthCapExceeded { max, actual })
        } else {
            Ok(())
        }
    }
}

/// Raised when a sub-agent hierarchy exceeds the configured depth cap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepthCapExceeded {
    pub max: usize,
    pub actual: usize,
}

impl fmt::Display for DepthCapExceeded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "agent hierarchy depth {} exceeds cap {}",
            self.actual, self.max
        )
    }
}

impl std::error::Error for DepthCapExceeded {}

// ---------------------------------------------------------------------------
// Roles & teams
// ---------------------------------------------------------------------------

/// A composed role in a hierarchical team (LOOP §4): an identity, the capabilities it is
/// granted (least-privilege), and the model tier it runs at.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Role {
    pub id: RoleId,
    pub capabilities: BTreeSet<String>,
    pub model_tier: ModelTier,
}

impl Role {
    pub fn new(
        id: impl Into<RoleId>,
        model_tier: ModelTier,
        capabilities: impl IntoIterator<Item = &'static str>,
    ) -> Self {
        Role {
            id: id.into(),
            model_tier,
            capabilities: capabilities.into_iter().map(str::to_string).collect(),
        }
    }

    /// True iff this role was granted `cap`. There is no implicit escalation — a role has
    /// exactly the capabilities it was given (least-privilege, LOOP §4 / gap AI).
    pub fn has_capability(&self, cap: &str) -> bool {
        self.capabilities.contains(cap)
    }
}

/// The registry of roles a Run may draw from.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Team {
    roles: BTreeMap<RoleId, Role>,
}

impl Team {
    pub fn new() -> Self {
        Team::default()
    }

    /// Register a role. Returns the previously-registered role of the same id, if any.
    pub fn add_role(&mut self, role: Role) -> Option<Role> {
        self.roles.insert(role.id.clone(), role)
    }

    pub fn get(&self, id: &RoleId) -> Option<&Role> {
        self.roles.get(id)
    }

    pub fn contains(&self, id: &RoleId) -> bool {
        self.roles.contains_key(id)
    }

    pub fn len(&self) -> usize {
        self.roles.len()
    }

    pub fn is_empty(&self) -> bool {
        self.roles.is_empty()
    }

    /// True iff `id` names a role in the team that holds `cap`.
    pub fn role_has_capability(&self, id: &RoleId, cap: &str) -> bool {
        self.roles.get(id).is_some_and(|r| r.has_capability(cap))
    }

    /// The UNION of every registered role's declared capabilities (LOOP §4) — the team-wide authority
    /// envelope no single role may exceed. GAP-FIX gap6-tools-hooks-obo-supplychain item 3: this is the
    /// PARENT scope a per-task OBO sub-agent delegation (`ainxt_tools::obo::OboContext::delegate`)
    /// narrows FROM — the team as a whole may do anything any of its roles are allowed to do, while
    /// each individual task is authorized against only its OWN role's `capabilities` (a genuine,
    /// provable subset whenever the team has more than one role, or a role that doesn't hold every
    /// capability in the team).
    pub fn all_capabilities(&self) -> BTreeSet<String> {
        self.roles
            .values()
            .flat_map(|r| r.capabilities.iter().cloned())
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Handoff contract
// ---------------------------------------------------------------------------

/// A structured handoff between two roles (LOOP §4). Roles never hand off free text: the
/// contract names the task, the producing/receiving roles, the inputs it *provides* (each an
/// artifact reference), the producer's self-estimated confidence, and any `open_questions`
/// the receiver must not silently resolve.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HandoffContract {
    pub from_role: RoleId,
    pub to_role: RoleId,
    pub task_id: TaskId,
    /// input name → artifact reference the producer is handing over.
    pub provided: BTreeMap<String, String>,
    /// The producing role's own self-estimate (0.0–1.0).
    pub confidence: f32,
    /// Ambiguities the next role must resolve explicitly rather than guess.
    pub open_questions: Vec<String>,
    /// The cost the producing role's task actually consumed (LOOP §4 handoff-contract completeness):
    /// carried through the handoff so the receiver — and the Run budget — see the running total, not
    /// just the artifacts. Defaults to [`Cost::ZERO`] for backward-compatible deserialization.
    #[serde(default)]
    pub cost_used: Cost,
    /// The acceptance criteria the producer certifies it satisfied, carried forward so the receiver
    /// inherits the definition of "done" instead of re-deriving it (LOOP §4). Defaults to empty.
    #[serde(default)]
    pub acceptance_criteria: BTreeSet<String>,
}

impl HandoffContract {
    pub fn new(
        from_role: impl Into<RoleId>,
        to_role: impl Into<RoleId>,
        task_id: impl Into<TaskId>,
    ) -> Self {
        HandoffContract {
            from_role: from_role.into(),
            to_role: to_role.into(),
            task_id: task_id.into(),
            provided: BTreeMap::new(),
            confidence: 1.0,
            open_questions: Vec::new(),
            cost_used: Cost::ZERO,
            acceptance_criteria: BTreeSet::new(),
        }
    }

    /// Builder: record an input this handoff provides.
    pub fn with_input(mut self, name: impl Into<String>, artifact_ref: impl Into<String>) -> Self {
        self.provided.insert(name.into(), artifact_ref.into());
        self
    }

    pub fn with_confidence(mut self, confidence: f32) -> Self {
        self.confidence = confidence;
        self
    }

    pub fn with_open_question(mut self, q: impl Into<String>) -> Self {
        self.open_questions.push(q.into());
        self
    }

    /// Builder: record the cost the producing task consumed (LOOP §4).
    pub fn with_cost_used(mut self, cost: Cost) -> Self {
        self.cost_used = cost;
        self
    }

    /// Builder: certify an acceptance criterion this handoff satisfies (LOOP §4).
    pub fn with_acceptance_criterion(mut self, criterion: impl Into<String>) -> Self {
        self.acceptance_criteria.insert(criterion.into());
        self
    }

    /// The receiving task's acceptance criteria this handoff does **not** carry. Empty ⇒ the handoff
    /// is complete with respect to "done" (LOOP §4 handoff-contract completeness). A non-empty result
    /// means the producer is handing off work whose acceptance is undefined for the receiver — the
    /// exact "silently guessed the definition of done" bug class this contract exists to prevent.
    pub fn missing_acceptance_criteria(&self, required: &BTreeSet<String>) -> Vec<String> {
        required
            .difference(&self.acceptance_criteria)
            .cloned()
            .collect()
    }

    /// The set of input names this handoff provides.
    pub fn provided_names(&self) -> BTreeSet<String> {
        self.provided.keys().cloned().collect()
    }

    /// Validate this handoff against the receiving task's `required` inputs. If any required
    /// input is missing the handoff is **refused** (LOOP §4) — the receiver must not proceed
    /// on a silently-assumed input. The refusal names every missing input, sorted.
    pub fn validate(&self, required: &BTreeSet<String>) -> Result<(), HandoffRefused> {
        validate_inputs(
            &self.to_role,
            &self.task_id,
            required,
            &self.provided_names(),
        )
    }
}

/// Raised when a handoff omits an input the receiving task requires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoffRefused {
    pub to_role: RoleId,
    pub task_id: TaskId,
    /// Required inputs that were not provided, sorted.
    pub missing_inputs: Vec<String>,
}

impl fmt::Display for HandoffRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "handoff to role '{}' for task '{}' refused: missing required input(s) {:?}",
            self.to_role, self.task_id, self.missing_inputs
        )
    }
}

impl std::error::Error for HandoffRefused {}

/// The shared handoff-validity check: `required ⊆ provided`, else a [`HandoffRefused`] naming
/// the difference. Used by both [`HandoffContract::validate`] and the scheduler.
pub fn validate_inputs(
    to_role: &RoleId,
    task_id: &TaskId,
    required: &BTreeSet<String>,
    provided: &BTreeSet<String>,
) -> Result<(), HandoffRefused> {
    let missing: Vec<String> = required.difference(provided).cloned().collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(HandoffRefused {
            to_role: to_role.clone(),
            task_id: task_id.clone(),
            missing_inputs: missing,
        })
    }
}

// ---------------------------------------------------------------------------
// Task graph
// ---------------------------------------------------------------------------

/// One node of the transient, agent-authored plan (LOOP §2 decomposition contract). Carries
/// the same fields whether it lives in a flat list (no `dependencies`) or a materialized graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Task {
    pub id: TaskId,
    /// Which team role owns this task.
    pub role: RoleId,
    pub description: String,
    /// Inputs (by name) this task needs before it can run — validated at handoff time.
    pub required_inputs: BTreeSet<String>,
    /// Outputs (by name) this task produces on success — feeds downstream handoffs.
    pub outputs: BTreeSet<String>,
    /// Task ids that must complete first (empty for a flat list's head).
    pub dependencies: BTreeSet<TaskId>,
    /// Token/tool-call/wall-time ceiling for this task.
    pub budget: Cost,
    /// The acceptance criteria this task must satisfy to be considered done (LOOP §2/§4 decomposition
    /// contract). Carried through the handoff so the next role does not silently redefine "done".
    #[serde(default)]
    pub acceptance_criteria: BTreeSet<String>,
}

impl Task {
    pub fn new(id: impl Into<TaskId>, role: impl Into<RoleId>) -> Self {
        Task {
            id: id.into(),
            role: role.into(),
            description: String::new(),
            required_inputs: BTreeSet::new(),
            outputs: BTreeSet::new(),
            dependencies: BTreeSet::new(),
            budget: Cost::ZERO,
            acceptance_criteria: BTreeSet::new(),
        }
    }

    pub fn describe(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }

    /// Builder: add an acceptance criterion this task must satisfy (LOOP §2/§4).
    pub fn accepts(mut self, criterion: impl Into<String>) -> Self {
        self.acceptance_criteria.insert(criterion.into());
        self
    }

    pub fn depends_on(mut self, dep: impl Into<TaskId>) -> Self {
        self.dependencies.insert(dep.into());
        self
    }

    pub fn requires(mut self, input: impl Into<String>) -> Self {
        self.required_inputs.insert(input.into());
        self
    }

    pub fn produces(mut self, output: impl Into<String>) -> Self {
        self.outputs.insert(output.into());
        self
    }

    pub fn with_budget(mut self, budget: Cost) -> Self {
        self.budget = budget;
        self
    }
}

/// A dependency-ordered set of tasks (LOOP §3). Authored by the agent, scoped to one Run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TaskGraph {
    tasks: BTreeMap<TaskId, Task>,
}

/// Why a graph cannot be scheduled. Every one blocks the whole run rather than executing a
/// silently-partial subset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraphError {
    /// A task id was inserted twice.
    DuplicateTask { id: TaskId },
    /// A task depends on itself.
    SelfDependency { id: TaskId },
    /// A task depends on an id that is not in the graph.
    MissingDependency { task: TaskId, missing: TaskId },
    /// The dependency relation contains a cycle; `involved` are the tasks still in it, sorted.
    Cycle { involved: Vec<TaskId> },
}

impl fmt::Display for GraphError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GraphError::DuplicateTask { id } => write!(f, "duplicate task '{id}'"),
            GraphError::SelfDependency { id } => write!(f, "task '{id}' depends on itself"),
            GraphError::MissingDependency { task, missing } => {
                write!(f, "task '{task}' depends on unknown task '{missing}'")
            }
            GraphError::Cycle { involved } => {
                write!(f, "dependency cycle among tasks {involved:?}")
            }
        }
    }
}

impl std::error::Error for GraphError {}

impl TaskGraph {
    pub fn new() -> Self {
        TaskGraph::default()
    }

    /// Insert a task. Rejects a duplicate id so a replan cannot silently clobber a node.
    pub fn add_task(&mut self, task: Task) -> Result<(), GraphError> {
        if self.tasks.contains_key(&task.id) {
            return Err(GraphError::DuplicateTask { id: task.id });
        }
        self.tasks.insert(task.id.clone(), task);
        Ok(())
    }

    pub fn get(&self, id: &TaskId) -> Option<&Task> {
        self.tasks.get(id)
    }

    pub fn len(&self) -> usize {
        self.tasks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    /// Validate every dependency reference resolves and no task depends on itself. Called by
    /// [`topological_order`](Self::topological_order); exposed for pre-flight checks.
    pub fn validate_edges(&self) -> Result<(), GraphError> {
        for (id, task) in &self.tasks {
            for dep in &task.dependencies {
                if dep == id {
                    return Err(GraphError::SelfDependency { id: id.clone() });
                }
                if !self.tasks.contains_key(dep) {
                    return Err(GraphError::MissingDependency {
                        task: id.clone(),
                        missing: dep.clone(),
                    });
                }
            }
        }
        Ok(())
    }

    /// The next **wave** of tasks admissible for concurrent execution (LOOP §3/§8): every task not
    /// yet `completed` whose dependencies are **all** in `completed`, capped at `fan_out_ceiling`.
    ///
    /// This is the pure admission decision the parallel scheduler makes each tick — *which* runnable
    /// tasks to launch this wave, bounded by the fan-out ceiling that stops a wide graph from
    /// swamping the fleet (§7). The concurrency itself (spawning the Runs) lives in the live runtime;
    /// the decision of what may run, and how many, is deterministic and lives here. Returned in
    /// task-id order (reproducible); a ceiling of 0 admits nothing.
    pub fn ready_wave(&self, completed: &BTreeSet<TaskId>, fan_out_ceiling: usize) -> Vec<TaskId> {
        self.tasks
            .values()
            .filter(|t| !completed.contains(&t.id))
            .filter(|t| t.dependencies.iter().all(|d| completed.contains(d)))
            .map(|t| t.id.clone())
            .take(fan_out_ceiling)
            .collect()
    }

    /// The set of tasks that depend on `id` (its direct dependents), sorted.
    pub fn dependents_of(&self, id: &TaskId) -> Vec<TaskId> {
        self.tasks
            .values()
            .filter(|t| t.dependencies.contains(id))
            .map(|t| t.id.clone())
            .collect()
    }

    /// Deterministic Kahn topological sort (LOOP §3). Ready nodes are admitted in task-id
    /// order, so the schedule is reproducible for a given graph. Returns [`GraphError::Cycle`]
    /// (naming the tasks still in the cycle) if the graph is not a DAG, and rejects dangling
    /// or self dependencies first.
    pub fn topological_order(&self) -> Result<Vec<TaskId>, GraphError> {
        self.validate_edges()?;

        // in-degree = number of unsatisfied dependencies.
        let mut in_degree: BTreeMap<TaskId, usize> =
            self.tasks.keys().map(|id| (id.clone(), 0usize)).collect();
        for task in self.tasks.values() {
            *in_degree.get_mut(&task.id).expect("id present") = task.dependencies.len();
        }

        // dep -> tasks that depend on it (reverse adjacency).
        let mut dependents: BTreeMap<TaskId, Vec<TaskId>> = BTreeMap::new();
        for task in self.tasks.values() {
            for dep in &task.dependencies {
                dependents
                    .entry(dep.clone())
                    .or_default()
                    .push(task.id.clone());
            }
        }

        // BTreeSet gives us a deterministic "smallest ready id first" admission order.
        let mut ready: BTreeSet<TaskId> = in_degree
            .iter()
            .filter(|(_, d)| **d == 0)
            .map(|(id, _)| id.clone())
            .collect();

        let mut order: Vec<TaskId> = Vec::with_capacity(self.tasks.len());
        while let Some(next) = ready.iter().next().cloned() {
            ready.remove(&next);
            order.push(next.clone());
            if let Some(deps) = dependents.get(&next) {
                for dependent in deps {
                    let deg = in_degree.get_mut(dependent).expect("dependent present");
                    *deg -= 1;
                    if *deg == 0 {
                        ready.insert(dependent.clone());
                    }
                }
            }
        }

        if order.len() != self.tasks.len() {
            // Whatever still has in-degree > 0 is trapped in (or downstream of) a cycle.
            let involved: Vec<TaskId> = in_degree
                .into_iter()
                .filter(|(_, d)| *d > 0)
                .map(|(id, _)| id)
                .collect();
            return Err(GraphError::Cycle { involved });
        }

        Ok(order)
    }
}

// ---------------------------------------------------------------------------
// Team run — scheduling with failure isolation & cost roll-up
// ---------------------------------------------------------------------------

/// Terminal state of a task after a [`run_team`] pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TaskState {
    /// Ran and reported success.
    Succeeded,
    /// Ran and reported failure (its own execution failed).
    Failed,
    /// Never ran: a dependency Failed, was Refused, or was itself Blocked (bulkhead cascade).
    Blocked,
    /// Never ran: a required input was not provided by any dependency (handoff refused).
    Refused,
    /// Never ran: the Run stopped before reaching it — the budget ceiling was crossed (LOOP §4 cost
    /// roll-up as a hard ceiling) or the Run was cancelled (LOOP §8). The [`RunReport`] flags which.
    Skipped,
    /// Never ran: the Run was cancelled at or before this task (LOOP §8 cancellation propagation —
    /// one Run token cancels the whole team at any depth).
    Cancelled,
}

/// What the injected `step` seam reports for one executed task.
#[derive(Debug, Clone, PartialEq)]
pub struct StepReport {
    /// The sub-agent call tree for this task (drives cost roll-up).
    pub invocation: AgentInvocation,
    /// Whether the task's own work succeeded.
    pub outcome: StepOutcome,
}

/// Outcome the role reports for its task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepOutcome {
    Success,
    Failure(String),
}

impl StepReport {
    pub fn success(invocation: AgentInvocation) -> Self {
        StepReport {
            invocation,
            outcome: StepOutcome::Success,
        }
    }

    pub fn failure(invocation: AgentInvocation, reason: impl Into<String>) -> Self {
        StepReport {
            invocation,
            outcome: StepOutcome::Failure(reason.into()),
        }
    }
}

/// The outcome of scheduling a whole [`TaskGraph`].
#[derive(Debug, Clone)]
pub struct RunReport {
    /// The order tasks were considered in (topological).
    pub order: Vec<TaskId>,
    /// Terminal state of every task.
    pub states: BTreeMap<TaskId, TaskState>,
    /// Aggregate cost, rolled up across every task that executed (LOOP §4).
    pub total_cost: Cost,
    /// Human-readable note per non-succeeded task (failure reason / missing inputs / blocker).
    pub notes: BTreeMap<TaskId, String>,
    /// True iff the Run stopped because the rolled-up cost crossed the budget ceiling (LOOP §4 hard
    /// ceiling). The crossing task still executed; every task after it is [`TaskState::Skipped`].
    pub budget_exhausted: bool,
    /// True iff the Run was cancelled mid-schedule (LOOP §8). Tasks reached after cancellation are
    /// [`TaskState::Cancelled`] and their `step` seam is never invoked.
    pub cancelled: bool,
    /// Read-only telemetry (LOOP §3/§8): the widest [`TaskGraph::ready_wave`] the graph ever
    /// presented during this pass, uncapped. This scheduler still admits and runs tasks **one at a
    /// time** in topological order (the sequential walk above is unchanged) — this field does not
    /// affect execution order, timing, or any other guarantee in this report. It exists so a caller
    /// (or the audit trail / Learning Record) can see how much fan-out potential the graph exposed at
    /// its widest point, i.e. how many *independent* tasks could in principle have been dispatched
    /// concurrently by a live runtime that actually spawns work, versus how many this pure, sequential
    /// core actually ran per step (always exactly one). Wiring the live runtime to *exploit* this
    /// potential (via [`TaskGraph::ready_wave`] and, upstream, `ainxt_planner::qos::ElasticFanoutPolicy`)
    /// is tracked separately — see the module docs.
    pub max_observed_wave_width: usize,
}

impl RunReport {
    pub fn state_of(&self, id: &TaskId) -> Option<TaskState> {
        self.states.get(id).copied()
    }

    /// Task ids in the given state, sorted.
    pub fn in_state(&self, state: TaskState) -> Vec<TaskId> {
        self.states
            .iter()
            .filter(|(_, s)| **s == state)
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// True iff every task ran and succeeded.
    pub fn all_succeeded(&self) -> bool {
        !self.states.is_empty() && self.states.values().all(|s| *s == TaskState::Succeeded)
    }
}

/// Why the schedule stopped early (before it walked the whole order).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StopCause {
    Budget,
    Cancelled,
}

/// Drive a [`TaskGraph`] to completion, one task at a time in topological order, applying the
/// injected `step` seam to each *runnable* task.
///
/// Guarantees (all asserted by the crate's tests):
///
/// * **Handoff validity** — before a task runs, the inputs it requires must all be provided by
///   `seed_inputs` or the outputs of its (already-succeeded) dependencies; otherwise it is
///   [`TaskState::Refused`] and `step` is never called for it (LOOP §4).
/// * **Failure isolation (bulkhead)** — a Failed or Refused task marks only its *transitive*
///   dependents [`TaskState::Blocked`]; tasks on independent branches keep running (LOOP §4).
/// * **Cost roll-up** — `total_cost` is the saturating sum of `rolled_up_cost()` over every
///   task that actually executed (Succeeded or Failed); Blocked/Refused tasks cost nothing.
///
/// Returns [`GraphError`] without calling `step` at all if the graph is not schedulable.
///
/// GAP-AUDIT gap6-synthesis-teams-scheduler — reachability check: the served team path
/// (`tiers::run_team_3tier_verified_cancellable`, reached from `ainxt-runtimed`'s
/// `program_exec.rs::drive_served_team_blocking` on `/v1/chat`) does not call this exact function by
/// name — it needs real fan-out + real cancellation, so it calls sibling wrapper
/// [`run_team_fanout_cancellable`] instead. That sibling shares this function's entire engine
/// (`run_team_inner`, below) byte-for-byte: same topological/Kahn admission, same
/// [`TaskGraph::ready_wave`] fan-out, same bulkhead isolation, same cost roll-up. See the module doc on
/// `tiers` for the full analysis — the served team path already reaches this scheduler every round; a
/// literal-name grep for `run_team` alone misses it.
pub fn run_team<F>(
    graph: &TaskGraph,
    seed_inputs: &BTreeSet<String>,
    step: F,
) -> Result<RunReport, GraphError>
where
    F: FnMut(&Task) -> StepReport,
{
    let mut never_cancel = || false;
    run_team_inner(graph, seed_inputs, None, 1, &mut never_cancel, step)
}

/// Like [`run_team`], but admits a **wave** of independent ready tasks each tick instead of walking
/// the graph strictly one task at a time (LOOP §3/§8 — GAP-AUDIT loop-teams-longhorizon: "the Team
/// scheduler processes exactly one ready task at a time, despite having a complete, tested
/// fan-out/parallel-admission primitive [`TaskGraph::ready_wave`] sitting unused one function away").
/// `run_team`/`run_team_budgeted`/`run_team_cancellable` all call the shared inner scheduler with a
/// fan-out ceiling of exactly `1`, which — because [`TaskGraph::ready_wave`]'s admission order is the
/// same deterministic "smallest ready id first" rule [`TaskGraph::topological_order`] uses — reproduces
/// their prior one-task-at-a-time schedule byte for byte. `fan_out_ceiling` is the real consumer the
/// audit found missing: pass the width [`ainxt_planner::qos::ElasticFanoutPolicy::admit`] computes for
/// the Run's [`ainxt_planner::qos::WorkloadClass`] and live
/// [`ainxt_planner::qos::FleetCapacity`] to admit independent siblings into the same wave instead of
/// serializing them.
///
/// Execution within an admitted wave is still a plain sequential `for task in wave` call into `step`
/// — true concurrent dispatch is the same deep concurrency-semantics redesign already deferred for the
/// analogous served Program driver (`ainxt-runtimed`'s `drive_served_program_governed`, GAP-AUDIT
/// loop-teams-longhorizon gap 5). What changes here, and what the test below proves, is the
/// **admission width**: independent siblings are grouped into the same wave (and so become reachable to
/// `step` in the same tick) rather than always being serialized regardless of independence.
pub fn run_team_fanout<F>(
    graph: &TaskGraph,
    seed_inputs: &BTreeSet<String>,
    fan_out_ceiling: usize,
    step: F,
) -> Result<RunReport, GraphError>
where
    F: FnMut(&Task) -> StepReport,
{
    let mut never_cancel = || false;
    run_team_inner(
        graph,
        seed_inputs,
        None,
        fan_out_ceiling,
        &mut never_cancel,
        step,
    )
}

/// [`run_team_fanout`] with the hard budget ceiling from [`run_team_budgeted`].
pub fn run_team_fanout_budgeted<F>(
    graph: &TaskGraph,
    seed_inputs: &BTreeSet<String>,
    ceiling: Cost,
    fan_out_ceiling: usize,
    step: F,
) -> Result<RunReport, GraphError>
where
    F: FnMut(&Task) -> StepReport,
{
    let mut never_cancel = || false;
    run_team_inner(
        graph,
        seed_inputs,
        Some(ceiling),
        fan_out_ceiling,
        &mut never_cancel,
        step,
    )
}

/// [`run_team_fanout`] with the cancellation seam from [`run_team_cancellable`]. One shared `cancel`
/// signal still cancels the whole team at any depth (LOOP §8) — a wave in flight is not preempted
/// mid-wave, but no further wave is admitted, matching [`run_team_cancellable`]'s "reached after cancel
/// never invoke `step`" guarantee.
pub fn run_team_fanout_cancellable<F, C>(
    graph: &TaskGraph,
    seed_inputs: &BTreeSet<String>,
    fan_out_ceiling: usize,
    cancel: C,
    step: F,
) -> Result<RunReport, GraphError>
where
    F: FnMut(&Task) -> StepReport,
    C: FnMut() -> bool,
{
    let mut cancel = cancel;
    run_team_inner(graph, seed_inputs, None, fan_out_ceiling, &mut cancel, step)
}

/// Like [`run_team`], but with a **hard budget ceiling** (LOOP §4 cost roll-up as an *enforced*
/// ceiling, not just an accounted total). Once the rolled-up `total_cost` crosses `ceiling`, the Run
/// stops admitting new work: the task that crossed the ceiling still completes (its cost was already
/// committed), and every task after it is [`TaskState::Skipped`] with `budget_exhausted = true`. This
/// is the loophole-closing enforcement the audit flagged — cost was rolled up but never *checked*
/// against a Run ceiling.
pub fn run_team_budgeted<F>(
    graph: &TaskGraph,
    seed_inputs: &BTreeSet<String>,
    ceiling: Cost,
    step: F,
) -> Result<RunReport, GraphError>
where
    F: FnMut(&Task) -> StepReport,
{
    let mut never_cancel = || false;
    run_team_inner(
        graph,
        seed_inputs,
        Some(ceiling),
        1,
        &mut never_cancel,
        step,
    )
}

/// Like [`run_team`], but cancellable (LOOP §8 cancellation propagation). `cancel` is polled once
/// **before** each task; the first time it returns `true` the Run stops and every not-yet-run task
/// is [`TaskState::Cancelled`] — its `step` seam is never invoked. One shared `cancel` signal cancels
/// the whole team at any depth (the caller shares one token across every child role invocation).
pub fn run_team_cancellable<F, C>(
    graph: &TaskGraph,
    seed_inputs: &BTreeSet<String>,
    mut cancel: C,
    step: F,
) -> Result<RunReport, GraphError>
where
    F: FnMut(&Task) -> StepReport,
    C: FnMut() -> bool,
{
    run_team_inner(graph, seed_inputs, None, 1, &mut cancel, step)
}

/// The shared scheduling core behind [`run_team`], [`run_team_budgeted`], and
/// [`run_team_cancellable`]. Deterministic given the graph, the seam, the ceiling, and the cancel
/// predicate — so every guarantee is a property a test asserts on concrete inputs.
fn run_team_inner<F, C>(
    graph: &TaskGraph,
    seed_inputs: &BTreeSet<String>,
    ceiling: Option<Cost>,
    fan_out_ceiling: usize,
    cancel: &mut C,
    mut step: F,
) -> Result<RunReport, GraphError>
where
    F: FnMut(&Task) -> StepReport,
    C: FnMut() -> bool,
{
    // `topological_order` still runs first for its cycle/self-dep/dangling-dep validation, and its
    // result is kept as the RunReport's reproducible `order` field for reporting/debugging — but it no
    // longer drives scheduling below. With `fan_out_ceiling == 1` the wave loop admits tasks in this
    // exact sequence (both pick the deterministic "smallest ready id first" rule), so every existing
    // `run_team`/`run_team_budgeted`/`run_team_cancellable` caller sees byte-identical scheduling;
    // `fan_out_ceiling > 1` (via `run_team_fanout` and friends) is the real fan-out admission the audit
    // found unused — `TaskGraph::ready_wave` was previously only a read-only telemetry probe here.
    let order = graph.topological_order()?;

    let mut states: BTreeMap<TaskId, TaskState> = BTreeMap::new();
    let mut notes: BTreeMap<TaskId, String> = BTreeMap::new();
    // Outputs produced by each succeeded task, for downstream handoff validation.
    let mut produced: BTreeMap<TaskId, BTreeSet<String>> = BTreeMap::new();
    let mut total_cost = Cost::ZERO;
    let mut stopped: Option<StopCause> = None;
    let mut succeeded_so_far: BTreeSet<TaskId> = BTreeSet::new();
    let mut max_observed_wave_width: usize = 0;

    loop {
        if states.len() == graph.len() {
            break;
        }

        // 0. Run-level stop (budget crossed or cancelled during a prior wave): every task not yet
        //    given a terminal state is skipped/cancelled and the run ends.
        if let Some(cause) = stopped {
            let (state, note) = match cause {
                StopCause::Budget => (
                    TaskState::Skipped,
                    "skipped: run budget ceiling exhausted".to_string(),
                ),
                StopCause::Cancelled => (
                    TaskState::Cancelled,
                    "cancelled: run cancelled before this task".to_string(),
                ),
            };
            for id in &order {
                if states.contains_key(id) {
                    continue;
                }
                states.insert(id.clone(), state);
                notes.insert(id.clone(), note.clone());
            }
            break;
        }

        // 1. Wave admission (LOOP §3/§8): every not-yet-succeeded task whose dependencies are ALL
        //    succeeded, capped at `fan_out_ceiling`. Called uncapped (`usize::MAX`) and re-capped after
        //    excluding already-terminal tasks (failed/blocked/refused/skipped/cancelled) — a task that
        //    failed is not in `succeeded_so_far`, so `ready_wave`'s own internal cap would otherwise be
        //    consumed by re-offering that same dead task every tick, starving a genuinely runnable
        //    sibling that is independent of it.
        let wave: Vec<TaskId> = graph
            .ready_wave(&succeeded_so_far, usize::MAX)
            .into_iter()
            .filter(|id| !states.contains_key(id))
            .take(fan_out_ceiling)
            .collect();

        if wave.is_empty() {
            // Bulkhead (LOOP §4): nothing can make further progress, so every remaining task is
            // blocked by a dependency that did not (and now cannot) succeed. Blocking cascades
            // transitively: a task blocked here never enters `succeeded_so_far`, so anything
            // depending on it fails this same check on the next pass (there is no next pass — the
            // run ends here — but the invariant is what makes a single pass sufficient).
            for id in &order {
                if states.contains_key(id) {
                    continue;
                }
                let task = graph.get(id).expect("topo id present in graph");
                let failed_dep = task
                    .dependencies
                    .iter()
                    .find(|d| states.get(*d) != Some(&TaskState::Succeeded));
                let note = match failed_dep {
                    Some(dep) => format!(
                        "blocked: dependency '{}' did not succeed ({:?})",
                        dep,
                        states.get(dep).copied()
                    ),
                    None => "blocked: dependency did not succeed".to_string(),
                };
                states.insert(id.clone(), TaskState::Blocked);
                notes.insert(id.clone(), note);
            }
            break;
        }

        if wave.len() > max_observed_wave_width {
            max_observed_wave_width = wave.len();
        }

        // 2. Execute the admitted wave. Still a plain sequential `for task in wave` call into `step`
        //    (see the doc comment on `run_team_fanout`) — what changed is which tasks are admitted
        //    together, not concurrent dispatch.
        for id in &wave {
            if stopped.is_some() {
                // A sibling earlier in this same wave cancelled/exhausted the budget: leave the rest
                // of the wave for the run-level stop handling at the top of the outer loop, which
                // marks every not-yet-terminal task with the correct cause and note.
                break;
            }
            let task = graph.get(id).expect("ready_wave id present in graph");

            // Handoff validation: every required input must be provided by the seed context or by a
            // dependency's outputs. A missing input refuses the handoff (LOOP §4) — a per-task
            // refusal, not a run-level stop, so the rest of the wave still proceeds.
            let mut available: BTreeSet<String> = seed_inputs.clone();
            for dep in &task.dependencies {
                if let Some(outs) = produced.get(dep) {
                    available.extend(outs.iter().cloned());
                }
            }
            if let Err(refused) = validate_inputs(&task.role, id, &task.required_inputs, &available)
            {
                states.insert(id.clone(), TaskState::Refused);
                notes.insert(id.clone(), refused.to_string());
                continue;
            }

            // Cancellation (LOOP §8): polled before executing. The first true stops the whole team.
            if cancel() {
                stopped = Some(StopCause::Cancelled);
                states.insert(id.clone(), TaskState::Cancelled);
                notes.insert(id.clone(), "cancelled: run cancelled".to_string());
                break;
            }

            // Budget pre-check (LOOP §4): if we are *already* over the ceiling, do not start.
            if let Some(c) = ceiling {
                if !total_cost.within(c) {
                    stopped = Some(StopCause::Budget);
                    states.insert(id.clone(), TaskState::Skipped);
                    notes.insert(
                        id.clone(),
                        "skipped: run budget ceiling already exhausted".to_string(),
                    );
                    break;
                }
            }

            // Execute via the seam and roll the sub-agent cost up into the Run aggregate.
            let report = step(task);
            total_cost = total_cost.saturating_add(report.invocation.rolled_up_cost());
            match report.outcome {
                StepOutcome::Success => {
                    states.insert(id.clone(), TaskState::Succeeded);
                    produced.insert(id.clone(), task.outputs.clone());
                    succeeded_so_far.insert(id.clone());
                }
                StepOutcome::Failure(reason) => {
                    states.insert(id.clone(), TaskState::Failed);
                    notes.insert(id.clone(), format!("failed: {reason}"));
                }
            }

            // Budget post-check: the task that crossed the ceiling completes, then the Run pauses
            // (LOOP §4 hard ceiling: cross 100% -> pause, never silent continuation).
            if let Some(c) = ceiling {
                if !total_cost.within(c) {
                    stopped = Some(StopCause::Budget);
                }
            }
        }
    }

    Ok(RunReport {
        order,
        states,
        total_cost,
        notes,
        budget_exhausted: stopped == Some(StopCause::Budget),
        cancelled: stopped == Some(StopCause::Cancelled),
        max_observed_wave_width,
    })
}

/// A terminal-Run Learning Record (LOOP §10 / ADR-027 §13 flywheel). Emitted once on every terminal
/// Run — the durable, structured summary the Improvement Engine curates: what succeeded, what failed
/// and *why*, what was blocked/refused/skipped, and the rolled-up cost. Pure projection of a
/// [`RunReport`]; the flywheel's gating/curation happens downstream (Enterprise-Memory).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LearningRecord {
    pub succeeded: Vec<TaskId>,
    pub failed: Vec<TaskId>,
    pub blocked: Vec<TaskId>,
    pub refused: Vec<TaskId>,
    pub skipped: Vec<TaskId>,
    pub cancelled: Vec<TaskId>,
    /// Failure/refusal/blocker notes, keyed by task, verbatim from the run (never swallowed).
    pub notes: BTreeMap<TaskId, String>,
    pub total_cost: Cost,
    pub all_succeeded: bool,
    pub budget_exhausted: bool,
    pub was_cancelled: bool,
}

impl LearningRecord {
    /// Distil a terminal [`RunReport`] into a Learning Record (LOOP §10).
    pub fn from_run(report: &RunReport) -> Self {
        LearningRecord {
            succeeded: report.in_state(TaskState::Succeeded),
            failed: report.in_state(TaskState::Failed),
            blocked: report.in_state(TaskState::Blocked),
            refused: report.in_state(TaskState::Refused),
            skipped: report.in_state(TaskState::Skipped),
            cancelled: report.in_state(TaskState::Cancelled),
            notes: report.notes.clone(),
            total_cost: report.total_cost,
            all_succeeded: report.all_succeeded(),
            budget_exhausted: report.budget_exhausted,
            was_cancelled: report.cancelled,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn tid(s: &str) -> TaskId {
        TaskId::from(s)
    }

    /// A step that always succeeds with a fixed cost — the default happy-path seam.
    fn ok_step(cost: Cost) -> impl FnMut(&Task) -> StepReport {
        move |task: &Task| StepReport::success(AgentInvocation::leaf(task.role.clone(), cost))
    }

    /// Assert `order` is a valid topological order of `graph`: every dependency appears
    /// before the task that depends on it.
    fn assert_valid_topo(graph: &TaskGraph, order: &[TaskId]) {
        let pos: BTreeMap<&TaskId, usize> =
            order.iter().enumerate().map(|(i, id)| (id, i)).collect();
        assert_eq!(pos.len(), graph.len(), "order must list every task once");
        for id in order {
            let task = graph.get(id).unwrap();
            for dep in &task.dependencies {
                assert!(
                    pos[dep] < pos[id],
                    "dependency {dep} must precede dependent {id}"
                );
            }
        }
    }

    // ---- topological order ------------------------------------------------

    #[test]
    fn topological_order_is_correct_and_deterministic() {
        // architect -> planner -> coder -> reviewer, plus an independent tester.
        let mut g = TaskGraph::new();
        g.add_task(Task::new("reviewer", "reviewer").depends_on("coder"))
            .unwrap();
        g.add_task(Task::new("coder", "coder").depends_on("planner"))
            .unwrap();
        g.add_task(Task::new("planner", "planner").depends_on("architect"))
            .unwrap();
        g.add_task(Task::new("architect", "architect")).unwrap();
        g.add_task(Task::new("tester", "tester")).unwrap();

        let order = g.topological_order().unwrap();
        assert_valid_topo(&g, &order);
        // Deterministic tie-break by id: at the start both `architect` and `tester` are ready;
        // `architect` sorts first, and each unlock admits the next chain node before `tester`.
        assert_eq!(
            order,
            vec![
                tid("architect"),
                tid("planner"),
                tid("coder"),
                tid("reviewer"),
                tid("tester"),
            ]
        );
    }

    #[test]
    fn topological_order_handles_diamond() {
        // a -> {b, c} -> d.
        let mut g = TaskGraph::new();
        g.add_task(Task::new("a", "r")).unwrap();
        g.add_task(Task::new("b", "r").depends_on("a")).unwrap();
        g.add_task(Task::new("c", "r").depends_on("a")).unwrap();
        g.add_task(Task::new("d", "r").depends_on("b").depends_on("c"))
            .unwrap();

        let order = g.topological_order().unwrap();
        assert_valid_topo(&g, &order);
        assert_eq!(order.first(), Some(&tid("a")));
        assert_eq!(order.last(), Some(&tid("d")));
    }

    #[test]
    fn cycle_is_detected_and_rejected() {
        // a -> b -> c -> a.
        let mut g = TaskGraph::new();
        g.add_task(Task::new("a", "r").depends_on("c")).unwrap();
        g.add_task(Task::new("b", "r").depends_on("a")).unwrap();
        g.add_task(Task::new("c", "r").depends_on("b")).unwrap();

        match g.topological_order() {
            Err(GraphError::Cycle { involved }) => {
                assert_eq!(
                    involved,
                    vec![tid("a"), tid("b"), tid("c")],
                    "all three nodes are trapped in the cycle"
                );
            }
            other => panic!("expected a cycle error, got {other:?}"),
        }
    }

    #[test]
    fn self_dependency_is_rejected() {
        let mut g = TaskGraph::new();
        g.add_task(Task::new("a", "r").depends_on("a")).unwrap();
        assert_eq!(
            g.topological_order(),
            Err(GraphError::SelfDependency { id: tid("a") })
        );
    }

    #[test]
    fn dangling_dependency_is_rejected() {
        let mut g = TaskGraph::new();
        g.add_task(Task::new("a", "r").depends_on("ghost")).unwrap();
        assert_eq!(
            g.topological_order(),
            Err(GraphError::MissingDependency {
                task: tid("a"),
                missing: tid("ghost"),
            })
        );
    }

    #[test]
    fn duplicate_task_is_rejected() {
        let mut g = TaskGraph::new();
        g.add_task(Task::new("a", "r")).unwrap();
        assert_eq!(
            g.add_task(Task::new("a", "other")),
            Err(GraphError::DuplicateTask { id: tid("a") })
        );
    }

    // ---- handoff validation ----------------------------------------------

    #[test]
    fn handoff_missing_required_input_is_refused() {
        let handoff = HandoffContract::new("planner", "coder", "impl-task")
            .with_input("design_doc", "artifact://design/1");
        // Coder needs both the design doc and the acceptance criteria; only one is provided.
        let required: BTreeSet<String> = ["design_doc", "acceptance_criteria"]
            .iter()
            .map(|s| s.to_string())
            .collect();

        let err = handoff.validate(&required).unwrap_err();
        assert_eq!(err.to_role, RoleId::from("coder"));
        assert_eq!(err.task_id, tid("impl-task"));
        assert_eq!(err.missing_inputs, vec!["acceptance_criteria".to_string()]);
    }

    #[test]
    fn handoff_with_all_required_inputs_is_accepted() {
        let handoff = HandoffContract::new("planner", "coder", "impl-task")
            .with_input("design_doc", "artifact://design/1")
            .with_input("acceptance_criteria", "artifact://ac/1")
            .with_confidence(0.9)
            .with_open_question("is the legacy adapter in scope?");
        let required: BTreeSet<String> = ["design_doc", "acceptance_criteria"]
            .iter()
            .map(|s| s.to_string())
            .collect();

        assert!(handoff.validate(&required).is_ok());
        // Extra provided inputs beyond what's required are fine.
        let fewer: BTreeSet<String> = ["design_doc"].iter().map(|s| s.to_string()).collect();
        assert!(handoff.validate(&fewer).is_ok());
    }

    #[test]
    fn scheduler_refuses_task_whose_input_no_dependency_provides() {
        // planner (produces design_doc) -> coder (requires SPEC, which nobody produces).
        // coder is refused; reviewer, which depends on coder, is blocked by the cascade.
        let mut g = TaskGraph::new();
        g.add_task(Task::new("planner", "planner").produces("design_doc"))
            .unwrap();
        g.add_task(
            Task::new("coder", "coder")
                .depends_on("planner")
                .requires("spec"),
        )
        .unwrap();
        g.add_task(Task::new("reviewer", "reviewer").depends_on("coder"))
            .unwrap();

        let report = run_team(&g, &BTreeSet::new(), ok_step(Cost::new(10, 0, 0, 0))).unwrap();
        assert_eq!(report.state_of(&tid("planner")), Some(TaskState::Succeeded));
        assert_eq!(report.state_of(&tid("coder")), Some(TaskState::Refused));
        assert_eq!(report.state_of(&tid("reviewer")), Some(TaskState::Blocked));
        // Only the planner ran, so only its cost is billed.
        assert_eq!(report.total_cost, Cost::new(10, 0, 0, 0));
    }

    #[test]
    fn scheduler_accepts_input_provided_by_dependency_output() {
        let mut g = TaskGraph::new();
        g.add_task(Task::new("planner", "planner").produces("spec"))
            .unwrap();
        g.add_task(
            Task::new("coder", "coder")
                .depends_on("planner")
                .requires("spec"),
        )
        .unwrap();

        let report = run_team(&g, &BTreeSet::new(), ok_step(Cost::new(5, 0, 0, 0))).unwrap();
        assert_eq!(report.state_of(&tid("coder")), Some(TaskState::Succeeded));
        assert!(report.all_succeeded());
    }

    #[test]
    fn scheduler_accepts_input_from_seed_context() {
        // A root task can require an input satisfied by the run's initial context (the goal),
        // not only by an upstream task.
        let mut g = TaskGraph::new();
        g.add_task(Task::new("architect", "architect").requires("goal"))
            .unwrap();
        let seed: BTreeSet<String> = ["goal"].iter().map(|s| s.to_string()).collect();

        let report = run_team(&g, &seed, ok_step(Cost::ZERO)).unwrap();
        assert_eq!(
            report.state_of(&tid("architect")),
            Some(TaskState::Succeeded)
        );
    }

    // ---- cost roll-up -----------------------------------------------------

    #[test]
    fn cost_rolls_up_through_the_invocation_tree() {
        // Architect(100) -> Planner(50) -> [Coder(200), Coder2(150)].
        let tree = AgentInvocation::leaf("architect", Cost::new(100, 1, 10, 1_000)).with_child(
            AgentInvocation::leaf("planner", Cost::new(50, 1, 5, 500))
                .with_child(AgentInvocation::leaf("coder", Cost::new(200, 3, 40, 4_000)))
                .with_child(AgentInvocation::leaf(
                    "coder-2",
                    Cost::new(150, 2, 30, 3_000),
                )),
        );

        let rolled = tree.rolled_up_cost();
        assert_eq!(rolled.tokens, 500); // 100 + 50 + 200 + 150
        assert_eq!(rolled.tool_calls, 7); // 1 + 1 + 3 + 2
        assert_eq!(rolled.wall_time_ms, 85); // 10 + 5 + 40 + 30
        assert_eq!(rolled.dollars_micros, 8_500); // 1000 + 500 + 4000 + 3000
        assert_eq!(tree.descendant_count(), 3);
        // A leaf's roll-up is just its own cost.
        assert_eq!(
            AgentInvocation::leaf("x", Cost::new(7, 0, 0, 0)).rolled_up_cost(),
            Cost::new(7, 0, 0, 0)
        );
    }

    #[test]
    fn run_total_cost_is_the_sum_across_executed_tasks() {
        // Two independent tasks; each spawns a sub-agent so the roll-up is exercised per task.
        let mut g = TaskGraph::new();
        g.add_task(Task::new("a", "coder")).unwrap();
        g.add_task(Task::new("b", "coder")).unwrap();

        let report = run_team(&g, &BTreeSet::new(), |task| {
            let inv = AgentInvocation::leaf(task.role.clone(), Cost::new(100, 1, 0, 0))
                .with_child(AgentInvocation::leaf("sub", Cost::new(25, 1, 0, 0)));
            StepReport::success(inv)
        })
        .unwrap();

        // Each task: 100 + 25 = 125; two tasks => 250 tokens, 4 tool calls.
        assert_eq!(report.total_cost, Cost::new(250, 4, 0, 0));
    }

    #[test]
    fn cost_saturates_instead_of_overflowing() {
        let big = Cost::new(u64::MAX, u64::MAX, u64::MAX, u64::MAX);
        let sum = big.saturating_add(Cost::new(1, 1, 1, 1));
        assert_eq!(
            sum, big,
            "saturating add must not wrap the budget aggregate"
        );
    }

    #[test]
    fn cost_within_ceiling_check() {
        let ceiling = Cost::new(1_000, 10, 5_000, 10_000);
        assert!(Cost::new(1_000, 10, 5_000, 10_000).within(ceiling));
        assert!(Cost::new(500, 5, 100, 1).within(ceiling));
        assert!(!Cost::new(1_001, 0, 0, 0).within(ceiling));
    }

    // ---- depth cap --------------------------------------------------------

    #[test]
    fn depth_cap_is_enforced() {
        // Architect -> Planner -> Coder is depth 3, at the default cap.
        let ok = AgentInvocation::leaf("architect", Cost::ZERO).with_child(
            AgentInvocation::leaf("planner", Cost::ZERO)
                .with_child(AgentInvocation::leaf("coder", Cost::ZERO)),
        );
        assert_eq!(ok.depth(), 3);
        assert!(ok.validate_depth(DEFAULT_MAX_DEPTH).is_ok());

        // One level deeper (a Coder spawning its own sub-agent) breaches the cap.
        let too_deep = AgentInvocation::leaf("architect", Cost::ZERO).with_child(
            AgentInvocation::leaf("planner", Cost::ZERO).with_child(
                AgentInvocation::leaf("coder", Cost::ZERO)
                    .with_child(AgentInvocation::leaf("rogue", Cost::ZERO)),
            ),
        );
        assert_eq!(too_deep.depth(), 4);
        assert_eq!(
            too_deep.validate_depth(DEFAULT_MAX_DEPTH),
            Err(DepthCapExceeded {
                max: DEFAULT_MAX_DEPTH,
                actual: 4
            })
        );
    }

    // ---- failure isolation ------------------------------------------------

    #[test]
    fn failed_task_blocks_only_its_dependents() {
        // Chain a -> b -> c (a fails), plus an independent d.
        let mut g = TaskGraph::new();
        g.add_task(Task::new("a", "coder")).unwrap();
        g.add_task(Task::new("b", "coder").depends_on("a")).unwrap();
        g.add_task(Task::new("c", "coder").depends_on("b")).unwrap();
        g.add_task(Task::new("d", "coder")).unwrap();

        let report = run_team(&g, &BTreeSet::new(), |task| {
            let inv = AgentInvocation::leaf(task.role.clone(), Cost::new(10, 1, 0, 0));
            if task.id == tid("a") {
                StepReport::failure(inv, "compile error")
            } else {
                StepReport::success(inv)
            }
        })
        .unwrap();

        assert_eq!(report.state_of(&tid("a")), Some(TaskState::Failed));
        assert_eq!(report.state_of(&tid("b")), Some(TaskState::Blocked));
        assert_eq!(report.state_of(&tid("c")), Some(TaskState::Blocked));
        // The independent branch is untouched by a's failure (bulkhead).
        assert_eq!(report.state_of(&tid("d")), Some(TaskState::Succeeded));

        assert_eq!(
            report.in_state(TaskState::Blocked),
            vec![tid("b"), tid("c")]
        );
        // Only a and d actually executed: 10 + 10 tokens, 2 tool calls.
        assert_eq!(report.total_cost, Cost::new(20, 2, 0, 0));
        // The failure reason is surfaced, not swallowed.
        assert!(report.notes[&tid("a")].contains("compile error"));
    }

    #[test]
    fn sibling_branch_completes_when_a_parallel_task_fails() {
        // root -> {left, right}; left fails, right and its child succeed. (LOOP acceptance #5.)
        let mut g = TaskGraph::new();
        g.add_task(Task::new("root", "planner")).unwrap();
        g.add_task(Task::new("left", "coder").depends_on("root"))
            .unwrap();
        g.add_task(Task::new("right", "coder").depends_on("root"))
            .unwrap();
        g.add_task(Task::new("right-child", "coder").depends_on("right"))
            .unwrap();

        let report = run_team(&g, &BTreeSet::new(), |task| {
            let inv = AgentInvocation::leaf(task.role.clone(), Cost::ZERO);
            if task.id == tid("left") {
                StepReport::failure(inv, "timeout")
            } else {
                StepReport::success(inv)
            }
        })
        .unwrap();

        assert_eq!(report.state_of(&tid("left")), Some(TaskState::Failed));
        assert_eq!(report.state_of(&tid("right")), Some(TaskState::Succeeded));
        assert_eq!(
            report.state_of(&tid("right-child")),
            Some(TaskState::Succeeded)
        );
    }

    #[test]
    fn empty_graph_runs_cleanly() {
        let g = TaskGraph::new();
        let report = run_team(&g, &BTreeSet::new(), ok_step(Cost::ZERO)).unwrap();
        assert!(report.order.is_empty());
        assert_eq!(report.total_cost, Cost::ZERO);
        assert!(!report.all_succeeded()); // vacuously: no tasks means nothing succeeded
    }

    #[test]
    fn unschedulable_graph_never_calls_step() {
        let mut g = TaskGraph::new();
        g.add_task(Task::new("a", "r").depends_on("b")).unwrap();
        g.add_task(Task::new("b", "r").depends_on("a")).unwrap();

        let mut calls = 0;
        let result = run_team(&g, &BTreeSet::new(), |task| {
            calls += 1;
            StepReport::success(AgentInvocation::leaf(task.role.clone(), Cost::ZERO))
        });
        assert!(matches!(result, Err(GraphError::Cycle { .. })));
        assert_eq!(calls, 0, "a non-DAG must be rejected before any task runs");
    }

    // ---- roles & team -----------------------------------------------------

    #[test]
    fn role_capabilities_are_least_privilege() {
        let coder = Role::new("coder", ModelTier::Medium, ["edit_code", "run_tests"]);
        assert!(coder.has_capability("edit_code"));
        assert!(coder.has_capability("run_tests"));
        assert!(!coder.has_capability("deploy")); // not granted => not held
        assert_eq!(coder.model_tier, ModelTier::Medium);
    }

    #[test]
    fn team_registry_lookups() {
        let mut team = Team::new();
        assert!(team.is_empty());
        team.add_role(Role::new(
            "architect",
            ModelTier::Complex,
            ["design", "approve"],
        ));
        team.add_role(Role::new("coder", ModelTier::Medium, ["edit_code"]));

        assert_eq!(team.len(), 2);
        assert!(team.contains(&RoleId::from("architect")));
        assert!(team.role_has_capability(&RoleId::from("architect"), "approve"));
        assert!(!team.role_has_capability(&RoleId::from("coder"), "approve"));
        assert!(!team.role_has_capability(&RoleId::from("ghost"), "anything"));
        assert_eq!(
            team.get(&RoleId::from("coder")).unwrap().model_tier,
            ModelTier::Medium
        );
    }

    #[test]
    fn handoff_contract_serde_roundtrip() {
        let h = HandoffContract::new("planner", "coder", "t1")
            .with_input("spec", "artifact://1")
            .with_confidence(0.75)
            .with_open_question("edge case?")
            .with_cost_used(Cost::new(1_234, 5, 60, 2_000))
            .with_acceptance_criterion("compiles")
            .with_acceptance_criterion("tests pass");
        let json = serde_json::to_string(&h).unwrap();
        let back: HandoffContract = serde_json::from_str(&json).unwrap();
        assert_eq!(h, back);
        // The completeness fields survive the round trip (not just the legacy ones).
        assert_eq!(back.cost_used, Cost::new(1_234, 5, 60, 2_000));
        assert!(back.acceptance_criteria.contains("compiles"));
    }

    // ---- handoff completeness: cost_used + acceptance criteria ------------

    #[test]
    fn handoff_missing_acceptance_criterion_is_flagged() {
        // The receiving task requires two acceptance criteria; the handoff certifies only one.
        let handoff =
            HandoffContract::new("planner", "coder", "impl").with_acceptance_criterion("compiles");
        let required: BTreeSet<String> = ["compiles", "passes-sast"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let missing = handoff.missing_acceptance_criteria(&required);
        assert_eq!(missing, vec!["passes-sast".to_string()]);

        // A complete handoff carries every criterion -> nothing missing.
        let complete = handoff.with_acceptance_criterion("passes-sast");
        assert!(complete.missing_acceptance_criteria(&required).is_empty());
    }

    #[test]
    fn task_carries_acceptance_criteria() {
        let t = Task::new("impl", "coder")
            .accepts("compiles")
            .accepts("behaviour-preserving");
        assert!(t.acceptance_criteria.contains("compiles"));
        assert!(t.acceptance_criteria.contains("behaviour-preserving"));
    }

    // ---- fan-out ready-wave admission (LOOP §3/§8) -----------------------

    #[test]
    fn ready_wave_admits_the_correct_batch_and_respects_the_fan_out_ceiling() {
        // Diamond a -> {b, c} -> d.
        let mut g = TaskGraph::new();
        g.add_task(Task::new("a", "r")).unwrap();
        g.add_task(Task::new("b", "r").depends_on("a")).unwrap();
        g.add_task(Task::new("c", "r").depends_on("a")).unwrap();
        g.add_task(Task::new("d", "r").depends_on("b").depends_on("c"))
            .unwrap();

        // Nothing done yet: only a is runnable.
        let none: BTreeSet<TaskId> = BTreeSet::new();
        assert_eq!(g.ready_wave(&none, 10), vec![tid("a")]);

        // a done: b and c are the wave (both parallelisable).
        let done_a: BTreeSet<TaskId> = [tid("a")].into_iter().collect();
        assert_eq!(g.ready_wave(&done_a, 10), vec![tid("b"), tid("c")]);
        // Fan-out ceiling of 1 admits only the first (deterministic id order).
        assert_eq!(g.ready_wave(&done_a, 1), vec![tid("b")]);
        // A ceiling of 0 admits nothing.
        assert!(g.ready_wave(&done_a, 0).is_empty());

        // d is not admitted until BOTH its deps (b and c) are done: with a+c done, only b is ready
        // (d still waits on b); d appears only once b and c are both complete.
        let done_ac: BTreeSet<TaskId> = [tid("a"), tid("c")].into_iter().collect();
        assert_eq!(g.ready_wave(&done_ac, 10), vec![tid("b")]);
        let done_abc: BTreeSet<TaskId> = [tid("a"), tid("b"), tid("c")].into_iter().collect();
        assert_eq!(g.ready_wave(&done_abc, 10), vec![tid("d")]);
    }

    /// GAP-AUDIT loop-teams-longhorizon: "the Team scheduler processes exactly one ready task at a
    /// time, despite having a complete, tested fan-out/parallel-admission primitive
    /// (`ElasticFanoutPolicy`) sitting unused one function away" — this proves `run_team_fanout` is the
    /// real consumer that closes it: three genuinely independent tasks are admitted into ONE wave when
    /// `fan_out_ceiling` allows it (`max_observed_wave_width == 3`, and the step seam observes all
    /// three as already-admitted in the same tick via the shared counter), never serialized down to a
    /// wave of one the way the pre-fix scheduler always did.
    #[test]
    fn run_team_fanout_admits_independent_siblings_into_the_same_wave() {
        // root -> {a, b, c}: three siblings with no edges between them.
        let mut g = TaskGraph::new();
        g.add_task(Task::new("root", "planner")).unwrap();
        for sib in ["a", "b", "c"] {
            g.add_task(Task::new(sib, "coder").depends_on("root"))
                .unwrap();
        }

        // A ceiling of 1 (== run_team's default admission width) must still serialize the siblings:
        // the widest wave ever admitted is 1, even though all three are mutually independent.
        let sequential = run_team_fanout(&g, &BTreeSet::new(), 1, ok_step(Cost::ZERO)).unwrap();
        assert!(sequential.all_succeeded());
        assert_eq!(
            sequential.max_observed_wave_width, 1,
            "fan_out_ceiling=1 must still admit siblings one at a time"
        );

        // A ceiling wide enough to cover all three siblings (as
        // `ainxt_planner::qos::ElasticFanoutPolicy::admit` would compute from live fleet capacity)
        // admits them together in one wave — the observable scheduling-width difference this gap
        // closes.
        let parallel = run_team_fanout(&g, &BTreeSet::new(), 10, ok_step(Cost::ZERO)).unwrap();
        assert!(parallel.all_succeeded());
        assert_eq!(
            parallel.max_observed_wave_width, 3,
            "fan_out_ceiling=10 must admit all 3 independent siblings into the same wave"
        );

        // Both runs reach the identical terminal outcome — the fix changes scheduling width, never
        // correctness (same discipline the served-Program fan-out fix (r17) proved).
        assert_eq!(sequential.states, parallel.states);
        assert_eq!(sequential.total_cost, parallel.total_cost);
    }

    /// A failed sibling must never starve an independent sibling's admission — the exact bug the first
    /// draft of the wave-based rewrite hit: `TaskGraph::ready_wave`'s own internal cap can be consumed
    /// by re-offering an already-failed (but not-yet-`succeeded`) task every tick, so the caller must
    /// exclude terminal tasks *before* applying the fan-out ceiling, not after.
    #[test]
    fn run_team_fanout_failed_sibling_does_not_starve_an_independent_sibling() {
        let mut g = TaskGraph::new();
        g.add_task(Task::new("root", "planner")).unwrap();
        g.add_task(Task::new("bad", "coder").depends_on("root"))
            .unwrap();
        g.add_task(Task::new("good", "coder").depends_on("root"))
            .unwrap();

        let report = run_team_fanout(&g, &BTreeSet::new(), 1, |task| {
            let inv = AgentInvocation::leaf(task.role.clone(), Cost::ZERO);
            if task.id == tid("bad") {
                StepReport::failure(inv, "boom")
            } else {
                StepReport::success(inv)
            }
        })
        .unwrap();

        assert_eq!(report.state_of(&tid("bad")), Some(TaskState::Failed));
        assert_eq!(report.state_of(&tid("good")), Some(TaskState::Succeeded));
    }

    /// [`run_team_fanout_cancellable`] with a wide ceiling: cancellation is still a first-class,
    /// immediate stop (LOOP §8) — a wave in flight is not preempted mid-task, but no further task
    /// (in this wave or any later one) ever reaches the `step` seam once `cancel` returns true.
    #[test]
    fn run_team_fanout_cancellable_stops_the_whole_team() {
        let mut g = TaskGraph::new();
        g.add_task(Task::new("root", "planner")).unwrap();
        for sib in ["a", "b", "c"] {
            g.add_task(Task::new(sib, "coder").depends_on("root"))
                .unwrap();
        }

        let calls = std::cell::RefCell::new(0usize);
        let report = run_team_fanout_cancellable(
            &g,
            &BTreeSet::new(),
            10,
            || true,
            |task| {
                *calls.borrow_mut() += 1;
                StepReport::success(AgentInvocation::leaf(task.role.clone(), Cost::ZERO))
            },
        )
        .unwrap();

        // `root` is admitted in the first wave (ceiling covers it alone) and is cancelled before its
        // step seam runs; nothing downstream is ever admitted at all.
        assert!(report.cancelled);
        assert_eq!(
            *calls.borrow(),
            0,
            "step must never be invoked once cancel() is true"
        );
        assert_eq!(report.state_of(&tid("root")), Some(TaskState::Cancelled));
        for sib in ["a", "b", "c"] {
            assert_eq!(report.state_of(&tid(sib)), Some(TaskState::Cancelled));
        }
    }

    // ---- budget ceiling enforcement (LOOP §4) ----------------------------

    #[test]
    fn budget_ceiling_stops_the_run_after_the_crossing_task() {
        // Three independent tasks, each 100 tokens; ceiling 150 tokens (others unbounded).
        let mut g = TaskGraph::new();
        g.add_task(Task::new("a", "coder")).unwrap();
        g.add_task(Task::new("b", "coder")).unwrap();
        g.add_task(Task::new("c", "coder")).unwrap();
        let ceiling = Cost::new(150, u64::MAX, u64::MAX, u64::MAX);

        let mut calls: Vec<String> = Vec::new();
        let report = run_team_budgeted(&g, &BTreeSet::new(), ceiling, |task| {
            calls.push(task.id.to_string());
            StepReport::success(AgentInvocation::leaf(
                task.role.clone(),
                Cost::new(100, 0, 0, 0),
            ))
        })
        .unwrap();

        // a runs (total 100, within), b runs (total 200, crosses) -> c is skipped, never executed.
        assert_eq!(calls, vec!["a".to_string(), "b".to_string()]);
        assert_eq!(report.state_of(&tid("a")), Some(TaskState::Succeeded));
        assert_eq!(report.state_of(&tid("b")), Some(TaskState::Succeeded));
        assert_eq!(report.state_of(&tid("c")), Some(TaskState::Skipped));
        assert!(report.budget_exhausted);
        assert!(!report.cancelled);
        assert_eq!(report.total_cost, Cost::new(200, 0, 0, 0));
    }

    #[test]
    fn a_run_within_budget_completes_normally() {
        let mut g = TaskGraph::new();
        g.add_task(Task::new("a", "coder")).unwrap();
        g.add_task(Task::new("b", "coder")).unwrap();
        let ceiling = Cost::new(1_000, u64::MAX, u64::MAX, u64::MAX);
        let report = run_team_budgeted(
            &g,
            &BTreeSet::new(),
            ceiling,
            ok_step(Cost::new(100, 0, 0, 0)),
        )
        .unwrap();
        assert!(report.all_succeeded());
        assert!(!report.budget_exhausted);
    }

    // ---- cancellation propagation (LOOP §8) ------------------------------

    #[test]
    fn cancellation_stops_the_whole_team_and_skips_the_step_seam() {
        // Chain a -> b -> c. Cancel fires on the SECOND poll (before b), so only a runs.
        let mut g = TaskGraph::new();
        g.add_task(Task::new("a", "coder")).unwrap();
        g.add_task(Task::new("b", "coder").depends_on("a")).unwrap();
        g.add_task(Task::new("c", "coder").depends_on("b")).unwrap();

        let mut polls = 0u32;
        let cancel = || {
            polls += 1;
            polls >= 2 // false for a, true from b onward
        };

        let mut executed: Vec<String> = Vec::new();
        let report = run_team_cancellable(&g, &BTreeSet::new(), cancel, |task| {
            executed.push(task.id.to_string());
            StepReport::success(AgentInvocation::leaf(
                task.role.clone(),
                Cost::new(1, 0, 0, 0),
            ))
        })
        .unwrap();

        assert_eq!(
            executed,
            vec!["a".to_string()],
            "only a executed before cancel"
        );
        assert_eq!(report.state_of(&tid("a")), Some(TaskState::Succeeded));
        assert_eq!(report.state_of(&tid("b")), Some(TaskState::Cancelled));
        assert_eq!(report.state_of(&tid("c")), Some(TaskState::Cancelled));
        assert!(report.cancelled);
        assert!(!report.budget_exhausted);
    }

    // ---- learning record (LOOP §10) --------------------------------------

    #[test]
    fn learning_record_distils_a_terminal_run() {
        // a fails; b (dependent) blocks; c (independent) succeeds.
        let mut g = TaskGraph::new();
        g.add_task(Task::new("a", "coder")).unwrap();
        g.add_task(Task::new("b", "coder").depends_on("a")).unwrap();
        g.add_task(Task::new("c", "coder")).unwrap();

        let report = run_team(&g, &BTreeSet::new(), |task| {
            let inv = AgentInvocation::leaf(task.role.clone(), Cost::new(10, 1, 0, 0));
            if task.id == tid("a") {
                StepReport::failure(inv, "compile error")
            } else {
                StepReport::success(inv)
            }
        })
        .unwrap();

        let rec = LearningRecord::from_run(&report);
        assert_eq!(rec.succeeded, vec![tid("c")]);
        assert_eq!(rec.failed, vec![tid("a")]);
        assert_eq!(rec.blocked, vec![tid("b")]);
        assert!(!rec.all_succeeded);
        assert!(!rec.budget_exhausted && !rec.was_cancelled);
        // The failure reason is carried into the flywheel record, not lost.
        assert!(rec.notes[&tid("a")].contains("compile error"));
        // Only a and c executed: 20 tokens billed.
        assert_eq!(rec.total_cost, Cost::new(20, 2, 0, 0));
    }
}
