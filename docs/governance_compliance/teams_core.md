# teams_core

The `teams_core` module is the pure, deterministic kernel of the runtime's multi-agent team orchestration. It lives in `crates/ainxt-teams/src/lib.rs` and owns the invariants that make long-horizon agent programs safe to schedule, test, and audit: task-graph validation, deterministic topological scheduling, structured role-to-role handoffs, sub-agent cost roll-up, hierarchy depth caps, hard budget ceilings, cancellation propagation, and failure bulkheads. The crate deliberately performs no I/O, spawns no threads, and calls no model; every LLM interaction is injected through the `step` closure. This purity makes every guarantee a unit-testable property rather than an operational hope.

---

## Architecture

```mermaid
flowchart TB
    subgraph "teams_core (pure kernel)"
        TG[TaskGraph]
        TC[Task / Role / Team]
        HC[HandoffContract]
        AI[AgentInvocation]
        C[Cost]
        RT[run_team_inner]
        LR[LearningRecord]
    end

    subgraph "Injected seams (caller provides)"
        STEP[step: Task -> StepReport]
        CANCEL["cancel: () -> bool"]
    end

    subgraph "Upstream planners & runtime"
        PLAN[planner / program_exec]
        QOS[ainxt_planner::qos::ElasticFanoutPolicy]
        TIER[teams_tiers]
        FLY[teams_flywheel]
    end

    PLAN -->|builds| TG
    QOS -->|fan_out_ceiling| RT
    TG -->|topological_order / ready_wave| RT
    TC -->|role capabilities| RT
    HC -->|validate inputs| RT
    STEP -->|StepReport| RT
    CANCEL -->|stop cause| RT
    AI -->|rolled_up_cost| C
    RT -->|RunReport| LR
    RT -->|RunReport| TIER
    LR -->|LearningRecord| FLY
```

`teams_core` sits at the bottom of the `teams` module hierarchy. It defines the data structures and scheduling primitives that `teams_tiers` (three-tier critic/judge loops) and `teams_flywheel` (post-run learning and role tuning) build on. The live runtime in `pipeline_runtime` (`ainxt-runtimed/src/program_exec.rs`) calls into tiered and fan-out wrappers rather than into the raw scheduler directly, but those wrappers share the same `run_team_inner` engine byte-for-byte.

---

## Core Components

### Identifiers

- **`RoleId`** — Stable string identity of a role within a team (e.g. `"architect"`).
- **`TaskId`** — Stable string identity of a task across replans.

Both are transparent newtypes with `From<&str>`, `From<String>`, `Display`, and total ordering so that deterministic tie-breaking is built in.

### Cost

- **`Cost`** — Exact, integer resource accounting: `tokens`, `tool_calls`, `wall_time_ms`, and `dollars_micros` (1 USD = 1,000,000 micro-dollars). Uses saturating arithmetic so aggregates can never wrap silently. Provides `within(ceiling)` for budget-gate checks.

### AgentInvocation

- **`AgentInvocation`** — One node in the sub-agent call tree. Carries `role`, `own_cost`, and `children`.
  - `rolled_up_cost()` sums the invocation and every descendant using saturating addition.
  - `depth()` measures the deepest chain.
  - `validate_depth(max)` enforces the hard hierarchy depth cap (default [`DEFAULT_MAX_DEPTH`] = 3).

This closes the budget-escape loophole where spawning many sub-agents would bypass a per-role ceiling: the Run budget is checked against the rolled-up tree total, not a per-role slice.

### Role & Team

- **`Role`** — A team identity with a `RoleId`, a `BTreeSet<String>` of capabilities, and a `ModelTier` (re-exported from `ainxt-types`).
- **`Team`** — Registry of roles. Provides least-privilege lookups and `all_capabilities()`, the team-wide authority envelope that per-task OBO delegations narrow from.

See [security_config_identity.md](../core_infrastructure/security_config_identity.md) for the `Principal` and identity primitives that roles ultimately resolve against.

### HandoffContract

- **`HandoffContract`** — Structured handoff between two roles. Never free text. Fields include:
  - `from_role`, `to_role`, `task_id`
  - `provided`: input name → artifact reference
  - `confidence`: producer self-estimate
  - `open_questions`: ambiguities the receiver must resolve explicitly
  - `cost_used`: running cost carried through the handoff
  - `acceptance_criteria`: definition of "done" inherited by the receiver

`validate(required)` returns `HandoffRefused` if any required input is missing. `missing_acceptance_criteria(required)` flags undefined acceptance criteria before work proceeds.

### Task & TaskGraph

- **`Task`** — One node in the agent-authored plan. Fields include `id`, `role`, `description`, `required_inputs`, `outputs`, `dependencies`, `budget`, and `acceptance_criteria`.
- **`TaskGraph`** — A dependency-ordered set of tasks.
  - `add_task` rejects duplicate ids.
  - `validate_edges` rejects self-dependencies and dangling dependencies.
  - `topological_order()` runs deterministic Kahn sorting (ties broken by `TaskId` order) and returns `GraphError::Cycle` if the graph is not a DAG.
  - `ready_wave(completed, fan_out_ceiling)` returns the next admissible batch of independent tasks.
  - `dependents_of(id)` supports bulkhead cascade analysis.

### Scheduler

The scheduler is implemented in `run_team_inner` and exposed through several convenience wrappers:

- `run_team` — sequential, one task per wave.
- `run_team_fanout` — admits a wave of independent tasks up to `fan_out_ceiling`.
- `run_team_budgeted` — hard Run budget ceiling.
- `run_team_cancellable` — cancellation seam.
- `run_team_fanout_budgeted`, `run_team_fanout_cancellable` — combinations.

Guarantees:

- **Handoff validity**: a task is refused if its required inputs are not provided by `seed_inputs` or succeeded-dependency outputs.
- **Failure isolation (bulkhead)**: a Failed or Refused task blocks only its transitive dependents; independent branches continue.
- **Cost roll-up**: `RunReport.total_cost` is the saturating sum of `rolled_up_cost()` over every executed task.
- **Hard budget ceiling**: once the rolled-up cost crosses `ceiling`, the crossing task completes and every remaining task is `Skipped`.
- **Cancellation propagation**: one shared `cancel` signal stops the whole team; tasks reached after cancel are `Cancelled` and never invoke `step`.

### RunReport & LearningRecord

- **`RunReport`** — Terminal result of a Run: topological `order`, per-task `states`, `total_cost`, human-readable `notes`, `budget_exhausted`, `cancelled`, and `max_observed_wave_width` telemetry.
- **`LearningRecord`** — Pure projection of a `RunReport` into the structured summary consumed by the improvement flywheel. Categorizes tasks by terminal state and preserves failure notes.

---

## Data Flow

```mermaid
sequenceDiagram
    participant Planner as Planner / Program
    participant TG as TaskGraph
    participant RT as run_team_inner
    participant Step as step seam
    participant Report as RunReport
    participant LR as LearningRecord

    Planner->>TG: add_task, validate_edges
    TG->>RT: topological_order / ready_wave
    loop until all tasks terminal or stopped
        RT->>RT: compute ready_wave(fan_out_ceiling)
        RT->>RT: validate_inputs(seed + dependency outputs)
        alt inputs missing
            RT->>Report: TaskState::Refused
        else inputs ok
            RT->>Step: invoke step(task)
            Step-->>RT: StepReport(invocation, outcome)
            RT->>RT: total_cost += invocation.rolled_up_cost()
            alt outcome Success
                RT->>Report: TaskState::Succeeded
            else outcome Failure
                RT->>Report: TaskState::Failed
            end
            alt budget crossed
                RT->>Report: stop cause = Budget
            else cancel true
                RT->>Report: stop cause = Cancelled
            end
        end
    end
    Report->>LR: LearningRecord::from_run
```

---

## Component Interactions

```mermaid
classDiagram
    class TaskGraph {
        +BTreeMap~TaskId,Task~ tasks
        +add_task(Task)
        +validate_edges()
        +topological_order()
        +ready_wave(completed, ceiling)
        +dependents_of(id)
    }
    class Task {
        +TaskId id
        +RoleId role
        +BTreeSet~String~ required_inputs
        +BTreeSet~String~ outputs
        +BTreeSet~TaskId~ dependencies
        +Cost budget
        +BTreeSet~String~ acceptance_criteria
    }
    class HandoffContract {
        +RoleId from_role
        +RoleId to_role
        +TaskId task_id
        +BTreeMap~String,String~ provided
        +BTreeSet~String~ acceptance_criteria
        +validate(required)
    }
    class AgentInvocation {
        +RoleId role
        +Cost own_cost
        +Vec~AgentInvocation~ children
        +rolled_up_cost()
        +depth()
        +validate_depth(max)
    }
    class Cost {
        +u64 tokens
        +u64 tool_calls
        +u64 wall_time_ms
        +u64 dollars_micros
        +saturating_add(other)
        +within(ceiling)
    }
    class Role {
        +RoleId id
        +BTreeSet~String~ capabilities
        +ModelTier model_tier
        +has_capability(cap)
    }
    class Team {
        +BTreeMap~RoleId,Role~ roles
        +add_role(Role)
        +role_has_capability(id, cap)
        +all_capabilities()
    }
    class RunReport {
        +Vec~TaskId~ order
        +BTreeMap~TaskId,TaskState~ states
        +Cost total_cost
        +BTreeMap~TaskId,String~ notes
        +bool budget_exhausted
        +bool cancelled
        +usize max_observed_wave_width
    }
    class LearningRecord {
        +Vec~TaskId~ succeeded/failed/blocked/refused/skipped/cancelled
        +BTreeMap~TaskId,String~ notes
        +Cost total_cost
    }

    TaskGraph "1" *-- "*" Task
    Task ..> HandoffContract : validated by
    AgentInvocation --> Cost : rolls up
    Role --> Team : registered in
    RunReport --> LearningRecord : distilled into
    TaskGraph --> RunReport : scheduled by
```

---

## Process Flows

### Building and validating a task graph

```mermaid
flowchart LR
    A[Planner emits Task nodes] --> B[TaskGraph::add_task]
    B --> C{duplicate id?}
    C -->|yes| D[GraphError::DuplicateTask]
    C -->|no| E[TaskGraph::validate_edges]
    E --> F{self-dep or dangling dep?}
    F -->|yes| G[GraphError::SelfDependency / MissingDependency]
    F -->|no| H[TaskGraph::topological_order]
    H --> I{contains cycle?}
    I -->|yes| J[GraphError::Cycle]
    I -->|no| K[deterministic order ready for scheduler]
```

### Running one wave

```mermaid
flowchart TD
    A[Compute ready_wave from succeeded tasks] --> B{wave empty?}
    B -->|yes| C[Mark remaining tasks Blocked and stop]
    B -->|no| D[For each task in wave]
    D --> E[Collect available inputs]
    E --> F{required ⊆ available?}
    F -->|no| G[TaskState::Refused]
    F -->|yes| H{cancelled?}
    H -->|yes| I[TaskState::Cancelled, stop]
    H -->|no| J{budget already exhausted?}
    J -->|yes| K[TaskState::Skipped, stop]
    J -->|no| L[Invoke step seam]
    L --> M[Receive StepReport]
    M --> N[total_cost += rolled_up_cost]
    N --> O{outcome}
    O -->|Success| P[TaskState::Succeeded, record outputs]
    O -->|Failure| Q[TaskState::Failed]
    N --> R{budget crossed?}
    R -->|yes| S[stop cause = Budget]
```

### Failure bulkhead

```mermaid
flowchart LR
    A[Task fails or is refused] --> B[Transitive dependents remain in ready_wave?]
    B -->|no, because deps not in succeeded| C[Dependents marked Blocked]
    D[Independent branches] --> E[Continue scheduling normally]
```

---

## Module Relationships

- **`teams_core`** is the pure foundation. It defines `TaskGraph`, `Role`, `HandoffContract`, `AgentInvocation`, `Cost`, and the scheduler.
- **`teams_tiers`** wraps the scheduler in a three-tier verification loop (executor, critic, judge) and adds `ThreeTierConfig` with `max_attempts_per_task`, `stuck_repeat_cap`, `max_judge_rounds`, and `fan_out_ceiling`. See [teams_tiers.md](teams_tiers.md).
- **`teams_flywheel`** consumes `LearningRecord` and produces `TaskPrior` and `RoleTuning` recommendations for the improvement engine. See [teams_flywheel.md](teams_flywheel.md).
- **`pipeline_runtime`** (`ainxt-runtimed/src/program_exec.rs`) drives served team runs using the fan-out/cancellable wrappers. See [pipeline_runtime.md](../pipeline_runtime/pipeline_runtime.md).
- **`ai_engine`** planners such as `ainxt-planner::qos::ElasticFanoutPolicy` compute the `fan_out_ceiling` fed into `run_team_fanout`. See [ai_engine.md](../ai_engine/ai_engine.md).
- **`core_infrastructure`** provides `ModelTier` (from `ainxt-types`) and the identity, security, and runtime config layers that roles and capabilities resolve against. See [core_infrastructure.md](../core_infrastructure/core_infrastructure.md).

---

## Key Design Decisions

1. **Pure core, injected seams** — No I/O, threads, or LLM calls inside `teams_core`. The `step` closure and `cancel` predicate are caller-provided seams.
2. **Deterministic scheduling** — Kahn topological sort and `ready_wave` both use `BTreeSet`/`BTreeMap` ordering, so the same graph always yields the same schedule.
3. **Structured handoffs** — Roles never exchange free text. Missing required inputs or acceptance criteria produce explicit `HandoffRefused` errors.
4. **Tree cost roll-up** — `AgentInvocation::rolled_up_cost` aggregates the entire sub-agent tree, closing the multi-sub-agent budget-escape loophole.
5. **Hard depth cap** — `AgentInvocation::validate_depth` rejects runaway agent-spawns-agent recursion at the kernel boundary.
6. **Bulkhead failure isolation** — Only transitive dependents of a failed/refused task are blocked; independent branches continue.
7. **Budget and cancellation as first-class stop causes** — Crossed ceilings and cancellation signals are recorded in `RunReport` and propagated to `LearningRecord`.

---

## References

- [teams_tiers.md](teams_tiers.md) — Three-tier critic/judge execution wrappers.
- [teams_flywheel.md](teams_flywheel.md) — Post-run learning and role tuning.
- [pipeline_runtime.md](../pipeline_runtime/pipeline_runtime.md) — Live runtime that drives served team runs.
- [ai_engine.md](../ai_engine/ai_engine.md) — Planners and fan-out policy.
- [core_infrastructure.md](../core_infrastructure/core_infrastructure.md) — Identity, security, and runtime configuration primitives.
- [security_config_identity.md](../core_infrastructure/security_config_identity.md) — `Principal` and identity types underlying role authorization.
