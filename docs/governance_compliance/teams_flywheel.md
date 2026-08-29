# teams_flywheel

## Brief Introduction

The `teams_flywheel` module (`crates/ainxt-teams/src/flywheel.rs`) is the **consumer side** of the hierarchical agent-team learning flywheel (LOOP §10 / ADR-027 §13). While the producer side — [`LearningRecord`](teams_core.md) — is emitted on every terminal team Run to capture what succeeded, what failed and *why*, this module reads batches of those accumulated records and distils them into three structured improvement artifacts:

1. **Eval-set generation** — every failed/blocked/refused task becomes a regression eval case so the *same* failure is caught automatically next time.
2. **Plan-template priors** — per-task success/failure counts yield a failure-rate prior that biases future task decomposition.
3. **Role-spec tuning** — per-role success rates yield a suggested model-tier bump for roles whose Runs fail too often.

The module is **pure and deterministic** — no clock, RNG, or I/O — so every curation rule is a unit-test property. The gating and curation of *which* signal to act on lives downstream in Enterprise-Memory; this crate produces the structured candidates it curates.

---

## Architecture

### Module Position

`teams_flywheel` is a submodule of the `teams` crate, which itself sits under the `governance_compliance` top-level domain. It has two sibling submodules:

| Sibling | File | Responsibility |
|---|---|---|
| [`teams_core`](teams_core.md) | `lib.rs` | Pure scheduler core: `Role`, `TaskGraph`, `HandoffContract`, `run_team`, `LearningRecord` (the flywheel's **producer**) |
| [`teams_tiers`](teams_tiers.md) | `tiers.rs` | 3-tier intelligence loop: tier-1 executor, tier-2 critic, tier-3 judge, self-heal, three-way verification gate |
| **`teams_flywheel`** (this module) | `flywheel.rs` | Downstream **consumer** curators that turn accumulated `LearningRecord`s into improvement signal |

### High-Level Architecture Diagram

```mermaid
graph TB
    subgraph "governance_compliance → teams"
        TC["teams_core<br/>(lib.rs)"]:::producer
        TT["teams_tiers<br/>(tiers.rs)"]:::tiers
        TF["teams_flywheel<br/>(flywheel.rs)"]:::consumer
    end

    subgraph "pipeline_runtime → runtime_engine"
        PE["program_exec.rs<br/>(ainxt-runtimed)"]:::runtime
    end

    subgraph "ai_engine → memory_management"
        MM["ImprovementEngine<br/>(ainxt-memory flywheel.rs)"]:::memory
    end

    subgraph "ai_engine → evaluation_testing"
        EV["Eval Pipeline<br/>(ainxt-eval)"]:::eval
    end

    TC -- "LearningRecord<br/>(producer)" --> TF
    TT -- "TeamRunReport.learning" --> TC
    PE -- "FlywheelCurationSweep<br/>.tick()" --> TF
    TF -- "EvalCase[]" --> EV
    TF -- "TaskPrior{}" --> PE
    TF -- "RoleTuning{} --> suggested_tier" --> PE

    classDef producer fill:#4a90d9,color:#fff,stroke:#2c5f8a
    classDef tiers fill:#e8a838,color:#fff,stroke:#b07d1a
    classDef consumer fill:#5cb85c,color:#fff,stroke:#3a7d3a
    classDef runtime fill:#9b59b6,color:#fff,stroke:#6c3483
    classDef memory fill:#e74c3c,color:#fff,stroke:#a82315
    classDef eval fill:#1abc9c,color:#fff,stroke:#117a65
```

### Dependency Graph

```mermaid
graph LR
    subgraph "ainxt-teams crate"
        flywheel["flywheel.rs<br/>(this module)"]
        lib["lib.rs<br/>(teams_core)"]
    end

    types["ainxt-types<br/>Tier (ModelTier)"]

    flywheel -- "LearningRecord, TaskId,<br/>RoleId, ModelTier, Cost" --> lib
    lib -- "pub use ainxt_types::Tier<br/>as ModelTier" --> types

    subgraph "ainxt-runtimed (downstream consumer)"
        pe["program_exec.rs"]
    end

    pe -- "FlywheelCurationSweep::tick()<br/>calls all 3 curators" --> flywheel
    pe -- "InMemoryLearningSink<br/>collects LearningRecord" --> lib
```

---

## Core Components

### EvalCase — Regression Eval-Set Generation

```rust
pub struct EvalCase {
    pub task: TaskId,
    pub failure_mode: FailureMode,
    pub observed: String,
}

pub enum FailureMode {
    Failed,    // task executed and failed (highest-value eval)
    Blocked,   // task blocked by upstream failure (dependency eval)
    Refused,   // task refused by policy/compliance/capability (guardrail eval)
}
```

**`generate_eval_cases(records: &[LearningRecord]) -> Vec<EvalCase>`**

Distils regression eval cases from a batch of terminal `LearningRecord`s. Every task in a `Failed`, `Blocked`, or `Refused` terminal state becomes a case, tagged with its failure mode and the verbatim note from the run (never swallowed). A run where everything succeeded contributes no cases.

**Deterministic order**: records in input order, then tasks in the record's stored order.

| Property | Guarantee |
|---|---|
| Completeness | Every non-succeeded task across all records becomes a case |
| Fidelity | The verbatim run note is carried — the eval case names *why* it failed |
| No false positives | A fully-succeeded run contributes zero cases |

### TaskPrior — Plan-Template Priors

```rust
pub struct TaskPrior {
    pub task: TaskId,
    pub runs: u32,
    pub successes: u32,
    pub failures: u32,
}

impl TaskPrior {
    pub fn failure_rate_bps(&self) -> u32  // 0..=10000, integer (no float)
    pub fn is_risky(&self) -> bool          // failure_rate_bps() > 5000
}
```

**`plan_template_priors(records: &[LearningRecord]) -> BTreeMap<TaskId, TaskPrior>`**

Aggregates per-task success/failure priors across a batch of `LearningRecord`s. A task counts one observation per record it appears in — as a success iff it is in that record's `succeeded` set, as a failure otherwise (failed / blocked / refused / skipped / cancelled).

**Design decisions**:
- Failure rate is in **basis points** (integer, 0–10000) so the prior is deterministic — no floating-point ambiguity.
- `is_risky()` flags a majority-failure task (>50% failure rate) for extra scrutiny the next time the planner emits it (a checkpoint, a smaller window).
- Returns a `BTreeMap` keyed by `TaskId` — sorted, deterministic.

### RoleTuning — Role-Spec Tuning

```rust
pub struct RoleTuning {
    pub role: RoleId,
    pub runs: u32,
    pub successes: u32,
    pub current_tier: ModelTier,
    pub suggested_tier: ModelTier,
}

impl RoleTuning {
    pub fn recommends_change(&self) -> bool  // suggested_tier != current_tier
}
```

**`role_spec_tuning(records, task_roles, role_tiers) -> BTreeMap<RoleId, RoleTuning>`**

Tunes role specs from accumulated outcomes. `task_roles` maps each task to the role that ran it; `role_tiers` gives each role's current model tier. A role whose tasks fail in the **majority** of observations earns a one-rung tier-bump recommendation.

**Model tier escalation ladder** (`Simple → Medium → Complex`, `Complex` is the ceiling):

```mermaid
graph LR
    S["Simple"] -->|bump| M["Medium"]
    M -->|bump| C["Complex"]
    C -->|"bump (ceiling)"| C
```

**Key invariants**:
- A role is only bumped when `failures * 2 > n` (strict majority failure).
- The recommendation **never auto-mutates** the role spec — a deployment reviews and applies it.
- Roles with no observations are omitted from the output.
- Unknown roles default to `ModelTier::Medium`.

---

## Data Flow

### The Complete Flywheel Cycle

```mermaid
sequenceDiagram
    participant Served as Served Team Run<br/>(TeamSurface)
    participant Tiers as 3-Tier Loop<br/>(teams_tiers)
    participant Core as Scheduler<br/>(teams_core)
    participant Sink as InMemoryLearningSink<br/>(ainxt-runtimed)
    participant Sweep as FlywheelCurationSweep<br/>(ainxt-runtimed)
    participant FW as teams_flywheel<br/>(this module)

    Served->>Tiers: run_team_3tier_verified_cancellable()
    Tiers->>Core: run_team_fanout_cancellable() per round
    Core-->>Tiers: RunReport (terminal states, notes, cost)
    Tiers-->>Served: TeamRunReport { learning: LearningRecord }

    Served->>Sink: sink.record(&report.learning)
    Note over Sink: Accumulates LearningRecords<br/>from every terminal Run

    loop Every 300s cadence
        Sweep->>Sink: records()
        Sink-->>Sweep: Vec<LearningRecord>
        Sweep->>FW: generate_eval_cases(&records)
        FW-->>Sweep: Vec<EvalCase>
        Sweep->>FW: plan_template_priors(&records)
        FW-->>Sweep: BTreeMap<TaskId, TaskPrior>
        Sweep->>FW: role_spec_tuning(&records, &task_roles, &role_tiers)
        FW-->>Sweep: BTreeMap<RoleId, RoleTuning>
        Sweep-->>Sweep: Store FlywheelSweepResult
    end
```

### LearningRecord → Curator Input Mapping

The `LearningRecord` (produced by [`teams_core`](teams_core.md)) carries six terminal-state vectors. Each curator reads a different projection:

```mermaid
graph TB
    subgraph LR["LearningRecord (teams_core)"]
        S["succeeded: Vec<TaskId>"]
        F["failed: Vec<TaskId>"]
        B["blocked: Vec<TaskId>"]
        R["refused: Vec<TaskId>"]
        SK["skipped: Vec<TaskId>"]
        CA["cancelled: Vec<TaskId>"]
        N["notes: BTreeMap<TaskId, String>"]
    end

    subgraph C1["generate_eval_cases"]
        EC["EvalCase { task, failure_mode, observed }"]
    end

    subgraph C2["plan_template_priors"]
        TP["TaskPrior { task, runs, successes, failures }"]
    end

    subgraph C3["role_spec_tuning"]
        RT["RoleTuning { role, runs, successes, current_tier, suggested_tier }"]
    end

    F --> EC
    B --> EC
    R --> EC
    N --> EC

    S --> TP
    F --> TP
    B --> TP
    R --> TP
    SK --> TP
    CA --> TP

    S --> RT
    F --> RT
    B --> RT
    R --> RT
    SK --> RT
    CA --> RT
```

---

## Component Interaction

### How the Curators Relate to the Broader System

```mermaid
graph TB
    subgraph "Producer Side (teams_core + teams_tiers)"
        TR["Terminal Team Run"]
        LR["LearningRecord"]
        TR --> LR
    end

    subgraph "Consumer Side (this module)"
        GEC["generate_eval_cases"]
        PTP["plan_template_priors"]
        RST["role_spec_tuning"]
        LR --> GEC
        LR --> PTP
        LR --> RST
    end

    subgraph "Downstream Destinations"
        EVAL["Eval Pipeline<br/>(evaluation_testing)"]
        PLANNER["Planner<br/>(planning_program_execution)"]
        WORKFORCE["Workforce Role Catalog<br/>(governance_compliance → workforce)"]
        MEM["Enterprise-Memory<br/>(memory_management)"]
    end

    GEC -- "EvalCase[]" --> EVAL
    PTP -- "TaskPrior{}" --> PLANNER
    RST -- "RoleTuning{}" --> WORKFORCE
    GEC -. "structured candidates" .-> MEM
    PTP -. "structured candidates" .-> MEM
    RST -. "structured candidates" .-> MEM
```

### Runtime Composition (ainxt-runtimed)

The `FlywheelCurationSweep` in `ainxt-runtimed`'s `program_exec.rs` is the composition-root entrypoint that wires this module to a live daemon cadence:

| Component | Role |
|---|---|
| `InMemoryLearningSink` | Collects `LearningRecord`s from every terminal team Run via `TeamSurface::with_learning_sink()` |
| `FlywheelCurationSweep` | Calls all three curators (`generate_eval_cases`, `plan_template_priors`, `role_spec_tuning`) on every tick over the sink's full accumulated history |
| `FlywheelSweepResult` | Holds the curated output: `eval_cases`, `template_priors`, `role_tuning`, `records_curated` |
| `spawn_flywheel_sweep()` | Spawns a `tokio::time::interval` loop (default 300s) that calls `tick()` automatically |
| `flywheel_role_maps_from_served_team()` | Derives the static `task_roles` / `role_tiers` maps from the canonical served team topology (`compose_served_team`) — never a hand-duplicated literal |

**Key design property**: A tick re-curates the sink's **full** accumulated history every time (never merely incremental), so a tick is always consistent with the sink's current record set.

---

## Process Flows

### Eval-Set Generation Flow

```mermaid
flowchart TD
    Start["Input: &[LearningRecord]"] --> Loop1{"For each record"}
    Loop1 -- yes --> Loop2{"For each failure mode<br/>(Failed, Blocked, Refused)"}
    Loop2 -- yes --> Loop3{"For each task in<br/>that mode's vector"}
    Loop3 -- yes --> Note{"Note exists for task?"}
    Note -- yes --> Push1["Push EvalCase {<br/>  task,<br/>  failure_mode,<br/>  observed: note<br/>}"]
    Note -- no --> Push2["Push EvalCase {<br/>  task,<br/>  failure_mode,<br/>  observed: '{mode:?} with no recorded note'<br/>}"]
    Push1 --> Loop3
    Push2 --> Loop3
    Loop3 -- no --> Loop2
    Loop2 -- no --> Loop1
    Loop1 -- no --> Return["Return Vec<EvalCase>"]
```

### Role-Spec Tuning Flow

```mermaid
flowchart TD
    Start["Input: records, task_roles, role_tiers"] --> Rollup["Roll task outcomes up to roles:<br/>for each task in succeeded → role.runs++, role.successes++<br/>for each task in failed/blocked/refused/skipped/cancelled → role.runs++, role.failures++"]
    Rollup --> Loop{"For each role with observations"}
    Loop -- yes --> Check{"failures * 2 > n?<br/>(majority failure)"}
    Check -- yes --> Bump["suggested_tier = bump(current_tier)"]
    Check -- no --> Keep["suggested_tier = current_tier"]
    Bump --> Emit["Emit RoleTuning"]
    Keep --> Emit
    Emit --> Loop
    Loop -- no --> Return["Return BTreeMap<RoleId, RoleTuning>"]
```

---

## Design Principles

### 1. Pure and Deterministic

No clock, RNG, or I/O. Every curation rule is a pure function of its inputs, so:
- The same batch of `LearningRecord`s always produces the same output.
- Every rule is a unit-test property that can be asserted on concrete inputs.
- The module can be tested exhaustively without a model, a database, or a network.

### 2. Producer/Consumer Separation

The flywheel is split across two modules:
- **Producer** ([`teams_core`](teams_core.md)): `LearningRecord::from_run()` distils a terminal `RunReport` into a structured summary. Emitted once on every terminal Run.
- **Consumer** (this module): three curators that read batches of records and emit improvement artifacts.

This separation means the producer has zero coupling to *what happens* with the records — it just emits them. The consumer has zero coupling to *how* records are produced — it just reads them.

### 3. Propose, Don't Mutate

`RoleTuning` produces a **suggestion** (`suggested_tier`), never an auto-applied mutation. A deployment reviews the recommendation before applying it to the role spec. This mirrors the broader system's "flywheel proposes, a human legislates" posture (see [`memory_management`](../ai_engine/memory_management.md)'s `ImprovementEngine`).

### 4. Integer Arithmetic Only

Failure rates are in basis points (0–10000), not floats. This keeps the prior deterministic across platforms and avoids floating-point comparison ambiguity in tests.

### 5. Verbatim Notes, Never Swallowed

Every `EvalCase` carries the verbatim run note (the error / refusal / blocker reason). The flywheel's core promise — "turn a production failure into a permanent test" — depends on the eval case naming *why* it failed, not just *that* it failed.

---

## Relationship to the Broader Flywheel

The system has **two flywheel implementations** that operate at different altitudes:

| Aspect | `teams_flywheel` (this module) | `memory_management` ImprovementEngine |
|---|---|---|
| **Altitude** | Team Run level (hierarchical agent teams) | Turn level (individual chat/runtime turns) |
| **Input** | `LearningRecord` (task-level terminal states) | `FeedbackEvent` (thumbs, corrections, edits, trajectories) |
| **Outputs** | Eval cases, task priors, role tuning | Prompt/retrieval/eval/OKI/fine-tune candidates |
| **Curation** | Pure deterministic curators | Rule + LLM-judge triage with human-review flags |
| **Gating** | Downstream in Enterprise-Memory | Per-destination independent gates (`DestinationGates`) |
| **Cadence** | `FlywheelCurationSweep` (300s interval) | On-demand `propose()` + `dispatch_gated()` |

Both share the same design philosophy: **the flywheel proposes, a human legislates**. Neither auto-mutates production state; both produce structured candidates that downstream gates review before acting.

---

## Key Types Reference

| Type | Module | Role |
|---|---|---|
| [`LearningRecord`](teams_core.md) | `teams_core` | Producer: terminal-Run structured summary |
| [`TaskId`](teams_core.md) | `teams_core` | Stable task identity (newtype over `String`) |
| [`RoleId`](teams_core.md) | `teams_core` | Stable role identity (newtype over `String`) |
| [`ModelTier`](teams_core.md) | `teams_core` (re-exported from `ainxt-types` as `Tier`) | Complexity tier: `Simple` / `Medium` / `Complex` |
| [`Cost`](teams_core.md) | `teams_core` | Resource cost (tokens, tool_calls, wall_time_ms, dollars_micros) |
| [`RunReport`](teams_core.md) | `teams_core` | Scheduler output: terminal states, notes, aggregate cost |
| [`TeamRunReport`](teams_tiers.md) | `teams_tiers` | 3-tier loop output: outcome, rounds, cost, `learning: LearningRecord` |
| `EvalCase` | **this module** | Consumer: regression eval case from a real failure |
| `TaskPrior` | **this module** | Consumer: per-task failure-rate prior |
| `RoleTuning` | **this module** | Consumer: per-role model-tier bump recommendation |
| `FlywheelCurationSweep` | `ainxt-runtimed` (`program_exec.rs`) | Composition root: cadence-driven curation over the learning sink |
| `InMemoryLearningSink` | `ainxt-runtimed` (`program_exec.rs`) | Collects `LearningRecord`s from terminal team Runs |

---

## Test Coverage

The module's tests (inline in `flywheel.rs`) prove four key properties:

1. **Eval cases are generated from failures with notes** — a failed task with a verbatim note becomes an `EvalCase` carrying that note.
2. **Eval cases are empty when everything succeeded** — a fully-succeeded run contributes zero cases.
3. **Plan priors accumulate success and failure rates** — a task that failed twice and succeeded once has `failure_rate_bps() == 6666` and `is_risky() == true`.
4. **Role tuning bumps a majority-failing role** — a coder role that fails 2 of 3 times earns a `Medium → Complex` bump; a reviewer role that succeeds every time is unchanged.

All tests use the same `LearningRecord` builder helper, ensuring the curators are exercised against realistic record shapes (not hand-crafted edge cases).
