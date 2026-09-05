# Pipeline Stages and Tools — Breaker

## Introduction

The **Breaker** (`pipeline_stages_and_tools_breaker`) is an optional, Tier-3-only differential and invariant oracle within the [pipeline orchestration](pipeline_orchestration.md) subsystem. It lives in `crates/ainxt-pipeline/src/breaker.rs` and provides a scoped escalation path for the highest-risk edits — typically critical-path modules or public-API breaks — by comparing the edited code's behavior against a reference implementation.

The Breaker is deliberately **not** a universal gate. It runs only when the preceding [classification and risk](pipeline_stages_and_tools_classification_and_risk.md) stage assigns a `RiskTier::HighRisk` verdict. For lower-risk edits, the Breaker is *not consulted*, and the absence of a result is reported honestly as "not run" rather than a false clean.

## Purpose and Core Functionality

The Breaker module serves three primary purposes:

1. **Differential Regression Oracle**: Detect behavioral divergences between a candidate edit and a trusted baseline/reference implementation.
2. **Invariant Checker**: Validate metamorphic or algebraic relations that must hold across the edited code.
3. **Honest Offline Stand-in**: Provide `ScriptedBreaker`, a deterministic, marker-based oracle for environments where the full differential infrastructure (sandbox + reference impl + input corpus) is unavailable.

### Core Components

| Component | Type | Responsibility |
|-----------|------|----------------|
| `BreakerKind` | Enum | Classifies a finding as either `Divergence` or `InvariantViolation`. |
| `BreakerFinding` | Struct | One concrete finding, including kind, human-readable detail, and whether it is `gating`. |
| `BreakerReport` | Struct | Aggregates all findings for a candidate and reports whether any are gating. |
| `DifferentialOracle` | Trait | The seam implemented by real differential/invariant infrastructure. |
| `ScriptedBreaker` | Struct | Offline, deterministic `DifferentialOracle` that flags markers newly present in the candidate. |
| `run_if_tier3` | Function | Guards execution so the oracle is only consulted for `RiskTier::HighRisk` edits. |

## Architecture

### Component Overview

```mermaid
classDiagram
    class BreakerKind {
        <<enum>>
        Divergence
        InvariantViolation
    }

    class BreakerFinding {
        +BreakerKind kind
        +String detail
        +bool gating
    }

    class BreakerReport {
        +Vec~BreakerFinding~ findings
        +has_gating_finding() bool
    }

    class DifferentialOracle {
        <<trait>>
        +differential_check(baseline, candidate) Vec~BreakerFinding~
    }

    class ScriptedBreaker {
        +Vec~String~ divergence_markers
        +Vec~String~ invariant_markers
        +new() ScriptedBreaker
        +with_divergence_marker(marker) ScriptedBreaker
        +with_invariant_marker(marker) ScriptedBreaker
    }

    class run_if_tier3 {
        <<function>>
        +run_if_tier3(tier, baseline, candidate, oracle) Option~BreakerReport~
    }

    BreakerReport "1" *-- "*" BreakerFinding
    BreakerFinding --> BreakerKind
    DifferentialOracle <|.. ScriptedBreaker
    ScriptedBreaker ..> BreakerFinding : produces
    run_if_tier3 ..> DifferentialOracle : consults
    run_if_tier3 ..> BreakerReport : returns
```

### Component Interaction

```mermaid
sequenceDiagram
    participant Stage as Stage Execution
    participant Risk as Risk Classifier
    participant Gate as run_if_tier3
    participant Oracle as DifferentialOracle
    participant Report as BreakerReport

    Stage->>Risk: classify edit
    Risk-->>Stage: RiskTier::HighRisk
    Stage->>Gate: run_if_tier3(HighRisk, baseline, candidate, oracle)
    Gate->>Oracle: differential_check(baseline, candidate)
    Oracle-->>Gate: Vec<BreakerFinding>
    Gate->>Report: BreakerReport { findings }
    Report-->>Gate: has_gating_finding()
    Gate-->>Stage: Some(report)

    alt RiskTier below HighRisk
        Stage->>Gate: run_if_tier3(tier, ...)
        Gate-->>Stage: None (not consulted)
    end
```

## Data Flow

The Breaker consumes two file sets — the `baseline` and the `candidate` — each represented as a `Vec<(String, String)>` of `(path, content)` pairs. The oracle collapses each file set into a single searchable string and compares marker presence.

```mermaid
flowchart LR
    A[Baseline Files] -->|"Vec<(path, content)>"| C[DifferentialOracle]
    B[Candidate Files] -->|"Vec<(path, content)>"| C
    C -->|"Vec<BreakerFinding>"| D[BreakerReport]
    D -->|has_gating_finding| E{Gate Decision}
    E -->|true| F[Block / Escalate]
    E -->|false| G[Allow to Proceed]
```

For the real infrastructure oracle, the same `(path, content)` shape is used, but the comparison is behavioral: both implementations are executed on generated or recorded inputs and their outputs are diffed.

## Process Flows

### Tier-3 Breaker Execution

```mermaid
flowchart TD
    A[Edit Turn Completes] --> B{Risk Tier?}
    B -->|Trivial / Local / Moderate| C[Breaker Not Consulted]
    C --> D[Report: Breaker not run]
    B -->|HighRisk| E[Consult DifferentialOracle]
    E --> F{Findings?}
    F -->|Gating finding| G[Block commit / hand off to human]
    F -->|No gating findings| H[Proceed to next gate]
    F -->|Advisory only| I[Surface advisory, proceed]
```

### ScriptedBreaker Differential Check

```mermaid
flowchart TD
    A[Receive baseline & candidate] --> B[Concatenate file contents]
    B --> C{For each divergence marker}
    C -->|Present in candidate<br/>Absent in baseline| D[Emit gating Divergence finding]
    C -->|Otherwise| E[No divergence]
    B --> F{For each invariant marker}
    F -->|Present in candidate<br/>Absent in baseline| G[Emit advisory InvariantViolation finding]
    F -->|Otherwise| H[No invariant violation]
    D & G --> I[Return Vec<BreakerFinding>]
    E & H --> I
```

## Integration with the Pipeline

The Breaker is one of several specialized gates in the [pipeline stages and tools](pipeline_stages_and_tools.md) family:

- [pipeline_stages_and_tools_stage_execution](pipeline_stages_and_tools_stage_execution.md) — executes individual pipeline stages.
- [pipeline_stages_and_tools_classification_and_risk](pipeline_stages_and_tools_classification_and_risk.md) — produces the `RiskTier` that gates Breaker execution.
- [pipeline_stages_and_tools_semantic_review](pipeline_stages_and_tools_semantic_review.md) — lightweight semantic gate; the Breaker is its high-risk escalation.
- [pipeline_stages_and_tools_sast](pipeline_stages_and_tools_sast.md) — static security scanning.
- [pipeline_stages_and_tools_commit_gate](pipeline_stages_and_tools_commit_gate.md) — final commit approval, which may consume `BreakerReport::has_gating_finding()`.
- [edit_turn_execution](edit_turn_execution.md) — the edit turn that produces the candidate file set fed into the Breaker.

There is also a conceptual relationship with [scenario_service_breaker](scenario_service_breaker.md), which provides chaos-style adversarial testing infrastructure. While the scenario Breaker focuses on *inducing* failures to validate resilience, the pipeline Breaker focuses on *detecting* behavioral divergences from a reference.

## Key Design Principles

1. **Scoped to High Risk**: `run_if_tier3` explicitly returns `None` for `Trivial`, `Local`, and `Moderate` tiers. This prevents wasting differential runs on low-risk changes.
2. **Honest Absence**: A `None` result means "not consulted," never "clean." A `Some(report)` with empty findings means the oracle was consulted and found nothing.
3. **Gating vs. Advisory**: `BreakerFinding::gating` distinguishes blocking divergences from informational invariant advisories.
4. **Infra-Ready Seam**: `DifferentialOracle` is a trait so real infrastructure (sandbox + reference implementation + input corpus) can replace `ScriptedBreaker` without changing the pipeline integration.
5. **Deterministic Offline Behavior**: `ScriptedBreaker` is marker-based and reproducible, making tests and local development predictable.

## References

- [pipeline_orchestration](pipeline_orchestration.md)
- [pipeline_stages_and_tools](pipeline_stages_and_tools.md)
- [pipeline_stages_and_tools_stage_execution](pipeline_stages_and_tools_stage_execution.md)
- [pipeline_stages_and_tools_classification_and_risk](pipeline_stages_and_tools_classification_and_risk.md)
- [pipeline_stages_and_tools_semantic_review](pipeline_stages_and_tools_semantic_review.md)
- [pipeline_stages_and_tools_sast](pipeline_stages_and_tools_sast.md)
- [pipeline_stages_and_tools_commit_gate](pipeline_stages_and_tools_commit_gate.md)
- [edit_turn_execution](edit_turn_execution.md)
- [scenario_service_breaker](scenario_service_breaker.md)
