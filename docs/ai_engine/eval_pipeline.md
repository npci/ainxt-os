# eval_pipeline Module

> Sub-module documentation: [Release Gate](eval_pipeline_release_gate.md) · [CI Integration](eval_pipeline_ci_integration.md) · [Durable Stores](eval_pipeline_durable_stores.md)


## Overview

The `eval_pipeline` module is the **merge-blocking release gate composition** for the AI engine's evaluation platform. It takes the individual evaluation instruments defined elsewhere in the `ainxt-eval` crate — meta-gate validation, sealed corpus integrity, Judge governance, contamination scanning, statistical gating, overfit tripwires, and regression vaults — and composes them into a single, fail-closed, statistically valid, auditable pipeline that a CI system can block a merge on.

Prior to this module, each rigorous instrument existed but was only exercised from its own unit tests. The downstream gate that actually ran was a naive aggregate pass-rate comparison that could block on sampling noise ("coin-flips"). `eval_pipeline` closes that gap by providing [`run_release_gate`](eval_pipeline_release_gate.md), the single entrypoint a CI merge-check or dogfood runner calls.

The module is intentionally I/O-agnostic: all heavy dependencies (encrypted sealed corpus store, tamper-evident Event Log, in-house Judge, dogfood runner) are supplied through trait seams. This lets the same composition be tested end-to-end with fakes in-crate and wired to real backends by the parent crates.

## Architecture

```mermaid
flowchart TB
    subgraph Inputs
        MAN[EvalSetManifest<br/>pre-registration + content commitment]
        SC[SealedCorpusStore]
        BL[Baseline EvalSystem]
        CD[Candidate EvalSystem]
        JS[JudgeSpec + QualityJudge]
        CAL[JudgeCalibration]
        CON[ContaminationScan]
        VLT[RegressionVault]
        CFG[ReleaseGateConfig]
    end

    RG[run_release_gate<br/>Release Gate Pipeline]

    subgraph Stages
        MG[Meta-gate<br/>powered + well-formed]
        SI[Sealed Corpus Integrity]
        JG[Judge Governance<br/>route / admit / drift]
        CS[Contamination Scan]
        SG[Statistical Gate<br/>paired per-cell CUPED]
        TW[Overfit Tripwire]
        VR[Regression Vault]
        RT[Rotation Hygiene Warning]
    end

    Inputs --> RG
    RG --> MG
    RG --> SI
    RG --> JG
    RG --> CS
    RG --> SG
    RG --> TW
    RG --> VR
    RG --> RT

    Stages --> RD{ReleaseDecision}
    RD -->|Ship| SH[SHIP]
    RD -->|Block| BLK[BLOCK]
    RD -->|Indeterminate| IND[INDETERMINATE]

    CI[CI Integration<br/>run_release_gate_ci] --> RG
    CI --> MSC[merge_status_check]
    MSC --> CSP[CommitStatusPublisher]
    MSC --> BPE[BranchProtectionEnforcer]

    DS[Durable Stores] --> SC
    DS --> VLT
    DS --> ES[EventSink]

    style RG fill:#e1f5fe
    style CI fill:#fff3e0
    style DS fill:#e8f5e9
```

### Key Design Principles

- **Fail-closed**: any stage that cannot be evaluated, any integrity failure, or any cancellation/over-budget condition results in `Block` or `Indeterminate` — never a silent pass.
- **Statistically valid**: the ship decision is the per-cell [`statistical_gate`](eval_judging.md), not a mean comparison or pass-rate arithmetic.
- **Auditable**: a deterministic, reproduce-from-SHA [`VerdictRecord`](eval_judging.md) is written to the Event Log **before** the decision is returned.
- **Enterprise-grade**: honours cooperative cancellation, per-run case budgets, and regulated-data-class Judge routing.

## Sub-modules

### [eval_pipeline_release_gate](eval_pipeline_release_gate.md)

Implements the core [`run_release_gate`](eval_pipeline_release_gate.md) entrypoint and all supporting request/response types (`ReleaseGateRequest`, `ReleaseGateReport`, `ReleaseDecision`, `GatedCase`, `PanelInputs`, etc.). It orchestrates the nine-stage pipeline:

1. Budget / cancellation check
2. Meta-gate validation
3. Sealed corpus load + content commitment verification
4. Judge governance (routing, admission, drift)
5. Contamination scan
6. Statistical gate with optional CUPED variance reduction and Judge-panel ensemble for hard-safety cells
7. Overfit tripwire
8. Regression vault monotonicity + route restoration
9. Rotation hygiene warning

### [eval_pipeline_ci_integration](eval_pipeline_ci_integration.md)

Wires the release gate to CI merge-check semantics. Provides [`run_release_gate_ci`](eval_pipeline_ci_integration.md) to map a `ReleaseDecision` to a merge-block decision and process exit code, plus [`merge_status_check`](eval_pipeline_ci_integration.md) to compose the eval gate with other required Definition-of-Done gates (e.g. the Scenario Matrix). It also includes the full [`run_ci_merge_check_enforced`](eval_pipeline_ci_integration.md) entrypoint that publishes a named commit status and enforces the branch-protection rule that requires it.

### [eval_pipeline_durable_stores](eval_pipeline_durable_stores.md)

File-backed, durable implementations of the trait seams the pipeline depends on:

- [`FileSealedCorpusStore`](eval_pipeline_durable_stores.md) — runner-identity-restricted sealed corpus.
- [`FileVaultStore`](eval_pipeline_durable_stores.md) — append-only regression vault with seal verification.
- [`FileEventSink`](eval_pipeline_durable_stores.md) — durable JSONL verdict log.

These are the no-infra tier behind the same seams; swapping in KMS-encrypted database/object-store backends is a configuration change.

## Data Flow

```mermaid
sequenceDiagram
    participant CI as CI Job / Dogfood Runner
    participant RG as run_release_gate
    participant MG as Meta-gate
    participant SC as SealedCorpusStore
    participant JG as Judge Governance
    participant CS as Contamination Scan
    participant SG as Statistical Gate
    participant TW as Tripwire
    participant RV as RegressionVault
    participant ES as EventSink

    CI->>RG: ReleaseGateRequest
    RG->>MG: validate pre-registration + power
    MG-->>RG: pass / fail reasons
    RG->>SC: load(set_id, version, runner_identity)
    RG->>RG: verify content commitment
    RG->>JG: route_judge / admit_judge / judge_drift
    JG-->>RG: judge_ok / block reasons
    RG->>CS: scan_contamination
    CS-->>RG: contaminated? hits
    RG->>SG: score paired cases per cell
    Note over SG: CUPED + panel ensemble<br/>for hard-safety cells
    SG-->>RG: GateReport + worst effect
    RG->>TW: tripwire_check
    TW-->>RG: overfit? drop
    RG->>RV: verify_all + is_monotonic + route_restored
    RV-->>RG: vault_ok / block reasons
    RG->>RG: assemble ReleaseDecision
    RG->>ES: append VerdictRecord
    ES-->>RG: ok
    RG-->>CI: ReleaseGateReport
```

## CI Merge-Check Wiring

```mermaid
flowchart LR
    subgraph "Definition of Done Gates"
        EG[Eval Gate<br/>ainxt/release-gate]
        SM[Scenario Matrix<br/>ainxt/scenario-matrix]
    end

    RG[run_release_gate] --> CGO[CiGateOutcome]
    CGO --> MSC[merge_status_check]
    SM --> MSC
    MSC --> SC[StatusCheck]
    SC --> CSP[CommitStatusPublisher]
    BPE[BranchProtectionEnforcer] --> SC

    style EG fill:#90EE90
    style SM fill:#FFB6C1
```

The eval gate alone is not enough to merge. Branch protection must require the composite `ainxt/release-gate` status, and that status is `Success` only when the eval gate **Ship**s **and** every other required DoD gate (typically the Scenario Matrix) has reported and passed. A missing required gate is treated as a failure (fail-closed).

## Relationship to Other Modules

- **[eval_cases](eval_cases.md)**: supplies `EvalCase`, `EvalSetManifest`, `EvalCaseContent`, `HoldoutCase`, and the sealed-corpus abstractions consumed by the pipeline.
- **[eval_judging](eval_judging.md)**: supplies `QualityJudge`, `JudgeSpec`, `JudgePanel`, `JudgeCalibration`, `statistical_gate`, `VerdictRecord`, and `EventSink` — the scoring and audit primitives the pipeline composes.
- **[conformance](conformance.md) / [canary](canary.md) / [replay](replay.md)**: sibling evaluation-testing modules that provide other gates and observability surfaces; the Scenario Matrix required check often draws from these.
- **[scenario_service](../scenario_service/scenario_service.md)**: the source of the Scenario Matrix safety/correctness gate that is composed with the eval gate in the merge-check.

## When to Use This Module

Use `eval_pipeline` when you need to:

- Block a PR merge on a rigorous, statistically valid evaluation of a candidate change.
- Run a dogfood evaluation that produces an auditable, reproduce-from-SHA verdict.
- Compose the individual evaluation instruments into a single fail-closed decision.
- Wire the eval gate into CI as a named, merge-blocking status check with branch-protection enforcement.
