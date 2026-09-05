# eval_pipeline_ci_integration

The **CI integration layer** for the evaluation release gate. This module exposes the offline, statistically-valid release gate as a **merge-blocking CI status check** and, optionally, as an **enforced branch-protection rule**. It is the callable entrypoint that turns the internal [`ReleaseDecision`](eval_pipeline_release_gate.md) into the two things a CI system actually needs: a boolean merge-block verdict and a process exit code.

In short: the release gate proves a change does not regress quality; this module wires that proof into the SCM so that a regression cannot merge.

---

## Overview

The evaluation pipeline ([`eval_pipeline_release_gate`](eval_pipeline_release_gate.md)) produces a rigorous, reproducible verdict (`Ship`, `Block`, or `Indeterminate`) by composing sealed-corpus integrity checks, judge calibration, contamination scans, statistical gating, and regression-vault comparisons. Before this module existed, that verdict was only exercised from unit tests â€” there was no production surface a CI job could call.

`eval_pipeline_ci_integration` closes that gap with three layers:

1. **Gate-to-CI mapping** â€” `run_release_gate_ci` runs the real composed gate and maps `ReleaseDecision` to `CiGateOutcome`, including a fail-closed merge-block flag and a process exit code.
2. **Status-check composition & publishing** â€” `merge_status_check` / `merge_status_check_required` compose the eval gate with other required Definition-of-Done gates (e.g. the Scenario Matrix), and `run_ci_merge_check` publishes the composite status to the SCM commit-status API via the `CommitStatusPublisher` seam.
3. **Branch-protection enforcement** â€” `run_ci_merge_check_enforced` ensures the SCM branch-protection rule actually requires the named status check, so a posted `failed` status cannot be ignored.

The module is intentionally thin: all heavy evaluation logic lives in sibling modules, and only the CI-specific semantics (status vocabulary, fail-closed composition, SCM wire seams) live here.

---

## Architecture

```mermaid
flowchart TB
    subgraph "SCM / CI System"
        BP["Branch Protection Rule"]
        CS["Commit Status API"]
    end

    subgraph "eval_pipeline_ci_integration"
        direction TB
        CI["run_release_gate_ci"]
        MSC["merge_status_check / merge_status_check_required"]
        RCMC["run_ci_merge_check"]
        RCME["run_ci_merge_check_enforced"]
        CSP["CommitStatusPublisher seam"]
        BPE["BranchProtectionEnforcer seam"]
    end

    subgraph "Upstream evaluation modules"
        RG["eval_pipeline_release_gate"]
        EJ["eval_judging"]
        AUD["eval_pipeline_durable_stores"]
    end

    RG -->|ReleaseGateRequest / ReleaseGateReport| CI
    EJ -->|dogfood::ReleaseGateProvider / MergeCheck| RCMC
    AUD -->|EventSink| CI

    CI -->|CiGateOutcome| MSC
    MSC -->|StatusCheck| RCMC
    RCMC -->|CommitStatus| CSP
    CSP -->|POST status| CS
    CS -->|required check| BP

    RCME -->|ensure_required + verify| BPE
    BPE -->|ProtectionRule| BP
```

### Component roles

| Component | Responsibility |
|-----------|----------------|
| `CiGateOutcome` | The CI-facing result of a release-gate run: merge-block flag, exit code, summary, and full report. |
| `StatusCheck` / `CheckState` | The named status-check vocabulary (`Pending`, `Success`, `Failure`) that branch protection understands. |
| `RequiredCheck` | An external required gate (e.g. Scenario Matrix) supplied by the CI job; fail-closed if missing or failed. |
| `merge_status_check` | Composes the eval gate with additional checks into the single `ainxt/release-gate` status. |
| `merge_status_check_required` | Strict variant: a required gate that is *absent* from the supplied list is treated as a hard failure. |
| `CommitStatus` | The payload posted to the SCM commit-status API, including target ref. |
| `CommitStatusPublisher` | Seam for the live SCM commit-status API; `RecordingStatusPublisher` is the offline deterministic stand-in. |
| `CiMergeCheck` | End-to-end result of `run_ci_merge_check`: status, merge-block, exit code, publish result, and underlying gate check. |
| `ProtectionRule` | The branch-protection rule listing required status checks. |
| `BranchProtectionEnforcer` | Seam to read and idempotently strengthen branch-protection rules; `RecordingBranchProtectionEnforcer` is the offline stand-in. |
| `CiMergeCheckEnforced` | Result of the fully enforced path: merge check plus confirmed protection rule. |

---

## Dependencies

```mermaid
flowchart LR
    A[eval_pipeline_ci_integration] --> B[eval_pipeline_release_gate]
    A --> C[conformance]
    A --> D[eval_pipeline_durable_stores]

    B --> E[eval_cases]
    B --> F[eval_judging]
    C --> G[eval_pipeline_release_gate]
    C --> H[eval_judging]
    D --> I[eval_cases]
```

- **[`eval_pipeline_release_gate`](eval_pipeline_release_gate.md)** â€” supplies `run_release_gate`, `ReleaseGateRequest`, `ReleaseGateReport`, and `ReleaseDecision`. This module does not reimplement gating; it only adapts the verdict.
- **[`conformance`](conformance.md)** â€” supplies the dogfood provider seam (`ReleaseGateProvider`, `run_merge_check`, `MergeCheck`) used by `run_ci_merge_check` to obtain a gate outcome through the production runtime path.
- **[`eval_pipeline_durable_stores`](eval_pipeline_durable_stores.md)** â€” supplies the `EventSink` seam used to write the reproduce-from-SHA verdict to the audit log before the decision is returned.

---

## Data Flow

### 1. Simple gate-to-CI mapping

```mermaid
sequenceDiagram
    participant CI_JOB as CI Job
    participant CI as run_release_gate_ci
    participant RG as eval_pipeline_release_gate
    participant SINK as EventSink

    CI_JOB ->> CI: ReleaseGateRequest
    CI ->> RG: run_release_gate(req, sink)
    RG ->> SINK: write reproduce-from-SHA verdict
    RG -->> CI: ReleaseGateReport
    CI ->> CI: map ReleaseDecision
    CI -->> CI_JOB: CiGateOutcome
```

`run_release_gate_ci` is the minimal entrypoint. It guarantees that the full composed gate runs and that the audit sink receives the verdict **before** the CI outcome is produced.

### 2. Composite status-check publishing

```mermaid
sequenceDiagram
    participant CI_JOB as CI Job
    participant RC as run_ci_merge_check
    participant DF as conformance / ReleaseGateProvider
    participant COMP as compose_required_status
    participant PUB as CommitStatusPublisher
    participant SCM as SCM Commit Status API

    CI_JOB ->> RC: provider, additional[], required[], target_ref, publisher
    RC ->> DF: run_merge_check(provider)
    DF -->> RC: MergeCheck
    RC ->> COMP: eval_mergeable, summary, additional, required
    COMP -->> RC: StatusCheck
    RC ->> RC: compute exit_code
    RC ->> PUB: publish(CommitStatus)
    PUB ->> SCM: POST status
    SCM -->> PUB: Ok / Err
    PUB -->> RC: Result<(), String>
    RC -->> CI_JOB: CiMergeCheck
```

### 3. Fully enforced merge check

```mermaid
sequenceDiagram
    participant GOV as Governance Job
    participant RCE as run_ci_merge_check_enforced
    participant BPE as BranchProtectionEnforcer
    participant BP as Branch Protection Rule
    participant RC as run_ci_merge_check
    participant PUB as CommitStatusPublisher

    GOV ->> RCE: provider, additional, required, target_ref, branch, publisher, enforcer
    RCE ->> BPE: ensure_required(branch, [RELEASE_GATE_CHECK, ...required])
    BPE ->> BP: add missing required checks
    BP -->> BPE: ProtectionRule
    RCE ->> BPE: branch_protection_covers(...)
    BPE -->> RCE: missing[]
    RCE ->> RC: run_ci_merge_check(...)
    RC -->> RCE: CiMergeCheck
    RCE ->> PUB: publish
    RCE -->> GOV: CiMergeCheckEnforced
```

---

## Fail-Closed Semantics

The module is designed to be **fail-closed** in every direction:

| Condition | Merge blocked? | Exit code | Rationale |
|-----------|---------------|-----------|-----------|
| `ReleaseDecision::Ship` | No | `EXIT_SHIP` (0) | Explicit pass only. |
| `ReleaseDecision::Block` | Yes | `EXIT_BLOCK` (1) | Statistically-valid regression or integrity failure. |
| `ReleaseDecision::Indeterminate` | Yes | `EXIT_INDETERMINATE` (2) | Cancelled, over-budget, corpus unavailable â€” never treated as pass. |
| Required gate missing | Yes | `EXIT_BLOCK` | A gate that never reported cannot satisfy "both gates green by rule". |
| Required gate failed | Yes | `EXIT_BLOCK` | The other DoD gate regressed. |
| SCM publish failed | Yes | â€” | The required status never turns green; branch protection stays blocking. |
| Branch-protection enforcement failed | Yes | â€” | A `Success` status on an unprotected branch is not mergeable. |

---

## Process Flows

### Running the eval gate as a CI merge-check

```mermaid
flowchart TD
    A[CI job starts] --> B[Build ReleaseGateRequest]
    B --> C[Call run_release_gate_ci]
    C --> D{ReleaseDecision?}
    D -->|Ship| E[merge_blocked = false]
    D -->|Block| F[merge_blocked = true]
    D -->|Indeterminate| G[merge_blocked = true]
    E --> H[exit process with EXIT_SHIP]
    F --> I[exit process with EXIT_BLOCK]
    G --> J[exit process with EXIT_INDETERMINATE]
```

### Publishing the composite required status

```mermaid
flowchart TD
    A[run_ci_merge_check] --> B[run_merge_check via ReleaseGateProvider]
    B --> C{MergeCheck mergeable?}
    C -->|Yes| D[eval_mergeable = true]
    C -->|No / FailClosed| E[eval_mergeable = false]
    D --> F[Compose with additional & required checks]
    E --> F
    F --> G{Any failure?}
    G -->|No| H[StatusCheck = Success]
    G -->|Yes| I[StatusCheck = Failure]
    H --> J[exit_code = EXIT_SHIP]
    I --> K[exit_code = gate code or EXIT_BLOCK]
    J --> L[publish CommitStatus]
    K --> L
    L --> M[CiMergeCheck returned]
```

### Enforcing branch protection

```mermaid
flowchart TD
    A[run_ci_merge_check_enforced] --> B[ensure_required branch rule]
    B --> C{Write succeeded?}
    C -->|No| D[protection = Err]
    C -->|Yes| E[re-read rule]
    E --> F{Covers all required names?}
    F -->|No| G[protection = Err with missing checks]
    F -->|Yes| H["protection = Ok(rule)"]
    D --> I[run_ci_merge_check]
    G --> I
    H --> I
    I --> J[CiMergeCheckEnforced returned]
    J --> K{is_mergeable?}
    K -->|Yes| L[Merge allowed]
    K -->|No| M[Merge blocked]
```

---

## Integration Points

### CI job contract

A CI job (e.g. `cargo xtask eval-gate`) typically calls one of two entrypoints:

- **`run_release_gate_ci`** â€” when the job only needs the gate outcome and exit code.
- **`run_ci_merge_check_enforced`** â€” when the job must also publish a commit status and guarantee the branch-protection rule requires it.

Both return a process exit code that the CI job can pass directly to `std::process::exit` or return as `std::process::ExitCode`.

### SCM seams

The module defines two traits that the reserved server/daemon crates implement for live SCM interaction:

- `CommitStatusPublisher::publish` â€” posts a `CommitStatus` to the SCM commit-status API.
- `BranchProtectionEnforcer::ensure_required` â€” idempotently adds required checks to a branch-protection rule.

Offline deterministic implementations (`RecordingStatusPublisher`, `RecordingBranchProtectionEnforcer`) are provided for tests and dry-runs.

### Required DoD gates

The composite status check can include any number of `RequiredCheck` results. By convention the Scenario Matrix check ([`SCENARIO_MATRIX_CHECK`]) is always required, reflecting the operating-system rule that "nothing ships until it passes both gates" â€” the eval gate (quality) and the scenario matrix (safety/correctness).

---

## Relationship to the System

`eval_pipeline_ci_integration` sits at the boundary between the **evaluation/testing subsystem** and the **CI/CD subsystem**. It does not perform evaluation itself; it is the adapter that makes the evaluation subsystem's verdict actionable by external merge automation.

Upstream modules of interest:

- [`eval_pipeline_release_gate`](eval_pipeline_release_gate.md) â€” the composed release-gate logic this module exposes.
- [`eval_cases`](eval_cases.md), [`eval_judging`](eval_judging.md) â€” the cases and judges consumed by the release gate.
- [`conformance`](conformance.md) â€” the dogfood provider that runs the gate through the production runtime.
- [`eval_pipeline_durable_stores`](eval_pipeline_durable_stores.md) â€” the durable audit/event-log sink.

---

## Key Design Decisions

1. **Fail-closed by default.** Only an explicit `Ship` is mergeable; every other state blocks.
2. **No stand-ins.** `run_release_gate_ci` calls the real `run_release_gate`, not a simplified aggregate gate.
3. **Audit-first.** The reproduce-from-SHA verdict is written to the `EventSink` before the CI outcome is returned.
4. **Separation of decision and enforcement.** `run_ci_merge_check` computes and publishes the status; `run_ci_merge_check_enforced` additionally verifies the branch-protection rule.
5. **Offline-provable seams.** Live SCM calls are behind traits with deterministic in-memory implementations, so the merge-blocking logic can be tested without network access.
