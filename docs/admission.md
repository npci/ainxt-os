# Admission Module

## Overview

The `admission` module (`ainxt-admission`) is the **admission and capability-permission core** of the system. Its sole responsibility is to decide whether a declared, engineer-authored orchestration (called a *harness*) is allowed to run, and to bound what it may spend and access. It does **not** execute harness steps itself — execution is delegated to the engine/runtime layer. This separation is deliberate: *admission owns the gate; the engine owns execution*.

The module enforces a fail-closed safety spine around harness invocations, including:

- **Least-privilege capability authorization** — a harness can only use capabilities it requested, that governance granted, and that the invoking principal holds.
- **Hard resource budgets** — caps on steps, tokens, and tool calls.
- **Data-class ceiling** — a harness cannot process turns more sensitive than its declared or governance-capped ceiling.
- **Payment boundary** — live payment-rail access is explicitly declared and enforced.
- **RBAC-on-execute** — visibility scoping (`public`/`department`/`private`) controls who may invoke a harness.
- **Autonomy / HITL gating** — write/side-effect steps require human approval under `assisted` autonomy and are refused under `none`.
- **Auditability** — every admission decision and step execution is recorded.
- **Renderer registration** — a harness declaring a custom bundled renderer must have registered it.

The module is pure, executor-agnostic, and exhaustively testable. It is invoked from product surfaces such as REST, Chat, connector triggers, and the CLI.

---

## Module Context

The admission module sits within the broader `governance_compliance` area. It depends on lower-level identity, types, runtime, and governance primitives, and is consumed by the server and client surfaces.

```mermaid
flowchart TB
    subgraph Surfaces
        REST[ainxt-server REST routes]
        Chat[ainxt-chat / ainxt-convo]
        Connector[ainxt-connector triggers]
        CLI[ainxt-cli dev loop]
    end

    subgraph GovernanceCompliance["governance_compliance"]
        Admission[admission module]
        Governance[governance module]
        Compliance[compliance module]
        Identity[identity module]
    end

    subgraph RuntimeAndTypes["runtime / types"]
        Runtime[ainxt-runtime]
        Types[ainxt-types]
    end

    Surfaces -->|invoke harness by id| Admission
    Admission -->|CapabilityGrant / Marketplace| Governance
    Admission -->|ComplianceGate scan| Compliance
    Admission -->|Principal / Role / DataClass| Types
    Admission -->|ApprovalGate adapter| Runtime
    Identity -->|Principal authority| Admission
```

---

## Architecture

The admission module is organized around four core artifacts:

1. **`HarnessManifest`** — the declarative definition of a harness (steps, capabilities, budget, RBAC, autonomy, payment boundary, renderer, dependencies).
2. **`HarnessRuntime`** — the policy engine that admits a manifest and gates each step.
3. **`HarnessRegistry`** — an id-keyed registry of published, invocable harnesses.
4. **`lint`** — deterministic semantic validation of manifests (shared by CI and CLI).

```mermaid
flowchart LR
    subgraph Manifest["HarnessManifest"]
        M1[steps]
        M2[requested_capabilities]
        M3[budget]
        M4[rbac / execute_rbac]
        M5[data_class_ceiling]
        M6[payment_boundary]
        M7[autonomy]
        M8[renderer]
        M9[depends_on]
    end

    subgraph Runtime["HarnessRuntime"]
        R1[admit]
        R2[gate_step]
        R3[autonomy_gate]
        R4[run variants]
    end

    subgraph Registry["HarnessRegistry"]
        Reg1[register]
        Reg2[invoke by id]
        Reg3[invoke_from_surface]
    end

    subgraph Lint["lint"]
        L1[lint_manifest]
        L2[LintFinding]
    end

    Manifest -->|validated by| Lint
    Manifest -->|admitted by| Runtime
    Registry -->|resolves manifest + grant| Runtime
```

---

## Core Components

### `HarnessManifest`

A `HarnessManifest` is the serialized, declarative definition of a harness. Key fields:

| Field | Purpose |
|-------|---------|
| `kind` | Must be `"harness"`. |
| `id` | Stable, unique slug. |
| `version` | Semver, bumped on every publish. |
| `owner` | CODEOWNERS entry for authoring RBAC. |
| `requested_capabilities` | Capabilities the harness asks for. |
| `steps` | Ordered list of [`HarnessStep`] entries. |
| `budget` | Hard caps on steps, tokens, and tool calls. |
| `rbac` | Role floor and required capabilities. |
| `execute_rbac` | Visibility scope (`public`/`department`/`private`) and permissions. |
| `data_class_ceiling` | Maximum data sensitivity the harness may process. |
| `payment_boundary` | Live payment-rail access (`none`/`read-only`/`write`). |
| `autonomy` | HITL policy (`none`/`assisted`/`autonomous`). |
| `renderer` | `chat` default or a bundled custom renderer id. |
| `depends_on` | Pinned `[REDACTED]@content_hash` dependencies. |

The schema uses `deny_unknown_fields`, so a manifest cannot express a compliance, RBAC, or audit bypass.

### `HarnessStep`

Each step declares:

- `id` — stable step identifier.
- `kind` — `Llm`, `Tool`, or `Skill`.
- `capability` — the single capability required.
- `estimated_tokens` — used for the pre-execution token budget check.
- `input` — optional prompt/argument for the engine-turn bridge.

### `HarnessRuntime`

The runtime is constructed with mandatory seams:

- `HarnessAuthorizer` — on-behalf-of capability authorization.
- `HarnessAudit` — records admission and step events.
- `PaymentRailClassifier` — classifies payment-rail capabilities.
- `SideEffectClassifier` — classifies write/side-effect capabilities.
- `RendererResolver` — validates custom renderer availability.

Default OSS implementations are provided:

- `CapabilityAuthorizer` — principal must hold the capability.
- `InMemoryHarnessAudit` — shared in-memory event log.
- `MarkerPaymentRailClassifier` — heuristic rail marker classifier.
- `MarkerSideEffectClassifier` — heuristic write-verb classifier.
- `AnyRendererResolver` — permissive dev default.
- `RegisteredRendererResolver` — fail-closed allow-set resolver.

#### Admission Flow (`admit`)

```mermaid
sequenceDiagram
    actor Caller
    participant Runtime as HarnessRuntime
    participant Authz as HarnessAuthorizer
    participant Audit as HarnessAudit

    Caller->>Runtime: admit(manifest, grant, principal, ctx)
    Runtime->>Runtime: check role floor
    alt role too low
        Runtime->>Audit: record rejected-role
        Runtime-->>Caller: Rejected
    end
    Runtime->>Runtime: check execute-RBAC visibility
    alt outside scope
        Runtime->>Audit: record rejected-visibility
        Runtime-->>Caller: VisibilityDenied
    end
    Runtime->>Runtime: check required capabilities
    alt missing required cap
        Runtime->>Audit: record rejected-cap
        Runtime-->>Caller: Rejected
    end
    Runtime->>Runtime: check custom renderer registered
    alt renderer unavailable
        Runtime->>Audit: record rejected-renderer
        Runtime-->>Caller: RendererUnavailable
    end
    Runtime->>Runtime: check data-class ceiling
    alt turn too sensitive
        Runtime->>Audit: record rejected-dataclass
        Runtime-->>Caller: DataClassExceeded
    end
    Runtime->>Runtime: effective = requested ∩ granted
    Runtime-->>Caller: AdmittedRun
```

#### Step Gating (`gate_step`)

After admission, each step is gated against:

1. Step budget (`max_steps`).
2. Effective capability set (`requested ∩ granted`).
3. Principal authorization (`HarnessAuthorizer`).
4. Payment boundary (if the capability is a rail call).
5. Token budget (using `estimated_tokens`).
6. Tool-call budget (for `Tool` steps).

```mermaid
flowchart TD
    A[gate_step] --> B{steps_run >= max_steps?}
    B -->|yes| C[BudgetExceeded steps]
    B -->|no| D{capability in effective set?}
    D -->|no| E[CapabilityDenied grant]
    D -->|yes| F{principal authorized?}
    F -->|no| G[CapabilityDenied authz]
    F -->|yes| H{payment-rail call?}
    H -->|yes| I{boundary permits?}
    I -->|no| J[PaymentBoundaryViolation]
    H -->|no| K{tokens + estimate > max?}
    I -->|yes| K
    K -->|yes| L[BudgetExceeded tokens]
    K -->|no| M{tool step && tool_calls >= max?}
    M -->|yes| N[BudgetExceeded tool_calls]
    M -->|no| O[Admit]
```

### `HarnessRegistry`

The registry bridges *authoring* a harness with *invoking* it by id. A surface resolves a harness through the registry and then runs it through the runtime. Registration requires the manifest to pass `lint_manifest` and the id to be unique.

```mermaid
sequenceDiagram
    participant Surface as Product Surface
    participant Registry as HarnessRegistry
    participant Lint as lint_manifest
    participant Runtime as HarnessRuntime

    Surface->>Registry: register(manifest, grant)
    Registry->>Lint: lint_manifest(manifest)
    alt lint fails
        Registry-->>Surface: LintFailed
    else id already registered
        Registry-->>Surface: AlreadyRegistered
    else ok
        Registry-->>Surface: Ok
    end

    Surface->>Registry: invoke_from_surface(surface, id, runtime, ...)
    Registry->>Registry: get(id)
    alt not found
        Registry-->>Surface: NotFound
    else found
        Registry->>Runtime: run_from_surface(...)
        Runtime-->>Registry: HarnessOutcome
        Registry-->>Surface: HarnessOutcome
    end
```

### Approval / HITL

The module defines an `ApprovalResolver` seam for human-in-the-loop decisions on write steps under `assisted` autonomy:

- `DenyingApprovalResolver` — fail-closed default; rejects all approvals.
- `AllowingApprovalResolver` — dev/test only; always approves.
- `RuntimeApprovalGateResolver` — adapts the runtime's live `ApprovalGate` (e.g., `WireApprovalGate`) into the harness approval seam, so the same human/wire mechanism gates both engine tool calls and harness writes.

```mermaid
sequenceDiagram
    participant Runtime as HarnessRuntime
    participant Gate as autonomy_gate
    participant Resolver as ApprovalResolver
    participant Audit as HarnessAudit

    Runtime->>Gate: classify side-effect
    alt pure read
        Gate-->>Runtime: Proceed
    else autonomy = none
        Gate-->>Runtime: Refused SideEffectRefused
    else autonomy = assisted
        Gate-->>Runtime: NeedsApproval
        Runtime->>Audit: approval-requested
        Runtime->>Resolver: resolve(ApprovalRequest)
        alt Approve
            Resolver-->>Runtime: Approve
            Runtime->>Audit: approval-granted
        else Reject
            Resolver-->>Runtime: Reject(reason)
            Runtime->>Audit: approval-rejected
            Runtime-->>Runtime: ApprovalRejected
        end
    else autonomy = autonomous
        Gate-->>Runtime: Proceed
    end
```

### Compliance Integration

- `ComplianceStepExecutor` wraps a `StepExecutor` and applies a `ComplianceGate` to each step's output (redact-and-proceed).
- `run_with_compliance` uses a `ChainingStepExecutor` so each step only sees the **redacted** outputs of prior steps.
- `ComplianceBackedPrereceiveGate` adapts the real `ComplianceGate` into a git pre-receive gate, blocking pushes that contain material the runtime would redact.

```mermaid
flowchart LR
    subgraph Execution["Step Execution"]
        E1[ChainingStepExecutor]
        E2[ComplianceStepExecutor]
        E3[ComplianceGate]
    end

    subgraph PreReceive["Git Pre-receive"]
        P1[ComplianceBackedPrereceiveGate]
        P2[ComplianceGate]
    end

    E1 -->|output| E2
    E2 -->|scan| E3
    E3 -->|redacted text| E2
    P1 -->|scan| P2
    P2 -->|redactions > 0| P1
    P1 -->|block push| Git[git push]
```

---

## Run Variants

The runtime exposes several synchronous run paths:

| Method | Purpose |
|--------|---------|
| `run` | Basic admit + run with default `internal` data class. |
| `run_with_context` | Admit + run under a specific `RunContext` (data class). |
| `run_with_approvals` | Enforces autonomy/HITL on write steps. |
| `run_from_surface` | Records invoking surface and runs with approvals. |
| `run_with_compliance` | Applies compliance gate to every step output. |

The registry surfaces these through `invoke`, `invoke_with_approvals`, and `invoke_from_surface`.

---

## Lint (`lint.rs`)

`lint_manifest` performs deterministic, pure semantic validation:

- `kind` must be `"harness"`.
- `id` must be a non-empty lowercase slug.
- `version` must be semver `MAJOR.MINOR.PATCH`.
- `owner` is required.
- At least one step must be declared.
- Every step's capability must appear in `requested_capabilities`.
- `execute_rbac.permissions` must be scoped to declared capabilities.
- `Department` visibility requires a `department`.
- `depends_on` refs must be fully pinned (`repo`, `tag`, `content_hash`).

A manifest that fails lint cannot be registered and cannot merge through the control-repo CI.

---

## Security Invariants

The module encodes the following fail-closed invariants:

1. **No bypass fields** — `deny_unknown_fields` prevents manifests from disabling compliance/RBAC/audit.
2. **Least privilege** — effective capabilities are `requested ∩ granted`.
3. **Caller authority ceiling** — the principal must hold each step's capability.
4. **Budget minima** — the effective budget is the field-wise minimum of the manifest budget and any governance ceiling.
5. **Data-class minimum sensitivity** — the effective ceiling is the less sensitive of the manifest ceiling and the governance cap.
6. **Payment boundary** — a `none` boundary blocks all rail calls; `read-only` blocks writes.
7. **Visibility** — `department`/`private` harnesses refuse out-of-scope callers (admin break-glass allowed).
8. **Autonomy** — `none` refuses writes; `assisted` requires approval; `autonomous` proceeds but is judge-audited upstream.
9. **Renderer** — an unregistered custom renderer is refused before any step runs.
10. **Audit** — every admission refusal and step execution is recorded.

---

## Dependencies

The admission module depends on:

- [`ainxt-types`](ainxt-types.md) — `Principal`, `Role`, `DataClass`, `Tier`.
- [`ainxt-runtime`](ainxt-runtime.md) — `ComplianceGate`, `ApprovalGate`, `Redacted`.
- [`ainxt-governance`](ainxt-governance.md) — `Marketplace`, `PinnedSource`, `PrereceiveGate`, `PublishRequest`.
- `serde` — manifest serialization/deserialization.

It is consumed by:

- [`ainxt-server`](ainxt-server.md) — `/v1/harness/:id` route.
- [`ainxt-client`](ainxt-client.md) — SDK harness invocation and `WireApprovalGate`.
- [`ainxt-cli`](ainxt-cli.md) — `ainxt harness lint` / `ainxt harness dev`.

---

## Data Flow: Harness Invocation from a Surface

```mermaid
sequenceDiagram
    actor User
    participant Surface as Chat / REST / Connector / CLI
    participant Registry as HarnessRegistry
    participant Runtime as HarnessRuntime
    participant Authorizer as HarnessAuthorizer
    participant Audit as HarnessAudit
    participant Engine as Engine / StepExecutor

    User->>Surface: "run harness X"
    Surface->>Registry: invoke_from_surface(surface, id, runtime, principal, ctx, executor, resolver)
    Registry->>Registry: get(id)
    Registry->>Runtime: run_from_surface(surface, manifest, grant, principal, ctx, executor, resolver)
    Runtime->>Audit: invoked:{surface}
    Runtime->>Runtime: admit(...)
    Runtime->>Authorizer: authorize(principal, capability)
    alt admission refused
        Runtime->>Audit: rejected-*
        Runtime-->>Registry: HarnessOutcome::Rejected/VisibilityDenied/...
    else admitted
        Runtime-->>Runtime: AdmittedRun
        loop each step
            Runtime->>Runtime: gate_step(...)
            alt step refused
                Runtime->>Audit: budget/capability/payment
                Runtime-->>Registry: HarnessOutcome
            else autonomy needs approval
                Runtime->>Runtime: autonomy_gate
                Runtime->>Resolver: resolve(ApprovalRequest)
            else admitted
                Runtime->>Engine: execute(step, principal)
                Engine-->>Runtime: StepResult
                Runtime->>Audit: executed
            end
        end
        Runtime-->>Registry: Completed
    end
    Registry-->>Surface: HarnessOutcome
    Surface-->>User: result
```

---

## Testing Strategy

The module is designed for exhaustive unit testing. The test suite covers:

- Budget ceiling enforcement (manifest vs. governance cap).
- Capability denial when not granted, not requested, or not held by the principal.
- RBAC floor and execute-RBAC visibility (`department`, `private`, admin break-glass).
- Data-class ceiling blocking overly sensitive turns.
- Payment boundary gating (`none`, `read-only`, write verbs).
- Autonomy/HITL behavior for reads vs. writes.
- `RuntimeApprovalGateResolver` bridging to `ApprovalGate`.
- Custom renderer registration gating.
- Compliance step output redaction and chaining.
- `ComplianceBackedPrereceiveGate` blocking spaced secrets.
- Manifest serde round-trips and rejection of bypass fields.
- Dependency hash-pinning and tamper detection.
- Registry registration, idempotency, duplicate-id rejection, and invoke-by-id.

All tests are pure and do not require I/O, making the safety invariants fast and reliable to verify in CI.
