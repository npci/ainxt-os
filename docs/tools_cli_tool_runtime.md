# tools_cli_tool_runtime

## Brief Introduction

The `tools_cli_tool_runtime` module implements the **Tool Runtime** and **Side-Effect Ledger** for the ainxt system. It is the execution layer that sits beneath the CLI and client SDK, responsible for dispatching tool calls, enforcing deterministic guardrails, preventing double-execution of side effects, and auditing every authorization decision. The module is defined in the `ainxt-tools` crate and is a core part of the broader [`tools_cli`](tools_cli.md) subsystem.

This module guarantees that side-effecting tools execute **at most once** per idempotency key, supports multi-step sagas with compensation, and resolves lost-ack scenarios through reconciliation rather than silent re-execution. It also integrates pre/post hooks, on-behalf-of (OBO) authorization, data-class classification, and egress controls.

---

## Module Purpose and Core Functionality

The Tool Runtime answers four questions for every tool call:

1. **Is the caller authorized?** — via OBO policy, grants, clearance, and issued scopes.
2. **Is the call safe to execute?** — via deterministic pre/post hooks, data-class scans, and egress allow-lists.
3. **Has this side effect already happened?** — via the ledger-backed idempotency system.
4. **What happens if the call is lost in flight?** — via the reconciler/sweeper that resolves pending rows.

Core capabilities include:

- **Tool dispatch** for native, MCP-discovered, and plugin-provided capabilities.
- **Effect classification** using the canonical four-value `EffectClass` from [`ainxt_payments`](governance_compliance_payments.md).
- **Exactly-once execution** for `SideEffecting` tools through a durable or in-memory ledger.
- **Two-phase commit** (`dry_run` → `commit`) for `HighRisk` tools.
- **Pre/post hooks** for argument/output rewriting and refusal.
- **OBO dispatch** with structured audit and no ambient fallback.
- **Saga execution** with compensation steps.
- **Reconciliation sweeper** for in-doubt ledger rows.

---

## Architecture

### High-Level Component Overview

```mermaid
flowchart TB
    subgraph tools_cli_tool_runtime["tools_cli_tool_runtime (ainxt-tools)"]
        TR["ToolRuntime"]
        DTR["DurableToolRuntime"]
        OD["OboDispatcher"]
        HR["HookRegistry"]
        LEDGER["Ledger Implementations"]
        RECON["Reconciler / Sweeper"]
        CAPS["Capability Types"]
    end

    subgraph tools_cli_client_sdk["tools_cli_client_sdk (ainxt-client)"]
        CLIENT["Client SDK / Invokers"]
    end

    subgraph tools_cli_surface_profiles["tools_cli_surface_profiles (ainxt-profile)"]
        PROFILE["SurfaceProfile / Policies"]
    end

    subgraph governance_compliance_payments["governance_compliance: payments"]
        PAY["Payment Boundary / MandateRegistry"]
    end

    subgraph ai_engine_safety_guardrails["ai_engine: safety_guardrails"]
        GUARD["Injection / Guardrails"]
    end

    subgraph core_infrastructure_security_config["core_infrastructure: security_config"]
        TYPES["ainxt-types / DataClass"]
    end

    CLIENT -->|dispatches| TR
    PROFILE -->|configures| TR
    TR -->|uses| HR
    TR -->|reads/writes| LEDGER
    TR -->|delegates OBO| OD
    TR -->|loads| CAPS
    DTR -->|wraps| TR
    DTR -->|shares ledger| RECON
    PAY -->|mandate check| TR
    GUARD -.->|classification input| TR
    TYPES -.->|DataClass| TR
```

### ToolRuntime Internal Structure

```mermaid
flowchart LR
    TR["ToolRuntime"]
    TOOLS[(tools: HashMap<String, Box<dyn Tool>>)]
    LEDGER[(ledger: Arc<dyn Ledger>)]
    RECONCILER[(reconciler: Arc<dyn Reconciler>)]
    TWO_PHASE[(two_phase: Mutex<HashMap>)]
    RLOCK[(resource_locks)]
    KLOCK[(key_locks)]
    HOOKS["hooks: HookRegistry"]
    EGRESS["egress_allowlist: Option<EgressAllowList>"]
    MANDATE["mandate_registry: Option<Arc<Mutex<MandateRegistry>>>"]

    TR --> TOOLS
    TR --> LEDGER
    TR --> RECONCILER
    TR --> TWO_PHASE
    TR --> RLOCK
    TR --> KLOCK
    TR --> HOOKS
    TR --> EGRESS
    TR --> MANDATE
```

The runtime is intentionally stateful around concurrency control and idempotency. It maintains:

- A registry of `Tool` implementations keyed by capability name.
- A pluggable `Ledger` for exactly-once tracking.
- A `Reconciler` for resolving in-doubt rows.
- Two-phase commit state for `HighRisk` previews.
- Per-resource and per-idempotency-key mutex tables for concurrent duplicate prevention.
- A `HookRegistry` for deterministic guardrails.
- Optional egress and mandate registries.

---

## Core Components

### Capability Model

Tools are represented by the `Tool` trait (referenced from `lib.rs`). The runtime supports multiple capability origins:

| Capability Type | Source | Key Types |
|----------------|--------|-----------|
| Native | Built-in Rust implementations | `NativeControlLock` |
| MCP | Model Context Protocol servers | `McpTool`, `McpCapability` |
| Plugin | WASM/native plugins | `PluginCapability` |
| Search | Capability discovery | `CapabilitySearchTool` |
| Ledger Query | Introspection of the ledger | `LedgerQueryTool` |

```mermaid
classDiagram
    class Tool {
        <<trait>>
        +name()
        +schema()
        +declared_data_class()
        +destination_data_class()
        +effect_class()
        +risk_tier()
        +egress()
        +execute(args)
    }

    class McpTool
    class McpCapability
    class PluginCapability
    class CapabilitySearchTool
    class LedgerQueryTool

    Tool <|.. McpTool
    Tool <|.. McpCapability
    Tool <|.. PluginCapability
    Tool <|.. CapabilitySearchTool
    Tool <|.. LedgerQueryTool
```

### Effect Classification and Risk Tiers

The runtime adopts `PaymentEffectClass` from [`ainxt_payments`](governance_compliance_payments.md) as the canonical effect classification:

- `Pure` — no side effects; safe to retry.
- `Idempotent` — world-changing but retry-safe; no ledger needed.
- `SideEffecting` — requires ledger-backed exactly-once execution.
- `PaymentInitiating` — **non-dispatchable**; refused at registration and dispatch.

Risk tiers drive approval and two-phase requirements:

| RiskTier | Approval Gate | Two-Phase Commit |
|----------|--------------|------------------|
| `Low` | No | No |
| `Elevated` | Yes | No |
| `High` | Yes | No |
| `HighRisk` | Yes | Yes (`dry_run` → `commit`) |

### Data-Class Classification

Every call is classified by fusing three independent signals and escalating to the most sensitive:

1. **Declared** — the tool's own claim.
2. **ArgScan** — compliance scan of serialized arguments (`MarkerArgScanner`, `BoundedArgScanner`).
3. **Destination** — egress destination sensitivity.

```mermaid
flowchart LR
    DECL["Declared DataClass"]
    SCAN["ArgScan DataClass"]
    DEST["Destination DataClass"]
    FUSE["EffectiveDataClass"]
    AUDIT["Audit Record"]

    DECL --> FUSE
    SCAN --> FUSE
    DEST --> FUSE
    FUSE -->|class + escalated + drivers + signals| AUDIT
```

This classification gates model routing and approval but does not itself deny the turn. See [`ai_engine_safety_guardrails`](ai_engine_safety_guardrails.md) for the broader safety context.

---

## Hook System

The `HookRegistry` provides deterministic pre/post guardrails around every dispatch. Hooks are defined in [`hooks.rs`](crates/ainxt-tools/src/hooks.rs).

### Hook Types

- `PreHook` — runs before execution; may rewrite arguments or refuse.
- `PostHook` — runs after execution; may rewrite output or refuse.

### Ordering

- **Pre-hooks**: global first, then tool-specific. Ensures platform-wide checks cannot be bypassed by a tool-specific rewrite.
- **Post-hooks**: tool-specific first, then global. Ensures targeted verification sees raw output before blanket transforms like redaction.

```mermaid
flowchart LR
    ARGS["Incoming Args"]
    GPRE["Global Pre-Hooks"]
    TPRE["Tool-Specific Pre-Hooks"]
    EXEC["Capability Execute"]
    TPOST["Tool-Specific Post-Hooks"]
    GPOST["Global Post-Hooks"]
    OUT["Final Output"]

    ARGS --> GPRE --> TPRE --> EXEC --> TPOST --> GPOST --> OUT
```

### Built-in Hooks

| Hook | Type | Behavior |
|------|------|----------|
| `HashVerifyHook` | Post | Refuses output whose SHA-256 does not match an expected digest. |
| `DenyArgsHook` | Pre | Refuses arguments containing forbidden substrings (substring, not regex, to avoid ReDoS). |
| `TruncateOutputHook` | Post | Rewrites oversized output with a visible truncation marker. |

Hooks refuse by returning `Err(HookRefusal)`, which becomes a `Blocked` dispatch result. They are intentionally sync, non-blocking, and allocation-free of a runtime.

---

## Ledger and Exactly-Once Execution

The ledger is the foundation of the exactly-once guarantee for `SideEffecting` tools.

### Ledger Implementations

| Implementation | Use Case |
|----------------|----------|
| `InMemoryLedger` | Tests and single-process deployments. |
| `EventLogLedger<L: EventLog>` | Durable append-only log backing. |
| `SqlLedger<D: SqlLedgerDriver>` | SQL-backed durability (e.g., PostgreSQL via `PostgresSqlLedgerDriver`). |
| `InMemorySqlStore` | In-memory SQL semantics for testing. |

### Ledger States

A side-effecting call progresses through ledger states:

```mermaid
stateDiagram-v2
    [*] --> Fresh: dispatch begins
    Fresh --> Pending: claim slot
    Pending --> Committed: execute + commit
    Pending --> Failed: execute failed / reconciler probe
    Pending --> ManualReconciliation: ambiguous / no probe
    Committed --> [*]: return stored result
    Failed --> [*]: safe to retry
    ManualReconciliation --> [*]: escalate incident
```

### Concurrency Controls

The runtime uses two complementary locking tables:

1. **`resource_locks`** — serializes calls targeting the same resource key while allowing parallel execution across disjoint resources.
2. **`key_locks`** — serializes concurrent dispatches with the same idempotency key (e.g., UI double-click + retry).

Together with the cross-process ledger, these cover both concurrent-duplicate and retry-after-restart double-execution scenarios.

---

## Dispatch Flow

```mermaid
sequenceDiagram
    autonumber
    participant Caller
    participant TR as ToolRuntime
    participant HR as HookRegistry
    participant OBO as OboDispatcher
    participant LEDGER as Ledger
    participant TOOL as Tool

    Caller->>TR: dispatch(tool, args, actor)
    TR->>HR: run_pre(tool, args, actor)
    alt hook refuses
        HR-->>TR: HookRefusal
        TR-->>Caller: Blocked
    else
        HR-->>TR: rewritten args
    end

    TR->>TR: classify data class (3 signals)
    TR->>TR: check egress allowlist
    TR->>OBO: authorize OBO
    alt OBO denies
        OBO-->>TR: OboDenial
        TR-->>Caller: Denied
    end

    alt effect == SideEffecting
        TR->>LEDGER: claim(idempotency_key)
        alt already Committed
            LEDGER-->>TR: stored result
            TR-->>Caller: Deduped(result)
        else already Pending
            TR->>TR: serialize on key_lock
        end
    end

    TR->>TOOL: execute(rewritten args)
    TOOL-->>TR: raw output

    TR->>HR: run_post(tool, output, actor)
    alt hook refuses
        HR-->>TR: HookRefusal
        TR-->>Caller: Blocked
    else
        HR-->>TR: rewritten output
    end

    alt effect == SideEffecting
        TR->>LEDGER: commit(result)
    end

    TR-->>Caller: Ok(output)
```

---

## Two-Phase Commit for HighRisk Tools

`HighRisk` tools cannot be dispatched directly. They require a preview step:

```mermaid
sequenceDiagram
    autonumber
    participant Caller
    participant TR as ToolRuntime
    participant TWO as two_phase table

    Caller->>TR: dry_run(tool, args)
    TR->>TR: validate risk == HighRisk
    TR->>TR: run pre-hooks + OBO + classification
    TR->>TR: compute commit_key from semantic args
    TR->>TWO: store PreparedCommit
    TR-->>Caller: DryRunOutcome { preview, commit_key, expires_at }

    Caller->>TR: commit(tool, commit_key)
    TR->>TWO: lookup prepared commit
    alt missing or expired
        TWO-->>TR: not found
        TR-->>Caller: Err
    else valid
        TR->>TR: execute via normal dispatch path
        TR->>TWO: remove prepared commit
        TR-->>Caller: Ok(result)
    end
```

The idempotency key must be purely semantic; timestamps or random components are forbidden because they would reopen the double-execution hole.

---

## OBO Authorization

`OboDispatcher` enforces on-behalf-of authorization with three layers:

1. **Layer 1 — Harness/role grants**: scoped declared grants.
2. **Layer 2 — Issued credential scope**: the user's actual token scopes (e.g., GitLab, Graph consent).
3. **Layer 3 — Clearance**: maximum data class the user may touch.

```mermaid
flowchart TB
    subgraph OBO["OboDispatcher"]
        POLICY["OboPolicy"]
        SINK["OboDecisionSink"]
    end

    REQ["Dispatch Request"]
    REQ -->|user_id + grants + issued_scope + clearance + depth| POLICY
    POLICY -->|OboDecision| SINK
    SINK -->|audit| EVENTLOG["EventLog / VecOboAudit"]
```

There is no ambient fallback. A denied OBO call returns a structured `OboDenial` and is recorded in the audit sink (`VecOboAudit`, `EventLogOboAudit`, or `NoOboAudit`).

---

## Reconciliation and Sweeper

When a `Pending` row is left in the ledger (crash, lost ack, downstream timeout), the `ReconcilerSweeper` resolves it:

```mermaid
sequenceDiagram
    autonumber
    participant SW as ReconcilerSweeper
    participant LEDGER as Ledger
    participant RECON as Reconciler Probe
    participant ESC as EscalationSink

    SW->>LEDGER: find PENDING rows older than min_age
    loop each row
        SW->>LEDGER: try_take_lease(row)
        alt lease taken
            SW->>RECON: probe(tool, args)
            RECON-->>SW: Committed / Failed / Ambiguous
            alt Committed
                SW->>LEDGER: move to COMMITTED, backfill result
            else Failed
                SW->>LEDGER: move to FAILED
            else Ambiguous
                SW->>ESC: record ReconIncident
            end
        else leased by another node
            SW->>SW: skip
        end
    end
    SW-->>Caller: SweepReport
```

The sweeper is designed to be safe to run concurrently: leases prevent double-probe, and ambiguous rows are escalated rather than guessed.

---

## Sagas

Multi-step side effects run as sagas with compensation. Each `LedgerSagaStep` carries:

- `name` — human-readable step name.
- `key` — semantic idempotency key for the step.
- `action` — the forward effect.
- `compensate` — the compensating action.

```mermaid
flowchart LR
    S1["Step 1: action + compensate"]
    S2["Step 2: action + compensate"]
    S3["Step 3: action + compensate"]

    S1 -->|success| S2 -->|success| S3
    S2 -->|failure| C2["compensate Step 2"]
    C2 --> C1["compensate Step 1"]
```

Sagas extend the single-tool exactly-once guarantee to coordinated sequences.

---

## Dependencies

The `tools_cli_tool_runtime` module depends on several other modules in the system:

| Dependency Module | Purpose |
|-------------------|---------|
| [`tools_cli_client_sdk`](tools_cli_client_sdk.md) | Higher-level invokers and transport abstractions that call into the runtime. |
| [`tools_cli_surface_profiles`](tools_cli_surface_profiles.md) | Surface profiles and policies that configure runtime behavior. |
| [`governance_compliance_payments`](governance_compliance_payments.md) | `PaymentEffectClass`, `MandateRegistry`, and payment-adjacent mandate enforcement. |
| [`core_infrastructure_security_config`](core_infrastructure_security_config.md) | `DataClass`, `Principal`, and token/config primitives. |
| [`ai_engine_safety_guardrails`](ai_engine_safety_guardrails.md) | Injection detection and guardrail inputs for data-class classification. |
| [`core_infrastructure_connectors`](core_infrastructure_connectors.md) | Connector runtime and MCP registry integration for MCP capabilities. |
| [`core_infrastructure_application_runtime`](core_infrastructure_application_runtime.md) | Plugin host and WASM sandbox for plugin capabilities. |

```mermaid
flowchart TB
    TR["tools_cli_tool_runtime"]

    TR -->|invoked by| CLIENT["tools_cli_client_sdk"]
    TR -->|configured by| PROFILE["tools_cli_surface_profiles"]
    TR -->|effect class + mandates| PAYMENTS["governance_compliance_payments"]
    TR -->|DataClass + Principal| SECURITY["core_infrastructure_security_config"]
    TR -->|classification input| GUARDRAILS["ai_engine_safety_guardrails"]
    TR -->|MCP tools| CONNECTORS["core_infrastructure_connectors"]
    TR -->|plugin host| APP_RUNTIME["core_infrastructure_application_runtime"]
```

---

## Safety and Invariants

The module enforces several critical invariants:

1. **Payment-initiating tools are structurally non-dispatchable.** `EffectClass::PaymentInitiating` has no dispatch arm.
2. **Side-effecting tools require a purely semantic idempotency key.** Missing or non-semantic keys are refused.
3. **No ambient fallback for OBO authorization.** Every call is authorized as a specific user or denied.
4. **Hooks refuse, not just warn.** A guardrail that only logs is decoration.
5. **Data-class classification escalates to the most sensitive signal.** Disagreement never averages down.
6. **Reconciliation escalates ambiguity.** Rows that cannot be probed are paged, not silently re-run.
7. **Two-phase commit is mandatory for `HighRisk` tools.** Direct dispatch is refused.

---

## Integration with the Broader System

The Tool Runtime sits at the boundary between the conversational/surface layer and the outside world. It is called by:

- The [`tools_cli_client_sdk`](tools_cli_client_sdk.md) invokers (`RecordingInvoker`, `LeakThenRecordInvoker`, etc.).
- The runtime engine in [`pipeline_runtime_runtime_engine`](pipeline_runtime_runtime_engine.md) via surfaces like `WorkforceSurface` and `PromptOptimizerSurface`.
- The server layer in [`pipeline_runtime_server_serving`](pipeline_runtime_server_serving.md) through HTTP request handlers.

It delegates outward to:

- Connectors and MCP servers for external tool discovery and execution.
- The payment boundary for mandate checks on payment-adjacent actions.
- The event log for durable audit records.

---

## References

- [`tools_cli`](tools_cli.md) — parent module overview.
- [`tools_cli_client_sdk`](tools_cli_client_sdk.md) — client SDK and invokers.
- [`tools_cli_surface_profiles`](tools_cli_surface_profiles.md) — surface profiles and runtime configuration.
- [`governance_compliance_payments`](governance_compliance_payments.md) — payment boundary and effect classification.
- [`core_infrastructure_security_config`](core_infrastructure_security_config.md) — security primitives (`DataClass`, `Principal`).
- [`ai_engine_safety_guardrails`](ai_engine_safety_guardrails.md) — injection detection and content guardrails.
- [`core_infrastructure_connectors`](core_infrastructure_connectors.md) — connector and MCP runtime.
- [`core_infrastructure_application_runtime`](core_infrastructure_application_runtime.md) — plugin and WASM runtime.
- [`pipeline_runtime_runtime_engine`](pipeline_runtime_runtime_engine.md) — runtime engine integration.
- [`pipeline_runtime_server_serving`](pipeline_runtime_server_serving.md) — server and serving infrastructure.
