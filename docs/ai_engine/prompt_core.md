# prompt_core — Prompt Engineering Core

The `prompt_core` module (`crates/ainxt-prompt`) is the runtime heart of the system's prompt-engineering discipline. It treats prompts as versioned, model-agnostic, auditable code artifacts rather than ad-hoc strings. The module is responsible for:

* **Prompts-as-code lifecycle** — versioned layer artifacts (L1–L4), git-native loading, eval-gated promotion, canary/rollback-by-pointer, and per-model variant serving.
* **Deterministic assembly** — composing L1 persona, L2 policy, L3 task, L4 guards, and L5 context into a plain-structured-text system prompt that works across Claude, OpenAI, Gemini, and in-house OSS families (Qwen/GLM/Gemma/Kimi).
* **Safety rails** — output-side system-prompt-leak detection, numeric-via-tools enforcement, and indirect-prompt-injection provenance gating that do **not** trust the model's own judgment.
* **Quality operations** — canary auto-promote/rollback, continuous production drift detection, and steerability scoring that gates model eligibility.
* **Structured output** — schema-valid JSON generation via native grammar decoding or a bounded repair loop, generalized to every structured-output call site in the system.

`prompt_core` sits under `ai_engine → prompt_engineering` and is consumed by the runtime surfaces in `ainxt-runtimed`, the HTTP server in `ainxt-server`, and the conversation manager in `ainxt-convo`. It depends on `ainxt-eval` for eval gates and quality judging, and on `ainxt-types` for routing tiers.

---

## Architecture Overview

```mermaid
flowchart TB
    subgraph Source["Prompt Source"]
        Files[(Git-native prompt files<br/>definition.json + variant.*.md)]
        Defaults[(Shipped default<br/>canonical bodies)]
    end

    subgraph Registry["Prompt Registry & Lifecycle"]
        CP[ControlPlane loader]
        Reg[Registry]
        Dep[Deployment<br/>prod / prod-canary]
        Rel[Release pins]
    end

    subgraph Assembly["Prompt Assembly"]
        Flat[Flat PromptEngine]
        Layered[LayeredAssembler]
        Policy[PolicyEngineConfig]
    end

    subgraph Safety["Safety Rails"]
        Leak[LeakRail]
        Num[Numeric enforcement]
        ToolGate[Tool-call provenance gate]
    end

    subgraph Quality["Quality Operations"]
        Canary[CanaryController]
        Drift[DriftController]
        Steer[Steerability scoring]
    end

    subgraph Structured["Structured Output"]
        SOE[StructuredOutputEngine]
    end

    Files -->|load + verify control.lock| CP
    CP --> Reg
    Defaults --> served
    served --> Reg
    Reg -->|pin| Rel
    Rel --> Dep
    Dep -->|serve + verify| Layered
    Policy --> Layered
    Flat -->|adaptive depth| Layered
    Layered --> Compiled[CompiledSystemPrompt]
    Compiled -->|output| Leak
    Compiled -->|secret| Leak
    Leak -->|safe output| Num
    Num -->|verdict| Downstream
    ToolGate -->|confirm?| Downstream
    Canary -->|pointer flip| Dep
    Drift -->|rollback| Dep
    Steer -->|eligibility| served
    SOE -->|schema-valid JSON| Downstream
```

### Layer Model (L1–L5)

The system prompt is assembled from five ordered layers:

| Layer | Purpose | Source | Key type |
|-------|---------|--------|----------|
| L1 | Persona / identity | Registry artifact | `Layer::Persona` |
| L2 | Org / config policy | `PolicyEngineConfig` (config-sourced) | `Layer::Policy` |
| L3 | Task instructions | Registry artifact | `Layer::Task` |
| L4 | Guard prompts | Registry artifact (`guard::GUARD_BODY`) | `Layer::Guards` |
| L5 | Per-turn context | Context Fabric / runtime | untrusted data |

L1–L4 are versioned, per-model artifacts loaded from the prompt tree; L5 is the per-turn untrusted context slice. Guards sit immediately above L5 to maximize recency-based adherence.

---

## Sub-modules

The module is split into five sub-modules for detailed documentation:

* **[prompt_core_registry](prompt_core_registry.md)** — `registry`, `control`, `served`, and `policy`: the prompts-as-code registry, git-native loader, lifecycle gates, deployment pins, and config-sourced L2 policy.
* **[prompt_core_assembly](prompt_core_assembly.md)** — `lib` and `layered`: the flat `PromptEngine` and the `LayeredAssembler` that builds the five-layer system prompt, including adaptive reasoning depth and token-budget condensation.
* **[prompt_core_safety](prompt_core_safety.md)** — `guard`, `numeric`, and `service`: output-side leak rail, numeric-via-tools enforcement, indirect-injection tool-call gate, and the per-turn `PromptService` / `ServedPromptEngine` wiring.
* **[prompt_core_quality](prompt_core_quality.md)** — `canary`, `drift`, and `steerability`: canary promote/rollback, continuous quality-drift monitoring, and instruction-following steerability scoring.
* **[prompt_core_structured](prompt_core_structured.md)** — `constrained`: the `StructuredOutputEngine`, `JsonSchema`, and GBNF grammar generation that guarantee schema-valid JSON from every model.

---

## Data Flow: One Served Turn

```mermaid
sequenceDiagram
    participant RT as Runtime surface
    participant SPE as ServedPromptEngine
    participant PS as PromptService
    participant Reg as Registry
    participant Dep as Deployment
    participant LA as LayeredAssembler
    participant Sink as EventSink
    participant Prov as Provider

    RT->>SPE: compile_turn(family, context)
    SPE->>PS: compile_turn(registry, deployment, sink, ...)
    PS->>Reg: serve(deployment, routing_key, family, layer_ids)
    Reg->>Dep: select_release(routing_key)
    Dep-->>Reg: release + canary flag
    Reg->>Reg: verify variant fingerprint
    Reg-->>PS: Vec<ResolvedLayer>
    PS->>LA: assemble(resolved, context, family, control_sha)
    LA-->>PS: CompiledSystemPrompt
    PS->>Sink: record_prompt(event_record)
    PS-->>SPE: CompiledSystemPrompt
    SPE-->>RT: CompiledSystemPrompt
    RT->>Prov: model call with compiled text
    Prov-->>RT: raw output
    RT->>PS: inspect_output(secret, output, numeric_policy, tool_numbers)
    PS-->>RT: OutputVerdict
```

The forensic event record is written **before** the provider call, so a later timeout, cancellation, or panic still leaves a byte-for-byte replayable prompt on disk.

---

## Key Design Principles

1. **Prompts are code** — Every L1–L4 artifact has an id, semver, owner, author, eval-set FK, per-model variants, and a lifecycle stage (`Draft → Eval → Review → Canary → Production → Deprecated`).
2. **Model-agnostic plain text** — Compiled prompts use plain section markers (`[L1]`, `[L2]`, `[REASONING]`, `[L5-CONTEXT]`) so the same artifact works on frontier and in-house OSS models.
3. **Fail-closed serving** — `Registry::serve` verifies every variant body against the pinned content fingerprint in the release; a tampered or drifted body returns `ServeError::LockMismatch`.
4. **Rollback by pointer flip** — Canary and production releases are immutable; rollback/promotion is an instant ref flip, not a rewrite.
5. **Never trust the model** — Output rails (`LeakRail`, numeric enforcement, tool-call provenance gate) inspect model output independently of what the model "decided".
6. **Deterministic** — No clock, RNG, or I/O in the core; sampling, canary splits, and drift keys are driven by stable hashes of routing keys.

---

## Integration with the Wider System

```mermaid
flowchart LR
    subgraph PC["prompt_core"]
        direction TB
        R[Registry / Deployment]
        A[Assembly]
        S[Safety rails]
        Q[Quality ops]
        SO[Structured output]
    end

    subgraph Consumers["Downstream consumers"]
        RT[ainxt-runtimed surfaces]
        SV[ainxt-server HTTP API]
        CM[ainxt-convo conversation]
    end

    subgraph Deps["Dependencies"]
        Eval[ainxt-eval]
        Types[ainxt-types]
        Config[ainxt-config]
    end

    R --> A --> S
    Q --> R
    SO --> RT
    PC --> RT
    PC --> SV
    PC --> CM
    Eval --> PC
    Types --> PC
    Config -.re-exports.-> PC
```

* `ainxt-eval` provides `EvalReport`, `GatePolicy`, `QualityJudge`, and the statistical drop-in gate used by the registry lifecycle and drift monitoring.
* `ainxt-types` provides the `Tier` enum that `ReasoningDepth` maps to for routing.
* `ainxt-config` re-exports `PromptConfig` and `PolicyEngineConfig` through its layered TOML loader so deployments can configure prompts without depending directly on `ainxt-prompt`.

For details on each area, see the sub-module documentation: [prompt_core_registry.md](prompt_core_registry.md), [prompt_core_assembly.md](prompt_core_assembly.md), [prompt_core_safety.md](prompt_core_safety.md), [prompt_core_quality.md](prompt_core_quality.md), and [prompt_core_structured.md](prompt_core_structured.md).
