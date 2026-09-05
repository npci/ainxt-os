# surface_conversation Module

## Introduction

The `surface_conversation` module is the **user-facing conversation runtime** of the AiNxt platform. It sits at the boundary between declarative surface profiles and the core execution engine, assembling multi-turn chat and command interactions into grounded, audited, and policy-enforced turns. The module's responsibility is to take a resolved [`SurfaceProfile`](surface_conversation_binding.md), a caller [`Principal`](security_config.md), and a user message, and produce a complete turn plan that the runtime engine can execute safely.

The module is composed of three tightly integrated subsystems:

- **Chat Surface** ([`surface_conversation_chat`](surface_conversation_chat.md)) â€” the end-to-end assembled chat surface that wires retrieval, intent classification, prompt assembly, compliance redaction, caching, and streaming into a single [`TurnHandler`](core_interaction.md).
- **Conversation Intelligence** ([`surface_conversation_intelligence`](surface_conversation_intelligence.md)) â€” the session memory, intent cascade, referent resolution, command pipelines, and answer verification layer that sits above the engine.
- **Surface Binding** ([`surface_conversation_binding`](surface_conversation_binding.md)) â€” the profile-to-runtime binding that turns a declarative surface profile into a concrete [`TurnPlan`](surface_conversation_binding.md) and enforces admission, data-class ceilings, capability intersection, and autonomy policy.

## Architecture Overview

```mermaid
flowchart TB
    subgraph Surface["Surface Layer"]
        CATALOG[SurfaceCatalog]
        BIND[SurfaceBinding]
        PLAN[TurnPlan]
        ART[SurfaceArtifacts]
    end

    subgraph Convo["Conversation Intelligence"]
        CM[ConversationManager]
        HC[HeuristicClassifier]
        MIC[ModelIntentClassifier]
        CP[CommandPipelineRegistry]
        SESS[SessionStore]
        VER[AnswerVerifier]
    end

    subgraph Chat["Chat Surface"]
        CS[ChatSurface]
        SSA[SurfaceScopedAuthorizer]
        CACHE[PartitionedCache]
    end

    subgraph Runtime["Core Runtime"]
        ENG[Engine]
        ROUTER[ModelRouter]
        AUTHZ[RbacAuthorizer]
        RED[StrongRedactor]
    end

    subgraph Profiles["Configuration"]
        SP[SurfaceProfile]
        SK[SkillRuntime]
    end

    SP --> CATALOG
    CATALOG --> BIND
    SK --> BIND
    BIND --> PLAN
    PLAN --> CS
    CS --> CM
    CM --> ENG
    CM --> HC
    CM --> MIC
    CM --> CP
    CM --> SESS
    CM --> VER
    CS --> CACHE
    SSA --> ENG
    ART --> CS

    style Surface fill:#e1f5fe
    style Convo fill:#e8f5e9
    style Chat fill:#fff3e0
    style Runtime fill:#f3e5f5
    style Profiles fill:#fff8e1
```

## High-Level Data Flow

A single chat turn flows through the module as follows:

```mermaid
sequenceDiagram
    participant User
    participant SM as SessionManager
    participant CS as ChatSurface
    participant Cache as PartitionedCache
    participant CM as ConversationManager
    participant SB as SurfaceBinding
    participant ENG as Engine
    participant Prov as Provider

    User->>SM: send turn
    SM->>SB: plan(principal, input, data_class)
    SB-->>SM: TurnPlan
    SM->>CS: handle_turn(principal, Request)
    CS->>Cache: get_tiered(partition, key)
    alt cache hit
        Cache-->>CS: cached answer
        CS->>ENG: authorize + audit short-circuit
        CS-->>SM: stream cached answer
    else cache miss
        CS->>CM: run_turn_streaming
        CM->>CM: classify intent
        CM->>CM: resolve referent/action
        CM->>CM: retrieve + rank context
        CM->>CM: assemble prompt
        CM->>ENG: run turn
        ENG->>Prov: model call
        Prov-->>ENG: token stream
        ENG-->>CM: final summary
        CM-->>CS: ManagerOutcome
        CS->>Cache: put(redacted answer)
        CS-->>SM: stream answer
    end
```

## Sub-modules

### [surface_conversation_chat](surface_conversation_chat.md)

The Chat Surface is the **integration seam** that assembles everything the lower crates build in isolation into one end-to-end flow. It owns:

- [`ChatSurface`](surface_conversation_chat.md) â€” the assembled chat surface implementing [`TurnHandler`](core_interaction.md).
- [`SurfaceScopedAuthorizer`](surface_conversation_chat.md) â€” narrows tool/connector authorization to the surface's declared capability set.
- Scoping-safe, tiered response caching keyed by clearance, data class, session, and harness id.
- Streaming turn handling with cache short-circuit authorization and audit.

See [surface_conversation_chat.md](surface_conversation_chat.md) for details.

### [surface_conversation_intelligence](surface_conversation_intelligence.md)

The Conversation Intelligence layer is the "chat-done-right" brain above the engine. It owns:

- [`ConversationManager`](surface_conversation_intelligence.md) â€” session memory, intent cascade, retrieval, prompt assembly, and answer composition.
- [`HeuristicClassifier`](surface_conversation_intelligence.md) and [`ModelIntentClassifier`](surface_conversation_intelligence.md) â€” deterministic and model-backed intent classification.
- [`CommandPipelineRegistry`](surface_conversation_intelligence.md) â€” git-native slash-command macro expansion.
- [`AnswerVerifier`](surface_conversation_intelligence.md) â€” numeric re-derivation and faithfulness/conflict gates.
- Session stores ([`InMemorySessions`](surface_conversation_intelligence.md), [`PersistentSessions`](surface_conversation_intelligence.md)).

See [surface_conversation_intelligence.md](surface_conversation_intelligence.md) for details.

### [surface_conversation_binding](surface_conversation_binding.md)

The Surface Binding layer turns declarative profiles into executable plans. It owns:

- [`SurfaceBinding`](surface_conversation_binding.md) â€” binds a [`SurfaceProfile`](security_config.md) and [`SkillRuntime`](application_runtime.md) to plan turns.
- [`TurnPlan`](surface_conversation_binding.md) â€” the concrete inputs the engine needs for one turn.
- [`SurfaceCatalog`](surface_conversation_binding.md) â€” registry of resolved surface profiles with layered deployment/tenant overrides.
- [`SurfaceArtifacts`](surface_conversation_binding.md) â€” shared artifact-generation runtime for document output.

See [surface_conversation_binding.md](surface_conversation_binding.md) for details.

## Module Boundaries and Dependencies

The `surface_conversation` module depends on several other modules documented elsewhere:

| Dependency | Module | Purpose |
|------------|--------|---------|
| `ainxt_runtime::Engine` | [runtime_engine](runtime_engine.md) | Core turn execution, provider routing, compliance redaction, audit. |
| `ainxt_session::SessionManager` | [core_interaction](core_interaction.md) | Session concurrency spine that drives `ChatSurface` as a `TurnHandler`. |
| `ainxt_profile::SurfaceProfile` | [security_config](security_config.md) | Declarative surface behavior (persona, capabilities, model policy, RBAC). |
| `ainxt_skill::SkillRuntime` | [skill_execution](skill_execution.md) | Prepares behavioral/execution skills for prompt/context assembly. |
| `ainxt_context` / `ainxt_retrieval` | [knowledge_retrieval](knowledge_retrieval.md) | Grounded retrieval, ranking, and citation assembly. |
| `ainxt_prompt` | [prompt_engineering](prompt_engineering.md) | Layered prompt service and model-agnostic prompt assembly. |
| `ainxt_answer` / `ainxt_artifact` | [answer_artifact](answer_artifact.md) | Answer composition and artifact rendering. |
| `ainxt_guardrails` / `ainxt_injection` | [safety_guardrails](safety_guardrails.md) | Output-side guardrails and retrieved-content injection defense. |
| `ainxt_cache` | [core_interaction](core_interaction.md) | Partition-isolated response cache. |

## Key Design Principles

1. **Fail-closed by default** â€” A surface refuses a turn if the principal fails admission, the data class exceeds the surface ceiling, or a request override attempts to widen authority.
2. **Least-privilege capability intersection** â€” Effective authority is always `surface.offered âˆ© principal.held`; the surface can never escalate a principal.
3. **Runtime owns control-flow** â€” Intent classifiers only recommend; the runtime decides whether to answer, clarify, generate an artifact, or execute an action.
4. **Referent resolution** â€” Content-consuming actions resolve the *prior answer* as content, never treat the instruction itself as content.
5. **Scoping-safe caching** â€” Cache partitions are isolated by data class, principal scope, and harness id; sensitive classes are never cached.
6. **Audit-and-proceed artifacts** â€” Document generation records compliance findings but never redacts content inside rendered artifacts.

## Mermaid: Component Interaction

```mermaid
flowchart LR
    subgraph Input["User Input"]
        MSG[message + principal + data_class]
    end

    subgraph surface_conversation
        SB[SurfaceBinding]
        TP[TurnPlan]
        CM[ConversationManager]
        CS[ChatSurface]
    end

    subgraph External
        PROF[SurfaceProfile]
        SKILLS[SkillRuntime]
        ENG[Engine]
        CACHE[PartitionedCache]
    end

    MSG --> SB
    PROF --> SB
    SKILLS --> SB
    SB --> TP
    TP --> CS
    CS --> CM
    CM --> ENG
    CS --> CACHE
    CM --> CACHE
```

## Related Documentation

- [surface_conversation_chat.md](surface_conversation_chat.md) — Chat surface assembly, scoped authorizer, and tiered caching.
- [surface_conversation_intelligence.md](surface_conversation_intelligence.md) — Conversation manager, intent classifiers, command pipelines, and answer verification.
- [surface_conversation_binding.md](surface_conversation_binding.md) — Surface binding, turn plans, catalog, and artifact generation.
