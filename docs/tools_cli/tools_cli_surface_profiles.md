# tools_cli_surface_profiles — Surface Profile Schema & Layered Loader

## Brief Introduction

The `tools_cli_surface_profiles` module (crate `ainxt-profile`) defines the **declarative Surface Profile** schema and its layered resolution/validation engine. A product surface — such as Chat, Buddy, Code, or SDLC — is not a separate runtime; it is a **Renderer** plus a **Surface Profile** that configures the shared AI spine for that surface's persona, capabilities, model routing, autonomy, RBAC floor, retrieval scope, and prompt policy.

The crate's core responsibility is to answer one question: *"Given a stack of configuration layers, what is the effective, validated profile for this surface on this turn?"* It resolves profiles through a deep TOML merge (`defaults → deployment → tenant → profile → request`, most-specific last) and enforces hard safety invariants: a profile can **declare** authority but never **escalate** a principal, and a per-turn request layer may only narrow — never widen — the surface's authority.

All enterprise-hard concerns (compliance, RBAC enforcement, budget, audit) remain in the spine; the profile only declares intent. The engine enforces.

---

## Core Concepts

| Concept | Description |
|---------|-------------|
| **Surface Profile** | A validated, resolved configuration (`SurfaceProfile`) describing how one product surface behaves. |
| **Layered Resolution** | Deep TOML merge across `defaults`, `deployment`, `tenant`, `profile`, and `request` layers. |
| **Safety Invariant** | Profiles default to the safest posture (`Autonomy::ReadOnly`); request layers can only narrow authority. |
| **Effective Authority** | `capabilities`/`connectors` offered by the profile are intersected with the calling principal's RBAC by the engine. |
| **Turn-Time Override** | `with_request_layer` allows a single turn to tweak narrow preferences (reasoning depth, output format, tier) without changing identity, RBAC, or autonomy. |

---

## Architecture

### High-Level Module Position

```mermaid
flowchart TB
    subgraph tools_cli["tools_cli"]
        direction TB
        headless[tools_cli_headless_cli]
        client_sdk[tools_cli_client_sdk]
        tool_runtime[tools_cli_tool_runtime]
        surface_profiles[tools_cli_surface_profiles]
        integration_tests[tools_cli_integration_tests]
    end

    subgraph core_infra["core_infrastructure"]
        config[ainxt-config Loader / merge_toml]
        types[ainxt-types DataClass / Role / Tier]
    end

    subgraph app_runtime["application_runtime"]
        surface[ainxt-surface TurnPlan / SurfaceBinding]
        chat[ainxt-chat ChatSurface]
        convo[ainxt-convo ConversationManager]
    end

    subgraph pipeline_runtime["pipeline_runtime"]
        runtime[ainxt-runtime Engine]
        runtimed[ainxt-runtimed surfaces]
    end

    surface_profiles -->|uses| config
    surface_profiles -->|uses| types
    surface_profiles -->|consumed by| surface
    surface_profiles -->|consumed by| chat
    surface_profiles -->|consumed by| convo
    surface_profiles -->|consumed by| runtimed
    runtimed -->|drives| runtime
```

### Component Diagram

```mermaid
classDiagram
    class SurfaceProfile {
        +String id
        +String persona
        +Vec~String~ capabilities
        +Vec~String~ skills
        +Vec~String~ connectors
        +ModelPolicy model_policy
        +Autonomy autonomy
        +RbacPolicy rbac
        +ContextStrategy context
        +PromptPolicy prompt
        +resolve(layers) Result~SurfaceProfile, ProfileError~
        +from_toml(src) Result~SurfaceProfile, ProfileError~
        +validate() Result~(), ProfileError~
        +with_request_layer(request_toml) Result~SurfaceProfile, ProfileError~
        +offers_capability(cap) bool
        +offers_connector(id) bool
        +allows_side_effects() bool
        +requires_approval() bool
        +is_autonomous() bool
    }

    class ModelPolicy {
        +Tier default_tier
        +bool pin_tier
        +Option~String~ forced_provider
        +Vec~String~ allowed_providers
        +DataClass max_data_class
    }

    class RbacPolicy {
        +Role min_role
        +Vec~String~ required_caps
        +bool department_scoped
        +Option~u8~ max_ad_level
    }

    class ContextStrategy {
        +RetrievalScope retrieval
        +u32 history_budget_tokens
        +bool condenser
    }

    class PromptPolicy {
        +ReasoningPref reasoning
        +NumericPref numeric
        +OutputPref output
    }

    class Autonomy {
        <<enumeration>>
        ReadOnly
        Suggest
        ActWithApproval
        Autonomous
    }

    class RetrievalScope {
        <<enumeration>>
        None
        PlatformAndNamespace
        RepoScoped
    }

    class ReasoningPref {
        <<enumeration>>
        Auto
        Shallow
        Standard
        Deep
    }

    class NumericPref {
        <<enumeration>>
        Allow
        ToolsOnly
    }

    class OutputPref {
        <<enumeration>>
        Text
        Markdown
        Json
    }

    class ProfileError {
        <<enumeration>>
        Load(String)
        MissingField(&'static str)
        Invalid(String)
    }

    SurfaceProfile --> ModelPolicy
    SurfaceProfile --> RbacPolicy
    SurfaceProfile --> ContextStrategy
    SurfaceProfile --> PromptPolicy
    SurfaceProfile --> Autonomy
    ContextStrategy --> RetrievalScope
    PromptPolicy --> ReasoningPref
    PromptPolicy --> NumericPref
    PromptPolicy --> OutputPref
    SurfaceProfile ..> ProfileError : returns
```

---

## Component Reference

### `SurfaceProfile`

The top-level resolved profile. It is `Default`-derived so every omitted field falls back to a safe default. The struct is serializable with `serde` and validated after resolution.

Key methods:

- **`resolve(layers)`** — deep-merges ordered TOML layers and validates the result.
- **`from_toml(src)`** — convenience single-layer parse.
- **`validate()`** — ensures `id` is non-empty and `forced_provider` is inside `allowed_providers` when the allow-list is non-empty.
- **`with_request_layer(request_toml)`** — applies a turn-time request layer on top of an already-resolved profile, then enforces narrowing invariants.
- **`offers_capability` / `offers_connector`** — exact-match queries used by the engine to intersect with principal RBAC.
- **`allows_side_effects` / `requires_approval` / `is_autonomous`** — autonomy helpers.

### `ModelPolicy`

Controls model routing inputs. The runtime's router and data-class gate enforce the policy.

- `default_tier` — fallback complexity tier.
- `pin_tier` — when `true`, the surface hard-pins every turn to `default_tier`; the engine fails closed if no eligible provider exists at that tier.
- `forced_provider` — optional pinned provider (still subject to data-class exclusion).
- `allowed_providers` — provider allow-list; empty means any eligible provider.
- `max_data_class` — compliance ceiling for data the surface may handle.

### `RbacPolicy`

Declares the RBAC floor a principal must meet. The engine's authz gate enforces it; the profile never escalates a principal.

- `min_role` — minimum `Role` required.
- `required_caps` — capability claims required to use the surface.
- `department_scoped` — whether data is scoped by the principal's department.
- `max_ad_level` — optional Active Directory seniority ceiling (`0` = most senior, `6` = junior); principals without an `ad_level` claim are fail-closed refused.

### `ContextStrategy`

Configures how context is assembled.

- `retrieval` — `None`, `PlatformAndNamespace`, or `RepoScoped`.
- `history_budget_tokens` — token budget for conversation-history tail.
- `condenser` — whether the condenser may compress history when over budget.

### `PromptPolicy`

Mapped to the Prompt Engine in the runtime binding.

- `reasoning` — default reasoning depth (`Auto`, `Shallow`, `Standard`, `Deep`).
- `numeric` — whether numeric/tabular reasoning must go through tools (`Allow` vs `ToolsOnly`).
- `output` — preferred output rendering (`Text`, `Markdown`, `Json`).

### `Autonomy`

Ordered least-to-most capable:

1. `ReadOnly` — no side effects.
2. `Suggest` — may propose drafts/diffs but not execute.
3. `ActWithApproval` — may execute side-effecting tools, each requiring HITL approval.
4. `Autonomous` — may execute side-effecting tools without per-action approval (still RBAC-gated).

---

## Data Flow

### Profile Resolution Flow

```mermaid
sequenceDiagram
    autonumber
    participant Caller as Surface / Runtime
    participant SP as SurfaceProfile
    participant Loader as ainxt_config::Loader
    participant Validator as validate()

    Caller->>SP: resolve([defaults, deployment, tenant, profile, request])
    loop Each layer in order
        SP->>Loader: loader.layer(name, toml_src)
    end
    SP->>Loader: loader.resolve()
    Loader-->>SP: deserialized SurfaceProfile
    SP->>Validator: validate()
    alt valid
        Validator-->>SP: Ok(())
        SP-->>Caller: Ok(SurfaceProfile)
    else invalid
        Validator-->>SP: Err(ProfileError)
        SP-->>Caller: Err(...)
    end
```

### Turn-Time Request Layer Flow

```mermaid
sequenceDiagram
    autonumber
    participant Turn as Turn / Request
    participant SP as SurfaceProfile
    participant Merge as merge_toml
    participant Invariant as enforce_request_layer_invariants

    Turn->>SP: with_request_layer(request_toml)
    SP->>SP: serialize base profile to toml::Value
    SP->>Merge: merge_toml(base, request)
    Merge-->>SP: merged toml::Value
    SP->>SP: deserialize merged SurfaceProfile
    SP->>SP: validate()
    SP->>Invariant: check narrowing invariants
    alt narrowing only
        Invariant-->>SP: Ok(())
        SP-->>Turn: Ok(SurfaceProfile)
    else widening detected
        Invariant-->>SP: Err(ProfileError::Invalid)
        SP-->>Turn: Err(...)
    end
```

---

## Layered Merge Semantics

```mermaid
flowchart LR
    A[defaults] --> B[deployment]
    B --> C[tenant]
    C --> D[profile]
    D --> E[request]
    E --> F[resolved SurfaceProfile]

    style A fill:#f9f,stroke:#333
    style E fill:#bbf,stroke:#333
    style F fill:#bfb,stroke:#333
```

- **Deep merge** — nested tables are recursively merged; later layers override scalar values in the same path.
- **Arrays replace** — a later array fully replaces an earlier array (not concatenated).
- **Most-specific wins** — `request` is the last layer and has the highest precedence.
- **Safe defaults** — omitted fields use `Default`, e.g. `Autonomy::ReadOnly`, `RetrievalScope::PlatformAndNamespace`, `Tier::Simple`.

---

## Request-Layer Narrowing Invariants

A request layer may only **narrow or hold** authority. The following changes are **rejected** (fail-closed):

| Attempted Change | Result |
|------------------|--------|
| Change `id` | Rejected |
| Change `persona` | Rejected |
| Change `skills` | Rejected |
| Change `rbac` floor | Rejected |
| Change `capabilities` | Rejected |
| Change `connectors` | Rejected |
| Change `autonomy` | Rejected |
| Change `context` / `retrieval` | Rejected |
| Change `model_policy.max_data_class` ceiling | Rejected |
| Change `model_policy.allowed_providers` allow-list | Rejected |
| Remove a deployment-pinned `pin_tier` | Rejected |
| Override a deployment-pinned `forced_provider` | Rejected |
| Select a `forced_provider` outside the allow-list | Rejected |
| Loosen `numeric` discipline (`tools-only` → `allow`) | Rejected |

Allowed narrowing tweaks include:

- `model_policy.default_tier`
- `prompt.reasoning`
- `prompt.output`
- Setting `forced_provider` when unset and within the allow-list
- Strengthening `numeric` (`allow` → `tools-only`)

---

## Dependencies

### Direct Crate Dependencies

| Crate | Module | Usage |
|-------|--------|-------|
| `ainxt-config` | [`core_infrastructure`](../core_infrastructure/core_infrastructure.md) | `Loader` for deep TOML merge and `merge_toml` for request-layer override. |
| `ainxt-types` | [`core_infrastructure`](../core_infrastructure/core_infrastructure.md) | `DataClass`, `Role`, `Tier` vocabulary. |
| `serde` / `toml` | external | Serialization and TOML parsing. |

### Consumers

| Crate | Module | Relationship |
|-------|--------|--------------|
| `ainxt-surface` | [`application_runtime`](../core_infrastructure/application_runtime.md) | `TurnPlan` and `SurfaceBinding` consume the profile to plan a turn. |
| `ainxt-chat` | [`application_runtime`](../core_infrastructure/application_runtime.md) | `ChatSurface` binds a profile to a chat surface. |
| `ainxt-convo` | [`application_runtime`](../core_infrastructure/application_runtime.md) | `ConversationManager` uses profile-derived context strategy. |
| `ainxt-runtimed` | [`pipeline_runtime`](../pipeline_runtime/pipeline_runtime.md) | Runtime surfaces (`chat_identity`, `fabric_chat`, `workforce_surface`, `prompt_optimizer_surface`) load and apply profiles. |
| `ainxt-runtime` | [`pipeline_runtime`](../pipeline_runtime/pipeline_runtime.md) | `Engine` enforces the model policy, RBAC, and data-class ceiling declared by the profile. |

---

## Error Model

`ProfileError` is the crate's only error type:

- **`Load(String)`** — parse or merge/deserialize failure.
- **`MissingField(&'static str)`** — required field absent after resolution (currently `id`).
- **`Invalid(String)`** — internal inconsistency or request-layer invariant violation.

All failures are fail-closed: an invalid profile cannot be used.

---

## Integration with the Wider System

```mermaid
flowchart TB
    subgraph profile["tools_cli_surface_profiles"]
        SP[SurfaceProfile]
    end

    subgraph config_layer["Configuration Layer"]
        Loader[ainxt_config::Loader]
        Merge[ainxt_config::merge_toml]
    end

    subgraph authz["Authorization"]
        RBAC[Principal RBAC]
        EngineAuthz[Engine Authz Gate]
    end

    subgraph runtime["Runtime"]
        TurnPlan[ainxt_surface::TurnPlan]
        Engine[ainxt_runtime::Engine]
        PromptEngine[Prompt Engine]
    end

    SP -->|declares| Capabilities[capabilities / connectors]
    RBAC -->|intersects| Capabilities
    EngineAuthz -->|enforces| Capabilities
    SP -->|drives| TurnPlan
    TurnPlan -->|feeds| Engine
    SP -->|prompt policy| PromptEngine
    SP -->|model policy| Engine
```

The profile is a **declaration**; the engine is the **enforcer**. This separation is intentional: enterprise-hard concerns such as compliance, RBAC, budget, and audit remain in the spine, while the profile provides a product-surface-specific configuration layer.

---

## Testing Strategy

The crate's inline tests cover:

- Safe defaults for a minimal profile.
- Deep layered merge with most-specific-wins semantics.
- Array replacement behavior.
- Validation of required fields and provider allow-lists.
- Unknown-field rejection (`deny_unknown_fields`).
- Autonomy helper correctness.
- Capability/connector query helpers.
- JSON serde round-tripping.
- Request-layer narrowing invariants (R15).
- Tier-pin policy (`pin_tier`) behavior.
- Numeric discipline strengthening.

---

## Related Documentation

- [`tools_cli.md`](tools_cli.md) — parent module overview (CLI, client SDK, tool runtime, profiles, integration tests).
- [`tools_cli_tool_runtime.md`](tools_cli_tool_runtime.md) — tool runtime and capability/connector execution.
- [`core_infrastructure.md`](../core_infrastructure/core_infrastructure.md) — `ainxt-config` loader and `ainxt-types` vocabulary.
- [`application_runtime.md`](../core_infrastructure/application_runtime.md) — surfaces, chat, and conversation runtime that consume profiles.
- [`pipeline_runtime.md`](../pipeline_runtime/pipeline_runtime.md) — runtime engine and served surfaces that enforce profile policies.
