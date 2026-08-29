# surfaces_prompt_optimizer

## Brief Introduction

The `surfaces_prompt_optimizer` module is the live runtime surface that closes the gap between the offline prompt-optimization engine and the served system. It exposes the `ainxt-promptopt` search-and-rank pipeline as a recurring, daemon-driven cadence, bridges certified prompt winners into the prompt-registry as `DRAFT` artifacts, and wires real LLM providers into both the optimization seam and the constrained-decoding judge. In short, it turns prompt engineering from a library-only capability into a continuously running production process.

The module lives in `crates/ainxt-runtimed/src/prompt_optimizer_surface.rs` and is part of the `pipeline_runtime` → `runtime_engine` → `surfaces` subsystem.

---

## Module Purpose and Core Functionality

### What Problem It Solves

Before this surface existed, `ainxt-promptopt` provided a fully implemented optimizer, an A/B promotion helper, a holdout overfit guard, and a registry bridge — but none of them were reachable from the running daemon. The optimizer had callers only inside its own unit tests. `surfaces_prompt_optimizer` resolves that by:

1. **Providing a composition-root entrypoint** (`run_prompt_optimizer_sweep_tick`) that a daemon timer can call each cycle.
2. **Wiring real providers** into the optimizer through `ProviderModelSeam` and `ProviderConstrainedDecoder`.
3. **Bridging winners into the live prompt registry** as immutable, versioned `DRAFT` artifacts — never auto-promoting past `DRAFT`.
4. **Offering a fuller, more rigorous pipeline** (`run_prompt_optimizer_sweep_tick_v2`) that adds candidate generation, cost budgeting, holdout confirmation, and A/B non-inferiority checks against the live champion.
5. **Spawning the actual recurring tick** (`spawn_prompt_optimizer_tick`) when a real chat-classifier provider is configured.

### Core Operations

| Operation | Function | Description |
|-----------|----------|-------------|
| Simple sweep | `run_prompt_optimizer_sweep_tick` | Ranks a fixed variant list per model and registers a merged multi-family DRAFT. |
| Full pipeline sweep | `run_prompt_optimizer_sweep_tick_v2` | Proposes candidates under a budget, confirms on holdout, runs A/B promotion, then registers DRAFTs. |
| Cadence spawn | `spawn_prompt_optimizer_tick` | Conditionally starts a Tokio interval loop that drives both sweep functions each cycle. |
| Provider seam | `ProviderModelSeam` | Adapts any `Provider` to the `ModelSeam` interface the optimizer requires. |
| Constrained judge | `ProviderConstrainedDecoder` | Adapts any `Provider` to the `ConstrainedDecoder` interface for the constrained LLM judge. |

---

## Architecture and Component Relationships

### High-Level Architecture

```mermaid
flowchart TB
    subgraph RuntimeDaemon["Runtime Daemon (ainxt-runtimed)"]
        direction TB
        SPT["spawn_prompt_optimizer_tick"]
        V1["run_prompt_optimizer_sweep_tick"]
        V2["run_prompt_optimizer_sweep_tick_v2"]
        PMS["ProviderModelSeam"]
        PCD["ProviderConstrainedDecoder"]
        CLJ["ConstrainedLlmJudge"]
    end

    subgraph PromptEngineering["Prompt Engineering (ainxt-promptopt)"]
        OA["optimize_all"]
        OB["optimize_budgeted"]
        OWH["optimize_with_holdout"]
        ABP["ab_promote"]
        PROP["propose"]
        BRIDGE["winner_to_draft / register_draft"]
    end

    subgraph PromptRegistry["Prompt Registry (ainxt-prompt::registry)"]
        REG["Registry"]
        ART["LayerArtifact (DRAFT)"]
    end

    subgraph Providers["LLM Providers (ainxt-providers / ainxt-runtime)"]
        PROV["dyn Provider"]
    end

    subgraph Evaluation["Evaluation (ainxt-eval)"]
        GOLD["EvalCase / gold set"]
        QJ["QualityJudge"]
    end

    SPT -->|drives| V1
    SPT -->|drives| V2
    V1 -->|uses| OA
    V2 -->|uses| PROP
    V2 -->|uses| OB
    V2 -->|uses| OWH
    V2 -->|uses| ABP
    V1 -->|bridges| BRIDGE
    V2 -->|bridges| BRIDGE
    BRIDGE -->|registers| REG
    REG -->|stores| ART
    PMS -->|adapts| PROV
    PCD -->|adapts| PROV
    CLJ -->|uses| PCD
    V1 -->|scores via| CLJ
    V2 -->|scores via| CLJ
    V1 -->|evaluates| GOLD
    V2 -->|evaluates| GOLD
    QJ -.->|implemented by| CLJ
```

### Component Interaction

```mermaid
sequenceDiagram
    participant Daemon as spawn_prompt_optimizer_tick
    participant V1 as run_prompt_optimizer_sweep_tick
    participant V2 as run_prompt_optimizer_sweep_tick_v2
    participant Seam as ProviderModelSeam
    participant Judge as ConstrainedLlmJudge<br/>+ ProviderConstrainedDecoder
    participant OptS as ainxt-promptopt
    participant Bridge as winner_to_draft /<br/>register_draft
    participant Reg as Registry

    Daemon->>+V1: interval tick
    V1->>OptS: optimize_all(variants, gold, judge, seams)
    OptS-->>V1: per-model optimizations
    loop each model
        V1->>Bridge: winner_to_draft(family, variants, opt)
        Bridge-->>V1: single-family LayerArtifact
    end
    V1->>Bridge: register_draft(merged artifact)
    Bridge->>Reg: store multi-family DRAFT
    Reg-->>V1: Stage::Draft
    V1-->>-Daemon: Vec<PromptSweepOutcome>

    Daemon->>+V2: interval tick
    V2->>OptS: propose(seed, catalog, exemplars, cfg)
    V2->>OptS: optimize_budgeted(...)
    OptS-->>V2: budgeted best candidate
    V2->>OptS: optimize_with_holdout(challenger, ...)
    OptS-->>V2: holdout outcome (overfit?)
    V2->>OptS: ab_promote(champion, challenger, holdout, ...)
    OptS-->>V2: Promotion decision
    loop promoted models
        V2->>Bridge: winner_to_draft(...)
        Bridge-->>V2: single-family LayerArtifact
    end
    V2->>Bridge: register_draft(merged artifact)
    Bridge->>Reg: store multi-family DRAFT
    Reg-->>V2: Stage::Draft
    V2-->>-Daemon: Vec<PromptSweepOutcomeV2>
```

---

## How It Fits into the Overall System

`surfaces_prompt_optimizer` sits at the intersection of three major subsystems:

1. **Runtime Engine** — It is one of the runtime surfaces (alongside [surfaces_chat_identity](surfaces_chat_identity.md), [surfaces_fabric_chat](surfaces_fabric_chat.md), and [surfaces_workforce](surfaces_workforce.md)) that the daemon exposes to the rest of the system. See [runtime_engine](runtime_engine.md) and [runtime_configuration](runtime_configuration.md).

2. **Prompt Engineering** — It consumes the optimization primitives defined in [prompt_optimization](prompt_optimization.md) and the prompt registry/layering primitives in [prompt_core](prompt_core.md). It does not reimplement optimization; it only provides the live driver and provider adapters.

3. **Evaluation & Providers** — It uses `EvalCase` and `QualityJudge` from [evaluation_testing](evaluation_testing.md) and the `Provider` trait from [llm_providers](llm_providers.md) / [core_engine](core_engine.md).

```mermaid
flowchart LR
    subgraph Surfaces["Runtime Surfaces"]
        PO[surfaces_prompt_optimizer]
        CI[surfaces_chat_identity]
        FC[surfaces_fabric_chat]
        WF[surfaces_workforce]
    end

    subgraph Runtime["Runtime Engine"]
        RE[runtime_engine]
        RC[runtime_configuration]
    end

    subgraph PromptEng["Prompt Engineering"]
        PC[prompt_core]
        POpt[prompt_optimization]
    end

    subgraph EvalProv["Evaluation & Providers"]
        ET[evaluation_testing]
        LP[llm_providers]
    end

    PO -->|hosted by| RE
    PO -->|configured via| RC
    PO -->|drives| POpt
    PO -->|registers artifacts in| PC
    PO -->|evaluates with| ET
    PO -->|calls models via| LP
    CI -.->|sibling surface| PO
    FC -.->|sibling surface| PO
    WF -.->|sibling surface| PO
```

---

## Core Components

### `PromptSweepSpec`

Immutable metadata for a single sweep pass. It describes:
- The target layer artifact id and `Layer` (typically an L3 task layer).
- The `next_version` to assign to any produced DRAFT.
- The owner, template variables, and `EvalSetRef` used for validation.

One spec produces one merged multi-family artifact per tick.

### `PromptSweepOutcome` / `PromptSweepOutcomeV2`

Per-model result enums. They guarantee that every input model receives exactly one outcome and that failures are reported with a precise reason rather than silently dropped.

| Outcome | Meaning |
|---------|---------|
| `Drafted` / `PromotedDraft` | Winner certified and registered as DRAFT. |
| `Skipped` | No winner, overfit, A/B loss, or registry rejection. |
| `KeptChampion` (v2 only) | Challenger did not beat the live champion by the A/B margin. |

### `ProviderModelSeam`

Adapts any `dyn Provider` to the `ModelSeam` trait required by `ainxt-promptopt`. It:
- Reports the provider's id and tier.
- Completes prompts by draining the provider's async stream in a blocking context.
- Fails soft on transport errors (returns empty string, letting the judge score it).

### `ProviderConstrainedDecoder`

Adapts any `dyn Provider` to the `ConstrainedDecoder` trait used by `ConstrainedLlmJudge`. It:
- Declares `grammar_native() == false` honestly, because no provider adapter exposes a native GBNF hook at this layer.
- Routes every decode through the `StructuredOutputEngine` bounded prompted-JSON repair loop.
- Uses `tokio::task::block_in_place` to bridge async provider calls from the synchronous decoder interface.

### `drain_provider_reply` / `blocking_provider_call`

Shared helpers that drain a `Provider::stream` into a plain string. They:
- Concatenate `TextDelta` events.
- Fail closed on `Event::Error`.
- Refuse tool-approval requests rather than guess.
- Ignore non-text events (reasoning, tool results, usage, artifacts).

### `spawn_prompt_optimizer_tick`

The daemon entrypoint. It:
1. Resolves a real chat-classifier provider from `LoadedConfig`.
2. Returns `None` on air-gapped defaults (no provider configured), matching other conditional cadences.
3. Spawns a Tokio interval task that runs both v1 and v2 sweeps each cycle.
4. Maintains a private in-task `Registry` with a pre-registered eval set.
5. Bumps the minor version each tick.

> **Honest infra gaps**: the shipped-default gold/variants/holdout are illustrative constants, not a deployment's real role-specific sets; the tick uses a private registry rather than the same registry that serves `/v1/chat`; and version-bumping policy is left to the caller. These are documented explicitly in code rather than hidden.

---

## Data Flow

### v1 Sweep Data Flow

```mermaid
flowchart LR
    A[PromptVariant list] -->|input| B[run_prompt_optimizer_sweep_tick]
    C[EvalCase gold set] -->|input| B
    D[QualityJudge] -->|input| B
    E["(&dyn ModelSeam, ModelFamily) list"] -->|input| B
    F[PromptSweepSpec] -->|input| B
    B -->|optimize_all| G[per-model Optimization]
    G -->|winner_to_draft| H[per-family LayerArtifact]
    H -->|merge| I[Multi-family LayerArtifact]
    I -->|register_draft| J[Registry]
    J -->|produces| K[Vec<PromptSweepOutcome>]
```

### v2 Sweep Data Flow

```mermaid
flowchart LR
    A[seed PromptVariant] -->|input| B[run_prompt_optimizer_sweep_tick_v2]
    C[ProposeCatalog + Exemplars] -->|input| B
    D[train_gold] -->|input| B
    E[holdout_gold] -->|input| B
    F[QualityJudge + CostModel + OptBudget] -->|input| B
    G["(&dyn ModelSeam, ModelFamily, champion) list"] -->|input| B
    H[PromptSweepSpec] -->|input| B
    B -->|propose| I[candidates]
    I -->|optimize_budgeted| J[budgeted best]
    J -->|optimize_with_holdout| K[holdout confirmation]
    K -->|ab_promote| L{beat champion?}
    L -->|yes| M[winner_to_draft]
    L -->|no| N[KeptChampion]
    M -->|merge| O[Multi-family LayerArtifact]
    O -->|register_draft| P[Registry]
    P -->|produces| Q[Vec<PromptSweepOutcomeV2>]
```

---

## Process Flows

### Full v2 Pipeline per Model

```mermaid
flowchart TB
    Start([Per model]) --> Propose[propose candidates from seed]
    Propose --> Budget[optimize_budgeted<br/>under cost budget]
    Budget --> Winner{Certified winner?}
    Winner -->|no| Skip1[Skipped: no budgeted winner]
    Winner -->|yes| Holdout[optimize_with_holdout<br/>on disjoint holdout]
    Holdout --> Overfit{Overfit?}
    Overfit -->|yes| Skip2[Skipped: overfit guard]
    Overfit -->|no| AB[ab_promote vs live champion]
    AB --> Decision{Promotion decision}
    Decision -->|KeepChampion| Keep[KeptChampion]
    Decision -->|Promote| Draft[winner_to_draft]
    Draft --> Merge[Merge into multi-family artifact]
    Merge --> Register[register_draft]
    Register --> Outcome[PromotedDraft]
```

### Cadence Lifecycle

```mermaid
flowchart TB
    Start([spawn_prompt_optimizer_tick]) --> Config{Chat classifier<br/>provider configured?}
    Config -->|no| None[Return None]
    Config -->|yes| Spawn[Spawn interval task]
    Spawn --> Init[Create private Registry<br/>+ eval set index]
    Init --> Loop[Each tick: minor++]
    Loop --> V1[run v1 sweep]
    V1 --> V2[run v2 sweep]
    V2 --> Loop
```

---

## Dependencies

### Direct Crate Dependencies

| Crate | Module Doc | Usage |
|-------|------------|-------|
| `ainxt_eval` | [evaluation_testing](evaluation_testing.md) | `EvalCase`, `QualityJudge`, scoring |
| `ainxt_prompt` | [prompt_core](prompt_core.md) | `Registry`, `Layer`, `ModelFamily`, `PromptVariant`, `ConstrainedDecoder` |
| `ainxt_promptopt` | [prompt_optimization](prompt_optimization.md) | Optimization, bridge, budget, holdout, A/B promotion, proposal |
| `ainxt_protocol` | [core_interaction](core_interaction.md) | `Event` streaming contract |
| `ainxt_runtime` | [core_engine](core_engine.md) | `Provider` trait |
| `ainxt_types` | [core_infrastructure](core_infrastructure.md) | `Tier` |

### Sibling Surfaces

- [surfaces_chat_identity](surfaces_chat_identity.md)
- [surfaces_fabric_chat](surfaces_fabric_chat.md)
- [surfaces_workforce](surfaces_workforce.md)

---

## Operational Notes

### Why DRAFT Only

The optimizer never auto-promotes past `DRAFT`. Promotion through `Eval`, `OpenPr`, and production stages is governed by the prompt registry lifecycle and release gates described in [prompt_core](prompt_core.md). This separation keeps the optimizer a pure recommendation engine and leaves human or gated approval processes in control.

### Multi-Family Merge Discipline

A `LayerArtifact` is immutable at a given `(id, version)` and declares all its compiled model families together. Therefore the sweep:
1. Bridges each model's winner into a single-family artifact.
2. Merges all single-family artifacts by extending `model_variants` and `variants`.
3. Calls `register_draft` exactly once per tick.

This prevents version collisions that would occur if each family registered independently.

### Async/Sync Bridge

The optimizer's judge and seam interfaces are synchronous, but provider calls are async. The module uses `tokio::task::block_in_place` plus `Handle::current().block_on` to run provider streams on the same multi-threaded Tokio runtime without nesting runtimes. This requires the caller to already be inside a multi-threaded Tokio runtime.

---

## Testing

The module includes unit tests that prove the end-to-end behavior:

- **`gap_ainxt_runtimed_prmt_12_sweep_tick_lands_a_draft_per_model`** — v1 sweep lands a merged multi-family DRAFT.
- **`gap_ainxt_runtimed_prmt_12_no_winner_is_skipped_not_silently_dropped`** — empty gold produces a reported `Skipped` outcome.
- **`gap_ainxt_runtimed_prmt_12_registry_rejection_is_reported_as_skipped`** — dangling eval-set FK surfaces as a skipped reason.
- **`gap6_promptopt_v2_overfit_challenger_is_refused_before_ab_check`** — v2 holdout guard refuses a memorizing challenger.
- **`gap6_promptopt_v2_worse_challenger_is_refused_by_ab_promote`** — v2 A/B check keeps the live champion when the challenger is worse.
- **`gap6_promptopt_v2_better_challenger_is_promoted_and_actually_drafted`** — v2 promotes a genuinely better challenger to DRAFT.

Test fixtures include deterministic `ModelSeam` implementations (`SbsModel`, `RegurgitateModel`, `MarkerModel`) and a simple `TermJudge` that checks for expected terms.

---

## See Also

- [prompt_optimization](prompt_optimization.md) — the underlying optimizer engine.
- [prompt_core](prompt_core.md) — prompt registry, layers, and lifecycle.
- [runtime_engine](runtime_engine.md) — the runtime engine that hosts this surface.
- [runtime_configuration](runtime_configuration.md) — how `LoadedConfig` and provider resolution work.
- [evaluation_testing](evaluation_testing.md) — eval cases, judges, and quality scoring.
- [llm_providers](llm_providers.md) — provider adapters and the `Provider` trait.
- [surfaces_chat_identity](surfaces_chat_identity.md), [surfaces_fabric_chat](surfaces_fabric_chat.md), [surfaces_workforce](surfaces_workforce.md) — sibling runtime surfaces.
