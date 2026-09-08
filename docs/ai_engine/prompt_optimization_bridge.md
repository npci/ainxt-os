# Prompt Optimization Bridge

## Brief Introduction

The **Prompt Optimization Bridge** (`crates/ainxt-promptopt/src/bridge.rs`) is the controlled hand-off between the automated prompt optimizer and the governed prompt artifact lifecycle. While the optimizer can discover a winning prompt variant through A/B evaluation and holdout validation, that winner is **never** allowed to ship directly to production. Instead, the bridge converts the winning [`PromptVariant`] into a per-model-family [`LayerArtifact`] and registers it in the Prompt [`Registry`] at [`Stage::Draft`]. From there, the artifact must advance through the normal gated pipeline—EVAL → REVIEW → CANARY → PRODUCTION—just like any human-authored prompt change.

This module enforces two critical safety properties:

1. **No auto-promotion**: the optimizer can only create a DRAFT; advancement requires the full lifecycle.
2. **Overfit refusal**: a winner flagged as overfit by the holdout outcome is rejected at the bridge and never becomes a draft.

---

## Core Responsibilities

| Responsibility | Description |
| -------------- | ----------- |
| **Winner → DRAFT conversion** | Turn a certified optimizer winner into a validated [`LayerArtifact`] for a specific [`ModelFamily`]. |
| **Holdout gating** | Refuse to bridge overfit candidates (gap AQ / PE10) before they can enter the registry. |
| **Registry integration** | Register the artifact at [`Stage::Draft`] and return the stage, performing no further lifecycle advancement. |
| **SoD enforcement** | The artifact author is recorded as `"prompt-optimizer"`; an optimizer author can never self-approve promotion. |

---

## Core Components

### `DraftSpec`

Metadata required to mint a new DRAFT artifact from an optimizer winner.

```rust
pub struct DraftSpec {
    pub id: String,              // artifact id (typically an L3 task layer)
    pub layer: Layer,            // registry layer classification
    pub version: Semver,         // new DRAFT version, bumped from current PRODUCTION
    pub owner: String,           // CODEOWNERS group
    pub author: String,          // e.g. "prompt-optimizer"
    pub variables: Vec<String>,  // template variables
    pub eval_set: EvalSetRef,    // evaluation set reference for the artifact
}
```

### `BridgeError`

Enumerates the ways the bridge can refuse to create a DRAFT:

- `NoWinner` — the optimization produced no certified winner.
- `WinnerNotFound` — the declared winner id is not in the supplied variant set.
- `Overfit` — the holdout flagged the winner as overfit.
- `Registry(RegistryError)` — the registry rejected the artifact (invalid body, dangling eval-set FK, duplicate version, etc.).

### Bridge Functions

| Function | Purpose |
| -------- | ------- |
| `winner_to_draft` | Converts a [`ModelOptimization`] winner into a [`LayerArtifact`] for one model family. |
| `holdout_winner_to_draft` | Wraps `winner_to_draft` and rejects overfit winners. |
| `register_draft` | Registers the artifact in the [`Registry`] at [`Stage::Draft`] only. |

### Test Helpers

- `SbsModel` — a test model seam that only succeeds when the prompt asks for step-by-step reasoning.
- `TermJudge` — a test quality judge that scores by terminal-keyword presence.

These are internal test fixtures and are not part of the production API surface.

---

## Architecture

```mermaid
flowchart TB
    subgraph PromptOptimization["prompt_optimization (ainxt-promptopt)"]
        direction TB
        Core[prompt_optimization_core<br/>ModelOptimization / HoldoutOutcome]
        Propose[prompt_optimization_propose<br/>PromptVariant catalog]
        Budget[prompt_optimization_budget<br/>OptBudget / CostModel]
        Judge[prompt_optimization_constrained_judge<br/>ConstrainedLlmJudge]
        Bridge[[prompt_optimization_bridge<br/>winner_to_draft / register_draft]]
    end

    subgraph PromptEngineering["prompt_engineering / prompt_core"]
        Registry[[prompt_core<br/>Registry / LayerArtifact / Stage]]
    end

    subgraph Evaluation["evaluation_testing"]
        Eval[[eval_cases / eval_judging<br/>EvalCase / QualityJudge]]
    end

    subgraph Runtime["pipeline_runtime / runtime_engine / surfaces"]
        Surface[[prompt_optimizer_surface<br/>PromptSweepSpec / SbsModel / TermJudge]]
    end

    Core -->|winner| Bridge
    Propose -->|variants| Bridge
    Budget -->|budget constraints| Core
    Judge -->|rich judge| Core
    Bridge -->|LayerArtifact| Registry
    Eval -->|gold / holdout| Core
    Surface -->|drives optimization| Core
```

---

## Dependencies

The bridge depends on components from the same crate and from the prompt registry:

```mermaid
flowchart LR
    Bridge[ainxt-promptopt::bridge] -->|uses| Core[ainxt-promptopt::lib<br/>ModelOptimization / HoldoutOutcome / PromptVariant]
    Bridge -->|uses| Registry[ainxt-prompt::registry<br/>Registry / LayerArtifact / Stage / Semver / ModelFamily]
    Core -->|uses| Eval[ainxt-eval<br/>EvalCase / QualityJudge / QualityScore]
    Surface[ainxt-runtimed::prompt_optimizer_surface] -->|consumes| Core
```

- **[prompt_optimization_core](prompt_optimization_core.md)** — provides the optimization result types (`ModelOptimization`, `HoldoutOutcome`) and the variant type (`PromptVariant`).
- **[prompt_optimization_propose](prompt_optimization_propose.md)** — produces the candidate `PromptVariant`s that the bridge consumes.
- **[prompt_optimization_budget](prompt_optimization_budget.md)** — constrains how many variants and judge calls the optimizer can afford before a winner reaches the bridge.
- **[prompt_optimization_constrained_judge](prompt_optimization_constrained_judge.md)** — supplies the constrained judge implementations used during optimization.
- **[prompt_core](prompt_core.md)** — owns the [`Registry`], [`LayerArtifact`], [`Stage`], and lifecycle semantics.
- **[evaluation_testing](evaluation_testing.md)** — defines the evaluation cases and quality judges that determine the winner.
- **[runtime_engine](../pipeline_runtime/runtime_engine.md)** / **[surfaces](../pipeline_runtime/surfaces.md)** — the runtime surface that orchestrates prompt optimization and consumes the resulting DRAFTs.

---

## Data Flow

### Optimizer Winner → Registry DRAFT

```mermaid
sequenceDiagram
    participant OptC as prompt_optimization_core
    participant Bridge as prompt_optimization_bridge
    participant Reg as prompt_core::Registry

    OptC->>OptC: optimize(variants, gold, judge, model) -> ModelOptimization
    OptC->>Bridge: holdout_winner_to_draft(spec, family, variants, HoldoutOutcome)
    Bridge->>Bridge: check outcome.overfit == false
    Bridge->>Bridge: winner_to_draft(spec, family, variants, opt)
    Bridge->>Bridge: find winner variant by id
    Bridge->>Bridge: build LayerArtifact with one model-family variant
    Bridge->>Bridge: art.validate()
    Bridge->>Reg: register_draft(registry, artifact)
    Reg-->>Bridge: Stage::Draft
    Bridge-->>OptC: LayerArtifact / Stage::Draft
```

### Overfit Rejection Path

```mermaid
sequenceDiagram
    participant OptC as prompt_optimization_core
    participant Bridge as prompt_optimization_bridge

    OptC->>Bridge: holdout_winner_to_draft(..., outcome)
    alt outcome.overfit == true
        Bridge-->>OptC: BridgeError::Overfit { id }
    else outcome.overfit == false
        Bridge->>Bridge: continue to winner_to_draft
    end
```

---

## Component Interaction

```mermaid
classDiagram
    class DraftSpec {
        +String id
        +Layer layer
        +Semver version
        +String owner
        +String author
        +Vec~String~ variables
        +EvalSetRef eval_set
    }

    class BridgeError {
        <<enum>>
        NoWinner
        WinnerNotFound
        Overfit
        Registry
    }

    class BridgeFunctions {
        +winner_to_draft() Result~LayerArtifact, BridgeError~
        +holdout_winner_to_draft() Result~LayerArtifact, BridgeError~
        +register_draft() Result~Stage, BridgeError~
    }

    class PromptVariant {
        +String id
        +String template
    }

    class ModelOptimization {
        +Option~String~ winner
    }

    class HoldoutOutcome {
        +Option~String~ winner
        +bool overfit
        +ModelOptimization train
    }

    class LayerArtifact {
        +String id
        +Layer layer
        +Semver version
        +String owner
        +String author
        +Vec~String~ variables
        +EvalSetRef eval_set
        +Vec~ModelFamily~ model_variants
        +BTreeMap~ModelFamily, String~ variants
    }

    class Registry {
        +register(artifact)
        +stage_of(id, version)
        +advance(id, version, event)
    }

    DraftSpec --> BridgeFunctions : input
    PromptVariant --> BridgeFunctions : input
    ModelOptimization --> BridgeFunctions : input
    HoldoutOutcome --> BridgeFunctions : input
    BridgeFunctions --> LayerArtifact : produces
    BridgeFunctions --> Registry : registers
    BridgeFunctions --> BridgeError : returns on refusal
```

---

## Process Flows

### Creating a DRAFT from an Optimization Winner

1. The optimizer runs `optimize` or `optimize_with_holdout` and produces a `ModelOptimization` or `HoldoutOutcome`.
2. The caller constructs a `DraftSpec` describing the target artifact id, layer, version, owner, author, variables, and eval set.
3. The caller invokes `holdout_winner_to_draft` (recommended) or `winner_to_draft` (direct).
4. The bridge extracts the winner id; if missing, returns `BridgeError::NoWinner`.
5. If using the holdout path and `outcome.overfit` is true, returns `BridgeError::Overfit`.
6. The bridge locates the winning `PromptVariant` in the supplied variant list; if absent, returns `BridgeError::WinnerNotFound`.
7. The bridge builds a `LayerArtifact` whose `variants` map contains exactly one entry: the winning template compiled for the requested `ModelFamily`.
8. The artifact is validated; validation failures surface as `BridgeError::Registry`.
9. `register_draft` stores the artifact in the `Registry` and returns `Stage::Draft`.
10. The artifact now follows the standard gated lifecycle; the optimizer cannot advance it further.

### Lifecycle After the Bridge

```mermaid
flowchart LR
    Optimizer[Optimizer discovers winner] -->|bridge| Draft[Stage::Draft]
    Draft -->|OpenPr| Eval[Stage::Eval]
    Eval -->|EvalPass| Review[Stage::Review]
    Review -->|ReviewPass| Canary[Stage::Canary]
    Canary -->|CanaryPass| Prod[Stage::Production]
```

This is the same lifecycle applied to all prompt artifacts; see [prompt_core](prompt_core.md) for details.

---

## Safety & Governance Properties

| Property | Mechanism |
| -------- | --------- |
| **No auto-promotion** | `register_draft` only calls `registry.register`; it never invokes `registry.advance`. |
| **Overfit guard** | `holdout_winner_to_draft` checks `outcome.overfit` and returns `BridgeError::Overfit` when true. |
| **Separation of duties** | The artifact author is `"prompt-optimizer"`; registry promotion requires human/CI approval gates. |
| **Per-model-family drafts** | Each `LayerArtifact` declares exactly one `ModelFamily`; other families are optimized and drafted separately. |
| **Registry validation** | `LayerArtifact::validate` catches invalid bodies, dangling eval-set references, and duplicate versions before registration. |

---

## Error Handling

All bridge operations return `Result<T, BridgeError>`. Callers should handle:

- `NoWinner` — optimization did not certify a winner; nothing to draft.
- `WinnerNotFound` — caller supplied a mismatched variant set; indicates a programming error.
- `Overfit` — holdout detected memorization; the winner must be discarded.
- `Registry(...)` — registry-level validation failure; inspect the inner `RegistryError`.

---

## Testing

The module includes tests that verify the PRMT-07 requirement family:

- `optimizer_winner_lands_as_draft_only` — winner becomes `Stage::Draft`, not production.
- `no_winner_cannot_be_drafted` — empty gold set yields `BridgeError::NoWinner`.
- `overfit_winner_is_refused_at_the_bridge` — overfit holdout outcome yields `BridgeError::Overfit`.
- `dangling_eval_set_fk_is_rejected_by_the_registry` — missing eval set in index yields `BridgeError::Registry(DanglingEvalSet)`.

---

## Integration Notes

- The bridge is intentionally small and stateless. It does not own the registry, the optimizer, or the judge.
- Runtime surfaces such as [`prompt_optimizer_surface`](../pipeline_runtime/runtime_engine.md) drive the optimization and then call the bridge to land results in the registry.
- Because the bridge produces a `LayerArtifact` for a single model family, multi-family prompt rollouts require one optimization + bridge cycle per family.
- For the optimization primitives that feed the bridge, see [prompt_optimization_core](prompt_optimization_core.md).
- For the registry lifecycle that consumes the bridge output, see [prompt_core](prompt_core.md).
