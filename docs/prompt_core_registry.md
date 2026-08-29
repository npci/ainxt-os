# prompt_core_registry

## Brief Introduction

`prompt_core_registry` is the runtime implementation of the **prompts-as-code** discipline for the AiNxt platform. It treats a prompt not as an ad-hoc string, but as a **versioned, per-model-tuned artifact** with a full software lifecycle: authored (`DRAFT`), evaluated (`EVAL`), reviewed (`REVIEW`), canaried (`CANARY`), promoted (`PRODUCTION`), and retired (`DEPRECATED`).

The module provides:

- A deterministic, clock-free [`Registry`](prompt_core_registry.md#registry) that stores layer artifacts, tracks lifecycle stages, enforces eval-set foreign-key resolution, and gates every lifecycle transition.
- [`LayerArtifact`](prompt_core_registry.md#layerartifact) and [`Manifest`](prompt_core_registry.md#manifest) types that bind front-matter metadata to compiled per-model variant bodies.
- [`Deployment`](prompt_core_registry.md#deployment), [`Release`](prompt_core_registry.md#release), and [`CanaryRelease`](prompt_core_registry.md#canaryrelease) types that support **rollback-by-pointer**: a regressed canary is reverted by flipping a pointer, not by rewriting immutable bodies.
- A git-native [`ControlPlane`](prompt_core_registry.md#controlplane) loader that reads `prompts/<id>/definition.json` plus `variant.<family>.md` siblings, verifies them against a `control.lock` content-address, and produces a fresh [`Registry`](prompt_core_registry.md#registry) for atomic hot-reload.
- A first-class [`ServedChatPrompts`](prompt_core_registry.md#servedchatprompts) default deployment that drives L1–L4 chat layers through the real lifecycle gates and pins them into a locked release.
- A config-sourced [`PolicyEngineConfig`](prompt_core_registry.md#policyengineconfig) so that L2 org/policy text is loaded through the existing layered TOML merge rather than hardcoded in source.

Everything is deterministic (no clock, no RNG) so that serve-time routing, rollback, and replay are reproducible.

---

## Comprehensive Documentation

### 1. Core Concepts

#### 1.1 Layered Prompt Artifacts

The registry models the four definition layers defined in `PROMPT_ENGINEERING.md` §2:

| Layer | Code | Purpose | Rank |
|-------|------|---------|------|
| Persona | `L1` | Identity / persona | 1 |
| Policy | `L2` | Org / config policy | 2 |
| Task | `L3` | Task instructions (Studio authors + optimizer tunes) | 3 |
| Guards | `L4` | Guard prompts (refuse/never; leak + injection defense) | 4 |

L5 (context) is intentionally **not** an artifact; it is the per-turn data-plane slice supplied by the context/retrieval subsystem. Layers compose in fixed rank order so that guards sit immediately above untrusted L5 context.

#### 1.2 Per-Model Variants

Each [`LayerArtifact`](prompt_core_registry.md#layerartifact) declares one or more `model_variants` and ships a compiled body for each. A Role switched from Claude to a self-hosted Qwen deployment receives the Qwen-tuned body, never the Claude prose run as-is. Variant bodies are plain structured text and are verified byte-for-byte at serve time against pinned content fingerprints.

#### 1.3 Eval-Set Foreign Key

Every artifact declares an `eval_set` reference (`id` + semver requirement). The [`EvalSetIndex`](prompt_core_registry.md#evalsetindex) is the "target table" for that foreign key. An artifact whose eval-set reference does not resolve cannot be registered, and an eval delta targeting the wrong eval set cannot advance an artifact from `EVAL` to `REVIEW`.

#### 1.4 Lifecycle Gates

The lifecycle is enforced by [`Registry::advance`](prompt_core_registry.md#registryadvance):

| From | Event | Gate | To |
|------|-------|------|-----|
| `DRAFT` | `OpenPr` | â€” | `EVAL` |
| `EVAL` | `SubmitEval(delta)` | Resolvable eval-set FK + non-regressing statistical drop-in gate | `REVIEW` |
| `REVIEW` | `Approve` | Approver is in `owner` group AND approver â‰  author (SoD) | `CANARY` |
| `CANARY` | `Promote(Healthy)` | Healthy canary soak | `PRODUCTION` |
| `CANARY` | `Promote(Regressed)` | â€” | blocked (`CanaryRegressed`) |
| any | `Deprecate` | â€” | `DEPRECATED` |

The EVALâ†’REVIEW gate reuses [`ainxt_eval::evaluate_gate_statistical_dropin`](evaluation_testing.md) so that the registry and the evaluation subsystem can never drift apart.

#### 1.5 Content Fingerprint & `control.lock`

Every variant body has a deterministic 128-bit fingerprint (`content_fingerprint`), computed from two FNV-1a lanes. This is the **in-runtime lock check**, not the cryptographic content-address (git provides that). At load time and serve time, the actual body fingerprint is compared to the pinned fingerprint; a mismatch fails closed before the body can reach a model.

---

### 2. Component Reference

#### 2.1 `Registry`

The central registry stores:

- `artifacts: BTreeMap<(id, Semver), LayerArtifact>` â€” all registered artifact versions.
- `stages: BTreeMap<(id, Semver), Stage>` â€” the lifecycle stage of each artifact.
- `eval_index: EvalSetIndex` â€” the eval-set FK target table.
- `owners: BTreeMap<String, BTreeSet<String>>` â€” CODEOWNERS membership for approval gating.

Key methods:

- `register(artifact)` â€” validates the artifact, checks the eval-set FK, rejects duplicate `(id, version)` pairs, and inserts at `DRAFT`.
- `get(id, version)` / `stage_of(id, version)` â€” lookups.
- `advance(id, version, event)` â€” enforces lifecycle gates and returns the new stage.
- `pin_release(tag, selection)` â€” builds a signed [`Release`](prompt_core_registry.md#release) with per-family variant fingerprints.
- `serve(deployment, routing_key, family, layer_ids)` â€” resolves layers for a turn, verifies each body against the release lock, and returns them in L1â†’L4 order.

<a name="registryadvance"></a>

#### 2.2 `LayerArtifact`

A single versioned layer artifact, the runtime shape of a `prompts/<id>/` directory:

- `id`, `layer`, `version`, `owner`, `author`, `variables`, `eval_set`, `model_variants`.
- `variants: BTreeMap<ModelFamily, String>` â€” compiled per-model bodies.

`LayerArtifact::validate` rejects empty ids, missing declared variants, empty variant bodies, and undeclared extra variants.

#### 2.3 `Manifest`

The parsed `definition.json` front-matter. `Manifest::into_artifact(bodies)` binds the manifest to the sibling `variant.<family>.md` bodies and runs validation. The manifest uses string versions; the runtime converts them to [`Semver`](prompt_core_registry.md#semver).

#### 2.4 `EvalSetIndex`

The set of eval sets that actually exist. `insert(id, version)` registers a version; `resolves(ref)` checks whether a reference matches any registered version.

#### 2.5 `Deployment`, `Release`, `PinnedLayer`, `CanaryRelease`

- `Release` â€” a signed git tag containing a `BTreeMap<String, PinnedLayer>`.
- `PinnedLayer` â€” an artifact id, its layer, its version, and `variant_hashes: BTreeMap<ModelFamily, String>`.
- `CanaryRelease` â€” a release plus a `weight_pct` (0â€“100).
- `Deployment` â€” holds `prod: Release` and an optional `canary: CanaryRelease`.

`Deployment` methods:

- `start_canary(release, weight_pct)` â€” stage a canary.
- `rollback_canary()` â€” instant pointer flip back to `prod`.
- `promote_canary()` â€” fast-forward `prod` onto the canary release.
- `rollback_prod_to(previous)` â€” repoint `prod` to a prior release.
- `select_release(routing_key)` â€” deterministic canary split based on a stable hash bucket of the routing key.

#### 2.6 `ControlPlane`, `ControlLock`, `Loaded`

The git-native loader:

- `ControlPlane::new(root, eval_index)` â€” loader bound to a `prompts/` directory.
- `allow_unlocked()` â€” bootstrap mode that permits loading without a `control.lock`.
- `load()` â€” reads `control.lock`, reads every artifact directory, verifies bodies against the lock, and registers artifacts into a fresh [`Registry`](prompt_core_registry.md#registry).
- `read_only()` â€” reads artifacts without registering them, so callers can derive the eval-set index from the artifacts' own declared refs.
- `ControlLock::of(artifacts)` â€” computes the lock a release job should write.
- `write_lock(root, lock)` â€” serializes the lock to disk.

`Loaded` returns the fresh registry, the artifact list, and a `lock_verified` flag.

#### 2.7 `ServedChatPrompts`, `LayerSpec`

The shipped-default layered chat deployment. It builds a [`Registry`](prompt_core_registry.md#registry) with L1â€“L4 chat layers, drives each through the real lifecycle to `PRODUCTION`, pins them into a release, and exposes everything the [`PromptService`](prompt_core_safety.md) needs to compile a turn.

Key functions:

- `served_chat_prompts(families)` â€” build from compiled-in canonical bodies.
- `served_chat_prompts_with_l2_policy(families, l2_policy_body)` â€” same, but with a config-sourced L2 override.
- `served_chat_prompts_from_dir(root)` â€” build from git-native prompt files on disk.
- `steerability_gated_served_chat_prompts(candidate, scores, min_bar)` â€” drop families that fail the steerability bar.
- `payments_served_chat_prompts(families)` / `default_payments_served_chat_prompts()` â€” payments surface with `numeric = ToolsOnly`.

`ServedChatPrompts` also provides drift baselines and canary evaluation wiring.

#### 2.8 `PolicyEngineConfig`

A `Deserialize`-able config struct that supplies the L2 policy body through `ainxt-config`'s layered TOML merge. `default_l2_body()` returns the previously hardcoded text so unconfigured deployments behave identically. See [security_config](security_config.md) and [core_infrastructure](core_infrastructure.md) for the broader config-loading story.

---

### 3. Architecture

```mermaid
flowchart TB
    subgraph GitNative["Git-Native Prompt Tree"]
        LOCK["control.lock"]
        DEF["prompts/&lt;id&gt;/definition.json"]
        VAR["prompts/&lt;id&gt;/variant.&lt;family&gt;.md"]
    end

    subgraph RegistryLayer["prompt_core_registry"]
        CP["ControlPlane loader"]
        REG["Registry"]
        ART["LayerArtifact"]
        MAN["Manifest"]
        ESI["EvalSetIndex"]
        DEP["Deployment / Release / CanaryRelease"]
        SCP["ServedChatPrompts"]
        PEC["PolicyEngineConfig"]
    end

    subgraph Consumers["Upstream Consumers"]
        PS["PromptService / ServedPromptEngine"]
        PE["PromptEngine / LayeredAssembler"]
        CM["CanaryController / DriftMonitor"]
    end

    DEF -->|parsed| MAN
    VAR -->|bound| ART
    MAN --> ART
    CP -->|reads + verifies| LOCK
    CP -->|reads| DEF
    CP -->|reads| VAR
    CP -->|produces| REG
    ESI -->|FK check| REG
    ART -->|registered| REG
    REG -->|pin_release| DEP
    REG -->|serve| PS
    SCP -->|wraps| REG
    SCP -->|wraps| DEP
    PEC -->|L2 body| SCP
    PS -->|assembles| PE
    SCP -->|drift baselines| CM
    SCP -->|evaluate_canary| CM
```

---

### 4. Dependencies

```mermaid
flowchart LR
    A[prompt_core_registry] -->|eval gate| B[evaluation_testing]
    A -->|L2 config| C[security_config]
    A -->|canary / drift / steerability| D[prompt_core_quality]
    A -->|guard / numeric / service| E[prompt_core_safety]
    A -->|assembly| F[prompt_core_assembly]
    A -->|structured output| G[prompt_core_structured]
    A -->|context fabric| H[knowledge_retrieval]
    A -->|runtime surfaces| I[pipeline_runtime]
```

- **[evaluation_testing](evaluation_testing.md)** â€” `Registry::advance` calls `ainxt_eval::evaluate_gate_statistical_dropin` for the EVALâ†’REVIEW merge-block gate.
- **[security_config](security_config.md)** / **[core_infrastructure](core_infrastructure.md)** â€” `PolicyEngineConfig` is designed to be resolved through `ainxt-config`'s layered TOML loader.
- **[prompt_core_quality](prompt_core_quality.md)** â€” `ServedChatPrompts` wires `CanaryController`, `DriftMonitor`, and steerability gating into the served deployment.
- **[prompt_core_safety](prompt_core_safety.md)** â€” L4 guard bodies and numeric policy flow into the served layers; `PromptService::compile_turn` consumes the registry/deployment produced here.
- **[prompt_core_assembly](prompt_core_assembly.md)** â€” `PromptEngine` and `LayeredAssembler` take the resolved `ResolvedLayer` bodies and compose the final system prompt.
- **[prompt_core_structured](prompt_core_structured.md)** â€” constrained/JSON-schema output is a sibling concern; the registry supplies the instruction bodies that structured engines decorate.
- **[knowledge_retrieval](knowledge_retrieval.md)** â€” L5 context is injected at serve time from the context/retrieval fabric.
- **[pipeline_runtime](pipeline_runtime.md)** â€” the runtime daemon holds `ServedPromptEngine` and routes turns through the served deployment.

---

### 5. Data Flow: Loading the Control Plane

```mermaid
sequenceDiagram
    participant FS as prompts/ directory
    participant CP as ControlPlane
    participant LOCK as control.lock
    participant REG as Registry
    participant UP as Upstream (daemon)

    UP->>CP: load()
    CP->>LOCK: read_lock()
    alt lock required and missing
        CP-->>UP: LoadError::MissingLock
    end
    CP->>FS: read_artifacts()
    loop each artifact directory
        FS-->>CP: definition.json + variant.*.md
        CP->>CP: Manifest::into_artifact
        CP->>CP: validate
    end
    CP->>LOCK: verify each artifact
    alt mismatch
        CP-->>UP: LoadError::LockHashMismatch
    end
    CP->>REG: Registry::new(eval_index)
    loop each artifact
        CP->>REG: register(artifact)
        REG->>REG: validate + FK check
    end
    CP-->>UP: Loaded { registry, artifacts, lock_verified }
    UP->>UP: atomic Arc swap
```

---

### 6. Data Flow: Lifecycle Advancement

```mermaid
sequenceDiagram
    participant Auth as Author / CI
    participant REG as Registry
    participant ESI as EvalSetIndex
    participant EV as evaluation_testing
    participant OWN as Owner group

    Auth->>REG: register(artifact)
    REG->>REG: validate artifact
    REG->>ESI: resolves(eval_set)?
    ESI-->>REG: yes
    REG-->>Auth: Stage::Draft

    Auth->>REG: advance(OpenPr)
    REG-->>Auth: Stage::Eval

    Auth->>REG: advance(SubmitEval(delta))
    REG->>REG: delta.eval_set == artifact.eval_set?
    REG->>ESI: resolves(delta.eval_set)?
    REG->>EV: evaluate_gate_statistical_dropin(candidate, policy, baseline)
    EV-->>REG: Pass / Fail(reasons)
    alt Pass
        REG-->>Auth: Stage::Review
    else Fail
        REG-->>Auth: RegistryError::EvalRegression
    end

    OWN->>REG: advance(Approve(approver))
    REG->>REG: approver in owner group?
    REG->>REG: approver != author?
    REG-->>OWN: Stage::Canary

    OWN->>REG: advance(Promote(Healthy))
    REG-->>OWN: Stage::Production
```

---

### 7. Data Flow: Serve-Time Resolution

```mermaid
sequenceDiagram
    participant PS as PromptService
    participant DEP as Deployment
    participant REG as Registry
    participant OUT as Model / upstream

    PS->>DEP: select_release(routing_key)
    DEP-->>PS: (release, is_canary)
    loop each layer_id
        PS->>DEP: PinnedLayer lookup
        DEP-->>PS: pinned_hash for family
        PS->>REG: get(id, version)
        REG-->>PS: LayerArtifact
        PS->>PS: actual = content_fingerprint(body)
        alt actual != pinned_hash
            PS-->>OUT: ServeError::LockMismatch (fail closed)
        end
        PS->>PS: push ResolvedLayer
    end
    PS->>PS: sort by layer rank L1â†’L4
    PS-->>OUT: Vec<ResolvedLayer>
```

---

### 8. Process Flow: Building the Shipped Default Chat Deployment

```mermaid
flowchart TB
    START([Build default chat prompts]) --> FAM{Families provided?}
    FAM -->|no| DFAM[use default_chat_families]
    FAM -->|yes| USEFAM[use provided families]
    DFAM --> SPECS[layer_specs]
    USEFAM --> SPECS
    SPECS --> IX[build EvalSetIndex from layer eval_sets]
    IX --> REG[Registry::new + set_owner_group]
    REG --> LOOP[for each L1..L4 layer]
    LOOP --> VAR[compile variant_body per family]
    VAR --> REGISTER[register LayerArtifact]
    REGISTER --> OPEN[advance OpenPr -> Eval]
    OPEN --> DELTA[build EvalDelta]
    DELTA --> SUBMIT[advance SubmitEval -> Review]
    SUBMIT --> APPROVE[advance Approve -> Canary]
    APPROVE --> PROMOTE[advance Promote Healthy -> Production]
    PROMOTE --> MORE{more layers?}
    MORE -->|yes| LOOP
    MORE -->|no| PIN[pin_release DEFAULT_CHAT_RELEASE_TAG]
    PIN --> DEP[Deployment::new]
    DEP --> RETURN[ServedChatPrompts]
```

---

### 9. Process Flow: Canary Rollback / Promote

```mermaid
flowchart LR
    A[Canary staged] --> B{evaluate_canary}
    B -->|Hold| C[No change]
    B -->|Rollback| D[deployment.rollback_canary]
    B -->|Promote| E[deployment.promote_canary]
    D --> F[prod serves last-known-good]
    E --> G[prod fast-forwards to canary tag]
```

Because bodies are immutable and content-addressed, rollback is an instant pointer flip that restores the exact last-known-good bytes.

---

### 10. Error Handling Philosophy

Every error in this module is **fail-closed**:

- A malformed manifest, missing variant, or dangling eval-set FK prevents registration.
- A missing `control.lock` in production posture prevents load.
- A lock hash mismatch prevents the tampered body from being registered or served.
- A regressing eval delta keeps the artifact at `EVAL`.
- A self-approval or non-owner approval keeps the artifact at `REVIEW`.
- A regressed canary keeps the artifact at `CANARY`.
- A missing or mismatched variant at serve time returns `ServeError` rather than falling back to another body.

---

### 11. Integration with the Wider System

- **Authoring**: Prompt engineers edit `definition.json` and `variant.<family>.md` files under `prompts/`. CODEOWNERS, branch protection, signed tags, and merge-blocking CI live in the git host; this module is the runtime consumer of those artifacts.
- **Evaluation**: The EVALâ†’REVIEW gate delegates to the same statistical drop-in evaluator used by the evaluation pipeline, ensuring a single source of truth for what counts as a regression.
- **Serving**: The runtime daemon holds a `ServedPromptEngine` that calls `Registry::serve` and passes the resolved layers to `LayeredAssembler` for final prompt composition.
- **Observability**: Every `ResolvedLayer` carries `from_canary` for A/B attribution, and `ServedChatPrompts` seeds `DriftMonitor` baselines from the deploy-time gate mean.
- **Governance**: The lifecycle gates encode producerâ‰ approver separation of duties and eval-set foreign-key discipline, which are enforced structurally rather than by convention.

---

### 12. See Also

- [prompt_core_assembly](prompt_core_assembly.md) â€” how resolved layers are assembled into the final prompt.
- [prompt_core_safety](prompt_core_safety.md) â€” guard rails, numeric policy, and the `PromptService` serve path.
- [prompt_core_quality](prompt_core_quality.md) â€” canary, drift, and steerability monitoring.
- [prompt_core_structured](prompt_core_structured.md) â€” constrained/structured output support.
- [evaluation_testing](evaluation_testing.md) â€” the evaluation gate and statistical drop-in test.
- [security_config](security_config.md) / [core_infrastructure](core_infrastructure.md) â€” config loading and infrastructure dependencies.
- [knowledge_retrieval](knowledge_retrieval.md) â€” context fabric that supplies L5 data.
- [pipeline_runtime](pipeline_runtime.md) â€” runtime daemon and serving surfaces.
