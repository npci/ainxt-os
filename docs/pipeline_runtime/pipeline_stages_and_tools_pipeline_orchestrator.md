# Pipeline Orchestrator (`pipeline_stages_and_tools_pipeline_orchestrator`)

> **Source file:** `crates/ainxt-pipeline/src/pipeline.rs`
>
> **Core components:** `PipelineInputs`, `StageCache`
>
> **Key function:** `run_pipeline`

## 1. Purpose

The pipeline orchestrator is the **single composition point** that binds every stage of the Code-Review Pipeline — risk classification, deterministic Phase-A stages, SAST hard-block, Confidence Score, and Commit Gate — into one typed [`PipelineOutcome`]. It is the heart of the system's anti-sycophancy design: an agent may never declare "done" about a code change except through a `Complete` outcome, and the orchestrator is the only code path that produces one.

The orchestrator does **not** itself shell out to compilers, LSPs, or LLMs. Those are stage seams whose results the caller feeds in (already deterministic-first per the pipeline's ordering rules). What lives here is the **policy composition** and the **invariants**:

- A Phase-A failure (compile / test / lint / type-check) or a SAST critical/high finding can **never** reach `Complete`.
- A Tier-3 (critical-path) edit is handed to a human **even at a perfect Confidence Score**.
- Every step is journaled to a SHA-256 hash-chained [`Journal`] for tamper-evident regulator replay.

The module also implements the **self-heal re-entry planner** (`StageCache`), which uses content-hash stage caching to ensure that a self-heal fix confined to one file does not needlessly re-run expensive stages (Architecture, Perf, SAST) on unrelated files whose content hash hasn't changed — while compile, test, lint, and type-check **always** re-run for any touched file.

## 2. Architecture Overview

```mermaid
graph TB
    subgraph "Pipeline Orchestrator (pipeline.rs)"
        PI["PipelineInputs<br/>(edit_id, tier, rung, stage_reports,<br/>sast, confidence, judge, policy)"]
        RP["run_pipeline()"]
        SC["StageCache<br/>(content-hash re-entry planner)"]
        CH["content_hash()"]
    end

    subgraph "Stage Model (stage.rs)"
        ST["Stage enum<br/>(12 stages)"]
        SR["StageReport"]
        SV["StageVerdict<br/>(Pass / Fail / Skipped / Advisory)"]
    end

    subgraph "Confidence (confidence.rs)"
        CI["ConfidenceInputs"]
        CS["ConfidenceScore<br/>(0–100 + breakdown)"]
        COMP["compute()"]
    end

    subgraph "Commit Gate (gate.rs)"
        GC["GateContext"]
        GP["GatePolicy"]
        GD["GateDecision<br/>(Blocked / RequiresHitl / Complete / Capped)"]
        DEC["decide()"]
    end

    subgraph "Outcome (outcome.rs)"
        PO["PipelineOutcome<br/>(Complete / Capped / Blocked)"]
        CA["CommitApproval<br/>(sealed, un-forgeable)"]
    end

    subgraph "Journal (journal.rs)"
        J["Journal<br/>(SHA-256 hash-chained)"]
        PE["PipelineEvent"]
    end

    subgraph "Risk (risk.rs)"
        RT["RiskTier<br/>(Trivial / Local / Moderate / HighRisk)"]
    end

    subgraph "SAST (sast.rs)"
        SF["SastFinding"]
        SEV["Severity<br/>(Low / Medium / High / Critical)"]
    end

    PI --> RP
    RP --> COMP
    COMP --> CS
    RP --> DEC
    CS --> DEC
    GC --> DEC
    GP --> DEC
    DEC --> GD
    GD --> PO
    PO --> CA
    RP --> J
    J --> PE
    SC --> CH
    RT --> PI
    SF --> PI
    ST --> SR
    SR --> PI
    SV --> SR
```

## 3. Core Components

### 3.1 `PipelineInputs<'a>`

The inputs to one pipeline pass. Phase-A stage results are supplied already-run (deterministic first, cheapest-most-likely-to-fail first — the ordering is the caller's responsibility, typically handled by the [stage execution module](pipeline_stages_and_tools_stage_execution.md)).

| Field | Type | Description |
|---|---|---|
| `edit_id` | `String` | Unique identifier for this edit, used as the journal key. |
| `tier` | `RiskTier` | The (possibly escalated) risk tier driving the Commit Gate. See [classification and risk](classification_and_risk.md). |
| `rung` | `Rung` | The edit-engine rung used (LSP / AST / StructuredPatch / TextPatch). Drives the Confidence Score's fidelity penalty. |
| `blast_fan_out` | `usize` | Direct 1-hop fan-out of the touched symbols. Journaled on `PipelineStarted`. |
| `stage_reports` | `Vec<StageReport>` | The Phase-A + optional later stage reports already produced this pass. |
| `sast` | `&'a [SastFinding]` | SAST findings from this pass. Critical/high hard-block; medium/low are scored. |
| `confidence` | `ConfidenceInputs<'a>` | Structured inputs to the Confidence Score computation. |
| `architecture_violations` | `u32` | Unremediated deterministic architecture boundary violations. Hard-blocks if > 0. |
| `judge_approved` | `Option<bool>` | Whether the Judge ran and approved. `None` = did not run (allowed only below Tier 2). |
| `judge_independent` | `bool` | Whether the verdict came from a genuine context-isolated independent panel. Required `true` for Tier-2+ commit. |
| `policy` | `GatePolicy` | The Commit Gate thresholds (auto-complete, review, trivial-floor). |

### 3.2 `StageCache`

A content-hash cache that tracks which `(stage, input-content-hash)` pairs have already been computed during a pipeline run. It implements the self-heal re-entry strategy: **re-enter at the earliest invalidated stage, not stage 1**.

```mermaid
graph LR
    subgraph "StageCache Decision Logic"
        A["should_run(stage, input_hash)"]
        AR["always_reruns(stage)?"]
        A --> AR
        AR -- "Yes (Compile/Test/Lint/TypeCheck)" --> R["→ must run"]
        AR -- "No (SAST/Architecture/Perf/...)" --> C["seen.contains((stage, hash))?"]
        C -- "Yes" --> S["→ skip (cached)"]
        C -- "No" --> R
    end
```

**Key methods:**

| Method | Description |
|---|---|
| `new()` | Create an empty cache. |
| `should_run(stage, input_hash)` | Whether `stage` must run given its input file set's `input_hash`. Phase-A stages always return `true`. |
| `record(stage, input_hash)` | Record that `stage` ran against `input_hash`. |
| `stages_to_rerun(tier_stages, input_hash)` | Plan the earliest-invalidated re-entry: the subset of `tier_stages` that must re-run, preserving stage order. |

**Always-rerun stages** (never cached, regardless of content hash):
- `Compile`, `Test`, `Lint`, `TypeCheck`

These are the "basics" that always re-run for any touched file, however small the fix — never trust a small change to skip the basics.

### 3.3 `content_hash(files)`

A deterministic SHA-256 content hash over a `BTreeMap<String, String>` (sorted path → content pairs). Used by `StageCache` to detect whether a self-heal round's file set has actually changed. Stable across replays and sensitive to any content change.

### 3.4 `run_pipeline(inp, journal) -> PipelineOutcome`

The main orchestration function. It is **deterministic**: journal ticks are a monotonic counter within the pass (no wall clock).

```mermaid
flowchart TD
    START["PipelineInputs received"] --> J1["Journal: PipelineStarted"]
    J1 --> J2["Journal: StageResult for each stage_report"]
    J2 --> SKIP["Fold observed skips into ConfidenceInputs<br/>(defensive: keep the larger count)"]
    SKIP --> J3{"judge_approved is Some?"}
    J3 -- Yes --> J4["Journal: JudgeVerdict"]
    J3 -- No --> SCORE
    J4 --> SCORE["Compute ConfidenceScore"]
    SCORE --> J5["Journal: StageResult(Confidence, Advisory)"]
    J5 --> CTX["Build GateContext"]
    CTX --> DEC["gate::decide(ctx, score, policy)"]
    DEC --> OUTCOME{"GateDecision"}
    OUTCOME -- "Blocked" --> PB["PipelineOutcome::Blocked"]
    OUTCOME -- "Complete" --> PC["PipelineOutcome::Complete"]
    OUTCOME -- "RequiresHitl" --> PH["PipelineOutcome::Capped<br/>(Tier-3 human hand-off)"]
    OUTCOME -- "Capped" --> PC2["PipelineOutcome::Capped"]
    PB --> J6["Journal: PipelineOutcome"]
    PC --> J6
    PH --> J6
    PC2 --> J6
    J6 --> DONE["Return PipelineOutcome"]
```

## 4. The Commit Gate Decision Flow

The orchestrator delegates the final policy decision to [`gate::decide`](pipeline_stages_and_tools_commit_gate.md), which applies a strict, non-negotiable ordering:

```mermaid
flowchart TD
    G1["1. Phase-A failure?"] -- Yes --> BLK1["Blocked<br/>(compile/test/lint/typecheck)"]
    G1 -- No --> G2["2. SAST critical/high?"]
    G2 -- Yes --> BLK2["Blocked<br/>(SAST)"]
    G2 -- No --> G3["3. Architecture violations > 0?"]
    G3 -- Yes --> BLK3["Blocked<br/>(Architecture)"]
    G3 -- No --> G4["4. Tier 3 (HighRisk)?"]
    G4 -- Yes --> HITL["RequiresHitl<br/>(human approval, even at score 100)"]
    G4 -- No --> G5["4b. Tier 2+ without independent Judge?"]
    G5 -- Yes --> CAP1["Capped<br/>(mandatory Judge absent/one-sided)"]
    G5 -- No --> G6["5. Trivial tier, score ≥ floor?"]
    G6 -- Yes --> CMP1["Complete<br/>(no spot-audit)"]
    G6 -- No --> G7["6. Score ≥ auto_complete (90)?"]
    G7 -- Yes --> CMP2["Complete<br/>(no spot-audit)"]
    G7 -- No --> G8["Score ≥ review (70)?"]
    G8 -- Yes --> CMP3["Complete<br/>(spot-audit)"]
    G8 -- No --> CAP2["Capped<br/>(below review band)"]
```

**Hard gates** (checked before the score is even consulted):
1. **Phase-A failures** — an unresolved compile/test/lint/type-check failure blocks immediately.
2. **SAST critical/high** — a secret leak or PAN-in-log hard-blocks regardless of score.
3. **Architecture violations** — unremediated boundary violations block.

**Tier-driven gates:**
4. **Tier 3 (HighRisk)** — forces human-in-the-loop even at Confidence 100.
4b. **Tier 2+ (Moderate/HighRisk)** — requires a genuine, context-isolated independent Judge panel verdict. A self-asserted `judge_approved = Some(true)` with `judge_independent = false` is "one-sided" and does not satisfy the mandate.

**Score-driven bands** (defaults from `GatePolicy::default()`):
- `≥ 90` → auto-complete (no spot-audit)
- `≥ 70` → complete with post-commit spot-audit
- `< 70` → capped (human hand-off)
- Trivial tier (`≥ 60` floor) → auto-complete without spot-audit

## 5. The Three Pipeline Outcomes

The orchestrator produces exactly one of three typed outcomes. There is **no fourth "mostly done" variant** by design.

```mermaid
graph TB
    PO["PipelineOutcome"]
    PO --> C["Complete<br/>{confidence, spot_audit, report}"]
    PO --> CAP["Capped<br/>{blocking_stage, reason, rounds_exhausted, gap_report}"]
    PO --> BLK["Blocked<br/>{stage, deterministic_failure}"]

    C --> CA["commit_approval() → Some(CommitApproval)<br/>← the ONLY path to a commit affordance"]
    CAP --> CA2["commit_approval() → None"]
    BLK --> CA3["commit_approval() → None"]
```

| Outcome | When | Commit? | Rendered as |
|---|---|---|---|
| **Complete** | All hard gates cleared, score in auto-complete or review band, Judge (if required) approved. | ✅ Yes (via `CommitApproval`) | "done" / commit affordance |
| **Capped** | Score below review band, Judge withheld, self-heal budget exhausted, or mandatory Judge absent/one-sided at Tier 2+. | ❌ No | Honest gap report + human hand-off |
| **Blocked** | A deterministic hard gate failed (Phase-A failure, SAST critical/high, architecture violation). | ❌ No | Hard block with exact failure detail |

The `CommitApproval` is a **sealed type** with no public constructor — it can only be obtained from `PipelineOutcome::commit_approval()`, which returns `Some` exclusively for `Complete`. This makes the anti-sycophancy invariant structural: a renderer has no code path to a "done" signal without a real `Complete` in hand.

## 6. Journaling and Tamper-Evidence

Every step of the pipeline pass is appended to a SHA-256 hash-chained [`Journal`]. The journal is the tamper-evident Event Log that a regulator reconstructs years later.

```mermaid
sequenceDiagram
    participant O as run_pipeline
    participant J as Journal
    participant V as Verifier

    O->>J: append(tick, PipelineStarted{edit_id, tier, blast_radius, rung})
    O->>J: append(tick, StageResult{stage, verdict, deterministic}) × N
    O->>J: append(tick, JudgeVerdict{approved, judge_model, context_isolation})
    O->>J: append(tick, StageResult{Confidence, Advisory{score, breakdown}})
    O->>J: append(tick, PipelineOutcome{outcome, confidence_score})

    Note over J: Each record chains: hash = SHA256(prev_hash || seq || tick || edit_id || event_json)

    V->>J: verify() — recompute entire chain, report first break
    V->>J: verify_seal(signer, seal) — signature over head_hash
```

**Journal events emitted by the orchestrator:**

| Event | When |
|---|---|
| `PipelineStarted` | At the start of `run_pipeline`, carrying the edit id, risk tier, blast radius, and edit-engine rung. |
| `StageResult` | For each stage report in the inputs, plus the synthesized Confidence stage. |
| `JudgeVerdict` | If `judge_approved` is `Some`, recording the verdict and context-isolation status. |
| `PipelineOutcome` | At the end, recording the outcome label and confidence score. |

Other events (`SelfHealTriggered`, `RoundCapped`, `RiskReclassified`, `WirePolicySealed`, `BreakerDifferential`) are emitted by the [self-healing loop](self_healing.md) and the [wire seal](wire_seal.md), not by the orchestrator itself.

## 7. Self-Heal Re-Entry Planning

The `StageCache` is the mechanism that makes self-heal efficient. When the [self-healing loop](self_healing.md) runs a fix-and-reverify cycle, it consults the `StageCache` to determine which stages must re-run:

```mermaid
flowchart TD
    R0["Self-heal round 0:<br/>Run all stages, record each in StageCache"]
    R0 --> O0{"PipelineOutcome?"}
    O0 -- Complete --> DONE0["Return (commit unlocked)"]
    O0 -- Capped/Blocked --> OBS["Build Observation{stage, exact tool output}"]
    OBS --> CODER["Coder.fix(round, files, observation) → new file set"]
    CODER --> HASH["content_hash(new_files)"]
    HASH --> PLAN["StageCache.stages_to_rerun(tier_stages, hash)"]
    PLAN --> R1["Self-heal round N:<br/>Re-run ONLY invalidated stages"]
    R1 --> O1{"PipelineOutcome?"}
    O1 -- Complete --> DONE1["Return"]
    O1 -- Capped/Blocked --> STUCK{"Stuck detector fires?"}
    STUCK -- Yes --> CAP_EARLY["Capped (stuck/thrash diagnosis)"]
    STUCK -- No --> RDBC{"Round cap reached?"}
    RDBC -- Yes --> CAP_FINAL["Capped (rounds exhausted)"]
    RDBC -- No --> OBS
```

**Re-entry rules:**
- **Phase-A stages** (Compile, Test, Lint, TypeCheck) **always** re-run, regardless of content hash — never trust a small change to skip the basics.
- **Expensive stages** (SAST, Architecture, Perf, Regression) are **cached** by `(stage, content_hash)`. If the file set's content hash hasn't changed, the stage is skipped.
- A **changed file set** (different content hash) re-invalidates all stages for that hash.

This implements the design's "re-enter at the earliest invalidated stage, not stage 1" principle: a fix confined to file X does not re-run Architecture/Perf/SAST on unrelated files whose hash didn't change.

## 8. How the Orchestrator Fits Into the System

```mermaid
graph TB
    subgraph "Surface Layer"
        SURF["surface::run_edit / run_review"]
        ET["edit_turn::run_edit_turn_full"]
        ST2["semantic_turn::run_semantic_turn_full"]
    end

    subgraph "Self-Heal Loop"
        SH["selfheal::run_selfheal_reclassified"]
    end

    subgraph "Orchestrator (this module)"
        RP["pipeline::run_pipeline"]
        SC["pipeline::StageCache"]
    end

    subgraph "Stage Execution"
        SDS["stages::run_deterministic_stages"]
    end

    subgraph "Policy Components"
        CONF["confidence::compute"]
        GATE["gate::decide"]
        RISK["risk::classify"]
        SAST["sast::BuiltinScanner"]
    end

    subgraph "Model Seams (ainxt-judge)"
        REV["Reviewer (finder)"]
        JP["JudgePanel (adjudicator)"]
        SD["StuckDetector"]
    end

    subgraph "Semantic Engine (ainxt-semantic)"
        LAD["ladder::EditLadder"]
        GRAPH["graph::SymbolGraph"]
        ARCH["arch::LayerContract"]
    end

    SURF --> ET
    SURF --> ST2
    ET --> SH
    ST2 --> ET
    SH --> SDS
    SH --> RP
    SH --> SC
    SH --> REV
    SH --> JP
    SH --> SD
    RP --> CONF
    RP --> GATE
    GATE --> RISK
    SDS --> SAST
    ET --> LAD
    RISK --> GRAPH
    SH --> ARCH
```

### Callers of `run_pipeline`

1. **[Self-healing loop](self_healing.md)** (`selfheal::run_selfheal_reclassified`) — the primary caller. Each self-heal round runs the deterministic stages, optionally runs perf/review/judge stages, assembles `PipelineInputs`, and calls `run_pipeline`. On `Complete` it returns; on `Capped`/`Blocked` it feeds the observation to the Coder and re-enters.

2. **[Surface review-only path](pipeline_stages_and_tools_surface_api.md)** (`surface::run_review`) — a single-pass review (no self-heal, no sink). Runs the deterministic stages + LLM Review + Judge panel, assembles `PipelineInputs`, and calls `run_pipeline` to produce the typed outcome.

3. **[Edit-turn gate](edit_turn_execution.md)** (`edit_turn::run_edit_turn_full`) — the public entrypoint for editing turns. Delegates to the self-heal loop, which in turn calls `run_pipeline`.

### What the orchestrator does NOT do

- **Does not run compilers/LLMs** — stage results are fed in by the caller.
- **Does not self-heal** — the [self-healing loop](self_healing.md) wraps `run_pipeline` in a bounded fix-and-reverify cycle.
- **Does not write to the sink** — the [edit-turn gate](edit_turn_execution.md) performs the durable write only after receiving a `CommitApproval` from a `Complete`.
- **Does not classify risk** — the [classification module](classification_and_risk.md) computes the tier before stage 1 runs; the orchestrator consumes it.
- **Does not compute architecture violations or test coverage** — the [semantic review module](pipeline_stages_and_tools_semantic_review.md) computes these from the code itself.

## 9. Dependency Graph

```mermaid
graph LR
    subgraph "Internal (ainxt-pipeline)"
        CONF["confidence"]
        GATE["gate"]
        JOURNAL["journal"]
        OUTCOME["outcome"]
        RISK["risk"]
        SAST["sast"]
        STAGE["stage"]
    end

    subgraph "External crates"
        SEM["ainxt-semantic<br/>(Rung, ladder)"]
        JUDGE["ainxt-judge<br/>(ReviewFinding, ReviewSeverity)"]
        SHA2["sha2<br/>(Sha256, Digest)"]
    end

    PIPELINE["pipeline.rs<br/>(this module)"]
    PIPELINE --> CONF
    PIPELINE --> GATE
    PIPELINE --> JOURNAL
    PIPELINE --> OUTCOME
    PIPELINE --> RISK
    PIPELINE --> SAST
    PIPELINE --> STAGE
    PIPELINE --> SEM
    PIPELINE --> SHA2
    CONF --> SAST
    CONF --> JUDGE
    CONF --> SEM
    GATE --> RISK
    GATE --> SAST
    GATE --> STAGE
    JOURNAL --> STAGE
    OUTCOME --> STAGE
```

## 10. Key Invariants

| # | Invariant | Enforced By |
|---|---|---|
| 1 | A Phase-A failure can never reach `Complete`. | `gate::decide` step 1, called by `run_pipeline`. |
| 2 | A SAST critical/high finding can never reach `Complete`, regardless of score. | `gate::decide` step 2. |
| 3 | An architecture boundary violation can never reach `Complete`. | `gate::decide` step 3. |
| 4 | A Tier-3 edit is always handed to a human, even at Confidence 100. | `gate::decide` step 4 (`RiskTier::forces_hitl`). |
| 5 | A Tier-2+ edit without a genuine independent Judge panel verdict is never `Complete`. | `gate::decide` step 4b. |
| 6 | A skip is never free — it is folded into the Confidence Score as a penalty. | `run_pipeline` defensively updates `confidence.skipped_stages` from observed reports. |
| 7 | The Judge's verdict is not a term in the Confidence Score arithmetic. | `confidence::compute` has no Judge input; the Judge is a gate *on top of* the score. |
| 8 | `CommitApproval` is un-forgeable outside the `outcome` module. | Private `seal: ()` field; only `PipelineOutcome::commit_approval()` constructs it. |
| 9 | Every pipeline step is journaled to a hash-chained, tamper-evident trail. | `run_pipeline` appends to `Journal` with monotonic ticks. |
| 10 | Self-heal re-enters at the earliest invalidated stage, not stage 1. | `StageCache::stages_to_rerun` with content-hash caching. |
| 11 | Compile, test, lint, and type-check always re-run for any touched file. | `always_reruns()` in `StageCache::should_run`. |

## 11. Related Module Documentation

| Module | Relationship |
|---|---|
| [pipeline_stages_and_tools_stage_model](pipeline_stages_and_tools_stage_model.md) | The `Stage` enum, `StageReport`, and `StageVerdict` types consumed by the orchestrator. |
| [pipeline_stages_and_tools_stage_execution](pipeline_stages_and_tools_stage_execution.md) | The `StageTools` trait and `run_deterministic_stages` driver that produces the stage reports the orchestrator consumes. |
| [pipeline_stages_and_tools_commit_gate](pipeline_stages_and_tools_commit_gate.md) | The `GateContext`, `GatePolicy`, `GateDecision`, and `decide()` function that the orchestrator delegates the final policy decision to. |
| [pipeline_stages_and_tools_surface_api](pipeline_stages_and_tools_surface_api.md) | The `run_edit` / `run_review` entrypoints that call `run_pipeline` (review-only path) or the self-heal loop (editing path). |
| [pipeline_stages_and_tools_semantic_review](pipeline_stages_and_tools_semantic_review.md) | The `analyze_semantic_gate` function that computes architecture violations and test coverage from the code, feeding the orchestrator's `architecture_violations` and `confidence.blast_radius_test_coverage`. |
| [pipeline_stages_and_tools_sast](pipeline_stages_and_tools_sast.md) | The `BuiltinScanner` and `SastFinding` types that produce the SAST findings the orchestrator hard-blocks on. |
| [pipeline_stages_and_tools_breaker](pipeline_stages_and_tools_breaker.md) | The optional Tier-3 differential/invariant oracle. |
| [classification_and_risk](classification_and_risk.md) | The `RiskTier`, `classify()`, and `classify_edit()` that compute the tier before stage 1 runs. |
| [self_healing](self_healing.md) | The `run_selfheal_reclassified` loop that wraps `run_pipeline` in a bounded fix-and-reverify cycle, using `StageCache` for re-entry planning. |
| [edit_turn_execution](edit_turn_execution.md) | The `run_edit_turn_full` gate that binds a code-editing turn to a `PipelineOutcome` and performs the durable write only on `Complete`. |
| [journaling](journaling.md) | The `Journal`, `PipelineEvent`, `JournalRecord`, and `SignedSeal` types that provide tamper-evident regulator replay. |
| [performance](performance.md) | The `analyze_perf` stage-6 function that produces the `perf_regression_penalty` fed into `ConfidenceInputs`. |
| [wire_seal](wire_seal.md) | The `seal_wire_config` function that replaces wire-supplied policy fields with deployment-derived values before the orchestrator runs. |
