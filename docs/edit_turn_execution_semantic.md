# `edit_turn_execution_semantic` â€” Semantic-Op Edit Turn

> Source: `crates/ainxt-pipeline/src/semantic_turn.rs`


## Brief Introduction

The `edit_turn_execution_semantic` module is the bridge between *agent-expressed*
structural code operations â€” rename a symbol, change a signature, extract/inline/move
a function, or replace a single function body â€” and the pipeline's durable,
atomic commit gate.

It lives inside the broader **edit-turn execution** subsystem
(`pipeline_runtime â†’ pipeline_orchestration â†’ edit_turn_execution`).
While [`edit_turn_execution_core`](edit_turn_execution_core.md) handles generic
file-level edits and [`edit_turn_execution_ladder`](edit_turn_execution_ladder.md)
handles multi-rung replacements, this module is responsible for:

1. **Parsing** a high-level [`AgentOp`](#agentop) into the concrete planning
   primitives provided by [`edit_semantic`](edit_semantic.md).
2. **Selecting the correct fidelity rung** (LSP â†’ AST â†’ structured patch â†’ text)
   for the operation and language.
3. **Planning** a deterministic, multi-file [`FileEdit`](edit_semantic.md) set.
4. **Handing the planned edit set to the full guarded edit turn**, which runs
   self-heal, SAST, review seams, classification, and atomic commit/rollback.

A durable write is only reachable when the underlying gate returns
`TurnOutcome::Committed` with a [`CommitApproval`](edit_turn_execution_outcome.md).
Planning failures never touch the workspace sink.

---

## Core Components

### `AgentOp`

`AgentOp` is the user/agent-facing request vocabulary. It is intentionally
restricted to operations that the AST rung can plan deterministically, so the
system never silently falls back to a dangerous text patch for a structural
operation.

| Variant | Maps to `SemanticOp` | Notes |
|---|---|---|
| `Rename { old, new }` | `RenameSymbol` | Cross-file AST rename; falls back to `field_rename_via_xref` for struct/enum fields |
| `ChangeSignature { name, spec }` | `ChangeSignature` | Adds a parameter and updates every call site |
| `Extract { file, enclosing, start_line, end_line, new_name }` | `ExtractFunction` | Extracts a line range into a new function |
| `Inline { name }` | `InlineFunction` | Inlines a single-expression function |
| `Move { name, from_file, to_file }` | `MoveDefinition` | Moves a definition across files |
| `ReplaceFunction { file, function_name, new_def, ... }` | `ReplaceFunction` | Smaller-blast-radius function replacement via the full wired ladder |

`AgentOp::semantic_op()` returns the [`edit_semantic`](edit_semantic.md) operation
class, and `AgentOp::lsp_target()` builds the `LspEditTarget` needed by an LSP
driver (currently populated for `Rename`).

`AgentOp` is serialized with `#[serde(tag = "op", rename_all = "snake_case")]`,
so external callers (HTTP API, planner surfaces, CLI) send requests such as:

```json
{ "op": "rename", "old": "charge", "new": "payment" }
```

### `SemanticTurn`

A `SemanticTurn` binds together everything needed for one semantic pass:

- `edit_id` â€” stable identifier for the turn.
- `files` â€” the working tree of AST-parseable [`SourceFile`](edit_semantic.md)
  snapshots the op is planned against.
- `op` â€” the [`AgentOp`](#agentop) to perform.
- `config` â€” a [`SelfHealConfig`](self_healing.md) that carries the rung, tier,
  and self-heal parameters.

### `PlanError`

`PlanError` captures why an operation could not be turned into an edit set
*before* any write occurs:

- `Plan(OpError)` â€” the AST planner rejected the op (invalid identifier, name
  collision, symbol not found, etc.).
- `FileNotFound(path)` â€” a file referenced by the op is missing from the turn.
- `FieldRenameRefused(detail)` â€” the field-rename fallback refused because the
  old identifier does not occur or the new one collides.
- `LadderExhausted(detail)` â€” the `ReplaceFunction` ladder exhausted every
  capable rung.

Because planning is pure, returning a `PlanError` leaves the sink untouched.

### `SemanticTurnOutcome`

The result of a planned and gated semantic turn:

- `rung` â€” the fidelity rung the operation actually resolved at. This is fed
  into the Confidence Score as an honest edit-fidelity penalty.
- `plan` â€” the multi-file `FileEdit` set produced by the planner.
- `turn` â€” the final `TurnOutcome` from the guarded edit turn
  (`Committed` or `HandedToHuman`).


### Public API

The module exposes three entry points in `crates/ainxt-pipeline/src/semantic_turn.rs`:

- `run_semantic_turn(turn, coder, tools, scanner, sink, journal)` — plans the
  op through the AST rung and drives it through the full guarded edit turn.
- `run_semantic_turn_with_lsp(turn, lsp, coder, tools, scanner, sink, journal)` —
  same as above, but first attempts a language-server refactor for every file
  the AST plan would touch.
- `run_semantic_turn_full(turn, lsp, review, coder, tools, scanner, sink, journal)` —
  the most general entry point, adding the optional independent `ReviewSeams`
  panel required for Tier 2+ edits.

All three return `Result<SemanticTurnOutcome, PlanError>`.

---

## Architecture

```mermaid
classDiagram
    direction TB

    class AgentOp {
        +Rename
        +ChangeSignature
        +Extract
        +Inline
        +Move
        +ReplaceFunction
        +semantic_op() SemanticOp
        +lsp_target(path) LspEditTarget
    }

    class SemanticTurn {
        +String edit_id
        +Vec~SourceFile~ files
        +AgentOp op
        +SelfHealConfig config
    }

    class PlanError {
        +Plan(OpError)
        +FileNotFound(String)
        +FieldRenameRefused(String)
        +LadderExhausted(String)
    }

    class SemanticTurnOutcome {
        +Rung rung
        +Vec~FileEdit~ plan
        +TurnOutcome turn
        +committed() bool
    }

    class run_semantic_turn {
        +run_semantic_turn(...)
        +run_semantic_turn_with_lsp(...)
        +run_semantic_turn_full(...)
    }

    AgentOp --> SemanticTurn : "carried by"
    SemanticTurn --> run_semantic_turn : "input"
    run_semantic_turn --> SemanticTurnOutcome : "produces"
    run_semantic_turn ..> PlanError : "may return"
```

The module itself is thin and compositional: it does not implement the gate,
the workspace, or the semantic planner. It translates an `AgentOp` into the
right lower-level primitives and then delegates to:

- [`edit_semantic`](edit_semantic.md) for AST-precise planning.
- [`edit_turn_execution_ladder`](edit_turn_execution_ladder.md) for the
  `ReplaceFunction` wired ladder.
- [`edit_turn_execution_core`](edit_turn_execution_core.md) for the guarded
  self-heal commit gate.
- [`journaling`](journaling.md) for the hash-chained audit trail.

---

## Data Flow

```mermaid
flowchart LR
    A[AgentOp request] --> B[SemanticTurn]
    B --> C{Select primary source}
    C -->|language + op| D[Ladder rung selection]
    D --> E[Plan via AST ops]
    E -->|Rename field fallback| F[ainxt-edit field_rename_via_xref]
    E -->|ReplaceFunction| G[run_replace_ladder]
    G --> H{AST / structured / text}
    E --> I{Optional LSP driver}
    I -->|all files applied| J[Adopt LSP plan @ Rung::Lsp]
    I -->|partial/declined| K[Keep AST plan @ current rung]
    F --> L[Materialize applied file set]
    J --> L
    K --> L
    H -->|success| L
    H -->|exhausted| M[PlanError::LadderExhausted]
    L --> N[Build EditTurn]
    N --> O[run_edit_turn_full_guarded]
    O --> P{CommitApproval?}
    P -->|yes| Q[Atomic apply + journal commit SHA]
    P -->|no| R[HandedToHuman]
    Q --> S[SemanticTurnOutcome Committed]
    R --> T[SemanticTurnOutcome HandedToHuman]
```

---

## Component Interaction

```mermaid
sequenceDiagram
    participant Caller
    participant STS as SemanticTurn
    participant ST as run_semantic_turn_inner
    participant LSP as LspRefactor (optional)
    participant SEM as ainxt-semantic ops
    participant LDR as ladder_driver
    participant ETC as edit_turn (core)
    participant SH as selfheal
    participant SAST as SastScanner
    participant Sink as WorkspaceSink
    participant JNL as Journal

    Caller->>STS: create SemanticTurn
    Caller->>ST: run_semantic_turn(...)
    ST->>SEM: primary_source + semantic_op
    alt Rename / ChangeSignature / Extract / Inline / Move
        ST->>SEM: plan_* operation
        SEM-->>ST: Vec<FileEdit> or OpError
        alt Rename field not in symbol graph
            ST->>SEM: field_rename_via_xref
            SEM-->>ST: FileEdit @ StructuredPatch
        end
    else ReplaceFunction
        ST->>LDR: run_replace_ladder(WiredReplace)
        LDR-->>ST: FallTrail (applied_rung + result)
    end
    opt LSP driver present and not ReplaceFunction
        ST->>LSP: apply(lang, op, source, target) per file
        LSP-->>ST: Applied / Unavailable / Failed
    end
    ST->>ST: materialize applied_files
    ST->>ETC: EditTurn(original_files, applied_files, config)
    ETC->>SH: run_selfheal_reclassified
    ETC->>SAST: scan
    ETC->>JNL: record stages
    ETC-->>ST: TurnOutcome
    alt TurnOutcome::Committed
        ST->>Sink: atomic apply (via Workspace::apply_atomic)
        ST->>JNL: set_commit_sha
        ST-->>Caller: SemanticTurnOutcome(Committed)
    else HandedToHuman
        ST-->>Caller: SemanticTurnOutcome(HandedToHuman)
    end
```

---

## Process Flow: Planning and Gating a Semantic Turn

### 1. Language and Rung Selection

The primary source file is chosen from the turn's file set:

- `Extract`, `Move`, and `ReplaceFunction` use the file named in the op.
- All other ops use the first file.

The source language is converted to the ladder's `CodeLanguage`, and the
operation's `SemanticOp` class is used to confirm that the AST rung is capable.
For every structural op except `ReplaceFunction`, the initial rung is `Ast`.

### 2. Planning the Edit Set

The planner dispatches by op:

| Op | Planner | Fallback |
|---|---|---|
| `Rename` | `plan_rename_symbol` | `field_rename_via_xref` for struct/enum fields |
| `ChangeSignature` | `apply_change_signature` | â€” |
| `Extract` | `plan_extract_function` | â€” |
| `Inline` | `plan_inline_function` | â€” |
| `Move` | `plan_move_definition` | â€” |
| `ReplaceFunction` | `run_replace_ladder` | AST â†’ structured anchored patch â†’ literal text replace |

The `ReplaceFunction` path is intentionally different from a plain full-file
regeneration: it targets a single function body, keeping the blast radius small.
See [`edit_turn_execution_ladder`](edit_turn_execution_ladder.md) for the ladder
mechanics.

### 3. Optional LSP Refactor

If an `LspRefactor` driver is supplied, the module attempts to apply the
language server to *every* file the AST plan would touch. A partial LSP result
is never mixed with AST edits; if any file is `Unavailable` or `Failed`, the
system falls back to the already-selected plan and records the original rung.
When the LSP succeeds for all files, the plan is replaced with the LSP result
and the rung is recorded as `Rung::Lsp`.

### 4. Materialize the Applied Tree

The planned `FileEdit` set is overlaid onto the original file set by path,
producing `applied_files`. This is the candidate tree that the gate will verify.

### 5. Run the Guarded Edit Turn

An [`EditTurn`](edit_turn_execution_core.md) is constructed from the original
and applied file sets, with `config.rung` set to the selected rung. The turn is
passed to `run_edit_turn_full_guarded`, which:

- Classifies the edit (see
  [`classification_and_risk`](classification_and_risk.md)).
- Runs the self-heal loop (see [`self_healing`](self_healing.md)).
- Enforces SAST, review seams, and optional performance/semantic gates.
- Requires a `CommitApproval` before any durable write.
- Applies the method-preservation guard and then atomically commits to the sink.

For structural ops, `guard_methods` is set to `false` because a rename or
extract legitimately makes an old symbol name disappear; the import-restore half
of the guard still runs.

### 6. Outcome

- `Committed` â€” the sink now holds the new file versions and the journal records
  a content-hash commit SHA.
- `HandedToHuman` â€” the gate did not clear; the sink remains at the pre-edit
  baseline.

---

## Rung Fidelity and Confidence Scoring

The selected rung is stored in `SemanticTurnOutcome::rung` and in the turn's
`SelfHealConfig`. The pipeline's Confidence Score uses the rung as an honest
edit-fidelity penalty:

- `Lsp` â€” toolchain-grade refactor, no penalty.
- `Ast` â€” tree-sitter AST transform, small penalty.
- `StructuredPatch` â€” anchored text rewrite, larger penalty.
- `TextPatch` â€” literal find/replace, largest penalty.

This prevents a lower-fidelity apply from being scored as if it were a precise
LSP/AST transform.

---

## Error Handling

All planning errors are returned as `PlanError` before any side effects:

```rust
pub enum PlanError {
    Plan(OpError),
    FileNotFound(String),
    FieldRenameRefused(String),
    LadderExhausted(String),
}
```

Runtime failures inside the guarded edit turn (deterministic stage failures,
SAST findings, review rejection, atomic apply failure, method-preservation
guard) are captured in `TurnOutcome::HandedToHuman` and surfaced through
`SemanticTurnOutcome::turn`.

---

## How It Fits into the System

`edit_turn_execution_semantic` sits at the intersection of three larger
subsystems:

1. **Semantic code understanding** â€” it consumes the symbol graph, LSP refactor
   seam, and AST-precise operations from [`edit_semantic`](edit_semantic.md).
2. **Edit-turn execution** â€” it delegates the actual gate, rollback, and atomic
   commit to [`edit_turn_execution_core`](edit_turn_execution_core.md) and the
   replace-function ladder to
   [`edit_turn_execution_ladder`](edit_turn_execution_ladder.md).
3. **Pipeline orchestration** â€” it participates in the stage/tooling ecosystem
   ([`pipeline_stages_and_tools`](pipeline_stages_and_tools.md)), risk
   classification ([`classification_and_risk`](classification_and_risk.md)),
   self-healing ([`self_healing`](self_healing.md)), and audit journaling
   ([`journaling`](journaling.md)).

Higher-level callers (for example, the server's `EditState` or planner-driven
program surfaces) express intent as an `AgentOp`; this module turns that intent
into a safe, observable, and reversible code change.

---

## References

- [`edit_turn_execution_core`](edit_turn_execution_core.md) â€” generic edit turn,
  `EditTurn`, `TurnOutcome`, and `run_edit_turn_full_guarded`.
- [`edit_turn_execution_ladder`](edit_turn_execution_ladder.md) â€” the
  `run_replace_ladder` and `WiredReplace` multi-rung replacement driver.
- [`edit_turn_execution_outcome`](edit_turn_execution_outcome.md) â€”
  `CommitApproval` and pipeline outcome types.
- [`edit_semantic`](edit_semantic.md) â€” AST-precise planning, `SymbolGraph`,
  `FileEdit`, `WorkspaceSink`, and the `Rung` ladder model.
- [`self_healing`](self_healing.md) â€” the self-heal loop, `Coder`,
  `SelfHealConfig`, and `ReviewSeams`.
- [`classification_and_risk`](classification_and_risk.md) â€” edit risk
  classification and tier escalation.
- [`pipeline_stages_and_tools`](pipeline_stages_and_tools.md) â€” `StageTools`,
  `SastScanner`, and stage execution.
- [`journaling`](journaling.md) â€” `Journal`, commit SHA binding, and forensic
  replay support.
