# Lifecycle DSAR Tiers

## Brief Introduction

The `lifecycle_dsar_tiers` module implements **real, production-grade cross-tier lineage resolvers** for Data Subject Access Request (DSAR) compliance. It closes the **FI-09** gap identified in `REGULATED_FI_COMPLIANCE_OPS.md` §4.4 step 2 (ADR-012/015): the sibling [lifecycle_dsar](lifecycle_dsar.md) module built the completeness-checked `LineageResolver` seam and the `CompleteLineage` / `fulfill_access_complete` machinery, but every required tier except `lifecycle-store` was a test double — so real cross-tier completeness was unproven. This module closes that gap by implementing `LineageResolver` over the **real in-memory/offline representations** of the actual data tiers, so a DSAR access export assembled from live objects either resolves the subject across *every* mandated tier or is refused.

All adapters are **pure**: no clock, no RNG, no I/O in `resolve`. The caller (the served HTTP handler or a programmatic embedder) is responsible for taking locks and making the real `export_subject` calls against the actual Redis/Postgres/KG/embedding-store/trace-log/incident-register organs and handing the resulting values in.

---

## Architecture Overview

### The Eight Mandated DSAR Tiers

A DPDP access/portability export must span eight canonical data tiers. Each tier is backed by a real type from the runtime's own already-hydrated, live snapshots:

| Required Tier | Real Backing Type | Resolver in This Module |
|---|---|---|
| `lifecycle-store` | `RecordStore` (in-crate, already wired in [lifecycle_core](lifecycle_core.md)) | `RecordStore` impl of `LineageResolver` (in [lifecycle_dsar](lifecycle_dsar.md)) |
| `redis-session` | `ainxt_memory` fabric — `MemoryKind::Session` items | `MemoryTier::redis_session` |
| `postgres-episodic` | `ainxt_memory` fabric — `MemoryKind::Episodic` items | `MemoryTier::postgres_episodic` |
| `kg-memoryfact` | `ainxt_memory` fabric — `MemoryKind::Semantic` items | `MemoryTier::kg_memoryfact` |
| `embeddings` | `ainxt_memory` fabric — items carrying a derived embedding | `MemoryTier::embeddings` |
| `traces` | `ainxt_eventlog::LogRecord` (offline; no file I/O) | `TraceTier` |
| `incident-register` | `ainxt_incident::IncidentRegister` | `IncidentTier` |
| `dsar-register` | `DsarRegister` itself (the subject's own DSAR history) | `DsarRegister` impl of `LineageResolver` |

```mermaid
graph TB
    subgraph "DSAR Access Export (CompleteLineage)"
        CL["CompleteLineage<br/>with_default_required()"]
    end

    subgraph "Resolvers Implemented in This Module"
        MT["MemoryTier<br/>(4 facets from 1 export)"]
        TT["TraceTier"]
        IT["IncidentTier"]
        DR["DsarRegister<br/>(self-tier impl)"]
    end

    subgraph "Resolver Already in lifecycle_dsar"
        RS["RecordStore<br/>(lifecycle-store tier)"]
    end

    subgraph "Real Backing Types (Hydrated by Caller)"
        SE["SubjectExport<br/>(ainxt_memory)"]
        LR["Vec<LogRecord><br/>(ainxt_eventlog)"]
        IR["IncidentRegister<br/>(ainxt_incident)"]
        DSR["DsarRegister<br/>(ainxt_lifecycle::dsar)"]
        RST["RecordStore<br/>(ainxt_lifecycle)"]
    end

    CL --> MT
    CL --> TT
    CL --> IT
    CL --> DR
    CL --> RS

    MT --> SE
    TT --> LR
    IT --> IR
    DR --> DSR
    RS --> RST

    SE -.->|"redis-session<br/>postgres-episodic<br/>kg-memoryfact<br/>embeddings"| MT
```

### Module Position in the System

This module sits within the `lifecycle` sub-module group under `governance_compliance`. It is the **wiring layer** that connects the DSAR completeness machinery (defined in [lifecycle_dsar](lifecycle_dsar.md)) to the real data-tier types owned by other crates.

```mermaid
graph LR
    subgraph "governance_compliance"
        subgraph "lifecycle"
            LC["lifecycle_core<br/>(RecordStore, RetentionPolicy,<br/>LegalHold, ErasureAttestation)"]
            LD["lifecycle_dsar<br/>(DsarRegister, CompleteLineage,<br/>LineageResolver trait)"]
            LDT["lifecycle_dsar_tiers<br/>(THIS MODULE)"]
            LGE["lifecycle_guarded_erasure<br/>(ErasableTier, GuardedErasure)"]
            LBG["lifecycle_breakglass<br/>(BreakGlassProgram)"]
            LR["lifecycle_routes<br/>(DsarWorkflow, RetentionService)"]
        end
        INC["incident<br/>(IncidentRegister)"]
    end

    subgraph "ai_engine"
        MEM["memory_management<br/>(MemoryItem, SubjectExport)"]
    end

    subgraph "core_infrastructure"
        EL["core_interaction<br/>(LogRecord, EventLog)"]
        TYP["security_config_identity<br/>(DataClass, Principal)"]
    end

    LDT -->|"implements LineageResolver"| LD
    LDT -->|"uses RecordStore"| LC
    LDT -->|"wraps IncidentRegister"| INC
    LDT -->|"wraps SubjectExport"| MEM
    LDT -->|"wraps LogRecord"| EL
    LDT -->|"uses DataClass"| TYP
    LD -->|"defines trait + CompleteLineage"| LDT
    LR -->|"calls hydrate_default_lineage"| LDT
```

---

## Core Components

### `MemoryTier`

A real memory-fabric lineage tier backed by `ainxt_memory`'s DPDP subject export (`SubjectExport`, produced by the live store's `export_subject`). One export feeds **four** logical tiers (one per `MemoryFacet`); registering each is what makes the memory tiers count toward cross-tier completeness.

```mermaid
classDiagram
    class MemoryTier {
        +tier: String
        +facet: MemoryFacet
        +export: SubjectExport
        +new(tier, facet, export) MemoryTier
        +redis_session(export) MemoryTier
        +postgres_episodic(export) MemoryTier
        +kg_memoryfact(export) MemoryTier
        +embeddings(export) MemoryTier
        +resolve(subject_id) Vec~LineageRecord~
    }

    class MemoryFacet {
        <<enum>>
        +Kind(MemoryKind)
        +Embeddings
    }

    class SubjectExport {
        +subject: String
        +items: Vec~MemoryItem~
    }

    class LineageResolver {
        <<trait>>
        +resolve(subject_id) Vec~LineageRecord~
    }

    MemoryTier ..|> LineageResolver
    MemoryTier --> MemoryFacet
    MemoryTier --> SubjectExport
```

**Key design decisions:**

- **Subject-scoped**: A mismatched `subject_id` contributes nothing — no cross-subject leak. The export's `subject` field is checked first; only items whose `scope == Scope::User(subject_id)` are considered.
- **Facet filtering**: Each `MemoryTier` instance projects the same `SubjectExport` through one `MemoryFacet`:
  - `MemoryFacet::Kind(MemoryKind::Session)` → `redis-session` tier
  - `MemoryFacet::Kind(MemoryKind::Episodic)` → `postgres-episodic` tier
  - `MemoryFacet::Kind(MemoryKind::Semantic)` → `kg-memoryfact` tier
  - `MemoryFacet::Embeddings` → `embeddings` tier (items where `embedding.is_some()`)
- **Full version history**: Every version of every matching item is surfaced (DPDP portability = full history), with record ids formatted as `"{id}#v{version}"`.
- **PII-in-embeddings captured**: Items carrying a derived embedding are regulated even as vectors — the `embeddings` tier ensures PII baked into embedding vectors appears in the access export (gap AJ).

### `TraceTier`

The `traces` tier — an offline, in-memory representation of the tamper-evident trace log (`ainxt_eventlog::LogRecord`). Resolves the trace records whose `actor` field matches the subject. No file I/O runs in `resolve` (the caller hydrates the records; the resolver is pure).

```mermaid
classDiagram
    class TraceTier {
        +records: Vec~LogRecord~
        +new(records) TraceTier
        +resolve(subject_id) Vec~LineageRecord~
    }

    class LogRecord {
        +session: String
        +seq: u64
        +ts_millis: u128
        +actor: String
        +kind: String
        +text: String
        +prev_hash: String
        +hash: String
        +hash_alg: String
    }

    class LineageRecord {
        +tier: String
        +record_id: String
        +subject_id: String
        +data_class: DataClass
        +summary: String
    }

    TraceTier ..|> LineageResolver
    TraceTier --> LogRecord
    TraceTier ..> LineageRecord : produces
```

**Key design decisions:**

- **Actor-based matching**: Only records where `r.actor == subject_id` are surfaced.
- **Operational metadata classification**: Trace records are classified `DataClass::Internal` — the trace log stores control-plane events, not payload PII by design.
- **Deterministic ordering**: Results are sorted by `record_id` (which is `"{session}#{seq}"`).
- **Record id format**: `"{session}#{seq}"` — uniquely identifies a trace record within the log.

### `IncidentTier`

The `incident-register` tier — wraps a real `ainxt_incident::IncidentRegister`. Incidents are aggregate and PII-free by design (they carry an *estimate* of affected principals, never subject ids), so the subject→incident linkage lives in the incident-response case file, supplied here as an explicit `BTreeMap<String, Vec<String>>` index.

```mermaid
classDiagram
    class IncidentTier {
        +register: IncidentRegister
        +subject_index: BTreeMap~String, Vec~String~~
        +new(register) IncidentTier
        +link(subject_id, incident_id) IncidentTier
        +resolve(subject_id) Vec~LineageRecord~
    }

    class IncidentRegister {
        +arming: ArmingPolicy
        +incidents: BTreeMap~String, Incident~
        +events: Vec~IncidentEvent~
        +incident(id) Option~&Incident~
    }

    class Incident {
        +id: String
        +class: IncidentClass
        +t0: Tick
        +affected_data_classes: BTreeSet~DataClass~
        +affected_principal_estimate: u64
        +status: IncidentStatus
    }

    IncidentTier ..|> LineageResolver
    IncidentTier --> IncidentRegister
    IncidentRegister --> Incident
```

**Key design decisions:**

- **Case-file linkage**: The `subject_index` maps subject ids to incident ids known to implicate them. This is populated via the chainable `link()` builder. Unknown ids are simply not surfaced at resolve time (the register is the source of truth).
- **Fail-safe data class**: The most-sensitive class among the incident's `affected_data_classes` is used (max by `sensitivity()`), defaulting to `DataClass::Internal` if none.
- **Register is the source of truth**: `resolve` pulls linked incidents from the *real* register via `register.incident(id)`, proving the register was queried and the referenced incidents actually exist. An incident id in the case-file index that does not exist in the register is silently skipped.

### `DsarRegister` (self-tier impl)

The `dsar-register` self-tier — a subject's DSAR history is itself data held about them, so an access export must include it (§4.4). This is implemented as a `LineageResolver` impl directly on `DsarRegister` (not a wrapper struct). A *snapshot* (`DsarRegister` is `Clone`) is registered so the tier does not alias the live register being fulfilled.

```mermaid
classDiagram
    class DsarRegister {
        +requests: BTreeMap~String, DsarRequest~
        +events: Vec~DsarEvent~
        +requests() Iterator~&DsarRequest~
        +resolve(subject_id) Vec~LineageRecord~
    }

    class DsarRequest {
        +id: String
        +subject_id: String
        +kind: DsarKind
        +status: DsarStatus
        +opened_tick: u64
        +sla_ticks: u64
        +identity_proofed: bool
    }

    DsarRegister ..|> LineageResolver
    DsarRegister --> DsarRequest
```

**Key design decisions:**

- **Self-referential by design**: The DSAR register tracks requests *about* a subject; those requests are themselves personal data the subject has a right to see.
- **Snapshot isolation**: Callers register a `clone()` of the register, not a reference, so the tier's view is frozen at hydration time and cannot be mutated by the fulfilment itself.
- **Classification**: DSAR request records are classified `DataClass::Internal` (operational metadata about the request, not the subject's underlying data).

---

## The `hydrate_default_lineage` Assembly Function

This is the **central wiring function** that assembles the mandated `CompleteLineage` for a DSAR access/portability fulfilment from the daemon's own already-hydrated, live snapshots. It is pure (no locking / clock / RNG / I/O) — consistent with every other resolver in this module.

```mermaid
flowchart TD
    subgraph "Caller (served HTTP handler or embedder)"
        A["1. Take locks"]
        B["2. Call export_subject on<br/>live Redis/Postgres/KG/embedding store"]
        C["3. Hydrate trace records from EventLog"]
        D["4. Gather incident case-file links"]
        E["5. Call hydrate_default_lineage()"]
        F["6. Call DsarRegister::fulfill_access_complete()"]
    end

    subgraph "hydrate_default_lineage (THIS MODULE)"
        G["Assemble CompleteLineage<br/>with_default_required()"]
        H["Register lifecycle-store tier<br/>(RecordStore clone)"]
        I["Register dsar-register tier<br/>(DsarRegister clone)"]
        J["Register traces tier<br/>(TraceTier)"]
        K["Register incident-register tier<br/>(IncidentTier with links)"]
        L{"memory_export<br/>is Some?"}
        M["Register 4 memory tiers:<br/>redis-session, postgres-episodic,<br/>kg-memoryfact, embeddings"]
        N["Leave 4 memory tiers<br/>unregistered"]
        O["Return CompleteLineage"]
    end

    A --> B --> C --> D --> E
    E --> G
    G --> H --> I --> J --> K --> L
    L -->|"Yes"| M --> O
    L -->|"No (refused or no backend)"| N --> O
    O --> F
```

### Parameters

| Parameter | Type | Description |
|---|---|---|
| `retention` | `&RecordStore` | The live retention/precedence store (cloned into the tier). |
| `dsar_register` | `&DsarRegister` | The live DSAR register (cloned as a snapshot for the self-tier). |
| `incidents` | `&IncidentRegister` | The real incident register (cloned into the `IncidentTier`). |
| `incident_links` | `&[String]` | Case-file linkage: incident ids known to implicate `subject_id`. Pass `&[]` when no such index exists. |
| `subject_id` | `&str` | The data principal whose data is being exported. |
| `trace_records` | `Vec<LogRecord>` | Hydrated trace log records (offline; no file I/O in resolve). |
| `memory_export` | `Option<SubjectExport>` | The subject's memory-fabric export. `None` when no live memory backend is configured, OR when the real `export_subject` call refused the operating principal. |

### Memory Export Absence Handling

When `memory_export` is `None`, the four memory-derived tiers (`redis-session`, `postgres-episodic`, `kg-memoryfact`, `embeddings`) are simply left unregistered. This means:

- `CompleteLineage::missing_tiers()` reports them as missing.
- A `require_complete=true` fulfilment is correctly **REFUSED** rather than certifying a partial export.
- **Never** a fabricated/empty stand-in is substituted.

This is the fail-closed posture: a missing tier is a detectable defect, not a silent gap. The caller can still fulfil with `require_complete=false` if a best-effort export is acceptable, but the completeness proof will honestly report the missing tiers.

### Identical Tier-Registration Logic

This function ensures every served caller gets **identical** tier-registration logic — the served HTTP path (`ainxt_server`'s `regfi_dsar_handler`) and the programmatic embedder path (`ainxt_runtimed`'s `AssembledFull`) can never silently diverge on which tiers count toward completeness.

---

## Data Flow: DSAR Access Fulfilment

```mermaid
sequenceDiagram
    participant Caller as Served Handler / Embedder
    participant Hdl as hydrate_default_lineage
    participant CL as CompleteLineage
    participant Reg as DsarRegister
    participant Res as Resolvers (8 tiers)

    Caller->>Caller: Take locks, hydrate live snapshots
    Caller->>Hdl: hydrate_default_lineage(retention, dsar_reg, incidents, links, subject, traces, memory_export)

    Hdl->>CL: CompleteLineage::with_default_required()
    Hdl->>Res: Register lifecycle-store (RecordStore clone)
    Hdl->>Res: Register dsar-register (DsarRegister clone)
    Hdl->>Res: Register traces (TraceTier)
    Hdl->>Res: Register incident-register (IncidentTier + links)

    alt memory_export is Some
        Hdl->>Res: Register redis-session (MemoryTier::redis_session)
        Hdl->>Res: Register postgres-episodic (MemoryTier::postgres_episodic)
        Hdl->>Res: Register kg-memoryfact (MemoryTier::kg_memoryfact)
        Hdl->>Res: Register embeddings (MemoryTier::embeddings)
    else memory_export is None
        Note over Hdl,Res: 4 memory tiers left unregistered<br/>(fail-closed, not fabricated)
    end

    Hdl-->>Caller: CompleteLineage

    Caller->>Reg: fulfill_access_complete(id, lineage, require_complete=true, now)

    alt missing_tiers is non-empty
        Reg-->>Caller: Err(IncompleteLineage { missing })
        Note over Caller: DSAR left un-fulfilled<br/>(not silently under-reported)
    else all tiers registered
        Reg->>CL: resolve_complete(subject_id)
        CL->>Res: Fan-out: each tier.resolve(subject_id)
        Res-->>CL: Vec<LineageRecord> per tier
        CL-->>Reg: LineageExport { records, covered, missing }
        Reg->>Reg: Mark Fulfilled, append hash-chained event
        Reg-->>Caller: Ok(LineageExport)
    end
```

---

## Subject Isolation Guarantee

Every resolver in this module is **subject-scoped**: querying a different subject yields nothing. This is enforced at three levels:

```mermaid
flowchart LR
    subgraph "MemoryTier"
        M1["Check export.subject == subject_id"]
        M2["Filter items by scope == User(subject_id)"]
        M3["Filter by facet (Kind or Embeddings)"]
    end

    subgraph "TraceTier"
        T1["Filter records by actor == subject_id"]
    end

    subgraph "IncidentTier"
        I1["Look up subject_index[subject_id]"]
        I2["If absent → return empty"]
        I3["For each linked incident_id:<br/>verify it exists in register"]
    end

    M1 -->|"mismatch → empty"| M2
    M2 --> M3
    T1 -->|"mismatch → empty"| T1
    I1 --> I2
    I2 --> I3
```

This is verified by the `tiers_do_not_leak_across_subjects` test: querying `"bob"` against a tier built for `"alice"` returns an empty `Vec` from every resolver.

---

## Relationship to Sibling Modules

```mermaid
graph TB
    subgraph "ainxt-lifecycle crate"
        LIB["lib.rs<br/>(RecordStore, RetentionPolicy,<br/>LegalHold, ErasureAttestation)"]
        DSR["dsar.rs<br/>(DsarRegister, CompleteLineage,<br/>LineageResolver trait, LineageRecord)"]
        DTR["dsar_tiers.rs<br/>(THIS MODULE:<br/>TraceTier, IncidentTier, MemoryTier,<br/>hydrate_default_lineage)"]
        GRD["guarded.rs<br/>(ErasableTier, GuardedErasure,<br/>MemoryFabricTier, SessionReplayTier)"]
        BRK["breakglass.rs<br/>(BreakGlassProgram,<br/>RedactionAttestation)"]
        RTS["routes.rs<br/>(DsarWorkflow, RetentionService)"]
        DUR["durable.rs<br/>(snapshot_store, restore_store)"]
    end

    DSR -->|"defines LineageResolver trait<br/>+ CompleteLineage + REQUIRED_DSAR_TIERS"| DTR
    DTR -->|"implements resolvers for<br/>6 of 8 required tiers"| DSR
    LIB -->|"RecordStore impls LineageResolver<br/>(lifecycle-store tier)"| DSR
    DTR -->|"uses RecordStore clone<br/>for lifecycle-store tier"| LIB
    RTS -->|"DsarWorkflow::handle(Access)<br/>calls hydrate_default_lineage"| DTR
    GRD -.->|"complementary: erasure path<br/>(not access path)"| DTR
    BRK -.->|"complementary: redaction<br/>for held/floored records"| DTR
    DUR -.->|"durable snapshot/restore<br/>for RecordStore"| LIB
```

### Complementary Modules

- **[lifecycle_dsar](lifecycle_dsar.md)**: Defines the `LineageResolver` trait, `CompleteLineage`, `LineageRecord`, `DsarRegister`, and the `REQUIRED_DSAR_TIERS` manifest. This module implements concrete resolvers for 6 of the 8 required tiers (the other 2 — `lifecycle-store` and `dsar-register` — are implemented directly on `RecordStore` and `DsarRegister` in `dsar.rs` and `lib.rs`).
- **[lifecycle_core](lifecycle_core.md)**: Provides `RecordStore`, `RetentionPolicy`, `LegalHold`, and the §6 precedence core. The `RecordStore` itself implements `LineageResolver` for the `lifecycle-store` tier.
- **[lifecycle_guarded_erasure](lifecycle_guarded_erasure.md)**: The **erasure** counterpart to this module's **access** focus. While this module resolves *what data exists* about a subject across tiers (for access/portability exports), `guarded.rs` resolves *what may be erased* through §6 precedence and propagates erasures into the real durable tiers.
- **[lifecycle_breakglass](lifecycle_breakglass.md)**: Handles remediation of PII that slipped into floor-bound or held records — the one place a normal erasure cannot touch. Operates on `Deferral` records produced by the erasure path.
- **[lifecycle_routes](lifecycle_routes.md)**: The route-ready `DsarWorkflow` and `RetentionService` services. `DsarWorkflow::handle`'s `Access` arm and `DsarWorkflow::fulfill_access` are the served entrypoints that call `hydrate_default_lineage` to assemble the cross-tier lineage before calling `fulfill_access_complete`.

---

## Purity and Determinism

All resolvers in this module are **pure functions** of their inputs:

| Property | Guarantee |
|---|---|
| **No clock** | Logical ticks are passed in by the caller; no `SystemTime::now()`. |
| **No RNG** | No random number generation anywhere in `resolve`. |
| **No I/O** | No file reads, no network calls, no database queries in `resolve`. The caller hydrates all data before calling. |
| **Deterministic ordering** | `TraceTier` sorts by `record_id`; `CompleteLineage::resolve_complete` sorts all merged records by `(tier, record_id)`. |
| **Reproducible** | Same inputs → same outputs, every time. |

This is consistent with the entire `ainxt-lifecycle` crate's design philosophy: purge, erasure, deferral, and lineage resolution are all reproducible and provable to a regulator.

---

## Key Invariants

1. **Completeness is enforced, not best-effort**: A DSAR access fulfilment with `require_complete=true` is REFUSED when any mandated tier has no registered resolver — it can never silently under-report. The refusal is `DsarError::IncompleteLineage { missing }`.

2. **No cross-subject leak**: Every resolver checks the subject id before returning records. A mismatched subject contributes nothing.

3. **PII-in-embeddings is captured**: The `embeddings` tier ensures that PII baked into embedding vectors (a regulated data class even as vectors) appears in the access export.

4. **PII-in-KG is captured**: The `kg-memoryfact` tier surfaces `MemoryKind::Semantic` items, which may carry `DataClass::Pii` (e.g., "this user works in payments-core").

5. **DSAR history is self-included**: A subject's own DSAR request history is data held about them and must appear in their access export (the `dsar-register` self-tier).

6. **Snapshot isolation**: The `DsarRegister` tier uses a clone, not a reference, so the tier's view is frozen at hydration time and cannot be mutated by the fulfilment itself.

7. **Incident linkage is honest**: When no real subject→incident case-file index exists, callers pass `&[]` for `incident_links`; the `incident-register` tier is still registered (satisfying completeness) and honestly resolves empty rather than fabricating a linkage that doesn't exist.

---

## Test Coverage

The module includes two comprehensive tests:

### `wire2_fi_09`

Proves FI-09 on the real assembled object: a completeness-required DSAR access export over live tier objects is REFUSED when a mandated tier is absent, and is certified complete — with records merged across every tier — only when all eight are registered. Specifically verifies:

- Seven of eight tiers → `IncompleteLineage { missing: ["incident-register"] }` → fulfilment REFUSED.
- All eight tiers → `is_complete() == true` → records from every tier merged.
- PII semantic fact and its embedding both surfaced.
- Subject's own DSAR request appears in the `dsar-register` tier.
- Hash-chained register still verifies after the fulfilment.

### `tiers_do_not_leak_across_subjects`

Proves each real resolver is subject-scoped: querying a different subject yields nothing from `MemoryTier`, `TraceTier`, and `IncidentTier`.
