# lifecycle_core

## Brief Introduction

`lifecycle_core` is the deterministic data-lifecycle and retention engine inside the `lifecycle` governance module. It resolves the three-way tension between:

- **DPDP right-to-erasure** — a data principal can demand their records be deleted.
- **Statutory retention (TTL)** — records expire and must be purged once past their window.
- **Legal-hold** — a litigation or investigation preservation obligation that overrides both TTL and erasure.

The crate is intentionally **pure**: logical time is passed in as a tick, there is no wall clock, no RNG, and no I/O. This makes every purge, erasure, deferral, and audit entry reproducible and regulator-auditable. The precedence rule is hard-coded and model-free:

1. **Legal-hold** (class-wide or per-matter) preserves matching records.
2. **Statutory retention floor** defers erasure until the floor elapses.
3. **Erase-now** applies when neither hold nor floor blocks the request.

For the higher-level DSAR workflow, break-glass redaction, guarded tiered erasure, and HTTP route wrappers, see the sibling modules linked below.

---

## Core Concepts

### Records and Policies

A [`Record`](lifecycle_core.md#record) is the unit of governed data:

```rust
pub struct Record {
    pub id: String,
    pub subject_id: String,   // data principal
    pub data_class: DataClass,
    pub created_tick: u64,    // logical creation time
}
```

A [`RetentionPolicy`](lifecycle_core.md#retentionpolicy) defines the lifecycle for one [`DataClass`](security_config_identity.md#dataclass):

- `ttl_ticks` — retention **ceiling**. The record becomes eligible for TTL purge at `created_tick + ttl_ticks`.
- `floor_ticks` — statutory retention **floor**. An erasure request is deferred until `created_tick + floor_ticks`.
- `legal_hold` — class-wide preservation switch.

Records whose class has **no policy** are never TTL-purged (fail-safe), but are still erasable on subject request.

### Legal-Hold Matters

[`LegalHold`](lifecycle_core.md#legalhold) represents a per-matter preservation obligation with a [`HoldScope`](lifecycle_core.md#holdscope) predicate. A scope can narrow the hold by subject, data class, and creation-tick range; an empty scope covers every record. A matter is opened at a tick and released later with a reason. Releasing a matter does **not** itself erase anything — deferred erasures must be fired by [`run_deferred`](lifecycle_core.md#recordstore).

### Erasure Precedence

[`erasure_decision`](lifecycle_core.md#recordstore) returns one of:

- `EraseNow` — no active hold and no floor in the way.
- `Defer(LegalHold { matter_id })` — covered by an active matter.
- `Defer(RetentionFloor { floor_expiry })` — still within statutory floor.

This decision is used by [`request_erasure`](lifecycle_core.md#recordstore), which produces an [`ErasureResolution`](lifecycle_core.md#erasureresolution): records erased now plus records deferred with a reason-coded notice.

### Audit and Attestation

Every lifecycle action is appended to an immutable [`AuditEntry`](lifecycle_core.md#auditentry) trail. Actions include `Purged`, `Erased`, `ErasureRefused` (legacy class-wide hold), and `ErasureDeferred` (precedence-aware deferral).

[`ErasureAttestation`](lifecycle_core.md#erasureattestation) wraps an [`ErasureResolution`](lifecycle_core.md#erasureresolution) with a SHA-256 content hash over canonical, length-prefixed fields. This produces a tamper-evident artifact that a regulator or DPO can verify with [`verify`](lifecycle_core.md#erasureattestation).

---

## Architecture

```mermaid
flowchart TB
    subgraph Inputs
        RP[RetentionPolicy]
        REC[Record]
        LH[LegalHold]
        ERASE[ErasureRequest]
        TICK[now_tick]
    end

    subgraph Core["lifecycle_core — pure deterministic engine"]
        RS[RecordStore]
        HS[HoldScope]
        ED[erasure_decision]
        PE[purge_expired]
        RE[request_erasure]
        RD[run_deferred]
        AUDIT[(AuditEntry trail)]
        DEFQ[(DeferredErasure queue)]
    end

    subgraph Outputs
        EO[ErasureOutcome]
        ERES[ErasureResolution]
        EATT[ErasureAttestation]
        PURGED[Purged ids]
    end

    RP -->|registered per DataClass| RS
    REC -->|put| RS
    LH -->|add_hold| RS
    HS -->|covers predicate| LH

    TICK --> PE
    RS --> PE --> PURGED
    RS --> AUDIT

    ERASE --> RE
    TICK --> RE
    RS --> ED
    ED -->|EraseNow / Defer| RE
    RE --> ERES
    RE --> DEFQ
    RE --> EATT

    TICK --> RD
    DEFQ --> RD
    RD -->|fires cleared deferrals| RS
    RD --> PURGED
```

---

## Component Relationships

```mermaid
classDiagram
    class RecordStore {
        +BTreeMap~DataClass, RetentionPolicy~ policies
        +BTreeMap~String, Record~ records
        +Vec~AuditEntry~ audit
        +BTreeMap~String, LegalHold~ holds
        +Vec~DeferredErasure~ deferred
        +set_policy(policy)
        +put(record)
        +get(id)
        +purge_expired(now_tick) Vec~String~
        +erase_subject(subject_id) ErasureOutcome
        +request_erasure(subject_id, now_tick) ErasureResolution
        +request_erasure_attested(subject_id, now_tick) ErasureAttestation
        +run_deferred(now_tick) Vec~String~
        +add_hold(hold)
        +release_hold(id, release_tick) bool
        +erasure_decision(record, now_tick) ErasureDecision
    }

    class RetentionPolicy {
        +DataClass data_class
        +u64 ttl_ticks
        +bool legal_hold
        +u64 floor_ticks
        +new(data_class, ttl_ticks)
        +with_legal_hold(held)
        +with_floor(floor_ticks)
    }

    class Record {
        +String id
        +String subject_id
        +DataClass data_class
        +u64 created_tick
    }

    class LegalHold {
        +String id
        +String custodian
        +HoldScope scope
        +u64 opened_tick
        +Option~u64~ released_tick
        +open(id, custodian, scope, opened_tick)
        +is_active() bool
    }

    class HoldScope {
        +BTreeSet~String~ subjects
        +BTreeSet~DataClass~ data_classes
        +Option~u64~ created_from
        +Option~u64~ created_to
        +covers(record) bool
    }

    class ErasureDecision {
        <<enumeration>>
        EraseNow
        Defer(DeferralCause)
    }

    class DeferredErasure {
        +String record_id
        +String subject_id
        +u64 requested_tick
        +DeferralCause cause
    }

    class ErasureAttestation {
        +String subject_id
        +u64 tick
        +ErasureResolution resolution
        +String content_hash
        +verify() bool
    }

    class AuditEntry {
        +LifecycleAction action
        +String record_id
        +String subject_id
        +DataClass data_class
        +Option~u64~ tick
        +Option~String~ reason
    }

    RecordStore --> RetentionPolicy : configures
    RecordStore --> Record : stores
    RecordStore --> LegalHold : manages
    RecordStore --> DeferredErasure : queues
    RecordStore --> AuditEntry : appends
    RecordStore --> ErasureAttestation : produces
    LegalHold --> HoldScope : owns
    ErasureDecision --> DeferredErasure : drives
```

---

## Data Flow

### TTL Sweep

```mermaid
sequenceDiagram
    participant Caller
    participant RS as RecordStore
    participant Audit as Audit trail

    Caller->>RS: purge_expired(now_tick)
    loop over records in id order
        RS->>RS: is_expired(record, now_tick)
        RS->>RS: is_legal_held(data_class)
        RS->>RS: is_under_active_matter(record)
        RS->>RS: is_within_floor(record, now_tick)
        alt not held and not matter-held and not within floor and expired
            RS->>RS: remove record
            RS->>Audit: append LifecycleAction::Purged
        end
    end
    RS-->>Caller: purged ids (sorted)
```

### Right-to-Erasure with Precedence

```mermaid
sequenceDiagram
    participant Caller
    participant RS as RecordStore
    participant DEF as Deferred queue
    participant Audit as Audit trail

    Caller->>RS: request_erasure(subject_id, now_tick)
    loop over subject's records in id order
        RS->>RS: erasure_decision(record, now_tick)
        alt EraseNow
            RS->>RS: remove record
            RS->>Audit: append LifecycleAction::Erased
        else Defer(LegalHold | RetentionFloor)
            RS->>DEF: enqueue DeferredErasure (idempotent)
            RS->>Audit: append LifecycleAction::ErasureDeferred
        end
    end
    RS-->>Caller: ErasureResolution
```

### Firing Deferred Erasures

```mermaid
sequenceDiagram
    participant Caller
    participant RS as RecordStore
    participant DEF as Deferred queue
    participant Audit as Audit trail

    Caller->>RS: run_deferred(now_tick)
    loop over deferred queue
        alt record still exists and erasure_decision == EraseNow
            RS->>RS: remove record
            RS->>Audit: append LifecycleAction::Erased
        else still blocked
            RS->>DEF: keep with refreshed cause
        else record already gone
            RS->>RS: drop stale queue entry
        end
    end
    RS-->>Caller: fired ids (sorted)
```

---

## How It Fits into the System

`lifecycle_core` sits at the bottom of the `lifecycle` governance stack. It is a pure policy engine that sibling modules build on top of:

- **[lifecycle_dsar](lifecycle_dsar.md)** orchestrates cross-tier subject-rights requests and uses `RecordStore::records_for_subject` and `subject_index` to attribute tier-level deletes to the correct data principal.
- **[lifecycle_dsar_tiers](lifecycle_dsar_tiers.md)** models the different storage tiers (trace, incident, memory) that a DSAR request must traverse.
- **[lifecycle_guarded_erasure](lifecycle_guarded_erasure.md)** wraps sweeps in tier-aware guards and produces `SweepReport`s, delegating the actual keep/erase/defer decision to `lifecycle_core`.
- **[lifecycle_breakglass](lifecycle_breakglass.md)** provides emergency redaction programs that still respect the precedence rules encoded here.
- **[lifecycle_routes](lifecycle_routes.md)** exposes HTTP service endpoints (`RetentionService`, `DsarWorkflow`) that drive the store.

Upstream, the engine is consumed by:

- **[core_interaction](core_interaction.md)** — the event log and session layers produce the `Record`s and `DataClass` classifications that this module governs.
- **[memory_management](memory_management.md)** — durable memory stores use the lifecycle engine for retention, erasure, and promotion decisions.
- **[server_serving_core](server_serving_core.md)** — the main server routes erasure, DSAR, and break-glass requests through the lifecycle stack.

```mermaid
flowchart TB
    subgraph Upstream
        EVENTLOG[core_interaction / eventlog]
        MEMORY[memory_management]
        SERVER[server_serving_core]
    end

    subgraph LifecycleStack["lifecycle module"]
        ROUTES[lifecycle_routes]
        DSAR[lifecycle_dsar]
        TIERS[lifecycle_dsar_tiers]
        GUARD[lifecycle_guarded_erasure]
        BG[lifecycle_breakglass]
        CORE[lifecycle_core]
    end

    EVENTLOG -->|records + DataClass| CORE
    MEMORY -->|retention / erasure| CORE
    SERVER -->|HTTP requests| ROUTES
    ROUTES --> DSAR
    ROUTES --> GUARD
    DSAR --> TIERS
    DSAR --> CORE
    GUARD --> CORE
    BG --> CORE
```

---

## Key Design Properties

- **Determinism.** All collections are `BTreeMap`/`BTreeSet`; outputs are id-sorted. Same state + same `now_tick` always yields the same result and audit trail.
- **Fail-safety.** No policy for a class means the class is never TTL-purged, but erasure still honors the subject's request.
- **Precedence, not judgment.** The keep/erase/defer decision is rule-based; no LLM or probabilistic model is involved.
- **Tamper-evident attestation.** `ErasureAttestation` binds the exact resolution with a SHA-256 hash so regulators can verify the outcome.
- **Idempotent deferral.** A record already queued for deferred erasure is not enqueued twice.

---

## References

- [lifecycle_dsar](lifecycle_dsar.md) — DSAR workflow and cross-tier lineage resolution.
- [lifecycle_dsar_tiers](lifecycle_dsar_tiers.md) — tier models for trace, incident, and memory data.
- [lifecycle_guarded_erasure](lifecycle_guarded_erasure.md) — tier-aware guarded sweeps and `SweepReport`.
- [lifecycle_breakglass](lifecycle_breakglass.md) — emergency break-glass redaction programs.
- [lifecycle_routes](lifecycle_routes.md) — HTTP service routes (`RetentionService`, `DsarWorkflow`).
- [security_config_identity](security_config_identity.md) — `Principal` and `DataClass` definitions.
- [core_interaction](core_interaction.md) — event log, session, and telemetry infrastructure that produces governed records.
- [memory_management](memory_management.md) — durable and session memory stores that consume lifecycle decisions.
- [server_serving_core](server_serving_core.md) — top-level server wiring for erasure and DSAR endpoints.
