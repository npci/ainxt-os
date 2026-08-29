# incident Module

## Introduction

The `ainxt-incident` crate is the statutory AI-incident breach-notification engine for the regulated financial infrastructure stack. It closes the gap between "we have a runbook" and "the system cannot miss a statutory deadline." India's payment switch is subject to hard statutory clocks the moment it processes a query: CERT-In requires a cyber-incident filing within 6 hours of *noticing*, DPDP imposes breach-notice windows, and RBI requires outsourcing/operational-risk reporting.

The design principle is simple: **every statutory deadline is an SLO with a durable countdown, and missing one is structurally impossible to hide.**

The module is a pure, deterministic, durable state machine:

- **`IncidentCandidate`** â€” a typed notice from a detection source (compliance gate, sink-guard, quality circuit-breaker, payment boundary, serving-ops, store-sweep, NTP-skew monitor, residency verifier, operator, or inbound advisory). Its `noticed_tick` is the legally operative **t0**.
- **`ArmingPolicy`** â€” the control-plane table (git-native) that maps *incident class â†’ which statutory clocks fire, with what budget*. The model classifies; the policy arms. Fail-safe: arm early, disarm only on an authenticated, reason-coded downgrade.
- **`StatutoryClock`** â€” a durable countdown from an immutable t0 with a config budget, a 50/75/90% â†’ owner/DPO/CISO + 100% â†’ board-delegate escalation ladder, and a crash-survival property: the clock lives in the serde register, never in a process.
- **`IncidentRegister`** â€” the append-only, SHA-256 hash-chained register that opens incidents, arms clocks, pages the ladder, and auto-raises a P1 compliance meta-incident the instant a clock crosses its budget without a recorded filing.

The module contains no wall clock, no RNG, and no I/O in its core. Logical time is the injected `Tick`; control-plane SHA and NTP particulars are injected strings. The same register advanced to the same `now` always produces the same pages, meta-incidents, and hash chain, so every property is unit-testable offline.

## Module Position

`ainxt-incident` lives under the `governance_compliance` branch of the system. It consumes detection signals from the broader runtime (compliance gates, serving infrastructure, payment boundaries, quality breakers) and produces statutory obligations, escalations, and court-admissible evidence. It depends on `ainxt_types` for `Principal` and `DataClass`, and on `ainxt_cryptoagility` for the governed hash policy that seals the evidentiary chain.

```mermaid
flowchart TB
    subgraph Runtime_Detectors["Runtime Detectors"]
        CG[Compliance Gate Egress]
        WG[Write-Path Sink Guard]
        QB[Quality Circuit Breaker]
        PB[Payment Boundary]
        SO[Serving Ops]
        SS[Store Sweep]
        NTP[NTP Skew Monitor]
        RV[Residency Verifier]
        OD[Operator Declaration]
        IA[Inbound Advisory]
    end

    subgraph Incident_Module["ainxt-incident"]
        direction TB
        REG[IncidentRegister]
        POL[ArmingPolicy]
        CLK[StatutoryClock]
        CAND[IncidentCandidate]
        EV[Hash-Chained Event Log]
        CAD[CadenceScheduler]
        DUR[SnapshotStore]
        AUD[AuditorSession]
        EXP[EvidentiaryExport]
        REP[ReportDraft]
    end

    subgraph Downstream["Downstream / Consumers"]
        PGR[Pager / Dashboard]
        FIL[Filing System]
        CRT[Court / Supervisor]
        LIF[Lifecycle / Erasure]
    end

    Runtime_Detectors -->|candidate| CAND
    CAND -->|open| REG
    POL -->|arms clocks| REG
    REG -->|tick| CLK
    REG -->|append| EV
    REG -->|snapshot| DUR
    CAD -->|due monitors| NTP
    CAD -->|due monitors| RV
    REG -->|export| EXP
    AUD -->|read-only scoped| REG
    REG -->|draft| REP
    REG -->|pages| PGR
    REG -->|meta-incident| LIF
    EXP -->|BSA Â§63 package| CRT
    REP -->|human review| FIL
```

## Architecture Overview

### Core State Machine

The register is the heart of the module. It maintains:

1. **`incidents`** â€” a `BTreeMap<String, Incident>` of all incidents, id-sorted.
2. **`events`** â€” the append-only, hash-chained event log (the evidentiary spine).
3. **`arming`** â€” the `ArmingPolicy` in force.
4. **`hash_policy`** â€” the crypto-agility policy governing the hash primitive used to seal each link.

Opening an incident appends an `Opened` event and one `ClockArmed` event per armed clock. Advancing the register via `tick(now)` evaluates every active clock, pages newly crossed ladder tiers once, and raises a `ComplianceDeadlineMissed` meta-incident if a clock is breached without a filing or downgrade.

```mermaid
stateDiagram-v2
    [*] --> Opened : open(candidate, class, now)
    Opened --> Armed : ClockArmed events
    Armed --> Escalated : tick crosses 50/75/90/100%
    Escalated --> Filed : record_filing(...)
    Escalated --> Downgraded : downgrade(actor, reason, now)
    Escalated --> Breached : tick past deadline
    Breached --> MetaIncidentRaised : auto-raise P1
    Filed --> Closed : all clocks resolved
    Downgraded --> Closed : all clocks resolved
```

### Statutory Clocks

A `StatutoryClock` is a durable countdown from an immutable `t0` with a `budget_ticks`. It supports:

- `CERT-In` (6h default)
- `DPDPDataPrincipal` (without undue delay)
- `DPDPBoard` (72h default)
- `RbiOutsourcing`
- `PaymentBoundaryEscalation`

The escalation ladder is:

| % of budget | Tier |
|-------------|------|
| 50% | IncidentOwner |
| 75% | DPO |
| 90% | CISO |
| 100% | BoardDelegate |

Crossing 100% without a filing or downgrade triggers a meta-incident.

### Determinism & Time Unit

The canonical time unit is **1 tick = 60 wall-clock seconds** (one minute). The `india_default` budgets assume this unit:

- CERT-In 6h = 360 ticks
- DPDP board 72h = 4320 ticks
- DPDP data principal 24h = 1440 ticks
- RBI outsourcing 24h = 1440 ticks
- Payment boundary escalation 1h = 60 ticks

A live driver must project Unix-epoch seconds onto the tick axis with `ticks_from_unix_secs` rather than feeding raw seconds, or clocks will breach 60Ã— early.

### Tamper-Evident Event Log

Every event is a link in a hash chain. Each link includes the previous hash, sequence number, incident id, canonical event tag, and tick. The digest primitive is resolved from the crypto-agility policy at the link's tick and recorded on the event, so an event sealed under a since-deprecated algorithm still verifies with the algorithm of record. `verify()` recomputes the chain end-to-end and reports the first break.

### Crash Survival

The register is pure serde state. The `SnapshotStore` trait provides a codec-free persistence seam; `snapshot_register` and `restore_register` serialize/deserialize through a caller-supplied codec. A `kill -9` mid-clock is survived by restoring the snapshot: `t0` is immutable, elapsed wall-clock continues from real time, and already-fired pages are not re-fired.

## Sub-Modules

The incident module is split into focused sub-modules:

| Sub-module | File(s) | Responsibility |
|------------|---------|----------------|
| [incident_core](incident_core.md) | `src/lib.rs` | Core state machine: `IncidentRegister`, `StatutoryClock`, `ArmingPolicy`, `IncidentCandidate`, `IncidentEvent`, hash chain, escalation, filing, downgrade. |
| [incident_cadence](incident_cadence.md) | `src/cadence.rs` | Deterministic cadence scheduler for supervisory monitors. |
| [incident_durable](incident_durable.md) | `src/durable.rs` | Codec-free snapshot/restore seam for crash survival. |
| [incident_evidence](incident_evidence.md) | `src/evidence.rs` | BSA Â§63 evidentiary export, chain-of-custody, and read-only auditor mode. |
| [incident_ops](incident_ops.md) | `src/ops.rs` | NTP-skew monitor and India-residency verifier. |
| [incident_report](incident_report.md) | `src/report.rs` | Pre-templated statutory report drafting. |

All six sub-module documents above (`incident_core.md`, `incident_cadence.md`, `incident_durable.md`, `incident_evidence.md`, `incident_ops.md`, `incident_report.md`) were generated from the source components and contain the detailed type-level descriptions, responsibilities, and interaction patterns for each area.

## Data Flow: From Detection to Filing

```mermaid
sequenceDiagram
    participant D as Detector
    participant C as IncidentCandidate
    participant R as IncidentRegister
    participant P as Pager
    participant H as Human
    participant F as Filing System

    D->>C: from_compliance_egress(t0, sha, PII, 5)
    C->>R: open_from(candidate, now)
    R->>R: append Opened + ClockArmed
    loop tick(now)
        R->>R: evaluate active clocks
        alt 50% crossed
            R->>P: page IncidentOwner
        else 75% crossed
            R->>P: page DPO
        else 90% crossed
            R->>P: page CISO
        else 100% crossed
            R->>P: page BoardDelegate
            R->>R: raise ComplianceDeadlineMissed
        end
    end
    H->>R: record_filing(clock, filing)
    R->>F: filing recorded
    R->>R: close(incident_id, now)
```

## Evidence Export Flow

```mermaid
sequenceDiagram
    participant A as Auditor
    participant S as AuditorSession
    participant R as IncidentRegister
    participant E as EvidentiaryExport
    participant C as Bsa63Certificate

    A->>S: open_authorized(principal, scope, now)
    S->>S: check AUDITOR_CAP
    S->>R: immutable borrow
    A->>S: export(id, params)
    S->>R: evidentiary_export(id, params, custody)
    R->>R: verify() chain
    R->>E: events + custody + certificate
    E->>C: fill particulars<br/>runtime version, control-plane SHA,<br/>NTP attestation, chain root, record hashes
    C->>A: draft certificate<br/>(human signatures blank)
    A->>A: sign(person_in_charge, expert)
```

## Integration Points

- **Detectors** raise `IncidentCandidate` via typed constructors (`from_compliance_egress`, `from_sink_guard`, `from_quality_breaker`, `from_payment_boundary`, `from_serving_ops`, `from_store_sweep`).
- **Triage Roles** may propose a classification via `open_from_triage`; the policy floors the armed class to the more-protective of proposal and source default.
- **Downgrades** require the `compliance:downgrade-clock` capability on the `Principal`.
- **Filings** stop a clock; the human legal act is recorded but not performed by the engine.
- **Supervisory auditors** open a read-only, scoped, chain-logged `AuditorSession` with the `incident:supervisory-auditor` capability.
- **Report drafting** consumes `Incident` facts and event-log evidence slices to pre-fill statutory templates.

## Security & Compliance Properties

- **Fail-safe arming**: every detector source has a default class; a confused or absent triage model cannot leave a reportable event unclassified.
- **Authenticated downgrade**: disarming a clock requires an explicit capability and is recorded on the chain.
- **Immutable t0**: the legally operative instant is never reset, even across restarts.
- **Tamper evidence**: any edit, reorder, or deletion in the event log breaks `verify()`.
- **Existence-hiding auditor scope**: out-of-scope incidents return `None`, indistinguishable from not-found.
- **Court admissibility**: `EvidentiaryExport` packages the hash-chained slice, chain-of-custody manifest, and a BSA Â§63 certificate draft with machine-filled particulars.
