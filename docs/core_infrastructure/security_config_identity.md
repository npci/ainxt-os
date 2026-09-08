# security_config_identity

## Brief Introduction

The `security_config_identity` module defines the core identity primitive used across the AiNxt runtime: the `Principal` type. Representing an authenticated caller, `Principal` encapsulates not only authentication attributes (user ID, role) but also authorization context including capability-based permissions, data classification clearance, organizational attributes, and OAuth/connector scopes. It serves as the foundational identity token that downstream security, retrieval, connector, and runtime modules use to make authorization and routing decisions.

This module is a leaf of the [security_config](security_config.md) subsystem under [core_infrastructure](core_infrastructure.md). It intentionally stays small and dependency-light so that almost every other crate can import the identity representation without pulling in heavier security machinery.

---

## Core Components

### `Principal`

Located in `crates/ainxt-types/src/lib.rs`, `Principal` is the canonical representation of an authenticated user or service identity within the system.

#### Fields

| Field | Type | Purpose |
|-------|------|---------|
| `user_id` | `String` | Unique identifier for the caller. |
| `role` | `Role` | `User` or `Admin`; `Admin` implies all capabilities. |
| `caps` | `Vec<String>` | Capability-based permissions granted to the principal. |
| `clearance` | `DataClass` | Maximum data sensitivity class the principal may read. |
| `department` | `Option<String>` | AD department / org unit for organizational scoping. |
| `ad_level` | `Option<u8>` | AD seniority level (0 = most senior exec, 6 = junior). |
| `groups` | `Vec<String>` | AD group / role memberships for group-based RBAC. |
| `connector_scopes` | `Vec<String>` | OAuth/connector scopes the user's own credential covers. |

#### Key Behaviors

- **Capability checking**: `has_cap()` returns true if the principal has the `Admin` role or possesses the named capability.
- **Fail-closed defaults**: Optional fields (`department`, `ad_level`, `groups`, `connector_scopes`) default to empty/None via serde, ensuring older principals or missing claims result in denial rather than accidental access.
- **Builder methods**: `with_clearance`, `with_department`, `with_ad_level`, `with_groups`, and `with_connector_scopes` allow fluent construction.
- **Convenience constructors**: `Principal::user()` and `Principal::admin()` cover the two most common creation paths.

#### Supporting Types

- `DataClass`: Defines sensitivity tiers (`Public`, `Internal`, `Confidential`, `RegulatedPayment`, `Pii`). Regulated and PII data must remain in-house per ADR-012.
- `Role`: `User` or `Admin`.
- `Tier`: Model complexity tier used elsewhere in routing decisions.

---

## Architecture

### Module Hierarchy

```mermaid
graph TD
    A[core_infrastructure] --> B[security_config]
    B --> C[security_config_identity]
    B --> D[security_config_cryptoagility]
    B --> E[security_config_token]
    B --> F[security_config_oauth]
    B --> G[security_config_runtime]
    C --> H[Principal]
    C --> I[DataClass]
    C --> J[Role]
```

### System Position

```mermaid
graph LR
    Auth[Authentication / OAuth] -->|constructs| P[Principal]
    P -->|carries identity| RBAC[RBAC / Authorization]
    P -->|drives routing| RT[Runtime Engine]
    P -->|filters retrieval| RET[Retrieval / Context]
    P -->|scopes connectors| CON[Connectors]
    P -->|governs sessions| SES[Session Manager]
```

---

## Dependencies

### Upstream

- `serde` — serialization and deserialization of identity attributes.

### Downstream Consumers

Modules that consume `Principal` include, but are not limited to:

- [security_config_cryptoagility](security_config_cryptoagility.md) — uses identity context for algorithm governance decisions.
- [security_config_token](security_config_token.md) — token vault operations are scoped to principals.
- [security_config_oauth](security_config_oauth.md) — OAuth flows produce principals enriched with `connector_scopes`.
- [security_config_runtime](security_config_runtime.md) — runtime configuration applies limits based on principal attributes.
- [core_interaction](core_interaction.md) — sessions and turns carry the principal through the interaction lifecycle.
- [governance_compliance_identity](../governance_compliance/identity.md) — advanced identity, attestation, delegation, and workload credentials build upon `Principal`.
- [pipeline_runtime_runtime_engine](../pipeline_runtime/runtime_engine.md) — the engine uses `Principal` for RBAC, outsourcing guard, and admission decisions.
- [ai_engine_knowledge_retrieval](../ai_engine/knowledge_retrieval.md) — retrieval ACLs filter by principal clearance, `ad_level`, and `groups`.

---

## Data Flow

### Principal Construction and Usage

```mermaid
sequenceDiagram
    participant Auth as Authentication Gateway
    participant OAuth as OAuth Provider
    participant P as Principal
    participant RT as Runtime / Engine
    participant Ret as Retrieval
    participant Con as Connector

    Auth->>P: Create Principal from JWT claims
    OAuth->>P: Enrich with connector_scopes
    RT->>P: Check capabilities & clearance
    Ret->>P: Filter by DataClass, ad_level, groups
    Con->>P: Validate connector_scopes
```

---

## Component Interactions

### Authorization Decision Flow

The following diagram illustrates how a single `Principal` is evaluated against multiple independent policy axes. Any axis can deny access; all required axes must allow it.

```mermaid
flowchart TD
    A[Request arrives with Principal] --> B{Role == Admin?}
    B -->|Yes| C[Allow]
    B -->|No| D{Has required capability?}
    D -->|No| E[Deny]
    D -->|Yes| F{DataClass <= clearance?}
    F -->|No| E
    F -->|Yes| G{Connector scope required?}
    G -->|Yes| H{scope in connector_scopes?}
    H -->|No| E
    G -->|No| C
    H -->|Yes| C
```

### Principal Attribute Axes

```mermaid
flowchart LR
    P[Principal]
    P --> Auth[Authentication<br/>user_id, role]
    P --> Cap[Capabilities<br/>caps]
    P --> Data[Data Clearance<br/>clearance]
    P --> Org[Org Scoping<br/>department, ad_level, groups]
    P --> OBO[Connector Scopes<br/>connector_scopes]
```

---

## Process Flows

### Creating a Principal

```mermaid
flowchart LR
    A[Extract JWT claims] --> B[Set user_id & role]
    B --> C[Parse capabilities]
    C --> D[Determine clearance from claims]
    D --> E[Extract department, ad_level, groups]
    E --> F[Fetch OAuth scopes]
    F --> G[Principal ready for runtime]
```

### Runtime Enforcement

```mermaid
flowchart TD
    A[Principal attached to turn/request] --> B[Engine receives request]
    B --> C[Check principal.has_cap for tool/action]
    C -->|Denied| D[Return authorization error]
    C -->|Allowed| E[Route to retrieval or connector]
    E --> F[Retrieval filters chunks by clearance, ad_level, groups]
    E --> G[Connector validates connector_scopes]
    F --> H[Proceed with governed response]
    G --> H
```

---

## Integration Notes

- The `Principal` type is intentionally additive. Fields such as `ad_level`, `groups`, and `connector_scopes` were introduced with serde defaults so that previously serialized principals continue to deserialize safely.
- `clearance` directly maps to `DataClass` and is used by retrieval and context modules to enforce ADR-012: regulated and PII data must stay in-house.
- `connector_scopes` implements OBO layer 2 per ADR-003 §1.6: a harness cannot grant connector capabilities beyond what the user's own credential authorizes.
- For more sophisticated identity concepts such as delegation chains, agent workload credentials, attestation quotes, kill switches, and transparency logs, see [governance_compliance_identity](../governance_compliance/identity.md).
