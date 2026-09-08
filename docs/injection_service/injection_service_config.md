# injection_service_config

The `injection_service_config` module defines how the `ainxt-injection-svc` service is configured at startup. It is responsible for declaring the TOML schema, resolving defaults, and overlaying values from environment variables to produce a single, fully-resolved `ServiceConfig` value that the rest of the service consumes.

This module is intentionally narrow: it does **not** implement scanning, judging, or HTTP handling. Those responsibilities live in sibling modules. Instead, `injection_service_config` provides the central configuration contract that binds the server, the layered defense pipeline, the LLM judge client, and external policy files together.

---

## Core responsibilities

| Responsibility | Description |
| -------------- | ----------- |
| **TOML schema** | Deserialize the `config.toml` file into typed sections (`[server]`, `[judges]`, `[layers]`, `[guardrails]`, `[keyword_scan]`, `[config]`). |
| **Default values** | Provide safe compiled-in defaults so the service can start without any configuration file. |
| **Layered loading** | Apply configuration in priority order: defaults → TOML file → environment variables. |
| **Path resolution** | Search multiple candidate locations for `config.toml` when no explicit path is provided. |
| **Resolved contract** | Expose `ServiceConfig`, a struct with concrete non-optional fields, so downstream code does not need to reason about `Option` values. |

---

## Architecture

The configuration layer sits at the bottom of the injection service stack. It is read once at startup and then immutably shared with the HTTP service, judge pipeline, policy engine, and logging subsystem.

```mermaid
flowchart TB
    subgraph "Configuration sources"
        A[Compiled-in defaults]
        B[config.toml file]
        C[Environment variables]
    end

    D[injection_service_config<br/>ServiceConfig::load]

    A -->|lowest priority| D
    B -->|middle priority| D
    C -->|highest priority| D

    D --> E[injection_service_http_service<br/>AppState]
    D --> F[injection_service_judge_pipeline<br/>JudgePipeline]
    D --> G[injection_service_policy_engine<br/>PolicyEngine]
    D --> H[Logging / tracing setup]

    style D fill:#e1f5e1
```

### Component diagram

```mermaid
classDiagram
    class ConfigFile {
        +config: ConfigFilesSection
        +server: ServerToml
        +layers: LayersToml
        +guardrails: GuardrailsToml
        +keyword_scan: KeywordScanToml
        +judges: JudgesToml
    }

    class ServiceConfig {
        +host: String
        +port: u16
        +mode: String
        +litellm_url: Option~String~
        +litellm_api_key: Option~String~
        +judge1_model: String
        +judge2_model: String
        +confidence_threshold: f32
        +keyword_scan_safe_score: f32
        +keyword_scan_block_score: f32
        +skip_cross_on_consensus: bool
        +tie_behaviour: String
        +timeout_ms: u64
        +llm_unavailable: String
        +fallback_models: Vec~String~
        +max_fallback_attempts: usize
        +circuit_breaker_failures: usize
        +circuit_breaker_timeout_s: u64
        +all_layers_disabled: String
        +guardrails_policy_rules_path: Option~String~
        +llm_judge_rules_path: Option~String~
        +judge_temperature: f32
        +judge_max_tokens: u32
        +judge_accept_invalid_certs: bool
        +max_chunks: usize
        +log_dir: Option~String~
        +log_level: String
        +guardrail_jailbreak_mode: String
        +guardrail_toxicity_mode: String
        +layer_compliance: bool
        +layer_guardrails_policy: bool
        +layer_keyword_scan: bool
        +layer_llm_judges: bool
        +load() ServiceConfig
        -apply_toml(file: ConfigFile)
        -apply_env()
    }

    class ServerToml {
        +host: Option~String~
        +port: Option~u16~
        +mode: Option~String~
        +all_layers_disabled: Option~String~
        +max_chunks: Option~usize~
        +log_dir: Option~String~
        +log_level: Option~String~
    }

    class JudgesToml {
        +litellm_url: Option~String~
        +litellm_api_key: Option~String~
        +judge1_model: Option~String~
        +judge2_model: Option~String~
        +confidence_threshold: Option~f32~
        +skip_cross_on_consensus: Option~bool~
        +tie_behaviour: Option~String~
        +timeout_ms: Option~u64~
        +llm_unavailable: Option~String~
        +fallback_models: Option~Vec~String~~
        +max_fallback_attempts: Option~usize~
        +circuit_breaker_failures: Option~usize~
        +circuit_breaker_timeout_s: Option~u64~
        +policy_path: Option~String~
        +temperature: Option~f32~
        +max_tokens: Option~u32~
        +accept_invalid_certs: Option~bool~
    }

    class LayersToml {
        +compliance_layer: Option~bool~
        +guardrails_policy_layer: Option~bool~
        +keyword_scan_layer: Option~bool~
        +llm_judges_layer: Option~bool~
    }

    class GuardrailsToml {
        +rules_path: Option~String~
        +guardrail_jailbreak_mode: Option~String~
        +guardrail_toxicity_mode: Option~String~
    }

    class KeywordScanToml {
        +safe_score: Option~f32~
        +block_score: Option~f32~
    }

    class ConfigFilesSection {
        +llm_judge_rules_path: Option~String~
        +guardrails_policy_rules_path: Option~String~
    }

    ConfigFile --> ConfigFilesSection
    ConfigFile --> ServerToml
    ConfigFile --> LayersToml
    ConfigFile --> GuardrailsToml
    ConfigFile --> KeywordScanToml
    ConfigFile --> JudgesToml

    ServiceConfig ..> ConfigFile : applies
```

---

## Configuration loading flow

`ServiceConfig::load()` is the single entry point used by the service binary. It performs three steps:

1. **Start with defaults** — `ServiceConfig::default()`.
2. **Overlay TOML** — search candidate paths for `config.toml` and call `apply_toml`.
3. **Overlay environment variables** — call `apply_env`, which has the highest priority.

```mermaid
sequenceDiagram
    participant Main as main.rs / AppState
    participant SC as ServiceConfig
    participant FS as Filesystem
    participant Env as std::env

    Main->>SC: load()
    SC->>SC: default()

    alt AINXT_INJECTION_CONFIG set
        SC->>FS: read explicit path
    else
        SC->>FS: try CWD/config.toml
        SC->>FS: try binary_dir/config.toml
        SC->>FS: try workspace_root/config.toml
        SC->>FS: try crates/ainxt-injection-svc/config.toml
    end

    loop candidate paths
        FS-->>SC: content or missing
        SC->>SC: toml::from_str::<ConfigFile>
        SC->>SC: apply_toml(&file)
    end

    SC->>Env: read env vars
    SC->>SC: apply_env()
    SC-->>Main: ServiceConfig
```

### Path resolution

When `AINXT_INJECTION_CONFIG` is not set, the loader tries these locations in order:

1. `config.toml` in the current working directory.
2. `config.toml` next to the running binary.
3. `config.toml` at the workspace root (three directories above the binary).
4. `crates/ainxt-injection-svc/config.toml` relative to the workspace root.

The first readable and parseable file wins. If none are found, the service starts with compiled-in defaults.

---

## Configuration sections

### `[server]` — HTTP server and global behavior

| Field | Default | Description |
| ----- | ------- | ----------- |
| `host` | `127.0.0.1` | Bind address. |
| `port` | `8007` | Bind port. |
| `mode` | `enforce` | Global injection mode: `enforce`, `audit`, or `off`. |
| `all_layers_disabled` | `allow` | Behavior when every layer is disabled: `allow` or `block`. |
| `max_chunks` | `256` | Maximum chunks accepted per `/scan` request. |
| `log_dir` | `None` | Directory for log files; `None` logs to stderr only. |
| `log_level` | `info` | Log level: `trace`, `debug`, `info`, `warn`, or `error`. |

### `[judges]` — LLM judge pipeline

| Field | Default | Description |
| ----- | ------- | ----------- |
| `litellm_url` | `None` | LiteLLM proxy base URL. If unset, the LLM judge layer is disabled. |
| `litellm_api_key` | `None` | API key for the LiteLLM proxy. |
| `judge1_model` | `judge1` | Primary judge model name. |
| `judge2_model` | `judge2` | Secondary judge model name. |
| `confidence_threshold` | `0.8` | Minimum confidence for a verdict to count in the majority vote. |
| `skip_cross_on_consensus` | `true` | Skip Stage 2 cross-validation when Stage 1 judges agree. |
| `tie_behaviour` | `block` | Tie-breaking behavior: `block` or `allow`. |
| `timeout_ms` | `30000` | Per-judge HTTP timeout. |
| `llm_unavailable` | `block` | Behavior when both judges are unavailable: `block` or `allow`. |
| `fallback_models` | `[]` | Ordered list of fallback model names. |
| `max_fallback_attempts` | `3` | Maximum models to try per judge call. |
| `circuit_breaker_failures` | `5` | Consecutive failures before a model is circuit-broken. |
| `circuit_breaker_timeout_s` | `10` | Seconds to skip a failed model before probing again. |
| `policy_path` | `None` | Legacy path to `llm-judge-rules.toml`. |
| `temperature` | `0.0` | LLM sampling temperature. |
| `max_tokens` | `1024` | Maximum tokens in a judge response. |
| `accept_invalid_certs` | `true` | Accept invalid TLS certificates for the LiteLLM proxy. |

### `[keyword_scan]` — L3 keyword scan thresholds

| Field | Default | Description |
| ----- | ------- | ----------- |
| `safe_score` | `0.1` | Score at or below which L2/L3 judges are skipped. |
| `block_score` | `0.8` | Score at or above which the request is blocked immediately. |

### `[guardrails]` — L2 guardrail behavior

| Field | Default | Description |
| ----- | ------- | ----------- |
| `rules_path` | `None` | Legacy path to `guardrails-policy-rules.toml`. |
| `guardrail_jailbreak_mode` | `audit` | Jailbreak detection mode: `audit` or `enforce`. |
| `guardrail_toxicity_mode` | `enforce` | Toxicity detection mode: `enforce` or `audit`. |

### `[layers]` — per-layer enable/disable toggles

| Field | Default | Description |
| ----- | ------- | ----------- |
| `compliance_layer` | `true` | L1 compliance input scan and output redaction. |
| `guardrails_policy_layer` | `true` | L2 guardrails ML + TOML rules. |
| `keyword_scan_layer` | `true` | L3 keyword scan detector. |
| `llm_judges_layer` | `true` | L4/L5 LLM judge pipeline. |

### `[config]` — external file paths

| Field | Default | Description |
| ----- | ------- | ----------- |
| `llm_judge_rules_path` | `None` | Path to `llm-judge-rules.toml` containing LLM judge system prompts. |
| `guardrails_policy_rules_path` | `None` | Path to `guardrails-policy-rules.toml` containing L2 deny/allow rules. |

---

## Environment variable reference

Environment variables always override TOML values. The table below maps each variable to its TOML key.

| Environment variable | TOML key |
| -------------------- | -------- |
| `AINXT_INJECTION_SVC_HOST` | `server.host` |
| `AINXT_INJECTION_SVC_PORT` | `server.port` |
| `AINXT_INJECTION_MODE` | `server.mode` |
| `ALL_LAYERS_DISABLED` | `server.all_layers_disabled` |
| `SERVER_MAX_CHUNKS` | `server.max_chunks` |
| `LOG_DIR` | `server.log_dir` |
| `LOG_LEVEL` | `server.log_level` |
| `JUDGE_LITELLM_URL` | `judges.litellm_url` |
| `JUDGE_LITELLM_API_KEY` | `judges.litellm_api_key` |
| `JUDGE1_MODEL` | `judges.judge1_model` |
| `JUDGE2_MODEL` | `judges.judge2_model` |
| `JUDGE_CONFIDENCE_THRESHOLD` | `judges.confidence_threshold` |
| `KEYWORD_SCAN_SAFE_SCORE` | `keyword_scan.safe_score` |
| `KEYWORD_SCAN_BLOCK_SCORE` | `keyword_scan.block_score` |
| `JUDGE_SKIP_CROSS_ON_CONSENSUS` | `judges.skip_cross_on_consensus` |
| `JUDGE_TIE_BEHAVIOUR` | `judges.tie_behaviour` |
| `JUDGE_TIMEOUT_MS` | `judges.timeout_ms` |
| `JUDGES_LLM_UNAVAILABLE` | `judges.llm_unavailable` |
| `JUDGE_FALLBACK_MODELS` | `judges.fallback_models` |
| `JUDGE_MAX_FALLBACK_ATTEMPTS` | `judges.max_fallback_attempts` |
| `JUDGE_CB_FAILURES` | `judges.circuit_breaker_failures` |
| `JUDGE_CB_TIMEOUT_S` | `judges.circuit_breaker_timeout_s` |
| `JUDGE_TEMPERATURE` | `judges.temperature` |
| `JUDGE_MAX_TOKENS` | `judges.max_tokens` |
| `JUDGE_ACCEPT_INVALID_CERTS` | `judges.accept_invalid_certs` |
| `GUARDRAILS_POLICY_RULES_PATH` | `config.guardrails_policy_rules_path` |
| `LLM_JUDGE_RULES_PATH` | `config.llm_judge_rules_path` |
| `GUARDRAIL_JAILBREAK_MODE` | `guardrails.guardrail_jailbreak_mode` |
| `GUARDRAIL_TOXICITY_MODE` | `guardrails.guardrail_toxicity_mode` |
| `COMPLIANCE_LAYER` | `layers.compliance_layer` |
| `GUARDRAILS_POLICY_LAYER` | `layers.guardrails_policy_layer` |
| `KEYWORD_SCAN_LAYER` | `layers.keyword_scan_layer` |
| `LLM_JUDGES_LAYER` | `layers.llm_judges_layer` |

---

## Relationship to other modules

`injection_service_config` is one of four submodules under `injection_service`:

```mermaid
flowchart TB
    subgraph injection_service
        A[injection_service_config<br/>config.rs]
        B[injection_service_http_service<br/>main.rs]
        C[injection_service_judge_pipeline<br/>judge.rs]
        D[injection_service_policy_engine<br/>policy.rs]
    end

    A -->|provides ServiceConfig| B
    A -->|provides judge settings| C
    A -->|provides policy file paths| D

    B -->|drives scan requests| C
    B -->|evaluates rules| D
```

- **[injection_service_http_service](injection_service_http_service.md)** receives the resolved `ServiceConfig` in `AppState` and uses it to bind the HTTP server, configure logging, and decide which layers to run for each `/scan` request.
- **[injection_service_judge_pipeline](injection_service_judge_pipeline.md)** consumes the judge-related fields (`litellm_url`, `judge1_model`, `fallback_models`, circuit breaker settings, etc.) to call LiteLLM and produce verdicts.
- **[injection_service_policy_engine](injection_service_policy_engine.md)** reads the `guardrails_policy_rules_path` to load `PolicyRulesFile` and evaluate `PolicyRule` entries.

---

## Data flow during a scan request

The resolved `ServiceConfig` controls how a request flows through the layered pipeline. The diagram below shows the configuration gates that are checked at each layer.

```mermaid
flowchart LR
    A[HTTP /scan request] --> B{layer_compliance?}
    B -->|yes| C[Compliance scan]
    B -->|no| D{layer_guardrails_policy?}
    C --> D
    D -->|yes| E[Guardrails + Policy]
    D -->|no| F{layer_keyword_scan?}
    E --> F
    F -->|yes| G[Keyword scan]
    F -->|no| H{layer_llm_judges?}
    G --> H
    H -->|yes| I[LLM judge pipeline]
    H -->|no| J[Return scan response]
    I --> J
```

If all layers are disabled, the service falls back to `all_layers_disabled` (`allow` or `block`) rather than returning an empty result.

---

## Backward compatibility

The loader supports several legacy TOML locations so older configuration files continue to work:

- `guardrails.rules_path` is mapped to `guardrails_policy_rules_path`.
- `judges.policy_path` is mapped to `llm_judge_rules_path`.
- The modern canonical locations are under `[config]` (`llm_judge_rules_path` and `guardrails_policy_rules_path`).

---

## Testing

The module includes unit tests that verify:

- Default values are sane.
- TOML values overlay correctly onto `ServiceConfig`.
- Environment variables override TOML values.

These tests live in the `tests` submodule of `config.rs` and can be run with `cargo test -p ainxt-injection-svc`.

---

## See also

- [injection_service](injection_service.md) — parent module overview
- [injection_service_http_service](injection_service_http_service.md) — HTTP API and request handling
- [injection_service_judge_pipeline](injection_service_judge_pipeline.md) — LLM judge pipeline
- [injection_service_policy_engine](injection_service_policy_engine.md) — TOML policy rule engine
