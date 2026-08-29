// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Config loader tests: defaults, layered precedence, deep merge, validation, and — the
//! load-bearing one — that the safety invariant (gates cannot be disabled) is unexpressible.

use ainxt_config::{
    AuditSinkKind, AuthzProvider, ComplianceProvider, ConfigError, Loader, PolicyEngineConfig,
    ProviderKind, RuntimeConfig, CONFIG_VERSION,
};
use ainxt_guardrails::RailMode;
use ainxt_types::DataClass;

#[test]
fn empty_loader_resolves_to_safe_defaults() {
    let cfg = Loader::new().resolve_runtime().unwrap();
    assert_eq!(cfg.version, CONFIG_VERSION);
    // Guardrails default OFF; injection default ON (Enforce) — see injection_default_on.rs.
    assert!(cfg.guardrails.is_off());
    assert!(!cfg.injection.is_off());
    // Limits have sane defaults.
    assert_eq!(cfg.limits.max_agent_iters, 4);
    assert_eq!(cfg.limits.stream_channel_bound, 64);
    // Gates default to the OSS providers — but crucially, they are SELECTED, never absent.
    assert_eq!(cfg.gates.compliance, ComplianceProvider::Default);
    assert_eq!(cfg.gates.authz, AuthzProvider::Rbac);
    assert_eq!(cfg.gates.audit, AuditSinkKind::Memory);
    assert_eq!(cfg, RuntimeConfig::default());
}

#[test]
fn later_layers_override_earlier_ones() {
    let cfg = Loader::new()
        .deployment(
            r#"[limits]
max_agent_iters = 6
"#,
        )
        .unwrap()
        .profile(
            r#"[limits]
max_agent_iters = 8
"#,
        )
        .unwrap()
        .request(
            r#"[limits]
max_agent_iters = 3
"#,
        )
        .unwrap()
        .resolve_runtime()
        .unwrap();
    assert_eq!(
        cfg.limits.max_agent_iters, 3,
        "most-specific (request) layer must win"
    );
    // Untouched fields keep their defaults.
    assert_eq!(cfg.limits.stream_channel_bound, 64);
}

#[test]
fn gap_ainxt_config_surf_07_full_canonical_five_layer_precedence() {
    // The documented canonical order is defaults → deployment → tenant → profile → request, most-
    // specific last. This locks the whole chain in one resolve: each layer overrides a DIFFERENT
    // field of the same nested table, EXCEPT `max_agent_iters`, which every layer sets — the request
    // layer (last) must win it. A deep merge means each layer's unique field survives.
    let cfg = Loader::new()
        .defaults(
            r#"[limits]
max_agent_iters = 1
max_input_bytes = 111
"#,
        )
        .unwrap()
        .deployment(
            r#"[limits]
max_agent_iters = 2
provider_max_retries = 5
"#,
        )
        .unwrap()
        .tenant(
            r#"[limits]
max_agent_iters = 3
stream_channel_bound = 128
"#,
        )
        .unwrap()
        .profile(
            r#"[limits]
max_agent_iters = 4
provider_backoff_base_ms = 250
"#,
        )
        .unwrap()
        .request(
            r#"[limits]
max_agent_iters = 6
"#,
        )
        .unwrap()
        .resolve_runtime()
        .unwrap();

    // Most-specific (request) layer wins the contested field.
    assert_eq!(
        cfg.limits.max_agent_iters, 6,
        "request layer (last) must win the contested field across the full 5-layer chain"
    );
    // Each layer's own field survives the deep merge (defaults, deployment, tenant, profile).
    assert_eq!(
        cfg.limits.max_input_bytes, 111,
        "defaults-layer field survives"
    );
    assert_eq!(
        cfg.limits.provider_max_retries, 5,
        "deployment-layer field survives"
    );
    assert_eq!(
        cfg.limits.stream_channel_bound, 128,
        "tenant-layer field survives"
    );
    assert_eq!(
        cfg.limits.provider_backoff_base_ms, 250,
        "profile-layer field survives"
    );
}

#[test]
fn injection_config_parses_and_defaults_off_but_fails_safe() {
    let cfg = Loader::new()
        .deployment(
            r#"[injection]
mode = "enforce"
"#,
        )
        .unwrap()
        .resolve_runtime()
        .unwrap();
    assert!(!cfg.injection.is_off());
    // Omitted gate flag defaults to true (fail-safe once the layer is on).
    assert!(cfg.injection.gate_side_effects_on_taint);
}

#[test]
fn deep_merge_preserves_sibling_keys_across_layers() {
    // deployment turns on jailbreak; tenant turns on groundedness — BOTH must survive (a deep
    // table merge, not a wholesale replace of the [guardrails] table).
    let cfg = Loader::new()
        .deployment(
            r#"[guardrails]
jailbreak = "enforce"
"#,
        )
        .unwrap()
        .tenant(
            r#"[guardrails]
groundedness = "audit"
"#,
        )
        .unwrap()
        .resolve_runtime()
        .unwrap();
    assert_eq!(cfg.guardrails.jailbreak, RailMode::Enforce);
    assert_eq!(cfg.guardrails.groundedness, RailMode::Audit);
    assert_eq!(cfg.guardrails.toxicity, RailMode::Off);
}

#[test]
fn providers_and_data_class_eligibility_parse() {
    let cfg = Loader::new()
        .deployment(
            r#"
[[models.providers]]
id = "local-qwen"
kind = "local"
eligible = ["public", "internal", "confidential", "regulated-payment", "pii"]

[[models.providers]]
id = "cloud-anthropic"
kind = "anthropic"
base_url = "https://api.anthropic.com"
eligible = ["public", "internal"]
"#,
        )
        .unwrap()
        .resolve_runtime()
        .unwrap();
    assert_eq!(cfg.models.providers.len(), 2);
    assert_eq!(cfg.models.providers[0].id, "local-qwen");
    assert_eq!(cfg.models.providers[0].kind, ProviderKind::Local);
    assert!(cfg.models.providers[0]
        .eligible
        .contains(&DataClass::RegulatedPayment));
    assert_eq!(cfg.models.providers[1].kind, ProviderKind::Anthropic);
    // The cloud provider is NOT eligible for regulated data (ADR-012 declared in config).
    assert!(!cfg.models.providers[1]
        .eligible
        .contains(&DataClass::RegulatedPayment));
}

#[test]
fn a_gate_cannot_be_selected_and_can_never_be_disabled() {
    // You CAN select a provider...
    let cfg = Loader::new()
        .deployment(
            r#"[gates]
compliance = "pci-dss"
authz = "ad-rbac"
audit = "event-log"
"#,
        )
        .unwrap()
        .resolve_runtime()
        .unwrap();
    assert_eq!(cfg.gates.compliance, ComplianceProvider::PciDss);
    assert_eq!(cfg.gates.authz, AuthzProvider::AdRbac);
    assert_eq!(cfg.gates.audit, AuditSinkKind::EventLog);

    // ...but you CANNOT turn one off: there is no such variant, so it fails to parse.
    let err = Loader::new()
        .deployment(
            r#"[gates]
compliance = "off"
"#,
        )
        .unwrap()
        .resolve_runtime()
        .unwrap_err();
    assert!(
        matches!(err, ConfigError::Parse(_)),
        "disabling a gate must be unexpressible: {err:?}"
    );

    // Nor via a stray `enabled = false` — deny_unknown_fields rejects it.
    let err = Loader::new()
        .deployment(
            r#"[gates]
enabled = false
"#,
        )
        .unwrap()
        .resolve_runtime()
        .unwrap_err();
    assert!(
        matches!(err, ConfigError::Parse(_)),
        "unknown gate keys must be rejected: {err:?}"
    );
}

#[test]
fn unknown_top_level_key_is_rejected() {
    let err = Loader::new()
        .deployment(
            r#"guardrailz = { jailbreak = "enforce" }
"#,
        )
        .unwrap()
        .resolve_runtime()
        .unwrap_err();
    assert!(
        matches!(err, ConfigError::Parse(_)),
        "typos must be caught, not silently ignored"
    );
}

#[test]
fn malformed_toml_is_a_parse_error_against_its_layer() {
    let err = Loader::new()
        .layer("deployment", "this is = = not toml")
        .unwrap_err();
    assert!(matches!(err, ConfigError::Parse(m) if m.contains("deployment")));
}

#[test]
fn out_of_range_iteration_cap_is_rejected() {
    let err = Loader::new()
        .deployment(
            r#"[limits]
max_agent_iters = 0
"#,
        )
        .unwrap()
        .resolve_runtime()
        .unwrap_err();
    assert!(matches!(err, ConfigError::Invalid(_)));

    let err = Loader::new()
        .deployment(
            r#"[limits]
max_agent_iters = 9999
"#,
        )
        .unwrap()
        .resolve_runtime()
        .unwrap_err();
    assert!(matches!(err, ConfigError::Invalid(_)));
}

#[test]
fn unsupported_version_is_rejected() {
    let err = Loader::new()
        .deployment(
            r#"version = 999
"#,
        )
        .unwrap()
        .resolve_runtime()
        .unwrap_err();
    assert_eq!(err, ConfigError::UnsupportedVersion(999));
}

#[test]
fn r12_canonical_model_registry_blocked_and_user_selectable_are_representable() {
    // The platform's model policy (core/model_registry.py) is now representable in config: a canonical
    // registry with per-model provider/tier, a BLOCKED_MODELS list, and user-selectable-only models
    // that are offered for explicit selection but never auto-routed.
    let cfg = Loader::new()
        .deployment(
            r#"
[[models.providers]]
id = "anthropic"
kind = "anthropic"
eligible = ["public", "internal"]

[[models.providers]]
id = "openai"
kind = "open-ai-schema"
eligible = ["public", "internal"]

# Canonical registry: two auto-routable models + one user-selectable-only model.
[[models.registry]]
name = "claude-sonnet-4-6"
provider = "anthropic"
tier = "complex"

[[models.registry]]
name = "gpt-5.4"
provider = "openai"
tier = "medium"

[[models.registry]]
name = "claude-opus-4-7"
provider = "anthropic"
user_selectable_only = true

# BLOCKED_MODELS: retired / forbidden, never routable nor selectable.
[models]
blocked = ["claude-opus-4-5", "gpt-5.2"]
"#,
        )
        .unwrap()
        .resolve_runtime()
        .unwrap();

    // Blocked models are recognized.
    assert!(cfg.models.is_blocked("claude-opus-4-5"));
    assert!(cfg.models.is_blocked("gpt-5.2"));
    assert!(!cfg.models.is_blocked("claude-sonnet-4-6"));

    // Canonical lookup carries provider + tier.
    let sonnet = cfg.models.canonical("claude-sonnet-4-6").unwrap();
    assert_eq!(sonnet.provider, "anthropic");
    assert_eq!(sonnet.tier.as_deref(), Some("complex"));

    // Auto-routable EXCLUDES the user-selectable-only model (and any blocked one).
    let routable: Vec<&str> = cfg
        .models
        .auto_routable()
        .iter()
        .map(|e| e.name.as_str())
        .collect();
    assert!(routable.contains(&"claude-sonnet-4-6"));
    assert!(routable.contains(&"gpt-5.4"));
    assert!(
        !routable.contains(&"claude-opus-4-7"),
        "a user-selectable-only model is never auto-routed"
    );

    // User-selectable: registered + not blocked. The opus model is selectable (just not auto-routed);
    // a blocked model is NOT selectable; an unknown model is NOT selectable.
    assert!(cfg.models.user_selectable("claude-opus-4-7"));
    assert!(cfg.models.user_selectable("claude-sonnet-4-6"));
    assert!(!cfg.models.user_selectable("claude-opus-4-5"));
    assert!(!cfg.models.user_selectable("nonexistent-model"));
}

#[test]
fn r12_model_registry_rejects_unknown_provider_dupes_and_block_contradiction() {
    // A registry entry must reference a declared provider.
    let err = Loader::new()
        .deployment(
            r#"
[[models.registry]]
name = "m1"
provider = "ghost"
"#,
        )
        .unwrap()
        .resolve_runtime()
        .unwrap_err();
    assert!(
        matches!(&err, ConfigError::Invalid(m) if m.contains("undeclared provider")),
        "a model referencing an undeclared provider must be rejected: {err:?}"
    );

    // Duplicate model names are rejected.
    let err = Loader::new()
        .deployment(
            r#"
[[models.providers]]
id = "p"
kind = "local"

[[models.registry]]
name = "dup"
provider = "p"

[[models.registry]]
name = "dup"
provider = "p"
"#,
        )
        .unwrap()
        .resolve_runtime()
        .unwrap_err();
    assert!(
        matches!(&err, ConfigError::Invalid(m) if m.contains("duplicate model registry entry"))
    );

    // A model may not be both registered and blocked (a contradiction).
    let err = Loader::new()
        .deployment(
            r#"
[[models.providers]]
id = "p"
kind = "local"

[[models.registry]]
name = "conflicted"
provider = "p"

[models]
blocked = ["conflicted"]
"#,
        )
        .unwrap()
        .resolve_runtime()
        .unwrap_err();
    assert!(
        matches!(&err, ConfigError::Invalid(m) if m.contains("both registered and blocked")),
        "a model that is both registered and blocked must be rejected: {err:?}"
    );
}

#[test]
fn duplicate_provider_ids_are_rejected() {
    let err = Loader::new()
        .deployment(
            r#"
[[models.providers]]
id = "dup"
kind = "local"

[[models.providers]]
id = "dup"
kind = "anthropic"
"#,
        )
        .unwrap()
        .resolve_runtime()
        .unwrap_err();
    assert!(matches!(err, ConfigError::Invalid(m) if m.contains("duplicate provider id")));
}

// --- gap closure: L2 policy config-sourcing (`ainxt_prompt::policy::PolicyEngineConfig`) ---------

#[test]
fn gap_ainxt_config_l2_policy_defaults_to_the_shipped_body_when_unconfigured() {
    let cfg = Loader::new().resolve_runtime().unwrap();
    assert_eq!(cfg.policy.l2_body, PolicyEngineConfig::default_l2_body());
}

#[test]
fn gap_ainxt_config_l2_policy_is_deployment_overridable_through_the_real_layered_merge() {
    let cfg = Loader::new()
        .deployment(
            r#"[policy]
l2_body = "DEPLOYMENT-wide: escalate any PAN-adjacent mention to the compliance desk before responding."
"#,
        )
        .unwrap()
        .resolve_runtime()
        .unwrap();
    assert_eq!(
        cfg.policy.l2_body,
        "DEPLOYMENT-wide: escalate any PAN-adjacent mention to the compliance desk before responding."
    );
    // Untouched sibling domains keep their defaults (deep-merge, not a full-document replace).
    assert_eq!(cfg.limits.max_agent_iters, 4);
}

#[test]
fn gap_ainxt_config_l2_policy_tenant_layer_wins_over_deployment_layer() {
    let cfg = Loader::new()
        .deployment(
            r#"[policy]
l2_body = "deployment-wide default policy text""#,
        )
        .unwrap()
        .tenant(
            r#"[policy]
l2_body = "tenant-specific policy text overriding the deployment default""#,
        )
        .unwrap()
        .resolve_runtime()
        .unwrap();
    assert_eq!(
        cfg.policy.l2_body,
        "tenant-specific policy text overriding the deployment default"
    );
}

#[test]
fn gap_ainxt_config_l2_policy_empty_body_is_rejected_fail_closed() {
    let err = Loader::new()
        .deployment(
            r#"[policy]
l2_body = ""
"#,
        )
        .unwrap()
        .resolve_runtime()
        .unwrap_err();
    assert!(matches!(err, ConfigError::Invalid(m) if m.contains("policy.l2_body")));
}
