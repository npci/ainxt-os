// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! The injection layer ships **DEFAULT ON** (`Enforce`).
//!
//! This inverts the original R11 posture (`r11_default_off.rs`), which made the layer inert unless a
//! deployment explicitly enabled it, on the stated grounds of "nothing double-processes during
//! Python-gateway coexistence". That justification did not survive review: the Python
//! `agents/compliance_engine.py` is an EGRESS control (stop sensitive data leaving), and nothing in
//! the Python platform scans INBOUND untrusted content for injected instructions. There was no
//! double-processing to avoid — only an unguarded indirect-injection vector, which is the #1 agentic
//! attack surface.
//!
//! What this file pins:
//!   1. the bare `Default` is `Enforce` with the fail-closed side-effect gate on;
//!   2. `InjectionMode::default()` agrees with `InjectionConfig::default().mode` (no
//!      `mode: Default::default()` footgun that silently disables the layer);
//!   3. an EMPTY config table (`{}` / no `[injection]` section) still deserializes to the ON posture
//!      — the case that actually decides production behaviour, since most deployments never write
//!      the section at all;
//!   4. a deployment can still explicitly opt OUT — this is a default, not a lock (config-first).

use ainxt_injection::{InjectionConfig, InjectionMode};

#[test]
fn default_injection_mode_is_enforce() {
    let cfg = InjectionConfig::default();
    assert_eq!(cfg.mode, InjectionMode::Enforce);
    assert!(!cfg.is_off(), "default injection config must be ON");
    assert_eq!(cfg.mode_label(), "enforce");
    // Fails safe: a tainted turn gates side-effecting tools.
    assert!(cfg.gate_side_effects_on_taint);
}

#[test]
fn bare_enum_default_agrees_with_config_default() {
    // The footgun guard: `InjectionConfig { .., mode: Default::default() }` must not silently
    // disable the layer.
    assert_eq!(InjectionMode::default(), InjectionMode::Enforce);
    assert_eq!(InjectionMode::default(), InjectionConfig::default().mode);
}

#[test]
fn empty_config_deserializes_to_the_on_posture() {
    // The production case: a deployment that never writes an `[injection]` section.
    let cfg: InjectionConfig = serde_json::from_str("{}").unwrap();
    assert!(
        !cfg.is_off(),
        "an absent config section must not mean 'no defense'"
    );
    assert_eq!(cfg.mode, InjectionMode::Enforce);
    assert!(cfg.gate_side_effects_on_taint);
}

#[test]
fn recommended_is_now_the_same_posture_as_default() {
    assert_eq!(InjectionConfig::recommended(), InjectionConfig::default());
}

#[test]
fn a_deployment_can_still_opt_out() {
    // Config-first: the default is a default, not a lock.
    let cfg: InjectionConfig = serde_json::from_str(r#"{"mode":"off"}"#).unwrap();
    assert!(cfg.is_off());
    assert_eq!(cfg.mode_label(), "off");
}

#[test]
fn partial_config_keeps_the_on_default_for_the_unset_mode() {
    // Container-level `#[serde(default)]`: a table that sets only ONE key must inherit `mode` from
    // `InjectionConfig::default()` (Enforce), not from the enum's pre-flip value.
    let cfg: InjectionConfig =
        serde_json::from_str(r#"{"gate_side_effects_on_taint":false}"#).unwrap();
    assert_eq!(cfg.mode, InjectionMode::Enforce);
    assert!(!cfg.gate_side_effects_on_taint);
}
