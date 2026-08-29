// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R11 gap closure: the guardrails layer ships DEFAULT OFF. During strangler-fig coexistence the
//! Python gateway owns compliance/guardrails; the runtime rails must be inert unless a deployment
//! explicitly turns a rail on, so nothing double-processes. This pins that invariant.

use ainxt_guardrails::{GuardrailsConfig, RailChain, RailMode};

#[test]
fn r11_default_off_every_rail_mode_defaults_off() {
    let cfg = GuardrailsConfig::default();
    assert_eq!(cfg.jailbreak, RailMode::Off);
    assert_eq!(cfg.groundedness, RailMode::Off);
    assert_eq!(cfg.toxicity, RailMode::Off);
    assert_eq!(cfg.topic, RailMode::Off);
    assert_eq!(cfg.system_prompt_leak, RailMode::Off);
    assert_eq!(cfg.format, RailMode::Off);
    assert!(cfg.is_off(), "default config must be fully off");
    // RailMode's own Default is Off.
    assert_eq!(RailMode::default(), RailMode::Off);
}

#[test]
fn r11_default_off_builds_empty_chains() {
    let cfg = GuardrailsConfig::default();
    assert!(RailChain::from_config(&cfg).is_empty());
    assert!(RailChain::for_input(&cfg).is_empty());
    assert!(RailChain::for_output(&cfg, Some("You are a system prompt.")).is_empty());
}

#[test]
fn r11_default_off_deserializes_from_empty_json() {
    // An absent/empty config document must deserialize to the fully-off layer.
    let cfg: GuardrailsConfig = serde_json::from_str("{}").unwrap();
    assert!(cfg.is_off());
}
