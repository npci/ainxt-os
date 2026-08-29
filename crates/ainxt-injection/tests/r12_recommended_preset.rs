// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R12 gap closure (out-of-the-box enforcement): the injection layer ships a first-class
//! batteries-included preset so a deployment enables real indirect-injection defense with one call.
//! Fail-before: `InjectionConfig::recommended()` did not exist.

use ainxt_injection::{InjectionConfig, InjectionMode};

#[test]
fn r12_recommended_is_enforce_with_fail_closed_gate() {
    let cfg = InjectionConfig::recommended();
    assert!(!cfg.is_off());
    assert_eq!(cfg.mode, InjectionMode::Enforce);
    assert_eq!(cfg.mode_label(), "enforce");
    assert!(
        cfg.gate_side_effects_on_taint,
        "the taint tool-gate must be on by default"
    );
}

#[test]
fn r12_recommended_roundtrips_via_serde() {
    let cfg = InjectionConfig::recommended();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: InjectionConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}
