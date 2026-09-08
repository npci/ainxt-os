// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! gap6_native_supply_chain_parity_composition_root — GAP-FIX gap6-tools-hooks-obo-supplychain item 2.
//!
//! §3.4 gives a WASM/native PLUGIN a mandatory content-hash pin + publisher allow-list check before
//! its capability is ever registered (`ainxt_plugin::supply_chain`,
//! `register_served_plugin_runtime`). A NATIVE Rust capability — full host privilege, no sandbox —
//! got no equivalent check: `ToolRuntime::try_register_governed_pinned` +
//! `ainxt_tools::native_supply_chain` existed and were unit-tested
//! (`ainxt-tools/tests/gap3_native_supply_chain_parity.rs`), but the served composition root
//! (`ainxt_runtimed::build_unified_capability_registry*`) registered every native capability through
//! the UNGATED `try_register_governed` — `try_register_governed_pinned` had zero callers anywhere in
//! `ainxt-runtimed`.
//!
//! This test goes through the REAL composition root: the REAL `ToolRuntime` +
//! `ainxt_runtimed::served_native_control_lock()` (the exact lock every native registration in
//! `build_unified_capability_registry_shared_over_with_mcp_admin` now checks against). None of
//! today's real default native capabilities declare `RiskTier::HighRisk` (that is asserted here too —
//! the behavior-preserving half of the claim), so a synthetic HighRisk probe tool is registered
//! through the SAME registry + SAME lock + SAME `try_register_governed_pinned` call the real
//! capabilities use, proving the gate is live end-to-end on the composition root's own objects, not
//! just re-proving the crate-level mechanism in isolation.

use ainxt_runtimed::{build_unified_capability_registry, served_native_control_lock};
use ainxt_tools::native_supply_chain::{native_manifest_hash, NativeLockEntry};
use ainxt_tools::{EffectClass, RiskTier, Tool, ToolError, ToolSchema};
use ainxt_types::DataClass;

/// A HighRisk, SideEffecting native probe tool — declares a reconcile probe so it clears the
/// pre-existing, separate §1.8 mandate `try_register_governed` already enforces (this test isolates
/// the supply-chain-parity gate, not §1.8's).
struct HighRiskProbeTool;
impl Tool for HighRiskProbeTool {
    fn name(&self) -> &str {
        "test_highrisk_probe"
    }
    fn effect_class(&self) -> EffectClass {
        EffectClass::SideEffecting
    }
    fn risk_tier(&self) -> RiskTier {
        RiskTier::HighRisk
    }
    fn declared_data_class(&self) -> DataClass {
        DataClass::RegulatedPayment
    }
    fn idempotency_key(&self, args: &str) -> Option<String> {
        Some(args.to_string())
    }
    fn has_reconcile_probe(&self) -> bool {
        true
    }
    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: self.name().into(),
            description: "test-only".into(),
            parameters: ainxt_tools::ParamSpec::Text,
        }
    }
    fn execute(&self, _args: &str) -> Result<String, ToolError> {
        Ok("done".into())
    }
}

#[test]
fn none_of_the_real_default_native_capabilities_are_highrisk_today() {
    // The behavior-preserving half of the claim in `served_native_control_lock`'s doc: switching
    // every real registration from `try_register_governed` to `try_register_governed_pinned` against
    // an EMPTY lock must not refuse anything that registers today.
    let mut report = Vec::new();
    let registry = build_unified_capability_registry(&mut report);
    for name in [
        "query_ledger",
        "federated_query",
        "structured_query",
        "named_fabric_query",
        "capability.search",
    ] {
        let tier = registry.risk_tier(name);
        assert!(
            matches!(tier, Some(RiskTier::Low) | Some(RiskTier::Elevated)),
            "unexpected risk tier for '{name}': {tier:?} (if this is now HighRisk, \
             served_native_control_lock() must gain a reviewed pin or registration will start \
             failing)"
        );
    }
    assert!(
        !report.iter().any(|l| l.contains("refused to register")),
        "no real default native capability should be refused by the empty lock: {report:?}"
    );
}

#[test]
fn a_highrisk_native_tool_with_no_pin_is_refused_through_the_real_composition_root_registry() {
    let mut report = Vec::new();
    let mut registry = build_unified_capability_registry(&mut report);
    // The EXACT lock `ainxt_runtimed`'s own composition root calls — empty today (see its doc).
    let lock = served_native_control_lock();

    let err = registry
        .try_register_governed_pinned(Box::new(HighRiskProbeTool), &lock)
        .unwrap_err();
    assert!(matches!(err, ToolError::Execution(_)));
    assert!(
        !registry
            .tool_names()
            .contains(&"test_highrisk_probe".to_string()),
        "an unpinned HighRisk native capability must never be admitted into the served registry"
    );
}

#[test]
fn a_highrisk_native_tool_matching_a_reviewed_pin_is_admitted_through_the_real_composition_root_registry(
) {
    let mut report = Vec::new();
    let mut registry = build_unified_capability_registry(&mut report);
    let mut lock = served_native_control_lock();
    lock.pin(NativeLockEntry {
        capability_name: "test_highrisk_probe".to_string(),
        manifest_hash: native_manifest_hash(&HighRiskProbeTool),
        reviewer: "security-team".to_string(),
    });

    registry
        .try_register_governed_pinned(Box::new(HighRiskProbeTool), &lock)
        .expect("a HighRisk native tool matching a reviewed pin must be admitted");
    assert!(registry
        .tool_names()
        .contains(&"test_highrisk_probe".to_string()));
}
