// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-AUDIT tooling-mcp-plugins-routing — "Native-tools supply-chain parity".
//!
//! `ainxt_plugin::supply_chain` gates a WASM/native PLUGIN's load with a mandatory content-hash pin
//! + publisher allow-list check, re-verified on EVERY load, before its capability is ever registered
//! (§3.4). `ToolRuntime::register`/`try_register`/`try_register_governed` gave a NATIVE Rust
//! capability — full host privilege, no sandbox, and often `RiskTier::HighRisk`/`SideEffecting`
//! (e.g. a ledger/payment-adjacent tool) — no equivalent integrity check at all: only business-logic
//! gates (the payment boundary, the §1.8 reconcile-probe mandate) ran. A HighRisk native tool's
//! declared admission-governing posture could silently drift with nothing catching it.
//!
//! `ToolRuntime::try_register_governed_pinned` + `native_supply_chain` close this at the SAME scope
//! §1.8 already targets (`RiskTier::HighRisk`): a reviewed `NativeControlLock` entry's manifest hash
//! must match the tool's live declared manifest (name/effect/risk/egress/data-class) before
//! registration succeeds.

use ainxt_tools::native_supply_chain::{native_manifest_hash, NativeControlLock, NativeLockEntry};
use ainxt_tools::{
    EffectClass, InMemoryLedger, ManualReconciler, RiskTier, Tool, ToolError, ToolRuntime,
};
use ainxt_types::DataClass;

/// A HighRisk, SideEffecting, egressing native tool (declares a reconcile probe so it also clears
/// the pre-existing §1.8 mandate `try_register_governed` already enforces — this test isolates the
/// NEW supply-chain-parity gate, not §1.8's separate one).
struct HighRiskLedgerWrite;
impl Tool for HighRiskLedgerWrite {
    fn name(&self) -> &str {
        "ledger_write"
    }
    fn effect_class(&self) -> EffectClass {
        EffectClass::SideEffecting
    }
    fn risk_tier(&self) -> RiskTier {
        RiskTier::HighRisk
    }
    fn egress(&self) -> bool {
        true
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
    fn execute(&self, _args: &str) -> Result<String, ToolError> {
        Ok("written".into())
    }
}

/// Same declared name, but the manifest DRIFTED after review: risk_tier relabeled down to `Elevated`
/// (still constructed as HighRisk in THIS test's control flow — see below — the point is the hash
/// changes when any admission-governing field changes).
struct DriftedLedgerWrite;
impl Tool for DriftedLedgerWrite {
    fn name(&self) -> &str {
        "ledger_write"
    }
    fn effect_class(&self) -> EffectClass {
        EffectClass::SideEffecting
    }
    fn risk_tier(&self) -> RiskTier {
        RiskTier::HighRisk
    }
    fn egress(&self) -> bool {
        false // <-- drifted from the reviewed `true`
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
    fn execute(&self, _args: &str) -> Result<String, ToolError> {
        Ok("written".into())
    }
}

fn runtime() -> ToolRuntime {
    ToolRuntime::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler))
}

#[test]
fn a_highrisk_native_tool_with_no_lock_entry_is_refused() {
    let mut rt = runtime();
    let lock = NativeControlLock::new(); // nothing pinned
    let err = rt
        .try_register_governed_pinned(Box::new(HighRiskLedgerWrite), &lock)
        .unwrap_err();
    assert!(matches!(err, ToolError::Execution(_)));
    assert!(!rt.tool_names().contains(&"ledger_write".to_string()));
}

#[test]
fn a_highrisk_native_tool_matching_its_reviewed_pin_is_admitted() {
    let mut rt = runtime();
    let hash = native_manifest_hash(&HighRiskLedgerWrite);
    let mut lock = NativeControlLock::new();
    lock.pin(NativeLockEntry {
        capability_name: "ledger_write".to_string(),
        manifest_hash: hash,
        reviewer: "security-team".to_string(),
    });

    rt.try_register_governed_pinned(Box::new(HighRiskLedgerWrite), &lock)
        .expect("a manifest matching its reviewed pin must be admitted");
    assert!(rt.tool_names().contains(&"ledger_write".to_string()));
}

#[test]
fn a_drifted_manifest_no_longer_matches_its_reviewed_pin_and_is_refused() {
    // Pin the hash of the ORIGINALLY reviewed tool...
    let hash = native_manifest_hash(&HighRiskLedgerWrite);
    let mut lock = NativeControlLock::new();
    lock.pin(NativeLockEntry {
        capability_name: "ledger_write".to_string(),
        manifest_hash: hash,
        reviewer: "security-team".to_string(),
    });

    // ...but the capability that's ACTUALLY being registered under that name has since drifted
    // (egress flag flipped without a new review) — same name, different governing manifest.
    let mut rt = runtime();
    let err = rt
        .try_register_governed_pinned(Box::new(DriftedLedgerWrite), &lock)
        .unwrap_err();
    assert!(matches!(err, ToolError::Execution(_)));
    assert!(
        !rt.tool_names().contains(&"ledger_write".to_string()),
        "a drifted HighRisk manifest must never be silently admitted under a stale pin"
    );
}

/// A tool BELOW `HighRisk` is unaffected by this gate — parity closes the gap for the highest-risk
/// tier without forcing every native tool (the overwhelming majority) to require a pin.
struct OrdinaryReadTool;
impl Tool for OrdinaryReadTool {
    fn name(&self) -> &str {
        "read_only_lookup"
    }
    fn effect_class(&self) -> EffectClass {
        EffectClass::Pure
    }
    fn risk_tier(&self) -> RiskTier {
        RiskTier::Low
    }
    fn execute(&self, _args: &str) -> Result<String, ToolError> {
        Ok("ok".into())
    }
}

#[test]
fn a_below_highrisk_native_tool_needs_no_pin() {
    let mut rt = runtime();
    let lock = NativeControlLock::new(); // nothing pinned, deliberately
    rt.try_register_governed_pinned(Box::new(OrdinaryReadTool), &lock)
        .expect("a Low-risk tool must register without any lock entry");
    assert!(rt.tool_names().contains(&"read_only_lookup".to_string()));
}
