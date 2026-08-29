// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R15 §1.8 — a mandatory reconcile probe for HighRisk SideEffecting capabilities, enforced at
//! registration via `ToolRuntime::try_register_governed`. Fail-before: nothing in the crate checked,
//! at registration time, whether a HighRisk SideEffecting tool had any way to ever resolve its own
//! lost-ack rows — the reconciler's honest "escalate on no-probe" degrade path (already real per
//! `r3_reconciler_sweep`) could silently become the PERMANENT behavior for a capability that never
//! got a probe wired, and nothing would ever flag that at the point where it's cheapest to catch it.
//! Pass-after: a HighRisk SideEffecting tool that does not override `Tool::has_reconcile_probe` is
//! REFUSED at registration through the governed gate — `try_register`/`register` (used by every
//! pre-existing test) are deliberately untouched, so this is additive, not a breaking change.

use ainxt_tools::{EffectClass, RiskTier, Tool, ToolError, ToolRuntime};

struct NoProbeSettlement;
impl Tool for NoProbeSettlement {
    fn name(&self) -> &str {
        "no_probe_settlement_write"
    }
    fn effect_class(&self) -> EffectClass {
        EffectClass::SideEffecting
    }
    fn risk_tier(&self) -> RiskTier {
        RiskTier::HighRisk
    }
    fn idempotency_key(&self, args: &str) -> Option<String> {
        Some(format!("no_probe_settlement_write:{args}"))
    }
    // Deliberately does NOT override `has_reconcile_probe` — defaults to `false`.
    fn execute(&self, args: &str) -> Result<String, ToolError> {
        Ok(format!("wrote {args}"))
    }
}

struct ProbedSettlement;
impl Tool for ProbedSettlement {
    fn name(&self) -> &str {
        "probed_settlement_write"
    }
    fn effect_class(&self) -> EffectClass {
        EffectClass::SideEffecting
    }
    fn risk_tier(&self) -> RiskTier {
        RiskTier::HighRisk
    }
    fn idempotency_key(&self, args: &str) -> Option<String> {
        Some(format!("probed_settlement_write:{args}"))
    }
    fn has_reconcile_probe(&self) -> bool {
        true
    }
    fn execute(&self, args: &str) -> Result<String, ToolError> {
        Ok(format!("wrote {args}"))
    }
}

struct LowRiskNoProbe;
impl Tool for LowRiskNoProbe {
    fn name(&self) -> &str {
        "low_risk_no_probe"
    }
    fn effect_class(&self) -> EffectClass {
        EffectClass::SideEffecting
    }
    fn risk_tier(&self) -> RiskTier {
        RiskTier::Low // NOT HighRisk — the mandate does not apply
    }
    fn idempotency_key(&self, args: &str) -> Option<String> {
        Some(format!("low_risk_no_probe:{args}"))
    }
    fn execute(&self, args: &str) -> Result<String, ToolError> {
        Ok(format!("wrote {args}"))
    }
}

struct HighRiskPureNoProbe;
impl Tool for HighRiskPureNoProbe {
    fn name(&self) -> &str {
        "high_risk_pure_read"
    }
    fn effect_class(&self) -> EffectClass {
        EffectClass::Pure // not SideEffecting — nothing to reconcile
    }
    fn risk_tier(&self) -> RiskTier {
        RiskTier::HighRisk
    }
    fn execute(&self, args: &str) -> Result<String, ToolError> {
        Ok(format!("read {args}"))
    }
}

#[test]
fn a_highrisk_sideeffecting_tool_with_no_probe_is_refused_by_the_governed_gate() {
    let mut rt = ToolRuntime::new(
        Box::new(ainxt_tools::InMemoryLedger::new()),
        Box::new(ainxt_tools::ManualReconciler),
    );
    let err = rt
        .try_register_governed(Box::new(NoProbeSettlement))
        .unwrap_err();
    assert!(matches!(err, ToolError::Execution(_)));
    // Provably never registered: it does not appear in the schema list / is unknown to the runtime.
    assert!(rt.risk_tier("no_probe_settlement_write").is_none());
}

#[test]
fn a_highrisk_sideeffecting_tool_that_declares_a_probe_registers_cleanly() {
    let mut rt = ToolRuntime::new(
        Box::new(ainxt_tools::InMemoryLedger::new()),
        Box::new(ainxt_tools::ManualReconciler),
    );
    rt.try_register_governed(Box::new(ProbedSettlement))
        .expect("a declared-probe HighRisk tool must register");
    assert_eq!(
        rt.risk_tier("probed_settlement_write"),
        Some(RiskTier::HighRisk)
    );
}

#[test]
fn the_mandate_only_applies_to_highrisk_sideeffecting_not_lower_tiers_or_pure_tools() {
    let mut rt = ToolRuntime::new(
        Box::new(ainxt_tools::InMemoryLedger::new()),
        Box::new(ainxt_tools::ManualReconciler),
    );
    // Low-risk side-effecting: no probe required, registers fine.
    rt.try_register_governed(Box::new(LowRiskNoProbe))
        .expect("Low risk tier is out of scope for the §1.8 mandate");
    // HighRisk but Pure (no ledger row to ever lose an ack for): no probe required.
    rt.try_register_governed(Box::new(HighRiskPureNoProbe))
        .expect("Pure effect class is out of scope for the §1.8 mandate");

    assert_eq!(rt.risk_tier("low_risk_no_probe"), Some(RiskTier::Low));
    assert_eq!(
        rt.risk_tier("high_risk_pure_read"),
        Some(RiskTier::HighRisk)
    );
}

#[test]
fn try_register_and_register_are_unaffected_by_the_mandate_backward_compatibility() {
    // The plain (ungoverned) registration paths — used by every pre-existing test in this crate —
    // must NOT be retrofitted with this check. A HighRisk SideEffecting tool with no probe still
    // registers successfully through `try_register`/`register`.
    let mut rt = ToolRuntime::new(
        Box::new(ainxt_tools::InMemoryLedger::new()),
        Box::new(ainxt_tools::ManualReconciler),
    );
    rt.try_register(Box::new(NoProbeSettlement))
        .expect("plain try_register must remain unaffected by the §1.8 governed gate");
    assert_eq!(
        rt.risk_tier("no_probe_settlement_write"),
        Some(RiskTier::HighRisk)
    );

    let mut rt2 = ToolRuntime::new(
        Box::new(ainxt_tools::InMemoryLedger::new()),
        Box::new(ainxt_tools::ManualReconciler),
    );
    rt2.register(Box::new(NoProbeSettlement));
    assert_eq!(
        rt2.risk_tier("no_probe_settlement_write"),
        Some(RiskTier::HighRisk)
    );
}
