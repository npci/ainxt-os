// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! ADR-016 payment boundary: an agent structurally cannot move money through a tool call. A
//! payment-initiating capability has no dispatch arm and is refused at registration; a tool that
//! *lies* about its effect class but carries a payment-initiation name is caught by the tripwire;
//! and — critically — an ordinary side-effecting tool is NOT a false positive.

use ainxt_tools::{
    DispatchResult, EffectClass, InMemoryLedger, ManualReconciler, Tool, ToolError, ToolRuntime,
};

/// A tool whose `execute` would "move money" — it must NEVER run.
struct PayoutTool {
    name: String,
    effect: EffectClass,
}
impl Tool for PayoutTool {
    fn name(&self) -> &str {
        &self.name
    }
    fn effect_class(&self) -> EffectClass {
        self.effect
    }
    fn idempotency_key(&self, args: &str) -> Option<String> {
        Some(args.to_string())
    }
    fn execute(&self, _args: &str) -> Result<String, ToolError> {
        Ok("MONEY MOVED".into()) // a bug if this string is ever observed
    }
}

fn rt() -> ToolRuntime {
    ToolRuntime::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler))
}

#[test]
fn payment_initiating_tool_is_refused_and_never_dispatches() {
    let mut t = rt();
    let err = t
        .try_register(Box::new(PayoutTool {
            name: "anything".into(),
            effect: EffectClass::PaymentInitiating,
        }))
        .unwrap_err();
    match err {
        ToolError::Execution(m) => assert!(
            m.contains("payment-initiating"),
            "wrong refusal reason: {m}"
        ),
    }
    // Refused ⇒ not in the registry ⇒ a dispatch by name is blocked (unknown), so "MONEY MOVED"
    // can never be produced.
    match t.dispatch("anything", "{}") {
        DispatchResult::Blocked(_) => {}
        other => panic!("a payment-initiating tool must never dispatch, got {other:?}"),
    }
}

#[test]
fn payment_signature_name_is_refused_even_when_declared_side_effecting() {
    let mut t = rt();
    // Lies about its class (SideEffecting) but the name screams money movement → Layer-6 tripwire.
    for name in [
        "wire_transfer",
        "disburse_funds",
        "initiate_payment",
        "credit_transfer_v2",
    ] {
        let r = t.try_register(Box::new(PayoutTool {
            name: name.into(),
            effect: EffectClass::SideEffecting,
        }));
        assert!(
            r.is_err(),
            "'{name}' should be refused by the payment-signature tripwire"
        );
    }
}

#[test]
fn ordinary_side_effecting_tools_are_not_false_positives() {
    let mut t = rt();
    // Legitimate side-effecting ledger stand-ins used across the test suite MUST still register.
    for name in ["settle", "pay", "create_ticket", "send_email"] {
        let r = t.try_register(Box::new(PayoutTool {
            name: name.into(),
            effect: EffectClass::SideEffecting,
        }));
        assert!(
            r.is_ok(),
            "ordinary side-effecting tool '{name}' must not be refused: {r:?}"
        );
    }
}
