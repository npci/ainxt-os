// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! IDN-11 wiring test: the Tool Runtime adopts the canonical four-value effect class
//! (`Pure | Idempotent | SideEffecting | PaymentInitiating`, ADR-016 §3.1) from
//! `ainxt_payments::boundary::PaymentEffectClass`, and its `is_dispatchable()` / `requires_ledger()`
//! methods drive the LIVE dispatch path. This test constructs the REAL assembled [`ToolRuntime`]
//! (real ledger, real reconciler) and asserts the wired behavior end-to-end:
//!   * the `Idempotent` variant EXISTS (this file would not COMPILE before the wire) and dispatches
//!     WITHOUT a ledger dedup — it is no longer folded into `SideEffecting`;
//!   * `SideEffecting` still takes the exactly-once ledger path (behavior preserved);
//!   * the payment boundary is UNWEAKENED: neither a `PaymentInitiating` tool nor an `Idempotent`
//!     tool wearing a payment-initiation name can register.

use ainxt_tools::{
    DispatchResult, EffectClass, InMemoryLedger, ManualReconciler, Tool, ToolError, ToolRuntime,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// A tool that counts how many times it actually executed — so we can prove whether the ledger
/// deduped a retry or the tool ran again.
struct CountingTool {
    name: String,
    effect: EffectClass,
    calls: Arc<AtomicUsize>,
}

impl Tool for CountingTool {
    fn name(&self) -> &str {
        &self.name
    }
    fn effect_class(&self) -> EffectClass {
        self.effect
    }
    fn idempotency_key(&self, args: &str) -> Option<String> {
        // Only a SideEffecting tool needs an exactly-once key; Idempotent/Pure return None.
        match self.effect {
            EffectClass::SideEffecting => Some(format!("{}|{}", self.name, args)),
            _ => None,
        }
    }
    fn execute(&self, _args: &str) -> Result<String, ToolError> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        Ok(format!("ran#{n}"))
    }
}

fn rt() -> ToolRuntime {
    ToolRuntime::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler))
}

#[test]
fn wire_idn_11() {
    let mut t = rt();

    // --- Idempotent: dispatchable, NO ledger dedup (re-runs every time) ----------------------
    let idem_calls = Arc::new(AtomicUsize::new(0));
    t.try_register(Box::new(CountingTool {
        name: "refresh_materialized_view".into(),
        effect: EffectClass::Idempotent,
        calls: idem_calls.clone(),
    }))
    .expect("an Idempotent tool must register");

    let r1 = t.dispatch("refresh_materialized_view", "{\"k\":1}");
    let r2 = t.dispatch("refresh_materialized_view", "{\"k\":1}");
    assert!(matches!(r1, DispatchResult::Ok(_)), "got {r1:?}");
    assert!(
        matches!(r2, DispatchResult::Ok(_)),
        "Idempotent must re-run on retry, NOT dedup (it is not folded into SideEffecting): {r2:?}"
    );
    assert_eq!(
        idem_calls.load(Ordering::SeqCst),
        2,
        "an Idempotent tool executes on every dispatch (requires_ledger()==false)"
    );

    // --- SideEffecting: exactly-once ledger dedup preserved -----------------------------------
    let se_calls = Arc::new(AtomicUsize::new(0));
    t.try_register(Box::new(CountingTool {
        name: "send_email".into(),
        effect: EffectClass::SideEffecting,
        calls: se_calls.clone(),
    }))
    .expect("an ordinary SideEffecting tool must register");
    let s1 = t.dispatch("send_email", "{\"to\":\"a@b\"}");
    let s2 = t.dispatch("send_email", "{\"to\":\"a@b\"}");
    assert!(matches!(s1, DispatchResult::Ok(_)), "got {s1:?}");
    assert!(
        matches!(s2, DispatchResult::Deduped(_)),
        "SideEffecting must dedup a retry via the ledger: {s2:?}"
    );
    assert_eq!(
        se_calls.load(Ordering::SeqCst),
        1,
        "exactly-once: the side-effecting tool ran only once"
    );

    // --- Payment boundary UNWEAKENED by the new variant --------------------------------------
    let mut t2 = rt();
    // A relabel-to-Idempotent attempt to skip the Layer-6 tripwire is still refused.
    let idem_payment = t2.try_register(Box::new(CountingTool {
        name: "wire_transfer".into(),
        effect: EffectClass::Idempotent,
        calls: Arc::new(AtomicUsize::new(0)),
    }));
    assert!(
        idem_payment.is_err(),
        "an Idempotent tool with a payment-initiation name must be refused (no bypass)"
    );
    // The apex class is non-dispatchable and refused at registration.
    let pi = t2.try_register(Box::new(CountingTool {
        name: "anything".into(),
        effect: EffectClass::PaymentInitiating,
        calls: Arc::new(AtomicUsize::new(0)),
    }));
    assert!(pi.is_err(), "PaymentInitiating must never register");
    // Even if one somehow slipped in, dispatch has no arm for it — is_dispatchable()==false.
    assert!(!EffectClass::PaymentInitiating.is_dispatchable());
    assert!(EffectClass::Idempotent.is_dispatchable());
    assert!(!EffectClass::Idempotent.requires_ledger());
    assert!(EffectClass::SideEffecting.requires_ledger());
}
