// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-AUDIT tooling-mcp-plugins-routing — "saga compensation". `run_saga`/`run_saga_ledgered` were
//! real, tested primitives, but took raw `Action`/`Compensate` closures the caller had to hand-wire
//! — nothing bridged a NAMED, registered `Tool` into that shape, so a saga could never be driven
//! against the actual capability registry a turn dispatches through. `ToolRuntime::dispatch_saga`
//! closes this: each step is a `(tool, args)` pair dispatched through the SAME `dispatch_inner` path
//! every other call uses.

use ainxt_tools::{
    DispatchResult, EffectClass, InMemoryLedger, ManualReconciler, RiskTier, SagaOutcome,
    SagaStepRequest, Tool, ToolError, ToolRuntime,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// A tool that always succeeds and declares a real compensate closure, tracking how many times it
/// was invoked (for the "compensated" assertion) via a shared counter.
struct CompensableTool {
    name: &'static str,
    undo_calls: Arc<AtomicUsize>,
}
impl Tool for CompensableTool {
    fn name(&self) -> &str {
        self.name
    }
    fn effect_class(&self) -> EffectClass {
        EffectClass::SideEffecting
    }
    fn risk_tier(&self) -> RiskTier {
        RiskTier::Low
    }
    fn idempotency_key(&self, args: &str) -> Option<String> {
        Some(format!("{}:{args}", self.name))
    }
    fn execute(&self, args: &str) -> Result<String, ToolError> {
        Ok(format!("{}-committed:{args}", self.name))
    }
    fn compensate(&self, receipt: &str) -> Option<ainxt_tools::Compensate> {
        let undo_calls = self.undo_calls.clone();
        let receipt = receipt.to_string();
        Some(Box::new(move || {
            assert!(
                receipt.contains("-committed:"),
                "compensate must receive the real receipt"
            );
            undo_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }))
    }
}

/// A tool that always succeeds and declares NO compensate (the honest default) — used to prove a
/// step with no declared compensate is reported `uncompensated`, never a false "rolled back" claim.
struct NonCompensableTool {
    name: &'static str,
}
impl Tool for NonCompensableTool {
    fn name(&self) -> &str {
        self.name
    }
    fn effect_class(&self) -> EffectClass {
        EffectClass::SideEffecting
    }
    fn risk_tier(&self) -> RiskTier {
        RiskTier::Low
    }
    fn idempotency_key(&self, args: &str) -> Option<String> {
        Some(format!("{}:{args}", self.name))
    }
    fn execute(&self, args: &str) -> Result<String, ToolError> {
        Ok(format!("{}-committed:{args}", self.name))
    }
}

/// A tool that always fails, to trigger compensation of prior steps.
struct FailingTool {
    name: &'static str,
}
impl Tool for FailingTool {
    fn name(&self) -> &str {
        self.name
    }
    fn effect_class(&self) -> EffectClass {
        EffectClass::SideEffecting
    }
    fn idempotency_key(&self, args: &str) -> Option<String> {
        Some(format!("{}:{args}", self.name))
    }
    fn execute(&self, _args: &str) -> Result<String, ToolError> {
        Err(ToolError::Execution(
            "downstream rejected the request".into(),
        ))
    }
}

fn runtime() -> ToolRuntime {
    ToolRuntime::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler))
}

#[test]
fn dispatch_saga_completes_and_returns_every_step_receipt_in_order() {
    let mut rt = runtime();
    rt.register(Box::new(CompensableTool {
        name: "jira.update",
        undo_calls: Arc::new(AtomicUsize::new(0)),
    }));
    rt.register(Box::new(CompensableTool {
        name: "gitlab.create_mr",
        undo_calls: Arc::new(AtomicUsize::new(0)),
    }));

    let steps = [
        SagaStepRequest {
            tool: "jira.update",
            args: "TICKET-1",
        },
        SagaStepRequest {
            tool: "gitlab.create_mr",
            args: "branch-x",
        },
    ];
    let outcome = rt.dispatch_saga(Some("alice"), &steps);
    assert_eq!(
        outcome,
        SagaOutcome::Completed(vec![
            "jira.update-committed:TICKET-1".to_string(),
            "gitlab.create_mr-committed:branch-x".to_string(),
        ])
    );

    // The identical dispatch path every other call uses — real ledger claim, not a saga-only shortcut.
    assert!(matches!(
        rt.dispatch_for("alice", "jira.update", "TICKET-1"),
        DispatchResult::Deduped(_)
    ));
}

#[test]
fn dispatch_saga_compensates_completed_steps_in_reverse_on_a_later_failure() {
    let mut rt = runtime();
    let undo_calls_a = Arc::new(AtomicUsize::new(0));
    let undo_calls_b = Arc::new(AtomicUsize::new(0));
    rt.register(Box::new(CompensableTool {
        name: "step.a",
        undo_calls: undo_calls_a.clone(),
    }));
    rt.register(Box::new(CompensableTool {
        name: "step.b",
        undo_calls: undo_calls_b.clone(),
    }));
    rt.register(Box::new(FailingTool { name: "step.c" }));

    let steps = [
        SagaStepRequest {
            tool: "step.a",
            args: "1",
        },
        SagaStepRequest {
            tool: "step.b",
            args: "2",
        },
        SagaStepRequest {
            tool: "step.c",
            args: "3",
        },
    ];
    let outcome = rt.dispatch_saga(Some("alice"), &steps);
    assert_eq!(
        outcome,
        SagaOutcome::Compensated {
            failed_step: "step.c".to_string(),
            reason: "downstream rejected the request".to_string(),
        }
    );
    assert_eq!(
        undo_calls_a.load(Ordering::SeqCst),
        1,
        "step.a must be compensated exactly once"
    );
    assert_eq!(
        undo_calls_b.load(Ordering::SeqCst),
        1,
        "step.b must be compensated exactly once"
    );
}

#[test]
fn dispatch_saga_reports_a_non_compensable_completed_step_as_uncompensated_not_rolled_back() {
    let mut rt = runtime();
    rt.register(Box::new(NonCompensableTool { name: "email.send" }));
    rt.register(Box::new(FailingTool { name: "step.fails" }));

    let steps = [
        SagaStepRequest {
            tool: "email.send",
            args: "hello",
        },
        SagaStepRequest {
            tool: "step.fails",
            args: "x",
        },
    ];
    let outcome = rt.dispatch_saga(Some("alice"), &steps);
    match outcome {
        SagaOutcome::FailedPartial {
            failed_step,
            reason,
            uncompensated,
        } => {
            assert_eq!(failed_step, "step.fails");
            assert_eq!(reason, "downstream rejected the request");
            assert_eq!(uncompensated.len(), 1);
            assert!(
                uncompensated[0].contains("email.send")
                    && uncompensated[0].contains("no compensate"),
                "must name the specific step and say why, not a generic failure: {uncompensated:?}"
            );
        }
        other => panic!("expected FailedPartial (honest, not a false rollback claim): {other:?}"),
    }
}
