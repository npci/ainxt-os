// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Approval-gate tests: a HIGH-risk tool is refused with no gate (fail-closed), dispatched on
//! approve, blocked with feedback on reject, and re-prompt-suppressed on approve-for-session.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use ainxt_protocol::{Event, Request};
use ainxt_runtime::approval::{
    ApprovalDecision, ApprovalGate, ApprovalRequest, AutoApprove, AutoReject,
};
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_runtime::{engine_with_defaults, Engine};
use ainxt_tools::{
    EffectClass, InMemoryLedger, ManualReconciler, RiskTier, Tool, ToolError, ToolRuntime,
};
use ainxt_types::{DataClass, Principal};
use tokio::sync::mpsc;

/// A HIGH-risk, side-effecting payment tool.
struct PayTool {
    counter: Arc<AtomicU32>,
}
impl Tool for PayTool {
    fn name(&self) -> &str {
        "pay"
    }
    fn effect_class(&self) -> EffectClass {
        EffectClass::SideEffecting
    }
    fn risk_tier(&self) -> RiskTier {
        RiskTier::High
    }
    fn idempotency_key(&self, args: &str) -> Option<String> {
        Some(args.to_string())
    }
    fn execute(&self, args: &str) -> Result<String, ToolError> {
        self.counter.fetch_add(1, Ordering::SeqCst);
        Ok(format!("paid:{args}"))
    }
}

/// Requests `pay` until it sees a result or a denial in the prompt, then acknowledges.
struct PayProvider {
    calls: usize,
}
impl Provider for PayProvider {
    fn id(&self) -> &str {
        "payprov"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, prompt: &str) -> mpsc::Receiver<Event> {
        let (tx, rx) = mpsc::channel(8);
        let settled =
            prompt.contains("[tool pay result:") || prompt.contains("denied by approval gate");
        let n = self.calls;
        tokio::spawn(async move {
            if settled {
                let _ = tx.send(Event::TextDelta("acknowledged".to_string())).await;
            } else {
                for i in 0..n {
                    let _ = tx
                        .send(Event::ToolCallStart {
                            id: format!("p{i}"),
                            name: "pay".to_string(),
                            args: "acct-1".to_string(),
                        })
                        .await;
                }
            }
            let _ = tx.send(Event::Done).await;
        });
        rx
    }
}

/// A gate that returns a fixed decision and counts how many times it was consulted.
struct CountingGate {
    calls: Arc<AtomicU32>,
    decision: ApprovalDecision,
}
impl ApprovalGate for CountingGate {
    fn decide(&self, _req: &ApprovalRequest) -> ApprovalDecision {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.decision.clone()
    }
}

fn user() -> Principal {
    Principal::user("u", &["chat.send", "tool.pay"])
}

fn build(calls: usize, counter: Arc<AtomicU32>, gate: Option<Box<dyn ApprovalGate>>) -> Engine {
    let mut router = ModelRouter::new();
    router.register(Box::new(PayProvider { calls }));
    let mut tr = ToolRuntime::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler));
    tr.register(Box::new(PayTool { counter }));
    let mut eng = engine_with_defaults(router).with_tools(tr);
    if let Some(g) = gate {
        eng = eng.with_approval(g);
    }
    eng
}

async fn run(eng: &Engine) -> ainxt_runtime::TurnOutcome {
    eng.run_turn_collect(
        &user(),
        &Request::chat("s", "t", "pay acct-1", DataClass::Public),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn high_risk_tool_is_refused_without_a_gate() {
    let counter = Arc::new(AtomicU32::new(0));
    let out = run(&build(1, counter.clone(), None)).await;
    assert_eq!(
        counter.load(Ordering::SeqCst),
        0,
        "fail-closed: no gate ⇒ high-risk tool must NOT run"
    );
    assert!(out
        .events
        .iter()
        .any(|e| matches!(e, Event::ApprovalRequest { .. })));
    assert!(out
        .events
        .iter()
        .any(|e| matches!(e, Event::ToolResult { output, .. } if output.starts_with("denied:"))));
    assert_eq!(out.final_text, "acknowledged");
}

#[tokio::test]
async fn high_risk_tool_runs_when_approved() {
    let counter = Arc::new(AtomicU32::new(0));
    let out = run(&build(1, counter.clone(), Some(Box::new(AutoApprove)))).await;
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "approved ⇒ the tool runs"
    );
    assert!(out
        .events
        .iter()
        .any(|e| matches!(e, Event::ToolResult { output, .. } if output == "paid:acct-1")));
}

#[tokio::test]
async fn high_risk_tool_is_blocked_with_feedback_on_reject() {
    let counter = Arc::new(AtomicU32::new(0));
    let gate = AutoReject("policy: needs a manager".to_string());
    let out = run(&build(1, counter.clone(), Some(Box::new(gate)))).await;
    assert_eq!(
        counter.load(Ordering::SeqCst),
        0,
        "rejected ⇒ the tool must NOT run"
    );
    assert!(out
        .events
        .iter()
        .any(|e| matches!(e, Event::ToolResult { output, .. } if output.contains("policy: needs a manager"))));
    assert_eq!(
        out.final_text, "acknowledged",
        "the model sees the denial and adapts"
    );
}

#[tokio::test]
async fn approve_for_session_suppresses_reprompt() {
    let gate_calls = Arc::new(AtomicU32::new(0));
    let counter = Arc::new(AtomicU32::new(0));
    let gate = CountingGate {
        calls: gate_calls.clone(),
        decision: ApprovalDecision::ApproveForSession,
    };
    // The model asks for the same high-risk tool twice in one round.
    let out = run(&build(2, counter.clone(), Some(Box::new(gate)))).await;
    assert_eq!(
        gate_calls.load(Ordering::SeqCst),
        1,
        "approve-for-session must ask only ONCE"
    );
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "and the ledger still dedups the duplicate call"
    );
    assert_eq!(out.final_text, "acknowledged");
}
