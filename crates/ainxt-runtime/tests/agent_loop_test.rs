// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Agent-loop tests: the engine dispatches provider tool calls through the ToolRuntime
//! (compliance on args/result, exactly-once via the ledger), feeds results back, and
//! completes — with a graceful path when no tool runtime is configured.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use ainxt_protocol::{Event, Request};
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_runtime::{engine_with_defaults, Engine};
use ainxt_tools::{EffectClass, InMemoryLedger, ManualReconciler, Tool, ToolError, ToolRuntime};
use ainxt_types::{DataClass, Principal};
use tokio::sync::mpsc;

/// Settlement tool; `counter` proves how many times it actually executed.
struct SettleTool {
    counter: Arc<AtomicU32>,
}
impl Tool for SettleTool {
    fn name(&self) -> &str {
        "settle"
    }
    fn effect_class(&self) -> EffectClass {
        EffectClass::SideEffecting
    }
    fn idempotency_key(&self, args: &str) -> Option<String> {
        Some(args.to_string())
    }
    fn execute(&self, args: &str) -> Result<String, ToolError> {
        self.counter.fetch_add(1, Ordering::SeqCst);
        Ok(format!("settled:{args}"))
    }
}

/// Round 1: request the tool. Round 2 (once the result is in the prompt): answer.
struct ToolThenAnswer {
    calls_per_round: usize,
}
impl Provider for ToolThenAnswer {
    fn id(&self) -> &str {
        "toolprov"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, prompt: &str) -> mpsc::Receiver<Event> {
        let (tx, rx) = mpsc::channel(8);
        let done = prompt.contains("[tool settle result:");
        let n = self.calls_per_round;
        tokio::spawn(async move {
            if done {
                let _ = tx
                    .send(Event::TextDelta("settlement complete".to_string()))
                    .await;
            } else {
                for i in 0..n {
                    let _ = tx
                        .send(Event::ToolCallStart {
                            id: format!("t{i}"),
                            name: "settle".to_string(),
                            args: "NEFT-1".to_string(),
                        })
                        .await;
                }
            }
            let _ = tx.send(Event::Done).await;
        });
        rx
    }
}

fn user() -> Principal {
    Principal::user("u", &["chat.send", "tool.settle"])
}

fn engine_with(provider: ToolThenAnswer, counter: Arc<AtomicU32>) -> Engine {
    let mut router = ModelRouter::new();
    router.register(Box::new(provider));
    let mut tr = ToolRuntime::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler));
    tr.register(Box::new(SettleTool { counter }));
    engine_with_defaults(router).with_tools(tr)
}

#[tokio::test]
async fn agent_loop_dispatches_tool_then_completes() {
    let counter = Arc::new(AtomicU32::new(0));
    let eng = engine_with(ToolThenAnswer { calls_per_round: 1 }, counter.clone());

    let out = eng
        .run_turn_collect(
            &user(),
            &Request::chat("s", "t", "please settle NEFT-1", DataClass::Public),
        )
        .await
        .unwrap();

    assert_eq!(out.final_text, "settlement complete");
    assert!(
        out.events
            .iter()
            .any(|e| matches!(e, Event::ToolCallStart { name, .. } if name == "settle")),
        "tool call must be surfaced"
    );
    assert!(
        out.events
            .iter()
            .any(|e| matches!(e, Event::ToolResult { output, .. } if output == "settled:NEFT-1")),
        "tool result must be surfaced"
    );
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "the tool must run exactly once"
    );
}

#[tokio::test]
async fn duplicate_tool_calls_in_one_round_execute_once() {
    let counter = Arc::new(AtomicU32::new(0));
    // The model (wrongly) asks for the same side-effecting tool twice in one round.
    let eng = engine_with(ToolThenAnswer { calls_per_round: 2 }, counter.clone());

    let out = eng
        .run_turn_collect(
            &user(),
            &Request::chat("s", "t", "settle it", DataClass::Public),
        )
        .await
        .unwrap();

    assert_eq!(out.final_text, "settlement complete");
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "the ledger must dedup the duplicate call"
    );
}

#[tokio::test]
async fn tool_call_without_a_runtime_errors_gracefully() {
    // Engine with a tool-requesting provider but NO tool runtime.
    let mut router = ModelRouter::new();
    router.register(Box::new(ToolThenAnswer { calls_per_round: 1 }));
    let eng = engine_with_defaults(router); // no .with_tools

    let out = eng
        .run_turn_collect(
            &user(),
            &Request::chat("s", "t", "settle it", DataClass::Public),
        )
        .await
        .unwrap();

    assert!(
        out.events.iter().any(|e| matches!(e, Event::Error(_))),
        "a tool call with no runtime must surface an error, not panic"
    );
    assert!(out.final_text.is_empty());
}
