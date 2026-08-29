// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R14 (served-composition, HIGH) — the served agent loop routes tool dispatch through the audited
//! THREE-LAYER On-Behalf-Of gate (`dispatch_obo_audited`): declared grant ∧ the caller's own issued
//! scope ∧ resource-ABAC clearance, with the decision (GRANTED **or** DENIED) written to the audit
//! sink BEFORE any effect and the agent's ambient credential NEVER substituted on a denial. Before
//! this round the engine's agent loop dispatched via the bare `dispatch_for` (user-id-scoped
//! exactly-once only — no issued-scope / resource-ABAC layer, no audited decision).
//!
//! FAIL-BEFORE: `Engine::with_obo`/`has_obo` did not exist and the loop called `dispatch_for`.
//! PASS-AFTER: green, offline, deterministic. Two tests: (1) the shipped daemon engine has OBO
//! installed on its loop; (2) a real tool-call turn is GRANTED for a cleared caller and DENIED
//! (audited, tool never executed) for an under-cleared caller — the resource-ABAC layer biting.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use ainxt_protocol::{Event, Request};
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_runtime::{engine_with_defaults, Engine};
use ainxt_runtimed::{build_engine, load_layered};
use ainxt_tools::obo::{MapAbac, OboDecisionSink, OboPolicy, ThreeLayerPolicy, VecOboAudit};
use ainxt_tools::{EffectClass, InMemoryLedger, ManualReconciler, Tool, ToolError, ToolRuntime};
use ainxt_types::{DataClass, Principal};
use tokio::sync::mpsc;

/// A Pure read-only KB tool targeting a fixed regulated resource; `counter` proves execution count.
struct KbSearchTool {
    counter: Arc<AtomicU32>,
}
impl Tool for KbSearchTool {
    fn name(&self) -> &str {
        "kb.search"
    }
    fn effect_class(&self) -> EffectClass {
        EffectClass::Pure
    }
    fn resource(&self, _args: &str) -> Option<String> {
        Some("kb:regulated".to_string())
    }
    fn execute(&self, args: &str) -> Result<String, ToolError> {
        self.counter.fetch_add(1, Ordering::SeqCst);
        Ok(format!("kb-hit:{args}"))
    }
}

/// Round 1: request the tool. Round 2 (once a tool result is in the prompt): answer.
struct ToolThenAnswer;
impl Provider for ToolThenAnswer {
    fn id(&self) -> &str {
        "toolprov"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, prompt: &str) -> mpsc::Receiver<Event> {
        let (tx, rx) = mpsc::channel(8);
        let done = prompt.contains("[tool ");
        tokio::spawn(async move {
            if done {
                let _ = tx.send(Event::TextDelta("done".to_string())).await;
            } else {
                let _ = tx
                    .send(Event::ToolCallStart {
                        id: "t0".to_string(),
                        name: "kb.search".to_string(),
                        args: "settlement".to_string(),
                    })
                    .await;
            }
            let _ = tx.send(Event::Done).await;
        });
        rx
    }
}

/// An engine whose agent loop is OBO-gated by a policy that classes `kb:regulated` at RegulatedPayment.
fn obo_engine(counter: Arc<AtomicU32>) -> (Engine, Arc<VecOboAudit>) {
    let mut router = ModelRouter::new();
    router.register(Box::new(ToolThenAnswer));
    let mut tr = ToolRuntime::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler));
    tr.register(Box::new(KbSearchTool { counter }));
    let sink = Arc::new(VecOboAudit::new());
    let policy: Box<dyn OboPolicy> = Box::new(ThreeLayerPolicy::new(
        MapAbac::new().with("kb:regulated", DataClass::RegulatedPayment),
    ));
    let engine = engine_with_defaults(router)
        .with_tools(tr)
        .with_obo(policy, sink.clone() as Arc<dyn OboDecisionSink>);
    (engine, sink)
}

#[tokio::test]
async fn r14_shipped_engine_has_obo_on_the_agent_loop() {
    let loaded = load_layered(&[("x", "version = 1")]).unwrap();
    let (engine, report) = build_engine(&loaded.runtime).expect("build shipped engine");
    assert!(
        engine.has_obo(),
        "the shipped daemon engine must route the agent loop's tool dispatch through the OBO gate"
    );
    assert!(
        report.iter().any(|r| r.contains("THREE-LAYER OBO")),
        "the assembly report must record the OBO wiring: {report:?}"
    );
}

#[tokio::test]
async fn r14_under_cleared_tool_call_is_denied_and_audited() {
    let counter = Arc::new(AtomicU32::new(0));
    let (engine, sink) = obo_engine(counter.clone());

    // A caller HOLDING the capability (passes the engine authz gate) but under-cleared for the
    // regulated resource: the resource-ABAC layer of OBO DENIES the dispatch.
    // Holds BOTH the OBO capability ("kb.search") and the engine's pre-dispatch tool cap
    // ("tool.kb.search"), so the pre-authz gate ALLOWS and OBO's resource-ABAC layer is the discriminator.
    let under = Principal::user("mallory", &["chat.send", "kb.search", "tool.kb.search"])
        .with_clearance(DataClass::Public);
    let out = engine
        .run_turn_collect(
            &under,
            &Request::chat("s", "t", "search the kb", DataClass::Public),
        )
        .await
        .unwrap();

    assert_eq!(
        counter.load(Ordering::SeqCst),
        0,
        "a denied tool must NEVER execute"
    );
    assert!(
        out.events
            .iter()
            .any(|e| matches!(e, Event::ToolResult { output, .. } if output.contains("blocked"))),
        "the denied dispatch must surface a blocked tool result: {:?}",
        out.events
    );
    // The DENIED decision was audited (the confused-deputy attempt a regulator asks about), on-behalf-of
    // the caller — never the agent's ambient identity.
    let decisions = sink.decisions();
    assert_eq!(decisions.len(), 1, "exactly one OBO decision recorded");
    assert!(!decisions[0].granted(), "the decision is a DENIAL");
    assert_eq!(
        decisions[0].user_id, "mallory",
        "audited on-behalf-of the caller"
    );
    assert_eq!(decisions[0].capability, "kb.search");
}

#[tokio::test]
async fn r14_cleared_tool_call_is_granted_and_audited() {
    let counter = Arc::new(AtomicU32::new(0));
    let (engine, sink) = obo_engine(counter.clone());

    // A caller cleared for the regulated resource: OBO GRANTS and the tool runs.
    let cleared = Principal::user("alice", &["chat.send", "kb.search", "tool.kb.search"])
        .with_clearance(DataClass::RegulatedPayment);
    let out = engine
        .run_turn_collect(
            &cleared,
            &Request::chat("s", "t", "search the kb", DataClass::RegulatedPayment),
        )
        .await
        .unwrap();

    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "the granted tool executes exactly once"
    );
    assert!(
        out.events.iter().any(|e| matches!(e, Event::ToolResult { output, .. } if output.contains("kb-hit:settlement"))),
        "the granted dispatch must surface the real tool result: {:?}", out.events
    );
    let decisions = sink.decisions();
    assert_eq!(decisions.len(), 1, "exactly one OBO decision recorded");
    assert!(decisions[0].granted(), "the decision is a GRANT");
    assert_eq!(decisions[0].user_id, "alice");
}
