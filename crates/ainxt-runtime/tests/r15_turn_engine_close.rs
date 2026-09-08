// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! R15 — close three turn-pipeline "medium" design gaps in the crown-jewel turn engine:
//!
//! 1. `r15_parallel_tool_dispatch` — a provider round with multiple tool calls dispatches them
//!    CONCURRENTLY (peak in-flight > 1) while two calls that edit the SAME file SERIALIZE (peak == 1),
//!    with one shared cancel token and a deterministic (call-order) result stream.
//! 2. `r15_hard_tier_route_fail_closed` — a turn that HARD-PINS a tier routes through the router's
//!    hard tier filter and FAILS CLOSED (typed routing error) when no eligible model serves that
//!    tier — it never silently falls through to an off-tier model (the soft path still does).
//! 3. `r15_complexity_derives_tier` — an UNPINNED turn runs the in-engine complexity classifier to
//!    DERIVE the tier before routing (deterministic, model-agnostic; no network model).
//!
//! Fail-before: the live `run_turn` path dispatched tool calls serially (no concurrency, no
//! same-file serialization primitive), routed every tier as a SOFT preference (a pinned tier could
//! fall through to an off-tier model), and never derived the tier from the turn. Pass-after: all
//! three hold, and every pre-existing seam order + safety gate is untouched.

use std::sync::{Arc, Mutex};

use ainxt_protocol::{Event, Request};
use ainxt_runtime::audit::InMemoryAudit;
use ainxt_runtime::authz::RbacAuthorizer;
use ainxt_runtime::complexity::{ComplexityClassifier, HeuristicComplexityClassifier};
use ainxt_runtime::compliance::RedactAndProceed;
use ainxt_runtime::dispatch::DispatchProbe;
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_runtime::{Engine, TurnError};
use ainxt_tools::{
    EffectClass, InMemoryLedger, ManualReconciler, RiskTier, Tool, ToolError, ToolRuntime,
};
use ainxt_types::{DataClass, Principal, Tier};
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------
// Shared test doubles
// ---------------------------------------------------------------------------

/// A provider that declares a tier and echoes its own id as the answer.
struct Tiered {
    id: &'static str,
    tier: Option<Tier>,
}
impl Provider for Tiered {
    fn id(&self) -> &str {
        self.id
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn tier(&self) -> Option<Tier> {
        self.tier
    }
    fn stream(&self, _prompt: &str) -> mpsc::Receiver<Event> {
        let (tx, rx) = mpsc::channel(4);
        let id = self.id.to_string();
        tokio::spawn(async move {
            let _ = tx.send(Event::TextDelta(id)).await;
            let _ = tx.send(Event::Done).await;
        });
        rx
    }
}

/// A side-effecting "edit" tool: records every (path, content) it executes; distinct args never
/// dedup (idempotency key = full args), while `edit_file_target` serializes calls on the same path.
struct EditTool {
    executed: Arc<Mutex<Vec<String>>>,
}
impl Tool for EditTool {
    fn name(&self) -> &str {
        "edit_file"
    }
    fn effect_class(&self) -> EffectClass {
        EffectClass::SideEffecting
    }
    fn risk_tier(&self) -> RiskTier {
        RiskTier::Low
    }
    fn idempotency_key(&self, args: &str) -> Option<String> {
        Some(args.to_string())
    }
    fn resource(&self, _args: &str) -> Option<String> {
        // No resource key: the same-file serialization is driven by the engine's file lock, not by
        // the ToolRuntime resource lock, so the test observes the engine's own concurrency control.
        None
    }
    fn execute(&self, args: &str) -> Result<String, ToolError> {
        self.executed.lock().unwrap().push(args.to_string());
        Ok(format!("edited {args}"))
    }
}

/// Emits a scripted list of (name, args) tool calls in round 1, then answers "done" in round 2.
struct ScriptedProvider {
    calls: Vec<(String, String)>,
}
impl Provider for ScriptedProvider {
    fn id(&self) -> &str {
        "agent"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, prompt: &str) -> mpsc::Receiver<Event> {
        let (tx, rx) = mpsc::channel(16);
        let done = prompt.contains("[tool");
        let calls = self.calls.clone();
        tokio::spawn(async move {
            if done {
                let _ = tx.send(Event::TextDelta("done".into())).await;
            } else {
                for (i, (name, args)) in calls.into_iter().enumerate() {
                    let _ = tx
                        .send(Event::ToolCallStart {
                            id: format!("c{i}"),
                            name,
                            args,
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
    Principal::user("u", &["chat.send", "tool.edit_file"])
}

fn two_tier_engine() -> Engine {
    let mut router = ModelRouter::new();
    // "cheap" (Simple) registered FIRST — absent a tier signal it would win by order.
    router.register(Box::new(Tiered {
        id: "cheap",
        tier: Some(Tier::Simple),
    }));
    router.register(Box::new(Tiered {
        id: "strong",
        tier: Some(Tier::Complex),
    }));
    Engine::new(
        Box::new(RedactAndProceed),
        Box::new(RbacAuthorizer),
        Box::new(InMemoryAudit::default()),
        router,
    )
}

// ---------------------------------------------------------------------------
// Gap 1 — parallel tool dispatch + same-file serialization
// ---------------------------------------------------------------------------

fn edit_engine(
    calls: Vec<(String, String)>,
    probe: Arc<DispatchProbe>,
) -> (Engine, Arc<Mutex<Vec<String>>>) {
    let executed = Arc::new(Mutex::new(Vec::new()));
    let mut router = ModelRouter::new();
    router.register(Box::new(ScriptedProvider { calls }));
    let mut tools = ToolRuntime::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler));
    tools.register(Box::new(EditTool {
        executed: executed.clone(),
    }));
    let engine = Engine::new(
        Box::new(RedactAndProceed),
        Box::new(RbacAuthorizer),
        Box::new(InMemoryAudit::default()),
        router,
    )
    .with_tools(tools)
    .with_dispatch_probe(probe);
    (engine, executed)
}

fn edit(path: &str, content: &str) -> (String, String) {
    (
        "edit_file".to_string(),
        format!("{{\"path\":\"{path}\",\"content\":\"{content}\"}}"),
    )
}

#[tokio::test]
async fn r15_parallel_tool_dispatch() {
    // Two edits to DISJOINT files in ONE round dispatch CONCURRENTLY: peak in-flight == 2.
    let probe = Arc::new(DispatchProbe::new());
    let (engine, executed) = edit_engine(
        vec![edit("a.rs", "aaa"), edit("b.rs", "bbb")],
        probe.clone(),
    );
    let out = engine
        .run_turn_collect(&user(), &Request::chat("s", "t", "go", DataClass::Public))
        .await
        .unwrap();
    assert_eq!(
        probe.peak_concurrency(),
        2,
        "disjoint-file tool calls in one round must dispatch concurrently"
    );
    assert_eq!(probe.total_dispatched(), 2, "both calls dispatched");
    // Both executed; results streamed in CALL order (deterministic audit/result ordering).
    assert_eq!(
        *executed.lock().unwrap(),
        vec![
            "{\"path\":\"a.rs\",\"content\":\"aaa\"}".to_string(),
            "{\"path\":\"b.rs\",\"content\":\"bbb\"}".to_string()
        ],
        "both files edited, in call order"
    );
    let tool_results: Vec<String> = out
        .events
        .iter()
        .filter_map(|e| match e {
            Event::ToolResult { output, .. } => Some(output.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(
        tool_results,
        vec![
            "edited {\"path\":\"a.rs\",\"content\":\"aaa\"}",
            "edited {\"path\":\"b.rs\",\"content\":\"bbb\"}"
        ],
        "tool results stream in stable call order regardless of completion order"
    );

    // Two edits to the SAME file in one round SERIALIZE: peak in-flight == 1.
    let probe2 = Arc::new(DispatchProbe::new());
    let (engine2, executed2) = edit_engine(
        vec![edit("same.rs", "first"), edit("same.rs", "second")],
        probe2.clone(),
    );
    let _ = engine2
        .run_turn_collect(&user(), &Request::chat("s", "t", "go", DataClass::Public))
        .await
        .unwrap();
    assert_eq!(
        probe2.peak_concurrency(),
        1,
        "two edits to the SAME file must serialize — never in flight together"
    );
    assert_eq!(
        probe2.total_dispatched(),
        2,
        "both same-file edits still execute"
    );
    assert_eq!(
        *executed2.lock().unwrap(),
        vec![
            "{\"path\":\"same.rs\",\"content\":\"first\"}".to_string(),
            "{\"path\":\"same.rs\",\"content\":\"second\"}".to_string()
        ],
        "same-file edits execute once each, in order"
    );
}

// ---------------------------------------------------------------------------
// Gap 2 — hard tier filter, fail-closed
// ---------------------------------------------------------------------------

#[tokio::test]
async fn r15_hard_tier_route_fail_closed() {
    // Only a Simple-tier model is registered. A turn that HARD-PINS Complex must FAIL CLOSED — it
    // must NEVER route to the off-tier Simple model.
    let mut router = ModelRouter::new();
    router.register(Box::new(Tiered {
        id: "simple_only",
        tier: Some(Tier::Simple),
    }));
    let engine = Engine::new(
        Box::new(RedactAndProceed),
        Box::new(RbacAuthorizer),
        Box::new(InMemoryAudit::default()),
        router,
    );

    let pinned = Request::chat("s", "t", "hi", DataClass::Public).with_pinned_tier(Tier::Complex);
    let err = engine
        .run_turn_collect(&user(), &pinned)
        .await
        .expect_err("a pinned tier with no eligible model must fail closed, not route off-tier");
    assert!(
        matches!(err, TurnError::Routing(_)),
        "fail-closed must surface a typed routing error, got {err:?}"
    );

    // Contrast: the SOFT path (unpinned) with the identical fleet gracefully falls back to the
    // Simple model — proving the hard filter is a genuinely stronger, opt-in guarantee.
    let mut soft = Request::chat("s", "t", "hi", DataClass::Public);
    soft.tier = Tier::Complex; // soft preference only
    let out = engine
        .run_turn_collect(&user(), &soft)
        .await
        .expect("the soft path falls back to first eligible");
    assert_eq!(
        out.provider, "simple_only",
        "unpinned (soft) routing still gracefully falls back — the hard filter is opt-in"
    );
}

// ---------------------------------------------------------------------------
// Gap 3 — in-engine complexity classifier derives the tier
// ---------------------------------------------------------------------------

#[tokio::test]
async fn r15_complexity_derives_tier() {
    // An unpinned turn whose request carries the DEFAULT (Simple) soft tier, but whose INPUT is a
    // deep-reasoning task. With the default (echo) classifier the soft preference is Simple → cheap.
    // With the heuristic classifier installed, the engine DERIVES Complex from the input → strong.
    let deep_input = "design a distributed reconciliation algorithm and prove its correctness";
    let req = Request::chat("s", "t", deep_input, DataClass::Public); // tier defaults to Simple, unpinned

    // Default engine (TierFromRequest): derives the request's Simple tier → routes to cheap.
    let default_engine = two_tier_engine();
    let out = default_engine
        .run_turn_collect(&user(), &req)
        .await
        .unwrap();
    assert_eq!(
        out.provider, "cheap",
        "without a real classifier the soft tier (Simple) drives routing"
    );

    // Heuristic classifier installed: derives Complex from the deep input → routes to strong.
    let derived_engine = two_tier_engine()
        .with_complexity_classifier(Box::new(HeuristicComplexityClassifier::new()));
    let out = derived_engine
        .run_turn_collect(&user(), &req)
        .await
        .unwrap();
    assert_eq!(
        out.provider, "strong",
        "the in-engine complexity classifier DERIVES Complex from the input and drives routing"
    );
}

#[test]
fn r15_complexity_classifier_is_deterministic_and_tiered() {
    let c = HeuristicComplexityClassifier::new();
    let classify = |input: &str| c.classify(&Request::chat("s", "t", input, DataClass::Public));
    // Trivial one-liner → Simple.
    assert_eq!(classify("hi there"), Tier::Simple);
    // Explicit reasoning-depth marker → Complex, regardless of length.
    assert_eq!(classify("prove this lemma"), Tier::Complex);
    assert_eq!(
        classify("design the settlement architecture"),
        Tier::Complex
    );
    // A longer multi-part ask with no deep markers → Medium.
    assert_eq!(
        classify("please list the seven fields and then format them into a compact table for me"),
        Tier::Medium
    );
    // Deterministic: same input, same tier.
    assert_eq!(classify("prove this lemma"), classify("prove this lemma"));
}
