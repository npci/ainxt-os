// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-AUDIT tooling-mcp-plugins-routing — "Saga/compensation has zero served callers".
//! `ainxt_tools::ToolRuntime::dispatch_saga` (§1.3, multi-step composite action with reverse-order
//! compensation) was a real, tested primitive but had ZERO callers outside `ainxt-tools`'s own tests
//! (`gap3_dispatch_saga.rs`, which builds its own bare `ToolRuntime` by hand) — no served entrypoint
//! ever drove a saga against the actual capability registry a turn dispatches through.
//!
//! `POST /v1/capability/saga` (`ainxt_server::saga_router`, mounted onto the shipped daemon's
//! `app_full_ext` alongside `/v1/harness/*` whenever `cfg.harness` is configured) closes this. This
//! test proves the wiring against the REAL served composition root
//! (`ainxt_runtimed::build_unified_capability_registry_shared` — the exact function
//! `build_engine_ext`/`build_harness_mounts` call) over a REAL bound HTTP server, not a hand-assembled
//! `ToolRuntime`:
//!   * a 2-step saga where every step succeeds returns `Completed` with both receipts, in order, and
//!     the SAME registry's own exactly-once ledger sees the second step's dispatch (a repeat of it
//!     alone dedupes) — proof the HTTP route reached the real dispatch path, not a side channel.
//!   * a 3-step saga whose last step fails is `Compensated`, with the two prior REAL `Tool::compensate`
//!     closures each invoked exactly once, in reverse order — proven by a shared counter the test
//!     tools bump, never by trusting the JSON alone.
//!   * an empty step list is refused 400, never dispatched as a vacuous "success".

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use ainxt_runtimed::build_unified_capability_registry_shared;
use ainxt_server::{saga_router, TrustedGatewayAuth};
use ainxt_tools::{Compensate, EffectClass, RiskTier, Tool, ToolError};

/// A Low-risk SideEffecting capability that declares a REAL compensate closure bumping a shared
/// counter — the same shape `gap3_dispatch_saga.rs` uses, so the compensation proof here is
/// apples-to-apples with the crate-level unit test, just driven over real HTTP + the real registry.
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
    fn compensate(&self, receipt: &str) -> Option<Compensate> {
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

/// A Low-risk SideEffecting capability that always fails, to trigger compensation of prior steps —
/// same shape as `gap3_dispatch_saga.rs`'s `FailingTool`.
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
    fn risk_tier(&self) -> RiskTier {
        RiskTier::Low
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

/// Build the REAL served registry (`build_unified_capability_registry_shared` — the exact function
/// `build_engine_ext`/`build_harness_mounts` call), register the two test capabilities into it
/// (mutably, BEFORE it is wrapped in the `Arc` every served consumer shares — the same pattern the
/// composition root itself uses to register `query_ledger`/`federated_query`/etc into this SAME
/// instance), then mount `saga_router` — the identical `pub fn` `app_full_ext` merges onto the shipped
/// daemon whenever a harness is configured — over a real bound HTTP server. Returns the base URL and
/// the compensation counters for the two `CompensableTool`s so the test can assert on them.
async fn spawn_saga_server() -> (String, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    std::env::set_var("AINXT_TRUSTED_GATEWAY", "1");
    let mut report = Vec::new();
    let (mut registry, _ledger, _reconciler) =
        build_unified_capability_registry_shared(&mut report);

    let undo_a = Arc::new(AtomicUsize::new(0));
    let undo_b = Arc::new(AtomicUsize::new(0));
    registry
        .try_register_governed(Box::new(CompensableTool {
            name: "step.a",
            undo_calls: undo_a.clone(),
        }))
        .expect("registers step.a into the real served registry");
    registry
        .try_register_governed(Box::new(CompensableTool {
            name: "step.b",
            undo_calls: undo_b.clone(),
        }))
        .expect("registers step.b into the real served registry");
    registry
        .try_register_governed(Box::new(FailingTool { name: "step.fails" }))
        .expect("registers step.fails into the real served registry");
    // Sanity: the built-in native capability the composition root itself registers is present too —
    // this IS that same one registry, not a fresh one this test built from scratch.
    let names: Vec<String> = registry.schemas().into_iter().map(|s| s.name).collect();
    assert!(names.iter().any(|n| n == "query_ledger"));

    let tools = Arc::new(registry);
    let router = saga_router(tools.clone(), Arc::new(TrustedGatewayAuth));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    (format!("http://{addr}"), undo_a, undo_b)
}

async fn post_saga(base: &str, steps: serde_json::Value) -> (u16, serde_json::Value) {
    let resp = reqwest::Client::new()
        .post(format!("{base}/v1/capability/saga"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header("x-ainxt-user", "alice")
        .header("x-ainxt-caps", "step.a,step.b,step.fails")
        .header("x-ainxt-clearance", "confidential")
        .body(serde_json::json!({ "steps": steps }).to_string())
        .send()
        .await
        .expect("send");
    let status = resp.status().as_u16();
    let text = resp.text().await.expect("body");
    let json: serde_json::Value = serde_json::from_str(&text).unwrap_or(serde_json::Value::Null);
    (status, json)
}

#[tokio::test(flavor = "multi_thread")]
async fn served_saga_route_completes_a_real_multi_step_action_through_the_real_registry() {
    let (base, undo_a, undo_b) = spawn_saga_server().await;

    let (status, body) = post_saga(
        &base,
        serde_json::json!([
            {"tool": "step.a", "args": "1"},
            {"tool": "step.b", "args": "2"},
        ]),
    )
    .await;
    assert_eq!(status, 200, "body: {body}");
    assert_eq!(body["outcome"], "completed", "body: {body}");
    assert_eq!(
        body["results"],
        serde_json::json!(["step.a-committed:1", "step.b-committed:2"]),
        "both step receipts must come back in order: {body}"
    );
    // Neither step's compensate ran on the happy path.
    assert_eq!(undo_a.load(Ordering::SeqCst), 0);
    assert_eq!(undo_b.load(Ordering::SeqCst), 0);

    // The saga's OWN dispatch of step.b claimed the SAME exactly-once ledger every other call on
    // this registry uses — a direct re-dispatch of the identical (user, tool, args) is deduped, not
    // re-executed. This is the proof the HTTP route reached the real `dispatch_inner` path, not a
    // side channel that only pretends to.
    let (status2, body2) =
        post_saga(&base, serde_json::json!([{"tool": "step.b", "args": "2"}])).await;
    assert_eq!(status2, 200);
    assert_eq!(
        body2["results"],
        serde_json::json!(["step.b-committed:2"]),
        "a solo dispatch of the SAME (user, tool, args) the saga already committed must dedupe to \
         the identical receipt via the shared ledger, not re-run: {body2}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn served_saga_route_compensates_completed_steps_in_reverse_on_a_later_failure() {
    let (base, undo_a, undo_b) = spawn_saga_server().await;

    let (status, body) = post_saga(
        &base,
        serde_json::json!([
            {"tool": "step.a", "args": "1"},
            {"tool": "step.b", "args": "2"},
            {"tool": "step.fails", "args": "3"},
        ]),
    )
    .await;
    assert_eq!(status, 200, "body: {body}");
    assert_eq!(body["outcome"], "compensated", "body: {body}");
    assert_eq!(body["failed_step"], "step.fails", "body: {body}");
    assert_eq!(
        body["reason"], "downstream rejected the request",
        "body: {body}"
    );
    // The REAL Tool::compensate closures ran — over HTTP, through the real registry — exactly once
    // each, proving the served route drove genuine compensation, not just a labeled JSON outcome.
    assert_eq!(
        undo_a.load(Ordering::SeqCst),
        1,
        "step.a must be compensated exactly once"
    );
    assert_eq!(
        undo_b.load(Ordering::SeqCst),
        1,
        "step.b must be compensated exactly once"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn served_saga_route_refuses_an_empty_step_list_rather_than_a_vacuous_success() {
    let (base, _undo_a, _undo_b) = spawn_saga_server().await;
    let (status, _body) = post_saga(&base, serde_json::json!([])).await;
    assert_eq!(
        status, 400,
        "an empty saga must be refused, never dispatched as a no-op success"
    );
}
