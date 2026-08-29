// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! r16_hooks_wired_into_dispatch — GAP-FIX tooling-mcp-plugins-routing.
//!
//! `ainxt_tools::hooks` (`HookRegistry`/`PreHook`/`PostHook` — the deterministic pre/post
//! "guardrails" box the crate's own module doc calls "the one box with nothing behind it") existed
//! as a complete, unit-tested file (`src/hooks.rs`) but was never declared as a module ANYWHERE in
//! this crate — no `mod hooks;` / `pub mod hooks;`, and no `#[path]` alternate reference. It was not
//! compiled into `ainxt-tools` at all (its own 11 unit tests never ran in any build), and
//! `ToolRuntime::execute_dispatch` — the origin-agnostic core shared by `dispatch`/`dispatch_for`/
//! `dispatch_obo`/`commit` — invoked a registered tool's `execute` directly with no hook in the
//! path.
//!
//! Fail-before: `use ainxt_tools::hooks::...;` did not compile (E0433: unresolved module `hooks`),
//! so this test could not even be written. Pass-after: `hooks` is a public module, `ToolRuntime`
//! carries a `HookRegistry` (empty/passthrough by default — every pre-existing test above is
//! unaffected), `ToolRuntime::hooks_mut()` lets a composition root install hooks, and
//! `execute_dispatch` runs them: a pre-hook may rewrite the arguments actually executed against (or
//! refuse before any effect), and a post-hook gates the content released to the caller on BOTH a
//! fresh dispatch and a deduped retry — without altering the ledger's own record of what happened.
//! Exercised entirely through the crate's real, served-composition-root-facing dispatch surface
//! (`ToolRuntime::dispatch`/`dispatch_for`), the identical entrypoint `ainxt-runtimed` calls.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use ainxt_tools::hooks::{DenyArgsHook, HashVerifyHook};
use ainxt_tools::{
    DispatchResult, EffectClass, InMemoryLedger, ManualReconciler, ParamSpec, Tool, ToolError,
    ToolRuntime, ToolSchema,
};

/// Echoes its (possibly hook-rewritten) args back, counting real invocations — proves both WHETHER
/// the underlying tool ran and (via the echoed content) exactly WHAT args it ran with.
struct EchoTool {
    name: &'static str,
    effect: EffectClass,
    calls: Arc<AtomicUsize>,
}
impl Tool for EchoTool {
    fn name(&self) -> &str {
        self.name
    }
    fn effect_class(&self) -> EffectClass {
        self.effect
    }
    fn idempotency_key(&self, args: &str) -> Option<String> {
        match self.effect {
            EffectClass::SideEffecting => Some(format!("{}:{args}", self.name)),
            _ => None,
        }
    }
    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: self.name.into(),
            description: String::new(),
            parameters: ParamSpec::Text,
        }
    }
    fn execute(&self, args: &str) -> Result<String, ToolError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(format!("echo:{args}"))
    }
}

fn runtime() -> ToolRuntime {
    ToolRuntime::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler))
}

#[test]
fn a_pre_hook_rewrites_the_args_the_tool_actually_executes_against() {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut rt = runtime();
    rt.register(Box::new(EchoTool {
        name: "echo",
        effect: EffectClass::Pure,
        calls: calls.clone(),
    }));

    struct Shout;
    impl ainxt_tools::hooks::PreHook for Shout {
        fn name(&self) -> &str {
            "shout"
        }
        fn before(
            &self,
            _tool: &str,
            args: &str,
            _actor: Option<&str>,
        ) -> Result<String, ainxt_tools::hooks::HookRefusal> {
            Ok(args.to_uppercase())
        }
    }
    rt.hooks_mut().add_global_pre(Arc::new(Shout));

    match rt.dispatch("echo", "hello") {
        DispatchResult::Ok(r) => assert_eq!(
            r, "echo:HELLO",
            "the tool must have executed against the REWRITTEN args, not the raw caller args"
        ),
        other => panic!("expected Ok, got {other:?}"),
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn a_pre_hook_refusal_blocks_the_call_before_any_effect() {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut rt = runtime();
    rt.register(Box::new(EchoTool {
        name: "run_sql",
        effect: EffectClass::Pure,
        calls: calls.clone(),
    }));
    rt.hooks_mut().add_pre(
        "run_sql",
        Arc::new(DenyArgsHook::new(
            vec!["drop table".into()],
            "destructive SQL",
        )),
    );

    // A benign call passes straight through, unaffected by the hook's presence.
    match rt.dispatch("run_sql", "select 1") {
        DispatchResult::Ok(r) => assert_eq!(r, "echo:select 1"),
        other => panic!("expected Ok for a benign call, got {other:?}"),
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // A forbidden call is BLOCKED before the tool ever runs — no effect, structurally, not a
    // post-hoc cleanup.
    match rt.dispatch("run_sql", "drop table users") {
        DispatchResult::Blocked(msg) => {
            assert!(
                msg.contains("destructive SQL"),
                "refusal reason must surface: {msg}"
            );
            assert!(msg.contains("run_sql"), "refusal must name the tool: {msg}");
        }
        other => panic!("expected Blocked, got {other:?}"),
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the forbidden call must never have reached Tool::execute"
    );
}

#[test]
fn a_post_hook_gates_content_on_both_a_fresh_call_and_a_deduped_retry_without_altering_the_ledger()
{
    // A SideEffecting capability whose real output never matches the expected hash — the worked
    // example from the module doc (a fetch capability whose post-hook verifies content integrity).
    let calls = Arc::new(AtomicUsize::new(0));
    let mut rt = runtime();
    rt.register(Box::new(EchoTool {
        name: "regulator_site_fetch",
        effect: EffectClass::SideEffecting,
        calls: calls.clone(),
    }));
    rt.hooks_mut().add_global_post(Arc::new(HashVerifyHook::new(
        "0000000000000000000000000000000000000000000000000000000000000000",
    )));

    let args = r#"{"doc":"circular-2026-07"}"#;

    // First call: the tool DOES execute (and the ledger DOES commit the raw result — the effect
    // happened and the ledger's job is to record the truth), but the post-hook refuses to release
    // unverified content, so the caller sees `Failed`, never the raw bytes.
    match rt.dispatch("regulator_site_fetch", args) {
        DispatchResult::Failed(msg) => assert!(
            msg.contains("hash mismatch"),
            "post-hook refusal reason must surface: {msg}"
        ),
        other => panic!("expected Failed (post-hook refusal), got {other:?}"),
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1, "the tool ran exactly once");

    // Retry with the SAME args (a lost-ack-style retry): the exactly-once ledger dedups — the
    // underlying tool is NOT re-executed — but the post-hook refusal is NOT bypassed by the dedup
    // path either. This is the point of running hooks on `Deduped` too: a caller cannot launder
    // unverified content through a retry.
    match rt.dispatch("regulator_site_fetch", args) {
        DispatchResult::Failed(msg) => assert!(msg.contains("hash mismatch"), "got: {msg}"),
        other => panic!("expected Failed again on the deduped retry, got {other:?}"),
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "exactly-once still holds — the retry must not re-execute the tool"
    );
}

#[test]
fn a_post_hook_rewrite_reaches_the_caller_on_both_ok_and_deduped() {
    struct Tag;
    impl ainxt_tools::hooks::PostHook for Tag {
        fn name(&self) -> &str {
            "tag"
        }
        fn after(
            &self,
            _tool: &str,
            out: &str,
            _actor: Option<&str>,
        ) -> Result<String, ainxt_tools::hooks::HookRefusal> {
            Ok(format!("{out}|verified"))
        }
    }

    let calls = Arc::new(AtomicUsize::new(0));
    let mut rt = runtime();
    rt.register(Box::new(EchoTool {
        name: "send_note",
        effect: EffectClass::SideEffecting,
        calls: calls.clone(),
    }));
    rt.hooks_mut().add_global_post(Arc::new(Tag));

    let args = r#"{"note":"hi"}"#;
    match rt.dispatch_for("alice", "send_note", args) {
        DispatchResult::Ok(r) => assert_eq!(r, "echo:{\"note\":\"hi\"}|verified"),
        other => panic!("expected Ok, got {other:?}"),
    }
    // A retry from the SAME user dedups via the ledger, and the rewrite is applied again to the
    // (unchanged) stored content — consistent behavior whether the content is fresh or replayed.
    match rt.dispatch_for("alice", "send_note", args) {
        DispatchResult::Deduped(r) => assert_eq!(r, "echo:{\"note\":\"hi\"}|verified"),
        other => panic!("expected Deduped, got {other:?}"),
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "still exactly-once underneath the rewrite"
    );
}

#[test]
fn no_hooks_installed_is_byte_identical_passthrough() {
    // Regression guard for every OTHER test in this crate: a `ToolRuntime` that never touches
    // `hooks_mut()` must behave exactly as it did before this field/wiring existed.
    let calls = Arc::new(AtomicUsize::new(0));
    let mut rt = runtime();
    rt.register(Box::new(EchoTool {
        name: "echo",
        effect: EffectClass::Pure,
        calls: calls.clone(),
    }));
    match rt.dispatch("echo", "unchanged") {
        DispatchResult::Ok(r) => assert_eq!(r, "echo:unchanged"),
        other => panic!("expected Ok, got {other:?}"),
    }
    assert_eq!(rt.hooks().counts(), (0, 0, 0, 0));
}
