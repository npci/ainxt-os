// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! gap6_hooks_wired_into_composition_root — GAP-FIX gap6-tools-hooks-obo-supplychain item 1.
//!
//! `ainxt_tools::hooks` (`HookRegistry`/`DenyArgsHook`/`TruncateOutputHook` — the "Pre/Post Hooks"
//! box of the reference Tool-Calling Layer architecture) was a fully implemented, unit-tested
//! mechanism with a real integration test proving it works standalone
//! (`ainxt-tools/tests/r16_hooks_wired_into_dispatch.rs`), but `ToolRuntime::hooks_mut` had ZERO
//! callers anywhere in the served composition root (`ainxt-runtimed`). A freshly built `ToolRuntime`
//! starts with `HookRegistry::default()` — empty — so every dispatch through the real served
//! registry ran the hook box as a pure passthrough no matter what a capability's arguments or output
//! looked like.
//!
//! This test goes through the REAL composition-root entrypoint
//! (`ainxt_runtimed::build_unified_capability_registry`) — the exact function
//! `build_engine_ext`/`assemble_*` call to construct the daemon's unified Capability registry — and
//! proves the default hooks it now installs actually gate dispatch, not merely that `HookRegistry`
//! works standalone (which the ainxt-tools test already proved).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use ainxt_runtimed::build_unified_capability_registry;
use ainxt_tools::{DispatchResult, EffectClass, ParamSpec, Tool, ToolError, ToolSchema};

/// A harmless extra capability registered into the REAL composition-root registry purely to produce
/// a large `Ok` payload — every default native capability the composition root itself registers
/// (`query_ledger`, `structured_query`, `named_fabric_query`, `capability.search`) deliberately fails
/// closed on the generic `Tool::execute` path (they require a principal-scoped `.compile`/`.dispatch`
/// boundary), so none of them can produce the successful, oversized `Ok` needed to observe
/// `TruncateOutputHook` in action. Dispatched through the SAME `ToolRuntime`/`HookRegistry` the
/// composition root built — the global post-hook applies to ANY tool on this registry, which is
/// exactly what "global" means and exactly what needs proving here.
struct LargeEchoTool {
    calls: Arc<AtomicUsize>,
}
impl Tool for LargeEchoTool {
    fn name(&self) -> &str {
        "test_large_echo"
    }
    fn effect_class(&self) -> EffectClass {
        EffectClass::Pure
    }
    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: self.name().into(),
            description: "test-only: echoes a large payload".into(),
            parameters: ParamSpec::Text,
        }
    }
    fn execute(&self, _args: &str) -> Result<String, ToolError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok("A".repeat(100_000))
    }
}

#[test]
fn the_real_composition_root_installs_non_empty_default_hooks() {
    let mut report = Vec::new();
    let registry = build_unified_capability_registry(&mut report);
    let (global_pre, global_post, per_tool_pre, per_tool_post) = registry.hooks().counts();
    assert!(
        global_pre >= 1,
        "the composition root must install at least one global pre-hook (DenyArgsHook) by default"
    );
    assert!(
        global_post >= 1,
        "the composition root must install at least one global post-hook (TruncateOutputHook) by \
         default"
    );
    // Per-tool hooks are untouched by this fix (HashVerifyHook stays per-capability, deployment-fed).
    assert_eq!(per_tool_pre, 0);
    assert_eq!(per_tool_post, 0);
    assert!(
        report
            .iter()
            .any(|line| line.contains("deterministic guardrails installed")),
        "the boot report must disclose the default guardrail installation: {report:?}"
    );
}

#[test]
fn a_dangerous_argument_dispatch_is_blocked_by_the_default_hook_before_the_tool_ever_runs() {
    let mut report = Vec::new();
    let registry = build_unified_capability_registry(&mut report);

    // `query_ledger` is registered by the real composition root and its own `Tool::execute` ALWAYS
    // refuses (fail-closed — it requires the principal-scoped `.compile` boundary). If the pre-hook
    // did not fire, `dispatch` would return `Failed` with the ledger's own boundary-refusal message
    // ("must be invoked through the principal-scoped boundary"). Getting `Blocked` with a
    // hook-refusal-shaped reason instead proves the DenyArgsHook intercepted BEFORE the tool's own
    // logic ran at all.
    let dangerous_args = r#"{"table":"accounts","op":"DROP TABLE accounts"}"#;
    match registry.dispatch("query_ledger", dangerous_args) {
        DispatchResult::Blocked(reason) => {
            assert!(
                reason.contains("deny-args"),
                "expected the DenyArgsHook's refusal, got: {reason}"
            );
            assert!(
                !reason.contains("principal-scoped boundary"),
                "the tool's own execute() must never have run: {reason}"
            );
        }
        other => panic!("expected Blocked by the default DenyArgsHook, got {other:?}"),
    }

    // A benign query for the SAME tool is unaffected by the hook (still fails closed on the tool's own
    // boundary, but for the TOOL's reason, not the hook's) — proving the hook is a narrow tripwire, not
    // a blanket refuser that disables the capability.
    match registry.dispatch("query_ledger", r#"{"table":"accounts","op":"select"}"#) {
        DispatchResult::Failed(reason) => {
            assert!(
                reason.contains("principal-scoped boundary"),
                "a benign call must reach the tool's own logic: {reason}"
            );
        }
        other => panic!("expected the tool's own fail-closed Failed, got {other:?}"),
    }
}

#[test]
fn oversized_tool_output_is_truncated_by_the_default_hook_on_the_real_registry() {
    let mut report = Vec::new();
    let mut registry = build_unified_capability_registry(&mut report);
    let calls = Arc::new(AtomicUsize::new(0));
    registry.register(Box::new(LargeEchoTool {
        calls: calls.clone(),
    }));

    match registry.dispatch("test_large_echo", "{}") {
        DispatchResult::Ok(out) => {
            assert_eq!(
                calls.load(Ordering::SeqCst),
                1,
                "the tool must have actually run"
            );
            assert!(
                out.chars().count() < 100_000,
                "output must be truncated well below the tool's real 100,000-char payload: {} chars",
                out.chars().count()
            );
            assert!(
                out.contains("truncated by tool hook"),
                "truncation must be visible, never a silent partial answer: {out}"
            );
        }
        other => panic!("expected Ok(<truncated>), got {other:?}"),
    }
}
