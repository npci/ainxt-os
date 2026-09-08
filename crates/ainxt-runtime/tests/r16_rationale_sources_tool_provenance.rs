// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! GAP-FIX rationale-sources (turn-pipeline) — `turn.rationale`'s `sources` field
//! (`Engine::run_turn_cancellable`, `runtime/crates/ainxt-runtime/src/lib.rs`) previously drew
//! EXCLUSIVELY from memory/Context-Fabric lineage (`{id}@v{version}`, populated only when a
//! `MemoryReader` is attached and returns hits). A turn that grounded its answer entirely on a
//! tool-result/retrieval producer — a search tool, an MCP resource fetch, any dispatched
//! capability — reported an EMPTY "why this" panel even though real, auditable provenance
//! existed: the model read the tool's observation and used it, same as it would a memory hit.
//!
//! Fixed by recording `"tool:{name}#{call_id}"` into the same `rationale_sources` accumulator at
//! BOTH tool-dispatch call sites that can produce a result: the concurrent/batched fast path
//! (`Engine::flush_dispatch_batch`) and the serial path (approval/payment/two-phase/injection-on
//! calls, which never enter the batch). Fails-before: `sources` was `[]` for a tool-only turn.
//!
//! `r16_rationale_sources_includes_tool_result` — no memory reader attached (so the ONLY possible
//! provenance is the tool call), one tool round dispatched on the batched path (no injection/
//! approval/payment configured ⇒ `LookupTool` qualifies for the concurrent fast path per the gate
//! at the `pending.push(PreparedCall ...)` call site) — asserts the wire's `turn.rationale.sources`
//! contains the tool-result provenance tag and the pre-fix-empty state does NOT recur.

use std::sync::Arc;

use ainxt_protocol::{Event, Request, WireEvent};
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_runtime::wire::VecWireSink;
use ainxt_runtime::{engine_with_defaults, Engine};
use ainxt_tools::{EffectClass, InMemoryLedger, ManualReconciler, Tool, ToolError, ToolRuntime};
use ainxt_types::{DataClass, Principal};
use tokio::sync::mpsc;

/// A pure lookup tool (no side effect) — same shape as the r4 fixture: the dispatch produces an
/// observation that is fed back into the prompt so the scripted provider can settle.
struct LookupTool;
impl Tool for LookupTool {
    fn name(&self) -> &str {
        "lookup"
    }
    fn effect_class(&self) -> EffectClass {
        EffectClass::Pure
    }
    fn execute(&self, _args: &str) -> Result<String, ToolError> {
        Ok("record-42".into())
    }
}

/// Emits ONE tool call on the first round, then acknowledges once the observation is folded back
/// into the prompt (mirrors `OneToolProvider` in `r4_turn_pipeline_test.rs`).
struct OneToolProvider {
    tool: String,
    args: String,
}
impl Provider for OneToolProvider {
    fn id(&self) -> &str {
        "oneprov"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, prompt: &str) -> mpsc::Receiver<Event> {
        let (tx, rx) = mpsc::channel(8);
        let settled = prompt.contains("result:");
        let tool = self.tool.clone();
        let args = self.args.clone();
        tokio::spawn(async move {
            if settled {
                let _ = tx.send(Event::TextDelta("acknowledged".into())).await;
            } else {
                let _ = tx
                    .send(Event::ToolCallStart {
                        id: "c0".into(),
                        name: tool,
                        args,
                    })
                    .await;
            }
            let _ = tx.send(Event::Done).await;
        });
        rx
    }
}

fn user(caps: &[&str]) -> Principal {
    Principal::user("u", caps)
}

#[tokio::test]
async fn r16_rationale_sources_includes_tool_result() {
    let mut router = ModelRouter::new();
    router.register(Box::new(OneToolProvider {
        tool: "lookup".into(),
        args: "{\"q\":\"x\"}".into(),
    }));
    let mut tr = ToolRuntime::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler));
    tr.register(Box::new(LookupTool));

    let wire = Arc::new(VecWireSink::default());
    // No memory reader attached: the ONLY possible `turn.rationale` provenance in this turn is the
    // tool call, so a non-empty `sources` proves it came from the tool-result path, not memory.
    let eng: Engine = engine_with_defaults(router)
        .with_tools(tr)
        .with_wire_sink(Box::new(Arc::clone(&wire)));

    eng.run_turn_collect(
        &user(&["chat.send", "tool.lookup"]),
        &Request::chat("s", "t", "look it up", DataClass::Public),
    )
    .await
    .unwrap();

    let envs = wire.snapshot();
    let sources = envs
        .iter()
        .find_map(|e| match &e.event {
            WireEvent::TurnRationale { sources, .. } => Some(sources.clone()),
            _ => None,
        })
        .expect("a turn.rationale envelope on the wire");

    assert!(
        sources.iter().any(|s| s == "tool:lookup#c0"),
        "expected turn.rationale.sources to carry tool-result provenance \
         (\"tool:lookup#c0\"), got: {sources:?}"
    );
}
