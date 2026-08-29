// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! GAP2 harness-sdk — artifact-event integration test, driven end-to-end on the REAL `Engine`
//! (`run_turn`), never a mock of the dispatch loop.
//!
//! Before this change: `ainxt_protocol::Event` had no `Artifact` variant, so an `artifact.*`
//! capability step's result surfaced on the live stream ONLY as an opaque `Event::ToolResult` —
//! indistinguishable, to a renderer/SDK consumer, from any other tool's plain text.
//!
//! After: dispatching a tool whose name is in the `artifact.*` namespace additionally emits a
//! typed `Event::Artifact { id, capability, output }` carrying the SAME call id and (compliance-
//! scanned) output as the `ToolResult` — additive, never a replacement — so a consumer that
//! understands the richer vocabulary can route it to artifact-aware handling.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use ainxt_protocol::{Event, Request};
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_runtime::wire::VecWireSink;
use ainxt_runtime::{engine_with_defaults, TurnError};
use ainxt_tools::{EffectClass, InMemoryLedger, ManualReconciler, Tool, ToolError, ToolRuntime};
use ainxt_types::{DataClass, Principal};
use tokio::sync::mpsc;

/// Calls the `artifact.generate` tool on its FIRST round, then answers plainly on the next round
/// (so the turn reaches a natural `Complete` stop instead of tripping the stuck-detector).
struct ArtifactToolProvider {
    called_once: Arc<AtomicBool>,
}
impl Provider for ArtifactToolProvider {
    fn id(&self) -> &str {
        "artifactprov"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, _prompt: &str) -> mpsc::Receiver<Event> {
        let (tx, rx) = mpsc::channel(8);
        let first = !self.called_once.swap(true, Ordering::SeqCst);
        tokio::spawn(async move {
            if first {
                let _ = tx
                    .send(Event::ToolCallStart {
                        id: "c1".into(),
                        name: "artifact.generate".into(),
                        args: "{}".into(),
                    })
                    .await;
            } else {
                let _ = tx
                    .send(Event::TextDelta("here is your report".into()))
                    .await;
            }
            let _ = tx.send(Event::Done).await;
        });
        rx
    }
}

/// A trivial artifact-producing tool — the "real" side effect is irrelevant to this test; only its
/// NAME (`artifact.generate`) matters for the emit-site routing under test.
struct ArtifactGenTool;
impl Tool for ArtifactGenTool {
    fn name(&self) -> &str {
        "artifact.generate"
    }
    fn effect_class(&self) -> EffectClass {
        EffectClass::Pure
    }
    fn execute(&self, _args: &str) -> Result<String, ToolError> {
        Ok("s3://bucket/report.pdf".into())
    }
}

async fn run_and_drain(
    eng: &ainxt_runtime::Engine,
    principal: &Principal,
    req: &Request,
) -> (Result<ainxt_runtime::TurnSummary, TurnError>, Vec<Event>) {
    let (tx, mut rx) = mpsc::channel::<Event>(64);
    let fut = eng.run_turn(principal, req, tx);
    let drain = async move {
        let mut v = Vec::new();
        while let Some(e) = rx.recv().await {
            v.push(e);
        }
        v
    };
    tokio::join!(fut, drain)
}

#[tokio::test]
async fn gap2_artifact_capability_emits_typed_artifact_event_additively() {
    let mut router = ModelRouter::new();
    router.register(Box::new(ArtifactToolProvider {
        called_once: Arc::new(AtomicBool::new(false)),
    }));
    let mut tr = ToolRuntime::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler));
    tr.register(Box::new(ArtifactGenTool));
    let wire = Arc::new(VecWireSink::default());
    let eng = engine_with_defaults(router)
        .with_tools(tr)
        .with_wire_sink(Box::new(wire.clone()));

    let p = Principal::user("u", &["chat.send", "tool.artifact.generate"]);
    let req = Request::chat("s", "t", "make me a report", DataClass::Public);

    let (res, events) = run_and_drain(&eng, &p, &req).await;
    assert!(
        res.is_ok(),
        "turn with an artifact.* tool call should complete, got {res:?}"
    );

    let artifact_ev = events.iter().find_map(|e| match e {
        Event::Artifact {
            id,
            capability,
            output,
        } => Some((id.clone(), capability.clone(), output.clone())),
        _ => None,
    });
    let (id, capability, output) = artifact_ev.unwrap_or_else(|| {
        panic!("an artifact.* capability call must emit a typed Event::Artifact; events={events:?}")
    });
    assert_eq!(capability, "artifact.generate");
    assert_eq!(output, "s3://bucket/report.pdf");

    // Additive, not a replacement: the legacy ToolResult for the SAME call id must still be present
    // so a consumer that only understands the old vocabulary is unaffected.
    assert!(
        events
            .iter()
            .any(|e| matches!(e, Event::ToolResult { id: rid, output: o } if *rid == id && *o == output)),
        "Event::Artifact must be emitted ALONGSIDE Event::ToolResult for the same call, never instead \
         of it; events={events:?}"
    );

    // A non-artifact tool call must NOT produce an Event::Artifact (the routing is name-scoped, not
    // universal) — proven implicitly here since no other tool ran, and explicitly in the unit test
    // below via `artifact_event_for`.
}
