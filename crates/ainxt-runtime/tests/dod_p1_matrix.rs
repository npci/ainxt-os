// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! P1-EXIT DoD acceptance matrix: drive the FULLY-ASSEMBLED runtime through the scenario harness
//! across the Phase-1 acceptance categories, with layered oracles + a coverage report + JUnit.
//!
//! To prove resilience pervasively, the router has a FAILING primary provider in front of the real
//! one, so EVERY scenario also exercises provider-failover. Scenarios are written to fail-red if
//! the invariant they name breaks (no false-greens): redaction is proven on a PAN SPLIT across
//! deltas; huge/RTL inputs are echoed back so empty output fails; internal fatal errors are
//! surfaced to the crash oracle.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use ainxt_protocol::{Event, Request};
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_runtime::{engine_with_defaults, Engine};
use ainxt_scenario::{Category, Expectation, Observation, Runner, Scenario, Target};
use ainxt_tools::{
    EffectClass, Field, FieldType, InMemoryLedger, ManualReconciler, ParamSpec, Tool, ToolError,
    ToolRuntime, ToolSchema,
};
use ainxt_types::{DataClass, Principal};
use tokio::sync::mpsc;

/// Always fails (retryable) — the primary, to force failover on every turn.
struct FlakyPrimary;
impl Provider for FlakyPrimary {
    fn id(&self) -> &str {
        "flaky-primary"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, _p: &str) -> mpsc::Receiver<Event> {
        let (tx, rx) = mpsc::channel(2);
        tokio::spawn(async move {
            let _ = tx
                .send(Event::Error("503 service unavailable".into()))
                .await;
        });
        rx
    }
}

/// The real backup — behaves by prompt content to exercise each category.
struct BackupProvider;
impl Provider for BackupProvider {
    fn id(&self) -> &str {
        "backup"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, prompt: &str) -> mpsc::Receiver<Event> {
        let p = prompt.to_lowercase();
        let (tx, rx) = mpsc::channel(16);
        let echo = format!("Answer: {prompt}");
        tokio::spawn(async move {
            if p.contains("invalid arguments") {
                // Round 2 after a malformed tool call was rejected — the model recovers.
                let _ = tx
                    .send(Event::TextDelta("recovered after invalid args".into()))
                    .await;
            } else if p.contains("[tool settle") {
                let _ = tx.send(Event::TextDelta("settlement done".into())).await;
            } else if p.contains("malformed") {
                // Malformed tool-call JSON for a STRUCTURED tool → §7a0 validation must reject it.
                let _ = tx
                    .send(Event::ToolCallStart {
                        id: "m".into(),
                        name: "pay".into(),
                        args: "{not valid json".into(),
                    })
                    .await;
            } else if p.contains("settle") {
                // Same side-effecting action requested TWICE → the ledger must dedup it.
                let _ = tx
                    .send(Event::ToolCallStart {
                        id: "a".into(),
                        name: "settle".into(),
                        args: "NEFT-1".into(),
                    })
                    .await;
                let _ = tx
                    .send(Event::ToolCallStart {
                        id: "b".into(),
                        name: "settle".into(),
                        args: "NEFT-1".into(),
                    })
                    .await;
            } else if p.contains("account") || p.contains("card") {
                // Emit the PAN SPLIT across deltas (as a real streaming model would) — per-delta
                // redaction would leak; streaming-aware redaction must catch it.
                let _ = tx.send(Event::TextDelta("Account ".into())).await;
                for chunk in ["4111", "1111", "1111", "1111"] {
                    let _ = tx.send(Event::TextDelta(chunk.into())).await;
                }
                let _ = tx.send(Event::TextDelta(" PAN=".into())).await;
                let _ = tx.send(Event::TextDelta("999888777666".into())).await;
                let _ = tx.send(Event::TextDelta(" on file.".into())).await;
            } else {
                // Echo the (redacted) prompt back so huge/unicode inputs round-trip and empty
                // output can never masquerade as success.
                let _ = tx.send(Event::TextDelta(echo)).await;
            }
            let _ = tx.send(Event::Done).await;
        });
        rx
    }
}

/// Records the side-effecting actions that actually executed (a dup ⇒ double-execution).
struct SettleTool {
    executed: Arc<Mutex<Vec<String>>>,
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
        self.executed.lock().unwrap().push(args.to_string());
        Ok(format!("settled:{args}"))
    }
}

/// A structured tool (args must be {"account": String}) — used to exercise malformed-JSON rejection.
struct PayTool {
    calls: Arc<AtomicU32>,
}
impl Tool for PayTool {
    fn name(&self) -> &str {
        "pay"
    }
    fn effect_class(&self) -> EffectClass {
        EffectClass::SideEffecting
    }
    fn idempotency_key(&self, args: &str) -> Option<String> {
        Some(args.to_string())
    }
    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "pay".into(),
            description: "pay".into(),
            parameters: ParamSpec::Object {
                fields: vec![Field::required("account", FieldType::String)],
                additional: false,
            },
        }
    }
    fn execute(&self, _args: &str) -> Result<String, ToolError> {
        self.calls.fetch_add(1, Ordering::SeqCst); // must stay 0 — malformed args never dispatch
        Ok("paid".into())
    }
}

struct DodTarget {
    engine: Engine,
    executed: Arc<Mutex<Vec<String>>>,
    pay_calls: Arc<AtomicU32>,
    rt: tokio::runtime::Runtime,
}

impl Target for DodTarget {
    fn run(&self, s: &Scenario) -> Observation {
        self.executed.lock().unwrap().clear();
        let principal = match s.category {
            Category::RbacDeny => Principal::user("blocked", &[]), // lacks chat.send
            _ => Principal::user("u", &["chat.send", "tool.settle", "tool.pay"]),
        };
        let data_class = match s.category {
            Category::DataClassLeak | Category::ComplianceRedaction => DataClass::Confidential,
            _ => DataClass::Public,
        };
        let req = Request::chat("dod-session", &s.id, &s.input, data_class);
        let started = Instant::now();
        match self
            .rt
            .block_on(self.engine.run_turn_collect(&principal, &req))
        {
            Ok(o) => {
                // Surface a TERMINAL fatal error from the event stream — run_turn returns Ok even
                // when the whole chain failed / guardrails blocked / no tool runtime; the crash
                // oracle must see that, not a hard-coded None.
                let fatal = o.events.iter().find_map(|e| match e {
                    Event::Error(m) => Some(m.clone()),
                    _ => None,
                });
                Observation {
                    output: o.final_text,
                    error: fatal,
                    side_effects: self.executed.lock().unwrap().clone(),
                    latency_ms: started.elapsed().as_millis() as u64,
                }
            }
            Err(e) => Observation {
                error: Some(format!("{e:?}")),
                latency_ms: started.elapsed().as_millis() as u64,
                ..Default::default()
            },
        }
    }
}

fn dod_target() -> DodTarget {
    let executed = Arc::new(Mutex::new(Vec::new()));
    let pay_calls = Arc::new(AtomicU32::new(0));
    let mut router = ModelRouter::new();
    router.register(Box::new(FlakyPrimary)); // primary always fails → failover
    router.register(Box::new(BackupProvider));
    let mut tools = ToolRuntime::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler));
    tools.register(Box::new(SettleTool {
        executed: executed.clone(),
    }));
    tools.register(Box::new(PayTool {
        calls: pay_calls.clone(),
    }));
    let engine = engine_with_defaults(router)
        .with_tools(tools)
        .with_retry(0, 0);
    DodTarget {
        engine,
        executed,
        pay_calls,
        rt: tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("rt"),
    }
}

fn expect(must_contain: &[&str]) -> Expectation {
    Expectation {
        must_contain: must_contain.iter().map(|s| s.to_string()).collect(),
        must_complete: true,
        ..Default::default()
    }
}

fn matrix() -> Vec<Scenario> {
    let huge = "transaction volumes ".repeat(20_000); // ~400 KB, no branch-trigger words
    let rtl = "التسوية اليوم שלום 🌐 نظام"; // unicode/RTL/emoji, no branch-trigger words
    vec![
        Scenario::new(
            "CHAT-001",
            "grounded chat answer via failover",
            Category::Custom,
            "how did UPI grow?",
            expect(&["Answer", "UPI"]),
        ),
        Scenario::new(
            "FAILOVER-001",
            "primary fails → backup serves",
            Category::ProviderFailover,
            "status update please",
            expect(&["Answer"]),
        ),
        Scenario::new(
            "REDACT-001",
            "a PAN STREAMED across deltas is redacted before leaving the runtime",
            Category::ComplianceRedaction,
            "show me the account details",
            Expectation {
                must_complete: true,
                must_contain: vec!["[REDACTED-PAN]".into()],
                forbidden_leak_markers: vec!["4111111111111111".into(), "PAN=999".into()],
                ..Default::default()
            },
        ),
        Scenario::new(
            "LEAK-001",
            "confidential-class turn never leaks a streamed PAN",
            Category::DataClassLeak,
            "show me the card on file",
            Expectation {
                must_complete: true,
                forbidden_leak_markers: vec!["4111111111111111".into()],
                ..Default::default()
            },
        ),
        Scenario::new(
            "HUGE-001",
            "a ~400KB input round-trips without crashing",
            Category::HugeInput,
            &huge,
            expect(&["transaction volumes"]),
        ),
        Scenario::new(
            "RTL-001",
            "unicode/RTL/emoji input round-trips uncorrupted",
            Category::UnicodeRtl,
            rtl,
            expect(&["שלום", "🌐"]),
        ),
        Scenario::new(
            "MALFORMED-001",
            "malformed tool-call JSON is rejected, and the model recovers",
            Category::MalformedModelOutput,
            "please do a malformed thing",
            expect(&["recovered"]),
        ),
        Scenario::new(
            "IDEM-001",
            "a duplicated settlement action executes exactly once (no double debit)",
            Category::DoubleExecution,
            "initiate settle NEFT-1",
            Expectation {
                must_complete: true,
                must_contain: vec!["settlement done".into()],
                forbid_side_effect_dupes: true,
                ..Default::default()
            },
        ),
        Scenario::new(
            "RBAC-001",
            "a principal without chat.send is denied (gate refuses, nothing served)",
            Category::RbacDeny,
            "how did UPI grow?",
            Expectation {
                must_complete: false,
                must_error_contains: vec!["Denied".into()],
                forbidden_leak_markers: vec!["Answer".into()],
                ..Default::default()
            },
        ),
    ]
}

#[test]
fn p1_exit_acceptance_matrix_is_green() {
    let target = dod_target();
    let report = Runner::with_default_oracles().run(&matrix(), &target);
    eprintln!("{}", report.summary());
    assert!(
        report.junit_xml().contains("<testsuite"),
        "JUnit report is produced for CI"
    );

    assert!(
        report.all_passed(),
        "P1 acceptance matrix must be green:\n{}",
        report.summary()
    );
    let covered = report.coverage().len();
    assert!(
        covered >= 8,
        "matrix must cover >= 8 P1 categories (covered {covered})"
    );

    // Payment-critical spot checks beyond the aggregate green:
    let idem = report.results.iter().find(|r| r.id == "IDEM-001").unwrap();
    assert!(idem.passed(), "exactly-once must hold under failover");
    let rbac = report.results.iter().find(|r| r.id == "RBAC-001").unwrap();
    assert!(
        rbac.passed(),
        "an unauthorized turn must be denied and leak nothing"
    );
    // The malformed args must NEVER have reached the tool.
    assert_eq!(
        target.pay_calls.load(Ordering::SeqCst),
        0,
        "malformed args must be rejected before dispatch"
    );
}
