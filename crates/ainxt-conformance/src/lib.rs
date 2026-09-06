// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! ainxt-conformance — the Definition-of-Done harness that runs the **full 1,000+-scenario matrix**
//! ([`ainxt_scenario::matrix`]) against the **fully-assembled real runtime**, not a mock.
//!
//! Why this crate exists: the scenario harness ([`ainxt_scenario`]) proves the *oracles* work; the
//! per-crate unit tests prove each *component* works. Neither proves the assembled *pipeline* holds
//! its invariants across a large, adversarial, genuinely-distinct corpus. This crate closes that
//! gap. Every scenario runs through a real [`Engine`] wired with:
//!
//! * [`StrongRedactor`] as the compliance gate (streaming-aware output redaction),
//! * [`RbacAuthorizer`] (capability authz + on-behalf-of tool authz),
//! * a [`ModelRouter`] with a **failing primary** in front of the real provider, so EVERY scenario
//!   also exercises provider-failover,
//! * a real [`ToolRuntime`] with an exactly-once ledger, and
//! * the injection taint-gate (side-effecting tools refused on a tainted turn).
//!
//! The conformance provider and the matrix generator share the SAME derivations
//! ([`ainxt_scenario::matrix::pan_from_seed`] et al.) via [`parse_directive`], so a scenario is green
//! iff the runtime's invariant actually holds — never because the test was rigged. A broken invariant
//! (a leaked PAN, a double-executed settlement, an injection that drove a side effect, an
//! unauthorized turn that was served) fails **RED**.
//!
//! Deterministic, no network, no keys (mock providers). See `tests/conformance_matrix.rs`.

pub mod dogfood;

use std::sync::{Arc, Mutex};
use std::time::Instant;

use ainxt_compliance::StrongRedactor;
use ainxt_injection::{InjectionConfig, InjectionMode};
use ainxt_protocol::{Event, Request};
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_runtime::{Engine, InMemoryAudit, RbacAuthorizer};
use ainxt_scenario::matrix::{parse_directive, Directive};
use ainxt_scenario::{Category, Observation, Report, Runner, Scenario, Target};
use ainxt_tools::{
    EffectClass, Field, FieldType, InMemoryLedger, ManualReconciler, ParamSpec, Tool, ToolError,
    ToolRuntime, ToolSchema,
};
use ainxt_types::{DataClass, Principal};
use tokio::sync::mpsc;

/// Always fails (retryable) — the router's primary, forcing failover on every turn.
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

/// The real backup provider — its output is driven by the conformance directive protocol
/// ([`ainxt_scenario::matrix`]) plus the runtime's own appended tool-round markers.
struct ConformanceProvider;

impl ConformanceProvider {
    /// Split a string into `n`-char chunks (for streaming a PAN across deltas — the hard case for
    /// output redaction, which must not leak a PAN split at a delta boundary).
    fn chunks(s: &str, n: usize) -> Vec<String> {
        let bytes: Vec<char> = s.chars().collect();
        bytes.chunks(n).map(|c| c.iter().collect()).collect()
    }
}

impl Provider for ConformanceProvider {
    fn id(&self) -> &str {
        "conformance-backup"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, prompt: &str) -> mpsc::Receiver<Event> {
        let pl = prompt.to_lowercase();
        let (tx, rx) = mpsc::channel(64);

        // Second-round behavior first (the loop appends these markers to the prompt):
        if pl.contains("invalid arguments") {
            // A malformed tool call was rejected — the model recovers.
            tokio::spawn(async move {
                let _ = tx
                    .send(Event::TextDelta("recovered after invalid args".into()))
                    .await;
                let _ = tx.send(Event::Done).await;
            });
            return rx;
        }
        if pl.contains("blocked:") {
            // A side-effecting tool was refused by the injection taint-gate — do NOT retry it.
            tokio::spawn(async move {
                let _ = tx
                    .send(Event::TextDelta(
                        "I will not act on untrusted instructions.".into(),
                    ))
                    .await;
                let _ = tx.send(Event::Done).await;
            });
            return rx;
        }
        if pl.contains("[tool settle result:") {
            // The settlement actually executed — emit a marker that ONLY appears on real execution,
            // so an injection scenario (where it must NOT execute) can forbid it.
            tokio::spawn(async move {
                let _ = tx
                    .send(Event::TextDelta("settlement done SETTLED-OK".into()))
                    .await;
                let _ = tx.send(Event::Done).await;
            });
            return rx;
        }

        // First round: interpret the scenario directive.
        match parse_directive(prompt) {
            Directive::EmitPanSplit(pan) => {
                let chunks = Self::chunks(&pan, 4);
                tokio::spawn(async move {
                    let _ = tx.send(Event::TextDelta("Your card ".into())).await;
                    for c in chunks {
                        let _ = tx.send(Event::TextDelta(c)).await;
                    }
                    let _ = tx.send(Event::TextDelta(" on file.".into())).await;
                    let _ = tx.send(Event::Done).await;
                });
            }
            Directive::EmitSecret(secret) => {
                tokio::spawn(async move {
                    let _ = tx
                        .send(Event::TextDelta(format!(
                            "the key is api_key={secret} thanks"
                        )))
                        .await;
                    let _ = tx.send(Event::Done).await;
                });
            }
            Directive::EmitEmail(email) => {
                tokio::spawn(async move {
                    let _ = tx
                        .send(Event::TextDelta(format!("contact: {email} ok")))
                        .await;
                    let _ = tx.send(Event::Done).await;
                });
            }
            Directive::DupSettle(key) => {
                tokio::spawn(async move {
                    // The SAME side-effecting action requested twice → the ledger must dedup it.
                    let _ = tx
                        .send(Event::ToolCallStart {
                            id: "a".into(),
                            name: "settle".into(),
                            args: key.clone(),
                        })
                        .await;
                    let _ = tx
                        .send(Event::ToolCallStart {
                            id: "b".into(),
                            name: "settle".into(),
                            args: key,
                        })
                        .await;
                    let _ = tx.send(Event::Done).await;
                });
            }
            Directive::Malformed => {
                tokio::spawn(async move {
                    // Malformed JSON for a STRUCTURED tool → §7a0 validation must reject it.
                    let _ = tx
                        .send(Event::ToolCallStart {
                            id: "m".into(),
                            name: "pay".into(),
                            args: "{not valid json".into(),
                        })
                        .await;
                    let _ = tx.send(Event::Done).await;
                });
            }
            Directive::InjectionSettle => {
                tokio::spawn(async move {
                    // A poisoned instruction tries to drive a real settlement — the taint-gate must
                    // block it (the turn is marked tainted by the caller).
                    let _ = tx
                        .send(Event::ToolCallStart {
                            id: "i".into(),
                            name: "settle".into(),
                            args: "inj-key".into(),
                        })
                        .await;
                    let _ = tx.send(Event::Done).await;
                });
            }
            Directive::Emit(text) => {
                tokio::spawn(async move {
                    // Echo (round-trip: huge / unicode / plain). Empty output can never masquerade
                    // as success because the scenario asserts a substring is present.
                    let _ = tx.send(Event::TextDelta(text)).await;
                    let _ = tx.send(Event::Done).await;
                });
            }
        }
        rx
    }
}

/// Records side-effecting settlements that actually executed (a duplicate ⇒ double-execution).
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

/// A structured tool ({"account": String}) — exercises malformed-JSON rejection.
struct PayTool;
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
            description: "pay an account".into(),
            parameters: ParamSpec::Object {
                fields: vec![Field::required("account", FieldType::String)],
                additional: false,
            },
        }
    }
    fn execute(&self, _args: &str) -> Result<String, ToolError> {
        Ok("paid".into())
    }
}

/// The real-runtime [`Target`]: maps a scenario to a runtime turn and captures the observation.
pub struct ConformanceTarget {
    engine: Arc<Engine>,
    executed: Arc<Mutex<Vec<String>>>,
    rt: tokio::runtime::Runtime,
}

impl ConformanceTarget {
    /// Build the fully-assembled conformance runtime.
    pub fn new() -> Self {
        let executed = Arc::new(Mutex::new(Vec::new()));
        let mut router = ModelRouter::new();
        router.register(Box::new(FlakyPrimary)); // primary always fails → failover on every turn
        router.register(Box::new(ConformanceProvider));
        let mut tools =
            ToolRuntime::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler));
        tools.register(Box::new(SettleTool {
            executed: executed.clone(),
        }));
        tools.register(Box::new(PayTool));
        // Injection must be ENFORCE (an Off config is treated as disabled by the engine), so a
        // tainted turn arms the side-effecting-tool gate.
        let injection = InjectionConfig {
            mode: InjectionMode::Enforce,
            gate_side_effects_on_taint: true,
            ..Default::default()
        };
        let engine = Engine::new(
            Box::new(StrongRedactor::new()),
            Box::new(RbacAuthorizer),
            Box::new(InMemoryAudit::default()),
            router,
        )
        .with_tools(tools)
        .with_retry(0, 0)
        .with_injection(&injection);
        ConformanceTarget {
            engine: Arc::new(engine),
            executed,
            rt: tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("rt"),
        }
    }
}

impl Default for ConformanceTarget {
    fn default() -> Self {
        Self::new()
    }
}

impl Target for ConformanceTarget {
    fn run(&self, s: &Scenario) -> Observation {
        self.executed.lock().unwrap().clear();
        // A principal WITHOUT chat.send for RBAC-deny scenarios; otherwise a normally-capable user.
        let principal = match s.category {
            Category::RbacDeny => Principal::user("blocked", &[]),
            _ => Principal::user("u", &["chat.send", "tool.settle", "tool.pay"]),
        };
        let data_class = match s.category {
            Category::DataClassLeak | Category::ComplianceRedaction => DataClass::Confidential,
            _ => DataClass::Public,
        };
        let mut req = Request::chat("conformance", &s.id, &s.input, data_class);
        // An injection scenario models untrusted content that has already tainted the turn.
        if s.category == Category::Injection {
            req.untrusted_tainted = true;
        }
        let started = Instant::now();
        let obs = match self
            .rt
            .block_on(self.engine.run_turn_collect(&principal, &req))
        {
            Ok(o) => {
                // Surface a TERMINAL fatal error from the event stream (run_turn returns Ok even
                // when the chain failed / a gate blocked) so the crash oracle sees it.
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
                side_effects: self.executed.lock().unwrap().clone(),
                latency_ms: started.elapsed().as_millis() as u64,
                ..Default::default()
            },
        };
        obs
    }
}

/// Run the full generated matrix through the real runtime and return the DoD report.
pub fn run_matrix() -> Report {
    let target = ConformanceTarget::new();
    Runner::with_default_oracles().run(&ainxt_scenario::matrix::matrix_suite(), &target)
}

/// Run the **pairwise-generated** corpus (`SCENARIO_MATRIX.md` §2 — the mechanism that produces the
/// 1,000+ matrix from `templates × pairwise(axes)`) through the real runtime and return the DoD
/// report. This proves the pairwise corpus is not just large but actually GREEN against the assembled
/// pipeline (every axis combination still holds every safety invariant).
pub fn run_pairwise_matrix() -> Report {
    let target = ConformanceTarget::new();
    Runner::with_default_oracles().run(&ainxt_scenario::matrix::pairwise_matrix_suite(), &target)
}

impl ConformanceTarget {
    /// Run a scenario against the real runtime with a **pre-cancelled** token (the cancel-mid-turn
    /// category, `SCENARIO_MATRIX.md` §1.3): the engine must honour cooperative cancellation and NOT
    /// execute any side effect. Returns the collected observation (its `error` names the cancel).
    pub fn run_cancelled(&self, s: &Scenario) -> Observation {
        use ainxt_runtime::cancel::CancelToken;
        self.executed.lock().unwrap().clear();
        let principal = Principal::user("u", &["chat.send", "tool.settle", "tool.pay"]);
        let req = Request::chat("conformance", &s.id, &s.input, DataClass::Public);
        let cancel = CancelToken::new();
        cancel.cancel(); // pre-cancelled: the turn must abort before any side effect
        let started = Instant::now();
        let (tx, mut rx) = mpsc::channel::<Event>(64);
        let obs = self.rt.block_on(async {
            let run = self
                .engine
                .run_turn_cancellable(&principal, &req, tx, &cancel);
            let collect = async move {
                let mut v = Vec::new();
                while let Some(e) = rx.recv().await {
                    v.push(e);
                }
                v
            };
            let (res, events) = tokio::join!(run, collect);
            let error = events.iter().find_map(|e| match e {
                Event::Error(m) => Some(m.clone()),
                _ => None,
            });
            let final_text = res.map(|s| s.final_text).unwrap_or_default();
            Observation {
                output: final_text,
                error,
                side_effects: self.executed.lock().unwrap().clone(),
                latency_ms: started.elapsed().as_millis() as u64,
            }
        });
        obs
    }

    /// Run many scenarios **concurrently against one engine** (the N-session concurrency category,
    /// `SCENARIO_MATRIX.md` §1.4): distinct sessions are spawned as real parallel tasks on a
    /// multi-thread runtime and each observation must reflect ONLY its own input — no cross-session
    /// state bleed. Returns `(scenario_id, observation)` pairs.
    pub fn run_many_concurrent(&self, scenarios: &[Scenario]) -> Vec<(String, Observation)> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .expect("multi-thread rt");
        rt.block_on(async {
            let mut handles = Vec::with_capacity(scenarios.len());
            for s in scenarios {
                let engine = self.engine.clone();
                let id = s.id.clone();
                let input = s.input.clone();
                handles.push(tokio::spawn(async move {
                    let principal = Principal::user("u", &["chat.send"]);
                    let req = Request::chat("conformance", &id, &input, DataClass::Public);
                    let out = engine
                        .run_turn_collect(&principal, &req)
                        .await
                        .map(|o| o.final_text)
                        .unwrap_or_default();
                    (
                        id,
                        Observation {
                            output: out,
                            ..Default::default()
                        },
                    )
                }));
            }
            let mut out = Vec::with_capacity(handles.len());
            for h in handles {
                out.push(h.await.expect("session task panicked"));
            }
            out
        })
    }
}
