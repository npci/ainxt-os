// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Pipeline hardening (P1 acceptance): cooperative cancellation, provider failover, same-provider
//! retry on retryable errors, and terminal handling once output has started.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ainxt_protocol::{Event, Request};
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_runtime::{engine_with_defaults, CancelToken};
use ainxt_tools::{EffectClass, InMemoryLedger, ManualReconciler, Tool, ToolError, ToolRuntime};
use ainxt_types::{DataClass, Principal};
use tokio::sync::{mpsc, Notify};

fn user() -> Principal {
    Principal::user("u", &["chat.send", "tool.noop", "tool.settle"])
}
fn req() -> Request {
    Request::chat("s", "t", "hi", DataClass::Public)
}

// --- provider doubles ---

/// Emits a fixed sequence of events; counts invocations.
struct ScriptProvider {
    id: &'static str,
    events: Vec<Event>,
    invocations: Arc<AtomicUsize>,
}
impl ScriptProvider {
    fn new(id: &'static str, events: Vec<Event>) -> (Self, Arc<AtomicUsize>) {
        let c = Arc::new(AtomicUsize::new(0));
        (
            ScriptProvider {
                id,
                events,
                invocations: c.clone(),
            },
            c,
        )
    }
}
impl Provider for ScriptProvider {
    fn id(&self) -> &str {
        self.id
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, _prompt: &str) -> mpsc::Receiver<Event> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = mpsc::channel(8);
        let events = self.events.clone();
        tokio::spawn(async move {
            for e in events {
                if tx.send(e).await.is_err() {
                    break;
                }
            }
        });
        rx
    }
}

/// Fails (retryable) for the first `fail_n` invocations, then succeeds with text.
struct FlakyProvider {
    invocations: Arc<AtomicUsize>,
    fail_n: usize,
}
impl Provider for FlakyProvider {
    fn id(&self) -> &str {
        "flaky"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, _prompt: &str) -> mpsc::Receiver<Event> {
        let n = self.invocations.fetch_add(1, Ordering::SeqCst); // 0-based invocation index
        let fail_n = self.fail_n;
        let (tx, rx) = mpsc::channel(8);
        tokio::spawn(async move {
            let evs = if n < fail_n {
                vec![Event::Error("503 service unavailable".into())]
            } else {
                vec![Event::TextDelta("recovered".into()), Event::Done]
            };
            for e in evs {
                let _ = tx.send(e).await;
            }
        });
        rx
    }
}

/// Emits a TextDelta, then blocks forever (a stuck/slow provider) — lets a cancel land mid-stream.
struct HangProvider {
    invocations: Arc<AtomicUsize>,
}
impl Provider for HangProvider {
    fn id(&self) -> &str {
        "hang"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, _prompt: &str) -> mpsc::Receiver<Event> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = mpsc::channel(8);
        tokio::spawn(async move {
            // The token ends on a boundary (a trailing space), like a real streamed word. Streaming-
            // aware output redaction holds back a trailing IN-PROGRESS alphanumeric run (a split PAN
            // could continue into the next delta), so a lone all-alnum token with no following
            // boundary would be legitimately buffered until Done/cancel — which never comes here. The
            // boundary lets the partial output be observed mid-stream, exactly as a real provider's
            // whitespace-separated tokens would.
            let _ = tx.send(Event::TextDelta("partial ".into())).await;
            std::future::pending::<()>().await; // never sends Done — simulates a hung provider
        });
        rx
    }
}

// --- tests ---

#[tokio::test]
async fn cancel_before_the_turn_never_calls_a_provider() {
    let (p, invs) = ScriptProvider::new("mock", vec![Event::TextDelta("hi".into()), Event::Done]);
    let mut router = ModelRouter::new();
    router.register(Box::new(p));
    let eng = engine_with_defaults(router);

    let cancel = CancelToken::new();
    cancel.cancel(); // cancelled up front

    let (tx, mut rx) = mpsc::channel(16);
    let summary = eng
        .run_turn_cancellable(&user(), &req(), tx, &cancel)
        .await
        .unwrap();
    let mut events = Vec::new();
    while let Some(e) = rx.recv().await {
        events.push(e);
    }

    assert_eq!(
        invs.load(Ordering::SeqCst),
        0,
        "a pre-cancelled turn must not call the provider"
    );
    assert_eq!(summary.provider, "cancelled");
    assert!(events
        .iter()
        .any(|e| matches!(e, Event::Error(m) if m.contains("cancelled"))));
    assert!(events.contains(&Event::Done));
}

#[tokio::test]
async fn cancel_mid_stream_stops_promptly_with_partial_output() {
    let invs = Arc::new(AtomicUsize::new(0));
    let mut router = ModelRouter::new();
    router.register(Box::new(HangProvider {
        invocations: invs.clone(),
    }));
    let eng = Arc::new(engine_with_defaults(router));

    let cancel = CancelToken::new();
    let (tx, mut rx) = mpsc::channel(16);

    let e2 = eng.clone();
    let c2 = cancel.clone();
    let handle = tokio::spawn(async move {
        let p = Principal::user("u", &["chat.send"]);
        let r = Request::chat("s", "t", "hi", DataClass::Public);
        e2.run_turn_cancellable(&p, &r, tx, &c2).await
    });

    // Observe the first (partial) delta, THEN cancel — the provider is still "hung".
    let first = rx.recv().await.unwrap();
    assert_eq!(first, Event::TextDelta("partial ".into()));
    cancel.cancel();

    let mut rest = Vec::new();
    while let Some(e) = rx.recv().await {
        rest.push(e);
    }
    let summary = handle.await.unwrap().unwrap();

    assert_eq!(
        summary.final_text, "partial ",
        "partial output before cancel is preserved"
    );
    // Audit fidelity: a partially-served cancelled turn is attributed to the serving provider,
    // not "none".
    assert_eq!(
        summary.provider, "hang",
        "cancelled-after-output must attribute to the provider"
    );
    assert!(rest
        .iter()
        .any(|e| matches!(e, Event::Error(m) if m.contains("cancelled"))));
    assert!(rest.contains(&Event::Done));
    assert_eq!(
        invs.load(Ordering::SeqCst),
        1,
        "the hung provider is invoked once, not re-invoked"
    );
}

#[tokio::test]
async fn failover_to_the_next_eligible_provider_on_error() {
    // Provider A errors before any output; B serves. With retries=0, A fails over immediately.
    let (a, a_invs) = ScriptProvider::new("A", vec![Event::Error("503 unavailable".into())]);
    let (b, b_invs) = ScriptProvider::new(
        "B",
        vec![Event::TextDelta("served-by-B".into()), Event::Done],
    );
    let mut router = ModelRouter::new();
    router.register(Box::new(a));
    router.register(Box::new(b));
    let eng = engine_with_defaults(router).with_retry(0, 0);

    let out = eng.run_turn_collect(&user(), &req()).await.unwrap();

    assert_eq!(out.final_text, "served-by-B");
    assert_eq!(out.provider, "B");
    assert_eq!(a_invs.load(Ordering::SeqCst), 1, "A is tried once");
    assert_eq!(b_invs.load(Ordering::SeqCst), 1, "then failover to B");
    assert_eq!(
        done_count(&out.events),
        1,
        "exactly one terminal Done across a failover"
    );
}

#[tokio::test]
async fn retryable_error_retries_the_same_provider_then_succeeds() {
    let invs = Arc::new(AtomicUsize::new(0));
    let mut router = ModelRouter::new();
    router.register(Box::new(FlakyProvider {
        invocations: invs.clone(),
        fail_n: 1,
    }));
    // Retry up to 2 times, no backoff delay (deterministic + fast).
    let eng = engine_with_defaults(router).with_retry(2, 0);

    let out = eng.run_turn_collect(&user(), &req()).await.unwrap();

    assert_eq!(out.final_text, "recovered");
    assert_eq!(out.provider, "flaky");
    assert_eq!(
        invs.load(Ordering::SeqCst),
        2,
        "first attempt fails (retryable), second succeeds"
    );
}

#[tokio::test]
async fn terminal_error_after_partial_output_does_not_fail_over() {
    // A streams a delta THEN errors — can't un-emit, so no failover even though B is healthy.
    let (a, a_invs) = ScriptProvider::new(
        "A",
        vec![
            Event::TextDelta("half".into()),
            Event::Error("400 bad".into()),
        ],
    );
    let (b, b_invs) = ScriptProvider::new(
        "B",
        vec![Event::TextDelta("should-not-run".into()), Event::Done],
    );
    let mut router = ModelRouter::new();
    router.register(Box::new(a));
    router.register(Box::new(b));
    let eng = engine_with_defaults(router).with_retry(3, 0);

    let out = eng.run_turn_collect(&user(), &req()).await.unwrap();

    assert!(out.final_text.starts_with("half"));
    assert!(out
        .events
        .iter()
        .any(|e| matches!(e, Event::Error(m) if m.contains("400 bad"))));
    assert_eq!(
        a_invs.load(Ordering::SeqCst),
        1,
        "A runs once; no retry after producing output"
    );
    assert_eq!(
        b_invs.load(Ordering::SeqCst),
        0,
        "no failover after output already streamed"
    );
}

#[tokio::test]
async fn all_providers_failing_surfaces_a_single_error() {
    let (a, _) = ScriptProvider::new("A", vec![Event::Error("401 unauthorized".into())]);
    let mut router = ModelRouter::new();
    router.register(Box::new(a));
    let eng = engine_with_defaults(router).with_retry(0, 0);

    let out = eng.run_turn_collect(&user(), &req()).await.unwrap();

    assert!(out.final_text.is_empty());
    assert!(
        out.events
            .iter()
            .any(|e| matches!(e, Event::Error(m) if m.contains("all eligible providers failed"))),
        "exhausting the failover chain must surface a clear error"
    );
    assert!(out.events.contains(&Event::Done));
}

// ---------------------------------------------------------------------------
// Coverage hardening (from adversarial review of this change).
// ---------------------------------------------------------------------------

fn done_count(events: &[Event]) -> usize {
    events.iter().filter(|e| matches!(e, Event::Done)).count()
}

/// Always errors (retryable) — counts invocations; distinct id per instance.
struct AlwaysRetryableProvider {
    id: &'static str,
    invocations: Arc<AtomicUsize>,
}
impl Provider for AlwaysRetryableProvider {
    fn id(&self) -> &str {
        self.id
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, _prompt: &str) -> mpsc::Receiver<Event> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = mpsc::channel(8);
        tokio::spawn(async move {
            let _ = tx
                .send(Event::Error("503 service unavailable".into()))
                .await;
        });
        rx
    }
}

#[tokio::test]
async fn terminal_error_fails_over_without_retrying_even_with_retries_available() {
    // A errors with a TERMINAL (non-retryable) code, no output. Even with retries configured, a
    // Terminal classification must skip retry and fail over at once — pins the classifier branch.
    let (a, a_invs) = ScriptProvider::new("A", vec![Event::Error("401 unauthorized".into())]);
    let (b, b_invs) = ScriptProvider::new(
        "B",
        vec![Event::TextDelta("served-by-B".into()), Event::Done],
    );
    let mut router = ModelRouter::new();
    router.register(Box::new(a));
    router.register(Box::new(b));
    let eng = engine_with_defaults(router).with_retry(3, 0); // retries available on purpose

    let out = eng.run_turn_collect(&user(), &req()).await.unwrap();

    assert_eq!(out.provider, "B");
    assert_eq!(
        a_invs.load(Ordering::SeqCst),
        1,
        "a terminal error must NOT be retried"
    );
    assert_eq!(b_invs.load(Ordering::SeqCst), 1, "immediate failover to B");
}

#[tokio::test]
async fn retryable_exhausted_then_fails_over() {
    // A fails retryably on every attempt; after the retry budget is spent it fails over to B.
    let a_invs = Arc::new(AtomicUsize::new(0));
    let (b, b_invs) = ScriptProvider::new(
        "B",
        vec![Event::TextDelta("served-by-B".into()), Event::Done],
    );
    let mut router = ModelRouter::new();
    router.register(Box::new(AlwaysRetryableProvider {
        id: "A",
        invocations: a_invs.clone(),
    }));
    router.register(Box::new(b));
    let eng = engine_with_defaults(router).with_retry(2, 0);

    let out = eng.run_turn_collect(&user(), &req()).await.unwrap();

    assert_eq!(out.provider, "B");
    assert_eq!(
        a_invs.load(Ordering::SeqCst),
        3,
        "A tried initial + 2 retries before failover"
    );
    assert_eq!(b_invs.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn retry_count_is_bounded_by_config() {
    // Single always-failing provider: exactly initial + max_retries attempts, then a clear error.
    let invs = Arc::new(AtomicUsize::new(0));
    let mut router = ModelRouter::new();
    router.register(Box::new(AlwaysRetryableProvider {
        id: "only",
        invocations: invs.clone(),
    }));
    let eng = engine_with_defaults(router).with_retry(2, 0);

    let out = eng.run_turn_collect(&user(), &req()).await.unwrap();

    assert_eq!(
        invs.load(Ordering::SeqCst),
        3,
        "initial + exactly 2 retries — no more"
    );
    assert!(out
        .events
        .iter()
        .any(|e| matches!(e, Event::Error(m) if m.contains("all eligible providers failed"))));
}

#[tokio::test]
async fn forced_eligible_provider_that_errors_does_not_fail_over() {
    // A and B are BOTH eligible; the request pins A. A errors before output → NO failover to B.
    let (a, a_invs) = ScriptProvider::new("A", vec![Event::Error("503 unavailable".into())]);
    let (b, b_invs) = ScriptProvider::new(
        "B",
        vec![Event::TextDelta("served-by-B".into()), Event::Done],
    );
    let mut router = ModelRouter::new();
    router.register(Box::new(a));
    router.register(Box::new(b));
    let eng = engine_with_defaults(router).with_retry(0, 0);

    let mut r = req();
    r.forced_provider = Some("A".into());
    let out = eng.run_turn_collect(&user(), &r).await.unwrap();

    assert_eq!(
        a_invs.load(Ordering::SeqCst),
        1,
        "the forced provider is tried once"
    );
    assert_eq!(
        b_invs.load(Ordering::SeqCst),
        0,
        "a forced pin must NOT fail over to another provider"
    );
    assert_ne!(out.provider, "B");
    assert!(out.final_text.is_empty());
}

#[tokio::test]
async fn two_providers_all_failing_emit_exactly_one_error() {
    let (a, a_invs) = ScriptProvider::new("A", vec![Event::Error("503 unavailable".into())]);
    let (b, b_invs) = ScriptProvider::new("B", vec![Event::Error("502 bad gateway".into())]);
    let mut router = ModelRouter::new();
    router.register(Box::new(a));
    router.register(Box::new(b));
    let eng = engine_with_defaults(router).with_retry(0, 0);

    let out = eng.run_turn_collect(&user(), &req()).await.unwrap();

    assert_eq!(a_invs.load(Ordering::SeqCst), 1, "A tried");
    assert_eq!(b_invs.load(Ordering::SeqCst), 1, "then B tried");
    let errors: Vec<_> = out
        .events
        .iter()
        .filter(|e| matches!(e, Event::Error(_)))
        .collect();
    assert_eq!(
        errors.len(),
        1,
        "exactly ONE aggregated error, not one per provider"
    );
    assert!(matches!(errors[0], Event::Error(m) if m.contains("all eligible providers failed")));
    assert_eq!(done_count(&out.events), 1, "exactly one terminal Done");
}

/// A side-effecting tool that cancels the turn on its first execution (to exercise the
/// "no further tool dispatch after cancel" guard).
struct CancelOnRunTool {
    counter: Arc<AtomicUsize>,
    cancel: CancelToken,
}
impl Tool for CancelOnRunTool {
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
        if self.counter.fetch_add(1, Ordering::SeqCst) == 0 {
            self.cancel.cancel(); // user hits stop right after the first side effect
        }
        Ok(format!("settled:{args}"))
    }
}

/// Emits two DISTINCT side-effecting tool calls in one round, then Done.
struct TwoToolProvider;
impl Provider for TwoToolProvider {
    fn id(&self) -> &str {
        "twotool"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, _prompt: &str) -> mpsc::Receiver<Event> {
        let (tx, rx) = mpsc::channel(8);
        tokio::spawn(async move {
            let _ = tx
                .send(Event::ToolCallStart {
                    id: "t1".into(),
                    name: "settle".into(),
                    args: "a".into(),
                })
                .await;
            let _ = tx
                .send(Event::ToolCallStart {
                    id: "t2".into(),
                    name: "settle".into(),
                    args: "b".into(),
                })
                .await;
            let _ = tx.send(Event::Done).await;
        });
        rx
    }
}

#[tokio::test]
async fn cancel_during_tool_dispatch_skips_remaining_tools() {
    // Round completes cleanly with two tool calls; the first tool cancels → the second must NOT
    // dispatch (the "no further side effects after cancel" safety guard).
    let counter = Arc::new(AtomicUsize::new(0));
    let cancel = CancelToken::new();
    let mut router = ModelRouter::new();
    router.register(Box::new(TwoToolProvider));
    let mut tools = ToolRuntime::new(Box::new(InMemoryLedger::new()), Box::new(ManualReconciler));
    tools.register(Box::new(CancelOnRunTool {
        counter: counter.clone(),
        cancel: cancel.clone(),
    }));
    let eng = engine_with_defaults(router).with_tools(tools);

    let (tx, mut rx) = mpsc::channel(32);
    let _ = eng
        .run_turn_cancellable(&user(), &req(), tx, &cancel)
        .await
        .unwrap();
    let mut events = Vec::new();
    while let Some(e) = rx.recv().await {
        events.push(e);
    }

    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "the second side-effecting tool must NOT run after cancel"
    );
    assert!(events
        .iter()
        .any(|e| matches!(e, Event::Error(m) if m.contains("cancelled"))));
    assert!(!events
        .iter()
        .any(|e| matches!(e, Event::ToolResult { output, .. } if output.contains("settled:b"))));
    assert_eq!(done_count(&events), 1, "exactly one terminal Done");
}

#[tokio::test(start_paused = true)]
async fn backoff_delay_is_applied_between_retries() {
    // Flaky provider fails once (retryable) then succeeds; nonzero backoff must delay the retry.
    // Paused clock → the assertion on elapsed virtual time is deterministic.
    let invs = Arc::new(AtomicUsize::new(0));
    let mut router = ModelRouter::new();
    router.register(Box::new(FlakyProvider {
        invocations: invs.clone(),
        fail_n: 1,
    }));
    let eng = engine_with_defaults(router).with_retry(2, 100);

    let start = tokio::time::Instant::now();
    let out = eng.run_turn_collect(&user(), &req()).await.unwrap();
    let elapsed = start.elapsed();

    assert_eq!(out.final_text, "recovered");
    assert!(
        elapsed >= Duration::from_millis(100),
        "backoff must delay the retry (elapsed {elapsed:?})"
    );
}

#[tokio::test(start_paused = true)]
async fn cancel_during_retry_backoff_aborts_without_reinvoking() {
    // Provider always fails retryably; between attempts the engine backs off. A cancel during
    // that backoff must abort the turn WITHOUT re-invoking the provider (pins the raced-backoff).
    let invs = Arc::new(AtomicUsize::new(0));
    let errored = Arc::new(Notify::new());

    struct P {
        invs: Arc<AtomicUsize>,
        errored: Arc<Notify>,
    }
    impl Provider for P {
        fn id(&self) -> &str {
            "flaky"
        }
        fn eligible(&self, _dc: DataClass) -> bool {
            true
        }
        fn stream(&self, _prompt: &str) -> mpsc::Receiver<Event> {
            self.invs.fetch_add(1, Ordering::SeqCst);
            let errored = self.errored.clone();
            let (tx, rx) = mpsc::channel(8);
            tokio::spawn(async move {
                let _ = tx
                    .send(Event::Error("503 service unavailable".into()))
                    .await;
                errored.notify_one(); // signal that the (first) error has been emitted
            });
            rx
        }
    }

    let mut router = ModelRouter::new();
    router.register(Box::new(P {
        invs: invs.clone(),
        errored: errored.clone(),
    }));
    // Large backoff base; on a paused clock the sleep never elapses on its own, so the ONLY exit
    // from the backoff is the cancel branch.
    let eng = Arc::new(engine_with_defaults(router).with_retry(3, 5_000));

    let cancel = CancelToken::new();
    let (tx, mut rx) = mpsc::channel(16);
    let e2 = eng.clone();
    let c2 = cancel.clone();
    let handle = tokio::spawn(async move {
        let p = Principal::user("u", &["chat.send"]);
        let r = Request::chat("s", "t", "hi", DataClass::Public);
        e2.run_turn_cancellable(&p, &r, tx, &c2).await
    });

    errored.notified().await; // first error emitted → engine is entering the backoff
    cancel.cancel();

    let mut events = Vec::new();
    while let Some(e) = rx.recv().await {
        events.push(e);
    }
    let _ = handle.await.unwrap().unwrap();

    assert_eq!(
        invs.load(Ordering::SeqCst),
        1,
        "must NOT re-invoke the provider after cancel during backoff"
    );
    assert!(events
        .iter()
        .any(|e| matches!(e, Event::Error(m) if m.contains("cancelled"))));
    assert_eq!(done_count(&events), 1, "exactly one terminal Done");
}
