// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! Session Manager: N-session concurrency, serial-per-session, backpressure→503 (per-session +
//! global cap), idle reaping (bounded memory), and per-turn cancellation.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use ainxt_protocol::{Event, Request};
use ainxt_runtime::provider::Provider;
use ainxt_runtime::router::ModelRouter;
use ainxt_runtime::{engine_with_defaults, Engine, TurnError};
use ainxt_session::{SessionConfig, SessionManager, SubmitError};
use ainxt_types::{DataClass, Principal};
use tokio::sync::{mpsc, Barrier};

/// Records each prompt it is asked to serve (to observe ordering), then completes quickly.
struct RecordingProvider {
    seen: Arc<Mutex<Vec<String>>>,
}
impl Provider for RecordingProvider {
    fn id(&self) -> &str {
        "rec"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, prompt: &str) -> mpsc::Receiver<Event> {
        self.seen.lock().unwrap().push(prompt.to_string());
        let (tx, rx) = mpsc::channel(8);
        tokio::spawn(async move {
            let _ = tx.send(Event::TextDelta("ok".into())).await;
            let _ = tx.send(Event::Done).await;
        });
        rx
    }
}

/// Never produces output — its turn hangs until cancelled (to occupy a session actor).
struct BlockProvider;
impl Provider for BlockProvider {
    fn id(&self) -> &str {
        "block"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, _prompt: &str) -> mpsc::Receiver<Event> {
        let (tx, rx) = mpsc::channel(8);
        tokio::spawn(async move {
            let _hold = tx; // keep the sender alive so rx never closes
            std::future::pending::<()>().await; // never sends; the turn blocks until cancel
        });
        rx
    }
}

fn engine_rec(seen: Arc<Mutex<Vec<String>>>) -> Arc<Engine> {
    let mut router = ModelRouter::new();
    router.register(Box::new(RecordingProvider { seen }));
    Arc::new(engine_with_defaults(router))
}
fn engine_block() -> Arc<Engine> {
    let mut router = ModelRouter::new();
    router.register(Box::new(BlockProvider));
    Arc::new(engine_with_defaults(router))
}
fn user() -> Principal {
    Principal::user("u", &["chat.send"])
}
fn req(session: &str, input: &str) -> Request {
    Request::chat(session, "t", input, DataClass::Public)
}
fn sink() -> (mpsc::Sender<Event>, mpsc::Receiver<Event>) {
    mpsc::channel(16)
}

#[tokio::test]
async fn many_sessions_run_concurrently() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let mgr = SessionManager::new(engine_rec(seen.clone()), SessionConfig::default());

    let mut tickets = Vec::new();
    let mut _rxs = Vec::new();
    for i in 0..50 {
        let (tx, rx) = sink();
        _rxs.push(rx);
        tickets.push(mgr.submit(user(), req(&format!("s{i}"), "hi"), tx).unwrap());
    }
    for t in tickets {
        let r = t.join().await.expect("turn not dropped");
        assert!(r.is_ok(), "each concurrent session's turn completes");
    }
    assert_eq!(
        seen.lock().unwrap().len(),
        50,
        "all 50 sessions were served"
    );
}

#[tokio::test]
async fn turns_in_one_session_run_serially_in_order() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let mgr = SessionManager::new(engine_rec(seen.clone()), SessionConfig::default());

    let (tx1, _r1) = sink();
    let t1 = mgr.submit(user(), req("s", "first"), tx1).unwrap();
    let (tx2, _r2) = sink();
    let t2 = mgr.submit(user(), req("s", "second"), tx2).unwrap();

    let _ = t1.join().await.unwrap();
    let _ = t2.join().await.unwrap();

    assert_eq!(
        *seen.lock().unwrap(),
        vec!["first".to_string(), "second".to_string()],
        "a session's turns are processed serially, in submission order"
    );
}

#[tokio::test]
async fn a_full_session_inbox_backpressures() {
    // A blocked actor never drains its inbox; once full, submit must backpressure (→ 503).
    let cfg = SessionConfig {
        inbox_capacity: 2,
        ..Default::default()
    };
    let mgr = SessionManager::new(engine_block(), cfg);

    let mut backpressured = false;
    let mut _rxs = Vec::new();
    let mut _tickets = Vec::new();
    for _ in 0..6 {
        let (tx, rx) = sink();
        _rxs.push(rx);
        match mgr.submit(user(), req("s", "hi"), tx) {
            Ok(t) => _tickets.push(t),
            Err(SubmitError::Backpressure(_)) => {
                backpressured = true;
                break;
            }
        }
    }
    assert!(
        backpressured,
        "a full session inbox must backpressure, never grow unbounded"
    );
}

#[tokio::test]
async fn the_global_session_cap_backpressures_new_sessions() {
    let cfg = SessionConfig {
        max_sessions: 1,
        ..Default::default()
    };
    let mgr = SessionManager::new(engine_block(), cfg);

    let (tx_a, _ra) = sink();
    let _a = mgr.submit(user(), req("A", "hi"), tx_a).unwrap(); // session A occupies the one slot
    assert_eq!(mgr.live_sessions(), 1);

    let (tx_b, _rb) = sink();
    match mgr.submit(user(), req("B", "hi"), tx_b) {
        Err(SubmitError::Backpressure(_)) => {}
        Ok(_) => panic!("a new session past the cap must backpressure"),
    }
}

#[tokio::test(start_paused = true)]
async fn an_idle_session_actor_is_reaped() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let cfg = SessionConfig {
        idle_ttl_ms: 1000,
        ..Default::default()
    };
    let mgr = SessionManager::new(engine_rec(seen), cfg);

    let (tx, _r) = sink();
    let t = mgr.submit(user(), req("s", "hi"), tx).unwrap();
    let _ = t.join().await.unwrap();
    assert_eq!(mgr.live_sessions(), 1, "session is live right after a turn");

    // Advance past the idle TTL; the actor should reap itself (bounded memory).
    tokio::time::advance(Duration::from_millis(1500)).await;
    for _ in 0..5 {
        tokio::task::yield_now().await;
    }
    assert_eq!(mgr.live_sessions(), 0, "an idle session actor reaps itself");
}

#[tokio::test]
async fn a_turn_can_be_cancelled_via_its_ticket() {
    let mgr = SessionManager::new(engine_block(), SessionConfig::default());
    let (tx, _r) = sink();
    let t = mgr.submit(user(), req("s", "hi"), tx).unwrap();

    tokio::task::yield_now().await; // let the actor start the (blocking) turn
    t.cancel.cancel();

    let summary = t.join().await.expect("not dropped").expect("turn ok");
    assert_eq!(
        summary.provider, "cancelled",
        "cancelling the ticket ends the in-flight turn"
    );
}

#[tokio::test(start_paused = true)]
async fn a_reaped_session_is_recreated_on_resubmit() {
    // Actually reap between the two turns, then prove the same session id transparently spawns a
    // fresh actor (exercises the recreate path, not just idle resubmission).
    let seen = Arc::new(Mutex::new(Vec::new()));
    let cfg = SessionConfig {
        idle_ttl_ms: 1000,
        ..Default::default()
    };
    let mgr = SessionManager::new(engine_rec(seen.clone()), cfg);

    let (tx1, _r1) = sink();
    let _ = mgr
        .submit(user(), req("s", "a"), tx1)
        .unwrap()
        .join()
        .await
        .unwrap();
    tokio::time::advance(Duration::from_millis(1500)).await;
    for _ in 0..5 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        mgr.live_sessions(),
        0,
        "the session is actually reaped first"
    );

    let (tx2, _r2) = sink();
    let _ = mgr
        .submit(user(), req("s", "b"), tx2)
        .unwrap()
        .join()
        .await
        .unwrap();
    assert_eq!(
        seen.lock().unwrap().clone(),
        vec!["a".to_string(), "b".to_string()]
    );
    assert_eq!(
        mgr.live_sessions(),
        1,
        "a fresh actor was created for the recreated session"
    );
}

// ---------------------------------------------------------------------------
// Hardening from the adversarial review of this change.
// ---------------------------------------------------------------------------

#[test]
fn session_config_validate_rejects_degenerate_values() {
    assert!(SessionConfig {
        inbox_capacity: 0,
        ..Default::default()
    }
    .validate()
    .is_err());
    assert!(SessionConfig {
        max_sessions: 0,
        ..Default::default()
    }
    .validate()
    .is_err());
    assert!(SessionConfig::default().validate().is_ok());
}

#[tokio::test]
async fn a_degenerate_config_is_clamped_and_never_panics() {
    // inbox_capacity=0 must NOT reach mpsc::channel(0) (which panics under the lock → poison).
    let seen = Arc::new(Mutex::new(Vec::new()));
    let cfg = SessionConfig {
        inbox_capacity: 0,
        max_sessions: 0,
        ..Default::default()
    };
    let mgr = SessionManager::new(engine_rec(seen), cfg);
    let (tx, _r) = sink();
    let t = mgr.submit(user(), req("s", "hi"), tx).unwrap(); // clamped to 1 → works, no panic
    assert!(t.join().await.unwrap().is_ok());
}

/// Its `stream` panics — to prove a panicking turn is isolated, not fatal to the actor.
struct PanicProvider;
impl Provider for PanicProvider {
    fn id(&self) -> &str {
        "panic"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, _prompt: &str) -> mpsc::Receiver<Event> {
        panic!("boom in the provider");
    }
}

#[tokio::test]
async fn a_panicking_turn_is_isolated_and_does_not_orphan_the_actor() {
    let mut router = ModelRouter::new();
    router.register(Box::new(PanicProvider));
    let mgr = SessionManager::new(
        Arc::new(engine_with_defaults(router)),
        SessionConfig::default(),
    );

    let (tx, _r) = sink();
    let res = mgr
        .submit(user(), req("s", "hi"), tx)
        .unwrap()
        .join()
        .await
        .expect("not dropped");
    assert!(
        matches!(res, Err(TurnError::Internal(_))),
        "a panicking turn surfaces as an internal error"
    );
    assert_eq!(
        mgr.live_sessions(),
        1,
        "the actor survives the panic — its entry is not orphaned"
    );
}

#[tokio::test(start_paused = true)]
async fn a_hung_turn_is_bounded_by_the_turn_timeout() {
    let cfg = SessionConfig {
        turn_timeout_ms: 1000,
        ..Default::default()
    };
    let mgr = SessionManager::new(engine_block(), cfg);
    let (tx, _r) = sink();
    let t = mgr.submit(user(), req("s", "hi"), tx).unwrap();

    tokio::task::yield_now().await; // let the turn start (and hang)
    tokio::time::advance(Duration::from_millis(1500)).await;

    let res = t.join().await.expect("not dropped");
    assert!(
        matches!(res, Err(TurnError::Internal(m)) if m.contains("timed out")),
        "a hung turn is force-aborted by the per-turn timeout"
    );
}

/// Records start/end markers around a small delay, to expose any interleaving within a session.
struct OrderProvider {
    log: Arc<Mutex<Vec<String>>>,
}
impl Provider for OrderProvider {
    fn id(&self) -> &str {
        "order"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, prompt: &str) -> mpsc::Receiver<Event> {
        self.log.lock().unwrap().push(format!("start:{prompt}"));
        let log = self.log.clone();
        let p = prompt.to_string();
        let (tx, rx) = mpsc::channel(8);
        tokio::spawn(async move {
            for _ in 0..3 {
                tokio::task::yield_now().await; // a window in which an interleaved turn would show
            }
            log.lock().unwrap().push(format!("end:{p}"));
            let _ = tx.send(Event::Done).await;
        });
        rx
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn turns_are_serial_within_a_session_under_real_concurrency() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let mut router = ModelRouter::new();
    router.register(Box::new(OrderProvider { log: log.clone() }));
    let mgr = SessionManager::new(
        Arc::new(engine_with_defaults(router)),
        SessionConfig::default(),
    );

    let (tx1, _r1) = sink();
    let t1 = mgr.submit(user(), req("s", "a"), tx1).unwrap();
    let (tx2, _r2) = sink();
    let t2 = mgr.submit(user(), req("s", "b"), tx2).unwrap();
    let _ = t1.join().await.unwrap();
    let _ = t2.join().await.unwrap();

    // Serial ⇒ a fully completes (start:a..end:a) before b starts — no interleaving.
    assert_eq!(
        log.lock().unwrap().clone(),
        vec!["start:a", "end:a", "start:b", "end:b"],
        "a session's turns must not interleave, even under a multi-threaded runtime"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn load_many_sessions_all_complete() {
    // Scaled load proof: 1500 distinct sessions each run a turn to completion concurrently. (A
    // sustained 2000+ req/s soak needs the GPU/infra box — see the DoD note.)
    const N: usize = 1500;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let mgr = SessionManager::new(engine_rec(seen.clone()), SessionConfig::default());

    let mut tickets = Vec::with_capacity(N);
    for i in 0..N {
        let (tx, rx) = sink();
        drop(rx); // fast provider; the turn still completes if the client isn't draining
        tickets.push(mgr.submit(user(), req(&format!("s{i}"), "hi"), tx).unwrap());
    }
    for t in tickets {
        assert!(t.join().await.expect("not dropped").is_ok());
    }
    assert_eq!(
        seen.lock().unwrap().len(),
        N,
        "every one of {N} sessions was served"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admission_control_holds_at_the_global_cap_under_a_burst() {
    // A burst of distinct sessions past the cap must 503 (bounded memory), not OOM.
    const CAP: usize = 200;
    let cfg = SessionConfig {
        max_sessions: CAP,
        ..Default::default()
    };
    let mgr = SessionManager::new(engine_block(), cfg); // turns hang → sessions stay live
    let mut accepted = 0usize;
    let mut rejected = 0usize;
    let mut _rxs = Vec::new();
    let mut _tickets = Vec::new();
    for i in 0..(CAP * 2) {
        let (tx, rx) = sink();
        _rxs.push(rx);
        match mgr.submit(user(), req(&format!("s{i}"), "hi"), tx) {
            Ok(t) => {
                accepted += 1;
                _tickets.push(t);
            }
            Err(SubmitError::Backpressure(_)) => rejected += 1,
        }
    }
    assert_eq!(
        accepted, CAP,
        "exactly the cap of distinct sessions is admitted"
    );
    assert_eq!(rejected, CAP, "the rest are shed with backpressure (503)");
    assert!(
        mgr.live_sessions() <= CAP,
        "live sessions never exceed the cap (bounded memory)"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn distinct_sessions_run_concurrently() {
    const N: usize = 4;
    // Each turn waits on a shared barrier; the turns can only all complete if they run CONCURRENTLY
    // (a serial-across-sessions manager would deadlock — caught by the outer timeout).
    let barrier = Arc::new(Barrier::new(N));

    struct BarrierProvider {
        barrier: Arc<Barrier>,
    }
    impl Provider for BarrierProvider {
        fn id(&self) -> &str {
            "barrier"
        }
        fn eligible(&self, _dc: DataClass) -> bool {
            true
        }
        fn stream(&self, _prompt: &str) -> mpsc::Receiver<Event> {
            let barrier = self.barrier.clone();
            let (tx, rx) = mpsc::channel(8);
            tokio::spawn(async move {
                barrier.wait().await; // all N must arrive → proves concurrency
                let _ = tx.send(Event::Done).await;
            });
            rx
        }
    }

    let mut router = ModelRouter::new();
    router.register(Box::new(BarrierProvider { barrier }));
    let mgr = SessionManager::new(
        Arc::new(engine_with_defaults(router)),
        SessionConfig::default(),
    );

    let mut tickets = Vec::new();
    let mut _rxs = Vec::new();
    for i in 0..N {
        let (tx, rx) = sink();
        _rxs.push(rx);
        tickets.push(mgr.submit(user(), req(&format!("s{i}"), "hi"), tx).unwrap());
    }
    let joined = tokio::time::timeout(Duration::from_secs(5), async {
        for t in tickets {
            let _ = t.join().await.unwrap();
        }
    })
    .await;
    assert!(
        joined.is_ok(),
        "distinct sessions must run concurrently (a barrier of {N} released)"
    );
}

// ============================ TURN-05 / SURF-11 wiring proofs ============================
// The reconnect/turn-tree code (SessionManager::resume + apply_interaction) landed without tests
// (the authoring agent stalled before writing them). These prove the wired behavior end-to-end on
// the real SessionManager.

use ainxt_protocol::{Command, EventEnvelope, Participant, SessionTree, WireEvent};
use ainxt_replay::{EventKind, LinearRecord, TurnRole};
use ainxt_session::{ResumeError, SnapshotState};

fn snap_state(participants: &[&str]) -> SnapshotState {
    SnapshotState {
        tree: SessionTree { turns: vec![] },
        active_head: None,
        participants: participants
            .iter()
            .map(|p| Participant {
                participant_id: (*p).into(),
                display_name: None,
            })
            .collect(),
        negotiated_version: "1.0".into(),
        control_plane_sha: "sha".into(),
        ts: "2026-07-22T00:00:00Z".into(),
    }
}

fn env(seq: u64) -> EventEnvelope {
    EventEnvelope {
        v: "1.0".into(),
        session_id: "s1".into(),
        turn_id: None,
        program_id: None,
        seq,
        ts: "2026-07-22T00:00:00Z".into(),
        control_plane_sha: "sha".into(),
        event: WireEvent::TextDelta {
            text: format!("d{seq}"),
        },
    }
}

#[tokio::test]
async fn wire2_turn_05_resume_replays_only_the_tail_after_the_cursor() {
    let mgr = SessionManager::new(
        engine_rec(Arc::new(Mutex::new(vec![]))),
        SessionConfig::default(),
    );
    let alice = Principal::user("alice", &["chat.send"]);
    let log = vec![env(1), env(2), env(3)];
    let cmd = Command::SessionResume {
        session_id: "s1".into(),
        from_event: Some(1),
    };
    let (tx, mut rx) = mpsc::channel(16);
    let outcome = mgr
        .resume(&alice, &cmd, snap_state(&["alice"]), &log, &tx)
        .await
        .expect("participant resume must succeed");
    assert!(
        outcome.actor_rebuilt,
        "cold-start resume must (re)build the actor"
    );
    assert_eq!(outcome.replayed, 2, "only seq>from_event(1) is replayed");
    assert_eq!(
        outcome.new_cursor, 3,
        "cursor advances to the last replayed seq"
    );
    // Snapshot first, pinned at the cursor; then the tail strictly ascending behind it.
    let first = rx.recv().await.expect("snapshot");
    assert!(
        matches!(first.event, WireEvent::SessionSnapshot { .. }),
        "resume must send session.snapshot first"
    );
    assert_eq!(first.seq, 1, "snapshot pinned at the client cursor");
    let a = rx.recv().await.expect("tail 1");
    let b = rx.recv().await.expect("tail 2");
    assert_eq!(
        (a.seq, b.seq),
        (2, 3),
        "tail replayed in ascending seq order"
    );
    assert!(rx.try_recv().is_err(), "nothing beyond the tail is sent");
}

#[tokio::test]
async fn wire2_turn_05_resume_refuses_a_non_participant() {
    let mgr = SessionManager::new(
        engine_rec(Arc::new(Mutex::new(vec![]))),
        SessionConfig::default(),
    );
    let mallory = Principal::user("mallory", &["chat.send"]);
    let cmd = Command::SessionResume {
        session_id: "s1".into(),
        from_event: None,
    };
    let (tx, _rx) = mpsc::channel(16);
    let err = mgr
        .resume(&mallory, &cmd, snap_state(&["alice"]), &[], &tx)
        .await
        .expect_err("a non-participant must not re-attach");
    assert!(matches!(err, ResumeError::NotAuthorized), "got {err:?}");
}

#[test]
fn wire2_surf_11_branch_forks_without_mutating_history() {
    let mgr = SessionManager::new(
        engine_rec(Arc::new(Mutex::new(vec![]))),
        SessionConfig::default(),
    );
    let alice = Principal::user("alice", &["chat.send"]);
    let rec = |kind, role, text: &str| LinearRecord {
        kind,
        role,
        author: "alice".into(),
        data_class: DataClass::Internal,
        text: text.into(),
        ts_millis: 1,
    };
    // Linear log → tree turns t0 (user), t1 (assistant).
    let log = vec![
        rec(EventKind::TurnStart, TurnRole::User, "q1"),
        rec(EventKind::TurnStart, TurnRole::Assistant, "a1"),
    ];
    let cmd = Command::TurnBranch {
        from_turn_id: "t0".into(),
        label: Some("alt".into()),
    };
    let out = mgr
        .apply_interaction(&alice, "s1", &["alice"], &log, &cmd, "t2", 42)
        .expect("participant branch must succeed");
    assert_eq!(
        out.new_turn_id.as_deref(),
        Some("t2"),
        "branch mints the new turn"
    );
    assert_eq!(
        out.turn_count, 3,
        "2 original turns are preserved + 1 branch (history never mutated)"
    );
    assert!(
        !out.appended_events.is_empty(),
        "the branch appends events for the caller to persist"
    );
}

// ---------------------------------------------------------------------------------------------
// A turn that dies must still terminate the caller's stream.
//
// Isolating a panicking turn so it cannot kill the session actor is correct. DISCARDING it was
// not: the sink is MOVED into the handler, so a panic dropped it, which the HTTP layer renders as a
// completed SSE stream carrying ZERO bytes — `200 OK`, correct content-type, no events, nothing in
// the log. A caller cannot distinguish that from a successful empty answer, cannot retry it and
// cannot report it. Same for a turn that times out.
// ---------------------------------------------------------------------------------------------

/// Panics the moment the engine asks it to stream — i.e. inside `handle_turn`, under the
/// session actor's `catch_unwind`.
struct PanickingProvider;
impl Provider for PanickingProvider {
    fn id(&self) -> &str {
        "panic"
    }
    fn eligible(&self, _dc: DataClass) -> bool {
        true
    }
    fn stream(&self, _prompt: &str) -> mpsc::Receiver<Event> {
        panic!("provider exploded");
    }
}

fn engine_panicking() -> Arc<Engine> {
    let mut router = ModelRouter::new();
    router.register(Box::new(PanickingProvider));
    Arc::new(engine_with_defaults(router))
}

#[tokio::test]
async fn a_panicking_turn_still_terminates_the_callers_stream() {
    let mgr = SessionManager::new(engine_panicking(), SessionConfig::default());
    let (tx, mut rx) = sink();
    let ticket = mgr.submit(user(), req("s-panic", "hi"), tx).unwrap();

    let res = ticket.join().await.expect("completion signal not dropped");
    assert!(
        matches!(res, Err(TurnError::Internal(ref m)) if m.contains("panicked")),
        "the supervising layer reports the panic as an internal turn error: {res:?}"
    );

    // The part that matters: the CALLER was told. Before the fix this channel yielded nothing.
    let mut events = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        events.push(ev);
    }
    assert!(
        !events.is_empty(),
        "a panicking turn must not leave the caller with an empty stream"
    );
    let err = events.iter().find_map(|e| match e {
        Event::Error(m) => Some(m.clone()),
        _ => None,
    });
    let err = err.expect("an Event::Error must reach the caller");
    assert!(
        err.contains("panicked"),
        "the error names the cause so it is diagnosable: {err}"
    );
    assert!(
        err.contains("provider exploded"),
        "the panic PAYLOAD is preserved, not discarded — this is the only pointer to the real \
         defect: {err}"
    );
    assert!(
        events.iter().any(|e| matches!(e, Event::Done)),
        "the stream is terminated, not left open: {events:?}"
    );
}

#[tokio::test]
async fn a_timed_out_turn_still_terminates_the_callers_stream() {
    // BlockProvider never sends, so the turn is killed by the turn timeout.
    let mut router = ModelRouter::new();
    router.register(Box::new(BlockProvider));
    let cfg = SessionConfig {
        turn_timeout_ms: 50,
        ..SessionConfig::default()
    };
    let mgr = SessionManager::new(Arc::new(engine_with_defaults(router)), cfg);
    let (tx, mut rx) = sink();
    let ticket = mgr.submit(user(), req("s-timeout", "hi"), tx).unwrap();

    let res = ticket.join().await.expect("completion signal not dropped");
    assert!(
        matches!(res, Err(TurnError::Internal(ref m)) if m.contains("timed out")),
        "a timed-out turn is reported as an internal turn error: {res:?}"
    );

    let mut events = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        events.push(ev);
    }
    assert!(
        events.iter().any(|e| matches!(e, Event::Error(m) if m.contains("timed out"))),
        "the caller is told the turn timed out, not left with an empty stream: {events:?}"
    );
    assert!(
        events.iter().any(|e| matches!(e, Event::Done)),
        "the stream is terminated: {events:?}"
    );
}
