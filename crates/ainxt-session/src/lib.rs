// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! ainxt-session — the Session Manager: the concurrency spine above the [`Engine`].
//!
//! Convergent vendor pattern (VENDOR_SYNTHESIS §): **actor-per-session + bounded channels +
//! per-turn cancellation**. Each session is an actor task owning a bounded inbox; it processes its
//! turns **serially** (no interleaved mutation of one session's state) by calling
//! [`Engine::run_turn_cancellable`]. Many sessions run concurrently.
//!
//! Enterprise invariants (design-for-failure, A3):
//! * **Backpressure → 503**: a full per-session inbox, or the global session cap, makes `submit`
//!   return [`SubmitError::Backpressure`] (never blocks, never grows unbounded). The transport
//!   maps that to HTTP 503.
//! * **Bounded memory**: bounded inboxes + a global session cap + **idle self-reaping** (an actor
//!   that sees no turn for `idle_ttl` removes itself) mean live state can never grow without
//!   bound — the memory-leak class of bug is structurally impossible.
//! * **Serial per session, concurrent across sessions.** Cancellation is per turn.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ainxt_protocol::{
    replay_tail, Command, Event, EventEnvelope, Participant, Request, SessionTree, WireEvent,
};
use ainxt_replay::{LinearRecord, ReplayEvent, SessionRecording, SteerDelivery, TreeError};
use ainxt_runtime::{CancelToken, TurnError, TurnHandler, TurnSummary};
use ainxt_types::{DataClass, Principal, Role};
use serde::Deserialize;
use tokio::sync::{mpsc, oneshot};

// Re-export the interaction-tree vocabulary a caller needs to drive [`SessionManager::apply_interaction`]
// and interpret its result, so a renderer/server need not also depend on `ainxt-replay` directly.
pub use ainxt_replay::{EventKind as ReplayEventKind, TurnRole};

fn default_max_sessions() -> usize {
    4096
}
fn default_inbox_capacity() -> usize {
    8
}
fn default_idle_ttl_ms() -> u64 {
    300_000 // 5 min
}
fn default_turn_timeout_ms() -> u64 {
    300_000 // 5 min — a hard ceiling so a hung turn can never pin an actor forever
}

/// Session-manager limits (config-first). All bounded — there is no "unbounded" setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionConfig {
    /// Global cap on concurrently-live sessions (memory bound + admission control).
    #[serde(default = "default_max_sessions")]
    pub max_sessions: usize,
    /// Per-session inbox capacity; a full inbox is backpressure.
    #[serde(default = "default_inbox_capacity")]
    pub inbox_capacity: usize,
    /// Reap a session actor that has seen no turn for this long (bounds idle memory).
    #[serde(default = "default_idle_ttl_ms")]
    pub idle_ttl_ms: u64,
    /// Hard wall-clock ceiling on a single turn; on expiry the turn is aborted (its resources
    /// freed) and the actor returns to reaping — so a hung/stalled turn cannot pin an actor or
    /// leak its session slot.
    #[serde(default = "default_turn_timeout_ms")]
    pub turn_timeout_ms: u64,
}

impl Default for SessionConfig {
    fn default() -> Self {
        SessionConfig {
            max_sessions: default_max_sessions(),
            inbox_capacity: default_inbox_capacity(),
            idle_ttl_ms: default_idle_ttl_ms(),
            turn_timeout_ms: default_turn_timeout_ms(),
        }
    }
}

impl SessionConfig {
    /// Validate the limits (call at config-load for a fail-fast, clear error). `max_sessions` and
    /// `inbox_capacity` must be >= 1 (a 0 inbox would make the bounded channel panic; a 0 session
    /// cap would reject every request).
    pub fn validate(&self) -> Result<(), String> {
        if self.max_sessions < 1 {
            return Err("session.max_sessions must be >= 1".into());
        }
        if self.inbox_capacity < 1 {
            return Err("session.inbox_capacity must be >= 1".into());
        }
        Ok(())
    }

    /// Clamp to safe minimums (defense in depth so no path can ever create a `channel(0)`).
    fn sanitized(mut self) -> Self {
        self.max_sessions = self.max_sessions.max(1);
        self.inbox_capacity = self.inbox_capacity.max(1);
        self
    }
}

/// Why a `submit` was rejected without running.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmitError {
    /// Back-pressure — a full session inbox or the global session cap. Map to HTTP 503.
    Backpressure(String),
}

/// Why a [`SessionManager::revoke`] could not run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevokeError {
    /// No live actor exists for this session id (already ended, idle-reaped, or never started).
    NotFound,
}

impl std::fmt::Display for RevokeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RevokeError::NotFound => write!(f, "no live session to revoke"),
        }
    }
}

impl std::error::Error for RevokeError {}

/// A handle to a submitted turn: cancel it, and await its summary.
pub struct TurnTicket {
    pub cancel: CancelToken,
    done: oneshot::Receiver<Result<TurnSummary, TurnError>>,
}

impl TurnTicket {
    /// Await the turn's summary. `Err(())` means the turn was dropped before completing (e.g. its
    /// session actor was reaped mid-flight) — a rare, observable degradation, never a hang.
    pub async fn join(self) -> Result<Result<TurnSummary, TurnError>, ()> {
        self.done.await.map_err(|_| ())
    }
}

struct Job {
    principal: Principal,
    request: Request,
    sink: mpsc::Sender<Event>,
    cancel: CancelToken,
    done: oneshot::Sender<Result<TurnSummary, TurnError>>,
}

type Sessions = Arc<Mutex<HashMap<String, mpsc::Sender<Job>>>>;

/// The currently in-flight turn per session and its live cancel token. Turns run **serially per
/// session**, so at most one entry per session id — bounded by the live-session count, and cleared
/// the instant a turn ends (see [`process`]). This is what lets an out-of-band `turn.stop` (SURF-11)
/// fire the running turn's token: the durable tree records the terminal state, this fires the live
/// cancellation.
type Cancels = Arc<Mutex<HashMap<String, (String, CancelToken)>>>;

/// Routes turns to per-session actors with bounded inboxes, a global cap, and idle reaping.
pub struct SessionManager {
    handler: Arc<dyn TurnHandler>,
    cfg: SessionConfig,
    sessions: Sessions,
    cancels: Cancels,
}

impl SessionManager {
    /// Build a manager. The config is clamped to safe minimums (see [`SessionConfig::validate`]
    /// to reject bad values at load instead) so no path can ever create a zero-capacity channel.
    /// Build a manager over any [`TurnHandler`]. An `Arc<Engine>` coerces here (the bare-engine
    /// surface); an `Arc<ChatHandler>` gives the full Chat intelligence — same spine, either way.
    pub fn new(handler: Arc<dyn TurnHandler>, cfg: SessionConfig) -> Self {
        SessionManager {
            handler,
            cfg: cfg.sanitized(),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            cancels: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Number of currently-live session actors (for observability / tests).
    pub fn live_sessions(&self) -> usize {
        self.sessions.lock().expect("sessions lock").len()
    }

    /// **SEC-F-005 — immediate, on-demand session termination.** Until now the only way a session
    /// ever ended was sitting idle for `idle_ttl_ms` and being self-reaped; there was no way to end
    /// one right now (e.g. a stolen device is reported, or an operator spots suspicious activity).
    /// This fires any in-flight turn's cancel token (same effect a `turn.stop` has on the running
    /// turn) and removes the session's actor from the live map, so any subsequent event for
    /// `session_id` finds no live actor and — via [`resume`](SessionManager::resume)'s existing
    /// [`ensure_actor`](SessionManager::ensure_actor) cold-start path — gets a *fresh* session, not
    /// the revoked one. Returns [`RevokeError::NotFound`] if the session has no live actor (already
    /// ended, idle-reaped, or never started) — revoking an absent session is a documented no-op
    /// class of error, not a panic.
    pub fn revoke(&self, session_id: &str) -> Result<(), RevokeError> {
        // Fire any in-flight turn's cancel token first, mirroring the `Command::TurnStop` handling
        // in `apply_interaction` exactly (same lock, same lookup, same `tok.cancel()` call).
        {
            let reg = self.cancels.lock().expect("cancels lock");
            if let Some((_turn_id, tok)) = reg.get(session_id) {
                tok.cancel();
            }
        }
        // Then drop the actor's inbox sender from the live-session map under the SAME lock
        // `submit`'s get-or-create and the actor's own idle-reap self-removal use, so this can
        // never race either of them into a lost job or a double-remove.
        let mut sessions = self.sessions.lock().expect("sessions lock");
        if sessions.remove(session_id).is_none() {
            return Err(RevokeError::NotFound);
        }
        Ok(())
    }

    /// Enqueue a turn for its session (from `request.session`), spawning the session actor on
    /// first use. Non-blocking: returns immediately with a [`TurnTicket`], or
    /// [`SubmitError::Backpressure`] if the inbox is full or the global cap is reached. The caller
    /// streams events from the `sink` receiver it owns.
    pub fn submit(
        &self,
        principal: Principal,
        request: Request,
        sink: mpsc::Sender<Event>,
    ) -> Result<TurnTicket, SubmitError> {
        let session_id = request.session.clone();
        let cancel = CancelToken::new();
        let (done_tx, done_rx) = oneshot::channel();
        let mut job = Job {
            principal,
            request,
            sink,
            cancel: cancel.clone(),
            done: done_tx,
        };

        // The whole get-or-create-then-send runs under the lock, so it cannot race a reaping
        // actor (which also removes itself under the lock): either we find a live inbox, or we
        // create a fresh one — a job is never sent into a channel that is about to be dropped.
        let mut sessions = self.sessions.lock().expect("sessions lock");
        loop {
            if let Some(tx) = sessions.get(&session_id) {
                match tx.try_send(job) {
                    Ok(()) => {
                        return Ok(TurnTicket {
                            cancel,
                            done: done_rx,
                        })
                    }
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        return Err(SubmitError::Backpressure(format!(
                            "session '{session_id}' inbox full ({})",
                            self.cfg.inbox_capacity
                        )));
                    }
                    Err(mpsc::error::TrySendError::Closed(returned)) => {
                        // The actor exited between insert and send; drop the stale entry and
                        // recreate below.
                        sessions.remove(&session_id);
                        job = returned;
                    }
                }
            } else {
                if sessions.len() >= self.cfg.max_sessions {
                    return Err(SubmitError::Backpressure(format!(
                        "at max sessions ({})",
                        self.cfg.max_sessions
                    )));
                }
                let tx = self.spawn_actor(session_id.clone());
                sessions.insert(session_id.clone(), tx);
                // loop back to send into the freshly-created inbox
            }
        }
    }

    /// Spawn a fresh session actor and return its inbox sender. Does NOT touch the `sessions` map —
    /// the caller inserts under its held lock (so this is safe to call while holding it; `spawn` is
    /// non-blocking and never locks `sessions`).
    fn spawn_actor(&self, session_id: String) -> mpsc::Sender<Job> {
        let (tx, rx) = mpsc::channel::<Job>(self.cfg.inbox_capacity);
        let handler = self.handler.clone();
        let sessions_ref = self.sessions.clone();
        let cancels = self.cancels.clone();
        let idle = Duration::from_millis(self.cfg.idle_ttl_ms);
        let turn_timeout = Duration::from_millis(self.cfg.turn_timeout_ms);
        tokio::spawn(async move {
            run_actor(
                handler,
                rx,
                sessions_ref,
                cancels,
                session_id,
                idle,
                turn_timeout,
            )
            .await
        });
        tx
    }

    /// Ensure a live actor exists for `session_id`, (re)spawning one if absent — the cold-start-safe
    /// re-attach a `session.resume` needs after the previous actor was idle-reaped (TURN-05). Returns
    /// `true` iff it had to build a new actor. Honors the global session cap (503 on overflow).
    fn ensure_actor(&self, session_id: &str) -> Result<bool, SubmitError> {
        let mut sessions = self.sessions.lock().expect("sessions lock");
        if sessions.contains_key(session_id) {
            return Ok(false);
        }
        if sessions.len() >= self.cfg.max_sessions {
            return Err(SubmitError::Backpressure(format!(
                "at max sessions ({})",
                self.cfg.max_sessions
            )));
        }
        let tx = self.spawn_actor(session_id.to_string());
        sessions.insert(session_id.to_string(), tx);
        Ok(true)
    }

    /// **TURN-05 — `session.resume{from_event}` (PROTOCOL.md §7.2).** A reconnecting client re-attaches
    /// to a session; the runtime (1) rebuilds/attaches the session actor so new turns route to a live
    /// actor even after idle-reaping (cold-start safe), (2) sends a `session.snapshot` of current
    /// state, then (3) replays *every* event with `seq > from_event` from the Event Log — in order —
    /// so the client is caught up exactly. `from_event == None` (a bare `--continue`) sends only the
    /// snapshot.
    ///
    /// `log` is the session's ordered event projection (the durable Event Log's tail, or an in-memory
    /// slice in tests); this manager owns the *delivery contract*, not the projection. RBAC: only a
    /// participant (or an admin) may re-attach.
    pub async fn resume(
        &self,
        principal: &Principal,
        command: &Command,
        state: SnapshotState,
        log: &[EventEnvelope],
        sink: &mpsc::Sender<EventEnvelope>,
    ) -> Result<ResumeOutcome, ResumeError> {
        // 1. Must be a `session.resume`.
        let (session_id, from_event) = match command {
            Command::SessionResume {
                session_id,
                from_event,
            } => (session_id.clone(), *from_event),
            _ => return Err(ResumeError::NotAResume),
        };

        // 2. RBAC (§7.2): a participant of the session, or an admin, may re-attach.
        let authorized = principal.role == Role::Admin
            || state
                .participants
                .iter()
                .any(|p| p.participant_id == principal.user_id);
        if !authorized {
            return Err(ResumeError::NotAuthorized);
        }

        // 3. Rebuild/attach the session actor (cold-start safe) BEFORE streaming, so a turn.submit
        //    that races the reconnect finds a live actor. Never holds a lock across an await.
        let actor_rebuilt = self.ensure_actor(&session_id).map_err(|e| match e {
            SubmitError::Backpressure(m) => ResumeError::Backpressure(m),
        })?;

        // 4. Snapshot first. Its `seq` is the client's current cursor, so the replayed tail (all
        //    strictly-greater seqs) stays monotonic behind it — no false gap on the client.
        let snapshot = EventEnvelope {
            v: state.negotiated_version.clone(),
            session_id: session_id.clone(),
            turn_id: None,
            program_id: None,
            seq: from_event.unwrap_or(0),
            ts: state.ts.clone(),
            control_plane_sha: state.control_plane_sha.clone(),
            event: WireEvent::SessionSnapshot {
                tree: state.tree.clone(),
                active_head: state.active_head.clone(),
                participants: state.participants.clone(),
                negotiated_version: state.negotiated_version.clone(),
            },
        };
        sink.send(snapshot)
            .await
            .map_err(|_| ResumeError::SinkClosed)?;

        // 5. Then the tail: every event with `seq > from_event`, in ascending order (the protocol's
        //    own `replay_tail`, which also sorts/de-dups defensively).
        let tail = replay_tail(from_event, log);
        let replayed = tail.len();
        let new_cursor = tail
            .last()
            .map(|e| e.seq)
            .unwrap_or_else(|| from_event.unwrap_or(0));
        for ev in tail {
            sink.send(ev).await.map_err(|_| ResumeError::SinkClosed)?;
        }

        Ok(ResumeOutcome {
            session_id,
            actor_rebuilt,
            replayed,
            new_cursor,
        })
    }

    /// **SURF-11 — turn-tree interaction over the linear Event Log (INTERACTION_REPL_COMMANDS §3).**
    /// The durable log is append-only *linear*; this ingests it into a [`SessionRecording`] tree via
    /// `ainxt_replay::SessionRecording::from_linear` and applies the first-class tree op a linear log
    /// cannot express — **branch / edit / stop / steer** — on the live session:
    ///
    /// * `turn.branch` / `turn.edit` fork a new sibling/child (`new_turn_id`), never mutating history;
    /// * `turn.steer` appends an interjection and reports its [`SteerDelivery`] (safe-boundary timing);
    /// * `turn.stop` records the durable terminal state **and** fires the live in-flight cancel token
    ///   (if the running turn matches), so the tree record and the running turn agree.
    ///
    /// Returns the resulting head/turn-count plus the events this op appended (for the caller to
    /// persist back to the durable log). RBAC is enforced by the recording's own authorizer
    /// (participant or `compliance.replay`).
    #[allow(clippy::too_many_arguments)]
    pub fn apply_interaction(
        &self,
        principal: &Principal,
        session_id: &str,
        participants: &[&str],
        linear_log: &[LinearRecord],
        command: &Command,
        new_turn_id: &str,
        now_millis: u128,
    ) -> Result<InteractionOutcome, InteractionError> {
        let mut rec = SessionRecording::from_linear(session_id, participants, linear_log);
        // RBAC: reuse the recording's authorizer (participant OR compliance.replay).
        rec.snapshot(principal)
            .map_err(|_| InteractionError::NotAuthorized)?;

        let baseline = rec.events().len();
        let author = principal.user_id.as_str();
        let mut minted = None;
        let mut steer_delivery = None;
        let mut live_cancel_fired = false;

        match command {
            Command::TurnBranch {
                from_turn_id,
                label,
            } => {
                rec.branch(
                    from_turn_id,
                    new_turn_id,
                    author,
                    label.as_deref(),
                    now_millis,
                )
                .map_err(InteractionError::Tree)?;
                minted = Some(new_turn_id.to_string());
            }
            Command::TurnEdit { turn_id, .. } => {
                rec.edit_turn(turn_id, new_turn_id, author, None, now_millis)
                    .map_err(InteractionError::Tree)?;
                minted = Some(new_turn_id.to_string());
            }
            Command::TurnStop { turn_id } => {
                // Durable terminal record (never deletes the turn) …
                rec.stop(turn_id, now_millis)
                    .map_err(InteractionError::Tree)?;
                // … then the live effect: fire the running turn's cancel token if it is this turn.
                let reg = self.cancels.lock().expect("cancels lock");
                if let Some((tid, tok)) = reg.get(session_id) {
                    if tid == turn_id {
                        tok.cancel();
                        live_cancel_fired = true;
                    }
                }
            }
            Command::TurnSteer { turn_id, text } => {
                let delivery = rec
                    .steer(turn_id, text, DataClass::Internal, now_millis)
                    .map_err(InteractionError::Tree)?;
                steer_delivery = Some(delivery);
            }
            _ => return Err(InteractionError::Unsupported),
        }

        let appended_events = rec.events()[baseline..].to_vec();
        Ok(InteractionOutcome {
            active_head: rec.tree().active_head().map(str::to_string),
            turn_count: rec.tree().turn_count(),
            new_turn_id: minted,
            steer_delivery,
            live_cancel_fired,
            appended_events,
        })
    }
}

/// Current session state the runtime supplies for the `session.snapshot` a `resume` sends first
/// (TURN-05). The tree / active head / participants come from the session's durable projection; this
/// manager owns only the delivery, never the projection.
#[derive(Debug, Clone)]
pub struct SnapshotState {
    pub tree: SessionTree,
    pub active_head: Option<String>,
    pub participants: Vec<Participant>,
    /// The negotiated protocol version string echoed back to the client (§10.2).
    pub negotiated_version: String,
    /// The control-repo commit the snapshot is pinned to (reproducibility; mirrors the log).
    pub control_plane_sha: String,
    /// RFC-3339 timestamp for the snapshot envelope.
    pub ts: String,
}

/// The result of a successful [`SessionManager::resume`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumeOutcome {
    pub session_id: String,
    /// `true` iff the session actor had to be (re)built (cold start after idle-reap).
    pub actor_rebuilt: bool,
    /// Number of tail events replayed (beyond the snapshot).
    pub replayed: usize,
    /// The `seq` the client should hold after this resume (its new resume cursor).
    pub new_cursor: u64,
}

/// Why a [`SessionManager::resume`] was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResumeError {
    /// The command was not a `session.resume`.
    NotAResume,
    /// The principal is not a participant of the session (and not an admin).
    NotAuthorized,
    /// The global session cap was hit while re-attaching (map to HTTP 503).
    Backpressure(String),
    /// The client's event sink closed before the snapshot/tail could be delivered.
    SinkClosed,
}

/// The result of a successful [`SessionManager::apply_interaction`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InteractionOutcome {
    /// The tree's active head after the op.
    pub active_head: Option<String>,
    /// Total turns in the tree after the op.
    pub turn_count: usize,
    /// The new sibling/child turn id for a `branch`/`edit` (`None` for `stop`/`steer`).
    pub new_turn_id: Option<String>,
    /// For a `steer`: when the interjection lands (safe-boundary timing). `None` otherwise.
    pub steer_delivery: Option<SteerDelivery>,
    /// For a `stop`: whether a live in-flight turn's cancel token was actually fired.
    pub live_cancel_fired: bool,
    /// The events this op appended — for the caller to persist back to the durable Event Log.
    pub appended_events: Vec<ReplayEvent>,
}

/// Why a [`SessionManager::apply_interaction`] was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InteractionError {
    /// The principal may not view/modify this session (not a participant, lacks `compliance.replay`).
    NotAuthorized,
    /// The command is not one of `turn.branch` / `turn.edit` / `turn.stop` / `turn.steer`.
    Unsupported,
    /// The underlying tree operation was refused (unknown/duplicate/not-editable/not-active turn).
    Tree(TreeError),
}

/// One session actor: process turns serially; reap self after `idle_ttl` of inactivity.
async fn run_actor(
    handler: Arc<dyn TurnHandler>,
    mut rx: mpsc::Receiver<Job>,
    sessions: Sessions,
    cancels: Cancels,
    session_id: String,
    idle_ttl: Duration,
    turn_timeout: Duration,
) {
    loop {
        match tokio::time::timeout(idle_ttl, rx.recv()).await {
            Ok(Some(job)) => process(&handler, job, turn_timeout, &cancels, &session_id).await,
            Ok(None) => break, // all senders dropped (manager gone)
            Err(_elapsed) => {
                // Idle — reap under the lock, but grab a straggler that raced in first. Because
                // `submit` also sends under the lock, this check is exclusive with it: we either
                // pick up the job or remove ourselves, never lose a job.
                let mut map = sessions.lock().expect("sessions lock");
                match rx.try_recv() {
                    Ok(job) => {
                        drop(map);
                        process(&handler, job, turn_timeout, &cancels, &session_id).await;
                    }
                    Err(_empty_or_disconnected) => {
                        map.remove(&session_id);
                        break;
                    }
                }
            }
        }
    }
}

/// Run one turn with a hard timeout AND panic isolation, so neither a hung turn nor a panicking
/// one can kill the actor (which would orphan its map entry) or pin its session slot.
async fn process(
    handler: &Arc<dyn TurnHandler>,
    job: Job,
    turn_timeout: Duration,
    cancels: &Cancels,
    session_id: &str,
) {
    use futures_util::FutureExt;
    let Job {
        principal,
        request,
        sink,
        cancel,
        done,
    } = job;
    // Publish the in-flight turn's cancel token so an out-of-band `turn.stop` routed through
    // [`SessionManager::apply_interaction`] (SURF-11) can fire it. Serial-per-session ⇒ this
    // key is exclusively ours for the turn's lifetime.
    let turn_id = request.turn.clone();
    cancels
        .lock()
        .expect("cancels lock")
        .insert(session_id.to_string(), (turn_id.clone(), cancel.clone()));

    let turn =
        std::panic::AssertUnwindSafe(handler.handle_turn(&principal, &request, sink, &cancel))
            .catch_unwind();
    let res = match tokio::time::timeout(turn_timeout, turn).await {
        Ok(Ok(res)) => res, // completed (ok or turn-error)
        Ok(Err(_panic)) => Err(TurnError::Internal("turn panicked".into())),
        Err(_elapsed) => Err(TurnError::Internal("turn timed out".into())), // dropping the future frees it
    };

    // Deregister — but only if the entry is still ours (defensive; serial execution makes this
    // hold, and it keeps the registry bounded: no stale token outlives its turn).
    {
        let mut reg = cancels.lock().expect("cancels lock");
        if reg
            .get(session_id)
            .map(|(t, _)| t == &turn_id)
            .unwrap_or(false)
        {
            reg.remove(session_id);
        }
    }

    let _ = done.send(res); // receiver may have gone away; that's fine
}
