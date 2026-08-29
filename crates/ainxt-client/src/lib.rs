// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! ainxt-client — the Rust protocol client / SDK (Phase 4).
//!
//! This is the Rust client boundary and the **reference implementation** of the wire contract. Today
//! its only consumers are the headless CLI (`ainxt-cli`) and the composition daemon (`ainxt-runtimed`
//! via [`Client::in_process`]); it speaks the [`ainxt_protocol`] contract to the runtime through a
//! [`Transport`] seam:
//!
//! - [`InProcessTransport`] embeds the [`SessionManager`] and runs turns in-process. This is how the
//!   headless CLI and (eventually) the desktop app talk to the runtime — **directly**, never by
//!   shelling out to a wrapped binary. It inherits the whole spine: compliance, RBAC, backpressure,
//!   cancel.
//! - A network HTTP/SSE transport (feature `http`, **not yet implemented**) will speak to
//!   `ainxt-server` for remote clients. The planned **Python SDK (first) and TypeScript SDK do not
//!   exist yet**; when built (in their own language repos/CI) they mirror this same wire contract —
//!   this Rust client is that contract's reference. See `docs/architecture/P4_EXIT_DOD.md`.
//!
//! The client turns a chat call into a [`ChatStream`] of typed [`Event`]s; [`ChatStream::collect`]
//! drains it into a [`Collected`] result (final text + usage + terminal status). Backpressure from
//! the spine surfaces as [`ClientError::Backpressure`] (the caller sheds load, e.g. HTTP 503), and a
//! turn can be [`cancelled`](ChatStream::cancel).
//!
//! Clean-room: the client API, transport seam, and collect semantics are original to AiNxt.

use std::sync::Arc;

/// The SDK **contract descriptor** and language-binding **codegen** (gap "Python/TS SDK"): the
/// machine-readable projection of the wire contract that the Python (first) and TypeScript SDKs are
/// generated from, so they are provably faithful mirrors of this Rust reference rather than
/// hand-maintained copies. See the module docs for the offline-vs-infra split.
pub mod sdk_contract;

use ainxt_protocol::{ApprovalRespond, Event, PaymentBoundary, Request};
use ainxt_runtime::compliance::{ComplianceGate, Direction, RedactAndProceed};
use ainxt_runtime::CancelToken;
use ainxt_session::{SessionManager, SubmitError};
use ainxt_types::{DataClass, Principal};
use std::collections::HashMap;
use std::sync::Mutex;
use tokio::sync::mpsc;

/// Protocol version this client is built against (see [`ainxt_protocol::VERSION`]).
pub const CLIENT_PROTOCOL_VERSION: u32 = ainxt_protocol::VERSION;

/// A client-side failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientError {
    /// The runtime shed the turn under load (full inbox / session cap). The caller should retry
    /// later or surface HTTP 503.
    Backpressure(String),
    /// A transport-level failure (network, serialization) — network transports only.
    Transport(String),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Backpressure(m) => write!(f, "runtime is at capacity: {m}"),
            ClientError::Transport(m) => write!(f, "transport error: {m}"),
        }
    }
}
impl std::error::Error for ClientError {}

/// The seam a client speaks through. Implemented in-process ([`InProcessTransport`]) or over the
/// network (feature `http`).
pub trait Transport: Send + Sync {
    /// Submit a turn; return a live event stream or a typed error.
    fn submit(&self, principal: Principal, request: Request) -> Result<ChatStream, ClientError>;
}

/// A live stream of a turn's events. Backed by a bounded channel; drop it (or [`cancel`]) to stop.
///
/// [`cancel`]: ChatStream::cancel
pub struct ChatStream {
    rx: mpsc::Receiver<Event>,
    cancel: CancelToken,
}

impl ChatStream {
    /// Build a stream from its backing channel + cancel token (used by transports).
    pub(crate) fn from_parts(rx: mpsc::Receiver<Event>, cancel: CancelToken) -> Self {
        ChatStream { rx, cancel }
    }

    /// The next event, or `None` when the turn is finished and the stream is closed.
    pub async fn recv(&mut self) -> Option<Event> {
        self.rx.recv().await
    }

    /// Cancel the in-flight turn (idempotent). Frees the runtime's resources for this turn.
    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    /// Drain the whole stream, assembling the final text, usage, and terminal status. Convenient for
    /// non-streaming callers (the CLI `--print` mode, contract tests).
    pub async fn collect(mut self) -> Collected {
        let mut out = Collected::default();
        while let Some(event) = self.rx.recv().await {
            match &event {
                Event::TextDelta(t) => out.text.push_str(t),
                Event::Error(e) => out.error = Some(e.clone()),
                Event::Usage {
                    input_tokens,
                    output_tokens,
                } => {
                    out.usage = Some(Usage {
                        input_tokens: *input_tokens,
                        output_tokens: *output_tokens,
                    })
                }
                Event::Done => out.completed = true,
                Event::ApprovalRequest { id, summary } => out.approvals.push(PendingApproval {
                    id: id.clone(),
                    summary: summary.clone(),
                }),
                _ => {}
            }
            out.events.push(event);
        }
        out
    }
}

/// Token usage for a turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Usage {
    pub input_tokens: u64,
    pub output_tokens: u64,
}

/// A HITL approval the runtime requested during a turn (surfaced so a non-streaming caller can act
/// on it). The approve/reject back-channel to the engine is a protocol/session concern; this client
/// captures the request so the SDK's typed-event contract is complete on the read side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingApproval {
    pub id: String,
    pub summary: String,
}

/// The assembled result of draining a [`ChatStream`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Collected {
    /// The concatenated `TextDelta`s — the model's answer.
    pub text: String,
    /// Every event seen, in order.
    pub events: Vec<Event>,
    /// The terminal error, if the turn emitted one.
    pub error: Option<String>,
    /// Token usage, if reported.
    pub usage: Option<Usage>,
    /// HITL approval requests seen during the turn.
    pub approvals: Vec<PendingApproval>,
    /// Whether a terminal `Done` was seen.
    pub completed: bool,
}

// ===========================================================================
// SDK-side HITL respond (gap harness-sdk-governance #1) — mirrors ainxt-server's §6.3
// ApprovalCoordinator/WireApprovalGate pair so an IN-PROCESS client (the headless CLI / desktop app —
// they talk to the runtime directly, never through a wrapped binary or the HTTP transport) can
// deliver a human's decision back to the engine's blocking approval gate. Before this, [`ChatStream`]
// could only OBSERVE an `Event::ApprovalRequest` (the read side, [`PendingApproval`]); there was no
// write side, so an in-process embedder had no way to ever unblock a gated high-risk/payment-boundary
// tool call short of the gate's own fail-closed timeout.
// ===========================================================================

/// The decision delivered back to a blocked [`WireApprovalGate`] — a projection of the caller's
/// [`ApprovalRespond`] onto the runtime's tri-state decision (feedback carried on reject). Mirrors
/// `ainxt_server::ApprovalOutcome` exactly.
#[derive(Debug, Clone)]
struct ApprovalOutcome {
    decision: ainxt_runtime::approval::ApprovalDecision,
}

/// The client-side half of the wire-level HITL approval round-trip (mirrors
/// `ainxt_server::ApprovalCoordinator`, TRANSP §6.3/ADR-016): couples the in-process engine's blocking
/// [`ApprovalGate`](ainxt_runtime::approval::ApprovalGate) — installed via
/// [`Client::in_process_with_approvals`] — to [`Client::respond_approval`]. Correlation is per
/// **session**, exactly as the server does: the engine blocks exactly one turn's tool dispatch at a
/// time on the gate, so a pending wait is keyed by the session the gated turn is running under.
#[derive(Default)]
pub struct ApprovalCoordinator {
    pending: Mutex<HashMap<String, std::sync::mpsc::SyncSender<ApprovalOutcome>>>,
}

impl ApprovalCoordinator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a pending approval for `session`, returning the receiver the blocked gate waits on. A
    /// prior un-answered pending for the same session is replaced (the newest gated turn wins).
    fn register(&self, session: &str) -> std::sync::mpsc::Receiver<ApprovalOutcome> {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        self.pending
            .lock()
            .expect("approval coordinator lock")
            .insert(session.to_string(), tx);
        rx
    }

    /// Deliver the caller's [`ApprovalRespond`] to the blocked gate for `session`. Returns whether a
    /// pending approval was actually waiting (so [`Client::respond_approval`] can tell an already
    /// timed-out / already-answered / never-gated session apart from a genuine delivery).
    pub fn resolve(&self, session: &str, respond: &ApprovalRespond) -> bool {
        // Same shape invariant the wire enforces (§5): a reject must carry feedback. Validated here
        // too so an in-process embedder gets the identical contract regardless of transport.
        if respond.is_valid(PaymentBoundary::None, false).is_err() {
            return false;
        }
        let decision = match respond.decision {
            ainxt_protocol::ApprovalDecision::Approve => {
                ainxt_runtime::approval::ApprovalDecision::Approve
            }
            ainxt_protocol::ApprovalDecision::ApproveForSession => {
                ainxt_runtime::approval::ApprovalDecision::ApproveForSession
            }
            ainxt_protocol::ApprovalDecision::Reject => {
                ainxt_runtime::approval::ApprovalDecision::Reject(
                    respond.feedback.clone().unwrap_or_default(),
                )
            }
            // The protocol enum is #[non_exhaustive]; an unknown future variant fails closed (reject).
            _ => ainxt_runtime::approval::ApprovalDecision::Reject(
                "unrecognized approval decision".to_string(),
            ),
        };
        match self
            .pending
            .lock()
            .expect("approval coordinator lock")
            .remove(session)
        {
            Some(tx) => tx.try_send(ApprovalOutcome { decision }).is_ok(),
            None => false,
        }
    }
}

/// The [`ApprovalGate`](ainxt_runtime::approval::ApprovalGate) [`Client::in_process_with_approvals`]
/// installs on its embedded engine so a gated tool's decision comes from a LIVE human delivered
/// through [`Client::respond_approval`], not a policy default. Mirrors `ainxt_server::WireApprovalGate`
/// exactly: `decide` parks the turn on the [`ApprovalCoordinator`] (keyed by session) and blocks until
/// the embedder responds or the bounded timeout elapses; a timeout FAILS CLOSED (reject), so an
/// embedder that never surfaces/answers the `ApprovalRequest` event can never leave a payment-boundary
/// tool hanging or silently auto-approved. `is_policy_auto` is `false` — this is a human/HITL gate.
pub struct WireApprovalGate {
    coordinator: Arc<ApprovalCoordinator>,
    timeout: std::time::Duration,
}

impl WireApprovalGate {
    /// Build a wire approval gate over `coordinator`, failing closed after `timeout` with no response.
    pub fn new(coordinator: Arc<ApprovalCoordinator>, timeout: std::time::Duration) -> Self {
        WireApprovalGate {
            coordinator,
            timeout,
        }
    }
}

impl ainxt_runtime::approval::ApprovalGate for WireApprovalGate {
    fn decide(
        &self,
        req: &ainxt_runtime::approval::ApprovalRequest,
    ) -> ainxt_runtime::approval::ApprovalDecision {
        let rx = self.coordinator.register(&req.session);
        match rx.recv_timeout(self.timeout) {
            Ok(outcome) => outcome.decision,
            Err(_) => ainxt_runtime::approval::ApprovalDecision::Reject(
                "approval timed out: no SDK response before deadline (fail-closed)".to_string(),
            ),
        }
    }

    fn is_policy_auto(&self) -> bool {
        false
    }
}

/// In-process transport: runs turns through an embedded [`SessionManager`].
pub struct InProcessTransport {
    manager: Arc<SessionManager>,
    channel_cap: usize,
}

impl InProcessTransport {
    pub fn new(manager: Arc<SessionManager>, channel_cap: usize) -> Self {
        InProcessTransport {
            manager,
            channel_cap: channel_cap.max(1),
        }
    }
}

impl Transport for InProcessTransport {
    fn submit(&self, principal: Principal, request: Request) -> Result<ChatStream, ClientError> {
        let (tx, rx) = mpsc::channel::<Event>(self.channel_cap);
        match self.manager.submit(principal, request, tx) {
            Ok(ticket) => Ok(ChatStream {
                rx,
                cancel: ticket.cancel.clone(),
            }),
            Err(SubmitError::Backpressure(m)) => Err(ClientError::Backpressure(m)),
        }
    }
}

/// Client configuration (endpoint/auth are used by network transports; profile + data-class shape
/// the request the convenience `chat` builds).
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Surface profile id the request runs under (informational for the in-process transport; the
    /// binding/engine apply it upstream).
    pub profile: Option<String>,
    /// The data class the convenience `chat` tags a turn with.
    pub default_data_class: DataClass,
    /// Bounded event-channel capacity (backpressure boundary) for the in-process transport.
    pub channel_cap: usize,
}

impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfig {
            profile: None,
            default_data_class: DataClass::Internal,
            channel_cap: 64,
        }
    }
}

/// The typed client. One client is bound to one authenticated [`Principal`]; it can run many turns
/// across many sessions.
pub struct Client {
    transport: Box<dyn Transport>,
    principal: Principal,
    config: ClientConfig,
    /// The SDK-side HITL coordinator, when this client's embedded engine was built with a
    /// [`WireApprovalGate`] ([`Client::in_process_with_approvals`]). `None` for every other
    /// constructor — [`Client::respond_approval`] then correctly reports nothing was delivered
    /// rather than silently doing nothing.
    approvals: Option<Arc<ApprovalCoordinator>>,
}

impl Client {
    pub fn new(transport: Box<dyn Transport>, principal: Principal, config: ClientConfig) -> Self {
        Client {
            transport,
            principal,
            config,
            approvals: None,
        }
    }

    /// Convenience constructor: an in-process client over `manager` for `principal`. The embedded
    /// engine's approval gate (if any) was wired by whoever built `manager`; this client has no
    /// coordinator handle of its own, so [`Client::respond_approval`] always reports "not delivered".
    /// Use [`Client::in_process_with_approvals`] to also wire the SDK-side HITL respond path.
    pub fn in_process(
        manager: Arc<SessionManager>,
        principal: Principal,
        config: ClientConfig,
    ) -> Self {
        let transport = Box::new(InProcessTransport::new(manager, config.channel_cap));
        Client {
            transport,
            principal,
            config,
            approvals: None,
        }
    }

    /// Convenience constructor: an in-process client whose embedded `engine`'s HITL approval gate is
    /// this crate's own [`WireApprovalGate`] over `coordinator` — the SDK-side mirror of
    /// `ainxt-server`'s §6.3 wire approval round-trip. This is how the headless CLI / desktop app (an
    /// in-process caller, never a wrapped binary) delivers a human's decision back to a blocked
    /// gated tool call via [`Client::respond_approval`], rather than only ever observing the
    /// `Event::ApprovalRequest` and letting the gate time out fail-closed.
    ///
    /// `engine` must not already carry an approval gate — this call installs one, overwriting any
    /// prior `.with_approval(..)`. `coordinator` is caller-owned (mirroring how `ainxt-runtimed` holds
    /// its own `Arc<ApprovalCoordinator>` at the composition root) so the embedder can also observe/
    /// share it directly if it needs to. `timeout` bounds how long a gated call blocks before failing
    /// closed when nobody answers.
    pub fn in_process_with_approvals(
        engine: ainxt_runtime::Engine,
        session_cfg: ainxt_session::SessionConfig,
        coordinator: Arc<ApprovalCoordinator>,
        timeout: std::time::Duration,
        principal: Principal,
        config: ClientConfig,
    ) -> Self {
        let gate = WireApprovalGate::new(coordinator.clone(), timeout);
        let engine = engine.with_approval(Box::new(gate));
        let manager = Arc::new(SessionManager::new(Arc::new(engine), session_cfg));
        let transport = Box::new(InProcessTransport::new(manager, config.channel_cap));
        Client {
            transport,
            principal,
            config,
            approvals: Some(coordinator),
        }
    }

    /// Deliver a human's decision on a pending HITL approval (surfaced to the caller as an
    /// [`Event::ApprovalRequest`] / [`PendingApproval`]) back to the blocked engine gate for
    /// `session` — the session id the gated turn is running under. Returns `true` iff a pending
    /// approval was actually waiting on that session (`false` if it already timed out, was already
    /// answered, or this client was not built with [`Client::in_process_with_approvals`]).
    pub fn respond_approval(&self, session: &str, respond: ApprovalRespond) -> bool {
        match &self.approvals {
            Some(coordinator) => coordinator.resolve(session, &respond),
            None => false,
        }
    }

    /// The data class new `chat` turns default to.
    pub fn default_data_class(&self) -> DataClass {
        self.config.default_data_class
    }

    /// Start a chat turn, using the client's default data class.
    pub fn chat(&self, session: &str, turn: &str, input: &str) -> Result<ChatStream, ClientError> {
        let request = Request::chat(session, turn, input, self.config.default_data_class);
        self.chat_request(request)
    }

    /// Start a turn from a fully-specified [`Request`] (tier, forced provider, data class).
    pub fn chat_request(&self, request: Request) -> Result<ChatStream, ClientError> {
        self.transport.submit(self.principal.clone(), request)
    }

    /// The principal this client is bound to.
    pub fn principal(&self) -> &Principal {
        &self.principal
    }

    /// Build the engine [`Request`] for one harness `Llm` step, applying the harness's declared
    /// `model_policy` and `context.namespace` (design `HARNESS_SDK.md` §1) exactly as a Chat turn's
    /// own `tier`/`forced_provider`/namespace already work — so a harness author's model/namespace
    /// declaration is not a decorative manifest field, it actually shapes the engine turn the SDK
    /// bridge issues. Still subject to the engine's non-overridable data-class exclusion gate (a
    /// pinned model ineligible for `ctx.data_class` is refused downstream, never silently honored).
    fn engine_request_for(
        manifest: &ainxt_admission::HarnessManifest,
        session: &str,
        turn: &str,
        input: &str,
        data_class: DataClass,
    ) -> Request {
        let mut request = Request::chat(session, turn, input, data_class);
        if let Some(policy) = &manifest.model_policy {
            let (tier, forced_provider) = ainxt_admission::resolve_model_policy(policy);
            request.tier = tier;
            request.forced_provider = forced_provider;
        }
        if let Some(namespace) = manifest.namespace() {
            request = request.with_namespace(namespace);
        }
        request
    }

    /// Run a declarative harness end-to-end over the runtime: the [`HarnessRuntime`] performs
    /// admission + per-step least-privilege/budget/data-class/payment gating, and **each admitted
    /// step is executed as a real engine turn** through this client — so compliance, RBAC, and
    /// backpressure run inside the spine, exactly as for a chat turn. This is the StepExecutor seam
    /// bridging a harness step to an engine turn + compliance; the harness owns *what runs*, the
    /// engine owns *that it stays safe*.
    ///
    /// A refused admission or step-gate short-circuits: no engine turn is issued for a denied step.
    ///
    /// HARN-02: this entrypoint has no [`CapabilityInvoker`] — EVERY admitted step, including a
    /// `StepKind::Tool` step, runs as an ordinary engine chat turn (`step.capability` is used only
    /// for the admission/least-privilege GATE above, never to select real execution). That is
    /// deliberate for this bare entrypoint (a manifest whose steps are all `Llm`/`Skill`, or a
    /// dry-run over an offline model with no real capability registry to dispatch against) — a
    /// caller whose manifest has `Tool` steps that must actually DISPATCH a capability (not just be
    /// simulated as a model turn) needs [`Self::run_harness_with_invoker`], which is what the served
    /// daemon's `/v1/harness/{id}` route uses.
    pub async fn run_harness(
        &self,
        runtime: &ainxt_admission::HarnessRuntime,
        manifest: &ainxt_admission::HarnessManifest,
        grant: &ainxt_admission::CapabilityGrant,
        ctx: &ainxt_admission::RunContext,
        session: &str,
    ) -> HarnessRunReport {
        use ainxt_admission::{HarnessOutcome, RunTally, StepGate, StepKind};

        let run = match runtime.admit(manifest, grant, &self.principal, ctx) {
            Ok(r) => r,
            Err(outcome) => return HarnessRunReport::terminal(outcome),
        };

        let mut tally = RunTally::default();
        let mut step_outputs: Vec<String> = Vec::new();
        let mut total_input_tokens = 0u64;
        let mut total_output_tokens = 0u64;
        let mut redactions_observed = 0usize;

        for step in &manifest.steps {
            match runtime.gate_step(&run, manifest, step, &self.principal, &tally) {
                StepGate::Reject(outcome) => {
                    return HarnessRunReport {
                        outcome,
                        step_outputs,
                        total_input_tokens,
                        total_output_tokens,
                        redactions_observed,
                    };
                }
                StepGate::Admit => {}
            }

            // Execute the step as a real engine turn (compliance runs inside the engine).
            let input = step.input.clone().unwrap_or_else(|| {
                if manifest.persona.is_empty() {
                    step.id.clone()
                } else {
                    manifest.persona.clone()
                }
            });
            let request =
                Self::engine_request_for(manifest, session, &step.id, &input, ctx.data_class);
            let collected = match self.chat_request(request) {
                Ok(stream) => stream.collect().await,
                Err(e) => {
                    return HarnessRunReport {
                        outcome: HarnessOutcome::Rejected(format!("engine turn failed: {e}")),
                        step_outputs,
                        total_input_tokens,
                        total_output_tokens,
                        redactions_observed,
                    };
                }
            };

            if let Some(usage) = collected.usage {
                total_input_tokens = total_input_tokens.saturating_add(usage.input_tokens);
                total_output_tokens = total_output_tokens.saturating_add(usage.output_tokens);
            }
            // The engine's compliance gate leaves a [REDACTED...] marker for each redaction.
            redactions_observed += collected.text.matches("[REDACTED").count();
            step_outputs.push(collected.text);

            // Budget accounting mirrors the sync runtime: charge actual usage against the token cap.
            let step_tokens = collected
                .usage
                .map(|u| u.input_tokens.saturating_add(u.output_tokens))
                .unwrap_or(0);
            tally.tokens_used = tally.tokens_used.saturating_add(step_tokens);
            tally.steps_run += 1;
            if step.kind == StepKind::Tool {
                tally.tool_calls += 1;
            }
        }

        HarnessRunReport {
            outcome: HarnessOutcome::Completed {
                steps_run: tally.steps_run,
                tokens_used: tally.tokens_used,
                tool_calls: tally.tool_calls,
            },
            step_outputs,
            total_input_tokens,
            total_output_tokens,
            redactions_observed,
        }
    }

    /// Run a declarative harness with **real capability dispatch + autonomy/HITL enforcement**.
    ///
    /// This is the production bridge (design §2.2): each admitted step is executed as the thing it
    /// declares — an `Llm` step streams through the engine as a chat turn, while a `Tool`/`Skill` step
    /// invokes its **named capability** through `invoker` (the tool registry / connector runtime), so a
    /// `connector.postgres.query` step actually queries rather than running a bare completion. Before
    /// any write/side-effect step runs, the harness runtime's autonomy gate is consulted: a
    /// `none`-autonomy harness refuses writes (suggest-only); an `assisted` harness raises an approval
    /// to `resolver` and runs the step only if approved; `autonomous` proceeds. Least-privilege,
    /// budget, data-class and payment gating apply exactly as in [`run_harness`]; a refusal
    /// short-circuits with no capability invoked.
    #[allow(clippy::too_many_arguments)]
    pub async fn run_harness_with_invoker(
        &self,
        runtime: &ainxt_admission::HarnessRuntime,
        manifest: &ainxt_admission::HarnessManifest,
        grant: &ainxt_admission::CapabilityGrant,
        ctx: &ainxt_admission::RunContext,
        session: &str,
        invoker: &dyn CapabilityInvoker,
        resolver: &dyn ainxt_admission::ApprovalResolver,
    ) -> HarnessRunReport {
        // The OSS placeholder gate is the default step-result compliance seam; a deployment plugs the
        // real PCI/DSS detector via `run_harness_with_invoker_gated`.
        self.run_harness_with_invoker_gated(
            runtime,
            manifest,
            grant,
            ctx,
            session,
            invoker,
            resolver,
            &RedactAndProceed,
        )
        .await
    }

    /// Like [`run_harness_with_invoker`](Self::run_harness_with_invoker) but with an explicit
    /// [`ComplianceGate`] applied to **every** step result — the tool/skill/connector output as well
    /// as the LLM output — before it is recorded or chained forward (design §4: PCI/DSS on every step
    /// output, not just the final answer).
    ///
    /// Two invariants this path adds over a bare dispatch:
    /// - **Step-result compliance.** A `Tool`/`Skill`/connector step's `StepInvocation.output` is
    ///   *untrusted* — the capability may have missed a PAN. The gate re-scans every step's output
    ///   under redact-and-proceed, so a sensitive value a step emits is removed here even if the
    ///   capability did not redact it. Redaction never fails the turn.
    /// - **Chaining sees only redacted output.** Each step's *redacted* output is fed into the next
    ///   step's input, so the next step (LLM turn or invoked capability) can never observe the raw,
    ///   pre-redaction value of a prior step.
    #[allow(clippy::too_many_arguments)]
    pub async fn run_harness_with_invoker_gated(
        &self,
        runtime: &ainxt_admission::HarnessRuntime,
        manifest: &ainxt_admission::HarnessManifest,
        grant: &ainxt_admission::CapabilityGrant,
        ctx: &ainxt_admission::RunContext,
        session: &str,
        invoker: &dyn CapabilityInvoker,
        resolver: &dyn ainxt_admission::ApprovalResolver,
        gate: &dyn ComplianceGate,
    ) -> HarnessRunReport {
        use ainxt_admission::{
            ApprovalDecision, ApprovalRequest, AutonomyDecision, HarnessOutcome, RunTally,
            StepGate, StepKind,
        };

        let run = match runtime.admit(manifest, grant, &self.principal, ctx) {
            Ok(r) => r,
            Err(outcome) => return HarnessRunReport::terminal(outcome),
        };

        let mut tally = RunTally::default();
        let mut step_outputs: Vec<String> = Vec::new();
        let mut total_input_tokens = 0u64;
        let mut total_output_tokens = 0u64;
        let mut redactions_observed = 0usize;

        macro_rules! report_with {
            ($outcome:expr) => {
                HarnessRunReport {
                    outcome: $outcome,
                    step_outputs,
                    total_input_tokens,
                    total_output_tokens,
                    redactions_observed,
                }
            };
        }

        for step in &manifest.steps {
            // Least-privilege / budget / payment gate.
            match runtime.gate_step(&run, manifest, step, &self.principal, &tally) {
                StepGate::Reject(outcome) => return report_with!(outcome),
                StepGate::Admit => {}
            }

            // Autonomy / HITL: enforce the write-approval policy before any side-effect happens.
            match runtime.autonomy_gate(manifest, step) {
                AutonomyDecision::Proceed => {}
                AutonomyDecision::Refused(outcome) => return report_with!(outcome),
                AutonomyDecision::NeedsApproval { .. } => {
                    let req = ApprovalRequest {
                        harness: manifest.id.clone(),
                        step: step.id.clone(),
                        capability: step.capability.clone(),
                    };
                    if let ApprovalDecision::Reject(reason) = resolver.resolve(&req) {
                        return report_with!(HarnessOutcome::ApprovalRejected {
                            step: step.id.clone(),
                            capability: step.capability.clone(),
                            reason,
                        });
                    }
                }
            }

            // Chaining: hand this step ONLY the prior step's already-redacted output. We clone the
            // declared step and fold the redacted prior output into its `input`, so both the engine
            // turn and the invoked capability observe the redacted form — never the raw prior value.
            let mut chained = step.clone();
            if let Some(prev) = step_outputs.last() {
                let base = chained.input.clone().unwrap_or_default();
                chained.input = Some(format!("{base}\n\n## Prior step output\n{prev}"));
            }

            // Dispatch: an LLM step streams through the engine; a tool/skill step invokes its named
            // capability. Either way execution happens inside the spine.
            let (input_tokens, output_tokens, raw_output) = match chained.kind {
                StepKind::Llm => {
                    let input = chained.input.clone().unwrap_or_else(|| {
                        if manifest.persona.is_empty() {
                            chained.id.clone()
                        } else {
                            manifest.persona.clone()
                        }
                    });
                    let request = Self::engine_request_for(
                        manifest,
                        session,
                        &chained.id,
                        &input,
                        ctx.data_class,
                    );
                    let collected = match self.chat_request(request) {
                        Ok(stream) => stream.collect().await,
                        Err(e) => {
                            return report_with!(HarnessOutcome::Rejected(format!(
                                "engine turn failed: {e}"
                            )))
                        }
                    };
                    let (it, ot) = collected
                        .usage
                        .map(|u| (u.input_tokens, u.output_tokens))
                        .unwrap_or((0, 0));
                    (it, ot, collected.text)
                }
                StepKind::Tool | StepKind::Skill => {
                    match invoker
                        .invoke(&chained, &self.principal, ctx.data_class)
                        .await
                    {
                        Ok(inv) => (inv.input_tokens, inv.output_tokens, inv.output),
                        Err(e) => {
                            return report_with!(HarnessOutcome::Rejected(format!(
                                "capability '{}' failed: {e}",
                                chained.capability
                            )))
                        }
                    }
                }
            };

            // MANDATORY step-result compliance: redact-and-proceed on THIS step's output before it is
            // recorded or fed to the next step. The LLM path is already redacted by the engine; this
            // is defense-in-depth there and the ENFORCEMENT point for untrusted tool/connector output.
            let scanned = gate.scan(&raw_output, Direction::Output);
            let output = scanned.text;
            // Count the redaction markers actually present in the final (post-gate) output, so both
            // engine-redacted and gate-redacted steps are reflected consistently.
            redactions_observed += output.matches("[REDACTED").count();

            total_input_tokens = total_input_tokens.saturating_add(input_tokens);
            total_output_tokens = total_output_tokens.saturating_add(output_tokens);
            step_outputs.push(output);

            tally.tokens_used = tally
                .tokens_used
                .saturating_add(input_tokens.saturating_add(output_tokens));
            tally.steps_run += 1;
            if step.kind == StepKind::Tool {
                tally.tool_calls += 1;
            }
        }

        report_with!(HarnessOutcome::Completed {
            steps_run: tally.steps_run,
            tokens_used: tally.tokens_used,
            tool_calls: tally.tool_calls,
        })
    }
}

/// The result of a step's real capability execution (a tool/skill/connector call), distinct from a
/// bare LLM chat turn. Its output has already had the capability's own compliance handling applied;
/// `redactions` reports what that removed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StepInvocation {
    pub output: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub redactions: usize,
}

/// The future a [`CapabilityInvoker`] returns (boxed so the trait stays object-safe without an
/// `async_trait` dependency).
pub type CapabilityFuture<'a> = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<StepInvocation, ClientError>> + Send + 'a>,
>;

/// Executes a harness step's **named capability** as real work — the tool/skill/connector the step
/// declares (e.g. `connector.postgres.query`, `artifact.generate_report`, `code.edit`) — rather than
/// a generic LLM chat completion. This is the seam the parent wires to the engine's tool registry /
/// connector runtime; the harness bridge dispatches `Tool`/`Skill` steps here so the declared
/// capability actually runs (design §2.2), while `Llm` steps still stream through the engine. The
/// invocation runs inside the spine, so compliance/RBAC/backpressure still apply to it.
pub trait CapabilityInvoker: Send + Sync {
    fn invoke<'a>(
        &'a self,
        step: &'a ainxt_admission::HarnessStep,
        principal: &'a Principal,
        data_class: DataClass,
    ) -> CapabilityFuture<'a>;
}

/// The result of running a harness through the engine bridge ([`Client::run_harness`]).
#[derive(Debug, Clone)]
pub struct HarnessRunReport {
    /// The terminal harness outcome (completed / a policy refusal).
    pub outcome: ainxt_admission::HarnessOutcome,
    /// Each executed step's (compliance-redacted) engine output, in order.
    pub step_outputs: Vec<String>,
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
    /// Number of `[REDACTED…]` markers the engine's compliance gate left across all step outputs.
    pub redactions_observed: usize,
}

impl HarnessRunReport {
    /// A report for a run refused at admission (no steps executed).
    fn terminal(outcome: ainxt_admission::HarnessOutcome) -> Self {
        HarnessRunReport {
            outcome,
            step_outputs: Vec::new(),
            total_input_tokens: 0,
            total_output_tokens: 0,
            redactions_observed: 0,
        }
    }
}

// ============================ Network transport (HTTP/SSE) — gap "Network HTTP/SSE transport" ============================

/// The wire codec + [`Transport`] seam a **remote** SDK client speaks to `ainxt-server` over
/// HTTP/SSE (design `HARNESS_SDK.md` §2.2 "network transport to ainxt-server").
///
/// The honest split: the pure **codec** (submit-body encode + SSE-frame decode) and the full
/// [`Transport`] wiring are implemented and tested here **fully offline** — a remote client encodes
/// its turn exactly the same way and reconstructs the identical [`Event`] stream. The only piece
/// that is infra is the socket itself: [`WireChannel::open`] against a live TCP endpoint (a
/// deployment fills the seam with `reqwest`/`hyper` and a running server). Because the codec is the
/// hard, drift-prone part and it lives here under test, a network transport is a thin socket shim over
/// a proven core rather than untested prose.
pub mod net {
    use super::{ChatStream, ClientError, Transport};
    use ainxt_protocol::{Event, Request};
    use ainxt_runtime::CancelToken;
    use ainxt_types::Principal;
    use std::sync::Arc;
    use tokio::sync::mpsc;

    /// Encode a turn submission as the JSON body a remote `POST /v1/chat` carries: the authenticated
    /// principal + the request. Deterministic; the server decodes the mirror of this.
    pub fn encode_submit(principal: &Principal, request: &Request) -> Result<String, ClientError> {
        serde_json::to_string(&serde_json::json!({
            "principal": principal,
            "request": request,
        }))
        .map_err(|e| ClientError::Transport(format!("encode submit: {e}")))
    }

    /// Return the SSE `data:` payload of a raw stream line, or `None` for a non-data line
    /// (comment/`event:`/blank keep-alive). This is the SSE framing a `text/event-stream` body uses.
    pub fn sse_data_payload(line: &str) -> Option<&str> {
        line.strip_prefix("data:").map(|s| s.trim_start())
    }

    /// Decode one SSE data payload into an [`Event`]. `Ok(None)` for the terminal `[DONE]` sentinel,
    /// `Ok(Some(event))` for a data event, `Err` on malformed JSON.
    pub fn decode_event_frame(payload: &str) -> Result<Option<Event>, ClientError> {
        let p = payload.trim();
        if p == "[DONE]" {
            return Ok(None);
        }
        serde_json::from_str::<Event>(p)
            .map(Some)
            .map_err(|e| ClientError::Transport(format!("decode frame: {e}")))
    }

    /// The socket seam: open a turn against the remote endpoint and yield its SSE **data payloads**
    /// in order (each is fed to [`decode_event_frame`]; the final one may be `[DONE]`). The real impl
    /// performs the HTTP POST of `body` and streams the `text/event-stream` response body (infra); an
    /// in-memory impl feeds canned frames offline.
    pub trait WireChannel: Send + Sync {
        fn open(
            &self,
            body: String,
        ) -> Result<Box<dyn Iterator<Item = String> + Send>, ClientError>;
    }

    /// A [`Transport`] over a [`WireChannel`]: encodes the submit, opens the channel, and forwards
    /// each decoded [`Event`] into a [`ChatStream`] on a reader thread — so the remote client streams
    /// exactly like the in-process one. Cancellation stops the reader promptly.
    pub struct NetworkTransport<C: WireChannel + 'static> {
        channel: Arc<C>,
        channel_cap: usize,
    }

    impl<C: WireChannel + 'static> NetworkTransport<C> {
        pub fn new(channel: Arc<C>, channel_cap: usize) -> Self {
            NetworkTransport {
                channel,
                channel_cap: channel_cap.max(1),
            }
        }
    }

    impl<C: WireChannel + 'static> Transport for NetworkTransport<C> {
        fn submit(
            &self,
            principal: Principal,
            request: Request,
        ) -> Result<ChatStream, ClientError> {
            let body = encode_submit(&principal, &request)?;
            let frames = self.channel.open(body)?;
            let (tx, rx) = mpsc::channel::<Event>(self.channel_cap);
            let cancel = CancelToken::new();
            let cancel_reader = cancel.clone();
            // A reader thread turns the channel's SSE payloads into the ChatStream's event flow. We
            // use a std thread + blocking_send (not tokio::spawn) so the client core needs no runtime
            // handle — the transport is usable from any caller.
            std::thread::spawn(move || {
                for payload in frames {
                    if cancel_reader.is_cancelled() {
                        break;
                    }
                    match decode_event_frame(&payload) {
                        Ok(Some(ev)) => {
                            if tx.blocking_send(ev).is_err() {
                                break; // receiver dropped
                            }
                        }
                        Ok(None) => {
                            let _ = tx.blocking_send(Event::Done);
                            break;
                        }
                        Err(e) => {
                            let _ = tx.blocking_send(Event::Error(e.to_string()));
                            break;
                        }
                    }
                }
            });
            Ok(ChatStream::from_parts(rx, cancel))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ainxt_runtime::engine_with_defaults;
    use ainxt_runtime::provider::Provider;
    use ainxt_runtime::router::ModelRouter;
    use ainxt_session::SessionConfig;

    /// Emits one text delta, a usage record, then Done.
    struct MockProvider;
    impl Provider for MockProvider {
        fn id(&self) -> &str {
            "mock"
        }
        fn eligible(&self, _dc: DataClass) -> bool {
            true
        }
        fn stream(&self, _prompt: &str) -> mpsc::Receiver<Event> {
            let (tx, rx) = mpsc::channel(8);
            tokio::spawn(async move {
                let _ = tx.send(Event::TextDelta("hello".into())).await;
                let _ = tx
                    .send(Event::Usage {
                        input_tokens: 3,
                        output_tokens: 1,
                    })
                    .await;
                let _ = tx.send(Event::Done).await;
            });
            rx
        }
    }

    /// Never produces output — occupies a session so the cap can be hit.
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
                let _hold = tx;
                std::future::pending::<()>().await;
            });
            rx
        }
    }

    fn client_over(provider: impl Provider + 'static, cfg: SessionConfig) -> Client {
        let mut router = ModelRouter::new();
        router.register(Box::new(provider));
        let manager = Arc::new(SessionManager::new(
            Arc::new(engine_with_defaults(router)),
            cfg,
        ));
        Client::in_process(
            manager,
            Principal::user("u", &["chat.send"]),
            ClientConfig::default(),
        )
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn chat_streams_and_collects() {
        let client = client_over(MockProvider, SessionConfig::default());
        let stream = client.chat("s1", "t1", "hi").unwrap();
        let out = stream.collect().await;
        assert_eq!(out.text, "hello");
        assert!(out.completed, "a terminal Done must be observed");
        assert_eq!(
            out.usage,
            Some(Usage {
                input_tokens: 3,
                output_tokens: 1
            })
        );
        assert!(out.error.is_none());
        // The stream carried the events in order.
        assert!(matches!(out.events.last(), Some(Event::Done)));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn streaming_recv_delivers_events_incrementally() {
        // Drain via recv() (the streaming API). Order is not asserted: the engine's streaming-aware
        // redaction buffers an in-progress token and flushes it at Done, so the text can trail the
        // Usage event — what matters is every event is delivered and the stream terminates.
        let client = client_over(MockProvider, SessionConfig::default());
        let mut stream = client.chat("s1", "t1", "hi").unwrap();
        let mut events = Vec::new();
        while let Some(ev) = stream.recv().await {
            events.push(ev);
        }
        assert!(
            events.contains(&Event::TextDelta("hello".into())),
            "text must be delivered: {events:?}"
        );
        assert!(
            events.contains(&Event::Done),
            "stream must terminate with Done"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn backpressure_surfaces_as_typed_error() {
        // Global cap = 1 with a hanging provider: session A occupies the only slot; session B is shed.
        let cfg = SessionConfig {
            max_sessions: 1,
            ..Default::default()
        };
        let client = client_over(BlockProvider, cfg);
        let _a = client.chat("A", "t", "hi").unwrap(); // occupies the slot (hangs)
        let b = client.chat("B", "t", "hi");
        assert!(
            matches!(b, Err(ClientError::Backpressure(_))),
            "second session must be shed under the cap"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn cancel_is_safe_and_idempotent() {
        let client = client_over(BlockProvider, SessionConfig::default());
        let stream = client.chat("s", "t", "hi").unwrap();
        stream.cancel();
        stream.cancel(); // idempotent, no panic
    }

    #[test]
    fn client_protocol_version_matches_the_protocol_crate() {
        assert_eq!(CLIENT_PROTOCOL_VERSION, ainxt_protocol::VERSION);
    }

    // ---- SDK-side HITL respond (gap harness-sdk-governance #1) ----
    //
    // Mirrors ainxt-server's own `r11_wire_approval_roundtrip_*` tests exactly: rather than forcing a
    // real high-risk/payment-boundary tool call through the engine (which needs a whole ToolRuntime +
    // risk-tier registration), drive the SAME `WireApprovalGate::decide` blocking mechanism the
    // engine's approval-gated dispatch path uses, sharing the coordinator [`Client::respond_approval`]
    // resolves against. This proves the client-side coordinator/gate pair round-trips correctly and
    // that `Client::in_process_with_approvals` genuinely installs the gate on a real `Engine`.

    fn approvals_client() -> (Client, Arc<ApprovalCoordinator>) {
        let mut router = ModelRouter::new();
        router.register(Box::new(MockProvider));
        let engine = engine_with_defaults(router);
        let coordinator = Arc::new(ApprovalCoordinator::new());
        let client = Client::in_process_with_approvals(
            engine,
            SessionConfig::default(),
            coordinator.clone(),
            std::time::Duration::from_secs(5),
            Principal::user("u", &["chat.send"]),
            ClientConfig::default(),
        );
        (client, coordinator)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sdk_hitl_respond_approve_unblocks_the_gate() {
        use ainxt_runtime::approval::{
            ApprovalDecision as RtDecision, ApprovalGate, ApprovalRequest,
        };

        let (client, coordinator) = approvals_client();

        // A gated tool call inside the engine would block exactly like this — `decide()` on the SAME
        // shared coordinator, parked until the SDK delivers a decision or the timeout fires.
        let gate = WireApprovalGate::new(coordinator.clone(), std::time::Duration::from_secs(5));
        let decider = tokio::task::spawn_blocking(move || {
            gate.decide(&ApprovalRequest {
                session: "s-appr".into(),
                actor: "alice".into(),
                tool: "settle.payment".into(),
                args: "amount=100".into(),
            })
        });

        // Give the blocking task a moment to register its pending wait, then answer through the
        // client — the actual SDK write-side surface under test.
        let mut delivered = false;
        for _ in 0..50 {
            delivered = client.respond_approval(
                "s-appr",
                ApprovalRespond {
                    approval_id: "ap-1".into(),
                    decision: ainxt_protocol::ApprovalDecision::Approve,
                    feedback: None,
                },
            );
            if delivered {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            delivered,
            "respond_approval must deliver to the blocked gate"
        );

        let decision = decider.await.expect("decider joined");
        assert_eq!(
            decision,
            RtDecision::Approve,
            "an SDK approve must resume the blocked gate as Approve"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sdk_hitl_respond_reject_carries_feedback() {
        use ainxt_runtime::approval::{
            ApprovalDecision as RtDecision, ApprovalGate, ApprovalRequest,
        };

        let (client, coordinator) = approvals_client();
        let gate = WireApprovalGate::new(coordinator.clone(), std::time::Duration::from_secs(5));
        let decider = tokio::task::spawn_blocking(move || {
            gate.decide(&ApprovalRequest {
                session: "s-rej".into(),
                actor: "alice".into(),
                tool: "t".into(),
                args: "".into(),
            })
        });

        // A reject with NO feedback is refused by the shape invariant (never delivered).
        assert!(!client.respond_approval(
            "s-rej",
            ApprovalRespond {
                approval_id: "ap".into(),
                decision: ainxt_protocol::ApprovalDecision::Reject,
                feedback: None,
            },
        ));

        let mut delivered = false;
        for _ in 0..50 {
            delivered = client.respond_approval(
                "s-rej",
                ApprovalRespond {
                    approval_id: "ap".into(),
                    decision: ainxt_protocol::ApprovalDecision::Reject,
                    feedback: Some("not allowed".into()),
                },
            );
            if delivered {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(delivered, "a reject WITH feedback must deliver");
        assert_eq!(
            decider.await.expect("decider joined"),
            RtDecision::Reject("not allowed".to_string())
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sdk_hitl_respond_fails_closed_on_timeout() {
        use ainxt_runtime::approval::{
            ApprovalDecision as RtDecision, ApprovalGate, ApprovalRequest,
        };

        let (_client, coordinator) = approvals_client();
        // A short timeout with nobody ever answering must reject, never hang or silently approve.
        let gate = WireApprovalGate::new(coordinator, std::time::Duration::from_millis(50));
        let decision = tokio::task::spawn_blocking(move || {
            gate.decide(&ApprovalRequest {
                session: "s-timeout".into(),
                actor: "alice".into(),
                tool: "t".into(),
                args: "".into(),
            })
        })
        .await
        .expect("decider joined");
        assert!(
            matches!(decision, RtDecision::Reject(_)),
            "no SDK response before the deadline must fail closed: {decision:?}"
        );
    }

    #[test]
    fn respond_approval_without_a_coordinator_reports_not_delivered() {
        // A client built via the plain `Client::in_process` (no approvals wiring) must not panic and
        // must honestly report nothing was delivered.
        let mut router = ModelRouter::new();
        router.register(Box::new(MockProvider));
        let manager = Arc::new(SessionManager::new(
            Arc::new(engine_with_defaults(router)),
            SessionConfig::default(),
        ));
        let client = Client::in_process(
            manager,
            Principal::user("u", &["chat.send"]),
            ClientConfig::default(),
        );
        assert!(!client.respond_approval(
            "s",
            ApprovalRespond {
                approval_id: "a".into(),
                decision: ainxt_protocol::ApprovalDecision::Approve,
                feedback: None,
            },
        ));
    }

    // ---- harness engine bridge ----

    use ainxt_admission::{
        CapabilityAuthorizer, CapabilityGrant, HarnessManifest, HarnessOutcome, HarnessRuntime,
        HarnessStep, InMemoryHarnessAudit, RunContext, StepKind,
    };

    /// Emits a 16-digit PAN so the engine's compliance gate must redact it.
    struct PanProvider;
    impl Provider for PanProvider {
        fn id(&self) -> &str {
            "pan"
        }
        fn eligible(&self, _dc: DataClass) -> bool {
            true
        }
        fn stream(&self, _prompt: &str) -> mpsc::Receiver<Event> {
            let (tx, rx) = mpsc::channel(8);
            tokio::spawn(async move {
                let _ = tx
                    .send(Event::TextDelta("card 4111111111111111 noted".into()))
                    .await;
                let _ = tx
                    .send(Event::Usage {
                        input_tokens: 4,
                        output_tokens: 6,
                    })
                    .await;
                let _ = tx.send(Event::Done).await;
            });
            rx
        }
    }

    fn harness_runtime() -> HarnessRuntime {
        HarnessRuntime::new(
            Box::new(CapabilityAuthorizer),
            Box::new(InMemoryHarnessAudit::new()),
        )
    }

    fn step(id: &str, cap: &str, kind: StepKind) -> HarnessStep {
        HarnessStep {
            id: id.into(),
            kind,
            capability: cap.into(),
            estimated_tokens: 10,
            input: Some(format!("run {id}")),
        }
    }

    /// A client whose principal holds `caps`, over `provider`.
    fn client_with_caps(provider: impl Provider + 'static, caps: &[&str]) -> Client {
        let mut router = ModelRouter::new();
        router.register(Box::new(provider));
        let manager = Arc::new(SessionManager::new(
            Arc::new(engine_with_defaults(router)),
            SessionConfig::default(),
        ));
        Client::in_process(manager, Principal::user("u", caps), ClientConfig::default())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn harness_bridge_runs_steps_through_the_engine_and_redacts() {
        let client = client_with_caps(PanProvider, &["chat.send", "llm.call", "tool.grep"]);
        let rt = harness_runtime();
        let m = HarnessManifest::new(
            "rca",
            vec![
                step("s1", "llm.call", StepKind::Llm),
                step("s2", "tool.grep", StepKind::Tool),
            ],
        )
        .with_capabilities(["llm.call", "tool.grep"]);
        let grant = CapabilityGrant::new(["llm.call", "tool.grep"]);

        let report = client
            .run_harness(&rt, &m, &grant, &RunContext::internal(), "sess")
            .await;

        assert!(
            report.outcome.is_completed(),
            "harness must complete: {:?}",
            report.outcome
        );
        assert_eq!(report.step_outputs.len(), 2);
        // Compliance ran inside the engine for each step.
        assert!(
            report.redactions_observed >= 2,
            "each step's PAN must be redacted, got {}",
            report.redactions_observed
        );
        for out in &report.step_outputs {
            assert!(out.contains("[REDACTED-PAN]"), "PAN leaked: {out}");
            assert!(!out.contains("4111111111111111"));
        }
        assert_eq!(report.total_output_tokens, 12); // 6 per step * 2
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn harness_bridge_denies_ungranted_capability_before_any_turn() {
        // Step needs a capability the grant does not include → CapabilityDenied, no engine turn.
        let mut router = ModelRouter::new();
        router.register(Box::new(MockProvider));
        let manager = Arc::new(SessionManager::new(
            Arc::new(engine_with_defaults(router)),
            SessionConfig::default(),
        ));
        let client = Client::in_process(
            manager,
            Principal::user("u", &["chat.send", "tool.delete"]),
            ClientConfig::default(),
        );
        let rt = harness_runtime();
        let m = HarnessManifest::new("x", vec![step("s1", "tool.delete", StepKind::Tool)])
            .with_capabilities(["tool.delete"]);
        let grant = CapabilityGrant::new(["tool.grep"]); // delete NOT granted
        let report = client
            .run_harness(&rt, &m, &grant, &RunContext::internal(), "sess")
            .await;
        assert!(matches!(
            report.outcome,
            HarnessOutcome::CapabilityDenied { .. }
        ));
        assert!(
            report.step_outputs.is_empty(),
            "no engine turn may run for a denied step"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn harness_bridge_refuses_a_turn_above_the_data_class_ceiling() {
        let mut router = ModelRouter::new();
        router.register(Box::new(MockProvider));
        let manager = Arc::new(SessionManager::new(
            Arc::new(engine_with_defaults(router)),
            SessionConfig::default(),
        ));
        let client = Client::in_process(
            manager,
            Principal::user("u", &["chat.send", "llm.call"]).with_clearance(DataClass::Pii),
            ClientConfig::default(),
        );
        let rt = harness_runtime();
        let mut m = HarnessManifest::new("x", vec![step("s1", "llm.call", StepKind::Llm)])
            .with_capabilities(["llm.call"]);
        m.data_class_ceiling = DataClass::Internal;
        let grant = CapabilityGrant::new(["llm.call"]);
        let report = client
            .run_harness(
                &rt,
                &m,
                &grant,
                &RunContext::new(DataClass::RegulatedPayment),
                "sess",
            )
            .await;
        assert!(matches!(
            report.outcome,
            HarnessOutcome::DataClassExceeded { .. }
        ));
        assert!(report.step_outputs.is_empty());
    }

    // ---- HARN-02: a tool/skill step invokes its NAMED capability, not a bare chat turn ----

    use ainxt_admission::{
        AllowingApprovalResolver, Autonomy, DenyingApprovalResolver, HarnessStep as HStep,
    };

    /// Records every capability it was asked to run; returns a marker output so the test can tell an
    /// invoked capability from an engine chat turn.
    struct RecordingInvoker {
        seen: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }
    impl RecordingInvoker {
        fn new() -> Self {
            RecordingInvoker {
                seen: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            }
        }
        fn seen(&self) -> Vec<String> {
            self.seen.lock().unwrap().clone()
        }
    }
    impl CapabilityInvoker for RecordingInvoker {
        fn invoke<'a>(
            &'a self,
            step: &'a HStep,
            _p: &'a Principal,
            _dc: DataClass,
        ) -> CapabilityFuture<'a> {
            let cap = step.capability.clone();
            let seen = self.seen.clone();
            Box::pin(async move {
                seen.lock().unwrap().push(cap.clone());
                Ok(StepInvocation {
                    output: format!("QUERIED:{cap}"),
                    input_tokens: 2,
                    output_tokens: 3,
                    redactions: 0,
                })
            })
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn gap_ainxt_client_tool_step_invokes_named_capability_not_chat() {
        let client = client_with_caps(
            MockProvider,
            &["chat.send", "llm.call", "connector.postgres.query"],
        );
        let rt = harness_runtime();
        let m = HarnessManifest::new(
            "settlement-investigator",
            vec![
                step("s1", "llm.call", StepKind::Llm),
                step("s2", "connector.postgres.query", StepKind::Tool),
            ],
        )
        .with_capabilities(["llm.call", "connector.postgres.query"]);
        let grant = CapabilityGrant::new(["llm.call", "connector.postgres.query"]);
        let invoker = RecordingInvoker::new();

        let report = client
            .run_harness_with_invoker(
                &rt,
                &m,
                &grant,
                &RunContext::internal(),
                "sess",
                &invoker,
                &DenyingApprovalResolver, // read-only tool never needs approval
            )
            .await;

        assert!(report.outcome.is_completed(), "got {:?}", report.outcome);
        // The Llm step streamed through the engine; the Tool step ran its NAMED capability.
        assert_eq!(
            report.step_outputs[0], "hello",
            "llm step must be an engine turn"
        );
        assert_eq!(
            report.step_outputs[1], "QUERIED:connector.postgres.query",
            "tool step must invoke its declared capability, not a chat completion"
        );
        assert_eq!(invoker.seen(), vec!["connector.postgres.query".to_string()]);
        // Usage is summed across the engine turn (1 out) and the capability (3 out).
        assert_eq!(report.total_output_tokens, 1 + 3);
    }

    // ---- HARN-03 (SDK side): assisted-autonomy write requires HITL approval before the capability runs ----

    #[tokio::test(flavor = "multi_thread")]
    async fn gap_ainxt_client_autonomy_assisted_write_requires_approval() {
        let client = client_with_caps(MockProvider, &["chat.send", "connector.gitlab.create_mr"]);
        let rt = harness_runtime();
        let mut m = HarnessManifest::new(
            "mr-bot",
            vec![step("s1", "connector.gitlab.create_mr", StepKind::Tool)],
        )
        .with_capabilities(["connector.gitlab.create_mr"]);
        m.autonomy = Autonomy::Assisted;
        let grant = CapabilityGrant::new(["connector.gitlab.create_mr"]);

        // No approver wired (fail-closed) → the write is rejected and the capability never runs.
        let denied = RecordingInvoker::new();
        let report = client
            .run_harness_with_invoker(
                &rt,
                &m,
                &grant,
                &RunContext::internal(),
                "sess",
                &denied,
                &DenyingApprovalResolver,
            )
            .await;
        assert!(
            matches!(report.outcome, HarnessOutcome::ApprovalRejected { .. }),
            "got {:?}",
            report.outcome
        );
        assert!(
            denied.seen().is_empty(),
            "a rejected write must not invoke the capability"
        );

        // Human approves → the capability runs and the harness completes.
        let approved = RecordingInvoker::new();
        let report2 = client
            .run_harness_with_invoker(
                &rt,
                &m,
                &grant,
                &RunContext::internal(),
                "sess",
                &approved,
                &AllowingApprovalResolver,
            )
            .await;
        assert!(report2.outcome.is_completed(), "got {:?}", report2.outcome);
        assert_eq!(
            approved.seen(),
            vec!["connector.gitlab.create_mr".to_string()]
        );
    }

    // ---- R4: a PAN in a tool/connector step result is redacted BEFORE the next step sees it ----

    /// Step 1 (a connector) leaks a raw PAN in its result; step 2 records the `input` it was handed
    /// so the test can prove the next step only ever saw the redacted form.
    struct LeakThenRecordInvoker {
        inputs_seen: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }
    impl LeakThenRecordInvoker {
        fn new() -> Self {
            LeakThenRecordInvoker {
                inputs_seen: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            }
        }
        fn inputs_seen(&self) -> Vec<String> {
            self.inputs_seen.lock().unwrap().clone()
        }
    }
    impl CapabilityInvoker for LeakThenRecordInvoker {
        fn invoke<'a>(
            &'a self,
            step: &'a HStep,
            _p: &'a Principal,
            _dc: DataClass,
        ) -> CapabilityFuture<'a> {
            let cap = step.capability.clone();
            let input = step.input.clone().unwrap_or_default();
            let seen = self.inputs_seen.clone();
            Box::pin(async move {
                seen.lock().unwrap().push(input.clone());
                // The connector returns a RAW PAN and claims zero redactions (untrusted output).
                let output = if cap == "connector.postgres.query" {
                    "settlement acct 4111111111111111 pending".to_string()
                } else {
                    format!("grep-result over: {input}")
                };
                Ok(StepInvocation {
                    output,
                    input_tokens: 2,
                    output_tokens: 3,
                    redactions: 0,
                })
            })
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn r4_tool_result_redacted_before_next_step() {
        let client = client_with_caps(
            MockProvider,
            &["chat.send", "connector.postgres.query", "tool.grep"],
        );
        let rt = harness_runtime();
        let m = HarnessManifest::new(
            "settlement-investigator",
            vec![
                step("s1", "connector.postgres.query", StepKind::Tool),
                step("s2", "tool.grep", StepKind::Tool),
            ],
        )
        .with_capabilities(["connector.postgres.query", "tool.grep"]);
        let grant = CapabilityGrant::new(["connector.postgres.query", "tool.grep"]);
        let invoker = LeakThenRecordInvoker::new();

        // The default run path applies the mandatory step-result compliance gate.
        let report = client
            .run_harness_with_invoker(
                &rt,
                &m,
                &grant,
                &RunContext::internal(),
                "sess",
                &invoker,
                &DenyingApprovalResolver, // reads never need approval
            )
            .await;

        assert!(report.outcome.is_completed(), "got {:?}", report.outcome);

        // 1) The connector's raw PAN was redacted at the step-result boundary.
        assert!(
            report.step_outputs[0].contains("[REDACTED-PAN]"),
            "connector step-result PAN must be redacted: {}",
            report.step_outputs[0]
        );
        assert!(!report.step_outputs[0].contains("4111111111111111"));
        assert!(
            report.redactions_observed >= 1,
            "the redaction must be observed, got {}",
            report.redactions_observed
        );

        // 2) THE PROOF: the NEXT step (s2) was handed only the redacted output — never the raw PAN.
        let seen = invoker.inputs_seen();
        assert_eq!(seen.len(), 2);
        assert!(
            seen[1].contains("[REDACTED-PAN]"),
            "next step must receive the redacted prior output: {}",
            seen[1]
        );
        assert!(
            !seen[1].contains("4111111111111111"),
            "the raw PAN must never reach the next step: {}",
            seen[1]
        );
    }

    // ---- r15: harness `model_policy` + `context.namespace` shape the engine request ----

    use ainxt_types::Tier;

    /// A provider identified by `pid` that always answers with `text`, optionally pinned to `tier`.
    struct NamedProvider {
        pid: &'static str,
        tier: Option<Tier>,
        text: &'static str,
    }
    impl Provider for NamedProvider {
        fn id(&self) -> &str {
            self.pid
        }
        fn eligible(&self, _dc: DataClass) -> bool {
            true
        }
        fn tier(&self) -> Option<Tier> {
            self.tier
        }
        fn stream(&self, _prompt: &str) -> mpsc::Receiver<Event> {
            let (tx, rx) = mpsc::channel(8);
            let text = self.text.to_string();
            tokio::spawn(async move {
                let _ = tx.send(Event::TextDelta(text)).await;
                let _ = tx.send(Event::Done).await;
            });
            rx
        }
    }

    /// A client over TWO registered providers (`cheap` registered first — the router's baseline
    /// choice absent any preference/pin — then `smart`, tiered `Complex`).
    fn client_with_two_providers() -> Client {
        let mut router = ModelRouter::new();
        router.register(Box::new(NamedProvider {
            pid: "cheap",
            tier: None,
            text: "cheap-answer",
        }));
        router.register(Box::new(NamedProvider {
            pid: "smart",
            tier: Some(Tier::Complex),
            text: "smart-answer",
        }));
        let manager = Arc::new(SessionManager::new(
            Arc::new(engine_with_defaults(router)),
            SessionConfig::default(),
        ));
        Client::in_process(
            manager,
            Principal::user("u", &["chat.send", "llm.call"]),
            ClientConfig::default(),
        )
    }

    #[test]
    fn r15_resolve_model_policy_maps_tiers_and_explicit_ids() {
        // A bare tier name resolves to that tier with no forced provider.
        assert_eq!(
            ainxt_admission::resolve_model_policy("simple"),
            (Tier::Simple, None)
        );
        assert_eq!(
            ainxt_admission::resolve_model_policy("Medium"),
            (Tier::Medium, None)
        );
        assert_eq!(
            ainxt_admission::resolve_model_policy("  complex "),
            (Tier::Complex, None)
        );
        // Anything else is an explicit model/provider id: Complex floor + forced pin.
        assert_eq!(
            ainxt_admission::resolve_model_policy("claude-sonnet-4-6"),
            (Tier::Complex, Some("claude-sonnet-4-6".to_string()))
        );
    }

    #[test]
    fn r15_engine_request_for_carries_model_policy_and_namespace() {
        let mut m = HarnessManifest::new("h", vec![]);
        m.model_policy = Some("smart".to_string());
        m.context = Some(ainxt_admission::HarnessContext {
            namespace: Some("settlement".to_string()),
        });
        let req = Client::engine_request_for(&m, "s1", "t1", "hi", DataClass::Internal);
        assert_eq!(req.tier, Tier::Complex);
        assert_eq!(req.forced_provider, Some("smart".to_string()));
        assert_eq!(req.namespace, Some("settlement".to_string()));

        // A bare-tier policy narrows the floor with NO forced provider.
        let mut m2 = HarnessManifest::new("h2", vec![]);
        m2.model_policy = Some("simple".to_string());
        let req2 = Client::engine_request_for(&m2, "s", "t", "hi", DataClass::Internal);
        assert_eq!(req2.tier, Tier::Simple);
        assert_eq!(req2.forced_provider, None);

        // Unset model_policy/namespace leaves the pre-existing defaults untouched (no regression).
        let m3 = HarnessManifest::new("h3", vec![]);
        let req3 = Client::engine_request_for(&m3, "s", "t", "hi", DataClass::Internal);
        assert_eq!(req3.tier, Tier::Simple);
        assert_eq!(req3.forced_provider, None);
        assert_eq!(req3.namespace, None);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn r15_harness_model_policy_pins_an_explicit_provider_end_to_end() {
        // model_policy names the EXACT provider id `smart` — the engine turn must be pinned to it
        // even though `cheap` was registered first (the router's baseline pick with no preference).
        let client = client_with_two_providers();
        let rt = harness_runtime();
        let mut m = HarnessManifest::new("pin", vec![step("s1", "llm.call", StepKind::Llm)])
            .with_capabilities(["llm.call"]);
        m.model_policy = Some("smart".to_string());
        let grant = CapabilityGrant::new(["llm.call"]);
        let report = client
            .run_harness(&rt, &m, &grant, &RunContext::internal(), "sess-pin")
            .await;
        assert!(report.outcome.is_completed(), "got {:?}", report.outcome);
        assert_eq!(report.step_outputs, vec!["smart-answer".to_string()]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn r15_harness_model_policy_tier_prefers_a_matching_provider_end_to_end() {
        // model_policy is a BARE TIER ("complex") — no forced pin, but the router's tier preference
        // must move the Complex-tiered `smart` provider ahead of `cheap` (registered first).
        let client = client_with_two_providers();
        let rt = harness_runtime();
        let mut m = HarnessManifest::new("tier", vec![step("s1", "llm.call", StepKind::Llm)])
            .with_capabilities(["llm.call"]);
        m.model_policy = Some("complex".to_string());
        let grant = CapabilityGrant::new(["llm.call"]);
        let report = client
            .run_harness(&rt, &m, &grant, &RunContext::internal(), "sess-tier")
            .await;
        assert!(report.outcome.is_completed(), "got {:?}", report.outcome);
        assert_eq!(report.step_outputs, vec!["smart-answer".to_string()]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn r15_harness_with_no_model_policy_keeps_the_baseline_route() {
        // No model_policy set: the baseline route (no preference) picks `cheap` — proving the new
        // wiring is a no-op when a manifest never declares a model policy (no regression).
        let client = client_with_two_providers();
        let rt = harness_runtime();
        let m = HarnessManifest::new("baseline", vec![step("s1", "llm.call", StepKind::Llm)])
            .with_capabilities(["llm.call"]);
        let grant = CapabilityGrant::new(["llm.call"]);
        let report = client
            .run_harness(&rt, &m, &grant, &RunContext::internal(), "sess-base")
            .await;
        assert!(report.outcome.is_completed(), "got {:?}", report.outcome);
        assert_eq!(report.step_outputs, vec!["cheap-answer".to_string()]);
    }
}
