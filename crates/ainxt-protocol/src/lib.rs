// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! ainxt-protocol — the versioned command/event contract every renderer + SDK depends on.
//! Design: `docs/architecture/PROTOCOL.md`, ADR-005. Pure types (no I/O), so clients link
//! this without pulling the engine (protocol-first, ADR-001).
//!
//! # Two layers (PROTOCOL.md §2)
//!
//! * The **wire contract** — [`CommandEnvelope`] wrapping a typed [`Command`] (client → runtime,
//!   §4.1/§5) and [`EventEnvelope`] wrapping a typed [`WireEvent`] (runtime → client, §4.2/§6).
//!   These are the normative message shapes and carry the ordering/idempotency/resume machinery.
//! * A **legacy in-proc pair** — [`Request`]/[`Event`] — the first-cut single-turn types the current
//!   engine, server, and in-proc client are already wired to. They are retained verbatim so those
//!   crates keep compiling; new work targets the wire contract above, which the parent migrates the
//!   engine/server onto (see the `needs_wiring` notes in the gap tracker).
//!
//! # Versioning (PROTOCOL.md §10)
//!
//! `protocol/MAJOR.MINOR.PATCH`. MINOR is **additive-only** and safe for old clients via the
//! must-ignore rule (§10.3): unknown event/command `type`s and unknown body fields are ignored,
//! never fatal. Enums are `#[non_exhaustive]` (§10.5) and the tagged wire enums carry an explicit
//! `Unknown` fallthrough so an old deserializer never rejects a newer peer. The runtime supports its
//! current major **plus the two prior majors** (N-2 window, §10.2), negotiated at `session.open`.

use ainxt_types::{DataClass, Tier};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Versioning (PROTOCOL.md §10) — additive-safe, must-ignore, N-2 window, negotiation.
// ---------------------------------------------------------------------------

/// Legacy coarse protocol major used by the in-proc [`Request`]/[`Event`] path. Retained for the
/// crates already built against it; new work uses [`PROTOCOL_VERSION`] (semver) instead.
pub const VERSION: u32 = 1;

/// How many *prior* majors the runtime keeps supporting alongside the current one (§10.2).
/// N-2 → the current major and the two before it are all acceptable. Sized as a policy knob
/// (ADR-004 config layering); exposed here as the contract's default.
pub const SUPPORTED_MAJOR_WINDOW: u32 = 2;

/// The current semantic protocol version this crate defines (PROTOCOL.md §10.1).
pub const PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion { major: 1, minor: 0 };

/// A semantic protocol version (`MAJOR.MINOR`; PATCH is doc-only and not carried on the wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ProtocolVersion {
    pub major: u32,
    pub minor: u32,
}

impl ProtocolVersion {
    pub const fn new(major: u32, minor: u32) -> Self {
        ProtocolVersion { major, minor }
    }
}

impl core::fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

impl core::str::FromStr for ProtocolVersion {
    type Err = VersionParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut it = s.trim().splitn(3, '.');
        let major = it.next().ok_or(VersionParseError)?;
        let minor = it.next().unwrap_or("0");
        // A PATCH segment (if present) is accepted and ignored — it is not a wire-affecting field.
        let major: u32 = major.parse().map_err(|_| VersionParseError)?;
        let minor: u32 = minor.parse().map_err(|_| VersionParseError)?;
        Ok(ProtocolVersion { major, minor })
    }
}

/// Parsing a malformed `"MAJOR.MINOR"` string failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionParseError;

impl core::fmt::Display for VersionParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("malformed protocol version (expected MAJOR.MINOR)")
    }
}

impl std::error::Error for VersionParseError {}

/// Whether a client built against major `client` can talk to a runtime speaking major `server`,
/// under the N-2 window (§10.2). A client that is *newer* than the runtime, or older than the
/// window, is refused cleanly (never a partial/corrupt session).
///
/// This supersedes the old exact-match rule (gap TURN-06): additive MINORs interoperate, and up to
/// two prior majors are still accepted.
pub fn is_compatible(client: u32, server: u32) -> bool {
    client <= server && client >= server.saturating_sub(SUPPORTED_MAJOR_WINDOW)
}

/// Outcome of the `session.open` handshake (PROTOCOL.md §10.2). Negotiation picks the **highest
/// common version** both sides can speak, or refuses with [`ErrorCategory::ProtocolIncompatible`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Negotiation {
    /// Both sides speak this version for the session's life.
    Agreed(ProtocolVersion),
    /// The client is outside the supported window; the runtime returns `protocol_incompatible`
    /// with the human-facing supported range.
    Incompatible { supported: String },
}

/// Negotiate the session protocol version (§10.2). `client` is the version from the handshake;
/// `server` is [`PROTOCOL_VERSION`] (or a config-overridden value). N-2 window applies to the major.
///
/// * client newer than the runtime → refused (a runtime cannot honor a future contract).
/// * client older than `server.major - N` → refused.
/// * otherwise → the highest version both can speak = `min(client, server)` (lexicographic on
///   `(major, minor)`), so a `1.2` client on a `1.7` runtime settles on `1.2`.
pub fn negotiate(client: ProtocolVersion, server: ProtocolVersion) -> Negotiation {
    if !is_compatible(client.major, server.major) {
        return Negotiation::Incompatible {
            supported: supported_range(server),
        };
    }
    Negotiation::Agreed(core::cmp::min(client, server))
}

/// Human-facing supported-major range string, e.g. `"protocol range 2.x–4.x; update your client"`.
pub fn supported_range(server: ProtocolVersion) -> String {
    let lo = server.major.saturating_sub(SUPPORTED_MAJOR_WINDOW);
    format!(
        "supported protocol range {lo}.x-{hi}.x; update your client",
        hi = server.major
    )
}

// ---------------------------------------------------------------------------
// GAP-AUDIT transport-daemon #3 — the §10 deprecation window: a machine-readable marker (previously
// NONE existed anywhere — only prose doc comments nobody could check) plus the N/N+1 coexistence
// guarantee it depends on.
// ---------------------------------------------------------------------------

/// A machine-readable deprecation marker for a wire event/command surface (PROTOCOL.md §10). `since`
/// is the protocol `"MAJOR.MINOR"` the surface was first marked deprecated; `reason` names its
/// successor. Deprecating a surface is a MARKER ONLY — it never stops working the moment it's
/// deprecated; [`SUPPORTED_MAJOR_WINDOW`] (the N-2 major window, §10.2) is the actual removal floor,
/// so an "N" client built against the deprecated surface keeps functioning, byte-identically,
/// throughout the ENTIRE deprecation window, while an "N+1" client (or a CI/docs tool) can query
/// [`deprecation_notice`] to warn a developer or route around it before an eventual removal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DeprecationNotice {
    pub since: &'static str,
    pub reason: &'static str,
}

/// The registry of deprecated wire event/command surfaces, keyed by a STABLE identifier — a wire
/// `type` discriminator for a [`WireEvent`]/[`Command`] variant (e.g. `"turn.edit"`), or, for a
/// surface that predates per-type wire tags, its Rust path (e.g. `"ainxt_protocol::Event"`). `None` =
/// not deprecated. Additive-only: entries are appended here as real deprecations happen and are never
/// removed retroactively (the surface's own eventual removal, once it falls outside
/// [`SUPPORTED_MAJOR_WINDOW`], is a separate later change) — this function is the single source of
/// truth a client/tool queries instead of grepping doc comments for the word "legacy".
///
/// Seeded with the ONE real deprecation this crate already had in PROSE but never enforced
/// mechanically: the "legacy in-proc pair" ([`Request`]/[`Event`], see the module doc) — fully
/// superseded by the versioned wire contract ([`CommandEnvelope`]/[`Command`] in,
/// [`EventEnvelope`]/[`WireEvent`] out, §4/§5/§6) but retained verbatim for crates not yet migrated.
pub fn deprecation_notice(surface: &str) -> Option<DeprecationNotice> {
    match surface {
        "ainxt_protocol::Event" => Some(DeprecationNotice {
            since: "1.0",
            reason: "superseded by EventEnvelope/WireEvent (§4.2/§6); retained only for crates not yet migrated onto the wire contract",
        }),
        "ainxt_protocol::Request" => Some(DeprecationNotice {
            since: "1.0",
            reason: "superseded by CommandEnvelope/Command (§4.1/§5); retained only for crates not yet migrated onto the wire contract",
        }),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// §4 Envelopes — the stable ordering/idempotency/resume machinery (gap TURN-02).
// ---------------------------------------------------------------------------

/// Command envelope (client → runtime, PROTOCOL.md §4.1). Wraps a typed [`Command`] body with the
/// idempotency + attribution fields the runtime's dedup ledger (ADR-013) and total-order actor
/// depend on. Auth (the JWT) travels in the transport's auth channel, **not** here; `participant_id`
/// is derived from the validated JWT `sub` by the Identity+Policy gate, never trusted from the body.
///
/// GAP-AUDIT protocol #1 (investigated, no wire change) — this type is a **design-reference shape**,
/// not deserialized verbatim by `POST /v1/command`: `ainxt-server`'s served route deserializes its own
/// `CommandRequest` DTO instead, which does not literally carry a top-level `protocol_version` field.
/// Investigated whether that's a real gap (an incompatible/unnegotiated client silently accepted) and
/// found it is not, because this envelope's own two load-bearing guarantees are already provided on
/// the real served path by separate, equivalent mechanisms:
///   * **`command_id` exactly-once dedup (ADR-013).** `CommandRequest` carries its own
///     `command_id: Option<String>`, and `command_handler` begins/commits it against
///     `ainxt_serving::idempotency::IdempotencyLedger` *before* dispatch — proven by
///     `ainxt-server/tests/r13_command_id_dedup.rs` over a real served `POST /v1/command`.
///   * **`protocol_version` negotiation (§10.2).** PROTOCOL.md §10.2 is explicit that negotiation
///     happens exactly once, at `session.open`, and both sides then speak that version for the
///     session's life — there is no per-command re-negotiation in the spec. `Command::SessionOpen`
///     carries `client_protocol_version`, and `command_dispatch` calls the real `negotiate()` against
///     it, refusing `protocol_incompatible` outside the N-2 window — proven by
///     `ainxt-server/tests/r13_session_open_negotiation.rs` over the same real served route.
/// `participant_id` is likewise never taken from either DTO's body — both this type's doc comment and
/// the actual `command_dispatch` code derive it from the authenticated `Principal` (JWT `sub`), so
/// there is no divergence there either. Conclusion: migrating `/v1/command` onto this struct verbatim
/// would be a breaking wire-format change (its shape is not backward-compatible with `CommandRequest`
/// as actually deployed — e.g. `session` vs. `session_id`, and `session_id` is documented as
/// server-minted/omitted on `session.open` while `CommandRequest.session` is always client-supplied)
/// for **zero** functional gain, since both audit-flagged guarantees are already real and tested. No
/// code change made for this item; this type remains the normative reference shape new transports
/// (gRPC/WebSocket, PROTOCOL.md §8) should target, and existing crates keep their own equivalent DTOs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandEnvelope {
    /// Client's protocol version; negotiated at `session.open` (§10.2). String form (`"1.0"`).
    pub protocol_version: String,
    /// Client-minted UUID; the exactly-once dedup key (ADR-013, I7). A re-delivered command with a
    /// seen `command_id` is acknowledged as a no-op, never re-applied.
    pub command_id: String,
    /// Omitted only on `session.open` (which mints one).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Resolved from the JWT `sub`; total-orders multi-writer collaboration.
    /// Checkmarx CX-FP: renamed to `actor_id`; `#[serde(rename)]` preserves the wire key.
    #[serde(rename = "participant_id")]
    pub actor_id: String,
    /// The typed command; its `type` discriminator and fields flatten onto the envelope (§4.1).
    #[serde(flatten)]
    pub command: Command,
}

/// Event envelope (runtime → client, PROTOCOL.md §4.2). Wraps a typed [`WireEvent`] body with the
/// `seq` ordering/resume cursor, timestamp, and `control_plane_sha` reproducibility pin.
///
/// (No `Eq` — [`WireEvent::Usage`] carries a floating-point `cost`; `PartialEq` is sufficient.)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EventEnvelope {
    /// Schema version of THIS event's body (§10). String form (`"1.0"`).
    pub v: String,
    pub session_id: String,
    /// Present for turn-scoped events; absent for session-scoped (e.g. `participant.*`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub turn_id: Option<String>,
    /// Present only when the turn belongs to a Program (§3.3); a client that doesn't speak
    /// `program.*` still renders the underlying turn.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub program_id: Option<String>,
    /// Per-session strictly-monotonic sequence — gap detection + resume (§7.2).
    pub seq: u64,
    /// RFC-3339 timestamp of emission.
    pub ts: String,
    /// The control-repo commit the turn is pinned to (ADR-026 §6.2) — reproducibility. The same
    /// value the Event Log records, so live rendering and audit agree.
    pub control_plane_sha: String,
    /// The typed event; its `type` discriminator and fields flatten onto the envelope (§4.2).
    #[serde(flatten)]
    pub event: WireEvent,
}

impl EventEnvelope {
    /// Convenience constructor for a turn-scoped event.
    pub fn turn(
        session_id: &str,
        turn_id: &str,
        seq: u64,
        ts: &str,
        control_plane_sha: &str,
        event: WireEvent,
    ) -> Self {
        EventEnvelope {
            v: PROTOCOL_VERSION.to_string(),
            session_id: session_id.to_string(),
            turn_id: Some(turn_id.to_string()),
            program_id: None,
            seq,
            ts: ts.to_string(),
            control_plane_sha: control_plane_sha.to_string(),
            event,
        }
    }
}

// ---------------------------------------------------------------------------
// §5 The Command set (client → runtime) — gap TURN-03.
// ---------------------------------------------------------------------------

/// The typed command family (PROTOCOL.md §5). Complete for v1. `#[non_exhaustive]` (§10.5) so
/// adding a command in a MINOR is non-breaking; the `Unknown` variant captures a `type` an older
/// runtime doesn't recognize so deserialization never fails (the runtime then answers
/// `error{category: invalid_command}`).
///
/// **Load-bearing absence (§9/I1, ADR-016):** there is deliberately no command that dispatches a
/// payment, moves value, or bypasses a gate. The boundary is enforced by the *shape* of this enum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
#[non_exhaustive]
pub enum Command {
    /// Start a new session for a Surface Profile. Mints `session_id`. Carries the handshake.
    #[serde(rename = "session.open")]
    SessionOpen {
        profile_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        client_info: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        capabilities_wanted: Vec<String>,
        /// GAP-AUDIT transport-daemon #1/#2 — the client's protocol version (`"major.minor"`,
        /// §10.2). Omitted = the client speaks whatever `PROTOCOL_VERSION` this build ships
        /// (pre-negotiation clients); present = the runtime calls [`negotiate`] against its own
        /// [`PROTOCOL_VERSION`] and refuses `protocol_incompatible` outside the N-2 major window.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        client_protocol_version: Option<String>,
    },
    /// Re-attach after disconnect, or continue tomorrow. `from_event` = last-seen `seq`; omitted =
    /// full snapshot only (`ainxt run --continue`). Drives the tail-replay of §7.2 (gap TURN-05).
    #[serde(rename = "session.resume")]
    SessionResume {
        session_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        from_event: Option<u64>,
    },
    /// Read-only tail for a dashboard / `ainxt session watch`. Cannot submit turns.
    #[serde(rename = "session.subscribe")]
    SessionSubscribe {
        session_id: String,
        mode: SubscribeMode,
    },
    /// Explicit branch to explore an alternative without touching the official line.
    #[serde(rename = "session.fork")]
    SessionFork {
        session_id: String,
        from_turn_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
    },
    /// Ends the live actor; Event Log retained (ADR-015).
    #[serde(rename = "session.close")]
    SessionClose { session_id: String },
    /// The main verb. `overrides` may request a user-selectable model (honored subject to ADR-012
    /// class-eligibility — never overrides a data-class exclusion).
    #[serde(rename = "turn.submit")]
    TurnSubmit {
        input: TurnInput,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        overrides: Option<TurnOverrides>,
    },
    /// Queued interjection, delivered at next safe boundary — **not** a cancel (§3.2).
    #[serde(rename = "turn.steer")]
    TurnSteer { turn_id: String, text: String },
    /// The **only** cancel. Fires the shared cancellation token (§7.1). Idempotent; always
    /// available from any authorized participant. See [`is_cancel_command`] (gap TURN-04).
    #[serde(rename = "turn.stop")]
    TurnStop { turn_id: String },
    /// Valid only on a *user* turn; creates a sibling branch, never mutates history.
    #[serde(rename = "turn.edit")]
    TurnEdit { turn_id: String, input: TurnInput },
    /// Named fork kept as a turn-level verb for renderers that branch from within a turn view.
    #[serde(rename = "turn.branch")]
    TurnBranch {
        from_turn_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
    },
    /// Answers an `approval.request`. `reject` requires `feedback` (becomes model-visible tool
    /// output). **Never valid as a policy auto-decision for a `payment_boundary != none` action**
    /// (§9, ADR-016) — enforced by [`ApprovalRespond::is_valid`].
    #[serde(rename = "approval.respond")]
    ApprovalRespond(ApprovalRespond),
    /// Long-horizon program control (ADR-027, §6.6). Additive; a client that doesn't speak these
    /// never needs to (I6).
    #[serde(rename = "program.start")]
    ProgramStart {
        program_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        spec: Option<String>,
    },
    #[serde(rename = "program.pause")]
    ProgramPause { program_id: String },
    #[serde(rename = "program.resume")]
    ProgramResume { program_id: String },
    #[serde(rename = "program.checkpoint.respond")]
    ProgramCheckpointRespond {
        program_id: String,
        checkpoint_id: String,
        decision: ApprovalDecision,
    },
    /// Must-ignore fallthrough (§10.3): a `type` this build doesn't recognize. The runtime answers
    /// `error{category: invalid_command}` rather than crashing.
    #[serde(other)]
    Unknown,
}

/// Body of `approval.respond` (§5). Split out so the payment-boundary invariant can be validated
/// as a method without duplicating the tri-state decision across call sites.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRespond {
    pub approval_id: String,
    pub decision: ApprovalDecision,
    /// Required (and model-visible) when `decision == Reject`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub feedback: Option<String>,
}

impl ApprovalRespond {
    /// Validate this response against the gated action's `payment_boundary` (PROTOCOL.md §9,
    /// ADR-016). `is_policy_auto` is `true` when the decision was produced by a policy/SDK default
    /// rather than a live human. Rules:
    ///
    /// * `reject` **must** carry `feedback`.
    /// * a `payment_boundary != none` action can be cleared **only** by a human `approve`
    ///   (`approve_for_session` and any policy auto-decision are refused for payments).
    pub fn is_valid(
        &self,
        boundary: PaymentBoundary,
        is_policy_auto: bool,
    ) -> Result<(), ProtocolError> {
        if matches!(self.decision, ApprovalDecision::Reject) && self.feedback.is_none() {
            return Err(ProtocolError::new(
                ErrorCategory::InvalidCommand,
                "approval.respond{reject} requires feedback",
            ));
        }
        if boundary != PaymentBoundary::None {
            let human_approve =
                matches!(self.decision, ApprovalDecision::Approve) && !is_policy_auto;
            if !human_approve {
                return Err(ProtocolError::new(
                    ErrorCategory::CapabilityDenied,
                    "payment_boundary action requires an explicit human approve (§9, ADR-016)",
                ));
            }
        }
        Ok(())
    }
}

/// Read-only subscription mode (§5). Its own enum so a future `mode` is additive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SubscribeMode {
    Observer,
}

/// The tri-state approval decision (§5; clean-room vocabulary, PROTOCOL.md §14).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ApprovalDecision {
    Approve,
    ApproveForSession,
    Reject,
}

/// A `turn.submit`/`turn.edit` input: text plus attachments (§5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TurnInput {
    pub text: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<Attachment>,
}

impl TurnInput {
    pub fn text(text: &str) -> Self {
        TurnInput {
            text: text.to_string(),
            attachments: Vec::new(),
        }
    }
}

/// An input attachment reference (§5). The bytes live in the Artifact/Context runtime; the wire
/// carries a reference, never inlined regulated payloads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attachment {
    pub kind: String,
    pub uri: String,
}

/// Power-user overrides on `turn.submit` (§5). A forced model is still subject to the
/// non-overridable data-class exclusion (ADR-012).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TurnOverrides {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forced_model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<Tier>,
}

// ---------------------------------------------------------------------------
// §6 The typed Event vocabulary (runtime → client) — gaps TURN-07, TURN-08.
// ---------------------------------------------------------------------------

/// The typed wire-event family (PROTOCOL.md §6). Internally tagged by `type` so it flattens cleanly
/// into [`EventEnvelope`] (the `type` discriminator and body fields sit at the envelope top level;
/// §4.2's `body` grouping is illustrative — see the doc's IDL disclaimer). `#[non_exhaustive]`
/// (§10.5) and carries an explicit `Unknown` fallthrough implementing the must-ignore rule (§10.3):
/// a renderer built against an older MINOR deserializes a newer event into `Unknown` — ignoring its
/// unknown fields — and skips it, instead of erroring the session.
///
/// (No `Eq` — [`WireEvent::Usage`] carries a floating-point `cost`; `PartialEq` is sufficient.)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type")]
#[non_exhaustive]
pub enum WireEvent {
    // -- §6.1 Content --------------------------------------------------------
    /// A fragment of assistant prose. Concatenate in `seq` order.
    #[serde(rename = "text.delta")]
    TextDelta { text: String },
    /// A fragment of model reasoning/"thinking". **Policy-gated** — only streamed to surfaces/roles
    /// the Policy Engine permits (ADR-003); withheld otherwise.
    #[serde(rename = "reasoning.delta")]
    ReasoningDelta { text: String },

    // -- §6.2 Tool-call lifecycle (always structured, never model-text — I2) --
    /// A tool call is beginning; name is known, args may still stream. `source` is a display label
    /// only — dispatch treats native/mcp/skill identically (ADR-002).
    #[serde(rename = "tool.call.start")]
    ToolCallStart {
        call_id: String,
        name: String,
        source: ToolSource,
    },
    /// A fragment of the tool's argument JSON as it streams from the model.
    #[serde(rename = "tool.call.delta")]
    ToolCallDelta { call_id: String, args_delta: String },
    /// Arguments fully parsed and validated against the tool's schema; ready to dispatch.
    #[serde(rename = "tool.call.stop")]
    ToolCallStop { call_id: String, args: String },
    /// The observation fed back to the model. `is_error=true` is a *soft* failure fed back to the
    /// model, **not** a turn abort.
    #[serde(rename = "tool.result")]
    ToolResult {
        call_id: String,
        blocks: Vec<ResultBlock>,
        is_error: bool,
    },

    // -- §6.3 Gate events (approval + compliance) ----------------------------
    /// The turn is blocked awaiting a decision (Approval Gate, ADR-003). If `payment_boundary !=
    /// none`, an auto/policy decision is refused — a human `approve` is mandatory (§9).
    #[serde(rename = "approval.request")]
    ApprovalRequest {
        approval_id: String,
        action: String,
        scope: String,
        risk_tier: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        preview: Option<String>,
        payment_boundary: PaymentBoundary,
    },
    /// Tells the renderer *what class* was redacted or audited — never the raw content (I4). This is
    /// how a user learns "an account number was redacted and the turn proceeded" without the wire
    /// ever carrying the PII (gap TURN-08).
    #[serde(rename = "compliance.notice")]
    ComplianceNotice {
        categories: Vec<String>,
        action: ComplianceAction,
    },

    // -- §6.4 Artifact + accounting ------------------------------------------
    /// A produced artifact reference (docx/pptx/pdf/xlsx/image/source). `verification` carries the
    /// post-generation artifact-vs-intent check.
    #[serde(rename = "artifact")]
    Artifact {
        artifact_id: String,
        kind: String,
        uri: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        preview: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        verification: Option<ArtifactVerification>,
    },
    /// Token/cost accounting. `model` is the **actually-routed** model (ADR-006/012) — never a
    /// placeholder — so a class-ineligible model can never appear here for a regulated turn.
    #[serde(rename = "usage")]
    Usage {
        model: String,
        input_tokens: u64,
        output_tokens: u64,
        cost: f64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cached: Option<bool>,
    },

    // -- §6.5 Lifecycle, error, presence -------------------------------------
    /// Full current state to a (re)joining client (§7.2). Sent in response to
    /// `session.open`/`resume`/`subscribe`/`fork`.
    #[serde(rename = "session.snapshot")]
    SessionSnapshot {
        tree: SessionTree,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        active_head: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        participants: Vec<Participant>,
        negotiated_version: String,
    },
    /// A turn entered RUNNING. The envelope's `control_plane_sha` pins this turn's definitions.
    #[serde(rename = "turn.started")]
    TurnStarted {
        turn_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        parent_turn_id: Option<String>,
        participant_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        model_hint: Option<String>,
    },
    /// The "why this" panel, generated from the Event Log's own trace — audit-grade for free.
    #[serde(rename = "turn.rationale")]
    TurnRationale {
        turn_id: String,
        model_tier: String,
        model: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        capabilities: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        sources: Vec<String>,
    },
    /// Turn ended. `outcome ∈ {complete, capped}` — `capped` is the honest "judge could not confirm
    /// done", **not** a failure (gap TURN-07: the previously-missing typed outcome).
    #[serde(rename = "turn.completed")]
    TurnCompleted {
        turn_id: String,
        outcome: TurnOutcome,
    },
    /// Turn cancelled by `turn.stop`; audit-visible, never deleted.
    #[serde(rename = "turn.stopped")]
    TurnStopped { turn_id: String },
    /// Turn ended with a typed, turn-scoped error (§6.5.1).
    #[serde(rename = "turn.failed")]
    TurnFailed {
        turn_id: String,
        error: ProtocolError,
    },
    /// Echo of a `turn.steer` command onto the stream so *every* subscriber sees the interjection.
    #[serde(rename = "turn.steer")]
    TurnSteer { turn_id: String, text: String },
    /// Echo of a `turn.edit` command (new sibling branch).
    #[serde(rename = "turn.edit")]
    TurnEdit { turn_id: String },
    /// Echo of a `turn.branch` command.
    #[serde(rename = "turn.branch")]
    TurnBranch {
        from_turn_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
    },
    /// A **session/stream-level** error (not turn-scoped) — e.g. `protocol_incompatible` at
    /// handshake, `capacity` backpressure before a turn starts, `invalid_command`. Distinct from
    /// [`WireEvent::TurnFailed`] (which is a turn outcome).
    #[serde(rename = "error")]
    Error(ProtocolError),
    /// Presence, broadcast over the same stream. Advisory only — never a lock.
    #[serde(rename = "participant.joined")]
    ParticipantJoined {
        participant_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        turn_id: Option<String>,
    },
    #[serde(rename = "participant.left")]
    ParticipantLeft { participant_id: String },
    #[serde(rename = "participant.typing")]
    ParticipantTyping {
        participant_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        turn_id: Option<String>,
    },
    #[serde(rename = "participant.viewing")]
    ParticipantViewing {
        participant_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        turn_id: Option<String>,
    },

    // -- §6.6 Program (long-horizon) lifecycle ---------------------------------
    // GAP-AUDIT turn-pipeline #8 — `program.*` commands (`Command::ProgramStart`/`ProgramPause`)
    // previously returned a bare ack with no corresponding wire notification, so a session observer
    // (`GET /v1/observe`) or a resuming client (`GET /v1/events`) had no durable record a program's
    // lifecycle actually changed (PROTOCOL.md §6.6 / the Program event table). These two are the
    // state-transition notifications the table defines for the two commands that have a direct 1:1
    // ack->event mapping; `program.resume` and `program.checkpoint.respond` are not in that table
    // (a resumed program simply continues emitting normal per-module `turn.*` events, and a
    // checkpoint-respond is the client answering a prior `program.checkpoint.request`, not itself a
    // new fact to broadcast) so they remain ack-only, unchanged.
    /// A long-horizon Program (ADR-027, `LONG_HORIZON_PROGRAMS.md`) began executing.
    #[serde(rename = "program.started")]
    ProgramStarted { program_id: String },
    /// A long-horizon Program was paused (its Supervisor stops admitting new module Runs).
    #[serde(rename = "program.paused")]
    ProgramPaused { program_id: String },

    /// Must-ignore fallthrough (§10.3, I6): an event `type` this build does not recognize. A
    /// conforming renderer skips it and never errors the session. This is the structural guarantee
    /// that a `1.2` client keeps working against a `1.7` runtime.
    #[serde(other)]
    Unknown,
}

/// Display label for a tool call's origin (§6.2). Dispatch is source-agnostic (ADR-002).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ToolSource {
    Native,
    Mcp,
    Skill,
}

/// A single block of a `tool.result` (§6.2): model-facing content, human-facing display, or a typed
/// UI block. Kept free of `serde_json::Value` so the contract crate stays dependency-light; a
/// structured UI block carries its already-serialized JSON as a string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "block", rename_all = "snake_case")]
#[non_exhaustive]
pub enum ResultBlock {
    /// Text fed to the model and/or shown to the human.
    Text { text: String },
    /// A typed UI block for the renderer (table/diff/etc.); `json` is the already-encoded payload.
    Ui { kind: String, json: String },
    /// Must-ignore fallthrough for a block kind an older renderer doesn't know.
    #[serde(other)]
    Unknown,
}

/// The `action` of a `compliance.notice` (§6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ComplianceAction {
    Redacted,
    Audited,
}

/// The post-generation artifact-vs-intent verification result (§6.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactVerification {
    pub matches_intent: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub caveats: Vec<String>,
}

/// A terminal turn outcome (§3.2/§6.5). `Capped` is a *truthful completion*, not a crash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TurnOutcome {
    Complete,
    Capped,
}

/// Whether a gated action moves value (§6.3/§9, ADR-016). A `!= None` boundary can be cleared only
/// by an explicit human `approve` — never a policy auto-decision. `#[non_exhaustive]` so finer
/// boundary classes are additive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PaymentBoundary {
    None,
    MovesValue,
    InitiatesSettlement,
}

/// The session tree (§6.5) delivered in a snapshot: turns with stable ids + parent pointers so
/// branches survive a resume.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SessionTree {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub turns: Vec<TurnNode>,
}

/// One node in the [`SessionTree`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TurnNode {
    pub turn_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_turn_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// A participant present in a session (§6.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Participant {
    pub participant_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

// ---------------------------------------------------------------------------
// §6.5.1 Typed error taxonomy — the only categories a client renders.
// ---------------------------------------------------------------------------

/// A typed protocol error (PROTOCOL.md §6.5.1). Drawn from one closed set — never a raw stack
/// trace. Used both by [`WireEvent::Error`] (session/stream-level) and [`WireEvent::TurnFailed`]
/// (turn-scoped).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolError {
    pub category: ErrorCategory,
    pub message: String,
    pub retryable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery: Option<String>,
}

impl ProtocolError {
    /// Build an error with the taxonomy's canonical `retryable` default for `category`, and a
    /// caller-supplied message. `recovery` is left unset (a renderer derives the standard hint from
    /// the category, or the caller sets a specific one via [`ProtocolError::with_recovery`]).
    pub fn new(category: ErrorCategory, message: impl Into<String>) -> Self {
        ProtocolError {
            retryable: category.retryable_default(),
            category,
            message: message.into(),
            recovery: None,
        }
    }

    pub fn with_recovery(mut self, recovery: impl Into<String>) -> Self {
        self.recovery = Some(recovery.into());
        self
    }
}

/// The closed set of error categories a client renders (§6.5.1). `#[non_exhaustive]` so a new
/// category is additive; a client that doesn't recognize one falls back to a generic presentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ErrorCategory {
    /// 503 / backpressure (§7.3). Retryable — "at capacity, retrying automatically".
    Capacity,
    /// RBAC/policy blocked an action (ADR-003), or a spend/quota ceiling was hit. Not retryable.
    CapabilityDenied,
    /// A provider failed **and** failover also failed (ADR-006). Retryable after failover.
    ProviderUnavailable,
    /// Judge-loop could not confirm completion. Not retryable; show the specific gap report.
    Capped,
    /// Genuinely underspecified request. Not retryable; ask a clarifying question.
    Ambiguous,
    /// Version outside the negotiated N-2 window (§10). Not retryable; "update your client".
    ProtocolIncompatible,
    /// Malformed/unknown command or bad envelope. Not retryable; a client bug.
    InvalidCommand,
}

impl ErrorCategory {
    /// The taxonomy's canonical retryability (§6.5.1 table).
    pub fn retryable_default(self) -> bool {
        matches!(
            self,
            ErrorCategory::Capacity | ErrorCategory::ProviderUnavailable
        )
    }
}

// ---------------------------------------------------------------------------
// §7.1/§7.2 Cancellation + resume capabilities (gaps TURN-04, TURN-05).
// These are pure helpers the runtime/server (RESERVED crates) call — no I/O here.
// ---------------------------------------------------------------------------

/// Whether a received command should fire the turn's shared cancellation token (§7.1).
///
/// **`turn.stop` is the ONLY cancel** — and a transport disconnect is *not a command at all*, so it
/// can never reach this function and can never cancel a turn (the disconnect ≠ cancel invariant,
/// I3/§7.2, gap TURN-04). The server's `CancelOnDisconnect` guard must be rewired to gate
/// cancellation on this predicate over *received commands*, not on the transport drop.
pub fn is_cancel_command(command: &Command) -> bool {
    matches!(command, Command::TurnStop { .. })
}

/// Replay the event tail after a `session.resume{from_event}` (§7.2, gap TURN-05).
///
/// Given the Event Log for a session and the client's `from_event` cursor (its last-seen `seq`),
/// returns exactly the events with `seq > from_event`, in ascending `seq` order — the "replay every
/// event with seq > from_event" contract. `from_event == None` (a bare `session.resume` /
/// `ainxt run --continue`) replays nothing beyond the snapshot the caller sends first.
///
/// Defensive against an unsorted/duplicated log: it sorts by `seq` and de-duplicates, so a caller
/// feeding a projection that isn't already ordered still gets a correct, gap-free tail.
pub fn replay_tail(from_event: Option<u64>, log: &[EventEnvelope]) -> Vec<EventEnvelope> {
    let cursor = match from_event {
        Some(c) => c,
        None => return Vec::new(),
    };
    let mut tail: Vec<EventEnvelope> = log.iter().filter(|e| e.seq > cursor).cloned().collect();
    tail.sort_by_key(|e| e.seq);
    tail.dedup_by_key(|e| e.seq);
    tail
}

/// Detect a sequence gap on the client side (§4.2/§7.2): given the last `seq` a client rendered and
/// the `seq` of the next event it received, returns `true` if one or more events were missed (so the
/// client should `session.resume{from_event: last_seen}`). A duplicate/out-of-order re-delivery
/// (`incoming <= last_seen`) is not a gap.
pub fn has_seq_gap(last_seen: u64, incoming: u64) -> bool {
    incoming > last_seen + 1
}

// ---------------------------------------------------------------------------
// Budget gate (gap TURN-01) — a pure policy helper the Identity+Policy gate calls.
// The spend/limit numbers are injected by the runtime from its per-user budget store; this crate
// owns only the decision → typed-error mapping, keeping the contract crate I/O-free.
// ---------------------------------------------------------------------------

/// Outcome of the pre-turn budget/quota check (RUNTIME_FEATURE_FLOWS §1 step 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BudgetOutcome {
    /// The turn may proceed.
    Allow,
    /// The user is over their spend/quota ceiling; the runtime must emit this error and NOT start
    /// the turn. Rendered as `capability_denied` (a spend ceiling is a policy limit, not transient
    /// capacity — so it is *not* auto-retried, unlike a 503).
    Deny(ProtocolError),
}

/// Pre-turn budget gate (gap TURN-01). Pure: the runtime supplies `already_spent` and `limit` (both
/// in the same token/cost unit) from its budget store and an `estimated_cost` for the turn. If the
/// projected total exceeds `limit`, the turn is denied *before* any model call — cost is enforced,
/// not merely recorded post-hoc.
///
/// A `limit == 0` means "no ceiling configured" and always allows (the runtime decides whether an
/// unset budget is unlimited or should be denied by policy; this helper treats 0 as unlimited).
pub fn budget_gate(already_spent: u64, limit: u64, estimated_cost: u64) -> BudgetOutcome {
    if limit == 0 {
        return BudgetOutcome::Allow;
    }
    let projected = already_spent.saturating_add(estimated_cost);
    if projected > limit {
        return BudgetOutcome::Deny(
            ProtocolError::new(
                ErrorCategory::CapabilityDenied,
                format!("over budget: {already_spent}+{estimated_cost} would exceed limit {limit}"),
            )
            .with_recovery("token/cost budget exhausted; request a higher limit or wait for reset"),
        );
    }
    BudgetOutcome::Allow
}

// ---------------------------------------------------------------------------
// Legacy in-proc pair (retained for the crates already wired to it — do not remove).
// ---------------------------------------------------------------------------

/// A request for one turn.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    pub session: String,
    pub turn: String,
    pub input: String,
    pub data_class: DataClass,
    pub tier: Tier,
    /// A power-user attempt to force a specific model/provider. Still gated by the
    /// non-overridable data-class exclusion (ADR-012) — a forced provider that is not
    /// eligible for the data class is refused, never honored.
    pub forced_provider: Option<String>,
    /// Set by an upstream layer (e.g. the Context Fabric) when the assembled input already
    /// carries UNTRUSTED content that was flagged for suspected prompt injection (ADR-009). The
    /// engine seeds its taint from this so RAG/connector-borne injection gates side-effecting
    /// tools exactly like a suspicious tool result does. Defaults to `false`.
    #[serde(default)]
    pub untrusted_tainted: bool,
    /// The RAW user turn, when `input` has been rewritten by an upstream layer into a COMPOSED
    /// prompt (e.g. a Surface profile prepending persona/guard/context, `ainxt-surface`
    /// `TurnPlan::to_request`). Intent classification / referent resolution MUST run on the user's
    /// own words, never on the composed prompt — a persona that says "make a PDF" must not be read
    /// as the user asking for a document. `None` (default) means `input` IS the user turn (the
    /// unwrapped path), so behavior is byte-identical when unset. Additive + serde-defaulted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_turn: Option<String>,
    /// The retrieval namespace this turn is scoped to, when the caller declares one explicitly (e.g.
    /// a harness's `context.namespace`, `ainxt_admission::HarnessManifest::namespace`). Distinct from a
    /// Surface Profile's own namespace resolution ([`ainxt_profile::RetrievalScope`]), which is bound
    /// per-SURFACE upstream of any single turn — this field lets a single turn carry an explicit
    /// override alongside that. Additive + serde-defaulted, so behavior is byte-identical when unset.
    /// **`needs_hot_wiring`**: consuming this to actually select the retrieval corpus (today resolved
    /// only by surface id, e.g. `ainxt_runtimed::scope_for_surface` / `KbScope::Namespace`) is the
    /// reserved daemon's job — this crate only carries the declaration across the wire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// A HARD pin of the model-complexity tier for this turn (§4.1 step 1). Distinct from [`tier`],
    /// which is a *soft* preference the router may gracefully fall back from: when `pinned_tier` is
    /// `Some(t)`, the runtime routes through the router's HARD tier filter
    /// (`select_chain_graded` / `tier_eligible`) so the turn can NEVER silently fall through to an
    /// off-tier model — if no eligible model exists for the pinned tier the turn fails closed with a
    /// typed routing error rather than routing to a wrong-tier model. `None` (the default, and the
    /// byte-identical pre-existing behavior) leaves the turn *unpinned*: the runtime derives the tier
    /// via its in-engine complexity classifier and uses the soft `select_chain` fallback, honoring
    /// [`tier`] as the graceful preference. Additive + serde-defaulted so requests that predate it
    /// load unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pinned_tier: Option<Tier>,
    /// GAP-FIX surfaces-profiles-skills-config — a per-turn TOML source for
    /// `ainxt_surface::SurfaceBinding::plan_with_request_override`'s "request" rung of the
    /// `defaults→deployment→tenant→profile→request` layered-config chain (ADR-004). The rung is
    /// narrowing-only (RBAC/capabilities/connectors/autonomy/retrieval/data-class ceiling/allow-list
    /// are all pinned; only prompt-policy preferences, the routing-tier floor, and an allow-listed
    /// provider choice may move) — a widening attempt is refused fail-closed BEFORE any admission
    /// check runs. `None` (the default) leaves every turn byte-identical to before this field
    /// existed. Additive + serde-defaulted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_override: Option<String>,
    /// GAP-FIX surfaces-profiles-skills-config — the surface's declared conversation-history token
    /// budget for context assembly ([`ainxt_surface::TurnPlan::history_budget_tokens`]), carried onto
    /// the engine turn by [`ainxt_surface::TurnPlan::to_request`]. Without this the plan's budget was
    /// computed and then discarded: the conversation layer always assembled history against its own
    /// hardcoded default (`ainxt_convo::PromptDeployment`'s 10,000-token default) regardless of what
    /// the surface actually declared. `None` (the default) leaves every turn byte-identical to before
    /// this field existed — the conversation layer falls back to its own configured default budget.
    /// Additive + serde-defaulted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_budget_tokens: Option<u32>,
}

impl Request {
    pub fn chat(session: &str, turn: &str, input: &str, data_class: DataClass) -> Self {
        Request {
            session: session.to_string(),
            turn: turn.to_string(),
            input: input.to_string(),
            data_class,
            tier: Tier::Simple,
            forced_provider: None,
            untrusted_tainted: false,
            user_turn: None,
            namespace: None,
            pinned_tier: None,
            request_override: None,
            history_budget_tokens: None,
        }
    }

    /// Attach the raw user turn when `input` is a composed prompt (see [`Request::user_turn`]).
    pub fn with_user_turn(mut self, user_turn: &str) -> Self {
        self.user_turn = Some(user_turn.to_string());
        self
    }

    /// Attach a per-turn "request" rung override (see [`Request::request_override`]).
    pub fn with_request_override(mut self, toml_src: &str) -> Self {
        self.request_override = Some(toml_src.to_string());
        self
    }

    /// HARD-pin the model-complexity tier for this turn (see [`Request::pinned_tier`]). The runtime
    /// then routes through the router's hard tier filter and fails closed (typed routing error) if no
    /// eligible model exists for the pinned tier — it never falls through to an off-tier model.
    pub fn with_pinned_tier(mut self, tier: Tier) -> Self {
        self.pinned_tier = Some(tier);
        self
    }

    /// Attach an explicit retrieval-namespace override (see [`Request::namespace`]).
    pub fn with_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespace = Some(namespace.into());
        self
    }

    /// Override the conversation-history assembly token budget for this turn (see
    /// [`Request::history_budget_tokens`]).
    pub fn with_history_budget_tokens(mut self, budget: u32) -> Self {
        self.history_budget_tokens = Some(budget);
        self
    }

    /// The text intent classification / referent resolution should run on: the raw [`Request::user_turn`]
    /// when set, else `input` (the unwrapped path).
    pub fn classify_source(&self) -> &str {
        self.user_turn.as_deref().unwrap_or(&self.input)
    }
}

/// The single typed streaming event — the seam between core and every vendor/renderer.
/// A provider's wire format is normalized into this; a renderer only ever sees this.
///
/// **Legacy.** This is the first-cut in-proc event the current engine/server/client are wired to.
/// New work targets [`WireEvent`] (the full §6 vocabulary); the parent migrates these crates onto
/// [`EventEnvelope`]/[`WireEvent`] (see `needs_wiring`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Event {
    TextDelta(String),
    /// GAP-AUDIT turn-pipeline #6 — a fragment of model reasoning/"thinking", distinct from the
    /// final answer text. Mirrors `WireEvent::ReasoningDelta` (§6.1) on the legacy side of the
    /// seam; a provider adapter that surfaces a vendor "thinking"/reasoning stream emits this
    /// instead of `TextDelta` for that content.
    ReasoningDelta(String),
    ToolCallStart {
        id: String,
        name: String,
        args: String,
    },
    ToolResult {
        id: String,
        output: String,
    },
    /// GAP2 harness-sdk — an `artifact.*` capability's result, distinct from an opaque
    /// [`Event::ToolResult`]. A renderer/SDK consumer needs the artifact identity (the declared
    /// `capability`, e.g. `artifact.generate`) to route the payload to artifact-aware handling
    /// (render/download/preview) instead of dumping it into the transcript as plain text.
    /// `output` carries the same compliance-scanned payload a `ToolResult` would carry for this
    /// call id; this event is emitted IN ADDITION TO (not instead of) the `ToolResult` for that
    /// id, so a consumer that only understands the legacy vocabulary still sees the text.
    Artifact {
        id: String,
        capability: String,
        output: String,
    },
    ApprovalRequest {
        id: String,
        summary: String,
    },
    Usage {
        input_tokens: u64,
        output_tokens: u64,
    },
    Error(String),
    Done,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    // -- legacy pair (unchanged behaviour) ----------------------------------

    #[test]
    fn request_round_trips() {
        let req = Request::chat("s", "t", "hello", DataClass::Internal);
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(serde_json::from_str::<Request>(&json).unwrap(), req);
    }

    #[test]
    fn additive_field_from_a_newer_peer_is_ignored() {
        let newer = r#"{
            "session":"s","turn":"t","input":"hi","data_class":"internal","tier":"simple",
            "forced_provider":null,"untrusted_tainted":false,"future_flag":true,"future_obj":{"x":1}
        }"#;
        let req: Request = serde_json::from_str(newer).expect("unknown fields must be ignored");
        assert_eq!(req.input, "hi");
    }

    #[test]
    fn older_serialized_request_missing_optional_field_still_loads() {
        let older = r#"{"session":"s","turn":"t","input":"hi","data_class":"public","tier":"simple","forced_provider":null}"#;
        let req: Request =
            serde_json::from_str(older).expect("missing optional field must default");
        assert!(!req.untrusted_tainted);
    }

    #[test]
    fn every_legacy_event_variant_round_trips() {
        let events = vec![
            Event::TextDelta("x".into()),
            Event::ToolCallStart {
                id: "1".into(),
                name: "t".into(),
                args: "{}".into(),
            },
            Event::ToolResult {
                id: "1".into(),
                output: "ok".into(),
            },
            Event::ApprovalRequest {
                id: "1".into(),
                summary: "risky".into(),
            },
            Event::Usage {
                input_tokens: 3,
                output_tokens: 4,
            },
            Event::Error("boom".into()),
            Event::Done,
        ];
        for e in events {
            let json = serde_json::to_string(&e).unwrap();
            assert_eq!(serde_json::from_str::<Event>(&json).unwrap(), e);
        }
    }

    // -- GAP2 harness-sdk: artifact-event -----------------------------------

    #[test]
    fn gap2_artifact_event_round_trips_and_is_distinct_from_tool_result() {
        let artifact = Event::Artifact {
            id: "call-1".into(),
            capability: "artifact.generate".into(),
            output: "s3://bucket/report.pdf".into(),
        };
        let json = serde_json::to_string(&artifact).unwrap();
        assert_eq!(serde_json::from_str::<Event>(&json).unwrap(), artifact);
        // The wire tag must be its own variant, never collapsed onto `tool_result` — a consumer
        // needs to distinguish "opaque tool text" from "this is an artifact reference".
        assert!(json.contains("Artifact") || json.contains("artifact"));
        let tool_result = Event::ToolResult {
            id: "call-1".into(),
            output: "s3://bucket/report.pdf".into(),
        };
        assert_ne!(
            artifact, tool_result,
            "artifact event must not be equal to a tool_result carrying the same payload"
        );
    }

    // -- gap TURN-06: versioning (additive-safe, must-ignore, N-2 window, negotiation) ----

    #[test]
    fn gap_turn_06_n2_window_and_negotiation() {
        // Old exact-match rule would REJECT any skew; the N-2 window must accept up to two prior
        // majors and a newer MINOR, and refuse only outside the window.
        assert!(is_compatible(1, 1));
        assert!(
            is_compatible(2, 4),
            "N-2: two majors behind is still supported"
        );
        assert!(is_compatible(3, 4));
        assert!(
            !is_compatible(1, 4),
            "three majors behind is outside the window"
        );
        assert!(
            !is_compatible(5, 4),
            "a client newer than the runtime is refused"
        );

        // Negotiation picks the highest common version.
        let server = ProtocolVersion::new(1, 7);
        match negotiate(ProtocolVersion::new(1, 2), server) {
            Negotiation::Agreed(v) => assert_eq!(v, ProtocolVersion::new(1, 2)),
            other => panic!("expected Agreed(1.2), got {other:?}"),
        }
        // A client newer than the runtime settles down to the runtime's version.
        match negotiate(ProtocolVersion::new(1, 9), server) {
            Negotiation::Agreed(v) => assert_eq!(v, ProtocolVersion::new(1, 7)),
            other => panic!("expected Agreed(1.7), got {other:?}"),
        }
        // Outside the window → clean protocol_incompatible with a supported range.
        match negotiate(ProtocolVersion::new(9, 0), ProtocolVersion::new(4, 0)) {
            Negotiation::Incompatible { supported } => assert!(supported.contains("2.x-4.x")),
            other => panic!("expected Incompatible, got {other:?}"),
        }
        assert_eq!(
            ProtocolVersion::from_str("3.2").unwrap(),
            ProtocolVersion::new(3, 2)
        );
        assert_eq!(
            ProtocolVersion::from_str("3").unwrap(),
            ProtocolVersion::new(3, 0)
        );
        assert!(ProtocolVersion::from_str("x.y").is_err());
    }

    #[test]
    fn gap_turn_06_unknown_event_type_is_must_ignored_not_fatal() {
        // A newer runtime streams an event type this build has never heard of. The old client MUST
        // deserialize it (into Unknown) and keep going — the load-bearing forward-compat guarantee
        // (§10.3). The pre-change plain serde enum would ERROR here.
        let env: EventEnvelope = serde_json::from_str(
            r#"{"v":"1.0","session_id":"s","seq":99,"ts":"t","control_plane_sha":"sha",
                "type":"some.future.event.from_2030","anything":true,"nested":{"x":1}}"#,
        )
        .expect("unknown event type must not error deserialization");
        assert_eq!(env.event, WireEvent::Unknown);
        assert_eq!(env.seq, 99);

        // Unknown FIELDS within a known body are also ignored (must-ignore, §10.3).
        let env2: EventEnvelope = serde_json::from_str(
            r#"{"v":"1.0","session_id":"s","seq":1,"ts":"t","control_plane_sha":"sha",
                "type":"text.delta","text":"hi","future_field":42}"#,
        )
        .expect("unknown body field must be ignored");
        assert_eq!(env2.event, WireEvent::TextDelta { text: "hi".into() });

        // And an unknown command type deserializes to Unknown (runtime answers invalid_command).
        let cmd: CommandEnvelope = serde_json::from_str(
            r#"{"protocol_version":"1.0","command_id":"c1","participant_id":"u",
                "type":"future.command","some_arg":true}"#,
        )
        .expect("unknown command type must not error");
        assert_eq!(cmd.command, Command::Unknown);
    }

    // -- GAP-AUDIT transport-daemon #3: §10 deprecation window (marker + N/N+1 coexistence) ----

    #[test]
    fn gap_transport_daemon_deprecation_registry_flags_the_legacy_pair() {
        // The module doc's existing "Legacy in-proc pair ... retained verbatim" claim, made real and
        // machine-checkable — a CI/docs tool can assert this instead of relying on prose nobody enforces.
        let event_notice = deprecation_notice("ainxt_protocol::Event")
            .expect("the legacy Event pair must be a registered deprecation");
        assert_eq!(event_notice.since, "1.0");
        assert!(
            event_notice.reason.contains("WireEvent"),
            "{}",
            event_notice.reason
        );
        let request_notice = deprecation_notice("ainxt_protocol::Request")
            .expect("the legacy Request pair must be a registered deprecation");
        assert!(
            request_notice.reason.contains("Command"),
            "{}",
            request_notice.reason
        );

        // A currently-live, non-deprecated wire surface must NOT be flagged — the registry is
        // precise, not a blanket "everything old is deprecated" stamp.
        assert!(deprecation_notice("turn.steer").is_none());
        assert!(deprecation_notice("ainxt_protocol::WireEvent").is_none());
    }

    #[test]
    fn gap_transport_daemon_n_and_n_plus_1_coexist_across_a_deprecation() {
        // "N" — a client still built against the now-deprecated in-proc pair. Deprecating a surface
        // is a MARKER ONLY: during the ENTIRE coexistence window it must keep working
        // byte-identically, never a silent behavior change or removal.
        let legacy = Event::TextDelta("hi".to_string());
        let json = serde_json::to_string(&legacy).unwrap();
        assert_eq!(
            serde_json::from_str::<Event>(&json).unwrap(),
            legacy,
            "a deprecated surface must keep round-tripping for its whole coexistence window"
        );

        // "N+1" — a client (or a CI/docs tool) that queries the registry sees the deprecation and can
        // warn/migrate, entirely independently of the "N" client above still working. Both being
        // correct AT THE SAME TIME is the coexistence guarantee (§10 deprecation window).
        assert!(deprecation_notice("ainxt_protocol::Event").is_some());

        // The SAME must-ignore guarantee (§10.3) that makes an ordinary additive MINOR safe is what
        // makes a deprecation announcement safe to introduce later too: an "N" `WireEvent` consumer
        // that predates a hypothetical future `protocol.surface_deprecated` notification type still
        // parses the envelope (falls back to `Unknown`) instead of erroring the session — exactly the
        // mechanism such an announcement would ride if the runtime ever emits one over the wire.
        let env: EventEnvelope = serde_json::from_str(
            r#"{"v":"1.0","session_id":"s","seq":1,"ts":"t","control_plane_sha":"sha",
                "type":"protocol.surface_deprecated","surface":"ainxt_protocol::Event",
                "since":"1.1","reason":"see deprecation_notice()"}"#,
        )
        .expect("an old client must not choke on a deprecation announcement it predates");
        assert_eq!(env.event, WireEvent::Unknown);
    }

    // -- gap TURN-02: the wire envelope carries the ordering/idempotency/resume fields ----

    #[test]
    fn gap_turn_02_envelopes_carry_the_full_machinery() {
        let env = EventEnvelope {
            v: "1.0".into(),
            session_id: "s-42".into(),
            turn_id: Some("t-7".into()),
            program_id: Some("p-13".into()),
            seq: 10427,
            ts: "2026-07-18T09:14:22.481Z".into(),
            control_plane_sha: "a1b2c3".into(),
            event: WireEvent::TextDelta { text: "hi".into() },
        };
        let json = serde_json::to_string(&env).unwrap();
        // the type discriminator + body fields are flattened to the envelope top level per §4.2.
        assert!(
            json.contains(r#""type":"text.delta""#),
            "flattened type missing: {json}"
        );
        assert!(
            json.contains(r#""text":"hi""#),
            "flattened body field missing: {json}"
        );
        assert!(json.contains(r#""seq":10427"#));
        assert!(json.contains(r#""control_plane_sha":"a1b2c3""#));
        let back: EventEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(back, env);

        let cmd = CommandEnvelope {
            protocol_version: "1.0".into(),
            command_id: "c-9f3a".into(),
            session_id: Some("s-42".into()),
            actor_id: "u-priya".into(),
            command: Command::TurnStop {
                turn_id: "t-7".into(),
            },
        };
        let cj = serde_json::to_string(&cmd).unwrap();
        assert!(cj.contains(r#""command_id":"c-9f3a""#));
        assert!(cj.contains(r#""type":"turn.stop""#));
        assert_eq!(serde_json::from_str::<CommandEnvelope>(&cj).unwrap(), cmd);

        // session.open omits session_id (it mints one) — the field must be absent, not null.
        let open = CommandEnvelope {
            protocol_version: "1.0".into(),
            command_id: "c-1".into(),
            session_id: None,
            actor_id: "u".into(),
            command: Command::SessionOpen {
                profile_id: "chat".into(),
                client_info: None,
                capabilities_wanted: vec![],
                client_protocol_version: None,
            },
        };
        let oj = serde_json::to_string(&open).unwrap();
        assert!(
            !oj.contains("session_id"),
            "session.open must omit session_id: {oj}"
        );
    }

    // -- gap TURN-03: the full command family + payment-boundary invariant ----

    #[test]
    fn gap_turn_03_command_family_round_trips() {
        let commands = vec![
            Command::SessionOpen {
                profile_id: "chat".into(),
                client_info: Some("cli".into()),
                capabilities_wanted: vec!["chat.send".into()],
                client_protocol_version: None,
            },
            Command::SessionResume {
                session_id: "s".into(),
                from_event: Some(41),
            },
            Command::SessionSubscribe {
                session_id: "s".into(),
                mode: SubscribeMode::Observer,
            },
            Command::SessionFork {
                session_id: "s".into(),
                from_turn_id: "t".into(),
                label: Some("alt".into()),
            },
            Command::SessionClose {
                session_id: "s".into(),
            },
            Command::TurnSubmit {
                input: TurnInput::text("hi"),
                overrides: Some(TurnOverrides {
                    forced_model: Some("gpt-5.4".into()),
                    tier: Some(Tier::Simple),
                }),
            },
            Command::TurnSteer {
                turn_id: "t".into(),
                text: "also check X".into(),
            },
            Command::TurnStop {
                turn_id: "t".into(),
            },
            Command::TurnEdit {
                turn_id: "t".into(),
                input: TurnInput::text("edited"),
            },
            Command::TurnBranch {
                from_turn_id: "t".into(),
                label: None,
            },
            Command::ApprovalRespond(ApprovalRespond {
                approval_id: "a".into(),
                decision: ApprovalDecision::ApproveForSession,
                feedback: None,
            }),
            Command::ProgramStart {
                program_id: "p".into(),
                spec: None,
            },
            Command::ProgramPause {
                program_id: "p".into(),
            },
            Command::ProgramResume {
                program_id: "p".into(),
            },
            Command::ProgramCheckpointRespond {
                program_id: "p".into(),
                checkpoint_id: "cp".into(),
                decision: ApprovalDecision::Approve,
            },
        ];
        for c in commands {
            let json = serde_json::to_string(&c).unwrap();
            assert_eq!(
                serde_json::from_str::<Command>(&json).unwrap(),
                c,
                "round-trip failed: {json}"
            );
        }
        // Wire names match the design's dotted discriminators (§5).
        let j = serde_json::to_string(&Command::TurnSubmit {
            input: TurnInput::text("hi"),
            overrides: None,
        })
        .unwrap();
        assert!(j.contains(r#""type":"turn.submit""#), "{j}");
    }

    #[test]
    fn gap_turn_03_payment_boundary_requires_human_approve() {
        // A non-payment action: approve_for_session is fine.
        let r = ApprovalRespond {
            approval_id: "a".into(),
            decision: ApprovalDecision::ApproveForSession,
            feedback: None,
        };
        assert!(r.is_valid(PaymentBoundary::None, false).is_ok());

        // A payment action: a policy auto human-style approve is REFUSED...
        let auto = ApprovalRespond {
            approval_id: "a".into(),
            decision: ApprovalDecision::Approve,
            feedback: None,
        };
        assert!(auto
            .is_valid(
                PaymentBoundary::InitiatesSettlement,
                /*is_policy_auto=*/ true
            )
            .is_err());
        // ...approve_for_session is refused...
        let sess = ApprovalRespond {
            approval_id: "a".into(),
            decision: ApprovalDecision::ApproveForSession,
            feedback: None,
        };
        assert!(sess
            .is_valid(PaymentBoundary::InitiatesSettlement, false)
            .is_err());
        // ...only an explicit human approve clears it.
        assert!(auto
            .is_valid(
                PaymentBoundary::InitiatesSettlement,
                /*is_policy_auto=*/ false
            )
            .is_ok());

        // reject without feedback is rejected.
        let bad = ApprovalRespond {
            approval_id: "a".into(),
            decision: ApprovalDecision::Reject,
            feedback: None,
        };
        assert!(bad.is_valid(PaymentBoundary::None, false).is_err());
    }

    // -- gap TURN-07: the fuller typed event vocabulary (incl. capped outcome) ----

    #[test]
    fn gap_turn_07_event_vocabulary_round_trips() {
        let events = vec![
            WireEvent::TextDelta { text: "x".into() },
            WireEvent::ReasoningDelta {
                text: "thinking".into(),
            },
            WireEvent::ToolCallStart {
                call_id: "k".into(),
                name: "kb.search".into(),
                source: ToolSource::Native,
            },
            WireEvent::ToolCallDelta {
                call_id: "k".into(),
                args_delta: "{\"q\":".into(),
            },
            WireEvent::ToolCallStop {
                call_id: "k".into(),
                args: "{\"q\":\"x\"}".into(),
            },
            WireEvent::ToolResult {
                call_id: "k".into(),
                blocks: vec![
                    ResultBlock::Text { text: "ok".into() },
                    ResultBlock::Ui {
                        kind: "table".into(),
                        json: "[]".into(),
                    },
                ],
                is_error: false,
            },
            WireEvent::ApprovalRequest {
                approval_id: "a".into(),
                action: "connector.email.send".into(),
                scope: "domain=*.example.org".into(),
                risk_tier: "Elevated".into(),
                preview: None,
                payment_boundary: PaymentBoundary::None,
            },
            WireEvent::ComplianceNotice {
                categories: vec!["ACCOUNT_NUMBER".into()],
                action: ComplianceAction::Redacted,
            },
            WireEvent::Artifact {
                artifact_id: "art".into(),
                kind: "pptx".into(),
                uri: "s3://x".into(),
                preview: None,
                verification: Some(ArtifactVerification {
                    matches_intent: true,
                    caveats: vec![],
                }),
            },
            WireEvent::Usage {
                model: "gpt-5.4".into(),
                input_tokens: 812,
                output_tokens: 240,
                cost: 0.01,
                cached: Some(false),
            },
            WireEvent::SessionSnapshot {
                tree: SessionTree {
                    turns: vec![TurnNode {
                        turn_id: "t".into(),
                        parent_turn_id: None,
                        label: None,
                    }],
                },
                active_head: Some("t".into()),
                participants: vec![Participant {
                    participant_id: "u".into(),
                    display_name: None,
                }],
                negotiated_version: "1.0".into(),
            },
            WireEvent::TurnStarted {
                turn_id: "t".into(),
                parent_turn_id: None,
                participant_id: "u".into(),
                model_hint: None,
            },
            WireEvent::TurnRationale {
                turn_id: "t".into(),
                model_tier: "medium".into(),
                model: "gpt-5.4".into(),
                capabilities: vec![],
                sources: vec!["docs_kb:x#L1".into()],
            },
            WireEvent::TurnCompleted {
                turn_id: "t".into(),
                outcome: TurnOutcome::Complete,
            },
            WireEvent::TurnCompleted {
                turn_id: "t".into(),
                outcome: TurnOutcome::Capped,
            },
            WireEvent::TurnStopped {
                turn_id: "t".into(),
            },
            WireEvent::TurnFailed {
                turn_id: "t".into(),
                error: ProtocolError::new(ErrorCategory::ProviderUnavailable, "all providers down"),
            },
            WireEvent::TurnSteer {
                turn_id: "t".into(),
                text: "hi".into(),
            },
            WireEvent::TurnEdit {
                turn_id: "t".into(),
            },
            WireEvent::TurnBranch {
                from_turn_id: "t".into(),
                label: None,
            },
            WireEvent::Error(ProtocolError::new(ErrorCategory::Capacity, "at capacity")),
            WireEvent::ParticipantJoined {
                participant_id: "u".into(),
                turn_id: None,
            },
            WireEvent::ParticipantLeft {
                participant_id: "u".into(),
            },
            WireEvent::ParticipantTyping {
                participant_id: "u".into(),
                turn_id: Some("t".into()),
            },
            WireEvent::ParticipantViewing {
                participant_id: "u".into(),
                turn_id: None,
            },
        ];
        for e in events {
            let json = serde_json::to_string(&e).unwrap();
            assert_eq!(
                serde_json::from_str::<WireEvent>(&json).unwrap(),
                e,
                "round-trip failed: {json}"
            );
        }
        // The honest `capped` outcome is a completion, not a failure (§3.2).
        let capped = serde_json::to_string(&WireEvent::TurnCompleted {
            turn_id: "t".into(),
            outcome: TurnOutcome::Capped,
        })
        .unwrap();
        assert!(
            capped.contains(r#""type":"turn.completed""#)
                && capped.contains(r#""outcome":"capped""#),
            "{capped}"
        );
        // Error taxonomy retryability defaults match §6.5.1.
        assert!(ErrorCategory::Capacity.retryable_default());
        assert!(ErrorCategory::ProviderUnavailable.retryable_default());
        assert!(!ErrorCategory::CapabilityDenied.retryable_default());
        assert!(!ErrorCategory::Capped.retryable_default());
        assert!(!ErrorCategory::ProtocolIncompatible.retryable_default());
    }

    // -- gap TURN-08: compliance.notice on the wire ----

    #[test]
    fn gap_turn_08_compliance_notice_reports_category_never_content() {
        let ev = WireEvent::ComplianceNotice {
            categories: vec!["ACCOUNT_NUMBER".into(), "UPI".into()],
            action: ComplianceAction::Redacted,
        };
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains(r#""type":"compliance.notice""#), "{json}");
        assert!(json.contains(r#""action":"redacted""#));
        assert!(json.contains("ACCOUNT_NUMBER"));
        // The raw PII is never on the wire — only the category label.
        assert!(
            !json.contains("4111"),
            "compliance.notice must never carry raw content"
        );
        assert_eq!(serde_json::from_str::<WireEvent>(&json).unwrap(), ev);
    }

    // -- gap TURN-04: disconnect ≠ cancel — only turn.stop cancels ----

    #[test]
    fn gap_turn_04_only_turn_stop_is_a_cancel() {
        assert!(is_cancel_command(&Command::TurnStop {
            turn_id: "t".into()
        }));
        // Nothing else cancels — steer, submit, resume, close, approvals, programs.
        for c in [
            Command::TurnSteer {
                turn_id: "t".into(),
                text: "x".into(),
            },
            Command::TurnSubmit {
                input: TurnInput::text("x"),
                overrides: None,
            },
            Command::SessionResume {
                session_id: "s".into(),
                from_event: Some(1),
            },
            Command::SessionClose {
                session_id: "s".into(),
            },
            Command::ApprovalRespond(ApprovalRespond {
                approval_id: "a".into(),
                decision: ApprovalDecision::Reject,
                feedback: Some("no".into()),
            }),
            Command::Unknown,
        ] {
            assert!(!is_cancel_command(&c), "only turn.stop may cancel");
        }
        // A transport disconnect is not a Command at all → it can never reach is_cancel_command,
        // so it can never cancel a turn (the I3 invariant this predicate exists to enforce).
    }

    // -- gap TURN-05: session.resume tail replay via seq cursor ----

    #[test]
    fn gap_turn_05_replay_tail_by_seq_cursor() {
        let mk = |seq: u64| {
            EventEnvelope::turn(
                "s",
                "t",
                seq,
                "ts",
                "sha",
                WireEvent::TextDelta {
                    text: format!("d{seq}"),
                },
            )
        };
        // Deliberately unsorted + a duplicate seq to prove defensiveness.
        let log = vec![mk(43), mk(41), mk(42), mk(42), mk(44), mk(40), mk(45)];

        // Client last saw seq 41 → replay 42,43,44,45 in order, no duplicates, nothing <= 41.
        let tail = replay_tail(Some(41), &log);
        let seqs: Vec<u64> = tail.iter().map(|e| e.seq).collect();
        assert_eq!(seqs, vec![42, 43, 44, 45]);

        // from_event omitted → nothing beyond the snapshot.
        assert!(replay_tail(None, &log).is_empty());

        // A cursor at/after the head yields nothing (already caught up).
        assert!(replay_tail(Some(45), &log).is_empty());
        assert!(replay_tail(Some(999), &log).is_empty());

        // Gap detection drives when a client should resume.
        assert!(has_seq_gap(41, 43), "missed 42 → gap");
        assert!(!has_seq_gap(41, 42), "contiguous → no gap");
        assert!(!has_seq_gap(41, 40), "stale re-delivery → not a gap");
    }

    // -- gap TURN-01: pre-turn budget gate enforces the spend ceiling ----

    #[test]
    fn gap_turn_01_budget_gate_denies_over_ceiling_pre_turn() {
        // Under budget → allow.
        assert_eq!(budget_gate(100, 1000, 50), BudgetOutcome::Allow);
        // Exactly at the ceiling → allow (<=).
        assert_eq!(budget_gate(950, 1000, 50), BudgetOutcome::Allow);
        // Projected over the ceiling → deny with a typed, NON-retryable capability_denied error,
        // BEFORE the turn runs (cost enforced, not merely recorded post-hoc).
        match budget_gate(980, 1000, 50) {
            BudgetOutcome::Deny(err) => {
                assert_eq!(err.category, ErrorCategory::CapabilityDenied);
                assert!(!err.retryable, "a spend ceiling is not auto-retryable");
                assert!(err.recovery.is_some());
            }
            other => panic!("expected Deny, got {other:?}"),
        }
        // limit == 0 means no ceiling configured → allow.
        assert_eq!(budget_gate(10_000_000, 0, 1), BudgetOutcome::Allow);
        // Overflow-safe.
        assert!(matches!(
            budget_gate(u64::MAX, 1000, 10),
            BudgetOutcome::Deny(_)
        ));
    }
}
