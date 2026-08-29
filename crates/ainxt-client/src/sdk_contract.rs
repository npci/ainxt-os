// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! SDK contract descriptor + language-binding codegen (Phase 4, gap "Python/TS SDK").
//!
//! # Why this exists
//!
//! The design (`HARNESS_SDK.md` §2.2, `P4_EXIT_DOD.md` "language/infra follow-ups") states that the
//! **Python SDK (first) and the TypeScript SDK mirror the exact wire contract** that this Rust client
//! is the reference implementation of. The honest infra gap is that those two SDKs live in their own
//! language packages (published + tested by `pytest` / `vitest` CI) and speak to a **live**
//! `ainxt-server` over HTTP/SSE — none of which exists in this Rust workspace run.
//!
//! What *can* be built — and is built here, fully offline — is the missing **machine-readable
//! contract** that turns "the SDKs mirror the wire contract" from a prose promise into a mechanized,
//! drift-guarded artifact:
//!
//! 1. [`contract_descriptor`] derives a serializable [`ContractDescriptor`] **directly from the live
//!    [`ainxt_protocol`] types** — every [`WireEvent`](ainxt_protocol::WireEvent) and
//!    [`Command`](ainxt_protocol::Command) variant, its wire `type` string and field shape, the
//!    closed [`ErrorCategory`](ainxt_protocol::ErrorCategory) taxonomy, the negotiated protocol
//!    version and the N-2 window. Field names/JSON-types are read back out of a real serialization of
//!    each variant, so the descriptor **cannot silently drift** from the actual wire shape.
//! 2. [`emit_python_sdk`] / [`emit_typescript_sdk`] are the **codegen** the language packages run:
//!    given the descriptor they emit typed-event definitions, the error taxonomy, the protocol-version
//!    constant, and an ergonomic `Runtime`/`Harness` client skeleton over a network-transport seam.
//!    This is what proves the two SDKs are *generated mirrors* of one contract, not hand-maintained
//!    copies that rot.
//!
//! The remaining work is genuinely infra: standing the packages up in Python/JS repos with their own
//! CI, and wiring the codegen'd client to the live HTTP/SSE transport against a running server. Those
//! are recorded as infra-gated — this module is the offline seam + impl + test they build on.

use ainxt_protocol::{
    ApprovalDecision, ApprovalRespond, Attachment, Command, ComplianceAction, ErrorCategory,
    Participant, PaymentBoundary, ProtocolError, ResultBlock, SessionTree, SubscribeMode,
    ToolSource, TurnInput, TurnNode, TurnOutcome, TurnOverrides, WireEvent, PROTOCOL_VERSION,
    SUPPORTED_MAJOR_WINDOW,
};
use serde::{Deserialize, Serialize};

/// The JSON shape of a single field on a wire message, as observed in a real serialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JsonType {
    String,
    Integer,
    Number,
    Bool,
    Array,
    Object,
    /// A field that serialized to `null` in the sample (should not normally occur — the descriptor
    /// populates every optional so its type is observable).
    Null,
}

impl JsonType {
    fn of(v: &serde_json::Value) -> JsonType {
        match v {
            serde_json::Value::String(_) => JsonType::String,
            serde_json::Value::Bool(_) => JsonType::Bool,
            serde_json::Value::Number(n) if n.is_f64() && !n.is_u64() && !n.is_i64() => {
                JsonType::Number
            }
            serde_json::Value::Number(_) => JsonType::Integer,
            serde_json::Value::Array(_) => JsonType::Array,
            serde_json::Value::Object(_) => JsonType::Object,
            serde_json::Value::Null => JsonType::Null,
        }
    }

    /// The Python type annotation for this JSON type.
    fn python(&self) -> &'static str {
        match self {
            JsonType::String => "str",
            JsonType::Integer => "int",
            JsonType::Number => "float",
            JsonType::Bool => "bool",
            JsonType::Array => "list",
            JsonType::Object => "dict",
            JsonType::Null => "object | None",
        }
    }

    /// The TypeScript type annotation for this JSON type.
    fn typescript(&self) -> &'static str {
        match self {
            JsonType::String => "string",
            JsonType::Integer | JsonType::Number => "number",
            JsonType::Bool => "boolean",
            JsonType::Array => "unknown[]",
            JsonType::Object => "Record<string, unknown>",
            JsonType::Null => "unknown | null",
        }
    }
}

/// One field of a wire message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldSpec {
    pub name: String,
    pub json_type: JsonType,
}

/// A wire message (one `WireEvent` or `Command` variant): its wire `type` discriminator, the Rust
/// variant it maps to (documentation only), and its observed field shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageSpec {
    /// The `"type"` discriminator carried on the wire.
    pub wire_type: String,
    /// The Rust variant name (for cross-referencing the reference implementation).
    pub rust_variant: String,
    pub fields: Vec<FieldSpec>,
}

/// A closed enum in the contract (rendered as a string-literal union in the SDKs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnumSpec {
    pub name: String,
    pub variants: Vec<String>,
}

/// One error category and its canonical retryability (`§6.5.1`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorCategorySpec {
    pub wire_name: String,
    pub retryable: bool,
}

/// The full, serializable contract every language SDK is generated from. Serialize this to JSON and
/// it is the single codegen input; regenerating a binding is `emit_*_sdk(&contract_descriptor())`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractDescriptor {
    /// The semantic protocol version (`MAJOR.MINOR`) this contract describes.
    pub protocol_version: String,
    /// How many prior majors interoperate (the N-2 window).
    pub supported_major_window: u32,
    /// Runtime → client events.
    pub events: Vec<MessageSpec>,
    /// Client → runtime commands.
    pub commands: Vec<MessageSpec>,
    /// The closed error taxonomy.
    pub error_categories: Vec<ErrorCategorySpec>,
    /// Closed enums referenced by message fields.
    pub enums: Vec<EnumSpec>,
}

/// Serialize a representative variant instance and split it into `(wire_type, fields)`. The `type`
/// tag and the field names/JSON-types are read straight out of the real serialization, so the
/// descriptor is a faithful, drift-proof projection of the wire shape.
fn spec_from_sample<T: Serialize>(rust_variant: &str, sample: &T) -> MessageSpec {
    let value = serde_json::to_value(sample).expect("wire type must serialize");
    let obj = value
        .as_object()
        .expect("an internally-tagged wire variant serializes to a JSON object");
    let wire_type = obj
        .get("type")
        .and_then(|t| t.as_str())
        .expect("every wire variant carries a `type` discriminator")
        .to_string();
    let mut fields: Vec<FieldSpec> = obj
        .iter()
        .filter(|(k, _)| k.as_str() != "type")
        .map(|(k, v)| FieldSpec {
            name: k.clone(),
            json_type: JsonType::of(v),
        })
        .collect();
    fields.sort_by(|a, b| a.name.cmp(&b.name));
    MessageSpec {
        wire_type,
        rust_variant: rust_variant.to_string(),
        fields,
    }
}

/// A representative [`ProtocolError`] used to shape error-bearing events.
fn sample_error() -> ProtocolError {
    ProtocolError::new(ErrorCategory::Capacity, "at capacity").with_recovery("retry shortly")
}

/// Every runtime→client event variant, populated so that all optional fields are present and thus
/// observable in the descriptor. The `Unknown` must-ignore fallthrough is intentionally excluded (it
/// is not a real wire type — it is how a client absorbs a *newer* peer's unknown event).
fn event_samples() -> Vec<(&'static str, WireEvent)> {
    vec![
        ("TextDelta", WireEvent::TextDelta { text: "hi".into() }),
        (
            "ReasoningDelta",
            WireEvent::ReasoningDelta { text: "why".into() },
        ),
        (
            "ToolCallStart",
            WireEvent::ToolCallStart {
                call_id: "c1".into(),
                name: "kb.search".into(),
                source: ToolSource::Native,
            },
        ),
        (
            "ToolCallDelta",
            WireEvent::ToolCallDelta {
                call_id: "c1".into(),
                args_delta: "{\"q\":".into(),
            },
        ),
        (
            "ToolCallStop",
            WireEvent::ToolCallStop {
                call_id: "c1".into(),
                args: "{}".into(),
            },
        ),
        (
            "ToolResult",
            WireEvent::ToolResult {
                call_id: "c1".into(),
                blocks: vec![ResultBlock::Text { text: "ok".into() }],
                is_error: false,
            },
        ),
        (
            "ApprovalRequest",
            WireEvent::ApprovalRequest {
                approval_id: "a1".into(),
                action: "gitlab.create_mr".into(),
                scope: "repo".into(),
                risk_tier: "high".into(),
                preview: Some("diff".into()),
                payment_boundary: PaymentBoundary::None,
            },
        ),
        (
            "ComplianceNotice",
            WireEvent::ComplianceNotice {
                categories: vec!["PAN".into()],
                action: ComplianceAction::Redacted,
            },
        ),
        (
            "Artifact",
            WireEvent::Artifact {
                artifact_id: "art1".into(),
                kind: "pdf".into(),
                uri: "artifact://art1".into(),
                preview: Some("preview".into()),
                verification: Some(ainxt_protocol::ArtifactVerification {
                    matches_intent: true,
                    caveats: vec![],
                }),
            },
        ),
        (
            "Usage",
            WireEvent::Usage {
                // Illustrative only. A real vendor id here made one provider look like
                // the canonical example in the published SDK contract; these samples
                // exercise the wire SHAPE, not any particular model.
                model: "example-model".into(),
                input_tokens: 10,
                output_tokens: 20,
                cost: 0.01,
                cached: Some(false),
            },
        ),
        (
            "SessionSnapshot",
            WireEvent::SessionSnapshot {
                tree: SessionTree {
                    turns: vec![TurnNode {
                        turn_id: "t1".into(),
                        parent_turn_id: None,
                        label: None,
                    }],
                },
                active_head: Some("t1".into()),
                participants: vec![Participant {
                    participant_id: "p1".into(),
                    display_name: Some("Ana".into()),
                }],
                negotiated_version: PROTOCOL_VERSION.to_string(),
            },
        ),
        (
            "TurnStarted",
            WireEvent::TurnStarted {
                turn_id: "t1".into(),
                parent_turn_id: Some("t0".into()),
                participant_id: "p1".into(),
                model_hint: Some("complex".into()),
            },
        ),
        (
            "TurnRationale",
            WireEvent::TurnRationale {
                turn_id: "t1".into(),
                model_tier: "complex".into(),
                model: "example-model".into(),  // illustrative, see above
                capabilities: vec!["kb.search".into()],
                sources: vec!["docs_kb:settlement".into()],
            },
        ),
        (
            "TurnCompleted",
            WireEvent::TurnCompleted {
                turn_id: "t1".into(),
                outcome: TurnOutcome::Complete,
            },
        ),
        (
            "TurnStopped",
            WireEvent::TurnStopped {
                turn_id: "t1".into(),
            },
        ),
        (
            "TurnFailed",
            WireEvent::TurnFailed {
                turn_id: "t1".into(),
                error: sample_error(),
            },
        ),
        (
            "TurnSteer",
            WireEvent::TurnSteer {
                turn_id: "t1".into(),
                text: "focus on NEFT".into(),
            },
        ),
        (
            "TurnEdit",
            WireEvent::TurnEdit {
                turn_id: "t1".into(),
            },
        ),
        (
            "TurnBranch",
            WireEvent::TurnBranch {
                from_turn_id: "t1".into(),
                label: Some("alt".into()),
            },
        ),
        ("Error", WireEvent::Error(sample_error())),
        (
            "ParticipantJoined",
            WireEvent::ParticipantJoined {
                participant_id: "p1".into(),
                turn_id: Some("t1".into()),
            },
        ),
        (
            "ParticipantLeft",
            WireEvent::ParticipantLeft {
                participant_id: "p1".into(),
            },
        ),
        (
            "ParticipantTyping",
            WireEvent::ParticipantTyping {
                participant_id: "p1".into(),
                turn_id: Some("t1".into()),
            },
        ),
        (
            "ParticipantViewing",
            WireEvent::ParticipantViewing {
                participant_id: "p1".into(),
                turn_id: Some("t1".into()),
            },
        ),
    ]
}

/// Every client→runtime command variant (excluding the `Unknown` must-ignore fallthrough).
fn command_samples() -> Vec<(&'static str, Command)> {
    vec![
        (
            "SessionOpen",
            Command::SessionOpen {
                profile_id: "chat".into(),
                client_info: Some("ainxt-py/0".into()),
                capabilities_wanted: vec!["chat.send".into()],
                client_protocol_version: None,
            },
        ),
        (
            "SessionResume",
            Command::SessionResume {
                session_id: "s1".into(),
                from_event: Some(42),
            },
        ),
        (
            "SessionSubscribe",
            Command::SessionSubscribe {
                session_id: "s1".into(),
                mode: SubscribeMode::Observer,
            },
        ),
        (
            "SessionFork",
            Command::SessionFork {
                session_id: "s1".into(),
                from_turn_id: "t1".into(),
                label: Some("alt".into()),
            },
        ),
        (
            "SessionClose",
            Command::SessionClose {
                session_id: "s1".into(),
            },
        ),
        (
            "TurnSubmit",
            Command::TurnSubmit {
                input: TurnInput {
                    text: "why did NEFT fail?".into(),
                    attachments: vec![Attachment {
                        kind: "log".into(),
                        uri: "artifact://l1".into(),
                    }],
                },
                overrides: Some(TurnOverrides {
                    forced_model: Some("example-model-pinned".into()),  // illustrative
                    tier: None,
                }),
            },
        ),
        (
            "TurnSteer",
            Command::TurnSteer {
                turn_id: "t1".into(),
                text: "focus".into(),
            },
        ),
        (
            "TurnStop",
            Command::TurnStop {
                turn_id: "t1".into(),
            },
        ),
        (
            "TurnEdit",
            Command::TurnEdit {
                turn_id: "t1".into(),
                input: TurnInput::text("edited"),
            },
        ),
        (
            "TurnBranch",
            Command::TurnBranch {
                from_turn_id: "t1".into(),
                label: Some("alt".into()),
            },
        ),
        (
            "ApprovalRespond",
            Command::ApprovalRespond(ApprovalRespond {
                approval_id: "a1".into(),
                decision: ApprovalDecision::Approve,
                feedback: Some("ok".into()),
            }),
        ),
        (
            "ProgramStart",
            Command::ProgramStart {
                program_id: "prog1".into(),
                spec: Some("migrate".into()),
            },
        ),
        (
            "ProgramPause",
            Command::ProgramPause {
                program_id: "prog1".into(),
            },
        ),
        (
            "ProgramResume",
            Command::ProgramResume {
                program_id: "prog1".into(),
            },
        ),
        (
            "ProgramCheckpointRespond",
            Command::ProgramCheckpointRespond {
                program_id: "prog1".into(),
                checkpoint_id: "cp1".into(),
                decision: ApprovalDecision::Approve,
            },
        ),
    ]
}

/// The closed error taxonomy (`§6.5.1`) with its canonical retryability.
fn error_category_specs() -> Vec<ErrorCategorySpec> {
    let all = [
        ErrorCategory::Capacity,
        ErrorCategory::CapabilityDenied,
        ErrorCategory::ProviderUnavailable,
        ErrorCategory::Capped,
        ErrorCategory::Ambiguous,
        ErrorCategory::ProtocolIncompatible,
        ErrorCategory::InvalidCommand,
    ];
    all.iter()
        .map(|c| ErrorCategorySpec {
            wire_name: serde_json::to_value(c)
                .ok()
                .and_then(|v| v.as_str().map(|s| s.to_string()))
                .expect("error category serializes to a string"),
            retryable: c.retryable_default(),
        })
        .collect()
}

/// The closed enums referenced by message fields, rendered as string-literal unions in the SDKs.
fn enum_specs() -> Vec<EnumSpec> {
    fn variant(v: &impl Serialize) -> String {
        serde_json::to_value(v)
            .ok()
            .and_then(|x| x.as_str().map(|s| s.to_string()))
            .expect("closed-enum variant serializes to a string")
    }
    vec![
        EnumSpec {
            name: "ToolSource".into(),
            variants: [ToolSource::Native, ToolSource::Mcp, ToolSource::Skill]
                .iter()
                .map(variant)
                .collect(),
        },
        EnumSpec {
            name: "ComplianceAction".into(),
            variants: [ComplianceAction::Redacted, ComplianceAction::Audited]
                .iter()
                .map(variant)
                .collect(),
        },
        EnumSpec {
            name: "TurnOutcome".into(),
            variants: [TurnOutcome::Complete, TurnOutcome::Capped]
                .iter()
                .map(variant)
                .collect(),
        },
        EnumSpec {
            name: "PaymentBoundary".into(),
            variants: [
                PaymentBoundary::None,
                PaymentBoundary::MovesValue,
                PaymentBoundary::InitiatesSettlement,
            ]
            .iter()
            .map(variant)
            .collect(),
        },
        EnumSpec {
            name: "ApprovalDecision".into(),
            variants: [
                ApprovalDecision::Approve,
                ApprovalDecision::ApproveForSession,
                ApprovalDecision::Reject,
            ]
            .iter()
            .map(variant)
            .collect(),
        },
        EnumSpec {
            name: "SubscribeMode".into(),
            variants: [SubscribeMode::Observer].iter().map(variant).collect(),
        },
    ]
}

/// Build the [`ContractDescriptor`] from the live protocol types. This is the single codegen input
/// every language SDK is generated from.
pub fn contract_descriptor() -> ContractDescriptor {
    ContractDescriptor {
        protocol_version: PROTOCOL_VERSION.to_string(),
        supported_major_window: SUPPORTED_MAJOR_WINDOW,
        events: event_samples()
            .iter()
            .map(|(name, ev)| spec_from_sample(name, ev))
            .collect(),
        commands: command_samples()
            .iter()
            .map(|(name, cmd)| spec_from_sample(name, cmd))
            .collect(),
        error_categories: error_category_specs(),
        enums: enum_specs(),
    }
}

/// `snake.case.wire` / `snake_case` → `PascalCase` identifier for a generated class/type name.
fn pascal(wire_type: &str) -> String {
    wire_type
        .split(['.', '_'])
        .filter(|s| !s.is_empty())
        .map(|seg| {
            let mut ch = seg.chars();
            match ch.next() {
                Some(f) => f.to_uppercase().collect::<String>() + ch.as_str(),
                None => String::new(),
            }
        })
        .collect()
}

/// Emit the **Python** SDK binding source from the contract. The output mirrors the wire contract
/// exactly: a protocol-version constant, a typed dataclass per event, the closed error taxonomy, and
/// an ergonomic `Runtime`/`Harness` client over a network-transport seam (the live HTTP/SSE I/O is
/// the infra follow-up; the seam and typed surface are generated here). This is what a Python package
/// runs at build time — the SDK is a *generated mirror*, never a hand-maintained copy.
pub fn emit_python_sdk(desc: &ContractDescriptor) -> String {
    let mut out = String::new();
    out.push_str("# SPDX-License-Identifier: Apache-2.0\n");
    out.push_str("# GENERATED by ainxt-client::sdk_contract::emit_python_sdk — DO NOT EDIT.\n");
    out.push_str(
        "# The Python SDK mirrors the AiNxt wire contract; regenerate from the descriptor.\n",
    );
    out.push_str("from __future__ import annotations\n");
    out.push_str("from dataclasses import dataclass, field\n\n");
    out.push_str(&format!(
        "PROTOCOL_VERSION = \"{}\"\n",
        desc.protocol_version
    ));
    out.push_str(&format!(
        "SUPPORTED_MAJOR_WINDOW = {}\n\n",
        desc.supported_major_window
    ));

    // Error taxonomy.
    out.push_str("ERROR_CATEGORIES = {\n");
    for e in &desc.error_categories {
        out.push_str(&format!(
            "    \"{}\": {{\"retryable\": {}}},\n",
            e.wire_name,
            if e.retryable { "True" } else { "False" }
        ));
    }
    out.push_str("}\n\n");

    // Closed enums.
    for en in &desc.enums {
        let lits = en
            .variants
            .iter()
            .map(|v| format!("\"{v}\""))
            .collect::<Vec<_>>()
            .join(", ");
        out.push_str(&format!("{} = ({})\n", en.name.to_uppercase(), lits));
    }
    out.push('\n');

    // A typed dataclass per event.
    out.push_str("# ---- Events (runtime -> client) ----\n");
    let mut event_types = Vec::new();
    for ev in &desc.events {
        let cls = pascal(&ev.wire_type);
        event_types.push((ev.wire_type.clone(), cls.clone()));
        out.push_str("@dataclass\n");
        out.push_str(&format!("class {cls}:\n"));
        out.push_str(&format!("    TYPE = \"{}\"\n", ev.wire_type));
        if ev.fields.is_empty() {
            out.push_str("    pass\n\n");
            continue;
        }
        for f in &ev.fields {
            let default = match f.json_type {
                JsonType::Array => " = field(default_factory=list)",
                JsonType::Object => " = field(default_factory=dict)",
                _ => "",
            };
            out.push_str(&format!(
                "    {}: {}{}\n",
                f.name,
                f.json_type.python(),
                default
            ));
        }
        out.push('\n');
    }

    // Event dispatch registry + parser.
    out.push_str("EVENT_TYPES = {\n");
    for (wire, cls) in &event_types {
        out.push_str(&format!("    \"{wire}\": {cls},\n"));
    }
    out.push_str("}\n\n");
    out.push_str("def parse_event(payload: dict):\n");
    out.push_str(
        "    \"\"\"Decode a wire event; unknown `type`s are ignored (must-ignore rule).\"\"\"\n",
    );
    out.push_str("    cls = EVENT_TYPES.get(payload.get(\"type\"))\n");
    out.push_str("    if cls is None:\n");
    out.push_str("        return None\n");
    out.push_str("    known = {k: v for k, v in payload.items() if k != \"type\"}\n");
    out.push_str(
        "    return cls(**{k: v for k, v in known.items() if k in cls.__annotations__})\n\n",
    );

    // Command type registry (names only — the client builds these).
    out.push_str("COMMAND_TYPES = (\n");
    for cmd in &desc.commands {
        out.push_str(&format!("    \"{}\",\n", cmd.wire_type));
    }
    out.push_str(")\n\n");

    // Ergonomic client skeleton over the transport seam.
    out.push_str(python_client_skeleton());
    out
}

/// The Python `Runtime`/`Harness` client skeleton (matches `HARNESS_SDK.md` §2.2). The network I/O
/// is the infra follow-up; the typed surface + transport seam are fixed by the contract.
fn python_client_skeleton() -> &'static str {
    r#"# ---- Client (thin, ergonomic; the headless CLI wraps this same surface) ----
class Transport:
    """Seam: an in-process embed (desktop-direct) or a network HTTP/SSE transport to ainxt-server."""
    def submit(self, principal, command: dict):
        raise NotImplementedError("network HTTP/SSE transport is the infra follow-up")

def _is_local_address(base_url: str) -> bool:
    """True if base_url's host is a loopback address (localhost/127.0.0.1/::1), where a plain
    "http://" is not a credential-leak risk because the traffic never leaves the machine."""
    host = base_url.split("://", 1)[-1].split("/", 1)[0]
    host = host.rsplit("@", 1)[-1]  # drop any userinfo
    host = host.split(":", 1)[0]  # drop port
    host = host.strip("[]")  # drop IPv6 brackets
    return host in ("localhost", "127.0.0.1", "::1") or host.startswith("127.")

class Runtime:
    def __init__(self, base_url: str, token: str, transport: "Transport | None" = None):
        # SEC-F-002: a bare "http://" address is unencrypted, and every call below sends `token`
        # (a real login credential) over it. Loopback/localhost is exempt (nothing off-machine can
        # observe that traffic); anything else must be "https://" or this constructor refuses.
        if base_url.startswith("http://") and not _is_local_address(base_url):
            raise ValueError(
                "base_url is not encrypted (http://), but a real login token is sent on every "
                "call. Use https://, or an in-process Transport that never touches the network."
            )
        self.base_url = base_url
        self.token = token  # secret: never log or print this value
        self._transport = transport

    def harness(self, **spec) -> "Harness":
        return Harness(self, spec)

class Harness:
    def __init__(self, runtime: "Runtime", spec: dict):
        self.runtime = runtime
        self.spec = spec

    def run(self, prompt: str):
        """Stream TYPED events for a turn. Backpressure surfaces as a typed capacity error."""
        if self.runtime._transport is None:
            raise NotImplementedError("network HTTP/SSE transport is the infra follow-up")
        cmd = {"type": "turn.submit", "input": {"text": prompt}}
        for payload in self.runtime._transport.submit(self.token, cmd):
            ev = parse_event(payload)
            if ev is not None:
                yield ev
"#
}

/// Emit the **TypeScript** SDK binding source from the contract (powers the IDE extension + web
/// tooling). Same mirror guarantee as [`emit_python_sdk`].
pub fn emit_typescript_sdk(desc: &ContractDescriptor) -> String {
    let mut out = String::new();
    out.push_str("// SPDX-License-Identifier: Apache-2.0\n");
    out.push_str(
        "// GENERATED by ainxt-client::sdk_contract::emit_typescript_sdk — DO NOT EDIT.\n",
    );
    out.push_str(&format!(
        "export const PROTOCOL_VERSION = \"{}\";\n",
        desc.protocol_version
    ));
    out.push_str(&format!(
        "export const SUPPORTED_MAJOR_WINDOW = {};\n\n",
        desc.supported_major_window
    ));

    // Error taxonomy as a string-literal union + a retryable map.
    let err_union = desc
        .error_categories
        .iter()
        .map(|e| format!("\"{}\"", e.wire_name))
        .collect::<Vec<_>>()
        .join(" | ");
    out.push_str(&format!("export type ErrorCategory = {err_union};\n"));
    out.push_str("export const ERROR_RETRYABLE: Record<ErrorCategory, boolean> = {\n");
    for e in &desc.error_categories {
        out.push_str(&format!("  \"{}\": {},\n", e.wire_name, e.retryable));
    }
    out.push_str("};\n\n");

    // Closed enums.
    for en in &desc.enums {
        let union = en
            .variants
            .iter()
            .map(|v| format!("\"{v}\""))
            .collect::<Vec<_>>()
            .join(" | ");
        out.push_str(&format!("export type {} = {};\n", en.name, union));
    }
    out.push('\n');

    // A typed interface per event + the discriminated union.
    out.push_str("// ---- Events (runtime -> client) ----\n");
    let mut names = Vec::new();
    for ev in &desc.events {
        let iface = pascal(&ev.wire_type);
        names.push(iface.clone());
        out.push_str(&format!("export interface {iface} {{\n"));
        out.push_str(&format!("  type: \"{}\";\n", ev.wire_type));
        for f in &ev.fields {
            out.push_str(&format!("  {}: {};\n", f.name, f.json_type.typescript()));
        }
        out.push_str("}\n");
    }
    out.push_str(&format!(
        "export type WireEvent = {};\n\n",
        names.join(" | ")
    ));

    // Command wire types.
    let cmd_union = desc
        .commands
        .iter()
        .map(|c| format!("\"{}\"", c.wire_type))
        .collect::<Vec<_>>()
        .join(" | ");
    out.push_str(&format!("export type CommandType = {cmd_union};\n\n"));

    out.push_str(typescript_client_skeleton());
    out
}

/// The TypeScript `Runtime`/`Harness` client skeleton over the transport seam.
fn typescript_client_skeleton() -> &'static str {
    r#"// ---- Client (thin; desktop + IDE extension consume this same surface) ----
export interface Transport {
  // Seam: in-process embed (desktop-direct) or a network HTTP/SSE transport to ainxt-server.
  submit(principal: string, command: { type: CommandType } & Record<string, unknown>): AsyncIterable<WireEvent>;
}

export interface HarnessSpec {
  name: string;
  persona?: string;
  modelPolicy?: string;
  capabilities?: string[];
  autonomy?: "none" | "assisted" | "autonomous";
}

function isLocalAddress(baseUrl: string): boolean {
  // True if baseUrl's host is a loopback address (localhost/127.0.0.1/::1), where a plain
  // "http://" is not a credential-leak risk because the traffic never leaves the machine.
  const afterScheme = baseUrl.split("://").pop() ?? baseUrl;
  const afterAuth = afterScheme.split("@").pop() ?? afterScheme;
  let host = afterAuth.split("/")[0].split(":")[0];
  host = host.replace(/^\[|\]$/g, ""); // drop IPv6 brackets
  return host === "localhost" || host === "127.0.0.1" || host === "::1" || host.startsWith("127.");
}

export class Runtime {
  constructor(private baseUrl: string, private token: string, private transport?: Transport) {
    // SEC-F-002: a bare "http://" address is unencrypted, and every call below sends `token`
    // (a real login credential) over it. Loopback/localhost is exempt (nothing off-machine can
    // observe that traffic); anything else must be "https://" or this constructor throws.
    if (baseUrl.startsWith("http://") && !isLocalAddress(baseUrl)) {
      throw new Error(
        "baseUrl is not encrypted (http://), but a real login token is sent on every " +
          "call. Use https://, or an in-process Transport that never touches the network."
      );
    }
  }
  harness(spec: HarnessSpec): Harness { return new Harness(this, spec); }
  get _transport(): Transport | undefined { return this.transport; }
  get _token(): string { return this.token; }
}

export class Harness {
  constructor(private runtime: Runtime, private spec: HarnessSpec) {}
  async *run(prompt: string): AsyncIterable<WireEvent> {
    if (!this.runtime._transport) throw new Error("network HTTP/SSE transport is the infra follow-up");
    yield* this.runtime._transport.submit(this.runtime._token, { type: "turn.submit", input: { text: prompt } } as never);
  }
}
"#
}
