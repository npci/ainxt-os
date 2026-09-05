// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! r11_python_ts_sdk — the offline conformance test for the "Python/TS SDK" gap.
//!
//! The Python (first) + TypeScript SDKs mirror the AiNxt wire contract. Standing the packages up in
//! Python/JS repos with their own CI, and wiring the codegen'd client to a **live** HTTP/SSE server,
//! is genuinely infra (recorded infra-gated). What is proven fully offline here is the *seam + impl*
//! those SDKs are built on: a machine-readable contract descriptor derived from the live protocol
//! types, and language codegen that emits provably faithful mirrors of it.
//!
//! These assertions FAIL if:
//! - the descriptor drifts from the real `WireEvent`/`Command` wire vocabulary (add/rename/remove);
//! - the descriptor claims a `type` string the runtime does not actually speak;
//! - the Python or TypeScript codegen drops any event, command, error category, or the version.

use ainxt_client::sdk_contract::{
    contract_descriptor, emit_python_sdk, emit_typescript_sdk, ContractDescriptor,
};
use ainxt_protocol::{Command, WireEvent, PROTOCOL_VERSION};
use std::collections::BTreeSet;

/// The canonical event wire-type vocabulary (`PROTOCOL.md` §6). A change here is a deliberate
/// contract change — this set gates SDK regeneration.
const EXPECTED_EVENT_TYPES: &[&str] = &[
    "text.delta",
    "reasoning.delta",
    "tool.call.start",
    "tool.call.delta",
    "tool.call.stop",
    "tool.result",
    "approval.request",
    "compliance.notice",
    "artifact",
    "usage",
    "session.snapshot",
    "turn.started",
    "turn.rationale",
    "turn.completed",
    "turn.stopped",
    "turn.failed",
    "turn.steer",
    "turn.edit",
    "turn.branch",
    "error",
    "participant.joined",
    "participant.left",
    "participant.typing",
    "participant.viewing",
];

/// The canonical command wire-type vocabulary (`PROTOCOL.md` §5).
const EXPECTED_COMMAND_TYPES: &[&str] = &[
    "session.open",
    "session.resume",
    "session.subscribe",
    "session.fork",
    "session.close",
    "turn.submit",
    "turn.steer",
    "turn.stop",
    "turn.edit",
    "turn.branch",
    "approval.respond",
    "program.start",
    "program.pause",
    "program.resume",
    "program.checkpoint.respond",
];

fn event_types(desc: &ContractDescriptor) -> BTreeSet<String> {
    desc.events.iter().map(|m| m.wire_type.clone()).collect()
}
fn command_types(desc: &ContractDescriptor) -> BTreeSet<String> {
    desc.commands.iter().map(|m| m.wire_type.clone()).collect()
}

#[test]
fn r11_descriptor_covers_the_full_wire_vocabulary() {
    let desc = contract_descriptor();

    let want_events: BTreeSet<String> =
        EXPECTED_EVENT_TYPES.iter().map(|s| s.to_string()).collect();
    assert_eq!(
        event_types(&desc),
        want_events,
        "the SDK contract descriptor must enumerate exactly the protocol's event vocabulary — \
         adding/renaming a WireEvent variant must be reflected here so the SDKs regenerate"
    );

    let want_cmds: BTreeSet<String> = EXPECTED_COMMAND_TYPES
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert_eq!(
        command_types(&desc),
        want_cmds,
        "the SDK contract descriptor must enumerate exactly the protocol's command vocabulary"
    );

    // The protocol version + N-2 window are pinned into the contract the SDKs advertise.
    assert_eq!(desc.protocol_version, PROTOCOL_VERSION.to_string());
    assert_eq!(
        desc.supported_major_window,
        ainxt_protocol::SUPPORTED_MAJOR_WINDOW
    );

    // The full closed error taxonomy is present, with retryability.
    let cats: BTreeSet<String> = desc
        .error_categories
        .iter()
        .map(|e| e.wire_name.clone())
        .collect();
    for c in [
        "capacity",
        "capability_denied",
        "provider_unavailable",
        "capped",
        "ambiguous",
        "protocol_incompatible",
        "invalid_command",
    ] {
        assert!(cats.contains(c), "error taxonomy missing `{c}`");
    }
    // `capacity` (backpressure) is the retryable one the SDK auto-retries.
    let capacity = desc
        .error_categories
        .iter()
        .find(|e| e.wire_name == "capacity")
        .unwrap();
    assert!(
        capacity.retryable,
        "capacity/backpressure must be retryable"
    );
    let denied = desc
        .error_categories
        .iter()
        .find(|e| e.wire_name == "capability_denied")
        .unwrap();
    assert!(!denied.retryable, "an RBAC denial must not be retryable");
}

#[test]
fn r11_descriptor_type_strings_are_real_protocol_types() {
    // Ties the descriptor's declared `type` strings to what the runtime ACTUALLY deserializes: a
    // known-good wire type round-trips into a recognized (non-`Unknown`) variant, while a bogus type
    // falls through to the must-ignore `Unknown`. This catches a typo'd/stale descriptor entry.
    let ev: WireEvent = serde_json::from_value(serde_json::json!({
        "type": "text.delta", "text": "hi"
    }))
    .unwrap();
    assert!(matches!(ev, WireEvent::TextDelta { .. }));

    let bogus: WireEvent = serde_json::from_value(serde_json::json!({
        "type": "text.delta.NOPE", "text": "hi"
    }))
    .unwrap();
    assert!(
        matches!(bogus, WireEvent::Unknown),
        "an unlisted event type must be absorbed as Unknown (must-ignore), not accepted"
    );

    let cmd: Command = serde_json::from_value(serde_json::json!({
        "type": "turn.stop", "turn_id": "t1"
    }))
    .unwrap();
    assert!(matches!(cmd, Command::TurnStop { .. }));

    // Every event type the descriptor lists must be one the reference vocabulary contains (so a
    // generated SDK never advertises a type the runtime cannot speak).
    let desc = contract_descriptor();
    let vocab: BTreeSet<&str> = EXPECTED_EVENT_TYPES.iter().copied().collect();
    for m in &desc.events {
        assert!(
            vocab.contains(m.wire_type.as_str()),
            "descriptor advertises unknown event type `{}`",
            m.wire_type
        );
        // Structured events carry fields; the field shape was read from a real serialization.
        if m.wire_type == "usage" {
            let names: BTreeSet<&str> = m.fields.iter().map(|f| f.name.as_str()).collect();
            for want in ["model", "input_tokens", "output_tokens", "cost"] {
                assert!(names.contains(want), "usage event missing field `{want}`");
            }
        }
    }
}

#[test]
fn r11_descriptor_round_trips_as_json_codegen_input() {
    // The descriptor IS the codegen input; it must round-trip through serde losslessly.
    let desc = contract_descriptor();
    let json = serde_json::to_string_pretty(&desc).unwrap();
    let back: ContractDescriptor = serde_json::from_str(&json).unwrap();
    assert_eq!(
        desc, back,
        "the contract descriptor must be a stable JSON artifact"
    );
}

#[test]
fn r11_python_sdk_is_a_faithful_generated_mirror() {
    let desc = contract_descriptor();
    let py = emit_python_sdk(&desc);

    // Version + window are baked in.
    assert!(py.contains(&format!("PROTOCOL_VERSION = \"{}\"", PROTOCOL_VERSION)));
    assert!(py.contains("SUPPORTED_MAJOR_WINDOW ="));

    // Every event has a class registered in EVENT_TYPES under its exact wire type.
    for ev in &desc.events {
        assert!(
            py.contains(&format!("\"{}\":", ev.wire_type)),
            "python SDK missing event `{}`",
            ev.wire_type
        );
    }
    // Every command wire type appears in the COMMAND_TYPES tuple.
    for cmd in &desc.commands {
        assert!(
            py.contains(&format!("\"{}\",", cmd.wire_type)),
            "python SDK missing command `{}`",
            cmd.wire_type
        );
    }
    // The full error taxonomy is present.
    for e in &desc.error_categories {
        assert!(
            py.contains(&format!("\"{}\":", e.wire_name)),
            "python SDK missing error category `{}`",
            e.wire_name
        );
    }
    // The ergonomic surface from HARNESS_SDK.md §2.2 + a parser + the transport seam are present.
    assert!(py.contains("class Runtime"));
    assert!(py.contains("class Harness"));
    assert!(py.contains("def parse_event"));
    assert!(py.contains("class Transport"));
    // A structured event dataclass carries its typed fields.
    assert!(py.contains("class Usage:"));
    assert!(py.contains("input_tokens: int"));
    assert!(py.contains("cost: float"));
}

#[test]
fn r11_typescript_sdk_is_a_faithful_generated_mirror() {
    let desc = contract_descriptor();
    let ts = emit_typescript_sdk(&desc);

    assert!(ts.contains(&format!("PROTOCOL_VERSION = \"{}\"", PROTOCOL_VERSION)));
    // The discriminated WireEvent union names an interface per event, keyed by the wire type.
    for ev in &desc.events {
        assert!(
            ts.contains(&format!("type: \"{}\";", ev.wire_type)),
            "typescript SDK missing event discriminant `{}`",
            ev.wire_type
        );
    }
    // Commands appear in the CommandType union.
    for cmd in &desc.commands {
        assert!(
            ts.contains(&format!("\"{}\"", cmd.wire_type)),
            "typescript SDK missing command `{}`",
            cmd.wire_type
        );
    }
    // Error taxonomy union + retryable map.
    assert!(ts.contains("export type ErrorCategory ="));
    assert!(ts.contains("export const ERROR_RETRYABLE"));
    for e in &desc.error_categories {
        assert!(
            ts.contains(&format!("\"{}\"", e.wire_name)),
            "typescript SDK missing error category `{}`",
            e.wire_name
        );
    }
    // Typed client surface + transport seam.
    assert!(ts.contains("export class Runtime"));
    assert!(ts.contains("export class Harness"));
    assert!(ts.contains("export interface Transport"));
    assert!(ts.contains("export type WireEvent ="));
}
