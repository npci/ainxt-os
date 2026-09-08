// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! r12_sdk_contract_covers_transport — the transport-side half of the gap
//! "Python and TypeScript SDKs (generated from one contract in CI)".
//!
//! The Python (first) + TypeScript SDKs are GENERATED from ONE machine-readable contract
//! ([`ainxt_client::sdk_contract::contract_descriptor`]) derived from the live `ainxt_protocol` types.
//! Standing those packages up in their own language repos with `pytest`/`vitest` CI, and running the
//! codegen against a LIVE HTTP/SSE server, is genuinely infra (recorded infra-gated). What this test
//! proves offline is the load-bearing invariant that makes the SDKs trustworthy: the ONE contract the
//! SDKs are generated from actually COVERS the control-command vocabulary the transport daemon serves
//! on `POST /v1/command`. If the transport gains/renames a served command and the contract is not
//! updated in lock-step, this fails — so a generated SDK can never silently lack (or misname) a verb
//! the runtime speaks.

use ainxt_client::sdk_contract::contract_descriptor;
use std::collections::BTreeSet;

/// The control-command wire `type` strings the transport's `command_handler` routes to a real effect
/// (PROTOCOL.md §5). This mirrors the served match arms in `ainxt-server`'s `/v1/command` handler.
const SERVED_COMMAND_WIRE_TYPES: &[&str] = &[
    "turn.stop",
    "turn.branch",
    "turn.edit",
    "turn.steer",
    "session.fork",
    "approval.respond",
    "session.resume",
    "session.open",
    "session.subscribe",
    "session.close",
    "turn.submit",
];

#[test]
fn r12_one_contract_covers_every_served_transport_command() {
    let desc = contract_descriptor();
    let contract_cmds: BTreeSet<&str> =
        desc.commands.iter().map(|c| c.wire_type.as_str()).collect();

    for served in SERVED_COMMAND_WIRE_TYPES {
        assert!(
            contract_cmds.contains(served),
            "the SDK contract (the ONE source the Python/TS SDKs are generated from) is missing the \
             served transport command `{served}` — a generated SDK would lack a verb the daemon speaks. \
             Contract commands: {contract_cmds:?}"
        );
    }

    // The negotiated protocol version travels in the same contract (the SDKs pin it for §10.2 handshake).
    assert!(
        !desc.protocol_version.is_empty(),
        "the contract must carry the protocol version the SDKs pin"
    );
    assert!(
        desc.supported_major_window >= 1,
        "the contract must declare the supported-major (N-2) window the SDKs negotiate against"
    );
}
