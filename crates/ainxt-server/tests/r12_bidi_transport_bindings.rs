// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! r12_bidi_transport_bindings — the offline seam proof for the gap
//! "gRPC-bidi and WebSocket transport bindings".
//!
//! Both bindings are the SAME transport-agnostic bidirectional core ([`WireDuplex`]): the inbound side
//! applies the typed [`Command`] vocabulary to the daemon's live organs (cancel / approval round-trip /
//! session close) and the outbound side is a session [`EventEnvelope`] tail. HTTP+SSE binds it today
//! (`POST /v1/command` + `GET /v1/observe`); a **gRPC bidi-streaming** service (tonic + protoc codegen)
//! and a **WebSocket** duplex (tungstenite) are two further concrete framings of this identical core —
//! each just carrying the same `Command`/`EventEnvelope` vocabulary over its wire. Those two concrete
//! framings pull a heavy network-protocol dependency, so per the ADR they live behind their own build
//! features and are the INFRA follow-up; this test proves the shared core they bind to is complete and
//! correct fully offline (no network protocol dependency), so a binding is a thin adapter, not a
//! re-implementation.

use ainxt_protocol::{ApprovalDecision, ApprovalRespond, Command};
use ainxt_server::{ApprovalCoordinator, CancelRegistry, WireDuplex};
use std::sync::Arc;

fn duplex_with_approvals() -> WireDuplex {
    WireDuplex::new(
        Arc::new(CancelRegistry::new()),
        Some(Arc::new(ApprovalCoordinator::new())),
        None, // no wire hub: the outbound tail is then absent (asserted below)
    )
}

#[test]
fn r12_bidi_core_frames_the_full_control_command_vocabulary() {
    let duplex = duplex_with_approvals();

    // turn.stop — the idempotent cancel verb. With no live turn it acks cancelled=false (the exact
    // typed ack a gRPC/WS binding would frame back).
    let stop = duplex.apply_command(
        "s1",
        &Command::TurnStop {
            turn_id: "t1".into(),
        },
    );
    assert_eq!(stop["command"], "turn.stop");
    assert_eq!(stop["accepted"], true);
    assert_eq!(stop["cancelled"], false);

    // approval.respond{reject} with no feedback is rejected by the payment-boundary invariant — the
    // core enforces §6.3, not the binding.
    let bad = duplex.apply_command(
        "s1",
        &Command::ApprovalRespond(ApprovalRespond {
            approval_id: "ap".into(),
            decision: ApprovalDecision::Reject,
            feedback: None,
        }),
    );
    assert_eq!(bad["command"], "approval.respond");
    assert_eq!(bad["accepted"], false);

    // approval.respond{approve} is well-formed; with nothing blocked it acks delivered=false
    // (idempotent — a late/duplicate response).
    let approve = duplex.apply_command(
        "s1",
        &Command::ApprovalRespond(ApprovalRespond {
            approval_id: "ap".into(),
            decision: ApprovalDecision::Approve,
            feedback: None,
        }),
    );
    assert_eq!(approve["accepted"], true);
    assert_eq!(approve["delivered"], false);

    // session.close acks (with no wire hub there are no observer tails to drop — still a typed ack).
    let close = duplex.apply_command(
        "s1",
        &Command::SessionClose {
            session_id: "s1".into(),
        },
    );
    assert_eq!(close["command"], "session.close");
    assert_eq!(close["accepted"], true);

    // An interaction-tree op is NOT handled on the identity-free bidi core — it needs the renderer
    // projection over the identity-gated HTTP path. The core says so explicitly (never silently drops).
    let branch = duplex.apply_command(
        "s1",
        &Command::TurnBranch {
            from_turn_id: "t1".into(),
            label: None,
        },
    );
    assert_eq!(branch["accepted"], false);
    assert!(
        branch["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("identity-gated HTTP path"),
        "a tree op must be routed to the identity-gated path, got {branch}"
    );
}

#[test]
fn r12_bidi_outbound_tail_absent_without_a_wire_hub() {
    // The outbound side is the session EventEnvelope tail every binding fans out. With no engine wire
    // hub wired it is honestly absent (None) rather than a silent empty stream — the binding then
    // reports "observe unavailable" instead of hanging.
    let duplex = duplex_with_approvals();
    assert!(
        duplex.observe("s1").is_none(),
        "no wire hub ⇒ no outbound observer tail"
    );
}
